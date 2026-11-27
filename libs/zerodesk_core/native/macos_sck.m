// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#import "macos_sck.h"

#import <CoreAudio/CoreAudio.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>

#include <os/lock.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define ZD_SCK_MAX_AUDIO_BUFFERS 8
#define ZD_SCK_DEFAULT_STOP_TIMEOUT_MS 2000u
#define ZD_SCK_START_TIMEOUT_NS (3LL * NSEC_PER_SEC)

enum ZdSckState {
    ZD_SCK_STATE_IDLE = 0,
    ZD_SCK_STATE_STARTING = 1,
    ZD_SCK_STATE_RUNNING = 2,
    ZD_SCK_STATE_STOPPING = 3,
    ZD_SCK_STATE_STOP_TIMED_OUT = 4,
};

static const void* kZdCallbackQueueKey = &kZdCallbackQueueKey;
static const void* kZdVideoQueueKey = &kZdVideoQueueKey;
static const void* kZdAudioQueueKey = &kZdAudioQueueKey;
static const void* kZdStopQueueKey = &kZdStopQueueKey;

/* Thread-local re-entrancy guard set around ALL three callbacks (video_cb, audio_cb, err_cb)
 * so zd_sck_stop / zd_sck_destroy cannot deadlock or re-lock _delegateLock even on Apple's
 * private ScreenCaptureKit error callback thread. */
static _Thread_local int g_zd_sck_in_callback = 0;

/* Heap-allocated completion box so late ScreenCaptureKit callbacks after a timeout
 * never write into an unwound caller stack frame. */
@interface ZdSckAsyncBox : NSObject {
    os_unfair_lock _lock;
    BOOL _completed;
}
@property (nonatomic, strong, readonly) dispatch_semaphore_t sem;
@property (nonatomic, strong) id result;
@property (nonatomic, strong) NSError* error;
- (void)completeWithResult:(id)res error:(NSError*)err;
- (BOOL)waitUntil:(dispatch_time_t)deadline outResult:(id*)outRes outError:(NSError**)outErr;
@end

@implementation ZdSckAsyncBox

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _completed = NO;
        _sem = dispatch_semaphore_create(0);
    }
    return self;
}

- (void)completeWithResult:(id)res error:(NSError*)err {
    os_unfair_lock_lock(&_lock);
    if (!_completed) {
        _result = res;
        _error = err;
        _completed = YES;
    }
    os_unfair_lock_unlock(&_lock);
    dispatch_semaphore_signal(_sem);
}

- (BOOL)waitUntil:(dispatch_time_t)deadline outResult:(id*)outRes outError:(NSError**)outErr {
    long rc = dispatch_semaphore_wait(_sem, deadline);
    if (rc != 0) {
        return NO;
    }
    os_unfair_lock_lock(&_lock);
    if (outRes != NULL) {
        *outRes = _result;
    }
    if (outErr != NULL) {
        *outErr = _error;
    }
    os_unfair_lock_unlock(&_lock);
    return YES;
}

@end

@interface ZdSckDelegate : NSObject <SCStreamDelegate, SCStreamOutput> {
    os_unfair_lock _delegateLock;
    ZdSckHandle* _handle;
    uint64_t _sessionId;
}
- (instancetype)initWithHandle:(ZdSckHandle*)handle;
- (void)armForSession:(uint64_t)sessionId;
- (void)detach;
@end

struct ZdSckHandle {
    ZdSckConfig cfg;
    ZdSckVideoCallback video_cb;
    ZdSckAudioCallback audio_cb;
    ZdSckErrorCallback err_cb;
    void* user_ctx;

    dispatch_queue_t video_queue;
    dispatch_queue_t audio_queue;
    dispatch_queue_t stop_queue;

    os_unfair_lock stream_lock;
    SCStream* stream;
    ZdSckDelegate* delegate;

    _Atomic uint32_t state;
    _Atomic uint64_t session_id;
    _Atomic uint32_t active_width;
    _Atomic uint32_t active_height;
};

static int64_t zd_cmtime_to_us(CMTime t) {
    if (!CMTIME_IS_NUMERIC(t) || t.timescale <= 0) {
        return 0;
    }
    double sec = CMTimeGetSeconds(t);
    if (sec < 0.0) {
        return 0;
    }
    return (int64_t)(sec * 1000000.0);
}

static uint32_t zd_clamp_even(uint32_t val, uint32_t min_v, uint32_t max_v) {
    if (val < min_v) {
        val = min_v;
    }
    if (val > max_v) {
        val = max_v;
    }
    return val & ~1u;
}

@implementation ZdSckDelegate

- (instancetype)initWithHandle:(ZdSckHandle*)handle {
    self = [super init];
    if (self != nil) {
        _delegateLock = OS_UNFAIR_LOCK_INIT;
        _handle = handle;
        _sessionId = 0;
    }
    return self;
}

- (void)armForSession:(uint64_t)sessionId {
    os_unfair_lock_lock(&_delegateLock);
    _sessionId = sessionId;
    os_unfair_lock_unlock(&_delegateLock);
}

- (void)detach {
    os_unfair_lock_lock(&_delegateLock);
    _handle = NULL;
    _sessionId = 0;
    os_unfair_lock_unlock(&_delegateLock);
}

- (void)stream:(SCStream*)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type {
    (void)stream;
    @autoreleasepool {
        @try {
            if (sampleBuffer == NULL) {
                return;
            }
            /* Snapshot handle + session_id under delegateLock. Because this callback runs
             * strictly on h->video_queue or h->audio_queue, and zd_sck_destroy detaches
             * _handle under _delegateLock BEFORE dispatch_sync draining both queues, `h`
             * is guaranteed alive for the full duration of this callback once non-NULL. */
            os_unfair_lock_lock(&_delegateLock);
            ZdSckHandle* h = _handle;
            uint64_t expected_sid = _sessionId;
            os_unfair_lock_unlock(&_delegateLock);

            if (h == NULL || expected_sid == 0) {
                return;
            }
            if (atomic_load_explicit(&h->state, memory_order_acquire) != ZD_SCK_STATE_RUNNING) {
                return;
            }
            if (atomic_load_explicit(&h->session_id, memory_order_acquire) != expected_sid) {
                return;
            }
            if (!CMSampleBufferIsValid(sampleBuffer) || !CMSampleBufferDataIsReady(sampleBuffer)) {
                return;
            }

            int64_t pts_us = zd_cmtime_to_us(CMSampleBufferGetPresentationTimeStamp(sampleBuffer));

            if (type == SCStreamOutputTypeScreen) {
                if (h->video_cb == NULL) {
                    return;
                }
                CFArrayRef attachments =
                    CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, false);
                if (attachments == NULL || CFArrayGetCount(attachments) == 0) {
                    return;
                }
                CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
                if (dict == NULL) {
                    return;
                }
                NSDictionary* info = (__bridge NSDictionary*)dict;
                NSNumber* statusNum = info[SCStreamFrameInfoStatus];
                if (statusNum == nil || (SCFrameStatus)statusNum.integerValue != SCFrameStatusComplete) {
                    /* Drop Idle / Blank / Suspended / Started frames cleanly. */
                    return;
                }
                float scale = 1.0f;
                NSNumber* scaleNum = info[SCStreamFrameInfoScaleFactor];
                if (scaleNum != nil && scaleNum.floatValue > 0.0f) {
                    scale = scaleNum.floatValue;
                }

                CVImageBufferRef pb = CMSampleBufferGetImageBuffer(sampleBuffer);
                if (pb == NULL) {
                    return;
                }
                if (CVPixelBufferGetPixelFormatType(pb) != kCVPixelFormatType_32BGRA) {
                    return;
                }
                CVReturn lock_rc = CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
                if (lock_rc != kCVReturnSuccess) {
                    return;
                }
                @try {
                    const uint8_t* base = (const uint8_t*)CVPixelBufferGetBaseAddress(pb);
                    size_t width = CVPixelBufferGetWidth(pb);
                    size_t height = CVPixelBufferGetHeight(pb);
                    size_t bpr = CVPixelBufferGetBytesPerRow(pb);
                    if (base != NULL && width > 0 && height > 0 && bpr >= width * 4
                        && width <= UINT32_MAX && height <= UINT32_MAX && bpr <= UINT32_MAX) {
                        atomic_store_explicit(&h->active_width, (uint32_t)width, memory_order_release);
                        atomic_store_explicit(&h->active_height, (uint32_t)height, memory_order_release);
                        g_zd_sck_in_callback = 1;
                        @try {
                            h->video_cb(
                                h->user_ctx,
                                base,
                                (uint32_t)width,
                                (uint32_t)height,
                                (uint32_t)bpr,
                                scale,
                                pts_us
                            );
                        } @finally {
                            g_zd_sck_in_callback = 0;
                        }
                    }
                } @finally {
                    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
                }
            } else if (type == SCStreamOutputTypeAudio) {
                if (h->audio_cb == NULL) {
                    return;
                }
                CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
                if (fmt == NULL) {
                    return;
                }
                const AudioStreamBasicDescription* asbd =
                    CMAudioFormatDescriptionGetStreamBasicDescription(fmt);
                if (asbd == NULL) {
                    return;
                }

                /* Stack-allocated AudioBufferList storage supporting up to 8 buffers (zero heap alloc). */
                _Alignas(16) uint8_t abl_storage[sizeof(AudioBufferList)
                    + (ZD_SCK_MAX_AUDIO_BUFFERS - 1) * sizeof(AudioBuffer)];
                AudioBufferList* abl = (AudioBufferList*)abl_storage;
                CMBlockBufferRef raw_block_buf = NULL;
                size_t needed_size = 0;

                OSStatus st = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
                    sampleBuffer,
                    &needed_size,
                    abl,
                    sizeof(abl_storage),
                    NULL,
                    NULL,
                    kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment,
                    &raw_block_buf
                );
                /* Transfer CoreFoundation +1 ownership directly into ARC via CFBridgingRelease:
                 * zero manual CFRelease (eliminates double-release risk) and zero leaks even on
                 * exception unwind with -fobjc-arc-exceptions. */
                id owned_block_buf = (raw_block_buf != NULL) ? CFBridgingRelease(raw_block_buf) : nil;
                raw_block_buf = NULL;
                if (st == noErr && abl->mNumberBuffers > 0
                    && abl->mNumberBuffers <= ZD_SCK_MAX_AUDIO_BUFFERS) {
                    ZdSckAudioBuffer bufs[ZD_SCK_MAX_AUDIO_BUFFERS];
                    uint32_t count = abl->mNumberBuffers;
                    for (uint32_t i = 0; i < count; i++) {
                        bufs[i].data = (const uint8_t*)abl->mBuffers[i].mData;
                        bufs[i].byte_len = abl->mBuffers[i].mDataByteSize;
                        bufs[i].channels = abl->mBuffers[i].mNumberChannels;
                    }
                    g_zd_sck_in_callback = 1;
                    @try {
                        h->audio_cb(
                            h->user_ctx,
                            asbd->mSampleRate,
                            asbd->mChannelsPerFrame,
                            asbd->mFormatFlags,
                            asbd->mBitsPerChannel,
                            count,
                            bufs,
                            pts_us
                        );
                    } @finally {
                        g_zd_sck_in_callback = 0;
                    }
                }
                owned_block_buf = nil;
                (void)owned_block_buf;
            }
        } @catch (NSException* ex) {
            os_unfair_lock_lock(&_delegateLock);
            ZdSckHandle* h = _handle;
            if (h != NULL && h->err_cb != NULL
                && atomic_load_explicit(&h->state, memory_order_acquire) == ZD_SCK_STATE_RUNNING) {
                const char* msg = ex.reason ? ex.reason.UTF8String : "NSException in SCK callback";
                g_zd_sck_in_callback = 1;
                @try {
                    h->err_cb(h->user_ctx, ZD_SCK_ERR_INTERNAL, msg);
                } @finally {
                    g_zd_sck_in_callback = 0;
                }
            }
            os_unfair_lock_unlock(&_delegateLock);
        }
    }
}

- (void)stream:(SCStream*)stream didStopWithError:(NSError*)error {
    (void)stream;
    @autoreleasepool {
        @try {
            /* Hold _delegateLock across the short non-blocking err_cb so zd_sck_destroy's
             * [delegate detach] strictly synchronizes with any Apple-internal callback thread
             * and prevents UAF on `h`. */
            os_unfair_lock_lock(&_delegateLock);
            @try {
                ZdSckHandle* h = _handle;
                uint64_t expected_sid = _sessionId;
                if (h != NULL && expected_sid != 0
                    && atomic_load_explicit(&h->session_id, memory_order_acquire) == expected_sid) {
                    uint32_t prev = ZD_SCK_STATE_RUNNING;
                    (void)atomic_compare_exchange_strong_explicit(
                        &h->state,
                        &prev,
                        ZD_SCK_STATE_IDLE,
                        memory_order_acq_rel,
                        memory_order_acquire
                    );
                    if (prev == ZD_SCK_STATE_RUNNING && h->err_cb != NULL) {
                        NSString* formatted = error
                            ? [NSString stringWithFormat:@"SCStream error domain=%@ code=%ld: %@",
                                  error.domain ?: @"unknown",
                                  (long)error.code,
                                  error.localizedDescription ?: @"(no description)"]
                            : @"SCStream stopped with unknown error";
                        /* Always report ZD_SCK_ERR_INTERNAL (never alias raw NSError.code into ZD_SCK_ERR_*). */
                        g_zd_sck_in_callback = 1;
                        @try {
                            h->err_cb(h->user_ctx, ZD_SCK_ERR_INTERNAL, formatted.UTF8String);
                        } @finally {
                            g_zd_sck_in_callback = 0;
                        }
                    }
                }
            } @finally {
                os_unfair_lock_unlock(&_delegateLock);
            }
        } @catch (NSException* ex) {
            (void)ex;
        }
    }
}

@end

int32_t zd_sck_preflight_permission(void) {
    /* Non-interactive check ONLY: NEVER invoke CGRequestScreenCaptureAccess(). */
    return CGPreflightScreenCaptureAccess() ? 1 : 0;
}

ZdSckHandle* zd_sck_create(
    const ZdSckConfig* cfg,
    ZdSckVideoCallback video_cb,
    ZdSckAudioCallback audio_cb,
    ZdSckErrorCallback err_cb,
    void* user_ctx
) {
    if (cfg == NULL) {
        return NULL;
    }
    @autoreleasepool {
        ZdSckHandle* h = (ZdSckHandle*)calloc(1, sizeof(ZdSckHandle));
        if (h == NULL) {
            return NULL;
        }
        h->cfg = *cfg;
        h->video_cb = video_cb;
        h->audio_cb = audio_cb;
        h->err_cb = err_cb;
        h->user_ctx = user_ctx;

        h->stream_lock = OS_UNFAIR_LOCK_INIT;
        h->video_queue = dispatch_queue_create("com.zerodesk.sck.video", DISPATCH_QUEUE_SERIAL);
        h->audio_queue = dispatch_queue_create("com.zerodesk.sck.audio", DISPATCH_QUEUE_SERIAL);
        h->stop_queue = dispatch_queue_create("com.zerodesk.sck.stop", DISPATCH_QUEUE_SERIAL);

        dispatch_queue_set_specific(h->video_queue, kZdCallbackQueueKey, (void*)kZdCallbackQueueKey, NULL);
        dispatch_queue_set_specific(h->audio_queue, kZdCallbackQueueKey, (void*)kZdCallbackQueueKey, NULL);
        dispatch_queue_set_specific(h->video_queue, kZdVideoQueueKey, (void*)kZdVideoQueueKey, NULL);
        dispatch_queue_set_specific(h->audio_queue, kZdAudioQueueKey, (void*)kZdAudioQueueKey, NULL);
        dispatch_queue_set_specific(h->stop_queue, kZdStopQueueKey, (void*)kZdStopQueueKey, NULL);

        h->delegate = [[ZdSckDelegate alloc] initWithHandle:h];
        atomic_init(&h->state, ZD_SCK_STATE_IDLE);
        atomic_init(&h->session_id, 0);
        atomic_init(&h->active_width, 0);
        atomic_init(&h->active_height, 0);
        return h;
    }
}

static void zd_sck_revert_starting_to_idle(ZdSckHandle* h) {
    uint32_t expected_starting = ZD_SCK_STATE_STARTING;
    (void)atomic_compare_exchange_strong_explicit(
        &h->state,
        &expected_starting,
        ZD_SCK_STATE_IDLE,
        memory_order_acq_rel,
        memory_order_acquire
    );
}

static void zd_sck_cleanup_orphan_stream(ZdSckHandle* h, SCStream* stream, uint64_t my_gen) {
    uint64_t expected_gen = my_gen;
    (void)atomic_compare_exchange_strong_explicit(
        &h->session_id,
        &expected_gen,
        my_gen + 1,
        memory_order_acq_rel,
        memory_order_acquire
    );
    [h->delegate armForSession:0];

    NSError* rem_err = nil;
    [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeScreen error:&rem_err];
    if (h->cfg.capture_audio != 0) {
        [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeAudio error:&rem_err];
    }

    os_unfair_lock_lock(&h->stream_lock);
    if (h->stream == stream) {
        h->stream = nil;
    }
    os_unfair_lock_unlock(&h->stream_lock);

    dispatch_async(h->stop_queue, ^{
        [stream stopCaptureWithCompletionHandler:^(NSError* stop_err) {
            (void)stop_err;
        }];
    });
    zd_sck_revert_starting_to_idle(h);
}

int32_t zd_sck_start(ZdSckHandle* h) {
    if (h == NULL) {
        return ZD_SCK_ERR_INVALID_ARG;
    }
    /* CAS Idle -> Starting; refuse restart while Running, Starting, Stopping, or StopTimedOut. */
    uint32_t expected = ZD_SCK_STATE_IDLE;
    if (!atomic_compare_exchange_strong_explicit(
            &h->state,
            &expected,
            ZD_SCK_STATE_STARTING,
            memory_order_acq_rel,
            memory_order_acquire)) {
        if (expected == ZD_SCK_STATE_RUNNING || expected == ZD_SCK_STATE_STARTING) {
            return ZD_SCK_ERR_ALREADY_RUNNING;
        }
        return ZD_SCK_ERR_INTERNAL;
    }

    /* Stamp unique start generation right after entering STARTING so any concurrent stop
     * invalidating session_id is reliably detected before publishing h->stream or RUNNING. */
    uint64_t my_gen = atomic_fetch_add_explicit(&h->session_id, 1, memory_order_acq_rel) + 1;

    /* Mandatory non-interactive preflight BEFORE touching SCShareableContent. */
    if (!CGPreflightScreenCaptureAccess()) {
        zd_sck_revert_starting_to_idle(h);
        return ZD_SCK_ERR_PERMISSION;
    }

    @autoreleasepool {
        ZdSckAsyncBox* content_box = [[ZdSckAsyncBox alloc] init];
        [SCShareableContent getShareableContentExcludingDesktopWindows:NO
                                                   onScreenWindowsOnly:YES
                                                     completionHandler:^(SCShareableContent* content, NSError* error) {
            [content_box completeWithResult:content error:error];
        }];

        id raw_content = nil;
        NSError* content_err = nil;
        BOOL got_content = [content_box
            waitUntil:dispatch_time(DISPATCH_TIME_NOW, ZD_SCK_START_TIMEOUT_NS)
            outResult:&raw_content
             outError:&content_err];
        SCShareableContent* captured_content = (SCShareableContent*)raw_content;
        if (!got_content || content_err != nil || captured_content == nil) {
            zd_sck_revert_starting_to_idle(h);
            return ZD_SCK_ERR_START_FAILED;
        }

        if (atomic_load_explicit(&h->session_id, memory_order_acquire) != my_gen
            || atomic_load_explicit(&h->state, memory_order_acquire) != ZD_SCK_STATE_STARTING) {
            zd_sck_revert_starting_to_idle(h);
            return ZD_SCK_ERR_START_FAILED;
        }

        NSArray<SCDisplay*>* displays = captured_content.displays;
        if (displays == nil || displays.count == 0) {
            zd_sck_revert_starting_to_idle(h);
            return ZD_SCK_ERR_NO_DISPLAY;
        }
        NSUInteger idx = (h->cfg.display_index < displays.count) ? h->cfg.display_index : 0;
        SCDisplay* display = displays[idx];

        uint32_t raw_w = (h->cfg.width > 0) ? h->cfg.width : (uint32_t)display.width;
        uint32_t raw_h = (h->cfg.height > 0) ? h->cfg.height : (uint32_t)display.height;
        uint32_t target_w = zd_clamp_even(raw_w, 32u, 1920u);
        uint32_t target_h = zd_clamp_even(raw_h, 32u, 1080u);
        uint32_t fps = (h->cfg.fps == 0) ? 30u : h->cfg.fps;
        if (fps > 120u) {
            fps = 120u;
        }

        SCStreamConfiguration* sc_cfg = [[SCStreamConfiguration alloc] init];
        sc_cfg.width = target_w;
        sc_cfg.height = target_h;
        sc_cfg.pixelFormat = kCVPixelFormatType_32BGRA;
        sc_cfg.minimumFrameInterval = CMTimeMake(1, (int32_t)fps);
        sc_cfg.queueDepth = 3;
        sc_cfg.showsCursor = YES;
        sc_cfg.capturesAudio = (h->cfg.capture_audio != 0);
        sc_cfg.excludesCurrentProcessAudio = (h->cfg.exclude_self_audio != 0);
        sc_cfg.sampleRate = 48000;
        sc_cfg.channelCount = 2;

        SCContentFilter* filter = [[SCContentFilter alloc] initWithDisplay:display
                                                          excludingWindows:@[]];
        SCStream* stream = [[SCStream alloc] initWithFilter:filter
                                              configuration:sc_cfg
                                                   delegate:h->delegate];
        if (stream == nil) {
            zd_sck_revert_starting_to_idle(h);
            return ZD_SCK_ERR_START_FAILED;
        }

        NSError* add_err = nil;
        if (![stream addStreamOutput:h->delegate
                                type:SCStreamOutputTypeScreen
                  sampleHandlerQueue:h->video_queue
                               error:&add_err]) {
            zd_sck_revert_starting_to_idle(h);
            return ZD_SCK_ERR_START_FAILED;
        }
        if (h->cfg.capture_audio != 0) {
            NSError* audio_err = nil;
            if (![stream addStreamOutput:h->delegate
                                    type:SCStreamOutputTypeAudio
                      sampleHandlerQueue:h->audio_queue
                                   error:&audio_err]) {
                NSError* rem_err = nil;
                [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeScreen error:&rem_err];
                zd_sck_revert_starting_to_idle(h);
                return ZD_SCK_ERR_START_FAILED;
            }
        }

        /* Re-verify generation + STARTING state before publishing h->stream under stream_lock. */
        os_unfair_lock_lock(&h->stream_lock);
        BOOL still_starting =
            (atomic_load_explicit(&h->session_id, memory_order_acquire) == my_gen
             && atomic_load_explicit(&h->state, memory_order_acquire) == ZD_SCK_STATE_STARTING);
        if (still_starting) {
            h->stream = stream;
        }
        os_unfair_lock_unlock(&h->stream_lock);
        if (!still_starting) {
            zd_sck_cleanup_orphan_stream(h, stream, my_gen);
            return ZD_SCK_ERR_START_FAILED;
        }

        [h->delegate armForSession:my_gen];
        atomic_store_explicit(&h->active_width, target_w, memory_order_release);
        atomic_store_explicit(&h->active_height, target_h, memory_order_release);

        ZdSckAsyncBox* start_box = [[ZdSckAsyncBox alloc] init];
        [stream startCaptureWithCompletionHandler:^(NSError* error) {
            [start_box completeWithResult:nil error:error];
        }];

        NSError* start_err = nil;
        BOOL got_start = [start_box
            waitUntil:dispatch_time(DISPATCH_TIME_NOW, ZD_SCK_START_TIMEOUT_NS)
            outResult:NULL
             outError:&start_err];
        if (!got_start || start_err != nil) {
            zd_sck_cleanup_orphan_stream(h, stream, my_gen);
            return ZD_SCK_ERR_START_FAILED;
        }

        /* CAS STARTING -> RUNNING only if our generation is still current (never clobber STOPPING). */
        uint32_t expected_starting = ZD_SCK_STATE_STARTING;
        if (atomic_load_explicit(&h->session_id, memory_order_acquire) != my_gen
            || !atomic_compare_exchange_strong_explicit(
                &h->state,
                &expected_starting,
                ZD_SCK_STATE_RUNNING,
                memory_order_acq_rel,
                memory_order_acquire)) {
            zd_sck_cleanup_orphan_stream(h, stream, my_gen);
            return ZD_SCK_ERR_START_FAILED;
        }
        return ZD_SCK_OK;
    }
}

int32_t zd_sck_stop(ZdSckHandle* h, uint32_t timeout_ms) {
    if (h == NULL) {
        return ZD_SCK_ERR_INVALID_ARG;
    }
    /* Re-entrancy guard: never stop synchronously from inside ANY video/audio/error callback. */
    if (g_zd_sck_in_callback || dispatch_get_specific(kZdCallbackQueueKey) != NULL) {
        return ZD_SCK_ERR_INVALID_ARG;
    }

    @autoreleasepool {
        uint32_t cur = atomic_load_explicit(&h->state, memory_order_acquire);
        while (cur == ZD_SCK_STATE_RUNNING || cur == ZD_SCK_STATE_STARTING) {
            if (atomic_compare_exchange_weak_explicit(
                    &h->state,
                    &cur,
                    ZD_SCK_STATE_STOPPING,
                    memory_order_acq_rel,
                    memory_order_acquire)) {
                break;
            }
        }
        if (cur == ZD_SCK_STATE_IDLE) {
            return ZD_SCK_OK;
        }
        if (cur == ZD_SCK_STATE_STOPPING) {
            return ZD_SCK_OK;
        }
        if (cur == ZD_SCK_STATE_STOP_TIMED_OUT) {
            return ZD_SCK_ERR_STOP_TIMEOUT;
        }

        /* Bump session_id immediately so any queued stale callbacks drop without invoking Rust. */
        (void)atomic_fetch_add_explicit(&h->session_id, 1, memory_order_acq_rel);
        [h->delegate armForSession:0];

        os_unfair_lock_lock(&h->stream_lock);
        SCStream* stream = h->stream;
        h->stream = nil;
        os_unfair_lock_unlock(&h->stream_lock);

        uint32_t effective_ms = (timeout_ms == 0) ? ZD_SCK_DEFAULT_STOP_TIMEOUT_MS : timeout_ms;
        int32_t result = ZD_SCK_OK;

        if (stream != nil) {
            ZdSckAsyncBox* stop_box = [[ZdSckAsyncBox alloc] init];
            /* Capture only ObjC objects in the async block (never raw `h` pointer). */
            dispatch_async(h->stop_queue, ^{
                [stream stopCaptureWithCompletionHandler:^(NSError* error) {
                    [stop_box completeWithResult:nil error:error];
                }];
            });

            BOOL stopped = [stop_box
                waitUntil:dispatch_time(DISPATCH_TIME_NOW, (int64_t)effective_ms * NSEC_PER_MSEC)
                outResult:NULL
                 outError:NULL];
            if (!stopped) {
                result = ZD_SCK_ERR_STOP_TIMEOUT;
            }

            NSError* rem_err = nil;
            [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeScreen error:&rem_err];
            if (h->cfg.capture_audio != 0) {
                [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeAudio error:&rem_err];
            }
        }

        /* Drain in-flight video/audio callbacks on our serial queues. */
        if (dispatch_get_specific(kZdVideoQueueKey) != kZdVideoQueueKey) {
            dispatch_sync(h->video_queue, ^{});
        }
        if (dispatch_get_specific(kZdAudioQueueKey) != kZdAudioQueueKey) {
            dispatch_sync(h->audio_queue, ^{});
        }

        if (result == ZD_SCK_ERR_STOP_TIMEOUT) {
            atomic_store_explicit(&h->state, ZD_SCK_STATE_STOP_TIMED_OUT, memory_order_release);
        } else {
            atomic_store_explicit(&h->state, ZD_SCK_STATE_IDLE, memory_order_release);
        }
        return result;
    }
}

void zd_sck_destroy(ZdSckHandle* h) {
    if (h == NULL) {
        return;
    }
    /* Refuse re-entrant destroy from inside any callback thread/queue to prevent
     * re-locking _delegateLock (os_unfair_lock abort) or self-deadlocking dispatch_sync. */
    if (g_zd_sck_in_callback || dispatch_get_specific(kZdCallbackQueueKey) != NULL) {
        return;
    }
    (void)zd_sck_stop(h, ZD_SCK_DEFAULT_STOP_TIMEOUT_MS);
    @autoreleasepool {
        /* Detach delegate under _delegateLock BEFORE draining queues and freeing `h`,
         * guaranteeing zero UAF even if Apple delivers didStopWithError on a private thread. */
        if (h->delegate != nil) {
            [h->delegate detach];
        }
        if (h->stop_queue != nil && dispatch_get_specific(kZdStopQueueKey) != kZdStopQueueKey) {
            dispatch_sync(h->stop_queue, ^{});
        }
        if (h->video_queue != nil && dispatch_get_specific(kZdVideoQueueKey) != kZdVideoQueueKey) {
            dispatch_sync(h->video_queue, ^{});
        }
        if (h->audio_queue != nil && dispatch_get_specific(kZdAudioQueueKey) != kZdAudioQueueKey) {
            dispatch_sync(h->audio_queue, ^{});
        }

        os_unfair_lock_lock(&h->stream_lock);
        h->stream = nil;
        os_unfair_lock_unlock(&h->stream_lock);

        h->delegate = nil;
        h->video_queue = nil;
        h->audio_queue = nil;
        h->stop_queue = nil;
        free(h);
    }
}

int32_t zd_sck_get_dimensions(
    const ZdSckHandle* h,
    uint32_t* out_width,
    uint32_t* out_height
) {
    if (h == NULL || out_width == NULL || out_height == NULL) {
        return ZD_SCK_ERR_INVALID_ARG;
    }
    *out_width = atomic_load_explicit(&h->active_width, memory_order_acquire);
    *out_height = atomic_load_explicit(&h->active_height, memory_order_acquire);
    return ZD_SCK_OK;
}

/* Weak fallback for scrap::quartz::Display::scale() so standalone staticlib/XCFramework
 * consumers (e.g. ZeroDeskApp SwiftUI) resolve BackingScaleFactor without colliding with
 * strong definitions in Rust CLI binaries or RustDesk's macos.mm. */
__attribute__((weak)) float BackingScaleFactor(uint32_t display) {
    CGDisplayModeRef mode = CGDisplayCopyDisplayMode((CGDirectDisplayID)display);
    if (mode == NULL) {
        return 1.0f;
    }
    size_t pixel_w = CGDisplayModeGetPixelWidth(mode);
    CGDisplayModeRelease(mode);
    size_t point_w = CGDisplayPixelsWide((CGDirectDisplayID)display);
    if (point_w == 0 || pixel_w == 0) {
        return 1.0f;
    }
    float scale = (float)pixel_w / (float)point_w;
    return (scale > 1.0f) ? scale : 1.0f;
}
