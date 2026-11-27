// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#import "macos_sck.h"

#import <CoreAudio/CoreAudio.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define ZD_SCK_MAX_AUDIO_BUFFERS 8
#define ZD_SCK_DEFAULT_STOP_TIMEOUT_MS 2000u
#define ZD_SCK_START_TIMEOUT_NS (3LL * NSEC_PER_SEC)

static const void* kZdVideoQueueKey = &kZdVideoQueueKey;
static const void* kZdAudioQueueKey = &kZdAudioQueueKey;

@interface ZdSckDelegate : NSObject <SCStreamDelegate, SCStreamOutput>
@property (nonatomic, assign) ZdSckHandle* handle;
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

    SCStream* stream;
    ZdSckDelegate* delegate;

    _Atomic uint8_t running;
    _Atomic uint8_t stopping;
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

- (void)stream:(SCStream*)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type {
    (void)stream;
    @autoreleasepool {
        @try {
            ZdSckHandle* h = self.handle;
            if (h == NULL || sampleBuffer == NULL) {
                return;
            }
            if (atomic_load_explicit(&h->stopping, memory_order_acquire) != 0) {
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
                const uint8_t* base = (const uint8_t*)CVPixelBufferGetBaseAddress(pb);
                size_t width = CVPixelBufferGetWidth(pb);
                size_t height = CVPixelBufferGetHeight(pb);
                size_t bpr = CVPixelBufferGetBytesPerRow(pb);
                if (base != NULL && width > 0 && height > 0 && bpr >= width * 4
                    && width <= UINT32_MAX && height <= UINT32_MAX && bpr <= UINT32_MAX) {
                    atomic_store_explicit(&h->active_width, (uint32_t)width, memory_order_release);
                    atomic_store_explicit(&h->active_height, (uint32_t)height, memory_order_release);
                    h->video_cb(
                        h->user_ctx,
                        base,
                        (uint32_t)width,
                        (uint32_t)height,
                        (uint32_t)bpr,
                        scale,
                        pts_us
                    );
                }
                CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
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
                CMBlockBufferRef block_buf = NULL;
                size_t needed_size = 0;

                OSStatus st = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
                    sampleBuffer,
                    &needed_size,
                    abl,
                    sizeof(abl_storage),
                    NULL,
                    NULL,
                    kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment,
                    &block_buf
                );
                if (st == noErr && abl->mNumberBuffers > 0
                    && abl->mNumberBuffers <= ZD_SCK_MAX_AUDIO_BUFFERS) {
                    ZdSckAudioBuffer bufs[ZD_SCK_MAX_AUDIO_BUFFERS];
                    uint32_t count = abl->mNumberBuffers;
                    for (uint32_t i = 0; i < count; i++) {
                        bufs[i].data = (const uint8_t*)abl->mBuffers[i].mData;
                        bufs[i].byte_len = abl->mBuffers[i].mDataByteSize;
                        bufs[i].channels = abl->mBuffers[i].mNumberChannels;
                    }
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
                }
                if (block_buf != NULL) {
                    CFRelease(block_buf);
                }
            }
        } @catch (NSException* ex) {
            ZdSckHandle* h = self.handle;
            if (h != NULL && h->err_cb != NULL
                && atomic_load_explicit(&h->stopping, memory_order_acquire) == 0) {
                const char* msg = ex.reason ? ex.reason.UTF8String : "NSException in SCK callback";
                h->err_cb(h->user_ctx, ZD_SCK_ERR_INTERNAL, msg);
            }
        }
    }
}

- (void)stream:(SCStream*)stream didStopWithError:(NSError*)error {
    (void)stream;
    @autoreleasepool {
        @try {
            ZdSckHandle* h = self.handle;
            if (h == NULL) {
                return;
            }
            atomic_store_explicit(&h->running, 0, memory_order_release);
            if (atomic_load_explicit(&h->stopping, memory_order_acquire) != 0) {
                return;
            }
            if (h->err_cb != NULL) {
                int32_t code = error ? (int32_t)error.code : ZD_SCK_ERR_INTERNAL;
                const char* msg = error && error.localizedDescription
                    ? error.localizedDescription.UTF8String
                    : "SCStream stopped with error";
                h->err_cb(h->user_ctx, code, msg);
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

        h->video_queue = dispatch_queue_create("com.zerodesk.sck.video", DISPATCH_QUEUE_SERIAL);
        h->audio_queue = dispatch_queue_create("com.zerodesk.sck.audio", DISPATCH_QUEUE_SERIAL);
        h->stop_queue = dispatch_queue_create("com.zerodesk.sck.stop", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(h->video_queue, kZdVideoQueueKey, (void*)kZdVideoQueueKey, NULL);
        dispatch_queue_set_specific(h->audio_queue, kZdAudioQueueKey, (void*)kZdAudioQueueKey, NULL);

        h->delegate = [[ZdSckDelegate alloc] init];
        h->delegate.handle = h;
        atomic_init(&h->running, 0);
        atomic_init(&h->stopping, 0);
        atomic_init(&h->active_width, 0);
        atomic_init(&h->active_height, 0);
        return h;
    }
}

int32_t zd_sck_start(ZdSckHandle* h) {
    if (h == NULL) {
        return ZD_SCK_ERR_INVALID_ARG;
    }
    if (atomic_load_explicit(&h->running, memory_order_acquire) != 0) {
        return ZD_SCK_ERR_ALREADY_RUNNING;
    }
    /* Mandatory non-interactive preflight BEFORE touching SCShareableContent. */
    if (!CGPreflightScreenCaptureAccess()) {
        return ZD_SCK_ERR_PERMISSION;
    }

    @autoreleasepool {
        __block SCShareableContent* captured_content = nil;
        __block NSError* content_err = nil;
        dispatch_semaphore_t content_sem = dispatch_semaphore_create(0);

        [SCShareableContent getShareableContentExcludingDesktopWindows:NO
                                                   onScreenWindowsOnly:YES
                                                     completionHandler:^(SCShareableContent* content, NSError* error) {
            captured_content = content;
            content_err = error;
            dispatch_semaphore_signal(content_sem);
        }];

        long wait_rc = dispatch_semaphore_wait(
            content_sem,
            dispatch_time(DISPATCH_TIME_NOW, ZD_SCK_START_TIMEOUT_NS)
        );
        if (wait_rc != 0 || content_err != nil || captured_content == nil) {
            return ZD_SCK_ERR_START_FAILED;
        }

        NSArray<SCDisplay*>* displays = captured_content.displays;
        if (displays == nil || displays.count == 0) {
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
            return ZD_SCK_ERR_START_FAILED;
        }

        NSError* add_err = nil;
        if (![stream addStreamOutput:h->delegate
                                type:SCStreamOutputTypeScreen
                  sampleHandlerQueue:h->video_queue
                               error:&add_err]) {
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
                return ZD_SCK_ERR_START_FAILED;
            }
        }

        atomic_store_explicit(&h->stopping, 0, memory_order_release);
        atomic_store_explicit(&h->active_width, target_w, memory_order_release);
        atomic_store_explicit(&h->active_height, target_h, memory_order_release);
        h->stream = stream;

        __block NSError* start_err = nil;
        dispatch_semaphore_t start_sem = dispatch_semaphore_create(0);
        [stream startCaptureWithCompletionHandler:^(NSError* error) {
            start_err = error;
            dispatch_semaphore_signal(start_sem);
        }];

        long start_wait = dispatch_semaphore_wait(
            start_sem,
            dispatch_time(DISPATCH_TIME_NOW, ZD_SCK_START_TIMEOUT_NS)
        );
        if (start_wait != 0 || start_err != nil) {
            h->stream = nil;
            return ZD_SCK_ERR_START_FAILED;
        }

        atomic_store_explicit(&h->running, 1, memory_order_release);
        return ZD_SCK_OK;
    }
}

int32_t zd_sck_stop(ZdSckHandle* h, uint32_t timeout_ms) {
    if (h == NULL) {
        return ZD_SCK_ERR_INVALID_ARG;
    }
    @autoreleasepool {
        atomic_store_explicit(&h->stopping, 1, memory_order_release);
        uint8_t was_running = atomic_exchange_explicit(&h->running, 0, memory_order_acq_rel);
        SCStream* stream = h->stream;
        if (was_running == 0 && stream == nil) {
            return ZD_SCK_OK;
        }

        uint32_t effective_ms = (timeout_ms == 0) ? ZD_SCK_DEFAULT_STOP_TIMEOUT_MS : timeout_ms;
        __block int32_t result = ZD_SCK_OK;

        if (stream != nil) {
            dispatch_semaphore_t stop_sem = dispatch_semaphore_create(0);
            /* Always dispatch stopCaptureWithCompletionHandler onto the dedicated serial stop_queue
             * so stopping from any thread/callback context can never deadlock. */
            dispatch_async(h->stop_queue, ^{
                [stream stopCaptureWithCompletionHandler:^(NSError* error) {
                    (void)error;
                    dispatch_semaphore_signal(stop_sem);
                }];
            });

            long wait_rc = dispatch_semaphore_wait(
                stop_sem,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)effective_ms * NSEC_PER_MSEC)
            );
            if (wait_rc != 0) {
                result = ZD_SCK_ERR_STOP_TIMEOUT;
            }

            NSError* rem_err = nil;
            [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeScreen error:&rem_err];
            if (h->cfg.capture_audio != 0) {
                [stream removeStreamOutput:h->delegate type:SCStreamOutputTypeAudio error:&rem_err];
            }
            h->stream = nil;
        }

        /* Drain any in-flight output callbacks before returning (skip sync if invoked on same queue). */
        if (dispatch_get_specific(kZdVideoQueueKey) != kZdVideoQueueKey) {
            dispatch_sync(h->video_queue, ^{});
        }
        if (dispatch_get_specific(kZdAudioQueueKey) != kZdAudioQueueKey) {
            dispatch_sync(h->audio_queue, ^{});
        }

        return result;
    }
}

void zd_sck_destroy(ZdSckHandle* h) {
    if (h == NULL) {
        return;
    }
    (void)zd_sck_stop(h, ZD_SCK_DEFAULT_STOP_TIMEOUT_MS);
    @autoreleasepool {
        if (h->delegate != nil) {
            h->delegate.handle = NULL;
            h->delegate = nil;
        }
        h->stream = nil;
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
