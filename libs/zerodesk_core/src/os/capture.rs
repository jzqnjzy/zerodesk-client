// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{OsCapturePair, OsError, OsScreenCapture, RawCapturedFrame};
use crate::{
    frame::{checked_frame_byte_len, PixelFormat},
    session::{capture::bgra_to_i420_bt601, video::I420Frame},
};

/// Converts a raw BGRA/RGBA buffer with arbitrary `bytes_per_row` stride directly into `I420Frame`
/// via `libyuv` (`scrap::ARGBToI420` / `ABGRToI420`), safely handling Retina HiDPI row padding.
pub fn convert_captured_stride_to_i420(frame: &RawCapturedFrame) -> Result<I420Frame, OsError> {
    let expected = checked_frame_byte_len(frame.width, frame.height, frame.stride)
        .map_err(|e| OsError::InvalidData(e.to_string()))?;
    if frame.data.len() < expected {
        return Err(OsError::InvalidData(format!(
            "captured buffer len {} < stride*height ({expected})",
            frame.data.len()
        )));
    }
    if frame.pixel_format == PixelFormat::Bgra8 {
        bgra_to_i420_bt601(
            &frame.data,
            frame.stride as usize,
            frame.width as usize,
            frame.height as usize,
        )
        .map_err(|e| OsError::CaptureFailed(e.to_string()))
    } else {
        // RGBA8 -> I420 using libyuv ABGRToI420 with explicit stride.
        let w = (frame.width as usize) & !1;
        let h = (frame.height as usize) & !1;
        let uv_w = w / 2;
        let uv_h = h / 2;
        let mut y = vec![0u8; w * h];
        let mut u = vec![0u8; uv_w * uv_h];
        let mut v = vec![0u8; uv_w * uv_h];
        let rc = unsafe {
            scrap::ABGRToI420(
                frame.data.as_ptr(),
                frame.stride as i32,
                y.as_mut_ptr(),
                w as i32,
                u.as_mut_ptr(),
                uv_w as i32,
                v.as_mut_ptr(),
                uv_w as i32,
                w as i32,
                h as i32,
            )
        };
        if rc != 0 {
            return Err(OsError::CaptureFailed(format!("ABGRToI420 failed: {rc}")));
        }
        I420Frame::new(w, h, y, u, v).map_err(|e| OsError::CaptureFailed(e.to_string()))
    }
}

/// Validates CoreGraphics `bitmap_info`, `bits_per_pixel`, and `bits_per_component` and returns
/// the corresponding `PixelFormat`, failing closed on unexpected pixel layouts.
pub fn validate_cg_bitmap_info(
    bitmap_info: u32,
    bits_per_pixel: usize,
    bits_per_component: usize,
) -> Result<PixelFormat, OsError> {
    const K_CG_BITMAP_ALPHA_INFO_MASK: u32 = 0x1F;
    const K_CG_BITMAP_BYTE_ORDER_MASK: u32 = 0x7000;
    const K_CG_BITMAP_BYTE_ORDER_DEFAULT: u32 = 0;
    const K_CG_BITMAP_BYTE_ORDER_32_LITTLE: u32 = 2 << 12;
    const K_CG_BITMAP_BYTE_ORDER_32_BIG: u32 = 4 << 12;
    const K_CG_IMAGE_ALPHA_PREMULTIPLIED_FIRST: u32 = 2;
    const K_CG_IMAGE_ALPHA_NONE_SKIP_FIRST: u32 = 6;
    const K_CG_IMAGE_ALPHA_FIRST: u32 = 4;
    const K_CG_IMAGE_ALPHA_PREMULTIPLIED_LAST: u32 = 1;
    const K_CG_IMAGE_ALPHA_NONE_SKIP_LAST: u32 = 5;
    const K_CG_IMAGE_ALPHA_LAST: u32 = 3;

    if bits_per_pixel != 32 || bits_per_component != 8 {
        return Err(OsError::InvalidData(format!(
            "unsupported CGImage depth: bpp={bits_per_pixel}, bpc={bits_per_component} (expected 32/8)"
        )));
    }
    let alpha = bitmap_info & K_CG_BITMAP_ALPHA_INFO_MASK;
    let byte_order = bitmap_info & K_CG_BITMAP_BYTE_ORDER_MASK;
    match (byte_order, alpha) {
        (
            K_CG_BITMAP_BYTE_ORDER_32_LITTLE,
            K_CG_IMAGE_ALPHA_PREMULTIPLIED_FIRST
            | K_CG_IMAGE_ALPHA_NONE_SKIP_FIRST
            | K_CG_IMAGE_ALPHA_FIRST,
        ) => Ok(PixelFormat::Bgra8),
        (
            K_CG_BITMAP_BYTE_ORDER_32_BIG | K_CG_BITMAP_BYTE_ORDER_DEFAULT,
            K_CG_IMAGE_ALPHA_PREMULTIPLIED_LAST
            | K_CG_IMAGE_ALPHA_NONE_SKIP_LAST
            | K_CG_IMAGE_ALPHA_LAST,
        ) => Ok(PixelFormat::Rgba8),
        _ => Err(OsError::InvalidData(format!(
            "unsupported CGImage bitmap_info={bitmap_info:#x} (byte_order={byte_order:#x}, alpha={alpha:#x})"
        ))),
    }
}

/// Non-interactive screen capture permission preflight (NEVER triggers an OS permission prompt).
pub fn preflight_screen_capture_permission() -> Result<bool, OsError> {
    #[cfg(all(target_os = "macos", feature = "os-sck"))]
    {
        super::sck::preflight_sck_permission()
    }
    #[cfg(all(target_os = "macos", not(feature = "os-sck"), feature = "os-capture"))]
    {
        extern "C" {
            fn CGPreflightScreenCaptureAccess() -> bool;
        }
        Ok(unsafe { CGPreflightScreenCaptureAccess() })
    }
    #[cfg(not(all(target_os = "macos", any(feature = "os-sck", feature = "os-capture"))))]
    {
        Err(OsError::UnsupportedPlatform(
            "os-capture screen permission probe not implemented on this platform",
        ))
    }
}

#[cfg(all(target_os = "macos", feature = "os-capture"))]
mod macos_impl {
    use super::*;
    use crate::os::OsPermission;
    use core_graphics::display::{CGDisplay, CGMainDisplayID};
    use std::ffi::c_void;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGDisplayCreateImage(display: u32) -> *mut c_void;
        fn CGImageRelease(image: *mut c_void);
        fn CGImageGetBitmapInfo(image: *const c_void) -> u32;
        fn CGImageGetBitsPerPixel(image: *const c_void) -> usize;
        fn CGImageGetBitsPerComponent(image: *const c_void) -> usize;
        fn CGImageGetBytesPerRow(image: *const c_void) -> usize;
        fn CGImageGetWidth(image: *const c_void) -> usize;
        fn CGImageGetHeight(image: *const c_void) -> usize;
        fn CGImageGetDataProvider(image: *const c_void) -> *const c_void;
        fn CGDataProviderCopyData(provider: *const c_void) -> *mut c_void;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
        fn CFDataGetLength(data: *const c_void) -> isize;
        fn CFRelease(cf: *const c_void);
    }

    struct OwnedCgImage(*mut c_void);

    impl Drop for OwnedCgImage {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CGImageRelease(self.0) };
            }
        }
    }

    struct OwnedCfData(*mut c_void);

    impl Drop for OwnedCfData {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0 as *const c_void) };
            }
        }
    }

    // Isolated single #[allow(deprecated)] wrapper for macOS CGDisplayCreateImage.
    #[allow(deprecated)]
    fn cg_display_create_image_raw(display_id: u32) -> Option<OwnedCgImage> {
        let ptr = unsafe { CGDisplayCreateImage(display_id) };
        if ptr.is_null() {
            None
        } else {
            Some(OwnedCgImage(ptr))
        }
    }

    pub struct MacOsScreenCapture {
        display_id: u32,
        last_dims: (u32, u32),
    }

    impl MacOsScreenCapture {
        pub fn new() -> Result<Self, OsError> {
            if !preflight_screen_capture_permission()? {
                return Err(OsError::PermissionDenied(OsPermission::ScreenRecording));
            }
            let display_id = unsafe { CGMainDisplayID() };
            let disp = CGDisplay::new(display_id);
            let w = disp.pixels_wide() as u32;
            let h = disp.pixels_high() as u32;
            Ok(Self {
                display_id,
                last_dims: (w, h),
            })
        }
    }

    impl OsScreenCapture for MacOsScreenCapture {
        fn dimensions(&self) -> (u32, u32) {
            self.last_dims
        }

        fn capture_frame(&mut self) -> Result<RawCapturedFrame, OsError> {
            if !preflight_screen_capture_permission()? {
                return Err(OsError::PermissionDenied(OsPermission::ScreenRecording));
            }
            // Preflight succeeded; NULL image MUST return CaptureFailed (retryable), NOT PermissionDenied.
            let img = cg_display_create_image_raw(self.display_id).ok_or_else(|| {
                OsError::CaptureFailed("CGDisplayCreateImage returned NULL".into())
            })?;
            let raw_ptr = img.0 as *const c_void;
            let bitmap_info = unsafe { CGImageGetBitmapInfo(raw_ptr) };
            let bpp = unsafe { CGImageGetBitsPerPixel(raw_ptr) };
            let bpc = unsafe { CGImageGetBitsPerComponent(raw_ptr) };
            let stride = unsafe { CGImageGetBytesPerRow(raw_ptr) };
            let width = unsafe { CGImageGetWidth(raw_ptr) };
            let height = unsafe { CGImageGetHeight(raw_ptr) };

            let pixel_format = validate_cg_bitmap_info(bitmap_info, bpp, bpc)?;
            let width_u32 = u32::try_from(width)
                .map_err(|_| OsError::InvalidData("CGImage width overflow".into()))?;
            let height_u32 = u32::try_from(height)
                .map_err(|_| OsError::InvalidData("CGImage height overflow".into()))?;
            let stride_u32 = u32::try_from(stride)
                .map_err(|_| OsError::InvalidData("CGImage stride overflow".into()))?;
            let expected_len = checked_frame_byte_len(width_u32, height_u32, stride_u32)
                .map_err(|e| OsError::InvalidData(e.to_string()))?;

            let provider = unsafe { CGImageGetDataProvider(raw_ptr) };
            if provider.is_null() {
                return Err(OsError::CaptureFailed("CGImageGetDataProvider returned NULL".into()));
            }
            let cf_data_ptr = unsafe { CGDataProviderCopyData(provider) };
            if cf_data_ptr.is_null() {
                return Err(OsError::CaptureFailed("CGDataProviderCopyData returned NULL".into()));
            }
            let cf_data = OwnedCfData(cf_data_ptr);
            let data_len = unsafe { CFDataGetLength(cf_data.0 as *const c_void) };
            let data_ptr = unsafe { CFDataGetBytePtr(cf_data.0 as *const c_void) };
            if data_ptr.is_null() || data_len < 0 || (data_len as usize) < expected_len {
                return Err(OsError::InvalidData(format!(
                    "CGImage data len {data_len} < expected stride*height ({expected_len})"
                )));
            }
            let bytes = unsafe { std::slice::from_raw_parts(data_ptr, expected_len) };
            self.last_dims = (width_u32, height_u32);
            Ok(RawCapturedFrame {
                width: width_u32,
                height: height_u32,
                stride: stride_u32,
                pixel_format,
                data: bytes.to_vec(),
            })
        }
    }
}

#[cfg(all(target_os = "macos", feature = "os-capture"))]
pub use macos_impl::MacOsScreenCapture;

/// Constructs the platform's native OS screen capture adapter (plus optional ScreenCaptureKit
/// system audio loopback capture on macOS).
///
/// On macOS with `os-sck`: tries ScreenCaptureKit FIRST. If permission is denied or start fails,
/// fails closed UNLESS `legacy_capture_fallback` is explicitly `true`.
pub fn create_os_screen_capture_with_policy(
    capture_audio: bool,
    legacy_capture_fallback: bool,
) -> Result<OsCapturePair, OsError> {
    #[cfg(all(target_os = "macos", feature = "os-sck"))]
    {
        let sck_cfg = super::sck::SckCaptureConfig {
            capture_audio,
            ..super::sck::SckCaptureConfig::default()
        };
        match super::sck::open_sck_capture(sck_cfg) {
            Ok(pair) => Ok(pair),
            Err(sck_err) => {
                if !legacy_capture_fallback {
                    return Err(sck_err);
                }
                #[cfg(feature = "os-capture")]
                {
                    Ok((Box::new(MacOsScreenCapture::new()?), None))
                }
                #[cfg(not(feature = "os-capture"))]
                {
                    Err(sck_err)
                }
            }
        }
    }
    #[cfg(all(target_os = "macos", not(feature = "os-sck"), feature = "os-capture"))]
    {
        let _ = (capture_audio, legacy_capture_fallback);
        Ok((Box::new(MacOsScreenCapture::new()?), None))
    }
    #[cfg(not(all(target_os = "macos", any(feature = "os-sck", feature = "os-capture"))))]
    {
        let _ = (capture_audio, legacy_capture_fallback);
        Err(OsError::UnsupportedPlatform(
            "native screen capture adapter unavailable on this build/platform",
        ))
    }
}

/// Constructs the platform's native OS screen capture adapter (fail-closed; no silent legacy fallback).
pub fn create_os_screen_capture() -> Result<Box<dyn OsScreenCapture>, OsError> {
    create_os_screen_capture_with_policy(false, false).map(|(cap, _)| cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cg_bitmap_info_validation_accepts_bgra_and_rejects_bad_formats() {
        // kCGBitmapByteOrder32Little (2<<12) | kCGImageAlphaPremultipliedFirst (2) -> BGRA8
        assert_eq!(
            validate_cg_bitmap_info((2 << 12) | 2, 32, 8).unwrap(),
            PixelFormat::Bgra8
        );
        // kCGBitmapByteOrder32Big (4<<12) | kCGImageAlphaNoneSkipLast (5) -> RGBA8
        assert_eq!(
            validate_cg_bitmap_info((4 << 12) | 5, 32, 8).unwrap(),
            PixelFormat::Rgba8
        );
        // Wrong depth -> fail-closed
        assert!(validate_cg_bitmap_info((2 << 12) | 2, 16, 5).is_err());
        // Unsupported layout -> fail-closed
        assert!(validate_cg_bitmap_info(0, 32, 8).is_err());
    }

    #[test]
    fn stride_padded_bgra_converts_cleanly_to_i420() {
        // 64x32 BGRA with 32 bytes extra padding per row (stride = 288 instead of 256)
        let w = 64u32;
        let h = 32u32;
        let stride = 288u32;
        let mut data = vec![0u8; (stride as usize) * (h as usize)];
        for row in 0..(h as usize) {
            for col in 0..(w as usize) {
                let off = row * (stride as usize) + col * 4;
                data[off] = 40;
                data[off + 1] = 180;
                data[off + 2] = 220;
                data[off + 3] = 255;
            }
        }
        let raw = RawCapturedFrame {
            width: w,
            height: h,
            stride,
            pixel_format: PixelFormat::Bgra8,
            data,
        };
        let i420 = convert_captured_stride_to_i420(&raw).unwrap();
        assert_eq!(i420.width, 64);
        assert_eq!(i420.height, 32);
        assert!(i420.y.iter().any(|&p| p > 100));
    }
}
