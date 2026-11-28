// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import CoreGraphics
import Foundation

/// Explicit coordinate origin convention for incoming view coordinates.
public enum CoordinateOrigin: Sendable, Equatable {
    /// AppKit `NSView` default coordinate space (`(0, 0)` at bottom-left, `+y` upward).
    case bottomLeft
    /// SwiftUI / CoreGraphics coordinate space (`(0, 0)` at top-left, `+y` downward).
    case topLeft
}

/// Dimensions of the remote desktop framebuffer in pixels.
public struct RemoteSize: Sendable, Equatable {
    public let width: Int
    public let height: Int

    public init(width: Int, height: Int) {
        self.width = width
        self.height = height
    }

    public var isValid: Bool {
        width > 0 && height > 0
    }

    public var cgSize: CGSize {
        CGSize(width: width, height: height)
    }
}

/// Mapped absolute coordinate in top-left remote desktop pixel space.
public struct RemotePoint: Sendable, Equatable {
    public let x: Int
    public let y: Int

    public init(x: Int, y: Int) {
        self.x = x
        self.y = y
    }
}

/// Display scaling mode for `RemoteMetalView` and `RemoteCoordinateMapper`.
public enum DisplayScaleMode: String, Codable, Sendable, CaseIterable, Equatable {
    case fit
    case actual1to1
    case fill

    public var displayLabel: String {
        switch self {
        case .fit: return "Fit"
        case .actual1to1: return "1:1"
        case .fill: return "Fill"
        }
    }
}

/// Pure-value single-source viewport state shared by `RemoteCoordinateMapper`, `MetalVideoRenderer`,
/// and `InputGate`.
public struct ViewportState: Sendable, Equatable {
    public let mode: DisplayScaleMode
    /// Backing pixel size of the rendering view (`bounds.size * backingScale` / `MTKView.drawableSize`).
    public let viewBackingSize: CGSize
    /// Decoded remote framebuffer pixel size (`width × height`).
    public let frameSize: CGSize
    /// Top-left scroll offset in backing pixels (active in `.actual1to1` when frame exceeds view).
    public let scrollOffset: CGPoint

    public init(
        mode: DisplayScaleMode = .fit,
        viewBackingSize: CGSize,
        frameSize: CGSize,
        scrollOffset: CGPoint = .zero
    ) {
        self.mode = mode
        self.viewBackingSize = viewBackingSize
        self.frameSize = frameSize
        self.scrollOffset = scrollOffset
    }

    public var isValid: Bool {
        let vw = Double(viewBackingSize.width)
        let vh = Double(viewBackingSize.height)
        let fw = Double(frameSize.width)
        let fh = Double(frameSize.height)
        return vw.isFinite && vh.isFinite && fw.isFinite && fh.isFinite
            && vw > 0 && vh > 0 && fw >= 1 && fh >= 1
    }
}

/// Single-source computed geometry shared by BOTH `RemoteCoordinateMapper` and `MetalVideoRenderer`.
public struct ViewportGeometry: Sendable, Equatable {
    public let mode: DisplayScaleMode
    /// Effective pixel scale (`backingPixels / framePixels`).
    public let scale: Double
    /// Full rendered frame rectangle in top-left backing pixel space (may extend beyond view in `.fill` / `.actual1to1`).
    public let renderedFrameRect: CGRect
    /// Intersection of `renderedFrameRect` with `[0, viewW] × [0, viewH]` in top-left backing pixels.
    public let visibleBackingRect: CGRect
    /// Maximum horizontal scroll offset in backing pixels (`> 0` only when `.actual1to1` overflows X).
    public let maxScrollX: Double
    /// Maximum vertical scroll offset in backing pixels (`> 0` only when `.actual1to1` overflows Y).
    public let maxScrollY: Double
    /// Clamped scroll offset actually applied in top-left backing pixels.
    public let clampedScrollOffset: CGPoint
    /// Metal NDC scale & offset uniforms (`positions * scale + offset`).
    public let ndcScaleX: Float
    public let ndcScaleY: Float
    public let ndcOffsetX: Float
    public let ndcOffsetY: Float

    public var canScrollLocally: Bool {
        mode == .actual1to1 && (maxScrollX > 0 || maxScrollY > 0)
    }
}

/// Computed centered aspect-preserving letterbox geometry inside a view (Phase 7B compatibility).
public struct LetterboxLayout: Sendable, Equatable {
    /// Uniform scale factor `min(viewWidth / remoteWidth, viewHeight / remoteHeight)`.
    public let scale: Double
    /// Rendered video rectangle in top-left view coordinates.
    public let videoRect: CGRect
    /// Normalized Metal NDC half-extents (`renderedWidth / viewWidth`, `renderedHeight / viewHeight`).
    public let ndcScaleX: Float
    public let ndcScaleY: Float

    public init(scale: Double, videoRect: CGRect, ndcScaleX: Float, ndcScaleY: Float) {
        self.scale = scale
        self.videoRect = videoRect
        self.ndcScaleX = ndcScaleX
        self.ndcScaleY = ndcScaleY
    }
}

/// Single source of truth for ALL coordinate transforms (`Fit` / `1:1` / `Fill`) and Metal render
/// uniforms. All intermediate calculations strictly use `Double`, with ONE single rounding helper
/// applied at the final step.
public struct RemoteCoordinateMapper: Sendable {
    private static let boundaryEps: Double = 1e-9

    /// Single final-step rounding helper converting continuous frame coordinates to `[0, maxIndex]`.
    private static func roundAndClampPixel(_ value: Double, maxIndex: Int) -> Int {
        let idx = Int(floor(value))
        return min(max(idx, 0), maxIndex)
    }

    /// Computes exact 3-mode geometry and Metal NDC uniforms from a `ViewportState`.
    public static func computeGeometry(for viewport: ViewportState) -> ViewportGeometry? {
        guard viewport.isValid else {
            return nil
        }

        let vw = Double(viewport.viewBackingSize.width)
        let vh = Double(viewport.viewBackingSize.height)
        let fw = Double(viewport.frameSize.width)
        let fh = Double(viewport.frameSize.height)

        let scale: Double
        switch viewport.mode {
        case .fit:
            scale = min(vw / fw, vh / fh)
        case .fill:
            scale = max(vw / fw, vh / fh)
        case .actual1to1:
            scale = 1.0
        }

        let renderedW = fw * scale
        let renderedH = fh * scale

        let originX: Double
        let originY: Double
        let maxScrollX: Double
        let maxScrollY: Double
        let clampedScrollX: Double
        let clampedScrollY: Double

        switch viewport.mode {
        case .fit, .fill:
            maxScrollX = 0.0
            maxScrollY = 0.0
            clampedScrollX = 0.0
            clampedScrollY = 0.0
            originX = (vw - renderedW) * 0.5
            originY = (vh - renderedH) * 0.5

        case .actual1to1:
            let rawScrollX = Double(viewport.scrollOffset.x).isFinite ? Double(viewport.scrollOffset.x) : 0.0
            let rawScrollY = Double(viewport.scrollOffset.y).isFinite ? Double(viewport.scrollOffset.y) : 0.0

            if renderedW > vw {
                maxScrollX = renderedW - vw
                clampedScrollX = min(max(rawScrollX, 0.0), maxScrollX)
                originX = -clampedScrollX
            } else {
                maxScrollX = 0.0
                clampedScrollX = 0.0
                originX = (vw - renderedW) * 0.5
            }

            if renderedH > vh {
                maxScrollY = renderedH - vh
                clampedScrollY = min(max(rawScrollY, 0.0), maxScrollY)
                originY = -clampedScrollY
            } else {
                maxScrollY = 0.0
                clampedScrollY = 0.0
                originY = (vh - renderedH) * 0.5
            }
        }

        let renderedRect = CGRect(x: originX, y: originY, width: renderedW, height: renderedH)
        let visMinX = max(0.0, originX)
        let visMinY = max(0.0, originY)
        let visMaxX = min(vw, originX + renderedW)
        let visMaxY = min(vh, originY + renderedH)
        let visibleRect = CGRect(
            x: visMinX,
            y: visMinY,
            width: max(0.0, visMaxX - visMinX),
            height: max(0.0, visMaxY - visMinY)
        )

        let centerX = originX + renderedW * 0.5
        let centerY = originY + renderedH * 0.5
        let ndcScaleX = Float(renderedW / vw)
        let ndcScaleY = Float(renderedH / vh)
        let ndcOffsetX = Float((centerX / vw) * 2.0 - 1.0)
        let ndcOffsetY = Float(1.0 - (centerY / vh) * 2.0)

        return ViewportGeometry(
            mode: viewport.mode,
            scale: scale,
            renderedFrameRect: renderedRect,
            visibleBackingRect: visibleRect,
            maxScrollX: maxScrollX,
            maxScrollY: maxScrollY,
            clampedScrollOffset: CGPoint(x: clampedScrollX, y: clampedScrollY),
            ndcScaleX: ndcScaleX,
            ndcScaleY: ndcScaleY,
            ndcOffsetX: ndcOffsetX,
            ndcOffsetY: ndcOffsetY
        )
    }

    /// Maps a point in backing pixels to remote desktop pixel coordinates `[0, fw-1] × [0, fh-1]`.
    ///
    /// - Strictly returns `nil` for letterbox/pillarbox regions in `.fit` (or non-overflow `.actual1to1`),
    ///   and for points outside `[0, viewW] × [0, viewH]` — NEVER dispatches or clamps to edge.
    public static func mapBackingPoint(
        _ backingPoint: CGPoint,
        in viewport: ViewportState,
        origin: CoordinateOrigin = .bottomLeft
    ) -> RemotePoint? {
        guard backingPoint.x.isFinite, backingPoint.y.isFinite,
              let geo = computeGeometry(for: viewport) else {
            return nil
        }

        let vw = Double(viewport.viewBackingSize.width)
        let vh = Double(viewport.viewBackingSize.height)
        let fw = Int(viewport.frameSize.width.rounded(.towardZero))
        let fh = Int(viewport.frameSize.height.rounded(.towardZero))
        guard fw >= 1, fh >= 1 else {
            return nil
        }

        let tx = Double(backingPoint.x)
        let ty: Double
        switch origin {
        case .topLeft:
            ty = Double(backingPoint.y)
        case .bottomLeft:
            ty = vh - Double(backingPoint.y)
        }

        // Point must lie inside both the visible view bounds AND the rendered video rect.
        let visMinX = Double(geo.visibleBackingRect.minX)
        let visMaxX = Double(geo.visibleBackingRect.maxX)
        let visMinY = Double(geo.visibleBackingRect.minY)
        let visMaxY = Double(geo.visibleBackingRect.maxY)

        let insideView = tx >= -boundaryEps && tx <= (vw + boundaryEps)
            && ty >= -boundaryEps && ty <= (vh + boundaryEps)
        let insideVisibleFrame = tx >= (visMinX - boundaryEps) && tx <= (visMaxX + boundaryEps)
            && ty >= (visMinY - boundaryEps) && ty <= (visMaxY + boundaryEps)

        guard insideView && insideVisibleFrame else {
            return nil
        }

        let originX = Double(geo.renderedFrameRect.minX)
        let originY = Double(geo.renderedFrameRect.minY)
        let continuousX = (tx - originX) / geo.scale
        let continuousY = (ty - originY) / geo.scale

        let rx = roundAndClampPixel(continuousX, maxIndex: fw - 1)
        let ry = roundAndClampPixel(continuousY, maxIndex: fh - 1)
        return RemotePoint(x: rx, y: ry)
    }

    /// Maps a point in AppKit/SwiftUI view points with an explicit `backingScale` (1x/2x/3x Retina)
    /// to remote desktop pixel coordinates using the single-source `ViewportState`.
    public static func mapViewPoint(
        _ viewPoint: CGPoint,
        backingScale: CGFloat,
        in viewport: ViewportState,
        origin: CoordinateOrigin = .bottomLeft
    ) -> RemotePoint? {
        guard backingScale.isFinite, backingScale > 0,
              viewPoint.x.isFinite, viewPoint.y.isFinite else {
            return nil
        }
        let scaleD = Double(backingScale)
        let backingPt = CGPoint(
            x: Double(viewPoint.x) * scaleD,
            y: Double(viewPoint.y) * scaleD
        )
        return mapBackingPoint(backingPt, in: viewport, origin: origin)
    }

    /// Inverse transform: maps a remote desktop pixel center `(x + 0.5, y + 0.5)` into local view
    /// backing pixel coordinates. Returns `nil` if the remote pixel is outside the currently visible
    /// viewport (e.g., cropped off in `.fill` or scrolled out of view in `.actual1to1`).
    public static func mapRemoteToBackingPoint(
        _ remotePoint: RemotePoint,
        in viewport: ViewportState,
        origin: CoordinateOrigin = .bottomLeft
    ) -> CGPoint? {
        guard let geo = computeGeometry(for: viewport) else {
            return nil
        }
        let fw = Int(viewport.frameSize.width.rounded(.towardZero))
        let fh = Int(viewport.frameSize.height.rounded(.towardZero))
        guard remotePoint.x >= 0, remotePoint.x < fw,
              remotePoint.y >= 0, remotePoint.y < fh else {
            return nil
        }

        let vw = Double(viewport.viewBackingSize.width)
        let vh = Double(viewport.viewBackingSize.height)
        let originX = Double(geo.renderedFrameRect.minX)
        let originY = Double(geo.renderedFrameRect.minY)

        let tx = originX + (Double(remotePoint.x) + 0.5) * geo.scale
        let tyTop = originY + (Double(remotePoint.y) + 0.5) * geo.scale

        guard tx >= -boundaryEps && tx <= (vw + boundaryEps)
            && tyTop >= -boundaryEps && tyTop <= (vh + boundaryEps) else {
            return nil
        }

        let outY: Double
        switch origin {
        case .topLeft:
            outY = tyTop
        case .bottomLeft:
            outY = vh - tyTop
        }
        return CGPoint(x: tx, y: outY)
    }

    /// Inverse transform returning AppKit/SwiftUI view points for a given `backingScale` (1x/2x/3x).
    public static func mapRemoteToViewPoint(
        _ remotePoint: RemotePoint,
        backingScale: CGFloat,
        in viewport: ViewportState,
        origin: CoordinateOrigin = .bottomLeft
    ) -> CGPoint? {
        guard backingScale.isFinite, backingScale > 0,
              let backingPt = mapRemoteToBackingPoint(remotePoint, in: viewport, origin: origin) else {
            return nil
        }
        let invScale = 1.0 / Double(backingScale)
        return CGPoint(x: Double(backingPt.x) * invScale, y: Double(backingPt.y) * invScale)
    }

    // MARK: - Phase 7B Backward-Compatible Fit Helpers

    public static func computeLayout(
        viewSize: CGSize,
        remoteSize: RemoteSize
    ) -> LetterboxLayout? {
        guard remoteSize.isValid else { return nil }
        let vp = ViewportState(
            mode: .fit,
            viewBackingSize: viewSize,
            frameSize: remoteSize.cgSize
        )
        guard let geo = computeGeometry(for: vp) else {
            return nil
        }
        return LetterboxLayout(
            scale: geo.scale,
            videoRect: geo.renderedFrameRect,
            ndcScaleX: geo.ndcScaleX,
            ndcScaleY: geo.ndcScaleY
        )
    }

    public static func mapPoint(
        _ viewPoint: CGPoint,
        viewSize: CGSize,
        remoteSize: RemoteSize,
        origin: CoordinateOrigin = .bottomLeft,
        isDragging: Bool = false
    ) -> RemotePoint? {
        guard viewPoint.x.isFinite, viewPoint.y.isFinite, remoteSize.isValid else {
            return nil
        }
        let vp = ViewportState(
            mode: .fit,
            viewBackingSize: viewSize,
            frameSize: remoteSize.cgSize
        )
        if !isDragging {
            return mapBackingPoint(viewPoint, in: vp, origin: origin)
        }
        guard let geo = computeGeometry(for: vp) else {
            return nil
        }
        let tx = Double(viewPoint.x)
        let ty: Double
        switch origin {
        case .topLeft:
            ty = Double(viewPoint.y)
        case .bottomLeft:
            ty = Double(viewSize.height) - Double(viewPoint.y)
        }
        let relX = (tx - Double(geo.renderedFrameRect.minX)) / geo.scale
        let relY = (ty - Double(geo.renderedFrameRect.minY)) / geo.scale
        return RemotePoint(
            x: roundAndClampPixel(relX, maxIndex: remoteSize.width - 1),
            y: roundAndClampPixel(relY, maxIndex: remoteSize.height - 1)
        )
    }

    public static func mapPoint(
        _ viewPoint: CGPoint,
        viewSize: CGSize,
        backingScale: CGFloat,
        remoteSize: RemoteSize,
        origin: CoordinateOrigin = .bottomLeft,
        isDragging: Bool = false
    ) -> RemotePoint? {
        guard backingScale.isFinite, backingScale > 0 else {
            return nil
        }
        let scaleD = Double(backingScale)
        let scaledPoint = CGPoint(x: Double(viewPoint.x) * scaleD, y: Double(viewPoint.y) * scaleD)
        let scaledSize = CGSize(width: Double(viewSize.width) * scaleD, height: Double(viewSize.height) * scaleD)
        return mapPoint(
            scaledPoint,
            viewSize: scaledSize,
            remoteSize: remoteSize,
            origin: origin,
            isDragging: isDragging
        )
    }
}
