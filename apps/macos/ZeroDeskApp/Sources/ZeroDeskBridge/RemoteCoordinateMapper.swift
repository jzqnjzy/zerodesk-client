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

/// Computed centered aspect-preserving letterbox geometry inside a view.
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

/// Pure, scale-invariant aspect-preserving letterbox coordinate mapper between local macOS
/// view coordinates (points or backing pixels, 1x or 2x Retina) and remote desktop pixels.
public struct RemoteCoordinateMapper: Sendable {
    public static func computeLayout(
        viewSize: CGSize,
        remoteSize: RemoteSize
    ) -> LetterboxLayout? {
        let vw = Double(viewSize.width)
        let vh = Double(viewSize.height)
        guard vw.isFinite, vh.isFinite, vw > 0, vh > 0, remoteSize.isValid else {
            return nil
        }
        let rw = Double(remoteSize.width)
        let rh = Double(remoteSize.height)
        let scale = min(vw / rw, vh / rh)
        let renderedW = rw * scale
        let renderedH = rh * scale
        let originX = (vw - renderedW) * 0.5
        let originY = (vh - renderedH) * 0.5
        let rect = CGRect(x: originX, y: originY, width: renderedW, height: renderedH)
        return LetterboxLayout(
            scale: scale,
            videoRect: rect,
            ndcScaleX: Float(renderedW / vw),
            ndcScaleY: Float(renderedH / vh)
        )
    }

    /// Maps a point in local view coordinates to remote desktop pixel coordinates `[0, W-1] × [0, H-1]`.
    ///
    /// - Parameters:
    ///   - viewPoint: Point in the same coordinate units as `viewSize` (points or backing pixels).
    ///   - viewSize: Dimensions of the view.
    ///   - remoteSize: Dimensions of the remote framebuffer in pixels.
    ///   - origin: Explicit origin convention (`.bottomLeft` for AppKit `NSView`, `.topLeft` for SwiftUI).
    ///   - isDragging: When `false`, points outside the letterboxed `videoRect` return `nil` (black bars
    ///     swallow events). When `true` (any mouse button held), out-of-rect points clamp to the nearest
    ///     edge `[0, width - 1] × [0, height - 1]` so drags never drop or leave buttons stuck.
    public static func mapPoint(
        _ viewPoint: CGPoint,
        viewSize: CGSize,
        remoteSize: RemoteSize,
        origin: CoordinateOrigin = .bottomLeft,
        isDragging: Bool = false
    ) -> RemotePoint? {
        guard viewPoint.x.isFinite, viewPoint.y.isFinite else {
            return nil
        }
        guard let layout = computeLayout(viewSize: viewSize, remoteSize: remoteSize) else {
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

        let minX = Double(layout.videoRect.minX)
        let maxX = Double(layout.videoRect.maxX)
        let minY = Double(layout.videoRect.minY)
        let maxY = Double(layout.videoRect.maxY)

        // Small boundary tolerance (1e-9) prevents IEEE-754 1-ULP drops on exact videoRect edges
        // after bottom-left <-> top-left origin conversion while still swallowing all black-bar clicks.
        let eps = 1e-9
        let inside = tx >= (minX - eps) && tx <= (maxX + eps)
            && ty >= (minY - eps) && ty <= (maxY + eps)
        if !inside && !isDragging {
            return nil
        }

        let relX = (tx - minX) / layout.scale
        let relY = (ty - minY) / layout.scale

        let maxRemoteX = Double(remoteSize.width - 1)
        let maxRemoteY = Double(remoteSize.height - 1)
        let clampedX = min(max(floor(relX), 0.0), maxRemoteX)
        let clampedY = min(max(floor(relY), 0.0), maxRemoteY)

        return RemotePoint(x: Int(clampedX), y: Int(clampedY))
    }

    /// Convenience helper accepting a view point in AppKit points and an explicit `backingScale`
    /// (`1.0` or `2.0` Retina) to verify scale-invariance across backing store pixel coordinates.
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
        let scaledPoint = CGPoint(x: viewPoint.x * backingScale, y: viewPoint.y * backingScale)
        let scaledSize = CGSize(width: viewSize.width * backingScale, height: viewSize.height * backingScale)
        return mapPoint(
            scaledPoint,
            viewSize: scaledSize,
            remoteSize: remoteSize,
            origin: origin,
            isDragging: isDragging
        )
    }
}
