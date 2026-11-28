// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import CoreGraphics
import Foundation
import Metal
import MetalKit
import QuartzCore

/// Lightweight render telemetry exposed for HUD display and benchmark tests.
public struct MetalRenderTelemetry: Sendable, Equatable {
    public let lastUploadAndDrawMs: Double
    public let framesRendered: UInt64
    public let idleFramesSkipped: UInt64
    public let textureAllocations: UInt64
    public let remoteSize: RemoteSize

    public init(
        lastUploadAndDrawMs: Double = 0,
        framesRendered: UInt64 = 0,
        idleFramesSkipped: UInt64 = 0,
        textureAllocations: UInt64 = 0,
        remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)
    ) {
        self.lastUploadAndDrawMs = lastUploadAndDrawMs
        self.framesRendered = framesRendered
        self.idleFramesSkipped = idleFramesSkipped
        self.textureAllocations = textureAllocations
        self.remoteSize = remoteSize
    }
}

public enum MetalVideoRendererError: Error, Sendable, CustomStringConvertible {
    case deviceUnavailable
    case commandQueueUnavailable
    case shaderCompileFailed(String)
    case pipelineCreationFailed(String)
    case samplerCreationFailed

    public var description: String {
        switch self {
        case .deviceUnavailable: return "Metal default device unavailable"
        case .commandQueueUnavailable: return "Metal command queue creation failed"
        case .shaderCompileFailed(let msg): return "Metal shader compilation failed: \(msg)"
        case .pipelineCreationFailed(let msg): return "Metal render pipeline creation failed: \(msg)"
        case .samplerCreationFailed: return "Metal sampler state creation failed"
        }
    }
}

/// GPU video renderer backed by Metal (`MTKViewDelegate`) with:
/// - Embedded MSL vertex + fragment shaders (no external `.metallib` dependency)
/// - Double-buffered `.bgra8Unorm` `MTLTexture` ring rebuilt only on dimension change
/// - Zero GPU render passes when idle (same `frameSeq` and `drawableSize`)
/// - Color-accurate `.bgra8Unorm` output (`CAMetalLayer.colorspace = nil`, EDR disabled)
public final class MetalVideoRenderer: NSObject, MTKViewDelegate, @unchecked Sendable {
    private struct LetterboxUniforms {
        var scaleX: Float
        var scaleY: Float
        var offsetX: Float
        var offsetY: Float
    }

    private static let shaderSource = """
    #include <metal_stdlib>
    using namespace metal;

    struct LetterboxUniforms {
        float2 scale;
        float2 offset;
    };

    struct VertexOut {
        float4 position [[position]];
        float2 texCoord;
    };

    vertex VertexOut zd_video_vertex(
        uint vid [[vertex_id]],
        constant LetterboxUniforms &u [[buffer(0)]]
    ) {
        constexpr float2 positions[4] = {
            float2(-1.0, -1.0),
            float2( 1.0, -1.0),
            float2(-1.0,  1.0),
            float2( 1.0,  1.0)
        };
        constexpr float2 uvs[4] = {
            float2(0.0, 1.0),
            float2(1.0, 1.0),
            float2(0.0, 0.0),
            float2(1.0, 0.0)
        };
        VertexOut out;
        out.position = float4(positions[vid] * u.scale + u.offset, 0.0, 1.0);
        out.texCoord = uvs[vid];
        return out;
    }

    fragment half4 zd_video_fragment(
        VertexOut in [[stage_in]],
        texture2d<half> tex [[texture(0)]],
        sampler smp [[sampler(0)]]
    ) {
        half4 c = tex.sample(smp, in.texCoord);
        return half4(c.rgb, half(1.0));
    }
    """

    public let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let pipelineState: MTLRenderPipelineState
    private let samplerState: MTLSamplerState

    private let stateLock = NSLock()
    private var pendingFrame: CapturedBGRAFrame?
    private var hasActiveFrame: Bool = false
    private var needsClearToBlack: Bool = false
    private var latestSubmittedSeq: UInt64 = 0

    // GPU-thread / synchronized render resources (double-buffered .bgra8Unorm texture ring).
    private let renderLock = NSLock()
    private var textureRing: [MTLTexture?] = [nil, nil]
    private var ringIndex: Int = 0
    private var activeTexture: MTLTexture?
    private var textureWidth: Int = 0
    private var textureHeight: Int = 0
    private var lastUploadedFrameSeq: UInt64 = 0
    private var lastRenderedFrameSeq: UInt64 = 0
    private var lastRenderedDrawableSize: CGSize = .zero
    private var lastRenderedViewportMode: DisplayScaleMode = .fit
    private var lastRenderedScrollOffset: CGPoint = .zero

    // Viewport state protected by stateLock.
    private var _displayScaleMode: DisplayScaleMode = .fit
    private var _scrollOffset: CGPoint = .zero

    // Telemetry counters protected by stateLock.
    private var _lastUploadAndDrawMs: Double = 0
    private var _framesRendered: UInt64 = 0
    private var _idleFramesSkipped: UInt64 = 0
    private var _textureAllocations: UInt64 = 0
    private var _remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)

    public init(device: MTLDevice? = MTLCreateSystemDefaultDevice()) throws {
        guard let mtlDevice = device else {
            throw MetalVideoRendererError.deviceUnavailable
        }
        guard let queue = mtlDevice.makeCommandQueue() else {
            throw MetalVideoRendererError.commandQueueUnavailable
        }

        let library: MTLLibrary
        do {
            library = try mtlDevice.makeLibrary(source: Self.shaderSource, options: nil)
        } catch {
            throw MetalVideoRendererError.shaderCompileFailed("\(error)")
        }

        guard let vertexFn = library.makeFunction(name: "zd_video_vertex"),
              let fragmentFn = library.makeFunction(name: "zd_video_fragment") else {
            throw MetalVideoRendererError.shaderCompileFailed("missing vertex/fragment shader entrypoints")
        }

        let desc = MTLRenderPipelineDescriptor()
        desc.label = "ZeroDeskVideoBGRA"
        desc.vertexFunction = vertexFn
        desc.fragmentFunction = fragmentFn
        desc.colorAttachments[0].pixelFormat = .bgra8Unorm

        let pipeline: MTLRenderPipelineState
        do {
            pipeline = try mtlDevice.makeRenderPipelineState(descriptor: desc)
        } catch {
            throw MetalVideoRendererError.pipelineCreationFailed("\(error)")
        }

        let samplerDesc = MTLSamplerDescriptor()
        samplerDesc.minFilter = .linear
        samplerDesc.magFilter = .linear
        samplerDesc.sAddressMode = .clampToEdge
        samplerDesc.tAddressMode = .clampToEdge
        guard let sampler = mtlDevice.makeSamplerState(descriptor: samplerDesc) else {
            throw MetalVideoRendererError.samplerCreationFailed
        }

        self.device = mtlDevice
        self.commandQueue = queue
        self.pipelineState = pipeline
        self.samplerState = sampler
        super.init()
    }

    /// Configures an `MTKView` for color-accurate 60fps BGRA rendering with zero macOS color shift.
    @MainActor
    public func configure(view: MTKView) {
        view.device = device
        view.delegate = self
        view.colorPixelFormat = .bgra8Unorm
        view.preferredFramesPerSecond = 60
        view.isPaused = false
        view.enableSetNeedsDisplay = false
        view.clearColor = MTLClearColor(red: 0, green: 0, blue: 0, alpha: 1)
        if let metalLayer = view.layer as? CAMetalLayer {
            metalLayer.colorspace = nil
            metalLayer.wantsExtendedDynamicRangeContent = false
        }
    }

    public var telemetry: MetalRenderTelemetry {
        stateLock.lock()
        defer { stateLock.unlock() }
        return MetalRenderTelemetry(
            lastUploadAndDrawMs: _lastUploadAndDrawMs,
            framesRendered: _framesRendered,
            idleFramesSkipped: _idleFramesSkipped,
            textureAllocations: _textureAllocations,
            remoteSize: _remoteSize
        )
    }

    public var lastUploadAndDrawMs: Double {
        telemetry.lastUploadAndDrawMs
    }

    public var framesRendered: UInt64 {
        telemetry.framesRendered
    }

    public var idleFramesSkipped: UInt64 {
        telemetry.idleFramesSkipped
    }

    public func updateViewport(mode: DisplayScaleMode, scrollOffset: CGPoint) {
        let sanitizedOffset: CGPoint
        switch mode {
        case .fit, .fill:
            sanitizedOffset = .zero
        case .actual1to1:
            let x = Double(scrollOffset.x).isFinite ? max(0.0, Double(scrollOffset.x).rounded()) : 0.0
            let y = Double(scrollOffset.y).isFinite ? max(0.0, Double(scrollOffset.y).rounded()) : 0.0
            sanitizedOffset = CGPoint(x: x, y: y)
        }
        stateLock.lock()
        _displayScaleMode = mode
        _scrollOffset = sanitizedOffset
        stateLock.unlock()
    }

    public func currentViewport() -> (mode: DisplayScaleMode, scrollOffset: CGPoint) {
        stateLock.lock()
        defer { stateLock.unlock() }
        return (_displayScaleMode, _scrollOffset)
    }

    public var currentDisplayScaleMode: DisplayScaleMode {
        currentViewport().mode
    }

    public var currentScrollOffset: CGPoint {
        currentViewport().scrollOffset
    }

    /// Submits a newly fetched BGRA frame for GPU upload on the next draw tick.
    public func submitFrame(_ frame: CapturedBGRAFrame) {
        stateLock.lock()
        pendingFrame = frame
        hasActiveFrame = true
        needsClearToBlack = false
        latestSubmittedSeq = frame.seq
        _remoteSize = RemoteSize(width: frame.width, height: frame.height)
        stateLock.unlock()
    }

    /// Clears any displayed remote frame (e.g., on `SessionEnded`), scheduling one black clear frame
    /// and then returning to zero-GPU-work idle.
    public func clearFrame() {
        stateLock.lock()
        pendingFrame = nil
        hasActiveFrame = false
        needsClearToBlack = true
        latestSubmittedSeq = 0
        _remoteSize = RemoteSize(width: 0, height: 0)
        stateLock.unlock()

        renderLock.lock()
        activeTexture = nil
        lastUploadedFrameSeq = 0
        lastRenderedFrameSeq = 0
        renderLock.unlock()
    }

    public func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
        // Drawable size change is detected automatically against `lastRenderedDrawableSize`
        // in `draw(in:)` so resized viewports re-render cleanly without extra state races.
        _ = size
    }

    public func draw(in view: MTKView) {
        let drawableSize = view.drawableSize
        guard drawableSize.width >= 1, drawableSize.height >= 1 else {
            return
        }

        if let metalLayer = view.layer as? CAMetalLayer {
            if metalLayer.colorspace != nil {
                metalLayer.colorspace = nil
            }
            if metalLayer.wantsExtendedDynamicRangeContent {
                metalLayer.wantsExtendedDynamicRangeContent = false
            }
        }

        let startNs = DispatchTime.now().uptimeNanoseconds

        stateLock.lock()
        let incoming = pendingFrame
        let active = hasActiveFrame
        let shouldClear = needsClearToBlack
        let submittedSeq = latestSubmittedSeq
        let mode = _displayScaleMode
        let scrollOffset = _scrollOffset
        stateLock.unlock()

        renderLock.lock()
        defer { renderLock.unlock() }

        if !active {
            if !shouldClear {
                recordIdleSkip()
                return
            }
            guard let passDesc = view.currentRenderPassDescriptor,
                  let drawable = view.currentDrawable,
                  let cmdBuf = commandQueue.makeCommandBuffer(),
                  let encoder = cmdBuf.makeRenderCommandEncoder(descriptor: passDesc) else {
                return
            }
            encoder.endEncoding()
            cmdBuf.present(drawable)
            cmdBuf.commit()

            lastRenderedDrawableSize = drawableSize
            lastRenderedViewportMode = mode
            lastRenderedScrollOffset = scrollOffset
            stateLock.lock()
            needsClearToBlack = false
            _framesRendered &+= 1
            _lastUploadAndDrawMs = Double(DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000.0
            stateLock.unlock()
            return
        }

        // Zero GPU work when idle: unchanged frameSeq, drawableSize, scale mode, and scroll offset.
        if submittedSeq == lastRenderedFrameSeq
            && drawableSize == lastRenderedDrawableSize
            && mode == lastRenderedViewportMode
            && scrollOffset == lastRenderedScrollOffset
            && activeTexture != nil
        {
            recordIdleSkip()
            return
        }

        // Upload pending frame into the alternating slot of the double-buffered texture ring.
        if let frame = incoming, frame.seq != lastUploadedFrameSeq {
            uploadFrameLocked(frame)
            stateLock.lock()
            if pendingFrame?.seq == frame.seq {
                pendingFrame = nil
            }
            stateLock.unlock()
        }

        guard let texture = activeTexture,
              let passDesc = view.currentRenderPassDescriptor,
              let drawable = view.currentDrawable,
              let cmdBuf = commandQueue.makeCommandBuffer() else {
            return
        }

        encodeRenderPass(
            commandBuffer: cmdBuf,
            renderPassDescriptor: passDesc,
            sourceTexture: texture,
            drawableSize: drawableSize,
            mode: mode,
            scrollOffset: scrollOffset
        )
        cmdBuf.present(drawable)
        cmdBuf.commit()

        lastRenderedFrameSeq = lastUploadedFrameSeq
        lastRenderedDrawableSize = drawableSize
        lastRenderedViewportMode = mode
        lastRenderedScrollOffset = scrollOffset
        let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000.0

        stateLock.lock()
        _framesRendered &+= 1
        _lastUploadAndDrawMs = elapsedMs
        stateLock.unlock()
    }

    /// Allocates a `.bgra8Unorm` offscreen target texture suitable for headless rendering & pixel readback.
    public func makeOffscreenTargetTexture(width: Int, height: Int) -> MTLTexture? {
        guard width > 0, height > 0 else { return nil }
        let desc = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .bgra8Unorm,
            width: width,
            height: height,
            mipmapped: false
        )
        desc.usage = [.renderTarget, .shaderRead]
        desc.storageMode = device.hasUnifiedMemory ? .shared : .managed
        return device.makeTexture(descriptor: desc)
    }

    /// Headless offscreen render path exercising the exact same double-buffered BGRA texture upload,
    /// zero-GPU-work idle skip, letterbox uniforms, and Metal render pipeline as `MTKView`.
    public func renderOffscreen(
        frame: CapturedBGRAFrame,
        drawableSize: CGSize,
        targetTexture: MTLTexture,
        waitUntilCompleted: Bool = false
    ) -> (rendered: Bool, elapsedMs: Double) {
        let startNs = DispatchTime.now().uptimeNanoseconds
        let (mode, scrollOffset) = currentViewport()

        renderLock.lock()
        defer { renderLock.unlock() }

        if frame.seq == lastRenderedFrameSeq
            && drawableSize == lastRenderedDrawableSize
            && mode == lastRenderedViewportMode
            && scrollOffset == lastRenderedScrollOffset
            && activeTexture != nil
        {
            recordIdleSkip()
            return (false, 0)
        }

        if frame.seq != lastUploadedFrameSeq {
            uploadFrameLocked(frame)
        }

        guard let sourceTexture = activeTexture,
              let cmdBuf = commandQueue.makeCommandBuffer() else {
            return (false, 0)
        }

        let passDesc = MTLRenderPassDescriptor()
        passDesc.colorAttachments[0].texture = targetTexture
        passDesc.colorAttachments[0].loadAction = .clear
        passDesc.colorAttachments[0].storeAction = .store
        passDesc.colorAttachments[0].clearColor = MTLClearColor(red: 0, green: 0, blue: 0, alpha: 1)

        encodeRenderPass(
            commandBuffer: cmdBuf,
            renderPassDescriptor: passDesc,
            sourceTexture: sourceTexture,
            drawableSize: drawableSize,
            mode: mode,
            scrollOffset: scrollOffset
        )
        cmdBuf.commit()
        if waitUntilCompleted {
            cmdBuf.waitUntilCompleted()
        }

        lastRenderedFrameSeq = lastUploadedFrameSeq
        lastRenderedDrawableSize = drawableSize
        lastRenderedViewportMode = mode
        lastRenderedScrollOffset = scrollOffset
        let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000.0

        stateLock.lock()
        _framesRendered &+= 1
        _lastUploadAndDrawMs = elapsedMs
        _remoteSize = RemoteSize(width: frame.width, height: frame.height)
        stateLock.unlock()

        return (true, elapsedMs)
    }

    private func recordIdleSkip() {
        stateLock.lock()
        _idleFramesSkipped &+= 1
        stateLock.unlock()
    }

    private func ensureTextureRingLocked(width: Int, height: Int) {
        guard width > 0, height > 0 else { return }
        if textureWidth == width && textureHeight == height
            && textureRing[0] != nil && textureRing[1] != nil
        {
            return
        }

        let desc = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .bgra8Unorm,
            width: width,
            height: height,
            mipmapped: false
        )
        desc.usage = [.shaderRead]
        desc.storageMode = device.hasUnifiedMemory ? .shared : .managed

        textureRing[0] = device.makeTexture(descriptor: desc)
        textureRing[1] = device.makeTexture(descriptor: desc)
        textureWidth = width
        textureHeight = height
        ringIndex = 0
        activeTexture = nil

        stateLock.lock()
        _textureAllocations &+= 2
        stateLock.unlock()
    }

    private func uploadFrameLocked(_ frame: CapturedBGRAFrame) {
        guard frame.width > 0, frame.height > 0, frame.stride >= frame.width * 4 else {
            return
        }
        let requiredBytes = (frame.height - 1) * frame.stride + frame.width * 4
        guard frame.data.count >= requiredBytes else {
            return
        }

        ensureTextureRingLocked(width: frame.width, height: frame.height)
        let slot = ringIndex
        ringIndex = (ringIndex + 1) % 2
        guard let texture = textureRing[slot] else {
            return
        }

        let region = MTLRegionMake2D(0, 0, frame.width, frame.height)
        frame.data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            texture.replace(
                region: region,
                mipmapLevel: 0,
                withBytes: base,
                bytesPerRow: frame.stride
            )
        }
        activeTexture = texture
        lastUploadedFrameSeq = frame.seq
    }

    private func encodeRenderPass(
        commandBuffer: MTLCommandBuffer,
        renderPassDescriptor: MTLRenderPassDescriptor,
        sourceTexture: MTLTexture,
        drawableSize: CGSize,
        mode: DisplayScaleMode,
        scrollOffset: CGPoint
    ) {
        guard let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: renderPassDescriptor) else {
            return
        }

        let viewport = ViewportState(
            mode: mode,
            viewBackingSize: drawableSize,
            frameSize: CGSize(width: sourceTexture.width, height: sourceTexture.height),
            scrollOffset: scrollOffset
        )
        let geo = RemoteCoordinateMapper.computeGeometry(for: viewport)
        var uniforms = LetterboxUniforms(
            scaleX: geo?.ndcScaleX ?? 1.0,
            scaleY: geo?.ndcScaleY ?? 1.0,
            offsetX: geo?.ndcOffsetX ?? 0.0,
            offsetY: geo?.ndcOffsetY ?? 0.0
        )

        encoder.setRenderPipelineState(pipelineState)
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<LetterboxUniforms>.stride, index: 0)
        encoder.setFragmentTexture(sourceTexture, index: 0)
        encoder.setFragmentSamplerState(samplerState, index: 0)
        encoder.drawPrimitives(type: .triangleStrip, vertexStart: 0, vertexCount: 4)
        encoder.endEncoding()
    }
}
