// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import Foundation

/// Discrete integer wheel step ready for `0x01 InputHID` `MouseEvent(Wheel)`.
public struct ScrollStep: Sendable, Equatable {
    public let wheelDx: Int16
    public let wheelDy: Int16

    public init(wheelDx: Int16, wheelDy: Int16) {
        self.wheelDx = wheelDx
        self.wheelDy = wheelDy
    }
}

/// Quantizes macOS scroll wheel / trackpad deltas into discrete remote wheel ticks:
/// - Strictly discards momentum phase (`momentumPhaseRaw != 0`).
/// - Accumulates sub-tick precise trackpad deltas until crossing `preciseStepThreshold`
///   and resets fractional remainders on gesture end/cancel or `reset()`.
/// - Honors `isDirectionInvertedFromDevice`.
public struct ScrollQuantizer: Sendable, Equatable {
    /// Matches `NSEvent.Phase.ended.rawValue` (4) and `NSEvent.Phase.cancelled.rawValue` (8).
    public static let phaseEndedRaw: UInt = 1 << 2
    public static let phaseCancelledRaw: UInt = 1 << 3

    public let preciseStepThreshold: Double
    private var remainderX: Double = 0
    private var remainderY: Double = 0

    public init(preciseStepThreshold: Double = 10.0) {
        self.preciseStepThreshold = max(1.0, preciseStepThreshold)
    }

    public var pendingRemainderX: Double { remainderX }
    public var pendingRemainderY: Double { remainderY }

    public mutating func reset() {
        remainderX = 0
        remainderY = 0
    }

    public mutating func process(
        deltaX: Double,
        deltaY: Double,
        hasPreciseScrollingDeltas: Bool,
        momentumPhaseRaw: UInt,
        isDirectionInvertedFromDevice: Bool,
        phaseRaw: UInt = 0
    ) -> ScrollStep? {
        // Strictly discard macOS momentum inertia events.
        if momentumPhaseRaw != 0 {
            return nil
        }
        guard deltaX.isFinite, deltaY.isFinite else {
            return nil
        }

        let sign: Double = isDirectionInvertedFromDevice ? -1.0 : 1.0
        let sx = deltaX * sign
        let sy = deltaY * sign

        let stepX: Int16
        let stepY: Int16

        if hasPreciseScrollingDeltas {
            remainderX += sx
            remainderY += sy

            let rawStepsX = (remainderX / preciseStepThreshold).rounded(.towardZero)
            let rawStepsY = (remainderY / preciseStepThreshold).rounded(.towardZero)

            remainderX -= rawStepsX * preciseStepThreshold
            remainderY -= rawStepsY * preciseStepThreshold

            stepX = Self.clampToInt16(rawStepsX)
            stepY = Self.clampToInt16(rawStepsY)

            let gestureEnded = (phaseRaw & (Self.phaseEndedRaw | Self.phaseCancelledRaw)) != 0
            if gestureEnded {
                reset()
            }
        } else {
            reset()
            stepX = Self.quantizeDiscrete(sx)
            stepY = Self.quantizeDiscrete(sy)
        }

        if stepX == 0 && stepY == 0 {
            return nil
        }
        return ScrollStep(wheelDx: stepX, wheelDy: stepY)
    }

    private static func quantizeDiscrete(_ value: Double) -> Int16 {
        if value == 0 {
            return 0
        }
        let rounded = value.rounded(.toNearestOrAwayFromZero)
        if rounded == 0 {
            return value > 0 ? 1 : -1
        }
        return clampToInt16(rounded)
    }

    private static func clampToInt16(_ value: Double) -> Int16 {
        if value >= Double(Int16.max) {
            return Int16.max
        }
        if value <= Double(Int16.min) {
            return Int16.min
        }
        return Int16(value)
    }
}
