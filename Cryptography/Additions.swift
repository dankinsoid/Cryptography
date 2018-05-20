//
//  SHA.swift
//  ExchangeAPI
//
//  Created by Данил Войдилов on 18.05.2018.
//  Copyright © 2018 Данил Войдилов. All rights reserved.
//

import Foundation

infix operator >>>: BitwiseShiftPrecedence
infix operator <<<: BitwiseShiftPrecedence
infix operator &>>>: BitwiseShiftPrecedence
infix operator &<<<: BitwiseShiftPrecedence

extension FixedWidthInteger {
    @inline(__always) public static func >>>(_ lhs: Self, _ rhs: Int) -> Self {
        return (lhs >> rhs) + (lhs << (bitWidth - rhs))
    }
    @inline(__always) public static func <<<(_ lhs: Self, _ rhs: Int) -> Self {
        return (lhs << rhs) + (lhs >> (bitWidth - rhs))
    }
    @inline(__always) public static func &>>>(_ lhs: Self, _ rhs: Int) -> Self {
        let r = rhs % bitWidth
        return (lhs >> r) + (lhs << (bitWidth - r))
    }
    @inline(__always) public static func &<<<(_ lhs: Self, _ rhs: Int) -> Self {
        let r = rhs % bitWidth
        return (lhs << r) + (lhs >> (bitWidth - r))
    }
    
    @inline(__always) public static func represent(_ bytes: [Byte]) -> [Self] {
        let a = bitWidth / 8
        let db = bitWidth - 8
        let cnt = bytes.count % a == 0 ? bytes.count/a : bytes.count/a + 1
        var result = [Self](repeating: 0, count: cnt)
        for i in 0..<cnt {
            let start = i * a
            for j in 0..<Swift.min(bytes.count - start, a) {
                let s = start + j
                result[i] += (Self(bytes[s]) << (db - j * 8))
            }
        }
        return result
    }
}


extension Array where Element: FixedWidthInteger {
    
    @inline(__always) static func ^(_ lhs: [Element], _ rhs: [Element]) -> [Element] {
        guard !lhs.isEmpty else { return rhs }
        guard !rhs.isEmpty else { return lhs }
        var result = lhs.count > rhs.count ? lhs : rhs
        for i in 0..<Swift.min(lhs.count, rhs.count) {
            result[i] = lhs[i] ^ rhs[i]
        }
        return result
    }
    
    @inline(__always) static func &(_ lhs: [Element], _ rhs: [Element]) -> [Element] {
        guard !lhs.isEmpty else { return [Element](repeating: 0, count: rhs.count) }
        guard !rhs.isEmpty else { return [Element](repeating: 0, count: lhs.count) }
        var result = [Element](repeating: 0, count: Swift.max(lhs.count, rhs.count))
        for i in 0..<Swift.min(lhs.count, rhs.count) {
            result[i] = lhs[i] & rhs[i]
        }
        return result
    }
    
    @inline(__always) static func |(_ lhs: [Element], _ rhs: [Element]) -> [Element] {
        guard !lhs.isEmpty else { return rhs }
        guard !rhs.isEmpty else { return lhs }
        var result = lhs.count > rhs.count ? lhs : rhs
        for i in 0..<Swift.min(lhs.count, rhs.count) {
            result[i] = lhs[i] | rhs[i]
        }
        return result
    }
    
    @inline(__always) func toBytes() -> [Byte] {
        var result: [Byte] = []
        let db = Element.bitWidth - 8
        let _: [[Byte]] = map {
            for k in 0..<Element.bitWidth / 8 {
                let d = 8 * k
                result.append(UInt8(($0 << d) >> db))
            }
            return result
        }
        return result
    }
}

extension String {
    var hexBytes: [Byte] {
        return utf8.map {
            let a = $0 & 0xf
            let b = $0 >> 6
            let c = ($0 & 0x40) >> 3
            return a + b | c
        }
    }
    
    static func hex(from bytes: [Byte]) -> String {
        return bytes.map { String(($0 >> 4), radix: 16, uppercase: false) + String(($0 << 4) >> 4, radix: 16, uppercase: false) }.joined()
    }
    
    static func hex<T: FixedWidthInteger>(_ from: [T]) -> String {
        let bytes = from.toBytes()
        return hex(from: bytes)
    }
    
}

extension Array {
    public func split(_ cnt: Int) -> [[Element]] {
        guard !isEmpty else { return [] }
        guard count > cnt else { return [self] }
        var result: [[Element]] = []
        let c = count % cnt == 0 ? count : count - 1
        for i in stride(from: 0, to: c, by: cnt) {
            result.append(Array(self[i..<i + cnt]))
        }
        if count != c {
            result.append(Array(suffix(count % cnt)))
        }
        return result
    }
}

