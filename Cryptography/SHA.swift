//
//  SHA.swift
//  SHA
//
//  Created by Данил Войдилов on 19.05.2018.
//  Copyright © 2018 Данил Войдилов. All rights reserved.
//

import Foundation

public protocol SHA: Hashing {
    associatedtype Word: UnsignedInteger, FixedWidthInteger
    static var origin: [Word] { get }
    //Таблица констант
    static var k: [Word] { get }
    static var iterationsCount: Int { get }
    static func prepare(_ msg: [Byte]) -> [[Word]]
    static func fill(block: [Word]) -> [Word]
    static func mainIteration(constants h: [Word], words w: [Word]) -> [Word]
    static func toBase(_ count: UInt64) -> [Word]
    static func ch(_ x: Word, _ y: Word, _ z: Word) -> Word
    static func maj(_ x: Word, _ y: Word, _ z: Word) -> Word
}

public protocol SHA2: SHA {
    static func sigma0(_ x: Word) -> Word
    static func sigma1(_ x: Word) -> Word
    static func delta0(_ x: Word) -> Word
    static func delta1(_ x: Word) -> Word
}

extension SHA {
    public static func hash(_ msg: [Byte]) -> [Byte] {
        //Пояснения:
        //Все переменные беззнаковые, имеют размер 32 бита и при вычислениях суммируются по модулю 2^32
        //msg — исходное двоичное сообщение
        //Далее сообщение обрабатывается последовательными порциями по 512 бит:
        var splited = prepare(msg)
        var h: [Word] = origin
        for j in 0..<splited.count {
            //Сгенерировать дополнительные слова:
            splited[j] = fill(block: splited[j])
            var h1 = mainIteration(constants: h, words: splited[j])
            //Добавить полученные значения к ранее вычисленному результату:
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        return h.toBytes()
    }
    
    //Предварительная обработка:
    public static func prepare(_ msg: [Byte]) -> [[Word]] {
        //msg — исходное двоичное сообщение
        //m — преобразованное сообщение
        let length = UInt64(msg.count) * 8
        var m = Self.Word.represent(msg + [128])
        let mod = m.count % 16
        let const = mod <= 14 ? 14 - mod : 30 - mod
        m += [Word](repeating: 0, count: const)
        m += toBase(length)
        return m.split(16)
    }
    
    public static func ch(_ x: Word, _ y: Word, _ z: Word) -> Word { return (x & y) ^ (~x & z) }
    public static func maj(_ x: Word, _ y: Word, _ z: Word) -> Word { return (x & y) ^ (x & z) ^ (y & z) }
}

extension SHA2 {
    
    public static func fill(block: [Word]) -> [Word] {
        var b = block
        for i in 16..<iterationsCount {
            let s0 = delta0(b[i-15])
            let s1 = delta1(b[i-2])
            b.append(b[i-16] &+ s0 &+ b[i-7] &+ s1)
        }
        return b
    }
    
    public static func toBase(_ count: UInt64) -> [Word] { return [Word(count >> Word.bitWidth), Word((count << Word.bitWidth) >> Word.bitWidth)] }
    
    public static func mainIteration(constants h: [Word], words w: [Word]) -> [Word] {
        var h1 = h
        for i in 0..<iterationsCount {
            let t1 = h1[7] &+ sigma1(h1[4]) &+ ch(h1[4], h1[5], h1[6]) &+ w[i] &+ k[i]
            let t2 = sigma0(h1[0]) &+ maj(h1[0], h1[1], h1[2])
            h1 = [t1 &+ t2, h1[0], h1[1], h1[2], h1[3] &+ t1, h1[4], h1[5], h1[6]]
        }
        return h1
    }
    public static func sigma0(_ x: Word) -> Word { return (x >>> 2) ^ (x >>> 13) ^ (x >>> 22) }
    public static func sigma1(_ x: Word) -> Word { return (x >>> 6) ^ (x >>> 11) ^ (x >>> 25) }
    public static func delta0(_ x: Word) -> Word { return (x >>> 7) ^ (x >>> 18) ^ (x >> 3) }
    public static func delta1(_ x: Word) -> Word { return (x >>> 17) ^ (x >>> 19) ^ (x >> 10) }
}

public class SHA1: SHA {
    public typealias Word = UInt32
    
    public static let blockSize: Int = 64
    public static let origin: [UInt32] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    public static let k: [UInt32] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]
    public static let iterationsCount: Int = 80
    
    private init() {}
    
    public static func fill(block: [UInt32]) -> [UInt32] {
        var b = block
        for i in 16..<iterationsCount {
            b.append((b[i - 3] ^ b[i - 8] ^ b[i - 14] ^ b[i - 16]) <<< 1)
        }
        return b
    }
    
    public static func mainIteration(constants h: [Word], words w: [Word]) -> [Word] {
        var h1 = h
        for i in 0..<20 {
            let t = (h1[0] <<< 5) &+ ch(h1[1], h1[2], h1[3]) &+ h1[4] &+ w[i] &+ k[0]
            h1 = [t, h1[0], h1[1] <<< 30, h1[2], h1[3]]
        }
        for i in 20..<40 {
            let t = (h1[0] <<< 5) &+ (h1[1] ^ h1[2] ^ h1[3]) &+ h1[4] &+ w[i] &+ k[1]
            h1 = [t, h1[0], h1[1] <<< 30, h1[2], h1[3]]
        }
        for i in 40..<60 {
            let t = (h1[0] <<< 5) &+ maj(h1[1], h1[2], h1[3]) &+ h1[4] &+ w[i] &+ k[2]
            h1 = [t, h1[0], h1[1] <<< 30, h1[2], h1[3]]
        }
        for i in 60..<iterationsCount {
            let t = (h1[0] <<< 5) &+ (h1[1] ^ h1[2] ^ h1[3]) &+ h1[4] &+ w[i] &+ k[3]
            h1 = [t, h1[0], h1[1] <<< 30, h1[2], h1[3]]
        }
        return h1
    }
    
    public static func toBase(_ count: UInt64) -> [UInt32] { return [UInt32(count >> 32), UInt32((count << 32) >> 32)] }
}

public class SHA224: SHA256 {
    
    public static let origin224: [UInt32] = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
    
    public static func hash(_ msg: [Byte]) -> [Byte] {
        var splited = prepare(msg)
        var h: [Word] = origin224
        for j in 0..<splited.count {
            splited[j] = fill(block: splited[j])
            var h1 = mainIteration(constants: h, words: splited[j])
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        return Array(h.dropLast()).toBytes()
    }
}

public class SHA256: SHA2 {
    public typealias Word = UInt32
    public static let iterationsCount: Int = 64
    public static let blockSize: Int = 64
    
    private init() {}
    
    //эти значения представляют собой первые 32 бита дробных частей квадратного корня простых чисел – порядковые номера чисел: первые 8
    public static let origin: [UInt32] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    
    //        Таблица констант
    //        (первые 32 бита дробных частей кубических корней первых 64 простых чисел [от 2 до 311]):
    public static let k: [UInt32] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    ]
}

public class SHA512: SHA2 {
    public typealias Word = UInt64
    public static let iterationsCount: Int = 80
    public static let blockSize: Int = 128
    
    private let origins: [UInt64]
    private var t: Int = 0
    
    private init() {
        t = 0
        origins = []
    }
    
    init(_ t: Int) {
        self.t = t
        let h = SHA512.origin | [UInt64](repeating: 0xA5A5A5A5A5A5A5A5, count: 8)
        origins = SHA512.hash(Array("SHA-512/\(t)".utf8), origin: h)
    }
    
    //эти значения представляют собой первые 64 бита дробных частей квадратного корня простых чисел – порядковые номера чисел: первые 8
    public static let origin: [UInt64] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    
    //Таблица констант
    //(первые 64 бита дробных частей кубических корней первых 80 простых чисел):
    public static let k: [UInt64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ]

    public static func toBase(_ count: UInt64) -> [UInt64] { return [0, count] }
    public static func sigma0(_ x: UInt64) -> UInt64 { return (x >>> 28) ^ (x >>> 34) ^ (x >>> 39) }
    public static func sigma1(_ x: UInt64) -> UInt64 { return (x >>> 14) ^ (x >>> 18) ^ (x >>> 41) }
    public static func delta0(_ x: UInt64) -> UInt64 { return (x >>> 1) ^ (x >>> 8) ^ (x >> 7) }
    public static func delta1(_ x: UInt64) -> UInt64 { return (x >>> 19) ^ (x >>> 61) ^ (x >> 6) }
    
    private static func hash(_ msg: [Byte], origin: [UInt64]) -> [UInt64] {
        var splited = prepare(msg)
        var h: [Word] = origin
        for j in 0..<splited.count {
            splited[j] = fill(block: splited[j])
            var h1 = mainIteration(constants: h, words: splited[j])
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        return h
    }
    
    public func hash(_ msg: [Byte]) -> [Byte] {
        var splited = SHA512.prepare(msg)
        var h: [Word] = origins
        for j in 0..<splited.count {
            splited[j] = SHA512.fill(block: splited[j])
            var h1 = SHA512.mainIteration(constants: h, words: splited[j])
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        return Array(h.toBytes().prefix(t / 8))
    }
}

public class SHA384: SHA512 {

    //эти значения представляют собой первые 64 бита дробных частей квадратного корня простых чисел – порядковые номера чисел: с 9-го по 16-е)
    public static let origin384: [UInt64] = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]
    
    public static func hash(_ msg: [Byte]) -> [Byte] {
        var splited = prepare(msg)
        var h: [Word] = origin384
        for j in 0..<splited.count {
            splited[j] = fill(block: splited[j])
            var h1 = mainIteration(constants: h, words: splited[j])
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        return Array(h[0..<6]).toBytes()
    }
}

public class SHA512_224: SHA512 {
    
    public static let origin224: [UInt64] = [0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1]
    
    public static func hash(_ msg: [Byte]) -> [Byte] {
        var splited = prepare(msg)
        var h: [Word] = origin224
        for j in 0..<splited.count {
            splited[j] = fill(block: splited[j])
            var h1 = mainIteration(constants: h, words: splited[j])
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        var arr = Array(h[0..<3])
        arr.append((h[3] << 32) >> 32)
        return arr.toBytes()
    }
}

public class SHA512_256: SHA512 {
    
    public static let origin256: [UInt64] = [0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2]
    
    public static func hash(_ msg: [Byte]) -> [Byte] {
        var splited = prepare(msg)
        var h: [Word] = origin256
        for j in 0..<splited.count {
            splited[j] = fill(block: splited[j])
            var h1 = mainIteration(constants: h, words: splited[j])
            for i in 0..<h.count { h[i] = h[i] &+ h1[i] }
        }
        return Array(h[0..<4]).toBytes()
    }
}
