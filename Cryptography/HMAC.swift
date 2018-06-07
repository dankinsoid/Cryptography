//
//  HMAC.swift
//  SHA
//
//  Created by Данил Войдилов on 19.05.2018.
//  Copyright © 2018 Данил Войдилов. All rights reserved.
//

import Foundation

public typealias Byte = UInt8

public protocol Hashing {
    static var blockSize: Int { get }
    static func hash(_ msg: [Byte]) -> [Byte]
    static func hash(_ msg: String) -> String
}

extension Hashing {
    public static func hash(_ msg: String) -> String {
        return String.hex(from: Self.hash(Array(msg.utf8)))
    }
}

public enum HashAlgorithms {
    case sha1
    case sha256
    case sha512
}

public struct Cryptography {
    private init() {}
    
    public static func hmac<T: Hashing>(key: [Byte], message msg: [Byte], algorithm: T.Type) -> [Byte] {
        var key = key
        let blockSize = T.blockSize
        // Если размер ключа больше, чем размер блока ...
        if key.count > blockSize {
            // Укорачиваем ключ до размера результата хеш-функции
            key = T.hash(key)
            // (Размер результата хеш-функции обычно меньше (а не равен), чем размер блока хеш-функции)
        }
        // Если ключ меньше, чем размер блока хеш-функции ...
        if key.count < blockSize {
            // Дополняем ключ нулевой последовательностью
            key += [Byte](repeating: 0, count: blockSize - key.count)
        }
        let iPad = [Byte](repeating: 0x36, count: blockSize)
        let oPad = [Byte](repeating: 0x5c, count: blockSize)
        let iKeyPad = iPad ^ key
        let oKeyPad = oPad ^ key
        return T.hash(oKeyPad + T.hash(iKeyPad + msg))
    }
    
    public static func hmac<T: Hashing>(key stringKey: String, message stringMsg: String, algorithm: T.Type) -> String {
        let key: [Byte] = Array(stringKey.utf8)
        let msg = Array(stringMsg.utf8)
        return String.hex(from: hmac(key: key, message: msg, algorithm: T.self))
        //print(key.map { String.hex(from: [$0]) }.split(4).map { $0.joined() })
    }
    
    public static func hmac(key stringKey: String, message stringMsg: String, algorithm: HashAlgorithms) -> String {
        switch algorithm {
        case .sha1: return hmac(key: stringKey, message: stringMsg, algorithm: SHA1.self)
        case .sha256: return hmac(key: stringKey, message: stringMsg, algorithm: SHA256.self)
        case .sha512: return hmac(key: stringKey, message: stringMsg, algorithm: SHA512.self)
        }
    }
    
    public static func hash(_ msg: [Byte], algorithm: HashAlgorithms) -> [Byte] {
        switch algorithm {
        case .sha1:   return SHA1.hash(msg)
        case .sha256: return SHA256.hash(msg)
        case .sha512: return SHA512.hash(msg)
        }
    }
    
    public static func hash(_ msg: String, algorithm: HashAlgorithms) -> String {
        switch algorithm {
        case .sha1:   return SHA1.hash(msg)
        case .sha256: return SHA256.hash(msg)
        case .sha512: return SHA512.hash(msg)
        }
    }
}
