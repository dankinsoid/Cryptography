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

public struct Cryptography {
    private init() {}
    
    public static func hmac<T: Hashing>(key: [Byte], message msg: [Byte], algorithm: T.Type) -> String {
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
        let result = T.hash(oKeyPad + T.hash(iKeyPad + msg))
        return String.hex(from: result)
    }
    
    public static func hmac<T: Hashing>(key stringKey: String, message stringMsg: String, algorithm: T.Type) -> String {
        let key: [Byte] = Array(stringKey.utf8)
        //[0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83]
        let msg = Array(stringMsg.utf8)
        return hmac(key: key, message: msg, algorithm: T.self)
        //print(key.map { String.hex(from: [$0]) }.split(4).map { $0.joined() })
    }
    
}
