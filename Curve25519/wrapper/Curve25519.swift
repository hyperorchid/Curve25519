//
//  Curve25519.swift
//  Curve25519
//
//  Created by hyperorchid on 2020/2/23.
//  Copyright © 2020 hyperorchid. All rights reserved.
//

import Foundation
import LibCurve25519

public let CurveKeySize = 32

public extension Data{
        
        mutating func toMutCArray() -> UnsafeMutablePointer<UInt8>?{
                return self.withUnsafeMutableBytes { (data:UnsafeMutableRawBufferPointer) in
                        return data.bindMemory(to: UInt8.self).baseAddress
                }
        }
        
        func toCArray() ->  UnsafePointer<UInt8>?{
                return self.withUnsafeBytes { (data:UnsafeRawBufferPointer) in
                        return data.bindMemory(to: UInt8.self).baseAddress
                }
        }
}

public final class Curve25519: NSObject {
        
        public static func SharedSecret(privateKey:Data, peerPublicKey:Data) -> Data?{
                
                guard privateKey.count == CurveKeySize && peerPublicKey.count == CurveKeySize else {
                        return nil
                }
                
                guard let pri_data = privateKey.toCArray(), let pub_data = peerPublicKey.toCArray() else {
                        return nil
                }
                
                var share_key = Data(repeating: 0, count: CurveKeySize)
                let secret = share_key.toMutCArray()
                
                let ret = LibCurve25519.curve25519_donna(secret, pri_data, pub_data)
                
                assert(ret != 0)
                
                return share_key
        }
        
        public static func MakePrivate(seed: Data? = nil) -> Data?{
                
                if seed == nil{
                        var bytes = [UInt8](repeating: 0, count: CurveKeySize)
                       let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

                       if status != errSecSuccess {
                           return nil
                       }
                       
                       bytes[0] &= 248
                       bytes[31] &= 127
                       bytes[31] |= 64
                       
                       return Data.init(bytes)
                }
               
                var ret = Data.init(seed!)
                ret[0] &= 248
                ret[31] &= 127
                ret[31] |= 64
                return ret
        }
        
        
        public static func GetPub(priKey: Data) -> Data?{
                guard priKey.count == CurveKeySize else{
                        return nil
                }
                var basePoint = Data.init(repeating: 0, count: CurveKeySize)
                basePoint[0] = 9
                
                return SharedSecret(privateKey: priKey, peerPublicKey: basePoint)
        }
}
