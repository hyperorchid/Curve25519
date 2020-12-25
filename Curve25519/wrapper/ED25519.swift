//
//  ED25519.swift
//  Curve25519
//
//  Created by wesley on 2020/12/25.
//  Copyright © 2020 hyperorchid. All rights reserved.
//

import Foundation
import Lib25519

public let EDPubSize = 64
public let EDPriSize = 32


public final class ED25519: NSObject {
        public static func verfiy(sig:Data, message:Data, pubKey:Data) -> Bool{
                
                guard let sig = sig.toCArray(),
                      let msg = message.toCArray(),
                      let pub = pubKey.toCArray() else {
                        return false
                }
                
                return Lib25519.ed25519_verify(sig, msg, message.count, pub) == 0
        }
}
