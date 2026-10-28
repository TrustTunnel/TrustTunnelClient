//
//  main.swift
//  SystemExtension
//
//  Created by Sergey Fionov on 28.10.2026.
//

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
