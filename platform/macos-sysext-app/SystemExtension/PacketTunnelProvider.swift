//
//  PacketTunnelProvider.swift
//  SystemExtension
//
//  All tunnel behavior (routes/DNS/MTU from the config, the C++ core, reconnects,
//  connection info, logs) is inherited from `AGPacketTunnelProvider` in the
//  TrustTunnelClient pod.
//

import TrustTunnelClient

class PacketTunnelProvider: AGPacketTunnelProvider {}
