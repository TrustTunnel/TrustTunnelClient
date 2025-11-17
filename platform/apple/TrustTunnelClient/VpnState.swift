// This should be always synced with `VpnSessionState`
enum VpnState : Int {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case waiting_for_recovery = 3
    case recovering = 4
    case waiting_for_network = 5
}
