#pragma once

#include <utility>

#include "vpn/fsm.h"
#include "vpn/vpn.h"

namespace ag {
namespace vpn_fsm {

enum ConnectEvent {
    CE_DO_CONNECT,          // start the connection procedure
    CE_RETRY_CONNECT,       // start the next attempt of the connection procedure
    CE_PING_READY,          // got locations pinger result
    CE_PING_FAIL,           // location pinging failed
    CE_CLIENT_READY,        // http client successfully connected
    CE_CLIENT_DISCONNECTED, // http client disconnected for some reason
    CE_DO_RECOVERY,         // need to run recovery
    CE_SHUTDOWN,            // shutting down
    CE_NETWORK_CHANGE,      // network has been changed
    CE_START_LISTENING,     // start listening for connections from client
    CE_ABANDON_ENDPOINT,    // current endpoint is notified of being inactive
    CE_COMPLETE_REQUEST,    // complete connection request
};

FsmTransitionTable get_transition_table();

} // namespace vpn_fsm
} // namespace ag
