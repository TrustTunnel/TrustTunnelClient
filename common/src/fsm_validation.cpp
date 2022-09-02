#include <cassert>
#include <unordered_map>

#include "common/logger.h"
#include "vpn/fsm.h"
#include "vpn/utils.h"

namespace std {
template <>
struct hash<ag::FsmTransitionEntry> {
    size_t operator()(const ag::FsmTransitionEntry &e) const {
        return size_t(ag::hash_pair_combine(std::hash<ag::FsmState>{}(e.src_state), std::hash<ag::FsmEvent>{}(e.event)));
    }
};
} // namespace std

namespace ag {

#ifndef NDEBUG

static inline bool operator==(const ag::FsmTransitionEntry &lh, const ag::FsmTransitionEntry &rh) {
    return lh.src_state == rh.src_state && lh.event == rh.event;
}

struct EntryValidationInfo {
    bool closed = false; // entry with the same (src_state, event) pair is closed by Fsm::OTHERWISE or Fsm::ANYWAY
};

bool Fsm::validate_transition_table(const FsmTransitionTable &table) {
    bool result = true;

    ag::Logger log{"FSM_VALIDATOR"};

    std::unordered_map<FsmTransitionEntry, EntryValidationInfo> validation_table;

    for (const auto &entry : table) {
        if (entry.src_state == Fsm::SAME_TARGET_STATE) {
            errlog(log, "Transition entry can't have SAME_STATE as source state");
            result = false;
            goto loop_exit;
        }

        if (entry.target_state == Fsm::ANY_SOURCE_STATE) {
            errlog(log, "Transition entry can't have ANY_STATE as target state");
            result = false;
            goto loop_exit;
        }

        EntryValidationInfo &info = validation_table[entry];
        if (info.closed) {
            errlog(log, "Entry with the same (src_state, event) pair is already closed: ({}, {})", entry.src_state,
                    entry.event);
            result = false;
            goto loop_exit;
        }

        info.closed = entry.condition == Fsm::ANYWAY || entry.condition == Fsm::OTHERWISE;
    }

loop_exit:

    return result;
}

#else

bool Fsm::validate_transition_table(const FsmTransitionTable &) {
    return true;
}

#endif // NDEBUG

} // namespace ag
