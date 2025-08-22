#pragma once

#include <sys/qos.h>

namespace ag {

struct VpnQosSettings {
    qos_class_t qos_class = QOS_CLASS_DEFAULT;
    int relative_priority = 0;
};

} // namespace ag
