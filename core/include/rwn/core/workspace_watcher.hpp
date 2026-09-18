#pragma once

#include "rwn/core/identity.hpp"

#include <chrono>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class WorkspaceTriggerKind {
    added,
    removed,
    modified,
    renamed_from,
    renamed_to,
    overflow,
};

struct WorkspaceTrigger {
    WorkspaceTriggerKind kind{WorkspaceTriggerKind::modified};
    std::string path;
};

class ChangeDebouncer {
public:
    explicit ChangeDebouncer(std::chrono::milliseconds quiet_period);
    void notify(WorkspaceTrigger trigger, TimePoint now);
    [[nodiscard]] std::vector<WorkspaceTrigger> take_ready(TimePoint now);

private:
    struct Pending {
        WorkspaceTrigger trigger;
        TimePoint observed_at{};
    };
    std::chrono::milliseconds quiet_period_;
    std::map<std::string, Pending, std::less<>> pending_;
};

}  // namespace rwn::core
