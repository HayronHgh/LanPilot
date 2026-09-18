#include "rwn/core/workspace_watcher.hpp"

#include "rwn/core/workspace_sync.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::core {

ChangeDebouncer::ChangeDebouncer(const std::chrono::milliseconds quiet_period)
    : quiet_period_(quiet_period) {
    if (quiet_period_ <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("debounce quiet period must be positive");
    }
}

void ChangeDebouncer::notify(WorkspaceTrigger trigger, const TimePoint now) {
    if (trigger.kind != WorkspaceTriggerKind::overflow &&
        !is_canonical_workspace_path(trigger.path)) {
        throw std::invalid_argument("workspace trigger path is not canonical");
    }
    const auto key = trigger.kind == WorkspaceTriggerKind::overflow
        ? std::string("<overflow>")
        : trigger.path;
    pending_.insert_or_assign(
        key, Pending{.trigger = std::move(trigger), .observed_at = now});
}

std::vector<WorkspaceTrigger> ChangeDebouncer::take_ready(const TimePoint now) {
    std::vector<WorkspaceTrigger> result;
    for (auto iterator = pending_.begin(); iterator != pending_.end();) {
        if (now >= iterator->second.observed_at &&
            now - iterator->second.observed_at >= quiet_period_) {
            result.push_back(std::move(iterator->second.trigger));
            iterator = pending_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    return result;
}

}  // namespace rwn::core
