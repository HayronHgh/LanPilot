#pragma once

#include <cmath>
#include <cstdint>
#include <stdexcept>

namespace rwn::desktop {

// Adapter-local click semantics; never coalesces button edges or changes wire data.
class PointerClickTracker {
public:
    void move(double x, double y) noexcept {
        if (std::abs(x - x_) > 4.0 || std::abs(y - y_) > 4.0)
            continuing_ = false;
    }

    std::uint32_t button(std::uint8_t button, bool down, double x, double y,
                         std::uint64_t now_us, std::uint64_t interval_us) {
        if (button < 1 || button > 3 || !std::isfinite(x) || !std::isfinite(y))
            throw std::invalid_argument("invalid click tracker input");
        const auto index = static_cast<unsigned>(button - 1);
        move(x, y);
        if (!down) {
            const auto result = active_[index];
            active_[index] = 0;
            return result ? result : 1;
        }
        const bool follows = continuing_ && button == last_button_ &&
            active_[index] == 0 && now_us >= last_down_us_ &&
            now_us - last_down_us_ <= interval_us;
        // AppKit uses 1/2/3 for single/double/triple selection. Bound long bursts.
        count_ = follows ? (count_ < 3 ? count_ + 1 : 1) : 1;
        last_button_ = button;
        last_down_us_ = now_us;
        x_ = x; y_ = y;
        continuing_ = true;
        active_[index] = count_;
        return count_;
    }

private:
    std::uint32_t active_[3]{};
    std::uint32_t count_{};
    std::uint8_t last_button_{};
    std::uint64_t last_down_us_{};
    double x_{}, y_{};
    bool continuing_{};
};

} // namespace rwn::desktop
