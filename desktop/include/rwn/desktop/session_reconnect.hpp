#pragma once
#include <algorithm>
#include <chrono>
#include <optional>

namespace rwn::desktop {
// A new session always owns fresh decoder/framebuffer/control/clipboard state.
// A stable authenticated session earns a new bounded retry window; a flapping
// peer does not reset the budget merely by accepting another connection.
class SessionReconnectPolicy {
public:
    using Clock=std::chrono::steady_clock;
    void connected(Clock::time_point now){connected_at_=now;}
    std::optional<std::chrono::milliseconds> interrupted(Clock::time_point now){
        using namespace std::chrono;
        if(connected_at_ && now>=*connected_at_+seconds{30}){window_.reset();attempts_=0;}
        connected_at_.reset();
        if(!window_)window_=now;
        if(now<*window_ || now>=*window_+seconds{60} || attempts_>=6)return {};
        const auto delay=seconds{1U<<std::min(attempts_,3U)};
        if(now+delay>*window_+seconds{60})return {};
        ++attempts_;return duration_cast<milliseconds>(delay);
    }
    unsigned attempts()const noexcept{return attempts_;}
private:
    std::optional<Clock::time_point> connected_at_,window_;
    unsigned attempts_{};
};
}
