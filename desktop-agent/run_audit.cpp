#include "run_audit.hpp"
#include "rwn/desktop/desktop.hpp"
#include <mutex>
#include <stdexcept>
#include <utility>

namespace rwn::agent {
namespace detail {
struct RunAuditState {
    std::mutex mutex;
    bool scope_live{true},supported{},ever_owned{},pending{},finished{},abandoned{};
    RunAuditResult result;
    RunAuditResult final_result;
    std::function<void()> listener_ready;
    bool listener_notified{};
};
}
namespace {
std::mutex active_mutex;
std::shared_ptr<detail::RunAuditState> active;
std::shared_ptr<detail::RunAuditState> current() {
    std::lock_guard lock(active_mutex);return active;
}
}
RunAudit::RunAudit(std::function<void()> listener_ready) {
    std::lock_guard lock(active_mutex);
    if(active){
        std::lock_guard state_lock(active->mutex);
        if(active->scope_live || active->pending)throw std::logic_error("agent invocation already owns input audit");
    }
    state_=std::make_shared<detail::RunAuditState>();state_->listener_ready=std::move(listener_ready);active=state_;
}
RunAudit::~RunAudit() {
    std::lock_guard lock(active_mutex);
    std::lock_guard state_lock(state_->mutex);
    state_->scope_live=false;
    if(active==state_ && !state_->pending)active.reset();
}
RunAuditResult RunAudit::finish() noexcept {
    std::lock_guard lock(state_->mutex);
    if(state_->finished)return state_->final_result;
    state_->finished=true;
    if(!state_->supported || state_->pending || state_->abandoned)return {};
    state_->final_result=state_->ever_owned?state_->result:RunAuditResult{InputExit::never_started,0,0};
    return state_->final_result;
}
void observe_stream_endpoint() {
    if(auto state=current()){
        std::lock_guard lock(state->mutex);
        if(!state->scope_live || state->finished)throw std::logic_error("agent endpoint started after completion");
        state->supported=true;
    }
}
void observe_listener_ready() {
    if(auto state=current()){
        std::function<void()> notify;
        {
            std::lock_guard lock(state->mutex);
            if(!state->scope_live || state->finished || !state->supported)
                throw std::logic_error("listener readiness outside supported invocation");
            if(state->listener_notified)return;
            state->listener_notified=true;notify=state->listener_ready;
        }
        if(notify)notify();
    }
}
void request_cli_permission(desktop::DesktopPermissionBackend& permissions,bool input) {
    if(auto state=current()){
        std::lock_guard lock(state->mutex);
        if(state->scope_live)return;
    }
    if(input)permissions.request_input();else permissions.request_capture();
}
InputOwnerAudit::InputOwnerAudit():state_(current()) {
    if(!state_)return;
    std::lock_guard lock(state_->mutex);
    if(!state_->scope_live || state_->finished || state_->ever_owned)throw std::logic_error("input owner exceeds audited invocation");
    state_->ever_owned=true;state_->pending=true;
}
InputOwnerAudit::~InputOwnerAudit() {
    if(finished_ || !state_)return;
    std::lock_guard lock(state_->mutex);
    state_->abandoned=true;state_->pending=false;
}
RunAuditResult InputOwnerAudit::finish_on_owner(desktop::InputReceiver& receiver) noexcept {
    if(finished_)return result_;
    auto receipt=receiver.close();
    std::size_t released=receipt.released;
    if(receipt.remaining){receipt=receiver.close();released+=receipt.released;}
    result_={receipt.remaining?InputExit::failed:InputExit::released,released,receipt.remaining};
    finished_=true;
    if(state_){
        std::lock_guard lock(state_->mutex);
        state_->result=result_;state_->pending=false;
    }
    return result_;
}
} // namespace rwn::agent
