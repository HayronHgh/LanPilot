#pragma once
#include <cstddef>
#include <memory>
#include <functional>

namespace rwn::desktop { class InputReceiver; class DesktopPermissionBackend; }
namespace rwn::agent {
namespace detail { struct RunAuditState; }
enum class InputExit { unknown, never_started, released, failed };
struct RunAuditResult {
    InputExit input{InputExit::unknown};
    std::size_t released{},remaining{};
};
// One service invocation per process. The caller must finish ONLY after run()
// has returned and destroyed its workers/transports. No OS input is inspected.
class RunAudit {
public:
    explicit RunAudit(std::function<void()> listener_ready={});
    ~RunAudit();
    RunAudit(const RunAudit&)=delete;
    RunAudit& operator=(const RunAudit&)=delete;
    [[nodiscard]] RunAuditResult finish() noexcept;
private:
    std::shared_ptr<detail::RunAuditState> state_;
};
// Records a supported visual endpoint, not permission or peer authentication.
void observe_stream_endpoint();
// Actual native listener-ready state, not command parsing or peer admission.
// The optional managed callback runs synchronously on the caller, never on the
// Network.framework event queue, before accepting input or a peer session.
void observe_listener_ready();
// Compatibility CLI may request consent; a managed background invocation must
// report missing permission and leave the native request to the foreground UI.
void request_cli_permission(desktop::DesktopPermissionBackend&,bool input);
// Construct BEFORE the input worker is scheduled; finish on that worker only.
// Destruction without finish is failed evidence, never an implicit release from
// the main thread. Shared state remains valid even if the caller exits early.
class InputOwnerAudit {
public:
    InputOwnerAudit();
    ~InputOwnerAudit();
    InputOwnerAudit(const InputOwnerAudit&)=delete;
    InputOwnerAudit& operator=(const InputOwnerAudit&)=delete;
    [[nodiscard]] RunAuditResult finish_on_owner(desktop::InputReceiver&) noexcept;
private:
    std::shared_ptr<detail::RunAuditState> state_;
    bool finished_{};
    RunAuditResult result_;
};
} // namespace rwn::agent
