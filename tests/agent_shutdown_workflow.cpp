#include "../desktop-agent/shutdown.hpp"
#include "../desktop-agent/stdio_shutdown.hpp"
#include "../desktop-agent/run_audit.hpp"
#include "../desktop-agent/macos/service_runtime.hpp"
#include "rwn/desktop/desktop.hpp"
#include "rwn/core/content_hash.hpp"
#include <chrono>
#include <functional>
#include <iostream>
#include <set>
#include <source_location>
#include <stdexcept>
#include <string_view>
#include <thread>
#if defined(__APPLE__)
#include <csignal>
#include <sys/wait.h>
#endif

namespace {
void check(bool ok,std::source_location where=std::source_location::current()) {
    if (!ok) throw std::runtime_error("agent shutdown assertion failed at line "+std::to_string(where.line()));
}
const rwn::core::AuthorizationResult authorization{
    .principal_matched=true, .workspace_allowed=true,
    .granted={rwn::core::Capability::desktop_control}, .denied={}};
rwn::desktop::InputEvent press(std::uint64_t sequence, std::uint32_t key) {
    return {.kind=rwn::desktop::InputKind::raw_key, .sequence=sequence,
        .occurred_at_us=1, .value_a=key, .pressed=true, .text={}};
}
// No platform backend: these sets are the entire simulated input state.
struct Backend final : rwn::desktop::InputBackend {
    std::set<std::uint32_t> keys;
    std::set<std::uint8_t> buttons;
    unsigned releases{}, failures{};
    std::function<void()> in_press, in_release;
    void raw_key(std::uint32_t usage, bool down) override {
        if (down) { if (in_press) in_press(); keys.insert(usage); }
        else {
            if (in_release) in_release();
            if (failures != 0) { --failures; throw std::runtime_error("simulated release failure"); }
            keys.erase(usage); ++releases;
        }
    }
    void pointer_button(std::uint8_t button, bool down) override {
        if (down) buttons.insert(button); else { buttons.erase(button); ++releases; }
    }
    void text_commit(std::string_view) override { throw std::runtime_error("unexpected text"); }
    void pointer_move(std::uint16_t, std::uint16_t) override { throw std::runtime_error("late pointer"); }
    void pointer_wheel(std::int32_t, bool) override { throw std::runtime_error("late wheel"); }
};
void seed(rwn::desktop::InputReceiver& receiver) {
    check(receiver.receive(press(1,0xe0),true,authorization));
    check(receiver.receive(press(2,4),true,authorization));
    check(receiver.receive({.kind=rwn::desktop::InputKind::pointer_button,
        .sequence=3,.occurred_at_us=1,.value_a=1,.pressed=true,.text={}},true,authorization));
}
void terminal_input() {
    Backend backend;
    rwn::desktop::InputReceiver receiver(backend);
    seed(receiver);
    // Closure is visible even to a callback inside a backend release.
    backend.in_release=[&] {
        check(!receiver.accept_input_epoch(100,true));
        check(!receiver.receive(press(4,5),true,authorization));
    };
    backend.failures=1;
    auto result=receiver.close();
    check(result.released==2 && result.remaining==1 && backend.buttons.empty());
    result=receiver.close();
    check(result.released==1 && result.remaining==0 && backend.keys.empty());
    result=receiver.close();
    check(result.released==0 && result.remaining==0 && backend.releases==3);
    for (auto kind : {rwn::desktop::InputKind::raw_key,rwn::desktop::InputKind::pointer_button,
        rwn::desktop::InputKind::pointer_move,rwn::desktop::InputKind::vertical_wheel,
        rwn::desktop::InputKind::text_commit}) {
        auto late=press(4,5); late.kind=kind;
        check(!receiver.receive(late,true,authorization));
    }
    Backend failure;
    rwn::desktop::InputReceiver failed(failure); seed(failed);
    failure.failures=100;
    check(failed.close().remaining==2 && failure.buttons.empty());
    check(failed.close().remaining==2 && !failed.accept_input_epoch(101,true));
    // A view-only receiver has nothing to release and cannot acquire control.
    Backend view;
    rwn::desktop::InputReceiver view_receiver(view);
    check(view_receiver.close().remaining==0 && view.releases==0);
    unsigned cleanups{};
    try {
        rwn::agent::OnExit cleanup([&] { ++cleanups; });
        throw std::runtime_error("startup failure");
    } catch (const std::runtime_error&) {}
    check(cleanups==1);
    { rwn::agent::OnExit cleanup([&] { ++cleanups; }); cleanup.run(); cleanup.run(); }
    check(cleanups==2);
}
void cancellation() {
    using rwn::core::CancellationSource;
    using Callback=rwn::core::CancellationCallback<std::function<void()>>;
    unsigned calls{};
    { Callback empty({},[&] { ++calls; }); }
    check(calls==0);
    CancellationSource source;
    { Callback removed(source.token(),[&] { ++calls; }); }
    check(source.request_stop() && !source.request_stop() && calls==0);
    { Callback immediate(source.token(),[&] { ++calls; }); }
    check(calls==1);
    CancellationSource bounded;
    std::array<std::unique_ptr<Callback>,8> registrations;
    for(auto& item:registrations)item=std::make_unique<Callback>(bounded.token(),[&] { ++calls; });
    bool rejected{};
    try { Callback excess(bounded.token(),[]{}); } catch(const std::length_error&) { rejected=true; }
    check(rejected);bounded.request_stop();check(calls==9);
    // Reentrant and simultaneous cross-source cancellation cannot deadlock.
    for(unsigned repeat=0;repeat<100;++repeat) {
        CancellationSource first,second;
        std::atomic_uint count{};
        rwn::core::CancellationCallback a(first.token(),[&] { ++count;second.request_stop(); });
        rwn::core::CancellationCallback b(second.token(),[&] { ++count;first.request_stop(); });
        std::atomic_bool go{};
        std::thread one([&] { while(!go.load()){} first.request_stop(); });
        std::thread two([&] { while(!go.load()){} second.request_stop(); });
        go.store(true);one.join();two.join();check(count.load()==2);
    }
    CancellationSource waiting;
    std::atomic_bool entered{},finish{},removed{};
    auto registration=std::make_unique<Callback>(waiting.token(),[&] {
        entered.store(true);
        while(!finish.load())std::this_thread::yield();
        check(!removed.load());
    });
    std::thread requester([&] { waiting.request_stop(); });
    while(!entered.load())std::this_thread::yield();
    std::thread remover([&] { registration.reset();removed.store(true); });
    finish.store(true);requester.join();remover.join();check(removed.load());
    CancellationSource self;
    std::unique_ptr<Callback> own;
    own=std::make_unique<Callback>(self.token(),[&] {
        auto& target=own;auto& total=calls;target.reset();++total;
    });
    self.request_stop();check(!own && calls==10);
}
template<class Action> void rejects(Action action) {
    bool rejected{};try{action();}catch(const std::logic_error&){rejected=true;}
    check(rejected);
}
void audit_runtime() {
    using namespace rwn::agent;
    namespace lp=rwn::agent::macos;
    struct Consent final:rwn::desktop::DesktopPermissionBackend {
        unsigned capture{},input{};
        rwn::desktop::DesktopPermissionStatus status()const override{return {};}
        void request_capture()override{++capture;}
        void request_input()override{++input;}
    } consent;
    request_cli_permission(consent,false);request_cli_permission(consent,true);
    check(consent.capture==1 && consent.input==1);
    {
        RunAudit unsupported;
        request_cli_permission(consent,false);request_cli_permission(consent,true);
        check(consent.capture==1 && consent.input==1);
        check(unsupported.finish().input==InputExit::unknown);
        request_cli_permission(consent,false);check(consent.capture==1);
    }
    {
        RunAudit no_input;observe_stream_endpoint();observe_stream_endpoint();
        check(no_input.finish().input==InputExit::never_started);
        rejects([]{observe_stream_endpoint();});
        rejects([]{RunAudit duplicate;});
    }
    {
        unsigned notifications{};
        const auto caller=std::this_thread::get_id();
        RunAudit readiness([&]{check(std::this_thread::get_id()==caller);++notifications;});
        rejects([]{observe_listener_ready();}); // Parsing has not accepted a stream.
        check(notifications==0);observe_stream_endpoint();
        check(notifications==0); // A parsed command is not a bound listener.
        observe_listener_ready();observe_listener_ready();
        check(notifications==1 && readiness.finish().input==InputExit::never_started);
        rejects([]{observe_listener_ready();});check(notifications==1);
    }
    {
        RunAudit failed_receipt([]{throw std::runtime_error("fixture receipt storage failure");});
        observe_stream_endpoint();bool storage_failed=false;
        try{observe_listener_ready();}catch(const std::runtime_error&){storage_failed=true;}
        check(storage_failed);
        check(failed_receipt.finish().input==InputExit::never_started);
    }
    Backend backend;rwn::desktop::InputReceiver receiver(backend);seed(receiver);
    {
        RunAudit early;observe_stream_endpoint();InputOwnerAudit owner;
        rejects([]{InputOwnerAudit duplicate;});
        check(early.finish().input==InputExit::unknown); // Scheduled, not finished.
        rejects([]{InputOwnerAudit late;});
        std::thread worker([&]{check(owner.finish_on_owner(receiver).input==InputExit::released);});
        worker.join();
        check(early.finish().input==InputExit::unknown); // Cannot upgrade frozen proof.
    }
    {
        RunAudit completed;observe_stream_endpoint();InputOwnerAudit owner;
        Backend input;rwn::desktop::InputReceiver tracked(input);seed(tracked);
        input.failures=1;
        std::thread worker([&]{
            auto result=owner.finish_on_owner(tracked);
            check(result.input==InputExit::released && result.released==3 && result.remaining==0);
        });worker.join();
        check(completed.finish().input==InputExit::released);
    }
    {
        RunAudit failed;observe_stream_endpoint();InputOwnerAudit owner;
        Backend input;rwn::desktop::InputReceiver tracked(input);seed(tracked);input.failures=100;
        check(owner.finish_on_owner(tracked).remaining==2);
        check(failed.finish().input==InputExit::failed);
    }
    {
        RunAudit abandoned;observe_stream_endpoint();
        {InputOwnerAudit pending;}
        check(abandoned.finish().input==InputExit::unknown);
    }
    std::unique_ptr<InputOwnerAudit> pending;
    { RunAudit gone;observe_stream_endpoint();pending=std::make_unique<InputOwnerAudit>(); }
    rejects([]{RunAudit cannot_replace_live_owner;});
    rejects([]{observe_stream_endpoint();});
    rejects([]{InputOwnerAudit after_scope;});
    check(pending->finish_on_owner(receiver).input==InputExit::released);pending.reset();
    { RunAudit subsequent;observe_stream_endpoint();check(subsequent.finish().input==InputExit::never_started); }
    lp::ServiceRuntime start{std::string(32,'a'),std::string(64,'b'),123};
    start.process_start_us=17;
    check(lp::parse_service_runtime(lp::serialize_service_runtime(start))==start);
    auto active=start;active.phase=lp::RuntimePhase::pending;
    const auto ready=lp::serialize_service_ready(active,std::string(32,'c'));
    check(ready.find("instance="+start.instance)!=std::string::npos);
    rejects([&]{(void)lp::serialize_service_ready(start,std::string(32,'c'));});
    const auto stopped=lp::finish_service_runtime(active,{InputExit::released,3,0},0);
    check(lp::runtime_stop_proven(active,stopped,true,true,true));
    for(unsigned flags=0;flags<7;++flags)
        check(!lp::runtime_stop_proven(active,stopped,(flags&1)!=0,(flags&2)!=0,(flags&4)!=0));
    check(!lp::runtime_stop_proven(active,start,true,true,true));
    check(lp::runtime_stop_proven(start,start,true,true,true)); // No delegation ever occurred.
    for(unsigned change=0;change<4;++change){
        auto stale=stopped;
        if(change==0)stale.instance[0]='d';else if(change==1)++stale.pid;else if(change==2)stale.configuration_hash[0]='d';else ++stale.process_start_us;
        check(!lp::runtime_stop_proven(active,stale,true,true,true));
    }
    const auto failed=lp::finish_service_runtime(active,{InputExit::failed,1,2},74);
    check(!lp::safe_input_exit(failed) && !lp::runtime_stop_proven(active,failed,true,true,true));
    check(!lp::runtime_stop_proven(failed,stopped,true,true,true));
    rejects([&]{(void)lp::finish_service_runtime(stopped,{InputExit::released,0,0},0);});
    const auto none=lp::finish_service_runtime(active,{InputExit::never_started,0,0},0);
    const std::array records{start,active,none,stopped,failed};
    for(const auto& previous:records)for(const auto& next:records){
        const bool allowed=previous==next ||
            (previous.phase==lp::RuntimePhase::preflight && next.phase==lp::RuntimePhase::pending) ||
            (previous.phase==lp::RuntimePhase::pending && (next.phase==lp::RuntimePhase::stopped_none ||
                next.phase==lp::RuntimePhase::stopped_released || next.phase==lp::RuntimePhase::stop_failed));
        if(allowed)lp::validate_runtime_transition(previous,next);
        else rejects([&]{lp::validate_runtime_transition(previous,next);});
        auto replacement=next;replacement.instance[0]='e';
        if(lp::safe_input_exit(previous) && next.phase==lp::RuntimePhase::preflight)
            lp::validate_runtime_transition(previous,replacement);
        else rejects([&]{lp::validate_runtime_transition(previous,replacement);});
    }
    lp::validate_runtime_transition(std::nullopt,start);
    rejects([&]{lp::validate_runtime_transition(std::nullopt,active);});
    auto changed_identity=active;++changed_identity.pid;
    rejects([&]{lp::validate_runtime_transition(start,changed_identity);});
    changed_identity=active;changed_identity.configuration_hash[0]='e';
    rejects([&]{lp::validate_runtime_transition(start,changed_identity);});
    for(auto text : {lp::serialize_service_runtime(start)+"command=evil\n",
        lp::serialize_service_runtime(start)+"pid=123\n",std::string(1025,'x'),std::string("schema=1\n")})
        rejects([&]{(void)lp::parse_service_runtime(text);});
    auto canonical=lp::serialize_service_runtime(start);
    for(auto field : {"schema=01","pid=0123","pid=0","pid=2147483648","instance=ABC","exit_code=256",
        "process_start_us=0","process_start_us=017","process_start_us=+17","process_start_us=18446744073709551616",
        "released=65544","remaining=65544","phase=unknown"}) {
        auto text=canonical;std::string value=field;auto key=value.substr(0,value.find('=')+1);
        const auto begin=text.find(key),end=text.find('\n',begin);text.replace(begin,end-begin,value);
        rejects([&]{(void)lp::parse_service_runtime(text);});
    }
    rejects([&]{(void)lp::parse_service_runtime(canonical.substr(0,canonical.size()-1));});
}
struct StopFixture final:rwn::agent::macos::RuntimeStopBackend {
    using Runtime=rwn::agent::macos::ServiceRuntime;
    bool contract{true},stop_ok{true},wait_ok{true},gone{true},original_gone{true},no_job{true},free{true};
    unsigned stops{},reads{};std::optional<Runtime> before,after;
    bool contract_verified()override{return contract;}
    bool original_process_gone()override{return original_gone;}
    std::optional<Runtime> record()override{return reads++==0?before:after;}
    bool unregister_service()override{++stops;return stop_ok;}
    bool await_stopped()override{return wait_ok;}
    bool process_gone(const Runtime&)override{return gone;}
    bool job_gone()override{return no_job;}
    bool lease_free()override{return free;}
};
void quiescence() {
    namespace lp=rwn::agent::macos;
    lp::ServiceRuntime active{std::string(32,'a'),std::string(64,'b'),123,lp::RuntimePhase::pending};
    active.process_start_us=17;
    const auto closed=lp::finish_service_runtime(active,{rwn::agent::InputExit::released,1,0},0);
    StopFixture good;good.before=active;good.after=closed;check(lp::quiesce_runtime(good));
    for(unsigned fault=0;fault<7;++fault){
        StopFixture item;item.before=active;item.after=closed;
        if(fault==0)item.contract=false;else if(fault==1)item.stop_ok=false;else if(fault==2)item.wait_ok=false;
        else if(fault==3)item.gone=false;else if(fault==4)item.no_job=false;else if(fault==5)item.free=false;else item.original_gone=false;
        check(!lp::quiesce_runtime(item));if(fault==0)check(item.stops==0 && item.reads==0);
    }
    StopFixture crash;crash.before=active;crash.after=active;check(!lp::quiesce_runtime(crash));
    StopFixture missing;missing.before=active;check(!lp::quiesce_runtime(missing));
    StopFixture absent;check(lp::quiesce_runtime(absent)); // Verified mandatory-record contract.
    StopFixture appeared;appeared.after=closed;check(lp::quiesce_runtime(appeared));
    StopFixture reboot;reboot.before=active;reboot.after=closed;reboot.after->instance[0]='d';
    check(!lp::quiesce_runtime(reboot));
}

#if defined(__APPLE__)
enum class Pending { idle_read, partial_read, blocked_write, busy_injection, broken_write, unwind };
int child(int ready, int control, int output, Pending pending) {
    try {
        rwn::agent::ProcessShutdown shutdown;
        rwn::agent::RunAudit run;
        rwn::agent::observe_stream_endpoint();
        rwn::agent::InputOwnerAudit owner;
        Backend backend;
        rwn::desktop::InputReceiver receiver(backend); seed(receiver);
        const auto notify=[&] { check(::write(ready,"R",1)==1); };
        if (pending==Pending::busy_injection) {
            backend.in_press=[&] {
                notify();
                while (!shutdown.token().stop_requested()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            };
            check(receiver.receive(press(4,5),true,authorization));
        } else if (pending==Pending::blocked_write || pending==Pending::broken_write) {
            rwn::agent::StoppableOutput buffer(output,shutdown.token());
            std::array<char,4096> bytes{};
            if (pending==Pending::blocked_write) {
                while (::write(output,bytes.data(),bytes.size())>0) {}
                check(errno==EAGAIN);
            }
            notify();
            check(buffer.sputn(bytes.data(),bytes.size())==0);
        } else if (pending==Pending::unwind) {
            rwn::core::CancellationSource local;
            std::thread worker([&] {
                std::array<std::byte,8> bytes{};
                notify();
                check(!rwn::agent::read_control_fd(control,bytes,local.token()));
                check(receiver.close().remaining==0);
            });
            try {
                rwn::agent::OnExit cleanup([&] { local.request_stop(); worker.join(); });
                while (!shutdown.token().stop_requested()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
                throw std::runtime_error("simulated startup unwind");
            } catch (const std::runtime_error&) {}
        } else {
            notify();
            std::array<std::byte,8> bytes{};
            check(!rwn::agent::read_control_fd(control,bytes,shutdown.token()));
        }
        check(receiver.close().remaining==0);
        check(owner.finish_on_owner(receiver).input==rwn::agent::InputExit::released);
        check(run.finish().input==rwn::agent::InputExit::released);
        check(backend.keys.empty() && backend.buttons.empty());
        check(!receiver.receive(press(5,6),true,authorization));
        check(backend.releases==(pending==Pending::busy_injection ? 4U : 3U));
        return 0;
    } catch (...) { return 1; }
}
void native_shutdown() {
    double maximum_ms{};
    unsigned cases{};
    for (unsigned repeat=0;repeat<10;++repeat) for (auto pending : {
        Pending::idle_read,Pending::partial_read,Pending::blocked_write,
        Pending::busy_injection,Pending::broken_write,Pending::unwind}) {
        int ready[2], control[2], output[2];
        check(pipe(ready)==0 && pipe(control)==0 && pipe(output)==0);
        const auto pid=fork(); check(pid>=0);
        if (pid==0) {
            close(ready[0]);close(control[1]);close(output[0]);
            _exit(child(ready[1],control[0],output[1],pending));
        }
        close(ready[1]);close(control[0]);close(output[1]);
        if (pending==Pending::broken_write) { close(output[0]); output[0]=-1; }
        rwn::agent::OnExit cleanup([&] {
            close(ready[0]);close(control[1]);if(output[0]>=0)close(output[0]);
            int status{};
            if (waitpid(pid,&status,WNOHANG)==0) { kill(pid,SIGKILL); waitpid(pid,&status,0); }
        });
        if (pending==Pending::partial_read) check(write(control[1],"x",1)==1);
        pollfd item{ready[0],POLLIN,0};check(poll(&item,1,2000)>0);
        char byte{};check(read(ready[0],&byte,1)==1 && byte=='R');
        const auto started=std::chrono::steady_clock::now();
        // Only this fixture child is signalled. Broken output tests SIGPIPE
        // handling without a termination signal masking the original failure.
        if (pending!=Pending::broken_write) kill(pid,repeat%2==0 ? SIGTERM : SIGINT);
        int status{};pid_t done{};
        do {
            done=waitpid(pid,&status,WNOHANG);
            if(done!=0)break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } while(std::chrono::steady_clock::now()-started<std::chrono::seconds(2));
        check(done==pid && WIFEXITED(status) && WEXITSTATUS(status)==0);
        const auto ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-started).count();
        check(ms<250);maximum_ms=std::max(maximum_ms,ms);++cases;
    }
    // Handlers and stdout flags are scoped; setup commands keep their behavior.
    struct sigaction before{},after{};
    check(sigaction(SIGTERM,nullptr,&before)==0);
    { rwn::agent::ProcessShutdown temporary; }
    check(sigaction(SIGTERM,nullptr,&after)==0 && before.sa_handler==after.sa_handler);
    std::cout<<" native_signal_cases="<<cases<<" stop_to_exit_max_ms="<<maximum_ms;
}
void binary_passthrough() {
    int data[2];check(pipe(data)==0);
    const auto original_flags=fcntl(data[1],F_GETFL);
    const auto original_descriptor_flags=fcntl(data[1],F_GETFD);
    rwn::agent::OnExit cleanup([&] {close(data[0]);close(data[1]);});
    std::vector<std::byte> intended(2*1024*1024),received(intended.size());
    for(std::size_t i=0;i<intended.size();++i)intended[i]=static_cast<std::byte>(i%251);
    rwn::core::CancellationSource stop;
    bool received_all{};
    std::thread reader([&] { received_all=rwn::agent::read_control_fd(data[0],received,stop.token()); });
    {
        rwn::agent::StoppableOutput writer(data[1],stop.token());
        check(writer.sputn(reinterpret_cast<const char*>(intended.data()),
            static_cast<std::streamsize>(intended.size()))==static_cast<std::streamsize>(intended.size()));
    }
    reader.join();
    check(received_all && received==intended &&
        rwn::core::sha256_hex(received)==rwn::core::sha256_hex(intended));
    const auto restored_flags=fcntl(data[1],F_GETFL);
    // Darwin also exposes the kernel's FWASWRITTEN marker after I/O. It is not
    // settable by F_SETFL. Check public mutable flags and descriptor flags.
    constexpr auto mask=O_NONBLOCK|O_APPEND|O_ASYNC|O_SYNC|O_DSYNC|O_ACCMODE;
    check(restored_flags>=0 && (restored_flags&mask)==(original_flags&mask));
    check(fcntl(data[1],F_GETFD)==original_descriptor_flags);
    std::cout<<" binary_roundtrip_bytes="<<intended.size()<<" fd_flags_restored=1";
}
#endif
}
int main() {
    try {
        terminal_input();
        cancellation();
        audit_runtime();
        quiescence();
#if defined(__APPLE__)
        native_shutdown();
        binary_passthrough();
#endif
        std::cout<<" agent_shutdown=PASS input_backend=fixture native_injection=0\n";return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
