// Exercise production queue/writer without OS input hooks, SSH, or injection.
#include "main.cpp"
#include <iostream>
#include "rwn/platform/windows/socket_io_retry.hpp"

static int startup_workflow(){
    using Startup=rwn::viewer::ConnectionStartup<std::unique_ptr<int>>;
    using Clock=std::chrono::steady_clock;
    auto check=[](bool value){if(!value)throw std::runtime_error("startup fixture failed");};
    const auto instance=GetModuleHandleW(nullptr);constexpr wchar_t name[]=L"LanPilotHiddenStartupFixture";
    WNDCLASSW definition{};definition.hInstance=instance;definition.lpfnWndProc=window_procedure;definition.lpszClassName=name;
    if(!RegisterClassW(&definition))throw std::runtime_error("startup fixture class failed");
    ViewerState state;state.interactive=true;state.connection_usable=false;
    const auto window=CreateWindowExW(0,name,L"Hidden connection startup",WS_OVERLAPPEDWINDOW,0,0,640,360,nullptr,nullptr,instance,&state);
    if(!window)throw std::runtime_error("startup fixture window failed");
    struct Cleanup{HWND w;~Cleanup(){if(IsWindow(w)){SetWindowLongPtrW(w,GWLP_USERDATA,0);DestroyWindow(w);}MSG m{};while(PeekMessageW(&m,nullptr,WM_QUIT,WM_QUIT,PM_REMOVE)){};}} cleanup{window};
    state.enqueue_input({.kind=rwn::desktop::InputKind::raw_key,.value_a=4,.pressed=true,.text={}});
    check(state.next_reliable_input_sequence==0 && state.reliable_control.empty());
    {Startup ready([](rwn::core::CancellationToken){return std::make_unique<int>(42);});
        check(rwn::viewer::wait_for_connection(window,ready));check(*ready.take()==42);}
    {Startup failed([](rwn::core::CancellationToken)->std::unique_ptr<int>{throw std::runtime_error("fixture trust rejected");});
        check(rwn::viewer::wait_for_connection(window,failed));bool denied{};try{(void)failed.take();}
        catch(const rwn::transport::TlsTransportInterrupted&){throw std::runtime_error("trust failure became retryable");}
        catch(const std::runtime_error& error){denied=std::string_view(error.what())=="fixture trust rejected";}check(denied);}
    {std::atomic_bool fatal{};Startup pending([&](rwn::core::CancellationToken stop)->std::unique_ptr<int>{
        rwn::platform::windows::detail::probe_connection_cancellation(stop,[&]{fatal=true;PostMessageW(window,WM_NULL,0,0);});
        throw std::runtime_error("probe must be cancelled");
    });check(!rwn::viewer::wait_for_connection(window,pending,[&]{return !fatal;}));}
    // Real Winsock name resolution + loopback connection, then a native read
    // stalled exactly where TLS startup would wait for the peer. The production
    // UI close path must wake it by cancellation and join it without publishing.
    std::atomic_bool cancelled{},finished{};std::atomic_uint live_results{};
    struct Result {std::atomic_uint& count;explicit Result(std::atomic_uint& c):count(c){++count;}~Result(){--count;}};
    const auto start=Clock::now();
    {rwn::viewer::ConnectionStartup<std::unique_ptr<Result>> pending([&](rwn::core::CancellationToken stop)->std::unique_ptr<Result>{
        try{rwn::platform::windows::detail::probe_connection_cancellation(stop,[&]{PostMessageW(window,WM_CLOSE,0,0);});}
        catch(const rwn::transport::TlsTransportInterrupted& error){cancelled=error.reason()==rwn::transport::TlsTransportInterrupted::Reason::cancelled;finished=true;return std::make_unique<Result>(live_results);}
        finished=true;throw std::runtime_error("probe must be cancelled");
    });const auto complete=rwn::viewer::wait_for_connection(window,pending);
        if(complete)(void)pending.take();
        check(!complete);}
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
    if(!(cancelled && finished && live_results==0 && elapsed<1500 && !IsWindow(window)))throw std::runtime_error("startup cancel failed elapsed_ms="+std::to_string(elapsed)+" cancelled="+std::to_string(cancelled.load())+" finished="+std::to_string(finished.load()));
    std::cout<<"viewer_startup=PASS native_loopback_cancel=1 worker_joined=1 result_not_published=1 late_result_disposed=1 fatal_during_setup_cancelled=1 trust_error_preserved=1 input_before_auth=0 cancel_ms="<<elapsed<<" shown_ui=0 input_injected=0\n";
    return 0;
}

static int reconnect_workflow(){
    const auto instance=GetModuleHandleW(nullptr);constexpr wchar_t name[]=L"LanPilotHiddenReconnectFixture";
    WNDCLASSW definition{};definition.hInstance=instance;definition.lpfnWndProc=window_procedure;definition.lpszClassName=name;
    if(!RegisterClassW(&definition))throw std::runtime_error("reconnect fixture class failed");
    auto check=[](bool value){if(!value)throw std::runtime_error("reconnect fixture failed");};
    ViewerState old;old.allow_reconnect=true;
    const auto window=CreateWindowExW(0,name,L"Hidden connection fixture",WS_OVERLAPPEDWINDOW,0,0,640,360,nullptr,nullptr,instance,&old);
    if(!window)throw std::runtime_error("reconnect fixture window failed");
    struct Cleanup{HWND value;~Cleanup(){if(IsWindow(value)){SetWindowLongPtrW(value,GWLP_USERDATA,0);DestroyWindow(value);}MSG m{};while(PeekMessageW(&m,nullptr,WM_QUIT,WM_QUIT,PM_REMOVE)){};}} cleanup{window};
    const rwn::transport::TlsTransportInterrupted interrupted(rwn::transport::TlsTransportInterrupted::Reason::closed,"fixture EOF");
    old.next_wire_sequence=42;old.input_epoch=9;old.pointer_control=PendingControlMessage{};old.reliable_control.push_back({});
    old.report_tls_failure(interrupted);
    MSG message{};
    while(GetMessageW(&message,nullptr,0,0)>0)DispatchMessageW(&message);
    check(message.wParam==reconnect_session_exit && old.stopping && IsWindow(window));
    SetWindowLongPtrW(window,GWLP_USERDATA,0);
    check(wait_for_reconnect(window,std::chrono::milliseconds{1}));
    ViewerState fresh;fresh.window=window;fresh.allow_reconnect=true;fresh.resume_control_required=true;
    SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(&fresh));
    check(fresh.input_epoch==1 && fresh.next_wire_sequence==0 && !fresh.pointer_control && fresh.reliable_control.empty() &&
          fresh.snapshot_commands.empty() && !fresh.frame && fresh.cursor_cache.empty() && !fresh.clipboard_enabled);
    SendMessageW(window,reconnect_requested_message,old.connection_instance,0);
    check(!fresh.stopping); // An old worker cannot restart a new session.
    fresh.report_tls_failure(interrupted);fresh.report_tls_failure(std::runtime_error("fixture malformed protocol"));
    while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){check(message.message!=WM_QUIT);DispatchMessageW(&message);}
    check(fresh.retry_forbidden && !fresh.stopping); // Fatal cause dominates transport closure.
    SetWindowLongPtrW(window,GWLP_USERDATA,0);
    PostMessageW(window,WM_CLOSE,0,0);
    check(!wait_for_reconnect(window,std::chrono::seconds{8}));
    std::cout<<"viewer_reconnect=PASS same_window=1 old_session_stopped=1 old_state_not_reused=1 stale_notification_rejected=1 fatal_no_retry=1 cancel_wait=1 input_injected=0 network=0 shown_ui=0\n";
    return 0;
}

int main(int argc, char** argv) {
    using namespace rwn::desktop;
    ViewerState state;
    HANDLE reader{};
    try {
        if(argc==2 && std::string_view(argv[1])=="--check-startup")return startup_workflow();
        if(argc==2 && std::string_view(argv[1])=="--check-reconnect")return reconnect_workflow();
        // Exercise the real heartbeat producer, scheduler and wire encoder.
        // A default PendingControlMessage had timestamp=0 and disconnected
        // both TLS sockets when the first five-second heartbeat was sent.
        {
            ViewerState heartbeat;
            HANDLE heartbeat_reader{};
            if (!CreatePipe(&heartbeat_reader, &heartbeat.input_write, nullptr, 65536))
                throw std::runtime_error("heartbeat pipe failed");
            heartbeat.interactive = true; // Enable the local pipe adapter only.
            heartbeat.enqueue_heartbeat();
            heartbeat.control_closing = true;
            heartbeat.control_writer = std::jthread([&] { control_writer_loop(heartbeat); });
            std::array<std::byte, reverse_control_header_size> bytes{};
            const auto received = read_exact(heartbeat_reader, bytes);
            CloseHandle(heartbeat_reader);
            heartbeat.control_writer.join();
            heartbeat.interactive = false;
            if (!received) throw std::runtime_error("heartbeat header missing");
            const auto header = decode_reverse_control_header(bytes);
            validate_reverse_control_payload(header, {});
            if (header.type != ReverseControlType::ping || header.sequence != 1 ||
                header.input_epoch != 1 || header.occurred_at_us == 0 || header.payload_size != 0)
                throw std::runtime_error("heartbeat metadata invalid");
        }
        // Evidence bookkeeping only; this deliberately does not claim GPU
        // execution. Scheduling revisions must never count as actual presents.
        state.rendered_revision.store(100);
        if (state.successful_present_receipts.load() != 0)
            throw std::runtime_error("scheduled revision counted as present");
        for (const auto receipt : {rwn::viewer::D3D11RenderReceipt{0,2,3},
                                   rwn::viewer::D3D11RenderReceipt{1,0,3},
                                   rwn::viewer::D3D11RenderReceipt{1,3,2}}) {
            bool rejected = false;
            try { state.record_present_receipt(receipt); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected || state.successful_present_receipts.load() != 0)
                throw std::runtime_error("invalid Present receipt admitted");
        }
        state.record_present_receipt({1,2,3});
        if (state.successful_present_receipts.load() != 1)
            throw std::runtime_error("valid Present receipt not recorded");
        const bool motion = argc == 2 && std::string_view(argv[1]) == "motion";
        const bool pressure = argc == 2 && std::string_view(argv[1]) == "pressure";
        if (argc > 2 || (argc == 2 && !motion && !pressure)) return 64;
        if (!CreatePipe(&reader, &state.input_write, nullptr, 65536))
            throw std::runtime_error("local pipe failed");
        state.interactive = true;
        if (pressure) {
            for (unsigned i = 0; i < 255; ++i)
                state.enqueue_input({.kind = InputKind::pointer_button,
                    .value_a = 1, .pressed = i % 2 == 0, .text = {}});
            state.enqueue_input({.kind = InputKind::pointer_move,
                .value_a = 1000, .value_b = 1000, .text = {}});
            bool rejected{};
            try { state.enqueue_input({.kind = InputKind::pointer_button,
                .value_a = 1, .pressed = false, .text = {}}); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected || state.reliable_control.size() != 255 || !state.pointer_control)
                throw std::runtime_error("barrier capacity admission was not atomic");
            state.enqueue_release_all();
            if (state.input_epoch != 2 || state.pointer_control ||
                state.reliable_control.size() != 1 ||
                state.reliable_control.front().type != ReverseControlType::release_all_input ||
                state.reliable_control.front().input_epoch != 2)
                throw std::runtime_error("overflow release did not invalidate old epoch");
            CloseHandle(reader); reader = nullptr;
            state.interactive = false;
            std::cout << "pressure=PASS bounded=1 atomic_rejection=1 release_epoch=2 input_injected=0\n";
            return 0;
        }
        if (motion) state.enqueue_input({.kind = InputKind::pointer_move,
            .value_a = 999, .value_b = 999, .text = {}});
        if (motion) state.enqueue_input({.kind = InputKind::pointer_move,
            .value_a = 1000, .value_b = 1000, .text = {}});
        for (unsigned click = 0; click < (motion ? 1U : 64U); ++click) {
            for (const bool pressed : {true, false})
            {
                state.enqueue_input({.kind = InputKind::pointer_button,
                    .value_a = 1, .pressed = pressed, .text = {}});
                if (motion && pressed) {
                    state.enqueue_input({.kind = InputKind::pointer_move,
                        .value_a = 1999, .value_b = 1999, .text = {}});
                    state.enqueue_input({.kind = InputKind::pointer_move,
                        .value_a = 2000, .value_b = 2000, .text = {}});
                }
            }
        }
        state.enqueue_release_all();
        state.control_closing = true;
        state.control_writer = std::jthread([&] { control_writer_loop(state); });
        unsigned edges{};
        for (std::uint64_t sequence = 1; sequence <= 129; ++sequence) {
            std::array<std::byte, reverse_control_header_size> bytes{};
            if (!read_exact(reader, bytes)) throw std::runtime_error("missing header");
            const auto header = decode_reverse_control_header(bytes);
            std::vector<std::byte> payload(header.payload_size);
            if (!read_exact(reader, payload)) throw std::runtime_error("missing payload");
            validate_reverse_control_payload(header, payload);
            if (motion) {
                // The pointer location at DOWN is an ordering barrier, not a
                // supersedable intermediate motion once a button edge follows.
                if (header.sequence != sequence || header.input_epoch != 1)
                    throw std::runtime_error("motion sequence/epoch lost");
                if (sequence == 5) {
                    if (header.type != ReverseControlType::release_all_input)
                        throw std::runtime_error("motion release lost");
                    break;
                }
                if (header.type != ReverseControlType::input_event)
                    throw std::runtime_error("motion input lost");
                const auto event = decode_input_event(payload);
                if (sequence == 1 || sequence == 3) {
                    if (event.kind != InputKind::pointer_move ||
                        event.value_a != (sequence == 1 ? 1000U : 2000U))
                        throw std::runtime_error("motion barrier FAIL: edge precedes its pointer location");
                } else {
                    if (event.kind != InputKind::pointer_button || event.value_a != 1 ||
                        event.pressed != (sequence == 2))
                        throw std::runtime_error("motion button edge lost");
                    ++edges;
                }
                continue;
            }
            if (header.sequence != sequence || header.input_epoch != 1)
                throw std::runtime_error("wire ordering or epoch lost");
            if (sequence == 129) {
                if (header.type != ReverseControlType::release_all_input)
                    throw std::runtime_error("release overtook button edges");
                continue;
            }
            if (header.type != ReverseControlType::input_event)
                throw std::runtime_error("button message type lost");
            const auto event = decode_input_event(payload);
            if (event.kind != InputKind::pointer_button || event.value_a != 1 ||
                event.sequence != sequence || event.pressed != (sequence % 2 == 1))
                throw std::runtime_error("button edge lost or reordered");
            ++edges;
        }
        state.control_writer.join();
        CloseHandle(reader); reader = nullptr;
        state.interactive = false;
        std::cout << "input_queue=PASS motion=" << motion << " edges=" << edges
                  << " ordered_release=1 input_injected=0\n";
        return 0;
    } catch (const std::exception& error) {
        if (reader) CloseHandle(reader); // Break pipe to unblock failed writer.
        { std::lock_guard lock(state.control_mutex); state.control_closing = true; }
        state.control_ready.notify_all();
        if (state.control_writer.joinable()) state.control_writer.join();
        state.interactive = false;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
