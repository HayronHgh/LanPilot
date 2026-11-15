#pragma once
#include "rwn/desktop/text_clipboard.hpp"
#include "rwn/transport/channel_session.hpp"

namespace text_clipboard_tests {
using namespace rwn::desktop;
inline void check(bool value){if(!value)throw std::runtime_error("text clipboard invariant failed");}
template<class F>void rejects(F operation){
    try{operation();}catch(const std::exception&){return;}
    throw std::runtime_error("unsafe clipboard operation accepted");
}
inline void enable(TextClipboardState& client,TextClipboardState& server){
    const auto reply=server.receive(client.request(true));check(reply.has_value());
    static_cast<void>(client.receive(*reply));check(client.active()&&server.active());
}
inline void workflow(){
    TextClipboardState client(false,true),server(true,true);enable(client,server);
    const auto sent=client.local("繁中\nabc 😀");check(sent.has_value());
    const auto wire=encode_text_clipboard(*sent);
    const auto decoded=decode_text_clipboard(wire);check(decoded.text==sent->text);
    const ReverseControlHeader control{ReverseControlType::text_clipboard,0,
        static_cast<std::uint32_t>(wire.size()),1,1,1};
    validate_reverse_control_payload(decode_reverse_control_header(encode_reverse_control_header(control)),wire);
    static_cast<void>(server.receive(decoded));check(server.pending()->text==sent->text);
    server.committed();check(!server.local(sent->text)); // No OS write echo.
    static_cast<void>(server.receive(decoded));check(!server.pending()); // Replay.
    const auto empty=server.local("");check(empty.has_value());
    static_cast<void>(client.receive(*empty));check(client.pending()->text.empty());client.committed();
    // Simultaneous copies: equal Lamport counters converge to the fixed Mac tie-break.
    TextClipboardState a(false,true),b(true,true);enable(a,b);
    const auto x=a.local("windows");const auto y=b.local("mac");
    static_cast<void>(a.receive(*y));static_cast<void>(b.receive(*x));
    check(a.pending()->text=="mac"&&!b.pending());a.committed();check(!a.local("mac"));
    const auto old=*a.local("old");
    static_cast<void>(b.receive(a.request(false)));check(!a.active()&&!b.active());
    static_cast<void>(a.receive({TextClipboardKind::enabled,old.epoch,0,{}}));check(!a.active());
    enable(a,b);static_cast<void>(b.receive(old));check(!b.pending());
    TextClipboardState new_session(true,true);static_cast<void>(new_session.receive(old));check(!new_session.active()&&!new_session.pending());
}
inline void security(){
    TextClipboardState denied(false,false),host_denied(true,false);
    rejects([&]{static_cast<void>(denied.request(true));});
    rejects([&]{static_cast<void>(host_denied.receive({TextClipboardKind::enable,1,0,{}}));});
    rejects([]{static_cast<void>(encode_text_clipboard({TextClipboardKind::text,1,1,std::string(text_clipboard_limit+1,'a')}));});
    rejects([]{static_cast<void>(encode_text_clipboard({TextClipboardKind::text,1,1,std::string("a\0b",3)}));});
    rejects([]{static_cast<void>(encode_text_clipboard({TextClipboardKind::text,1,1,std::string("\xff",1)}));});
    rejects([]{static_cast<void>(encode_text_clipboard({TextClipboardKind::text,0,1,"x"}));});
    rejects([]{static_cast<void>(encode_text_clipboard({TextClipboardKind::text,1,0,"x"}));});
    auto wire=encode_text_clipboard({TextClipboardKind::text,1,1,"x"});
    auto bad=wire;bad.pop_back();rejects([&]{static_cast<void>(decode_text_clipboard(bad));});
    bad=wire;bad.push_back(std::byte{});rejects([&]{static_cast<void>(decode_text_clipboard(bad));});
    bad=wire;bad[6]=std::byte{1};rejects([&]{static_cast<void>(decode_text_clipboard(bad));});
    bad=wire;bad[24]=std::byte{127};rejects([&]{static_cast<void>(text_clipboard_payload_size(std::span{bad}.first(text_clipboard_header_size)));});
    TextClipboardState client(false,true),server(true,true);enable(client,server);
    static_cast<void>(client.receive({TextClipboardKind::text,1,UINT64_MAX,"limit"}));
    rejects([&]{static_cast<void>(client.local("overflow"));});
    rwn::transport::ChannelSessionId id{};id[0]=1;
    const rwn::transport::ChannelAdmission admission{id,1,{true,true,true,true}};
    check(rwn::transport::decode_channel_admission(rwn::transport::encode_channel_admission(admission)).grants.text_clipboard);
    rejects([&]{static_cast<void>(rwn::transport::encode_channel_admission({id,1,{true,true,false,true}}));});
}
struct FakeClipboard {
    std::mutex mutex;std::optional<std::string> content{"private preexisting text"};
    std::atomic_uint64_t revision{1},reads{},writes{};
    std::atomic_bool busy_once{};
    std::optional<std::string> read(){std::lock_guard lock(mutex);++reads;return content;}
    void copy(std::optional<std::string> value){std::lock_guard lock(mutex);content=std::move(value);++revision;}
    void write(std::string_view value){if(busy_once.exchange(false))throw std::runtime_error("fixture busy");++writes;copy(std::string(value));}
    bool equals(std::string_view value){std::lock_guard lock(mutex);return content&&*content==value;}
};
template<class F>void eventually(F condition){
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while(!condition()&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
    check(condition());
}
inline void pump_workflow(){
    FakeClipboard windows,mac;
    std::unique_ptr<TextClipboardPump> client,server;
    const auto callbacks=[&](FakeClipboard& local,std::unique_ptr<TextClipboardPump>& remote){
        return TextClipboardCallbacks{[&local]{return local.revision.load();},
            [&local]{return local.read();},[&local](std::string_view value){local.write(value);},
            [&remote](const TextClipboardMessage& message){if(remote)remote->receive(decode_text_clipboard(encode_text_clipboard(message)));}};
    };
    server=std::make_unique<TextClipboardPump>(true,true,callbacks(mac,client));
    client=std::make_unique<TextClipboardPump>(false,true,callbacks(windows,server));
    client->set_enabled(true);eventually([&]{return client->active()&&server->active();});
    check(windows.reads==0&&mac.reads==0); // Neither initial clipboard is disclosed.
    mac.busy_once.store(true);
    windows.copy("繁中 😀\nfirst");eventually([&]{return mac.equals("繁中 😀\nfirst");});
    check(server->os_retries==1); // Retry a locked OS clipboard without losing text.
    mac.copy("reverse\r\nsecond");eventually([&]{return windows.equals("reverse\r\nsecond");});
    eventually([&]{return windows.reads>=2&&mac.reads>=1;});
    check(windows.writes==1&&mac.writes==1); // No feedback loop.
    windows.copy(std::nullopt); // File/image-only clipboard must not erase remote text.
    eventually([&]{return windows.reads>=3;});check(mac.equals("reverse\r\nsecond"));
    windows.copy(std::string(text_clipboard_limit+1,'x'));eventually([&]{return client->local_rejected==1;});
    check(mac.equals("reverse\r\nsecond"));
    client->set_enabled(false);eventually([&]{return !client->active()&&!server->active();});
    const auto reads=windows.reads.load();windows.copy("not shared");
    std::this_thread::sleep_for(std::chrono::milliseconds(120));check(windows.reads==reads);
    check(!client->failed&&!server->failed);client.reset();server.reset();
}
} // namespace text_clipboard_tests
