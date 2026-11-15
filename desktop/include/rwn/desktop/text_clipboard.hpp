#pragma once

#include "rwn/desktop/desktop.hpp"
#include "rwn/core/content_hash.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <thread>

namespace rwn::desktop {
// Text only, deliberately below the RWC1 payload cap. Never truncate Unicode.
inline constexpr std::size_t text_clipboard_limit = 32U * 1024U;
inline constexpr std::size_t text_clipboard_header_size = 28;
enum class TextClipboardKind : std::uint8_t { enable=1, disable=2, enabled=3, text=4 };
struct TextClipboardMessage {
    TextClipboardKind kind{};
    std::uint64_t epoch{}, revision{};
    std::string text;
};
inline void validate_text_clipboard(const TextClipboardMessage& message) {
    const auto kind=static_cast<unsigned>(message.kind);
    if (kind<1 || kind>4 || !message.epoch ||
        message.text.size()>text_clipboard_limit ||
        message.text.find('\0')!=std::string::npos || !valid_utf8(message.text) ||
        (message.kind==TextClipboardKind::text ? !message.revision :
            (message.revision!=0 || !message.text.empty())))
        throw std::invalid_argument("invalid text clipboard message");
}
inline std::vector<std::byte> encode_text_clipboard(const TextClipboardMessage& message) {
    validate_text_clipboard(message);
    std::vector<std::byte> wire(text_clipboard_header_size+message.text.size());
    wire[0]=std::byte{'L'};wire[1]=std::byte{'P'};wire[2]=std::byte{'C'};wire[3]=std::byte{'1'};
    wire[4]=std::byte{1};wire[5]=static_cast<std::byte>(message.kind);
    const auto integer=[&](std::size_t offset,std::size_t size,std::uint64_t value){
        for(std::size_t i=0;i<size;++i) wire[offset+i]=static_cast<std::byte>(value>>((size-i-1)*8));
    };
    integer(8,8,message.epoch);integer(16,8,message.revision);integer(24,4,message.text.size());
    std::copy(std::as_bytes(std::span{message.text}).begin(),
              std::as_bytes(std::span{message.text}).end(),wire.begin()+text_clipboard_header_size);
    return wire;
}
inline std::size_t text_clipboard_payload_size(std::span<const std::byte> header) {
    if(header.size()!=text_clipboard_header_size || header[0]!=std::byte{'L'} ||
       header[1]!=std::byte{'P'} || header[2]!=std::byte{'C'} || header[3]!=std::byte{'1'} ||
       header[4]!=std::byte{1} || header[6]!=std::byte{} || header[7]!=std::byte{} ||
       std::to_integer<unsigned>(header[5])<1 || std::to_integer<unsigned>(header[5])>4)
        throw std::invalid_argument("invalid text clipboard header");
    std::size_t size{};
    for(std::size_t i=24;i<28;++i) size=(size<<8)|std::to_integer<unsigned>(header[i]);
    if(size>text_clipboard_limit) throw std::invalid_argument("text clipboard exceeds limit");
    if(header[5]!=static_cast<std::byte>(TextClipboardKind::text) && size)
        throw std::invalid_argument("clipboard control contains data");
    return size;
}
inline TextClipboardMessage decode_text_clipboard(std::span<const std::byte> wire) {
    if(wire.size()<text_clipboard_header_size) throw std::invalid_argument("truncated clipboard header");
    const auto size=text_clipboard_payload_size(wire.first(text_clipboard_header_size));
    if(wire.size()!=text_clipboard_header_size+size) throw std::invalid_argument("truncated clipboard text");
    const auto integer=[&](std::size_t offset){
        std::uint64_t value{};
        for(std::size_t i=0;i<8;++i){value=(value<<8)|std::to_integer<unsigned>(wire[offset+i]);}
        return value;
    };
    TextClipboardMessage result{static_cast<TextClipboardKind>(wire[5]),integer(8),integer(16),
        std::string(reinterpret_cast<const char*>(wire.data()+text_clipboard_header_size),size)};
    validate_text_clipboard(result);return result;
}

// Connection-local state. Explicit client consent AND server-local policy are
// required. Lamport versions with a fixed endpoint tie-break converge even
// when both users copy concurrently. Content hashes suppress OS write echoes.
class TextClipboardState {
public:
    TextClipboardState(bool server,bool allowed):server_(server),allowed_(allowed){}
    TextClipboardMessage request(bool enabled) {
        if(server_ || !allowed_) throw std::logic_error("clipboard consent not granted");
        active_=false;pending_.reset();hash_.reset();
        if(enabled){if(epoch_==UINT64_MAX)throw std::overflow_error("clipboard epoch exhausted");
            ++epoch_;clock_=version_=0;origin_=0;requested_=true;
        } else requested_=false;
        return {enabled?TextClipboardKind::enable:TextClipboardKind::disable,epoch_,0,{}};
    }
    std::optional<TextClipboardMessage> receive(const TextClipboardMessage& message) {
        validate_text_clipboard(message);
        if(message.kind==TextClipboardKind::enable){
            if(!server_ || !allowed_ || message.epoch<=epoch_)throw std::invalid_argument("clipboard enable denied");
            epoch_=message.epoch;clock_=version_=0;origin_=0;hash_.reset();pending_.reset();active_=true;
            return TextClipboardMessage{TextClipboardKind::enabled,epoch_,0,{}};
        }
        if(message.kind==TextClipboardKind::enabled){
            if(server_ || !allowed_)
                throw std::invalid_argument("unsolicited clipboard grant");
            if(!requested_ || message.epoch!=epoch_ || active_)return {};
            active_=true;return {};
        }
        if(message.epoch!=epoch_ || !active_){return {};}
        if(message.kind==TextClipboardKind::disable){
            active_=false;pending_.reset();hash_.reset();return {};
        }
        const auto peer_origin=server_?1U:2U;
        clock_=std::max(clock_,message.revision);
        if(message.revision<version_ || (message.revision==version_ && peer_origin<=origin_))return {};
        version_=message.revision;origin_=peer_origin;
        if(hash_ && *hash_==core::sha256_hex(message.text)){pending_.reset();return {};}
        pending_=message;return {};
    }
    std::optional<TextClipboardMessage> local(std::string text) {
        if(!active_)return {};
        TextClipboardMessage message{TextClipboardKind::text,epoch_,1,std::move(text)};
        validate_text_clipboard(message);
        const auto hash=core::sha256_hex(message.text);
        if(hash_ && hash==*hash_)return {};
        if(clock_==UINT64_MAX)throw std::overflow_error("clipboard revision exhausted");
        message.revision=++clock_;version_=clock_;origin_=server_?2U:1U;
        hash_=hash;pending_.reset();return message;
    }
    bool active()const noexcept{return active_;}
    const std::optional<TextClipboardMessage>& pending()const noexcept{return pending_;}
    void committed(){if(pending_){hash_=core::sha256_hex(pending_->text);pending_.reset();}}
private:
    bool server_{},allowed_{},active_{},requested_{};
    std::uint64_t epoch_{},clock_{},version_{};
    unsigned origin_{};
    std::optional<std::string> hash_;
    std::optional<TextClipboardMessage> pending_;
};

struct TextClipboardCallbacks {
    std::function<std::uint64_t()> change_token;
    std::function<std::optional<std::string>()> read;
    std::function<void(std::string_view)> write;
    std::function<void(const TextClipboardMessage&)> send;
};
// OS operations are confined to this sidecar, never input/render/capture threads.
// No initial clipboard read: only copies made after explicit enable are shared.
class TextClipboardPump {
public:
    TextClipboardPump(bool server,bool allowed,TextClipboardCallbacks callbacks)
        :server_(server),state_(server,allowed),callbacks_(std::move(callbacks)),
         worker_([this]{run();}){}
    ~TextClipboardPump(){stopping_.store(true);ready_.notify_all();if(worker_.joinable())worker_.join();}
    void set_enabled(bool enabled){desired_.store(enabled);ready_.notify_all();}
    void receive(TextClipboardMessage message){
        validate_text_clipboard(message);
        std::lock_guard lock(mutex_);
        if(message.kind==TextClipboardKind::text && !incoming_.empty() &&
           incoming_.back().kind==TextClipboardKind::text && incoming_.back().epoch==message.epoch){
            if(message.revision>incoming_.back().revision)incoming_.back()=std::move(message);
        }else{
            if(incoming_.size()>=8)throw std::runtime_error("clipboard inbox full");
            incoming_.push_back(std::move(message));
        }
        ready_.notify_all();
    }
    bool active()const noexcept{return active_.load();}
    std::atomic_uint64_t sent{},received{},os_retries{},local_rejected{};
    std::atomic_bool failed{};
private:
    void run()noexcept{
        bool requested{};std::uint64_t token{};
        try{
            while(!stopping_.load()){
                if(!server_ && requested!=desired_.load()){
                    requested=desired_.load();callbacks_.send(state_.request(requested));
                }
                std::deque<TextClipboardMessage> messages;
                {std::lock_guard lock(mutex_);messages.swap(incoming_);}
                for(const auto& message:messages){
                    const auto was_active=state_.active();
                    const auto reply=state_.receive(message);
                    if(!was_active && state_.active())token=callbacks_.change_token();
                    if(reply)callbacks_.send(*reply);
                }
                active_.store(state_.active() && (server_ || desired_.load()));
                if(active_.load()){
                    std::optional<TextClipboardMessage> outbound;
                    try{
                        const auto current=callbacks_.change_token();
                        if(current!=token){
                            const auto value=callbacks_.read();
                            if(current==callbacks_.change_token()){
                                token=current;
                                if(value){
                                    try{outbound=state_.local(*value);}
                                    catch(const std::invalid_argument&){++local_rejected;}
                                }
                            }
                        }
                        if(state_.pending() && (server_ || desired_.load())){
                            callbacks_.write(state_.pending()->text);state_.committed();++received;
                        }
                    }catch(const std::runtime_error&){++os_retries;}
                    if(outbound){callbacks_.send(*outbound);++sent;}
                }
                std::unique_lock lock(mutex_);
                ready_.wait_for(lock,std::chrono::milliseconds(100),[&]{
                    return stopping_.load() || !incoming_.empty() || (!server_ && requested!=desired_.load());});
            }
        }catch(...){failed.store(true);}
        active_.store(false);
    }
    bool server_{};
    TextClipboardState state_;
    TextClipboardCallbacks callbacks_;
    std::mutex mutex_;
    std::condition_variable_any ready_;
    std::deque<TextClipboardMessage> incoming_;
    std::atomic_bool desired_{},active_{},stopping_{};
    std::thread worker_;
};
} // namespace rwn::desktop
