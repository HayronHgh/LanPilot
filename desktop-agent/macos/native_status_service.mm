#include "native_status_service.hpp"
#include "rwn/platform/enrollment_tcp.hpp"
#include "rwn/platform/macos/enrollment_journal.hpp"
#include "rwn/platform/macos/enrollment_identity.hpp"
#include "rwn/platform/macos/enrollment_key.hpp"
#include <algorithm>
#include <thread>
#include <cstring>
#include <mutex>
#include "rwn/core/enrollment_credentials.hpp"

namespace rwn::agent::macos {
namespace {
namespace e=core::enrollment;namespace tcp=platform::enrollment;
void require(bool b){if(!b)throw std::runtime_error("configured native renewal is not ready");}
struct Prefix final:e::EnrollmentChannel{
    EnrollmentChannel& c;e::Bytes prefix;std::size_t at{};e::PairingSession::Clock::time_point deadline;
    Prefix(EnrollmentChannel& ch,e::Bytes b,e::PairingSession::Clock::time_point end):c(ch),prefix(std::move(b)),deadline(end){}
    Read read(std::span<std::byte> out,std::chrono::milliseconds t)override{require(e::PairingSession::Clock::now()<deadline);
        if(at<prefix.size()){const auto n=std::min(out.size(),prefix.size()-at);std::copy_n(prefix.begin()+static_cast<std::ptrdiff_t>(at),n,out.begin());at+=n;return {n,false};}return c.read(out,t);}
    void write(std::span<const std::byte> b,e::PairingSession::Clock::time_point until,const std::atomic_bool& stop)override{c.write(b,std::min(until,deadline),stop);}
    void close()noexcept override{c.close();}
};
}
class NativeStatusService::Impl {
public:
    std::string bind;std::uint16_t desktop_port;e::Bytes identity,root;core::Sha256Digest peer;
    std::atomic_bool stop{};std::unique_ptr<tcp::Listener> listener;std::thread worker;
    std::mutex cache_mutex;std::optional<e::StatusSnapshot> cache;
    core::CancellationSource rollover;e::Bytes active_identity;std::optional<e::StatusSnapshot> active;
    Impl(std::string address,std::uint16_t port,e::Bytes id,core::Sha256Digest p,e::Bytes r)
        :bind(std::move(address)),desktop_port(port),identity(std::move(id)),root(std::move(r)),peer(p){
        active=current(true);
        {auto file=platform::macos::enrollment_journal();auto keys=platform::macos::enrollment_key_store();auto ids=platform::macos::enrollment_identity_store();auto verifier=platform::macos::enrollment_pairing_verifier();
            active_identity=e::CredentialInstaller::install(*file,*keys,*ids,*verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())).native_reference;}
        listener=tcp::listen(tcp::parse_private_ipv4(bind),tcp::pairing_port);
        worker=std::thread([this]{run();});
    }
    void validate(e::FileEnrollmentJournal& file,e::IdentityStore& ids,const e::PairProofVerifier& verifier){
        const auto r=e::DurablePairing::inspect(file,verifier);require(r && r->staged.role==e::PairRole::host && !r->receipts[4].empty() && r->receipts[5].empty());
        require(r->transcript.host.desktop_ipv4==tcp::parse_private_ipv4(bind) && r->transcript.host.desktop_port==desktop_port && r->staged.bundle.root==root && core::sha256(r->staged.bundle.client)==peer);
        require(ids.describe(r->staged.keys.back().reference,r->staged.bundle.server,r->transcript.host.desktop_ipv4)==identity);
    }
    e::StatusSnapshot current(bool renew=false){
        auto file=platform::macos::enrollment_journal();auto keys=platform::macos::enrollment_key_store();auto ids=platform::macos::enrollment_identity_store();auto verifier=platform::macos::enrollment_pairing_verifier();
        validate(*file,*ids,*verifier);auto result=e::EnrollmentStatus::issue(*file,*keys,*ids,*verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()),renew);
        if(active)require(result.bundle.root==active->bundle.root && result.bundle.server==active->bundle.server && result.bundle.client==active->bundle.client);
        {std::lock_guard lock(cache_mutex);cache=result;}return result;
    }
    e::Bytes client_ocsp(){
        // The TLS verification queue performs no journal, Keychain signing or
        // public-socket wait. Native TLS still validates this response itself.
        const auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        std::lock_guard lock(cache_mutex);require(cache && now+std::chrono::minutes{5}>=cache->issued && now<cache->expires);
        return cache->bundle.client_ocsp;
    }
    void run(){auto refresh_at=e::PairingSession::Clock::now()+std::chrono::minutes{1};while(!stop){try{
        if(e::PairingSession::Clock::now()>=refresh_at){
            const auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());const auto ip=tcp::parse_private_ipv4(bind);
            if(e::certificate_facts(active->bundle.root,e::KeyPurpose::authority).validity.after<now+std::chrono::days{365} ||
               e::certificate_facts(active->bundle.server,e::KeyPurpose::server,ip).validity.after<now+std::chrono::days{30} ||
               e::certificate_facts(active->bundle.client,e::KeyPurpose::client).validity.after<now+std::chrono::days{30}){
                rollover.request_stop();stop=true;break;
            }
            refresh_at=e::PairingSession::Clock::now()+std::chrono::minutes{1};(void)current();
        }
        auto channel=listener->accept(std::chrono::milliseconds{20});if(!channel)continue;
        e::Bytes first;const auto until=e::PairingSession::Clock::now()+std::chrono::seconds{3};
        while(first.size()<4){require(!stop && e::PairingSession::Clock::now()<until);const auto old=first.size();first.resize(4);const auto n=channel->read(std::span(first).subspan(old),std::chrono::milliseconds{20});require(!n.eof && n.bytes<=4-old);first.resize(old+n.bytes);}
        Prefix buffered(*channel,first,until);
        auto file=platform::macos::enrollment_journal();auto keys=platform::macos::enrollment_key_store();auto ids=platform::macos::enrollment_identity_store();auto verifier=platform::macos::enrollment_pairing_verifier();validate(*file,*ids,*verifier);
        if(std::memcmp(first.data(),"LPQ1",4)==0)e::serve_status(buffered,*file,*keys,*ids,*verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()),stop);
        else if(std::memcmp(first.data(),"LPR1",4)==0){e::EnrollmentSetupCallbacks callbacks;callbacks.random=tcp::secure_random;
            callbacks.show_comparison=[](auto){throw std::runtime_error("background renewal cannot approve pairing");};
            (void)e::recover_enrollment(buffered,*file,*keys,*ids,*verifier,tcp::parse_private_ipv4(bind),callbacks,stop);
        }
        // LPP1 and all unknown protocols are rejected; no first-use UI/keys/grant.
    }catch(...){/* Bounded public request failure never changes desktop authority. */}}}
    ~Impl(){stop=true;if(worker.joinable())worker.join();}
};
NativeStatusService::NativeStatusService(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
NativeStatusService::~NativeStatusService()=default;
std::shared_ptr<NativeStatusService> NativeStatusService::create(std::string bind,std::uint16_t port,e::Bytes identity,core::Sha256Digest peer,e::Bytes root){
    if(!platform::macos::is_enrollment_identity_reference(identity))return {};
    return std::shared_ptr<NativeStatusService>(new NativeStatusService(std::make_unique<Impl>(std::move(bind),port,std::move(identity),peer,std::move(root))));
}
e::Bytes NativeStatusService::client_ocsp(){return impl_->client_ocsp();}
e::Bytes NativeStatusService::server_identity()const{return impl_->active_identity;}
e::Bytes NativeStatusService::root()const{return impl_->active->bundle.root;}
core::Sha256Digest NativeStatusService::client_fingerprint()const{return core::sha256(impl_->active->bundle.client);}
core::CancellationToken NativeStatusService::rollover_token()const{return impl_->rollover.token();}
}
