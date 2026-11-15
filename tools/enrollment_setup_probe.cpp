// Explicit isolated runtime probe. Synthetic comparison exists ONLY here;
// production native UIs never accept an auto-approve flag. No desktop/input.
#include "rwn/platform/enrollment_tcp.hpp"
#include "enrollment_journal_fixture.hpp"
#include "rwn/core/enrollment_status.hpp"
#include "enrollment_status_fixture.hpp"
#include "enrollment_credential_fixture.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <algorithm>
#include <charconv>
#include <cstring>
#if defined(_WIN32)
#include "rwn/platform/windows/enrollment_key.hpp"
#include "rwn/platform/windows/enrollment_identity.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include "rwn/platform/macos/enrollment_key.hpp"
#include "rwn/platform/macos/enrollment_identity.hpp"
#include <unistd.h>
#include <fcntl.h>
#endif
namespace e=rwn::core::enrollment;namespace tcp=rwn::platform::enrollment;
namespace {
void check(bool b){if(!b)throw std::runtime_error("isolated setup probe failed");}
template<class F>void reject(F f){bool failed=false;try{f();}catch(...){failed=true;}check(failed);}
struct NativeStores {
#if defined(_WIN32)
    HCERTSTORE certs{CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,CERT_STORE_CREATE_NEW_FLAG,nullptr)};
    NativeStores(){check(certs!=nullptr);}~NativeStores(){if(certs)CertCloseStore(certs,0);}
    auto keys(){return rwn::platform::windows::enrollment_key_store();}
    auto identities(){return rwn::platform::windows::enrollment_identity_store(certs);}
    auto verifier(){return rwn::platform::windows::enrollment_pairing_verifier();}
#else
    SecKeychainRef keychain{};std::filesystem::path root;
    NativeStores(){check(SecKeychainSetUserInteractionAllowed(false)==errSecSuccess);
        auto pattern=(std::filesystem::canonical(std::filesystem::temp_directory_path())/"lanpilot-setup-keychain-XXXXXX").string();check(mkdtemp(pattern.data())!=nullptr);root=pattern;
        std::array<std::byte,32> password{};tcp::secure_random(password);CFArrayRef before{};check(SecKeychainCopySearchList(&before)==errSecSuccess);
        const auto created=SecKeychainCreate((root/"fixture.keychain").c_str(),32,password.data(),false,nullptr,&keychain);
        const auto restored=SecKeychainSetSearchList(before);CFRelease(before);std::fill(password.begin(),password.end(),std::byte{});check(created==errSecSuccess && restored==errSecSuccess && keychain);
    }
    ~NativeStores(){if(keychain){SecKeychainDelete(keychain);CFRelease(keychain);}std::error_code error;std::filesystem::remove(root,error);}
    auto keys(){return rwn::platform::macos::enrollment_key_store(keychain);}
    auto identities(){return rwn::platform::macos::enrollment_identity_store(keychain);}
    auto verifier(){return rwn::platform::macos::enrollment_pairing_verifier();}
#endif
};
[[maybe_unused]] void ready_file(const std::filesystem::path& p,std::uint16_t port){
    check(p.is_absolute() && p==p.lexically_normal() && std::filesystem::canonical(p.parent_path())==p.parent_path());const auto text=std::to_string(port)+"\n";
#if defined(_WIN32)
    const auto file=CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(file!=INVALID_HANDLE_VALUE);DWORD n{};
    const bool good=WriteFile(file,text.data(),static_cast<DWORD>(text.size()),&n,nullptr) && n==text.size() && FlushFileBuffers(file);CloseHandle(file);check(good);
#else
    const auto file=open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);check(file>=0);const auto n=write(file,text.data(),text.size());const bool good=n==static_cast<ssize_t>(text.size()) && fsync(file)==0;close(file);check(good);
#endif
}
void cleanup(const std::filesystem::path& root,e::KeyStore& keys,e::IdentityStore& identities,const e::PairProofVerifier& verifier){
    for(const auto* name:{"credential.current","credential.retired"})if(std::filesystem::exists(root/name)){
        const auto updated=e::decode_enrollment_record(rwn::fixture::status_bytes(root/name));
        for(const auto& key:updated.keys)check(key.existed); // Renewal never owns a private key.
        if(updated.phase!=e::EnrollmentPhase::keys && !updated.certificate_existed){const auto& cert=updated.role==e::PairRole::host?updated.bundle.server:updated.bundle.client;
            if(auto local=identities.locate(updated.keys.back().reference,cert,updated.server_ipv4)){local->created=true;check(identities.remove_created(*local));}
            check(identities.certificate_absent(cert));
        }
    }
    const auto path=root/"enrollment.pending";if(!std::filesystem::exists(path))return;
    check(std::filesystem::file_size(path)<=e::enrollment_storage_cap);std::ifstream f(path,std::ios::binary);std::vector<char> text((std::istreambuf_iterator<char>(f)),{});
    const auto bytes=std::as_bytes(std::span{text});e::EnrollmentRecord r;
    if(bytes.size()>=4 && bytes[3]==std::byte{1})r=e::decode_enrollment_record(bytes);else r=e::decode_enrollment_commit(bytes,verifier).staged;
    if(r.phase!=e::EnrollmentPhase::keys){const auto& cert=r.role==e::PairRole::host?r.bundle.server:r.bundle.client;
        if(auto identity=identities.locate(r.keys.back().reference,cert,r.server_ipv4)){identity->created=!r.certificate_existed;check(identities.remove_created(*identity));}}
    for(const auto& key:r.keys)if(!key.existed){auto actual=keys.open(key.reference);if(actual){const auto point=actual->public_key();actual.reset();check(keys.remove_if_matches(key.reference,point));}}
}
int socket_test(){
    for(const auto* bad:{"8.8.8.8","0.0.0.0","192.168.00.1","192.168.1.1x","::1","example.test","192.168.1"})reject([&]{tcp::parse_private_ipv4(bad);});
    const auto ip=tcp::parse_private_ipv4("127.0.0.1");auto listener=tcp::listen(ip,0);std::atomic_bool stop{};
    auto client=tcp::connect(ip,listener->port(),std::chrono::seconds{1},stop);auto server=listener->accept(std::chrono::seconds{1});check(server!=nullptr);
    const std::array data{std::byte{'L'},std::byte{'P'},std::byte{'P'},std::byte{'1'}};client->write(data,e::PairingSession::Clock::now()+std::chrono::seconds{1},stop);
    std::array<std::byte,16> received{};const auto read=server->read(received,std::chrono::seconds{1});check(read.bytes==data.size() && !read.eof && std::equal(data.begin(),data.end(),received.begin()));
    check(server->read(received,std::chrono::milliseconds{5}).bytes==0);client->close();check(server->read(received,std::chrono::seconds{1}).eof);
    stop=true;reject([&]{tcp::connect(ip,listener->port(),std::chrono::seconds{1},stop);});
    std::cout<<"enrollment_socket=PASS loopback=1 bounded_timeout=1 eof=1 cancelled_connect_rejected=1 private_ipv4=1 desktop_data=0\n";return 0;
}
struct InterruptChannel final:e::EnrollmentChannel {
    EnrollmentChannel& inner;unsigned kind;bool after{},injected{};
    InterruptChannel(EnrollmentChannel& c,unsigned k,bool a):inner(c),kind(k),after(a){}
    Read read(std::span<std::byte> b,std::chrono::milliseconds t)override{return inner.read(b,t);}
    void write(std::span<const std::byte> b,e::PairingSession::Clock::time_point t,const std::atomic_bool& stop)override{
        if(kind && !injected && b.size()>=143 && std::memcmp(b.data(),"LPC1",4)==0 && std::to_integer<unsigned>(b[4])==kind){
            injected=true;if(after)inner.write(b,t,stop);inner.close();throw std::runtime_error("fixture controlled connection interruption");
        }inner.write(b,t,stop);
    }
    void close()noexcept override{inner.close();}
};
void same_identity(const e::EnrollmentCommitRecord& before,const e::EnrollmentCommitRecord& after){
    check(before.round==after.round && before.staged.transaction==after.staged.transaction && before.staged.keys.size()==after.staged.keys.size() &&
        before.transcript.binding==after.transcript.binding && before.staged.bundle.root==after.staged.bundle.root);
    for(std::size_t i=0;i<before.staged.keys.size();++i)check(before.staged.keys[i].reference.id==after.staged.keys[i].reference.id && before.staged.keys[i].point==after.staged.keys[i].point);
}
}
int main(int argc,char** argv){try{
    if(argc==1)return socket_test();
    check(argc>=4);const std::string mode(argv[1]);const auto ip=tcp::parse_private_ipv4(argv[2]);unsigned port{};const auto number=std::string_view(argv[3]);
    const auto parsed=std::from_chars(number.data(),number.data()+number.size(),port);check(parsed.ec==std::errc{} && parsed.ptr==number.data()+number.size() && port<=65535);
    rwn::fixture::JournalDirectory directory;NativeStores native;auto file=directory.open();auto keys=native.keys();auto identities=native.identities();auto verifier=native.verifier();
    struct Cleanup{const std::filesystem::path& root;e::KeyStore& keys;e::IdentityStore& ids;const e::PairProofVerifier& v;bool done{};~Cleanup(){if(!done)try{cleanup(root,keys,ids,v);}catch(...){}}} owned{directory.root,*keys,*identities,*verifier};
    unsigned comparisons{};e::EnrollmentSetupCallbacks cb;cb.random=tcp::secure_random;cb.show_comparison=[&](auto model){++comparisons;check(model->local_decision(model->binding(),true,e::PairingSession::Clock::now()));};
    cb.progress=[](std::string_view stage){std::cout<<"enrollment_fixture=progress stage="<<stage<<" synthetic_local_consent=1\n"<<std::flush;};std::atomic_bool stop{};
    std::string fault;
    if(mode=="--fixture-host" && argc==7)fault=argv[6];
    if(mode=="--fixture-client" && argc==6)fault=argv[5];
    const bool status_mode=fault=="status-renewal",credential_mode=fault=="credential-renewal";if(status_mode || credential_mode)fault.clear();
    check(fault.empty() || fault=="host-prepared" || fault=="host-decision" || fault=="client-committed" || fault=="host-final" || fault=="abort-retry" || fault=="host-only-retry");
    const bool retry=fault=="abort-retry" || fault=="host-only-retry";
    auto retire=[&](e::PairRole role,const std::optional<e::EnrollmentCommitRecord>& before){
        e::prepare_enrollment_retry(*file,*keys,*identities,*verifier,role);
        check(!e::DurablePairing::inspect(*file,*verifier));
        if(before){check(e::DurablePairing::archived_abort(*file,before->round,*verifier).has_value());
            for(const auto& k:before->staged.keys)if(!k.existed)check(!keys->open(k.reference));}
    };
    auto resume=[&](e::EnrollmentChannel& channel,const e::EnrollmentCommitRecord& before){
        file.reset();file=directory.open(); // Fresh coordinator; only native files/keys survive.
        cb.show_comparison=[](auto){throw std::runtime_error("recovery revived comparison UI");};
        const auto proof=e::recover_enrollment(channel,*file,*keys,*identities,*verifier,ip,cb,stop);
        const auto after=e::DurablePairing::inspect(*file,*verifier);check(after.has_value());same_identity(before,*after);
        if(fault=="host-prepared")check(!proof && !after->receipts[5].empty() && after->receipts[2].empty());
        else{check(proof.has_value());(void)e::EnrollmentConfigurationHandoff::persist(*file,*proof,*identities,*verifier);}
    };
    if(mode=="--fixture-host"){
#if defined(_WIN32)
        throw std::runtime_error("host fixture requires native Mac configuration backend");
#else
        check(argc>=5 && argc<=7);auto bind_ip=ip;
        if(argc>=6){bind_ip=tcp::parse_private_ipv4(argv[5]);check(bind_ip==tcp::parse_private_ipv4("127.0.0.1"));}
        auto listener=tcp::listen(bind_ip,static_cast<std::uint16_t>(port));ready_file(argv[4],listener->port());
        auto accept=[&]{const auto deadline=e::PairingSession::Clock::now()+std::chrono::seconds{45};std::unique_ptr<e::EnrollmentChannel> accepted;
            while(e::PairingSession::Clock::now()<deadline){accepted=listener->accept(std::chrono::milliseconds{20});if(accepted)break;}check(accepted!=nullptr);return accepted;};
        auto channel=accept();
        std::cout<<"fixture_socket=accepted\n"<<std::flush;
        InterruptChannel controlled(*channel,(fault=="host-prepared" || retry)?1U:fault=="host-decision"?3U:fault=="host-final"?5U:0U,fault=="host-prepared" || fault=="abort-retry");
        const auto lifetimes=credential_mode?e::EnrollmentCertificateLifetimes{std::chrono::days{30},std::chrono::days{7}}:e::EnrollmentCertificateLifetimes{};
        bool failed=false;try{(void)e::enroll_host(controlled,*file,*keys,*identities,*verifier,{ip,45443},cb,stop,lifetimes);}catch(...){if(fault.empty())throw;failed=true;}
        if(!fault.empty()){check(failed);const auto before=e::DurablePairing::inspect(*file,*verifier);check(before.has_value());
            if(retry){retire(e::PairRole::host,before);channel=accept();(void)e::enroll_host(*channel,*file,*keys,*identities,*verifier,{ip,45443},cb,stop);
                check(e::DurablePairing::inspect(*file,*verifier)->round!=before->round);
                if(fault=="abort-retry"){
                    const auto committed=e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier));channel=accept();
                    check(!e::recover_enrollment(*channel,*file,*keys,*identities,*verifier,ip,cb,stop));
                    check(e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier))==committed);
                    std::cout<<"late_abort_replay=PASS current_commit_preserved=1 old_private_key_required=0\n";
                }}
            else{channel=accept();resume(*channel,*before);}}
        if(credential_mode){
            const auto before=*e::DurablePairing::inspect(*file,*verifier);const auto saved=e::encode_enrollment_commit(before);rwn::fixture::NoNewCredentialKeys same_keys(*keys);
            const auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());const auto renewed=e::EnrollmentStatus::issue(*file,same_keys,*identities,*verifier,now,true);
            check(renewed.bundle.root!=before.staged.bundle.root && renewed.bundle.server!=before.staged.bundle.server && renewed.bundle.client!=before.staged.bundle.client);
            const auto local=e::CredentialInstaller::install(*file,same_keys,*identities,*verifier,now);check(identities->ready(local));
            for(unsigned reload=0;reload<2;++reload){channel=accept();e::serve_status(*channel,*file,same_keys,*identities,*verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()),stop);}
            check(same_keys.creates==0 && comparisons==1 && e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier))==saved);
            std::cout<<"enrollment_credential_runtime=PASS root_and_leaves_renewed=1 same_private_keys=1 no_reapproval=1 client_certificate_sha256="<<rwn::fixture::credential_hex(rwn::core::sha256(renewed.bundle.client))<<" server_certificate_sha256="<<rwn::fixture::credential_hex(rwn::core::sha256(renewed.bundle.server))<<" installed_changes=0\n";
        }
        if(status_mode){
            const auto before=*e::DurablePairing::inspect(*file,*verifier);const auto original=e::encode_enrollment_commit(before);
            auto wall=[](){return std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());};
            channel=accept();e::serve_status(*channel,*file,*keys,*identities,*verifier,wall(),stop);
            for(unsigned cycle=0;cycle<2;++cycle){
                const auto old=rwn::fixture::expired_status(before,*keys,wall());check(!identities->verify_revocation(old.bundle,ip,wall()));
                // Install a previously-valid expired fixture state while
                // retaining its actual native keys and protected file ACL.
                rwn::fixture::status_write(directory.root/"revocation.current",old.wire);channel=accept();
                const auto expected=e::status_request(before);e::Bytes request;const auto deadline=e::PairingSession::Clock::now()+std::chrono::seconds{3};
                while(request.size()<expected.size()){
                    check(e::PairingSession::Clock::now()<deadline);const auto offset=request.size();request.resize(expected.size());
                    const auto n=channel->read(std::span(request).subspan(offset),std::chrono::milliseconds{20});check(!n.eof && n.bytes<=expected.size()-offset);request.resize(offset+n.bytes);
                }
                check(request==expected);channel->write(old.wire,deadline,stop);channel->close();
                channel=accept();e::serve_status(*channel,*file,*keys,*identities,*verifier,wall(),stop);
                check(e::EnrollmentStatus::cached(*file,*identities,*verifier,wall()).has_value());
                check(e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier))==original);
            }
            check(comparisons==1);std::cout<<"enrollment_status_runtime=PASS real_expired_evidence=1 renewals=2 immutable_pairing=1 unchanged_native_keys=1 installed_changes=0\n";
        }
#endif
    }else{check(mode=="--fixture-client" && argc>=4 && argc<=6 && port>0);
#if !defined(_WIN32)
        throw std::runtime_error("client fixture requires native Windows configuration backend");
#else
        // Optional fixture-only loopback tunnel isolates application protocol
        // correctness from native per-executable inbound network admission.
        // The expected, approved host address remains the original LAN IPv4.
        auto socket_ip=ip;
        if(argc>=5){socket_ip=tcp::parse_private_ipv4(argv[4]);check(socket_ip==tcp::parse_private_ipv4("127.0.0.1"));}
        auto channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);
        std::cout<<"fixture_socket=connected\n"<<std::flush;
        InterruptChannel controlled(*channel,fault=="client-committed"?4U:0U,false);
        bool failed=false;try{(void)e::enroll_client(controlled,*file,*keys,*identities,*verifier,ip,cb,stop);}catch(...){if(fault.empty())throw;failed=true;}
        if(!fault.empty()){check(failed);const auto before=e::DurablePairing::inspect(*file,*verifier);check(before.has_value() || fault=="host-only-retry");
            channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);
            if(retry){if(before){check(!e::recover_enrollment(*channel,*file,*keys,*identities,*verifier,ip,cb,stop,true));retire(e::PairRole::client,before);}
                (void)e::enroll_client(*channel,*file,*keys,*identities,*verifier,ip,cb,stop);
                if(before)check(e::DurablePairing::inspect(*file,*verifier)->round!=before->round);
                if(fault=="abort-retry"){
                    check(before.has_value());const auto committed=e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier));
                    // A separate isolated journal models a late prepared client
                    // after the original owned keys have already been removed.
                    // Seed its protected file using only this fixture's saved
                    // public record; no installed data or private key is copied.
                    rwn::fixture::JournalDirectory late;auto late_file=late.open();e::EnrollmentStager seed(*late_file,*keys,*identities);
                    std::array<std::byte,32> id{};tcp::secure_random(id);const auto ref=before->staged.keys.back().reference;seed.begin(id,e::PairRole::client,std::span{&ref,1});
                    const auto bytes=e::encode_enrollment_commit(*before);
                    {std::ofstream out(late.root/"enrollment.pending",std::ios::binary|std::ios::trunc);out.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));check(out.good());}
                    channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);
                    check(!e::recover_enrollment(*channel,*late_file,*keys,*identities,*verifier,ip,cb,stop));
                    e::prepare_enrollment_retry(*late_file,*keys,*identities,*verifier,e::PairRole::client);
                    check(!e::DurablePairing::inspect(*late_file,*verifier) && e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier))==committed);
                    std::cout<<"late_abort_replay=PASS current_commit_preserved=1 old_private_key_required=0\n";
                }}
            else resume(*channel,*before);}
        if(credential_mode){
            const auto before=*e::DurablePairing::inspect(*file,*verifier);const auto saved=e::encode_enrollment_commit(before);rwn::fixture::NoNewCredentialKeys same_keys(*keys);
            const auto original=identities->describe(before.staged.keys.back().reference,before.staged.bundle.client,ip);e::AssociatedIdentity local;
            for(unsigned reload=0;reload<2;++reload){
                const auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
                const auto selected=e::EnrollmentStatus::connection_credentials(*file,same_keys,*identities,*verifier,before.staged.bundle.root,rwn::core::sha256(before.staged.bundle.server),original,now,[&]{
                    channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);return e::exchange_status(*channel,e::status_request(before),stop);});
                check(selected.bundle.root!=before.staged.bundle.root && selected.bundle.client!=before.staged.bundle.client);local=e::CredentialInstaller::install(*file,same_keys,*identities,*verifier,now);check(identities->ready(local));
                file.reset();file=directory.open();check(e::CredentialInstaller::install(*file,same_keys,*identities,*verifier,now).native_reference==local.native_reference);
            }
            const auto selected=e::EnrollmentStatus::cached(*file,*identities,*verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
            check(selected && same_keys.creates==0 && comparisons==1 && e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier))==saved);
            std::cout<<"enrollment_credential_runtime=PASS root_and_leaves_renewed=1 same_private_keys=1 no_reapproval=1 native_identity_ready=1 cache_and_association_reopened=1 client_certificate_sha256="<<rwn::fixture::credential_hex(rwn::core::sha256(selected->bundle.client))<<" server_certificate_sha256="<<rwn::fixture::credential_hex(rwn::core::sha256(selected->bundle.server))<<" installed_changes=0\n";
        }
        if(status_mode){
            const auto before=*e::DurablePairing::inspect(*file,*verifier);const auto original=e::encode_enrollment_commit(before);
            auto wall=[](){return std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());};
            channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);
            (void)e::fetch_status(*channel,*file,*identities,*verifier,wall(),stop);
            const auto local=identities->locate(before.staged.keys.back().reference,before.staged.bundle.client,ip);check(local && identities->ready(*local));
            for(unsigned cycle=0;cycle<2;++cycle){
                channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);
                const auto old=e::exchange_status(*channel,e::status_request(before),stop);
                reject([&]{e::EnrollmentStatus::accept(*file,*identities,*verifier,old,wall());});
                rwn::fixture::status_write(directory.root/"revocation.current",old);file.reset();file=directory.open();unsigned fetches{};
                rwn::fixture::CurrentStatusOnly current_native(*identities,wall());
                const auto crl=e::EnrollmentStatus::connection_crl(*file,current_native,*verifier,before.staged.bundle.root,rwn::core::sha256(before.staged.bundle.server),local->native_reference,current_native.now,[&]{
                    ++fetches;channel=tcp::connect(socket_ip,static_cast<std::uint16_t>(port),std::chrono::seconds{5},stop);
                    return e::exchange_status(*channel,e::status_request(before),stop);
                });
                check(fetches==1);file.reset();file=directory.open();const auto renewed=e::EnrollmentStatus::cached(*file,*identities,*verifier,wall());
                check(renewed && renewed->bundle.crl==crl && identities->verify_revocation(renewed->bundle,ip,wall()));
                check(e::EnrollmentStatus::connection_crl(*file,*identities,*verifier,before.staged.bundle.root,rwn::core::sha256(before.staged.bundle.server),local->native_reference,wall(),[]()->e::Bytes{throw std::runtime_error("unexpected cache network access");})==crl);
                check(e::encode_enrollment_commit(*e::DurablePairing::inspect(*file,*verifier))==original && identities->ready(*local));
            }
            check(comparisons==1);std::cout<<"enrollment_status_runtime=PASS real_expired_evidence=1 renewals=2 native_positive=1 connection_selector=1 cache_reopen=1 no_rekey=1 no_reapproval=1 system_clock_changed=0 installed_changes=0\n";
        }
#endif
    }
    check(e::EnrollmentConfigurationHandoff::recover(*file,*keys,*identities,*verifier).has_value()==(fault!="host-prepared"));cleanup(directory.root,*keys,*identities,*verifier);owned.done=true;
    if(retry){check(comparisons==2);std::cout<<"enrollment_abort_retry=PASS new_dual_confirmation=1 old_owned_keys_removed=1 abort_history_preserved=1 new_transaction=1\n";}
    if(!fault.empty() && !retry)std::cout<<"enrollment_recovery=PASS phase="<<fault<<" no_rekey=1 fresh_peer_proof=1 no_comparison_revival=1 safe_abort="<<(fault=="host-prepared"?1:0)<<"\n";
    std::cout<<"enrollment_first_contact=PASS actual_socket=1 native_stores=1 signed_mutual_approval=1 durable_both_committed="<<(fault=="host-prepared"?0:1)<<" compatible_configuration=1 synthetic_consent=1 installed_changes=0 desktop_data=0\n";return 0;
}catch(const std::exception& error){std::cerr<<"enrollment_setup_probe_failed="<<error.what()<<'\n';return 1;}}
