#pragma once
#include "rwn/core/enrollment_status.hpp"
#include <fstream>
#include <iostream>
#include <source_location>

namespace rwn::fixture {
inline core::enrollment::Bytes status_bytes(const std::filesystem::path& path){
    const auto size=std::filesystem::file_size(path);if(size==0 || size>core::enrollment::status_wire_cap)throw std::runtime_error("fixture status size");
    core::enrollment::Bytes b(static_cast<std::size_t>(size));std::ifstream in(path,std::ios::binary);
    in.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));if(!in || in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("fixture status read");return b;
}
inline void status_write(const std::filesystem::path& path,std::span<const std::byte> b){
    std::ofstream out(path,std::ios::binary|std::ios::trunc);out.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));out.flush();if(!out)throw std::runtime_error("fixture status write");
}
// Construct previously-valid but NOW expired signed evidence, using only this
// fixture's actual native CA key and certificate-valid time interval. No clock
// change or relaxation of a native trust policy is needed to test renewal.
inline core::enrollment::StatusSnapshot expired_status(const core::enrollment::EnrollmentCommitRecord& host,
    core::enrollment::KeyStore& keys,core::enrollment::Time now){
    namespace e=core::enrollment;using namespace std::chrono;
    auto issuer=keys.open(host.staged.keys.front().reference);const auto& b=host.staged.bundle;
    const auto root=e::certificate_facts(b.root,e::KeyPurpose::authority),server=e::certificate_facts(b.server,e::KeyPurpose::server,host.transcript.host.desktop_ipv4),client=e::certificate_facts(b.client,e::KeyPurpose::client);
    const auto before=std::max({now-seconds{30},server.validity.before,client.validity.before}),after=now-seconds{1};
    if(before>=after)throw std::runtime_error("fixture needs a certificate-valid expired interval");
    auto old=b;old.crl=e::revocation_list(*issuer,1,{before,after},root.validity,{});
    old.server_ocsp=e::ocsp_response(*issuer,server.serial,e::Status::good,before,{before,after},root.validity);
    old.client_ocsp=e::ocsp_response(*issuer,client.serial,e::Status::good,before,{before,after},root.validity);
    auto add=[](e::Bytes& out,std::span<const std::byte> bytes){out.insert(out.end(),bytes.begin(),bytes.end());};
    auto number=[](e::Bytes& out,std::uint64_t n,unsigned size){for(unsigned i=size;i>0;--i)out.push_back(static_cast<std::byte>(n>>((i-1)*8)));};
    e::Bytes body{std::byte{1},std::byte{},std::byte{},std::byte{}};const auto request=e::status_request(host);add(body,std::span(request).subspan(4));
    number(body,static_cast<std::uint64_t>(before.time_since_epoch().count()),8);number(body,static_cast<std::uint64_t>(after.time_since_epoch().count()),8);
    for(const auto* p:{&old.crl,&old.server_ocsp,&old.client_ocsp})add(body,core::sha256(*p));
    for(const auto* p:{&old.crl,&old.server_ocsp,&old.client_ocsp})number(body,p->size(),4);
    constexpr std::string_view domain="LanPilot native revocation refresh v1";e::Bytes message;add(message,std::as_bytes(std::span{domain}));message.push_back(std::byte{});add(message,body);
    const auto signature=issuer->sign_sha256(message);number(body,signature.size(),2);add(body,signature);
    for(const auto* p:{&old.crl,&old.server_ocsp,&old.client_ocsp})add(body,*p);
    e::Bytes wire{std::byte{'L'},std::byte{'P'},std::byte{'S'},std::byte{'1'}};number(wire,body.size(),4);add(wire,body);
    return {std::move(wire),std::move(old),before,after};
}
struct StatusChannel final:core::enrollment::EnrollmentChannel {
    core::enrollment::Bytes incoming,sent;std::size_t at{};bool closed{};
    explicit StatusChannel(core::enrollment::Bytes b):incoming(std::move(b)){}
    Read read(std::span<std::byte> out,std::chrono::milliseconds)override{
        const auto n=std::min({out.size(),incoming.size()-at,std::size_t{3}});
        std::copy_n(incoming.begin()+static_cast<std::ptrdiff_t>(at),n,out.begin());at+=n;return {n,n==0};
    }
    void write(std::span<const std::byte> b,core::PairingConsent::Clock::time_point,const std::atomic_bool& stop)override{
        if(stop)throw std::runtime_error("cancelled fixture write");
        sent.assign(b.begin(),b.end());
    }
    void close()noexcept override{closed=true;}
};
// Simulate the documented native limitation: cached evidence cannot be made
// fresh merely by asking the OS about its historical issue date. Real native
// validation is still mandatory for all evidence at the requested new time.
struct CurrentStatusOnly final:core::enrollment::IdentityStore {
    core::enrollment::IdentityStore& native;core::enrollment::Time now;
    CurrentStatusOnly(core::enrollment::IdentityStore& n,core::enrollment::Time t):native(n),now(t){}
    core::enrollment::AssociatedIdentity associate(const core::enrollment::ApprovedPairing& a,const core::enrollment::KeyReference& k,core::enrollment::PublicIdentityBundle b,core::PairingConsent::Clock::time_point t)override{return native.associate(a,k,std::move(b),t);}
    bool ready(const core::enrollment::AssociatedIdentity& i)override{return native.ready(i);}
    std::optional<core::enrollment::AssociatedIdentity> locate(const core::enrollment::KeyReference& k,core::enrollment::Bytes b,std::array<std::byte,4> ip)override{return native.locate(k,std::move(b),ip);}
    bool remove_created(const core::enrollment::AssociatedIdentity& i)override{return native.remove_created(i);}
    bool verify_revocation(const core::enrollment::PublicIdentityBundle& b,std::array<std::byte,4> ip,core::enrollment::Time t={})override{return t==now && native.verify_revocation(b,ip,t);}
};
// Real native issuer, trust evaluators and protected files. Only verification
// time is advanced; the system clock, installed stores and services are not.
template<class Check,class Reject>
void status_fixture(core::enrollment::FileEnrollmentJournal& host,
    core::enrollment::FileEnrollmentJournal& client,core::enrollment::KeyStore& keys,
    core::enrollment::IdentityStore& ids,const core::enrollment::PairProofVerifier& verifier,
    const std::filesystem::path& host_root,const std::filesystem::path& client_root,Check,Reject){
    namespace e=core::enrollment;using namespace std::chrono;
    auto check=[](bool good,const std::source_location where=std::source_location::current()){
        if(!good)throw std::runtime_error("native status fixture condition at line "+std::to_string(where.line()));};
    auto reject=[](auto operation,const std::source_location where=std::source_location::current()){
        bool failed=false;try{operation();}catch(...){failed=true;}
        if(!failed)throw std::runtime_error("native status fixture unexpected acceptance at line "+std::to_string(where.line()));};
    const auto now=floor<seconds>(system_clock::now()),future=now+days{2};
    const auto hr=*e::DurablePairing::inspect(host,verifier),cr=*e::DurablePairing::inspect(client,verifier);
    const auto hrecord=e::encode_enrollment_commit(hr),crecord=e::encode_enrollment_commit(cr);
    const auto& b=cr.staged.bundle;const auto ip=cr.transcript.host.desktop_ipv4;
    check(!e::EnrollmentStatus::cached(client,ids,verifier,now));
    reject([&]{e::EnrollmentStatus::issue(client,keys,ids,verifier,now);});
    const auto first=e::EnrollmentStatus::issue(host,keys,ids,verifier,now);
    check(first.bundle.root==b.root && first.bundle.server==b.server && first.bundle.client==b.client);
    check(e::EnrollmentStatus::issue(host,keys,ids,verifier,now).wire==first.wire);
    check(e::EnrollmentStatus::accept(client,ids,verifier,first.wire,now).wire==first.wire);
    // A crash may leave even an empty staging file; native ownership still
    // applies before cleanup. This fixture retains the protected file's ACL.
    const auto path=client_root/"revocation.current",stage=client_root/".revocation.next";
    std::filesystem::rename(path,stage);std::filesystem::resize_file(stage,0);
    check(e::EnrollmentStatus::accept(client,ids,verifier,first.wire,now).wire==first.wire && !std::filesystem::exists(stage));
    const auto expired=expired_status(hr,keys,now);
    check(!ids.verify_revocation(expired.bundle,ip,now));
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,expired.wire,now);});
    status_write(host_root/"revocation.current",expired.wire);status_write(path,expired.wire);
    CurrentStatusOnly actual_native(ids,now);
    const auto fresh=e::EnrollmentStatus::issue(host,keys,actual_native,verifier,now);
    check(fresh.issued>expired.issued && ids.verify_revocation(fresh.bundle,ip,now));
    const auto native_local=ids.locate(cr.staged.keys.back().reference,b.client,ip);check(native_local && ids.ready(*native_local));
    unsigned actual_fetches{};
    check(e::EnrollmentStatus::connection_crl(client,actual_native,verifier,b.root,core::sha256(b.server),native_local->native_reference,now,[&]{++actual_fetches;return fresh.wire;})==fresh.bundle.crl && actual_fetches==1);
    check(status_bytes(path)==fresh.wire);
#if defined(__APPLE__)
    {
    // Security's revocation cache uses actual time even when the trust object's
    // certificate verify date is changed. Actual-expiry proof is authoritative;
    // do not weaken native trust to manufacture future-OCSP acceptance.
    auto corrupt=fresh.wire;corrupt.at(corrupt.size()-1)^=std::byte{1};
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,corrupt,now);});
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,expired.wire,now);});
    auto damaged=fresh.bundle;damaged.client_ocsp.at(damaged.client_ocsp.size()-1)^=std::byte{1};check(!ids.verify_revocation(damaged,ip,now));
    const auto serial=e::certificate_facts(b.client,e::KeyPurpose::client).serial;
    auto signer=keys.open(hr.staged.keys.front().reference);const auto issuer=e::certificate_facts(b.root,e::KeyPurpose::authority).validity;
    for(const auto state:{e::Status::unknown,e::Status::revoked}){
        damaged=fresh.bundle;damaged.client_ocsp=e::ocsp_response(*signer,serial,state,now,{now-minutes{1},now+hours{1}},issuer,now-minutes{2});
        check(!ids.verify_revocation(damaged,ip,now));
    }
    std::atomic_bool stop{};const auto request=e::status_request(cr);StatusChannel good(fresh.wire);
    check(e::exchange_status(good,request,stop)==fresh.wire && good.closed);
    for(unsigned kind=0;kind<3;++kind){auto wire=fresh.wire;if(kind==0)wire.resize(7);if(kind==1)wire.resize(wire.size()-1);if(kind==2){wire.resize(8);for(unsigned i=4;i<8;++i)wire[i]=std::byte{255};}
        StatusChannel bad(std::move(wire));reject([&]{e::exchange_status(bad,request,stop);});check(bad.closed);}
    status_write(path,corrupt);reject([&]{e::EnrollmentStatus::connection_crl(client,ids,verifier,b.root,core::sha256(b.server),native_local->native_reference,now,[&]{++actual_fetches;return fresh.wire;});});
    check(actual_fetches==1);status_write(path,fresh.wire);
    std::filesystem::create_hard_link(path,client_root/"alias.fixture");reject([&]{e::EnrollmentStatus::cached(client,ids,verifier,now);});std::filesystem::remove(client_root/"alias.fixture");
    check(status_bytes(path)==fresh.wire && e::encode_enrollment_commit(*e::DurablePairing::inspect(host,verifier))==hrecord && e::encode_enrollment_commit(*e::DurablePairing::inspect(client,verifier))==crecord);
    std::cout<<"enrollment_native_status=PASS real_expired_evidence=1 native_positive=1 no_rekey=1 immutable_pairing=1 startup_selector=1 expired_native_counter_not_required=1 tamper_rejected=1 empty_staging_recovered=1 system_clock_changed=0 installed_changes=0\n";
    return;
    }
#endif
    check(!ids.verify_revocation(b,ip,future));
    CurrentStatusOnly future_native(ids,future);
    const auto renewed=e::EnrollmentStatus::issue(host,keys,future_native,verifier,future);
    check(renewed.issued>first.issued && ids.verify_revocation(renewed.bundle,ip,future));
    const auto serial=e::certificate_facts(b.client,e::KeyPurpose::client).serial;
    const auto authority=hr.transcript.host.authority_key;
    e::require_good_ocsp(renewed.bundle.client_ocsp,b.root,serial,authority,verifier,future);
    reject([&]{e::require_good_ocsp(b.client_ocsp,b.root,serial,authority,verifier,future);});
    auto bad_ocsp=renewed.bundle.client_ocsp;bad_ocsp.at(bad_ocsp.size()-1)^=std::byte{1};
    reject([&]{e::require_good_ocsp(bad_ocsp,b.root,serial,authority,verifier,future);});
    auto wrong_serial=serial;wrong_serial[0]^=std::byte{1};
    reject([&]{e::require_good_ocsp(renewed.bundle.client_ocsp,b.root,wrong_serial,authority,verifier,future);});
    auto signer=keys.open(hr.staged.keys.front().reference);const auto issuer=e::certificate_facts(b.root,e::KeyPurpose::authority).validity;
    for(const auto state:{e::Status::unknown,e::Status::revoked}){
        const auto negative=e::ocsp_response(*signer,serial,state,future,{future-minutes{1},future+hours{1}},issuer,future-minutes{2});
        reject([&]{e::require_good_ocsp(negative,b.root,serial,authority,verifier,future);});
    }
#if defined(_WIN32)
    auto invalid_crl=renewed.bundle;invalid_crl.crl.at(invalid_crl.crl.size()-1)^=std::byte{1};
    check(!ids.verify_revocation(invalid_crl,ip,future));
#endif
    const auto local=ids.locate(cr.staged.keys.back().reference,b.client,ip);check(local && ids.ready(*local));
    const auto peer=core::sha256(b.server);unsigned fetches{};
    auto connect=[&](auto when,auto fetch){CurrentStatusOnly current_native(ids,when);return e::EnrollmentStatus::connection_crl(client,current_native,verifier,b.root,peer,local->native_reference,when,fetch);};
    check(connect(future,[&]{++fetches;return renewed.wire;})==renewed.bundle.crl && fetches==1);
    check(connect(future,[&]()->e::Bytes{++fetches;throw std::runtime_error("offline fixture");})==renewed.bundle.crl && fetches==1);
    // Equal replay is idempotent. A later generation is monotonic even while
    // the previous generation still has valid revocation lifetime.
    check(e::EnrollmentStatus::accept(client,ids,verifier,renewed.wire,future).wire==renewed.wire);
    CurrentStatusOnly next_native(ids,future+hours{13});
    const auto next=e::EnrollmentStatus::issue(host,keys,next_native,verifier,future+hours{13});
    check(e::EnrollmentStatus::accept(client,ids,verifier,next.wire,future+hours{13}).wire==next.wire);
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,renewed.wire,future+hours{13});});
    reject([&]{e::EnrollmentStatus::issue(host,keys,ids,verifier,future);});
    for(const auto index:{8U,12U,172U,188U,300U}){
        auto damaged=next.wire;damaged.at(index)^=std::byte{1};
        reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,damaged,future+hours{13});});
    }
    auto damaged=next.wire;damaged.at(damaged.size()-1)^=std::byte{1};
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,damaged,future+hours{13});});
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,e::Bytes(e::status_wire_cap+1),future+hours{13});});
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,e::Bytes(next.wire.begin(),next.wire.end()-1),future+hours{13});});
    auto wrong=peer;wrong[0]^=std::byte{1};
    reject([&]{e::EnrollmentStatus::connection_crl(client,ids,verifier,b.root,wrong,local->native_reference,future,[&]{++fetches;return next.wire;});});
    check(fetches==1 && status_bytes(path)==next.wire);
    check(connect(future+hours{31},[&]()->e::Bytes{++fetches;throw std::runtime_error("offline fixture");})==next.bundle.crl && fetches==2);
    reject([&]{connect(future+days{2},[&]()->e::Bytes{++fetches;throw std::runtime_error("offline fixture");});});
    check(fetches==3 && status_bytes(path)==next.wire);
    std::filesystem::create_hard_link(path,client_root/"alias.fixture");
    reject([&]{e::EnrollmentStatus::cached(client,ids,verifier,future+hours{13});});
    std::filesystem::remove(client_root/"alias.fixture");
    auto corrupt=next.wire;corrupt.at(corrupt.size()-1)^=std::byte{1};status_write(path,corrupt);
    reject([&]{connect(future+hours{13},[&]{++fetches;return next.wire;});});
    check(fetches==3);status_write(path,next.wire);
    check(e::EnrollmentStatus::cached(client,ids,verifier,future+hours{13})->wire==next.wire);
    // Wire fragmentation, partial EOF, length-before-allocation and stop are
    // tested at the same reader used by the production bootstrap connection.
    const auto request=e::status_request(cr);std::atomic_bool stop{};StatusChannel good(next.wire);
    check(e::exchange_status(good,request,stop)==next.wire && good.closed && good.sent==request);
    for(unsigned kind=0;kind<4;++kind){auto wire=next.wire;
        if(kind==0)wire.resize(7);
        if(kind==1)wire.resize(wire.size()-1);
        if(kind==2)wire[0]=std::byte{'X'};
        if(kind==3){wire.resize(8);for(unsigned i=4;i<8;++i)wire[i]=std::byte{255};}
        StatusChannel bad(std::move(wire));reject([&]{e::exchange_status(bad,request,stop);});check(bad.closed);
    }
    stop=true;StatusChannel cancelled(next.wire);reject([&]{e::exchange_status(cancelled,request,stop);});check(cancelled.closed);stop=false;
    auto other_round=request;other_round[4]^=std::byte{1};StatusChannel foreign(other_round);
    reject([&]{e::serve_status(foreign,host,keys,ids,verifier,future+hours{13},stop);});
    check(foreign.closed && foreign.sent.empty() && e::EnrollmentStatus::cached(host,ids,verifier,future+hours{13})->wire==next.wire);
    check(e::encode_enrollment_commit(*e::DurablePairing::inspect(host,verifier))==hrecord &&
        e::encode_enrollment_commit(*e::DurablePairing::inspect(client,verifier))==crecord);
    check(ids.ready(*local) && keys.open(cr.staged.keys.back().reference)->public_key()==local->subject_key);
    std::cout<<"enrollment_native_status=PASS original_expired=1 future_days=4 native_positive=1 no_rekey=1 immutable_pairing=1 startup_selector=1 cache_reopen=1 rollback_rejected=1 tamper_rejected=1 offline_valid_only=1 empty_staging_recovered=1 system_clock_changed=0 installed_changes=0\n";
}
}
