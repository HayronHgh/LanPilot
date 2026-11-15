#pragma once
#include "rwn/core/enrollment_setup.hpp"
#include "rwn/platform/enrollment_tcp.hpp"
#include <thread>
#include <exception>
#include <algorithm>

namespace rwn::fixture {
// Real loopback sockets plus the caller's real protected journals/native keys.
// A fixture deadline bounds failures below the enclosing native CTest timeout.
struct RecoveryChannel final:core::enrollment::EnrollmentChannel {
    std::unique_ptr<EnrollmentChannel> inner;
    core::PairingConsent::Clock::time_point limit{core::PairingConsent::Clock::now()+std::chrono::seconds{3}};
    bool tamper{};core::enrollment::Bytes replay,observed;
    explicit RecoveryChannel(std::unique_ptr<EnrollmentChannel> c):inner(std::move(c)){}
    Read read(std::span<std::byte> b,std::chrono::milliseconds t)override{
        if(core::PairingConsent::Clock::now()>=limit)throw std::runtime_error("recovery fixture deadline");
        return inner->read(b,t);
    }
    void write(std::span<const std::byte> b,core::PairingConsent::Clock::time_point t,const std::atomic_bool& stop)override{
        if(b.size()>8 && b[4]==std::byte{2}){
            observed.assign(b.begin(),b.end());
            if(!replay.empty()){inner->write(replay,std::min(t,limit),stop);return;}
            if(tamper){auto bad=observed;bad.back()^=std::byte{1};inner->write(bad,std::min(t,limit),stop);return;}
        }
        inner->write(b,std::min(t,limit),stop);
    }
    void close()noexcept override{inner->close();}
};
template<class Random>
auto recover_pair(core::enrollment::FileEnrollmentJournal& host_file,core::enrollment::FileEnrollmentJournal& client_file,
    core::enrollment::KeyStore& keys,core::enrollment::IdentityStore& identities,
    const core::enrollment::PairProofVerifier& verifier,std::array<std::byte,4> address,Random random,
    bool tamper=false,core::enrollment::Bytes replay={}){
    namespace e=core::enrollment;namespace tcp=platform::enrollment;
    auto listener=tcp::listen(tcp::parse_private_ipv4("127.0.0.1"),0);std::atomic_bool stop{};
    auto client=std::make_unique<RecoveryChannel>(tcp::connect(tcp::parse_private_ipv4("127.0.0.1"),listener->port(),std::chrono::seconds{1},stop));
    auto host=std::make_unique<RecoveryChannel>(listener->accept(std::chrono::seconds{1}));listener.reset();
    if(!host->inner)throw std::runtime_error("recovery fixture accept failed");
    client->tamper=tamper;client->replay=std::move(replay);
    e::EnrollmentSetupCallbacks callbacks;callbacks.random=[&](std::span<std::byte> bytes){random(bytes);};
    callbacks.show_comparison=[](auto){throw std::runtime_error("recovery must never revive consent");};
    struct Result{std::optional<e::PersistablePairing> host,client;std::exception_ptr host_error,client_error;e::Bytes client_proof;};Result result;
    std::thread worker([&]{try{result.host=e::recover_enrollment(*host,host_file,keys,identities,verifier,address,callbacks,stop);}catch(...){result.host_error=std::current_exception();host->close();}});
    try{result.client=e::recover_enrollment(*client,client_file,keys,identities,verifier,address,callbacks,stop);}catch(...){result.client_error=std::current_exception();client->close();}
    worker.join();result.client_proof=client->observed;return result;
}
}
