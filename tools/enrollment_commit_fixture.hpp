#pragma once
#include "rwn/core/enrollment_commit.hpp"
#include "enrollment_journal_fixture.hpp"
#include "enrollment_configuration_fixture.hpp"
#include "enrollment_recovery_fixture.hpp"
#include "enrollment_status_fixture.hpp"
#include "enrollment_credential_fixture.hpp"
#include <fstream>

namespace rwn::fixture {
// Failure only at a named receipt signature boundary; all successful signatures
// and verifications still use the actual protected CNG/Keychain fixture keys.
struct ReceiptSigner:core::enrollment::Signer {
    core::enrollment::Signer& native;unsigned fail_kind{};
    explicit ReceiptSigner(core::enrollment::Signer& n):native(n){}
    core::enrollment::PublicKey public_key()const override{return native.public_key();}
    bool accepts_public_key(const core::enrollment::PublicKey& p)const override{return native.accepts_public_key(p);}
    core::enrollment::Bytes sign_sha256(std::span<const std::byte> m)override{
        constexpr auto offset=std::string_view("LanPilot durable pairing receipt v1").size()+1;
        if(fail_kind && m.size()>offset+4 && m[offset+4]==static_cast<std::byte>(fail_kind)){
            fail_kind=0;throw std::runtime_error("fixture receipt signing interruption");}
        return native.sign_sha256(m);
    }
};
template<class Check,class Reject,class Random,class Count>
void durable_completion_fixture(core::enrollment::KeyStore& keys,core::enrollment::IdentityStore& identities,
    core::enrollment::Signer& host,core::enrollment::Signer& client,const core::enrollment::KeyReference& authority_ref,
    const core::enrollment::KeyReference& host_ref,const core::enrollment::KeyReference& client_ref,
    core::enrollment::PairHello host_hello,core::enrollment::PairHello client_hello,
    const core::enrollment::PublicIdentityBundle& bundle,const core::enrollment::PairProofVerifier& verifier,
    Check check,Reject reject,Random random,Count count){
    namespace e=core::enrollment;using Clock=e::PairingSession::Clock;
    e::Bytes previous_commit,previous_abort;
    for(unsigned scenario=0;scenario<10;++scenario){
        check(count()==0);random(host_hello.nonce);random(client_hello.nonce);const auto now=Clock::now();
        e::PairingSession hs(host_hello,host,verifier,now),cs(client_hello,client,verifier,now);
        auto x=hs.send_hello(now),y=cs.send_hello(now);hs.receive(y,now);cs.receive(x,now);
        x=hs.send_proof(now);y=cs.send_proof(now);hs.receive(y,now);cs.receive(x,now);hs.local_decision(true,now);cs.local_decision(true,now);
        x=hs.send_local_approval(now);y=cs.send_local_approval(now);hs.receive(y,now);cs.receive(x,now);
        auto ha=hs.take_approved(now),ca=cs.take_approved(now);
        JournalDirectory hd,cd;auto hj=hd.open(),cj=cd.open();std::array<std::byte,32> id{};random(id);const std::array refs{authority_ref,host_ref};
        e::EnrollmentStager hstage(*hj,keys,identities),cstage(*cj,keys,identities);hstage.begin(id,e::PairRole::host,refs);hstage.ensure_keys();
        random(id);cstage.begin(id,e::PairRole::client,std::span{&client_ref,1});cstage.ensure_keys();
        const auto hi=hstage.associate(*ha,bundle,now),ci=cstage.associate(*ca,bundle,now);check(count()==2);
        ReceiptSigner hsign(host),csign(client);
        auto hp=e::DurablePairing::prepare(*hj,std::move(ha),hsign,identities,verifier,now);
        const auto host_prepared=hp->outgoing().front();
        auto cp=e::DurablePairing::prepare(*cj,std::move(ca),csign,identities,verifier,now,host_prepared);
        const auto client_prepared=cp->outgoing().front();check(!hp->persistable() && !cp->persistable());
        check(!e::EnrollmentConfigurationHandoff::recover(*hj,keys,identities,verifier) &&
              !e::EnrollmentConfigurationHandoff::recover(*cj,keys,identities,verifier));
        reject([&](){e::EnrollmentStatus::issue(*hj,keys,identities,verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));});
        reject([&](){hstage.rollback();});reject([&](){cstage.rollback();});check(count()==2);
        reject([&](){hp->decide_commit(now);}); // no client PREPARED yet
        reject([&](){cp->cleanup_aborted(keys);});
        auto malformed=client_prepared;malformed.back()^=std::byte{1};reject([&](){hp->receive(malformed);});
        // Fragmentation, coalescing and partial EOF are bounded and explicit.
        if(scenario==0){for(std::size_t split=0;split<=host_prepared.size();++split){e::CommitReceiptReader reader;
            check(reader.consume(std::span(host_prepared).first(split))==split);check(reader.consume(std::span(host_prepared).subspan(split))==host_prepared.size()-split);
            check(reader.ready() && reader.take()==host_prepared);reader.eof();}
            e::Bytes both=host_prepared;both.insert(both.end(),client_prepared.begin(),client_prepared.end());e::CommitReceiptReader reader;
            const auto used=reader.consume(both);check(used==host_prepared.size() && reader.take()==host_prepared);
            check(reader.consume(std::span(both).subspan(used))==client_prepared.size() && reader.take()==client_prepared);
            e::CommitReceiptReader partial;partial.consume(std::span(host_prepared).first(134));reject([&](){partial.eof();});
            auto wrong_kind=host_prepared;wrong_kind[4]=std::byte{7};e::CommitReceiptReader unknown;
            reject([&](){unknown.consume(wrong_kind);});
            auto too_long=host_prepared;too_long[133]=std::byte{255};too_long[134]=std::byte{255};e::CommitReceiptReader overlong;
            reject([&](){overlong.consume(too_long);});
        }
        if(scenario>=6){
            hp->receive(client_prepared);
            e::Bytes decision;
            if(scenario!=9){hp->decide_commit(now);decision=hp->outgoing().back();}
            if(scenario==7 || scenario==8)cp->receive(decision);
            if(scenario==8)hp->receive(cp->outgoing().back());
            hp.reset();cp.reset();hj.reset();cj.reset();hj=hd.open();cj=cd.open();
            auto recovered=recover_pair(*hj,*cj,keys,identities,verifier,host_hello.desktop_ipv4,random);
            if(recovered.host_error)std::rethrow_exception(recovered.host_error);
            if(recovered.client_error)std::rethrow_exception(recovered.client_error);
            const auto hr=e::DurablePairing::inspect(*hj,verifier),cr=e::DurablePairing::inspect(*cj,verifier);
            check(hr && cr);
            if(scenario==9){check(!recovered.host && !recovered.client && !hr->receipts[5].empty() && hr->receipts[2].empty() && cr->receipts[5]==hr->receipts[5]);}
            else {
                check(recovered.host && recovered.client && hr->receipts[2]==decision && cr->receipts[2]==decision && hr->receipts[4]==cr->receipts[4]);
                const auto before_host=e::encode_enrollment_commit(*hr),before_client=e::encode_enrollment_commit(*cr);
                auto bad=recover_pair(*hj,*cj,keys,identities,verifier,host_hello.desktop_ipv4,random,true);
                check(bad.host_error && bad.client_error && e::encode_enrollment_commit(*e::DurablePairing::inspect(*hj,verifier))==before_host &&
                    e::encode_enrollment_commit(*e::DurablePairing::inspect(*cj,verifier))==before_client);
                auto replayed=recover_pair(*hj,*cj,keys,identities,verifier,host_hello.desktop_ipv4,random,false,recovered.client_proof);
                check(replayed.host_error && replayed.client_error && e::encode_enrollment_commit(*e::DurablePairing::inspect(*hj,verifier))==before_host &&
                    e::encode_enrollment_commit(*e::DurablePairing::inspect(*cj,verifier))==before_client);
            }
            check(identities.remove_created(hi) && identities.remove_created(ci) && count()==0);
            check(keys.open(host_ref)->public_key()==host.public_key() && keys.open(client_ref)->public_key()==client.public_key());
            continue;
        }
        const bool abort=scenario==1 || scenario==2 || scenario==5;
        if(scenario!=5)hp->receive(client_prepared);
        if(scenario==1){hp.reset();hj.reset();hj=hd.open();hp=e::DurablePairing::resume(*hj,&hsign,identities,verifier);
            reject([&](){hp->decide_commit(now);}); // restarted approval is NOT revived
        }
        if(scenario==2)reject([&](){hp->decide_commit(now+std::chrono::seconds{121});});
        if(abort){hp->decide_abort();const auto aborted=hp->outgoing().back();
            if(scenario==5)hp->receive(client_prepared); // crossed terminal decision
            auto damaged_abort=aborted;damaged_abort.back()^=std::byte{1};reject([&](){cp->receive(damaged_abort);});
            if(!previous_abort.empty())reject([&](){cp->receive(previous_abort);});
            cp->receive(aborted);previous_abort=aborted;check(!hp->persistable() && !cp->persistable());
            reject([&](){hp->decide_commit(now);});if(!previous_commit.empty())reject([&](){cp->receive(previous_commit);});
            check(cp->cleanup_aborted(keys) && hp->cleanup_aborted(keys) && count()==0);
            hp.reset();cp.reset();hj.reset();cj.reset();hj=hd.open();cj=cd.open();
            hp=e::DurablePairing::resume(*hj,nullptr,identities,verifier);cp=e::DurablePairing::resume(*cj,nullptr,identities,verifier);
            check(hp->outgoing().back()==aborted && hp->record().aborted_objects_removed && cp->record().aborted_objects_removed);
            check(hp->cleanup_aborted(keys) && cp->cleanup_aborted(keys));
            check(!e::EnrollmentConfigurationHandoff::recover(*hj,keys,identities,verifier) &&
                  !e::EnrollmentConfigurationHandoff::recover(*cj,keys,identities,verifier));
            const auto round=hp->record().round;hp.reset();cp.reset();
            e::DurablePairing::retire_abort(*hj,keys,identities,verifier);e::DurablePairing::retire_abort(*cj,keys,identities,verifier);
            check(!e::DurablePairing::inspect(*hj,verifier) && !e::DurablePairing::inspect(*cj,verifier));
            const auto harchive=e::DurablePairing::archived_abort(*hj,round,verifier),carchive=e::DurablePairing::archived_abort(*cj,round,verifier);
            check(harchive && carchive && harchive->receipts[5]==aborted && carchive->receipts[5]==aborted);
            std::array<std::byte,32> unknown{};random(unknown);check(!e::DurablePairing::archived_abort(*hj,unknown,verifier));
            if(scenario==1){
                std::string name;for(auto b:round){const auto n=std::to_integer<unsigned>(b);name+="0123456789abcdef"[n>>4];name+="0123456789abcdef"[n&15];}
                const auto path=hd.root/"aborted"/(name+".lpj");const auto original=e::encode_enrollment_commit(*harchive);auto damaged=original;damaged.back()^=std::byte{1};
                {std::ofstream out(path,std::ios::binary|std::ios::trunc);out.write(reinterpret_cast<const char*>(damaged.data()),static_cast<std::streamsize>(damaged.size()));}
                reject([&](){e::DurablePairing::archived_abort(*hj,round,verifier);});
                {std::ofstream out(path,std::ios::binary|std::ios::trunc);out.write(reinterpret_cast<const char*>(original.data()),static_cast<std::streamsize>(original.size()));}
                std::filesystem::create_hard_link(path,hd.root/"alias.fixture");reject([&](){e::DurablePairing::archived_abort(*hj,round,verifier);});
                std::filesystem::remove(hd.root/"alias.fixture");check(e::DurablePairing::archived_abort(*hj,round,verifier).has_value());
            }
        }else{
            hp->receive(client_prepared);hp->decide_commit(now);const auto decision=hp->outgoing().back();previous_commit=decision;
            reject([&](){hp->decide_abort();});check(!hp->persistable());
            hp.reset();hj.reset();hj=hd.open();hp=e::DurablePairing::resume(*hj,&hsign,identities,verifier);
            check(hp->outgoing().back()==decision); // exact saved signature replay
            if(scenario==3){csign.fail_kind=4;reject([&](){cp->receive(decision);});
                check(!cp->record().receipts[2].empty() && cp->record().receipts[3].empty());cp.reset();cj.reset();cj=cd.open();
                cp=e::DurablePairing::resume(*cj,&csign,identities,verifier); // drains without network input
            }else cp->receive(decision);
            const auto client_committed=cp->outgoing().back();check(!cp->persistable());
            if(scenario==4){hsign.fail_kind=5;reject([&](){hp->receive(client_committed);});
                check(!hp->record().receipts[3].empty() && hp->record().receipts[4].empty());hp.reset();hj.reset();hj=hd.open();
                hp=e::DurablePairing::resume(*hj,&hsign,identities,verifier);
            }else hp->receive(client_committed);
            const auto host_committed=hp->outgoing().back();check(hp->persistable().has_value() && !cp->persistable());
            cp->receive(host_committed);check(cp->persistable().has_value());
            reject([&](){e::DurablePairing::retire_abort(*hj,keys,identities,verifier);});
            cp->receive(decision);hp->receive(client_committed);cp->receive(host_committed); // idempotent
            auto bytes=e::encode_enrollment_commit(hp->record());check(e::decode_enrollment_commit(bytes,verifier).receipts[4]==host_committed);
            auto wrong=hp->record();wrong.receipts[4].back()^=std::byte{1};const auto invalid=e::encode_enrollment_commit(wrong);
            reject([&](){e::decode_enrollment_commit(invalid,verifier);});wrong=hp->record();wrong.staged.bundle.crl.back()^=std::byte{1};
            const auto changed=e::encode_enrollment_commit(wrong);reject([&](){e::decode_enrollment_commit(changed,verifier);});
            e::Bytes oversize(e::enrollment_storage_cap+1);reject([&](){e::decode_enrollment_commit(oversize,verifier);});
            wrong=hp->record();wrong.staged.phase=e::EnrollmentPhase::association_intent;reject([&](){e::encode_enrollment_commit(wrong);});
            wrong=hp->record();wrong.transcript.client.identity_key[0]^=std::byte{1};reject([&](){e::encode_enrollment_commit(wrong);});
            hp.reset();cp.reset();hj.reset();cj.reset();hj=hd.open();cj=cd.open();
            hp=e::DurablePairing::resume(*hj,nullptr,identities,verifier);cp=e::DurablePairing::resume(*cj,nullptr,identities,verifier);
            check(hp->persistable().has_value() && cp->persistable().has_value() && hp->outgoing().back()==host_committed);
#if defined(_WIN32)
            configuration_fixture(*cj,*cp->persistable(),keys,identities,verifier,cd.root,check,reject);
#else
            configuration_fixture(*hj,*hp->persistable(),keys,identities,verifier,hd.root,check,reject);
#endif
            if(scenario==4)status_fixture(*hj,*cj,keys,identities,verifier,hd.root,cd.root,check,reject);
            if(scenario==0)credential_fixture(*hj,*cj,keys,identities,verifier,hd.root,cd.root,hi,ci,count,random);
            // Fixture cleanup only. Product activation never deletes LPJ2 or an
            // active identity before a durable configuration handoff exists.
            if(scenario!=0)check(identities.remove_created(hi) && identities.remove_created(ci) && count()==0);
            else check(count()==0);
        }
        check(keys.open(host_ref)->public_key()==host.public_key() && keys.open(client_ref)->public_key()==client.public_key());
    }
}
}
