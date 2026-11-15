#include "rwn/core/enrollment_credentials.hpp"
#include <algorithm>

namespace rwn::core::enrollment {
namespace {
void require(bool b){if(!b)throw std::runtime_error("native credential transaction unavailable");}
class Slot final:public EnrollmentJournal {
public:
    std::function<std::optional<Bytes>()> read;std::function<void(std::span<const std::byte>)> write;std::function<void()> erase;
    std::optional<EnrollmentRecord> load()override{const auto b=read();if(!b)return {};return decode_enrollment_record(*b);}
    void save(const EnrollmentRecord& next)override{const auto old=load();require(old?(old->transaction==next.transaction && next.revision==old->revision+1):next.revision==1);write(encode_enrollment_record(next));}
    void clear(const std::array<std::byte,32>& id)override{const auto old=load();require(old && old->transaction==id);erase();}
};
const Bytes& local(const EnrollmentRecord& r){return r.role==PairRole::host?r.bundle.server:r.bundle.client;}
void owned(const EnrollmentRecord& r,const EnrollmentCommitRecord& origin){
    require(r.role==origin.staged.role && r.keys.size()==origin.staged.keys.size());
    for(std::size_t i=0;i<r.keys.size();++i){const auto& a=r.keys[i];const auto& b=origin.staged.keys[i];
        require(a.existed && a.point==b.point && a.reference.purpose==b.reference.purpose && a.reference.id==b.reference.id);}
    if(r.phase!=EnrollmentPhase::keys){require(r.approval_binding==origin.transcript.binding && r.server_ipv4==origin.transcript.host.desktop_ipv4);
        require(certificate_facts(r.bundle.root,KeyPurpose::authority).subject_key==origin.transcript.host.authority_key &&
            certificate_facts(r.bundle.server,KeyPurpose::server,r.server_ipv4).subject_key==origin.transcript.host.identity_key &&
            certificate_facts(r.bundle.client,KeyPurpose::client).subject_key==origin.transcript.client.identity_key);}
}
}
AssociatedIdentity CredentialInstaller::install(FileEnrollmentJournal& file,KeyStore& keys,IdentityStore& ids,const PairProofVerifier& verifier,Time now){
    const auto origin=DurablePairing::inspect(file,verifier);require(origin && !origin->receipts[4].empty() && origin->receipts[5].empty());
    const auto proof=EnrollmentStatus::identity_proof(file,ids,verifier,now);
    for(const auto& k:origin->staged.keys){auto key=keys.open(k.reference);require(key && key->public_key()==k.point);}
    auto slot=[&](bool retired){Slot s;s.read=[&,retired]{return file.read_credential(retired);};s.write=[&,retired](auto b){file.store_credential(retired,b);};s.erase=[&,retired]{file.clear_credential(retired);};return s;};
    auto current=slot(false),retired=slot(true);auto c=current.load(),r=retired.load();if(c)owned(*c,*origin);if(r)owned(*r,*origin);
    const auto& wanted=proof.role()==PairRole::host?proof.bundle().server:proof.bundle().client;
    // Crash after archiving but before clearing must not delete the only
    // usable old identity. Keep its durable owner in the retired slot.
    if(c && r && c->transaction==r->transaction){require(encode_enrollment_record(*c)==encode_enrollment_record(*r));current.clear(c->transaction);c.reset();}
    EnrollmentStager stage(current,keys,ids),old(retired,keys,ids);
    if(r && r->phase!=EnrollmentPhase::keys && local(*r)==wanted){
        require(!c);if(auto ready=old.recover_staged()){
            const auto bytes=encode_enrollment_record(*retired.load());file.store_credential(false,bytes);require(file.read_credential(false)==file.read_credential(true));file.clear_credential(true);return *ready;
        }
        require(ids.certificate_absent(local(*r)) && old.rollback());r.reset();
    }
    if(r && c && c->phase==EnrollmentPhase::staged && stage.recover_staged()){require(old.rollback());r.reset();}
    if(c && c->phase!=EnrollmentPhase::keys && local(*c)!=wanted){
        const auto before=certificate_facts(local(*c),c->keys.back().reference.purpose,c->server_ipv4),after=certificate_facts(wanted,c->keys.back().reference.purpose,c->server_ipv4);
        require(after.validity.before>=before.validity.before && after.validity.after>before.validity.after);
    }
    if(c && c->phase!=EnrollmentPhase::keys && local(*c)==wanted){
        if(auto ready=stage.recover_staged()){require_renewed_identity(proof,ready->key,ready->subject_key,now);if(r)require(old.rollback());return *ready;}
        require(ids.certificate_absent(local(*c)) && stage.rollback());c.reset();
    }
    if(c){
        if(c->phase==EnrollmentPhase::staged && stage.recover_staged()){
            require(!r);file.store_credential(true,encode_enrollment_record(*c));require(file.read_credential(true)==file.read_credential(false));current.clear(c->transaction);r=c;
        }else require(stage.rollback());
    }
    // Local deterministic target identifier, never used as a filename or
    // supplied by an unauthenticated peer. All native keys MUST already exist.
    if(!current.load()){
        Bytes target;for(auto x:origin->round)target.push_back(x);target.insert(target.end(),wanted.begin(),wanted.end());
        const auto digest=sha256(target);std::array<std::byte,32> transaction{};std::copy(digest.begin(),digest.end(),transaction.begin());
        EnrollmentRecord pending;pending.transaction=transaction;pending.revision=1;pending.role=proof.role();pending.keys=origin->staged.keys;
        for(auto& k:pending.keys)k.existed=true; // A disappearing key must fail, never be regenerated.
        current.save(pending);stage.ensure_keys();
    }
    auto installed=stage.associate_renewed(proof);if(retired.load())require(old.rollback());
    require(ids.ready(installed));return installed;
}
}
