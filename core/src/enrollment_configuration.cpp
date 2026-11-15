#include "rwn/core/enrollment_configuration.hpp"
#include "rwn/core/enrollment_status.hpp"
#include <algorithm>

namespace rwn::core::enrollment {
namespace {
void require(bool b){if(!b)throw std::runtime_error("remembered enrollment configuration unavailable");}
std::string hex(std::span<const std::byte> b){std::string s;for(auto x:b){const auto n=std::to_integer<unsigned>(x);s+="0123456789abcdef"[n>>4];s+="0123456789abcdef"[n&15];}return s;}
std::string json(std::string_view text){std::string s="\"";for(const auto raw:text){const auto c=static_cast<unsigned char>(raw);
    if(c=='\\' || c=='"'){s+='\\';s+=static_cast<char>(c);}else if(c<32){s+="\\u00";s+="0123456789abcdef"[c>>4];s+="0123456789abcdef"[c&15];}else s+=static_cast<char>(c);}return s+'"';}
Sha256Digest generation(const std::array<Bytes,6>& objects){Bytes b;std::size_t total{};for(const auto& o:objects){require(!o.empty() && o.size()<=65536);total+=o.size();
    for(int shift=24;shift>=0;shift-=8)b.push_back(static_cast<std::byte>(o.size()>>shift));
    b.insert(b.end(),o.begin(),o.end());}require(total<=131072);return sha256(b);}
}
EnrollmentConfigurationReceipt EnrollmentConfigurationHandoff::persist(FileEnrollmentJournal& file,const PersistablePairing& proof,
    IdentityStore& identities,const PairProofVerifier& verifier){
    const auto bytes=file.read_record();require(bytes.has_value());const auto current=decode_enrollment_commit(*bytes,verifier);
    require(*bytes==encode_enrollment_commit(proof.record()) && !current.receipts[4].empty() && current.receipts[5].empty());
    const auto& r=current.staged;const auto& k=r.keys.back();const auto& certificate=r.role==PairRole::host?r.bundle.server:r.bundle.client;
    require(proof.local_identity().key.purpose==k.reference.purpose && proof.local_identity().key.id==k.reference.id);
    const auto anchor=identities.describe(k.reference,certificate,r.server_ipv4);std::optional<AssociatedIdentity> local;
    if(proof.descriptor_only()){
        require(identities.key_ready(k.reference,k.point));local=proof.local_identity();
        require(local->subject_key==k.point && local->certificate_der==certificate && local->native_reference==anchor && local->certificate_sha256==sha256(certificate));
    }else{local=identities.locate(k.reference,proof.local_identity().certificate_der,r.server_ipv4);require(local && local->subject_key==k.point && identities.ready(*local));}
    require(local->certificate_sha256==proof.local_identity().certificate_sha256 && local->native_reference==proof.local_identity().native_reference);
    if(local->certificate_der!=certificate){const auto refreshed=EnrollmentStatus::identity_proof(file,identities,verifier,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
        require(local->certificate_der==(r.role==PairRole::host?refreshed.bundle().server:refreshed.bundle().client));}
    const std::array objects{r.bundle.root,r.bundle.server,r.bundle.client,r.bundle.crl,r.bundle.server_ocsp,r.bundle.client_ocsp};
    const auto g=generation(objects);const auto layout=file.configuration_layout(g);require(!layout.profile_path.empty() && !layout.trust_directory.empty());
    std::string address;for(auto x:r.server_ipv4){if(!address.empty())address+='.';address+=std::to_string(std::to_integer<unsigned>(x));}
    const auto port=std::to_string(current.transcript.host.desktop_port);std::string profile;
    if(layout.kind==EnrollmentConfigurationLayout::Kind::windows_client){
        require(r.role==PairRole::client && anchor.size()==20);
        const auto base=layout.trust_directory+"/";
        profile="{\"schema\":2,\"transport\":\"tls\",\"host\":"+json(address)+",\"port\":"+port+
            ",\"clientCertificate\":"+json(hex(anchor))+",\"serverFingerprint\":"+json(hex(sha256(r.bundle.server)))+
            ",\"rootDer\":"+json(base+"root.der")+",\"crlDer\":"+json(base+"revocation.der")+
            ",\"control\":\"view-only\",\"visual\":\"h264-only\",\"status\":\"native\"}\n";
    }else{
        require(layout.kind==EnrollmentConfigurationLayout::Kind::macos_host && r.role==PairRole::host && !anchor.empty() && anchor.size()<=4096);
        require(layout.trust_directory.size()<=1024 && layout.trust_directory.front()=='/' && layout.trust_directory.find_first_of("\r\n\\\"")==std::string::npos);
        profile="schema=1\nbind="+address+"\nport="+port+"\nidentity_ref="+hex(anchor)+"\npeer_sha256="+hex(sha256(r.bundle.client))+
            "\nca_path="+layout.trust_directory+"/root.der\nocsp_path="+layout.trust_directory+
            "/client-ocsp.der\ncontrol=view-only\nvisual=h264-only\nclipboard_text=false\n";
    }
    require(!profile.empty() && profile.size()<=16384);const auto data=std::as_bytes(std::span{profile});
    // The native call preflights the existing protected config, fsyncs/flushes
    // every create-only public object, then atomically exposes the profile.
    const bool created=file.publish_configuration(g,objects,data);
    require(file.read_record()==bytes);return {layout.profile_path,sha256(data),g,created};
}
std::optional<EnrollmentConfigurationReceipt> EnrollmentConfigurationHandoff::recover(FileEnrollmentJournal& file,
    KeyStore& keys,IdentityStore& identities,const PairProofVerifier& verifier){
    const auto bytes=file.read_record();if(!bytes)return {};
    // LPJ1 staging has not crossed the durable decision boundary. Do not treat
    // it as authorization or silently promote it while repairing configuration.
    if(bytes->size()>=4 && (*bytes)[0]==std::byte{'L'} && (*bytes)[1]==std::byte{'P'} && (*bytes)[2]==std::byte{'J'} && (*bytes)[3]==std::byte{1}){
        (void)decode_enrollment_record(*bytes);return {};
    }
    const auto r=decode_enrollment_commit(*bytes,verifier);if(!r.receipts[5].empty() || r.receipts[2].empty())return {};
    if(!r.receipts[4].empty()){
        const auto& cert=r.staged.role==PairRole::host?r.staged.bundle.server:r.staged.bundle.client;
        const auto original=identities.locate(r.staged.keys.back().reference,cert,r.staged.server_ipv4);
        if(!original || !identities.ready(*original)){
            const auto& k=r.staged.keys.back();require(identities.key_ready(k.reference,k.point));
            AssociatedIdentity descriptor{k.reference,k.point,sha256(cert),r.staged.server_ipv4,identities.describe(k.reference,cert,r.staged.server_ipv4),cert,false};
            return persist(file,PersistablePairing(r,std::move(descriptor),true),identities,verifier);
        }
    }
    const auto index=r.staged.role==PairRole::host?4U:3U;std::unique_ptr<Signer> signer;
    if(r.receipts[index].empty() && !r.receipts[index-1].empty()){
        signer=keys.open(r.staged.keys.back().reference);require(signer && signer->public_key()==r.staged.keys.back().point);
    }
    auto completion=DurablePairing::resume(file,signer.get(),identities,verifier);auto proof=completion->persistable();
    if(!proof)return {};
    return persist(file,*proof,identities,verifier);
}
} // namespace rwn::core::enrollment
