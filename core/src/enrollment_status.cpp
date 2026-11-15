#include "rwn/core/enrollment_status.hpp"
#include <algorithm>
#include <cstring>

namespace rwn::core::enrollment {
namespace {
void require(bool b){if(!b)throw std::runtime_error("native revocation refresh unavailable");}
void append(Bytes& b,std::span<const std::byte> p){b.insert(b.end(),p.begin(),p.end());}
void number(Bytes& b,std::uint64_t n,unsigned width){for(unsigned i=width;i>0;--i)b.push_back(static_cast<std::byte>(n>>((i-1)*8)));}
struct Reader{
    std::span<const std::byte> bytes;std::size_t at{};
    auto take(std::size_t n){require(n<=bytes.size()-at);auto b=bytes.subspan(at,n);at+=n;return b;}
    std::uint64_t number(unsigned n){std::uint64_t v{};for(auto b:take(n))v=(v<<8)|std::to_integer<unsigned>(b);return v;}
};
void time_valid(Time t){using namespace std::chrono;require(t>=sys_days{year{2020}/1/1} && t<sys_days{year{2100}/1/1});}
EnrollmentCommitRecord committed(FileEnrollmentJournal& f,const PairProofVerifier& v){auto r=DurablePairing::inspect(f,v);require(r && !r->receipts[4].empty() && r->receipts[5].empty());return *r;}
Bytes scope(const EnrollmentCommitRecord& r){Bytes b;append(b,r.round);append(b,std::as_bytes(std::span{r.transcript.binding}));
    for(const auto* p:{&r.staged.bundle.root,&r.staged.bundle.server,&r.staged.bundle.client})append(b,sha256(*p));
    return b;}
Bytes signed_message(std::span<const std::byte> b,bool full=false){const std::string_view domain=full?"LanPilot native revocation refresh v2":"LanPilot native revocation refresh v1";Bytes out;append(out,std::as_bytes(std::span{domain}));out.push_back(std::byte{});append(out,b);return out;}
auto objects(PublicIdentityBundle& b,bool full){std::vector<Bytes*> out;
    if(full)out={&b.root,&b.server,&b.client};
    out.insert(out.end(),{&b.crl,&b.server_ocsp,&b.client_ocsp});return out;}
void same_keys(const EnrollmentCommitRecord& r,const PublicIdentityBundle& b){
    require(certificate_facts(b.root,KeyPurpose::authority).subject_key==r.transcript.host.authority_key &&
        certificate_facts(b.server,KeyPurpose::server,r.transcript.host.desktop_ipv4).subject_key==r.transcript.host.identity_key &&
        certificate_facts(b.client,KeyPurpose::client).subject_key==r.transcript.client.identity_key);
}
StatusSnapshot decode(const EnrollmentCommitRecord& r,IdentityStore& ids,const PairProofVerifier& v,Bytes wire,Time now,bool historical=false){
    require(wire.size()>=306 && wire.size()<=status_wire_cap);const bool full=std::memcmp(wire.data(),"LPS2",4)==0;
    require(full || std::memcmp(wire.data(),"LPS1",4)==0);Reader in{wire};in.take(4);require(in.number(4)==wire.size()-8);
    const auto start=in.at;require(in.number(4)==(full?0x02000000U:0x01000000U));require(std::ranges::equal(in.take(160),scope(r)));
    const auto issued=in.number(8),expires=in.number(8);require(issued<=0x7fffffffffffffffULL && expires<=0x7fffffffffffffffULL);
    const Time before{std::chrono::seconds{static_cast<std::int64_t>(issued)}},after{std::chrono::seconds{static_cast<std::int64_t>(expires)}};
    time_valid(before);time_valid(after);require(after>before && after-before<=std::chrono::hours{24});time_valid(now);
    if(!historical)require(before<=now+std::chrono::minutes{5} && now<after);
    auto bundle=r.staged.bundle;auto parts=objects(bundle,full);std::vector<Sha256Digest> hashes(parts.size());for(auto& h:hashes)std::ranges::copy(in.take(32),h.begin());
    std::vector<std::size_t> sizes(parts.size());std::size_t total{};for(auto& n:sizes){n=static_cast<std::size_t>(in.number(4));require(n>0 && n<=65536);total+=n;}require(total<=131072);
    const auto header=std::span(wire).subspan(start,in.at-start);const auto signature_size=in.number(2);require(signature_size>=8 && signature_size<=72);
    const auto signature=in.take(static_cast<std::size_t>(signature_size));(void)pairing_signature_raw(signature);
    require(v.verify(r.transcript.host.authority_key,signed_message(header,full),signature));
    for(std::size_t i=0;i<parts.size();++i){const auto b=in.take(sizes[i]);require(sha256(b)==hashes[i]);parts[i]->assign(b.begin(),b.end());}
    same_keys(r,bundle);
    require(in.at==wire.size());
    // An expired, authenticated cache supplies ONLY a monotonic counter. Its
    // signature/scope/payload hashes are still checked above. Requiring native
    // CURRENT revocation freshness here would deadlock renewal after expiry:
    // Windows pTime does not change CRL freshness checking. Historical mode
    // never returns usable connection evidence; all new/cache admission below
    // separately requires positive native validation at the operation's time.
    if(!historical)require(ids.verify_revocation(bundle,r.transcript.host.desktop_ipv4,now));
    return {std::move(wire),std::move(bundle),before,after};
}
Bytes issue_wire(const EnrollmentCommitRecord& r,const PublicIdentityBundle& bundle,Signer& signer,Time before,Time after){
    const bool full=bundle.root!=r.staged.bundle.root || bundle.server!=r.staged.bundle.server || bundle.client!=r.staged.bundle.client;auto copy=bundle;const auto parts=objects(copy,full);
    Bytes body{full?std::byte{2}:std::byte{1},std::byte{},std::byte{},std::byte{}};append(body,scope(r));number(body,static_cast<std::uint64_t>(before.time_since_epoch().count()),8);number(body,static_cast<std::uint64_t>(after.time_since_epoch().count()),8);
    for(const auto* p:parts)append(body,sha256(*p));
    for(const auto* p:parts){require(!p->empty() && p->size()<=65536);number(body,p->size(),4);}
    const auto signature=signer.sign_sha256(signed_message(body,full));(void)pairing_signature_raw(signature);number(body,signature.size(),2);append(body,signature);
    for(const auto* p:parts)append(body,*p);
    Bytes out{std::byte{'L'},std::byte{'P'},std::byte{'S'},full?std::byte{'2'}:std::byte{'1'}};number(out,body.size(),4);append(out,body);require(out.size()<=status_wire_cap);return out;
}
Serial renewal_serial(const Bytes& previous,Time now,unsigned role){Bytes m;append(m,sha256(previous));number(m,static_cast<std::uint64_t>(now.time_since_epoch().count()),8);number(m,role,1);
    const auto digest=sha256(m);Serial id{};std::copy_n(digest.begin(),id.size(),id.begin());if(std::ranges::all_of(id,[](auto b){return b==std::byte{};}))id[0]=std::byte{1};return id;}
void read(EnrollmentChannel& c,Bytes& b,std::size_t size,const std::atomic_bool& stop,PairingConsent::Clock::time_point until){
    require(size<=status_wire_cap && b.size()<=size);while(b.size()<size){require(!stop && PairingConsent::Clock::now()<until);const auto old=b.size(),n=std::min<std::size_t>(size-old,4096);b.resize(old+n);
        const auto result=c.read(std::span(b).subspan(old),std::chrono::milliseconds{20});require(!result.eof && result.bytes<=n);b.resize(old+result.bytes);}
}
}
std::optional<StatusSnapshot> EnrollmentStatus::cached(FileEnrollmentJournal& f,IdentityStore& ids,const PairProofVerifier& v,Time now){
    const auto r=committed(f,v);const auto bytes=f.read_status();if(!bytes)return {};return decode(r,ids,v,*bytes,now);
}
StatusSnapshot EnrollmentStatus::issue(FileEnrollmentJournal& f,KeyStore& keys,IdentityStore& ids,const PairProofVerifier& v,Time now,bool renew_certificates){
    using namespace std::chrono;const auto r=committed(f,v);require(r.staged.role==PairRole::host);time_valid(now);
    auto bundle=r.staged.bundle;std::optional<Time> previous_issue;const auto previous=f.read_status();if(previous){
        const auto old=decode(r,ids,v,*previous,now,true);require(now+minutes{5}>=old.issued);
        bundle=old.bundle;previous_issue=old.issued;
    }
    auto issuer=keys.open(r.staged.keys.front().reference);require(issuer && issuer->public_key()==r.transcript.host.authority_key);
    auto root=certificate_facts(bundle.root,KeyPurpose::authority);
    auto server=certificate_facts(bundle.server,KeyPurpose::server,r.transcript.host.desktop_ipv4),client=certificate_facts(bundle.client,KeyPurpose::client);
    const bool due=renew_certificates && (root.validity.after<now+days{365} || server.validity.after<now+days{30} || client.validity.after<now+days{30});
    if(previous && !due && now<*previous_issue+hours{12}){const auto old=decode(r,ids,v,*previous,now,true);if(now<old.expires)return decode(r,ids,v,*previous,now);}
    if(due){
        if(root.validity.after<now+days{365}){bundle.root=root_certificate(*issuer,renewal_serial(bundle.root,now,0),{std::max(now-minutes{5},root.validity.before),now+days{3650}});root=certificate_facts(bundle.root,KeyPurpose::authority);}
        const Validity leaf{std::max({now-minutes{5},root.validity.before,server.validity.before,client.validity.before}),std::min(now+days{180},root.validity.after)};
        const AlternativeName address{Bytes(r.transcript.host.desktop_ipv4.begin(),r.transcript.host.desktop_ipv4.end()),{}};
        bundle.server=leaf_certificate(*issuer,renewal_serial(bundle.server,now,1),r.transcript.host.identity_key,Role::server,leaf,root.validity,std::span{&address,1});
        bundle.client=leaf_certificate(*issuer,renewal_serial(bundle.client,now,2),r.transcript.client.identity_key,Role::client,leaf,root.validity);
        server=certificate_facts(bundle.server,KeyPurpose::server,r.transcript.host.desktop_ipv4);client=certificate_facts(bundle.client,KeyPurpose::client);same_keys(r,bundle);
    }
    const Time issued=std::max({Time{floor<hours>(now)},root.validity.before,server.validity.before,client.validity.before,previous_issue?*previous_issue+seconds{1}:Time{}});
    const auto after=std::min({issued+hours{23},root.validity.after,server.validity.after,client.validity.after});require(after>now+minutes{5});
    const Validity window{std::max(issued-minutes{5},root.validity.before),after};
    bundle.crl=revocation_list(*issuer,static_cast<std::uint64_t>(issued.time_since_epoch().count())+1,window,root.validity,{});
    bundle.server_ocsp=ocsp_response(*issuer,server.serial,Status::good,issued,window,root.validity);
    bundle.client_ocsp=ocsp_response(*issuer,client.serial,Status::good,issued,window,root.validity);
    auto result=decode(r,ids,v,issue_wire(r,bundle,*issuer,issued,after),now);require(f.read_status()==previous);f.store_status(result.wire);require(f.read_status()==std::optional<Bytes>{result.wire});return result;
}
RenewedIdentity EnrollmentStatus::identity_proof(FileEnrollmentJournal& f,IdentityStore& ids,const PairProofVerifier& v,Time now){
    const auto r=committed(f,v);const auto bytes=f.read_status();
    if(!bytes){require(ids.verify_revocation(r.staged.bundle,r.transcript.host.desktop_ipv4,now));return RenewedIdentity{r.transcript,r.staged.bundle,r.staged.role,now+std::chrono::seconds{5}};}
    auto s=decode(r,ids,v,*bytes,now);
    return RenewedIdentity{r.transcript,std::move(s.bundle),r.staged.role,s.expires};
}
StatusSnapshot EnrollmentStatus::accept(FileEnrollmentJournal& f,IdentityStore& ids,const PairProofVerifier& v,Bytes wire,Time now){
    const auto r=committed(f,v);auto next=decode(r,ids,v,std::move(wire),now);
    const auto previous=f.read_status();if(previous){const auto old=decode(r,ids,v,*previous,now,true);require(next.issued>old.issued || next.wire==old.wire);
        for(const auto role:{KeyPurpose::authority,KeyPurpose::server,KeyPurpose::client}){
            const auto& before=role==KeyPurpose::authority?old.bundle.root:role==KeyPurpose::server?old.bundle.server:old.bundle.client;
            const auto& after=role==KeyPurpose::authority?next.bundle.root:role==KeyPurpose::server?next.bundle.server:next.bundle.client;
            if(before!=after){const auto a=certificate_facts(before,role,r.transcript.host.desktop_ipv4),b=certificate_facts(after,role,r.transcript.host.desktop_ipv4);
                require(b.validity.before>=a.validity.before && b.validity.after>a.validity.after);}
        }
    }
    require(f.read_status()==previous);f.store_status(next.wire);require(f.read_status()==std::optional<Bytes>{next.wire});return next;
}
Bytes status_request(const EnrollmentCommitRecord& r){require(!r.receipts[4].empty() && r.receipts[5].empty());Bytes b{std::byte{'L'},std::byte{'P'},std::byte{'Q'},std::byte{'1'}};append(b,scope(r));return b;}
void serve_status(EnrollmentChannel& c,FileEnrollmentJournal& f,KeyStore& keys,IdentityStore& ids,const PairProofVerifier& v,Time now,const std::atomic_bool& stop){
    struct Close{EnrollmentChannel& c;~Close(){c.close();}} close{c};const auto until=PairingConsent::Clock::now()+std::chrono::seconds{3};Bytes request;const auto expected=status_request(committed(f,v));read(c,request,expected.size(),stop,until);require(request==expected);
    const auto status=EnrollmentStatus::issue(f,keys,ids,v,now);c.write(status.wire,until,stop);
}
StatusSnapshot fetch_status(EnrollmentChannel& c,FileEnrollmentJournal& f,IdentityStore& ids,const PairProofVerifier& v,Time now,const std::atomic_bool& stop){
    return EnrollmentStatus::accept(f,ids,v,exchange_status(c,status_request(committed(f,v)),stop),now);
}
Bytes exchange_status(EnrollmentChannel& c,std::span<const std::byte> request,const std::atomic_bool& stop){
    struct Close{EnrollmentChannel& c;~Close(){c.close();}} close{c};require(request.size()==164);const auto until=PairingConsent::Clock::now()+std::chrono::seconds{3};c.write(request,until,stop);Bytes b;read(c,b,8,stop,until);require(std::memcmp(b.data(),"LPS1",4)==0 || std::memcmp(b.data(),"LPS2",4)==0);
    Reader header{b};header.take(4);const auto n=header.number(4);require(n>=298 && n<=status_wire_cap-8);read(c,b,8+static_cast<std::size_t>(n),stop,until);return b;
}
Bytes EnrollmentStatus::connection_crl(FileEnrollmentJournal& f,IdentityStore& ids,const PairProofVerifier& v,std::span<const std::byte> root,
    std::span<const std::byte> server,std::span<const std::byte> local,Time now,std::function<Bytes()> fetch){
    const auto r=committed(f,v);require(r.staged.role==PairRole::client && std::ranges::equal(root,r.staged.bundle.root) && std::ranges::equal(server,sha256(r.staged.bundle.server)));
    const auto identity=ids.locate(r.staged.keys.back().reference,r.staged.bundle.client,r.transcript.host.desktop_ipv4);
    require(identity && std::ranges::equal(identity->native_reference,local) && ids.ready(*identity));
    std::optional<StatusSnapshot> current;
    const auto bytes=f.read_status();if(bytes){
        const auto old=decode(r,ids,v,*bytes,now,true);
        if(now<old.expires){current=decode(r,ids,v,*bytes,now);if(now+std::chrono::hours{6}<old.expires)return old.bundle.crl;}
    }
    try{return EnrollmentStatus::accept(f,ids,v,fetch(),now).bundle.crl;}
    catch(...){if(current)return current->bundle.crl;if(!bytes && ids.verify_revocation(r.staged.bundle,r.transcript.host.desktop_ipv4,now))return r.staged.bundle.crl;throw;}
}
StatusSnapshot EnrollmentStatus::connection_credentials(FileEnrollmentJournal& f,KeyStore& keys,IdentityStore& ids,const PairProofVerifier& v,
    std::span<const std::byte> root,std::span<const std::byte> server,std::span<const std::byte> local,Time now,std::function<Bytes()> fetch){
    const auto r=committed(f,v);require(r.staged.role==PairRole::client && std::ranges::equal(root,r.staged.bundle.root) && std::ranges::equal(server,sha256(r.staged.bundle.server)));
    const auto& ref=r.staged.keys.back().reference;auto key=keys.open(ref);require(key && key->public_key()==r.transcript.client.identity_key);
    require(std::ranges::equal(local,ids.describe(ref,r.staged.bundle.client,r.transcript.host.desktop_ipv4)));
    std::optional<StatusSnapshot> current;const auto bytes=f.read_status();
    if(bytes){const auto old=decode(r,ids,v,*bytes,now,true);if(now<old.expires)current=decode(r,ids,v,*bytes,now);}
    // New connections must discover the server incarnation's selected leaves,
    // even while a previous signed certificate snapshot is still time-valid.
    try{return accept(f,ids,v,fetch(),now);}catch(...){
        if(current)return *current;
        if(!bytes && ids.verify_revocation(r.staged.bundle,r.transcript.host.desktop_ipv4,now))return {{},r.staged.bundle,now,now+std::chrono::seconds{5}};
        throw;
    }
}
}
