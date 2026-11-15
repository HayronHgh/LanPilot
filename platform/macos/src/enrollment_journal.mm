#include "rwn/platform/macos/enrollment_journal.hpp"
#include "rwn/core/enrollment_configuration.hpp"
#include "rwn/core/enrollment_status.hpp"
#include <cerrno>
#include <algorithm>
#include <cstdio>
#include <fcntl.h>
#include <pwd.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

namespace rwn::platform::macos {
namespace {
namespace e=core::enrollment;
[[noreturn]]void fail(){throw std::runtime_error("protected enrollment journal unavailable");}
struct Fd {
    int value{-1};explicit Fd(int n=-1):value(n){}~Fd(){if(value>=0)close(value);}
    Fd(const Fd&)=delete;Fd& operator=(const Fd&)=delete;
    Fd(Fd&& o)noexcept:value(o.value){o.value=-1;}
    Fd& operator=(Fd&& o)noexcept{if(this!=&o){if(value>=0)close(value);value=o.value;o.value=-1;}return *this;}
};
void check(int fd,bool directory,bool private_object){
    struct stat s{};if(fd<0 || fstat(fd,&s)!=0 || (directory?!S_ISDIR(s.st_mode):!S_ISREG(s.st_mode)) ||
        (s.st_uid!=getuid() && !(directory && !private_object && s.st_uid==0)) ||
        (private_object && (s.st_mode&0077)!=0) || (!directory && s.st_nlink!=1))fail();
    filesec_t security=filesec_init();if(!security)fail();struct stat extra{};int present{};acl_t acl{};
    const bool ok=fstatx_np(fd,&extra,security)==0 && filesec_query_property(security,FILESEC_ACL,&present)==0 &&
        (!present || filesec_get_property(security,FILESEC_ACL,&acl)==0);filesec_free(security);
    if(!ok || (present && !acl)){if(acl)acl_free(acl);fail();}if(!present)return;
    bool unsafe=false;acl_entry_t entry{};int result=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);
    while(result==0){acl_tag_t tag{};acl_permset_t p{};if(acl_get_tag_type(entry,&tag)!=0 || acl_get_permset(entry,&p)!=0){unsafe=true;break;}
        if(tag==ACL_EXTENDED_ALLOW){for(auto permission:{ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,ACL_WRITE_ATTRIBUTES,
            ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER})if(acl_get_perm_np(p,permission)!=0)unsafe=true;
            if(private_object && acl_get_perm_np(p,ACL_READ_DATA)!=0)unsafe=true;}
        result=acl_get_entry(acl,ACL_NEXT_ENTRY,&entry);
    }acl_free(acl);if(unsafe)fail();
}
bool exists(int directory,const char* name){struct stat s{};if(fstatat(directory,name,&s,AT_SYMLINK_NOFOLLOW)==0)return true;if(errno!=ENOENT)fail();return false;}
// Pin every path component; no symlink traversal. System /private/tmp ancestry
// is permitted only for isolated fixtures; final directory must be 0700 user.
Fd open_directory(const std::filesystem::path& p){
    if(getuid()==0 || getuid()!=geteuid() || !p.is_absolute() || p!=p.lexically_normal())fail();
    Fd current(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
    for(const auto& component:p.relative_path()){
        if(component=="." || component==".." || component.empty())fail();
        Fd next(openat(current.value,component.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        check(next.value,true,false);current=std::move(next);
    }check(current.value,true,true);return current;
}
Fd child(int parent,const char* name,bool private_directory){
    if(mkdirat(parent,name,0700)!=0 && errno!=EEXIST)fail();
    Fd fd(openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));check(fd.value,true,private_directory);
    struct stat s{};if(fstat(fd.value,&s)!=0 || (s.st_mode&0022)!=0)fail();return fd;
}
std::optional<e::Bytes> read_at(int directory,const char* name,std::size_t cap){
    if(!exists(directory,name))return {};
    Fd file(openat(directory,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));check(file.value,false,true);
    struct stat before{},after{};if(fstat(file.value,&before)!=0 || before.st_size<=0 || static_cast<std::uint64_t>(before.st_size)>cap)fail();
    e::Bytes bytes(static_cast<std::size_t>(before.st_size));std::size_t offset{};
    while(offset<bytes.size()){const auto n=read(file.value,bytes.data()+offset,bytes.size()-offset);if(n<0 && errno==EINTR)continue;if(n<=0)fail();offset+=static_cast<std::size_t>(n);}
    char extra{};if(read(file.value,&extra,1)!=0 || fstat(file.value,&after)!=0 || before.st_size!=after.st_size ||
        before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec)fail();return bytes;
}
void create_at(int directory,const char* name,std::span<const std::byte> bytes,std::size_t cap){
    if(bytes.empty() || bytes.size()>cap)fail();
    if(const auto old=read_at(directory,name,cap)){if(!std::ranges::equal(*old,bytes))fail();return;}
    const auto staging=std::string(".")+name+".enrollment-next";
    if(exists(directory,staging.c_str())){
        Fd old(openat(directory,staging.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));check(old.value,false,true);struct stat s{};
        if(fstat(old.value,&s)!=0 || s.st_size<0 || static_cast<std::uint64_t>(s.st_size)>cap || unlinkat(directory,staging.c_str(),0)!=0 || fsync(directory)!=0)fail();
    }
    Fd file(openat(directory,staging.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));check(file.value,false,true);std::size_t offset{};
    while(offset<bytes.size()){const auto n=write(file.value,bytes.data()+offset,bytes.size()-offset);if(n<0 && errno==EINTR)continue;if(n<=0)fail();offset+=static_cast<std::size_t>(n);}
    if(fsync(file.value)!=0 || renameatx_np(directory,staging.c_str(),directory,name,RENAME_EXCL)!=0 || fsync(directory)!=0)fail();
}
std::string hex(const core::Sha256Digest& hash){std::string s;for(auto x:hash){const auto n=std::to_integer<unsigned>(x);s+="0123456789abcdef"[n>>4];s+="0123456789abcdef"[n&15];}return s;}
class Journal final:public e::FileEnrollmentJournal {
public:
    explicit Journal(const std::filesystem::path& root,bool fixture=false):directory_(open_directory(root)),lease_(openat(directory_.value,"owner.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600)),
        logical_root_(fixture?"/Users/fixture/Library/Application Support/LanPilot":root.string()){
        check(lease_.value,false,true);if(flock(lease_.value,LOCK_EX|LOCK_NB)!=0)fail();
        // A failed previous write never becomes the authoritative record.
        if(exists(directory_.value,".enrollment.next")){
            Fd stale(openat(directory_.value,".enrollment.next",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));check(stale.value,false,true);
            struct stat s{};if(fstat(stale.value,&s)!=0 || s.st_size<0 || static_cast<std::uint64_t>(s.st_size)>e::enrollment_storage_cap)fail();
            if(unlinkat(directory_.value,".enrollment.next",0)!=0 || fsync(directory_.value)!=0)fail();
        }
    }
private:
    e::EnrollmentConfigurationLayout configuration_layout(const core::Sha256Digest& g)override{
        return {e::EnrollmentConfigurationLayout::Kind::macos_host,logical_root_+"/service.conf",logical_root_+"/identity/enrolled-v1/"+hex(g)};
    }
    bool publish_configuration(const core::Sha256Digest& g,const std::array<e::Bytes,6>& objects,std::span<const std::byte> profile)override{
        if(profile.empty() || profile.size()>16384)fail();
        // Borrow the held owner.lock; only runtime.lock is additionally needed.
        Fd runtime(openat(directory_.value,"runtime.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600));check(runtime.value,false,true);
        if(flock(runtime.value,LOCK_EX|LOCK_NB)!=0)fail();
        const auto old=read_at(directory_.value,"service.conf",16384);if(old && !std::ranges::equal(*old,profile))fail();
        auto identity=child(directory_.value,"identity",false),enrolled=child(identity.value,"enrolled-v1",true),target=child(enrolled.value,hex(g).c_str(),true);
        for(std::size_t i=0;i<objects.size();++i)create_at(target.value,e::enrollment_resource_names[i],objects[i],65536);
        if(fsync(target.value)!=0 || fsync(enrolled.value)!=0 || fsync(identity.value)!=0 || fsync(directory_.value)!=0)fail();
        create_at(directory_.value,"service.conf",profile,16384);return !old.has_value();
    }
    std::optional<e::Bytes> read_record()override{
        if(!exists(directory_.value,"enrollment.pending"))return {};
        Fd file(openat(directory_.value,"enrollment.pending",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));check(file.value,false,true);
        struct stat before{},after{};if(fstat(file.value,&before)!=0 || before.st_size<=0 || static_cast<std::uint64_t>(before.st_size)>e::enrollment_storage_cap)fail();
        e::Bytes bytes(static_cast<std::size_t>(before.st_size));std::size_t offset{};
        while(offset<bytes.size()){const auto n=read(file.value,bytes.data()+offset,bytes.size()-offset);if(n<0 && errno==EINTR)continue;if(n<=0)fail();offset+=static_cast<std::size_t>(n);}
        char extra{};if(read(file.value,&extra,1)!=0 || fstat(file.value,&after)!=0 || before.st_size!=after.st_size ||
            before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec)fail();return bytes;
    }
    void replace_record(std::span<const std::byte> bytes)override{
        Fd file(openat(directory_.value,".enrollment.next",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));check(file.value,false,true);
        // On any failure retain the incomplete staging file for the next owner.
        std::size_t offset{};while(offset<bytes.size()){const auto n=write(file.value,bytes.data()+offset,bytes.size()-offset);if(n<0 && errno==EINTR)continue;if(n<=0)fail();offset+=static_cast<std::size_t>(n);}
        if(fsync(file.value)!=0 || renameat(directory_.value,".enrollment.next",directory_.value,"enrollment.pending")!=0 || fsync(directory_.value)!=0)fail();
    }
    void remove_record()override{
        if(unlinkat(directory_.value,"enrollment.pending",0)!=0 || fsync(directory_.value)!=0)fail();
    }
    std::optional<e::Bytes> read_status()override{return read_at(directory_.value,"revocation.current",e::status_wire_cap);}
    std::optional<e::Bytes> read_credential(bool retired)override{return read_at(directory_.value,retired?"credential.retired":"credential.current",e::enrollment_record_cap);}
    void store_credential(bool retired,std::span<const std::byte> bytes)override{
        if(bytes.empty() || bytes.size()>e::enrollment_record_cap)fail();
        (void)read_credential(retired);
        const auto* target=retired?"credential.retired":"credential.current";const auto stage=std::string(target)+".next";
        if(exists(directory_.value,stage.c_str())){Fd old(openat(directory_.value,stage.c_str(),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));check(old.value,false,true);struct stat s{};
            if(fstat(old.value,&s)!=0 || s.st_size<0 || static_cast<std::uint64_t>(s.st_size)>e::enrollment_record_cap || unlinkat(directory_.value,stage.c_str(),0)!=0)fail();}
        Fd out(openat(directory_.value,stage.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));check(out.value,false,true);std::size_t at{};
        while(at<bytes.size()){const auto n=write(out.value,bytes.data()+at,bytes.size()-at);if(n<0 && errno==EINTR)continue;if(n<=0)fail();at+=static_cast<std::size_t>(n);}
        if(fsync(out.value)!=0 || renameat(directory_.value,stage.c_str(),directory_.value,target)!=0 || fsync(directory_.value)!=0)fail();
    }
    void clear_credential(bool retired)override{
        if(!read_credential(retired) || unlinkat(directory_.value,retired?"credential.retired":"credential.current",0)!=0 || fsync(directory_.value)!=0)fail();
    }
    void store_status(std::span<const std::byte> bytes)override{
        if(bytes.empty() || bytes.size()>e::status_wire_cap)fail();
        (void)read_status();
        if(exists(directory_.value,".revocation.next")){
            Fd stale(openat(directory_.value,".revocation.next",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));check(stale.value,false,true);struct stat s{};
            if(fstat(stale.value,&s)!=0 || s.st_size<0 || static_cast<std::uint64_t>(s.st_size)>e::status_wire_cap || unlinkat(directory_.value,".revocation.next",0)!=0)fail();
        }
        Fd file(openat(directory_.value,".revocation.next",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));check(file.value,false,true);std::size_t at{};
        while(at<bytes.size()){const auto n=write(file.value,bytes.data()+at,bytes.size()-at);if(n<0 && errno==EINTR)continue;if(n<=0)fail();at+=static_cast<std::size_t>(n);}
        if(fsync(file.value)!=0 || renameat(directory_.value,".revocation.next",directory_.value,"revocation.current")!=0 || fsync(directory_.value)!=0)fail();
    }
    std::optional<e::Bytes> read_abort(const std::array<std::byte,32>& round)override{
        if(!exists(directory_.value,"aborted"))return {};
        Fd dir(openat(directory_.value,"aborted",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));check(dir.value,true,true);
        return read_at(dir.value,(hex(round)+".lpj").c_str(),e::enrollment_storage_cap);
    }
    void store_abort(const std::array<std::byte,32>& round,std::span<const std::byte> bytes)override{
        auto dir=child(directory_.value,"aborted",true);std::size_t count{};
        const auto copy=dup(dir.value);if(copy<0)fail();DIR* scan=fdopendir(copy);if(!scan){::close(copy);fail();}struct CloseDir{DIR* d;~CloseDir(){closedir(d);}} close{scan};
        errno=0;while(const auto* entry=readdir(scan)){const std::string name(entry->d_name);if(name=="." || name=="..")continue;
            if(name=="."+hex(round)+".lpj.enrollment-next")continue;
            if(name.size()!=68 || name.substr(64)!=".lpj" || name.substr(0,64).find_first_not_of("0123456789abcdef")!=std::string::npos)fail();
            if(++count>e::enrollment_abort_history_cap)fail();
            errno=0;
        }if(errno)fail();
        const auto target=hex(round)+".lpj";
        if(!exists(dir.value,target.c_str()) && count>=e::enrollment_abort_history_cap)fail();
        create_at(dir.value,target.c_str(),bytes,e::enrollment_storage_cap);if(fsync(directory_.value)!=0)fail();
    }
    Fd directory_,lease_;std::string logical_root_;
};
}
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal_fixture(const std::filesystem::path& root){return std::make_unique<Journal>(root,true);}
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal(){
    const auto* p=getpwuid(getuid());if(!p || !p->pw_dir)fail();const std::filesystem::path home(p->pw_dir);
    if(!home.string().starts_with("/Users/") || home.string().find('/',7)!=std::string::npos)fail();
    // Do not create or alter a legacy installation's parent permissions here.
    // The canonical installer owns creation of this 0700 product directory.
    return std::make_unique<Journal>(home/"Library/Application Support/LanPilot");
}
}
