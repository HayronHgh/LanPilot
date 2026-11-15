#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

#include "configuration_store.hpp"
#include "product_configuration.hpp"
#include "code_identity.hpp"
#include "program_install.hpp"
#include "program_service.hpp"
#include "program_update.hpp"
#include "service_runtime.hpp"
#include "native_status_service.hpp"
#include "rwn/platform/macos/enrollment_identity.hpp"
#include "../agent_entry.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/platform/macos/desktop_runtime.hpp"
#include "rwn/platform/macos/tcp_listener.hpp"
#include "rwn/platform/macos/update_signature.hpp"

#include <cerrno>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <membership.h>
#include <libproc.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rwn::agent::macos {
namespace {
[[noreturn]] void fail(){throw std::runtime_error("protected LanPilot configuration unavailable");}

class Descriptor {
public:
    explicit Descriptor(int value=-1):value_(value){}
    ~Descriptor(){if(value_>=0)close(value_);}
    Descriptor(const Descriptor&)=delete;
    Descriptor& operator=(const Descriptor&)=delete;
    Descriptor(Descriptor&& other) noexcept:value_(other.value_){other.value_=-1;}
    Descriptor& operator=(Descriptor&& other) noexcept {
        if(this!=&other){if(value_>=0)close(value_);value_=other.value_;other.value_=-1;}return *this;
    }
    int get()const{return value_;}
private:int value_;
};

std::string local_home(){
    if(getuid()==0 || getuid()!=geteuid())fail();
    const auto* entry=getpwuid(getuid());if(!entry || !entry->pw_dir)fail();
    const std::string home(entry->pw_dir);
    if(!canonical_path(home) || !home.starts_with("/Users/") || home.find('/',7)!=std::string::npos)fail();
    return home;
}

void validate_object(int fd,bool directory,bool private_object,bool allow_root_owner=false){
    struct stat state{};if(fd<0 || fstat(fd,&state)!=0)fail();
    if(directory?!S_ISDIR(state.st_mode):!S_ISREG(state.st_mode))fail();
    if(state.st_uid!=getuid() && !(allow_root_owner && state.st_uid==0))fail();
    if((state.st_mode&0022)!=0 || (private_object && (state.st_mode&0077)!=0) ||
       (!directory && state.st_nlink!=1))fail();
    // acl_get_fd_np returns NULL/ENOENT for an existing file with no ACL.
    // Query presence separately so absence is not mistaken for read failure.
    filesec_t security=filesec_init();if(!security)fail();
    struct stat extended{};int present=0;acl_t acl=nullptr;
    const bool retrieved=fstatx_np(fd,&extended,security)==0 &&
        filesec_query_property(security,FILESEC_ACL,&present)==0 &&
        (!present || filesec_get_property(security,FILESEC_ACL,&acl)==0);
    filesec_free(security);
    if(!retrieved){if(acl)acl_free(acl);fail();}
    if(!present)return;
    if(!acl)fail();
    acl_entry_t entry{};int found=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);
    bool unsafe=false;
    while(found==0){
        acl_tag_t tag{};acl_permset_t permissions{};
        if(acl_get_tag_type(entry,&tag)!=0 || acl_get_permset(entry,&permissions)!=0){unsafe=true;break;}
        if(tag==ACL_EXTENDED_ALLOW){
            for(auto permission:{ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,
                                 ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER}){
                if(acl_get_perm_np(permissions,permission)!=0)unsafe=true;
            }
            // Private metadata must not acquire an ACL read grant either.
            if(private_object && acl_get_perm_np(permissions,ACL_READ_DATA)!=0)unsafe=true;
        }
        found=acl_get_entry(acl,ACL_NEXT_ENTRY,&entry);
    }
    acl_free(acl);if(unsafe)fail();
}

Descriptor directory_at(int parent,const char* name,bool create,bool private_directory){
    if(create && mkdirat(parent,name,0700)!=0 && errno!=EEXIST)fail();
    Descriptor result(openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    validate_object(result.get(),true,private_directory,true);return result;
}

Descriptor absolute_directory(std::string_view path){
    if(!canonical_path(path))fail();
    Descriptor current(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
    std::size_t start=1;
    while(start<path.size()){
        const auto end=path.find('/',start);
        const std::string component(path.substr(start,end==std::string_view::npos?end:end-start));
        current=directory_at(current.get(),component.c_str(),false,false);
        start=end==std::string_view::npos?path.size():end+1;
    }
    return current;
}

Descriptor product_directory(bool create){
    auto home=absolute_directory(local_home());
    auto library=directory_at(home.get(),"Library",false,false);
    auto support=directory_at(library.get(),"Application Support",create,false);
    return directory_at(support.get(),"LanPilot",create,true);
}

Descriptor owner(int directory,const char* name="owner.lock"){
    Descriptor lease(openat(directory,name,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));
    validate_object(lease.get(),false,true);
    if(flock(lease.get(),LOCK_EX|LOCK_NB)!=0)fail();
    return lease; // Never unlink the inode while a contender may own it.
}

std::string read_file(int directory,const char* name,std::size_t cap,bool private_file,bool root_owner=false){
    Descriptor file(openat(directory,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
    validate_object(file.get(),false,private_file,root_owner);
    struct stat before{},after{};if(fstat(file.get(),&before)!=0 || before.st_size<=0 ||
        static_cast<std::uint64_t>(before.st_size)>cap)fail();
    std::string bytes(static_cast<std::size_t>(before.st_size),'\0');std::size_t offset=0;
    while(offset<bytes.size()){
        const auto count=read(file.get(),bytes.data()+offset,bytes.size()-offset);
        if(count<0 && errno==EINTR)continue;
        if(count<=0)fail();offset+=static_cast<std::size_t>(count);
    }
    char excess{};if(read(file.get(),&excess,1)!=0 || fstat(file.get(),&after)!=0 ||
        before.st_size!=after.st_size || before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec)fail();
    return bytes;
}

std::string read_absolute(const std::string& path,std::size_t cap,bool root_owner=false){
    if(!canonical_path(path))fail();
    const auto separator=path.rfind('/');auto parent=absolute_directory(path.substr(0,separator));
    return read_file(parent.get(),path.substr(separator+1).c_str(),cap,false,root_owner);
}

bool exists_at(int directory,const char* name){
    struct stat state{};if(fstatat(directory,name,&state,AT_SYMLINK_NOFOLLOW)==0)return true;
    if(errno!=ENOENT)fail();return false;
}

bool save_new(int directory,const ServiceConfiguration& configuration,std::string_view home){
    auto lease=owner(directory);
    auto runtime=owner(directory,"runtime.lock");
    const auto bytes=serialize_configuration(configuration,home);
    if(exists_at(directory,"service.conf")){
        if(parse_configuration(read_file(directory,"service.conf",maximum_configuration_bytes,true),home)!=configuration)fail();
        return false; // Same imported metadata, no rewrite or key access.
    }
    const std::string temporary=".service-"+std::string(NSUUID.UUID.UUIDString.UTF8String);
    Descriptor file(openat(directory,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    try {
        validate_object(file.get(),false,true);
        std::size_t offset=0;
        while(offset<bytes.size()){
            const auto count=write(file.get(),bytes.data()+offset,bytes.size()-offset);
            if(count<0 && errno==EINTR)continue;
            if(count<=0)fail();offset+=static_cast<std::size_t>(count);
        }
        if(fsync(file.get())!=0 || renameatx_np(directory,temporary.c_str(),directory,"service.conf",RENAME_EXCL)!=0 ||
           fsync(directory)!=0)fail();
    } catch(...){unlinkat(directory,temporary.c_str(),0);throw;}
    return true;
}

ServiceConfiguration legacy_configuration(){
    const auto home=local_home();
    const auto bytes=read_absolute(home+"/Library/LaunchAgents/com.lanpilot.desktop-tls.plist",65536);
    auto* data=[NSData dataWithBytes:bytes.data() length:bytes.size()];
    id value=[NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nullptr error:nullptr];
    if(![value isKindOfClass:NSDictionary.class])fail();
    NSDictionary* plist=value;
    const NSSet* allowed=[NSSet setWithArray:@[@"Label",@"ProgramArguments",@"LimitLoadToSessionType",@"RunAtLoad",
        @"KeepAlive",@"ThrottleInterval",@"Umask",@"WorkingDirectory",@"StandardOutPath",@"StandardErrorPath"]];
    for(id key in plist)if(![allowed containsObject:key])fail();
    if(![plist[@"Label"] isEqual:@"com.lanpilot.desktop-tls"])fail();
    if(![plist[@"LimitLoadToSessionType"] isEqual:@"Aqua"] || ![plist[@"RunAtLoad"] isEqual:@YES] ||
       ![plist[@"KeepAlive"] isEqual:@YES] || ![plist[@"ThrottleInterval"] isEqual:@10] ||
       ![plist[@"Umask"] isEqual:@63] || ![plist[@"WorkingDirectory"] isEqual:[NSString stringWithUTF8String:home.c_str()]] ||
       ![plist[@"StandardOutPath"] isEqual:@"/dev/null"])fail();
    auto* diagnostic=[NSString stringWithUTF8String:(home+"/.local/share/lanpilot/logs/clipboard-startup.log").c_str()];
    if(![plist[@"StandardErrorPath"] isEqual:@"/dev/null"] && ![plist[@"StandardErrorPath"] isEqual:diagnostic])fail();
    id raw=plist[@"ProgramArguments"];
    if(![raw isKindOfClass:NSArray.class])fail();
    NSArray* arguments=raw;if(arguments.count!=10 && arguments.count!=11)fail();
    std::vector<std::string> args;
    for(id argument in arguments){
        if(![argument isKindOfClass:NSString.class] || [argument length]>8192)fail();
        const char* utf8=[argument UTF8String];if(!utf8 || std::strlen(utf8)!=[argument lengthOfBytesUsingEncoding:NSUTF8StringEncoding])fail();
        args.emplace_back(utf8);
    }
    if(args[0]!=home+"/.local/libexec/lanpilot-tls/rwn-desktop-agent" || args[1]!="--stream-visual-tls" ||
       (args.size()==11 && args[10]!="--clipboard-text"))fail();
    for(auto index:{4U,5U})for(char& c:args[index])if(c>='A' && c<='F')c=static_cast<char>(c-'A'+'a');
    ServiceConfiguration configuration{args[2],static_cast<std::uint16_t>(canonical_unsigned(args[3],65535)),
        args[4],args[5],args[6],args[9],args[7],args[8],args.size()==11};
    validate_configuration(configuration,home);
    // Verify resource objects without parsing/exporting keys or modifying trust.
    (void)read_absolute(configuration.ca_path,65536);(void)read_absolute(configuration.ocsp_path,65536);
    return configuration;
}

bool loaded_legacy_service(){
    auto* task=[[NSTask alloc] init];task.executableURL=[NSURL fileURLWithPath:@"/bin/launchctl"];
    task.arguments=@[@"print",[NSString stringWithFormat:@"gui/%u/com.lanpilot.desktop-tls",getuid()]];
    task.standardOutput=NSFileHandle.fileHandleWithNullDevice;
    task.standardError=NSFileHandle.fileHandleWithNullDevice;
    if(![task launchAndReturnError:nullptr])fail();
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(task.running && std::chrono::steady_clock::now()<deadline)usleep(10000);
    if(task.running){[task terminate];fail();}
    return task.terminationStatus==0;
}

// Fixed filenames only; all callers hold the operation or runtime owner lease.
void write_protected(int directory,const char* name,std::string_view bytes,bool replace){
    if(bytes.empty() || bytes.size()>65536)fail();
    if(exists_at(directory,name)){
        (void)read_file(directory,name,65536,true);
        if(!replace)fail();
    }
    const std::string temporary=".login-"+std::string(NSUUID.UUID.UUIDString.UTF8String);
    Descriptor file(openat(directory,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    try {
        validate_object(file.get(),false,true);std::size_t offset=0;
        while(offset<bytes.size()){
            const auto count=write(file.get(),bytes.data()+offset,bytes.size()-offset);
            if(count<0 && errno==EINTR)continue;
            if(count<=0)fail();offset+=static_cast<std::size_t>(count);
        }
        if(fsync(file.get())!=0)fail();
        const int moved=replace?renameat(directory,temporary.c_str(),directory,name):
            renameatx_np(directory,temporary.c_str(),directory,name,RENAME_EXCL);
        if(moved!=0 || fsync(directory)!=0)fail();
    } catch(...){unlinkat(directory,temporary.c_str(),0);throw;}
}

bool runtime_busy(int directory){
    Descriptor runtime(openat(directory,"runtime.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));
    validate_object(runtime.get(),false,true);
    if(flock(runtime.get(),LOCK_EX|LOCK_NB)==0)return false;
    if(errno!=EWOULDBLOCK)fail();return true;
}

struct CommandResult{int exit_code{};std::string output;};
CommandResult bounded_product_command(NSString* executable,NSArray<NSString*>* arguments){
    @autoreleasepool {
    auto* task=[[NSTask alloc] init];task.executableURL=[NSURL fileURLWithPath:executable];
    task.arguments=arguments;task.environment=@{@"PATH":@"/usr/bin:/bin:/usr/sbin:/sbin",@"LANG":@"C"};
    auto* pipe=[NSPipe pipe];task.standardOutput=pipe;task.standardError=NSFileHandle.fileHandleWithNullDevice;
    if(![task launchAndReturnError:nullptr])fail();
    const int fd=pipe.fileHandleForReading.fileDescriptor;
    if(fcntl(fd,F_SETFL,O_NONBLOCK)!=0){
        if(task.running)kill(task.processIdentifier,SIGKILL);
        fail();
    }
    CommandResult result;bool exceeded=false;
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    for(;;){
        char buffer[4096];const auto count=read(fd,buffer,sizeof(buffer));
        if(count>0){
            result.output.append(buffer,static_cast<std::size_t>(count));
            if(result.output.size()>65536){exceeded=true;break;}
        }else if(count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR){exceeded=true;break;}
        else if(!task.running && count<=0)break;
        if(std::chrono::steady_clock::now()>=deadline){exceeded=true;break;}
        if(count<=0)usleep(10000);
    }
    if(exceeded || task.running){
        if(task.running){@try{[task terminate];}@catch(NSException*){}}
        usleep(20000);
        if(task.running)kill(task.processIdentifier,SIGKILL);
        fail();
    }
    result.exit_code=task.terminationStatus;return result;
    }
}
CommandResult launch_control(NSArray<NSString*>* arguments){return bounded_product_command(@"/bin/launchctl",arguments);}

NSString* job_target(bool legacy){return [NSString stringWithFormat:@"gui/%u/%@",getuid(),
    legacy?@"com.lanpilot.desktop-tls":@"com.lanpilot.desktop.service"];}

pid_t job_pid(bool legacy){
    const auto result=launch_control(@[@"print",job_target(legacy)]);
    if(result.exit_code!=0)return 0;
    const auto marker=result.output.find("\tpid = ");
    if(marker==std::string::npos)return 0;
    const auto begin=marker+7;const auto end=result.output.find('\n',begin);
    return static_cast<pid_t>(canonical_unsigned(std::string_view(result.output).substr(begin,end-begin),2147483647));
}

std::optional<std::uint64_t> process_start(unsigned pid);
bool wait_stopped(bool legacy,pid_t previous,int directory,std::uint64_t expected_start=0){
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    do {
        bool alive=previous>0 && (kill(previous,0)==0 || errno==EPERM);
        if(alive && expected_start){
            const auto actual=process_start(static_cast<unsigned>(previous));
            if(actual && *actual!=expected_start)alive=false;
        }
        if(!alive && job_pid(legacy)==0 && (legacy || !runtime_busy(directory)))return true;
        usleep(20000);
    }while(std::chrono::steady_clock::now()<deadline);
    return false;
}

SMAppService* native_service(){return [SMAppService agentServiceWithPlistName:@"com.lanpilot.desktop.service.plist"];}

std::vector<std::byte> identity_bytes(const ServiceConfiguration& configuration){
    std::vector<std::byte> result;
    const auto nibble=[](char c){return static_cast<unsigned>(c<='9'?c-'0':c-'a'+10);};
    for(std::size_t i=0;i<configuration.identity_reference.size();i+=2)
        result.push_back(static_cast<std::byte>((nibble(configuration.identity_reference[i])<<4)|nibble(configuration.identity_reference[i+1])));
    return result;
}

LoginJournal load_journal(int directory){
    if(!exists_at(directory,"login.journal"))return {};
    return parse_login_journal(read_file(directory,"login.journal",1024,true));
}

std::string activation_nonce(){
    std::string nonce(NSUUID.UUID.UUIDString.UTF8String);
    nonce.erase(std::remove(nonce.begin(),nonce.end(),'-'),nonce.end());
    for(char& c:nonce)if(c>='A' && c<='F')c=static_cast<char>(c-'A'+'a');
    return nonce;
}
void save_login_journal(int directory,const LoginJournal& journal){
    write_protected(directory,"login.journal",serialize_login_journal(journal),exists_at(directory,"login.journal"));
}
void close_program_login_gate(int directory){
    if(!exists_at(directory,"login.journal"))return;
    auto journal=load_journal(directory);journal.phase=LoginPhase::restoring;save_login_journal(directory,journal);
}
LoginJournal prepare_program_login(int directory,std::string_view configuration_hash){
    auto journal=load_journal(directory);
    const auto nonce=activation_nonce();if(nonce==journal.nonce)fail();
    journal.phase=LoginPhase::starting;journal.nonce=nonce;journal.configuration_hash=configuration_hash;
    save_login_journal(directory,journal);return journal;
}

bool program_start_allowed(); // Defined beside the program storage boundary.

std::optional<ServiceRuntime> load_runtime(int directory) {
    if(!exists_at(directory,"service.runtime"))return std::nullopt;
    return parse_service_runtime(read_file(directory,"service.runtime",1024,true));
}
void save_runtime(int directory,const ServiceRuntime& record) {
    validate_runtime_transition(load_runtime(directory),record);
    write_protected(directory,"service.runtime",serialize_service_runtime(record),exists_at(directory,"service.runtime"));
}
std::optional<std::uint64_t> process_start(unsigned pid) {
    if(!pid || pid>2147483647)return std::nullopt;
    proc_bsdinfo information{};
    if(proc_pidinfo(static_cast<int>(pid),PROC_PIDTBSDINFO,0,&information,static_cast<int>(sizeof(information)))!=static_cast<int>(sizeof(information)))return std::nullopt;
    if(information.pbi_start_tvusec>=1000000 ||
       information.pbi_start_tvsec>(std::numeric_limits<std::uint64_t>::max()-information.pbi_start_tvusec)/1000000)return std::nullopt;
    return information.pbi_start_tvsec*1000000+information.pbi_start_tvusec;
}
bool process_gone(unsigned pid,std::uint64_t started) {
    if(!pid)return true;
    if(const auto current=process_start(pid))return started && *current!=started;
    return kill(static_cast<pid_t>(pid),0)<0 && errno==ESRCH;
}

// Caller already owns owner.lock; never reacquire it from an updater hook.
class NativeRuntimeStop final:public RuntimeStopBackend {
public:
    NativeRuntimeStop(int directory,std::string configuration_hash)
        :directory_(directory),configuration_hash_(std::move(configuration_hash)),pid_(static_cast<unsigned>(job_pid(false))),started_(process_start(pid_).value_or(0)){}
    bool contract_verified() override {
        if(!product_code_ready())return false;
        const auto existing=record();
        if(!existing && exists_at(directory_,"service.receipt"))return false;
        if(pid_ && !macos::process_gone(pid_,started_))return started_ && service_process_code_ready(pid_);
        if(existing && !process_gone(*existing)){
            pid_=existing->pid;started_=existing->process_start_us;return service_process_code_ready(pid_);
        }
        return !runtime_busy(directory_);
    }
    bool original_process_gone() override{return macos::process_gone(pid_,started_);}
    std::optional<ServiceRuntime> record() override {
        auto value=load_runtime(directory_);
        if(value && value->configuration_hash!=configuration_hash_)fail();
        return value;
    }
    bool unregister_service() override {
        return native_service().status==SMAppServiceStatusNotRegistered ||
            [native_service() unregisterAndReturnError:nullptr];
    }
    bool await_stopped() override{return wait_stopped(false,static_cast<pid_t>(pid_),directory_,started_);}
    bool process_gone(const ServiceRuntime& runtime) override{return macos::process_gone(runtime.pid,runtime.process_start_us);}
    bool job_gone() override{return job_pid(false)==0;}
    bool lease_free() override{return !runtime_busy(directory_);}
private:
    int directory_;std::string configuration_hash_;unsigned pid_{};std::uint64_t started_{};
};

bool valid_receipt(int directory,const LoginJournal& record){
    if(!exists_at(directory,"service.receipt"))return false;
    const auto runtime=load_runtime(directory);
    if(!runtime || runtime->phase!=RuntimePhase::pending || runtime->configuration_hash!=record.configuration_hash)return false;
    const auto receipt=read_file(directory,"service.receipt",512,true);
    if(receipt!=serialize_service_ready(*runtime,record.nonce))return false;
    const auto pid=static_cast<pid_t>(runtime->pid);
    const auto actual_start=process_start(runtime->pid);
    return pid>0 && actual_start && *actual_start==runtime->process_start_us && runtime_busy(directory) && job_pid(false)==pid;
}

class NativeLoginBackend final:public LoginBackend {
public:
    NativeLoginBackend():directory_(product_directory(false)),operation_(owner(directory_.get())),
        configuration_(parse_configuration(read_file(directory_.get(),"service.conf",maximum_configuration_bytes,true),local_home())),
        record_(load_journal(directory_.get())){}
    bool preflight() override {
        if(!product_code_ready() || !program_start_allowed())return false;
        if(launch_control(@[@"print",[NSString stringWithFormat:@"gui/%u",getuid()]]).exit_code!=0)return false;
        return record_.phase==LoginPhase::none || record_.configuration_hash==configuration_hash();
    }
    bool activation_ready() override {
        if(!preflight())return false;
        const auto permissions=rwn::platform::macos::MacosDesktopPermissionBackend{}.status();
        if(permissions.capture!=rwn::desktop::PermissionState::granted ||
           (configuration_.control=="interactive" && permissions.input!=rwn::desktop::PermissionState::granted))return false;
        try {
            (void)read_absolute(configuration_.ca_path,65536);(void)read_absolute(configuration_.ocsp_path,65536);
            rwn::platform::macos::verify_local_tls_identity(identity_bytes(configuration_),false);
            return true;
        }catch(const std::exception&){return false;}
    }
    LoginPhase phase() override{return record_.phase;}
    bool prepare() override {
        const auto home=local_home();const auto path=home+"/Library/LaunchAgents/com.lanpilot.desktop-tls.plist";
        struct stat state{};const bool present=lstat(path.c_str(),&state)==0;
        if(!present && errno!=ENOENT)fail();
        std::string backup;
        if(present){
            if(legacy_configuration()!=configuration_)fail();
            backup=read_absolute(path,65536);
        }else if(loaded_legacy_service())fail(); // No verifiable rollback source.
        if(record_.phase==LoginPhase::authorizing){
            if(present!=record_.legacy_present || (present && rwn::core::sha256_hex(backup)!=record_.legacy_hash))fail();
            return true;
        }
        if(present)write_protected(directory_.get(),"legacy-service.plist",backup,exists_at(directory_.get(),"legacy-service.plist"));
        record_={LoginPhase::none,activation_nonce(),configuration_hash(),present?rwn::core::sha256_hex(backup):"-",present,loaded_legacy_service()};
        return true;
    }
    bool persist(LoginPhase phase) override {
        auto updated=record_;updated.phase=phase;
        write_protected(directory_.get(),"login.journal",serialize_login_journal(updated),exists_at(directory_.get(),"login.journal"));
        record_=std::move(updated);return true;
    }
    LoginRegistration registration() override {
        switch(native_service().status){
            case SMAppServiceStatusEnabled:return LoginRegistration::enabled;
            case SMAppServiceStatusRequiresApproval:return LoginRegistration::approval_required;
            default:return LoginRegistration::absent;
        }
    }
    bool register_canonical() override{return [native_service() registerAndReturnError:nullptr];}
    bool stop_canonical() override {
        NativeRuntimeStop backend(directory_.get(),configuration_hash());
        return quiesce_runtime(backend);
    }
    bool stop_legacy() override {
        const auto pid=job_pid(true);
        if(loaded_legacy_service() && launch_control(@[@"bootout",job_target(true)]).exit_code!=0)return false;
        return wait_stopped(true,pid,directory_.get());
    }
    bool retire_legacy() override {
        if(!record_.legacy_present)return true;
        auto agents=absolute_directory(local_home()+"/Library/LaunchAgents");
        if(rwn::core::sha256_hex(read_file(agents.get(),"com.lanpilot.desktop-tls.plist",65536,false))!=record_.legacy_hash)fail();
        if(unlinkat(agents.get(),"com.lanpilot.desktop-tls.plist",0)!=0 || fsync(agents.get())!=0)fail();
        return true;
    }
    bool restore_legacy() override {
        if(runtime_busy(directory_.get()) || job_pid(false)>0)return false;
        if(!record_.legacy_present)return true;
        const auto bytes=read_file(directory_.get(),"legacy-service.plist",65536,true);
        if(rwn::core::sha256_hex(bytes)!=record_.legacy_hash)fail();
        auto agents=absolute_directory(local_home()+"/Library/LaunchAgents");
        if(exists_at(agents.get(),"com.lanpilot.desktop-tls.plist")){
            if(read_file(agents.get(),"com.lanpilot.desktop-tls.plist",65536,false)!=bytes)fail();
        }else write_protected(agents.get(),"com.lanpilot.desktop-tls.plist",bytes,false);
        if(!record_.legacy_running || loaded_legacy_service())return true;
        auto* file=[NSString stringWithUTF8String:(local_home()+"/Library/LaunchAgents/com.lanpilot.desktop-tls.plist").c_str()];
        if(launch_control(@[@"bootstrap",[NSString stringWithFormat:@"gui/%u",getuid()],file]).exit_code!=0)return false;
        return loaded_legacy_service();
    }
    bool receipt_valid() override{return valid_receipt(directory_.get(),record_);}
    bool await_receipt() override {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(6);
        do {if(receipt_valid())return true;usleep(20000);}while(std::chrono::steady_clock::now()<deadline);
        return false;
    }
private:
    std::string configuration_hash()const{return rwn::core::sha256_hex(serialize_configuration(configuration_,local_home()));}
    Descriptor directory_,operation_;ServiceConfiguration configuration_;LoginJournal record_;
};

// This adapter has NO owner() member. install/recover own the operation lease
// for its entire lifetime and pass the already-open protected directory.
class NativeProgramLogin final:public ProgramLoginBackend {
public:
    explicit NativeProgramLogin(int directory):directory_(directory){}
    bool context_valid() override {
        if(!publisher_policy_configured())return false;
        if(exists_at(directory_,"service.conf")){
            const auto configuration=parse_configuration(read_file(directory_,"service.conf",maximum_configuration_bytes,true),local_home());
            configuration_hash_=core::sha256_hex(serialize_configuration(configuration,local_home()));
        }else configuration_hash_.clear();
        const auto journal=load_journal(directory_);
        if(journal.phase!=LoginPhase::none && (configuration_hash_.empty() || journal.configuration_hash!=configuration_hash_))return false;
        // An unfinished owner migration has a different recovery coordinator.
        if(journal.phase==LoginPhase::authorizing || journal.phase==LoginPhase::prepared ||
           journal.phase==LoginPhase::retired || journal.phase==LoginPhase::rollback_failed)return false;
        if(registration()!=LoginRegistration::absent && journal.phase==LoginPhase::none)return false;
        if(legacy_service_present() && (registration()!=LoginRegistration::absent || job_pid(false)>0))return false;
        return true;
    }
    LoginRegistration registration() override {
        switch(native_service().status){
            case SMAppServiceStatusEnabled:return LoginRegistration::enabled;
            case SMAppServiceStatusRequiresApproval:return LoginRegistration::approval_required;
            default:return LoginRegistration::absent;
        }
    }
    bool close_startup_gate() override {
        close_program_login_gate(directory_);return true;
    }
    bool stop_verified_instance() override {
        previous_=load_runtime(directory_);
        // An initial program placement may coexist with the untouched legacy
        // service, but never with an untracked canonical owner.
        if(!product_code_ready())return !previous_ && !exists_at(directory_,"service.receipt") &&
            registration()==LoginRegistration::absent && job_pid(false)==0 && !runtime_busy(directory_);
        if(configuration_hash_.empty())return !previous_ && !exists_at(directory_,"service.receipt") &&
            registration()==LoginRegistration::absent && job_pid(false)==0 && !runtime_busy(directory_);
        NativeRuntimeStop backend(directory_,configuration_hash_);
        return quiesce_runtime(backend);
    }
    bool probe_installed_code() override {
        if(!product_code_ready())return false;
        auto* executable=[NSString stringWithUTF8String:(local_home()+"/Applications/LanPilot.app/Contents/MacOS/LanPilot").c_str()];
        const auto result=bounded_product_command(executable,@[@"--check-application"]);
        if(result.exit_code!=0 || result.output.empty())return false;
        auto* data=[NSData dataWithBytes:result.output.data() length:result.output.size()];
        id object=[NSJSONSerialization JSONObjectWithData:data options:0 error:nullptr];
        if(![object isKindOfClass:NSDictionary.class])return false;
        NSDictionary* status=object;
        for(NSString* key in @[@"canonical_bundle",@"publisher_policy_configured",@"publisher_code_verified"]){
            if(status[key]!=(__bridge id)kCFBooleanTrue)return false;
        }
        return status[@"listener_started"]==(__bridge id)kCFBooleanFalse && status[@"clipboard_accessed"]==(__bridge id)kCFBooleanFalse &&
            [status[@"consent_requests"] isKindOfClass:NSNumber.class] && [status[@"consent_requests"] unsignedIntegerValue]==0;
    }
    bool start_fresh_instance() override {
        if(configuration_hash_.empty() || legacy_service_present() || registration()!=LoginRegistration::absent ||
           job_pid(false)>0 || runtime_busy(directory_))return false;
        const auto before=load_runtime(directory_);
        if(before && (!safe_input_exit(*before) || !macos::process_gone(before->pid,before->process_start_us)))return false;
        previous_=before;
        starting_=prepare_program_login(directory_,configuration_hash_);
        return [native_service() registerAndReturnError:nullptr] && registration()==LoginRegistration::enabled;
    }
    bool await_fresh_receipt() override {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(6);
        do {
            const auto runtime=load_runtime(directory_);
            if(runtime && fresh_service_ready(*runtime,previous_,configuration_hash_) && valid_receipt(directory_,starting_) &&
               service_process_code_ready(runtime->pid)){
                auto active=starting_;active.phase=LoginPhase::active;save_login_journal(directory_,active);return true;
            }
            usleep(20000);
        }while(std::chrono::steady_clock::now()<deadline);
        return false;
    }
    bool keep_disabled() override {
        if(registration()!=LoginRegistration::absent || job_pid(false)>0 || runtime_busy(directory_))return false;
        if(const auto runtime=load_runtime(directory_);runtime &&
           (!safe_input_exit(*runtime) || !macos::process_gone(runtime->pid,runtime->process_start_us)))return false;
        if(exists_at(directory_,"login.journal")){
            auto journal=load_journal(directory_);journal.phase=LoginPhase::restored;save_login_journal(directory_,journal);
        }
        return true;
    }
private:
    int directory_;std::string configuration_hash_;std::optional<ServiceRuntime> previous_;LoginJournal starting_;
};
} // namespace

bool legacy_service_present(){
    const auto path=local_home()+"/Library/LaunchAgents/com.lanpilot.desktop-tls.plist";
    struct stat state{};
    if(lstat(path.c_str(),&state)==0)return true; // Even an invalid link blocks a second owner.
    if(errno!=ENOENT)fail();return loaded_legacy_service();
}

ConfigurationInspection inspect_configuration(){
    ConfigurationInspection result;result.legacy_owner=legacy_service_present();
    try {
        auto directory=product_directory(false);
        if(!exists_at(directory.get(),"service.conf")){
            result.description="No saved product settings. Import the existing connection locally.";return result;
        }
        const auto configuration=parse_configuration(read_file(directory.get(),"service.conf",maximum_configuration_bytes,true),local_home());
        result.requires_input=configuration.control=="interactive";
        result.configured=true;
        result.description=result.legacy_owner?"Settings saved. The existing service still owns connections.":"Settings saved. Login service activation is separate.";
    } catch(const std::exception&){
        // Missing configuration is distinct from malformed/unsafe metadata.
        const auto path=local_home()+"/Library/Application Support/LanPilot";
        struct stat state{};
        if(lstat(path.c_str(),&state)<0 && errno==ENOENT)
            result.description="No saved product settings. Import the existing connection locally.";
        else result.description="Saved settings are unavailable or unsafe; no service was started.";
    }
    return result;
}

bool import_legacy_configuration(){
    const auto configuration=legacy_configuration();
    auto directory=product_directory(true);return save_new(directory.get(),configuration,local_home());
}
void prepare_enrollment_directory(){(void)product_directory(true);}

bool check_legacy_configuration(){
    const auto configuration=legacy_configuration();
    return parse_configuration(serialize_configuration(configuration,local_home()),local_home())==configuration;
}

int run_configured_service(){
    if(!product_code_ready())return 78;
    auto directory=product_directory(false);auto lease=owner(directory.get(),"runtime.lock");
    const auto configuration=parse_configuration(read_file(directory.get(),"service.conf",maximum_configuration_bytes,true),local_home());
    const auto previous=load_runtime(directory.get());
    // Never erase evidence from an input-owning crash/failed release. New input
    // cannot be created until the previous instance is known safe and stopped.
    if(previous && !safe_input_exit(*previous))return 78;
    if(!previous && exists_at(directory.get(),"service.receipt"))return 78;
    std::string instance(NSUUID.UUID.UUIDString.UTF8String);
    instance.erase(std::remove(instance.begin(),instance.end(),'-'),instance.end());
    for(char& c:instance)if(c>='A' && c<='F')c=static_cast<char>(c-'A'+'a');
    ServiceRuntime runtime{instance,rwn::core::sha256_hex(serialize_configuration(configuration,local_home())),
        static_cast<unsigned>(getpid())};
    runtime.process_start_us=process_start(runtime.pid).value_or(0);
    save_runtime(directory.get(),runtime); // Durable no-input preflight gate.
    if(legacy_service_present() || !program_start_allowed())return 78;
    const auto journal=load_journal(directory.get());
    if((journal.phase!=LoginPhase::starting && journal.phase!=LoginPhase::active) ||
       journal.configuration_hash!=rwn::core::sha256_hex(serialize_configuration(configuration,local_home())))return 78;
    (void)read_absolute(configuration.ca_path,65536);(void)read_absolute(configuration.ocsp_path,65536);
    const auto permissions=rwn::platform::macos::MacosDesktopPermissionBackend{}.status();
    if(permissions.capture!=rwn::desktop::PermissionState::granted ||
       (configuration.control=="interactive" && permissions.input!=rwn::desktop::PermissionState::granted))return 78;
    const bool native_identity=rwn::platform::macos::is_enrollment_identity_reference(identity_bytes(configuration));
    if(!native_identity)rwn::platform::macos::verify_local_tls_identity(identity_bytes(configuration),false);
    // A background service must fail rather than display Keychain prompts.
    if(SecKeychainSetUserInteractionAllowed(false)!=errSecSuccess)return 78;
    {
        // One startup-only proof from the actual service/responsible process.
        // Pixels never leave memory or enter the readiness receipt. Ordinary
        // sessions still use the existing capture/encode/transport pipeline.
        rwn::platform::macos::MacosScreenCaptureBackend capture(1920,1080,60);
        if(!capture.capture(std::chrono::seconds(2)))return 78;
    }
    core::Sha256Digest native_peer{};const auto fingerprint=rwn::transport::parse_apple_network_sha256_fingerprint(configuration.peer_sha256);
    for(std::size_t i=0;i<native_peer.size();++i)native_peer[i]=static_cast<std::byte>(fingerprint[i]);
    const auto root_text=read_absolute(configuration.ca_path,65536);const auto root_bytes=std::as_bytes(std::span{root_text});
    auto native_status=NativeStatusService::create(configuration.bind_address,configuration.port,identity_bytes(configuration),native_peer,{root_bytes.begin(),root_bytes.end()});
    auto active_configuration=configuration;
    auto credential_hex=[](std::span<const std::byte> bytes){std::string text;for(auto b:bytes){const auto n=std::to_integer<unsigned>(b);text+="0123456789abcdef"[n>>4];text+="0123456789abcdef"[n&15];}return text;};
    if(native_status){
        const auto selected=native_status->server_identity();rwn::platform::macos::verify_local_tls_identity(selected,false);
        active_configuration.identity_reference=credential_hex(selected);active_configuration.peer_sha256=credential_hex(native_status->client_fingerprint());
    }
    auto arguments=agent_arguments(active_configuration,local_home());std::vector<char*> argv;
    for(auto& argument:arguments)argv.push_back(argument.data());argv.push_back(nullptr);
    RunAudit audit([&] {
        write_protected(directory.get(),"service.receipt",serialize_service_ready(runtime,journal.nonce),
            exists_at(directory.get(),"service.receipt"));
    });
    runtime.phase=RuntimePhase::pending;
    save_runtime(directory.get(),runtime); // Must precede delegation to agent.
    std::function<std::vector<std::byte>()> provider;
    if(native_status){const std::weak_ptr<NativeStatusService> weak=native_status;
        provider=[weak]{auto owner=weak.lock();if(!owner)throw std::runtime_error("renewal service stopped");return owner->client_ocsp();};}
    const auto selected_root=native_status?native_status->root():std::vector<std::byte>{};
    const auto rollover=native_status?native_status->rollover_token():core::CancellationToken{};
    const auto result=rwn::agent::run(static_cast<int>(arguments.size()),argv.data(),provider,selected_root,rollover);
    // run() has returned, so its workers and TLS session have been destroyed.
    // The runtime lease remains held until this completion is durable.
    runtime=finish_service_runtime(runtime,audit.finish(),result);
    save_runtime(directory.get(),runtime);
    return result;
}

LoginResult activate_login_service(){
    if(!product_code_ready())return LoginResult::not_ready;
    NativeLoginBackend backend;return activate_login_owner(backend);
}
LoginResult recover_login_service(){
    if(!product_code_ready())return LoginResult::not_ready;
    NativeLoginBackend backend;return recover_login_owner(backend);
}
void authorize_configuration_identity(){
    if(!product_code_ready())fail();
    auto directory=product_directory(false);auto lease=owner(directory.get());
    auto runtime=owner(directory.get(),"runtime.lock");
    const auto configuration=parse_configuration(read_file(directory.get(),"service.conf",maximum_configuration_bytes,true),local_home());
    rwn::platform::macos::verify_local_tls_identity(identity_bytes(configuration),true);
}
std::string login_service_description(){
    if(!publisher_policy_configured())return "Production publisher is not configured. The existing service is unchanged.";
    if(!product_code_ready())return "An installed app signed by the expected publisher is required.";
    auto directory=product_directory(false);const auto record=load_journal(directory.get());
    if(record.phase==LoginPhase::active && valid_receipt(directory.get(),record))
        return "Login service running; local capture and identity checked. Remote connection is not verified.";
    if(record.phase==LoginPhase::authorizing)return "Background approval is pending. The existing service still owns connections.";
    if(record.phase==LoginPhase::rollback_failed)return "Recovery needs attention. A second service was not started.";
    return "Login service is not verified as running. Enable or recover it locally.";
}
bool configured_service_verified(){
    if(!product_code_ready())return false;
    try{auto directory=product_directory(false);const auto record=load_journal(directory.get());return record.phase==LoginPhase::active && valid_receipt(directory.get(),record);}catch(...){return false;}
}

int check_login_service_bundle(){
    const char* path=NSBundle.mainBundle.bundlePath.UTF8String;if(!path)fail();
    const auto bytes=read_absolute(std::string(path)+"/Contents/Library/LaunchAgents/com.lanpilot.desktop.service.plist",4096);
    auto* data=[NSData dataWithBytes:bytes.data() length:bytes.size()];
    id plist=[NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nullptr error:nullptr];
    NSDictionary* expected=@{@"Label":@"com.lanpilot.desktop.service",@"BundleProgram":@"Contents/MacOS/LanPilot",
        @"ProgramArguments":@[@"LanPilot",@"--run-configured-service"],@"LimitLoadToSessionType":@"Aqua",
        @"RunAtLoad":@YES,@"KeepAlive":@YES,@"ThrottleInterval":@10,@"Umask":@63,
        @"StandardOutPath":@"/dev/null",@"StandardErrorPath":@"/dev/null"};
    const bool valid=[plist isKindOfClass:NSDictionary.class] && [plist isEqualToDictionary:expected];
    // Read-only observation also checks the native launchctl PID parser against
    // this account, without logging arguments, identity references or keys.
    const bool legacy_pid=job_pid(true)>0;
    std::printf("service_bundle=%s legacy_pid_observed=%d registration_operations=0 listener_started=0\n",valid?"PASS":"FAIL",legacy_pid?1:0);
    return valid?0:1;
}

int configuration_store_fixture(){
    // Only an isolated owner-created directory. Never imports the live plist,
    // inspects Keychain, starts launchd, requests consent or opens a listener.
    const auto pattern=std::string(NSTemporaryDirectory().UTF8String)+"lanpilot-config-XXXXXX";
    std::vector<char> name(pattern.begin(),pattern.end());name.push_back('\0');
    if(!mkdtemp(name.data()))return 1;
    Descriptor directory(open(name.data(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    bool passed=false;unsigned step=0;int failure_errno=0;
    try {
        step=1;
        validate_object(directory.get(),true,true);
        const std::string home="/Users/fixture";
        const ServiceConfiguration c{"127.0.0.1",45443,"00aa",std::string(64,'a'),
            home+"/.local/share/lanpilot/identity-v1/root.der",home+"/.local/share/lanpilot/identity-v1/client-ocsp.der"};
        step=2;if(!save_new(directory.get(),c,home))fail();
        step=3;if(save_new(directory.get(),c,home))fail();
        step=4;
        const auto before=read_file(directory.get(),"service.conf",maximum_configuration_bytes,true);
        auto changed=c;changed.port=45444;
        bool conflict=false;try{save_new(directory.get(),changed,home);}catch(const std::exception&){conflict=true;}
        if(!conflict || before!=read_file(directory.get(),"service.conf",maximum_configuration_bytes,true))fail();
        step=5;
        {
            auto lease=owner(directory.get());bool denied=false;
            try{auto duplicate=owner(directory.get());}catch(const std::exception&){denied=true;}
            if(!denied)fail();
        }
        auto released=owner(directory.get());
        step=6;
        if(symlinkat("service.conf",directory.get(),"linked.conf")!=0)fail();
        bool link_denied=false;
        try{read_file(directory.get(),"linked.conf",maximum_configuration_bytes,true);}catch(const std::exception&){link_denied=true;}
        if(!link_denied)fail();
        step=7;
        if(linkat(directory.get(),"service.conf",directory.get(),"hardlink.conf",0)!=0)fail();
        bool hardlink_denied=false;
        try{read_file(directory.get(),"service.conf",maximum_configuration_bytes,true);}catch(const std::exception&){hardlink_denied=true;}
        if(!hardlink_denied)fail();
        step=8;
        unlinkat(directory.get(),"hardlink.conf",0);
        if(fchmodat(directory.get(),"service.conf",0644,0)!=0)fail();
        bool mode_denied=false;
        try{read_file(directory.get(),"service.conf",maximum_configuration_bytes,true);}catch(const std::exception&){mode_denied=true;}
        if(!mode_denied)fail();
        step=9;
        if(fchmodat(directory.get(),"service.conf",0600,0)!=0)fail();
        Descriptor acl_file(openat(directory.get(),"service.conf",O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
        uuid_t uuid{};if(mbr_uid_to_uuid(getuid(),uuid)!=0)fail();
        acl_t acl=acl_init(1);if(!acl)fail();
        acl_entry_t entry{};acl_permset_t permissions{};
        const bool acl_ready=acl_create_entry(&acl,&entry)==0 && acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0 &&
            acl_set_qualifier(entry,uuid)==0 && acl_get_permset(entry,&permissions)==0 &&
            acl_add_perm(permissions,ACL_WRITE_DATA)==0 && acl_set_fd_np(acl_file.get(),acl,ACL_TYPE_EXTENDED)==0;
        acl_free(acl);if(!acl_ready)fail();
        bool acl_denied=false;
        try{read_file(directory.get(),"service.conf",maximum_configuration_bytes,true);}catch(const std::exception&){acl_denied=true;}
        if(!acl_denied)fail();
        step=10;
        const LoginJournal record{LoginPhase::starting,std::string(32,'a'),std::string(64,'b'),"-",false,false};
        write_protected(directory.get(),"login.journal",serialize_login_journal(record),false);
        auto journal=load_journal(directory.get());if(journal.phase!=LoginPhase::starting)fail();
        journal.phase=LoginPhase::active;
        write_protected(directory.get(),"login.journal",serialize_login_journal(journal),true);
        if(load_journal(directory.get()).phase!=LoginPhase::active)fail();
        write_protected(directory.get(),"login.journal","schema=1\nphase=active\n",true);
        bool truncated_denied=false;
        try{(void)load_journal(directory.get());}catch(const std::exception&){truncated_denied=true;}
        if(!truncated_denied)fail();
        step=11;
        write_protected(directory.get(),"service.receipt","nonce="+std::string(32,'c')+
            "\npid=1\nconfiguration_hash="+record.configuration_hash+"\ncapture_verified=true\nidentity_checked=true\n",false);
        if(valid_receipt(directory.get(),record))fail();
        write_protected(directory.get(),"service.receipt","nonce="+record.nonce+
            "\npid=0\nconfiguration_hash="+record.configuration_hash+"\ncapture_verified=true\nidentity_checked=true\n",true);
        if(valid_receipt(directory.get(),record))fail();
        step=12;
        journal.phase=LoginPhase::prepared;
        write_protected(directory.get(),"login.journal",serialize_login_journal(journal),true);
        released=Descriptor{};
        {auto runtime_file=owner(directory.get(),"runtime.lock");}
        int signals[2]{};if(pipe(signals)!=0)fail();
        Descriptor read_end(signals[0]),write_end(signals[1]);
        const pid_t child=fork();if(child<0)fail();
        if(child==0){
            // Only raw descriptor/syscall operations after fork; no Foundation,
            // Objective-C, allocation, capture, Keychain or service APIs.
            close(signals[0]);
            const int held=openat(directory.get(),"owner.lock",O_RDWR|O_NOFOLLOW);
            if(held<0 || flock(held,LOCK_EX|LOCK_NB)!=0)_exit(2);
            const int runtime=openat(directory.get(),"runtime.lock",O_RDWR|O_NOFOLLOW);
            if(runtime<0 || flock(runtime,LOCK_EX|LOCK_NB)!=0)_exit(4);
            const char ready='R';if(write(signals[1],&ready,1)!=1)_exit(3);
            for(;;)pause();
        }
        struct ChildOwner {
            pid_t pid;
            ~ChildOwner(){
                if(pid>0){
                    pid_t state;
                    do{state=waitpid(pid,nullptr,WNOHANG);}while(state<0 && errno==EINTR);
                    if(state==0){kill(pid,SIGKILL);while(waitpid(pid,nullptr,0)<0 && errno==EINTR){}}
                }
            }
        } child_owner{child};
        write_end=Descriptor{};
        pollfd notification{read_end.get(),POLLIN,0};
        if(poll(&notification,1,1000)!=1)fail();
        char ready{};if(read(read_end.get(),&ready,1)!=1 || ready!='R')fail();
        bool process_denied=false;
        try{auto contender=owner(directory.get());}catch(const std::exception&){process_denied=errno==EWOULDBLOCK;}
        if(!process_denied || !runtime_busy(directory.get()))fail();
        ServiceRuntime pending{std::string(32,'d'),record.configuration_hash,static_cast<unsigned>(child)};
        pending.process_start_us=process_start(pending.pid).value_or(0);
        save_runtime(directory.get(),pending);
        pending.phase=RuntimePhase::pending;save_runtime(directory.get(),pending);
        if(kill(child,SIGKILL)!=0)fail();
        int child_status{};
        while(waitpid(child,&child_status,0)<0){if(errno!=EINTR){child_owner.pid=-1;fail();}}
        child_owner.pid=-1;
        if(!WIFSIGNALED(child_status) || WTERMSIG(child_status)!=SIGKILL)fail();
        auto recovered_owner=owner(directory.get());
        if(load_journal(directory.get()).phase!=LoginPhase::prepared)fail();
        if(runtime_busy(directory.get()) || !load_runtime(directory.get()) ||
           runtime_stop_proven(pending,*load_runtime(directory.get()),true,true,true))fail();
        const auto self_start=process_start(static_cast<unsigned>(getpid()));
        if(!self_start || process_gone(static_cast<unsigned>(getpid()),*self_start) ||
           !process_gone(static_cast<unsigned>(getpid()),*self_start+1) ||
           !process_gone(pending.pid,pending.process_start_us))fail();
        step=13;
        const auto failed=finish_service_runtime(pending,{InputExit::unknown,0,0},1);
        save_runtime(directory.get(),failed);
        auto forbidden=failed;forbidden.instance[0]='e';forbidden.phase=RuntimePhase::preflight;
        const auto failed_bytes=read_file(directory.get(),"service.runtime",1024,true);
        bool restart_denied=false;
        try{save_runtime(directory.get(),forbidden);}catch(const std::exception&){restart_denied=true;}
        if(!restart_denied || read_file(directory.get(),"service.runtime",1024,true)!=failed_bytes)fail();
        step=14;
        if(fchmodat(directory.get(),"service.runtime",0644,0)!=0)fail();
        bool runtime_mode_denied=false;
        try{(void)load_runtime(directory.get());}catch(const std::exception&){runtime_mode_denied=true;}
        if(!runtime_mode_denied || fchmodat(directory.get(),"service.runtime",0600,0)!=0)fail();
        write_protected(directory.get(),"service.runtime","schema=1\nphase=stopped_released\n",true);
        bool runtime_corruption_denied=false;
        try{(void)load_runtime(directory.get());}catch(const std::exception&){runtime_corruption_denied=true;}
        if(!runtime_corruption_denied)fail();
        step=15;
        save_login_journal(directory.get(),record);
        close_program_login_gate(directory.get());
        auto closed=load_journal(directory.get());
        if(closed.phase!=LoginPhase::restoring || closed.nonce!=record.nonce ||
           closed.configuration_hash!=record.configuration_hash)fail();
        const auto fresh=prepare_program_login(directory.get(),record.configuration_hash);
        if(fresh.phase!=LoginPhase::starting || fresh.nonce==record.nonce || fresh.configuration_hash!=record.configuration_hash ||
           fresh.legacy_hash!=record.legacy_hash || fresh.legacy_present!=record.legacy_present ||
           fresh.legacy_running!=record.legacy_running || load_journal(directory.get()).nonce!=fresh.nonce)fail();
        bool still_owned=false;try{auto duplicate=owner(directory.get());}catch(const std::exception&){still_owned=true;}
        if(!still_owned)fail();
        passed=true;
    } catch(const std::exception&){failure_errno=errno;}
    for(auto file:{"linked.conf","hardlink.conf","service.conf","owner.lock","runtime.lock","login.journal","service.receipt","service.runtime"})unlinkat(directory.get(),file,0);
    const bool cleaned=rmdir(name.data())==0;
    std::printf("configuration_store=%s step=%u errno=%d cleaned=%d isolated=1 native_consent_requests=0 listener_started=0 keychain_accessed=0\n",passed&&cleaned?"PASS":"FAIL",step,failure_errno,cleaned?1:0);
    return passed&&cleaned?0:1;
}
} // namespace rwn::agent::macos

// One translation unit shares the descriptor/ACL/atomic-write boundary without
// exposing raw directory authority as a public application API.
#include "program_store.inc"
