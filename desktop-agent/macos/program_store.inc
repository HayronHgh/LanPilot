// Private implementation, included exactly once by configuration_store.mm.
#include <dirent.h>
#include <array>
#include <set>
#include <sstream>
#include <sys/xattr.h>

namespace rwn::agent::macos {
namespace {
constexpr std::uint64_t program_file_cap=256ULL*1024*1024,program_total_cap=512ULL*1024*1024;
constexpr std::size_t program_inventory_cap=4U*1024U*1024U;
struct ProgramNode {
    std::string path;bool directory{};std::uint64_t bytes{};std::string digest;
    bool operator==(const ProgramNode&)const=default;
};
using ProgramTree=std::vector<ProgramNode>;
bool universal_layout(int file){
    struct stat state{};if(fstat(file,&state)!=0 || state.st_size<72)return false;
    std::array<unsigned char,72> table{};if(pread(file,table.data(),table.size(),0)!=static_cast<ssize_t>(table.size()))return false;
    auto big=[&](std::size_t offset){return (std::uint32_t(table[offset])<<24)|(std::uint32_t(table[offset+1])<<16)|
        (std::uint32_t(table[offset+2])<<8)|std::uint32_t(table[offset+3]);};
    const bool wide=big(0)==0xcafebabfU;
    if((!wide && big(0)!=0xcafebabeU) || big(4)!=2)return false;
    const std::size_t entry=wide?32:20;bool arm=false,intel=false;
    std::array<std::pair<std::uint64_t,std::uint64_t>,2> ranges{};
    for(std::size_t i=0;i<2;++i){
        const auto base=8+i*entry;
        const auto cpu=big(base);
        if(cpu==0x0100000cU && !arm)arm=true;
        else if(cpu==0x01000007U && !intel)intel=true;
        else return false;
        const auto offset=wide?(std::uint64_t(big(base+8))<<32)|big(base+12):big(base+8);
        const auto size=wide?(std::uint64_t(big(base+16))<<32)|big(base+20):big(base+12);
        if(offset<8+2*entry || size<32 || offset>static_cast<std::uint64_t>(state.st_size) ||
           size>static_cast<std::uint64_t>(state.st_size)-offset)return false;
        ranges[i]={offset,offset+size};
        std::array<unsigned char,32> header{};
        if(pread(file,header.data(),header.size(),static_cast<off_t>(offset))!=static_cast<ssize_t>(header.size()) ||
           header[0]!=0xcf || header[1]!=0xfa || header[2]!=0xed || header[3]!=0xfe)return false;
        const auto slice_cpu=std::uint32_t(header[4])|(std::uint32_t(header[5])<<8)|
            (std::uint32_t(header[6])<<16)|(std::uint32_t(header[7])<<24);
        if(slice_cpu!=cpu)return false;
    }
    return arm && intel && (ranges[0].second<=ranges[1].first || ranges[1].second<=ranges[0].first);
}
bool universal_bundle(int root){
    auto contents=directory_at(root,"Contents",false,false);auto binaries=directory_at(contents.get(),"MacOS",false,false);
    Descriptor executable(openat(binaries.get(),"LanPilot",O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    validate_object(executable.get(),false,false,true);return universal_layout(executable.get());
}
void copy_program_xattrs(int source,int destination,std::uint64_t& package_total){
    const auto size=flistxattr(source,nullptr,0,0);if(size<0 || size>4096)fail();
    std::vector<char> names(static_cast<std::size_t>(size));
    if(size>0 && flistxattr(source,names.data(),names.size(),0)!=size)fail();
    std::size_t offset=0,total=0;unsigned count=0;
    while(offset<names.size()){
        const auto end=std::find(names.begin()+static_cast<std::ptrdiff_t>(offset),names.end(),'\0');
        if(end==names.end() || ++count>32)fail();
        const char* name=names.data()+offset;
        if(std::string_view(name)=="com.apple.system.Security")fail(); // Never copy ACL authority as an xattr.
        const auto length=fgetxattr(source,name,nullptr,0,0,0);
        if(length<0 || length>65536 || total+static_cast<std::size_t>(length)>1048576 ||
           package_total>program_total_cap-static_cast<std::uint64_t>(length))fail();
        std::vector<std::byte> bytes(static_cast<std::size_t>(length));
        if(fgetxattr(source,name,bytes.data(),bytes.size(),0,0)!=length ||
           fsetxattr(destination,name,bytes.data(),bytes.size(),0,0)!=0)fail();
        total+=bytes.size();package_total+=bytes.size();offset=static_cast<std::size_t>(end-names.begin())+1;
    }
}
bool assessed_program(const std::filesystem::path& path){
    auto* value=[NSString stringWithUTF8String:path.c_str()];if(!value)return false;
    return bounded_product_command(@"/usr/sbin/spctl",@[@"--assess",@"--type",@"execute",@"--ignore-cache",@"--no-cache",value]).exit_code==0;
}

bool program_path(std::string_view path,bool directory){
    if(path.empty() || path.size()>1024 || path.front()=='/' || path.back()=='/')return false;
    for(char c:path)if(!((c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') ||
        c=='/' || c=='_' || c=='-' || c=='.' || c==' '))return false;
    std::size_t begin=0;
    while(begin<path.size()){
        const auto end=path.find('/',begin),size=end==std::string_view::npos?path.size()-begin:end-begin;
        if(size==0 || path[begin]=='.')return false;
        begin=end==std::string_view::npos?path.size():end+1;
    }
    if(directory)return path=="Contents" || path=="Contents/MacOS" || path=="Contents/Library" ||
        path=="Contents/Library/LaunchAgents" || path=="Contents/_CodeSignature" ||
        path=="Contents/Resources" || path.starts_with("Contents/Resources/");
    if(path=="Contents/Info.plist" || path=="Contents/PkgInfo" || path=="Contents/MacOS/LanPilot" ||
       path=="Contents/Library/LaunchAgents/com.lanpilot.desktop.service.plist" || path=="Contents/_CodeSignature/CodeResources")return true;
    if(!path.starts_with("Contents/Resources/"))return false;
    for(auto suffix:{".pem",".key",".p12",".pfx",".env"})if(path.ends_with(suffix))return false;
    return true;
}

std::vector<std::string> directory_names(int directory){
    DIR* stream=fdopendir(openat(directory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC));if(!stream)fail();
    std::vector<std::string> result;
    try {
        errno=0;
        while(auto* entry=readdir(stream)){
            const std::string name(entry->d_name);if(name=="." || name=="..")continue;
            if(result.size()>=4096)fail();result.push_back(name);errno=0;
        }
        if(errno!=0)fail();
    }catch(...){closedir(stream);throw;}
    closedir(stream);std::sort(result.begin(),result.end());return result;
}

void scan_program(int source,int destination,std::string prefix,ProgramTree& tree,std::uint64_t& total,const ProgramTree* expected=nullptr){
    for(const auto& name:directory_names(source)){
        if(tree.size()>=4096)fail();
        const auto path=prefix.empty()?name:prefix+"/"+name;
        struct stat state{};if(fstatat(source,name.c_str(),&state,AT_SYMLINK_NOFOLLOW)!=0)fail();
        const bool directory=S_ISDIR(state.st_mode);
        if(!program_path(path,directory) || (!directory && !S_ISREG(state.st_mode)) || (state.st_mode&07022)!=0)fail();
        const ProgramNode* expected_node=nullptr;
        if(expected){
            const auto found=std::lower_bound(expected->begin(),expected->end(),path,[](const auto& node,const auto& key){return node.path<key;});
            if(found==expected->end() || found->path!=path || found->directory!=directory)fail();
            expected_node=&*found;
        }
        if(directory){
            auto child=directory_at(source,name.c_str(),false,false);
            tree.push_back({path,true,0,{}});
            Descriptor copy;
            if(destination>=0)copy=directory_at(destination,name.c_str(),true,false);
            scan_program(child.get(),copy.get(),path,tree,total,expected);
            if(copy.get()>=0)copy_program_xattrs(child.get(),copy.get(),total);
            if(copy.get()>=0 && (fchmod(copy.get(),0755)!=0 || fsync(copy.get())!=0))fail();
            continue;
        }
        Descriptor input(openat(source,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
        validate_object(input.get(),false,false,true);
        struct stat opened{};
        if(fstat(input.get(),&opened)!=0 || opened.st_dev!=state.st_dev || opened.st_ino!=state.st_ino ||
           opened.st_size<0 || static_cast<std::uint64_t>(opened.st_size)>program_file_cap)fail();
        const auto size=static_cast<std::uint64_t>(opened.st_size);
        if(expected_node && expected_node->bytes!=size)fail();
        if(total>program_total_cap-size)fail();total+=size;
        Descriptor output;
        if(destination>=0){
            output=Descriptor(openat(destination,name.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
            validate_object(output.get(),false,true);
        }
        core::Sha256Accumulator accumulator;std::array<std::byte,65536> buffer{};std::uint64_t received=0;
        for(;;){
            const auto count=read(input.get(),buffer.data(),buffer.size());
            if(count<0 && errno==EINTR)continue;
            if(count<0)fail();if(count==0)break;
            const auto amount=static_cast<std::size_t>(count);received+=amount;if(received>size)fail();
            accumulator.update(std::span(buffer).first(amount));
            if(output.get()>=0){
                std::size_t offset=0;
                while(offset<amount){const auto written=write(output.get(),buffer.data()+offset,amount-offset);
                    if(written<0 && errno==EINTR)continue;
                    if(written<=0)fail();offset+=static_cast<std::size_t>(written);}
            }
        }
        struct stat after{};
        if(received!=size || fstat(input.get(),&after)!=0 || after.st_size!=opened.st_size ||
           after.st_mtimespec.tv_sec!=opened.st_mtimespec.tv_sec || after.st_mtimespec.tv_nsec!=opened.st_mtimespec.tv_nsec)fail();
        const auto digest=accumulator.finish();std::string hex;constexpr char alphabet[]="0123456789abcdef";
        for(auto byte:digest){const auto value=std::to_integer<unsigned>(byte);hex+=alphabet[value>>4];hex+=alphabet[value&15];}
        tree.push_back({path,false,size,hex});
        if(expected_node && expected_node->digest!=hex)fail();
        if(output.get()>=0)copy_program_xattrs(input.get(),output.get(),total);
        if(output.get()>=0 && (fchmod(output.get(),path=="Contents/MacOS/LanPilot"?0755:0644)!=0 || fsync(output.get())!=0))fail();
    }
}
ProgramTree program_tree(int directory){
    ProgramTree tree;std::uint64_t total=0;scan_program(directory,-1,{},tree,total);
    std::sort(tree.begin(),tree.end(),[](const auto& a,const auto& b){return a.path<b.path;});return tree;
}
std::string inventory_text(const ProgramTree& tree){
    std::string result="LanPilotBundle1\n";
    for(const auto& node:tree){
        if(!program_path(node.path,node.directory))fail();
        result+=(node.directory?"D\t":"F\t")+node.path;
        if(!node.directory)result+="\t"+std::to_string(node.bytes)+"\t"+node.digest;
        result+='\n';if(result.size()>program_inventory_cap)fail();
    }
    return result;
}
ProgramTree parse_inventory(std::string_view text){
    if(text.size()>program_inventory_cap || !text.starts_with("LanPilotBundle1\n") || text.back()!='\n')fail();
    text.remove_prefix(std::string_view("LanPilotBundle1\n").size());ProgramTree tree;std::uint64_t total=0;
    while(!text.empty()){
        const auto end=text.find('\n');const auto line=text.substr(0,end);text.remove_prefix(end+1);
        const auto first=line.find('\t');if(first!=1 || tree.size()>=4096)fail();
        const bool directory=line[0]=='D';if(!directory && line[0]!='F')fail();
        const auto second=line.find('\t',2),third=second==std::string_view::npos?second:line.find('\t',second+1);
        ProgramNode node{std::string(line.substr(2,second==std::string_view::npos?second:second-2)),directory,0,{}};
        if(!program_path(node.path,directory) || (!tree.empty() && tree.back().path>=node.path))fail();
        if(directory){if(second!=std::string_view::npos)fail();}
        else {
            if(second==std::string_view::npos || third==std::string_view::npos)fail();
            node.bytes=canonical_unsigned(line.substr(second+1,third-second-1),static_cast<unsigned>(program_file_cap));
            node.digest=line.substr(third+1);if(!lowercase_hex(node.digest,64,64) || total>program_total_cap-node.bytes)fail();total+=node.bytes;
        }
        tree.push_back(std::move(node));
    }
    for(auto required:{"Contents/Info.plist","Contents/MacOS/LanPilot","Contents/Library/LaunchAgents/com.lanpilot.desktop.service.plist"}){
        const auto found=std::find_if(tree.begin(),tree.end(),[&](const auto& node){return node.path==required && !node.directory && node.bytes>0;});
        if(found==tree.end())fail();
    }
    return tree;
}
std::string slot_digest(int parent,const char* name){
    if(!exists_at(parent,name))return "-";
    auto root=directory_at(parent,name,false,false);return core::sha256_hex(inventory_text(program_tree(root.get())));
}
core::SemanticVersion slot_version(int parent,const char* name){
    auto root=directory_at(parent,name,false,false);auto contents=directory_at(root.get(),"Contents",false,false);
    const auto bytes=read_file(contents.get(),"Info.plist",65536,false,true);
    id plist=[NSPropertyListSerialization propertyListWithData:[NSData dataWithBytes:bytes.data() length:bytes.size()]
        options:NSPropertyListImmutable format:nullptr error:nullptr];
    if(![plist isKindOfClass:NSDictionary.class] || ![plist[@"CFBundleIdentifier"] isEqual:@"com.lanpilot.desktop"] ||
       ![plist[@"CFBundleVersion"] isKindOfClass:NSString.class])fail();
    return core::parse_semantic_version([plist[@"CFBundleVersion"] UTF8String]);
}
void exchange_slots(int apps,int maintenance,bool previous){
    struct stat left{},right{};if(fstat(apps,&left)!=0 || fstat(maintenance,&right)!=0 || left.st_dev!=right.st_dev)fail();
    const auto flags=static_cast<unsigned>(previous?RENAME_SWAP:RENAME_EXCL);
    if(renameatx_np(maintenance,"candidate.app",apps,"LanPilot.app",flags)!=0 || fsync(apps)!=0 || fsync(maintenance)!=0)fail();
}
void erase_candidate(int maintenance,std::string_view expected,std::string_view manifest,bool partial=false){
    if(core::sha256_hex(manifest)!=expected)fail();
    const auto full=parse_inventory(manifest);
    if(!exists_at(maintenance,"candidate.app"))return;
    auto root=directory_at(maintenance,"candidate.app",false,false);const auto remaining=program_tree(root.get());
    for(const auto& node:remaining){
        const auto found=std::lower_bound(full.begin(),full.end(),node.path,[](const auto& n,const auto& path){return n.path<path;});
        if(found==full.end() || found->path!=node.path || found->directory!=node.directory ||
           (partial?node.bytes>found->bytes:*found!=node))fail();
    }
    for(auto item=remaining.rbegin();item!=remaining.rend();++item){
        Descriptor parent(dup(root.get()));std::size_t start=0;
        for(auto slash=item->path.find('/');slash!=std::string::npos;slash=item->path.find('/',start)){
            parent=directory_at(parent.get(),item->path.substr(start,slash-start).c_str(),false,false);start=slash+1;
        }
        if(unlinkat(parent.get(),item->path.substr(start).c_str(),item->directory?AT_REMOVEDIR:0)!=0)fail();
    }
    if(unlinkat(maintenance,"candidate.app",AT_REMOVEDIR)!=0 || fsync(maintenance)!=0)fail();
}

// Read-only startup fence. The login journal alone must not reopen a service
// while a program transaction is staging/swapping an incompatible generation.
bool program_start_allowed(){
    auto apps=absolute_directory(local_home()+"/Applications");
    if(!exists_at(apps.get(),".LanPilot"))return true;
    auto maintenance=directory_at(apps.get(),".LanPilot",false,true);
    if(!exists_at(maintenance.get(),"program.journal"))return true;
    const auto record=parse_program_journal(read_file(maintenance.get(),"program.journal",1024,true));
    const auto actual=slot_digest(apps.get(),"LanPilot.app");
    const auto version=slot_version(apps.get(),"LanPilot.app");
    return program_runtime_generation_allowed(record,actual,version) &&
        publisher_bundle_ready(local_home()+"/Applications/LanPilot.app",core::to_string(version));
}

class NativeProgramBackend final:public ProgramBackend {
public:
    NativeProgramBackend(int apps,int maintenance,const core::VerifiedUpdate* update,std::filesystem::path source,
        ProgramServiceHooks& hooks,bool fixture=false,int lifecycle=-1):apps_(apps),maintenance_(maintenance),lifecycle_(lifecycle<0?maintenance:lifecycle),update_(update),source_(std::move(source)),hooks_(hooks),fixture_(fixture){
        struct stat left{},right{};if(fstat(apps_,&left)!=0 || fstat(maintenance_,&right)!=0 || left.st_dev!=right.st_dev)fail();
        if(exists_at(maintenance_,"program.journal"))record_=parse_program_journal(read_file(maintenance_,"program.journal",1024,true));
    }
    ProgramPhase phase()override{return record_.phase;}
    bool recovery_ready()override{
        if(!fixture_ && !publisher_policy_configured())return false;
        const auto active=slot_digest(apps_,"LanPilot.app");
        return record_.phase==ProgramPhase::none ||
            (active==record_.target_digest && trusted_slot("LanPilot.app",false,record_.target_version)) ||
            (active==record_.previous_digest && record_.had_previous && trusted_slot("LanPilot.app",false,record_.previous_version)) ||
            (!record_.had_previous && active=="-");
    }
    bool stage_verified()override{
        if(!update_)return false;
        try {
            const auto& manifest=update_->manifest();
            if(manifest.platform!="macos-app-inventory" || manifest.architecture!="universal2" || manifest.package_size>program_inventory_cap)fail();
            const auto inventory=read_absolute(update_->package_path().string(),program_inventory_cap,true);
            if(inventory.size()!=manifest.package_size || core::sha256_hex(inventory)!=manifest.package_sha256)fail();
            const auto expected=parse_inventory(inventory);
            auto source=absolute_directory(source_.string());
            if(slot_version(source.get(),".")!=manifest.version || inventory_text(program_tree(source.get()))!=inventory ||
               (!fixture_ && (!universal_bundle(source.get()) || !publisher_bundle_ready(source_,core::to_string(manifest.version)) || !assessed_program(source_))))fail();
            const auto current=slot_digest(apps_,"LanPilot.app");
            const bool installed=current!="-";
            const auto version=installed?slot_version(apps_,"LanPilot.app"):core::SemanticVersion{};
            if(installed && manifest.version==version && current==manifest.package_sha256){same_=true;return true;}
            if(manifest.version<=version || (installed && !trusted_slot("LanPilot.app",false,version)))fail();
            const auto retained=slot_digest(maintenance_,"previous.app");
            if(retained!="-" && (!installed || slot_version(maintenance_,"previous.app")>=version ||
                !trusted_slot("previous.app",true,slot_version(maintenance_,"previous.app"))))fail();
            if(exists_at(maintenance_,"candidate.app"))fail();
            record_={ProgramPhase::staging,manifest.package_sha256,current,manifest.version,version,installed,retained,installed&&hooks_.initially_enabled(),false};
            write_large_inventory("target.inventory",inventory);
            if(!persist(ProgramPhase::staging))fail();
            auto destination=directory_at(maintenance_,"candidate.app",true,false);
            ProgramTree copied;std::uint64_t total=0;scan_program(source.get(),destination.get(),{},copied,total,&expected);
            copy_program_xattrs(source.get(),destination.get(),total);
            if(fsync(destination.get())!=0 || slot_digest(maintenance_,"candidate.app")!=record_.target_digest ||
               !trusted_slot("candidate.app",true,record_.target_version))fail();
            return true;
        }catch(const std::exception&){return false;}
    }
    bool unchanged()override{return same_;}
    bool prepare()override{record_.candidate_verified=true;return persist(ProgramPhase::prepared);}
    bool persist(ProgramPhase phase)override{
        auto record=record_;record.phase=phase;
        write_protected(maintenance_,"program.journal",serialize_program_journal(record),exists_at(maintenance_,"program.journal"));
        record_=std::move(record);return true;
    }
    bool quiesce()override{return hooks_.quiesce() && !runtime_busy(lifecycle_);}
    bool exchange()override{
        if(slot_digest(apps_,"LanPilot.app")!=record_.previous_digest || slot_digest(maintenance_,"candidate.app")!=record_.target_digest)fail();
        exchange_slots(apps_,maintenance_,record_.had_previous);return true;
    }
    bool healthy()override{
        return slot_digest(apps_,"LanPilot.app")==record_.target_digest && trusted_slot("LanPilot.app",false,record_.target_version) &&
            hooks_.accept_candidate(record_.service_enabled);
    }
    bool restore_slots()override{
        const auto active=slot_digest(apps_,"LanPilot.app");
        if(active==record_.previous_digest)return !record_.had_previous || trusted_slot("LanPilot.app",false,record_.previous_version);
        if(active!=record_.target_digest)fail();
        if(record_.had_previous){
            if(slot_digest(maintenance_,"candidate.app")!=record_.previous_digest || !trusted_slot("candidate.app",true,record_.previous_version))fail();
            exchange_slots(apps_,maintenance_,true);
        }else if(renameatx_np(apps_,"LanPilot.app",maintenance_,"candidate.app",RENAME_EXCL)!=0 || fsync(apps_)!=0 || fsync(maintenance_)!=0)fail();
        return slot_digest(apps_,"LanPilot.app")==record_.previous_digest;
    }
    bool resume_previous()override{return hooks_.resume_previous(record_.had_previous,record_.service_enabled);}
    bool finish_commit()override{
        if(slot_digest(apps_,"LanPilot.app")!=record_.target_digest || !trusted_slot("LanPilot.app",false,record_.target_version))fail();
        if(!record_.had_previous)return !exists_at(maintenance_,"candidate.app");
        const auto previous=slot_digest(maintenance_,"previous.app");
        if(previous!=record_.previous_digest){
            if(slot_digest(maintenance_,"candidate.app")!=record_.previous_digest || previous!=record_.retained_digest)fail();
            const int moved=previous=="-"?renameatx_np(maintenance_,"candidate.app",maintenance_,"previous.app",RENAME_EXCL):
                renameatx_np(maintenance_,"candidate.app",maintenance_,"previous.app",RENAME_SWAP);
            if(moved!=0 || fsync(maintenance_)!=0)fail();
        }
        if(record_.retained_digest!="-" && exists_at(maintenance_,"candidate.app")){
            if(!exists_at(maintenance_,"gc.inventory")){
                auto retired=directory_at(maintenance_,"candidate.app",false,false);
                const auto inventory=inventory_text(program_tree(retired.get()));
                if(core::sha256_hex(inventory)!=record_.retained_digest)fail();write_large_inventory("gc.inventory",inventory);
            }
            erase_candidate(maintenance_,record_.retained_digest,read_file(maintenance_,"gc.inventory",program_inventory_cap,true));
        }
        if(exists_at(maintenance_,"gc.inventory") && (unlinkat(maintenance_,"gc.inventory",0)!=0 || fsync(maintenance_)!=0))fail();
        return true;
    }
    bool finish_rollback()override{
        if(slot_digest(apps_,"LanPilot.app")!=record_.previous_digest)fail();
        erase_candidate(maintenance_,record_.target_digest,read_file(maintenance_,"target.inventory",program_inventory_cap,true),!record_.candidate_verified);return true;
    }
private:
    bool trusted_slot(const char* name,bool maintenance,core::SemanticVersion version){
        if(fixture_)return true;
        const auto root=local_home()+"/Applications/"+(maintenance?".LanPilot/":"");
        return publisher_bundle_ready(root+name,core::to_string(version)) && assessed_program(root+name);
    }
    void write_large_inventory(const char* name,std::string_view bytes){
        if(bytes.empty() || bytes.size()>program_inventory_cap)fail();
        // Inventory may be larger than the small lifecycle journal limit.
        const std::string temporary=".inventory-"+std::string(NSUUID.UUID.UUIDString.UTF8String);
        Descriptor file(openat(maintenance_,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        try {
            validate_object(file.get(),false,true);std::size_t offset=0;
            while(offset<bytes.size()){
                const auto count=write(file.get(),bytes.data()+offset,bytes.size()-offset);
                if(count<0 && errno==EINTR)continue;
                if(count<=0)fail();offset+=static_cast<std::size_t>(count);
            }
            if(exists_at(maintenance_,name))(void)read_file(maintenance_,name,program_inventory_cap,true);
            if(fsync(file.get())!=0 || renameat(maintenance_,temporary.c_str(),maintenance_,name)!=0 || fsync(maintenance_)!=0)fail();
        }catch(...){unlinkat(maintenance_,temporary.c_str(),0);throw;}
    }
    int apps_,maintenance_,lifecycle_;const core::VerifiedUpdate* update_;std::filesystem::path source_;
    ProgramServiceHooks& hooks_;bool fixture_,same_{};ProgramJournal record_;
};

class IncomingProgramUpdate {
public:
    IncomingProgramUpdate():IncomingProgramUpdate(product_directory(true),local_home()+"/Library/Application Support/LanPilot"){}
    // Internal native fixture can supply only its own private temporary root.
    IncomingProgramUpdate(Descriptor data,std::filesystem::path root):data_(std::move(data)),root_(std::move(root)),
        lease_(owner(data_.get(),"update-verification.lock")),incoming_(directory_at(data_.get(),"update-incoming",true,true)){clear();}
    ~IncomingProgramUpdate(){try{clear();}catch(const std::exception&){}}
    void copy(const char* name,std::string_view bytes){
        const std::string_view file_name(name);
        if(file_name!="release.toml" && file_name!="bundle.inventory")fail();
        const std::size_t cap=file_name=="release.toml"?65536:program_inventory_cap;
        if(bytes.empty() || bytes.size()>cap)fail();
        Descriptor file(openat(incoming_.get(),name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        validate_object(file.get(),false,true);std::size_t offset=0;
        while(offset<bytes.size()){
            const auto count=write(file.get(),bytes.data()+offset,bytes.size()-offset);
            if(count<0 && errno==EINTR)continue;
            if(count<=0)fail();offset+=static_cast<std::size_t>(count);
        }
        if(fsync(file.get())!=0 || fsync(incoming_.get())!=0)fail();
    }
    std::filesystem::path path(const char* name)const{return root_/"update-incoming"/name;}
private:
    void clear(){
        const int enumeration=openat(incoming_.get(),".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(enumeration<0)fail();
        DIR* entries=fdopendir(enumeration);if(!entries){close(enumeration);fail();}
        std::vector<std::string> files;bool valid=true;
        errno=0;
        while(auto* item=readdir(entries)){
            const std::string name(item->d_name);if(name=="." || name=="..")continue;
            if((name!="release.toml" && name!="bundle.inventory") || files.size()>=2){valid=false;break;}
            files.push_back(name);
        }
        const int read_error=errno;
        if(closedir(entries)!=0 || read_error!=0 || !valid)fail();
        // Validate the whole fixed set before deleting anything. An empty or
        // truncated scratch file after a crash is safe to discard, unlike a
        // lifecycle journal or an active/retained application.
        for(const auto& name:files){
            Descriptor file(openat(incoming_.get(),name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
            validate_object(file.get(),false,true);struct stat state{};
            const auto cap=name=="release.toml"?65536:program_inventory_cap;
            if(fstat(file.get(),&state)!=0 || state.st_size<0 || static_cast<std::uint64_t>(state.st_size)>cap)fail();
        }
        for(const auto& name:files)if(unlinkat(incoming_.get(),name.c_str(),0)!=0)fail();
        if(fsync(incoming_.get())!=0)fail();
    }
    Descriptor data_;std::filesystem::path root_;Descriptor lease_,incoming_;
};

#ifndef LANPILOT_RELEASE_PUBLIC_KEY_XY
#define LANPILOT_RELEASE_PUBLIC_KEY_XY ""
#endif
template<class Action> auto verified_program_package(const std::filesystem::path& package,Action action){
    if(!program_update_policy_ready() || !product_code_ready())fail();
    if(!package.is_absolute() || package.lexically_normal()!=package)fail();
    auto source=absolute_directory(package.string());
    // Copy each bounded input ONCE; the verifier/parser never rereads mutable
    // selected metadata or accepts a package-provided verifier, key or policy.
    const auto manifest_text=read_file(source.get(),"release.toml",65536,false,true);
    const auto inventory=read_file(source.get(),"bundle.inventory",program_inventory_cap,false,true);
    IncomingProgramUpdate incoming;
    incoming.copy("release.toml",manifest_text);
    incoming.copy("bundle.inventory",inventory);
    const auto manifest=core::load_update_manifest(incoming.path("release.toml"));
    auto apps=absolute_directory(local_home()+"/Applications");
    const auto installed=slot_version(apps.get(),"LanPilot.app");
    const core::ReleaseCompatibilityPolicy policy{manifest.version,{0,0,0},{65535,65535,65535},1,1,1,1,1};
    const platform::macos::SecurityEcdsaP256UpdateVerifier verifier(release_public_key(LANPILOT_RELEASE_PUBLIC_KEY_XY));
    const auto verified=core::verify_update_candidate(manifest,installed,policy,"macos-app-inventory","universal2",incoming.path("bundle.inventory"),verifier);
    const ProgramOffer offer{manifest.version,program_offer_token(manifest)};
    return action(verified,package/"LanPilot.app",offer);
}
} // namespace

ProgramResult install_verified_program(const core::VerifiedUpdate& update,const std::filesystem::path& source){
    const char* executable_bundle=NSBundle.mainBundle.bundlePath.UTF8String;
    if(!executable_bundle || !publisher_bundle_ready(executable_bundle))return ProgramResult::rejected;
    auto data=product_directory(true);auto operation=owner(data.get());
    NativeProgramLogin service(data.get());ProgramLoginHooks hooks(service);
    auto home=absolute_directory(local_home());auto apps=directory_at(home.get(),"Applications",true,false);
    auto maintenance=directory_at(apps.get(),".LanPilot",true,true);
    NativeProgramBackend backend(apps.get(),maintenance.get(),&update,source,hooks,false,data.get());return apply_program(backend);
}
ProgramResult recover_program_install(){
    const char* executable_bundle=NSBundle.mainBundle.bundlePath.UTF8String;
    if(!executable_bundle || !publisher_bundle_ready(executable_bundle))return ProgramResult::recovery_required;
    auto data=product_directory(true);auto operation=owner(data.get());
    auto apps=absolute_directory(local_home()+"/Applications");
    if(!exists_at(apps.get(),".LanPilot"))return ProgramResult::unchanged;
    auto maintenance=directory_at(apps.get(),".LanPilot",false,true);
    NativeProgramLogin service(data.get());ProgramLoginHooks hooks(service);
    NativeProgramBackend backend(apps.get(),maintenance.get(),nullptr,{},hooks,false,data.get());return recover_program(backend);
}

bool program_update_policy_ready(){
    try{return publisher_policy_configured() && release_public_key(LANPILOT_RELEASE_PUBLIC_KEY_XY).size()==64;}
    catch(const std::exception&){return false;}
}
ProgramOffer inspect_program_update(const std::filesystem::path& package){
    return verified_program_package(package,[](const auto&,const auto&,const ProgramOffer& offer){return offer;});
}
ProgramResult apply_program_update(const std::filesystem::path& package,std::string_view confirmed){
    if(!lowercase_hex(confirmed,64,64))return ProgramResult::rejected;
    return verified_program_package(package,[&](const core::VerifiedUpdate& update,const auto& bundle,const ProgramOffer& offer){
        if(offer.confirmation!=confirmed)return ProgramResult::rejected;
        return install_verified_program(update,bundle);
    });
}

int release_verifier_fixture(){
    try {
        const auto key=release_public_key("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
        const auto signature=release_public_key("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
        const platform::macos::SecurityEcdsaP256UpdateVerifier verifier(key);
        const std::string sample="sample",changed="sample!";
        auto invalid=signature;invalid.front()^=std::byte{1};
        if(!verifier.verify(std::as_bytes(std::span{sample}),signature) ||
           verifier.verify(std::as_bytes(std::span{changed}),signature) ||
           verifier.verify(std::as_bytes(std::span{sample}),invalid))fail();
        if(apply_program_update("relative","unconfirmed")!=ProgramResult::rejected)fail();
        std::printf("release_verifier=PASS native_security=1 vector=RFC6979 fixture_only=1 keys_created=0 keychain_accessed=0 install_operations=0\n");
        return 0;
    }catch(const std::exception&){return 1;}
}

int write_program_inventory(const std::filesystem::path& output){
    const char* bundle=NSBundle.mainBundle.bundlePath.UTF8String;if(!bundle)fail();
    const std::filesystem::path source(bundle);
    if(!output.is_absolute() || output.lexically_normal()!=output || !canonical_path(output.string()) ||
       output==source || output.string().starts_with(source.string()+"/"))fail();
    auto root=absolute_directory(source.string());const auto inventory=inventory_text(program_tree(root.get()));
    (void)parse_inventory(inventory);
    auto parent=absolute_directory(output.parent_path().string());
    // Compare physical ancestors as well: case-insensitive aliases must not
    // turn a nominally external output into a write inside the signed bundle.
    struct stat source_identity{};if(fstat(root.get(),&source_identity)!=0)fail();
    Descriptor ancestor(dup(parent.get()));bool reached_root=false;
    for(unsigned depth=0;depth<128;++depth){
        struct stat current{},above{};if(fstat(ancestor.get(),&current)!=0)fail();
        if(current.st_dev==source_identity.st_dev && current.st_ino==source_identity.st_ino)fail();
        Descriptor next(openat(ancestor.get(),"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(next.get()<0 || fstat(next.get(),&above)!=0)fail();
        if(current.st_dev==above.st_dev && current.st_ino==above.st_ino){reached_root=true;break;}
        ancestor=std::move(next);
    }
    if(!reached_root)fail();
    const auto filename=output.filename().string();if(exists_at(parent.get(),filename.c_str()))fail();
    const std::string temporary=".program-inventory-"+std::string(NSUUID.UUID.UUIDString.UTF8String);
    Descriptor file(openat(parent.get(),temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    try {
        validate_object(file.get(),false,true);std::size_t offset=0;
        while(offset<inventory.size()){
            const auto count=write(file.get(),inventory.data()+offset,inventory.size()-offset);
            if(count<0 && errno==EINTR)continue;
            if(count<=0)fail();offset+=static_cast<std::size_t>(count);
        }
        if(fsync(file.get())!=0 || renameatx_np(parent.get(),temporary.c_str(),parent.get(),filename.c_str(),RENAME_EXCL)!=0 || fsync(parent.get())!=0)fail();
    }catch(...){unlinkat(parent.get(),temporary.c_str(),0);throw;}
    std::printf("program_inventory=created bytes=%zu manifest_signed=0 listener_started=0\n",inventory.size());return 0;
}

int program_store_fixture(){
    const auto pattern=std::string(NSTemporaryDirectory().UTF8String)+"lanpilot-program-XXXXXX";
    std::vector<char> name(pattern.begin(),pattern.end());name.push_back('\0');
    if(!mkdtemp(name.data()))return 1;
    const auto path=std::filesystem::canonical(name.data());
    Descriptor root(open(path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    struct stat original{};if(fstat(root.get(),&original)!=0)return 1;
    bool passed=false;unsigned step=0;
    try {
        validate_object(root.get(),true,true);
        auto lease=owner(root.get());auto apps=directory_at(root.get(),"Applications",true,true);
        auto maintenance=directory_at(apps.get(),".LanPilot",true,true);
        write_protected(root.get(),"identity.fixture","opaque-state-preserved",false);
        struct Signatures final:core::UpdateSignatureVerifier{
            bool verify(std::span<const std::byte> payload,std::span<const std::byte> signature)const override{
                return !payload.empty() && signature.size()==64;
            }
        } fixture_signatures;
        struct Services final:ProgramServiceHooks{
            bool running{},healthy{true};unsigned stops{};
            bool quiesce()override{++stops;running=false;return true;}
            bool initially_enabled()override{return running;}
            bool accept_candidate(bool enabled)override{running=enabled&&healthy;return healthy;}
            bool resume_previous(bool previous,bool enabled)override{running=previous&&enabled;return true;}
        } services;
        auto prepare=[&](unsigned patch){
            const auto source_name="source"+std::to_string(patch)+".app";
            auto source=directory_at(root.get(),source_name.c_str(),true,true);
            auto contents=directory_at(source.get(),"Contents",true,false);
            auto binaries=directory_at(contents.get(),"MacOS",true,false);
            auto library=directory_at(contents.get(),"Library",true,false);
            auto jobs=directory_at(library.get(),"LaunchAgents",true,false);
            const auto version=core::to_string({1,0,static_cast<std::uint16_t>(patch)});
            const auto plist="<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.lanpilot.desktop</string><key>CFBundleVersion</key><string>"+version+
                "</string><key>CFBundleExecutable</key><string>LanPilot</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>";
            write_protected(contents.get(),"Info.plist",plist,false);
            write_protected(binaries.get(),"LanPilot","fixture-not-executed-"+version,false);
            if(fchmodat(binaries.get(),"LanPilot",0755,0)!=0)fail();
            write_protected(jobs.get(),"com.lanpilot.desktop.service.plist","fixture-job-not-registered",false);
            const char attribute[]="origin-preserved";
            if(fsetxattr(source.get(),"com.lanpilot.fixture",attribute,sizeof(attribute),0,0)!=0)fail();
            const auto inventory=inventory_text(program_tree(source.get()));
            write_protected(root.get(),"bundle.inventory",inventory,exists_at(root.get(),"bundle.inventory"));
            const core::UpdateManifest manifest{{1,0,static_cast<std::uint16_t>(patch)},{0,0,0},"macos-app-inventory","universal2",
                core::sha256_hex(inventory),inventory.size(),1,1,"ecdsa-p256-sha256",std::string(128,'1')};
            const core::ReleaseCompatibilityPolicy policy{manifest.version,{0,0,0},{65535,65535,65535},1,1,1,1,1};
            const auto installed=exists_at(apps.get(),"LanPilot.app")?slot_version(apps.get(),"LanPilot.app"):core::SemanticVersion{};
            return std::pair{core::verify_update_candidate(manifest,installed,policy,"macos-app-inventory","universal2",path/"bundle.inventory",fixture_signatures),path/source_name};
        };
        step=1;auto first=prepare(1);
        NativeProgramBackend install(apps.get(),maintenance.get(),&first.first,first.second,services,true);
        if(apply_program(install)!=ProgramResult::active || slot_version(apps.get(),"LanPilot.app")!=core::SemanticVersion{1,0,1})fail();
        const auto stops=services.stops;
        NativeProgramBackend repeat(apps.get(),maintenance.get(),&first.first,first.second,services,true);
        if(apply_program(repeat)!=ProgramResult::unchanged || services.stops!=stops)fail();
        step=2;
        auto installed=directory_at(apps.get(),"LanPilot.app",false,false);char attribute[32]{};
        if(fgetxattr(installed.get(),"com.lanpilot.fixture",attribute,sizeof(attribute),0,0)!=sizeof("origin-preserved") ||
            std::string_view(attribute)!="origin-preserved")fail();
        services.running=true;
        for(unsigned patch:{2U,3U}){
            auto candidate=prepare(patch);
            NativeProgramBackend upgrade(apps.get(),maintenance.get(),&candidate.first,candidate.second,services,true);
            if(apply_program(upgrade)!=ProgramResult::active || slot_version(apps.get(),"LanPilot.app")!=core::SemanticVersion{1,0,static_cast<std::uint16_t>(patch)} ||
               slot_version(maintenance.get(),"previous.app")!=core::SemanticVersion{1,0,static_cast<std::uint16_t>(patch-1)} ||
               exists_at(maintenance.get(),"candidate.app") || !services.running)fail();
        }
        step=3;auto broken=prepare(4);services.healthy=false;
        NativeProgramBackend failing(apps.get(),maintenance.get(),&broken.first,broken.second,services,true);
        if(apply_program(failing)!=ProgramResult::rolled_back || slot_version(apps.get(),"LanPilot.app")!=core::SemanticVersion{1,0,3} || !services.running)fail();
        step=4;services.healthy=true;auto interrupted=prepare(5);
        NativeProgramBackend pending(apps.get(),maintenance.get(),&interrupted.first,interrupted.second,services,true);
        if(!pending.stage_verified() || !pending.prepare() || !pending.quiesce() || !pending.exchange())fail();
        // Deliberately omit the activated journal write: the disk slots, not an
        // optimistic phase label, must determine safe recovery.
        NativeProgramBackend recovery(apps.get(),maintenance.get(),nullptr,{},services,true);
        if(recover_program(recovery)!=ProgramResult::rolled_back || slot_version(apps.get(),"LanPilot.app")!=core::SemanticVersion{1,0,3} || !services.running)fail();
        step=5;auto corrupt=prepare(6);
        auto source=absolute_directory(corrupt.second.string());auto contents=directory_at(source.get(),"Contents",false,false);
        auto binaries=directory_at(contents.get(),"MacOS",false,false);
        if(fchmodat(binaries.get(),"LanPilot",0600,0)!=0)fail();
        write_protected(binaries.get(),"LanPilot","changed-after-verification",true);
        const auto before=services.stops;
        NativeProgramBackend reject(apps.get(),maintenance.get(),&corrupt.first,corrupt.second,services,true);
        if(apply_program(reject)!=ProgramResult::rejected || services.stops!=before || !services.running)fail();
        step=6;auto committed=prepare(7);
        NativeProgramBackend retained(apps.get(),maintenance.get(),&committed.first,committed.second,services,true);
        if(!retained.stage_verified() || !retained.prepare() || !retained.quiesce() || !retained.exchange() ||
           !retained.persist(ProgramPhase::activated) || !retained.healthy() || !retained.persist(ProgramPhase::committed))fail();
        // Interrupt retention after the old rollback slot moved into the
        // candidate slot and one declared file was already removed.
        if(renameatx_np(maintenance.get(),"candidate.app",maintenance.get(),"previous.app",RENAME_SWAP)!=0 || fsync(maintenance.get())!=0)fail();
        auto garbage=directory_at(maintenance.get(),"candidate.app",false,false);
        write_protected(maintenance.get(),"gc.inventory",inventory_text(program_tree(garbage.get())),false);
        auto garbage_contents=directory_at(garbage.get(),"Contents",false,false);
        if(unlinkat(garbage_contents.get(),"Info.plist",0)!=0 || fsync(garbage_contents.get())!=0)fail();
        NativeProgramBackend finish_retention(apps.get(),maintenance.get(),nullptr,{},services,true);
        if(recover_program(finish_retention)!=ProgramResult::active || exists_at(maintenance.get(),"candidate.app") ||
           exists_at(maintenance.get(),"gc.inventory") || slot_version(maintenance.get(),"previous.app")!=core::SemanticVersion{1,0,3})fail();
        step=7;auto incomplete=prepare(8);
        NativeProgramBackend copying(apps.get(),maintenance.get(),&incomplete.first,incomplete.second,services,true);
        if(!copying.stage_verified())fail();
        auto partial_root=directory_at(maintenance.get(),"candidate.app",false,false);
        auto partial_contents=directory_at(partial_root.get(),"Contents",false,false);
        auto partial_binaries=directory_at(partial_contents.get(),"MacOS",false,false);
        Descriptor partial(openat(partial_binaries.get(),"LanPilot",O_WRONLY|O_NOFOLLOW|O_CLOEXEC));
        if(partial.get()<0 || ftruncate(partial.get(),3)!=0 || fsync(partial.get())!=0)fail();
        const auto stops_before=services.stops;
        NativeProgramBackend resume_copy(apps.get(),maintenance.get(),nullptr,{},services,true);
        if(recover_program(resume_copy)!=ProgramResult::rolled_back || services.stops!=stops_before || !services.running ||
           exists_at(maintenance.get(),"candidate.app") || slot_version(apps.get(),"LanPilot.app")!=core::SemanticVersion{1,0,7})fail();
        step=8;
        if(read_file(root.get(),"identity.fixture",100,true)!="opaque-state-preserved" ||
           slot_version(maintenance.get(),"previous.app")!=core::SemanticVersion{1,0,3})fail();
        step=9;
        std::string fat(128,'\0');
        const auto put_big=[&](std::size_t offset,std::uint32_t value){for(unsigned i=0;i<4;++i)fat[offset+i]=static_cast<char>(value>>(24-i*8));};
        put_big(0,0xcafebabeU);put_big(4,2);put_big(8,0x0100000cU);put_big(16,64);put_big(20,32);
        put_big(28,0x01000007U);put_big(36,96);put_big(40,32);
        for(std::size_t offset:{64U,96U}){fat[offset]=static_cast<char>(0xcf);fat[offset+1]=static_cast<char>(0xfa);
            fat[offset+2]=static_cast<char>(0xed);fat[offset+3]=static_cast<char>(0xfe);fat[offset+6]=0;fat[offset+7]=1;}
        fat[68]=12;fat[100]=7;
        write_protected(root.get(),"abi.fixture",fat,false);
        Descriptor abi(openat(root.get(),"abi.fixture",O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
        if(!universal_layout(abi.get()))fail();
        put_big(36,64);write_protected(root.get(),"abi.fixture",fat,true);
        Descriptor overlap(openat(root.get(),"abi.fixture",O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
        if(universal_layout(overlap.get()))fail();
        step=10;services.running=false;auto disabled_update=prepare(9);
        NativeProgramBackend disabled(apps.get(),maintenance.get(),&disabled_update.first,disabled_update.second,services,true);
        if(apply_program(disabled)!=ProgramResult::active || services.running ||
           slot_version(apps.get(),"LanPilot.app")!=core::SemanticVersion{1,0,9} ||
           slot_version(maintenance.get(),"previous.app")!=core::SemanticVersion{1,0,7} ||
           read_file(root.get(),"identity.fixture",100,true)!="opaque-state-preserved")fail();
        step=11;
        {
            IncomingProgramUpdate inputs(Descriptor(dup(root.get())),path);
            inputs.copy("release.toml","fixture");inputs.copy("bundle.inventory","inventory");
            bool locked=false;try{IncomingProgramUpdate duplicate(Descriptor(dup(root.get())),path);}catch(const std::exception&){locked=true;}
            if(!locked || !std::filesystem::exists(inputs.path("release.toml")))fail();
            bool oversized=false;try{inputs.copy("release.toml",std::string(65537,'a'));}catch(const std::exception&){oversized=true;}
            if(!oversized)fail();
        }
        auto scratch=directory_at(root.get(),"update-incoming",false,true);
        if(exists_at(scratch.get(),"release.toml") || exists_at(scratch.get(),"bundle.inventory"))fail();
        write_protected(scratch.get(),"unknown.fixture","must-be-preserved",false);
        bool unknown=false;try{IncomingProgramUpdate reject(Descriptor(dup(root.get())),path);}catch(const std::exception&){unknown=true;}
        if(!unknown || read_file(scratch.get(),"unknown.fixture",100,true)!="must-be-preserved" || unlinkat(scratch.get(),"unknown.fixture",0)!=0)fail();
        {Descriptor partial(openat(scratch.get(),"release.toml",O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600));if(partial.get()<0)fail();}
        {IncomingProgramUpdate recover(Descriptor(dup(root.get())),path);if(exists_at(scratch.get(),"release.toml"))fail();}
        if(symlinkat("../identity.fixture",scratch.get(),"bundle.inventory")!=0)fail();
        bool linked=false;try{IncomingProgramUpdate reject(Descriptor(dup(root.get())),path);}catch(const std::exception&){linked=true;}
        if(!linked || unlinkat(scratch.get(),"bundle.inventory",0)!=0 || read_file(root.get(),"identity.fixture",100,true)!="opaque-state-preserved")fail();
        passed=true;
    }catch(const std::exception&){}
    struct stat current{};bool cleaned=false;
    if(lstat(path.c_str(),&current)==0 && current.st_dev==original.st_dev && current.st_ino==original.st_ino && !S_ISLNK(current.st_mode)){
        std::error_code error;std::filesystem::remove_all(path,error);cleaned=!error;
    }
    std::printf("program_store=%s step=%u cleaned=%d signature_mode=fixture service_operations=0 pixels_read=0 keychain_accessed=0\n",passed&&cleaned?"PASS":"FAIL",step,cleaned?1:0);
    return passed&&cleaned?0:1;
}
} // namespace rwn::agent::macos
