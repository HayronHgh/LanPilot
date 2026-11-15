#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include "code_identity.hpp"
#include "rwn/core/release_compatibility.hpp"
#include <pwd.h>
#include <exception>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#ifndef LANPILOT_DEVELOPER_TEAM_ID
#define LANPILOT_DEVELOPER_TEAM_ID ""
#endif

namespace rwn::agent::macos {
namespace {
bool shutdown_contract(NSDictionary* secured) {
    id value=secured[@"LanPilotServiceProtocol"];
    if(!value || CFGetTypeID((__bridge CFTypeRef)value)!=CFNumberGetTypeID() ||
       CFNumberIsFloatType((__bridge CFNumberRef)value))return false;
    long long protocol{};
    return CFNumberGetValue((__bridge CFNumberRef)value,kCFNumberLongLongType,&protocol) && protocol==1;
}
NSString* publisher_requirement() {
    return [NSString stringWithFormat:
        @"anchor apple generic and identifier \"com.lanpilot.desktop\" and certificate leaf[subject.OU] = \"%s\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",LANPILOT_DEVELOPER_TEAM_ID];
}
}
bool publisher_policy_configured(){return std::string_view(LANPILOT_DEVELOPER_TEAM_ID).size()==10;}
bool publisher_bundle_ready(const std::filesystem::path& bundle_path,std::string_view expected_version){
    if(!publisher_policy_configured() || getuid()==0 || getuid()!=geteuid())return false;
    if(!bundle_path.is_absolute() || bundle_path.lexically_normal()!=bundle_path)return false;
    // Reject a redirected install/ancestor; no app or system permission changes.
    auto cursor=bundle_path.string();
    while(!cursor.empty()){
        struct stat state{};if(lstat(cursor.c_str(),&state)!=0 || !S_ISDIR(state.st_mode) ||
            (state.st_uid!=getuid() && state.st_uid!=0) || (state.st_mode&0022)!=0)return false;
        const auto slash=cursor.rfind('/');if(slash==0)break;cursor.resize(slash);
    }
    auto* requirementText=publisher_requirement();
    SecRequirementRef requirement=nullptr;SecStaticCodeRef code=nullptr;
    if(SecRequirementCreateWithString((__bridge CFStringRef)requirementText,kSecCSDefaultFlags,&requirement)!=errSecSuccess)return false;
    auto* name=[NSString stringWithUTF8String:bundle_path.c_str()];
    if(!name){CFRelease(requirement);return false;}
    auto* url=[NSURL fileURLWithPath:name isDirectory:YES];
    const auto created=SecStaticCodeCreateWithPath((__bridge CFURLRef)url,kSecCSDefaultFlags,&code);
    bool valid=created==errSecSuccess && SecStaticCodeCheckValidity(code,
        kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode,requirement)==errSecSuccess;
    if(valid){
        CFDictionaryRef information=nullptr;
        valid=SecCodeCopySigningInformation(code,kSecCSSigningInformation,&information)==errSecSuccess;
        if(valid){
            NSDictionary* secured=((__bridge NSDictionary*)information)[(__bridge NSString*)kSecCodeInfoPList];
            valid=[secured isKindOfClass:NSDictionary.class] && shutdown_contract(secured);
            id version=valid?secured[@"CFBundleVersion"]:nil;
            valid=valid && [version isKindOfClass:NSString.class] &&
                [secured[@"CFBundleIdentifier"] isEqual:@"com.lanpilot.desktop"] &&
                [secured[@"CFBundleExecutable"] isEqual:@"LanPilot"] && [secured[@"CFBundlePackageType"] isEqual:@"APPL"];
            if(valid){
                const char* value=[version UTF8String];
                try {
                    valid=value && core::to_string(core::parse_semantic_version(value))==value &&
                        (expected_version.empty() || expected_version==value);
                }catch(const std::exception&){valid=false;}
            }
            CFRelease(information);
        }
    }
    if(code)CFRelease(code);CFRelease(requirement);return valid;
}
bool product_code_ready(){
    const auto* account=getpwuid(getuid());if(!account || !account->pw_dir)return false;
    const std::string expected=std::string(account->pw_dir)+"/Applications/LanPilot.app";
    const char* actual=NSBundle.mainBundle.bundlePath.UTF8String;
    return actual && expected==actual && publisher_bundle_ready(expected);
}
bool service_process_code_ready(unsigned pid) {
    if(!product_code_ready() || pid==0 || pid>2147483647)return false;
    const auto* account=getpwuid(getuid());if(!account || !account->pw_dir)return false;
    const auto expected=std::string(account->pw_dir)+"/Applications/LanPilot.app/Contents/MacOS/LanPilot";
    NSDictionary* attributes=@{(__bridge NSString*)kSecGuestAttributePid:@(pid)};
    SecCodeRef code=nullptr;SecStaticCodeRef installed=nullptr;SecRequirementRef requirement=nullptr;
    CFDictionaryRef information=nullptr,installed_information=nullptr;
    bool valid=SecRequirementCreateWithString((__bridge CFStringRef)publisher_requirement(),kSecCSDefaultFlags,&requirement)==errSecSuccess &&
        SecCodeCopyGuestWithAttributes(nullptr,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code)==errSecSuccess &&
        SecCodeCheckValidity(code,kSecCSStrictValidate,requirement)==errSecSuccess &&
        SecCodeCopySigningInformation(code,kSecCSSigningInformation,&information)==errSecSuccess;
    if(valid){
        NSDictionary* signed_info=(__bridge NSDictionary*)information;
        NSDictionary* secured=signed_info[(__bridge NSString*)kSecCodeInfoPList];
        id executable=signed_info[(__bridge NSString*)kSecCodeInfoMainExecutable];
        valid=[secured isKindOfClass:NSDictionary.class] && shutdown_contract(secured) &&
            [executable isKindOfClass:NSURL.class] &&
            [[executable path] isEqualToString:[NSString stringWithUTF8String:expected.c_str()]];
        // A valid older process from the same publisher/path is not the new
        // program generation. Compare the native selected slice's CDHash and
        // secured version with the currently installed authenticated bundle.
        auto* bundle=[NSURL fileURLWithPath:[NSString stringWithUTF8String:(std::string(account->pw_dir)+"/Applications/LanPilot.app").c_str()]];
        valid=valid && SecStaticCodeCreateWithPath((__bridge CFURLRef)bundle,kSecCSDefaultFlags,&installed)==errSecSuccess &&
            SecCodeCopySigningInformation(installed,kSecCSSigningInformation,&installed_information)==errSecSuccess;
        if(valid){
            NSDictionary* disk=(__bridge NSDictionary*)installed_information;
            NSDictionary* disk_plist=disk[(__bridge NSString*)kSecCodeInfoPList];
            id actual_hash=signed_info[(__bridge NSString*)kSecCodeInfoUnique];
            id disk_hash=disk[(__bridge NSString*)kSecCodeInfoUnique];
            valid=[actual_hash isKindOfClass:NSData.class] && [disk_hash isKindOfClass:NSData.class] &&
                [actual_hash isEqual:disk_hash] && [secured[@"CFBundleVersion"] isKindOfClass:NSString.class] &&
                [secured[@"CFBundleVersion"] isEqual:disk_plist[@"CFBundleVersion"]];
        }
    }
    if(installed_information)CFRelease(installed_information);if(installed)CFRelease(installed);
    if(information)CFRelease(information);if(code)CFRelease(code);if(requirement)CFRelease(requirement);
    return valid;
}
}
