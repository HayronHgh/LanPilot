#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>

#include "../agent_entry.hpp"
#include "configuration_store.hpp"
#include "code_identity.hpp"
#include "program_install.hpp"
#include "program_update.hpp"
#include "rwn/platform/macos/desktop_runtime.hpp"
#include "rwn/platform/enrollment_tcp.hpp"
#include "rwn/platform/macos/enrollment_journal.hpp"
#include "rwn/platform/macos/enrollment_key.hpp"
#include "rwn/platform/macos/enrollment_identity.hpp"
#include "rwn/platform/macos/pairing_consent.hpp"

#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <pwd.h>
#include <string_view>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

namespace {
std::string lan_address(){
    ifaddrs* list{};if(getifaddrs(&list)!=0)return {};
    struct Release{ifaddrs* list;~Release(){freeifaddrs(list);}} release{list};
    for(auto* entry=list;entry;entry=entry->ifa_next){
        if(!entry->ifa_addr || entry->ifa_addr->sa_family!=AF_INET || !(entry->ifa_flags&IFF_UP) || (entry->ifa_flags&IFF_LOOPBACK))continue;
        char text[INET_ADDRSTRLEN]{};const auto* a=reinterpret_cast<const sockaddr_in*>(entry->ifa_addr);
        if(!inet_ntop(AF_INET,&a->sin_addr,text,sizeof(text)))continue;
        try{(void)rwn::platform::enrollment::parse_private_ipv4(text);return text;}catch(...){}
    }return {};
}
struct ApplicationStatus {
    bool canonical_bundle{};
    bool capture_permission{};
    bool input_permission{};
    bool signed_with_team{};
};

ApplicationStatus status(const rwn::desktop::DesktopPermissionBackend& permissions) {
    const auto access=permissions.status();
    ApplicationStatus result{
        .canonical_bundle=static_cast<bool>([NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.lanpilot.desktop"]),
        .capture_permission=access.capture==rwn::desktop::PermissionState::granted,
        .input_permission=access.input==rwn::desktop::PermissionState::granted,
    };
    SecCodeRef code=nullptr;
    if(SecCodeCopySelf(kSecCSDefaultFlags,&code)==errSecSuccess){
        CFDictionaryRef dictionary=nullptr;
        if(SecCodeCopySigningInformation(code,kSecCSSigningInformation,&dictionary)==errSecSuccess){
            NSDictionary* info=(__bridge NSDictionary*)dictionary;
            NSNumber* flags=info[(__bridge NSString*)kSecCodeInfoFlags];
            NSString* team=info[(__bridge NSString*)kSecCodeInfoTeamIdentifier];
            result.signed_with_team=team.length>0 &&
                (flags.unsignedIntValue&kSecCodeSignatureAdhoc)==0 &&
                SecCodeCheckValidity(code,kSecCSStrictValidate,nullptr)==errSecSuccess;
            CFRelease(dictionary);
        }
        CFRelease(code);
    }
    return result;
}

// Headless UI workflow checks exercise consent ordering without calling either
// OS request API, regardless of the machine's actual grant state.
class FixturePermissions final : public rwn::desktop::DesktopPermissionBackend {
public:
    rwn::desktop::DesktopPermissionStatus state{
        .capture=rwn::desktop::PermissionState::denied,
        .input=rwn::desktop::PermissionState::denied};
    unsigned capture_requests{},input_requests{};
    rwn::desktop::DesktopPermissionStatus status() const override{return state;}
    void request_capture() override{++capture_requests;state.capture=rwn::desktop::PermissionState::granted;}
    void request_input() override{++input_requests;state.input=rwn::desktop::PermissionState::granted;}
};

const char* boolean(const bool value){return value?"true":"false";}

NSTextField* label(NSString* text){
    auto* value=[NSTextField wrappingLabelWithString:text];
    value.selectable=NO;
    return value;
}

bool gui_session_present(){
    const auto dictionary=CGSessionCopyCurrentDictionary();
    if(!dictionary)return false;
    CFRelease(dictionary);
    return true;
}

bool render_own_view(NSView* view,const char* output){
    // Test artifact only: cache our own NSView, never a screen/window-list
    // capture, and refuse existing files or linked output ancestors.
    const std::filesystem::path path(output);
    if(!path.is_absolute() || path.lexically_normal()!=path)return false;
    auto cursor=path;
    while(!cursor.empty()){
        std::error_code error;
        const auto state=std::filesystem::symlink_status(cursor,error);
        if(!error && std::filesystem::is_symlink(state))return false;
        const auto parent=cursor.parent_path();if(parent==cursor)break;cursor=parent;
    }
    if(std::filesystem::exists(path))return false;
    auto* bitmap=[view bitmapImageRepForCachingDisplayInRect:view.bounds];
    if(!bitmap)return false;
    [view cacheDisplayInRect:view.bounds toBitmapImageRep:bitmap];
    auto* opaque=[[NSBitmapImageRep alloc] initWithBitmapDataPlanes:nullptr
        pixelsWide:bitmap.pixelsWide pixelsHigh:bitmap.pixelsHigh bitsPerSample:8
        samplesPerPixel:4 hasAlpha:YES isPlanar:NO colorSpaceName:NSCalibratedRGBColorSpace
        bytesPerRow:0 bitsPerPixel:0];
    if(!opaque)return false;
    [view.effectiveAppearance performAsCurrentDrawingAppearance:^{
        [NSGraphicsContext saveGraphicsState];
        NSGraphicsContext.currentContext=[NSGraphicsContext graphicsContextWithBitmapImageRep:opaque];
        const auto bounds=NSMakeRect(0,0,static_cast<CGFloat>(bitmap.pixelsWide),static_cast<CGFloat>(bitmap.pixelsHigh));
        [NSColor.windowBackgroundColor setFill];NSRectFill(bounds);
        auto* image=[[NSImage alloc] initWithSize:bounds.size];
        [image addRepresentation:bitmap];
        [image drawInRect:bounds fromRect:NSZeroRect operation:NSCompositingOperationSourceOver
            fraction:1.0 respectFlipped:NO hints:nil];
        [NSGraphicsContext restoreGraphicsState];
    }];
    auto* bytes=[opaque representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    if(!bytes || bytes.length>4U*1024U*1024U)return false;
    auto* name=[NSString stringWithUTF8String:output];
    if(!name)return false;
    auto* file=[NSURL fileURLWithPath:name];
    return [bytes writeToURL:file options:NSDataWritingWithoutOverwriting error:nullptr];
}
} // namespace

@interface LPApplicationDelegate : NSObject<NSApplicationDelegate> {
    std::shared_ptr<std::atomic_bool> pairingCancellation_;
}
@property(strong) NSWindow* window;
@property(strong) NSTextField* captureStatus;
@property(strong) NSTextField* inputStatus;
@property(strong) NSTextField* codeStatus;
@property(strong) NSTextField* configurationStatus;
@property(strong) NSTextField* serviceStatus;
@property(strong) NSButton* serviceButton;
@property(strong) NSButton* updateButton;
@property(strong) NSTextField* updateStatus;
@property(strong) NSButton* captureButton;
@property(strong) NSButton* inputButton;
@property(strong) NSButton* controlOption;
@property(strong) NSButton* pairingButton;
@property(strong) NSTextField* pairingAddress;
@property(strong) NSTextField* pairingStatus;
@property(assign) BOOL pairingOperation;
@property(assign) BOOL legacyOwner;
@property(strong) NSTimer* refreshTimer;
@property(assign) NSUInteger consentRequests;
@property(assign) rwn::desktop::DesktopPermissionBackend* permissions;
@property(assign) BOOL allowVisibleUI;
@property(assign) BOOL fixtureConfiguration;
@property(assign) BOOL configurationReady;
@property(assign) BOOL configurationRequiresInput;
@property(assign) BOOL serviceOperation;
@property(assign) BOOL programRecoveryReady;
@property(assign) BOOL terminationPending;
- (void)buildWindow;
- (void)refresh:(id)sender;
- (void)requestCapture:(id)sender;
- (void)requestInput:(id)sender;
- (void)importConfiguration:(id)sender;
- (void)startPairing:(id)sender;
- (void)enableLogin:(id)sender;
- (void)recoverLogin;
- (void)installUpdate:(id)sender;
@end

@implementation LPApplicationDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    (void)notification;
    if(!self.allowVisibleUI)return;
    [self buildWindow];
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    if(rwn::agent::macos::product_code_ready())[self recoverLogin];
    __weak LPApplicationDelegate* weakSelf=self;
    self.refreshTimer=[NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer*){
        [weakSelf refresh:nil];
    }];
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)application {
    (void)application;
    return YES; // The separately registered login owner outlives the setup UI.
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)application {
    (void)application;
    if(!self.serviceOperation)return NSTerminateNow;
    self.terminationPending=YES;if(pairingCancellation_)pairingCancellation_->store(true);return NSTerminateLater;
}
- (void)applicationWillTerminate:(NSNotification*)notification {
    (void)notification;
    [self.refreshTimer invalidate];
}
- (void)buildWindow {
    NSParameterAssert(self.permissions!=nullptr);
    self.window=[[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,760,770)
        styleMask:(NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable)
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title=@"LanPilot";
    self.window.releasedWhenClosed=NO;
    auto* title=label(@"Prepare this Mac");
    title.font=[NSFont systemFontOfSize:26 weight:NSFontWeightSemibold];
    auto* introduction=label(@"Approve local permissions here. Remote connections still require a paired identity and separate permission to control this Mac.");
    self.captureStatus=label(@"");self.inputStatus=label(@"");self.codeStatus=label(@"");
    self.configurationStatus=label(@"");
    self.serviceStatus=label(@"");
    self.updateStatus=label(rwn::agent::macos::program_update_policy_ready()
        ?@"Signed updates use this app's fixed publisher key.":@"Updates unavailable: this development build has no release publisher key.");
    if(self.fixtureConfiguration){
        self.programRecoveryReady=YES;
        self.configurationStatus.stringValue=@"Settings saved. The existing service still owns connections.";
        self.serviceStatus.stringValue=@"Production publisher is not configured. The existing service is unchanged.";
        self.configurationReady=YES;self.configurationRequiresInput=YES;
    }
    else {
        try {
            const auto configuration=rwn::agent::macos::inspect_configuration();
            self.configurationStatus.stringValue=[NSString stringWithUTF8String:configuration.description.c_str()];
            self.configurationReady=configuration.configured;self.configurationRequiresInput=configuration.requires_input;
            self.legacyOwner=configuration.legacy_owner;
            const auto service=rwn::agent::macos::login_service_description();
            self.serviceStatus.stringValue=[NSString stringWithUTF8String:service.c_str()];
        } catch(const std::exception&){self.configurationStatus.stringValue=@"Could not inspect local settings. No service was started.";}
    }
    auto* grid=[NSGridView gridViewWithViews:@[
        @[label(@"Screen Recording"),self.captureStatus],
        @[label(@"Accessibility"),self.inputStatus],
        @[label(@"Application identity"),self.codeStatus],
        @[label(@"Saved connection"),self.configurationStatus],
        @[label(@"Login service"),self.serviceStatus],
        @[label(@"Program updates"),self.updateStatus],
        @[label(@"Remote connection"),label(@"Not verified by this setup window.")]]];
    grid.rowSpacing=15;grid.columnSpacing=18;
    [grid columnAtIndex:0].width=155;
    self.controlOption=[NSButton checkboxWithTitle:@"Prepare keyboard and mouse control (optional)"
        target:self action:@selector(refresh:)];
    self.controlOption.state=NSControlStateValueOff;
    self.captureButton=[NSButton buttonWithTitle:@"Allow Screen Recording"
        target:self action:@selector(requestCapture:)];
    self.inputButton=[NSButton buttonWithTitle:@"Allow Accessibility"
        target:self action:@selector(requestInput:)];
    auto* buttons=[NSStackView stackViewWithViews:@[self.captureButton,self.inputButton]];
    buttons.orientation=NSUserInterfaceLayoutOrientationHorizontal;buttons.spacing=12;
    auto* settings=[NSButton buttonWithTitle:@"Open System Settings"
        target:self action:@selector(openSettings:)];
    auto* refresh=[NSButton buttonWithTitle:@"Refresh status"
        target:self action:@selector(refresh:)];
    auto* secondary=[NSStackView stackViewWithViews:@[settings,refresh]];
    secondary.orientation=NSUserInterfaceLayoutOrientationHorizontal;secondary.spacing=12;
    auto* importSettings=[NSButton buttonWithTitle:@"Import existing connection settings"
        target:self action:@selector(importConfiguration:)];
    self.pairingAddress=[NSTextField textFieldWithString:[NSString stringWithUTF8String:lan_address().c_str()]];
    self.pairingAddress.placeholderString=@"This Mac's private LAN IPv4";
    self.pairingButton=[NSButton buttonWithTitle:@"Pair a Windows computer" target:self action:@selector(startPairing:)];
    auto* pairingRow=[NSStackView stackViewWithViews:@[self.pairingAddress,self.pairingButton]];
    pairingRow.orientation=NSUserInterfaceLayoutOrientationHorizontal;pairingRow.spacing=12;
    [self.pairingAddress.widthAnchor constraintGreaterThanOrEqualToConstant:220].active=YES;
    self.pairingStatus=label(@"First use: open a pairing window here, then enter this IP in Windows LanPilot. Compare all pairing information on both computers.");
    self.serviceButton=[NSButton buttonWithTitle:@"Enable start at login" target:self action:@selector(enableLogin:)];
    auto* loginSettings=[NSButton buttonWithTitle:@"Open Login Items" target:self action:@selector(openLoginItems:)];
    self.updateButton=[NSButton buttonWithTitle:@"Install signed update…" target:self action:@selector(installUpdate:)];
    auto* loginButtons=[NSStackView stackViewWithViews:@[self.serviceButton,loginSettings,self.updateButton]];
    loginButtons.orientation=NSUserInterfaceLayoutOrientationHorizontal;loginButtons.spacing=12;
    auto* limitation=label(@"Pairing saves a view-only connection. Screen Recording, optional control and login service activation remain separate. Production service migration and updates require this app signed by the expected publisher. Automatic update downloads are not ready. This window reads no clipboard.");
    limitation.font=[NSFont systemFontOfSize:12];limitation.textColor=NSColor.secondaryLabelColor;
    auto* stack=[NSStackView stackViewWithViews:@[title,introduction,grid,importSettings,pairingRow,self.pairingStatus,self.controlOption,buttons,secondary,loginButtons,limitation]];
    stack.orientation=NSUserInterfaceLayoutOrientationVertical;
    stack.alignment=NSLayoutAttributeLeading;stack.spacing=18;
    stack.translatesAutoresizingMaskIntoConstraints=NO;
    [self.window.contentView addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:self.window.contentView.leadingAnchor constant:28],
        [stack.trailingAnchor constraintEqualToAnchor:self.window.contentView.trailingAnchor constant:-28],
        [stack.topAnchor constraintEqualToAnchor:self.window.contentView.topAnchor constant:26],
        [stack.bottomAnchor constraintLessThanOrEqualToAnchor:self.window.contentView.bottomAnchor constant:-24],
        [introduction.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
        [grid.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
        [self.pairingStatus.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
        [limitation.widthAnchor constraintEqualToAnchor:stack.widthAnchor]]];
    [self refresh:nil];
}
- (void)refresh:(id)sender {
    (void)sender;
    const auto current=status(*self.permissions);
    self.captureStatus.stringValue=current.capture_permission?@"Allowed for this LanPilot process":@"Your approval is required";
    self.inputStatus.stringValue=current.input_permission?@"Allowed for this LanPilot process":@"Needed only for optional keyboard and mouse control";
    self.codeStatus.stringValue=current.signed_with_team?@"Signed with a team; release and notarization checks still required":@"Development code; production signing is not available";
    self.captureButton.enabled=!current.capture_permission && !self.serviceOperation;
    self.inputButton.enabled=self.controlOption.state==NSControlStateValueOn && !current.input_permission && !self.serviceOperation;
    self.pairingButton.enabled=self.allowVisibleUI && !self.fixtureConfiguration && !self.serviceOperation && !self.legacyOwner;
    self.pairingButton.title=self.configurationReady?@"Finish interrupted pairing":@"Pair a Windows computer";
    self.pairingAddress.enabled=!self.serviceOperation && !self.configurationReady && !self.legacyOwner;
    self.updateButton.enabled=!self.fixtureConfiguration && self.programRecoveryReady && !self.serviceOperation &&
        rwn::agent::macos::program_update_policy_ready() && rwn::agent::macos::product_code_ready();
    self.serviceButton.enabled=!self.fixtureConfiguration && self.programRecoveryReady && !self.serviceOperation && self.configurationReady &&
        current.capture_permission && (!self.configurationRequiresInput || current.input_permission) &&
        rwn::agent::macos::product_code_ready();
    if(sender && !self.fixtureConfiguration && !self.serviceOperation && self.programRecoveryReady){
        try {
            const auto service=rwn::agent::macos::login_service_description();
            self.serviceStatus.stringValue=[NSString stringWithUTF8String:service.c_str()];
        }catch(const std::exception&){self.serviceStatus.stringValue=@"Service status is unavailable. No second owner was started.";}
    }
}
- (void)requestCapture:(id)sender {
    (void)sender;
    if(!self.captureButton.enabled)return;
    ++self.consentRequests;
    self.permissions->request_capture();
    [self refresh:nil];
}
- (void)requestInput:(id)sender {
    (void)sender;
    if(!self.inputButton.enabled || self.controlOption.state!=NSControlStateValueOn)return;
    ++self.consentRequests;
    self.permissions->request_input();
    [self refresh:nil];
}
- (void)startPairing:(id)sender {
    (void)sender;
    if(!self.pairingButton.enabled || self.fixtureConfiguration || self.serviceOperation)return;
    if(self.configurationReady && rwn::agent::macos::configured_service_verified()){
        self.pairingStatus.stringValue=@"LanPilot is already running. Retry pairing on Windows; the saved transaction can finish automatically.";return;
    }
    std::array<std::byte,4> address{};
    try {address=rwn::platform::enrollment::parse_private_ipv4(self.pairingAddress.stringValue.UTF8String);}
    catch(...){self.pairingStatus.stringValue=@"Enter this Mac's private LAN IPv4 address. No pairing listener was opened.";return;}
    self.serviceOperation=YES;self.pairingOperation=YES;pairingCancellation_=std::make_shared<std::atomic_bool>(false);
    const auto cancellation=pairingCancellation_;const bool savedConfiguration=self.configurationReady;__weak LPApplicationDelegate* weakSelf=self;
    self.pairingStatus.stringValue=@"Opening a 120-second pairing window. Existing desktop service configuration is unchanged.";[self refresh:nil];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool {
        bool okay=false;
        try {
            rwn::agent::macos::prepare_enrollment_directory();
            auto file=rwn::platform::macos::enrollment_journal();auto keys=rwn::platform::macos::enrollment_key_store();
            auto identities=rwn::platform::macos::enrollment_identity_store();auto verifier=rwn::platform::macos::enrollment_pairing_verifier();
            rwn::core::enrollment::prepare_enrollment_retry(*file,*keys,*identities,*verifier,rwn::core::enrollment::PairRole::host);
            const auto pending=rwn::core::enrollment::DurablePairing::inspect(*file,*verifier);
            if(pending && pending->staged.role!=rwn::core::enrollment::PairRole::host)throw std::runtime_error("invalid local pairing role");
            // Existing settings are not an invitation to issue a new identity.
            // A configured host may replay only its own exact durable record.
            if(savedConfiguration && !pending)throw std::runtime_error("no native pairing to finish");
            {
                auto listener=rwn::platform::enrollment::listen(address,rwn::platform::enrollment::pairing_port);
                rwn::core::enrollment::EnrollmentSetupCallbacks callbacks;callbacks.random=rwn::platform::enrollment::secure_random;
                callbacks.progress=[weakSelf](std::string_view text){
                    NSString* message=[[NSString alloc] initWithBytes:text.data() length:text.size() encoding:NSUTF8StringEncoding];
                    dispatch_async(dispatch_get_main_queue(),^{LPApplicationDelegate* owner=weakSelf;if(owner)owner.pairingStatus.stringValue=message?:@"Pairing in progress…";});
                };
                callbacks.show_comparison=[weakSelf,cancellation](auto model){
                    dispatch_async(dispatch_get_main_queue(),^{
                        LPApplicationDelegate* owner=weakSelf;
                        if(!owner || !owner.allowVisibleUI || !owner.window.visible || cancellation->load())model->cancel(rwn::core::PairingConsent::Clock::now());
                        else (void)rwn::platform::macos::request_local_pairing_consent(*model);
                    });
                };
                callbacks.progress("Pairing window open for 120 seconds. Enter this IP in Windows LanPilot. If macOS asks, allow incoming connections for LanPilot.");
                const auto deadline=rwn::core::PairingConsent::Clock::now()+std::chrono::seconds{120};
                std::unique_ptr<rwn::core::enrollment::EnrollmentChannel> channel;
                while(!cancellation->load() && rwn::core::PairingConsent::Clock::now()<deadline){channel=listener->accept(std::chrono::milliseconds{20});if(channel)break;}
                listener.reset();
                if(!channel || cancellation->load())throw std::runtime_error("pairing window closed");
                if(pending){
                    auto proof=rwn::core::enrollment::recover_enrollment(*channel,*file,*keys,*identities,*verifier,address,callbacks,*cancellation);
                    if(proof){
                        // The existing valid profile may contain user choices
                        // and may be owned by an active runtime. Replay never
                        // overwrites it or stops that service.
                        if(!savedConfiguration)(void)rwn::core::enrollment::EnrollmentConfigurationHandoff::persist(*file,*proof,*identities,*verifier);
                        okay=true;
                    }
                }else{(void)rwn::core::enrollment::enroll_host(*channel,*file,*keys,*identities,*verifier,{address,45443},callbacks,*cancellation);okay=true;}
            }
        }catch(...){okay=false;}
        dispatch_async(dispatch_get_main_queue(),^{
            LPApplicationDelegate* owner=weakSelf;if(!owner)return;
            owner.serviceOperation=NO;owner.pairingOperation=NO;owner->pairingCancellation_.reset();
            owner.pairingStatus.stringValue=okay?@"Paired connection saved. Finish local permissions and enable start at login when ready.":
                @"Pairing did not finish. Existing settings were preserved. Any durable pending pairing remains saved for recovery.";
            if(okay){try {const auto c=rwn::agent::macos::inspect_configuration();owner.configurationReady=c.configured;owner.configurationRequiresInput=c.requires_input;owner.legacyOwner=c.legacy_owner;
                owner.configurationStatus.stringValue=[NSString stringWithUTF8String:c.description.c_str()];}catch(...){}}
            [owner refresh:nil];if(owner.terminationPending){owner.terminationPending=NO;[NSApp replyToApplicationShouldTerminate:YES];}
        });
    }});
}
- (void)importConfiguration:(id)sender {
    (void)sender;
    if(self.fixtureConfiguration || self.serviceOperation)return; // Hidden layout never touches user settings.
    try {
        const bool created=rwn::agent::macos::import_legacy_configuration();
        self.configurationStatus.stringValue=created?@"Settings imported. Existing service and Keychain are unchanged.":@"The same connection is already saved. No files were changed.";
        const auto configuration=rwn::agent::macos::inspect_configuration();
        self.configurationReady=configuration.configured;self.configurationRequiresInput=configuration.requires_input;
        [self refresh:nil];
    } catch(const std::exception&){
        self.configurationStatus.stringValue=@"Could not safely import existing settings. Nothing was activated or overwritten.";
    }
}
- (void)finishServiceOperation:(rwn::agent::macos::LoginResult)result {
    self.serviceOperation=NO;
    if(self.terminationPending){[NSApp replyToApplicationShouldTerminate:YES];return;}
    switch(result){
        case rwn::agent::macos::LoginResult::active:
            self.serviceStatus.stringValue=@"Login service running; local capture and identity checked. Remote connection not verified.";break;
        case rwn::agent::macos::LoginResult::approval_required:
            self.serviceStatus.stringValue=@"Allow LanPilot in Login Items, then click Enable again. The existing service is unchanged.";break;
        case rwn::agent::macos::LoginResult::restored:
            self.serviceStatus.stringValue=@"The previous service configuration was restored.";break;
        case rwn::agent::macos::LoginResult::recovery_required:
            self.serviceStatus.stringValue=@"Recovery is incomplete. A second service was not started.";break;
        default:
            self.serviceStatus.stringValue=@"Not ready: check the installed app, saved settings and local permissions.";break;
    }
    [self refresh:nil];
}
- (void)enableLogin:(id)sender {
    (void)sender;
    if(!self.serviceButton.enabled || self.fixtureConfiguration || self.serviceOperation)return;
    self.serviceOperation=YES;self.serviceButton.enabled=NO;
    self.serviceStatus.stringValue=@"Checking the saved identity and switching the login owner…";
    __weak LPApplicationDelegate* weakSelf=self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        @autoreleasepool {
            auto result=rwn::agent::macos::LoginResult::not_ready;
            try {
                result=rwn::agent::macos::activate_login_service();
                if(result==rwn::agent::macos::LoginResult::not_ready){
                    // Explicit local button only; never reached by a headless
                    // check or startup recovery. No new identity is created.
                    rwn::agent::macos::authorize_configuration_identity();
                    result=rwn::agent::macos::activate_login_service();
                }
            }catch(const std::exception&){}
            dispatch_async(dispatch_get_main_queue(),^{[weakSelf finishServiceOperation:result];});
        }
    });
}
- (void)recoverLogin {
    if(self.fixtureConfiguration || self.serviceOperation)return;
    self.serviceOperation=YES;self.serviceButton.enabled=NO;
    __weak LPApplicationDelegate* weakSelf=self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        @autoreleasepool {
            auto result=rwn::agent::macos::LoginResult::not_ready;
            bool programReady=false;
            try{
                const auto recovery=rwn::agent::macos::recover_program_install();
                programReady=recovery!=rwn::agent::macos::ProgramResult::recovery_required &&
                    recovery!=rwn::agent::macos::ProgramResult::rejected;
                if(programReady && rwn::agent::macos::inspect_configuration().configured)
                    result=rwn::agent::macos::recover_login_service();
            }catch(const std::exception&){}
            dispatch_async(dispatch_get_main_queue(),^{
                weakSelf.programRecoveryReady=programReady;
                if(programReady)[weakSelf finishServiceOperation:result];
                else {
                    weakSelf.serviceOperation=NO;
                    if(weakSelf.terminationPending){[NSApp replyToApplicationShouldTerminate:YES];return;}
                    weakSelf.serviceStatus.stringValue=@"An unfinished program update needs recovery. Login activation remains disabled.";
                    [weakSelf refresh:nil];
                }
            });
        }
    });
}
- (void)finishUpdate:(rwn::agent::macos::ProgramResult)result {
    self.serviceOperation=NO;
    if(self.terminationPending){[NSApp replyToApplicationShouldTerminate:YES];return;}
    switch(result){
        case rwn::agent::macos::ProgramResult::active:
            self.programRecoveryReady=NO;
            self.updateStatus.stringValue=@"Update installed. Quit and reopen LanPilot to use the new application.";break;
        case rwn::agent::macos::ProgramResult::unchanged:
            self.updateStatus.stringValue=@"This update is already installed.";break;
        case rwn::agent::macos::ProgramResult::rolled_back:
            self.updateStatus.stringValue=@"Update did not complete. The previous version was restored.";break;
        case rwn::agent::macos::ProgramResult::recovery_required:
            self.programRecoveryReady=NO;
            self.updateStatus.stringValue=@"Update recovery is required. Reopen LanPilot before enabling connections.";break;
        default:
            self.updateStatus.stringValue=@"No verified compatible update was installed. Existing settings and identity are retained.";break;
    }
    [self refresh:nil];
}
- (void)installUpdate:(id)sender {
    (void)sender;
    if(self.fixtureConfiguration || !self.updateButton.enabled || self.serviceOperation)return;
    auto* panel=[NSOpenPanel openPanel];panel.canChooseDirectories=YES;panel.canChooseFiles=NO;
    panel.allowsMultipleSelection=NO;panel.resolvesAliases=NO;
    panel.message=@"Select the LanPilot update folder from the publisher. Your connection settings and identity will be kept.";
    if([panel runModal]!=NSModalResponseOK || !panel.URL.isFileURL)return;
    NSString* directory=panel.URL.path;
    self.serviceOperation=YES;self.updateStatus.stringValue=@"Checking the signed update…";[self refresh:nil];
    __weak LPApplicationDelegate* weakSelf=self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        @autoreleasepool {
            try {
                const auto offer=rwn::agent::macos::inspect_program_update(directory.fileSystemRepresentation);
                dispatch_async(dispatch_get_main_queue(),^{
                    if(weakSelf.terminationPending){weakSelf.serviceOperation=NO;[NSApp replyToApplicationShouldTerminate:YES];return;}
                    auto* confirm=[[NSAlert alloc] init];
                    confirm.messageText=[NSString stringWithFormat:@"Install LanPilot %s?",rwn::core::to_string(offer.version).c_str()];
                    confirm.informativeText=@"This update's metadata is signed by the pinned publisher. Settings and identities are preserved. Desktop connections may pause; the previous app is retained for recovery.";
                    [confirm addButtonWithTitle:@"Install update"];[confirm addButtonWithTitle:@"Cancel"];
                    if([confirm runModal]!=NSAlertFirstButtonReturn){
                        weakSelf.serviceOperation=NO;weakSelf.updateStatus.stringValue=@"Update cancelled. No program was changed.";[weakSelf refresh:nil];
                        if(weakSelf.terminationPending)[NSApp replyToApplicationShouldTerminate:YES];return;
                    }
                    weakSelf.updateStatus.stringValue=@"Installing verified update…";
                    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
                        @autoreleasepool {
                            auto result=rwn::agent::macos::ProgramResult::rejected;
                            try{result=rwn::agent::macos::apply_program_update(directory.fileSystemRepresentation,offer.confirmation);}
                            catch(const std::exception&){}
                            dispatch_async(dispatch_get_main_queue(),^{[weakSelf finishUpdate:result];});
                        }
                    });
                });
            }catch(const std::exception&){
                dispatch_async(dispatch_get_main_queue(),^{[weakSelf finishUpdate:rwn::agent::macos::ProgramResult::rejected];});
            }
        }
    });
}
- (void)openLoginItems:(id)sender {
    (void)sender;if(self.fixtureConfiguration)return;
    [SMAppService openSystemSettingsLoginItems];
}
- (void)openSettings:(id)sender {
    (void)sender;
    // Fixed system app; no shell, peer-supplied URL or private preference key.
    auto* url=[NSURL fileURLWithPath:@"/System/Applications/System Settings.app" isDirectory:YES];
    [NSWorkspace.sharedWorkspace openApplicationAtURL:url
        configuration:[NSWorkspaceOpenConfiguration configuration] completionHandler:nil];
}
@end

int main(const int argc,char** argv){
    try {
    @autoreleasepool {
        if(geteuid()==0)return 65;
        if(argc==2 && std::string_view(argv[1])=="--check-release-verifier")
            return rwn::agent::macos::release_verifier_fixture();
        if(argc==2 && std::string_view(argv[1])=="--check-program-store")
            return rwn::agent::macos::program_store_fixture();
        if(argc==3 && std::string_view(argv[1])=="--write-program-inventory")
            return rwn::agent::macos::write_program_inventory(argv[2]);
        if(argc==2 && std::string_view(argv[1])=="--check-configuration-store")
            return rwn::agent::macos::configuration_store_fixture();
        if(argc==2 && std::string_view(argv[1])=="--check-service-bundle")
            return rwn::agent::macos::check_login_service_bundle();
        if(argc==2 && std::string_view(argv[1])=="--check-existing-connection"){
            const bool valid=rwn::agent::macos::check_legacy_configuration();
            std::printf("existing_connection=%s files_changed=0 keychain_accessed=0 listener_started=0\n",valid?"valid":"invalid");
            return valid?0:1;
        }
        if(argc==2 && std::string_view(argv[1])=="--check-configuration"){
            const auto configuration=rwn::agent::macos::inspect_configuration();
            std::printf("product_configuration configured=%s legacy_owner=%s listener_started=false keychain_accessed=false\n",
                boolean(configuration.configured),boolean(configuration.legacy_owner));
            return 0;
        }
        if(argc==2 && std::string_view(argv[1])=="--import-legacy-configuration"){
            const bool created=rwn::agent::macos::import_legacy_configuration();
            std::printf("product_configuration_import=complete created=%s service_changed=false keychain_accessed=false\n",boolean(created));
            return 0;
        }
        if(argc==2 && std::string_view(argv[1])=="--run-configured-service"){
            if(!rwn::agent::macos::product_code_ready()){
                std::fputs("product_service=not_ready reason=installed_expected_publisher_required listener_started=0\n",stderr);
                return 78;
            }
            return rwn::agent::macos::run_configured_service();
        }
        if(argc>1 && std::string_view(argv[1])=="--desktop-agent"){
            if(argc!=2){
                std::fprintf(stderr,"Use the configured service endpoint for application streaming.\n");
                return 64;
            }
            // Readiness only. Real streams must enter the configured wrapper,
            // including its durable record, publisher gate and runtime lease.
            return rwn::agent::run(argc-1,argv+1);
        }
        if(argc==2 && std::string_view(argv[1])=="--check-application"){
            rwn::platform::macos::MacosDesktopPermissionBackend permissions;
            const auto current=status(permissions);
            std::printf("{\"canonical_bundle\":%s,\"screen_permission_reported\":%s,"
                "\"input_permission_reported\":%s,\"signed_with_team\":%s,"
                "\"publisher_policy_configured\":%s,\"publisher_code_verified\":%s,"
                "\"capture_verified\":false,\"identity_checked\":false,\"peer_authenticated\":false,"
                "\"consent_requests\":0,\"listener_started\":false,\"clipboard_accessed\":false}\n",
                boolean(current.canonical_bundle),boolean(current.capture_permission),
                boolean(current.input_permission),boolean(current.signed_with_team),
                boolean(rwn::agent::macos::publisher_policy_configured()),boolean(rwn::agent::macos::product_code_ready()));
            return current.canonical_bundle?0:1;
        }
        const bool preview=argc==3 && std::string_view(argv[1])=="--render-layout";
        const bool layout=(argc==2 && std::string_view(argv[1])=="--check-layout") || preview;
        if(argc!=1 && !layout)return 64;
        if(!gui_session_present())return layout?77:65;
        auto* app=[NSApplication sharedApplication];
        std::unique_ptr<rwn::desktop::DesktopPermissionBackend> permissions;
        if(layout)permissions=std::make_unique<FixturePermissions>();
        else permissions=std::make_unique<rwn::platform::macos::MacosDesktopPermissionBackend>();
        auto* delegate=[[LPApplicationDelegate alloc] init];
        delegate.permissions=permissions.get();
        delegate.fixtureConfiguration=layout;
        app.delegate=delegate;
        if(layout){
            [app setActivationPolicy:NSApplicationActivationPolicyProhibited];
            [delegate buildWindow];
            delegate.window.appearance=[NSAppearance appearanceNamed:NSAppearanceNameAqua];
            [delegate.window.contentView layoutSubtreeIfNeeded];
            [delegate.window displayIfNeeded];
            bool valid=delegate.controlOption.state==NSControlStateValueOff &&
                !delegate.inputButton.enabled && delegate.consentRequests==0 &&
                !delegate.window.visible && [delegate.window.title isEqualToString:@"LanPilot"];
            auto* content=delegate.window.contentView;
            const auto frame=content.subviews.firstObject.frame;
            const bool bounds=NSMinX(frame)>=27 && NSMaxX(frame)<=content.bounds.size.width-27 &&
                NSMinY(frame)>=23 && NSMaxY(frame)<=content.bounds.size.height-25;
            std::printf("application_layout_detail initial=%d bounds=%d stack=%.1f,%.1f,%.1f,%.1f content=%.1f,%.1f\n",
                valid?1:0,bounds?1:0,static_cast<double>(frame.origin.x),static_cast<double>(frame.origin.y),
                static_cast<double>(frame.size.width),static_cast<double>(frame.size.height),
                static_cast<double>(content.bounds.size.width),static_cast<double>(content.bounds.size.height));
            valid=valid && bounds;
            const bool rendered=!preview || render_own_view(delegate.window.contentView,argv[2]);
            auto& fixture=static_cast<FixturePermissions&>(*permissions);
            [delegate requestInput:nil]; // No optional control consent yet.
            valid=valid && fixture.input_requests==0;
            [delegate enableLogin:nil];
            [delegate recoverLogin];
            [delegate installUpdate:nil];
            valid=valid && !delegate.updateButton.enabled;
            valid=valid && [delegate applicationShouldTerminate:app]==NSTerminateNow;
            delegate.serviceOperation=YES;
            valid=valid && [delegate applicationShouldTerminate:app]==NSTerminateLater && delegate.terminationPending;
            delegate.serviceOperation=NO;delegate.terminationPending=NO;
            valid=valid && !delegate.serviceOperation && !delegate.serviceButton.enabled;
            [delegate requestCapture:nil];
            [delegate requestCapture:nil]; // Granted button must stay disabled.
            delegate.controlOption.state=NSControlStateValueOn;
            [delegate refresh:nil];
            [delegate requestInput:nil];
            [delegate requestInput:nil];
            valid=valid && fixture.capture_requests==1 && fixture.input_requests==1 &&
                delegate.consentRequests==2 && !delegate.inputButton.enabled && !delegate.captureButton.enabled;
            std::printf("application_layout=%s native_consent_requests=0 simulated_consent_requests=%lu listener_started=0 clipboard_accessed=0 window_shown=%d\n",
                valid&&rendered?"PASS":"FAIL",static_cast<unsigned long>(delegate.consentRequests),delegate.window.visible?1:0);
            return valid&&rendered?0:1;
        }
        delegate.allowVisibleUI=YES;
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        auto* menu=[[NSMenu alloc] init];auto* item=[[NSMenuItem alloc] init];
        [menu addItem:item];
        auto* applicationMenu=[[NSMenu alloc] initWithTitle:@"LanPilot"];
        [applicationMenu addItemWithTitle:@"Quit LanPilot" action:@selector(terminate:) keyEquivalent:@"q"];
        item.submenu=applicationMenu;app.mainMenu=menu;
        [app run];
        return 0;
    }
    } catch(const std::exception&) {
        std::fputs("lanpilot_application_setup_failed\n",stderr);
        return 1;
    }
}
