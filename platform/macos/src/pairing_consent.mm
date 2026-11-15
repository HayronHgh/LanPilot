#include "rwn/platform/macos/pairing_consent.hpp"
#import <AppKit/AppKit.h>
#include <stdexcept>
#include <string>

namespace rwn::platform::macos {
bool request_local_pairing_consent(rwn::core::PairingConsent& consent) {
    using Consent = rwn::core::PairingConsent;
    using State = Consent::State;
    if (![NSThread isMainThread])
        throw std::logic_error("pairing consent UI requires main thread");
    // Modal loops can be reentrant. Never stack prompts or let an unrelated
    // peer's timer abort another pairing dialog.
    static bool showing = false;
    if (showing) return false;
    const auto initial = consent.state(Consent::Clock::now());
    if (initial != State::awaiting_both && initial != State::awaiting_local) return false;
    showing = true;
    struct Reset { bool& flag; ~Reset() { flag = false; } } reset{showing};
    @autoreleasepool {
        [NSApplication sharedApplication];
        const auto binding = consent.binding();
        constexpr char digits[] = "0123456789ABCDEF";
        std::string comparison;
        for (std::size_t i = 0; i < binding.size(); ++i) {
            if (i && i % 8 == 0) comparison += '\n';
            else if (i && i % 2 == 0) comparison += ' ';
            comparison += digits[binding[i] >> 4];
            comparison += digits[binding[i] & 15];
        }
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"允許配對這台電腦？";
        alert.informativeText = @"請確認 Windows 與 Mac 顯示的核對資訊完全相同。\n若不是你發起的連線，請拒絕。配對不會授予 SSH 或遠端鍵鼠控制權。";
        alert.alertStyle = NSAlertStyleInformational;
        // Return/Escape both refuse. Approval always requires an explicit click.
        NSButton* deny = [alert addButtonWithTitle:@"拒絕"];
        deny.keyEquivalent = @"\r";
        NSButton* allow = [alert addButtonWithTitle:@"資訊相同，允許配對"];
        allow.keyEquivalent = @"";
        NSTextField* text = [NSTextField labelWithString:
            [NSString stringWithUTF8String:comparison.c_str()]];
        text.font = [NSFont monospacedSystemFontOfSize:16 weight:NSFontWeightRegular];
        text.frame = NSMakeRect(0, 0, 350, 100);
        text.selectable = NO;
        alert.accessoryView = text;
        Consent* model = &consent;
        NSTimer* timer = [NSTimer timerWithTimeInterval:0.1 repeats:YES block:^(NSTimer*) {
            const auto state = model->state(Consent::Clock::now());
            if (state != State::awaiting_both && state != State::awaiting_local)
                [NSApp abortModal];
        }];
        // Default-mode timers do not advance while runModal owns the run loop.
        [[NSRunLoop mainRunLoop] addTimer:timer forMode:NSModalPanelRunLoopMode];
        NSModalResponse response = NSModalResponseAbort;
        @try { response = [alert runModal]; }
        @finally { [timer invalidate]; [alert.window orderOut:nil]; }
        if (response == NSAlertSecondButtonReturn)
            return consent.local_decision(binding, true, Consent::Clock::now());
        (void)consent.local_decision(binding, false, Consent::Clock::now());
        return false;
    }
}
}
