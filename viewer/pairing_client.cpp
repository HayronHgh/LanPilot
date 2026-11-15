// Explicit foreground first-run enrollment. No shell, system trust mutation,
// clipboard access, desktop/input connection or automatic local approval.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "pairing_client.hpp"
#include "rwn/platform/enrollment_tcp.hpp"
#include "rwn/platform/windows/enrollment_journal.hpp"
#include "rwn/platform/windows/enrollment_key.hpp"
#include "rwn/platform/windows/enrollment_identity.hpp"
#include <thread>
#include <cstdio>

namespace {
namespace e=rwn::core::enrollment;
constexpr UINT comparison_message=WM_APP+21,status_message=WM_APP+22,done_message=WM_APP+23;
struct State {
    HWND window{},status{},comparison{},allow{},cancel{};HFONT font{},mono{};
    std::atomic_bool cancelled{};bool done{};int result{1};std::thread worker;
    std::shared_ptr<rwn::core::PairingConsent> model;
};
std::wstring wide(std::string_view s){const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);if(n<=0)return L"Pairing status unavailable.";
    std::wstring out(static_cast<std::size_t>(n),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);return out;}
void post_status(HWND window,std::string_view s){auto* text=new std::wstring(wide(s));if(!PostMessageW(window,status_message,0,reinterpret_cast<LPARAM>(text)))delete text;}
void stop(State& s){s.cancelled=true;if(s.model)s.model->cancel(rwn::core::PairingConsent::Clock::now());EnableWindow(s.allow,FALSE);SetWindowTextW(s.status,L"Cancelling pairing safely…");}
LRESULT CALLBACK procedure(HWND w,UINT m,WPARAM a,LPARAM b){
    auto* s=reinterpret_cast<State*>(GetWindowLongPtrW(w,GWLP_USERDATA));
    if(m==WM_NCCREATE){s=static_cast<State*>(reinterpret_cast<CREATESTRUCTW*>(b)->lpCreateParams);SetWindowLongPtrW(w,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(s));s->window=w;}
    if(!s)return DefWindowProcW(w,m,a,b);
    if(m==status_message){std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(b));SetWindowTextW(s->status,text->c_str());return 0;}
    if(m==comparison_message){std::unique_ptr<std::shared_ptr<rwn::core::PairingConsent>> model(reinterpret_cast<std::shared_ptr<rwn::core::PairingConsent>*>(b));s->model=*model;
        if(s->cancelled){s->model->cancel(rwn::core::PairingConsent::Clock::now());return 0;}
        std::wstring text;constexpr wchar_t digits[]=L"0123456789ABCDEF";const auto binding=s->model->binding();
        for(std::size_t i=0;i<binding.size();++i){if(i && i%8==0)text+=L"\r\n";else if(i && i%2==0)text+=L' ';text+=digits[binding[i]>>4];text+=digits[binding[i]&15];}
        SetWindowTextW(s->comparison,text.c_str());SetWindowTextW(s->status,L"Compare ALL pairing information with the Mac. Allow only if both match.");EnableWindow(s->allow,TRUE);return 0;
    }
    if(m==WM_COMMAND && LOWORD(a)==1 && s->model && !s->cancelled && !s->done){
        if(s->model->local_decision(s->model->binding(),true,rwn::core::PairingConsent::Clock::now())){EnableWindow(s->allow,FALSE);SetWindowTextW(s->status,L"Your approval is saved for this attempt. Waiting for the Mac…");}return 0;
    }
    if(m==WM_COMMAND && LOWORD(a)==2){if(s->done)DestroyWindow(w);else stop(*s);return 0;}
    if(m==WM_KEYDOWN && (a==VK_ESCAPE || a==VK_RETURN)){if(s->done)DestroyWindow(w);else stop(*s);return 0;}
    if(m==done_message){s->done=true;s->result=static_cast<int>(a);EnableWindow(s->allow,FALSE);
        if(s->result==0){DestroyWindow(w);}else{SetWindowTextW(s->status,L"Pairing did not finish. Existing connection settings were preserved. Close this window to return to LanPilot.");SetWindowTextW(s->cancel,L"Close");}return 0;}
    if(m==WM_CLOSE){if(s->done)DestroyWindow(w);else stop(*s);return 0;}
    if(m==WM_DESTROY){PostQuitMessage(s->result);return 0;}
    return DefWindowProcW(w,m,a,b);
}
}
int run_pairing_client_ui(std::wstring_view address_text,bool check_layout){
    try {
        const auto instance=GetModuleHandleW(nullptr);std::string ip;for(auto c:address_text){if(c>127)return ERROR_INVALID_PARAMETER;ip+=static_cast<char>(c);}
        const auto address=rwn::platform::enrollment::parse_private_ipv4(ip);
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        WNDCLASSW type{};type.hInstance=instance;type.lpfnWndProc=procedure;type.lpszClassName=L"LanPilot.NativePairing.v1";type.hCursor=LoadCursorW(nullptr,MAKEINTRESOURCEW(32512));type.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
        if(!RegisterClassW(&type) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return ERROR_INVALID_PARAMETER;
        State s;const auto window=CreateWindowExW(WS_EX_DLGMODALFRAME,type.lpszClassName,L"LanPilot - Pair with your Mac",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
            CW_USEDEFAULT,CW_USEDEFAULT,670,480,nullptr,nullptr,instance,&s);if(!window)return ERROR_INVALID_WINDOW_HANDLE;
        s.font=CreateFontW(-17,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
        s.mono=CreateFontW(-24,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,FIXED_PITCH,L"Consolas");
        s.status=CreateWindowW(L"STATIC",L"Connecting to the Mac. Open LanPilot there and choose Pair a Windows computer.",WS_CHILD|WS_VISIBLE,24,24,610,72,window,nullptr,instance,nullptr);
        s.comparison=CreateWindowW(L"STATIC",L"Waiting for authenticated pairing information…",WS_CHILD|WS_VISIBLE,24,115,610,145,window,nullptr,instance,nullptr);
        const auto note=CreateWindowW(L"STATIC",L"This pairs protected local identities. Screen Recording, keyboard/mouse control, clipboard and SSH permission remain separate. Enter and Escape decline.",WS_CHILD|WS_VISIBLE,24,285,610,76,window,nullptr,instance,nullptr);
        s.allow=CreateWindowW(L"BUTTON",L"Both match - Allow pairing",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,286,380,345,36,window,reinterpret_cast<HMENU>(1),instance,nullptr);
        s.cancel=CreateWindowW(L"BUTTON",L"Cancel",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,24,380,150,36,window,reinterpret_cast<HMENU>(2),instance,nullptr);
        for(auto control:{s.status,note,s.allow,s.cancel}){
            SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(s.font),TRUE);
        }
        SendMessageW(s.comparison,WM_SETFONT,reinterpret_cast<WPARAM>(s.mono),TRUE);
        EnableWindow(s.allow,FALSE);
        if(check_layout){
            // Exercise ONLY this hidden view and its consent message handler.
            // No worker, sockets, key/certificate stores or system input APIs.
            bool okay=!IsWindowVisible(window) && !IsWindowEnabled(s.allow);
            RECT client{};GetClientRect(window,&client);
            for(auto child:{s.status,s.comparison,note,s.allow,s.cancel}){
                RECT bounds{};GetWindowRect(child,&bounds);MapWindowPoints(nullptr,window,reinterpret_cast<POINT*>(&bounds),2);
                okay=okay && bounds.left>=0 && bounds.top>=0 && bounds.right<=client.right && bounds.bottom<=client.bottom;
            }
            rwn::core::PairingConsent::Binding binding{};binding[0]=1;
            auto model=std::make_shared<rwn::core::PairingConsent>(binding,rwn::core::PairingConsent::Clock::now());
            SendMessageW(window,comparison_message,0,reinterpret_cast<LPARAM>(new std::shared_ptr<rwn::core::PairingConsent>(model)));
            okay=okay && IsWindowEnabled(s.allow) && GetWindowTextLengthW(s.comparison)==82;
            SendMessageW(window,WM_KEYDOWN,VK_RETURN,0);SendMessageW(window,WM_COMMAND,1,0);
            okay=okay && model->state(rwn::core::PairingConsent::Clock::now())==rwn::core::PairingConsent::State::cancelled;
            DestroyWindow(window);DeleteObject(s.font);DeleteObject(s.mono);
            std::printf("pairing_layout=%s window_shown=0 network=0 native_stores=0 enter_declines=1 late_allow_rejected=1\n",okay?"PASS":"FAIL");
            return okay?0:1;
        }
        ShowWindow(window,SW_SHOW);UpdateWindow(window);
        s.worker=std::thread([&s,address]{int result=1;try{
            auto file=rwn::platform::windows::enrollment_journal();auto keys=rwn::platform::windows::enrollment_key_store();auto identities=rwn::platform::windows::enrollment_identity_store();auto verifier=rwn::platform::windows::enrollment_pairing_verifier();
            if(e::EnrollmentConfigurationHandoff::recover(*file,*keys,*identities,*verifier)){result=0;}
            else {
                e::prepare_enrollment_retry(*file,*keys,*identities,*verifier,e::PairRole::client);
                auto channel=rwn::platform::enrollment::connect(address,rwn::platform::enrollment::pairing_port,std::chrono::seconds{10},s.cancelled);
                e::EnrollmentSetupCallbacks callbacks;callbacks.random=rwn::platform::enrollment::secure_random;
                callbacks.progress=[window=s.window](std::string_view text){post_status(window,text);};
                callbacks.show_comparison=[window=s.window](auto model){auto* owned=new std::shared_ptr<rwn::core::PairingConsent>(std::move(model));if(!PostMessageW(window,comparison_message,0,reinterpret_cast<LPARAM>(owned))){(*owned)->cancel(rwn::core::PairingConsent::Clock::now());delete owned;}};
                if(const auto pending=e::DurablePairing::inspect(*file,*verifier)){
                    if(pending->staged.role!=e::PairRole::client)throw std::runtime_error("invalid local pairing role");
                    auto proof=e::recover_enrollment(*channel,*file,*keys,*identities,*verifier,address,callbacks,s.cancelled,true);
                    if(proof){(void)e::EnrollmentConfigurationHandoff::persist(*file,*proof,*identities,*verifier);result=0;}
                    else{e::prepare_enrollment_retry(*file,*keys,*identities,*verifier,e::PairRole::client);
                        (void)e::enroll_client(*channel,*file,*keys,*identities,*verifier,address,callbacks,s.cancelled);result=0;}
                }else{(void)e::enroll_client(*channel,*file,*keys,*identities,*verifier,address,callbacks,s.cancelled);result=0;}
            }
        }catch(...){result=1;}PostMessageW(s.window,done_message,static_cast<WPARAM>(result),0);});
        MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){
            if(message.message==WM_KEYDOWN && (message.wParam==VK_ESCAPE || message.wParam==VK_RETURN)){
                if(s.done)DestroyWindow(window);else stop(s);continue;
            }TranslateMessage(&message);DispatchMessageW(&message);
        }
        s.cancelled=true;if(s.worker.joinable())s.worker.join();if(s.font)DeleteObject(s.font);if(s.mono)DeleteObject(s.mono);return s.result;
    }catch(...){MessageBoxW(nullptr,L"Enter a private LAN IPv4 address, then open LanPilot on the Mac to begin pairing.",L"LanPilot pairing",MB_OK|MB_ICONERROR);return ERROR_INVALID_PARAMETER;}
}
