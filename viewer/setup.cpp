// Offline per-user setup. Both payload and fixed driver are PE resources.
// No downloaded code, script-path option, elevation, identity or trust changes.
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

namespace {
namespace fs=std::filesystem;
constexpr UINT tick=1;
HWND status_text{},status_heading{},action{},open_button{},progress{};
HFONT font{},heading_font{},small_font{};
HBRUSH background{},footer_background{};
UINT dpi=96;
COLORREF status_color=RGB(68,83,105);
struct ControlLayout { HWND window; int x,y,width,height; HFONT* type; };
std::vector<ControlLayout> layout;
int scaled(int value) { return MulDiv(value,static_cast<int>(dpi),96); }
bool running{},succeeded{},hidden{},ui_probe{},workspace_created{},pair_probe{};
int probe_result=1;
HANDLE child{},log_handle{};
std::vector<HANDLE> held;
fs::path workspace,install_root;
std::wstring quote(const std::wstring& value) {
    std::wstring out=L"\"";std::size_t slashes{};
    for(wchar_t ch:value){
        if(ch==L'\\'){++slashes;continue;}
        out.append(ch==L'\"'?slashes*2+1:slashes,L'\\');slashes=0;out+=ch;
    }
    out.append(slashes*2,L'\\');return out+L'\"';
}
fs::path local_data() {
    PWSTR value{};
    if(FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_DEFAULT,nullptr,&value)))
        throw std::runtime_error("Local application data is unavailable.");
    fs::path result(value);CoTaskMemFree(value);return result;
}
bool create_workspace(const fs::path& path) {
    HANDLE token{};if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;
    DWORD bytes{};GetTokenInformation(token,TokenUser,nullptr,0,&bytes);
    std::vector<unsigned char> storage(bytes);
    const auto ok=GetTokenInformation(token,TokenUser,storage.data(),bytes,&bytes);CloseHandle(token);
    if(!ok)return false;
    LPWSTR sid{};
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid,&sid))return false;
    const auto dacl=std::wstring(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;")+sid+L")";LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor{};
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(),SDDL_REVISION_1,&descriptor,nullptr))return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    const auto created=CreateDirectoryW(path.c_str(),&attributes);LocalFree(descriptor);return created!=FALSE;
}
bool unlinked(fs::path path) {
    while(!path.empty()){
        const auto attrs=GetFileAttributesW(path.c_str());
        if(attrs==INVALID_FILE_ATTRIBUTES || (attrs&FILE_ATTRIBUTE_REPARSE_POINT))return false;
        const auto parent=path.parent_path();if(parent==path)break;path=parent;
    }
    return true;
}
void resource_file(int id,const wchar_t* name) {
    auto resource=FindResourceW(nullptr,MAKEINTRESOURCEW(id),MAKEINTRESOURCEW(10));
    auto loaded=resource?LoadResource(nullptr,resource):nullptr;
    const DWORD size=resource?SizeofResource(nullptr,resource):0;
    if(!loaded || !size || size>268435456)throw std::runtime_error("Embedded setup package is unavailable.");
    auto path=workspace/name;
    HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot prepare setup package.");
    DWORD written{};const auto ok=WriteFile(file,LockResource(loaded),size,&written,nullptr);
    CloseHandle(file);
    if(!ok || written!=size)throw std::runtime_error("Cannot write setup package.");
    file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot lock setup package.");
    held.push_back(file);
}
void cleanup() {
    if(child){CloseHandle(child);child=nullptr;}
    if(log_handle){CloseHandle(log_handle);log_handle=nullptr;}
    for(auto handle:held)CloseHandle(handle);
    held.clear();
    // Only the unique directory created by this process, with checked ancestry.
    if(workspace_created && !workspace.empty() && unlinked(workspace) && workspace.filename().wstring().starts_with(L"LanPilot-Setup-")){
        std::error_code error;fs::remove_all(workspace,error);
    }
    workspace_created=false;
}
void start(bool verify) {
    if(running)return;
    wchar_t temp[32768]{};
    if(!GetTempPathW(32768,temp) || !unlinked(fs::path(temp)))throw std::runtime_error("A regular local temporary directory is required.");
    GUID guid{};
    if(FAILED(CoCreateGuid(&guid)))throw std::runtime_error("Cannot create setup workspace.");
    wchar_t unique[40]{};StringFromGUID2(guid,unique,40);
    workspace=fs::path(temp)/(std::wstring(L"LanPilot-Setup-")+unique);
    workspace_created=create_workspace(workspace);
    if(!workspace_created || !unlinked(workspace))
        throw std::runtime_error("Cannot create a private setup workspace.");
    resource_file(101,L"payload.zip");resource_file(102,L"driver.ps1");
    SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};
    log_handle=CreateFileW((workspace/L"result.log").c_str(),GENERIC_WRITE,FILE_SHARE_READ,
        &security,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(log_handle==INVALID_HANDLE_VALUE){log_handle=nullptr;throw std::runtime_error("Cannot create setup result log.");}
    wchar_t system[MAX_PATH]{};
    if(!GetSystemDirectoryW(system,MAX_PATH))throw std::runtime_error("System PowerShell is unavailable.");
    auto host=fs::path(system)/L"WindowsPowerShell/v1.0/powershell.exe";
    auto command=quote(host.wstring())+L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+
        quote((workspace/L"driver.ps1").wstring())+(verify?(pair_probe?L" pair-check":L" verify"):L" install");
    STARTUPINFOW startup{};startup.cb=sizeof(startup);
    startup.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;startup.wShowWindow=SW_HIDE;
    startup.hStdOutput=log_handle;startup.hStdError=log_handle;
    HANDLE input=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,0,nullptr);
    startup.hStdInput=input;
    PROCESS_INFORMATION process{};
    // Deliberately do NOT kill the installer mid-transaction when setup closes.
    // Normal UI close is disabled during activation; OS interruption is journaled.
    const auto ok=CreateProcessW(host.c_str(),command.data(),nullptr,nullptr,TRUE,
        CREATE_NO_WINDOW,nullptr,workspace.c_str(),&startup,&process);
    if(input!=INVALID_HANDLE_VALUE)CloseHandle(input);
    if(!ok)throw std::runtime_error("Cannot start the Windows installer.");
    child=process.hProcess;CloseHandle(process.hThread);running=true;
}
std::wstring failure_message() {
    std::ifstream file(workspace/L"result.log",std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(file)),{});
    const auto pos=bytes.rfind("Setup could not finish:");
    if(pos==std::string::npos)return L"Installation did not complete. Close LanPilot and try again. Settings and keys were not reset.";
    bytes=bytes.substr(pos+24,180);
    if(const auto line_end=bytes.find_first_of("\r\n");line_end!=std::string::npos)bytes.resize(line_end);
    bytes+="\nYour saved settings and keys were kept.";
    const int length=MultiByteToWideChar(CP_UTF8,0,bytes.data(),static_cast<int>(bytes.size()),nullptr,0);
    std::wstring result(static_cast<std::size_t>(length),L' ');
    MultiByteToWideChar(CP_UTF8,0,bytes.data(),static_cast<int>(bytes.size()),result.data(),length);
    return result;
}
HWND label(HWND parent,const wchar_t* text,int x,int y,int width,int height,HFONT use_font=nullptr) {
    auto control=CreateWindowW(L"STATIC",text,WS_CHILD|WS_VISIBLE,scaled(x),scaled(y),scaled(width),scaled(height),parent,nullptr,nullptr,nullptr);
    auto type=use_font==heading_font?&heading_font:use_font==small_font?&small_font:&font;
    layout.push_back({control,x,y,width,height,type});
    SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(*type),TRUE);return control;
}
void set_fonts() {
    auto old_font=font,old_heading=heading_font,old_small=small_font;
    font=CreateFontW(-scaled(16),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    heading_font=CreateFontW(-scaled(28),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    small_font=CreateFontW(-scaled(13),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    for(const auto& item:layout){
        MoveWindow(item.window,scaled(item.x),scaled(item.y),scaled(item.width),scaled(item.height),TRUE);
        SendMessageW(item.window,WM_SETFONT,reinterpret_cast<WPARAM>(*item.type),TRUE);
    }
    for(auto old:{old_font,old_heading,old_small})if(old)DeleteObject(old);
}
void status(const wchar_t* title,const std::wstring& detail,COLORREF color) {
    status_color=color;SetWindowTextW(status_heading,title);SetWindowTextW(status_text,detail.c_str());
    InvalidateRect(status_heading,nullptr,TRUE);
}
void paint_background(HWND window,HDC dc) {
        RECT area{};GetClientRect(window,&area);
        FillRect(dc,&area,background);RECT footer{0,scaled(452),area.right,area.bottom};FillRect(dc,&footer,footer_background);
        auto navy=CreateSolidBrush(RGB(30,64,112));RECT mark{scaled(32),scaled(28),scaled(68),scaled(68)};FillRect(dc,&mark,navy);DeleteObject(navy);
        auto pen=CreatePen(PS_SOLID,scaled(2),RGB(255,255,255));auto old_pen=SelectObject(dc,pen);auto old_brush=SelectObject(dc,GetStockObject(HOLLOW_BRUSH));
        Rectangle(dc,scaled(39),scaled(36),scaled(61),scaled(52));MoveToEx(dc,scaled(50),scaled(52),nullptr);LineTo(dc,scaled(50),scaled(59));
        MoveToEx(dc,scaled(44),scaled(59),nullptr);LineTo(dc,scaled(56),scaled(59));SelectObject(dc,old_pen);SelectObject(dc,old_brush);DeleteObject(pen);
}
// Deterministic layout probe: render only our own hidden window into a new BMP.
// Never captures the desktop, clicks Install, or changes the installed product.
bool write_layout(HWND window,const fs::path& path) {
    if(!path.is_absolute() || !unlinked(path.parent_path()))return false;
    RECT rect{};GetClientRect(window,&rect);
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=rect.right;info.bmiHeader.biHeight=-rect.bottom;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    void* pixels{};auto dc=CreateCompatibleDC(nullptr);
    auto bitmap=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&pixels,nullptr,0);
    if(!bitmap){DeleteDC(dc);return false;}
    auto old=SelectObject(dc,bitmap);
    paint_background(window,dc);
    for(const auto& item:layout){
        if(!(GetWindowLongW(item.window,GWL_STYLE)&WS_VISIBLE))continue;
        const auto saved=SaveDC(dc);SetViewportOrgEx(dc,scaled(item.x),scaled(item.y),nullptr);
        wchar_t type[32]{};GetClassNameW(item.window,type,32);
        if(std::wstring(type)==L"STATIC"){
            wchar_t text[1024]{};GetWindowTextW(item.window,text,1024);
            SelectObject(dc,*item.type);SetBkMode(dc,TRANSPARENT);
            SetTextColor(dc,item.window==status_heading?status_color:item.type==&heading_font?RGB(22,36,57):RGB(68,83,105));
            RECT bounds{0,0,scaled(item.width),scaled(item.height)};
            auto flags=DT_LEFT|DT_TOP|DT_WORDBREAK|DT_NOPREFIX;
            if(GetWindowLongW(item.window,GWL_STYLE)&SS_PATHELLIPSIS)flags|=DT_PATH_ELLIPSIS;
            DrawTextW(dc,text,-1,&bounds,flags);
        }else{
            SendMessageW(item.window,WM_PRINTCLIENT,reinterpret_cast<WPARAM>(dc),PRF_CLIENT|PRF_ERASEBKGND);
        }
        RestoreDC(dc,saved);
    }
    GdiFlush();
    const DWORD bytes=static_cast<DWORD>(rect.right*rect.bottom*4);
    BITMAPFILEHEADER header{};header.bfType=0x4d42;
    header.bfOffBits=sizeof(header)+sizeof(BITMAPINFOHEADER);header.bfSize=header.bfOffBits+bytes;
    auto file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    bool ok=false;DWORD written{};
    if(file!=INVALID_HANDLE_VALUE){
        ok=WriteFile(file,&header,sizeof(header),&written,nullptr) && written==sizeof(header) &&
            WriteFile(file,&info.bmiHeader,sizeof(BITMAPINFOHEADER),&written,nullptr) && written==sizeof(BITMAPINFOHEADER) &&
            WriteFile(file,pixels,bytes,&written,nullptr) && written==bytes;
        CloseHandle(file);
    }
    SelectObject(dc,old);DeleteObject(bitmap);DeleteDC(dc);return ok;
}
LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wp,LPARAM lp) {
    switch(message){
    case WM_CREATE: {
        dpi=GetDpiForWindow(window);set_fonts();
        background=CreateSolidBrush(RGB(255,255,255));footer_background=CreateSolidBrush(RGB(245,247,250));
        label(window,L"LanPilot",82,28,260,30);
#ifdef LANPILOT_PERSONAL_SETUP
        label(window,L"Personal edition",82,51,300,22,small_font);
#else
        label(window,L"Desktop setup",82,51,300,22,small_font);
#endif
        const bool installed=fs::exists(install_root/L"LanPilot.exe");
        label(window,(std::wstring(L"Version ")+LANPILOT_SETUP_VERSION).c_str(),440,37,136,22,small_font);
        label(window,installed?L"Update LanPilot":L"Install LanPilot",32,102,536,42,heading_font);
        label(window,L"Connect to your Mac, right from your Windows desktop.\nYour saved connections and device keys stay in place.",32,155,536,52);
        label(window,L"Install location",32,230,536,22,small_font);
        auto path_label=label(window,install_root.wstring().c_str(),32,257,536,44,small_font);
        SetWindowLongPtrW(path_label,GWL_STYLE,GetWindowLongPtrW(path_label,GWL_STYLE)|SS_PATHELLIPSIS);
#ifdef LANPILOT_PERSONAL_SETUP
        label(window,L"For your already-paired devices. No administrator access needed.",32,307,536,22,small_font);
#else
        label(window,L"For personal use. Commercial use requires permission.",32,307,536,22,small_font);
#endif
        status_heading=label(window,L"Ready to install",32,355,536,24);
        status_text=label(window,L"Close LanPilot before continuing.",32,385,536,46,small_font);
        if(installed)SetWindowTextW(status_heading,L"Ready to update");
        progress=CreateWindowW(PROGRESS_CLASSW,L"",WS_CHILD|PBS_MARQUEE,scaled(32),scaled(434),scaled(536),scaled(4),window,nullptr,nullptr,nullptr);
        action=CreateWindowW(L"BUTTON",installed?L"Update LanPilot":L"Install LanPilot",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,scaled(388),scaled(465),scaled(180),scaled(40),window,reinterpret_cast<HMENU>(1),nullptr,nullptr);
        open_button=CreateWindowW(L"BUTTON",L"Open LanPilot",WS_CHILD|WS_TABSTOP,scaled(192),scaled(465),scaled(180),scaled(40),window,reinterpret_cast<HMENU>(1002),nullptr,nullptr);
        layout.push_back({progress,32,434,536,4,&font});
        layout.push_back({action,388,465,180,40,&font});layout.push_back({open_button,192,465,180,40,&font});
        for(auto button:{action,open_button})SendMessageW(button,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
        label(window,L"No admin access needed",32,477,156,28,small_font);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        auto dc=reinterpret_cast<HDC>(wp);SetBkMode(dc,TRANSPARENT);
        const auto control=reinterpret_cast<HWND>(lp);
        SetTextColor(dc,control==status_heading?status_color:
            reinterpret_cast<HFONT>(SendMessageW(control,WM_GETFONT,0,0))==heading_font?RGB(22,36,57):RGB(68,83,105));
        POINT origin{};MapWindowPoints(reinterpret_cast<HWND>(lp),window,&origin,1);
        return reinterpret_cast<LRESULT>(origin.y>=scaled(452)?footer_background:background);
    }
    case WM_PAINT: {
        PAINTSTRUCT paint{};auto dc=BeginPaint(window,&paint);paint_background(window,dc);
        EndPaint(window,&paint);return 0;
    }
    case WM_PRINTCLIENT:
        paint_background(window,reinterpret_cast<HDC>(wp));return 0;
    case WM_DRAWITEM: {
        const auto item=reinterpret_cast<DRAWITEMSTRUCT*>(lp);if(item->CtlID!=1)break;
        const bool disabled=(item->itemState&ODS_DISABLED)!=0;
        auto fill=CreateSolidBrush(disabled?RGB(220,226,235):(item->itemState&ODS_SELECTED)?RGB(21,47,83):RGB(30,64,112));
        FillRect(item->hDC,&item->rcItem,fill);DeleteObject(fill);SetBkMode(item->hDC,TRANSPARENT);SetTextColor(item->hDC,disabled?RGB(91,105,126):RGB(255,255,255));
        SelectObject(item->hDC,font);wchar_t text[80]{};GetWindowTextW(action,text,80);auto rect=item->rcItem;
        DrawTextW(item->hDC,text,-1,&rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        if(item->itemState&ODS_FOCUS){InflateRect(&rect,-scaled(4),-scaled(4));DrawFocusRect(item->hDC,&rect);}return TRUE;
    }
    case WM_DPICHANGED: {
        dpi=HIWORD(wp);set_fonts();const auto rect=reinterpret_cast<RECT*>(lp);
        SetWindowPos(window,nullptr,rect->left,rect->top,rect->right-rect->left,rect->bottom-rect->top,SWP_NOZORDER|SWP_NOACTIVATE);
        InvalidateRect(window,nullptr,TRUE);return 0;
    }
    case WM_COMMAND:
        if(LOWORD(wp)==1){
            if(succeeded){DestroyWindow(window);return 0;}
            try{
                start(ui_probe);EnableWindow(action,FALSE);
                status(L"Installing LanPilot",L"Checking the package and installing. Please keep this window open.",RGB(30,64,112));
                ShowWindow(progress,SW_SHOW);SendMessageW(progress,PBM_SETMARQUEE,TRUE,25);
                SetTimer(window,tick,100,nullptr);
            }catch(const std::exception&){
                cleanup();status(L"Setup could not start",L"Check that Windows PowerShell and your temporary folder are available, then retry.",RGB(170,45,45));
                if(ui_probe){probe_result=1;DestroyWindow(window);}
            }
        }else if(LOWORD(wp)==1002 && succeeded){
            ShellExecuteW(window,L"open",(install_root/L"LanPilot.exe").c_str(),nullptr,install_root.c_str(),SW_SHOWNORMAL);
        }else if(LOWORD(wp)==IDCANCEL){
            SendMessageW(window,WM_CLOSE,0,0);
        }
        return 0;
    case WM_TIMER:
        if(running && WaitForSingleObject(child,0)==WAIT_OBJECT_0){
            DWORD code{};GetExitCodeProcess(child,&code);running=false;succeeded=code==0;
            auto text=succeeded?std::wstring(L"Open LanPilot to connect. Your saved connections and keys were kept."):failure_message();
            status(succeeded?L"You're ready to connect":L"Installation needs attention",text,succeeded?RGB(28,112,78):RGB(170,45,45));
            SetWindowTextW(action,succeeded?L"Done":L"Retry");
            EnableWindow(action,TRUE);ShowWindow(progress,SW_HIDE);
            if(succeeded)ShowWindow(open_button,SW_SHOW);
            KillTimer(window,tick);cleanup();
            if(ui_probe){
                probe_result=succeeded && IsWindowEnabled(action) &&
                    (GetWindowLongW(open_button,GWL_STYLE)&WS_VISIBLE)?0:1;
                DestroyWindow(window);
            }
        }
        return 0;
    case WM_CLOSE:
        if(running){SetWindowTextW(status_text,L"Installation is in progress. Please wait for the result before closing.");return 0;}
        DestroyWindow(window);return 0;
    case WM_DESTROY:
        DeleteObject(font);DeleteObject(heading_font);DeleteObject(small_font);DeleteObject(background);DeleteObject(footer_background);PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(window,message,wp,lp);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int) {
    int argc{};auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    const bool verify=argc==2 && std::wstring(argv[1])==L"--check-package";
    const bool check_ui=argc==2 && std::wstring(argv[1])==L"--check-ui";
    const bool check_layout=argc==3 && std::wstring(argv[1])==L"--check-layout";
    const auto layout_path=check_layout?fs::path(argv[2]):fs::path{};
    pair_probe=argc==2 && std::wstring(argv[1])==L"--check-existing-pair";
    const bool valid=argc==1 || verify || check_ui || check_layout || pair_probe;
    LocalFree(argv);if(!valid)return ERROR_INVALID_PARAMETER;
    hidden=verify||check_ui||check_layout||pair_probe;
    ui_probe=check_ui;
    try {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        dpi=GetDpiForSystem();
        install_root=local_data()/L"Programs/LanPilot";
        if(verify||pair_probe){
            start(true);WaitForSingleObject(child,INFINITE);DWORD code{};GetExitCodeProcess(child,&code);
            running=false;cleanup();return static_cast<int>(code);
        }
        INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_PROGRESS_CLASS};InitCommonControlsEx(&controls);
        WNDCLASSW type{};type.lpfnWndProc=window_proc;type.hInstance=instance;
        type.hCursor=LoadCursorW(nullptr,MAKEINTRESOURCEW(32512));type.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
        type.lpszClassName=L"LanPilot.Setup";
        if(!RegisterClassW(&type))throw std::runtime_error("Cannot register setup window.");
        RECT size{0,0,scaled(600),scaled(530)};AdjustWindowRectExForDpi(&size,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,FALSE,0,dpi);
        auto window=CreateWindowW(type.lpszClassName,L"LanPilot - Install or update",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
            CW_USEDEFAULT,CW_USEDEFAULT,size.right-size.left,size.bottom-size.top,nullptr,nullptr,instance,nullptr);
        if(!window)throw std::runtime_error("Cannot create setup window.");
        if(check_layout){const auto ok=write_layout(window,layout_path);DestroyWindow(window);cleanup();return ok?0:1;}
        if(check_ui){
            if(!status_text || !action || !open_button || !progress){DestroyWindow(window);return 1;}
            PostMessageW(window,WM_COMMAND,1,0);
        }else{ShowWindow(window,SW_SHOWNORMAL);}
        MSG message{};
        while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
        cleanup();return check_ui?probe_result:0;
    }catch(const std::exception&){cleanup();if(!hidden)MessageBoxW(nullptr,L"LanPilot setup could not start. Please download the complete setup file and try again.",L"LanPilot Setup",MB_OK|MB_ICONERROR);return 1;}
}
