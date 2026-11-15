#pragma once
#include "rwn/core/cancellation.hpp"
#include "rwn/transport/tls_byte_channel.hpp"
#include <windows.h>
#include <atomic>
#include <exception>
#include <functional>
#include <optional>
#include <thread>
#include <utility>

namespace rwn::viewer {
// The worker owns all partially established state until the UI takes a fully
// verified result. It is always joined; cancellation never detaches work.
template<class Result> class ConnectionStartup final {
    struct Event {
        HANDLE value{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
        Event(){if(!value)throw std::runtime_error("connection event creation failed");}
        ~Event(){CloseHandle(value);}
    } ready_;
    core::CancellationSource stop_;
    std::optional<Result> result_;
    std::exception_ptr error_;
    std::atomic_bool done_{};
    bool taken_{};
    std::jthread worker_;
public:
    template<class Work> explicit ConnectionStartup(Work work){
        worker_=std::jthread([this,work=std::move(work)]()mutable{
            try{result_.emplace(work(stop_.token()));}catch(...){error_=std::current_exception();}
            done_.store(true,std::memory_order_release);SetEvent(ready_.value);
        });
    }
    ConnectionStartup(const ConnectionStartup&)=delete;
    ConnectionStartup& operator=(const ConnectionStartup&)=delete;
    ~ConnectionStartup(){if(!taken_)cancel();if(worker_.joinable())worker_.join();}
    void cancel()noexcept{stop_.request_stop();}
    bool ready()const noexcept{return done_.load(std::memory_order_acquire);}
    HANDLE event()const noexcept{return ready_.value;}
    Result take(){
        if(!ready())throw std::logic_error("connection is not ready");
        if(worker_.joinable())worker_.join();
        if(stop_.token().stop_requested())throw transport::TlsTransportInterrupted(transport::TlsTransportInterrupted::Reason::cancelled,"connection startup cancelled");
        if(error_)std::rethrow_exception(error_);
        if(!result_ || taken_)throw std::logic_error("connection result already consumed");
        taken_=true;return std::move(*result_);
    }
};

template<class Startup> bool wait_for_connection(HWND window,Startup& startup,const std::function<bool()>& keep_running = {}){
    for(;;){
        MSG message{};
        while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){
            if(message.message==WM_QUIT){startup.cancel();return false;}
            TranslateMessage(&message);DispatchMessageW(&message);
        }
        if(!IsWindow(window) || (keep_running && !keep_running())){startup.cancel();return false;}
        if(startup.ready())return true;
        const auto event=startup.event();
        if(MsgWaitForMultipleObjectsEx(1,&event,INFINITE,QS_ALLINPUT,MWMO_INPUTAVAILABLE)==WAIT_FAILED){
            startup.cancel();throw std::runtime_error("connection message wait failed");
        }
    }
}
}
