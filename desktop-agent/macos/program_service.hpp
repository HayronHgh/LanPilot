#pragma once

#include "program_install.hpp"
#include "service_lifecycle.hpp"

namespace rwn::agent::macos {
// Called only while the program transaction owns the product operation lease.
// The native adapter borrows that directory/lease; it must not call public login
// entry points, which would reacquire the same lock.
class ProgramLoginBackend {
public:
    virtual ~ProgramLoginBackend()=default;
    virtual bool context_valid()=0;
    virtual LoginRegistration registration()=0;
    virtual bool close_startup_gate()=0;
    virtual bool stop_verified_instance()=0;
    virtual bool probe_installed_code()=0;
    virtual bool start_fresh_instance()=0;
    virtual bool await_fresh_receipt()=0;
    virtual bool keep_disabled()=0;
};

class ProgramLoginHooks final:public ProgramServiceHooks {
public:
    explicit ProgramLoginHooks(ProgramLoginBackend& backend):backend_(backend){}
    bool initially_enabled() override {
        if(!backend_.context_valid())throw std::runtime_error("unsafe program service context");
        const auto state=backend_.registration();
        if(state==LoginRegistration::approval_required)
            throw std::runtime_error("login approval is pending");
        return state==LoginRegistration::enabled;
    }
    bool quiesce() override {
        return backend_.context_valid() && backend_.close_startup_gate() && backend_.stop_verified_instance();
    }
    bool accept_candidate(bool enabled) override{return resume(true,enabled);}
    bool resume_previous(bool had_previous,bool enabled) override{return resume(had_previous,enabled);}
private:
    bool resume(bool exists,bool enabled) {
        if(!backend_.context_valid())return false;
        if(!exists)return !enabled && backend_.keep_disabled();
        if(!backend_.probe_installed_code())return false;
        if(!enabled)return backend_.keep_disabled();
        return backend_.start_fresh_instance() && backend_.await_fresh_receipt();
    }
    ProgramLoginBackend& backend_;
};
} // namespace rwn::agent::macos
