#include "../desktop-agent/macos/service_lifecycle.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace lp=rwn::agent::macos;
namespace {
void check(bool value){if(!value)throw std::runtime_error("login lifecycle invariant failed");}
struct PowerLoss {}; // Deliberately bypasses normal exception rollback.
class Fixture final:public lp::LoginBackend {
public:
    lp::LoginPhase state{lp::LoginPhase::none};
    lp::LoginRegistration approval{lp::LoginRegistration::absent};
    bool allowed{true},old_running{true},old_file{true},new_running{},new_receipt{},needs_approval{};
    bool refuse_stop{},restore_ok{true},can_activate{true};
    unsigned operations{},fail_at{},crash_at{};
    std::vector<std::string> events;
    bool step(std::string name){
        check(!(old_running && new_running));events.push_back(std::move(name));++operations;
        if(operations==crash_at)throw PowerLoss{};
        return operations!=fail_at;
    }
    bool preflight() override{return allowed;}
    bool activation_ready() override{return allowed && can_activate;}
    lp::LoginPhase phase() override{return state;}
    bool prepare() override{return step("prepare");}
    bool persist(lp::LoginPhase phase) override{
        if(!step("journal"))return false;
        state=phase;return true;
    }
    lp::LoginRegistration registration() override{return approval;}
    bool register_canonical() override{
        if(!step("register"))return false;
        approval=needs_approval?lp::LoginRegistration::approval_required:lp::LoginRegistration::enabled;
        if(state==lp::LoginPhase::starting && approval==lp::LoginRegistration::enabled){
            check(!old_running && !old_file);new_running=true;new_receipt=true;
        }
        return true;
    }
    bool stop_canonical() override{
        if(!step("stop_new") || refuse_stop)return false;
        new_running=false;new_receipt=false;approval=lp::LoginRegistration::absent;return true;
    }
    bool stop_legacy() override{if(!step("stop_old"))return false;old_running=false;return true;}
    bool retire_legacy() override{
        if(!step("retire_old"))return false;
        check(!old_running);old_file=false;return true;
    }
    bool restore_legacy() override{
        if(!step("restore_old") || !restore_ok)return false;
        check(!new_running);old_running=true;old_file=true;return true;
    }
    bool receipt_valid() override{return new_running && new_receipt;}
    bool await_receipt() override{return step("receipt") && receipt_valid();}
};
}
int main(){
    try {
        const lp::LoginJournal journal{lp::LoginPhase::starting,std::string(32,'a'),std::string(64,'b'),std::string(64,'c'),true,true};
        const auto encoded=lp::serialize_login_journal(journal);
        check(lp::serialize_login_journal(lp::parse_login_journal(encoded))==encoded);
        for(const auto& invalid:{encoded+"phase=active\n",encoded+"command=unexpected\n",
            encoded.substr(0,encoded.size()-1),std::string(1025,'x')}){
            bool rejected=false;try{(void)lp::parse_login_journal(invalid);}catch(const std::invalid_argument&){rejected=true;}
            check(rejected);
        }
        Fixture ordinary;check(lp::activate_login_owner(ordinary)==lp::LoginResult::active);
        check(ordinary.new_running && !ordinary.old_running && !ordinary.old_file);
        const auto operations=ordinary.operations;
        check(lp::activate_login_owner(ordinary)==lp::LoginResult::active && ordinary.operations==operations);
        Fixture stopped;stopped.state=lp::LoginPhase::active;stopped.old_running=false;stopped.old_file=false;
        check(lp::recover_login_owner(stopped)==lp::LoginResult::not_ready && stopped.operations==0);
        check(lp::activate_login_owner(stopped)==lp::LoginResult::active && stopped.new_running && !stopped.old_running);
        Fixture denied;denied.allowed=false;
        check(lp::activate_login_owner(denied)==lp::LoginResult::not_ready && denied.operations==0 && denied.old_running);
        Fixture approval;approval.needs_approval=true;
        check(lp::activate_login_owner(approval)==lp::LoginResult::approval_required && approval.old_running && approval.old_file && !approval.new_running);
        const auto before=approval.operations;
        check(lp::recover_login_owner(approval)==lp::LoginResult::approval_required && approval.operations==before);
        approval.needs_approval=false;approval.approval=lp::LoginRegistration::enabled;
        check(lp::activate_login_owner(approval)==lp::LoginResult::active && !approval.old_running);
        for(unsigned fault=1;fault<=operations;++fault){
            Fixture failing;failing.fail_at=fault;
            const auto result=lp::activate_login_owner(failing);
            check(result!=lp::LoginResult::active && !(failing.old_running && failing.new_running));
            if(failing.state!=lp::LoginPhase::none && failing.state!=lp::LoginPhase::restored){
                failing.fail_at=0;(void)lp::recover_login_owner(failing);
            }
            check(failing.old_running && failing.old_file && !failing.new_running);
        }
        for(unsigned crash=1;crash<=operations;++crash){
            Fixture interrupted;interrupted.crash_at=crash;
            try{(void)lp::activate_login_owner(interrupted);}catch(const PowerLoss&){}
            interrupted.crash_at=0;
            const auto result=lp::recover_login_owner(interrupted);
            check(!(interrupted.old_running && interrupted.new_running));
            if(result==lp::LoginResult::active)check(interrupted.new_running && interrupted.new_receipt && !interrupted.old_file);
            else check(interrupted.old_running && interrupted.old_file && !interrupted.new_running);
        }
        Fixture unsafe;unsafe.state=lp::LoginPhase::starting;unsafe.old_running=false;unsafe.old_file=false;
        unsafe.new_running=true;unsafe.refuse_stop=true;
        check(lp::recover_login_owner(unsafe)==lp::LoginResult::recovery_required && !unsafe.old_running);
        unsafe.refuse_stop=false;
        check(lp::recover_login_owner(unsafe)==lp::LoginResult::restored && unsafe.old_running && !unsafe.new_running);
        Fixture lost_grant;lost_grant.state=lp::LoginPhase::starting;lost_grant.old_running=false;lost_grant.old_file=false;
        lost_grant.can_activate=false;
        check(lp::activate_login_owner(lost_grant)==lp::LoginResult::not_ready && lost_grant.operations==0);
        check(lp::recover_login_owner(lost_grant)==lp::LoginResult::restored && lost_grant.old_running);
        for(unsigned fault=1;fault<=4;++fault){
            Fixture recovery;recovery.state=lp::LoginPhase::starting;recovery.old_running=false;recovery.old_file=false;
            recovery.new_running=true;recovery.fail_at=fault;
            (void)lp::recover_login_owner(recovery);
            check(!(recovery.old_running && recovery.new_running));
            recovery.fail_at=0;
            check(lp::recover_login_owner(recovery)==lp::LoginResult::restored && recovery.old_running && !recovery.new_running);
        }
        for(unsigned crash=1;crash<=4;++crash){
            Fixture recovery;recovery.state=lp::LoginPhase::starting;recovery.old_running=false;recovery.old_file=false;
            recovery.new_running=true;recovery.crash_at=crash;
            try{(void)lp::recover_login_owner(recovery);}catch(const PowerLoss&){}
            check(!(recovery.old_running && recovery.new_running));recovery.crash_at=0;
            check(lp::recover_login_owner(recovery)==lp::LoginResult::restored && recovery.old_running && !recovery.new_running);
        }
        std::cout<<"login_service_workflow=PASS fault_boundaries="<<operations<<" native_operations=0\n";return 0;
    } catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
