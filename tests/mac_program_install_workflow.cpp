#include "../desktop-agent/macos/program_install.hpp"
#include "../desktop-agent/macos/program_service.hpp"
#include "../desktop-agent/macos/service_runtime.hpp"
#include "../desktop-agent/macos/program_update.hpp"

#include <iostream>
#include <stdexcept>

namespace lp=rwn::agent::macos;
namespace {
void check(bool value){if(!value)throw std::runtime_error("program update invariant failed");}
struct PowerLoss{};
class LoginFixture final:public lp::ProgramLoginBackend {
public:
    bool safe{true},gate{},stopped{},probed{},started{},fresh{true},disabled{},healthy{true};
    bool fail_stop{},fail_probe{},fail_start{};
    lp::LoginRegistration state{lp::LoginRegistration::enabled};
    std::vector<std::string> events;
    bool context_valid()override{events.emplace_back("context");return safe;}
    lp::LoginRegistration registration()override{events.emplace_back("registration");return state;}
    bool close_startup_gate()override{events.emplace_back("gate");gate=true;return true;}
    bool stop_verified_instance()override{events.emplace_back("stop");check(gate);stopped=!fail_stop;return stopped;}
    bool probe_installed_code()override{events.emplace_back("probe");check(stopped);probed=true;return !fail_probe;}
    bool start_fresh_instance()override{events.emplace_back("start");check(probed && stopped);started=true;return !fail_start;}
    bool await_fresh_receipt()override{events.emplace_back("receipt");check(started);return fresh && healthy;}
    bool keep_disabled()override{events.emplace_back("disabled");check(stopped);disabled=true;return true;}
};
void service_workflow(){
    check(lp::release_public_key("").empty());
    check(lp::release_public_key(std::string(128,'a')).size()==64);
    for(const auto& invalid:std::vector<std::string>{std::string(128,'0'),std::string(126,'a'),std::string(128,'F'),std::string(127,'a')+"g",std::string(128,'a')+"\n"}){
        bool rejected_key=false;try{(void)lp::release_public_key(invalid);}catch(const std::invalid_argument&){rejected_key=true;}
        check(rejected_key);
    }
    const rwn::core::UpdateManifest selected{{1,2,0},{1,0,0},"macos-app-inventory","universal2",std::string(64,'a'),17,1,1,"ecdsa-p256-sha256",std::string(128,'b')};
    const auto confirmation=lp::program_offer_token(selected);
    check(lp::lowercase_hex(confirmation,64,64));
    for(unsigned field=0;field<9;++field){
        auto changed=selected;
        switch(field){
            case 0:changed.version.patch=1;break;
            case 1:changed.minimum_installed_version.patch=1;break;
            case 2:changed.platform="other-platform";break;
            case 3:changed.architecture="arm64";break;
            case 4:changed.package_sha256[0]='c';break;
            case 5:++changed.package_size;break;
            case 6:++changed.state_schema;break;
            case 7:++changed.package_schema;break;
            default:changed.signature_hex[0]='c';break;
        }
        check(lp::program_offer_token(changed)!=confirmation);
    }
    LoginFixture native;lp::ProgramLoginHooks hooks(native);
    check(hooks.initially_enabled() && hooks.quiesce() && hooks.accept_candidate(true));
    check(native.events==std::vector<std::string>{"context","registration","context","gate","stop","context","probe","start","receipt"});
    LoginFixture idle;idle.state=lp::LoginRegistration::absent;lp::ProgramLoginHooks disabled(idle);
    check(!disabled.initially_enabled() && disabled.quiesce() && disabled.accept_candidate(false));
    check(idle.disabled && !idle.started);
    LoginFixture denied;denied.safe=false;lp::ProgramLoginHooks unsafe(denied);
    bool rejected=false;try{(void)unsafe.initially_enabled();}catch(const std::runtime_error&){rejected=true;}
    check(rejected && !unsafe.quiesce() && !denied.gate);
    LoginFixture approval;approval.state=lp::LoginRegistration::approval_required;lp::ProgramLoginHooks pending(approval);
    rejected=false;try{(void)pending.initially_enabled();}catch(const std::runtime_error&){rejected=true;}
    check(rejected && !approval.gate);
    for(unsigned stage=0;stage<4;++stage){
        LoginFixture failing;failing.fail_stop=stage==0;failing.fail_probe=stage==1;
        failing.fail_start=stage==2;failing.fresh=stage!=3;lp::ProgramLoginHooks failed(failing);
        const bool quiet=failed.quiesce();
        check(stage==0?!quiet:quiet && !failed.accept_candidate(true));
        if(stage<=1)check(!failing.started);
    }
    LoginFixture returning;lp::ProgramLoginHooks rollback(returning);
    check(rollback.quiesce() && rollback.resume_previous(true,true) && returning.started);
    LoginFixture first;lp::ProgramLoginHooks no_previous(first);
    check(no_previous.quiesce() && no_previous.resume_previous(false,false) && first.disabled && !first.probed);
    check(!no_previous.resume_previous(false,true));
    lp::ServiceRuntime previous{std::string(32,'a'),std::string(64,'b'),123,lp::RuntimePhase::stopped_released,0,2,0,100};
    auto current=previous;current.instance=std::string(32,'c');current.pid=124;current.process_start_us=101;
    current.phase=lp::RuntimePhase::pending;current.released=0;
    check(lp::fresh_service_ready(current,previous,previous.configuration_hash));
    check(!lp::fresh_service_ready(current,previous,std::string(64,'d')));
    auto stale=current;stale.instance=previous.instance;
    check(!lp::fresh_service_ready(stale,previous,previous.configuration_hash));
    stale=current;stale.pid=previous.pid;stale.process_start_us=previous.process_start_us;
    check(!lp::fresh_service_ready(stale,previous,previous.configuration_hash));
    stale=current;stale.phase=lp::RuntimePhase::preflight;
    check(!lp::fresh_service_ready(stale,previous,previous.configuration_hash));
    auto pending_old=previous;pending_old.phase=lp::RuntimePhase::pending;pending_old.released=0;
    check(!lp::fresh_service_ready(current,pending_old,previous.configuration_hash));
    lp::ProgramJournal journal{lp::ProgramPhase::prepared,std::string(64,'a'),std::string(64,'b'),{1,2,0},{1,1,0},true};
    for(unsigned i=0;i<lp::program_phase_names.size();++i){
        journal.phase=static_cast<lp::ProgramPhase>(i);
        const bool target=journal.phase==lp::ProgramPhase::activated || journal.phase==lp::ProgramPhase::committed;
        const bool old=journal.phase==lp::ProgramPhase::restoring || journal.phase==lp::ProgramPhase::rolled_back;
        check(lp::program_runtime_generation_allowed(journal,journal.target_digest,journal.target_version)==target);
        check(lp::program_runtime_generation_allowed(journal,journal.previous_digest,journal.previous_version)==old);
        check(!lp::program_runtime_generation_allowed(journal,journal.target_digest,journal.previous_version));
    }
}
class Fixture final:public lp::ProgramBackend {
public:
    lp::ProgramPhase state{lp::ProgramPhase::none};
    bool verified{true},same{},candidate{},old_present{true},active_new{},running{true},healthy_result{true};
    unsigned operations{},fail_at{},crash_at{},stops{};
    bool step(){++operations;if(operations==crash_at)throw PowerLoss{};return operations!=fail_at;}
    lp::ProgramPhase phase()override{return state;}
    bool recovery_ready()override{return verified;}
    bool stage_verified()override{if(!verified || !step())return false;candidate=true;return true;}
    bool unchanged()override{return same;}
    bool prepare()override{if(!step())return false;state=lp::ProgramPhase::prepared;return true;}
    bool persist(lp::ProgramPhase next)override{if(!step())return false;state=next;return true;}
    bool quiesce()override{++stops;if(!step())return false;running=false;return true;}
    bool exchange()override{if(!step())return false;check(!running && candidate);active_new=true;return true;}
    bool healthy()override{if(!step() || !healthy_result)return false;check(active_new);running=true;return true;}
    bool restore_slots()override{if(!step())return false;check(!running);active_new=false;return true;}
    bool resume_previous()override{if(!step())return false;check(!active_new);running=old_present;return true;}
    bool finish_commit()override{if(!step())return false;check(active_new && running);candidate=false;return true;}
    bool finish_rollback()override{if(!step())return false;check(!active_new);candidate=false;return true;}
};
}
int main(){
    try {
        service_workflow();
        lp::ProgramJournal journal{lp::ProgramPhase::prepared,std::string(64,'a'),std::string(64,'b'),{1,2,0},{1,1,0},true};
        const auto text=lp::serialize_program_journal(journal);
        check(lp::serialize_program_journal(lp::parse_program_journal(text))==text);
        for(const auto& invalid:{text+"path=/tmp/escape\n",text+"phase=committed\n",text.substr(0,text.size()-1),std::string(1025,'x')}){
            bool denied=false;try{(void)lp::parse_program_journal(invalid);}catch(const std::invalid_argument&){denied=true;}
            check(denied);
        }
        Fixture success;check(lp::apply_program(success)==lp::ProgramResult::active);
        const unsigned count=success.operations;
        Fixture untrusted;untrusted.verified=false;
        check(lp::apply_program(untrusted)==lp::ProgramResult::rejected && untrusted.stops==0 && untrusted.running);
        Fixture same;same.same=true;
        check(lp::apply_program(same)==lp::ProgramResult::unchanged && same.stops==0 && same.running);
        Fixture unhealthy;unhealthy.healthy_result=false;
        check(lp::apply_program(unhealthy)==lp::ProgramResult::rolled_back && unhealthy.running && !unhealthy.active_new);
        for(unsigned fault=1;fault<=count;++fault){
            Fixture instance;instance.fail_at=fault;(void)lp::apply_program(instance);
            instance.fail_at=0;
            const auto result=lp::recover_program(instance);
            if(result==lp::ProgramResult::active)check(instance.active_new && instance.running);
            else check(!instance.active_new && instance.running);
        }
        for(unsigned crash=1;crash<=count;++crash){
            Fixture instance;instance.crash_at=crash;
            try{(void)lp::apply_program(instance);}catch(const PowerLoss&){}
            instance.crash_at=0;
            const auto result=lp::recover_program(instance);
            if(result==lp::ProgramResult::active)check(instance.active_new && instance.running);
            else check(!instance.active_new && instance.running);
        }
        Fixture fresh;fresh.old_present=false;fresh.healthy_result=false;fresh.running=false;
        check(lp::apply_program(fresh)==lp::ProgramResult::rolled_back && !fresh.running && !fresh.active_new);
        std::cout<<"mac_program_install=PASS fault_boundaries="<<count<<" native_operations=0\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
