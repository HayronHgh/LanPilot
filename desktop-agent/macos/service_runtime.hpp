#pragma once
#include "product_configuration.hpp"
#include "../run_audit.hpp"
#include <optional>
#include <limits>

namespace rwn::agent::macos {
enum class RuntimePhase { preflight, pending, stopped_none, stopped_released, stop_failed };
inline constexpr std::array<std::string_view,5> runtime_phase_names{
    "preflight","pending","stopped_none","stopped_released","stop_failed"};
inline constexpr unsigned maximum_tracked_input=65535+8;
struct ServiceRuntime {
    std::string instance,configuration_hash;
    unsigned pid{};
    RuntimePhase phase{RuntimePhase::preflight};
    unsigned exit_code{},released{},remaining{};
    std::uint64_t process_start_us{};
    bool operator==(const ServiceRuntime&) const=default;
};
inline std::string serialize_service_runtime(const ServiceRuntime& record) {
    const auto phase=static_cast<std::size_t>(record.phase);
    if(!lowercase_hex(record.instance,32,32) || !lowercase_hex(record.configuration_hash,64,64) ||
       record.pid==0 || record.pid>2147483647 || !record.process_start_us || phase>=runtime_phase_names.size() ||
       record.exit_code>255 || record.released>maximum_tracked_input ||
       record.remaining>maximum_tracked_input-record.released ||
       ((record.phase==RuntimePhase::preflight || record.phase==RuntimePhase::pending) &&
          (record.exit_code || record.released || record.remaining)) ||
       (record.phase==RuntimePhase::stopped_none && (record.released || record.remaining)) ||
       (record.phase==RuntimePhase::stopped_released && record.remaining))
        throw std::invalid_argument("invalid service runtime record");
    return "schema=1\ninstance="+record.instance+"\npid="+std::to_string(record.pid)+
        "\nprocess_start_us="+std::to_string(record.process_start_us)+
        "\nconfiguration_hash="+record.configuration_hash+"\nphase="+std::string(runtime_phase_names[phase])+
        "\nexit_code="+std::to_string(record.exit_code)+"\nreleased="+std::to_string(record.released)+
        "\nremaining="+std::to_string(record.remaining)+"\n";
}
inline ServiceRuntime parse_service_runtime(std::string_view text) {
    if(text.empty() || text.size()>1024 || text.back()!='\n')throw std::invalid_argument("invalid runtime record size");
    std::map<std::string,std::string,std::less<>> fields;
    while(!text.empty()){
        const auto end=text.find('\n'),separator=text.find('=');
        if(separator==std::string_view::npos || separator==0 || separator>=end || separator+1==end ||
           !fields.emplace(std::string(text.substr(0,separator)),std::string(text.substr(separator+1,end-separator-1))).second)
            throw std::invalid_argument("invalid runtime record field");
        text.remove_prefix(end+1);
    }
    constexpr std::array<std::string_view,9> keys{"schema","instance","pid","process_start_us","configuration_hash","phase","exit_code","released","remaining"};
    if(fields.size()!=keys.size())throw std::invalid_argument("unknown runtime field");
    for(auto key:keys)if(!fields.contains(key))throw std::invalid_argument("missing runtime field");
    if(fields.at("schema")!="1")throw std::invalid_argument("unknown runtime schema");
    const auto& time=fields.at("process_start_us");std::uint64_t started{};
    const auto parsed=std::from_chars(time.data(),time.data()+time.size(),started);
    if(time.empty() || (time.size()>1 && time.front()=='0') || parsed.ec!=std::errc{} || parsed.ptr!=time.data()+time.size())
        throw std::invalid_argument("invalid process start time");
    std::size_t phase{};while(phase<runtime_phase_names.size() && runtime_phase_names[phase]!=fields.at("phase"))++phase;
    ServiceRuntime record{fields.at("instance"),fields.at("configuration_hash"),
        canonical_unsigned(fields.at("pid"),2147483647),static_cast<RuntimePhase>(phase),
        canonical_unsigned(fields.at("exit_code"),255),canonical_unsigned(fields.at("released"),maximum_tracked_input),
        canonical_unsigned(fields.at("remaining"),maximum_tracked_input),started};
    (void)serialize_service_runtime(record);return record;
}
inline bool safe_input_exit(const ServiceRuntime& record) {
    (void)serialize_service_runtime(record);
    return record.phase==RuntimePhase::preflight || record.phase==RuntimePhase::stopped_none ||
        record.phase==RuntimePhase::stopped_released;
}
inline void validate_runtime_transition(const std::optional<ServiceRuntime>& previous,const ServiceRuntime& next) {
    (void)serialize_service_runtime(next);
    if(!previous){
        if(next.phase!=RuntimePhase::preflight)throw std::invalid_argument("runtime must begin in preflight");
        return;
    }
    (void)serialize_service_runtime(*previous);
    if(*previous==next)return;
    if(previous->instance!=next.instance){
        if(!safe_input_exit(*previous) || next.phase!=RuntimePhase::preflight)
            throw std::invalid_argument("unsafe previous runtime instance");
        return;
    }
    if(previous->pid!=next.pid || previous->process_start_us!=next.process_start_us || previous->configuration_hash!=next.configuration_hash)
        throw std::invalid_argument("runtime identity changed");
    if(previous->phase==RuntimePhase::preflight && next.phase==RuntimePhase::pending)return;
    if(previous->phase==RuntimePhase::pending && (next.phase==RuntimePhase::stopped_none ||
       next.phase==RuntimePhase::stopped_released || next.phase==RuntimePhase::stop_failed))return;
    throw std::invalid_argument("invalid runtime phase transition");
}
inline ServiceRuntime finish_service_runtime(ServiceRuntime record,RunAuditResult result,int exit_code) {
    if(record.phase!=RuntimePhase::pending || exit_code<0 || exit_code>255 ||
       result.released>maximum_tracked_input || result.remaining>maximum_tracked_input-result.released)
        throw std::invalid_argument("invalid runtime completion");
    record.exit_code=static_cast<unsigned>(exit_code);record.released=static_cast<unsigned>(result.released);
    record.remaining=static_cast<unsigned>(result.remaining);
    switch(result.input){
        case InputExit::never_started:record.phase=RuntimePhase::stopped_none;break;
        case InputExit::released:record.phase=RuntimePhase::stopped_released;break;
        default:record.phase=RuntimePhase::stop_failed;break;
    }
    (void)serialize_service_runtime(record);return record;
}
inline bool runtime_stop_proven(const ServiceRuntime& expected,const ServiceRuntime& final,
                               bool process_gone,bool job_gone,bool lease_free) {
    (void)serialize_service_runtime(expected);(void)serialize_service_runtime(final);
    if(!process_gone || !job_gone || !lease_free || expected.instance!=final.instance ||
       expected.pid!=final.pid || expected.process_start_us!=final.process_start_us || expected.configuration_hash!=final.configuration_hash ||
       !safe_input_exit(final))return false;
    if(expected.phase==RuntimePhase::stop_failed)return false;
    if(expected.phase==RuntimePhase::pending && final.phase==RuntimePhase::preflight)return false;
    if(expected.phase==RuntimePhase::stopped_none || expected.phase==RuntimePhase::stopped_released)return expected==final;
    return true;
}
// The native implementation owns the lifecycle lease and verifies the running
// publisher/mandatory-record contract. Tests replace only OS operations.
class RuntimeStopBackend {
public:
    virtual ~RuntimeStopBackend()=default;
    virtual bool contract_verified()=0;
    virtual bool original_process_gone()=0;
    virtual std::optional<ServiceRuntime> record()=0;
    virtual bool unregister_service()=0;
    virtual bool await_stopped()=0;
    virtual bool process_gone(const ServiceRuntime&)=0;
    virtual bool job_gone()=0;
    virtual bool lease_free()=0;
};
inline bool quiesce_runtime(RuntimeStopBackend& backend) {
    if(!backend.contract_verified())return false;
    auto expected=backend.record();
    if(!backend.unregister_service() || !backend.await_stopped() ||
       !backend.original_process_gone() || !backend.job_gone() || !backend.lease_free())return false;
    const auto final=backend.record();
    // Verified contract: delegation cannot precede the durable pending record.
    // An absent record is safe ONLY if no prior record was observed either.
    if(!final)return !expected;
    if(!expected)expected=final;
    return runtime_stop_proven(*expected,*final,backend.process_gone(*expected),true,true);
}
inline std::string serialize_service_ready(const ServiceRuntime& runtime,std::string_view activation_nonce) {
    (void)serialize_service_runtime(runtime);
    if(runtime.phase!=RuntimePhase::pending || !lowercase_hex(activation_nonce,32,32))
        throw std::invalid_argument("invalid service readiness record");
    return "schema=1\nnonce="+std::string(activation_nonce)+"\ninstance="+runtime.instance+
        "\npid="+std::to_string(runtime.pid)+"\nprocess_start_us="+std::to_string(runtime.process_start_us)+
        "\nconfiguration_hash="+runtime.configuration_hash+
        "\ncapture_verified=true\nidentity_checked=true\n";
}
inline bool fresh_service_ready(const ServiceRuntime& current,const std::optional<ServiceRuntime>& previous,std::string_view configuration_hash){
    (void)serialize_service_runtime(current);
    if(current.phase!=RuntimePhase::pending || current.configuration_hash!=configuration_hash)return false;
    if(!previous)return true;
    (void)serialize_service_runtime(*previous);
    return safe_input_exit(*previous) && current.instance!=previous->instance &&
        (current.pid!=previous->pid || current.process_start_us!=previous->process_start_us);
}
} // namespace rwn::agent::macos
