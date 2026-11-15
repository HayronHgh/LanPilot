#pragma once

#include "product_configuration.hpp"
#include <exception>

namespace rwn::agent::macos {
enum class LoginPhase { none, authorizing, prepared, retired, starting, active, restored, restoring, rollback_failed };
enum class LoginRegistration { absent, approval_required, enabled };
enum class LoginResult { active, approval_required, not_ready, restored, recovery_required };

inline constexpr std::array<std::string_view,9> login_phase_names{
    "none","authorizing","prepared","retired","starting","active","restored","restoring","rollback_failed"};
struct LoginJournal {
    LoginPhase phase{LoginPhase::none};
    std::string nonce,configuration_hash,legacy_hash{"-"};
    bool legacy_present{},legacy_running{};
};
inline std::string serialize_login_journal(const LoginJournal& record){
    const auto index=static_cast<std::size_t>(record.phase);
    if(index>=login_phase_names.size() || !lowercase_hex(record.nonce,32,32) ||
       !lowercase_hex(record.configuration_hash,64,64) ||
       (record.legacy_present?!lowercase_hex(record.legacy_hash,64,64):record.legacy_hash!="-") ||
       (record.legacy_running && !record.legacy_present))
        throw std::invalid_argument("invalid login migration journal");
    return "schema=1\nphase="+std::string(login_phase_names[index])+"\nnonce="+record.nonce+
        "\nconfiguration_hash="+record.configuration_hash+"\nlegacy_hash="+record.legacy_hash+
        "\nlegacy_present="+(record.legacy_present?"true":"false")+
        "\nlegacy_running="+(record.legacy_running?"true\n":"false\n");
}
inline LoginJournal parse_login_journal(std::string_view text){
    if(text.empty() || text.size()>1024 || text.back()!='\n')throw std::invalid_argument("invalid journal size");
    std::map<std::string,std::string,std::less<>> fields;
    while(!text.empty()){
        const auto end=text.find('\n'),separator=text.find('=');
        if(separator==std::string_view::npos || separator>=end || separator==0 || separator+1==end ||
           !fields.emplace(std::string(text.substr(0,separator)),std::string(text.substr(separator+1,end-separator-1))).second)
            throw std::invalid_argument("invalid journal field");
        text.remove_prefix(end+1);
    }
    constexpr std::array<std::string_view,7> keys{"schema","phase","nonce","configuration_hash","legacy_hash","legacy_present","legacy_running"};
    if(fields.size()!=keys.size())throw std::invalid_argument("unknown journal field");
    for(const auto key:keys)if(!fields.contains(key))throw std::invalid_argument("missing journal field");
    if(fields.at("schema")!="1")throw std::invalid_argument("unknown journal schema");
    auto boolean=[&](const char* key){
        const auto& value=fields.at(key);
        if(value!="true" && value!="false")throw std::invalid_argument("invalid journal boolean");
        return value=="true";
    };
    std::size_t index=0;
    while(index<login_phase_names.size() && login_phase_names[index]!=fields.at("phase"))++index;
    if(index==login_phase_names.size())throw std::invalid_argument("unknown login phase");
    LoginJournal record{static_cast<LoginPhase>(index),fields.at("nonce"),fields.at("configuration_hash"),
        fields.at("legacy_hash"),boolean("legacy_present"),boolean("legacy_running")};
    (void)serialize_login_journal(record);return record;
}

// The same coordinator drives native operations and fault-injection workflows.
// Its backend owns the operation lease and validates all persistent records.
class LoginBackend {
public:
    virtual ~LoginBackend()=default;
    virtual bool preflight()=0;
    virtual bool activation_ready(){return preflight();}
    virtual LoginPhase phase()=0;
    virtual bool prepare()=0;
    virtual bool persist(LoginPhase)=0;
    virtual LoginRegistration registration()=0;
    virtual bool register_canonical()=0;
    virtual bool stop_canonical()=0;
    virtual bool stop_legacy()=0;
    virtual bool retire_legacy()=0;
    virtual bool restore_legacy()=0;
    virtual bool receipt_valid()=0;
    virtual bool await_receipt()=0;
};

inline LoginResult restore_login_owner(LoginBackend& backend){
    try {
        // Never restore an old job while a new owner may still be alive.
        // Close the durable startup gate BEFORE unregistering. A late/new
        // launch must not race restoration of the legacy job.
        if(!backend.persist(LoginPhase::restoring) || !backend.stop_canonical() ||
           !backend.restore_legacy() || !backend.persist(LoginPhase::restored)){
            (void)backend.persist(LoginPhase::rollback_failed);
            return LoginResult::recovery_required;
        }
        return LoginResult::restored;
    } catch(const std::exception&){
        try{(void)backend.persist(LoginPhase::rollback_failed);}catch(const std::exception&){}
        return LoginResult::recovery_required;
    }
}

inline LoginResult recover_login_owner(LoginBackend& backend){
    if(!backend.preflight())return LoginResult::not_ready;
    const auto phase=backend.phase();
    if(phase==LoginPhase::none || phase==LoginPhase::restored)return LoginResult::restored;
    // Authorization has not touched the old owner. Do not repeatedly register,
    // restart it, or undo a person's pending System Settings approval on launch.
    if(phase==LoginPhase::authorizing)return LoginResult::approval_required;
    if(phase==LoginPhase::active)return backend.receipt_valid()?LoginResult::active:LoginResult::not_ready;
    if(phase==LoginPhase::starting && backend.receipt_valid() && backend.persist(LoginPhase::active))
        return LoginResult::active;
    return restore_login_owner(backend);
}

inline LoginResult activate_login_owner(LoginBackend& backend){
    if(!backend.activation_ready())return LoginResult::not_ready;
    try {
        const auto current=backend.phase();
        if(current==LoginPhase::active && backend.receipt_valid())return LoginResult::active;
        if(current!=LoginPhase::none && current!=LoginPhase::authorizing && current!=LoginPhase::restored){
            if(recover_login_owner(backend)==LoginResult::recovery_required)return LoginResult::recovery_required;
            if(backend.phase()==LoginPhase::active){
                if(backend.receipt_valid())return LoginResult::active;
                if(restore_login_owner(backend)!=LoginResult::restored)return LoginResult::recovery_required;
            }
        }
        if(!backend.prepare() || !backend.persist(LoginPhase::authorizing))return LoginResult::not_ready;
        // Preauthorize the new login item while the journal prevents its service
        // endpoint from starting. The legacy owner remains fully operational.
        if(backend.registration()!=LoginRegistration::enabled && !backend.register_canonical()){
            if(backend.registration()==LoginRegistration::approval_required)return LoginResult::approval_required;
            return restore_login_owner(backend);
        }
        if(backend.registration()==LoginRegistration::approval_required)return LoginResult::approval_required;
        if(backend.registration()!=LoginRegistration::enabled)return restore_login_owner(backend);
        if(!backend.stop_canonical() || !backend.persist(LoginPhase::prepared) ||
           !backend.stop_legacy() || !backend.retire_legacy() || !backend.persist(LoginPhase::retired) ||
           !backend.persist(LoginPhase::starting) || !backend.register_canonical() ||
           backend.registration()!=LoginRegistration::enabled || !backend.await_receipt() ||
           !backend.persist(LoginPhase::active))return restore_login_owner(backend);
        return LoginResult::active;
    } catch(const std::exception&){return restore_login_owner(backend);}
}
} // namespace rwn::agent::macos
