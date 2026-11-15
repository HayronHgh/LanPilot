#pragma once

#include "product_configuration.hpp"
#include "rwn/core/release_compatibility.hpp"

#include <filesystem>

namespace rwn::agent::macos {
enum class ProgramPhase { none, staging, prepared, activated, committed, restoring, rolled_back, recovery_failed };
enum class ProgramResult { active, unchanged, rejected, rolled_back, recovery_required };
inline constexpr std::array<std::string_view,8> program_phase_names{
    "none","staging","prepared","activated","committed","restoring","rolled_back","recovery_failed"};

struct ProgramJournal {
    ProgramPhase phase{ProgramPhase::none};
    std::string target_digest,previous_digest{"-"};
    core::SemanticVersion target_version{},previous_version{};
    bool had_previous{};
    std::string retained_digest{"-"};
    bool service_enabled{};
    bool candidate_verified{true};
};
inline std::string serialize_program_journal(const ProgramJournal& record){
    const auto index=static_cast<std::size_t>(record.phase);
    if(index>=program_phase_names.size() || !lowercase_hex(record.target_digest,64,64) ||
       (record.had_previous?!lowercase_hex(record.previous_digest,64,64):record.previous_digest!="-") ||
       record.target_version==core::SemanticVersion{} ||
       (record.had_previous && record.previous_version>=record.target_version) ||
       (!record.had_previous && (record.previous_version!=core::SemanticVersion{} || record.retained_digest!="-" || record.service_enabled)) ||
       (record.retained_digest!="-" && !lowercase_hex(record.retained_digest,64,64)) ||
       (!record.candidate_verified && (record.phase==ProgramPhase::prepared || record.phase==ProgramPhase::activated || record.phase==ProgramPhase::committed)))
        throw std::invalid_argument("invalid program transaction journal");
    return "schema=1\nphase="+std::string(program_phase_names[index])+"\ntarget_digest="+record.target_digest+
        "\nprevious_digest="+record.previous_digest+"\ntarget_version="+core::to_string(record.target_version)+
        "\nprevious_version="+core::to_string(record.previous_version)+"\nhad_previous="+(record.had_previous?"true":"false")+
        "\nretained_digest="+record.retained_digest+"\nservice_enabled="+(record.service_enabled?"true":"false")+
        "\ncandidate_verified="+(record.candidate_verified?"true\n":"false\n");
}
inline ProgramJournal parse_program_journal(std::string_view text){
    if(text.empty() || text.size()>1024 || text.back()!='\n')throw std::invalid_argument("invalid program journal size");
    std::map<std::string,std::string,std::less<>> fields;
    while(!text.empty()){
        const auto end=text.find('\n'),equals=text.find('=');
        if(equals==std::string_view::npos || equals==0 || equals+1>=end ||
           !fields.emplace(std::string(text.substr(0,equals)),std::string(text.substr(equals+1,end-equals-1))).second)
            throw std::invalid_argument("invalid program journal field");
        text.remove_prefix(end+1);
    }
    constexpr std::array<std::string_view,10> keys{"schema","phase","target_digest","previous_digest","target_version","previous_version","had_previous","retained_digest","service_enabled","candidate_verified"};
    if(fields.size()!=keys.size())throw std::invalid_argument("unknown program journal field");
    for(auto key:keys)if(!fields.contains(key))throw std::invalid_argument("missing program journal field");
    if(fields.at("schema")!="1" || (fields.at("had_previous")!="true" && fields.at("had_previous")!="false") ||
       (fields.at("service_enabled")!="true" && fields.at("service_enabled")!="false") ||
       (fields.at("candidate_verified")!="true" && fields.at("candidate_verified")!="false"))
        throw std::invalid_argument("invalid program journal schema");
    std::size_t index=0;while(index<program_phase_names.size() && program_phase_names[index]!=fields.at("phase"))++index;
    if(index==program_phase_names.size())throw std::invalid_argument("unknown program journal phase");
    ProgramJournal record{static_cast<ProgramPhase>(index),fields.at("target_digest"),fields.at("previous_digest"),
        core::parse_semantic_version(fields.at("target_version")),core::parse_semantic_version(fields.at("previous_version")),fields.at("had_previous")=="true",
        fields.at("retained_digest"),fields.at("service_enabled")=="true",fields.at("candidate_verified")=="true"};
    (void)serialize_program_journal(record);return record;
}

inline bool program_runtime_generation_allowed(const ProgramJournal& record,std::string_view digest,core::SemanticVersion version){
    (void)serialize_program_journal(record);
    if(record.phase==ProgramPhase::activated || record.phase==ProgramPhase::committed)
        return digest==record.target_digest && version==record.target_version;
    if(record.phase==ProgramPhase::restoring || record.phase==ProgramPhase::rolled_back)
        return record.had_previous && digest==record.previous_digest && version==record.previous_version;
    return false;
}

class ProgramBackend {
public:
    virtual ~ProgramBackend()=default;
    virtual ProgramPhase phase()=0;
    virtual bool recovery_ready()=0;
    virtual bool stage_verified()=0;
    virtual bool unchanged()=0;
    virtual bool prepare()=0;
    virtual bool persist(ProgramPhase)=0;
    virtual bool quiesce()=0;
    virtual bool exchange()=0;
    virtual bool healthy()=0;
    virtual bool restore_slots()=0;
    virtual bool resume_previous()=0;
    virtual bool finish_commit()=0;
    virtual bool finish_rollback()=0;
};
inline ProgramResult rollback_program(ProgramBackend& backend){
    try {
        if(!backend.persist(ProgramPhase::restoring) || !backend.quiesce() || !backend.restore_slots() ||
           !backend.resume_previous() || !backend.persist(ProgramPhase::rolled_back) || !backend.finish_rollback()){
            (void)backend.persist(ProgramPhase::recovery_failed);return ProgramResult::recovery_required;
        }
        return ProgramResult::rolled_back;
    }catch(const std::exception&){
        try{(void)backend.persist(ProgramPhase::recovery_failed);}catch(const std::exception&){}
        return ProgramResult::recovery_required;
    }
}
inline ProgramResult recover_program(ProgramBackend& backend){
    if(!backend.recovery_ready())return ProgramResult::recovery_required;
    if(backend.phase()==ProgramPhase::none)return ProgramResult::unchanged;
    if(backend.phase()==ProgramPhase::committed)return backend.finish_commit()?ProgramResult::active:ProgramResult::recovery_required;
    if(backend.phase()==ProgramPhase::rolled_back)return backend.finish_rollback()?ProgramResult::rolled_back:ProgramResult::recovery_required;
    if(backend.phase()==ProgramPhase::staging){
        // An incomplete candidate has never stopped the old service.
        return backend.persist(ProgramPhase::rolled_back) && backend.finish_rollback()?ProgramResult::rolled_back:ProgramResult::recovery_required;
    }
    return rollback_program(backend);
}
inline ProgramResult apply_program(ProgramBackend& backend){
    if(backend.phase()!=ProgramPhase::none && recover_program(backend)==ProgramResult::recovery_required)
        return ProgramResult::recovery_required;
    if(!backend.stage_verified()){
        if(backend.phase()==ProgramPhase::staging && recover_program(backend)==ProgramResult::recovery_required)
            return ProgramResult::recovery_required;
        return ProgramResult::rejected;
    }
    if(backend.unchanged())return ProgramResult::unchanged;
    if(!backend.prepare())return ProgramResult::rejected;
    try {
        if(!backend.quiesce() || !backend.exchange() || !backend.persist(ProgramPhase::activated) || !backend.healthy())
            return rollback_program(backend);
        if(!backend.persist(ProgramPhase::committed))return rollback_program(backend);
        // Once committed, a retention/finalization error must not roll back a
        // healthy active version. Recovery can finish that bounded maintenance.
        return backend.finish_commit()?ProgramResult::active:ProgramResult::recovery_required;
    }catch(const std::exception&){
        if(backend.phase()==ProgramPhase::committed)return ProgramResult::recovery_required;
        return rollback_program(backend);
    }
}

class ProgramServiceHooks {
public:
    virtual ~ProgramServiceHooks()=default;
    // The application integration must close its startup gate and prove all
    // owners stopped. It must never interpret a signature as a health receipt.
    virtual bool quiesce()=0;
    virtual bool initially_enabled()=0;
    virtual bool accept_candidate(bool resume_service)=0;
    virtual bool resume_previous(bool had_previous,bool was_enabled)=0;
};

// Production APIs accept only shared-verifier proof + a publisher-verified
// canonical app inventory. No fixture bypass is exposed through these APIs.
ProgramResult install_verified_program(const core::VerifiedUpdate&,const std::filesystem::path& source_bundle);
ProgramResult recover_program_install();
int program_store_fixture();
int write_program_inventory(const std::filesystem::path& absolute_new_output);
} // namespace rwn::agent::macos
