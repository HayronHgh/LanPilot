add_library(rwn_core
  src/agent_runtime.cpp
  src/audit.cpp
  src/audit_file.cpp
  src/artifact_store.cpp
  src/authorization.cpp
  src/build.cpp
  src/build_config.cpp
  src/content_hash.cpp
  src/deployment.cpp
  src/file_transfer.cpp
  src/identity.cpp
  src/pairing_store.cpp
  src/ignore_rules.cpp
  src/policy_file.cpp
  src/process_isolation.cpp
  src/product_config.cpp
  src/release_compatibility.cpp
  src/release_diagnostics.cpp
  src/release_security.cpp
  src/release_update.cpp
  src/session.cpp
  src/session_service.cpp
  src/terminal.cpp
  src/workspace_sync.cpp
  src/workspace_manifest.cpp
  src/workspace_watcher.cpp
  src/workspace_scope.cpp
)

target_include_directories(rwn_core PUBLIC include)
target_link_libraries(rwn_core PRIVATE rwn_project_options)
add_library(rwn::core ALIAS rwn_core)

add_executable(rwn-release-security-gate release_security_main.cpp)
target_link_libraries(rwn-release-security-gate
  PRIVATE rwn::core rwn_project_options)
