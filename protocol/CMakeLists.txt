add_library(rwn_protocol
  src/build_control.cpp
  src/envelope.cpp
  src/session_control.cpp
  src/security_gate.cpp
  src/workspace_control.cpp
)

target_include_directories(rwn_protocol PUBLIC include)
target_link_libraries(rwn_protocol PRIVATE rwn_project_options)
add_library(rwn::protocol ALIAS rwn_protocol)

add_executable(rwn-protocol-security-gate security_gate_main.cpp)
target_link_libraries(rwn-protocol-security-gate
  PRIVATE rwn::protocol rwn_project_options)
