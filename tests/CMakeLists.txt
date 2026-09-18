add_executable(rwn_process_fixture process_fixture.cpp)
target_link_libraries(rwn_process_fixture PRIVATE rwn_project_options)
if(MINGW)
  target_link_options(rwn_process_fixture PRIVATE -static)
endif()

add_executable(rwn_flow_unit_tests flow_unit_tests.cpp)
target_compile_definitions(rwn_flow_unit_tests PRIVATE
  RWN_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
  RWN_PROCESS_FIXTURE="$<TARGET_FILE:rwn_process_fixture>"
)
target_link_libraries(rwn_flow_unit_tests PRIVATE rwn::audio rwn::client_service rwn::core rwn::desktop rwn::node_service rwn::protocol rwn_project_options)
add_dependencies(rwn_flow_unit_tests rwn_process_fixture)
add_test(NAME workflow-unit COMMAND rwn_flow_unit_tests)
set_tests_properties(workflow-unit PROPERTIES LABELS "unit;workflow")

add_executable(rwn_security_tests security_tests.cpp)
target_compile_definitions(rwn_security_tests PRIVATE
  RWN_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
  RWN_PROCESS_FIXTURE="$<TARGET_FILE:rwn_process_fixture>"
)
target_link_libraries(rwn_security_tests PRIVATE rwn::audio rwn::client_service rwn::core rwn::desktop rwn::node_service rwn::protocol rwn_project_options)
add_dependencies(rwn_security_tests rwn_process_fixture)
if(WIN32)
  find_program(RWN_GIT_EXECUTABLE git REQUIRED)
  target_compile_definitions(rwn_flow_unit_tests PRIVATE
    RWN_GIT_EXECUTABLE="${RWN_GIT_EXECUTABLE}"
  )
  target_compile_definitions(rwn_security_tests PRIVATE
    RWN_GIT_EXECUTABLE="${RWN_GIT_EXECUTABLE}"
  )
  target_link_libraries(rwn_flow_unit_tests PRIVATE rwn::platform_windows)
  target_compile_definitions(rwn_flow_unit_tests PRIVATE RWN_TEST_WINDOWS_PLATFORM=1)
  target_link_libraries(rwn_security_tests PRIVATE rwn::platform_windows)
  target_compile_definitions(rwn_security_tests PRIVATE RWN_TEST_WINDOWS_PLATFORM=1)
endif()
if(TARGET rwn_transport_msquic)
  target_link_libraries(rwn_flow_unit_tests PRIVATE rwn::transport_msquic)
  target_compile_definitions(rwn_flow_unit_tests PRIVATE
    RWN_TEST_MSQUIC_PROVIDER=1
    RWN_TEST_MSQUIC_DLL="${RWN_MSQUIC_RUNTIME}"
  )
  target_link_libraries(rwn_security_tests PRIVATE rwn::transport_msquic)
  target_compile_definitions(rwn_security_tests PRIVATE
    RWN_TEST_MSQUIC_PROVIDER=1
    RWN_TEST_MSQUIC_DLL="${RWN_MSQUIC_RUNTIME}"
  )
endif()
add_test(NAME security COMMAND rwn_security_tests)
set_tests_properties(security PROPERTIES LABELS "security")
