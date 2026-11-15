if(RWN_BUILD_PACKAGING AND (WIN32 OR APPLE))
  add_test(NAME lanpilot-desktop-package-workflow
    COMMAND "${CMAKE_COMMAND}" "-DBUILD_ROOT=${PROJECT_BINARY_DIR}"
      "-DCONFIG=$<CONFIG>" "-DHOST_SYSTEM=${CMAKE_SYSTEM_NAME}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/desktop_package_workflow.cmake")
  set_tests_properties(lanpilot-desktop-package-workflow PROPERTIES
    LABELS "workflow;packaging" TIMEOUT 240)
endif()

add_executable(rwn_process_fixture process_fixture.cpp)
add_executable(lanpilot_enrollment_identity_workflow enrollment_identity_workflow.cpp)
target_link_libraries(lanpilot_enrollment_identity_workflow PRIVATE rwn::core rwn_project_options)
add_test(NAME lanpilot-enrollment-identity-workflow COMMAND lanpilot_enrollment_identity_workflow)
set_tests_properties(lanpilot-enrollment-identity-workflow PROPERTIES LABELS "workflow;security")
add_executable(lanpilot_enrollment_pairing_workflow enrollment_pairing_workflow.cpp)
target_link_libraries(lanpilot_enrollment_pairing_workflow PRIVATE rwn::core rwn_project_options)
add_test(NAME lanpilot-enrollment-pairing-workflow COMMAND lanpilot_enrollment_pairing_workflow)
set_tests_properties(lanpilot-enrollment-pairing-workflow PROPERTIES LABELS "workflow;security")
add_executable(lanpilot_enrollment_certificate_workflow enrollment_certificate_workflow.cpp)
target_link_libraries(lanpilot_enrollment_certificate_workflow PRIVATE rwn::core rwn_project_options)
add_test(NAME lanpilot-enrollment-certificate-workflow COMMAND lanpilot_enrollment_certificate_workflow)
set_tests_properties(lanpilot-enrollment-certificate-workflow PROPERTIES LABELS "workflow;security")
if(TARGET rwn-enrollment-certificate-probe)
  add_test(NAME lanpilot-native-enrollment-certificate COMMAND rwn-enrollment-certificate-probe)
  set_tests_properties(lanpilot-native-enrollment-certificate PROPERTIES LABELS "workflow;security" TIMEOUT 20)
endif()
if(TARGET rwn-enrollment-journal-probe)
  add_test(NAME lanpilot-enrollment-socket-workflow COMMAND rwn-enrollment-setup-probe)
  set_tests_properties(lanpilot-enrollment-socket-workflow PROPERTIES LABELS "workflow;security" TIMEOUT 10)
  add_test(NAME lanpilot-native-enrollment-journal COMMAND rwn-enrollment-journal-probe)
  set_tests_properties(lanpilot-native-enrollment-journal PROPERTIES LABELS "workflow;security" TIMEOUT 20)
endif()
if(TARGET rwn-enrollment-key-probe)
  add_test(NAME lanpilot-native-enrollment-key COMMAND rwn-enrollment-key-probe)
  set_tests_properties(lanpilot-native-enrollment-key PROPERTIES LABELS "workflow;security" TIMEOUT 30)
endif()
if(TARGET rwn-enrollment-pairing-probe)
  add_test(NAME lanpilot-native-enrollment-pairing COMMAND rwn-enrollment-pairing-probe)
  set_tests_properties(lanpilot-native-enrollment-pairing PROPERTIES LABELS "workflow;security" TIMEOUT 20)
endif()
target_link_libraries(rwn_process_fixture PRIVATE rwn_project_options)
if(MINGW)
  target_link_options(rwn_process_fixture PRIVATE -static)
endif()

add_executable(lanpilot_mac_configuration_workflow mac_product_configuration_workflow.cpp)
add_executable(lanpilot_agent_shutdown_workflow agent_shutdown_workflow.cpp ../desktop-agent/shutdown.cpp ../desktop-agent/run_audit.cpp)
target_link_libraries(lanpilot_agent_shutdown_workflow PRIVATE rwn::desktop rwn_project_options)
add_test(NAME lanpilot-agent-shutdown-workflow COMMAND lanpilot_agent_shutdown_workflow)
set_tests_properties(lanpilot-agent-shutdown-workflow PROPERTIES LABELS "workflow;security" TIMEOUT 20)

target_link_libraries(lanpilot_mac_configuration_workflow PRIVATE rwn_project_options)
add_test(NAME lanpilot-macos-configuration-workflow COMMAND lanpilot_mac_configuration_workflow)
set_tests_properties(lanpilot-macos-configuration-workflow PROPERTIES LABELS "workflow;packaging;security")

add_executable(lanpilot_mac_login_workflow mac_login_service_workflow.cpp)
target_link_libraries(lanpilot_mac_login_workflow PRIVATE rwn_project_options)
add_test(NAME lanpilot-macos-login-workflow COMMAND lanpilot_mac_login_workflow)
set_tests_properties(lanpilot-macos-login-workflow PROPERTIES LABELS "workflow;packaging;security")

add_executable(lanpilot_mac_program_workflow mac_program_install_workflow.cpp)
target_link_libraries(lanpilot_mac_program_workflow PRIVATE rwn::core rwn_project_options)
add_test(NAME lanpilot-macos-program-workflow COMMAND lanpilot_mac_program_workflow)
set_tests_properties(lanpilot-macos-program-workflow PROPERTIES LABELS "workflow;packaging;security")

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

if(APPLE AND TARGET LanPilotMac)
  if(RWN_BUILD_PACKAGING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME lanpilot-macos-installer-workflow
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mac_installer_workflow.py"
        --app "$<TARGET_BUNDLE_DIR:LanPilotMac>"
        --builder "${PROJECT_SOURCE_DIR}/packaging/macos/build-native-installer.py")
    set_tests_properties(lanpilot-macos-installer-workflow PROPERTIES
      LABELS "workflow;packaging;security" TIMEOUT 120)
    add_test(NAME lanpilot-personal-installer-workflow
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/personal_installer_workflow.py"
        "${PROJECT_SOURCE_DIR}/packaging/macos/build-personal-installer.py" "${PROJECT_SOURCE_DIR}/LICENSE")
    set_tests_properties(lanpilot-personal-installer-workflow PROPERTIES
      LABELS "workflow;packaging;security" TIMEOUT 120)
  endif()
  add_test(NAME lanpilot-macos-release-verifier
    COMMAND "$<TARGET_FILE:LanPilotMac>" --check-release-verifier)
  set_tests_properties(lanpilot-macos-release-verifier PROPERTIES LABELS "workflow;security"
    PASS_REGULAR_EXPRESSION "release_verifier=PASS")
  add_test(NAME lanpilot-macos-tls-command-graph
    COMMAND "${CMAKE_COMMAND}" "-DPROGRAM=$<TARGET_FILE:rwn-desktop-agent>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/mac_tls_command_guard.cmake")
  set_tests_properties(lanpilot-macos-tls-command-graph PROPERTIES LABELS "workflow;security")
  add_test(NAME lanpilot-macos-agent-entry-boundary
    COMMAND "${CMAKE_COMMAND}" "-DPROGRAM=$<TARGET_FILE:LanPilotMac>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/mac_agent_entry_guard.cmake")
  set_tests_properties(lanpilot-macos-agent-entry-boundary PROPERTIES LABELS "workflow;security")
  add_test(NAME lanpilot-macos-program-store-workflow
    COMMAND "$<TARGET_FILE:LanPilotMac>" --check-program-store)
  set_tests_properties(lanpilot-macos-program-store-workflow PROPERTIES
    LABELS "workflow;packaging;security"
    PASS_REGULAR_EXPRESSION "program_store=PASS")
  add_test(NAME lanpilot-macos-login-bundle-workflow
    COMMAND "$<TARGET_FILE:LanPilotMac>" --check-service-bundle)
  set_tests_properties(lanpilot-macos-login-bundle-workflow PROPERTIES
    LABELS "workflow;packaging;security"
    PASS_REGULAR_EXPRESSION "service_bundle=PASS")
  add_test(NAME lanpilot-macos-configuration-store-workflow
    COMMAND "$<TARGET_FILE:LanPilotMac>" --check-configuration-store)
  set_tests_properties(lanpilot-macos-configuration-store-workflow PROPERTIES
    LABELS "workflow;packaging;security"
    PASS_REGULAR_EXPRESSION "configuration_store=PASS")
  add_test(NAME lanpilot-macos-application-workflow
    COMMAND "$<TARGET_FILE:LanPilotMac>" --check-application)
  set_tests_properties(lanpilot-macos-application-workflow PROPERTIES
    LABELS "workflow;packaging;security"
    PASS_REGULAR_EXPRESSION "\"canonical_bundle\":true")
  add_test(NAME lanpilot-macos-layout-workflow
    COMMAND "$<TARGET_FILE:LanPilotMac>" --check-layout)
  set_tests_properties(lanpilot-macos-layout-workflow PROPERTIES
    LABELS "workflow;packaging" SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "application_layout=PASS")
  add_test(NAME lanpilot-macos-shared-agent-workflow
    COMMAND "$<TARGET_FILE:LanPilotMac>" --desktop-agent)
  set_tests_properties(lanpilot-macos-shared-agent-workflow PROPERTIES
    LABELS "workflow;packaging;security"
    PASS_REGULAR_EXPRESSION "desktop agent ready; capabilities=")
endif()

if(WIN32)
  find_program(RWN_WINDOWS_POWERSHELL powershell REQUIRED)
  if(RWN_BUILD_PACKAGING)
    add_test(NAME lanpilot-setup-workflow
      COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
        -File "${CMAKE_CURRENT_SOURCE_DIR}/setup_workflow.ps1"
        -Setup "$<TARGET_FILE:LanPilot-Setup>"
        -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows")
    set_tests_properties(lanpilot-setup-workflow PROPERTIES LABELS "workflow;packaging;security" TIMEOUT 180)
  endif()
  add_test(NAME lanpilot-viewer-reconnect-workflow COMMAND "$<TARGET_FILE:rwn-input-queue-probe>" --check-reconnect)
  set_tests_properties(lanpilot-viewer-reconnect-workflow PROPERTIES
    LABELS "workflow;security" TIMEOUT 10 PASS_REGULAR_EXPRESSION "viewer_reconnect=PASS")
  add_test(NAME lanpilot-viewer-startup-workflow COMMAND "$<TARGET_FILE:rwn-input-queue-probe>" --check-startup)
  set_tests_properties(lanpilot-viewer-startup-workflow PROPERTIES
    LABELS "workflow;security" TIMEOUT 10 PASS_REGULAR_EXPRESSION "viewer_startup=PASS")
  add_test(NAME lanpilot-pairing-layout-workflow
    COMMAND "$<TARGET_FILE:rwn-viewer>" --check-pairing-layout)
  set_tests_properties(lanpilot-pairing-layout-workflow PROPERTIES
    LABELS "workflow;security" TIMEOUT 10 PASS_REGULAR_EXPRESSION "pairing_layout=PASS")
  add_test(NAME lanpilot-source-export-workflow
    COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/source_export_workflow.ps1"
      -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging")
  set_tests_properties(lanpilot-source-export-workflow PROPERTIES LABELS "workflow;packaging;security")
  add_test(NAME lanpilot-product-install-workflow
    COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/product_install_workflow.ps1"
      -Launcher "$<TARGET_FILE:LanPilot>"
      -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows")
  set_tests_properties(lanpilot-product-install-workflow PROPERTIES LABELS "workflow;packaging;security")
  add_dependencies(rwn_flow_unit_tests rwn-maintenance-launcher LanPilot)
  add_test(NAME lanpilot-maintenance-launcher-workflow
    COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/maintenance_launcher_workflow.ps1"
      -Launcher "$<TARGET_FILE:rwn-maintenance-launcher>"
      -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows")
  set_tests_properties(lanpilot-maintenance-launcher-workflow PROPERTIES
    LABELS "workflow;packaging;security")
  add_test(NAME lanpilot-product-layout-workflow
    COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/lanpilot_product_layout_workflow.ps1"
      -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows")
  set_tests_properties(lanpilot-product-layout-workflow PROPERTIES
    LABELS "workflow;packaging")
  add_test(NAME lanpilot-trust-renewal-workflow
    COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/trust_renewal_workflow.ps1"
      -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows")
  set_tests_properties(lanpilot-trust-renewal-workflow PROPERTIES
    LABELS "workflow;packaging;security")
  add_test(NAME lanpilot-background-trust-workflow
    COMMAND "${RWN_WINDOWS_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/background_trust_workflow.ps1"
      -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows")
  set_tests_properties(lanpilot-background-trust-workflow PROPERTIES
    LABELS "workflow;packaging;security")
endif()
