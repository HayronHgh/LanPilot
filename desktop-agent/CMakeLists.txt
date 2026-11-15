add_library(rwn_desktop_agent_entry STATIC main.cpp shutdown.cpp run_audit.cpp)
target_link_libraries(rwn_desktop_agent_entry PUBLIC rwn::core rwn::desktop rwn_project_options)
if(WIN32)
  target_link_libraries(rwn_desktop_agent_entry PUBLIC rwn::platform_windows)
endif()
if(APPLE)
  target_link_libraries(rwn_desktop_agent_entry PUBLIC rwn::platform_macos)
endif()
add_executable(rwn-desktop-agent agent_main.cpp)
target_link_libraries(rwn-desktop-agent PRIVATE rwn_desktop_agent_entry)

if(APPLE)
  # Language rules enabled in platform/macos do not reach this sibling directory.
  enable_language(OBJCXX)
  set(LANPILOT_DEVELOPER_TEAM_ID "" CACHE STRING "Expected Developer ID publisher team; empty disables service activation")
  set(LANPILOT_RELEASE_PUBLIC_KEY_XY "" CACHE STRING "Pinned release ECDSA-P256 public key X||Y in lowercase hex; empty disables program updates")
  string(LENGTH "${LANPILOT_RELEASE_PUBLIC_KEY_XY}" _lanpilot_release_key_length)
  if(NOT LANPILOT_RELEASE_PUBLIC_KEY_XY STREQUAL "" AND
      (NOT _lanpilot_release_key_length EQUAL 128 OR NOT LANPILOT_RELEASE_PUBLIC_KEY_XY MATCHES "^[0-9a-f]+$" OR
       LANPILOT_RELEASE_PUBLIC_KEY_XY MATCHES "^0+$"))
    message(FATAL_ERROR "LANPILOT_RELEASE_PUBLIC_KEY_XY must be empty or a nonzero 64-byte lowercase hexadecimal public key")
  endif()
  string(LENGTH "${LANPILOT_DEVELOPER_TEAM_ID}" _lanpilot_team_length)
  if(NOT LANPILOT_DEVELOPER_TEAM_ID STREQUAL "" AND
      (NOT _lanpilot_team_length EQUAL 10 OR NOT LANPILOT_DEVELOPER_TEAM_ID MATCHES "^[A-Z0-9]+$"))
    message(FATAL_ERROR "LANPILOT_DEVELOPER_TEAM_ID must be empty or a canonical ten-character team identifier")
  endif()
  add_executable(LanPilotMac MACOSX_BUNDLE macos/lanpilot_app.mm macos/configuration_store.mm macos/code_identity.mm macos/native_status_service.mm)
  target_link_libraries(LanPilotMac PRIVATE rwn_desktop_agent_entry
    "-framework AppKit" "-framework ApplicationServices" "-framework Security" "-framework ServiceManagement")
  target_compile_definitions(LanPilotMac PRIVATE LANPILOT_DEVELOPER_TEAM_ID="${LANPILOT_DEVELOPER_TEAM_ID}")
  target_compile_definitions(LanPilotMac PRIVATE LANPILOT_RELEASE_PUBLIC_KEY_XY="${LANPILOT_RELEASE_PUBLIC_KEY_XY}")
  target_compile_options(LanPilotMac PRIVATE -fobjc-arc)
  set_target_properties(LanPilotMac PROPERTIES
    OUTPUT_NAME LanPilot
    MACOSX_BUNDLE_BUNDLE_NAME LanPilot
    MACOSX_BUNDLE_GUI_IDENTIFIER com.lanpilot.desktop
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/macos/com.lanpilot.desktop.service.plist"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/macos/Info.plist.in")
  add_custom_command(TARGET LanPilotMac POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_BUNDLE_DIR:LanPilotMac>/Contents/Resources"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${PROJECT_SOURCE_DIR}/LICENSE" "$<TARGET_BUNDLE_DIR:LanPilotMac>/Contents/Resources/LICENSE.txt"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_BUNDLE_DIR:LanPilotMac>/Contents/Library/LaunchAgents"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${CMAKE_CURRENT_SOURCE_DIR}/macos/com.lanpilot.desktop.service.plist"
      "$<TARGET_BUNDLE_DIR:LanPilotMac>/Contents/Library/LaunchAgents/com.lanpilot.desktop.service.plist")
  # An explicit staging component, separate from the still-supported CLI bundle.
  # This does not sign, install, start, migrate or register a service.
  if(RWN_BUILD_PACKAGING)
    install(TARGETS LanPilotMac BUNDLE DESTINATION .
      COMPONENT macos-app EXCLUDE_FROM_ALL)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(_lanpilot_pkg "${PROJECT_BINARY_DIR}/native-installer/LanPilot-macOS-UNSIGNED.pkg")
    add_custom_command(OUTPUT "${_lanpilot_pkg}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/native-installer"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${_lanpilot_pkg}"
      COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/packaging/macos/build-native-installer.py"
        --app "$<TARGET_BUNDLE_DIR:LanPilotMac>" --output "${_lanpilot_pkg}" --mode development
      DEPENDS LanPilotMac "${PROJECT_SOURCE_DIR}/packaging/macos/build-native-installer.py"
        "${PROJECT_SOURCE_DIR}/packaging/macos/installer-preinstall.sh"
      VERBATIM)
    add_custom_target(lanpilot-macos-installer DEPENDS "${_lanpilot_pkg}")
    install(FILES "${_lanpilot_pkg}" DESTINATION . COMPONENT macos-installer EXCLUDE_FROM_ALL)
  endif()
endif()
