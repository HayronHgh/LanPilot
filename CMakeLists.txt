cmake_minimum_required(VERSION 3.25)

project(RemoteWorkspaceNode VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RWN_BUILD_TESTS "Build workflow unit and security tests" ON)
option(RWN_BUILD_PACKAGING "Enable install rules and CPack release archives" ON)

add_library(rwn_project_options INTERFACE)
if(WIN32)
  # Also cover standalone helpers that do not link rwn_platform_windows.
  target_compile_definitions(rwn_project_options INTERFACE NOMINMAX)
endif()
if(MSVC)
  target_compile_options(rwn_project_options INTERFACE /W4 /permissive-)
else()
  target_compile_options(rwn_project_options INTERFACE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()
if(MINGW)
  target_link_options(rwn_project_options INTERFACE -static)
endif()

add_subdirectory(protocol)
add_subdirectory(core)
add_subdirectory(transport)
add_subdirectory(audio)
add_subdirectory(desktop)
add_subdirectory(platform)
add_subdirectory(node)
add_subdirectory(client)
add_subdirectory(viewer)
add_subdirectory(broker)
add_subdirectory(build-worker)
add_subdirectory(desktop-agent)
add_subdirectory(tools)

if(RWN_BUILD_TESTS)
  include(CTest)
  add_subdirectory(tests)
endif()

if(RWN_BUILD_PACKAGING)
  include(GNUInstallDirs)
  include(packaging/DesktopPackage.cmake)

  configure_file(
    packaging/release-manifest.toml.in
    "${CMAKE_CURRENT_BINARY_DIR}/release-manifest.toml"
    @ONLY)

  install(TARGETS
    rwn-client
    rwn-node
    rwn-broker
    rwn-build-worker
    rwn-desktop-agent
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    COMPONENT runtime)
  if(TARGET rwn-viewer)
    install(TARGETS rwn-viewer
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
      COMPONENT runtime)
  endif()
  install(TARGETS
    rwn-audio-probe
    rwn-protocol-security-gate
    rwn-release-security-gate
    rwn-transport-verification
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/tools"
    COMPONENT verification)
  if(TARGET rwn-diagnostics)
    install(TARGETS rwn-diagnostics
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/tools"
      COMPONENT verification)
  endif()
  if(TARGET rwn-schannel-fallback-probe)
    install(TARGETS
      rwn-schannel-fallback-probe
      rwn-schannel-fallback-loopback-probe
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/tools"
      COMPONENT verification)
  endif()
  if(TARGET rwn-network-peer-probe)
    install(TARGETS rwn-network-peer-probe
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/tools"
      COMPONENT verification)
  endif()

  if(TARGET rwn-msquic-probe)
    install(TARGETS rwn-msquic-probe rwn-msquic-loopback-probe
      rwn-msquic-peer-probe
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/tools"
      COMPONENT verification)
    install(FILES "${RWN_MSQUIC_RUNTIME}"
      DESTINATION "${CMAKE_INSTALL_BINDIR}"
      COMPONENT runtime)
    if(EXISTS "${RWN_MSQUIC_ROOT}/LICENSE")
      install(FILES "${RWN_MSQUIC_ROOT}/LICENSE"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses"
        RENAME "msquic-LICENSE.txt"
        COMPONENT documentation)
    else()
      message(FATAL_ERROR "The explicit MsQuic package is missing LICENSE")
    endif()
  endif()

  install(FILES
    README.md
    CONTRIBUTING.md
    remote-workspace.toml
    "${CMAKE_CURRENT_BINARY_DIR}/release-manifest.toml"
    DESTINATION "."
    COMPONENT documentation)
  install(DIRECTORY config/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/config"
    COMPONENT configuration
    FILES_MATCHING
      PATTERN "*.toml"
      PATTERN "*.tsv")
  install(DIRECTORY doc/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/doc"
    COMPONENT documentation
    FILES_MATCHING PATTERN "*.md")

  if(WIN32)
    install(PROGRAMS
      packaging/windows/Install-DesktopPreview.ps1
      packaging/windows/Start-DesktopPreview.ps1
      packaging/windows/Start-LanPilot.ps1
      packaging/windows/Start-LanPilotTls.ps1
      packaging/windows/TlsConnectionSettings.psm1
      packaging/windows/Uninstall-DesktopPreview.ps1
      DESTINATION "${CMAKE_INSTALL_BINDIR}"
      COMPONENT runtime)
  elseif(APPLE)
    install(PROGRAMS
      packaging/macos/install-desktop-preview.sh
      packaging/macos/uninstall-desktop-preview.sh
      DESTINATION "${CMAKE_INSTALL_BINDIR}"
      COMPONENT runtime)
  endif()

  set(CPACK_PACKAGE_NAME "RemoteWorkspaceNode")
  set(CPACK_PACKAGE_VENDOR "Remote Workspace Node Project")
  set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
  set(CPACK_PACKAGE_DIRECTORY "${PROJECT_SOURCE_DIR}/out/packages")
  string(TOLOWER "${CMAKE_SYSTEM_NAME}" RWN_PACKAGE_SYSTEM)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" RWN_PACKAGE_PROCESSOR)
  if(TARGET rwn-msquic-probe)
    set(RWN_PACKAGE_VARIANT "msquic")
  else()
    set(RWN_PACKAGE_VARIANT "core")
  endif()
  set(CPACK_PACKAGE_FILE_NAME
    "RemoteWorkspaceNode-${PROJECT_VERSION}-${RWN_PACKAGE_SYSTEM}-${RWN_PACKAGE_PROCESSOR}-${RWN_PACKAGE_VARIANT}")
  set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
  set(CPACK_MONOLITHIC_INSTALL ON)
  if(APPLE)
    set(CPACK_GENERATOR "TGZ;DragNDrop")
  elseif(WIN32)
    set(CPACK_GENERATOR "ZIP")
  else()
    set(CPACK_GENERATOR "TGZ")
  endif()
  include(CPack)
endif()
