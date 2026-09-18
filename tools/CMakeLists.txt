if(WIN32 OR APPLE)
  add_executable(rwn-dedicated-tls-probe dedicated_tls_probe.cpp)
  if(WIN32)
    add_executable(rwn-desktop-control-security-probe desktop_control_security_probe.cpp)
    target_link_libraries(rwn-desktop-control-security-probe PRIVATE
      rwn::desktop rwn::platform_windows rwn_project_options)
    target_link_libraries(rwn-dedicated-tls-probe PRIVATE rwn::platform_windows rwn_project_options)
  else()
    target_link_libraries(rwn-dedicated-tls-probe PRIVATE rwn::platform_macos rwn_project_options)
  endif()
  add_executable(rwn-diagnostics diagnostics_main.cpp)
  target_link_libraries(rwn-diagnostics PRIVATE rwn::core rwn_project_options)
  target_compile_definitions(rwn-diagnostics PRIVATE
    RWN_PROJECT_VERSION="${PROJECT_VERSION}")
  if(WIN32)
    target_link_libraries(rwn-diagnostics PRIVATE rwn::platform_windows)
    target_compile_definitions(rwn-diagnostics PRIVATE RWN_DIAGNOSTICS_WINDOWS=1)
    add_executable(rwn-schannel-fallback-probe schannel_fallback_probe.cpp)
    target_link_libraries(rwn-schannel-fallback-probe
      PRIVATE rwn::platform_windows rwn_project_options)
    add_executable(rwn-schannel-fallback-loopback-probe
      schannel_fallback_loopback_probe.cpp)
    target_link_libraries(rwn-schannel-fallback-loopback-probe
      PRIVATE rwn::platform_windows rwn_project_options)
  else()
    target_link_libraries(rwn-diagnostics PRIVATE rwn::platform_macos)
    target_compile_definitions(rwn-diagnostics PRIVATE RWN_DIAGNOSTICS_MACOS=1)
  endif()
endif()

add_executable(rwn-visual-evidence visual_evidence_main.cpp)
target_link_libraries(rwn-visual-evidence
  PRIVATE rwn::desktop rwn_project_options)
