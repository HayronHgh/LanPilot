# Build a standalone offline GUI installer, not an arbitrary-script launcher.
enable_language(RC)
find_program(LANPILOT_SETUP_POWERSHELL powershell REQUIRED)
set(_setup_dir "${PROJECT_BINARY_DIR}/setup/$<CONFIG>")
set(LANPILOT_SETUP_EXISTING_VIEWER "" CACHE FILEPATH "Personal installer: existing verified Viewer executable; empty builds the normal package")
set(LANPILOT_SETUP_EXISTING_VIEWER_SHA256 "" CACHE STRING "Required SHA-256 for the existing personal Viewer baseline")
set(_setup_viewer "$<TARGET_FILE:rwn-viewer>")
set(_setup_personal_args)
if(NOT LANPILOT_SETUP_EXISTING_VIEWER STREQUAL "")
  if(NOT IS_ABSOLUTE "${LANPILOT_SETUP_EXISTING_VIEWER}" OR NOT EXISTS "${LANPILOT_SETUP_EXISTING_VIEWER}" OR IS_DIRECTORY "${LANPILOT_SETUP_EXISTING_VIEWER}")
    message(FATAL_ERROR "Personal Viewer must be an existing absolute program file")
  endif()
  file(SHA256 "${LANPILOT_SETUP_EXISTING_VIEWER}" _actual_viewer_hash)
  if(NOT _actual_viewer_hash STREQUAL LANPILOT_SETUP_EXISTING_VIEWER_SHA256)
    message(FATAL_ERROR "Personal Viewer does not match the explicit baseline SHA-256")
  endif()
  set(_setup_viewer "${LANPILOT_SETUP_EXISTING_VIEWER}")
  set(_setup_personal_args -ExistingPair -ExpectedViewerSha256 "${LANPILOT_SETUP_EXISTING_VIEWER_SHA256}")
endif()
set(_setup_scripts)
foreach(_name IN ITEMS Install-DesktopPreview.ps1 Maintain-LanPilotTrust.ps1
    Invoke-LanPilotTrustMaintenance.ps1 Register-LanPilotMaintenance.ps1
    TrustMaintenance.psm1 ProductInstall.psm1 Start-LanPilotBootstrap.ps1
    Start-DesktopPreview.ps1 Start-LanPilot.ps1 Start-LanPilotTls.ps1
    TlsConnectionSettings.psm1 Uninstall-DesktopPreview.ps1 Update-LanPilotTrustBundle.ps1
    Build-SetupPayload.ps1 Setup-Driver.ps1 Setup.manifest)
  list(APPEND _setup_scripts "${PROJECT_SOURCE_DIR}/packaging/windows/${_name}")
endforeach()
add_custom_command(OUTPUT "${_setup_dir}/payload.rc"
  "${_setup_dir}/payload.zip" "${_setup_dir}/driver.ps1"
  COMMAND "${LANPILOT_SETUP_POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
    -File "${PROJECT_SOURCE_DIR}/packaging/windows/Build-SetupPayload.ps1"
    -PackagingDirectory "${PROJECT_SOURCE_DIR}/packaging/windows"
    -Destination "${_setup_dir}"
    -Viewer "${_setup_viewer}" -Launcher "$<TARGET_FILE:LanPilot>"
    -Maintenance "$<TARGET_FILE:rwn-maintenance-launcher>"
    -License "${PROJECT_SOURCE_DIR}/LICENSE" -ProductVersion "${PROJECT_VERSION}" ${_setup_personal_args}
  DEPENDS rwn-viewer LanPilot rwn-maintenance-launcher ${_setup_scripts} "${_setup_viewer}"
    "${PROJECT_SOURCE_DIR}/LICENSE"
  VERBATIM)
add_executable(LanPilot-Setup WIN32
  "${PROJECT_SOURCE_DIR}/viewer/setup.cpp" "${_setup_dir}/payload.rc")
target_link_libraries(LanPilot-Setup PRIVATE rwn_project_options user32 gdi32 shell32 ole32 uuid comctl32 advapi32)
target_compile_definitions(LanPilot-Setup PRIVATE LANPILOT_SETUP_VERSION=L"${PROJECT_VERSION}")
if(NOT LANPILOT_SETUP_EXISTING_VIEWER STREQUAL "")
  target_compile_definitions(LanPilot-Setup PRIVATE LANPILOT_PERSONAL_SETUP=1)
endif()
if(MINGW)
  target_link_options(LanPilot-Setup PRIVATE -municode)
elseif(MSVC)
  target_link_options(LanPilot-Setup PRIVATE /MANIFEST:NO)
endif()
