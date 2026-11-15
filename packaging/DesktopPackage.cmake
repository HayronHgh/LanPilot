# The desktop product has one installer entry. Loose compatibility tools are an
# explicit separate component; the engineering CPack install stays independent.
if(WIN32 AND TARGET rwn-viewer)
  include("${PROJECT_SOURCE_DIR}/packaging/windows/Setup.cmake")
  install(TARGETS LanPilot-Setup RUNTIME DESTINATION .
    COMPONENT desktop EXCLUDE_FROM_ALL)
  install(TARGETS rwn-viewer rwn-maintenance-launcher LanPilot RUNTIME DESTINATION bin
    COMPONENT desktop-compat EXCLUDE_FROM_ALL)
  install(PROGRAMS
    "${PROJECT_SOURCE_DIR}/packaging/windows/Install-DesktopPreview.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Maintain-LanPilotTrust.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Invoke-LanPilotTrustMaintenance.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Register-LanPilotMaintenance.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/TrustMaintenance.psm1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/ProductInstall.psm1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Start-LanPilotBootstrap.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Start-DesktopPreview.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Start-LanPilot.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Start-LanPilotTls.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/TlsConnectionSettings.psm1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Uninstall-DesktopPreview.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Update-LanPilotTrustBundle.ps1"
    DESTINATION bin COMPONENT desktop-compat EXCLUDE_FROM_ALL)
elseif(APPLE AND TARGET rwn-desktop-agent)
  # Build lanpilot-macos-installer before staging. This is the same native
  # package exposed by macos-installer; no service activation or trust change.
  install(FILES "${PROJECT_BINARY_DIR}/native-installer/LanPilot-macOS-UNSIGNED.pkg"
    DESTINATION . COMPONENT desktop EXCLUDE_FROM_ALL)
  install(TARGETS rwn-desktop-agent RUNTIME DESTINATION bin
    COMPONENT desktop-compat EXCLUDE_FROM_ALL)
  install(PROGRAMS
    "${PROJECT_SOURCE_DIR}/packaging/macos/install-desktop-preview.sh"
    "${PROJECT_SOURCE_DIR}/packaging/macos/uninstall-desktop-preview.sh"
    DESTINATION bin COMPONENT desktop-compat EXCLUDE_FROM_ALL)
else()
  return()
endif()

foreach(_desktop_component IN ITEMS desktop desktop-compat)
  install(FILES "${PROJECT_SOURCE_DIR}/packaging/DESKTOP-README.md"
    DESTINATION . RENAME README.md COMPONENT ${_desktop_component} EXCLUDE_FROM_ALL)
  install(FILES "${PROJECT_SOURCE_DIR}/LICENSE"
    DESTINATION . COMPONENT ${_desktop_component} EXCLUDE_FROM_ALL)
endforeach()
