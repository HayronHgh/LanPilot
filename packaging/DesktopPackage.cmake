# An explicit allowlist for the end-user desktop bundle. The engineering CPack
# install remains independent. Stage with --component desktop, never copy out/.
if(WIN32 AND TARGET rwn-viewer)
  install(TARGETS rwn-viewer RUNTIME DESTINATION bin
    COMPONENT desktop EXCLUDE_FROM_ALL)
  install(PROGRAMS
    "${PROJECT_SOURCE_DIR}/packaging/windows/Install-DesktopPreview.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Start-DesktopPreview.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Start-LanPilotTls.ps1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/TlsConnectionSettings.psm1"
    "${PROJECT_SOURCE_DIR}/packaging/windows/Uninstall-DesktopPreview.ps1"
    DESTINATION bin COMPONENT desktop EXCLUDE_FROM_ALL)
elseif(APPLE AND TARGET rwn-desktop-agent)
  install(TARGETS rwn-desktop-agent RUNTIME DESTINATION bin
    COMPONENT desktop EXCLUDE_FROM_ALL)
  install(PROGRAMS
    "${PROJECT_SOURCE_DIR}/packaging/macos/install-desktop-preview.sh"
    "${PROJECT_SOURCE_DIR}/packaging/macos/uninstall-desktop-preview.sh"
    DESTINATION bin COMPONENT desktop EXCLUDE_FROM_ALL)
else()
  return()
endif()

install(FILES "${PROJECT_SOURCE_DIR}/packaging/DESKTOP-README.md"
  DESTINATION . RENAME README.md COMPONENT desktop EXCLUDE_FROM_ALL)
# No invented license. A distribution gate must verify the chosen license and
# dependency notices before publishing; local staging does not grant permission.
if(EXISTS "${PROJECT_SOURCE_DIR}/LICENSE")
  install(FILES "${PROJECT_SOURCE_DIR}/LICENSE"
    DESTINATION . COMPONENT desktop EXCLUDE_FROM_ALL)
endif()
