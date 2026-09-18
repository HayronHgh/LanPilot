enable_language(OBJCXX)

add_library(rwn_platform_macos
  src/app_packager.cpp
  src/audio_runtime.mm
  src/build_worker_ipc.cpp
  src/command_executor.cpp
  src/desktop_runtime.mm
  src/deployment_broker_ipc.cpp
  src/directory_watcher.mm
  src/durable_filesystem.cpp
  src/network_transport.mm
  src/pairing_code.cpp
  src/pty_terminal.cpp
  src/process_identity.cpp
  src/update_signature.cpp
)

target_include_directories(rwn_platform_macos PUBLIC include)
target_link_libraries(rwn_platform_macos PUBLIC
  rwn::audio rwn::core rwn::desktop rwn::protocol rwn::transport)
target_link_libraries(rwn_platform_macos PRIVATE
  "-framework AppKit"
  "-framework ApplicationServices"
  "-framework AudioToolbox"
  "-framework CoreMedia"
  "-framework CoreServices"
  "-framework CoreVideo"
  "-framework Metal"
  "-framework Network"
  "-framework ScreenCaptureKit"
  "-framework Security"
  "-framework VideoToolbox"
  rwn_project_options
)
target_compile_options(rwn_platform_macos PRIVATE -fblocks)
set_source_files_properties(src/network_transport.mm PROPERTIES
  COMPILE_OPTIONS "-fobjc-arc")
add_library(rwn::platform_macos ALIAS rwn_platform_macos)

add_executable(rwn-network-peer-probe network_peer_probe.mm)
target_link_libraries(rwn-network-peer-probe
  PRIVATE rwn::platform_macos rwn_project_options)
target_compile_options(rwn-network-peer-probe PRIVATE -fblocks -fobjc-arc)
