add_library(rwn_platform_windows
  src/audio_runtime.cpp
  src/command_executor.cpp
  src/desktop_runtime.cpp
  src/dns_sd_discovery.cpp
  src/durable_filesystem.cpp
  src/directory_watcher.cpp
  src/pairing_code.cpp
  src/schannel_fallback.cpp
  src/schannel_transport.cpp
  src/update_signature.cpp
)

target_include_directories(rwn_platform_windows PUBLIC include)
# Public platform headers expose Windows SDK types to Viewer/probe consumers.
# They must use the same macro contract as this library under MSVC.
target_compile_definitions(rwn_platform_windows PUBLIC NOMINMAX)
target_link_libraries(rwn_platform_windows PUBLIC
  rwn::audio rwn::core rwn::desktop rwn::transport)
target_link_libraries(rwn_platform_windows PRIVATE
  bcrypt crypt32 d3d11 dnsapi dxgi mfplat mfuuid ole32 secur32
  strmiids wmcodecdspuuid ws2_32
  rwn_project_options
)
add_library(rwn::platform_windows ALIAS rwn_platform_windows)
