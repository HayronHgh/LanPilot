add_library(rwn_transport
  src/apple_network_contract.cpp
  src/certificate_identity.cpp
  src/encrypted_fallback.cpp
  src/resilient_transport.cpp
  src/verification.cpp
)
target_include_directories(rwn_transport PUBLIC include)
target_link_libraries(rwn_transport PRIVATE rwn_project_options)
add_library(rwn::transport ALIAS rwn_transport)

add_executable(rwn-transport-verification verification_main.cpp)
target_link_libraries(rwn-transport-verification
  PRIVATE rwn::transport rwn_project_options)

set(RWN_MSQUIC_ROOT "" CACHE STRING
  "Explicit root of an extracted Microsoft.Native.Quic.MsQuic.Schannel package")

if(WIN32 AND RWN_MSQUIC_ROOT)
  if(NOT IS_ABSOLUTE "${RWN_MSQUIC_ROOT}")
    message(FATAL_ERROR "RWN_MSQUIC_ROOT must be an absolute path")
  endif()

  unset(RWN_MSQUIC_INCLUDE_DIR CACHE)
  unset(RWN_MSQUIC_RUNTIME CACHE)
  find_path(RWN_MSQUIC_INCLUDE_DIR msquic.h
    PATHS "${RWN_MSQUIC_ROOT}/build/native/include"
    NO_DEFAULT_PATH REQUIRED)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(RWN_MSQUIC_ARCH x64)
  else()
    set(RWN_MSQUIC_ARCH x86)
  endif()
  find_file(RWN_MSQUIC_RUNTIME msquic.dll
    PATHS "${RWN_MSQUIC_ROOT}/build/native/bin/${RWN_MSQUIC_ARCH}"
    NO_DEFAULT_PATH REQUIRED)

  add_library(rwn_transport_msquic src/msquic_client.cpp)
  target_include_directories(rwn_transport_msquic PUBLIC include)
  target_include_directories(rwn_transport_msquic SYSTEM
    PRIVATE "${RWN_MSQUIC_INCLUDE_DIR}")
  target_link_libraries(rwn_transport_msquic
    PUBLIC rwn::transport
    PRIVATE crypt32 rwn_project_options)
  add_library(rwn::transport_msquic ALIAS rwn_transport_msquic)

  add_executable(rwn-msquic-probe msquic_probe.cpp)
  target_link_libraries(rwn-msquic-probe
    PRIVATE rwn::transport_msquic rwn_project_options)

  add_executable(rwn-msquic-loopback-probe msquic_loopback_probe.cpp)
  target_link_libraries(rwn-msquic-loopback-probe
    PRIVATE rwn::transport_msquic rwn_project_options)

  add_executable(rwn-msquic-peer-probe msquic_peer_probe.cpp)
  target_link_libraries(rwn-msquic-peer-probe
    PRIVATE rwn::transport_msquic rwn_project_options)
endif()
