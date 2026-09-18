add_library(rwn_node_service
  src/artifact_service.cpp
  src/build_service.cpp
  src/deployment_service.cpp
  src/pairing_service.cpp
  src/control_service.cpp
  src/workspace_service.cpp)
target_include_directories(rwn_node_service PUBLIC include)
target_link_libraries(rwn_node_service
  PUBLIC rwn::core rwn::protocol rwn::transport
  PRIVATE rwn_project_options)
add_library(rwn::node_service ALIAS rwn_node_service)

add_executable(rwn-node main.cpp)
target_link_libraries(rwn-node
  PRIVATE rwn::node_service rwn_project_options)

if(APPLE)
  target_link_libraries(rwn-node PRIVATE rwn::platform_macos)
  target_compile_definitions(rwn-node PRIVATE RWN_HAS_NETWORK_FRAMEWORK=1)
elseif(WIN32)
  target_link_libraries(rwn-node PRIVATE rwn::platform_windows)
  target_compile_definitions(rwn-node PRIVATE RWN_HAS_WINDOWS_PLATFORM=1)
  if(TARGET rwn_transport_msquic)
    target_link_libraries(rwn-node PRIVATE rwn::transport_msquic)
  endif()
endif()

if(TARGET rwn_transport_msquic)
  target_compile_definitions(rwn-node PRIVATE RWN_HAS_MSQUIC=1)
endif()
