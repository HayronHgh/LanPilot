add_library(rwn_client_service
  src/artifact_client.cpp
  src/build_client.cpp
  src/deployment_client.cpp
  src/session_client.cpp
  src/workspace_client.cpp)
target_include_directories(rwn_client_service PUBLIC include)
target_link_libraries(rwn_client_service
  PUBLIC rwn::core rwn::protocol rwn::transport
  PRIVATE rwn_project_options)
add_library(rwn::client_service ALIAS rwn_client_service)

add_executable(rwn-client main.cpp)
target_link_libraries(rwn-client
  PRIVATE rwn::client_service rwn::core rwn_project_options)

if(TARGET rwn_transport_msquic)
  target_link_libraries(rwn-client PRIVATE
    rwn::platform_windows rwn::transport_msquic)
  target_compile_definitions(rwn-client PRIVATE RWN_HAS_MSQUIC=1)
endif()
