add_executable(rwn-build-worker main.cpp)
target_link_libraries(rwn-build-worker PRIVATE
  rwn::core rwn::node_service rwn::protocol rwn_project_options)
if(APPLE)
  target_link_libraries(rwn-build-worker PRIVATE rwn::platform_macos)
endif()
