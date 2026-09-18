add_executable(rwn-broker main.cpp)
target_link_libraries(rwn-broker PRIVATE
  rwn::core rwn::protocol rwn_project_options)
if(APPLE)
  target_link_libraries(rwn-broker PRIVATE rwn::platform_macos)
endif()
