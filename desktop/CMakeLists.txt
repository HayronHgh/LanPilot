add_library(rwn_desktop
  src/desktop.cpp
  src/visual_evidence.cpp
  src/visual_trace.cpp
)

target_include_directories(rwn_desktop PUBLIC include)
target_link_libraries(rwn_desktop
  PUBLIC rwn::core rwn::protocol rwn::transport
  PRIVATE rwn_project_options
)
add_library(rwn::desktop ALIAS rwn_desktop)
