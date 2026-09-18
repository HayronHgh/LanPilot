add_library(rwn_audio
  src/audio.cpp
  src/dynamic_opus.cpp
)

target_include_directories(rwn_audio PUBLIC include)
target_link_libraries(rwn_audio
  PUBLIC rwn::core rwn::transport
  PRIVATE ${CMAKE_DL_LIBS} rwn_project_options
)
add_library(rwn::audio ALIAS rwn_audio)

add_executable(rwn-audio-probe probe.cpp)
target_link_libraries(rwn-audio-probe PRIVATE rwn::audio rwn_project_options)
