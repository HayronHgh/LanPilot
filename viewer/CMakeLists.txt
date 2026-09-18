if(WIN32)
  add_executable(rwn-input-queue-probe input_queue_probe.cpp d3d11_renderer.cpp)
  target_link_libraries(rwn-input-queue-probe PRIVATE
    rwn::desktop rwn::platform_windows
    d3d11 dxgi gdi32 shell32 user32 rwn_project_options)
  add_executable(rwn-color-gpu-probe color_gpu_probe.cpp d3d11_renderer.cpp)
  target_link_libraries(rwn-color-gpu-probe PRIVATE
    rwn::desktop rwn::platform_windows
    d3d11 dxgi gdi32 shell32 user32 rwn_project_options)
  add_executable(rwn-decoder-epoch-probe decoder_epoch_probe.cpp d3d11_renderer.cpp)
  target_link_libraries(rwn-decoder-epoch-probe PRIVATE
    rwn::desktop rwn::platform_windows
    d3d11 dxgi gdi32 shell32 user32 rwn_project_options)
  add_executable(rwn-snapshot-receiver-probe snapshot_receiver_probe.cpp d3d11_renderer.cpp)
  target_link_libraries(rwn-snapshot-receiver-probe PRIVATE
    rwn::desktop rwn::platform_windows
    d3d11 dxgi gdi32 shell32 user32 rwn_project_options)
  add_executable(rwn-snapshot-gpu-probe snapshot_gpu_probe.cpp d3d11_renderer.cpp)
  target_link_libraries(rwn-snapshot-gpu-probe PRIVATE
    rwn::desktop rwn::platform_windows
    d3d11 dxgi gdi32 shell32 user32 rwn_project_options)
  add_executable(rwn-viewer WIN32 main.cpp d3d11_renderer.cpp)
  target_link_libraries(rwn-viewer PRIVATE
    rwn::desktop rwn::platform_windows
    d3d11 dxgi gdi32 shell32 user32 rwn_project_options)
  if(MINGW)
    target_link_options(rwn-viewer PRIVATE -municode)
  endif()
endif()
