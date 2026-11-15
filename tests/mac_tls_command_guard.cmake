if(NOT DEFINED PROGRAM)
  message(FATAL_ERROR "Missing CLI fixture")
endif()
# Valid command arity, deliberately invalid port: parsing must reject before
# identity lookup, file reading, listener construction, capture or input.
execute_process(COMMAND "${PROGRAM}" --stream-visual-tls 127.0.0.1 0
  00 0000000000000000000000000000000000000000000000000000000000000000
  /nonexistent-lanpilot-root view-only h264-only
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 5)
if(NOT result STREQUAL "1" OR NOT error MATCHES "invalid TLS port" OR NOT output STREQUAL "")
  message(FATAL_ERROR "TLS command graph missing or invalid-port boundary changed")
endif()
message(STATUS "tls_command_graph=PASS rejected_before_identity_and_listener=1")
