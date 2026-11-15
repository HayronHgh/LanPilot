if(NOT DEFINED PROGRAM)
  message(FATAL_ERROR "Missing application fixture")
endif()
# This incomplete command cannot stream even on the old compatibility parser.
# Verify the dedicated boundary diagnostic, not merely an unknown-CLI exit.
execute_process(COMMAND "${PROGRAM}" --desktop-agent --stream-visual-tls
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 5)
if(NOT result STREQUAL "64" OR
   NOT error MATCHES "Use the configured service endpoint for application streaming" OR
   NOT output STREQUAL "")
  message(FATAL_ERROR "Application streaming bypass was not rejected")
endif()
message(STATUS "application_entry_boundary=PASS listener_started=0")
