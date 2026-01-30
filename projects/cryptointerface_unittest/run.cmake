cmake_minimum_required(VERSION 3.5)

# Skip first 3 arguments - (cmake -P <file>)
set(ARG_NUM 3)
math(EXPR ARGC_COUNT "${CMAKE_ARGC}")
# Loop through caller arguments
while (ARG_NUM LESS ARGC_COUNT)
    set(ALL_ARGS ${ALL_ARGS} ${CMAKE_ARGV${ARG_NUM}})
    # Increment arg count
    math(EXPR ARG_NUM "${ARG_NUM}+1")
endwhile()

message("Running Unit Test...")
execute_process(
    COMMAND ../../../bin_win32/crypto_interface_test.exe ${ALL_ARGS}
    WORKING_DIRECTORY ../../src/crypto/test
    RESULT_VARIABLE rc)
if(NOT rc EQUAL "0")
    message(FATAL_ERROR "${rc}")
  endif()