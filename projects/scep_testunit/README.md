# SCEP Client API Tests

This directory contains tests for the SCEP client API functions.

## Project Structure

```
${MSS_DIR}/projects/scep_testunit/
├── build.sh                      # Build script for the tests
├── clean.sh                      # Clean script
├── CMakeLists.txt                # CMake configuration
├── mocana_flags.txt              # Compile flags for SCEP features
├── build/                        # Build directory (generated)
└── src/scep/testunit/           # Test source files
    ├── test_scep_client.c        # SCEP client API unit tests
    ├── test_scep_utils.c         # SCEP utilities unit tests
    ├── test_scep_context.c       # SCEP context unit tests
    └── test_scep_message.c       # SCEP message unit tests
```

## Test Coverage

### test_scep_client.c (Unit Tests)
- Unit tests for SCEP client API functions
- SCEP connection management
- Certificate enrollment operations

### test_scep_utils.c (Unit Tests)
- Unit tests for SCEP utility functions

### test_scep_context.c (Unit Tests)
- Unit tests for SCEP context management

### test_scep_message.c (Unit Tests)
- Unit tests for SCEP message handling

## Dependencies

- **CMocka 1.1.5**: Testing framework located in `${MOCN_MSS}/cmocka-1.1.5`
- **Mocana MSS**: Core libraries built in `bin_static/` and `bin/` directory
- **SCEP Client API**: Located in `src/scep/` directory

## Building the Tests

### Prerequisites
1. Build the main Mocana MSS libraries first
2. Enable SCEP support in the main build
3. CMocka library will be automatically built if not present

### Build Commands

```bash
# Clean any previous builds
./clean.sh

# Build the tests
./build.sh

# Build with debug symbols
./build.sh --gdb

# Build with code coverage
./build.sh --enable-coverage
```

## Running the Tests

All test executables are built in the `${MSS_DIR}/src/scep/testunit/` directory:

```bash
# Run all tests
./run.sh

# Run a specific test
./run.sh test_scep_client

# Run multiple specific tests
./run.sh test_scep_client test_scep_utils
```

## Test Execution Results

> Executing ./test_scep_client
[==========] Running 32 test(s).
[ RUN      ] test_SCEP_CLIENT_initContext_valid
[       OK ] test_SCEP_CLIENT_initContext_valid
[ RUN      ] test_SCEP_CLIENT_initContext_null_param
[       OK ] test_SCEP_CLIENT_initContext_null_param
[ RUN      ] test_SCEP_CLIENT_initContextEx_null_param
[       OK ] test_SCEP_CLIENT_initContextEx_null_param
[ RUN      ] test_SCEP_CLIENT_initContextEx_valid
[       OK ] test_SCEP_CLIENT_initContextEx_valid
[ RUN      ] test_SCEP_CLIENT_releaseContext_null_param
[       OK ] test_SCEP_CLIENT_releaseContext_null_param
[ RUN      ] test_SCEP_CLIENT_releaseContext_null_pointer_content
[       OK ] test_SCEP_CLIENT_releaseContext_null_pointer_content
[ RUN      ] test_SCEP_CLIENT_setRequestInfo_null_context
[       OK ] test_SCEP_CLIENT_setRequestInfo_null_context
[ RUN      ] test_SCEP_CLIENT_setRequestInfo_null_requestinfo
[       OK ] test_SCEP_CLIENT_setRequestInfo_null_requestinfo
[ RUN      ] test_SCEP_CLIENT_setRequestInfo_valid_pkcs_req
[       OK ] test_SCEP_CLIENT_setRequestInfo_valid_pkcs_req
[ RUN      ] test_SCEP_CLIENT_setRequestInfo_multiple_calls
[       OK ] test_SCEP_CLIENT_setRequestInfo_multiple_calls
[ RUN      ] test_SCEP_CLIENT_generateRequestEx_http_post
[       OK ] test_SCEP_CLIENT_generateRequestEx_http_post
[ RUN      ] test_SCEP_CLIENT_generateRequestEx_http_get
[       OK ] test_SCEP_CLIENT_generateRequestEx_http_get
[ RUN      ] test_SCEP_CLIENT_recvResponse_zero_length
[       OK ] test_SCEP_CLIENT_recvResponse_zero_length
[ RUN      ] test_SCEP_CLIENT_generatePollServerRequest_null_params
[       OK ] test_SCEP_CLIENT_generatePollServerRequest_null_params
[ RUN      ] test_SCEP_CLIENT_generatePollServerRequest_valid_context
[       OK ] test_SCEP_CLIENT_generatePollServerRequest_valid_context
[ RUN      ] test_SCEP_CLIENT_releaseCookie_null
[       OK ] test_SCEP_CLIENT_releaseCookie_null
[ RUN      ] test_SCEP_CLIENT_releasePollCookie_null
[       OK ] test_SCEP_CLIENT_releasePollCookie_null
[ RUN      ] test_SCEP_CLIENT_http_responseHeaderCallback_null_context
[       OK ] test_SCEP_CLIENT_http_responseHeaderCallback_null_context
[ RUN      ] test_SCEP_CLIENT_http_responseHeaderCallback_continue_flag
[       OK ] test_SCEP_CLIENT_http_responseHeaderCallback_continue_flag
[ RUN      ] test_SCEP_CLIENT_http_responseBodyCallback_zero_length
[       OK ] test_SCEP_CLIENT_http_responseBodyCallback_zero_length
[ RUN      ] test_SCEP_CLIENT_http_responseBodyCallback_null_data
[       OK ] test_SCEP_CLIENT_http_responseBodyCallback_null_data
[ RUN      ] test_SCEP_CLIENT_multiple_contexts
[       OK ] test_SCEP_CLIENT_multiple_contexts
[ RUN      ] test_SCEP_CLIENT_getStatus_valid_context
[       OK ] test_SCEP_CLIENT_getStatus_valid_context
[ RUN      ] test_SCEP_CLIENT_isDoneReceivingResponse_valid_context
[       OK ] test_SCEP_CLIENT_isDoneReceivingResponse_valid_context
[ RUN      ] test_SCEP_CLIENT_getHTTPStatusCode_null_context
[       OK ] test_SCEP_CLIENT_getHTTPStatusCode_null_context
[ RUN      ] test_SCEP_CLIENT_getHTTPStatusCode_valid_context
[       OK ] test_SCEP_CLIENT_getHTTPStatusCode_valid_context
[ RUN      ] test_SCEP_CLIENT_getMessageType_null_params
[       OK ] test_SCEP_CLIENT_getMessageType_null_params
[ RUN      ] test_SCEP_CLIENT_getMessageType_valid_context
[       OK ] test_SCEP_CLIENT_getMessageType_valid_context
[ RUN      ] test_SCEP_CLIENT_getFailInfo_null_params
[       OK ] test_SCEP_CLIENT_getFailInfo_null_params
[ RUN      ] test_SCEP_CLIENT_getFailInfo_valid_context
[       OK ] test_SCEP_CLIENT_getFailInfo_valid_context
[ RUN      ] test_SCEP_CLIENT_workflow_sequence
[       OK ] test_SCEP_CLIENT_workflow_sequence
[ RUN      ] test_SCEP_CLIENT_context_reuse
[       OK ] test_SCEP_CLIENT_context_reuse
[==========] 32 test(s) run.
[  PASSED  ] 32 test(s).
> Executing ./test_scep_context
[==========] Running 19 test(s).
[ RUN      ] test_SCEP_CONTEXT_createContext_valid
[       OK ] test_SCEP_CONTEXT_createContext_valid
[ RUN      ] test_SCEP_CONTEXT_createContext_null_param
[       OK ] test_SCEP_CONTEXT_createContext_null_param
[ RUN      ] test_SCEP_CONTEXT_createContext_invalid_role
[       OK ] test_SCEP_CONTEXT_createContext_invalid_role
[ RUN      ] test_SCEP_CONTEXT_resetContext_valid
[       OK ] test_SCEP_CONTEXT_resetContext_valid
[ RUN      ] test_SCEP_CONTEXT_resetContext_null_param
[       OK ] test_SCEP_CONTEXT_resetContext_null_param
[ RUN      ] test_SCEP_CONTEXT_releaseContext_valid
[       OK ] test_SCEP_CONTEXT_releaseContext_valid
[ RUN      ] test_SCEP_CONTEXT_releaseContext_null_param
[       OK ] test_SCEP_CONTEXT_releaseContext_null_param
[ RUN      ] test_SCEP_CONTEXT_resetContextEx_valid
[       OK ] test_SCEP_CONTEXT_resetContextEx_valid
[ RUN      ] test_SCEP_CONTEXT_resetContextEx_null_param
[       OK ] test_SCEP_CONTEXT_resetContextEx_null_param
[ RUN      ] test_SCEP_CONTEXT_multiple_contexts
[       OK ] test_SCEP_CONTEXT_multiple_contexts
[ RUN      ] test_SCEP_CONTEXT_reset_after_release
[       OK ] test_SCEP_CONTEXT_reset_after_release
[ RUN      ] test_SCEP_CONTEXT_multiple_reset
[       OK ] test_SCEP_CONTEXT_multiple_reset
[ RUN      ] test_SCEP_CONTEXT_resetContextEx_flags
[       OK ] test_SCEP_CONTEXT_resetContextEx_flags
[ RUN      ] test_SCEP_CONTEXT_verify_context_structure
[       OK ] test_SCEP_CONTEXT_verify_context_structure
[ RUN      ] test_SCEP_CONTEXT_reset_reusability
[       OK ] test_SCEP_CONTEXT_reset_reusability
[ RUN      ] test_SCEP_CONTEXT_double_release
[       OK ] test_SCEP_CONTEXT_double_release
[ RUN      ] test_SCEP_CONTEXT_releaseRequestInfo_null
[       OK ] test_SCEP_CONTEXT_releaseRequestInfo_null
[ RUN      ] test_SCEP_CONTEXT_releaseRequestInfo_pkcs_req
[       OK ] test_SCEP_CONTEXT_releaseRequestInfo_pkcs_req
[ RUN      ] test_SCEP_CONTEXT_releaseRequestInfo_get_ca_cert
[       OK ] test_SCEP_CONTEXT_releaseRequestInfo_get_ca_cert
[==========] 19 test(s) run.
[  PASSED  ] 19 test(s).
> Executing ./test_scep_utils
[==========] Running 18 test(s).
[ RUN      ] test_SCEP_UTILS_integerToString_valid
[       OK ] test_SCEP_UTILS_integerToString_valid
[ RUN      ] test_SCEP_UTILS_integerToString_single_byte
[       OK ] test_SCEP_UTILS_integerToString_single_byte
[ RUN      ] test_SCEP_UTILS_integerToString_zeros
[       OK ] test_SCEP_UTILS_integerToString_zeros
[ RUN      ] test_SCEP_UTILS_integerToString_max_values
[       OK ] test_SCEP_UTILS_integerToString_max_values
[ RUN      ] test_SCEP_UTILS_integerToString_mixed_values
[       OK ] test_SCEP_UTILS_integerToString_mixed_values
[ RUN      ] test_SCEP_UTILS_integerToString_insufficient_buffer
[       OK ] test_SCEP_UTILS_integerToString_insufficient_buffer
[ RUN      ] test_SCEP_UTILS_integerToString_exact_buffer
[       OK ] test_SCEP_UTILS_integerToString_exact_buffer
[ RUN      ] test_SCEP_UTILS_integerToString_zero_length
[       OK ] test_SCEP_UTILS_integerToString_zero_length
[ RUN      ] test_SCEP_UTILS_integerToString_large_input
[       OK ] test_SCEP_UTILS_integerToString_large_input
[ RUN      ] test_SCEP_UTILS_integerToString_alternating_pattern
[       OK ] test_SCEP_UTILS_integerToString_alternating_pattern
[ RUN      ] test_SCEP_UTILS_integerToString_ascending
[       OK ] test_SCEP_UTILS_integerToString_ascending
[ RUN      ] test_SCEP_UTILS_integerToString_descending
[       OK ] test_SCEP_UTILS_integerToString_descending
[ RUN      ] test_SCEP_UTILS_integerToString_boundary_0f
[       OK ] test_SCEP_UTILS_integerToString_boundary_0f
[ RUN      ] test_SCEP_UTILS_integerToString_very_large
[       OK ] test_SCEP_UTILS_integerToString_very_large
[ RUN      ] test_SCEP_UTILS_integerToString_exact_required_size
[       OK ] test_SCEP_UTILS_integerToString_exact_required_size
[ RUN      ] test_SCEP_UTILS_integerToString_prime_pattern
[       OK ] test_SCEP_UTILS_integerToString_prime_pattern
[ RUN      ] test_SCEP_UTILS_integerToString_repeated_conversion
[       OK ] test_SCEP_UTILS_integerToString_repeated_conversion
[ RUN      ] test_SCEP_UTILS_integerToString_nibble_boundaries
[       OK ] test_SCEP_UTILS_integerToString_nibble_boundaries
[==========] 18 test(s) run.
[  PASSED  ] 18 test(s).
> Executing ./test_scep_message
[==========] Running 25 test(s).
[ RUN      ] test_SCEP_MESSAGE_generatePayLoad_null_params
[       OK ] test_SCEP_MESSAGE_generatePayLoad_null_params
[ RUN      ] test_SCEP_MESSAGE_generatePayLoad_null_key
[       OK ] test_SCEP_MESSAGE_generatePayLoad_null_key
[ RUN      ] test_SCEP_MESSAGE_generatePayLoad_minimal_pkcs_req
[       OK ] test_SCEP_MESSAGE_generatePayLoad_minimal_pkcs_req
[ RUN      ] test_SCEP_MESSAGE_generatePayLoad_get_cert
[       OK ] test_SCEP_MESSAGE_generatePayLoad_get_cert
[ RUN      ] test_SCEP_MESSAGE_generatePayLoad_get_crl
[       OK ] test_SCEP_MESSAGE_generatePayLoad_get_crl
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_zero_length
[       OK ] test_SCEP_MESSAGE_breakIntoLines_zero_length
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_small_data
[       OK ] test_SCEP_MESSAGE_breakIntoLines_small_data
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_valid_data
[       OK ] test_SCEP_MESSAGE_breakIntoLines_valid_data
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_large_data
[       OK ] test_SCEP_MESSAGE_breakIntoLines_large_data
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_exactly_64_bytes
[       OK ] test_SCEP_MESSAGE_breakIntoLines_exactly_64_bytes
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_65_bytes
[       OK ] test_SCEP_MESSAGE_breakIntoLines_65_bytes
[ RUN      ] test_SCEP_MESSAGE_breakIntoLines_max_typical_data
[       OK ] test_SCEP_MESSAGE_breakIntoLines_max_typical_data
[ RUN      ] test_SCEP_MESSAGE_verisign_oids_defined
[       OK ] test_SCEP_MESSAGE_verisign_oids_defined
[ RUN      ] test_SCEP_MESSAGE_oid_lengths
[       OK ] test_SCEP_MESSAGE_oid_lengths
[ RUN      ] test_SCEP_MESSAGE_oid_uniqueness
[       OK ] test_SCEP_MESSAGE_oid_uniqueness
[ RUN      ] test_SCEP_MESSAGE_parsePkcsResponse_null_context
[       OK ] test_SCEP_MESSAGE_parsePkcsResponse_null_context
[ RUN      ] test_SCEP_MESSAGE_parsePkcsResponse_zero_length
[       OK ] test_SCEP_MESSAGE_parsePkcsResponse_zero_length
[ RUN      ] test_SCEP_MESSAGE_parsePkcsResponse_pki_message_type
[       OK ] test_SCEP_MESSAGE_parsePkcsResponse_pki_message_type
[ RUN      ] test_SCEP_MESSAGE_parsePkcsResponse_cert_chain_type
[       OK ] test_SCEP_MESSAGE_parsePkcsResponse_cert_chain_type
[ RUN      ] test_SCEP_MESSAGE_parsePkcsResponse_invalid_type
[       OK ] test_SCEP_MESSAGE_parsePkcsResponse_invalid_type
[ RUN      ] test_SCEP_MESSAGE_parsePkcsResponse_x509_cert
[       OK ] test_SCEP_MESSAGE_parsePkcsResponse_x509_cert
[ RUN      ] test_SCEP_MESSAGE_generatePkiRequestMessage_null_params
[       OK ] test_SCEP_MESSAGE_generatePkiRequestMessage_null_params
[ RUN      ] test_SCEP_MESSAGE_generatePkiRequestMessage_null_output
[       OK ] test_SCEP_MESSAGE_generatePkiRequestMessage_null_output
[ RUN      ] test_SCEP_MESSAGE_generatePkiRequestMessage_invalid_roletype
[       OK ] test_SCEP_MESSAGE_generatePkiRequestMessage_invalid_roletype
[ RUN      ] test_SCEP_MESSAGE_generatePkiRequestMessage_missing_cert
[       OK ] test_SCEP_MESSAGE_generatePkiRequestMessage_missing_cert
[==========] 25 test(s) run.
[  PASSED  ] 25 test(s).

## Integration with Main Build

To build SCEP unit tests as part of the main build:

```bash
cd ${MSS_DIR}
cmake -DENABLE_SCEP=ON -DENABLE_SCEP_UNITTEST=ON -B build
cmake --build build
```

## Build and run SCEP test suite

Run all tests:
```bash
${MOCN_MSS}/scripts/scep/build_scep_client_test.sh --enable-tests
```

## Build and run SCEP test suite with gcov coverage enabled

```bash
${MOCN_MSS}/scripts/scep/build_scep_client_test.sh --enable-tests --enable-coverage
```

## Build and run tests individually

To build all tests:
```bash
cd ${MSS_DIR}/projects/scep_testunit
./clean.sh
./build.sh --gdb
```

Run individual test executables:
```bash
# Run unit tests
${MSS_DIR}/src/scep/testunit/test_scep_client
${MSS_DIR}/src/scep/testunit/test_scep_context
${MSS_DIR}/src/scep/testunit/test_scep_utils
${MSS_DIR}/src/scep/testunit/test_scep_message
```

Run all tests via CTest:
```bash
cd ${MSS_DIR}/projects/scep_testunit/build
ctest -V
```

## Test Development

When adding new tests:
1. Create test file in `src/scep/testunit/`
2. Add executable and test in `CMakeLists.txt`
3. Follow the naming convention: `test_scep_<module>.c`
4. Use CMocka framework for assertions and test structure

## Troubleshooting

If CMocka is not found:
```bash
cd ${MSS_DIR}
wget https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
tar -xf cmocka-1.1.5.tar.xz
cd cmocka-1.1.5
mkdir build && cd build
cmake -D WITH_STATIC_LIB=ON ..
make
cp src/libcmocka-static.a ${MSS_DIR}/bin_static/
```

## Code Coverage

To generate code coverage reports:
```bash
./build.sh --enable-coverage
./run.sh
# Generate coverage reports using gcov/lcov
```
