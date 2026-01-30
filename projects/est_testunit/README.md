# EST Client API Tests

This directory contains tests for the EST client API functions.

## Project Structure

```
${MSS_DIR}/projects/est_testunit/
├── build.sh                      # Build script for the tests
├── clean.sh                      # Clean script
├── CMakeLists.txt                # CMake configuration
├── mocana_flags.txt              # Compile flags for EST features
├── build/                        # Build directory (generated)
└── src/est/testunit/            # Test source files
    ├── test_est_client_api.c     # EST client API sanity tests
    ├── test_est_utils.c          # EST utilities unit tests
    ├── test_est_cert_utils.c     # EST certificate utilities unit tests
    ├── test_est_context.c        # EST context unit tests
    ├── test_est_message.c        # EST message unit tests
    └── test_est_client_operations.c  # EST client operations unit tests
```

## Test Coverage

### test_est_client_api.c (Sanity Tests)
- 🔄 EST_openConnection api validation
- 🔄 EST_closeConnection api validation
- 🔄 EST_sendCaCertsRequest api validation
- 🔄 EST_sendCsrAttrsRequest api validation
- 🔄 EST_sendSimpleEnrollRequest api validation
- 🔄 EST_sendSimpleReEnrollRequest api validation
- 🔄 EST_generateCSRRequestFromConfig api validation
- 🔄 EST_receiveResponse api validation
- 🔄 EST_responseBodyCallbackHandle api validation
- 🔄 EST_requestBodyCallback api validation

### test_est_utils.c (Unit Tests)
- Unit tests for EST utility functions

### test_est_cert_utils.c (Unit Tests)
- Unit tests for EST certificate utility functions

### test_est_context.c (Unit Tests)
- Unit tests for EST context management

### test_est_message.c (Unit Tests)
- Unit tests for EST message handling

### test_est_client_operations.c (Unit Tests)
- Unit tests for EST client operations

## Dependencies

- **CMocka 1.1.5**: Testing framework located in `${MOCN_MSS}/cmocka-1.1.5`
- **Mocana MSS**: Core libraries built in `bin_static/` and `bin/` directory
- **EST Client API**: Located in `src/est/` directory

## Test Execution

All test executables are built in the `${MSS_DIR}/src/est/testunit/` directory:
> Executing ./test_est_utils
[==========] Running 12 test(s).
[ RUN      ] test_EST_UTILS_filterPkcs7Message_valid_base64
[       OK ] test_EST_UTILS_filterPkcs7Message_valid_base64
[ RUN      ] test_EST_UTILS_filterPkcs7Message_with_newlines
[       OK ] test_EST_UTILS_filterPkcs7Message_with_newlines
[ RUN      ] test_EST_UTILS_filterPkcs7Message_with_spaces
[       OK ] test_EST_UTILS_filterPkcs7Message_with_spaces
[ RUN      ] test_EST_UTILS_filterPkcs7Message_mixed_whitespace
[       OK ] test_EST_UTILS_filterPkcs7Message_mixed_whitespace
[ RUN      ] test_EST_UTILS_filterPkcs7Message_empty_input
[       OK ] test_EST_UTILS_filterPkcs7Message_empty_input
[ RUN      ] test_EST_UTILS_filterPkcs7Message_verify_filtered_content
[       OK ] test_EST_UTILS_filterPkcs7Message_verify_filtered_content
[ RUN      ] test_EST_UTILS_filterPkcs7Message_real_base64_cert
[       OK ] test_EST_UTILS_filterPkcs7Message_real_base64_cert
[ RUN      ] test_EST_UTILS_filterPkcs7Message_only_base64_chars
[       OK ] test_EST_UTILS_filterPkcs7Message_only_base64_chars
[ RUN      ] test_EST_UTILS_filterPkcs7Message_leading_trailing_whitespace
[       OK ] test_EST_UTILS_filterPkcs7Message_leading_trailing_whitespace
[ RUN      ] test_EST_UTILS_filterPkcs7Message_multiple_equal_signs
[       OK ] test_EST_UTILS_filterPkcs7Message_multiple_equal_signs
[ RUN      ] test_EST_UTILS_filterPkcs7Message_pem_header_footer
[       OK ] test_EST_UTILS_filterPkcs7Message_pem_header_footer
[ RUN      ] test_EST_UTILS_filterPkcs7Message_invalid_chars_filtered
[       OK ] test_EST_UTILS_filterPkcs7Message_invalid_chars_filtered
[==========] 12 test(s) run.
[  PASSED  ] 12 test(s).
> Executing ./test_est_message
[==========] Running 16 test(s).
[ RUN      ] test_EST_setCookie_null_context
[       OK ] test_EST_setCookie_null_context
[ RUN      ] test_EST_freeCookie_null_context
[       OK ] test_EST_freeCookie_null_context
[ RUN      ] test_EST_receiveResponse_null_context
[       OK ] test_EST_receiveResponse_null_context
[ RUN      ] test_EST_receiveResponse_null_output
[       OK ] test_EST_receiveResponse_null_output
[ RUN      ] test_EST_validateReceivedCertificate_null_params
[       OK ] test_EST_validateReceivedCertificate_null_params
[ RUN      ] test_EST_MESSAGE_CertReqToCSR_null_input
[       OK ] test_EST_MESSAGE_CertReqToCSR_null_input
[ RUN      ] test_EST_MESSAGE_parseResponse_null_input
[       OK ] test_EST_MESSAGE_parseResponse_null_input
[ RUN      ] test_EST_MESSAGE_parseResponse_null_output
[       OK ] test_EST_MESSAGE_parseResponse_null_output
[ RUN      ] test_EST_MESSAGE_parseResponse_csrattrs_null
[       OK ] test_EST_MESSAGE_parseResponse_csrattrs_null
[ RUN      ] test_EST_MESSAGE_CertReqToCSR_valid_minimal
[       OK ] test_EST_MESSAGE_CertReqToCSR_valid_minimal
[ RUN      ] test_EST_MESSAGE_CertReqToCSR_zero_length_input
[       OK ] test_EST_MESSAGE_CertReqToCSR_zero_length_input
[ RUN      ] test_EST_MESSAGE_parseResponse_validates_type
[       OK ] test_EST_MESSAGE_parseResponse_validates_type
[ RUN      ] test_EST_MESSAGE_parseResponse_csrattrs_valid
[       OK ] test_EST_MESSAGE_parseResponse_csrattrs_valid
[ RUN      ] test_EST_MESSAGE_CertReqToCSR_malformed_asn1
[       OK ] test_EST_MESSAGE_CertReqToCSR_malformed_asn1
[ RUN      ] test_EST_MESSAGE_parseResponse_validates_output_length
[       OK ] test_EST_MESSAGE_parseResponse_validates_output_length
[ RUN      ] test_EST_validateReceivedCertificate_null_store
[       OK ] test_EST_validateReceivedCertificate_null_store
[==========] 16 test(s) run.
[  PASSED  ] 16 test(s).
> Executing ./test_est_cert_utils
[==========] Running 24 test(s).
[ RUN      ] test_EST_CERT_UTIL_getFullPath_valid
[       OK ] test_EST_CERT_UTIL_getFullPath_valid
[ RUN      ] test_EST_CERT_UTIL_getFullPath_null_directory
[       OK ] test_EST_CERT_UTIL_getFullPath_null_directory
[ RUN      ] test_EST_CERT_UTIL_getFullPath_null_name
[       OK ] test_EST_CERT_UTIL_getFullPath_null_name
[ RUN      ] test_EST_CERT_UTIL_setIsWriteExtensions
[       OK ] test_EST_CERT_UTIL_setIsWriteExtensions
[ RUN      ] test_EST_CERT_UTIL_createDirectory_valid
[       OK ] test_EST_CERT_UTIL_createDirectory_valid
[ RUN      ] test_EST_CERT_UTIL_createDirectory_null
[       OK ] test_EST_CERT_UTIL_createDirectory_null
[ RUN      ] test_EST_CERT_UTIL_getPkiDBPtr
[       OK ] test_EST_CERT_UTIL_getPkiDBPtr
[ RUN      ] test_EST_CERT_UTIL_createPkiDB_valid
[       OK ] test_EST_CERT_UTIL_createPkiDB_valid
[ RUN      ] test_EST_CERT_UTIL_buildKeyStoreFullPath_valid
[       OK ] test_EST_CERT_UTIL_buildKeyStoreFullPath_valid
[ RUN      ] test_EST_CERT_UTIL_buildKeyStoreFullPath_null_keystore
[       OK ] test_EST_CERT_UTIL_buildKeyStoreFullPath_null_keystore
[ RUN      ] test_EST_CERT_UTIL_buildKeyStoreFullPath_null_subdir
[       OK ] test_EST_CERT_UTIL_buildKeyStoreFullPath_null_subdir
[ RUN      ] test_EST_CERT_UTIL_generateOIDFromString_null_output
[       OK ] test_EST_CERT_UTIL_generateOIDFromString_null_output
[ RUN      ] test_EST_CERT_UTIL_convertStringToBmpByteArray_valid
[       OK ] test_EST_CERT_UTIL_convertStringToBmpByteArray_valid
[ RUN      ] test_EST_CERT_UTIL_writeExtensionToFile_null
[       OK ] test_EST_CERT_UTIL_writeExtensionToFile_null
[ RUN      ] test_EST_CERT_UTIL_makeExtensionsFromBuffer_null
[       OK ] test_EST_CERT_UTIL_makeExtensionsFromBuffer_null
[ RUN      ] test_EST_CERT_UTIL_makeExtensionsFromBuffer_zero_len
[       OK ] test_EST_CERT_UTIL_makeExtensionsFromBuffer_zero_len
[ RUN      ] test_EST_CERT_UTIL_makeExtensionsFromConfigFile_null
[       OK ] test_EST_CERT_UTIL_makeExtensionsFromConfigFile_null
[ RUN      ] test_EST_CERT_UTIL_convertStringToByteArray_validates_output
[       OK ] test_EST_CERT_UTIL_convertStringToByteArray_validates_output
[ RUN      ] test_EST_CERT_UTIL_convertStringToByteArray_hex_values
[       OK ] test_EST_CERT_UTIL_convertStringToByteArray_hex_values
[ RUN      ] test_EST_CERT_UTIL_generateOIDFromString_validates_rsa_oid
[       OK ] test_EST_CERT_UTIL_generateOIDFromString_validates_rsa_oid
[ RUN      ] test_EST_CERT_UTIL_generateOIDFromString_validates_sha256_oid
[       OK ] test_EST_CERT_UTIL_generateOIDFromString_validates_sha256_oid
[ RUN      ] test_EST_CERT_UTIL_getFullPath_creates_correct_path
[       OK ] test_EST_CERT_UTIL_getFullPath_creates_correct_path
[ RUN      ] test_EST_CERT_UTIL_buildKeyStoreFullPath_validates_structure
[       OK ] test_EST_CERT_UTIL_buildKeyStoreFullPath_validates_structure
[ RUN      ] test_EST_CERT_UTIL_convertStringToBmpByteArray_validates_encoding
[       OK ] test_EST_CERT_UTIL_convertStringToBmpByteArray_validates_encoding
[==========] 24 test(s) run.
[  PASSED  ] 24 test(s).
> Executing ./test_est_client_api
[==========] Running 3 test(s).
[ RUN      ] test_est_send_ca_certs_request
[       OK ] test_est_send_ca_certs_request
[ RUN      ] test_est_send_simple_enroll_request
[       OK ] test_est_send_simple_enroll_request
[ RUN      ] test_est_send_simple_reenroll_request
[       OK ] test_est_send_simple_reenroll_request
[==========] 3 test(s) run.
[  PASSED  ] 3 test(s).
> Executing ./test_est_client_operations
[==========] Running 24 test(s).
[ RUN      ] test_EST_sendCaCertsRequest_null_context
[       OK ] test_EST_sendCaCertsRequest_null_context
[ RUN      ] test_EST_sendCaCertsRequest_null_url
[       OK ] test_EST_sendCaCertsRequest_null_url
[ RUN      ] test_EST_sendSimpleEnrollRequest_null_context
[       OK ] test_EST_sendSimpleEnrollRequest_null_context
[ RUN      ] test_EST_sendSimpleEnrollRequest_zero_csr_length
[       OK ] test_EST_sendSimpleEnrollRequest_zero_csr_length
[ RUN      ] test_EST_sendCsrAttrsRequest_null_context
[       OK ] test_EST_sendCsrAttrsRequest_null_context
[ RUN      ] test_EST_sendServerKeyGenRequest_null_context
[       OK ] test_EST_sendServerKeyGenRequest_null_context
[ RUN      ] test_EST_sendFullCmcRequest_null_context
[       OK ] test_EST_sendFullCmcRequest_null_context
[ RUN      ] test_EST_openConnection_null_params
[       OK ] test_EST_openConnection_null_params
[ RUN      ] test_EST_openConnection_invalid_port
[       OK ] test_EST_openConnection_invalid_port
[ RUN      ] test_EST_closeConnection_null_context
[       OK ] test_EST_closeConnection_null_context
[ RUN      ] test_EST_generateCSRRequestFromConfig_null_params
[       OK ] test_EST_generateCSRRequestFromConfig_null_params
[ RUN      ] test_EST_sendCaCertsRequest_validates_url_format
[       OK ] test_EST_sendCaCertsRequest_validates_url_format
[ RUN      ] test_EST_sendSimpleEnrollRequest_validates_path
[       OK ] test_EST_sendSimpleEnrollRequest_validates_path
[ RUN      ] test_EST_sendCsrAttrsRequest_validates_server_identity
[       OK ] test_EST_sendCsrAttrsRequest_validates_server_identity
[ RUN      ] test_EST_sendServerKeyGenRequest_validates_params
[       OK ] test_EST_sendServerKeyGenRequest_validates_params
[ RUN      ] test_EST_sendFullCmcRequest_validates_request_types
[       OK ] test_EST_sendFullCmcRequest_validates_request_types
[ RUN      ] test_EST_openConnection_validates_ports
[       OK ] test_EST_openConnection_validates_ports
[ RUN      ] test_EST_openConnection_with_ocsp
[       OK ] test_EST_openConnection_with_ocsp
[ RUN      ] test_EST_openConnection_with_pqc
[       OK ] test_EST_openConnection_with_pqc
[ RUN      ] test_EST_closeConnection_with_valid_instance
[       OK ] test_EST_closeConnection_with_valid_instance
[ RUN      ] test_EST_setCookie_null_context
[       OK ] test_EST_setCookie_null_context
[ RUN      ] test_EST_setCookie_null_body
[       OK ] test_EST_setCookie_null_body
[ RUN      ] test_EST_setCookie_zero_length
[       OK ] test_EST_setCookie_zero_length
[ RUN      ] test_EST_freeCookie_null_context
[       OK ] test_EST_freeCookie_null_context
[==========] 24 test(s) run.
[  PASSED  ] 24 test(s).
> Executing ./test_est_context
[==========] Running 13 test(s).
[ RUN      ] test_EST_parseEndpoint_valid
[       OK ] test_EST_parseEndpoint_valid
[ RUN      ] test_EST_parseEndpoint_no_label
[       OK ] test_EST_parseEndpoint_no_label
[ RUN      ] test_EST_parseEndpoint_null_input
[       OK ] test_EST_parseEndpoint_null_input
[ RUN      ] test_EST_filterPkcs7Message_valid
[       OK ] test_EST_filterPkcs7Message_valid
[ RUN      ] test_EST_filterPkcs7Message_null_input
[       OK ] test_EST_filterPkcs7Message_null_input
[ RUN      ] test_EST_estSettings_returns_valid
[       OK ] test_EST_estSettings_returns_valid
[ RUN      ] test_EST_parseEndpoint_validates_server_extraction
[       OK ] test_EST_parseEndpoint_validates_server_extraction
[ RUN      ] test_EST_parseEndpoint_with_port
[       OK ] test_EST_parseEndpoint_with_port
[ RUN      ] test_EST_parseEndpoint_simpleenroll_path
[       OK ] test_EST_parseEndpoint_simpleenroll_path
[ RUN      ] test_EST_parseEndpoint_cacerts_path
[       OK ] test_EST_parseEndpoint_cacerts_path
[ RUN      ] test_EST_filterPkcs7Message_validates_content
[       OK ] test_EST_filterPkcs7Message_validates_content
[ RUN      ] test_EST_filterPkcs7Message_pem_format
[       OK ] test_EST_filterPkcs7Message_pem_format
[ RUN      ] test_EST_parseEndpoint_ipv4_address
[       OK ] test_EST_parseEndpoint_ipv4_address
[==========] 13 test(s) run.
[  PASSED  ] 13 test(s).

## Build and run EST test suite

> **Note**: To run EST sanity tests, you must set the `EST_PASS` environment variable:
> ```bash
> export EST_PASS=your_password
> ```

Run all tests (sanity tests + unit tests):
```bash
${MOCN_MSS}/scripts/est/build_est_client_test.sh --enable-tests
```

## Build and run EST test suite with gcov coverage enabled

```bash
${MOCN_MSS}/scripts/est/build_est_client_test.sh --enable-tests --enable-coverage
```

## Build and run tests individually

To build all tests:
```bash
cd ${MSS_DIR}/projects/est_testunit
./clean.sh
./build.sh --gdb
```

Run individual test executables:
```bash
# Run sanity tests
${MSS_DIR}/src/est/testunit/test_est_client_api

# Run unit tests
${MSS_DIR}/src/est/testunit/test_est_utils
${MSS_DIR}/src/est/testunit/test_est_cert_utils
${MSS_DIR}/src/est/testunit/test_est_context
${MSS_DIR}/src/est/testunit/test_est_message
${MSS_DIR}/src/est/testunit/test_est_client_operations
```

Run all tests via CTest:
```bash
cd ${MSS_DIR}/projects/est_testunit/build
ctest -V
```
