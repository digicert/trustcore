#!/bin/bash

################################################################################
# TrustCore NanoROOT TAP Test Suite
#
# Description:
#   Comprehensive test suite for NanoROOT TAP operations including:
#   - Seal/Unseal operations
#   - RSA signature operations (2K, 3K, 4K)
#   - Post-Quantum MLDSA signature operations (44, 65, 87)
#   - ECC signature operations (P-256, P-384, P-521)
#   - OpenSSL cross-verification
#
# Usage:
#   ./run_tap_nanoroot_test.sh [OPTIONS]
#
# Options:
#   -v, --verbose     Enable verbose output
#   -h, --help        Display this help message
#   -c, --cleanup     Clean up test artifacts after completion
#
# Test Selection (by default all tests run):
#   --seal            Run only seal/unseal tests
#   --rsa             Run only RSA signature tests (2K, 3K, 4K)
#   --rsa8k           Run RSA 8K signature tests (must be explicitly specified)
#   --ecc             Run only ECC signature tests
#   --mldsa           Run only MLDSA (Post-Quantum) signature tests
#   --all             Run all tests (default, excludes RSA 8K)
#
# Examples:
#   ./run_tap_nanoroot_test.sh                    # Run all tests (excludes RSA 8K)
#   ./run_tap_nanoroot_test.sh --seal --rsa       # Run seal/unseal and RSA tests only
#   ./run_tap_nanoroot_test.sh --rsa --rsa8k      # Run all RSA tests including 8K
#   ./run_tap_nanoroot_test.sh --rsa8k --verbose  # Run only RSA 8K tests with verbose output
#   ./run_tap_nanoroot_test.sh --mldsa --verbose  # Run MLDSA tests with verbose output
#
################################################################################

set -u  # Exit on undefined variables
set -o pipefail  # Only set pipefail in bash
# Don't use set -e so individual test failures don't exit the script

################################################################################
# Global Variables
################################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
readonly TMP_DIR="./tmp_nanoroot"
readonly TEST_DATA_FILE="${TMP_DIR}/data10KiB.bin"
readonly CONFIG_FILE="samples/nanoroot/config/nanoroot_smp.conf"
readonly TAP_EXECUTABLE="samples/bin/tap_nanoroot_example"
readonly FINGERPRINT_SCRIPT="samples/nanoroot/config/setFingerPrintValues.sh"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0
TESTS_STARTED=false

# Options
VERBOSE=false
CLEANUP=false

# Test selection flags (default: run all except RSA 8K)
RUN_SEAL=false
RUN_RSA=false
RUN_RSA8K=false
RUN_ECC=false
RUN_MLDSA=false
RUN_ALL=true

################################################################################
# Helper Functions
################################################################################

# Print colored output
print_info() {
    echo -e "\033[0;36m[INFO]\033[0m $*"
}

print_success() {
    echo -e "\033[0;32m[PASS]\033[0m $*"
}

print_error() {
    echo -e "\033[0;31m[FAIL]\033[0m $*" >&2
}

print_warning() {
    echo -e "\033[0;33m[WARN]\033[0m $*"
}

print_header() {
    echo ""
    echo "================================================================================"
    echo "$*"
    echo "================================================================================"
}

# Display usage information
usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \?//' | head -n -1
    exit 0
}

# Cleanup test artifacts
cleanup_artifacts() {
    print_info "Cleaning up test artifacts..."
    
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}" && print_info "  Removed: ${TMP_DIR}"
    fi
}

# Trap for cleanup on exit
cleanup_on_exit() {
    local exit_code=$?
    
    if [ "$CLEANUP" = true ]; then
        cleanup_artifacts
    fi
    
    # Only print test summary if tests were actually started
    if [ "$TESTS_STARTED" = true ]; then
        print_test_summary
        local summary_exit=$?
        
        # Exit with failure if tests failed
        if [ $summary_exit -ne 0 ]; then
            exit 1
        fi
        exit 0
    else
        # If tests never started, preserve the original exit code
        exit "$exit_code"
    fi
}

trap cleanup_on_exit EXIT

# Validate prerequisites
validate_prerequisites() {
    print_header "Validating Prerequisites"
    
    # Check if running from repo root by looking for permanent directories
    if [ ! -d "projects" ] || [ ! -d "src" ] || [ ! -d "samples" ]; then
        print_error "Must run from repository root directory"
        print_info "Current directory: $(pwd)"
        print_info "Expected directory: ${REPO_DIR}"
        print_info "Please run this script from the repository root"
        exit 1
    fi
    
    # Check if samples/bin directory exists
    if [ ! -d "samples/bin" ]; then
        print_error "samples/bin directory not found"
        print_info "The project needs to be built before running tests"
        print_info "Please build the project from repository root using:"
        print_info "  cmake -DENABLE_NANOROOT=ON -DBUILD_SAMPLES=ON -B build -S ."
        print_info "  cmake --build build"
        exit 1
    fi
    
    # Check for required executable
    if [ ! -f "${TAP_EXECUTABLE}" ]; then
        print_error "TAP executable not found: ${TAP_EXECUTABLE}"
        print_info "Please build the project from repository root using:"
        print_info "  cmake -DENABLE_NANOROOT=ON -DBUILD_SAMPLES=ON -B build -S ."
        print_info "  cmake --build build"
        exit 1
    fi
    
    if [ ! -x "${TAP_EXECUTABLE}" ]; then
        print_error "TAP executable is not executable: ${TAP_EXECUTABLE}"
        print_info "Making it executable..."
        chmod +x "${TAP_EXECUTABLE}" || {
            print_error "Failed to make executable"
            exit 1
        }
    fi
    
    # Check for required config file
    if [ ! -f "${CONFIG_FILE}" ]; then
        print_error "Config file not found: ${CONFIG_FILE}"
        exit 1
    fi
    
    # Check for fingerprint script
    if [ ! -f "${FINGERPRINT_SCRIPT}" ]; then
        print_warning "Fingerprint script not found: ${FINGERPRINT_SCRIPT}"
    fi
    
    # Check for OpenSSL
    if ! command -v openssl &> /dev/null; then
        print_warning "OpenSSL not found - cross-verification tests will be skipped"
    fi
    
    # Check for dd utility
    if ! command -v dd &> /dev/null; then
        print_error "dd utility not found - required for test data generation"
        exit 1
    fi
    
    print_success "All prerequisites validated"
}

# Run a test command with error handling
run_test() {
    local test_name="$1"
    shift
    local cmd=("$@")
    local exit_code=0
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [ "$VERBOSE" = true ]; then
        print_info "Running: ${cmd[*]}"
    fi
    
    # Run command and capture output and exit code
    local output
    if output=$("${cmd[@]}" 2>&1); then
        exit_code=0
    else
        exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        [ "$VERBOSE" = true ] && echo "$output"
        return 0
    else
        print_error "$test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$output" >&2
        return 1
    fi
}

# Print test summary
print_test_summary() {
    print_header "Test Summary"
    echo "Total Tests:  ${TESTS_TOTAL}"
    echo "Passed:       ${TESTS_PASSED}"
    echo "Failed:       ${TESTS_FAILED}"
    echo ""
    
    if [ ${TESTS_FAILED} -eq 0 ]; then
        print_success "All tests passed!"
        return 0
    else
        print_error "${TESTS_FAILED} test(s) failed"
        return 1
    fi
}

################################################################################
# Main Functions
################################################################################

# Parse command line arguments
parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--cleanup)
                CLEANUP=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            --seal)
                RUN_SEAL=true
                RUN_ALL=false
                shift
                ;;
            --rsa)
                RUN_RSA=true
                RUN_ALL=false
                shift
                ;;
            --rsa8k)
                RUN_RSA8K=true
                RUN_ALL=false
                shift
                ;;
            --ecc)
                RUN_ECC=true
                RUN_ALL=false
                shift
                ;;
            --mldsa)
                RUN_MLDSA=true
                RUN_ALL=false
                shift
                ;;
            --all)
                RUN_ALL=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # If no specific tests selected, run all (except RSA 8K which must be explicit)
    if [ "$RUN_ALL" = true ]; then
        RUN_SEAL=true
        RUN_RSA=true
        RUN_ECC=true
        RUN_MLDSA=true
        # RUN_RSA8K remains false unless explicitly specified
    fi
}

# Setup test environment
setup_environment() {
    print_header "Setting Up Test Environment"
    
    # Change to repository root
    cd "${REPO_DIR}" || exit 1
    print_info "Working directory: $(pwd)"
    
    # Create temporary directory for test artifacts
    if [ -d "${TMP_DIR}" ]; then
        print_warning "Temporary directory already exists: ${TMP_DIR}"
        print_info "Cleaning existing temporary directory..."
        rm -rf "${TMP_DIR}"
    fi
    
    mkdir -p "${TMP_DIR}" || {
        print_error "Failed to create temporary directory: ${TMP_DIR}"
        exit 1
    }
    print_success "Created temporary directory: ${TMP_DIR}"
    
    # Set library path
    export LD_LIBRARY_PATH="lib/:crypto_lib/linux-x86_64/:${LD_LIBRARY_PATH:-}"
    print_info "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
    
    # Source fingerprint environment variables if available
    if [ -f "${FINGERPRINT_SCRIPT}" ]; then
        # shellcheck disable=SC1090
        . "${FINGERPRINT_SCRIPT}"
        print_success "Loaded fingerprint environment variables"
    fi
    
    # Generate test data
    print_info "Generating test data file: ${TEST_DATA_FILE} (10 KiB)"
    if dd if=/dev/urandom of="${TEST_DATA_FILE}" bs=1K count=10 status=none 2>/dev/null; then
        print_success "Test data generated successfully"
    else
        print_error "Failed to generate test data"
        exit 1
    fi
}

# Test seal and unseal operations
test_seal_unseal() {
    print_header "Testing Seal/Unseal Operations"
    
    local encrypted_file="${TMP_DIR}/encrypted_10KiB.bin"
    local recovered_file="${TMP_DIR}/recovered_10KiB.bin"
    
    # Seal operation
    run_test "Seal operation" \
        "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
        --infile "${TEST_DATA_FILE}" --outfile "${encrypted_file}" \
        --seal --passphrase digicert
    
    # Unseal operation
    run_test "Unseal operation" \
        "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
        --infile "${encrypted_file}" --outfile "${recovered_file}" \
        --unseal --passphrase digicert
    
    # Verify data integrity
    if [ -f "${recovered_file}" ]; then
        run_test "Seal/Unseal data integrity verification" cmp -s "${TEST_DATA_FILE}" "${recovered_file}"
    fi
}

# Test RSA signature operations (2K, 3K, 4K)
test_rsa_signatures() {
    print_header "Testing RSA Signature Operations (2K, 3K, 4K)"
    
    local -a rsa_tests=(
        "2K:100000002:1:sha256"
        "3K:100000003:1:sha256"
        "4K:100000004:2:sha512"
    )
    
    for test_config in "${rsa_tests[@]}"; do
        IFS=':' read -r key_size key_id hash_type openssl_hash <<< "$test_config"

        key_size_lower="$(echo "$key_size" | tr '[:upper:]' '[:lower:]')"
        local sig_file="${TMP_DIR}/sign_${key_size_lower}.bin"
        local pub_key="${TMP_DIR}/rsa${key_size_lower}_pub.pem"
        
        print_info "Testing RSA-${key_size} operations..."
        
        # Sign operation
        run_test "RSA-${key_size} sign operation" \
            "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
            --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
            --pubKey "${pub_key}" --keyId "${key_id}" \
            --hashType "${hash_type}" --signBuffer
        
        # Verify operation
        run_test "RSA-${key_size} verify operation" \
            "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
            --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
            --pubKey "${pub_key}" --keyId "${key_id}" \
            --hashType "${hash_type}" --verify
        
        # OpenSSL cross-verification
        if command -v openssl &> /dev/null && [ -f "${pub_key}" ] && [ -f "${sig_file}" ]; then
            run_test "RSA-${key_size} OpenSSL cross-verification" \
                openssl dgst "-${openssl_hash}" -verify "${pub_key}" \
                -signature "${sig_file}" "${TEST_DATA_FILE}"
        fi
    done
}

# Test RSA 8K signature operations
test_rsa8k_signatures() {
    print_header "Testing RSA Signature Operations (8K)"
    
    local key_size="8K"
    local key_id="100000005"
    local hash_type="2"
    local openssl_hash="sha512"

    key_size_lower="$(echo "$key_size" | tr '[:upper:]' '[:lower:]')"
    local sig_file="${TMP_DIR}/sign_${key_size_lower}.bin"
    local pub_key="${TMP_DIR}/rsa${key_size_lower}_pub.pem"

    print_info "Testing RSA-${key_size} operations..."
    
    # Sign operation
    run_test "RSA-${key_size} sign operation" \
        "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
        --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
        --pubKey "${pub_key}" --keyId "${key_id}" \
        --hashType "${hash_type}" --signBuffer
    
    # Verify operation
    run_test "RSA-${key_size} verify operation" \
        "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
        --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
        --pubKey "${pub_key}" --keyId "${key_id}" \
        --hashType "${hash_type}" --verify
    
    # OpenSSL cross-verification
    if command -v openssl &> /dev/null && [ -f "${pub_key}" ] && [ -f "${sig_file}" ]; then
        run_test "RSA-${key_size} OpenSSL cross-verification" \
            openssl dgst "-${openssl_hash}" -verify "${pub_key}" \
            -signature "${sig_file}" "${TEST_DATA_FILE}"
    fi
}

# Test Post-Quantum MLDSA signature operations
test_mldsa_signatures() {
    print_header "Testing Post-Quantum MLDSA Signature Operations"
    
    local -a mldsa_tests=(
        "44:200000001"
        "65:200000002"
        "87:200000003"
    )
    
    for test_config in "${mldsa_tests[@]}"; do
        IFS=':' read -r variant key_id <<< "$test_config"
        
        local sig_file="${TMP_DIR}/sign_mldsa${variant}.bin"
        local pub_key="${TMP_DIR}/mldsa${variant}.pem"
        
        print_info "Testing MLDSA-${variant} operations..."
        
        # Sign operation (hashType 0 for MLDSA)
        run_test "MLDSA-${variant} sign operation" \
            "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
            --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
            --pubKey "${pub_key}" --keyId "${key_id}" \
            --hashType 0 --signBuffer
        
        # Verify operation
        run_test "MLDSA-${variant} verify operation" \
            "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
            --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
            --pubKey "${pub_key}" --keyId "${key_id}" \
            --hashType 0 --verify
    done
}
# Test ECC signature operations
test_ecc_signatures() {
    print_header "Testing ECC Signature Operations"
    
    local -a ecc_tests=(
        "256:0x300000001:1:sha256"
        "384:0x300000002:1:sha256"
        "521:0x300000003:2:sha512"
    )
    
    for test_config in "${ecc_tests[@]}"; do
        IFS=':' read -r curve key_id hash_type openssl_hash <<< "$test_config"
        
        local sig_file="${TMP_DIR}/p${curve}.sig"
        local pub_key="${TMP_DIR}/p${curve}_pub.pem"
        
        print_info "Testing P-${curve} operations..."
        
        # Sign operation using signDigest
        run_test "P-${curve} sign operation" \
            "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
            --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
            --pubKey "${pub_key}" --keyId "${key_id}" \
            --hashType "${hash_type}" --signDigest
        
        # Verify operation
        run_test "P-${curve} verify operation" \
            "${TAP_EXECUTABLE}" --config "${CONFIG_FILE}" \
            --infile "${TEST_DATA_FILE}" --sigfile "${sig_file}" \
            --pubKey "${pub_key}" --keyId "${key_id}" \
            --hashType "${hash_type}" --verify
        
        # OpenSSL cross-verification
        if command -v openssl &> /dev/null && [ -f "${pub_key}" ] && [ -f "${sig_file}" ]; then
            run_test "P-${curve} OpenSSL cross-verification" \
                openssl dgst "-${openssl_hash}" -verify "${pub_key}" \
                -signature "${sig_file}" "${TEST_DATA_FILE}"
        fi
    done
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "TrustCore NanoROOT TAP Test Suite"
    
    parse_arguments "$@"
    validate_prerequisites
    setup_environment
    
    # Display selected test suites
    print_info "Test suites to run:"
    [ "$RUN_SEAL" = true ] && print_info "  - Seal/Unseal operations"
    [ "$RUN_RSA" = true ] && print_info "  - RSA signatures (2K, 3K, 4K)"
    [ "$RUN_RSA8K" = true ] && print_info "  - RSA signatures (8K)"
    [ "$RUN_MLDSA" = true ] && print_info "  - MLDSA (Post-Quantum) signatures"
    [ "$RUN_ECC" = true ] && print_info "  - ECC signatures"
    echo ""
    
    # Mark that tests have started
    TESTS_STARTED=true
    
    # Run selected test suites
    [ "$RUN_SEAL" = true ] && test_seal_unseal
    [ "$RUN_RSA" = true ] && test_rsa_signatures
    [ "$RUN_RSA8K" = true ] && test_rsa8k_signatures
    [ "$RUN_MLDSA" = true ] && test_mldsa_signatures
    [ "$RUN_ECC" = true ] && test_ecc_signatures
    
    print_header "Test Execution Complete"
}

# Execute main function
main "$@"
