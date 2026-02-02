#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MSS_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VERBOSE=0
ENABLE_COVERAGE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -v, --verbose      Enable verbose output
    -c, --coverage     Enable code coverage analysis (text format only)
    -h, --help         Display this help message

Examples:
    $0                          # Run tests only
    $0 --coverage               # Run tests with coverage report
    $0 --verbose --coverage     # Verbose mode with coverage

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -c|--coverage)
            ENABLE_COVERAGE=1
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            ;;
    esac
done

print_info "=========================================="
print_info "NanoROOT SMP Unit Tests"
print_info "=========================================="

# Step 1: Check dependencies
print_info "Checking dependencies..."

# Check for cmocka
if ! pkg-config --exists cmocka; then
    print_error "cmocka library not found!"
    print_error "Install with: sudo apt-get install libcmocka-dev"
    exit 1
fi

# Check for coverage tools if needed
if [ ${ENABLE_COVERAGE} -eq 1 ]; then
    if ! command -v lcov &> /dev/null && ! command -v gcovr &> /dev/null; then
        print_error "No coverage tool found (lcov or gcovr required)!"
        print_error "Install with: sudo apt-get install lcov"
        print_error "         OR: pip3 install gcovr"
        exit 1
    fi
    
    # Prefer gcovr for text output (cleaner format)
    if command -v gcovr &> /dev/null; then
        COVERAGE_TOOL="gcovr"
        print_info "Using gcovr for coverage analysis"
    else
        COVERAGE_TOOL="lcov"
        print_info "Using lcov for coverage analysis"
    fi
fi

# Step 2: Verify library has coverage instrumentation
if [ ${ENABLE_COVERAGE} -eq 1 ]; then
    print_info "Verifying library has coverage instrumentation..."
    
    LIBRARY_BUILD_DIR="${MSS_ROOT}/build/projects/smp_nanoroot"
    
    if [ ! -d "${LIBRARY_BUILD_DIR}" ]; then
        print_error "Library build directory not found: ${LIBRARY_BUILD_DIR}"
        print_error ""
        print_error "Please build the library with coverage enabled first:"
        print_error "  cd ${MSS_ROOT}"
        print_error "  export CM_ENV_CODE_COVERAGE=1"
        print_error "  cmake -S . -B build -DENABLE_NANOROOT=ON"
        print_error "  cmake --build build -j\$(nproc)"
        exit 1
    fi
    
    GCNO_COUNT=$(find "${LIBRARY_BUILD_DIR}" -name "*.gcno" -type f | wc -l)
    
    if [ ${GCNO_COUNT} -eq 0 ]; then
        print_error "No .gcno files found in library build directory!"
        print_error "Library was not built with coverage enabled."
        print_error ""
        print_error "Rebuild the library with coverage:"
        print_error "  cd ${MSS_ROOT}"
        print_error "  rm -rf build"
        print_error "  export CM_ENV_CODE_COVERAGE=1"
        print_error "  cmake -S . -B build -DENABLE_NANOROOT=ON"
        print_error "  cmake --build build -j\$(nproc)"
        exit 1
    fi
    
    print_info "Found ${GCNO_COUNT} .gcno files (coverage instrumentation verified)"
fi

# Step 3: Build unit tests
print_info "Building unit tests..."

cd "${SCRIPT_DIR}"

# Clean previous build
rm -rf build

# Configure CMake
if [ ${VERBOSE} -eq 1 ]; then
    cmake -B build -DENABLE_COVERAGE=${ENABLE_COVERAGE}
else
    cmake -B build -DENABLE_COVERAGE=${ENABLE_COVERAGE} > /dev/null 2>&1
fi

# Build tests
if [ ${VERBOSE} -eq 1 ]; then
    cmake --build build
else
    cmake --build build > /dev/null 2>&1
fi

if [ ! -f "build/smp_nanoroot_unit_test" ]; then
    print_error "Failed to build test executable"
    exit 1
fi

print_info "Build successful"

# Step 4: Run unit tests
print_info "Running unit tests..."
print_info ""

cd build
if [ ${VERBOSE} -eq 1 ]; then
    ./smp_nanoroot_unit_test
else
    ./smp_nanoroot_unit_test 2>&1 | grep -E "^\[|PASSED|FAILED|Error"
fi

TEST_RESULT=${PIPESTATUS[0]}
cd "${SCRIPT_DIR}"

print_info ""
if [ ${TEST_RESULT} -ne 0 ]; then
    print_error "Unit tests FAILED"
    exit ${TEST_RESULT}
fi

print_info "Unit tests PASSED"

# Step 5: Generate coverage report (text only)
if [ ${ENABLE_COVERAGE} -eq 1 ]; then
    print_info ""
    print_info "=========================================="
    print_info "Generating Coverage Report"
    print_info "=========================================="
    
    # Clean old coverage data files from library directory
    find "${LIBRARY_BUILD_DIR}" -name "*.gcda" -type f -delete 2>/dev/null || true
    
    # Run tests again to generate fresh .gcda files
    print_info "Collecting coverage data..."
    cd build && ./smp_nanoroot_unit_test > /dev/null 2>&1
    cd "${SCRIPT_DIR}"
    
    # Verify .gcda files were created
    GCDA_COUNT=$(find "${LIBRARY_BUILD_DIR}" -name "*.gcda" -type f | wc -l)
    
    if [ ${GCDA_COUNT} -eq 0 ]; then
        print_warn "No .gcda files generated!"
        print_warn "Coverage data may not be available."
    else
        print_info "Found ${GCDA_COUNT} .gcda files"
    fi
    
    print_info ""
    print_info "Coverage Report:"
    print_info "=========================================="
    
    if [ "${COVERAGE_TOOL}" = "gcovr" ]; then
        # Use gcovr for clean text output
        gcovr -r "${MSS_ROOT}/src/smp/smp_nanoroot" \
              --object-directory "${LIBRARY_BUILD_DIR}" \
              --exclude '.*/test/.*' \
              --exclude '.*_test\.c' \
              --exclude '.*_unittest\.c' \
              --exclude '.*/cmocka/.*'
    else
        # Use lcov with text output
        COVERAGE_INFO="${SCRIPT_DIR}/coverage.info"
        
        # Detect lcov version
        LCOV_VERSION=$(lcov --version 2>/dev/null | grep -oP 'version \K[0-9]+' | head -1)
        LCOV_IGNORE_ERRORS=""
        if [ "${LCOV_VERSION}" -ge 2 ]; then
            LCOV_IGNORE_ERRORS="--ignore-errors unused,mismatch,empty,negative"
        fi
        
        # Capture coverage
        lcov ${LCOV_IGNORE_ERRORS} \
             --capture \
             --directory "${LIBRARY_BUILD_DIR}" \
             --output-file "${COVERAGE_INFO}" > /dev/null 2>&1
        
        # Filter unwanted files
        lcov ${LCOV_IGNORE_ERRORS} \
             --remove "${COVERAGE_INFO}" \
             '/usr/*' '*/thirdparty/*' '*/cmocka*' '*/test/*' '*_test.c' '*_unittest.c' \
             --output-file "${COVERAGE_INFO}" > /dev/null 2>&1
        
        # Display coverage summary
        lcov --list "${COVERAGE_INFO}"
        
        # Cleanup
        rm -f "${COVERAGE_INFO}"
    fi
    
    print_info "=========================================="
fi

print_info ""
print_info "=========================================="
print_info "All tests completed successfully!"
print_info "=========================================="

exit 0
