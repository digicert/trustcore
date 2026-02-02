#!/usr/bin/env bash

# Usage: ./build_and_run_all.sh [--mbedtls] [--mbed-path <path>]
# --mbedtls   -  Build w/ mbed tls enabled
# --mbed-path -  Path to mbed install location, can be absolute or relative

function show_usage
{
    echo "Build and run all Crypto Interface unit tests"
    echo "./build_and_run_all.sh [OPTIONS]"
    echo "OPTIONS:"
    echo "--speedtest           - Get execution time for operations."
    echo "--quick               - Reduces the number of tests executed."
    echo "--mbedtls             - Adds test with MbedTLS as the crypto."
    echo "--mbed-path           - Argument for path to MbedTLS. Must be followed by path."
    exit
}



# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null


BUILD_OPTIONS=
USE_MBED=false
MBED_PATH=
INV_OPT=0

while test $# -gt 0
do
    case "$1" in
        --speedtest) echo "Building with speedtests enabled...";
                     BUILD_OPTIONS+=" --speedtest"
            ;;
        --quick) echo "Building with quicktest enabled...";
                     BUILD_OPTIONS+=" --quick"
            ;;
        --mbedtls) USE_MBED=true
            ;;
        --mbed-path) MBED_PATH=$2; shift
            ;;
        --help)
            INV_OPT=1
            ;;
        ?)
            INV_OPT=1
            ;;
        --*) echo "Invalid option: $1"
            ;;
        *) echo "Argument: $1"
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
    show_usage
fi

if [[ "$USE_MBED" == true ]]; then
    if [ -z "$MBED_PATH" ]; then
        echo "No path provided to MbedTLS sources..."
        echo "Exiting build"
        exit 1
    fi
fi

# Build and run w/ CryptoInterface enabled
printf "\n\n\n===== Building & running w/ CryptoInterface enabled... =====\n\n\n\n" &&
./build.sh $@ >/dev/null &&
./run.sh || exit 1

# If the first run was done with mbedtls enabled, do a second passthrough run
if [[ "$USE_MBED" == true ]]; then
  printf "\n\n\n===== Building & running w/ CryptoInterface passthrough... =====\n\n\n\n" &&
  ./build.sh ${BUILD_OPTIONS} >/dev/null &&
  ./run.sh || exit 1
fi

#printf "\n\n\n===== Building & running w/ CryptoInterface disabled... =====\n\n\n\n" &&
#./build.sh --no-ci ${BUILD_OPTIONS} >/dev/null &&
#./run.sh
