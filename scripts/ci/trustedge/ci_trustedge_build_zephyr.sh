#!/usr/bin/env bash

set -e
SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
ROOT_DIR=${SCRIPT_DIR}/../../..
EXAMPLE_DIR=${ROOT_DIR}/src/examples/zephyr_examples
ZEPHYR_DEPS_DIR=${ROOT_DIR}/projects/trustedge/zephyr_deps
MSS_SRC_DIR=${ROOT_DIR}/src

TRUSTEDGE_SAMPLE=1
TRUSTEDGE_ARGS=""
BUILD_TRUSTEDGE_LIB=1
BOARD_TYPE="native_sim/native/64"
BOARD_ARG="native_sim"
BOARD_OVERLAY="./boards/flash_size.overlay"
IMAGE_NAME="trustedge"
BOOTLOADER_SETTING="OFF"
MINIMAL_BUILD=0
CLEAN=0
ZEPHYR_VENV=""
BOARD_CONF_FILE="native_sim_prj.conf"
ZEPHYR_INSTALL_DIR="${HOME}"
ZEPHYR_INSTALL=0
ZEPHYR_MINIMAL=""
BUILD_ESP32_BOOTLOADER=0
MEM_PROFILING=""
CUSTOM_HEAP=""
USE_KMALLOC=0
ETH_SHIELD=""

function show_usage
{
  echo "   --board <board>      - Build for the target board."
  echo "                            options:"
  echo "                                nrf5340dk"
  echo "                                nrf7002dk"
  echo "                                stm32h745i_disco"
  echo "                                nucleo_h745zi_q"
  echo "                                esp32s3_devkitc"
  echo "                                native_sim"
  echo "   --crypto-tests       - Build crypto test sample."
  echo "   --netfs-tests        - Build network and file system test sample."
  echo "   --custom-heap        - Build with custom heap."
  echo "   --trustedge          - Build trustedge test sample (default)."
  echo "   --ota-sample         - Build OTA sample application."
  echo "   --disable-est        - Disable EST (Enrollment over Secure Transport) support."
  echo "   --skip-lib           - skip rebuilding trustedge archive file."
  echo "   --zephyr-install     - Install and setup zephyr developement environment."
  echo "   --mem-prof           - Build with heap memory profiling."
  echo "   --stack-prof         - Build with stack usage profiling."
  echo "   --image-name <name>  - Name of the image to build."
  echo "   --help               - Build options information."
  echo "   --minimal            - Enable minimal code size build."
  echo "   --zephyr-venv <path> - Path to zephyr virtual environment."
  echo "   --clean              - clean mss. (ignored if --skip-lib)."
}

run_setup() {
    if [ -d "${ZEPHYR_INSTALL_DIR}/zephyrproject" ]; then
        echo "Zephyr already installed. Please remove ${ZEPHYR_INSTALL_DIR}/zephyrproject directory and any variables starting with ZEPHYR_* in .bashrc file."
        exit
    fi

    # Updating outdated packages
    sudo apt update
    sudo apt upgrade -y

    # Installing zephyr dependencies
    sudo apt install -y --no-install-recommends build-essential git cmake ninja-build gperf ccache dfu-util device-tree-compiler wget \
            python3-dev python3-pip python3-setuptools python3-tk python3-wheel xz-utils file make gcc libsdl2-dev libmagic1 python3-venv \
            libfuse-dev minicom

    # Install zephyr and python dependencies
    python3 -m venv ${ZEPHYR_INSTALL_DIR}/zephyrproject/.venv
    source ${ZEPHYR_INSTALL_DIR}/zephyrproject/.venv/bin/activate
    pip install west

    west init -m https://github.com/zephyrproject-rtos/zephyr --mr v4.2.0 ${ZEPHYR_INSTALL_DIR}/zephyrproject
    pushd ${ZEPHYR_INSTALL_DIR}/zephyrproject
    west update
    west zephyr-export

    echo "installing python dependencies for zephyr"
    for file in "${ZEPHYR_DEPS_DIR}"/*.txt; do
        if [ -f "${file}" ]; then
            pip install -r "${file}"
        fi
    done

    # Install zephyr sdk
    pushd zephyr
    west sdk install --install-base ${ZEPHYR_INSTALL_DIR}

    echo "export ZEPHYR_BASE=${ZEPHYR_INSTALL_DIR}/zephyrproject/zephyr" >> ${HOME}/.bashrc
    echo "export ZEPHYR_TOOLCHAIN_VARIANT=zephyr" >> ${HOME}/.bashrc
    echo "export ZEPHYR_SDK_INSTALL_DIR=\"${ZEPHYR_INSTALL_DIR}/zephyr-sdk-`cat SDK_VERSION`\"" >> ${HOME}/.bashrc
    echo "export PATH=${ZEPHYR_INSTALL_DIR}/zephyrproject/scripts:$PATH" >> ${HOME}/.bashrc
    echo "alias zephenv='source ${ZEPHYR_INSTALL_DIR}/zephyrproject/.venv/bin/activate'" >> ${HOME}/.bashrc
    echo "Zephyr installed in ${ZEPHYR_INSTALL_DIR}"
    echo "IMPORTANT: Run command \"zephenv\" to use west and other utilitis and run \"deactivate\" when done."
    echo "IMPORTANT: Please restart/logout once for environment variables to take effect."

    popd
    popd
}

get_local_ip() {
    local ip=""

    if command -v ip >/dev/null 2>&1; then
        ip=$(ip route get 8.8.8.8 2>/dev/null | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
    fi

    if [[ -z "$ip" ]] && command -v ifconfig >/dev/null 2>&1; then
        ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    fi

    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    echo "$ip"
}

build_esp32_bootloader() {
    pushd $1
    if [ -f "build_mcuboot/zephyr/zephyr.bin" ]; then
        echo "======================================================================="
        echo "bootloader dir found => ${EXAMPLE_DIR}/trustedge_sample/build_mcuboot"
        echo "======================================================================="
    else
        echo "Building bootloader for esp32s3_devkitc..."
        west build -b $2 -d build_mcuboot ${ZEPHYR_INSTALL_DIR}/zephyrproject/bootloader/mcuboot/boot/zephyr
    fi
    popd
}


# Parse command line arguments
while test $# -gt 0
do
    case "$1" in
        --board)
            BOARD="$2"
            if [ "${BOARD}" == "stm32h745i_disco" ]; then
                BOARD_TYPE="stm32h745i_disco/stm32h745xx/m7"
                BOARD_ARG="${BOARD}"
                TRUSTEDGE_ARGS+=" --x32"
                BOARD_OVERLAY="./boards/stm32h745i_disco_stm32h745xx_m7_full.overlay"
                BOARD_CONF_FILE="stm32_prj.conf"
            elif [ "${BOARD}" == "nrf5340dk" ]; then
                BOARD_TYPE="nrf5340dk/nrf5340/cpuapp"
                BOARD_ARG="${BOARD}"
                BOARD_OVERLAY=""
                ETH_SHIELD="-DSHIELD=seeed_w5500"
                BOARD_OVERLAY="./boards/nrf5340dk_nrf340_cpuapp.overlay"
                TRUSTEDGE_ARGS+=" --x32"
                BOARD_CONF_FILE="nrf5340dk_prj.conf"
            elif [ "${BOARD}" == "nrf7002dk" ]; then
                BOARD_TYPE="nrf7002dk/nrf5340/cpuapp"
                BOARD_ARG="${BOARD}"
                BOARD_OVERLAY=""
                BOARD_OVERLAY="./boards/nrf5340dk_nrf340_cpuapp.overlay"
                TRUSTEDGE_ARGS+=" --x32"
                BOARD_CONF_FILE="stm32_prj.conf"
            elif [ "${BOARD}" == "nucleo_h745zi_q" ]; then
                BOARD_TYPE="nucleo_h745zi_q/stm32h745xx/m7"
                BOARD_ARG="${BOARD}"
                BOARD_OVERLAY="./boards/nucleo_h745zi_q_stm32h745xx_m7.overlay"
                TRUSTEDGE_ARGS+=" --x32"
                BOARD_CONF_FILE="stm32_prj.conf"
            elif [ "${BOARD}" == "native_sim" ]; then
                BOARD_TYPE="native_sim/native/64"
                BOARD_ARG="${BOARD}"
                BOARD_OVERLAY="./boards/flash_size.overlay"
                TRUSTEDGE_ARGS+=" --x64"
                BOARD_CONF_FILE="native_sim_prj.conf"
             elif [ "${BOARD}" == "esp32s3_devkitc" ]; then
                BOARD_TYPE="esp32s3_devkitc/esp32s3/procpu"
                BOARD_ARG="${BOARD}"
                BOARD_OVERLAY="./boards/esp32s3_devkitc.overlay"
                TRUSTEDGE_ARGS+=" --x32"
                BOARD_CONF_FILE="esp32s3_prj.conf"
                BUILD_ESP32_BOOTLOADER=1
                if [ -z "$ZEPHYR_HOST_IP" ]; then
                    echo "========================"
                    echo "Detecting IP address..."
                    export ZEPHYR_HOST_IP=$(get_local_ip)
                    if [[ -n "$ZEPHYR_HOST_IP" ]]; then
                        echo "IP: $ZEPHYR_HOST_IP"
                    else
                        echo "Please export ZEPHYR_HOST_IP env variable to ip address and run the script again"
                        exit 1
                    fi
                    echo "========================"
                fi
            fi
            shift
            ;;
        --gdb)
            TRUSTEDGE_ARGS+=" --gdb"
            ;;
        --skip-lib)
            BUILD_TRUSTEDGE_LIB=0
            ;;
        --crypto-tests)
            TRUSTEDGE_SAMPLE=0
            ;;
        --disable-est)
            TRUSTEDGE_ARGS+=" --disable-est"
            ;;
        --mem-prof)
            TRUSTEDGE_ARGS+=" --mem-prof"
            MEM_PROFILING+=" -DCM_ENABLE_MEM_PROFILE=ON"
            ;;
        --stack-prof)
            MEM_PROFILING+=" -DCM_ENABLE_STACK_PROFILE=ON"
            ;;
        --image-name)
            IMAGE_NAME="$2"
            shift
            if [ -z "${IMAGE_NAME}" ]; then
                echo "Image name cannot be empty."
                exit 1
            fi
            echo "Image name set to: ${IMAGE_NAME}"
            ;;
        --custom-heap)
            CUSTOM_HEAP=" -DCM_ENABLE_CUSTOM_HEAP=ON"
            TRUSTEDGE_ARGS+=" --custom-heap"
            ;;
        --kmalloc)
            TRUSTEDGE_ARGS+=" --kmalloc"
            USE_KMALLOC=1
            ;;
        --trustedge)
            TRUSTEDGE_SAMPLE=1
            ;;
        --netfs-tests)
            TRUSTEDGE_SAMPLE=2
            ;;
        --ota-sample)
            TRUSTEDGE_SAMPLE=3
            ;;
        --zephyr-venv)
            ZEPHYR_VENV="$2"
            shift
            ;;
        --zephyr-install)
            ZEPHYR_INSTALL=1
            ;;
        --minimal)
            MINIMAL_BUILD=1
            ;;
        --mcuboot-path)
            MCUBOOT_PATH="$2"
            shift
            if [ -z "${MCUBOOT_PATH}" ]; then
                echo "bootloader path cannot be empty."
                exit 1
            fi
            ;;
        --clean)
            CLEAN=1
            ;;
        --help)
            show_usage
            exit
            ;;
        *)
            echo "Invalid option provided."
            show_usage
            exit
            ;;
    esac
    shift
done

if [ ${ZEPHYR_INSTALL} -eq 1 ]; then
    run_setup
    exit
fi

if ! type west &> /dev/null; then
    if [ -f "${ZEPHYR_VENV}/bin/activate" ]; then
        source "${ZEPHYR_VENV}/bin/activate"
        if ! type west &> /dev/null; then
            echo "zephyr venv environment not found"
            exit 1
        fi
    else
        echo "west not found"
        exit 1
    fi
fi

if [ ${MINIMAL_BUILD} -eq 1 ]; then
    if [[ "${BOARD}" == "stm32h745i_disco" ]]; then
        BOARD_OVERLAY="./boards/stm32h745i_disco_stm32h745xx_m7.overlay"
        BOOTLOADER_SETTING="ON"
        BOARD_CONF_FILE+=";bootloader.conf"
    elif [[ "${BOARD}" != "native_sim" && "${BOARD}" != "nrf5340dk" ]]; then
        BOARD_CONF_FILE="stm32_prj.conf"
    fi
    TRUSTEDGE_ARGS+=" --minimal --disable-rest-api"
    ZEPHYR_MINIMAL="-DCM_ENABLE_MINIMAL=ON"
fi

if [ "${BOARD}" == "nrf5340dk" ]; then
    BOARD_OVERLAY="./boards/nrf5340dk_nrf340_cpuapp.overlay"
    BOARD_CONF_FILE+=";seeed_w5500.conf"
fi

# use proper heap allocations depending on the build used
if [[ "${BOARD}" != "native_sim" ]]; then
    if [[ ${USE_KMALLOC} -eq 1 ]]; then
        BOARD_CONF_FILE+=";stm32_kmalloc.conf"
    elif [[ -n "${CUSTOM_HEAP}" ]]; then
        BOARD_CONF_FILE+=";stm32_custom_heap.conf"
    else
        BOARD_CONF_FILE+=";stm32_posix.conf"
    fi
fi

echo "board conf files: ${BOARD_CONF_FILE}"

if [ ${BUILD_TRUSTEDGE_LIB} -eq 0 ]; then
    # if we are skipping archive, we do not want to clean.
    CLEAN=0
fi

if [ ${CLEAN} -eq 1 ]; then
    git clean -xfd
fi

if [ ${BUILD_TRUSTEDGE_LIB} -eq 1 ]; then
    pushd "${ROOT_DIR}/projects/trustedge"
    ./clean.sh
    ./build.sh --disable-pqc --persist-artifact --gdb --board "${BOARD_ARG}" ${TRUSTEDGE_ARGS} --debug --generator ZIP
    popd

    cp "${ROOT_DIR}/projects/trustedge/build/lib/libtrustedge.a" bin_static/ || true
fi

if [ ${TRUSTEDGE_SAMPLE} -eq 0 ]; then
    UNITTEST_SAMPLE_DIR=${EXAMPLE_DIR}/crypto_sample

    if [ ${BUILD_ESP32_BOOTLOADER} -eq 1 ]; then
        build_esp32_bootloader $UNITTEST_SAMPLE_DIR $BOARD_TYPE
    fi

    echo "building network sample application"

    if [ "native" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.exe"
        CMAKE_ARGS="-DCONFIG_NET_NO_REBOOT=y"
    elif [ "stm32" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.bin"
        CMAKE_ARGS=""
    elif [ "esp32s3_devkitc" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.signed.bin"
        CMAKE_ARGS=""
    fi

    pushd "${UNITTEST_SAMPLE_DIR}"
    if [ "${BOARD_ARG}" == "esp32s3_devkitc" ]; then
        west build -b ${BOARD_TYPE} -p --build-dir "${UNITTEST_SAMPLE_DIR}/build" -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}"
    else
        west build -b ${BOARD_TYPE} -p --build-dir "${UNITTEST_SAMPLE_DIR}/build" -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}"
    fi
    popd

    echo "build dir => ${UNITTEST_SAMPLE_DIR}/build/"
    if [ -f "${UNITTEST_SAMPLE_DIR}/build/zephyr/${FINAL_BIN_NAME}" ]; then
        cp "${UNITTEST_SAMPLE_DIR}/build/zephyr/${FINAL_BIN_NAME}"  "${ROOT_DIR}/bin/crypto_sample"
        echo "binary location => bin/crypto_sample"
    else
        echo "could not find ${FINAL_BIN_NAME}"
        exit 1
    fi
fi

if [ ${TRUSTEDGE_SAMPLE} -eq 1 ]; then
    TRUSTEDGE_SAMPLE_DIR=${EXAMPLE_DIR}/trustedge_sample

    if [ ${BUILD_ESP32_BOOTLOADER} -eq 1 ]; then
        build_esp32_bootloader $TRUSTEDGE_SAMPLE_DIR $BOARD_TYPE
    fi

    echo "building trustedge sample application"

    # create include directory for shipping application
    rm -rf "${TRUSTEDGE_SAMPLE_DIR}/include"
    mkdir -p ${TRUSTEDGE_SAMPLE_DIR}/include/common/
    mkdir -p ${TRUSTEDGE_SAMPLE_DIR}/include/trustedge/agent/
    mkdir -p ${TRUSTEDGE_SAMPLE_DIR}/include/trustedge/utils/

    cp "${MSS_SRC_DIR}/common/hash_table.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/moptions.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/moptions_custom.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/mdefs.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/mtypes.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/merrors.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/mstdlib.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/mrtos.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/mrtos_custom.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/common/mfmgmt.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    if [ -n "${MEM_PROFILING}" ]; then
        cp "${MSS_SRC_DIR}/common/mtcp.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
        cp "${MSS_SRC_DIR}/common/mtcp_custom.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    fi
    #cp "${MSS_SRC_DIR}/common/common_utils.h" "${TRUSTEDGE_SAMPLE_DIR}/include/common/"
    cp "${MSS_SRC_DIR}/trustedge/trustedge_main.h" "${TRUSTEDGE_SAMPLE_DIR}/include/trustedge/"
    cp "${MSS_SRC_DIR}/trustedge/agent/trustedge_agent_policy_data_types.h" "${TRUSTEDGE_SAMPLE_DIR}/include/trustedge/agent/"

    pushd ${TRUSTEDGE_SAMPLE_DIR}

    if [ "${BOARD_ARG}" == "native_sim" ]; then
        west build -b ${BOARD_TYPE} -p -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DCONF_FILE="${BOARD_CONF_FILE}" -DTRUSTEDGE_IMAGE_NAME="${IMAGE_NAME}" ${MEM_PROFILING} ${CUSTOM_HEAP}
    elif [[ "${BOARD_ARG}" == "nrf7002dk" || "${BOARD_ARG}" == "stm32h745i_disco" ]]; then
        west build -b ${BOARD_TYPE} -p -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}" -DTRUSTEDGE_IMAGE_NAME="${IMAGE_NAME}" -DCM_ENABLE_BOOTLOADER="${BOOTLOADER_SETTING}" ${MEM_PROFILING} ${CUSTOM_HEAP}
    elif [[  "${BOARD_ARG}" == "nrf5340dk" ]]; then
        west build -b ${BOARD_TYPE} -p -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}" -DTRUSTEDGE_IMAGE_NAME="${IMAGE_NAME}" -DCM_ENABLE_BOOTLOADER="${BOOTLOADER_SETTING}" ${MEM_PROFILING} ${CUSTOM_HEAP} ${ETH_SHIELD}
    elif [ "${BOARD_ARG}" == "esp32s3_devkitc" ]; then
        west build -b ${BOARD_TYPE} -p -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}"
    fi
    popd

    if [ "ON" == "${BOOTLOADER_SETTING}" ]; then
        if [ ! -d "${MCUBOOT_PATH}" ]; then
            echo "MCUBOOT_PATH is not a valid path. Please provide the path to the mcuboot directory using --mcuboot-path."
            exit 1
        fi

        echo "combine bootloader and application into one image.."
        pushd "${MCUBOOT_PATH}"
        python scripts/assemble.py -b "${MCUBOOT_PATH}/boot/zephyr/build/" -p ${ROOT_DIR}/src/examples/zephyr_examples/trustedge_sample/build/zephyr/trustedge.signed.bin -o ${ROOT_DIR}/bin/trustedge_with_mcuboot.bin
        popd
    fi

    pushd ${ROOT_DIR}/projects/trustedge
    git clean -xfd # clean up trustege to build packaging
    cmake  -DCMAKE_BUILD_TYPE=Debug -DCM_ENABLE_CVC=ON -DCM_ENABLE_DEBUG=ON -DLIB_TYPE:STRING=STATIC -DCM_ENABLE_ZEPHYR_PACKAGING=ON \
           -DCM_GENERATOR_BUILD=ZIP ${ZEPHYR_MINIMAL} ${X64_BUILD}
    make package
    popd
    rm -f ${ROOT_DIR}/bin_static/libtrustedge.so 2>/dev/null || true

    echo "build dir => src/examples/zephyr_examples/trustedge_sample/build/"

    if [ "native_sim" == "${BOARD_ARG}" ]; then
        if [ -f ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.exe ]; then
            cp ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.exe ${ROOT_DIR}/bin/trustedge
            echo "binary location => bin/trustedge"
        else
            echo "could not find ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.exe"
            exit 1
        fi

        #echo "building provisioning tool"
        #pushd ${EXAMPLE_DIR}/device_provision
        #west build -b  ${BOARD_TYPE} -p -- -DCONFIG_FUSE_FS_ACCESS=y -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}"
        #popd

    elif [ "stm32h745i_disco" == "${BOARD_ARG}" ]; then
        if [ -f ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.bin ]; then
            cp ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.bin ${ROOT_DIR}/bin/trustedge
            echo "binary location => bin/trustedge"
        else
            echo "could not find trustedge.bin"
            exit 1
        fi
    elif [ "esp32s3_devkitc" == "${BOARD_ARG}" ]; then
        if [ -f ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.signed.bin ]; then
            cp ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.signed.bin ${ROOT_DIR}/bin/trustedge
            echo "binary location => bin/trustedge"
        else
            echo "could not find trustedge.signed.bin"
            exit 1
        fi
    elif [ "nrf5340dk" == "${BOARD_ARG}" ]; then
        # nrf uses the hex file, not the bin file to flash
        if [ -f ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.hex ]; then
            cp ${TRUSTEDGE_SAMPLE_DIR}/build/zephyr/trustedge.hex ${ROOT_DIR}/bin/trustedge.hex
            echo "binary location => bin/trustedge.hex"
        else
            echo "could not find trustedge.hex"
            exit 1
        fi
    fi
fi

if [ ${TRUSTEDGE_SAMPLE} -eq 2 ]; then
    UNITTEST_SAMPLE_DIR=${EXAMPLE_DIR}/network_sample

    if [ ${BUILD_ESP32_BOOTLOADER} -eq 1 ]; then
        build_esp32_bootloader $UNITTEST_SAMPLE_DIR $BOARD_TYPE
    fi

    echo "building network sample application"

    if [ "native" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.exe"
        CMAKE_ARGS="-DCONFIG_NET_NO_REBOOT=y"
    elif [ "stm32" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.bin"
        CMAKE_ARGS=""
    elif [ "esp32s3_devkitc" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.signed.bin"
        CMAKE_ARGS=""
    fi

    pushd "${UNITTEST_SAMPLE_DIR}"
    west build -b ${BOARD_TYPE} -p --build-dir "${UNITTEST_SAMPLE_DIR}/build" -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}"
    popd

    echo "build dir => ${UNITTEST_SAMPLE_DIR}/build/"
    if [ -f "${UNITTEST_SAMPLE_DIR}/build/zephyr/${FINAL_BIN_NAME}" ]; then
        cp "${UNITTEST_SAMPLE_DIR}/build/zephyr/${FINAL_BIN_NAME}"  "${ROOT_DIR}/bin/network_sample"
        echo "binary location => bin/network_sample"
    else
        echo "could not find ${FINAL_BIN_NAME}"
        exit 1
    fi
fi

if [ ${TRUSTEDGE_SAMPLE} -eq 3 ]; then
    UNITTEST_SAMPLE_DIR=${EXAMPLE_DIR}/trustedge_dfu_handler_sample

    echo "building OTA sample application"

    if [ "native" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.exe"
        CMAKE_ARGS="-DCONFIG_NET_NO_REBOOT=y"
    elif [ "stm32" == "${BOARD_ARG}" ]; then
        FINAL_BIN_NAME="trustedge.bin"
        CMAKE_ARGS=""
    fi

    pushd "${UNITTEST_SAMPLE_DIR}"
    west build -b ${BOARD_TYPE} -p --build-dir "${UNITTEST_SAMPLE_DIR}/build" -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}" -DIMAGE_NAME="OTA sample"
    popd

    echo "build dir => ${UNITTEST_SAMPLE_DIR}/build/"
    if [ -f "${UNITTEST_SAMPLE_DIR}/build/zephyr/${FINAL_BIN_NAME}" ]; then
        cp "${UNITTEST_SAMPLE_DIR}/build/zephyr/${FINAL_BIN_NAME}"  "${ROOT_DIR}/bin/network_sample"
        echo "binary location => bin/network_sample"
    else
        echo "could not find ${FINAL_BIN_NAME}"
        exit 1
    fi
fi
