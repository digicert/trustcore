#!/bin/bash

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
REPO_DIR=$( cd ${SCRIPT_DIR}/../../.. ; pwd -P )

function show_usage
{
    echo "options:"
    echo "  --user      <username>" 
    echo "  --pass      <password>" 
    echo "  --ip        <ip address>"
    echo "  --port      <port>"
    echo "  --hostfile  <path/to>"
    echo "  --keydir    <path/to>   (mandatory)"
}

check_log() {
    local file="$1"
    local string="$2"

    if grep -q "${string}" "${file}"; then
        return 0 # found
    else
        return 1 # not found
    fi
}

wait_for_server() {
    local port=${REMOTE_PORT}
    local timeout=20

    for i in $(seq 1 $timeout); do
        if ss -tln 2>/dev/null | grep -q ":$port "; then
            return 0
        fi
        sleep 1
    done

    echo "Server failed to start within $timeout seconds"
    return 1
}

run_openssh_test()
{
    local TEST_NUM=$1
    local TEST_NAME=$2
    local CMAKE_CMD=$3
    local SERVER_BIN=$4
    local SERVER_ARGS=$5
    local BUILD_DIR="build"
    local SERVER_LOG="server.log"
    local CLIENT_LOG="client.log"
    local BUILD_LOG="build.log"
    local PASS=false
    local SEARCH_STRING="Mocana NanoSSH server!!"
    local TOTAL=0

    echo
    echo "=== Running Test $TEST_NUM: $TEST_NAME ==="

    # Fresh build directory
    rm -rf $BUILD_DIR

    # Build with error checking
    if ! eval $CMAKE_CMD > $BUILD_LOG 2>&1; then
        echo "❌ Test $TEST_NUM FAILED - CMake configuration failed"
        RESULTS+=("Test $TEST_NUM: FAILED (cmake config)")
        echo "=== Build Log ==="
        cat $BUILD_LOG
        echo "=================="

        # Cleanup and return early
        rm -f $BUILD_LOG
        rm -rf $BUILD_DIR
        return
    fi

    echo "Building project..."
    if ! cmake --build $BUILD_DIR >> $BUILD_LOG 2>&1; then
        echo "❌ Test $TEST_NUM FAILED - Build failed"
        RESULTS+=("Test $TEST_NUM: FAILED (build)")
        echo "=== Build Log ==="
        cat $BUILD_LOG
        echo "=================="

        # Cleanup and return early
        rm -f $BUILD_LOG
        rm -rf $BUILD_DIR
        return
    fi

    export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:${LD_LIBRARY_PATH:-}

    # Start the server
    echo "Starting server..."
    $SERVER_BIN $SERVER_ARGS > $SERVER_LOG 2>&1 &
    SERVER_PID=$!

    # Wait for server to start
    if ! wait_for_server; then
        echo "❌ Test $TEST_NUM FAILED - Server startup timeout"
        kill $SERVER_PID 2>/dev/null || true
        RESULTS+=("Test $TEST_NUM: FAILED (server timeout)")
        cat $SERVER_LOG
        return
    fi

    # Clear or create output file
    true > "$KNOWN_HOST_FILE"

    # Loop through all .pub files in the directory
    for pubkey in "$KEY_DIR"/*.pub; do
        if [[ -f "$pubkey" ]]; then
            # Extract key type and base64 key
            read -r KEY_TYPE BASE64_KEY _ < "$pubkey"

            # Format: [REMOTE_HOST]:REMOTE_PORT KEY_TYPE BASE64_KEY
            echo "[$REMOTE_HOST]:$REMOTE_PORT $KEY_TYPE $BASE64_KEY" >> "$KNOWN_HOST_FILE"
        fi
    done

    echo "✅ known_hosts file generated: $KNOWN_HOST_FILE"

    echo "Running client tests..."
    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=diffie-hellman-group14-sha256 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=diffie-hellman-group14-sha256 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=diffie-hellman-group16-sha512 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=diffie-hellman-group16-sha512 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=diffie-hellman-group18-sha512 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=diffie-hellman-group18-sha512 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=diffie-hellman-group-exchange-sha256 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=diffie-hellman-group-exchange-sha256 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=ecdh-sha2-nistp256 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=ecdh-sha2-nistp256 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=ecdh-sha2-nistp384 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=ecdh-sha2-nistp384 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=ecdh-sha2-nistp521 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=ecdh-sha2-nistp521 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o KexAlgorithms=curve25519-sha256 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "KexAlgorithms=curve25519-sha256 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o HostKeyAlgorithms=ssh-ed25519 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "HostKeyAlgorithms=ssh-ed25519 failed"
        TOTAL=$((TOTAL + 1))
    fi

    sshpass -p "${REMOTE_PASSWORD}" ssh -vvvv -o UserKnownHostsFile=${KNOWN_HOST_FILE} -o HostKeyAlgorithms=ecdsa-sha2-nistp256 -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "bye\x0d" > "${CLIENT_LOG}" 2>&1
    if ! check_log "${CLIENT_LOG}" "${SEARCH_STRING}"; then
        echo "HostKeyAlgorithms=ecdsa-sha2-nistp256 failed"
        TOTAL=$((TOTAL + 1))
    fi

    echo "test results: $TOTAL failures"
    # Stop the server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true


    if [ $TOTAL -eq 0 ]; then
        PASS=true
    else
        PASS=false
    fi

    if [ "$PASS" = true ]; then
        echo "✅ Test $TEST_NUM PASSED"
        RESULTS+=("Test $TEST_NUM: PASSED")
    else
        echo "❌ Test $TEST_NUM FAILED"
        RESULTS+=("Test $TEST_NUM: FAILED")
        echo "=== Server Log ==="
        cat $SERVER_LOG
        echo
        echo
        echo "=== Client Log ==="
        cat $CLIENT_LOG
        echo "=================="
    fi

    # Clean up
    echo "Cleaning up..."
    rm -f $SERVER_LOG $CLIENT_LOG $BUILD_LOG
    rm -rf $BUILD_DIR
    rm -f sshc_remote.pub sshc_keys.dat id_dsa.pub
}

while test $# -gt 0
do
    case "$1" in
        --user)
            REMOTE_USER="$2"
            shift
            ;;
        --pass)
            REMOTE_PASSWORD="$2"
            shift
            ;;
        --ip)
            REMOTE_HOST="$2"
            shift
            ;;
        --port)
            REMOTE_PORT="$2"
            shift
            ;;
        --hostfile)
            KNOWN_HOST_FILE="$2"
            shift
            ;;
        --keydir)
            KEY_DIR="$2"
            shift
            ;;
        *)
            echo "unsupported argument $1"
            show_usage
            exit 0
            ;;
    esac
    shift
done

: "${REMOTE_USER:=admin}"
: "${REMOTE_HOST:=127.0.0.1}"
: "${REMOTE_PORT:=8188}"
: "${REMOTE_PASSWORD:=secure}"
: "${KNOWN_HOST_FILE:=known_hosts}"
: "${KEY_DIR:=${REPO_DIR}}"

# Validate inputs
if [[ -z "$KEY_DIR" ]]; then
    echo "--keydir not found"
    show_usage
    exit 1
fi

if [[ ! -d "${KEY_DIR}" ]]; then
    echo "argument to --keydir not a valid directory"
    show_usage
    exit 1
fi

echo "user:             ${REMOTE_USER}"
echo "pass:             ${REMOTE_PASSWORD}"
echo "ip:               ${REMOTE_HOST}"
echo "port:             ${REMOTE_PORT}"
echo "hostfile:         ${KNOWN_HOST_FILE}"
echo "key directory:    ${KEY_DIR}"

run_openssh_test 12 "OpenSSH tests" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port ${REMOTE_PORT}"
