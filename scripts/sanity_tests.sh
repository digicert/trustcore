#!/bin/bash
set -u

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
REPO_DIR=$( cd ${SCRIPT_DIR}/.. ; pwd -P )
RESULTS=()

wait_for_server() {
    local port=8818
    local timeout=30

    for i in $(seq 1 $timeout); do
        if ss -tln 2>/dev/null | grep -q ":$port "; then
            return 0
        fi
        sleep 1
    done

    echo "Server failed to start within $timeout seconds"
    return 1
}

verify_test_result()
{
    local TEST_NUM=$1
    local CLIENT_LOG=$2
    local SERVER_LOG=$3
    local PASS=false

    case $TEST_NUM in
        1) #Password-based authentication - MLDSA
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q password <<< "$ascii_strings" && \
                    grep -q secure <<< "$ascii_strings" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        2) #Public Key-Based Authentication - Pure MLDSA
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q publickey <<< "$ascii_strings" && \
                    grep -q ssh-mldsa44 <<< "$ascii_strings" && \
                    grep -q SSH_MSG_USERAUTH_PK_OK <<< "$block" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        3) #Public Key-Based Authentication - Composite MLDSA
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q publickey <<< "$ascii_strings" && \
                    grep -q ssh-mldsa44-es256 <<< "$ascii_strings" && \
                    grep -q SSH_MSG_USERAUTH_PK_OK <<< "$block" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        4) #Certificate based authentication - RSA Client Certificate Authentication
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q publickey <<< "$ascii_strings" && \
                    grep -q x509v3-rsa2048-sha256 <<< "$ascii_strings" && \
                    grep -q SSH_MSG_USERAUTH_PK_OK <<< "$block" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        5) #Certificate based authentication - RSA Server Certificate Authentication
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q password <<< "$ascii_strings" && \
                    grep -q secure <<< "$ascii_strings" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;

        6) #Certificate based authentication - RSA Server and Client Certificate Authentication
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q publickey <<< "$ascii_strings" && \
                    grep -q x509v3-rsa2048-sha256 <<< "$ascii_strings" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        7) #Certificate based authentication - ECDSA Client Certificate Authentication
            if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q publickey <<< "$ascii_strings" && \
                    grep -q x509v3-ecdsa-sha2-nistp256 <<< "$ascii_strings" && \
                    grep -q SSH_MSG_USERAUTH_PK_OK <<< "$block" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        8) #Certificate based authentication - ECDSA Server and Client Certificate Authentication
             if grep -q "SSHC_EXAMPLE_doSftpCommands: test finished, status = 0" $CLIENT_LOG && \
               grep -q "SSH_CLIENTEXAMPLE_main: test finished, status = 0" $CLIENT_LOG; then
                block=$(sed -n '/SSH_MSG_USERAUTH_REQUEST(50)/,/SSH2_MSG_USERAUTH_SUCCESS(52)/p' $SERVER_LOG)
                ascii_strings=$(echo "$block" | grep -oP '(?<=[0-9a-f]{8}:\s)([0-9a-f]{2}\s){0,16}' | xxd -r -p | strings)
                if [ -n "$block" ] && [ -n "$ascii_strings" ] && \
                    grep -q admin <<< "$ascii_strings" && \
                    grep -q ssh-connection <<< "$ascii_strings" && \
                    grep -q publickey <<< "$ascii_strings" && \
                    grep -q x509v3-ecdsa-sha2-nistp256 <<< "$ascii_strings" && \
                    ! grep -q SSH_MSG_USERAUTH_FAILURE <<< "$block"; then
                    PASS=true
                else
                    echo "Authentication verification failed - expected credentials not found in server log"
                fi
            fi
            ;;
        *)
            echo "Unknown test number: $TEST_NUM"
            ;;
    esac

    # Return the result
    if [ "$PASS" = true ]; then
        return 0  # Success
    else
        return 1  # Failure
    fi
}

run_test()
{
    local TEST_NUM=$1
    local TEST_NAME=$2
    local CMAKE_CMD=$3
    local SERVER_BIN=$4
    local SERVER_ARGS=$5
    local CLIENT_BIN=$6
    local CLIENT_ARGS=$7
    local BUILD_DIR="build"
    local SERVER_LOG="server.log"
    local CLIENT_LOG="client.log"
    local BUILD_LOG="build.log"
    local PASS=false

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

    export LD_LIBRARY_PATH=lib/:${LD_LIBRARY_PATH:-}

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

    # Test specific setup before running client
    case $TEST_NUM in
        2)
            echo "Copying MLDSA key for public key authentication..."
            cp ssh_mldsa44.key sshc_keys.dat
            ;;
        3)
            echo "Copying MLDSA composite key for public key authentication..."
            cp ssh_mldsa44_p256.key sshc_keys.dat
            ;;
        *)
            ;;
    esac

    # Run the client
    echo "Running client..."
    $CLIENT_BIN $CLIENT_ARGS > $CLIENT_LOG 2>&1
    CLIENT_EXIT_CODE=$?

    # Stop the server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true

    # Verification
    if verify_test_result $TEST_NUM $CLIENT_LOG $SERVER_LOG; then
        PASS=true
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

check_log() {
    local file="$1"
    local string="$2"

    if grep -q "${string}" "${file}"; then
        return 0 # found
    else
        return 1 # not found
    fi
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
    local REMOTE_USER="admin"
    local REMOTE_HOST=127.0.0.1
    local REMOTE_PORT=8818
    local REMOTE_PASSWORD="secure"
    local KNOWN_HOST_FILE="known_hosts"
    local KEY_DIR="${REPO_DIR}"

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

    export LD_LIBRARY_PATH=lib/:${LD_LIBRARY_PATH:-}

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
    echo "generate known_hosts file"
    for pubkey in "$KEY_DIR"/*.pub; do
        echo "public key: $pubkey"
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
    fi

    # Clean up
    echo "Cleaning up..."
    rm -f $SERVER_LOG $CLIENT_LOG $BUILD_LOG
    rm -rf $BUILD_DIR
    rm -f sshc_remote.pub sshc_keys.dat id_dsa.pub
}

run_test 1 "Password-based authentication - MLDSA" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -username admin -password secure"

run_test 2 "Public Key-Based Authentication - Pure MLDSA" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_AUTH=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -username admin"

run_test 3 "Public Key-Based Authentication - Composite MLDSA" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_AUTH=ON -DENABLE_PQC_COMPOSITE=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -username admin"

run_test 4 "Certificate based authentication - RSA Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -DCM_ENABLE_SSL=OFF -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca/rsa_ca.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_client_cert keystore/certs/rsa_cert.pem -ssh_client_blob keystore/keys/rsa_key.pem"

run_test 5 "Certificate based authentication - RSA Server Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_server_cert keystore/certs/rsa_cert.pem -ssh_server_blob keystore/keys/rsa_key.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_ca_cert keystore/ca/rsa_ca.pem"

run_test 6 "Certificate based authentication - RSA Server and Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca/rsa_ca.pem -ssh_server_cert keystore/certs/rsa_cert.pem -ssh_server_blob keystore/keys/rsa_key.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_ca_cert keystore/ca/rsa_ca.pem -ssh_client_cert keystore/certs/rsa_cert.pem -ssh_client_blob keystore/keys/rsa_key.pem"

run_test 7 "Certificate based authentication - ECDSA Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DDISABLE_PQC=ON -DDISABLE_EDDSA_25519_SUPPORT=ON -DDISABLE_ECDH_25519_SUPPORT=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca/ca.der" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_client_cert keystore/certs/ecdsa_cert.der -ssh_client_blob keystore/keys/ecdsa_key.pem"

run_test 8 "Certificate based authentication - ECDSA Server and Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_PQC=ON -DDISABLE_EDDSA_25519_SUPPORT=ON -DDISABLE_ECDH_25519_SUPPORT=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca/ca.der -ssh_server_cert keystore/certs/ecdsa_cert.der -ssh_server_blob keystore/keys/ecdsa_key.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_ca_cert keystore/ca/ca.der -ssh_client_cert keystore/certs/ecdsa_cert.der -ssh_client_blob keystore/keys/ecdsa_key.pem"

run_openssh_test 9 "OpenSSH tests" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_SERVER=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818"

# ====================
# Final Results
# ====================
echo
echo "=== Sanity Test Results ==="
for result in "${RESULTS[@]}"; do
    echo "$result"
done
echo "============================"

if printf '%s\n' "${RESULTS[@]}" | grep -q "FAILED"; then
    echo "Some tests failed. Please check the logs."
    exit 1
else
    echo "All tests passed successfully."
    exit 0
fi
