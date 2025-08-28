#!/bin/bash
set -u

RESULTS=()

wait_for_server() {
    local port=8818
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

run_test 1 "Password-based authentication - MLDSA" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -username admin -password secure"

run_test 2 "Public Key-Based Authentication - Pure MLDSA" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_AUTH=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -username admin"

run_test 3 "Public Key-Based Authentication - Composite MLDSA" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_AUTH=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -username admin"

run_test 4 "Certificate based authentication - RSA Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca.der" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_client_cert keystore/rsa_cert.der -ssh_client_blob keystore/rsa_key.pem"

run_test 5 "Certificate based authentication - RSA Server Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_server_cert keystore/rsa_cert.der -ssh_server_blob keystore/rsa_key.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_ca_cert keystore/ca.der"

run_test 6 "Certificate based authentication - RSA Server and Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca.der -ssh_server_cert keystore/rsa_cert.der -ssh_server_blob keystore/rsa_key.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_ca_cert keystore/ca.der -ssh_client_cert keystore/rsa_cert.der -ssh_client_blob keystore/rsa_key.pem"

run_test 7 "Certificate based authentication - ECDSA Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DDISABLE_PQC=ON -DDISABLE_EDDSA_25519_SUPPORT=ON -DDISABLE_ECDH_25519_SUPPORT=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca.der" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_client_cert keystore/ecdsa_cert.der -ssh_client_blob keystore/ecdsa_key.pem"

run_test 8 "Certificate based authentication - ECDSA Server and Client Certificate Authentication" \
    "cmake -DWITH_LOGGING=ON -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_PQC=ON -DDISABLE_EDDSA_25519_SUPPORT=ON -DDISABLE_ECDH_25519_SUPPORT=ON -B build -S ." \
    "./samples/bin/ssh_server" "-port 8818 -ssh_ca_cert keystore/ca.der -ssh_server_cert keystore/ecdsa_cert.der -ssh_server_blob keystore/ecdsa_key.pem" \
    "./samples/bin/ssh_client" "-ip 127.0.0.1 -port 8818 -ssh_ca_cert keystore/ca.der -ssh_client_cert keystore/ecdsa_cert.der -ssh_client_blob keystore/ecdsa_key.pem"

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