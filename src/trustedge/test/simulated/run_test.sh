#!/bin/bash

set -e

BUILD=false
GDB=false
VALGRIND=false
TEST_DIR=
WORKSPACE_DIR=

# PID for processes to be cleaned up on exit
TRUSTEDGE_PID=
MOSQUITTO_BROKER_PID=
AZURE_DPS_PID=

while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD=true
            ;;
        --test-dir)
            TEST_DIR="$2"
            shift
            ;;
        --gdb)
            GDB=true
            ;;
        --valgrind)
            VALGRIND=true
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

if [ "$BUILD" = true ]; then
    echo "Building TrustEdge..."
    VERBOSE=1 ./scripts/ci/trustedge/ci_trustedge_build.sh --version-string 1.0.0 --monolithic --tpm2 --cvc --proxy --pqc --pqc-composite --enable-pc --package --azure-dps --gdb --unittest
fi

# Validate build
# - Check if ./bin/trustedge_agent_generate_data exists
# - Check if DIGICERT_CUSTOM_getEntropy symbol exists in ./bin/trustedge
if [ ! -f "./bin/trustedge_agent_generate_data" ]; then
    echo "Error: ./bin/trustedge_agent_generate_data not found. Build with --unittest option to generate this binary."
    exit 1
fi

if [ -z "$TEST_DIR" ]; then
    echo "Error: --test-dir option is required."
    exit 1
fi

# Check if any test processes are running, if they are then throw an error and
# exit
check_for_processes() {
    # Check if TrustEdge is running
    if pgrep -x "trustedge" > /dev/null; then
        echo "Error: TrustEdge process is running. Please terminate it before running the test."
        exit 1
    fi

    # Check if mosquitto broker is running
    if pgrep -x "mosquitto" > /dev/null; then
        echo "Error: Mosquitto broker process is running. Please terminate it before running the test."
        exit 1
    fi

    # Check if mosquitto subscriber is running
    if pgrep -x "mosquitto_sub" > /dev/null; then
        echo "Error: Mosquitto subscriber process is running. Please terminate it before running the test."
        exit 1
    fi

    # Check if Azure DPS mock server is running
    if pgrep -f "mock_azure_dps_server.py" > /dev/null; then
        echo "Error: Azure DPS mock server process is running. Please terminate it before running the test."
        exit 1
    fi
}

setup_test_environment() {
    echo "Setting up test environment..."

    # Append _workspace to TEST_DIR and copy it
    WORKSPACE_DIR="${TEST_DIR}_workspace"
    if [ -d "$WORKSPACE_DIR" ]; then
        echo "Removing existing workspace directory: $WORKSPACE_DIR"
        rm -rf "$WORKSPACE_DIR"
    fi
    echo "Copying test directory to workspace: $WORKSPACE_DIR"
    cp -r "$TEST_DIR" "$WORKSPACE_DIR"
    # Replace <path> in trustedge.json with WORKSPACE_DIR
    sed -i "s|<path>|$WORKSPACE_DIR|g" "$WORKSPACE_DIR/trustedge.json"
}

start_test_processes() {
    echo "Starting test processes..."

    # Start mosquitto broker in the background
    echo "Starting Mosquitto broker..."
    nohup ./src/trustedge/test/broker/mosquitto > mosquitto.log 2>&1 &
    MOSQUITTO_BROKER_PID=$!
    sleep 1  # Wait for broker to start
    # Ensure process is running
    if ! ps -p $MOSQUITTO_BROKER_PID > /dev/null; then
        echo "Error: Failed to start Mosquitto broker."
        exit 1
    fi

    # Create messages directory for captured responses
    mkdir -p "${WORKSPACE_DIR}/messages"

    # Start Azure DPS mock server in the background
    echo "Starting Azure DPS mock server..."
    cd ./projects/trustedge/sample/mock_azure_dps
    nohup python3 ./mock_azure_dps_server.py > mock_azure_dps_server.log 2>&1 &
    AZURE_DPS_PID=$!
    sleep 1  # Wait for mock server to start
    # Ensure process is running
    if ! ps -p $AZURE_DPS_PID > /dev/null; then
        echo "Error: Failed to start Azure DPS mock server."
        exit 1
    fi
    cd - > /dev/null  # Return to the previous directory

    # Start TrustEdge in the background
    echo "Starting TrustEdge..."
    if [ "$VALGRIND" = true ]; then
        TRUSTEDGE_CONFIG=$WORKSPACE_DIR/trustedge.json nohup valgrind --leak-check=full --show-leak-kinds=all --num-callers=20 --log-file=trustedge.valgrind ./bin/trustedge agent > trustedge.log 2>&1 &
    else
        TRUSTEDGE_CONFIG=$WORKSPACE_DIR/trustedge.json nohup ./bin/trustedge agent > trustedge.log 2>&1 &
    fi
    TRUSTEDGE_PID=$!
    sleep 1  # Wait for TrustEdge to start
    # Ensure process is running
    if ! ps -p $TRUSTEDGE_PID > /dev/null; then
        echo "Error: Failed to start TrustEdge."
        exit 1
    fi

    # If GDB is enabled, wait for user to attach GDB to TrustEdge process
    if [ "$GDB" = true ]; then
        echo "GDB mode enabled. Please attach GDB to the TrustEdge process (PID: $TRUSTEDGE_PID) and press Enter to continue..."
        read -r
    fi
}

start_test() {
    echo "Starting test..."

    # Iterate through $WORKSPACE_DIR/messages and look for sequential pattern #-req. For
    # each message, construct protobuf message and send it
    #
    # Messages are named in the following format: <sequence_number>-<message_type>.<extension>
    # For example: 1-req.uuid, 1-req.body, 2-req.uuid, 2-req.body, etc.
    #
    # Start looping from 1 and keep going until we don't find a message with the
    # next sequence number
    
    # Read configuration for topics
    account_id=$(jq -r '.configuration.account_id' "$WORKSPACE_DIR/bootstrap_config.json")
    device_id=$(jq -r '.configuration.device_id' "$WORKSPACE_DIR/bootstrap_config.json")
    
    sequence_number=1
    while true; do
        msg_uuid="$WORKSPACE_DIR/messages/${sequence_number}-req.uuid"
        msg_body="$WORKSPACE_DIR/messages/${sequence_number}-req.body"
        if [ ! -f "$msg_uuid" ] || [ ! -f "$msg_body" ]; then
            break
        fi

        echo "Processing message: sequence_number=$sequence_number"

        # If GDB is enabled, wait for user to press enter before sending the message
        if [ "$GDB" = true ]; then
            echo "GDB mode enabled. Press enter to send message $sequence_number..."
            read -r
        fi

        # Start mosquitto subscriber for this specific message
        local sub_log="${WORKSPACE_DIR}/messages/${sequence_number}-resp.log"
        ./src/trustedge/test/broker/mosquitto_sub \
            -h 127.0.0.1 \
            -p 1883 \
            -t "spBv1.0/${account_id}/NDATA/${device_id}" \
            -F '%I|%t|%x' \
            > "$sub_log" 2>&1 &
        local sub_pid=$!
        sleep 0.5  # Give subscriber time to connect

        # Look for "timestamp": "*" in $msg_body and replace it with the current
        # timestamp in following format: "timestamp": "2026-08-04T20:37:46.919Z"
        current_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
        sed -i "s/\"timestamp\": \".*\"/\"timestamp\": \"$current_timestamp\"/" "$msg_body"

        # Read expected response count (required)
        local expected_responses_file="$WORKSPACE_DIR/messages/${sequence_number}-req.responses"
        if [ ! -f "$expected_responses_file" ]; then
            echo "Error: Expected responses file not found: $expected_responses_file"
            exit 1
        fi
        local expected_responses
        expected_responses=$(cat "$expected_responses_file" | tr -d '[:space:]')

        # Construct protobuf message and send it
        ./bin/trustedge_agent_generate_data --msg-uuid-file "$msg_uuid" --msg-body-file "$msg_body" --out-file "${WORKSPACE_DIR}/messages/${sequence_number}-req.protobuf" &> /dev/null
        TRUSTEDGE_CONFIG=$WORKSPACE_DIR/trustedge.json ./bin/trustedge mqtt \
            --mqtt_servername 127.0.0.1 \
            --mqtt_port 1883 \
            --mqtt_client_id test_client \
            --mqtt_pub_topic "spBv1.0/$account_id/NCMD/$device_id" \
            --mqtt_pub_file "${WORKSPACE_DIR}/messages/${sequence_number}-req.protobuf" &> /dev/null
        echo "Sent message number $sequence_number"
        echo "    Topic: spBv1.0/$account_id/NCMD/$device_id"
        echo "    UUID: $(cat "$msg_uuid")"
        echo "    File: ${WORKSPACE_DIR}/messages/${sequence_number}-req.protobuf"

        # Wait for response message(s) from trustedge agent
        echo "Waiting for $expected_responses response(s) from trustedge agent..."
        if [ "$expected_responses" -eq 0 ]; then
            # No responses expected, just wait a bit and continue
            sleep 2
            kill "$sub_pid" 2>/dev/null || true
            wait "$sub_pid" 2>/dev/null || true
            echo "No responses expected for sequence $sequence_number"
        else
            wait_for_response "$sub_log" "$expected_responses"
            # Stop the subscriber
            kill "$sub_pid" 2>/dev/null || true
            wait "$sub_pid" 2>/dev/null || true
            
            # Process captured responses
            local response_count=0
            while IFS='|' read -r timestamp topic hex_payload; do
                response_count=$((response_count + 1))
                local msg_type
                msg_type=$(echo "$topic" | cut -d'/' -f3)
                
                echo "  Response $response_count: $msg_type (topic: $topic)"
                
                # Save response files with sequence number prefix
                echo "$topic" > "${WORKSPACE_DIR}/messages/${sequence_number}-resp-${response_count}.topic"
                echo "$hex_payload" > "${WORKSPACE_DIR}/messages/${sequence_number}-resp-${response_count}.hex"
                
                # Convert hex to binary if payload exists
                if [ -n "$hex_payload" ]; then
                    echo "$hex_payload" | xxd -r -p > "${WORKSPACE_DIR}/messages/${sequence_number}-resp-${response_count}.bin"
                fi
            done < "$sub_log"
            
            if [ "$response_count" -ne "$expected_responses" ]; then
                echo "Error: Expected $expected_responses response(s) but received $response_count for sequence $sequence_number"
                exit 1
            else
                echo "Received $response_count response message(s) for sequence $sequence_number"
            fi
        fi

        sequence_number=$((sequence_number + 1))
    done

    # Wait for trustedge to exit
    echo "Waiting for TrustEdge process to exit..."
    wait "$TRUSTEDGE_PID" 2>/dev/null || true
}

# Wait for expected number of messages to appear in the log file
# Args: log_file, expected_count
wait_for_response() {
    local log_file=$1
    local expected_count=$2
    
    while true; do
        if [ -f "$log_file" ]; then
            local lines_now
            lines_now=$(wc -l < "$log_file")
            if [ "$lines_now" -ge "$expected_count" ]; then
                return 0
            fi
        fi
        sleep 0.5
    done
}

cleanup() {
    echo "Cleaning up test processes..."

    # Kill TrustEdge process if running
    if [ -n "$TRUSTEDGE_PID" ] && ps -p "$TRUSTEDGE_PID" > /dev/null; then
        echo "Killing TrustEdge process (PID: $TRUSTEDGE_PID)"
        kill "$TRUSTEDGE_PID"
    fi

    # Kill Mosquitto broker process if running
    if [ -n "$MOSQUITTO_BROKER_PID" ] && ps -p "$MOSQUITTO_BROKER_PID" > /dev/null; then
        echo "Killing Mosquitto broker process (PID: $MOSQUITTO_BROKER_PID)"
        kill "$MOSQUITTO_BROKER_PID"
    fi

    # Kill any leftover mosquitto_sub processes
    pkill -f "mosquitto_sub.*spBv1.0" 2>/dev/null || true

    # Kill Azure DPS mock server process if running
    if [ -n "$AZURE_DPS_PID" ] && ps -p "$AZURE_DPS_PID" > /dev/null; then
        echo "Killing Azure DPS mock server process (PID: $AZURE_DPS_PID)"
        kill "$AZURE_DPS_PID"
    fi

    echo "Cleanup complete."
}

# This function recursively iterates through $WORKSPACE_DIR looking for files that end in
# .validate and ensures they match the corresponding file without the .validate
# extension. If any of the files do not match, it prints an error message and
# exits with a non-zero status.
#
# The files are diffed using the cmp command, which compares the files byte by
# byte.
validate_results() {
    echo "Validating test results..."

    local validation_failed="false"

    # Find all .validate files in the workspace directory
    while read -r validate_file; do
        # Determine the corresponding file without the .validate extension
        local original_file="${validate_file%.validate}"

        # Check if the original file exists
        if [ ! -f "$original_file" ]; then
            echo "Error: Original file not found for validation: $original_file"
            validation_failed="true"
            continue
        fi

        # Compare the contents of the two files
        if ! cmp -s "$original_file" "$validate_file"; then
            echo "Validation failed for: $original_file"
            echo "    Original file: $original_file"
            echo "    Validate file: $validate_file"
            validation_failed="true"
        else
            echo "Validation passed for: $original_file"
        fi
    done < <(find "$WORKSPACE_DIR" -type f -name "*.validate")

    if [ "$validation_failed" = "true" ]; then
        echo "ERROR: Test validation failed."
        exit 1
    else
        echo "All test validations passed."
    fi
}

trap cleanup EXIT

check_for_processes

setup_test_environment

start_test_processes

start_test

validate_results