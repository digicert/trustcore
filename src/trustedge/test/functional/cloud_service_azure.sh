#!/bin/bash

set -e

GDB=false

# Loop through arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --gdb)
            GDB=true
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

kill_test_processes() {
    echo "Killing test processes..."
    
    echo "Check if TrustEdge is running..."
    if pgrep -x "trustedge" > /dev/null; then
        echo "TrustEdge is running. Attempting to terminate..."
        pkill -f "trustedge" || true
        sleep 5  # Wait for TrustEdge to terminate
        echo "TrustEdge terminated."
    else
        echo "TrustEdge is not running."
    fi

    echo "Check if mosquitto broker is running..."
    if pgrep -x "mosquitto" > /dev/null; then
        echo "Mosquitto broker is running. Attempting to terminate..."
        pkill -f "mosquitto" || true
        sleep 5  # Wait for Mosquitto to terminate
        echo "Mosquitto broker terminated."
    else
        echo "Mosquitto broker is not running." 
    fi
}

start_test_processes() {
    echo "Starting test processes..."

    echo "Starting Mosquitto broker..."
    # Log the output of Mosquitto to a file for debugging purposes
    if [ -f ./src/trustedge/test/broker/mosquitto ]; then
        nohup ./src/trustedge/test/broker/mosquitto > mosquitto.log 2>&1 &
        sleep 2  # Wait for Mosquitto to initialize
    else
        echo "Warning: Mosquitto broker binary not found at ./src/trustedge/test/broker/mosquitto"
    fi

    echo "Starting TrustEdge..."
    # Log the output of TrustEdge to a file for debugging purposes
    if [ -f ./bin/trustedge ]; then
        TRUSTEDGE_CONFIG=./src/trustedge/test/config/trustedge.json nohup ./bin/trustedge agent > trustedge.log 2>&1 &
        sleep 2  # Wait for TrustEdge to initialize
        # If GDB is enabled, wait for user to attach GDB
        if [ "$GDB" = true ]; then
            echo "GDB mode enabled. Please attach GDB to the TrustEdge process (PID: $(pgrep -x "trustedge")) and press Enter to continue..."
            read -r
        fi
    else
        echo "Warning: TrustEdge binary not found at ./bin/trustedge"
    fi

    echo "Test processes started."
}

wait_for_trustedge() {
    echo "Waiting for TrustEdge to exit..."
    local max_retries=1
    local retry_count=0
    local wait_time=6

    while [ $retry_count -lt $max_retries ]; do
        if pgrep -x "trustedge" > /dev/null; then
            echo "TrustEdge is still running. Retrying in $wait_time seconds..."
            sleep $wait_time
            retry_count=$((retry_count + 1))
        else
            echo "TrustEdge has exited."
            return 0
        fi
    done

    echo "Error: TrustEdge did not exit within the expected time."
    exit 1
}

send_message() {
    local message_dir=$1
    local message_number=$2
    echo "Sending message $message_number..."
    # Add any additional logic for sending messages if needed
    # Check if .body file needs timestamp update. Check if it contains the
    # string ""timestamp": "*"". If it does, replace it with the current
    # time in the following format: "2025-03-20T16:37:03.669Z"
    if grep -q '"timestamp": "[^"]*"' "${message_dir}/${message_number}.body"; then
        local current_time
        current_time=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
        sed -i "s/\"timestamp\": \"[^\"]*\"/\"timestamp\": \"${current_time}\"/" "${message_dir}/${message_number}.body"
    fi
    ./bin/trustedge_agent_generate_data \
        --msg-uuid-file ${message_dir}/${message_number}.uuid \
        --msg-body-file ${message_dir}/${message_number}.body \
        --out-file ${message_dir}/${message_number}.protobuf
    TRUSTEDGE_CONFIG=./src/trustedge/test/config/trustedge.json ./bin/trustedge mqtt \
        --mqtt_servername 127.0.0.1 \
        --mqtt_port 1883 \
        --mqtt_client_id test_client \
        --mqtt_pub_topic spBv1.0/ACCOUNT-ID-TEST-0/NCMD/DEVICE-ID-TEST-0 \
        --mqtt_pub_file ${message_dir}/${message_number}.protobuf
    sleep 2
    if [ "$GDB" = true ]; then
        echo "Press Enter to continue..."
        read -r
    fi
}

kill_test_processes

start_test_processes

# Create message to send
send_message projects/trustedge/sample/messages/cloud_service_azure 1

send_message projects/trustedge/sample/messages/cloud_service_azure 2a

# send_message projects/trustedge/sample/messages/cloud_service_azure 3

wait_for_trustedge