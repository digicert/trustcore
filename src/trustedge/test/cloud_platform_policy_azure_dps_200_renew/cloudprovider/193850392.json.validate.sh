EXPECTED_FILE=$(cat <<'EOF'
{
    "iothub_url": "mock-iot-hub.azure-devices.net",
    "device_id": "lcl-id-skg-sample-01-clientauth",
    "device_cert": "./src/trustedge/test/cloud_platform_policy_azure_dps_200_renew_workspace/keystore/certs/294820113.pem",
    "device_key": "./src/trustedge/test/cloud_platform_policy_azure_dps_200_renew_workspace/keystore/keys/294820113.pem"
}

EOF
)

# Get the full path of the current script and remove .validate.sh
# extension to get full path without extension
CURRENT_FILE_NAME=$(realpath "$0")
CURRENT_FILE_NAME=${CURRENT_FILE_NAME%.validate.sh}

# Diff the expected file with the current file
diff <(echo "$EXPECTED_FILE") <(cat "$CURRENT_FILE_NAME") > /dev/null
if [ $? -ne 0 ]; then
    echo "Validation failed: The content of $CURRENT_FILE_NAME does not match the expected content."
    exit 1
fi

exit 0