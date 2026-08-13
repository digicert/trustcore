EXPECTED_FILE=$(cat <<'EOF'
{
    "failedPolicies": [
        {
            "deviceGroupId": "DEVICE-GROUP-ID-TEST-0",
            "policyType": "CLOUDPLATFORM",
            "policyId": "193850392",
            "priority": 0,
            "policyDependency": [
                {
                    "policyType": "CERTIFICATE",
                    "policyId": "294820113"
                }
            ],
            "policyErrorResponses": 0,
            "creationTimestamp": "2026-08-13T17:00:03.393Z",
            "processTimestamp": "2026-08-13T17:00:03.393Z",
            "errorTimestamp": "2026-08-13T17:00:14.077Z",
            "status": "FAILED",
            "policyState": "CLOUDPLATFORM"
        }
    ]
}

EOF
)

# Get the full path of the current script and remove .validate.sh
# extension to get full path without extension
CURRENT_FILE_NAME=$(realpath "$0")
CURRENT_FILE_NAME=${CURRENT_FILE_NAME%.validate.sh}

# Diff the expected file with the current file, need to ignore the
# timestamp fields since they will always be different
diff <(echo "$EXPECTED_FILE" | jq 'del(.failedPolicies[].creationTimestamp, .failedPolicies[].processTimestamp, .failedPolicies[].errorTimestamp)') <(cat "$CURRENT_FILE_NAME" | jq 'del(.failedPolicies[].creationTimestamp, .failedPolicies[].processTimestamp, .failedPolicies[].errorTimestamp)') > /dev/null
if [ $? -ne 0 ]; then
    echo "Validation failed: The content of $CURRENT_FILE_NAME does not match the expected content."
    exit 1
fi

exit 0