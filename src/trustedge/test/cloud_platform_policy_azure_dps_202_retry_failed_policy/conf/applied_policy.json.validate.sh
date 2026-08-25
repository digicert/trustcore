EXPECTED_FILE=$(cat << EOF
{
    "appliedPolicies": [
        {
            "deviceGroupId": "DEVICE-GROUP-ID-TEST-0",
            "policyType": "CERTIFICATE",
            "policyId": "294820113",
            "priority": 0,
            "policyErrorResponses": 0,
            "creationTimestamp": "2026-08-05T22:10:20.224Z",
            "processTimestamp": "2026-08-05T22:10:20.224Z",
            "completionTimestamp": "2026-08-05T22:10:21.468Z",
            "alias": "294820113",
            "status": "SUCCESS"
        },
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
            "creationTimestamp": "2026-08-13T17:46:45.293Z",
            "processTimestamp": "2026-08-13T17:46:45.293Z",
            "completionTimestamp": "2026-08-13T17:46:55.978Z",
            "status": "SUCCESS"
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
diff <(echo "$EXPECTED_FILE" | jq 'del(.appliedPolicies[].creationTimestamp, .appliedPolicies[].processTimestamp, .appliedPolicies[].completionTimestamp)') <(cat "$CURRENT_FILE_NAME" | jq 'del(.appliedPolicies[].creationTimestamp, .appliedPolicies[].processTimestamp, .appliedPolicies[].completionTimestamp)') > /dev/null
if [ $? -ne 0 ]; then
    echo "Validation failed: The content of $CURRENT_FILE_NAME does not match the expected content."
    exit 1
fi

exit 0