EXPECTED_FILE=$(cat <<'EOF'
{
    "state": "REREGISTERED",
    "timestamp": "2026-08-14T22:21:03.023Z"
}
EOF
)

# Get the full path of the current script and remove .validate.sh
# extension to get full path without extension
CURRENT_FILE_NAME=$(realpath "$0")
CURRENT_FILE_NAME=${CURRENT_FILE_NAME%.validate.sh}

# Diff the expected file with the current file, need to ignore the
# timestamp fields since they will always be different
diff <(echo "$EXPECTED_FILE" | jq 'del(.timestamp)') <(cat "$CURRENT_FILE_NAME" | jq 'del(.timestamp)') > /dev/null
if [ $? -ne 0 ]; then
    echo "Validation failed: The content of $CURRENT_FILE_NAME does not match the expected content."
    exit 1
fi

exit 0