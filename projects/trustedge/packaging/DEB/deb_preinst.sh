#!/bin/bash

set -e

IS_UPGRADE=0

if [ "$1" = "upgrade" ]; then
  IS_UPGRADE=1
fi

EULA_CONTENT="@EULA_FILE_CONTENT@"
EULA=$(cat << EOF
${EULA_CONTENT}
EOF
)

# Display the EULA
display_eula() {
    echo "${EULA}" | less
}


check_eula_already_accepted () {
    if [ -n "$DIGICERT_EULA_ACCEPT" ] && [ "$DIGICERT_EULA_ACCEPT" = "yes" ]; then
        exit 0
    fi

    if [ $IS_UPGRADE -eq 1 ] ; then
        exit 0
    fi
}

read_user_response () {
    # Read user input
    read -rp "Do you accept the terms of the EULA? (yes/no): " response

    # Check user's response
    if [ "$response" != "yes" ]; then
        echo "You declined the EULA. Aborting installation."
        exit 1
    fi
}

check_eula_already_accepted

display_eula

read_user_response

exit 0
