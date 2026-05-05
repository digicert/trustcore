#!/bin/bash

# $1 == 1 : Fresh Install
# $1 >= 2 : Upgrade
# $1 == 0 : Uninstalled

set -e

EULA_FILE="/etc/digicert/conf/eula.txt"

dbg_msg ()
{
    [ "$TE_DEBUG" = "1" ] && echo "DEBUG: $1" || true
}



check_eula_already_accepted ()
{
    if [ "$DIGICERT_EULA_ACCEPT" = "yes" ]; then
        echo "EULA already accepted via environment variable"
        return 0
    fi
}

display_eula ()
{
    if [ "$DIGICERT_EULA_ACCEPT" != "yes" ]; then
        cat << 'EULA_CONTENT_EOF'

===================================
TrustEdge End User License Agreement
===================================

@EULA_CONTENT@

EULA_CONTENT_EOF
    fi
}

read_user_response ()
{
    if [ "$DIGICERT_EULA_ACCEPT" = "yes" ]; then
        return 0
    fi

    echo "Do you accept the terms of the license agreement? (yes/no)"
    read -r response < /dev/tty

    if [ "$response" != "yes" ]; then
        echo "Installation aborted. License agreement not accepted."
        exit 1
    fi

    echo "License agreement accepted. Proceeding with installation..."
}

check_eula_already_accepted

display_eula

read_user_response
exit 0
