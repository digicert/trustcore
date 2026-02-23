#!/bin/bash
# This script checks if we're in an OSI (Open Source Initiative) build environment
# by verifying if digicert_example.c exists and is not a symlink.
# Can be sourced by other scripts to set OSI_BUILD variable.

# Get script directory
OSI_SCRIPT_DIR=$( cd $(dirname "${BASH_SOURCE[0]}") ; pwd -P )

# Check if digicert_example.c exists and is not a symlink
CHECK_FILE="$OSI_SCRIPT_DIR/../samples/common/digicert_example.c"

if [ -f "$CHECK_FILE" ] && [ ! -L "$CHECK_FILE" ]; then
    OSI_BUILD=1
else
    OSI_BUILD=0
fi

export OSI_BUILD