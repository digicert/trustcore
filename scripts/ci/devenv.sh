#!/usr/bin/env bash

# This script could be used to set environment variables on developer's system
# prior to using the CI scripts. See README.md for additional information.
#
# WARNING: These variables will be automatically set on Jenkins, so DO NOT execute
# this script on Jenkins as it might mess up build server's environment.

function dev_env_die()
{
    printf "$@"
    exit 255
}

function dev_env_main()
{
    local DEV_ENV_OLD_PWD="$(pwd)"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    export WORKSPACE=$( cd "${SCRIPT_DIR}/../.." ; pwd -P )
    export BUILD_NUMBER='DEV'
    export GIT_COMMIT=$( git rev-parse --short HEAD )

    echo "WORKSPACE=${WORKSPACE}"
    echo "BUILD_NUMBER=${BUILD_NUMBER}"
    echo "GIT_COMMIT=${GIT_COMMIT}"

    cd "${DEV_ENV_OLD_PWD}"
}

# ensure the script is running in main shell process
echo $0 | grep -q devenv && dev_env_die "\nYou must source this script. For example:\n    $ source $0\n\n"

dev_env_main
