#!/usr/bin/env bash

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export NANOSSH_SCRIPTS="${SCRIPT_DIR}/.."
${NANOSSH_SCRIPTS}/build_nanossh_target_nux.sh ssh_server --tap-local --suiteb --export --mbed "$@"
