#!/bin/bash

echo "Cleaning up..."

# Place us in the dir of this script
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
cd $CURR_DIR

if [ -d "build" ]; then
  rm -rf build
fi

# Delete config file
DEVICE_TYPE_FILE="${CURR_DIR}/sample/tpuc_data/persist/devcreds/tpuc_device_type_info.json"
if [[ -a ${DEVICE_TYPE_FILE} ]]; then
  rm -f ${DEVICE_TYPE_FILE}
fi
