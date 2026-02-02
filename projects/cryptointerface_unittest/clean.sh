#!/usr/bin/env bash

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
MSS_DIR=$(pwd)/../..

echo "Cleaning up..."

if [ -d build/ ]; then
  rm -rf build/
fi

if [ -f main.c ]; then
  rm main.c
fi

# Remove the test binary
if [ -f $MSS_DIR/bin/crypto_interface_test ]; then
  echo "Removing test binary..."
  rm $MSS_DIR/bin/crypto_interface_test
fi
