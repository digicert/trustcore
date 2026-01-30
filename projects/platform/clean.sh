#!/usr/bin/env bash

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null

echo "Cleaning up..."
rm -rf build
