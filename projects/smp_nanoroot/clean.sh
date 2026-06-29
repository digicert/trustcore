#!/usr/bin/env bash

echo "Cleaning up...$1"

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null

for targetName in $1
do
    rm -rf ../../bin/${targetName}*
done

if [ -d "build" ]; then
    rm -rf build
fi

rm -f ../../bin/libsmpnanoroot.so
