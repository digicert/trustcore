#!/usr/bin/env bash

echo "Cleaning up...$1"

rm -rf build

for targetName in $1
do
    rm -rf ../../bin/${targetName}.a 2>/dev/null
    rm -rf ../../bin/${targetName}.so 2>/dev/null
done
