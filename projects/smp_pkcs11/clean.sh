#!/usr/bin/env bash

echo "Cleaning up...$1"

rm -rf build

for targetName in $1
do
    rm -rf ../../bin/${targetName}*
done
