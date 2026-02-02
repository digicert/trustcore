#!/usr/bin/env bash

echo "Building ASN1 Unit Test project."
. clean.sh

cmake -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt
make clean all
