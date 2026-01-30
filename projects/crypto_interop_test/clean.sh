#!/usr/bin/env bash

echo "Cleaning up..."

rm -f `find . -name CMakeCache.txt`
rm -f `find . -name Makefile`
rm -f `find . -name cmake_install.cmake`
rm -f `find . -name CTestTestfile.cmake`
rm -f `find . -name DartConfiguration.tcl`

rm -rf `find . -name CMakeFiles`
rm -rf `find . -name Testing`
rm -rf `find . -name boringssl`
rm -rf `find . -name wolfssl`
