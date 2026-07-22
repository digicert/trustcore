#!/bin/bash

echo "Cleaning up..."

rm -f `find . -name CMakeCache.txt`
rm -f `find . -name Makefile`
rm -f `find . -name cmake_install.cmake`
rm -f `find . -name install_manifest.txt`
rm -f `find . -name CPackConfig.cmake`
rm -f `find . -name CPackSourceConfig.cmake`
rm -f `find . -name iaes*.o`
rm -f so_sign/so_sign
rm -f libmss/libmss.*

rm -rf `find . -name CMakeFiles`
rm -rf `find . -name _CPack_Packages`
