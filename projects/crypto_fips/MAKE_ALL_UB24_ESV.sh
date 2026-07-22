#! /usr/bin/env bash
###


# Set parameters that depend on size
if [ "$1" = "32bit" ]; then
   echo "Building 32 bits ..."
   MY_TGTBITS=32
   MY_TGTNAME=x86_32
   MY_LIBPATH=/lib32/
   MY_PERSISTPATH=/tmp/mss32p.bin
else
   echo "Building 64 bits ..."
   MY_TGTBITS=64
   MY_TGTNAME=x86_64
   MY_LIBPATH=/usr/local/lib/
   MY_PERSISTPATH=/tmp/mss64p.bin
fi

CURDIR=$(pwd)

# Run the CMake based full build
./build.sh --x${MY_TGTBITS} --lib-path ${MY_LIBPATH} --fips-persist ${MY_PERSISTPATH} --enable-jent-lkm 

# Create distribution tree
mkdir -p ${MY_TGTNAME}/host

# 'so_sign' tool for host
cp build/so_sign/so_sign ${MY_TGTNAME}/host/

# Shared libraries
cp build/libmss/libmss.so ${MY_TGTNAME}/
cp build/libmss/libmss.so.sig ${MY_TGTNAME}/

#######
## DISABLED THE LINES BELOW, Don't install yet...
## sudo cp -a x86_32/libmss* /lib32/
## OR 
## sudo cp -a x86_64/libmss* /usr/local/lib/
## sudo ldconfig 
#######
