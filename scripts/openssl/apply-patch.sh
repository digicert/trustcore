#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Error: Provide OpenSSL patch directory"
    exit 1
fi

foundVersion=false

for version in * ; do
    if [ "$version" = "$1" ]; then
        foundVersion=true
    fi
done

if [ "$foundVersion" = false ]; then
    echo "Error: $1 Invalid version"
    exit 1
fi

# Get all files in patch directory
allFiles=$(find $1 -type f -name '*')

# Move to root directory (some versions of patch do not like leading ..)
cd ../..

for curFile in $allFiles; do
    if [[ "$curFile" == *.patch ]]; then
        origFile=${curFile::-6}
        patch ./thirdparty/$origFile < ./scripts/openssl/$curFile
    fi
done

# Copy version-specific files from src/openssl_wrapper/versions/$1 to thirdparty/openssl-$1
if [ -d "src/openssl_wrapper/versions/$1" ]; then
    cp -r src/openssl_wrapper/versions/$1/* thirdparty/$1/
    echo "Copied version-specific files for $1 to thirdparty/$1"
else
    echo "Warning: No version-specific directory found for $1"
fi