#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Error: Provide an OpenSSL version (for example 3.5.0 or 3.5.7)"
    exit 1
fi

version=${1#openssl-}

if [[ ! "$version" =~ ^[0-9]+(\.[0-9]+)*[a-z]?$ ]]; then
    echo "Error: Invalid OpenSSL version: $1"
    exit 1
fi

patchVersion="openssl-$version"
targetVersion="$patchVersion"
overlayVersion="$patchVersion"

case "$version" in
    3.5.0)
        overlayVersion="openssl-3.5"
        ;;
    3.5.7)
        overlayVersion="openssl-3.5"
        ;;
esac

scriptDir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repoRoot=$(cd "$scriptDir/../.." && pwd)
patchDir="$scriptDir/$patchVersion"
targetDir="$repoRoot/thirdparty/$targetVersion"
overlayDir="$repoRoot/src/openssl_wrapper/versions/$overlayVersion"

if [ ! -d "$patchDir" ]; then
    echo "Error: No patch set found for OpenSSL $version ($patchDir)"
    exit 1
fi

if [ ! -d "$targetDir" ]; then
    echo "Error: OpenSSL source directory not found: $targetDir"
    exit 1
fi

while IFS= read -r -d '' patchFile; do
    relativeFile=${patchFile#"$patchDir"/}
    targetFile="$targetDir/${relativeFile%.patch}"
    if [ ! -f "$targetFile" ]; then
        echo "Error: Patch target not found: $targetFile"
        exit 1
    fi
    if ! patch --batch --forward "$targetFile" < "$patchFile"; then
        echo "Error: Failed to apply $patchFile"
        exit 1
    fi
done < <(find "$patchDir" -type f -name '*.patch' -print0)

if [ -d "$overlayDir" ]; then
    if ! cp -r "$overlayDir/." "$targetDir/"; then
        echo "Error: Failed to copy version-specific files from $overlayVersion"
        exit 1
    fi
    echo "Copied version-specific files from $overlayVersion to $targetVersion"
else
    echo "Warning: No version-specific directory found for $overlayVersion"
fi