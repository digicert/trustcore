#!/bin/bash

set -e

ZIP_FILE="$1"
EXTRACT_DIR="."
ORIGINAL_DIR="$(pwd)"
NEW_ZIP_FILE="trustedge_2.0.2.arm.zip"
ABS_ZIP_PATH="$(pwd)/$NEW_ZIP_FILE"
CA_CERT_PATH1="etc/digicert/keystore/ca/DigiCertGlobalRootG2.crt"
CERT_URL1="https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"
CA_CERT_PATH2="etc/digicert/keystore/ca/DigiCertEVRSACAG2.crt"
CERT_URL2="https://cacerts.digicert.com/DigiCertEVRSACAG2.crt"
SRC_FILE="../../../../trustedge/test/data/service/est_request.json"
DEST_FILE="etc/digicert/service/est_request.json"

validate_zip() {
    local ZIP_FILE="$1"

    if [ -z "$ZIP_FILE" ]; then
        echo "Error: Please provide path to trustedge zip"
        return 1
    fi

    if [ ! -f "$ZIP_FILE" ]; then
        echo "Error: File '$ZIP_FILE' not found!"
        return 1
    fi

    if [ ! -r "$ZIP_FILE" ]; then
        echo "Error: File '$ZIP_FILE' is not readable!"
        return 1
    fi

    if command -v unzip > /dev/null; then
        if ! unzip -t "$ZIP_FILE" > /dev/null 2>&1; then
            echo "Error: '$ZIP_FILE' is not a valid zip file or is corrupted!"
            return 1
        fi
    else
        echo "Error: unzip not found. Please install unzip."
        exit 1
    fi

    return 0
}


if validate_zip "$ZIP_FILE"; then
    echo "Extracting $ZIP_FILE..."
    unzip -q "$ZIP_FILE" -d "$EXTRACT_DIR"

    if command -v curl > /dev/null; then
        curl -o "$CA_CERT_PATH1" "$CERT_URL1"
        curl -o "$CA_CERT_PATH2" "$CERT_URL2"
    elif command -v wget > /dev/null; then
        wget -O "$CA_CERT_PATH1" "$CERT_URL1"
        wget -O "$CA_CERT_PATH2" "$CERT_URL2"
    else
        echo "Error: Neither curl nor wget found. Please install one of them."
        exit 1
    fi


    echo "Extracted files from $ZIP_FILE"
    echo "Downloaded certificates to: etc/digicert/keystore/ca"

    if cp "$SRC_FILE" "$DEST_FILE"; then
        echo "Copied est_request.json to $DEST_FILE"
    else
	echo "Error: Failed to copy $SRC_FILE to $DEST_FILE"
	rm -rf etc/
        exit 1
    fi

    echo ""
    echo "Creating new zip file: $NEW_ZIP_FILE"

    cd "$EXTRACT_DIR"
    if command -v zip > /dev/null; then
        zip -r "$ABS_ZIP_PATH" etc/
    else
        echo "Error: zip not found. Please install zip."
        rm -rf etc/
        exit 1
    fi

    cd "$ORIGINAL_DIR"

    if [ ! -f "$NEW_ZIP_FILE" ]; then
        echo "Error: Failed to create new zip file!"
        rm -rf etc/
        exit 1
    fi

    rm -rf etc/

    echo ""
    echo "Cleaned up leftovers"
    echo "Created new zip file: $NEW_ZIP_FILE"
else
    exit 1
fi
