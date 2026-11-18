#!/bin/bash

################################################################################
# Description: Script creates patch files for the specified OpenSSL version by
#              comparing a clean OpenSSL tree with thirdparty/openssl-<version>.
################################################################################

# Exit on error
set -e

# Set script directory
SCRIPT_DIR=$( cd "$(dirname "$0")" ; pwd -P )
WORKSPACE="$( cd "${SCRIPT_DIR}/../.." ; pwd -P )"
OPENSSL_PATCHED_DIR="${WORKSPACE}/thirdparty"

OPENSSL_PATH=""
OPENSSL_VERSION=""

function show_usage
{
    echo ""
    echo "Usage: $0 [Options]"
    echo ""
    echo "Options:"
    echo "  --openssl <path>    - [Mandatory] Path to original (clean) OpenSSL directory."
    echo "  --version <version> - [Mandatory] OpenSSL version, e.g. 3.5.0. Selects thirdparty/openssl-<version>."
    echo "  --help              - Show this help menu."
    echo ""
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        exit 1
    else
        exit 0
    fi
}

# Process command line options
while test $# -gt 0
do
    case "$1" in
        --openssl)
            if [ -z "$2" ]; then
                show_usage "Missing <path> for --openssl argument"
            fi
            OPENSSL_PATH="$2"
            shift
            ;;
        --version)
            if [ -z "$2" ]; then
                show_usage "Missing <version> for --version argument"
            fi
            OPENSSL_VERSION="$2"
            shift
            ;;
        --help)
            show_usage
            ;;
        *)
            show_usage "Invalid option: $1"
            ;;
    esac
    shift
done

if [ -z "$OPENSSL_PATH" ]; then
    show_usage "Argument --openssl required"
fi

if [ -z "$OPENSSL_VERSION" ]; then
    show_usage "Argument --version required"
fi

if [ ! -d "$OPENSSL_PATH" ]; then
    show_usage "Path $OPENSSL_PATH is not a directory"
fi

# Validate version and resolve the clean source path
if [[ ! "$OPENSSL_VERSION" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    show_usage "Invalid version: $OPENSSL_VERSION. Expected a version like 3.5.0"
fi

OPENSSL_PATH="$( cd "$OPENSSL_PATH" ; pwd -P )"
OPENSSL_VERSION="openssl-$OPENSSL_VERSION"
OPENSSL_PATCHED="$OPENSSL_PATCHED_DIR/$OPENSSL_VERSION"
PATCH_DIR="$SCRIPT_DIR/$OPENSSL_VERSION"

# Check if the patched OpenSSL version exists
if [ ! -d "$OPENSSL_PATCHED" ]; then
    show_usage "Missing patched OpenSSL directory $OPENSSL_PATCHED"
fi

if [ "$OPENSSL_PATH" = "$(cd "$OPENSSL_PATCHED" ; pwd -P)" ]; then
    show_usage "Clean and patched OpenSSL trees must be different"
fi

# Prompt user to ensure they are patching the intended version
read -p "Creating patches for OpenSSL version $OPENSSL_VERSION. Enter y to continue: " -r REPLY
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Generate into a temp dir so existing patches survive until confirmed
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING_DIR"' EXIT

shopt -s globstar dotglob
for PATCH_FILE in "$OPENSSL_PATCHED"/**; do
    [ -f "$PATCH_FILE" ] || continue
    FILE_PATH=${PATCH_FILE#"$OPENSSL_PATCHED"}
    ORIG_PATH="$OPENSSL_PATH$FILE_PATH"
    [ -f "$ORIG_PATH" ] || continue

    result=0
    cmp --silent -- "$PATCH_FILE" "$ORIG_PATH" || result=$?
    if [ "$result" -eq 0 ]; then
        continue
    elif [ "$result" -ne 1 ]; then
        echo "Error: comparison failed for $FILE_PATH" >&2
        exit "$result"
    fi

    echo "Creating patch file for $FILE_PATH"
    mkdir -p "$STAGING_DIR$(dirname "$FILE_PATH")"
    result=0
    diff "$ORIG_PATH" "$PATCH_FILE" > "$STAGING_DIR$FILE_PATH.patch" || result=$?
    if [ "$result" -ne 1 ]; then
        echo "Error: diff failed for $FILE_PATH" >&2
        exit 1
    fi
    if grep -q '^Binary files .* differ$' "$STAGING_DIR$FILE_PATH.patch"; then
        echo "Error: cannot create a text patch for $FILE_PATH" >&2
        exit 1
    fi
done

echo ""

if [ -d "$PATCH_DIR" ] && [ -n "$(find "$PATCH_DIR" -type f -name '*.patch' -print -quit)" ]; then
    read -p "Existing .patch files in $PATCH_DIR will be replaced. Enter y to continue: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Existing patches are unchanged."
        exit 1
    fi
    find "$PATCH_DIR" -type f -name '*.patch' -delete
    find "$PATCH_DIR" -type d -empty -delete
fi

mkdir -p "$PATCH_DIR"
cp -R "$STAGING_DIR"/. "$PATCH_DIR"/

echo "Generated patches in $PATCH_DIR:"
(cd "$STAGING_DIR" && find . -type f -name '*.patch' | sed 's|^\./||' | sort)

echo "Done!"
