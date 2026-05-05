#!/bin/bash

set -e

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
PKG_DIR=
ARTIFACT_ID=
ARTIFACT_NAME=
ARTIFACT_VERSION=
ARTIFACT_DESCRIPTION=
PAYLOAD_FILE=
MANIFEST_FILE=

OUTPUT_STRING=''

function show_usage
{
    echo ""
    echo "./create_artifact_download.sh --package-dir <pathname>"
    echo ""
    echo "   --package-dir <pathname>     Path to the package directory."
    echo "   --artifact-id <id>           Artifact ID."
    echo "   --artifact-name <name>       Artifact Name."
    echo "   --artifact-version <version> Artifact Version."
    echo "   --artifact-description <description> Artifact description."
    echo "   --payload-file <file>        Path to payload file. (default is to create payload.zip from payload directory)"
    echo "   --manifest-file <file>       Path to manifest file. (defualt is manifest.json)"
    echo ""
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        exit 1
    else
        exit 0
    fi
}

while test $# -gt 0
do
    case "$1" in
        --package-dir)
            if [ -z "$2" ]; then
                echo "ERROR: Missing path argument for package directory..."
                exit 1
            fi
            PKG_DIR="$2"
            shift
            ;;
        --artifact-id)
            if [ -z "$2" ]; then
                echo "ERROR: Missing argument for artifact ID..."
                exit 1
            fi
            ARTIFACT_ID="$2"
            shift
            ;;
        --artifact-name)
            if [ -z "$2" ]; then
                echo "ERROR: Missing argument for artifact name..."
                exit 1
            fi
            ARTIFACT_NAME="$2"
            shift
            ;;
        --artifact-version)
            if [ -z "$2" ]; then
                echo "ERROR: Missing argument for artifact version..."
                exit 1
            fi
            ARTIFACT_VERSION="$2"
            shift
            ;;
        --artifact-description)
            if [ -z "$2" ]; then
                echo "ERROR: Missing argument for artifact description..."
                exit 1
            fi
            ARTIFACT_DESCRIPTION="$2"
            shift
            ;;
        --payload-file)
            if [ -z "$2" ]; then
                echo "ERROR: Missing argument for payload file..."
                exit 1
            fi
            PAYLOAD_FILE="$2"
            shift
            ;;
        --manifest-file)
            if [ -z "$2" ]; then
                echo "ERROR: Missing argument for manifest file..."
                exit 1
            fi
            MANIFEST_FILE="$2"
            shift
            ;;
        --help)
            show_usage
            ;;
        *)
            show_usage "ERROR: Invalid argument: $1"
            ;;
    esac
    shift
done

if [[ -z "${PKG_DIR}" ]]; then
    show_usage "ERROR: package directory not provided..."
fi

if [[ ! -d "${PKG_DIR}" ]]; then
    show_usage "ERROR: Package directory does not exist..."
fi

cd $PKG_DIR

if [[ -z "${PAYLOAD_FILE}" ]]; then
    echo "Creating $PKG_DIR/payload.zip..."
    zip -r payload.zip payload
    PAYLOAD_FILE="payload.zip"
else
    PAYLOAD_FILE=$(basename ${PAYLOAD_FILE})
fi

if [[ -z "${MANIFEST_FILE}" ]]; then
    MANIFEST_FILE="manifest.json"
else
    MANIFEST_FILE=$(basename ${MANIFEST_FILE})
fi

echo "Creating $PKG_DIR/artifact.zip..."
rm -rf artifact
mkdir -p artifact
cp $MANIFEST_FILE artifact/
cp $PAYLOAD_FILE artifact/
zip -r artifact.zip artifact
rm -rf artifact

echo "Creating $PKG_DIR/artifact_download.pb..."
echo "{" > artifact.json
echo "    \"artifactId\": \"$ARTIFACT_ID\"," >> artifact.json
echo "    \"artifactName\": \"$ARTIFACT_NAME\"," >> artifact.json
echo "    \"artifactVersion\": \"$ARTIFACT_VERSION\"," >> artifact.json
echo "    \"description\": \"$ARTIFACT_DESCRIPTION\"," >> artifact.json
echo "    \"artifactChunkOffset\": 0," >> artifact.json
echo "    \"artifactChunkSize\": 1" >> artifact.json
echo -n "}" >> artifact.json
$SCRIPT_DIR/create_mime.py artifact.json artifact.zip artifact_download.mime
$SCRIPT_DIR/generate_protobuf_message --msg-uuid DeviceTM_Artifact_Download --msg-body-file artifact_download.mime --out-file artifact_download.pb
