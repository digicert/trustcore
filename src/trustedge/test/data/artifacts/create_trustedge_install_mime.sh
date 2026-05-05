#!/usr/bin/bash

echo "creating trustedge installer artifact"

if [ -z "${VERSION_STR}" ]; then
    VERSION_STR="4.1.19-1"
fi
echo "VERSION: $VERSION_STR"

echo "copying install_trustedge.sh"
cp ../../../../../projects/trustedge/install_trustedge.sh demo_trustedge_installer/payload/scripts/


echo "copying trustedge installer from dist/"
mkdir demo_trustedge_installer/payload/package/
cp ../../../../../dist/*deb demo_trustedge_installer/payload/package/

./create_artifact_download.sh --package-dir demo_trustedge_installer/ --artifact-id "3f6d8a2b-1e9c-5d7b-c4a3-0b6e5f8c9d2a" --artifact-name "trustedge installer" --artifact-version "$VERSION_STR"
