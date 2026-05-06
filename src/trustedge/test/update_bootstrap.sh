#!/bin/bash

function error_msg()
{
    local msg="$1"
    echo "ERROR: ${msg}"
    exit 1
}

IP_ADDR=""
BOOTSTRAP_ZIP=""
PORT_NUM=

BOOTSTRAP_FILE="tmp/sample_bootstrap_configuration.json"

while test $# -gt 0
do
     case "$1" in
        --ip)
            if [ -z "$2" ]; then
                error_msg "IP address of MQTT broker is missing.."
            fi

            IP_ADDR="$2"

            shift
            ;;
        --port)
            if [ -z "$2" ]; then
                error_msg "Port number of MQTT broker is missing.."
            fi
            PORT_NUM="$2"
            RE='^[0-9]+$'

            if ! [[ $PORT_NUM =~ $RE ]]; then
                error_msg "$2 is not a number"
            fi

            shift
            ;;
        --bootstrap-zip)
            if [ -z "$2" ]; then
                error_msg "Missing bootstrap ZIP.."
            fi

            if [ ! -f "$2" ]; then
              error_msg "$2 is not a valid file.."
            fi

            BOOTSTRAP_ZIP="$2"

            shift
            ;;
        --help)
            echo "no help menu"
            exit 0
            ;;
        *)
            echo "$1 is invalid argument"
            exit 1
            ;;
    esac
    shift
done

rm -rf tmp > /dev/null 2>&1 || true
mkdir tmp

unzip test_bootstrap.zip -d tmp

sed -i.bak "s/\(mqtt:\/\/\)[0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}/\1${IP_ADDR}/" "$BOOTSTRAP_FILE"

pushd tmp || exit 1

zip -r bootstrap.zip ca/ device_sunny03.cert.crt device_sunny03.cert-key.crt sample_bootstrap_configuration.json
mv bootstrap.zip ..

popd || exit 1

exit 0
