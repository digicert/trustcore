#!/bin/bash

set -e

DEFAULT_ALG="RS256"
DEFAULT_ISS="DeviceTM Service - US"
DEFAULT_EXPIRY_YEARS=1

RSA_KEY_SIZE=2048

usage() {
    echo "Usage: $0 -i <input_file> [-o <output_file>] [-a <algorithm>] [-e <expiry_date>] [-s <issuer>]"
    echo ""
    echo "Options:"
    echo "  -i <input_file>    Input JSON file (required)"
    echo "  -o <output_file>   Output file for the generated JWT (default: same as input with .sig extension)"
    echo "  -a <algorithm>     JWT algorithm (default: RS256)"
    echo "                     Supported: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512"
    echo "  -e <expiry_date>   Expiry date as Unix timestamp or +<years>y format (default: +1y)"
    echo "  -s <issuer>        Issuer string (default: 'DeviceTM Service - US')"
    exit 1
}

base64url_encode() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

calc_cert_thumbprint() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -outform DER | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

get_cert_chain() {
    local cert_file="$1"
    local ica_file="$2"
    local rca_file="$3"

    local leaf_cert=$(openssl x509 -in "$cert_file" -outform DER | openssl base64 -A)
    local ica_cert=$(openssl x509 -in "$ica_file" -outform DER | openssl base64 -A)
    local rca_cert=$(openssl x509 -in "$rca_file" -outform DER | openssl base64 -A)

    echo "[\"$leaf_cert\", \"$ica_cert\", \"$rca_cert\"]"
}

generate_crypto_material() {
    local alg="$1"
    local temp_dir="$2"

    case "$alg" in
        RS256|RS384|RS512|PS256|PS384|PS512)
            openssl genrsa -out "$temp_dir/rca_key.pem" $RSA_KEY_SIZE 2>/dev/null
            openssl genrsa -out "$temp_dir/ica_key.pem" $RSA_KEY_SIZE 2>/dev/null
            openssl genrsa -out "$temp_dir/private_key.pem" $RSA_KEY_SIZE 2>/dev/null
            ;;
        ES256)
            openssl ecparam -genkey -name prime256v1 -out "$temp_dir/rca_key.pem" 2>/dev/null
            openssl ecparam -genkey -name prime256v1 -out "$temp_dir/ica_key.pem" 2>/dev/null
            openssl ecparam -genkey -name prime256v1 -out "$temp_dir/private_key.pem" 2>/dev/null
            ;;
        ES384)
            openssl ecparam -genkey -name secp384r1 -out "$temp_dir/rca_key.pem" 2>/dev/null
            openssl ecparam -genkey -name secp384r1 -out "$temp_dir/ica_key.pem" 2>/dev/null
            openssl ecparam -genkey -name secp384r1 -out "$temp_dir/private_key.pem" 2>/dev/null
            ;;
        ES512)
            openssl ecparam -genkey -name secp521r1 -out "$temp_dir/rca_key.pem" 2>/dev/null
            openssl ecparam -genkey -name secp521r1 -out "$temp_dir/ica_key.pem" 2>/dev/null
            openssl ecparam -genkey -name secp521r1 -out "$temp_dir/private_key.pem" 2>/dev/null
            ;;
        *)
            echo "Error: Unsupported algorithm: $alg" >&2
            exit 1
            ;;
    esac

    openssl req -new -x509 -key "$temp_dir/rca_key.pem" -out "$temp_dir/rca_cert.pem" -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=DeviceTM Service/OU=Root CA/CN=DeviceTM Root CA" 2>/dev/null

    openssl req -new -key "$temp_dir/ica_key.pem" -out "$temp_dir/ica_cert.csr" -days 3650 \
        -subj "/C=US/ST=California/L=San Francisco/O=DeviceTM Service/OU=Root CA/CN=DeviceTM Intermediate CA" 2>/dev/null

    openssl req -new -key "$temp_dir/private_key.pem" -out "$temp_dir/cert.csr" \
        -subj "/C=US/ST=California/L=San Francisco/O=DeviceTM Service/OU=Device Management/CN=DeviceTM Signing Certificate" 2>/dev/null

    openssl x509 -req -in "$temp_dir/ica_cert.csr" -CA "$temp_dir/rca_cert.pem" -CAkey "$temp_dir/rca_key.pem" \
        -CAcreateserial -out "$temp_dir/ica_cert.pem" -days 730 2>/dev/null

    openssl x509 -req -in "$temp_dir/cert.csr" -CA "$temp_dir/ica_cert.pem" -CAkey "$temp_dir/ica_key.pem" \
        -CAcreateserial -out "$temp_dir/cert.pem" -days 730 2>/dev/null
}

sign_jwt() {
    local header_payload="$1"
    local alg="$2"
    local private_key="$3"

    case "$alg" in
        RS256)
            echo -n "$header_payload" | openssl dgst -sha256 -sign "$private_key" | base64url_encode
            ;;
        RS384)
            echo -n "$header_payload" | openssl dgst -sha384 -sign "$private_key" | base64url_encode
            ;;
        RS512)
            echo -n "$header_payload" | openssl dgst -sha512 -sign "$private_key" | base64url_encode
            ;;
        ES256)
            echo -n "$header_payload" | openssl dgst -sha256 -sign "$private_key" | base64url_encode
            ;;
        ES384)
            echo -n "$header_payload" | openssl dgst -sha384 -sign "$private_key" | base64url_encode
            ;;
        ES512)
            echo -n "$header_payload" | openssl dgst -sha512 -sign "$private_key" | base64url_encode
            ;;
        PS256)
            echo -n "$header_payload" | openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign "$private_key" | base64url_encode
            ;;
        PS384)
            echo -n "$header_payload" | openssl dgst -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign "$private_key" | base64url_encode
            ;;
        PS512)
            echo -n "$header_payload" | openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign "$private_key" | base64url_encode
            ;;
        *)
            echo "Error: Unsupported signing algorithm: $alg" >&2
            exit 1
            ;;
    esac
}

while getopts "i:o:a:e:s:h" opt; do
    case $opt in
        i)
            INPUT_FILE="$OPTARG"
            ;;
        o)
            OUTPUT_FILE="$OPTARG"
            ;;
        a)
            ALG="$OPTARG"
            ;;
        e)
            EXPIRY="$OPTARG"
            ;;
        s)
            ISS="$OPTARG"
            ;;
        h)
            usage
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
    esac
done

if [ -z "$INPUT_FILE" ]; then
    echo "Error: Input file is required" >&2
    usage
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist" >&2
    exit 1
fi

ALG="${ALG:-$DEFAULT_ALG}"
ISS="${ISS:-$DEFAULT_ISS}"

if [ -z "$OUTPUT_FILE" ]; then
    if [[ "$INPUT_FILE" == *.json ]]; then
        OUTPUT_FILE="${INPUT_FILE%.json}.sig"
    else
        OUTPUT_FILE="${INPUT_FILE}.sig"
    fi
fi

if [ -z "$EXPIRY" ]; then
    EXPIRY_TIMESTAMP=$(date -d "+${DEFAULT_EXPIRY_YEARS} years" +%s)
elif [[ "$EXPIRY" =~ ^[0-9]+$ ]]; then
    EXPIRY_TIMESTAMP="$EXPIRY"
elif [[ "$EXPIRY" =~ ^[+]([0-9]+)y$ ]]; then
    years="${BASH_REMATCH[1]}"
    EXPIRY_TIMESTAMP=$(date -d "+${years} years" +%s)
else
    echo "Error: Invalid expiry format. Use Unix timestamp or +Ny format (e.g., +2y)" >&2
    exit 1
fi

echo "Generating JWT with the following parameters:"
echo "  Input file: $INPUT_FILE"
echo "  Output file: $OUTPUT_FILE"
echo "  Algorithm: $ALG"
echo "  Issuer: $ISS"
echo "  Expiry: $EXPIRY_TIMESTAMP ($(date -d "@$EXPIRY_TIMESTAMP"))"

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Generating keys and certificates..."
generate_crypto_material "$ALG" "$TEMP_DIR"

echo "Extracting configuration from input file..."
DEVICE_ID=$(jq -r '.configuration.device_id // empty' "$INPUT_FILE")
DEVICE_NAME=$(jq -r '.configuration.device_name // empty' "$INPUT_FILE")
ACCOUNT_ID=$(jq -r '.configuration.account_id // empty' "$INPUT_FILE")
DIVISION_ID=$(jq -r '.configuration.division_id // empty' "$INPUT_FILE")
DEVICE_GROUP_ID=$(jq -r '.configuration.device_group_id // empty' "$INPUT_FILE")

if [ -z "$DEVICE_ID" ] || [ -z "$DEVICE_NAME" ] || [ -z "$ACCOUNT_ID" ] || [ -z "$DIVISION_ID" ] || [ -z "$DEVICE_GROUP_ID" ]; then
    echo "Error: Missing required fields in configuration. Required: device_id, device_name, account_id, division_id, device_group_id" >&2
    exit 1
fi

echo "Extracted configuration:"
echo "  Device ID: $DEVICE_ID"
echo "  Device Name: $DEVICE_NAME"
echo "  Account ID: $ACCOUNT_ID"
echo "  Division ID: $DIVISION_ID"
echo "  Device Group ID: $DEVICE_GROUP_ID"

X5C=$(get_cert_chain "$TEMP_DIR/cert.pem" "$TEMP_DIR/ica_cert.pem" "$TEMP_DIR/rca_cert.pem")
X5T_S256=$(calc_cert_thumbprint "$TEMP_DIR/cert.pem")

HEADER=$(jq -n \
    --arg typ "JWT" \
    --arg use "sig" \
    --arg alg "$ALG" \
    --argjson x5c "$X5C" \
    --arg x5t_s256 "$X5T_S256" \
    '{
        typ: $typ,
        use: $use,
        alg: $alg,
        x5c: $x5c,
        "x5t#S256": $x5t_s256
    }')

PAYLOAD=$(jq -n \
    --arg device_id "$DEVICE_ID" \
    --arg device_name "$DEVICE_NAME" \
    --arg account_id "$ACCOUNT_ID" \
    --arg division_id "$DIVISION_ID" \
    --arg device_group_id "$DEVICE_GROUP_ID" \
    --argjson exp "$EXPIRY_TIMESTAMP" \
    --arg iss "$ISS" \
    '{
        device_id: $device_id,
        device_name: $device_name,
        account_id: $account_id,
        division_id: $division_id,
        device_group_id: $device_group_id,
        exp: $exp,
        iss: $iss
    }')

HEADER_B64=$(echo -n "$HEADER" | base64url_encode)
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64url_encode)

HEADER_PAYLOAD="${HEADER_B64}.${PAYLOAD_B64}"

echo "Signing JWT..."
SIGNATURE=$(sign_jwt "$HEADER_PAYLOAD" "$ALG" "$TEMP_DIR/private_key.pem")

JWT="${HEADER_PAYLOAD}.${SIGNATURE}"

echo "$JWT" > "$OUTPUT_FILE"

echo "JWT successfully generated and saved to: $OUTPUT_FILE"
