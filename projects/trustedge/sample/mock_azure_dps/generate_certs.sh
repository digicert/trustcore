#!/bin/bash
#
# Generate test certificates for Azure DPS Mock Server
#
# This script creates a self-signed CA and server certificate for TLS testing.
# For mTLS (mutual TLS) testing, it also creates a client certificate.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

# Certificate validity (days)
CA_VALIDITY=3650
CERT_VALIDITY=365

# Subject fields
COUNTRY="US"
STATE="Utah"
LOCALITY="Lehi"
ORG="DigiCert Test"
OU="TrustEdge Mock"

echo "=== Azure DPS Mock Server Certificate Generator ==="
echo ""

# Create certs directory
mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

# Generate CA private key and certificate
echo "Generating CA certificate..."
openssl genrsa -out ca.key 4096

openssl req -new -x509 -days ${CA_VALIDITY} -key ca.key -out ca.pem \
  -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG}/OU=${OU}/CN=Mock DPS CA"

# Generate server private key
echo "Generating server certificate..."
openssl genrsa -out server.key 2048

# Create server CSR
openssl req -new -key server.key -out server.csr \
  -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG}/OU=${OU}/CN=localhost"

# Create server certificate extensions file
cat > server_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = global.azure-devices-provisioning.net
DNS.3 = *.azure-devices-provisioning.net
DNS.4 = mock-dps.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days ${CERT_VALIDITY} -extfile server_ext.cnf

# Create combined server certificate (cert + key for some servers)
cat server.crt server.key > server.pem

# Generate client certificate for mTLS testing
echo "Generating client certificate..."
openssl genrsa -out client.key 2048

openssl req -new -key client.key -out client.csr \
  -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG}/OU=${OU}/CN=test-device-001"

# Create client certificate extensions file
cat > client_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.crt -days ${CERT_VALIDITY} -extfile client_ext.cnf

# Create combined client certificate
cat client.crt client.key > client.pem

# Create symbolic links in parent directory for convenience
echo "Creating convenience links..."
cd "${SCRIPT_DIR}"
ln -sf certs/server.pem server.pem
ln -sf certs/server.key server.key
ln -sf certs/ca.pem ca.pem
ln -sf certs/client.pem client.pem
ln -sf certs/client.key client.key

# Cleanup CSRs and temp files
rm -f "${CERTS_DIR}"/*.csr "${CERTS_DIR}"/*_ext.cnf

echo ""
echo "=== Certificates Generated ==="
echo ""
echo "Files created in ${CERTS_DIR}:"
echo "  ca.pem       - CA certificate (trust anchor)"
echo "  ca.key       - CA private key"
echo "  server.pem   - Server certificate + key (for mock server)"
echo "  server.crt   - Server certificate only"
echo "  server.key   - Server private key"
echo "  client.pem   - Client certificate + key (for mTLS testing)"
echo "  client.crt   - Client certificate only"
echo "  client.key   - Client private key"
echo ""
echo "Symbolic links in ${SCRIPT_DIR}:"
echo "  server.pem, server.key, ca.pem, client.pem, client.key"
echo ""
echo "Usage:"
echo "  # Start mock server"
echo "  python3 mock_azure_dps_server.py --cert server.pem --key server.key"
echo ""
echo "  # Start with client certificate verification"
echo "  python3 mock_azure_dps_server.py --cert server.pem --key server.key --ca ca.pem"
echo ""
echo "  # Test with curl"
echo "  curl -k https://localhost:8443/0ne00000000/registrations/test-device/register"
echo ""
echo "  # Test with client cert"
echo "  curl --cacert ca.pem --cert client.pem \\"
echo "       https://localhost:8443/0ne00000000/registrations/test-device/register"
