#/usr/bin/env bash

# Run this script as ./genpki.sh <certificate_chain_length>
# e.g., ./genpki.sh 5
# will generate 1 Root CA cert, 3 Intermediate CA certs and 1 Server cert
# If no argument is given, it will create 1 Root CA cert and 1 Server cert

DIR=pki_certs
if [ -d "${DIR}" ]; then
   rm -rf ${DIR}
fi

mkdir ${DIR}
pushd ${DIR} &>/dev/null

# Get certificate chain length from CLI (including root and leaf certificates)
num=$1

if [[ -z "$1" ]]; then
    num=2
fi

if [[ ! "${num}" =~ ^[0-9]+$ ]]; then
    echo "Argument is NOT a number"
    exit
fi

echo "Generating certificate chain of length ${num}..."

# Generate root key and certificate
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.pem -subj "/C=IN/ST=NCT/L=Delhi/O=RootCA/CN=Root CA"

# Generate intermediate certificates key and csr (if required)
j=$((num-2))
for i in $(seq 1 $j); do
    openssl genrsa -out int${i}.key 2048
    openssl req -new -key int${i}.key -out int${i}.csr -subj "/C=IN/ST=NCT/L=Delhi/O=Intermediate${i}/CN=Intermediate ${i}"
done

# Sign first intermediate csr with root ca (if required)
if [[ "$num" -ge 3 ]]; then
    openssl x509 -req -in int1.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out int1.pem -days 1825 -sha256 -extfile <(printf "basicConstraints=CA:TRUE\nkeyUsage=critical,keyCertSign")
fi

# Sign all intermediate csrs with to form a chain (if required)
j=$((num-3))
for i in $(seq 1 $j); do
    k=$((i+1))
    openssl x509 -req -in int${k}.csr -CA int${i}.pem -CAkey int${i}.key -CAcreateserial -out int${k}.pem -days 1825 -sha256 -extfile <(printf "basicConstraints=CA:TRUE\nkeyUsage=critical,keyCertSign")
done

# Generate leaf server's key and csr
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=IN/ST=NCT/L=Delhi/O=Localhost/CN=localhost"

# Sign server's csr with root ca or intermediate ca as required
if [[ "$num" -le 2 ]]; then
    openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out server.pem -days 365 -sha256 -extfile <(printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth")
else
    j=$((num-2))
    openssl x509 -req -in server.csr -CA int${j}.pem -CAkey int${j}.key -CAcreateserial -out server.pem -days 365 -sha256 -extfile <(printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth")
fi

# Remove extra generated files
rm -f *.srl *.csr

# Merge server cert and it's intermediate certs into one
if [[ "$num" -ge 3 ]]; then
    j=$((num-2))
    certs_list="server.pem"
    for i in $(seq 1 $j); do
        certs_list+=" int${j}.pem"
	j=$((j-1))
    done

    cat ${certs_list} > server-chain.pem
fi

popd &>/dev/null
echo "Certificate chain generated successfully"
