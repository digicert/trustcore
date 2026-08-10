# IKEv2 EAP-TLS with ECDSA Cert with x9.62 key- Strongswan initiates as EAP supplicant, NanoSec responds
# as EAP authenticator (pubkey + eap-tls)

TC_NAME="Testcase 180 IKEv2 EAP-TLS with ECDSA Cert with x9.62 key / Strongswan(supplicant)->NanoSec(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="init"   # StrongSwan is the EAP authenticator / IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if [[ -z "$TC_SKIP_REASON" ]] && ! tc_gen_certs tc_180 ecdsa ecdsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# StrongSwan's libtls looks up certs by FQDN EAP identity, not by subject DN.
# Re-sign both certs with matching subjectAltName so FQDN lookups succeed:
#   - responder cert: DNS:responder (server cert chain verification by charon)
#   - initiator cert: DNS:initiator (TLS client cert selection by eap-tls plugin)
if [[ -z "$TC_SKIP_REASON" ]]; then
    _tc180_ca_key="${REPO_DIR}/keystore/keys/tc_180_ca.key"
    openssl x509 -req \
        -in <(openssl req -new -key "$TC_RESP_KEY" -subj "/CN=responder" 2>/dev/null) \
        -CA "$TC_CA_CERT" -CAkey "$_tc180_ca_key" \
        -CAcreateserial -out "$TC_RESP_CERT" -days 1 -sha256 \
        -extfile <(printf 'subjectAltName=DNS:responder\n') 2>/dev/null \
        || TC_SKIP_REASON="responder cert re-sign with SAN failed"
fi
if [[ -z "$TC_SKIP_REASON" ]]; then
    _tc180_ca_key="${REPO_DIR}/keystore/keys/tc_180_ca.key"
    openssl x509 -req \
        -in <(openssl req -new -key "$TC_INIT_KEY" -subj "/CN=initiator" 2>/dev/null) \
        -CA "$TC_CA_CERT" -CAkey "$_tc180_ca_key" \
        -CAcreateserial -out "$TC_INIT_CERT" -days 1 -sha256 \
        -extfile <(printf 'subjectAltName=DNS:initiator\n') 2>/dev/null \
        || TC_SKIP_REASON="initiator cert re-sign with SAN failed"
fi

# NanoSec is the responder: give it the responder cert/key and CA cert.
TC_RESP_IKE_FLAGS=(
    -e
    -a tls
)

TC_VERIFY_AUTH="sha256"
TC_VERIFY_ENCR="aes"
TC_VERIFY_KEYLEN=16

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
    cp "$TC_INIT_CERT" /etc/swanctl/x509/tc_suite_init.pem
    cp "$TC_INIT_KEY"  /etc/swanctl/private/tc_suite_init.key
    cp "$TC_CA_CERT"   /etc/swanctl/x509ca/tc_suite_ca.pem
    # Pre-load the responder cert so charon's libtls can verify the server cert chain.
    cp "$TC_RESP_CERT" /etc/swanctl/x509/tc_suite_resp.pem

    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 2
        local_addrs  = $i
        remote_addrs = $r
        local {
            auth = eap-tls
            id = %any
            eap_id = initiator
            certs = tc_suite_init.pem
        }
        remote {
            auth = eap
            id   = "CN=responder"
        }
        proposals = aes128-sha256-modp3072
        children {
            child1 {
                mode          = transport
                esp_proposals = aes128-sha256-modp3072
                local_ts      = $i/32
                remote_ts     = $r/32
            }
        }
    }
}
EOF
}

tc_setup_policies() {
    local r="$1" i="$2" rf="$3"
    openssl x509 -in "$TC_CA_CERT"   -outform DER -out "${REPO_DIR}/ca.der"
    openssl x509 -in "$TC_RESP_CERT" -outform DER -out "${REPO_DIR}/server.der"
    openssl pkey  -in "$TC_RESP_KEY"  -outform DER -out "${REPO_DIR}/serverkey.der"
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs any encr_algs any }
EOF
}

tc_teardown() {
    tc_cleanup_certs tc_180
    rm -f "${REPO_DIR}/server.der" "${REPO_DIR}/serverkey.der" "${REPO_DIR}/ca.der"
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem \
          /etc/swanctl/x509/tc_suite_resp.pem
}