# IKEv2 EAP-MD5 — Strongswan initiates as EAP supplicant, NanoSec responds
# as EAP authenticator (pubkey + eap-md5)

TC_NAME="Testcase 170 IKEv2 EAP-MD5 / Strongswan(supplicant)->NanoSec(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="init"   # StrongSwan is the EAP authenticator / IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! tc_gen_certs tc_170 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# StrongSwan's libtls looks up the peer cert by EAP identity (FQDN "responder") not by cert subject DN.
# Re-sign the responder cert with subjectAltName=DNS:responder so the FQDN identity matches the cert's SAN during chain verification.
if [[ -z "$TC_SKIP_REASON" ]]; then
    _tc170_ca_key="${REPO_DIR}/keystore/keys/tc_170_ca.key"
    openssl x509 -req \
        -in <(openssl req -new -key "$TC_RESP_KEY" -subj "/CN=responder" 2>/dev/null) \
        -CA "$TC_CA_CERT" -CAkey "$_tc170_ca_key" \
        -CAcreateserial -out "$TC_RESP_CERT" -days 1 -sha256 \
        -extfile <(printf 'subjectAltName=DNS:responder\n') 2>/dev/null \
        || TC_SKIP_REASON="responder cert re-sign with SAN failed"
fi

# NanoSec is the responder: give it the responder cert/key and CA cert.
TC_RESP_IKE_FLAGS=(
    -a md5
    -A user:0x74657374696e67
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
    # EAP-TLS client cert: charon's libtls looks up the peer cert by identity in the
    # credential store; pre-loading it lets the CA-chain verification succeed.
    cp "$TC_RESP_CERT" /etc/swanctl/x509/tc_suite_resp.pem

    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 2
        local_addrs  = $i
        remote_addrs = $r
        local {
            auth    = eap-md5
            id      = %any
            eap_id  = user
        }
        remote {
            auth  = pubkey
            certs = tc_suite_resp.pem
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
secrets {
    eap-user {
        id = user
        secret = testing
    }
}
EOF
}

tc_setup_policies() {
    local r="$1" i="$2" rf="$3"
    openssl x509 -in "$TC_RESP_CERT" -outform DER -out "${REPO_DIR}/server.der"
    openssl rsa  -in "$TC_RESP_KEY"  -outform DER -out "${REPO_DIR}/serverkey.der"
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs any encr_algs any }
EOF
}

tc_teardown() {
    tc_cleanup_certs tc_170
    rm -f "${REPO_DIR}/server.der" "${REPO_DIR}/serverkey.der"
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem \
          /etc/swanctl/x509/tc_suite_resp.pem
}
