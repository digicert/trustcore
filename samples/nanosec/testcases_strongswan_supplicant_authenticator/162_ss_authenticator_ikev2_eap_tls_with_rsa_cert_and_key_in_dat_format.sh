# IKEv2 EAP-TLS using RSA Cert and Key in DAT format — NanoSec initiates as EAP supplicant, StrongSwan responds as EAP authenticator (pubkey + eap-tls)

TC_NAME="Testcase 162 IKEv2 EAP-TLS using RSA Cert and Key in DAT format / NanoSec(supplicant)->StrongSwan(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! grep -aq -- "--eap_password" "${IKE_BIN}" 2>/dev/null; then
    TC_SKIP_REASON="ike binary was not built with EAP supplicant support (rebuild with -DCM_ENABLE_EAPS=ON)"
fi

if [[ -z "$TC_SKIP_REASON" ]] && ! tc_gen_certs tc_162 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# StrongSwan's libtls looks up the peer cert by EAP identity (FQDN "initiator") not by cert subject DN.
# Re-sign the initiator cert with subjectAltName=DNS:initiator so the FQDN identity matches the cert's SAN during chain verification.
if [[ -z "$TC_SKIP_REASON" ]]; then
    _tc162_ca_key="${REPO_DIR}/keystore/keys/tc_162_ca.key"
    openssl x509 -req \
        -in <(openssl req -new -key "$TC_INIT_KEY" -subj "/CN=initiator" 2>/dev/null) \
        -CA "$TC_CA_CERT" -CAkey "$_tc162_ca_key" \
        -CAcreateserial -out "$TC_INIT_CERT" -days 1 -sha256 \
        -extfile <(printf 'subjectAltName=DNS:initiator\n') 2>/dev/null \
        || TC_SKIP_REASON="initiator cert re-sign with SAN failed"
fi

# NanoSec is the IKE initiator and the EAP supplicant.
# -e: EAP-Only authentication (no IKE pubkey auth from NanoSec side)
# -s tls: use EAP-TLS method
# --eap_identity: must match the subject CN of the generated initiator cert
# --eap_server_commonname: must match CN of the generated responder cert (tc_gen_certs uses "responder")
TC_INIT_IKE_FLAGS=(
    -e
    -s tls
    --eap_identity initiator
    --eap_server_commonname responder
)

TC_VERIFY_AUTH="sha256"
TC_VERIFY_ENCR="aes"
TC_VERIFY_KEYLEN=16

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    mkdir -p /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/x509ca
    cp "$TC_RESP_CERT" /etc/swanctl/x509/tc_suite_resp.pem
    cp "$TC_RESP_KEY"  /etc/swanctl/private/tc_suite_resp.key
    # CA cert needed by charon to verify the NanoSec EAP-TLS client certificate
    cp "$TC_CA_CERT"   /etc/swanctl/x509ca/tc_suite_ca.pem
    # EAP-TLS client cert: charon's libtls looks up the peer cert by identity in the
    # credential store; pre-loading it lets the CA-chain verification succeed.
    cp "$TC_INIT_CERT" /etc/swanctl/x509/tc_suite_init.pem

    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 2
        local_addrs  = $r
        remote_addrs = $i
        local {
            auth  = pubkey
            certs = tc_suite_resp.pem
        }
        remote {
            auth   = eap-tls
            id     = %any
            eap_id = initiator
        }
        children {
            child1 {
                mode          = transport
                esp_proposals = aes128-sha256-modp3072
                local_ts      = $r/32
                remote_ts     = $i/32
            }
        }
    }
}
EOF
}

tc_setup_policies() {
    local r="$1" i="$2" rf="$3" inf="$4" sf="$5"
    # EAP-TLS supplicant build looks for these files in the working directory:
    #   ca.der       — CA cert (DER) to verify the StrongSwan IKE/EAP server cert
    #   client.der   — NanoSec's own EAP-TLS client cert (DER)
    #   clientkey.der — NanoSec's own EAP-TLS client private key (DER, not PEM)
    openssl x509 -in "$TC_CA_CERT"   -outform DER -out "${REPO_DIR}/ca.der"
    openssl x509 -in "$TC_INIT_CERT" -outform DER -out "${REPO_DIR}/client.der"
    openssl rsa  -in "$TC_INIT_KEY"  -outform DER -out "${REPO_DIR}/key.dat"
    cp -r "${REPO_DIR}/key.dat" "${REPO_DIR}/clientkey.der"

    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs any encr_algs any }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs any encr_algs any sa init }
EOF
}

tc_teardown() {
    tc_cleanup_certs tc_162
    rm -f "${REPO_DIR}/ca.der" "${REPO_DIR}/client.der" "${REPO_DIR}/clientkey.der" "${REPO_DIR}/key.dat"
    rm -f /etc/swanctl/x509/tc_suite_resp.pem \
          /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_resp.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem
}
