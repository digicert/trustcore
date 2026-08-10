# IKEv2 EAP-GTC — NanoSec initiates as EAP supplicant, StrongSwan responds
# as EAP authenticator (pubkey + eap-gtc)

TC_NAME="Testcase 157 IKEv2 EAP-GTC / NanoSec(supplicant)->StrongSwan(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"   # StrongSwan is the EAP authenticator / IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! grep -aq -- "--eap_password" "${IKE_BIN}" 2>/dev/null; then
    TC_SKIP_REASON="ike binary was not built with EAP supplicant support (rebuild with -DCM_ENABLE_EAPS=ON)"
fi

if [[ -z "$TC_SKIP_REASON" ]] && ! tc_gen_certs tc_157 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

TC_PASSWORD="mocana"
# NanoSec is the IKE initiator and the EAP supplicant.
TC_INIT_IKE_FLAGS=(
    -s gtc
    --eap_identity root
)

TC_VERIFY_AUTH="sha256"
TC_VERIFY_ENCR="aes"
TC_VERIFY_KEYLEN=16

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    mkdir -p /etc/swanctl/x509 /etc/swanctl/private
    cp "$TC_RESP_CERT" /etc/swanctl/x509/tc_suite_resp.pem
    cp "$TC_RESP_KEY"  /etc/swanctl/private/tc_suite_resp.key

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
            auth   = eap-gtc
            id     = %any
            eap_id = root
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
secrets {
    eap-user1 {
        id     = root
        secret = "mocana"
    }
}
EOF
}

tc_setup_policies() {
    local r="$1" i="$2" rf="$3" inf="$4" sf="$5"
    # EAP supplicant build finds the CA cert by scanning the cwd for ca.der
    openssl x509 -in "$TC_CA_CERT" -outform DER -out "${REPO_DIR}/ca.der"
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs any encr_algs any }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs any encr_algs any sa init }
EOF
}

tc_teardown() {
    tc_cleanup_certs tc_157
    rm -f "${REPO_DIR}/ca.der"
    rm -f /etc/swanctl/x509/tc_suite_resp.pem \
          /etc/swanctl/private/tc_suite_resp.key
}
