# IKEv2 EAP-AKA — NanoSec initiates as EAP supplicant, StrongSwan responds
# as EAP authenticator (pubkey + eap-aka)

TC_NAME="Testcase 159 IKEv2 EAP-AKA / NanoSec(supplicant)->StrongSwan(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! grep -aq -- "--eap_password" "${IKE_BIN}" 2>/dev/null; then
    TC_SKIP_REASON="ike binary was not built with EAP supplicant support (rebuild with -DCM_ENABLE_EAPS=ON)"
fi

if [[ -z "$TC_SKIP_REASON" ]] && \
   [[ ! -f /usr/lib/ipsec/plugins/libstrongswan-eap-aka-file.so ]]; then
    TC_SKIP_REASON="eap-aka-file plugin not installed — rebuild StrongSwan: sudo $0 -I"
fi

if [[ -z "$TC_SKIP_REASON" ]] && ! tc_gen_certs tc_159 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# NanoSec hardcoded AKA vector (from samples/nanosec/src/ike_example.c eapAkaVector):
#   RAND: 00112233445566778899aabbccddeeff
#   AUTN: 112233445566778899aabbccddeeff00
#   CK:   2233445566778899aabbccddeeff0011
#   IK:   33445566778899aabbccddeeff001122
#   RES:  00112233445566778899  (10 bytes)
_TC159_QUINTUPLETS="/etc/ipsec.d/aka_quintuplets.dat"
if [[ -z "$TC_SKIP_REASON" ]]; then
    mkdir -p /etc/ipsec.d
    cat > "$_TC159_QUINTUPLETS" <<'QEOF'
# identity,RAND(32 hex),AUTN(32 hex),XRES(hex),CK(32 hex),IK(32 hex)
user,00112233445566778899aabbccddeeff,112233445566778899aabbccddeeff00,00112233445566778899,2233445566778899aabbccddeeff0011,33445566778899aabbccddeeff001122
QEOF
fi

TC_INIT_IKE_FLAGS=(-s aka --eap_identity user)

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
            auth   = eap-aka
            id     = %any
            eap_id = user
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
    tc_cleanup_certs tc_159
    rm -f "${REPO_DIR}/ca.der" "$_TC159_QUINTUPLETS"
    rm -f /etc/swanctl/x509/tc_suite_resp.pem \
          /etc/swanctl/private/tc_suite_resp.key
}
