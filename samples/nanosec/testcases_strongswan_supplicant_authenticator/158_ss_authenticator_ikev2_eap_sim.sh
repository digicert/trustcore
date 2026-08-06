# IKEv2 EAP-SIM — NanoSec initiates as EAP supplicant, StrongSwan responds
# as EAP authenticator (pubkey + eap-sim)

TC_NAME="Testcase 158 IKEv2 EAP-SIM / NanoSec(supplicant)->StrongSwan(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! grep -aq -- "--eap_password" "${IKE_BIN}" 2>/dev/null; then
    TC_SKIP_REASON="ike binary was not built with EAP supplicant support (rebuild with -DCM_ENABLE_EAPS=ON)"
fi

# eap-sim-file must be compiled into charon. It provides the SIM triplet
# database so StrongSwan can challenge NanoSec with the specific RAND values
# that NanoSec's hardcoded triplet table recognises (from ike_example.c).
if [[ -z "$TC_SKIP_REASON" ]] && \
   ! grep -aq "eap-sim-file" "${CHARON_BIN:-/usr/libexec/ipsec/charon}" 2>/dev/null; then
    TC_SKIP_REASON="eap-sim-file not in charon — rebuild StrongSwan: sudo $0 -I"
fi

if [[ -z "$TC_SKIP_REASON" ]] && ! tc_gen_certs tc_158 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# Write the SIM triplets to the eap-sim-file plugin's default path before charon starts
_TC158_TRIPLETS="/etc/ipsec.d/triplets.dat"
if [[ -z "$TC_SKIP_REASON" ]]; then
    mkdir -p /etc/ipsec.d
    cat > "$_TC158_TRIPLETS" <<'TRIPEOF'
# identity,RAND(32 hex chars),SRES(8 hex chars),Kc(16 hex chars)
user,101112131415161718191a1b1c1d1e1f,d1d2d3d4,a0a1a2a3a4a5a6a7
user,202122232425262728292a2b2c2d2e2f,e1e2e3e4,b0b1b2b3b4b5b6b7
user,303132333435363738393a3b3c3d3e3f,f1f2f3f4,c0c1c2c3c4c5c6c7
TRIPEOF
fi

# NanoSec is the IKE initiator and the EAP supplicant.
TC_INIT_IKE_FLAGS=(
    -s sim
    --eap_identity user
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
            auth   = eap-sim
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
    tc_cleanup_certs tc_158
    rm -f "${REPO_DIR}/ca.der" "$_TC158_TRIPLETS"
    rm -f /etc/swanctl/x509/tc_suite_resp.pem \
          /etc/swanctl/private/tc_suite_resp.key
}
