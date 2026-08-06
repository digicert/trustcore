# IKEv2 EAP-AKA — Strongswan initiates as EAP supplicant, NanoSec responds
# as EAP authenticator (pubkey + eap-aka)

TC_NAME="Testcase 173 IKEv2 EAP-AKA / Strongswan(supplicant)->NanoSec(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="init"   # StrongSwan is the EAP authenticator / IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if [[ -z "$TC_SKIP_REASON" ]] && \
   [[ ! -f /usr/lib/ipsec/plugins/libstrongswan-eap-aka-file.so ]]; then
    TC_SKIP_REASON="eap-aka-file plugin not installed — rebuild StrongSwan: sudo $0 -I"
fi

if ! tc_gen_certs tc_173 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# StrongSwan's libtls looks up the peer cert by EAP identity (FQDN "responder") not by cert subject DN.
# Re-sign the responder cert with subjectAltName=DNS:responder so the FQDN identity matches the cert's SAN during chain verification.
if [[ -z "$TC_SKIP_REASON" ]]; then
    _tc173_ca_key="${REPO_DIR}/keystore/keys/tc_173_ca.key"
    openssl x509 -req \
        -in <(openssl req -new -key "$TC_RESP_KEY" -subj "/CN=responder" 2>/dev/null) \
        -CA "$TC_CA_CERT" -CAkey "$_tc173_ca_key" \
        -CAcreateserial -out "$TC_RESP_CERT" -days 1 -sha256 \
        -extfile <(printf 'subjectAltName=DNS:responder\n') 2>/dev/null \
        || TC_SKIP_REASON="responder cert re-sign with SAN failed"
fi


# NanoSec hardcoded AKA vector (from samples/nanosec/src/ike_example.c eapAkaVector):
#   RAND: 00112233445566778899aabbccddeeff
#   AUTN: 112233445566778899aabbccddeeff00
#   CK:   2233445566778899aabbccddeeff0011
#   IK:   33445566778899aabbccddeeff001122
#   RES:  00112233445566778899  (10 bytes)
_TC173_QUINTUPLETS="/etc/ipsec.d/aka_quintuplets.dat"
if [[ -z "$TC_SKIP_REASON" ]]; then
    mkdir -p /etc/ipsec.d
    cat > "$_TC173_QUINTUPLETS" <<'QEOF'
# identity,RAND(32 hex),AUTN(32 hex),XRES(hex),CK(32 hex),IK(32 hex)
user,00112233445566778899aabbccddeeff,112233445566778899aabbccddeeff00,00112233445566778899,2233445566778899aabbccddeeff0011,33445566778899aabbccddeeff001122
QEOF
fi

# NanoSec is the responder: give it the responder cert/key and CA cert.
TC_RESP_IKE_FLAGS=(
    -a aka
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
            auth    = eap-aka
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
    tc_cleanup_certs tc_173
    rm -f "${REPO_DIR}/server.der" "${REPO_DIR}/serverkey.der" "$_TC173_QUINTUPLETS"
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem \
          /etc/swanctl/x509/tc_suite_resp.pem
}
