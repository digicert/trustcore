# IKEv2 EAP-SIM — Strongswan initiates as EAP supplicant, NanoSec responds
# as EAP authenticator (pubkey + eap-sim)

TC_NAME="Testcase 172 IKEv2 EAP-SIM / Strongswan(supplicant)->NanoSec(authenticator), esp:aes128-sha256-modp3072"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="init"   # StrongSwan is the EAP authenticator / IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

# eap-sim-file must be compiled into charon. It provides the SIM triplet
# database so StrongSwan can challenge NanoSec with the specific RAND values
# that NanoSec's hardcoded triplet table recognises (from ike_example.c).
if [[ -z "$TC_SKIP_REASON" ]] && \
   ! grep -aq "eap-sim-file" "${CHARON_BIN:-/usr/libexec/ipsec/charon}" 2>/dev/null; then
    TC_SKIP_REASON="eap-sim-file not in charon — rebuild StrongSwan: sudo $0 -I"
fi

if ! tc_gen_certs tc_172 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# StrongSwan's libtls looks up the peer cert by EAP identity (FQDN "responder") not by cert subject DN.
# Re-sign the responder cert with subjectAltName=DNS:responder so the FQDN identity matches the cert's SAN during chain verification.
if [[ -z "$TC_SKIP_REASON" ]]; then
    _tc172_ca_key="${REPO_DIR}/keystore/keys/tc_172_ca.key"
    openssl x509 -req \
        -in <(openssl req -new -key "$TC_RESP_KEY" -subj "/CN=responder" 2>/dev/null) \
        -CA "$TC_CA_CERT" -CAkey "$_tc172_ca_key" \
        -CAcreateserial -out "$TC_RESP_CERT" -days 1 -sha256 \
        -extfile <(printf 'subjectAltName=DNS:responder\n') 2>/dev/null \
        || TC_SKIP_REASON="responder cert re-sign with SAN failed"
fi

# Write the SIM triplets to the eap-sim-file plugin's default path before charon starts
_TC172_TRIPLETS="/etc/ipsec.d/triplets.dat"
if [[ -z "$TC_SKIP_REASON" ]]; then
    mkdir -p /etc/ipsec.d
    cat > "$_TC172_TRIPLETS" <<'TRIPEOF'
# identity,RAND(32 hex chars),SRES(8 hex chars),Kc(16 hex chars)
user,101112131415161718191a1b1c1d1e1f,d1d2d3d4,a0a1a2a3a4a5a6a7
user,202122232425262728292a2b2c2d2e2f,e1e2e3e4,b0b1b2b3b4b5b6b7
user,303132333435363738393a3b3c3d3e3f,f1f2f3f4,c0c1c2c3c4c5c6c7
TRIPEOF
fi


# NanoSec is the responder: give it the responder cert/key and CA cert.
TC_RESP_IKE_FLAGS=(
    -a sim 
    -A user
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
            auth    = eap-sim
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
    tc_cleanup_certs tc_172
    rm -f "${REPO_DIR}/server.der" "${REPO_DIR}/serverkey.der" "$_TC172_TRIPLETS"
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem \
          /etc/swanctl/x509/tc_suite_resp.pem
}
