# IKEv2 Certificate — StrongSwan initiates, NanoSec responds
# 3DES-CBC + HMAC-SHA1, modp1024 (DH group 2), transport mode

TC_NAME="IKEv2 Cert / StrongSwan->NanoSec / 3DES-CBC + HMAC-SHA1"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="init"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! tc_gen_certs; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# NanoSec is the responder: give it the responder cert/key and CA cert.
TC_RESP_IKE_FLAGS=(
    --ike_cert    "$TC_RESP_CERT"
    --ike_keyblob "$TC_RESP_KEY"
    --ike_ca_cert "$TC_CA_CERT"
)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="3des"
TC_VERIFY_KEYLEN=24

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
    cp "$TC_INIT_CERT" /etc/swanctl/x509/tc_suite_init.pem
    cp "$TC_INIT_KEY"  /etc/swanctl/private/tc_suite_init.key
    cp "$TC_CA_CERT"   /etc/swanctl/x509ca/tc_suite_ca.pem

    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 2
        local_addrs  = $i
        remote_addrs = $r
        local {
            auth    = pubkey
            certs   = tc_suite_init.pem
        }
        remote {
            auth    = pubkey
            cacerts = tc_suite_ca.pem
        }
        proposals = 3des-sha256-modp1024
        children {
            child1 {
                mode          = transport
                esp_proposals = 3des-sha1
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
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 }
EOF
}

tc_teardown() {
    tc_cleanup_certs
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem
}
