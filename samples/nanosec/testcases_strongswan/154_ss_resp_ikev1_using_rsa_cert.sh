# IKEv1 Certificate — NanoSec initiates, Strongswan responds
# IKEv1 using RSA Certificate

TC_NAME="Testcase 154 IKEv1 Cert / NanoSec->Strongswan / RSA Certificate"
TC_IKE_VERSION=1
TC_STRONGSWAN_ROLE="resp"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! tc_gen_certs tc_154 rsa rsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# NanoSec is the initiator here: give it the initiator cert/key and CA cert.
TC_INIT_IKE_FLAGS=(
    --ike_cert    "$TC_INIT_CERT"
    --ike_keyblob "$TC_INIT_KEY"
    --ike_ca_cert "$TC_CA_CERT"
    -g 15
)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="aes"
TC_VERIFY_KEYLEN=32

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
    cp "$TC_RESP_CERT" /etc/swanctl/x509/tc_suite_init.pem
    cp "$TC_RESP_KEY"  /etc/swanctl/private/tc_suite_init.key
    cp "$TC_CA_CERT"   /etc/swanctl/x509ca/tc_suite_ca.pem

    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 1
        local_addrs  = $r
        remote_addrs = $i
        local {
            auth    = pubkey
            certs   = tc_suite_init.pem
        }
        remote {
            auth    = pubkey
            cacerts = tc_suite_ca.pem
        }
        proposals = aes256-sha512-modp3072
        children {
            child1 {
                mode          = transport
                esp_proposals = aes256-sha1-modp3072
                local_ts      = $r/32
                remote_ts     = $i/32
            }
        }
    }
}
EOF
}

# NanoSec side: initiator — init_file and sainit_file need content.
tc_setup_policies() {
    local r="$1" i="$2" rf="$3" inf="$4" sf="$5"
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs aes keylength 32}
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs aes keylength 32 sa init }
EOF
}

tc_teardown() {
    tc_cleanup_certs tc_154
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem
}
