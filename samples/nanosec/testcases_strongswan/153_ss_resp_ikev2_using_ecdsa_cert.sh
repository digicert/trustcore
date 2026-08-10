# IKEv2 Certificate — NanoSec initiates, Strongswan responds
# IKEv2 using ECDSA Certificate

TC_NAME="Testcase 153 IKEv2 Cert / NanoSec->Strongswan / ECDSA Certificate"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

if ! tc_gen_certs tc_153 ecdsa ecdsa; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

# NanoSec is the initiator here: give it the initiator cert/key and CA cert.
TC_INIT_IKE_FLAGS=(
    --ike_cert    "$TC_INIT_CERT"
    --ike_keyblob "$TC_INIT_KEY"
    --ike_ca_cert "$TC_CA_CERT"
    -g 21
)

TC_VERIFY_ENCR="gcm"
TC_VERIFY_KEYLEN=36

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
    cp "$TC_RESP_CERT" /etc/swanctl/x509/tc_suite_init.pem
    cp "$TC_RESP_KEY"  /etc/swanctl/private/tc_suite_init.key
    cp "$TC_CA_CERT"   /etc/swanctl/x509ca/tc_suite_ca.pem

    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 2
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
        proposals = aes256-sha512-modp768-modp1024-modp1536-modp2048-modp3072-modp4096-modp6144-modp8192-ecp256-ecp384-ecp521-modp2048s256-ecp192-ecp224-curve25519-curve448,aes256gcm128-prfsha512-modp768-modp1024-modp1536-modp2048-modp3072-modp4096-modp6144-modp8192-ecp256-ecp384-ecp521-modp2048s256-ecp192-ecp224-curve25519-curve448
        children {
            child1 {
                mode          = transport
                esp_proposals = blowfish128-blowfish192-blowfish256-3des-aes128-aes192-aes256-aes128ctr-aes192ctr-aes256ctr-md5-sha1-sha256-sha384-sha512-aesxcbc,aes128ccm64-aes192ccm96-aes256ccm128-aes128gcm64-aes192gcm96-aes256gcm128-chacha20poly1305
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
{ laddr $i raddr $r } ipsec { encr_algs gcm }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_algs gcm sa init }
EOF
}

tc_teardown() {
    tc_cleanup_certs tc_153
    rm -f /etc/swanctl/x509/tc_suite_init.pem \
          /etc/swanctl/private/tc_suite_init.key \
          /etc/swanctl/x509ca/tc_suite_ca.pem
}
