# IKEv1 Certificate — 3DES-CBC + HMAC-SHA1

TC_NAME="IKEv1 Certificate / 3DES-CBC + HMAC-SHA1"
TC_IKE_VERSION=1

if ! tc_gen_certs; then
    TC_SKIP_REASON="cert generation failed — is openssl installed?"
fi

tc_teardown() { tc_cleanup_certs; }

TC_RESP_IKE_FLAGS=(
    --ike_cert    "$TC_RESP_CERT"
    --ike_keyblob "$TC_RESP_KEY"
    --ike_ca_cert "$TC_CA_CERT"
)
TC_INIT_IKE_FLAGS=(
    --ike_cert    "$TC_INIT_CERT"
    --ike_keyblob "$TC_INIT_KEY"
    --ike_ca_cert "$TC_CA_CERT"
)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="3des"
TC_VERIFY_KEYLEN=24

tc_setup_policies() {
    local r=$1 i=$2 rf=$3 inf=$4 sf=$5
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 }
EOF
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 sa init }
EOF
}
