# IKEv1 PSK — 3DES-CBC + HMAC-SHA1, tunnel mode

TC_NAME="IKEv1 PSK / 3DES-CBC + HMAC-SHA1 / tunnel"
TC_IKE_VERSION=1

TC_RESP_IKE_FLAGS=(-p qatestingexample)
TC_INIT_IKE_FLAGS=(-p qatestingexample)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="3des"
TC_VERIFY_KEYLEN=24

tc_setup_policies() {
    local r=$1 i=$2 rf=$3 inf=$4 sf=$5
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 tladdr $r traddr $i }
EOF
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 tladdr $i traddr $r }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 tladdr $i traddr $r sa init }
EOF
}
