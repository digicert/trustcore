# IKEv2 PSK

TC_NAME="Testcase 9 IKEv2 PSK / NanoSec as Initiator and Responder"
TC_IKE_VERSION=2

TC_RESP_IKE_FLAGS=(-p qatestingexample)
TC_INIT_IKE_FLAGS=(-p qatestingexample)

TC_VERIFY_AUTH="blake2b"
TC_VERIFY_ENCR="3des"
TC_VERIFY_KEYLEN=24

tc_setup_policies() {
    local r=$1 i=$2 rf=$3 inf=$4 sf=$5
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs any encr_algs any }
EOF
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs any encr_algs any }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs any encr_algs any sa init }
EOF
}
