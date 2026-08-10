# IKEv2 ECDSA Cert

TC_NAME="Testcase 13 IKEv2 ECDSA Cert / NanoSec as Initiator and Responder"
TC_IKE_VERSION=2

TC_RESP_IKE_FLAGS=(
    --ike_cert    ipsec_keystore/nanosecB_ecdsa.der
    --ike_keyblob ipsec_keystore/nanosecB_ecdsakey.dat
    --ike_ca_cert ipsec_keystore/nanosecA_ecdsa.der
)
TC_INIT_IKE_FLAGS=(
    --ike_cert    ipsec_keystore/nanosecA_ecdsa.der
    --ike_keyblob ipsec_keystore/nanosecA_ecdsakey.dat
    --ike_ca_cert ipsec_keystore/nanosecB_ecdsa.der
)

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
