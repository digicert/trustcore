# IKEv1 PSK — StrongSwan initiates -> NanoSec responds
# 3DES-CBC + HMAC-SHA1, modp1024 (DH group 2), tunnel mode

TC_NAME="IKEv1 PSK / StrongSwan->NanoSec / 3DES-CBC + HMAC-SHA1 / tunnel"
TC_IKE_VERSION=1
TC_STRONGSWAN_ROLE="init"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

TC_RESP_IKE_FLAGS=(-p qatestingexample)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="3des"
TC_VERIFY_KEYLEN=24

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 1
        local_addrs  = $i
        remote_addrs = $r
        local {
            auth = psk
            id   = $i
        }
        remote {
            auth = psk
            id   = $r
        }
        proposals = 3des-sha256-modp1024
        children {
            child1 {
                mode          = tunnel
                esp_proposals = 3des-sha1
                local_ts      = $i/32
                remote_ts     = $r/32
            }
        }
    }
}
secrets {
    ike-nanosec {
        id     = $r
        secret = qatestingexample
    }
}
EOF
}

tc_setup_policies() {
    local r="$1" i="$2" rf="$3"
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 tladdr $r traddr $i }
EOF
}
