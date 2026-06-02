# IKEv1 PSK — NanoSec initiates -> StrongSwan responds
# 3DES-CBC + HMAC-SHA1, modp1024 (DH group 2), tunnel mode

TC_NAME="IKEv1 PSK / NanoSec->StrongSwan / 3DES-CBC + HMAC-SHA1 / tunnel"
TC_IKE_VERSION=1
TC_STRONGSWAN_ROLE="resp"
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

TC_INIT_IKE_FLAGS=(-p qatestingexample)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="3des"
TC_VERIFY_KEYLEN=24

tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 1
        local_addrs  = $r
        remote_addrs = $i
        local {
            auth = psk
            id   = $r
        }
        remote {
            auth = psk
            id   = $i
        }
        proposals = 3des-sha256-modp1024
        children {
            child1 {
                mode          = tunnel
                esp_proposals = 3des-sha1-modp1024
                local_ts      = $r/32
                remote_ts     = $i/32
            }
        }
    }
}
secrets {
    ike-nanosec {
        id     = $i
        secret = qatestingexample
    }
}
EOF
}

tc_setup_policies() {
    local r="$1" i="$2" rf="$3" inf="$4" sf="$5"
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 tladdr $i traddr $r }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs 3des keylength 24 tladdr $i traddr $r sa init }
EOF
}
