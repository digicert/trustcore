# IKEv1 PSK — StrongSwan initiates → NanoSec responds
# blowfish192-sha512-modp4096

TC_NAME="Testcase 18 IKEv1 PSK / StrongSwan->NanoSec / ike:blowfish192-sha512-modp4096 esp:blowfish192-sha512-modp4096"
TC_IKE_VERSION=1
TC_STRONGSWAN_ROLE="init"   # StrongSwan is IKE initiator
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

TC_RESP_IKE_FLAGS=(-p qatestingexample)

TC_VERIFY_AUTH="sha512"
TC_VERIFY_ENCR="blowfish"
TC_VERIFY_KEYLEN=24

# StrongSwan side: initiator at INIT_IP, connects to NanoSec responder at RESP_IP.
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
        proposals = blowfish192-sha512-modp4096
        children {
            child1 {
                mode          = transport
                esp_proposals = blowfish192-sha512
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

# NanoSec side: responder only — only resp_file needs content.
tc_setup_policies() {
    local r="$1" i="$2" rf="$3"
    cat > "$rf" <<EOF
flush;
spdflush;
{ laddr $r raddr $i } ipsec { encr_auth_algs sha512 encr_algs blowfish keylength 24 }
EOF
}
