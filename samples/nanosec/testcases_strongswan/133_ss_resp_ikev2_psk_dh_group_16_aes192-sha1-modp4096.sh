# IKEv2 PSK — NanoSec initiates → StrongSwan responds
# dh group 16 (modp4096), ESP: AES-CBC-192 & SHA-1

TC_NAME="Testcase 133 IKEv2 PSK / NanoSec->StrongSwan / dh group 16 (modp4096), ESP: AES-CBC-192 & SHA-1"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"   # StrongSwan is IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

TC_INIT_IKE_FLAGS=(-p qatestingexample -g 16)

TC_VERIFY_AUTH="sha1"
TC_VERIFY_ENCR="aes"
TC_VERIFY_KEYLEN=24

# StrongSwan side: responder at RESP_IP, waits for NanoSec initiator at INIT_IP.
tc_setup_swanctl() {
    local r="$1" i="$2" cf="$3"
    cat > "$cf" <<EOF
connections {
    nanosec-interop {
        version = 2
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
        proposals = aes256-sha512-modp4096
        children {
            child1 {
                mode          = transport
                esp_proposals = aes192-sha1
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

# NanoSec side: initiator — init_file and sainit_file need content.
tc_setup_policies() {
    local r="$1" i="$2" rf="$3" inf="$4" sf="$5"
    cat > "$inf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs aes keylength 24 }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_auth_algs sha1 encr_algs aes keylength 24 sa init }
EOF
}
