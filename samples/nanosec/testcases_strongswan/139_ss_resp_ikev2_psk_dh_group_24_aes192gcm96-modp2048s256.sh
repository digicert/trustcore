# IKEv2 PSK — NanoSec initiates → StrongSwan responds
# dh group 24 (modp2048s256), ESP: AES-GCM-192

TC_NAME="Testcase 139 IKEv2 PSK / NanoSec->StrongSwan / dh group 24 (modp2048s256), ESP: AES-GCM-192"
TC_IKE_VERSION=2
TC_STRONGSWAN_ROLE="resp"   # StrongSwan is IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

TC_INIT_IKE_FLAGS=(-p qatestingexample -g 24)

TC_VERIFY_ENCR="gcm"
TC_VERIFY_KEYLEN=28

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
        proposals = aes256gcm128-prfsha512-modp2048s256
        children {
            child1 {
                mode          = transport
                esp_proposals = aes192gcm96
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
{ laddr $i raddr $r } ipsec { encr_algs any keylength 24 tag 12 }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_algs any keylength 24 tag 12 sa init }
EOF
}
