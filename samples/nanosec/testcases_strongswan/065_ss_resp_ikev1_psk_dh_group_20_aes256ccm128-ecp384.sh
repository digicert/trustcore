# IKEv1 PSK — NanoSec initiates → StrongSwan responds
# dh group 20 (ecp384), ESP: AES-CCM-256

TC_NAME="Testcase 65 IKEv1 PSK / NanoSec->StrongSwan / dh group 20 (ecp384), ESP: AES-CCM-256"
TC_IKE_VERSION=1
TC_STRONGSWAN_ROLE="resp"   # StrongSwan is IKE responder
TC_SS_CONN_NAME="nanosec-interop"
TC_SS_CHILD_NAME="child1"

TC_INIT_IKE_FLAGS=(-p qatestingexample -g 20)

TC_VERIFY_ENCR="ccm"
TC_VERIFY_KEYLEN=35

# StrongSwan side: responder at RESP_IP, waits for NanoSec initiator at INIT_IP.
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
        proposals = aes256-sha512-ecp384
        children {
            child1 {
                mode          = transport
                esp_proposals = aes256ccm128-ecp384
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
{ laddr $i raddr $r } ipsec { encr_algs ccm }
EOF
    cat > "$sf" <<EOF
{ laddr $i raddr $r } ipsec { encr_algs ccm sa init }
EOF
}
