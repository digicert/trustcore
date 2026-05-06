DEVICETM_DEVICE_GROUP_ID="63acb3c3-844c-43a2-ad33-70d9863360e9"

CERTIFICATE_POLICY_CONFIG=(
# policy block 1
'
    POLICY_ID="IOT_5d6382ee-86c0-4da9-a341-cda352cb43c8"
    POLICY_TYPE="Bootstrap"
    ENROLLMENT_METHOD="EST"
    EST_KEY_GENERATION_SOURCE="Local"
    EST_KEY_ALGORITHM="ECC"
    EST_KEY_SIZE="P256"
    EST_KEY_ALIAS="signing"
    EST_AUTHENTICATION_MODE="BASIC"
    EST_PASSWORD="<password>"
    EST_CSR="signing-csr.conf"
'
# policy block 2
'
    POLICY_ID="IOT_8ca68860-df1c-40cd-85fe-82140a07da15"
    POLICY_TYPE="Operational"
    ENROLLMENT_METHOD="EST"
    EST_KEY_GENERATION_SOURCE="SKG"
    EST_KEY_ALGORITHM="RSA"
    EST_KEY_SIZE="2048"
    EST_KEY_ALIAS="rsa-server"
    EST_AUTHENTICATION_MODE="BASIC"
    EST_USER="user123"
    EST_PASSWORD="<password>"
    EST_CSR="server-rsa-csr.conf"
'
# policy block 3
'
    POLICY_ID="IOT_ff01040d-21cf-4cc4-a2aa-1a8d6647ee70"
    POLICY_TYPE="Operational"
    ENROLLMENT_METHOD="EST"
    EST_KEY_GENERATION_SOURCE="SKG"
    EST_KEY_ALGORITHM="QS"
    EST_KEY_SIZE="MLDSA_44"
    EST_KEY_ALIAS="mldsa-server"
    EST_AUTHENTICATION_MODE="BASIC"
    EST_MTLS_ALIAS="mutual-auth"
    EST_CSR="server-mldsa-csr.conf"
'
)