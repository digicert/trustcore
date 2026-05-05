#!/bin/bash

set -e

NULL_FILE="/dev/null"
PLATFORMS=("x64" "rpi64" "rpi32")
KEYSTORE_CA_DIR="/etc/digicert/keystore/ca"
KEYSTORE_CERTS_DIR="/etc/digicert/keystore/certs"
KEYSTORE_KEYS_DIR="/etc/digicert/keystore/keys"
KEYSORE_REQ_DIR="/etc/digicert/keystore/req"
KEYSTORE_CONF_DIR="/etc/digicert/keystore/conf"
CONF_DIR="/etc/digicert/conf"
CLOUD_DIR="/etc/digicert/cloudprovider"

ALL_TESTS_PASSED=false

declare -A TEST_RESULTS
declare -a ORDERED_TESTS

collect_test_results() {
    TEST_RESULTS["$1"]=$2
    ORDERED_TESTS+=("$1")
}

display_summary() {
    echo " "
    echo "*************************************************************************"
    echo "*************************** Test Summary ********************************"
    echo "*************************************************************************"
    echo "| Test Name                                                    | Result |"
    echo "|--------------------------------------------------------------|--------|"
    for key in "${ORDERED_TESTS[@]}"; do
        printf "| %-60s | %-6s |\n" "$key" "${TEST_RESULTS[$key]}"
        echo "|--------------------------------------------------------------|--------|"
    done
}

log_section() {
    echo " "
    echo "*************************************************************************"
    echo "*** $1"
    echo "*************************************************************************"
}
cd ../../../

display_summary_and_cleanup() {
    if [ $? -ne 0 ]; then
        echo "An error occurred. Exiting..."
    fi

    display_summary

    if [ "$ALL_TESTS_PASSED" == true ]; then
    echo "All tests passed"
    else
    echo "Some tests failed or skipped"
    fi

    echo "Cleaning up..."
    #rm arm64 and armhf architectures
    dpkg --remove-architecture arm64
    dpkg --remove-architecture armhf

    if [ -f bootstrap.zip ]; then
        rm -f bootstrap.zip
    fi

    if [ -f device_id.txt ]; then
        python3 tmp/disable_delete_device.py "$device_id"
        rm -f device_id.txt
    fi

    if [ -d tmp ]; then
        rm -rf tmp
    fi

    if [ -f sub_output.txt ]; then
        rm -f sub_output.txt
    fi

    #uninstall trustedge
    dpkg --purge trustedge > $NULL_FILE
}

trap display_summary_and_cleanup EXIT

#***********************************************************************************************************

install_uninstall_test() {
    local platform=$1

    #deb
    log_section "Starting Trustedge install/uninstall(deb) test for $platform"

    #Install

    log_section "Installing trustedge(deb) for $platform"
    DIGICERT_EULA_ACCEPT=yes dpkg -i tmp/deb/$platform/trustedge*.deb > $NULL_FILE

    text=$(dpkg -s trustedge 2> $NULL_FILE)
    STATUS=$(echo "$text" | grep "Status" | awk '{print $2, $3, $4}')
    VERSION=$(echo "$text" | grep "^Version" | awk '{print $2}')

    echo "Trustedge version: $VERSION"
    echo "Trustedge status: $STATUS"
    if [ "$STATUS" == "install ok installed" ]; then
        echo "**********[Test Passed] Trustedge installation(deb) successful for $platform"
        collect_test_results "Trustedge installation(deb) for $platform" "PASS"
    else
        echo "**********[Test Failed] Trustedge installation(deb) failed for $platform"
        collect_test_results "Trustedge installation(deb) for $platform" "FAIL"
        exit 1
    fi

    #Uninstall

    log_section "Uninstalling trustedge(deb) for $platform"
    dpkg --purge trustedge > $NULL_FILE

    if dpkg -s trustedge > $NULL_FILE 2>&1 ; then
        echo "**********[Test Failed] Trustedge uninstallation(deb) failed for $platform"
        collect_test_results "Trustedge uninstallation(deb) for $platform" "FAIL"
        exit 1
    fi

    if [ "$(ls -A /etc/digicert)" > $NULL_FILE ]; then
        echo "**********[Test Failed] Trustedge uninstallation(deb) failed for $platform"
        collect_test_results "Trustedge uninstallation(deb) for $platform" "FAIL"
        exit 1
    fi

    echo "**********[Test Passed] Trustedge uninstallation(deb) successful for $platform"
    collect_test_results "Trustedge uninstallation(deb) for $platform" "PASS"

    log_section "Trustedge install/uninstall(deb) for $platform completed successfully"
    collect_test_results "Trustedge install/uninstall(deb) for $platform" "PASS"

    #TGZ
    log_section "Extracting trustedge(tgz) for $platform"
    tar -xzf tmp/tgz/$platform/trustedge*.tar.gz -C /tmp

    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Trustedge extraction(tgz) failed for $platform"
        collect_test_results "Trustedge extraction(tgz) for $platform" "FAIL"
        exit 1
    fi

    echo "Trustedge(tgz) installed successfully for $platform"
    collect_test_results "Trustedge extraction(tgz) for $platform" "PASS"

    if [ -d /tmp/bin ] && [ -f /tmp/bin/trustedge ] && \
       [ -d /tmp/cloudprovider ] && \
       [ -d /tmp/conf ] && [ -d /tmp/keystore ] && \
       [ -d /tmp/scripts ] && [ -f /tmp/scripts/configure_trustedge.sh ] && \
       [ -f /tmp/scripts/start_trustedge.sh ] && \
       [ -d /tmp/service ] && [ -d /tmp/service/completed ] && \
       [ -d /tmp/service/failed ] && [ -d /tmp/service/processing ] && \
       [ -d /tmp/service/request ] && \
       [ -f /tmp/trustedge.json ]; then
        echo "**********[Test Passed] Trustedge(tgz) file structure verified successfully for $platform"
        collect_test_results "Trustedge(tgz) file structure verification for $platform" "PASS"
    else
        echo "**********[Test Failed] Trustedge(tgz) file structure verification failed for $platform"
        collect_test_results "Trustedge(tgz) file structure verification for $platform" "FAIL"
        exit 1
    fi

    #cleanup extracted files
    log_section "trustedge(tgz) cleanup for $platform"
    rm -rf /tmp/bin /tmp/cloudprovider /tmp/conf /tmp/keystore /tmp/scripts /tmp/service /tmp/trustedge.json
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Trustedge(tgz) cleanup failed for $platform"
        collect_test_results "Trustedge(tgz) cleanup for $platform" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Trustedge(tgz) cleanup successful for $platform"
        collect_test_results "Trustedge(tgz) cleanup for $platform" "PASS"
    fi
}

#***********************************************************************************************************

trustedge_agent_reset() {
    log_section "Resetting trustedge agent"
    trustedge agent --reset
    if [ "$(ls -A $KEYSTORE_CA_DIR)" ]; then
        echo "$KEYSTORE_CA_DIR is not empty"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "$KEYSTORE_CA_DIR is empty"
    fi
    if [ "$(ls -A $KEYSTORE_CERTS_DIR)" ]; then
        echo "$KEYSTORE_CERTS_DIR is not empty"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "$KEYSTORE_CERTS_DIR is empty"
    fi

    if [ "$(ls -A $KEYSTORE_KEYS_DIR)" ]; then
        echo "$KEYSTORE_KEYS_DIR is not empty"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    fi

    if [ "$(ls -A $KEYSORE_REQ_DIR)" ]; then
        echo "$KEYSORE_REQ_DIR is not empty"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "$KEYSORE_REQ_DIR is empty"
    fi

    if [ "$(ls -A $CLOUD_DIR)" ]; then
        echo "$CLOUD_DIR is not empty"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "$CLOUD_DIR is empty"
    fi

    if [ -f $CONF_DIR/metrics.pb ]; then
        echo "metrics.pb exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "metrics.pb does not exist"
    fi
    if [ -f $CONF_DIR/desired_attributes.pb ]; then
        echo "desired_attributes.pb exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "desired_attributes.pb does not exist"
    fi
    if [ -f $CONF_DIR/applied_policy.json ]; then
        echo "applied_policy.json exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "applied_policy.json does not exist"
    fi
    if [ -f $CONF_DIR/policy_authorization.jwt ]; then
        echo "policy_authorization.jwt exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "policy_authorization.jwt does not exist"
    fi
    if [ -f $CONF_DIR/failed_policy.json ]; then
        echo "failed_policy.json exists"
        exit 1
    else
        echo "failed_policy.json does not exist"
    fi
    if [ -f $CONF_DIR/processing_policy.json ]; then
        echo "processing_policy.json exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "processing_policy.json does not exist"
    fi
    if [ -f $CONF_DIR/pending_policy.json ]; then
        echo "pending_policy.json exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "pending_policy.json does not exist"
    fi
    if [ -f $CONF_DIR/bootstrap_config.json ]; then
        echo "bootstrap_config.json exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "bootstrap_config.json does not exist"
    fi
    if [ -f $CONF_DIR/cert_spec.json ]; then
        echo "cert_spec.json exists"
        echo "**********[Test Failed] Trustedge agent reset failed"
        collect_test_results "Trustedge agent reset" "FAIL"
        exit 1
    else
        echo "cert_spec.json does not exist"
    fi

    echo "**********[Test Passed] Trustedge agent reset successful"
    collect_test_results "Trustedge agent reset" "PASS"
}

trustedge_help_version() {
    log_section "Running trustedge help and version"
    trustedge --help
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge --help failed"
        collect_test_results "Trustedge --help" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge --help successful"
        collect_test_results "Trustedge --help" "PASS"
    fi

    trustedge --version
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge --version failed"
        collect_test_results "Trustedge --version" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge --version successful"
        collect_test_results "Trustedge --version" "PASS"
    fi
}

trustedge_agent() {
    log_section "Running trustedge agent"
    trustedge agent --help
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge agent --help failed"
        collect_test_results "Trustedge agent --help" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge agent --help successful"
        collect_test_results "Trustedge agent --help" "PASS"
    fi

    #get bootstrap config
    echo " "
    echo ">>>Generating bootstrap config"
    echo " "
    register_and_get_bootstrap

    #configure trustedge check
    echo " "
    echo ">>>Checking trustedge configuration"
    echo " "
    check_trustedge_config

    #run trustedge agent
    echo " "
    echo ">>>Running trustedge agent"
    echo " "

    trustedge agent --log-level VERBOSE
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge agent --log-level VERBOSE failed"
        collect_test_results "Trustedge agent --log-level VERBOSE" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge agent --log-level VERBOSE successful"
        collect_test_results "Trustedge agent --log-level VERBOSE" "PASS"

    fi

    echo " "
    echo "Applied policy"
    cat $CONF_DIR/applied_policy.json

    echo " "
    echo "Failed policy"
    cat $CONF_DIR/failed_policy.json
    if [ "$(jq '.failedPolicies | length' $CONF_DIR/failed_policy.json)" -eq 0 ]; then
        echo "No failed policies"
    else
        echo "Failed policies exist"
        collect_test_results "Trustedge agent" "FAIL"
        exit 1
    fi

    echo " "
    echo "Processing policy"
    cat $CONF_DIR/processing_policy.json
    if [ "$(jq '.processingPolicies | length' $CONF_DIR/processing_policy.json)" -eq 0 ]; then
        echo "No processing policies"
    else
        echo "Processing policies exist"
        collect_test_results "Trustedge agent" "FAIL"
        exit 1
    fi

    if [ -f $CONF_DIR/metrics.pb ]; then
        echo "metrics.pb exists"
    else
        echo "metrics.pb does not exist"
        collect_test_results "Trustedge agent" "FAIL"
        exit 1
    fi

    if [ -f $CONF_DIR/desired_attributes.pb ]; then
        echo "desired_attributes.pb exists"
    else
        echo "desired_attributes.pb does not exist"
        collect_test_results "Trustedge agent" "FAIL"
        exit 1
    fi

    #decode metrics.pb
    echo " "
    echo ">>>Decoding metrics.pb"
    echo " "
    protoc --decode_raw < $CONF_DIR/metrics.pb

    #decode desired_attributes.pb
    echo " "
    echo ">>>Decoding desired_attributes.pb"
    echo " "
    protoc --decode_raw < $CONF_DIR/desired_attributes.pb

    collect_test_results "Trustedge agent test" "PASS"
}

check_trustedge_config() {
    if [ -f /etc/digicert/trustedge.json ]; then
        echo "trustedge.json exists"
    else
        echo "trustedge.json does not exist"
        echo "**********[Test Failed] Trustedge configuration failed"
        collect_test_results "Trustedge configuration" "FAIL"
        exit 1
    fi

    if [ -f $CONF_DIR/bootstrap_config.json ]; then
        echo "bootstrap_config.json exists"
    else
        echo "bootstrap_config.json does not exist"
        echo "**********[Test Failed] Trustedge configuration failed"
        collect_test_results "Trustedge configuration" "FAIL"
        exit 1
    fi

    collect_test_results "Trustedge configuration" "PASS"
}

register_and_get_bootstrap() {
    # run python script that registers a device and gets bootstrap config
    python3 tmp/register_device.py
    # get device id from device_id.txt
    device_id=$(cat device_id.txt)
    echo "Device id: $device_id"
    # check if bootstrap config is generated
    if [ -f bootstrap.zip ]; then
        echo "Bootstrap config generated"
    else
        echo "Bootstrap config not generated"
        exit 1
    fi

    # unzip bootstrap config
    echo " "
    echo ">>>Unzipping bootstrap config"
    echo " "
    trustedge agent --configure --trustedge-user trustedge --trustedge-group trustedge --bootstrap-zip ./bootstrap.zip
}


test_trustedge_agent_x64() {

    # run trustedge help
    trustedge_help_version

    #run trustedge agent
    trustedge_agent
}

#***********************************************************************************************************

test_mqtt() {

    #run mqtt basic publish subscribe tests
    log_section "Running trustedge mqtt basic publish subscribe tests"

    echo " "
    echo ">>>Subscribing to topic house/bulb1"
    echo " "
    trustedge mqtt --mqtt_servername test.mosquitto.org --mqtt_sub_topic house/bulb1 --mqtt_port 1883 --mqtt_clean_start > sub_output.txt &
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge mqtt subscribe failed"
        collect_test_results "Trustedge mqtt subscribe" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge mqtt subscribe successful"
        collect_test_results "Trustedge mqtt subscribe" "PASS"
    fi
    SUB_PID=$!

    sleep 5

    echo " "
    echo ">>>Publishing to topic house/bulb1"
    echo " "
    trustedge mqtt --mqtt_servername test.mosquitto.org --mqtt_pub_topic house/bulb1 --mqtt_pub_message "test message" --mqtt_port 1883 --mqtt_clean_start
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge mqtt publish failed"
        collect_test_results "Trustedge mqtt publish" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge mqtt publish successful"
        collect_test_results "Trustedge mqtt publish" "PASS"
    fi

    sleep 5

    echo " "
    echo ">>>Checking subscription output"
    echo " "
    SUB_OUTPUT=$(cat sub_output.txt)
    TOPIC=$(echo "$SUB_OUTPUT" | grep "Topic" | awk '{print $2}')
    PAYLOAD=$(echo "$SUB_OUTPUT" | grep "Payload" | awk '{print $2, $3}')
    echo "Received Topic: $TOPIC"
    echo "Received Payload: $PAYLOAD"
    if [ "$TOPIC" == "house/bulb1" ]; then
        echo "**********[Test Passed] Topic matched"
    else
        echo "**********[Test Failed] Topic did not match"
        collect_test_results "Trustedge mqtt subscribe publish" "FAIL"
        exit 1
    fi

    if [ "$PAYLOAD" == "test message" ]; then
        echo "**********[Test Passed] Payload matched"
    else
        echo "**********[Test Failed] Payload did not match"
        collect_test_results "Trustedge mqtt subscribe publish" "FAIL"
        exit 1
    fi

    kill -SIGINT $SUB_PID

    collect_test_results "Trustedge mqtt subscribe publish" "PASS"
}


test_trustedge_mqtt_x64() {
    log_section "Testing trustedge mqtt on x64"

    #run mqtt --help
    log_section "Running trustedge mqtt --help"
    trustedge mqtt --help
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge mqtt --help failed"
        collect_test_results "Trustedge mqtt --help" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge mqtt --help successful"
        collect_test_results "Trustedge mqtt --help" "PASS"
    fi

    #run basic publish subscribe tests
    #test_mqtt
}

#***********************************************************************************************************

test_certificate_est() {
    log_section "Testing trustedge certificate est"

    #run certificate est --help
    echo " "
    echo ">>>Running trustedge certificate est --help"
    echo " "
    trustedge certificate est --help
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate est --help failed"
        collect_test_results "Trustedge certificate est --help" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate est --help successful"
        collect_test_results "Trustedge certificate est --help" "PASS"
    fi
}

test_certificate_scep() {
    log_section "Testing trustedge certificate scep"

    #run certificate scep --help
    echo " "
    echo ">>>Running trustedge certificate scep --help"
    echo " "
    trustedge certificate scep --help
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate scep --help failed"
        collect_test_results "Trustedge certificate scep --help" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate scep --help successful"
        collect_test_results "Trustedge certificate scep --help" "PASS"
    fi
}

test_certificate()
{
    log_section "Testing trustedge certificate"

    # generate software-based private key
    echo " "
    echo ">>>Generating software-based private key (RSA 2048)"
    echo " "
    trustedge certificate --algorithm RSA --size 2048 --output-file RSA_2048.pem
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Generate software-based private key (RSA 2048) failed"
        collect_test_results "Trustedge certificate: Generate RSA 2048 private key" "FAIL"
        exit 1
    fi

    trustedge certificate --algorithm ECC --curve P256 --output-file ECC_P256.pem
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Generate software-based private key (ECC P256) failed"
        collect_test_results "Trustedge certificate: Generate ECC P256 private key" "FAIL"
        exit 1
    fi

    if [ -f $KEYSTORE_KEYS_DIR/RSA_2048.pem ]; then
        echo "RSA_2048.pem exists"
        echo "**********[Test Passed] Generate software-based private key (RSA 2048) successful"
        collect_test_results "Trustedge certificate: Generate RSA 2048 private key" "PASS"
    else
        echo "**********[Test Failed] Generate software-based private key (RSA 2048) failed"
        collect_test_results "Trustedge certificate: Generate RSA 2048 private key" "FAIL"
        exit 1
    fi

    if [ -f $KEYSTORE_KEYS_DIR/ECC_P256.pem ]; then
        echo "ECC_P256.pem exists"
        echo "**********[Test Passed] Generate software-based private key (ECC P256) successful"
        collect_test_results "Trustedge certificate: Generate ECC P256 private key" "PASS"
    else
        echo "**********[Test Failed] Generate software-based private key (ECC P256) failed"
        collect_test_results "Trustedge certificate: Generate ECC P256 private key" "FAIL"
        exit 1
    fi

    # create a CSR
    echo " "
    echo ">>>Creating a CSR"
    echo " "
cat > $KEYSTORE_CONF_DIR/sample_csr.cnf <<EOF
##Subject
countryName=US
commonName=iot-device101
stateOrProvinceName=California
localityName=San Francisco
organizationName=DBA
organizationalUnitName=BU
##Requested Extensions
hasBasicConstraints=true
isCA=true
certPathLen=-1
keyUsage=keyEncipherment, digitalSignature, keyCertSign
subjectAltNames=2; *.mydomain.com, 2; *.mydomain.net, 2
EOF

    cat $KEYSTORE_CONF_DIR/sample_csr.cnf
    # Generate the CSR
    echo " "
    echo ">>>Generating the CSR (RSA 2048)"
    echo " "
    trustedge certificate --cert-sign-req --output-file CSR_RSA_2048.pem --signing-key RSA_2048.pem --csr-conf sample_csr.cnf --digest SHA256
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Generate CSR (RSA 2048) failed"
        collect_test_results "Trustedge certificate: Generate CSR RSA 2048" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Generate CSR (RSA 2048) successful"
        collect_test_results "Trustedge certificate: Generate CSR RSA 2048" "PASS"
    fi

    echo " "
    echo ">>>Generating the CSR (ECC P256)"
    echo " "
    trustedge certificate --cert-sign-req --output-file CSR_ECC_P256.pem --signing-key ECC_P256.pem --csr-conf sample_csr.cnf --digest SHA256
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Generate CSR (ECC P256) failed"
        collect_test_results "Trustedge certificate: Generate CSR ECC P256" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Generate CSR (ECC P256) successful"
        collect_test_results "Trustedge certificate: Generate CSR ECC P256" "PASS"
    fi

    # verify the CSR
    echo " "
    echo ">>>Verifying the CSR (RSA 2048)"
    echo " "
    trustedge certificate --print-cert $KEYSORE_REQ_DIR/CSR_RSA_2048.pem
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --print-cert CSR_RSA_2048 failed"
        collect_test_results "Trustedge certificate: --print-cert CSR_RSA_2048" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --print-cert CSR_RSA_2048 successful"
        collect_test_results "Trustedge certificate: --print-cert CSR_RSA_2048" "PASS"
    fi

    echo " "
    echo ">>>Verifying the CSR (ECC P256)"
    echo " "
    trustedge certificate --print-cert $KEYSORE_REQ_DIR/CSR_ECC_P256.pem
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --print-cert CSR_ECC_P256 failed"
        collect_test_results "Trustedge certificate: --print-cert CSR_ECC_P256" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --print-cert CSR_ECC_P256 successful"
        collect_test_results "Trustedge certificate: --print-cert CSR_ECC_P256" "PASS"
    fi

    # generate the X.509 cert
    echo " "
    echo ">>>Generating the X.509 cert (RSA 2048)"
    echo " "
    trustedge certificate --algorithm RSA --size 2048 --output-file RSA_CERT_2048.pem --csr-conf sample_csr.cnf --x509-cert RSA_CERT_2048.pem --days 365
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --x509-cert RSA_CERT_2048 failed"
        collect_test_results "Trustedge certificate: --x509-cert RSA_CERT_2048" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --x509-cert RSA_CERT_2048 successful"
        collect_test_results "Trustedge certificate: --x509-cert RSA_CERT_2048" "PASS"
    fi

    echo " "
    echo ">>>Generating the X.509 cert (ECC P256)"
    echo " "
    trustedge certificate --algorithm ECC --curve P256 --output-file ECC_CERT_P256.pem --csr-conf sample_csr.cnf --x509-cert ECC_CERT_P256.pem --days 365
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --x509-cert ECC_CERT_P256 failed"
        collect_test_results "Trustedge certificate: --x509-cert ECC_CERT_P256" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --x509-cert ECC_CERT_P256 successful"
        collect_test_results "Trustedge certificate: --x509-cert ECC_CERT_P256" "PASS"
    fi

    # verify the cert creation
    echo " "
    echo ">>>Verifying the cert creation (RSA 2048)"
    echo " "
    trustedge certificate --print-cert $KEYSTORE_CERTS_DIR/RSA_CERT_2048.pem
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --print-cert RSA_CERT_2048 failed"
        collect_test_results "Trustedge certificate: --print-cert RSA_CERT_2048" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --print-cert RSA_CERT_2048 successful"
        collect_test_results "Trustedge certificate: --print-cert RSA_CERT_2048" "PASS"
    fi

    echo " "
    echo ">>>Verifying the cert creation (ECC P256)"
    echo " "
    trustedge certificate --print-cert $KEYSTORE_CERTS_DIR/ECC_CERT_P256.pem   
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --print-cert ECC_CERT_P256 failed"
        collect_test_results "Trustedge certificate: --print-cert ECC_CERT_P256" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --print-cert ECC_CERT_P256 successful"
        collect_test_results "Trustedge certificate: --print-cert ECC_CERT_P256" "PASS"
    fi
}

test_trustedge_certificate_x64() {
    log_section "Testing trustedge certificate on x64"

    #run certificate --help
    log_section "Running trustedge certificate --help"
    trustedge certificate --help
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] trustedge certificate --help failed"
        collect_test_results "Trustedge certificate --help" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] trustedge certificate --help successful"
        collect_test_results "Trustedge certificate --help" "PASS"
    fi

    test_certificate
    test_certificate_est
    test_certificate_scep
}


#***********************************************************************************************************

check_service_status()
{
    log_section "Checking trustedge service status"
    expected_status="$1"

    received_status=$(systemctl status trustedge.service | grep "Active:" | awk '{print $2}')
    echo "received status: $received_status"
    if [ "$received_status" != "$expected_status" ]; then
        echo "**********[Test Failed] Trustedge service status is not $expected_status"
        collect_test_results "Trustedge service status" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Trustedge service status is $expected_status"
        collect_test_results "Trustedge service status" "PASS"
    fi

}

start_service()
{
    log_section "Starting trustedge service"
    systemctl start trustedge.service
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Trustedge service start failed"
        collect_test_results "Trustedge service start" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Trustedge service start successful"
        collect_test_results "Trustedge service start" "PASS"
    fi
}

stop_service()
{
    log_section "Stopping trustedge service"
    systemctl stop trustedge.service
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Trustedge service stop failed"
        collect_test_results "Trustedge service stop" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Trustedge service stop successful"
        collect_test_results "Trustedge service stop" "PASS"
    fi
}



test_trustedge_service_x64()
{
    log_section "Testing trustedge service on x64"

    check_service_status "inactive"

    start_service
    check_service_status "active"

    stop_service
    check_service_status "inactive"

    journalctl -u trustedge.service --since "2 minutes ago"
    if [ $? -ne 0 ]; then
        echo "**********[Test Failed] Trustedge service logs failed"
        collect_test_results "Trustedge service logs" "FAIL"
        exit 1
    else
        echo "**********[Test Passed] Trustedge service logs successful"
        collect_test_results "Trustedge service logs" "PASS"
    fi
}

#***********************************************************************************************************

test_reinstallation_x64()
{
    log_section "Reinstalling trustedge on x64"
    DIGICERT_EULA_ACCEPT=yes dpkg -i tmp/deb/x64/trustedge*.deb > $NULL_FILE

    text=$(dpkg -s trustedge 2> $NULL_FILE)
    STATUS=$(echo "$text" | grep "Status" | awk '{print $2, $3, $4}')
    VERSION=$(echo "$text" | grep "^Version" | awk '{print $2}')

    echo "Trustedge version: $VERSION"
    echo "Trustedge status: $STATUS"

    if [ "$STATUS" == "install ok installed" ]; then
        echo "**********[Test Passed] Trustedge reinstallation successful for x64"
        collect_test_results "Trustedge reinstallation for x64" "PASS"
    else
        echo "**********[Test Failed] Trustedge reinstallation failed for x64"
        collect_test_results "Trustedge reinstallation for x64" "FAIL"
        exit 1
    fi

    log_section "Trustedge reinstallation successful for x64"
}

#***********************************************************************************************************

#add architecture for arm64 and armhf
dpkg --add-architecture arm64
dpkg --add-architecture armhf

for platform in "${PLATFORMS[@]}"; do
   install_uninstall_test $platform
done

test_reinstallation_x64
test_trustedge_agent_x64
test_trustedge_certificate_x64
test_trustedge_mqtt_x64
test_trustedge_service_x64
trustedge_agent_reset

ALL_TESTS_PASSED=true