#!/bin/bash

CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
echo $CURR_DIR

QS_ARG=""
QS_ARG_PATH=""

clean_func()
{
    cd $CURR_DIR

    rm bin/* 2>/dev/null
    rm build/* 2>/dev/null
    rm test/* 2>/dev/null
    rm testaux/* 2>/dev/null
    rm -r testaux/CA/ 2>/dev/null
    rm testaux/CA/newcerts/* 2>/dev/null
    rm testaux/ocsp_test_certs/* 2>/dev/null
    rm $CURR_DIR/../../bin/lib* 2>/dev/null
}

build_target()
{
    local target_name="$1";

    cd $CURR_DIR/build && rm -rf * && cmake .. -D${target_name}=ON && make

    cd $CURR_DIR
}

case "$1" in
start)
    killall sslserv
    killall sslserv_versionset
    killall sslserv_expired
    killall sslserv_mutauth
    killall sslserv_ocsp_certchain
    killall sslserv_ocsp_missing_issuer
    killall sslserv_ocsp_revoked
    killall sslserv_ocsp_valid
    killall sslserv_srp
    killall sslserv_tls13
    killall sslserv_tls13_ocsp
    killall openssl

    echo "Starting..."
    cd $CURR_DIR/testaux

    make -f makefile_openssl_server run
    make -f makefile_sslserv_ocsp_responder run

    sleep 2
    (./sslserv &)
    (./sslserv_versionset &)
    (./sslserv_expired &)
    (./sslserv_mutauth &)
    (./sslserv_ocsp_certchain &)
    (./sslserv_ocsp_missing_issuer &)
    (./sslserv_ocsp_revoked &)
    (./sslserv_ocsp_valid &)
    (./sslserv_srp &)
    (./sslserv_tls13 &)
    (./sslserv_tls13_ocsp &)
    cd $CURR_DIR
    ;;
stop)
    echo "Stopping..."
    killall sslserv || true
    killall sslserv_versionset || true
    killall sslserv_expired || true
    killall sslserv_mutauth || true
    killall sslserv_ocsp_certchain || true
    killall sslserv_ocsp_missing_issuer || true
    killall sslserv_ocsp_revoked || true
    killall sslserv_ocsp_valid || true
    killall sslserv_srp || true
    killall sslserv_tls13 || true
    killall sslserv_tls13_ocsp || true
    killall openssl || true
    ;;
clean)
    echo "Cleaning..."
    clean_func
    ;;
build)
    echo "Building..."
    clean_func

    cd $CURR_DIR

    QS_ARG_PATH=$(printenv QS_PATH)

    if [ -z ${QS_ARG_PATH} ]; then
        echo "Building without QS";
    else
        echo "QS_PATH is ${QS_ARG_PATH}";
        QS_ARG="--oqs --oqs-path ${QS_ARG_PATH}"
    fi

    # Build the TAP local libraries
    ./build_tap_local.sh --gdb --tap-hybrid-sign ${QS_ARG}

    build_target CM_SSLSERV
    build_target CM_SSLSERV_EXPIRED
    build_target CM_SSLSERV_MUTAUTH
    build_target CM_SSLSERV_VERSIONSET
    build_target CM_SSLSERV_OCSP_CERTCHAIN
    build_target CM_SSLSERV_OCSP_MISSING_ISSUER
    build_target CM_SSLSERV_OCSP_REVOKED
    build_target CM_SSLSERV_OCSP_VALID
    build_target CM_SSLSERV_SRP
    build_target CM_SSLSERV_TLS13
    build_target CM_SSLSERV_TLS13_OCSP
    build_target CM_SSLCLIENT

    cp -r $CURR_DIR/../../src/ssl/testaux/ocsp_test_certs/ testaux/
    mkdir -p testaux/CA/newcerts
    cp $CURR_DIR/../../src/ssl/testaux/*der testaux
    cp $CURR_DIR/../../src/ssl/testaux/*pem testaux
    cp $CURR_DIR/certificates/* testaux
    cp $CURR_DIR/certificates/ca_rsa_cert.der testaux/ocsp_test_certs/ocsp_parent_cert.der
    cp $CURR_DIR/certificates/rsa_2048_signed_by_rsa_cert.der testaux/ocsp_test_certs/ocsp_leaf_cert.der
    cp $CURR_DIR/certificates/rsa_2048_signed_by_rsa_key.pem testaux/ocsp_test_certs/ocsp_leaf_key.pem
    ;;
esac
