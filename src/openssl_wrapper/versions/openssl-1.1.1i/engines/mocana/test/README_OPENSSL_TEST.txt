Running OpenSSL EVP tests
=========================

OpenSSL test sources have been modified by Mocana to use the Mocana EVP
engine. The test source files are located in
`mss/thirdparty/openssl-1.1.1{X}/test` and they can be built through the OpenSSL
build setup.

Building
--------

To build the tests to run with the Mocana EVP engine use the top level scripts
located in mss/scripts/nanossl/openssl_connector

    cd mss
    ./scripts/nanossl/openssl_connector/build_openssl_connector_cap.sh --gdb --debug --openssl_1_1_1 --test

Testing
-------

Run the following commands to validate the EVP engine.

    cd mss/thirdparty/openssl-1.1.1{X}
    LD_LIBRARY_PATH=/absolute/path/to/mss/bin make cryptointerface=true test
