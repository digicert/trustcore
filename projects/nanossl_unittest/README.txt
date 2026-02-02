NanoSSL Unittest Framework
==========================

This guide covers running the NanoSSL unittests. All test server binaries are
output into the testaux directory and the client binary is output into the test
directory.

Build
-----

The build is driven through the build target in test.sh

    ./test.sh build

        This target builds all of the servers and clients required for running
        the tests. This should be the first target to run.

NOTE: Please ensure the mss/bin directory does not contain any *.so files. CMake
attempts to link against libraries in the bin directory so it must be clean
before running the build target.

Run
---

The test is driven through the start target in test.sh

    ./test.sh start

        This target starts the servers. Note that this target also takes care
        of the appropriate setup required for the test monkey such as setting up
        directories and invoking the appropriate commands to generate
        certificates, keys, etc. Note that tests can be run multiple times
        without rebuilding. If this is the first time the start target is used
        for a clean setup then all setup files are generated. If the setup files
        already exist then the existing setup files are used.

Once the servers are up the client can be invoked through the following commands

    cd test
    ./ssl_client

This will launch the test client to connect to the Test Monkey servers.

Cleanup
-------

The stop target is used to stop servers that are occupying a port.

    ./test.sh stop

        This target stops all the test servers. After the tests are done running
        the servers will still be running and occupying a port. Run this target
        to stop the servers from listening on a port.

The clean target is used to cleanup the unittest directory

    ./test.sh clean

        This target removes all test binaries and setup files.

OCSP Testing
------------

1. Ensure the following files exist

    testaux/ocsp_test_certs/ocsp_parent_cert.der
    testaux/ocsp_test_certs/ocsp_leaf_cert.der
    testaux/ocsp_test_certs/ocsp_leaf_key.der

2. Start OCSP server

    $ cd testaux
    $ ./sslserv_tls13_ocsp

3. Run OCSP client

    $ cd test
    $ ENABLE_TLS13_TESTS=1 ./ssl_client ssl_cli_tls13_test_ocsp