Overview
========
Folder ./thirdparty/openssl-1.1.1{X}/engines/mocana/test contains the test harness
to validate implementation of Mocana EVP engine for OpenSSL.

NOTE: EVP implementation was verified against OpenSSL v.1.1.1{X}


Building test harness
=====================
To build the Mocana test harness make sure OpenSSL libraries built
successfully.

The test harness links against libeay32.lib, libnanocrypto.lib
libraries which should be located in PATH value:
    Ensure that the PATH environment variable is appropriately updated to
    contain these values: 
        > "<ossl_install_path>\bin"
        > "<ossl_install_path>\lib\engines"

After that, try to build the test harness:

    $ cd ./thirdparty/openssl-1.1.1{X}/engines/mocana/test
    $ nmake -f evptest.mak 

    [TODO - to add fips support for windows build and test]

Running EVP tests
=================
A convenience script is provided which runs *all* included tests:

    $ cd ./thirdparty/openssl-1.1.1{X}/engines/mocana/test
    $ moc_evp_testall.bat

