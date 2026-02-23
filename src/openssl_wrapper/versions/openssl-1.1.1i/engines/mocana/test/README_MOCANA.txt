Overview
========
Folder ./thirdparty/openssl-1.1.1{X}/engines/mocana/test contains the test harness
to validate implementation of Mocana EVP engine for OpenSSL.

NOTE: EVP implementation was verified against OpenSSL v.1.1.1{X}


Building test harness
=====================
To build the Mocana test harness make sure OpenSSL libcrypto libraries build
successfully.

The test harness links against libcrypto.a and libnanocrypto.a which should be
located in ./openssl-1.1.1{X} folder:

    $ cd ./thirdparty/openssl-1.1.1{X}/
    $ cp ${PATH_TO_LIBS}/libcrypto.a .
    $ cp ${PATH_TO_LIBS}/libnanocrypto.a .

After that, try to build the test harness:

    $ cd ./thirdparty/openssl-1.1.1{X}/engines/mocana/test
    $ make -f Makefile.evptest all

To build the tests with Mocana's FIPS-certified library(libmss.so), ensure that
libmss.so and libmss.so.sig are in /usr/local/lib. The following command should be used
to build with this library:

    $ cd ./thirdparty/openssl-1.1.1{X}/engines/mocana/test
    $ make -f Makefile.evptest fips=true all

Running EVP tests
=================
A convenience script is provided which runs *all* included tests:

    $ cd ./thirdparty/openssl-1.1.1{X}/engines/mocana/test
    $ ./moc_evp_testall.sh

You can also compile and run a single test.
For example, to test MD5 Digest algorithm:

    $ gcc moc_evp_md5test.c -o moc_evp_md5test \ 
        -D__RTOS_LINUX__ -O0 -g -Wall -I../../../../openssl-1.1.1{X} \
        -I../../../../openssl-1.1.1{X}/include \
        -I../../../../../src ../../../libcrypto.a ../../../libnanocrypto.a \ 
        -lpthread -ldl

    $ ./moc_evp_md5test
