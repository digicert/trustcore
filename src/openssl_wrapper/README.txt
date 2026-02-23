OpenSSL Compatibility Layer for NanoSSL
=======================================

This folder contains the implementation of the OpenSSL compatibility layer
for NanoSSL, the Mocana implementation of the SSL/TLS protocol. By providing
an OpenSSL compatibility layer, existing applications that use the OpenSSL APIs
can transparently use NanoSSL as the underlying SSL/TLS protocol implementation.

Such an application also uses the Mocana cryptographic library (NanoCrypto)
functions for symmetric and asymmetric ciphers, signatures, and message digests.
Mocana has validated the solution for both SSL server and client operational modes.

The Mocana OpenSSL compatibility solution is structured as four libraries:

    * libopenssl_shim encapsulates the OpenSSL compatibility API functions;
        it has no direct calls to libnanossl functions. Libopenssl_shim.so can
        be renamed and replace libssl.so, allowing the programs like python,
        httpd, wget to use the nanossl stack.

    * libnanossl is the Mocana native SSL/TLS library that provides an optimal
        implementation of the SSL/TLS protocol stack.

    * libcrypto includes the OpenSSL crypto code and the Mocana EVP engine glue
        layer (or shim).

    * libnanocrypto is the Mocana native crypto library that implements an
        extensive set of ciphers (e.g. aes_128_cbc), digests (e.g. SHA512),
        key-pair generators and public key algorithms (e.g. RSA).

The Mocana OpenSSL compatibility solution comprises of two layers:

    * OpenSSL compatibility layer
    * Mocana native library layer

The figure below represents relationships (dependency) between the libraries.

 +-------------------------------+
 |          Application          |
 +-------------------------------+
       |                  |
       v                  v
 +-------------+     +-----------+
 |   libssl    | --> | libcrypto |       OpenSSL compatibility layer
 +-------------+     +-----------+
       |                  |
**************************************** Open-source boundary *****************
       |                  |
       v                  |
 +--------------+         |              Mocana native library layer
 |  libnanossl  |         |
 +--------------+         |
       |                  |
       v                  v
 +------------------------------+
 |         libnanocrypto        |
 +------------------------------+

These two layers are bound through indirect function pointers that are
registered at library initialization time so that Mocana can improve libnanossl
and libnanocrypto over time without impacting OpenSSL compatibility.


Building OpenSSL Compatibility Layer for NanoSSL
================================================

1) Build 'libnanocrypto' and 'libcrypto' libraries.

    Perform the following steps to setup OpenSSL source tree, apply Mocana patches
    and build libnanocrypto and libcrypto libraries.

    Note: The commands below are given for openssl 1.0.2i, please modify accordingly
    for your desired version of OpenSSL (1.0.2i, 1.0.2k, 1.0.2l).

    a) Obtain OpenSSL distribution

        $ mkdir ${MOCANA_SOURCE_ROOT}/thirdparty
        $ cd ${MOCANA_SOURCE_ROOT}/thirdparty
        $ wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2i.tar.gz
        $ tar -xf openssl-1.0.2i.tar.gz

    b) Apply Mocana patch

        $ cd ${MOCANA_SOURCE_ROOT}/src/openssl_wrapper
        $ ./patch-openssl-1.0.2.sh openssl-1.0.2i_patch.tar.gz

    c) Build libnanocrypto and libcrypto libraries

        $ cd ${MOCANA_SOURCE_ROOT}/thirdparty/openssl-1.0.2i
        $ ./config
        $ make debug=true clean build_libs build-shared

        Note: If you have licensed Mocana NanoTAP product you can enable TPM support
        by adding 'tpm=true' flag to the command above.

        Note: If you have licensed Mocana's Suite B cryptography you can enable it
        by adding 'suiteb=true' flag to the command above.

    d) Copy generated libraries to the ./bin folder

        cd ${MOCANA_SOURCE_ROOT}/thirdparty/openssl-1.0.2i
        $ ./copy_to_mss_bin.sh -all

2) Build 'libnanossl' and 'libopenssl_shim' libraries.

    a) To generate shared (.so/.dylib) libraries:

        $ cd ${MOCANA_SOURCE_ROOT}
        $ make -f make/Makefile.ssl debug=true dtls=true openssl_shim=true clean nanossl openssl_shim

        Note: If you have licensed Mocana NanoTAP product you can enable TPM support
        by adding 'tpm=true' flag to the command above.

    b) To generate static (.a) libraries:

        $ cd ${MOCANA_SOURCE_ROOT}
        $ make -f make/Makefile.ssl debug=true dtls=true openssl_shim=true clean nanossl_static openssl_shim_static

        Note: If you have licensed Mocana NanoTAP product you can enable TPM support
        by adding 'tpm=true' flag to the command above.

    c) To generate a static (.a) library that includes both crypto and SSL:

        $ cd ${MOCANA_SOURCE_ROOT}
        $ make -f make/Makefile.ssl debug=true tpm=true clean nanossl_crypto_static
