This test is for linux at this moment. You must have ruby and cproto installed. For example...

sudo apt-get install cproto

To build run

./build.sh

Some build options for this script may be unavailable at the moment for this open source test. Once the intel_aes_ni folder is available...

The --ni option builds AES with the Intel “new instruction” set (ie assembly code). 
FIRST you must build intel_aes_ni.a by running make in the mocn-mss/src/crypto/intel_aes_ni folder.

To build with mbedtls comparisons for big integer arithmetic, add the --mbedtls option to the build.sh script.
FIRST you must build libmbedcrypto.so, and place this in the mocn-mss/bin folder, and place the mbedtls 
headers in a /usr/local/include/mbedtls folder.

To build with openssl comparisons for some ciphers, add the --openssl option to the build.sh script.
FIRST you must build openssl3.0 with the methods ossl_bn_rsa_fips186_4_gen_prob_primes and
ossl_rsa_sp800_56b_generate_key exposed. Add these methods to the global: list in libcrypto.ld file in
the home openssl folder. You may or may not have to add __attribute__((visibility("default"))) and/or 
extern to the declaration and/or definitions of those two methods. Then also make sure openssl is
installed with libcrypto.so in /usr/local/lib and the headers with /usr/local/include/ and also
libcrypto.so in mocn-mss/bin. You may need to run the test executable with LD_LIBRARY_PATH=<path to bin>

To build with pqc tests add the --cryptointerface option. The other tests will also now go through the
crypto interface too but the impact on the timing numbers should be trivial.
