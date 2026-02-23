#!/bin/sh
export LD_LIBRARY_PATH=../../../../../bin

echo "*********************************************************************"
echo "Running EVP tests..."
echo 
echo "Executing 3DES tests..."
./moc_evp_3des_test
echo 
echo "*********************************************************************"
echo "Executing AES 128 tests..."
./moc_evp_aes_128_test
echo 
echo "*********************************************************************"
echo "Executing AES 192 tests..."
./moc_evp_aes_192_test
echo 
echo "*********************************************************************"
echo "Executing AES AEAD tests..."
./moc_evp_aes_aead_test
echo 
echo "*********************************************************************"
echo "Executing AES tests..."
./moc_evp_aes_test
echo
echo "*********************************************************************"
echo "Executing CHACHA20 tests..."
./moc_evp_chacha20_test
echo
echo "*********************************************************************"
echo "Executing CHACHA20_POLY1305 tests..."
./moc_evp_chacha20_poly1305_test
echo
echo "*********************************************************************"
echo "Executing cipher and digest tests..."
./moc_evp_ciphers_digest evptests_export.txt
echo 
echo "*********************************************************************"
echo "Executing DH Derive tests..."
./moc_evp_dh_derive_test
echo 
echo "*********************************************************************"
echo "Executing dh tests..."
./moc_evp_dh_test
echo
echo "*********************************************************************"
echo "Executing ecdh tests..."
./moc_evp_ecdh_test
echo
echo "*********************************************************************"
echo "Executing ECDSA tests..."
./moc_evp_ecdsa_test
echo 
echo "*********************************************************************"
echo "Executing EC KeyPair Generator test..."
./moc_evp_ec_keypair_gen
echo 
echo "*********************************************************************"
echo "Executing MD5 tests..."
./moc_evp_md5test
echo 
echo "*********************************************************************"
echo "Executing RSA DSA ECDSA test with RSA key..."
./moc_evp_rsa_dsa_ecdsa_test -p private.pem
./moc_evp_rsa_dsa_ecdsa_test -p private.pem -s
echo 
echo "Executing RSA DSA ECDSA test with EC key..."
./moc_evp_rsa_dsa_ecdsa_test -p ec_key.pem -s
echo 
echo "*********************************************************************"
echo "Executing RSA KeyPair Generator test..."
./moc_evp_rsa_keypair_gen_test

./moc_evp_rsa_keypair_gen_test -s
echo
echo "*********************************************************************"
echo "Executing RSA tests..."
./moc_evp_rsa_test
echo 
echo "*********************************************************************"
echo "Executing SHA1 tests..."
./moc_evp_sha1_test
echo 
echo "*********************************************************************"
echo "Executing SHA224 SHA256 tests..."
./moc_evp_sha224_256_test
echo 
echo "*********************************************************************"
echo "Executing SHA384 SHA512 tests..."
./moc_evp_sha384_512_test
echo 
echo "*********************************************************************"
echo "Executing HMAC tests..."
./moc_evp_hmac_test
echo 
echo "*********************************************************************"
echo "Executing copy tests..."
./moc_evp_copy_test
echo 
echo "*********************************************************************"
echo Done.
echo "*********************************************************************"
