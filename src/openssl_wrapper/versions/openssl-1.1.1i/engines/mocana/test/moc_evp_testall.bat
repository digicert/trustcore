@echo OFF
echo "*********************************************************************"
echo "Running EVP tests..."
echo 
echo "Executing 3DES tests..."
moc_evp_3des_test.exe
echo 
echo "*********************************************************************"
echo "Executing AES 128 tests..."
moc_evp_aes_128_test.exe
echo 
echo "*********************************************************************"
echo "Executing AES 192 tests..."
moc_evp_aes_192_test.exe
echo 
echo "*********************************************************************"
echo "Executing AES AEAD tests..."
moc_evp_aes_aead_test.exe
echo 
echo "*********************************************************************"
echo "Executing AES tests..."
moc_evp_aes_test.exe
echo 
echo "*********************************************************************"
echo "Executing cipher and digest tests..."
moc_evp_ciphers_digest.exe evptests.txt
echo 
echo "*********************************************************************"
echo "Executing DES tests..."
moc_evp_des_test.exe
echo 
echo "*********************************************************************"
echo "Executing DH Derive tests..."
moc_evp_dh_derive_test.exe
echo 
echo "*********************************************************************"
echo "Executing dh tests..."
moc_evp_dh_test.exe
echo
echo "*********************************************************************"
echo "Executing DSA KeyPair Generator test..."
moc_evp_dsa_keypair_gen.exe
echo
echo "*********************************************************************"
echo "Executing DSA tests..."
moc_evp_dsa_test.exe
echo 
echo "*********************************************************************"
echo "Executing ecdh tests..."
moc_evp_ecdh_test.exe
echo
echo "*********************************************************************"
echo "Executing ECDSA tests..."
moc_evp_ecdsa_test.exe
echo 
echo "*********************************************************************"
echo "Executing EC KeyPair Generator test..."
moc_evp_ec_keypair_gen.exe
echo
echo "*********************************************************************"
echo "Executing MD2 tests..."
moc_evp_md2_test.exe
echo
echo "*********************************************************************"
echo "Executing MD4 tests..."
moc_evp_md4_test.exe
echo 
echo "*********************************************************************"
echo "Executing MD5 tests..."
moc_evp_md5test.exe
echo 
echo "*********************************************************************"
echo "Executing RC4 tests..."
moc_evp_rc4_test.exe
echo 
echo "*********************************************************************"
echo "Executing RSA DSA ECDSA test with RSA key..."
moc_evp_rsa_dsa_ecdsa_test.exe -p private.pem
moc_evp_rsa_dsa_ecdsa_test.exe -p private.pem -s
echo 
echo "Executing RSA DSA ECDSA test with EC key..."
moc_evp_rsa_dsa_ecdsa_test.exe -p ec_key.pem -s
echo 
echo "*********************************************************************"
echo "Executing RSA KeyPair Generator test..."
moc_evp_rsa_keypair_gen_test.exe
echo
echo "*********************************************************************"
echo "Executing RSA tests..."
moc_evp_rsa_test.exe
echo 
echo "*********************************************************************"
echo "Executing SHA1 tests..."
moc_evp_sha1_test.exe
echo 
echo "*********************************************************************"
echo "Executing SHA224 SHA256 tests..."
moc_evp_sha224_256_test.exe
echo 
echo "*********************************************************************"
echo "Executing SHA384 SHA512 tests..."
moc_evp_sha384_512_test.exe
echo 
echo "*********************************************************************"
echo "Executing HMAC tests..."
moc_evp_hmac_test.exe
echo 
echo "*********************************************************************"
echo Done.
echo "*********************************************************************"
