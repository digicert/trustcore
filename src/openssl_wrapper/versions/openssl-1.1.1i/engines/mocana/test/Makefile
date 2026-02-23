# Set the include directory
override CFLAGS+=-g -O0  -Wall -I../../../include -I../../.. -I../../../crypto/include

# Set the LD_LIBRARY_PATH
export LD_LIBRARY_PATH:=${LD_LIBRARY_PATH}:../../../../../bin

# Set the libraries to link against
LDFLAGS+=-L../../.. -lssl -lcrypto

ifeq ($(dynamic_engine),true)
	override CFLAGS+=-D__ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__
endif

# Flags for export
ifeq ($(export),true)
	override CFLAGS+=-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ -D__DISABLE_AES_CCM__ -D__DISABLE_AES_XTS__
endif

# Get all the sample sources
SRC=$(wildcard *.c)

TEST_SCRIPT=test.sh

# Function for adding tests to test script
define add_test
	echo "echo '*************************************************'" >> ${TEST_SCRIPT}
	echo "echo 'Executing $(2) tests...'" >> ${TEST_SCRIPT}
	echo "echo ''" >> ${TEST_SCRIPT}
	echo "$(1)" >> ${TEST_SCRIPT}
	echo "echo ''" >> ${TEST_SCRIPT}
	echo "echo 'Finished $(2) tests.'" >> ${TEST_SCRIPT}
endef

# Get all the sample targets
TARGETS=$(SRC:.c=)

all: $(TARGETS)
	@> ${TEST_SCRIPT}
	@echo "#!/bin/bash" >> ${TEST_SCRIPT}
	@echo "export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:../../../../../bin" >> ${TEST_SCRIPT}
	@$(call add_test,./moc_evp_3des_test,3DES)
	@$(call add_test,./moc_evp_aes_128_test,AES 128)
	@$(call add_test,./moc_evp_aes_192_test,AES 192)
	@$(call add_test,./moc_evp_aes_aead_test,AES AEAD)
	@$(call add_test,./moc_evp_aes_test,AES)
	@$(call add_test,./moc_evp_chacha20_test,CHACHA20)
	@$(call add_test,./moc_evp_chacha20_poly1305_test,CHACHA20_POLY1305)
ifeq ($(export),true)
	@$(call add_test,./moc_evp_ciphers_digest evptests_export.txt,cipher and digest)
else
	@$(call add_test,./moc_evp_ciphers_digest evptests.txt,cipher and digest)
endif
ifneq ($(export),true)
	@$(call add_test,./moc_evp_des_test,DES)
	@$(call add_test,./moc_evp_dsa_keypair_gen,DSA KeyPair Generator)
	@$(call add_test,./moc_evp_dsa_test,DSA)
	@$(call add_test,./moc_evp_md2_test,MD2)
	@$(call add_test,./moc_evp_md4_test,MD4)
	@$(call add_test,./moc_evp_rc2_test,RC2)
	@$(call add_test,./moc_evp_rc4_test,RC4)
	@$(call add_test,./moc_evp_rc5_test,RC5)
endif
	@$(call add_test,./moc_evp_dh_derive_test,DH Derive)
	@$(call add_test,./moc_evp_dh_test,dh)
	@$(call add_test,./moc_evp_ecdh_test,ecdh)
	@$(call add_test,./moc_evp_ecdsa_test,ECDSA)
	@$(call add_test,./moc_evp_ec_keypair_gen,EC KeyPair Generator)
	@$(call add_test,./moc_evp_md5test,MD5)
	@$(call add_test,./moc_evp_rsa_dsa_ecdsa_test -p private.pem,RSA key)
	@$(call add_test,./moc_evp_rsa_dsa_ecdsa_test -p private.pem -s,RSA key)
	@$(call add_test,./moc_evp_rsa_dsa_ecdsa_test -p ec_key.pem -s,EC key)
	@$(call add_test,./moc_evp_rsa_keypair_gen_test,RSA KeyPair Generator)
	@$(call add_test,./moc_evp_rsa_keypair_gen_test -s,RSA KeyPair Generator)
	@$(call add_test,./moc_evp_rsa_test,RSA)
	@$(call add_test,./moc_evp_sha1_test,SHA1)
	@$(call add_test,./moc_evp_sha224_256_test,SHA224 SHA256)
	@$(call add_test,./moc_evp_sha384_512_test,SHA384 SHA512)
	@$(call add_test,./moc_evp_hmac_test,HMAC)
	@echo "echo '*************************************************'" >> ${TEST_SCRIPT}
	@echo "echo 'Done.'" >> ${TEST_SCRIPT}
	@chmod +x ${TEST_SCRIPT}
	@echo "Execute ./${TEST_SCRIPT} to run EVP tests"

$(TARGETS):
	$(CC) -o $@ $@.c $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGETS)
