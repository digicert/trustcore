!MESSAGE **** MOCANA EVP Test Windows MAKE file ****

################################################################################
# MACROS - Directory values 
#
################################################################################

MOC_SEP 		= 	^\
MOC_OSSL_TOP	=	..$(MOC_SEP)..$(MOC_SEP)..
MOCANA_BASE 	= 	$(MOC_OSSL_TOP)$(MOC_SEP)..$(MOC_SEP)..

################################################################################
# Macro definitions - Build command related variables
#
################################################################################

MOC_CC 					= cl
MOC_INCLUDES 			= /I$(MOC_OSSL_TOP) /I$(MOC_OSSL_TOP)$(MOC_SEP)inc32 /I$(MOC_OSSL_TOP)$(MOC_SEP)include /I$(MOC_OSSL_TOP)$(MOC_SEP)crypto$(MOC_SEP)include /I..$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)src
!IF "$(gdb)" == "true"
MOC_DEBUG_FLAG = d
!ELSE
MOC_DEBUG_FLAG =
!ENDIF

!IF "$(static)" == "true"
MOC_PLATFORM_CFLAGS 	= /MT$(MOC_DEBUG_FLAG) -D__RTOS_WIN32__ -D__ENABLE_DIGICERT_WIN_STUDIO_BUILD__ -DWIN32_LEAN_AND_MEAN
!ELSE
MOC_PLATFORM_CFLAGS 	= /MD$(MOC_DEBUG_FLAG) -D__RTOS_WIN32__ -D__ENABLE_DIGICERT_WIN_STUDIO_BUILD__ -DWIN32_LEAN_AND_MEAN
!ENDIF
#-DWIN32 -D_WINDOWS
MOC_CFLAGS				= $(MOC_INCLUDES) $(MOC_PLATFORM_CFLAGS) -DOPENSSL_ENGINE 
#-O0 -Wall 
MOC_DEBUG_CFLAGS		= /Zi

MOC_LINK				= link

!IF "$(static)" == "true"
MOC_LINK_LIBS			= libcrypto.lib nanocrypto.lib asn1.lib common.lib cryptointerface.lib initialize.lib nanocap.lib nanocert.lib nanocrypto.lib platform.lib crypt32.lib User32.lib GDI32.lib Advapi32.lib Ws2_32.lib
!ELSE
MOC_LINK_LIBS			= libcrypto.lib nanocrypto.lib 
!ENDIF
MOC_LINK_LIBS_EXPORT	= libcrypto.lib cryptomw.lib 
!IF "$(export)" == "true"
MOC_LINK_LIBS = $(MOC_LINK_LIBS_EXPORT)
MOC_CFLAGS = $(MOC_CFLAGS) -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ -D__DISABLE_AES_CCM__ -D__DISABLE_AES_XTS__
!ENDIF
#Ws2_32.lib ShlWapi.lib Shell32.lib
!IF "$(static)" == "true"
MOC_LDFLAGS				= /LIBPATH:$(MOC_OSSL_TOP)$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)bin_win32_static
!ELSE
MOC_LDFLAGS				= /LIBPATH:$(MOC_OSSL_TOP)$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)bin_win32
!ENDIF
MOC_DEBUG_LDFLAGS		= /DEBUG

!IF "$(static)" == "true"
OSSL_TMP_D				= tmp32
!ELSE
OSSL_TMP_D				= tmp32dll
!ENDIF
OSSL_CFLAG_INC			= -Iinc32 -I$(OSSL_TMP_D)

################################################################################
# Parse input arguments and set flags appropriately
#
################################################################################

# set tpm=true on command line to enable TPM1.2 support
!IF "$(tpm)" == "true"
  !MESSAGE "Enabling TPM support"
  MOC_CFLAGS = $(MOC_CFLAGS) -D__ENABLE_DIGICERT_TPM__ -D__ENABLE_DIGICERT_HW_SECURITY_MODULE__
!ENDIF

# set tap=true on command line to enable TAP support
!IF "$(tap)" == "true"
!MESSAGE Enabling TAP support
MOC_CFLAGS = $(MOC_CFLAGS) -D__ENABLE_DIGICERT_TAP__ -D__ENABLE_DIGICERT_CRYPTO_INTERFACE__ -D__ENABLE_DIGICERT_SMP__
MOC_LINK_LIBS = $(MOC_LINK_LIBS) initialize.lib common.lib cryptointerface.lib nanotap2.lib nanotap2_common.lib nanotap2_configparser.lib smptpm2.lib tpm2.lib
!ENDIF

!IF "$(tap_remote)" == "true"
  !MESSAGE "Enabling TAP Remote support"
  MOC_CFLAGS = $(MOC_CFLAGS) -D__ENABLE_TAP_REMOTE__
!ENDIF

!IF "$(emulator)" == "true"
   MOC_CFLAGS = $(MOC_CFLAGS) -D__ENABLE_DIGICERT_TPM_EMULATOR__
!ENDIF

!IF "$(dbgdump)" == "true"
 	MOCANA_DEBUG_FLAGS = $(MOCANA_DEBUG_FLAGS) -D__ENABLE_DIGICERT_DEBUG_MEMORY__
!ENDIF

!IF "$(suiteb)" == "false"
   MOC_CFLAGS = $(MOC_CFLAGS) -D__DISABLE_DIGICERT_SUITE_B__
!ENDIF

!IF "$(fips)" == "true"
!IF "$(static)" == "true"
MOC_LDFLAGS = $(MOC_LDFLAGS) /LIBPATH:$(MOC_OSSL_TOP)$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)bin_win32_static libmss.lib
!ELSE
MOC_LDFLAGS = $(MOC_LDFLAGS) /LIBPATH:$(MOC_OSSL_TOP)$(MOC_SEP)..$(MOC_SEP)..$(MOC_SEP)bin_win32 libmss.lib
!ENDIF
MOC_CFLAGS  = $(MOC_CFLAGS) -D__EVP_NAMESPACE_CONFLICT__
!ENDIF

MOC_CFLAGS = $(MOC_CFLAGS) $(MOC_DEBUG_CFLAGS)
MOC_LDFLAGS = $(MOC_LDFLAGS) $(MOC_LINK_LIBS) $(MOC_DEBUG_LDFLAGS)

OSSL_TEST_APP_CFLAGS = $(OSSL_CFLAG_INC) -DOPENSSL_THREADS  -DDSO_WIN32 -DOPENSSL_SYSNAME_WIN32 -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DUNICODE -D_UNICODE -D_CRT_SECURE_NO_DEPRECATE -DOPENSSL_USE_APPLINK -DOPENSSL_NO_RC5 -DOPENSSL_NO_MD2 -DOPENSSL_NO_SSL2 -DOPENSSL_NO_KRB5 -DOPENSSL_NO_JPAKE -DOPENSSL_NO_WEAK_SSL_CIPHERS -DOPENSSL_NO_STATIC_ENGINE $(MOC_PLATFORM_CFLAGS) $(MOC_DEBUG_CFLAGS)

################################################################################
#  SRC DIR variables
#
################################################################################
MOCANA_COMMON_DIR	= $(MOCANA_BASE)$(MOC_SEP)src$(MOC_SEP)common
MOC_OBJ_DIR			= .

################################################################################
# Compile rule
#
################################################################################

.c.obj::  
	$(MOC_CC) /Fo$(MOC_OBJ_DIR)$(MOC_SEP) $(MOC_CFLAGS) /c $<

{$(MOCANA_COMMON_DIR)\}.c{$(MOC_OBJ_DIR)\}.obj::
	$(MOC_CC) /Fo$(MOC_OBJ_DIR)$(MOC_SEP) $(MOC_CFLAGS) /c $<

# for compiling ms\applink.c
{$(MOC_OSSL_TOP)\ms\}.c{$(MOC_OBJ_DIR)\}.obj::
	$(MOC_CC) /Fo$(MOC_OBJ_DIR)$(MOC_SEP) $(OSSL_TEST_APP_CFLAGS) -c $<

################################################################################
# Compile targets for test
#
################################################################################

TEST_3DES= moc_evp_3des_test
TEST_AES_128= moc_evp_aes_128_test
TEST_AES_192= moc_evp_aes_192_test
TEST_AES_AEAD= moc_evp_aes_aead_test
TEST_AES= moc_evp_aes_test
TEST_CHACHA20= moc_evp_chacha20_test
TEST_CHACHAPOLY= moc_evp_chacha20_poly1305_test
TEST_CIPHER_DIGEST= moc_evp_ciphers_digest
TEST_DES= moc_evp_des_test
TEST_DH_DERIVE= moc_evp_dh_derive_test
TEST_DH= moc_evp_dh_test
TEST_DSA_KEYPAIR_GEN= moc_evp_dsa_keypair_gen
TEST_DSA= moc_evp_dsa_test
TEST_ECDH= moc_evp_ecdh_test
TEST_ECDSA= moc_evp_ecdsa_test
TEST_EC_KEYPAIR_GEN= moc_evp_ec_keypair_gen
TEST_MD2= moc_evp_md2_test
TEST_MD4= moc_evp_md4_test
TEST_MD5= moc_evp_md5test
TEST_RC4= moc_evp_rc4_test
TEST_TPM_PEM= moc_evp_rsa_dsa_ecdsa_test
TEST_RSA_KEYPAIR_GEN= moc_evp_rsa_keypair_gen_test
TEST_RSA= moc_evp_rsa_test
TEST_SHA1= moc_evp_sha1_test
TEST_SHA224_256= moc_evp_sha224_256_test
TEST_SHA384_512= moc_evp_sha384_512_test
TEST_HMAC= moc_evp_hmac_test
TEST_FIPS_VERSION= moc_evp_fips_version_test

OSSL_TEST_APP_DEP = 

MOC_COMMON_TEST_OBJ = 

build_all: \
$(TEST_3DES).exe \
$(TEST_AES_128).exe \
$(TEST_AES_192).exe \
$(TEST_AES_AEAD).exe \
$(TEST_AES).exe \
$(TEST_CHACHA20).exe \
$(TEST_CHACHAPOLY).exe \
$(TEST_CIPHER_DIGEST).exe \
$(TEST_DES).exe \
$(TEST_DH_DERIVE).exe \
$(TEST_ECDSA).exe \
$(TEST_RC4).exe \
$(TEST_TPM_PEM).exe \
$(TEST_RSA_KEYPAIR_GEN).exe \
$(TEST_RSA).exe \
$(TEST_SHA224_256).exe \
$(TEST_SHA384_512).exe \
$(TEST_HMAC).exe \
$(TEST_DH).exe \
$(TEST_DSA_KEYPAIR_GEN).exe \
$(TEST_DSA).exe \
$(TEST_ECDH).exe \
$(TEST_EC_KEYPAIR_GEN).exe \
$(TEST_MD2).exe \
$(TEST_MD4).exe \
$(TEST_MD5).exe \
!IF "$(fips)" == "true"
$(TEST_FIPS_VERSION).exe \
!ENDIF
$(TEST_SHA1).exe 

clean: 
	del /s /q \
	$(TEST_3DES).obj $(TEST_3DES).pdb $(TEST_3DES).ilk $(TEST_3DES).exp $(TEST_3DES).exe \
	$(TEST_AES_128).obj $(TEST_AES_128).pdb $(TEST_AES_128).ilk $(TEST_AES_128).exp $(TEST_AES_128).exe \
	$(TEST_AES_192).obj $(TEST_AES_192).pdb $(TEST_AES_192).ilk $(TEST_AES_192).exp $(TEST_AES_192).exe \
	$(TEST_AES_AEAD).obj $(TEST_AES_AEAD).pdb $(TEST_AES_AEAD).ilk $(TEST_AES_AEAD).exp $(TEST_AES_AEAD).exe \
	$(TEST_AES).obj $(TEST_AES).pdb $(TEST_AES).ilk $(TEST_AES).exp $(TEST_AES).exe \
	$(TEST_CHACHA20).obj $(TEST_CHACHA20).pdb $(TEST_CHACHA20).ilk $(TEST_CHACHA20).exp $(TEST_CHACHA20).exe \
	$(TEST_CHACHAPOLY).obj $(TEST_CHACHAPOLY).pdb $(TEST_CHACHAPOLY).ilk $(TEST_CHACHAPOLY).exp $(TEST_CHACHAPOLY).exe \
	$(TEST_CIPHER_DIGEST).obj $(TEST_CIPHER_DIGEST).pdb $(TEST_CIPHER_DIGEST).ilk $(TEST_CIPHER_DIGEST).exp $(TEST_CIPHER_DIGEST).exe \
	$(TEST_DES).obj $(TEST_DES).pdb $(TEST_DES).ilk $(TEST_DES).exp $(TEST_DES).exe \
	$(TEST_DH_DERIVE).obj $(TEST_DH_DERIVE).pdb $(TEST_DH_DERIVE).ilk $(TEST_DH_DERIVE).exp $(TEST_DH_DERIVE).exe \
	$(TEST_ECDSA).obj $(TEST_ECDSA).pdb $(TEST_ECDSA).ilk $(TEST_ECDSA).exp $(TEST_ECDSA).exe \
	$(TEST_RC4).obj $(TEST_RC4).pdb $(TEST_RC4).ilk $(TEST_RC4).exp $(TEST_RC4).exe \
	$(TEST_TPM_PEM).obj $(TEST_TPM_PEM).pdb $(TEST_TPM_PEM).ilk $(TEST_TPM_PEM).exp $(TEST_TPM_PEM).exe \
	$(TEST_RSA_KEYPAIR_GEN).obj $(TEST_RSA_KEYPAIR_GEN).pdb $(TEST_RSA_KEYPAIR_GEN).ilk $(TEST_RSA_KEYPAIR_GEN).exp $(TEST_RSA_KEYPAIR_GEN).exe \
	$(TEST_RSA).obj $(TEST_RSA).pdb $(TEST_RSA).ilk $(TEST_RSA).exp $(TEST_RSA).exe \
	$(TEST_SHA224_256).obj $(TEST_SHA224_256).pdb $(TEST_SHA224_256).ilk $(TEST_SHA224_256).exp $(TEST_SHA224_256).exe \
	$(TEST_SHA384_512).obj $(TEST_SHA384_512).pdb $(TEST_SHA384_512).ilk $(TEST_SHA384_512).exp $(TEST_SHA384_512).exe \
	$(TEST_HMAC).obj $(TEST_HMAC).pdb $(TEST_HMAC).ilk $(TEST_HMAC).exp $(TEST_HMAC).exe \
	$(TEST_DH).obj $(TEST_DH).pdb $(TEST_DH).ilk $(TEST_DH).exp $(TEST_DH).exe \
	$(TEST_DSA_KEYPAIR_GEN).obj $(TEST_DSA_KEYPAIR_GEN).pdb $(TEST_DSA_KEYPAIR_GEN).ilk $(TEST_DSA_KEYPAIR_GEN).exp $(TEST_DSA_KEYPAIR_GEN).exe \
	$(TEST_DSA).obj $(TEST_DSA).pdb $(TEST_DSA).ilk $(TEST_DSA).exp $(TEST_DSA).exe \
	$(TEST_ECDH).obj $(TEST_ECDH).pdb $(TEST_ECDH).ilk $(TEST_ECDH).exp $(TEST_ECDH).exe \
	$(TEST_EC_KEYPAIR_GEN).obj $(TEST_EC_KEYPAIR_GEN).pdb $(TEST_EC_KEYPAIR_GEN).ilk $(TEST_EC_KEYPAIR_GEN).exp $(TEST_EC_KEYPAIR_GEN).exe \
	$(TEST_MD2).obj $(TEST_MD2).pdb $(TEST_MD2).ilk $(TEST_MD2).exp $(TEST_MD2).exe \
	$(TEST_MD4).obj $(TEST_MD4).pdb $(TEST_MD4).ilk $(TEST_MD4).exp $(TEST_MD4).exe \
	$(TEST_MD5).obj $(TEST_MD5).pdb $(TEST_MD5).ilk $(TEST_MD5).exp $(TEST_MD5).exe \
	$(TEST_SHA1).obj $(TEST_SHA1).pdb $(TEST_SHA1).ilk $(TEST_SHA1).exp $(TEST_SHA1).exe \
	$(TEST_FIPS_VERSION).obj $(TEST_FIPS_VERSION).pdb $(TEST_FIPS_VERSION).ilk $(TEST_FIPS_VERSION).exp $(TEST_FIPS_VERSION).exe \
	$(OSSL_TEST_APP_DEP) $(MOC_COMMON_TEST_OBJ)

all: clean build_all

$(TEST_3DES).exe: $(TEST_3DES).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS) $(TEST_3DES).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_AES_128).exe:  $(TEST_AES_128).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_AES_128).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_AES_192).exe:  $(TEST_AES_192).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_AES_192).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_AES_AEAD).exe:  $(TEST_AES_AEAD).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_AES_AEAD).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_AES).exe:  $(TEST_AES).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_AES).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_CHACHA20).exe:  $(TEST_CHACHA20).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_CHACHA20).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_CHACHAPOLY).exe:  $(TEST_CHACHAPOLY).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_CHACHAPOLY).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_CIPHER_DIGEST).exe:  $(TEST_CIPHER_DIGEST).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_CIPHER_DIGEST).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_DES).exe:  $(TEST_DES).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_DES).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_DH_DERIVE).exe:  $(TEST_DH_DERIVE).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_DH_DERIVE).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_DH).exe:  $(TEST_DH).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_DH).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP) libcrypto.lib

$(TEST_DSA_KEYPAIR_GEN).exe:  $(TEST_DSA_KEYPAIR_GEN).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS) $(TEST_DSA_KEYPAIR_GEN).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)

$(TEST_DSA).exe:  $(TEST_DSA).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_DSA).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP) libcrypto.lib

$(TEST_ECDH).exe:  $(TEST_ECDH).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_ECDH).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP) libcrypto.lib

$(TEST_ECDSA).exe:  $(TEST_ECDSA).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_ECDSA).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP) libcrypto.lib

$(TEST_EC_KEYPAIR_GEN).exe:  $(TEST_EC_KEYPAIR_GEN).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_EC_KEYPAIR_GEN).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib 

$(TEST_MD2).exe:  $(TEST_MD2).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_MD2).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_MD4).exe:  $(TEST_MD4).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_MD4).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_MD5).exe:  $(TEST_MD5).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_MD5).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_RC4).exe:  $(TEST_RC4).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_RC4).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_TPM_PEM).exe:  $(TEST_TPM_PEM).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS) $(TEST_TPM_PEM).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP) 

$(TEST_RSA_KEYPAIR_GEN).exe:  $(TEST_RSA_KEYPAIR_GEN).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP)
	$(MOC_LINK) $(MOC_LDFLAGS) $(TEST_RSA_KEYPAIR_GEN).obj $(MOC_COMMON_TEST_OBJ) $(OSSL_TEST_APP_DEP) 

$(TEST_RSA).exe:  $(TEST_RSA).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_RSA).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_SHA1).exe:  $(TEST_SHA1).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_SHA1).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_SHA224_256).exe:  $(TEST_SHA224_256).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_SHA224_256).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_SHA384_512).exe:  $(TEST_SHA384_512).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_SHA384_512).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_HMAC).exe:  $(TEST_HMAC).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_HMAC).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib

$(TEST_FIPS_VERSION).exe:  $(TEST_FIPS_VERSION).obj $(MOC_COMMON_TEST_OBJ)
	$(MOC_LINK) $(MOC_LDFLAGS)  $(TEST_FIPS_VERSION).obj $(MOC_COMMON_TEST_OBJ) libcrypto.lib
