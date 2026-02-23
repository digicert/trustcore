/*
 * digiprov.c
 *
 * Provider for OSSL 3.0
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mocana.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/sha256.h"
#include "mocana_glue.h"

#include "openssl/evp.h"
#include "prov/names.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/params.h"
#include "openssl/objects.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "prov/seeding.h"
#include "prov/bio.h"
#include "crypto/evp.h"
#include "../crypto/evp/evp_local.h"
#include "digiprov.h"

/* Certain applications may not initialize the provider before using them. This
 * flag makes it so the provider is always "initialized" even if the application
 * hasn't made the initialization call. */
#ifndef DIGIPROV_NO_AUTO_INIT
#define DIGIPROV_ALWAYS_INITIALIZED
#endif

int moc_init_ex_app_data(OSSL_LIB_CTX *pLibCtx);
void moc_clear_ex_app_data(void);

static const char prov_name_fips[] = "provider=digi,fips=yes";
static const char prov_name_no_fips[] = "provider=digi,fips=no";

static const OSSL_ALGORITHM digiprov_digests[] = {
    { PROV_NAMES_MD4, prov_name_no_fips, digiprov_md4_functions },
    { PROV_NAMES_MD5, prov_name_fips, digiprov_md5_functions },
    { PROV_NAMES_SHA1, prov_name_fips, digiprov_sha1_functions },
    { PROV_NAMES_SHA2_224, prov_name_fips, digiprov_sha224_functions },
    { PROV_NAMES_SHA2_256, prov_name_fips, digiprov_sha256_functions },
    { PROV_NAMES_SHA2_384, prov_name_fips, digiprov_sha384_functions },
    { PROV_NAMES_SHA2_512, prov_name_fips, digiprov_sha512_functions },
    { PROV_NAMES_SHA3_224, prov_name_fips, digiprov_sha3_224_functions },
    { PROV_NAMES_SHA3_256, prov_name_fips, digiprov_sha3_256_functions },
    { PROV_NAMES_SHA3_384, prov_name_fips, digiprov_sha3_384_functions },
    { PROV_NAMES_SHA3_512, prov_name_fips, digiprov_sha3_512_functions },
    { PROV_NAMES_SHAKE_128, prov_name_fips, digiprov_shake_128_functions },
    { PROV_NAMES_SHAKE_256, prov_name_fips, digiprov_shake_256_functions },
    { PROV_NAMES_BLAKE2S_256, prov_name_fips, digiprov_blake2s256_functions },
    { PROV_NAMES_BLAKE2B_512, prov_name_fips, digiprov_blake2b512_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_macs[] = {
    { PROV_NAMES_HMAC, prov_name_fips, digiprov_hmac_functions },
#ifndef OPENSSL_NO_BLAKE2
    { PROV_NAMES_BLAKE2BMAC, prov_name_fips, digiprov_blake2bmac_functions },
    { PROV_NAMES_BLAKE2SMAC, prov_name_fips, digiprov_blake2smac_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, prov_name_fips, digiprov_cmac_functions },
#endif
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_POLY1305, prov_name_fips, digiprov_poly1305_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_kdf_algos[] = {
    { PROV_NAMES_KBKDF, prov_name_fips, digiprov_nist_kdf_functions},
    { PROV_NAMES_HKDF, prov_name_fips, digiprov_hmac_kdf_functions},
    { PROV_NAMES_X963KDF, prov_name_fips, digiprov_x963_kdf_functions},
    { PROV_NAMES_PBKDF1, prov_name_fips, digiprov_pbkdf1_functions },
    { PROV_NAMES_PBKDF2, prov_name_fips, digiprov_pbkdf2_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_cipher_algos[] = {
    { PROV_NAMES_AES_128_CBC, prov_name_fips, digiprov_aes128cbc_functions},
    { PROV_NAMES_AES_192_CBC, prov_name_fips, digiprov_aes192cbc_functions},
    { PROV_NAMES_AES_256_CBC, prov_name_fips, digiprov_aes256cbc_functions},
    { PROV_NAMES_AES_128_ECB, prov_name_fips, digiprov_aes128ecb_functions},
    { PROV_NAMES_AES_192_ECB, prov_name_fips, digiprov_aes192ecb_functions},
    { PROV_NAMES_AES_256_ECB, prov_name_fips, digiprov_aes256ecb_functions},
    { PROV_NAMES_AES_128_OFB, prov_name_fips, digiprov_aes128ofb_functions},
    { PROV_NAMES_AES_192_OFB, prov_name_fips, digiprov_aes192ofb_functions},
    { PROV_NAMES_AES_256_OFB, prov_name_fips, digiprov_aes256ofb_functions},
    { PROV_NAMES_AES_128_CFB, prov_name_fips, digiprov_aes128cfb_functions},
    { PROV_NAMES_AES_192_CFB, prov_name_fips, digiprov_aes192cfb_functions},
    { PROV_NAMES_AES_256_CFB, prov_name_fips, digiprov_aes256cfb_functions},
    { PROV_NAMES_AES_128_CTR, prov_name_fips, digiprov_aes128ctr_functions},
    { PROV_NAMES_AES_192_CTR, prov_name_fips, digiprov_aes192ctr_functions},
    { PROV_NAMES_AES_256_CTR, prov_name_fips, digiprov_aes256ctr_functions},
    { PROV_NAMES_AES_128_XTS, prov_name_fips, digiprov_aes256xts_functions},
    { PROV_NAMES_AES_256_XTS, prov_name_fips, digiprov_aes512xts_functions},
    { PROV_NAMES_AES_128_GCM, prov_name_fips, digiprov_aes128gcm_functions},
    { PROV_NAMES_AES_192_GCM, prov_name_fips, digiprov_aes192gcm_functions},
    { PROV_NAMES_AES_256_GCM, prov_name_fips, digiprov_aes256gcm_functions},
    { PROV_NAMES_AES_128_CCM, prov_name_fips, digiprov_aes128ccm_functions},
    { PROV_NAMES_AES_192_CCM, prov_name_fips, digiprov_aes192ccm_functions},
    { PROV_NAMES_AES_256_CCM, prov_name_fips, digiprov_aes256ccm_functions},
    { PROV_NAMES_AES_256_WRAP, prov_name_fips, digiprov_aes256wrap_functions},
    { PROV_NAMES_AES_192_WRAP, prov_name_fips, digiprov_aes192wrap_functions},
    { PROV_NAMES_AES_128_WRAP, prov_name_fips, digiprov_aes128wrap_functions},
    { PROV_NAMES_AES_256_WRAP_PAD, prov_name_fips, digiprov_aes256wrappad_functions},
    { PROV_NAMES_AES_192_WRAP_PAD, prov_name_fips, digiprov_aes192wrappad_functions},
    { PROV_NAMES_AES_128_WRAP_PAD, prov_name_fips, digiprov_aes128wrappad_functions},
    { PROV_NAMES_AES_256_WRAP_INV, prov_name_fips, digiprov_aes256wrapinv_functions},
    { PROV_NAMES_AES_192_WRAP_INV, prov_name_fips, digiprov_aes192wrapinv_functions},
    { PROV_NAMES_AES_128_WRAP_INV, prov_name_fips, digiprov_aes128wrapinv_functions},
    { PROV_NAMES_AES_256_WRAP_PAD_INV, prov_name_fips, digiprov_aes256wrappadinv_functions},
    { PROV_NAMES_AES_192_WRAP_PAD_INV, prov_name_fips, digiprov_aes192wrappadinv_functions},
    { PROV_NAMES_AES_128_WRAP_PAD_INV, prov_name_fips, digiprov_aes128wrappadinv_functions},
#ifndef OPENSSL_NO_DES
    { PROV_NAMES_DES_EDE3_ECB, prov_name_fips, digiprov_tdes192ecb_functions},
    { PROV_NAMES_DES_EDE3_CBC, prov_name_fips, digiprov_tdes192cbc_functions},
    { PROV_NAMES_DES_ECB, prov_name_no_fips, digiprov_des64ecb_functions},
    { PROV_NAMES_DES_CBC, prov_name_no_fips, digiprov_des64cbc_functions},
    { PROV_NAMES_DES_EDE_ECB, prov_name_fips, digiprov_tdes128ecb_functions},
    { PROV_NAMES_DES_EDE_CBC, prov_name_fips, digiprov_tdes128cbc_functions},
#endif /* OPENSSL_NO_DES */
#ifndef OPENSSL_NO_BF
   /* { PROV_NAMES_BF_ECB, prov_name_fips, digiprov_blowfish128ecb_functions}, */
    { PROV_NAMES_BF_CBC, prov_name_fips, digiprov_blowfish128cbc_functions},
#endif /* OPENSSL_NO_BF */
#ifndef OPENSSL_NO_RC4
    { PROV_NAMES_RC4, prov_name_fips, digiprov_rc4128ctr_functions},
    { PROV_NAMES_RC4_40, prov_name_fips, digiprov_rc440ctr_functions},
#endif /* OPENSSL_NO_RC4 */
#ifndef OPENSSL_NO_RC5
    { PROV_NAMES_RC5_ECB, prov_name_fips, digiprov_rc5128ecb_functions},
    { PROV_NAMES_RC5_CBC, prov_name_fips, digiprov_rc5128cbc_functions},
#endif /* OPENSSL_NO_RC5 */
#ifndef OPENSSL_NO_CHACHA
    { PROV_NAMES_ChaCha20, prov_name_fips, digiprov_chacha20_functions},
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_ChaCha20_Poly1305, prov_name_fips, digiprov_chacha20_poly1305_functions},
#endif
#endif /* OPENSSL_NO_CHACHA */
    { NULL, NULL, NULL}
};

static const OSSL_ALGORITHM digiprov_keymgmt[] = {
    { PROV_NAMES_DH, prov_name_fips, digiprov_dh_keymgmt_functions},
    { PROV_NAMES_RSA, prov_name_fips, digiprov_rsa_keymgmt_functions},
    { PROV_NAMES_RSA_PSS, prov_name_fips, digiprov_rsapss_keymgmt_functions},
    { PROV_NAMES_EC, prov_name_fips, digiprov_ec_keymgmt_functions},
    { PROV_NAMES_X25519, prov_name_fips, digiprov_x25519_keymgmt_functions},
    { PROV_NAMES_X448, prov_name_fips, digiprov_x448_keymgmt_functions},
    { PROV_NAMES_ED25519, prov_name_fips, digiprov_ed25519_keymgmt_functions},
    { PROV_NAMES_ED448, prov_name_fips, digiprov_ed448_keymgmt_functions},
    { PROV_NAMES_DSA, prov_name_fips, digiprov_dsa_keymgmt_functions},
    { PROV_NAMES_HMAC, prov_name_fips, digiprov_mac_keymgmt_functions},
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_POLY1305, prov_name_fips, digiprov_mac_keymgmt_functions},
#endif
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, prov_name_fips, digiprov_cmac_keymgmt_functions},
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    { PROV_NAMES_MLKEM_512, prov_name_fips, digiprov_mlkem512_keymgmt_functions},
    { PROV_NAMES_MLKEM_768, prov_name_fips, digiprov_mlkem768_keymgmt_functions},
    { PROV_NAMES_MLKEM_1024, prov_name_fips, digiprov_mlkem1024_keymgmt_functions},
    { PROV_NAMES_MLDSA_44, prov_name_fips, digiprov_mldsa44_keymgmt_functions},
    { PROV_NAMES_MLDSA_65, prov_name_fips, digiprov_mldsa65_keymgmt_functions},
    { PROV_NAMES_MLDSA_87, prov_name_fips, digiprov_mldsa87_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHA2_128S, prov_name_fips, digiprov_slhdsa_sha2_128s_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHA2_128F, prov_name_fips, digiprov_slhdsa_sha2_128f_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHA2_192S, prov_name_fips, digiprov_slhdsa_sha2_192s_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHA2_192F, prov_name_fips, digiprov_slhdsa_sha2_192f_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHA2_256S, prov_name_fips, digiprov_slhdsa_sha2_256s_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHA2_256F, prov_name_fips, digiprov_slhdsa_sha2_256f_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHAKE_128S, prov_name_fips, digiprov_slhdsa_shake_128s_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHAKE_128F, prov_name_fips, digiprov_slhdsa_shake_128f_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHAKE_192S, prov_name_fips, digiprov_slhdsa_shake_192s_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHAKE_192F, prov_name_fips, digiprov_slhdsa_shake_192f_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHAKE_256S, prov_name_fips, digiprov_slhdsa_shake_256s_keymgmt_functions},
    { PROV_NAMES_SLHDSA_SHAKE_256F, prov_name_fips, digiprov_slhdsa_shake_256f_keymgmt_functions},
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_signature[] = {
    { PROV_NAMES_RSA, prov_name_fips, digiprov_rsa_sig_functions},
    { PROV_NAMES_ECDSA, prov_name_fips, digiprov_ecdsa_functions},
    { PROV_NAMES_ED25519, prov_name_fips, digiprov_ed25519_functions},
    { PROV_NAMES_ED448, prov_name_fips, digiprov_ed448_functions},
    { PROV_NAMES_DSA, prov_name_fips, digiprov_dsa_functions},
    { PROV_NAMES_HMAC, prov_name_fips, digiprov_mac_hmac_signature_functions},
#ifndef OPENSSL_NO_CMAC    
    { PROV_NAMES_CMAC, prov_name_fips, digiprov_mac_cmac_signature_functions},
#endif
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_POLY1305, prov_name_fips, digiprov_mac_poly1305_signature_functions},
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    { PROV_NAMES_MLDSA_44, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_MLDSA_65, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_MLDSA_87, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHA2_128S, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHA2_128F, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHA2_192S, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHA2_192F, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHA2_256S, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHA2_256F, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHAKE_128S, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHAKE_128F, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHAKE_192S, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHAKE_192F, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHAKE_256S, prov_name_fips, digiprov_pqc_signature_functions},
    { PROV_NAMES_SLHDSA_SHAKE_256F, prov_name_fips, digiprov_pqc_signature_functions},
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_asym_cipher_functions[] = {
    { PROV_NAMES_RSA, prov_name_fips, digiprov_rsa_cipher_functions},
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_keyexch_algos[] = {
    { PROV_NAMES_DH, prov_name_fips, digiprov_dh_keyexch_functions },
    { PROV_NAMES_ECDH, prov_name_fips, digiprov_ecdh_keyexch_functions },
    { PROV_NAMES_X25519, prov_name_fips, digiprov_x25519_keyexch_functions},
    { PROV_NAMES_X448, prov_name_fips, digiprov_x448_keyexch_functions},
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM digiprov_rands[] = {
    { PROV_NAMES_CTR_DRBG, prov_name_fips, digiprov_drbg_ctr_functions },
    { PROV_NAMES_HASH_DRBG, prov_name_fips, digiprov_drbg_hash_functions },
    { PROV_NAMES_TEST_RAND, prov_name_fips, digiprov_drbg_ctr_functions },
    { NULL, NULL, NULL }
};

#ifdef __ENABLE_DIGICERT_PQC__
static const OSSL_ALGORITHM digiprov_asym_kem[] = {
    { PROV_NAMES_MLKEM_512, prov_name_fips, digiprov_pqc_kem_functions},
    { PROV_NAMES_MLKEM_768, prov_name_fips, digiprov_pqc_kem_functions},
    { PROV_NAMES_MLKEM_1024, prov_name_fips, digiprov_pqc_kem_functions},
    { NULL, NULL, NULL }
};
#endif

static const OSSL_ALGORITHM digiprov_decoder[] = 
{
#ifdef __ENABLE_DIGICERT_TAP__ 
    { "DER", "provider=digi,input=der,structure=PrivateKeyInfo", digiprov_der_to_tap_decoder_functions },
#endif
    { NULL, NULL, NULL }
};

/*----------------------------------------------------------------------------------------------------*/

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Global flag, 1 for running, 0 for off */
#if !defined(DIGIPROV_ALWAYS_INITIALIZED)
static int gIsRunning = 0;
#endif

int digiprov_is_running(void)
{
#if defined(DIGIPROV_ALWAYS_INITIALIZED)
    return 1;
#else
    return gIsRunning;
#endif
}

static const OSSL_PARAM digiprov_param_types[] = 
{
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static int digiprov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DigiCert OpenSSL 3 Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DigiCert Provider Build Info String"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
#if defined(DIGIPROV_ALWAYS_INITIALIZED)
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
#else
    if (p != NULL && !OSSL_PARAM_set_int(p, gIsRunning))
        return 0;
#endif
    return 1;
}

static const OSSL_ALGORITHM* digiprov_provider_query(void *provCtx, int opId, int *noStore)
{
    *noStore = 0;

    if (!digiprov_is_running())
        return NULL;

    switch(opId)
    {
        case OSSL_OP_DIGEST:
            return digiprov_digests;
        case OSSL_OP_CIPHER:
            return digiprov_cipher_algos;
        case OSSL_OP_MAC:
            return digiprov_macs;
        case OSSL_OP_KDF:
            return digiprov_kdf_algos;
        case OSSL_OP_RAND:
            return digiprov_rands;
        case OSSL_OP_KEYMGMT:
            return digiprov_keymgmt;
        case OSSL_OP_DECODER:
            return digiprov_decoder;
        case OSSL_OP_KEYEXCH:
            return digiprov_keyexch_algos;
        case OSSL_OP_SIGNATURE:
            return digiprov_signature;
        case OSSL_OP_ASYM_CIPHER:
            return digiprov_asym_cipher_functions;
        case OSSL_OP_KEM:
#ifdef __ENABLE_DIGICERT_PQC__
            return digiprov_asym_kem;
#else
            return NULL;
#endif
        default:
            break;
    }

    return NULL;
}

static const OSSL_PARAM *digiprov_gettable_params(void *provctx)
{
    return digiprov_param_types;
}

static void digiprov_teardown(void *provctx)
{
    moc_clear_ex_app_data();
    (void) DIGICERT_freeDigicert();
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
#if !defined(DIGIPROV_ALWAYS_INITIALIZED)
    gIsRunning = 0;
#endif
}

int digiprov_get_capabilities(void *provctx, const char *capability,
                              OSSL_CALLBACK *cb, void *arg)
{
    return 1;
}

static const OSSL_DISPATCH digiprov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))digiprov_teardown},
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))digiprov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))digiprov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))digiprov_provider_query},
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))digiprov_get_capabilities },
    { 0, NULL }
};

extern int ossl_digi_provider_init(const OSSL_CORE_HANDLE *handle,
         const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
         void **provctx)
{
    int status;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *pLibCtx = NULL;

    if (!ossl_prov_seeding_from_dispatch(in))
        return 0;
    if (!ossl_prov_bio_from_dispatch(in))
        return 0;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    status = DIGICERT_initDigicert();
    if (OK != status)
        return 0;

    if ( (*provctx = ossl_prov_ctx_new()) == NULL || 
         (corebiometh = ossl_bio_prov_init_bio_method()) == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }

    pLibCtx = (OSSL_LIB_CTX *) c_get_libctx(handle);
    ossl_prov_ctx_set0_libctx(*provctx, pLibCtx);
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_bio_method(*provctx, corebiometh);

    if(!moc_init_ex_app_data(pLibCtx))
        return 0;

    *out = digiprov_dispatch_table;
#if !defined(DIGIPROV_ALWAYS_INITIALIZED)
    gIsRunning = 1;
#endif
    return 1;
}
