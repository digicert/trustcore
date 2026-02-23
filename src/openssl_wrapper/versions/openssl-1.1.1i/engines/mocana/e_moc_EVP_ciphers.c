/*
 * e_moc_EVP_ciphers.c
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

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "e_moc_EVP_ciphers.h"
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include "../../crypto/asn1/asn1_locl.h"

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "../../include/openssl/pkcs12.h"
#define VERSION_1_1_0_OR_1_1_1C_OR_3_0
#else
#include "../../crypto/pkcs12/pkcs12.h"
#endif

#endif /* OPENSSL_VERSION_NUMBER < 0x010101060 */

#define MOC_EVP_LIB_NAME "MOC_EVP"
#include "e_moc_evp_err.h"

#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#ifndef OPENSSL_NO_EC
#include "moc_ec_pmeth.c"
#endif
#endif

#include "moc_dsa_pmeth.c"

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
#include "../../../src/crypto_interface/crypto_interface_rsa_tap.h"
#endif

#define ENCRYPT     (1)
#define DECRYPT     (0)

static int MOC_EVP_engineInit(ENGINE *e);
static int MOC_EVP_engineFinish(ENGINE *e);
static int MOC_EVP_engineDestroy(ENGINE *e);
BIGNUM *DIGI_EVP_vlong2BN(vlong *v);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static const ubyte* getDigest_OID(int len);
#endif

/* Flags specific to the OpenSSL version.
 *
 * If none of the version flags are specified then the else condition will
 * define the flags for OpenSSL version 1.0.2.
 */
#if defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    #define VERSION_EVP_MD_FLAG EVP_MD_FLAG_DIGALGID_ABSENT
    #define VERSION_RSA_F_RSA_PRIVATE_ENCRYPT RSA_F_RSA_OSSL_PRIVATE_DECRYPT
    #define VERSION_RSA_F_RSA_PRIVATE_DECRYPT RSA_F_RSA_OSSL_PRIVATE_DECRYPT
    #define VERSION_RSA_METHOD_FLAG 0
#else
    #define VERSION_EVP_MD_FLAG EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT
    #define VERSION_RSA_F_RSA_PRIVATE_ENCRYPT RSA_F_RSA_EAY_PRIVATE_ENCRYPT
    #define VERSION_RSA_F_RSA_PRIVATE_DECRYPT RSA_F_RSA_EAY_PRIVATE_DECRYPT
    #define VERSION_RSA_METHOD_FLAG RSA_FLAG_SIGN_VER
#endif /* VERSION_1_1_0_OR_1_1_1C_OR_3_0 */

#ifdef __RTOS_WIN32__
#include <stdint.h>

typedef uint32_t u_int32_t;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "../../../src/common/win32oid.c"
#include "../../../src/common/win32crypto.c"
#else
#include "../../../../src/common/win32oid.c"
#include "../../../../src/common/win32crypto.c"
#endif

#endif /* __RTOS_WIN32__ */

#if defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0) && \
    !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#error "Mocana EVP with OpenSSL 1.1.x must be built with Crypto Interface enabled"
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

#include "../../implementations/rands/drbg_local.h"
#define pem_check_suffix ossl_pem_check_suffix

#endif

int pem_check_suffix(const char *pem_str, const char *suffix);


/* varibles used to get/set CRYPTO_EX_DATA values */
#define MOC_EVP_INVALID_EX_DATA -1
static int rsaExAppData = MOC_EVP_INVALID_EX_DATA;
static int eccExAppData = MOC_EVP_INVALID_EX_DATA;

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
void freeExtraData(
    void *pParent, void *pData, CRYPTO_EX_DATA *pExData, int index, long arg,
    void *pArg
    )
{
    MOC_EVP_KEY_DATA *pMocKeyData = (MOC_EVP_KEY_DATA *) pData;

    if (NULL == pMocKeyData)
        return;

    if (NULL != pMocKeyData->pContents)
    {
        (void) DIGI_MEMSET_FREE(&pMocKeyData->pContents, pMocKeyData->contentsLen);
    }

    if (NULL != pMocKeyData->pData)
    {
        (void) DIGI_FREE((void **)&pMocKeyData->pData);
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != pMocKeyData->pCred)
    {
        (void) DIGI_MEMSET_FREE(&pMocKeyData->pCred, pMocKeyData->credLen);
    }
#endif

    (void) DIGI_FREE((void **)&pMocKeyData);
}

#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__

#ifdef __ENABLE_DIGICERT_TAP__
#ifndef MOC_EVP_KEY_CRED_MASK_SEED 
#define MOC_EVP_KEY_CRED_MASK_SEED 0x6b
#endif
#ifndef MOC_EVP_KEY_CRED_MASK_MUL 
#define MOC_EVP_KEY_CRED_MASK_MUL 3
#endif

void DIGI_EVP_maskCred(ubyte *pIn, ubyte4 inLen)
{
    ubyte mask = MOC_EVP_KEY_CRED_MASK_SEED;
    ubyte4 i = 0;

    for (; i < inLen; i++)
    {
        pIn[i] ^= mask;
        mask *= MOC_EVP_KEY_CRED_MASK_MUL;
    }
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/* Shadow structure to be able to obtain the internal
   randomContext. Must match DP_DRBG_CTR structure
   through the pRandCtx field.
*/
typedef struct _DP_DRBG_CTR_SHADOW 
{
    char cipher[12];
    size_t keylen;
    int use_df;
    randomContext *pRandCtx;
    /* ... rest of fields not needed */
} DP_DRBG_CTR_SHADOW;

static OSSL_LIB_CTX *gpLibCtx = NULL;

/* Some APIs don't take an RNG_Fun and we need to 
   retrieve the mocana rng from the internals */

/* This method only works for DRBG-CTR. FOR DRBG-HASH a new method 
   would be needed to wrap the DRBG-HASH context in a pRandomContext */
randomContext *RANDOM_getMocCtx(void)
{
    /* calling RAND_get0_public will instantiate if needbe */
    EVP_RAND_CTX *pRandCtx = RAND_get0_public(gpLibCtx);
    PROV_DRBG *pProv = NULL;
    DP_DRBG_CTR_SHADOW *pDrbg = NULL;

    if (NULL == pRandCtx)
        return NULL;

    pProv = (PROV_DRBG *) pRandCtx->algctx;
    if (NULL == pProv)
        return NULL;

    pDrbg = (DP_DRBG_CTR_SHADOW *) pProv->data;
    if (NULL == pDrbg)
        return NULL;
    
    return pDrbg->pRandCtx;    
}

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MOC_UNUSED(pRngFunArg);

    if (0 >= RAND_bytes_ex(gpLibCtx, pBuffer, length, 0))
        return ERR_RAND;
    else
        return OK;
}

#define RANDOM_FUN DIGI_EVP_RandomRngFun
#define RANDOM_CTX NULL
#define RANDOM_CTX_MOC RANDOM_getMocCtx()
#define RANDOM_CTX_PR RANDOM_getMocCtx()

int moc_get_rsa_ex_app_data(void)
{
    return rsaExAppData;
}

int moc_get_ecc_ex_app_data(void)
{
    return eccExAppData;
}

int moc_init_ex_app_data(OSSL_LIB_CTX *pLibCtx)
{
    if (MOC_EVP_INVALID_EX_DATA == rsaExAppData)
    {
        rsaExAppData = RSA_get_ex_new_index(0, NULL, NULL, NULL, freeExtraData);
    }
    if (MOC_EVP_INVALID_EX_DATA == eccExAppData)
    {
        eccExAppData = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, freeExtraData);
    }
    if (MOC_EVP_INVALID_EX_DATA == rsaExAppData || MOC_EVP_INVALID_EX_DATA == eccExAppData)
    {
        return 0;
    }
    
    gpLibCtx = pLibCtx;

    return 1;
}

void moc_clear_ex_app_data(void)
{
    rsaExAppData = MOC_EVP_INVALID_EX_DATA;
    eccExAppData = MOC_EVP_INVALID_EX_DATA;
    gpLibCtx = NULL;
}

#else

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
static sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MOC_UNUSED(pRngFunArg);

    if (0 >= RAND_bytes(pBuffer, length))
        return ERR_RAND;
    else
        return OK;
}
#endif

#define RANDOM_FUN RANDOM_rngFun
#define RANDOM_CTX g_pRandomContext
#define RANDOM_CTX_MOC g_pRandomContext
#define RANDOM_CTX_PR pRandomContext

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

typedef void (*KEYCONTEXT_CALLBACK) (AsymmetricKey *pAsymKey, int *status);

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
static int fipsModeSet = 0;
#endif

#define EVP_DH_CUSTOM_GROUP_PRI_LEN (32)

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__)

int DIGI_EVP_ENGINE_register()
{
    ENGINE *pEngine = ENGINE_by_id("mocana");
    if (NULL == pEngine)
    {
        return 0;
    }

    ENGINE_register_RSA(pEngine);
    ENGINE_register_DSA(pEngine);
    ENGINE_register_ECDH(pEngine);
    ENGINE_register_ECDSA(pEngine);
    ENGINE_register_DH(pEngine);
    ENGINE_register_RAND(pEngine);
    ENGINE_register_STORE(pEngine);
    ENGINE_register_ciphers(pEngine);
    ENGINE_register_digests(pEngine);

    ENGINE_free(pEngine);

    return 1;
}

/*------------------------------------------------------------------*/

int MOC_EVP_ENGINE_unregister()
{
    ENGINE *pEngine = ENGINE_by_id("mocana");
    if (NULL == pEngine)
    {
        return 0;
    }

    ENGINE_unregister_RSA(pEngine);
    ENGINE_unregister_DSA(pEngine);
    ENGINE_unregister_ECDH(pEngine);
    ENGINE_unregister_ECDSA(pEngine);
    ENGINE_unregister_DH(pEngine);
    ENGINE_unregister_RAND(pEngine);
    ENGINE_unregister_STORE(pEngine);
    ENGINE_unregister_ciphers(pEngine);
    ENGINE_unregister_digests(pEngine);

    ENGINE_free(pEngine);

    return 1;
}

#endif /* __ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__ */

/*------------------------------------------------------------------*/

int DIGI_EVP_setFipsMode(int fipsMode)
{
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if ( (0 != fipsMode) && (1 != fipsMode) )
    {
        return 0;
    }
    else
    {
#if defined(__ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__)
        if (0 == fipsMode)
        {
            if (0 == MOC_EVP_ENGINE_unregister())
            {
                return 0;
            }
        }
        else if (1 == fipsMode)
        {
            if (0 == DIGI_EVP_ENGINE_register())
            {
                return 0;
            }
        }
#endif /* __ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__ */

        fipsModeSet = fipsMode;
        if (1 == fipsModeSet)
        {
            if (FIPS_ModeEnabled())
            {
                return 1;
            }
            else
            {
                CRYPTOerr(CRYPTO_F_FIPS_MODE_SET, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
                return 0;
            }
        }
        else
        {
            return 1;
        }
    }
#else
    if (fipsMode == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
#endif
}

/*------------------------------------------------------------------*/

int DIGI_EVP_getFipsMode()
{
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (1 == fipsModeSet)
    {
        if (FIPS_ModeEnabled())
        {
            return 1;
        }
        else
        {
            CRYPTOerr(CRYPTO_F_FIPS_MODE_SET, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
            return 0;
        }
    }
    else
    {
        return 0;
    }
#else
    return 0;
#endif
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
static char versionBuf[256] = { 0 };
static int versionSet = 0;
#endif

/*------------------------------------------------------------------*/

unsigned long DIGI_EVP_FIPS_module_version(void)
{
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    MSTATUS status;
    ubyte4 vLen;
    ubyte4 index = 0, count = 0;
    unsigned long versionNum = 0;
    static char localVersionBuf[256] = { 0 };
    sbyte *pItr = (sbyte *) localVersionBuf;

    status = DIGICERT_readVersion(VT_MAIN, (ubyte *) localVersionBuf, sizeof(localVersionBuf));
    if (OK != status)
    {
        goto exit;
    }

    vLen = DIGI_STRLEN((const sbyte *) localVersionBuf);
    versionNum = 0;

    while (index < vLen && count < 3)
    {
        if (localVersionBuf[index] == '.')
        {
            localVersionBuf[index] = '\0';
            versionNum |= DIGI_ATOL(pItr, (const sbyte **) &pItr) << (8 * (3 - count));
            localVersionBuf[index] = '.';
            pItr++;
            count++;
        }

        index++;
    }

exit:

    return versionNum;
#else
    return 0;
#endif
}

/*------------------------------------------------------------------*/

const char *DIGI_EVP_FIPS_module_version_text(void)
{
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (versionSet == 0)
    {
        if (OK != DIGICERT_readVersion(VT_MAIN, (ubyte *) versionBuf, sizeof(versionBuf)))
        {
            return NULL;
        }

        versionSet = 1;
    }

    return versionBuf;
#else
    return NULL;
#endif
}

/*------------------------------------------------------------------*/

/* Helper method in order to obtain the working IV */
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
int DIGI_EVP_cipherGetIv(EVP_CIPHER_CTX *ctx, unsigned char *pIv, size_t ivLen, int isRc5)
{
    MSTATUS status = OK;
    MOC_EVP_CIPHER_CTX *mocCtx = NULL;
#ifdef __ENABLE_DIGICERT_RC5__
    MOC_EVP_RC5_CIPHER_CTX *mocRc5Ctx = NULL;
#else
    MOC_UNUSED(isRc5);
#endif

    if (NULL == ctx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

#ifdef __ENABLE_DIGICERT_RC5__
    if (isRc5)
    {
        mocRc5Ctx = (MOC_EVP_RC5_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
        if (NULL != mocRc5Ctx)
        {
            status = CRYPTO_INTERFACE_MocRC5GetIv(mocRc5Ctx->pEncrData, pIv, ivLen);
            if (OK != status)
                return 0;    
        }
        else
        {
            return 0;
        }
    }
    else
#endif
    {
        mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);

        if (IS_AES_CTR_CIPHER(ctx))
        {
            if (ivLen != AES_BLOCK_SIZE)
                return 0;

            status = CRYPTO_INTERFACE_GetCounterBlockAESCTR(mocCtx->pEncrData, pIv);
            if (OK != status)
                return 0;
        }
        else
        {
            if ((ubyte4) ivLen != mocCtx->ivLen)
            { 
                DIGI_EVP_WARN("%s: Invalid ivLen\n", __func__);
                return 0;
            }

            status = DIGI_MEMCPY((void *) pIv, mocCtx->wIv, mocCtx->ivLen);
            if (OK != status)
            return 0;
        }
    }

    return 1;
}
#endif

/* Theory of Operation: Before this func is called, the App. created a ctx
 * and obtained a ref to a EVP_CIPHER that it set in ctx->cipher. So far,
 * no Mocana specific per-ctx state for crypto created except that the EVP
 * layer has allocated room for a MOC_EVP_CIPHER_CTX in ctx->cipher_data.
 * Now we initialize this using code in our crypto/evp.c as a reference
 */
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int
DIGI_EVP_cipherInit(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		           const unsigned char *iv, int isEncrypt)
{
    int 		savedPadOption, savedIvLen, savedTagLen, savedRc2KeyBits;
    int 		cipherType;
    int			keyLen;
    int 		tempIvLen = 0;
    MOC_EVP_CIPHER_CTX *mocCtx;
    ubyte               keyMaterial[64]; /* big enough for all AES or ChaCha key/iv/ctr combos */
    ubyte               savedTag[MOC_EVP_MAX_BLOCK_LENGTH];
  
    ubyte pIv[MOC_EVP_MAX_IV_LENGTH] = { 0 };
    ubyte4 ivLen = 0;

    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    if (EVP_CIPHER_CTX_cipher(ctx) == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher object NULL\n", __func__);
        return 0;
    }
    cipherType = EVP_CIPHER_CTX_nid(ctx);
    keyLen = EVP_CIPHER_CTX_key_length(ctx);
  
    if ( 0 != mocCtx->ivLen )
    {
      DIGI_MEMCPY(pIv, mocCtx->wIv, mocCtx->ivLen);
      ivLen = mocCtx->ivLen;
    }

    if (NULL != key)
    {
        savedPadOption = mocCtx->pad;
        savedIvLen = mocCtx->ivLen;
        savedTagLen = mocCtx->tagLen;
        savedRc2KeyBits = mocCtx->rc2EffectiveKeyBits;
        DIGI_MEMCPY((ubyte*)savedTag, (ubyte*)mocCtx->tag, mocCtx->tagLen);
        DIGI_EVP_CIPHER_CTX_cleanup(MOC_SYM(hwAccelCtx) mocCtx);
        DIGI_EVP_CIPHER_CTX_init(mocCtx);
        mocCtx->pad = savedPadOption;
        mocCtx->ivLen = savedIvLen;
        mocCtx->tagLen = savedTagLen;
        mocCtx->rc2EffectiveKeyBits = savedRc2KeyBits;
        DIGI_MEMCPY((ubyte*)mocCtx->tag, (ubyte*)savedTag, mocCtx->tagLen);
    }

    DIGI_EVP_setEncrAlgo(mocCtx, cipherType);
    if (NULL == mocCtx->pEncrAlgo)
    {
        return 0;
    }

    iv = iv ? iv : ctx->iv;

    /* If the IV is provided by the caller or there is an IV in the context
     * then copy that IV over, otherwise restore the original IV from the
     * Mocana context.
     */
    if (NULL != iv)
    {
        if (NID_chacha20 == cipherType)
        {
            mocCtx->init = 0;
        }

        if (IS_AEAD_CIPHER(ctx))
        {
            tempIvLen = mocCtx->ivLen;
        }

        if (0 == tempIvLen)
        {
            tempIvLen = EVP_CIPHER_CTX_iv_length(ctx);
            mocCtx->ivLen = tempIvLen;
        }

        DIGI_MEMCPY(mocCtx->oIv, iv, tempIvLen);
        DIGI_MEMCPY(mocCtx->wIv, mocCtx->oIv, tempIvLen);
    }
    else
    {
        DIGI_MEMCPY(mocCtx->wIv, pIv, ivLen);
        DIGI_MEMCPY(mocCtx->oIv, pIv, ivLen);
        mocCtx->ivLen = ivLen;

        DIGI_MEMSET(pIv, 0x00, ivLen);
    }

    if (key != NULL)
    {
        DIGI_MEMCPY(keyMaterial, (ubyte *)key, keyLen);
        if (cipherType == NID_aes_128_ctr || cipherType == NID_aes_192_ctr || cipherType == NID_aes_256_ctr
#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER)
            || cipherType == NID_chacha20
#endif
            )
        {
            DIGI_MEMCPY(keyMaterial+keyLen, (ubyte *)iv, 16); /* AES or CHACHA IV size */
        }

        /* For all Mocana algorithms the create function is as follows
         *
         *   BulkCtx CreateFunc(ubyte *pKey, sbyte4 keyLen, sbyte4 encrypt)
         *
         * Except for RC2. RC2 expects the effective key bits in place of the
         * encrypt parameter, therefore special handling must be done here for the
         * RC2 algorithms to ensure that the effective key bits are passed in.
         */
        if ( (NID_rc2_ecb == cipherType) || (NID_rc2_cbc == cipherType) ||
             (NID_rc2_40_cbc == cipherType) )
        {
            mocCtx->pEncrData = mocCtx->pEncrAlgo->pBEAlgo->createFunc(
                MOC_SYM(hwAccelCtx) keyMaterial, keyLen,
                mocCtx->rc2EffectiveKeyBits);
        }
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
        else if (NID_rc4 == cipherType || NID_rc4_40 == cipherType || NID_bf_cbc == cipherType || NID_bf_ecb == cipherType)
        {
            mocCtx->pEncrData = (void*)mocCtx->pEncrAlgo->pBEAlgo->createFunc( MOC_SYM(hwAccelCtx)
                                            keyMaterial, keyLen, isEncrypt );
        }
#endif
        else
        {
            mocCtx->pEncrData = (void*)mocCtx->pEncrAlgo->pBEAlgo->createFunc( MOC_SYM(hwAccelCtx)
                                            keyMaterial, mocCtx->pEncrAlgo->keySize, isEncrypt );
        }

        if (NULL == mocCtx->pEncrData)
        {
            return 0;
        }
    }

    mocCtx->ivSet = FALSE;
    if (mocCtx->ivLen)
        mocCtx->ivSet = TRUE;

    return 1;
}

/*----------------------------------------------------------------------------*/

int DIGI_EVP_CIPHER_copyCtx(
    EVP_CIPHER_CTX *pCtx, EVP_CIPHER_CTX *pCtxCopy)
{
    MSTATUS status;
    int retVal = 0;
    MOC_EVP_CIPHER_CTX *pMocEvpCtx = NULL, *pMocEvpCtxCopy = NULL;

    if ( (NULL == pCtx) || (NULL == pCtxCopy) )
    {
        goto exit;
    }

    pMocEvpCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocEvpCtx)
    {
        /* Nothing to copy, set success return code and exit. */
        retVal = 1;
        goto exit;
    }

    if (NULL == pCtx->cipher)
    {
        goto exit;
    }

    /* Whatever context this is, if the context size is not supported. Throw an
     * error.
     */
    if (sizeof(MOC_EVP_CIPHER_CTX) != pCtx->cipher->ctx_size)
    {
        goto exit;
    }

    /* OpenSSL should take care of performing a shallow copy. If they didn't
     * then make a copy.
     */
    pMocEvpCtxCopy = DIGI_EVP_CIPHER_CTX_getCipherData(pCtxCopy);
    if (NULL == pMocEvpCtxCopy)
    {
        pCtxCopy->cipher_data = OPENSSL_malloc(sizeof(MOC_EVP_CIPHER_CTX));
        if (NULL == pCtxCopy->cipher_data)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        pMocEvpCtxCopy = DIGI_EVP_CIPHER_CTX_getCipherData(pCtxCopy);
    }

    /* Regardless of whether OpenSSL performed a shallow copy or not, override
     * the data.
     */
    DIGI_MEMCPY(
        pCtxCopy->cipher_data, pCtx->cipher_data, sizeof(MOC_EVP_CIPHER_CTX));

    /* If the current context contains a key, copy it over the the new context.
     */
    if (NULL != pMocEvpCtx->key)
    {
        pMocEvpCtxCopy->key = OPENSSL_malloc(pCtx->key_len);
        if (NULL == pMocEvpCtxCopy->key)
        {
            goto exit;
        }

        DIGI_MEMCPY(pMocEvpCtxCopy->key, pMocEvpCtx->key, pCtx->key_len);
    }

    /* If the current context has created a Mocana crypto context then copy it
     * over.
     */
    if (NULL != pMocEvpCtx->pEncrData)
    {
        if (NULL == pMocEvpCtx->pEncrAlgo->pBEAlgo->cloneFunc)
        {
            goto exit;
        }

        status = pMocEvpCtx->pEncrAlgo->pBEAlgo->cloneFunc(
            pMocEvpCtx->pEncrData, &(pMocEvpCtxCopy->pEncrData));
        if (OK != status)
        {
            goto exit;
        }
    }

    retVal = 1;

exit:

    return retVal;
}

/*----------------------------------------------------------------------------*/

int DIGI_EVP_CIPHER_ctrl(EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr)
{
    int retVal = 0;

    if (NULL == pCtx)
    {
        goto exit;
    }

    switch (type)
    {
        case EVP_CTRL_COPY:
            retVal = DIGI_EVP_CIPHER_copyCtx(pCtx, pPtr);
            break;

        default:
            break;
    }

exit:

    return retVal;
}

/*----------------------------------------------------------------------------*/

#if( !defined(__DISABLE_3DES_CIPHERS__) || defined(__ENABLE_DES_CIPHER__))
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_ThreeDesInit(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		                 const unsigned char *iv, int isEncrypt)
{
    int 		cipherType;
    int			keyLen;
    MOC_EVP_CIPHER_CTX *mocCtx;
    ubyte *keyMaterial = NULL;

    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    if (EVP_CIPHER_CTX_cipher(ctx) == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher object NULL\n", __func__);
        return 0;
    }
    cipherType = EVP_CIPHER_CTX_nid(ctx);
    keyLen = EVP_CIPHER_CTX_key_length(ctx);

    DIGI_EVP_setEncrAlgo(mocCtx, cipherType);
    if (NULL == mocCtx->pEncrAlgo)
    {
        return 0;
    }

    iv = iv ? iv : ctx->iv;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    mocCtx->ivLen = EVP_CIPHER_CTX_iv_length(ctx);
    DIGI_MEMCPY(mocCtx->oIv, iv, mocCtx->ivLen);
    DIGI_MEMCPY(mocCtx->wIv, mocCtx->oIv, mocCtx->ivLen);
#else
    DIGI_MEMCPY(mocCtx->oIv, iv, mocCtx->pEncrAlgo->pBEAlgo->blockSize);
    DIGI_MEMCPY(mocCtx->wIv, mocCtx->oIv, mocCtx->pEncrAlgo->pBEAlgo->blockSize);
#endif

    if (NULL != key)
    {
        if(0 < keyLen)
        {
            keyMaterial = OPENSSL_malloc(keyLen);
            DIGI_MEMCPY(keyMaterial, (ubyte *)key, keyLen);
        }

        mocCtx->pEncrData = (void*)mocCtx->pEncrAlgo->pBEAlgo->createFunc( MOC_SYM(hwAccelCtx)
                                        keyMaterial,
                                        mocCtx->pEncrAlgo->keySize,
                                        isEncrypt );

        if(NULL != keyMaterial)
        {
            OPENSSL_free(keyMaterial);
            keyMaterial = NULL;
        }

        if (NULL == mocCtx->pEncrData)
        {
            return 0;
        }
    }

    return 1;
}
#endif

/*------------------------------------------------------------------*/

static MSTATUS MOC_EVP_AES_GCM_setIv(
    MOC_EVP_AES_GCM_CIPHER_CTX *pGCtx, ubyte *pIv, ubyte4 ivLen)
{
    MSTATUS status;

    if (NULL == pGCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pGCtx->pCopyIv)
    {
        DIGI_FREE((void **) &(pGCtx->pCopyIv));
        pGCtx->copyIvLen = 0;
    }

    status = DIGI_MALLOC((void **) &(pGCtx->pCopyIv), ivLen);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(pGCtx->pCopyIv, pIv, ivLen);
    pGCtx->copyIvLen = ivLen;

exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_AES_GCM_cipherInit(
    EVP_CIPHER_CTX *pCtx, const unsigned char *pKey, const unsigned char *pIv,
    int isEncrypt)
{
    MSTATUS status;
    MOC_EVP_AES_GCM_CIPHER_CTX *pGCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);

    if (!pIv && !pKey)
    {
        return 1;
    }

    if (pKey)
    {
        if (NULL != pGCtx->pGcmCtx)
        {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            CRYPTO_INTERFACE_GCM_deleteCtx(&(pGCtx->pGcmCtx));
#else
            GCM_deleteCtx(&(pGCtx->pGcmCtx));
#endif
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        pGCtx->pGcmCtx = CRYPTO_INTERFACE_GCM_createCtx(
            (ubyte *) pKey, pCtx->key_len, pCtx->encrypt);
#else
        pGCtx->pGcmCtx = GCM_createCtx(
            (ubyte *) pKey, pCtx->key_len, pCtx->encrypt);
#endif
        if (NULL == pGCtx->pGcmCtx)
        {
            return 0;
        }

        if (pIv == NULL && pGCtx->ivSet)
        {
            pIv = pGCtx->pIv;
        }
        if (pIv)
        {
            status = MOC_EVP_AES_GCM_setIv(
                pGCtx, (ubyte *) pIv, pGCtx->ivLen);
            if (OK != status)
            {
                return 0;
            }

            pGCtx->ivSet = TRUE;
        }

        pGCtx->keySet = TRUE;
    }
    else
    {
        if (pGCtx->keySet)
        {
            status = MOC_EVP_AES_GCM_setIv(
                pGCtx, (ubyte *) pIv, pGCtx->ivLen);
            if (OK != status)
            {
                return 0;
            }
        }
        else
        {
            DIGI_MEMCPY(pGCtx->pIv, pIv, pGCtx->ivLen);
        }

        pGCtx->ivSet = TRUE;
        pGCtx->ivGen = FALSE;
    }

    pGCtx->init = FALSE;

    return 1;
}

/*------------------------------------------------------------------*/

static int MOC_EVP_AES_GCM_TLS_doCipher(
    EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn,
    size_t inLen)
{
    MSTATUS status;
    int rv = -1;
    MOC_EVP_AES_GCM_CIPHER_CTX *pGCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);

    if (pOut != pIn || inLen < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
    {
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(
            pCtx, pCtx->encrypt ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
            EVP_GCM_TLS_EXPLICIT_IV_LEN, pOut) <= 0)
    {
        goto err;
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_GCM_init(
        pGCtx->pGcmCtx, pGCtx->pCopyIv, pGCtx->copyIvLen, pCtx->buf,
        pGCtx->tlsAadLen);
#else
    status = GCM_init(
        pGCtx->pGcmCtx, pGCtx->pCopyIv, pGCtx->copyIvLen, pCtx->buf,
        pGCtx->tlsAadLen);
#endif
    if (OK != status)
    {
        goto err;
    }

    /* Fix buffer and length to point to payload */
    pIn += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    pOut += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    inLen -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

    DIGI_MEMCPY(pOut, pIn, (sbyte4)inLen);
    if (pCtx->encrypt)
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_GCM_update_encrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#else
        status = GCM_update_encrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#endif
        if (OK != status)
        {
            goto err;
        }

        pOut += inLen;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_GCM_final(pGCtx->pGcmCtx, pOut);
#else
        status = GCM_final(pGCtx->pGcmCtx, pOut);
#endif
        if (OK != status)
        {
            goto err;
        }
        rv = (int)inLen + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    }
    else
    {
        sbyte4 res;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_GCM_update_decrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#else
        status = GCM_update_decrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#endif
        if (OK != status)
        {
            goto err;
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_GCM_final(pGCtx->pGcmCtx, pCtx->buf);
#else
        status = GCM_final(pGCtx->pGcmCtx, pCtx->buf);
#endif
        if (OK != status)
        {
            goto err;
        }

        DIGI_CTIME_MATCH(pCtx->buf, pIn + inLen, EVP_GCM_TLS_TAG_LEN, &res);
        if (0 != res)
        {
            DIGI_MEMSET(pOut, 0x00, (usize)inLen);
            goto err;
        }
        rv = (int)inLen;
    }

err:
    pGCtx->ivSet = FALSE;
    pGCtx->tlsAadLen = -1;
    return rv;
}

/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_AES_GCM_doCipher(
    EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn,
    size_t inLen)
{
    MSTATUS status;
    MOC_EVP_AES_GCM_CIPHER_CTX *pGCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);

    if (!pGCtx->keySet)
    {
        return -1;
    }

    if (pGCtx->tlsAadLen >= 0)
    {
        return MOC_EVP_AES_GCM_TLS_doCipher(pCtx, pOut, pIn, inLen);
    }

    if (!pGCtx->ivSet)
    {
        return -1;
    }

    if (pIn)
    {
        /* No output buffer provided. Treat input as AAD.
         */
        if (pOut == NULL)
        {
            if (inLen != 0)
            {
                ubyte *pNewAad = NULL;

                status = DIGI_MALLOC((void **) &pNewAad, pGCtx->aadLen + (ubyte4)inLen);
                if (OK != status)
                {
                    return -1;
                }

                DIGI_MEMCPY(pNewAad, pGCtx->pAad, pGCtx->aadLen);
                DIGI_MEMCPY(pNewAad + pGCtx->aadLen, pIn, (sbyte4)inLen);
                DIGI_FREE((void **) &(pGCtx->pAad));
                pGCtx->pAad = pNewAad;
                pGCtx->aadLen += (ubyte4)inLen;
            }
        }
        else
        {
            if (FALSE == pGCtx->init)
            {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                status = CRYPTO_INTERFACE_GCM_init(
                    pGCtx->pGcmCtx, pGCtx->pCopyIv, pGCtx->copyIvLen,
                    pGCtx->pAad, pGCtx->aadLen);
#else
                status = GCM_init(
                    pGCtx->pGcmCtx, pGCtx->pCopyIv, pGCtx->copyIvLen,
                    pGCtx->pAad, pGCtx->aadLen);
#endif
                if (OK != status)
                {
                    return -1;
                }

                DIGI_FREE((void **) &(pGCtx->pAad));
                pGCtx->aadLen = 0;

                pGCtx->init = TRUE;
            }

            DIGI_MEMCPY(pOut, pIn, (sbyte4)inLen);
            if (pCtx->encrypt)
            {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                status = CRYPTO_INTERFACE_GCM_update_encrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#else
                status = GCM_update_encrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#endif
            }
            else
            {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                status = CRYPTO_INTERFACE_GCM_update_decrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#else
                status = GCM_update_decrypt(pGCtx->pGcmCtx, pOut, (ubyte4)inLen);
#endif
            }
            if (OK != status)
            {
                return -1;
            }
        }

        return (int)inLen;
    }
    else
    {
        ubyte pTag[AES_BLOCK_SIZE];

        if (FALSE == pGCtx->init)
        {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            status = CRYPTO_INTERFACE_GCM_init(
                pGCtx->pGcmCtx, pGCtx->pCopyIv, pGCtx->copyIvLen,
                pGCtx->pAad, pGCtx->aadLen);
#else
            status = GCM_init(
                pGCtx->pGcmCtx, pGCtx->pCopyIv, pGCtx->copyIvLen,
                pGCtx->pAad, pGCtx->aadLen);
#endif
            if (OK != status)
            {
                return -1;
            }

            DIGI_FREE((void **) &(pGCtx->pAad));
            pGCtx->aadLen = 0;

            pGCtx->init = TRUE;
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_GCM_final(pGCtx->pGcmCtx, pTag);
#else
        status = GCM_final(pGCtx->pGcmCtx, pTag);
#endif
        if (OK != status)
        {
            return -1;
        }

        if (!pCtx->encrypt)
        {
            sbyte4 res;

            if (pGCtx->tagLen < 0)
            {
                return -1;
            }

            DIGI_CTIME_MATCH(pTag, pCtx->buf, pGCtx->tagLen, &res);
            if (0 != res)
            {
                return -1;
            }

            pGCtx->ivSet = FALSE;
            pGCtx->init = FALSE;
            return 0;
        }

        DIGI_MEMCPY(pCtx->buf, pTag, 16);
        pGCtx->tagLen = 16;
        pGCtx->ivSet = FALSE;
        pGCtx->init = FALSE;
        return 0;
    }
}

/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_AES_GCM_cipherCleanup(EVP_CIPHER_CTX *pCtx)
{
    MOC_EVP_AES_GCM_CIPHER_CTX *pGCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);

    if (NULL == pGCtx)
    {
        return 0;
    }

    if (NULL != pGCtx->pIv && pGCtx->pIv != pCtx->iv)
    {
        DIGI_FREE((void **) &(pGCtx->pIv));
    }

    if (NULL != pGCtx->pCopyIv)
    {
        DIGI_FREE((void **) &(pGCtx->pCopyIv));
    }

    if (NULL != pGCtx->pAad)
    {
        DIGI_FREE((void **) &(pGCtx->pAad));
    }

    if (NULL != pGCtx->pGcmCtx)
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        CRYPTO_INTERFACE_GCM_deleteCtx(&(pGCtx->pGcmCtx));
#else
        GCM_deleteCtx(&(pGCtx->pGcmCtx));
#endif
    }

    return 1;
}

/*------------------------------------------------------------------*/

void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

/*------------------------------------------------------------------*/
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_AES_GCM_cipherCtxCtrl(
    EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr)
{
    MSTATUS status;
    MOC_EVP_AES_GCM_CIPHER_CTX *pGCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);

    switch (type)
    {
        case EVP_CTRL_INIT:
            pGCtx->keySet = FALSE;
            pGCtx->pIv = pCtx->iv;
            pGCtx->ivLen = pCtx->cipher->iv_len;
            pGCtx->pCopyIv = NULL;
            pGCtx->copyIvLen = 0;
            pGCtx->ivSet = FALSE;
            pGCtx->ivGen = FALSE;
            pGCtx->tlsAadLen = -1;
            pGCtx->pAad = NULL;
            pGCtx->aadLen = 0;
            pGCtx->pGcmCtx = NULL;
            pGCtx->init = FALSE;
            pGCtx->tagLen = -1;
            return 1;

        case EVP_CTRL_GCM_SET_IVLEN:
            if (arg <= 0)
            {
                return 0;
            }

            if ((arg > EVP_MAX_IV_LENGTH) && (arg > pGCtx->ivLen))
            {
                if (pGCtx->pIv != pCtx->iv)
                {
                    DIGI_FREE((void **) &(pGCtx->pIv));
                }

                status = DIGI_MALLOC((void **) &(pGCtx->pIv), arg);
                if (OK != status)
                {
                    return 0;
                }
            }
            pGCtx->ivLen = arg;
            return 1;

        case EVP_CTRL_GCM_SET_TAG:
            if (arg <= 0 || arg > 16 || pCtx->encrypt)
            {
                return 0;
            }

            DIGI_MEMCPY(pCtx->buf, pPtr, arg);
            pGCtx->tagLen = arg;
            return 1;

        case EVP_CTRL_GCM_GET_TAG:
            if (arg <= 0 || arg > 16 || !pCtx->encrypt || pGCtx->tagLen < 0)
            {
                return 0;
            }

            DIGI_MEMCPY(pPtr, pCtx->buf, arg);
            return 1;

        case EVP_CTRL_GCM_SET_IV_FIXED:
            /* Special case: -1 length restores whole IV */
            if (arg == -1)
            {
                DIGI_MEMCPY(pGCtx->pIv, pPtr, pGCtx->ivLen);
                pGCtx->ivGen = TRUE;
                return 1;
            }
            /*
            * Fixed field must be at least 4 bytes and invocation field at least
            * 8.
            */
            if ((arg < 4) || (pGCtx->ivLen - arg) < 8)
            {
                return 0;
            }

            if (arg)
            {
                DIGI_MEMCPY(pGCtx->pIv, pPtr, arg);
            }

            if (pCtx->encrypt && RAND_bytes(pGCtx->pIv + arg, pGCtx->ivLen - arg) <= 0)
            {
                return 0;
            }

            pGCtx->ivGen = TRUE;
            return 1;

        case EVP_CTRL_GCM_IV_GEN:
            if (pGCtx->ivGen == FALSE || pGCtx->keySet == FALSE)
            {
                return 0;
            }

            status = MOC_EVP_AES_GCM_setIv(pGCtx, pGCtx->pIv, pGCtx->ivLen);
            if (OK != status)
            {
                return 0;
            }

            if (arg <= 0 || arg > pGCtx->ivLen)
            {
                arg = pGCtx->ivLen;
            }
            DIGI_MEMCPY(pPtr, pGCtx->pIv + pGCtx->ivLen - arg, arg);
            /*
            * Invocation field will be at least 8 bytes in size and so no need
            * to check wrap around or increment more than last 8 bytes.
            */
            ctr64_inc(pGCtx->pIv + pGCtx->ivLen - 8);
            pGCtx->ivSet = TRUE;
            return 1;

        case EVP_CTRL_GCM_SET_IV_INV:
            if (pGCtx->ivGen == FALSE || pGCtx->keySet == FALSE || pCtx->encrypt)
            {
                return 0;
            }
            DIGI_MEMCPY(pGCtx->pIv + pGCtx->ivLen - arg, pPtr, arg);
            status = MOC_EVP_AES_GCM_setIv(pGCtx, pGCtx->pIv, pGCtx->ivLen);
            if (OK != status)
            {
                return 0;
            }
            pGCtx->ivSet = TRUE;
            return 1;

        case EVP_CTRL_AEAD_TLS1_AAD:
            /* Save the AAD for later use */
            if (arg != EVP_AEAD_TLS1_AAD_LEN)
            {
                return 0;
            }
            DIGI_MEMCPY(pCtx->buf, pPtr, arg);
            pGCtx->tlsAadLen = arg;
            {
                unsigned int len = pCtx->buf[arg - 2] << 8 | pCtx->buf[arg - 1];
                /* Correct length for explicit IV */
                if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
                {
                    return 0;
                }
                len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
                /* If decrypting correct for tag too */
                if (!pCtx->encrypt)
                {
                    if (len < EVP_GCM_TLS_TAG_LEN)
                    {
                        return 0;
                    }
                    len -= EVP_GCM_TLS_TAG_LEN;
                }
                pCtx->buf[arg - 2] = len >> 8;
                pCtx->buf[arg - 1] = len & 0xff;
            }
            /* Extra padding: tag appended to record */
            return EVP_GCM_TLS_TAG_LEN;

        case EVP_CTRL_COPY:
            {
                EVP_CIPHER_CTX *pCtxOut = pPtr;
                MOC_EVP_AES_GCM_CIPHER_CTX *pGCtxOut = DIGI_EVP_CIPHER_CTX_getCipherData(pCtxOut);

                DIGI_MEMCPY(pGCtxOut, pGCtx, sizeof(MOC_EVP_AES_GCM_CIPHER_CTX));

                if (pGCtx->pIv == pCtx->iv)
                {
                    pGCtxOut->pIv = pCtxOut->iv;
                }
                else
                {
                    status = DIGI_MALLOC(
                        (void **) &(pGCtxOut->pIv), pGCtx->ivLen);
                    if (OK != status)
                    {
                        return 0;
                    }
                    DIGI_MEMCPY(pGCtxOut->pIv, pGCtx->pIv, pGCtx->ivLen);
                }

                if (NULL != pGCtx->pCopyIv)
                {
                    status = DIGI_MALLOC(
                        (void **) &(pGCtxOut->pCopyIv), pGCtx->copyIvLen);
                    if (OK != status)
                    {
                        return 0;
                    }
                    DIGI_MEMCPY(pGCtxOut->pCopyIv, pGCtx->pCopyIv, pGCtx->copyIvLen);
                }

                if (NULL != pGCtx->pAad)
                {
                    status = DIGI_MALLOC(
                        (void **) &(pGCtxOut->pAad), pGCtx->aadLen);
                    if (OK != status)
                    {
                        return 0;
                    }
                    DIGI_MEMCPY(pGCtxOut->pAad, pGCtx->pAad, pGCtx->aadLen);
                }

                if (NULL != pGCtx->pGcmCtx)
                {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                    status = CRYPTO_INTERFACE_GCM_clone(
                        pGCtx->pGcmCtx, &(pGCtxOut->pGcmCtx));
#else
                    status = GCM_clone(
                        pGCtx->pGcmCtx, &(pGCtxOut->pGcmCtx));
#endif
                    if (OK != status)
                    {
                        return 0;
                    }
                }
                return 1;
            }

        default:
            return -1;
    }
}

/*------------------------------------------------------------------*/

/* This is called from EVP_CIPHER_CTX_reset()[openssl/crypto/evp/evp_enc.c]
 * and is supposed to do per-cipher (ENGINE specific) cleanup.
 */
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int
DIGI_EVP_cipherCleanup(EVP_CIPHER_CTX *ctx)
{
    MOC_EVP_CIPHER_CTX *mocCtx;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    DIGI_EVP_CIPHER_CTX_cleanup(mocCtx);
    return 1;
}

static int MOC_EVP_doCustomCipher(
    EVP_CIPHER_CTX *pCtx,
    unsigned char *pOut,
    const unsigned char *pIn,
    size_t inLen
    )
{
    MSTATUS status;
    MOC_EVP_CIPHER_CTX *pMocEvpCtx;
    ubyte4 blockBytes;
    int isEncrypt, bytesProcessed = 0, retVal = -1;

    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        goto exit;
    }

    pMocEvpCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocEvpCtx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        goto exit;
    }

    isEncrypt = DIGI_EVP_CIPHER_CTX_encrypting(pCtx) ? ENCRYPT : DECRYPT;

    if (NULL != pIn)
    {
        /* Get the number of bytes required to fill an entire block
         */
        blockBytes = pCtx->cipher->block_size - pMocEvpCtx->blockBufLen;

        /* Check how many bytes can be copied into the block buffer
         */
        blockBytes = blockBytes > inLen ? inLen : blockBytes;

        /* Copy over the bytes into the block buffer. No status check intentional.
         */
        DIGI_MEMCPY(
            pMocEvpCtx->blockBuf + pMocEvpCtx->blockBufLen, pIn, blockBytes);
        pMocEvpCtx->blockBufLen += blockBytes;
        pIn += blockBytes;
        inLen -= blockBytes;
    }

    /* Check if there is enough data to perform a block operation.
     */
    if ( (pCtx->cipher->block_size == pMocEvpCtx->blockBufLen) ||
         ((NULL == pIn) && (0 != pMocEvpCtx->blockBufLen)) )
    {
        status = pMocEvpCtx->pEncrAlgo->pBEAlgo->cipherFunc(
            MOC_SYM(hwAccelCtx) pMocEvpCtx->pEncrData, pMocEvpCtx->blockBuf,
            pCtx->cipher->block_size, isEncrypt,
            IS_AES_CTR_CIPHER(pCtx) ? NULL : pMocEvpCtx->wIv);
        if (OK > status)
            goto exit;

        DIGI_MEMCPY(pOut, pMocEvpCtx->blockBuf, pMocEvpCtx->blockBufLen);
        bytesProcessed += pMocEvpCtx->blockBufLen;
        pOut += pMocEvpCtx->blockBufLen;
        pMocEvpCtx->blockBufLen = 0;

        if ( (NULL != pIn) && (0 != inLen) )
        {
            /* Use blockBytes to store the number of leftover bytes that will need
             * to be copied back to the context.
             */
            blockBytes = inLen & (pCtx->cipher->block_size - 1);
            inLen -= blockBytes;

            if (0 != inLen)
            {
                /* Process the remaining bytes
                 */
                DIGI_MEMCPY(pOut, pIn, inLen);
                status = pMocEvpCtx->pEncrAlgo->pBEAlgo->cipherFunc(
                    MOC_SYM(hwAccelCtx) pMocEvpCtx->pEncrData, pOut, inLen, isEncrypt,
                    IS_AES_CTR_CIPHER(pCtx) ? NULL : pMocEvpCtx->wIv);
                if (OK > status)
                    goto exit;

                bytesProcessed += inLen;
                pIn += inLen;
            }

            if (0 != blockBytes)
            {
                /* Copy the leftover bytes into the block buffer
                 */
                DIGI_MEMCPY(pMocEvpCtx->blockBuf, pIn, blockBytes);
                pMocEvpCtx->blockBufLen = blockBytes;
            }
        }
    }

    retVal = bytesProcessed;

exit:

    return retVal;
}

/* Called by EVP_EncryptUpdate() [evp_enc.c]. It always calls do_cipher() below with a
 * multiple of block size. Also, EVP_EncryptFinal_ex() calls this with 16 bytes of data that
 * could either be pure padding (16 bytes each being 0x10) or mix of data and pad. See
 * https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7 Decrypt always looks
 * at the last byte of data and clips off that many bytes. do_cipher doesn't need to
 * know if it is being called by Update or Final_ex. In both cases, we call doCipherUpdate
 * with a mult of block size. This is consistent with code in crypto/evp.c that defines
 * its own EVP_EncryptUpate and EVP_EncryptFinal. The latter also always adds padding
 * even if input data was a mult of block size. MOC_EVP_doCipherUpdate slurps all the
 * data its given since it's a mult of blocksize and it never buffers any remainder data
 * i.e ctx->blockBufLen in that code is always 0
 */
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int DIGI_EVP_doCipher(
  EVP_CIPHER_CTX *ctx,
  unsigned char *out,
  const unsigned char *in,
  size_t inl
  )
{
  MOC_EVP_CIPHER_CTX *mocCtx;
  int is_encrypt;
  MSTATUS status;
  unsigned char *pInput = NULL;
  size_t retLen;
  ubyte *pIv = NULL;

  if (ctx == NULL)
  {
    DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
    return 0;
  }
  
  mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
  
  if (mocCtx == NULL)
  {
    DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
    return 0;
  }
  
  is_encrypt = DIGI_EVP_CIPHER_CTX_encrypting(ctx) ? ENCRYPT : DECRYPT;

  /* In case of AEAD cipher, out is null while updating aad data
   */
  if ( in && !out && IS_AEAD_CIPHER(ctx) )
  {
    mocCtx->aadLen = (ubyte4)inl;
    OPENSSL_free(mocCtx->aad);
    mocCtx->aad = (ubyte *)OPENSSL_malloc(inl);
    DIGI_MEMCPY((ubyte *)mocCtx->aad, (ubyte *)in, (ubyte4)inl);
    return (int)inl;
  }

  if (IS_AEAD_CIPHER(ctx))
  {
    int verifyLen = mocCtx->tagLen ? mocCtx->tagLen : AES_BLOCK_SIZE;

    if (FALSE == mocCtx->ivSet)
        return -1;
    
    status = DIGI_MALLOC((void **) &pInput, (ubyte4)inl + (ubyte4)verifyLen);
    if (OK != status)
        return 0;
    DIGI_MEMCPY(pInput, in, (sbyte4)inl);
  
    if (!is_encrypt)
    {
      DIGI_MEMCPY(pInput + inl, mocCtx->tag, verifyLen);
    }
    
    if (EVP_CIPHER_CTX_nid(ctx) == NID_aes_256_ccm 
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
       || EVP_CIPHER_CTX_nid(ctx) == NID_aes_192_ccm
       || EVP_CIPHER_CTX_nid(ctx) == NID_aes_128_ccm
#endif
       )
    {
        if ( (NULL == in) || (NULL == out) )
        {
            if (NULL != pInput)
            {
                DIGI_MEMSET(pInput, 0x00, (usize)inl);
                DIGI_FREE((void **) &pInput);
            }
            return (int)inl;
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_AES_CCM_cipher(
#else
        status = AESCCM_cipher(
#endif
            MOC_SYM(hwAccelCtx) mocCtx->pEncrData, mocCtx->wIv, mocCtx->ivLen,
            mocCtx->aad, mocCtx->aadLen, pInput, (ubyte4)inl, verifyLen, is_encrypt);
        if (OK != status)
        {
            if (NULL != pInput)
            {
                DIGI_MEMSET(pInput, 0x00, (usize)inl);
                DIGI_FREE((void **) &pInput);
            }
            return -1;
        }
    }

    if (NULL != mocCtx->aad)
    {
        OPENSSL_free(mocCtx->aad);
        mocCtx->aad = NULL;
    }

    retLen = inl;
    DIGI_MEMCPY(out, pInput, (sbyte4)inl);

    if (is_encrypt)
    {
      if (EVP_CIPHER_CTX_nid(ctx) == NID_aes_256_ccm
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
       || EVP_CIPHER_CTX_nid(ctx) == NID_aes_192_ccm
       || EVP_CIPHER_CTX_nid(ctx) == NID_aes_128_ccm
#endif
         )
      {
        DIGI_MEMCPY(mocCtx->tag, pInput + inl, verifyLen);
        mocCtx->tagLen = verifyLen;
      }

    }
    else if ( mocCtx->tagLen )
    {
        if (0 != memcmp((ubyte *)mocCtx->tag, pInput + inl,
                        mocCtx->tagLen ? mocCtx->tagLen : AES_BLOCK_SIZE))
        {
            retLen = -1;
        }
    }
    if (NULL != pInput)
    {
        DIGI_MEMSET(pInput, 0x00, (usize)inl);
        DIGI_FREE((void **) &pInput);
    }

    return (int)retLen;
  }
  else
  {
        pIv = IS_AES_CTR_CIPHER(ctx) ? NULL : mocCtx->wIv;

        if (EVP_CIPHER_CTX_nid(ctx) == NID_chacha20)
        {
            /* The IV must be NULL for all calls beyond the first cipherupdate
             * for chacha */
            if (1 == mocCtx->init)
            {
                pIv = NULL;
            }
            if (0 == mocCtx->init)
            {
                mocCtx->init = 1;
            }
        }

        DIGI_MEMCPY(out, in, (sbyte4)inl);

        status = mocCtx->pEncrAlgo->pBEAlgo->cipherFunc(
            MOC_SYM(hwAccelCtx) mocCtx->pEncrData, out,
            (int)inl, is_encrypt, pIv);

        return OK > status ? 0 : 1;

        /* verify cbc/ctr/xts cases */
    }
}

#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#define IS_TYPE_SET_IVLEN(type) (type == EVP_CTRL_GCM_SET_IVLEN || type == EVP_CTRL_CCM_SET_IVLEN)
#define IS_TYPE_GET_TAG(type)   (type == EVP_CTRL_GCM_GET_TAG   || type == EVP_CTRL_CCM_GET_TAG)
#define IS_TYPE_SET_TAG(type)   (type == EVP_CTRL_GCM_SET_TAG   || type == EVP_CTRL_CCM_SET_TAG)
#else
#define IS_TYPE_SET_IVLEN(type) (type == EVP_CTRL_CCM_SET_IVLEN)
#define IS_TYPE_GET_TAG(type)   (type == EVP_CTRL_CCM_GET_TAG)
#define IS_TYPE_SET_TAG(type)   (type == EVP_CTRL_CCM_SET_TAG)
#endif

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_cipherCtxCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int     status = 0;
    MOC_EVP_CIPHER_CTX *mocCtx = NULL;

    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    if(IS_TYPE_SET_IVLEN(type) && IS_AEAD_CIPHER(ctx))
    {
        mocCtx->ivLen = arg;
        status = 1;
    }
    else if(IS_TYPE_GET_TAG(type) && IS_AEAD_CIPHER(ctx))
    {
        DIGI_MEMCPY((ubyte *)ptr, mocCtx->tag, arg); /* no need to check return code */
        status = 1;
    }
    else if (IS_TYPE_SET_TAG(type) && IS_AEAD_CIPHER(ctx))
    {
        mocCtx->tagLen = arg;
        if(ptr)
            DIGI_MEMCPY(mocCtx->tag, ptr, arg);
        status = 1;
    }
    else if (EVP_CTRL_COPY == type)
    {
        status = DIGI_EVP_CIPHER_ctrl(ctx, type, arg, ptr);
    }
    return status;
}

#define WRAP_FLAGS  (EVP_CIPH_WRAP_MODE \
                     | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                     | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)

int DIGI_EVP_AESWrapInit(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc) {

    MOC_EVP_CIPHER_CTX *mocCtx = NULL;
    ubyte *pKey = NULL;

    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    if (NULL != key)
    {
        if (NULL != mocCtx->key)
        {
            OPENSSL_free(mocCtx->key);
            mocCtx->key = NULL;
        }
        pKey = OPENSSL_malloc(ctx->key_len);
        DIGI_MEMCPY(pKey, key, ctx->key_len);
    }
    else if (NULL != mocCtx->key)
    {
        pKey = mocCtx->key;
        mocCtx->key = NULL;
    }

    /* Do initialize the MOC_EVP_CIPHER_CTX structure */
    DIGI_EVP_CIPHER_CTX_init(mocCtx);
    DIGI_EVP_CIPHER_CTX_cleanup(MOC_SYM(hwAccelCtx) mocCtx);

    mocCtx->key = pKey;

    return 1;
}

#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static int MOC_EVP_doAESWrapCipherEx(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen, ubyte transform)
{
    MSTATUS status = -1;
    MOC_EVP_CIPHER_CTX *mocCtx = NULL;
    ubyte4 len = 0;

    if (!in)
        return 0;
    if (inlen % 8)
        return -1;
    if (ctx->encrypt && inlen < 8)
    {
        return -1;
    }
    if (!ctx->encrypt && inlen < 16)
    {
        return -1;
    }

    if (!out)
    {
        if (ctx->encrypt)
        {
            return (int)inlen + 8;
        }
        else
        {
            return (int)inlen - 8;
	}
    }

    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    /* Original flow assumes out buffer is always large enough so we do the same here */
    len = inlen + 16;

    if(ctx->encrypt)
    {
        status = CRYPTO_INTERFACE_AESKWRAP_encrypt3394Ex((ubyte*)mocCtx->key, ctx->key_len, (ubyte*)in, (ubyte4)inlen, (ubyte*)out, len, &len, transform);
        if (status < OK)
        {
            return status;
        }
    }
    else
    {
        status = CRYPTO_INTERFACE_AESKWRAP_decrypt3394Ex((ubyte*)mocCtx->key, ctx->key_len, (ubyte*)in, (ubyte4)inlen, out, inlen, &len, transform);
        if(status < OK)
        {
            return status;
        }

        return len;
    }

    if (ctx->encrypt)
    {
        return (int)inlen + 8;
    }
    else
    {
        return (int)inlen - 8;
    }
}

int DIGI_EVP_doAESWrapCipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen, int pad, ubyte transform) {
    MSTATUS status = -1;
    MOC_EVP_CIPHER_CTX *mocCtx = NULL;
    ubyte4 len = 0;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

    if (FALSE == pad)
    {
        return MOC_EVP_doAESWrapCipherEx(ctx, out, in, inlen, transform);
    }

    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    /* Assume the output buffer is large enough, calling with NULL output buffer 
     * tells caller the buffer size needed */
    len = inlen + 16;

    if(ctx->encrypt)
    {
        status = CRYPTO_INTERFACE_AESKWRAP_encrypt5649Ex (
            (ubyte*)mocCtx->key, ctx->key_len, (ubyte*)in, (ubyte4)inlen, (ubyte*)out,
            len, &len, transform);
        if (status < OK)
        {
            return status;
        }
    }
    else
    {
        status = CRYPTO_INTERFACE_AESKWRAP_decrypt5649Ex (
            (ubyte*)mocCtx->key, ctx->key_len, (ubyte*)in, (ubyte4)inlen, out, inlen, 
            &len, transform);
        if(status < OK)
        {
            return status;
        }
    }

    return len;
}

int DIGI_EVP_doAESWrapCipherOld(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen) {
    MSTATUS status = -1;
    MOC_EVP_CIPHER_CTX *mocCtx = NULL;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

    if (!in)
        return 0;
    if (inlen % 8)
        return -1;
    if (ctx->encrypt && inlen < 8)
    {
        return -1;
    }
    if (!ctx->encrypt && inlen < 16)
    {
        return -1;
    }

    if (!out)
    {
        if (ctx->encrypt)
        {
            return (int)inlen + 8;
        }
        else
        {
            return (int)inlen - 8;
	}
    }

    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    if(ctx->encrypt)
    {
        status = AESKWRAP_encrypt((ubyte*)mocCtx->key, ctx->key_len, (const ubyte*)in, (ubyte4)inlen, (ubyte*)out);
        if (status < OK)
        {
            return status;
        }
    }
    else
    {
	    status = AESKWRAP_decrypt((ubyte*)mocCtx->key, ctx->key_len, (const ubyte*)in, (ubyte4)inlen, (ubyte*)out);
        if(status < OK)
        {
	    return status;
        }
    }

    if (ctx->encrypt)
    {
        return (int)inlen + 8;
    }
    else
    {
        return (int)inlen - 8;
    }
}

#else
int DIGI_EVP_doAESWrapCipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen) {
    MSTATUS status = -1;
    MOC_EVP_CIPHER_CTX *mocCtx = NULL;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

    if (!in)
        return 0;
    if (inlen % 8)
        return -1;
    if (ctx->encrypt && inlen < 8)
    {
        return -1;
    }
    if (!ctx->encrypt && inlen < 16)
    {
        return -1;
    }

    if (!out)
    {
        if (ctx->encrypt)
        {
            return (int)inlen + 8;
        }
        else
        {
            return (int)inlen - 8;
	}
    }

    mocCtx = DIGI_EVP_CIPHER_CTX_getCipherData(ctx);
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    if(ctx->encrypt)
    {
        status = AESKWRAP_encrypt((ubyte*)mocCtx->key, ctx->key_len, (const ubyte*)in, (ubyte4)inlen, (ubyte*)out);
        if (status < OK)
        {
            return status;
        }
    }
    else
    {
	    status = AESKWRAP_decrypt((ubyte*)mocCtx->key, ctx->key_len, (const ubyte*)in, (ubyte4)inlen, (ubyte*)out);
        if(status < OK)
        {
	    return status;
        }
    }

    if (ctx->encrypt)
    {
        return (int)inlen + 8;
    }
    else
    {
        return (int)inlen - 8;
    }
}
#endif /* ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__*/


static const char *engine_moc_evp_id = "mocana";
static const char *engine_moc_evp_name = "Mocana engine support";

static int moc_evp_cipher_nids[] = {
    NID_aes_128_ecb,
    NID_aes_128_cbc,
    NID_aes_128_ofb128,
    NID_aes_128_cfb128,
#ifndef __DISABLE_AES_CTR_CIPHER__
    NID_aes_128_ctr,
    NID_aes_192_ctr,
    NID_aes_256_ctr,
#endif
    NID_aes_192_ecb,
    NID_aes_192_cbc,
    NID_aes_192_ofb128,
    NID_aes_192_cfb128,
    NID_aes_256_ecb,
    NID_aes_256_cbc,
    NID_aes_256_ofb128,
    NID_aes_256_cfb128,
#if !defined(__DISABLE_DIGICERT_SUITE_B__)
    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm,
#endif
#ifndef __DISABLE_AES_CCM__
    NID_aes_256_ccm,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    NID_aes_192_ccm,
    NID_aes_128_ccm,
#endif
#endif /* __DISABLE_AES_CCM__ */
    NID_aes_128_xts,
    NID_aes_256_xts
#ifndef __DISABLE_3DES_CIPHERS__
    ,
    NID_des_ede3_ecb,
    NID_des_ede3_cbc
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && !defined(__DISABLE_3DES_TWO_KEY_CIPHER__)
    ,
    NID_des_ede_ecb,
    NID_des_ede_cbc
#endif
#endif
#ifdef __ENABLE_DES_CIPHER__
    ,
    NID_des_cbc,
    NID_des_ecb
#endif
#ifdef __ENABLE_DIGICERT_RC5__
    ,
    NID_rc5_ecb,
    NID_rc5_cbc
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
    ,
    NID_rc4
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    ,
    NID_rc4_40
#endif
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
    ,
    NID_rc2_ecb,
    NID_rc2_cbc,
    NID_rc2_40_cbc
#endif
#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER)
    ,
    NID_chacha20
#ifdef __ENABLE_DIGICERT_POLY1305__
    ,
    NID_chacha20_poly1305
#endif
#endif
    ,
    NID_id_aes128_wrap,
    NID_id_aes192_wrap,
    NID_id_aes256_wrap
#if defined(__ENABLE_BLOWFISH_CIPHERS__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ,
    NID_bf_cbc
#endif
};

/* Some AES-related constants */
#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32
#define THREE_DES_KEY_SIZE      24
#define RC4_KEY_SIZE            16

#define EVP_CIPHER_block_size_ECB           AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CBC           AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_OFB           AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CFB           AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CTR           AES_BLOCK_SIZE
#define EVP_CIPHER_des_ede3_block_size_ECB  THREE_DES_BLOCK_SIZE
#define EVP_CIPHER_des_ede3_block_size_CBC  THREE_DES_BLOCK_SIZE
#define EVP_CIPHER_des_block_size_CBC       DES_BLOCK_SIZE
#define EVP_CIPHER_des_block_size_ECB       DES_BLOCK_SIZE

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/*
 * Declaring so many ciphers by hand would be a pain. Instead introduce a bit
 * of preprocessor magic :-)
 */
#define DECLARE_AES_EVP(ksize,lmode,umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {     \
        NID_aes_##ksize##_##lmode,                              \
        EVP_CIPHER_block_size_##umode,                          \
        AES_KEY_SIZE_##ksize,                                   \
        AES_BLOCK_SIZE,                                         \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_##umode##_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        0,                                                      \
        DIGI_EVP_cipherInit,		                                \
	    DIGI_EVP_doCipher,		                                \
        DIGI_EVP_cipherCleanup,		                            \
        sizeof(MOC_EVP_CIPHER_CTX),	                            \
        EVP_CIPHER_set_asn1_iv,                                 \
        EVP_CIPHER_get_asn1_iv,                                 \
        DIGI_EVP_CIPHER_ctrl,                                    \
        NULL,                                                   \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,   \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   \
        NULL                                                    \
};					                                            \
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_AES_EVP_CTR(ksize,lmode,umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {     \
        NID_aes_##ksize##_##lmode,                              \
        1,                                                      \
        AES_KEY_SIZE_##ksize,                                   \
        AES_BLOCK_SIZE,                                         \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTR_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        0,                                                      \
        DIGI_EVP_cipherInit,		                                \
	    DIGI_EVP_doCipher,		                                \
        DIGI_EVP_cipherCleanup,		                            \
        sizeof(MOC_EVP_CIPHER_CTX),	                            \
        EVP_CIPHER_set_asn1_iv,                                 \
        EVP_CIPHER_get_asn1_iv,                                 \
        DIGI_EVP_CIPHER_ctrl,                                    \
        NULL,                                                   \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,   \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   \
        NULL                                                    \
};					                                            \
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_AES_EVP_CUSTOM(ksize,lmode,umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {     \
        NID_aes_##ksize##_##lmode,                              \
        EVP_CIPHER_block_size_##umode,                          \
        AES_KEY_SIZE_##ksize,                                   \
        AES_BLOCK_SIZE,                                         \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_##umode##_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_CUSTOM_CIPHER,    \
        0,                                                      \
        DIGI_EVP_cipherInit,		                                \
	    MOC_EVP_doCustomCipher,		                            \
        DIGI_EVP_cipherCleanup,		                            \
        sizeof(MOC_EVP_CIPHER_CTX),	                            \
        EVP_CIPHER_set_asn1_iv,                                 \
        EVP_CIPHER_get_asn1_iv,                                 \
        DIGI_EVP_CIPHER_ctrl,                                    \
        NULL,                                                   \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,   \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   \
        NULL                                                    \
};					                                            \
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_DES_EVP(cipher,lmode,umode,ksize)      \
static const EVP_CIPHER _s_hidden_##cipher##_##lmode = {       \
        NID_##cipher##_##lmode,                                \
        EVP_CIPHER_##cipher##_block_size_##umode,              \
        (ksize),                                               \
        DES_BLOCK_SIZE,                                        \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_##umode##_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        0,                                                     \
        DIGI_EVP_ThreeDesInit,		                           \
	    DIGI_EVP_doCipher,		                               \
        DIGI_EVP_cipherCleanup,		                           \
        sizeof(MOC_EVP_CIPHER_CTX),	                           \
        EVP_CIPHER_set_asn1_iv,                                \
        EVP_CIPHER_get_asn1_iv,                                \
        DIGI_EVP_CIPHER_ctrl,                                   \
        NULL,                                                  \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,  \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  \
        NULL                                                   \
};					                                           \
static const EVP_CIPHER * _hidden_##cipher##_##lmode = &_s_hidden_##cipher##_##lmode

#define DECLARE_STREAM_EVP(cipher)                  \
static const EVP_CIPHER _s_hidden_##cipher = {                 \
        NID_##cipher,                                          \
        1,                                                     \
        RC4_KEY_SIZE,                                          \
        0,                                                     \
        0 | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        0,                                                     \
        DIGI_EVP_cipherInit,		                               \
	    DIGI_EVP_doCipher,		                               \
        DIGI_EVP_cipherCleanup,		                           \
        sizeof(MOC_EVP_CIPHER_CTX),	                           \
        NULL,                                                  \
        NULL,                                                  \
        DIGI_EVP_CIPHER_ctrl,                                   \
        NULL,                                                  \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,  \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  \
        NULL                                                   \
};					                                           \
static const EVP_CIPHER * _hidden_##cipher = &_s_hidden_##cipher


#if defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0)
#define EVP_AES_AEAD_FLAGS (EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_AEAD_CIPHER)
#else
#define EVP_AES_AEAD_FLAGS (EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)
#endif

#define DECLARE_AES_AEAD_EVP(ksize, ivsize, lmode, umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {       \
        NID_aes_##ksize##_##lmode,                                \
        AES_BLOCK_SIZE,                                           \
        AES_KEY_SIZE_##ksize,                                     \
        (ivsize),                                                 \
        EVP_AES_AEAD_FLAGS | EVP_CIPH_##umode##_MODE,             \
        0,                                                        \
        DIGI_EVP_cipherInit,		                                  \
	    DIGI_EVP_doCipher,		                                  \
        DIGI_EVP_cipherCleanup,		                              \
        sizeof(MOC_EVP_CIPHER_CTX),	                              \
        EVP_CIPHER_set_asn1_iv,                                   \
        EVP_CIPHER_get_asn1_iv,                                   \
        DIGI_EVP_cipherCtxCtrl,                                    \
        NULL,                                                     \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,     \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,     \
        NULL                                                      \
};					                                              \
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_AES_GCM_AEAD_EVP(ksize, ivsize, lmode, umode)               \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {                 \
        NID_aes_##ksize##_##lmode,                                          \
        1,                                                                  \
        AES_KEY_SIZE_##ksize,                                               \
        (ivsize),                                                           \
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_GCM_MODE, \
        0,                                                                  \
        DIGI_EVP_AES_GCM_cipherInit,                                         \
        DIGI_EVP_AES_GCM_doCipher,                                           \
        DIGI_EVP_AES_GCM_cipherCleanup,                                      \
        sizeof(MOC_EVP_AES_GCM_CIPHER_CTX),                                 \
        NULL,                                                               \
        NULL,                                                               \
        DIGI_EVP_AES_GCM_cipherCtxCtrl,                                      \
        NULL,                                                               \
        0, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL,               \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,               \
        NULL                                                                \
};					                                                        \
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#else /* if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */
/*
 * Declaring so many ciphers by hand would be a pain. Instead introduce a bit
 * of preprocessor magic :-)
 */
#define DECLARE_AES_EVP(ksize,lmode,umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {       \
        NID_aes_##ksize##_##lmode,              \
        EVP_CIPHER_block_size_##umode,  \
        AES_KEY_SIZE_##ksize,           \
        AES_BLOCK_SIZE,                 \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_##umode##_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        DIGI_EVP_cipherInit,		\
	DIGI_EVP_doCipher,		\
        DIGI_EVP_cipherCleanup,		\
        sizeof(MOC_EVP_CIPHER_CTX),	\
        EVP_CIPHER_set_asn1_iv,         \
        EVP_CIPHER_get_asn1_iv,         \
        DIGI_EVP_CIPHER_ctrl,            \
        NULL                            \
};					\
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_AES_EVP_CTR(ksize,lmode,umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {       \
        NID_aes_##ksize##_##lmode,              \
        1,  \
        AES_KEY_SIZE_##ksize,           \
        AES_BLOCK_SIZE,                 \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTR_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        DIGI_EVP_cipherInit,		\
	DIGI_EVP_doCipher,		\
        DIGI_EVP_cipherCleanup,		\
        sizeof(MOC_EVP_CIPHER_CTX),	\
        EVP_CIPHER_set_asn1_iv,         \
        EVP_CIPHER_get_asn1_iv,         \
        DIGI_EVP_CIPHER_ctrl,                           \
        NULL                            \
};					\
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_AES_EVP_CUSTOM(ksize,lmode,umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {       \
        NID_aes_##ksize##_##lmode,              \
        EVP_CIPHER_block_size_##umode,  \
        AES_KEY_SIZE_##ksize,           \
        AES_BLOCK_SIZE,                 \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_##umode##_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_CUSTOM_CIPHER,    \
        DIGI_EVP_cipherInit,		\
	MOC_EVP_doCustomCipher,		\
        DIGI_EVP_cipherCleanup,		\
        sizeof(MOC_EVP_CIPHER_CTX),	\
        EVP_CIPHER_set_asn1_iv,         \
        EVP_CIPHER_get_asn1_iv,         \
        DIGI_EVP_CIPHER_ctrl,            \
        NULL                            \
};					\
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_DES_EVP(cipher,lmode,umode,ksize)      \
static const EVP_CIPHER _s_hidden_##cipher##_##lmode = {       \
        NID_##cipher##_##lmode,              \
        EVP_CIPHER_##cipher##_block_size_##umode,  \
        (ksize),           \
        DES_BLOCK_SIZE,                 \
        0 | EVP_CIPH_##umode##_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_##umode##_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        DIGI_EVP_ThreeDesInit,		\
	DIGI_EVP_doCipher,		\
        DIGI_EVP_cipherCleanup,		\
        sizeof(MOC_EVP_CIPHER_CTX),	\
        EVP_CIPHER_set_asn1_iv,         \
        EVP_CIPHER_get_asn1_iv,         \
        DIGI_EVP_CIPHER_ctrl,                           \
        NULL                            \
};					\
static const EVP_CIPHER * _hidden_##cipher##_##lmode = &_s_hidden_##cipher##_##lmode

#define DECLARE_STREAM_EVP(cipher)      \
static const EVP_CIPHER _s_hidden_##cipher = {       \
        NID_##cipher,              \
        1,  \
        RC4_KEY_SIZE,           \
        0,                 \
        0 | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,    \
        DIGI_EVP_cipherInit,		\
	    DIGI_EVP_doCipher,		\
        DIGI_EVP_cipherCleanup,		\
        sizeof(MOC_EVP_CIPHER_CTX),	\
        NULL,         \
        NULL,         \
        DIGI_EVP_CIPHER_ctrl,                           \
        NULL                            \
};					\
static const EVP_CIPHER * _hidden_##cipher = &_s_hidden_##cipher


#if defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0)
#define EVP_AES_AEAD_FLAGS (EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_AEAD_CIPHER)
#else
#define EVP_AES_AEAD_FLAGS (EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)
#endif

#define DECLARE_AES_AEAD_EVP(ksize, ivsize, lmode, umode)      \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {       \
        NID_aes_##ksize##_##lmode,              \
        AES_BLOCK_SIZE,  \
        AES_KEY_SIZE_##ksize,           \
        (ivsize),                 \
        EVP_AES_AEAD_FLAGS | EVP_CIPH_##umode##_MODE,    \
        DIGI_EVP_cipherInit,		\
	DIGI_EVP_doCipher,		\
        DIGI_EVP_cipherCleanup,		\
        sizeof(MOC_EVP_CIPHER_CTX),	\
        EVP_CIPHER_set_asn1_iv,         \
        EVP_CIPHER_get_asn1_iv,         \
        DIGI_EVP_cipherCtxCtrl,                           \
        NULL                            \
};					\
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

#define DECLARE_AES_GCM_AEAD_EVP(ksize, ivsize, lmode, umode)               \
static const EVP_CIPHER _s_hidden_aes_##ksize##_##lmode = {                 \
        NID_aes_##ksize##_##lmode,                                          \
        1,                                                                  \
        AES_KEY_SIZE_##ksize,                                               \
        (ivsize),                                                           \
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_GCM_MODE, \
        DIGI_EVP_AES_GCM_cipherInit,                                         \
        DIGI_EVP_AES_GCM_doCipher,                                           \
        DIGI_EVP_AES_GCM_cipherCleanup,                                      \
        sizeof(MOC_EVP_AES_GCM_CIPHER_CTX),                                 \
        NULL,                                                               \
        NULL,                                                               \
        DIGI_EVP_AES_GCM_cipherCtxCtrl,                                      \
        NULL                                                                \
};                                                                          \
static const EVP_CIPHER * _hidden_aes_##ksize##_##lmode = &_s_hidden_aes_##ksize##_##lmode

/* TODO unify ifdefs */
#endif /* if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static const EVP_CIPHER _s_hidden_aeswrap_128 = {
	NID_id_aes128_wrap,
	16,
	16,
	8,
	WRAP_FLAGS,
    0,
	DIGI_EVP_AESWrapInit,
    DIGI_EVP_doAESWrapCipherOld,
	DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL,
    0, NULL, NULL, NULL, 0, NULL, 
    NULL, /* newctx */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static const EVP_CIPHER _s_hidden_aeswrap_192 = {
	NID_id_aes192_wrap,
	16,
	24,
	8,
	WRAP_FLAGS,
    0,
	DIGI_EVP_AESWrapInit,
        DIGI_EVP_doAESWrapCipherOld,
	DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL,
    0, NULL, NULL, NULL, 0, NULL, 
    NULL, /* newctx */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static const EVP_CIPHER _s_hidden_aeswrap_256 = {
	NID_id_aes256_wrap,
	16,
	32,
	8,
	WRAP_FLAGS,
    0,
	DIGI_EVP_AESWrapInit,
        DIGI_EVP_doAESWrapCipherOld,
	DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL,
    0, NULL, NULL, NULL, 0, NULL, 
    NULL, /* newctx */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#ifndef __DISABLE_AES_XTS__

static const EVP_CIPHER _s_hidden_aes_128_xts = {
	NID_aes_128_xts,
	1,
	32,
	AES_BLOCK_SIZE,
	EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
    0,
	DIGI_EVP_cipherInit,
        DIGI_EVP_doCipher,
        DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL,
    0, NULL, NULL, NULL, 0, NULL, 
    NULL, /* newctx */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static const EVP_CIPHER _s_hidden_aes_256_xts = {
	NID_aes_256_xts,
	1,
	64,
	AES_BLOCK_SIZE,
	EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
    0,
	DIGI_EVP_cipherInit,
        DIGI_EVP_doCipher,
        DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL,
    0, NULL, NULL, NULL, 0, NULL, 
    NULL, /* newctx */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif

#else /* if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */
static const EVP_CIPHER _s_hidden_aeswrap_128 = {
	NID_id_aes128_wrap,
	16,
	16,
	8,
	WRAP_FLAGS,
	DIGI_EVP_AESWrapInit,
    DIGI_EVP_doAESWrapCipher,
	DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL
};

static const EVP_CIPHER _s_hidden_aeswrap_192 = {
	NID_id_aes192_wrap,
	16,
	24,
	8,
	WRAP_FLAGS,
	DIGI_EVP_AESWrapInit,
        DIGI_EVP_doAESWrapCipher,
	DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL
};

static const EVP_CIPHER _s_hidden_aeswrap_256 = {
	NID_id_aes256_wrap,
	16,
	32,
	8,
	WRAP_FLAGS,
	DIGI_EVP_AESWrapInit,
        DIGI_EVP_doAESWrapCipher,
	DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL
};

#ifndef __DISABLE_AES_XTS__

static const EVP_CIPHER _s_hidden_aes_128_xts = {
	NID_aes_128_xts,
	1,
	32,
	AES_BLOCK_SIZE,
	EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
	DIGI_EVP_cipherInit,
        DIGI_EVP_doCipher,
        DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL
};

static const EVP_CIPHER _s_hidden_aes_256_xts = {
	NID_aes_256_xts,
	1,
	64,
	AES_BLOCK_SIZE,
	EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
	DIGI_EVP_cipherInit,
        DIGI_EVP_doCipher,
        DIGI_EVP_cipherCleanup,
	sizeof(MOC_EVP_CIPHER_CTX),
	NULL, NULL, DIGI_EVP_CIPHER_ctrl, NULL
};

#endif

#endif /* if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */

static const EVP_CIPHER *_hidden_aeswrap_128 = &_s_hidden_aeswrap_128;
static const EVP_CIPHER *_hidden_aeswrap_192 = &_s_hidden_aeswrap_192;
static const EVP_CIPHER *_hidden_aeswrap_256 = &_s_hidden_aeswrap_256;
#ifndef __DISABLE_AES_XTS__
static const EVP_CIPHER *_hidden_aes_128_xts = &_s_hidden_aes_128_xts;
static const EVP_CIPHER *_hidden_aes_256_xts = &_s_hidden_aes_256_xts;
#endif


DECLARE_AES_EVP(128, ecb, ECB);
DECLARE_AES_EVP(128, cbc, CBC);
DECLARE_AES_EVP_CUSTOM(128, ofb128, OFB);
DECLARE_AES_EVP_CUSTOM(128, cfb128, CFB);
DECLARE_AES_EVP_CTR(128, ctr, CTR);
DECLARE_AES_EVP_CTR(192, ctr, CTR);
DECLARE_AES_EVP_CTR(256, ctr, CTR);
DECLARE_AES_EVP(192, ecb, ECB);
DECLARE_AES_EVP(192, cbc, CBC);
DECLARE_AES_EVP_CUSTOM(192, ofb128, OFB);
DECLARE_AES_EVP_CUSTOM(192, cfb128, CFB);
DECLARE_AES_EVP(256, ecb, ECB);
DECLARE_AES_EVP(256, cbc, CBC);
DECLARE_AES_EVP_CUSTOM(256, ofb128, OFB);
DECLARE_AES_EVP_CUSTOM(256, cfb128, CFB);

#if !defined(__DISABLE_DIGICERT_SUITE_B__)
DECLARE_AES_GCM_AEAD_EVP(128, 12, gcm, GCM);
DECLARE_AES_GCM_AEAD_EVP(192, 12, gcm, GCM);
DECLARE_AES_GCM_AEAD_EVP(256, 12, gcm, GCM);
#endif
#ifndef __DISABLE_AES_CCM__
DECLARE_AES_AEAD_EVP(256, 12, ccm, CCM);
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
DECLARE_AES_AEAD_EVP(192, 12, ccm, CCM);
DECLARE_AES_AEAD_EVP(128, 12, ccm, CCM);
#endif
#endif

#ifndef __DISABLE_3DES_CIPHERS__
DECLARE_DES_EVP(des_ede3, ecb, ECB, THREE_DES_KEY_LENGTH);
DECLARE_DES_EVP(des_ede3, cbc, CBC, THREE_DES_KEY_LENGTH);
#endif
#ifdef __ENABLE_DES_CIPHER__
DECLARE_DES_EVP(des, cbc, CBC, DES_KEY_LENGTH);
DECLARE_DES_EVP(des, ecb, ECB, DES_KEY_LENGTH);
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
DECLARE_STREAM_EVP(rc4);
#endif



#ifdef __ENABLE_ARC2_CIPHERS__

int DIGI_EVP_rc2Ctrl(
    EVP_CIPHER_CTX *pCtx,
    int type,
    int arg,
    void *pPtr
    )
{
    int retVal = -1;
    MOC_EVP_CIPHER_CTX *pMocEvpCtx;

    if (NULL != pCtx)
    {
        pMocEvpCtx = DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);

        switch (type)
        {
            /* During initialization set the default effective key bits.
             */
            case EVP_CTRL_INIT:
                pMocEvpCtx->rc2EffectiveKeyBits = EVP_CIPHER_CTX_key_length(pCtx) * 8;
                retVal = 1;
                break;

            /* Get the set of key bits set for RC2.
             */
            case EVP_CTRL_GET_RC2_KEY_BITS:
                *(int *) pPtr = pMocEvpCtx->rc2EffectiveKeyBits;
                retVal = 1;
                break;

            /* Set the key bits for RC2.
             */
            case EVP_CTRL_SET_RC2_KEY_BITS:
                if (arg > 0)
                {
                    pMocEvpCtx->rc2EffectiveKeyBits = arg;
                    retVal = 1;
                }
                else
                {
                    retVal = 0;
                }
                break;

            /* Copy RC2 context.
             */
            case EVP_CTRL_COPY:
                retVal = DIGI_EVP_CIPHER_ctrl(pCtx, type, arg, pPtr);
                break;
        }
    }

    return retVal;
}

/* RC2 ECB, CBC, and 40 CBC.
 */
static const EVP_CIPHER _s_hidden_rc2_ecb = {
    NID_rc2_ecb,
    8,
    16,
    0,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_cipherInit,
    DIGI_EVP_doCipher,
    DIGI_EVP_cipherCleanup,
    sizeof(MOC_EVP_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_rc2Ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_rc2_ecb = &_s_hidden_rc2_ecb;

static const EVP_CIPHER _s_hidden_rc2_cbc = {
    NID_rc2_cbc,
    8,
    16,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT | EVP_CIPH_CBC_MODE | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_cipherInit,
    DIGI_EVP_doCipher,
    DIGI_EVP_cipherCleanup,
    sizeof(MOC_EVP_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_rc2Ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_rc2_cbc = &_s_hidden_rc2_cbc;

static const EVP_CIPHER _s_hidden_rc2_40_cbc = {
    NID_rc2_40_cbc,
    8,
    5,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT | EVP_CIPH_CBC_MODE | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_cipherInit,
    DIGI_EVP_doCipher,
    DIGI_EVP_cipherCleanup,
    sizeof(MOC_EVP_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_rc2Ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_rc2_40_cbc = &_s_hidden_rc2_40_cbc;

#endif /* __ENABLE_ARC2_CIPHERS__ */

#ifdef __ENABLE_DIGICERT_RC5__

#define MOC_EVP_RC5_BLOCKSIZE 8 /* 64 bits */
#define MOC_EVP_RC5_KEYSIZE 16  /* 128 bits */
#define MOC_EVP_RC5_IVSIZE MOC_EVP_RC5_BLOCKSIZE   /* for cbc */
#define MOC_EVP_RC5_DEFAULT_ROUNDS 12

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_RC5_cipherInit(EVP_CIPHER_CTX *pCtx, const unsigned char *pKey,
                                  const unsigned char *pIv, int isEncrypt)
{
    MSTATUS status = OK;
    MOC_EVP_RC5_CIPHER_CTX *pMocRC5Ctx = NULL;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    
    pMocRC5Ctx = (MOC_EVP_RC5_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocRC5Ctx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    if (NULL == EVP_CIPHER_CTX_cipher(pCtx))
    {
        DIGI_EVP_WARN("%s: Cipher object NULL\n", __func__);
        return 0;
    }

    /* delete existing context if it is there */
    if (NULL != pMocRC5Ctx->pEncrData)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_MocDeleteRC5Ctx(&(pMocRC5Ctx->pEncrData));
#else 
        status = MocDeleteRC5Ctx(&(pMocRC5Ctx->pEncrData));
#endif
        if (OK != status)
            return 0;
    }
    
    /* don't delete the roundCount, reset encrypt */
    pMocRC5Ctx->encrypt = isEncrypt;
    
    /* for the MocCreateRC5Ctx ensure pIv is NULL check if we are doing ecb */
    if (!pCtx->cipher->iv_len)
        pIv = NULL; /* ok to modify passed by value pointer address */
    else if (NULL == pIv)
        pIv = pCtx->iv; /* If its not ecb and no IV is provided, use the IV set by OpenSSL */

    if (NULL != pKey)
    {
        if (NULL != pMocRC5Ctx->pKey)
        {
            DIGI_FREE((void **) &pMocRC5Ctx->pKey);
        }

        status = DIGI_MALLOC((void **)&(pMocRC5Ctx->pKey), pCtx->key_len);
        if (OK != status)
            return 0;

        DIGI_MEMCPY(pMocRC5Ctx->pKey, pKey, pCtx->key_len);
    }

    if (NULL != pMocRC5Ctx->pKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_MocCreateRC5Ctx(
#else
        status = MocCreateRC5Ctx(
#endif
                                (ubyte *) pMocRC5Ctx->pKey,
                                pCtx->key_len,
                                (ubyte *) pIv,
                                pCtx->cipher->iv_len,
                                pCtx->cipher->block_size * 8, /* our api takes it in bits */
                                pMocRC5Ctx->roundCount,
                                MOC_RC5_NO_PAD, /* padding not required. OpenSSL will handle it */
                                pMocRC5Ctx->encrypt,
                                &(pMocRC5Ctx->pEncrData));
    }

    return (OK != status) ? 0 : 1;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif 
int DIGI_EVP_RC5_doCipher(EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn, size_t inlen)
{
    MOC_EVP_RC5_CIPHER_CTX *pMocRC5Ctx = NULL;
    MSTATUS status = OK;
    ubyte4 outLen;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0; /* IMPORTANT, EVP_CIPH_FLAG_CUSTOM_CIPHER is not set so return 0 on error */
    }
    
    pMocRC5Ctx = (MOC_EVP_RC5_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    
    if (NULL == pMocRC5Ctx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    
    if (NULL != pIn)
    {
        /*
         first pass in NULL for the output buffer. If no output is
         given via this call we are ok. Otherwise we get the length needed and
         can call update again.
         */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_MocRC5Update(
#else
        status = MocRC5Update(
#endif
                               pMocRC5Ctx->pEncrData,
                               pMocRC5Ctx->encrypt,
                               (ubyte *) pIn,
                               (ubyte4) inlen,
                               NULL,
                               0,
                               &outLen
                               );
        if (OK == status)
            return 1; /* 0 bytes written */
        else if (ERR_BUFFER_TOO_SMALL != status)
            return 0;
        
        /* else ERR_BUFFER_TOO_SMALL == status and we now know the length */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_MocRC5Update(
#else
        status = MocRC5Update(
#endif
                               pMocRC5Ctx->pEncrData,
                               pMocRC5Ctx->encrypt,
                               (ubyte *) pIn,
                               (ubyte4) inlen,
                               (ubyte *) pOut,
                               outLen,
                               &outLen
                               );
    }
    else
    {
        /* We are done, no more data, call MocRC5Final, first get the length */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_MocRC5Final(
#else
        status = MocRC5Final(
#endif
                             pMocRC5Ctx->pEncrData,
                             pMocRC5Ctx->encrypt,
                             NULL,
                             0,
                             NULL,
                             0,
                             &outLen
                             );
        if (OK == status)
            return 1; /* 0 bytes written */
        else if (ERR_BUFFER_TOO_SMALL != status)
            return 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_MocRC5Final(
#else        
        status = MocRC5Final(
#endif
                             pMocRC5Ctx->pEncrData,
                             pMocRC5Ctx->encrypt,
                             NULL,
                             0,
                             (ubyte *)pOut,
                             outLen,
                             &outLen
                             );
        
    }
    
    /* IMPORTANT, EVP_CIPH_FLAG_CUSTOM_CIPHER is not set so return 1 for success */
    return (OK != status) ? 0 : 1;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_RC5_cipherCleanup(EVP_CIPHER_CTX *pCtx)
{
    MSTATUS status = OK;
    MOC_EVP_RC5_CIPHER_CTX *pMocRC5Ctx = NULL;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    
    pMocRC5Ctx = (MOC_EVP_RC5_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocRC5Ctx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    if (NULL != pMocRC5Ctx->pKey)
    {
        DIGI_MEMSET(pMocRC5Ctx->pKey, 0x00, pCtx->key_len);
        DIGI_FREE((void **) &(pMocRC5Ctx->pKey));
    }
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_MocDeleteRC5Ctx(&(pMocRC5Ctx->pEncrData));
#else 
    status = MocDeleteRC5Ctx(&(pMocRC5Ctx->pEncrData));
#endif
    pMocRC5Ctx->encrypt = 0;
    pMocRC5Ctx->roundCount = 0;
    
    return (OK != status) ? 0 : 1;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int DIGI_EVP_RC5_ctrl(EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr)
{
    MOC_EVP_RC5_CIPHER_CTX *pMocRC5Ctx;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    
    pMocRC5Ctx = (MOC_EVP_RC5_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocRC5Ctx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }

    switch (type)
    {
        /* During initialization set the default number of rounds. */
        case EVP_CTRL_INIT:
            pMocRC5Ctx->roundCount = MOC_EVP_RC5_DEFAULT_ROUNDS;
            pMocRC5Ctx->encrypt = 0;
            return 1;
            
            /* Get the number of rounds */
        case EVP_CTRL_GET_RC5_ROUNDS:
            if (NULL == pPtr)
                return 0;
            
            *((int *) pPtr) = (int) pMocRC5Ctx->roundCount;
            return 1;
            
           /* Set the number of rounds */
        case EVP_CTRL_SET_RC5_ROUNDS:
            if (arg > 0)
            {
                pMocRC5Ctx->roundCount = (ubyte4) arg;
                return 1;
            }
            else
                return 0;
        default:
            break;
    }
    
    return 0;
}

static const EVP_CIPHER _s_hidden_rc5_ecb = {
    NID_rc5_ecb,
    MOC_EVP_RC5_BLOCKSIZE,
    MOC_EVP_RC5_KEYSIZE,
    0,   /* iv size 0 for ecb */
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_RC5_cipherInit,
    DIGI_EVP_RC5_doCipher,
    DIGI_EVP_RC5_cipherCleanup,
    sizeof(MOC_EVP_RC5_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_RC5_ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_rc5_ecb = &_s_hidden_rc5_ecb;

static const EVP_CIPHER _s_hidden_rc5_cbc = {
    NID_rc5_cbc,
    MOC_EVP_RC5_BLOCKSIZE,
    MOC_EVP_RC5_KEYSIZE,
    MOC_EVP_RC5_IVSIZE,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT | EVP_CIPH_CBC_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_RC5_cipherInit,
    DIGI_EVP_RC5_doCipher,
    DIGI_EVP_RC5_cipherCleanup,
    sizeof(MOC_EVP_RC5_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_RC5_ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_rc5_cbc = &_s_hidden_rc5_cbc;

#endif /* __ENABLE_DIGICERT_RC5__ */

#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER)

#define MOC_EVP_CHACHA_BLOCK_SIZE 1 /* stream cipher */
#define MOC_EVP_CHACHA_KEY_SIZE 32
#define MOC_EVP_CHACHA_IV_SIZE 16 /* 4 byte LE counter followed by 12 byte nonce */
#define MOC_EVP_CHACHAPOLY_TAG_SIZE 16 /* We only allow 16 bytes, not less */

static const EVP_CIPHER _s_hidden_chacha20 = {
    NID_chacha20,
    MOC_EVP_CHACHA_BLOCK_SIZE,
    MOC_EVP_CHACHA_KEY_SIZE,
    MOC_EVP_CHACHA_IV_SIZE,
    EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_cipherInit,
    DIGI_EVP_doCipher,
    DIGI_EVP_cipherCleanup,
    sizeof(MOC_EVP_CIPHER_CTX),
    NULL,
    NULL,
    NULL,
    NULL
};
static const EVP_CIPHER * _hidden_chacha20 = &_s_hidden_chacha20;

#ifdef __ENABLE_DIGICERT_POLY1305__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int DIGI_EVP_CHACHAPOLY_cipherInit(EVP_CIPHER_CTX *pCtx, const unsigned char *pKey,
                                  const unsigned char *pIv, int isEncrypt)
{
    MSTATUS status = OK;
    MOC_EVP_CHACHAPOLY_CIPHER_CTX *pMocCtx = NULL;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    
    pMocCtx = (MOC_EVP_CHACHAPOLY_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocCtx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    if (NULL == EVP_CIPHER_CTX_cipher(pCtx))
    {
        DIGI_EVP_WARN("%s: Cipher object NULL\n", __func__);
        return 0;
    }
    
    /* delete existing context if it is there */
    if (NULL != pMocCtx->pEncrData)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx(&(pMocCtx->pEncrData));
#else
        status = ChaCha20Poly1305_deleteCtx(&(pMocCtx->pEncrData));
#endif
        if (OK != status)
        {
            DIGI_EVP_WARN("%s: Error: ChaCha20Poly1305_deleteCtx\n", __func__);
            return 0;
        }
    }

    if (NULL != pIv)
    {
        DIGI_MEMCPY(pMocCtx->pIv, pIv, MOC_EVP_CHACHA_NONCE_SIZE);
    }

    if (NULL != pKey)
    {
        /* delete the tag, reset encrypt */
        pMocCtx->encrypt = isEncrypt;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        pMocCtx->pEncrData = CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx( MOC_SYM(hwAccelDescr hwAccelCtx) (ubyte *) pKey,
                                                                      MOC_EVP_CHACHA_KEY_SIZE, pMocCtx->encrypt);
#else
        pMocCtx->pEncrData = ChaCha20Poly1305_createCtx( MOC_SYM(hwAccelDescr hwAccelCtx) (ubyte *) pKey,
                                                     MOC_EVP_CHACHA_KEY_SIZE, pMocCtx->encrypt);
#endif
        
        if (NULL == pMocCtx->pEncrData)
        {
            DIGI_EVP_WARN("%s: Error: ChaCha20Poly1305_createCtx\n", __func__);
            return 0;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ChaCha20Poly1305_update_nonce( MOC_SYM(hwAccelDescr hwAccelCtx) pMocCtx->pEncrData,
                                                                 (ubyte *) pIv, MOC_EVP_CHACHA_NONCE_SIZE);
#else
        status = ChaCha20Poly1305_update_nonce( MOC_SYM(hwAccelDescr hwAccelCtx) pMocCtx->pEncrData,
                                                (ubyte *) pIv, MOC_EVP_CHACHA_NONCE_SIZE);
#endif
        
        if (OK != status)
        {
            DIGI_EVP_WARN("%s: Error: ChaCha20Poly1305_update_nonce\n", __func__);
            return 0;
        }
    }

    return 1;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_CHACHAPOLY_doCipher(EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn, size_t inlen)
{
    MOC_EVP_CHACHAPOLY_CIPHER_CTX *pMocCtx = NULL;
    MSTATUS status = OK;
    int outLen = 0;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null pCtx Parameter\n", __func__);
        return -1; /* IMPORTANT, EVP_CIPH_FLAG_CUSTOM_CIPHER is set so return -1 on error */
    }
    
    pMocCtx = (MOC_EVP_CHACHAPOLY_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    
    if (NULL == pMocCtx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return -1;
    }
    
    if (NULL != pIn)  /* deal with input */
    {
        if (!inlen)
        {
            return 0;  /* OK no-op, return output length of 0 */
        }
        
        if (NULL == pOut) /* Update AAD */
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ChaCha20Poly1305_update_aad (MOC_SYM(hwAccelDescr hwAccelCtx)
                                                                   pMocCtx->pEncrData,
                                                                   (ubyte *) pIn,
                                                                   (ubyte4) inlen
                                                                   );
#else
            status = ChaCha20Poly1305_update_aad (MOC_SYM(hwAccelDescr hwAccelCtx)
                                                  pMocCtx->pEncrData,
                                                  (ubyte *) pIn,
                                                  (ubyte4) inlen
                                                  );
#endif
            if (OK != status)
            {
                DIGI_EVP_WARN("%s: ChaCha20Poly1305_update_aad failure\n", __func__);
                return -1;
            }
        }
        else /* update plaintext/ciphertext */
        {
            /* need to make a copy of the input as it'll be updated inplace */
            ubyte *pTemp = NULL;
            
            status = DIGI_MALLOC((void **) &pTemp, (ubyte4) inlen);
            if (OK != status)
            {
                DIGI_EVP_WARN("%s: DIGI_MALLOC failure\n", __func__);
                return -1;
            }
            
            DIGI_MEMCPY(pTemp, (ubyte *) pIn, (ubyte4) inlen); /* ok to not check return, pTemp/pIn known not null */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ChaCha20Poly1305_update_data (MOC_SYM(hwAccelDescr hwAccelCtx)
                                                                    pMocCtx->pEncrData,
                                                                    pTemp,
                                                                    (ubyte4) inlen
                                                                    );
#else
            status = ChaCha20Poly1305_update_data (MOC_SYM(hwAccelDescr hwAccelCtx)
                                                   pMocCtx->pEncrData,
                                                   pTemp,
                                                   (ubyte4) inlen
                                                   );
#endif
            if (OK != status)
            {
                DIGI_EVP_WARN("%s: ChaCha20Poly1305_update_data failure\n", __func__);
                DIGI_FREE((void **) &pTemp); /* ok to not check return */
                return -1;
            }
            
            DIGI_MEMCPY((ubyte *) pOut, pTemp, (ubyte4) inlen); /* ok to not check return, pOut/pTemp known not null */
            DIGI_FREE((void **) &pTemp); /* ok to not check return */
        }
        
        /* as per openssl, return inlen even when updating the aad */
        outLen = (int) inlen;
    }
    else  /* we are done, compute or verify the tag */
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ChaCha20Poly1305_final(MOC_SYM(hwAccelDescr hwAccelCtx)
                                                         pMocCtx->pEncrData,
                                                         pMocCtx->pTag,
                                                         MOC_EVP_CHACHAPOLY_TAG_LEN
                                                         );
#else
        status = ChaCha20Poly1305_final(MOC_SYM(hwAccelDescr hwAccelCtx)
                                        pMocCtx->pEncrData,
                                        pMocCtx->pTag,
                                        MOC_EVP_CHACHAPOLY_TAG_LEN
                                        );
#endif
        if (OK != status)
        {
            DIGI_EVP_WARN("%s: ChaCha20Poly1305_final failure\n", __func__);
            return -1;
        }
        
        /* outLen still 0 */
    }
    
    /* success, IMPORTANT: EVP_CIPH_FLAG_CUSTOM_CIPHER is set so return the number of bytes written */
    return outLen;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_CHACHAPOLY_cipherCleanup(EVP_CIPHER_CTX *pCtx)
{
    MSTATUS status = OK;
    MOC_EVP_CHACHAPOLY_CIPHER_CTX *pMocCtx = NULL;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    
    pMocCtx = (MOC_EVP_CHACHAPOLY_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocCtx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx(&(pMocCtx->pEncrData));
#else
    status = ChaCha20Poly1305_deleteCtx(&(pMocCtx->pEncrData));
#endif
    
    pMocCtx->encrypt = 0;
    DIGI_MEMSET(pMocCtx->pTag, 0x00, MOC_EVP_CHACHAPOLY_TAG_LEN); /* ok to ignore return code */
    
    return (OK != status) ? 0 : 1;
}
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int DIGI_EVP_CHACHAPOLY_ctrl(EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr)
{
    MOC_EVP_CHACHAPOLY_CIPHER_CTX *pMocCtx;
    
    if (NULL == pCtx)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    
    pMocCtx = (MOC_EVP_CHACHAPOLY_CIPHER_CTX *) DIGI_EVP_CIPHER_CTX_getCipherData(pCtx);
    if (NULL == pMocCtx)
    {
        DIGI_EVP_WARN("%s: Cipher data NULL\n", __func__);
        return 0;
    }
    
    switch (type)
    {
            /* During initialization zero the tag */
        case EVP_CTRL_INIT:
            DIGI_MEMSET(pMocCtx->pTag, 0x00, MOC_EVP_CHACHAPOLY_TAG_SIZE); /* ok to ignore return code */
            pMocCtx->encrypt = 0;
            return 1;
            
            /* Set the tag */
        case EVP_CTRL_AEAD_SET_TAG:
            if (MOC_EVP_CHACHAPOLY_TAG_SIZE != arg)
                return 0;

            if (NULL != pPtr)
                DIGI_MEMCPY(pMocCtx->pTag, pPtr, MOC_EVP_CHACHAPOLY_TAG_SIZE); /* ok to ignore return code */

            return 1;
            
            /* Get the tag */
        case EVP_CTRL_AEAD_GET_TAG:
            if (MOC_EVP_CHACHAPOLY_TAG_SIZE != arg)
                return 0;
            
            DIGI_MEMCPY(pPtr, pMocCtx->pTag, MOC_EVP_CHACHAPOLY_TAG_SIZE); /* ok to ignore return code */
            return 1;

        /* Set the IV length */
        case EVP_CTRL_AEAD_SET_IVLEN:
            if (MOC_EVP_CHACHA_NONCE_SIZE != arg)
                return 0;

            /* No need to store the IV length. ChaCha20Poly1305 API always
             * requires a 12 byte nonce. */
            return 1;

        default:
            break;
    }
    
    return 0;
}

static const EVP_CIPHER _s_hidden_chachapoly = {
    NID_chacha20_poly1305,
    MOC_EVP_CHACHA_BLOCK_SIZE,
    MOC_EVP_CHACHA_KEY_SIZE,
    MOC_EVP_CHACHA_NONCE_SIZE,
    EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_AEAD_CIPHER,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    0,
#endif
    DIGI_EVP_CHACHAPOLY_cipherInit,
    DIGI_EVP_CHACHAPOLY_doCipher,
    DIGI_EVP_CHACHAPOLY_cipherCleanup,
    sizeof(MOC_EVP_CHACHAPOLY_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_CHACHAPOLY_ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_chachapoly = &_s_hidden_chachapoly;

#endif /* __ENABLE_DIGICERT_POLY1305__ */
#endif /* defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER) */

#if defined(__ENABLE_BLOWFISH_CIPHERS__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static const EVP_CIPHER _s_hidden_bf_cbc = {
    NID_bf_cbc,
    8,
    16,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT | EVP_CIPH_CBC_MODE | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1,
    0,
    DIGI_EVP_cipherInit,
    DIGI_EVP_doCipher,
    DIGI_EVP_cipherCleanup,
    sizeof(MOC_EVP_CIPHER_CTX),
    NULL,
    NULL,
    DIGI_EVP_CIPHER_ctrl,
    NULL
};
static const EVP_CIPHER * _hidden_bf_cbc = &_s_hidden_bf_cbc;
#endif

static int
DIGI_EVP_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
			   const int **nids, int nid)
{
    /* If cipher is NULL then OpenSSL is requesting the total count of supported
     * cipher algorithms.
     */
    if (cipher == NULL)
    {
        *nids = moc_evp_cipher_nids;
        return (sizeof(moc_evp_cipher_nids) / sizeof(moc_evp_cipher_nids[0]));
    }

    *cipher = NULL;

    switch (nid) {
    case NID_aes_128_ecb:
        *cipher = _hidden_aes_128_ecb;
        break;
    case NID_aes_128_cbc:
        *cipher = _hidden_aes_128_cbc;
        break;
    case NID_aes_128_ofb128:
	*cipher = _hidden_aes_128_ofb128;
        break;
    case NID_aes_128_cfb128:
        *cipher = _hidden_aes_128_cfb128;
        break;
#ifndef __DISABLE_AES_CTR_CIPHER__
    case NID_aes_128_ctr:
	*cipher = _hidden_aes_128_ctr;
        break;
    case NID_aes_192_ctr:
	*cipher = _hidden_aes_192_ctr;
        break;
    case NID_aes_256_ctr:
	*cipher = _hidden_aes_256_ctr;
        break;
#endif
    case NID_aes_192_ecb:
        *cipher = _hidden_aes_192_ecb;
        break;
    case NID_aes_192_cbc:
        *cipher = _hidden_aes_192_cbc;
        break;
    case NID_aes_192_ofb128:
	*cipher = _hidden_aes_192_ofb128;
        break;
    case NID_aes_192_cfb128:
        *cipher = _hidden_aes_192_cfb128;
        break;
    case NID_aes_256_ecb:
        *cipher = _hidden_aes_256_ecb;
        break;
    case NID_aes_256_cbc:
        *cipher = _hidden_aes_256_cbc;
        break;
    case NID_aes_256_ofb128:
	*cipher = _hidden_aes_256_ofb128;
        break;
    case NID_aes_256_cfb128:
        *cipher = _hidden_aes_256_cfb128;
        break;
#if !defined(__DISABLE_DIGICERT_SUITE_B__)
    case NID_aes_128_gcm:
        *cipher = _hidden_aes_128_gcm;
        break;
    case NID_aes_192_gcm:
        *cipher = _hidden_aes_192_gcm;
        break;
    case NID_aes_256_gcm:
        *cipher = _hidden_aes_256_gcm;
        break;
#endif
#ifndef __DISABLE_AES_CCM__
    case NID_aes_256_ccm:
        *cipher = _hidden_aes_256_ccm;
        break;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    case NID_aes_192_ccm:
        *cipher = _hidden_aes_192_ccm;
        break;
    case NID_aes_128_ccm:
        *cipher = _hidden_aes_128_ccm;
        break;
#endif
#endif /* __DISABLE_AES_CCM__ */
#ifndef __DISABLE_AES_XTS__
    case NID_aes_128_xts:
        *cipher = _hidden_aes_128_xts;
        break;
    case NID_aes_256_xts:
        *cipher = _hidden_aes_256_xts;
        break;
#endif
#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER)
    case NID_chacha20:
        *cipher = _hidden_chacha20;
        break;
#ifdef __ENABLE_DIGICERT_POLY1305__
    case NID_chacha20_poly1305:
        *cipher = _hidden_chachapoly;
        break;
#endif
#endif
#ifndef __DISABLE_3DES_CIPHERS__
    case NID_des_ede3_ecb:
	    *cipher = _hidden_des_ede3_ecb;
	    break;
    case NID_des_ede3_cbc:
	    *cipher = _hidden_des_ede3_cbc;
	    break;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && !defined(__DISABLE_3DES_TWO_KEY_CIPHER__)
    case NID_des_ede_ecb:
	    *cipher = _hidden_des_ede3_ecb;
	    break;
    case NID_des_ede_cbc:
	    *cipher = _hidden_des_ede3_cbc;
	    break;
#endif
#endif
    case NID_id_aes128_wrap:
            *cipher = _hidden_aeswrap_128;
            break;
    case NID_id_aes192_wrap:
            *cipher = _hidden_aeswrap_192;
            break;
    case NID_id_aes256_wrap:
            *cipher = _hidden_aeswrap_256;
            break;
    }

    /* If FIPS mode is not being enforced then check if NID matches with any of
     * the non-FIPS algorithms.
     */
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (0 == DIGI_EVP_getFipsMode())
#endif
    {
        switch (nid)
        {
#ifdef __ENABLE_DES_CIPHER__
            case NID_des_cbc:
                *cipher = _hidden_des_cbc;
                break;
            case NID_des_ecb:
                *cipher = _hidden_des_ecb;
                break;
#endif
#ifdef __ENABLE_DIGICERT_RC5__
            case NID_rc5_ecb:
                *cipher = _hidden_rc5_ecb;
                break;
            case NID_rc5_cbc:
                *cipher = _hidden_rc5_cbc;
                break;
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
            case NID_rc4:
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
            case NID_rc4_40:
#endif
                *cipher = _hidden_rc4;
                break;
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
            case NID_rc2_ecb:
                *cipher = _hidden_rc2_ecb;
                break;
            case NID_rc2_cbc:
                *cipher = _hidden_rc2_cbc;
                break;
            case NID_rc2_40_cbc:
                *cipher = _hidden_rc2_40_cbc;
                break;
#endif /* __ENABLE_ARC2_CIPHERS__ */
#if defined(__ENABLE_BLOWFISH_CIPHERS__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            case NID_bf_cbc:
                *cipher = _hidden_bf_cbc;
                break;
#endif
        }
    }

    if (*cipher != NULL)
        return 1;
    else
        return 0;
}


#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
int moc_evp_digest_copy(
    EVP_MD_CTX *pDest,
    const EVP_MD_CTX *pSrc
    )
{
    MSTATUS status;
    ubyte4 contextSize;
    MOC_EVP_MD_CTX *pSrcCtx = NULL;
    MOC_EVP_MD_CTX *pDestCtx = NULL;

    /* OpenSSL will handle allocating the destination context.
     */
    if ( (NULL == pSrc) || (NULL == pDest) )
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

    /* Check if the Mocana context underneath is NULL. This context contains
     * the algorithm suite, which is just a set of function pointers, and a
     * context used to operate on data.
     */
    pSrcCtx = pSrc->md_data;
    pDestCtx = pDest->md_data;
    if ( (NULL == pSrcCtx) || (NULL == pDestCtx) )
    {
        DIGI_EVP_WARN("%s: Digest data NULL\n", __func__);
        return 1;
    }

    /* Nothing to copy over */
    if (NULL == pSrcCtx->pDigestAlgo && NULL == pSrcCtx->pDigestData)
    {
        DIGI_EVP_WARN("%s: Digest Algo and Digest data NULL\n", __func__);
        return 1;
    }

    /* OpenSSL will perform a shallow copy into the destination context. There
     * should be an algorithm suite here from the shallow copy.
     */
    if (NULL == pDestCtx->pDigestAlgo)
    {
        DIGI_EVP_WARN("%s: Digest Algo NULL\n", __func__);
        return 0;
    }

    /* If the source context doesn't contain an algorithm suite then set the
     * destination algorithm suite to NULL and don't copy anything over.
     */
    if (NULL == pSrcCtx->pDigestData)
    {
        pDestCtx->pDigestData = NULL;
        DIGI_EVP_WARN("%s: Digest Data to be copied is NULL\n", __func__);
        return 1;
    }

    /* If an algorithm suite is available then allocate the shell.
     */
    if (NULL != pDestCtx->pDigestAlgo)
    {
        status = pDestCtx->pDigestAlgo->pHashAlgo->allocFunc(
            MOC_HASH(hwAccelCtx) &(pDestCtx->pDigestData));
        if (OK != status)
        {
            DIGI_EVP_WARN("%s: AllocFunc Failed\n", __func__);
            return 0;
        }
    }

    /* At this point, determine which algorithm is being used, and use the
     * Crypto Interface to copy over the data. Note that a shallow copy may not
     * be sufficient. The context may have a CAP implementation underneath which
     * will require a deep copy of the context.
     */
    switch(pDestCtx->pDigestAlgo->NID)
    {
        case NID_md4WithRSAEncryption:
            contextSize = sizeof(struct MD4_CTX);
            break;

        case NID_md5WithRSAEncryption:
            contextSize = sizeof(struct MD5_CTX);
            break;

        case NID_sha1WithRSAEncryption:
	    case NID_dsaWithSHA1:
		    contextSize = sizeof(struct SW_SHA1_CTX);
	        break;

        case NID_sha256WithRSAEncryption:
	    case NID_sha224WithRSAEncryption:
		    contextSize = sizeof(struct SW_SHA256_CTX);
	        break;

	    case NID_sha384WithRSAEncryption:
	    case NID_sha512WithRSAEncryption:
		    contextSize = sizeof(struct SHA512_CTX);
	        break;

	    default:
	        DIGI_EVP_WARN("%s: NOT SUPPORTED DIGEST\n", __func__);
	        return 0;
    }

    /* Let the Crypto Interface determine whether a shallow copy or deep copy
     * must be made.
     */
    status = CRYPTO_INTERFACE_cloneHashCtx(
        pSrcCtx->pDigestData, pDestCtx->pDigestData, contextSize);
    if (OK != status)
    {
        DIGI_EVP_WARN("%s: CRYPTO_INTERFACE_cloneHashCtx failed\n");
        return 0;
    }

    return 1;
}
#else
int
moc_evp_digest_copy(EVP_MD_CTX *pTo, const EVP_MD_CTX *pFrom)
{

    MOC_EVP_MD_CTX *pFromMocCtx = NULL;
    MOC_EVP_MD_CTX *pToMocCtx = NULL;

    if(pTo == NULL || pFrom == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }

    pFromMocCtx = pFrom->md_data;
    pToMocCtx = pTo->md_data;
    if (pFromMocCtx == NULL || pToMocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Digest data NULL\n", __func__);
        return 1;
    }

    /* Nothing to copy over */
    if (NULL == pFromMocCtx->pDigestAlgo && NULL == pFromMocCtx->pDigestData)
    {
        DIGI_EVP_WARN("%s: Digest Algo and Digest data NULL\n", __func__);
        return 1;
    }

    if (pToMocCtx->pDigestAlgo == NULL)
    {
        DIGI_EVP_WARN("%s: Digest Algo NULL\n", __func__);
        return 0;
    }

    if(pFromMocCtx->pDigestData == NULL)
    {
        pToMocCtx->pDigestData = NULL;
        DIGI_EVP_WARN("%s: Digest Data to be copied is NULL\n", __func__);
        return 1;
    }

    /* Copy the private data. */
    if (pToMocCtx->pDigestAlgo && (OK > pToMocCtx->pDigestAlgo->pHashAlgo->allocFunc(MOC_HASH(hwAccelCtx) &pToMocCtx->pDigestData)))
    {
        DIGI_EVP_WARN("%s: AllocFunc Failed\n", __func__);
        return 0;
    }

    switch(pToMocCtx->pDigestAlgo->NID)
    {
            
    case NID_md2WithRSAEncryption:
        memcpy(pToMocCtx->pDigestData, pFromMocCtx->pDigestData, sizeof(struct MD2_CTX));
    break;
            
	case NID_md4WithRSAEncryption:
		memcpy(pToMocCtx->pDigestData, pFromMocCtx->pDigestData, sizeof(struct MD4_CTX));
	break;

	case NID_md5WithRSAEncryption:
		memcpy(pToMocCtx->pDigestData, pFromMocCtx->pDigestData, sizeof(struct MD5_CTX));
	break;

	case NID_sha1WithRSAEncryption:
	case NID_dsaWithSHA1:
		memcpy(pToMocCtx->pDigestData, pFromMocCtx->pDigestData, sizeof(struct SW_SHA1_CTX));
	break;

	case NID_sha256WithRSAEncryption:
	case NID_sha224WithRSAEncryption:
		memcpy(pToMocCtx->pDigestData, pFromMocCtx->pDigestData, sizeof(struct SW_SHA256_CTX));
	break;

	case NID_sha384WithRSAEncryption:
	case NID_sha512WithRSAEncryption:
		memcpy(pToMocCtx->pDigestData, pFromMocCtx->pDigestData, sizeof(struct SHA512_CTX));
	break;

	default:
	DIGI_EVP_WARN("%s: NOT SUPPORTED DIGEST\n", __func__);
	return 0;
    }
    return 1;
}
#endif

int
moc_evp_digest_init(MOC_HASH(hwAccelDescr hwAccelCtx) EVP_MD_CTX *ctx)
{
    int 		digesttype;
    MOC_EVP_MD_CTX *mocCtx;

    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = ctx->md_data;
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Digest data NULL\n", __func__);
        return 0;
    }
    if (ctx->digest == NULL)
    {
        DIGI_EVP_WARN("%s: Digest object NULL\n", __func__);
        return 0;
    }
    digesttype = ctx->digest->type;

    DIGI_EVP_MD_CTX_init(mocCtx);
    DIGI_EVP_MD_CTX_cleanup(MOC_HASH(hwAccelCtx) mocCtx);

    DIGI_EVP_setDigestAlgo(mocCtx, digesttype);
    if (mocCtx->pDigestAlgo == NULL)
    {
        DIGI_EVP_WARN("%s: Digest object NULL in mocCtx\n", __func__);
        return 0;
    }
    if (OK > mocCtx->pDigestAlgo->pHashAlgo->allocFunc(MOC_HASH(hwAccelCtx) &mocCtx->pDigestData))
    {
        DIGI_EVP_WARN("%s: allocFunc Failed\n", __func__);
        return 0;
    }

    if ( !mocCtx->pDigestData)
    {
        DIGI_EVP_WARN("%s: pDigestData null\n", __func__);
        return 0;
    }

    if (OK > mocCtx->pDigestAlgo->pHashAlgo->initFunc(MOC_HASH(hwAccelCtx) mocCtx->pDigestData))
    {
        DIGI_EVP_WARN("%s: initFunc failed\n", __func__);
        return 0;
    }

    return 1;
}

int
moc_evp_digest_cleanup(EVP_MD_CTX *ctx)
{
    MOC_EVP_MD_CTX *mocCtx;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = ctx->md_data;
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Digest data NULL\n", __func__);
        return 0;
    }
    if (0 == DIGI_EVP_MD_CTX_cleanup(mocCtx))
    {
        DIGI_EVP_WARN("%s: DIGI_EVP_MD_CTX_cleanup failed\n", __func__);
        return 0;
    }

    return 1;
}

int
moc_evp_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    MOC_EVP_MD_CTX *mocCtx;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = ctx->md_data;

    if (count == 0)
	return 1;
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Digest data NULL\n", __func__);
        return 0;
    }
    if ( 0 == DIGI_EVP_digestUpdate(MOC_HASH(hwAccelCtx) mocCtx, (const ubyte*) data, (unsigned int)count))
    {
        DIGI_EVP_WARN("%s: DIGI_EVP_digestUpdate failed\n", __func__);
        return 0;
    }

    return 1;
}

int
moc_evp_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    MOC_EVP_MD_CTX *mocCtx;
    if (ctx == NULL)
    {
        DIGI_EVP_WARN("%s: Null Parameter\n", __func__);
        return 0;
    }
    mocCtx = ctx->md_data;
    if (mocCtx == NULL)
    {
        DIGI_EVP_WARN("%s: Digest data NULL\n", __func__);
        return 0;
    }
    if ( 0 == DIGI_EVP_digestFinal(mocCtx, md))
    {
        DIGI_EVP_WARN("%s: DIGI_EVP_digestFinal failed\n", __func__);
        return 0;
    }

    return 1;
}

static int moc_evp_digest_nids[] = {
    NID_md2,
    NID_md4,
    NID_md5,
    NID_sha1,
    NID_sha224,
    NID_sha256,
    NID_sha384,
    NID_sha512,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    NID_sha3_224,
    NID_sha3_256,
    NID_sha3_384,
    NID_sha3_512,
    NID_shake128,
    NID_shake256
#endif
};

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#define DECLARE_DIGEST_EVP(name, pkey_name, digestsz, blksz) \
static const EVP_MD _s_hidden_digest_##name = {	    \
    NID_##name,					    \
    NID_##pkey_name,				    \
    digestsz,					    \
    VERSION_EVP_MD_FLAG, \
    moc_evp_digest_init,			    \
    moc_evp_digest_update,			    \
    moc_evp_digest_final,			    \
    moc_evp_digest_copy,					    \
    moc_evp_digest_cleanup,			    \
    blksz,					    \
    sizeof(MOC_EVP_MD_CTX),			    \
    NULL  \
};	      \
static const EVP_MD * _hidden_digest_##name = & _s_hidden_digest_##name
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define DECLARE_DIGEST_EVP(name, pkey_name, digestsz, blksz) \
static const EVP_MD _s_hidden_digest_##name = {	    \
    NID_##name,					        \
    NID_##pkey_name,				    \
    digestsz,					        \
    VERSION_EVP_MD_FLAG,                \
    0,                                  \
    moc_evp_digest_init,			    \
    moc_evp_digest_update,			    \
    moc_evp_digest_final,			    \
    moc_evp_digest_copy,		        \
    moc_evp_digest_cleanup,			    \
    blksz,			                    \
    sizeof(MOC_EVP_MD_CTX),			    \
    NULL,                               \
    0, NULL, NULL, NULL, 0, NULL, NULL, \
    NULL, NULL, NULL, NULL, NULL, NULL, \
    NULL, NULL, NULL, NULL, NULL, NULL  \
};	                                    \
static const EVP_MD * _hidden_digest_##name = & _s_hidden_digest_##name
#else
#define DECLARE_DIGEST_EVP(name, pkey_name, digestsz, blksz) \
static const EVP_MD _s_hidden_digest_##name = {	    \
    NID_##name,					    \
    NID_##pkey_name,				    \
    digestsz,					    \
    VERSION_EVP_MD_FLAG, \
    moc_evp_digest_init,			    \
    moc_evp_digest_update,			    \
    moc_evp_digest_final,			    \
    moc_evp_digest_copy,					    \
    moc_evp_digest_cleanup,			    \
    NULL,			    \
    NULL,			    \
    {NID_undef, NID_undef, 0, 0, 0},     \
    blksz,					    \
    sizeof(MOC_EVP_MD_CTX),			    \
    NULL  \
};	      \
static const EVP_MD * _hidden_digest_##name = & _s_hidden_digest_##name
#endif  /* VERSION_1_1_0_OR_1_1_1C_OR_3_0 */

DECLARE_DIGEST_EVP(md2, md2WithRSAEncryption, MD2_DIGESTSIZE, MD2_BLOCK_SIZE);
DECLARE_DIGEST_EVP(md4, md4WithRSAEncryption, MD4_DIGESTSIZE, MD4_BLOCK_SIZE);
DECLARE_DIGEST_EVP(md5, md5WithRSAEncryption, MD5_DIGESTSIZE, MD5_BLOCK_SIZE);
DECLARE_DIGEST_EVP(sha1, sha1WithRSAEncryption, SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE);
DECLARE_DIGEST_EVP(sha224, sha224WithRSAEncryption, SHA224_RESULT_SIZE, SHA256_BLOCK_SIZE);
DECLARE_DIGEST_EVP(sha256, sha256WithRSAEncryption, SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE);
DECLARE_DIGEST_EVP(sha384, sha384WithRSAEncryption, SHA384_RESULT_SIZE, SHA512_BLOCK_SIZE);
DECLARE_DIGEST_EVP(sha512, sha512WithRSAEncryption, SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

MSTATUS DIGI_EVP_convertSha3TypeOsslToMoc(int nid, ubyte4 *pMode)
{
    MSTATUS status = OK;

    if (NULL == pMode)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (nid)
    {
        case NID_sha3_224:
            *pMode = MOCANA_SHA3_MODE_SHA3_224;
            break;

        case NID_sha3_256:
            *pMode = MOCANA_SHA3_MODE_SHA3_256;
            break;

        case NID_sha3_384:
            *pMode = MOCANA_SHA3_MODE_SHA3_384;
            break;

        case NID_sha3_512:
            *pMode = MOCANA_SHA3_MODE_SHA3_512;
            break;

        case NID_shake128:
            *pMode = MOCANA_SHA3_MODE_SHAKE128;
            break;

        case NID_shake256:
            *pMode = MOCANA_SHA3_MODE_SHAKE256;
            break;

        default:
            status = ERR_SHA3_INVALID_MODE;
            break;
    }

exit:
    return status;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_sha3_init(EVP_MD_CTX *pEvpCtx)
{
    MSTATUS status;
    ubyte4 mode;
    int rval = 0;
    MOC_EVP_MD_SHA3_CTX *pMocCtx = pEvpCtx->md_data;

    status = DIGI_EVP_convertSha3TypeOsslToMoc(pEvpCtx->digest->type, &mode);
    if (OK != status)
        goto exit;

    pMocCtx->mdSize = pEvpCtx->digest->md_size;

    status = CRYPTO_INTERFACE_SHA3_allocDigest((BulkCtx *) &(pMocCtx->pCtx));
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_SHA3_initDigest(pMocCtx->pCtx, mode);
    if (OK != status)
        goto exit;

    rval = 1;

exit:

    return rval;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_sha3_update(EVP_MD_CTX *pEvpCtx, const void *pData, size_t count)
{
    MSTATUS status;
    MOC_EVP_MD_SHA3_CTX *pMocCtx = pEvpCtx->md_data;

    status = CRYPTO_INTERFACE_SHA3_updateDigest(
        pMocCtx->pCtx, (ubyte *) pData, count);
    return (OK == status) ? 1 : 0;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_sha3_final(EVP_MD_CTX *pEvpCtx, unsigned char *pOut)
{
    MSTATUS status;
    MOC_EVP_MD_SHA3_CTX *pMocCtx = pEvpCtx->md_data;

    status = CRYPTO_INTERFACE_SHA3_finalDigest(pMocCtx->pCtx, pOut, pMocCtx->mdSize);
    return (OK == status) ? 1 : 0;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_sha3_copy(EVP_MD_CTX *pDest, const EVP_MD_CTX *pSrc)
{
    MSTATUS status;
    MOC_EVP_MD_SHA3_CTX *pSrcCtx = NULL;
    MOC_EVP_MD_SHA3_CTX *pDestCtx = NULL;
    ubyte4 mode;

    /* OpenSSL will handle allocating the destination context.
     */
    if ( (NULL == pSrc) || (NULL == pDest) )
    {
        DIGI_EVP_WARN("%s: SHA-3 Null Parameter\n", __func__);
        return 0;
    }

    /* Check if the Mocana context underneath is NULL. This context contains
     * the algorithm suite, which is just a set of function pointers, and a
     * context used to operate on data.
     */
    pSrcCtx = pSrc->md_data;
    pDestCtx = pDest->md_data;
    if ( (NULL == pSrcCtx) || (NULL == pDestCtx) )
    {
        DIGI_EVP_WARN("%s: SHA-3 Digest data NULL\n", __func__);
        return 1;
    }

    status = DIGI_EVP_convertSha3TypeOsslToMoc(pSrc->digest->type, &mode);
    if (OK != status)
    {
        DIGI_EVP_WARN("%s: SHA-3 Digest mode invalid\n", __func__);
        return 0;
    }

    status = CRYPTO_INTERFACE_SHA3_allocDigest((BulkCtx *) &(pDestCtx->pCtx));
    if (OK != status)
    {
        DIGI_EVP_WARN("%s: SHA3_allocDigest Failed\n", __func__);
        return 0;
    }

    status = CRYPTO_INTERFACE_SHA3_cloneCtx(pDestCtx->pCtx, pSrcCtx->pCtx);
    if (OK != status)
    {
        DIGI_EVP_WARN("%s: CRYPTO_INTERFACE_SHA3_cloneCtx failed\n");
        return 0;
    }

    return 1;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_sha3_cleanup(EVP_MD_CTX *pEvpCtx)
{
    MSTATUS status;
    MOC_EVP_MD_SHA3_CTX *pMocCtx = pEvpCtx->md_data;

    status = CRYPTO_INTERFACE_SHA3_freeDigest((BulkCtx *) &(pMocCtx->pCtx));
    return (OK == status) ? 1 : 0;
}

static const EVP_MD moc_sha3_224_md = {
    NID_sha3_224,
    NID_RSA_SHA3_224,
    SHA3_224_RESULT_SIZE,
    EVP_MD_FLAG_DIGALGID_ABSENT,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    0,
#endif
    moc_sha3_init,
    moc_sha3_update,
    moc_sha3_final,
    moc_sha3_copy,
    moc_sha3_cleanup,
    SHA3_224_BLOCK_SIZE,
    sizeof(MOC_EVP_MD_SHA3_CTX),
    NULL
};
static const EVP_MD * _hidden_digest_sha3_224 = &moc_sha3_224_md;

static const EVP_MD moc_sha3_256_md = {
    NID_sha3_256,
    NID_RSA_SHA3_256,
    SHA3_256_RESULT_SIZE,
    EVP_MD_FLAG_DIGALGID_ABSENT,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    0,
#endif
    moc_sha3_init,
    moc_sha3_update,
    moc_sha3_final,
    moc_sha3_copy,
    moc_sha3_cleanup,
    SHA3_256_BLOCK_SIZE,
    sizeof(MOC_EVP_MD_SHA3_CTX),
    NULL
};
static const EVP_MD * _hidden_digest_sha3_256 = &moc_sha3_256_md;

static const EVP_MD moc_sha3_384_md = {
    NID_sha3_384,
    NID_RSA_SHA3_384,
    SHA3_384_RESULT_SIZE,
    EVP_MD_FLAG_DIGALGID_ABSENT,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    0,
#endif
    moc_sha3_init,
    moc_sha3_update,
    moc_sha3_final,
    moc_sha3_copy,
    moc_sha3_cleanup,
    SHA3_384_BLOCK_SIZE,
    sizeof(MOC_EVP_MD_SHA3_CTX),
    NULL
};
static const EVP_MD * _hidden_digest_sha3_384 = &moc_sha3_384_md;

static const EVP_MD moc_sha3_512_md = {
    NID_sha3_512,
    NID_RSA_SHA3_512,
    SHA3_512_RESULT_SIZE,
    EVP_MD_FLAG_DIGALGID_ABSENT,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    0,
#endif
    moc_sha3_init,
    moc_sha3_update,
    moc_sha3_final,
    moc_sha3_copy,
    moc_sha3_cleanup,
    SHA3_512_BLOCK_SIZE,
    sizeof(MOC_EVP_MD_SHA3_CTX),
    NULL
};
static const EVP_MD * _hidden_digest_sha3_512 = &moc_sha3_512_md;

static int moc_shake_ctrl(EVP_MD_CTX *pEvpCtx, int cmd, int p1, void *p2)
{
    MOC_EVP_MD_SHA3_CTX *pCtx = (MOC_EVP_MD_SHA3_CTX *) pEvpCtx->md_data;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    EVP_MD *pMd = (EVP_MD *) pEvpCtx->digest;
#endif

    switch (cmd)
    {
        case EVP_MD_CTRL_XOF_LEN:
            /* set both size params */
            pCtx->mdSize = p1;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
            pMd->md_size = p1;
#endif
            return 1;
        default:
            return 0;
    }
}

static const EVP_MD moc_shake128 = {
    NID_shake128,
    0,
    128 / 8,
    EVP_MD_FLAG_XOF,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    0,
#endif
    moc_sha3_init,
    moc_sha3_update,
    moc_sha3_final,
    moc_sha3_copy,
    moc_sha3_cleanup,
    168,
    sizeof(MOC_EVP_MD_SHA3_CTX),
    moc_shake_ctrl
};
static const EVP_MD * _hidden_digest_shake128 = &moc_shake128;

static const EVP_MD moc_shake256 = {
    NID_shake256,
    0,
    256 / 8,
    EVP_MD_FLAG_XOF,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    0,
#endif
    moc_sha3_init,
    moc_sha3_update,
    moc_sha3_final,
    moc_sha3_copy,
    moc_sha3_cleanup,
    136,
    sizeof(MOC_EVP_MD_SHA3_CTX),
    moc_shake_ctrl
};
static const EVP_MD * _hidden_digest_shake256 = &moc_shake256;

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ OR __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

static int MOC_EVP_digests(ENGINE *e, const EVP_MD **digest,
			   const int **nids, int nid)
{

    /* If digest is NULL then OpenSSL is requesting the total count of supported
     * digest algorithms.
     */
    if (digest == NULL) {
        *nids = moc_evp_digest_nids;
        return (sizeof(moc_evp_digest_nids) / sizeof(moc_evp_digest_nids[0]));
    }

    *digest = NULL;

    switch (nid)
    {
        case NID_sha1:
            *digest = _hidden_digest_sha1;
            break;
        case NID_sha224:
            *digest = _hidden_digest_sha224;
            break;
        case NID_sha256:
            *digest = _hidden_digest_sha256;
            break;
        case NID_sha384:
            *digest = _hidden_digest_sha384;
            break;
        case NID_sha512:
            *digest = _hidden_digest_sha512;
            break;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        case NID_sha3_224:
            *digest = _hidden_digest_sha3_224;
            break;
        case NID_sha3_256:
            *digest = _hidden_digest_sha3_256;
            break;
        case NID_sha3_384:
            *digest = _hidden_digest_sha3_384;
            break;
        case NID_sha3_512:
            *digest = _hidden_digest_sha3_512;
            break;
        case NID_shake128:
            *digest = _hidden_digest_shake128;
            break;
        case NID_shake256:
            *digest = _hidden_digest_shake256;
            break;
#endif
    }

    /* If FIPS mode is not being enforced then check if NID matches with any of
     * the non-FIPS algorithms.
     */
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (0 == DIGI_EVP_getFipsMode())
#endif
    {
        switch (nid)
        {
            case NID_md2:
                *digest = _hidden_digest_md2;
                break;
            case NID_md4:
                *digest = _hidden_digest_md4;
                break;
            case NID_md5:
                *digest = _hidden_digest_md5;
                break;
        }
    }

    if (*digest != NULL)
        return 1;
    else
        return 0;
}

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
void *
DIGI_EVP_opensslRSA2DIGI(RSA *rsa, AsymmetricKey *pAsymKey)
{
    RSAKey      *pRSAKey = NULL;
    MSTATUS		status;
    ubyte *pPubExpo = NULL;
    ubyte4 pubExpoLen = 0;
    ubyte *pModulus = NULL;
    ubyte4 modulusLen = 0;
    ubyte *pPrime1 = NULL;
    ubyte4 prime1Len = 0;
    ubyte *pPrime2 = NULL;
    ubyte4 prime2Len = 0;

    MOC_EVP_KEY_DATA *pMocKeyData = RSA_get_ex_data(rsa, rsaExAppData);

    if(NULL != pMocKeyData)
    {
        /* Attempt to deserialize the key data. This will attempt to deserialize
         * the data blob as a TAP key. If it is unsuccessful then attempt to
         * use the array of function pointers to deserialize the key as a
         * software key.
         */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
        if (NULL != pMocKeyData->pCred)
        {
            DIGI_EVP_maskCred(pMocKeyData->pCred, pMocKeyData->credLen);

            status = CRYPTO_deserializeAsymKeyWithCreds(pMocKeyData->pContents, pMocKeyData->contentsLen, NULL, 
                                                        pMocKeyData->pCred, pMocKeyData->credLen, NULL, pAsymKey);        
            /* done with credential, re-mask it*/
            DIGI_EVP_maskCred(pMocKeyData->pCred, pMocKeyData->credLen);

        }
        else
#endif
        {
            status = CRYPTO_deserializeAsymKey(
                pMocKeyData->pContents, pMocKeyData->contentsLen,
                NULL, pAsymKey);
            if (OK != status)
                goto exit;
        }
        /* Call the provided callback, only if the key is a non RSA TAP key.
         */
        if ( (NULL != pMocKeyData->cb_data) && (akt_tap_rsa != pAsymKey->type) )
        {
            MKeyContextCallbackInfo *pCallbackInfo = pMocKeyData->cb_data;
            if ( (pCallbackInfo != NULL) &&
                 (pCallbackInfo->KeyContextCallback != NULL) )
            {
                status = pCallbackInfo->KeyContextCallback(
                    pAsymKey, pCallbackInfo->pLocalData, 0);
                if (OK != status)
                    goto exit;
            }
        }

        /* Return the inner key.
         */
        return pAsymKey->key.pMocAsymKey;
    }
    else
    {
        if (OK > (status = CRYPTO_INTERFACE_RSA_createKey(
            (void **) &pRSAKey, akt_rsa, NULL)))
        {
            return NULL;
        }

        /* convert n */
        modulusLen = BN_num_bytes(rsa->n);
        pModulus = OPENSSL_malloc(modulusLen);
        DIGI_MEMSET((ubyte *)pModulus, 0x0, modulusLen);
        BN_bn2bin(rsa->n, pModulus);

        /* convert e */
        pubExpoLen = BN_num_bytes(rsa->e);
        pPubExpo = OPENSSL_malloc(pubExpoLen);
        DIGI_MEMSET((ubyte *)pPubExpo, 0x0, pubExpoLen);
        BN_bn2bin(rsa->e, pPubExpo);

        /* If neither the prime or subprime values are in the OpenSSL RSA key
         * object then just set the public key data (exponent and modulus). If
         * the prime and subprime are available then set the private key data
         * (prime, subprime, exponent, modulus).
         */
        if ((NULL == rsa->p) || (NULL == rsa->q))
        {
            pRSAKey->privateKey = 0;

            status = CRYPTO_INTERFACE_RSA_setPublicKeyData(
                pRSAKey, pPubExpo, pubExpoLen, pModulus, modulusLen, NULL);
        }
        else
        {
            pRSAKey->privateKey = 1;

            /* private values */
            if (rsa->p)
            {
                prime1Len = BN_num_bytes(rsa->p);
                pPrime1 = OPENSSL_malloc(prime1Len);
                DIGI_MEMSET((ubyte *)pPrime1, 0x0, prime1Len);
                BN_bn2bin(rsa->p, pPrime1);
            }
            if (rsa->q)
            {
                prime2Len = BN_num_bytes(rsa->q);
                pPrime2 = OPENSSL_malloc(prime2Len);
                DIGI_MEMSET((ubyte *)pPrime2, 0x0, prime2Len);
                BN_bn2bin(rsa->q, pPrime2);
            }

            status = CRYPTO_INTERFACE_RSA_setAllKeyData(
                MOC_RSA(hwAccelDescr hwAccelCtx) pRSAKey, pPubExpo, pubExpoLen,
                pModulus, modulusLen, pPrime1, prime1Len, pPrime2, prime2Len,
                NULL, akt_rsa);
        }
        if (OK != status)
        {
            CRYPTO_INTERFACE_RSA_freeKey((void **) &pRSAKey, NULL, akt_rsa);
            return NULL;
        }

        (pAsymKey->key).pRSA = pRSAKey;
        pAsymKey->type = akt_rsa;
    }
exit:
    if (pModulus)
    {
        OPENSSL_free(pModulus);
        pModulus = NULL;
    }
    if (pPubExpo)
    {
        OPENSSL_free(pPubExpo);
        pPubExpo = NULL;
    }
    if (pPrime1)
    {
        OPENSSL_free(pPrime1);
        pPrime1 = NULL;
    }
    if (pPrime2)
    {
        OPENSSL_free(pPrime2);
        pPrime2 = NULL;
    }
    return pRSAKey;
}
#else
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
void *
DIGI_EVP_opensslRSA2DIGI(RSA *rsa, AsymmetricKey *pAsymKey)
{
    RSAKey      *pRSAKey = NULL;
    unsigned char     * to;
    int			tolen;
    MSTATUS		status;

    MOC_EVP_KEY_DATA *pMocKeyData = RSA_get_ex_data(rsa, rsaExAppData);

    if(NULL != pMocKeyData)
    {
        status = CRYPTO_deserializeAsymKey(
            pMocKeyData->pContents, pMocKeyData->contentsLen,
            NULL, pAsymKey);
        if (OK != status)
        {
            goto exit;
        }

        if (NULL != pMocKeyData->cb_data )
        {
            MKeyContextCallbackInfo *pCallbackInfo = pMocKeyData->cb_data;
            if(pCallbackInfo != NULL && pCallbackInfo->KeyContextCallback != NULL)
            {
                status = pCallbackInfo->KeyContextCallback(pAsymKey, pCallbackInfo->pLocalData, 0);
                if (OK != status) {
                   goto exit;
                }
            }
        }

        pRSAKey = (pAsymKey->key).pRSA;
    }
    else
    {
        if (OK > (status = RSA_createKey(&pRSAKey)))
        {
            return NULL;
        }

        /* convert n */
        tolen = BN_num_bytes(rsa->n);
        to = OPENSSL_malloc(tolen);
        DIGI_MEMSET((ubyte *)to, 0x0, tolen);
        BN_bn2bin(rsa->n, to);
        VLONG_vlongFromByteString((const ubyte *)to, tolen, &RSA_N(pRSAKey), NULL);
        OPENSSL_free(to);
        to = NULL;
        /* convert e */
        tolen = BN_num_bytes(rsa->e);
        to = OPENSSL_malloc(tolen);
        DIGI_MEMSET((ubyte *)to, 0x0, tolen);
        BN_bn2bin(rsa->e, to);
        VLONG_vlongFromByteString((const ubyte *)to, tolen, &RSA_E(pRSAKey), NULL);
        OPENSSL_free(to);
        to = NULL;
        if ((NULL == rsa->p) || (NULL == rsa->q))
        {
            pRSAKey->privateKey = 0;
        }
        else
        {
            pRSAKey->privateKey = 1;
            /* private values */
            if (rsa->p)
            {
                tolen = BN_num_bytes(rsa->p);
                to = OPENSSL_malloc(tolen);
                DIGI_MEMSET((ubyte *)to, 0x0, tolen);
                BN_bn2bin(rsa->p, to);
                VLONG_vlongFromByteString((const ubyte *)to, tolen, &RSA_P(pRSAKey), NULL);
                OPENSSL_free(to);
                to = NULL;
            }
            if (rsa->q)
            {
                tolen = BN_num_bytes(rsa->q);
                to = OPENSSL_malloc(tolen);
                DIGI_MEMSET((ubyte *)to, 0x0, tolen);
                BN_bn2bin(rsa->q, to);
                VLONG_vlongFromByteString((const ubyte *)to, tolen, &RSA_Q(pRSAKey), NULL);
                OPENSSL_free(to);
                to = NULL;
            }
        }
        RSA_prepareKey(MOC_RSA(hwAccelDescr hwAccelCtx) pRSAKey, NULL);

        (pAsymKey->key).pRSA = pRSAKey;
        pAsymKey->type = akt_rsa;
#if 0
        if (rsa->dmp1) {
            tolen = BN_num_bytes(rsa->dmp1);
            to = OPENSSL_malloc(tolen);
            DIGI_MEMSET((ubyte *)to, 0x0, tolen);
            BN_bn2bin(rsa->dmp1, to);
            VLONG_vlongFromByteString((const ubyte *)to, tolen, &RSA_DP(pRSAKey), NULL);
            OPENSSL_free(to);
            to = NULL;
        }
        if (rsa->dmq1) {
            tolen = BN_num_bytes(rsa->dmq1);
            to = OPENSSL_malloc(tolen);
            DIGI_MEMSET((ubyte *)to, 0x0, tolen);
            BN_bn2bin(rsa->dmq1, to);
            VLONG_vlongFromByteString((const ubyte *)to, tolen, &RSA_DQ(pRSAKey), NULL);
            OPENSSL_free(to);
            to = NULL;
        }
#endif
    }
exit:
    return pRSAKey;
}
#endif

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int
moc_rsa_pub_enc(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
    void*       pRSAKey = NULL;
    MSTATUS 	status = ERR_RSA_UNKNOWN_PKCS5_ALGO;
    vlong*      pVlongQueue  = NULL;
    int		rval = -1, num;
    ubyte4	tolen;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    vlong*  	pPkcs1       = NULL;
    vlong*  	pEncrypted   = NULL;
    hwAccelDescr    hwAccelCtx = 0;
#endif
    ubyte*  	buf = NULL;
    ubyte*      pBuf = NULL;
    AsymmetricKey asymKey;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte *pOutput = NULL;
#endif

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        goto exit;
    if (NULL == (pRSAKey = DIGI_EVP_opensslRSA2DIGI(rsa, &asymKey)))
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return 0;
    }
    switch (padding)
    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
        case RSA_SSLV23_PADDING:
	        num = BN_num_bytes(rsa->n);
            RSA_padding_add_SSLv23(to, num, from, flen);
            pBuf = OPENSSL_malloc(num);
            memcpy(pBuf, to, num);

            from = pBuf;
            flen = num;
#endif
        case RSA_NO_PADDING:
            {
	        num = BN_num_bytes(rsa->n);
	        if (flen > num)
                {
	            RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
	            break;
	        }
	        if (flen < num)
                {
                    RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
	            break;
	        }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_RSA_applyPublicKey(
                pRSAKey, (ubyte *) from, flen, &pOutput, &pVlongQueue,
                asymKey.type)))
            {
                break;
            }

            if (pOutput != NULL)
            {
                DIGI_MEMCPY(to, pOutput, flen);
            }
#else
	        DIGI_MEMCPY(to, from, flen);
	        if (OK > (status = VLONG_vlongFromByteString(to, flen, &pPkcs1,
						             &pVlongQueue)))
	        break;
                if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) pPkcs1, RSA_E((RSAKey*)pRSAKey),
		   		                RSA_N((RSAKey*)pRSAKey), &pEncrypted, &pVlongQueue)))
	        break;
                if (OK > (status = VLONG_byteStringFromVlong(pEncrypted, to,
                                                             &num)))
#endif
	        break;
            }
	    break;
        case RSA_PKCS1_PADDING:
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_encrypt(pRSAKey, from, flen, to,
                     RANDOM_FUN, RANDOM_CTX, &pVlongQueue, asymKey.type);
#else
	        status = RSA_encrypt(MOC_RSA(hwAccelCtx) (RSAKey*)pRSAKey,
			             from, flen, to,
			             RANDOM_FUN, RANDOM_CTX, &pVlongQueue);
#endif
	        switch (status)
                {
	            case ERR_RSA_INVALID_KEY:
	                RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2,
		               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
	                break;
	            default:
	                break;
	        }
            }
	    break;
        case RSA_PKCS1_OAEP_PADDING:
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
          status = CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt(
            RANDOM_CTX_MOC, pRSAKey, sha1withRSAEncryption,
            MOC_PKCS1_ALG_MGF1, sha1withRSAEncryption, from, flen, NULL, 0,
            &buf, &tolen);
#else
	        status = PKCS1_rsaesOaepEncrypt(
	                hwAccelCtx, RANDOM_CTX_MOC, (RSAKey*)pRSAKey, sha1withRSAEncryption,
		            PKCS1_MGF1_FUNC, from, flen, NULL, 0, &buf, &tolen);
#endif
                switch (status)
                {
	            case ERR_BAD_LENGTH:
	                RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
                               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
                        break;
	            default:
	                 break;
	        }
	        if ((OK == status) && buf)
                {
	            DIGI_MEMCPY(to, buf, tolen);
                }
                if (buf)
	           FREE(buf);
            }
            break;
        default:
            status = ERR_UNSUPPORTED_OPERATION;
            RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
            break;
    }
    if (OK > status)
        goto exit;

    rval = BN_num_bytes(rsa->n);
exit:
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pOutput != NULL)
        DIGI_FREE((void **)&pOutput);
#else
    if (pEncrypted != NULL)
    {
        VLONG_freeVlong(&pEncrypted, &pVlongQueue);
    }
    if(pPkcs1 != NULL)
    {
        VLONG_freeVlong(&pPkcs1, &pVlongQueue);
    }
#endif
    if(pVlongQueue != NULL)
    {
        VLONG_freeVlongQueue(&pVlongQueue);
    }

    if (NULL != pBuf)
    {
        OPENSSL_free(pBuf);
    }

    return rval;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int
moc_rsa_priv_dec(int flen, const unsigned char *from,
		 unsigned char *to, RSA *rsa, int padding)
{
    void*       pRSAKey;
    MSTATUS 	status;
    vlong*      pVlongQueue  = NULL;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    vlong*      pClear  = NULL;
    int decryptedLen;
    vlong*    pEncrypted = NULL;
    hwAccelDescr    hwAccelCtx = 0;
#endif
    u_int32_t	tolen;
    int		rval = -1, num;
    unsigned char *buf = NULL;
    AsymmetricKey asymKey;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte *pOutput = NULL;
#endif

    num = BN_num_bytes(rsa->n);
    if (flen > num)
    {
        RSAerr(VERSION_RSA_F_RSA_PRIVATE_DECRYPT,
               RSA_R_DATA_GREATER_THAN_MOD_LEN);
        return rval;
    }

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        goto exit;
    if (NULL == (pRSAKey = DIGI_EVP_opensslRSA2DIGI(rsa, &asymKey)))
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return rval;
    }

    switch(padding)
    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
        case RSA_SSLV23_PADDING:
            {
            ubyte *pBuff = NULL;
            pBuff = OPENSSL_malloc(num);
            if (NULL == pBuff)
                break;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_RSA_applyPrivateKey(
                    pRSAKey, RANDOM_FUN, RANDOM_CTX, (ubyte *) from,
                    num, &pOutput, &pVlongQueue, asymKey.type)))
            {
                goto exit2;
            }

            memcpy(pBuff, pOutput, num);
#else
	        if (OK > (status = VLONG_vlongFromByteString(from, num, &pEncrypted, &pVlongQueue)))
	            goto exit2;
	        status = RSA_RSADP(MOC_RSA(hwAccelCtx) pRSAKey, pEncrypted, &pClear, &pVlongQueue);
            if (OK != status)
                goto exit2;
	        decryptedLen = num;
	        buf = OPENSSL_malloc(num);
            if (NULL == buf)
                goto exit2;

            status = VLONG_byteStringFromVlong(pClear, buf, &decryptedLen);
	        if (OK > status)
            {
                OPENSSL_free(buf);
	            goto exit2;
            }
            memset(pBuff, 0, num - decryptedLen);
            memcpy(pBuff + num - decryptedLen, buf, decryptedLen);
            OPENSSL_cleanse(buf, num);
            OPENSSL_free(buf);
#endif

            rval = RSA_padding_check_SSLv23(to, num, pBuff, num, num);
exit2:
            if (NULL != pBuff)
            {
                OPENSSL_cleanse(pBuff, num);
                OPENSSL_free(pBuff);
            }
            }
            break;
#endif
        case RSA_NO_PADDING:
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_RSA_applyPrivateKey(
                    pRSAKey, RANDOM_FUN, RANDOM_CTX, (ubyte *) from,
                    num, &pOutput, &pVlongQueue, asymKey.type)))
            {
                break;
            }

            DIGI_MEMCPY((ubyte *)to, pOutput, num);
            rval = num;
#else
	        if (OK > (status = VLONG_vlongFromByteString(from, num, &pEncrypted, &pVlongQueue)))
	            break;
	        status = RSA_RSADP(MOC_RSA(hwAccelCtx) (RSAKey*)pRSAKey, pEncrypted, &pClear, &pVlongQueue);
	        decryptedLen = num;
	        buf = OPENSSL_malloc(num);
            if (NULL == buf)
                goto exit;

	        if (OK > (status = VLONG_byteStringFromVlong(pClear, buf, &decryptedLen)))
            {
                OPENSSL_free(buf);
	            goto exit;
            }
            DIGI_MEMSET((ubyte *)to, 0, num - decryptedLen);
            DIGI_MEMCPY((ubyte *)to + num - decryptedLen, buf, decryptedLen);
            rval = decryptedLen;
            OPENSSL_cleanse(buf, num);
            OPENSSL_free(buf);
#endif
            }
    	    break;
        case RSA_PKCS1_PADDING:
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_RSA_decrypt(pRSAKey, from, to, &tolen,
                     NULL, NULL,  &pVlongQueue, asymKey.type);
#else
                status = RSA_decrypt(MOC_RSA(hwAccelCtx) (RSAKey*)pRSAKey,
			             from, to, &tolen,
			             NULL, NULL, &pVlongQueue);
#endif
                if (OK == status)
                    rval = tolen;
            }
	    break;
        case RSA_PKCS1_OAEP_PADDING:
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(
                    pRSAKey, sha1withRSAEncryption, MOC_PKCS1_ALG_MGF1,
                    sha1withRSAEncryption, from, flen, NULL, 0, &buf, &tolen);
#else
                status = PKCS1_rsaesOaepDecrypt(hwAccelCtx, (RSAKey*)pRSAKey, sha1withRSAEncryption,
					PKCS1_MGF1_FUNC, from, flen, NULL, 0, &buf, &tolen);
#endif
                if ((OK == status) && buf) {
	            DIGI_MEMCPY(to, buf, tolen);
                    rval = tolen;
	        }
	        if (buf)
	           FREE(buf);
            }
	    break;
        default:
	    RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
	    break;
    }
exit:
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pOutput != NULL)
        DIGI_FREE((void **)&pOutput);
#else
    if(pEncrypted != NULL)
    {
        VLONG_freeVlong(&pEncrypted, &pVlongQueue);
    }
    if(pClear != NULL)
    {
        VLONG_freeVlong(&pClear, &pVlongQueue);
    }
#endif
    if(pVlongQueue != NULL)
    {
        VLONG_freeVlongQueue(&pVlongQueue);
    }

    return rval;
}

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int
moc_rsa_priv_enc(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
{
    void*       pRSAKey;
    MSTATUS 	status = -1;
    vlong*      pVlongQueue  = NULL, *pSignature = NULL;
    int		rval = -1;
    int		num;
    AsymmetricKey asymKey;
    ubyte *pOutput = NULL;

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        return 0;
    if (NULL == (pRSAKey = DIGI_EVP_opensslRSA2DIGI(rsa, &asymKey)))
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return 0;
    }

    num = BN_num_bytes(rsa->n);
    switch(padding)
    {
        case RSA_PKCS1_PADDING:
        {
            ubyte4 dataLen;
            ubyte  *pBuffer   = 0;
            
/* 3.0 already handled putting in digest info form in all cases */
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            ubyte  *digestOid = (ubyte *) getDigest_OID(flen);

            if ((asymKey.type == akt_tap_rsa) && (NULL != digestOid))
            {
                DER_ITEMPTR     pSequence = 0;
                /* now construct a new ASN.1 DER encoding with this */
                if ( OK > (status = DER_AddSequence( NULL, &pSequence)))
                    break;

                if ( OK > ( status = DER_StoreAlgoOID( pSequence, digestOid, TRUE)))
                   break;

                if ( OK > ( status = DER_AddItem( pSequence, OCTETSTRING, flen, from, NULL)))
                   break;

                if ( OK > ( status = DER_Serialize( pSequence, &pBuffer, &dataLen)))
                    break;
                if(pSequence)
                    TREE_DeleteTreeItem((TreeItem*)pSequence);
            }
            else
#endif
            {
                pBuffer = (ubyte *)from;
                dataLen = flen;
            }

            status = CRYPTO_INTERFACE_RSA_signMessage(pRSAKey, pBuffer, dataLen, to, &pVlongQueue, asymKey.type);

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            if ((asymKey.type == akt_tap_rsa) && (NULL != digestOid))
            {
                DIGI_FREE((void **)&pBuffer);
            }
#endif

	        switch(status)
            {
	            case ERR_RSA_UNSUPPORTED_KEY_LENGTH:
	                RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT,
		               RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
	                break;
	            case ERR_RSA_INVALID_KEY:
	                RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,
		               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
	                break;
	            default:
	                break;
	        }
	        break;
        }
        case RSA_NO_PADDING:
            {
                if (flen > num) {
                    RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
                    break;
                }
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
                if (flen < num) {
                    RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
                    break;
                }
#endif
                if (OK > (status = CRYPTO_INTERFACE_RSA_applyPrivateKey(
                        pRSAKey, RANDOM_FUN, RANDOM_CTX, (ubyte *) from,
                        flen, &pOutput, &pVlongQueue, asymKey.type)))
                {
                    break;
                }

                status = DIGI_MEMCPY((void *)to, (const void *)pOutput, flen);
	        }
	        break;
        case RSA_X931_PADDING:

            if (RSA_padding_add_X931(to, num, from, flen) <= 0)
                break;

            if (OK > (status = CRYPTO_INTERFACE_RSA_applyPrivateKey(
                    pRSAKey, RANDOM_FUN, RANDOM_CTX, (ubyte *) from,
                    flen, &pOutput, &pVlongQueue, asymKey.type)))
                break;

            if (OK > (status = VLONG_vlongFromByteString(
                    pOutput, flen, &pSignature, &pVlongQueue)))
                break;

            if (OK > (status = VLONG_byteStringFromVlong(pSignature, to, &num)))
                break;

            break;
        default:
	    RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
	    break;
    }
    if (OK == status)
	    rval = num;

    if (pOutput != NULL)
    {
        DIGI_MEMSET(pOutput, 0, flen);
        DIGI_FREE((void **)&pOutput);
    }
    if (NULL != pSignature)
    {
        VLONG_freeVlong(&pSignature, &pVlongQueue);
    }
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    VLONG_freeVlongQueue(&pVlongQueue);

    return rval;
}
#else
static int moc_rsa_priv_enc(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
{
    void*       pRSAKey;
    MSTATUS 	status = -1;
    vlong*      pVlongQueue  = NULL;
    int		rval = -1;
    int		num;
    vlong* 	pTBS = NULL;
    vlong*	pSignature = NULL;
    AsymmetricKey asymKey;
    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        return 0;
    if (NULL == (pRSAKey = DIGI_EVP_opensslRSA2DIGI(rsa, &asymKey)))
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return 0;
    }

    num = BN_num_bytes(rsa->n);
    switch(padding)
    {
        case RSA_PKCS1_PADDING:
        {

	        status = RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx) (RSAKey*)pRSAKey,
			         from, flen, to, &pVlongQueue);

	        switch(status)
            {
	            case ERR_RSA_UNSUPPORTED_KEY_LENGTH:
	                RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT,
		               RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
	                break;
	            case ERR_RSA_INVALID_KEY:
	                RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,
		               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
	                break;
	            default:
	                break;
	        }
	        break;
        }
        case RSA_NO_PADDING:
            {
	        if (flen > num) {
	            RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
	            break;
	        }
	        if (flen < num) {
	            RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
	            break;
	        }
	        DIGI_MEMCPY(to, from, flen);
	        if (OK > (status = VLONG_vlongFromByteString(to, num, &pTBS, &pVlongQueue)))
	            break;
	        if (OK > (status = RSA_RSASP1(MOC_RSA(hwAccelCtx) (RSAKey*)pRSAKey, pTBS, NULL, NULL, &pSignature, &pVlongQueue)))
	            break;
	        if (OK > (status = VLONG_byteStringFromVlong(pSignature, to, &num)))
	            break;
            }
	    break;
        case RSA_X931_PADDING:
            {
                if (RSA_padding_add_X931(to, num, from, flen) <= 0)
                    break;

                if (OK > (status = VLONG_vlongFromByteString(to, num, &pTBS, &pVlongQueue)))
                    break;

                if (OK > (status = RSA_RSASP1(MOC_RSA(hwAccelCtx) (RSAKey*)pRSAKey, pTBS, NULL, NULL, &pSignature, &pVlongQueue)))
                    break;

                if (OK > (status = VLONG_byteStringFromVlong(pSignature, to, &num)))
                {
                    break;
                }
            }
            break;
        default:
            RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
            break;
    }
    if (OK == status)
	    rval = num;

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    VLONG_freeVlong(&pSignature, &pVlongQueue);
    VLONG_freeVlong(&pTBS, &pVlongQueue);
    VLONG_freeVlongQueue(&pVlongQueue);
    return rval;
}
#endif


#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int
moc_rsa_pub_dec(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
    void*     pRSAKey;
    MSTATUS 	status;
    vlong*      pVlongQueue  = NULL;
    int		rval = 0;
    u_int32_t	tolen;
    vlong*	pSignature = NULL;
    vlong*	pRetMessage = NULL;
    int		num;
    AsymmetricKey asymKey;
    ubyte *pOutput = NULL;

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        return 0;
    if (NULL == (pRSAKey = DIGI_EVP_opensslRSA2DIGI(rsa, &asymKey)))
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return 0;
    }

    num = BN_num_bytes(rsa->n);

    switch(padding)
    {
        case RSA_PKCS1_PADDING:
            {
#ifdef __ENABLE_DIGICERT_TAP__
                /*if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignature(pRSAKey, from,
					       to, &tolen, NULL, asymKey.type))) {
	                break;
	            }*/
                /* CRYPTO_INTERFACE_RSA_verifySignature API does not return decrypted output,
                   hence we are using software RSA_verifySignature API.*/
                if(asymKey.type == akt_tap_rsa)
                {
                    /* Convert TAP RSA private key to public key and call software RSA_verifySignature
                       Which will return plain text.*/
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
                    unsigned char *pBuffer = NULL;
                    ubyte *pOid = NULL;
                    ubyte4 digestAlg, oidLen;
#endif
                    ubyte4 outlen = 0;
                    AsymmetricKey asymPubKey;
                    ubyte4 expo = 0;
                    TAP_Key *pTapKey = NULL;
                    TAP_RSAPublicKey *pRsaTapPub = NULL;

                    status = CRYPTO_initAsymmetricKey (&asymPubKey);
                    if (OK != status)
                        break;

                    status = CRYPTO_INTERFACE_RSA_getTapKey(pRSAKey, &pTapKey);
                    if (OK != status)
                        break;

                    pRsaTapPub = (TAP_RSAPublicKey *)(&(pTapKey->keyData.publicKey.publicKey.rsaKey));

                    /* Exponent length must fit into a 32-bit integer */
                    /* exponent is Little Endian */
                    switch (pRsaTapPub->exponentLen)
                    {
                        case 4:  /* fallthrough on each */
                            expo |= (((ubyte4) (pRsaTapPub->pExponent[3])) << 24);
                        case 3:
                            expo |= (((ubyte4) (pRsaTapPub->pExponent[2])) << 16);
                        case 2:
                            expo |= (((ubyte4) (pRsaTapPub->pExponent[1])) << 8);
                        case 1:
                            expo |= ((ubyte4) (pRsaTapPub->pExponent[0]));
                            break;
                        default:
                            status = ERR_BAD_KEY;
                            goto exit_1;
                    }

                    /* Create shell for SW public key */
                    status = CRYPTO_INTERFACE_RSA_createKey(
                      (void **) &asymPubKey.key.pRSA, akt_rsa, NULL);
                    asymPubKey.type = akt_rsa;
                    if (OK != status)
                      goto exit_1;

                    /* Load the public info into the RSA SW key from the RSA TAP key */
                    status = CRYPTO_INTERFACE_RSA_setPublicKeyParameters (
                        asymPubKey.key.pRSA, expo, pRsaTapPub->pModulus, pRsaTapPub->modulusLen, NULL, asymPubKey.type);
                    if (OK != status)
                      goto exit_1;

					/* As we are using SW key pass akt_rsa */
	                if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignature(
	                                MOC_RSA(hwAccelDescr hwAccelCtx) (RSAKey*)asymPubKey.key.pRSA,
	                                from, to, &outlen, NULL, akt_rsa))) {
	                    goto exit_1;
	                }

                    /* 3.0 provider wants the digest info to decode itself, don't decode it now */
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
                    tolen = outlen;
#else
                    if (OK > (status = ASN1_parseDigestInfo ((ubyte*)to, outlen, &pOid, &oidLen, &pBuffer, &tolen, &digestAlg)))
                    {
                        goto exit_1;
                    }
                    if (OK > (status = DIGI_MEMCPY(to, pBuffer, tolen)))
                    {
                        goto exit_1;
                    }
#endif
exit_1:
                    CRYPTO_uninitAsymmetricKey(&asymPubKey, NULL);
                    if(OK < status)
                        break;
                }
                else
                {
#endif
					/* As we are using SW key pass akt_rsa */
	                if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignature(
	                            MOC_RSA(hwAccelDescr hwAccelCtx) (RSAKey*)pRSAKey,
	                            from, to, &tolen, &pVlongQueue, akt_rsa))) {
	                    break;
	                }
#ifdef __ENABLE_DIGICERT_TAP__
                }
#endif
	            rval = tolen;
            }
            break;
        case RSA_NO_PADDING:
        case RSA_X931_PADDING:
            {
            if (OK > (status = CRYPTO_INTERFACE_RSA_applyPublicKey(
                pRSAKey, (ubyte *) from, flen, &pOutput, &pVlongQueue,
                asymKey.type)))
            {
                break;
            }

            if (RSA_NO_PADDING == padding)
                rval = RSA_padding_check_none(to, num, pOutput, flen, num);
            else
                rval = RSA_padding_check_X931(to, num, pOutput, flen, num);

            }
            break;
        default:
	    RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
	    break;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
    if (akt_tap_rsa == asymKey.type)
    {
        (void) CRYPTO_INTERFACE_TAP_RsaUnloadKey(asymKey.key.pRSA);
    }
#endif

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    if (pOutput != NULL)
        DIGI_FREE((void **)&pOutput);
    VLONG_freeVlong(&pSignature, &pVlongQueue);
    VLONG_freeVlong(&pRetMessage, &pVlongQueue);
    VLONG_freeVlongQueue(&pVlongQueue);
    return rval;
}
#else
static int
moc_rsa_pub_dec(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
    void*     pRSAKey;
    MSTATUS 	status;
    vlong*      pVlongQueue  = NULL;
    int		rval = 0;
    u_int32_t	tolen;
    vlong*	pSignature = NULL;
    vlong*	pRetMessage = NULL;
    int		num, i;
    unsigned char *buf;
    AsymmetricKey asymKey;
    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        return 0;
    if (NULL == (pRSAKey = DIGI_EVP_opensslRSA2DIGI(rsa, &asymKey)))
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return 0;
    }

    num = BN_num_bytes(rsa->n);
    switch(padding)
    {
        case RSA_PKCS1_PADDING:
            if (OK > (status = RSA_verifySignature(MOC_RSA(hwAccelDescr hwAccelCtx) (RSAKey*)pRSAKey, from,
				        to, &tolen, &pVlongQueue)))
			{
	            break;
	        }
	        rval = tolen;
            break;
        case RSA_NO_PADDING:
        case RSA_X931_PADDING:
            {
	        if (NULL == (buf = OPENSSL_malloc(num)))
	            break;
                if (OK > (status = VLONG_vlongFromByteString(from, num, &pSignature, &pVlongQueue)))
                    break;
                if (OK > (status = RSA_RSAVP1(MOC_RSA(hwAccelCtx) (RSAKey*)pRSAKey, pSignature, &pRetMessage, &pVlongQueue)))
                    break;

                /* VLONG_byteStringFromVlong uses the value stored at the
                 * pointer length as the length of the output buffer and
                 * performs length checks against this value.
                 */
                i = num;

                if (OK > (status = VLONG_byteStringFromVlong(pRetMessage, buf, &i)))
                    break;
                if (padding == RSA_NO_PADDING)
                    rval = RSA_padding_check_none(to, num, buf, i, num);
                else
                    rval = RSA_padding_check_X931(to, num, buf, i, num);
                if (buf != NULL) {
                    OPENSSL_cleanse(buf, num);
                    OPENSSL_free(buf);
                }
            }
            break;
        default:
	    RSAerr(VERSION_RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
	    break;
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    VLONG_freeVlong(&pSignature, &pVlongQueue);
    VLONG_freeVlong(&pRetMessage, &pVlongQueue);
    VLONG_freeVlongQueue(&pVlongQueue);
    return rval;
}
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static int
moc_rsa_prepare_key(RSA *rsa)
{
    int ret = -1;
    BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL;
    BIGNUM *d, *p;
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto exit;

    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);

    /* Ensure all components are non-NULL */
    if (!rsa->n && ((rsa->n = BN_new()) == NULL))
        goto exit;
    if (!rsa->d && ((rsa->d = BN_new()) == NULL))
        goto exit;
    if (!rsa->e && ((rsa->e = BN_new()) == NULL))
        goto exit;
    if (!rsa->p && ((rsa->p = BN_new()) == NULL))
        goto exit;
    if (!rsa->q && ((rsa->q = BN_new()) == NULL))
        goto exit;
    if (!rsa->dmp1 && ((rsa->dmp1 = BN_new()) == NULL))
        goto exit;
    if (!rsa->dmq1 && ((rsa->dmq1 = BN_new()) == NULL))
        goto exit;
    if (!rsa->iqmp && ((rsa->iqmp = BN_new()) == NULL))
        goto exit;

    /* calculate d */
    if (!BN_sub(r1, rsa->p, BN_value_one()))
    {
        ret = 0;
        goto exit;               /* p-1 */
    }
    if (!BN_sub(r2, rsa->q, BN_value_one()))
    {
        ret = 0;
        goto exit;               /* q-1 */
    }
    if (!BN_mul(r0, r1, r2, ctx))
    {
        ret = 0;
        goto exit;               /* (p-1)(q-1) */
    }
    if (!BN_mod_inverse(rsa->d, rsa->e, r0, ctx))
    {
        ret = 0;
        goto exit;
    }

    d = rsa->d;

    /* calculate d mod (p-1) */
    if (!BN_mod(rsa->dmp1, d, r1, ctx))
    {
        ret = 0;
        goto exit;
    }

    /* calculate d mod (q-1) */
    if (!BN_mod(rsa->dmq1, d, r2, ctx))
    {
        ret = 0;
        goto exit;
    }

    /* calculate inverse of q mod p */
    p = rsa->p;
    if (!BN_mod_inverse(rsa->iqmp, rsa->q, p, ctx))
    {
        ret = 0;
        goto exit;
    }

    ret = 1;

exit:
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}
#endif

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    RSAKey* pRSAKey = NULL;
    MSTATUS status;
    int ret = -1;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    MRsaKeyTemplate template = {0};
#else
    BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL;
    BN_CTX *ctx = NULL;
#endif
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    randomContext* pRandomContext = NULL;
#endif

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        goto exit;
    }

    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    if (g_pRandomContext == NULL)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
        {
	    ret = 0;
            goto exit;
        }
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if ( OK > (status = CRYPTO_INTERFACE_RSA_createKey(
        (void **) &pRSAKey, akt_rsa, NULL)))
    {
         ret = 0;
         goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_RSA_generateKey(MOC_SYM(hwAccelCtx) RANDOM_CTX_PR, pRSAKey,bits, NULL)))
    {
        ret = 0;
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(MOC_SYM(hwAccelCtx) pRSAKey,
                                    &template, MOC_GET_PRIVATE_KEY_DATA, akt_rsa)))
    {
        ret = 0;
        goto exit;
    }

    rsa->e = BN_bin2bn((unsigned char *)template.pE, template.eLen, NULL);
    rsa->n = BN_bin2bn((unsigned char *)template.pN, template.nLen, NULL);
    rsa->p = BN_bin2bn((unsigned char *)template.pP, template.pLen, NULL);
    rsa->q = BN_bin2bn((unsigned char *)template.pQ, template.qLen, NULL);

    if (moc_rsa_prepare_key(rsa) != 1)
    {
        ret = 0;
        goto exit;
    }
#else
    if ( OK > (status = RSA_createKey( &pRSAKey)))
    {
         ret = 0;
         goto exit;
    }
    if (OK > (status = RSA_generateKey(MOC_SYM(hwAccelCtx) RANDOM_CTX_PR, pRSAKey,bits, NULL)))
    {
        ret = 0;
        goto exit;
    }

    rsa->e = DIGI_EVP_vlong2BN(RSA_E(pRSAKey));
    rsa->n = DIGI_EVP_vlong2BN(RSA_N(pRSAKey));
    rsa->p = DIGI_EVP_vlong2BN(RSA_P(pRSAKey));
    rsa->q = DIGI_EVP_vlong2BN(RSA_Q(pRSAKey));
    rsa->dmp1 = DIGI_EVP_vlong2BN(RSA_DP(pRSAKey));
    rsa->dmq1 = DIGI_EVP_vlong2BN(RSA_DQ(pRSAKey));
    rsa->iqmp = DIGI_EVP_vlong2BN(RSA_QINV(pRSAKey));
    rsa->d = BN_new();

    /* calculate d */
    if (!BN_sub(r1, rsa->p, BN_value_one()))
    {
        ret = 0;
        goto exit;               /* p-1 */
    }
    if (!BN_sub(r2, rsa->q, BN_value_one()))
    {
        ret = 0;
        goto exit;               /* q-1 */
    }
    if (!BN_mul(r0, r1, r2, ctx))
    {
        ret = 0;
        goto exit;               /* (p-1)(q-1) */
    }
    if (!BN_mod_inverse(rsa->d, rsa->e, r0, ctx))
    {
        ret = 0;
        goto exit;
    }
#endif

    ret = 1;

exit:
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    CRYPTO_INTERFACE_RSA_freeKeyTemplate(pRSAKey, &template, akt_rsa);
#endif
    if (pRSAKey != NULL)
    {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        CRYPTO_INTERFACE_RSA_freeKey( (void **) &pRSAKey, NULL, akt_rsa);
#else
        RSA_freeKey( &pRSAKey, NULL);
#endif
    }

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    /* g_pRandomContext freed in DIGICERT_free()*/
    if (pRandomContext && (g_pRandomContext != pRandomContext))
    {
        RANDOM_releaseContext(&pRandomContext);
    }
#endif

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    return ret;
}

static int moc_rsa_init(RSA *rsa)
{
    return 1;
}

static int moc_rsa_finish(RSA *rsa)
{
    return 1;
}

static RSA_METHOD moc_evp_rsa = {
    "Mocana RSA method",
    moc_rsa_pub_enc,	/* encrypt */
    moc_rsa_pub_dec, 	/* verify */
    moc_rsa_priv_enc, 	/* sign */
    moc_rsa_priv_dec,	/* decrypt */
    NULL,	/* rsa_mod_exp */
    NULL,	/* mod_exp_mont */
    moc_rsa_init,	/* init */
    moc_rsa_finish,	/* finish */
    VERSION_RSA_METHOD_FLAG,          /* flags */
    NULL,	/* app_data */
    NULL,	/* sign (new style) */
    NULL,	/* verify (new style) */
    moc_rsa_keygen
};

#ifdef __ENABLE_DIGICERT_OSSL_FORCE_METH_BIND__
static const RSA_METHOD *moc_default_RSA_method = &moc_evp_rsa;
const RSA_METHOD *MOC_RSA_get_default_method(void)
{
    return moc_default_RSA_method;
}
#endif
#if !defined(__DISABLE_DIGICERT_SUITE_B__)

#ifdef __ENABLE_DIGICERT_TAP__

static MSTATUS
DIGI_EVP_opensslEC2MocAsym(EC_KEY *eckey, MocAsymKey *asymKey)
{
    MSTATUS status;
    AsymmetricKey asymmetricKey = { 0 };
#if defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    MOC_EVP_KEY_DATA *pMocKeyData = EC_KEY_get_ex_data(eckey, eccExAppData);
#else
    MOC_EVP_KEY_DATA *pMocKeyData = ECDSA_get_ex_data(eckey, eccExAppData);
#endif

    if(NULL != pMocKeyData)
    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (NULL != pMocKeyData->pCred)
        {
            DIGI_EVP_maskCred(pMocKeyData->pCred, pMocKeyData->credLen);

            status = CRYPTO_deserializeAsymKeyWithCreds(pMocKeyData->pContents, pMocKeyData->contentsLen, NULL, 
                                                        pMocKeyData->pCred, pMocKeyData->credLen, NULL, &asymmetricKey);        
            /* done with credential, re-mask it*/
            DIGI_EVP_maskCred(pMocKeyData->pCred, pMocKeyData->credLen);

        }
        else
#endif
        {
            status = CRYPTO_deserializeAsymKey(
                pMocKeyData->pContents, pMocKeyData->contentsLen, NULL,
                &asymmetricKey);
        }
        if (OK != status)
            goto exit;

        *asymKey = asymmetricKey.key.pMocAsymKey;
    }
    else
    {
        status = ERR_INVALID_INPUT;
    }
exit:
    return status;
}
#endif

#ifndef OPENSSL_NO_EC

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static ECCKey *MOC_EVP_opensslEC2MOC(
    EC_KEY *pEcKey
    )
{
    MSTATUS status = OK;
    ECCKey *pNewKey = NULL;
    ubyte4 eccCurveId;
    BN_CTX *pBnCtx = NULL;
    BIGNUM *pPubKey = NULL;
    int pubPointLen = 0, priScalarLen = 0;
    unsigned char *pPublicPoint = NULL, *pPrivateScalar = NULL;

    switch (pEcKey->group->curve_name)
    {
        case NID_X9_62_prime192v1:
            eccCurveId = cid_EC_P192;
            break;

        case NID_secp224r1:
	        eccCurveId = cid_EC_P224;
	        break;

        case NID_X9_62_prime256v1:
            eccCurveId = cid_EC_P256;
            break;

        case NID_secp384r1:
            eccCurveId = cid_EC_P384;
            break;

        case NID_secp521r1:
            eccCurveId = cid_EC_P521;
            break;

        default:
	        return NULL;
    }

    if (OK > (status = CRYPTO_INTERFACE_EC_newKeyEx(eccCurveId, &pNewKey, akt_ecc, NULL)))
        return NULL;

    pBnCtx = BN_CTX_new();
    if (NULL == pBnCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Retrieve the public point as a BIGNUM
     */
    pPubKey = EC_POINT_point2bn(
        pEcKey->group, pEcKey->pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL,
        pBnCtx);
    if (NULL == pPubKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Get the length of the public point and allocate memory to store it.
     */
    pubPointLen = BN_num_bytes(pPubKey);
    pPublicPoint = OPENSSL_malloc(pubPointLen);
    if (NULL == pPublicPoint)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *) pPublicPoint, 0x00, pubPointLen);

    /* Write out the public point to the buffer. The point should be in the
     * uncompressed form.
     */
    BN_bn2bin(pPubKey, pPublicPoint);

    /* Retrieve the private portion of the key if there is one.
     */
    if (NULL != pEcKey->priv_key)
    {
        priScalarLen = BN_num_bytes(pEcKey->priv_key);
        pPrivateScalar = OPENSSL_malloc(priScalarLen);
        if (NULL == pPrivateScalar)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET((ubyte *) pPrivateScalar, 0x00, priScalarLen);

        BN_bn2bin(pEcKey->priv_key, pPrivateScalar);
    }

    /* Set the parameters in the key using the crypto interface.
     */
    status = CRYPTO_INTERFACE_EC_setKeyParameters(pNewKey, pPublicPoint, pubPointLen, pPrivateScalar, priScalarLen, akt_ecc);

exit:

    /* Free up any data that was allocated.
     */
    if (NULL != pBnCtx)
        BN_CTX_free(pBnCtx);

    if (NULL != pPubKey)
        BN_free(pPubKey);

    if (NULL != pPublicPoint)
        OPENSSL_free(pPublicPoint);

    if (NULL != pPrivateScalar)
    {
        DIGI_MEMSET((ubyte *) pPrivateScalar, 0x00, priScalarLen);
        OPENSSL_free(pPrivateScalar);
    }

    if (OK != status)
    {
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pNewKey, akt_ecc);
        pNewKey = NULL;
    }

    return pNewKey;
}
#else
static ECCKey*
MOC_EVP_opensslEC2MOC(EC_KEY *eckey)
{
    ECCKey    * pNewKey = 0;
    MSTATUS	status = OK;
    unsigned char     * to;
    int			tolen, tolenby2;
    PrimeFieldPtr 	pPF;
    BIGNUM 	*pubkey_bn = NULL;
    BN_CTX    * ctx = NULL;
    PEllipticCurvePtr pEC;

    switch(eckey->group->curve_name)
    {
        case NID_X9_62_prime192v1:
	    pEC = EC_P192;
	    break;
        case NID_secp224r1:
	    pEC = EC_P224;
	    break;
        case NID_X9_62_prime256v1:
	    pEC = EC_P256;
	    break;
        case NID_secp384r1:
	    pEC = EC_P384;
	    break;
        case NID_secp521r1:
	    pEC = EC_P521;
	    break;
        default:
	    return NULL;
	    break;
    }
    if (OK > (status = EC_newKey( pEC, &pNewKey)))
    {
	    return NULL;
    }
    pPF = EC_getUnderlyingField(pNewKey->pCurve);
    ctx = BN_CTX_new();
    if (NULL == ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto done;
    }
    pubkey_bn = EC_POINT_point2bn(eckey->group, eckey->pub_key,
			POINT_CONVERSION_UNCOMPRESSED, NULL, ctx);
    tolen = BN_num_bytes(pubkey_bn);
    to = OPENSSL_malloc(tolen);
    if (NULL == to)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto done;
    }
    DIGI_MEMSET((ubyte *)to, 0x0, tolen);
    BN_bn2bin(pubkey_bn, to);
    tolenby2 = (tolen -1)/2;
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pNewKey->Qx, to+1, tolenby2)))
	    goto done;

    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pNewKey->Qy, to+1+tolenby2, tolenby2)))
	    goto done;

    /* populate into 'pNewKey' the private key 'k', and public key pair 'Qx','Qy'
     * by reading it from eckey
     */
    if (NULL == eckey->priv_key)
    {
	    pNewKey->privateKey = 0;
	    goto done;
    }
    tolen = BN_num_bytes(eckey->priv_key);
    OPENSSL_free(to);
    to = OPENSSL_malloc(tolen);
    if (NULL == to)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto done;
    }
    DIGI_MEMSET((ubyte *)to, 0x0, tolen);
    BN_bn2bin(eckey->priv_key, to);
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pNewKey->k, to, tolen)))
	    goto done;

    pNewKey->privateKey = 1;
done:
    if (NULL != to)
    {
        OPENSSL_free(to);
        to = NULL;
    }
    if (ctx != NULL)
    {
        BN_CTX_free(ctx);
        ctx = NULL;
    }
    if(pubkey_bn != NULL)
    {
        BN_free(pubkey_bn);
        pubkey_bn = NULL;
    }
    
    if (OK != status)
    {
        EC_deleteKeyEx(&pNewKey);
        pNewKey = NULL;
    }

    return pNewKey;
}
#endif
#endif

#if !defined(OPENSSL_NO_ECDSA) && !defined(OPENSSL_NO_EC)

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
ECDSA_SIG *moc_ecdsa_sign(
    const unsigned char *pDigest,
    int digestLen,
    const BIGNUM *pKInv,
    const BIGNUM *pR,
    EC_KEY *pEcKey
    )
{
    MSTATUS status;
    void *pKey = NULL;
    ubyte4 keyType, elementLen;
    ubyte *pSignature = NULL;
    ubyte4 signatureLen;
    ECDSA_SIG *pRetSig = NULL;

    /* Attempt to deserialize a TAP key. If the TAP portion fails then attempt
     * to deserialize the key as a software key. If both fail then return NULL.
     */
#ifdef __ENABLE_DIGICERT_TAP__
    keyType = akt_tap_ecc;
    if (OK != (status = DIGI_EVP_opensslEC2MocAsym(
            pEcKey, (MocAsymKey *) &pKey)))
#endif
    {
        keyType = akt_ecc;
        pKey = MOC_EVP_opensslEC2MOC(pEcKey);
        if (NULL == pKey)
            return NULL;
    }

    /* Retrieve the length of an EC element from the key.
     */
    if (OK > (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
            pKey, &elementLen, keyType)))
        goto exit;

    /* The signature length should be twice the element length, so allocate a
     * buffer with the appropriate length.
     */
    signatureLen = elementLen * 2;
    pSignature = (ubyte *) MALLOC(signatureLen);
    if (NULL == pSignature)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Sign the digest with the key. The key will be a TAP key or a software
     * key.
     */
    if (OK > (status = CRYPTO_INTERFACE_ECDSA_signDigest(
            pKey, RANDOM_FUN, RANDOM_CTX, (ubyte *) pDigest, digestLen,
            pSignature, signatureLen, &signatureLen, keyType)))
        goto exit;

    if ( signatureLen != (elementLen * 2) )
    {
        status = ERR_SSL_INVALID_SIGNATURE;
        goto exit;
    }

    /* Convert the ECDSA signature into an OpenSSL ECDSA signature object.
     * This will be returned to the caller.
     */
    pRetSig = ECDSA_SIG_new();
    if (NULL == pRetSig)
        goto exit;

    if (pRetSig->r != NULL)
    {
        /* In 1.0.2x versions, ECDSA_SIG_new allocates r and s values.
         * If we overwrite them, it leads to a leak
         */
        BN_bin2bn(pSignature, elementLen, pRetSig->r);
    }
    else
    {
        pRetSig->r = BN_bin2bn(pSignature, elementLen, NULL);
    }

    if (pRetSig->s != NULL)
    {
        BN_bin2bn(pSignature + elementLen, elementLen, pRetSig->s);
    }
    else
    {
        pRetSig->s = BN_bin2bn(pSignature + elementLen, elementLen, NULL);
    }

exit:

    if (NULL != pKey)
        CRYPTO_INTERFACE_EC_deleteKey(&pKey, keyType);

    if (NULL != pSignature)
        FREE(pSignature);

    return pRetSig;
}
#else
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
ECDSA_SIG*
moc_ecdsa_sign(const unsigned char *dgst, int dlen,
               const BIGNUM *in_kinv, const BIGNUM *in_r,
               EC_KEY *eckey)
{
    ECCKey*     pECCKey = NULL;
    MSTATUS 	status;
    ECDSA_SIG * rval = NULL;
    PFEPtr 	r = 0, s = 0;
    PrimeFieldPtr 	pPF;
    ubyte     * pub = NULL;
    sbyte4	plen;

    if (NULL == (pECCKey = MOC_EVP_opensslEC2MOC(eckey))) {
        return NULL;
    }
    pPF = EC_getUnderlyingField(pECCKey->pCurve);
    PRIMEFIELD_newElement(pPF, &r);
    PRIMEFIELD_newElement(pPF, &s);

    if (OK > (status = ECDSA_signDigestAux(pECCKey->pCurve, pECCKey->k, RANDOM_FUN,
                    RANDOM_CTX, dgst, dlen, r, s))) {
        if ( OK != status ) {
            goto exit;
        }
    }

    /* convert r and s to ECDSA_SIG format */

    if (NULL == (rval = ECDSA_SIG_new())) {
        return NULL;
    }
    PRIMEFIELD_getAsByteString(pPF, r, &pub, &plen);
    if (rval->r != NULL)
    {
        /* In 1.0.2x versions, ECDSA_SIG_new allocates r and s values.
         * If we overwrite them, it leads to a leak
         * */
        BN_bin2bn(pub, plen, rval->r);
    }
    else
    {
        rval->r = BN_bin2bn(pub, plen, NULL);
    }

    FREE(pub);
    PRIMEFIELD_getAsByteString(pPF, s, &pub, &plen);
    if (rval->s != NULL)
    {
        BN_bin2bn(pub, plen, rval->s);
    }
    else
    {
        rval->s = BN_bin2bn(pub, plen, NULL);
    }

    FREE(pub);
exit:

    if(r) PRIMEFIELD_deleteElement(pPF, &r);
    if(s) PRIMEFIELD_deleteElement(pPF, &s);
    if(pECCKey) EC_deleteKey(&pECCKey);

    return rval;
}
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_ecdsa_verify(
    const unsigned char *pDigest,
    int digestLen,
    const ECDSA_SIG *pSignature,
    EC_KEY *pEcKey
    )
{
    MSTATUS status;
    void *pKey = NULL;
    ubyte4 keyType;
    ubyte *pR = NULL, *pS = NULL;
    ubyte4 rLen, sLen, vfyRes;
    int retVal = 0;

    /* Attempt to deserialize a TAP key. If the TAP portion fails then attempt
     * to deserialize the key as a software key. If both fail then return NULL.
     */
#ifdef __ENABLE_DIGICERT_TAP__
    keyType = akt_tap_ecc;
    if (OK != (status = DIGI_EVP_opensslEC2MocAsym(pEcKey, (MocAsymKey *) &pKey)))
#endif
    {
        keyType = akt_ecc;
        pKey = MOC_EVP_opensslEC2MOC(pEcKey);
        if (NULL == pKey)
            return 0;
    }

    rLen = BN_num_bytes(pSignature->r);
    pR = OPENSSL_malloc(rLen);
    BN_bn2bin(pSignature->r, pR);

    sLen = BN_num_bytes(pSignature->s);
    pS = OPENSSL_malloc(sLen);
    BN_bn2bin(pSignature->s, pS);

    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigest(
        pKey, (ubyte *) pDigest, digestLen, pR, rLen, pS, sLen, &vfyRes, keyType);
    if ( (OK != status) || (0 != vfyRes) )
        goto exit;

    retVal = 1;

exit:

    if (NULL != pKey)
        CRYPTO_INTERFACE_EC_deleteKey(&pKey, keyType);

    if (NULL != pR)
        OPENSSL_free(pR);

    if (NULL != pS)
        OPENSSL_free(pS);

    return retVal;
}
#else
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
int moc_ecdsa_verify(const unsigned char *dgst, int dgst_len,
                     const ECDSA_SIG *sig, EC_KEY *eckey)
{
    ECCKey*     pECCKey = NULL;
    MSTATUS 	status;
    int 	rval = 0;
    unsigned char     * to;
    int			tolen;
    PrimeFieldPtr 	pPF;
    PFEPtr 	r = NULL, s = NULL;

    if (NULL == (pECCKey = MOC_EVP_opensslEC2MOC(eckey)))
        return 0;

    pPF = EC_getUnderlyingField(pECCKey->pCurve);
    PRIMEFIELD_newElement(pPF, &r);
    PRIMEFIELD_newElement(pPF, &s);

    tolen = BN_num_bytes(sig->r);
    to = OPENSSL_malloc(tolen);
    DIGI_MEMSET((ubyte *)to, 0x0, tolen);
    BN_bn2bin(sig->r, to);
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, r, to, tolen)))
    {
        OPENSSL_free(to);
        goto exit;
    }
    OPENSSL_free(to);
    tolen = BN_num_bytes(sig->s);
    to = OPENSSL_malloc(tolen);
    DIGI_MEMSET((ubyte *)to, 0x0, tolen);
    BN_bn2bin(sig->s, to);
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, s, to, tolen)))
    {
        OPENSSL_free(to);
        goto exit;
    }
    OPENSSL_free(to);

    if (OK > (status = ECDSA_verifySignature(pECCKey->pCurve, pECCKey->Qx,
                    pECCKey->Qy, dgst, dgst_len, r, s)))
    {
        rval = 0;
        goto exit;
    }

    rval = 1;

exit:
    if(r) PRIMEFIELD_deleteElement(pPF, &r);
    if(s) PRIMEFIELD_deleteElement(pPF, &s);
    if(pECCKey) EC_deleteKey(&pECCKey);
    return rval;
}
#endif

static int
moc_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
		     BIGNUM **r)
{
    return 1;
}

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static ECDSA_METHOD moc_evp_ecdsa_meth = {
    "Mocana ECDSA method",
    moc_ecdsa_sign,
    moc_ecdsa_sign_setup,
    moc_ecdsa_verify,
#if 0
    moc_ecdsa_init,             /* init */
    NULL,                       /* finish */
#endif
    0,                          /* flags */
    NULL                        /* app_data */
};
#endif
#endif
#endif

#ifdef __ENABLE_DIGICERT_DSA__

#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
#define OSSL_DSA_KEY_PARAM( x) dsa->params.x
#else
#define OSSL_DSA_KEY_PARAM( x) dsa->x
#endif

static DSAKey *
MOC_EVP_opensslDSA2MOC(DSA *dsa)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MDsaKeyTemplate template = { 0 };
#endif
    DSAKey    * pDSAKey = NULL;
    ubyte     * pP, *pQ, *pG, *pX, *pY;
    ubyte4	lenP, lenQ, lenG, lenX, lenY;
    MSTATUS	status;
    vlong     * pVlongQueue  = NULL;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    lenP = lenQ = lenG = lenX = lenY = 0;

    if (OK > (status = CRYPTO_INTERFACE_DSA_createKey(&pDSAKey)))
        return NULL;
#else
    if (OK > (status = DSA_createKey(&pDSAKey)))
	return NULL;
#endif

    pP = pQ = pG = pX = pY = NULL;
    /* convert p */
    lenP = BN_num_bytes(OSSL_DSA_KEY_PARAM(p));
    pP = OPENSSL_malloc(lenP);
    DIGI_MEMSET((ubyte *)pP, 0x0, lenP);
    BN_bn2bin(OSSL_DSA_KEY_PARAM(p), pP);
    /* convert q */
    lenQ = BN_num_bytes(OSSL_DSA_KEY_PARAM(q));
    pQ = OPENSSL_malloc(lenQ);
    DIGI_MEMSET((ubyte *)pQ, 0x0, lenQ);
    BN_bn2bin(OSSL_DSA_KEY_PARAM(q), pQ);
    /* convert g */
    lenG = BN_num_bytes(OSSL_DSA_KEY_PARAM(g));
    pG = OPENSSL_malloc(lenG);
    DIGI_MEMSET((ubyte *)pG, 0x0, lenG);
    BN_bn2bin(OSSL_DSA_KEY_PARAM(g), pG);
    if (dsa->priv_key)
    {
	/* convert priv_key */
	lenX = BN_num_bytes(dsa->priv_key);
	pX = OPENSSL_malloc(lenX);
	DIGI_MEMSET((ubyte *)pX, 0x0, lenX);
	BN_bn2bin(dsa->priv_key, pX);
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
	if (OK > (status = DSA_setAllKeyParameters(MOC_RSA(hwAccelCtx) pDSAKey,
			       pP, lenP, pQ, lenQ, pG, lenG,  pX, lenX, &pVlongQueue)))
        {
	    DSA_freeKey(&pDSAKey, NULL);
	    goto exit;
	}
#endif
    }
    else if (dsa->pub_key)
    {
	/* convert pub_key */
	lenY = BN_num_bytes(dsa->pub_key);
	pY = OPENSSL_malloc(lenY);
	DIGI_MEMSET((ubyte *)pY, 0x0, lenY);
	BN_bn2bin(dsa->pub_key, pY);
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
	if (OK > (status = DSA_setPublicKeyParameters(pDSAKey, pP, lenP, pQ, lenQ,
			       pG, lenG,  pY, lenY, &pVlongQueue)))
        {
	        DSA_freeKey(&pDSAKey, NULL);
	        goto exit;
	    }
#endif
    }
    else
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_freeKey(&pDSAKey, NULL);
#else
        DSA_freeKey(&pDSAKey, NULL);
#endif
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    template.pP = pP;
    template.pLen = lenP;
    template.pQ = pQ;
    template.qLen = lenQ;
    template.pG = pG;
    template.gLen = lenG;
    template.pY = pY;
    template.yLen = lenY;
    template.pX = pX;
    template.xLen = lenX;
    if (OK > (status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(
            pDSAKey, &template)))
    {
        CRYPTO_INTERFACE_DSA_freeKey(&pDSAKey, NULL);
    }
#endif

exit:

    if (pP) OPENSSL_free(pP);
    if (pQ) OPENSSL_free(pQ);
    if (pG) OPENSSL_free(pG);
    if (pX) OPENSSL_free(pX);
    if (pY) OPENSSL_free(pY);
    VLONG_freeVlongQueue(&pVlongQueue);

    return pDSAKey;
}
#endif

BIGNUM *
DIGI_EVP_vlong2BN(vlong *v)
{
    sbyte4	bufferLen;
    ubyte     * buffer = NULL;
    BIGNUM    * ret = NULL;

    if (OK != VLONG_byteStringFromVlong(v, NULL, &bufferLen))
    {
        goto exit;
    }
    if (NULL == (buffer = OPENSSL_malloc(bufferLen)))
    {
        goto exit;
    }
    if (OK != VLONG_byteStringFromVlong(v, buffer, &bufferLen))
    {
        goto exit;
    }
    ret = BN_bin2bn((unsigned char *)buffer, bufferLen, NULL);

exit:
    if (NULL != buffer)
    {
        OPENSSL_free(buffer);
    }
    return ret;
}

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
vlong * moc_BIGNUM_to_vlong(const BIGNUM *bn, vlong **ppVlongQueue)
{
    int 	len;
    unsigned char * buf;
    vlong     * pRet = NULL;

    len = BN_num_bytes(bn);
    buf = OPENSSL_malloc(len);
    if (NULL == buf)
    {
        return NULL;
    }
    DIGI_MEMSET((ubyte *)buf, 0x0, len);
    BN_bn2bin(bn, buf);
    (void) VLONG_vlongFromByteString((const ubyte *)buf, len, &pRet, ppVlongQueue);
    OPENSSL_free(buf);
    return pRet;
}

#ifdef __ENABLE_DIGICERT_DSA__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static 
#endif
DSA_SIG *moc_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    DSAKey    * pDSAKey;
    DSA_SIG   * ret = NULL;
    vlong     * pVlongQueue = NULL;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte *pR = NULL, *pS = NULL;
    ubyte4 rLen, sLen;
#else
    vlong     * vR = NULL;
    vlong     * vS = NULL;
#endif
    MSTATUS 	status = OK;

    if (NULL == (pDSAKey = MOC_EVP_opensslDSA2MOC(dsa)))
	return NULL;

    ret = DSA_SIG_new();
    if (ret == NULL)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DSA_computeSignature2Aux(RANDOM_FUN, RANDOM_CTX,
             pDSAKey, (ubyte *) dgst, dlen, &pR, &rLen, &pS, &sLen, &pVlongQueue)))
      goto exit;

    ret->r = BN_bin2bn(pR, rLen, NULL);
    ret->s = BN_bin2bn(pS, sLen, NULL);
#else
    if (OK > (status = DSA_computeSignature2(RANDOM_FUN, RANDOM_CTX,
             pDSAKey, dgst, dlen, &vR, &vS, &pVlongQueue)))
      goto exit;

    ret->r = DIGI_EVP_vlong2BN(vR);
    ret->s = DIGI_EVP_vlong2BN(vS);
#endif


  exit:
    if (OK > status) {
	DSA_SIG_free(ret);
	ret = NULL;
    }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    DIGI_FREE((void **) &pR);
    DIGI_FREE((void **) &pS);
    CRYPTO_INTERFACE_DSA_freeKey(&pDSAKey, NULL);
#else
    VLONG_freeVlong(&vR, &pVlongQueue);
    VLONG_freeVlong(&vS, &pVlongQueue);
    DSA_freeKey(&pDSAKey, NULL);
#endif
    VLONG_freeVlongQueue(&pVlongQueue);

    return ret;
}
#endif

#ifdef __ENABLE_DIGICERT_DSA__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif 
int moc_dsa_do_verify(const unsigned char *dgst, int dgst_len,
			     DSA_SIG *sig, DSA *dsa)
{
    DSAKey    * pDSAKey;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte *pR = NULL, *pS = NULL;
    ubyte4 rLen, sLen;
#else
    vlong     * pR = NULL;
    vlong     * pS = NULL;
#endif
    int		rval = -1;
    vlong     * pVlongQueue = NULL;
    intBoolean  isGoodSignature;
    MSTATUS	status;

    if (NULL == (pDSAKey = MOC_EVP_opensslDSA2MOC(dsa)))
	return 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* convert r */
    rLen = BN_num_bytes(sig->r);
    pR = OPENSSL_malloc(rLen);
    DIGI_MEMSET(pR, 0x00, rLen);
    BN_bn2bin(sig->r, pR);

    /* convert s */
    sLen = BN_num_bytes(sig->s);
    pS = OPENSSL_malloc(sLen);
    DIGI_MEMSET(pS, 0x00, sLen);
    BN_bn2bin(sig->s, pS);

    if (OK > (status = CRYPTO_INTERFACE_DSA_verifySignature2Aux(
            MOC_DSA(hwAccelDescr hwAccelCtx) pDSAKey, (ubyte *) dgst, dgst_len, pR, rLen,
            pS, sLen, &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (NULL == (pR = moc_BIGNUM_to_vlong(sig->r, &pVlongQueue)))
	goto exit;
    if (NULL == (pS = moc_BIGNUM_to_vlong(sig->s, &pVlongQueue)))
	goto exit;

    if (OK > (status = DSA_verifySignature2(MOC_DSA(hwAccelDescr hwAccelCtx) pDSAKey,
					   dgst, dgst_len, pR, pS, &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }
#endif

    rval = isGoodSignature ? 1 : 0;
  exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pR) OPENSSL_free(pR);
    if (pS) OPENSSL_free(pS);
    CRYPTO_INTERFACE_DSA_freeKey(&pDSAKey, NULL);
#else
    if (pR) VLONG_freeVlong(&pR, &pVlongQueue);
    if (pS) VLONG_freeVlong(&pS, &pVlongQueue);
    DSA_freeKey(&pDSAKey, NULL);
#endif
    VLONG_freeVlongQueue(&pVlongQueue);
   return rval;
}
#endif

#ifdef __ENABLE_DIGICERT_DSA__
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int moc_dsa_keygen(DSA *dsa) {

    DSAKey    		*pDSAKey = NULL;
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    randomContext*  	pRandomContext = NULL;
#endif
    MSTATUS         	status = -1;
    int 		len_p = 0;
    int 		len_q = 0;
    int 		len_g = 0;
    unsigned char 	*bufp = NULL;
    unsigned char 	*bufq = NULL;
    unsigned char 	*bufg = NULL;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MDsaKeyTemplate template = { 0 };
    intBoolean freeTemplate = FALSE;
#endif

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    if (g_pRandomContext == NULL)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
        {
            goto exit;
        }
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DSA_createKey(&pDSAKey)))
        goto exit;
#else
    if (OK > (status = DSA_createKey(&pDSAKey)))
        goto exit;
#endif

    len_p = BN_num_bytes(OSSL_DSA_KEY_PARAM(p));
    bufp = OPENSSL_malloc(len_p);
    if (NULL == bufp)
	goto exit;

    DIGI_MEMSET((ubyte *)bufp, 0x0, len_p);
    BN_bn2bin(OSSL_DSA_KEY_PARAM(p), bufp);

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* Convert p byte array to vlong and copy to pDSAKey */
    if (OK > (status = VLONG_vlongFromByteString((const ubyte*)bufp, len_p, &(DSA_P(pDSAKey)),
                                             NULL)))
    {
        goto exit;
    }
#endif

    len_q = BN_num_bytes(OSSL_DSA_KEY_PARAM(q));
    bufq = OPENSSL_malloc(len_q);
    if (NULL == bufq) {
	goto exit;
    }
    DIGI_MEMSET((ubyte *)bufq, 0x0, len_q);
    BN_bn2bin(OSSL_DSA_KEY_PARAM(q), bufq);

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* Convert q byte array to vlong and copy to pDSAKey */
    if (OK > (status = VLONG_vlongFromByteString((const ubyte*)bufq, len_q, &(DSA_Q(pDSAKey)),
                                             NULL)))
    {
        goto exit;
    }
#endif

    len_g = BN_num_bytes(OSSL_DSA_KEY_PARAM(g));
    bufg = OPENSSL_malloc(len_g);
    if (NULL == bufg)
	goto exit;

    DIGI_MEMSET((ubyte *)bufg, 0x0, len_g);
    BN_bn2bin(OSSL_DSA_KEY_PARAM(g), bufg);

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* Convert g byte array to vlong and copy to pDSAKey */
    if (OK > (status = VLONG_vlongFromByteString((const ubyte*)bufg, len_g, &(DSA_G(pDSAKey)),
                                             NULL)))
    {
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    template.pP = bufp;
    template.pLen = len_p;
    template.pQ = bufq;
    template.qLen = len_q;
    template.pG = bufg;
    template.gLen = len_g;

    if (OK > (status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(
            pDSAKey, &template)))
    {
        goto exit;
    }

    DIGI_MEMSET((ubyte *) &template, 0x00, sizeof(MDsaKeyTemplate));

    if (OK > (status = CRYPTO_INTERFACE_DSA_computeKeyPair(RANDOM_CTX_PR, pDSAKey, NULL)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(
            pDSAKey, &template, MOC_GET_PRIVATE_KEY_DATA)))
    {
        goto exit;
    }

    freeTemplate = TRUE;

    if(dsa->pub_key) BN_free(dsa->pub_key);
    dsa->pub_key = BN_bin2bn(template.pY, template.yLen, NULL);

    if(dsa->priv_key) BN_free(dsa->priv_key);
    dsa->priv_key = BN_bin2bn(template.pX, template.xLen, NULL);
#else
    if (OK > (status = DSA_computeKeyPair(RANDOM_CTX_PR, pDSAKey, NULL)))
    {
        goto exit;
    }

    if(dsa->pub_key) BN_free(dsa->pub_key);
    dsa->pub_key = DIGI_EVP_vlong2BN(DSA_Y(pDSAKey));
    if(dsa->priv_key) BN_free(dsa->priv_key);
    dsa->priv_key = DIGI_EVP_vlong2BN(DSA_X(pDSAKey));
#endif

    status = 1;

  exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (TRUE == freeTemplate)
        CRYPTO_INTERFACE_DSA_freeKeyTemplate(pDSAKey, &template);
#endif

    if (pDSAKey != NULL)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_freeKey(&pDSAKey, NULL);
#else
        DSA_freeKey(&pDSAKey, NULL);
#endif
    }

#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    /* g_pRandomContext freed in DIGICERT_free()*/
    if (pRandomContext && (g_pRandomContext != pRandomContext))
    {
        RANDOM_releaseContext(&pRandomContext);
    }
#endif

    if(bufp)
        OPENSSL_free(bufp);
    if(bufq)
        OPENSSL_free(bufq);
    if(bufg)
        OPENSSL_free(bufg);

    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_DSA__
/* TODO: review DSA changes */
static int moc_dsa_init(DSA *dsa)
{
    return (1);
}

static int moc_dsa_finish(DSA *dsa)
{
    return (1);
}

static int moc_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
			      BIGNUM **rp)
{
    return 1;
}

static DSA_METHOD moc_evp_dsa_meth = {
    "MOCANA DSA method",
    moc_dsa_do_sign,
    moc_dsa_sign_setup,
    moc_dsa_do_verify,
    NULL,                       /* dsa_mod_exp, */
    NULL,                       /* dsa_bn_mod_exp, */
    moc_dsa_init,
    moc_dsa_finish,
    0,
    NULL,
    NULL,
    moc_dsa_keygen
};
#endif

#ifdef __ENABLE_DIGICERT_OSSL_FORCE_METH_BIND__
static const DSA_METHOD *moc_default_DSA_method = &moc_evp_dsa_meth;
const DSA_METHOD *MOC_DSA_get_default_method(void)
{
    return moc_default_DSA_method;
}
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

static MSTATUS MocEvpBignumToByteArrAlloc(
    BIGNUM *pBignum,
    ubyte **ppRetBuffer,
    ubyte4 *pRetBufferLen
    )
{
    MSTATUS status;
    int bufferLen;
    ubyte *pBuffer = NULL;

    if ( (NULL == pBignum) || (NULL == ppRetBuffer) || (NULL == pRetBufferLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != *ppRetBuffer)
    {
        status = DIGI_FREE((void **) ppRetBuffer);
        if (OK != status)
            goto exit;
    }

    bufferLen = BN_num_bytes(pBignum);

    status = DIGI_MALLOC((void **) &pBuffer, (ubyte4) bufferLen);
    if (OK != status)
        goto exit;

    *pRetBufferLen = (ubyte4) BN_bn2bin(pBignum, pBuffer);
    *ppRetBuffer = pBuffer;
    pBuffer = NULL;

exit:

    if (NULL != pBuffer)
        DIGI_FREE((void **) &pBuffer);

    return status;
}

static MSTATUS MocEvpOpensslDhToMocDh(
    DH *pDH,
    diffieHellmanContext **ppRetContext
    )
{
    MSTATUS status;
    diffieHellmanContext *pContext = NULL;
    MDhKeyTemplate template = { 0 };
    intBoolean isValid = FALSE;
    ubyte4 privKeyLen;

    status = CRYPTO_INTERFACE_DH_allocateExt(&pContext, NULL);
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->params.p, &(template.pP), &(template.pLen));
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->params.g, &(template.pG), &(template.gLen));
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->priv_key, &(template.pY), &(template.yLen));
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->priv_key, &(template.pY), &(template.yLen));
    if (OK != status)
        goto exit;

    if (NULL != pDH->params.q)
    {
        status = MocEvpBignumToByteArrAlloc(
            pDH->params.q, &(template.pQ), &(template.qLen));
        if (OK != status)
            goto exit; 
    }

    status = CRYPTO_INTERFACE_DH_setKeyParametersExt(
        pContext, &template, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_verifySafePG(pContext, &isValid,
        &privKeyLen, NULL);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_DIGICERT_STRICT_DH_GROUP__))
        status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
        goto exit;
#else
        privKeyLen = EVP_DH_CUSTOM_GROUP_PRI_LEN;
#endif
    }

    *ppRetContext = pContext;
    pContext = NULL;

exit:

    CRYPTO_INTERFACE_DH_freeKeyTemplate(pContext, &template);

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContextExt(&pContext, NULL, NULL);

    return status;
}

int moc_compute_dh_key(
    unsigned char *pKey,
    const BIGNUM *pPubKey,
    DH *pDH,
    ubyte pad,
    ubyte4 dhSize
    )
{
    MSTATUS status;
    diffieHellmanContext *pContext = NULL;
    ubyte *pPublic = NULL, *pSecret = NULL;
    ubyte4 publicLen = 0, secretLen = 0;

    status = MocEvpOpensslDhToMocDh(pDH, &pContext);
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        (BIGNUM *) pPubKey, &pPublic, &publicLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(
        pContext, NULL, pPublic, publicLen, &pSecret, &secretLen, NULL);
    if (OK != status)
        goto exit;

    if(pad)
    {
        ubyte4 i = 0;

        for (; i < (dhSize - secretLen); i++)
        {
            *pKey = 0x00;
            pKey++; /* ok to change passed by value ptr value */
        }
    }

    status = DIGI_MEMCPY(pKey, pSecret, secretLen);

exit:

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContext(&pContext, NULL);

    if (NULL != pSecret)
    {
        DIGI_MEMSET(pSecret, 0x00, secretLen);
        DIGI_FREE((void **) &pSecret);
    }

    if (NULL != pPublic)
        DIGI_FREE((void **) &pPublic);

    return status ? -1 : (int) (pad ? dhSize : secretLen);
}

static
int moc_compute_dh_key_ex(
    unsigned char *pKey,
    const BIGNUM *pPubKey,
    DH *pDH
    )
{
    MSTATUS status;
    diffieHellmanContext *pContext = NULL;
    ubyte *pPublic = NULL, *pSecret = NULL;
    ubyte4 publicLen = 0, secretLen = 0;

    status = MocEvpOpensslDhToMocDh(pDH, &pContext);
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        (BIGNUM *) pPubKey, &pPublic, &publicLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(
        pContext, NULL, pPublic, publicLen, &pSecret, &secretLen, NULL);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKey, pSecret, secretLen);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContext(&pContext, NULL);

    if (NULL != pSecret)
    {
        DIGI_MEMSET(pSecret, 0x00, secretLen);
        DIGI_FREE((void **) &pSecret);
    }

    if (NULL != pPublic)
        DIGI_FREE((void **) &pPublic);

    return status ? -1 : secretLen;
}

static MSTATUS MocEvpDhComputePublic(
    DH *pDH
    )
{
    MSTATUS status;
    BN_CTX *pBnCtx = NULL;

    pBnCtx = BN_CTX_new();
    if (NULL == pBnCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pDH->pub_key)
    {
        pDH->pub_key = BN_new();
        if (NULL == pDH->pub_key)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }

    if (1 != BN_mod_exp(pDH->pub_key, pDH->params.g, pDH->priv_key, pDH->params.p, pBnCtx))
        status = ERR_CRYPTO;
    else
        status = OK;

exit:

    if (NULL != pBnCtx)
        BN_CTX_free(pBnCtx);

    return status;
}

int moc_generate_key(
    DH *pDH
    )
{
    MSTATUS status;
    ubyte4 privLen;
    MDhKeyTemplate template = { 0 };
    diffieHellmanContext *pContext = NULL;
    intBoolean isValid = FALSE;

    if ( (NULL == pDH->params.p) || (NULL == pDH->params.g) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* If a private key value does not exist then create a DH context and load
     * in the generator and prime values. Once these values are loaded in a new
     * key pair can be generated. Once the new key pair is generated, store the
     * public and private portion as BIGNUMs in the callers OpenSSL DH context.
     *
     * If a private key value already exists then compute the public portion and
     * set it in the OpenSSL DH context.
     */
    if (NULL == pDH->priv_key)
    {
        status = CRYPTO_INTERFACE_DH_allocateExt(&pContext, NULL);
        if (OK != status)
            goto exit;

        status = MocEvpBignumToByteArrAlloc(
            pDH->params.p, &(template.pP), &(template.pLen));
        if (OK != status)
            goto exit;

        status = MocEvpBignumToByteArrAlloc(
            pDH->params.g, &(template.pG), &(template.gLen));
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_setKeyParametersExt(
            pContext, &template, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_verifySafePG(pContext, &isValid, &privLen,
            NULL);
        if (OK != status)
            goto exit;

        if (FALSE == isValid)
        {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_DIGICERT_STRICT_DH_GROUP__))
            status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
            goto exit;
#else
            privLen = EVP_DH_CUSTOM_GROUP_PRI_LEN;
#endif
        }

        status = CRYPTO_INTERFACE_DH_generateKeyPairExt(
            pContext, RANDOM_CTX_MOC, privLen, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_freeKeyTemplate(pContext, &template);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(
            &template, pContext, MOC_GET_PRIVATE_KEY_DATA, NULL);
        if (OK != status)
            goto exit;

        pDH->priv_key = BN_bin2bn(template.pY, template.yLen, NULL);
        if (NULL == pDH->priv_key)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pDH->pub_key = BN_bin2bn(template.pF, template.fLen, NULL);
        if (NULL == pDH->pub_key)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }
    else
    {
        status = MocEvpDhComputePublic(pDH);
        if (OK != status)
            goto exit;
    }

exit:

    CRYPTO_INTERFACE_DH_freeKeyTemplate(pContext, &template);

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContext(&pContext, NULL);

    return status ? 0 : 1;
}

static int moc_dh_init(DH *dh)
{
    return 1;
}

static int moc_dh_finish(DH *dh)
{
    return 1;
}

static int
moc_dh_bn_mod_exp(const DH *dh, BIGNUM *r,
	      const BIGNUM *a, const BIGNUM *p,
	      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    vlong     * G = NULL;
    vlong     * priv = NULL;
    vlong     * P = NULL;
    vlong     * pVlongQueue = NULL;
    vlong     * pub = NULL;
    BIGNUM    * ret = NULL;
    MSTATUS	status;
    int		rval = 0;

    if (NULL == (G = moc_BIGNUM_to_vlong(a, &pVlongQueue)))
	goto exit;
    if (NULL == (priv = moc_BIGNUM_to_vlong(p, &pVlongQueue)))
	goto exit;
    if (NULL == (P = moc_BIGNUM_to_vlong(m, &pVlongQueue)))
	goto exit;
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx)
			     G, priv, P, &pub, &pVlongQueue)))
    {
	goto exit;
    }
    ret = DIGI_EVP_vlong2BN(pub);
    BN_copy(r, ret);
    rval = 1;
exit:
    if (G) VLONG_freeVlong(&G, &pVlongQueue);
    if (priv) VLONG_freeVlong(&priv, &pVlongQueue);
    if (P) VLONG_freeVlong(&P, &pVlongQueue);
    if (pub) VLONG_freeVlong(&pub, &pVlongQueue);
    if (ret) BN_clear_free(ret);
    VLONG_freeVlongQueue(&pVlongQueue);
    return rval;
}

#else /* if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__

static MSTATUS MocEvpBignumToByteArrAlloc(
    BIGNUM *pBignum,
    ubyte **ppRetBuffer,
    ubyte4 *pRetBufferLen
    )
{
    MSTATUS status;
    int bufferLen;
    ubyte *pBuffer = NULL;

    if ( (NULL == pBignum) || (NULL == ppRetBuffer) || (NULL == pRetBufferLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != *ppRetBuffer)
    {
        status = DIGI_FREE((void **) ppRetBuffer);
        if (OK != status)
            goto exit;
    }

    bufferLen = BN_num_bytes(pBignum);

    status = DIGI_MALLOC((void **) &pBuffer, (ubyte4) bufferLen);
    if (OK != status)
        goto exit;

    *pRetBufferLen = (ubyte4) BN_bn2bin(pBignum, pBuffer);
    *ppRetBuffer = pBuffer;
    pBuffer = NULL;

exit:

    if (NULL != pBuffer)
        DIGI_FREE((void **) &pBuffer);

    return status;
}

static MSTATUS MocEvpOpensslDhToMocDh(
    DH *pDH,
    diffieHellmanContext **ppRetContext
    )
{
    MSTATUS status;
    diffieHellmanContext *pContext = NULL;
    MDhKeyTemplate template = { 0 };
    intBoolean isValid = FALSE;
    ubyte4 privKeyLen;

    status = CRYPTO_INTERFACE_DH_allocateExt(&pContext, NULL);
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->p, &(template.pP), &(template.pLen));
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->g, &(template.pG), &(template.gLen));
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->priv_key, &(template.pY), &(template.yLen));
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        pDH->priv_key, &(template.pY), &(template.yLen));
    if (OK != status)
        goto exit;

    if (NULL != pDH->q)
    {
        status = MocEvpBignumToByteArrAlloc(
            pDH->q, &(template.pQ), &(template.qLen));
        if (OK != status)
            goto exit; 
    }

    status = CRYPTO_INTERFACE_DH_setKeyParametersExt(
        pContext, &template, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_verifySafePG(pContext, &isValid,
        &privKeyLen, NULL);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_DIGICERT_STRICT_DH_GROUP__))
        status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
        goto exit;
#else
        privKeyLen = EVP_DH_CUSTOM_GROUP_PRI_LEN;
#endif
    }

    *ppRetContext = pContext;
    pContext = NULL;

exit:

    CRYPTO_INTERFACE_DH_freeKeyTemplate(pContext, &template);

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContextExt(&pContext, NULL, NULL);

    return status;
}
#else
static diffieHellmanContext *
MOC_EVP_opensslDH2MOC(const BIGNUM *pub_key, DH *dh, vlong **ppVlongQueue)
{
    diffieHellmanContext      * pDHCtx = NULL;
    MSTATUS			status;

    if (OK > (status = DH_allocate(&pDHCtx)))
	return NULL;

    if (NULL == (COMPUTED_VLONG_P(pDHCtx) = moc_BIGNUM_to_vlong(dh->p, ppVlongQueue)))
	goto exit;
    if (NULL == (COMPUTED_VLONG_G(pDHCtx) = moc_BIGNUM_to_vlong(dh->g, ppVlongQueue)))
	goto exit;
#if 0
    if (NULL == (COMPUTED_VLONG_F(pDHCtx) = moc_BIGNUM_to_vlong(dh->pub_key, ppVlongQueue)))
	goto exit;
#endif
    if (NULL == (COMPUTED_VLONG_Y(pDHCtx) = moc_BIGNUM_to_vlong(dh->priv_key, ppVlongQueue)))
	goto exit;
    if (NULL == (COMPUTED_VLONG_E(pDHCtx) = moc_BIGNUM_to_vlong((BIGNUM *)pub_key, ppVlongQueue)))
	goto exit;

    if (NULL != dh->q)
    {
        if (NULL == (COMPUTED_VLONG_Q(pDHCtx) = moc_BIGNUM_to_vlong(dh->q, ppVlongQueue)))
            goto exit;
    }

    return pDHCtx;
  exit:
    DH_freeDhContext(&pDHCtx, ppVlongQueue);
    return NULL;
}
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static
int moc_compute_dh_key(
    unsigned char *pKey,
    const BIGNUM *pPubKey,
    DH *pDH
    )
{
    MSTATUS status;
    diffieHellmanContext *pContext = NULL;
    ubyte *pPublic = NULL, *pSecret = NULL;
    ubyte4 publicLen = 0, secretLen = 0;

    status = MocEvpOpensslDhToMocDh(pDH, &pContext);
    if (OK != status)
        goto exit;

    status = MocEvpBignumToByteArrAlloc(
        (BIGNUM *) pPubKey, &pPublic, &publicLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(
        pContext, NULL, pPublic, publicLen, &pSecret, &secretLen, NULL);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKey, pSecret, secretLen);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContext(&pContext, NULL);

    if (NULL != pSecret)
    {
        DIGI_MEMSET(pSecret, 0x00, secretLen);
        DIGI_FREE((void **) &pSecret);
    }

    if (NULL != pPublic)
        DIGI_FREE((void **) &pPublic);

    return status ? -1 : secretLen;
}
#else
static int moc_compute_dh_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    diffieHellmanContext      * pDHCtx;
    vlong     	              * pVlongQueue  = NULL;
    int 			rval = -1;
    sbyte4			retLen;
    MSTATUS			status;

    if (NULL == (pDHCtx = MOC_EVP_opensslDH2MOC(pub_key, dh, &pVlongQueue)))
	goto exit;

    if (OK > (status = DH_computeKeyExchange(MOC_DH(hwAccelDescr hwAccelCtx) pDHCtx, &pVlongQueue)))
	goto exit;

    VLONG_byteStringFromVlong(COMPUTED_VLONG_K(pDHCtx), NULL, &retLen);
    if (OK > (status = VLONG_byteStringFromVlong(COMPUTED_VLONG_K(pDHCtx), (ubyte*)key, &retLen)))
	goto exit;
    rval = retLen;
 exit:
    DH_freeDhContext(&pDHCtx, &pVlongQueue);
    VLONG_freeVlongQueue(&pVlongQueue);
    return rval;
}
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS MocEvpDhComputePublic(
    DH *pDH
    )
{
    MSTATUS status;
    BN_CTX *pBnCtx = NULL;

    pBnCtx = BN_CTX_new();
    if (NULL == pBnCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pDH->pub_key)
    {
        pDH->pub_key = BN_new();
        if (NULL == pDH->pub_key)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }

    if (1 != BN_mod_exp(pDH->pub_key, pDH->g, pDH->priv_key, pDH->p, pBnCtx))
        status = ERR_CRYPTO;
    else
        status = OK;

exit:

    if (NULL != pBnCtx)
        BN_CTX_free(pBnCtx);

    return status;
}

static int moc_generate_key(
    DH *pDH
    )
{
    MSTATUS status;
    ubyte4 privLen;
    MDhKeyTemplate template = { 0 };
    diffieHellmanContext *pContext = NULL;
    intBoolean isValid = FALSE;

    if ( (NULL == pDH->p) || (NULL == pDH->g) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* If a private key value does not exist then create a DH context and load
     * in the generator and prime values. Once these values are loaded in a new
     * key pair can be generated. Once the new key pair is generated, store the
     * public and private portion as BIGNUMs in the callers OpenSSL DH context.
     *
     * If a private key value already exists then compute the public portion and
     * set it in the OpenSSL DH context.
     */
    if (NULL == pDH->priv_key)
    {
        status = CRYPTO_INTERFACE_DH_allocateExt(&pContext, NULL);
        if (OK != status)
            goto exit;

        status = MocEvpBignumToByteArrAlloc(
            pDH->p, &(template.pP), &(template.pLen));
        if (OK != status)
            goto exit;

        status = MocEvpBignumToByteArrAlloc(
            pDH->g, &(template.pG), &(template.gLen));
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_setKeyParametersExt(
            pContext, &template, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_verifySafePG(pContext, &isValid, &privLen,
            NULL);
        if (OK != status)
            goto exit;

        if (FALSE == isValid)
        {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_DIGICERT_STRICT_DH_GROUP__))
            status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
            goto exit;
#else
            privLen = EVP_DH_CUSTOM_GROUP_PRI_LEN;
#endif
        }

        status = CRYPTO_INTERFACE_DH_generateKeyPairExt(
            pContext, RANDOM_CTX_MOC, privLen, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_freeKeyTemplate(pContext, &template);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(
            &template, pContext, MOC_GET_PRIVATE_KEY_DATA, NULL);
        if (OK != status)
            goto exit;

        pDH->priv_key = BN_bin2bn(template.pY, template.yLen, NULL);
        if (NULL == pDH->priv_key)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pDH->pub_key = BN_bin2bn(template.pF, template.fLen, NULL);
        if (NULL == pDH->pub_key)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }
    else
    {
        status = MocEvpDhComputePublic(pDH);
        if (OK != status)
            goto exit;
    }

exit:

    CRYPTO_INTERFACE_DH_freeKeyTemplate(pContext, &template);

    if (NULL != pContext)
        CRYPTO_INTERFACE_DH_freeDhContext(&pContext, NULL);

    return status ? 0 : 1;
}
#else
static int moc_generate_key(DH *dh)
{
    int         ok = 0;
    vlong     * P = NULL;
    vlong     * G = NULL;
    vlong     * priv = NULL;
    vlong     * pub = NULL;
    vlong     * pVlongQueue  = NULL;
    diffieHellmanContext      * pDHCtx = NULL;
    MSTATUS     status;
    ubyte4      lengthY;
    BIGNUM    * ret = NULL;
    int         freepub = 1;

    if (OK > (status = DH_allocate(&pDHCtx)))
	goto exit;

    if (NULL == (P = moc_BIGNUM_to_vlong(dh->p, &pVlongQueue)))
	goto exit;
    if (NULL == (G = moc_BIGNUM_to_vlong(dh->g, &pVlongQueue)))
	goto exit;
    if (NULL == dh->priv_key)
    {
	lengthY = dh->length ? dh->length : BN_num_bits(dh->p) - 1;
    lengthY = (lengthY + 7) / 8;
	if (OK > (status = DH_setPG(MOC_DH(hwAccelDescr hwAccelCtx) RANDOM_CTX_MOC, lengthY,
				    pDHCtx, P, G)))
	    goto exit;
	dh->priv_key = DIGI_EVP_vlong2BN(COMPUTED_VLONG_Y(pDHCtx));
	pub = COMPUTED_VLONG_F(pDHCtx);
	freepub = 0;
    }
    else
    {
	if (NULL == (priv = moc_BIGNUM_to_vlong(dh->priv_key, &pVlongQueue)))
	    goto exit;
	if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx)
					G, priv, P, &pub, &pVlongQueue)))
        {
	    goto exit;
	}
    }
    ret = DIGI_EVP_vlong2BN(pub);
    if (dh->pub_key == NULL)
    {
        dh->pub_key = BN_new();
        if (dh->pub_key == NULL)
            goto exit;
    }
    BN_copy(dh->pub_key, ret);
    ok = 1;
exit:
    DH_freeDhContext(&pDHCtx, &pVlongQueue);
    if (freepub && pub) VLONG_freeVlong(&pub, &pVlongQueue);
    if (priv) VLONG_freeVlong(&priv, &pVlongQueue);
    if (ret) BN_clear_free(ret);
    if (P) VLONG_freeVlong(&P, &pVlongQueue);
    if (G) VLONG_freeVlong(&G, &pVlongQueue);
    VLONG_freeVlongQueue(&pVlongQueue);
    return ok;
}
#endif

static int moc_dh_init(DH *dh)
{
    return 1;
}

static int moc_dh_finish(DH *dh)
{
    return 1;
}

static int
moc_dh_bn_mod_exp(const DH *dh, BIGNUM *r,
	      const BIGNUM *a, const BIGNUM *p,
	      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    vlong     * G = NULL;
    vlong     * priv = NULL;
    vlong     * P = NULL;
    vlong     * pVlongQueue = NULL;
    vlong     * pub = NULL;
    BIGNUM    * ret = NULL;
    MSTATUS	status;
    int		rval = 0;

    if (NULL == (G = moc_BIGNUM_to_vlong(a, &pVlongQueue)))
	goto exit;
    if (NULL == (priv = moc_BIGNUM_to_vlong(p, &pVlongQueue)))
	goto exit;
    if (NULL == (P = moc_BIGNUM_to_vlong(m, &pVlongQueue)))
	goto exit;
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx)
			     G, priv, P, &pub, &pVlongQueue)))
    {
	goto exit;
    }
    ret = DIGI_EVP_vlong2BN(pub);
    BN_copy(r, ret);
    rval = 1;
exit:
    if (G) VLONG_freeVlong(&G, &pVlongQueue);
    if (priv) VLONG_freeVlong(&priv, &pVlongQueue);
    if (P) VLONG_freeVlong(&P, &pVlongQueue);
    if (pub) VLONG_freeVlong(&pub, &pVlongQueue);
    if (ret) BN_clear_free(ret);
    VLONG_freeVlongQueue(&pVlongQueue);
    return rval;
}

#endif /* if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */

static DH_METHOD moc_evp_dh_meth = {
    "Mocana DH Method",
    moc_generate_key,
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    moc_compute_dh_key_ex,
#else
    moc_compute_dh_key,
#endif
    moc_dh_bn_mod_exp,
    moc_dh_init,
    moc_dh_finish,
    0,
    NULL,
    NULL
};

#ifdef __ENABLE_DIGICERT_OSSL_FORCE_METH_BIND__
static const DH_METHOD *moc_default_DH_method = &moc_evp_dh_meth;
const DH_METHOD *MOC_DH_get_default_method(void)
{
    return moc_default_DH_method;
}
#endif

static int moc_pkey_nids[] = {
#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#ifndef OPENSSL_NO_EC
    EVP_PKEY_EC,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
    EVP_PKEY_X25519,
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
    EVP_PKEY_X448,
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    EVP_PKEY_ED25519,
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    EVP_PKEY_ED448,
#endif
#endif
#endif
#endif
    EVP_PKEY_DSA,
    0
};

static int
pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    if (!pmeth)
    {
         *nids = moc_pkey_nids;
         return sizeof(moc_pkey_nids)/sizeof(int);
    }

#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#ifndef OPENSSL_NO_EC
    if (nid == EVP_PKEY_EC)
    {
        MOC_registerECMeth(pmeth);
        return 1;
    }
    else
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
    if (nid == EVP_PKEY_X25519)
    {
        MOC_registerEcx25519Meth(pmeth);
        return 1;
    }
    else
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
    if (nid == EVP_PKEY_X448)
    {
        MOC_registerEcx448Meth(pmeth);
        return 1;
    }
    else
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    if (nid == EVP_PKEY_ED25519)
    {
        MOC_registerEd448Meth(pmeth);
        return 1;
    }
    else
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    if (nid == EVP_PKEY_ED448)
    {
        MOC_registerEd448Meth(pmeth);
        return 1;
    }
    else
#endif
#endif
#endif
#endif
#ifdef __ENABLE_DIGICERT_DSA__
    if (nid == EVP_PKEY_DSA)
    {
        MOC_registerDSAMeth(pmeth);
        return 1;
    }
#endif
    *pmeth = NULL;
    return 0;
}

#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#if !defined(OPENSSL_NO_ECDH) && !defined(OPENSSL_NO_EC)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static
#endif
int moc_compute_ecdh_key(
    unsigned char **ppOut,
    size_t *pOutLen,
    const EC_POINT *pPubPoint,
    const EC_KEY *pKey
    )
#else
static int moc_compute_ecdh_key(
    void *pOut,
    size_t outLen,
    const EC_POINT *pPubPoint,
    EC_KEY *pKey,
    void *(*pKDF) (
        const void *pIn, size_t inLen, void *pOut, size_t *pOutLen)
    )
#endif
{
    ECCKey *pPriKey = NULL, *pPubKey = NULL;
    EC_GROUP *pGroup;
    int retVal = 0;
    unsigned char *pPublic = NULL, *pScalar = NULL;
    size_t pubLen, scalarLen;
    ubyte *pSecret = NULL;
    ubyte4 secretLen, eccCurveId;
    byteBoolean isValid;

#if defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    if (NULL != pOutLen)
    {
        *pOutLen = 0;
    }
#else
    if (outLen > INT_MAX)
    {
        return -1;
    }
#endif

    if (NULL == pKey->priv_key)
        return -1;

    pGroup = (EC_GROUP *) EC_KEY_get0_group(pKey);

    switch (pKey->group->curve_name)
    {
        case NID_X9_62_prime192v1:
            eccCurveId = cid_EC_P192;
            break;

        case NID_secp224r1:
            eccCurveId = cid_EC_P224;
            break;

        case NID_X9_62_prime256v1:
            eccCurveId = cid_EC_P256;
            break;

        case NID_secp384r1:
            eccCurveId = cid_EC_P384;
            break;

        case NID_secp521r1:
            eccCurveId = cid_EC_P521;
            break;

        default:
            return -1;
    }

    /* Extract the X and Y coordinates from the public point.
     */
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    pubLen = ossl_ec_GFp_simple_point2oct(pGroup, pPubPoint, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
#else
    pubLen = ec_GFp_simple_point2oct(pGroup, pPubPoint, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
#endif
    pPublic = OPENSSL_malloc(pubLen);
    if (NULL == pPublic)
        goto exit;

    DIGI_MEMSET((ubyte *) pPublic, 0x00, pubLen);
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    pubLen = ossl_ec_GFp_simple_point2oct(pGroup, pPubPoint, POINT_CONVERSION_UNCOMPRESSED, pPublic, pubLen, NULL);
#else
    pubLen = ec_GFp_simple_point2oct(pGroup, pPubPoint, POINT_CONVERSION_UNCOMPRESSED, pPublic, pubLen, NULL);
#endif
    if (pubLen == 0)
      goto exit;

    if (OK > CRYPTO_INTERFACE_EC_newPublicKeyFromByteString(
            eccCurveId, (void **) &pPubKey, pPublic, pubLen, akt_ecc))
        goto exit;

    /* Validate the public point.
     */
    if (OK > CRYPTO_INTERFACE_EC_verifyPublicKey(pPubKey, &isValid, akt_ecc))
        goto exit;

    if (FALSE == isValid)
        goto exit;

    /* Convert the private key into a software key. There is no hardware path for
     * ECDH.
     */
    if (NULL == pKey->priv_key)
        goto exit;

    scalarLen = BN_num_bytes(pKey->priv_key);
    pScalar = OPENSSL_malloc(scalarLen);
    DIGI_MEMSET((ubyte *) pScalar, 0x00, scalarLen);
    BN_bn2bin(pKey->priv_key, pScalar);

    if (OK > CRYPTO_INTERFACE_EC_newKeyAux(eccCurveId, &pPriKey))
        goto exit;

    if (OK > CRYPTO_INTERFACE_EC_setKeyParametersAux(
            pPriKey, pPublic, pubLen, pScalar, scalarLen))
        goto exit;

    /* Generate the shared secret.
     */
    if (OK > CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteString(
            pPriKey, pPublic, pubLen, &pSecret, &secretLen, 1, NULL, akt_ecc))
        goto exit;

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    *ppOut = pSecret;
    *pOutLen = secretLen;
    pSecret = NULL;
    retVal = 1;
#else
    /* If a KDF function pointer was provided then call it, otherwise just copy the
     * secret into the output buffer.
     */
    if (NULL != pKDF)
    {
        if (NULL == pKDF(pSecret, secretLen, pOut, &outLen))
            goto exit;
    }
    else
    {
        if (outLen > secretLen)
            outLen = secretLen;

        memcpy(pOut, pSecret, outLen);
    }
    retVal = (int) outLen;
#endif

exit:

    if (NULL != pPublic)
        OPENSSL_free(pPublic);

    if (NULL != pScalar)
        OPENSSL_free(pScalar);

    if (NULL != pPriKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pPriKey, akt_ecc);

    if (NULL != pPubKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pPubKey, akt_ecc);

    if (NULL != pSecret)
    {
        DIGI_MEMSET(pSecret, 0x00, secretLen);
        DIGI_FREE((void **) &pSecret);
    }

    return retVal;
}
#else
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
static int moc_compute_ecdh_key(void **out, size_t *outlen, const EC_POINT *pub_key,
        EC_KEY *ec_key)
#else
static int moc_compute_ecdh_key(void *out, size_t outlen, const EC_POINT *pub_key,
        EC_KEY *ec_key,
        void *(*KDF) (const void *in, size_t inlen,
                     void *out, size_t *outlen))
#endif
{
    size_t rval = -1;
    sbyte4 ret_len;
    MSTATUS status;
    PEllipticCurvePtr pECurve;
    ubyte *key = NULL;
    BIGNUM    *key_bn = NULL;
    unsigned char *q_X = NULL;
    unsigned char *q_Y = NULL;
    unsigned char *p_k = NULL;
    PFEPtr qx = 0;
    PFEPtr qy = 0;
    PFEPtr k = 0;
    int qx_size = 0;
    int qy_size = 0;
    int k_size = 0;
    PrimeFieldPtr pPF = NULL;
    size_t buflen, len;
    unsigned char *buf = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EC_GROUP *group = NULL;

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (outlen > INT_MAX)
    {
        return -1;
    }
#endif

    group = (EC_GROUP*)EC_KEY_get0_group(ec_key);

    switch(ec_key->group->curve_name)
    {
        case NID_X9_62_prime192v1:
            pECurve = EC_P192;
            break;
        case NID_secp224r1:
            pECurve = EC_P224;
            break;
        case NID_X9_62_prime256v1:
            pECurve = EC_P256;
            break;
        case NID_secp384r1:
            pECurve = EC_P384;
            break;
        case NID_secp521r1:
            pECurve = EC_P521;
            break;
        default:
            return rval;
            break;
    }

    /* Extract the X, Y values from public key */
    x = BN_new();
    y = BN_new();

    if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, x, y, NULL))
    {
        goto exit;
    }

    qx_size = BN_num_bytes(x);
    q_X = OPENSSL_malloc(qx_size);
    DIGI_MEMSET((ubyte *)q_X, 0x0, qx_size);
    BN_bn2bin(x, q_X);

    qy_size = BN_num_bytes(y);
    q_Y = OPENSSL_malloc(qy_size);
    DIGI_MEMSET((ubyte *)q_Y, 0x0, qy_size);
    BN_bn2bin(y, q_Y);

    if (NULL == ec_key->priv_key)
    {
	goto exit;
    }

    /* Extract k from private key */
    k_size = BN_num_bytes(ec_key->priv_key);
    p_k = OPENSSL_malloc(k_size);
    DIGI_MEMSET((ubyte *)p_k, 0x0, k_size);
    BN_bn2bin(ec_key->priv_key, p_k);

    pPF = EC_getUnderlyingField(pECurve);

    if (OK > (status = PRIMEFIELD_newElement(pPF, &qx)))
    {
        goto exit;
    }
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, qx, (const ubyte*)q_X, qx_size)))
    {
        goto exit;
    }

    if (OK > (status = PRIMEFIELD_newElement(pPF, &qy)))
    {
        goto exit;
    }
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, qy, (const ubyte*)q_Y, qy_size)))
    {
        goto exit;
    }

    if (OK > (status = PRIMEFIELD_newElement(pPF, &k)))
    {
        goto exit;
    }
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, k, (const ubyte*)p_k, k_size)))
    {
        goto exit;
    }

    if (OK > (status = EC_verifyPublicKey(pECurve, qx, qy)))
    {
        goto exit;
    }

    /* Generate secret key */
    if (OK > (status = ECDH_generateSharedSecretAux(pECurve,qx,qy,k,
                                                    (ubyte **)&key, &ret_len,1)))
    {
        goto exit;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    key_bn = BN_bin2bn((unsigned char *)key, ret_len, NULL);
    len = BN_num_bytes(key_bn);
    if (len > buflen)
    {
        goto exit;
    }
    if ((buf = OPENSSL_malloc(buflen)) == NULL)
    {
        goto exit;
    }

    memset(buf, 0, buflen - len);
    if (len != (size_t)BN_bn2bin(key_bn, buf + buflen - len))
    {
        goto exit;
    }

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    *out = buf;
    *outlen = buflen;
    buf = NULL;
    rval = 1;
#else
    if (KDF != 0)
    {
        if (KDF(buf, buflen, out, &outlen) == NULL)
        {
            goto exit;
        }
        rval = (int)outlen;
    }
    else
    {
        /* no KDF, just copy as much as we can */
        if (outlen > buflen)
            outlen = buflen;
        memcpy(out, buf, outlen);
        rval = (int)outlen;
    }
#endif

exit:
    if(NULL != q_X)
    {
        OPENSSL_free(q_X);
    }
    if(NULL != q_Y)
    {
        OPENSSL_free(q_Y);
    }
    if(NULL != p_k)
    {
        OPENSSL_free(p_k);
    }
    if (NULL != qx)
    {
        PRIMEFIELD_deleteElement(pPF, &qx);
    }
    if (NULL != qy)
    {
        PRIMEFIELD_deleteElement(pPF, &qy);
    }
    if (NULL != k)
    {
        PRIMEFIELD_deleteElement(pPF, &k);
    }
    if (NULL != buf)
    {
        OPENSSL_free(buf);
    }
    if (NULL != x)
    {
        BN_free(x);
    }
    if (NULL != y)
    {
        BN_free(y);
    }
    if (NULL != key)
    {
        free(key);
    }
    if(key_bn) BN_free(key_bn);
    return rval;
}
#endif

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static ECDH_METHOD moc_evp_ecdh_meth = {
    "Mocana ECDH Method",
    moc_compute_ecdh_key,
# if 0
    NULL,
    NULL,
# endif
    0,
    NULL,
};
#endif /* !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ && !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ OR !__ENABLE_DIGICERT_OPENSSL_LIB_3_0__*/
#endif
#endif

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
static int moc_ecdsa_sign_aux(
    int type,
    const unsigned char *pDigest,
    int digestLen,
    unsigned char *pSig,
    unsigned int *pSigLen,
    const BIGNUM *pKInv,
    const BIGNUM *pR,
    EC_KEY *pEcKey
    )
{
    /* The type variable is currently ignored.
     */

    int ret = 0;
    ECDSA_SIG *pSigData = moc_ecdsa_sign(
        pDigest, digestLen, pKInv, pR, pEcKey);
    if (NULL == pSigData)
        goto exit;

    *pSigLen = i2d_ECDSA_SIG(pSigData, &pSig);
    if (0 == *pSigLen)
        goto exit;

    ret = 1;

exit:

    if (NULL != pSigData)
    {
        ECDSA_SIG_free(pSigData);
    }

    return ret;
}

static int moc_ecdsa_verify_aux(
    int type,
    const unsigned char *pDigest,
    int digestLen,
    const unsigned char *pSig,
    int sigLen,
    EC_KEY *pEcKey
    )
{
    int ret = -1, derLen = -1;
    unsigned char *pDer = NULL;
    const unsigned char*pTempSig = pSig;
    ECDSA_SIG *pSigData = d2i_ECDSA_SIG(NULL, &pSig, sigLen);
    if (NULL == pSigData || sigLen <= 0)
    {
        goto exit;
    }

    /* Ensure signature uses DER and doesn't have trailing garbage */
    derLen = i2d_ECDSA_SIG(pSigData, &pDer);
    if (derLen != sigLen || memcmp(pTempSig, pDer, derLen) != 0)
    {
        goto exit;
    }

    ret = moc_ecdsa_verify(pDigest, digestLen, pSigData, pEcKey);

exit:

    if (NULL != pSigData)
    {
        ECDSA_SIG_free(pSigData);
    }

    if (pDer != NULL)
    {
        OPENSSL_free(pDer);
    }
    return ret;
}
#endif

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
int moc_ecc_keygen(
    EC_KEY *pEcKey
    )
{
    MSTATUS status;
    int ret = 0, curveNid = 0;
    ubyte4 eccCurveId;
    ECCKey *pEccKey = NULL;
    MEccKeyTemplate template = { 0 };

    curveNid = EC_GROUP_get_curve_name(EC_KEY_get0_group(pEcKey));

    switch (curveNid)
    {
        case NID_X9_62_prime192v1:
            eccCurveId = cid_EC_P192;
            break;

        case NID_secp224r1:
            eccCurveId = cid_EC_P224;
            break;

        case NID_X9_62_prime256v1:
            eccCurveId = cid_EC_P256;
            break;

        case NID_secp384r1:
            eccCurveId = cid_EC_P384;
            break;

        case NID_secp521r1:
            eccCurveId = cid_EC_P521;
            break;

        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }

    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(
        eccCurveId, (void **) &pEccKey, DIGI_EVP_RandomRngFun, NULL, akt_ecc,
        NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(
        pEccKey, &template, MOC_GET_PRIVATE_KEY_DATA);
    if (OK != status)
        goto exit;

    ret = EC_KEY_oct2key(
        pEcKey, template.pPublicKey, template.publicKeyLen, NULL);
    if (1 != ret)
        goto exit;

    ret = EC_KEY_oct2priv(
        pEcKey, template.pPrivateKey, template.privateKeyLen);
    if (1 != ret)
        goto exit;

exit:

    CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pEccKey, &template);

    if (NULL != pEccKey)
    {
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccKey);
    }

    return ret;
}
#endif

#if !defined(OPENSSL_NO_EC) && \
     defined(VERSION_1_1_0_OR_1_1_1C_OR_3_0)
static EC_KEY_METHOD moc_evp_ecc_meth = {
    "Mocana ECC method",
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    moc_ecc_keygen,
    moc_compute_ecdh_key,
    moc_ecdsa_sign_aux,
    moc_ecdsa_sign_setup,
    moc_ecdsa_sign,
    moc_ecdsa_verify_aux,
    moc_ecdsa_verify
};

#ifdef __ENABLE_DIGICERT_OSSL_FORCE_METH_BIND__
static const EC_KEY_METHOD *moc_default_EC_KEY_method = &moc_evp_ecc_meth;
const EC_KEY_METHOD *MOC_EC_KEY_get_default_method(void)
{
    return moc_default_EC_KEY_method;
}
#endif /* __ENABLE_DIGICERT_OSSL_FORCE_METH_BIND__ */
#endif /* !OPENSSL_NO_EC && VERSION_1_1_0_OR_1_1_1C_OR_3_0 */

/* Check if the key provided is in one of the known PEM formats */
static int moc_check_pem(const char *nm, const char *name)
{
    /* Normal matching nm and name */
    if (!strcmp(nm, name))
        return 1;

    /* Make PEM_STRING_EVP_PKEY match any private key */

    if (!strcmp(name, PEM_STRING_EVP_PKEY)) {
        int slen;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (!strcmp(nm, PEM_STRING_PKCS8))
            return 1;
        if (!strcmp(nm, PEM_STRING_PKCS8INF))
            return 1;
        slen = pem_check_suffix(nm, "PRIVATE KEY");
        if (slen > 0) {
            /*
             * NB: ENGINE implementations wont contain a deprecated old
             * private key decode function so don't look for them.
             */
            ameth = EVP_PKEY_asn1_find_str(NULL, nm, slen);
            if (ameth && ameth->old_priv_decode)
                return 1;
        }
        return 0;
    }

    if (!strcmp(name, PEM_STRING_PARAMETERS)) {
        int slen;
        const EVP_PKEY_ASN1_METHOD *ameth;
        slen = pem_check_suffix(nm, "PARAMETERS");
        if (slen > 0) {
            ENGINE *e;
            ameth = EVP_PKEY_asn1_find_str(&e, nm, slen);
            if (ameth) {
                int r;
                if (ameth->param_decode)
                    r = 1;
                else
                    r = 0;
#ifndef OPENSSL_NO_ENGINE
                if (e)
                    ENGINE_finish(e);
#endif
                return r;
            }
        }
        return 0;
    }
    /* If reading DH parameters handle X9.42 DH format too */
    if (!strcmp(nm, PEM_STRING_DHXPARAMS) &&
        !strcmp(name, PEM_STRING_DHPARAMS))
        return 1;

    /* Permit older strings */

    if (!strcmp(nm, PEM_STRING_X509_OLD) && !strcmp(name, PEM_STRING_X509))
        return 1;

    if (!strcmp(nm, PEM_STRING_X509_REQ_OLD) &&
        !strcmp(name, PEM_STRING_X509_REQ))
        return 1;

    /* Allow normal certs to be read as trusted certs */
    if (!strcmp(nm, PEM_STRING_X509) &&
        !strcmp(name, PEM_STRING_X509_TRUSTED))
        return 1;

    if (!strcmp(nm, PEM_STRING_X509_OLD) &&
        !strcmp(name, PEM_STRING_X509_TRUSTED))
        return 1;

    /* Some CAs use PKCS#7 with CERTIFICATE headers */
    if (!strcmp(nm, PEM_STRING_X509) && !strcmp(name, PEM_STRING_PKCS7))
        return 1;

    if (!strcmp(nm, PEM_STRING_PKCS7_SIGNED) &&
        !strcmp(name, PEM_STRING_PKCS7))
        return 1;

#ifndef OPENSSL_NO_CMS
    if (!strcmp(nm, PEM_STRING_X509) && !strcmp(name, PEM_STRING_CMS))
        return 1;
    /* Allow CMS to be read from PKCS#7 headers */
    if (!strcmp(nm, PEM_STRING_PKCS7) && !strcmp(name, PEM_STRING_CMS))
        return 1;
#endif

    return 0;
}

MSTATUS
moc_pem_bytes_read_bio(unsigned char **pData, long *pLen, char **pnm,
                       const char *name, BIO *pB, pem_password_cb *cb,
                       void *u)
{
    EVP_CIPHER_INFO cipher;
    char *nm = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len;
    MSTATUS status = -1;

    for (;;) {
        if (!PEM_read_bio(pB, &nm, &header, &data, &len)) {
            if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE)
                ERR_add_error_data(2, "Expecting: ", name);
            status = -1;
			goto exit;
        }
        if (moc_check_pem(nm, name))
            break;
        OPENSSL_free(nm);
        nm = NULL;
        OPENSSL_free(header);
        header = NULL;
        OPENSSL_free(data);
        data = NULL;
    }
    if (!PEM_get_EVP_CIPHER_INFO(header, &cipher))
	{
		status = -1;
        goto exit;
	}

    if (!PEM_do_header(&cipher, data, &len, cb, u))
	{
		status = -1;
        goto exit;
	}

    *pData = data;
    *pLen = len;

    if (pnm)
        *pnm = nm;

    status = OK;

 exit:
    if (status || !pnm)
        OPENSSL_free(nm);
    OPENSSL_free(header);
    if (status)
        OPENSSL_free(data);
    return status;
}

extern MSTATUS
moc_get_decrypted_content(BIO *pB, unsigned char **pData, long *pLen, pem_password_cb *cb,void *u)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    int dataLen = 0;
    MSTATUS status = OK;

    if (OK > (status = moc_pem_bytes_read_bio(&data, &len, &nm, PEM_STRING_EVP_PKEY, pB, cb, u)))
    {
        goto exit;
    }
    p = data;

    if (strcmp(nm, PEM_STRING_PKCS8) == 0)
    {
        X509_SIG *p8;
        int klen;
        char psbuf[PEM_BUFSIZE];
        p8 = d2i_X509_SIG(NULL, &p, len);
        if (!p8)
        {
            status = -1;
            goto exit;
        }

        if (cb)
            klen = cb(psbuf, PEM_BUFSIZE, 0, u);
        else
            klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);

        if (klen <= 0)
        {
            PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, PEM_R_BAD_PASSWORD_READ);
            X509_SIG_free(p8);
            status = -1;
            goto exit;
        }

        OPENSSL_free(data);
        data = NULL;
        len = 0;
        if (!PKCS12_pbe_crypt(p8->algor, psbuf, klen, p8->digest->data, p8->digest->length,
                              &data, &dataLen, 0))
        {
            status = -1;
            goto exit;
        }
        len = dataLen;
        p = data;
        X509_SIG_free(p8);

        status = OK;
    }

    *pData = (unsigned char *) p;
    *pLen = len;

exit:
    if (NULL != nm)
    {
        OPENSSL_free(nm);
        nm = NULL;
    }
    return status;
}

static int
ends_with_extension(const char *name, const char *extension, size_t length)
{
    const char *lDot = strrchr(name, '.');
    if (lDot != NULL)
    {
        if (length == 0)
        {
            length = strlen(extension);
        }
        return strncmp(lDot + 1, extension, length) == 0;
    }
    return 0;
}

static MSTATUS moc_evp_get_asymmetric_key_from_pem(MOC_EVP_KEY_DATA *pMocKeyData, AsymmetricKey *pAsymKey, const char *key_id)
{
    MSTATUS status = -1;
    long cLen = 0;

    /* Read PEM file and convert to keyblob */
    BIO *b;
    FILE *fp = NULL;

    if (pMocKeyData == NULL)
    {
        goto exit;
    }

    /*
     * If the given key is Mocana custom Key which ends with .dat
     * then directly deserialize the Key.
     */
    if(ends_with_extension(key_id, "pem", 3) == 1 ||
       ends_with_extension(key_id, "PEM", 3) == 1)
    {
#ifdef __RTOS_WIN32__
        if ((fopen_s(&fp, key_id, "r")) != 0)
#else
        if ((fp = fopen(key_id, "r")) == NULL)
#endif
        {
#ifdef __RTOS_WIN32__
            DIGI_EVP_ERR("Error opening file %s\n", key_id);
#else
            DIGI_EVP_ERR("Error %s opening file %s\n", strerror(errno), key_id);
#endif
            goto exit;
        }

        if ((b = BIO_new(BIO_s_file())) == NULL) {
            PEMerr(PEM_F_PEM_READ_PRIVATEKEY, ERR_R_BUF_LIB);
            goto exit;
        }
        BIO_set_fp(b, fp, BIO_NOCLOSE);
        if(OK > (status = moc_get_decrypted_content(b, &pMocKeyData->pContents, (long int *) &cLen, NULL, NULL)))
        {
            goto exit;
        }
        pMocKeyData->contentsLen = (ubyte4) cLen;
        BIO_free(b);

        if(!pMocKeyData->pContents)
        {
            status = -1;
            goto exit;
        }
    }
    else
    {
        /* Mocana Key file or other than .pem */
        if (OK > (status = DIGICERT_readFile(
            (const char *)key_id, &pMocKeyData->pContents, &pMocKeyData->contentsLen)))
        {
            goto exit;
        }
    }

    status = CRYPTO_deserializeAsymKey(
        pMocKeyData->pContents, pMocKeyData->contentsLen, NULL, pAsymKey);

exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    return status;
}


static EVP_PKEY *moc_engine_load_key(ENGINE *e, const char *key_id,
                             UI_METHOD *ui, void *cb_data)
{
    EVP_PKEY *pKey = NULL;
    RSA *rsa = NULL;
    AsymmetricKey pAsymKey;
    MOC_EVP_KEY_DATA *pMocKeyData = NULL;
    MSTATUS status;
    FILE *fp = NULL;
    RSAKey *pRSAKey = NULL;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    MRsaKeyTemplate template = {0};
#else
    BN_CTX *ctx = NULL;
    BIGNUM *r0 = NULL;
    BIGNUM *r1 = NULL;
    BIGNUM *r2 = NULL;
#endif

    pMocKeyData = OPENSSL_malloc(sizeof(struct MOC_EVP_KEY_DATA_s));
    if (NULL == pMocKeyData)
        return NULL;

    DIGI_MEMSET((ubyte *)pMocKeyData, 0x0, sizeof(struct MOC_EVP_KEY_DATA_s));
#ifdef __ENABLE_DIGICERT_TAP__
	pMocKeyData->pData = cb_data;
#else
    pMocKeyData->cb_data = (MKeyContextCallbackInfo *)cb_data;
#endif

    status = CRYPTO_initAsymmetricKey (&pAsymKey);
    if (OK != status)
       goto exit;

     status = moc_evp_get_asymmetric_key_from_pem(pMocKeyData, &pAsymKey, key_id);
     if (0 <= status)
     {
        if (akt_ecc == pAsymKey.type)
            goto parseDefault;

       /* RSA Key de serialized
        initialise with default values and
         MOC_EVP_KEY_DATA in extra_data in OpenSSL Key Structure */

        if (NULL == (pKey = EVP_PKEY_new()))
        {
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_TAP__
        if(pAsymKey.type == akt_tap_ecc)
        {
            EC_KEY *ecKey = NULL;
            ubyte4 curveId;
            int osslEcCurveId;

            status = CRYPTO_INTERFACE_EC_getCurveIdFromKey(
                pAsymKey.key.pMocAsymKey, &curveId, pAsymKey.type);
            if (OK != status)
                goto exit;

            switch (curveId)
            {
                case cid_EC_P192:
                    osslEcCurveId = NID_X9_62_prime192v1;
                    break;
                case cid_EC_P224:
                    osslEcCurveId = NID_secp224r1;
                    break;
                case cid_EC_P256:
                    osslEcCurveId = NID_X9_62_prime256v1;
                    break;
                case cid_EC_P384:
                    osslEcCurveId = NID_secp384r1;
                    break;
                case cid_EC_P521:
                    osslEcCurveId = NID_secp521r1;
                    break;

                default:
                    status = ERR_EC_UNSUPPORTED_CURVE;
                    goto exit;
            }

            pKey->type = EVP_PKEY_EC;

            if (NULL == (ecKey = EC_KEY_new_by_curve_name(osslEcCurveId)))
            {
                goto exit;
            }

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
            EC_KEY_set_ex_data(ecKey, eccExAppData, pMocKeyData);
#else
            ECDSA_set_ex_data(
                ecKey, eccExAppData, pMocKeyData);
#endif
            pKey->pkey.ec = ecKey;

            EVP_PKEY_assign_EC_KEY(pKey, ecKey);

            CRYPTO_uninitAsymmetricKey(&pAsymKey, NULL);

            return pKey;
        }
#endif
        pKey->type = EVP_PKEY_RSA;

        if (NULL == (rsa = RSA_new()))
        {
            goto exit;
        }

        rsa->meth = &moc_evp_rsa;
        rsa->meth->init(rsa);
        RSA_set_ex_data(rsa, rsaExAppData, pMocKeyData);
        pKey->pkey.rsa = rsa;
#ifdef __ENABLE_DIGICERT_TAP__
        if(pAsymKey.type == akt_tap_rsa)
        {
            /*Conversion of MocAsymKey to openssl RSA key*/
            TAP_Key *pTapKey = NULL;
            TAP_RSAPublicKey *pRsaTapPub = NULL;

            status = CRYPTO_INTERFACE_getTapKey(&pAsymKey, &pTapKey);
            if (OK != status)
                goto exit;

            pRsaTapPub = (TAP_RSAPublicKey *)(&(pTapKey->keyData.publicKey.publicKey.rsaKey));

            rsa->n = BN_bin2bn(pRsaTapPub->pModulus, pRsaTapPub->modulusLen, NULL);
            rsa->e = BN_bin2bn(pRsaTapPub->pExponent, pRsaTapPub->exponentLen, NULL);
        }
        else
        {
#endif
            pRSAKey = pAsymKey.key.pRSA;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__

            ctx = BN_CTX_new();
            BN_CTX_start(ctx);
            r0 = BN_CTX_get(ctx);
            r1 = BN_CTX_get(ctx);
            r2 = BN_CTX_get(ctx);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            if (OK > (status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(MOC_SYM(hwAccelCtx) pRSAKey,
                                        &template, MOC_GET_PRIVATE_KEY_DATA, pAsymKey.type)))
            {
                goto exit;
            }

            rsa->e = BN_bin2bn((unsigned char *)template.pE, template.eLen, NULL);
            rsa->n = BN_bin2bn((unsigned char *)template.pN, template.nLen, NULL);
            rsa->p = BN_bin2bn((unsigned char *)template.pP, template.pLen, NULL);
            rsa->q = BN_bin2bn((unsigned char *)template.pQ, template.qLen, NULL);

            if (moc_rsa_prepare_key(rsa) != 1)
            {
                goto exit;
            }
#else
            rsa->e = DIGI_EVP_vlong2BN(RSA_E(pRSAKey));
            rsa->n = DIGI_EVP_vlong2BN(RSA_N(pRSAKey));
            rsa->p = DIGI_EVP_vlong2BN(RSA_P(pRSAKey));
            rsa->q = DIGI_EVP_vlong2BN(RSA_Q(pRSAKey));
            rsa->dmp1 = DIGI_EVP_vlong2BN(RSA_DP(pRSAKey));
            rsa->dmq1 = DIGI_EVP_vlong2BN(RSA_DQ(pRSAKey));
            rsa->iqmp = DIGI_EVP_vlong2BN(RSA_QINV(pRSAKey));
            rsa->d = BN_new();

            /* calculate d */
            if (!BN_sub(r1, rsa->p, BN_value_one()))
            {
                goto exit;               /* p-1 */
            }
            if (!BN_sub(r2, rsa->q, BN_value_one()))
            {
                goto exit;               /* q-1 */
            }
            if (!BN_mul(r0, r1, r2, ctx))
            {
                goto exit;               /* (p-1)(q-1) */
            }
            if (!BN_mod_inverse(rsa->d, rsa->e, r0, ctx))
            {
                goto exit;
            }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#ifdef __ENABLE_DIGICERT_TAP__
        }
#endif
        EVP_PKEY_assign_RSA(pKey, rsa);
     }
     else
     {
parseDefault:
        /* As this is not used with standard ECDSA & DSA keys, free it. */
        if (pMocKeyData->pContents != NULL)
        {
            OPENSSL_free(pMocKeyData->pContents);
            pMocKeyData->pContents = NULL;
        }
        pMocKeyData->cb_data = NULL;
        OPENSSL_free(pMocKeyData);
    
        /* Not RSA PEM file */
#ifdef __RTOS_WIN32__
        if ((fopen_s(&fp, key_id, "r")) != 0)
#else
        if ((fp = fopen(key_id, "r")) == NULL)
#endif
        {
#ifdef __RTOS_WIN32__
            DIGI_EVP_ERR("Error opening file %s\n", key_id);
#else
            DIGI_EVP_ERR("Error %s opening file %s\n", strerror(errno), key_id);
#endif
            goto exit;
        }

        pKey = PEM_read_PrivateKey(fp, NULL,  NULL, NULL);
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (pRSAKey)
    {
        CRYPTO_INTERFACE_RSA_freeKeyTemplate(pRSAKey, &template, pAsymKey.type);
    }
#else
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
#endif
    CRYPTO_uninitAsymmetricKey(&pAsymKey, NULL);
    if(fp) fclose(fp);
    return pKey;

exit:
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    CRYPTO_INTERFACE_RSA_freeKeyTemplate(pRSAKey, &template, akt_rsa);
#else
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
#endif

    CRYPTO_uninitAsymmetricKey(&pAsymKey, NULL);
    if(pKey != NULL)
    {
        EVP_PKEY_free(pKey);
    }
    if(rsa != NULL)
    {
        RSA_free(rsa);
    }

    return NULL;
}

static int moc_rand_bytes(unsigned char *buf, int num)
{
    MSTATUS status = OK;
    int ret = 1;
    randomContext* pRandomContext = NULL;

    if (g_pRandomContext == NULL)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
        {
            goto exit;
        }
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }

    if (OK > (status = RANDOM_numberGenerator(pRandomContext, (ubyte*)buf, num)))
    {
        goto exit;
    }

exit:
    /* g_pRandomContext freed in DIGICERT_free()*/
    if (pRandomContext && (g_pRandomContext != pRandomContext))
    {
        RANDOM_releaseContext(&pRandomContext);
    }

    ret = (status < 0) ? 0 : 1;
    return ret;
}

static int moc_rand_status(void)
{

	return 1;
}

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
static int moc_rand_seed(const void *buf, int num)
#else
static void moc_rand_seed(const void *buf, int num)
#endif
{
    MSTATUS status = OK;
    randomContext* pRandomContext = NULL;

    if (g_pRandomContext == NULL)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
        {
            goto exit;
        }
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }

    if (OK > (status = RANDOM_addEntropyBit(pRandomContext, num)))
    {
        goto exit;
    }

exit:
    /* g_pRandomContext freed in DIGICERT_free()*/
    if (pRandomContext && (g_pRandomContext != pRandomContext))
    {
        RANDOM_releaseContext(&pRandomContext);
    }

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    if (OK == status)
    {
        return 1;
    }
    else
    {
        return 0;
    }
#else
    return;
#endif
}

static RAND_METHOD moc_rand = {
	/* "TPM RAND method", */
	moc_rand_seed,
	moc_rand_bytes,
	NULL,
	NULL,
	moc_rand_bytes,
	moc_rand_status,
};

static int bind_moc_evp(ENGINE *e)
{
    ERR_load_DIGI_EVP_strings();
    if (!ENGINE_set_id(e, engine_moc_evp_id)
        || !ENGINE_set_RAND(e, &moc_rand)
        || !ENGINE_set_name(e, engine_moc_evp_name)
        || !ENGINE_set_destroy_function(e, MOC_EVP_engineDestroy)
        || !ENGINE_set_init_function(e, MOC_EVP_engineInit)
        || !ENGINE_set_finish_function(e, MOC_EVP_engineFinish)) {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }

    if (!ENGINE_set_ciphers(e, DIGI_EVP_ciphers))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }

    if (!ENGINE_set_digests(e, MOC_EVP_digests))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }

    if (!ENGINE_set_RSA(e, &moc_evp_rsa))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }

#ifdef __ENABLE_DIGICERT_DSA__
    if (!ENGINE_set_DSA(e, &moc_evp_dsa_meth))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }
#endif
#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
#ifndef OPENSSL_NO_EC
    if (!ENGINE_set_EC(e, &moc_evp_ecc_meth))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }
#endif
#else
#ifndef OPENSSL_NO_ECDSA
    if (!ENGINE_set_ECDSA(e, &moc_evp_ecdsa_meth))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }
#endif
#ifndef OPENSSL_NO_ECDH
    if (!ENGINE_set_ECDH(e, &moc_evp_ecdh_meth))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }
#endif
#endif /* VERSION_1_1_0_OR_1_1_1C_OR_3_0 */
#endif
    if (!ENGINE_set_DH(e, &moc_evp_dh_meth))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }

    if (!ENGINE_set_pkey_meths(e, &pkey_meths))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }
    /* handling private reading from PEM files. This is done while supporting TPM PEM files.*/
    if (!ENGINE_set_load_privkey_function(e, moc_engine_load_key))
    {
        MOC_EVPerr(MOC_EVP_F_BIND, MOC_EVP_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
/* TODO */
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_moc_evp_id) != 0))
        return 0;
    if (!bind_moc_evp(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# else
static ENGINE *engine_moc_evp(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_moc_evp(ret))
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_moc_evp(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_moc_evp();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
void engine_load_mocana_int(void)
{
    ENGINE_load_moc_evp();
}
#endif
#endif

static int MOC_EVP_engineInit(ENGINE *e)
{
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    sbyte4 status = OK;
#endif

    DIGICERT_initDigicert();
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (!FIPS_ModeEnabled())
    {
        status = -1;
    }
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    ossl_assert(status == OK);
#else
    OPENSSL_assert(status == OK);
#endif
#endif

#if 0
    RSA_set_default_method(&moc_evp_rsa);
    ECDSA_set_default_method(&moc_evp_ecdsa_meth);
#endif

    /* in 3.0 we set these on provider init.*/
#ifndef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    if (MOC_EVP_INVALID_EX_DATA == rsaExAppData)
    {
        rsaExAppData = RSA_get_ex_new_index(
            0, NULL, NULL, NULL, freeExtraData);
    }
    if (MOC_EVP_INVALID_EX_DATA == eccExAppData)
    {
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
        eccExAppData = EC_KEY_get_ex_new_index(
            0, NULL, NULL, NULL, freeExtraData);
#else
        eccExAppData = ECDSA_get_ex_new_index(
            0, NULL, NULL, NULL, freeExtraData);
#endif
    }
    if ( (MOC_EVP_INVALID_EX_DATA == rsaExAppData) ||
         (MOC_EVP_INVALID_EX_DATA == eccExAppData) )
    {
        return 0;
    }
#endif

#if !defined(__ENABLE_DIGICERT_EVP_ENGINE_DEFAULT__) && defined(__ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__)
    MOC_EVP_ENGINE_unregister();
#endif /* !__ENABLE_DIGICERT_EVP_ENGINE_DEFAULT__ && __ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__ */

    return 1;
}

static int MOC_EVP_engineFinish(ENGINE *e)
{
    DIGICERT_freeDigicert();
    return 1;
}

static int MOC_EVP_engineDestroy(ENGINE *e)
{
    ERR_unload_DIGI_EVP_strings();
    return 1;
}

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
const ubyte* getDigest_OID_fromNid(int nid)
{
	switch(nid)
	{
        case NID_sha1:
            return sha1_OID;        
        case NID_sha224:
            return sha224_OID;        
        case NID_sha256:
            return sha256_OID;
        case NID_sha384:
            return sha384_OID;
        case NID_sha512:
            return sha512_OID;
#if defined(__ENABLE_DIGICERT_SHA3__)
        case NID_sha3_224:
            return sha3_224_OID;
        case NID_sha3_256:
            return sha3_256_OID;
        case NID_sha3_384:
            return sha3_384_OID;
        case NID_sha3_512:
            return sha3_512_OID;
#endif
	}
	return NULL;
}
#else
static const ubyte* getDigest_OID(int length)
{
	switch(length)
	{
		case SHA1_RESULT_SIZE:
			return sha1_OID;
		case SHA224_RESULT_SIZE:
			return sha224_OID;
		case SHA256_RESULT_SIZE:
			return sha256_OID;
		case SHA384_RESULT_SIZE:
			return sha384_OID;
		case SHA512_RESULT_SIZE:
			return sha512_OID;
	}
	return NULL;
}
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */


#if !defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__) && defined(__RTOS_WIN32__)
int OPENSSL_register_pem_bio_handler(EVP_PKEY *(*handler)(BIO *, EVP_PKEY**, pem_password_cb *, void *))
{
    return 0;
}
#endif
