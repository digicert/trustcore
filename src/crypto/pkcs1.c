/*
 * pkcs1.c
 *
 * PKCS#1 Version 2.1 Utilities
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
@file       pkcs1.c
@brief      C source code for the Mocana SoTP PKCS&nbsp;\#1 convenience API.
@details    This file contains the Mocana SoTP convenience functions that
            support PKCS&nbsp;\#1, version 2.1, as defined by RFC&nbsp;3447.


@flags
To enable the SoT Platform PKCS&nbsp;\#1 convenience API functions, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS1__

@filedoc    pkcs1.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS1_INTERNAL__

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_PKCS1__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifndef __RSA_PKCS1_HARDWARE_ACCELERATOR__

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/memory_debug.h"
#include "../common/debug_console.h"
#include "../asn1/oiddefs.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs1.h"
#include "../crypto/pkcs1_int.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/crypto_hash_fips.h"
#endif
#include "../harness/harness.h"

#ifndef __DISABLE_DIGICERT_RSA__

/*--------------------------------------------------------------------------*/

extern MSTATUS
PKCS1_rsaOaepEncrypt(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfType,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppCipherText,
    ubyte4 *pCipherTextLen
    )
{
    MSTATUS status = ERR_INVALID_ARG;
    BulkHashAlgo *pHashAlgo = NULL;
    BulkHashAlgo *pMgfHashAlgo = NULL;
    mgfFunc MGF = 0;
    
    if ( MOC_PKCS1_ALG_MGF1 == mgfType)
    {
        /* the hash algorithm must match the hash algorithm used for the MGF */
        if (hashAlgo != mgfHashAlgo)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        pMgfHashAlgo = pHashAlgo;
        MGF = PKCS1_MGF1_FUNC;
    }
#ifndef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
    /* FIPS_700 Binary did not include MOC_PKCS1_ALG_SHAKE */
    else if (MOC_PKCS1_ALG_SHAKE == mgfType)
    {
        /* mgfHashAlgo must be an xof */
        if (mgfHashAlgo != ht_shake128 && mgfHashAlgo != ht_shake256)
            goto exit;

        /* We allow any other hashAlgo */
        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(mgfHashAlgo, (const BulkHashAlgo **)&pMgfHashAlgo);
        if (OK != status)
            goto exit;

        MGF = PKCS1_MGF_SHAKE_FUNC;
    }
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */
    else
    {
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsaesOaepEncrypt (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, MGF, pMessage, mLen,
        pLabel, lLen, ppCipherText, pCipherTextLen);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsaesOaepEncrypt (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, pMgfHashAlgo, MGF, pMessage, mLen,
        pLabel, lLen, ppCipherText, pCipherTextLen);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */


exit:
    return status;
}


MOC_EXTERN MSTATUS
PKCS1_rsaesOaepEncrypt(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte H_rsaAlgoId,
    mgfFunc MGF,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppCipherText,
    ubyte4 *pCipherTextLen
    )
{
    MSTATUS status;
    BulkHashAlgo *pHashAlgo = NULL;

    status = CRYPTO_getRSAHashAlgo(H_rsaAlgoId, (const BulkHashAlgo **)&pHashAlgo);
    if (OK != status)
        goto exit;
#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsaesOaepEncrypt (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, MGF, pMessage, mLen,
        pLabel, lLen, ppCipherText, pCipherTextLen);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsaesOaepEncrypt (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, pHashAlgo, MGF, pMessage, mLen,
        pLabel, lLen, ppCipherText, pCipherTextLen);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

exit:
    return status;
}

#endif /* !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) */

/*--------------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)

extern MSTATUS
PKCS1_rsaOaepDecrypt(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfType,
    ubyte mgfHashAlgo,
    const ubyte *pCipherText,
    ubyte4 cLen,
    const ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppPlainText,
    ubyte4 *pPlainTextLen
    )
{
    MSTATUS status = ERR_INVALID_ARG;
    BulkHashAlgo *pHashAlgo = NULL;
    BulkHashAlgo *pMgfHashAlgo = NULL;
    mgfFunc MGF = 0;
    
    if ( MOC_PKCS1_ALG_MGF1 == mgfType)
    {
        /* the hash algorithm must match the hash algorithm used for the MGF */
        if (hashAlgo != mgfHashAlgo)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        pMgfHashAlgo = pHashAlgo;
        MGF = PKCS1_MGF1_FUNC;
    }
#ifndef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
    /* FIPS_700 Binary did not include MOC_PKCS1_ALG_SHAKE */
    else if (MOC_PKCS1_ALG_SHAKE == mgfType)
    {
        /* mgfHashAlgo must be an xof */
        if (mgfHashAlgo != ht_shake128 && mgfHashAlgo != ht_shake256)
            goto exit;

        /* We allow any other hashAlgo */
        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(mgfHashAlgo, (const BulkHashAlgo **)&pMgfHashAlgo);
        if (OK != status)
            goto exit;

        MGF = PKCS1_MGF_SHAKE_FUNC;
    }
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */
    else
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsaesOaepDecrypt(
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, MGF, pCipherText, cLen, pLabel, lLen,
        ppPlainText, pPlainTextLen);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsaesOaepDecrypt(
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, pMgfHashAlgo, MGF, pCipherText, cLen, pLabel, lLen,
        ppPlainText, pPlainTextLen);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

exit:
    return status;
}


extern MSTATUS
PKCS1_rsaesOaepDecrypt(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte H_rsaAlgoId,
    mgfFunc MGF,
    const ubyte *pCipherText,
    ubyte4 cLen,
    const ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppPlainText,
    ubyte4 *pPlainTextLen
    )
{
    MSTATUS status;
    BulkHashAlgo *pHashAlgo = NULL;

    status = CRYPTO_getRSAHashAlgo(H_rsaAlgoId, (const BulkHashAlgo **)&pHashAlgo);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsaesOaepDecrypt(
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, MGF, pCipherText, cLen, pLabel, lLen,
        ppPlainText, pPlainTextLen);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsaesOaepDecrypt(
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, pHashAlgo, MGF, pCipherText, cLen, pLabel, lLen,
        ppPlainText, pPlainTextLen);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

exit:
    return status;
}

#endif /* !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) */

/*--------------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))

MOC_EXTERN MSTATUS PKCS1_rsaPssSignExt (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_INVALID_ARG;
    BulkHashAlgo *pHashAlgo = NULL;
    BulkHashAlgo *pMgfHashAlgo = NULL;
    mgfFunc MGF = 0;
    MOC_UNUSED(pExtCtx);
    
    if ( MOC_PKCS1_ALG_MGF1 == mgfAlgo)
    {
        /* the hash algorithm must match the hash algorithm used for the MGF */
        if (hashAlgo != mgfHashAlgo)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        pMgfHashAlgo = pHashAlgo;
        MGF = PKCS1_MGF1_FUNC;
    }
#ifndef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
    /* FIPS_700 Binary did not include MOC_PKCS1_ALG_SHAKE */
    else if (MOC_PKCS1_ALG_SHAKE == mgfAlgo)
    {
        /* mgfHashAlgo must be an xof */
        if (mgfHashAlgo != ht_shake128 && mgfHashAlgo != ht_shake256)
            goto exit;

        /* We allow any other hashAlgo */
        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(mgfHashAlgo, (const BulkHashAlgo **)&pMgfHashAlgo);
        if (OK != status)
            goto exit;

        MGF = PKCS1_MGF_SHAKE_FUNC;
    }
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */
    else
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsassaPssSign (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, MGF, pMessage, mLen,
        saltLen, ppSignature, pSignatureLen);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsassaPssSign (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, pMgfHashAlgo, MGF, pMessage, mLen,
        saltLen, ppSignature, pSignatureLen);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

exit:
    return status;
}

/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PKCS1_rsaPssSign (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    )
{
    return PKCS1_rsaPssSignExt ( MOC_RSA(hwAccelCtx)
        pRandomContext, pRSAKey, hashAlgo, mgfAlgo, mgfHashAlgo, pMessage,
        mLen, saltLen, ppSignature, pSignatureLen, NULL);
}


MOC_EXTERN MSTATUS PKCS1_rsassaPssSign (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte H_rsaAlgoId,
    mgfFunc MGF,
    const ubyte *pMessage,
    ubyte4 mLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    )
{
    MSTATUS status;
    BulkHashAlgo *pHashAlgo = NULL;

    status = CRYPTO_getRSAHashAlgo(H_rsaAlgoId, (const BulkHashAlgo **)&pHashAlgo);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsassaPssSign (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, MGF, pMessage, mLen,
        saltLen, ppSignature, pSignatureLen);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsassaPssSign (
        MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pHashAlgo, pHashAlgo, MGF, pMessage, mLen,
        saltLen, ppSignature, pSignatureLen);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

exit:
    
    return status;
}

#endif /* if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)) */


/*--------------------------------------------------------------------------*/

/**
@brief      Free signature memory.

@details    This function frees memory allocated for a signature generated by
            the RSASSA_PSS signature scheme.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param  hwAccelCtx  For future use.
@param  ppSignature Pointer to signature generated by RSASSA_PSS signature
                      scheme.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
MOC_EXTERN MSTATUS
PKCS1_rsassaFreePssSign(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte **ppSignature)
{
    return PKCS1_INT_rsassaFreePssSign(MOC_RSA(hwAccelCtx) ppSignature);
}


/*--------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__

MOC_EXTERN MSTATUS PKCS1_rsaPssVerifyExt (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    ubyte4 *pVerify,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_INVALID_ARG;
    BulkHashAlgo *pHashAlgo = NULL;
    BulkHashAlgo *pMgfHashAlgo = NULL;
    intBoolean vStatus = FALSE;
    mgfFunc MGF = 0;
    MOC_UNUSED(pExtCtx);

    if (NULL == pVerify)
        return ERR_NULL_POINTER;

    if ( MOC_PKCS1_ALG_MGF1 == mgfAlgo)
    {
        /* the hash algorithm must match the hash algorithm used for the MGF */
        if (hashAlgo != mgfHashAlgo)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        pMgfHashAlgo = pHashAlgo;
        MGF = PKCS1_MGF1_FUNC;
    }
#ifndef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
    /* FIPS_700 Binary did not include MOC_PKCS1_ALG_SHAKE */
    else if (MOC_PKCS1_ALG_SHAKE == mgfAlgo)
    {
        /* mgfHashAlgo must be an xof */
        if (mgfHashAlgo != ht_shake128 && mgfHashAlgo != ht_shake256)
            goto exit;

        /* We allow any other hashAlgo */
        status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pHashAlgo);
        if (OK != status)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(mgfHashAlgo, (const BulkHashAlgo **)&pMgfHashAlgo);
        if (OK != status)
            goto exit;

        MGF = PKCS1_MGF_SHAKE_FUNC;
    }
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */
    else
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsassaPssVerify (
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, MGF, pMessage, mLen, pSignature, signatureLen,
        saltLen, &vStatus);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsassaPssVerify (
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, pMgfHashAlgo, MGF, pMessage, mLen, pSignature, signatureLen,
        saltLen, &vStatus);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

    /* Change result to ubyte4 irregardless of status */
    if (TRUE == vStatus)
    {
        *pVerify = 0;
    }
    else
    {
        *pVerify = 1;
    }

exit:
    return status;
}

/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PKCS1_rsaPssVerify (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    ubyte4 *pVerify
    )
{
    return PKCS1_rsaPssVerifyExt ( MOC_RSA(hwAccelCtx)
        pRSAKey, hashAlgo, mgfAlgo, mgfHashAlgo, (const ubyte *)pMessage, mLen,
        pSignature, signatureLen, saltLen, pVerify, NULL);
}

MOC_EXTERN MSTATUS PKCS1_rsassaPssVerify (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte H_rsaAlgoId,
    mgfFunc MGF,
    const ubyte * const pMessage,
    ubyte4 mLen,
    const ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    intBoolean *pVerify
    )
{
    MSTATUS status;
    BulkHashAlgo *pHashAlgo = NULL;

    status = CRYPTO_getRSAHashAlgo(H_rsaAlgoId, (const BulkHashAlgo **)&pHashAlgo);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */
    status = PKCS1_INT_rsassaPssVerify (
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, MGF, pMessage, mLen, pSignature, signatureLen,
        saltLen, pVerify);
#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */
    status = PKCS1_INT_rsassaPssVerify (
        MOC_RSA(hwAccelCtx) pRSAKey, pHashAlgo, pHashAlgo, MGF, pMessage, mLen, pSignature, signatureLen,
        saltLen, pVerify);
#endif /* __ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__ */

exit:

    return status;
}
#endif /* __DISABLE_DIGICERT_RSA__ */
#endif /* __RSA_PKCS1_HARDWARE_ACCELERATOR__ */
#endif /* __ENABLE_DIGICERT_PKCS1__ */
