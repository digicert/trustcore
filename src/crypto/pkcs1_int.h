/*
 * pkcs1_int.h
 *
 * PKCS#1 Version 2.1 Internal Header
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
@file       pkcs1_int.h

@brief      Header file for SoT Platform PKCS&nbsp;\#1 convenience API.
@details    Header file for SoT Platform PKCS&nbsp;\#1, version 2.1, convenience
            API, as defined by RFC&nbsp;3447.

For documentation for this file's definitions, enumerations, and functions, see
pkcs1.c.
*/


/*------------------------------------------------------------------*/

#ifndef __PKCS1_INT_HEADER__
#define __PKCS1_INT_HEADER__

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS1__
#include "../crypto_interface/crypto_interface_pkcs1_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_PKCS1_INT
#define MOC_EXTERN_PKCS1_INT_H __declspec(dllexport)
#else
#define MOC_EXTERN_PKCS1_INT_H __declspec(dllimport) extern 
#endif /* WIN_EXPORT_PKCS1_INT */

#ifdef WIN_STATIC
#undef MOC_EXTERN_PKCS1_INT_H
#define MOC_EXTERN_PKCS1_INT_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_PKCS1_INT_H MOC_EXTERN

#endif /* RTOS_WIN32 */


/*------------------------------------------------------------------*/

/* exported routines */

/* For non OpenSSL builds macro the old API into the new API for backwards
 * compatability. OpenSSL builds cannot define this macro as there are namespace
 * issues with the old APIs. */
#ifndef OPENSSL_ENGINE
#ifndef PKCS1_MGF1
#define PKCS1_MGF1 PKCS1_MGF1_FUNC
#endif /* PKCS1_MGF1 */
#endif /* OPENSSL_ENGINE */

/**
@dont_show
@internal
*/
#if !defined(__RTOS_QNX_6_5__) && !defined(__RTOS_VXWORKS__)
typedef MSTATUS (*mgfFunc)(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask);
#endif
/*------------------------------------------------------------------*/
#ifdef __ENABLE_MOCANA_FIPS_700_BINARY_SUPPORT__
/* FIPS_700 Binary did not include additional pMgfHashAlgo parameter */

MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsaesOaepEncrypt(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, mgfFunc MGF, const ubyte *M, ubyte4 mLen, const ubyte *L, ubyte4 lLen, ubyte **ppRetEncrypt, ubyte4 *pRetEncryptLen);
#if (!defined(__DISABLE_MOCANA_RSA_DECRYPTION__))
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsaesOaepDecrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, mgfFunc MGF, const ubyte *C, ubyte4 cLen, const ubyte *L, ubyte4 lLen, ubyte **ppRetDecrypt, ubyte4 *pRetDecryptLength);
#endif

#if (!defined(__DISABLE_MOCANA_RSA_DECRYPTION__))
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsassaPssSign(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, mgfFunc MGF, const ubyte *pMessage, ubyte4 mesgLen, ubyte4 saltLen, ubyte **ppRetSignature, ubyte4 *pRetSignatureLen);
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsassaFreePssSign(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte **ppSignature);
#endif
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsassaPssVerify(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, mgfFunc MGF, const ubyte * const pMessage, ubyte4 mesgLen, const ubyte *pSignature, ubyte4 signatureLen, sbyte4 saltLen, intBoolean *pRetIsSignatureValid);

#else /* Typical 710 build */
/* FIPS_710 Binary does include additional pMgfHashAlgo */

MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsaesOaepEncrypt(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, BulkHashAlgo *pMgfHashAlgo, mgfFunc MGF, const ubyte *M, ubyte4 mLen, const ubyte *L, ubyte4 lLen, ubyte **ppRetEncrypt, ubyte4 *pRetEncryptLen);
#if (!defined(__DISABLE_MOCANA_RSA_DECRYPTION__))
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsaesOaepDecrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, BulkHashAlgo *pMgfHashAlgo, mgfFunc MGF, const ubyte *C, ubyte4 cLen, const ubyte *L, ubyte4 lLen, ubyte **ppRetDecrypt, ubyte4 *pRetDecryptLength);
#endif

#if (!defined(__DISABLE_MOCANA_RSA_DECRYPTION__))
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsassaPssSign(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, BulkHashAlgo *pMgfHashAlgo, mgfFunc MGF, const ubyte *pMessage, ubyte4 mesgLen, ubyte4 saltLen, ubyte **ppRetSignature, ubyte4 *pRetSignatureLen);
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsassaFreePssSign(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte **ppSignature);
#endif
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_INT_rsassaPssVerify(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, BulkHashAlgo *pHashAlgo, BulkHashAlgo *pMgfHashAlgo, mgfFunc MGF, const ubyte * const pMessage, ubyte4 mesgLen, const ubyte *pSignature, ubyte4 signatureLen, sbyte4 saltLen, intBoolean *pRetIsSignatureValid);

#endif /* __ENABLE_MOCANA_FIPS_700_BINARY_SUPPORT__ */

/* helper function */
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_MGF1_FUNC(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask);
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_MGF_SHAKE_FUNC(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask);
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_OS2IP(const ubyte *pMessage, ubyte4 mesgLen, vlong **ppRetM);
MOC_EXTERN_PKCS1_INT_H MSTATUS PKCS1_I2OSP(vlong *pValue, ubyte4 fixedLength, ubyte **ppRetString);

#ifdef __cplusplus
}
#endif


#endif  /* __PKCS1_HEADER__ */
