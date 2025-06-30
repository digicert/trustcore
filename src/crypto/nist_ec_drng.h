/*
 * nist_rng.h
 *
 * Implementation of the RNGs described in NIST 800-90
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

/*! \file nist_rng.h NIST RNG developer API header.
This header file contains definitions, enumerations, structures, and function
declarations used for NIST RNG constructions as described in NIST 800-90.

\since 3.0.6
\version 5.0.5 and later

! Flags
No flag definitions are required to use this file.

! External Functions
*/


/*------------------------------------------------------------------*/

#ifndef __NIST_EC_DRNG_HEADER__
#define __NIST_EC_DRNG_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/*  Function prototypes  */

struct NIST_EC_DRBG_Ctx;

MOC_EXTERN MSTATUS NIST_ECDRBG_newContext( MOC_HASH(hwAccelDescr hwAccelCtx)
                                              struct NIST_EC_DRBG_Ctx **ppNewContext,
                                              PEllipticCurvePtr pCurve,
                                              ubyte4 rsaHashAlgoId,
                                              const ubyte* d, ubyte4 dLen,
                                              const ubyte* entropyInput,
                                              ubyte4 entropyInputLen,
                                              const ubyte* nonce,
                                              ubyte4 nonceLen,
                                              const ubyte* personalization,
                                              ubyte4 personalizationLen);


MOC_EXTERN MSTATUS NIST_ECDRBG_deleteContext(struct NIST_EC_DRBG_Ctx **ppNewContext);

MOC_EXTERN MSTATUS NIST_ECDRBG_reseed( MOC_HASH(hwAccelDescr hwAccelCtx)
                                      struct NIST_EC_DRBG_Ctx* pContext,
                                      const ubyte* entropyInput,
                                      ubyte4 entropyInputLen,
                                      const ubyte* additionalInput,
                                      ubyte4 additionalInputLen);
    
MOC_EXTERN MSTATUS NIST_ECDRBG_setStateFromOutput( MOC_HASH(hwAccelDescr hwAccelCtx)
                                                  struct NIST_EC_DRBG_Ctx *pContext,
                                                  const ubyte* output,
                                                  ubyte4  outputLen);

MOC_EXTERN MSTATUS NIST_ECDRBG_getSecretLength( struct NIST_EC_DRBG_Ctx* pContext,
                                               ubyte4* secretLength);

/* this one will generate an output of fixed length corresponding to 2 points */
MOC_EXTERN MSTATUS NIST_ECDRBG_generateSecret(MOC_HASH(hwAccelDescr hwAccelCtx)
                                              struct NIST_EC_DRBG_Ctx* pContext,
                                              const ubyte* additionalInput,
                                              ubyte4 additionalInputLen,
                                              ubyte* secret,
                                              ubyte4 secretLength);

MOC_EXTERN MSTATUS NIST_ECDRBG_generate(MOC_HASH(hwAccelDescr hwAccelCtx)
                                        struct NIST_EC_DRBG_Ctx* pContext,
                                        const ubyte* additionalInput,
                                        ubyte4 additionalInputLen,
                                        ubyte* output, ubyte4 outputLenBits);

/* canonical interface to random number generator */
MOC_EXTERN MSTATUS NIST_ECDRBG_numberGenerator(MOC_HASH(hwAccelDescr hwAccelCtx)
                                               randomContext *pRandomContext,
                                               ubyte *pBuffer, sbyte4 bufSize);

MOC_EXTERN sbyte4 NIST_ECDRBG_rngFun(MOC_HASH(hwAccelDescr hwAccelCtx)
                                     void* rngFunArg,
                                     ubyte4 length, ubyte *buffer);


#ifdef __cplusplus
}
#endif

#endif /* __NIST_RNG_HEADER__ */

