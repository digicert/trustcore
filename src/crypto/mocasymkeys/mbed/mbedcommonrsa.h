/*
 * commonrsa.h
 *
 * Functions common to RSA operations.
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

#include "mbedtls/rsa.h"

#ifndef __DIGICERT_MBED_COMMON_RSA_H__
#define __DIGICERT_MBED_COMMON_RSA_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_MBED_RSA_EXPONENT 65537

MOC_EXTERN MSTATUS RsaMbedGetSecuritySize(
    MocAsymKey pMocAsymKey,
    ubyte4 *pOutputInfo
    );

MOC_EXTERN MSTATUS RsaMbedGenerateKeyPair(
    MocCtx pMocCtx,
    MKeyPairGenInfo *pInputInfo,
    MKeyPairGenResult *pOutputInfo
    );

MOC_EXTERN MSTATUS RsaMbedEncrypt (
    MocAsymKey pMocAsymKey,
    MKeyAsymEncryptInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    );

MOC_EXTERN MSTATUS RsaMbedDecrypt (
    MocAsymKey pMocAsymKey,
    MKeyAsymEncryptInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    );

MOC_EXTERN MSTATUS RsaMbedSign (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    );

MOC_EXTERN MSTATUS RsaMbedVerify (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    );

MOC_EXTERN MSTATUS RsaMbedGetPubFromPri(
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppRetKey
    );

MOC_EXTERN MSTATUS RsaMbedCloneKey (
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppNewKey
    );

MOC_EXTERN MSTATUS RsaMbedSetKeyData (
    MocAsymKey pMocAsymKey,
    MRsaKeyTemplate *pTemplate
    );

MOC_EXTERN MSTATUS RsaMbedGetKeyDataAlloc (
    MocAsymKey pMocAsymKey,
    MRsaKeyTemplate *pTemplate,
    ubyte *pInputInfo
    );

MOC_EXTERN MSTATUS RsaMbedFreeKey(
    MocAsymKey pMocAsymKey
    );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_COMMON_RSA_H__ */
