/*
 * commonrsa.h
 *
 * Functions common to RSA operations.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
