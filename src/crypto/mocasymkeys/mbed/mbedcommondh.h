/*
 * mbedcommondh.h
 *
 * Functions common to DH operations.
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

#include "mbedtls/dhm.h"

#ifndef __DIGICERT_MBED_COMMON_DH_H__
#define __DIGICERT_MBED_COMMON_DH_H__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS DhMbedGenerateKeyPair(
    MocCtx pMocCtx,
    MKeyPairGenInfo *pInputInfo,
    MKeyPairGenResult *pOutputInfo
    );

MOC_EXTERN MSTATUS DhMbedGetPubFromPri(
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppRetKey
    );

MOC_EXTERN MSTATUS DhMbedCloneKey (
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppNewKey
    );

MOC_EXTERN MSTATUS DhMbedSetKeyData (
    MocAsymKey pMocAsymKey,
    MDhKeyTemplate *pTemplate
    );

MOC_EXTERN MSTATUS DhMbedGetKeyDataAlloc (
    MocAsymKey pMocAsymKey,
    MDhKeyTemplate *pTemplate,
    ubyte *pInputInfo
    );

MOC_EXTERN MSTATUS DhMbedReturnPubValAlloc (
    MocAsymKey pMocAsymKey,
    MKeyOperatorDataReturn *pPubVal
    );

MOC_EXTERN MSTATUS DhMbedComputeSharedSecret (
    MocAsymKey pMocAsymKey,
    MKeyOperatorData *pPubVal,
    MKeyOperatorBuffer *pSharedSecret
    );

MOC_EXTERN MSTATUS DhMbedFreeKey(
    MocAsymKey pMocAsymKey
    );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_COMMON_DH_H__ */
