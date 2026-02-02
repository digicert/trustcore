/*
 * mbedcommonecc.h
 *
 * Operator for Software version of ECC MocAsym Key.
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

#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#ifndef __DIGICERT_MBED_COMMON_ECC_H__
#define __DIGICERT_MBED_COMMON_ECC_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MBED_ECP_PUB_DER_MAX_BYTES 30 + 2 * MBEDTLS_ECP_MAX_BYTES
#define MBED_ECP_PRV_DER_MAX_BYTES 29 + 3 * MBEDTLS_ECP_MAX_BYTES

typedef int (*MbedSerialize)(
    mbedtls_pk_context *pPkCtx,
    unsigned char *pBuffer,
    size_t bufferLen
    );

MOC_EXTERN MSTATUS EccMbedSign (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    );

MOC_EXTERN MSTATUS EccMbedSignDigestInfo (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    );
    
MOC_EXTERN MSTATUS EccMbedSignMessage (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    );
    
MOC_EXTERN MSTATUS EccMbedVerify (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    );

MOC_EXTERN MSTATUS EccMbedVerifyDigestInfo (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    );

MOC_EXTERN MSTATUS EccMbedVerifyMessage (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    );
    
MOC_EXTERN MSTATUS EccMbedGenerateKeyPair(
    MocCtx pMocCtx,
    MKeyOperator KeyOperator,
    MKeyPairGenInfo *pInputInfo,
    MKeyPairGenResult *pOutputInfo,
    mbedtls_ecp_group_id eccGroupId
    );

MOC_EXTERN MSTATUS EccMbedComputeSharedSecret (
    MocAsymKey pMocAsymKey,
    MKeyOperatorData *pPubVal,
    MKeyOperatorBuffer *pSharedSecret
    );

MOC_EXTERN MSTATUS EccMbedSetKeyData (
    MocAsymKey pMocAsymKey,
    MKeyOperator operator,
    ubyte4 localType,
    MEccKeyTemplate *pTemplate,
    mbedtls_ecp_group_id eccGroupId
    );

MOC_EXTERN MSTATUS EccMbedGetKeyDataAlloc(
    MocAsymKey pMocAsymKey,
    MEccKeyTemplate *pOutputInfo,
    ubyte *pInputInfo
    );

MOC_EXTERN MSTATUS EccMbedCloneKey (
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppNewKey
    );

MOC_EXTERN MSTATUS EccMbedReturnPubValAlloc (
    MocAsymKey pMocAsymKey,
    MKeyOperatorDataReturn *pPubVal
    );

MOC_EXTERN MSTATUS EccMbedGetPubFromPri (
    MocAsymKey pMocAsymKey,
    MKeyOperator KeyOperator,
    MocAsymKey *ppPubKey
    );

MOC_EXTERN MSTATUS EccMbedValidatePubPriMatch (
    MocAsymKey pMocAsymKey,
    MocAsymKey pPubKey,
    byteBoolean *pMatch
    );

MOC_EXTERN MSTATUS EccMbedValidateKey (
    MocAsymKey pMocAsymKey,
    byteBoolean *pIsValid
    );

MOC_EXTERN MSTATUS EccMbedFreeKey (
    MocAsymKey pMocAsymKey
    );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_COMMON_ECC_H__ */
