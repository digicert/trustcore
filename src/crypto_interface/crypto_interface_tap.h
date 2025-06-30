
/*
 * crypto_interface_tap.h
 *
 * Cryptographic Interface header file for declaring TAP functions
 * for the Crypto Interface.
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

#ifndef __CRYPTO_INTERFACE_TAP_HEADER__
#define __CRYPTO_INTERFACE_TAP_HEADER__

#include "../tap/tap_smp.h"
#include "../tap/tap.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_serializeKeyById(
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_CredentialList *pKeyCredentials,
    TAP_KeyInfo *pKeyInfo,
    ubyte *pId,
    ubyte4 idLen,
    ubyte serialFormat,
    ubyte **ppSerializedKey,
    ubyte4 *pSerializedKeyLen);

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_loadWithCreds(
    MocAsymKey pKey,
    ubyte *pPassword, 
    ubyte4 passwordLen,
    void *pLoadCtx);

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getKeyTapInfo(
    MocAsymKey pKey,
    ubyte4 *pProvider,
    ubyte4 *pModuleId);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_TAP_HEADER__ */
