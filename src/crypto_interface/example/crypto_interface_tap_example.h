/*
 * crypto_interface_tap_example.h
 *
 * Crypto Interface TAP Example Header
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

#ifndef __CRYPTO_INTERFACE_TAP_EXAMPLE_HEADER__
#define __CRYPTO_INTERFACE_TAP_EXAMPLE_HEADER__

#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS TAP_EXAMPLE_getCtx1(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext);

MOC_EXTERN MSTATUS TAP_EXAMPLE_getCtx2(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext);

MOC_EXTERN MSTATUS TAP_EXAMPLE_init(ubyte4 *pModNums, ubyte4 numMods);

MOC_EXTERN TAP_Context * TAP_EXAMPLE_getTapContext(ubyte4 moduleNum);
MOC_EXTERN TAP_EntityCredentialList * TAP_EXAMPLE_getEntityCredentialList(ubyte4 moduleNum);
MOC_EXTERN TAP_CredentialList * TAP_EXAMPLE_getCredentialList(ubyte4 moduleNum);
MOC_EXTERN TAP_PROVIDER TAP_EXAMPLE_getProvider(void);

MOC_EXTERN void TAP_EXAMPLE_clean(void);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_TAP_EXAMPLE_HEADER__ */
