/*
 * symtap.h
 *
 * Structures for performing Symmetric TAP operations.
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

#include "../../../crypto/mocsym.h"
#include "../../../tap/tap.h"
#include "../../../tap/tap_smp.h"

#ifndef __DIGICERT_SYM_TAP_HEADER__
#define __DIGICERT_SYM_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_TAP__

#define MOCANA_SYM_TAP_ENCRYPT 1
#define MOCANA_SYM_TAP_DECRYPT 0

/* TAP local data */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  TAP_Key                  *pKey;
  byteBoolean               isKeyLoaded;
  byteBoolean               isDeferUnload;
  TAP_SYM_KEY_MODE          symMode;   /* not used for hmac */
  sbyte4                    direction; /* not used for hmac */
  ubyte                     pLeftOvers[16]; /* for implementations that may not process all bytes */
  ubyte4                    leftOverLen;
  
} MTapKeyData;

typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  TAP_KEY_ALGORITHM         keyAlgorithm;
  
  /* Use symMode for AES and hashAlg for HMAC. Otherwise use TAP_SYM_KEY_MODE_UNDEFINED */
  TAP_SYM_KEY_MODE          symMode;
  TAP_HASH_ALG              hashAlg;
  TAP_KEY_USAGE             keyUsage;

} MSymTapKeyGenArgs;

typedef struct
{
    ubyte *pKeyData;
    ubyte4 keyDataLen;
    byteBoolean token;
    TAP_KeyInfo *pKeyInfo;
    
} MSymTapCreateArgs;

MOC_EXTERN MSTATUS SymTapCreate(MocSymCtx pMocSymCtx, MSymTapKeyGenArgs *pKeyGenArgs, ubyte4 localType, MSymOperator operator);
MOC_EXTERN MSTATUS SymTapFree(MocSymCtx pMocSymCtx);

#endif  /* __ENABLE_DIGICERT_TAP__ */

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_SYM_TAP_HEADER__ */
