/*
 * qstap.h
 *
 * Functions for performing QS TAP operations.
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

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"

#ifndef __DIGICERT_ASYM_QS_TAP_HEADER__
#define __DIGICERT_ASYM_QS_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
/* QS TAP local data */
typedef struct
{
  MAsymCommonKeyData        common;
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  TAP_Key                  *pKey;
  MOperatorCallback         Callback;
  StandardParams            standardParams;
  byteBoolean               isKeyLoaded;
  byteBoolean               isDeferUnload;

} MQsTapKeyData;

/* Argument structure for creating a new QS TAP key */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  MOperatorCallback         Callback;

  /* Optional params structure, this must be specified if the caller wants to
   * receive the software implemented public key after generation */
  StandardParams            standardParams;
} MQsTapCreateArgs;

/* Argument structure for generating a new QS TAP key, note this
 * structure is a superset of the creation args with equal offsets
 * so that MQsTapKeyGenArgs can be cast as MQsTapCreateArgs */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  MOperatorCallback         Callback;

  /* Optional params structure, this must be specified if the caller wants to
   * receive the software implemented public key after generation */
  StandardParams            standardParams;
  TAP_KEY_USAGE             keyUsage;
  TAP_KeyInfo_Union         algKeyInfo;
  TAP_TokenId               tokenId;
} MQsTapKeyGenArgs;

/* Identifier for the custom Digicert Blob format, used in serialization */
#define MOC_QS_TAP_BLOB_START_LEN 12
#define MOC_QS_TAP_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x02, 0x00, 0x72

/* Implements MOC_ASYM_OP_CREATE.
 *
 * This function allocates space for the local data.
 * This function expects the pMocAsymKey->pKeyData to be MQsTapKeyData.
 */
MOC_EXTERN MSTATUS QsTapCreate (
  MocAsymKey pMocAsymKey,
  void *pCreateInfo,
  keyOperation keyOp
  );

/* Implements MOC_ASYM_OP_FREE,
 *
 * Free the mocAsymKey->pKeyData.
 * This function expects the pMocAsymKey->pKeyData to be MQsTapKeyData.
 */
MOC_EXTERN MSTATUS QsTapFreeKey (
  MocAsymKey pMocAsymKey
  );


/* This builds the local data (the pKeyData) if necessary, and  stores the input.
 * Any one or all of the input (new key, algId, paramsCall) can be NULL.
 * This will copy a reference to *ppNewKey, and NULL out *ppNewKey.
 * This means that the custom key will take over ownership of the TAP_Key, algId,
 * and/or params call. It will destroy them later when the MocAsymKey is destroyed.
 * This will allocate space to copy the algId and memcpy it.
 */
MOC_EXTERN MSTATUS QsTapLoadKeyData (
  TAP_Key **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocSymCtx *ppDigestCtx,
  StandardParams paramsCall,
  MocAsymKey pMocAsymKey
  );

MOC_EXTERN MSTATUS QsTapGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey
  );

MOC_EXTERN MSTATUS QsTapSerializeKey (
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  );

MOC_EXTERN MSTATUS QsTapDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo
  );

MOC_EXTERN MSTATUS SerializeQsTapKeyAlloc (
  TAP_Key *pKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

#endif /* defined(__ENABLE_DIGICERT_TAP__) */

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_ASYM_QS_TAP_HEADER__ */
