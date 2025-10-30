/*
 * ecctap.h
 *
 * Functions for performing ECC TAP operations.
 *
 * Copyright Mocana Corp 2017. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonecc.h"
#include "../../../tap/tap_serialize.h"
#include "../../../tap/tap_serialize_smp.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"

#ifndef __MOCANA_ASYM_ECC_TAP_HEADER__
#define __MOCANA_ASYM_ECC_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_MOCANA_TAP__)
/* ECC TAP local data */
typedef struct
{
  MAsymCommonKeyData        common;
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  TAP_Key                  *pKey;
  intBoolean                useDataNotDigest;
  MocSymCtx                 pTapDigester;
  MOperatorCallback         Callback;

  /* A function pointer to recieve the curve parameter info which is used
   * to construct the software public key from the private TAP key. This
   * function pointer can be optionally specified at either generation time
   * or deserialization time, the key will hold onto that info here until it is
   * needed to implement getPubFromPri. If it is never specified then a public
   * key can not be constructed from the private. */
  StandardParams       standardParams;
  byteBoolean          isKeyLoaded;
  byteBoolean          isDeferUnload;
} MEccTapKeyData;

/* Argument structure for creating a new ECC TAP key or deserializing an
 * existing ECC TAP serialized key. */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  MOperatorCallback         Callback;

  /* Optional params structure, this must be specified if the caller wants to
   * recieve the software implemented public key after generation */
  StandardParams            standardParams;
} MEccTapCreateArgs;

/* Argument structure for generating a new ECC TAP key, note this
 * structure is a superset of the creation args with equal offsets
 * so that MEccTapKeyGenArgs can be cast as MEccTapCreateArgs */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  MOperatorCallback         Callback;

  /* Optional params structure, this must be specified if the caller wants to
   * recieve the software implemented public key after generation */
  StandardParams            standardParams;
  TAP_KEY_USAGE             keyUsage;
  TAP_KeyInfo_Union         algKeyInfo;
  TAP_TokenId               tokenId;
} MEccTapKeyGenArgs;

/* Identifier for the custom Mocana Blob format, used in serialization */
#define MOC_ECC_TAP_BLOB_START_LEN 12
#define MOC_ECC_TAP_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x02, 0x00, 0x02

/* Implements MOC_ASYM_OP_CREATE.
 *
 * This function allocates space for the local data.
 * This function expects the pMocAsymKey->pKeyData to be MEccTapKeyData.
 */
MOC_EXTERN MSTATUS EccTapCreate (
  MocAsymKey pMocAsymKey,
  void *pCreateInfo,
  keyOperation keyOp
  );

/* Implements MOC_ASYM_OP_FREE,
 *
 * Free the mocAsymKey->pKeyData.
 * This function expects the pMocAsymKey->pKeyData to be MEccTapKeyData.
 */
MOC_EXTERN MSTATUS EccTapFreeKey (
  MocAsymKey pMocAsymKey
  );

/* Implements MOC_ASYM_OP_GENERATE
 *
 * Generate a new key pair, placing them into the objects passed in the
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MEccTapKeyData.
 * This function expects an MEccTapKeyGenArgs structure for the
 * associated operator info.
 */
MOC_EXTERN MSTATUS EccTapGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyPairGenInfo *pInputInfo,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS EccTapSign (
  MocAsymKey pMocAsymKey,
  MKeyAsymEncryptInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* This builds the local data (the pKeyData) if necessary, and  stores the input.
 * Any one or all of the input (new key, algId, paramsCall) can be NULL.
 * This will copy a reference to *ppNewKey, and NULL out *ppNewKey.
 * This means that the custom key will take over ownership of the TAP_Key, algId,
 * and/or params call. It will destroy them later when the MocAsymKey is destroyed.
 * This will allocate space to copy the algId and memcpy it.
 */
MOC_EXTERN MSTATUS EccTapLoadKeyData (
  TAP_Key **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocSymCtx *ppDigestCtx,
  StandardParams paramsCall,
  MocAsymKey pMocAsymKey
  );

MOC_EXTERN MSTATUS EccTapGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey
  );

MOC_EXTERN MSTATUS EccTapSerializeKey (
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  );

MOC_EXTERN MSTATUS EccTapDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo
  );

MOC_EXTERN MSTATUS DeserializeEccTapKey (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  );

MOC_EXTERN MSTATUS ReadEccTapKeyBlob (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  TAP_Key **ppTapKey
  );

MOC_EXTERN MSTATUS ReadEccTapKeyDer (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  );

MOC_EXTERN MSTATUS SerializeEccTapKeyAlloc (
  TAP_Key *pKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

#endif /* defined(__ENABLE_MOCANA_TAP__) */

#ifdef __cplusplus
}
#endif

#endif /* __MOCANA_ASYM_ECC_TAP_HEADER__ */
