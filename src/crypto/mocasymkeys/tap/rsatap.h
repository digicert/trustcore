/*
 * rsatap.h
 *
 * Functions for performing RSA TAP operations.
 *
 * Copyright Mocana Corp 2017. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../../../tap/tap_serialize.h"
#include "../../../tap/tap_serialize_smp.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"
#include "../../../tap/tap_utils.h"

#ifndef __MOCANA_ASYM_RSA_TAP_HEADER__
#define __MOCANA_ASYM_RSA_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_TAP__

/* RSA TAP local data, note the TAP context and credential information
 * is only used for deserialization operations */
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
  byteBoolean               isKeyLoaded;
  byteBoolean               isDeferUnload;
} MRsaTapKeyData;

/* Argument structure for generating a new RSA TAP key, note this
 * structure is a superset of the creation args with equal offsets
 * so that MRsaTapKeyGenArgs can be cast as MRsaTapCreateArgs */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  MOperatorCallback         Callback;
  TAP_KEY_USAGE             keyUsage;
  TAP_KeyInfo_Union         algKeyInfo;
  TAP_TokenId               tokenId;
} MRsaTapKeyGenArgs;

/* Argument structure for creating a new RSA TAP key or deserializing an
 * existing RSA TAP serialized key. */
typedef struct
{
  TAP_Context              *pTapCtx;
  TAP_CredentialList       *pKeyCredentials;
  TAP_EntityCredentialList *pEntityCredentials;
  TAP_AttributeList        *pKeyAttributes;
  MOperatorCallback         Callback;
} MRsaTapCreateArgs;

/* RSA TAP Key Mocana Blob Definition */
#define MOC_RSA_TAP_BLOB_START_LEN 12
#define MOC_RSA_TAP_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x02, 0x00, 0x01

/* Implements MOC_ASYM_OP_GENERATE
 *
 * Generate a new key pair, placing them into the objects passed in the
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MRsaTapKeyData.
 * This function expects an MRsaTapKeyGenArgs structure for the
 * associated operator info.
 */
MOC_EXTERN MSTATUS RsaTapGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyPairGenInfo *pInputInfo,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_CREATE.
 *
 * This function allocates space for the local data.
 * This function expects the pMocAsymKey->pKeyData to be MRsaTapKeyData.
 */
MOC_EXTERN MSTATUS RsaTapCreate (
  MocAsymKey pMocAsymKey,
  void *pCreateInfo,
  keyOperation keyOp
  );

/* This builds the local data (the pKeyData) if necessary, and  stores the input.
 * Any one or all of the input (new key, algId, digest) can be NULL.
 * This will copy a reference to *ppNewKey, and NULL out *ppNewKey.
 * This will copy a reference to *ppDigestCtx, and NULL out *ppDigestCtx.
 * This means that the mocasym key will take over ownership of the RSAKey, algId,
 * and/or digest ctx. It will destroy them later when the MocAsymKey is destroyed.
 * This will allocate space to copy the algId and memcpy it.
 */
MOC_EXTERN MSTATUS RsaTapLoadKeyData (
  TAP_Key **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocSymCtx *ppDigestCtx,
  MocAsymKey pMocAsymKey
  );

/* Implements MOC_ASYM_OP_FREE,
 *
 * Free the mocAsymKey->pKeyData.
 * This function expects the pMocAsymKey->pKeyData to be MRsaTapKeyData.
 */
MOC_EXTERN MSTATUS RsaTapFreeKey (
  MocAsymKey pMocAsymKey
  );

/* Implements MOC_ASYM_OP_GET_SECURITY_SIZE
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaTapKeyData.
 */
MOC_EXTERN MSTATUS RsaTapGetSecuritySize (
  MocAsymKey pMocAsymKey,
  ubyte4 *pSecuritySize
  );

/* Implements MOC_ASYM_OP_SERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaTapKeyData.
 */
MOC_EXTERN MSTATUS RsaTapSerializeKey (
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  );

/* Serialize an RSA TAP key.
 * The function will allocate memory for the data and return the new buffer and
 * its length at the addresses given.
 * This function does not check the args, it is the responsibility of the caller
 * not to make mistakes.
 */
MOC_EXTERN MSTATUS SerializeRsaTapKeyAlloc (
  TAP_Key *pKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

/* This will build the Mocana version 2 key blob of the given key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using MOC_FREE.
 */
MOC_EXTERN MSTATUS BuildRsaTapKeyBlobAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* This will build the PKCS 8 DER encoding of the private key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using MOC_FREE.
 */
MOC_EXTERN MSTATUS DerEncodeRsaTapKeyAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* Implements MOC_ASYM_OP_DESERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaTapKeyData.
 */
MOC_EXTERN MSTATUS RsaTapDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo
  );

/* Deserialize an RSA TAP key.
 * The function will build an existing RSA TAP Key from its serialized blob.
 */
MOC_EXTERN MSTATUS DeserializeRsaTapKey (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  );

/* Read the given blob and determine if it is a mocana blob containing an
 * RSA TAP key. If so, build the key with the data.
 */
MOC_EXTERN MSTATUS ReadRsaTapKeyBlob (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  TAP_Key **ppTapKey
  );

/* Read the given blob and determine if it is a DER encoding containing an
 * RSA TAP key. If so, build the key with the data.
 */
MOC_EXTERN MSTATUS ReadRsaTapKeyDer (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  );

MOC_EXTERN MSTATUS RsaTapGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  );

#endif  /* __ENABLE_MOCANA_TAP__ */

#ifdef __cplusplus
}
#endif

#endif /* __MOCANA_ASYM_RSA_TAP_HEADER__ */
