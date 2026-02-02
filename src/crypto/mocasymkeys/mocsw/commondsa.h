/*
 * commondsa.h
 *
 * Functions common to DSA operations.
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

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"

#ifndef __COMMON_DSA_HEADER__
#define __COMMON_DSA_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* This is the pKeyData inside an DsaSw key.
 */
typedef struct
{
  MAsymCommonKeyData   common;
  DSAKey              *pKey;
} MDsaSwKeyData;

/* Implements MOC_ASYM_OP_FREE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwFreeKey (
  MocAsymKey pMocAsymKey,
  struct vlong **ppVlongQueue
  );

/* This builds the local data (the pKeyData) if necessary, and  stores the input.
 * Any one or all of the input (new key, algId,) can be NULL.
 * This will copy a reference to *ppNewKey, and NULL out *ppNewKey.
 * This means that the mocasym key will take over ownership of the DSAKey. It will
 * destroy them later when the MocAsymKey is destroyed.
 * This will allocate space to copy the algId and memcpy it.
 */
MOC_EXTERN MSTATUS DsaSwLoadKeyData (
  DSAKey **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocAsymKey pMocAsymKey,
  vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_PUB_FROM_PRI
 *
 * Construct a new public key from the private key.
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_IS_SAME_PUB_KEY
 */
MOC_EXTERN MSTATUS DsaSwIsSamePubKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pDerKey,
  intBoolean *pIsMatch,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_CLONE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwCloneKey (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppNewKey,
  vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GET_SECURITY_SIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwGetSecuritySize (
  MocAsymKey pMocAsymKey,
  ubyte4 *pSecuritySize
  );

/* Implements MOC_ASYM_OP_GENERATE.
 *
 * Generate a new key pair, placing them into the objects passed in the
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyPairGenInfo *pInputInfo,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_SIGN_DIGEST_INFO.
 *
 * Sign the data in pInputInfo, placing the signature into the buffer in
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwSign (
  MocAsymKey pMocAsymKey,
  MKeyAsymEncryptInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_VERIFY_DIGEST_INFO.
 *
 * Verify the data in pInputInfo, setting *pOutputInfo to the result.
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwVerify (
  MocAsymKey pMocAsymKey,
  MKeyAsymVerifyInfo *pInputInfo,
  ubyte4 *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GET_ALG_ID.
 */
MOC_EXTERN MSTATUS DsaSwReturnAlgId (
  MocAsymKey pMocAsymKey,
  MKeyOperatorAlgIdReturn *pInputInfo,
  MKeyOperatorDataReturn *pOutputInfo
  );

#define MOC_DSA_BLOB_START_LEN 12
#define MOC_DSA_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x00, 0x00, 0x03

/* Implements MOC_ASYM_OP_SERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwSerializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  );

/* Serialize a DSA key.
 * The function will allocate memory for the data and return the new buffer and
 * its length at the addresses given.
 * This function does not check the args, it is the responsibility of the caller
 * not to make mistakes.
 */
MOC_EXTERN MSTATUS SerializeDsaKeyAlloc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

/* This will build the PKCS 8 DER encoding of a private key, or the X.509
 * SubjectPubkicKeyInfo of a public key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using DIGI_FREE.
 */
MOC_EXTERN MSTATUS DerEncodeDsaKeyAlloc (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  DSAKey *pDsaKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* Implements MOC_ASYM_OP_DESERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo,
  struct vlong **ppVlongQueue
  );

/* Deserialize a DSA key.
 * The function will build a new DSAKey.
 */
MOC_EXTERN MSTATUS DeserializeDsaKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  AsymmetricKey *pAsymKey,
  struct vlong **ppVlongQueue
  );

/* Read the given blob and determine if it is for DSA. If so, build the key with
 * the data.
 */
MOC_EXTERN MSTATUS ReadDsaKeyBlob (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  DSAKey **ppDsaKey,
  struct vlong **ppVlongQueue
  );

/* Try to decode some ASN.1 data. This might be DSA in alternate definitions.
 * <p>The DER of a DSA key should be something that follows the standards.
 * However, there are packages out there (such as OpenSSL) that don't follow
 * them. Try these definitions.
 * <pre>
 * <code>
 *   PrivateKey :
 *     SEQ {
 *       INT version,
 *       INT p,
 *       INT q,
 *       INT g,
 *       INT y,
 *       INT x }
 *
 *   PublicKey :
 *     SEQ {
 *       INT p,
 *       INT q,
 *       INT g,
 *       INT y }
 * </code>
 * </pre>
 * <p>The caller passes in a flag indicating whether the key is public, private,
 * or unknown. That is, it might be possible that the caller knows whether the
 * key is supposed to be public or private. If so, pass that info in. DO this
 * with pubPriFlag. If unknown, pass in 0. If known and public, pass in 1, if
 * known and private, pass in 2.
 * <p>This function will build a new key object.
 */
MOC_EXTERN MSTATUS DecodeDsaAlternate (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte4 pubPriFlag,
  DSAKey **ppKey,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GET_PARAMS.
 *
 * This function expects the pMocAsymKey->pKeyData to be MDsaSwKeyData.
 */
MOC_EXTERN MSTATUS DsaSwReturnParamsAlloc (
  MocAsymKey pMocAsymKey,
  MDsaParams **ppParams,
  struct vlong **ppVlongQueue
  );

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_DSA_HEADER__ */
