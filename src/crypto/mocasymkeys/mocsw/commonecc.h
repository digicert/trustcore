/*
 * commonecc.h
 *
 * Functions common to ECC operations.
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

#ifndef __COMMON_ECC_HEADER__
#define __COMMON_ECC_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* This is the pKeyData inside an EccSw key.
 */
typedef struct
{
  MAsymCommonKeyData   common;
  struct ECCKey       *pKey;
  StandardParams       ParamsCall;
  ubyte4               securitySize;
} MEccSwKeyData;

/* Implements MOC_ASYM_OP_CREATE, MOC_ASYM_OP_CREATE_PUB, MOC_ASYM_OP_CREATE_PRI.
 *
 * This function builds an MEccSwKeyData struct for the pMocAsymKey->pKeyData.
 */
MOC_EXTERN MSTATUS EccSwCreateKey (
  MocAsymKey pMocAsymKey,
  MKeyOperator KeyOperator,
  StandardParams Params,
  ubyte4 keyType
  );

/* Implements MOC_ASYM_OP_FREE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwFreeKey (
  MocAsymKey pMocAsymKey,
  struct vlong **ppVlongQueue
  );

/* This builds the local data (the pKeyData) if necessary, and  stores the input.
 * Any one or all of the input (new key, algId, ParamsCall) can be NULL.
 * This will copy a reference to *ppNewKey, and NULL out *ppNewKey.
 * This means that the mocasym key will take over ownership of the ECCKey. It will
 * destroy them later when the MocAsymKey is destroyed.
 * This will allocate space to copy the algId and memcpy it.
 */
MOC_EXTERN MSTATUS EccSwLoadKeyData (
  struct ECCKey **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  StandardParams ParamsCall,
  MocAsymKey pMocAsymKey,
  vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_SET_KEY_DATA.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwSetKeyData (
  MocAsymKey pMocAsymKey,
  MEccKeyTemplate *pTemplate,
  StandardParams Params
  );

/* Implements MOC_ASYM_OP_GET_KEY_DATA.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwGetKeyDataAlloc (
  MocAsymKey pMocAsymKey,
  MEccKeyTemplate *pTemplate,
  ubyte reqType
  );

/* Implements MOC_ASYM_OP_FREE_KEY_TEMPLATE. */
MOC_EXTERN MSTATUS EccSwFreeKeyTemplate (
  MocAsymKey pMocAsymKey,
  MEccKeyTemplate *pTemplate
  );

/* Implements MOC_ASYM_OP_PUB_FROM_PRI
 *
 * Construct a new public key from the private key.
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_IS_SAME_PUB_KEY
 */
MOC_EXTERN MSTATUS EccSwIsSamePubKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pDerKey,
  intBoolean *pIsMatch,
  struct vlong **ppVlongQueue
  );

#define MOC_ECC_BLOB_START_LEN 12
#define MOC_ECC_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x00, 0x00, 0x02

/* Serialize an ECC key.
 * The function will allocate memory for the data and return the new buffer and
 * its length at the addresses given.
 * The caller also supplies the curve (as StandardParams, e.g.
 * EccParamsNistP224r1).
 * This function does not check the args, it is the responsibility of the caller
 * not to make mistakes.
 */
MOC_EXTERN MSTATUS SerializeEccKeyAlloc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  StandardParams Params,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );


/* Deserialize an ECC key that's in PKCS8 or X509 form.
 * The function will load an existing key.
 * ERR_EC_DIFFERENT_SERIALIZATION is returned if this
 * method doesn't recognize the type of serialization.
 * In which case DeserializeEccKeyAlt() should be called.
 *
 * NOTE: ppPriv and ppPub are not allocated but will have
 * their addresses set with pointers to the private key
 * and public key within pSerialized key. Do not free
 * ppPriv and ppPub.
 */
MOC_EXTERN MSTATUS DeserializeEccKeyPKCS8X509 (
  StandardParams Params,
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPriv,
  ubyte4 *pPrivLen,
  ubyte **ppPub,
  ubyte4 *pPubLen,
  MAlgoId **ppAlgoId
  );

/* Deserialize an Edward's form ECC key that's in PKCS8 form.
 * The function will load an existing key.
 *
 * NOTE: ppPriv and ppPub are not allocated but will have
 * their addresses set with pointers to the private key
 * and public key within pSerialized key. Do not free
 * ppPriv and ppPub.
 */
MOC_EXTERN MSTATUS DeserializeEccEdKeyPKCS8 (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPriv,
  ubyte4 *pPrivLen,
  ubyte **ppPub,
  ubyte4 *pPubLen
  );
  
/*
 * Deserializes a public key in a compressed form
 * 0x04 (x coord in Big Endian binary) (y coord in Big Endian binary)
 *
 * NOTE: ppPub is not allocated but will have
 * its value set with a pointer to the public key
 * within pSerialized key. Do not free ppPub.
 */
MOC_EXTERN MSTATUS DeserializeEccKeyAlt (
  StandardParams Params,
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPub,
  ubyte4 *pPubLen
  );

/* This will build the Mocana version 2 key blob of the given key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using DIGI_FREE.
 */
MOC_EXTERN MSTATUS BuildEccKeyBlobAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  struct ECCKey *pEccKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* This will build the PKCS 8 DER encoding of a private key, or the X.509
 * SubjectPubkicKeyInfo of a public key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using DIGI_FREE.
 */
MOC_EXTERN MSTATUS DerEncodeEccKeyAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  struct ECCKey *pEccKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );
  
/* This will build the PKCS 8 DER encoding of a private key, or the X.509
 * SubjectPubkicKeyInfo of a public key for an Edward's curve EdDSA key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using DIGI_FREE.
 */
MOC_EXTERN MSTATUS DerEncodeEccEdKeyAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pEccKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* Given the curve Oid (not counting the first two bytes,
 * ie 0x06 and len, get the curve's Id */
MOC_EXTERN MSTATUS GetCurveId (
  ubyte *pOid,
  ubyte4 oidLen,
  ubyte4 *pCurveId
  );

/* Given a curveId, return the OID for that curve.
 * The caller supplies a buffer into which the function will place the OID.
 * See mss/src/asn1/parseasn1.h for a MAX Curve OID len.
 * NOTE!!! This function does not check the args, it is the responsibility of the
 * caller not to make mistakes.
 */
MOC_EXTERN MSTATUS GetCurveOid (
  ubyte4 curveId,
  ubyte *pOidBuf,
  ubyte4 bufferSize,
  ubyte4 *pOidLen
  );

/* Read the given blob and determine if it is an ECC key and for which curve.
 *
 * NOTE: ppPriv and ppPub are not allocated but will have
 * their addresses set with pointers to the private key
 * and public key within pSerialized key. Do not free
 * ppPriv and ppPub.
 */
MOC_EXTERN MSTATUS ReadEccKeyBlob (
  StandardParams Params,
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPriv,
  ubyte4 *pPrivLen,
  ubyte **ppPub,
  ubyte4 *pPubLen
  );

/* Implements MOC_ASYM_OP_GET_ALG_ID.
 */
MOC_EXTERN MSTATUS EccSwReturnAlgId (
  MocAsymKey pMocAsymKey,
  MKeyOperatorAlgIdReturn *pInputInfo,
  MKeyOperatorDataReturn *pOutputInfo
  );

/* Implements MOC_ASYM_OP_SERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwSerializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  );

/* Implements MOC_ASYM_OP_DESERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwDeserializeKey (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_CLONE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwCloneKey (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppNewKey,
  vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GET_PARAMS.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwReturnParamsAlloc (
  MocAsymKey pMocAsymKey,
  MEccParams **ppParams,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GET_PUB_VALUE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwReturnPubValAlloc (
  MocAsymKey pMocAsymKey,
  MKeyOperatorDataReturn *pPubVal,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GENERATE.
 *
 * Generate a new key pair, placing them into the objects passed in the
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyOperator KeyOperator,
  StandardParams Params,
  MRandomGenInfo *pRandom,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Impelements MOC_ASYM_OP_SIGN_DIGEST
 *
 * Sign the data in pInputInfo, placing the signature into the buffer in
 * pOutputInfo.
 *
 * This function expects a raw digest to be located within pInputInfo, not a
 * DigestInfo.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwSignDigest (
  MocAsymKey pMocAsymKey,
  MKeyAsymSignInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_SIGN_DIGEST_INFO.
 *
 * Sign the data in pInputInfo, placing the signature into the buffer in
 * pOutputInfo.
 *
 * This function expects a DigestInfo to be located within pInputInfo, not a
 * raw digest.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwSignDigestInfo (
  MocAsymKey pMocAsymKey,
  MKeyAsymSignInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_VERIFY_DIGEST
 *
 * Verify the data in pInputInfo, setting *pOutputInfo to the result.
 *
 * This function expects a raw digest to be located within pInputInfo, not a
 * DigestInfo.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwVerifyDigest (
  MocAsymKey pMocAsymKey,
  MKeyAsymVerifyInfo *pInputInfo,
  ubyte4 *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_VERIFY_DIGEST_INFO.
 *
 * Verify the data in pInputInfo, setting *pOutputInfo to the result.
 *
 * This function expects a DigestInfo to be located within pInputInfo, not a
 * raw digest.
 *
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwVerifyDigestInfo (
  MocAsymKey pMocAsymKey,
  MKeyAsymVerifyInfo *pInputInfo,
  ubyte4 *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_COMPUTE_SHARED_SECRET.
 *
 * Use other party pub and this party pri to compute an ECDH shared secret.
 * This function expects the pMocAsymKey->pKeyData to be MEccSwKeyData.
 */
MOC_EXTERN MSTATUS EccSwComputeSharedSecret (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pPubVal,
  MKeyOperatorBuffer *pSharedSecret,
  struct vlong **ppVlongQueue
  );

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_ECC_HEADER__ */
