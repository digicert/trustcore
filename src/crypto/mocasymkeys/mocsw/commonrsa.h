/*
 * commonrsa.h
 *
 * Functions common to RSA operations.
 *
 * Copyright Mocana Corp 2017. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"

#ifndef __COMMON_RSA_HEADER__
#define __COMMON_RSA_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* This is the pKeyData inside an RsaSw key.
 * When buiding a key from algId, it is possible a digest object will be needed
 * (for OAEP).
 */
typedef struct
{
  MAsymCommonKeyData   common;
  RSAKey              *pKey;
} MRsaSwKeyData;

/* Implements MOC_ASYM_OP_FREE,
 *
 * Free the mocAsymKey->pKeyData.
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwFreeKey (
  MocAsymKey pMocAsymKey,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_GET_SECURITY_SIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwGetSecuritySize (
  MocAsymKey pMocAsymKey,
  ubyte4 *pSecuritySize
  );

/* Implements MOC_ASYM_OP_GENERATE
 *
 * Generate a new key pair, placing them into the objects passed in the
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyPairGenInfo *pInputInfo,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_PUB_FROM_PRI
 *
 * Construct a new public key from the private key.
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_IS_SAME_PUB_KEY
 */
MOC_EXTERN MSTATUS RsaSwIsSamePubKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pDerKey,
  intBoolean *pIsMatch,
  struct vlong **ppVlongQueue
  );

/* Implements keyOpEncrypt or keyOpDecrypt
 *
 * Encrypt the data in pInputInfo, placing the ciphertext into the buffer in
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwEncryptDecrypt (
  keyOperation keyOp,
  MocAsymKey pMocAsymKey,
  MKeyAsymEncryptInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_SIGN_DIGEST_INFO.
 *
 * Sign the data in pInputInfo, placing the signature into the buffer in
 * pOutputInfo.
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwSign (
  MocAsymKey pMocAsymKey,
  MKeyAsymEncryptInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_VERIFY_DIGEST_INFO.
 *
 * Verify the data in pInputInfo, setting *pOutputInfo to the result.
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwVerify (
  MocAsymKey pMocAsymKey,
  MKeyAsymVerifyInfo *pInputInfo,
  ubyte4 *pOutputInfo,
  struct vlong **ppVlongQueue
  );

#define MOC_RSA_BLOB_START_LEN 12
#define MOC_RSA_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x00, 0x00, 0x01

/* Implements MOC_ASYM_OP_SERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwSerializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  );

/* Serialize an RSA key.
 * The function will allocate memory for the data and return the new buffer and
 * its length at the addresses given.
 * This function does not check the args, it is the responsibility of the caller
 * not to make mistakes.
 */
MOC_EXTERN MSTATUS SerializeRsaKeyAlloc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

/* This will build the Mocana version 2 key blob of the given key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using MOC_FREE.
 */
MOC_EXTERN MSTATUS BuildRsaKeyBlobAlloc (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pRsaKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* This will build the PKCS 8 DER encoding of a private key, or the X.509
 * SubjectPubkicKeyInfo of a public key.
 * It will allocate memory for the result. It is the responsibility of the caller
 * to free it using MOC_FREE.
 */
MOC_EXTERN MSTATUS DerEncodeRsaKeyAlloc (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  byteBoolean isPriSer,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/* Implements MOC_ASYM_OP_DESERIALIZE.
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo,
  struct vlong **ppVlongQueue
  );

/* Deserialize an RSA key.
 * The function will build an existing RSAKey.
 */
MOC_EXTERN MSTATUS DeserializeRsaKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  AsymmetricKey *pAsymKey,
  struct vlong **ppVlongQueue
  );

/* Read the given blob and determine if it is for RSA. If so, build the key with
 * the data.
 */
MOC_EXTERN MSTATUS ReadRsaKeyBlob (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  RSAKey **ppRsaKey,
  struct vlong **ppVlongQueue
  );

/* Implements MOC_ASYM_OP_CLONE
 *
 * This function expects the pMocAsymKey->pKeyData to be MRsaSwKeyData.
 */
MOC_EXTERN MSTATUS RsaSwCloneKey (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppNewKey,
  vlong **ppVlongQueue
  );

/* This builds the local data (the pKeyData) if necessary, and  stores the input.
 * Any one or all of the input (new key, algId, digest) can be NULL.
 * This will copy a reference to *ppNewKey, and NULL out *ppNewKey.
 * This will copy a reference to *ppDigestCtx, and NULL out *ppDigestCtx.
 * This means that the mocasym key will take over ownership of the RSAKey, algId,
 * and/or digest ctx. It will destroy them later when the MocAsymKey is destroyed.
 * This will allocate space to copy the algId and memcpy it.
 * This is available to all implementations because sometimes hardware
 * implementations are actually a combination of hardware (private) and software
 * (public).
 */
MOC_EXTERN MSTATUS RsaSwLoadKeyData (
  RSAKey **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocSymCtx *pDigestCtx,
  MocAsymKey pMocAsymKey
  );

/* This builds an algId based on input (as opposed to the latest algId, the one
 * representing the last thing an object did).
 * All implementations of RSA can use this.
 * This is only valid for RSA PKCS 1.5 (no AEP or PSS).
 */
MOC_EXTERN MSTATUS RsaSwReturnAlgId (
  MocAsymKey pMocAsymKey,
  MKeyOperatorAlgIdReturn *pInputInfo,
  MKeyOperatorDataReturn *pOutputInfo
  );

/**
 * Implements MOC_ASYM_OP_GET_KEY_DATA
 * 
 * This function will retrieve the standard key parameters from the underlying
 * key-structure within the MocAsymKey. These parameters will be allocated and
 * loaded into standard, per-algorithm, template structure (in this case, 
 * MRsaKeyTemplate) as byte-strings. Since these byte-string buffers are 
 * allocated on the heap, it is the caller's responsibility to call the 
 * accompanying free-function (in this case, RSA_freeKeyTemplate). 
 */
MOC_EXTERN MSTATUS RsaSwGetKeyDataAlloc (
  MocAsymKey pMocAsymKey,
  MRsaKeyTemplate *pTemplate,
  ubyte keyType
  );

/**
 * Implements MOC_ASYM_OP_FREE_KEY_TEMPLATE
 * 
 * Free the internal byte-string buffers located within the template structure.
 * Template must have been created by the function that makes use of the RSA 
 * Operator's RsaSwGetKeyDataAlloc function.
 */
MOC_EXTERN MSTATUS RsaSwFreeKeyTemplate (
  MocAsymKey pMocAsymKey,
  MRsaKeyTemplate *pTemplate
  );

/**
 * Implements MOC_ASYM_OP_SET_KEY_DATA
 * 
 * This function will fill in a MocAsymKey's appropriate, per-algorithm key
 * parameters using the standard, per-algorithm, template structure (in this
 * case, MRsaKeyTemplate). This template structure must be filled using the 
 * function that makes use of the RSA Operator's RsaSwGetKeyDataAlloc function.
 * If there is no underlying RSAKey within pMocAsymKey, this function will
 * allocate one.
 */
MOC_EXTERN MSTATUS RsaSwSetKeyData (
  MocAsymKey pMocAsymKey,
  MRsaKeyTemplate *pTemplate
  );

/** Create a block of data that is the input data padded following PKCS 1 version
 * 1.5.
 * <p>The padding is different depending on whether the data will be encrypted or
 * signed. Pass in the operation as either MOC_ASYM_KEY_FUNCTION_ENCRYPT or
 * MOC_ASYM_KEY_FUNCTION_SIGN.
 * <p>If encrypting, the function will need to generate random bytes, hence pass
 * in a randomContext.
 * <p>The caller also supplies the output buffer and its size. For example, if
 * the data is to be encrypted using a 2048-bit key, then the output buffer must
 * be 256 bytes big. It is the caller's responsibility to know how big the buffer
 * needs to be.
 * <p>The output buffer MUST be a different buffer. This function will not pad
 * "in place".
 * <p>Note that there is a maximum length of input data to be padded following
 * P1.5 (or think of it, there is a minimum number of pad bytes). So if you have
 * too much data and the buffer is not big enough (the buffer is bigger than the
 * data, but still too small, not enough room for the minimum pad bytes), then
 * the function will return an error.
 *
 * @param pDataToPad The data that is to be encrypted or signed.
 * @param dataToPadLen The length, in bytes, of the input data.
 * @param operation ENCRYPT or SIGN.
 * @param pRandom For padding when the operation is ENCRYPT.
 * @param pPaddedData The output buffer.
 * @param bufferSize The final size of the padded data. This must be the same
 * size as the key (e.g. 2048-bit key means 256-byte buffer). The function will
 * simply fill in the buffer to the bufferSize given.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaPadPkcs15 (
  ubyte *pDataToPad,
  ubyte4 dataToPadLen,
  ubyte4 operation,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pPaddedData,
  ubyte4 bufferSize
  );

/** Unpad following PKCS 1 version 1.5.
 * <p>The caller passes in a block of decrypted data (which could be the
 * decryption of a signature). The function will determine if the padding is
 * correct, and if so, remove it. It will simply move the unpadded data to the
 * beginning of the buffer, and return that length at the address given by
 * pUnpadLen.
 * <p>For example, suppose we have a 256-byte block.
 * <pre>
 * <code>
 *    Input:   00 01  ff ff ff ... ff  00 <data, 41 bytes long>
 *          or 00 01 <212 bytes of ff> 00 <41 bytes of data>
 *
 *    Result:  <data, 41 bytes long> ff ff ... 00 <data, 41 bytes long>
 *          or <41 bytes of data> <173 bytes of ff> 00 <41 bytes of data>
 * </code>
 * </pre>
 * <p>If someone looks at the full buffer, they will see that the last bytes of
 * the data were moved to the front of the buffer, overwriting anything that was
 * there already (the start of the pad). And the original data was not deleted
 * (overwritten) in any way.
 * <p>But this function will not simply move the data, it will also verify that
 * the pad is valid. If the function is unpadding a signature, and if the pad is
 * valid, the function will set *pPadCheck to 0 (no failures). If the pad is
 * invalid, it will set it to one or more MOC_ASYM_VFY_FAIL_ bits defined in
 * mss/src/crypto/mocasym.h. If this is unpadding for encryption, it will set
 * *pPadCheck to 0 for no errors, and nonzero for error.
 * <p>NOTE!! The function will set the padCheck value if the pad is incorrect. It
 * will not return an error. So even if the return from this function is OK, it
 * is possible the pad is incorrect. This function unpads and checks the pad. If
 * it can unpad and check the pad, it has successfully completed the operation.
 * <p>The caller must also specify the operation (MOC_ASYM_KEY_FUNCTION_ENCRYPT
 * or MOC_ASYM_KEY_FUNCTION_SIGN). The padding is different based on the
 * operation, so to verify it is valid requires knowing what it is supposed to be.
 * <p>If the padding is incorrect, the function might return an error. However,
 * if the the function is able to unpad, even if the pad is incorrect, and move
 * the data to the beginning, returning a data length, it will do so and return
 * OK. So check pUnpadLen and pPadCheck upon return as well as the function's
 * return value. Some applications might want to report both the unpadded data
 * and the error.
 *
 * @param operation ENCRYPT or SIGN.
 * @param pDataToUnpad A block of decrypted data.
 * @param dataLen The length, in bytes, of the block. This should be the key size.
 * @param pUnpadLen The address where the function will deposit the length, in
 * bytes, of the unpadded data.
 * @param pPadCheck The address where the function will deposit the result of the
 * padding checks. It will set the value to 0 if there are no verification
 * failures.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaUnpadPkcs15 (
  ubyte4 operation,
  ubyte *pDataToUnpad,
  ubyte4 dataLen,
  ubyte4 *pUnpadLen,
  ubyte4 *pPadCheck
  );

/** Create a block of data that is the input data padded following PKCS 1 version
 * 2.0 PSS (this is Bellare and Rogaway's EMSA-PSS).
 * <p>The caller passes in the bufferSize and the keyLenBits. Although the
 * keyLenBits is probably always going to be 8 * bufferSize, it is possible the
 * bit length is not exactly 8 * bufferSize.
 * <p>PSS uses random bytes, so you must pass in a randomContext.
 * <p>The caller also supplies the output buffer and its size. For example, if
 * the data is to be signed using a 2048-bit key, then the output buffer must
 * be 256 bytes big. It is the caller's responsibility to know how big the buffer
 * needs to be.
 * <p>The output buffer MUST be a different buffer. This function will not pad
 * "in place".
 * <p>Note that there is a maximum length of input data to be padded following
 * PSS (or think of it, there is a minimum number of pad bytes). So if you have
 * too much data and the buffer is not big enough (the buffer is bigger than the
 * data, but still too small, not enough room for the minimum pad bytes), then
 * the function will return an error.
 * <p>PSS digests data, so you need to pass in an object built to perform the
 * digest algorithm requested. Pass in the digestLen as well. The function will
 * not check these args, it will simply use whatever is given.
 * <p>The Mask Generating Function (MGF) also uses a digest object. If it is a
 * different algorithm than the main OAEP digester, then the caller supplies
 * another object. If it is the same algorithm, pass NULL and the function will
 * use the other one passed in.
 *
 * @param rngFun RNG used to generate random bytes.
 * @param rngFunArg RNG argument.
 * @param M Message to encode.
 * @param mLen Length of the message to encode in bytes.
 * @param emBits 1 less then the bit length of the RSA key.
 * @param sLen Size of the salt to use.
 * @param Halgo Hash algorithm to use for input data digestion.
 * @param mgfHalgo Hash algorithm to use for MGF1. 
 * @param hLen Output length of the hash algorithm \c Halgo.
 * @param MGF Mask generation function.
 * @param ppRetEM Encoded message is stored here. Caller must free this memory.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaPadPss(
  MOC_HASH(hwAccelDescr hwAccelCtx)
  RNGFun rngFun,
  void *rngFunArg,
  const ubyte *M,
  ubyte4 mLen,
  ubyte4 emBits,
  ubyte4 sLen,
  BulkHashAlgo *Halgo,
  BulkHashAlgo *mgfHalgo,
  ubyte4 hLen,
  ubyte MGF,
  ubyte** ppRetEM
  );

/** Create a block of data that is the input data padded following PKCS 1 version
 * 2.0 PSS (this is Bellare and Rogaway's EMSA-PSS). Unlike \c RsaPadPss this 
 * method expects the initial digest of the message and not the entire message.
 * <p>The caller passes in the bufferSize and the keyLenBits. Although the
 * keyLenBits is probably always going to be 8 * bufferSize, it is possible the
 * bit length is not exactly 8 * bufferSize.
 * <p>PSS uses random bytes, so you must pass in a randomContext.
 * <p>The caller also supplies the output buffer and its size. For example, if
 * the data is to be signed using a 2048-bit key, then the output buffer must
 * be 256 bytes big. It is the caller's responsibility to know how big the buffer
 * needs to be.
 * <p>The output buffer MUST be a different buffer. This function will not pad
 * "in place".
 * <p>Note that there is a maximum length of input data to be padded following
 * PSS (or think of it, there is a minimum number of pad bytes). So if you have
 * too much data and the buffer is not big enough (the buffer is bigger than the
 * data, but still too small, not enough room for the minimum pad bytes), then
 * the function will return an error.
 * <p>PSS digests data, so you need to pass in an object built to perform the
 * digest algorithm requested. Pass in the digestLen as well. The function will
 * not check these args, it will simply use whatever is given.
 * <p>The Mask Generating Function (MGF) also uses a digest object. If it is a
 * different algorithm than the main OAEP digester, then the caller supplies
 * another object. If it is the same algorithm, pass NULL and the function will
 * use the other one passed in.
 *
 * @param rngFun RNG used to generate random bytes.
 * @param rngFunArg RNG argument.
 * @param pDigest Message digest to encode.
 * @param hLen Output length of the hash algorithm.
 * @param emBits 1 less then the bit length of the RSA key.
 * @param sLen Size of the salt to use.
 * @param Halgo Hash algorithm to use for data digestion.
 * @param mgfHalgo Hash algorith to use with MGF1.
 * @param MGF Mask generation function.
 * @param ppRetEM Encoded message is stored here. Caller must free this memory.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaPadPssDigest(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    RNGFun rngFun,
    void *rngFunArg,
    const ubyte *pDigest,
    ubyte4 hLen,
    ubyte4 emBits,
    ubyte4 sLen,
    BulkHashAlgo *Halgo,
    BulkHashAlgo *mgfHalgo,
    ubyte MGF,
    ubyte **ppRetEM
    );

/** Verify the padding following PKCS 1 version 2.0 PSS. This method takes in
 * the initial digest of the message and not the message itself.
 * <p>With PSS, the "unpad" operation is not actually an unpadding. The data in
 * the PSS padded block does not contain the actual decrypted digest (as in PKCS
 * 1.5). It contains a salt and H value. The H value is the hash of eight 00
 * bytes, the digest of the data to sign, and the salt. To verify the PSS pad,
 * find the salt, then compute the hash of the three values, and compare to the H
 * value in the signature.
 * <p>The caller passes in a block of decrypted data. The function will determine
 * if the padding is correct. It will not return any data.
 * <p>The caller passes in the dataLen and the keyLenBits. Although the
 * keyLenBits is probably always going to be 8 * dataLen, it is possible the bit
 * length is not exactly 8 * dataLen.
 * <p>The function will verify that the pad is valid. If the pad is valid, the
 * function will set *pPadCheck to 0 (no failures). If the pad is invalid, it
 * will set it to one or more MOC_ASYM_VFY_FAIL_ bits defined in
 * mss/src/crypto/mocasym.h.
 * <p>NOTE!! The function will set the padCheck value if the pad is incorrect. It
 * will not return an error. So even if the return from this function is OK, it
 * is possible the pad is incorrect. This function unpads and checks the pad. If
 * it can unpad and check the pad, it has successfully completed the operation.
 * <p>PSS digests data, so you need to pass in an object built to perform the
 * digest algorithm requested. Pass in the digestLen as well. The function will
 * not check these args, it will simply use whatever is given.
 * <p>The Mask Generating Function (MGF) also uses a digest object. If it is a
 * different algorithm than the main OAEP digester, then the caller supplies
 * another object. If it is the same algorithm, pass NULL and the function will
 * use the other one passed in.
 * <p>If the padding is incorrect, the function might return an error. However,
 * if the the function is able to unpad, even if the pad is incorrect, it will do
 * so and return OK. So check pPadCheck upon return as well as the function's
 * return value. Some applications might want to report both the unpadded data
 * and the error.
 *
 * @param pDigest Message digest to encode.
 * @param hLen Output length of the hash algorithm.
 * @param EM The result of decrypting the signature.
 * @param emBits 1 less then the bit length of the RSA key.
 * @param sLen Size of the salt used. -1 will indicate the
 *             method to compute the saltLen rather than validate it.
 * @param Halgo Hash algorithm to use for data digestion.
 * @param mgfHalgo Hash algorith to use with MGF1.
 * @param MGF Mask generation function.
 * @param pIsConsistent Will be set to \c TRUE for a valid signature
 *                      and \c FALSE otherwise.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaPadPssVerifyDigest(
  MOC_HASH(hwAccelDescr hwAccelCtx) 
  const ubyte *pDigest,
  ubyte4 hLen,
  ubyte *EM,
  ubyte4 emBits,
  sbyte4 sLen,
  BulkHashAlgo *Halgo,
  BulkHashAlgo *mgfHalgo,
  ubyte MGF,
  intBoolean *pIsConsistent);

/** Perform Mask Generating Function 1 for OAEP and PSS.
 * <p>The caller supplies a digest object and the digest length (just as a
 * convenience so the function does not need to compute it).
 * <p>The function will perform MGF1 on the seed data, producing maskLen bytes,
 * placed into a new buffer located at ppRetMask.
 *
 * @param mgfSeed MGF seed used to build the mask
 * @param mgfSeedLen MGF seed length
 * @param maskLen Size of mask to generate.
 * @param H Digest used to build the mask.
 * @param ppRetMask Return mask.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MaskGenFunction1(
  MOC_HASH(hwAccelDescr hwAccelCtx)
  const ubyte *mgfSeed,
  ubyte4 mgfSeedLen,
  ubyte4 maskLen,
  BulkHashAlgo *H,
  ubyte **ppRetMask
  );

/** Perform Mask Generation using SHAKE for RSA PSS.
 * <p> The digest passed in needs to have the finalXOF function defined, ie
 * be from a SHAKE128 or SHAKE256 hash suite.
 * <p>The function produces maskLen bytes,
 * placed into a new buffer located at ppRetMask.
 *
 * @param mgfSeed MGF seed used to build the mask
 * @param mgfSeedLen MGF seed length
 * @param maskLen Size of mask to generate.
 * @param H Digest used to build the mask.
 * @param ppRetMask Return mask.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MaskGenFunctionShake(
  MOC_HASH(hwAccelDescr hwAccelCtx)
  const ubyte *mgfSeed,
  ubyte4 mgfSeedLen,
  ubyte4 maskLen,
  BulkHashAlgo *H,
  ubyte **ppRetMask
  );

/** Perform a raw RSA public key operation
 * <p>For RSA public key operations, after padding (encryption), or before
 * unpadding (signature verification), perform raw RSA (a modExp). This is that
 * function.
 * <p>This function will take the dataLen bytes as is and perform RSA. The
 * dataLen must be the same size as the key. This argument is there as a check
 * against data that does not match the key.
 * <p>The function will perform the raw RSA and place the result into the same
 * buffer. That is, this operates "in place"
 *
 * @param pRsaKey The key to use.
 * @param pDataToProcess One block of data.
 * @param dataLen The length, in bytes, of the data to process. It must be the
 * same as the key length (security size of the key in bytes). For example, with
 * a 2048-bit key, the dataLen must be 256 bytes, no more, no less.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaRawPublic (
  RSAKey *pRsaKey,
  ubyte *pDataToProcess,
  ubyte4 dataLen,
  struct vlong **ppVlongQueue
  );

/** Perform a raw RSA private key operation
 * <p>For RSA private key operations, after padding (signing), or before
 * unpadding (decryption), perform raw RSA (a modExp CRT). This is that
 * function.
 * <p>This function will take the dataLen bytes as is and perform RSA using the
 * Chinese Remainder Theorem (CRT). The dataLen must be the same size as the key.
 * This argument is there as a check against data that does not match the key.
 * <p>The function will perform the raw RSA and place the result into the same
 * buffer. That is, this operates "in place"
 *
 * @param pRsaKey The key to use.
 * @param pDataToProcess One block of data.
 * @param dataLen The length, in bytes, of the data to process. It must be the
 * same as the key length (security size of the key in bytes). For example, with
 * a 2048-bit key, the dataLen must be 256 bytes, no more, no less.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RsaRawPrivate (
  RSAKey *pRsaKey,
  ubyte *pDataToProcess,
  ubyte4 dataLen,
  struct vlong **ppVlongQueue
  );

/** Build the algorithm identifier for RSA. This will work for RSA Encryption and
 * Signing. Note that the algorithm identifiers are defined in PKCS #1, which was
 * made into an RFC 3447 and 8017.
 * <p>The AlgIds for RSA-OAEP and RSA-PSS can get very complicated. Hence, we
 * have this special function to handle it. Both of those algIds call for a mask
 * generating function, but only one has ever been defined, and there will likely
 * never be another one.
 * <p>The caller passes in a flag indicating which variant of RSA is to be
 * encoded. The values are one of the MOC_RSA_VARIANT_ flags defined in
 * parseasn1.h.
 * <p>If the variant is PKCS 1 version 1.5 encrypting (MOC_RSA_VARIANT_P1_5_ENC),
 * then there is no need for digestAlg, pDigestObj, pMgfDigestObj, label,
 * saltLen, or trailerField. The function will ignore those arguments.
 * <p>If the variant is PKCS 1 version 1.5 signing (MOC_RSA_VARIANT_P1_5_SIGN),
 * you need to specify the digestAlg (the algorithm used to digest the data to
 * sign), but there is no need for pDigestObj, pMgfDigestObj, label, saltLen, or
 * trailerField. The function will ignore those arguments.
 * <p>If the variant is OAEP, then there is no need for saltLen or trailerField.
 * The function will ignore those arguments. The caller passes in the pDigestObj
 * and pMgfDigestObj. The MgfDigestObj is used by the Mask Generating Function as
 * part of its operations. It can be NULL if the digest algorithm used by the MGF
 * is the same as the one used to perfrom OAEP operations. The default is SHA-1.
 * If the digest is not SHA-1, the function will call on the pDigestObj and (if
 * not NULL) the pMgfDigestObj to get the algId(s) of the digest(s) for the
 * params. The label can be empty, in which case, pass in NULL. Note that the
 * default label defined in the RFCs is empty and most uses of RSA-OAEP use an
 * empty label.
 * <p>If the variant is for PSS, then there is no need for the digestAlg and
 * label. The function will ignore those arguments. The caller passes in the
 * pDigestObj and pMgfDigestObj. The pMgfDigestObj is used by the Mask Generating
 * Function as part of its operations. It can be NULL if the digest algorithm
 * used by the MGF is the same as the one used to perfrom PSS operations. The
 * default is SHA-1. If the digest is not SHA-1, the function will call on the
 * pDigestObj and (if not NULL) the pMgfDigestObj to get the algId(s) of the
 * digest(s) for the params. Note that the PSS digest algorithm must be the same
 * one used to digest the actual data to sign. The saltLen should either be the
 * default value (20, or MOC_RSA_PSS_DEFAULT_SALT_LEN), or the length of the
 * digest algorithm. The trailerField is an 8-bit number. The default is 0xBC or
 * MOC_RSA_PSS_DEFAULT_TRAILER_FIELD. Currently the only trailerField supported
 * is the default (0xBC). In IEEE 1363 there is an alternate trailer field, but
 * the RFCs do not support it yet, so this function does not support it. This
 * argument is here in case standards allow for more values.
 * <p>The function will allocate memory for the algId and return a pointer to
 * that memory at the address given by ppAlgId. The caller must free that memory
 * using MOC_FREE.
 * <p>NOTE! This function does not check the input args, it is the responsibility
 * of the caller not to make mistakes.
 *
 * @param rsaVariant One of the MOC_RSA_VARIANT flags.
 * @param digestAlg For P1.5 signing, one of the ht_ values, it is the algorithm
 * used to digest the data to sign.
 * @param pDigestObj Used for OAEP and PSS. It is the object used to perform the
 * OAEP digest operations. The function will get the digest algId from this
 * object.
 * @param pMgfDigestObj Used for OAEP and PSS. It is the object the Mask
 * Generating Function uses. If it is NULL, then the digest algorithm used by the
 * MGF is the same one used by the OAEP functions.
 * @param pLabel For OAEP, it can be NULL for the default empty label.
 * @param labelLen The length, in bytes, of the label.
 * @param saltLen For PSS, the length of the salt, the default is 20.
 * @param trailerField For PSS, an 8-bit value, the default is 0xBC.
 * @param ppAlgId The address where the function will deposit the allocated
 * memory holding the algId.
 * @param pAlgIdLen The address where the function will deposit the length, in
 * bytes, of the algId.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_rsaBuildAlgIdAlloc (
  ubyte4 rsaVariant,
  ubyte4 digestAlg,
  MocSymCtx pDigestObj,
  ubyte4 mgfDigestAlg,
  MocSymCtx pMgfDigestObj,
  ubyte *pLabel,
  ubyte4 labelLen,
  ubyte4 saltLen,
  ubyte4 trailerField,
  ubyte **ppAlgId,
  ubyte4 *pAlgIdLen
  );

/** Parse the AlgId for RSA, returning the details at the addresses given. See
 * also the comments for RsaBuildAlgIdAlloc for more information on the variants
 * and algorithm identifiers.
 * <p>If the algId is for RSA PKCS 1 version 1.5 encrypting, the function will
 * set *pRsaVariant to MOC_RSA_VARIANT_P1_5_ENC. It will set all the other args
 * to 0/NULL or default values.
 * <p>If the algId is for RSA PKCS 1 version 1.5 signing, the function will set
 * *pRsaVariant to MOC_RSA_VARIANT_P1_5_SIGN and *pDigestAlg to the ht_ value of
 * the algorithm used to digest the data to sign. It will set all the other args
 * to 0/NULL.
 * <p>If the algId is for RSA OAEP, the function will set *pRsaVariant to
 * MOC_RSA_VARIANT_OAEP, *pDigestAlg to the ht_ value of the algorithm used in
 * generating the OAEP values, *pMgfDigestAlg to the ht_value of the digest
 * algorithm used by MGF1, and *ppLabel to the address inside the algId where
 * the label begins. This can be NULL if there is no label (the default empty
 * label). Note that this does not allocate memory for the label, it simply
 * returns a pointer to the label inside the algId. The *pSaltLen and
 * *pTrailerField will be set to 0.
 * <p>If the algId is for RSA PSS, the function will set *pRsaVariant to
 * MOC_RSA_VARIANT_PSS, *pDigestAlg to the ht_value of the algorithm used to
 * digest the data to sign as well as generating the PSS values, *pMgfDigestAlg
 * to the ht_value of the digest algorithm used by MGF1 *pSaltLen to the salt
 * length length, and *pTrailerField to the trailer field. The label and length
 * will be set to NULL/0.
 * <p>NOTE! This function does not check the input args, it is the responsibility
 * of the caller not to make mistakes.
 *
 * @param pAlgId The algId to read.
 * @param algIdLen The length, in bytes, of the algId.
 * @param pRsaVariant The address where the function will deposit the
 * MOC_RSA_VARIANT_ flag.
 * @param pDigestAlg The address where the function will deposit the ht_ value of
 * the digest algorithm.
 * @param pMgfDigestAlg The address where the function will deposit the ht_ value
 * of the digest algorithm used by MGF1.
 * @param ppLabel The address where the function will deposit the pointer to the
 * place inside pAlgId where the label begins. This can be NULL if the algId
 * specifies the default empty label.
 * @param pLabelLen The address where the function will deposit the length, in
 * bytes, of the label.
 * @param pSaltLen The address where the function will deposit the salt length.
 * @param pTrailerField The address where the function will deposit the trailer
 * field.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_rsaReadAlgId (
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 *pRsaVariant,
  ubyte4 *pDigestAlg,
  ubyte4 *pMgfDigestAlg,
  ubyte **ppLabel,
  ubyte4 *pLabelLen,
  ubyte4 *pSaltLen,
  ubyte4 *pTrailerField
  );

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_RSA_HEADER__ */
