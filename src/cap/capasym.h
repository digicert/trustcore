/*
 * capasym.h
 *
 * Cryptographic Abstraction Platform (CAP) Asymmetric algorithm declarations.
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

#include "../cap/capsym.h"

/**
@file       capasym.h
@brief      Cryptographic Abstraction Platform (CAP) Asymmetric algorithm declarations.
@details    Add details here.

@filedoc    capasym.h
*/
#ifndef __CAP_ASYMMETRIC_HEADER__
#define __CAP_ASYMMETRIC_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_NANOCAP
#define MOC_EXTERN_CAPASYM_H __declspec(dllexport)
#else
#define MOC_EXTERN_CAPASYM_H __declspec(dllimport) extern
#endif /* WIN_EXPORT_NANOCAP */

#ifdef WIN_STATIC
#undef MOC_EXTERN_CAPASYM_H
#define MOC_EXTERN_CAPASYM_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_CAPASYM_H extern

#endif /* __RTOS_WIN32__ */

typedef ubyte4 keyOperation;

/* Use this keyOperation to indicate that the Operator function should build
 * itself. The Operator will be given an empty MocAsymKey. The Create will fill
 * in as much of that object as possible.
 * <pre>
 * <code>
 * pInputInfo is void *, the pOperatorInfo passed during the call to
 *                       CRYPTO_createMocAsymKey.
 * pOutputInfo is NULL,  there is nothing to output, the create builds
 *                       the key.
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_CREATE                 (MOC_ASYM_OP_CODE+1)

/* It's possible that the caller knows that the key to be created will be a
 * public key. It's also possible that there are differences between a public
 * and private key, so it might be built differently (e.g. a hardware key is
 * really a hardware privat key and a software public key).
 * <p>The info is the same as MOC_ASYM_OP_CREATE.
 */
#define MOC_ASYM_OP_CREATE_PUB             (MOC_ASYM_OP_CODE+2)

/* It's possible that the caller knows that the key to be created will be a
 * private key. It's also possible that there are differences between a public
 * and private key, so it might be built differently (e.g. a hardware key is
 * really a hardware private key and a software public key).
 * <p>The info is the same as MOC_ASYM_OP_CREATE.
 */
#define MOC_ASYM_OP_CREATE_PRI             (MOC_ASYM_OP_CODE+3)

/* Use this keyOperation to indicate that the Operator function should free the
 * key data. The Operator should free any memory allocated (and release any
 * other resource acquired) during the construction of the actual key data that
 * resides at mocAsymKey->keyData.
 * <p>Someone will call CRYPTO_freeMocAsymKey, which will call on the Operator to
 * free the key data, and the freeMocAsymKey call will free any memory allocated
 * for the MocAsymKey struct itself.
 * <p>With this keyOp, there will be no input or output info (both will be
 * NULL). The free will operate on the actual MocAsymKey passed in.
 * <pre>
 * <code>
 *   inputInfo   NULL
 *   outputInfo  NULL
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_FREE                   (MOC_ASYM_OP_CODE+4)

/* Use this keyOperation to indicate that the Operator function should generate
 * a key pair.
 * <p>The inputInfo will be a pointer to an MKeyPairGenInfo struct containing
 * the Operator info and a MRandomGenInfo struct containing a function pointer
 * used to generate random bytes and the argument to that function.
 * <p>The outputInfo will be a pointer to an MKeyPairGenResult struct
 * containing two addresses. The Operator is to build two MocAsymKey objects
 * containing the new key data, then deposit the two new keys at those
 * addresses.
 * <p>The first argument to an Operator is a MocAsymKey. However, for this call,
 * that argument will be NULL. There are two MocAsymKeys, and they are in the
 * outputInfo.
 */
#define MOC_ASYM_OP_GENERATE               (MOC_ASYM_OP_CODE+5)

/* Use this key operation to indicate that the Operator function should return
 * the security size.
 * <p>For RSA, DSA, and Diffie-Hellman (DH), this is the modulus length in
 * bits. For ECC, it is the equivalent security size. The following table
 * indicates the actual sizes given the supported security sizes.
 * <pre>
 * <code>
 *    security  |  RSA modulus |  DSA sizes  |  ECC prime  | DH prime
 *      size    |     size     |             |    size     |   size
 *  ------------|--------------|-------------|-------------|----------
 *       1024   |     1024     |  1024/160   |  160 or 192 |   1024
 *       2048   |     2048     |  2048/224   |  224        |   2048
 *       3072   |     3072     |  3072/256   |  256        |   3072
 *       7680   |     7680     |  7680/384   |  384        |   7680
 *      15,360  |    15,360    | 15,360/512  |  512 or 521 |  15,360
 * </code>
 * </pre>
 * <p>This is generally invoked after someone loads a key (deserialize). The
 * caller will pass in a pointer to a ubyte4 as the output data, the
 * implementation will deposit at the address the security size.
 * <pre>
 * <code>
 *   inputInfo   NULL (the key itself is the input)
 *   outputInfo  ubyte4 *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_GET_SECURITY_SIZE      (MOC_ASYM_OP_CODE+6)

/* Use this key operation to indicate that the Operator function should return
 * a reference to the local key.
 * <p>See the comments for CRYPTO_getLocalKeyReference for more information on
 * the local key.
 * <p>The caller will pass in the outputInfo as a void *, but it will really be
 * a void **. The Operator will go to the address given and deposit a pointer,
 * cast to void *. The pointer is the local key.
 * <pre>
 * <code>
 *   inputInfo   NULL (the key itself is the input)
 *   outputInfo  void **
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_GET_LOCAL_KEY          (MOC_ASYM_OP_CODE+7)

/* Use this key operation to indicate that the Operator function should
 * serialize the key. The Operator must be able to serialize as either a blob
 * or the DER encoding. The Operator must allocate memory for the data and
 * return the buffer and length in the outputArg, which will
 * be a pointer to an MKeyOperatorDataReturn.
 * <p>The inputInfo will be a pointer to a serializedKeyFormat, indicating into
 * which format the key is to be serialized. The Operator must implement
 * serialization for mocanaBlobVersion2, publicKeyInfoDer, and
 * privateKeyInfoDer. It is not necessary to implement PEM formats, the calling
 * routine will call on the Operator to DER encode the key, then it will
 * perform the Base64 encoding and apply the header and footer.
 * <p>The outputInfo is a pointer to a MKeyOperatorDataReturn struct. The
 * application will have called a makeKeyBlob function (there are several) or
 * or CRYPTO_serializeKey. The caller will provide addresses where the function
 * should deposit the buffer it allocates and the length. The Mocana code will
 * call the KeyOperator with those addresses inside the MKeyOperatorDataReturn
 * struct.
 * <p>The Operator must use DIGI_MALLOC to allocate the returned data.
 * <pre>
 * <code>
 *   inputInfo   serializedKeyFormat *
 *   outputInfo  MKeyOperatorDataReturn *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_SERIALIZE              (MOC_ASYM_OP_CODE+8)

/* Use this key operation to indicate that the Operator function should set a
 * key object using serialized key data. The input is either a key blob or the
 * DER encoding of SubjectPublicKeyInfo or PrivateKeyInfo, the Operator must
 * parse it and set the key object.
 * <p>The calling function will have checked the key object to set, and if it
 * is a MocAsymKey, it will call the Operator with the data. The Operator will
 * convert the data into the appropriate format, storing it at the
 * key.mocAsymKey field.
 * <p>The inputInfo is a pointer to an MKeyOperatorData struct that contains
 * the blob and its length. The outputInfo is NULL. In essence, the output is
 * the actual MocAsymKey object being set.
 * <p>This is generally invoked when someone calls KEYBLOB_extractKeyBlobEx or
 * CRYPTO_deserializeKey.
 * <pre>
 * <code>
 *   inputInfo   MKeyOperatorData *
 *   outputInfo  NULL
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_DESERIALIZE            (MOC_ASYM_OP_CODE+9)

/* Use this key operation to indicate that the Operator function should clone
 * the key.
 * <p>The operator must create a new MocAsymKey object and set it with the same
 * data as the source object.
 * <p>The inputInfo is NULL. The input is the actual MocAsymKey object itself,
 * so there's no need for any other inputInfo.
 * <p>The outputInfo is the address of a MocAsymKey pointer. That is, it is the
 * address where the function will place the newly created MocAsymKey.
 * <pre>
 * <code>
 *   inputInfo   NULL
 *   outputInfo  MocAsymKey *
 *
 *   for example, the key operator will be called something like this:
 *
 *   MocAsymKey pNewKey = NULL;
 *
 *   pSrcKey->KeyOperator (
 *     pSrcKey, MOC_ASYM_OP_CLONE, NULL, (void *)&pNewKey, NULL);
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_CLONE                  (MOC_ASYM_OP_CODE+10)

/* Use this key operation to indicate that the Operator function should return
 * an algorithm identifier (algId = SEQ { OID, params ANY }). The Operator is
 * to return the algId of the operation it last performed. See also the
 * comments for CRYPTO_getAsymAlgId.
 * <p>Most of the time we sign or encrypt data, we provide an algorithm
 * identifier along with the processed data so that the reader can know which
 * algorithm to use to decrypt or verify the data.
 * <p>The outputInfo is a pointer to an MKeyOperatorBuffer struct. It will
 * contain the buffer into which the Operator is to place the algId. The struct
 * contains the buffer size and an address to seposit the length of the result.
 * <p>An algId consists of an OID and parameters. Many public key algorithms
 * have no parameters, but some do, such as RSA-PSS. The Operator function must
 * know how to build the parameters. If the object needs more information (e.g.
 * with RSA-PSS, the params include MGF, salt length, and more), that should
 * have been set during creation and setting.
 * <pre>
 * <code>
 *   inputInfo   NULL
 *   outputInfo  MKeyOperatorBuffer *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_GET_LATEST_ALG_ID      (MOC_ASYM_OP_CODE+11)

/* Use this key operation to indicate that the Operator function should create
 * a digital signature.
 * <p>Note that this will only work if the key is a private key.
 * <p>The inputInfo is a pointer to an MKeyAsymSignData struct containing the
 * digestInfo (The digest represented as the DER encoding of DigestInfo) of the
 * data to sign, along with the algId or algorithmDetails, SymOperators for
 * supporting operations and a MRandomGenInfo.
 * <p>The outputInfo is a pointer to an MKeyOperatorDataReturn struct
 * containing the output buffer, its size, and an address where the Operator
 * should deposit the signature length.
 * <p>The caller passes in the DigestInfo. If the signature uses the DigestInfo
 * (e.g. RSA with PKCS 1 padding), it's there. If not, the Operator can extract
 * the actual digest. The Operator will also be able to extract the digest OID
 * to be used in building the signature algId.
 * <p>The operator must return the signature as a single buffer.
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymSignInfo *
 *   outputInfo  MKeyOperatorBuffer *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_SIGN_DIGEST_INFO       (MOC_ASYM_OP_CODE+12)

/* Use this key operation to indicate that the Operator function should verify
 * a digital signature.
 * <p>Note that for some implementations, this will only work if the key is a
 * public key.
 * <p>The inputInfo is a pointer to an MKeyAsymVerifyData struct containing the
 * digestInfo (The digest represented as the DER encoding of DigestInfo) of the
 * data to verify, along with the algId or algorithmDetails, SymOperators for
 * supporting operations, a MRandomGenInfo, and the signature to verify.
 * <p>The outputInfo is the address where the Operator should return the
 * verification failures (nonzero is a list of verification failures, so does
 * not verify, zero = no verification failures, so the signture verifies).
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymVerifyData *
 *   outputInfo  ubyte4 *
 *
 *   for example, the key operator will be called something like this:
 *
 *   ubyte4 vfyFailures;
 *   MKeyAsymVerifyData vfyInfo;
 *
 *   pSrcKey->KeyOperator (
 *     pKeyObj, keyOpVerify, (void *)&vfyInfo, (void *)&vfyFailures, NULL);
 * </code>
 * </pre>
 * <p>The caller passes in the DigestInfo. If the signature uses the DigestInfo
 * (e.g. RSA with PKCS 1 padding), it's there. If not, the Operator can extract
 * the actual digest. The Operator will also be able to extract the digest OID
 * to be used in building the signature algId.
 */
#define MOC_ASYM_OP_VERIFY_DIGEST_INFO     (MOC_ASYM_OP_CODE+13)

/* Use this key operation to indicate that the Operator function should perform
 * asymmetric encryption on the data.
 * <p>The inputInfo is a pointer to an MKeyAsymEncryptInfo struct containing
 * the data to process and its length, along with the algorithm details and an
 * optional digest object.
 * <p>The outputInfo is a pointer to an MKeyOperatorBuffer struct containing
 * the buffer into which the result will be placed.
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymEncryptInfo *
 *   outputInfo  MKeyOperatorBuffer *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_ENCRYPT                (MOC_ASYM_OP_CODE+14)

/* Use this key operation to indicate that the Operator function should perform
 * asymmetric decryption on the data.
 * <p>The inputInfo is a pointer to an MKeyAsymDecryptInfo struct containing
 * the data to process and its length, along with the algorithm details and an
 * optional digest object.
 * <p>The outputInfo is a pointer to an MKeyOperatorBuffer struct containing
 * the buffer into which the result will be placed.
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymEncryptInfo *
 *   outputInfo  MKeyOperatorBuffer *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_DECRYPT                (MOC_ASYM_OP_CODE+15)

/* Use this key operation to indicate that the Operator function should perform
 * phase 2 of Diffie-Hellman (or ECDH), computing the shared secret from the
 * caller's private key and the correspondent's public value. The caller will
 * be operating on the private key object. That is, it is the private key's
 * Operator that will be called upon to perform this operation.
 * <p>The inputInfo is a pointer to an MKeyOperatorData struct containing the
 * other party's public value (a canonical integer for DH and a point in
 * compressed/uncompressed format for ECDH). A point will be one of the
 * following (where || means concatenate).
 * <pre>
 * <code>
 *    04 || x || y
 *    02 || x
 *    03 || x
 * </code>
 * </pre>
 * <p>The outputInfo is a pointer to an MKeyOperatorBuffer struct.
 */
#define MOC_ASYM_OP_COMPUTE_SHARED_SECRET   (MOC_ASYM_OP_CODE+16)

/* Use this key operation to indicate that the Operator function should return
 * the params.
 * <p>The inputInfo is NULL.
 * <p>The outputInfo is a pointer to an MDsaParams, MEccParams, or MDhParams
 * pointer. For example, if the caller wants a copy of the ECC params, declare
 * a variable to be of type MEccParams *, initialize to NULL and pass its
 * address to the Operator as the outputInfo.
 * <p>The caller should check the localType of the source object to make sure
 * it is the appropriate algorithm (mask localType with MOC_LOCAL_KEY_COM_MASK
 * to get the algorithm which will be MOC_LOCAL_KEY_DSA, _DH, _ECC, or _RSA).
 * <p>The Operator will allocate memory for the struct itself and the data, if
 * there is any. The Operator must allocate one buffer using DIGI_MALLOC. The
 * caller will free the memory (using DIGI_FREE) when done with the params.
 * <p>The Operator will never set the pPublicKey field of any params struct.
 * <p>For ECC, only standard params are allowed, so set that field in the
 * output. If the params are DSA, set the prime, subprime, and base, along with
 * the securitySize. If the params are DH, they will be either StandardParams
 * or the actual prime, optional subprime, and base, along with the priValLen.
 * <p>For example,
 * <pre>
 * <code>
 *   MDhParams *pGetParams = NULL;
 *
 *   // Is this MocAsymKey DH?
 *   // If not, skip the GetParams.
 *   if (MOC_LOCAL_KEY_DH !=
 *       ((pMocAsymKey->localType) & MOC_LOCAL_KEY_COM_MASK))
 *     goto exit;
 *
 *   status = pMocAsymKey->KeyOperator (
 *     pMocAsymKey, MOC_ASYM_OP_GET_PARAMS, NULL, (void *)&pGetParams, NULL);
 *
 *      . . .
 *
 * exit:
 *   // Free the memory returned from the Get, it will be one buffer.
 *   DIGI_FREE ((void **)&pGetParams);
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_GET_PARAMS             (MOC_ASYM_OP_CODE+17)

/* Use this key operation to indicate that the Operator function should return
 * the public value in a Diffie-Hellman (or ECC) key as a byte array.
 * <p>Note that an ECDH public value is actually a point. It should be returned
 * in the standard format:
 * <pre>
 * <code>
 *    04 || x || y
 *    02 || x
 *    03 || x
 *   where || means concatenate
 * </code>
 * </pre>
 * <p>The inputInfo is NULL.
 * <p>The outputInfo is a pointer to an MKeyOperatorDataReturn struct. That is,
 * to get the public value, declare a variable to be of type
 * MKeyOperatorDataReturn, set the fields to the addresses where the Operator
 * should deposit the buffer and length, and pass its address to the Operator
 * as the outputInfo.
 * <p>The caller should check the localType of the source object to make sure
 * it is the appropriate algorithm (mask localType with MOC_LOCAL_KEY_COM_MASK
 * to get the algorithm which will be MOC_LOCAL_KEY_DH, or _ECC).
 * <p>The Operator will allocate memory for the data (deposited at the address
 * given by the ppData field of the outputInfo). The Operator must allocate the
 * buffer using DIGI_MALLOC. The caller will free the memory (using DIGI_FREE)
 * when done with the value.
 * <p>For example,
 * <pre>
 * <code>
 *   ubyte4 pubValLen;
 *   ubyte *pPubVal = NULL;
 *   MKeyOperatorDataReturn getPubVal;
 *
 *   // Is this MocAsymKey DH?
 *   // If not, skip the GetPubVal.
 *   if (MOC_LOCAL_KEY_DH !=
 *       ((pMocAsymKey->localType) & MOC_LOCAL_KEY_COM_MASK))
 *     goto exit;
 *
 *   getPubVal.ppData = &pPubVal;
 *   getPubVal.pLength = &pubValLen;
 *   status = pMocAsymKey->KeyOperator (
 *     pMocAsymKey, MOC_ASYM_OP_GET_PUB_VALUE, NULL, (void *)&getPubVal, NULL);
 *
 *      . . .
 *
 * exit:
 *   // Free the memory returned from the Get, it will be one buffer.
 *   DIGI_FREE ((void **)&pPubVal);
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_GET_PUB_VALUE          (MOC_ASYM_OP_CODE+18)

/* Works with older code. The input is MKeyOperatorAlgIdReturn and the output
 * is MKeyOperatorDataReturn.
 */
#define MOC_ASYM_OP_GET_ALG_ID             (MOC_ASYM_OP_CODE+19)

/* Use this key operation to build a new public key from an
 * existing private key.  The memory for the new key will be allocated by this
 * function, it is the callers responsibility to free it when the key is
 * no longer needed by the application.
 * <p>The inputInfo for this operation is always NULL, the new public key will
 * be extracted from the MocAsymKey itself, not the inputInfo.
 * <p>The outputInfo for this operation is a double pointer to a MocAsymKey
 * structure that will recieve to the location of the new public key.
 * <pre>
 * <code>
 *   inputInfo    NULL
 *   outputInfo   MocAsymKey *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_PUB_FROM_PRI           (MOC_ASYM_OP_CODE+20)

/* Use this key op to compare two public keys. The caller wil pass in a
 * candidate key in DER form (subject public key info), the Operator will
 * determine if the key data passed in is the same as the key data inside.
 * <p>This is for determining if the key data from a cert is the same as the
 * key data in an existing public key.
 * <p>The inputInfo for this operation is a pointer to MKeyOperatorData
 * containing the DER of the key to compare.
 * <p>The outputInfo is a pointer to an intBoolean, which the operator will set
 * to TRUE or FALSE, depending on whether the key matches or not.
 * <pre>
 * <code>
 *   inputInfo   pointer to MKeyOperatorData
 *   outputInfo  pointer to intBoolean
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_IS_SAME_PUB_KEY        (MOC_ASYM_OP_CODE+21)

/** Update an operators associated data.
 * <pre>
 * <code>
 * inputInfo is a pointer to an implementation dependent operator data structure.
 * outputInfo is NULL.
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_UPDATE_OP_DATA          (MOC_ASYM_OP_CODE+22)

/**
 * Use this key operation to instruct the Operator to request that the standard,
 * per-algorithm, template structure be filled with the appropriate parameters for
 * a given key type. The parameters within the template will be stored as
 * byte-strings (as opposed to vlongs), which the function will allocate.  It is
 * therefore the caller's responsibility to call the template's accompanying
 * free-function.  The specific name of the free-function should be in the
 * documentation for the template structure (mocasym.h is a good place to
 * check first).
 *
 * pInputInfo should be NULL
 * pOutputInfo should be one of MEccKeyTemplate, MRsaKeyTemplate, MDsaKeyTemplate,
 * MDhKeyTemplate, MKeyOperatorBuffer, or MPqcKeyTemplate
 */
#define MOC_ASYM_OP_GET_KEY_DATA            (MOC_ASYM_OP_CODE+23)

/**
 * Use this key operation to instruct the Operator to fill in a key's appropriate
 * standard parameters using the standard, per-algorithm, template structure.
 * This template structure must be filled using the function that makes use of
 * the MOC_ASYM_OP_GET_KEY_DATA key operation.
 *
 * pInputInfo should be one of MEccKeyTemplate, MRsaKeyTemplate, MDsaKeyTemplate,
 * MDhKeyTemplate, MKeyOperatorBuffer, or MPqcKeyTemplate
 * pOutputInfo should be NULL
 */
#define MOC_ASYM_OP_SET_KEY_DATA            (MOC_ASYM_OP_CODE+24)

/**
 * Use this key operation to instruct the Operator to free the standard,
 * per-algorithm key template structure created by the function that makes use
 * of the MOC_ASYM_OP_GET_KEY_DATA key operation.
 *
 * pInputInfo should be one of MEccKeyTemplate, MRsaKeyTemplate, MDsaKeyTemplate,
 * or MDhKeyTemplate
 * pOutputInfo should be NULL
 */
#define MOC_ASYM_OP_FREE_KEY_TEMPLATE       (MOC_ASYM_OP_CODE+25)

/**
 * Use this key operation to determine the local type of a key Operator.
 * pInputInfo should be NULL
 * pOutputInfo should be a ubyte4 *
 */
#define MOC_ASYM_OP_GET_LOCAL_TYPE          (MOC_ASYM_OP_CODE+26)

/**
 * Use this operation to determine if a given public and private key match
 * pInputInfo should be a MocAsymKey
 * pOutputInfo should be a byteBoolean *
 */
#define MOC_ASYM_OP_VALIDATE_PUB_PRI_MATCH  (MOC_ASYM_OP_CODE+27)

/**
 * Use this key operation to determine if a key object is valid.
 * pInputInfo should be NULL
 * pOutputInfo should be a byteBoolean *
 */
#define MOC_ASYM_OP_VALIDATE_KEY            (MOC_ASYM_OP_CODE+28)

/**
 * Use this for a key encapsulation mechanism (KEM) algorithm.
 * pInputInfo should be NULL
 * pOutputInfo should point to a MKeyEncapsulationInfo
 */
#define MOC_ASYM_OP_ENCAPSULATE             (MOC_ASYM_OP_CODE+29)

/* Use this key operation to indicate that the Operator function should return a
 * digest object that can be used with the key when signing or verifying.
 * <p>See CRYPTO_getDigestObjectFromKey.
 * <p>The inputInfo is a pointer to an MKeyAsymGetDigestinfo struct containing
 * the algId or algorithmDetails flag.
 * <p>The output info is a MocSymCtx **. This is the address where the Operator
 * is to deposit the created digest object.
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymGetDigestInfo *
 *   outputInfo  MocSymCtx **
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_GET_DIGEST_FROM_KEY    (MOC_ASYM_OP_CODE+30)

/* Use this key operation to indicate that the Operator function should create
 * a digital signature.
 * <p>Note that this will only work if the key is a private key.
 * <p>The inputInfo is a pointer to an MKeyAsymSignData struct containing the
 * digest of the data to sign, along with the algId or algorithmDetails,
 * SymOperators for supporting operations and a MRandomGenInfo.
 * <p>The outputInfo is a pointer to an MKeyOperatorDataReturn struct
 * containing the output buffer, its size, and an address where the Operator
 * should deposit the signature length.
 * <p>The caller passes in the raw digest. This cannot be used with RSA PKCS1.5
 * signing.
 * <p>The operator must return the signature as a single buffer.
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymSignInfo *
 *   outputInfo  MKeyOperatorBuffer *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_SIGN_DIGEST            (MOC_ASYM_OP_CODE+31)


/* Use this key operation to indicate that the Operator function should verify
 * a digital signature.
 * <p>Note that for some implementations, this will only work if the key is a
 * public key.
 * <p>The inputInfo is a pointer to an MKeyAsymVerifyData struct containing the
 * digest of the data to verify, along with the algId or algorithmDetails,
 * SymOperators for supporting operations, a MRandomGenInfo, and the
 * signature to verify.
 * <p>The outputInfo is the address where the Operator should return the
 * verification failures (nonzero is a list of verification failures, so does
 * not verify, zero = no verification failures, so the signture verifies).
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymVerifyData *
 *   outputInfo  ubyte4 *
 *
 *   for example, the key operator will be called something like this:
 *
 *   ubyte4 vfyFailures;
 *   MKeyAsymVerifyData vfyInfo;
 *
 *   pSrcKey->KeyOperator (
 *     pKeyObj, keyOpVerify, (void *)&vfyInfo, (void *)&vfyFailures, NULL);
 * </code>
 * </pre>
 * <p>The caller passes in the raw digest.
 */
#define MOC_ASYM_OP_VERIFY_DIGEST          (MOC_ASYM_OP_CODE+32)

/* Use this key operation to indicate that the Operator function should create
 * a digital signature.
 * <p>Note that this will only work if the key is a private key.
 * <p>The inputInfo is a pointer to an MKeyAsymSignData struct containing the
 * the data to sign, along with the algId or algorithmDetails,
 * SymOperators for supporting operations and a MRandomGenInfo.
 * <p>The outputInfo is a pointer to an MKeyOperatorDataReturn struct
 * containing the output buffer, its size, and an address where the Operator
 * should deposit the signature length.
 * <p>The caller passes in the raw data.
 * <p>The operator must return the signature as a single buffer.
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymSignInfo *
 *   outputInfo  MKeyOperatorBuffer *
 * </code>
 * </pre>
 */
#define MOC_ASYM_OP_SIGN_MESSAGE           (MOC_ASYM_OP_CODE+33)

/* Use this key operation to indicate that the Operator function should verify
 * a digital signature.
 * <p>Note that for some implementations, this will only work if the key is a
 * public key.
 * <p>The inputInfo is a pointer to an MKeyAsymVerifyData struct containing the
 * the data to verify, along with the algId or algorithmDetails,
 * SymOperators for supporting operations, a MRandomGenInfo, and the
 * signature to verify.
 * <p>The outputInfo is the address where the Operator should return the
 * verification failures (nonzero is a list of verification failures, so does
 * not verify, zero = no verification failures, so the signture verifies).
 * <pre>
 * <code>
 *   inputInfo   MKeyAsymVerifyData *
 *   outputInfo  ubyte4 *
 *
 *   for example, the key operator will be called something like this:
 *
 *   ubyte4 vfyFailures;
 *   MKeyAsymVerifyData vfyInfo;
 *
 *   pSrcKey->KeyOperator (
 *     pKeyObj, keyOpVerify, (void *)&vfyInfo, (void *)&vfyFailures, NULL);
 * </code>
 * </pre>
 * <p>The caller passes in the raw data.
 */
#define MOC_ASYM_OP_VERIFY_MESSAGE          (MOC_ASYM_OP_CODE+34)

/**
 * Use this to decapsulate a key with respect to a key encapsulation
 * mechanism (KEM) algorithm.
 * pInputInfo should point to a MKeyEncapsulationInfo
 * pOutputInfo should point to a MKeyEncapsulationInfo
 */
#define MOC_ASYM_OP_DECAPSULATE             (MOC_ASYM_OP_CODE+35)


/* This struct contains a byte array, its length, and a generic (void *)
 * supporting structure. The byte array is for when the Mocana code has to pass
 * data to the KeyOperator function. The supporting structure is for overriding
 * certain default behaviors of an Operator. The correct casting / usage will be
 * documented with the Operator itself.
 */
typedef struct
{
  ubyte    *pData;
  ubyte4    length;
  void     *pAdditionalOpInfo;
} MKeyOperatorData;

/* This struct contains the address where an operation should deposit a buffer of
 * allocated data and the address where it should deposit the length.
 * <p>Some operations will generate a buffer of data (make a key blob or DER
 * encode the key data). The operation allocates memory and fills that memory
 * with the data. It must return the buffer and its length at addresses provided
 * by the caller. This is how we can pass around those addresses as a single
 * element.
 * <p>The Operator must allocate any memory returned using DIGI_MALLOC.
 */
typedef struct
{
  ubyte   **ppData;
  ubyte4   *pLength;
} MKeyOperatorDataReturn;

/* This struct contains the buffer into which an operator will place a result. It
 * contains the buffer, its size, and an address where an operator is to place
 * the length. The length is the number of bytes placed into the buffer, or else
 * it is the required buffer size.
 * <p>The operator will look at the bufferSize to see if the buffer is big
 * enough, and if not, it will set *pLength to the size needed and return
 * ERR_BUFFER_TOO_SMALL. If the pBuffer field is NULL, the operator will know
 * that the bufferSize is 0.
 * <p>The size required might be bigger than the actual data length. This is
 * because the operator might not know the exact length of output before it
 * performs the operation, and won't perform the operation until it knows the
 * buffer is big enough. Hence, it will return a maximum output length. For
 * example, when decrypting, there might be pad bytes that will be stripped, but
 * the operator can't know in advance how many pad bytes there will be, so will
 * need a buffer that can handle any pad length possibility.
 */
typedef struct
{
  ubyte    *pBuffer;
  ubyte4    bufferSize;
  ubyte4   *pLength;
} MKeyOperatorBuffer;

/* This struct is the input arg that accompanies a call to a KeyOperator with the
 * KeyOperation MOC_ASYM_OP_GET_ALG_ID.
 * <p>The function field is either MOC_ASYM_KEY_FUNCTION_ENCRYPT or
 * MOC_ASYM_KEY_FUNCTION_SIGN.
 * <p>If the function is SIGN, the digestAlgorithm field will be one of the ht_
 * values defined in crypto.h (ht_sha1, ht_sha256, etc.). If the function is
 * ENCRYPT, ignore the digestAlgorithm field.
 */
typedef struct
{
  ubyte4      function;
  ubyte4      digestAlgorithm;
} MKeyOperatorAlgIdReturn;

#define MOC_ASYM_KEY_FUNCTION_ENCRYPT    1
#define MOC_ASYM_KEY_FUNCTION_KEY_AGREE  2
#define MOC_ASYM_KEY_FUNCTION_SIGN       4

/* This is the input data to accompany MOC_ASYM_OP_GENERATE.
 * <p>The operator info is whatever was passed in to the call to
 * CRYPTO_generateKeyPair.
 * <p>The actual implementation might not use the random context passed in, but
 * it is there in case it is needed.
 */
typedef struct
{
  void            *pOperatorInfo;
  MRandomGenInfo   *pRandInfo;
} MKeyPairGenInfo;

/* This is the output data to accompany MOC_ASYM_OP_GENERATE.
 * <p>Each object should already be created using the Operator and info.
 */
typedef struct
{
  struct MocAsymmetricKey   **ppPubKey;
  struct MocAsymmetricKey   **ppPriKey;
} MKeyPairGenResult;


/* This is the input data used to store a data object (typically a key)
 * to secure storage with a given Id and token.
 */
typedef struct
{
  ubyte *pId;
  ubyte4 idLen;
  ubyte4 provider;
  ubyte4 moduleId;
  ubyte4 tokenId;
} MKeyObjectInfo;

/* This is the input data to accompany MOC_ASYM_OP_ENCRYPT or MOC_ASYM_OP_DECRYPT.
 * See the comments for CRYPTO_asymEncrypt for more information on the meaning of
 * each of the fields.
 * The pData is simply the data to process.
 */
typedef struct
{
  ubyte                *pAlgId;
  ubyte4                algIdLen;
  ubyte4                algorithmDetails;
  MSymOperatorAndInfo  *pSymOperators;
  ubyte4                listCount;
  void                 *pAdditionalInfo;
  MRandomGenInfo       *pRandInfo;
  ubyte                *pData;
  ubyte4                length;
} MKeyAsymEncryptInfo;

/** This is simply a typedef allowing you to have a struct with the word Decrypt
 * instead of Encrypt.
 */
typedef MKeyAsymEncryptInfo MKeyAsymDecryptInfo;
/** This is simply a typedef allowing you to have a struct with the word Sign
 * instead of Encrypt.
 */
typedef MKeyAsymEncryptInfo MKeyAsymSignInfo;

/* This is the inputInfo to accompany MOC_ASYM_OP_VERIFY_DIGEST_INFO.
 * See the comments for CRYPTO_asymVerifyDigestInfo for more information on the meaning of
 * each of the fields.
 */
typedef struct
{
  ubyte                *pAlgId;
  ubyte4                algIdLen;
  ubyte4                algorithmDetails;
  MSymOperatorAndInfo  *pSymOperators;
  ubyte4                listCount;
  void                 *pAdditionalVfyInfo;
  MRandomGenInfo       *pRandInfo;
  ubyte                *pData;
  ubyte4                length;
  ubyte                *pSignature;
  ubyte4                signatureLen;
} MKeyAsymVerifyInfo;

/* This is the inputInfo to accompany MOC_ASYM_OP_GET_DIGEST_FROM_KEY.
 * See the comments for CRYPTO_getDigestObjectFromKey for more information on the
 * meaning of each of the fields.
 */
typedef struct
{
  ubyte                *pAlgId;
  ubyte4                algIdLen;
  ubyte4                algorithmDetails;
} MKeyAsymGetDigestInfo;

/* This struct accompanies a call to a KeyOperator with the KeyOperation
 * MOC_ASYM_OP_SIGN_DIGEST_INFO.
 * <p>The caller will have digested the data to sign, and will set the pDigest
 * and digest len fields to the resulting value. The caller will also set the
 * digestAlgorithm field to one of the ht_ values defined in crypto.h (ht_sha1,
 * ht_sha256, etc.).
 * <p>The caller will also pass a random number generator in the form of an
 * RNGFun and its arg. If the operator wants to use its own RNG or if it doesn't
 * need one, it can ignore the one passed in.
 * <p>Note that if the MocAsymKey implementation needs more information to
 * compute the signature (e.g. a hardware handle), that should have been set in the
 * object when the key data was being loaded, or when the object was cloned.
 */
typedef struct
{
  ubyte      *pDigest;
  ubyte4      digestLen;
  ubyte4      digestAlgorithm;
  RNGFun      rngFun;
  void       *rngFunArg;
} MKeyOperatorSignInfo;

/* This struct accompanies a call to a KeyOperator with the KeyOperation
 * keyOpVerify.
 * The caller will have digested the data and isolated the signature. The caller
 * will also set the digestAlgorithm field to one of the ht_ values defined in
 * crypto.h (ht_sha1, ht_sha256, etc.).
 * The Operator determine if the given signature verifies with the supplied
 * digest. It will then deposit the verification result at the address given in
 * the pVerifyResult field. Set the result to 1 (TRUE) if the signature verifies
 * and 0 (FALSE) if it does not.
 * Note that the function returns an error code that is different from the verify
 * result. That is, if the Operator determines that the signature does not
 * verify, that is not an error.
 * Note that if the MocAsymKey implementation needs more information to compute
 * the signature (e.g. a hardware handle), that should have been set in the
 * object when the key data was being loaded, or when the object was cloned.
 */
typedef struct
{
  ubyte      *pDigest;
  ubyte4      digestLen;
  ubyte4      digestAlgorithm;
  ubyte      *pSignature;
  ubyte4      signatureLen;
} MKeyOperatorVerifyInfo;

/*
 * This struct should accompany a call to a KeyOperator with the KeyOperation
 * being MOC_ASYM_OP_ENCAPSULATE or MOC_ASYM_OP_DECAPSULATE. A pointer to this struct can
 * be used as an input parameter containing the buffer of ciphertext and its length
 * (in which case leave pSharedSecret NULL), or conversely a pointer to this struct can
 * be used as an output parameter. For encapsulation both buffers will be set with
 * the ciphertext and shared secret repsectively. For decapsulation only the shared
 * secret buffer will be set.
 */
typedef struct
{
  ubyte                *pCipherText;
  ubyte4                cipherTextLen;
  ubyte                *pSharedSecret;
  ubyte4                sharedSecretLen;
} MKeyEncapsulationInfo;

/* This is the signature of the operator callback function for MocAsymKeys.
 * <p>There are certain situations in which a caller might want to perform
 * some action or modify some data before a particular operation occurs.
 * <p>This is largely designed for hardware operators, which might have
 * to set internal parameters such a context to associate the key with
 * that is managed by the application itself.
 * <p>In these cases the operator data will contain a callback. The callback
 * will be called when certain operations are performed, see each operator
 * for more information on exactly when the callback will be called.
 * <p>Note the callback is primarily for the reciever, originators can still
 * use this or update the data manually with CRYPTO_updateOperatorData.
 *
 * @param pMocCtx The MocCtx built during the call to DIGICERT_initialize.
 * @param keyOp The op code for the operation currently being performed.
 * @param pOperatorData A pointer to the MocAsymKeys internal data structure.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
typedef MSTATUS (*MOperatorCallback) (
  MocCtx        pMocCtx,
  keyOperation  keyOp,
  void         *pOperatorData
  );

/* This is the signature of the operator function in a MocAsymKey.
 * When Mocana code needs to perform some operation on the key, but that
 * operation requires knowledge of the actual key data, it will call the Operator
 * function.
 * <p>The Mocana code will pass to the Operator function a flag indicating what
 * it wants the the operator to do. The flag will be one of the keyOperation
 * values (see the definition for the enum keyOperation).
 * <p>The Mocana code will also pass to the Operator inputInfo and outputInfo.
 * There will be different infos for each keyOperation. Check the documentation
 * for what associated info to expect for each keyOp. Some info might be NULL, it
 * could be a data struct with a field where the Operator is to deposit allocated
 * memory (e.g. the DER encoding of a key). The infos will likely be data
 * structs, the addresses cast to void *. The operator dereferences the pointers
 * to the specific structs based on the keyOp arg.
 * <p>The implementation of the Operator function will likely begin with a switch
 * statement. It will switch on the keyOp. For each operation the implementation
 * supports, it will call a specific subroutine that knows how to dereference the
 * associated info and perform the specific operation.
 * <p>Mocana will pass to the Operator function the MocAsymKey. The actual key
 * data is at the mocAsymKey->keyData field, but the Operator will have the entire
 * object at its disposal.
 * <p>The vlongQueue is optional. It is a vlong pool of sorts. Some functions
 * that will be calling the KeyOperator will have a vlong queue, and will pass it
 * along in case the operator wants to use it.
 *
 * @param pMocAsymKey The object that contains the key data.
 * @param keyOp What operation the caller is requesting the key perform.
 * @param pInputInfo Any input info (such as data to encrypt or sign) on which
 * the operator is to perform.
 * @param pOutputInfo Any buffers or addresses where the operator is to place
 * results.
 * @param ppVlongQueue Optional, a vlong pool available to the operator if it
 * wants it.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
typedef MSTATUS (*MKeyOperator) (
  struct MocAsymmetricKey *pMocAsymKey,
  MocCtx pMocCtx,
  ubyte4 keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/** This data struct is used to pass an Operator or array of Operators along with
 * associated info in one unit.
 * <p>Most likely the info will be NULL or a hardware handle.
 */
typedef struct
{
  MKeyOperator   KeyOperator;
  void          *pOperatorInfo;
} MKeyOperatorAndInfo;

/* A MocAsymKey is a struct that holds a moc asym key, including an Operator
 * function and the actual key data.
 * <p>You will likely build The MocAsymKey struct (using allocated memory),
 * set the localType to whatever you want (so you can later make sure a
 * MocAsymKey is what you are expecting), load the KeyOperator, and build a
 * data struct with the actual key data (cast to void *).
 * <p>You set the localType to whatever value you want, as long as the
 * MOC_LOCAL_KEY_MOCANA bit is not set. Any MocAsymKey type defined by Mocana
 * will have the MOC_LOCAL_KEY_MOCANA bit set. Later on, you can look at that field
 * to make sure you have an object you expect.
 * <p>The create function call will be given the MocCtx, and will acquire a
 * reference to it.
 * <p>You must supply the Operator function. See the documentation for
 * MKeyOperator for information on this function pointer.
 */
typedef struct MocAsymmetricKey
{
  ubyte4         localType;
  MocCtx         pMocCtx;
  MKeyOperator   KeyOperator;
  void          *pKeyData;
} MocAsymmetricKey;

/* These are bits to build a value for the localType.
 * See also the bits in mocsym.h.
 * Don't use 0x10000000, it is reserved for MocSym.
 * The symmetric and asymmetric flags are defined here so that we can keep track
 * of them in one place, so that we don't accidentally reuse bits.
 * Both a MocAsymKey and MocSymCtx have a ubyte4 as the first element, so it is
 * possible to look at an object and determine if it is Asym or Sym.
 */
#define MOC_LOCAL_KEY_MOCANA     MOC_LOCAL_TYPE_MOCANA
#define MOC_LOCAL_KEY_QS         MOC_LOCAL_TYPE_QS
#define MOC_LOCAL_KEY_SYM        MOC_LOCAL_TYPE_SYM
#define MOC_LOCAL_KEY_ASYM       MOC_LOCAL_TYPE_ASYM
#define MOC_LOCAL_KEY_SW         MOC_LOCAL_TYPE_SW
#define MOC_LOCAL_KEY_HSM        MOC_LOCAL_TYPE_HSM
#define MOC_LOCAL_KEY_HW         MOC_LOCAL_TYPE_HW
#define MOC_LOCAL_KEY_ASYM       MOC_LOCAL_TYPE_ASYM
#define MOC_LOCAL_KEY_PRI        MOC_LOCAL_TYPE_PRI

#define MOC_LOCAL_KEY_ALG_MASK   MOC_LOCAL_TYPE_ALG_MASK

#define MOC_LOCAL_KEY_P1_PAD     MOC_LOCAL_TYPE_P1_PAD
#define MOC_LOCAL_KEY_OAEP       MOC_LOCAL_TYPE_OAEP
#define MOC_LOCAL_KEY_PSS        MOC_LOCAL_TYPE_PSS

#define MOC_LOCAL_KEY_P192       MOC_LOCAL_TYPE_P192
#define MOC_LOCAL_KEY_P224       MOC_LOCAL_TYPE_P224
#define MOC_LOCAL_KEY_P256       MOC_LOCAL_TYPE_P256
#define MOC_LOCAL_KEY_P384       MOC_LOCAL_TYPE_P384
#define MOC_LOCAL_KEY_P521       MOC_LOCAL_TYPE_P521
#define MOC_LOCAL_KEY_X25519     MOC_LOCAL_TYPE_X25519
#define MOC_LOCAL_KEY_X448       MOC_LOCAL_TYPE_X448
#define MOC_LOCAL_KEY_ED25519    MOC_LOCAL_TYPE_ED25519
#define MOC_LOCAL_KEY_ED448      MOC_LOCAL_TYPE_ED448

#define MOC_LOCAL_KEY_COM_MASK   MOC_LOCAL_TYPE_COM_MASK

#define MOC_LOCAL_KEY_RSA        MOC_LOCAL_TYPE_RSA
#define MOC_LOCAL_KEY_DSA        MOC_LOCAL_TYPE_DSA
#define MOC_LOCAL_KEY_DH         MOC_LOCAL_TYPE_DH
#define MOC_LOCAL_KEY_ECC        MOC_LOCAL_TYPE_ECC

#define MOC_LOCAL_KEY_QS_KEM     MOC_LOCAL_TYPE_QS_KEM
#define MOC_LOCAL_KEY_QS_SIG     MOC_LOCAL_TYPE_QS_SIG

#define MOC_LOCAL_KEY_PQC_MLKEM  MOC_LOCAL_TYPE_PQC_MLKEM
#define MOC_LOCAL_KEY_PQC_MLDSA  MOC_LOCAL_TYPE_PQC_MLDSA
#define MOC_LOCAL_KEY_PQC_FNDSA  MOC_LOCAL_TYPE_PQC_FNDSA
#define MOC_LOCAL_KEY_PQC_SLHDSA MOC_LOCAL_TYPE_PQC_SLHDSA

#define MOC_ASYM_ALG_DH          ( MOC_LOCAL_KEY_DH )
#define MOC_ASYM_ALG_RSA         ( MOC_LOCAL_KEY_RSA )
#define MOC_ASYM_ALG_DSA         ( MOC_LOCAL_KEY_DSA )
#define MOC_ASYM_ALG_ECC_P192    ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_P192 )
#define MOC_ASYM_ALG_ECC_P224    ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_P224 )
#define MOC_ASYM_ALG_ECC_P256    ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_P256 )
#define MOC_ASYM_ALG_ECC_P384    ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_P384 )
#define MOC_ASYM_ALG_ECC_P521    ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_P521 )
#define MOC_ASYM_ALG_ECC_X25519  ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_X25519 )
#define MOC_ASYM_ALG_ECC_X448    ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_X448 )
#define MOC_ASYM_ALG_ECC_ED25519 ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_ED25519 )
#define MOC_ASYM_ALG_ECC_ED448   ( MOC_LOCAL_KEY_ECC | MOC_LOCAL_TYPE_ED448 )

#define MOC_ASYM_ALG_PQC_MLKEM \
    ( MOC_LOCAL_KEY_QS_KEM | MOC_LOCAL_KEY_PQC_MLKEM )
#define MOC_ASYM_ALG_PQC_MLDSA \
    ( MOC_LOCAL_KEY_QS_SIG | MOC_LOCAL_KEY_PQC_MLDSA )
#define MOC_ASYM_ALG_PQC_FNDSA \
    ( MOC_LOCAL_KEY_QS_SIG | MOC_LOCAL_KEY_PQC_FNDSA )
#define MOC_ASYM_ALG_PQC_SLHDSA \
    ( MOC_LOCAL_KEY_QS_SIG | MOC_LOCAL_KEY_PQC_SLHDSA )

    /* Global list defining the asymmetric algorithms that CAP supports */
#define MOC_NUM_SUPPORTED_ASYM_ALGOS 16

MOC_EXTERN_CAPASYM_H const ubyte4 pSupportedAsymAlgos[MOC_NUM_SUPPORTED_ASYM_ALGOS];

/* Use this value as the rsaVariant flag in ASN1_rsaBuildAlgIdAlloc when you
 * want the algId of RSA with PKCS 1 version 1.5 pad encryption.
 */
#define MOC_RSA_VARIANT_P1_5_ENC    1
/* Use this value as the rsaVariant flag in ASN1_rsaBuildAlgIdAlloc when you
 * want the algId of RSA with OAEP pad encryption (OAEP defined in PKCS 1 version
 * 2.1).
 */
#define MOC_RSA_VARIANT_OAEP        2
/* Use this value as the rsaVariant flag in ASN1_rsaBuildAlgIdAlloc when you
 * want the algId of RSA PKCS 1 version 1.5 signing.
 */
#define MOC_RSA_VARIANT_P1_5_SIGN   4
/* Use this value as the rsaVariant flag in ASN1_rsaBuildAlgIdAlloc when you
 * want the algId of RSA with PSS pad signatures (PSS defined in PKCS 1 version
 * 2.1).
 */
#define MOC_RSA_VARIANT_PSS         8

/* Use this value so we can create other flags that are different from the
 * defined RSA variant values.
 */
#define MOC_MAX_RSA_VARIANT         MOC_RSA_VARIANT_PSS

/** This value indicates raw RSA. There is no OID for raw RSA, so it is not used
 * as an RSA_VARIANT.
 */
#define MOC_RSA_RAW                 16

/** Use this value as the saltLen value when you want to specify the default salt
 * length for PSS.
 */
#define MOC_RSA_PSS_DEFAULT_SALT_LEN  20
/** Use this value as the trailerField value when you want to specify the default
 * trailer field for PSS.
 */
#define MOC_RSA_PSS_DEFAULT_TRAILER_FIELD  0xBC

/** Use this flag as the algorithmDetails in CRYPTO_asymEncrypt or
 * CRYPTO_asymDecrypt, if you want to encrypt or decrypt the data using RSA, but
 * perform no padding or unpadding.
 * <p>This is generally called "Raw RSA".
 * <p>With this flag the input data must be the same size as the RSA modulus.
 * For example, with a 2048-bit key, the modulus is 2048 bits, which is 256
 * bytes. The input must be 256 bytes long. If the data is only 255 bytes long,
 * you pass in a 256-byte buffer with a prepended 00 byte and the 255 bytes to
 * process.
 * <p>The result will be the same size as the modulus, with prepended 00 bytes if
 * the result is not exactly the length of the modulus.
 * <p>NOTE!!! The input, as an integer, must be less than the modulus. That is,
 * consider the input and modulus to be integers (as byte arrays, they are in
 * canonical format), make sure the input < modulus. You can do this if you make
 * the first byte of input (input[0]) to be 0. It is almost certain that the
 * first byte of the modulus will be 0x80 or greater. Hence, if the first byte of
 * input is 0x7F or less, then the input will be less than the modulus.
 * <p>If the key to use is a public key, call CRYPTO_asymEncrypt. If the key is
 * private, call CRYPTO_asymDecrypt. It is possible you are verifying a signature
 * and want to directly examine the decrypted signature. You still call
 * CRYPTO_asymEncrypt.
 * <p>Note that there is no OID for raw RSA, so there is no algId associated with
 * it. So if you encrypt or decrypt with this flag and call CRYPTO_getAsymAlgId,
 * you will get an error. There is no algId for this so you cannot call
 * asymEncrypt or Decrypt with an algId and get raw RSA, you must use the flag.
 * <p>If you use this flag, you do not need any supporting symmetric operators.
 * <p>One of the args to DIGICERT_initialize is a list of symmetric operators,
 * containing implementations of algorithms you are willing to support and can be
 * used as a resource for the RSA encryption function when it needs to perform
 * supporting operations.
 * <p>However, with this flag there are no supporting operations.
 */
#define MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD     MOC_RSA_RAW

/** Use this flag as the algorithmDetails in CRYPTO_asymEncrypt, if you want to
 * encrypt the data using RSA and pad following PKCS 1 version 1.5. Use this flag
 * in asymDecrypt to unpad the data using PKCS 1 version 1.5.
 * <p>If you use this flag, you do not need any supporting symmetric operators.
 * <p>One of the args to DIGICERT_initialize is a list of symmetric operators,
 * containing implementations of algorithms you are willing to support and can be
 * used as a resource for the RSA encryption function when it needs to perform
 * supporting operations.
 * <p>However, with this flag (PKCS 1 pad), there are no supporting operations.
 */
#define MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD     MOC_RSA_VARIANT_P1_5_ENC

/** Use this flag as the algorithmDetails in CRYPTO_asymEncrypt, if you want to
 * encrypt the data using RSA and pad following OAEP defined in PKCS 1 version 2.
 * Use this flag in asymDecrypt to unpad the data using OAEP.
 * <p>OAEP consists of a digest, a mask generating function (MGF), a digest for
 * the MGF, and an optional label.
 * <p>The only mask generating function currently defined is MGF1, which uses a
 * digest. This flag therefore really specifies RSA with OAEP defined in PKCS 1
 * version 2.0, with SHA-1 as the default digest algorithm, MGF1 with SHA-1 as
 * the default mask generating function and no label. These are the default
 * parameters.
 * <p>To specify non default parameters, set up a MRsaOaepInfo structure and
 * pass it as the additional info when encrypting or decrypting.
 */
#define MOC_ASYM_KEY_ALG_RSA_OAEP_PAD    MOC_RSA_VARIANT_OAEP

/**
 * This is the structure to pass into CRYPTO_asymEncrypt as the additional info
 * when encrypting or decrypting using the OAEP padding scheme. It contains the
 * hash algorithm to be used, an identifier indicating the MGF function to use,
 * the hash function to use for the MGF, and the optional label.
 *
 * The values to use for hashAlgo and mgfHashAlgo can be found in crypto.h.
 * Currently the mgfAlgo must be MOC_PKCS1_ALG_MGF1 as defined below.
 */
typedef struct
{
  ubyte hashAlgo;
  ubyte mgfAlgo;
  ubyte mgfHashAlgo;
  ubyte *pLabel;
  ubyte4 labelLen;
} MRsaOaepInfo;

typedef struct
{
  ubyte hashAlgo;
  ubyte mgfAlgo;
  ubyte mgfHashAlgo;
  sbyte4 saltLen;
} MRsaPssInfo;

/* Expected value to use for the mgfAlgo in the above MRsaOaepInfo structure */
#ifndef MOC_PKCS1_ALG_MGF1
#define MOC_PKCS1_ALG_MGF1 1
#endif

/** Use this flag as the algorithmDetails in CRYPTO_asymSignDigestInfo, if you want to sign
 * the data using RSA and pad following PKCS 1 version 1.5. Use this flag in
 * asymVerify to unpad the data using PKCS 1 version 1.5.
 * <p>If you use this flag, you do not need any supporting symmetric operators.
 * <p>One of the args to asymEncrypt is a list of symmetric operators, containing
 * implementations of algorithms you are willing to support and can be used as a
 * resource for the RSA encryption function when it needs to perform supporting
 * operations.
 * <p>However, with this flag (PKCS 1 pad), there are no supporting operations
 * and the list of symmetric operators can be NULL.
 */
#define MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD      MOC_RSA_VARIANT_P1_5_SIGN
/** Use this flag as the algorithmDetails in CRYPTO_asymSignDigestInfo, if you want to
 * sign the data using RSA and pad following PSS defined in PKCS 1 version 2. Use
 * this flag in asymVerify to unpad the data using PKCS 1 version 2.0 PSS.
 * <p>PSS consists of a mask generating function (MGF), a digest, a salt length,
 * and a trailer field.
 * <p>There is only one mask generating function defined, MGF1, and it uses a
 * digest algorithm. There is a default salt length and a default trailing field.
 * <p>The digest algorithm used by PSS will be the one defined in the DigestInfo.
 * That is, the same digest algorithm used to digest the data to sign, will be
 * the algorithm used to perform the PSS operations. MGF1 uses a digest, and with
 * this flag, the digest used is the same as the one defined in DigestInfo.
 * <p>There are three digest algorithms: one to digest the data to sign, one for
 * PSS, and one for MGF1. However, with this flag, the same algorithm will be
 * used for all three.
 * <p>The saltLen and trailer field when using this flag will be the defaults (20
 * and 0xBC).
 * <p>If you use this flag, you need to supply digest Operators in the list of
 * symmetric operators.
 * <p>One of the args to asymSign is a list of symmetric operators, containing
 * implementations of algorithms you are willing to support and can be used as a
 * resource for the RSA encryption function when it needs to perform supporting
 * operations.
 * <p>With this flag (PSS), the only supporting operation is a message digest.
 * However, that digest can be for any number of algorithms (it is not limited to
 * SHA-1, for example). Hence, you must supply a list of Operators, and that list
 * must contain a Operators for all the digest algorithms you are willing to
 * support, such as MSha1SwOperator, MSha256SwOperator, and so on.
 * <p>If you want to use another variant of PSS (different saltLen or trailer
 * field), then you must specify that using the algId. See
 * ASN1_rsaBuildAlgIdAlloc for how to build an algId for RSA.
 */
#define MOC_ASYM_KEY_ALG_RSA_PSS_PAD        MOC_RSA_VARIANT_PSS
/** Use this flag as the algorithmDetails in CRYPTO_asymSignDigestInfo or
 * CRYPTO_asymVerifyDigestInfo, if you want to sign or verify the data using DSA. There is
 * no padding. This will produce the signature as a single blob of data, namely
 * the BER encoding of
 * <pre>
 * <code>
 *   SEQUENCE {
 *     r INTEGER,
 *     s INTEGER }
 * </code>
 * </pre>
 * <p>If you use this flag, you do not need any supporting symmetric operators.
 * <p>One of the args to asymEncrypt is a list of symmetric operators, containing
 * implementations of algorithms you are willing to support and can be used as a
 * resource for the DSA signature function when it needs to perform supporting
 * operations.
 * <p>However, with this flag (DSA), there are no supporting operations and the
 * list of symmetric operators can be NULL.
 */
#define MOC_ASYM_KEY_ALG_DSA                MOC_MAX_RSA_VARIANT + 1

/** Use this flag as the algorithmDetails in CRYPTO_asymSignDigestInfo or
 * CRYPTO_asymVerifyDigestInfo, if you want to sign or verify the data using ECDSA.
 * The signature format is the concatenation of r and s as big endian bytestrings,
 * zero padded if necessary to ensure each individual bytestring is exactly
 * element length.
 */
#define MOC_ASYM_KEY_ALG_ECDSA              MOC_MAX_RSA_VARIANT + 2

/**
 * This is the structure to pass into CRYPTO_asymSignMessage or
 * CRYPTO_asymVerifyMessage as the pAdditionalInfo or pAdditionalVfyInfo.
 * It contains the format for the signature and the hash algorithm to be used
 * for digesting the message.
 *
 * The values to use for hashAlgo can be found in crypto.h.
 */
typedef struct MEccDsaInfo
{
  ubyte4 format;
  ubyte hashAlgo;

} MEccDsaInfo;

/* The ECDSA signature formats */
#define MOC_ECDSA_SIGN_FORMAT_RAW 1

/**
 * This structure holds the following components of an RSAKey key-structure as
 * byte strings (instead of vlongs):
 *   - Public Exponent (E)
 *   - Modulus (N)
 *   - Components For private keys only:
 *     - Prime            P
 *     - Prime            Q
 *     - Private Exponent D
 *     - Exponent1        D mod (P-1)
 *     - Exponent2        D mod (Q-1)
 *     - Coefficient      Qinv mod P
 *
 * The structure is intended to be used with the RSA_getKeyParametersAlloc
 * function, which will allocate the inner byte-string buffers and fill in the
 * accompanying lengths.
 *
 * In order to free the buffers contained within this structure, a call must
 * be made to RSA_freeKeyTemplate.
 */
typedef struct MRsaKeyTemplate
{
  ubyte   *pE;
  ubyte4   eLen;
  ubyte   *pN;
  ubyte4   nLen;
  ubyte   *pP;
  ubyte4   pLen;
  ubyte   *pQ;
  ubyte4   qLen;
  ubyte   *pD;
  ubyte4   dLen;
  ubyte   *pDp;
  ubyte4   dpLen;
  ubyte   *pDq;
  ubyte4   dqLen;
  ubyte   *pQinv;
  ubyte4   qInvLen;
} MRsaKeyTemplate;

/**
 * This is a standard data structure that represents the public key and optionally
 * the private key for an ECC key. The formats are as follows:
 *   - The private key is a big endian bytestring
 *   - The public key is encoded as a single byte to indicate compression status,
 *     (typically uncompressed) followed by public values X and Y as big endian
 *     bytestrings, zero padded to exactly element length if necessary. This
 *     format is described in Standards for Efficient Cryptography 1: Elliptic
 *     Curve Cryptography Ver 1.9 section 2.3.3.
 *
 * This structure is used to get and set ECC key data. The appropriate free
 * function must be called once the caller is finished using the structure.
 */
typedef struct MEccKeyTemplate
{
  ubyte   *pPrivateKey;
  ubyte4   privateKeyLen;
  ubyte   *pPublicKey;
  ubyte4   publicKeyLen;
} MEccKeyTemplate;

/**
 * This is a standard data structure that represents the public key and optionally
 * the private key for a DH key. Each param is in Big Endian binary with the
 * length specified. The params are...
 *
 * G - the generator of the cyclic group
 * P - the defining prime of the finite field
 * Q - the order of the generator G (this param is optional for verification of
 *     the other party's public key)
 * Y - our private key (if the key represented is a private key)
 * F - our public key
 * groupNum - A non-zero groupNum will override the setting of all of the above
 *            parameters. The values P and G will then be set based on the
 *            pre-defined parameters associated with GroupNum. For getting
 *            key data groupNum is unused and always 0.
 *
 * This structure is used to get and set DH key data. The appropriate free
 * function must be called once the caller is finished using the structure.
 */
typedef struct MDhKeyTemplate
{
    ubyte *pG;
    ubyte4 gLen;
    ubyte *pP;
    ubyte4 pLen;
    ubyte *pQ;
    ubyte4 qLen;
    ubyte *pY;
    ubyte4 yLen;
    ubyte *pF;
    ubyte4 fLen;
    ubyte4 groupNum;

} MDhKeyTemplate;

/**
 * This struct holds parameters needed for finite field DH key generation.
 * For a standard DH group (see for example https://tools.ietf.org/html/rfc3526)
 * one should set the groupNum field in pKeyTemplate. For a custom group,
 * use a keyTemplate that has P, G, and yLen set and groupNum = 0.
 *
 * keyTemplate - Pointer to a template with the groupNum or domain params
 *               set and also yLen.
 * isServer    - TRUE means that both a private key and public key will be
 *               generated (for typical server side use). FALSE means that
 *               just a private key with no public key will be generated
 *               (for typical use on the client side).
 */
typedef struct MDhKeyGenParams
{
    MDhKeyTemplate *pKeyTemplate;
    byteBoolean isServer;

} MDhKeyGenParams;

typedef struct MDsaKeyTemplate
{
    ubyte *pP;
    ubyte4 pLen;
    ubyte *pQ;
    ubyte4 qLen;
    ubyte *pG;
    ubyte4 gLen;
    ubyte *pY;
    ubyte4 yLen;
    ubyte *pX;
    ubyte4 xLen;
} MDsaKeyTemplate;

typedef struct MPqcKeyTemplate
{
    ubyte *pSecretKey;
    ubyte4 secretKeyLen;
    ubyte *pPublicKey;
    ubyte4 publicKeyLen;

} MPqcKeyTemplate;

/* Use one of these flags as an argument to the CRYPTO_getKeyDataAlloc function.
 * The function has a parameter for the type of data to receive, either public
 * key data or private.
*/
#define MOC_GET_PUBLIC_KEY_DATA   1
#define MOC_GET_PRIVATE_KEY_DATA  2

/* Generally, an application will build a MocAsymKey in two ways: (1) Generate a
 * KeyPair, and (2) Load a Key, where loading is done by deserializing.
 */

/** These are the different formats a key can be serialized as using the function
 * CRYPTO_serializeKey.
 * <p>Note that there are a total of three Mocana Blob formats. However, the
 * CRYPTO_serializeKey will only generate Version2. Version 0 and version 1 are
 * older formats which should not be used in new code.
 * <p>The Mocana blob version 2 looks something like this.
 * <pre>
 * <code>
 *   00 00 00 00 00 00 00 01 || alg || key data
 *
 *   where the alg is
 *     00 00 00 01    RSA
 *     00 00 00 02    ECC
 *     00 00 00 03    DSA
 *     00 00 00 65    Custom
 *
 *   The key data is then algorithm-specific.
 * </code>
 * </pre>
 * <p>The deserialize format is used when deserializing a key. You will likely
 * never need to use that value, it will be used internally.
 * <p>The CRYPTO_deserializeKey function will be able to read any supported
 * format. That is, it will be able to recognize what format and what algorithm a
 * serialized key is and parse it.
 * <p>The publicKeyInfoDer format will produce the DER encoding of the ASN.1
 * definition for SubjectPublicKeyInfo (in some places it is known as
 * PublicKeyInfo).
 * <pre>
 * <code>
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm       AlgorithmIdentifier,
 *     PublicKey       BIT STRING }
 *
 *   where PublicKey is a BIT STRING wrapping the actual key data.
 *
 *   RSAPublicKey ::= SEQUENCE {
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER   -- e  }
 *
 *   DSAPublicKey ::= INTEGER
 *    The DSA params are in the AlgorithmIdentifier
 *
 *   ECPublicKey ::= ECPoint
 *    The EC params are specified in the AlgorithmIdentifier, a named curve.
 * </code>
 * </pre>
 * <p>The privateKeyInfoDer format will produce the DER encoding of the ASN.1
 * definition for PrivateKeyInfo.
 *
 * <pre>
 * <code>
 *   PrivateKeyInfo ::= SEQUENCE {
 *     version                   INTEGER,
 *     privateKeyAlgorithm       AlgorithmIdentifier,
 *     privateKey                OCTET STRING,
 *     attributes           [0]  IMPLICIT Attributes OPTIONAL }
 *
 *   where privateKey is an OCTET STRING wrapping the actual key data.
 *   Mocana does not support the attributes field.
 *
 *   RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL }
 *
 *   Mocana does not support RSA with more than 2 primes, so there will never be
 *   OtherPrimeInfos.
 *
 *   DSAPrivateKey ::= OCTET STRING
 *
 *   ECPrivateKey ::= SEQUENCE {
 *     version           INTEGER,
 *     privateValue      OCTET STRING,
 *     parameters    [0] ECParameters {{ Named Curve }} OPTIONAL,
 *     publicKey     [1] EXPLICIT BIT STRING OPTIONAL }
 * </code>
 * </pre>
 * The PEM formats will be the subjecPublicKeyInfo or PrivateKeyInfo base 64
 * encoded with PEM headers and footers. For example,
 * <pre>
 * <code>
 *    -----BEGIN PUBLIC KEY-----
 *    MIH1MIGuBgcqhkjOPQIBMIGiAgEBMCw
 *     . . .
 *    AB4WE4I559o=
 *    -----END PUBLIC KEY-----
 * </code>
 * </pre>
 * <p>Note that the PEM header and footer do not specify the algorithm. The PEM
 * format specifies that when the key is encoded as SubjectPublicKeyInfo or
 * PrivateKeyInfo, then the header and footer do not specify the algorithm. If
 * the key is encoded, for instance, RSAPublicKey or DSAPrivateKey, then the PEM
 * header and footer will specify the algorithm.
 */
typedef enum {
  noFormat            = 0,
  mocanaBlobVersion2  = 2,
  publicKeyInfoDer    = 3,
  privateKeyInfoDer   = 4,
  publicKeyPem        = 5,
  privateKeyPem       = 6,
  deserialize         = 100
} serializedKeyFormat;

/** Generate a key pair, using the MocAsymKey Operator.
 * <p>The caller passes in the Operator to use to generate the key pair. The
 * Operator will almost certainly need associated info, such as a hardware
 * handle, or an ECC parameter set, or simply a security size. See the
 * documentation for each Operator to find out what associated info is needed.
 * <p>The caller will pass in two pointers to NULL MocAsymKey objects, this
 * function will allocate and initialize the new MocAsymKey objects. If the
 * addresses passed in point to existing keys, those keys will be freed.
 * <p>Note that the private key might be a hardware key, meaning the data
 * returned is not the actual key data.
 * <p>The associated info will almost certainly specify a security size. For RSA,
 * DSA, and Diffie-Hellman (DH), this is the modulus length in bits. For ECC, it
 * is the equivalent security size. The following table indicates the actual
 * sizes given the supported security sizes.
 * <pre>
 * <code>
 *    security  |  RSA modulus |  DSA sizes  |  ECC prime  | DH prime
 *      size    |     size     |             |    size     |   size
 *  ------------|--------------|-------------|-------------|----------
 *       1024   |     1024     |  1024/160   |  160 or 192 |   1024
 *       2048   |     2048     |  2048/224   |  224        |   2048
 *       3072   |     3072     |  3072/256   |  256        |   3072
 *       7680   |     7680     |  7680/384   |  384        |   7680
 *      15,360  |    15,360    | 15,360/512  |  512 or 521 |  15,360
 * </code>
 * </pre>
 * <p>Note that not all implementations will support all sizes.
 * <p>The caller passes in a RNGFun and its argument. To use the global random
 * created at initalization simply pass RANDOM_rngFun with the g_pRandomContext
 * as the argument.
 * <p>The vlongQueue is optional. It is a vlong pool of sorts.
 * <p>For example.
 * <pre>
 * <code>
 *   MSTATUS status
 *   MocAsymKey pPubKey = NULL;
 *   MocAsymKey pPriKey = NULL;
 *   MEccParams eccParams;
 *   vlong *queue = NULL;
 *
 *   // Even though the actual prime will be 224 bits, the securitySize will be
 *   // 2048. That is, this function will generate a key pair that has 2048 bits
 *   // of asymmetric security.
 *   eccParams.pPublicKey = NULL;
 *   eccParams.standardParams = EccParamsNistP224r1;
 *   status = CRYPTO_generateKeyPair (
 *     KeyOperatorEccSw, (void *)&eccParams, pMocCtx, RANDOM_rngFun,
 *     g_pRandomContext, &pPubKey, &pPriKey, &queue);
 *   if (OK != status)
 *     goto exit;
 *
 *   // Or suppose you are generating an RSA key pair.
 *   ubyte4 securitySize;
 *
 *   securitySize = 2048;
 *   status = CRYPTO_generateKeyPair (
 *     KeyOperatorRsaSw, (void *)&securitySize, pMocCtx, RANDOM_rngFun,
 *     g_pRandomContext, &pPubKey, &pPriKey, &queue);
 *   if (OK != status)
 *     goto exit;
 *      . . .
 *
 * exit:
 *
 *   if (NULL != pPubKey)
 *     CRYPTO_freeMocAsymKey(&pPubKey, &queue);
 *   if (NULL != pPriKey)
 *     CRYPTO_freeMocAsymKey(&pPriKey, &queue);
 *
 *   VLONG_freeVlongQueue (&queue);
 * </code>
 * </pre>
 *
 * @param KeyOperator The Operator function the function will use.
 * @param pOperatorInfo If the operator function needs some info in order to
 * work, pass it in here. See the documentation for each Operator to determine
 * what info it needs.
 * @param pMocCtx The MocCtx built during the call to DIGICERT_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param ppPubKey The location into which the new public key will be placed.
 * @param ppPriKey The location into which the new private key will be placed.
 * @param ppVlongQueue Optional, a vlong pool available to the operator if it
 * wants it.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_generateKeyPair (
  MKeyOperator KeyOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  RNGFun RngFun,
  void *pRngFunArg,
  MocAsymKey *ppPubKey,
  MocAsymKey *ppPriKey,
  struct vlong **ppVlongQueue
  );

/* Free any memory allocated and release any resources acquired during the
 * creation and setting of this object.
 * <p>This function will call on the loaded Operator function to free the actual
 * key data (located at the keyData field inside the MocAsymKey object), then it
 * will free the shell that is the MocAsymKey.
 *
 * @param ppMocAsymKey The address where the function will find the key to free,
 * and where it will deposit NULL when it successfully completes.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_freeMocAsymKey (
  MocAsymKey *ppMocAsymKey,
  struct vlong **ppVlongQueue
  );

/** Get the security size of the given key object.
 * <p>See the comments for CRYPTO_generateKeyPair for a more extensive discussion
 * of security sizes. Note that not all implementations support all sizes, and
 * with ECC, the security size is not the same as the prime size.
 *
 * @param pKey The key to query.
 * @param pSecuritySize The address where the function will deposit the security
 * size (a number such as 1024, 2048, or 3072).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getSecuritySize (
  MocAsymKey pKey,
  ubyte4 *pSecuritySize
  );

/** Encrypt the pDataToEncrypt using the given key. Place the result into the
 * pEncryptedData buffer.
 * <p>Although the key is of a specific algorithm, there are further details
 * needed. For example, an RSA key can encrypt using RSA, but it must pad using
 * PKCS 1.5 or OAEP. Similarly, there are different ECC encryption details.
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the encryption process will need to digest data. It is
 * also possible that in the future, an algorithm might need a supporting
 * operation other than a digest, such as a mask generating function. To perform
 * any supporting operation needed, the Encrypt function will build an object
 * using the array of supported Operators found in the MocCtx (built during the
 * call to DIGICERT_initialize, the key object contains a reference to the MocCtx).
 * Make sure your arrays of supporting Operators contains the digest Operators of
 * algorithms needed by the encryption processes you support.
 * <p>Some encryption functions require random bytes, so the caller passes in a
 * function pointer used to generate random bytes and the argument to that function.
 * <p>For the data to encrypt, note that algorithms will likely have a limit on
 * the number of bytes it is able to encrypt. For example, RSA-OAEP can encrypt a
 * maximum of k-2*hLen-2 bytes, where k is the key length (in bytes) and hLen is
 * the length of the hash function. For example, with a 2048-bit RSA key and
 * using OAEP with SHA-1, the max input length is 256 - 2*20 -2 = 214.
 * <p>The caller passes in a buffer into which the function will place the
 * encrypted data. If the buffer is too small, the function will return
 * ERR_BUFFER_TOO_SMALL and set *pEncryptedDataLen to the required size.
 * <p>NOTE! The input buffer and output buffer must be different. You cannot
 * encrypt "in place".
 *
 * @param pKey The key that will be used to encrypt.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails If the algId is NULL, this indicates further details
 * on the algorithm to use to encrypt.
 * @param pAdditionalEncryptInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pDataToEncrypt The input data.
 * @param dataToEncryptLen The length, in bytes, of the data to encrypt.
 * @param pEncryptedData The buffer into which the function will place the
 * encrypted data.
 * @param bufferSize The size, in bytes, of pEncryptedData.
 * @param pEncryptedDataLen The address where the function will deposit the
 * number of bytes placed into the output buffer, or the required size if the
 * output buffer is not big enough.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymEncrypt (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalEncryptInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  struct vlong **ppVlongQueue
  );

/** Decrypt the pDataToDecrypt using the given key. Place the result into the
 * pDecryptedData buffer.
 * <p>Although the key is of a specific algorithm, there are further details
 * needed. For example, an RSA key can decrypt using RSA, but it must pad using
 * PKCS 1.5 or OAEP. Similarly, there are different ECC encryption details.
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the decryption process will need to digest data. It is
 * also possible that in the future, an algorithm might need a supporting
 * operation other than a digest, such as a mask generating function. To perform
 * any supporting operation needed, the Encrypt function will build an object
 * using the array of supported Operators found in the MocCtx (built during the
 * call to DIGICERT_initialize, the key object contains a reference to the MocCtx).
 * Make sure your arrays of supporting Operators contains the digest Operators of
 * algorithms needed by the encryption processes you support.
 * <p>Some encryption functions require random bytes, so the caller passes in a
 * function pointer the operator can use if needed. Generally, a decryption
 * operation will not need random bytes, but the argument is provided in case
 * some algorithm in the future needs it.
 * <p>For the data to decrypt, note that algorithms will likely require a
 * specific input length. For example, with RSA, the input must be the same
 * length as the key (leading 00 bytes if the actual value is not exactly the
 * same length).
 * <p>The caller passes in a buffer into which the function will place the
 * decrypted data. If the buffer is too small, the function will return
 * ERR_BUFFER_TOO_SMALL and set *pDecryptedDataLen to the required size. It is
 * possible that the actual output length is smaller than the required length.
 * The function will not decrypt until it knows the output buffer is big enough,
 * but does not know how big the output buffer needs to be until it decrypts and
 * removes the padding. Hence, it will require an output buffer that is a maximum
 * length, place the output into that buffer, and report how many bytes make up
 * the actual decrypted data.
 * <p>NOTE! The input buffer and output buffer must be different. You cannot
 * decrypt "in place".
 *
 * @param pKey The key that will be used to decrypt.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails If the algId is NULL, this indicates further details
 * on the algorithm to use to encrypt.
 * @param pAdditionalDecryptInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pDataToDecrypt The input data.
 * @param dataToDecryptLen The length, in bytes, of the data to decrypt.
 * @param pDecryptedData The buffer into which the function will place the
 * decrypted data.
 * @param bufferSize The size, in bytes, of pDecryptedData.
 * @param pDecryptedDataLen The address where the function will deposit the
 * number of bytes placed into the output buffer, or the required size if the
 * output buffer is not big enough.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymDecrypt (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalDecryptInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDataToDecrypt,
  ubyte4 dataToDecryptLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  struct vlong **ppVlongQueue
  );

/** Sign the data using the given key. This is asymmetric signing as opposed to
 * symmetric signing, such as HMAC.
 * <p>The input data is the DER encoding of the  DigestInfo. That is, the caller
 * must digest the bulk data that is being signed and build the DigestInfo.
 * <pre>
 * <code>
 *   DigestInfo ::= SEQENCE {
 *     algId,
 *     OCTET STRING }
 * </code>
 * </pre>
 * <p>To get the DigestInfo, you can use the MocSymCtx API, calling
 * CRYPTO_digestInfoFinal to get the actual message digest inside the DigestInfo
 * encoding.
 * <p>Generally, the signer will simply build a digest object to perform the hash
 * operations. However, if the key being used to sign is a hardware key, it might
 * need to perform the digest itself (that is, the hardware refuses to create a
 * digital signature using a digest unless it digested the data itself). So
 * rather than building a digest object, you will want to call
 * CRYPTO_getDigestObjectFromKey. That function will return a MocSymCtx that can
 * digest the data using the appropriate algorithm, and if the key needs the
 * digester to be tied to the key, it will return an object tied to the key.
 * <p>Although the key is of a specific algorithm, there are further details
 * needed. For example, an RSA key can sign using RSA, but it must pad using
 * PKCS 1.5 or PSS.
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the signing process will need to digest data (not the
 * data to sign, but some other data. See, for example Probabilistic Signing
 * Scheme, PSS, which is to RSA signatures what OAEP is to RSA encryption). It is
 * also possible that in the future, an algorithm might need a supporting
 * operation other than a digest, such as a mask generating function. To perform
 * any supporting operation needed, the Sign function will build an object
 * using the array of supported Operators found in the MocCtx (built during the
 * call to DIGICERT_initialize, the key object contains a reference to the MocCtx).
 * Make sure your arrays of supporting Operators contains the digest Operators of
 * algorithms needed by the encryption processes you support.
 * <p>The caller supplies the buffer into which the result will be placed. If the
 * buffer is not big enough, the function will return ERR_BUFFER_TOO_SMALL and
 * set *pSignatureLen to the required size. Note that the required size might be
 * bigger than the actual size. The function will not perform any operation until
 * it knows the buffer is big enough, but it cannot know the exact output size
 * until it performs the operation. However, it can determine a maximum size. It
 * will require the buffer to be the max size, then upon return, the result will
 * indicate the exact size.
 * <p>You can call this function with a NULL output buffer to get the required
 * size, then allocate a buffer big enough and call the function a second time
 * with the buffer.
 *
 * @param pKey The key that will be used to sign.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails if pAlgId is NULL, the function will expect to find
 * one of the MOC_ASYM_KEY_ALG_ flags.
 * @param pAdditionalSignInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pDigestInfo The input data, it is the digest of the data to sign, DER
 * encoded as DigestInfo.
 * @param digestInfoLen The length, in bytes, of the input data.
 * @param pSignature The buffer into which the function will place the signature.
 * @param bufferSize The size, in bytes, of pSignature.
 * @param pSignatureLen The address where the function will deposit the
 * number of bytes placed into the output buffer, or the required size if the
 * output buffer is not big enough.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymSignDigestInfo (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalSignInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigestInfo,
  ubyte4 digestInfoLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  struct vlong **ppVlongQueue
  );

/** Sign the data using the given key. Note that in general the
 * CRYPTO_asymSignDigestInfo should be used instead, also note that this
 * function can not perform RSA PKCS1.5 signing as that requires the digestInfo.
 * This is asymmetric signing as opposed to symmetric signing, such as HMAC.
 * <p>The input data is the raw digest.
 * </code>
 * </pre>
 * <p>To get the Digest, you can use the MocSymCtx API, calling
 * CRYPTO_digestFinal to get the message digest.
 * <p>Generally, the signer will simply build a digest object to perform the hash
 * operations. However, if the key being used to sign is a hardware key, it might
 * need to perform the digest itself (that is, the hardware refuses to create a
 * digital signature using a digest unless it digested the data itself). So
 * rather than building a digest object, you will want to call
 * CRYPTO_getDigestObjectFromKey. That function will return a MocSymCtx that can
 * digest the data using the appropriate algorithm, and if the key needs the
 * digester to be tied to the key, it will return an object tied to the key.
 * <p>Although the key is of a specific algorithm, there are further details
 * needed. For example, an RSA key can sign using RSA, but it must pad using
 * PKCS 1.5 or PSS.
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the signing process will need to digest data (not the
 * data to sign, but some other data. See, for example Probabilistic Signing
 * Scheme, PSS, which is to RSA signatures what OAEP is to RSA encryption). It is
 * also possible that in the future, an algorithm might need a supporting
 * operation other than a digest, such as a mask generating function. To perform
 * any supporting operation needed, the Sign function will build an object
 * using the array of supported Operators found in the MocCtx (built during the
 * call to DIGICERT_initialize, the key object contains a reference to the MocCtx).
 * Make sure your arrays of supporting Operators contains the digest Operators of
 * algorithms needed by the encryption processes you support.
 * <p>The caller supplies the buffer into which the result will be placed. If the
 * buffer is not big enough, the function will return ERR_BUFFER_TOO_SMALL and
 * set *pSignatureLen to the required size. Note that the required size might be
 * bigger than the actual size. The function will not perform any operation until
 * it knows the buffer is big enough, but it cannot know the exact output size
 * until it performs the operation. However, it can determine a maximum size. It
 * will require the buffer to be the max size, then upon return, the result will
 * indicate the exact size.
 * <p>You can call this function with a NULL output buffer to get the required
 * size, then allocate a buffer big enough and call the function a second time
 * with the buffer.
 *
 * @param pKey The key that will be used to sign.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails if pAlgId is NULL, the function will expect to find
 * one of the MOC_ASYM_KEY_ALG_ flags.
 * @param pAdditionalSignInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pDigest  The input data, it is the digest of the data to sign.
 * @param digestLen The length, in bytes, of the input data.
 * @param pSignature The buffer into which the function will place the signature.
 * @param bufferSize The size, in bytes, of pSignature.
 * @param pSignatureLen The address where the function will deposit the
 * number of bytes placed into the output buffer, or the required size if the
 * output buffer is not big enough.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymSignDigest (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalSignInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigest,
  ubyte4 digestLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  struct vlong **ppVlongQueue
  );

/** Sign the data using the given key. Note that in general the
 * CRYPTO_asymSignDigestInfo should be used instead where applicable.
 * This is asymmetric signing as opposed to symmetric signing, such as HMAC.
 * <p>The input data is the message to be signed.
 * </code>
 * </pre>
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the signing process will need to digest data (not the
 * data to sign, but some other data. See, for example Probabilistic Signing
 * Scheme, PSS, which is to RSA signatures what OAEP is to RSA encryption). It is
 * also possible that in the future, an algorithm might need a supporting
 * operation other than a digest, such as a mask generating function. To perform
 * any supporting operation needed, the Sign function will build an object
 * using the array of supported Operators found in the MocCtx (built during the
 * call to DIGICERT_initialize, the key object contains a reference to the MocCtx).
 * Make sure your arrays of supporting Operators contains the digest Operators of
 * algorithms needed by the encryption processes you support.
 * <p>The caller supplies the buffer into which the result will be placed. If the
 * buffer is not big enough, the function will return ERR_BUFFER_TOO_SMALL and
 * set *pSignatureLen to the required size. Note that the required size might be
 * bigger than the actual size. The function will not perform any operation until
 * it knows the buffer is big enough, but it cannot know the exact output size
 * until it performs the operation. However, it can determine a maximum size. It
 * will require the buffer to be the max size, then upon return, the result will
 * indicate the exact size.
 * <p>You can call this function with a NULL output buffer to get the required
 * size, then allocate a buffer big enough and call the function a second time
 * with the buffer.
 *
 * @param pKey The key that will be used to sign.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails if pAlgId is NULL, the function will expect to find
 * one of the MOC_ASYM_KEY_ALG_ flags.
 * @param pAdditionalSignInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pMessage   The data to sign.
 * @param messageLen The length, in bytes, of the input data.
 * @param pSignature The buffer into which the function will place the signature.
 * @param bufferSize The size, in bytes, of pSignature.
 * @param pSignatureLen The address where the function will deposit the
 * number of bytes placed into the output buffer, or the required size if the
 * output buffer is not big enough.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymSignMessage (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalSignInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  struct vlong **ppVlongQueue
  );

/** Verify the given signature using the given key. This is asymmetric
 * verification as opposed to symmetric verification, such as HMAC.
 * <p>The caller will digest the data to verify and build the DigestInfo.
 * <pre>
 * <code>
 *   DigestInfo ::= SEQENCE {
 *     algId,
 *     OCTET STRING }
 * </code>
 * </pre>
 * <p>To get the DigestInfo, you can use the MocSymCtx API, calling
 * CRYPTO_digestInfoFinal to get the actual message digest inside the DigestInfo
 * encoding.
 * <p>Incidentally, how does one know which digest algorithm to use? Generally,
 * when verifying, you will be given an algId which specifies the public key
 * algorithm, the digest algorithm, and if RSA, the padding scheme and
 * parameters. To get a digest object from an algId, call
 * CRYPTO_getDigestObjectFromSigAlgId. If you don't have an algId, then there was
 * some other method for communicating the algorithm details.
 * <p>Although the key is of a specific algorithm, there are further details
 * needed. For example, an RSA key can sign using RSA, but it must pad using
 * PKCS 1.5 or PSS.
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the verification process will need to digest data (not
 * the data to verify, but some other data. See, for example Probabilistic
 * Signing Scheme, PSS, which is to RSA signatures what OAEP is to RSA
 * encryption). It is also possible that in the future, an algorithm might need a
 * supporting operation other than a digest, such as a mask generating function.
 * To perform any supporting operation needed, the Verify function will build an
 * object using the array of supported Operators found in the MocCtx (built
 * during the call to DIGICERT_initialize, the key object contains a reference to
 * the MocCtx). Make sure your arrays of supporting Operators contains the digest
 * Operators of algorithms needed by the signing processes you support.
 * <p>The caller passes in the address of a ubyte4, the function will deposit the
 * verification failures at that address. If, upon return, the value is 0, there
 * were no verification failures and the signature verifies. Otherwise, the value
 * will be set to one or more bits describing why the verification failed. The
 * possible values of the verification failure are the MOC_ASYM_VFY_FAIL_
 * #defines. If the result is 0, there were no failures and the signature
 * verifies. If the result is nonzero, the signature did not verify. You can then
 * look at the bits to determine why. Of course, you can simply compare to 0, if
 * zero, no failures (signature verifies), or non-zero, there was at least one
 * failure (signature does not verify).
 * <p>You can think of this result as similar to "memcmp". When memcmp returns 0,
 * the values match. If it is non-zero, the values do not match.
 * <p>Remember, the return value is success or failure of the function, not the
 * signature itself. The return from the function (MSTATUS) can be OK and the
 * verifyFailures is non-zero. In that case, the function worked, it did what it
 * was supposed to do, determine if the signature verified, so it returns OK, but
 * it sets the result of that operation, does not verify.
 *
 * @param pKey The key that will be used to verify.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails if pAlgId is NULL, the function will expect to find
 * one of the MOC_ASYM_KEY_ALG_ flags.
 * @param pAdditionalVfyInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pDigestInfo The input data, it is the digest of the data to sign, DER
 * encoded as DigestInfo.
 * @param digestInfoLen The length, in bytes, of the input data.
 * @param pSignature The buffer containing the signature to verify.
 * @param signatureLen The length, in bytes, of the signature.
 * @param pVerifyFailures A bit field indicating what went wrong in the
 * verification process. Upon return, if this is set to 0, there were no
 * failures. Otherwise it is set to one or more MOC_ASYM_VFY_FAIL_ bits.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymVerifyDigestInfo (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditonalVfyInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigestInfo,
  ubyte4 digestInfoLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  );

/** Verify the given signature using the given key. Note that in general the
 * CRYPTO_asymVerifyDigestInfo should be used. This is asymmetric
 * verification as opposed to symmetric verification, such as HMAC.
 * <p>The caller will digest the data to verify.
 * </pre>
 * <p>To get the Digest, you can use the MocSymCtx API, calling
 * CRYPTO_digestFinal to get the message digest.
 * <p>Incidentally, how does one know which digest algorithm to use? Generally,
 * when verifying, you will be given an algId which specifies the public key
 * algorithm, the digest algorithm, and if RSA, the padding scheme and
 * parameters. To get a digest object from an algId, call
 * CRYPTO_getDigestObjectFromSigAlgId. If you don't have an algId, then there was
 * some other method for communicating the algorithm details.
 * <p>Although the key is of a specific algorithm, there are further details
 * needed. For example, an RSA key can sign using RSA, but it must pad using
 * PKCS 1.5 or PSS.
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the verification process will need to digest data (not
 * the data to verify, but some other data. See, for example Probabilistic
 * Signing Scheme, PSS, which is to RSA signatures what OAEP is to RSA
 * encryption). It is also possible that in the future, an algorithm might need a
 * supporting operation other than a digest, such as a mask generating function.
 * To perform any supporting operation needed, the Verify function will build an
 * object using the array of supported Operators found in the MocCtx (built
 * during the call to DIGICERT_initialize, the key object contains a reference to
 * the MocCtx). Make sure your arrays of supporting Operators contains the digest
 * Operators of algorithms needed by the signing processes you support.
 * <p>The caller passes in the address of a ubyte4, the function will deposit the
 * verification failures at that address. If, upon return, the value is 0, there
 * were no verification failures and the signature verifies. Otherwise, the value
 * will be set to one or more bits describing why the verification failed. The
 * possible values of the verification failure are the MOC_ASYM_VFY_FAIL_
 * #defines. If the result is 0, there were no failures and the signature
 * verifies. If the result is nonzero, the signature did not verify. You can then
 * look at the bits to determine why. Of course, you can simply compare to 0, if
 * zero, no failures (signature verifies), or non-zero, there was at least one
 * failure (signature does not verify).
 * <p>You can think of this result as similar to "memcmp". When memcmp returns 0,
 * the values match. If it is non-zero, the values do not match.
 * <p>Remember, the return value is success or failure of the function, not the
 * signature itself. The return from the function (MSTATUS) can be OK and the
 * verifyFailures is non-zero. In that case, the function worked, it did what it
 * was supposed to do, determine if the signature verified, so it returns OK, but
 * it sets the result of that operation, does not verify.
 *
 * @param pKey The key that will be used to verify.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails if pAlgId is NULL, the function will expect to find
 * one of the MOC_ASYM_KEY_ALG_ flags.
 * @param pAdditionalVfyInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pDigest The input data, it is the digest of the data to sign.
 * @param digestLen The length, in bytes, of the input data.
 * @param pSignature The buffer containing the signature to verify.
 * @param signatureLen The length, in bytes, of the signature.
 * @param pVerifyFailures A bit field indicating what went wrong in the
 * verification process. Upon return, if this is set to 0, there were no
 * failures. Otherwise it is set to one or more MOC_ASYM_VFY_FAIL_ bits.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymVerifyDigest (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalVfyInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigest,
  ubyte4 digestLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  );

/** Verify the given signature using the given key. Note that in general the
 * CRYPTO_asymVerifyDigestInfo should be used. This is asymmetric
 * verification as opposed to symmetric verification, such as HMAC.
 * <p>The caller will pass in the data to verify.
 * </pre>
 * <p>There are two ways to specify the details: one, with the algorithm
 * identifier (algId), or two, the algorithmDetails arg. If the algId is NULL,
 * this function will look to the algorithmDetails. If the algId is not NULL, the
 * function will determine the details from it and ignore the algorithmDetails.
 * <p>If you do not pass in an algId, you must specify the algorithmDetails using
 * one of the MOC_ASYM_KEY_ALG_ flags defined.
 * <p>It is possible that the verification process will need to digest data (not
 * the data to verify, but some other data. See, for example Probabilistic
 * Signing Scheme, PSS, which is to RSA signatures what OAEP is to RSA
 * encryption). It is also possible that in the future, an algorithm might need a
 * supporting operation other than a digest, such as a mask generating function.
 * To perform any supporting operation needed, the Verify function will build an
 * object using the array of supported Operators found in the MocCtx (built
 * during the call to DIGICERT_initialize, the key object contains a reference to
 * the MocCtx). Make sure your arrays of supporting Operators contains the digest
 * Operators of algorithms needed by the signing processes you support.
 * <p>The caller passes in the address of a ubyte4, the function will deposit the
 * verification failures at that address. If, upon return, the value is 0, there
 * were no verification failures and the signature verifies. Otherwise, the value
 * will be set to one or more bits describing why the verification failed. The
 * possible values of the verification failure are the MOC_ASYM_VFY_FAIL_
 * #defines. If the result is 0, there were no failures and the signature
 * verifies. If the result is nonzero, the signature did not verify. You can then
 * look at the bits to determine why. Of course, you can simply compare to 0, if
 * zero, no failures (signature verifies), or non-zero, there was at least one
 * failure (signature does not verify).
 * <p>You can think of this result as similar to "memcmp". When memcmp returns 0,
 * the values match. If it is non-zero, the values do not match.
 * <p>Remember, the return value is success or failure of the function, not the
 * signature itself. The return from the function (MSTATUS) can be OK and the
 * verifyFailures is non-zero. In that case, the function worked, it did what it
 * was supposed to do, determine if the signature verified, so it returns OK, but
 * it sets the result of that operation, does not verify.
 *
 * @param pKey The key that will be used to verify.
 * @param pAlgId If not NULL, this specifies algorithm details and supporting
 * operations (pad, digest alg, etc.).
 * @param algIdLen The length, in bytes, of the algId.
 * @param algorithmDetails if pAlgId is NULL, the function will expect to find
 * one of the MOC_ASYM_KEY_ALG_ flags.
 * @param pAdditionalVfyInfo  A generalized structure that can be
 * optionally provided to override an Operator's default behavior.
 * @param RngFun A function pointer used to generate random bytes. To use a
 * randomContext, pass RANDOM_rngFun for this parameter and the randomContext
 * as the argument.
 * @param pRngFunArg The argument to the function pointer.
 * @param pMessage The input data, it is the data to sign.
 * @param messageLen The length, in bytes, of the input data.
 * @param pSignature The buffer containing the signature to verify.
 * @param signatureLen The length, in bytes, of the signature.
 * @param pVerifyFailures A bit field indicating what went wrong in the
 * verification process. Upon return, if this is set to 0, there were no
 * failures. Otherwise it is set to one or more MOC_ASYM_VFY_FAIL_ bits.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_asymVerifyMessage (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalVfyInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  );

/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the digest in the signature is not the same as
 * the digest provided. This is generally valid for RSA signatures, where the
 * digest is encrypted, so verification is a "memcmp".
 */
#define MOC_ASYM_VFY_FAIL_DIGEST              0x00000001
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the algorithm specified in the signature or
 * padding scheme is not the same algorithm specified in the verificaion function
 * (either the algId or algorithmDetails). This happens with RSA PKCS 1.5,
 * because the signature contains the digest info, which includes the algorithm's
 * OID. It also happens with RSA PSS when the digest algorithm used to digest the
 * actual data to sign is not the algorithm used in PSS operations (the PSS
 * standard requres using the same algorithm). It can also happen with other
 * signature schemes because some values are the wrong length.
 */
#define MOC_ASYM_VFY_FAIL_DIGEST_ALG          0x00000002
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because some element of the signature does not match
 * the  verification value. This is generally applicable with DSA or ECDSA,
 * because these algorithms compute values based on the digest and keys, and
 * compare these values, rather than comparing digests directly.
 */
#define MOC_ASYM_VFY_FAIL_VALUE               0x00000004
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the padding is incorrect. This is generally
 * applicable only with RSA, other algorithms might not pad.
 */
#define MOC_ASYM_VFY_FAIL_PAD                 0x00000010
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the padding bytes themselves are incorrect.
 * This is generally applicable only with RSA, other algorithms might not pad.
 */
#define MOC_ASYM_VFY_FAIL_PAD_BYTES           0x00000020
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the padding length is bad (e.g. too few pad
 * bytes). This is generally applicable only with RSA, other algorithms might not
 * pad.
 */
#define MOC_ASYM_VFY_FAIL_PAD_LEN             0x00000040
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the padding is PSS and the trailerField is not
 * the expected value. This is generally applicable only with RSA, other
 * algorithms might not pad.
 */
#define MOC_ASYM_VFY_FAIL_PAD_PSS_TF          0x00000080
/* A verification failed because there was a bad algorithm identifier. This will
 * likely happen in a cert, where an algId is in the data to sign and out.
 */
#define MOC_ASYM_VFY_FAIL_ALG_ID              0x00000100
/* A verification failed because a time was not valid. This is likely to happen
 * in a cert if a time to compare is outside the validity period.
 */
#define MOC_ASYM_VFY_FAIL_INVALID_TIME        0x00000200
/* A verification failed because a critical extension was missing. This is likely
 * to happen in a cert if the caller expects an extension to be present but it is
 * not.
 * <p>Note: This is for when the cert is missing an extension the caller believes
 * is critical
 */
#define MOC_ASYM_VFY_FAIL_EXT_MISSING         0x00000400
/* A verification failed because a critical extension in a cert was not readable
 * by any MCertExtension passed in.
 * <p>Note: This is for when the cert has a critical extension but the caller did
 * not supply the corresponding MCertExtension.
 */
#define MOC_ASYM_VFY_FAIL_EXT_CRITICAL        0x00000800
/* A verification failed because an extension's value was unexpected and wrong.
 * This is likely to happen in a cert verification.
 */
#define MOC_ASYM_VFY_FAIL_EXT_VALUE           0x00001000
/* A verification failed because a cert's BasicConstraints extension's value was
 * unexpected and wrong.
 */
#define MOC_ASYM_VFY_FAIL_BASIC_CONS          0x00002000
/* A verification failed because a cert's KeyUsage extension's value was
 * unexpected and wrong.
 */
#define MOC_ASYM_VFY_FAIL_KEY_USAGE           0x00004000
/* A verification failed because a cert's CertificateNameTemplate extension
 * value was unexpected and wrong.
 */
#define MOC_ASYM_VFY_FAIL_CERT_TEMPLATE_NAME  0x00008000
/* A verification failed because the issuer's cert could not be found.
 * This could be the direct CA, the CA's CA, or the root.
 */
#define MOC_ASYM_VFY_FAIL_NO_ISSUER_CERT      0x00100000
/* A verification failed because no cert in the chain was a trusted cert. This
 * can happen if all the certs are available, but none of them were declared
 * trusted.
 */
#define MOC_ASYM_VFY_FAIL_NO_TRUSTED_ROOT     0x00200000
/* A verification failed because some other cert in the chain failed.
 */
#define MOC_ASYM_VFY_FAIL_CHAIN               0x08000000
/* The CRYPTO_asymVerifyDigestInfo function will set this bit in the verifyResult value if
 * the verification fails because the verification process could not complete.
 */
#define MOC_ASYM_VFY_FAIL_INCOMPLETE          0x80000000

/** Generate a DH or ECDH shared secret using your private key and either the
 * other party's public key or public value.
 * <p>Diffie-Hellman in NanoCrypto is performed following this procedure.
 * <pre>
 * <code>
 *     // 1(a) Generate a key pair using standard params
 *
 *     MDhParams dhParams;
 *     DIGI_MEMSET (&dhParams, 0, sizeof (dhParams);
 *
 *     dhParams.StandardParams = DhParamsGroup14;
 *     status = CRYPTO_generateKeyPair (
 *       KeyOperatorDhSw, (void *)&dhParams, pMocCtx, g_pRandomContext,
 *       &pubKey, &priKey, &queue);
 *
 *     // 1(b) Generate a key pair using a public key. A correspondent has
 *     // initiated contact with you and sent their DH public key.
 *     dhParams.pPublicKey = &otherPartyPubKey;
 *     status = CRYPTO_generateKeyPair (
 *       KeyOperatorDhSw, (void *)&dhParams, pMocCtx, g_pRandomContext,
 *       &pubKey, &priKey, &queue);
 *
 *     // 2 Generate the shared secret.
 *     status = CRYPTO_computeSharedSecret (
 *       priKey, NULL, pOtherPartyPubValue, pubValLen,
 *       pSharedSecret, 256, &secretLen);
 * </code>
 * </pre>
 * <p>The caller specifies the private key and the other party's public value. The
 * function will perform Phase 2 of DH.
 * <p>The other party's public value is either represented as a MocAsymKey
 * object or as a byte array. The key object will contain the parametrs and the
 * public value. Ideally, you will probably want to use key objects. However,
 * it is possible that in certain situations, you will only have access to the
 * public value as a byte array.
 * <p>If the pPublicKey is not NULL, the function will expect to find an
 * appropriate key object and use it to perform phase 2. In this case, it will
 * ignore the pPublicValue and publicValueLen arguments.
 * <p>If the pPublicKey arg is NULL, the function will expect to find a public
 * value in the pPublicValue buffer and use it to perform phase 2.
 * <p>The caller supplies the buffer into which the function will deposit the
 * shared secret. The size of the buffer will be the same size as the DH modulus,
 * which is the security size. If the buffer is not big enough, the function will
 * return ERR_BUFFER_TOO_SMALL and set *pSecretLen to the required size.
 * <p>The function returns the "raw" secret value. Many standards specify that a
 * shared secret key is derived from the raw secret.
 *
 * @param pPrivateKey The caller's private key.
 * @param pPublicKey The correspondent's (other party's) public key. If NULL, the
 * function will expect to find the public value in the pPublicValue buffer.
 * @param pPublicValue The correspondent's (other party's) public value. This is
 * a byte array (the canonical value of the integer that is a public value).
 * @param publicValueLen The length, in bytes, of the correspondent's public
 * value.
 * @param pAdditionalVfyInfo  A generalized structure that can be
 * optionally provided to override the Operator's default behavior.
 * @param pSharedSecret The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pSecretLen The address where the function will place the required size
 * if the buffer is too small, or the number of bytes placed into the buffer, if
 * the buffer is big enough.
 * @param ppVlongQueue Optional, a vlong pool.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_computeSharedSecret (
  MocAsymKey pPrivateKey,
  MocAsymKey pPublicKey,
  ubyte *pPublicValue,
  ubyte4 publicValueLen,
  void *pAdditionalOpInfo,
  ubyte *pSharedSecret,
  ubyte4 bufferSize,
  ubyte4 *pSecretLen,
  struct vlong **ppVlongQueue
  );


/**
 * Performs encapsulation for a key encapsulation mechanism (KEM). This method
 * allocates two buffer so be sure to free these buffers when done.
 *
 * @param pPublicKey        Pointer to the public key to use for encapsulation.
 * @param rngFun            Function pointer to a random number generation function.
 * @param pRngFunArg        Input data or context into the random number generation function
 *                          pointer.
 * @param pCipherText       Buffer to hold the resulting ciphertext.
 * @param cipherTextLen     The length of the ciphertext buffer in bytes.
 * @param pSharedSecret     Buffer to hold the resulting shared secret.
 * @param sharedSecretLen   The length of the shared secret buffer in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_keyEncapsulate (
  MocAsymKey pPublicKey,
  RNGFun rngFun,
  void *pRngFunArg,
  ubyte *pCipherText,
  ubyte4 cipherTextLen,
  ubyte *pSharedSecret,
  ubyte4 sharedSecretLen
  );

/**
 * Performs decapsulation for a key encapsulation mechanism (KEM).
 *
 * @param pSecretKey        Pointer to the secret key to use for decapsulation.
 * @param pCipherText       Buffer holding the input ciphertext.
 * @param cipherTextLen     The length of the ciphertext in bytes.
 * @param pSharedSecret     Buffer to hold the resulting shared secret.
 * @param pSharedSecretLen  The length of the shared secret buffer in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_keyDecapsulate (
  MocAsymKey pSecretKey,
  ubyte *pCipherText,
  ubyte4 cipherTextLen,
  ubyte *pSharedSecret,
  ubyte4 pSharedSecretLen
  );

/** Serialize a MocAsymKey object.
 * <p>A MocAsymKey object knows how to serialize itself, this function simply
 * calls on the object to get the serialized data and then wraps that data
 * into the desired format if necessary.
 * <p>You specify the format of the serialized key with the format argument. It
 * will be one of the values specified in the serializedKeyFormat enum. Note that
 * not all keys will support all formats. For example, you won't be able to
 * serialize an RSAKey using eccPublicKeyDer. It's also possible that some keys
 * won't support all versions of the Mocana blob.
 * <p>Keys will not be able to be serialized into all formats. Certainly a public
 * key cannot be serialized into a private key DER. But it is also possible that
 * some key cannot be serialized into all Mocana Blob versions. Versions 0 and 1
 * are older versions and should not be used in new code. They are there for
 * backwards compatibility.
 *
 * <pre>
 * <code>
 *   ubyte4 serializedKeyLen;
 *   ubyte *pSerializedKey = NULL;
 *
 *   status = CRYPTO_serializeMocAsymKeyAlloc (
 *     pPubMocAsymKey, publicKeyInfoDer, &pSerializedKey, &serializedKeyLen);
 *   if (OK != status)
 *     goto exit;
 *
 * exit:
 *   DIGI_FREE ((void **)&pSerializedKey);
 * </code>
 * </pre>
 *
 * @param pKeyToSerialize The MocAsymKey you want serialized.
 * @param format The format into which you want the key to be serialized.
 * @param ppSerializedKey The address where the function will deposit a pointer
 * to allocated memory containing the serialized key. It is the responsiblity of
 * the caller to free that memory using DIGI_FREE.
 * @param pSerializedKeyLen the address where the function will deposit the
 * length, in bytes, of the serialized key.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_serializeMocAsymKeyAlloc (
  MocAsymKey pKeyToSerialize,
  serializedKeyFormat format,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

/** This is the same as CRYPTO_deserializeKey, except it takes a MocCtx
 * containing the arrays of MKeyOperator to build a MocAsymKey. That is, you can
 * deserialize a key without creating the MocAsymKey first.
 * <p>The function will cycle through the MKeyOperator list in the given MocCtx,
 * asking each if it can deserialize and build the MocAsymKey.
 * <p>For example,
 * <pre>
 *   MocAsymKey pAsymKey = NULL;
 *
 *   status = CRYPTO_deserializeMocAsymKey (
 *     pSerializedKey, serializedKeyLen,  pMocCtx, &pAsymKey, NULL);
 *   if (OK != status)
 *     goto exit;
 *
 *     . . .
 *
 * exit:
 *   CRYPTO_freeMocAsymKey (&pAsymKey, NULL);
 * <code>
 * </code>
 * </pre>
 *
 * @param pSerializedKey The input data.
 * @param serializedKeyLen The length, in bytes, of the input data.
 * @param pMocCtx The MocCtx built during the call to DIGICERT_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppDeserializedKey The location that will recieve the deserialized key.
 * @param ppVlongQueue Optional, a vlong pool available to the operator if it
 * wants it.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_deserializeMocAsymKey (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MocCtx pMocCtx,
  MocAsymKey *ppDeserializedKey,
  struct vlong **ppVlongQueue
  );

/** Get the algorithm ID of the algorithm for which the key was last used.
 * <p>NOTE! This is not the same as getting the DER encoding of the key data
 * itself. For that, call CRYPTO_serializeKey.
 * <p>This function will return the algId for things such as RSA Encryption with
 * OAEP, or ECDSA with SHA-256.
 * <p>An Algorithm Identifier (algId) is defined as
 * <pre>
 * <code>
 *   SEQUENCE {
 *     algorithm  OBJECT IDENTIFIER,
 *     ANY defined by algorithm }
 * </code>
 * </pre>
 * <p>This function will return the DER encoding of that ASN.1 definition.
 * <p>Some keys can be used for multiple operations. For example, an RSA key can
 * be used to encrypt or sign, and there are multiple possible padding schemes
 * and digest algorithms. Or an ECC key can be used to perform key exchange or
 * signatures.
 * <p>There are generally different OIDs and hence different algIds for the
 * different uses. After you use a key, you can get the algId. If you call for an
 * algId before using it, this function will return an error.
 * <p>For example, suppose you build a MocAsymKey that can perform RSA. You then
 * use it to encrypt using OAEP. Now call this function and you will get the
 * RSA-OAEP algId. Or suppose you build a MocAsymKey that can perform ECC, and use
 * it to sign using ECDSA with SHA-256. Call this function and get that algId.
 * <p>The caller passes in a buffer into which the function will place the AlgId.
 * If the buffer is too small, the function will return ERR_BUFFER_TOO_SMALL and
 * set *pAlgIdLen to the required size.
 * <p>This function returns the algId of the last operation. If the last
 * operation returned a BUFFER_TOO_SMALL error, then the algId will be the
 * algorithm of that operation. For example, if you call CRYPTO_asymSignDigestInfo with an
 * RSA key, and the algorithm indicates PSS, and the buffer is not big enough,
 * you can call this function to get the algId and it will return the value for
 * RSA with PSS.
 *
 * @param pKey The key built to perform some algorithm.
 * @param pAlgId The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the buffer.
 * @param pAlgIdLen The address where the function will deposit the length, in
 * bytes, of the algorithm Id.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getAsymAlgId (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 bufferSize,
  ubyte4 *pAlgIdLen
  );

/** Build a new MocAsymKey object using the given Operator.
 * <p>This function will create the MocAsymKey, then call on the Operator to build
 * the local data and set the localType.
 * <p>Call CRYPTO_freeMocAsymKey to free any memory. Note that freeMocAsymKey
 * will call on the KeyOperator to free any local data as well as freeing the
 * MocAsymKey struct.
 * <p>The caller can pass in a flag indicating whether the key is going to be a
 * public key or a private key. If you do not know in advance whether the key
 * will be public or private, pass in 0 (MOC_ASYM_KEY_TYPE_UNKNOWN) for the
 * typeFlag arg. Otherwise, pass in MOC_ASYM_KEY_TYPE_PUBLIC or
 * MOC_ASYM_KEY_TYPE_PRIVATE.
 * <p>For some implementations, a public and private key might have different
 * implementations, so it is good to know which is being built. For example, a
 * hardware implementation might actually use software for public key operations
 * and hardware for private key operations.
 * <p>It is possible the implementations are the same, but in case they are not,
 * you should use this flag if you know the key object will be used to hold a
 * public key.
 * <p>The caller passes in any associated info the Operator might need. If it
 * needs something, the Operator will likely need a hardware handle or a "helper"
 * function (e.g. special curve information for an ECC implementation). However,
 * it is also possible an Operator needs nothing (pass in NULL), because the
 * Operator itself will manage any handles or supporting functions. Check the
 * documentation for each Operator to find out what, if any, info you need to
 * pass in.
 * <p>The caller passes in the address of a MocAsymKey. The function will go to
 * that address and deposit the newly created context.
 * <p>For example.
 * <pre>
 * <code>
 *   MSTATUS status;
 *   MocAsymKey pNewKey = NULL;
 *
 *   status = CRYPTO_createMocAsymKey (
 *     SomeHwOperator, NULL, pMocCtx, MOC_ASYM_KEY_TYPE_PRIVATE, &pNewKey);
 *   if (OK != status)
 *     goto exit;
 *
 *      . . .
 *
 * exit:
 *
 *   CRYPTO_freeMocAsymKey (&pNewKey);
 * </code>
 * </pre>
 *
 * @param KeyOperator The Operator function the ctx will use.
 * @param pOperatorInfo If the operator function needs some info in order to
 * work, pass it in here. See the documentation for each Operator to determine
 * what info it needs.
 * @param pMocCtx The MocCtx built during the call to DIGICERT_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppNewKey The address where the function will deposit the newly
 * built MocAsymKey.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_createMocAsymKey (
  MKeyOperator KeyOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  ubyte4 typeFlag,
  MocAsymKey *ppNewKey
  );

#define MOC_ASYM_KEY_TYPE_UNKNOWN   0
#define MOC_ASYM_KEY_TYPE_PUBLIC    1
#define MOC_ASYM_KEY_TYPE_PRIVATE   2

/** Make a clone or copy of an existing MocAsymKey object.
 * <p>This does not return a reference, but a full new clone of the key object.
 * It is the callers responsibility to free the new key with CRYPTO_freeMocAsymKey.
 *
 * <pre>
 * <code>
 *   MocAsymKey pKey = NULL;
 *   MocAsymKey pNewKey = NULL;
 *
 *   // pKey is populated with a valid key
 *
 *   status = CRYPTO_cloneMocAsymKey(pKey, &pNewKey);
 *   if (OK != status)
 *     goto exit;
 *
 *   . . .
 *
 * exit:
 *   CRYPTO_freeMocAsymKey(&pNewKey, NULL);
 * </code>
 * </pre>
 *
 * @param pKeyToClone Pointer to an existing MocAsymKey to be cloned.
 * @param ppClonedKey Pointer to the location that will recieve the cloned key.
 * @param ppVlongQueue The vlong queue to use.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_cloneMocAsymKey (
  MocAsymKey pKeyToClone,
  MocAsymKey *ppClonedKey,
  vlong **ppVlongQueue
  );

/** Get the "local" key out of a MocAsymKey. This returns a reference to the key,
 * not a copy or clone.
 * <p>This will likely only be used by hardware keys.
 * <p>For example, the local key for an operator that performs RSA in software is
 * a pointer to RSAKey. Similarly, the local key for an operator that performs
 * ECC in software is a pointer to an ECCKey.
 * <p>However, the local key for an operator that performs RSA on a TPM will
 * likely be a TAPKey (or some other type).
 * <p>Check the documentation for each Operator to find out what the local type
 * is.
 * <p>This is most likely useful when you need to perform an operation not
 * defined as a MocAsymKey function. For example, suppose you have a hardware key
 * and want to associate an authentication token with that key, allowing it to
 * perform certain operations. There is no CRYPTO_ function to do that. So you
 * will have to call the hardware API to perform that function. That function
 * will require the key as some other type, not a MocAsymKey.
 * <p>It is likely that anything you need to do with a MocAsymKey will be
 * something from the CRYPTO_ API (such as CRYPTO_asymSignDigestInfo or
 * CRYPTO_getSecuritySize), however, for some applications, you might need to
 * perform some operation unique to the type. In that case, use the local key.
 * <p>And remember, this function returns a reference to the local key, not a
 * copy.
 * <p>For example,
 * <pre>
 * <code>
 *    TAPKey *pLocalKey = NULL;
 *
 *    status = CRYPTO_getLocalKeyReference (
 *      pAsymKey, (void **)&pLocalKey);
 * </code>
 * </pre>
 *
 * @param pKey The MocAsymKey object from which the local key will be returned.
 * @param ppLocalKey The address where the function will deposit the reference to
 * the local key.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getLocalKeyReference (
  MocAsymKey pKey,
  void **ppLocalKey
  );

/**
 * Construct a new public key from an existing private key.
 * This function can only be used by MocAsymKeys.
 * <pre>
 * <code>
 *    MocAsymKey priKey = NULL;
 *    MocAsymKey pubKey = NULL;
 *
 *    // priKey is populated with data
 *
 *    status = CRYPTO_getPubFromPri (priKey, &pubKey, NULL);
 * </code>
 * </pre>
 *
 * @param pPriKey      Pointer to an existing private MocAsymKey.
 * @param ppPubKey     Pointer to the location that will be populated with a new
 *                     public MocAsymKey object from the private key.
 * @param ppVlongQueue The vlong queue to use.
 * @return         \c OK (0) if successful; otherwise a negative number error code
 *                 definition from merrors.h. To retrieve a string containing an
 *                 English text error identifier corresponding to the function's
 *                 returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getPubFromPri (
  MocAsymKey pPriKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  );

/** Get a flag indicating what the algorithm of the key is.
 * <p>This sets *pAlgFlag to one of the akt_ values defined in ca_mgmt.h:
 * akt_rsa, akt_ecc, akt_dsa, akt_dh.
 * <p>If the key is NULL, or is not set, or for some other reason the function
 * cannot determine the algorithm, the function sets *pAlgFlag to akt_undefined
 * and returns OK.
 *
 * @param pKey The key object to query.
 * @param pAlgFlag The address where the function will deposit the flag
 * indicating the key's algorithm.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getAlgorithmFlag (
  MocAsymKey pKey,
  ubyte4 *pAlgFlag
  );

/* param inputs for CRYPTO_getDomainParam. More can be adeded as needed */
#define MOC_ASYM_KEY_PARAM_PUBKEY_LEN       1
#define MOC_ASYM_KEY_PARAM_CIPHERTEXT_LEN   2
#define MOC_ASYM_KEY_PARAM_SHAREDSECRET_LEN 3
#define MOC_ASYM_KEY_PARAM_SIGNATURE_LEN    4
#define MOC_ASYM_KEY_PARAM_PRIKEY_LEN       5

/** Gets a domain parameter's value from a MocAsymKey
 *
 * @param pKey  The key object to query.
 * @param param One of the following macros representing which parameter to obtain
 *
 *              MOC_ASYM_KEY_PARAM_PUBKEY_LEN
 *              MOC_ASYM_KEY_PARAM_CIPHERTEXT_LEN
 *              MOC_ASYM_KEY_PARAM_SHAREDSECRET_LEN
 *              MOC_ASYM_KEY_PARAM_SIGNATURE_LEN
 *
 * @paramValue  Contents will be set to the value of the parameter requested.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getDomainParam (
  MocAsymKey pKey,
  ubyte4 param,
  ubyte4 *pParamValue
  );

/** Determine if the DER encoding of the public key provided is the same as the
 * public key object.
 * <p>This function is generally used to determine if a key in a cert is the same
 * as an existing key in an object.
 * <p>The caller supplies a key object containing a public key. This must be a
 * MocAsymKey and it must be a public key, it cannot be a private key.
 * <p>The key data to compare must be the DER encoding of SubjectPublicKeyInfo
 * (how a public key is encoded inside a cert). No other encoding is allowed.
 * <p>The caller also supplies a pointer to an intBoolean. The function will
 * deposit the result of the comparison there. If the keys do not match
 * (differnet algorithms or smae algorithm but with different data), the function
 * will set it to FALSE. If they do match, it will set it to TRUE.
 *
 * @param pPubKey A public key object.
 * @param pDerPubKey The DER encoding of SubjectPublicKeyInfo
 * @param derPubKeyLen The length, in bytes, of the DER encoded key.
 * @param pIsMatch The address where the function will deposit the result of the
 * comparison, TRUE for the same key, FALSE otherwise.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_isMatchingKey (
  MocAsymKey pPubKey,
  ubyte *pDerPubKey,
  ubyte4 derPubKeyLen,
  intBoolean *pIsMatch
  );

/** Validate that a given private and public key pair are consistent. For
 * example, calling this function with two ECC keys will validate that
 * k * P = Q.
 *
 * @param pPrivateKey The private key to be checked.
 * @param pPublicKey  The public key to be checked.
 * @param pMatch      Pointer to a byteBoolean that will recieve a boolean
 *                    indication of if these keys are consistent.
 *
 * @return            \c OK (0) if successful; otherwise a negative
 *                    number error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_validatePubPriMatch (
  MocAsymKey pPrivateKey,
  MocAsymKey pPublicKey,
  byteBoolean *pMatch
  );

/** Determine if the provided key object is valid.  For example, calling this
 * function on an ECC key will verify that the public point lies on the curve.
 *
 * @param pKey
 * @param pIsValid Pointer to the byteBoolean that will recieve the result of
 *                 the validation, TRUE if the key is valid, FALSE otherwise.
 *
 * @return         \c OK (0) if successful; otherwise a negative number error
 *                 code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_validateKey (
  MocAsymKey pKey,
  byteBoolean *pIsValid
  );

/** Get an Asymmetric key object from an index into the provided MocCtx.
 *
 * @param index The index of the operator in the MocCtx to be created.
 * @param pMocCtx The MocCtx to use for this operation.
 * @param pOpInfo The optional associated info to use for creation, if NULL
 * then the info from the MocCtx will be used.
 * @param keyType The type of key to create (none, public or private).
 * @param ppObj Pointer to the location that will recieve the new MocAsymKey.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getAsymObjectFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  void *pOpInfo,
  ubyte4 keyType,
  MocAsymKey *ppObj
  );

/** Get an Asymmetric Key Operator and its associated info from an index
 * into the provided MocCtx.
 *
 * @param index The index of the operator in the MocCtx to be retrieved.
 * @param pMocCtx The MocCtx to use for this operation.
 * @param ppKeyOperator Pointer to the location that will recieve the
 * MKeyOperator for the provided index.
 * @param ppOperatorInfo Pointer to the location that will recieve the
 * operator info for the provided index.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getAsymOperatorAndInfoFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  MKeyOperator *ppKeyOperator,
  void **ppOperatorInfo
  );

/** Update operator associated data for a MocAsymKey.
 * <p>This function is infrequently used to update the operator data for
 * a particular MocAsymKey object. The update data structure will always be the same
 * structure used for object creation. This is usually used to accomodate unique
 * situations or facilitate uncommon functionality.
 *
 * @param pKey       The object that will recieve the updated operator data.
 * @param pOperatorData Pointer to implementation dependent structure containing
 *                   the new associated info to update.
 *
 * @return           \c OK (0) if successful; otherwise a negative number error
 *                   code definition from merrors.h. To retrieve a string
 *                   containing an English text error identifier corresponding
 *                   to the function's returned error status, use
 *                   the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_updateAsymOperatorData (
  MocAsymKey pKey,
  void *pOperatorData
  );

/**
 * Retrieve the standard, per-algorithm key parameters from the MocAsymKey.
 * The type of parameters retrieved are based on what key type is passed in for
 * the keyType param (typically public or private).
 * These parameters will be allocated and loaded into the standard,
 * per-algorithm, template structure. The parameters within the template will
 * be stored as byte-strings (as opposed to vlongs), which this function will
 * allocate. It is therefore the caller's responsibility to call the template's
 * accompanying free-function. The specific name of the free-function should be
 * in the documentation for the template structure (mocasym.h is a good place to
 * check first).
 *
 * @param [in]    pKey            Pointer to the MocAsymKey we are pulling the
 *                                parameters from.
 *
 * @param [out]   pOperatorData   Pointer to the standard, per-algorithm key
 *                                parameters template structure.
 *
 * @param [in]    keyType         Flag that will determine what type of key data
 *                                is retrieved.
 *
 * @return           \c OK (0) if successful; otherwise a negative number error
 *                   code definition from merrors.h. To retrieve a string
 *                   containing an English text error identifier corresponding
 *                   to the function's returned error status, use
 *                   the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getKeyDataAlloc (
  MocAsymKey pKey,
  void *pOperatorData,
  ubyte keyType
  );


/**
 * Free the internal byte-string buffers located within the standard,
 * per-algorithm key parameters template stucture.
 *
 * @param [in]  pOperatorData   Pointer to the standard, per-algorithm key
 *                              parameters template structure.
 *
  * @return           \c OK (0) if successful; otherwise a negative number error
 *                   code definition from merrors.h. To retrieve a string
 *                   containing an English text error identifier corresponding
 *                   to the function's returned error status, use
 *                   the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_freeKeyTemplate (
  MocAsymKey pKey,
  void *pOperatorData
  );

/**
 * Fill in the MocAsymKey's standard key parameters using information from the
 * standard, per-algorithm, template structure (pOperatorData). The template
 * structure must be filled using CRYPTO_getKeyDataAlloc. If there is no
 * underlying key structure located within the MocAsymKey, the function will
 * allocate one.
 *
 * @param [in,out]   pKey            Pointer to the MocAsymKey whose parameters
 *                                   are to be filled.
 *
 * @param [in]       pOperatorData   Pointer to the standard, per-algorithm key
 *                                   parameter template structure which the
 *                                   parameters will be pulled from.
 *
 * @return           \c OK (0) if successful; otherwise a negative number error
 *                   code definition from merrors.h. To retrieve a string
 *                   containing an English text error identifier corresponding
 *                   to the function's returned error status, use
 *                   the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_setKeyData (
  MocAsymKey pKey,
  void *pOperatorData
  );

#ifdef __cplusplus
}
#endif

#endif /* __CAP_ASYMMETRIC_HEADER__ */
