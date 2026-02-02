/*
 * moccms_encode.h
 *
 * Internal Declarations and Definitions for the Mocana CMS Encoder
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

/**
@file       moccms_encode.h

@brief      Header file for the Mocana SoT Platform API for
              Cryptographic Message Syntax (CMS) support.
              DO NOT include in any source code using the public API!

@filedoc    moccms_encode.h
*/

#ifndef __DIGICERT_CMS_ENCODE_HEADER__
#define __DIGICERT_CMS_ENCODE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** A 'generic' data array containing a byte array and the length of that array
 *
 */
typedef struct MOC_CMS_Array
{
    ubyte* pData;
    ubyte4 dataLen;
} MOC_CMS_Array;

/** A structure to describe a CMS 'Signer'.
 *
 */
typedef struct MOC_CMS_SignerCtx
{
    ubyte*               cert;
    ubyte4               certLen;
    MOC_CMS_action       flags;
    const AsymmetricKey* pKey;
    ubyte*               digestAlgoOID;
    ubyte4               digestAlgoOIDLen;
    ubyte*               signature;
    ubyte4               signatureLen;
    ubyte*               digest;
    ubyte4               digestLen;
    ubyte4               numAuthAttr;
    MOC_CMS_Attribute**  pAuthAttr; /* [numAuthAttr] */
    ubyte4               numUnauthAttr;
    MOC_CMS_Attribute**  pUnauthAttr; /* [numUnauthAttr] */
    hwAccelDescr         hwAccelCtx;
} MOC_CMS_SignerCtx;

/** The context structure for encoding a 'signed' CMS.
 *
 */
typedef struct MOC_CMS_OUT_SignedCtx
{
    MAsn1Element*        pRoot;
    ubyte2               idxOID;
    ubyte2               idxVersion;
    ubyte2               idxDigest;
    ubyte2               idxPkgOID;
    ubyte2               idxPkgData;
    ubyte2               idxCerts;
    ubyte2               idxCRLs;
    ubyte2               idxSigners;
    sbyte4               numSigners;
    MOC_CMS_SignerCtx**  pSigners; /*[numSigners]*/
    ubyte4               numAlgos;
    MOC_CMS_SignedDataHash* pHashes; /* [numAlgos] */
    intBoolean           hashesDone;
    sbyte4               numAddedCerts;
    MOC_CMS_Array**      pAddedCerts; /* [numAddedCerts] */
    sbyte4               numCRLs;
    MOC_CMS_Array**      pCRLs; /* [numCRLs] */
    sbyte4               numAddedDigests;
    MOC_CMS_Array**      pAddedDigests; /* [numAddedDigests] */
    sbyte4               numAddedRawSigs;
    MOC_CMS_Array**      pAddedRawSigs; /* [numAddedRawSigs] */
    hwAccelDescr         hwAccelCtx;
} MOC_CMS_OUT_SignedCtx;

/** The context structure for encoding an 'enveloped' CMS.
 *
 */
typedef struct MOC_CMS_OUT_EnvelopCtx
{
    MAsn1Element*        pRoot;
    ubyte2               idxOID;
    ubyte2               idxVersion;
    ubyte2               idxOrigin;
    ubyte2               idxRecipients;
    ubyte2               idxPkgOID;
    ubyte2               idxAlgo;
    ubyte2               idxPkg;
    ubyte2               idxAttr;
    ubyte4               version;
    RNGFun               encrRngFun;
    void*                encrRngArg;
    ubyte                iv[MAX_IV_LENGTH];
    ubyte4               encrKeyLen;
    ubyte                encryptKey[MAX_ENC_KEY_LENGTH]; /* big enough for AES-256 */
    BulkCtx              pBulkCtx;
    const BulkEncryptionAlgo* pBulkAlgo;
    ubyte                last[MAX_IV_LENGTH];
    ubyte4               last_size;
    intBoolean           firstDone;
    sbyte4               numRecipients;
    MOC_CMS_Array**      pRecipients; /* [numRecipients] */
    ubyte4               numAttributes;
    MOC_CMS_Attribute**  pUnauthAttributes; /* [numAttributes] */
    hwAccelDescr         hwAccelCtx;
} MOC_CMS_OUT_EnvelopCtx;

/** The 'union' overlaying context structures of different types for CMS
 *  writing.
 *  <p>Depending on the type of CMS messages (see also <code>MOC_CMS_ContentType</code>),
 *  one of these union members is used.
 */
typedef union MOC_CMS_OUT_TypeCtx
{
    MOC_CMS_OUT_SignedCtx  sign;
    MOC_CMS_OUT_EnvelopCtx env;
} MOC_CMS_OUT_TypeCtx;

/** The CMS context to create an ASN1 encoded message.
 *
 */
typedef struct MOC_CMS_OUT_CTX
{
    ubyte                    mag;
    hwAccelDescr             hwAccelCtx;
    RNGFun                   rngFun;
    void*                    rngArg;
    MOC_CMS_UpdateData       cb;
    const void*              cbArg;
    MOC_CMS_ContentType      contentType;
    MOC_CMS_StreamType       streamType;
    ubyte4                   payloadLen;
    intBoolean               lastDone;
    MOC_CMS_ASN1_Memory*     pAsn1Mem;
    MOC_CMS_OUT_TypeCtx*     pUn;
#ifdef __ENABLE_DIGICERT_RE_SIGNER__
    void*                    pResData;
#endif
} MOC_CMS_OUT_CTX;

/****************************************************************************/

/**
 * @brief Function to delete the 'typed' internal context for writing CMS
 * data.
 * @details Function to delete the 'typed' internal context for writing CMS
 * data.
 *
 * @param pCtx  The pointer to a 'MOC_CMS_OUT_CTX' instance.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN void
DIGI_CMS_deleteContextOut(MOC_CMS_OUT_CTX* pCtx);

/** 
 * @brief Function to create a specific context for 'signed' CMS data output.
 * @details Function to create a specific context for 'signed' CMS data output.
 *  <p>The new context is stored in the given 'MOC_CMS_OUT_CTX' instance.
 *  <p>The 'pUn' pointer in that context must be accessed as a 'MOC_CMS_OUT_SignedCtx*' after
 *     this function is finished.
 *
 * @param pCtx      The pointer to a 'MOC_CMS_OUT_CTX' instance.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_createSignContextOut(MOC_CMS_OUT_CTX *pCtx);

/** 
 * @brief Function to delete a 'MOC_CMS_OUT_SignedCtx' instance.
 * @details Function to delete a 'MOC_CMS_OUT_SignedCtx' instance.
 *  <p>All memory held by this instance will be 'freed'.
 *
 * @param pCtx      A pointer to a 'MOC_CMS_OUT_SignedCtx' instance, which will be freed and
 *                  the pointer will be set to NULL.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_deleteSignContextOut(MOC_CMS_OUT_SignedCtx *pCtx);

/** 
 * @brief Function to create a specific context for 'envelop' CMS data output.
 * @details Function to create a specific context for 'envelop' CMS data output.
 *  <p>The new context is stored in the given 'MOC_CMS_OUT_CTX' instance.
 *  <p>The 'pUn' pointer in that context must be accessed as a 'MOC_CMS_OUT_EnvelopCtx*' after
 *     this function is finished.
 *
 * @param pCtx      The pointer to a 'MOC_CMS_OUT_CTX' instance.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_createEnvelopContextOut(MOC_CMS_OUT_CTX *pCtx);

/** 
 * @brief Function to delete a 'MOC_CMS_OUT_EnvelopCtx' instance.
 * @details Function to delete a 'MOC_CMS_OUT_EnvelopCtx' instance.
 *  <p>All memory held by this instance will be 'freed'.
 *
 * @param pCtx      A pointer to a 'MOC_CMS_OUT_EnvelopCtx' instance, which will be freed and
 *                  the pointer will be set to NULL.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_deleteEnvelopContextOut(MOC_CMS_OUT_EnvelopCtx *pCtx);

/** 
 * @brief Stream more ASN1 payload data for the given context, which represents a
 *  'signed' CMS message.
 * @details Stream more ASN1 payload data for the given context, which represents a
 *  'signed' CMS message.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *
 * @param pCtx      A pointer to the context instance to be used.
 * @param pData     The ASN1 data string with (more) payload data.
 * @param dataLen   The length of the ANS1 data string.
 * @param last      Signals that this is the last payload data being streamed, when set
 *                   to \c TRUE.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_writeSigned(MOC_CMS_OUT_CTX *pCtx,
                    const ubyte *pData,
                    ubyte4 dataLen,
                    intBoolean last);

/** 
 * @brief Create the final ASN1 data for a complete CMS structure for the given context,
 * which represents a 'signed' CMS message.
 * @details Create the final ASN1 data for a complete CMS structure for the given context,
 * which represents a 'signed' CMS message.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *
 * @param pCtx      A pointer to the context instance to be used.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_finalizeSigned(MOC_CMS_OUT_CTX *pCtx);

/** 
 * @brief Stream more ASN1 payload data for the given context, which represents an
 *  'envelop' CMS message.
 * @details Stream more ASN1 payload data for the given context, which represents an
 *  'envelop' CMS message.
 *  <p>This function will fail, if the context does not process a 'envelop' CMS.
 *
 * @param pCtx      A pointer to the context instance to be used.
 * @param pData     The ASN1 data string with (more) payload data.
 * @param dataLen   The length of the ANS1 data string.
 * @param last      Signals that this is the last payload data being streamed, when set
 *                  to \c TRUE.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_writeEnvelop(MOC_CMS_OUT_CTX *pCtx,
                     const ubyte *pData,
                     ubyte4 dataLen,
                     intBoolean last);

/** 
 * @brief Create the final ASN1 data for a complete CMS structure for the given context,
 * which represents an 'envelop' CMS message.
 * @details Create the final ASN1 data for a complete CMS structure for the given context,
 * which represents an 'envelop' CMS message.
 *  <p>This function will fail, if the context does not process a 'envelop' CMS.
 *
 * @param pCtx      A pointer to the context instance to be used.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_finalizeEnvelop(MOC_CMS_OUT_CTX *pCtx);

/** 
 * @brief Add an 'attribute' to the CMS output by adding its data to the \c MOC_CMS_SignerCtx instance.
 * @details Add an 'attribute' to the CMS output by adding its data to the \c MOC_CMS_SignerCtx instance.
 *  An 'attribute' contains an OID string and a value. The value is placed inside an ASN1 'SETOF', and
 *  its 'type id' and actual value is provided by the caller (e.g. \c MASN1_TYPE_INTEGER).
 *  A flag signals whether this 'attribute' should belong the the 'authenticated' set or the
 *  'unauthenticated' set.
 *
 * @param pSigner        A pointer to the \c MOC_CMS_SignerCtx instance to which the attribute
 *                       is added.
 * @param authenticated  An \c intBoolean signaling if the attribute should be added as 'authenticated'
 *                       or not.
 * @param pOID           A pointer to the OID value to be used.
 * @param oidLen         The length of the OID value in bytes.
 * @param typeId         The MOCASN1 type id of the data (see mocasn1.h).
 * @param pVal           A pointer to a byte array that hold the value;
 * @param valLen         The length of the value array in bytes.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_addAttribute(MOC_CMS_SignerCtx *pSigner,
                     intBoolean        authenticated,
                     const ubyte       *pOID,
                     ubyte4            oidLen,
                     ubyte4            typeId,
                     const ubyte       *pVal,
                     ubyte4            valLen);

/** 
 * @brief A function to create an ASN1 encoded byte array from the 'type id' and value data given as
 *  input.
 * @details A function to create an ASN1 encoded byte array from the 'type id' and value data given as
 *  input.
 *
 * @param typeID    The MOCASN1 type id of the data (see mocasn1.h).
 * @param value     A pointer to a byte array that hold the value;
 * @param valueLen  The length of the value array in bytes.
 * @param pAttr     A pointer to a \c MOC_CMS_Attribute instance, where the encoded data will
 *                  be stored.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_makeASN1FromAttribute(ubyte4 typeID,
                              const ubyte* value,
                              ubyte4 valueLen,
                              MOC_CMS_Attribute* pAttr);

/** 
 * @brief A function to create the crypto algorithm for encrypting an enveloped CMS payload.
 * @details A function to create the crypto algorithm for encrypting an enveloped CMS payload.
 *
 * @param pOID      A pointer to the OID value to be used.
 * @param oidLen    The length of the OID value in bytes.
 * @param pMem      A pointer to the memory structure to be used.
 * @param pCtx      A pointer to the context instance to be used.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_createBulkAlgo(MOC_SYM(hwAccelDescr hwAccelCtx)
                       ubyte  *pOID,
                       ubyte4 OIDLen,
                       MOC_CMS_ASN1_Memory    *pMem,
                       MOC_CMS_OUT_EnvelopCtx *pCtx);

#ifdef __cplusplus
}
#endif

#endif  /* __DIGICERT_CMS_ENCODE_HEADER__ */
