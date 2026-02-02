/*
 * moccms_decode.h
 *
 * Internal Declarations and Definitions for the Mocana CMS Decoder
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
@file       moccms_decode.h

@brief      Header file for the Mocana SoT Platform API for
              Cryptographic Message Syntax (CMS) support.
              DO NOT include in any source code using the public API!

@filedoc    moccms_decode.h
*/

#ifndef __DIGICERT_CMS_DECODE_HEADER__
#define __DIGICERT_CMS_DECODE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** This is the context structure when parsing a CMS-signed ASN1 string.
 *
 */
typedef struct MOC_CMS_SignedCtx
{
    MAsn1Element*        asnSign;
    MAsn1Element*        asnRawDef;
    MAsn1Element*        asnRawIndef;
    MOC_CMS_CollectData* pCrypto;
    MOC_CMS_CollectData* pCerts;
    MOC_CMS_CollectData* pCRLs;
    MOC_CMS_CollectData* pDigest;
    MOC_CMS_CollectData* pPkgOid;
    ubyte2               idxEnv;
    ubyte2               idxDataOid;
    ubyte2               idxAlgo;
    ubyte2               idxCerts;
    ubyte2               idxCRLs;
    ubyte2               idxDigest;
    ubyte2               idxRaw;
    intBoolean           streaming;
    ubyte*               stream_data;
    ubyte4               stream_data_len;
    ubyte4               numSigners;
    ubyte4               numValidSigs;
    MOC_CMS_MsgSignInfo* pSigners; /* [numValidSigs] */
    ubyte4               numAlgos;
    MOC_CMS_SignedDataHash* pHashes; /* [numAlgos] */
    intBoolean           hashesDone;
    intBoolean           finished;
    intBoolean           signFinished;
    hwAccelDescr             hwAccelCtx;
} MOC_CMS_SignedCtx;

/** This is the context structure when parsing a CMS-enveloped ASN1 string.
 *
 */
typedef struct MOC_CMS_EnvelopCtx
{
    MAsn1Element*        asnCrypto;
    MAsn1Element*        asnRaw;
    MAsn1Element*        asnRawImpl;
    MOC_CMS_CollectData* pRecipient;
    MOC_CMS_CollectData* pPkgOid;
    MOC_CMS_CollectData* pCryptoA;
    MOC_CMS_CollectData* pCryptoI;
    ubyte2               idxEnv;
    ubyte2               idxCrypRecipient;
    ubyte2               idxCrypDataOID;
    ubyte2               idxCrypAlgo;
    ubyte2               idxCrypIV;
    ubyte2               idxCrypRaw;
    intBoolean           streaming;
    ubyte*               stream_data;
    ubyte4               stream_data_len;
    ubyte*               held_data;
    ubyte4               held_data_len;
    ubyte                iv[MAX_IV_LENGTH];
    BulkCtx              pBulkCtx;
    const BulkEncryptionAlgo*  pBulkAlgo;
    ubyte                last[MAX_IV_LENGTH];
    ubyte4               last_size;
    intBoolean           last_done;
    sbyte4               numRecipients;
    MOC_CMS_RecipientId** pRecipients; /* [numRecipients] */
    hwAccelDescr          hwAccelCtx;
} MOC_CMS_EnvelopCtx;

/** The 'union' overlaying context structures of different types for CMS
 *  parsing.
 *  <p>Depending on the type of CMS messages (see also <code>MOC_CMS_ContentType</code>),
 *  one of these union members is used.
 */
typedef union MOC_CMS_TypeCtx
{
    MOC_CMS_SignedCtx  sign;
    MOC_CMS_EnvelopCtx env;
} MOC_CMS_TypeCtx;


/** The CMS context to parse an ASN1 encoded message.
 *
 */
typedef struct MOC_CMS_CTX
{
    ubyte                    mag;
    hwAccelDescr             hwAccelCtx;
    const MOC_CMS_Callbacks* cb;
    const void*              cbArg;
    MOC_CMS_ContentType      contentType;
    MAsn1Element*            pRootEnv;
    ubyte4                   idxEnvOID;
    ubyte4                   idxEnvContent;
    MOC_CMS_StreamType       streamType;
    MOC_CMS_CollectData*     pOidData;
    intBoolean               lastDone;
    MOC_CMS_TypeCtx*         pUn;
    void*                    pResData;
} MOC_CMS_CTX;

/*******************************************************************************/

/** 
 * @brief Function to delete the 'typed' internal context for parsing CMS
 *         data.
 * @details Function to delete the 'typed' internal context for parsing CMS
 *          data.
 *
 * @param pCtx  The pointer to a 'MOC_CMS_CTX' instance.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN void
DIGI_CMS_deleteContextIn(MOC_CMS_CTX* pCtx);

/** 
 * @brief Function to 'clone' a 'MOC_CMS_MsgSignInfo' instance, making a 'deep copy'.
 * @details Function to 'clone' a 'MOC_CMS_MsgSignInfo' instance, making a 'deep copy'.
 *
 * @param pOut The pointer to the output instance.
 * @param pIn  The pointer to the input instance.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_cloneSigner(MOC_CMS_MsgSignInfo* pOut,
                    const MOC_CMS_MsgSignInfo* pIn);

/** 
 * @brief Function to 'clone' a 'MOC_CMS_KeyTransRecipientId' instance, making a 'deep copy'.
 * @details Function to 'clone' a 'MOC_CMS_KeyTransRecipientId' instance, making a 'deep copy'.
 *
 * @param pOut The pointer to the output instance.
 * @param pIn  The pointer to the input instance.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_cloneKTRid(MOC_CMS_KeyTransRecipientId* pOut,
                   const MOC_CMS_KeyTransRecipientId* pIn);

/** 
 * @brief Function to 'clone' a 'MOC_CMS_KeyAgreeRecipientId' instance, making a 'deep copy'.
 * @details Function to 'clone' a 'MOC_CMS_KeyAgreeRecipientId' instance, making a 'deep copy'.
 *
 * @param pOut The pointer to the output instance.
 * @param pIn  The pointer to the input instance.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_cloneKARid(MOC_CMS_KeyAgreeRecipientId* pOut,
                   const MOC_CMS_KeyAgreeRecipientId* pIn);

/** 
 * @brief Function to 'free' a 'MOC_CMS_KeyTransRecipientId' instance, releasing all held memory.
 * @details Function to 'free' a 'MOC_CMS_KeyTransRecipientId' instance, releasing all held memory.
 *
 * @param pData The pointer to the instance to be freed.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_freeKTRid(MOC_CMS_KeyTransRecipientId* pData);

/** 
 * @brief Function to 'free' a 'MOC_CMS_KeyAgreeRecipientId' instance, releasing all held memory.
 * @details Function to 'free' a 'MOC_CMS_KeyAgreeRecipientId' instance, releasing all held memory.
 *
 * @param pData The pointer to the instance to be freed.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_freeKARid(MOC_CMS_KeyAgreeRecipientId* pData);


/** 
 * @brief Update the ASN1 data for the given context, which represents a 'signed' CMS
 *  message.
 * @details Update the ASN1 data for the given context, which represents a 'signed' CMS
 *  message.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *  <p>Only one of the two input 'containers' is used:
 *   <ul>
 *   <li>The ASN1 data string given by the user (pData/dataLen);
 *   <li>The ASN1 encoded data inside an 'indefinite' sequence (pInfo);
 *  </ul>
 *
 * @param pCtx    A pointer to the context instance to be used.
 * @param pData   The ASN1 data string with the update.
 * @param dataLen The length of the ANS1 data string.
 * @param pInfo   The encoded ASN1 data when an 'indefinite' format is used,
 *                 held by a 'MOC_CMS_DataInfo' instance.
 * @param last    \c TRUE if this is the last chunk of data to be processed.
 *                 \c FALSE otherwise.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_parseSigned(MOC_CMS_CTX *pCtx,
                    const ubyte *pData,
                    ubyte4 dataLen,
                    MOC_CMS_DataInfo *pInfo,
                    intBoolean last);

/** 
 * @brief Update the ASN1 data for the given context, which represents a 'envelope' CMS
 *  message.
 * @details Update the ASN1 data for the given context, which represents a 'envelope' CMS
 *  message.
 *  <p>This function will fail, if the context does not process a 'envelope' CMS.
 *  <p>Only one of the two input 'containers' is used:
 *   <ul>
 *   <li>The ASN1 data string given by the user (pData/dataLen);
 *   <li>The ASN1 encoded data inside an 'indefinite' sequence (pInfo);
 *  </ul>
 *
 * @param pCtx    A pointer to the context instance to be used.
 * @param pData   The ASN1 data string with the update.
 * @param dataLen The length of the ANS1 data string.
 * @param pInfo   The encoded ASN1 data when an 'indefinite' format is used,
 *                 held by a 'MOC_CMS_DataInfo' instance.
 * @param last    \c TRUE if this is the last chunk of data to be processed.
 *                 \c FALSE otherwise.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_parseEnveloped(MOC_CMS_CTX *pCtx,
                       const ubyte *pData,
                       ubyte4 dataLen,
                       MOC_CMS_DataInfo *pInfo,
                       intBoolean last);

#ifdef __cplusplus
}
#endif

#endif  /* __DIGICERT_CMS_DECODE_HEADER__ */
