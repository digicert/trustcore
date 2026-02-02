/*
 * moccms_asn.h
 *
 * Declarations and definitions for the Mocana CMS ASN1 parsing functions
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
@file       moccms_asn.h

@brief      Header file for the Mocana Cryptographic Message Syntax (CMS) ASN parsing tools.
@details    Header file for the Mocana Cryptographic Message Syntax (CMS) ASN parsing tools.
*/
#ifndef __DIGICERT_CMS_ASN1_HEADER__
#define __DIGICERT_CMS_ASN1_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** A structure to collect partial ASN1 strings when data is being
 *  streamed.
 *  <p>This structure is used when the function <code>DIGI_CMS_A_collectEncoded</code>
 *     or <code>DIGI_CMS_A_collectOid</code> are used while streaming data with unknown
 *     placement of the chunk 'borders'.
 *  <p>You do not need this when parsing a complete ASN1 string in memory with the
 *     <code>MAsn1Decode</code> function.
 *  <p>The entry <code>keepDone</code> signals whether the ASN1 string being collected is
 *     complete, using the value 'TRUE' when it is.
 *  <p>After the ASN1 string is complete, it can be read as a 'ubyte' array using the
 *     pointer <code>pKeepData</code>. The length of this array is found in
 *     <code>keepDataLen</code>.
 *  <p>Other entries in this structure are used by the internal code logic. Do not rely on
 *     their meaning or values in user code.
 */
typedef struct MOC_CMS_CollectData
{
    MAsn1Element* pElement;
    MAsn1Element* pParent;
    ubyte*        pKeepData;
    ubyte4        keepDataSize;
    ubyte4        keepDataLen;
    ubyte4        lastState;
    intBoolean    keepDone;
} MOC_CMS_CollectData;

/** The structure to capture ASN1 strings inside 'indefinite' encoded strings.
 *  <p>See <code>MOC_CMS_U_decodeSeqDataReturn</code>.
 *  <p>The 'next' entry allows the creation of a linked list of such structures.
 *  <p>The 'type' entry is used as an identifier, in case that is needed.
 */
typedef struct MOC_CMS_DataInfo
{
    void*         pNext;
    MAsn1Element* pElement;
    ubyte*        pData;
    ubyte4        size;
    ubyte4        len;
    ubyte4        type;
    ubyte4        tags;
} MOC_CMS_DataInfo;

/**
 * @brief The callback function used by CMS when calling 'MAsn1DecodeIndefiniteUpdate'.
 * @details The callback function used by CMS when calling 'MAsn1DecodeIndefiniteUpdate'.
 *  <p>It is called when indefinite data needs to be captured.
 *  <p>This function matches the 'IndefiniteLengthDataReturn' type as defined by the ASN1
 *     parser.
 *  <p>This function expects the 'pCallbackInfo' to point to an instance of 'MOC_CMS_DataInfo'.
 *  <p>The user code will NOT call this function, directly. Instead the CMS parser will call it.
 *
 * @param pCallbackInfo The pointer to the (generic) callback argument provided by the ASN1 parser.
 * @param pData         The pointer to the memory where the new ASN1 data is stored.
 * @param dataLen       The number of bytes of ASN1 data available.
 * @param pElement      The pointer to the ASN1 element instance that is being parsed.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_decodeSeqDataReturn(void *pCallbackInfo,
                              ubyte *pData,
                              ubyte4 dataLen,
                              MAsn1Element *pElement);

/** 
 * @brief Utility function to free an instance of 'MOC_CMS_DataInfo'.
 * @details Utility function to free an instance of 'MOC_CMS_DataInfo'.
 *  <p>The memory 'held' by the given instance is released.
 *
 * @param pDataInfo Then pointer to memory of a 'MOC_CMS_DataInfo' instance.
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_freeDataInfo(MOC_CMS_DataInfo *pDataInfo);

/** 
 * @brief Create a new instance of 'MOC_CMS_CollectData' and fill a few fields.
 * @details Create a new instance of 'MOC_CMS_CollectData' and fill a few fields.
 *
 * @param ppData  The pointer to a 'MOC_CMS_CollectData' pointer that will be set;
 * @param pParent The pointer to the ASN1 element that is the parent of this ASN1 item;
 * @param pTarget The pointer to the ASN1 item that needs its value stored while
 *                streaming data;
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_createCollectData(MOC_CMS_CollectData **ppData,
                            MAsn1Element *pParent,
                            MAsn1Element *pTarget);

/** 
 * @brief Free an instance of the type 'MOC_CMS_CollectData'
 * @details Free an instance of the type 'MOC_CMS_CollectData'
 *
 * @param ppData    The pointer to a 'MOC_CMS_CollectData' pointer that will be freed;
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_freeCollectData(MOC_CMS_CollectData **ppData);

/** 
 * @brief Capture the whole encoded ASN1 ENCODED string for the given input, while it is streamed.
 * @details Capture the whole encoded ASN1 ENCODED string for the given input, while it is streamed.
 *
 * @param pData     The pointer to the 'MOC_CMS_CollectData' instance being processed;
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_collectEncoded(MOC_CMS_CollectData *pData);

/** 
 * @brief Capture the whole encoded ASN1 SET_OF string for the given input, while it is streamed.
 * @details Capture the whole encoded ASN1 SET_OF string for the given input, while it is streamed.
 *
 * @param pData     The pointer to the 'MOC_CMS_CollectData' instance being processed;
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_collectSetOF(MOC_CMS_CollectData* pData);

/** 
 * @brief Capture the whole encoded ASN1 OID string for the given input, while it is streamed.
 * @details Capture the whole encoded ASN1 OID string for the given input, while it is streamed.
 *
 * @param pData     The pointer to the 'MOC_CMS_CollectData' instance being processed;
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_A_collectOid(MOC_CMS_CollectData* pData);

#ifdef __cplusplus
}
#endif

#endif  /* __DIGICERT_CMS_ASN1_HEADER__ */
