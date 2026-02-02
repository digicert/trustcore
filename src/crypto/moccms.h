/*
 * moccms.h
 *
 * Declarations and definitions for the Mocana CMS handling
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
@file       moccms.h

@brief      Header file for the Mocana SoT Platform API for
              Cryptographic Message Syntax (CMS) support.
@details    Header file for the Mocana SoT Platform API for
              Cryptographic Message Syntax (CMS) support.

@par Flags  To enable these functions, the following conditions must be met:
            + \c \__ENABLE_DIGICERT_CMS__ \b must be defined

@filedoc    moccms.h
*/

#ifndef __DIGICERT_CMS_HEADER__
#define __DIGICERT_CMS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** Content type of a received or created CMS.
 *  <p>These values reflect the <code>ContentType</code> types as defined by
 *  RFC-5652. It also includes an 'undetermined' and 'invalid' value to support
 *  the implementation's core logic.
 *  <p>Not all of these type are supported by the CMS API.
 */
typedef enum MOC_CMS_ContentType
{
    E_MOC_CMS_ct_undetermined = 0,
    E_MOC_CMS_ct_data = 1,
    E_MOC_CMS_ct_signedData = 2,
    E_MOC_CMS_ct_envelopedData = 3,
    E_MOC_CMS_ct_signedAndEnvelopedData = 4,
    E_MOC_CMS_ct_digestedData = 5,
    E_MOC_CMS_ct_encryptedData = 6,
    E_MOC_CMS_ct_authData = 102,
    E_MOC_CMS_ct_invalid = 999,
} MOC_CMS_ContentType;

/** Payload update type.
 *  <p>See the callback function <code>MOC_CMS_updateData</code>.
 */
typedef enum MOC_CMS_UpdateType
{
   E_MOC_CMS_ut_invalid = 0,
   E_MOC_CMS_ut_update = 1,
   E_MOC_CMS_ut_final = 2,
   E_MOC_CMS_ut_result = 3,
} MOC_CMS_UpdateType;

/** Action type when adding a certificate to the output CMS
 *
 */
typedef enum MOC_CMS_action
{
    E_MOC_CMS_sa_none = 0,
    E_MOC_CMS_sa_addCert = 1,
    E_MOC_CMS_sa_version3 = 4
} MOC_CMS_action;

/** The type for a signer's ID value
 *
 */
typedef sbyte4 MOC_CMS_signerID;

/* The value to identify 'all' signers */
#define MOC_CMS_signerID_ALL (-1)

/** The 'issuer' and 'serial number' of a certificate.
 * <p>This structure combines the parsed/created ASN.1 data of two certificate
 * fields:
 * <ul>
 * <li>The issuer name fields.</li>
 * <li>The serial number value.</li>
 * </ul>
 * <p>This data is used in a callback to access the matching private key data, as
 * managed by the user code.
 */
typedef struct MOC_CMS_IssuerSerialNumber
{
   ubyte* pIssuer;
   ubyte4 issuerLen;
   ubyte* pSerialNumber;
   ubyte4 serialNumberLen;
} MOC_CMS_IssuerSerialNumber;

/** The 'originatorKey' of a certificate, as defined in RFC-5652 for
 * the 'KeyAgreeRecipientInfo' sequence.
 * <p>This structure represents the content of the 'OriginatorPublicKey' typed
 * variable 'originatorKey', which is
 * <pre>
 *  OriginatorPublicKey ::= SEQUENCE {
 *      algorithm AlgorithmIdentifier,
 *      publicKey BIT STRING }
 * </pre>
 * <p>The 'algorithm' value is represented in two ASN1 items: The OID and the
 * (optional) parameters needed for the algorithm identified by the OID.
 * <p>The 'publicKey' value is represented by a single ASn1 item, that contains
 * the bit string with the public key data.
 * <p>This data is used in a callback to access the matching private key data, as
 * managed by the user code.
 */
typedef struct MOC_CMS_OriginatorPublicKey
{
    ubyte* pAlgoOID;
    ubyte4 algoOIDLen;
    ubyte* pAlgoParameters;
    ubyte4 algoParametersLen;
    ubyte* pPublicKey;
    ubyte4 publicKeyLen;
} MOC_CMS_OriginatorPublicKey;

/** The 'SubjectKeyIdentifier' of a certificate
 *
 */
typedef struct MOC_CMS_SubjectKeyIdentifier
{
    ubyte* pIdentifier;
    ubyte4 identifierLen;
} MOC_CMS_SubjectKeyIdentifier;

/** The 'RecipientId' structure for the 'KeyTrans' type
 *
 */
typedef struct MOC_CMS_KeyTransRecipientId
{
    ubyte4 type;
    union
    {
        MOC_CMS_IssuerSerialNumber   issuerAndSerialNumber; /* type = NO_TAG */
        MOC_CMS_SubjectKeyIdentifier subjectKeyIdentifier;  /* type = 0 OCTETSTRING */
    } u;
} MOC_CMS_KeyTransRecipientId;

/** The 'RecipientId' structure for the 'KeyAgree' type
 *
 */
typedef struct MOC_CMS_KeyAgreeRecipientId
{
    ubyte4 type;
    union
    {
        MOC_CMS_IssuerSerialNumber   issuerAndSerialNumber;  /* type = NO_TAG */
        MOC_CMS_SubjectKeyIdentifier subjectKeyIdentifier;   /* type = 0 OCTETSTRING */
        MOC_CMS_OriginatorPublicKey  originatorKey;          /* type = 1 */
    } u;
} MOC_CMS_KeyAgreeRecipientId;

/** The general 'RecipientId' structure for all CMS recipient data
 *  <p>The 'type' field identifies the specific recipient id, as it is found in CMS.
 *  <p>The 'union' field is the data presented by the specific type of recipient id.
 */
typedef struct MOC_CMS_RecipientId
{
    ubyte4 type;
    union
    {
        MOC_CMS_KeyTransRecipientId    ktrid;   /* type = NO_TAG */
        MOC_CMS_KeyAgreeRecipientId    karid;   /* type = 1 */
       /*
        MOC_CMS_KEKRecipientId         kekrid;     type = 2
        MOC_CMS_PasswordRecipientId    pwrdi;      type = 3
        MOC_CMS_OtherRecipientId       orid;       type = 4
       */
    } ri;
} MOC_CMS_RecipientId;

/** The 'signer info' structure.
 *  <p>This structure contains the signer data, and a boolean that shows if the signature
 *     was successfully verified.
 *  <p>The 'raw' ASN1 encoded signature is included, so that user code can access attributes
 *     and other optional field.
 */
typedef struct MOC_CMS_MsgSignInfo
{
    ubyte*      pASN1;
    ubyte4      ASN1Len;
    ubyte*      pMsgSigDigest;
    ubyte4      msgSigDigestLen;
    intBoolean  verifies;
    TimeDate*   pSigningTime;
} MOC_CMS_MsgSignInfo;

/* Recipient id tag value used to represent that the CMS id data was not tagged. */
#define NO_TAG (0xFFFFFFFF)

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* MOC_CMS_context;

/** Callback type when the CMS engine needs the private key data identified by
 * the given serial number and issuer name, found in the public certificate data
 * included in the CMS message.
 * <p>The returned status is either 'OK', or a failure condition. When 'OK' is
 * returned, the <code>pKey</code> pointer must be set to a valid 'AsymmetricKey'
 * representing the private key.
 * <p>This call is issued when the provided data has been located in the CMS
 * message. The locating this type of data in the CMS message depends on the 'type'
 * of the certificate and choices made by the creator of the message.
 */
typedef MSTATUS (*MOC_CMS_GetPrivateKey)(const void* arg,
                                         ubyte* pSerialNumber,
                                         ubyte4 serialNumberLen,
                                         ubyte* pIssuer,
                                         ubyte4 issuerLen,
                                         struct AsymmetricKey* pKey);

/** Callback type when the CMS engine needs the private key data identified by
 * the given MOC_CMS_RecipientId instance, found in the public certificate data
 * included in the CMS message.
 * <p>The returned status is either 'OK', or a failure condition. When 'OK' is
 * returned, the <code>pKey</code> pointer must be set to a valid 'AsymmetricKey'
 * representing the private key.
 */
typedef MSTATUS (*MOC_CMS_GetPrivateKeyEx)(const void* arg,
                                           const MOC_CMS_RecipientId* pRecipientId,
                                           struct AsymmetricKey* pKey);

/** Callback type when the CMS engine needs to validate a certificate with the
 * user. The public certificate data is obtained from the CMS message.
 * <p>The returned status 'shall' reflect the validity of the certificate, where
 * 'OK' signifies that the certificate is valid, and a failure code that it is
 * not.
 */
typedef MSTATUS (*MOC_CMS_ValidateRootCertificate)(const void* arg,
                                                   ubyte* pCertificate,
                                                   ubyte4 certificateLen,
                                                   MOC_CMS_MsgSignInfo *pSigInfo);

/** Callback type when the CMS engine needs the public certificate data identified by
 * the given serial number and issuer name.
 * <p>The returned status is either 'OK', or a failure condition. When 'OK' is
 * returned, the <code>ppCertificate</code> pointer must have been set to valid ASN1
 * data string, representing the certificate data, and <code>pCertificateLen</code>
 * must contain the length of that data (in bytes).
 */
typedef MSTATUS (*MOC_CMS_GetCertificate)(const void* arg,
                                          ubyte* pSerialNumber,
                                          ubyte4 serialNumberLen,
                                          ubyte* pIssuer,
                                          ubyte4 issuerLen,
                                          ubyte** ppCertificate,
                                          ubyte4* pCertificateLen);


/** Callback type when the CMS engine needs the public certificate data identified by
 * the given subject key identifier.
 * <p>The returned status is either 'OK', or a failure condition. When 'OK' is
 * returned, the <code>ppCertificate</code> pointer must have been set to valid ASN1
 * data string, representing the certificate data, and <code>pCertificateLen</code>
 * must contain the length of that data (in bytes).
 */
typedef MSTATUS (*MOC_CMS_GetCertificateVersion3)(const void* arg,
                                                  ubyte* pSubjectKeyIdentifier,
                                                  ubyte4 subjectKeyIdentifierLen,
                                                  ubyte** ppCertificate,
                                                  ubyte4* pCertificateLen);

/** Callback type when the CMS engine has acquired payload data and intends to
 * pass it on to user code.
 * <p>The data is delivered as a byte array (<code>pBuf</code>) with the given length
 * <code>bufLen</code>.
 * <p>An update call contains a 'type', that indicates where in the payload delivery
 * this piece of data fits in (see <code>MOC_CMS_UpdateType</code>):
 * <ul>
 * <li>E_MOC_CMS_ut_update: The first or next data of the payload.</li>
 * <li>E_MOC_CMS_ut_final: The last data of the payload.</li>
 * <li>E_MOC_CMS_ut_result: The final call, which allows inspection of the context state,
 *     but does not deliver any data.</li>
 * </ul>
 * <p>The CMS context pointer, so that public API calls like <code>DIGI_CMS_getContentType</code>
 * are available to the user.
 */
typedef MSTATUS (*MOC_CMS_UpdateData)(const void* arg,
                                      MOC_CMS_context pCtx,
                                      MOC_CMS_UpdateType type,
                                      ubyte* pBuf,
                                      ubyte4 bufLen);

typedef struct MOC_CMS_Callbacks
{
    /**
    @brief      Pointer to the MOC_CMS_GetPrivateKey() callback function.
    @details    Pointer to the MOC_CMS_GetPrivateKey() callback function.
    */
    MOC_CMS_GetPrivateKey             getPrivKeyFun;
    /**
    @brief      Pointer to the MOC_CMS_GetPrivateKeyEx() callback function.
    @details    Pointer to the MOC_CMS_GetPrivateKeyEx() callback function.
    */
    MOC_CMS_GetPrivateKeyEx           getPrivKeyFunEx;
    /**
    @brief      Pointer to the MOC_CMS_ValidateRootCertificate() callback function.
    @details    Pointer to the MOC_CMS_ValidateRootCertificate() callback function.
    */
    MOC_CMS_ValidateRootCertificate   valCertFun;
    /**
    @brief      Pointer to the MOC_CMS_GetCertificate() callback function.
    @details    Pointer to the MOC_CMS_GetCertificate() callback function.
    */
    MOC_CMS_GetCertificate            getCertFun;
    /**
    @brief      Pointer to the MOC_CMS_CB() callback function.
    @details    Pointer to the MOC_CMS_CB() callback function.
    */
    MOC_CMS_UpdateData                dataUpdateFun;
    /**
    @brief      Pointer to the MOC_CMS_GetCertificateVersion3() callback function.
    @details    Pointer to the MOC_CMS_GetCertificateVersion3() callback function.
    */
    MOC_CMS_GetCertificateVersion3    getCertFunV3;
    
} MOC_CMS_Callbacks;

/**
 * @brief   Create a new context to parse a CMS
 * @details Allocates the new context instance and sets the 'pNewContext' pointer.
 *         <p>The function takes a generic callback argument and a pointer to a
 *          'MOC_CMS_Callbacks' structure to set up callback calls to the user code.
 *
 * @param  pNewContext A pointer to where the memory address of the context
 *                     is stored. Is not allowed to be NULL.
 * @param  callbackArg Argument passed to all callback functions.
 * @param  pCallbacks  The 'MOC_CMS_Callbacks' structure containing function pointers
 *                     to the user's callback code.
 * @return             \c OK (0) if successful; otherwise a negative number
 *                     error code definition from merrors.h. To retrieve a
 *                     string containing an English text error identifier
 *                     corresponding to the function's returned error status,
 *                     use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_newContext (MOC_HW(hwAccelDescr hwAccelCtx)
                                       MOC_CMS_context* pNewContext,
                                       const void* callbackArg,
                                       const MOC_CMS_Callbacks* pCallbacks);

/**
 * @brief   Create a new context to output data in a CMS format
 * @details Allocates the new context instance and sets the 'pNewContext' pointer.
 *         <p>The generated CMS format is determined by the 'type' value.
 *         <p>The function takes a generic callback argument and a pointer to a function
 *          of type 'MOC_CMS_UpdateData' to set up a callback with formatted data to
 *          the user code.
 *         <p>The CMS format can handle 'streaming' data of a length not determined at the
 *          start of the processing. If this is way this instance should behave, the value
 *          of 'isStreaming' must be set to 'TRUE'. Otherwise, use FALSE.
 *
 * @param  pNewContext A pointer to where the memory address of the context
 *                     is stored. Is not allowed to be NULL.
 * @param  type        The type of CMS format to be created. Selected with a value from
 *                     the 'MOC_CMS_ContentType' enum, e.g. 'E_MOC_CMS_ct_signedData'.
 * @param  rngFun      Pointer to a function that generates random numbers
 *                     suitable for cryptographic use. To be FIPS-compliant,
 *                     reference RANDOM_rngFun() (defined in random.c), and make
 *                     sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is defined in
 *                     moptions.h
 * @param  rngFunArg   Pointer to arguments that are required by the function
 *                     referenced in \p rngFun. If you use RANDOM_rngFun(), you
 *                     must supply a \c randomContext structure, which you can
 *                     create by calling \c RANDOM_acquireContext(...).
 * @param  isStreaming A Boolean value telling the context to use a 'streaming' format or
 *                     not.
 * @param  callbackArg Argument passed to the callback function.
 * @param  dataUpdateFun  A function pointer of type 'MOC_CMS_UpdateData' that will receive
 *                     the formatted data as input.
 * @return             \c OK (0) if successful; otherwise a negative number
 *                     error code definition from merrors.h. To retrieve a
 *                     string containing an English text error identifier
 *                     corresponding to the function's returned error status,
 *                     use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_newContextOut (MOC_HW(hwAccelDescr hwAccelCtx)
                                          MOC_CMS_context *pNewContext,
                                          MOC_CMS_ContentType type,
                                          RNGFun rngFun,
                                          void *rngFunArg,
                                          intBoolean isStreaming,
                                          const void *callbackArg,
                                          MOC_CMS_UpdateData dataUpdateFun);

/**
 * @brief   Add CMS message data to the context.
 * @details Passes new message data to the CMS context for parsing.
 *         <p>If the logical end of the processing has been reached
 *          (i.e. no more data is necessary), the returned '*pFinished' value
 *          is no longer FALSE.
 *
 * @param  context   The CMS context
 * @param  input     The 'ubyte' array of new CMS data
 * @param  inputLen  The size of the above array
 * @param  pFinished A pointer to 'intBoolean' to store the 'Finished' flag
 * @return           \c OK (0) if successful; otherwise a negative number
 *                   error code definition from merrors.h. To retrieve a
 *                   string containing an English text error identifier
 *                   corresponding to the function's returned error status,
 *                   use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_updateContext (MOC_CMS_context context,
                                          const ubyte* input,
                                          ubyte4 inputLen,
                                          intBoolean* pFinished);

/**
 * @brief   Add pay load data to the context for CMS output.
 * @details Passes new message data to the CMS context so that it is part of the output.
 *         <p>If the last pay load data is being passed in, signal
 *          that with a 'final' value of TRUE.
 *
 * @param  context   The CMS context
 * @param  output    The 'ubyte' array of new pay load data
 * @param  outputLen The size of the above array
 * @param  last      An 'intBoolean' signal the end of the pay load data
 * @return           \c OK (0) if successful; otherwise a negative number
 *                   error code definition from merrors.h. To retrieve a
 *                   string containing an English text error identifier
 *                   corresponding to the function's returned error status,
 *                   use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_updateContextOut (MOC_CMS_context context,
                                             const ubyte* output,
                                             ubyte4 outputLen,
                                             intBoolean last);

/**
 * @brief   Finalize CMS output and flush all data.
 * @details This causes the CMS context generate all final data and write all
 *          buffered data to the output callback.
 *
 * @param  context   The CMS context
 * @return           \c OK (0) if successful; otherwise a negative number
 *                   error code definition from merrors.h. To retrieve a
 *                   string containing an English text error identifier
 *                   corresponding to the function's returned error status,
 *                   use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_finalizeContextOut (MOC_CMS_context context);

/**
 * @brief   Delete the context.
 * @details Frees all memory referenced by the context.
 *         <p>The argument is a pointer to the memory where the context reference is stored.
 *          It will be set to NULL.
 *
 * @param  pContext  A pointer to the CMS context
 * @return           \c OK (0) if successful; otherwise a negative number
 *                   error code definition from merrors.h. To retrieve a
 *                   string containing an English text error identifier
 *                   corresponding to the function's returned error status,
 *                   use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_deleteContext (MOC_CMS_context* pContext);

/**
 * @brief   Return the value of type 'CMS_ContentType'.
 * @details Allows access to the field inside the 'opaque' context, and returns its current
 *          value.
 *
 * @param context        The CMS context
 * @param cmsContentType The pointer to the memory where the content type value is
 *                       to be stored. It is not allowed to be NULL.
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h. To retrieve a
 *                       string containing an English text error identifier
 *                       corresponding to the function's returned error status,
 *                       use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getContentType (MOC_CMS_context context,
                                           MOC_CMS_ContentType* cmsContentType);

/**
 * @brief   Return the values inside the callback structure.
 * @details Allows access to the field inside the 'opaque' context, and returns its current
 *          value.
 *         <p>The returned data is a copy and changing it does not change the function pointers
 *          within the context.
 *
 * @param context The CMS context
 * @param pCB     The pointer to the memory where the 'MOC_CMS_Callback' copy is
 *                to be stored. It is not allowed to be NULL.
 * @return        \c OK (0) if successful; otherwise a negative number
 *                error code definition from merrors.h. To retrieve a
 *                string containing an English text error identifier
 *                corresponding to the function's returned error status,
 *                use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getCallbacks (MOC_CMS_context context,
                                         MOC_CMS_Callbacks* pCB);

/**
 * @brief   Return the number of recipients, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_envelopedData'.
 *         <p>The returned value represents the number of recipients found in the
 *          CMS message
 *
 * @param context        The CMS context
 * @param pNumRecipients The pointer to the memory where the value is to be stored.
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h. To retrieve a
 *                       string containing an English text error identifier
 *                       corresponding to the function's returned error status,
 *                       use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getNumRecipients (MOC_CMS_context context,
                                             sbyte4* pNumRecipients);

/**
 * @brief   Return the recipient id for 'idxRecipient' value, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_envelopedData'.
 *         <p>A signer is identified with an instance of 'MOC_CMS_RecipientId'.
 *         <p>The returned data is a deep copy of the context data fields and
 *          MUST be freed by the caller.
 *
 * @param context      The CMS context
 * @param idxRecipient The index number of the requested recipient. A valid value must be
 *                     larger than or equal 0, and be smaller than the number obtained with
 *                     'DIGI_CMS_getNumRecipients'.
 * @param pRecipient   The pointer to a recipient struct (MOC_CMS_RecipientId). The selected
 *                     data will be copied to that memory, and it is not allowed to be NULL.
 * @return             \c OK (0) if successful; otherwise a negative number
 *                     error code definition from merrors.h. To retrieve a
 *                     string containing an English text error identifier
 *                     corresponding to the function's returned error status,
 *                     use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getRecipientId (MOC_CMS_context context,
                                           sbyte4 idxRecipient,
                                           MOC_CMS_RecipientId* pRecipient);

/**
 * @brief   Delete an instance of 'MOC_CMS_RecipientId'
 * @details This function allows the user code to free the memory held by a 'MOC_CMS_RecipientId'
 *          instance, easily.
 *
 * @param pRecipient   The pointer to a recipient struct (MOC_CMS_RecipientId).
 * @return             \c OK (0) if successful; otherwise a negative number
 *                     error code definition from merrors.h. To retrieve a
 *                     string containing an English text error identifier
 *                     corresponding to the function's returned error status,
 *                     use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_deleteRecipientId (MOC_CMS_RecipientId* pRecipient);

/**
 * @brief   Return the number of signers, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>The returned value represents the number of verified signatures.
 *
 * @param context     The CMS context
 * @param pNumSigners The pointer to the memory where the value is to be stored.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getNumSigners (MOC_CMS_context context,
                                          sbyte4* pNumSigners);

/**
 * @brief   Return the signing info for 'idxSigner' value, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>A signer is identified with an instance of 'MOC_CMS_MsgSignInfo'.
 *         <p>The returned data is a deep copy of the context data fields and
 *          MUST be freed by the caller.
 *
 * @param context     The CMS context
 * @param idxSigner   The index number of the requested signer. A valid value must be
 *                    larger than or equal 0, and be smaller than the number obtained with
 *                    'DIGI_CMS_getNumSigners'.
 * @param pSigner     The pointer to a signer struct (MOC_CMS_MsgSignInfo). The selected
 *                    data will be copied to that memory, and it is not allowed to be NULL.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getSignerInfo (MOC_CMS_context context,
                                          sbyte4 idxSigner,
                                          MOC_CMS_MsgSignInfo* pSigner);

/**
 * @brief   Return the number of signatures, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>The returned value represents the number of signature fields found in the CMS.
 *
 * @param context   The CMS context
 * @param pNumSigs  The pointer to the memory where the value is to be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getNumSignatures (MOC_CMS_context context,
                                             sbyte4* pNumSigs);

/**
 * @brief   Delete an instance of 'MOC_CMS_MsgSignInfo'
 * @details This function allows the user code to free the memory held by a 'MOC_CMS_MsgSignInfo'
 *          instance, easily.
 *
 * @param pSigner     The pointer to a signer struct (MOC_CMS_MsgSignInfo).
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_deleteSignerInfo (MOC_CMS_MsgSignInfo* pSigner);

/**
 * @brief   Return the certificates inside the CMS data context.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>A concatenated array of certificates is returned in memory, the memory is 'owned'
 *          by the context and the caller must make a copy if it wants to retain the data.
 *         <p>In case there were no certificates in the CMS data (yet), a NULL is returned.
 *
 * @param context     The CMS context
 * @param ppCerts     The pointer to a variable where the memory pointer will be stored.
 * @param pCertLen    The pointer to a variable where the size of the memory will be stored.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getCertificates (MOC_CMS_context context,
                                            const ubyte **ppCerts,
                                            ubyte4 *pCertLen);

/**
 * @brief   Return the CRLs inside the CMS data context.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>A concatenated array of CRL entries is returned in memory, the memory is 'owned'
 *          by the context and the caller must make a copy if it wants to retain the data.
 *         <p>In case there were no CRLs in the CMS data (yet), a NULL is returned.
 *
 * @param context     The CMS context
 * @param ppCRLs      The pointer to a variable where the CRL pointer will be stored.
 * @param pCRLsLen    The pointer to a variable where the size of the memory will be stored.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getCRLs (MOC_CMS_context context,
                                    const ubyte **ppCRLs,
                                    ubyte4 *pCRLsLen);

/**
 * @brief   Return the number of digests, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>The returned value represents the number of digests used in the CMS data.
 *
 * @param context     The CMS context
 * @param pNumDigests The pointer to the memory where the value is to be stored.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getNumDigests (MOC_CMS_context context,
                                          ubyte4* pNumDigests);

/**
 * @brief   Return the OID value for a digest, if applicable.
 * @details This call is only valid when the CMS context type is 'E_MOC_CMS_ct_signedData'.
 *         <p>A digest is identified with ASN1 encoded OID.
 *         <p>The returned data is reference to context data and MAY NOT be freed by the caller.
 *
 * @param context     The CMS context
 * @param idx         The index number of the requested digest. A valid value must be
 *                    larger than or equal 0, and be smaller than the number obtained with
 *                    'DIGI_CMS_getNumDigests'.
 * @param pDigestAlgoOID The pointer to a memory pointer, that is 'const'. It will be set to point
 *                    to data within the context. It is not allowed to be NULL.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h. To retrieve a
 *                    string containing an English text error identifier
 *                    corresponding to the function's returned error status,
 *                    use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_getDigestID (MOC_CMS_context context,
                                        ubyte4 idx,
                                        const ubyte** pDigestAlgoOID);

/**
 * @brief   Sets the pay load length for the CMS output context.
 * @details This function may be used when the output format of the CMS is NOT of
 *          the 'streaming' type, i.e. the value \c FALSE was used for \c isStreaming when
 *          creating the CMS output context. It informs the CMS context about the size
 *          of the payload and it then can enforce that value while the function
 *          \c DIGI_CMS_updateContextOut() processes input data.
 *          <p>You can safely 'ignore' this function.
 *          <p>A call to this function is valid for all output CMS types.
 *          <p>This function must be called *before* the first pay load data
 *          is provided to the same context.
 *
 * @param context   The context for which to set the pay load length.
 * @param len       The total length (in bytes) of the pay load embedded in the CMS output.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_setPayloadLength (MOC_CMS_context context,
                                             ubyte4 len);

/**
 * @brief   Add a 'signer' to the CMS output context.
 * @details This function adds all needed data to sign a payload in a sign-data CMS with a
 *          specific 'Signer' identity. The identity is found in X509 data and a private key
 *          is used to sign. Also, the digest algorithm is specified.
 *         <p>This function can return a unique ID value for the signer, that can be used
 *          in the 'DIGI_CMS_addSignerAttribute' function to set an attribute for a 'signer'.
 *         <p>This call is only valid for CMS types that sign or digest data.
 *
 * @param context          The context to which to add the 'Signer' data.
 * @param pCert            The byte array containing the X509 certificate data.
 * @param certLen          The length of the above array.
 * @param pKey             Pointer to the private key data, stored as an 'AsymmetricKey' type.
 * @param pDigestAlgoOID   The ASN1 encoded identifier for the digest algorithm, e.g. NIST SHA256.
 * @param digestAlgoOIDLen The length of the OID in bytes.
 * @param action           A bit-OR of values from the 'MOC_CMS_action' enum, to cause further action
 *                         for this 'Signer'. It can for instance cause the certificate to be included
 *                         in the output.
 * @param pSignId          Pointer to memory where the 'Signer' ID value is stored, if it is not NULL.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addSigner (MOC_CMS_context context,
                                      ubyte* pCert,
                                      ubyte4 certLen,
                                      const AsymmetricKey* pKey,
                                      const ubyte* pDigestAlgoOID,
                                      ubyte4 digestAlgoOIDLen,
                                      MOC_CMS_action action,
                                      MOC_CMS_signerID *pSignID);

/**
 * @brief   Add an attribute to the CMS output context.
 * @details This function adds an 'attribute' to the CMS output, which can be authenticated
 *          with a 'Signer' signature, or not. The attribute type and value are provided
 *          as input and the CMS will contain that data in ASN1/DER formatting.
 *         <p>This call is only valid for CMS types that sign or digest data.
 *
 * @param context   The context to which to add the 'attribute' data
 * @param signId    The 'Signer' identity to which this attribute shall belong, or the
 *                  value 'MOC_CMS_signerID_ALL'.
 * @param idOID     The ASN1 encoded OID used as the attribute's identifier.
 * @param oidLen    The length of the \c idOID in bytes.
 * @param typeID    The type of the value, e.g. an id taken from 'mocasn1.h' like 'MASN1_TYPE_INTEGER'
 * @param value     The memory containing the value, passed as a byte array.
 * @param valueLen  The size of the value memory in bytes.
 * @param authenticated A Boolean to cause the attribute to be 'signed' so that it can be
 *                  authenticated by the reader of the CMS data.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addSignerAttribute (MOC_CMS_context context,
                                               MOC_CMS_signerID signId,
                                               const ubyte* idOID,
                                               ubyte4 oidLen,
                                               ubyte4 typeID,
                                               const ubyte* value,
                                               ubyte4 valueLen,
                                               intBoolean authenticated);

/**
 * @brief   Add a certificate to the CMS output context.
 * @details This function adds a X509 certificate to the CMS output, which can be extracted
 *          by the reader of the CMS. The X509 formatted binary data is provided
 *          as input.
 *         <p>The data is not validate, just copied into the CMS.
 *
 * @param context   The context to which to add the certificate data
 * @param pCert     The memory containing the binary certificate data
 * @param certLen   The length of the certificate binary
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addCertificate (MOC_CMS_context context,
                                           ubyte* pCert,
                                           ubyte4 certLen);

/**
 * @brief   Add a certificate revocation list to the CMS output context.
 * @details This function adds a X509 CRL to the CMS output, which can be extracted
 *          by the reader of the CMS. The X509 formatted binary data is provided
 *          as input.
 *         <p>The data is not validate, just copied into the CMS.
 *
 * @param context   The context to which to add the CRL data
 * @param pCRL      The memory containing the binary CRL data
 * @param CRLLen    The length of the CRL binary
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addCRL (MOC_CMS_context context,
                                   ubyte* pCRL,
                                   ubyte4 CRLLen);

/**
 * @brief   Add a 'raw' signature to the CMS output context.
 * @details This function adds a binary signature field the CMS output, which is found
 *          by the reader of the CMS just like a generated signature. The binary data is
 *          provided as input.
 *         <p>The data is not validate, just copied into the CMS.
 *         <p>This call is used for 'resigning' a payload read from an input CMS, when
 *          the original signatures in the CMS need to be preserved.
 *         <p>This call is only valid for CMS types that sign or digest data.
 *
 * @param context   The context to which to add the 'raw' signature
 * @param pSig      The memory containing the signature data
 * @param sigLen    The length of the signature data
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addSignatureRaw (MOC_CMS_context context,
                                            const ubyte* pSig,
                                            ubyte4 sigLen);

/**
 * @brief   Add a digest to the CMS output context, should it not exits.
 * @details This function adds a digest algorithm the CMS context, which will be used for
 *          verifying the CMS payload.
 *         <p>This call is used for 'resigning' a payload read from an input CMS, when
 *          the original signatures in the CMS need to be preserved and the reader needs to
 *          use the given digest for validation.
 *         <p>See 'DIGI_CMS_getDigestID()' on how to access the digest OID of a parsed CMS input.
 *         <p>This call is only valid for CMS types that sign or digest data.
 *
 * @param context          The context to which to add the digest algorithm
 * @param digestAlgoOID    The ASN1 encoded OID of the digest, e.g. SHA-256
 * @param digestAlgoOIDLen The length of \c digestAlgoOID in bytes
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addDigest (MOC_CMS_context context,
                                      const ubyte* digestAlgoOID,
                                      ubyte4 digestAlgoOIDLen);

/**
 * @brief   Sets the encryption algorithm for the CMS output context.
 * @details This function defines the crypto algorithm the CMS context, which will be used for
 *          encrypting the CMS payload.
 *          <p>A random number generator function is passed as well. It may be needed by the
 *           cryptographic algorithm, e.g. for salt generation. It can be set to a different RNG function
 *           than provided when the context was created, or the same RNG function can be used.
 *          <p>This call is only valid for CMS types that encrypt data.
 *
 * @param context   The context for which to configure the encryption algorithm
 * @param encryptAlgoOID   The ASN1 encoded OID of the cryptographic algorithm, e.g AES-256
 * @param encryptAlgoOIDLen The length of \c encryptAlgoOID in bytes
 * @param rngFun    A function pointer to a random number generate, typed as 'RNGFun'
 * @param rngFunArg The argument passed to the RNG function when it is called
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_setEncryption (MOC_CMS_context context,
                                          const ubyte* encryptAlgoOID,
                                          ubyte4       encryptAlgoOIDLen,
                                          RNGFun rngFun,
                                          void* rngFunArg);

/**
 * @brief   Add a 'recipient' to the CMS output context.
 * @details This function adds all needed data to encrypt a payload in a envelop-data CMS
 *          with a public key of a recipient. The identity is found in X509 data and
 *          its public key is used encrypt the encryption key.
 *         <p>This call is only valid for CMS types that encrypt data.
 *
 * @param context   The context to which to add the 'Recipient' data
 * @param pCert     The byte array containing the X509 certificate data
 * @param certLen   The length of the above array
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addRecipient (MOC_CMS_context context,
                                         const ubyte* pCert,
                                         ubyte4 certLen);

/**
 * @brief   Add an attribute to the CMS output context.
 * @details This function adds an 'attribute' to the CMS output. The attribute type and
 *          value are provided as input and the CMS will contain that data in ASN1/DER formatting.
 *         <p>This call is only valid for CMS types that encrypt data.
 *         <p>The data is never authenticated.
 *
 * @param context   The context to which to add the 'attribute' data
 * @param idOID     The ASN1 encoded OID used as the attribute's identifier.
 * @param oidLen    The length of \c idOID in bytes.
 * @param typeID    The type of the value, e.g. an id taken from 'mocasn1.h' like 'MASN1_TYPE_INTEGER'
 *                  Use 'MASN1_TYPE_ENCODED' if you add a 'raw' DER encoded value.
 * @param value     The memory containing the value, passed as a byte array.
 * @param valueLen  The size of the value memory in bytes.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS DIGI_CMS_addUnprotectedAttribute (MOC_CMS_context context,
                                                    const ubyte* idOID,
                                                    ubyte4 oidLen,
                                                    ubyte4 typeID,
                                                    const ubyte* value,
                                                    ubyte4 valueLen);

#ifdef __cplusplus
}
#endif

#endif  /* __DIGICERT_CMS_HEADER__ */
