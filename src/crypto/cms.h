/*
 * cms.h
 *
 * CMS Parser and utilities routines
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
@file       cms.h

@brief      Header file for the Mocana SoT Platform convenience API for
              Cryptographic Message Syntax (CMS) support.
@details    Header file for the Mocana SoT Platform convenience API for
              Cryptographic Message Syntax (CMS) support.
*/

#ifndef __CMS_HEADER__
#define __CMS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/* Content type of a received CMS cf. CMS_getContentType() */
typedef enum CMS_ContentType
{
    E_CMS_undetermined = 0,
    E_CMS_data = 1,
    E_CMS_signedData = 2,
    E_CMS_envelopedData = 3,
    /* E_PCKS7S_signedAndEnvelopedData = 4, */
    E_CMS_digestedData = 5,
    E_CMS_encryptedData = 6,
    E_CMS_ct_authData = 102,
} CMS_ContentType;

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* CMS_context;  /* opaque structure used when parsing a CMS */

/* opaque structures used when creating a CMS */
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* CMS_signedDataContext;
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* CMS_signerInfo;
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* CMS_envelopedDataContext;


#define NO_TAG (0xFFFFFFFF)

/* data structures used in callbacks */
/**
@brief      ASN1_ITEMPTR pointers for a certificate Issuer ID and serial number.

@details    This structure is referenced within a union in the
            CMSKeyAgreeRecipientId structure.

The CMSIssuerSerialNumber structure is defined as follows:
<pre>
    typedef struct CMSIssuerSerialNumber
    {
        ASN1_ITEMPTR pIssuer;
        ASN1_ITEMPTR pSerialNumber;
    } CMSIssuerSerialNumber;
</pre>

Within the CMSIssuerSerialNumber, use the structures referenced by the
ASN1_ITEMPTR pointers to find offsets and buffer lengths for the Issuer and
SerialNumber for a certificate that identifies the subject for which the
caller wants password information. These offsets and buffer sizes apply to a
CStream that was passed in when it called your CMS_GetPrivateKey() callback
function.
*/
typedef struct CMSIssuerSerialNumber
{
    ASN1_ITEMPTR pIssuer;
    ASN1_ITEMPTR pSerialNumber;
} CMSIssuerSerialNumber;

/**
@brief      Union that identifies a recipient for whom a transient key is wanted.

@details    This structure serves as a member in a union in the \c
            CMSRecipientId structure. The CMS_GetPrivateKey() callback
            function passes in a pointer to a CMSRecipientId() structure to identify the recipient for which the key is wanted.

The CMSKeyTransRecipientId structure is defined as:
<pre>
    typedef struct CMSKeyTransRecipientId
    {
        ubyte4 type;
        union
        {
            CMSIssuerSerialNumber issuerAndSerialNumber; // type = NO_TAG
            ASN1_ITEMPTR          subjectKeyIdentifier;  // type = 0 OCTETSTRING
        } u;
    } CMSKeyTransRecipientId;
</pre>

If the type is NO_TAG, the issuerAndSerialNumber member applies. This member
supplies a pointer to a CMSIssuerSerialNumber structure.

If the type is 0, the subjectKeyIdentifier member applies. This member supplies
an ASN1_ITEMPTR that provides offset and buffer length information that you can
use to find subject key identifier information in the CStream that was passed
to the CMS_GetPrivateKey() callback function.

This structure reflects the layout of the RecipientIdentifier object of the
KeyTransRecipientInfo object. The RecipientIdentifier is a choice.
<pre>
    KeyTransRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 0 or 2
        rid RecipientIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      RecipientIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
</pre>

CMSKeyTransRecipientId.issuerAndSerialNumber corresponds to the
issuerAndSerialNumber object. CMSKeyTransRecipientId.subjectKeyIdentifier
 corresponds to the subjectKeyIdentifier object.
*/
typedef struct CMSKeyTransRecipientId
{
    ubyte4 type;
    union
    {
        CMSIssuerSerialNumber issuerAndSerialNumber; /* type = NO_TAG */
        ASN1_ITEMPTR          subjectKeyIdentifier;  /* type = 0 OCTETSTRING */
    } u;
} CMSKeyTransRecipientId;


/**
@brief      Union that identifies a recipient for whom a transient key is wanted.

@details    This structure serves as a member in a union in the CMSRecipientId
            structure.

The CMSOriginatorPublicKey is defined as follows:
<pre>
    typedef struct CMSOriginatorPublicKey
    {
        ASN1_ITEMPTR pAlgoOID;  // AlgorithmIdentifier: algorithm OID
        ASN1_ITEMPTR pAlgoParameters; // AlgorithmIdentifier: parameters ANY
        ASN1_ITEMPTR pPublicKey; // BIT STRING
    } CMSOriginatorPublicKey;
</pre>

The contained ASN1_ITEMPTR members provide offset and buffer size information
for information within the CStream, which was passed to the
CMS_GetPrivateKey() callback function.

The information provided by these members are an algorithm ID, any parameters
associated with that algorithm, and the public key.

The CMSOriginatorPublicKey structure reflects the layout of the
OriginatorPublicKey component of the KeyAgreeRecipientInfo ASN.1 object:
<pre>
      KeyAgreeRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 3
        originator [0] EXPLICIT OriginatorIdentifierOrKey,
        ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        recipientEncryptedKeys RecipientEncryptedKeys }

      OriginatorIdentifierOrKey ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier,
        originatorKey [1] OriginatorPublicKey }

      OriginatorPublicKey ::= SEQUENCE {
        algorithm AlgorithmIdentifier,
        publicKey BIT STRING }
</pre>
*/
typedef struct CMSOriginatorPublicKey
{
    ASN1_ITEMPTR pAlgoOID;  /* AlgorithmIdentifier: algorithm OID */
    ASN1_ITEMPTR pAlgoParameters; /* AlgorithmIdentifier: parameters ANY */
    ASN1_ITEMPTR pPublicKey; /* BIT STRING */
} CMSOriginatorPublicKey;

/**
@brief      Union that identifies a CMS recipient.

@details    This structure is a member in a union in the CMSRecipientId
            structure.

The CMS_GetPrivateKey() callback function passes pointer to a CMSRecipientId()
structure to identify the recipient from which the key is wanted.

The CMSKeyAgreeRecipientId structure is defined as:
<pre>
    typedef struct CMSKeyAgreeRecipientId
    {
        ubyte4 type;
        union
        {
            CMSIssuerSerialNumber   issuerAndSerialNumber;  // type = NO_TAG
            ASN1_ITEMPTR            subjectKeyIdentifier;   // type = 0 OCTETSTRING
            CMSOriginatorPublicKey  originatorKey;          // type = 1  /
        } u;
    } CMSKeyAgreeRecipientId;
</pre>

To interpret this structure, read the type value.
+ If type is NO_TAG, the issuerAndSerialNumber applies, which supplies a
    CMSIssuerSerialNumber structure.
+ If the type is 0 (zero), the subjectKeyIdentifier applies, which provides an
    ASN1_ITEMPTR structure that provides offset and buffer size information
    for the subjectKeyIdentifier in the CStream that is passed to the callback.
+ If type is 1 (one), the originatorKey member applies, which provides a
    CMSOriginatorPublicKey structure.

The CMSKeyAgreeRecipientId structure reflects the layout of the originator
component of the KeyAgreeRecipientInfo ASN.1 object:
<pre>
      KeyAgreeRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 3
        originator [0] EXPLICIT OriginatorIdentifierOrKey,
        ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        recipientEncryptedKeys RecipientEncryptedKeys }

      OriginatorIdentifierOrKey ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier,
        originatorKey [1] OriginatorPublicKey }

      OriginatorPublicKey ::= SEQUENCE {
        algorithm AlgorithmIdentifier,
        publicKey BIT STRING }
</pre>

The \c OriginatorIdentifierOrKey object is a choice of an
issuerAndSerialNumber object, a \c subjectKeyIdentifier object, and an
\c originatorKey object.
*/
typedef struct CMSKeyAgreeRecipientId
{
    /**
    @brief      Tells you how to interpret the \b u member of a
                  CMSKeyAgreeRecipientId structure.
    @details    Tells you how to interpret the \b u member of a
                  CMSKeyAgreeRecipientId structure.
    */
    ubyte4 type;
    /**
    @brief      Recipient for which the callback wants a key.
    @details    Recipient for which the callback wants a key.
    */
    union
    {
        CMSIssuerSerialNumber   issuerAndSerialNumber;  /* type = NO_TAG */
        ASN1_ITEMPTR            subjectKeyIdentifier;   /* type = 0 OCTETSTRING */
        CMSOriginatorPublicKey  originatorKey;          /* type = 1 */
    } u;
} CMSKeyAgreeRecipientId;

/* data structure used in the CMS_GetPrivateKey callback. The callback implementer
should use the content of this structure to determine which key is requested */
/**
@brief      CMS recipient identification information.

@details    CMS recipient identification information that is passed to a
            CMS_GetPrivateKey() call.

The CMSRecipientId structure is defined as:
<pre>
    typedef struct CMSRecipientId
    {
        ubyte4 type;
        union
        {
            CMSKeyTransRecipientId    ktrid;   // type = NO_TAG
            CMSKeyAgreeRecipientId    karid;   // type = 1
        } ri;
    } CMSRecipientId;
</pre>

The layout of this structure shadows that of the RecipientInfo object.
<pre>
      RecipientInfo ::= CHOICE {
        ktri KeyTransRecipientInfo,
        kari [1] KeyAgreeRecipientInfo,
        kekri [2] KEKRecipientInfo }
</pre>

@note       The KEKRecipientInfo object is omitted from the \c CMSRecipientId
            structure.

The \p ktrid member supplies a \c CMSKeyTransRecipientId structure, and the
\p karid member supplies a \c CMSKeyAgreeRecipientId structure.

When your callback function must interpret a CMSRecipientId structure, read the
type member.
+ If the type is NO_TAG, the ktrid member applies, and this structure
    provides information from a KeyTransRecipientInfo object.
+ If the type is 1 (one), the karid member applies, and this structure
    provides information from a KeyAgreeRecipientInfo object.
*/
typedef struct CMSRecipientId
{
    ubyte4 type;
    union
    {
        CMSKeyTransRecipientId    ktrid;   /* type = NO_TAG */
        CMSKeyAgreeRecipientId    karid;   /* type = 1 */
       /*
        CMSKEKRecipientId         kekrid;     type = 2 
        CMSPasswordRecipientId    pwrdi;      type = 3 
        CMSOtherRecipientId       orid;       type = 4 
       */
    } ri;
} CMSRecipientId;

/* this callback is used to retrieve the private key that */
/* corresponds to a CMSRecipientId */
/**
@brief      Get the private key associated with a given certificate in
            a CMS message stream.

@details    This callback function searches a given CMS stream (message), \p
            cs, for a certificate that matches given recipient
            information&mdash;serial number and issuer name. To obtain the
            certificate, call the CMS_GetCertificate() callback function. To
            validate the certificate, call the CMS_ValidateRootCertificate()
            callback function. If the certificate is valid, this callback
            function (CMS_GetPrivateKey()) can get the associated private key.

If the subject's PEM-encoded private key is stored in a file, you can copy the
key to an \c AsymmetricKey structure as follows:
@code
AsymmetricKey key;
ubyte* pemKeyFile = FILE_PATH("key.pem");
ubyte *pPemKey=NULL, *pKeyblob=NULL;
ubyte4 pemKeyLen, keyblobLen;

if (OK > (status = DIGICERT_readFile( pemKeyFile, &pPemKey, &pemKeyLen)))
    goto exit;   // at exit, handle error

if (OK > (status = BASE64_initializeContext()))
    goto exit;

if (OK > (status = CA_MGMT_convertKeyPEM(pPemKey, pemKeyLen, &pKeyblob, &keyblobLen)))
    goto exit;

if (OK > (status = BASE64_freeContext()))
    goto exit;

if (OK > (status = CRYPTO_initAsymmetricKey( &key)))
    goto exit;

if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key)))
    goto exit;
@endcode

Given this code, the callback function returns the private key through the \p
pKey parameter.

@todo_eng_review (when is callback invoked?)
@todo_eng_review (what is the \p arg param?)

@ingroup    cb_cert_mgmt_cms

@inc_file cms.h

@param  arg             TBD.
@param  cs              \c CStream containing the CMS message (a \c ContentInfo
                          object containing a CMS \c EnvelopedData object) to
                          search.
@param  pRecipientId    Pointer to CMS \c RecipientId object that contains the
                          serial number and issuer name of the certificate of interest.
@param  pKey            On return, pointer to the certificate's private key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    cms.h
*/
typedef MSTATUS (*CMS_GetPrivateKey)(const void* arg,
                                     CStream cs,
                                     const CMSRecipientId* pRecipientId,
                                     AsymmetricKey* pKey);

/* this callback is used to verify that this certificate is recognized
as valid */
/**
@brief      Validate the certificates in a CMS message.

@details    This callback function validates the certificates in a CMS message.

Which validity checks to perform depends on your application and environment.
Typical checks are:
+ Validity dates.
+ Walking a certificate chain to endsure that each certificate was issued by
    the next certificate in the chain.
+ Ensuring that the last certificate in a chain is trusted.
+ For incomplete certificate chains, searching a private store for certificates
    that could complete the chain.
+ Business logic indicating whether access is ok (regardless of the validity
    of the certificate itself), such as an employee's current status or
    whether a customer's purchase has enabled a given service/access.

@todo_eng_review (when is callback invoked?)
@todo_eng_review (is the "top" certificate the root or end-user?)
@todo_eng_review (what's the "arg" param for?)

@ingroup    cb_cert_mgmt_cms

@inc_file cms.h

@param  arg                 TBD.
@param  cs                  \c CStream containing the CMS message of interest.
@param  pCertificate        Pointer to topmost certificate in the certificate chain
                            whether it is the root or not.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    cms.h
*/
typedef MSTATUS (*CMS_ValidateRootCertificate)(const void* arg,
                                               CStream cs,
                                               ASN1_ITEM* pCertificate);

/* this callback is used to get a certificate given the issuer name and
serial number */
/**
@brief      Return a message's certificate that matches a given serial number
            and issuer name.

@details    This callback function searches a given CMS stream (message), \p
            cs, for a certificate that matches serial number and issuer name. If
            no match is found, this callback function should search a private
            store of certificates (which has been read into a CStream) for a
            match.

@todo_eng_review (when is callback invoked?)
@todo_eng_review (what's the "arg" param for?)

@ingroup    cb_cert_mgmt_cms

@inc_file cms.h

@param  arg             TBD.
@param  cs              \c CStream containing the CMS message in which to
                          search for the certificate.
@param  pSerialNumber   Pointer to \c ANS1_ITEM that references the serial
                          number to search for.
@param  pIssuerName    Pointer to \c ANS1_ITEM that references the issuer name
                          to search for.
@param  ppCertificate   On return, pointer to the matching certificate; NULL
                          if no matching certificate is found.
@param  pCertStream     On return, pointer to \c CStream that
                          contains the matching certificate, \p ppCertificate.
                          The \c CStream can be the same as the input, \p cs,
                          or it can be a \c CStream containing a private store
                          of certificates.

@return     \c OK (0). If no matching certificate is found, NULL is returned in
            the \p ppCertificate parameter.

@callbackdoc    cms.h
*/
typedef MSTATUS (*CMS_GetCertificate)(const void* arg, CStream cs,
                                      ASN1_ITEM* pSerialNumber,
                                      ASN1_ITEM* pIssuerName,
                                      ubyte** ppCertificate,
                                      ubyte4* certificateLen);

/* this callback is used to get a certificate given the subjectKeyIdentifier extension */
/**
@brief      Return a message's certificate that matches a given subjectKeyIdentifier extension.

@details    This callback function searches a given CMS stream (message), \p
            cs, for a certificate that matches the subjectKeyIdnentifier extension. If
            no match is found, this callback function should search a private
            store of certificates (which has been read into a CStream) for a
            match.

@todo_eng_review (when is callback invoked?)
@todo_eng_review (what's the "arg" param for?)

@ingroup    cb_cert_mgmt_cms

@inc_file cms.h

@param  arg             TBD.
@param  cs              \c CStream containing the CMS message in which to
                          search for the certificate.
@param  pSubjectKeyIdentifier Pointer to \c ANS1_ITEM that references the 
                          subjectKeyIdentifier to search for.
@param  ppCertificate   On return, pointer to the matching certificate; NULL
                          if no matching certificate is found.
@param  pCertStream     On return, pointer to \c CStream that
                          contains the matching certificate, \p ppCertificate.
                          The \c CStream can be the same as the input, \p cs,
                          or it can be a \c CStream containing a private store
                          of certificates.

@return     \c OK (0). If no matching certificate is found, NULL is returned in
            the \p ppCertificate parameter.

@callbackdoc    cms.h
*/
typedef MSTATUS (*CMS_GetCertificateVersion3)(const void* arg, CStream cs,
    ASN1_ITEM* pSubjectKeyIdentifier,
    ubyte** ppCertificate,
    ubyte4* certificateLen);

/* all the callbacks that the CMS parser might need. */
/**
@brief      Pointers to functions required by the internal CMS parser.

@details    This structure provides pointers to functions that can get the
            private key for a particular subject, validate a root certificate,
            and search a CStream for a certificate that matches a specified
            issuer name and serial number.

The contained callback functions must conform to the following prototypes:
+ CMS_GetPrivateKey()
+ CMS_ValidateRootCertificate()
+ CMS_GetCertificate()
*/
typedef struct CMS_Callbacks
{
    /**
    @brief      Pointer to the CMS_GetPrivateKey() callback function.
    @details    Pointer to the CMS_GetPrivateKey() callback function.
    */
    CMS_GetPrivateKey             getPrivKeyFun;
    /**
    @brief      Pointer to the CMS_ValidateRootCertificate() callback function.
    @details    Pointer to the CMS_ValidateRootCertificate() callback function.
    */
    CMS_ValidateRootCertificate   valCertFun;
    /**
    @brief      Pointer to the CMS_GetCertificate() callback function.
    @details    Pointer to the CMS_GetCertificate() callback function.
    */
    CMS_GetCertificate            getCertFun;
    /**
    @brief      Pointer to the CMS_GetCertificateVersion3() callback function.
    @details    Pointer to the CMS_GetCertificateVersion3() callback function.
    */
    CMS_GetCertificateVersion3    getCertFunV3;

} CMS_Callbacks;

/**
@brief      This callback is used to perform a signature operation.

@details    This callback is used to perform a signature operation.
            It can be used in place of a private key when a private
            key itself is unavailable, for example in a tpm.

@ingroup    cb_cert_mgmt_cms

@inc_file cms.h

@param  pCbInfo         Optional callback args you may need for your routine.
@param  digestAlgoOID   For RSA, the digest OID to be used when a digest info
                        needs to be created.
@param  pDataToSign     The data to sign. This should be a raw digest and not a
                        digest info.
@param  dataToSignLen   The length of the data to sign in bytes.
@param  pSigBuffer      Buffer that will hold the resulting signature. For ECC
                        and DSA this is r concatenated by s with each padded to
                        their standard length based on the curve or q.
@param  sigBufferLen    The length of the signature buffer in bytes.

@return     \c OK (0) and a negative return code if otherwise.

@callbackdoc    cms.h
*/
typedef MSTATUS (*CMS_SignData)(void *pCbInfo,
                                const ubyte *digestAlgoOID,
                                const ubyte *pDataToSign,
                                ubyte4 dataToSignLen,
                                ubyte *pSigBuffer,
                                ubyte4 sigBufferLen);

/**
@brief      Create a CMS context structure for parsing a received CMS
            object.

@details    This function creates a CMS context structure, initializes
            its  state, and populates its callback pointers with the passed-in
            function pointers, \p pCallbacks.

Use this function to parse a received CMS object. The CMS context structure,
\p pNewContext, contains information required to parse a CMS message. Treat this
structure as opaque, and do not attempt to access its members directly.

@note       To create a new CMS \e object, do not use CMS_newContext(), which
            creates a <em>context structure</em>, not a CMS object. Instead,
            use  CMS_signedNewContext() to create a new \c SignedData object, or
            use CMS_envelopedNewContext() to create a new \c EnvelopedData
            object.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  pNewContext     On return, pointer to a \c MS_context structure, which
                          maintains context information required by functions that
                          parse a CMS message. Treat this structure as opaque,
                          and do not access its members directly.
@param  callbackArg     Pointer to arguments that are required by the function
                          referenced in \p pCallbacks.
@param  pCallbacks      Pointer to a populated \c CMS_Callbacks structure
                          containing pointers to functions for obtaining the
                          private key for a particular subject, for validating a
                          root certificate, and for searching a CStream for a
                          certificate that matches a specified issuer name and
                          serial number.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_newContext(CMS_context* pNewContext,
                                  const void* callbackArg,
                                  const CMS_Callbacks* pCallbacks);

/**
@brief      Add data to a \c CMS_context object.

@details    This function adds data to a given \c CMS_context. The decrypted
            data (if any) is returned in newly allocated output buffers. If
            the logical end of the processing has been reached (that is, no
            more data is necessary), the returned value of \p pFinished is TRUE.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the \c CMS_context object to which to add data.
@param  input       Pointer to the data to add.
@param  inputLen    Length of the data to add, \p input.
@param  ppOutput      On return, pointer to the address of a buffer containing
                      the ASN.1 object to which the \p input contents were added.
@param  pOutputLen  On return, pointer to the length of the ASN.1 object, \p
                      pOutput.
@param  pFinished   On return, pointer \c TRUE if the ASN.1 object, \p pOutput,
                      is complete; otherwise pointer to \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_updateContext( CMS_context context, const ubyte* input,
                                        ubyte4 inputLen, ubyte** ppOutput,
                                        ubyte4* pOutputLen, intBoolean* pFinished);

/**
@brief      Free a CMS context structure.

@details    This function frees (releases) a CMS context structure.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  pContext    Pointer to the CMS context structure to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_deleteContext( CMS_context* pContext);

/*======== other functions to query the context for more information =======*/

/* These functions can return OK (success), ERR_EOF (more data must be provided by calling
CMS_updateContext) or some other error message (invalid data) */
/**
 * @cond
 */
MOC_EXTERN MSTATUS CMS_createContentInfo(const ubyte* contentType,	DER_ITEMPTR *ppContentInfo, DER_ITEMPTR *ppContent);
/**
 * @endcond
 */

/**
@brief      Get the ContentType (\c CMS_contentType enumerated value from
            cms.h) of a given CMS object.

@details    This function returns the ContentType (\c CMS_contentType
            enumerated value from cms.h) of a given CMS object, through the \p cmsContentType parameter.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context         Pointer to the CMS object from which to extract the
                          ContentType.
@param  cmsContentType  On return, pointer to a \c CMS_ContentType enumerated
                          value (see cms.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getContentType( CMS_context context, CMS_ContentType* cmsContentType);

/**
@brief      Get the ContentType (\c CMS_contentType enumerated value from
            cms.h) of a given data buffer input.

@details    This function returns the ContentType (\c CMS_contentType
            enumerated value from cms.h) of the input data buffer, through the \p
            cType parameter.
            Note that this call will only return accurate information on the
            first data buffer.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context   Pointer to the \c CMS_context object

@param  pInput    Pointer to the data from which to ascertain the ContentType

@param  inputLen  Length of the data to add, \p input.

@param  cType     On return, pointer to a \c CMS_ContentType enumerated
                          value (see cms.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getContentTypeOnly( CMS_context context,
                                           const ubyte* pInput,
                                           ubyte4 inputLen, CMS_ContentType* cType);

/**
@brief      Get the OID (with length prefix) of the encapsulated content type.

@details    This function returns the OID (with length prefix) of the
            encapsulated content type of a given CMS_context, through the \p
            ppOID parameter.

@warning    This function allocates memory for the \p ppOID buffer. To avoid
            memory leaks, you must free the buffer when you are done with it.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the CMS context from which to extract the OID.
@param  ppOID       On return, pointer to the address of an OID value. The
                      value's buffer is allocated by this function, and you
                      must free it when you are done with it.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getEncapContentType( CMS_context context, ubyte** ppOID);

/********* EnvelopedData recipients **********/

/**
@brief      Get the number of recipients in a given CMS \c EnvelopedData object.

@details    This function returns the number of recipients in the referenced CMS
            \c EnvelopedData object, through the \p numRecipients parameter. If
            the recipients are not all in the EnvelopedData object, this
            function returns an error (\c ERR_EOF).

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context         EnvelopedData object from which to extract
                          the number of recipients.
@param  numRecipients   On return, pointer to the number of recipients in the
                          referenced EnvelopedData object, \p context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getNumRecipients( CMS_context context,
                                          sbyte4* numRecipients);

/**
@brief      Get offset and length information of a given \c RecipientInfo object
            in a given \c EnvelopedData object, as well as the \c CStream that
            contains the \c RecipientInfo.

@details    This function returns the offset and length information of a
            given \c RecipientInfo object in a given \c EnvelopedData (\c
            CMS_context) object, as well as the \c CStream that contains the
            \c RecipientInfo.

You can use the offset and length information, which is returned through the
\p pRecipientInfo parameter, to find the \c RecipientInfo object in the returned
CStream. If the recipient is not in the \c EnvelopedData (\c CMS_context) object,
this function returns an error (\c ERR_EOF).

@todo_eng_review (there's contradictory info in inherited Doxygen documentation.)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context         Pointer to the CMS context structure for the
                          EnvelopedData object from which you want to extract a
                          RecipientInfo object.
@param  recipientIndexZeroBased   Zero-based index of the \c RecipientInfo
                                    object of interest in the \c EnvelopedData object, \p context. (To  get the
                                    size of the \c EnvelopedData array, call
                                    CMS_getNumRecipients().)
@param  pRecipientInfo  On return, pointer to the address of an \c ASN1_ITEM
                          structure that contains offset and length information for the \c RecipientInfo object of interest.
@param  pCS             On return, pointer to the \c CStream that contains
                          the \c RecipientInfo object of interest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getRecipientInfo( CMS_context context,
                                          sbyte4 recipientIndexZeroBased,
                                          const ASN1_ITEM** pRecipientInfo,
                                          CStream* pCS);

/**
@brief      Gets the index of the decrypting recipient in a given
            \c EnvelopedData object.

@details    This function returns the index of the decrypting recipient in a
            given \c EnvelopedData object, through the \p
            recipientIndexZeroBased parameter.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context                     Pointer to the CMS context structure of the
                                      \c EnvelopedData object to query.
@param  recipientIndexZeroBased     On return, pointer to the zero-based index
                                      of the decrypting recipient in the \c
                                      EnvelopedData object.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getDecryptingRecipient( CMS_context context,
                                          sbyte4* recipientIndexZeroBased);

/**
@brief      Get the OID (with prefix length) of the encryption algorithm of a
            given \c CMS_context.

@details    This function returns the OID (with prefix length) of the encryption
            algorithm of a given \c CMS_context, through the \p ppEncryptionAlgoOID parameter.

@warning    This function allocates memory for the \p ppEncryptionAlgoOID
            buffer. To avoid memory leaks, you must free the buffer when you
            are done with it.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context                 Pointer to the \c CMS_context for the
                                  \c EnvelopedData object to query.
@param  ppEncryptionAlgoOID     On return, pointer to the address of a buffer
                                  that contains the OID (with prefix length)
                                  of the encryption algorithm. value's buffer
                                  is allocated by this function, and you must
                                  free it when you are done with it.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getEncryptionAlgo( CMS_context context,
                                         ubyte** ppEncryptionAlgoOID);

/******* SignedData signers **********/

/**
@brief      Get the number of verified signers of a given \c SignedData object.

@details    This function returns the number of verified signers of a given
            \c SignedData object, returned through the \p numSigners parameter.

If you do not know whether the given \c SignedData object is a detached
signature, before calling this function you should call
CMS_detachedSignature(). If the \c SignedData object \e is a detached
signature, you must call CMS_setDetachedSignatureData() before calling the
CMS_getNumSigners function. Otherwise, the CMS_getNumSigners function cannot
verify the signers, and will return the error, \c ERR_PKCS7_DETACHED_DATA.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the \c CMS_context structure that contains the
                      \c SignedData object of interest.
@param  numSigners  On return, pointer to the number of verified signers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getNumSigners( CMS_context context,
                                        sbyte4* numSigners);

/**
@brief      Get the SignerInfo object for a given verified signer.

@details    Call this function to get an ASN1_ITEM structure that provides the
            offset and length information for a \c SignerInfo object for a
            verified signer of the given \c SignedData object.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the \c CMS_context structure containing the \c
                      SignedData object from which to extract the \c
                      SignerInfo object.
@param  index       Zero-based index of the \c SignerInfo object of interest
                      in the \c SignedData object that is in \p context. (To
                      get the size of the SignedData array, call
                      CMS_getNumSigners().)
@param  ppRecipientInfo     On return, pointer to the address of an
                              \c ASN1_ITEM structure that contains offset and
                              length information for the \c SignerInfo object
                              of interest.
@param  pCS         On return, pointer to the \c CStream that contains
                      the \c SignedData object of interest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getSignerInfo( CMS_context context,
                                      sbyte4 index,
                                      const ASN1_ITEM** ppRecipientInfo,
                                      CStream* pCS);

/**
@brief      Get message ID and signature of a given signed \c Receipt.

@details    This function gets the message ID and signature of a given signed
            \c Receipt.

Call this function after the \c signedData has been parsed and the
signature(s) verified. The encapsulated Content Type (see
CMS_getEncapContentType()) is \c id-ct-receipt. The receipt is the signed
data (which is built by concatenating the \c CMS_updateContext object's
returned buffers).

@warning    The returned pointers point to data inside the input \p receipt
            buffer. Do not free these pointers.

@todo_eng_review (confusing description in inherited Doxygen comments)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  receipt         Pointer to signed \c Receipt of interest.
@param  receiptLen      Length of the \c Receipt buffer, \p receipt.
@param  messageId       On return, pointer the address of an offset into the
                          signed \c Receipt for the message ID.
@param  messageIdLen    On return, pointer to length of the message ID, \p                          messageId.
@param  signature       On return, pointer to the address of an offset into the
                          signed \c Receipt for the signature.
@param  signatureLen    On return, pointer to the length of the signature, \p
                          signature.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getReceiptInfo( const ubyte* receipt, ubyte4 receiptLen,
                                        const ubyte** messageId, ubyte4* messageIdLen,
                                        const ubyte** signature, ubyte4* signatureLen);

/**
@brief      Get the message digest of a given signed \c Receipt.

@details    This function gets the message digest of a given signed \c Receipt.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context         Pointer to \c CMS_context for the signed \c Receipt
                          object of interest.
@param  ppDigest        On return, pointer to the address of a buffer
                          containing the message digest of the signed \c Receipt.
@param  pDigestLen      On return, pointer to the length of the message digest
                          buffer, \p ppDigest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getReceiptMsgDigest( CMS_context context,
                                           const ubyte** ppDigest, ubyte4* pDigestLen);

/**
@brief      Get the first certificate (its \c ASN1_ITEM structure) in a given
            \c CMS_context \c SignedData object.

@details    This function Get the first certificate (its \c ASN1_ITEM
            structure) in a given\c CMS_context \c SignedData object. The \c
            ASN1_ITEM structure contains offset and length information for the
            certificate that is in the returned \c CStream, \p pCS.

To get subsequent certificates, use ASN1_NEXT_SIBLING.

@todo_eng_review (Pls clarify how to "use ASN1_NEXT_SIBLING" to get subsequent
                  certificates.)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context         Pointer to the \c CMS_context for the \c SignedData
                          object from which to get its first certificate.
@param  ppCertificate   On return, pointer to the address of the \c ASN1_ITEM
                          structure for the found certificate. This structure
                          contains offset and length information for the
                          certificate, which is in the \c CStream, \p pCS.
@param  pCS             On return, pointer to the \c CStream that contains
                          the \c ASN1_ITEM structure, \p ppCertificate, of the
                          first certificate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_getFirstCertificate( CMS_context context,
                                           const ASN1_ITEM** ppCertificate,
                                           CStream* pCS);

/**
@brief      Determine whether a given \c CMS_context is a detached signature.

@details    This function determines whether a given \c CMS_context is a
            detached signature&mdash;a \c SignedData object that contains the
            signature that would otherwise be included in a different \c
            CMS_context.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the \c CMS_context of interest.
@param  detached    On return, pointer to \c TRUE if the \p context is a
                      detached signature; otherwise \c pointer to \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_detachedSignature(CMS_context context, intBoolean* detached);

/**
@brief      Add payload information to a \c CMS_context so that it can
            verify a detached signature.

@details    This function adds payload information to a \c CMS_context so that
            it can verify a <em>detached signature</em>&mdash;a \c SignedData
            object that contains the signature that would otherwise be included in the \c CMS_context.

@todo_eng_review (There are confusing statements in inherited Doxygen
                    documentation.)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:`
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the \c CMS_context structure that
                      contains the \c SignedData object that is an external
                      signature for the data in the buffer, \p payload.\n On
                      return, also contains the information that is required
                      to verify the \c SignedData object's detached signature.
@param  payload     Pointer to the buffer containing the data that is signed
                      by the \p context object's \c SignedData object.
@param  payloadLen  Length of the signed data, \p payload.
@param  final       \c TRUE if all the data is already added; otherwise \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_setDetachedSignatureData( CMS_context context, const ubyte* payload,
                                                ubyte4 payloadLen, intBoolean final);

/**
@brief      Create a signed \c Receipt on the given message for a given signer.

@details    This function creates a signed \c Receipt object for the given
            message and signer. A <em>signed \c Receipt</em> object is a \c
            Receipt object that is encapsulated within a \c SignedData object.

For details about \c Receipt and signed \c Receipt objects, refer to
RFC&nbsp;2634.

@todo_eng_review (FIPS-compliance info in \p rngFun parameter desc)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  context     Pointer to the CMS context structure for the
                      \c SignedData object for which you want to create a
                      signed \c Receipt.
@param  index       Index value indicating the verified signer of the \c
                      SignedData object for which you want to generate a signed
                      \c Receipt.
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().
@param  signerCert  Pointer to a DER-encoded certificate for the signer
                      of the signed \c Receipt to create.
@param  signerCertLen   Length of the DER-encoded certificate, \p signerCert.
@param  pKey        Pointer to an \c AsymmetricKey structure containing the
                      signer's private key, which is used to sign the \c
                      Receipt.
@param  hashAlgoOID Pointer to the OID for the message digest method to use
                      for this signer. Valid values are pointers to \c md5_OID or
                      \c sha1_OID, which are defined in src/asn1/oiddefs.h.
@param  ppReceipt   On return, pointer to the signed \c Receipt object, which
                      is encapsulated in a \c SignedData object.
@param  pReceiptLen On return, pointer to the length of the signed \c Receipt
                      object, \p ppReceipt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_createSignedReceipt( CMS_context context,
                                            sbyte4 index,
                                            RNGFun rngFun, void* rngFunArg,
                                            const ubyte* signerCert, ubyte4 signerCertLen,
                                            const AsymmetricKey* pKey, const ubyte* hashAlgoOID,
                                            ubyte** ppReceipt, ubyte4* pReceiptLen);

/************ CREATING CMS API **************************************/
/* 2 distinct APIs are provided for creating CMS, one for signed data and the other
for enveloped data */


/**
@brief      Create a CMS \c SignedData object.

@details    This function creates a CMS \c SignedData object. After you call
            this function, you must call other functions to populate to
            populate the object.

@note       To create a new CMS <em>context structure</em>, do not use this
            function, which creates a CMS \c SignedData \e object. Instead, use
            CMS_newContext().

To delete and free the \c SignedData object, call CMS_signedDeleteContext().

@sa     CMS_signedAddCertificate()
@sa     CMS_signedAddCRL()
@sa     CMS_signedAddSigner()
@sa     CMS_signedAddSignerAttribute()
@sa     CMS_signedAddReceiptRequest()
@sa     CMS_signedUpdateContext()
@sa     CMS_signedDeleteContext()

@todo_eng_review (FIPS-compliance info in \p rngFun parameter desc)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  pNewCtx         On return, pointer to the new \c SignedData object.
@param  payloadTypeOID  Pointer to an OID describing the data against which
                          this \c SignedData object is a signature. The
                          src/asn1/oiddefs.c file defines the valid constant
                          arrays, such as \c pkcs7_data_OID. You can create
                          a \c SignedData object for other types of payloads,
                          such as \c pkcs7_encryptedData_OID. Refer to
                          src/asn1/oiddefs.c for the arrays of OID types.
@param  detached        \c TRUE if the \c SignedData object is a detached
                          signature; otherwise \c FALSE.
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedNewContext( CMS_signedDataContext* pNewCtx,
                                           const ubyte* payloadTypeOID,
                                           intBoolean detached, RNGFun rngFun,
                                           void* rngFunArg);

/**
@brief      Add a signed certificate to a CMS \c SignedData object.

@details    This function adds a signed certificate to CMS \c SignedData object.
            This function can add an intermediate certificate.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to the CMS \c SignedData object to which to add a
                      certificate.
@param  cert        Pointer to DER-encoded certificate to add.
@param  certLen     Length of the certificate buffer, \p cert.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedAddCertificate( CMS_signedDataContext myCtx, const ubyte* cert,
                                        ubyte4 certLen);

/**
@brief      Add a signed CRL to a CMS \c SignedData object.

@details    This function adds a signed CRL (Certificate Revocation List) to
            a CMS \c SignedData object.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to CMS \c SignedData object to which to add a CRL.
@param  crl         Pointer to the DER-encoded CRL to add.
@param  crlLen      Length of the CRL buffer, \p crl.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedAddCRL( CMS_signedDataContext myCtx, const ubyte* crl,
                                        ubyte4 crlLen);

/* flags in CMS_signedAddSigner are a combination of the following values */
enum {
    e_cms_signer_addCert = 0x0001,       /* add the certificate to the CMS */
    e_cms_signer_forceAuthAttr = 0x0002, /* this signer wants to add some authenticated attributes */
    e_cms_signer_version3 = 0x0004       /* version 3 signer info with SubjectKeyIdentifier */
};

/**
@brief      Add a signer to a given \c SignedData object.

@details    This function adds a signer, and optionally a certificate and
            authenticated atrributes, to a given \c SignedData object.

@todo_eng_review (Does this function "add" or "allocate, initialize, and
                    populate"?)

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to the CMS context for the SignedData object
                      to which to add a signer.
@param  cert        Pointer to signer's DER-encoded certificate.
@param  certLen     Length of the signer's DER-encoded certificate, \p cert.
@param  pKey        Pointer to signer's key, an \c AsymetricKey structure.
@param  digestAlgoOID   Pointer to the OID for the message digest method to
                          use for the signer. Valid values are \c md5_OID or
                          \c sha1_OID, defined in src/asn1/oiddefs.h.
@param  flags       Zero (0) or bitmask combination (created by
                      <tt>OR</tt>ing definitions together) specifying which
                      signing elements to include (defined in cms.h):
        + \c e_cms_signer_addCert&mdash;Add the certificate to the CMS context.
        + \c e_cms_signer_forceAuthAttr&mdash;Add authenticate attributes.
        + \c e_cms_signer_version3
@param  pNewSignerInfo  On return, pointer to a newly allocated
                          \c CMS_signerInfo structure (an opaque structure).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedAddSigner( CMS_signedDataContext myCtx,
                                        const ubyte* cert,
                                        ubyte4 certLen,
                                        const AsymmetricKey* pKey,
                                        const ubyte* digestAlgoOID,
                                        ubyte4 flags,
                                        CMS_signerInfo* pNewSignerInfo);


/**
@brief      Add a signer to a given \c SignedData object when the private key
            is unavailable.

@details    Add a signer to a given \c SignedData object when the private key
            is unavailable. Later a callback will be used to perform the signing
            operation.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to the CMS context for the SignedData object
                      to which to add a signer.
@param  cert        Pointer to signer's DER-encoded certificate.
@param  certLen     Length of the signer's DER-encoded certificate, \p cert.
@param  signCallback    Callback that will perform a signing operation given
                        the proper inputs.
@param  pCbInfo         Optional callback argument that may be needed by
                        your implementation. 
@param  digestAlgoOID   Pointer to the OID for the message digest method to
                          use for the signer. Valid values are \c md5_OID or
                          \c sha1_OID, defined in src/asn1/oiddefs.h.
@param  flags       Zero (0) or bitmask combination (created by
                      <tt>OR</tt>ing definitions together) specifying which
                      signing elements to include (defined in cms.h):
        + \c e_cms_signer_addCert&mdash;Add the certificate to the CMS context.
        + \c e_cms_signer_forceAuthAttr&mdash;Add authenticate attributes.
        + \c e_cms_signer_version3
@param  pNewSignerInfo  On return, pointer to a newly allocated
                          \c CMS_signerInfo structure (an opaque structure).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedAddSignerWithCallback( MOC_HW(hwAccelDescr hwAccelCtx)
                                                    CMS_signedDataContext myCtx,
                                                    const ubyte* cert,
                                                    ubyte4 certLen,
                                                    CMS_SignData signCallback,
                                                    void* pCbInfo,
                                                    const ubyte* digestAlgoOID,
                                                    ubyte4 flags,
                                                    CMS_signerInfo* pNewSignerInfo);
/**
@brief      Add an attribute (authenticated or non-authenticated) to a CMS \c
            SignedData object's signer(s).

@details    This function adds an attribute (authenticated or
            non-authenticated) to a CMS \c SignedData object's signer(s).

To add an authenticated signer attribute, RFC&nbsp;5652 requires that you add at
least two attributes:
+ A content-type attribute specifying the content type of the \c
    EncapsulatedContentInfo value being signed.
+ A message-digest attribute, specifying the message digest of the content.

A typical function call is similar to the following:
<pre>
CMS_signedAddSignerAttribute(
	myCtx,
	mySigner,
	pkcs9_emailAddress_OID,
	PRINTABLESTRING,
	(const ubyte*) "nobody@mocana.com",
	17,
	1)
</pre>

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to the CMS \c SignedData object containing the
                      signer(s) to which to add an attributed.
@param  signerInfo  Zero (0) to add the attribute to all signers; otherwise
                      pointer to the \c CMS_signerInfo structure, created by
                      CMS_signedAddSigner(), for the signer to which to add
                      the attribute.
@param typeOID      OID specifying the type of signer attribute to add, such
                      as \c pkcs9_emailAddress_OID.
@param  type        OID specifying the content type of the signer attribute; for
                      example, the \c PRINTABLESTRING constant defined in
                      src/asn1/parseasn1.h.
@param  value       Pointer to the signer attribute to add; for example,
                      "nobody@mocana.com".
@param  valueLen    Length of the signer attribute to add, \p value.
@param  authenticated   \c TRUE if the signer attribute to add, \p value, is an
                        authenticated attribute; otherwise \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedAddSignerAttribute( CMS_signedDataContext myCtx,
                                            CMS_signerInfo signerInfo,
                                            const ubyte* typeOID,
                                            ubyte4 type, /* id|tag */
                                            const ubyte* value,
                                            ubyte4 valueLen,
                                            intBoolean authenticated);

/**
@brief      Request a receipt for a given message.

@details    This function requests a receipt for a given message.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx           Pointer to the CMS \c SignedData object containing the
                          signer(s) to which to add a receipt request.
@param  receiptFrom     Array of recipient email addresses from which receipts
                          are requested.
@param  numReceiptFrom  -1 for all; 0 for not on mailing list; >0 to use the
                          \p receiptFrom value.
@param  receiptTo       Array of email addresses to which to send receipts.
@param  numReceiptTo   -1 for all; 0 for not on mailing list; >0 to use the
                          \p receiptTo value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedAddReceiptRequest( MOC_HASH(hwAccelDescr hwAccelCtx)
                        CMS_signedDataContext myCtx,
                        const ubyte** receiptFrom,  /* Array of recipient email addresses from which receipts are requested*/
                        sbyte4 numReceiptFrom,      /* -1 for all, 0 for not on mailing list or > 0 to use the receiptFrom arg */
                        const ubyte** receiptTo,    /* Array of email addresses that receipts are to be sent to */
                        sbyte4 numReceiptTo);

/**
@brief      Extract receipt request information.

@details    This function extracts receipt request information, which should
            be saved for processing the receipt when it arrives.

Do not call this function until \e after:
+ You create the receipt request by calling CMS_signedAddReceiptRequest().
+ The last call to CMS_signedUpdateContext(), which must specify \c TRUE for
    the \p finished parameter.

@warning    The returned pointers point to data inside the  \c
            CMS_signedDataContext structure. Do not free these pointers. If
            the \c CMS_signedDataContext structure is deleted, these pointers
            become invalid.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx           Pointer to the CMS \c SignedData object from which to
                          extract receipt request information.
@param  signerInfo      Pointer to the \c CMS_signerInfo structure, created by
                          CMS_signedAddSigner(), for the signer from which to
                          extract receipt request information.
@param  messageId       On return, pointer the address of an offset into the
                          signed \c Receipt for the message ID.
@param  messageIdLen    On return, pointer to length of the message ID, \p                          messageId.
@param  digest          On return, pointer the address of an offset into the
                          signed \c Receipt for the message digest.
@param  digestLen       On return, pointer to length of the message digest, \p                          digest.
@param  signature       On return, pointer the address of an offset into the
                          signed \c Receipt for the signature.
@param  signatureLen    On return, pointer to length of the signature, \p                          signature.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedGetRequestInfo( CMS_signedDataContext myCtx,
                                        CMS_signerInfo signerInfo,
                                        const ubyte** messageId, ubyte4* messageIdLen,
                                        const ubyte** digest, ubyte4* digestLen,
                                        const ubyte** signature, ubyte4* signatureLen);

/**
@brief      Add data to a CMS \c SignedData object.

@details    This function adds data to a CMS \c SignedData object.

@note       In streaming mode, output must be quick. As soon as all the data
            is in, call this function with the \p finished parameter equal to \c
            TRUE, which indicates that all the data is in and that the CMS can
            be generated in its entirety.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to the CMS \c SignedData object to which to add data.
@param  data        Pointer to the data to add.
@param  dataLen     Length of the data to add, \p data.
@param  ppOutput    On return, if \p finished is \c TRUE, pointer to the
                      address of the DER-encoded, signed CMS \c SignedData object.
@param  pOutputLen  On return, if \p finished is \c TRUE, pointer to the
                      length of the DER-encoded, signed CMS \c SignedData
                      object, \p ppOutput.
@param  finished    \c TRUE if this function supplies the last data to add;
                      otherwise \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedUpdateContext( MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           CMS_signedDataContext myCtx,
                                           const ubyte* data, ubyte4 dataLen,
                                           ubyte** ppOutput, ubyte4* pOutputLen,
                                           intBoolean finished);

/**
@brief      Delete and free a CMS \c SignedData object that was allocated by
            CMS_signedNewContext().

@details    This function deletes and frees a CMS \c SignedData object that was
            allocated by CMS_signedNewContext().

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  ppCtx       Pointer to CMS \c SignedData object to delete and free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_signedDeleteContext(MOC_HASH(hwAccelDescr hwAccelCtx)
                                           CMS_signedDataContext* ppCtx);


/**
@brief      Create a CMS \c EnvelopedData object.

@details    This function creates a CMS \c EnvelopedData object. After you
            call this function, you must call other functions to populate the
            object.

@note       To create a new CMS <em>context structure</em>, do not use this
            function, which creates a CMS \c EnvelopedData \e object. Instead,
            use CMS_newContext().

To delete and free the \c EnvelopedData object, call
CMS_envelopedDeleteContext().

@sa         CMS_envelopedAddRecipient()
@sa         CMS_envelopedAddUnauthAttribute()
@sa         CMS_envelopedUpdateContext()
@sa         CMS_envelopedDeleteContext()

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  pNewCtx         On return, pointer to the new \c EnvelopedData object.
@param  encryptAlgoOID  Pointer to OID array that describes the type of
                          encryption to apply to the \c EnvelopedData object.
                          Use any of the preconfigured OID arrays from
                          src/asn1/oiddefs.h:
                          + \c aes128CBC_OID
                          + \c aes192CBC_OID
                          + \c aes256CBC_OID
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and
                      make sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is
                      defined in moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@todo_eng_review (FIPS-compliance info in \p rngFun parameter description.)

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_envelopedNewContext( CMS_envelopedDataContext* pNewCtx,
                                                  const ubyte* encryptAlgoOID,
                                                  RNGFun rngFun, void* rngFunArg);

/**
@brief      Add a recipient, identified by its DER-encoded certificate, to a
            CMS \c EnvelopedData object.

@details    This function adds a recipient to a CMS \c EnvelopedData object.
            You identify the recipient using its DER-encoded certificate.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to CMS \c EnvelopedData object to which to add a
                      recipient.
@param  cert        Pointer to the recipients's DER-encoded certificate.
@param  certLen     Length of the certificate buffer, \p cert.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_envelopedAddRecipient( CMS_envelopedDataContext myCtx,
                                              const ubyte* cert, ubyte4 certLen);


/**
@brief      Add an unauthenticated attribute to a CMS \c EnvelopedData object.

@details    This function adds an unauthenticated attribute to a CMS \c
            EnvelopedData object.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to the CMS \c EnvelopedData object to which to add
                      the unauthenticated attribute.
@param  typeOID     Pointer to OID value specifying the data type of enveloped
                      data.
@param  type        Pointer to content type of the enveloped data.
@param  value       Pointer to unauthenticated attribute to add.
@param  valueLen    Length of the unauthenticated attribute to add, \p value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_envelopedAddUnauthAttribute( CMS_envelopedDataContext myCtx,
                                            const ubyte* typeOID,
                                            ubyte4 type, /* id|tag */
                                            const ubyte* value,
                                            ubyte4 valueLen);

/**
@brief      Add data to a CMS \c EnvelopedData object.

@details    This function adds data to a CMS \c EnvelopedData object.

@note       In streaming mode, output must be quick. As soon as all the data
            is in, call this function with the \p finished parameter equal to \c
            TRUE, which indicates that all the data is in and that the CMS can
            be generated in its entirety.

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  myCtx       Pointer to CMS \c EnvelopedData object to which to add data.
@param  data        Pointer to the data to add.
@param  dataLen     Length of the data to add, \p data.
@param  ppOutput    On return, if \p finished is \c TRUE, pointer to the
                      address of the DER-encoded, signed CMS \c EnvelopedData
                      object.
@param  pOutputLen  On return, if \p finished is \c TRUE, pointer to the
                      length of the DER-encoded, signed CMS object, \p ppOutput.
@param  finished    \c TRUE if this function supplies the last data to add;
                      otherwise \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_envelopedUpdateContext(MOC_HW(hwAccelDescr hwAccelCtx)
                                              CMS_envelopedDataContext myCtx,
                                              const ubyte* data, ubyte4 dataLen,
                                              ubyte** ppOutput, ubyte4* pOutputLen,
                                              intBoolean finished);

/**
@brief      Delete and free a CMS \c EnvelopedData object that was allocated by
            CMS_envelopedNewContext().

@details    This function deletes and frees a CMS \c EnvelopedData object that
            was allocated by CMS_envelopedNewContext().

@ingroup    cms_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@inc_file   pkcs7.h, cms.h

@param  ppCtx       Pointer to CMS \c EnvelopedData object to delete and free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cms.h
*/
MOC_EXTERN MSTATUS CMS_envelopedDeleteContext(MOC_SYM(hwAccelDescr hwAccelCtx)
                                              CMS_envelopedDataContext* ppCtx);


#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __CMS_HEADER__ */
