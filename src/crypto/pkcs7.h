/*
 * pkcs7.h
 *
 * PKCS#7 Parser and utilities routines
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
@file       pkcs7.h

@brief      Header file for SoT Platform PKCS&nbsp;\#7 convenience API.

@details    Header file for SoT Platform PKCS&nbsp;\#7 convenience API.

*/

#ifndef __PKCS7_HEADER__
#define __PKCS7_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

/* PKCS7_signData flags */
#define PKCS7_EXTERNAL_SIGNATURES 0x01

/* type definitions */

struct ASN1_ITEM;

struct DER_ITEM;

struct AsymmetricKey;

enum encryptedContentType;

typedef struct CertsData
{
	ubyte *pCertData;
	ubyte4 certDataLen;
} CERTS_DATA;


/**
@brief      Information about an attribute of a \c SignedData object.

@details    This structure contains information about an attribute of a \c
            SignedData object.

For the \c typeOID field, specify any of the following preconfigured
PKCS&nbsp;\#9 attribute constant arrays from src/asn1/oiddefs.h:
+ \c pkcs9_emailAddress_OID
+ \c pkcs9_contentType_OID
+ \c pkcs9_messageDigest_OID
+ \c pkcs9_signingTime_OID
+ \c pkcs9_challengePassword_OID
+ \c pkcs9_extensionRequest_OID

@todo_eng_review (is the given list of \c pkcs9_* constants complete? there are
                  more in oiddefs.h...)

\b Example \n
To populate an \c Attribute structure to store an email address, you could use
code similar to the following snippet:
@code
    pAuthAttributes = (Attribute *)MALLOC(sizeof(Attribute)*authAttributeLen);
    if (!pAuthAttributes)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pAuthAttributes->typeOID = pkcs9_emailAddress_OID;
    pAuthAttributes->type = PRINTABLESTRING;
    pAuthAttributes->value = "nobody@mocana.com";
    pAuthAttributes->valueLen = 17;
@endcode
*/
typedef struct Attribute
{
    const ubyte* typeOID;
    ubyte4 type; /* id|tag */
    ubyte* value;
    ubyte4 valueLen;
} Attribute;

/**
@brief      Information about a \c SignedData object's signer.

@details    This structure contains information about a \c SignedData
            object's signer. The structure (when populated) provides signing
            information to the PKCS7_SignData() function.
*/
typedef struct signerInfo {
    /**
    @brief      ASN1_ITEMPTR for the \c Issuer object in this signer's
                  certificate.
    */
    struct ASN1_ITEM* pIssuer; /* signer certificate's issuer */
    /**
    @brief      ASN1_ITEMPTR for the \c SerialNumber object in this signer's
                  certificate.
    */
    struct ASN1_ITEM* pSerialNumber; /* signer certificate's issuer specific serial number */
    /**
    @brief      \c CStream for the certificate referenced by \p pSerialNumber and
                  \p pIssuer.
    */
    CStream cs; /* common stream for both issuer and serial number */
    /**
    @brief      Pointer to \c AsymmetricKey structure that contains the signer's
                  private key.
    */
    AsymmetricKey* pKey; /* private key */
    /**
    @brief      Pointer to the OID for the message digest method to use for this
                  signer.

    @details    Stores a pointer to the OID for the message digest method to use
                  for this signer. Valid values for this member are pointers
                  to \c md5_OID or \c sha1_OID, which are defined in
                  src/asn1/oiddefs.h.
    */
    const ubyte* digestAlgoOID; /* must point to one of the constants in oiddefs.h */
    /**
    @brief      For future use.
    */
    const ubyte* unused;
    /**
    @brief      NULL or pointer to an \c Attributes structure for the signer's
                  authenticated attributes.

    @details    NULL or a pointer to an \c Attributes structure for the signer's
                  authenticated attributes. If there is more than one attribute,
                  use this member to reference an array of \c Attributes
                  structures.

    These attributes are optional if the \c ContentInfo object's type is data.
    */
    Attribute* pAuthAttrs;
    /**
    @brief      Size of the authenticated attributes, \p pAuthAttrs.
    */
    ubyte4 authAttrsLen;
    /**
    @brief      NULL or pointer to an \c Attributes structure for the signer's
                  non-authenticated attributes.

    @details    NULL or a pointer to an \c Attributes structure for the signer's
                  non-authenticated attributes. If there is more than one
                  attribute, use this member to reference an array of \c
                  Attributes structures.

    The atttribute types are as defined by PKCS&nbsp;\#9.
    */
    Attribute* pUnauthAttrs;
    /**
    @brief      Size of the authenticated attributes, \p pUnauthAttrs.
    */
    ubyte4 unauthAttrsLen;
} signerInfo;

typedef struct signerInfo *signerInfoPtr;

/* this callback is used to retrieve the private key that
   corresponds to an issuer and serial number; key will
   be released by PKCS7 stack */
/**
@brief      Get the private key associated with a given certificate in a
            PKCS&nbsp;\#7 message (CMS message stream).

@details    This callback function searches a given PKCS&nbsp;\#7 message (CMS
            message stream), \p cs, for a certificate that matches the given
            serial number and issuer name. To obtain the certificate, you could
            call the PKCS7_GetCertificate() callback function, which searches
            both the given \c CStream, cs, and a private store of certificates.
            To validate the certificate, call the
            PKCS7_ValidateRootCertificate() callback function. If the
            certificate is valid, this callback function
            (PKCS7_GetPrivateKey()) can get the associated private key.

If the subject's PEM-encoded private key is stored in a file, you can copy the
key to an \c AsymmetricKey structure as follows:

@code
AsymmetricKey key;
ubyte* pemKeyFile = FILE_PATH("key.pem");
ubyte *pPemKey=NULL, *pKeyblob=NULL;
ubyte4 pemKeyLen, keyblobLen;

if (OK > (status = MOCANA_readFile( pemKeyFile, &pPemKey, &pemKeyLen)))
    goto exit;   // at exit, handle error

if (OK > (status = CA_MGMT_convertKeyPEM(pPemKey, pemKeyLen, &pKeyblob, &keyblobLen)))
    goto exit;

if (OK > (status = CRYPTO_initAsymmetricKey( &key)))
    goto exit;

if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyblob, keyblobLen, &key)))
    goto exit;
@endcode

Given this code, the callback function returns the private key through the \p
pKey parameter.

@ingroup    cb_cert_mgmt_pkcs7

@inc_file pkcs7.h

@param  arg             Data that can be passed to the callback.
@param  cs              \c CStream containing the PKCS&nbsp;7 message (a \c
                          ContentInfo object containing a CMS \c EnvelopedData
                          object) to search.
@param  pSerialNumber   Pointer to \c ASN1_ITEM structure containing the
                          certificate serial number of interest. To get this
                          pointer, call X509_getCertificateIssuerSerialNumber()
                          against a certificate that is known to contain the
                          issuer and serial number of interest.
@param  pIssuerName     Pointer to \c ASN1_ITEM structure containing the
                          issuer name of interest. To get this pointer, call
                          X509_getCertificateIssuerSerialNumber() against a
                          certificate that is known to contain the issuer
                          and serial number of interest.
@param  pKey            On return, pointer to the certificate's private key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    pkcs7.h
*/
typedef MSTATUS (*PKCS7_GetPrivateKey)(const void* arg,
                                       CStream cs,
                                       struct ASN1_ITEM* pSerialNumber,
                                       struct ASN1_ITEM* pIssuerName,
                                       struct AsymmetricKey* pKey);

/* this callback is used to verify that this certificate is recognized
   as valid */
/**
@brief      Validate the certificates in a PKCS&nbsp;\#7 message.

@details    This callback function validates the certificates in a
            PKCS&nbsp;\#7 message.

Which validity checks to perform depends on your application and environment.
Typical checks are:
+ Validity dates.
+ Walking a certificate chain to ensure that each certificate was issued by
    the next certificate in the chain.
+ Ensuring that the last certificate in a chain is trusted.
+ For incomplete certificate chains, searching a private store for certificates
    that could complete the chain.
+ Business logic indicating whether access is ok (regardless of the validity
    of the certificate itself), such as an employee's current status or
    whether a customer's purchase has enabled a given service/access.

If the Mocana certificate store is being used then look at
CERT_STORE_PKCS7_ValidateRootCertificate in mss/src/crypto/cert_store.c on how
to use the certificate store to validate a certificate.

@todo_eng_review (when is this callback invoked?)
@todo_eng_review (is the "top" certificate the root or end-user?)

@ingroup    cb_cert_mgmt_pkcs7

@inc_file pkcs7.h

@param  arg                 Data that can be passed to the callback.
@param  cs                  \c CStream containing the PKCS&nbsp;\#7 message.
@param  pCertificate        Pointer to topmost certificate in the certificate chain
                            whether it is the root or not.
@param  chainLength         The lenth of the certificate chain from the current to the
                            topmost parent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    pkcs7.h
*/
typedef MSTATUS (*PKCS7_ValidateRootCertificate)(const void* arg,
                                                 CStream cs,
                                                 struct ASN1_ITEM* pCertificate,
                                                 sbyte4 chainLength);

/* this callback is used to get a certificate given the issuer name and
   serial number; the ppCertificate will be released by the PKCS7 stack */
/**
@brief      Get a certificate for a given issuer name and serial number.

@details    This callback function gets a certificate (that matches a given
            issuer name and serial number) for a \c SignedData object whose
            certificates are external to its data. The @ref
            PKCS7_VerifySignedData() and @ref PKCS7_VerifySignedDataEx()
            functions invoke this callback to
            search for certificates for such \c SignedData objects.

This callback function should call PKCS_GetCertificates() to search the given
\c CStream, pCertStream, for the first certificate that contains a \c
SignedData object; if none are found, this callback function should then
search a private store of certificates. Then you can search for the desired
certificate among those found by PCKS_GetCertificates() or among those found
in the private store.

@ingroup    cb_cert_mgmt_pkcs7

@inc_file pkcs7.h

@param  arg             Data that can be passed to the callback.
@param  cs              \c CStream containing a PKCS&nbsp;\#7 message (a \c
                          ContentInfo object) containing the \c SignedData
                          object to search for a matching certificate.
@param  pSerialNumber   Pointer to \c ASN1_ITEM structure containing the
                          certificate serial number of interest. To get this
                          pointer, call X509_getCertificateIssuerSerialNumber()
                          against a certificate that is know to contain the
                          issuer and serial number of interest.
@param  pIssuerName     Pointer to \c ASN1_ITEM structure containing the
                          issuer name of interest. To get this pointer, call
                          X509_getCertificateIssuerSerialNumber() against a
                          certificate that is known to contain the issuer
                          and serial number of interest.
@param  ppCertificate   On return, pointer to buffer of the matching
                          certificate. If no match is found, the value is
                          NULL (zero).
@param  certificateLen  On return, length of the matching certificate.

@return     \c OK (0) under all circumstances.

@callbackdoc    pkcs7.h
*/
typedef MSTATUS (*PKCS7_GetCertificate)(const void* arg,
                                        CStream cs,
                                        struct ASN1_ITEM* pSerialNumber,
                                        struct ASN1_ITEM* pIssuerName,
                                        ubyte** ppCertificate,
                                        ubyte4* certificateLen);


/* this callback is used to get a certificate given the subjectKeyIdentifier
   extension; the ppCertificate will be released by the PKCS7 stack */
/**
@brief      Get a certificate for a given subjectKeyIdentifier.

@details    This callback function gets a certificate (that matches a given
            subjectKeyIdentifier) for a \c SignedData object whose
            certificates are external to its data. The @ref
            PKCS7_VerifySignedData() and @ref PKCS7_VerifySignedDataEx()
            functions invoke this callback to
            search for certificates for such \c SignedData objects.

This callback function should call PKCS_GetCertificates() to search the given
\c CStream, pCertStream, for the first certificate that contains a \c
SignedData object; if none are found, this callback function should then
search a private store of certificates. Then you can search for the desired
certificate among those found by PCKS_GetCertificates() or among those found
in the private store.

@ingroup    cb_cert_mgmt_pkcs7

@inc_file pkcs7.h

@param  arg             Data that can be passed to the callback.
@param  cs              \c CStream containing a PKCS&nbsp;\#7 message (a \c
                          ContentInfo object) containing the \c SignedData
                          object to search for a matching certificate.
@param  pSubjectKeyIdentifier   Pointer to \c ASN1_ITEM structure containing the
                          certificate subjectKeyIdentifier extension.
@param  ppCertificate   On return, pointer to buffer of the matching
                          certificate. If no match is found, the value is
                          NULL (zero).
@param  certificateLen  On return, length of the matching certificate.

@return     \c OK (0) under all circumstances.

@callbackdoc    pkcs7.h
*/
typedef MSTATUS (*PKCS7_GetCertificateVersion3)(
    const void* arg,
    CStream cs,
    struct ASN1_ITEM* pSubjectKeyIdentifier,
    ubyte** ppCertificate,
    ubyte4* certificateLen);

/* used by PKCS#12 */
/**
@brief      Pointers to PKCS&nbsp;\#7 callback functions required by
            PKCS&nbsp;\#12 functions.

@details    This structure provides Pointers to PKCS&nbsp;\#7 callback
            functions required by PKCS&nbsp;\#12 functions.

The contained callback functions must conform to the following prototypes:
+ PKCS7_GetPrivateKey()
+ PKCS7_ValidateRootCertificate()
+ PKCS7_GetCertificate()
+ PKCS7_GetCertificateVersion3()
*/
typedef struct PKCS7_Callbacks
{
    PKCS7_GetPrivateKey             getPrivKeyFun;
    PKCS7_ValidateRootCertificate   valCertFun;
    PKCS7_GetCertificate            getCertFun;
    PKCS7_GetCertificateVersion3    getCertFunV3;
} PKCS7_Callbacks;

/*------------------------------------------------------------------*/
/* exported routines */
#ifdef __ENABLE_MOCANA_PKCS7__

/* this routine takes a pointer to the root item of a parsed PKCS7
    message (by ASN1_Parse) and returns the pointer to the first
    certificate in the message. If the PKCS7 contains several
    certificates, they are the siblings of the first one */

/**
@brief      If a given \c CStream contains a PKCS&nbsp;\#7 \c SignedData
            object, get the first certificate.

@details    This function determines whether a given \c CStream contains a
            PKCS&nbsp;\#7 \c SignedData object, and if so, returns a pointer through the \p ppFirstCertificate parameter to the address of an \c ASN1_ITEM structure for the first certificate in the \c SignedData object.

@note       This function can be useful in a PKCS7_GetCertificate() callback
            function. After calling PKCS7_GetCertificates() on the input \c
            CStream, you can then use PKCS7_FindCertificate() to locate specific
            certificates.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pRootItem   Pointer to root of the given \c CStream, \p s, containing
                      the \c SignedData object to search. To obtain this
                      root item pointer, call the ASN1_Parse() function for
                      the \c CStream, \p s. For more information about
                      setting up the \c CStream and getting the root, see
                      the "Setting up a CStream and Getting the ASN1_ITEM
                      for the Root ASN.1 Object" information in the overview
                      for the pkcs7.c file.
@param  s           Pointer to the \c CStream containig the \c SignedData from
                      which to get the first certificate.
@param  ppFirstCertificate  On return, pointer to address of the \c ASN1_ITEM
                              structure for the first certificate in \p s.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_GetCertificates(struct ASN1_ITEM* pRootItem, CStream s,
                      struct ASN1_ITEM** ppFirstCertificate);



/**
@brief      Retrieves and filters certificates.

@details    This routine retrieves the certificates from the asn1 form pointer 
            and places them in an \c certDescriptor array. It has the ability
            to filter and just get the chain associated with a private key.
@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pCerts         Asn1 pointer to the first ceritifcate, usually the output
                       of \c PKCS7_GetCertificates
@param  certStream     The cert stream from parsing the asn1 form.
@param  pPrivKey       The private key used to filter to a specific cert or cert chain.
@param  chainOnly      If \c TRUE just the cert chain associtated with the private
                       key will be returned, in order from leaf to root. If \c FALSE
                       the leaf will be first and all other certs will follow.
@param  ppCertArray    Location of a newly allocated array to hold the certificates.
@param  pCertArrayLen  The length of the array, ie the number of certificates.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS PKCS7_filterCertificates(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ASN1_ITEM *pCerts,
    CStream certStream,
    AsymmetricKey *pPrivKey,
    byteBoolean chainOnly,
    CERTS_DATA **ppCertArray,
    ubyte4 *pCertArrayLen
);

/**
@brief      Verify the signature of a \c SignedData object that contains the
            signed data.

@details    This function verifies the signature of a PKCS&nbsp;\#7 DER-encoded
            ASN.1 \c SignedData object that contains the signature; that is, the
            signature is not \e detached.

@note       To verify the signature of \c SignedData object that has a detached
            signature, call the PKCS7_VerifySignedDataEx() function.

Information about the signers and their hash values is extracted from the \c
SignerInfo objects in the \c SignedData object. If the \p getCertFun
parameter is NULL, this function searches the \c SignedData object directly
for certificates that match the IssuerName and SerialNumber for each signer
in the \c SignedData object.

If the \p getCertFun parameter contains a callback function that conforms to the
@ref PKCS7_GetCertificate typedef, this function does not search the
\c SignedData object directly for matching certificates, but passes the \c
CStream containing the \c SignedData object to the callback, which performs the
search.

This supports the RFC&nbsp;2315 requirement that the \c SignedData object
does not need to include all of the certificates needed to verify all
signatures. In this case, it is assumed that the recipient of the \c
SignedData object can obtain the additional certificates from an external
source.

After finding a certificate for a signer of the \c SignedData object, this
function uses the callback specified by the \p valCertFun parameter to
validate the certificate. If the certificate is expired, recalled, or
otherwise compromised, this function will not verify the signature.

If the certificate is valid, this function uses it to verify the signature of
the \c SignedData object's signed data.

On return, this function uses the \p numKnownSigners parameter to provide a
count of the signatures that it was able to verify. A value of 0 (zero)
indicates that this function could not verify any of the signatures.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pSignedData     Pointer to \c ASN1_ITEM structure containing the root
                          of the DER-encoded ASN.1 \c ContentInfo object
                          (PKCS&nbsp;\#7 message) that contains the \c
                          SignedData object for which to verify the signature(s).
@param  s               \c CStream containing the \c ContentInfo object
                          (PKCS&nbsp;\#7 message) that contains a \c SignedData
                          object. For more information about setting up the \c
                          CStream and getting the root, see the "Setting up a
                          CStream and Getting the ASN1_ITEM for the Root ASN.1
                          Object" information in the overview information for
                          the pkcs7.dxd file.
@param  callbackArg     Pointer to arguments that are required by the function
                          referenced in \p getCertFun.
@param  getCertFun      NULL if the \c SignedData object contains all the
                          certificates needed to verify all of the signatures of
                          the \c SignedData object. Otherwise, pointer to a
                          callback function conforming to the typedef, @ref
                          PKCS7_GetCertificate(), which searches an external \c
                          CStream store of certificates for a matching
                          certificate via Issuer and Serial Number.
@param  valCertFun      Pointer to a callback function conforming to the
                          @ref PKCS7_ValidateRootCertificate() typedef,
                          validates certificates in the \c SignedData object or
                          from an external source.
@param  payLoad         NULL if the \c SignedData object contains the signed
                          data; otherwise (for detached signatures) pointer to
                          external data for which the signature(s) were
                          generated.
@param  payLoadLen      Length of payload parameter, \p payLoad.
@param  numKnownSigners On return, pointer to number of recognized signers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_VerifySignedData(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         struct ASN1_ITEM* pSignedData, CStream s,
                        /* getCertFun can be NULL, if certificates
                         * are included in signedData
                         */
                         const void* callbackArg,
                         PKCS7_GetCertificate getCertFun,
                         PKCS7_ValidateRootCertificate valCertFun,
                         const ubyte* payLoad, /* for detached signatures */
                         ubyte4 payLoadLen,
                         sbyte4* numKnownSigners);


                         /**
@brief      Verify the signature of a \c SignedData object that contains the
            signed data including subject key identifiers.

@details    This function verifies the signature of a PKCS&nbsp;\#7 DER-encoded
            ASN.1 \c SignedData object that contains the signature; that is, the
            signature is not \e detached.

@note       To verify the signature of \c SignedData object that has a detached
            signature, call the PKCS7_VerifySignedDataEx() function.

Information about the signers and their hash values is extracted from the \c
SignerInfo objects in the \c SignedData object. If the \p getCertFun
parameter is NULL, this function searches the \c SignedData object directly
for certificates that match the IssuerName and SerialNumber for each signer
in the \c SignedData object.

If the \p getCertFun or \p getCertFunV3 parameters contain a callback function that conforms to the
appropriate typedef, this function does not search the
\c SignedData object directly for matching certificates, but passes the \c
CStream containing the \c SignedData object to the callback, which performs the
search.

This supports the RFC&nbsp;2315 requirement that the \c SignedData object
does not need to include all of the certificates needed to verify all
signatures. In this case, it is assumed that the recipient of the \c
SignedData object can obtain the additional certificates from an external
source.

After finding a certificate for a signer of the \c SignedData object, this
function uses the callback specified by the \p valCertFun parameter to
validate the certificate. If the certificate is expired, recalled, or
otherwise compromised, this function will not verify the signature.

If the certificate is valid, this function uses it to verify the signature of
the \c SignedData object's signed data.

On return, this function uses the \p numKnownSigners parameter to provide a
count of the signatures that it was able to verify. A value of 0 (zero)
indicates that this function could not verify any of the signatures.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pSignedData     Pointer to \c ASN1_ITEM structure containing the root
                          of the DER-encoded ASN.1 \c ContentInfo object
                          (PKCS&nbsp;\#7 message) that contains the \c
                          SignedData object for which to verify the signature(s).
@param  s               \c CStream containing the \c ContentInfo object
                          (PKCS&nbsp;\#7 message) that contains a \c SignedData
                          object. For more information about setting up the \c
                          CStream and getting the root, see the "Setting up a
                          CStream and Getting the ASN1_ITEM for the Root ASN.1
                          Object" information in the overview information for
                          the pkcs7.dxd file.
@param  callbackArg     Pointer to arguments that are required by the function
                          referenced in \p getCertFun.
@param  getCertFun      NULL if the \c SignedData object contains all the
                          certificates needed to verify all of the signatures of
                          the \c SignedData object. Otherwise, pointer to a
                          callback function conforming to the typedef, @ref
                          PKCS7_GetCertificate(), which searches an external \c
                          CStream store of certificates for a matching
                          certificate via Issuer and Serial Number.
@param  getCertFunV3    NULL if the \c SignedData object contains all the
                          certificates needed to verify all of the signatures of
                          the \c SignedData object. Otherwise, pointer to a
                          callback function conforming to the typedef, @ref
                          PKCS7_GetCertificateVersion3(), which searches an external \c
                          CStream store of certificates for a matching
                          certificate via subjectKeyIdentifier.
@param  valCertFun      Pointer to a callback function conforming to the
                          @ref PKCS7_ValidateRootCertificate() typedef,
                          validates certificates in the \c SignedData object or
                          from an external source.
@param  payLoad         NULL if the \c SignedData object contains the signed
                          data; otherwise (for detached signatures) pointer to
                          external data for which the signature(s) were
                          generated.
@param  payLoadLen      Length of payload parameter, \p payLoad.
@param  numKnownSigners On return, pointer to number of recognized signers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_VerifySignedDataV3(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         struct ASN1_ITEM* pSignedData, CStream s,
                        /* getCertFun can be NULL, if certificates
                         * are included in signedData
                         */
                         const void* callbackArg,
                         PKCS7_GetCertificate getCertFun,
                         PKCS7_GetCertificateVersion3 getCertFunV3,
                         PKCS7_ValidateRootCertificate valCertFun,
                         const ubyte* payLoad, /* for detached signatures */
                         ubyte4 payLoadLen,
                         sbyte4* numKnownSigners);

/**
@brief      Decrypt an \c EnvelopedData object and get its encryption details.

@details    This function extracts and decrypts the encrypted content of an
            \c EnvelopedData object, and returns its encryption details.

The \c EnvelopedData object is defined as follows:
<pre>
    EnvelopedData ::= SEQUENCE {
        version Version,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo }

    RecipientInfos ::= SET OF RecipientInfo

    EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

    EncryptedContent ::= OCTET STRING

    RecipientInfo ::= SEQUENCE {
        version Version,
        issuerAndSerialNumber IssuerAndSerialNumber,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

    EncryptedKey ::= OCTET STRING
</pre>

@todo_eng_review (clarify how decrypted info is returned)

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pEnvelopedData      Pointer to root of \c EnvelopedData object in the
                              given \c CStream, \p s.
@param  s                   \c CStream containing the DER-encoded PKCS&nbsp;\#7
                              message that contains the ASN.1 \c EnvelopedData
                              object to decrypt.
@param  callbackArg         Pointer to arguments that are required by the
                              function referenced in \p getPrivateKeyFun.
@param  getPrivateKeyFun    Pointer to a callback function that gets the private
                              key for the recipient of the \c EnvelopedData
                              object. The recipient is specified by a pair of
                              SerialNumber and IssuerName values, which uniquely
                              identify a certificate, and therefore, a subject.
                              These values are read from the \c RecipientInfos
                              object of the \c CStream \p s object's \c
                              EnvelopedData object.
@param  pType               On return, pointer to \c encryptedContentType
                              enumerated value, from pkcs_common.h, identifying
                              the \c EnvelopedData object's content type.
@param  ppEncryptedContent  On return, pointer to address of the encrypted data.
@param  pBulkCtx            On return, pointer to an opaque encryption context
                              structure.
@param  ppBulkAlgo          On return, pointer to constant array containing
                              information about the bulk encryption algorithm
                              used; any of the following preconfigured
                              BulkEncryptionAlgo arrays from crypto.c:
                              + \c CRYPTO_TripleDESSuite
                              + \c CRYPTO_TwoKeyTripleDESSuite
                              + \c CRYPTO_DESSuite
                              + \c CRYPTO_RC4Suite
                              + \c CRYPTO_RC2Suite
                              + \c CRYPTO_RC2EffectiveBitsSuite
                              + \c CRYPTO_BlowfishSuite
                              + \c CRYPTO_AESSuite
                              + \c CRYPTO_AESCtrSuite
                              + \c CRYPTO_NilSuite
@param  iv                  On return, pointer to array containing the
                              initialization vector.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_DecryptEnvelopedDataAux( MOC_HW(hwAccelDescr hwAccelCtx)
                              struct ASN1_ITEM* pEnvelopedData, CStream s,
                              const void* callbackArg,
                              PKCS7_GetPrivateKey getPrivateKeyFun,
                              enum encryptedContentType* pType,
                              struct ASN1_ITEM** ppEncryptedContent,
                              BulkCtx* ppBulkCtx,
                              const BulkEncryptionAlgo** ppBulkAlgo,
                              ubyte iv[/*16=MAX_IV_SIZE*/]);

/**
@brief      Extract and decrypt the encrypted content of an \c EnvelopedData
            object.

@details    This function extracts and decrypts the encrypted content of a
            CMS \c EnvelopedData object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__


@inc_file pkcs7.h

@param  pEnvelopedData      Pointer to root of \c EnvelopedData object in the
                              given \c CStream, \p s.
@param  s                   \c CStream containing the DER-encoded PKCS&nbsp;\#7
                              message that contains the ASN.1 \c EnvelopedData
                              object to decrypt.
@param  callbackArg     Pointer to arguments that are required by the function
                          referenced in \p getPrivateKeyFun.
@param  getPrivateKeyFun    Pointer to a callback function that gets the private
                              key for the recipient of the \c EnvelopedData
                              object. The recipient is specified by a pair of
                              SerialNumber and IssuerName values, which uniquely
                              identify a certificate, and therefore, a subject.
                              These values are read from the \c RecipientInfos
                              object of the \c CStream \p s object's \c
                              EnvelopedData object.
@param  decryptedInfo       On return, pointer to the address of a buffer
                              containing the decrypted content.
@param  decryptedInfoLen    On return, pointer to length of decrypted data, \p
                              decryptedInfo.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_DecryptEnvelopedData( MOC_HW(hwAccelDescr hwAccelCtx)
                           struct ASN1_ITEM* pEnvelopedData, CStream s,
                           const void* callbackArg,
                           PKCS7_GetPrivateKey getPrivateKeyFun,
                           ubyte** decryptedInfo, sbyte4* decryptedInfoLen);

/**
@brief      Create a DER-encoded, version 0, ASN.1 \c EnvelopedData object
            containing a given payload.

@details    This function creates a DER-encoded, version 0, ASN.1 \c
            EnvelopedData object that contains the given payload.

RFC&nbsp;2315 defines the \c EnvelopedData object as follows:
<pre>
    EnvelopedData ::= SEQUENCE {
        version Version,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo }

    RecipientInfos ::= SET OF RecipientInfo

    EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent[0] IMPLICIT EncryptedContent OPTIONAL }

    EncryptedContent ::= OCTET STRING

    RecipientInfo ::= SEQUENCE {
        version Version,
        issuerAndSerialNumber IssuerAndSerialNumber,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

    EncryptedKey ::= OCTET STRING
</pre>

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pStart      NULL to \b not encapsulate the generated \c EnvelopedData
                      object in a \c ContentInfo object; otherwise \c
                      DER_ITEMPTR whose referenced structure contains the
                      (mostly empty) ASN.1 DER-encoded \c ContentInfo object
                      that serves as a container for the \c EnvelopedData object
                      to create. (For details about the \c ContentInfo object
                      and how to populate it, see the \"About RFC&nbsp;2315
                      Objects" writeup for pkcs7.dxd.)
@param  pParent     NULL if the \p pStart parameter is NULL; otherwise \c
                      DER_ITEMPTR for the \p pStart parameter's referenced \c
                      ContentInfo object. In the code snippet for populating a
                      \c ContentType object with a \c EnvelopedData object,
                      shown in the \"About RFC&nbsp;2315 Objects" writeup for
                      pkcs7.dxd, this would be the \p pEnvelopedData object.
@param  pCACertificatesParseRoots
                        Array of \c ASN1_ITEMPTR pointers. Each \c
                              ASN1_ITEMPTR references the root object of its
                              corresponding certificate in the \p pStreams array.
@param  pStreams        Array of \c CStream structures. The certificate supplied
                          in this parameter provides the information required to
                          create new \c EnvelopedData object's \c RecipientInfo
                          object.
@param  numCACerts      Pointer to number of certificates in \p pStreams.
@param  encryptAlgoOID  Pointer to OID array that describes the type of
                          encryption to apply to the \c EnvelopedData object.
                          Use any of the preconfigured OID arrays from
                          src/asn1/oiddefs.h:
                          + \c aes128CBC_OID
                          + \c aes192CBC_OID
                          + \c aes256CBC_OID
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_MOCANA_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().
@param  pPayLoad    Pointer to the data to envelope in the \c EnvelopedData
                      object created by this function.
@param  payLoadLen  Pointer to length of payload, \p pPayLoad.
@param  ppEnveloped     On return: if \p pStart = NULL, pointer to the address
                          of a DER-encoded ASN.1 \c EnvelopedData object;
                          otherwise, pointer to address of a DER-encoded ASN.1
                          \c ContentInfo object that contains the \c
                          EnvelopedData object created by this function.
@param  pEnvelopedLen  On return, pointer to length of \c EnvelopedData object,
                          \p ppEnveloped.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_EnvelopData( MOC_HW(hwAccelDescr hwAccelCtx)
                  struct DER_ITEM* pStart, /* can be null */
                  struct DER_ITEM* pParent, /* can be null */
                  struct ASN1_ITEM* pCACertificatesParseRoots[/*numCACerts*/],
                  CStream pStreams[/*numCACerts*/],
                  sbyte4 numCACerts,
                  const ubyte* encryptAlgoOID,
                  RNGFun rngFun, void* rngFunArg,
                  const ubyte* pPayLoad, ubyte4 payLoadLen,
                  ubyte** ppEnveloped, ubyte4* pEnvelopedLen);

/**
@brief      Create a DER-encoded, version 0, ASN.1 \c EnvelopedData object
            containing a given payload. Oaep padding for RSA is available.

@details    This function creates a DER-encoded, version 0, ASN.1 \c
            EnvelopedData object that contains the given payload.
            Oaep padding for RSA is available.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pStart      NULL to \b not encapsulate the generated \c EnvelopedData
                      object in a \c ContentInfo object; otherwise \c
                      DER_ITEMPTR whose referenced structure contains the
                      (mostly empty) ASN.1 DER-encoded \c ContentInfo object
                      that serves as a container for the \c EnvelopedData object
                      to create. (For details about the \c ContentInfo object
                      and how to populate it, see the \"About RFC&nbsp;2315
                      Objects" writeup for pkcs7.dxd.)
@param  pParent     NULL if the \p pStart parameter is NULL; otherwise \c
                      DER_ITEMPTR for the \p pStart parameter's referenced \c
                      ContentInfo object. In the code snippet for populating a
                      \c ContentType object with a \c EnvelopedData object,
                      shown in the \"About RFC&nbsp;2315 Objects" writeup for
                      pkcs7.dxd, this would be the \p pEnvelopedData object.
@param  pCACertificatesParseRoots
                        Array of \c ASN1_ITEMPTR pointers. Each \c
                              ASN1_ITEMPTR references the root object of its
                              corresponding certificate in the \p pStreams array.
@param  pStreams        Array of \c CStream structures. The certificate supplied
                          in this parameter provides the information required to
                          create new \c EnvelopedData object's \c RecipientInfo
                          object.
@param  numCACerts      Pointer to number of certificates in \p pStreams.
@param  encryptAlgoOID  Pointer to OID array that describes the type of
                          encryption to apply to the \c EnvelopedData object.
                          Use any of the preconfigured OID arrays from
                          src/asn1/oiddefs.h:
                          + \c aes128CBC_OID
                          + \c aes192CBC_OID
                          + \c aes256CBC_OID
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_MOCANA_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().
@param  isOaep        For RSA encryption, use oeapPadding.
@param  oaepHashAlgo  For RSA-OAEP encryption, the hashAlgoId to use.
@param  pOaepLabel    For RSA-OAEP encryption, the label to use.
@param  pPayLoad    Pointer to the data to envelope in the \c EnvelopedData
                      object created by this function.
@param  payLoadLen  Pointer to length of payload, \p pPayLoad.
@param  ppEnveloped     On return: if \p pStart = NULL, pointer to the address
                          of a DER-encoded ASN.1 \c EnvelopedData object;
                          otherwise, pointer to address of a DER-encoded ASN.1
                          \c ContentInfo object that contains the \c
                          EnvelopedData object created by this function.
@param  pEnvelopedLen  On return, pointer to length of \c EnvelopedData object,
                          \p ppEnveloped.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_EnvelopDataWoaep( MOC_HW(hwAccelDescr hwAccelCtx)
                  struct DER_ITEM* pStart, /* can be null */
                  struct DER_ITEM* pParent, /* can be null */
                  struct ASN1_ITEM* pCACertificatesParseRoots[/*numCACerts*/],
                  CStream pStreams[/*numCACerts*/],
                  sbyte4 numCACerts,
                  const ubyte* encryptAlgoOID,
                  RNGFun rngFun, void* rngFunArg,
                  ubyte isOaep, ubyte4 oaepHashAlgo, sbyte *pOaepLabel,
                  const ubyte* pPayLoad, ubyte4 payLoadLen,
                  ubyte** ppEnveloped, ubyte4* pEnvelopedLen);

/**
@brief      Create a DER-encoded, version 1, ASN.1 \c SignedData object for data
            internal or external to the \c SignedData object.

@details    This function creates a DER-encoded, version 1, ASN.1 \c SignedData
            object for the data internal or external to the \c SignedData object.

RFC&nbsp;2315 defines the \c SignedData object as follows:
<pre>
    SignedData ::= SEQUENCE {
        version Version,
        digestAlgorithms DigestAlgorithmIdentifiers,
        contentInfo ContentInfo,
        certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
        crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
        signerInfos SignerInfos }

    DigestAlgorithmIdentifiers ::=

        SET OF DigestAlgorithmIdentifier

        SignerInfos ::= SET OF SignerInfo

        SignerInfo ::= SEQUENCE {
            version Version,
            issuerAndSerialNumber IssuerAndSerialNumber,
            digestAlgorithm DigestAlgorithmIdentifier,
            authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
            digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
            encryptedDigest EncryptedDigest,
            unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }

       EncryptedDigest ::= OCTET STRING
</pre>

If you use this function to create an \e unsigned \c SignedData object, the
resulting object is referred to as \e degenerate. RFC&nbsp;2315 says you can use
degenerate objects to distribute certificates and certificate revocation lists.

As required by RFC&nbsp;2315, you can create a \c SignedData object that does not contain all the certificates needed to verify all the signatures, so long as the \c SignedData object is expected to have access to a certificate store contaiing the required signatures.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  flags       Zero (0) or bitmask combination (created by
                      <tt>OR</tt>ing definitions together) specifying which
                      signing elements to include.
@param  pStart      NULL to \b not encapsulate the generated \c SignedData
                      object in a \c ContentInfo object; otherwise \c
                      DER_ITEMPTR whose referenced structure contains the
                      (mostly empty) ASN.1 DER-encoded \c ContentInfo object
                      that serves as a container for the \c SignedData object
                      to create. (For details about the \c ContentInfo object
                      and how to populate it, see the \"About RFC&nbsp;2315
                      Objects" writeup for pkcs7.dxd.)
@param  pParent     NULL if the \p pStart parameter is NULL; otherwise \
                      DER_ITEMPTR for the \p pStart parameter's referenced \c
                      ContentInfo object. In the code snippet for populating a
                      \c ContentType object with a \c SignedData object, shown
                      in the \"About RFC&nbsp;2315 Objects" writeup for
                      pkcs7.dxd, this would be the \p pSignedData object.
@param  pCACertificatesParseRoots
                            NULL to exclude certificates from the resultant \c
                              SignedData object; otherwise array of \c
                              ASN1_ITEMPTR pointers. The first array element
                              references the first certificate in the \c
                              CStream, \p pCAStreams, that contains the
                              certificates to include in the resultant \c
                              SignedData object. To get this \c ASN1_ITEMPTR,
                              submit the \p pCAStreams to ASN1_Parse().
@param  pCAStreams          NULL to exclude certificates from the resultant \c
                              SignedData object; otherwise array of \c CStream
                              objects containing the certificates to include in
                              the resultant \c SignedData object.
@param  numCACerts      Number of certificates in \p pCAStreams.
@param  pCrlsParseRoots NULL to exclude CRLs from the resultant \c SignedData
                          object; otherwise array of \c ASN1_ITEMPTR pointers.
                          The first array element references the first CRL in
                          the \c CStream, \p pCrlStreams, that contains the CRLs
                          to include in the resultant \c SignedDat object. To
                          get this \c ASN1_ITEMPTR, submit the \p pCrlStreams to
                          ASN1_Parse().
@param  pCrlStreams     NULL to exclude CRLs from the resultant \c SignedData
                          object; otherwise array of \c CStream objects
                          containing the CRLs to include in the resultant \c
                          SignedData object.
@param  numCrls         Number of CRLs in \p pCrlStreams.
@param  pSignerInfos    NULL to create an unsigned (\e degenerate) \c SignedData
                          object; otherwise pointer to array of \c signerInfo
                          structures, each of which contains the signing
                          information for a single signer. For details about
                          populating this structure, see \c @ref signerInfo.
@param  numSigners      0 (zero) if \p pSignerInfos is NULL; otherwise nubmer of
                          elements in the \p pSignerInfos array.
@param  payLoadType     Pointer to an OID describing the data in \p pPayLoad;
                          typically \c pkcs7_data_OID, but can be any of the
                          following OID type constant arrays from
                          src/asn1/oiddefs.c:
                          + pkcs7_data_OID
                          + pkcs7_signedData_OID
                          + pkcs7_envelopedData_OID
                          + pkcs7_signedAndEnvelopedData_OID
                          + pkcs7_digestedData_OID
                          + pkcs7_encryptedData_OID
@param  pPayLoad    Pointer to data for which to create signatures.
@param  payLoadLen  Pointer to length of payload, \p pPayLoad.
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_MOCANA_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().
@param  ppSigned    On return, if \p pStart = NULL, pointer to the address of a
                      DER-encoded, version 1, ASN.1 \c SignedData object;
                      otherwise, pointer to a DER-encoded ASN.1 \c ContentInfo
                      structure that contains the \c SignedData object created
                      by this function.
@param  pSignedLen  On return, pointer to length of the \c SignedData object,
                      \p ppSigned.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_SignData(MOC_ASYM(hwAccelDescr hwAccelCtx)
               ubyte4 flags,
               struct DER_ITEM* pStart, /* can be null */
               struct DER_ITEM* pParent,
               struct ASN1_ITEM* pCACertificatesParseRoots[/*numCACerts*/], /* can be null */
               CStream pCAStreams[/*numCACerts*/], sbyte4 numCACerts,
               struct ASN1_ITEM* pCrlsParseRoots[/*numCrls*/], /* can be null */
               CStream pCrlStreams[/*numCrls*/], sbyte4 numCrls,
               signerInfoPtr *pSignerInfos, /* if NULL, will create degenerate SignedData */
               ubyte4 numSigners, /* number of signers */
               const ubyte* payLoadType, /* if NULL, will create degenerate SignedData */
               const ubyte* pPayLoad, ubyte4 payLoadLen,
               RNGFun rngFun,             /* this can be NULL for degenerate SignedData */
               void* rngFunArg,           /* this can be NULL for degenerate SignedData */
               ubyte** ppSigned, ubyte4* pSignedLen);

/**
@brief      Create a DER-encoded, ASN.1 \c DigestedData object for the given
            data.

@details    This function creates a DER-encoded, ASN.1 \c DigestedData object
            for the given data.

RFC&nbsp;2315 defines the \c DigestedData object as follows:
<pre>
    DigestedData ::= SEQUENCE {
        version Version,
        digestAlgorithm DigestAlgorithmIdentifier,
        contentInfo ContentInfo,
        digest Digest }

        Digest ::= OCTET STRING

        ContentInfo ::= SEQUENCE {
            contentType ContentType,
            content
                [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
</pre>

@ingroup    pkcs_functions

@since 1.41
@version 2.02

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pStart      NULL to \b not encapsulate the generated \c DigestedData
                      object in a \c ContentInfo object; otherwise \c
                      DER_ITEMPTR whose referenced structure contains the
                      (mostly empty) ASN.1 DER-encoded \c ContentInfo object
                      that serves as a container for the \c DigestedData object
                      to create. (For details about the \c ContentInfo object
                      and how to populate it, see the \"About RFC&nbsp;2315
                      Objects" writeup for pkcs7.dxd.)
@param  pParent     NULL if the \p pStart parameter is NULL; otherwise \c
                      DER_ITEMPTR for the \p pStart parameter's referenced \c
                      ContentInfo object. In the code snippet for populating a
                      \c ContentType object with a \c EnvelopedData object,
                      shown in the \"About RFC&nbsp;2315 Objects" writeup for
                      pkcs7.dxd, this would be the \p pDigestedData object.
@param  payloadType Pointer to an OID describing the data in \p pPayLoad;
                      typically \c pkcs7_data_OID, but can be any of the
                      following OID type constant arrays from src/asn1/oiddefs.c:
                      + pkcs7_data_OID
                      + pkcs7_signedData_OID
                      + pkcs7_envelopedData_OID
                      + pkcs7_signedAndEnvelopedData_OID
                      + pkcs7_digestedData_OID (rarely applicable)
                      + pkcs7_encryptedData_OID
@param  hashType    Hash function to use to create the digest; any of the
                      following enum values from src/crypto/crypto.h:
                      + \c ht_md2
                      + \c ht_md4
                      + \c ht_md5
                      + \c ht_sha1
                      + \c ht_sha256
                      + \c ht_sha384
                      + \c ht_sha512
                      + \c ht_sha224
@param  pPayload    Pointer data to digest.
@param  payloadLen  Pointer to length of payload, \p pPayLoad.
@param  ppDigested      On return, if \p pStart = NULL, pointer to the address
                          of a DER-encoded, version 1, ASN.1 \c DigestedData
                          object; otherwise, pointer to a DER-encoded ASN.1 \c
                          ContentInfo structure that contains the \c
                          DigestedData object created by this function.
@param  pDigestedLen    On return, pointer to length of the \c DigestedData
                         object, \p ppDigested.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_DigestData( MOC_HASH(hwAccelDescr hwAccelCtx)
                 struct DER_ITEM* pStart, /* can be null */
                 struct DER_ITEM* pParent,
                 const ubyte* payLoadType, /* OID can be null then will used pkcs7_data_OID */
                 ubyte hashType,
                 const ubyte* pPayLoad, ubyte4 payLoadLen,
                 ubyte** ppDigested, ubyte4* pDigestedLen);


/**
@brief      Get a \c SignerInfo object's digest hash function identifier.

@details    This function gets a \c SignerInfo object's digest hash function
            identifier.

RFC&nbsp;2315 defines the \c SignerInfo object as follows:
<pre>
    SignerInfo ::= SEQUENCE {
        version Version,
        issuerAndSerialNumber IssuerAndSerialNumber,
        digestAlgorithm DigestAlgorithmIdentifier,
        authenticatedAttributes
            [0] IMPLICIT Attributes OPTIONAL,
        digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
        encryptedDigest EncryptedDigest,
        unauthenticatedAttributes
           [1] IMPLICIT Attributes OPTIONAL }

       EncryptedDigest ::= OCTET STRING
</pre>

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pSignerInfo     ASN1_ITEMPTR pointer to the \c SignerInfo object from
                          which to get its digest algorithm. How to get this
                          ASN1_ITEMPTR depends on the type of ASN.1 object that
                          contains the \c SignerInfo object of interest. If you
                          know the the object's ASN.1 definition, you can use
                          ASN1_GetNthChild() and other functions from
                          src/asn1/parseasn1.c to navigate a DER-encoded, ASN.1
                          object.
@param  cs              Pointer to \c CStream that contains the \c SignerInfo
                          object of interest, \p pSignerInfo.
@param  hashAlgoId      On return, pointer to hash function specified in
                          the \c SignerInfo object's \c digestAlgorithm;
                          typically any of the following enum values from
                          src/crypto/crypto.h:
                          + \c ht_md2
                          + \c ht_md4
                          + \c ht_md5
                          + \c ht_sha1
                          + \c ht_sha256
                          + \c ht_sha384
                          + \c ht_sha512
                          + \c ht_sha224

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_GetSignerDigestAlgo( struct ASN1_ITEM* pSignerInfo, CStream cs, ubyte* hashAlgoId);

/**
@brief      Get a \c SignerInfo object's digest encryption algorithm identifier.

@details    This function gets a \c SignerInfo object's digest encryption
            algorithm identifier (the child \c digestEncryptionAlgorithm object).

RFC&nbsp;2315 defines the \c SignerInfo object as follows:
<pre>
    SignerInfo ::= SEQUENCE {
        version Version,
        issuerAndSerialNumber IssuerAndSerialNumber,
        digestAlgorithm DigestAlgorithmIdentifier,
        authenticatedAttributes
            [0] IMPLICIT Attributes OPTIONAL,
        digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
        encryptedDigest EncryptedDigest,
        unauthenticatedAttributes
           [1] IMPLICIT Attributes OPTIONAL }

       EncryptedDigest ::= OCTET STRING
</pre>

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pSignerInfo     ASN1_ITEMPTR pointer to the \c SignerInfo object from
                          which to get its encryption algorithm. How to get this
                          ASN1_ITEMPTR depends on the type of ASN.1 object that
                          contains the \c SignerInfo object of interest. If you
                          know the the object's ASN.1 definition, you can use
                          ASN1_GetNthChild() and other functions from
                          src/asn1/parseasn1.c to navigate a DER-encoded, ASN.1
                          object.
@param  cs              Pointer to \c CStream that contains the \c SignerInfo
                          object of interest, \p pSignerInfo.
@param  pubKeyType      On return, pointer to encryption algorithm specified in
                          the \c SignerInfo object's \c
                          digestEncryptionAlgorithm; typically any of the
                          following enum values from ca_mgmt.h:
                          + \c akt_rsa
                          + \c akt_ecc
                          + \c akt_dsa

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_GetSignerSignatureAlgo( struct ASN1_ITEM* pSignerInfo, CStream cs, ubyte* pubKeyAlgoId);

/**
@brief      Get the first signed attribute in a DER-encoded, ASN.1 \c
            SignerInfo object.

@details    This function gets the first signed attribute in a DER-encoded,
            ASN.1 \c SignerInfo object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pSignerInfo     ASN1_ITEMPTR pointer to the \c SignerInfo object from
                          which to get its first signed attribute. How to get this
                          ASN1_ITEMPTR depends on the type of ASN.1 object that
                          contains the \c SignerInfo object of interest. If you
                          know the the object's ASN.1 definition, you can use
                          ASN1_GetNthChild() and other functions from
                          src/asn1/parseasn1.c to navigate a DER-encoded, ASN.1
                          object.
@param  ppFirstSignedAttribute  On return, pointer to the address of an
                                  ASN1_ITEMPTR for the first signed attribute
                                  in the \c SignerInfo object, \p pSignerInfo.
                                  The referenced \c ASN1_ITEM structure does \b
                                  not contain data from the \c SignerInfo
                                  object; it contains the offsets and length
                                  values that you can use to find data within
                                  the \c CStream that contains the \c
                                  SignerInfo object.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_GetSignerSignedAttributes( struct ASN1_ITEM* pSignerInfo,
                        struct ASN1_ITEM* *ppFirstSignedAttribute);

/**
@brief      Get the first unsigned attribute in a DER-encoded, ASN.1 \c
            SignerInfo object.

@details    This function gets the first unsigned attribute in a DER-encoded,
            ASN.1 \c SignerInfo object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS7__

@inc_file pkcs7.h

@param  pSignerInfo     ASN1_ITEMPTR pointer to the \c SignerInfo object from
                          which to get its first unsigned attribute. How to get
                          this ASN1_ITEMPTR depends on the type of ASN.1 object
                          that contains the \c SignerInfo object of interest.
                          If you know the the object's ASN.1 definition, you
                          can use ASN1_GetNthChild() and other functions from
                          src/asn1/parseasn1.c to navigate a DER-encoded, ASN.1
                          object.
@param  ppFirstUnsignedAttribute  On return, pointer to the address of an
                                  ASN1_ITEMPTR for the first unsigned attribute
                                  in the \c SignerInfo object, \p pSignerInfo.
                                  The referenced \c ASN1_ITEM structure does \b
                                  not contain data from the \c SignerInfo
                                  object; it contains the offsets and length
                                  values that you can use to find data within
                                  the \c CStream that contains the \c
                                  SignerInfo object.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
PKCS7_GetSignerUnsignedAttributes( struct ASN1_ITEM* pSignerInfo,
                        struct ASN1_ITEM* *ppFirstUnsignedAttribute);

/*------------------------------------------------------------------*/

typedef enum {
    success = 0,
    failed = 2,
    pending = 3,
    noSupport = 4,
    confirmRequired = 5,
    popRequired = 6,
    partial = 7
} CMCStatus;

typedef struct cmcSignerInfo {
    /**
     @brief      signerInfo object inherited from pkcs7.
     */
    signerInfo *pSignerInfo;
    /**
     @brief      ASN1_ITEMPTR for the \c SubjectKeyIdentifier object in this signer's
                  certificate.
     */
    struct ASN1_ITEM* pSubjectKeyIdentifier;

} cmcSignerInfo;

typedef struct taggedContent
{
    ubyte *pData;
    ubyte4 dataLen;
} taggedContent;

typedef struct taggedAttribute
{
    ubyte4 bodyPartId;
    ubyte *pAttributeTypeOid;
    taggedContent *pTaggedAttributeValues;
    ubyte4 numAttributeValues;
} taggedAttribute;

typedef struct taggedContentInfo
{
    ubyte4 bodyPartId;
    /* ContentInfo */
    taggedContent *pTaggedContentInfo;
} taggedContentInfo;

typedef struct otherMsg
{
    ubyte4 bodyPartId;
    ubyte *pOtherMsgTypeOid;
    /*otherMsgValue*/
    taggedContent *pOtherMsgValue;
} otherMsg;

typedef struct cmcSignerInfo *cmcSignerInfoPtr;

MOC_EXTERN MSTATUS
CMC_createPKIDataEx(taggedAttribute pTaggedAttributes[], ubyte4 numTaggedAttrs, ubyte *pDerCertificateRequest, ubyte4 derCertificateReqLen, taggedContentInfo pTaggedContentInfos[], ubyte4 numTaggedContents, otherMsg pOtherMsgs[], ubyte4 numOtherMsgs, ubyte **ppBuffer, ubyte4 *pBufferLen);

MOC_EXTERN MSTATUS
CMC_processCmsSequence(ASN1_ITEM *pPKIInputData, CStream stream, ubyte4 *pBodyPartsList, ubyte4 numBodyParts, byteBoolean isResponseData, ASN1_ITEMPTR **ppEnvelopDataItems, ubyte4 *pNumEnvelopDataItems);

MOC_EXTERN MSTATUS
CMC_processControlSequence(ASN1_ITEM *pPKIInputData, CStream stream, ubyte *pBatchOID, ubyte4 **ppBodyPartIds, ubyte4 *pNumBodyPartIds);

MOC_EXTERN MSTATUS
CMC_processOtherMsgSequence(ASN1_ITEM *pPKIInputData, CStream stream, ubyte **ppOutData, ubyte4 *pOutDataLen, byteBoolean isResponseData);

MOC_EXTERN MSTATUS
CMC_verifyAttestationReqType(ASN1_ITEM *pPKIInputData, CStream stream, byteBoolean *pAttestFlow, ubyte **ppOid);

MOC_EXTERN MSTATUS
CMC_createPKIData(ASN1_ITEMPTR pControlItem, CStream *controlStream, ASN1_ITEMPTR pReqItem, CStream *reqStream, ubyte **ppBuffer, ubyte4 *pBufferLen);

MOC_EXTERN MSTATUS
CMC_getPKIResponse(ASN1_ITEM* pRootItem, CStream stream, ASN1_ITEM **ppPkiResponse);

MOC_EXTERN MSTATUS
CMC_getPKIData(ASN1_ITEM* pRootItem, CStream stream, ASN1_ITEM **ppPkiRequest);
#if defined(__ENABLE_MOCANA_AIDE_SERVER__)
MOC_EXTERN MSTATUS
CMC_addCMCStatusInfoV2(CMCStatus status, sbyte4 referanceIds[], sbyte4 numRefIds, ubyte **ppBuffer, ubyte4 *pBufferLen);
MOC_EXTERN MSTATUS
CMC_addTaggedAttribute(sbyte4 bodyPartID, ubyte *attrTypeOid, ubyte *attrValueData, ubyte4 attrValueLen, ubyte **ppBuffer, ubyte4 *pBufferLen);
MOC_EXTERN MSTATUS
CMC_createSimplePKIMessage(CERTS_DATA *pCertsData, sbyte4 certDataLen, ubyte **ppPkiMessage, ubyte4 *pPkiMessageLen);
MOC_EXTERN MSTATUS
CMC_createFullPKIMessage(ubyte* pSignerCertBytes, ubyte4 signerCertByteLen, AsymmetricKey *pSignerKey, CERTS_DATA *pCertsData, sbyte4 certDataLen, intBoolean isAttest, ubyte *pEkCertData, ubyte4 ekCertDataLen, ubyte *pOtherMsgData, ubyte4 otherMsgDataLen, ubyte **ppPkiMessage, ubyte4 *pPkiMessageLen);

MOC_EXTERN MSTATUS
CMC_createCMSEnvelopForKekri(ubyte *encryptAlgoOID, BulkEncryptionAlgo* pBulkEncryptionAlgo, sbyte4 keyLength,
	ubyte *decryptKeyIdentifierData, ubyte4 decryptKeyIdentifierDataLen,
	ubyte *pPreSharedKey, ubyte4 preSharedKeyLen,
    ubyte *pSecret, ubyte4 secretLen,
	ubyte *pPayload, ubyte4 payloadLen,
	ubyte** ppOutData, ubyte4 *pOutDataLen);

MOC_EXTERN MSTATUS
CMC_createCMSEnvelopForKtri(ubyte *encryptAlgoOID,
	ubyte *pPreSharedCert, ubyte4 preSharedCertLen,
	ubyte *pPayload, ubyte4 payloadLen,
	ubyte** ppRetKeyData, ubyte4 *pRetKeyDataLen);

#endif

/**
@brief      Create a DER-encoded, version 1, ASN.1 \c SignedData object for data
            internal or external to the \c SignedData object.

@details    This function creates a DER-encoded, version 1, ASN.1 \c SignedData
            object for the data internal or external to the \c SignedData object.

RFC&nbsp;2315 defines the \c SignedData object as follows:
<pre>
    SignedData ::= SEQUENCE {
        version Version,
        digestAlgorithms DigestAlgorithmIdentifiers,
        contentInfo ContentInfo,
        certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
        crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
        signerInfos SignerInfos }

    DigestAlgorithmIdentifiers ::=

        SET OF DigestAlgorithmIdentifier

        SignerInfos ::= SET OF SignerInfo

        SignerInfo ::= SEQUENCE {
            version Version,
            issuerAndSerialNumber IssuerAndSerialNumber,
            digestAlgorithm DigestAlgorithmIdentifier,
            authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
            digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
            encryptedDigest EncryptedDigest,
            unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }

       EncryptedDigest ::= OCTET STRING
</pre>

If you use this function to create an \e unsigned \c SignedData object, the
resulting object is referred to as \e degenerate. RFC&nbsp;2315 says you can use
degenerate objects to distribute certificates and certificate revocation lists.

As required by RFC&nbsp;2315, you can create a \c SignedData object that does not contain all the certificates needed to verify all the signatures, so long as the \c SignedData object is expected to have access to a certificate store contaiing the required signatures.

@ingroup    pkcs_functions

@inc_file pkcs7.h

@param  flags       Zero (0) or bitmask combination (created by
                      <tt>OR</tt>ing definitions together) specifying which
                      signing elements to include.
@param  pStart      NULL to \b not encapsulate the generated \c SignedData
                      object in a \c ContentInfo object; otherwise \c
                      DER_ITEMPTR whose referenced structure contains the
                      (mostly empty) ASN.1 DER-encoded \c ContentInfo object
                      that serves as a container for the \c SignedData object
                      to create.
@param  pParent     NULL if the \p pStart parameter is NULL; otherwise \
                      DER_ITEMPTR for the \p pStart parameter's referenced \c
                      ContentInfo object.
@param  pCACertificatesParseRoots
                            NULL to exclude certificates from the resultant \c
                              SignedData object; otherwise array of \c
                              ASN1_ITEMPTR pointers. The first array element
                              references the first certificate in the \c
                              CStream, \p pCAStreams, that contains the
                              certificates to include in the resultant \c
                              SignedData object. To get this \c ASN1_ITEMPTR,
                              submit the \p pCAStreams to ASN1_Parse().
@param  pCAStreams          NULL to exclude certificates from the resultant \c
                              SignedData object; otherwise array of \c CStream
                              objects containing the certificates to include in
                              the resultant \c SignedData object.
@param  numCACerts      Number of certificates in \p pCAStreams.
@param  pCrlsParseRoots NULL to exclude CRLs from the resultant \c SignedData
                          object; otherwise array of \c ASN1_ITEMPTR pointers.
                          The first array element references the first CRL in
                          the \c CStream, \p pCrlStreams, that contains the CRLs
                          to include in the resultant \c SignedDat object. To
                          get this \c ASN1_ITEMPTR, submit the \p pCrlStreams to
                          ASN1_Parse().
@param  pCrlStreams     NULL to exclude CRLs from the resultant \c SignedData
                          object; otherwise array of \c CStream objects
                          containing the CRLs to include in the resultant \c
                          SignedData object.
@param  numCrls         Number of CRLs in \p pCrlStreams.
@param  pSignerInfos    NULL to create an unsigned (\e degenerate) \c SignedData
                          object; otherwise pointer to array of \c signerInfo
                          structures, each of which contains the signing
                          information for a single signer. For details about
                          populating this structure, see \c @ref signerInfo.
@param  numSigners      0 (zero) if \p pSignerInfos is NULL; otherwise nubmer of
                          elements in the \p pSignerInfos array.
@param  payLoadType     Pointer to an OID describing the data in \p pPayLoad;
                          typically \c pkcs7_data_OID, but can be any of the
                          following OID type constant arrays from
                          src/asn1/oiddefs.c:
                          + pkcs7_data_OID
                          + pkcs7_signedData_OID
                          + pkcs7_envelopedData_OID
                          + pkcs7_signedAndEnvelopedData_OID
                          + pkcs7_digestedData_OID
                          + pkcs7_encryptedData_OID
@param  pPayLoad    Pointer to data for which to create signatures.
@param  payLoadLen  Pointer to length of payload, \p pPayLoad.
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_MOCANA_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().
@param  ppSigned    On return, if \p pStart = NULL, pointer to the address of a
                      DER-encoded, version 1, ASN.1 \c SignedData object;
                      otherwise, pointer to a DER-encoded ASN.1 \c ContentInfo
                      structure that contains the \c SignedData object created
                      by this function.
@param  pSignedLen  On return, pointer to length of the \c SignedData object,
                      \p ppSigned.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs7.h
*/
MOC_EXTERN MSTATUS
CMC_SignData(MOC_ASYM(hwAccelDescr hwAccelCtx)
               ubyte4 flags,
               struct DER_ITEM* pStart, /* can be null */
               struct DER_ITEM* pParent,
               struct ASN1_ITEM* pCACertificatesParseRoots[/*numCACerts*/], /* can be null */
               CStream pCAStreams[/*numCACerts*/], sbyte4 numCACerts,
               struct ASN1_ITEM* pCrlsParseRoots[/*numCrls*/], /* can be null */
               CStream pCrlStreams[/*numCrls*/], sbyte4 numCrls,
               cmcSignerInfoPtr *pCmcSignerInfos, /* if NULL, will create degenerate SignedData */
               ubyte4 numSigners, /* number of signers */
               const ubyte* payLoadType, /* if NULL, will create degenerate SignedData */
               const ubyte* pPayLoad, ubyte4 payLoadLen,
               RNGFun rngFun,             /* this can be NULL for degenerate SignedData */
               void* rngFunArg,           /* this can be NULL for degenerate SignedData */
               ubyte** ppSigned, ubyte4* pSignedLen);

#endif  /*#ifdef __ENABLE_MOCANA_PKCS7__*/

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __PKCS7_HEADER__ */
