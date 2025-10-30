/*
 * pkcs10.h
 *
 * PKCS #10 Header
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
@file       pkcs10.h
@brief      Mocana SoT Platform PKCS&nbsp;\#10 developer API header.
@details    This header file contains structures, enumerations, and function
            declarations used for Mocana SoT Platform PKCS&nbsp;\#10 operations.

@since 1.41
@version 6.4 and later

@flags
Whether the following flags are defined determines which function declarations and callbacks are enabled:
+ \c \__ENABLE_MOCANA_PKCS10__

@filedoc    pkcs10.h
*/

/*------------------------------------------------------------------*/

#ifndef __PKCS10_HEADER__
#define __PKCS10_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __ENABLE_MOCANA_PKCS10__

/* PKCS#10 certificate request attributes as defined in PKCS#9 */
typedef struct requestAttributes
{
    sbyte*      pChallengePwd;             /* ChallengePassword */
    ubyte4      challengePwdLength;

    certExtensions *pExtensions;
} requestAttributes;

/* This holds a P10 cert request attribute.
 * An attribute consists of an OID and data. It is encoded as follows:
 *   SEQ {
 *     OID,
 *     SET OF
 *       ANY }
 * There can be many attribute values for each OID.
 * At the moment, we don't support multiple values for an attribute.
 * The actual data can be ANY. It might be a SEQUENCE of some group of elements,
 * it could be an OCTET STRING.
 * When you set the value field, you should set it to a buffer containing the DER
 * encoding of the "ANY". For example, if you are adding the Microsoft
 * EnrollmentNameValuePair, and the pair is "CertificateTemplate" and "User",
 * then the value will be
 *   30 32
 *      1e 26 <Unicode String of CertificateTemplate>
 *      1e 08 <Unicode String of User>
 * and the valueLen will be 52.
 * The OID can be one of the *_OID values defined in /mss/src/asn1/oiddefs.h, or
 * it can be your own buffer if the attribute OID is not defined in Mocana's
 * code. The format of the OID is <len || OID>. That is, build a buffer, set the
 * first byte to be the length and then the next length bytes to be the actual
 * OID. For example, the subjectAltName OID would be { 3, 0x55, 0x1D, 0x11 }, or
 * the Microsoft EnrollmentNameValuePair would be
 * { 10, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0D, 0x01, 0x01 }
 * Because the first byte is the length, you don't need to specify the length
 * searately, and that's why there is no oidLen field.
 */
typedef struct MocRequestAttr
{
  ubyte   *oid;
  ubyte   *pValue;
  ubyte4   valueLen;
} MocRequestAttr;

/* This is the same as requestAttributes, except it is extended.
 * It contains a field for other attributes, just as the certExtensions struct
 * contains a field for other extensions.
 * If there are no other attributes, set pOtherAttrs to NULL and set
 * otherAttrCount to 0. Otherwise, create an array of MocRequestAttr, set the
 * fields in each entry to that array, and set pOtherAttrs to that array and
 * otherAttrCount to the number of entries in the array.
 */
typedef struct requestAttributesEx
{
  sbyte           *pChallengePwd;
  ubyte4           challengePwdLength;

  certExtensions  *pExtensions;

  MocRequestAttr  *pOtherAttrs;
  ubyte4           otherAttrCount;
} requestAttributesEx;

/* outbound CSR BER encoded use FREE to delete */

/**
@brief      Generate a DER-encoded PKCS&nbsp;#10 certificate request for a
            given distinguished name.

@details    This function generates a DER-encoded PKCS&nbsp;#10 certificate
            request for a given distinguished name.

@warning    The buffer containing the returned certificate request is allocated
            by the \c MALLOC() function/macro; you must free it using the \c FREE()
            function/macro.

@ingroup    pkcs_functions

@since 6.4
@version 6.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS10__

@inc_file   pkcs10.h

@param  pKey        Pointer to key (RSA or ECC) to use in the certificate
                      request. The public part of the key is placed in the
                      certificate request; the private part of the key is used
                      to sign the certificate request.
@param  signAlgo    Hash function used to generate the signature. The values
                      are defined in crypto/crypto.h as enums with the prefix
                      "ht_" (for HashType). Recommended values as of this
                      writing (2016) are:
                      + ht_sha256
                      + ht_sha384
                      + ht_sha512
@param  pCertInfo   Pointer to a @ref certDistinguishedName structure that
                      identifies the subject to associate with the public key.
@param  pReqAttrs   NULL pointer or pointer to a populated \c requestAttributes
                      structure containing a challenge password and the
                      requested X.509 version 3 certificate extensions for the
                      new certificate.
@param  ppCertReq       On successful return, pointer to buffer containing the
                          ASN.1 DER-encoded certificate request.
@param  pCertReqLength  On successful return, pointer to length of new
                          certificate request, \p ppCertReq.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs10.h
*/
MOC_EXTERN MSTATUS PKCS10_GenerateCertReqFromDN(AsymmetricKey* pKey,
                                                ubyte signAlgo,
                                                const certDistinguishedName *pCertInfo,
                                                const requestAttributes *pReqAttrs, /* can be null */
                                                ubyte** ppCertReq,
                                                ubyte4* pCertReqLength);

/**
@brief      Generate a DER-encoded PKCS&nbsp;#10 certificate request for a
            given ASN.1 name.

@details    This function generates a DER-encoded PKCS&nbsp;#10 certificate
            request for a given ASN.1 name.

@note       This function is very convenient for generating a certificate
            request for the subject or issuer of an existing DER-encoded
            certificate. Point the pASN1Name parameter to the correct part of
            the existing DER-encoded certificate.

@warning    The buffer containing the returned certificate request is allocated
            by the \c MALLOC() function/macro; you must free it using the \c FREE()
            function/macro.

@ingroup    pkcs_functions

@since 6.4
@version 6.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS10__

@inc_file   pkcs10.h

@param  pKey        Pointer to key (RSA or ECC) to use in the certificate
                      request. The public part of the key is placed in the
                      certificate request; the private part of the key is used
                      to sign the certificate request.
@param  signAlgo    Hash function used to generate the signature. The values
                      are defined in crypto/crypto.h as enums with the prefix
                      "ht_" (for HashType). Recommended values as of this
                      writing (2016) are:
                      + ht_sha256
                      + ht_sha384
                      + ht_sha512
@param  pASN1Name   Pointer to buffer containing the ASN.1 DER-encoded X.509
                      name (a sequence of \c RelativeDistinguishedName objects)
                      that identifies the subject to associate with the public
                      key.
@param  asn1NameLen Pointer to length of ASN.1 Der-encoded X.509 name,
                      \p pASN1Name.
@param  pReqAttrs   NULL pointer or pointer to a populated \c requestAttributes
                      structure containing a challenge password and the
                      requested X.509 version 3 certificate extensions for the
                      new certificate.
@param  ppCertReq       On successful return, pointer to buffer containing the
                          ASN.1 DER-encoded certificate request.
@param  pCertReqLength  On successful return, pointer to length of new
                          certificate request, \p ppCertReq.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs10.h
*/
MOC_EXTERN MSTATUS PKCS10_GenerateCertReqFromASN1Name(AsymmetricKey* pKey,
                                                      ubyte signAlgo,
                                                      const ubyte* pASN1Name,
                                                      ubyte4 asn1NameLen,
                                                      const requestAttributes *pReqAttrs, /* can be null */
                                                      ubyte** ppCertReq,
                                                      ubyte4* pCertReqLength);

/**
@brief      Generate a text representation of a DER-encoded certificate request.

@details    This function generates a text representaiton of a DER-encoded
            certificate request by using Base64 encoding and generating lines of
            the proper length for compatibility with most CAs (certificate
            authorities).

@warning    The buffer containing the returned certificate text is allocated
            by the \c MALLOC() function/macro; you must free it using the \c FREE()
            function/macro.

@ingroup    pkcs_functions

@since 6.4
@version 6.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS10__

@inc_file   pkcs10.h

@param  pCertReq        Pointer to DER-encoded certificate request.
@param  certReqLen      Length of the DER-encoded certificate request,
                          \p pCertReq.
@param  ppCsr           On successful return, pointer to a buffer containing the
                          text representation of the DER-encoded certificat
@param  pCsrLength      On successful return, pointer to length of the
                          certificate text buffer, \p ppCsr.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs10.h
*/
MOC_EXTERN MSTATUS PKCS10_CertReqToCSR( const ubyte* pCertReq, ubyte4 pCertReqLength,
                                       ubyte** ppCsr, ubyte4* pCsrLength);

/**
 * @brief This is the same as PKCS10_GenerateCertReqFromDN, except that it takes
 * a requestAttributesEx.
 *
 * @details The original function took in a request attributes struct that
 * allowed for only two specific request attributes: challenge password and
 * extension request. The new requestAttributesEx allows for more attributes.
 * @warning    The buffer containing the returned certificate request is allocated
 * by the \c MALLOC() function/macro; you must free it using the \c FREE()
 * function/macro.
 *
 * @ingroup    pkcs_functions
 *
 * @since 6.4
 * @version 6.4 and later
 *
 * @flags
 * To enable this function, the following flag must be defined in moptions.h:
 * + \c \__ENABLE_MOCANA_PKCS10__
 *
 * @inc_file   pkcs10.h
 *
 * @param  pKey        Pointer to key (RSA or ECC) to use in the certificate
 * request. The public part of the key is placed in the
 * certificate request; the private part of the key is used
 * to sign the certificate request.
 * @param  signAlgo    Hash function used to generate the signature. The values
 * are defined in crypto/crypto.h as enums with the prefix
 * "ht_" (for HashType). Recommended values as of this
 * writing (2016) are:
 * + ht_sha256
 * + ht_sha384
 * + ht_sha512
 * @param  pCertInfo   Pointer to a @ref certDistinguishedName structure that
 * identifies the subject to associate with the public key.
 * @param  pReqAttrs   NULL pointer or pointer to a populated \c
 * requestAttributesEx structure containing a challenge password, requested X.509
 * version 3 certificate extensions for the new certificate, and optional other
 * attributes.
 * @param  ppCertReq       On successful return, pointer to buffer containing the
 * ASN.1 DER-encoded certificate request.
 * @param  pCertReqLength  On successful return, pointer to length of new
 * certificate request, \p ppCertReq.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 * definition from merrors.h. To retrieve a string containing an
 * English text error identifier corresponding to the function's
 * returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc pkcs10.h
 */
MOC_EXTERN MSTATUS PKCS10_GenerateCertReqFromDNEx (
  AsymmetricKey* pKey,
  ubyte signAlgo,
  const certDistinguishedName *pCertInfo,
  const requestAttributesEx *pReqAttrs, /* can be null */
  ubyte** ppCertReq,
  ubyte4* pCertReqLength
  );

/**
 * @brief This is the same as PKCS10_GenerateCertReqFromDNEx, except that the
 * signing key is optional.
 *
 * @details If the signing key is NULL, then the public key and signature is not
 * included in the certificate request.
 * @warning    The buffer containing the returned certificate request is allocated
 * by the \c MALLOC() function/macro; you must free it using the \c FREE()
 * function/macro.
 *
 * @ingroup    pkcs_functions
 *
 * @since 6.4
 * @version 6.4 and later
 *
 * @flags
 * To enable this function, the following flag must be defined in moptions.h:
 * + \c \__ENABLE_MOCANA_PKCS10__
 *
 * @inc_file   pkcs10.h
 *
 * @param  pKey        Pointer to key (RSA or ECC) to use in the certificate
 * request. The public part of the key is placed in the
 * certificate request; the private part of the key is used
 * to sign the certificate request.
 * @param  signAlgo    Hash function used to generate the signature. The values
 * are defined in crypto/crypto.h as enums with the prefix
 * "ht_" (for HashType). Recommended values as of this
 * writing (2016) are:
 * + ht_sha256
 * + ht_sha384
 * + ht_sha512
 * @param  pCertInfo   Pointer to a @ref certDistinguishedName structure that
 * identifies the subject to associate with the public key.
 * @param  pReqAttrs   NULL pointer or pointer to a populated \c
 * requestAttributesEx structure containing a challenge password, requested X.509
 * version 3 certificate extensions for the new certificate, and optional other
 * attributes.
 * @param  ppCertReq       On successful return, pointer to buffer containing the
 * ASN.1 DER-encoded certificate request.
 * @param  pCertReqLength  On successful return, pointer to length of new
 * certificate request, \p ppCertReq.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 * definition from merrors.h. To retrieve a string containing an
 * English text error identifier corresponding to the function's
 * returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc pkcs10.h
 */
MOC_EXTERN MSTATUS PKCS10_GenerateCertReqFromDNEx2 (
  AsymmetricKey* pKey, /* can be null */
  ubyte signAlgo,
  const certDistinguishedName *pCertInfo,
  const requestAttributesEx *pReqAttrs, /* can be null */
  ubyte** ppCertReq,
  ubyte4* pCertReqLength
  );

#endif /* __ENABLE_MOCANA_PKCS10__ */

#ifdef __cplusplus
}
#endif

#endif /* __PKCS10_HEADER__ */
