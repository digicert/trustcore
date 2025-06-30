/*
 * ca_mgmt.h
 *
 * Certificate Authority Management Factory
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
@file       ca_mgmt.h
@brief      Mocana SoT Platform certificate authority management factory.
@details    This header file contains structures, enumerations, and function
            declarations for SoT Platform certificate management functions.

@since 1.41
@version 5.3 and later

@todo_version (new structures, new functions, etc.)

@flags
Whether the following flags are defined determines which structures and
enumerations are defined:
+ \c \__ENABLE_MOCANA_MULTIPLE_COMMON_NAMES__
+ \c \__ENABLE_MOCANA_ECC__

Whether the following flags are defined determines which function declarations are enabled:
+ \c \__ENABLE_MOCANA_EXTRACT_CERT_BLOB__
+ \c \__PUBCRYPTO_HEADER__

@filedoc    ca_mgmt.h
*/


/*------------------------------------------------------------------*/

#ifndef __CA_MGMT_HEADER__
#define __CA_MGMT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/* these values are serialized -- add but don't modify */
/* valid values for the AsymmetricKey type field */
/* The akt_custom is for custom keys, such as hardware keys.
 */
enum
{
    akt_undefined = 0, /* keep it 0 -> static var are correctly initialized */
                       /* as undefined */
    akt_rsa = 1,
    akt_ecc = 2,
    akt_dsa = 3,
    akt_dh  = 4,
    akt_rsa_pss = 5,

    akt_custom = 101,
    akt_moc    = 102,
    
    akt_ecc_ed = 112,
    
    akt_hybrid = 113,
    akt_qs = 114,
    
    akt_tap_rsa = 0x00020001,
    akt_tap_ecc = 0x00020002,
    akt_hsm_rsa = 0x00010001,
    akt_hsm_ecc = 0x00010002
};

#if (defined(__ENABLE_MOCANA_ECC__))
/*
 curveId: they actually match the suffix of the OID
 for these curves or algorithm identifiers
 */
enum
{
    cid_EC_P192 = 1,
    cid_EC_P256 = 7,
    cid_EC_P224 = 33,
    cid_EC_P384 = 34,
    cid_EC_P521 = 35,
    cid_EC_X25519 = 110,  /* edDH X25519 suffix */
    cid_EC_X448 = 111,    /* edDH X448 suffix */
    cid_EC_Ed25519 = 112, /* edDSA 25519 suffix */
    cid_EC_Ed448 = 113    /* edDSA 448 suffix */
};

#endif

/* Identifiers for quantum safe sig algs, SIG values match the OID suffix for each algorithm */ 
enum
{
    cid_PQC_MLDSA_44 = 0x04,
    cid_PQC_MLDSA_65 = 0x05,
    cid_PQC_MLDSA_87 = 0x07,
    cid_PQC_FNDSA_512 = 0x10,
    cid_PQC_FNDSA_1024 = 0x11,
    cid_PQC_SLHDSA_SHA2_128S = 0x50,
    cid_PQC_SLHDSA_SHA2_128F = 0x51,
    cid_PQC_SLHDSA_SHAKE_128S = 0x52,
    cid_PQC_SLHDSA_SHAKE_128F = 0x53,
    cid_PQC_SLHDSA_SHA2_192S = 0x54,
    cid_PQC_SLHDSA_SHA2_192F = 0x55,
    cid_PQC_SLHDSA_SHAKE_192S = 0x56,
    cid_PQC_SLHDSA_SHAKE_192F = 0x57,
    cid_PQC_SLHDSA_SHA2_256S = 0x58,
    cid_PQC_SLHDSA_SHA2_256F = 0x59,
    cid_PQC_SLHDSA_SHAKE_256S = 0x5a,
    cid_PQC_SLHDSA_SHAKE_256F = 0x5b,

    cid_PQC_MLKEM_512 = 0x110,
    cid_PQC_MLKEM_768 = 0x111,
    cid_PQC_MLKEM_1024 = 0x112,
};

/* Identifiers for classical portion of composite keys 
   For ECC the cid_EC codes above will be used. These 
   RSA identifiers must be distinct and large values than those for ECC. */
enum
{
    cid_RSA_2048_PKCS15 = 128,
    cid_RSA_3072_PKCS15 = 129,
    cid_RSA_4096_PKCS15 = 130,
    cid_RSA_2048_PSS    = 131,
    cid_RSA_3072_PSS    = 132,
    cid_RSA_4096_PSS    = 133
};

/*------------------------------------------------------------------*/

struct AsymmetricKey;

/**
@brief      Certificate context (information required to manage a DER-encoded
            X.509 certificate).

@details    This structure encapsulates the required context of a
            DER-encoded X.509 certificate. An entity using a certificate for
            authentication must have access to the corresponding public and
            private key pair used to sign the certificate. Mocana SoT Platform
            provides API functions for generating and importing certificates;
            those API functions use the \c certDescriptor structure for
            passing certificate information.

@since 1.41
@version 1.41 and later
*/
typedef struct certDescriptor
{
    /**
        @brief      Pointer to DER-encoded X.509 certificate.
        @details    Pointer to DER-encoded X.509 certificate.
    */
    ubyte*  pCertificate;

    /**
        @brief      Number of bytes in \p pCertificate.
        @details    Number of bytes in \p pCertificate.
    */
    ubyte4  certLength;

    /**
        @brief      Pointer to key blob value.
        @details    Pointer to key blob value.
    */
    ubyte*  pKeyBlob;

    /**
        @brief      Number of bytes in \p pKeyBlob.
        @details    Number of bytes in \p pKeyBlob.
    */
    ubyte4  keyBlobLength;

    /**
        @brief      Pointer to asymmetric key; if defined, use this instead of
                      \p pKeyBlob.
        @details    Pointer to asymmetric key; if defined, use this instead of
                      \p pKeyBlob.
    */
    struct AsymmetricKey* pKey;

#if !(defined __ENABLE_MOCANA_64_BIT__)
    /**
        @brief      Application-specific %cookie.
        @details    Application-specific %cookie.

        @note       If the \c \__ENABLE_MOCANA_64_BIT__ flag is defined, only
                      the \c ubyte4 \c %cookie field (not the \c ubyte8 \c
                      %cookie field) is included in the structure. If the flag
                      is not defined, only the \c ubyte8 \c %cookie (not the
                      \c ubyte4 %cookie) is included.
    */
    ubyte4  cookie;
#else
    /**
        @brief      Application-specific %cookie.
        @details    Application-specific %cookie.

        @note       If the \c \__ENABLE_MOCANA_64_BIT__ flag is defined, only
                      the \c ubyte4 \c %cookie field (not the \c ubyte8 \c
                      %cookie field) is included in the structure. If the flag
                      is not defined, only the \c ubyte8 \c %cookie (not the
                      \c ubyte4 %cookie) is included.
    */
    ubyte8  cookie;
#endif
} certDescriptor;

/* old structure */

/**
@brief      Certificate generation support for constructing an
            \c AttributeTypeAndValues ASN.1 object.

@details    This structure provides backward compatability with earlier
            Mocana SoT Platform certificate generation and authentication
            functions. The structure is a container for constructing an \c
            AttributeTypeAndValues ASN.1 object, defined as:

<pre>
AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY DEFINED BY AttributeType

   DirectoryString ::= CHOICE {
         teletexString           TeletexString (SIZE (1..MAX)),
         printableString         PrintableString (SIZE (1..MAX)),
         universalString         UniversalString (SIZE (1..MAX)),
         utf8String              UTF8String (SIZE (1..MAX)),
         bmpString               BMPString (SIZE (1..MAX)) }
</pre>

This example shows how you could populate a \c nameAttr strucutre to define a \c RelativeDistinguisedName:

<pre>
nameAttr pNames1[] = {
    { countryName_OID,            UTF8STRING, (ubyte*)"US",                    2}};  // country
nameAttr pNames2[] = {
    { stateOrProvinceName_OID,    UTF8STRING, (ubyte*)"California",           10}};  // state or province
nameAttr pNames3[] = {
    { localityName_OID,           UTF8STRING, (ubyte*)"San Francisco",        10}};  // locality
nameAttr pNames4[] = {
    { organizationName_OID,       UTF8STRING, (ubyte*)"Mocana Corporation",   18}};  // company name
nameAttr pNames5[] = {
    { organizationalUnitName_OID, UTF8STRING, (ubyte*)"Engineering",          11}};  // organizational unit
nameAttr pNames6[] = {
    { commonName_OID,             UTF8STRING, (ubyte*)"anexample.mocana.com", 20}};  // common name
nameAttr pNames7[] = {
    { pkcs9_emailAddress_OID,     UTF8STRING, (ubyte*)"anexample@mocana.com", 20}};  // pkcs-9-at-emailAddress
</pre>

@todo_version (and \@since; accidentally omitted, forever...)
*/
typedef struct nameAttr
{
    /**
        @brief      \c AttributeType: attribute's OID (object identifier).
        @details    \c AttributeType: attribute's OID (object identifier). Use
                      any of the following *_OID constants from
                      src/asn1/oiddefs.h:
                      + countryName_OID
                      + stateOrProvinceName_OID
                      + localityName_OID
                      + organizationName_OID
                      + organizationalUnitName_OID
                      + commonName_OID
                      + pkcs9_emailAddress_OID
        @todo_eng_review (verify which *_OID constants are valid)
    */
    const ubyte *oid; /* the OID of the attribute */
    /**
        @brief      (Optional) <tt> DirectoryString CHOICE</tt> for the \p
                      value field, such as \c UTF8String.
        @details    (Optional) <tt> DirectoryString CHOICE</tt> for the \p
                      \p value field. Use any of the following constants from
                      src/asn1/parseasn1.h:
                      + TELETEXSTRING
                      + PRINTABLESTRING
                      + GENERALSTRING
                      + UTF8STRING
                      + BMPSTRING
    */
    ubyte type;
    /**
        @brief      (Optional) String containing information applicable to the
                      \p oid field.
        @details    (Optional) String containing information applicable to the
                      \p oid field.
    */
    ubyte* value;
    /**
        @brief      Number of bytes in the name value buffer (\p value).
        @details    Number of bytes in the name value buffer (\p value).
    */
    ubyte4 valueLen;
} nameAttr;

/**
@brief      Container for \c nameAttr structure information required to
            construct an ASN.1 \c RelativeDistinguishedName object.

@details    This structure is a container for \c nameAttr structure
            information required to construct an ASN.1 \c
            RelativeDistinguishedName object, defined as:

<pre>
RelativeDistinguishedName ::=
     SET OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY DEFINED BY AttributeType

   DirectoryString ::= CHOICE {
         teletexString           TeletexString (SIZE (1..MAX)),
         printableString         PrintableString (SIZE (1..MAX)),
         universalString         UniversalString (SIZE (1..MAX)),
         utf8String              UTF8String (SIZE (1..MAX)),
         bmpString               BMPString (SIZE (1..MAX)) }
</pre>

This example shows how you could populate a \c nameAttr strucutre to define a \c RelativeDistinguisedName:

<pre>

relativeDN pRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pNames6, 1},
    {pNames7, 1}
};

nameAttr pNames1[] = {
    { countryName_OID,            UTF8STRING, (ubyte*)"US",                     2}};  // country
nameAttr pNames2[] = {
    { stateOrProvinceName_OID,    UTF8STRING, (ubyte*)"California",            10}};  // state or province
nameAttr pNames3[] = {
    { localityName_OID,           UTF8STRING, (ubyte*)"San Francisco",         10}};  // locality
nameAttr pNames4[] = {
    { organizationName_OID,       UTF8STRING, (ubyte*)"Mocana Corporation",    18}};  // company name
nameAttr pNames5[] = {
    { organizationalUnitName_OID, UTF8STRING, (ubyte*)"Engineering",           11}};  // organizational unit
nameAttr pNames6[] = {
    { commonName_OID,             UTF8STRING, (ubyte*)"anexample.mocana.com",  20}};  // common name
nameAttr pNames7[] = {
    { pkcs9_emailAddress_OID,     UTF8STRING, (ubyte*)"anexample@mocana.com",  20}}; // pkcs-9-at-emailAddress
</pre>

@todo_version (and \@since; accidentally omitted, forever...)
*/
typedef struct relativeDN /* RDN */
{
    /**
        @brief      Array of \c nameAttr of length \c dnCount.
        @details    This field identifies AttributeTypeAndValues that make up
                      an RDN field.
    */
    nameAttr *pNameAttr;
    /**
        @brief      Number of \c nameAttr objects in \p pNameAttr.
        @details    Number of \c nameAttr objects in \p pNameAttr..
    */
    ubyte4   nameAttrCount;
} relativeDN;

/**
@brief      Distinguished name data (names and start/end dates) to support
            certificate generation.

@details    This structure contains a list of relative distinguished names for
            a given certificate, as well as validity start and end dates. The
            order reflects the sequence of RDN.

@note       Microsoft&reg; Internet Explorer&reg; limits certificate lifetimes
            to 30 years.

@todo_version (and \@since; accidentally omitted, forever...)
*/
typedef struct certDistinguishedName
{
    /**
        @brief      Pointer to buffer array of relative distinguished names.
        @details    Pointer to buffer array of relative distinguished names.
    */
    relativeDN *pDistinguishedName;
    /**
        @brief      Number of relative distinguished names in \p
                      pDistinguishedName buffer.
        @details    Number of relative distinguished names in \p
                      pDistinguishedName buffer.
    */
    ubyte4      dnCount;

    /**
        @brief      String identifying certificate's start date, in the format
                      yymmddhhmmssZ; for example, "030526000126Z" specifies
                      May 26th, 2003 12:01:26 AM.
        @details    String identifying certificate's start date, in the format
                      yymmddhhmmssZ, where "Z" terminates the string; for
                      example, "030526000126Z" specifies May 26th, 2003
                      12:01:26 AM.
    */
    sbyte*          pStartDate;                 /* 030526000126Z */

    /**
        @brief      String identifying certificate's end date, in the format
                      yymmddhhmmssZ; for example, "330524230347Z" specifies
                      May 24th, 2033 11:03:47 PM.
        @details    String identifying certificate's end date, in the format
                      yymmddhhmmssZ, where "Z" terminates the string; for
                      example, "330524230347Z" specifies May 24th, 2033
                      11:03:47 PM.
    */
    sbyte*          pEndDate;                   /* 330524230347Z */

} certDistinguishedName;

/**
@brief      Version 3 certificate or CRL extension (as defined in RFC&nbsp;3280).

@details    This structure is used to specify a version 3 certificate or CRL
            extension (as defined in RFC&nbsp;3280).

@since 3.06
@version 3.06 and later

*/
typedef struct extensions
{
    /**
        @brief      Extension Id: an OID defined in src/asn1/oiddefs.h.
        @details    Extension Id: an OID defined in src/asn1/oiddefs.h. The table shows the valid *_OID constants and the applicable section of RFC&nbsp;3280.\n
Certificate Extension oiddefs Variable|RFC&nbsp;3280
--------------------------------------|----------------------------|
|authorityKeyIdentifier_OID      |4.2.1.1  Authority Key Identifier|
|subjectKeyIdentifier_OID        |4.2.1.2  Subject Key Identifier|
|keyUsage_OID                    |4.2.1.3  Key Usage|
|privateKeyUsagePeriod_OID       |4.2.1.4  Private Key Usage Period|
|certificatePolicies_OID         |4.2.1.5  Certificate Policies|
|policyMappings_OID              |4.2.1.6  Policy Mappings|
|subjectAltName_OID              |4.2.1.7  Subject Alternative Name|
|issuerAltName_OID               |4.2.1.8  Issuer Alternative Name|
|subjectDirectoryAttributes_OID  |4.2.1.9  Subject Directory Attributes|
|basicConstraints_OID            |4.2.1.10  Basic Constraints|
|nameConstraints_OID             |4.2.1.11  Name Constraints|
|policyConstraints_OI            |4.2.1.12  Policy Constraints|
|extendedKeyUsage_OID            |4.2.1.13  Extended Key Usage|
|crl_OID                         |4.2.1.14  CRL Distribution Points|
|inhibitAnyPolicy_OID            |4.2.1.15  Inhibit Any-Policy|
|freshestCRL_OID                 |4.2.1.16  Freshest CRL|
|&nbsp;|&nbsp;|
|CRL Extension oiddefs Variable |RFC&nbsp;3280 Section|
|authorityKeyIdentifier_OID     |5.2.1  Authority Key Identifier
|issuerAltName_OID              |5.2.2  Issuer Alternative Name
|cRLNumber  20                  |5.2.3  CRL Number
|deltaCRLIndicator  27          |5.2.4  Delta CRL Indicator
|issuingDistributionPoint 28    |5.2.5  Issuing Distribution Point
|freshestCRL  46                |5.2.6  Freshest CRL
|                               |5.3  CRL Entry Extensions
|cRLReason  21                  |5.3.1  Reason Code
|holdInstructionCode  23        |5.3.2  Hold Instruction Code
|invalidityDate  24             |5.3.3  Invalidity Date
|certificateIssuer   29         |5.3.4  Certificate Issuer|
        @todo_eng_review (verify which *_OID constants are valid)
    */
    ubyte* oid;

    /**
        @brief      \c TRUE if extension is critical; otherwise \c FALSE.
        @details    \c TRUE if extension is critical; otherwise \c FALSE.
    */
    byteBoolean isCritical;

    /**
        @brief      DER-encoded extension %value.
        @details    DER-encoded extension %value. When DER-encoding the \p value, refer to the ASN.1 definitions provided in the following sections of RFC&nbsp;3280, https://tools.ietf.org/html/rfc3280:
        + 4.2.1.1, Authority Key Identifier
        + 4.2.1.2, Subject Key Identifier
        + 4.2.1.3, Key Usage
        + 4.2.1.4, Private Key Usage Period
        + 4.2.1.5, Certificate Policies
        + 4.2.1.6, Policy Mappings
        + 4.2.1.7, Subject Alternative Name
        + 4.2.1.8, Issuer Alternative Name
        + 4.2.1.9, Subject Directory Attributes
        + 4.2.1.10, Basic Constraints
        + 4.2.1.11, Name Constraints
        + 4.2.1.12, Policy Constraints
        + 4.2.1.13, Extended Key Usage
        + 4.2.1.14, CRL Distribution Points
        + 4.2.1.15, Inhibit Any-Policy
        + 4.2.1.16, Freshest CRL
    */
    ubyte* value;

    /**
        @brief      Number of bytes in the DER-encoded extension %value
                      (\p value).
        @details    Number of bytes in the DER-encoded extension %value
                      (\p value).
    */
    ubyte4 valueLen;
} extensions;

/**
@brief      Container for a certificate's version 3 %extensions.

@details    This structure specifies a certificate's version 3 %extensions.
            For more information, refer to RFC&nbsp;3280
            (ftp://ftp.rfc-editor.org/in-notes/pdfrfc/rfc3280.txt.pdf).

@since 1.41
@version 3.06 and later
*/
typedef struct certExtensions
{
    /**
        @brief      \c TRUE specifies that the certificate contains a
                      \c basicConstraints extension; \c FALSE otherwise.
        @details    \c TRUE specifies that the certificate contains a
                      \c basicConstraints extension; \c FALSE otherwise.
    */
    byteBoolean    hasBasicConstraints;

    /**
        @brief      \c TRUE specifies that the \c basicConstraints is a CA value;
                      \c FALSE otherwise.
        @details    \c TRUE specifies that the \c basicConstraints is a CA
                      value; \c FALSE otherwise.
    */
    byteBoolean    isCA;

    /**
        @brief      Number of certificates in the certificate chain; if
                      negative, it's omitted from the \c basicConstraints. (This
                      field corresponds to the \c pathLenConstraint referenced
                      in RFC&nbsp;3280.)
        @details    Number of certificates in the certificate chain; if
                      negative, it's omitted from the \c basicConstraints. (This
                      field corresponds to the \c pathLenConstraint referenced
                      in RFC&nbsp;3280.
    */
    sbyte          certPathLen; /* if negative omit this */

    /**
        @brief      \c TRUE specifies that the certificate contains a
                      \p keyUsage extension; \c FALSE otherwise.
        @details    \c TRUE specifies that the certificate contains a
                      \p keyUsage extension; \c FALSE otherwise.
    */
    /* key usage */
    byteBoolean    hasKeyUsage;

    /**
        @brief      Bit-string representing the desired version 3 certificate
                      extensions.
        @details    Bit-string representing the desired version 3 certificate
                      extensions; click \p keyUsage for details about setting
                      this value.
<pre>
    %keyUsage ::= BIT STRING {
    &nbsp;&nbsp;digitalSignature(0), nonRepudiation(1), keyEncipherment(2),
    &nbsp;&nbsp;dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6),
    &nbsp;&nbsp;encipherOnly(7), decipherOnly(8)}
</pre>

    For example, to set the key usage extension to "digital signature,
    certificate signing, CRL signing" use the following code:

    <tt>%keyUsage = (1 << 0) + (1 << 5) + (1 << 6)</tt>
    */
    ubyte2         keyUsage;

    /**
        @brief      Pointer to array of version 3 %extensions.
        @details    Pointer to array of version 3 %extensions.
    */
    extensions *otherExts;

    /**
        @brief      Number of %extensions in the extensions array.
        @details    Number of %extensions in the extensions array.
    */
    ubyte4      otherExtCount;
} certExtensions;

enum matchFlag
{
    matchFlagSuffix = 0x01,     /* match only the last part "server1.acme.com" matches "acme.com" */
    noWildcardMatch = 0x02,     /* name is not following rules... */
    matchFlagNoWildcard = 0x02,
    matchFlagDotSuffix = 0x04
    /* others tbd */
};


/**
 * @dont_show
 * @internal
 */
typedef struct CNMatchInfo
{
    ubyte4          flags;
    const sbyte*    name;
} CNMatchInfo;

/* subtype of SubjectAltName */
enum
{
    SubjectAltName_otherName,
    SubjectAltName_rfc822Name,
    SubjectAltName_dNSName,
    SubjectAltName_x400Address,
    SubjectAltName_directoryName,
    SubjectAltName_ediPartyName,
    SubjectAltName_uniformResourceIdentifier,
    SubjectAltName_iPAddress,
    SubjectAltName_registeredID
};

typedef struct Blob
{
    ubyte4 dataLen;
    ubyte* data;
} Blob;

/* similar to nameAttr */
typedef struct SubjectAltNameAttr
{
    Blob  subjectAltNameValue;
    ubyte subjectAltNameType;
} SubjectAltNameAttr;


/* keyPropertyType values */
enum
{
    kp_undefined = 0,
    kp_size = 1,
    kp_blob = 2,
    kp_key = 3
};

/* properties to use when creating a certificate
 all are optional, if not specified, appropriate default values will be used */
typedef struct CertProperties
{
    ubyte signAlgorithm;
    ubyte keyPropertyType; /* kp_xxxx */
    union
    {
        Blob keyBlob;
        const struct AsymmetricKey* pKey;
        ubyte4 keySize;
    } keyProperty;
    const certDescriptor* pParentCert;
    const certExtensions* pExtensions;
    Blob serialNumber;
} CertProperties;


/*------------------------------------------------------------------*/

/* common server (certificate & key related methods) */
/* signAlgo is now the last digit of the PKCS1 OID ex: md5withRSAEncryption */
/* more complex versions of these -- specify extensions and parent certificate */
MOC_EXTERN sbyte4 CA_MGMT_generateCertificateEx( certDescriptor *pRetCertificate, ubyte4 keySize,
                                            const certDistinguishedName *pCertInfo, ubyte signAlgorithm,
                                            const certExtensions* pExtensions,
                                            const certDescriptor* pParentCertificate);

MOC_EXTERN sbyte4 CA_MGMT_generateCertificateWithProperties( certDescriptor *pRetCertificate,
                                                            const certDistinguishedName* forName,
                                                            const CertProperties* properties);

MOC_EXTERN sbyte4 CA_MGMT_generateCertificateEx2( certDescriptor *pRetCertificate,
                                                 struct AsymmetricKey* key,
                                                 const certDistinguishedName *pCertInfo,
                                                 ubyte signAlgorithm);

/**
 @brief      Generate a signed X.509 certificate and public/private key
             pair.
 
 @details    This function generates a signed X.509 certificate and
             public/private key pair. If you do not specify a parent, \p pParentCertificate, the
             generated certificate is self-signed. (Self-signed certificates are typically
             used during application development and testing.)
 
             To avoid losing a certificate in the event of power loss, store the generated
             certificate and key blob to persistent storage.
 
 @ingroup    cert_mgmt_functions
 
 @since 2.02
 @version 2.02 and later
 @todo_version   (Revised post-6.4, commit [3c61741], April 14, 2016.)
 
 @flags
 To enable this function, the following flags must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 + \c \__DISABLE_MOCANA_CERTIFICATE_PARSING__
 + \c \__DISABLE_MOCANA_KEY_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pRetCertificate      Pointer to \c certDescriptor structure, which on
                             return contains the generated certificate and
                             key blob.
 @param keyType              Explicitly specifies the type of key (RSA, DSA, ECC)
                             instead of inferring it based on the keySize
 @param keySize              On return, number of bits in the generated key.
 @param pCertInfo            Pointer to distinguished name and associated
                             information for creating the certificate.
 @param signAlgorithm        Hash function to use to sign the certificate. \n
                             The following enumerated values (defined in crypto.h) are supported:
                             + \c ht_md5 \n
                             + \c ht_sha1 \n
                             + \c ht_sha256 \n
                             + \c ht_sha3846 \n
                             + \c ht_sha512 \n
                             + \c ht_sha224
 @param pExtensions          NULL if no required extensions; otherwise pointer
                             to a bit string representing the desired
                             version 3 certificate extensions. For details
                             about forming the bit string, see the \c
                             certExtensions documentation.
 @param pParentCertificate   NULL or pointer to a parent certificate. If
                             NULL, a self-signed certificate is generated.
                             Otherwise, a child certificate (signed using
                             the parent certificate) is generated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @code
 sbyte status = 0;
 certDescriptor newCertificate;
 certDistinguishedName certSubjectName;
 
 // omitted code: initialize all fields of newCertificate to 0,
 // and set the fields of certSubjectName to the desired value
 
 // generate a self-signed certificate for the EEC curve P-256 with no extensions
 if (0 > (status = CA_MGMT_generateCertificateEx(&newCertificate, 256, &certSubjectName, ht_sha256, NULL, NULL)))
 {
 goto exit;
 }
 @endcode
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_generateCertificateExType( certDescriptor *pRetCertificate, ubyte4 keyType, ubyte4 keySize,
                                const certDistinguishedName *pCertInfo, ubyte signAlgorithm,
                                const certExtensions* pExtensions,
				                const certDescriptor* pParentCertificate);

/**
 @brief      Generates a signed X.509 certificate and private/public key pair
             for a hybrid authentication algorithm.
 
 @details    Generates a signed X.509 certificate and private/public key pair
             for a hybrid authentication algorithm consisting of ECDSA and a
             quantum safe algorithm. If you do not specify a parent, \p pParentCertificate, the
             generated certificate is self-signed. (Self-signed certificates are typically
             used during application development and testing.) This method allocates
             memory so be sure to call \c CA_MGMT_freeCertificate when done with the certificate.

 @ingroup    cert_mgmt_functions
  
 @flags
 To enable this function, the following flag must \b not be defined:
 To enable this function, the following flags must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 + \c \__DISABLE_MOCANA_CERTIFICATE_PARSING__
 + \c \__DISABLE_MOCANA_KEY_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pRetCertificate      Pointer to \c certDescriptor structure, which on
                             return contains the generated certificate and
                             key blob.
 @param clAlg                One of the classical algorithm identifiers.
 @param qsAlg                One of the quantum safe (pqc) algorithm identifiers.
                             listed in the enum above.
 @param pCertInfo            Pointer to distinguished name and associated
                             information for creating the certificate.
 @param pExtensions          NULL if no required extensions; otherwise pointer
                             to a bit string representing the desired
                             version 3 certificate extensions. For details
                             about forming the bit string, see the \c
                             certExtensions documentation.
 @param pParentCertificate   NULL or pointer to a parent certificate. If
                             NULL, a self-signed certificate is generated.
                             Otherwise, a child certificate (signed using
                             the parent certificate) is generated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
  
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_generateCertificateHybrid(MOC_ASYM(hwAccelDescr hwAccelCtx) certDescriptor *pRetCertificate, 
                                                    ubyte4 clAlg, ubyte4 qsAlg,
                                                    const certDistinguishedName *pCertInfo, const certExtensions* pExtensions,
				                                    const certDescriptor* pParentCertificate);


MOC_EXTERN sbyte4 CA_MGMT_makeSubjectAltNameExtension( extensions* pExtension,
                                                      const SubjectAltNameAttr* nameAttrs,
                                                      sbyte4 numNameAttrs);


/**
 @brief      Free memory allocated by CA_MGMT_generateCertificate().
 
 @details    This function frees the memory in the specified \c certDescriptor
             buffer that was previously allocated by a call to
             CA_MGMT_generateCertificate().
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pRetCertificateDescr     Pointer to the X.509 certificate and key blob
                                 to free.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @code
 sbyte4 status = 0;
 
 status = CA_MGMT_freeCertificate(pFreeThisCertDescr);
 @endcode
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_freeCertificate(certDescriptor *pRetCertificateDescr);

#if 0
/*
 @cond
 
 @brief      Get a copy of an SoT Platform key blob's public key.
 
 @details    This function gets a copy of the public key in an SoT Platform
             key blob returned by CA_MGMT_generateCertificate().
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificateDescr    Pointer to the certificate descriptor containing
                             the X.509 certificate and key blob from which
                             you want to extract the key.
 @param ppRetPublicKey       On return, pointer to the extracted public key.
 @param pRetPublicKeyLength  On return, pointer to number of bytes in the
                             generated public key.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @code
 sbyte4 status = 0;
 
 status = CA_MGMT_returnPublicKey(pCertificateDescr, &pRetPublicKey, &retPublicKeyLength);
 @endcode
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_returnPublicKey(certDescriptor *pCertificateDescr, ubyte **ppRetPublicKey, ubyte4 *pRetPublicKeyLength);

/*
 @brief      Get number of bytes in a certificate's public key.
 
 @details    This function gets the number of bytes in a specified
             certificate's public key.
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificateDescr            Pointer to the certificate descriptor
                                     containing the X.509 certificate and
                                     key blob generated public key whose
                                     length you want.
 @param pRetPublicKeyLengthInBits    On return, pointer to length (in bits) of
                                     the generated public key.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_returnPublicKeyBitLength(certDescriptor *pCertificateDescr, ubyte4 *pRetPublicKeyLengthInBits);

/*
 @brief      Free memory allocated by CA_MGMT_returnPublicKey().
 
 @details    This function frees the memory in the specified buffer that was
              previously allocated by a call to CA_MGMT__returnPublicKey().
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param ppRetPublicKey   Pointer to the public key to free.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
              definition from merrors.h. To retrieve a string containing an
              English text error identifier corresponding to the function's
              returned error status, use the \c DISPLAY_ERROR macro.
 
 @code
 sbyte4 status = 0;
 
 status = CA_MGMT_freePublicKey(&pRetPublicKey);
 @endcode
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_freePublicKey(ubyte **ppRetPublicKey);

/**
 @endcond
 */
#endif

/**
 @brief      Allocate and initialize a \c pCertificateDesc structure.
 
 @details    This function allocates and initializaes (to zero) a
             \c pCertificateDesc structure.
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 6.4 and later
 
 @flags
 No flag definitions are required to use this function.
 
 @inc_file ca_mgmt.h
 
 @param ppNewCertDistName    On return, structure referenced contains the
                             allocated and initialized certificate.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_allocCertDistinguishedName(certDistinguishedName **ppNewCertDistName);

/**
 @brief      Get a DER-encoded X.509 certificate's subject or issuer  (as
             specified by the \p isSubject parameter) distinguished name.
 
 @details    This function gets a DER-encoded X.509 certificate's subject or
             issuer  (as specified by the \p isSubject parameter)
             distinguished name.
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @todo_version (internal changes, post-5.3.1...)
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificate         Pointer to the DER-encoded X.509 certificate of
                             interest.
 @param certificateLength    Length of the certificate, \p pCertificate, in
                             bytes.
 @param isSubject            \c TRUE to return the subject's distinguished name;
                             \c FALSE to return the issuer's distinguished
                             name.
 @param pRetDN               On return, pointer to the requested distinguished
                             name.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @code
 certDistinguishedName distName;
 sbyte4 status;
 
 status = CA_MGMT_extractCertDistinguishedName(pCertificate, certificateLength, 1, &distName);
 @endcode
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_extractCertDistinguishedName(ubyte *pCertificate, ubyte4 certificateLength, sbyte4 isSubject, certDistinguishedName *pRetDN);

/**
 @brief      Generate an X.509 certificate's SHA-1 and MD5 fingerprints.
 
 @details    This function generates and returns an X.509 certificate's SHA-1
             and MD5 \e fingerprints&mdash;message digests (output of hash functions).
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificate     Pointer to the DER-encoded X.509 certificate of
                         interest.
 @param certLength       Length of the certificate, \p pCertificate, in bytes.
 @param pShaFingerPrint  On return, pointer to the generated SHA-1 fingerprint.
 @param pMD5FingerPrint  On return, pointer to the generated MD5 fingerprint.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @code
 sbyte4 status = 0;
 
 status = CA_MGMT_returnCertificatePrints(pCertificate, certLength, &ShaFgrBuf, &MD5FgrBuf);
 @endcode
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_returnCertificatePrints(ubyte *pCertificate, ubyte4 certLength, ubyte *pShaFingerPrint, ubyte *pMD5FingerPrint);


/**
 @brief      Free \c certDistinguishedName structure's memory.
 
 @details    This function frees the memory in the given \c
             certDistinguishedName structure, as well as all memory pointed
             to by the structure's fields.
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 No flag definitions are required to use this function.
 
 @inc_file ca_mgmt.h
 
 @param ppFreeCertDistName   Pointer to the X.509 certificate's distinguished
                             name structure to release.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_freeCertDistinguishedName(certDistinguishedName **ppFreeCertDistName);

/**
 @brief      Get an X.509 certificate's subject or issuer DER-encoded ASN.1 name.
 
 @details    This function gets an X.509 certificate's subject or issuer (as
             specified by the \p isSubject parameter) DER-encoded ASN.1 name. The
             subject is typically used to generate a PKCS-10 request.
 
             When choosing whether to specify \p includeASN1SeqHeader as \c TRUE or \c FALSE,
             keep in mind that DER-encoded objects (which can be nested) have a general format
             of tag+length+data. For this function, the tag+length represents the header.
             RFC&nbsp;3280 defines a DER-encoded ASN1 as follows:
 <pre>
 Name ::= CHOICE {
 RDNSequence }
 
 RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 
 RelativeDistinguishedName ::=
 SET OF AttributeTypeAndValue
 
 AttributeTypeAndValue ::= SEQUENCE {
 type     AttributeType,
 value    AttributeValue }
 
 AttributeType ::= OBJECT IDENTIFIER
 
 AttributeValue ::= ANY DEFINED BY AttributeType
 </pre>
 
 When you specify \p includeASN1SeqHeader as \c TRUE, the returned \p pASN1NameOffset points to the
 start of the \e tag part of the DER-encoded ASN1 name, which identifies this name as a SEQUENCE OF
 RelativeDistinguishedName objects. When you specify \p includeASN1SeqHeader as \c FALSE, the returned
 \p pASN1NameOffset points to the \e value part of the tag+length+data DER-encoded name, which is the
 first of the RelativeDistinguishedName objects in the name.
 
 To add a name "as is" to a certificate or CSR (Certificate Signing Request), as in functions such
 as PKCS10_GenerateCertReqFromASN1() and PKCS10_generateCSRFromASN1(), include the header.
 
 @todo_eng_review (details expanded post-5.3.1)
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 5.3 and later
 
 @todo_version (internal changes, post-5.3.1...)
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificate         Pointer to the DER-encoded X.509 certificate of
                             interest.
 @param certificateLength    Length of the certificate, \p pCertificate, in
                             bytes.
 @param isSubject            \c TRUE to return the subject's distinguished name;
                             \c FALSE to return the issuer's distinguished
                             name.
 @param includeASN1SeqHeader \c TRUE to include the ASN.1 sequence; otherwise
                             \c FALSE (to advance the \p pASN1NameOffset pointer past the header to the name's value).
 @param pASN1NameOffset      On return, pointer to certificate's ASN.1 name
                             field.
 @param pASN1NameLen         On return, pointer to number of bytes in
                             certificate's ASN.1 name.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_extractCertASN1Name(const ubyte *pCertificate, ubyte4 certificateLength,
                                           sbyte4 isSubject, sbyte4 includeASN1SeqHeader, ubyte4* pASN1NameOffset, ubyte4* pASN1NameLen);

/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN sbyte4  CA_MGMT_convertKeyDER(ubyte *pDerRsaKey, ubyte4 derRsaKeyLength, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN sbyte4  CA_MGMT_convertKeyPEM(ubyte *pPemRsaKey, ubyte4 pemRsaKeyLength, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_keyBlobToDER(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_publicKeyBlobToDER(const ubyte *pPublicKeyBlob, ubyte4 publicKeyBlobLength,
  ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_keyBlobToPEM(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetKeyPEM, ubyte4 *pRetKeyPEMLength);

/**
 * @brief Convert the DER encoding of an RSA public key in PublicKeyInfo format
 * into a Mocana key blob.
 *
 * @details The ASN.1 definitions of PublicKeyInfo (also known as
 * SubjectPublicKey) and RSAPublicKey are the following.
 * <pre>
 * <code>
 *   PublicKeyInfo ::= SEQUENCE {
 *     algorithm       AlgorithmIdentifier,
 *     PublicKey       BIT STRING }
 *
 *   RSAPublicKey ::= SEQUENCE {
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER   -- e  }
 * </code>
 * </pre>
 * The DER encoding of an RSA public key might be RSAPublicKey or it might be
 * PublicKeyInfo. If it is PublicKeyInfo, call this routine to convert it into a
 * Mocana format key blob (which you can use to build an AsymmetricKey object).
 * The BIT STRING of the PublicKeyInfo "wraps" the DER encoding of RSAPublicKey.
 * <p>The function will allocate memory. The caller passes in the address of a
 * ubyte pointer, the function will allocate memory to hold the key blob, fill
 * that memory with the key blob and deposit the pointer at the address given. It
 * is the repsonsibility of the caller to free that memory using MOC_FREE.
 *
 * @memory Make sure you free the buffer returned at the address ppRetKeyBlob
 * using MOC_FREE when you are done with it.
 *
 * @ingroup    cert_mgmt_functions
 * @flags
 * To enable this function, at least one of the following flags must be defined in moptions.h:
 * + \c \__ENABLE_MOCANA_DER_CONVERSION__
 * + \c \__ENABLE_MOCANA_PEM_CONVERSION__
 *
 * @inc_file ca_mgmt.h
 *
 * @param pDerRsaKey The DER encoding of an RSA public key following the ASN.1
 * definition PublicKeyInfo.
 * @param derRsaKeyLength The length, in bytes, of the DER-encoded key.
 * @param ppRetKeyBlob The address where the function will deposit a pointer to
 * allocated memory containing the key data as a Mocana key blob.
 * @param pRetKeyBlobLength The address where the function will deposit the
 * length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 * definition from merrors.h. To retrieve a string containing an
 * English text error identifier corresponding to the function's
 * returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    ca_mgmt.h
 */
MOC_EXTERN MSTATUS CA_MGMT_convertRSAPublicKeyInfoDER (
  ubyte *pDerRsaKey,
  ubyte4 derRsaKeyLength,
  ubyte **ppRetKeyBlob,
  ubyte4 *pRetKeyBlobLength
  );

struct vlong;

/* Build the DER encoding of
 * <pre>
 * <code>
 *   MocanaTPM1.2RSAKeyData ::= SEQUENCE {
 *     OCTET STRING   encryptedPrivateKey,
 *     INTEGER        modulus,
 *     INTEGER        publicExponent }
 * </code>
 * </pre>
 * <p>This function will allocate space for the encoding and return a pointer to
 * this allocated memory at the address given by ppDerEncoding.
 * <p>Note that the blob is the Mocana version 2 blob.
 */
MOC_EXTERN MSTATUS CA_MGMT_tpm12RsaKeyBlobToDer (
  ubyte *pKeyBlob,
  ubyte4 keyBlobLen,
  struct vlong *pModulus,
  struct vlong *pPubExpo,
  ubyte **ppDerEncoding,
  ubyte4 *pDerEncodingLen
  );

/**
 @brief      Validate a DER-encoded X.509 certificate's start and expiration
             times and dates against the current time.
 
 @details    This function gets a DER-encoded X.509 certificate's start and
             expiration times and dates and validates them against the current
             time.
 
 @ingroup    cert_mgmt_functions
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCert                Pointer to the DER-encoded X.509 certificate of
                             interest.
 @param certLen              Length of the certificate, \p pCertificate, in
                             bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN MSTATUS CA_MGMT_verifyCertDate(ubyte *pCert, ubyte4 certLen);

MOC_EXTERN MSTATUS CA_MGMT_verifyCertAndKeyPair(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCert,
    ubyte4 certLen,
    struct AsymmetricKey *pAsymKey,
    byteBoolean *pIsGood);

/**
 @brief      Verify correspondence of a \c certDescriptor key blob and
             certificate's key.
 
 @details    This function verifies that a \c certDescriptor key blob matches
             the X.509 certificate's key.
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 3.06 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificateDescr    Pointer to the certificate descriptor containing the
                             X.509 certificate and key blob generated public
                             key.
 @param pIsGood              Pointer to buffer that on return contains \c TRUE
                             if the certificate's key blob matches the cedrtificate's key; otherwise \c FALSE.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_verifyCertWithKeyBlob(certDescriptor *pCertificateDescr, sbyte4 *pIsGood);

/**
 @brief      Get a DER-encoded X.509 certificate's start and expiration times
             and dates.
 
 @details    This function gets a DER-encoded X.509 certificate's start and
             expiration times and dates.
 
 @warning    The only meaningful fields in the returned \p pRetDN \c
             certDistinguisedName structure are \c pStartDate and \c pEndDate. Do
             not use the remaining fields in \p pRetDN.
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param pCertificate         Pointer to the DER-encoded X.509 certificate of
                             interest.
 @param certificateLength    Length of the certificate, \p pCertificate, in
                             bytes.
 @param pRetDN               On return, pointer to the certificate's start and
                             end dates.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_extractCertTimes(ubyte *pCertificate, ubyte4 certificateLength, certDistinguishedName *pRetDN);
    
/**
 @brief      Convert PEM-encoded certificate to DER-encoded certificate.
 
 @details    This function converts a PEM-encoded certificate to a DER-encoded
             certificate. This function allocates memory that the caller must free
             (using MOC_FREE).
 
 @ingroup    cert_mgmt_functions
 
 @since 1.41
 @version 1.41 and later
 
 @todo_version (changed return type; added param validity checking...)
 
 @flags
 To enable this function, at least one of the following flags must be defined in moptions.h:
 + \c \__ENABLE_MOCANA_PKCS10__
 + \c \__ENABLE_MOCANA_PEM_CONVERSION__
 
 @inc_file ca_mgmt.h
 
 @param pKeyFile         Pointer to certificate file to decode.
 @param fileSize         Number of bytes in certificate file.
 @param ppDecodeFile     The address where the function will deposit allocated
                         memory containing the DER version of the certificate.
 @param pDecodedLength   On return, pointer to number of bytes in \p ppDecodeFile.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_decodeCertificate(ubyte* pKeyFile, ubyte4 fileSize, ubyte** ppDecodeFile, ubyte4 *pDecodedLength);

#ifdef __ENABLE_MOCANA_CERTIFICATE_SEARCH_SUPPORT__
MOC_EXTERN sbyte4  CA_MGMT_extractSerialNum (ubyte* pCertificate, ubyte4 certificateLength, ubyte** ppRetSerialNum, ubyte4* pRetSerialNumLength);
MOC_EXTERN sbyte4  CA_MGMT_freeSearchDetails(ubyte** ppFreeData);

/**
 * @dont_show
 * @internal
 */
typedef sbyte4 (*CA_MGMT_EnumItemCBFun)( const ubyte* pContent, ubyte4 contentLen, ubyte4 contentType,
                                        ubyte4 index, void* userArg);


/**
 @brief      Enumerate the CRLs (certificate revocation lists) in a
             certificate, and invoke the given callback function for each CRL.
 
 @details    This function parses the CRLs (certificate revocation lists) in a
             certificate and finds its CRLs, and for each CRL invokes the
             callback function that is passed through the \p callbackFunc
             parameter.
 
 @ingroup    cert_mgmt_functions
 
 @since 2.02
 @version 4.0 and later
 
 @todo_version (internal changes, post-5.3.1...)
 
 The \p callbackFunc parameter's callback function must have the following
 method signature:
 
 <pre>
 sbyte4 userFunc(const ubyte *pContent, ubyte4 contentLen, ubyte4 contentType, ubyte4 index, void *userArg);
 </pre>
 
 ### Syntax/parameters
 Name|Type|Description
 ----|----|-----------|
 |<tt>\<pContent></tt>|<tt>const ubyte *</tt>|Pointer to CRL buffer.|
 |<tt>\<contentLen></tt>|\c ubyte4|Number of bytes in CRL buffer (\p pContent).|
 |<tt>\<contentType></tt>|\c ubyte4|ASN.1 tag associated with the CRL, which indicates how to interpret the CRL's contents.
 For details, refer to the description of the \c GeneralName type
 http://www.itu.int/ITU-T/asn1/database/itu-t/x/x509/1997/CertificateExtensions.html#CertificateExtensions.GeneralName.|
 |<tt>\<index></tt>|\c ubyte4|0-based index of this CRL's location in the CRL list.|
 |<tt>\<userArg></tt>|<tt>void *</tt>|Value of the \c userArg parameter when the \c %CA_MGMT_enumCrl function was called.|
 |&nbsp;|&nbsp;|&nbsp;\n|
 |Return value|\c sbyte4|Negative number to stop CRL enumeration; otherwise a number >= 0 to continue CRL enumeration.|
 
 @flags
 To enable this function, the following flag must be defined in moptions.h:
 + \c \__ENABLE_MOCANA_CERTIFICATE_SEARCH_SUPPORT__
 
 @inc_file ca_mgmt.h
 
 @param pCertificate         Pointer to DER-encoded certificate to parse.
 @param certificateLength    Number of bytes in the certificate
                             (\p pCertificate).
 @param callbackFunc         Pointer to user-defined callback function to
                             invoke for each CRL. See the description
                             section for callback function details.
 @param userArg              Pointer to argument to provide to callback function:
                             \c NULL or a context to provide to the callback function.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_enumCrl(ubyte* pCertificate, ubyte4 certificateLength,
                                         CA_MGMT_EnumItemCBFun callbackFunc, void* userArg);

/**
 @brief      Enumerate the subject/issuer alternative names in a DER-encoded
             X.509 certificate, and invoke the given callback function for
             each alternative name.
 
 @details    This function parses a DER-encoded X.509 certificate and compiles
             a list of \c SubjectAltName or \c IssuerAltName objects,
             depending on the value of the \p isSubject parameter. For each
             alternative name, this function invokes the callback function
             that is passed through the \p callbackFunc parameter.
 
 @ingroup    cert_mgmt_functions
 
 @since 4.0
 @version 4.0 and later

 @todo_version (internal changes, post-5.3.1...)
 
 The \p callbackFunc parameter's callback function must have the following
 method signature:
 
 <pre>
 sbyte4 userFunc(const ubyte *pContent, ubyte4 contentLen, ubyte4 contentType, ubyte4 index, void *userArg);
 </pre>
 
 ### Syntax/parameters
 Name|Type|Description
 ----|----|-----------|
 |<tt>\<pContent></tt>|<tt>const ubyte *</tt>|Pointer to CRL buffer.|
 |<tt>\<contentLen></tt>|\c ubyte4|Number of bytes in CRL buffer (\p pContent).|
 |<tt>\<contentType></tt>|\c ubyte4|ASN.1 tag associated with the CRL, which indicates how to interpret the CRL's contents.
 For details, refer to the description of the \c GeneralName type
 http://www.itu.int/ITU-T/asn1/database/itu-t/x/x509/1997/CertificateExtensions.html#CertificateExtensions.GeneralName.|
 |<tt>\<index></tt>|\c ubyte4|0-based index of this CRL's location in the CRL list.|
 |<tt>\<userArg></tt>|<tt>void *</tt>|Value of the \c userArg parameter when the \c %CA_MGMT_enumAltName function was called.|
 |&nbsp;|&nbsp;|&nbsp;\n|
 |Return value|\c sbyte4|Negative number to stop CRL enumeration; otherwise a number >= 0 to continue CRL enumeration.|
 
 @flags
 To enable this function, the following flag must be defined in moptions.h:
 + \c \__ENABLE_MOCANA_CERTIFICATE_SEARCH_SUPPORT__
 
 @inc_file ca_mgmt.h
 
 @param pCertificate         Pointer to DER-encoded certificate to parse.
 @param certificateLength    Number of bytes in the certificate
                             (\p pCertificate).
 @param isSubject            \c TRUE to find \c SubjectAltName objects; \c FALSE
                             to find \c IssuerAltName objects.
 @param callbackFunc         Pointer to user-defined callback function to
                             invoke for each alternative name. See the
                             description section for callback function details.
 @param userArg              Pointer to argument to provide to callback function:
                             \c NULL or a context to provide to the callback function.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @remark     This is a convenience function provided for your application's
             use; it is not used by Mocana SoT Platform internal code.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4  CA_MGMT_enumAltName( ubyte* pCertificate, ubyte4 certificateLength, sbyte4 isSubject,
                                         CA_MGMT_EnumItemCBFun callbackFunc, void* userArg);
#endif

#ifdef __PUBCRYPTO_HEADER__
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_makeKeyBlobEx(const AsymmetricKey *pKey, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_extractKeyBlobEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength, AsymmetricKey* pKey);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_extractKeyBlobTypeEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte4 *pRetKeyType);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS CA_MGMT_extractPublicKey(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetPublicKeyBlob, ubyte4 *pRetPublicKeyBlobLength, ubyte4 *pRetKeyType);
#endif /* __PUBCRYPTO_HEADER__ */

#ifdef __ENABLE_MOCANA_EXTRACT_CERT_BLOB__
MOC_EXTERN sbyte4 CA_MGMT_findCertDistinguishedName(ubyte *pCertificate, ubyte4 certificateLength, intBoolean isSubject, ubyte **ppRetDistinguishedName, ubyte4 *pRetDistinguishedNameLen);
#endif

/**
 @brief      Generate a naked key.
 
 @details    This function generates a <em>naked key</em>&mdash;a key blob
             that has no associated certificate&mdash;. The naked key can be
             used as input to generate a certificate or as signing data for
             authentication.
 
 @ingroup    cert_mgmt_functions
 
 @since 2.02
 @version 2.02 and later
 
 @todo_version (internal changes, post-5.3.1...)
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_KEY_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param keyType              Type of key to generate. \n\n
 The following enumerated values (defined in ca_mgmt.h) are supported:
                             + \c akt_undefined \n
                             + \c akt_rsa \n
                             + \c akt_ecc \n
                             + \c akt_ecc_ed \n
                             + \c akt_dsa
 @param keySize              Number of bits the generated key must contain.
 @param ppRetNewKeyBlob      On return, pointer to generated naked key.
 @param pRetNewKeyBlobLength On return, pointer to number of bytes in the
                             naked key (\p ppRetNewKeyBlob).
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_generateNakedKey(ubyte4 keyType, ubyte4 keySize, ubyte **ppRetNewKeyBlob, ubyte4 *pRetNewKeyBlobLength);

/**
 @brief      Generate a naked key. Supports ability to generate qs or hybrid keys.
 
 @details    This function generates a <em>naked key</em>&mdash;a key blob
             that has no associated certificate&mdash;. The naked key can be
             used as input to generate a certificate or as signing data for
             authentication.
 
 @ingroup    cert_mgmt_functions
 
 @since 2.02
 @version 2.02 and later
 
 @todo_version (internal changes, post-5.3.1...)
 
 @flags
 To enable this function, the following flags must be defined:
 + \c \__ENABLE_MOCANA_PQC__
 + \c \__ENABLE_MOCANA_ECC__

 And the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_KEY_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param keyType              Type of key to generate. \n\n
                             The following enumerated values (defined in ca_mgmt.h) are supported:
                             + \c akt_undefined \n
                             + \c akt_rsa \n
                             + \c akt_ecc \n
                             + \c akt_ecc_ed \n
                             + \c akt_dsa \n
                             + \c akt_qs \n
                             + \c akt_hybrid
 @param keySizeOrClAlg       Classical Alg identifier for hybrid keys. For ECC or
                             or RSA keys this may be a size or identifier. This
                             is unused for pure pqc keys. The identifiers are the 
                             + \c cid_EC... or \c cid_RSA... ones found in this file. 
 @param qsAlg                The identifer for the pqc key or portion thereof. \n\n
                             The following enumerated values (defined in ca_mgmt.h) are supported:
                             + \c cid_PQC_MLDSA_44 \n
                             + \c cid_PQC_MLDSA_65 \n
                             + \c cid_PQC_MLDSA_87 \n
                             + \c cid_PQC_FNDSA_512 \n
                             + \c cid_PQC_FNDSA_1024 \n
                             + \c cid_PQC_SLHDSA_SHA2_128S \n
                             + \c cid_PQC_SLHDSA_SHA2_128F \n
                             + \c cid_PQC_SLHDSA_SHAKE_128S \n
                             + \c cid_PQC_SLHDSA_SHAKE_128F \n
                             + \c cid_PQC_SLHDSA_SHA2_192S \n
                             + \c cid_PQC_SLHDSA_SHA2_192F \n
                             + \c cid_PQC_SLHDSA_SHAKE_192S \n
                             + \c cid_PQC_SLHDSA_SHAKE_192F \n
                             + \c cid_PQC_SLHDSA_SHA2_256S \n
                             + \c cid_PQC_SLHDSA_SHA2_256F \n
                             + \c cid_PQC_SLHDSA_SHAKE_256S \n
                             + \c cid_PQC_SLHDSA_SHAKE_256F \n
 @param ppRetNewKeyBlob      On return, pointer to generated naked key.
 @param pRetNewKeyBlobLength On return, pointer to number of bytes in the
                             naked key (\p ppRetNewKeyBlob).
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_generateNakedKeyPQC(ubyte4 keyType, ubyte4 keySizeOrClAlg, ubyte4 qsAlg,
                                              ubyte **ppRetNewKeyBlob, ubyte4 *pRetNewKeyBlobLength);

/**
 @brief      Free (release) a naked key blob's memory.
 
 @details    This function frees (releases)the memory used by a naked key blob.
 
 @ingroup    cert_mgmt_functions
 
 @since 2.02
 @version 2.02 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_KEY_GENERATION__
 
 @inc_file ca_mgmt.h
 
 @param ppFreeKeyBlob    Pointer to naked key blob to free (release).
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_freeNakedKey(ubyte **ppFreeKeyBlob);

/**
 @brief      Convert unprotected RSA private key to a Mocana SoT Platform
             private RSA keyblob.
 
 @details    This function converts an unprotected RSA private key (extracted
             from a PKCS&nbsp;\#8 DER-encoded buffer) to a Mocana SoT Platform
             private RSA keyblob.
 
 @note       After you are done with the returned keyblob, be sure to free its
             memory by calling MOC_FREE() or CA_MGMT_freeNakedKey().
 
 @ingroup    cert_mgmt_functions
 
 @since 5.1
 @version 5.1 and later
 
 @todo_version (internal changes, post-5.3.1...)
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_PARSING__
 
 Additionally, \c \__DISABLE_MOCANA_KEY_GENERATION__ must \b not be defined,
 or one of the following flags must be defined:
 + \c \__ENABLE_MOCANA_PEM_CONVERSION__
 + \c \__ENABLE_MOCANA_DER_CONVERSION__
 
 @inc_file ca_mgmt.h
 
 @param pPKCS8DER            Pointer to PKCS&nbsp;\#8 DER-encoded key.
 @param pkcs8DERLen          Number of bytes in the DER-encoded key
                             ($\p pPKCS8DER).
 @param ppRetKeyBlob         On return, pointer to converted keyblob.
 @param pRetKeyBlobLength    On return, number of bytes in the converted
                             keyblob (\p ppRetKeyBlob).
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_convertPKCS8KeyToKeyBlob(const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength);

/**
 @brief      Extract a protected RSA private key from a PKCS&nbsp;\#8 DER-
             encoded buffer, converting it into a Mocana SoT Platform
             unprotected private RSA key blob.
 
 @details    This function extracts a protected RSA private key from a
             PKCS&nbsp;\#8 DER-encoded buffer, and converts the key to a
             Mocana SoT Platform unprotected private RSA keyblob.
 
 @note       After you are done with the returned keyblob, be sure to free its
             memory by calling MOC_FREE() or CA_MGMT_freeNakedKey().
 
 @ingroup    cert_mgmt_functions
 
 @since 5.1
 @version 6.4 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_PARSING__
 
 Additionally, \c \__DISABLE_MOCANA_KEY_GENERATION__ must \b not be defined,
 or one of the following flags must be defined:
 + \c \__ENABLE_MOCANA_PEM_CONVERSION__
 + \c \__ENABLE_MOCANA_DER_CONVERSION__
 
 @inc_file ca_mgmt.h
 
 @param pPKCS8DER            Pointer to PKCS&nbsp;\#8 DER-encoded key.
 @param pkcs8DERLen          Length in bytes of the DER-encoded key, \p
                             pPKCS8DER.
 @param pPassword            Pointer to password that protects the
                             PKCS&nbsp;\#8 DER-encoded key.
 @param passwordLen          Length in bytes of the password, \p pPassword.
 @param ppRetKeyBlob         On return, pointer to extracted/converted key blob.
 @param pRetKeyBlobLength    On return, length of extracted/converted key blob
                             \p ppRetKeyBlob.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_convertProtectedPKCS8KeyToKeyBlob(const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen, ubyte *pPassword, ubyte4 passwordLen, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength);

#ifdef __PKCS_KEY_HEADER__

/**
 @brief      Encapsulate a Mocana SoT Platform keyblob in a protected
             PKCS&nbsp;\#8 DER-encoded buffer.
 
 @details    This function encapsulates a Mocana SoT Platform keyblob in a
             protected PKCS&nbsp;\#8 DER-encoded buffer.
 
 @note       After you are done with the returned keyblob, be sure to free its
             memory by calling MOC_FREE() or CA_MGMT_freeNakedKey().
 
 @ingroup    cert_mgmt_functions
 
 @since 5.1
 @version 6.4 and later
 
 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_CERTIFICATE_PARSING__
 
 Additionally, the following flag must be defined:
 + \c \__ENABLE_MOCANA_DER_CONVERSION__
 
 @inc_file ca_mgmt.h
 
 @param pKeyBlob             Pointer to Mocana SoT Platform key blob to convert.
 @param keyBlobLength        Number of bytes in the keyblob (\p pKeyBlob).
 @param encType              Type of encryption method to use; any of the \c
                             PKCS8EncryptionType enumerations (except \c
                             PCKS8_EncryptionType_undefined) in pkcs_key.h.
 @param pPassword            Pointer to password to use to protect the
                             PKCS&nbsp;\#8 DER-encoded key.
 @param passwordLen          Number of bytes in the password (\p pPassword).
 @param ppRetPKCS8DER        On return, pointer to PKCS&nbsp;\#8 DER-encoded key.
 @param pRetPkcs8DERLen      On return, number of bytes in the DER-encoded key
                             (\p ppRetPKCS8DER).
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    ca_mgmt.h
 */
MOC_EXTERN sbyte4 CA_MGMT_convertKeyBlobToPKCS8Key(const ubyte *pKeyBlob, ubyte4 keyBlobLength, enum PKCS8EncryptionType encType, const ubyte *pPassword, ubyte4 passwordLen, ubyte **ppRetPKCS8DER, ubyte4 *pRetPkcs8DERLen);
#endif

#if !(defined(__DISABLE_MOCANA_KEY_GENERATION__)) && !(defined(__DISABLE_MOCANA_CERTIFICATE_PARSING__))

/**
 * @brief   Gets the public key from a certificate.
 *
 * @details Gets the public key from a certificate. A buffer will be allocated
 *          to hold the public key in Mocana keyblob format. Be sure to free this buffer when done with it.
 *
 * @param pCertificate    Pointer to the DER encoded certificate.
 * @param certificateLen  The length of the certificate in bytes.
 * @param ppRetKeyBlob    Pointer to the location that will receive the newly
 *                        allocated buffer holding the serialized public key.
 * @param pRetKeyBlobLen  Contents will be set to the length of the serialized public key in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN sbyte4 CA_MGMT_extractPublicKeyInfo(ubyte *pCertificate, ubyte4 certificateLen, ubyte** ppRetKeyBlob, ubyte4 *pRetKeyBlobLen);
#endif

/**
 * @brief   Verifies the signature in a certificate.
 *
 * @details Verifies the signature in a certificate.
 *
 * @param pIssuerCertBlob    The issuer public key serialized as a Mocana blob.
 * @param issuerCertBlobLen  The length of the serialized public key in bytes.
 * @param pCertificate       Pointer to the DER encoded certificate.
 * @param certLen            The length of the certificate in bytes.
 *
 * @return  \c OK (0) if successful and the signature is valid, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN sbyte4 CA_MGMT_verifySignature(const ubyte* pIssuerCertBlob, ubyte4 issuerCertBlobLen, ubyte* pCertificate, ubyte4 certLen);

/**
 * @brief   Verifies the signature in a certificate with AsymmetricKey.
 *
 * @details Verifies the signature in a certificate with AsymmetricKey.
 *
 * @param pAsymKey           Key used to verify signature.
 * @param pCertOrCsr         Pointer to the PEM/DER CSR or certificate.
 * @param certOrCsrLen       The length of the CSR or certificate in bytes.
 *
 * @return  \c OK (0) if successful and the signature is valid, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CA_MGMT_verifySignatureWithAsymKey(MOC_ASYM(hwAccelDescr hwAccelCtx) struct AsymmetricKey *pAsymKey, ubyte *pCertOrCsr, ubyte4 certOrCsrLen);

/**
 * @brief   Gets the signature out of a cert.
 *
 * @details Gets the signature out of a cert. A buffer will be allocated
 *          to hold the signature. Be sure to free this buffer when done with it.
 *
 * @param pCertificate   Pointer to the DER encoded certificate.
 * @param certificateLen The length of the certificate in bytes.
 * @param ppSignature    Pointer to the location that will receive the newly
 *                       allocated signature buffer.
 * @param pSignatureLen  Contents will be set to the length of the signature in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN sbyte4 CA_MGMT_extractSignature(ubyte* pCertificate, ubyte4 certificateLen, ubyte** ppSignature, ubyte4* pSignatureLen);

/** Get the BasicConstraints extension out of a cert.
 * <p>Pass in the DER-encoded cert, along with a pointer to a certExtensions
 * struct. This function will set the BasicCOnstraints fields of the struct. You
 * can then examine the results.
 * <p>This function will set all the non-BasicConstraints fields in the struct to
 * NULL/0.
 */
MOC_EXTERN sbyte4 CA_MGMT_extractBasicConstraint(ubyte* pCertificate, ubyte4 certificateLen, intBoolean* pIsCritical, certExtensions* pCertExtensions);

/**
 * @brief   Gets the hash type and public key type out of a cert.
 *
 * @details Gets the hash type and public key type out of a cert.
 *
 * @param pCertificate   Pointer to the DER encoded certificate.
 * @param certificateLen The length of the certificate in bytes.
 * @param pHashType      Contents will be set to the hash identifier
 *                       found in the certificate (if there is one). These
 *                       identifiers can be found in the enum in crypto.h.
 * @param pPubKeyType    Contents will be set to the public key type.
 *                       These are the akt_<type> identifiers above.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CA_MGMT_getCertSignAlgoType(ubyte *pCertificate, ubyte4 certificateLen, ubyte4* pHashType, ubyte4* pPubKeyType);

/**
 * @brief   Converts an IP address represented by a string (v4 or v6) to raw bytes.
 *
 * @details Converts an IP address represented by a string (v4 or v6) to raw bytes.
 *          For example, v4 would look like 192.168.1.10 with decimal integers and
 *          v6 would look like 1234:5678:9abc:def0:fedc:bca9:0000:1111 with 8 groups
 *          of hex integers (with zero integers required, ie no empty groups).
 *
 * @param pIpString   The input string form of the ip address.
 * @param pIpBytes    Buffer to hold the output raw byte form ip. Must be 16 bytes if
 *                    IPv6 is to be supported.
 * @param pIpLen      Will be set to the length of the raw byte form (either 4 or 16
 *                    for v4 or v6 respectively)
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CA_MGMT_convertIpAddress(ubyte *pIpString, ubyte *pIpBytes, ubyte4 *pIpLen);

#ifdef __cplusplus
}
#endif

#endif /* __CA_MGMT_HEADER__ */
