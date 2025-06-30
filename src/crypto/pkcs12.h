/*
 * pkcs12.h
 *
 * PKCS#12 Parser
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
@file       pkcs12.h

@brief      Header file for SoT Platform PKCS&nbsp;\#12 convenience API.
@details    Header file for SoT Platform PKCS&nbsp;\#12 convenience API.

*/

#ifndef __PKCS12_HEADER__
#define __PKCS12_HEADER__

#include "../common/sizedbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PKCS12__
/* public constants */
MOC_EXTERN const ubyte pkcs12_bagtypes_root_OID[]; /* 1.2.840.113549.1.12.10.1 */
MOC_EXTERN const ubyte pkcs12_Pbe_root_OID[]; /* 1.2.840.113549.1.12.1 */

/**
@brief      Enumeration of content types for PKCS&nbsp;\#12.
@details    Enumeration of content types for PKCS&nbsp;\#12; defined in pkcs12.h.
*/
typedef enum
{
    KEYINFO, CERT, CRL
} contentTypes;

/**
@brief      Enumeration of certificate types for PKCS&nbsp;\#12.
@details    Enumeration of certificate types for PKCS&nbsp;\#12; defined in
              pkcs12.h.
*/
typedef enum
{
#ifndef __DISABLE_MOCANA_PKCS12_X509_CERTTYPE_DEFINITION__
    X509 = 1,
#endif
    SDSI=2
} certTypes;

/*PKCS12 Encryption and Integrity Modes */
/**
@brief      Enumeration of PKCS12 encryption and integrity modes.
@details    Enumeration of PKCS12 encryption and integrity modes; defined in
              pkcs12.h.
*/
typedef enum ePKCS12Mode
{
    PKCS12Mode_Privacy_none = 0,
    PKCS12Mode_Privacy_data,
    PKCS12Mode_Privacy_password,
    PKCS12Mode_Privacy_pubKey,
    PKCS12Mode_Integrity_password,
    PKCS12Mode_Integrity_pubKey
} ePKCS12Mode;

/* enum for pkcs12 attribute */
/**
@brief      Enumeration of PKCS&nbsp;\#12 attributes.
@details    Enumeration of PKCS&nbsp;\#12 attributes; defined in pkcs12.h.
*/
typedef enum ePKCS12AttributeType
{
    PKCS12_AttributeType_friendlyName = 0,
    PKCS12_AttributeType_localKeyId
} ePKCS12AttributeType;

/* User configuration related structures */

/*
 * PKCS12AttributeUserValue
 * Section 4.2 PKCS12AttrSet : If the user desires to assign nicknames and identifiers to keys etc
 */
/**
@brief      Nickname and/or identifier for keys; as defined in Section 4.2,
              "PKCS12AttrSet,", in <em>PKCS 12 v1.0: Personal Information
              Exchange Syntax</em>, available at
              ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf.

@details    Nickname and/or identifier for keys; as defined in Section 4.2,
              "PKCS12AttrSet,", in <em>PKCS 12 v1.0: Personal Information
              Exchange Syntax</em>, available at
              ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf.
*/
typedef struct PKCS12AttributeUserValue
{
    /**
    @brief      Attribute type; any of the \c ePKCS12AttributeType enum values
                  defined in pkcs12.h.
    @details    Attribute type; any of the \c ePKCS12AttributeType enum values
                  defined in pkcs12.h.
    */
    ePKCS12AttributeType             eAttrType;    /* One of the above mentioned Attribute type */
    /**
    @brief      Pointer to attribute value.
    @details    Pointer to attribute value.
    */
    ubyte*                           pValue;       /* Holds the Value */
    /**
    @brief      Length of the attribute value, \p PKCS12AttributeUserValue::pValue.
    @details    Length of the attribute value, \p PKCS12AttributeUserValue::pValue.
    */
    ubyte4                           valueLen;     /* length of Value */
} PKCS12AttributeUserValue;

/*
 * PKCS12DataObject
 * Contents that need to be published within the PKCS#12 file along with the privacy mode
 */
/**
@brief      Content to be published in the PKCS&nbsp;\#12 file with the privacy
            mode.

@details    Content to be published in the PKCS&nbsp;\#12 file with the privacy
            mode.
*/
typedef struct PKCS12DataObject
{
    /**
    @brief      Encryption and integrity to apply to the data; any of the
                \c ePKCS12Mode enum values from pkcs12.h.

    @details    Encryption and integrity to apply to the data; any of the
                followoing \c ePKCS12Mode enum values from pkcs12.h:
                 + \c PKCS12Mode_Privacy_none (the mode will default to \c
                    PKCS12Mode_Privacy_password)
                 + \c PKCS12Mode_Privacy_data
                 + \c PKCS12Mode_Privacy_password
                 + \c PKCS12Mode_Privacy_pubKey
                 + \c PKCS12Mode_Integrity_password
                 + \c PKCS12Mode_Integrity_pubKey
    */
    ePKCS12Mode                  privacyMode;          /* Privacy Mode: Indicates how the user wants to encrypt the data given below.
                                                        * for PKCS12Mode_Privacy_none: In this case the mode would default to PKCS12Mode_Privacy_password
                                                        */
    /**
    @brief      PKCS&nbsp;\#8 encrytion key type; any of the \c
                  PKCS8EncryptionType enum values from pkcs_key.h.

    @details    PKCS&nbsp;\#8 encrytion key type; any of the \c
                  PKCS8EncryptionType enum values from pkcs_key.h.
    */
    ubyte4                       encKeyType;           /* enum PKCS8EncryptionType : PKCS#8 Encrytion Key type */
    /**
    @brief      Password for key encryption.

    @details    Password for key encryption; either of the following:
                + NULL to use the PKCS&nbsp;\#8 \c PrivateKeyInfo.
                + Pointer to a private key that is shrouded accordance with
                PKCS&nbsp;\#8 (see Section 4.2.2, "The PKCS-8ShroundedKeyBag type,"
                in ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf).
    */
    const ubyte*                 pKeyPassword;         /* Password for Key encryption
                                                        * Option 1: if NULL then PKCS#8PrivateKeyInfo is used
                                                        * Option 2: if set then PKCS#8ShroudedKey is used.
                                                        */
    /**
    @brief      Length of the password (in bytes).
    @details    Length of the password (in bytes).
    */
    ubyte4                       keyPasswordLen;       /* Indicates the length of the password in bytes */
    /**
    @brief      Private key to publish in PKCS&nbsp;\#12.
    @details    Private key to publish in PKCS&nbsp;\#12.
    */
    AsymmetricKey*               pPrivateKey;          /* Private key that needs to be published in PKCS#12 */
    /**
    @brief      Type of certificate; any of the \c certTypes enum values from
                  pkcs12.h.
    @details    Type of certificate; any of the \c certTypes enum values from
                  pkcs12.h.
    */
    certTypes                    eCertType;            /* Type of certificate from certTypes enum */
    /**
    @brief      DER-encoded certificate file to publish in PKCS&nbsp;\#12.
    @details    DER-encoded certificate file to publish in PKCS&nbsp;\#12.
    */
    ubyte*                       pCertificate;         /* DER formatted certificate file to be published in PKCS#12 */
    /**
    @brief      Length of certificate file to publish, \p
                  PKCS12DataObject::pCertificate.
    @details    Length of certificate file to publish, \p
                  PKCS12DataObject::pCertificate.
    */
    ubyte4                       certificateLen;       /* Length of certificate file */
    /**
    @brief      Stream containing the %CRL to publish in PKCS&nbsp;\#12.
    @details    Stream containing the %CRL to publish in PKCS&nbsp;\#12.
    */
    ubyte*                       pCrl;                 /* Stream that hold the crl to be published in PKCS#12 */
    /**
    @brief      Length of the %CRL data object to publish, \p
                  KCS12DataObject::pCrl.
    @details    Length of the %CRL data object to publish, \p
                  KCS12DataObject::pCrl.
    */
    ubyte4                       crlLen;               /* Length of CRL format */
    /**
    @brief      NULL if no parameters required; otherwise pointer to
                  PKCS12AtttributeUserValue object instance(s).
    @details    NULL if no parameters required; otherwise pointer to
                  PKCS12AtttributeUserValue object instance(s).
    */
    PKCS12AttributeUserValue**   ppPKCS12AttrValue;    /* Stores 1 or more instances, if no parameters need to passed assign NULL / 0 */
    /**
    @brief      Number of PKCS12AtttributeUserValue instances in \p
                  ppPKCS12AttrValue.
    @details    Number of PKCS12AtttributeUserValue instances in \p
                  ppPKCS12AttrValue.
    */
    ubyte4                       numPKCS12AttrValue;   /* Indicates number of PKCS12AtttributeUserValue instance/s, 0 if none */
} PKCS12DataObject;

/*
 * PKCS12PrivacyModeConfig
 */
/**
@brief      Configuration information for PKCS&nbsp;12 privacy (encryption)
            operations.

@details    Configuration information for PKCS&nbsp;12 privacy (encryption)
            operations.

For password privacy, use the following members:
+ pPrivacyPassword
+ privacyPasswordLen
+ pkcs12EncryptionType

@note       If password integrity mode is enabled and the \p pPrivacyPassword
            member of the \c PKCS12PrivacyModeConfig structure is not set, the
            password entered for password integrity mode (by the \c
            pIntegrityPswd parameter within \c PKCS12_EncryptPFXPdu) is used.

For public key privacy, use the following members:
+ pEncryptionAlgoOID
+ ppCSDestPubKeyStream
+ numPubKeyStream
*/
typedef struct PKCS12PrivacyModeConfig
{
    /* Privacy Mode : Password */
    /**
    @brief      Password for the privacy (encryption) mode; if it is NULL/0, the
                password from Integrity password mode is used.

    @details    Password for the privacy (encryption) mode; if it is NULL/0, the
                password from Integrity password mode is used.
    */
    const ubyte*                   pPrivacyPassword;             /* Password for privacy mode, if its NULL/0 then password from Integrity password mode is used */
    /**
    @brief      Length, in bytes, of the password referenced by \p
                  pPrivacyPassword.
    @details    Length, in bytes, of the password referenced by \p
                  pPrivacyPassword.
    */
    ubyte4                         privacyPasswordLen;           /* Length of the password in bytes */
    /**
    @brief      For password privacy, encryption to apply; default = \c
                PCKS8_EncryptionType_pkcs12_sha_rc2_40.

    @details    (default = \ PCKS8_EncryptionType_pkcs12_sha_rc2_40) For
                password privacy, encryption to apply. Any of the following \c
                PKCS8EncryptionType enum values from pkcs_key.h:
                + \c PCKS8_EncryptionType_pkcs12_sha_2des
                + \c PCKS8_EncryptionType_pkcs12_sha_3des
                + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128
                + \c PCKS8_EncryptionType_pkcs12_sha_rc4_40
                + \c PCKS8_EncryptionType_pkcs12_sha_rc4_128
    */
    ubyte4                         pkcs12EncryptionType;
    /* Privacy Mode : Public Key */
    /**
    @brief      For public key privacy, encryption to apply.

    @details    For public key privacy, encryption to apply; any of the
                following preconfigured OID arrays from src/asn1/oiddefs.h:
                + \c desCBC_OID
                + \c desEDE3CBC_OID
                + \c aes128CBC_OID
                + \c aes192CBC_OID
                + \c aes256CBC_OID
    */
    const ubyte*                   pEncryptionAlgoOID;
    /**
    @brief      Pointer to array of CStream objects containing the public key(s).
    @details    Pointer to array of CStream objects containing the public key(s).
    */
    CStream**                      ppCSDestPubKeyStream;         /* public key stream/s*/
    /**
    @brief      Number of elements in the \p ppCSDestPubKeyStream CStream array.
    @details    Number of elements in the \p ppCSDestPubKeyStream CStream array.
    */
    ubyte4                         numPubKeyStream;              /* number of public key stream/s */
} PKCS12PrivacyModeConfig;

/* End of User configuration realted structures */

/*
 * when type is KEYINFO, content contains the DER encoded PKCS#8 PrivateKeyInfo;
 * when type is CERT, and extraInfo is X509, content contains the DER encoded X.509 certificate;
 * when type is CERT, and extraInfo is SDSI, content contains the BASE64 encoded SDSI certificate;
 * when type is CRL, and extraInfo is X509, content contains the DER encoded X.509 CRL.
*/

/**
@brief      Process and return the information extracted from a PFX PDU.

@details    This callback function processes the information extracted from a
            PFX PDU by a call to PKCS12_ExtractInfo(), and return the content
            and content type.

@ingroup    cb_cert_mgmt_pkcs12

@flags

@inc_file pkcs12.h

@param  type    Content type; any of the \c ContentTypes enum values from
                  pkcs12.h:
                   + <tt>KEYINFO</tt>&mdash;For content containig a DER-encoded
                      PKCS&nbsp;\#8 PrivateKeyInfo object or content containing
                      a private key that is shrouded in accordance with
                      PKCS&nbsp;\#8 (see Section 4.2.2, "The
                      PKCS-8ShroundedKeyBag type," in
                      ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf).
                      To obtain the contents for \c KEYINFO types, your callback
                      can decrypt the content by calling the
                      PKCS8_decodePrivateKeyDER() function.
                   + <tt>CERT</tt>&mdash;Typically your callback will write the
                      decrypted/extracted information to a file.
                   + <tt>CRL</tt>&mdash;Typically your callback will write the
                      decrypted/extracted information to a file.

@todo_eng_review (clarify how to decrypt info for \c CERT and \c CRL)

@param  extraInfo   Additional information, depending on the value of the \p
                      type parameter; any of the \c certTypes enum values defined in pkcs12.h, given the following restrictions:
                      + \p type = \c CERT:
                        + X509&mdash;For DER-encoded X.509 certificate content.
                        + SDSI&mdash;BASE64-encoded SDSI certificate content.
                      + \p type = CRL:
                        + X509&mdash;DER-encoded X.509 CRL content.

@param  content     Pointer to buffer containing data extracted from the PFX PDU.
                      Use the values of the \p type and \p extraInfo parameters
                      to determine the type of content in this buffer.
@param  contentLen  Lenght of content, \p content.

@return     \c OK (0) under all circumstances.

@callbackdoc    pkcs12.h
*/
typedef MSTATUS (*PKCS12_contentHandler)(const void* context, contentTypes type,
                                         ubyte4 extraInfo,
                                         const ubyte* content,
                                         ubyte4 contentLen);

/*------------------------------------------------------------------*/

/* these routines take a pointer to the root item of a parsed PKCS12
    message (by ASN1_Parse) */

/**
@brief      Extract and decrypt information from a PFX PDU, and submit the
            information to the given callback.

@details    This function extracts information from a PFX PDU, decrypts the
            information, and submits the information to the given callback.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param  pRootItem   Pointer to \c ASN1_ITEM for the root of the CStream,
                      \p s, that contains the PFX object from which to extract
                      information. To get this root item pointer, call
                      ASN1_Parse() for the CStream. For details about
                      setting up this CStream and getting the root, see
                      <em>Setting up a CStream and Getting the ASN1_ITEM for
                      the Root ASN.1 Object</em> in the pkcs7.dxd
                      documentation.
@param  s           Pointer to CStream that contains the PFX object, \p
                      pRootItem.
@param  uniPassword UNICODE password that protects the PFX PDU.
@param  uniPassLen  Length of the UNICODE password, \p uniPassword.
@param  callbackArg Pointer to arguments that are required by the function
                      referenced in \p pkcs7CBs.
@param  pkcs7CBs    Pointer to a PKCS7_Callbacks structure containing
                      callback functions to decrypt a PKCS&nbsp;\#12 file if
                      the contents of the PFX PDU are digitally signed with
                      a private signature key or if the contents are
                      encrypted with a trusted public key.
@param  handlerContext  TBD.
@param  handler     Pointer to callback function that conforms to the
                      prototype, PKCS12_contentHandler(). After
                      PKCS12_ExtractInfo() extracts the information from the
                      specified PFX object, it passes that information to this
                      \p handler parameter's callback function.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS PKCS12_ExtractInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                      ASN1_ITEM* pRootItem,
                                      CStream s,
                                      const ubyte* uniPassword,
                                      sbyte4 uniPassLen,
                                      void* pkcs7CBArg,
                                      PKCS7_Callbacks* pkcs7CBs,
                                      void* handlerContext,
                                      PKCS12_contentHandler handler);


/* NOTE for PKCS12_decrypt/PKCS12_encrypt: password argument can be unicode or not */

/**
@brief      Decrypt data according to a given algorithm, \p pAlgorithmIdentifier.

@details    This function decrypts data according to a given algorithm, \p
            pAlgorithmIdentifier.

@note       The PKCS12_ExtractInfo() function performs data decryption;
            therefore you do not need to call this decryption function for
            information that is extracted by the PKCS12_ExtractInfo() function.
            This function is a convenience function for data obtained other ways.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param  pEncryptedData  \c ASN1_ITEMPTR object referencing the data to decrypt.
@param  pAlgoIdentifier \c ASN1_ITEMPTR referencing the decryption algorithm.
@param  s               Pointer to CStream that contains the data referenced by
                          the ASN1_ITEMPTR objects, \p pEncryptedData and \p
                          pAlgoIdentifier.
@param  password        Password required to decrypt the data. The password is
                          not required to be in Unicode.
@param  passwordLen     Length of the password, \p password.
@param  decryptedInfo       On return, pointer to the address of a buffer
                              containing the decrypted data.
@param  decryptedInfoLen    On return, pointer to address containing the length
                              of the decrypted information, \p decryptedInfo.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS PKCS12_decrypt(MOC_SYM(hwAccelDescr hwAccelCtx)
               ASN1_ITEMPTR pEncryptedData,
               ASN1_ITEMPTR pAlgoIdentifier,
               CStream s, const ubyte* password,
               sbyte4 passwordLen,
               ubyte** decryptedInfo,
               sbyte4* decryptedInfoLen);

/**
@brief      Encrypt a buffer, typically a public key, according to the specified
            algorithm.

@details    This function encrypts the submitted plaintext according to the
            specified algorithm. Its main purpose is not bulk encryption but the
            generation of a PCKS&nbsp;\#12 public key from an input asymmetric
            key.

To create an encrypted PFX PDU, use PKCS12_EncryptPFXPdu(). This function
(PKCS12_encrypt), is provided as a convenience.

@ingroup    pkcs_functions

@inc_file pkcs12.h

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS12__

@param  pbeSubType  Encryption sub type; any of the following \c
                      PKCS8EncryptionType enum values from pkcs_key.h:
                      + \c PCKS8_EncryptionType_pkcs12_sha_2des
                      + \c PCKS8_EncryptionType_pkcs12_sha_3des
                      + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                      + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128
                      + \c PCKS8_EncryptionType_pkcs12_sha_rc4_40
                      + \c PCKS8_EncryptionType_pkcs12_sha_rc4_128
@param  password    Password required to encrypt the data. The password does
                          not need to be in UNICODE.
@param  passwordLen Length of the password, \p password.
@param  salt        Pointer to salt to use as input to the key generation. The
                      salt bits should be a random value generated by a
                      cryptographically strong pseudo-random number generator.
                      At a minimum, generate a salt value of at least eight
                      bits.
@param  saltLen     Length of the salt buffer, \p salt.
@param  iterCount   Number of iterations to apply in the key generation
                      algorithm. The more iterations, the heavier the
                      computational load, but the stronger the generated key. A
                      value of 2048 is recommended.
@param  plainText       On input, pointer to plaintext message to encrypt.\n
                          On return, pointer to encrypted ciphertext.
@param  plainTextLen    Length in bytes of plaintext message, \p plainText. On
                          return, the ciphertext will have the same length.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS PKCS12_encrypt(MOC_SYM(hwAccelDescr hwAccelCtx)
               ubyte pbeSubType,
               const ubyte* password, sbyte4 passwordLen,
               const ubyte* salt, sbyte4 saltLen, ubyte4 iterCount,
               ubyte* plainText, sbyte4 plainTextLen);

/**
@brief      Return function pointers for create, delete, and decrypt/encrypt
            operations for the specified PBE sub type.

@details    This funciton returns a \c BulkEncryptionAlgo structure containing
            the function pointers for create, delete, and decrypt/encrypt
            operations for the specified PBE sub type.

@note       If you call PKCS12_EncryptPFXPdu(), you do not need to call this
            convenience function.

@warning    If you directly access the ciphers that are accessible through this
            function, you take on the responsibility of managing IVs
            (initialization vectors). To ensure confidentiality, it is essential
            to correctly manage IVs.

The \c BulkEncryptionAlgo structure is defined in crypto.h as follows:
<pre>
    typedef struct BulkEncryptionAlgo
    {
        ubyte4                  blockSize;
        CreateBulkCtxFunc       createFunc;
        DeleteBulkCtxFunc       deleteFunc;
        CipherFunc              cipherFunc;
    } BulkEncryptionAlgo;
</pre>

For
The \c CreateBulkCtxFunc, \c DeleteBulkCtxFunc, and \c CipherFunc typedefs are
defined in crypto.h:
<pre>
    typedef BulkCtx (*CreateBulkCtxFunc)(MOC_SYM(hwAccelDescr hwAccelCtx)
             ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
    typedef MSTATUS (*DeleteBulkCtxFunc) (MOC_SYM(hwAccelDescr hwAccelCtx)
             BulkCtx *ctx);
    typedef MSTATUS (*CipherFunc)(MOC_SYM(hwAccelDescr hwAccelCtx)
             BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
</pre>

### Using \c CreateBulkCtxFunc typedef
The \c CreateBulkCtxFunc function creates an encryption/decryption context.  The
following parameters are required:
+ \c keyMaterial&mdash;Key appropriate to the underlying cipher.
  + 3DES in two-key mode: pass in key material that is a concatenation of two
    distinct DES keys (a total of 16 bytes for both keys).
  + 3DES in three-key mode: use a concatenation of three unique DES keys (24
    bytes for all three keys).
  + RC2: pass in an RC2 key of the appropriate length for the PBE sub type. The
    key length can be from one to 16 bytes (and is typically 16 bytes).
  + RC4: pass in a 16-byte key.
+ \c keylength&mdash;Length of the key material, \p keyMaterial.
+ \c encrypt&mdash;To encrypt data, specify \c TRUE; to decrypt data, specify \c
    FALSE. You cannot use the same encryption/decryption context for encryption
    and decryption.

### Using \c CipherFunc typedef
The \c CipherFunc function encrypts or decrypts a content buffer. The following
 parameters are required:
+ \c ctx&mdash;Context for the cipher, returned by the \c CreateBulkCtxFunc
    function.
+ \c data&mdash;On input, pointer to the address of the plaintext buffer to
    encrypt or the ciphertext buffer to decrypt. If the underlying cipher is a
    block cipher, this buffer must be an even multiple of the block size. If it
    is not, you must pad the data. \n\n On return, pointer to address of the
    resulting ciphertext or plaintext buffer.
+ \c dataLength&mdash;Length of plaintext/ciphertext buffer, \p data.
+ \c encrypt&mdash;To encrypt data, specify \c TRUE; to decrypt data, specify \c
    FALSE. The value must match the value that was specified in the
    CreateBulkCtxFunc call that created the context in \p ctx.
+ iv&mdash;Initialization vector appropriate to the cipher. For RC4 (a
    symmetric-key stream cipher), pass NULL because no initialization vector is
    required.

### Using DeleteBulkCtxFunc
After the data is encrypted/decrypted, call \c DeleteBulkCtxFunc to free the
 context (which was allocated by \c CreateBulkCtxFunc).

### Generating Initialization Vectors
All the block ciphers accessible through this function are implemented in CBC
mode. As input, a block cipher in CBC mode requires an initialization
vector, \c iv, which is generated externally from this API. that is you must
handle it within your application. This \c iv must be known by the message
recipient in order for it to decrypt the message. For the CBC mode, the \c
iv need not be secret, which simplifies the problem of getting the \c iv to
the recipient. However, the \c iv must be unpredictable for any particular
plaintext.

One method for producing an unpredictable \c iv is to apply the encryption
function (using the same key that is used to encrypt the data) to a nonce.
This nonce must be a data block that is unique for each buffer encrypted
under a given key. Useful sources of unique nonce values are counters (as
described in Appendix B of NIST Special Publication 800-38A, 2001 Edition)
or message numbers. Another commonly used method is to generate a random
data block using a FIPS-approved (and therefore cryptographically strong)
random number generator to use as the nonce.

For CBC mode, the \c iv should be unique for all messages encrypted under a
given key. For CBC mode, reusing an \c iv leaks information on the first
block of plaintext, and on any %common prefix shared by the two messages.

### Padding
For a block cipher in CBC mode, the input for encryption or decryption must
be an even multiple of the block size. In the Mocana SoT Platform
implementation of these modes, if the input data does not meet this
requirement, processing stops and the function returns an error. Therefore,
before submitting data to a Mocana SoT Platform API function that implements
these modes, be sure to check the size of the data and, if necessary, pad it
to an even multiple of the block size. You can use any padding method.
Typical schemes are:
+ RFC&nbsp;1321, step 3.1, describes a %common bit-oriented scheme.
+ RFC&nbsp;5652, section 6.3, describes a a byte-oriented padding scheme
+ Another byte-oriented scheme is provided in ANSI X.923.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param  pbeSubType  Encryption sub type for which you want a set of function
                      pointers; any of the following \c PKCS8EncryptionType enum
                      values from pkcs_key.h:
                      + \c PCKS8_EncryptionType_pkcs12_sha_2des
                      + \c PCKS8_EncryptionType_pkcs12_sha_3des
                      + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                      + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN const BulkEncryptionAlgo* PKCS12_GetEncryptionAlgo( ubyte pbeSubType);

/**
@brief      Create an encrypted PFX PDU.

@details    This function creates an encrypted PFX PDU.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
flags:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param  pRandomContext  Pointer to a \c randomContext structure, an opaque
                          structure containing information required to generate a
                          random number using the functions documented in \ref
                          random.dxd. To allocate this structure, call
                          RANDOM_acquireContext(). To release the memory for
                          such a structure, call RANDOM_releaseContext().
@param  integrityMode   Integrity mode; either of the following \c ePKCS12Mode
                          enum values from pkcs12.h:
                          + \c PKCS12Mode_Integrity_password&mdash;Use the
                            submitted password for authentication.
                          + \c PKCS12Mode_Integrity_pubKey&mdash;Use
                            certificates for authentication.
@param  pIntegrityPswd  If \p integrityMode is specified as \c
                          PKCS12Mode_Integrity_password, the secret password;
                          otherwise NULL.
@param  integrityPswdLen    If \p pIntegrityPswd is not NULL, length of the
                              secret password, \p pIntegrityPswd.
@param  pVsrcSigK       If \p integrityMode is specified as
                          \ PKCS12Mode_Integrity_pubKey, the source private
                          signature key; otherwise NULL.
@param  pDigestAlgoOID  If \p integrityMode is specified as
                          PKCS12Mode_Integrity_pubKey, the digest algorithm to use for the digital signature; any of the following preconfigured OID arrays from src/asn1/oiddefs.h:
                          + \c md5_OID
                          + \c sha1_OID
                          + \c sha1_OID
                          + \c sha224_OID
                          + \c sha256_OID
                          + \c sha384_OID
                          + \c sha512_OID
@param  csSignerCertificate     If \p integrityMode is specified as \c
                                PKCS12Mode_Integrity_pubKey, array containing
                                the signer certificate streams used to digitally
                                sign the PKCS&nbsp;\#12 PDU.
@param  numSignerCerts  If \p integrityMode is specified as \c
                          PKCS12Mode_Integrity_pubKey, number of signer
                          certificate streams in array, \p csSignerCertificate.
@param  pPkcs12PrivacyModeConfig    Pointer to structure containing the
                                      parameters required for the privacy mode.
@param  pkcs12DataObject    Pointer to array of \c PKCS12DataObject structures
                              that contain the data objects to put into the
                              PKCS&nbsp;\#12 PDU. Valid objects are
                              certificates, CRLs, and PKCS&nbsp;\#8 private keys.
@param  numPKCS12DataObj    Number of objects in the \c PKCS12DataObject array,
                              \p pkcs12DataObject.
@param  ppRetPkcs12CertDer      On return, pointer to address of resulting
                                  DER-encoded PKCS&nbsp;\#12 PDU.
@param  pRetPkcs12CertDerLen    On return, pointer to address of length of
                                  resulting PDU, \p ppRetPkcs12CertDer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS
PKCS12_EncryptPFXPdu(MOC_HW(hwAccelDescr hwAccelCtx)
                     randomContext* pRandomContext,
                     ubyte4 integrityMode,
                     /* Password Integrity Mode */
                     const ubyte* pIntegrityPswd,
                     ubyte4 integrityPswdLen,
                     /* Pub Key Integrity Mode */
                     AsymmetricKey* pVsrcSigK,
                     const ubyte* pDigestAlgoOID,
                     CStream csSignerCertificate[],
                     ubyte4  numSignerCerts,
                     /* PKCS Privacy Mode Configuration and Data */
                     const PKCS12PrivacyModeConfig *pPkcs12PrivacyModeConfig,
                     /* Data to be encrypted */
                     PKCS12DataObject pkcs12DataObject[/*numPKCS12DataObj*/],
                     ubyte4 numPKCS12DataObj,
                     /* return PKCS#12 certificate */
                     ubyte** ppRetPkcs12CertDer, ubyte4* pRetPkcs12CertDerLen);

/**
@brief      Decrypt a password integrity mode encrypted PFX PDU.

@details    Decrypt a password integrity mode encrypted PFX PDU. This function
            decrypts a PFX PDU generated from PKCS12_EncryptPFXPduPwMode. The
            certificate(s) and private key are extracted from the
            pkcs12 data.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
flags:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param pPkcs12Data      Buffer containing pkcs12 document in DER format.
@param pkcs12DataLen    Length of the pkcs12 document.
@param pEncPw           Encryption password used to protect the private key
                        stored in the pkcs12 document.
@param encPwLen         Length of the encryption password.
@param pPrivacyPswd     Privacy password used to encrypt the pkcs12 document.
@param privacyPswdLen   Length of the privacy password.
@param pIntegrityPswd   Integrity password used to generate the pkcs12 document
                        MAC.
@param integrityPswdLen Length of the integrity password.
@param ppCerts          Contents will be set to the certificates extracted from
                        the pkcs12 document. Must be freed by caller.
@param pCertCount       Contents will be set to the number of certificates
                        extracted.
@param ppKeyBlob        Contents will be set to the private key extracted from
                        the pkcs12 document. Must be freed by caller.
@param pKeyBlobLen      Contents will be set to the number of bytes allocated
                        in the key buffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS PKCS12_DecryptPFXPduPwMode(
    MOC_HW(hwAccelDescr hwAccelCtx)
    ubyte *pPkcs12Data,
    ubyte4 pkcs12DataLen,
    ubyte *pEncPw,
    ubyte4 encPwLen,
    ubyte *pPrivacyPswd,
    ubyte4 privacyPswdLen,
    ubyte *pIntegrityPswd,
    ubyte4 integrityPswdLen,
    SizedBuffer **ppCerts,
    ubyte4 *pCertCount,
    ubyte **ppKeyBlob,
    ubyte4 *pKeyBlobLen);

/**
@brief      Create a password integrity mode encrypted PFX PDU.

@details    Create a password integrity mode encrypted PFX PDU.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
flags:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param pRandomContext   (Optional) Pointer to a \c randomContext structure. If
                        NULL then the global default will be used.

@param pCerts           The target certificates to be pkcs12 encoded.      
@param certCount        The number of certificates in the \c pCerts buffers.
@param pKeyBlob         The serialized target key to be pkcs12 encoded.
@param keyBlobLen       The length of the serialized target key in bytes.
@param pCA              (Optional) A CA cert in DER form to be pkcs12 encoded.
@param caLen            The length of the CA cert in bytes. 
@param pEncPw           (Optional) The encryption password to be used for the key and certs.
@param encPwLen         The length of the encryption password in bytes.
@param pkcs12EncryptionType Any of the following \c PKCS8EncryptionType enum values from pkcs_key.h:
                            + \c PCKS8_EncryptionType_pkcs12_sha_2des
                            + \c PCKS8_EncryptionType_pkcs12_sha_3des
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc4_40
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc4_128
@param pPrivacyPswd         (Optional) The privacy password.
@param privacyPswdLen       The length of the privacy password in bytes.
@param pIntegrityPswd       (Optional) Buffer holding the secret password for the pkcs12 document.
@param integrityPswdLen     The length of the secret password in bytes.
@param ppRetPkcs12CertDer   Contents will be set to the location of the allocated buffer
                            holding the generated DER form pkcs12 document.
@param pRetPkcs12CertDerLen Contents will be set to the length of the allocated buffer in bytes.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS PKCS12_EncryptPFXPduPwMode(
    MOC_HW(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    SizedBuffer *pCerts,
    ubyte4 certCount,
    ubyte *pKeyBlob,
    ubyte4 keyBlobLen,
    ubyte *pCA,
    ubyte4 caLen,
    ubyte *pEncPw,
    ubyte4 encPwLen,
    ubyte4 pkcs12EncryptionType,
    ubyte *pPrivacyPswd,
    ubyte4 privacyPswdLen,
    ubyte *pIntegrityPswd,
    ubyte4 integrityPswdLen,
    ubyte **ppRetPkcs12CertDer, 
    ubyte4 *pRetPkcs12CertDerLen);


/**
@brief      Create a key integrity mode encrypted PFX PDU.

@details    Create a key integrity mode encrypted PFX PDU.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
flags:
+ \c \__ENABLE_MOCANA_PKCS12__

@inc_file pkcs12.h

@param pRandomContext   (Optional) Pointer to a \c randomContext structure. If
                        NULL then the global default will be used.

@param pCerts           The target certificates to be pkcs12 encoded.      
@param certCount        The number of certificates in the \c pCerts buffers.
@param pKeyBlob         The serialized target key to be pkcs12 encoded.
@param keyBlobLen       The length of the serialized target key in bytes.
@param pCA              (Optional) A CA cert in DER form to be pkcs12 encoded.
@param caLen            The length of the CA cert in bytes.
@param pEncPw           (Optional) The encryption password to be used for the key and certs.
@param encPwLen         The length of the encryption password in bytes.
@param pkcs12EncryptionType Any of the following \c PKCS8EncryptionType enum values from pkcs_key.h:
                            + \c PCKS8_EncryptionType_pkcs12_sha_2des
                            + \c PCKS8_EncryptionType_pkcs12_sha_3des
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc4_40
                            + \c PCKS8_EncryptionType_pkcs12_sha_rc4_128
@param pEncKeyCert      Certificate holding the public key used to encrypt each target.
@param encKeyCertLen    The length of the certificate in bytes.
@param pEncAlgoId           The public key encrption algorithm OID.
@param pIntegrityKeyblob    Serialized private key used to sign the generated pkcs12 document.
@param integrityKeyblobLen  The length of the serialized private key in bytes.
@param pIntegrityCert       The certificate associated with the signing private key.
@param integrityCertLen     The length of the certificate in bytes.
@param pDigestAlgoOID       The digest algorithm OID of that to be used in the signing process.
@param ppRetPkcs12CertDer   Contents will be set to the location of the allocated buffer
                            holding the generated DER form pkcs12 document.
@param pRetPkcs12CertDerLen Contents will be set to the length of the allocated buffer in bytes.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs12.h
*/
MOC_EXTERN MSTATUS PKCS12_EncryptPFXPduCertMode(
    MOC_HW(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    SizedBuffer *pCerts,
    ubyte4 certCount,
    ubyte *pKeyBlob,
    ubyte4 keyBlobLen,
    ubyte *pCA,
    ubyte4 caLen,
    ubyte *pEncPw,
    ubyte4 encPwLen,
    ubyte4 pkcs12EncryptionType,
    ubyte *pEncKeyCert,
    ubyte4 encKeyCertLen,
    const ubyte *pEncAlgoId,
    ubyte *pIntegrityKeyblob,
    ubyte4 integrityKeyblobLen,
    ubyte *pIntegrityCert,
    ubyte4 integrityCertLen,
    const ubyte *pDigestAlgoOID,
    ubyte **ppRetPkcs12CertDer, 
    ubyte4 *pRetPkcs12CertDerLen);

#endif /* __ENABLE_MOCANA_PKCS12__ */


#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __PKCS12_HEADER__ */
