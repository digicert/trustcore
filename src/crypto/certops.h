/*
 * certops.h
 *
 * Declarations and definitions for building and reading PKCS 10 cert requests
 * and X.509 certificates.
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

#include "../crypto/mocasym.h"
#include "../crypto/mocsym.h"
#include "../asn1/mocasn1.h"
#include "../common/datetime.h"

#ifndef __CERT_OPERATIONS_HEADER__
#define __CERT_OPERATIONS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

struct MCertOrRequestObject;
typedef struct MCertOrRequestObject *MRequestObj;
typedef struct MCertOrRequestObject *MCertObj;

/* The mocstore.h needs to include the certops.h file, and the certops.h
 * needs the MCertStore type.
 * So rather than have a circular reference, use this forward referencing. If it
 * is defined, don't define it again, but make sure it is defined in every file
 * it is used.
 */
#ifndef __MOC_STORE__
struct MocStoreObject;
typedef struct MocStoreObject *MocStore;
#define __MOC_STORE__
#endif

/* This is the signature of a NameType.
 * <p>A cert Name consists of a collection of attribute types and values. Some of
 * the Name types are country, locality, commonName, and emailAddress. In the new
 * Mocana Cert handling system, a Name type is really a function pointer that
 * knows how to encode and decode each type.
 * <p>Do not call a NameType directly, only use it in the NameType field of an
 * MCertNameElement struct or as an argument to a Get function.
 */
typedef MSTATUS (*MNameType) (
  ubyte4, ubyte *, ubyte4, void *
  );

/* Encode the name element as an RDN.
 * The info will be a pointer to an MSymOperatorData struct. The NameType will
 * encode itself, allocating memory using MOC_MALLOC to hold the encoding, and
 * set the pData field to that encoding and the length field to its length.
 * The caller must free the memory using MOC_FREE.
 */
#define MOC_NAME_OP_ENCODE_RDN    0x1002

/* Decode the RDN.
 * The info will be a pointer to an MGetAttributeData struct.
 * That struct contains the OID (full OID, the tag and length and value), the
 * encoded value, and a place to put the decoded value.
 * The pValue and valueLen will be NULL/0.
 */
#define MOC_NAME_OP_DECODE_RDN    0x1003

/* This is the signature of an AttrType.
 * <p>A cert request contains of a collection of attributes, each of which is an
 * attribute type and value. Some of the Attribute types are extensionRequest,
 * challengePassword. In the new Mocana Cert handling system, an Attribute type
 * is really a function pointer that knows how to encode and decode each
 * attribute.
 * <p>Do not call an AttrType directly, only use it in the AttrType field of an
 * MRequestAttribute struct or as an argument to a Get function.
 */
typedef MSTATUS (*MAttrType) (
  ubyte4, ubyte *, ubyte4, void *
  );

/* Encode the cert request attribute.
 * The info will be a pointer to an MSymOperatorData struct. The AttrType will
 * encode itself, allocating memory using MOC_MALLOC to hold the encoding, and
 * set the pData field to that encoding and the length field to its length.
 * The caller must free the memory using MOC_FREE.
 * <p>Note that the encoding of an Attribute is
 * <pre>
 * <code>
 *    SEQENCE {
 *      OID,
 *      SET OF {
 *        Any } }
 * </code>
 * </pre>
 */
#define MOC_REQ_ATTR_OP_ENCODE    0x2002

/* Decode the Attribute.
 * The info will be a pointer to an MGetAttributeData struct.
 * That struct contains the OID (full OID, the tag and length and value), the
 * encoded value, and a place to put the decoded value.
 * The pValue and valueLen will be NULL/0.
 */
#define MOC_REQ_ATTR_OP_DECODE    0x2003

/* This is the signature of an ExtensionType.
 * <p>A cert can contain a list of extensions. This is how such extensions are
 * represented in NanoCrypto.
 * <p>When building a cert, you supply an array of extensions. The code will
 * build that array of MExtensionTypes into the appropriate encoding structure.
 * <p>A cert request can contain extensions as well. They are collected in a
 * single attribute, the extensionRequest. When building a cert request, you can
 * supply a list of extensions, which the code will build into the appropriate
 * attribute containing all the extensions.
 * <p>An ExtensionType will know how to build itself using the data you provide.
 * <p>When verifying a cert, you can specify which extensions should also be
 * verified. Each ExtensionType will know how to verify itself, using the info
 * you provide.
 * <p>Do not call an ExtensionType directly, only use it in the ExtensionType
 * field of an MExtensionAttribute struct or as an argument to a Get function.
 */
typedef MSTATUS (*MExtensionType) (
  ubyte4 operation, ubyte *pValue, ubyte4 valueLen, void *pInfo
  );

/* Encode the extension.
 * The info will be a pointer to an MSymOperatorData struct. The ExtensionType
 * will encode itself, allocating memory using MOC_MALLOC to hold the encoding,
 * and set the pData field to that encoding and the length field to its length.
 * The caller must free the memory using MOC_FREE.
 */
#define MOC_EXTENSION_OP_ENCODE   0x3002

/* Decode the extension.
 * The info will be a pointer to an MGetAttributeData struct.
 * That struct contains the OID (full OID, the tag and length and value), the
 * encoded value, and a place to put the decoded value.
 * The pValue and valueLen will be NULL/0.
 * The decoder will need the criticality as well, so the caller must set the
 * criticality field as well.
 */
#define MOC_EXTENSION_OP_DECODE   0x3003

/* Is the given OID the OID for this Extension.
 * The pValue arg will be the OID to compare, the valueLen arg will be the
 * length. The OID passed in will be the full OID, TLV, not just the V.
 * The info will be a pointer to an intBoolean. If the given OID matches, set it
 * to TRUE, otherwise, set it to FALSE.
 */
#define MOC_EXTENSION_OP_IS_OID   0x3004

/* Does the extension verify?
 * The caller will pass this value as the operation, the value and length of the
 * actual value in the cert, and the info will be the data passed in from the
 * caller. The caller will pass in something that represents the expected value.
 * For example, with KeyUsage, the caller will pass a flag indicating what the
 * cert is being used for. The extension code itself will look at the flag passed
 * in and see if the KeyUsage bits in the extension value indicate that usage is
 * allowed.
 * <p>When this OP is used, the info passed in will be a pointer to an
 * MVerifyExtension struct.
 */
#define MOC_EXTENSION_OP_VERIFY   0x3005

/* Is this extension BasicConstraints?
 * The value and length will be NULL/0. The pInfo will be a pointer to
 * intBoolean. Set that boolean to TRUE if this is BasicConstraints, FALSE
 * otherwise.
 * We do this rather than have a general purpose Op code, so that code size can
 * be smaller.
 */
#define MOC_EXTENSION_OP_IS_BC    0x3010

/* Is this extension KeyUsage?
 * The value and length will be NULL/0. The pInfo will be a pointer to
 * intBoolean. Set that boolean to TRUE if this is KeyUsage, FALSE
 * otherwise.
 * We do this rather than have a general purpose Op code, so that code size can
 * be smaller.
 */
#define MOC_EXTENSION_OP_IS_KU    0x3020

/** This is the data to accompany MOC_EXTENSION_OP_VERIFY. The caller will pass
 * in the cert under consideration. The ExtensionType will set verifyFailures to
 * either 0 (no failures) or a set of bit values indicating what went wrong. See
 * mocasym.h for a list of MOC_ASYM_VFY_FAIL_ flags that are the bits.
 */
typedef struct
{
  MCertObj     pCert;
  intBoolean   verifyFailures;
} MVerifyExtension;

/* This is what to pass to an RDN, attribute, or extension when decoding.
 * Set the pOid to the full OID (TLV) and the length to the full length (the
 * length of the TLV, not the length of the V, which is the L).
 * The Type will decode the encodedValue, and set pDecodedValue to the decoding.
 * That might be just a pointer to a location inside the encodedValue, or it
 * might be allocated memory. If the Type allocated memory, it will set
 * isAllocated to TRUE and the caller must free pDecodedValue using MOC_FREE.
 * Check each RDN, attribute, and extension for the specific format of the value.
 * The criticality is used only by extensions. RDNs and attributes will ignore
 * that field.
 */
typedef struct
{
  struct MCertOrRequestObject  *pObj;
  ubyte                        *pOid;
  ubyte4                        oidLen;
  intBoolean                    criticality;
  ubyte                        *pEncodedValue;
  ubyte4                        encodedValueLen;
  ubyte                        *pDecodedValue;
  ubyte4                        decodedValueLen;
} MGetAttributeData;

/** A Name consists of a collection of name elements, each of which is an
 * attribute type and value. This struct is how to represent on such element.
 * <p>For each element of a Name, build an MCertNameElement. Set the NameType to
 * one of the MNameTypes defined, such as NameTypeCountry or
 * NameTypeEmailAddress. Set the pValue to point to the buffer containing the
 * UTF8 string containing the actual value, and valueLen to the length, in bytes,
 * of the value.
 * <p>Generally, you will know in advance how many Elements your application will
 * support, and you define an array for NameElements.
 * <pre>
 * <code>
 *   MCertNameElement pNameList[6] = {
 *     { NameTypeCountry, (ubyte *)"US", 2 },
 *     { NameTypeLocality, (ubyte *)"San Francisco", 13 },
 *        . . .
 *
 *   or
 *
 *   MCertNameElement pNameList[6];
 *
 *   // Set the array to values entered in by the user.
 *   pNameList[0].NameType = NameTypeCountry;
 *   pNameList[0].pValue = pCountry;
 *   pNameList[0].valueLen = countryLen;
 *        . . .
 * </code>
 * </pre>
 */
typedef struct
{
  MNameType      NameType;
  ubyte         *pValue;
  ubyte4         valueLen;
} MCertNameElement;

/** A PKCS 10 cert request contains a Name, a public key, and a collection of
 * attributes. This struct is how to represent a cert request attribute.
 * <p>For each Attribute in a cert request, build an MCertRequestAttribute. Set
 * the AttrType to one of the MRequestAttrs defined, such as
 * AttrTypeChallengePassword. Set the pValue to point to the buffer containing
 * the actual value, and valueLen to the length, in bytes, of the value. The
 * documentation for each RequestAttr will describe what the value should be.
 * <p>Generally, you will know in advance how many Attributes your application
 * will support, and you define an array for RequestAttributes.
 * <pre>
 * <code>
 *   MRequestAttribute pAttrList[6];
 *
 *   // Set the array to values entered in by the user.
 *   pAttrList[0].AttrType = RequestAttrChallengePassword;
 *   pAttrList[0].pValue = pPassword;
 *   pAttrList[0].valueLen = passwordLen;
 *
 *        . . .
 * </code>
 * </pre>
 */
typedef struct
{
  MAttrType      AttrType;
  ubyte         *pValue;
  ubyte4         valueLen;
} MRequestAttribute;

/** An X.509 cert contains a SEQUENCE OF extension. This struct is how to
 * represent an extension.
 * <p>PKCS 10 cert requests also contain extensions, but they are "wrapped" in an
 * Attribute.
 * <p>For each Extension, build an MCertExtension. Set the ExtensionType to one
 * of the MExtensionTypes defined, such as ExtensionTypeKeyUsage or
 * ExtensionTypeBasicConstraints. Set the pValue to point to the buffer
 * containing the actual value, and valueLen to the length, in bytes, of the
 * value. The documentation for each ExtensionType will describe what the value
 * should be. It is possible the value is not a simple byte array but must be
 * some other struct (and cast to ubyte *).
 * <p>Generally, you will know in advance how many Extensions your application
 * will support, and you define an array for Extensions.
 * <pre>
 * <code>
 *   MCertExtension pExtList[2];
 *   MBasicConstraintsInfo basicInfo;
 *
 *   basicInfo.isCritical = TRUE;
 *   basicInfo.isCa = TRUE;
 *   basicInfo.pathLen = 1;
 *   pExtList[0].AttrType = ExtensionTypeBasicConstraints;
 *   pExtList[0].pValue = (ubyte *)&basicInfo;
 *   pExtList[0].valueLen = 0;
 *
 *   keyUsage = MOC_KEY_USAGE_SIGN;
 *   pExtList[1].AttrType = ExtensionTypeKeyUsage;
 *   pExtList[1].pValue = (ubyte *)&keyUsage;
 *   pExtList[1].valueLen = 0;
 *        . . .
 * </code>
 * </pre>
 */
typedef struct
{
  MExtensionType   ExtensionType;
  ubyte           *pValue;
  ubyte4           valueLen;
} MCertExtension;

/** @brief Build a PKCS 10 certificate request.
 * @details The caller passes in a key pair, name information, an attribute
 * list, and an extension list. The function will use that information to build
 * and sign a PKCS 10 cert request.
 * <p>The keys must be MocAsymKeys, the function will test the keys
 * to make sure they are partners.
 * <p>The keys are defined to be a particular algorithm, so the signature
 * algorithm is tied to the key (e.g., an RSA key will sign using RSA and an EC
 * key will sign using ECDSA). However, the function needs to know more
 * information about the signing algorithm: the digest to use and if RSA, the
 * padding scheme to use. Hence, the caller can supply a flag describing the
 * digest algorithm, and another flag specifying the signature algorithm. If you
 * pass 0 for one or both of the flags, the function will use a default. The
 * defaults are based on key size.
 * <pre>
 * <code>
 *   RSA: PKCS 1 version 1.5 padding.
 *        1024-bit key: SHA-1
 *        2048-bit key: SHA-224
 *        3072-bit key: SHA-256
 *   DSA: 1024-bit key: SHA-1
 *        2048-bit key: SHA-224
 *        3072-bit key: SHA-256
 *    EC: 192-bit params: SHA-1
 *        224-bit params: SHA-224
 *        256-bit params: SHA-256
 *        384-bit params: SHA-384
 *        521-bit params: SHA-512
 * </code>
 * </pre>
 * <p>If you want to use a digest algorithm other than the default, set the
 * digestAlg arg to one of the ht_ values defined in crypto.h, such as ht_sha224.
 * If you use an algorithm other than RSA, the function will ignore the
 * sigDetails arg. But if the algorithm is RSA, then you can set that value to
 * either MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD or MOC_ASYM_KEY_ALG_RSA_PSS_PAD.
 * The default is P1_PAD so there's really no need to use that value. If you use
 * PSS, the digest algorithm used by PSS and the MGF will be the same digest
 * algorithm specified by the digestAlg arg (the saltLen will always be 20). If
 * you want to use a different combination of PSS params, contact Mocana and we
 * can revisit this function. However, the RFC on PSS recommends using the same
 * hash function. Hence, to avoid unnecessary complications (and PSS can get
 * outrageously, annoyingly, and unnecessarily complicated), this function
 * simplifies PSS.
 * <p>For example,
 * <pre>
 * <code>
 *    // If the key is RSA, use SHA-224 and PSS.
 *    // The PSS digest algorithm will also be SHA-224, the MGF digest algorithm
 *    // will be SHA-224, and the saltLen will be 20.
 *    digestAlg = ht_sha224;
 *    sigDetails = MOC_ASYM_KEY_ALG_RSA_PSS_PAD;
 *
 *    // If the key is RSA, set the sig to use the default digest and PSS
 *    // padding. If the key is not RSA, use the default digest alg and the
 *    // sigDetails is ignored. In this way, your app can specify that if the key
 *    // is RSA use PSS, but if the key is not RSA, it doesn't matter what you
 *    // wanted to happen with an RSA key.
 *    digestAlg = 0;
 *    sigDetails = MOC_ASYM_KEY_ALG_RSA_PSS_PAD;
 * </code>
 * </pre>
 * <p>If the signature algorithm is DSA, ECDSA, or RSA with PSS, then the
 * function will need a randomContext to generate random bytes. Pass in either
 * the global random (g_pRandomContext) or some other random object you built
 * (CRYPTO_createMocSymRandom in mocsym.h)
 * <p>The caller also passes in the MocCtx which contains arrays of
 * MSymOperatorAndInfo (see initmocana.h), representing the digest algorithms you
 * are willing to support.
 * <p>The name on the certificate request is represented as an Array
 * ofNameElements. See the documentation for MCertNameElement to learn more about
 * building such an array.
 * <p>A cert request contains at a minimum a public key and Name, but there are
 * optional Attributes as well. You can pass NULL/0 for theAttributeArray and
 * attributeCount, but if you do want to specify any attributes, build an array.
 * See the documentation for MRequestAttribute to learn more about building such
 * an array.
 * <p>One of the attributes is requested extensions. If you want to specify some
 * extensions you would like to see in the cert, pass in an array of
 * MCertExtension. You can pass NULL/0 for the ExtensionArray, extensionCount.
 * See the documentation for MCertExtension to learn more about building such an
 * array.
 * <p>Note that you can pass in NULL for the Attribute Array, but non-NULL for
 * the Extension Array. In that case, the function will build one Attribute, the
 * ExtensionRequest Attribute.
 * <p>The function will return the cert request in one of two formats: DER or
 * PEM. Set the format arg to one of the MOC_CERT_REQUEST_FORMAT_ values. If you
 * pass 0, the function will return the request in the default format, which is
 * DER.
 * <p>The function will allocate memory for the resulting request and return the
 * buffer created at the address given by ppRequest. It is the responsibility of
 * the caller to free that memory using MOC_FREE.
 *
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_MOCANA_ASYM_KEY__
 *  + \c \__ENABLE_MOCANA_SYM__
 *
 * @param pPubKey The public key that will be placed into the request.
 * @param pPriKey The private key that will be used to sign the request.
 * @param digestAlg If 0, the function will use the default, or else one of the
 * ht_ values defined in crypto.h.
 * @param sigDetails If 0, the function will use the default, or else one of the
 * MOC_ASYM_KEY_ALG_ values define int mocasym.h, such as
 * MOC_ASYM_KEY_ALG_RSA_PSS_PAD.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param pRandom A random object. This can be g_pRandomContext.
 * @param pNameArray An array of NameType and value structs containing the name
 * information that will be used in the request.
 * @param nameArrayCount The number of Name elements in the NameArray.
 * @param pAttributeArray An array of AttributeType and value structs containing
 * the attributes to go into the request.
 * @param attributeCount The number of Attributes in the AttrArray.
 * @param format The format of the request, either MOC_CERT_REQUEST_FORMAT_DER or
 * MOC_CERT_REQUEST_FORMAT_PEM.
 * @param ppRequest The address where the function will deposit a pointer to the
 * allocated buffer containing the request built from the given info.
 * @param pRequestLen The address where the function will deposit the length, in
 * bytes, of the request.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppRequest and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS PKCS10_buildCertRequestAlloc (
  MocAsymKey pPubKey,
  MocAsymKey pPriKey,
  ubyte4 digestAlg,
  ubyte4 sigDetails,
  MocCtx pMocCtx,
  randomContext *pRandom,
  MCertNameElement *pNameArray,
  ubyte4 nameArrayCount,
  MRequestAttribute *pAttributeArray,
  ubyte4 attributeCount,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte4 format,
  ubyte **ppRequest,
  ubyte4 *pRequestLen,
  struct vlong **ppVlongQueue
  );

/** Set the format arg in PKCS10_buildCertRequestAlloc to this value if you want
 * the request returned in DER format.
 */
#define MOC_CERT_REQUEST_FORMAT_DER  1
/** Set the format arg in PKCS10_buildCertRequestAlloc to this value if you want
 * the request returned in PEM format.
 */
#define MOC_CERT_REQUEST_FORMAT_PEM  2

/** Parse a cert request, verify the signature, and return an object that can be
 * used to extract specific information.
 * <p>This function will accept either the DER of a request, or the PEM version.
 * <p>The function will verify that the public key inside the request verifies
 * the signature on the request.
 * <p>The caller passes in the address of a ubyte4, the function will deposit the
 * verification failures at that address. If, upon return, the value is 0, there
 * were no verification failures and the signature verifies. Otherwise, the value
 * will be set to one or more bits describing why the verification failed. The
 * possible values of the verification failure are the MOC_ASYM_VFY_FAIL_
 * #defines (see mocasym.h). If the result is 0, there were no failures and the
 * signature verifies. If the result is nonzero, the signature did not verify.
 * You can then look at the bits to determine why. Of course, you can simply
 * compare to 0, if zero, no failures (signature verifies), or non-zero, there
 * was at least one failure (signature does not verify).
 * <p>You can think of this result as similar to "memcmp". When memcmp returns 0,
 * the values match. If it is non-zero, the values do not match.
 * <p>The function also returns an object that you can use to get information.
 * For example, once the request has been parsed, you can call functions such as
 * MGetNameRdn or MGetExtension. This will be how you get specific information
 * out of the request, such as a common name or challenge password attribute.
 * <p>The caller also supplies the MocCtx which contains lists of Operators the
 * application is willing to support. In order to verify the signature, the
 * function will read the AlgId of the digest and build a MocSymCtx using that
 * AlgId and the list of SymOperators in the MocCtx. It will also deserialize the
 * public key inside the request using the array of KeyOperators in the MocCtx.
 * Using the resulting MocAsymKey, the function can verify the signature. Your
 * lists will include those algorithms and implementations your application
 * supports. For example, if your application supports only ECC (the list of
 * KeyOperators includes only ECC Operators) and it encounters a DSA key and
 * signature, the function will not be able to verify and will return an error.
 * <p>There is a randomContext argument. It is likely that no algorithm used to
 * verify a cert will use a random object (some signing algorithms do need random
 * bytes), but the argument is there in case somewhere in the future some
 * verification function needs it.
 * <p>You must call PKCS10_freeRequestObject when done with the object.
 *
 * @param pRequest The cert request to parse, either DER or PEM.
 * @param requestLen The length, in bytes, of the request.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param pRandom An object that can generate random numbers. Likely it will not
 * be used.
 * @param pVerifyFailures A bit field indicating what went wrong in the
 * verification process. Upon return, if this is set to 0, there were no
 * failures. Otherwise it is set to one or more MOC_ASYM_VFY_FAIL_ bits.
 * @param ppRequestObj The address where the function will deposit an object that
 * can be used to extract information.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS PKCS10_parseCertRequest (
  ubyte *pRequest,
  ubyte4 requestLen,
  MocCtx pMocCtx,
  randomContext *pRandom,
  ubyte4 *pVerifyFailures,
  MRequestObj *ppRequestObj,
  struct vlong **ppVlongQueue
  );

/** Free a CertRequestObj created by a call to PKCS10_parseCertRequest.
 *
 * @param ppRequestObj The address where the function will find the object to
 * free. If the function successfully frees the object, it will deposit a NULL at
 * the address.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS PKCS10_freeRequestObject (
  MRequestObj *ppRequestObj,
  struct vlong **ppVlongQueue
  );

/** Build a new X.509 version 3 certificate from a certificate request.
 * <p>The caller will have parsed a cert request which builds a RequestObject.
 * This function will extract the SubjectName and PublicKey from the request. It
 * will also extract the requested extensions and place them into the cert. Note
 * that if you don't want to place certain requested extensions into the cert, or
 * if the contents of a requested extension is not to your liking, you reject the
 * request.
 * <p>A cert also contains the issuer's name, a serial number, validity dates,
 * and optionally an issuerUniqueId and subjectUniqueId.
 * <p>The caller provides the private key with which to sign the cert, along with
 * the digest algorithm and signature details.
 * <p>The key must be a MocAsymKey (pIssuerPriKey->type is akt_moc). See
 * mss/src/crypto/mocasym.h.
 * <p>The key is defined to be a particular algorithm, so the signature algorithm
 * is tied to the key (e.g., an RSA key will sign using RSA and an EC key will
 * sign using ECDSA). However, the function needs to know more information about
 * the signing algorithm: the digest to use and if RSA, the padding scheme to
 * use. Hence, the caller can supply a flag describing the digest algorithm, and
 * another flag specifying the signature algorithm. If you pass 0 for one or both
 * of these flags, the function will use a default. The defaults are based on key
 * size.
 * <pre>
 * <code>
 *   RSA: PKCS 1 version 1.5 padding.
 *        1024-bit key: SHA-1
 *        2048-bit key: SHA-224
 *        3072-bit key: SHA-256
 *   DSA: 1024-bit key: SHA-1
 *        2048-bit key: SHA-224
 *        3072-bit key: SHA-256
 *    EC: 192-bit params: SHA-1
 *        224-bit params: SHA-224
 *        256-bit params: SHA-256
 *        384-bit params: SHA-384
 *        521-bit params: SHA-512
 * </code>
 * </pre>
 * <p>If you want to use a digest algorithm other than the default, set the
 * digestAlg arg to one of the ht_ values defined in crypto.h, such as ht_sha224.
 * If you use an algorithm other than RSA, the function will ignore the
 * sigDetails arg. But if the algorithm is RSA, then you can set that value to
 * either MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD or MOC_ASYM_KEY_ALG_RSA_PSS_PAD.
 * The default is P1_PAD so there's really no need to use that value. If you use
 * PSS, the digest algorithm used by PSS and the MGF will be the same digest
 * algorithm specified by the digestAlg arg (the saltLen will always be 20). If
 * you want to use a different combination of PSS params, contact Mocana and we
 * can revisit this function. However, the RFC on PSS recommends using the same
 * hash function. Hence, to avoid unnecessary complications (and PSS can get
 * outrageously, annoyingly, and unnecessarily complicated), this function
 * simplifies PSS.
 * <p>For example,
 * <pre>
 * <code>
 *    // If the key is RSA, use SHA-224 and PSS.
 *    // The PSS digest algorithm will also be SHA-224, the MGF digest algorithm
 *    // will be SHA-224, and the saltLen will be 20.
 *    digestAlg = ht_sha224;
 *    sigDetails = MOC_ASYM_KEY_ALG_RSA_PSS_PAD;
 *
 *    // If the key is RSA, set the sig to use the default digest and PSS
 *    // padding. If the key is not RSA, use the default digest alg and the
 *    // sigDetails is ignored. In this way, your app can specify that if the key
 *    // is RSA use PSS, but if the key is not RSA, it doesn't matter what you
 *    // wanted to happen with an RSA key.
 *    digestAlg = 0;
 *    sigDetails = MOC_ASYM_KEY_ALG_RSA_PSS_PAD;
 * </code>
 * </pre>
 * <p>If the signature algorithm is DSA, ECDSA, or RSA with PSS, then the
 * function will need a randomContext to generate random bytes. Pass in either
 * the global random (g_pRandomContext) or some other random object you built
 * (CRYPTO_createMocSymRandom in mocsym.h)
 * <p>The caller also passes in the MocCtx which contains an array of
 * MSymOperatorAndInfo (see initmocana.h), representing the digest algorithms you
 * are willing to support.
 * <p>The issuer name in the certificate is representaed as an Array
 * ofNameElements. See the documentation for MCertNameElement to learn more about
 * building such an array.
 * <p>The serial number is a byte array, an integer in canonical format. This
 * number will always be considered positive. For example,
 * <pre>
 * <code>
 *    1       :  0x01
 *    390     :  0x01 86
 *    41,310  :  0xA1 5E
 *               This will be encoded as 02 03 00 A1 5E
 * </code>
 * </pre>
 * <p>The validity dates are represented as TimeDate structs. See
 * mss/src/common/mrtos.h for the definition.
 * <p>The subject unique ID and issuer unique ID are byte arrays. The function
 * treats them as binary data (in a cert they are unnamed BIT STRINGS). Generall
 * they are digests of keys or combinations of keys and serial numbers. One or
 * both of these values can be NULL.
 * <p>You can supply further extensions beyond the ones in the request. The
 * pExtensionArray can be NULL. But if you do supply extensions, and any of them
 * match the extension type in the request, the function will ignore the provided
 * extension and use the value from the request.
 * <p>The function will return the cert in one of two formats: DER or PEM. Set
 * the format arg to one of the MOC_CERT_FORMAT_ values. If you pass 0, the
 * function will return the request in the default format, which is DER.
 * <p>The function will allocate memory for the resulting request and return the
 * buffer created at the address given by ppRequest. It is the responsibility of
 * the caller to free that memory using MOC_FREE.
 *
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_MOCANA_ASYM_KEY__
 *  + \c \__ENABLE_MOCANA_SYM__
 *
 * @param pRequestObj The parsed cert request from which the cert will be built.
 * @param pIssuerPriKey The private key that will be used to sign the cert.
 * @param digestAlg If 0, the function will use the default, or else one of the
 * ht_ values defined in crypto.h.
 * @param sigDetails If 0, the function will use the default, or else one of the
 * MOC_ASYM_KEY_ALG_ values define int mocasym.h, such as
 * MOC_ASYM_KEY_ALG_RSA_PSS_PAD.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param pRandom A random object. This can be g_pRandomContext.
 * @param pIssuerNameArray An array of NameType and value structs containing the
 * name information that will be used as the IssuerName.
 * @param issuerNameArrayCount The number of Name elements in the NameArray.
 * @param pSerialNum The serial number as a positive canonical integer.
 * @param serialNumLen The length, in bytes, of the serial number.
 * @param pNotBefore A pointer to a TimeDate struct containing the start date and
 * time of the cert.
 * @param pNotAfter A pointer to a TimeDate struct containing the end data and
 * time of the cert.
 * @param pSubjUniqueId An application-defined unique identifier for the subject.
 * @param subjUniqueIdLen The length, in bytes, of the subject unique ID.
 * @param pIssuerUniqueId An application-defined unique identifier for the issuer.
 * @param issuerUniqueIdLen The length, in bytes, of the issuer unique ID.
 * @param pExtensionArray Any additional extensions to include in the cert beyond
 * the ones in the request.
 * @param extensionCount The number of additional extensions.
 * @param format The format of the request, either MOC_CERT_FORMAT_DER or
 * MOC_CERT_FORMAT_PEM.
 * @param ppCert The address where the function will deposit a pointer to the
 * allocated buffer containing the cert built from the given info.
 * @param pCertLen The address where the function will deposit the length, in
 * bytes, of the cert.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppRequest and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS X509_buildCertFromRequestAlloc (
  MRequestObj pRequestObj,
  MocAsymKey pIssuerPriKey,
  ubyte4 digestAlg,
  ubyte4 sigDetails,
  MocCtx pMocCtx,
  randomContext *pRandom,
  MCertNameElement *pIssuerNameArray,
  ubyte4 issuerNameArrayCount,
  ubyte *pSerialNum,
  ubyte4 serialNumLen,
  TimeDate *pNotBefore,
  TimeDate *pNotAfter,
  ubyte *pSubjUniqueId,
  ubyte4 subjUniqueIdLen,
  ubyte *pIssuerUniqueId,
  ubyte4 issuerUniqueIdLen,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte4 format,
  ubyte **ppCert,
  ubyte4 *pCertLen,
  struct vlong **ppVlongQueue
  );

/** Set the format arg in X509_buildCertFromRequestAlloc to this value if you want
 * the cert returned in DER format.
 */
#define MOC_CERT_FORMAT_DER  1
/** Set the format arg in X509_buildCertFromRequestAlloc to this value if you want
 * the cert returned in PEM format.
 */
#define MOC_CERT_FORMAT_PEM  2

/** Parse a cert and return an object that can be used to extract specific
 * information.
 * <p>This function will accept either the DER of a request, or the PEM version.
 * <p>Note that this does NOT verify. The parseCertRequest function does verify,
 * but that function has access to the public key. The purpose of this function
 * is to parse it and make it possible to get things out of it. Some of these
 * things are elements that can be used to find the issuer cert, such as
 * issuerName and issuerUniqueId. With the issuer cert, you can call the
 * X509_verifyCert function.
 * <p>Note also that to verify a cert you must verify more than just the
 * signature. For example, is the verification time within the validity dates? Or
 * does the KeyUsage extension include the current usage of the key? This
 * function does not verify those elements. This function parse the cert only.
 * <p>The function returns an object that you can use to get information.
 * For example, once the cert has been parsed, you can call functions such as
 * MGetNameRdn or MGetExtension. This will be how you get specific information
 * out of the request, such as a common name or issuerNameSerialNumber.
 * <p>You must call PKCS10_freeRequestObject when done with the object.
 *
 * @param pCert The cert to parse, either DER or PEM.
 * @param certLen The length, in bytes, of the cert.
 * @param ppCertObj The address where the function will deposit an object that
 * can be used to extract information.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS X509_parseCert (
  ubyte *pCert,
  ubyte4 certLen,
  MCertObj *ppCertObj
  );

/** Verify the signature, validity dates, and given extensions of a cert, then
 * verify certain elements of the cert's CA, and so on until reaching a trusted
 * cert. In other words, verify a chain.
 * <p>We are sorry this is a very complex function, but cert verification is an
 * extremely complicated procedure.
 * <p>NOTE! This function will verify the cert you supply using the extensions
 * you provide, but will verify the rest of the chain's extensions following a
 * function-defined method (described below). That is, you can specify how the
 * function will verify the extensions of the initial cert, but you cannot
 * specify how the function will verify the extensions of any cert up the chain.
 * If you want to control that process, you must find each of the certs in the
 * chain yourself and call X509_verifyCert for each of the CA/root certs.
 * <p>The caller supplies a cert to verify, along with a certStore containing CA
 * and root certs which the function will search to find certs needed to verify
 * the cert in question.
 * <p>Generally, you build a cert store by loading certs (or cert/key combos),
 * indicating at load time whether the cert is trusted or not. A trusted cert is
 * usually a root cert your app has already verified in some way. It is often
 * built into the software. But you can also determine that a cert is trusted if
 * it is a CA cert and you have already verified it as part of another
 * verification.
 * <p>In order to verify a cert, the function will have to build public key
 * objects and use these keys to verify cert signatures. The caller passes in the
 * MocCtx which contains an array of Key Operators which the function will use to
 * build keys. When the function finds a CA cert, it will extract the CA's public
 * key and build an object using that key and the array of Operators (see
 * CRYPTO_deserializeMocAsymKey).
 * <p>In order to verify the cert, the function will have to digest data. The
 * MocCtx also contains an array of SymOperators, the digest implementations the
 * app is willing to support. The function will get the digest algId out of a
 * cert and build an object from the algId and array of Operators (see
 * CRYPTO_createMocSymCtxFromAlgId).
 * <p>The function will also verify any extensions you supply. You build an array
 * of MCertExtension. This can be NULL if there are no extensions you want
 * verified. For each extension in the arry, the function will verify the cert is
 * valid. Generally you will supply the ExtensionType and the expected value. See
 * the documentation for each Extension for more info on what to pass in, and
 * what verification means. You supply the expected data for each extension for
 * the cert your function begins with (the actual cert you are passing to this
 * function). Note that some extensions are not something to be verified. For
 * example, AuthorityKeyIdentifier offers a good way to find a CA cert, but it is
 * nothing that can be verified.
 * <p>You must supply extensions you are willing to support, even if they are not
 * something that is verified, in order to check for criticality. The cert to
 * verify will contain a set of extensions. Some subset of those extensions will
 * be critical, meaning the reader must understand them or else the verification
 * fails. This function will make sure any critical extension in the cert can be
 * read by an MCertExtension provided. If there is an extension in the cert for
 * which there is no MCertExtension passed in, and that extension is critical,
 * this function will set the MOC_ASYM_VFY_FAIL_EXT_CRITICAL bit in the
 * VerifyFailues value.
 * <p>When the function verifies the chain, it will check to make sure any
 * critical extension is represented by an MCertExtension you pass in. It will
 * also check BasicConstraints and KeyUsage, if you pass in those extensions.
 * However, it will create its own expected values. That is, the expected values
 * you pass in will be used for the cert passed in, but for further certs, the
 * function will use its own expected values.
 * <p>You provide the time against which the function will compare the notBefore
 * and notAfter values. This might be the current time, but it is also possible
 * that you are verifying a cert attached to a message that was created two weeks
 * ago. You want to know if the cert was valid when the message was sent, not
 * necessarily if it is still valid.
 * <p>You also provide a cert store where the function will find CA and root
 * certs. You load up all the relevant certs into the cert store, then pass it
 * in. Note that you can load up certs as trusted or not. So certs you get from
 * the message (or SSL handshake, or wherever) will be loaded as untrusted (they
 * are to be verified themselves), and your trusted certs (root certs built into
 * the app, for example) are loaded as trusted. This function will look for CA
 * and root certs in the cert store, and will verify each until it reaces a
 * trusted cert. If the verification leads to an untrusted root cert (a root cert
 * is self signed), the function will set a verification failure bit indicating
 * the state.
 * <p>The random object will likely not be needed. It is there in case the public
 * key algorithm needs random bytes. Currently there are no algorithms that use
 * random bytes to verify, but the argument is there in case something comes
 * along and we need it. You can pass g_pRandomObject.
 * <p>Finally, you pass in the address of a ubyte4, the function will deposit the
 * verification failures at that address. If, upon return, the value is 0, there
 * were no verification failures and the cert verifies. Otherwise, the value
 * will be set to one or more bits describing why the verification failed. The
 * possible values of the verification failure are the MOC_ASYM_VFY_FAIL_
 * #defines. If the result is 0, there were no failures and the cert verifies. If
 * the result is nonzero, the signature did not verify. You can then look at the
 * bits to determine why. Of course, you can simply compare to 0, if zero, no
 * failures (cert verifies), or non-zero, there was at least one failure (cert
 * does not verify).
 * <p>You can think of this result as similar to "memcmp". When memcmp returns 0,
 * the values match. If it is non-zero, the values do not match.
 * <p>Remember, the return value is success or failure of the function, not the
 * signature itself. The return from the function (MSTATUS) can be OK and the
 * verifyFailures is non-zero. In that case, the function worked, it did what it
 * was supposed to do, determine if the cert verified, so it returns OK, but it
 * sets the result of that operation, does not verify.
 * <p>Note that this function does not check CRLs. For CRL operations, see
 * mss/src/crypto.crlops.h.
 *
 * @param pCertObj The first cert in the chain to verify.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param pVerifyTime The time against which the function will determine validity.
 * @param pExtensions A list of extensions (this can be NULL) that the function
 * will verify as well.
 * @param extCount The number of entries in the pExtensions array/
 * @param pCertStore WHere the function will get certs needed to verify the chain.
 * @param pRandom A random object. This can be g_pRandomContext.
 * @param pVerifyFailures A bit field indicating what went wrong in the
 * verification process. Upon return, if this is set to 0, there were no
 * failures. Otherwise it is set to one or more MOC_ASYM_VFY_FAIL_ bits.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS X509_verifyCertChain (
  MCertObj pCertObj,
  MocCtx pMocCtx,
  TimeDate *pVerifyTime,
  MCertExtension *pExtensions,
  ubyte4 extCount,
  MocStore pCertStore,
  randomContext *pRandom,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  );

/** Verify the signature, validity dates, and extensions of a certificate.
 * <p>Note that this will set an integer to the verification result. The return
 * value is an error code. The function can return OK (no error) even if a cert
 * does not verify. In that case, the function succeeded at its job, to determine
 * if the cert verifies or not. The result of that operation is returned in the
 * pVerifyFailures arg.
 * <p>We are sorry this is a very complex function, but cert verification is an
 * extremely complicated procedure.
 * <p>There are a number of reasons to reject a certificate, the signature and
 * validity dates are two of them. The other reasons are in the Extensions. For
 * example, if the BasicConstraints Extension is present and it indicates the
 * cert is not a CA cert, yet the public key was used to verify a certificate,
 * then you reject the cert.
 * <p>This function checks the signature and validity dates always. If you want
 * it to perform verification operations on some of the extensions, you will have
 * to supply an array of MCertExtension containing those extensions that you want
 * the function to verify, containing the data needed to verify. See the
 * documentation for each Extension for more info on what to pass in.
 * <p>Note that part of cert verification is chaining: verify the cert and verify
 * the cert that signed this cert, and so on, until reaching a root. This
 * function does not chain. To chain a cert, call X509_verifyCertChain. That
 * function will actually call this function to perform each of the chaining
 * verifications.
 * <p>The caller supplies the public key used to verify the signature.
 * Your app will likely get the public key from a certificate, either attached
 * to a message or returned from a database search. For example, to verify a
 * cert, you might parse it first, get the IssuerName or IssuerUniqueId out of
 * it (see MGetName and MGetUniqueId), and perform a search against the value.
 * You will then have the issuer's cert and can build a MocAsymKey object from
 * it (see MGetPublicKeyFromCert).
 * <p>In order to verify the cert, the function will need to digest the
 * TBSCertificate value. Which algorithm to use to digest is in the cert itself
 * (an algorithm identifier). The caller supplies the MocCtx which contains an
 * array of SymOperators the function will search to find an implementation that
 * can perform the digest requested. This is a list of algorithms your app is
 * willing to support.
 * <p>You provide the time against which the function will compare the notBefore
 * and notAfter values. This might be the current time, but it is also possible
 * that you are verifying a cert attached to a message that was created two weeks
 * ago. You want to know if the cert was valid when the message was sent, not
 * necessarily if it is still valid.
 * <p>The caller supplies an array of Extensions. The function will verify all
 * extensions in the cert against the Extensions passed in. There are some
 * extensions that are part of the verification process (e.g. BasicConstraints,
 * KeyUsage), and others that are there to just provide information
 * (e.g AuthorityKeyId). You might still want to supply in your list, the
 * extensions that are info only. The reason is criticality. An extension can be
 * critical or not. If it is critical, the verifier is expected to understand it
 * or else reject the cert. So pass in all the extensions you are willing to
 * support. This function will verify each one you pass in. If the cert does not
 * contain a particular extension, there is no error. If the cert does contain an
 * extension and it is critical (even if there is nothing to verify), and you
 * pass in the corresponding ExtensionType, that extension will verify, because
 * your app has demonstrated that it understands the critical extension.
 * <p>The random object will likely not be needed. It is there in case the public
 * key algorithm needs random bytes. Currently there are no algorithms that use
 * random bytes to verify, but the argument is there in case something comes
 * along and we need it. You can pass g_pRandomObject.
 * <p>The result of the verification is returned at the address given by
 * pVerifyFailures. The caller passes in the address of a ubyte4, the function
 * will deposit the verification failures at that address. If, upon return, the
 * value is 0, there were no verification failures and the signature verifies.
 * Otherwise, the value will be set to one or more bits describing why the
 * verification failed. The possible values of the verification failure are the
 * MOC_ASYM_VFY_FAIL_ #defines (see mss/src/crypto/mocasym.h). If the result is
 * 0, there were no failures and the cert verifies. If the result is nonzero, the
 * cert did not verify. You can then look at the bits to determine why. Of
 * course, you can simply compare to 0, if zero, no failures (cert verifies), or
 * non-zero, there was at least one failure (cert does not verify).
 * <p>You can think of this result as similar to "memcmp". When memcmp returns 0,
 * the values match. If it is non-zero, the values do not match.
 *
 * @param pCertObj The object containing the cert to verify.
 * @param pVerificationKey The public key that will be used to
 * verify the cert's signature.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param pVerifyTime The time against which the function will determine validity.
 * @param pExtensions A list of extensions (this can be NULL) that the function
 * will verify as well.
 * @param extCount The number of entries in the pExtensions array/
 * @param pRandom A random object. This can be g_pRandomContext.
 * @param pVerifyFailures A bit field indicating what went wrong in the
 * verification process. Upon return, if this is set to 0, there were no
 * failures. Otherwise it is set to one or more MOC_ASYM_VFY_FAIL_ bits.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS X509_verifyCert (
  MCertObj pCertObj,
  MocAsymKey pVerificationKey,
  MocCtx pMocCtx,
  TimeDate *pVerifyTime,
  MCertExtension *pExtensions,
  ubyte4 extCount,
  randomContext *pRandom,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  );

/** Free a CertObj created by a call to X509_parseCert.
 *
 * @param ppCertObj The address where the function will find the object to
 * free. If the function successfully frees the object, it will deposit a NULL at
 * the address.
 * @param ppVlongQueue Optional, a vlong pool.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS X509_freeCertObject (
  MCertObj *ppCertObj,
  struct vlong **ppVlongQueue
  );

#define MOC_PADDING_MASK            0x0C000000
#define MOC_DIGEST_MASK             0x00FF0000

/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the
 * signature algorithm is RSA and you want the padding to be PKCS 1 version 1.5.
 */
#define MOC_RSA_PADDING_PKCS_1_5    0x04000000
/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the
 * signature algorithm is RSA and you want the padding to be PSS (PKCS 1 version
 * 2.0).
 */
#define MOC_RSA_PADDING_PSS         0x08000000

/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the data to
 * be signed is to be digested using SHA-1.
 */
#define MOC_SIG_DIGEST_ALG_SHA1     0x00050000
/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the data to
 * be signed is to be digested using SHA-224
 */
#define MOC_SIG_DIGEST_ALG_SHA224   0x000E0000
/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the data to
 * be signed is to be digested using SHA-256.
 */
#define MOC_SIG_DIGEST_ALG_SHA256   0x000B0000
/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the data to
 * be signed is to be digested using SHA-384.
 */
#define MOC_SIG_DIGEST_ALG_SHA384   0x000C0000
/** OR this value into the supportAlgs argument to
 * PKCS10_buildCertRequestAlloc or X509_buildCertFromRequestAlloc if the data to
 * be signed is to be digested using SHA-512.
 */
#define MOC_SIG_DIGEST_ALG_SHA512   0x000D0000

/** Use this value as the whichName or whichId arg in funtions that return name
 * or uniqueId information, when the name or Id to examine is the IssuerName.
 * <p>This is only valid when looking at certs. There is only one name in a
 * request, the SubjectName. If you use this flag when looking at a request, the
 * function will return an error.
 */
#define MOC_ISSUER    1
/** Use this value as the whichName or whichId arg in funtions that return name
 * or uniqueId information, when the name or Id to examine is the SubjectName.
 * <p>You can use this flag when looking at a cert or request.
 */
#define MOC_SUBJECT   2

/** Extract the public key out of a cert or request object. This will return the
 * public key as the DER of SubjectPublicKeyInfo, or as a MocAsymKey, or both.
 * <p>After parsing a cert or request (PKCS10_parseCertRequest or
 * X509_parseCert), call this function to either get a key object or just the DER
 * of the key, or both.
 * <p>If you want the key returned as an object, pass in a pointer to a
 * MocAsymKey variable and the MocCtx (which contains all the algorithms and
 * implementations your application is willing to support). The reason for the
 * array is that your app might be willing to read, for example, RSA and ECC
 * certs, but you don't know in advance what algorithm key is in which cert, so
 * you provide a list of Operators that you're willing to support. The function
 * will match the key in the cert with the Operator and build a key object using
 * it.
 * <p>The function will build a new MocAsymKey, you must call
 * CRYPTO_freeMocAsymKey when you are done with it.
 * <p>If you pass in a MocAsymKey but the function cannot find a matching
 * Operator in the array, the function will return an error.
 * <p>If you pass NULL for pKeyObj, the function simply won't try to build a key
 * object. It will move on to returning the key data.
 * <p>If you want the actual key data (the DER of SubjectPublicKeyInfo), pass in
 * the address where the function can deposit a pointer to the key data. The
 * function will point to memory inside the object where the key is. That is, the
 * function does not allocate new memory, it does not copy the data but only
 * copies a reference. Do not free or alter the memory.
 * <p>If you pass NULL for ppSubjPubKey, the function will simply not return the
 * data. That is, it is not an error to pass a NULL for that arg.
 *
 * @param pObj The cert or request object.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppKeyObj The address where the function will deposit a new object
 * containing the key. If this is NULL, the function will simply not try to build
 * an object and move on to returning the key data.
 * @param ppSubjPubKey The address where the function will deposit a pointer to
 * the SubjectPublicKeyInfo, the DER of the public key in the cert or request.
 * @param pSubjPubKeyLen The address where the function will deposit the length,
 * in bytes, of the encoded key.
 * @param ppVlongQueue Optional, a vlong pool available to the operator if it
 * wants it.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetPublicKeyFromCertOrRequest (
  struct MCertOrRequestObject *pObj,
  MocCtx pMocCtx,
  MocAsymKey *ppKeyObj,
  ubyte **ppSubjPubKey,
  ubyte4 *pSubjPubKeyLen,
  struct vlong **ppVlongQueue
  );

/** Verify that a private key and cert match.
 * <p>This will determine if the public key in the cert is a match for the
 * private key given.
 * <p>The function will set *pIsMatch to TRUE if they match, or FALSE otherwise.
 *
 * @param pPriKey The key under consideration.
 * @param pCert The cert from which the key will be extracted.
 * @param pIsMatch The address where the function will deposit the result, TRUE
 * for a match, FALSE otherwise.
 * @param ppVlongQueue Optional, a vlong pool available to the operator if it
 * wants it.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS X509_validateKeyCertMatch (
  MocAsymKey pPriKey,
  MCertObj pCert,
  intBoolean *pIsMatch,
  vlong **ppVlongQueue
  );

/** Get a pointer to the data inside the object where a particular Name is. This
 * returns the full, unparsed Name, the DER of the Name. This is often useful
 * when finding certs by Name.
 * <p>The function returns a pointer to the location inside the object where the
 * value is. This function does not copy the data. Do not alter or free the value
 * returned.
 * <p>A cert contains an IssuerName and a SubjectName, so you must specify in
 * which Name you are interested. Do that with the whichName arg, either
 * MOC_ISSUER or MOC_SUBJECT. For a cert request, there is only one
 * Name, the subject name. You must pass in MOC_SUBJECT for the whichName
 * arg when examining a request, otherwise the function will return an error.
 *
 * @param pObj The cert or request object.
 * @param whichName Indicates whether the function should look at the SubjectName
 * or IssuerName.
 * @param ppNameDer The address where the function will deposit a pointer to
 * object-owned memory that contains the DER of the Name.
 * @param pNameDerLen The address where the function will deposit the length, in
 * bytes, of the NameDer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetName (
  struct MCertOrRequestObject *pObj,
  ubyte4 whichName,
  ubyte **ppNameDer,
  ubyte4 *pNameDerLen
  );

/** Return the IssuerAndSerialNumber.
 * <p>A cert is uniquely identified by the combination of IssuerName and
 * SerialNumber. PKCS #7 defines a construction of the two.
 * <pre>
 * <code>
 *   IssuerAndSerialNumber ::= SEQUENCE {
 *     issuer         Name,
 *     serialNumber   CertificateSerialNumber }
 * </code>
 * </pre>
 * <p>This is used to identify which cert was used during an operation, without
 * loading an entire cert into a message. Most applications will then search a
 * database of certs against this value (they will be able to search against many
 * values, such as Name and UniqueId, but this is one).
 * <p>This function returns a buffer containing the DER encoding of
 * IssuerAndSerialNumber. That buffer belongs to the cert object, do not alter or
 * free it.
 *
 * @param pCertObj The object containing the parsed cert.
 * @param ppIssuerSerial The address where the function will deposit a pointer to
 * a buffer containing the DER of IssuerAndSerialNumber.
 * @param pIssuerSerialLen The address where the function will deposit the
 * length, in bytes, of the Der encoding.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetIssuerSerial (
  MCertObj pCertObj,
  ubyte **ppIssuerSerial,
  ubyte4 *pIssuerSerialLen
  );

/** Get a pointer to the data inside the object where a particular UniqueId is.
 * This returns the ID bytes only, not the DER of the UniqueId (i.e., it returns
 * the V of TLV).
 * <p>The function returns a pointer to the location inside the object where the
 * value is. This function does not copy the data. Do not alter or free the value
 * returned.
 * <p>A cert can contain an IssuerUniqueId and a SubjectUniqueId, so you must
 * specify which ID you are interested. Do that with the whichId arg, either
 * MOC_ISSUER or MOC_SUBJECT.
 * <p>NOTE! A uniqueId is optional. Any particular cert might or might not have
 * one or either uniqueIds. If a cert does not have a unique Id, this function
 * will set *ppUniqueId to NULL and *pUniqueIdLen to 0.
 *
 * @param pCertObj The cert object.
 * @param whichId Indicates whether the function should return the
 * SubjectUniqueId or the IssuerUniqueId.
 * @param ppUniqueId The address where the function will deposit a pointer to
 * object-owned memory that contains the uniqueId.
 * @param pUniqueIdLen The address where the function will deposit the length, in
 * bytes, of the uniqueId.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetUniqueId (
  MCertObj pCertObj,
  ubyte4 whichId,
  ubyte **ppUniqueId,
  ubyte4 *pUniqueIdLen
  );

/** Get the NotBefore and NotAfter times of a cert.
 * <p>The caller passes in a cert object, the function will determine the
 * validity times in the object and set the two DateTime input variables to the
 * times.
 * <p>For example,
 * <pre>
 * <code>
 *   MCertObj pCertObj = NULL;
 *   DateTime notBefore, notAfter;
 *
 *   status = X509_parseCert (pCertData, certLen, &pCertObj);
 *
 *   status = MGetValidityDates (pCertObj, &notBefore, &notAfter);
 * </code>
 * </pre>
 *
 * @param pCertObj The cert object.
 * @param pNotBefore A pointer to a DateTime, which the function will set with
 * the notBefore time.
 * @param pNotAfter A pointer to a DateTime, which the function will set with
 * the notAfter time.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetValidityDates (
  MCertObj pCertObj,
  TimeDate *pNotBefore,
  TimeDate *pNotAfter
  );

/** Get a pointer to the data inside the object where the serial number is. This
 * returns the number bytes only, not the DER of the SerialNum (i.e., it returns
 * the V of TLV). It returns the number as a canonical integer.
 * For example,
 * <pre>
 * <code>
 *    1       :  0x01
 *    390     :  0x01 86
 *    41,310  :  0x00 A1 5E
 * </code>
 * </pre>
 * <p>The function returns a pointer to the location inside the object where the
 * value is. This function does not copy the data. Do not alter or free the value
 * returned.
 *
 * @param pCertObj The cert object.
 * @param ppSerialNum The address where the function will deposit a pointer to
 * object-owned memory that contains the serial number.
 * @param pSerialNumLen The address where the function will deposit the length, in
 * bytes, of the serial number.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetSerialNum (
  MCertObj pCertObj,
  ubyte **ppSerialNum,
  ubyte4 *pSerialNumLen
  );

/** Get the signature key's algorithm.
 * <p>This function looks at the signature algId of the cert or request, and
 * determines the key's algorithm. The return is one of the akt_ values (akt_rsa,
 * akt_dsa, akt_ecc). That is, the function does not return the actual algorithm
 * used to sign (such as RSA with SHA-256 and PSS, or ECC with SHA-224), but
 * rather the key's algorithm (RSA, DSA, ECC).
 * <p>This is generally used to match a key in one cert with the algorithm used
 * to sign in another cert.
 *
 * @param pObj The cert or request object.
 * @param pAlgorithm The address where the function will deposit the algorithm
 * flag, either akt_rsa, akt_dsa, or akt_ecc.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetSignatureKeyAlg (
  struct MCertOrRequestObject *pObj,
  ubyte4 *pAlgorithm
  );

/** Get the algorithm of the key inside a cert or request.
 * <p>This function looks at the key of the cert or request, and determines the
 * algorithm. The return is one of the akt_ values (akt_rsa, akt_dsa, akt_ecc).
 * <p>This is generally used to match a key in one cert with the algorithm used
 * to sign in another cert.
 *
 * @param pObj The cert or request object.
 * @param pAlgorithm The address where the function will deposit the algorithm
 * flag, either akt_rsa, akt_dsa, or akt_ecc.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetCertOrRequestKeyAlg (
  struct MCertOrRequestObject *pObj,
  ubyte4 *pAlgorithm
  );

/** Get a specific RDN out of a Cert or Request object.
 * <p>The caller passes in an MNameType. The function will examine the object to
 * see if that particular Name Type is represented in the cert or request.
 * <p>The function returns a pointer to the location inside the object where the
 * value is. This function does not copy the data. Do not alter or free the value
 * returned.
 * <p>For example,
 * <pre>
 * <code>
 *    ubyte4 commonNameLen;
 *    ubyte *pCommonName;
 *
 *    status = MGetNameRdn (
 *      (struct MCertOrRequestObject *)pRequestObj, NameTypeCommonName,
 *      &pCommonName, &commonNameLen);
 * </code>
 * </pre>
 * <p>A cert contains an IssuerName and a SubjectName, so you must specify in
 * which Name you are interested. Do that with the whichName arg, either
 * MOC_ISSUER or MOC_SUBJECT. For a cert request, there is only one
 * Name, the subject name. You must pass in MOC_SUBJECT for the whichName
 * arg when examining a request, otherwise the function will return an error.
 *
 * @param pObj The object to query. This is either an MRequestObj or an MCertObj.
 * @param whichName Indicates whether the function should look at the SubjectName
 * or IssuerName.
 * @param NameType The name element requested.
 * @param ppValue The address where the function will deposit a pointer to the
 * value of the name element. This is copy by reference, the function will not
 * allocate memory for the value, do not free it.
 * @param pValueLen The address where the function will deposit the length, in
 * bytes, of the value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetNameRdn (
  struct MCertOrRequestObject *pObj,
  ubyte4 whichName,
  MNameType NameType,
  ubyte **ppValue,
  ubyte4 *pValueLen
  );

/** How many RDNs make up the name in a cert or request?
 * <p>The caller passes in either an MRequestObj or MCertObj cast to
 * MCertOrRequestObject pointer. The function will determine how many RDNs make
 * up the name.
 * <p>The purpose of this is for a reader to determine if they have read all the
 * name elements, that there is not something in the name they have not checked.
 * <p>A cert contains an IssuerName and a SubjectName, so you must specify in
 * which Name you are interested. Do that with the whichName arg, either
 * MOC_ISSUER or MOC_SUBJECT. For a cert request, there is only one
 * Name, the subject name. You must pass in MOC_SUBJECT for the whichName
 * arg when examining a request, otherwise the function will return an error.
 *
 * @param pObj The cert or request object.
 * @param whichName Indicates whether the function should look at the SubjectName
 * or IssuerName.
 * @param pCount The address where the function will deposit the number of RDNs
 * in the name.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetNameRdnCount (
  struct MCertOrRequestObject *pObj,
  ubyte4 whichName,
  ubyte4 *pCount
  );

/** Get the RDN at the given index.
 * <p>In a cert or request there are Names which are made up of RDNs. You can get
 * the number of RDNs from a Name (by calling MGetNameRdnCount), then cycle
 * through them (start counting at index 0) to make sure you look at all.
 * <p>The purpose of this is to make sure you examine all RDNs. It is possible
 * you look at say 4 RDNs directly (see MGetNameRdn), but maybe a particular Name
 * has 5 RDNs. Using this function, you can verify that you have seen all RDNs.
 * <p>The caller supplies an array of MNameTypes. The function will look through
 * the array to find the appropriate NameType to read the RDN at the given index.
 * <p>If the function cannot find an MNameType in the array that matches an RDN
 * in the Name, it will return an error.
 * <p>If index is beyond the number of RDNs (e.g. if a Name has an RDN count of 5
 * and the caller passes in index 5, 6, or higher), the function will return an
 * error.
 * <p>A cert contains an IssuerName and a SubjectName, so you must specify in
 * which Name you are interested. Do that with the whichName arg, either
 * MOC_ISSUER or MOC_SUBJECT. For a cert request, there is only one
 * Name, the subject name. You must pass in MOC_SUBJECT for the whichName
 * arg when examining a request, otherwise the function will return an error.
 *
 * @param pObj The object to query. This is either an MRequestObj or an MCertObj.
 * @param whichName Indicates whether the function should look at the SubjectName
 * or IssuerName.
 * @param index The index in the Name of the RDN to examine.
 * @param pNameTypeArray An array of MNameTypes the function will use to find a
 * NameType that can parse the given RDN.
 * @param nameTypeCount The number of MNameTypes in the array.
 * @param pNameTypeIndex The address where the function will deposit the index
 * into the NameTypeArray of the NameType used to parse the RDN.
 * @param ppValue The address where the function will deposit a pointer to the
 * value of the name element. This is copy by reference, the function will not
 * allocate memory for the value, do not free it.
 * @param pValueLen The address where the function will deposit the length, in
 * bytes, of the value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetNameRdnByIndex (
  struct MCertOrRequestObject *pObj,
  ubyte4 whichName,
  ubyte4 index,
  MNameType *pNameTypeArray,
  ubyte4 nameTypeCount,
  ubyte4 *pNameTypeIndex,
  ubyte **ppValue,
  ubyte4 *pValueLen
  );

/** Get a specific Request Attribute out of a Request object.
 * <p>The caller passes in an MAttrType. The function will examine the object to
 * see if that particular Attribute Type is represented in the request.
 * <p>The function returns a pointer to the location inside the object where the
 * value is. Any memory allocated for this attribute belongs to the object, do
 * not alter or free the buffer.
 * <p>The attribute value is returned as a char * and length. That is, the value
 * is returned as a buffer. However, the value might be something else cast to
 * char *, see the documentation for each AttrType to determine what the actual
 * value is.
 * <p>For example,
 * <pre>
 * <code>
 *    ubyte4 challengePassLen;
 *    ubyte *pChallengePass
 *
 *    status = MGetRequestAttribute (
 *      pRequestObj, AttrTypeChallengePassword,
 *      &pChallengePass, &challengePassLen);
 * </code>
 * </pre>
 * <p>Note that there is no AttrType for requested extensions. To get a requested
 * extension out of a request object, call MGetExtension.
 *
 * @param pRequestObj The object to query.
 * @param AttrType The attribute requested.
 * @param ppValue The address where the function will deposit a pointer to the
 * value of the name element. This is copy by reference, the function will not
 * allocate memory for the value, do not free it.
 * @param pValueLen The address where the function will deposit the length, in
 * bytes, of the value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetRequestAttribute (
  MRequestObj pRequestObj,
  MAttrType AttrType,
  ubyte **ppValue,
  ubyte4 *pValueLen
  );

/** How many Attributes that are not extension requests are in a cert request?
 * <p>The caller passes in either an MRequestObj, the function will determine how
 * many attributes are in the object. It will only count those attributes that
 * are not the attribute extension requests.
 * <p>There are many request attributes defined, such as challengePassword or
 * emailAddress. There is also one called extensionRequest. This attribute
 * contains a number of X.509 Extensions the requestor wants to be part of the
 * resulting cert. That is, one attribute contains multiple extension.
 * <p>This function will count those attributes that are not extensionRequest. To
 * determine how many extensions are in the request (actually, how many
 * extensions are in the extensionRequest attribute), call MGetExtensionCount.
 * <p>The purpose of this is for a reader to determine if they have read all the
 * attributes, that there is not something in the request they have not checked.
 * <p>For example, suppose a request contains 2 attributes: challenge password
 * and extensionRequest. This function will return one, because there is only one
 * non-extensionRequest attribute.
 *
 * @param pRequestObj The cert or request object.
 * @param pCount The address where the function will deposit the number of RDNs
 * in the name.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetRequestAttributeCount (
  MRequestObj pRequestObj,
  ubyte4 *pCount
  );

/** Get the attribute at the given index. This will only look at Attributes that
 * are not extensionRequest.
 * <p>In a request there are Attributes. You can get the number of attributes
 * from a request (by calling MGetRequestAttributeCount), then cycle through them
 * (start counting at index 0) to make sure you look at all.
 * <p>The purpose of this is to make sure you examine all Attributes. It is
 * possible you look at say 4 Attributes directly (see MGetRequestAttribute), but
 * maybe a particular Request has 5 Attributes. Using this function, you can
 * verify that you have seen all Attributes.
 * <p>The caller supplies an array of MAttrTypes. The function will look through
 * the array to find the appropriate AttrType to read the Attribute at the given
 * index.
 * <p>The attribute value is returned as a char * and length. That is, the value
 * is returned as a buffer. However, the value might be something else cast to
 * char *, see the documentation for each AttrType to determine what the actual
 * value is.
 * <p>If the function cannot find an MAttrType in the array that matches an
 * Attribute in the Request, it will return an error.
 * <p>If index is beyond the number of Attributes (e.g. if a Request has an
 * Attribute count of 5 and the caller passes in index 5, 6, or higher), the
 * function will return an error.
 * <p>Note that there is no AttrType for requested extensions. To get a requested
 * extension out of a request object, call MGetExtension or MGetExtensionByIndex.
 *
 * @param pRequestObj The object to query.
 * @param index The index in the Request of the Attribute to examine.
 * @param pAttrTypeArray An array of MAttrTypes the function will use to find a
 * AttrType that can parse the given attribute.
 * @param attrTypeCount The number of MAttrTypes in the array.
 * @param pAttrTypeIndex The address where the function will deposit the index
 * into the AttrTypeArray of the AttrType used to parse the RDN.
 * @param ppValue The address where the function will deposit a pointer to the
 * value of the attribute. This is copy by reference, the function will not
 * allocate memory for the value, do not free it.
 * @param pValueLen The address where the function will deposit the length, in
 * bytes, of the value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetRequestAttributeByIndex (
  MRequestObj pRequestObj,
  ubyte4 index,
  MAttrType *pAttrTypeArray,
  ubyte4 attrTypeCount,
  ubyte4 *pAttrTypeIndex,
  ubyte **ppValue,
  ubyte4 *pValueLen
  );

/** Get a specific Extension out of a Cert or Request object.
 * <p>If getting an extension out of a request, this is really getting the
 * extension out of the Attribute extensionRequest. That request attribute
 * contains a list of exensions the requestor wants in the resulting cert.
 * <p>The caller passes in an MExtensionType. The function will examine the
 * object to see if that particular Extension Type is represented in the cert or
 * request.
 * <p>The function returns a pointer to the location inside the object where the
 * value is. This function does not copy the data. Do not alter or free the value
 * returned.
 * <p>The extension value is returned as a char * and length. That is, the value
 * is returned as a buffer. However, the value might be something else cast to
 * char *, see the documentation for each ExtensionType to determine what the
 * actual value is.
 * <p>For example,
 * <pre>
 * <code>
 *    ubyte4 keyUsageLen;
 *    MKeyUsageInfo pGetKeyUsageInfo
 *
 *    status = MGetExtension (
 *      (struct MCertOrRequestObject *)pRequestObj, ExtensionTypeKeyUsage,
 *      (ubyte **)&pGetKeyUsageInfo, &keyUsageLen);
 * </code>
 * </pre>
 * <p>If there is no extension, the function sets the return value to NULL and
 * returns OK.
 *
 * @param pObj The object to query. This is either an MRequestObj or an MCertObj.
 * @param ExtensionType The extension requested.
 * @param ppValue The address where the function will deposit a pointer to the
 * value of the extension. This is copy by reference, the function will not
 * allocate memory for the value, do not free it.
 * @param pValueLen The address where the function will deposit the length, in
 * bytes, of the value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetExtension (
  struct MCertOrRequestObject *pObj,
  MExtensionType ExtensionType,
  ubyte **ppValue,
  ubyte4 *pValueLen
  );

/** How many extensions are in a cert or request?
 * <p>If getting an extension  count out of a request, this is really getting the
 * count of extensions in the Attribute extensionRequest. That request attribute
 * contains a list of exensions the requestor wants in the resulting cert.
 * <p>The caller passes in either an MRequestObj or MCertObj cast to
 * MCertOrRequestObject pointer. The function will determine how many exensions
 * are in the object.
 * <p>The purpose of this is for a reader to determine if they have read all the
 * extensions, that there is not something in the object they have not checked.
 *
 * @param pObj The cert or request object.
 * @param pCount The address where the function will deposit the number of
 * exensions in the object.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetExtensionCount (
  struct MCertOrRequestObject *pObj,
  ubyte4 *pCount
  );

/** Get the extension at the given index.
 * <p>In a cert or request there are extensions (in a request they are located in
 * the extensionRequest attribute). You can get the number of extensions from an
 * object (by calling MGetExtensionCount), then cycle through them (start
 * counting at index 0) to make sure you look at all.
 * <p>The purpose of this is to make sure you examine all extensions. It is
 * possible you look at say 4 extensions directly (see MGetExtension), but maybe
 * a particular object has 5 extensions. Using this function, you can verify that
 * you have seen all extensions.
 * <p>The extension value is returned as a char * and length. That is, the value
 * is returned as a buffer. However, the value might be something else cast to
 * char *, see the documentation for each ExtensionType to determine what the
 * actual value is.
 * <p>The caller supplies an array of MExtensionTypes. The function will look
 * through the array to find the appropriate ExtensionType to read the extension
 * at the given index.
 * <p>The function will return the index into the ExtensionType array, of which
 * ExtensionType read the extension. Note that this arg is a pointer to a signed
 * integer. That is so the return value can be -1 if the function cannot find a
 * matching ExtensionType.
 * <p>If the function cannot find an MExtensionType in the array that matches an
 * extension in the object, it will return OK and set value and valueLen to
 * NULL/0, and the extTypeIndex to -1. This means the cert contains an extension
 * that your app does not recognize.
 * <p>Whether the function finds a matching ExtensionType or not, it will return
 * a boolean to indicate whether the extension is critical or not. If the
 * extension in the cert is encoded as critical, the function will set
 * *pIsCritical to TRUE. If the extention is critical and there is no
 * ExtensionType, then you can say your app is looking at a cert with a critical
 * extension it does not understand.
 * <p>If index is beyond the number of extensions (e.g. if an object has an
 * extension count of 5 and the caller passes in index 5, 6, or higher), the
 * function will return an error.
 *
 * @param pObj The object to query. This is either an MRequestObj or an MCertObj.
 * @param index The index in the object of the extension to examine.
 * @param pExtTypeArray An array of MExtensionTypes the function will use to find
 * an ExtensionType that can parse the given extension.
 * @param extTypeCount The number of MExtensionTypes in the array.
 * @param pExtTypeIndex The address where the function will deposit the index
 * into the Extension Array of the MExtensionType used to parse.
 * @param pIsCritical The address where the function will deposit a boolean, is
 * the extension critical? This is indicating whether the extension in the cert
 * is declared critical.
 * @param ppValue The address where the function will deposit a pointer to the
 * value of the name element. This is copy by reference, the function will not
 * allocate memory for the value, do not free it.
 * @param pValueLen The address where the function will deposit the length, in
 * bytes, of the value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetExtensionByIndex (
  struct MCertOrRequestObject *pObj,
  ubyte4 index,
  MExtensionType *pExtTypeArray,
  ubyte4 extTypeCount,
  sbyte4 *pExtTypeIndex,
  intBoolean *pIsCritical,
  ubyte **ppValue,
  ubyte4 *pValueLen
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the CommonName (id-at-commonName).
 */
MOC_EXTERN MSTATUS NameTypeCommonName (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the CountryName (id-at-countryName).
 */
MOC_EXTERN MSTATUS NameTypeCountry (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the StateOrPrivinceName
 * (id-at-stateOrProvinceName).
 */
MOC_EXTERN MSTATUS NameTypeStateOrProvince (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the LocalityName (id-at-localityName).
 */
MOC_EXTERN MSTATUS NameTypeLocality (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the OrganizationName (id-at-organizationName).
 */
MOC_EXTERN MSTATUS NameTypeOrganization (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the OrganizationalUnitName
 * (id-at-organizationalUnitName).
 */
MOC_EXTERN MSTATUS NameTypeOrganizationalUnit (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MNameType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * NameType field of a MCertNameElement struct.
 * <p>This is the NameType to use for the EmailAddressName
 * (pkcs9-at-emailAddress).
 */
MOC_EXTERN MSTATUS NameTypeEmailAddress (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MAttrType
 * <p>Although this is a function, do not call it directly. Only use it in the
 * AttrType field of a MCertRequestAttribute struct.
 * <p>This is the AttrType to use for ChallengePassword
 * (pkcs-9-at-challengePassword).
 * <p>The value is data and length and must be a UTF8String.
 */
MOC_EXTERN MSTATUS AttrTypeChallengePassword (
  ubyte4, ubyte *, ubyte4, void *
  );

/** Implements MExtensionType.
 * <p>Although this is a function, do not call it directly. Only use it in the
 * ExtensionType field of a MCertExtension struct or as an arg to a Get function.
 * <p>This is the ExtensionType to use to add BasicConstraints to a cert request
 * attribute (pkcs-9-at-extensionRequest) or a cert. It is also used when
 * verifying a cert.
 * <p>When building, the data to accompany this Extension in an MCertExtension
 * struct is a pValue that is a pointer to an MBasicConstraintsInfo struct
 * containing criticality, whether it is a CA, and if a CA, the pathLen
 * constraint. The valueLen is 0.
 * <p>If the isCa field is FALSE, the pathLen is meaningless.
 * <p>For example,
 * <pre>
 * <code>
 *   MBasicConstraintsInfo basicInfo;
 *   MCertExtension bcAttr;
 *
 *   basicInfo.isCritical = TRUE;
 *   basicInfo.isCa = TRUE;
 *   basicInfo.pathLen = 1;
 *   bcAttr.AttrType = ExtensionTypeBasicConstraints;
 *   bcAttr.pValue = (ubyte *)&basicInfo;
 *   bcAttr.valueLen = 0;
 * </code>
 * </pre>
 * <p>When verifying, the accompanying data is the same. You are setting the
 * struct to what you expect to find. If you set isCritical to TRUE, the
 * verification will fail if the cert being verified does not contain the
 * extension. If FALSE, the verification will verify the extension if there, but
 * if it is not, the verification will ignore BasicConstraints. If isCA is FALSE,
 * the verification will make sure the cert is not signing another cert. If it is
 * TRUE, specify the path length. If this is a CA cert veriifying a leaf cert,
 * the pathLen is 1. For example,
 * <pre>
 * <code>
 *   MBasicConstraintsInfo basicInfo;
 *
 *   // We're verifying a cert. This cert is being used as a CA cert that is
 *   // verifying another CA cert that is verifying the leaf cert. So the pathLen
 *   // is 2.
 *   // The verification will expect the cert to contain this extension
 *   // (isCritical is TRUE), expect the isCa to be TRUE and a pathLen of 2 or
 *   // more.
 *   basicInfo.isCritical = TRUE;
 *   basicInfo.isCa = TRUE;
 *   basicInfo.pathLen = 2;
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS ExtensionTypeBasicConstraints (
  ubyte4, ubyte *, ubyte4, void *
  );

/** This is the data to accompany ExtensionTypeBasicConstraints.
 * <p>If the extension is to be critical, make sure isCritical is set to TRUE.
 * Otherwise, make sure it is set to FALSE.
 * <p>If the extension is for a CA cert, make sure isCa is set to TRUE. If it is
 * a leaf cert, set it to FALSE.
 * <p>If isCa is TRUE, set pathLen to the path length constraint. This is the
 * number of intermediate certs allowed. For example, if the CA is allowed to
 * sign only leaf certs (not other CA certs), then the pathLen is 0. If the CAL
 * is allowed to sign other CA certs, but those CAs are allowed to sign only leaf
 * certs, then the pathLen is 1 (at most 1 cert between the CA and leaf).
 * <p>NanoCrypto assumes that the pathLen will be less than 127.
 */
typedef struct
{
  intBoolean    isCritical;
  intBoolean    isCa;
  ubyte4        pathLen;
} MBasicConstraintsInfo;

/** Implements MExtensionType
 * <p>Although this is a function, do not call it directly. Only use it in the
 * ExtensionType field of a MCertExtension struct.
 * <p>This is the ExtensionType to use to add KeyUsage to a cert request
 * attribute (pkcs-9-at-extensionRequest) or a cert. It is also used when
 * verifying a cert.
 * <p>When building, the data to accompany this Extension in a MCertExtension
 * struct is a pValue that is a pointer to an MKeyUsageInfo struct containing
 * criticality and the OR of the KeyUsage bits. The valueLen is 0. The values of
 * the key usage bits are the values defined MOC_KEY_USAGE_, such as
 * MOC_KEY_USAGE_DIGITAL_SIGNATURE.
 * <p>For example,
 * <pre>
 * <code>
 *   MKeyUsageInfo keyUsageInfo;
 *   MCertExtension kuAttr;
 *
 *   keyUsageInfo.isCritical = TRUE;
 *   keyUsageInfo.keyUsageBits =
 *     MOC_KEY_USAGE_KEY_CERT_SIGN | MOC_KEY_USAGE_CRL_SIGN;
 *   bcAttr.AttrType = ExtensionTypeKeyUsage;
 *   bcAttr.pValue = (ubyte *)&keyUsageInfo;
 *   bcAttr.valueLen = 0;
 * </code>
 * </pre>
 * <p>When verifying, the accompanying data is the same. You are setting the
 * struct to what you expect to find. If you set isCritical to TRUE, the
 * verification will fail if the cert being verified does not contain the
 * extension. If FALSE, the verification will verify the extension if there, but
 * if it is not, the verification will ignore KeyUsage. Set the keyIsageBits
 * field to what the key is being used for at the time of verification. The
 * verification will make sure that the extension in the cert has at least the
 * bit set you provide. For example,
 * <pre>
 * <code>
 *   MKeyUsageInfo keyUsageInfo;
 *
 *   // We're verifying a cert. This cert is being used to sign another cert. So
 *   // set the keyUsageBits to KEY_CERT_SIGN. The actual extension in the cert
 *   // might contain more bits, but we want to check that it has at least this
 *   // one.
 *   // The verification will expect the cert to contain this extension
 *   keyUsageInfo.isCritical = TRUE;
 *   keyUsageInfo.keyUsageBits = MOC_KEY_USAGE_KEY_CERT_SIGN;
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS ExtensionTypeKeyUsage (
  ubyte4, ubyte *, ubyte4, void *
  );

/** This is the data to accompany ExtensionTypeKeyUsage.
 * <p>If the extension is to be critical, make sure isCritical is set to TRUE.
 * Otherwise, make sure it is set to FALSE.
 * <p>The keyUsageBits field is the OR of all the flags that define what the key
 * can be used for. Valid values are the MOC_KEY_USAGE_ values. For example, to
 * set the key usage to be cert sign and CRL sign, set keyUsageBits to be
 * MOC_KEY_USAGE_KEY_CERT_SIGN | MOC_KEY_USAGE_CRL_SIGN.
 */
typedef struct
{
  intBoolean    isCritical;
  ubyte4        keyUsageBits;
} MKeyUsageInfo;

#define MOC_KEY_USAGE_DIGITAL_SIGNATURE    0x0080
#define MOC_KEY_USAGE_NON_REPUDIATION      0x0100
#define MOC_KEY_USAGE_KEY_ENCIPHERMENT     0x0200
#define MOC_KEY_USAGE_DATA_ENCIPHERMENT    0x0400
#define MOC_KEY_USAGE_KEY_AGREEMENT        0x0800
#define MOC_KEY_USAGE_KEY_CERT_SIGN        0x1000
#define MOC_KEY_USAGE_CRL_SIGN             0x2000
#define MOC_KEY_USAGE_ENCIPHER_ONLY        0x4000
#define MOC_KEY_USAGE_DECIPHER_ONLY        0x8000

/** Implements MExtensionType
 * <p>Although this is a function, do not call it directly. Only use it in the
 * ExtensionType field of a MCertExtension struct.
 * <p>This is the ExtensionType to use to add Certificate Name Template to a cert
 * request attribute or a cert. It is also used when verifying a cert.
 * <p>When building, the data to accompany this Extension in a MCertExtension
 * struct is a pValue that is a pointer to an MTemplateNameInfo struct containing
 * the criticality, specified template name, and template name length. The value
 * for this extension is a wide character string, it is up to the caller to
 * supply the data in that format. The template name value specified by
 * Microsoft for this extension is "DomainController", it is highly recommended
 * to use this value.
 * <p>For example,
 * <pre>
 * <code>
 *   MTemplateNameInfo templateNameInfo;
 *   MCertExtension tnAttr;
 *   ubyte templateValue[32] = {
 *     0x00, 0x44, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6E,
 *     0x00, 0x43, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x72, 0x00, 0x6F,
 *     0x00, 0x6C, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x72
 *   };
 *
 *   templateNameInfo.isCritical = TRUE;
 *   templateNameInfo.pValue = (ubyte *)templateValue;
 *   templateNameInfo.valueLen = 16;
 *   tnAttr.AttrType = ExtensionTypeTemplateName;
 *   tnAttr.pValue = (ubyte *)&templateNameInfo;
 *   tnAttr.valueLen = 0;
 * </code>
 * </pre>
 * <p>When verifying, the accompanying data is the same. You are setting the
 * struct to what you expect to find. If you set isCritical to TRUE, the
 * verification will fail if the cert being verified does not contain the
 * extension. If FALSE, the verification will verify the extension if there, but
 * if it is not, the verification will ignore TemplateName. Set the pValue
 * field to the specified certificate template name and the valueLen field to
 * the length of the specified certificate template name.  For example,
 * <pre>
 * <code>
 *   MTemplateNameInfo templateNameInfo;
 *
 *   // The verification will expect the cert to contain this extension
 *   templateNameInfo.isCritical = TRUE;
 *   templateNameInfo.pValue = (ubyte *)templateValue;
 *   templateNameInfo.valueLen = 16;
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS ExtensionTypeTemplateName (
  ubyte4, ubyte *, ubyte4, void *
  );

/** This is the data to accompany ExtensionTypeTemplateName.
 * <p>If the extension is to be critical, make sure isCritical is set to TRUE.
 * Otherwise, make sure it is set to FALSE.
 * <p>The pValue field is the specified certificate template name. The valueLen
 * field is the length of the specified certificate template name.
 */
typedef struct
{
  intBoolean  isCritical;
  ubyte      *pValue;
  ubyte4      valueLen;
} MTemplateNameInfo;

/** Implements MExtensionType
 * <p>Although this is a function, do not call it directly. Only use it in the
 * ExtensionType field of a MCertExtension struct.
 * <p>This is the ExtensionType to use to add AuthorityKeyIdentifier to a cert
 * request attribute (id-ce-authorityKeyIdentifier) or a cert. It is also used
 * when verifying a cert.
 * <p>When building, the data to accompany this Extension in a MCertExtension
 * struct is a pValue that is a pointer to an MAuthKeyIdInfo struct containing
 * the KeyIdentifier, encoded AuthorityCertIssuer, and AuthorityCertSerialNumber.
 * The struct value for the AuthorityCertIssuer is the DER encoding of a
 * GeneralName choice. The struct also contains a flag to indicate which choice
 * was made. It is up to the caller to produce that encoding and its associated
 * flag.
 * <p>For example,
 * <pre>
 * <code>
 *   MAuthKeyIdInfo authKeyIdInfo;
 *   MCertExtension akiAttr;
 *
 *   ubyte *pEncodedInfo = NULL;
 *   ubyte encodedInfoLen = 0;
 *   ubyte pSerial[5] = { 0x12, 0x34, 0x56, 0x78, 0x90 };
 *   ubyte *pKeyId = "somekeyid";
 *   MCertNameElement pNameArray[4] = {
 *     { NameTypeCountry, (ubyte *)"US", 2 },
 *     { NameTypeStateOrProvince, (ubyte *)"California", 10 },
 *     { NameTypeLocality, (ubyte *)"San Francisco", 13 },
 *     { NameTypeCommonName, (ubyte *)"FakeName", 8 }
 *   };
 *
 *   // Get the DER encoding of a Name
 *   status = MBuildNameDerAlloc (
 *     pNameArray, 4, &pEncodedInfo, &encodedInfoLen);
 *   if (OK != status)
 *     goto exit;
 *
 *   authKeyIdInfo.pKeyId = pKeyId;
 *   authKeyIdInfo.keyIdLen = 9;
 *   authKeyIdInfo.pAuthCertSerialNum = (ubyte *)pSerial;
 *   authKeyIdInfo.authCertSerialNumLen = 5;
 *   authKeyIdInfo.pAuthCertIssuerEncoding = pEncodedInfo;
 *   authKeyIdInfo.authCertIssuerEncodingLen = encodedInfoLen;
 *   authKeyIdInfo.authCertIssuerGeneralNameChoice = GENERAL_NAME_DIRECTORY;
 *
 *   akiAttr.AttrType = ExtensionTypeAuthKeyId;
 *   akiAttr.pValue = (ubyte *)&authKeyIdInfo;
 *   akiAttr.valueLen = 0;
 * </code>
 * </pre>
 * <p>This extension will always verify.
 *
 */
MOC_EXTERN MSTATUS ExtensionTypeAuthKeyId (
  ubyte4, ubyte *, ubyte4, void *
  );

/** This is the data to accompany ExtensionTypeAuthKeyId.
 * <p>This extension is always non-critical.
 * <p>The pKeyId field is a pointer to the buffer containing the KeyIdentifier.
 * The keyIdLen field is the length, in bytes, of that buffer.
 * <p>The pAuthCertIssuerEncoding field is a pointer to the buffer containing
 * the DER encoding of a GeneralName choice.  The authCertIssuerEncodingLen
 * field is the length, in bytes, of that buffer.
 * <p>The authCertIssuerGeneralNameChoice is a flag to indicate the GeneralName
 * choice, it must be one of the GENERAL_NAME_* flags.
 * <p>The pAuthCertSerialNum field is a pointer to the buffer containg the
 * canonical integer value for the AuthorityCertSerialNumber. The
 * authCertSerialNumLen field is the length, in bytes, of that buffer.
 */
typedef struct
{
  ubyte *pKeyId;
  ubyte4 keyIdLen;
  ubyte *pAuthCertIssuerEncoding;
  ubyte4 authCertIssuerEncodingLen;
  ubyte4 authCertIssuerGeneralNameChoice;
  ubyte *pAuthCertSerialNum;
  ubyte4 authCertSerialNumLen;
} MAuthKeyIdInfo;

/* Flags to indicate general name */
#define GENERAL_NAME_OTHER         0
#define GENERAL_NAME_RFC822        1
#define GENERAL_NAME_DNS           2
#define GENERAL_NAME_X400_ADDR     3
#define GENERAL_NAME_DIRECTORY     4
#define GENERAL_NAME_EDI_PARTY     5
#define GENERAL_NAME_URI           6
#define GENERAL_NAME_IP_ADDR       7
#define GENERAL_NAME_REGISTERED_ID 8

/** Implements MExtensionType
 * <p>Although this is a function, do not call it directly. Only use it in the
 * ExtensionType field of a MCertExtension struct.
 * <p>This is the ExtensionType to use to add Subject Key Identifier to a cert
 * request attribute or a cert. It is also used when verifying a cert.
 * <p>When building, the data to accompany this Extension in a MCertExtension
 * struct is a pValue that is a pointer to an MSubjectKeyIdInfo struct containing
 * the keyIdentifier and its length.
 * <p>For example,
 * <pre>
 * <code>
 *   MSubjectKeyIdInfo subjectKeyIdInfo;
 *   MCertExtension skaAttr;
 *
 *   subjectKeyIdInfo.pValue = "SomeSubjectKeyId";
 *   subjectKeyIdInfo.valueLen = 16;
 *   skaAttr.AttrType = ExtensionTypeSubjectKeyId;
 *   skaAttr.pValue = (ubyte *)&subjectKeyIdInfo;
 *   skaAttr.valueLen = 0;
 * </code>
 * </pre>
 * <p>This extension will always verify.
 */
MOC_EXTERN MSTATUS ExtensionTypeSubjectKeyId (
  ubyte4, ubyte *, ubyte4, void *
  );

/** This is the data to accompany ExtensionTypeAuthKeyId.
 * <p>This extension is always non-critical.
 * <p>The pValue field is the value for the Subject Key Identifier, the valueLen
 * field is the length in bytes.
 */
typedef struct
{
  ubyte *pValue;
  ubyte4 valueLen;
} MSubjectKeyIdInfo;

/** Build the DER of a Name using the array of MCertNameElement.
 * <pre>
 * <code>
 * A Name is an RDNSequence
 *    SEQUENCE OF {
 *      RelativeDistinguishedName }
 *
 * A RelativeDistinguishedName (RDN) is
 *    SET OF {
 *      AttributeTypeAndValue }
 *
 * An AttributeTypeAndValue is
 *    SEQUENCE {
 *      type,
 *      value }
 * </code>
 * </pre>
 * <p>To build the name, the function will build an RDN for each element in the
 * array. Although an RDN is a SET OF, and can have more than one Attribute,
 * common practice has only one Attribute for each RDN.
 * <p>This function will allocate memory for the result, it is the responsibility
 * of the caller to free it using MOC_FREE.
 *
 * @param pNameArray An array of NameType and value structs containing the name
 * information that will be used to build the Name.
 * @param nameArrayCount The number of Name elements in the NameArray.
 * @param ppNameDer The address where the function will deposit a pointer to
 * allocated memory containing the resulting DER encoding of the Name.
 * @param pNameDerLen The address where the function will deposit the length, in
 * bytes, of the DER of the Name.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppNameDer and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS MBuildNameDerAlloc (
  MCertNameElement *pNameArray,
  ubyte4 nameArrayCount,
  ubyte **ppNameDer,
  ubyte4 *pNameDerLen
  );

/** Encode an array of Attribute elements into Attributes for a PKCS 10 cert
 * request.
 * <pre>
 * <code>
 * Attributes is
 *    SET OF {
 *      Attribute }
 *
 * An Attribute is
 *    SEQUENCE {
 *      type,
 *      value }
 * </code>
 * </pre>
 * <p>To build the Attributes, the function will call on each AttrType to build
 * itself and put it together as a SET OF. One attribute is the ExtensionRequest,
 * which is a collection of extensions from attributes. In the API, you specify
 * each of the requested extensions separately, but the function will combine
 * them into a single attribute. For example, you can include in your list of
 * ExtensionTypes ExtensionTypeBasicConstraints and ExtensionTypeKeyUsage. They
 * will be two elements in the array of ExtensionTypes. However, the function
 * will combine them into one attribute: extensionRequest.
 * <p>If there are no attributes, this function will set *ppEncoding to NULL and
 * *pEncodingLen to 0.
 * <p>This function will allocate memory for the result, it is the responsibility
 * of the caller to free it using MOC_FREE.
 *
 * @param pAttrArray An array of AttrType and value structs containing the
 * attribute information.
 * @param attrArrayCount The number of Attribute elements in the AttrArray.
 * @param pExtensionArray An array of extensions that will be combined into the
 * ExtensionRequest attribute.
 * @param extensionCount The number of extensions in the array.
 * @param ppEncoding The address where the function will deposit a pointer to
 * allocated memory containing the resulting DER encoding of the Attributes.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the DER of the Attributes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppNameDer and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS MBuildAttributesAlloc (
  MRequestAttribute *pAttrArray,
  ubyte4 attrArrayCount,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Build the extensionRequest cert request Attribute.
 * <p>One Attribute for a P10 request is extensionRequest. This attribute is
 * actually a collection of extensions that the requestor wants to be part of the
 * cert. The Mocana API treats each extension for a cert request as an individual
 * AttrType. So this function will find all the AttrTypes in the pAttrArray that
 * are extensions, and put them into a single attribute.
 * <p>This function will allocate memory for the result, it is the responsibility
 * of the caller to free it using MOC_FREE.
 *
 * @param pExtArray An array of ExtensionType and value structs containing the
 * extension information.
 * @param extArrayCount The number of Extension elements in the ExtensionArray.
 * @param ppEncoding The address where the function will deposit a pointer to
 * allocated memory containing the resulting DER encoding of the Attribute.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the DER of the Attribute.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppNameDer and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS MBuildExtensionRequestAlloc (
  MCertExtension *pExtArray,
  ubyte4 extArrayCount,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Encode a simple RDN.
 * <p>Many RDNs are very similar, so use this helper routine.
 * <p>An RDN is
 * <pre>
 * <code>
 *   SET OF {
 *     SEQUENCE {
 *       OID,
 *       ANY } }
 * </code>
 * </pre>
 * <p>For many, the ANY is just a String (such as UTF8String or PrintableString).
 * <p>This function will build the RDN, using the OID given and setting the ANY
 * as simply the TYPE and value given, as long as the TYPE is an atomic type
 * (such as a String or INTEGER or OCTET STRING, but not SEQUENCE or SET). That
 * is, the caller passes in the type, which must be one of the MASN1_TYPE_ values
 * specified in mocasn1.h (e.g. MASN1_TYPE_UTF8_STRING). The function will build
 * the SET OF.
 * <p>The ANY for this function is the type and value as a single "atomic" unit.
 * That is, the TLV is made up of the type (the T) and value (the V) given. The
 * function will compute the length (L), but the value is fully formed. The
 * purpose of this function is really for strings, but of course, if a caller has
 * a compound value and has it encoded already, the type can be ENCODED.
 * <p>The OID is the value of the OID only (no tag and len).
 * <p>The function allocates memory for the result and returns it at the address
 * given by ppEncoding. It is the responsibility of the caller to free it.
 *
 * @param pOid The OID of the RDN.
 * @param oidLen The length, in bytes, of the OID.
 * @param type The MASN1_TYPE_ of the value.
 * @param pValue The value to encode.
 * @param valueLen The length, in bytes, of the value.
 * @param ppEncoding The address where the function will deposit the allocated
 * buffer containing the result.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the result.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MEncodeSimpleRdnAlloc (
  ubyte *pOid,
  ubyte4 oidLen,
  ubyte4 type,
  ubyte *pValue,
  ubyte4 valueLen,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Encode an attribute.
 * <p>Many attributes ar very similar, so use this helper routine.
 * <p>An Attribute is
 * <pre>
 * <code>
 *     SEQUENCE {
 *       OID,
 *       SET OF {
 *         ANY } }
 * </code>
 * </pre>
 * <p>This function will build the attribute, using the OID given and setting the
 * ANY as simply the TYPE and value given. That is, the caller passes in the
 * type, which must be one of the MASN1_TYPE_ values specified in mocasn1.h (e.g.
 * MASN1_TYPE_UTF8_STRING). The function will build the SEQUENCE.
 * <p>The ANY for this function is the type and value as a single "atomic" unit.
 * That is, the TLV is made up of the type (the T) and value (the V) given. The
 * function will compute the length (L), but the value is fully formed. The
 * purpose of this function is really for strings, but of course, if a caller has
 * a compound value and has it encoded already, the type can be ENCODED.
 * <p>The OID is the value of the OID only (no tag and len).
 * <p>The function allocates memory for the result and returns it at the address
 * given by ppEncoding. It is the responsibility of the caller to free it.
 *
 * @param pOid The OID of the attribute.
 * @param oidLen The length, in bytes, of the OID.
 * @param type The MASN1_TYPE_ of the value.
 * @param pValue The value to encode.
 * @param valueLen The length, in bytes, of the value.
 * @param ppEncoding The address where the function will deposit the allocated
 * buffer containing the result.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the result.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MEncodeSimpleAttrAlloc (
  ubyte *pOid,
  ubyte4 oidLen,
  ubyte4 type,
  ubyte *pValue,
  ubyte4 valueLen,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Create the encoding of an Extension.
 * <p>An extension is
 * <pre>
 * <code>
 *   SEQUENCE {
 *     extId     OID,
 *     critical  BOOLEAN DEFAULT FALSE,
 *     value     OCTET STRING }
 * </code>
 * </pre>
 * <p>The OCTET STRING wraps the actual value encoding.
 * <p>The OID must be the OID only, not the tag and length octets.
 * <p>The caller passes in the OID, criticality, and the encoded value. This
 * function will encode the extension, allocating memory for the result. The
 * caller must free that memory using MOC_FREE.
 *
 * @param pOid The OID of the extension.
 * @param oidLen The length, in bytes, of the OID.
 * @param isCritical criticality, is this extension to be critical?
 * @param pValue The encoded value to be wrapped in the OCTET STRING.
 * @param valueLen The length, in bytes, of the value.
 * @param ppEncoding The address where the function will deposit the allocated
 * buffer containing the result.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the result.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MEncodeExtensionAlloc (
  ubyte *pOid,
  ubyte4 oidLen,
  intBoolean isCritical,
  ubyte *pValue,
  ubyte4 valueLen,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Build the encoding of Extensions, which is a SEQUENCE OF { Extension }.
 * <p>This function will get extensions from a Request object and/or the
 * ExtensionArray.
 * <p>A cert request has an attribute ExtensionRequest. If the pRequestObj is not
 * NULL, the function will look inside the object for that attribute. If it is in
 * there, it will extract the extensions an use them in building the new
 * encoding. It is possible there is no ExtensionRequest attribute in the
 * request, if so, then the function will use only the pExtensionArray.
 * <p>If pRequestObj is NULL, the function will look only in the pExtensionArray
 * for extensions. If pExtensionArray is NULL or extensionCount is 0, the
 * function will look only in pRequestObj for extensions. If they are both NULL,
 * the function will return no extensions by setting *ppEncoding to NULL.
 *
 * @param pRequestObj If not NULL, it is an object containing a cert request,
 * which includes Attributes, one of which might be ExtensionRequest.
 * @param pExtensionArray An array of extensions that will be combined into the
 * ExtensionRequest attribute.
 * @param extensionCount The number of extensions in the array.
 * @param ppEncoding The address where the function will deposit a pointer to
 * allocated memory containing the resulting DER encoding of the Extensions.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the DER of the Extensions.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppNameDer and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS MBuildExtensionsAlloc (
  MRequestObj pRequestObj,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Determine the digest based on key size.
 * <p>This function will set pDigestAlg to one of the ht_ values defined in
 * crypto.h. It will do so based on the key size.
 * <pre>
 * <code>
 *          securitySize <= 1024     ht_sha1
 *   1024 < securitySize <= 2048     ht_sha256
 *   2048 < securitySize <= 3072     ht_sha256
 *   3072 < securitySize <= 7680     ht_sha384
 *   7680 < securitySize             ht_sha512
 * </code>
 * </pre>
 *
 * @param pKey The key from which the function will retrieve the key size.
 * @param pDigestAlg The address where the function will deposit the ht_ value
 * corresponding to the key size.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MGetDigestFlagFromKeySize (
  MocAsymKey pKey,
  ubyte4 *pDigestAlg
  );

#ifdef __cplusplus
}
#endif

#endif /* __CERT_OPERATIONS_HEADER__ */
