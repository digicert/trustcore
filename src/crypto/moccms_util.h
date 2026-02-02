/*
 * moccms_util.h
 *
 * Declarations and definitions for the Mocana CMS Utility functions
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
@file       moccms_util.h

@brief      Header file for the Mocana Cryptographic Message Syntax (CMS) utilities.
@details    Header file for the Mocana Cryptographic Message Syntax (CMS) utilities.
*/

#ifndef __DIGICERT_CMS_UTIL_HEADER__
#define __DIGICERT_CMS_UTIL_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------*/

/** The 'MOC_CMS_SignedDataHash' struct is used to create a digest of the payload.
 *  <p>It contains the context instance for a hash algorithm, which matches the stored
 *     OID value.
 *  <p>After the payload data has been processed, the hash data can be found in this struct.
 */
typedef struct MOC_CMS_SignedDataHash
{
    ubyte               hashType;
    const ubyte*        algoOID;
    const BulkHashAlgo* hashAlgo;
    ubyte*              hashData;
    ubyte4              hashDataLen;
    BulkCtx             bulkCtx;
} MOC_CMS_SignedDataHash;


/* See 'Attribute' type in [RFC-5280, Appendix A.1, page 111] */
typedef struct MOC_CMS_Attribute
{
    ubyte*         pOID;
    ubyte4         oidLen;
    ubyte*         pASN1;
    ubyte4         asn1Len;
} MOC_CMS_Attribute;

/** A 'linked-list' structure to hold memory references while a CMS
 *  DER encoding is being created. All memory 'stored' in this list
 *  will be released once the 'final' data has been passed to the
 *  callback function.
 */
typedef struct MOC_CMS_ASN1_Memory
{
    void*                       asn1Entry;
    struct MOC_CMS_ASN1_Memory* pNext;
} MOC_CMS_ASN1_Memory;

/*----------------------------------------------------------------------*/

/** Create the initial (empty) memory cache, by creating a root
 *  list entry. It is stored in the referenced pointer.
 *
 *  @param ppMem   A pointer to the variable that should hold the
 *                 list root element.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_createAsn1MemoryCache(MOC_CMS_ASN1_Memory **ppMem);

/*----------------------------------------------------------------------*/

/** Delete the memory cache. This will delete all memory referenced by the
 *  linked list and the list itself.
 *
 *  @param ppMem   A pointer to the variable that holds the
 *                 list root element. It will be reset to NULL.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_deleteAsn1MemoryCache(MOC_CMS_ASN1_Memory **ppMem);

/*----------------------------------------------------------------------*/

/** Add a new memory (of the type \c void*) to the cached linked list.
 *
 *  @param pMem  The root of the cache list.
 *  @param pASN1 The memory holding a section of DER encoded ASN1 that was
 *               allocated from memory.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_addToAsn1MemoryCache(MOC_CMS_ASN1_Memory* pMem,
                               void* pASN1);

/*----------------------------------------------------------------------*/

/** Clean the memory cache as it is currently filled. Free all memory referenced
 *  and reset the internal list to just the (empty) root element.
 *
 *  @param pMem  The root of the cache list.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_cleanAsn1MemoryCache(MOC_CMS_ASN1_Memory* pMem);

/*----------------------------------------------------------------------*/

/** This function creates an array of 'MOC_CMS_SignedDataHash' instances, reading
 *  the input bit-pattern in 'hashes'.
 *  <p>The created array and its size is returned via pointers.
 *  <p>A valid bit pattern can be constructed with the 'DIGI_CMS_U_getDigestAlgorithmHash'
 *    function.
 *
 *  @param hashes    The bit pattern describing the requested hash algos.
 *  @param numHashes A pointer to where the number of created hashes should be stored.
 *  @param ppHashes  A pointer to the memory where the array pointer should be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_constructHashes(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 hashes,
                          ubyte4 *numHashes,
                          MOC_CMS_SignedDataHash **ppHashes);

/** This function frees an array of 'MOC_CMS_SignedDataHash' instances, that
 *  was previously created with 'DIGI_CMS_U_constructHashes'.
 *  <p>The pointer variable holding the array memory is set to NULL.
 *
 *  @param numHashes The number of created hashes stored in the array.
 *  @param ppHashes  A pointer to the memory where the array pointer is stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_destructHashes(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 numHashes,
                         MOC_CMS_SignedDataHash  **ppHashes);

/** This function maps an OID (taken from ASN1) into an internal digest algorithm id.
 *  <p>This function calls the \c DIGI_CMS_U_getHashAlgoIdFromHashAlgoOIDData() function after
 *   obtaining the ASN1 byte array from the \c MAsn1Element instance.
 *
 *  @param pDigestAlgoOID The pointer to an ASN1 element instance, holding an OID.
 *  @param pDigestAlg     The pointer to a 'ubyte4' variable, where the obtained id is to
 *                        be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getHashAlgoIdFromHashAlgoOID(MAsn1Element *pDigestAlgoOID,
                                       ubyte4 *pDigestAlg);

/** This function maps a hash OID into an internal digest algorithm id.
 *
 *  @param pDigestAlgoOID   The pointer to a byte array, holding an OID.
 *  @param digestAlgoOIDLen The length of the byte array.
 *  @param pDigestAlg       The pointer to a 'ubyte4' variable, where the obtained id is to
 *                          be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getHashAlgoIdFromHashAlgoOIDData(const ubyte *pDigestAlgoOID,
                                           ubyte4 digestAlgoOIDLen,
                                           ubyte4 *pDigestAlg);

/** This function maps an OID (taken from ASN1) into an internal digest algorithm id,
 *  which is represented as a bit with the respective 'value'.
 *  <p>For example, id value 2 is represented as bit 2 in a 'ubyte4'. Expressed in hex
 *     that would be '0x00000004'.
 *
 *  @param pDigestAlgorithm The pointer to an ASN1 element instance, holding an OID.
 *  @param pHashes          The pointer to a 'ubyte4' variable, where the obtained bit is to
 *                          be set.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getDigestAlgorithmHash(MAsn1Element *pDigestAlgorithm,
                                 ubyte4 *pHashes);

/** This function creates ASN1 DER data to describe the digest algorithm.
 *  That ASN1 data is allocated and its memory is added to the ASN1 cache (\c pMem),
 *  and the \c MAsn1Element is filled with the encoded value.
 *
 *  @param pMem              The ASN1 memory cache for the allocated memory.
 *  @param pDigestAlgoOID    The OID value of the digest as byte array.
 *  @param digestAlgoOIDLen  The length of the OID value.
 *  @param pDigestAlgorithm  The \c MAsn1Element instance that should hold the encoded data.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setDigestAlgorithmHash(MOC_CMS_ASN1_Memory* pMem,
                                 const ubyte *pDigestAlgoOID,
                                 ubyte4 digestAlgoOIDLen,
                                 MAsn1Element *pDigestAlgorithm);

/** This function sets the content of a \c MAsn1Element to a 'NULL' value (DER-nil)
 *
 *   @param pEnc  The \c MAsn1Element instance that should hold 'NIL'.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setEncodedNIL(MAsn1Element *pEnc);

/** Encode a list of 'attribute' entries into ASN1 DER.
 *
 *  @param pMem          The ASN1 memory cache for the allocated memory.
 *  @param pAttributes   An array of references to \c MOC_CMS_Attribute instances. All attributes contained
 *                       in this array wull be encoded.
 *  @param numAttributes The number if array entries passed to this function.
 *  @param tagVal        The 'TAG' value the encoded SET is tagged with. See the RFC for allowed values.
 *  @param pEnc          A pointer to an \c MAsn1Element instance. The function will store the created ASN1
 *                       encoding in this 'element'.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setAttributesImpl(MOC_CMS_ASN1_Memory *pMem,
                            MOC_CMS_Attribute **pAttributes,
                            ubyte4            numAttributes,
                            ubyte             tagVal,
                            MAsn1Element      *pEnc);

/** Function to determine the key type of a public key in CMS 'SignerInfo'.
 *  <p>The input is the ASN1 string containing the CMS 'SignerInfo' data.
 *  <p>The returned data is a byte value matching the 'akt' type enum value as defined in
 *     'ca_mgmt.h'.
 *
 *  @param pSignerInfo The ASN1 element containing the 'SignerInfo' data.
 *  @param pubKeyType  A pointer to a 'ubyte4', where the result value will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getSignerSignatureAlgo(MAsn1Element* pSignerInfo,
                                 ubyte4 *pubKeyType);

/** Function to encode the key type and digest algorithm of a CMS 'Signer'.
 *
 *  @param pMem         The ASN1 memory cache for the allocated memory.
 *  @param pubKeyType   The ID value identifying the key type (e.g. \c akt_rsa) as defined in 'ca_mgmt.h'.
 *  @param digestAlg    The hash identifier value (e.g. \c ht_sha1) as defined in 'crypto.h'
 *  @param pSignerInfo  A pointer to an \c MAsn1Element instance, where this function will store the encoded
 *                      ASN1 data.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setSignerSignatureAlgo(MOC_CMS_ASN1_Memory* pMem,
                                 ubyte         pubKeyType,
                                 ubyte4        digestAlg,
                                 MAsn1Element* pSignerInfo);

/** Function to encode the key type and digest algorithm of a CMS 'Signer'. This uses the \c AsymmetricKey
 *  directly and should be called rather than \c DIGI_CMS_U_setSignerSignatureAlgo when using quantum safe keys.
 *
 *  @param pMem         The ASN1 memory cache for the allocated memory.
 *  @param pKey         Pointer to the signing key.
 *  @param digestAlg    The hash identifier value (e.g. \c ht_sha1) as defined in 'crypto.h'
 *  @param pSignerInfo  A pointer to an \c MAsn1Element instance, where this function will store the encoded
 *                      ASN1 data.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setSignerSignatureAlgoKey(MOC_CMS_ASN1_Memory* pMem,
                                    AsymmetricKey *pKey,
                                    ubyte4        digestAlg,
                                    MAsn1Element* pSignerInfo);

/** Function to determine the digest type of a certificate signature.
 *  <p>The input is the ASN1 string containing the CMS 'AlgorithmIdentifier' data.
 *  <p>The returned data is a byte value matching the 'akt' type enum value as defined in
 *     'ca_mgmt.h'.
 *  <p>This function calls \c DIGI_CMS_U_getSignerAlgorithmHashEncoded() after obtaining
 *     the ASN1 byte array from the \c MAsn1Element instance.
 *
 *  @param pCertSigner The ASN1 element containing the 'AlgorithmIdentifier' data.
 *  @param pDigestAlg  A pointer to a 'ubyte4', where the result value will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getSignerAlgorithmHash(MAsn1Element* pCertSigner,
                                 ubyte4* pDigestAlg);

/** Function to determine the digest type of a certificate signature.
 *  <p>The input is the ASN1 string containing the CMS 'AlgorithmIdentifier' data.
 *  <p>The returned data is a byte value matching the 'akt' type enum value as defined in
 *     'ca_mgmt.h'.
 *
 *  @param pEnc        The ASN1 'AlgorithmIdentifier' data.
 *  @param encLen      The lenght of the ASN1 data in bytes.
 *  @param pDigestAlg  A pointer to a 'ubyte4', where the result value will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getSignerAlgorithmHashEncoded(ubyte  *pEnc,
                                        ubyte4 encLen,
                                        ubyte4 *pDigestAlg);

/** Function to determine the hash type from an OID value.
 *  <p>The identifier is a \c ubyte4 value as defined in `crypto/crypto.h', e.g. a value like
 *   \c ht_sha1.
 *
 *  @param pOID     The OID value as byte array (not the full ASN1/DER encoding).
 *  @param oidLen   The length of the OID data in bytes.
 *  @param pHashAlg A pointer to a 'ubyte4', where the result value will be stored
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getSignerAlgorithmHashType(const ubyte  *pOID,
                                     ubyte4       oidLen,
                                     ubyte4       *pHashAlg);

/** Function to compare the issuer name of an X509 ASN1 encoded certificate
 *  with the subject name of an an X509 ASN1 encoded parent certificate.
 *  <p>This function returns 'OK' when the 'parent' is the correct
 *     issuer of the certificate. Otherwise 'ERR_FALSE' is returned.
 *
 *  @param pParent   The ASN1 encoded parent certificate data.
 *  @param parentLen The length of the parent ASN1 string.
 *  @param pCert     The ASN1 encoded certificate data.
 *  @param certLen   The length of the ASN1 string.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_checkCertificateIssuer(const ubyte *pParent,
                                 ubyte4      parentLen,
                                 const ubyte *pCert,
                                 ubyte4      certLen);

/** Function to extract the 'CertificateSerialNumber' from an X509 encoded certificate.
 *  <p>This utility must be used when the 7.0 API for certificate operations is disabled.
 *  <p>The returned string is the ASN1 encoded INTEGER value.
 *  <p>The output parameters are not allowed to be NULL.
 *  <p>The output string pointer references the memory of 'pCert', so it stays valid
 *     until 'pCert' is deleted.
 *
 *  @param pCert       The ASN1 encoded X509 certificate data.
 *  @param certLen     The length of the ASN1 data string.
 *  @param ppSerial    The pointer to the variable where the pointer to the
 *                     'CertificateSerialNumber' data string will be stored.
 *  @param pSerialLen  The pointer to the variable where the length of the
 *                     'CertificateSerialNumber' data string will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_parseX509CertForSerialNumber(const ubyte *pCert,
                                       ubyte4      certLen,
                                       ubyte       **ppSerial,
                                       ubyte4      *pSerialLen);

/** Function to extract the 'Subject' from an X509 encoded certificate.
 *  <p>This utility must be used when the 7.0 API for certificate operations is disabled.
 *  <p>The returned string is the ASN1 encoded 'name' value.
 *  <p>The output parameters are not allowed to be NULL.
 *  <p>The output string pointer references the memory of 'pCert', so it stays valid
 *     until 'pCert' is deleted.
 *
 *  @param pCert     The ASN1 encoded X509 certificate data.
 *  @param certLen   The length of the ASN1 data string.
 *  @param ppSubj    The pointer to the variable where the pointer to the
 *                   'Subject' data string will be stored.
 *  @param pSubjLen  The pointer to the variable where the length of the
 *                   'Subject' data string will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_parseX509CertForSubject(const ubyte *pCert,
                                  ubyte4      certLen,
                                  ubyte       **ppSubj,
                                  ubyte4      *pSubjLen);

/** Function to extract the 'IssuerName' from an X509 encoded certificate.
 *  <p>This utility must be used when the 7.0 API for certificate operations is disabled.
 *  <p>The returned string is the ASN1 encoded 'name' value.
 *  <p>The output parameters are not allowed to be NULL.
 *  <p>The output string pointer references the memory of 'pCert', so it stays valid
 *     until 'pCert' is deleted.
 *
 *  @param pCert           The ASN1 encoded X509 certificate data.
 *  @param certLen         The length of the ASN1 data string.
 *  @param ppIssuerName    The pointer to the variable where the pointer to the
 *                         'IssuerName' data string will be stored.
 *  @param pIssuerNameLen  The pointer to the variable where the length of the
 *                         'IssuerName' data string will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_parseX509CertForIssuerName(const ubyte *pCert,
                                     ubyte4      certLen,
                                     ubyte       **ppIssuerName,
                                     ubyte4      *pIssuerNameLen);

/** Function to extract the 'Subject Key Identifier Extension' from an X509 encoded certificate.
 *  <p>This utility must be used when the 7.0 API for certificate operations is disabled.
 *  <p>The returned octet string is the ASN1 encoded value.
 *  <p>The output parameters are not allowed to be NULL.
 *  <p>The output string pointer references the memory of 'pCert', so it stays valid
 *     until 'pCert' is deleted.
 *
 *  @param pCert           The ASN1 encoded X509 certificate data.
 *  @param certLen         The length of the ASN1 data string.
 *  @param ppExt           The pointer to the variable where the pointer to the
 *                         octet string will be stored.
 *  @param pExtLen         The pointer to the variable where the length of the
 *                         octet string will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */

MOC_EXTERN MSTATUS
DIGI_CMS_U_parseX509CertForSubjectKeyIdentifier(const ubyte *pCert,
                                               ubyte4      certLen,
                                               ubyte       **ppExt,
                                               ubyte4      *pExtLen);

/** Function to extract the 'SubjectPublicKeyInfo' from an X509 encoded certificate.
 *  <p>This utility must be used when the 7.0 API for certificate operations is disabled.
 *  <p>The returned string is the ASN1 encoded public key value.
 *  <p>The output parameters are not allowed to be NULL.
 *  <p>The output string pointer references the memory of 'pCert', so it stays valid
 *     until 'pCert' is deleted.
 *
 *  @param pCert           The ASN1 encoded X509 certificate data.
 *  @param certLen         The length of the ASN1 data string.
 *  @param ppSubjPubKey    The pointer to the variable where the pointer to the
 *                         'SubjectPublicKeyInfo' data string will be stored.
 *  @param pSubjPubKeyLen  The pointer to the variable where the length of the
 *                         'SubjectPublicKeyInfo' data string will be stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_parseX509CertForPublicKey(const ubyte *pCert,
                                    ubyte4      certLen,
                                    ubyte       **ppSubjPubKey,
                                    ubyte4      *pSubjPubKeyLen);

/** This function extracts an 'AsymmetricKey' instance from the Certificate object filled
 *  with data from a certificate file or other source.
 *
 *  @param pCert    The ASN1 Certificate data.
 *  @param certLen  The length of the ASN1 data string.
 *  @param pCertKey The pointer to an 'AsymmetricKey' variable which is used to store the
 *                  obtained key.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                         const ubyte    *pCert,
                                         ubyte4         certLen,
                                         AsymmetricKey* pCertKey);

/** Process the signature data collected from a CMS message.
 *  <p>The CMS data is presented to the function as three ASN1 element roots.
 *     One for the 'SignerInfo', one for the 'Certificate', and one for the 'Signature Data'.
 *  <p>The already constructed array of hashes is passed in, which will be used as input
 *     to the digest algorithm needed for each 'SignerInfo'.
 *
 *  @param pSigner         The ASN1 'SignerInfo' data element from the CMS.
 *  @param pCertificate    The ASN1 element containing a certificate data from the CMS.
 *  @param pSignData       The ASN1 element containing the signature data from the CMS.
 *  @param numHashes       The number of entries in the array of hashes.
 *  @param pSignedDataHash The array of 'MOC_CMS_SignedDataHash' instances containing the
 *                         payload hash values.
 *  @param pSigInfos       The pointer to memory where an array of 'MOC_CMS_MsgSignInfo'
 *                         instances should be stored. Can be set to NULL to not make that
 *                         array.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_processSignerInfoWithCert(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                    MAsn1Element *pSigner,
                                    MAsn1Element *pCertificate,
                                    MAsn1Element *pSignData,
                                    ubyte4 numHashes,
                                    MOC_CMS_SignedDataHash *pSignedDataHash,
                                    MOC_CMS_MsgSignInfo *pSigInfos);

/** This function tries to verify a certificate's signature with an 'AsymmetricKey' instance
 *  that represents a public key.
 *
 *  @param pCert         The ASN1 certificate data.
 *  @param certLen       The length of the ASN1 data string.
 *  @param parentCertKey A pointer to an 'AsymmetricKey' instance (that should be loaded from the parent
 *                       certificate). It contains a public key value.
 *  @param pFails        A pointer to a 'intBoolean' in which the verification result is stored.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_verifyCertificateSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                     ubyte* pCert,
                                     ubyte4 certLen,
                                     AsymmetricKey *parentCertKey,
                                     intBoolean *pFails);

/** This function computes the signature value for a given hash by encrypting
 *  it with the given key. The signature is returned as ASN1 encoded data and
 *  placed in a \c MAsn1Element instance.
 *  <p>Supported algorithms (depending on compile flags) are
 *  <ul>
 *   <li>RSA</li>
 *   <li>ECDSA</li>
 *   <li>DSA</li>
 *  </ul>
 *
 *  @param pMem       The ASN1 memory cache for the allocated memory.
 *  @param rngFun     An RNG function pointer.
 *  @param rngArg     The RNG private value argument to be passed to the RNG function when called.
 *  @param pKey       A pointer to the (private) key value to be used.
 *  @param pHash      The hash value as byte array, that is input to the signature function.
 *  @param hashLen    The length of the hash value in bytes.
 *  @param hashAlgo   An id value that designates the hash algorithm used to generate the above value.
 *                    It is a \c ubyte4 value taken from 'crypto/crypto.h', for instance \c ht_sha1.
 *  @param pSig       A pointer to an \c MAsn1Element instance, where the created signature data will the
 *                    held as encoded ASN1.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setSignatureValue(MOC_ASYM(hwAccelDescr hwAccelCtx)
                            MOC_CMS_ASN1_Memory* pMem,
                            RNGFun rngFun, void* rngArg,
                            const AsymmetricKey*  pKey,
                            ubyte        *pHash,
                            ubyte4       hashLen,
                            ubyte4       hashAlgo,
                            MAsn1Element *pSig);

/** This function verifies that the given certificate was signed with the parent's certificate.
 * <p>It first checks that the 'issuer' of the certificate matches the 'subject' name of the
 *  parent. Then it extracts the public key from the parent and validates the signature of the
 *  certificate.
 *
 *  @param pCert     The ASN1 certificate data.
 *  @param certLen   The length of the ASN1 data string of the certificate.
 *  @param pParent   The ASN1 certificate data of the parent.
 *  @param parentLen The length of the ASN1 data string of the parent.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                       ubyte*       pCert,
                       ubyte4       certLen,
                       const ubyte* pParent,
                       ubyte4       parentLen);

/** This function verifies that the given certificate is a root.
 * <p>It first checks that certificate is self-signed. It then reads the attributes
 *  of the certificate to make sure it is allowed to be the root of a signature chain.
 * <p>It returns 'OK' when it is a root, and 'ERR_FALSE' when it is not.
 *
 *  @param pCert     The ASN1 certificate data.
 *  @param certLen   The length of the ASN1 data string of the certificate.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_isRootCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                            ubyte* pCert,
                            ubyte4 certLen);

/** Create the bulk symmetric crypto instance, and initialize it with given input.
 *  <p>The algorithm is identified by the OID, passed in as an ASN1 string.
 *  <p>The IV value are given as ASN1 string input.
 *  <p>The key value is given as a (raw) byte array.
 *  <p>When using the pre-7.0 crypto API, a 'BulkCtx' and the 'BulkEncryptionAlgo' instance is
 *     created.
 *
 *  @param pEncryptOID     The OID of the encryption algorithm, read from CMS data.
 *  @param encryptOIDLen   The length of the OID ASN1 string.
 *  @param pEncryptIV      The encrypted IV array, read from CMS data.
 *  @param encryptIVLen    The length of the IV array.
 *  @param pSymmetricKey   The symmetric key array.
 *  @param symmetricKeyLen The length of the symmetric key.
 *  @param iv              Pointer to memory where the IV value should be stored.
 *  @param pBulkCtx        The pointer to a 'BulkCtx' instance that should be initialized
 *                         by this function.
 *  @param ppBulkAlgo      A pointer to a 'const BulkEncryptionAlgo*' variable, that should be
 *                         overwritten by this function.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getBulkAlgo (MOC_SYM(hwAccelDescr hwAccelCtx)
                       ubyte* pEncryptOID,
                       ubyte4 encryptOIDLen,
                       ubyte* pEncryptIV,
                       ubyte4 encryptIVLen,
                       ubyte* pSymmetricKey,
                       ubyte4 symmetricKeyLen,
                       ubyte* iv,
                       BulkCtx* pBulkCtx,
                       const BulkEncryptionAlgo** ppBulkAlgo);

/** A function to convert an OID value to the encryption algorithm and its expected key length value.
 *  <p>Depending on compile flags, the supported algorithms are
 *  <ul>
 *   <li>AES</li>
 *   <li>3DES</li>
 *   <li>DES</li>
 *  </ul>
 *
 *  @param encryptAlgoOID    The byte array containing an OID value (not in ASN1/DER encoding).
 *  @param encryptAlgoOIDLen The length of the above data in bytes.
 *  @param ppBulkAlgo        A pointer to a \c BulkEncryptionAlgo reference, where this function will
 *                           store the reference to the identified instance (e.g. \c CRYPTO_AESSuite).
 *  @param keyLength         The length of the key the algorithm can handle (in bytes).
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getCryptoAlgoParams (const ubyte* encryptAlgoOID,
                               ubyte4 encryptAlgoOIDLen,
                               const BulkEncryptionAlgo** ppBulkAlgo,
                               sbyte4 *keyLength);

/** Process the ASN1 string that contains the CMS 'KeyAgreeRecipientInfo'. This
 *  function returns the symmetric key and the recipient id data.
 *  <p>To manage private key data, two callback functions are provided to call
 *     'user' code.
 *  <p>The symmetric key data is used to decrypt the payload of the CMS, and its value
 *     is itself encrypted with the public key (of an asymmetric algorithm), specified in
 *     the CMS recipient info data.
 *
 *  @param root               The root ASN1 element of the CMS recipient data.
 *  @param callbackArg        The user provided callback argument, passed to all calls.
 *  @param getPrivateKeyFun   The callback function, taking an 'issuer name' and a 'serial
 *                            number' as identifier.
 *  @param getPrivateKeyFunEx The callback function, taking a 'MOC_CMS_RecipientId' as an
 *                            identifier.
 *  @param ppSymmetricKey     A pointer to a 'ubyte*' variable, where the obtained symmetric
 *                            key data is to be stored.
 *  @param pSymmetricKeyLen   A pointer to a 'ubyte4' variable, where the length of the
 *                            symmetric key array is to be stored.
 *  @param pRec               The pointer to memory where an array of 'MOC_CMS_RecipientId*'
 *                            instances should be stored. Can be set to NULL to not make that
 *                            array.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_processKeyAgreeRecipientInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                       MAsn1Element* root,
                                       const void* callbackArg,
                                       MOC_CMS_GetPrivateKey getPrivateKeyFun,
                                       MOC_CMS_GetPrivateKeyEx getPrivateKeyFunEx,
                                       ubyte** ppSymmetricKey,
                                       ubyte4* pSymmetricKeyLen,
                                       MOC_CMS_RecipientId** pRec);

/** Process the ASN1 string that contains the CMS 'KeyTransRecipientInfo'. This
 *  function returns the symmetric key and the recipient id data.
 *  <p>To manage private key data, two callback functions are provided to call
 *     'user' code.
 *  <p>The symmetric key data is used to decrypt the payload of the CMS, and its value
 *     is itself encrypted with the public key (of an asymmetric algorithm), specified in
 *     the CMS recipient info data.
 *
 *  @param pRoot              The root ASN1 element of the CMS recipient data.
 *  @param callbackArg        The user provided callback argument, passed to all calls.
 *  @param getPrivateKeyFun   The callback function, taking an 'issuer name' and a 'serial
 *                            number' as identifier.
 *  @param getPrivateKeyFunEx The callback function, taking a 'MOC_CMS_RecipientId' as an
 *                            identifier.
 *  @param ppSymmetricKey     A pointer to a 'ubyte*' variable, where the obtained symmetric
 *                            key data is to be stored.
 *  @param pSymmetricKeyLen   A pointer to a 'ubyte4' variable, where the length of the
 *                            symmetric key array is to be stored.
 *  @param pRec               The pointer to memory where an array of 'MOC_CMS_MsgSignInfo*'
 *                            instances should be stored. Can be set to NULL to not make that
 *                            array.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_processKeyTransRecipientInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                       MAsn1Element* pRoot,
                                       const void* callbackArg,
                                       MOC_CMS_GetPrivateKey getPrivateKeyFun,
                                       MOC_CMS_GetPrivateKeyEx getPrivateKeyFunEx,
                                       ubyte** ppSymmetricKey,
                                       ubyte4* pSymmetricKeyLen,
                                       MOC_CMS_RecipientId** pRec);

/** Function to write the 'recipient' data for an encrypted CMS.
 *  <p>The supported public key types are RSA and ECDH.
 *
 *  @param pMem                The ASN1 memory cache for the allocated memory.
 *  @param rngFun              An RNG function pointer.
 *  @param rngFunArg           The RNG private value argument to be passed to the RNG function when called.
 *  @param pBulkEncryptionAlgo A pointer to the encryption algorithm.
 *  @param pEncrKey            The value of the encryption key.
 *  @param encrKeyLen          The length in bytes of the encryption key data.
 *  @param pCert               The X509 certificate data of the recipient. The public key in this certificate
 *                             will be used to generated the 'encrypted key' value.
 *  @param certLen             The length of the X509 certificate data.
 *  @param pID                 A pointer to an MAsn1Element, which will contain the encoded ASN1
 *  @param pVersion            A pointer to a \ubyte4, which will be used to store the CMS 'version' generated,
 *                             as defined by RFC-5652.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_writeRecipientID(MOC_HW(hwAccelDescr hwAccelCtx)
                           MOC_CMS_ASN1_Memory *pMem,
                           RNGFun              rngFun,
                           void                *rngFunArg,
                           const BulkEncryptionAlgo* pBulkEncryptionAlgo,
                           ubyte               *pEncrKey,
                           ubyte4              encrKeyLen,
                           ubyte               *pCert,
                           ubyte4              certLen,
                           MAsn1Element        *pID,
                           ubyte4              *pVersion);

/** A function to convert an ASN1 representation of identifying data, the issuer and
 *  serial number of a certificate, to a 'MOC_CMS_IssuerSerialNumber' struct.
 *
 *  @param pIssuerSerialNumber The pointer to the ASN1 element with data.
 *  @param pISN                The pointer to a 'MOC_CMS_IssuerSerialNumber' instance,
 *                             which will be filled with the obtained data.
 *                             The values are using (shared) memory from the ASN1 element.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getIssuerSerialNumber(MAsn1Element* pIssuerSerialNumber,
                                MOC_CMS_IssuerSerialNumber* pISN);

/** A function to convert an ASN1 representation of identifying data, the originator
 *  public key of a certificate, to a 'MOC_CMS_OriginatorPublicKey' struct.
 *
 *  @param pRoot           The pointer to the ASN1 element with data.
 *  @param pOriginatorKey  The pointer to a 'MOC_CMS_OriginatorPublicKey' instance,
 *                         which will be filled with the obtained data.
 *                         The values are using (shared) memory from the ASN1 element.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_getOriginatorPublicKey(MAsn1Element* pRoot,
                                 MOC_CMS_OriginatorPublicKey* pOriginatorKey);

/** A function to store data held by \c MOC_CMS_IssuerSerialNumber as an ASN1 DER
 *  encoded byte array.
 *
 *  @param pMem                The ASN1 memory cache for the allocated memory.
 *  @param pISN                A pointer to an instance of \c MOC_CMS_IssuerSerialNumber, that contains the
 *                             values to be encoded.
 *  @param pIssuerSerialNumber A pointer to an \c MAsn1Element instance, where this function will store
 *                             the encoded ASN1 data.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setIssuerSerialNumber(MOC_CMS_ASN1_Memory* pMem,
                                MOC_CMS_IssuerSerialNumber* pISN,
                                MAsn1Element* pIssuerSerialNumber);


/** A function to store the subject key identifier as an
 *  encoded byte array.
 *
 *  @param pMem                The ASN1 memory cache for the allocated memory.
 *  @param pSKI                The raw subjectKeyIdentifier extension value. 
 *  @param skiLen              The length of \c pSKI in bytes.
 *  @param pSKIElement         Will contain the asn1 encoded subjectKeyIdentifier.
 *
 * @return          \c OK (0) if successful; otherwise a negative number
 *                  error code definition from merrors.h. To retrieve a
 *                  string containing an English text error identifier
 *                  corresponding to the function's returned error status,
 *                  use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
DIGI_CMS_U_setSubjectKeyIdentifier(MOC_CMS_ASN1_Memory *pMem,
                                  ubyte *pSKI,
                                  ubyte4 skiLen,
                                  MAsn1Element *pSKIelement);

#ifdef __cplusplus
}
#endif

#endif  /* __DIGICERT_CMS_UTIL_HEADER__ */
