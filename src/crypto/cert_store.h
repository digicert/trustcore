/*
 * cert_store.h
 *
 * Certificate Store Header
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
@file       cert_store.h
@brief      SoT Platform certificate store factory.
@details    This header file contains structures, enumerations, and function
            declarations used for SoT Platform certificate stores.

@since 1.41
@version 2.02 and later

@todo_version (new structure fields, functions, tc.)

@flags
No flag definitions are required to use this file.

@filedoc    cert_store.h
*/

/**
@cond
*/

#include "../common/initmocana.h"
#include "../common/sizedbuffer.h"

#ifndef __CERT_STORE_HEADER__
#define __CERT_STORE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

/**
 * @cond
 */

#ifndef MAX_SIZE_CERT_STORE_TRUST_HASH_TABLE
#define MAX_SIZE_CERT_STORE_TRUST_HASH_TABLE        (0x1f)
#endif

/* left first octet is reserved */
#define CERT_STORE_ALGO_FLAG_RESERVED               (0xFF000000L)
/* left second octet is for ECDSA curves */
#define CERT_STORE_ALGO_FLAG_ECCURVES               (0x00FF0000L)
/* left third octet is for sign keyType */
#define CERT_STORE_ALGO_FLAG_SIGNKEYTYPE            (0x0000FF00L)
/* right most octet is for HASH algorithms */
#define CERT_STORE_ALGO_FLAG_HASHALGO               (0x000000FFL)

/* Function Like Macros for setting algo id's for a cert key or sign algo */
#define CERT_STORE_ALGO_ID_SET_KEYTYPE( id, value) (id) |= (((value) & 0xff) << 24 )
#define CERT_STORE_ALGO_ID_SET_HASH( id, value)    (id) |= (((value) & 0xff) << 16 )
#define CERT_STORE_ALGO_ID_SET_QSALG( id, value)   (id) |= (((value) & 0xffff) << 8 )
#define CERT_STORE_ALGO_ID_SET_CURVE( id, value)   (id) |= ((value) & 0xff)
#define CERT_STORE_ALGO_ID_SET_CLALG( id, value)   (id) |= ((value) & 0xff) /* ok to use same byte as curve */

#define CERT_STORE_ALGO_ID_GET_KEYTYPE(id)  ((id & 0xff000000) >> 24)
#define CERT_STORE_ALGO_ID_GET_HASH(id)     ((id & 0x00ff0000) >> 16)

#define CERT_STORE_ALGO_ID_HASH_MASK                (0x00ff0000L)

#define CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK    (~CERT_STORE_ALGO_ID_HASH_MASK)
#define CERT_STORE_ALGO_ID_MASK_REMOVE_CURVE_MASK   (0xffffff00L)

/**
 * @endcond
 */

/* individual flags: ec curves */
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a EC192
 * key.
 */
#define CERT_STORE_ALGO_FLAG_EC192                  (0x00010000L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a EC224
 * key.
 */
#define CERT_STORE_ALGO_FLAG_EC224                  (0x00020000L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a EC256
 * key.
 */
#define CERT_STORE_ALGO_FLAG_EC256                  (0x00040000L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a EC384
 * key.
 */
#define CERT_STORE_ALGO_FLAG_EC384                  (0x00080000L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a EC521
 * key.
 */
#define CERT_STORE_ALGO_FLAG_EC521                  (0x00100000L)
#define CERT_STORE_ALGO_FLAG_EC25519                (0x00200000L)
#define CERT_STORE_ALGO_FLAG_EC448                  (0x00400000L)

/* individual flags: signing keyType */
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate which has been signed using RSA.
 */
#define CERT_STORE_ALGO_FLAG_RSA                    (0x00000100L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate which has been signed using ECDSA.
 */
#define CERT_STORE_ALGO_FLAG_ECDSA                  (0x00000200L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate which has been signed using DSA.
 */
#define CERT_STORE_ALGO_FLAG_DSA                    (0x00000400L)
#define CERT_STORE_ALGO_FLAG_EDDSA_25519            (0x00000800L)
#define CERT_STORE_ALGO_FLAG_EDDSA_448              (0x00001000L)
#define CERT_STORE_ALGO_FLAG_HYBRID                 (0x00002000L)
#define CERT_STORE_ALGO_FLAG_QS                     (0x00004000L)

/* individual flags: hash algos */
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate where the certificate signature is computed over a MD5 digest.
 */
#define CERT_STORE_ALGO_FLAG_MD5                    (0x00000001L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate where the certificate signature is computed over a SHA-1 digest.
 */
#define CERT_STORE_ALGO_FLAG_SHA1                   (0x00000002L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate where the certificate signature is computed over a SHA-224
 * digest.
 */
#define CERT_STORE_ALGO_FLAG_SHA224                 (0x00000004L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate where the certificate signature is computed over a SHA-256
 * digest.
 */
#define CERT_STORE_ALGO_FLAG_SHA256                 (0x00000008L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate where the certificate signature is computed over a SHA-384
 * digest.
 */
#define CERT_STORE_ALGO_FLAG_SHA384                 (0x00000010L)
/**
 * This flag can be OR'ed into the supportedAlgoFlags parameter into
 * CERT_STORE_findIdentityCertChainFirst or any other certificate store API
 * which takes in a supported algorithm flags bit field to search for a
 * certificate where the certificate signature is computed over a SHA-512
 * digest.
 */
#define CERT_STORE_ALGO_FLAG_SHA512                 (0x00000020L)
#define CERT_STORE_ALGO_FLAG_INTRINSIC              (0x00000040L)

/*------------------------------------------------------------------*/

/**
 * The certificate store places identities into algorithm indexes. These indexes
 * may be passed into the certificate store to search through all the identites
 * for a particular algorithm.
 */
enum authTypes
{
    CERT_STORE_AUTH_TYPE_RSA                        = 0,
    CERT_STORE_AUTH_TYPE_ECDSA                      = 1,
    CERT_STORE_AUTH_TYPE_DSA                        = 2,
    CERT_STORE_AUTH_TYPE_RSA_PSS                    = 3,
    CERT_STORE_AUTH_TYPE_EDDSA                      = 4,
    CERT_STORE_AUTH_TYPE_HYBRID                     = 5,
    CERT_STORE_AUTH_TYPE_QS                         = 6,
    CERT_STORE_AUTH_TYPE_ARRAY_SIZE                 = 7     /* needs to be last */
};

/**
 * The certificate store has two types of identities. When loading only a key
 * into the certificate store, the key will be stored in
 * CERT_STORE_IDENTITY_TYPE_NAKED. Certificates and certificate/key pairs are
 * stored in the CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 index. These values can
 * be passed into the certificate store APIs to search through all the
 * identities stored for that index.
 */
enum identityTypes
{
    CERT_STORE_IDENTITY_TYPE_NAKED                  = 0,
    CERT_STORE_IDENTITY_TYPE_CERT_X509_V3           = 1,
    CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE             = 2     /* needs to be last */
};

/*------------------------------------------------------------------*/

struct AsymmetricKey;
struct certStore;
struct SizedBuffer;

typedef struct certStore* certStorePtr;

#if defined(__ENABLE_DIGICERT_MINIMAL_CA__)
struct certStoreIssuer;
typedef struct certStoreIssuer* certStoreIssuerPtr;
#endif

typedef sbyte4 (*ExtendedDataCallback)(sbyte4 extDataIdentifier, enum dataType *pType, enum dataEncoding *pFormat,
                                     sbyte **ppBuffer, sbyte4 *pBufferLen);

/**
 * @dont_show
 * @internal
 */
typedef struct extendedData
{
    sbyte4              extDataIdentifier;
    ExtendedDataCallback  extDataFunc;
} extendedData;

/*------------------------------------------------------------------*/

/**
 * Create a certificate store object.
 * <p>This function creates a certificate store object. The caller may then use
 * the certificate store APIs to add "identites" to the certificate store. These
 * identities may represent certificates, keys, certifcate/key pairs, and PSKs.
 * These identities, once loaded into the certificate store, may be retrieved
 * at a later point in time through the certificate store APIs.
 * <p>The caller must free the certificate store once it is done.
 *
 * @ingroup cert_store_functions
 *
 * @param ppNewStore Pointer to store the new certificate store.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_createStore (
  certStorePtr *ppNewStore
  );

/**
 * Delete a certificate store object.
 * <p>This function frees up the certificate store and any identities stored in
 * the certificate store. Note that if the caller has retrieved any references
 * from the certificate store, this call will free up any identities, which will
 * cause the references to be invalidated.
 *
 * @ingroup cert_store_functions
 *
 * @param ppReleaseStore Pointer to the certificate store to delete.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_releaseStore (
  certStorePtr *ppReleaseStore
  );

/**
 * @cond
 */

/* Load a MocCtx into this cert store. If later operations need it, it's there.
 * This function will acquire a reference to the MocCtx, and then when the store
 * is released, it will release it. That is, the caller does not need to do
 * anything beyond calling _releaseStore (which it is already doing, right?).
 */
MOC_EXTERN MSTATUS CERT_STORE_loadMocCtx (
  certStorePtr pCertStore,
  MocCtx pMocCtx
  );

/* handy conversion functions */
MOC_EXTERN MSTATUS CERT_STORE_convertCertStoreKeyTypeToPubKeyType(ubyte4 certStoreKeyType, ubyte4 *pRetPubKeyType);

/**
 * @endcond
 */

/* add identity */
#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

/**
 * Load a certificate and key pair into the certificate store.
 * <p>The caller provides a key and certificate pair to add into the certificate
 * store. The key and certificate pair can be looked up later on. Note that the
 * key is optional and the caller may only provide the certificate.
 * <p>This function will parse the certificate and determine the key type the
 * certificate and key pair belong to. It will also determine the signature
 * algorithm used in the certificate. When retrieving the identity from the
 * store the caller can pass in a bit field to restrict the certificate store
 * search to certificates and keys based on the algorithms specified in the bit
 * field.
 * <p>Note that you can pass in either a cert, or a key and cert, but not a key
 * alone (call CERT_STORE_addIdentityNakedKeyEx for that).
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param pDerCert The DER of the cert to add.
 * @param derCertLength The length, in bytes, of the cert.
 * @param pKeyBlob If not NULL, the private key partner to the cert, in Mocana
 * key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentity (
  certStorePtr pCertStore,
  const ubyte *pDerCert,
  ubyte4 derCertLength,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  );

/**
 * This is the same as CERT_STORE_addIdentity except the caller also supplies an
 * "alias".
 * <p>The alias is a name or label. It is simply another way to search for certs
 * and keys. The caller supplies the cert and key as usual, but also an alias.
 * The alias will be stored with the cert and key, in the same entry of the
 * store. Later on, it will be possible to search for a cert or key (or both) by
 * alias.
 * <p>This function will check to see if an entry already exists with that alias.
 * If one does exist, it will return an error. This means you cannot replace an
 * entry with new data (same alias, new data). It also means you cannot add new
 * data to an existing entry. For example, you might want to do this: generate a
 * key pair, store the private key, make a cert request, and after you have the
 * cert, add it to the entry with the key. That is not possible. You must add the
 * key and cert at the same time.
 * <p>Note that you can pass in either a cert, or a key and cert, but not a key
 * alone (call CERT_STORE_addIdentityNakedKeyEx for that).
 * <p>Note also that if pAlias is NULL, or aliasLen is 0, the function will
 * return an error.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param pAlias The alias, or name of the entry.
 * @param aliasLen The length, in bytes, of the alias.
 * @param pDerCert The DER of the cert to add.
 * @param derCertLength The length, in bytes, of the cert.
 * @param pKeyBlob If not NULL, the private key partner to the cert, in Mocana
 * key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  ubyte *pDerCert,
  ubyte4 derCertLength,
  ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  );

/**
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param pAlias The alias, or name of the entry.
 * @param aliasLen The length, in bytes, of the alias.
 * @param pKeyBlob If not NULL, the private key partner to the cert, in Mocana
 * key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @param identityType The identity type. Look at cert_store.h regarding this
 * enum.
 * @param certificates The array of DER certificates to add.
 * @param numCertificate The number of DER certificates.
 * @param pExtData  The pointer to extended data.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addGenericIdentity (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  enum identityTypes identityType,
  SizedBuffer *certificates,
  ubyte4 numCertificate,
  extendedData *pExtData
  );

/**
 * This is the same as CERT_STORE_addIdentity except the caller can specify
 * multiple certificates.
 * <p>The caller provides a key and certificate pair to add into the certificate
 * store. The key and certificate pair can be looked up later on. Multiple
 * certificates can be provided through this API.
 * <p>This function parses the leaf certificate and key pair for the key
 * algorithm and signature algorithm. The caller may look up the identity pair
 * based on the key algorithm and signature algorithm.
 * <p>Note that you can pass in either a cert, or a key and cert, but not a key
 * alone (call CERT_STORE_addIdentityNakedKeyEx for that).
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param certificates The array of DER certificates to add.
 * @param numCertificate The number of DER certificates.
 * @param pKeyBlob If not NULL, the private key partner to the first
 * certificate, in Mocana key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityWithCertificateChain (
  certStorePtr pCertStore,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  );

/**
 * This is the same as CERT_STORE_addIdentityWithCertificateChain, except the
 * caller also supplies a callback and identifier.
 * <p> The callback and identifier will be associated to the key in certificate store.
 * <p>The chain can be of length 1.
 * <p>You can pass in a chain without a key, or a chain with a key (the key must
 * match the first cert in the list, the cert at index 0). But you cannot pass in
 * key without a chain.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param certificates An array of certificates. The cert at index 0 must be the
 * partner to the key (if a key is provided).
 * @param numCertificate The number of certificates in the array.
 * @param pKeyBlob If not NULL, the private key partner to the cert, in Mocana
 * key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @param extDataFunc Pointer to callback associated with key.
 * @param extDataIdentifier A user defined value associated with key.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
CERT_STORE_addIdentityWithCertificateChainExtData(certStorePtr pCertStore,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  ExtendedDataCallback extDataFunc,
  sbyte4 extDataIdentifier
  );

/**
 * This is the same as CERT_STORE_addIdentityWithCertificateChain, except the
 * caller also supplies a callback and identifier.
 * <p> The callback and identifier will be associated to the key in certificate store.
 * <p>The chain can be of length 1.
 * <p>You can pass in a chain without a key, or a chain with a key (the key must
 * match the first cert in the list, the cert at index 0). But you cannot pass in
 * key without a chain.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param certificates An array of certificates. The cert at index 0 must be the
 * partner to the key (if a key is provided).
 * @param numCertificate The number of certificates in the array.
 * @param pKeyBlob If not NULL, the private key partner to the cert, in Mocana
 * key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @param extDataFunc Pointer to callback associated with key.
 * @param extDataIdentifier A user defined value associated with key.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityWithCertificateChainExtDataEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  ExtendedDataCallback extDataFunc,
  sbyte4 extDataIdentifier
  );

/**
 * This is the same as CERT_STORE_addIdentityWithCertificateChain, except the
 * caller also supplies an "alias".
 * <p>See the comments for CERT_STORE_addIdentityEx for more on alias.
 * <p>This function will check to see if an entry already exists with that alias.
 * If one does exist, it will return an error. This means you cannot replace an
 * entry with new data (same alias, new data). It also means you cannot add new
 * data to an existing entry. For example, you might want to do this: generate a
 * key pair, store the private key, make a cert request, and after you have the
 * cert, add it to the entry with the key. That is not possible. You must add the
 * key and cert at the same time.
 * <p>The chain can be of length 1.
 * <p>You can pass in a chain without a key, or a chain with a key (the key must
 * match the first cert in the list, the cert at index 0). But you cannot pass in
 * key without a chain.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param pAlias The alias, or name of the entry.
 * @param aliasLen The length, in bytes, of the alias.
 * @param certificates An array of certificates. The cert at index 0 must be the
 * partner to the key (if a key is provided).
 * @param numCertificate The number of certificates in the array.
 * @param pKeyBlob If not NULL, the private key partner to the cert, in Mocana
 * key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityWithCertificateChainEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  );

#endif /* ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */

/**
 * This API adds a key blob to the certificate store.
 * <p>This function adds a key blob to the certificate store. The key is stored
 * in certificate store and the key algorithm is stored in the identity. The
 * caller may query for the key identity based on the algorithm.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param pKeyBlob The private key to store, in Mocana key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityNakedKey (
  certStorePtr pCertStore,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  );

/**
 * This is the same as CERT_STORE_addIdentityNakedKey, except the caller also
 * supplies an "alias".
 * <p>See the comments for CERT_STORE_addIdentityEx for more on alias.
 * <p>This function will check to see if an entry already exists with that alias.
 * If one does exist, it will return an error. This means you cannot replace an
 * entry with new data (same alias, new data).
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The cert store to which the entry will be added.
 * @param pAlias The alias, or name of the entry.
 * @param aliasLen The length, in bytes, of the alias.
 * @param pKeyBlob The private key to store, in Mocana key blob format.
 * @param keyBlobLength The length, in bytes, of the key blob.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityNakedKeyEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  );

/**
 * Add a PSK to the certificate store.
 * <p>This API adds a pre-shared secret into the certificate store. The caller
 * provides the PSK identity, the optional PSK hint, and the PSK itself. The
 * PSK identity is the identity value the caller may use to look-up the PSK
 * value itself. Providing a existing identity value will not override the
 * original identity, both identities will exist. The caller may iterate through
 * the list of PSKs based on the identity value. The optional hint value is
 * defined by the user and is retrieved when retrieving a PSK. The hint value is
 * caller specific data. The PSK secret value is the actual PSK data.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The cert store to which the PSK will be added.
 * @param pPskIdentity The PSK identity the caller may use to later look-up the
 * the PSK.
 * @param pskIdentityLength The length of the PSK identity.
 * @param pPskHint Optional PSK hint value.
 * @param pskHintLength Length of PSK hint value.
 * @param pPskSecret PSK as a byte array.
 * @param pskSecretLength Length of the PSK.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addIdentityPSK(certStorePtr pCertStore,
                                             const ubyte *pPskIdentity,
                                             ubyte4 pskIdentityLength,
                                             const ubyte *pPskHint,
                                             ubyte4 pskHintLength,
                                             const ubyte *pPskSecret,
                                             ubyte4 pskSecretLength);

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

/**
 * Add a trust point to a Mocana SoT Platform certificate store.
 * <p>This function adds a trust point to a Mocana SoT Platform certificate
 * store.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore Pointer to the SoT Platform certificate store to
 * which to add the trust point.
 * @param pDerTrustPoint Pointer to the trust point to add.
 * @param derTrustPointLength Number of bytes in the trust point
 * (\p pDerTrustPoint).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_addTrustPoint(certStorePtr pCertStore,
                                            const ubyte *pDerTrustPoint,
                                            ubyte4 derTrustPointLength);

#ifdef __ENABLE_DIGICERT_CV_CERT__

/**
 * Add a trust point to a Mocana SoT Platform certificate store.
 * <p>This function adds a trust point to a Mocana SoT Platform certificate
 * store.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_DIGICERT_CV_CERT__
 *
 * @param pCertStore Pointer to the SoT Platform certificate store to
 * which to add the trust point.
 * @param pTrustPoint Pointer to the trust point certificate in CVC format to add.
 * @param trustPointLength Number of bytes in the trust point
 * (\p pDerTrustPoint).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_CVC_addTrustPoint(certStorePtr pCertStore,
                                            const ubyte *pTrustPoint,
                                            ubyte4 trustPointLength);

#endif

/**
 * Find a trusted certificate by subject.
 * <p>This function retrieves a trusted certificate based on the subject name.
 * The search begins from the first trusted certificate. The caller passes in
 * the subject name to search by and the certificate and iterator object is
 * returned. The iterator object may be used with other certificate store APIs
 * to continue the search if the certificate found was not suitable.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore Pointer to the SoT Platform certificate store to search for
 * the certificate.
 * @param subject Pointer to the subject.
 * @param subjectLength Length of the subject in bytes.
 * @param ppRetDerCert Reference to the certificate found. This is an internal
 * reference. The caller should not modify this buffer. Value may be NULL if
 * no certificate is found.
 * @param pRetDerCertLength Length of the certificate found.
 * @param iterator The current iterator for the certificate found. Value may be
 * NULL if no certificate is found.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findTrustPointBySubjectFirst(const certStorePtr pCertStore,
                                                           const ubyte *subject,
                                                           ubyte4 subjectLength,
                                                           const ubyte **ppRetDerCert,
                                                           ubyte4 *pRetDerCertLength,
                                                           const void** iterator);

/**
 * This function continues a search for a certificate based on the iterator.
 * <p>This function is similar to CERT_STORE_findTrustPointBySubjectFirst, but
 * it will continue searching for certificates based on the iterator provided by
 * the caller.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param iterator Iterator object to start searching from.
 * @param ppRetDerCert Reference to the certificate found. This is an internal
 * reference. The caller should not modify this buffer. Value may be NULL if
 * no certificate is found.
 * @param pRetDerCertLength Length of the certificate found.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findTrustPointBySubjectNext(const void** iterator,
                                                         const ubyte **ppRetDerCert,
                                                         ubyte4* pRetDerCertLength);


/* test function: return OK if  match, ERR_FALSE if no match, anything else to
 stop the search */
/**
 * Certificate store callback.
 * <p>This callback is specified by the caller when calling certificate store
 * APIs. When searching through identities in the certificate store, there may
 * be attributes that the caller is looking for that are not stored in the
 * identity. The certificate store provides APIs where the caller may provide
 * a callback where the caller can parse the certificate and check whether the
 * certificate is suitable or not.
 * <p>If this API returns OK then the certificate store will return the identity
 * back to the caller, otherwise the certificate store will continue searching
 * through identities. Note that certificate store APIs may not all use the
 * callback in the same manner.
 *
 * @param arg User provided callback argument.
 * @param testCert The certificate found.
 * @param testCertLen The certificate length.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h.
 */
typedef MSTATUS (*CERT_STORE_MatchFun) (MOC_ASYM(hwAccelDescr hwAccelCtx)
                                        const void* arg,
                                        const ubyte* testCert,
                                        ubyte4 testCertLen);

/**
 * Find a trusted certificate by subject and user defined callback.
 * <p>This function retrieves a trusted certificate based on the subject name.
 * The search begins from the first trusted certificate. The caller passes in
 * the subject name to search by and a user defined callback which is used to
 * determine whether or not the certificate is a valid match or not. This API
 * does not provide a iterator object back to the caller because it will loop
 * through all of the identities and each subject match will invoke the callback
 * to check whether the certificate is suitable or not.
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore Pointer to the SoT Platform certificate store to search for
 * the certificate.
 * @param subject Pointer to the subject.
 * @param subjectLength Length of the subject in bytes.
 * @param cbArg Caller provided callback argument.
 * @param cb User defined callback to check whether certificate is suitable or
 * not.
 * @param ppRetDerCert Reference to the certificate found. This is an internal
 * reference. The caller should not modify this buffer. Value may be NULL if
 * no certificate is found.
 * @param pRetDerCertLength Length of the certificate found.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                                      const certStorePtr pCertStore,
                                                      const ubyte* subject,
                                                      ubyte4 subjectLength,
                                                      const void* cbArg,
                                                      CERT_STORE_MatchFun cb,
                                                      const ubyte** ppRetDerCert,
                                                      ubyte4* pRetDerCertLength);

/**
 * @cond
 */
MOC_EXTERN MSTATUS CERT_STORE_traverseTrustPoints(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                                  const certStorePtr pCertStore,
                                                  const void* cbArg,
                                                  CERT_STORE_MatchFun cb);
/**
 * @endcond
 */
#endif

/**
 * Find the identity in the cert store associated with the given "alias".
 * <p>The function will look through the given store, and compare the alias in
 * each entry with the one passed in. If it is the same, it will return the key
 * and cert from that entry.
 * <p>Note that an entry might have only a key or a cert, or both a key and cert.
 * <p>The function will return references to the key and cert insde the store, it
 * will not build a new AsymmetricKey object, nor will it allocate memory for the
 * cert it returns. Do not alter or uninit the key and do not alter or free the
 * cert buffer returned.
 * <p>If the function cannot find an entry with the given alias, it will set the
 * return key and cert args to NULL/0 and return OK. That is, if it finds no
 * entry, that is not an error, it simply indicates there is no entry with that
 * alias.
 * <p>You might only want a key, and not a cert. If so, you can pass NULL for the
 * ppRetDerCert and pRetDerCertLen args. That is not an error. The function will
 * return a reference to the key and not a cert. Similarly, you can pass NULL for
 * the key and receive only a cert.
 * <p>It is possible an entry has no key, only a cert. This function will return
 * a pointer to an AsymmetricKey, but it might be empty. Check the return key's
 * type. If it is 0 (akt_undefined), there is no key.
 * <p>Note that you might have stored a key and cert chain against the alias.
 * However, this function returns only a cert. It returns the first cert in the
 * chain (index 0), which is required to be the cert partner to the key.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pAlias The alias, or name of the entry, against which the cert will be
 * made.
 * @param aliasLen The length, in bytes, of the alias.
 * @param ppReturnIdentityKey If not NULL, the address where the function will
 * deposit a reference to the key object inside the cert store for the entry
 * associated with the alias.
 * @param ppRetDerCert If not NULL, the address where the function will deposit a
 * reference to the cert stored (or cert[0] if it contains a chain) in the entry
 * for the given alias.
 * @param pRetDerCertLength If not NULL, the address where the function will
 * deposit the length, in bytes, of the cert.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityByAlias (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct AsymmetricKey **ppReturnIdentityKey,
  ubyte **ppRetDerCert,
  ubyte4 *pRetDerCertLength
  );

/**
 * Find the identity in the cert store associated with the given "alias" and verify
 * it satisfies a given public key type, a given keyUsage,
 * and membership in a list of supported cert key algorithms,
 * and membership in a list of supported sign algorithms.
 * <p>The function will look through the given store, and compare the alias in
 * each entry with the one passed in. If it is the same, it will return the key
 * and cert from that entry.
 * <p>Note that an entry might have only a key or a cert, or both a key and cert.
 * <p>The function will return references to the key and cert insde the store, it
 * will not build a new AsymmetricKey object, nor will it allocate memory for the
 * cert it returns. Do not alter or uninit the key and do not alter or free the
 * cert buffer returned.
 * <p>If the function cannot find an entry with the given alias, it will set the
 * return key and cert args to NULL/0 and return OK. That is, if it finds no
 * entry, that is not an error, it simply indicates there is no entry with that
 * alias.
 * <p>You might only want a key, and not a cert. If so, you can pass NULL for the
 * ppRetDerCert and pRetDerCertLen args. That is not an error. The function will
 * return a reference to the key and not a cert. Similarly, you can pass NULL for
 * the key and receive only a cert.
 * <p>It is possible an entry has no key, only a cert. This function will return
 * a pointer to an AsymmetricKey, but it might be empty. Check the return key's
 * type. If it is 0 (akt_undefined), there is no key.
 * <p>Note that you might have stored a key and cert chain against the alias.
 * However, this function returns only a cert. It returns the first cert in the
 * chain (index 0), which is required to be the cert partner to the key.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param keyUsage The key usage bits to search for in the certificate.
 * @param pSupportedCertKeyAlgos An array of supported algorithm Ids
 * for the certificate key. Pass in \c NULL if all
 * ids are supported or support information is not relevant. The hashId bits
 * of values in this array will be ignored.
 * @param supportedCertKeyAlgosLen The number of algorithm ids in the \c pSupportedCertKeyAlgos array.
 * @param pSupportedSignAlgos An array of supported algorithm Ids
 * for the signing algorithm. Pass in \c NULL if all
 * ids are supported or support information is not relevant.
 * @param supportedSignAlgosLen The number of algorithm ids in the \c pSupportedSignAlgos array.
 * @param pAlias The alias, or name of the entry, against which the cert will be
 * made.
 * @param aliasLen The length, in bytes, of the alias.
 * @param ppReturnIdentityKey If not NULL, the address where the function will
 * deposit a reference to the key object inside the cert store for the entry
 * associated with the alias.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityByAliasAndAlgo (
  certStorePtr pCertStore,
  ubyte4 pubKeyType,
  ubyte2 keyUsage,
  ubyte4 *pSupportedCertKeyAlgos,
  ubyte4 supportedCertKeyAlgosLen,
  ubyte4 *pSupportedSignAlgos,
  ubyte4 supportedSignAlgosLen,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct AsymmetricKey **ppReturnIdentityKey,
  struct SizedBuffer **ppRetCertificates,
  ubyte4 *pRetNumCertificates,
  void **ppRetHint
  );

/* Find the identity in the cert store associated with the given "alias".
 * <p>The function will look through the given store, and compare the alias in
 * each entry with the one passed in. If it is the same, it will return the key
 * and cert chain from that entry.
 * <p>Note that an entry might have only a key or a cert, or both a key and cert.
 * <p>The function will return references to the key and cert insde the store, it
 * will not build a new AsymmetricKey object, nor will it allocate memory for the
 * cert it returns. Do not alter or uninit the key and do not alter or free the
 * cert buffer returned.
 * <p>If the function cannot find an entry with the given alias, it will set the
 * return key and cert chain args to NULL/0 and return OK. That is, if it finds no
 * entry, that is not an error, it simply indicates there is no entry with that
 * alias.
 * <p>You might only want a key, and not a cert. If so, you can pass NULL for the
 * ppRetDerCert and pRetDerCertLen args. That is not an error. The function will
 * return a reference to the key and not a cert. Similarly, you can pass NULL for
 * the key and receive only a cert chain.
 * <p>It is possible an entry has no key, only a cert. This function will return
 * a pointer to an AsymmetricKey, but it might be empty. Check the return key's
 * type. If it is 0 (akt_undefined), there is no key.
 *
 * @param pCertStore The store to search.
 * @param pAlias The alias, or name of the entry, against which the cert will be
 * made.
 * @param aliasLen The length, in bytes, of the alias.
 * @param ppReturnIdentityKey If not NULL, the address where the function will
 * deposit a reference to the key object inside the cert store for the entry
 * associated with the alias.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit a reference to the cert chain corresponding to the entry.
 * for the given alias.
 * @param pRetNumCertificates If not NULL, the address where the function will
 * deposit the number of certificates in the returned chain.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityByAliasEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct AsymmetricKey **ppReturnIdentityKey,
  struct SizedBuffer **ppRetCertificates,
  ubyte4 *pRetNumCertificates
  );

MOC_EXTERN MSTATUS CERT_STORE_updateIdentityByAliasExtData (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *pCertChain,
  ubyte4 certChainCount,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLen,
  ExtendedDataCallback extDataFunc,
  sbyte4 extDataIdentifier
  );

MOC_EXTERN MSTATUS CERT_STORE_getIdentityPairExtData (
  void *pIdentity,
  ExtendedDataCallback *pExtDataFunc,
  sbyte4 *pExtDataIdentifier
);

MOC_EXTERN MSTATUS CERT_STORE_updateIdentityByAlias (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *pCertChain,
  ubyte4 certChainCount,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLen
  );

/**
 * Retrieve the first identity stored for the specified auth type and identity
 * type.
 * <p>This function retrieves the first identity stored in certificate store for
 * the specified auth type and identity type.
 * <p>For auth types look at the authTypes enum in cert_store.h and for the
 * identity type look at identityTypes enum in cert_store.h. This API retrieves
 * the certificate and key pair stored in the certificate store for the found
 * identity. The hint that is retrieved from this API may be used in other
 * certificate store APIs to start a search from the specified hint. If the
 * first identity does meet the callers criteria then they may use the hint to
 * continue searching for a similar identity.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param authType The authentication type. Look at cert_store.h regarding this
 * enum.
 * @param identityType The identity type. Look at cert_store.h regarding this
 * enum.
 * @param ppRetIdentityKey If not NULL, the address where the function will
 * deposit a reference to the key object inside the cert store for the entry
 * associated with the alias.
 * @param ppRetDerCert If not NULL, the address where the function will deposit
 * a reference to the cert stored (or cert[0] if it contains a chain) in the
 * entry for the given alias.
 * @param pRetDerCertLength If not NULL, the address where the function will
 * deposit the length, in bytes, of the cert.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityByTypeFirst(const certStorePtr pCertStore,
                                                      enum authTypes authType,
                                                      enum identityTypes identityType,
                                                      const struct AsymmetricKey** ppRetIdentityKey,
                                                      const ubyte **ppRetDerCert,
                                                      ubyte4 *pRetDerCertLength,
                                                      void** ppRetHint);

/**
 * This function continues the search for a hint. The hint is mandatory.
 * <p>This function is similar to CERT_STORE_findIdentityByTypeFirst but instead
 * of stopping at the first match, the caller must provide a starting hint
 * (through CERT_STORE_findIdentityByTypeFirst or another certificate store API)
 * which will be used as the starting point.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param authType The authentication type. Look at cert_store.h regarding this
 * enum.
 * @param identityType The identity type. Look at cert_store.h regarding this
 * enum.
 * @param ppRetIdentityKey If not NULL, the address where the function will
 * deposit a reference to the key object inside the cert store for the entry
 * associated with the alias.
 * @param ppRetDerCert If not NULL, the address where the function will deposit
 * a reference to the cert stored (or cert[0] if it contains a chain) in the
 * entry for the given alias.
 * @param pRetDerCertLength If not NULL, the address where the function will
 * deposit the length, in bytes, of the cert.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityByTypeNext(const certStorePtr pCertStore,
                                                     enum authTypes authType,
                                                     enum identityTypes identityType,
                                                     const struct AsymmetricKey** ppRetIdentityKey,
                                                     const ubyte **ppRetDerCert,
                                                     ubyte4 *pRetDerCertLength,
                                                     void** ppRetHint);

/**
 * Retrieve the first identity stored for the specified key type and supported
 * algorithm.
 * <p>The caller may use this API to search for a particular identity based on
 * the key type and supported algorithm.
 * <p>The key type specifies the algorithm to search for. These key types will
 * be the akt_* key values defined in ca_mgmt.h.
 * <p>To further limit the search the caller must pass in a supported algorithm
 * flags bit field. For further information on these bit fields look at the
 * CERT_STORE_ALGO_* flags defined in cert_store.h. Note that this bit field is
 * both for limiting the search based on certificate and key information.
 * <p>The certificate and key pair search is also limited on the usage bits set
 * in the certificate itself. The caller may query for particular bits set in
 * the certificate such as the digital signature, key encipherment bit, etc.
 * The key usage bits can be found in parsecert.h. The key usage bit should be
 * an ORing of the bits. For example
 *
 *   (1 << digitalSignature) | (1 << keyEncipherment)
 *
 * This API will perform an exact match against the key usage bits.
 * <p>On return, if a valid identity is found based on the algorithms provided,
 * the certificate(s) and key will be returned as well as the hint which the
 * caller may use to continue the search if the identity found is not suitable.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param keyUsage The key usage bits to search for in the certificate.
 * @param supportedAlgoFlags Bit field which can specify both certificate and
 * key algorithms to look for.
 * @param ppRetIdentityKey If not NULL, the address where the function will deposit
 * a reference to the private key.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityCertChainFirstEx(const certStorePtr pCertStore,
                                                           ubyte4 pubKeyType,
                                                           ubyte2 keyUsage,
                                                           ubyte4 supportedAlgoFlags,
                                                           const struct AsymmetricKey** ppRetIdentityKey,
                                                           const struct SizedBuffer** ppRetCertificates,
                                                           ubyte4 *pRetNumberCertificate,
                                                           void** ppRetHint);

/**
 * Continue the search for an identity from the hint provided. The caller must
 * provide a hint.
 * <p>This function is the same as CERT_STORE_findIdentityCertChainFirstEx but
 * it will continue the search from the hint provided. A typical flow would
 * be to call CERT_STORE_findIdentityCertChainFirstEx first to get an identity,
 * check whether that identity is suitable or not, and if it is not suitable
 * then call this API with the hint retrieved from
 * CERT_STORE_findIdentityCertChainFirstEx to continue searching. This API will
 * update the hint value provided as new matches are found.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param keyUsage The key usage bits to search for in the certificate.
 * @param supportedAlgoFlags Bit field which can specify both certificate and
 * key algorithms to look for.
 * @param ppRetIdentityKey If not NULL, the address where the function will deposit
 * a reference to the private key.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint Hint which specifies where to begin the search from.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityCertChainNextEx(const certStorePtr pCertStore,
                                                          ubyte4 pubKeyType,
                                                          ubyte2 keyUsage,
                                                          ubyte4 supportedKeyTypeAndAlgoFlags,
                                                          const struct AsymmetricKey** ppRetIdentityKey,
                                                          const struct SizedBuffer** ppRetCertificates,
                                                          ubyte4 *pRetNumberCertificate,
                                                          void** ppRetHint);



/**
 * Retrieve the first identity stored for the specified key type and supported
 * algorithms.
 * <p>The caller may use this API to search for a particular identity based on
 * the key type and supported algorithms for either the certificate key, the
 * signing algorithm, or both.
 * <p>The key type specifies the certificate key type to search for. These key types will
 * be the akt_* key values defined in ca_mgmt.h.
 * <p>To further limit the search the caller may pass in two arrays of supported
 * algorithm ids. One is for the certificate key and one is for the signing algorithm.
 * One may pass in NULL if all keys/algorithms are supported or if support information
 * is not relevant. Each id in the array should be a 32 bit value. The first 8 bits are
 * the keytype as give in ca_mgmt.h. For non-quantum hybrid choices the next 8 bits are
 * the hash algorithm used as given in crypto.h. For ECC based algos the last 8 bits
 * are the curveId as given in ca_mgmt.h. For quantum-safe hybrid choices the middle
 * 16 bits are the quantum-safe identifier as given in ca_mgmt.h with the last
 * 8 bits being the curve identifier. For the certificate key array the hashAlgo bits will
 * be ignored. This will allow callers to pass in the same array for both the
 * the signing algorithm and certificate key in most use cases.
 *
 * <p>On return, if a valid identity is found based on the algorithms provided,
 * the certificate(s) and key will be returned as well as the hint which the
 * caller may use to continue the search if the identity found is not suitable.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param keyUsage The key usage bits to search for in the certificate.
 * @param pSupportedCertKeyIds An array of supported algorithm Ids
 * for the certificate key. Pass in \c NULL if all
 * ids are supported or support information is not relevant. The hashId bits
 * of values in this array will be ignored.
 * @param supportedCertKeyIdsLen The number of algorithm ids in the \c pSupportedCertKeyIds array.
 * @param pSupportedSignAlgoIds An array of supported algorithm Ids
 * for the signing algorithm. Pass in \c NULL if all
 * ids are supported or support information is not relevant.
 * @param supportedSignAlgoIdsLen The number of algorithm ids in the \c pSupportedSignAlgoIds array.
 * @param ppRetIdentityKey If not NULL, the address where the function will deposit
 * a reference to the private key.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityCertChainFirstFromList(
                                                           const certStorePtr pCertStore,
                                                           ubyte4 pubKeyType,
                                                           ubyte2 keyUsage,
                                                           ubyte4 *pSupportedCertKeyIds,
                                                           ubyte4 supportedCertKeyIdsLen,
                                                           ubyte4 *pSupportedSignAlgoIds,
                                                           ubyte4 supportedSignAlgoIdsLen,
                                                           const struct AsymmetricKey** ppRetIdentityKey,
                                                           const struct SizedBuffer** ppRetCertificates,
                                                           ubyte4 *pRetNumberCertificate,
                                                           void** ppRetHint);


/**
 * Continue the search for an identity from the hint provided. The caller must
 * provide a hint.
 * <p>This function is the same as \c CERT_STORE_findIdentityCertChainFirstFromList but
 * it will continue the search from the hint provided. A typical flow would
 * be to call \c CERT_STORE_findIdentityCertChainFirstFromList first to get an identity,
 * check whether that identity is suitable or not, and if it is not suitable
 * then call this API with the hint retrieved from
 * \c CERT_STORE_findIdentityCertChainFirstFromList to continue searching. This API will
 * update the hint value provided as new matches are found.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param keyUsage The key usage bits to search for in the certificate.
 * @param pSupportedCertKeyIds An array of supported algorithm Ids
 * for the certificate key. Pass in \c NULL if all
 * ids are supported or support information is not relevant. The hashId bits
 * of values in this array will be ignored.
 * @param supportedCertKeyIdsLen The number of algorithm ids in the \c pSupportedCertKeyIds array.
 * @param pSupportedSignAlgoIds An array of supported algorithm Ids
 * for the signing algorithm. Pass in \c NULL if all
 * ids are supported or support information is not relevant.
 * @param supportedSignAlgoIdsLen The number of algorithm ids in the \c pSupportedSignAlgoIds array.
 * @param ppRetIdentityKey If not NULL, the address where the function will deposit
 * a reference to the private key.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint Hint which specifies where to begin the search from.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityCertChainNextFromList(
                                                          const certStorePtr pCertStore,
                                                          ubyte4 pubKeyType,
                                                          ubyte2 keyUsage,
                                                          ubyte4 *pSupportedCertKeyIds,
                                                          ubyte4 supportedCertKeyIdsLen,
                                                          ubyte4 *pSupportedSignAlgoIds,
                                                          ubyte4 supportedSignAlgoIdsLen,
                                                          const struct AsymmetricKey** ppRetIdentityKey,
                                                          const struct SizedBuffer** ppRetCertificates,
                                                          ubyte4 *pRetNumberCertificate,
                                                          void** ppRetHint);

/**
 * Retrieve the first identity stored for the specified key type and supported
 * algorithm.
 * <p>This API is the same CERT_STORE_findIdentityCertChainFirstEx but does
 * allow the caller to specify the key usage bits.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param supportedAlgoFlags Bit field which can specify both certificate and
 * key algorithms to look for.
 * @param ppRetIdentityKey If not NULL, the address where the function will deposit
 * a reference to the private key.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityCertChainFirst(const certStorePtr pCertStore,
                                                             ubyte4 pubKeyType,
                                                             ubyte4 supportedAlgoFlags,
                                                             const struct AsymmetricKey** ppRetIdentityKey,
                                                             const struct SizedBuffer** ppRetCertificates,
                                                             ubyte4 *pRetNumberCertificate,
                                                             void** ppRetHint);

/**
 * Continue the search for an identity from the hint provided. The caller must
 * provide a hint.
 * <p>This API is the same CERT_STORE_findIdentityCertChainNextEx but does
 * allow the caller to specify the key usage bits.
 *
 * @ingroup cert_store_functions
 *
 * @param pCertStore The store to search.
 * @param pubKeyType The algorithm of the private key to search for.
 * @param supportedAlgoFlags Bit field which can specify both certificate and
 * key algorithms to look for.
 * @param ppRetIdentityKey If not NULL, the address where the function will deposit
 * a reference to the private key.
 * @param ppRetCertificates If not NULL, the address where the function will
 * deposit the certificates found.
 * @param pRetNumberCertificate If not NULL, the address where the function will
 * deposit the number of certificates found.
 * @param ppRetHint If not NULL, the address where the first identity will be
 * stored.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CERT_STORE_findIdentityCertChainNext(const certStorePtr pCertStore,
                                                            ubyte4 pubKeyType,
                                                            ubyte4 supportedKeyTypeAndAlgoFlags,
                                                            const struct AsymmetricKey** ppRetIdentityKey,
                                                            const struct SizedBuffer** ppRetCertificates,
                                                            ubyte4 *pRetNumberCertificate,
                                                            void** ppRetHint);

/**
 * @cond
 */
/* traverse/find a psk */
MOC_EXTERN MSTATUS CERT_STORE_traversePskListHead(const certStorePtr pCertStore,
                                                  ubyte **ppRetPskIdentity,
                                                  ubyte4 *pRetPskIdentityLength,
                                                  ubyte **ppRetPskHint,
                                                  ubyte4 *pRetPskHintLength,
                                                  ubyte **ppRetPskSecret,
                                                  ubyte4 *pRetPskSecretLength,
                                                  void** ppRetHint);
MOC_EXTERN MSTATUS CERT_STORE_traversePskListNext(const certStorePtr pCertStore,
                                                  ubyte **ppRetPskIdentity,
                                                  ubyte4 *pRetPskIdentityLength,
                                                  ubyte **ppRetPskHint,
                                                  ubyte4 *pRetPskHintLength,
                                                  ubyte **ppRetPskSecret,
                                                  ubyte4 *pRetPskSecretLength,
                                                  void** ppRetHint);
MOC_EXTERN MSTATUS CERT_STORE_findPskByIdentity(const certStorePtr pCertStore,
                                                ubyte *pPskIdentity,
                                                ubyte4 pskIdentityLength,
                                                ubyte **ppRetPskSecret,
                                                ubyte4 *pRetPskSecretLength);
/**
 * @endcond
 */

/* find a certificate and possibly key by issuer/serial number */
/**
 * Retrieve the certificate and associated private key if available.
 * <p>
 *
 * @ingroup cert_store_functions
 * @flags
 * To enable this function, the following flag must \b NOT be defined:
 * + \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__
 *
 * @param pCertStore The store to search.
 * @param pIssuer The bytestring representation of the certificate issuer.
 * @param issuerLength The length in bytes of the issuer data.
 * @param serialNumber The serial number of the certificate to be found.
 * @param serialNumberLength The length in bytes of the serial number.
 * @param ppRetDerCert If not NULL, the address where the function will deposit
 * a reference to the cert stored (or cert[0] if it contains a chain) in the
 * entry for the given issuer and serial number.
 * @param pRetDerCertLength If not NULL, the address where the function will
 * deposit the length, in bytes, of the cert.
 * @param pRetPrivateKey If not NULL, the address where the function will
 * deposit a reference to the key object inside the cert store for the entry
 * associated with the given issuer and serial number if available.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
CERT_STORE_findCertificateByIssuerSerialNumber(const certStorePtr pCertStore,
                                               const ubyte* pIssuer,
                                               ubyte4 issuerLength,
                                               const ubyte* serialNumber,
                                               ubyte4 serialNumberLength,
                                               const ubyte** ppRetDerCert,
                                               ubyte4* ppRetDerCertLength,
                                               const struct AsymmetricKey** pRetPrivateKey);

#if defined(__ENABLE_DIGICERT_MINIMAL_CA__)

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS
CERT_STORE_createIssuerStore(sbyte *pDirPath, certStoreIssuerPtr *pStore);

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS
CERT_STORE_releaseIssuerStore(certStoreIssuerPtr *pStore);

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS
CERT_STORE_traverseChildCertsByFile(
    certStoreIssuerPtr pStore, void **ppCookie, ubyte4 *pIndex, sbyte **ppFile);

#endif /* __ENABLE_DIGICERT_MINIMAL_CA__ */

#ifdef __cplusplus
}
#endif

#endif /* __CERT_STORE_HEADER__ */

/**
@endcond
*/
