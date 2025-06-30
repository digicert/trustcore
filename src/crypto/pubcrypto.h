/*
 * pubcrypto.h
 *
 * General Public Crypto Definitions & Types Header
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
@file       pubcrypto.h
@filedoc    pubcrypto.h
 */

/*------------------------------------------------------------------*/

#ifndef __PUBCRYPTO_HEADER__
#define __PUBCRYPTO_HEADER__

#include "../cap/capasym.h"
#include "../crypto/cryptodecl.h"
#include "../crypto_interface/crypto_interface_qs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
struct ECCKey;
struct PrimeEllipticCurve;
#endif

struct RSAKey;

#if (defined(__ENABLE_MOCANA_DSA__))
struct DSAKey;
#endif
struct AsymmetricKey;
struct vlong;
struct MAlgoId;

typedef struct AsymmetricKey
{
    ubyte4 type;
    union
    {
        struct RSAKey* pRSA;
#if (defined(__ENABLE_MOCANA_ECC__))
        struct ECCKey* pECC;
#endif
#if (defined(__ENABLE_MOCANA_DSA__))
        struct DSAKey* pDSA;
#endif
        struct MocAsymmetricKey *pMocAsymKey;
    } key;
    
    struct MAlgoId *pAlgoId;
    QS_CTX *pQsCtx;
    ubyte4 clAlg; /* classical algorithm id for hybrid keys */
    
} AsymmetricKey;

/* General structure that can be used to load two keys at once */
typedef struct HybridKey
{
	void *pKey1;
	void *pKey2;
  ubyte4 clAlg;
	
} HybridKey;

/**
 * @brief Initialize a caller allocated AsymmetricKey. CRYPTO_uninitAsymmetricKey
 *        should be called once the key is no longer needed.
 * @note  This function does not allocate the AsymmetricKey structure, the
 *        caller is responsible for that.
 *
 * @param pKey Pointer to the AsymmetricKey to be initialized.
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_initAsymmetricKey(AsymmetricKey* pKey);

/**
 * @brief Uninitialize an AsymmetricKey.
 *
 * @param pKey Pointer to the AsymmetricKey to be uninitialized.
 * @param ppVlongQueue Optional pointer to a vlong queue. When freeing RSA and DSA keys, the
 *                     underlying vlongs will be placed into this queue so other operations
 *                     can just use the memory from the queue instead of allocating new memory.
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_uninitAsymmetricKey(AsymmetricKey* pKey, struct vlong** ppVlongQueue);

/**
 * @brief Copy the contents an AsymmetricKey to another caller allocated AsymmetricKey
 *
 * @param pNew Pointer to the caller allocated AsymmetricKey that will be filled
 *             with the contents of the source key.
 * @param pSrc Pointer to the key to be copied.
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_copyAsymmetricKey(AsymmetricKey* pNew, const AsymmetricKey* pSrc);

/**
 * @brief Determine if two AsymmetricKey structures contain the same key values.
 *
 * @param pKey1 Key to be compared with key2.
 * @param pKey2 Key to be compared with key1.
 * @return     \c OK (0) if keys are equal, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_matchPublicKey(const AsymmetricKey* pKey1, const AsymmetricKey* pKey2);

#if (defined(__ENABLE_MOCANA_ECC__))

/**
 * @brief Get the ECC curveId from an AsymmetricKey.
 *
 * @param pKey Pointer to the AsymmetricKey containing an ECC
 *             from which to retrieve the curveId.
 * @return     One of the nonzero curveId as defined in ca_mgmt.h on success,
 *             zero on failure.
 */
MOC_EXTERN ubyte4   CRYPTO_getECCurveId( const AsymmetricKey* pKey);
#endif

/**
 * @brief Populate an existing AsymmetricKey structure with a new RSA key.
 *
 * @param pKey         Pointer to a caller allocated AsymmetricKey structure to be
 *                     populated with a new RSA key.  If the structure already contains
 *                     another key it will be cleared before populating with the
 *                     new RSA key data.
 * @param ppVlongQueue Optional pointer to a vlong queue that will be used for
 *                     the underlying RSA key creation.
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_createRSAKey( AsymmetricKey* pKey, struct vlong** ppVlongQueue);

/**
 * @brief Populate an existing AsymmetricKey structure with the provided RSA key data.
 *
 * @param pKey         Pointer to the caller allocated AsymmetricKey structure to
 *                     be populated.
 * @param exponent     RSA public key exponent.
 * @param modulus      Pointer to a buffer containing the modulus, represented as
 *                     a buffer of bytes in big endian format.
 * @param modulusLen   Length in bytes of the modulus material.
 * @param p            Pointer to a buffer containing first prime number for RSA
 *                     key calculation.  If both primes and associated lengths are not
 *                     provided, only the public key data will be set.
 * @param pLen         Length in bytes of the first prime number.
 * @param q            Pointer to a buffer containing second prime number for RSA
 *                     key calculation.  If both primes and associated lengths are not
 *                     provided, only the public key data will be set.
 * @param qLen         Length in bytes of the second prime number.
 * @param ppVlongQueue Optional pointer to a vlong queue to use for this operation.
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_setRSAParameters(MOC_RSA(hwAccelDescr hwAccelCtx)
                                        AsymmetricKey* pKey,
                                        ubyte4 exponent,
                                        const ubyte* modulus,
                                        ubyte4 modulusLen,
                                        const ubyte* p,
                                        ubyte4 pLen,
                                        const ubyte* q,
                                        ubyte4 qLen,
                                        struct vlong **ppVlongQueue);
/* ECC key */
#if (defined(__ENABLE_MOCANA_ECC__))

/**
 * @brief Populate a caller allocated AsymmetricKey structure with a
 *        new empty ECC key.
 * @note  This function should not be used with the cryptointerface,
 *        use CRYPTO_createECCKeyEx instead.
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_MOCANA_ECC__
 *
 * @param pKey Pointer to a caller allocated AsymmetricKey structure
 *             to be populated.
 * @param pEC  One of the prime elliptic curve pointers specifying the
 *             curve to use for key creation. The declarations for the
 *             various prime curves can be found in primeec.h.
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_createECCKey(
    AsymmetricKey* pKey,
    PEllipticCurvePtr pEC
    );

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
/**
 * @brief Populate a caller allocated AsymmetricKey structure with a
 *        new empty ECC key.
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_MOCANA_ECC__
 * + \c \__ENABLE_MOCANA_CRYPTO_INTERFACE__
 *
 * @param pKey        Pointer to a caller allocated AsymmetricKey structure
 *                    to be populated.
 * @param eccCurveId  The curveId to use for key creation.
 * @return            \c OK (0) if successful, otherwise a negative number
 *                    error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_createECCKeyEx(
    AsymmetricKey *pKey,
    ubyte4 eccCurveId
    );
#endif

/**
 * @brief Populate a caller allocated AsymmetricKey structure with the provided
 *        ECC key data.
 *
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_MOCANA_ECC__
 *
 * @param pKey      Pointer to a caller allocated AsymmetricKey
 *                  structure to be populated.
 * @param curveId   The curveId specifying which curve to use.
 * @param point     The public point data.
 * @param pointLen  Length in bytes of the point data.
 * @param scalar    The private scalar data.
 * @param scalarLen Length in bytes of the scalar data.
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_setECCParameters(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
                                        ubyte4 curveId,
                                        const ubyte* point,
                                        ubyte4 pointLen,
                                        const ubyte* scalar,
                                        ubyte4 scalarLen);
    
/**
 * @brief Populate a caller allocated AsymmetricKey structure with the provided
 *        hybrid public key data.
 *
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_MOCANA_ECC__
 * + \c \__ENABLE_MOCANA_PQC__
 *
 * @param pKey      Pointer to a caller allocated AsymmetricKey
 *                  structure to be populated.
 * @param clAlgId   The classical algorithm identifier from ca_mgmt.h.
 * @param qsAlgId   The quantum safe algorithm identifier from ca_mgmt.h.
 * @param pPubKey   The hybrid public key consisting of an ECC point followed
 *                  by the QS public key.
 * @param pubKeyLen Length in bytes of the hybrid public key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_setHybridParameters(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    ubyte4 clAlgId,
    ubyte4 qsAlgId,
    ubyte *pPubKey,
    ubyte4 pubKeyLen
    );
#endif /* __ENABLE_MOCANA_ECC__ */

#if (defined(__ENABLE_MOCANA_DSA__))

/**
 * @brief Populate an existing AsymmetricKey structure with a new DSA key.
 *
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_MOCANA_DSA__
 *
 * @param pKey         Pointer to a caller allocated AsymmetricKey structure to be
 *                     populated with a new DSA key. If the structure already contains
 *                     another key it will be cleared before being re-populated.
 * @param ppVlongQueue Optional pointer to a vlong queue that will be used for
 *                     the underlying DSA key creation.
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_createDSAKey( AsymmetricKey* pKey, struct vlong** ppVlongQueue);

/**
 * @brief Populate an existing AsymmetricKey structure with a new DSA key and sets all
 *        of the DSA key parameters.
 *
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_MOCANA_DSA__
 *
 * @param pKey         Pointer to a caller allocated AsymmetricKey structure to be
 *                     populated with a new DSA key and its parameters. If the
 *                     structure already contains another key it will be cleared
 *                     before being re-populated.
 * @param p            Buffer holding the DSA prime p as a Big Endian byte array.
 * @param pLen         The length of p in bytes.
 * @param q            Buffer holding the DSA cyclic group order q as a Big Endian
 *                     byte array.
 * @param qLen         The length of q in bytes.
 * @param g            Buffer holding the DSA cyclic group generator g as a Big Endian
 *                     byte array.
 * @param gLen         The legnth of q in bytes.
 * @param y            Optional. Buffer holding the DSA public key y as a Big Endian
 *                     byte array.
 * @param yLen         The length of y in bytes.
 * @param x            Optional. Buffer holding the DSA private key x as a Big Endian
 *                     byte array.
 * @param xLen         The length of x in bytes.
 * @param ppVlongQueue Optional. Pointer to a vlong queue that will be used for
 *                     the underlying DSA key creation.
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS  CRYPTO_setDSAParameters( MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
                                        const ubyte* p,
                                        ubyte4 pLen,
                                        const ubyte* q,
                                        ubyte4 qLen,
                                        const ubyte* g,
                                        ubyte4 gLen,
                                        const ubyte* y,
                                        ubyte4 yLen,
                                        const ubyte* x,
                                        ubyte4 xLen,
                                        struct vlong **ppVlongQueue);
#endif

/* To convert a key object to a single byte array (serialize), call
 * CRYPTO_serializeKey.
 * To convert the byte array version of the key to a key object (deserialize),
 * call CRYPTO_deserializeKey.
 * The serialize function takes an AsymmetricKey as a the key object to
 * serialize. However, you might not have the key in that form. It might be an
 * RSAKey, DSAKey, ECCKey, or MocAsymKey. To "convert" an "algorithm key" to an
 * AsymmetricKey, call CRYPTO_loadAsymmetricKey
 */

/** Load the AlgKey into the AsymKey, transferring ownership to the AsymKey.
 * <p>The caller passes in an existing but empty AsymmetricKey, along with an
 * algorithm key (RSAKey, DSAKey, ECCKey, MocAsymKey). The function will set the
 * AsymKey with the AlgKey. But it will also take ownership, so that when
 * CRYPTO_uninitAsymmetricKey is called, that function will destroy the algorithm
 * key.
 * <p>For example, suppose you build an RSAKey. Maybe you called RSA_createKey,
 * and RSA_generateKey, or RSA_cloneKey. Normaly, you would perform operations on
 * that object and then when done with it call RSA_freeKey.
 * <p>However, there is a function you want to call that takes an AsymmetricKey
 * as an argument, not an RSAKey. So you need to "convert" your RSAKey into an
 * AsymmetricKey. To do so, call this load function.
 * <p>You pass in the empty AsymKey, along with the algorithm key and its type.
 * The function will load the algorithm key and take ownership. You actually pass
 * in the address of the pointer to the algorithm key. The function will go to
 * that address and find the key to load, load it, and then set that address to
 * NULL, indicating that you no longer have direct control of that key, and if
 * you called freeKey, it would not destroy it, because you would be calling
 * freeKey on a NULL.
 * <p>For example,
 * <pre>
 * <code>
 *   RSAKey *pRSAKey = NULL;
 *   AsymmetricKey asymKey;
 *
 *   status = CRYPTO_initAsymmetricKey (&asymKey);
 *   if (OK != status)
 *     goto exit;
 *
 *   status = RSA_createKey (&pRSAKey);
 *   if (OK != status)
 *     goto exit;
 *
 *   status = RSA_generateKey (randCtx, pRSAKey, 2048, NULL);
 *   if (OK != status)
 *     goto exit;
 *
 *   status = CRYPTO_loadAsymmetricKey (
 *     &asymKey, akt_rsa, (void **)&pRSAKey);
 *   if (OK != status)
 *     goto exit;
 *
 *   // At this point, if the load succeeded, pRSAKey is NULL.
 *
 *   < rest of operation >
 *
 * exit:
 *   RSA_freeKey (&pRSAKey, NULL);
 *   CRYPTO_uninitAsymmetricKey (&asymKey, NULL);
 * </code>
 * </pre>
 * <p>In the above example, the exit code calls RSA_freeKey because you called
 * RSA_createKey. If the load succeeded, the pointer pRSAKey points to NULL, so
 * the freeKey call will do nothing. So why call freeKey? Because suppose
 * something went wrong during the call to RSA_generateKey, then you would have
 * never loaded the RSAKey, but it would still need to be freed.
 * <p>Note that the keyType is one of the akt_ enum values.
 * <p>The third argument is a pointer to pointer. Functions with such an argument
 * are generally constructors or destructors (alloc and free). This is definitely
 * not a constructor, but it isn't exactly a destructor. But it is similar to a
 * destructor in that once you run this function, you no longer have any direct
 * responsibility for the AlgKey.
 *
 * @param pAsymKey The key object that will take control of the algorithm key.
 * @param keyType The type of the key, one of the akt_ enum values.
 * @param ppAlgKey The address of an algorithm key object, such as RSAKey,
 * DSAKey, etc.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_loadAsymmetricKey (
  AsymmetricKey *pAsymKey,
  ubyte4 keyType,
  void **ppAlgKey
  );

MOC_EXTERN MSTATUS CRYPTO_loadAlgoId (
  AsymmetricKey *pAsymKey,
  void **ppAlgoId
  );

/** This is what an MKeySerialize really is.
 * <p>For the serialize and deserialize key functions, you specify which
 * algorithms you support by passing in an array of MKeySerialize. This is what
 * that type is.
 * <p>Although an MKeySerialize is a function pointer, do not call one directly,
 * only pass them as arguments to the serialize and deserialize functions.
 * <p>The actual MKeySerialize you pass to the functions will be declared as
 * KeySerialize*, such as KeySerializeRsa, KeySerializeEcc, or KeySerializeDsa.
 * <p>Note that there is no implementation of MKeySerializ such as
 * KeySerializeMocAsymKey that serializes and deserializes mocasym keys. That is
 * because a MocAsymKey knows how to serialize and deserialize itself. For
 * deserializing into a MocAsymKey, see the documentation for
 * CRYPTO_deserializeKey.
 */
typedef MSTATUS (*MKeySerialize) ( MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

/** This is an implementation of MKeySerialize. It knows how to serialize and
 * deserialize an RSA key.
 * <p>Although this is a function, do not call it directly, only use it as a
 * member of the array you pass to the serialize or deserialize functions.
 */
MOC_EXTERN MSTATUS KeySerializeRsa ( MOC_ASYM(hwAccelDescr )
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

/** This is an implementation of MKeySerialize. It knows how to serialize and
 * deserialize a DSA key.
 * <p>Although this is a function, do not call it directly, only use it as a
 * member of the array you pass to the serialize or deserialize functions.
 */
MOC_EXTERN MSTATUS KeySerializeDsa ( MOC_ASYM(hwAccelDescr )
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

/** This is an implementation of MKeySerialize. It knows how to serialize and
 * deserialize an ECC key.
 * <p>Although this is a function, do not call it directly, only use it as a
 * member of the array you pass to the serialize or deserialize functions.
 */
MOC_EXTERN MSTATUS KeySerializeEcc ( MOC_ASYM(hwAccelDescr )
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

/** This is an implementation of MKeySerialize. It knows how to serialize and
 * deserialize a quantum safe key (QS ctx).
 * <p>Although this is a function, do not call it directly, only use it as a
 * member of the array you pass to the serialize or deserialize functions.
 */
MOC_EXTERN MSTATUS KeySerializeQs (MOC_ASYM(hwAccelDescr ) 
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

/** This is an implementation of MKeySerialize. It knows how to serialize and
 * deserialize a hybrid key made up of an ECC key and an QS ctx.
 * <p>Although this is a function, do not call it directly, only use it as a
 * member of the array you pass to the serialize or deserialize functions.
 */
MOC_EXTERN MSTATUS KeySerializeHybrid (MOC_ASYM(hwAccelDescr ) 
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

MOC_EXTERN MSTATUS KeySerializeTpmRsa (
  AsymmetricKey *, serializedKeyFormat, ubyte **, ubyte4 *);

/** Serialize an asymmetric key. This will "convert" the key object into a single
 * byte array.
 * <p>An ASymmetricKey contains a key of some algorithm, RSA, DSA, ECC, or
 * custom. If you want it as a single buffer (rather than a collection of
 * integers and other values), call this function. It will allocate memory to
 * hold the serialized key and return that buffer to you. It is the caller's
 * responsibility to free that memory by calling MOC_FREE.
 * <p>You specify the format of the serialized key with the format argument. It
 * will be one of the values specified in the serializedKeyFormat enum. Note that
 * not all keys will support all formats. For example, you won't be able to
 * serialize an RSAKey using eccPublicKeyDer. It's also possible that some keys
 * won't support all versions of the Mocana blob.
 * <p>You also specify which algorithms you are willing to support with the
 * pSupportedAlgorithms array. Suppose you only support ECC keys in your
 * application. Maybe you want to keep your application small, so you don't want
 * to load up code that knows how to serialize RSA or DSA keys. You create an
 * array of MKeySerialize elements and pass that array.
 * <p>For example,
 * <pre>
 * <code>
 *   ubyte4 pubKeyDerLen;
 *   ubyte *pPubKeyDer = NULL;
 *   MKeySerialize pSupported[2] = {
 *     KeySerializeRsa,
 *     KeySerializeEcc
 *   };
 *
 *   status = CRYPTO_serializeKey (
 *     &asymKey, pSupported, 2, publicKeyInfoDer,
 *     &pPubKeyDer, &pubKeyDerLen);
 *   if (OK != status)
 *     goto exit;
 *
 *     . . .
 *
 * exit:
 *   MOC_FREE ((void **)&pPubKeyDer);
 * </code>
 * </pre>
 * <p>Keys will not be able to be serialized into all formats. Certainly a public
 * key cannot be serialized into a private key DER. But it is also possible that
 * some key cannot be serialized into all Mocana Blob versions. Versions 0 and 1
 * are older versions and should not be used in new code. They are there for
 * backwards compatibility.
 *
 * @param pKeyToSerialize The AsymmetricKey you want serialized.
 * @param pSupportedAlgorithms An array of MKeySerialize. These are the
 * algorithms your application is willing to support.
 * @param supportedAlgorithmCount The number of entries in the
 * pSupportedAlgorithms array.
 * @param format The format into which you want the key to be serialized.
 * @param ppSerializedKey The address where the function will deposit a pointer
 * to allocated memory containing the serialized key. It is the responsiblity of
 * the caller to free that memory using MOC_FREE.
 * @param pSerializedKeyLen the address where the function will deposit the
 * length, in bytes, of the serialized key.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_serializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey  *pKeyToSerialize,
  MKeySerialize *pSupportedAlgorithms,
  ubyte4 supportedAlgorithmCount,
  serializedKeyFormat format,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

/** Deserialize a key, building an AsymmetricKey from the byte array that is the
 * key data.
 * <p>The caller supplies the serialized key and an initialized AsymmetricKey.
 * The function will determine the format of the serialized key (Mocana blob,
 * DER, etc.), then find the appropriate MKeySerialize from the supplied array
 * that will know how to deserialize the data and build the appropriate key.
 * <p>You also specify which algorithms you are willing to support with the
 * pSupportedAlgorithms array. Suppose you only support ECC keys in your
 * application. Maybe you want to keep your application small, so you don't want
 * to load up code that knows how to serialize RSA or DSA keys. You create an
 * array of MKeySerialize elements and pass that array.
 * <p>For example,
 * <pre>
 *   AsymmetricKey asymKey;
 *   MKeySerialize pSupported[2] = {
 *     KeySerializeRsa,
 *     KeySerializeEcc
 *   };
 *
 *   status = CRYPTO_initAsymmetricKey (&asymKey);
 *   if (OK != status)
 *     goto exit;
 *
 *   status = CRYPTO_deserializeKey (
 *     pSerializedKey, serializedKeyLen, pSupported, 2, &asymKey);
 *   if (OK != status)
 *     goto exit;
 *
 *     . . .
 *
 * exit:
 *   CRYPTO_uninitAsymmetricKey (&asymKey, NULL);
 * <code>
 * </code>
 * </pre>
 * <p>If you want to deserialize a mocasym key, you must initialize the
 * AsymmetricKey with the function CRYPTO_initMocAsymKey. That key
 * object will know how to deserialize a serialized key for that mocasym key, but
 * will not be able to deserialize any other key. So while deserializeKey can
 * generally operate on any key, that is, determine the key algorithm from the
 * serialized data itself and parse it, if the AsymmetricKey is built to be a
 * mocasym key, then it will only know how to parse the appropriate key data. If
 * you have an app that might run across a mocasym key or a non-mocasym key, then
 * you will likely have to call deserializeKey twice, once for the mocasym key and
 * if that didn't work, a second time for general keys.
 * <p>If you are deserializing into a MocAsym Key, you can pass NULL for the
 * supportedAlgorithms.
 *
 * @param pSerializedKey The byte array that is the serialized key.
 * @param serializedKeyLen The length, in bytes, of the serialized key.
 * @param pSupportedAlgorithms An array of MKeySerialize. These are the
 * algorithms your application is willing to support.
 * @param supportedAlgorithmCount The number of entries in the
 * pSupportedAlgorithms array.
 * @param pDeserializedKey The key object into which the key will be placed.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_deserializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MKeySerialize *pSupportedAlgorithms,
  ubyte4 supportedAlgorithmCount,
  AsymmetricKey *pDeserializedKey
  );

/** Serialize an asymmetric key. This will "convert" the key object into a single
 * byte array.
 * <p>An AsymmetricKey contains a key of some algorithm, RSA, DSA, ECC, or
 * custom. If you want it as a single buffer (rather than a collection of
 * integers and other values), call this function. It will allocate memory to
 * hold the serialized key and return that buffer to you. It is the caller's
 * responsibility to free that memory by calling MOC_FREE.
 * <p>You specify the format of the serialized key with the format argument. It
 * will be one of the values specified in the serializedKeyFormat enum. Note that
 * not all keys will support all formats. For example, you won't be able to
 * serialize an RSAKey using eccPublicKeyDer. It's also possible that some keys
 * won't support all versions of the Mocana blob.
 * <p>Keys will not be able to be serialized into all formats. Certainly a public
 * key cannot be serialized into a private key DER. But it is also possible that
 * some key cannot be serialized into all Mocana Blob versions. Versions 0 and 1
 * are older versions and should not be used in new code. They are there for
 * backwards compatibility.
 *
 * @param pKeyToSerialize The AsymmetricKey you want serialized.
 * @param format The format into which you want the key to be serialized.
 * @param ppSerializedKey The address where the function will deposit a pointer
 * to allocated memory containing the serialized key. It is the responsiblity of
 * the caller to free that memory using MOC_FREE.
 * @param pSerializedKeyLen the address where the function will deposit the
 * length, in bytes, of the serialized key.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_serializeAsymKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pKeyToSerialize,
  serializedKeyFormat format,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  );

/** Checks a serialized key to see if it is a tradition TAP key or Secure Storage
 *  key and outputs the provider and module if so.
 *
 * @param pKey       The serialized key you want to check.
 * @param keyLen     The length of the serialized key in bytes.
 * @param pMocCtx    The MocCtx to use when searching for operators, may be NULL.
 * @param pIsTap     Will be set to \c TRUE if the serialized key is a TAP or Secure
 *                   Storage Key.
 * @param pProvider  Contents will be set to the provider.
 * @param pModuleId  Contents will be set to the module id.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getKeyTapInfo(
  ubyte *pKey,
  ubyte4 keyLen,
  MocCtx pMocCtx,
  byteBoolean *pIsTap,
  ubyte4 *pProvider,
  ubyte4 *pModuleId
);

/** Serialize an asymmetric key to secure storage with a given token 
 * and identifier.
 *
 * @param pKeyToSerialize The AsymmetricKey you want serialized.
 * @param format The format into which you want the key's outer identifier to be serialized.
 *               The inner key will always be serialized in DER form.
 * @param pId    Buffer holding the identifier for the key.
 * @param idLen  The length of the id in bytes.
 * @param token  The token (ie secure storage application id) to be used.
 * @param ppSerializedKey The address where the function will deposit a pointer
 * to allocated memory containing the serialized key. It is the responsiblity of
 * the caller to free that memory using MOC_FREE.
 * @param pSerializedKeyLen the address where the function will deposit the
 * length, in bytes, of the serialized key.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_serializeAsymKeyToStorage(
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pKeyToSerialize,
  serializedKeyFormat format,
  ubyte *pId,
  ubyte4 idLen,
  ubyte4 tokenId,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
);

/** Deserialize a key, building an AsymmetricKey from the byte array that is the
 * key data.
 * <p>The caller supplies the serialized key and an initialized AsymmetricKey.
 * The function will determine the format of the serialized key (Mocana blob,
 * DER, etc.), then search through the provided MocCtx for an operator
 * that will know how to deserialize the data and build the appropriate key.
 * If no MocCtx is provided, the internal MocCtx created by the crypto interface
 * core will be used.
 * <p>If you are deserializing into a MocAsym Key, you can pass NULL for the
 * pMocCtx.
 *
 * @param pSerializedKey The byte array that is the serialized key.
 * @param serializedKeyLen The length, in bytes, of the serialized key.
 * @param pMocCtx The MocCtx to use when searching for operators, may be NULL.
 * @param pDeserializedKey The key object into which the key will be placed.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_deserializeAsymKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MocCtx pMocCtx,
  AsymmetricKey *pDeserializedKey
  );

/** Deserialize a key, building an AsymmetricKey from the byte array that is the
 * key data. Pkcs8 password protoected keys and TAP password protected keys
 * may also be deserialized.
 * <p>The caller supplies the serialized key and an initialized AsymmetricKey.
 * The function will determine the format of the serialized key (Mocana blob,
 * DER, etc.), then search through the provided MocCtx for an operator
 * that will know how to deserialize the data and build the appropriate key.
 * If no MocCtx is provided, the internal MocCtx created by the crypto interface
 * core will be used.
 * <p>If you are deserializing into a MocAsym Key, you can pass NULL for the
 * pMocCtx.
 *
 * @param pSerializedKey The byte array that is the serialized key.
 * @param serializedKeyLen The length, in bytes, of the serialized key.
 * @param pMocCtx The MocCtx to use when searching for operators, may be NULL.
 * @param pPassword (Optional) The password for pkcs8 or TAP password protected keys.
 * @param passwordLen The length of the password in bytes.
 * @param pLoadCtx (Optional) Pointer to a context that can be used for key loading, typically
 *                 a \c TAP_Context. If provided it will force the load of \c TAP_Key.
 * @param pDeserializedKey The key object into which the key will be placed.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_deserializeAsymKeyWithCreds (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MocCtx pMocCtx,
  ubyte *pPassword,
  ubyte4 passwordLen,
  void *pLoadCtx,
  AsymmetricKey *pDeserializedKey
  );

/** Build SubjectPublicKeyInfo or PrivateKeyInfo.
 * <p>If privateKey is TRUE, build PrivateKeyInfo, if FALSE, build
 * SubjectPublicKeyInfo.
 * <p>This function will allocate memory for the output buffer and return that
 * buffer at the address given by ppKeyInfo.
 */
MOC_EXTERN MSTATUS CRYPTO_makeKeyInfo (
  intBoolean isPrivateKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte **ppKeyInfo,
  ubyte4 *pKeyInfoLen
  );

/** Find the algorithm identifier and the actual key info in the KeyInfo.
 * <p>The algId might contain necessary info for the key. For example, with DSA
 * and ECC keys, the public parameters are in the algId, not the actual key data.
 * With RSA, there's no key information in the algId.
 * <p>In addition, the algId contains the OID of the algorithm, in order to
 * verify the key is indeed the key expected.
 * <p>The KeyInfo might be SubjectPublicKeyInfo or PrivateKeyInfo. Depending on
 * which type of key it is, the algId is in a different location, and the actual
 * key data is wrapped in either a BIT STRING or OCTET STRING, and also in a
 * different location.
 * <p>This function will find where in the encoding the algID and actual key data
 * are located. It will return pointers to locations inside the encoded key where
 * these values begin. The function does not allocate memory. Do NOT free the
 * buffers returned.
 * <p>Note that the key data address returned will point to the key data that is
 * wrapped. That is, it will NOT return the OCTET STRING or BIT STRING, but
 * rather the actual data those STRINGs wrap.
 * <p>The function will indicate whether the key is public or private. The caller
 * passes in the address of an intBoolean, the function will set it to TRUE if
 * the key is private and FALSE if it is public.
 *
 * @param pKeyInfo The DER encoding of the key, either SubjectPublicKeyInfo or
 * PrivateKeyInfo.
 * @param keyInfoLen The length, in bytes, of the KeyInfo.
 * @param ppAlgId The address where the function will deposit the address where,
 * in the KeyInfo, the algId begins.
 * @param pAlgIdLen The address where the function will deposit the length, in
 * bytes, of the algId.
 * @param ppKeyData The address where the function will deposit the address
 * where, in the KeyInfo, the KeyData begins.
 * @param pKeyDataLen The address where the function will deposit the length, in
 * bytes, of the KeyData.
 * @param isPrivate The address where the function will deposit TRUE if the
 * serialized key is private or FALSE if it is public.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_findKeyInfoComponents (
  ubyte *pKeyInfo,
  ubyte4 keyInfoLen,
  ubyte **ppAlgId,
  ubyte4 *pAlgIdLen,
  ubyte **ppKeyData,
  ubyte4 *pKeyDataLen,
  intBoolean *isPrivate
  );

/* This is the definiton (function signature) of a callback used when loading
* keys into an AsymmetricKey object.
* <p>A user will be calling a function (e.g. an OpenSSL engine written by
* Mocana) with key data to load. The loading function will know how to perform
* some of the operations needed to load the key, but it is possible the key data
* represents a hardware key or some other non-standard situation. In that case,
* the caller will supply a callback to perform initialization operations (such
* creating or copying a hardware handle).
* <p>This is the interface for the Callback.
* <p>The caller passes in a data struct containing the Callback function along
* with any information the function will need to perform its operations. That
* pLocalData can be NULL, or it might be a hardware handle, or it could be a
* struct itself, containing hardware info or maybe key usage data or whatever
* the key needs.
* <p>The called function will make a call to the Callback, passing the
* pLocalData it was given back to the callback.
* <p>For example, the caller might do something like this.
* <pre>
* <code>
*   MKeyContextCallbackInfo callbackInfo;
*
*   callbackInfo.KeyContextCallback = TPMCallback;
*   callbackInfo.pLocalInfo = (void *)secModHandle;
*
*   status = SomeLoadFunction (
*     data, dataLen, pAsymKey, (void *)&callbackInfo);
* </code>
* </pre>
* <p>The Load function will do something like this.
* <pre>
* <code>
*
*    --load key data operations--
*
*   if (NULL != pCallbackInfo)
*   {
*     if (NULL != pCallbackInfo->KeyContextCallback)
*     {
*       status = pCallbackInfo->KeyContextCallback (
*         pAsymKey, pCallbackInfo->pLocalInfo, state);
*       if (OK != state)
*         goto exit;
*     }
*   }
*
*    --more load key data operations--
*
* </code>
* </pre>
* <p>The state is ???
*/
typedef MSTATUS (*MKeyContextCallback) (
  AsymmetricKey *pAsymKey,
  void *pLocalInfo,
  ubyte4 state
  );

/* This is a struct containing the Callback information to pass to a Load
 * function.
 * <p>See the comments for the definition of the function pointer
 * KeyContextCallback.
 */
typedef struct
{
  MKeyContextCallback   KeyContextCallback;
  void                 *pLocalData;
} MKeyContextCallbackInfo;


#ifdef __cplusplus
}
#endif
/* For backwards compatibility.
 * In previous versions of NanoCrypto, the definitions in mocasym.h were in
 * pubcrypto.h. So if someone includes pubcrypto.h expecting to get the MocAsymKey
 * definitions, they'll get them here.
 */
#include "../crypto/mocasym.h"

#endif /* __PUBCRYPTO_HEADER__ */
