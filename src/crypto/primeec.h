/*
 * primeec.h
 *
 * Finite Field Elliptic Curve Header
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
@file       primeec.h

@brief      Header file for the Nanocrypto Finite Field Elliptic Curve
            API.
@details    This file documents the definitions, enumerations, structures, and
            functions of the NanoCrypto Finite Field Elliptic Curve (EC) API.

@flags      To enable the functions in primeec.{c,h}, the following flag must be defined in moptions.h:
            + \c \__ENABLE_MOCANA_ECC__

@filedoc primeec.h
*/

/*------------------------------------------------------------------*/

#ifndef __PRIMEEC_HEADER__
#define __PRIMEEC_HEADER__

#include "../cap/capdecl.h"
#include "../crypto/cryptodecl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Support for Finite Field Elliptic Curve Operations */

/* Default flag passed into ECDH generate shared secret. This will return the X
 * value back to the caller.
 */
#define ECDH_X_CORD_ONLY 1

/* Pass this into ECDH generate shared secret to get the X and Y back.
 */
#define ECDH_XY_CORD 0

typedef struct ECCKey
{
    intBoolean          privateKey;
    PFEPtr              Qx;         /* public */
    PFEPtr              Qy;         /* public */
    PFEPtr              k;          /* private*/
    PEllipticCurvePtr   pCurve;     /* curve */
    MocAsymKey pPrivateKey;
    MocAsymKey pPublicKey;
    ubyte4 curveIndex;
    ubyte4 enabled;
    ubyte4 curveId;
    void *pEdECCKey;

} ECCKey;

/* Forward declaration */
typedef struct MEccKeyTemplate *MEccKeyTemplatePtr;

#if (defined(__ENABLE_MOCANA_ECC__))

#ifdef MOC_EXTERN_PRIMEEC_H
#undef MOC_EXTERN_PRIMEEC_H
#endif /* MOC_EXTERN_PRIMEEC_H */

/* For non OpenSSL builds macro the old API into the new API for backwards
 * compatability. OpenSSL builds cannot define this macro as there are namespace
 * issues with the old APIs. */
#ifndef OPENSSL_ENGINE
#ifndef ECDSA_sign
#define ECDSA_sign ECDSA_signDigestAux
#endif /* ECDSA_sign */
#endif /* OPENSSL_ENGINE */

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_PRIMEEC_H
#define MOC_EXTERN_PRIMEEC_H __declspec(dllexport)
#else
#define MOC_EXTERN_PRIMEEC_H __declspec(dllimport) extern 
#endif /* WIN_EXPORT_PRIMEEC_H */

#ifdef WIN_STATIC
#undef MOC_EXTERN_PRIMEEC_H
#define MOC_EXTERN_PRIMEEC_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_PRIMEEC_H MOC_EXTERN

#endif /* RTOS_WIN32 */

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif /* MOC_EXTERN_P */

#define MOC_EXTERN_P MOC_EXTERN_PRIMEEC_H

/* NIST curves */
#ifndef __ENABLE_MOCANA_ECC_P192__
#define NUM_EC_P192 (0)
#else
#define NUM_EC_P192 (1)
MOC_EXTERN_PRIMEEC_H const PEllipticCurvePtr EC_P192;
#endif

#ifdef __DISABLE_MOCANA_ECC_P224__
#define NUM_EC_P224 (0)
#else
#define NUM_EC_P224 (1)
MOC_EXTERN_PRIMEEC_H const PEllipticCurvePtr EC_P224;
#endif

#ifdef __DISABLE_MOCANA_ECC_P256__
#define NUM_EC_P256 (0)
#else
#define NUM_EC_P256 (1)
MOC_EXTERN_PRIMEEC_H const PEllipticCurvePtr EC_P256;
#endif

#ifdef __DISABLE_MOCANA_ECC_P384__
#define NUM_EC_P384 (0)
#else
#define NUM_EC_P384 (1)
MOC_EXTERN_PRIMEEC_H const PEllipticCurvePtr EC_P384;
#endif

#ifdef __DISABLE_MOCANA_ECC_P521__
#define NUM_EC_P521 (0)
#else
#define NUM_EC_P521 (1)
MOC_EXTERN_PRIMEEC_H const PEllipticCurvePtr EC_P521;
#endif

#define NUM_ECC_PCURVES    ((NUM_EC_P192) + (NUM_EC_P224) + (NUM_EC_P256) + \
                                        (NUM_EC_P384) + (NUM_EC_P521))


/**
 * @brief   Gets the underlying prime field associated with a prime curve.
 *
 * @details Gets the underlying prime field associated with a prime curve.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 *
 * @return  A pointer to the global prime field associated with the input curve.
 */
MOC_EXTERN PrimeFieldPtr EC_getUnderlyingField(PEllipticCurvePtr pEC);

/**
 * @brief   Computes a scalar-point multiplication on a prime curve.
 *
 * @details Computes a scalar-point multiplication on a prime curve. It is not
 *          checked that the input coordinates (pX,pY) represent a valid point.
 *
 * @param pPF        The globally defined prime field associated with the prime curve.
 * @param pResX      The resulting point's X coordinate.
 * @param pResY      The resulting point's Y coordinate.
 * @param k          The input scalar stored in the form of a prime field element. This
 *                   need not be a reduced prime field element.
 * @param pX         The input point's X coordinate.
 * @param pY         The input point's Y coordinate.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_multiplyPoint(PrimeFieldPtr pPF, PFEPtr pResX, PFEPtr pResY,
                                    ConstPFEPtr k, ConstPFEPtr pX, ConstPFEPtr pY);

/**
 * @brief   Computes a scalar-point multiplication plus an addition on a prime curve.
 *
 * @details Computes a scalar-point multiplication plus an addition on a prime curve.
 *          This is essentially (pResX, pResY) = k * (pX, pY) + (pAddedX, pAddedY).
 *          It is not checked that the input points are valid points on the curve.
 *
 * @param pPF        The globally defined prime field associated with the prime curve.
 * @param pResX      The resulting point's X coordinate.
 * @param pResY      The resulting point's Y coordinate.
 * @param pAddedX    The addended point's X coordinate.
 * @param pAddedY    The addended point's Y coordinate.
 * @param k          The input scalar stored in the form of a prime field element. This
 *                   need not be a reduced prime field element.
 * @param pX         The to be scaled point's X coordinate.
 * @param pY         The to be scaled point's Y coordinate.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_addMultiplyPoint(PrimeFieldPtr pPF, PFEPtr pResX, PFEPtr pResY,
                                        ConstPFEPtr pAddedX, ConstPFEPtr pAddedY,
                                        ConstPFEPtr k, ConstPFEPtr pX, ConstPFEPtr pY);

/**
 * @brief   Computes a Y coordinate of a point on the curve from an X coordinate.
 *
 * @details Computes a Y coordinate of a point on the curve from an X coordinate.
 *          It will compute one of the two possible Y coordinates if it exists. If
 *          no such point (X,Y) exists then \c ERR_NOT_FOUND (-6009) is returned.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param x          The input X coordinate.
 * @param y          The resulting Y coordinate.
 *
 * @return  \c OK (0) if successful and such an (X,Y) exists. If no such (X,Y) exists
 *          then \c ERR_NOT_FOUND (-6009) is returned.
 */
MOC_EXTERN MSTATUS EC_computeYFromX( PEllipticCurvePtr pEC, ConstPFEPtr x, PFEPtr y);

/**
 * @brief   Allocates a new ECCKey instance.
 *
 * @details Allocates a new ECCKey instance. Be sure to call \c EC_deleteKey
 *          when done in order to free the allocated memory.
 *
 * @param pEC        One of the globally defined prime field curves.
 *
 *                   EC_P192 (if enabled)
 *                   EC_P224
 *                   EC_P256
 *                   EC_P384
 *                   EC_P521
 *
 * @param ppNewKey   Pointer to the location that will receive the new key.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_newKey(PEllipticCurvePtr pEC, ECCKey** ppNewKey);

/**
 * @brief   Deletes an ECCKey instance.
 *
 * @details Zeroes and frees memory allocated within and for an ECCKey.
 *
 * @param ppKey      Pointer to the location of the key that will be deleted.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_deleteKey(ECCKey** ppKey);

/**
 * @brief   Clones an ECCKey instance.
 *
 * @details Allocates a new copy of an already existing ECCKey. Be sure to
 *          free this key when done with it by calling \c EC_deleteKey.
 *
 * @param ppNew      Pointer to the location that will receive the new key.
 * @param pSrc       Pointer to the previously existing key that will be cloned.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_cloneKey(ECCKey** ppNew, const ECCKey* pSrc);

/**
 * @brief   Tests whether two ECCKeys have identical public keys.
 *
 * @details Tests whether two ECCKeys have identical public keys. The private
 *          key portions for private keys are ignored.
 *
 * @param pKey1      The first input key.
 * @param pKey2      The second input key.
 * @param res        Contents will be set to TRUE if the two public keys are the
 *                   same point on the curve and FALSE otherwise.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_equalKey(const ECCKey* pKey1, const ECCKey* pKey2, byteBoolean* res);

/**
 * @brief   Sets the key parameters of an ECCKey.
 *
 * @details Sets the key parameters of an ECCKey. This method can set a public key by
 *          passing in NULL for the scalar parameter, or it can be used to set a
 *          private key by passing the scalar in along with the public point.
 *
 * @param pKey       Pointer to a previously allocated key.
 * @param point      Buffer holding the point in an uncompressed form. This form must
 *                   begin with a 0x04 byte followed by the X and Y coordinates
 *                   in Big Endian, each zero padded to the proper prime field element length.
 *                   If not provided, the public key will still be set in pKey from the private key.
 * @param pointLen   The length of the point buffer in bytes.
 * @param scalar     Optional. The scalar as Big Endian byte array. If this is NULL then
 *                   the key type will be public, and otherwise private. Note this value
 *                   is required to be less than the prime number associated with the curve
 *                   in question.
 * @param scalarLen  The length of the scalar in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_setKeyParameters(ECCKey* pKey, const ubyte* point, ubyte4 pointLen,
                                       const ubyte* scalar, ubyte4 scalarLen);

/**
 * @brief   Sets the private key parameter of an ECCKey.
 *
 * @details Sets the private key parameter of an ECCKey. The public key
 *          will be left \c NULL.
 *
 * @param pKey       Pointer to a previously allocated key.
 * @param scalar     The scalar as Big Endian byte array.
 * @param scalarLen  The length of the scalar in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_setPrivateKey( ECCKey *pKey, ubyte *pScalar, ubyte4 scalarLen);

/**
 * @brief   Compares if two elliptic curve pointers are the same curve.
 *
 * @details Compares if two elliptic curve pointers are the same curve.
 *
 * @param pEC1       Pointer to the first curve.
 * @param pEC2       Pointer to the second curve.
 *
 * @return  \c TRUE if the the two curves are the same, \c FALSE otherwise.
 */
MOC_EXTERN intBoolean EC_compareEllipticCurves(PEllipticCurvePtr pEC1,
                                               PEllipticCurvePtr pEC2);

/**
 * @brief   Verifies that a given private key is associated with a given public key.
 *
 * @details Verifies that a given private key, ie a scalar, is associated with a given
 *          public key, ie a point.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param k          The private key scalar stored in the form of a prime field element.
 * @param pQx        The public key point's X coordinate.
 * @param pQy        The public key point's Y coordinate.
 *
 * @return  \c OK (0) if successful and the input consists of a valid key pair,
 *          otherwise a negative number error code from merrors.h
 */
MOC_EXTERN MSTATUS EC_verifyKeyPair(PEllipticCurvePtr pEC, ConstPFEPtr k,
                                    ConstPFEPtr pQx, ConstPFEPtr pQy);

/**
 * @brief   Generates a new ECC private/public key pair.
 *
 * @details Generates a new ECC private/public key pair in prime field element forms.
 *
 * @param pEC        The curve to associate with the key. This is should be one of the
 *                   globally defined prime field curves.
 *
 *                   EC_P192 (if enabled)
 *                   EC_P224
 *                   EC_P256
 *                   EC_P384
 *                   EC_P521
 *
 * @param rngFun     Function pointer callback to a method that will provide random entropy.
 * @param rngArg     Optional argument that may be needed by the \c rngFun provided.
 * @param k          The resuling private key scalar in a prime field element form.
 * @param pQx        The resulting public key point's X coordinate.
 * @param pQy        The resulting public key point's Y coordinate.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_generateKeyPair(PEllipticCurvePtr pEC, RNGFun rngFun, void* rngArg,
                                      PFEPtr k, PFEPtr pQx, PFEPtr pQy);

/**
 * @brief   Verifies that a public key point is a valid point on the curve.
 *
 * @details Verifies that a public key point is a valid point on the curve. This method
 *          is the same as \c EC_verifyPoint except the input is also validated to
 *          be reduced prime field elements.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param pQx        The public key point's X coordinate.
 * @param pQy        The public key point's Y coordinate.
 *
 * @return  \c OK (0) if successful and the input consists of a valid public key point,
 *          otherwise a negative number error code from merrors.h
 */
MOC_EXTERN MSTATUS EC_verifyPublicKey(PEllipticCurvePtr pEC, ConstPFEPtr pQx, ConstPFEPtr pQy);

/**
 * @brief   Verifies that a point is a valid point on the curve.
 *
 * @details Verifies that a point is a valid point on the curve. This method
 *          is the same as \c EC_verifyPublicKey execpt the input is not validated
 *          as reduced prime field elements. Non-reduced elements will produce garbage
 *          results.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param pQx        The public key point's X coordinate.
 * @param pQy        The public key point's Y coordinate.
 *
 * @return  \c OK (0) if successful and the input consists of a valid point,
 *          otherwise a negative number error code from merrors.h
 */
MOC_EXTERN MSTATUS EC_verifyPoint(PEllipticCurvePtr pEC, ConstPFEPtr pQx, ConstPFEPtr pQy);

/**
 * @brief   Converts a point on the curve to an uncompressed form byte array.
 *
 * @details Allocates a buffer and converts a point on the curve to an uncompressed
 *          form byte array. This byte array will begin with a 0x04 byte followed
 *          by the X and Y coordinates in Big Endian, each of length equal to the
 *          standard prime field element length. Be sure to FREE this buffer when
 *          done with it.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param pX         The point's X coordinate.
 * @param pY         The point's Y coordinate.
 * @param s          Location of the newly allocated buffer that will hold the
 *                   resulting uncompressed form point.
 * @param pLen       Contents will be set to the length of the newly allocated buffer in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_pointToByteString(PEllipticCurvePtr pEC,
                                        ConstPFEPtr pX, ConstPFEPtr pY,
                                        ubyte** s, sbyte4* pLen);

/**
 * @brief   Converts an uncompressed form point to prime field elements.
 *
 * @details Converts a byte array form uncompressed point to the point in
 *          the form of two prime field elements.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param s          Buffer holding the uncompressed form point. This should
 *                   begin with an 0x04 byte followed by X and Y in Big Endian
 *                   each properly padded to the prime field's element length.
 * @param len        The length of the buffer s in bytes.
 * @param pX         The resulting X coordinate as a prime field element.
 * @param pY         The resulting Y coordinate as a prime field element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_setPointToByteString(PEllipticCurvePtr pEC,
                                           const ubyte* s, sbyte4 len,
                                           PFEPtr pX, PFEPtr pY);

/**
 * @brief   Gets the length in bytes of an arbitrary point's uncompressed form.
 *
 * @details Gets the length in bytes of an arbitrary point's uncompressed form.
 *          All points on the curve will have this same length (ie will be
 *          properly zero padded if neccessary).
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param pLen       Contents will be set to the number of bytes in an uncompressed
 *                   form point.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_getPointByteStringLen(PEllipticCurvePtr pEC, sbyte4 *pLen);

/**
 * @brief   Converts a point on the curve to an uncompressed form byte array.
 *
 * @details Converts a point on the curve to an uncompressed form byte array in a
 *          previously existing buffer. This byte array will begin with a 0x04 byte
 *          followed by the X and Y coordinates in Big Endian, each of length equal
 *          to the standard prime field element length.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param pX         The point's X coordinate.
 * @param pY         The point's Y coordinate.
 * @param s          Buffer that will hold the resulting uncompressed form point.
 * @param len        The length of the buffer s in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_writePointToBuffer(PEllipticCurvePtr pEC,
                                         ConstPFEPtr pX, ConstPFEPtr pY,
                                         ubyte* s, sbyte4 len);

/**
 * @brief   Converts an uncompressed form point to newly allocated prime field elements.
 *
 * @details Converts a byte array form uncompressed point to the point in
 *          the form of two newly allocated prime field elements. Be sure to
 *          free these elements when done with them by calling \c PRIMEFIELD_deleteElement
 *          on each.
 *
 * @param pEC        Pointer to the globally defined prime curve in question.
 * @param s          Buffer holding the uncompressed form point. This should
 *                   begin with an 0x04 byte followed by X and Y in Big Endian
 *                   each properly padded to the prime field's element length.
 * @param len        The length of the buffer s in bytes.
 * @param ppX        Pointer to the location that will hold the resulting X
 *                   coordinate as a prime field element.
 * @param ppY        Pointer to the location that will hold the resulting Y
 *                   coordinate as a prime field element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_byteStringToPoint(PEllipticCurvePtr pEC,
                                        const ubyte* s, sbyte4 len,
                                        PFEPtr* ppX, PFEPtr* ppY);

/**
 * @brief   Signs a message digest via the ECDSA signature algorithm.
 *
 * @details Signs a message digest via the ECDSA signature algorithm. The computed
 *          signature (r,s) will be in the form of prime field elements.
 *
 * @param pEC        Pointer to the globally defined prime curve.
 * @param d          The private key scalar stored as a prime field element.
 * @param rngFun     Function pointer callback to a method that will provide random entropy.
 * @param rngArg     Optional argument that may be needed by the \c rngFun provided.
 * @param hash       Buffer holding the digest of the message to be signed.
 * @param hashLen    The length of the message digest in bytes.
 * @param r          The resulting signature's r value stored as a prime field element.
 * @param s          The resulting signature's s value stored as a prime field element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS ECDSA_signDigestAux(PEllipticCurvePtr pEC, ConstPFEPtr d,
                              RNGFun rngFun, void* rngArg,
                              const ubyte* hash, ubyte4 hashLen,
                              PFEPtr r, PFEPtr s);

/**
 * @brief   Verifies a message digest via the ECDSA signature algorithm.
 *
 * @details Verifies a message digest via the ECDSA signature algorithm.
 *
 * @param pEC          Pointer to the globally defined prime curve.
 * @param pPublicKeyX  The public key's X-coordinate.
 * @param pPublicKeyY  The public key's Y-coordinate.
 * @param hash         Buffer holding the digest of the message to be verified.
 * @param hashLen      The length of the message digest in bytes.
 * @param r            The input signature's r value stored as a prime field element.
 * @param s            The input signature's s value stored as a prime field element.
 *
 * @return  \c OK (0) if successful AND the signature is valid, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS ECDSA_verifySignature(PEllipticCurvePtr pEC,
                                         ConstPFEPtr pPublicKeyX, ConstPFEPtr pPublicKeyY,
                                         const ubyte* hash, ubyte4 hashLen,
                                         ConstPFEPtr r, ConstPFEPtr s);

/**
 * @brief   Generates a Diffie-Hellman shared secret.
 *
 * @details Generates a Diffie-Hellman shared secret and places it in a newly allocated buffer.
 *          Be sure to FREE this buffer when done with it.
 *
 * @param pEC               Pointer to the globally defined prime curve.
 * @param pX                The other party's public key's X-coordinate.
 * @param pY                The other party's public key's Y-coordinate.
 * @param scalarMultiplier  Our private key scalar stored as a prime field element.
 * @param sharedSecret      Pointer to the location of the newly allocated buffer that will
 *                          store the shared secret.
 * @param sharedSecretLen   Contents will be set to the length of the shared secret in bytes.
 * @param flag              Use \c ECDH_X_CORD_ONLY (1) for a shared secret consisting of just
 *                          the X-coordinate in Big Endian form with leading zeros preserved
 *                          (typically called Z). Use \c ECDH_XY_CORD (0) for a shared secret
 *                          consisting of a concatenated X and Y in such form.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS ECDH_generateSharedSecretAux(PEllipticCurvePtr pEC,
                                                ConstPFEPtr pX, ConstPFEPtr pY,
                                                ConstPFEPtr scalarMultiplier,
                                                ubyte** sharedSecret,
                                                sbyte4* sharedSecretLen,
                                                sbyte4 flag);

/**
 * @brief   Generates a Diffie-Hellman shared secret from an uncompressed form public key.
 *
 * @details Generates a Diffie-Hellman shared secret from an uncompressed form public key
 *          and places it in a newly allocated buffer. The shared secret will consist of just the
 *          X-coordinate in Big Endian form with leading zeros preserved. Be sure to FREE
 *          this buffer when done with it.
 *
 * @param pEC                Pointer to the globally defined prime curve.
 * @param pointByteString    The other party's public key as an uncompressed form byte array.
 *                           This should begin with an 0x04 byte followed by X and Y in Big Endian
 *                           each properly padded to the prime field's element length.
 * @param pointByteStringLen The length of the uncompressed form byte array in bytes.
 * @param scalarMultiplier   Our private key scalar stored as a prime field element.
 * @param sharedSecret       Pointer to the location of the newly allocated buffer that will
 *                           store the shared secret.
 * @param sharedSecretLen    Contents will be set to the length of the shared secret in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS ECDH_generateSharedSecret(PEllipticCurvePtr pEC,
                                             const ubyte* pointByteString,
                                             sbyte4 pointByteStringLen,
                                             ConstPFEPtr scalarMultiplier,
                                             ubyte** sharedSecret,
                                             sbyte4* sharedSecretLen);


/* mode macros for DH Key Agreement Schemes */
#define FULL_UNIFIED       0
#define FULL_MQV           1
#define EPHEMERAL_UNIFIED  2
#define ONE_PASS_UNIFIED_U 3
#define ONE_PASS_UNIFIED_V 4
#define ONE_PASS_MQV_U     5
#define ONE_PASS_MQV_V     6
#define ONE_PASS_DH_U      7
#define ONE_PASS_DH_V      8
#define STATIC_UNIFIED     9

/**
 * @brief   Generates a Diffie-Hellman shared secret via one of the major modes.
 *
 * @details Generates a Diffie-Hellman shared secret via one of the major modes.
 *          This method allocates a buffer to hold the secret. Be sure to FREE
 *          this buffer when done with it.
 *
 * @flags   To use this method one must define __ENABLE_MOCANA_ECDH_MODES__
 *
 * @param mode                  One of the following macro values
 *                              + \c FULL_UNIFIED
 *                              + \c FULL_MQV
 *                              + \c EPHEMERAL_UNIFIED
 *                              + \c ONE_PASS_UNIFIED_U
 *                              + \c ONE_PASS_UNIFIED_V
 *                              + \c ONE_PASS_MQV_U
 *                              + \c ONE_PASS_MQV_V
 *                              + \c ONE_PASS_DH_U
 *                              + \c ONE_PASS_DH_V
 *                              + \c STATIC_UNIFIED                        
 *                  
 * @param pStatic               Our private static key.                             
 * @param pEphemeral            Our private ephemeral key.
 * @param pOtherPartysStatic    The other party's static public key as an uncompressed form byte array.
 * @param otherStaticLen        The length of the uncompressed form static key byte array in bytes.  
 * @param pOtherPartysEphemeral The other party's ephemeral public key as an uncompressed form byte array.
 * @param otherEphemeralLen     The length of the uncompressed form ephemeral key byte array in bytes.  
 * @param ppSharedSecret        Pointer to the location of the newly allocated buffer that will
 *                              store the shared secret.
 * @param pSharedSecretLen      Contents will be set to the length of the shared secret in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS ECDH_keyAgreementSchemePrimeCurve(
    ubyte4 mode, 
    ECCKey *pStatic, 
    ECCKey *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen);

#if defined(__ENABLE_MOCANA_ECC_COMB__) || !defined( __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__)

/**
 * @brief   Computes the total number of \c pf_units that will be needed to store a comb.
 *
 * @details Computes the total number of \c pf_units that will be needed to store a comb
 *          with a given window size w. This is 2 * (2^w - 2) * n where n is the number
 *          of \c pf_units in a prime field element.
 *
 * @param pPF        The globally defined prime field associated to the curve in question.
 * @param windowSize The input window size. This must be 2 or larger.
 * @param size       Contents will be set to the comb size.
 *
 * @flags            To use this method one must define __ENABLE_MOCANA_ECC_COMB__
 *                   and have __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__ not defined.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_combSize( PrimeFieldPtr pPF, sbyte4 windowSize, sbyte4* size);

/**
 * @brief   Computes the comb of a point on the curve.
 *
 * @details Computes the comb of a point on the curve. The table created can be used
 *          to speed up multiplication of a scalar times the point in question. The table
 *          will be allocated so be sure to call \c EC_deleteComb to free such memory
 *          when done with it.
 *
 * @param pPF          The globally defined prime field associated to the curve in question.
 * @param pQx          The input point's X coordinate.
 * @param pQy          The input point's Y coordinate.
 * @param windowSize   The input window size. This must be 2 or larger and is a memory
 *                     vs speed tradeoff. Generally 4 or 5 is optimal.
 * @param pPrecomputed Pointer to the location of a newly allocated array of \c PFEPtrs
 *                     representing the comb table of the input point.
 *
 * @flags              To use this method one must define __ENABLE_MOCANA_ECC_COMB__
 *                     and have __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__ not defined.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_precomputeComb(PrimeFieldPtr pPF, ConstPFEPtr pQx,
                                     ConstPFEPtr pQy, sbyte4 windowSize,
                                     PFEPtr* pPrecomputed);

/**
 * @brief   Computes the comb of the curve's large cyclic group generator.
 *
 * @details Computes the comb of the curve's large cyclic group generator. The table created
 *          can be used to speed up multiplication of a scalar times the generator. The table
 *          will be allocated so be sure to call \c EC_deleteComb to free such memory
 *          when done with it.
 *
 * @param pEC          Pointer to the globally defined prime curve in question.
 * @param windowSize   The input window size. This must be 2 or larger and is a memory
 *                     vs speed tradeoff. Generally 4 or 5 is optimal.
 * @param pCurvePrecomputed  Pointer to the location of a newly allocated array of
 *                            \c PFEPtrs representing the comb table of the generator point.
 *
 * @flags              To use this method one must define __ENABLE_MOCANA_ECC_COMB__
 *                     and have __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__ not defined.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_precomputeCombOfCurve(PEllipticCurvePtr pEC, sbyte4 windowSize,
                                            PFEPtr* pCurvePrecomputed);

/**
 * @brief   Zeros and frees a comb.
 *
 * @details Zeros and frees a comb allocated by the \c EC_precomputeCombOfCurve
 *          or \c EC_precomputeComb methods.
 *
 * @param pPF        The globally defined prime field associated to the curve in question.
 * @param windowSize The input comb's window size. This MUST match the window size
 *                   used when the comb was created.
 * @param pComb      Pointer to the location of the comb to be deleted.
 *
 * @flags            To use this method one must define __ENABLE_MOCANA_ECC_COMB__
 *                   and have __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__ not defined.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_deleteComb(PrimeFieldPtr pPF, sbyte4 windowSize, PFEPtr *pComb);

#endif /* __ENABLE_MOCANA_ECC_COMB__ !__ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__ */

#if !defined(__DISABLE_MOCANA_SIGNED_ODD_COMB__) && defined(__ENABLE_MOCANA_SIGNED_ODD_COMB_PERSIST__)
/**
 * @brief   Zeros and frees globally stored combs and mutexes.
 *
 * @details Zeros and frees globally stored combs and mutexes. These are the mutexes
 *          created by the \c EC_createPrimeCurveMutexes method. The comb's will have
 *          been generated as needed by the ECDSA signing algorithm.
 *
 * @flags   To use this method one must define __ENABLE_MOCANA_SIGNED_ODD_COMB_PERSIST__
 *          and not have __DISABLE_MOCANA_SIGNED_ODD_COMB__ not defined.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_deletePrimeCurveCombsAndMutexes(void);

/**
 * @brief   Creates globally stored mutexes used for thread safety.
 *
 * @details Creates globally stored mutexes used for thread safety among comb
 *          generation for each of the prime curve's cyclic group generators. This
 *          method should only be called once and in an initialization phase, for
 *          example from \c CRYPTO_MOC_init. Be sure to then also call
 *          \c EC_deletePrimeCurveCombsAndMutexes in an appropriate cleanup phase.
 *
 * @flags   To use this method one must define __ENABLE_MOCANA_SIGNED_ODD_COMB_PERSIST__
 *          and not have __DISABLE_MOCANA_SIGNED_ODD_COMB__ not defined.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_createPrimeCurveMutexes(void);
#endif

/**
 * @brief   Verifies a message digest via the ECDSA signature algorithm using provided combs.
 *
 * @details Verifies a message digest via the ECDSA signature algorithm using provided combs.
 *          The comb(s) may have been generated in the signing phase and stored alongside
 *          the public key. This will greatly improve efficiency in the verification algorithm.
 *
 * @param pEC            Pointer to the globally defined prime curve.
 * @param pPublicKeyX    The public key's X-coordinate.
 * @param pPublicKeyY    The public key's Y-coordinate.
 * @param hash           Buffer holding the digest of the message to be verified.
 * @param hashLen        The length of the message digest in bytes.
 * @param curveWinSize   The window size of the input pCurvePrecomp comb. Use 0 if no comb is provided.
 * @param pCurvePrecomp  Optional pointer to a comb of the curve's large cyclic group generator.
 * @param pubKeyWinSize  The window size of the input pPubKeyPrecomp comb. Use 0 if no comb is provided.
 * @param pPubKeyPrecomp Optional pointer to a comb of the public key point.
 * @param r              The input signature's r value stored as a prime field element.
 * @param s              The input signature's s value stored as a prime field element.
 *
 * @return  \c OK (0) if successful AND the signature is valid, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS ECDSA_verifySignatureEx(PEllipticCurvePtr pEC,
                                           ConstPFEPtr pPublicKeyX, ConstPFEPtr pPublicKeyY,
                                           const ubyte* hash, ubyte4 hashLen,
                                           sbyte4 curveWinSize, ConstPFEPtr pCurvePrecomp,
                                           sbyte4 pubKeyWinSize, ConstPFEPtr pPubKeyPrecomp,
                                           ConstPFEPtr r, ConstPFEPtr s);

#endif /* __ENABLE_MOCANA_ECC__  */

#ifdef __cplusplus
}
#endif

#endif /* __PRIMEEC_HEADER__ */

