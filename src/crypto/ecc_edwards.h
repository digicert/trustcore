/*
 * ecc_edwards.h
 *
 * Header for curve25519 and curve448 operations.
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
 * @file       ecc_edwards.h
 *
 * @brief      Header for curve25519 and curve448 operations.
 *
 * @details    Documentation file for curve25519 and curve448 operations.
 *
 * @flags      To enable the methods in this file one must define
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             and at least one or more of the following flags
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_25519__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_448__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 *
 * @filedoc    ecc_edwards.h
 */

/*------------------------------------------------------------------*/

#ifndef __ECC_EDWARDS_HEADER__
#define __ECC_EDWARDS_HEADER__

#include "../crypto/primefld25519.h"
#include "../common/vlong.h"
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Curve25519 definitions */
#define MOC_CURVE25519_BYTE_SIZE MOC_NUM_25519_BYTES  /* 32 */
#define MOC_CURVE25519_ENCODING_SIZE MOC_CURVE25519_BYTE_SIZE

typedef struct
{
    sbyte4 pX[MOC_NUM_25519_UNITS];
    sbyte4 pY[MOC_NUM_25519_UNITS];
    sbyte4 pZ[MOC_NUM_25519_UNITS];
    sbyte4 pT[MOC_NUM_25519_UNITS];
  
} projPoint25519;

/**
 * @brief   Converts an encoded point on curve25519 to a projective form.
 *
 * @details Converts an encoded point on curve25519 to a projective form. See the description
 *          of \c CURVE25519_convertProjectiveToEncoded for a description of an encoded point.
 *
 * @param pResult       Pointer to the projective form point that will be set.
 * @param pEncodedInput Buffer holding The exising encoded point. This must be 32 bytes in length.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE25519_convertEncodedToProjective(projPoint25519 *pResult, const ubyte *pEncodedInput);

/**
 * @brief   Adds two projective form points on curve25519.
 *
 * @details Adds two projective form points on curve25519.
 *
 * @param pResult The resulting sum. This must be a distinct pointer from pP or pQ.
 * @param pP      The first point to be added.
 * @param pQ      The second point to be added.
 * @param pTemps  Scratch memory space. This must have space for four finite field elements.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 */
MOC_EXTERN void CURVE25519_addPoints(projPoint25519 *pResult, const projPoint25519 *pP, const projPoint25519 *pQ, sbyte4 *pTemps);

/**
 * @brief   Performs a scalar point multiplication on curve25519.
 *
 * @details Performs a scalar point multiplication on curve25519.
 *
 * @param pResult The result of the scalar point multiply. This must be a distinct pointer from pP.
 * @param pScalar The scalar in Little endian byte array form. This must be 32 bytes in length.
 * @param pP      The point to be scaled. If this is NULL then the curve's large cyclic group
 *                generator will be scaled by the scalar.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE25519_multiplyPoint(MOC_ECC(hwAccelDescr hwAccelCtx) projPoint25519 *pResult, const ubyte *pScalar, const projPoint25519 *pP);
    
/**
 * @brief   Converts a projective form point on curve25519 to an encoded form point.
 *
 * @details Converts a projective form point to an encoded form point. The encoded form
 *          consists of the 255 bit affine Y coordinate in a 32 byte (256 bit) buffer in
 *          Little Endian (bytewise) form, and with the last bit of the 256 bit buffer set to
 *          the least significant bit of the affine X coordinate.
 *
 * @param pBuffer  Buffer to hold the resulting encoded form point. This must be 32 bytes in space.
 * @param pInput   Pointer to the input projective form point.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE25519_convertProjectiveToEncoded(ubyte *pBuffer, const projPoint25519 *pInput);

/**
 * @brief   Creates a mutex for thread safety for curve25519 comb generation.
 *
 * @details Creates a mutex to be used for thread safety when creating a scalar point multiplication
 *          comb for the generator of the large cyclic group on curve25519.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE25519_createCombMutex(void);

/**
 * @brief   Zeroes and frees the persisted comb and mutex for curve25519.
 *
 * @details Zeroes and frees the persisted comb made for the generator of the large cyclic
 *          group on curve25519. Also deletes the mutex made for thread safety.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE25519_deleteCombAndMutex(void);

/**
 * @brief   Scalar point multiplication for EDDH on curve25519.
 *
 * @details The scalar point multiply "X25519" method as described in RFC 7748 Section 5.
 *          The pU and pResult are actually Montgomery form X-coordinates in Little Endian
 *          byte array form with the 256th bit of the buffer cleared. All 3 inputs to this
 *          method must be buffers of 32 bytes in length.
 *
 * @param pResult   Buffer to hold the result of the scalar point multiply. It is ok
 *                  for pResult to be the same buffer as pU.
 * @param pScalar   Buffer holding the input scalar in Little Endian byte array form.
 * @param pU        Buffer holding the input point.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_25519__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE25519_X25519(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pResult, ubyte *pScalar, ubyte *pU);

/* ------------------------------------------------------------------------------------ */
    
/* X448 (curve448) definitions */
#define MOC_CURVE448_BYTE_SIZE 56
#define MOC_CURVE448_ENCODING_SIZE (MOC_CURVE448_BYTE_SIZE+1)
#define MOC_CURVE448_NUM_UNITS (MOC_CURVE448_BYTE_SIZE/sizeof(pf_unit))

typedef struct
{
    pf_unit pX[MOC_CURVE448_NUM_UNITS];
    pf_unit pY[MOC_CURVE448_NUM_UNITS];
    pf_unit pZ[MOC_CURVE448_NUM_UNITS];
  
} projPoint448;

/**
 * @brief   Converts an encoded point on curve448 to a projective form.
 *
 * @details Converts an encoded point on curve448 to a projective form. See the description
 *          of \c CURVE448_convertProjectiveToEncoded for a description of an encoded point.
 *
 * @param pResult       Pointer to the projective form point that will be set.
 * @param pEncodedInput Buffer holding The exising encoded point. This must be 57 bytes in length.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE448_convertEncodedToProjective(projPoint448 *pResult, const ubyte *pEncodedInput);

/**
 * @brief   Adds two projective form points on curve448.
 *
 * @details Adds two projective form points on curve448.
 *
 * @param pResult The resulting sum. This must be a distinct pointer from pP or pQ.
 * @param pP      The first point to be added.
 * @param pQ      The second point to be added.
 * @param pTemps  Scratch memory space. This must have space for seven finite field elements.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 */
MOC_EXTERN void CURVE448_addPoints(projPoint448 *pResult, const projPoint448 *pP, const projPoint448 *pQ, pf_unit *pTemps);

/**
 * @brief   Performs a scalar point multiplication on curve448.
 *
 * @details Performs a scalar point multiplication on curve448.
 *
 * @param pResult The result of the scalar point multiply. This must be a distinct pointer from pP.
 * @param pScalar The scalar in Little endian byte array form. This must be 57 bytes in length.
 * @param pP      The point to be scaled. If this is NULL then the curve's large cyclic group
 *                generator will be scaled by the scalar.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE448_multiplyPoint(MOC_ECC(hwAccelDescr hwAccelCtx) projPoint448 *pResult, const ubyte *pScalar, const projPoint448 *pP);

/**
 * @brief   Converts a projective form point on curve448 to an encoded form point.
 *
 * @details Converts a projective form point to an encoded form point. The encoded form
 *          consists of the 448 bit affine Y coordinate in the first 56 bytes of a 57 byte buffer
 *          in Little Endian (bytewise) form, and with the most significant bit of the 57th byte
 *          being the least significant bit of the affine X coordinate.
 *
 * @param pBuffer  Buffer to hold the resulting encoded form point. This must be 57 bytes in space.
 * @param pInput   Pointer to the input projective form point.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE448_convertProjectiveToEncoded(ubyte *pBuffer, const projPoint448 *pInput);

/**
 * @brief   Creates a mutex for thread safety for curve448 comb generation.
 *
 * @details Creates a mutex to be used for thread safety when creating a scalar point multiplication
 *          comb for the generator of the large cyclic group on curve448.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE448_createCombMutex(void);

/**
 * @brief   Zeroes and frees the persisted comb and mutex for curve448.
 *
 * @details Zeroes and frees the persisted comb made for the generator of the large cyclic
 *          group on curve448. Also deletes the mutex made for thread safety.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE448_deleteCombAndMutex(void);

/**
 * @brief   Scalar point multiplication for EDDH on curve448.
 *
 * @details The scalar point multiply "X448" method as described in RFC 7748 Section 5.
 *          The pU and pResult are actually Montgomery form X-coordinates in Little Endian
 *          byte array form. All 3 inputs to this method must be buffers of 56 bytes in length.
 *
 * @param pResult   Buffer to hold the result of the scalar point multiply. It is ok
 *                  for pResult to be the same buffer as pU.
 * @param pScalar   Buffer holding the input scalar in Little Endian byte array form.
 * @param pU        Buffer holding the input point.
 *
 * @flags      To enable this method one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS CURVE448_X448(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pResult, ubyte *pScalar, ubyte *pU);

#ifdef __cplusplus
}
#endif

#endif /* __ECC_EDWARDS_HEADER__ */
