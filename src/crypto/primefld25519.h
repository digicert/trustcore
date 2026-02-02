/*
 * primefld25519.h
 *
 * Prime Field Header for the field with p = 2^255 - 19 elements;
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
 * @file       primefld25519.h
 *
 * @brief      Documentation file for the prime field 25519 APIs.
 *
 * @details    Documentation file for the prime field 25519 APIs. This is the prime
 *             field with 2^255 - 19 elements.
 *
 * @flags      To enable the methods in this file one must define
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             and at least one or more of the following flags
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_25519__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDSA_25519__
 *
 * @filedoc    primefld25519.h
 */

/*------------------------------------------------------------------*/

#ifndef __PRIMEFLD25519_HEADER__
#define __PRIMEFLD25519_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_NUM_25519_BYTES 32
#define MOC_NUM_25519_UNITS 10
#define MOC_NUM_25519_ELEM_BYTES 40  /* 10 four byte units per element */

/*
 MACROS provided for addition and subtraction. These are for curve25519
 specific operations and not for general purpose. The words of pA and pB
 should be < 2^26 in absolute value. The resulting pResult will have words
 < 2^27 in absolute value. No carries are needed.
 */
#define PF_25519_add(pResult, pA, pB, i)  \
for (i = 0; i < MOC_NUM_25519_UNITS; ++i) \
{                                         \
    pResult[i] = pA[i] + pB[i];           \
}

#define PF_25519_subtract(pResult, pA, pB, i)  \
for (i = 0; i < MOC_NUM_25519_UNITS; ++i)      \
{                                              \
    pResult[i] = pA[i] - pB[i];                \
}

#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
#define PF_25519_additiveInvert(pA, i) \
for (i = 0; i < MOC_NUM_25519_UNITS; ++i)      \
{                                              \
    pA[i] = (~(pA[i]))+1;                      \
}
#else
#define PF_25519_additiveInvert(pA, i) \
for (i = 0; i < MOC_NUM_25519_UNITS; ++i)      \
{                                              \
pA[i] = -1 * pA[i];                            \
}
#endif

/**
 * Multiplies two finite field elements. The absolute value of the words of pA and pB
 * must be 27 bits or less. pA and pB are allowed to be the same pointer but one
 * should use the more efficient \c PF_25519_square method in that case. The result
 * will have words that will be 26 bits or less in absolute value. pResult is
 * allowed to be the same pointer as pA or pB.
 *
 * @param pResult   Buffer to hold the resulting element.
 * @param pA        The first input element.
 * @param pB        The second input element.
 */
MOC_EXTERN void PF_25519_multiply(sbyte4 *pResult, const sbyte4 *pA, const sbyte4 *pB);

/**
 * Squares a finite field elements. The absolute value of the words of pA
 * must be 27 bits or less. The result will have words that will be 26 bits or less in
 * absolute value. pResult is allowed to be the same pointer as pA.
 *
 * @param pResult   Buffer to hold the resulting element.
 * @param pA        The input element.
 */
MOC_EXTERN void PF_25519_square(sbyte4 *pResult, const sbyte4 *pA);

/**
 * Performs a finite field exponentiation that can be used to compute the
 * inverse of an element or a partial result needed for a square root computation.
 *
 * @param pResult       Buffer to hold the resulting element.
 * @param pA            The input element.
 * @param isInverse     If TRUE then pA^-1 = pA^(p-2) is calculated. If FALSE
 *                      then pA^((p-5)/8)) is calculated.
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS PF_25519_specialExp(sbyte4 *pResult, const sbyte4 *pA, const byteBoolean isInverse);

/**
 * Tests if two finite field elements (encoded as sbyte4 word arrays)
 * actually represent the same element.
 *
 * @param pA      The first element.
 * @param pB      The second element.
 *
 * @return    TRUE if pA and pB represent the same finite field element. FALSE otherwise.
 */
MOC_EXTERN byteBoolean PF_25519_match(const sbyte4 *pA, const sbyte4 *pB);

/**
 * Converts a finite field element stored as an sbyte4 word array into a Little Endian byte
 * array representing a reduced element mod p. The input element must consist of all words
 * that are 26 bits or less in absolute value.
 *
 * @param pResult   Buffer that will hold the resulting reduced element. This must be 32 bytes in length.
 * @param pA        The input element. This value will be mangled.
 *
 * @warning   This method mangles the input value pA. If use of pA is needed again you must make
 *            another copy before calling this method.
 */
MOC_EXTERN void PF_25519_to_bytes(ubyte *pResult, sbyte4 *pA);

/**
 * Converts a Little Endian byte array representing a finite field element
 * into an element in sbyte4 word array form.
 *
 * @param pResult           Pointer to the resulting word array form of the element.
 * @param pInput            The input element in Little Endian byte array form. This must be 32 bytes.
 * @param compareToThePrime If TRUE then the input element will be checked that it is less than the prime
 *                          p. If FALSE then no validation check is done.
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS PF_25519_from_bytes(sbyte4 *pResult, const ubyte *pInput, byteBoolean compareToThePrime);

#ifdef __cplusplus
}
#endif

#endif /* __PRIMEFLD25519_HEADER__ */

