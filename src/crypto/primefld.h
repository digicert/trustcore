/*
 * primefld.h
 *
 * Prime Field Header
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
 @file       primefld.h

 @brief      Header file for the Nanocrypto EC prime field management APIs.

 @details    This file documents the definitions, enumerations, structures, and
             functions of the NanoCrypto EC prime field management APIs.

 @flags      To enable the functions in primeec.{c,h}, the following flag must be defined in moptions.h:
             + \c \__ENABLE_MOCANA_ECC__

 @filedoc    primefld.h
 */

/*------------------------------------------------------------------*/

#ifndef __PRIMEFLD_HEADER__
#define __PRIMEFLD_HEADER__

#include "../crypto/cryptodecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_MOCANA_ECC__))

#ifdef __ENABLE_MOCANA_64_BIT__
#define MOC_EC_ONE 0x01ULL
#define MOC_EC_TWO 0x02ULL
#else
#define MOC_EC_ONE 0x01
#define MOC_EC_TWO 0x02
#endif

#ifdef MOC_EXTERN_PRIMEFLD_H
#undef MOC_EXTERN_PRIMEFLD_H
#endif /* MOC_EXTERN_PRIMEFLD_H */

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_PRIMEFLD_H
#define MOC_EXTERN_PRIMEFLD_H __declspec(dllexport)
#else
#define MOC_EXTERN_PRIMEFLD_H __declspec(dllimport) extern 
#endif /* WIN_EXPORT_PRIMEFLD_H */

#ifdef WIN_STATIC
#undef MOC_EXTERN_PRIMEFLD_H
#define MOC_EXTERN_PRIMEFLD_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_PRIMEFLD_H MOC_EXTERN

#endif /* RTOS_WIN32 */

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif /* MOC_EXTERN_P */

#define MOC_EXTERN_P MOC_EXTERN_PRIMEFLD_H

/* NIST curves */
#ifdef __ENABLE_MOCANA_ECC_P192__
MOC_EXTERN_PRIMEFLD_H const PrimeFieldPtr PF_p192;
#endif

#ifndef __DISABLE_MOCANA_ECC_P224__
MOC_EXTERN_PRIMEFLD_H const PrimeFieldPtr PF_p224;
#endif

#ifndef __DISABLE_MOCANA_ECC_P256__
MOC_EXTERN_PRIMEFLD_H const PrimeFieldPtr PF_p256;
#endif

#ifndef __DISABLE_MOCANA_ECC_P384__
MOC_EXTERN_PRIMEFLD_H const PrimeFieldPtr PF_p384;
#endif

#if defined(__ENABLE_MOCANA_ECC_EDDSA_448__) || defined(__ENABLE_MOCANA_ECC_EDDH_448__) || defined(__ENABLE_MOCANA_FIPS_MODULE__)
MOC_EXTERN_PRIMEFLD_H const PrimeFieldPtr PF_p448;
#endif

#ifndef __DISABLE_MOCANA_ECC_P521__
MOC_EXTERN_PRIMEFLD_H const PrimeFieldPtr PF_p521;
#endif

/**
 * @brief   Allocates a new prime field element.
 *
 * @details Allocates a new prime field element. Be sure to call \c PRIMEFIELD_deleteElement
 *          when done in order to free the allocated memory.
 *
 * @param pField     One of the globally defined prime field pointers.
 *
 *                   PF_p192 (if enabled)
 *                   PF_p224
 *                   PF_p256
 *                   PF_p384
 *                   PF_p448 (if enabled)
 *                   PF_p521
 *
 * @param ppNewElem  Pointer to the location that will receive the new element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_newElement( PrimeFieldPtr pField, PFEPtr* ppNewElem);

/**
 * @brief   Copies a prime field element.
 *
 * @details Copies a finite field element to a previously allocated element.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pDestElem  The destination element of the copy. This must have been previously allocated.
 * @param pSrcElem   The source element of the copy.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_copyElement( PrimeFieldPtr pField, PFEPtr pDestElem, ConstPFEPtr pSrcElem);

MOC_EXTERN intBoolean PRIMEFIELD_comparePrimeFields(PrimeFieldPtr pField1, PrimeFieldPtr pField2);

/**
 * @brief   Deletes a prime field element.
 *
 * @details Zeroes and frees memory allocaeted within a prime field element.
 *
 * @param pField        The globally defined prime field pointer associated with the element.
 * @param ppDeleteElem  Pointer to the location that holds the element to be deleted.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_deleteElement( PrimeFieldPtr pField, PFEPtr* ppDeleteElem);

/**
 * @brief   Adds prime field elements.
 *
 * @details Adds prime field elements inplace with respect to the first input.
 *          The result is a standard mod p reduced element.
 *
 * @param pField        The globally defined prime field pointer associated with the elements.
 * @param pSumAndValue  The first addend, which will be replaced with the resulting sum.
 * @param pAddend       The second addend. It is ok for this to be the same pointer as pSumAndValue.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_add( PrimeFieldPtr pField, PFEPtr pSumAndValue, ConstPFEPtr pAddend);

/**
 * @brief   Subtracts prime field elements.
 *
 * @details Subtracts prime field elements inplace with respect to the first input.
 *          The result is a standard mod p reduced element.
 *
 * @param pField          The globally defined prime field pointer associated with the elements.
 * @param pResultAndValue The minuend, which will be replaced with the resulting difference.
 * @param pAddend         The subtrahend. It is ok for this to be the same pointer as pResultAndValue.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_subtract( PrimeFieldPtr pField, PFEPtr pResultAndValue, ConstPFEPtr pSubtract);

/**
 * @brief   Xor's prime field elements.
 *
 * @details Xor's prime field elements. The result is NOT necessarily a mod p reduced element.
 *
 * @param pField          The globally defined prime field pointer associated with the elements.
 * @param pResultAndValue The first input element, which will be replaced with the resulting xor.
 * @param pXor            The second input element. It is ok for this to be the same pointer as pResultAndValue.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_xor(PrimeFieldPtr pField, PFEPtr pResultAndValue, ConstPFEPtr pXor);

/**
 * @brief   Multiplies prime field elements.
 *
 * @details Multiplies prime field elements. The result is a standard mod p reduced element.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pProduct   The resulting product. It is ok for this to be the same pointer as pA or pB.
 * @param pA         The first input.
 * @param PB         The second input. It is ok for this to be the same pointer as pA.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_multiply( PrimeFieldPtr pField, PFEPtr pProduct, ConstPFEPtr pA, ConstPFEPtr pB);

/**
 * @brief   Right bit shifts a prime field element a single bit.
 *
 * @details Right bit shifts a prime field element a single bit. This operation is
 *          inplace. It is NOT a mod p divide by 2 operation.
 *
 * @param pField     The globally defined prime field pointer associated with the element.
 * @param pA         The input which will be replaced with the resulting element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_shiftR( PrimeFieldPtr pField, PFEPtr pA);

/**
 * @brief   Gets a bit in a prime field element.
 *
 * @details Gets a bit in a prime field element. The 0-th bit is considered the least
 *          significant.
 *
 * @param pField     The globally defined prime field pointer associated with the element.
 * @param pA         The input element.
 * @param bitNum     The bit to find, beginning with 0 being the least signficant.
 * @param bit        Contents will be set to the element's bitNum bit, ie to 0 or 1.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_getBit( PrimeFieldPtr pField, ConstPFEPtr pA, ubyte4 bitNum, ubyte* bit);

/**
 * @brief   Multiplicatively inverts a prime field element.
 *
 * @details Multiplicatively inverts a prime field element. If the input element is zero an error code will
 *          be returned. The result will be a standard mod p reduced element.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pInverse   The resulting inverse element. It is ok for this to be the same pointer as pA.
 * @param pA         The input element to be inverted.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_inverse( PrimeFieldPtr pField, PFEPtr pInverse, ConstPFEPtr pA);

/**
 * @brief   Multipies a prime field element by the inverse of another element.
 *
 * @details Multipies a prime field element by the inverse of another element. If the divisor element
 *          is zero an error code will be returned. The result will be a standard mod p reduced element.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pResult    The resulting element. It is ok for this to be the same pointer as pA or pDivisor.
 * @param pA         The first input element to be multipied.
 * @param PDivisor   The second input element that will be inverted and multiplied. It is ok for this to
 *                   be the same pointer as pA.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_divide( PrimeFieldPtr pField, PFEPtr pResult, ConstPFEPtr pA, ConstPFEPtr pDivisor);

/**
 * @brief   Computes the square root of a prime field element.
 *
 * @details Computes the square root of a prime field element or returns an error code if
 *          no such square root exists. The result if found will be a standard mod p reduced element.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pResult    The resulting square root of the input if it exists.
 * @param pA         The input element.
 *
 * @warning Be sure to always check for a return code of OK before proceeding, as (p+1)/2,
 *          of the finite field elements do not have square roots.
 *
 * @return  \c OK (0) for successful computation of a sqaure root, and \c ERR_NOT_FOUND (-6009)
 *          if no square root exists, or another negative error code upon computation failure.
 */
MOC_EXTERN MSTATUS PRIMEFIELD_squareRoot(PrimeFieldPtr pField, PFEPtr pResult, ConstPFEPtr pA);

/**
 * @brief   Compares a prime field element to an unsigned small integer.
 *
 * @details Compares a prime field element to an unsigned small integer.
 *
 * @param pField     The globally defined prime field pointer associated with the element.
 * @param pA         The first element to be compared.
 * @param val        The small 4 byte unsigned integer to be compared.
 *
 * @return  One (1) if pA > val, zero (0) if pA and val are the same, and minus one (-1) if pA < val.
 */
MOC_EXTERN sbyte4 PRIMEFIELD_cmpToUnsigned(PrimeFieldPtr pField, ConstPFEPtr pA, ubyte4 val);

/**
 * @brief   Sets a prime field element to an unsigned small integer.
 *
 * @details Sets a prime field element to an unsigned small integer.
 *
 * @param pField    The globally defined prime field pointer associated with the element.
 * @param pA        The target element to be set.
 * @param val       The input small 4 byte unsigned integer.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_setToUnsigned(PrimeFieldPtr pField, PFEPtr pA, ubyte4 val);

/**
 * @brief   Sets a prime field element from a Big Endian byte array.
 *
 * @details Sets a prime field element from a Big Endian byte array. The integer
 *          represented must already be reduced, ie < p, else an error will be returned.
 *
 * @param pField    The globally defined prime field pointer associated with the element.
 * @param pA        The target element to be set.
 * @param b         Buffer holding the input Big Endian byte array.
 * @param len       The length of the byte array b in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_setToByteString( PrimeFieldPtr pField, PFEPtr pA, const ubyte* b, sbyte4 len);

/**
 * @brief   Converts a prime field element to a Big Endian byte array.
 *
 * @details Converts a prime field element to a Big Endian byte array. Leading zeros will
 *          be preserved, ie the length of the byte array will depend only on the field
 *          and not on the value of the element. The resulting array will be in a newly
 *          allocated buffer. Be sure to FREE it when done with it.
 *
 * @param pField    The globally defined prime field pointer associated with the element.
 * @param pA        The input element.
 * @param b         Pointer to the newly allocated buffer that will hold the Big Endian byte array.
 * @param len       Contents will be set to the length of the buffer b in bytes. This only depends
 *                  on the field and not the value of the element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_getAsByteString( PrimeFieldPtr pField, ConstPFEPtr pA, ubyte** b, sbyte4* len);

/**
 * @brief   Converts two prime field elements to Big Endian byte arrays concatenated.
 *
 * @details Converts two prime field elements to Big Endian byte arrays concatenated.
 *          Leading zeros will be preserved, ie the length of the byte array will depend
 *          only on the field and not on the value of the elements. The resulting array
 *          will be in a newly allocated buffer. Be sure to FREE it when done with it.
 *
 * @param pField    The globally defined prime field pointer associated with the elements.
 * @param pA        The first input element.
 * @param pB        The second input element.
 * @param b         Pointer to the newly allocated buffer that will hold the Big Endian byte arrays.
 * @param len       Contents will be set to the length of the buffer b in bytes. This only depends
 *                  on the field and not the value of the elements.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_getAsByteString2( PrimeFieldPtr pField, ConstPFEPtr pA, ConstPFEPtr pB, ubyte** b, sbyte4* len);

/**
 * @brief   Writes a prime field element to an existing byte array.
 *
 * @details Writes a prime field element to a previously existing array, in Big
 *          Endian form. Leading zeros will be preserved and the array must be big
 *          enough for arbitrary elements.
 *
 * @param pField    The globally defined prime field pointer associated with the element.
 * @param pA        The input element.
 * @param b         The buffer that will be filled with the Big Endian byte array.
 * @param len       The length of the buffer b in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_writeByteString( PrimeFieldPtr pField, ConstPFEPtr pA, ubyte* b, sbyte4 len);

/**
 * @brief   Gets the length of an arbitrary prime field element when written as a byte array.
 *
 * @details Gets the length of an arbitrary prime field element when written as a byte array.
 *
 * @param pField    Prime field pointer to the field in question.
 * @param len       Contents will be set to the length in bytes of an element when written
 *                  in byte array form.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_getElementByteStringLen(PrimeFieldPtr pField, sbyte4* len);

/**
 * @brief   Compares two prime field elements.
 *
 * @details Compares two prime field elements (considered as integers).
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pA         The first element to be compared.
 * @param pB         The second element to be compared.
 *
 * @return  One (1) if pA > pB, zero (0) if pA and pB are the same, and minus one (-1) if pA < pB.
 */
MOC_EXTERN sbyte4 PRIMEFIELD_cmp(PrimeFieldPtr pField, ConstPFEPtr pA, ConstPFEPtr pB);

/**
 * @brief   Tests equality for two prime field elements.
 *
 * @details Tests equality for two prime field elements.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pA         The first input element.
 * @param pB         The second input element.
 *
 * @return  TRUE if pA and pB represent the same element, FALSE otherwise.
 */
MOC_EXTERN intBoolean PRIMEFIELD_match(PrimeFieldPtr pField, ConstPFEPtr pA, ConstPFEPtr pB);

/**
 * @brief   Performs an arbitrary modular multiplication with the Barrett reduction routine.
 *
 * @details Performs an arbitrary modular multiplication with the Barrett reduction routine.
 *          This routine acts on two prime field elements but will reduce their (big integer)
 *          product by an arbitrary modulus. The result should no longer be considered a
 *          prime field element even though it is stored in such.
 *
 * @param pField     The globally defined prime field pointer associated with the elements.
 * @param pProduct   The resulting product modulo the pModulo passed in.
 * @param pA         The first input element.
 * @param pB         The second input element.
 * @param pModulo    The modulus for which to reduce the product by. This should not be p.
 * @param pMu        The Barrett multiplication constant associated with the pModulo passed in.
 *
 * @warning For an arbitary modulus the resulting pProduct will not necessarily be a
 *          reduced mod p prime field element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_barrettMultiply( PrimeFieldPtr pField, PFEPtr pProduct, ConstPFEPtr pA,
                                          ConstPFEPtr pB, ConstPFEPtr pModulo, ConstPFEPtr pMu);

/**
 * @brief   Performs an arbitrary modular addition.
 *
 * @details Performs an arbitrary modular addition. This routine acts on two prime
 *          field elements but will reduce their (big integer) sum by an arbitrary
 *          modulus. The result should no longer be considered a prime field
 *          element even though it is stored in such.
 *
 * @param pField       The globally defined prime field pointer associated with the elements.
 * @param pSumAndValue The first addend, which will be replaced with the resulting sum.
 * @param pAddend      The second addend. It is ok for this to be the same pointer as pSumAndValue.
 * @param pModulo      The modulus for which to reduce the product by. This should not be p.
 *
 * @warning For an arbitary modulus the resulting pSumAndValue will not necessarily be a
 *          reduced mod p prime field element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_addAux( PrimeFieldPtr pField, PFEPtr pSumAndValue, ConstPFEPtr pAddend,
                                    ConstPFEPtr pModulus);

/**
 * @brief   Performs an arbitrary modular inversion.
 *
 * @details Performs an arbitrary modular inversion. This routine acts on a prime
 *          field element but will invert it (as a big integer) by an arbitrary
 *          modulus. The modulus need not be prime. The result should no longer
 *          be considered a prime field element even though it is stored in such.
 *          An error will be returned if the input element is not invertible.
 *
 * @param k         The number of words in pModulus. pA cannot be a larger size in words.
 * @param pInverse  The resulting inverse modulo pModulus.
 * @param pA        The input element to be inverted.
 * @param pModulus  The input modulus.
 *
 * @warning For an arbitary modulus the resulting pInverse will not necessarily be a
 *          reduced mod p prime field element.
 *
 * @return  \c OK (0) if successful and an inverse exists, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_inverseAux( sbyte4 k, PFEPtr pInverse, ConstPFEPtr pA, ConstPFEPtr pModulus);

/**
 * @brief   Adds two prime field elements.
 *
 * @details Adds two prime field elements with a distinc pointer for the result.
 *          The result is a standard mod p reduced element.
 *
 * @param pField    The globally defined prime field pointer associated with the elements.
 * @param pSum      The resulting sum. This must be distinct pointer from pAddend2.
 * @param pAddend   The first addend. It is ok for this to be the same pointer as pSum.
 * @param pAddend2  The second addend. It is ok for this to be the same pointer as pAddend
 *                  but must be distinct from pSum.
 *
 * @flags           Must enable one of the curve448 algorithms in order to use this method.
 *
 *                  + \c \__ENABLE_MOCANA_ECC_EDDSA_448__
 *                  + \c \__ENABLE_MOCANA_ECC_EDDH_448__
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_add2( PrimeFieldPtr pField, PFEPtr pSum, ConstPFEPtr pAddend, ConstPFEPtr pAddend2);

/**
 * @brief   Subtracts two prime field elements.
 *
 * @details Subtracts two prime field elements with a distinc pointer for the result.
 *          The result is a standard mod p reduced element.
 *
 * @param pField       The globally defined prime field pointer associated with the elements.
 * @param pResult      The resulting difference. This must be distinct pointer from pSubtrahend.
 * @param pMinuend     The minuend. It is ok for this to be the same pointer as pResult.
 * @param pSubtrahend  The pSubtrahend. It is ok for this to be the same pointer as pMinuend
 *                     but must be distinct from pResult.
 *
 * @flags            Must enable one of the curve448 algorithms in order to use this method.
 *
 *                   + \c \__ENABLE_MOCANA_ECC_EDDSA_448__
 *                   + \c \__ENABLE_MOCANA_ECC_EDDH_448__
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_subtract2( PrimeFieldPtr pField, PFEPtr pResult, ConstPFEPtr pMinuend, ConstPFEPtr pSubtrahend);

/**
 * @brief   Additively inverts a prime field element inplace.
 *
 * @details Additively inverts a prime field element inplace.
 *          The result is a standard mod p reduced element.
 *
 * @param pField    The globally defined prime field pointer associated with the element.
 * @param pA        The element to be additively inverted and the result of the inversion.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_additiveInvert(PrimeFieldPtr pField, PFEPtr pA);

/**
 * @brief   Special finite field exponentiation for inverses or square roots.
 *
 * @details Special finite field exponentiation method that can be used to compute the
 *          inverse of an element or a partial result needed for a square root computation.
 *          This is for the PF_p448 field only. The result is a standard mod p reduced element.
 *
 * @param pResult       The resulting element. It is ok for this to be the same pointer as pA.
 * @param pA            The input element to be exponentiated.
 * @param isInverse     If TRUE then pA^-1 = pA^(p-2) is calculated. If FALSE
 *                      then pA^((p-3)/4) is calculated.
 *
 * @flags            Must enable one of the curve448 algorithms in order to use this method.
 *
 *                   + \c \__ENABLE_MOCANA_ECC_EDDSA_448__
 *                   + \c \__ENABLE_MOCANA_ECC_EDDH_448__
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_specialExp448( PFEPtr pResult, ConstPFEPtr pA, byteBoolean isInverse);

#if (defined(__ENABLE_MOCANA_VLONG_ECC_CONVERSION__))

/**
 * @brief   Creates a new prime field element from a vlong element.
 *
 * @details Allocates and creates a new prime field element from a vlong element.
 *          Be sure to call \c PRIMEFIELD_deleteElement to free allocated memory
 *          when done with the new element.
 *
 * @param pField     The globally defined prime field pointer you wish to associate with the element.
 * @param pV         Pointer to the vlong element to be copied and converted.
 * @param ppNewElem  Pointer that will be set to the location of the newly created prime
 *                   field element.
 *
 * @flags   Must define + \c \__ENABLE_MOCANA_VLONG_ECC_CONVERSION__ in order to use this method.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_newElementFromVlong( PrimeFieldPtr pField, const vlong* pV,
                                              PFEPtr* ppNewElem);

/**
 * @brief   Creates a new vlong from a prime field element.
 *
 * @details Allocates and creates a new vlong from a prime field element.
 *          Be sure to call \c VLONG_freeVlong to free allocated memory
 *          when done with the new vlong.
 *
 * @param pField     The globally defined prime field pointer associated with the element.
 * @param pElem      The input element to be copied and converted.
 * @param ppNewElem  Pointer that will be set to the location of the newly created vlong.
 * @param ppQueue    Pointer to an optional vlong queue.
 *
 * @flags   Must define + \c \__ENABLE_MOCANA_VLONG_ECC_CONVERSION__ in order to use this method.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_newVlongFromElement( PrimeFieldPtr pField, ConstPFEPtr pElem,
                                              vlong** ppNewElem, vlong** ppQueue);

/**
 * @brief   Gets the prime number associateed with the prime field as a new vlong.
 *
 * @details Gets the prime number associateed with the prime field
 *          as a newly allocated vlong. Be sure to call \c VLONG_freeVlong
 *          to free allocated memory when done with the new vlong.
 *
 * @param pField     The input prime field.
 * @param ppPrime    Pointer that will be set to the location of the newly created vlong
 *                   element representing the prime p associated with the field.
 *
 * @flags   Must define + \c \__ENABLE_MOCANA_VLONG_ECC_CONVERSION__ in order to use this method.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_getPrime( PrimeFieldPtr pField, vlong** ppPrime);

/**
 * @brief   Creates a new multiple precision integer from a prime field element.
 *
 * @details Creates a new multiple precision integer from a prime field element.
 *          A buffer will be allocated to store the new integer. Be sure to FREE
 *          this buffer when done with it.
 *
 * @param pField           The globally defined prime field pointer associated with the element.
 * @param pElem            The input element to be copied and converted.
 * @param ppNewMpint       Pointer to the location that will hold the newly allocated multiple
 *                         precision integer.
 * @param pRetMpintLength  Contents will be set to the number of bytes in the new integer.
 * @param ppVlongQueue     Pointer to an optional vlong queue.
 *
 * @flags   Must define + \c \__ENABLE_MOCANA_VLONG_ECC_CONVERSION__ in order to use this method.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_newMpintFromElement(PrimeFieldPtr pField, ConstPFEPtr pElem, ubyte** ppNewMpint, sbyte4 *pRetMpintLength, vlong** ppVlongQueue);

/**
 * @brief   Creates a new prime field element from a multiple precision integer.
 *
 * @details Creates a new prime field element from a multiple precision integer.
 *          The new element will be allocates so be sure to call \c PRIMEFIELD_deleteElement
 *          when finished with it. The input integer can be contained in a buffer of more than
 *          one integer and a pointer to the next integer will be updated upon successful completion
 *          of this method.
 *
 * @param pBuffer     Buffer holding the multiple precision integer(s) to be copied and converted.
 * @param bufSize     The length of pBuffer in bytes.
 * @param pBufIndex   Offset in pBuffer where the current integer to be converted is stored. The contents
 *                    of this pointer will be updated to the next potential integer in the buffer upon
 *                    succesful completion of this method.
 * @param pField      The globally defined prime field pointer you wish to associate with the element.
 * @param ppNewElem   Pointer to the location that will hold the newly allocated prime field element.
 *
 * @flags   Must define + \c \__ENABLE_MOCANA_VLONG_ECC_CONVERSION__ in order to use this method.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS PRIMEFIELD_newElementFromMpint(const ubyte* pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, PrimeFieldPtr pField, PFEPtr* ppNewElem);
#endif

#endif /* __ENABLE_MOCANA_ECC__  */

#ifdef __cplusplus
}
#endif

#endif /* __PRIMEFLD_HEADER__ */

