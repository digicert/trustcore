/*
 * primefld25519.c
 *
 * Prime Field Arithmetic for the field with 2^255 - 19 elements
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

/*
 This file provides methods to do arithmetic in the finite field
 of 2^255 - 19 elements. We can do it on 64-bit or 32-bit platforms.
 The 64 bit form follows Bernstein's original paper (Section 4).

 http://cr.yp.to/ecdh/curve25519-20060209.pdf

 Essentially a finite field element consists of an array of 10 (ie MOC_NUM_25519_UNITS)
 64-bit signed words. The radix is a fractional 25.5, meaning the 10 word
 array u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 represents...

 u0       + u1 2^26  + u2 2^51  + u3 2^77  + u4 2^102 +
 u5 2^128 + u6 2^153 + u7 2^179 + u8 2^204 + u9 2^230

 Since the integers u0 can be signed and larger than 26 bits there are
 multiple representations for a single finite field element. We will speak
 of a "reduced representation" or "reduced words" which will mean
 the words ui are actually all 26 bits or less, ie |ui| < 2^26 for each i.
 This does not refer to reduction modulo p and does not mean the words
 are positive (so still multiple reduced representations exist for each
 element).

 For 32 bit platforms we represent 64 bits using a struct consisting of a lo 32-bit
 subword that can be signed or unsinged, and a hi 32-bit subword that is unsigned. Reduced
 words are just treated as using the signed lo subword, and when adding unreduced
 words we use the unsigned lo and hi subword and a 2's complement representation
 within them to represent negative numbers (ie the first bit of the hi subword is the
 sign bit).

 Methods PF_25519_to_bytes and PF_25519_from_bytes are provided to go back and
 forth from Little Endian Byte arrays (of actually reduced mod p elements).

 IMPORTANT. The add and subtract methods here are not for general purpose but
 optimized specifically for the elliptic curve arithmetic methods on curve25519.
 We know only one add or subtract needs to be called at a time before the results
 get input to a multiply or square method. Therefore we don't have to do any
 carrys, borrows, or word reductions when doing an add or subtract.

 The PF_25519_multiply method will reduce the words of an element. More details
 are given in the comments about each method.

 Note most methods do not perform input validation checks and do not return a
 return code. Since these are all taylored specifically for curve25519 these
 should be considered as internal methods and calling methods are responsible
 for valid input.
 */

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_ECC__
#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

/* define these macros first, for use in the primefld25519.h header too */
#if (-32 >> 1) == -16
#define __PF_25519_SIGN_EXTENSION_OK__
#endif

#if (-1 & 3) == 3
#define __PF_25519_TWOS_COMPLIMENT_OK__
#endif

#include "../crypto/primefld25519.h"

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__

/* Little Endian of the prime p = 2^255 - 19 */
static const ubyte pP[MOC_NUM_25519_BYTES] =
{
    0xED,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F
};
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */

#define IS_ODD( a) (0x01 == (a & 0x01))

#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
#define SIGN_BIT_32( a) (a & 0x80000000)
#else
#define SIGN_BIT_32( a) (a < 0)
#endif

#define CONVERT_OUT( i, s) \
pResult[s+0] |=  pA[i] & 0xff; \
pResult[s+1]  = (pA[i] >> 8) & 0xff; \
pResult[s+2]  = (pA[i] >> 16) & 0xff; \
pResult[s+3]  = (pA[i] >> 24) & 0xff

#define CONVERT_IN( n, start, shift, mask) \
pResult[n] = ((((sbyte4) pInput[start + 0]) | \
((sbyte4) pInput[start + 1]) << 8 | \
((sbyte4) pInput[start + 2]) << 16 | \
((sbyte4) pInput[start + 3]) << 24) >> shift) & mask

/*---------------------------------------------------------------------------*/

/*
 We use the __DIGICERT_MAX_INT__ flag from mtypes.h indicating the sbyte8 type
 is a 64 bit long long, even if the system is a 32-bit system.
 */
#if __DIGICERT_MAX_INT__ == 64

typedef sbyte8 pf_unit_25519;

#define PLUS_EQ( res, a) res += a
#define MINUS_EQ( res, a) res -= a
#define PLUS_EQ_PRODUCT( res, a, b) res += (a * b)
#define LEFT_SHIFT( a, bits) a <<= bits
#define ZERO( a) a = 0x00LL

#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
#define SIGN_BIT( a) (a & 0x8000000000000000LL)
#else
#define SIGN_BIT( a) (a < 0)
#endif

#define AND_EQ( a, b) a &= b##LL

/*
 RIGHT_SHIFT_EQ not used for 64-bit negative numbers without both
 2's compliment and sign extension. ok to keep this macro simple.
 */
#define RIGHT_SHIFT_EQ( res, a, bits) res = (a >> bits)

#else /* __DIGICERT_MAX_INT__ == 64 */

typedef struct
{
    union
    {
        sbyte4 lo_signed;
        ubyte4 lo;
    };
    ubyte4 hi;

} pf_unit_25519;

#define PLUS_EQ( res, a) doPLUS_EQ( &res, &a)
#define MINUS_EQ( res, a) doMINUS_EQ( &res, &a)
#define PLUS_EQ_PRODUCT( res, a, b) doPLUS_EQ_PRODUCT( &res, a.lo_signed, b.lo_signed)
#define LEFT_SHIFT( a, bits) doLEFT_SHIFT_##bits( &a)
#define LEFT_SHIFT_EQ( res, a, bits) doLEFT_SHIFT_##bits( &res, &a)
#define ZERO( a) a.hi = 0; a.lo = 0
#define SIGN_BIT( a) (a.hi & 0x80000000)
#define AND_EQ( a, b) a.lo &= b; a.hi = 0
#define RIGHT_SHIFT_EQ( res, a, bits) doRIGHT_SHIFT_##bits( &res, &a)

/* inplace left shift 1 bit */
static void MOC_INLINE doLEFT_SHIFT_1(pf_unit_25519 *res)
{
    res->hi <<= 1;
    res->hi |= ((res->lo & 0x80000000) >> 31);
    res->lo <<= 1;
}

/* inplace left shift 3 bits */
static void MOC_INLINE doLEFT_SHIFT_3(pf_unit_25519 *res)
{
    res->hi <<= 3;
    res->hi |= ((res->lo & 0xe0000000) >> 29);
    res->lo <<= 3;
}

/*
 res = a left shifted 25 bits,
 ok for res and a to be the same pointer,
 a is not modified if its a distinct pointer from res.
 */
static void MOC_INLINE doLEFT_SHIFT_25(pf_unit_25519 *res, pf_unit_25519 *a)
{
    res->hi = a->hi << 25;
    res->hi |= ((a->lo & 0xffffff80) >> 7);
    res->lo = a->lo << 25;
}

/*
 res = a left shifted 26 bits,
 ok for res and a to be the same pointer,
 a is not modified if its a distinct pointer from res.
 */
static void MOC_INLINE doLEFT_SHIFT_26(pf_unit_25519 *res, pf_unit_25519 *a)
{
    res->hi = a->hi << 26;
    res->hi |= ((a->lo & 0xffffffc0) >> 6);
    res->lo = a->lo << 26;
}

/*
 res = a right shifted 25 bits,
 ok for res and a to be the same pointer,
 a is not modified if its a distinct pointer from res.
 */
static void MOC_INLINE doRIGHT_SHIFT_25(pf_unit_25519 *res, pf_unit_25519 *a)
{
    res->lo = a->lo >> 25;
    res->lo |= (((a->hi) & 0x01ffffff) << 7);
#ifdef __PF_25519_SIGN_EXTENSION_OK__
    res->hi = (ubyte4) (((sbyte4) a->hi) >> 25);
#else
    res->hi = a->hi >> 25;
    if (a->hi & 0x80000000)
    {
        res->hi |= 0xffffff80;
    }
#endif
}

/*
 res = a right shifted 26 bits,
 ok for res and a to be the same pointer,
 a is not modified if its a distinct pointer from res.
 */
static void MOC_INLINE doRIGHT_SHIFT_26(pf_unit_25519 *res, pf_unit_25519 *a)
{
    res->lo = a->lo >> 26;
    res->lo |= (((a->hi) & 0x03ffffff) << 6);
#ifdef __PF_25519_SIGN_EXTENSION_OK__
    res->hi = (ubyte4) (((sbyte4) a->hi) >> 26);
#else
    res->hi = a->hi >> 26;
    if (a->hi & 0x80000000)
    {
        res->hi |= 0xffffffc0;
    }
#endif
}

/*
 Computes res = res + a
 res and a should not be bigger than 62 bits in order to avoid overflow.
 NOT OK for res and a to be the same pointer
 */
static void MOC_INLINE doPLUS_EQ(pf_unit_25519 *res, pf_unit_25519 *a)
{
    res->lo += a->lo;
    if ( (ubyte4) (res->lo) < (ubyte4) (a->lo))
    { /* carry */
        res->hi++;
    }
    res->hi += a->hi;
}

/*
 Computes res = res - a
 We do this by calling doPLUS_EQ(res, -a)

 IMPORTANT NOTE: a is modified to be -a so this should only
 be called when a is a temp variable whose value is no longer needed.

 NOT OK for res and a to be the same pointer.
 */
static void MOC_INLINE doMINUS_EQ(pf_unit_25519 *res, pf_unit_25519 *a)
{
    /* first make -a */
    a->lo = ~a->lo;
    a->hi = ~a->hi;

    a->lo++;
    if (0 == a->lo)
    { /* carry to hi word */
        a->hi++;
    }

    /* add -a */
    doPLUS_EQ(res, a);
}

/*
 Computes res = res + a*b

 Input a and b are signed integers that should satisfy
 |a| < 2^27 and |b| < 2^27.

 Their product will be an up to 54 bit signed integer stored in the
 2 32-bit unsigned words of temp. It will be in 2's compliment
 form if negative. temp then will be added to res.
 */
static void doPLUS_EQ_PRODUCT(pf_unit_25519 *res, sbyte4 a, sbyte4 b)
{

    ubyte4 a0,a1,b0,b1,inner;
    byteBoolean isNegative = FALSE;

    pf_unit_25519 temp = {0,0};

    /* first make a and b positive, store for now in a1 and b1 */
    if ( SIGN_BIT_32(a) )    /* if negative */
    {
#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
        a1 = (ubyte4)((~a)+1); /* multiply by -1 */
#else
        a1 = (ubyte4)(-1 * a);
#endif
        isNegative = TRUE;
    }
    else
    {
        a1 = (ubyte4) a;
    }

    if ( SIGN_BIT_32(b) ) /* if negative */
    {
#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
        b1 = (ubyte4)((~b)+1); /* multiply by -1 */
#else
        b1 = (ubyte4)(-1 * b);
#endif
        isNegative = (isNegative ? FALSE : TRUE);
    }
    else
    {
        b1 = (ubyte4) b;
    }

    /* now write |a| as a0 + a1 2^16 */
    a0 = a1 & 0x0000ffff;
    a1 >>= 16;

    /* now write |b| as b0 + b1 2^16 */
    b0 = b1 & 0x0000ffff;
    b1 >>= 16;

    /*
     multiply |a| and |b| and put the result in temp. Start with the inner term as a simple
     sum of products. We won't use Karatsuba in order to avoid all the checks needed with
     respect to overflow. Here a1 and b1 are 11 bits or less and a0 and b0 are 16 bits
     or less, so there can't be overflow.
     */
    inner = a1 * b0 + a0 * b1;

    /* set the hi bit of temp, inner is at most 28 bits and a1*b1 at most 22, so no overflow */
    temp.hi = (inner >> 16) + (a1 * b1);

    /* set the lo bit of temp, we will check for overflow */
    inner = (inner & 0x0000ffff) << 16;
    temp.lo = inner + a0 * b0;
    if (temp.lo < inner)
    { /* overflow, carry to temp1 */
        temp.hi++;
    }

    /* if negative, make it a 2's complement signed 64 bit integer */
    if (isNegative)
    {
        temp.lo = ~temp.lo;
        temp.hi = ~temp.hi;

        (temp.lo)++;
        if (0 == temp.lo)
        { /* carry to hi word */
            (temp.hi)++;
        }
    }

    /* add the product to result */
    doPLUS_EQ(res, &temp);
}
#endif /* __DIGICERT_MAX_INT__ == 64 */


/*
 Takes in a finite field element whose words might be up to 267 * (a 54 bit number)
 in size and reduces them back to 26 bits or less each. This is done by carrying factors of
 2^26 or 2^25 in a word of pA into the next most significant word. When we get to the most
 significant word we reduce 2^255 back to 19 and into our least significant word. Our
 least significant word may therefore need one additional reduction.

 NOTE: For 32 bit implementations note the high 32-bit part of each word of pA can be ignored
 and the low 32-bit part will still be a 2's complement signed sbyte4. If we are not on a
 2's compliment system we need to properly convert it to what it should be.
 */
static void PF_25519_reduce_words(sbyte4 *pResult, pf_unit_25519 *pA)
{
    int i;

    pf_unit_25519 quotient;

#if __DIGICERT_MAX_INT__ != 64
    /* For 32-bits we will make use of a temp var for some intermediate results */
    pf_unit_25519 temp;
#endif

    ZERO(quotient);

    for (i = 0; i < MOC_NUM_25519_UNITS; i += 2) { /* we'll handle two words each iteration */

        /* handle a 26 bit word first */
        if ( SIGN_BIT(pA[i]) )            /* if negative */
        {
#if __DIGICERT_MAX_INT__ == 64
            /*
             to divide the negative value pA[i] by 2^26,
             we need to add 26 bits, ie 0x03ffffff, before shifting.
             */
#if defined(__PF_25519_TWOS_COMPLIMENT_OK__) && defined(__PF_25519_SIGN_EXTENSION_OK__)
            RIGHT_SHIFT_EQ(quotient, (pA[i] + 0x03ffffffLL), 26);
#else
            quotient = pA[i] / 0x04000000LL;
#endif
            /* Subtract leaving pA[i] as the remainder, which is < 26 bits */
            MINUS_EQ(pA[i], (quotient << 26));
#else /* __DIGICERT_MAX_INT__ == 32 */
            temp.lo = 0x03ffffff;
            temp.hi = 0;

            /*
             to divide the negative value pA[i] by 2^26,
             we need to add 26 bits, ie 0x03ffffff, before shifting.
             */
            PLUS_EQ(temp, pA[i]);
            RIGHT_SHIFT_EQ(quotient, temp, 26);
            LEFT_SHIFT_EQ(temp, quotient, 26);
            /* Subtract leaving pA[i] as the remainder which is < 26 bits */
            MINUS_EQ(pA[i], temp);
#ifndef __PF_25519_TWOS_COMPLIMENT_OK__
            /*
             Convert the low byte of pA to a positive integer and then put
             it back in the form the system requires
             */
            pA[i].lo_signed = -1 * (sbyte4) ((~(pA[i].lo)) + 1);
#endif
#endif /* __DIGICERT_MAX_INT__ == 64 */
        }
        else  /* pA[i] is positive */
        {
            /* simple divide by 2^26 */
            RIGHT_SHIFT_EQ(quotient, pA[i], 26);
            /* simple mod by 2^26 */
            AND_EQ(pA[i], 0x03ffffff);
        }

        /*
         add the quotient to the next word of pA.
         Note: We are adding at most (267 * 2^54)/2^26 or 267 * 2^28.
         so the sum here is now easily bounded by 268 * 2^54 and
         continuing this for the next 9 words will still give
         us all values < 277 * 2^54.
         */
        PLUS_EQ(pA[i+1], quotient);

        /*
         handle a 25 bit word next, similar to the above code
         except the bound on the quotient is (277 * 2^54)/2^25 or 277 * 2^29
         */
        if ( SIGN_BIT(pA[i+1]) )
        {
#if __DIGICERT_MAX_INT__ == 64
#if defined(__PF_25519_TWOS_COMPLIMENT_OK__) && defined(__PF_25519_SIGN_EXTENSION_OK__)
            RIGHT_SHIFT_EQ(quotient, (pA[i+1] + 0x01ffffffLL), 25);
#else
            quotient = pA[i+1] / 0x02000000LL;
#endif
            MINUS_EQ(pA[i+1], (quotient << 25));
#else /* __DIGICERT_MAX_INT__ == 32 */
            temp.lo = 0x01ffffff;
            temp.hi = 0;

            PLUS_EQ(temp, pA[i+1]);
            RIGHT_SHIFT_EQ(quotient, temp, 25);
            LEFT_SHIFT_EQ(temp, quotient, 25);
            MINUS_EQ(pA[i+1], temp);
#ifndef __PF_25519_TWOS_COMPLIMENT_OK__
            /*
             Convert the low byte of pA to a positive integer and then put
             it back in the form the system requires
             */
            pA[i+1].lo_signed = -1 * (sbyte4) ((~(pA[i+1].lo)) + 1);
#endif
#endif
        }
        else
        {
            RIGHT_SHIFT_EQ(quotient, pA[i+1], 25);
            AND_EQ(pA[i+1], 0x01ffffff);
        }

        /* add the quotient to the next word of pA */
        if (i < MOC_NUM_25519_UNITS - 2)       /* not the final word */
        {
            PLUS_EQ(pA[i+2], quotient);
        }
        else /* a value of 2^255 reduces to 19, add 19 * quotient back to least
              significant word. Note this is < 19 * 277 * 2^29
              and pA[0] is already reduced, ie < 2^26 */
        {
            PLUS_EQ(pA[0], quotient); /* += quotient */
            LEFT_SHIFT(quotient, 1);
            PLUS_EQ(pA[0], quotient); /* += 2 * quotient */
            LEFT_SHIFT(quotient, 3);
            PLUS_EQ(pA[0], quotient); /* += 16 * quotient */
        }
    }

    /* reduce the least significant word again */
    if ( SIGN_BIT(pA[0]) )
    {
#if __DIGICERT_MAX_INT__ == 64
#if defined(__PF_25519_TWOS_COMPLIMENT_OK__) && defined(__PF_25519_SIGN_EXTENSION_OK__)
        RIGHT_SHIFT_EQ(quotient, (pA[0] + 0x03ffffffLL), 26);
#else
        quotient = pA[0] / 0x04000000LL;
#endif
        MINUS_EQ(pA[0], (quotient << 26));
#else /* __DIGICERT_MAX_INT__ == 32 */
        temp.lo = 0x03ffffff;
        temp.hi = 0;

        PLUS_EQ(temp, pA[0]);
        RIGHT_SHIFT_EQ(quotient, temp, 26);
        LEFT_SHIFT_EQ(temp, quotient, 26);
        MINUS_EQ(pA[0], temp);
#ifndef __PF_25519_TWOS_COMPLIMENT_OK__
        /*
         Convert the low byte of pA to a positive integer and then put
         it back in the form the system requires
         */
        pA[0].lo_signed = -1 * (sbyte4) ((~(pA[0].lo)) + 1);
#endif
#endif
    }
    else
    {
        RIGHT_SHIFT_EQ(quotient, pA[0], 26);
        AND_EQ(pA[0], 0x03ffffff);
    }

    /*
     Now quotient is at most (19 * 278 * 2^29) / 2^26 which is at most 16 bits.
     pA[1] is at most 25 bits so the following sum still satisfies that
     it is < 26 bits total. No further reductions needed
     */
    PLUS_EQ(pA[1], quotient);

    for (i = 0; i < MOC_NUM_25519_UNITS; ++i)
    {
#if __DIGICERT_MAX_INT__ == 64
        pResult[i] = (sbyte4) pA[i];
#else
        pResult[i] = pA[i].lo_signed;
#endif
    }
}


/*
 Multiplies two finite field elements pA and pB. The requirements are that the absolute
 value of the words of pA and pB are 27 bits or less. pA and pB are allowed to be the
 same pointer but one should use the more efficient PF_25519_square method in that
 case. pResultOut may be the same pointer as pAInput or pBInput.

 Multiplying the 10 (ie MOC_NUM_25519_UNITS) words of pA times the 10 words of pB gives
 a 10x10 multiplication table. The ij-th entry in the table is the coefficient
 of the i-th word of pA with the j-th word of pB. Note due to the fractional radix of 25.5
 we have alternating factors of 2 on odd index rows. Also coefficients containing a multiple
 of 2^255 get that factored out as just 19. The ith word of pResult therefore becomes the
 sum of the elements on the i-th and (10 + i)-th diagonals from the upper left.
 We expand along each diagonal, first the even numbered ones which alternate with additional
 factors of two, and then we do the odd numbered diagonals.

 Note that since each word of pA or PB is 27 bits or less, a product of two words is
 at most 54 bits, and so the largest possible value of a word of pResult
 is therefore (38*5 + 19*4 + 1) times a 54 bit number or 267 times a 54 bit number.
 This is at most 63 bits and fits in an pf_unit_25519 for either 64-bit or 32-bit platforms.

 The resulting pResult, will also have words of 26 bits or less
 (because PF_25519_reduce_words is called at the end).

 power of 2 |  0   26   51   77   102   128   153   179   204   230
 ---------------------------------------------------------------------
 0          |  1    1    1    1     1     1     1     1     1     1
 26         |  1    2    1    2     1     2     1     2     1    38
 51         |  1    1    1    1     1     1     1     1    19    19
 77         |  1    2    1    2     1     2     1    38    19    38
 102        |  1    1    1    1     1     1    19    19    19    19
 128        |  1    2    1    2     1    38    19    38    19    38
 153        |  1    1    1    1    19    19    19    19    19    19
 179        |  1    2    1   38    19    38    19    38    19    38
 204        |  1    1   19   19    19    19    19    19    19    19
 230        |  1   38   19   38    19    38    19    38    19    38
 */
void PF_25519_multiply(sbyte4 *pResultOut, const sbyte4 *pAInput, const sbyte4 *pBInput)
{
    int i;
    pf_unit_25519 temp;
    pf_unit_25519 pA[MOC_NUM_25519_UNITS];
    pf_unit_25519 pB[MOC_NUM_25519_UNITS];
    pf_unit_25519 pResult[MOC_NUM_25519_UNITS] = {0};

    for (i = 0; i < MOC_NUM_25519_UNITS; ++i)
    {
#if __DIGICERT_MAX_INT__ == 64
        pA[i] = (pf_unit_25519) pAInput[i];
#else
        pA[i].lo_signed = pAInput[i];
        /* no need to set hi byte as it's not used */
#endif
    }

    for (i = 0; i < MOC_NUM_25519_UNITS; ++i)
    {
#if __DIGICERT_MAX_INT__ == 64
        pB[i] = (pf_unit_25519) pBInput[i];
#else
        pB[i].lo_signed = pBInput[i];
#endif
    }

    /******* pResult[0] *******/

    /* expand along diagonal index 0 */
    PLUS_EQ_PRODUCT(pResult[0], pA[0], pB[0]);

    /* expand along diagonal index 10, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[2], pB[8]);
    PLUS_EQ_PRODUCT(temp, pA[4], pB[6]);
    PLUS_EQ_PRODUCT(temp, pA[6], pB[4]);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[2]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[0], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[0], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[0], temp); /* += 4 * temp */

    /* expand along diagonal index 10, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[3], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[5]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[3]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[1]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[0], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[0], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[0], temp); /* += 32 * temp */

    /******* pResult[1] *******/

    /* expand along diagonal index 1 */
    PLUS_EQ_PRODUCT(pResult[1], pA[0], pB[1]);
    PLUS_EQ_PRODUCT(pResult[1], pA[1], pB[0]);

    /* expand along diagonal index 11 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[2], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[3], pB[8]);
    PLUS_EQ_PRODUCT(temp, pA[4], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[6]);
    PLUS_EQ_PRODUCT(temp, pA[6], pB[5]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[4]);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[3]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[2]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[1], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[1], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[1], temp); /* += 4 * temp */

    /******* pResult[2] *******/

    /* expand along diagonal index 2, even indices */
    PLUS_EQ_PRODUCT(pResult[2], pA[0], pB[2]);
    PLUS_EQ_PRODUCT(pResult[2], pA[2], pB[0]);

    /* expand along diagonal index 2, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pB[1]);
    LEFT_SHIFT(temp, 1);    /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[2], temp);

    /* expand along diagonal index 12, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[4], pB[8]);
    PLUS_EQ_PRODUCT(temp, pA[6], pB[6]);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[4]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[2], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[2], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[2], temp); /* += 4 * temp */

    /* expand along diagonal index 12, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[3], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[5]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[3]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[2], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[2], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[2], temp); /* += 32 * temp */

    /******* pResult[3] *******/

    /* expand along diagonal index 3 */
    PLUS_EQ_PRODUCT(pResult[3], pA[0], pB[3]);
    PLUS_EQ_PRODUCT(pResult[3], pA[1], pB[2]);
    PLUS_EQ_PRODUCT(pResult[3], pA[2], pB[1]);
    PLUS_EQ_PRODUCT(pResult[3], pA[3], pB[0]);

    /* expand along diagonal index 13 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[4], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[8]);
    PLUS_EQ_PRODUCT(temp, pA[6], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[6]);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[5]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[4]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[3], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[3], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[3], temp); /* += 4 * temp */

    /******* pResult[4] *******/

    /* expand along diagonal index 4, even indices */
    PLUS_EQ_PRODUCT(pResult[4], pA[0], pB[4]);
    PLUS_EQ_PRODUCT(pResult[4], pA[2], pB[2]);
    PLUS_EQ_PRODUCT(pResult[4], pA[4], pB[0]);

    /* expand along diagonal index 4, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pB[3]);
    PLUS_EQ_PRODUCT(temp, pA[3], pB[1]);

    LEFT_SHIFT(temp, 1);    /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[4], temp);

    /* expand along diagonal index 14, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[6], pB[8]);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[6]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[4], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[4], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[4], temp); /* += 4 * temp */

    /* expand along diagonal index 14, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[5]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[4], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[4], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[4], temp); /* += 32 * temp */

    /******* pResult[5] *******/

    /* expand along diagonal index 5 */
    PLUS_EQ_PRODUCT(pResult[5], pA[0], pB[5]);
    PLUS_EQ_PRODUCT(pResult[5], pA[1], pB[4]);
    PLUS_EQ_PRODUCT(pResult[5], pA[2], pB[3]);
    PLUS_EQ_PRODUCT(pResult[5], pA[3], pB[2]);
    PLUS_EQ_PRODUCT(pResult[5], pA[4], pB[1]);
    PLUS_EQ_PRODUCT(pResult[5], pA[5], pB[0]);

    /* expand along diagonal index 15 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[6], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[8]);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[6]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[5], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[5], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[5], temp); /* += 4 * temp */

    /******* pResult[6] *******/

    /* expand along diagonal index 6, even indices */
    PLUS_EQ_PRODUCT(pResult[6], pA[0], pB[6]);
    PLUS_EQ_PRODUCT(pResult[6], pA[2], pB[4]);
    PLUS_EQ_PRODUCT(pResult[6], pA[4], pB[2]);
    PLUS_EQ_PRODUCT(pResult[6], pA[6], pB[0]);

    /* expand along diagonal index 6, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pB[5]);
    PLUS_EQ_PRODUCT(temp, pA[3], pB[3]);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[1]);

    LEFT_SHIFT(temp, 1);    /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[6], temp);

    /* expand along diagonal index 16, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[8]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[6], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[6], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[6], temp); /* += 4 * temp */

    /* expand along diagonal index 16, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[7]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[6], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[6], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[6], temp); /* += 32 * temp */

    /******* pResult[7] *******/

    /* expand along diagonal index 7 */
    PLUS_EQ_PRODUCT(pResult[7], pA[0], pB[7]);
    PLUS_EQ_PRODUCT(pResult[7], pA[1], pB[6]);
    PLUS_EQ_PRODUCT(pResult[7], pA[2], pB[5]);
    PLUS_EQ_PRODUCT(pResult[7], pA[3], pB[4]);
    PLUS_EQ_PRODUCT(pResult[7], pA[4], pB[3]);
    PLUS_EQ_PRODUCT(pResult[7], pA[5], pB[2]);
    PLUS_EQ_PRODUCT(pResult[7], pA[6], pB[1]);
    PLUS_EQ_PRODUCT(pResult[7], pA[7], pB[0]);

    /* expand along diagonal index 17 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[8], pB[9]);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[8]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[7], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[7], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[7], temp); /* += 4 * temp */

    /******* pResult[8] *******/

    /* expand along diagonal index 8, even indices */
    PLUS_EQ_PRODUCT(pResult[8], pA[0], pB[8]);
    PLUS_EQ_PRODUCT(pResult[8], pA[2], pB[6]);
    PLUS_EQ_PRODUCT(pResult[8], pA[4], pB[4]);
    PLUS_EQ_PRODUCT(pResult[8], pA[6], pB[2]);
    PLUS_EQ_PRODUCT(pResult[8], pA[8], pB[0]);

    /* expand along diagonal index 8, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pB[7]);
    PLUS_EQ_PRODUCT(temp, pA[3], pB[5]);
    PLUS_EQ_PRODUCT(temp, pA[5], pB[3]);
    PLUS_EQ_PRODUCT(temp, pA[7], pB[1]);
    LEFT_SHIFT(temp, 1);      /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[8], temp);

    /* expand along diagonal index 18, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[9], pB[9]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[8], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[8], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[8], temp); /* += 32 * temp */

    /******* pResult[9] *******/

    /* expand along diagonal index 9 */
    PLUS_EQ_PRODUCT(pResult[9], pA[0], pB[9]);
    PLUS_EQ_PRODUCT(pResult[9], pA[1], pB[8]);
    PLUS_EQ_PRODUCT(pResult[9], pA[2], pB[7]);
    PLUS_EQ_PRODUCT(pResult[9], pA[3], pB[6]);
    PLUS_EQ_PRODUCT(pResult[9], pA[4], pB[5]);
    PLUS_EQ_PRODUCT(pResult[9], pA[5], pB[4]);
    PLUS_EQ_PRODUCT(pResult[9], pA[6], pB[3]);
    PLUS_EQ_PRODUCT(pResult[9], pA[7], pB[2]);
    PLUS_EQ_PRODUCT(pResult[9], pA[8], pB[1]);
    PLUS_EQ_PRODUCT(pResult[9], pA[9], pB[0]);

    /* reduce the words of pResult */
    PF_25519_reduce_words(pResultOut, pResult);
}


/*
 Computes pA^2. This is more efficient than using PF_25519_multiply
 since instead of computing all 100 possible products of words (from
 two distinct elements), we have to compute only 55 products (ie half
 of the matrix shown above including the diagonal).

 pResultOut may be the same pointer as pAInput.
 */
void PF_25519_square(sbyte4 *pResultOut, const sbyte4 *pAInput)
{
    int i;
    pf_unit_25519 temp;
    pf_unit_25519 pA[MOC_NUM_25519_UNITS];
    pf_unit_25519 pResult[MOC_NUM_25519_UNITS] = {0};

    for (i = 0; i < MOC_NUM_25519_UNITS; ++i)
    {
#if __DIGICERT_MAX_INT__ == 64
        pA[i] = (pf_unit_25519) pAInput[i];
#else
        pA[i].lo_signed = pAInput[i];
        /* no need to set hi byte as it's not used */
#endif
    }

    /*
     Each diagonal expansion (ie lower left to upper right) now only
     needs to go until the halfway point (ie the upper left to lower
     right diagonal) and then can be doubled (except for products
     representing exactly the diagonal)
     */

    /******* pResult[0] *******/

    /* expand along diagonal index 0 */
    PLUS_EQ_PRODUCT(pResult[0], pA[0], pA[0]);

    /* expand along diagonal index 10, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[2], pA[8]);
    PLUS_EQ_PRODUCT(temp, pA[4], pA[6]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[0], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[0], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[0], temp); /* += 4 * temp */

    /* expand along diagonal index 10, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pA[9]);
    PLUS_EQ_PRODUCT(temp, pA[3], pA[7]);
    LEFT_SHIFT(temp, 1);                /* double it */
    PLUS_EQ_PRODUCT(temp, pA[5], pA[5]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[0], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[0], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[0], temp); /* += 32 * temp */

    /******* pResult[1] *******/

    /* expand along diagonal index 1 */
    PLUS_EQ_PRODUCT(pResult[1], pA[0], pA[1]);
    LEFT_SHIFT(pResult[1], 1);          /* double it */

    /* expand along diagonal index 11 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[2], pA[9]);
    PLUS_EQ_PRODUCT(temp, pA[3], pA[8]);
    PLUS_EQ_PRODUCT(temp, pA[4], pA[7]);
    PLUS_EQ_PRODUCT(temp, pA[5], pA[6]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[1], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[1], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[1], temp); /* += 4 * temp */

    /******* pResult[2] *******/

    /* expand along diagonal index 2, even indices */
    PLUS_EQ_PRODUCT(pResult[2], pA[0], pA[2]);
    LEFT_SHIFT(pResult[2], 1);          /* double it */

    /* expand along diagonal index 2, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pA[1]);
    LEFT_SHIFT(temp, 1);    /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[2], temp);

    /* expand along diagonal index 12, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[4], pA[8]);
    LEFT_SHIFT(temp, 1);                /* double it */
    PLUS_EQ_PRODUCT(temp, pA[6], pA[6]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[2], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[2], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[2], temp); /* += 4 * temp */

    /* expand along diagonal index 12, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[3], pA[9]);
    PLUS_EQ_PRODUCT(temp, pA[5], pA[7]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[2], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[2], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[2], temp); /* += 32 * temp */

    /******* pResult[3] *******/

    /* expand along diagonal index 3 */
    PLUS_EQ_PRODUCT(pResult[3], pA[0], pA[3]);
    PLUS_EQ_PRODUCT(pResult[3], pA[1], pA[2]);
    LEFT_SHIFT(pResult[3], 1);          /* double it */

    /* expand along diagonal index 13 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[4], pA[9]);
    PLUS_EQ_PRODUCT(temp, pA[5], pA[8]);
    PLUS_EQ_PRODUCT(temp, pA[6], pA[7]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[3], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[3], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[3], temp); /* += 4 * temp */

    /******* pResult[4] *******/

    /* expand along diagonal index 4, even indices */
    PLUS_EQ_PRODUCT(pResult[4], pA[0], pA[4]);
    LEFT_SHIFT(pResult[4], 1);          /* double it */
    PLUS_EQ_PRODUCT(pResult[4], pA[2], pA[2]);

    /* expand along diagonal index 4, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pA[3]);
    LEFT_SHIFT(temp, 1);                /* double it */

    LEFT_SHIFT(temp, 1);    /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[4], temp);

    /* expand along diagonal index 14, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[6], pA[8]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[4], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[4], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[4], temp); /* += 4 * temp */

    /* expand along diagonal index 14, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[5], pA[9]);
    LEFT_SHIFT(temp, 1);                /* double it */
    PLUS_EQ_PRODUCT(temp, pA[7], pA[7]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[4], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[4], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[4], temp); /* += 32 * temp */

    /******* pResult[5] *******/

    /* expand along diagonal index 5 */
    PLUS_EQ_PRODUCT(pResult[5], pA[0], pA[5]);
    PLUS_EQ_PRODUCT(pResult[5], pA[1], pA[4]);
    PLUS_EQ_PRODUCT(pResult[5], pA[2], pA[3]);
    LEFT_SHIFT(pResult[5], 1);          /* double it */

    /* expand along diagonal index 15 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[6], pA[9]);
    PLUS_EQ_PRODUCT(temp, pA[7], pA[8]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[5], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[5], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[5], temp); /* += 4 * temp */

    /******* pResult[6] *******/

    /* expand along diagonal index 6, even indices */
    PLUS_EQ_PRODUCT(pResult[6], pA[0], pA[6]);
    PLUS_EQ_PRODUCT(pResult[6], pA[2], pA[4]);
    LEFT_SHIFT(pResult[6], 1);          /* double it */

    /* expand along diagonal index 6, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pA[5]);
    LEFT_SHIFT(temp, 1);                /* double it */
    PLUS_EQ_PRODUCT(temp, pA[3], pA[3]);

    LEFT_SHIFT(temp, 1);    /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[6], temp);

    /* expand along diagonal index 16, even indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[8], pA[8]);

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[6], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[6], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[6], temp); /* += 4 * temp */

    /* expand along diagonal index 16, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[7], pA[9]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[6], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[6], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[6], temp); /* += 32 * temp */

    /******* pResult[7] *******/

    /* expand along diagonal index 7 */
    PLUS_EQ_PRODUCT(pResult[7], pA[0], pA[7]);
    PLUS_EQ_PRODUCT(pResult[7], pA[1], pA[6]);
    PLUS_EQ_PRODUCT(pResult[7], pA[2], pA[5]);
    PLUS_EQ_PRODUCT(pResult[7], pA[3], pA[4]);
    LEFT_SHIFT(pResult[7], 1);          /* double it */

    /* expand along diagonal index 17 */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[8], pA[9]);
    LEFT_SHIFT(temp, 1);                /* double it */

    /* add (19 * temp) to pResult */
    PLUS_EQ(pResult[7], temp); /* += temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[7], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[7], temp); /* += 4 * temp */

    /******* pResult[8] *******/

    /* expand along diagonal index 8, even indices */
    PLUS_EQ_PRODUCT(pResult[8], pA[0], pA[8]);
    PLUS_EQ_PRODUCT(pResult[8], pA[2], pA[6]);
    LEFT_SHIFT(pResult[8], 1);          /* double it */
    PLUS_EQ_PRODUCT(pResult[8], pA[4], pA[4]);

    /* expand along diagonal index 8, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[1], pA[7]);
    PLUS_EQ_PRODUCT(temp, pA[3], pA[5]);
    LEFT_SHIFT(temp, 1);      /* double it */
    LEFT_SHIFT(temp, 1);      /* multiply the intermediate sum by 2. */
    PLUS_EQ(pResult[8], temp);

    /* expand along diagonal index 18, odd indices */
    ZERO(temp);
    PLUS_EQ_PRODUCT(temp, pA[9], pA[9]);

    /* add (38 * temp) to pResult */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[8], temp); /* += 2 * temp */
    LEFT_SHIFT(temp, 1);
    PLUS_EQ(pResult[8], temp); /* += 4 * temp */
    LEFT_SHIFT(temp, 3);
    PLUS_EQ(pResult[8], temp); /* += 32 * temp */

    /******* pResult[9] *******/

    /* expand along diagonal index 9 */
    PLUS_EQ_PRODUCT(pResult[9], pA[0], pA[9]);
    PLUS_EQ_PRODUCT(pResult[9], pA[1], pA[8]);
    PLUS_EQ_PRODUCT(pResult[9], pA[2], pA[7]);
    PLUS_EQ_PRODUCT(pResult[9], pA[3], pA[6]);
    PLUS_EQ_PRODUCT(pResult[9], pA[4], pA[5]);
    LEFT_SHIFT(pResult[9], 1);          /* double it */

    /* reduce the words of pResult */
    PF_25519_reduce_words(pResultOut, pResult);
}


/*
 If isInverse is true then this computes the modular inverse of pA by
 raising pA to the (p-2)-th power, ie to the 2^255 - 21.

 If isInverse is false then this computes pA to the (p-5)/8-th power,
 ie to the 2^252 - 3.

 We use Bernstein's addition chain.
 */
MSTATUS PF_25519_specialExp(sbyte4 *pResult, const sbyte4 *pA, const byteBoolean isInverse)
{
    MSTATUS status;
    int i;

    sbyte4 *pTemp1 = NULL;
    sbyte4 *pTemp2;
    sbyte4 *pTemp3;
    sbyte4 *pTemp4;
    sbyte4 *pTemp5;

    /* Allocate memory for all 5 temp vars in a single shot */
    status = DIGI_CALLOC((void**) &pTemp1, 1, 5 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        return status;

    pTemp2 = pTemp1 + MOC_NUM_25519_UNITS;
    pTemp3 = pTemp2 + MOC_NUM_25519_UNITS;
    pTemp4 = pTemp3 + MOC_NUM_25519_UNITS;
    pTemp5 = pTemp4 + MOC_NUM_25519_UNITS;

    /* pA to an exponent of 2 */
    PF_25519_square(pTemp1,pA);

    /* pA to an exponent of 4 */
    PF_25519_square(pTemp2,pTemp1);

    /* pA to an exponent of 8 */
    PF_25519_square(pTemp3,pTemp2);

    /* pA to an exponent of 9 */
    PF_25519_multiply(pTemp4,pTemp3,pA);

    /* pA to an exponent of 11 */
    PF_25519_multiply(pTemp5,pTemp4,pTemp1);

    /* pA to an exponent of 22 */
    PF_25519_square(pTemp3,pTemp5);

    /****** done with this pTemp1, reuse it ******/

    /* pA to an exponent of 2^5 - 2^0 = 31 */
    PF_25519_multiply(pTemp1,pTemp3,pTemp4);

    /****** done with this pTemp4, reuse it later ******/

    /* pA to an exponent of 2^6 - 2^1 */
    PF_25519_square(pTemp3,pTemp1);

    /* pA to an exponent of 2^7 - 2^2 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^8 - 2^3 */
    PF_25519_square(pTemp3,pTemp2);

    /* pA to an exponent of 2^9 - 2^4 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^10 - 2^5 */
    PF_25519_square(pTemp3,pTemp2);

    /* pA to an exponent of 2^10 - 2^0 */
    PF_25519_multiply(pTemp4,pTemp3,pTemp1);

    /****** done with pTemp1 again, reuse ******/

    /* pA to an exponent of 2^11 - 2^1 */
    PF_25519_square(pTemp3,pTemp4);

    /* pA to an exponent of 2^12 - 2^2 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^20 - 2^10 */
    for (i = 2; i < 10; i += 2)
    {
        PF_25519_square(pTemp3,pTemp2);
        PF_25519_square(pTemp2,pTemp3);
    }

    /* pA to an exponent of 2^20 - 2^0 */
    PF_25519_multiply(pTemp1,pTemp2,pTemp4);

    /* pA to an exponent of 2^21 - 2^1 */
    PF_25519_square(pTemp3,pTemp1);

    /* pA to an exponent of 2^22 - 2^2 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^40 - 2^20 */
    for (i = 2; i < 20; i += 2)
    {
        PF_25519_square(pTemp3,pTemp2);
        PF_25519_square(pTemp2,pTemp3);
    }

    /* pA to an exponent of 2^40 - 2^0 */
    PF_25519_multiply(pTemp3,pTemp2,pTemp1);

    /****** done with pTemp1 again, reuse ******/

    /* pA to an exponent of 2^41 - 2^1 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^42 - 2^2 */
    PF_25519_square(pTemp3,pTemp2);

    /* pA to an exponent of 2^50 - 2^10 */
    for (i = 2; i < 10; i += 2)
    {
        PF_25519_square(pTemp2,pTemp3);
        PF_25519_square(pTemp3,pTemp2);
    }

    /* pA to an exponent of 2^50 - 2^0 */
    PF_25519_multiply(pTemp1,pTemp3,pTemp4);

    /****** done with pTemp4 again *******/

    /* pA to an exponent of 2^51 - 2^1 */
    PF_25519_square(pTemp3,pTemp1);

    /* pA to an exponent of 2^52 - 2^2 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^100 - 2^50 */
    for (i = 2; i < 50; i += 2)
    {
        PF_25519_square(pTemp3,pTemp2);
        PF_25519_square(pTemp2,pTemp3);
    }

    /* pA to an exponent of 2^100 - 2^0 */
    PF_25519_multiply(pTemp4,pTemp2,pTemp1);

    /* pA to an exponent of 2^101 - 2^1 */
    PF_25519_square(pTemp2,pTemp4);

    /* pA to an exponent of 2^102 - 2^2 */
    PF_25519_square(pTemp3,pTemp2);

    /* pA to an exponent of 2^200 - 2^100 */
    for (i = 2; i < 100; i += 2)
    {
        PF_25519_square(pTemp2,pTemp3);
        PF_25519_square(pTemp3,pTemp2);
    }

    /* pA to an exponent of 2^200 - 2^0 */
    PF_25519_multiply(pTemp2,pTemp3,pTemp4);

    /* pA to an exponent of 2^201 - 2^1 */
    PF_25519_square(pTemp3,pTemp2);

    /* pA to an exponent of 2^202 - 2^2 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^250 - 2^50 */
    for (i = 2; i < 50; i += 2)
    {
        PF_25519_square(pTemp3,pTemp2);
        PF_25519_square(pTemp2,pTemp3);
    }

    /* pA to an exponent of 2^250 - 2^0 */
    PF_25519_multiply(pTemp3,pTemp2,pTemp1);

    /* pA to an exponent of 2^251 - 2^1 */
    PF_25519_square(pTemp2,pTemp3);

    /* pA to an exponent of 2^252 - 2^2 */
    PF_25519_square(pTemp3,pTemp2);

    if (isInverse)
    {
        /* pA to an exponent of 2^253 - 2^3 */
        PF_25519_square(pTemp2,pTemp3);

        /* pA to an exponent of 2^254 - 2^4 */
        PF_25519_square(pTemp3,pTemp2);

        /* pA to an exponent of 2^255 - 2^5 */
        PF_25519_square(pTemp2,pTemp3);

        /* pA to an exponent of 2^255 - 21 */
        PF_25519_multiply(pResult,pTemp2,pTemp5);
    }
    else
    {
        /* pA to an exponent of 2^252 - 3 */
        PF_25519_multiply(pResult, pTemp3, pA);
    }

    /* ignore return code of DIGI_MEMSET as we want to DIGI_FREE regardless, pTemp1 can't be NULL */
    DIGI_MEMSET((ubyte *) pTemp1, 0x00, 5*MOC_NUM_25519_ELEM_BYTES);
    return DIGI_FREE((void **)&pTemp1);
}


/*
 Returns TRUE if pA and pB represent the same element of the finite field.
 Remember elements may have different representations. We subtract and
 then output the result
 */
byteBoolean PF_25519_match(const sbyte4 *pA, const sbyte4 *pB)
{
    byteBoolean retVal = TRUE;
    int i;

    pf_unit_25519 pTemp[MOC_NUM_25519_UNITS];
    ubyte pBuffer[MOC_NUM_25519_BYTES];

    for (i = 0; i < MOC_NUM_25519_UNITS; ++i)
    {
#if __DIGICERT_MAX_INT__ == 64
        pTemp[i] = (pf_unit_25519) (pB[i] - pA[i]);
#else
        pTemp[i].lo_signed = pB[i] - pA[i];

        if (SIGN_BIT_32(pTemp[i].lo_signed)) /* keep the 2's compliment structure */
            pTemp[i].hi = 0xffffffff;
        else
            pTemp[i].hi = 0x00;
#endif
    }

    PF_25519_reduce_words((sbyte4 *) pTemp, pTemp);  /* re-use memory of pTemp */
    PF_25519_to_bytes(pBuffer, (sbyte4 *) pTemp);

    for (i = 0; i < MOC_NUM_25519_BYTES; ++i)
    {
        if (pBuffer[i])
        {
            retVal = FALSE;  /* ok to not be constant time */
            break;
        }
    }

    return retVal;
}


/*
 Converts an element pA into a Little Endian byte array.
 pA must be in a reduced form, ie |pA[i]| < 2^26 for each i.
 The buffer pResult should already have been allocated.

 NOTE: This method mangles pA so pA should no longer be
 used after calling this method.
 */
void PF_25519_to_bytes(ubyte *pResult, sbyte4 *pA)
{
    int i;
    int count = 0;
    sbyte4 borrow;

    /*
     Make each word positive by borrowing from the next larger word.
     We may need to go through this process twice.
     */
    while(count < 2)
    {
        for (i = 0; i < MOC_NUM_25519_UNITS - 1; ++i)
        {
            if( SIGN_BIT_32(pA[i]) )
            {
                if (IS_ODD(i))
                {
                    /* calculate how much to borrow, (-pA) / 2^25 */
#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
                    borrow = (((~pA[i])+1) >> 25);
#else
                    borrow = (-1 * pA[i]) >> 25; /* borrow is positive */
#endif
                    /* add 2^25 * borrow to the unit */
                    pA[i] = pA[i] + (borrow << 25);
                    /* subtract from the next unit */
                    pA[i+1] = pA[i+1] - borrow;
                }
                else
                {
                    /* same process except borrowing from a nominally 26 bit term */
#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
                    borrow = (((~pA[i])+1) >> 26);
#else
                    borrow = (-1 * pA[i]) >> 26; /* borrow is positive */
#endif
                    pA[i] = pA[i] + (borrow << 26);
                    pA[i+1] = pA[i+1] - borrow;
                }
            }
        }

        /* handle pA[9] by itself */
        if ( SIGN_BIT_32(pA[9]) )
        {
            /* for pA[9] borrow from 2^255. This is (2^255 * borrow = 19 * borrow) out of pA[0] */
#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
            borrow = (((~pA[9])+1) >> 25);
#else
            borrow = (-1 * pA[9]) >> 25; /* borrow is positive */
#endif
            pA[9] = pA[9] + (borrow << 25);
            pA[0] = pA[0] - (borrow * 19);

            /* However. now pA[0] might be negative! */
            if( SIGN_BIT_32(pA[0]) )
            {
                /*
                 Note that | pA[9] | was origially < 2^26 so the borrow from it is at most 1,
                 and pA[0] is now >= -19 after the first while loop iteration.
                 If we're in the second iteration we can only still be decreasing pA[0]
                 if every borrow of 1 happened to every word, ie pA[1] to pA[9] were all 0.
                 in this case we have input[1] is now exactly 2^25-1 and borrowing just 1 from
                 it will suffice in making input[0] non-negative while keeping input[1]
                 non-negative.
                 */
                if (count)
                {
#ifdef __PF_25519_TWOS_COMPLIMENT_OK__
                    borrow = (((~pA[0])+1) >> 26);
#else
                    borrow = (-1 * pA[0]) >> 26;   /* borrow is positive */
#endif
                    pA[0] = pA[0] + (borrow << 26);
                    pA[1] = pA[1] - borrow;
                    break; /* All terms are non-negative, break out */
                }
                else
                {
                    count++;
                }
            }
            else
            {
                break;  /* All terms are non-negative, break out */
            }
        }
        else
        {
            break; /* All terms are non-negative, break out */
        }
    }

    /*
     All pA[i] are now non-negative. However, there might be values between
     2^25 and 2^26 in a word which is, nominally, 25 bits wide. Use the borrow
     variable to represent a carry of an oversized word to the next word. Note
     this may make the next word too big even if it was nominally 26 bits. Loop
     through twice.
     */
    count = 0;
    while (count < 2)
    {
        for (i = 0; i < MOC_NUM_25519_UNITS - 1; ++i)
        {
            if (IS_ODD(i))
            {
                borrow = pA[i] >> 25;
                pA[i] &= 0x01ffffff;
                pA[i+1] += borrow;
            }
            else
            {
                borrow = pA[i] >> 26;
                pA[i] &= 0x03ffffff;
                pA[i+1] += borrow;
            }
        }

        borrow = pA[9] >> 25;
        pA[9] &= 0x01ffffff;
        pA[0] += 19 * borrow; /* 2^255 times borrow */
        count++;

        /*
         If pA[0] is out bounds after the first iteration then it is of
         course still < 2^26 + 38 (since the last carry can be at most 2).
         If we still carry to each term on the second iteration, then pA[0]
         will be decreased by 2^26 and on the second iteration will certainly
         be in bounds after adding at most 19.
         */
    }

    /*
     Even though all words of pA are the right size, it still
     remains the case that the value it represents might be between
     2^255-19 and 2^255. In this case, pA[1..9] must take their maximum value
     and pA[0] must be >= (2^255-19) which is 0x3ffffed.
     */
    if (0x01ffffff == pA[9] && 0x03ffffff == pA[8] && 0x01ffffff == pA[7] &&
        0x03ffffff == pA[6] && 0x01ffffff == pA[5] && 0x03ffffff == pA[4] &&
        0x01ffffff == pA[3] && 0x03ffffff == pA[2] && 0x01ffffff == pA[1] &&
        pA[0] >= 0x03ffffed )
    {
        pA[0] -= 0x03ffffed;
        for (i = 1; i < MOC_NUM_25519_UNITS; ++i)
        {
            pA[i] = 0;
        }
    }

    /*
     Ready to output shift each 25 or 26 bit word into what position they
     will go into in a 32-bit word byte array */
    pA[1] <<= 2;
    pA[2] <<= 3;
    pA[3] <<= 5;
    pA[4] <<= 6;
    pA[6] <<= 1;
    pA[7] <<= 3;
    pA[8] <<= 4;
    pA[9] <<= 6;

    /*
     each CONVERT_OUT will |= the first byte of a word with the last byte
     of the previous word. For byte index 0 and 16 (start of a new cycle)
     there was no previous word, so enusure the buffer starts at 0. */
    pResult[0] = 0;
    pResult[16] = 0;

    /* and now convert each word to bytes*/
    CONVERT_OUT(0,0);
    CONVERT_OUT(1,3);
    CONVERT_OUT(2,6);
    CONVERT_OUT(3,9);
    CONVERT_OUT(4,12);
    CONVERT_OUT(5,16);
    CONVERT_OUT(6,19);
    CONVERT_OUT(7,22);
    CONVERT_OUT(8,25);
    CONVERT_OUT(9,28);
}


/*
 Converts a Little Endian byte array representing a finite field element
 into an element.

 pInput must be defined and 32 bytes in length. pInput will be checked
 that it is not bigger than p if compareToThePrime = TRUE.
 */
MSTATUS PF_25519_from_bytes(sbyte4 *pResult, const ubyte *pInput, byteBoolean compareToThePrime)
{
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    /* Little Endian of the prime p = 2^255 - 19 */
    static const ubyte pP[MOC_NUM_25519_BYTES] =
    {
        0xED,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F
    };
#endif

    if (compareToThePrime)
    {
        int i = MOC_NUM_25519_BYTES - 1;

        while (i >= 0)
        {
            if ( pInput[i] > pP[i] )
            {
                return ERR_FF_DIFFERENT_FIELDS;
            }
            else if ( pInput[i] < pP[i] )
            {
                break;
            }
            i--;
        }
        if (-1 == i)   /* y = p in this case */
        {
            return ERR_FF_DIFFERENT_FIELDS;
        }
    }

    CONVERT_IN(0, 0, 0, 0x3ffffff);
    CONVERT_IN(1, 3, 2, 0x1ffffff);
    CONVERT_IN(2, 6, 3, 0x3ffffff);
    CONVERT_IN(3, 9, 5, 0x1ffffff);
    CONVERT_IN(4, 12, 6, 0x3ffffff);
    CONVERT_IN(5, 16, 0, 0x1ffffff);
    CONVERT_IN(6, 19, 1, 0x3ffffff);
    CONVERT_IN(7, 22, 3, 0x1ffffff);
    CONVERT_IN(8, 25, 4, 0x3ffffff);
    CONVERT_IN(9, 28, 6, 0x1ffffff);

    return OK;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) */
#endif /* __ENABLE_DIGICERT_ECC__ */
