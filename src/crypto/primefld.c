/*
 * primefld.c
 *
 * Prime Field Arithmetic
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

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_RSA_SIMPLE__) )

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../common/vlong.h"    /* need vlong.h because of inline functions in
                   some of the asm_math implementations */
#endif

#include "../common/asm_math.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#endif
#include "../crypto/ca_mgmt.h"
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
#include "../common/bn_mul.h"
#endif

/*---------------------------------------------------------------------------*/

/** NanoBoot needs to redirect MALLOC, etc... This is only used for that product */
#if defined(__USE_DIGICERT_SB_HEAP__)

MOC_EXTERN MSTATUS
sb_moc_malloc( void** pptr, size_t size);

MOC_EXTERN MSTATUS
sb_moc_free(void** pptr);

MOC_EXTERN void
sb_free(void* p);

MOC_EXTERN void*
sb_malloc( size_t size);

/* Un-define, if needed */
#ifdef MALLOC
#undef MALLOC
#undef FREE
#undef DIGI_MALLOC
#undef DIGI_FREE
#endif

/* Point to SB malloc API */
#define MALLOC           sb_malloc
#define FREE             sb_free
#define DIGI_MALLOC       sb_moc_malloc
#define DIGI_FREE         sb_moc_free
#endif /* __USE_DIGICERT_SB_HEAP__ */

#define IS_EVEN(arr)    (0 == ((arr[0]) & 1))

/*---------------------------------------------------------------------------*/

/* RSA Simple needs access to the BI functions in this file, but we only want
 * these ECC definitions if we are in fact using ECC */
#if (defined(__ENABLE_DIGICERT_ECC__))

#define DECLARE_PRIME_FIELD( a)  const struct PrimeField PrimeFieldP##a =\
        {   FF_p##a,                                                     \
            FF_p##a##p1d4,                                               \
            sizeof(FF_p##a)/sizeof(pf_unit),                             \
            a,                                                           \
            fastReductionP##a,                                           \
            cid_EC_P##a                                                  \
            };                                                           \
            MOC_EXTERN_DATA_DEF const PrimeFieldPtr PF_p##a = &PrimeFieldP##a;


#ifdef __ENABLE_DIGICERT_ECC_P192__
/*********** p192 **********************************************/
/* bytes of 2 ^192 - 2 ^ 64 - 1 stored least significant first */
#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit FF_p192[] = {
    0xffffffffffffffffULL,
    0xfffffffffffffffeULL,
    0xffffffffffffffffULL
};
static const pf_unit FF_p192p1d4[] = {
    0xc000000000000000ULL,
    0xffffffffffffffffULL,
    0x3fffffffffffffffULL

};
#else
static const pf_unit FF_p192[] = {
    0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff,
    0xffffffff
};
static const pf_unit FF_p192p1d4[] = {
    0x00000000, 0xc0000000, 0xffffffff, 0xffffffff, 0xffffffff,
    0x3fffffff
};
#endif

DECLARE_PRIME_FIELD(192);

#ifdef __MAX_UNITS
#undef __MAX_UNITS
#endif
#define __MAX_UNITS COUNTOF(FF_p192)

#endif  /* __ENABLE_DIGICERT_ECC_P192__ */


#ifndef __DISABLE_DIGICERT_ECC_P224__
/*********** p224 **********************************************/
/* bytes of 2 ^224 - 2 ^ 96 + 1 stored least significant first */
#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit FF_p224[] = {
    0x0000000000000001ULL,
    0xffffffff00000000ULL,
    0xffffffffffffffffULL,
    0xffffffffULL
};
static const pf_unit FF_p224p1d4[] = {
    0x0000000000000000ULL,
    0xffffffffc0000000ULL,
    0xffffffffffffffffULL,
    0x3fffffffULL
};

#else
static const pf_unit FF_p224[] = {
    0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff
};

static const pf_unit FF_p224p1d4[] = {
    0x00000000, 0x00000000, 0xc0000000, 0xffffffff, 0xffffffff,
    0xffffffff, 0x3fffffff
};
#endif

DECLARE_PRIME_FIELD(224);

#ifdef __MAX_UNITS
#undef __MAX_UNITS
#endif
#define __MAX_UNITS COUNTOF(FF_p224)


#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
/*********** p256 **********************************************/
/* bytes of 2 ^ 256 - 2 ^ 224 + 2^192 + 2 ^ 96 - 1 stored least significant first */
#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit FF_p256[] = {
    0xffffffffffffffffULL,
    0x00000000ffffffffULL,
    0x0000000000000000ULL,
    0xffffffff00000001ULL
};

static const pf_unit FF_p256p1d4[] = {
    0x0000000000000000ULL,
    0x0000000040000000ULL,
    0x4000000000000000ULL,
    0x3fffffffc0000000ULL,
};
#else
static const pf_unit FF_p256[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000,
    0x00000000, 0x00000001, 0xffffffff
};

static const pf_unit FF_p256p1d4[] = {
    0x00000000, 0x00000000, 0x40000000, 0x00000000, 0x00000000,
    0x40000000, 0xc0000000, 0x3fffffff
};
#endif

DECLARE_PRIME_FIELD(256);

#ifdef __MAX_UNITS
#undef __MAX_UNITS
#endif
#define __MAX_UNITS COUNTOF(FF_p256)

#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
/*********** p384 **********************************************/
/* bytes of 2 ^ 384 - 2 ^ 128 - 2^96 + 2 ^ 32 - 1 stored least significant first */
#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit FF_p384[] = {
    0x00000000ffffffffULL,
    0xffffffff00000000ULL,
    0xfffffffffffffffeULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL
};

static const pf_unit FF_p384p1d4[] = {
    0x0000000040000000ULL,
    0xbfffffffc0000000ULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x3fffffffffffffffULL
};

#else
static const pf_unit FF_p384[] = {
    0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xfffffffe,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff
};

static const pf_unit FF_p384p1d4[] = {
    0x40000000, 0x00000000, 0xc0000000, 0xbfffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0x3fffffff
};

#endif

DECLARE_PRIME_FIELD(384);

#ifdef __MAX_UNITS
#undef __MAX_UNITS
#endif
#define __MAX_UNITS COUNTOF(FF_p384)

#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)

/*********** X448 **********************************************/
/* bytes of 2 ^ 448 - 2 ^ 224 - 1 stored least significant first */
#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit FF_p448[] = {
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xfffffffeffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL
};

/* NOT NEEDED, zero it out */
static const pf_unit FF_p448p1d4[] = {
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL
};

#else
static const pf_unit FF_p448[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
};

/* NOT NEEDED, zero it out */
static const pf_unit FF_p448p1d4[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};
#endif

/*
 DECLARE_PRIME_FIELD requires curveId param of the form cid_EC_P...
 We may use the cid_EC_X448 here as this curveId is ununsed anyway
 */
#define cid_EC_P448 cid_EC_X448

DECLARE_PRIME_FIELD(448);

#ifdef __MAX_UNITS
#undef __MAX_UNITS
#endif
#define __MAX_UNITS COUNTOF(FF_p448)

#endif /* #if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__) */

#ifndef __DISABLE_DIGICERT_ECC_P521__
/*********** p521 **********************************************/
/* bytes of 2 ^521 - 1 stored least significant first */
#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit FF_p521[] = {
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x00000000000001ffULL
};

static const pf_unit FF_p521p1d4[] = {
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000080ULL
};

#else
static const pf_unit FF_p521[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0x000001ff
};
static const pf_unit FF_p521p1d4[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000080
};

#endif

DECLARE_PRIME_FIELD(521);

#ifdef __MAX_UNITS
#undef __MAX_UNITS
#endif
#define __MAX_UNITS COUNTOF(FF_p521)

#endif

#ifdef __MAX_UNITS
/* This global can be used to represent one(1) for all finite fields */
const pf_unit g_pOneUnits[__MAX_UNITS] = { 1 };
#endif

/*---------------------------------------------------------------------------*/

static sbyte4 BI_cmpToUnsigned(sbyte4 n, const pf_unit* a, pf_unit val)
{
    sbyte4 i;

    if (a[0] > val)
    {
        return 1;
    }

    /* need to look at the rest of units */
    for ( i = 1; i < n; ++i)
    {
        if ( a[i])
            return 1;
    }

    return ( a[0] == val) ? 0 : -1;
}

/*---------------------------------------------------------------------------*/

/* BI_sqr: multiplication hilo is size 2 * n */
void BI_sqr( sbyte4 n, pf_unit* hilo,
            const pf_unit* a, sbyte4 x_limit)
{

#ifndef __ENABLE_DIGICERT_BI_MUL_ASM__
    ubyte4  i_limit, j_limit;

#if ((defined(__ASM_CAVIUM__)) && (defined(MACRO_MULTIPLICATION_LOOP)))
    i_limit = j_limit = n;
#else
    i_limit = j_limit = n-1;
#endif
    /* x_limit = 2*n; */

/* currently the buffers are not set up to be used by the Altivec or SSE2 routines or ARM_NEON */
#if defined(__ALTIVEC__) || defined(__SSE2__) || defined(__ARM_NEON__) || defined(__ARM_V6__) || !defined(SQR_MULTIPLICATION_LOOP)
    {
        pf_unit  r0, r1, r2;
        pf_unit  h0, h1, h2;
        ubyte4  i, j;
        sbyte4 x;

        r0 = r1 = r2 = 0;

        for (x = 0; x < x_limit; x++)
        {
            h0 = h1 = h2 = 0;
            i = ((ubyte4) x <= i_limit) ? (ubyte4) x : i_limit;
            j = x - i;

            while (j < i)
            {
                /* r2:r1:r0 += a[i] * b[j]; */
                MULT_ADDCX(a, a, i, j, h0, h1, h2);
                i--; j++;
            }
            ADD_DOUBLE(r0, r1, r2, h0, h1, h2);

            /* add odd-even case */
            if (i == j)
            {
                MULT_ADDCX(a,a,i,j,r0,r1,r2);
            }

            *hilo++ = r0;
            r0  = r1;
            r1  = r2;
            r2  = 0;
        }
    }
#else
    SQR_MULTIPLICATION_LOOP(hilo,a,b,i_limit,j_limit,x_limit);
#endif

#else
    /* No assembly squaring method, multiply by itself */
    BI_mul(n, hilo, a, a, x_limit);
#endif /* __ENABLE_DIGICERT_BI_MUL_ASM__ */
}


/*---------------------------------------------------------------------------*/

/* FF_add: addition in the Finite Field
a_s = a_s + b mod p; a_s, b, mod are pf_unit[n]
should be implemented in assembly (carry handling) */
static void FF_add( sbyte4 n, pf_unit* a_s, const pf_unit* b,
                   const pf_unit* mod)
{
    pf_unit carry = BI_add(n, a_s, b);

    if ( carry ||  BI_cmp(n, a_s, mod) >= 0)
    {
        BI_sub(n, a_s, mod);
    }
}


/*---------------------------------------------------------------------------*/

/* FF_sub: subtraction in the Finite Field
a_s = a_s - b mod p; a_s, b, mod are pf_unit[n]
should be implemented in assembly (borrow handling) */
static void FF_sub( sbyte4 n, pf_unit* a_s, const pf_unit* b,
                   const pf_unit* mod)
{
    pf_unit borrow = BI_sub(n, a_s, b);

    if ( borrow)
    {
        BI_add(n, a_s, mod);
    }
}

/*---------------------------------------------------------------------------*/

/* BI_getBit: get bit */
static ubyte BI_getBit( sbyte4 n, const pf_unit* a_s, ubyte4 bit)
{
    ubyte4 index1, index2;

    index1 = bit / (sizeof( pf_unit) * 8);
    if (index1 < (ubyte4) n)
    {
        index2 = bit % (sizeof( pf_unit) * 8);
        return (ubyte) ((a_s[index1] >> index2) & 1);
    }
    return 0;
}

/*---------------------------------------------------------------------------*/

#if defined( _DEBUG) && defined(_WIN32)
#include <stdio.h>


void print_arr( const sbyte* msg, sbyte4 n, const pf_unit* arr)
{
    sbyte4 i;

    printf("%s = \n", msg);
    for (i = n-1; i >= 0; --i)
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        printf("%016I64X ", arr[i]);
#else
        printf("%08X ", arr[i]);
#endif
    }
    printf("\n");
}

void print_pfe( const sbyte* msg, PrimeFieldPtr pFld, ConstPFEPtr pfe)
{
    print_arr( msg, pFld->n, pfe->units);
}

#endif

/*---------------------------------------------------------------------------*/

static MSTATUS
FF_divide(sbyte4 n, pf_unit* r, const pf_unit* b, const pf_unit* a,
            const pf_unit* p)
{
    MSTATUS status = OK;

    sbyte4 i, ucmp;
    pf_unit *tmp = 0;
    pf_unit *u, *v, *x1, *x2;

    /* allocate some working area buffer */
    tmp = (pf_unit*) MALLOC(4 * sizeof(pf_unit) * n);
    if (!tmp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* make the temp var points to the working area */
    u = tmp;
    v = u + n;
    x1 = v + n;
    x2 = x1 + n;

    ucmp = 0;
    /* u = a, v = p, x1 = b, x2 = 0 */
    for ( i = 0; i < n; ++i)
    {
        if (0 != (u[i] = a[i]))
        {
            ++ucmp;
        }
        v[i] = p[i];
        x1[i] = b[i];
        x2[i] = 0;
    }

    /* while (u != 1 and v != 1) */
    while ( 0 != (ucmp = BI_cmpToUnsigned( n, u, 1)) &&
            0 != (BI_cmpToUnsigned( n, v, 1)) )
    {
        /* if u or v are zero then a is not invertible mod p */
        if (0 == BI_cmpToUnsigned( n, u, 0) || 0 == BI_cmpToUnsigned( n, v, 0))
        {
          status = ERR_DIVIDE_BY_ZERO;
          goto exit;
        }

        /* while u is even */
        while ( IS_EVEN(u) )
        {
            BI_shiftREx( n, u, 1);
            if ( IS_EVEN(x1) )
            {
                BI_shiftREx(n, x1, 1);
            }
            else
            {
                pf_unit carry = BI_add(n, x1, p);
                BI_shiftREx(n, x1, 1);
                x1[n-1] |= (carry << (BPU-1));
            }
        }

        /* while v is even */
        while ( IS_EVEN(v))
        {
            BI_shiftREx( n, v, 1);
            if ( IS_EVEN(x2))
            {
                BI_shiftREx(n, x2, 1);
            }
            else
            {
                pf_unit carry = BI_add(n, x2, p);
                BI_shiftREx(n, x2, 1);
                x2[n-1] |= (carry << (BPU-1) );
            }
        }

        /* if u >= v */
        if ( BI_cmp(n, u, v) >= 0)
        {
            FF_sub(n, u, v, p);
            FF_sub(n, x1, x2, p);
        }
        else
        {
            FF_sub(n, v, u, p);
            FF_sub(n, x2, x1, p);
        }
    }

    if (0 == ucmp)
    {
        x2 = x1;
    }
    for ( i = 0; i < n; ++i)
    {
        r[i] = x2[i];
    }

exit:

    if ( tmp)
    {
        FREE(tmp);
    }
    return status;
}


/*---------------------------------------------------------------------------*/

intBoolean
PRIMEFIELD_comparePrimeFields(PrimeFieldPtr pField1, PrimeFieldPtr pField2)
{
    if ( (NULL == pField1) || (NULL == pField2) )
    {
        return FALSE;
    }

    return (pField1->curveId == pField2->curveId) ? TRUE : FALSE;
}

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
static MSTATUS
FF_assignArrToVlong( const pf_unit* arr, ubyte4 n, vlong* res)
{
    MSTATUS status;
    ubyte4 c, i;

    /* determine the last non null element in arr */
    c = n + 1;
    for (i = 0; i < n; ++i)
    {
        if ( arr[i])
        {
            c = i;
        }
    }

    /* case arr = 0 */
    if ( n+1 == c)
    {
        res->numUnitsUsed = 0;
        return OK;
    }

    /* need c + 1 units -- reallocVlong will do nothing */
    if (OK > (status = VLONG_reallocVlong( res, c+1)))
    {
        return status;
    }

    res->numUnitsUsed = c+1;
    for (i = 0; i <= c; ++i)
    {
        res->pUnits[i] = arr[i];
    }

    return OK;
}
#endif /* (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__)) */


/*---------------------------------------------------------------------------*/

/* fast reduction functions for NIST curves */
#ifdef __ENABLE_DIGICERT_ECC_P192__

void
fastReductionP192(const pf_unit* c,
                    pf_unit* r,
                    PrimeFieldPtr pField)
{
    ubyte4 i;

#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit s[3];
    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 3; ++i)
    {
        r[i] = c[i];
    }
    /* make sure r is reduced via the modulus */
    if (BI_cmp(3, r, FF_p192) >= 0)
    {
        BI_sub(3, r, FF_p192);
    }

    /* r += s2 */
    s[2] = ZERO_UNIT;
    s[0] = s[1] = c[3];

    /* high bits of s2 are zero so we know it is reduced */
    FF_add( 3, r, s, FF_p192);

    /* r += s3 */
    s[2] = s[1] = c[4];
    s[0] = ZERO_UNIT;

    /* make sure s3 is reduced via the modulus */
    if (BI_cmp(3, s, FF_p192) >= 0)
    {
        BI_sub(3, s, FF_p192);
    }
    FF_add( 3, r, s, FF_p192);

    /* r += s4 */
    s[2] = s[1] = s[0] = c[5];

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(3, s, FF_p192) >= 0)
    {
        BI_sub(3, s, FF_p192);
    }
    FF_add( 3, r, s, FF_p192);

#else
    pf_unit s[6];
    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 6; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(6, r, FF_p192) >= 0)
    {
        BI_sub(6, r, FF_p192);
    }

    /* r += s2 */
    s[5] = s[4] = ZERO_UNIT;
    s[3] = s[1] = c[7];
    s[2] = s[0] = c[6];

    /* high bits of s2 are zero so we know it is reduced */
    FF_add( 6, r, s, FF_p192);

    /* r += s3 */
    s[5] = s[3] = c[9];
    s[4] = s[2] = c[8];
    s[1] = s[0] = ZERO_UNIT;

    /* make sure s3 is reduced via the modulus */
    if (BI_cmp(6, s, FF_p192) >= 0)
    {
        BI_sub(6, s, FF_p192);
    }
    FF_add( 6, r, s, FF_p192);

    /* r += s4 */
    s[5] = s[3] = s[1] = c[11];
    s[4] = s[2] = s[0] = c[10];

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(6, s, FF_p192) >= 0)
    {
        BI_sub(6, s, FF_p192);
    }
    FF_add( 6, r, s, FF_p192);

#endif
}

#endif


/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P224__

MOC_EXTERN void
fastReductionP224( const pf_unit* c,
                    pf_unit* r,
                    PrimeFieldPtr pField)
{
    ubyte4 i;

#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit s[4];

    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 3; ++i)
    {
        r[i] = c[i];
    }
    r[3] = LO_HUNIT(c[3]);

    /* make sure r is reduced via the modulus */
    if (BI_cmp(4, r, FF_p224) >= 0)
    {
        BI_sub(4, r, FF_p224);
    }

    /* r += s2 */
    s[0] = ZERO_UNIT;
    s[1] = c[3] & HI_MASK;
    s[2] = c[4];
    s[3] = LO_HUNIT(c[5]);

    /* bottom 1.5 words of s2 are zero so it is at most p-1
       and therefore it is reduced */
    FF_add( 4, r, s, FF_p224);

    /* r += s3 */
    s[0] = ZERO_UNIT;
    s[1] = c[5] & HI_MASK;
    s[2] = c[6];
    s[3] = ZERO_UNIT;

    /* bottom 1.5 words of s3 are zero and therefore it is reduced */
    FF_add( 4, r, s, FF_p224);

    /* r -= s4 */
    for (i = 0; i < 3; ++i)
    {
        s[i] = MAKE_UNIT( LO_HUNIT(c[i+4]), HI_HUNIT(c[i+3]));
    }
    s[3] = HI_HUNIT(c[6]);

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(4, s, FF_p224) >= 0)
    {
        BI_sub(4, s, FF_p224);
    }
    FF_sub( 4, r, s, FF_p224);

    /* r -= s5 */
    s[0] = s[2];
    s[1] = s[3];
    s[2] = s[3] = ZERO_UNIT;

    /* high words of s5 are zero and therefore it is reduced */
    FF_sub( 4, r, s, FF_p224);

#else
    pf_unit s[7];

    MOC_UNUSED(pField);
    for (i = 0; i < 7; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(7, r, FF_p224) >= 0)
    {
        BI_sub(7, r, FF_p224);
    }

    /* r += s2 */
    s[2] = s[1] = s[0] = 0;
    for ( i =3; i < 7; ++i)
    {
        s[i] = c[i+4];
    }

    /* bottom 3 words of s2 are zero so it is at most p-1
       and therefore it is reduced */
    FF_add( 7, r, s, FF_p224);

    /* r += s3 */
    s[6] = s[2] = s[1] = s[0] = 0;
    s[5] = c[13]; s[4] = c[12]; s[3] = c[11];

    /* bottom 3 words of s3 are zero and therefore it is reduced */
    FF_add( 7, r, s, FF_p224);

    /* r -= s4 */
    for (i = 0; i < 7; ++i)
    {
        s[i] = c[i+7];
    }

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(7, s, FF_p224) >= 0)
    {
        BI_sub(7, s, FF_p224);
    }
    FF_sub(7, r, s, FF_p224);

    /* r -= s5 */
    s[2] = c[13]; s[1] = c[12]; s[0] = c[11];
    for (i = 3; i < 7; ++i)
    {
        s[i] = 0;
    }

    /* high words of s5 are zero and therefore it is reduced */
    FF_sub(7, r, s, FF_p224);
#endif
}

#endif

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P256__

MOC_EXTERN void
fastReductionP256( const pf_unit* c,
                    pf_unit* r,
                    PrimeFieldPtr pField)
{
    ubyte4 i;

#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit s[4];
    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 4; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(4, r, FF_p256) >= 0)
    {
        BI_sub(4, r, FF_p256);
    }

    /* r += 2 * s2 */
    s[0] = ZERO_UNIT;
    s[1] = c[5] & HI_MASK;
    s[2] = c[6];
    s[3] = c[7];

    /* make sure s2 is reduced via the modulus */
    if (BI_cmp(4, s, FF_p256) >= 0)
    {
        BI_sub(4, s, FF_p256);
    }
    FF_add(4, r, s, FF_p256);
    FF_add(4, r, s, FF_p256);

    /* r += 2 * s3 */
    s[1] = MAKE_UNIT( LO_HUNIT(c[6]), 0);
    s[2] = MAKE_UNIT( LO_HUNIT(c[7]), HI_HUNIT(c[6]));
    s[3] = HI_HUNIT(c[7]);

    /* high bits of s3 are 0, it is already reduced */
    FF_add(4, r, s, FF_p256);
    FF_add(4, r, s, FF_p256);

    /* r += s4 */
    s[0] = c[4];
    s[1] = LO_HUNIT(c[5]);
    s[2] = ZERO_UNIT;
    s[3] = c[7];

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(4, s, FF_p256) >= 0)
    {
        BI_sub(4, s, FF_p256);
    }
    FF_add(4, r, s, FF_p256);

    /* r += s5 */
    s[0] = MAKE_UNIT( LO_HUNIT(c[5]), HI_HUNIT(c[4]));
    s[1] = MAKE_UNIT( HI_HUNIT(c[6]), HI_HUNIT(c[5]));
    s[2] = c[7];
    s[3] = MAKE_UNIT( LO_HUNIT(c[4]), HI_HUNIT(c[6]));

    /* make sure s5 is reduced via the modulus */
    if (BI_cmp(4, s, FF_p256) >= 0)
    {
        BI_sub(4, s, FF_p256);
    }
    FF_add(4, r, s, FF_p256);

    /* r -= s6 */
    s[0] = MAKE_UNIT( LO_HUNIT(c[6]), HI_HUNIT(c[5]));
    s[1] = HI_HUNIT(c[6]);
    s[2] = ZERO_UNIT;
    s[3] = MAKE_UNIT( LO_HUNIT(c[5]), LO_HUNIT(c[4]));

    /* make sure s6 is reduced via the modulus */
    if (BI_cmp(4, s, FF_p256) >= 0)
    {
        BI_sub(4, s, FF_p256);
    }
    FF_sub( 4, r, s, FF_p256);

    /* r -= s7 */
    s[0] = c[6];
    s[1] = c[7];
    s[2] = ZERO_UNIT;
    s[3] = MAKE_UNIT( HI_HUNIT(c[5]), HI_HUNIT(c[4]));

    /* make sure s7 is reduced via the modulus */
    if (BI_cmp(4, s, FF_p256) >= 0)
    {
        BI_sub(4, s, FF_p256);
    }
    FF_sub( 4, r, s, FF_p256);

    /* r -= s8 */
    s[0] = MAKE_UNIT( LO_HUNIT(c[7]), HI_HUNIT(c[6]));
    s[1] = MAKE_UNIT( LO_HUNIT(c[4]), HI_HUNIT(c[7]));
    s[2] = MAKE_UNIT( LO_HUNIT(c[5]), HI_HUNIT(c[4]));
    s[3] = MAKE_UNIT( LO_HUNIT(c[6]), 0);

    /* second most significant word of s8 is 0, it is already reduced */
    FF_sub( 4, r, s, FF_p256);

    /* r -= s9 */
    s[0] = c[7];
    s[1] = c[4] & HI_MASK;
    s[2] = c[5];
    s[3] = c[6] & HI_MASK;

    /* second most significant word of s9 is 0, it is already reduced */
    FF_sub( 4, r, s, FF_p256);

#else
    pf_unit s[8];
    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 8; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(8, r, FF_p256) >= 0)
    {
        BI_sub(8, r, FF_p256);
    }

    /* r += 2 * s2 */
    s[0] = s[1] = s[2] = 0;
    for ( i = 3; i < 8; ++i)
    {
        s[i] = c[i+8];
    }

    /* make sure s2 is reduced via the modulus */
    if (BI_cmp(8, s, FF_p256) >= 0)
    {
        BI_sub(8, s, FF_p256);
    }
    FF_add(8, r, s, FF_p256);
    FF_add(8, r, s, FF_p256);

    /* r += 2 * s3 */
    s[7] = 0; /* s[0] = s[1] = s[2] = 0; already done before */
    for ( i = 3; i < 7; ++i)
    {
        s[i] = c[i + 9];
    }

    /* high bits of s3 are 0, it is already reduced */
    FF_add(8, r, s, FF_p256);
    FF_add(8, r, s, FF_p256);

    /* r += s4 */
    s[7] = c[15]; s[6] = c[14];
    s[5] = s[4] = s[3] = 0;
    s[2] = c[10]; s[1] = c[9]; s[0] = c[8];

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(8, s, FF_p256) >= 0)
    {
        BI_sub(8, s, FF_p256);
    }
    FF_add(8, r, s, FF_p256);

    /* r -= s6 */
    /* We do s6 before s5 in order to reuse s[5],s[4],s[3] = 0 */
    s[7] = c[10]; s[6] = c[8];
    /* s[5] = s[4] = s[3] = 0; already done before */
    s[2] = c[13]; s[1] = c[12]; s[0] = c[11];

    /* make sure s6 is reduced via the modulus */
    if (BI_cmp(8, s, FF_p256) >= 0)
    {
        BI_sub(8, s, FF_p256);
    }
    FF_sub( 8, r, s, FF_p256);

    /* r += s5 */
    s[0] = c[9]; s[1] = c[10]; s[2] = c[11];
    s[3] = c[13]; s[4] = c[14]; s[5] = c[15];
    s[6] = c[13];
    s[7] = c[8];

    /* make sure s5 is reduced via the modulus */
    if (BI_cmp(8, s, FF_p256) >= 0)
    {
        BI_sub(8, s, FF_p256);
    }
    FF_add(8, r, s, FF_p256);

    /* r -= s7 */
    s[7] = c[11]; s[6] = c[9];
    s[5] = s[4] = 0;
    for (i = 0; i < 4; ++i)
    {
        s[i] = c[i + 12];
    }

    /* make sure s7 is reduced via the modulus */
    if (BI_cmp(8, s, FF_p256) >= 0)
    {
        BI_sub(8, s, FF_p256);
    }
    FF_sub( 8, r, s, FF_p256);

    /* r -= s8 */
    s[7] = c[12]; s[6] = 0;
    s[5] = c[10]; s[4] = c[9]; s[3] = c[8];
    s[2] = c[15]; s[1] = c[14]; s[0] = c[13];

    /* second most significant word of s8 is 0, it is already reduced */
    FF_sub( 8, r, s, FF_p256);

    /* r -= s9 */
    s[7] = c[13];
    s[6] = s[2] = 0;
    s[5] = c[11]; s[4] = c[10]; s[3] = c[9];
    s[1] = c[15]; s[0] = c[14];

    /* second most significant word of s9 is 0, it is already reduced */
    FF_sub( 8, r, s, FF_p256);
#endif
}
#endif

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P384__

MOC_EXTERN void
fastReductionP384( const pf_unit* c,
                    pf_unit* r,
                    PrimeFieldPtr pField)
{
    ubyte4 i;

#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit s[6];
    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 6; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(6, r, FF_p384) >= 0)
    {
        BI_sub(6, r, FF_p384);
    }

    /* r += 2 * s2 */
    s[0] = s[1] = s[4] = s[5] = ZERO_UNIT;
    s[2] = MAKE_UNIT( LO_HUNIT(c[11]), HI_HUNIT(c[10]));
    s[3] = HI_HUNIT( c[11]);

    /* most significant words of s2 are 0, it is already reduced */
    FF_add(6, r, s, FF_p384);
    FF_add(6, r, s, FF_p384);

    /* r += s3 */
    for (i = 0; i < 6; ++i)
    {
        s[i] = c[i+6];
    }

    /* make sure s3 is reduced via the modulus */
    if (BI_cmp(6, s, FF_p384) >= 0)
    {
        BI_sub(6, s, FF_p384);
    }
    FF_add(6, r, s, FF_p384);

    /* r += s4 */
    s[0] = MAKE_UNIT( LO_HUNIT(c[11]), HI_HUNIT(c[10]));
    s[1] = MAKE_UNIT( LO_HUNIT(c[6]), HI_HUNIT(c[11]));
    for (i = 2; i < 6; ++i)
    {
        s[i] = MAKE_UNIT( LO_HUNIT(c[i+5]), HI_HUNIT(c[i+4]));
    }

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(6, s, FF_p384) >= 0)
    {
        BI_sub(6, s, FF_p384);
    }
    FF_add(6, r, s, FF_p384);

    /* r += s5 */
    s[0] = c[11] & HI_MASK;
    s[1] = MAKE_UNIT( LO_HUNIT(c[10]), 0);
    for (i = 2; i < 6; ++i)
    {
        s[i] = c[i+4];
    }

    /* make sure s5 is reduced via the modulus */
    if (BI_cmp(6, s, FF_p384) >= 0)
    {
        BI_sub(6, s, FF_p384);
    }
    FF_add(6, r, s, FF_p384);

    /* r += s6 */
    s[0] = s[1] = s[4] = s[5] = 0;
    s[2] = c[10];
    s[3] = c[11];

    /* most significant words of s6 are 0, it is already reduced */
    FF_add(6, r, s, FF_p384);

    /* r += s7 */
    s[0] = LO_HUNIT(c[10]);
    s[1] = c[10] & HI_MASK;
    s[2] = c[11];
    s[3] = s[4] = s[5] = ZERO_UNIT;

    /* most significant words of s7 are 0, it is already reduced */
    FF_add(6, r, s, FF_p384);

    /* r -= s8 */
    s[0] = MAKE_UNIT(LO_HUNIT(c[6]), HI_HUNIT(c[11]));
    for (i = 1; i < 6; ++i)
    {
        s[i] = MAKE_UNIT( LO_HUNIT(c[i+6]), HI_HUNIT(c[i+5]));
    }

    /* make sure s8 is reduced via the modulus */
    if (BI_cmp(6, s, FF_p384) >= 0)
    {
        BI_sub(6, s, FF_p384);
    }
    FF_sub(6, r, s, FF_p384);

    /* r -= s9 */
    s[0] = MAKE_UNIT(LO_HUNIT(c[10]), 0);
    s[1] = MAKE_UNIT( LO_HUNIT(c[11]), HI_HUNIT(c[10]));
    s[2] = HI_HUNIT(c[11]);
    s[3] = s[4] = s[5] = ZERO_UNIT;

    /* most significant words of s9 are 0, it is already reduced */
    FF_sub(6, r, s, FF_p384);

    /* r -= s10 */
    s[0] = ZERO_UNIT;
    s[1] = c[11] & HI_MASK;
    s[2] = HI_HUNIT(c[11]);
    s[3] = s[4] = s[5] = ZERO_UNIT;

    /* most significant words of s10 are 0, it is already reduced */
    FF_sub(6, r, s, FF_p384);

#else
    pf_unit s[12];
    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 12; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(12, r, FF_p384) >= 0)
    {
        BI_sub(12, r, FF_p384);
    }

    /* r += 2 * s2 */
    s[11] = s[10] = s[9] = s[8] = s[7] = s[0] = s[1] = s[2] = s[3] = 0;
    s[4] = c[21]; s[5] = c[22]; s[6] = c[23];

    /* most significant words of s2 are 0, it is already reduced */
    FF_add(12, r, s, FF_p384);
    FF_add(12, r, s, FF_p384);

    /* r += s3 */
    for (i = 0; i < 12; ++i)
    {
        s[i] = c[i+12];
    }

    /* make sure s3 is reduced via the modulus */
    if (BI_cmp(12, s, FF_p384) >= 0)
    {
        BI_sub(12, s, FF_p384);
    }
    FF_add(12, r, s, FF_p384);

    /* r += s4 */
    s[0] = c[21]; s[1] = c[22]; s[2] = c[23];
    for (i = 3; i < 12; ++i)
    {
        s[i] = c[i+9];
    }

    /* make sure s4 is reduced via the modulus */
    if (BI_cmp(12, s, FF_p384) >= 0)
    {
        BI_sub(12, s, FF_p384);
    }
    FF_add(12, r, s, FF_p384);

    /* r += s5 */
    s[0] = s[2] = 0;
    s[1] = c[23]; s[3] = c[20];
    for (i = 4; i < 12; ++i)
    {
        s[i] = c[i+8];
    }

    /* make sure s5 is reduced via the modulus */
    if (BI_cmp(12, s, FF_p384) >= 0)
    {
        BI_sub(12, s, FF_p384);
    }
    FF_add(12, r, s, FF_p384);

    /* r += s6 */
    s[0] = s[1] = s[2] = s[3] = s[8] = s[9] = s[10] = s[11] = 0;
    for (i = 4; i < 8; ++i)
    {
        s[i] = c[i+16];
    }

    /* most significant words of s6 are 0, it is already reduced */
    FF_add(12, r, s, FF_p384);

    /* r += s7 */
    s[0] = c[20];
    s[3] = c[21]; s[4] = c[22]; s[5] = c[23];
    s[6] = s[7] = 0; /* rest is like s6 */

    /* most significant words of s7 are 0, it is already reduced */
    FF_add(12, r, s, FF_p384);

    /* r -= s8 */
    s[0] = c[23];
    for (i = 1; i < 12; ++i)
    {
        s[i] = c[i+11];
    }

    /* make sure s8 is reduced via the modulus */
    if (BI_cmp(12, s, FF_p384) >= 0)
    {
        BI_sub(12, s, FF_p384);
    }
    FF_sub(12, r, s, FF_p384);

    /* r -= s9 */
    s[0] = 0;
    for (i = 1; i < 5; ++i)
    {
        s[i] = c[i+19];
    }
    for (i = 5; i < 12; ++i)
    {
        s[i] = 0;
    }

    /* most significant words of s9 are 0, it is already reduced */
    FF_sub(12, r, s, FF_p384);

    /* r -= s10 */
    s[1] = s[2] = 0;
    s[3] = s[4] = c[23]; /* rest is like s9 */

    /* most significant words of s10 are 0, it is already reduced */
    FF_sub(12, r, s, FF_p384);
#endif
}
#endif

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)

MOC_EXTERN void
fastReductionP448( const pf_unit *c,
                  pf_unit *r,
                  PrimeFieldPtr pField)
{
    ubyte4 i;

#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit s[7] = {0};

    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 7; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(7, r, FF_p448) >= 0)
    {
        BI_sub(7, r, FF_p448);
    }

    /* r += s2 (low words of s already 0) */
    s[3] = MAKE_UNIT( LO_HUNIT(c[7]), 0x00);
    for (i = 4; i < 7; ++i)
    {
        s[i] = MAKE_UNIT( LO_HUNIT(c[i+4]), HI_HUNIT(c[i+3]));
    }

    /* make sure s is reduced via the modulus */
    if (BI_cmp(7, s, FF_p448) >= 0)
    {
        BI_sub(7, s, FF_p448);
    }
    FF_add(7, r, s, FF_p448);

    /* r += s3 */
    for (i = 0; i < 7; ++i)
    {
        s[i] = c[i+7];
    }

    /* make sure s is reduced via the modulus */
    if (BI_cmp(7, s, FF_p448) >= 0)
    {
        BI_sub(7, s, FF_p448);
    }
    FF_add( 7, r, s, FF_p448);

    /* r += s4 */
    for (i = 0; i < 3; ++i)
    {
        s[i] = MAKE_UNIT( LO_HUNIT(c[i+11]), HI_HUNIT(c[i+10]));
    }
    s[3] = MAKE_UNIT( HI_HUNIT(c[10]), HI_HUNIT(c[13]));
    /* s[4..6] are already correct */

    /* make sure s is reduced via the modulus */
    if (BI_cmp(7, s, FF_p448) >= 0)
    {
        BI_sub(7, s, FF_p448);
    }
    FF_add( 7, r, s, FF_p448);

#else
    pf_unit s[14] = {0};

    MOC_UNUSED(pField);

    /* r = s1 */
    for (i = 0; i < 14; ++i)
    {
        r[i] = c[i];
    }

    /* make sure r is reduced via the modulus */
    if (BI_cmp(14, r, FF_p448) >= 0)
    {
        BI_sub(14, r, FF_p448);
    }

    /* r += s2 */
    for (i = 7; i < 14; ++i)
    {
        s[i] = c[i+7];
    }

    /* make sure s is reduced via the modulus */
    if (BI_cmp(14, s, FF_p448) >= 0)
    {
        BI_sub(14, s, FF_p448);
    }
    FF_add(14, r, s, FF_p448);

    /* r += s3 */
    for (i = 0; i < 14; ++i)
    {
        s[i] = c[i+14];
    }

    /* make sure s is reduced via the modulus */
    if (BI_cmp(14, s, FF_p448) >= 0)
    {
        BI_sub(14, s, FF_p448);
    }
    FF_add(14, r, s, FF_p448);

    /* r += s4 */
    for (i = 0; i < 7; ++i)
    {
        s[i] = c[i+21];
    }
    /* s[7..13] are already correct */

    /* make sure s is reduced via the modulus */
    if (BI_cmp(14, s, FF_p448) >= 0)
    {
        BI_sub(14, s, FF_p448);
    }
    FF_add(14, r, s, FF_p448);

#endif
}

#endif /* if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__) */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P521__

MOC_EXTERN void
fastReductionP521( const pf_unit* c,
                    pf_unit* r,
                    PrimeFieldPtr pField)
{
    ubyte4 i;
#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit s[9];
    MOC_UNUSED(pField);

    for (i = 0; i < 8; ++i)
    {
        r[i] = c[i];
    }

    /* 9 bits to r[8] */
    r[8] = c[8] & 0x01FF;

    /* make sure r is reduced via the modulus
       (yes it can come out to be exactly the modulus!
        try c = a * b where a = 2^520-1 and b = 2^520+1,
        then r is the last 521 bits of 2^1040 - 1
        which has all such bits set, and hence is = p)
     */
    if (BI_cmp(9, r, FF_p521) >= 0)
    {
        BI_sub(9, r, FF_p521);
    }

    /* loop: add upper 55 bits and lower 9 bits to s */
    for (i = 0; i < 9; ++i)
    {
        s[i] = (c[8+i] >> 9);
        s[i] |= ((c[9+i] & 0x01FF) << 55);
    }

    /* assuming reduction is only occuring after a multiply (right now true),
       s can't have more of its bits set than the highest 521 bits of
       (p-1)^2 = (2^521 - 2)^2, which has 519 bits set, hence s is reduced */

    FF_add( 9, r, s, FF_p521);

#else
    pf_unit s[17];
    MOC_UNUSED(pField);

    for ( i = 0; i < 16; ++i)
    {
        r[i] = c[i];
    }
    /* 9 bits to r[16] */
    r[16] = (c[16] & 0x01FF);

    /* make sure r is reduced via the modulus
       (yes it can come out to be exactly the modulus!
        try c = a * b where a = 2^520-1 and b = 2^520+1,
        then r is the last 521 bits of 2^1040 - 1
        which has all such bits set, and hence is = p)
     */
    if (BI_cmp(17, r, FF_p521) >= 0)
    {
        BI_sub(17, r, FF_p521);
    }

    /* loop: add upper 23 bits and lower 9 bits to s[0]... */
    for ( i = 0; i < 17; ++i)
    {
        s[i] = (c[16+i] >> 9);
        s[i] |= ((c[17+i] & 0x01FF) << 23);
    }

    /* assuming reduction is only occuring after a multiply (right now true),
       s can't have more of its bits set than the highest 521 bits of
       (p-1)^2 = (2^521 - 2)^2, which has 519 bits set, hence s is reduced */

    FF_add( 17, r, s, FF_p521);
#endif
}
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_barrettMultiply( PrimeFieldPtr pField, PFEPtr pProduct, ConstPFEPtr pA,
                            ConstPFEPtr pB, ConstPFEPtr pModulo, ConstPFEPtr pMu)
{
    MSTATUS status;
    pf_unit* mulBuffer = 0;
    sbyte4  k;

    if (!pField || !pProduct || !pA || !pB || !pModulo || !pMu)
        return ERR_NULL_POINTER;

    k = pField->n;

    /* allocate a buffer big enough for everything */
    mulBuffer = (pf_unit*) MALLOC( ((2 * k) + (2 * (k+1))) * sizeof(pf_unit));
    if ( !mulBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* multiply into buffer */
    BI_mul( k, mulBuffer, pA->units, pB->units, 2 * k);

    /* barrett reduction */
    status = BI_barrettReduction( k, mulBuffer, pProduct->units, mulBuffer + (2 * k), pMu->units, pModulo->units);

exit:

    if ( mulBuffer)
    {
        FREE( mulBuffer);
    }

    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_addAux( PrimeFieldPtr pField, PFEPtr pSumAndValue,
                ConstPFEPtr pAddend, ConstPFEPtr pModulus)
{
    if ( !pField || !pSumAndValue || !pAddend || !pModulus)
    {
        return ERR_NULL_POINTER;
    }

    FF_add( pField->n, pSumAndValue->units, pAddend->units,
           pModulus->units);

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_add( PrimeFieldPtr pField, PFEPtr pSumAndValue,
                ConstPFEPtr pAddend)
{
    if ( !pField || !pSumAndValue || !pAddend)
    {
        return ERR_NULL_POINTER;
    }

    FF_add( pField->n, pSumAndValue->units, pAddend->units,
            pField->units);

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_subtract( PrimeFieldPtr pField,PFEPtr pResultAndValue,
                        ConstPFEPtr pSubtract)
{
    if ( !pField || !pResultAndValue || !pSubtract)
    {
        return ERR_NULL_POINTER;
    }

    FF_sub( pField->n, pResultAndValue->units, pSubtract->units,
                pField->units);

    return OK;
}


/*---------------------------------------------------------------------------*/

/* Inplace computation of -pA */
MOC_EXTERN MSTATUS PRIMEFIELD_additiveInvert(PrimeFieldPtr pField, PFEPtr pA)
{
    MSTATUS status;

    PFEPtr pTemp = NULL;

    if (NULL == pField || NULL == pA)
        return ERR_NULL_POINTER;

    /* Initialize pTemp which also sets it to zero */
    status = PRIMEFIELD_newElement(pField, &pTemp);
    if (OK != status)
        return status;

    FF_sub(pField->n, pTemp->units, pA->units, pField->units);

    status = PRIMEFIELD_copyElement(pField, pA, pTemp);

    if (NULL != pTemp)
    {
        PRIMEFIELD_deleteElement(pField, &pTemp);
    }

    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_xor( PrimeFieldPtr pField, PFEPtr pResultAndValue,
                        ConstPFEPtr pXor)
{
    sbyte4 i;
    pf_unit *r;
    const pf_unit* op;

    if ( !pField || !pResultAndValue || !pXor)
    {
        return ERR_NULL_POINTER;
    }

    r = pResultAndValue->units;
    op = pXor->units;

    for ( i = 0; i < pField->n; ++i)
    {
       r[i] ^= op[i];
    }

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_multiply( PrimeFieldPtr pField, PFEPtr pProduct,
                        ConstPFEPtr pA, ConstPFEPtr pB)
{
    pf_unit* hilo = 0;

    if ( !pField || !pProduct || !pA || !pB)
    {
        return ERR_NULL_POINTER;
    }

    hilo = (pf_unit*) MALLOC( 2 * pField->n * sizeof(pf_unit));
    if ( !hilo)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    BI_mul( pField->n, hilo, pA->units, pB->units, 2 * pField->n);

    pField->reduceFun( hilo, pProduct->units, pField);

    FREE( hilo);

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_multiplyAux( PrimeFieldPtr pField, PFEPtr pProduct,
                        ConstPFEPtr pA, ConstPFEPtr pB, pf_unit* hilo)
{
    if ( !pField || !pProduct || !pA || !pB || !hilo)
    {
        return ERR_NULL_POINTER;
    }

    BI_mul( pField->n, hilo, pA->units, pB->units, 2 * pField->n);

    pField->reduceFun( hilo, pProduct->units, pField);

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_squareAux( PrimeFieldPtr pField, PFEPtr pProduct,
                      ConstPFEPtr pA, pf_unit* hilo)
{
    if ( !pField || !pProduct || !pA || !hilo)
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__
    BI_mul( pField->n, hilo, pA->units, pA->units, 2 * pField->n);
#else
    BI_sqr( pField->n, hilo, pA->units, 2 * pField->n);
#endif

    pField->reduceFun( hilo, pProduct->units, pField);

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PRIMEFIELD_exp( PrimeFieldPtr pField, PFEPtr pA,
               ConstPFEPtr pG, ConstPFEPtr pExp, pf_unit* hilo)
{
    sbyte4 shift, unit, stillOne = 1,
        numBitsPerUnit = 8 * sizeof(pf_unit);

    if ( !pField || !pA || !pG ||  !pExp || !hilo)
    {
        return ERR_NULL_POINTER;
    }

    PRIMEFIELD_setToUnsigned(pField, pA, 1);

    for (unit = pField->n-1; unit >= 0; --unit)
    {
        for ( shift = numBitsPerUnit-1; shift >=0; --shift)
        {
            if (!stillOne)
            {
#ifdef __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__
                BI_mul( pField->n, hilo, pA->units, pA->units, 2 * pField->n);
#else
                BI_sqr( pField->n, hilo, pA->units, 2 * pField->n);
#endif
                pField->reduceFun( hilo, pA->units, pField);
            }

            if ( ((pExp->units[unit]) >> shift) & 1)
            {
                stillOne = 0;
                BI_mul( pField->n, hilo, pA->units, pG->units, 2 * pField->n);
                pField->reduceFun( hilo, pA->units, pField);
            }
        }
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)

#ifdef __ENABLE_DIGICERT_ECC_P192__

/* Computes pA^((p+1)/4), ie pA^(2^190 - 2^62) */
static MSTATUS PRIMEFIELD_specialExp192(PFEPtr pResult, ConstPFEPtr pA, pf_unit *pHilo)
{
    MSTATUS status;
    int i,j;

    PFEPtr pTemp = NULL;

    /*
     Internal method, NULL checks already done

     NOTE: We purposely ignore return codes for PRIMEFIELD_square/multiplyAux and
     since NULL params are already checked and that's the only possible return code.

     We use pResult as a temp var for now too.
     */

    status = PRIMEFIELD_newElement(PF_p192, &pTemp);
    if (OK != status)
        goto exit;

    PRIMEFIELD_copyElement(PF_p192, pResult, pA);

    for (j = 0; j < 7; ++j)
    {
        /* We begin the j loop iteration with pResult = pA^( 2^(2^j) - 1 ), copy to pTemp */
        PRIMEFIELD_copyElement(PF_p192, pTemp, pResult);

        /* square it 2^j times to get pA^( (2^(2^j) - 1) * 2^(2^j) ) ie pA^( 2^(2^(j+1)) - 2^(2^j) ) */
        for (i = 0; i < (0x01<<j); ++i)
        {
            PRIMEFIELD_squareAux(PF_p192, pResult, pResult, pHilo); /* inplace op ok */
        }

        /*
         multiply by pTemp and get the 2^(2^j) parts of the exponents to cancel,
         yielding pA^( 2^(2^(j+1)) - 1 ) as desired.
         */
        PRIMEFIELD_multiplyAux(PF_p192, pResult, pTemp, pResult, pHilo); /* inplace op ok */
    }

    /* now we have pA^(2^128 - 1), just square now 62 times to get pA^(2^190 - 2^62) */
    for (i = 0; i < 62; ++i)
    {
        PRIMEFIELD_squareAux(PF_p192, pResult, pResult, pHilo);
    }

exit:

    /* On error pResult will be zeroed out by the calling method */

    if (NULL != pTemp)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p192, &pTemp);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC_P192__ */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P224__

#define P224_S 96

#ifdef __ENABLE_DIGICERT_64_BIT__
static const pf_unit gpInitialC_p224[4] =
{
    0xF3FB3632DC691B74ULL, 0x0B2D6FFBBEA3D8CEULL, 0x8598A7920C55B2D4ULL, 0x6A0FEC67ULL
};
#else
static const pf_unit gpInitialC_p224[7] =
{
    0xDC691B74, 0xF3FB3632, 0xBEA3D8CE, 0x0B2D6FFB, 0x0C55B2D4, 0x8598A792, 0x6A0FEC67
};
#endif

/*
 This method computes the initial values of T and R from pA in the
 Tonelli-Shanks algorithm. We have for the prime p = 2^224 - 2^96 + 1,
 p - 1 = 2^S Q where S = 96 and Q = 2^128 - 1.

 We compute T = pA^Q and R = pA^( (Q+1)/2 ). We also note that 11 has
 no square root mod p so we can precompute a 2^S-th primitive root of unity C
 by computing 11^Q. That is above.
 */
static MSTATUS PRIMEFIELD_initTonelliShanks_p224(PFEPtr pT, PFEPtr pR, ConstPFEPtr pA, pf_unit * pHilo)
{
    MSTATUS status;
    int i;
    PFEPtr pTemp1 = NULL;
    PFEPtr pTemp2 = NULL;

    /* Internal method, NULL checks already done */

    status = PRIMEFIELD_newElement(PF_p224, &pTemp1);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p224, &pTemp2);
    if (OK != status)
        goto exit;

    /*
     We also use pT and pR as temp vars for now.

     NOTE: We purposely ignore return codes for PRIMEFIELD_squareAux and
     PRIMEFIELD_multiplyAux since NULL params are already checked
     and that's the only possible return code.
     */

    /* pA to an exponent of 2 */
    PRIMEFIELD_squareAux(PF_p224, pTemp1, pA, pHilo);

    /* pA to an exponent of 3 */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp2, pTemp1, pA, pHilo);

    /* pA to an exponent of 4 */
    PRIMEFIELD_squareAux(PF_p224, pT, pTemp1, pHilo);

    /* pA to an exponent of 7, save pTemp1 for later! */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp1, pTemp2, pT, pHilo);

    /* pA to an exponent of 8 */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pT, pHilo);

    /* pA to an exponent of 15 */
    PRIMEFIELD_multiplyAux(PF_p224, pT, pTemp1, pTemp2, pHilo);

    /* pA to an exponent of 30 */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pT, pHilo);

    /* pA to an exponent of 60 */
    PRIMEFIELD_squareAux(PF_p224, pT, pTemp2, pHilo);

    /* pA to an exponent of 120 */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pT, pHilo);

    /* pA to an exponent of 127 = 2^7 - 1, save pT, done with pTemp1 */
    PRIMEFIELD_multiplyAux(PF_p224, pT, pTemp2, pTemp1, pHilo);

    /* pA to an exponent of 2^8 - 2^1  */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pT, pHilo);

    /* pA to an exponent of 2^14 - 2^7 */
    for (i = 0; i < 6; ++i)
    {
        PRIMEFIELD_squareAux(PF_p224, pTemp2, pTemp2, pHilo);  /* ok to do inplace operation */
    }

    /* pA to an exponent of 2^14 - 1 */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp1, pTemp2, pT, pHilo);

    /* pA to an exponent of 2^15 - 2 */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pTemp1, pHilo);

    /* pA to an exponent of 2^15 - 1, save pR */
    PRIMEFIELD_multiplyAux(PF_p224, pR, pTemp2, pA, pHilo);

    /* pA to an exponent of 2^16 - 2^1 */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pR, pHilo);

    /* pA to an exponent of 2^30 - 2^15 */
    for (i = 0; i < 14; ++i)
    {
        PRIMEFIELD_squareAux(PF_p224, pTemp2, pTemp2, pHilo);
    }

    /* pA to an exponent of 2^30 - 1, save pTemp1, done with pR */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp1, pTemp2, pR, pHilo);

    /* pA to an exponent of 2^31 - 2^1 */
    PRIMEFIELD_squareAux(PF_p224, pTemp2, pTemp1, pHilo);

    /* pA to an exponent of 2^32 - 2^2 */
    PRIMEFIELD_squareAux(PF_p224, pR, pTemp2, pHilo);

    /* pA to an exponent of 2^60 - 2^30 */
    for (i = 0; i < 28; ++i)
    {
        PRIMEFIELD_squareAux(PF_p224, pR, pR, pHilo);
    }

    /* pA to an exponent of 2^60 - 1, save pTemp2, done with pTemp1 */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp2, pR, pTemp1, pHilo);

    /* pA to an exponent of 2^61 - 2^1 */
    PRIMEFIELD_squareAux(PF_p224, pTemp1, pTemp2, pHilo);

    /* pA to an exponent of 2^62 - 2^2 */
    PRIMEFIELD_squareAux(PF_p224, pR, pTemp1, pHilo);

    /* pA to an exponent of 2^120 - 2^60 */
    for (i = 0; i < 58; ++i)
    {
        PRIMEFIELD_squareAux(PF_p224, pR, pR, pHilo);
    }

    /* pA to an exponent of 2^120 - 1, done with pTemp2 */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp1, pR, pTemp2, pHilo);

    /* pA to an exponent of 2^121 - 2^1 */
    PRIMEFIELD_squareAux(PF_p224, pR, pTemp1, pHilo);

    /* pA to an exponent of 2^127 - 2^7 */
    for (i = 0; i < 6; ++i)
    {
        PRIMEFIELD_squareAux(PF_p224, pR, pR, pHilo);
    }

    /* pA to an exponent of 2^127 - 1 */
    PRIMEFIELD_multiplyAux(PF_p224, pTemp1, pR, pT, pHilo);

    /* pA to an exponent of 2^127, ie (Q+1)/2, this is R */
    PRIMEFIELD_multiplyAux(PF_p224, pR, pTemp1, pA, pHilo);

    /* pA to an exponent of 2^127 + 2^127 - 1 = 2^128 - 1, ie this is T */
    PRIMEFIELD_multiplyAux(PF_p224, pT, pTemp1, pR, pHilo);
exit:

    if (NULL != pTemp1)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p224, &pTemp1);
    }

    if (NULL != pTemp2)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p224, &pTemp2);
    }

    return status;
}


/*
 TonelliShanks algorithm. This method could be easily modified to work with any
 field and not just PF_p224. Just the initialization of the variables M and C,
 and also of T and R (done by the above method) would need to be different (and
 obviously we'd pass in the field instead of using the PF_p224 constant).
 */
static MSTATUS PRIMEFIELD_TonelliShanks(PFEPtr pResult, ConstPFEPtr pA, pf_unit * pHilo)
{
    MSTATUS status;
    ubyte4 i,j;
    ubyte4 M = P224_S; /* For p224 only */
    ubyte4 exp = 0;

    PFEPtr pC = NULL;
    PFEPtr pT = NULL;
    PFEPtr pB = NULL;
    PFEPtr pTemp = NULL;

    /* internal method, NULL checks already done. */

    status = PRIMEFIELD_newElement(PF_p224, &pC);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p224, &pT);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p224, &pB);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p224, &pTemp);
    if (OK != status)
        goto exit;
    /*
     We call init before checking for pA = 0 or 1, since such input is
     extremeley rare, and the init call will result in pResult being set
     properly to 0 or 1 respectively anyway. We use pResult as R.
     */
    status = PRIMEFIELD_initTonelliShanks_p224(pT, pResult, pA, pHilo); /* For p224 only */
    if (OK != status)
        goto exit;

    /* Now do check for zero */

    if (!PRIMEFIELD_cmpToUnsigned(PF_p224, pA, 0))
    {
        goto exit; /* we're done, pResult is also correctly zero */
    }

    /* ok to ignore return codes of some PRIMEFIELD_... methods as NULL cases are already checked */

    PRIMEFIELD_copyElement(PF_p224, pC, (PFEPtr) gpInitialC_p224); /* For p224 only */
    /*
     If pT = 1 then we are done, pResult is correct.
     Otherwise we need to find the minimum i such that pT^(2^i) is 1
     Note that minimum i is at most S with i == S if and only if pA has
     no square root mod p. This follows from Euler's criterion since

     pT^(2^(S-1)) = ( pA^Q )^(2^(S-1)) = pA^( Q 2^(S-1) ) = pA^( (p-1)/2 ) = -1 or 1
     */
    while (PRIMEFIELD_cmpToUnsigned(PF_p224, pT, 1))
    {
        i = 0;

        /* use pB as a temp var for now */
        PRIMEFIELD_squareAux(PF_p224, pB, pT, pHilo);
        i++;
        if (PRIMEFIELD_cmpToUnsigned(PF_p224, pB, 1))
        {
            while (TRUE)  /* can't go more than M/2 iterations */
            {
                PRIMEFIELD_squareAux(PF_p224, pTemp, pB, pHilo);
                i++;
                if (!PRIMEFIELD_cmpToUnsigned(PF_p224, pTemp, 1))
                {
                    break;
                }

                PRIMEFIELD_squareAux(PF_p224, pB, pTemp, pHilo);
                i++;
                if (!PRIMEFIELD_cmpToUnsigned(PF_p224, pB, 1))
                {
                    break;
                }
            }
        }
        if (P224_S == i)
        {
            /* no sqaure root exists */
            status = ERR_NOT_FOUND;
            goto exit;
        }

        /* Set pB to pC^( 2^(M - i - 1) ) */
        exp = M - i - 1;
        if ( exp > 0 )
        {
            PRIMEFIELD_squareAux(PF_p224, pB, pC, pHilo);

            /* Do as many more pairs of squares as we can */
            for (j = 0; j < (exp - 1)/2 ; ++j)
            {
                PRIMEFIELD_squareAux(PF_p224, pTemp, pB, pHilo);
                PRIMEFIELD_squareAux(PF_p224, pB, pTemp, pHilo);
            }

            /* if exponent is even we need one more square and a copy */
            if ( 0 == (exp & 0x01) )
            {
                PRIMEFIELD_squareAux(PF_p224, pTemp, pB, pHilo);
                PRIMEFIELD_copyElement(PF_p224, pB, pTemp);
            }
        }
        else
        {
            PRIMEFIELD_copyElement(PF_p224, pB, pC);
        }

        /* set M to i */
        M = i;

        /* set pC to pB^2 */
        PRIMEFIELD_squareAux(PF_p224, pC, pB, pHilo);

        /* set pT to pT pB^2 */
        PRIMEFIELD_multiplyAux(PF_p224, pTemp, pT, pC, pHilo);
        PRIMEFIELD_copyElement(PF_p224, pT, pTemp);

        /* set pResult to pResult pB */
        PRIMEFIELD_multiplyAux(PF_p224, pTemp, pResult, pB, pHilo);
        PRIMEFIELD_copyElement(PF_p224, pResult, pTemp);
    }

exit:

    /* On error pResult will be zeroed out by the calling method */

    if (NULL != pC)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p224, &pC);
    }

    if (NULL != pT)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p224, &pT);
    }

    if (NULL != pB)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p224, &pB);
    }
    if (NULL != pTemp)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p224, &pTemp);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_ECC_P224__ */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P256__

/* Computes pA^((p+1)/4), ie pA^(2^254 - 2^222 + 2^190 + 2^94) */
static MSTATUS PRIMEFIELD_specialExp256(PFEPtr pResult, ConstPFEPtr pA, pf_unit *pHilo)
{
    MSTATUS status;
    int i,j;

    PFEPtr pTemp = NULL;
    /*
     Internal method, NULL checks already done

     NOTE: We purposely ignore return codes for PRIMEFIELD_square/multiplyAux and
     since NULL params are already checked and that's the only possible return code.

     We use pResult as a temp var for now too.
     */

    status = PRIMEFIELD_newElement(PF_p256, &pTemp);
    if (OK != status)
        goto exit;

    PRIMEFIELD_copyElement(PF_p256, pResult, pA);

    for (j = 0; j < 5; ++j)
    {
        /* We begin the j loop iteration with pResult = pA^( 2^(2^j) - 1 ), copy to pTemp */
        PRIMEFIELD_copyElement(PF_p256, pTemp, pResult);

        /* square it 2^j times to get pA^( (2^(2^j) - 1) * 2^(2^j) ) ie pA^( 2^(2^(j+1)) - 2^(2^j) ) */
        for (i = 0; i < (0x01<<j); ++i)
        {
            PRIMEFIELD_squareAux(PF_p256, pResult, pResult, pHilo); /* inplace op ok */
        }

        /*
         multiply by pTemp and get the 2^(2^j) parts of the exponents to cancel,
         yielding pA^( 2^(2^(j+1)) - 1 ) as desired.
         */
        PRIMEFIELD_multiplyAux(PF_p256, pResult, pTemp, pResult, pHilo); /* inplace op ok */
    }

    /* now we have pA^(2^32 - 1), square now 32 times to get pA^(2^64 - 2^32) */
    for (i = 0; i < 32; ++i)
    {
        PRIMEFIELD_squareAux(PF_p256, pResult, pResult, pHilo);
    }

    /* now pA to an exponent of 2^64 - 2^32 + 1 */
    PRIMEFIELD_multiplyAux(PF_p256, pResult, pResult, pA, pHilo);

    /* square 96 times to get pA to an exponent of 2^160 - 2^128 + 2^96 */
    for (i = 0; i < 96; ++i)
    {
        PRIMEFIELD_squareAux(PF_p256, pResult, pResult, pHilo);
    }

    /* now pA to an exponent of 2^160 - 2^128 + 2^96 + 1 */
    PRIMEFIELD_multiplyAux(PF_p256, pResult, pResult, pA, pHilo);

    /* square 94 times to get pA to an exponent of 2^254 - 2^222 + 2^190 + 2^94 */
    for (i = 0; i < 94; ++i)
    {
        PRIMEFIELD_squareAux(PF_p256, pResult, pResult, pHilo);
    }
exit:

    /* On error pResult will be zeroed out by the calling method */

    if (NULL != pTemp)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p256, &pTemp);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_ECC_P256__ */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P384__

/* Computes pA^((p+1)/4), ie pA^(2^382 - 2^126 - 2^94 + 2^30) */
static MSTATUS PRIMEFIELD_specialExp384(PFEPtr pResult, ConstPFEPtr pA, pf_unit *pHilo)
{
    MSTATUS status;
    int i;

    PFEPtr pTemp1 = NULL;
    PFEPtr pTemp2 = NULL;
    PFEPtr pTemp3 = NULL;
    PFEPtr pTemp4 = NULL;

    /*
     Internal method, NULL checks already done

     NOTE: We purposely ignore return codes for PRIMEFIELD_square/multiplyAux and
     since NULL params are already checked and that's the only possible return code.

     We use pResult as a temp var for now too.
     */

    status = PRIMEFIELD_newElement(PF_p384, &pTemp1);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p384, &pTemp2);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p384, &pTemp3);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p384, &pTemp4);
    if (OK != status)
        goto exit;

    /* pA^2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pA, pHilo);

    /* pA^3, save pTemp1 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp1, pResult, pA, pHilo);

    /* pA^4, inplace ops ok */
    PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);

    /* pA^7, ie an exponent of 2^3 - 1, save pTemp2 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp2, pResult, pTemp1, pHilo);

    /* pA to an exponent of 2^4 - 2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp2, pHilo);

    /* pA to an exponent of 2^6 - 2^3 */
    for (i = 0; i < 2; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^6 - 1, save pTemp3 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp3, pResult, pTemp2, pHilo);

    /* pA to an exponent of 2^7 - 2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp3, pHilo);

    /* pA to an exponent of 2^12 - 2^6 */
    for (i = 0; i < 5; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^12 - 1 */
    PRIMEFIELD_multiplyAux(PF_p384, pResult, pResult, pTemp3, pHilo);

    /* pA to an exponent of 2^15 - 2^3 */
    for (i = 0; i < 3; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^15 - 1, done with former pTemp2, save new pTemp2 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp2, pResult, pTemp2, pHilo);

    /* pA to an exponent of 2^16 - 2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp2, pHilo);

    /* pA to an exponent of 2^30 - 2^15 */
    for (i = 0; i < 14; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^30 - 1, done with former pTemp3, save new pTemp3 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp3, pResult, pTemp2, pHilo);

    /* pA to an exponent of 2^31 - 2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp3, pHilo);
    /* pA to an exponent of 2^32 - 4 */
    PRIMEFIELD_squareAux(PF_p384, pTemp4, pResult, pHilo);

    /* pA to an exponent of 2^32 - 1, done with pTemp1, save new pTemp1 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp1, pTemp4, pTemp1, pHilo);

    /* pA to an exponent of 2^33 - 2^3 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp4, pHilo);

    /* pA to an exponent of 2^60 - 2^30 */
    for (i = 0; i < 27; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^60 - 1, done with former pTemp3, save new pTemp3 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp3, pResult, pTemp3, pHilo);

    /* pA to an exponent of 2^61 - 2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp3, pHilo);

    /* pA to an exponent of 2^120 - 2^60 */
    for (i = 0; i < 59; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^120 - 1, done with former pTemp3, save new pTemp3 */
    PRIMEFIELD_multiplyAux(PF_p384, pTemp3, pResult, pTemp3, pHilo);
    /* pA to an exponent of 2^121 - 2 */
    PRIMEFIELD_squareAux(PF_p384, pResult, pTemp3, pHilo);

    /* pA to an exponent of 2^240 - 2^120 */
    for (i = 0; i < 119; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^240 - 1 */
    PRIMEFIELD_multiplyAux(PF_p384, pResult, pResult, pTemp3, pHilo);

    /* pA to an exponent of 2^255 - 2^15 */
    for (i = 0; i < 15; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^255 - 1 */
    PRIMEFIELD_multiplyAux(PF_p384, pResult, pResult, pTemp2, pHilo);

    /* pA to an exponent of 2^288 - 2^33 */
    for (i = 0; i < 33; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^288 - 2^33 + 2^32 - 1 = 2^288 - 2^32 - 1 */
    PRIMEFIELD_multiplyAux(PF_p384, pResult, pResult, pTemp1, pHilo);

    /* pA to an exponent of 2^352 - 2^96 - 2^64 */
    for (i = 0; i < 64; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

    /* pA to an exponent of 2^352 - 2^96 - 2^64 + 1 */
    PRIMEFIELD_multiplyAux(PF_p384, pResult, pResult, pA, pHilo);

    /* pA to an exponent of 2^382 - 2^126 - 2^94 + 2^30 */
    for (i = 0; i < 30; ++i)
    {
        PRIMEFIELD_squareAux(PF_p384, pResult, pResult, pHilo);
    }

exit:

    /* On error pResult will be zeroed out by the calling method */

    if (NULL != pTemp1)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p384, &pTemp1);
    }
    if (NULL != pTemp2)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p384, &pTemp2);
    }
    if (NULL != pTemp3)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p384, &pTemp3);
    }
    if (NULL != pTemp4)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(PF_p384, &pTemp4);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_ECC_P384__ */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECC_P521__

/* Computes pA^((p+1)/4), ie pA^(2^519) */
static void PRIMEFIELD_specialExp521(PFEPtr pResult, ConstPFEPtr pA, pf_unit *pHilo)
{
    int i;

    /*
     Internal method, NULL checks already done

     NOTE: We purposely ignore return codes for PRIMEFIELD_squareAux and
     since NULL params are already checked and that's the only possible return code.
     */
    PRIMEFIELD_squareAux(PF_p521, pResult, pA, pHilo);

    for (i = 0; i < 518; ++i)
    {
        /* ok to do inplace operation */
        PRIMEFIELD_squareAux(PF_p521, pResult, pResult, pHilo);
    }
}
#endif /* __DISABLE_DIGICERT_ECC_P521__ */

/*---------------------------------------------------------------------------*/

MSTATUS PRIMEFIELD_squareRoot(PrimeFieldPtr pField, PFEPtr pResult, ConstPFEPtr pA)
{
    MSTATUS status;
    pf_unit *pHilo = NULL;
    PFEPtr pTemp = NULL;
    if (NULL == pField || NULL == pResult || NULL == pA)
        return ERR_NULL_POINTER;

    status = DIGI_MALLOC((void **) &pHilo, 2 * pField->n * sizeof(pf_unit));
    if (OK != status)
        goto exit;
#ifndef __DISABLE_DIGICERT_ECC_P224__
    if(PF_p224 == pField)
    {
        status = PRIMEFIELD_TonelliShanks(pResult, pA, pHilo);
        /* Done, no need to square and check. */
        goto exit;
    }
    else
    {
#endif
        status = PRIMEFIELD_newElement(pField, &pTemp);
        if (OK != status)
            goto exit;

#ifndef __DISABLE_DIGICERT_ECC_P224__
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC_P192__
    if (PF_p192 == pField)
    {
        status = PRIMEFIELD_specialExp192(pResult, pA, pHilo);
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
    if (PF_p256 == pField)
    {
        status = PRIMEFIELD_specialExp256(pResult, pA, pHilo);
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
    if (PF_p384 == pField)
    {
        status = PRIMEFIELD_specialExp384(pResult, pA, pHilo);
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
    if (PF_p521 == pField)
    {
        /* void return value anyway */
        PRIMEFIELD_specialExp521(pResult, pA, pHilo);
    }
#endif
    if (OK != status)
        goto exit;

#ifndef __DISABLE_DIGICERT_ECC_P224__
    if (PF_p224 != pField)
    {
#endif
        /* check if it is indeed a square root, no need to check return code */
        PRIMEFIELD_squareAux(pField, pTemp, pResult, pHilo);

        if ( !PRIMEFIELD_match(pField, pTemp, pA) )
        {
            status = ERR_NOT_FOUND;
        }
#ifndef __DISABLE_DIGICERT_ECC_P224__
    }
#endif
exit:

    if (OK != status)
    {   /* zero out pResult, don't change status */
        PRIMEFIELD_setToUnsigned(pField, pResult, 0);
    }

    if (NULL != pHilo)
    {   /* don't change status */
        DIGI_MEMSET((ubyte *) pHilo, 0x00, 2 * pField->n * sizeof(pf_unit));
        DIGI_FREE((void **) &pHilo);
    }

    if (NULL != pTemp)
    {   /* don't change status */
        PRIMEFIELD_deleteElement(pField, &pTemp);
    }

    return status;
}

#endif /* #if defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__) */

#ifdef __MAX_UNITS

/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_inverseAux( sbyte4 k, PFEPtr pInverse, ConstPFEPtr pA,
                      ConstPFEPtr pModulus)
{
    if ( !pA || !pInverse || !pModulus || k <= 0)
    {
        return ERR_NULL_POINTER;
    }

    return FF_divide(k, pInverse->units, g_pOneUnits, pA->units,
                        pModulus->units);
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_inverse( PrimeFieldPtr pField, PFEPtr pInverse, ConstPFEPtr pA)
{
    if ( !pField || !pA || !pInverse )
    {
        return ERR_NULL_POINTER;
    }

    return FF_divide(pField->n, pInverse->units, g_pOneUnits, pA->units,
                        pField->units);
}

#endif  /* __MAX_UNITS__ */

/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_divide( PrimeFieldPtr pField, PFEPtr pResult,
                  ConstPFEPtr pA, ConstPFEPtr pDivisor)
{
    if ( !pField || !pResult || !pA || !pDivisor )
    {
        return ERR_NULL_POINTER;
    }

    return FF_divide(pField->n, pResult->units, pA->units, pDivisor->units,
                        pField->units);
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_shiftR( PrimeFieldPtr pField, PFEPtr pA)
{
    if (!pField || !pA)
    {
        return ERR_NULL_POINTER;
    }

    BI_shiftREx( pField->n, pA->units, 1);
    return OK;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_getBit( PrimeFieldPtr pField, ConstPFEPtr pA, ubyte4 bitNum,
                  ubyte* bit)
{
    if (!pField || !pA || !bit)
    {
        return ERR_NULL_POINTER;
    }
    *bit =  (bitNum > pField->numBits) ? 0 :
            BI_getBit( pField->n, pA->units, bitNum);
    return OK;
}


/*---------------------------------------------------------------------------*/

sbyte4
PRIMEFIELD_cmpToUnsigned(PrimeFieldPtr pField, ConstPFEPtr pPFE, ubyte4 val)
{
    if ( !pField || !pPFE)
      return (sbyte4) ERR_NULL_POINTER;

    return BI_cmpToUnsigned( pField->n, pPFE->units, val);
}


/*---------------------------------------------------------------------------*/

sbyte4
PRIMEFIELD_cmp(PrimeFieldPtr pField, ConstPFEPtr pA, ConstPFEPtr pB)
{
    if ( !pField || !pA || !pB)
      return (sbyte4) ERR_NULL_POINTER;

    return BI_cmp( pField->n, pA->units, pB->units);
}


/*---------------------------------------------------------------------------*/

intBoolean
PRIMEFIELD_match(PrimeFieldPtr pField, ConstPFEPtr pA, ConstPFEPtr pB)
{
    sbyte4 i;
    intBoolean differ = 0;

    if ( !pField || !pA || !pB)
      return FALSE;

    for (i =0; i < pField->n; ++i)
    {
        differ |= (pA->units[i]) ^ (pB->units[i]);
    }

    return (0 == differ);
}


/*---------------------------------------------------------------------------*/


MSTATUS
PRIMEFIELD_newElement( PrimeFieldPtr pField, PFEPtr* ppNewElem)
{
    if( NULL == pField || NULL == ppNewElem)
      return ERR_NULL_POINTER;

    *ppNewElem = (PFEPtr) MALLOC( sizeof(pf_unit) * pField->n);
    if ( *ppNewElem)
    {
        sbyte4 i;
        for ( i = 0; i < pField->n; ++i)
        {
            (*ppNewElem)->units[i] = 0;
        }
        return OK;
    }

    return ERR_MEM_ALLOC_FAIL;
}


/*---------------------------------------------------------------------------*/


MSTATUS
PRIMEFIELD_copyElement( PrimeFieldPtr pField, PFEPtr pDestElem, ConstPFEPtr pSrcElem)
{
    if (!pField || !pDestElem || !pSrcElem)
    {
        return ERR_NULL_POINTER;
    }

    if ( pDestElem != pSrcElem)
    {
        DIGI_MEMCPY( (ubyte*) pDestElem->units,
                     (ubyte*) pSrcElem->units,
                     pField->n * sizeof(pf_unit));
    }

    return OK;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_setToUnsigned( PrimeFieldPtr pField, PFEPtr pDestElem, ubyte4 val)
{
    sbyte4 i;

    if (!pField || !pDestElem )
    {
        return ERR_NULL_POINTER;
    }

    pDestElem->units[0] = val;
    for (i = 1; i < pField->n; ++i)
    {
        pDestElem->units[i] = 0;
    }

    return OK;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_setToByteString( PrimeFieldPtr pField, PFEPtr pA,
                           const ubyte* b, sbyte4 len)
{
    if ( (NULL == pField) || (NULL == pA) || (NULL == b) || (0 >= len) )
    {
        return ERR_NULL_POINTER;
    }
    /* trim leading zeros
     * Don't check if len is 1. If the byte is not 0, then we're done. If that
     * byte is 0, then the value is 0: a buffer of length 1, that one byte being
     * zero.
     */
    while ( (1 < len) && (0 == *b) )
    {
        b++;
        len--;
    }

    if ( (ubyte4)len > pField->n * sizeof(pf_unit) )
    {
        return ERR_FF_DIFFERENT_FIELDS;
    }

    BI_setUnitsToByteString( pField->n, pA->units, b, len);

    /* make sure it is less than pField->units */
    if ( BI_cmp( pField->n, pA->units, pField->units) >= 0)
    {
        return ERR_FF_DIFFERENT_FIELDS;
    }
    return OK;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_writeByteString( PrimeFieldPtr pField, ConstPFEPtr pA, ubyte* b,
                           sbyte4 len)
{
    sbyte4 i, shift;
    pf_unit u;
    sbyte4 minByteLen;

    if (!pField || !pA || !b)
        return ERR_NULL_POINTER;

    minByteLen = (pField->numBits + 7) / 8;

    if (len < minByteLen)
        return ERR_BUFFER_OVERFLOW;

    for (i = 0; i < pField->n - 1; ++i)
    {
        u = pA->units[i];

        b[--len] = (ubyte) ((u));
        b[--len] = (ubyte) ((u) >> 8);
        b[--len] = (ubyte) ((u) >> 16);
        b[--len] = (ubyte) ((u) >> 24);
#ifdef __ENABLE_DIGICERT_64_BIT__
        b[--len] = (ubyte) ((u) >> 32);
        b[--len] = (ubyte) ((u) >> 40);
        b[--len] = (ubyte) ((u) >> 48);
        b[--len] = (ubyte) ((u) >> 56);
#endif
    }

    /* last pf_unit */
    u = pA->units[i];
    shift = 0;
    switch (minByteLen % sizeof(pf_unit))
    {
    case 0:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
#ifdef __ENABLE_DIGICERT_64_BIT__
    case 7:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
    case 6:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
    case 5:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
    case 4:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
#endif
    case 3:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
    case 2:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        /* fall through */
    case 1:
        b[--len] = (ubyte) ((u) >> shift);
        shift += 8;
        break;

    default:
        return ERR_CRYPTO;
    }

    while (len > 0)
    {
        b[--len] = 0;
    }

    return OK;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_getAsByteString( PrimeFieldPtr pField, ConstPFEPtr pA, ubyte** b,
                           sbyte4* pLen)
{
    /* note: this function should preserve leading zeroes! */
    ubyte* pBuffer;
    sbyte4 len;

    if ( !pField || !pA || !b || !pLen)
    {
        return ERR_NULL_POINTER;
    }

    *b = 0;

    len = (pField->numBits + 7) / 8;
    pBuffer = (ubyte*) MALLOC(len);
    if (!pBuffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }
    *b = pBuffer;
    *pLen = len;

    return PRIMEFIELD_writeByteString( pField, pA, pBuffer, len);
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_getAsByteString2( PrimeFieldPtr pField,
                            ConstPFEPtr pA, ConstPFEPtr pB,
                            ubyte** b, sbyte4* pLen)
{
    /* note: this function should preserve leading zeroes! */
    ubyte* pBuffer;
    sbyte4 len;

    if ( !pField || !pA || !pB || !b || !pLen)
    {
        return ERR_NULL_POINTER;
    }

    *b = 0;

    len = (pField->numBits + 7) / 8;
    pBuffer = (ubyte*) MALLOC(2 * len);
    if (!pBuffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }
    *b = pBuffer;
    *pLen = 2 * len;

    PRIMEFIELD_writeByteString( pField, pA, pBuffer, len);
    PRIMEFIELD_writeByteString( pField, pB, pBuffer + len, len);

    return OK;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
PRIMEFIELD_getElementByteStringLen(PrimeFieldPtr pField, sbyte4* len)
{

    if (!pField || !len)
    {
        return ERR_NULL_POINTER;
    }
    *len = (pField->numBits + 7) / 8;

    return OK;
}


/*---------------------------------------------------------------------------*/


MSTATUS
PRIMEFIELD_deleteElement( PrimeFieldPtr pField, PFEPtr* ppNewElem)
{
#ifdef __ZEROIZE_TEST__
	int counter = 0;
#endif

    if (!pField || !ppNewElem || !(*ppNewElem))
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ZEROIZE_TEST__
	FIPS_PRINT("\nPRIMEFIELD Delete Element - Before Zeroization\n");
	for (counter = 0; counter < (sizeof(pf_unit) * pField->n); counter++)
	{
		FIPS_PRINT("%02x", *((ubyte*) *ppNewElem + counter));
	}
	FIPS_PRINT("\n");
#endif

    DIGI_MEMSET((ubyte*) *ppNewElem, 0, sizeof(pf_unit) * pField->n);

#ifdef __ZEROIZE_TEST__
	FIPS_PRINT("\nPRIMEFIELD Delete Element - After Zeroization\n");
	for (counter = 0; counter < (sizeof(pf_unit) * pField->n); counter++)
	{
		FIPS_PRINT("%02x", *((ubyte*) *ppNewElem + counter));
	}
	FIPS_PRINT("\n");
#endif

    FREE( *ppNewElem);
    *ppNewElem = 0;

    return OK;
}


/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))

MSTATUS
PRIMEFIELD_getPrime( PrimeFieldPtr pField, vlong **ppPrime)
{
    MSTATUS status;
    vlong*  pNew = 0;

    if ( !pField || !ppPrime)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > (status = VLONG_allocVlong( &pNew, NULL)))
        goto exit;

    /* newFromArrayUnit reverses everything... */
    if ( OK > ( status = FF_assignArrToVlong( pField->units, pField->n,
                                                pNew)))
    {
        goto exit;
    }

    *ppPrime = pNew;
    pNew = 0;

exit:

    VLONG_freeVlong( &pNew, 0);
    return status;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_newElementFromVlong( PrimeFieldPtr pField, const vlong* pV,
                               PFEPtr* ppNewElem)
{
    MSTATUS status;
    sbyte4 i;
    PFEPtr pNewElem = 0;

    if (!pField || !pV || !ppNewElem)
    {
        return ERR_NULL_POINTER;
    }

    *ppNewElem = 0;

    if ( pV->negative || ((sbyte4) pV->numUnitsUsed) > pField->n)
    {
        return ERR_FF_DIFFERENT_FIELDS;
    }

    if ( pV->numUnitsUsed == pField->n &&
        BI_cmp( pField->n, pV->pUnits, pField->units) >= 0)
    {
        return ERR_FF_DIFFERENT_FIELDS;
    }

    if ( OK > ( status = PRIMEFIELD_newElement( pField, &pNewElem)))
        goto exit;

    for (i = 0; i < (sbyte4) pV->numUnitsUsed; ++i)
    {
        pNewElem->units[i] = pV->pUnits[i];
    }
    for (; i < pField->n; ++i)
    {
        pNewElem->units[i] = 0;
    }

    *ppNewElem = pNewElem;
    pNewElem = 0;

exit:

    PRIMEFIELD_deleteElement( pField, &pNewElem);

    return status;
}


/*---------------------------------------------------------------------------*/

MSTATUS
PRIMEFIELD_newVlongFromElement( PrimeFieldPtr pField, ConstPFEPtr pElem,
                                    vlong** ppNewVlong, vlong** ppQueue)
{
    MSTATUS status;
    vlong*  pNewVlong = 0;

    if (NULL == pField || NULL == pElem || NULL == ppNewVlong)
      return ERR_NULL_POINTER;

    if ( OK > (status = VLONG_allocVlong( &pNewVlong, ppQueue)))
        goto exit;

    if ( OK > ( status = FF_assignArrToVlong( pElem->units, pField->n,
                                                pNewVlong)))
    {
        goto exit;
    }

    *ppNewVlong = pNewVlong;
    pNewVlong = 0;

exit:
    VLONG_freeVlong( &pNewVlong, ppQueue);

    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
PRIMEFIELD_newMpintFromElement(PrimeFieldPtr pField, ConstPFEPtr pElem, ubyte** ppNewMpint, sbyte4 *pRetMpintLength, vlong** ppVlongQueue)
{
    vlong*  pTempVlong = NULL;
    MSTATUS status;

    /* called methods below will handle checking for NULL parameters */

    if (OK > (status = PRIMEFIELD_newVlongFromElement(pField, pElem, &pTempVlong, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_mpintByteStringFromVlong(pTempVlong, ppNewMpint, pRetMpintLength)))
        goto exit;

exit:
    VLONG_freeVlong(&pTempVlong, ppVlongQueue);

    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
PRIMEFIELD_newElementFromMpint(const ubyte* pBuffer, ubyte4 bufSize,
                               ubyte4 *pBufIndex, PrimeFieldPtr pField,
                               PFEPtr* ppNewElem)
{
    ubyte4  numBytesUsed;
    vlong*  pTempVlong = NULL;
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pBuffer || NULL == pBufIndex || NULL == pField || NULL == ppNewElem)
      goto exit;

    if (*pBufIndex == bufSize)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    if ((bufSize < *pBufIndex) || (bufSize < (4 + *pBufIndex)))
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    if (OK > (status = VLONG_newFromMpintBytes((*pBufIndex) + pBuffer, bufSize - (*pBufIndex), &pTempVlong, &numBytesUsed, NULL)))
        goto exit;

    if ((bufSize < numBytesUsed) || (bufSize < ((*pBufIndex) + numBytesUsed)))
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    if (OK > (status = PRIMEFIELD_newElementFromVlong(pField, pTempVlong, ppNewElem)))
        goto exit;

    *pBufIndex += numBytesUsed;

exit:
    VLONG_freeVlong(&pTempVlong, NULL);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__)) */


/* non-inplace addition method. NOT OK for pSum to be the same pointer as pAddend2 */
MSTATUS PRIMEFIELD_add2( PrimeFieldPtr pField, PFEPtr pSum, ConstPFEPtr pAddend, ConstPFEPtr pAddend2)
{
    MSTATUS status;

    /* check pAddend2 for NULL, other params checked below in PRIMEFIELD_copyElement */
    if (NULL == pAddend2)
        return ERR_NULL_POINTER;

    /* Copy pAddend to a mutable pSum. */
    status = PRIMEFIELD_copyElement(pField, pSum, pAddend);
    if (OK != status)
        return status;

    /* add pAddend2 to pSum */
    FF_add( pField->n, pSum->units, pAddend2->units, pField->units);

    return status;
}


/* non-inplace subtraction method. NOT OK for pResult to be the same pointer as pSubtrahend */
MSTATUS PRIMEFIELD_subtract2( PrimeFieldPtr pField, PFEPtr pResult, ConstPFEPtr pMinuend, ConstPFEPtr pSubtrahend)
{
    MSTATUS status;

    /* check pSubtrahend for NULL, other params checked below in PRIMEFIELD_copyElement */
    if (NULL == pSubtrahend)
        return ERR_NULL_POINTER;

    /* Copy pMinuend to a mutable pResult. */
    status = PRIMEFIELD_copyElement(pField, pResult, pMinuend);
    if (OK != status)
        return status;

    /* subtract pSubtrahend from pResult */
    FF_sub( pField->n, pResult->units, pSubtrahend->units, pField->units);

    return status;
}

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)

/*
  This method is only provided for PF_p448 and has the dual purpose
  of calculating a modular inverse or an intermediate step in
  calculating a modular square root via exponentiation.

  If isInverse is true then this computes the modular inverse of pA by
  raising pA to the (p-2)-th power, ie to the 2^448 - 2^224 - 3.

  If isInverse is false then this computes pA to the (p-3)/4-th power,
  ie to the 2^446 - 2^222 - 1, which is a intermediate calculation needed
  in finding a candidate square root (as per the edDSA specs on curve X488,
  section 5.2.3 step 2) of https://tools.ietf.org/pdf/rfc8032.pdf ).

  We use my own custom addition chain.
 */
MSTATUS PRIMEFIELD_specialExp448( PFEPtr pResult, ConstPFEPtr pA, byteBoolean isInverse)
{
    MSTATUS status;
    int i;

#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit hilo[14] = {0};
#else
    pf_unit hilo[28] = {0};
#endif

    PFEPtr pTemp1 = NULL;
    PFEPtr pTemp2 = NULL;
    PFEPtr pTemp3 = NULL;
    PFEPtr pTemp4 = NULL;

    if (NULL == pResult || NULL == pA)
        return ERR_NULL_POINTER;

    status = PRIMEFIELD_newElement(PF_p448, &pTemp1);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p448, &pTemp2);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p448, &pTemp3);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(PF_p448, &pTemp4);
    if (OK != status)
        goto exit;

    /* NOTE: We purposely ignore return codes for PRIMEFIELD_squareAux and
     PRIMEFIELD_multiplyAux since NULL params are already checked
     and that's the only possible return code. */

    /* pA to an exponent of 2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp1, pA, hilo);

    /* pA to an exponent of 3 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp2, pTemp1, pA, hilo);

    /* pA to an exponent of 4 */
    PRIMEFIELD_squareAux(PF_p448, pTemp3, pTemp1, hilo);

    /****** done with pTemp1, reuse it ******/

    /* pA to an exponent of 7 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp1, pTemp2, pTemp3, hilo);

    /****** done with pTemp2 and pTemp3, reuse them ******/

    /* pA to an exponent of 14 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);

    /* pA to an exponent of 28 */
    PRIMEFIELD_squareAux(PF_p448, pTemp3, pTemp2, hilo);

    /* pA to an exponent of 56 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp3, hilo);

    /* pA to an exponent of 63 = 2^6 - 1  */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp3, pTemp2, pTemp1, hilo);

    /****** done with this pTemp1 and pTemp2, reuse them, save pTemp3 ******/

    /* pA to an exponent of 2^7 - 2^1  */
    PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp3, hilo);

    /* pA to an exponent of 2^8 - 2^2  */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);

    /* pA to an exponent of 2^12 - 2^6 */
    for (i = 0; i < 2; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp2, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);
    }

    /* pA to an exponent of 2^12 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp4, pTemp3, pTemp2, hilo);

    /* pA to an exponent of 2^13 - 2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp4, hilo);

    /* pA to an exponent of 2^14 - 2^2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);

    /* pA to an exponent of 2^24 - 2^12 */
    for (i = 0; i < 5; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp2, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);
    }

    /* pA to an exponent of 2^24 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp1, pTemp4, pTemp2, hilo);

    /******* done with this pTemp4, reuse. save pTemp1 for now *******/

    /* pA to an exponent of 2^25 - 2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);

    /* pA to an exponent of 2^26 - 2^2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp4, pTemp2, hilo);

    /* pA to an exponent of 2^48 - 2^24 */
    for (i = 0; i < 11; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp4, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp4, pTemp2, hilo);
    }

    /* pA to an exponent of 2^48 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp2, pTemp1, pTemp4, hilo);

    /* pA to an exponent of 2^54 - 2^6 */
    for (i = 0; i < 3; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp2, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);
    }

    /* pA to an exponent of 2^54 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp1, pTemp2, pTemp3, hilo);

    /******* save pTemp1 for now *******/

    /* pA to an exponent of 2^55 - 2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp4, pTemp1, hilo);

    /* pA to an exponent of 2^56 - 2^2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp4, hilo);

    /* pA to an exponent of 2^108 - 2^54 */
    for (i = 0; i < 26; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp4, pTemp2, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp4, hilo);
    }

    /* pA to an exponent of 2^108 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp4, pTemp1, pTemp2, hilo);

    /******* save pTemp4 for now *******/

    /* pA to an exponent of 2^109 - 2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp4, hilo);

    /* pA to an exponent of 2^110 - 2^2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp2, hilo);

    /* pA to an exponent of 2^216 - 2^108 */
    for (i = 0; i < 53; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp2, hilo);
    }

    /* pA to an exponent of 2^216 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp2, pTemp1, pTemp4, hilo);

    /* pA to an exponent of 2^222 - 2^6 */
    for (i = 0; i < 3; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp2, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);
    }

    /* pA to an exponent of 2^222 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp1, pTemp2, pTemp3, hilo);

    /******* save pTemp1 *******/

    /* pA to an exponent of 2^223 - 2 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp1, hilo);

    /* pA to an exponent of 2^223 - 1 */
    PRIMEFIELD_multiplyAux(PF_p448, pTemp4, pTemp2, pA, hilo);

    /* pA to an exponent of 2^224 - 2^1 */
    PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp4, hilo);

    /* pA to an exponent of 2^446 - 2^223 */
    for (i = 0; i < 111; ++i)
    {
        PRIMEFIELD_squareAux(PF_p448, pTemp4, pTemp2, hilo);
        PRIMEFIELD_squareAux(PF_p448, pTemp2, pTemp4, hilo);
    }

    if (isInverse)
    {
        /* pA to an exponent of (2^446 - 2^223) + (2^222 - 1) = 2^446 - 2^222 - 1 */
        PRIMEFIELD_multiplyAux(PF_p448, pTemp4, pTemp2, pTemp1, hilo);

        /* pA to an exponent of 2^447 - 2^223 - 2 */
        PRIMEFIELD_squareAux(PF_p448, pTemp1, pTemp4, hilo);

        /* pA to an exponent of 2^448 - 2^224 - 4 */
        PRIMEFIELD_squareAux(PF_p448, pTemp4, pTemp1, hilo);

        /* pA to an exponent of 2^448 - 2^224 - 3 */
        PRIMEFIELD_multiplyAux(PF_p448, pResult, pTemp4, pA, hilo);
    }
    else
    {
        /* pA to an exponent of (2^446 - 2^223) + (2^222 - 1) = 2^446 - 2^222 - 1 */
        PRIMEFIELD_multiplyAux(PF_p448, pResult, pTemp2, pTemp1, hilo);
    }

exit:

    if (NULL != pTemp1)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pTemp1);
    }
    if (NULL != pTemp2)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pTemp2);
    }
    if (NULL != pTemp3)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pTemp3);
    }
    if (NULL != pTemp4)
    {
        PRIMEFIELD_deleteElement(PF_p448, &pTemp4);
    }

    return status;
}

#endif /* if defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__) */
#endif /* if (defined(__ENABLE_DIGICERT_ECC__)) */

/*---------------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_RSA_SIMPLE__) || defined (__ENABLE_DIGICERT_PKCS1_SIMPLE__)

#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

typedef struct signed_bi
{
    sbyte4  neg;        /* negative */
    sbyte4  nu;         /* units used */
    pf_unit digits[1];  /* digits */
} signed_bi;

#define SIGNED_BI_SIZE(n)  ( sizeof(signed_bi) + ((n) - 1) * sizeof(pf_unit) )

/*---------------------------------------------------------------------------*/

static sbyte4 BI_lastUnitSet( sbyte4 n, const pf_unit a[/*n*/])
{
    sbyte4 i, retVal = -1;

    for (i = 0; i < n; ++i)
    {
        if ( a[i]) retVal = i;
    }
    return retVal;
}


/*---------------------------------------------------------------------------*/

/* a = b - a, returns borrow ( borrow != 0 if a > b )*/

static pf_unit BI_subRev( sbyte4 n, pf_unit* a, const pf_unit* b)
{
    pf_unit borrow;
    sbyte4 i;

    borrow = 0;
    for (i = 0; i < n; ++i)
    {
        pf_unit tmp = b[i];
        pf_unit bbb = ( tmp < borrow) ? 1 : 0;
        tmp -= borrow;

        bbb += ( tmp < a[i]) ? 1 : 0;
        tmp -= a[i];
        a[i] = tmp;
        borrow = bbb;
    }
    return borrow;
}


/*---------------------------------------------------------------------------*/

static void BIS_shiftR( signed_bi* a)
{
    if ( a->nu > 0)
    {
        BI_shiftREx( a->nu, a->digits, 1);
        if ( ZERO_UNIT == a->digits[a->nu-1])
        {
            a->nu--;
        }
    }
}


/*---------------------------------------------------------------------------*/

/* a_s += b, returns carry */
static pf_unit BIS_add( sbyte4 n, signed_bi* a, const signed_bi* b)
{
    pf_unit carry;

    if (a->neg == b->neg)
    {
        carry = BI_add(n, a->digits, b->digits); /* possible carry */
    }
    else if ( BI_cmp(n, a->digits, b->digits) >= 0)
    {
        carry = BI_sub(n, a->digits, b->digits); /* no borrow and no carry */
    }
    else
    {
        /* use a special function; otherwise we need to do mem allocation
        cf. vlong */
        /* subRev => a->digits = b->digits - a->digits */
        a->neg = b->neg; /* results takes the sign of b */
        carry = BI_subRev(n, a->digits, b->digits); /* no borrow and no carry */
    }
    a->nu = 1 + BI_lastUnitSet(n,a->digits);
    return carry;
}


/*---------------------------------------------------------------------------*/

/* a_s -= b, returns borrow */
static pf_unit BIS_sub( sbyte4 n, signed_bi* a, const signed_bi* b)
{
    pf_unit carry;

    if (a->neg != b->neg)
    {
        carry = BI_add(n, a->digits, b->digits);
    }
    else if ( BI_cmp(n, a->digits, b->digits) >= 0)
    {
        carry = BI_sub(n, a->digits, b->digits); /* no borrow and no carry */
    }
    else
    {
        /* use a special function; otherwise we need to do mem allocation
        cf. vlong */
        /* subRev => a->digits = b->digits - a->digits */
        a->neg = 1 - (b->neg);
        carry = BI_subRev(n, a->digits, b->digits); /* no borrow and no carry */
    }
    a->nu = 1 + BI_lastUnitSet(n,a->digits);
    return carry;
}


/*---------------------------------------------------------------------------*/

static sbyte4 BIS_cmp( sbyte4 n, const signed_bi* a, const signed_bi* b)
{
    sbyte4 negA, negB;

    negA = (a->nu > 0 && a->neg) ? TRUE : FALSE;
    negB = (b->nu > 0 && b->neg) ? TRUE : FALSE;
    if (negA == negB)
    {
        sbyte4 uCmp = BI_cmp( n, a->digits, b->digits);
        return  ( negA) ? -uCmp : uCmp;
    }
    else if (negA)
    {
        return -1;
    }
    else
    {
        return 1;
    }
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
BI_modExp( sbyte4 k, pf_unit pResult[/*k*/], const pf_unit pN[/*k*/],
           ubyte4 e, const pf_unit pModulo[/*k+1*/], const pf_unit pMu[/*k+1*/])
{
    /* This routine is used as part of the sec_boot project: it is used
    to implement RSA encryption with the minimal amount of code */
    MSTATUS status;
    pf_unit* mulBuffer = 0;
    sbyte4 i;
    ubyte4 mask = 0x80000000;

    if (!pResult || !pN || !pModulo || !pMu)
        return ERR_NULL_POINTER;

    /* allocate a buffer big enough for everything */
    mulBuffer = (pf_unit*) MALLOC( ((2 * k) + (2 * (k+1))) * sizeof(pf_unit));

    if ( !mulBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* don't spend time multiplying 1 by 1 */
    for (i = 0; i < 8 * sizeof(ubyte4); ++i, mask >>= 1)
    {
        if (mask & e)
        {
            DIGI_MEMCPY( pResult, pN, k * sizeof(pf_unit));
            break;
        }
    }

    for (++i, mask >>= 1; i < 8 * sizeof(ubyte4); ++i, mask >>= 1)
    {
        /* pResult = pResult * pResult */
        /* multiply into buffer */
        BI_mul( k, mulBuffer, pResult, pResult, 2 * k);
        /* barrett reduction */
#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
        status = BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
        if (OK != status)
            goto exit;

#else   /* return status always OK */
        BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
#endif
        if ( mask & e)
        {
            /* pResult = pResult * pN */
            BI_mul( k, mulBuffer, pResult, pN, 2 * k);
            /* barrett reduction */
#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
            status = BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
            if (OK != status)
                goto exit;
#else   /* return status always OK */
            BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
#endif
        }
    }

    status = OK;

exit:

    if ( mulBuffer)
    {
        FREE( mulBuffer);
    }

    return status;
}

/*---------------------------------------------------------------------------*/



MOC_EXTERN MSTATUS
BI_modExpEx( sbyte4 k, pf_unit pResult[/*k*/], const pf_unit pN[/*2*k*/],
           sbyte4 eLen, const pf_unit pE[/*eLen*/],
           const pf_unit pModulo[/*k+1*/], const pf_unit pMu[/*k+1*/])
{
    MSTATUS status;
    pf_unit* pNN = 0;
    pf_unit* mulBuffer;
    sbyte4 i;
    pf_unit mask;

    if (!pResult || !pN || !pModulo || !pMu || !pE)
        return ERR_NULL_POINTER;

    /* allocate a buffer big enough for everything */
    pNN = (pf_unit*) MALLOC( ((4 * k) + (2 * (k+1))) * sizeof(pf_unit));

    if ( !pNN)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* make a copy of pN since Barrett Reduction will modify it */
    for ( i = 0; i < 2 * k ; ++i)
    {
        pNN[i] = pN[i];
    }

    mulBuffer = pNN + 2 * k;

    --eLen;

    while (eLen >= 0 && ZERO_UNIT == pE[eLen])
    {
        --eLen;
    }

    if (eLen < 0) /* exponent 0, result = 1 */
    {
        DIGI_MEMSET( (ubyte*) pResult, 0, k * sizeof(pf_unit));
        pResult[0] = 1;
        status = OK;
        goto exit;
    }

    mask = (((pf_unit) 1) << (BPU-1));
    /* don't spend time multiplying 1 by 1 */
    for (i = 0; i < BPU; ++i, mask >>= 1)
    {
        if (mask & pE[eLen])
        {

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
            status = BI_barrettReduction( k, pNN, pResult, mulBuffer, pMu, pModulo);
            if (OK != status)
                goto exit;
#else     /* return status always OK */
            BI_barrettReduction( k, pNN, pResult, mulBuffer, pMu, pModulo);
#endif
            /* pNN = pResult at this point -- no need to copy pResult to pNN */
            break;
        }
    }

    ++i;
    mask >>= 1;

    for (; eLen >= 0; --eLen)
    {
        for (; i < BPU; ++i, mask >>= 1)
        {
            /* pResult = pResult * pResult */
            /* multiply into buffer */
            BI_mul( k, mulBuffer, pResult, pResult, 2 * k);
            /* barrett reduction */
#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
            status = BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
            if (OK != status)
                goto exit;

#else       /* return status always OK */
            BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
#endif
            if ( mask & pE[eLen])
            {
                /* pResult = pResult * pN */
                BI_mul( k, mulBuffer, pResult, pNN, 2 * k);
                /* barrett reduction */
#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
                status = BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
                if (OK != status)
                    goto exit;

#else           /* return status always OK */
                BI_barrettReduction( k, mulBuffer, pResult, mulBuffer + (2 * k), pMu, pModulo);
#endif
            }
        }

        i = 0;
        mask = (((pf_unit) 1) << (BPU-1));
    }

    status = OK;

exit:

    if ( pNN)
    {
        FREE( pNN);
    }

    return status;
}

MOC_EXTERN MSTATUS
BI_barrettMu( sbyte4 k, pf_unit mu[/*k+1*/], const pf_unit modulus[/*k+1*/])
{
    MSTATUS status;
    pf_unit* b2k;
    pf_unit* cdivisor;
    const pf_unit* divisor;
    sbyte4 i,j;
    pf_unit yt, b;
    ubyte4 shift, bitLen;
    pf_unit* m;

    if (!modulus || !mu)
        return ERR_NULL_POINTER;

    /* make sure modulus[k-1] is not zero */
    while ( k > 0 && 0 == modulus[k-1])
    {
        --k;
    }
    if (0 == k)
    {
        return ERR_DIVIDE_BY_ZERO;
    }

    /* generate b^(2k) */
    /* b^2k is 2k + 1 units long  i.e. n = 2k t = k-1 */
    m = (pf_unit*) MALLOC( ((3 * k) + 2) * sizeof(pf_unit));
    if ( !m)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    b2k = m + 1;
    cdivisor = b2k + 2 * k + 1;

    /* zero pMu and most of b2k */
    for ( i = 0; i < k + 1; ++i)
    {
        b2k[i] = mu[i] = 0;
    }
    for (; i < 2 * k; ++i)
    {
        b2k[i] = 0;
    }

    /* divide b2k by modulus -- we will do it by half-word
    so that we can use the word by word division */
    /* normalize */
# ifdef __ENABLE_DIGICERT_64_BIT__
    {
        ubyte4 hi = HI_HUNIT(modulus[k-1]);
        bitLen = (hi) ? 32 + DIGI_BITLENGTH(hi) :
                DIGI_BITLENGTH( (ubyte4) LO_HUNIT(modulus[k-1]));
    }
#else
    bitLen = DIGI_BITLENGTH(modulus[k-1]);  /* pModulus[k] = 0 */
#endif

    shift = BPU - bitLen;
    b2k[2*k] = ((pf_unit)1) << shift;

    if ( shift > 0)
    {
        pf_unit temp;

        b = 0;
        for (i = 0; i < k; ++i)
        {
            temp = modulus[i];
            cdivisor[i] = ( (temp << shift) | b);
            b = (temp >> bitLen);
        }
        divisor = cdivisor;
    }
    else
    {
        divisor = modulus;
    }
    /* everything normalized -- do the divide */
    /* step 2 */
    /* compare b2k with y.b^(n-t) since b2k is 1<<shift followed by zeroes
    and divisor[k-1] is at minimum 1 << shift this is never the case */

    /* step 3  -- use half words */
    yt = HI_HUNIT(divisor[k-1]);
    for ( i = 2*k; i > k - 1; --i)
    {
        pf_unit hi, lo, r0, r1, r2;

        /* hi word first */
        /* 3.1*/
        if ( HI_HUNIT(b2k[i]) == yt)
        {
            hi = LO_HUNIT(FULL_MASK);
        }
        else
        {
            hi = LO_HUNIT(b2k[i]/yt);
        }
        /* 3.2*/
        for (;;)
        {
            r0 = hi * LO_HUNIT(divisor[k-1]);
            r1 = hi * yt;
            r1 += HI_HUNIT(r0);
            r0 &= LO_MASK;

            if ( r1 > b2k[i] ||
                (r1 == b2k[i] && r0 > HI_HUNIT(b2k[i-1])))
            {
                --hi;
            }
            else
            {
                break;
            }
        }

        /* 3.3 - subtract hi * divisor from b2k */
        r0 = r1 = r2 = 0;
        for (j = 0; j < k; ++j)
        {
            m[0] = MAKE_UNIT(hi, 0);
            MULT_ADDCX(m, divisor, 0, j, r0, r1, r2);
            b = ( b2k[i+j-k] < r0) ? 1 : 0;
            b2k[i+j-k] -= r0;
            /* add the other digits including the borrow */
            r0 = r1; r0 += b; b = (r0 >= r1) ? 0 : 1;
            r1 = b;
        }

        /* 3.4 */
        if ( b2k[i] < r0 )
        {
            b = 0;

            b2k[i] -= r0;

            r0 = r1 = 0;
            for ( j = 0; j < k; ++j)
            {
                r0 += MAKE_HI_HUNIT(divisor[j]);
                b = (r0 < MAKE_HI_HUNIT(divisor[j]))? 1 : 0;
                r1 = HI_HUNIT(divisor[j]) + b;

                b2k[i+j-k] += r0;
                b = (b2k[i+j-k]  < r0) ? 1 : 0;
                r0 = r1 + b;
            }
            b2k[i] += r0;
            hi--;
        }
        else
        {
            b2k[i] -= r0;
        }

        /* lo word next */
        r2 = MAKE_UNIT(LO_HUNIT(b2k[i]), HI_HUNIT(b2k[i-1]));
        if ( LO_HUNIT(b2k[i]) == yt)
        {
            lo = LO_HUNIT(FULL_MASK);
        }
        else
        {
            lo =  LO_HUNIT(r2/yt);
        }

        for (;;)
        {
            r0 = lo * LO_HUNIT(divisor[k-1]);
            r1 = lo * yt;
            r1 += HI_HUNIT(r0);
            r0 &= LO_MASK;

            if ( r1 > r2 ||
                (r1 == r2 && r0 > LO_HUNIT(b2k[i-1]) ))
            {
                --lo;
            }
            else
            {
                break;
            }
        }

        /* 3.3 - subtract lo * divisor from b2k */
        r0 = r1 = r2 = 0;
        for (j = 0; j < k; ++j)
        {
            m[0] = lo;
            MULT_ADDCX(m, divisor, 0, j, r0, r1, r2);
            b = ( b2k[i+j-k] < r0) ? 1 : 0;
            b2k[i+j-k] -= r0;
            /* add the other digits including the borrow */
            r0 = r1; r0 += b; b = (r0 >= r1) ? 0 : 1;
            r1 = b;
        }

        /* 3.4 */
        if ( b2k[i] < r0 )
        {
            b = 0;

            b2k[i] -= r0;
            for ( j = 0; j < k; ++j)
            {
                b2k[i+j-k] += b;
                b = (b2k[i+j-k]  < b) ? 1 : 0;

                b2k[i+j-k] += divisor[j];
                b += (b2k[i+j-k]  < divisor[j]) ? 1 : 0;
            }
            b2k[i] += b;
            lo--;
        }
        else
        {
            b2k[i] -= r0;
        }

        /* store now */
        mu[i-k] += MAKE_UNIT(hi, lo);
    }

    status = OK;

exit:

    if ( m)
    {
        FREE( m);
    }

    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
BI_divide( sbyte4 n, const pf_unit a[/*n*/],
          sbyte4 t, const pf_unit b[/*t*/],
          pf_unit q[/*n-t+1*/], pf_unit r[/*t*/])
{
    MSTATUS status;
    sbyte4 i,j;
    pf_unit yt, bc; /* bc = borrow or carry */
    ubyte4 shift, bitLen;
    pf_unit* m;
    pf_unit* x;
    pf_unit* y;

    if (!a || !b || !q || !r)
        return ERR_NULL_POINTER;

    DIGI_MEMSET((ubyte*)q, 0, (n-t+1) * sizeof(pf_unit)); /* zero out the quotient */
    DIGI_MEMSET((ubyte*)r, 0, t * sizeof(pf_unit)); /* zero out the remainder */

    /* more checks */
    while ( 0!=t && 0 == b[t-1])
    {
        --t;
    }

    if (0 == t)
    {
        return ERR_DIVIDE_BY_ZERO;
    }

    if (t > n)
    {
        /* q = 0, r = a */
        DIGI_MEMCPY( r, a, n * sizeof(pf_unit));
        DIGI_MEMSET((ubyte*)(r + n), 0, t - n);
        return OK;
    }

    /* normalize */
# ifdef __ENABLE_DIGICERT_64_BIT__
    {
        ubyte4 hi = HI_HUNIT(b[t-1]);
        bitLen = (hi) ? 32 + DIGI_BITLENGTH(hi) :
                DIGI_BITLENGTH( (ubyte4) LO_HUNIT(b[t-1]));
    }
#else
    bitLen = DIGI_BITLENGTH(b[t-1]);  /* pModulus[k] = 0 */
#endif
    shift = BPU - bitLen;
    /* need to allocate memory for shifted values */
    /* bitLen = BPU - shift; */
    if ( shift)
    {
        ubyte4 size = (1 + t + n + (( a[n-1] >> bitLen) ? 1 : 0));
        m = MALLOC(size * sizeof(pf_unit));
        if ( 0 == m)
            return ERR_MEM_ALLOC_FAIL;
        /* shift a */
        bc = 0;
        x = m + 1;
        for (i = 0; i < n; ++i)
        {
            x[i] = ((a[i] << shift) | bc);
            bc = (a[i] >> bitLen);
        }
        if (bc)
        {
            x[n++] = bc;
        }

        /* shift b */
        bc = 0;
        y = x + n;
        for (i = 0; i < t; ++i)
        {
            y[i] = ((b[i] << shift) | bc);
            bc = (b[i] >> bitLen);
        }
        /* assert bc == 0 */
    }
    else
    {
        m = MALLOC( (1 + n) * sizeof(pf_unit));
        if ( 0 == m)
            return ERR_MEM_ALLOC_FAIL;
        x = m + 1;
        DIGI_MEMCPY(x, a, n * sizeof(pf_unit));
        y = (pf_unit *) b;
        /* assert bc == 0 */
    }

    /* everything normalized -- do the divide */
    /* step 2 */
    /* compare x with y.b^(n-t) */
    i = BI_cmp( t, x + n - t, y);
    if (i > 0)
    {
        BI_sub(t, x + n - t, y);
        q[n-t] = 1;
    }

    /* step 3  -- use half words */
    yt = HI_HUNIT(y[t-1]);
    for ( i = n-1; i >= t; --i)
    {
        pf_unit hi, lo, r0, r1, r2;

        /* hi word first */
        /* 3.1*/
        if ( HI_HUNIT(x[i]) == yt)
        {
            hi = LO_HUNIT(FULL_MASK);
        }
        else
        {
            hi = LO_HUNIT(x[i]/yt);
        }
        /* 3.2*/
        for (;;)
        {
            r0 = hi * LO_HUNIT(y[t-1]);
            r1 = hi * yt;
            r1 += HI_HUNIT(r0);
            r0 &= LO_MASK;

            if ( r1 > x[i] ||
                (r1 == x[i] && r0 > HI_HUNIT(x[i-1])))
            {
                --hi;
            }
            else
            {
                break;
            }
        }

        /* 3.3 - subtract hi * divisor from x */
        r0 = r1 = r2 = 0;
        for (j = 0; j < t; ++j)
        {
            m[0] = MAKE_UNIT(hi, 0);
            MULT_ADDCX(m, y, 0, j, r0, r1, r2);
            bc = ( x[i+j-t] < r0) ? 1 : 0;
            x[i+j-t] -= r0;
            /* add the other digits including the bc */
            r0 = r1; r0 += bc; bc = (r0 >= r1) ? 0 : 1;
            r1 = bc;
        }

        /* 3.4 */
        if ( x[i] < r0 )
        {
            bc = 0;

            x[i] -= r0;

            r0 = r1 = 0;
            for ( j = 0; j < t; ++j)
            {
                r0 += MAKE_HI_HUNIT(y[j]);
                bc = (r0 < MAKE_HI_HUNIT(y[j]))? 1 : 0;
                r1 = HI_HUNIT(y[j]) + bc;

                x[i+j-t] += r0;
                bc = (x[i+j-t]  < r0) ? 1 : 0;
                r0 = r1 + bc;
            }
            x[i] += r0;
            hi--;
        }
        else
        {
            x[i] -= r0;
        }

        /* lo word next */
        r2 = MAKE_UNIT(LO_HUNIT(x[i]), HI_HUNIT(x[i-1]));
        if ( LO_HUNIT(x[i]) == yt)
        {
            lo = LO_HUNIT(FULL_MASK);
        }
        else
        {
            lo =  LO_HUNIT(r2/yt);
        }

        for (;;)
        {
            r0 = lo * LO_HUNIT(y[t-1]);
            r1 = lo * yt;
            r1 += HI_HUNIT(r0);
            r0 &= LO_MASK;

            if ( r1 > r2 ||
                (r1 == r2 && r0 > LO_HUNIT(x[i-1]) ))
            {
                --lo;
            }
            else
            {
                break;
            }
        }

        /* 3.3 - subtract lo * y from x */
        r0 = r1 = r2 = 0;
        for (j = 0; j < t; ++j)
        {
            m[0] = lo;
            MULT_ADDCX(m, y, 0, j, r0, r1, r2);
            bc = ( x[i+j-t] < r0) ? 1 : 0;
            x[i+j-t] -= r0;
            /* add the other digits including the bc */
            r0 = r1; r0 += bc; bc = (r0 >= r1) ? 0 : 1;
            r1 = bc;
        }

        /* 3.4 */
        if ( x[i] < r0 )
        {
            bc = 0;

            x[i] -= r0;
            for ( j = 0; j < t; ++j)
            {
                x[i+j-t] += bc;
                bc = (x[i+j-t]  < bc) ? 1 : 0;

                x[i+j-t] += y[j];
                bc += (x[i+j-t]  < y[j]) ? 1 : 0;
            }
            x[i] += bc;
            lo--;
        }
        else
        {
            x[i] -= r0;
        }

        /* store now */
        q[i-t] += MAKE_UNIT(hi, lo);
    }

    if (shift)
    {
        bc = 0;
        for (i = t-1; i >= 0; --i)
        {
            r[i] = ((x[i] >> shift) | bc);
            bc = (x[i] << bitLen);
        }
    }
    else
    {
        DIGI_MEMCPY( r, x, t * sizeof(pf_unit));
    }
    status = OK;

    if ( m)
    {
        FREE( m);
    }

    return status;
}


/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
BI_modularInverse(sbyte4 n, const pf_unit a[/*n*/], const pf_unit m[/*n*/],
                  pf_unit inv[/*n*/])
{
    MSTATUS status = OK;
    signed_bi* x = NULL;
    signed_bi* y;
    signed_bi* A;
    signed_bi* B;
    signed_bi* C;
    signed_bi* D;
    signed_bi* u;
    signed_bi* v;
    signed_bi* modulus;
    sbyte4 N = n+1;

    x = MALLOC( 9 * SIGNED_BI_SIZE(N));

    if (!x)
        return ERR_MEM_ALLOC_FAIL;

    DIGI_MEMSET( (ubyte*) x, 0, 9 * SIGNED_BI_SIZE(N));

    y = (signed_bi*) (((ubyte*)x) + SIGNED_BI_SIZE(N));
    A = (signed_bi*) (((ubyte*)y) + SIGNED_BI_SIZE(N));
    B = (signed_bi*) (((ubyte*)A) + SIGNED_BI_SIZE(N));
    C = (signed_bi*) (((ubyte*)B) + SIGNED_BI_SIZE(N));
    D = (signed_bi*) (((ubyte*)C) + SIGNED_BI_SIZE(N));
    u = (signed_bi*) (((ubyte*)D) + SIGNED_BI_SIZE(N));
    v = (signed_bi*) (((ubyte*)u) + SIGNED_BI_SIZE(N));
    modulus = (signed_bi*) (((ubyte*)v) + SIGNED_BI_SIZE(N));

    DIGI_MEMCPY( x->digits, m, n * sizeof(pf_unit));
    x->neg = 0;
    x->nu = 1 + BI_lastUnitSet(n, x->digits);

    DIGI_MEMCPY( modulus->digits, m, n * sizeof(pf_unit));
    modulus->neg = 0;
    modulus->nu = x->nu;

    DIGI_MEMCPY( y->digits, a, n * sizeof(pf_unit));
    y->neg = 0;
    y->nu = 1 + BI_lastUnitSet(n, y->digits);

    /* A = D = 1, B = C = 0 */
    A->digits[0] = D->digits[0] = 1;
    A->nu = D->nu = 1;

    while (x->nu > 0 && IS_EVEN(x->digits) &&
           y->nu > 0 && IS_EVEN(y->digits) )
    {
        BIS_shiftR(x);
        BIS_shiftR(y);
    }

    DIGI_MEMCPY( u, x, SIGNED_BI_SIZE(x->nu));
    DIGI_MEMCPY( v, y, SIGNED_BI_SIZE(y->nu));

    do
    {
        while ( u->nu > 0 && IS_EVEN( u->digits))
        {
            BIS_shiftR(u);

            if ( !IS_EVEN(A->digits) || !IS_EVEN( B->digits))
            {
                BIS_add(N, A, y);
                BIS_sub(N, B, x);
            }

            BIS_shiftR(A);
            BIS_shiftR(B);

        }

        while (v->nu > 0 && IS_EVEN( v->digits))
        {
            BIS_shiftR(v);

            if ( !IS_EVEN(C->digits) || !IS_EVEN( D->digits))
            {
                BIS_add(N, C, y);
                BIS_sub(N, D, modulus);
            }
            BIS_shiftR(C);
            BIS_shiftR(D);
        }

        if ( BIS_cmp(N, u, v) >= 0)
        {
            BIS_sub(N, u, v);  /* no borrow */
            BIS_sub(N, A, C);
            BIS_sub(N, B, D);
        }
        else
        {
            BIS_sub(N, v, u); /* no borrow */
            BIS_sub(N, C, A);
            BIS_sub(N, D, B);
        }

    } while (u->nu > 0);

    while ( D->neg)
    {
        BIS_add(N, D, modulus);
    }

    DIGI_MEMCPY( inv, D->digits, n * sizeof(pf_unit));

    FREE(x);

    return status;
}

#endif /* if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__)) */

#endif /* __ENABLE_DIGICERT_RSA_SIMPLE__ */

/*--------------------------------------------------------------------------*/

MOC_EXTERN void BI_setUnitsToByteString( sbyte4 n, pf_unit* a,
                               const ubyte* b, sbyte4 bLen)
{
    sbyte4 i, j, count;

    count = 0;

    for (i = bLen - 1; i >= 0; ++count)
    {
        pf_unit elem = 0;

        for (j = 0; j < (sbyte4)(sizeof(pf_unit)) && i >= 0; ++j, --i)
        {
            elem |= (((pf_unit) b[i]) << (j * 8));
        }
        a[count] = elem;
    }
    for ( ; count < n; ++count)
    {
        a[count] = 0;
    }
 }

/*---------------------------------------------------------------------------*/

/* a_s += b, returns carry */
MOC_EXTERN pf_unit BI_add( sbyte4 n, pf_unit* a_s, const pf_unit* b)
{
    pf_unit carry;
    sbyte4 i;

    carry = 0;

    if ( a_s == b) /* doubling */
    {
        pf_unit old_b; /* save in case a == b */

        for (i = 0; i < n; ++i)
        {
            old_b = b[i];
            a_s[i] += carry;
            carry = (a_s[i] < carry) ? 1 : 0;

            a_s[i] += old_b;
            carry += (a_s[i] < old_b) ? 1 : 0;
        }
    }
    else
    {
        for (i = 0; i < n; ++i)
        {
            a_s[i] += carry;
            carry = (a_s[i] < carry) ? 1 : 0;

            a_s[i] += b[i];
            carry += (a_s[i] < b[i]) ? 1 : 0;
        }
    }
    return carry;
}


/*---------------------------------------------------------------------------*/

/* a_s -= b, returns borrow ( borrow != 0 if a_s < b )*/

MOC_EXTERN pf_unit BI_sub( sbyte4 n, pf_unit* a_s, const pf_unit* b)
{
    pf_unit borrow;
    sbyte4 i;

    borrow = 0;
    for (i = 0; i < n; ++i)
    {
        pf_unit bbb = ( a_s[i] < borrow) ? 1 : 0;
        a_s[i] -= borrow;

        bbb += ( a_s[i] < b[i]) ? 1 : 0;
        a_s[i] -= b[i];
        borrow = bbb;
    }
    return borrow;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN sbyte4 BI_cmp(sbyte4 n, const pf_unit* a, const pf_unit* b)
{
    sbyte4 i;

    for ( i = n-1; i >=0; --i)
    {
        if ( a[i] > b[i]) return 1;
        if ( a[i] < b[i]) return -1;
    }
    return 0;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__

#if defined(__arm__) && !defined(__OPTIMIZE__)
#warning Assembly multiplication routine will default back to C code. Must compile with the -O1 option to use the assembly code.
#endif

static
#if defined(__APPLE__) && defined(__arm__)
/*
 * Apple LLVM version 4.2 (clang-425.0.24) (based on LLVM 3.2svn)
 * appears to need this to prevent bad ARM code generation at -O3.
 */
__attribute__ ((noinline))
#endif
void BI_mul_assembly( ubyte4 i, pf_unit *s, pf_unit *d, pf_unit b )
{
    pf_unit c = 0;
#ifdef ASM_COLDFIRE_BACKUP_VARS
    ASM_COLDFIRE_BACKUP_VARS(pf_unit)
#endif
    pf_unit t = 0;

#if defined(MOC_MULADDC_HUIT)
    for( ; i >= 8; i -= 8 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_HUIT
        MOC_MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
#else /* MOC_MULADDC_HUIT */
    for( ; i >= 16; i -= 16 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE

        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }

    for( ; i >= 8; i -= 8 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE

        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
#endif /* MOC_MULADDC_HUIT */

    t++;

    do
    {
        *d += c; c = ( *d < c ); d++;
    }
    while( c );
}
#endif /* __ENABLE_DIGICERT_BI_MUL_ASM__ */

/*
 BI_mul: multiplication hilo is size 2 * n

 IMPORTANT: FOR __ENABLE_DIGICERT_BI_MUL_ASM__ the output buffer hilo must be different from the input buffers a and b
 */
MOC_EXTERN void BI_mul( sbyte4 n, pf_unit* hilo,
            const pf_unit* a, const pf_unit* b,
            sbyte4 x_limit)
{
#ifndef __ENABLE_DIGICERT_BI_MUL_ASM__
    ubyte4  i_limit, j_limit;

#if ((defined(__ASM_CAVIUM__)) && (defined(MACRO_MULTIPLICATION_LOOP)))
    i_limit = j_limit = n;
#else
    i_limit = j_limit = n-1;
#endif
    /* x_limit = 2*n; */

/* currently the buffers are not set up to be used by the Altivec or SSE2 routines or ARM_NEON */
#if defined(__ALTIVEC__) || defined(__SSE2__) || defined(__ARM_NEON__) || defined(__ARM_V6__) || !defined(MACRO_MULTIPLICATION_LOOP)
    {
        pf_unit  r0, r1, r2;
        ubyte4  i, j;
        ubyte4  j_upper;
        sbyte4 x;

        r0 = r1 = r2 = 0;

        for (x = 0; x < x_limit; x++)
        {
            i = ((ubyte4) x <= i_limit) ? (ubyte4) x : i_limit;
            j = x - i;
            j_upper = (((ubyte4) x <= j_limit) ? (ubyte4) x : j_limit);

            while (j <= j_upper)
            {
                /* r2:r1:r0 += a[i] * b[j]; */
                MULT_ADDCX(a, b, i, j, r0, r1, r2);
                i--; j++;
            }

            *hilo++ = r0;
            r0  = r1;
            r1  = r2;
            r2  = 0;
        }
    }
#else
    MACRO_MULTIPLICATION_LOOP(hilo,a,b,i_limit,j_limit,x_limit);
#endif
#else /* __ENABLE_DIGICERT_BI_MUL_ASM__ */

    sbyte4 i, j;

    for (i = 0; i < x_limit; ++i)
        hilo[i] = 0;

    for( i = n; i > 0; --i )
        if( a[i - 1] )
            break;

    for( j = n; j > 0; --j )
        if( b[j - 1] )
            break;

    for( ; j > 0; --j )
    {
        BI_mul_assembly( (ubyte4) i, (pf_unit *) a, hilo + j - 1, b[j - 1] );
    }
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
BI_barrettReduction( sbyte4 k,
                    pf_unit* c,              /* 2 * k */
                    pf_unit* r,              /* k */
                    pf_unit* mulBuffer,      /* 2 k + 2 */
                    const pf_unit* mu,       /* k + 1 */
                    const pf_unit* m)        /* k + 1 */
{
    /*
        q1 = floor(c / b^(k-1)) <=> q1 = (k+1) most significant units of c
        q2 = q1 * mu                (k+1) * (k+1) multiplication
        q3 = floor(q2 / b^(k+1))    q3 =  [(2k+2) - (k+1) = (k+1)] most significant units of q2
        r2 = (q3 * m) mod b^(k+1)   (k+1) * (k+1) mul. take the k+1 least significant units
        r1 = x mod b^(k+1)          r1 = (k+1) least significant units
        r1  -=  r2                  (k+1) - (k+1)

        if(r1 < 0)
            r1 = r1 + b^(k+1)
        while(r1 >= m)
            r1 = r1 - m
        return r1
    */
#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
    pf_unit *pTempBuff = NULL;

    MSTATUS status = DIGI_MALLOC((void **) &pTempBuff, (2*k + 2) * sizeof(pf_unit));
    if (OK != status)
        goto exit;
#endif

    /* q2 = mulBuffer */
    BI_mul( k+1, mulBuffer, c + k - 1, mu, 2 * k + 2);
    /* q3 = mulBuffer + k + 1,  k+1 units */

    c[k+1] = 0;

    /* r2 = mulBuffer (k+1) units */
    /* use the k+1 least significant units of c padded to k+2  = r1 */
    /* subtract r2 from r1, ignore the borrow */

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
    /* ASM requires different output buffer, use tempBuff */

    BI_mul( k+1, pTempBuff, mulBuffer + k + 1, m, 2 * k + 2);
    BI_sub( k+1, c, pTempBuff);
#else
    BI_mul( k+1, mulBuffer, mulBuffer + k + 1, m, k + 1);
    BI_sub( k+1, c, mulBuffer);
#endif

    while ( BI_cmp( k+1, c, m) >= 0)
    {
        BI_sub( k+1, c, m);
    }

    DIGI_MEMCPY( (ubyte*) r, (ubyte*) c, k * sizeof(pf_unit));

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
exit:

    if (NULL != pTempBuff)
        DIGI_FREE((void **) &pTempBuff);

    return status;
#else
    return OK;
#endif
}

/*---------------------------------------------------------------------------*/

/* BI_shiftR: shiftR */
MOC_EXTERN void BI_shiftREx( sbyte4 n, pf_unit* a_s, sbyte4 shift)
{

#ifndef MACRO_SHIFT_RIGHT
    pf_unit  carry = 0;
    sbyte4  i = n;
    pf_unit  u;
    
    if (0 == shift || shift >= (sbyte4) BPU) return; /* invalid arg */

    while (i)
    {
        i--;

        u = a_s[i];
        a_s[i] = ((u >> shift) | carry);

        carry = u << (BPU-shift);
    }
#else
    MACRO_SHIFT_RIGHT(a_s, n);
#endif
}

#endif /* (defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_RSA_SIMPLE__) ) */
