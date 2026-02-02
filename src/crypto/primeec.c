/*
 * primeec.c
 *
 * Prime Elliptic Curve Cryptography
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
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../common/vlong.h"
#endif
#include "../common/random.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#include "../crypto/primefld.h"
#include "../crypto/primeec.h"

#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"

#include "../crypto/ca_mgmt.h"

#if (defined(__ENABLE_DIGICERT_ECC__))

#ifdef __ENABLE_DIGICERT_ECDH_MODES__
#include "../crypto/primeec_mqv.h"
#endif

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__

#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__

#ifdef __ENABLE_DIGICERT_64_BIT__
#include "../crypto/primeec_comb_data_64.h"
#else
#include "../crypto/primeec_comb_data_32.h"
#endif

#endif /* __ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__ */

#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__

#ifdef __ENABLE_DIGICERT_ECC_P192__
static const pf_unit *gpComb192 = NULL;
static RTOS_MUTEX gpEccCombMutex192 = NULL;
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
static const pf_unit *gpComb224 = NULL;
static RTOS_MUTEX gpEccCombMutex224 = NULL;
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
static const pf_unit *gpComb256 = NULL;
static RTOS_MUTEX gpEccCombMutex256 = NULL;
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
static const pf_unit *gpComb384 = NULL;
static RTOS_MUTEX gpEccCombMutex384 = NULL;
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
static const pf_unit *gpComb521 = NULL;
static RTOS_MUTEX gpEccCombMutex521 = NULL;
#endif

#endif /* __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__ */

#endif /* __DISABLE_DIGICERT_SIGNED_ODD_COMB__ */

typedef struct ComputeHelper
{
    ubyte4      size;
    /* affine Pt*/
    ConstPFEPtr x2;
    ConstPFEPtr y2;

    /* Jacobi Pt */
    PFEPtr X1;
    PFEPtr Y1;
    PFEPtr Z1;      /*3*/
    /*  Temp */
    PFEPtr T1;
    PFEPtr T2;
    PFEPtr T3;
    PFEPtr T4;      /*4*/
    /* hilo */
    pf_unit* hilo;   /*2*/

    /* storage */
    pf_unit storage[1];
} ComputeHelper;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#define DECLARE_PRIME_H_VALUE 1
#define DECLARE_PRIME_EC(a) const struct PrimeEllipticCurve PrimeECP##a =   \
                            {   &PrimeFieldP##a,                            \
                                (PFEPtr) Px_##a,                            \
                                (PFEPtr) Py_##a,                            \
                                (PFEPtr) Pb_##a,                            \
                                (PFEPtr) Pn_##a,                            \
                                (PFEPtr) Pmu_##a,                           \
                                DECLARE_PRIME_H_VALUE                       \
                            };                                              \
                            MOC_EXTERN_DATA_DEF const PEllipticCurvePtr EC_P##a = &PrimeECP##a;
#else
#define DECLARE_PRIME_EC(a) const struct PrimeEllipticCurve PrimeECP##a =   \
                            {   &PrimeFieldP##a,                            \
                                (PFEPtr) Px_##a,                            \
                                (PFEPtr) Py_##a,                            \
                                (PFEPtr) Pb_##a,                            \
                                (PFEPtr) Pn_##a,                            \
                                (PFEPtr) Pmu_##a,                           \
                            };                                              \
                            MOC_EXTERN_DATA_DEF const PEllipticCurvePtr EC_P##a = &PrimeECP##a;
#endif

#ifdef __ENABLE_DIGICERT_ECC_P192__
/************************************************* P-192 */

#ifdef __ENABLE_DIGICERT_64_BIT__

static const pf_unit Px_192[] =
{    0xf4ff0afd82ff1012ULL,
     0x7cbf20eb43a18800ULL,
     0x188da80eb03090f6ULL
};

static const pf_unit Py_192[] =
{   0x73f977a11e794811ULL,
    0x631011ed6b24cdd5ULL,
    0x07192b95ffc8da78ULL
};

/* order */
static const pf_unit Pn_192[] =
{
    0x146bc9b1b4d22831ULL,
    0xffffffff99def836ULL,
    0xffffffffffffffffULL,
    0x0ULL /* must be pPF->n + 1 long for barrett's reduction */
};

/* mu = barrett's precomputed value */
static const pf_unit Pmu_192[] = /* floor( (2 ^ 64 ) ^ (2 * pPF->n) / Pn_192) */
{
    0xeb94364e4b2dd7cfULL,
    0x00000000662107c9ULL,
    0x0000000000000000ULL,
    0x1ULL
};

/* b coefficient of the curve */
static const pf_unit Pb_192[] =
{
    0xfeb8deecc146b9b1ULL,
    0x0fa7e9ab72243049ULL,
    0x64210519e59c80e7ULL
};


#else
static const pf_unit Px_192[] =
{   0x82ff1012, 0xf4ff0afd, 0x43a18800, 0x7cbf20eb, 0xb03090f6,
    0x188da80e
};

static const pf_unit Py_192[] =
{   0x1e794811, 0x73f977a1, 0x6b24cdd5, 0x631011ed, 0xffc8da78,
    0x07192b95
};

/* order */
static const pf_unit Pn_192[] =
{
    0xb4d22831, 0x146bc9b1, 0x99def836, 0xffffffff, 0xffffffff,
    0xffffffff, 0x0 /* must be pPF->n + 1 long for barrett's reduction */
};

/* mu = barrett's precomputed value */
static const pf_unit Pmu_192[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_192) */
{
    0x4b2dd7cf, 0xeb94364e, 0x662107c9, 0x00000000, 0x00000000,
    0x00000000, 0x1
};

/* b coefficient of the curve */
static const pf_unit Pb_192[] =
{
    /*1*/0xc146b9b1, /*2*/0xfeb8deec, /*3*/0x72243049, /*4*/0x0fa7e9ab, /*5*/0xe59c80e7,
    /*6*/0x64210519
};

#endif

DECLARE_PRIME_EC(192)

#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__

/**************************************************************** P-224 */

#ifdef __ENABLE_DIGICERT_64_BIT__

static const pf_unit Px_224[] =
{
    0x343280d6115c1d21ULL,
    0x4a03c1d356c21122ULL,
    0x6bb4bf7f321390b9ULL,
    0x00000000b70e0cbdULL
};

static const pf_unit Py_224[] =
{
    0x44d5819985007e34ULL,
    0xcd4375a05a074764ULL,
    0xb5f723fb4c22dfe6ULL,
    0x00000000bd376388ULL
};

static const pf_unit Pn_224[] =
{
   0x13dd29455c5c2a3dULL,
   0xffff16a2e0b8f03eULL,
   0xffffffffffffffffULL,
   0x00000000ffffffffULL,
   0x0ULL /* must be pPF->n + 1 long for barrett's reduction */
};

/*
00000001 00000000 00000000 00000000
0000E95D 1F470FC1 EC22D6BA A3A3D5C3
*/
static const pf_unit Pmu_224[] = /* floor( (2 ^ 64 ) ^ (2 * pPF->n) / Pn_224) */
{
    0xd4baa4cf1822bc47ULL,
    0xec22d6baa3a3d5c3ULL,
    0x0000e95d1f470fc1ULL,
    0x0000000000000000ULL,
    0x0000000100000000ULL
};

static const pf_unit Pb_224[] =
{
    0x270b39432355ffb4ULL,
    0x5044b0b7d7bfd8baULL,
    0x0c04b3abf5413256ULL,
    0x00000000b4050a85ULL
};

#else

static const pf_unit Px_224[] =
{
    0x115c1d21, 0x343280d6, 0x56c21122, 0x4a03c1d3, 0x321390b9,
    0x6bb4bf7f, 0xb70e0cbd
};

static const pf_unit Py_224[] =
{
    0x85007e34, 0x44d58199, 0x5a074764, 0xcd4375a0, 0x4c22dfe6,
    0xb5f723fb, 0xbd376388
};

static const pf_unit Pn_224[] =
{
    0x5c5c2a3d, 0x13dd2945, 0xe0b8f03e, 0xffff16a2,
    0xffffffff, 0xffffffff, 0xffffffff, 0x0 /* must be pPF->n + 1 long for barrett's reduction */
};

/*
00000001 00000000 00000000 00000000
0000E95D 1F470FC1 EC22D6BA A3A3D5C3
*/
static const pf_unit Pmu_224[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_224) */
{
    0xa3a3d5c3, 0xec22d6ba, 0x1f470fc1, 0x0000e95d,
    0x00000000, 0x00000000, 0x00000000, 0x1
};

static const pf_unit Pb_224[] =
{
    0x2355ffb4, 0x270b3943, 0xd7bfd8ba, 0x5044b0b7,
    0xf5413256, 0x0c04b3ab, 0xb4050a85
};

#endif

DECLARE_PRIME_EC(224)

#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
/**************************************************************** P-256 */

#ifdef __ENABLE_DIGICERT_64_BIT__

static const pf_unit Px_256[] =
{
    0xf4a13945d898c296ULL,
    0x77037d812deb33a0ULL,
    0xf8bce6e563a440f2ULL,
    0x6b17d1f2e12c4247ULL
};

static const pf_unit Py_256[] =
{
    0xcbb6406837bf51f5ULL,
    0x2bce33576b315eceULL,
    0x8ee7eb4a7c0f9e16ULL,
    0x4fe342e2fe1a7f9bULL
};

static const pf_unit Pn_256[] =
{
    0xf3b9cac2fc632551ULL,
    0xbce6faada7179e84ULL,
    0xffffffffffffffffULL,
    0xffffffff00000000ULL,
    0x0ULL /* must be pPF->n + 1 long for barrett's reduction */
};

/*
00000001 00000000 FFFFFFFF FFFFFFFE
FFFFFFFF 43190552 DF1A6C21 012FFD85 EEDF9BFE
*/
static const pf_unit Pmu_256[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_256) */
{
    0x012ffd85eedf9bfeULL,
    0x43190552df1a6c21ULL,
    0xfffffffeffffffffULL,
    0x00000000ffffffffULL,
    0x1ULL
};

static const pf_unit Pb_256[] =
{
    0x3bce3c3e27d2604bULL,
    0x651d06b0cc53b0f6ULL,
    0xb3ebbd55769886bcULL,
    0x5ac635d8aa3a93e7ULL
};

#else

static const pf_unit Px_256[] =
{
    0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81, 0x63a440f2,
    0xf8bce6e5, 0xe12c4247, 0x6b17d1f2
};

static const pf_unit Py_256[] =
{
    0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357, 0x7c0f9e16,
    0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2
};

static const pf_unit Pn_256[] =
{
    0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff,
    0xffffffff, 0x00000000, 0xffffffff, 0x0 /* must be pPF->n + 1 long for barrett's reduction */
};

/*
00000001 00000000 FFFFFFFF FFFFFFFE
FFFFFFFF 43190552 DF1A6C21 012FFD85 EEDF9BFE
*/
static const pf_unit Pmu_256[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_256) */
{
    0xeedf9bfe, 0x012ffd85, 0xdf1a6c21, 0x43190552, 0xffffffff,
    0xfffffffe, 0xffffffff, 0x00000000, 0x1
};

static const pf_unit Pb_256[] =
{
    0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0, 0x769886bc,
    0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8
};

#endif

DECLARE_PRIME_EC(256)
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__

#ifdef __ENABLE_DIGICERT_64_BIT__

/**************************************************************** P-384 */
static const pf_unit Px_384[] =
{
   0x3a545e3872760ab7ULL,
   0x5502f25dbf55296cULL,
   0x59f741e082542a38ULL,
   0x6e1d3b628ba79b98ULL,
   0x8eb1c71ef320ad74ULL,
   0xaa87ca22be8b0537ULL
};

static const pf_unit Py_384[] =
{
    0x7a431d7c90ea0e5fULL,
    0x0a60b1ce1d7e819dULL,
    0xe9da3113b5f0b8c0ULL,
    0xf8f41dbd289a147cULL,
    0x5d9e98bf9292dc29ULL,
    0x3617de4a96262c6fULL
};

/* FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
   C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973*/

static const pf_unit Pn_384[] =
{
    0xecec196accc52973ULL,
    0x581a0db248b0a77aULL,
    0xc7634d81f4372ddfULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x0ULL  /* must be pPF->n + 1 long for barrett's reduction */
};

/*
00000001 00000000 00000000
00000000 00000000 00000000 00000000 389CB27E
0BC8D220 A7E5F24D B74F5885 1313E695 333AD68D
*/

static const pf_unit Pmu_384[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_384) */
{
    0x1313e695333ad68dULL,
    0xa7e5f24db74f5885ULL,
    0x389cb27e0bc8d220ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x1
};

static const pf_unit Pb_384[] =
{
    0x2a85c8edd3ec2aefULL,
    0xc656398d8a2ed19dULL,
    0x0314088f5013875aULL,
    0x181d9c6efe814112ULL,
    0x988e056be3f82d19ULL,
    0xb3312fa7e23ee7e4ULL
};

#else

static const pf_unit Px_384[] =
{
    0x72760ab7, 0x3a545e38, 0xbf55296c, 0x5502f25d, 0x82542a38,
    0x59f741e0, 0x8ba79b98, 0x6e1d3b62, 0xf320ad74, 0x8eb1c71e,
    0xbe8b0537, 0xaa87ca22
};

static const pf_unit Py_384[] =
{
    0x90ea0e5f, 0x7a431d7c, 0x1d7e819d, 0x0a60b1ce, 0xb5f0b8c0,
    0xe9da3113, 0x289a147c, 0xf8f41dbd, 0x9292dc29, 0x5d9e98bf,
    0x96262c6f, 0x3617de4a
};

static const pf_unit Pn_384[] =
{
    0xccc52973, 0xecec196a, 0x48b0a77a, 0x581a0db2, 0xf4372ddf,
    0xc7634d81, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0x0  /* must be pPF->n + 1 long for barrett's reduction */
};

/*
00000001 00000000 00000000
00000000 00000000 00000000 00000000 389CB27E
0BC8D220 A7E5F24D B74F5885 1313E695 333AD68D
*/

static const pf_unit Pmu_384[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_384) */
{
    0x333ad68d, 0x1313e695, 0xb74f5885, 0xa7e5f24d, 0x0bc8d220,
    0x389cb27e, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x1
};

static const pf_unit Pb_384[] =
{
    0xd3ec2aef, 0x2a85c8ed, 0x8a2ed19d, 0xc656398d, 0x5013875a,
    0x0314088f, 0xfe814112, 0x181d9c6e, 0xe3f82d19, 0x988e056b,
    0xe23ee7e4, 0xb3312fa7
};

#endif

DECLARE_PRIME_EC(384)

#endif


#ifndef __DISABLE_DIGICERT_ECC_P521__
/**************************************************************** P-521 */

#ifdef __ENABLE_DIGICERT_64_BIT__

static const pf_unit Px_521[] =
{
    0xf97e7e31c2e5bd66ULL,
    0x3348b3c1856a429bULL,
    0xfe1dc127a2ffa8deULL,
    0xa14b5e77efe75928ULL,
    0xf828af606b4d3dbaULL,
    0x9c648139053fb521ULL,
    0x9e3ecb662395b442ULL,
    0x858e06b70404e9cdULL,
    0x00000000000000c6ULL
};

static const pf_unit Py_521[] =
{
    0x88be94769fd16650ULL,
    0x353c7086a272c240ULL,
    0xc550b9013fad0761ULL,
    0x97ee72995ef42640ULL,
    0x17afbd17273e662cULL,
    0x98f54449579b4468ULL,
    0x5c8a5fb42c7d1bd9ULL,
    0x39296a789a3bc004ULL,
    0x0000000000000118ULL
};

/*1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA
51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409 */

static const pf_unit Pn_521[] =
{
    0xbb6fb71e91386409ULL,
    0x3bb5c9b8899c47aeULL,
    0x7fcc0148f709a5d0ULL,
    0x51868783bf2f966bULL,
    0xfffffffffffffffaULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x00000000000001ffULL,
    0x0ULL /* must be pPF->n + 1 long for barrett's reduction */
};

static const pf_unit Pmu_521[] = /* floor( (2 ^ 64 ) ^ (2 * pPF->n) / Pn_521) */
{
    0xcd2dad1d7f46221cULL,
    0xe6fdc408f501c8d1ULL,
    0xee14512412385bb1ULL,
    0x968bf1128d91dd98ULL,
    0x1a65200cffadc23dULL,
    0x00016b9e5e1f1034ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0080000000000000ULL
};

static const pf_unit Pb_521[] =
{
    0xef451fd46b503f00ULL,
    0x3573df883d2c34f1ULL,
    0x1652c0bd3bb1bf07ULL,
    0x56193951ec7e937bULL,
    0xb8b489918ef109e1ULL,
    0xa2da725b99b315f3ULL,
    0x929a21a0b68540eeULL,
    0x953eb9618e1c9a1fULL,
    0x051ULL
};

#else

static const pf_unit Px_521[] =
{
    0xc2e5bd66, 0xf97e7e31, 0x856a429b, 0x3348b3c1, 0xa2ffa8de,
    0xfe1dc127, 0xefe75928, 0xa14b5e77, 0x6b4d3dba, 0xf828af60,
    0x053fb521, 0x9c648139, 0x2395b442, 0x9e3ecb66, 0x0404e9cd,
    0x858e06b7, 0xc6
};

static const pf_unit Py_521[] =
{
    0x9fd16650, 0x88be9476, 0xa272c240, 0x353c7086, 0x3fad0761,
    0xc550b901, 0x5ef42640, 0x97ee7299, 0x273e662c, 0x17afbd17,
    0x579b4468, 0x98f54449, 0x2c7d1bd9, 0x5c8a5fb4, 0x9a3bc004,
    0x39296a78, 0x118
};

static const pf_unit Pn_521[] =
{
    0x91386409, 0xbb6fb71e, 0x899c47ae, 0x3bb5c9b8, 0xf709a5d0,
    0x7fcc0148, 0xbf2f966b, 0x51868783, 0xfffffffa, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0x000001ff, 0x0 /* must be pPF->n + 1 long for barrett's reduction */
};


/*
00800000 00000000 00000000
00000000 00000000 00000000 00000000 00000000
00016B9E 5E1F1034 1A65200C FFADC23D 968BF112
8D91DD98 EE145124 12385BB1 E6FDC408 F501C8D1
*/
static const pf_unit Pmu_521[] = /* floor( (2 ^ 32 ) ^ (2 * pPF->n) / Pn_521) */
{
    0xf501c8d1, 0xe6fdc408, 0x12385bb1, 0xee145124, 0x8d91dd98,
    0x968bf112, 0xffadc23d, 0x1a65200c, 0x5e1f1034, 0x00016b9e,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00800000
};

static const pf_unit Pb_521[] =
{
    0x6b503f00, 0xef451fd4, 0x3d2c34f1, 0x3573df88, 0x3bb1bf07,
    0x1652c0bd, 0xec7e937b, 0x56193951, 0x8ef109e1, 0xb8b48991,
    0x99b315f3, 0xa2da725b, 0xb68540ee, 0x929a21a0, 0x8e1c9a1f,
    0x953eb961, 0x051
};

#endif

#ifdef __ENABLE_COFACTOR_MUL_TEST__

/* for testing purposes only we set the cofactor of P521 to an incorrect value greater than 1 */
#ifndef MOC_COFACTOR
#error Must define MOC_COFACTOR if __ENABLE_COFACTOR_MUL_TEST__ is defined
#endif

#define DECLARE_PRIME_H_VALUE MOC_COFACTOR;

#endif /* __ENABLE_COFACTOR_MUL_TEST__ */

DECLARE_PRIME_EC(521)

#ifdef __ENABLE_COFACTOR_MUL_TEST__
#undef DECLARE_PRIME_H_VALUE
#define DECLARE_PRIME_H_VALUE 1
#endif

#endif /* disable P521 */

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


#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int ecdsa_fail = 0;
FIPS_TESTLOG_IMPORT;
#endif

#ifdef __ENABLE_DIGICERT_SOFT_DIVIDE__
/*---------------------------------------------------------------------------*/

/* routine for CPU that does not support divide instructions -- so that
   we can link with no libraries */

ubyte4 EC_unsignedDivide(ubyte4 dividend, ubyte4 divisor)
{
    ubyte4 tmpDivisor;
    ubyte4 tmpQuotient;
    ubyte4 quotient, remainder;

    quotient = 0;
    remainder = dividend;
    tmpDivisor = divisor;
    tmpQuotient = 1;

    while (remainder > tmpDivisor && (0 == (tmpDivisor & 0x80000000) ))
    {
        tmpDivisor <<= 1;
        tmpQuotient <<= 1;
    }

    while (remainder >= divisor)
    {
        while (remainder < tmpDivisor)
        {
            tmpDivisor >>= 1;
            tmpQuotient >>= 1;
        }

        remainder -= tmpDivisor;

        quotient += tmpQuotient;
    }

    return quotient;

} /* EC_unsignedDivide */

#define SOFT_DIV(x,y)  EC_unsignedDivide( (x), (y))

#else

#define SOFT_DIV(x,y)   ( (x) / (y))

#endif

/*---------------------------------------------------------------------------*/

static MSTATUS EC_newComputeHelper( ubyte4 elemSize, ComputeHelper** ppH)
{
    ComputeHelper*  pNew;
    pf_unit*        storage;
    ubyte4          size;

    if (!ppH)
        return ERR_NULL_POINTER;

    size = sizeof( ComputeHelper) - sizeof(pf_unit) + elemSize * 9 * sizeof(pf_unit);
    pNew = (ComputeHelper*) MALLOC(size);
    if (!pNew)
    {
        *ppH = 0;
        return ERR_MEM_ALLOC_FAIL;
    }

    pNew->size = size;
    storage = pNew->storage;

    pNew->hilo = storage;
    storage += 2 * elemSize;

    pNew->X1 = (PFEPtr) storage;
    storage += elemSize;
    pNew->Y1 = (PFEPtr) storage;
    storage += elemSize;
    pNew->Z1 = (PFEPtr) storage;
    storage += elemSize;
    pNew->T1 = (PFEPtr) storage;
    storage += elemSize;
    pNew->T2 = (PFEPtr) storage;
    storage += elemSize;
    pNew->T3 = (PFEPtr) storage;
    storage += elemSize;
    pNew->T4 = (PFEPtr) storage;

    pNew->x2 = pNew->y2 = 0;

    *ppH = pNew;

    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS EC_deleteComputeHelper( PrimeFieldPtr pField,
                                      ComputeHelper** ppH)
{
    if ( !pField || !ppH || !(*ppH))
        return ERR_NULL_POINTER;

    /* zeroize before freeing */
    DIGI_MEMSET( (ubyte*) *ppH, 0, (**ppH).size);
    FREE( *ppH);
    return OK;
}


/*---------------------------------------------------------------------------*/

static ubyte4 EC_GetUnitBitLength(pf_unit u)
{
    ubyte4 bits;
#ifdef __ENABLE_DIGICERT_64_BIT__
    bits = DIGI_BITLENGTH( (ubyte4) HI_HUNIT(u));
    if (0 == bits)
    {
        bits = DIGI_BITLENGTH( (ubyte4) LO_HUNIT(u));
    }
    else
    {
        bits += 32;
    }
#else
    bits = DIGI_BITLENGTH( u);
#endif
    return bits;
}


/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

static MSTATUS EC_generateRandomNumber( PEllipticCurvePtr pEC, PFEPtr k,
                                    RNGFun rngFun, void* rngArg)
{
    MSTATUS status;
    ubyte4 bits;
    pf_unit mask;
    PFEPtr pTest = NULL;
    PFEPtr pOne = NULL;

    /* Follow NIST.SP.800-56Ar3 Sec 5.6.1.2.2.
     s is implicitly the maximum allowed security strength per curve
     We start with step 3 but first prepare n - 1 */

    status = PRIMEFIELD_newElement(pEC->pPF, &pTest);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pOne);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_copyElement(pEC->pPF, pTest, pEC->n);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_setToUnsigned(pEC->pPF, pOne, 1);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_subtract(pEC->pPF, pTest, pOne);
    if (OK != status)
        goto exit;

    bits = EC_GetUnitBitLength( pEC->n->units[pEC->pPF->n-1]);
    mask = FULL_MASK >> (BPU - bits);

    do   /* Step 4 and 5 */
    {
        /* generate a random k of n bits */
        if ( OK > (status = (MSTATUS) rngFun(rngArg,
                                             pEC->pPF->n * sizeof(pf_unit),
                                             (ubyte*) k->units)))
        {
            goto exit;
        }
        k->units[pEC->pPF->n-1] &= mask;
    }
    while ( PRIMEFIELD_cmp( pEC->pPF, k, pTest) >= 0);  /* step 6, repeat if k >= n - 1 (equiv to k > n - 2) */

    status = PRIMEFIELD_add(pEC->pPF, k, pOne); /* step 7 */

    /* step 8, public key computation, is done by the calling method */

exit:

    PRIMEFIELD_deleteElement(pEC->pPF, &pTest); /* ok to ignore return codes here */
    PRIMEFIELD_deleteElement(pEC->pPF, &pOne);

    return status;
}
#endif /* !defined(__ENABLE_MSVB_SMALL_CODE_SIZE__) */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS EC_modOrder( PEllipticCurvePtr pEC, PFEPtr x)
{
    /* this function should be declared static but is used in some
    other ECC file */
    /* n is close to p in pEC so subtracting n from 1 < x < p
    should do the trick fast ( x = 0n + r or x = 1n + r) */

    sbyte4 i = 0;
    MSTATUS status;

    if (NULL == pEC || NULL == x)
        return ERR_NULL_POINTER;

    while ( PRIMEFIELD_cmp( pEC->pPF, x, pEC->n) >= 0)
    {
        ++i;
        if ( OK > ( status = PRIMEFIELD_subtract( pEC->pPF, x, pEC->n)))
            return status;
    }
    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS EC_setJacobiPt( PrimeFieldPtr pField, PFEPtr pX, PFEPtr pY,
                           PFEPtr pZ, ConstPFEPtr px, ConstPFEPtr py)
{
    MSTATUS status;

    if ( OK > ( status = PRIMEFIELD_copyElement( pField, pX, px)))
        return status;
    if ( OK > ( status = PRIMEFIELD_copyElement( pField, pY, py)))
        return status;
    return PRIMEFIELD_setToUnsigned( pField, pZ, 1);
}



/*---------------------------------------------------------------------------*/

static MSTATUS EC_setJacobiPtToInfinity( PrimeFieldPtr pField, PFEPtr pX, PFEPtr pY,
                           PFEPtr pZ)
{
    MSTATUS status;

    if ( OK > ( status =PRIMEFIELD_setToUnsigned( pField, pX, 1)))
        return status;
    if ( OK > ( status = PRIMEFIELD_setToUnsigned( pField, pY, 1)))
        return status;
    return PRIMEFIELD_setToUnsigned( pField, pZ, 0);
}

/* operations on points */
/* for the curve y2 = x3 - 3x + b */
/*---------------------------------------------------------------------------*/

/* compute the double of X1,Y1,Z1 in pB */
static MSTATUS EC_doubleJacobiPoint(PrimeFieldPtr pField, ComputeHelper* pB)
{
    MSTATUS status;

    /* if 0 -> return 0 */
    if ( 0 == PRIMEFIELD_cmpToUnsigned(pField, pB->Z1, 0))
        return OK;

    if ( OK > (status = PRIMEFIELD_squareAux( pField, pB->T1, pB->Y1,
                                                pB->hilo)))
    {
        goto exit;
    }

    if ( OK  > (status = PRIMEFIELD_add( pField, pB->T1, pB->T1)))
        goto exit;

    if ( OK > (status = PRIMEFIELD_squareAux( pField, pB->T2, pB->T1,
                                                pB->hilo)))
    {
        goto exit;
    }

    if ( OK  > (status = PRIMEFIELD_add( pField, pB->T1, pB->T1)))
        goto exit;

    if ( OK  > (status = PRIMEFIELD_add( pField, pB->T2, pB->T2)))
        goto exit;

    if ( OK >(status = PRIMEFIELD_multiplyAux( pField, pB->T4, pB->X1, pB->T1,
                                                pB->hilo)))
    {
        goto exit;
    }
    /* a = t4 */

    if ( OK >(status = PRIMEFIELD_squareAux( pField, pB->T1, pB->Z1,
                                                pB->hilo)))
    {
        goto exit;
    }

    if ( OK > ( status = PRIMEFIELD_copyElement( pField, pB->T3, pB->X1)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->T3, pB->T1)))
        goto exit;

    if ( OK > ( status = PRIMEFIELD_add( pField, pB->T1, pB->X1)))
        goto exit;

    if ( OK >(status = PRIMEFIELD_multiplyAux( pField, pB->T1, pB->T1, pB->T3,
                                                pB->hilo)))
    {
        goto exit;
    }

    if ( OK > ( status = PRIMEFIELD_copyElement( pField, pB->T3, pB->T1)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_add( pField, pB->T3, pB->T1)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_add( pField, pB->T3, pB->T1)))
        goto exit;
    /* c = x3 */

    if ( OK > ( status = PRIMEFIELD_copyElement( pField, pB->T1, pB->Y1)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_add( pField, pB->T1, pB->Y1)))
        goto exit;

    if ( OK >(status = PRIMEFIELD_multiplyAux( pField, pB->Z1, pB->T1, pB->Z1,
                                                pB->hilo)))
    {
        goto exit;
    }

    if ( OK >(status = PRIMEFIELD_squareAux( pField, pB->X1, pB->T3,
                                                pB->hilo)))
    {
        goto exit;
    }


    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->X1, pB->T4)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->X1, pB->T4)))
        goto exit;
    /* d = x3 */

    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->T4, pB->X1)))
        goto exit;

    if ( OK >(status = PRIMEFIELD_multiplyAux( pField, pB->Y1, pB->T3, pB->T4,
                                                pB->hilo)))
    {
        goto exit;
    }

    if ( OK >(status = PRIMEFIELD_subtract( pField, pB->Y1, pB->T2)))
        goto exit;

exit:

    return status;
}


/*---------------------------------------------------------------------------*/

/* in pB add the affine point x2,y2 to X1,Y1,Z1 */

static MSTATUS EC_addAffineToJacobiPt(PrimeFieldPtr pField, ComputeHelper* pB)
{
    MSTATUS status = OK;

    /* note pB's affine point can't be point at infinity by defn */

    /* if pP == O -> return pQ converted to JacobiPt */
    if ( 0 == PRIMEFIELD_cmpToUnsigned(pField, pB->Z1, 0))
    {
        return EC_setJacobiPt( pField, pB->X1, pB->Y1, pB->Z1, pB->x2, pB->y2);
    }

    /* T1 = Z1 * Z1 */
    if ( OK > ( status = PRIMEFIELD_squareAux( pField, pB->T1, pB->Z1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T2 = T1 * Z1 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T2, pB->T1, pB->Z1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T1 = T1 * x2 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T1, pB->T1, pB->x2,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T2 = T2 * y2 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T2, pB->T2, pB->y2,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T1 = T1 - X1 */
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->T1, pB->X1)))
        goto exit;

    /* T2 = T2 - Y1 */
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->T2, pB->Y1)))
        goto exit;

    if ( 0 == PRIMEFIELD_cmpToUnsigned( pField, pB->T1, 0))
    {
        if ( 0 == PRIMEFIELD_cmpToUnsigned( pField, pB->T2, 0))
        {
            if (OK > ( status = EC_setJacobiPt( pField, pB->X1, pB->Y1, pB->Z1, pB->x2, pB->y2)))
                return status;
            status = EC_doubleJacobiPoint( pField, pB);
        }
        else
        {
            status = EC_setJacobiPtToInfinity( pField, pB->X1, pB->Y1, pB->Z1);
        }
        return status;
    }

    /* Z3 = Z1 * T1 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->Z1, pB->Z1, pB->T1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T3 = T1 * T1 */
    if ( OK > ( status = PRIMEFIELD_squareAux( pField, pB->T3, pB->T1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T4 = T3 * T1 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T4, pB->T3, pB->T1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* T3 = T3 * X */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T3, pB->T3, pB->X1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* X1 = T2 * T2 */
    if ( OK > ( status = PRIMEFIELD_squareAux( pField, pB->X1, pB->T2,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* X1 = X1 -  2 * T3 */
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->X1, pB->T3)))
        goto exit;

    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->X1, pB->T3)))
        goto exit;

    /* X1 = X1 - T4 */
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->X1, pB->T4)))
        goto exit;

    /* T3 = T3 - X1 */
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->T3, pB->X1)))
        goto exit;

    /* T4 = T4 * Y1 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T4, pB->T4, pB->Y1,
                                                pB->hilo)))
    {
        goto exit;
    }

    /* Y1 = T3 * T2 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->Y1, pB->T3, pB->T2,
                                                pB->hilo)))
    {
        goto exit;
    }


    /* Y1 = Y1 - T4 */
    if ( OK > ( status = PRIMEFIELD_subtract( pField, pB->Y1, pB->T4)))
        goto exit;

exit:

    return status;
}


#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

/*---------------------------------------------------------------------------*/

/* add Jacobi Pt pA to Jacobi Pt pR */

static MSTATUS EC_addJacobiPoint(PrimeFieldPtr pField, ComputeHelper* pR,
                                 ComputeHelper* pA)
{
    MSTATUS status = OK;

    /* if A = O -> return R + A = R, do nothing */
    if ( 0 == PRIMEFIELD_cmpToUnsigned(pField, pA->Z1, 0))
    {
        goto exit;
    }

    /* if R = O return R + A = A so just copy A over to R  */
    if ( 0 == PRIMEFIELD_cmpToUnsigned(pField, pR->Z1, 0) )
    {
        PRIMEFIELD_copyElement(pField, pR->X1, pA->X1); /* ok to ignore return codes */
        PRIMEFIELD_copyElement(pField, pR->Y1, pA->Y1);
        PRIMEFIELD_copyElement(pField, pR->Z1, pA->Z1);
        goto exit;
    }

    /* pR->T1 = pR->Z1 * pR->Z1; square */
    if (OK > ( status = PRIMEFIELD_squareAux(pField, pR->T1, pR->Z1, pR->hilo)))
    {
        goto exit;
    }

    /* pR->T2 = pA->Z1 * pA->Z1; square */
    if (OK > ( status = PRIMEFIELD_squareAux(pField, pR->T2, pA->Z1, pR->hilo)))
    {
        goto exit;
    }

    /* pR->T3 = pR->X1 * pR->T2; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->T3, pR->X1, pR->T2,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->T4 = pA->X1 * pR->T1; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->T4, pA->X1, pR->T1,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pA->T1 = pA->Z1 * pR->T2; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pA->T1, pA->Z1, pR->T2,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pA->T2 = pR->Y1 * pA->T1; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pA->T2, pR->Y1, pA->T1,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pA->T1 = pR->Z1 * pR->T1; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pA->T1, pR->Z1, pR->T1,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->T1 = pA->Y1 * pA->T1; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->T1, pA->Y1, pA->T1,
                                               pR->hilo)))
    {
        goto exit;
    }

    /*
    if (pR->T3 == pR->T4)
    {
        if (pA->T2 != pR->T1)
        {
            printf("Infinity\n");
            return;
        }
        else
        {
            printf("Double\n");
            return;
        }
    }
    */
    if (PRIMEFIELD_match(pField, pR->T3, pR->T4))
    {
        if (!PRIMEFIELD_match( pField, pA->T2, pR->T1 ))
        {
            return EC_setJacobiPtToInfinity(pField, pR->X1, pR->Y1, pR->Z1);
        }
        return EC_doubleJacobiPoint(pField, pR);
    }

    /* pR->T4 -= pR->T3;  */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pR->T4, pR->T3)))
    {
        goto exit;
    }

    /* pR->T2 = pR->T4 * pR->T4; square */
    if (OK > ( status = PRIMEFIELD_squareAux(pField, pR->T2, pR->T4, pR->hilo)))
    {
        goto exit;
    }

    /* pA->T1 = pR->T4 * pR->T2; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pA->T1, pR->T4, pR->T2,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->T1 -= pA->T2; */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pR->T1, pA->T2)))
    {
        goto exit;
    }

    /* pA->T3 = pR->T3 * pR->T2; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pA->T3, pR->T3, pR->T2,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->X1 = pR->T1 * pR->T1;  square */
    if (OK > ( status = PRIMEFIELD_squareAux(pField, pR->X1, pR->T1, pR->hilo)))
    {
        goto exit;
    }


    /* pR->X1 -= pA->T1; */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pR->X1, pA->T1)))
    {
        goto exit;
    }

    /* pR->X1 -= pA->T3; */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pR->X1, pA->T3)))
    {
        goto exit;
    }

    /* pR->X1 -= pA->T3; */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pR->X1, pA->T3)))
    {
        goto exit;
    }

    /* pA->T3 -= pR->X1; */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pA->T3, pR->X1)))
    {
        goto exit;
    }

    /* pR->T2 = pA->T2 * pA->T1; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->T2, pA->T2, pA->T1,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->Y1 = pR->T1 * pA->T3; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->Y1, pR->T1, pA->T3,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->Y1 -= pR->T2; */
    if (OK > ( status = PRIMEFIELD_subtract(pField, pR->Y1, pR->T2)))
    {
        goto exit;
    }


    /* pR->T1 = pA->Z1 * pR->T4; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->T1, pA->Z1, pR->T4,
                                               pR->hilo)))
    {
        goto exit;
    }

    /* pR->Z1 = pR->Z1 * pR->T1; */
    if (OK > ( status = PRIMEFIELD_multiplyAux(pField, pR->Z1, pR->Z1, pR->T1,
                                               pR->hilo)))
    {
        goto exit;
    }

exit:

    return status;
}

#endif /* if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__)) */

/*---------------------------------------------------------------------------*/

/* in convert X1, Y1, Z1 to affine X1', Y1' */

static MSTATUS EC_convertToAffine(PrimeFieldPtr pField, ComputeHelper* pB)
{
    MSTATUS status;

    /* verify Z1 != 0 */
    if ( 0 == PRIMEFIELD_cmpToUnsigned( pField, pB->Z1, 0))
    {
        return ERR_EC_INFINITE_RESULT;
    }

    /* T1 = 1/Z1 */
    if ( OK > ( status = PRIMEFIELD_inverse( pField, pB->T1, pB->Z1)))
        return status;

    /* T2 = T1 * T1 ( = 1/Z1 * 1/Z1 ) */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T2, pB->T1, pB->T1, pB->hilo)))
        return status;

    /* X1 = X1 * T2 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->X1, pB->X1, pB->T2, pB->hilo)))
        return status;

    /* T3 = T1 * T2 */
    if ( OK > ( status = PRIMEFIELD_multiplyAux( pField, pB->T3, pB->T1, pB->T2, pB->hilo)))
        return status;

    /* Y1 = Y1 * T3 */
    return PRIMEFIELD_multiplyAux( pField, pB->Y1, pB->Y1, pB->T3, pB->hilo);
}


/*---------------------------------------------------------------------------*/

static MSTATUS
EC_multiplyPointJacobiLRBSimple(PrimeFieldPtr pField, ConstPFEPtr k,
                                ConstPFEPtr pX, ConstPFEPtr pY,
                                ComputeHelper* pBlock)
{
    MSTATUS status;
    sbyte4 i, j;

    pBlock->x2 = pX;
    pBlock->y2 = pY;

    /* Q = infinity or 0 */
    if (OK > ( status = EC_setJacobiPtToInfinity( pField, pBlock->X1, pBlock->Y1, pBlock->Z1)))
    {
        goto exit;
    }

    /* left to right binary method for point multiplication */
    for ( i = pField->n - 1; i >= 0; --i)
    {
        pf_unit val = k->units[i];

        for (j = sizeof(pf_unit) * 8 - 1; j >= 0; --j)
        {
            if  (OK > ( status = EC_doubleJacobiPoint( pField, pBlock)))
                goto exit;

            if ( (val >> j) & 1)
            {
                if  (OK > ( status = EC_addAffineToJacobiPt( pField, pBlock)))
                    goto exit;
            }
        }
    }

exit:

    return status;
}


/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

static MSTATUS
EC_multiplyPointJacobi(PrimeFieldPtr pField, ConstPFEPtr k,
                       ConstPFEPtr pX, ConstPFEPtr pY,
                       ComputeHelper* pR0)
{
    MSTATUS status;
    sbyte4 i, j;
    pf_unit val;

    ComputeHelper* pR1 = 0;


    /* find the first set bit */
    i = pField->n - 1;

    while (i>=0 && 0 == k->units[i])
    {
        --i;
    }

    if (0 > i)
    {
        /* multiplication by 0 -> return point at infinity */
        return EC_setJacobiPtToInfinity(pField, pR0->X1, pR0->Y1, pR0->Z1);
    }


    /* set up R0 = P */
    /* Q set to P */
    if (OK > ( status = EC_setJacobiPt( pField, pR0->X1, pR0->Y1, pR0->Z1,
                                       pX, pY)))
    {
        goto exit;
    }

    /* k->units[i] is the first unit with a bit set */
    val = k->units[i];
    j = sizeof(pf_unit) * 8 - 1;
    while ( j >=0 && !((val >> j) & 1) )
    {
        --j;
    }
    if (j == 0)
    {
        /* first bit of the unit is set */
        if (i == 0)
        {
            /* multiplication by 1 : R0 is already set to pX, pY*/
            return OK;
        }
        else
        {
            /* go to next unit */
            --i;
            j = sizeof(pf_unit) * 8 - 1;
        }
    }
    else
    {
        --j;
    }

    /* R1 = 2 P */
    if (OK > (status = EC_newComputeHelper(pField->n, &pR1)))
    {
        goto exit;
    }

    /* Q set to P */
    if (OK > ( status = EC_setJacobiPt( pField, pR1->X1, pR1->Y1, pR1->Z1,
                                       pX, pY)))
    {
        goto exit;
    }

    /* double the point in R1 = 2P */
    if  (OK > ( status = EC_doubleJacobiPoint( pField, pR1)))
        goto exit;

    /* montgomery ladder */
    while (i >= 0)
    {
        val = k->units[i];

        while (j >= 0)
        {
            if ( (val >> j) & 1)
            {
                /* RO = RO + R1; R1 = 2 R1 */
                if (OK > ( status = EC_addJacobiPoint(pField, pR0, pR1)))
                {
                    goto exit;
                }

                if (OK > ( status = EC_doubleJacobiPoint(pField, pR1)))
                {
                    goto exit;
                }
            }
            else
            {
                /* R1 = R0 + R1; R0 = 2 R0 */
                if (OK > ( status = EC_addJacobiPoint(pField, pR1, pR0)))
                {
                    goto exit;
                }

                if (OK > ( status = EC_doubleJacobiPoint(pField, pR0)))
                {
                    goto exit;
                }
            }
            --j;
        }

        --i;
        j = sizeof(pf_unit) * 8 - 1;
    }

exit:

    if (pR1)
    {
        EC_deleteComputeHelper(pField, &pR1);
    }

    return status;
}

#endif /* if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__)) */

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__

#ifdef MOCANA_ECDSA_COMB_FIXED_WIN_SIZE
#if MOCANA_ECDSA_COMB_FIXED_WIN_SIZE > 7 || MOCANA_ECDSA_COMB_FIXED_WIN_SIZE < 2
#error Invalid value for MOCANA_ECDSA_COMB_FIXED_WIN_SIZE, must be 2 to 7
#endif
#endif /* MOCANA_ECDSA_COMB_FIXED_WIN_SIZE */

#if defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__) && defined (__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__)
#error Cannot define both __ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__ and __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__
#endif

static PFEPtr EC_getCompElemXSignComb( sbyte4 numUnits, ConstPFEPtr pTable, sbyte4 i)
{
    return (PFEPtr) (((const pf_unit*) pTable) + (2*i - 2) * numUnits);
}

static PFEPtr EC_getCompElemYSignComb( sbyte4 numUnits, ConstPFEPtr pTable, sbyte4 i)
{
    return (PFEPtr) (((const pf_unit*) pTable) + (2*i - 1) * numUnits);
}

static MSTATUS EC_deleteSignedOddComb(PrimeFieldPtr pPF, sbyte4 windowSize, PFEPtr *ppComb)
{
    DIGI_MEMSET((ubyte *) *ppComb, 0x00, ((1 << windowSize)+1) * 2 * sizeof(pf_unit) * pPF->n);
    return DIGI_FREE((void **) ppComb);
}

#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__
MSTATUS EC_createPrimeCurveMutexes(void)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_ECC_P192__
    if (NULL == gpEccCombMutex192)
    {
        status = RTOS_mutexCreate(&gpEccCombMutex192, EC_COMB_MUTEX, 1);
        if (OK != status)
            goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
    if (NULL == gpEccCombMutex224)
    {
        status = RTOS_mutexCreate(&gpEccCombMutex224, EC_COMB_MUTEX, 1);
        if (OK != status)
            goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
    if (NULL == gpEccCombMutex256)
    {
        status = RTOS_mutexCreate(&gpEccCombMutex256, EC_COMB_MUTEX, 1);
        if (OK != status)
            goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
    if (NULL == gpEccCombMutex384)
    {
        status = RTOS_mutexCreate(&gpEccCombMutex384, EC_COMB_MUTEX, 1);
        if (OK != status)
            goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
    if (NULL == gpEccCombMutex521)
    {
        status = RTOS_mutexCreate(&gpEccCombMutex521, EC_COMB_MUTEX, 1);
    }
#endif

exit:

    return status;
}

MSTATUS EC_deletePrimeCurveCombsAndMutexes(void)
{
    MSTATUS status = OK, fstatus = OK;
#ifdef MOCANA_ECDSA_COMB_FIXED_WIN_SIZE
    ubyte4 windowSize = MOCANA_ECDSA_COMB_FIXED_WIN_SIZE;
#else
    ubyte4 windowSize = 5;
#endif /* MOCANA_ECDSA_COMB_FIXED_WIN_SIZE */

#ifdef __ENABLE_DIGICERT_ECC_P192__
    if (NULL != gpComb192)
    {   /* p192 is the only one with 4 as the default windowsize if it's not defined */
#ifdef MOCANA_ECDSA_COMB_FIXED_WIN_SIZE
        status = EC_deleteSignedOddComb(PF_p192, windowSize, (PFEPtr *) &gpComb192);
#else
        status = EC_deleteSignedOddComb(PF_p192, windowSize - 1, (PFEPtr *) &gpComb192);
#endif
    }

    if (NULL != gpEccCombMutex192)
    {
        fstatus = RTOS_mutexFree(&gpEccCombMutex192);
        if (OK == status)
            status = fstatus;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
    if (NULL != gpComb224)
    {
        fstatus = EC_deleteSignedOddComb(PF_p224, windowSize, (PFEPtr *) &gpComb224);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != gpEccCombMutex224)
    {
        fstatus = RTOS_mutexFree(&gpEccCombMutex224);
        if (OK == status)
            status = fstatus;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
    if (NULL != gpComb256)
    {
        fstatus = EC_deleteSignedOddComb(PF_p256, windowSize, (PFEPtr *) &gpComb256);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != gpEccCombMutex256)
    {
        fstatus = RTOS_mutexFree(&gpEccCombMutex256);
        if (OK == status)
            status = fstatus;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
    if (NULL != gpComb384)
    {
        fstatus = EC_deleteSignedOddComb(PF_p384, windowSize, (PFEPtr *) &gpComb384);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != gpEccCombMutex384)
    {
        fstatus = RTOS_mutexFree(&gpEccCombMutex384);
        if (OK == status)
            status = fstatus;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
    if (NULL != gpComb521)
    {
        fstatus = EC_deleteSignedOddComb(PF_p521, windowSize, (PFEPtr *) &gpComb521);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != gpEccCombMutex521)
    {
        fstatus = RTOS_mutexFree(&gpEccCombMutex521);
        if (OK == status)
            status = fstatus;
    }
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__ */

/*---------------------------------------------------------------------------*/

static MSTATUS EC_precomputeSignedOddComb(PrimeFieldPtr pPF, ConstPFEPtr pPx, ConstPFEPtr pPy, sbyte4 windowSize, sbyte4 d, ComputeHelper *pBlock, PFEPtr *ppComb)
{
    PFEPtr pCombTable = NULL;

    sbyte4 i = 0, j = 0;
    sbyte4 n = pPF->n;
    sbyte4 indexMax = (1 << windowSize);
    MSTATUS status = OK;

    /* internal method NULL input validity checks not needed */

    /* allocate space for all precomputed values - we use affine coordinates, we add 2 more points for -P and -2P */
    if (OK > ( status = DIGI_MALLOC( (void **) &pCombTable, (indexMax+1) * 2 * sizeof(pf_unit) * n)))
        goto exit;

    /* fill the table, first element is just P */
    PRIMEFIELD_copyElement( pPF, EC_getCompElemXSignComb(n, pCombTable, 1), pPx);
    PRIMEFIELD_copyElement( pPF, EC_getCompElemYSignComb(n, pCombTable, 1), pPy);

    /* also make and store -P at the end of the table */
    PRIMEFIELD_copyElement( pPF, EC_getCompElemXSignComb(n, pCombTable, indexMax), pPx);
    PRIMEFIELD_copyElement( pPF, EC_getCompElemYSignComb(n, pCombTable, indexMax), pPy);

    if (OK > ( status = PRIMEFIELD_additiveInvert(pPF, EC_getCompElemYSignComb(n, pCombTable, indexMax))))
        goto exit;

    /* set the compute helper jacobi pt to P */
    if (OK > ( status = EC_setJacobiPt( pPF, pBlock->X1, pBlock->Y1, pBlock->Z1, pPx, pPy)))
        goto exit;

    /* first loop: 2^d.P, 2^(2d).P,  2^(3d).P, etc... */
    for ( i = 1; i < windowSize; ++i)
    {
        for (j = 0; j < d; ++j)
        {
            if (OK > (status = EC_doubleJacobiPoint(pPF, pBlock)))
                goto exit;

            if (1 == i && 0 == j) /* if first iteration, pBlock is 2P, we need to store -2P at the end of the table */
            {
                /* copy 2P, convert back to affine coordinates */
                if (OK > ( status = EC_convertToAffine(pPF, pBlock)))
                    goto exit;

                /* safe to ignore return codes of PRIMEFIELD_copyElement */
                PRIMEFIELD_copyElement( pPF, EC_getCompElemXSignComb(n, pCombTable, indexMax + 1), pBlock->X1);
                PRIMEFIELD_copyElement( pPF, EC_getCompElemYSignComb(n, pCombTable, indexMax + 1), pBlock->Y1);

                if (OK > ( status = PRIMEFIELD_additiveInvert(pPF, EC_getCompElemYSignComb(n, pCombTable, indexMax + 1))))
                    goto exit;

                /* convert the original 2P back to projective by setting Z to 1 */
                PRIMEFIELD_setToUnsigned( pPF, pBlock->Z1, 1);
            }
        }

        j = 1<<i;

        if (OK > ( status = EC_convertToAffine(pPF, pBlock)))
            goto exit;

        PRIMEFIELD_copyElement( pPF, EC_getCompElemXSignComb(n, pCombTable, j), pBlock->X1);
        PRIMEFIELD_copyElement( pPF, EC_getCompElemYSignComb(n, pCombTable, j), pBlock->Y1);

        /* convert back to projective by setting Z to 1 */
        PRIMEFIELD_setToUnsigned( pPF, pBlock->Z1, 1);
    }

    /* second loop: compute the remaining values by addition */
    for (i = 2; i < indexMax; i *= 2)
    {
        for ( j = 1; j < i; ++j)
        {
            /* set the compute helper jacobi pt to table[i] */
            if (OK > ( status = EC_setJacobiPt( pPF, pBlock->X1, pBlock->Y1, pBlock->Z1,
                                                EC_getCompElemXSignComb(n, pCombTable, i), EC_getCompElemYSignComb(n, pCombTable, i))))
                goto exit;

            /* set the affine pt to table[j] */
            pBlock->x2 = EC_getCompElemXSignComb(n, pCombTable, j);
            pBlock->y2 = EC_getCompElemYSignComb(n, pCombTable, j);

            if (OK > ( status = EC_addAffineToJacobiPt(pPF, pBlock)))
                goto exit;

            if (OK > ( status = EC_convertToAffine(pPF, pBlock)))
                goto exit;

            /* now we have table[i + j] */
            PRIMEFIELD_copyElement( pPF, EC_getCompElemXSignComb(n, pCombTable, i + j), pBlock->X1);
            PRIMEFIELD_copyElement( pPF, EC_getCompElemYSignComb(n, pCombTable, i + j), pBlock->Y1);
        }
    }

    *ppComb = pCombTable;  pCombTable = NULL;

exit:

    /* don't change status, ok to ignore return codes */
    if (NULL != pCombTable)
    {
        DIGI_MEMSET((ubyte *) pCombTable, 0x00, (indexMax+1) * 2 * sizeof(pf_unit) * n);
        DIGI_FREE((void **) &pCombTable);
    }

    return status;
}

/* steps 4-9 of Algorithm 8 */
static MSTATUS EC_signedCombInternalMultiply(PrimeFieldPtr pPF, ubyte *pRecodedWords, sbyte4 d, byteBoolean isKodd, ComputeHelper *pBlock, PFEPtr pComb, sbyte4 windowSize)
{
    MSTATUS status = OK;
    sbyte4 i = 0, n = pPF->n;
    PFEPtr pTempY = NULL;
    PFEPtr pYptr = NULL;
    sbyte4 indexMax = (1 << windowSize) - 1; /* subtract one so we have to add 1 or 2 (in order to remain constant time) */

    status = PRIMEFIELD_newElement(pPF, &pTempY);
    if (OK != status)
        goto exit;

    /* step 4 */
    status = EC_setJacobiPtToInfinity(pPF, pBlock->X1, pBlock->Y1, pBlock->Z1);
    if (OK != status)
        goto exit;

    /* step 5 */
    for (i = d - 1; i >= 0; --i)
    {
        /* set pTempY back to 0, ok to ignore return code */
        PRIMEFIELD_setToUnsigned(pPF, pTempY, 0);

        /* step 6 */
        status = EC_doubleJacobiPoint(pPF, pBlock);
        if (OK != status)
            goto exit;

        /* x is always the same regardless of sign of pRecodedWords[i] */
        pBlock->x2 = EC_getCompElemXSignComb(n, pComb, pRecodedWords[i] & 0x7f);

        /* point pYptr to original Y */
        pYptr = EC_getCompElemYSignComb(n, pComb, pRecodedWords[i] & 0x7f);

        /* put -Y in pTempY for all cases in order to remain constant time */
        status = PRIMEFIELD_subtract(pPF, pTempY, pYptr);
        if (OK != status)
            goto exit;

        /* step 7, if negative, use -P */
        if (pRecodedWords[i] & 0x80)
        {
            pBlock->y2 = pTempY;
        }
        else
        {
            pBlock->y2 = pYptr;
        }

        status = EC_addAffineToJacobiPt(pPF, pBlock);
        if (OK != status)
            goto exit;
    }

    /* step 8 was done already, -P and -2P precomputed at the end of the comb, just set the pointers */
    if (isKodd)
    {
        pBlock->x2 = EC_getCompElemXSignComb(n, pComb, indexMax + 2);
        pBlock->y2 = EC_getCompElemYSignComb(n, pComb, indexMax + 2);
    }
    else
    {
        pBlock->x2 = EC_getCompElemXSignComb(n, pComb, indexMax + 1);
        pBlock->y2 = EC_getCompElemYSignComb(n, pComb, indexMax + 1);
    }

    /* step 9, add -P or -2P */
    status = EC_addAffineToJacobiPt(pPF, pBlock);

exit:

    /* don't change status, ignore return code */
    PRIMEFIELD_deleteElement(pPF, &pTempY);

    return status;
}

/*
 Adds added_unit to pInput starting at the word defined by position. This method assumes pf_unit
 has one more unit than the field order, zero padded. It assumes position is no bigger than the pPF->n
 */
static void EC_addOneSpecial(PrimeFieldPtr pPF, pf_unit *pInput, const pf_unit added_unit, ubyte4 position)
{
    pf_unit carry = 0;

    pInput[position] += added_unit;
    carry = (pInput[position] < added_unit) ? MOC_EC_ONE : 0;

    /* ok to modify passed by value input */
    position++;

    /* loop over rest of the units in pInput */
    for (; (sbyte4)position <= pPF->n; ++position)
    {
        pInput[position] += carry;
        carry = (pInput[position] < carry) ? MOC_EC_ONE : 0;
    }

    /* can't be any final carry since highest unit was 0 */
}

/* algorithm 4, pRecodedWords must have d bytes of space available, and must already be zero padded */
static MSTATUS EC_recodeScalar(PrimeFieldPtr pPF, sbyte4 windowSize, pf_unit *pK, ubyte *pRecodedWords, sbyte4 d)
{
    MSTATUS status = OK;
    sbyte4 i = 0, j = 0;
    sbyte4 wordNum = 0;

    sbyte *pBiPrime = NULL;

    pf_unit tester = MOC_EC_TWO; /* within the loop we will begin at the second bit */
    ubyte setter = 0;

    sbyte temp = 0;
    pf_unit *pDummyK = NULL;
    pf_unit *pKptr = NULL;

    status = DIGI_CALLOC((void **) &pBiPrime, 1, windowSize * d);
    if (OK != status)
        goto exit;

    /* make a dummy buffer for use in calculations needed to remain constant time */
    status = DIGI_CALLOC((void **) &pDummyK, sizeof(pf_unit), pPF->n + 1);
    if (OK != status)
        goto exit;

    /* steps 1-3, we take care of i = 0 outside the loop */
    pBiPrime[0] = 1;

    /* loop for i = 1 to d - 1 */
    for (i = 1; i < d; ++i)
    {
        if (0 == (i % (8*sizeof(pf_unit))))
        {
            wordNum++;
            tester = MOC_EC_ONE;
        }

        pBiPrime[i] = 1;
        temp = pBiPrime[i - 1];

        if (pK[wordNum] & tester)
        {
            pBiPrime[i - 1] = temp;  /* assignment to itself remain constant time */
        }
        else
        {
            pBiPrime[i - 1] = -1;
        }

        tester <<= 1;
    }

    if (0 == (i % (8*sizeof(pf_unit))))
    {
        wordNum++;
        tester = MOC_EC_ONE;
    }

    /*
     Step 4, we don't need to explicitly set a variable e. e is understood to be pK shifted i bits to
     the right, so pK from the leftmost bit through the bit defined by numWords and tester. All
     arithmetic, such as EC_addOneSpecial, will begin as if that is the rightmost bit. Note i = d already.

     Steps 5-8 while loop. to remain constant time always calculate temp even if it's not used, and
     always add one even if to pDummyK.
     */
    while (i < windowSize * d)
    {
        temp = (((pK[wordNum] & tester) >> (i % (8*sizeof(pf_unit)))) & 0xff);

        /* put pK dependent clause second, so short circuits on first clause are not K dependent */
        if ( (-1 == pBiPrime[i % d]) && (pK[wordNum] & tester) )
        {
            pBiPrime[i] = -1;
            pKptr = pK;
        }
        else
        {
            pBiPrime[i] = temp;
            pKptr = pDummyK;
        }

        i++;

        if (0 == (i % (8*sizeof(pf_unit))))
        {
            wordNum++;
            tester = MOC_EC_ONE;
        }
        else
            tester <<= 1;

        EC_addOneSpecial(pPF, pKptr, tester, wordNum);
    }

    /* compute the comb words */
    for (i = 0; i < d; i++)
    {
        setter = 0x01;

        /* first set the value, use a dummy 0x80 (for now) in order to remain constant time */
        for (j = 0; j < windowSize; ++j)
        {
            if (pBiPrime[j * d + i])
                pRecodedWords[i] |= setter;
            else
                pRecodedWords[i] |= 0x80;

            setter <<= 1;
        }

        /* first bit of pRecodedWords[i] is the sign bit, set it or remove it  */
        if (-1 == pBiPrime[i])
        {
            pRecodedWords[i] |= 0x80;
        }
        else
        {
            pRecodedWords[i] &= 0x7f;
        }
    }

exit:

    if (NULL != pBiPrime)
    {
        DIGI_MEMSET((ubyte *) pBiPrime, 0x00, (sbyte4) (windowSize * d)); /* don't change status, ignore return codes */
        DIGI_FREE((void **) &pBiPrime);
    }

    if (NULL != pDummyK)
    {
        DIGI_MEMSET((ubyte *) pDummyK, 0x00, sizeof(pf_unit) * (pPF->n + 1));
        DIGI_FREE((void **) &pDummyK);
    }

    return status;
}

/*
 Efficient Comb Elliptic Curve Multiplication Methods Resistant to Power Analysis
 by Min Feng, Bin B. Zhu, Maozhi Xu, Shipeng Li.

 https://pdfs.semanticscholar.org/9fb0/f19746e0c446c0ba6a285aefdf5ee1b9a475.pdf

 Algorithm 8

 Pass in NULL for pPx or pPy to multiply the curve's generator.
 */
static MSTATUS EC_signedCombPointMultiply(PEllipticCurvePtr pEC, ConstPFEPtr pK, ConstPFEPtr pPx, ConstPFEPtr pPy, ComputeHelper *pBlock)
{
    MSTATUS status = OK, fstatus = OK;
    ubyte *pRecodedWords = NULL;
    pf_unit *pMutableK = NULL;
    byteBoolean isKodd = FALSE;
    sbyte4 d = 0;
    PFEPtr pComb = NULL;

    /* set the window size for now */
#ifdef MOCANA_ECDSA_COMB_FIXED_WIN_SIZE
    sbyte4 windowSize = MOCANA_ECDSA_COMB_FIXED_WIN_SIZE;
#else
    sbyte4 windowSize = (pEC->pPF->numBits < 224 ? 4 : 5);
#endif /* MOCANA_ECDSA_COMB_FIXED_WIN_SIZE */

#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__
    PFEPtr *ppComb = NULL;
    RTOS_MUTEX pCombMutex = NULL;
#endif

    /* internal method, input validity not needed */

#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__
    if (NULL == pPx || NULL == pPy)
    {
        switch (pEC->pPF->curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case cid_EC_P192:

                pComb = (PFEPtr) gpComb192;
                windowSize = ECC_SIGNED_ODD_COMB_WIN_SIZE_P192; /* MUST reset window size */
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
            case cid_EC_P224:

                pComb = (PFEPtr) gpComb224;
                windowSize = ECC_SIGNED_ODD_COMB_WIN_SIZE_P224;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
            case cid_EC_P256:

                pComb = (PFEPtr) gpComb256;
                windowSize = ECC_SIGNED_ODD_COMB_WIN_SIZE_P256;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
            case cid_EC_P384:

                pComb = (PFEPtr) gpComb384;
                windowSize = ECC_SIGNED_ODD_COMB_WIN_SIZE_P384;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
            case cid_EC_P521:

                pComb = (PFEPtr) gpComb521;
                windowSize = ECC_SIGNED_ODD_COMB_WIN_SIZE_P521;
                break;
#endif
            default:

                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__ */

#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__
    if (NULL == pPx || NULL == pPy)
    {
        switch (pEC->pPF->curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case cid_EC_P192:

                ppComb = (PFEPtr *) &gpComb192;
                pCombMutex = gpEccCombMutex192;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
            case cid_EC_P224:

                ppComb = (PFEPtr *) &gpComb224;
                pCombMutex = gpEccCombMutex224;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
            case cid_EC_P256:

                ppComb = (PFEPtr *) &gpComb256;
                pCombMutex = gpEccCombMutex256;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
            case cid_EC_P384:

                ppComb = (PFEPtr *) &gpComb384;
                pCombMutex = gpEccCombMutex384;
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
            case cid_EC_P521:

                ppComb = (PFEPtr *) &gpComb521;
                pCombMutex = gpEccCombMutex521;
                break;
#endif
            default:

                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
        }

        /* set pComb to point to the comb too */
        pComb = *ppComb;
    }
#endif

    d = SOFT_DIV(pEC->pPF->numBits + windowSize, windowSize);  /* ceil (numBits + 1)/windowSize */

    /* make a mutable copy of the scalar K with an extra zero padded high word */
    status = DIGI_CALLOC((void **) &pMutableK, sizeof(pf_unit), pEC->pPF->n + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((ubyte *) pMutableK, (ubyte *) pK->units, pEC->pPF->n * sizeof(pf_unit));
    if (OK != status)
        goto exit;

    if (NULL != pPx && NULL != pPy)
    {
        /* Step 1, compute the comb */
        status = EC_precomputeSignedOddComb(pEC->pPF, pPx, pPy, windowSize, d, pBlock, &pComb);
        if (OK != status)
            goto exit;
    }
#if !defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__) && !defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__)
    else
    {
        status = EC_precomputeSignedOddComb(pEC->pPF, pEC->pPx, pEC->pPy, windowSize, d, pBlock, &pComb);
        if (OK != status)
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__
    else if (NULL == *ppComb)  /* only create if it's needed */
    {
        /* RTOS_mutexWait will verify pCombMutex is not null, and returns ERR_RTOS_MUTEX_WAIT if so */
        status = RTOS_mutexWait(pCombMutex);
        if (OK != status)
            goto exit;

        /* check again in case another thread created the comb after the first check */
        if (NULL == *ppComb)
        {
            status = EC_precomputeSignedOddComb(pEC->pPF, pEC->pPx, pEC->pPy, windowSize, d, pBlock, ppComb);
        }

        /* release no matter what status */
        fstatus = RTOS_mutexRelease(pCombMutex);
        if (OK == status)
            status = fstatus;

        if (OK != status)
            goto exit;

        /* set pComb to point to the comb */
        pComb = *ppComb;
    }
#endif

    /* Step 2, ensure k is odd, add 1 for even k, 2 for odd k */
    if (pMutableK[0] & 0x01)
    {
        isKodd = TRUE;
        EC_addOneSpecial(pEC->pPF, pMutableK, MOC_EC_TWO, 0);
    }
    else
    {
        isKodd = FALSE;
        EC_addOneSpecial(pEC->pPF, pMutableK, MOC_EC_ONE, 0);
    }

    /* step 3, apply algorithm 4 to compute the recoded words */
    status = DIGI_CALLOC((void **) &pRecodedWords, 1, d);
    if (OK != status)
        goto exit;

    status = EC_recodeScalar(pEC->pPF, windowSize, pMutableK, pRecodedWords, d);
    if (OK != status)
        goto exit;

    /* Steps 4-9, evaluation stage */
    status = EC_signedCombInternalMultiply(pEC->pPF, pRecodedWords, d, isKodd, pBlock, pComb, windowSize);

exit:

#if defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PRECOMPUTED__) || defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__)
    if (NULL != pPx && NULL != pPy && NULL != pComb)  /* only delete comb if it is not the generator point */
#else
    if (NULL != pComb)  /* always delete the comb */
#endif
    {
        fstatus = EC_deleteSignedOddComb(pEC->pPF, windowSize, &pComb);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pRecodedWords)
    {
        DIGI_MEMSET(pRecodedWords, 0x00, d);
        DIGI_FREE((void **) &pRecodedWords);
    }
    if (NULL != pMutableK)
    {
        DIGI_MEMSET((ubyte *) pMutableK, 0x00, sizeof(pf_unit) * (pEC->pPF->n + 1));
        DIGI_FREE((void **) &pMutableK);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_SIGNED_ODD_COMB__ */

#if defined (__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

/*---------------------------------------------------------------------------*/

MSTATUS EC_combSize( PrimeFieldPtr pPF, sbyte4 windowSize, sbyte4 *res)
{
    if (!pPF || !res)
        return ERR_NULL_POINTER;

    if ( windowSize < 2)
        return ERR_INVALID_ARG;

    *res = (((1 << windowSize) - 2) * 2 * pPF->n);
    return OK;
}

/*---------------------------------------------------------------------------*/

static PFEPtr EC_getCompElemX( sbyte4 numUnits, ConstPFEPtr pTable, sbyte4 i)
{
    return (PFEPtr) (((const pf_unit*) pTable) + (2*i - 4) * numUnits);
}


/*---------------------------------------------------------------------------*/

static PFEPtr EC_getCompElemY( sbyte4 numUnits, ConstPFEPtr pTable, sbyte4 i)
{
    return (PFEPtr) (((const pf_unit*) pTable) + (2*i - 3) * numUnits);
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
EC_precomputeComb( PrimeFieldPtr pPF, ConstPFEPtr pQx, ConstPFEPtr pQy,
                  sbyte4 windowSize, PFEPtr* pPrecomputed)
{
    ComputeHelper* pBlock = 0;
    PFEPtr  table = 0;
    sbyte4  i, n, d, indexMax;
    MSTATUS status = OK;

    if (!pPF || !pQx || !pQy || !pPrecomputed)
        return ERR_NULL_POINTER;

    if (windowSize < 2)
        return ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECC); /* may return here */

    n = pPF->n;
    indexMax = (1 << windowSize);

    if ( OK > ( status = EC_newComputeHelper(n, &pBlock)))
        goto exit;

    /* allocate space for all precomputed values-we use affine coordinates
        since our routines for adding uses these */
    table = (PFEPtr) MALLOC( (indexMax-2) * 2 * sizeof(pf_unit) * n);
    if (!table)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set the compute helper jacobi pt to pQx, pQy */
    if (OK > ( status = EC_setJacobiPt( pPF, pBlock->X1, pBlock->Y1,
            pBlock->Z1, pQx, pQy)))
    {
        goto exit;
    }

    d = SOFT_DIV(pPF->numBits + windowSize - 1, windowSize);

    /* fill the table */
    /* first loop: 2^d.P, 2^(2d).P,  2^(3d).P, etc... */
    for ( i = 1; i < windowSize; ++i)
    {
        sbyte4 j;
        for (j = 0; j < d; ++j)
        {
            if (OK > (status = EC_doubleJacobiPoint( pPF, pBlock)))
                goto exit;
        }

        if (OK > (status = EC_convertToAffine( pPF, pBlock)))
            goto exit;

        /* EC_convertToAffine does not convert the Z1 so do it here
           since we are reusing the block */
        if (OK > ( status = PRIMEFIELD_setToUnsigned( pPF, pBlock->Z1, 1)))
            goto exit;

        /* copy pX1 and pY1 to the correct index in the table */
        if (OK > ( status =
                   PRIMEFIELD_copyElement( pPF,
                                           EC_getCompElemX(n, table, 1<<i),
                                           pBlock->X1)))
        {
            goto exit;
        }

        if (OK > ( status =
                   PRIMEFIELD_copyElement( pPF,
                                           EC_getCompElemY(n, table, 1<<i),
                                           pBlock->Y1)))
        {
            goto exit;
        }
    }

    /* second loop: compute the remaining values by addition */
    for (i = 2; i < indexMax; i *= 2)
    {
        sbyte4 j;

        pBlock->x2 = EC_getCompElemX(n, table, i);
        pBlock->y2 = EC_getCompElemY(n, table, i);

        for ( j = 1; j < i; ++j)
        {
            /* table[i+j] = table[i] + table[j]; */

            /* set the compute helper jacobi pt to table[j] */
            if (OK > ( status = EC_setJacobiPt( pPF, pBlock->X1, pBlock->Y1,
                                                pBlock->Z1,
                                                (1==j) ? pQx : EC_getCompElemX(n, table, j),
                                                (1==j) ? pQy : EC_getCompElemY(n, table, j))))
            {
                goto exit;
            }

            /* do the addition */
            if (OK > ( status = EC_addAffineToJacobiPt( pPF, pBlock)))
                goto exit;

            /* convert to affine and store in table */
            if (OK > (status = EC_convertToAffine( pPF, pBlock)))
                goto exit;

            /* copy pX1 and pY1 to the correct index in the table */
            if (OK > ( status =
                       PRIMEFIELD_copyElement( pPF,
                                               EC_getCompElemX(n, table, i+j),
                                               pBlock->X1)))
            {
                goto exit;
            }

            if (OK > ( status =
                       PRIMEFIELD_copyElement( pPF,
                                               EC_getCompElemY(n, table, i+j),
                                               pBlock->Y1)))
            {
                goto exit;
            }
        }
    }

    *pPrecomputed = table;
    table = 0;
exit:

    if ( table)
    {
        FREE( table);
    }
    EC_deleteComputeHelper( pPF, &pBlock);
    return status;

}

/*---------------------------------------------------------------------------*/

extern MSTATUS
EC_precomputeCombOfCurve( PEllipticCurvePtr pEC, sbyte4 windowSize,
                            PFEPtr* pCurvePrecomputed)
{
  if (NULL == pEC)
    return ERR_NULL_POINTER;

  /* other NULL checks are performed in EC_precomputeComb */
  return EC_precomputeComb( pEC->pPF, pEC->pPx, pEC->pPy,
            windowSize, pCurvePrecomputed);
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
EC_deleteComb(PrimeFieldPtr pPF, sbyte4 windowSize, PFEPtr * ppComb)
{

  MSTATUS status;
  PFEPtr pComb = NULL;
  sbyte4 combSize;

  if (NULL == pPF || NULL == ppComb || NULL == *ppComb)
    return ERR_NULL_POINTER;

  if (windowSize < 2)
    return ERR_INVALID_ARG;

  pComb = *ppComb;
  /* params already checked for NULL, ignore return code */
  EC_combSize(pPF, windowSize, &combSize);

  status = DIGI_MEMSET((ubyte *) pComb, 0x00, combSize * sizeof (pf_unit));
  if (OK != status)
    return status;

  status = DIGI_FREE( (void**) ppComb);
  *ppComb = 0;

  return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
EC_multiplyPointJacobiLRBComb(PrimeFieldPtr pField, ConstPFEPtr k,
                              ConstPFEPtr pX, ConstPFEPtr pY,
                              ComputeHelper* pBlock,
                              sbyte4 windowSize,
                              ConstPFEPtr pPrecomp)
{
    MSTATUS status;
    sbyte4 i, j, index, d;

    d = SOFT_DIV(pField->numBits + windowSize - 1, windowSize);

    /* Q = infinity or 0 */
    if (OK > ( status = EC_setJacobiPtToInfinity( pField, pBlock->X1, pBlock->Y1, pBlock->Z1)))
    {
        goto exit;
    }

    /* comb method for point multiplication */
    for ( i = d - 1; i >= 0; --i)
    {
        if  (OK > ( status = EC_doubleJacobiPoint( pField, pBlock)))
            goto exit;

        index = 0;
        for (j = windowSize - 1; j >= 0; --j)
        {
            ubyte bit;

            PRIMEFIELD_getBit( pField, k, i + j * d, &bit);
            index <<= 1;
            index |= ((sbyte4) bit);

        }

        if ( 0 != index)
        {
            /* add the selected element from precomp block */
            if ( 1 == index)
            {
                pBlock->x2 = pX;
                pBlock->y2 = pY;
            }
            else
            {
                pBlock->x2 = EC_getCompElemX( pField->n, pPrecomp, index);
                pBlock->y2 = EC_getCompElemY( pField->n, pPrecomp, index);
            }
            if (OK > ( status = EC_addAffineToJacobiPt( pField, pBlock)))
                goto exit;
        }
    }

exit:

    return status;
}

#endif

/*---------------------------------------------------------------------------*/

static MSTATUS
EC_multiplyPointJacobiLRB(PrimeFieldPtr pField, ConstPFEPtr k,
                          ConstPFEPtr pX, ConstPFEPtr pY,
                          ComputeHelper* pBlock,
                          sbyte4 windowSize,
                          ConstPFEPtr pPrecomp)
{
    MSTATUS status;

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)
    if (windowSize)
    {
        if ( OK > ( status = EC_multiplyPointJacobiLRBComb( pField, k, pX, pY, pBlock,
                                                     windowSize, pPrecomp)))
        {
            goto exit;
        }
    }
    else
    {
         if ( OK > ( status = EC_multiplyPointJacobiLRBSimple( pField, k, pX, pY, pBlock)))
        {
            goto exit;
        }
    }
#else
    if ( OK > ( status = EC_multiplyPointJacobiLRBSimple( pField, k, pX, pY, pBlock)))
    {
        goto exit;
    }
#endif

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

static MSTATUS
EC_multiplyPointAux(PrimeFieldPtr pField, ConstPFEPtr k,
                    ConstPFEPtr pX, ConstPFEPtr pY,
                    ComputeHelper* pBlock)
{
    MSTATUS status;

    if ( OK > ( status = EC_multiplyPointJacobi(pField, k, pX, pY, pBlock)))
    {
        goto exit;
    }

    /* convert back to affine coordinates */
    if (OK > ( status = EC_convertToAffine( pField, pBlock)))
        goto exit;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
EC_multiplyPoint( PrimeFieldPtr pPF, PFEPtr pResX, PFEPtr pResY,
                   ConstPFEPtr k, ConstPFEPtr pX, ConstPFEPtr pY)
{
    MSTATUS         status;
    ComputeHelper*  pBlock = 0;

    if ( !pPF || !pResX || !pResY || !k || !pX || !pY)
        return ERR_NULL_POINTER;

    /* allocate all the memory we will ever need */
    if ( OK > ( status = EC_newComputeHelper( pPF->n, &pBlock)))
        goto exit;

    /* Q = kP */
    if  ( OK > ( status = EC_multiplyPointAux(pPF, k, pX, pY, pBlock)))
    {
        goto exit;
    }

    /* result is in X1 and Y1 of the ComputeHelper */
    if (OK > ( status = PRIMEFIELD_copyElement( pPF, pResX, pBlock->X1)))
        goto exit;

    if (OK > ( status = PRIMEFIELD_copyElement( pPF, pResY, pBlock->Y1)))
        goto exit;

exit:

    EC_deleteComputeHelper( pPF, &pBlock);
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
EC_addMultiplyPointAux(PrimeFieldPtr pField,
                        ConstPFEPtr pAddedX, ConstPFEPtr pAddedY,
                        ConstPFEPtr k,
                        ConstPFEPtr pX, ConstPFEPtr pY,
                        ComputeHelper* pBlock)
{
    MSTATUS status;

    /* multiply the point */
    if ( OK > ( status = EC_multiplyPointJacobi( pField, k, pX, pY, pBlock)))
    {
        goto exit;
    }

    /* add the pAddedX, pAddedY */
    /* once the multiplication is done, we can add the other point
    by just making the x2,y2 point to that point */
    pBlock->x2 = pAddedX;
    pBlock->y2 = pAddedY;

    if (OK > ( status = EC_addAffineToJacobiPt( pField, pBlock)))
    {
        goto exit;
    }

    /* convert back to affine coordinates */
    if (OK > ( status = EC_convertToAffine( pField, pBlock)))
        goto exit;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
EC_computeYSquareFromX( PEllipticCurvePtr pEC, ConstPFEPtr x, ComputeHelper* pB)
{
    /* compute the result of the curve equationn
     y^2 = x^3  - 3 * x + b in the PrimeField. Result will be in pB->T1 */
    MSTATUS status;

    if ( OK > ( status = PRIMEFIELD_squareAux(pEC->pPF, pB->T2, x, pB->hilo))) /* T2 = x^2 */
    {
        goto exit;
    }

    if (OK > ( status = PRIMEFIELD_multiplyAux(pEC->pPF, pB->T1, pB->T2, x, pB->hilo)))   /* T1 = x ^3 */
    {
        goto exit;
    }

    if (OK > ( status = PRIMEFIELD_setToUnsigned(pEC->pPF, pB->T2, 3))) /* T2 = 3 */
    {
        goto exit;
    }

    if (OK > ( status = PRIMEFIELD_multiplyAux(pEC->pPF, pB->T2, pB->T2, x, pB->hilo))) /* T2 = 3 * x */
    {
        goto exit;
    }

    if (OK > ( status = PRIMEFIELD_subtract(pEC->pPF, pB->T1, pB->T2))) /* T1 = x ^ 3 - 3 * x */
    {
        goto exit;
    }

    if (OK > ( status = PRIMEFIELD_add(pEC->pPF, pB->T1, pEC->b)))     /* y^2 = x ^3  - 3 * x + b */
    {
        goto exit;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
EC_addMultiplyPoint( PrimeFieldPtr pPF, PFEPtr pResX, PFEPtr pResY,
                   ConstPFEPtr pAddedX, ConstPFEPtr pAddedY,
                   ConstPFEPtr k, ConstPFEPtr pX, ConstPFEPtr pY)
{
    MSTATUS         status;
    ComputeHelper*  pBlock = 0;

    if ( !pPF || !pResX || !pResY || !pAddedX || !pAddedY || !k || !pX || !pY )
        return ERR_NULL_POINTER;

    /* allocate all the memory we will ever need */
    if ( OK > ( status = EC_newComputeHelper( pPF->n, &pBlock)))
        goto exit;

    /* Q = kP */
    if  ( OK > ( status = EC_addMultiplyPointAux(pPF, pAddedX, pAddedY,
                                                 k, pX, pY, pBlock)))
    {
        goto exit;
    }

    /* result is in X1 and Y1 of the ComputeHelper */
    if (OK > ( status = PRIMEFIELD_copyElement( pPF, pResX, pBlock->X1)))
        goto exit;

    if (OK > ( status = PRIMEFIELD_copyElement( pPF, pResY, pBlock->Y1)))
        goto exit;

exit:

    EC_deleteComputeHelper( pPF, &pBlock);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_verifyKeyPair( PEllipticCurvePtr pEC, ConstPFEPtr k,
                    ConstPFEPtr pQx, ConstPFEPtr pQy)
{
    MSTATUS status;
    ComputeHelper*  pBlock = 0;

    if ( !pEC || !k || !pQx || !pQy)
        return ERR_NULL_POINTER;

    /* this does not verify the public key -- just that kP = Q */
    /* allocate all the memory we will ever need */
    if ( OK > ( status = EC_newComputeHelper( pEC->pPF->n, &pBlock)))
        goto exit;

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    if ( OK > (status = EC_signedCombPointMultiply(pEC, k, NULL, NULL, pBlock)))
        goto exit;

    /* convert back to affine coordinates */
    if ( OK > (status = EC_convertToAffine( pEC->pPF, pBlock)))
        goto exit;
#else
    if ( OK > (status = EC_multiplyPointAux(pEC->pPF, k, pEC->pPx, pEC->pPy, pBlock)))
    {
        goto exit;
    }
#endif

    if ( !PRIMEFIELD_match( pEC->pPF, pBlock->X1, pQx) ||
        !PRIMEFIELD_match( pEC->pPF, pBlock->Y1, pQy))
    {
        status = ERR_FALSE;
        goto exit;
    }

exit:

    EC_deleteComputeHelper( pEC->pPF, &pBlock);
    return status;
}


/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)

MSTATUS EC_computeYFromX( PEllipticCurvePtr pEC, ConstPFEPtr x, PFEPtr y)
{
    MSTATUS status;
    ComputeHelper* pBlock;

    if (NULL == pEC || NULL == x || NULL == y)
        return ERR_NULL_POINTER;

    /* allocate all the memory we will ever need */
    if ( OK > ( status = EC_newComputeHelper( pEC->pPF->n, &pBlock)))
        goto exit;

    if (OK > ( status = EC_computeYSquareFromX(pEC, x, pBlock)))
    {
        goto exit;
    }
    /* y^2 is in pBlock->T1 */

    status = PRIMEFIELD_squareRoot(pEC->pPF, y, pBlock->T1);

exit:

    EC_deleteComputeHelper( pEC->pPF, &pBlock);

    return status;
}

#endif

/*---------------------------------------------------------------------------*/


static MSTATUS
ECDSA_signTest2( PEllipticCurvePtr pEC, ConstPFEPtr d,
                    ConstPFEPtr r, ConstPFEPtr k,
                    ConstPFEPtr e, PFEPtr k_1, PFEPtr s)
{
    MSTATUS status;

    /* compute s = (e + dr)/k mod n */

    /* s = dr mod n */
    if (OK > ( status = PRIMEFIELD_barrettMultiply( pEC->pPF, s, d, r, pEC->n, pEC->mu)))
    {
        goto exit;
    }

    /* s = e + (dr mod n); since e < n, e = e mod n */
    if (OK > ( status = PRIMEFIELD_addAux( pEC->pPF, s, e, pEC->n)))
        goto exit;

    if ( OK > ( status = PRIMEFIELD_inverseAux( pEC->pPF->n, k_1, k, pEC->n)))
    {
        goto exit;
    }

    if (OK > ( status = PRIMEFIELD_barrettMultiply( pEC->pPF, s, s, k_1, pEC->n, pEC->mu)))
    {
        goto exit;
    }

    if ( 0 == PRIMEFIELD_cmpToUnsigned( pEC->pPF, s, 0))
    {
        status = ERR_FALSE;
        goto exit;
    }

    status = OK;

exit:

    return status;
}

#endif /* if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__)) */

/*---------------------------------------------------------------------------*/

static MSTATUS EC_newIntegerFromHash( PEllipticCurvePtr pEC,
                                     const ubyte* hash, ubyte4 hashLen,
                                     PFEPtr* p_e)
{
    MSTATUS status;
    PFEPtr  e = 0;
    ubyte4 orderBits;
    ubyte4 leftOverBits = 0;

    if ( OK > ( status = PRIMEFIELD_newElement( pEC->pPF, &e)))
        goto exit;

    /*
     SEC1: if hashLen*8 is more than the number of bits in the order of the curve,
     then the hash should be truncated to the leftmost number of bits in the order of the curve.
    */

    /* get the total number of bits in the curve order */
    orderBits = EC_GetUnitBitLength( pEC->n->units[pEC->pPF->n-1]) + ((pEC->pPF->n)-1) * 8 * sizeof(pf_unit);

    if (hashLen * 8 > orderBits )
    {
        /* crude truncation of all extra bytes */
        hashLen = (orderBits+7)/8;

        /* get the number of bits in the curve order's most significant byte */
        leftOverBits = orderBits % 8;
    }

    /* convert the hash to an integer */
    BI_setUnitsToByteString( pEC->pPF->n, e->units, hash, hashLen);

    /* shift so that the hash integer also has the same number of bits as the curve order */
    if (leftOverBits)
    {
        BI_shiftREx(pEC->pPF->n, e->units, 8 - leftOverBits);
    }

    /* safe to modulo by the order of the curve */
    if ( OK > ( status = EC_modOrder( pEC, e )))
        goto exit;

    *p_e = e;
    e = 0;

exit:

    PRIMEFIELD_deleteElement( pEC->pPF, &e);
    return status;
}

/*------------------------------------------------------------------*/

#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

MOC_EXTERN MSTATUS
ECDSA_signDigestAux( PEllipticCurvePtr pEC, ConstPFEPtr d,
           RNGFun rngFun, void* rngArg,
           const ubyte* hash, ubyte4 hashLen,
           PFEPtr r, PFEPtr s)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ComputeHelper*  pBlock = 0;
    PFEPtr          k = 0;
    PFEPtr          e = 0;

    if ( !pEC || !d || !rngFun || !hash || !r || !s)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,pEC->pPF->curveId);

    if ( OK > ( status = PRIMEFIELD_newElement( pEC->pPF, &k)))
        goto exit;

    if ( OK > ( status = EC_newIntegerFromHash( pEC, hash, hashLen, &e)))
        goto exit;

    if ( OK > ( status = EC_newComputeHelper( pEC->pPF->n, &pBlock)))
        goto exit;

    while ( 1)
    {
        /* generate ephemeral key k so that kP = Qx,Qy and Qx mod n <> 0 */
        do
        {
            if (OK > (status = EC_generateRandomNumber( pEC, k, rngFun, rngArg)))
                goto exit;

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
            if (OK > (status = EC_signedCombPointMultiply(pEC, k, NULL, NULL, pBlock)))
                goto exit;
#else
            if (OK > (status = EC_multiplyPointJacobiLRBSimple(pEC->pPF, k, pEC->pPx, pEC->pPy, pBlock)))
                goto exit;

#endif /* __DISABLE_DIGICERT_SIGNED_ODD_COMB__ */

            /* convert back to affine coordinates */
            if (OK > ( status = EC_convertToAffine(pEC->pPF, pBlock)))
                goto exit;

            /* X1 = X1 mod n */
            if ( OK > (status = EC_modOrder( pEC, pBlock->X1)))
            {
                goto exit;
            }
        } while ( 0 == PRIMEFIELD_cmpToUnsigned( pEC->pPF, pBlock->X1, 0));

        /* second test -- use pBlock storage */
        if ( OK == ECDSA_signTest2( pEC, d, pBlock->X1, k, e, pBlock->T1, s))
        {
            break;
        }
    }

    if (OK > ( status = PRIMEFIELD_copyElement( pEC->pPF, r, pBlock->X1)))
        goto exit;

exit:

    EC_deleteComputeHelper( pEC->pPF, &pBlock);
    PRIMEFIELD_deleteElement( pEC->pPF, &k);
    PRIMEFIELD_deleteElement( pEC->pPF, &e);

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,pEC->pPF->curveId);
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

extern MSTATUS
EC_generateKey_FIPS_consistancy_test( PEllipticCurvePtr pEC,
                                      RNGFun rngFun, void* rngArg,
                                      PFEPtr k, PFEPtr pQx, PFEPtr pQy)
{
    sbyte4  msgLen = 15;
    ubyte   msg[] = {
        'C', 'L', 'E', 'A', 'R', '_', 'T', 'E', 'X', 'T', '_', 'L', 'I', 'N', 'E'
    };
    PFEPtr          r = NULL;
    PFEPtr          s = NULL;
    PrimeFieldPtr   pPF = NULL;
    MSTATUS         status = OK;

    pPF = EC_getUnderlyingField( pEC);

    if (OK > (status = PRIMEFIELD_newElement(pPF, &r)))
        goto exit;

    if (OK > (status = PRIMEFIELD_newElement(pPF, &s)))
        goto exit;

    if (OK > (status = ECDSA_signDigestAux(pEC, k, rngFun, rngArg,
                                          msg, msgLen, r, s)))
    {
        goto exit;
    }

    if ( 1 == ecdsa_fail )
    {
        r->units[0] ^= 0x783F;
    }
    ecdsa_fail = 0;

    if (OK > (status = ECDSA_verifySignature(pEC, pQx, pQy,
                                             msg, msgLen, r, s)))
    {
        goto exit;
    }

    FIPS_TESTLOG(1070, "EC_generateKey_FIPS_consistancy_test: GOOD Signature Verify!" );

exit:
    if (ERR_FALSE == status)
    {
        status = ERR_FIPS_ECDSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_ECC,status);
        setFIPS_Status(FIPS_ALGO_ECDSA,status);
    }

    PRIMEFIELD_deleteElement(pPF, &r);
    PRIMEFIELD_deleteElement(pPF, &s);

    return status;

} /* EC_generateKey_FIPS_consistancy_test */

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*---------------------------------------------------------------------------*/

MSTATUS
EC_generateKeyPair( PEllipticCurvePtr pEC, RNGFun rngFun, void* rngArg,
                    PFEPtr k, PFEPtr pQx, PFEPtr pQy)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    ComputeHelper*  pBlock = 0;
#endif

    if ( !pEC || !rngFun || !k || !pQx || !pQy )
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECC,pEC->pPF->curveId);

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    if ( OK > ( status = EC_newComputeHelper( pEC->pPF->n, &pBlock)))
        goto exit;
#endif

    if (OK > (status = EC_generateRandomNumber(pEC, k, rngFun, rngArg)))
        goto exit;

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    if ( OK > (status = EC_signedCombPointMultiply(pEC, k, NULL, NULL, pBlock)))
        goto exit;

    /* convert back to affine coordinates */
    if ( OK > (status = EC_convertToAffine( pEC->pPF, pBlock)))
        goto exit;

    /* ok to ignore copyElement return codes */
    PRIMEFIELD_copyElement(pEC->pPF, pQx, pBlock->X1);
    PRIMEFIELD_copyElement(pEC->pPF, pQy, pBlock->Y1);

#else
    if (OK > (status = EC_multiplyPoint( pEC->pPF, pQx, pQy, k,
                                        pEC->pPx, pEC->pPy)))
    {
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    status = EC_generateKey_FIPS_consistancy_test( pEC, rngFun, rngArg,
                                             k, pQx, pQy);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

exit:

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    EC_deleteComputeHelper(pEC->pPF, &pBlock); /* don't change status, ok to ignore return code */
#endif

    FIPS_LOG_END_ALG(FIPS_ALGO_ECC,pEC->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_verifyPoint( PEllipticCurvePtr pEC, ConstPFEPtr pQx, ConstPFEPtr pQy)
{
    MSTATUS status;
    ComputeHelper*  pBlock = 0;

    if (NULL == pEC || NULL == pQx || NULL == pQy)
        return ERR_NULL_POINTER;

    /***** verify that it's a point on the curve */
    if ( OK > ( status = EC_newComputeHelper( pEC->pPF->n, &pBlock)))
        goto exit;

    /* this routine will place the Y square computed from X equation into
     pBlock->T1 and clobbers T2 */
    if ( OK > ( status  = EC_computeYSquareFromX(pEC, pQx, pBlock)))
    {
        goto exit;
    }

    /* T2 = Qy ^ 2 */
    if ( OK > ( status = PRIMEFIELD_squareAux( pEC->pPF, pBlock->T2, pQy,
                                              pBlock->hilo)))
    {
        goto exit;
    }

    if ( !PRIMEFIELD_match( pEC->pPF, pBlock->T1, pBlock->T2))
    {
        status = ERR_FALSE;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    /* This check is not necessary if the cofactor is equal to 1 which is the
    case for the NIST curves over prime fields */
    /* verify nQ = O if the cofactor is bigger than 1 */
    if (1 < pEC->h)
    {
        status = EC_multiplyPointAux( pEC->pPF, pEC->n, pQx, pQy, pBlock);
        if (ERR_EC_INFINITE_RESULT == status)
        {
            status = OK;
        }
        else
        {
            status = ERR_FALSE;
        }
    }
#endif

exit:

    EC_deleteComputeHelper( pEC->pPF, &pBlock);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_verifyPublicKey( PEllipticCurvePtr pEC, ConstPFEPtr pQx, ConstPFEPtr pQy)
{
    if ( !pEC || !pQx || !pQy)
        return ERR_NULL_POINTER;

    /* Sanity check, verify they are reduced elements of the field */
    if ( PRIMEFIELD_cmp( pEC->pPF, pQx, (PFEPtr) pEC->pPF->units) >= 0 ||
         PRIMEFIELD_cmp( pEC->pPF, pQy, (PFEPtr) pEC->pPF->units) >= 0 )
    {
        return ERR_FALSE;
    }

    /* verify that it's a point on the curve */
    return EC_verifyPoint( pEC, pQx, pQy);
}

#endif

/*---------------------------------------------------------------------------*/

extern MSTATUS
ECDSA_verifySignatureEx( PEllipticCurvePtr pEC,
                           ConstPFEPtr pPubKeyX, ConstPFEPtr pPubKeyY,
                           const ubyte* hash, ubyte4 hashLen,
                           sbyte4 curveWinSize, ConstPFEPtr pCurvePrecomp,
                           sbyte4 pubKeyWinSize, ConstPFEPtr pPubKeyPrecomp,
                           ConstPFEPtr r, ConstPFEPtr s)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    PFEPtr          e = 0;
    PFEPtr          w = 0;
    PFEPtr          u1 = 0;
    PFEPtr          u2 = 0;

    ComputeHelper*  pBlock = 0;

    if ( !pEC || !pPubKeyX || !pPubKeyY || !hash || !r || !s)
        return ERR_NULL_POINTER;

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    /* verify the window size and that there really is a comb if window size > 1 */
    if ( 1 == curveWinSize || curveWinSize < 0 || 1 == pubKeyWinSize || pubKeyWinSize < 0 )
        return ERR_INVALID_ARG;

    if ( (curveWinSize > 1 && NULL == pCurvePrecomp) || (pubKeyWinSize > 1 && NULL == pPubKeyPrecomp) )
        return ERR_NULL_POINTER;
#else

    /* comb methods are not defined, there should be no window sizes */
    if ( 0 != curveWinSize || 0 != pubKeyWinSize)
        return ERR_INVALID_ARG;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,pEC->pPF->curveId);

    /* verify r, s are in the interval [1, n-1] */
    if ( PRIMEFIELD_cmpToUnsigned( pEC->pPF, r, 0) == 0 ||
            PRIMEFIELD_cmpToUnsigned( pEC->pPF, s, 0) == 0 ||
            PRIMEFIELD_cmp( pEC->pPF, r, pEC->n) >= 0 ||
            PRIMEFIELD_cmp( pEC->pPF, s, pEC->n) >= 0 )
    {
        status = ERR_FALSE;
        goto exit;
    }

    if ( OK > ( status = EC_newIntegerFromHash( pEC, hash, hashLen, &e)))
        goto exit;


    if ( OK > ( status = PRIMEFIELD_newElement( pEC->pPF, &w)))
        goto exit;

    if ( OK > ( status = PRIMEFIELD_newElement( pEC->pPF, &u1)))
        goto exit;

    if ( OK > ( status = PRIMEFIELD_newElement( pEC->pPF, &u2)))
        goto exit;

    if ( OK > (status = PRIMEFIELD_inverseAux( pEC->pPF->n, w, s, pEC->n)))
        goto exit;

    if (OK > ( status = PRIMEFIELD_barrettMultiply( pEC->pPF, u1, e, w, pEC->n, pEC->mu)))
        goto exit;

    if (OK > ( status = PRIMEFIELD_barrettMultiply( pEC->pPF, u2, r, w, pEC->n, pEC->mu)))
        goto exit;

    /* calculate u1P + u2Q */
    if ( OK > ( status = EC_newComputeHelper( pEC->pPF->n, &pBlock)))
        goto exit;

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    if (NULL == pPubKeyPrecomp)
    {
        if ( OK > ( status = EC_signedCombPointMultiply(pEC, u2, pPubKeyX, pPubKeyY, pBlock)))
            goto exit;
    }
    else
#endif
    {
        if ( OK > ( status = EC_multiplyPointJacobiLRB( pEC->pPF, u2,
                                                       pPubKeyX, pPubKeyY, pBlock,
                                                       pubKeyWinSize, pPubKeyPrecomp)))
        {
            goto exit;
        }
    }

    /* convert back to affine coordinates */
    if (OK > ( status = EC_convertToAffine( pEC->pPF, pBlock)))
        goto exit;

    /* save the results into e and w */
    if ( OK > ( status = PRIMEFIELD_copyElement( pEC->pPF, e, pBlock->X1)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_copyElement( pEC->pPF, w, pBlock->Y1)))
        goto exit;

#ifndef __DISABLE_DIGICERT_SIGNED_ODD_COMB__
    if (NULL == pCurvePrecomp)
    {
        if ( OK > ( status = EC_signedCombPointMultiply(pEC, u1, NULL, NULL, pBlock)))
            goto exit;
    }
    else
#endif
    {
        /* compute u1 * P and leave the result in Jacobi coordinates */
        if ( OK > ( status = EC_multiplyPointJacobiLRB( pEC->pPF, u1,
                                                       pEC->pPx, pEC->pPy, pBlock,
                                                       curveWinSize, pCurvePrecomp)))
        {
            goto exit;
        }
    }

    /* low level code ---- */
    pBlock->x2 = e;
    pBlock->y2 = w;

    if  (OK > ( status = EC_addAffineToJacobiPt( pEC->pPF, pBlock)))
        goto exit;

    /* convert back to affine coordinates */
    status = EC_convertToAffine( pEC->pPF, pBlock);
    if (ERR_EC_INFINITE_RESULT == status)
        status = ERR_FALSE;
    if (OK != status)
        goto exit;

    /* pBlock->X1 , pBlock->Y1 now have the result */
    /* verify this is not zero or infinity */
    if ( 0 == PRIMEFIELD_cmpToUnsigned( pEC->pPF, pBlock->X1, 0) &&
         0 == PRIMEFIELD_cmpToUnsigned( pEC->pPF, pBlock->Y1, 0))
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* compute x1 mod n */
    if ( OK > ( status = EC_modOrder( pEC, pBlock->X1)))
        goto exit;

    /* compare with r */
    status = PRIMEFIELD_match(pEC->pPF, pBlock->X1, r) ? OK : ERR_FALSE;

exit:

    EC_deleteComputeHelper( pEC->pPF, &pBlock);

    PRIMEFIELD_deleteElement( pEC->pPF, &w);
    PRIMEFIELD_deleteElement( pEC->pPF, &e);
    PRIMEFIELD_deleteElement( pEC->pPF, &u1);
    PRIMEFIELD_deleteElement( pEC->pPF, &u2);

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,pEC->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
ECDSA_verifySignature( PEllipticCurvePtr pEC,
                   ConstPFEPtr pPubKeyX, ConstPFEPtr pPubKeyY,
                   const ubyte* hash, ubyte4 hashLen,
                   ConstPFEPtr r, ConstPFEPtr s)
{
    return ECDSA_verifySignatureEx( pEC, pPubKeyX, pPubKeyY,
                   hash, hashLen, 0, 0, 0, 0, r, s);
}

/*---------------------------------------------------------------------------*/

PrimeFieldPtr
EC_getUnderlyingField( PEllipticCurvePtr pEC)
{
    if (NULL == pEC)
        return NULL;

    return pEC->pPF;
}

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__))

MSTATUS EC_pointToByteString( PEllipticCurvePtr pEC,
                                  ConstPFEPtr pX, ConstPFEPtr pY,
                                  ubyte** s, sbyte4* pLen)
{
    MSTATUS         status = OK;
    PrimeFieldPtr   pPF;
    ubyte*          buffer = 0;
    sbyte4          elemLen;
    ubyte*          p;

    if (!pEC || !pX || !pY || !s || !pLen)
    {
        return ERR_NULL_POINTER;
    }

    pPF = pEC->pPF;

    /* note, point at infinity can't be represented as input to this method */
    PRIMEFIELD_getElementByteStringLen( pEC->pPF, &elemLen);

    buffer = (ubyte*) MALLOC(1 + 2 * elemLen);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    p = buffer;

    *p++ = 0x04; /* uncompressed form */

    PRIMEFIELD_writeByteString( pPF, pX, p, elemLen);
    PRIMEFIELD_writeByteString( pPF, pY, p + elemLen, elemLen);

    *pLen = 1  + 2 * elemLen;
    *s = buffer;
    buffer = 0;

exit:

    /* no cleanup since malloc is last thing that can fail */

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_getPointByteStringLen( PEllipticCurvePtr pEC, sbyte4 *pLen)
{
    sbyte4 elemLen;

    if (!pEC || !pLen)
        return ERR_NULL_POINTER;

    PRIMEFIELD_getElementByteStringLen( pEC->pPF, &elemLen);

    *pLen = 1 + 2 * elemLen;
    return OK;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_writePointToBuffer( PEllipticCurvePtr pEC,
                  ConstPFEPtr pX, ConstPFEPtr pY,
                  ubyte* s, sbyte4 len)
{
    MSTATUS         status = OK;
    PrimeFieldPtr   pPF;

    if (!pEC || !pX || !pY || !s )
    {
        return ERR_NULL_POINTER;
    }

    pPF = pEC->pPF;

    /* deal with the special case of the point at infinity */
    if ( 0 == PRIMEFIELD_cmpToUnsigned( pPF, pX, 0) &&
            0 == PRIMEFIELD_cmpToUnsigned( pPF, pY, 0))
    {
        if ( len < 1)
        {
            status = ERR_BUFFER_OVERFLOW;
            goto exit;
        }
        *s = 0;
    }
    else
    {
        sbyte4 elemLen;

        PRIMEFIELD_getElementByteStringLen( pPF, &elemLen);

        if ( len < (1 + 2 * elemLen))
        {
            status = ERR_BUFFER_OVERFLOW;
            goto exit;
        }

        *s++ = 0x04; /* uncompressed form */

        PRIMEFIELD_writeByteString( pPF, pX, s, elemLen);
        PRIMEFIELD_writeByteString( pPF, pY, s + elemLen, elemLen);
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_setPointToByteString( PEllipticCurvePtr pEC,
                            const ubyte* s, sbyte4 len,
                            PFEPtr pX, PFEPtr pY)
{
    PrimeFieldPtr pPF;
    MSTATUS status;
    sbyte4 elemLen;
    sbyte4 ptLen;

    if(NULL == pEC || NULL == s || NULL == pX || NULL == pY)
        return ERR_NULL_POINTER;

    pPF = pEC->pPF;

    /* check for point at infinity, we will not allow it */
    if (1 == len)
    {
        if (0 != *s)
        {
            status = ERR_FF_INVALID_PT_STRING;
        }
        else
        {
            status = ERR_EC_INFINITE_RESULT;
        }

        goto exit;
    }

    PRIMEFIELD_getElementByteStringLen(pPF, &elemLen);

    if ( len != (sbyte4) (1 + 2 * elemLen))
    {
        /* support only no compression or hybrid pt representation */
        status = ERR_FF_INVALID_PT_STRING;
        goto exit;
    }

    if ( 0x04 != *s && 0x06 != *s && 0x07 != *s)
    {
        /* support only no compression or hybrid pt representation */
        status = ERR_FF_UNSUPPORTED_PT_REPRESENTATION;
        goto exit;
    }

    ptLen = len/2;

    ++s; /* over the type byte */

    if (OK > (status = PRIMEFIELD_setToByteString( pPF, pX, s, ptLen)))
        goto exit;

    s += ptLen;

    if (OK > (status = PRIMEFIELD_setToByteString( pPF, pY, s, ptLen)))
        goto exit;

    status = EC_verifyPoint( pEC, pX, pY);

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_byteStringToPoint( PEllipticCurvePtr pEC,
                                    const ubyte* s, sbyte4 len,
                                    PFEPtr* ppX, PFEPtr* ppY)
{
    MSTATUS         status;
    PrimeFieldPtr   pPF;
    PFEPtr          pNewX = 0;
    PFEPtr          pNewY = 0;

    if (!pEC || !s || !ppX || !ppY)
    {
        return ERR_NULL_POINTER;
    }

    pPF = pEC->pPF;

    if (OK > (status = PRIMEFIELD_newElement( pPF, &pNewX)))
        goto exit;

    if (OK > (status = PRIMEFIELD_newElement( pPF, &pNewY)))
        goto exit;

    if ( OK > (status = EC_setPointToByteString( pEC, s, len, pNewX, pNewY)))
            goto exit;

    *ppX = pNewX;
    pNewX = 0;
    *ppY = pNewY;
    pNewY = 0;

exit:

    PRIMEFIELD_deleteElement( pPF, &pNewX);
    PRIMEFIELD_deleteElement( pPF, &pNewY);

    return status;
}

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ECDH__

MSTATUS
ECDH_generateSharedSecretAux(PEllipticCurvePtr pEC,
                            ConstPFEPtr pX, ConstPFEPtr pY,
                            ConstPFEPtr scalarMultiplier,
                            ubyte** sharedSecret,
                            sbyte4* sharedSecretLen,
                            sbyte4 flag)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ComputeHelper* pBlock = 0;
    PrimeFieldPtr pFld;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    PFEPtr pH = NULL;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */


    if (!pEC || !pX || !pY || !scalarMultiplier || !sharedSecret || !sharedSecretLen)
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDH,pEC->pPF->curveId);

    pFld = pEC->pPF;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    /*
     Applications should be using ECDH_generateSharedSecret which does the point
     (ie public key) validation. In FIPS mode we'll be doubly safe though
     and perform another validation here.
     */
    if ( OK > ( status = EC_verifyPoint(pEC, pX, pY)))
        goto exit;
#endif

    if ( OK > ( status = EC_newComputeHelper( pFld->n, &pBlock)))
        goto exit;

    /* multiply by scalar */
    if ( OK > ( status = EC_multiplyPointAux( pFld, scalarMultiplier,
                                                pX, pY, pBlock)))
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    /* multiply by the cofactor if it's bigger than 1 */
    if (1 < pEC->h)
    {
        if ( OK > ( status = PRIMEFIELD_newElement(pFld, &pH)))
            goto exit;

        if ( OK > ( status = PRIMEFIELD_setToUnsigned(pFld, pH, pEC->h)))
            goto exit;

        /* multiply by h */
        if ( OK > ( status = EC_multiplyPointAux( pFld, pH, pBlock->X1, pBlock->Y1, pBlock)))
            goto exit;
    }
#endif


    if (flag)
    {
        /* shared secret is the X coordinate of the product: pBlock->X1 */
        if ( OK > ( status = PRIMEFIELD_getAsByteString( pFld, pBlock->X1,
                                sharedSecret, sharedSecretLen)))
        {
            goto exit;
        }
    }
    else
    {
        if ( OK > ( status = PRIMEFIELD_getAsByteString2( pFld,
                                pBlock->X1, pBlock->Y1,
                                sharedSecret, sharedSecretLen)))
        {
            goto exit;
        }
    }

exit:

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (NULL != pH)
    {
        PRIMEFIELD_deleteElement( pFld, &pH); /* ok to ignore return code */
    }
#endif

    EC_deleteComputeHelper( pFld, &pBlock);

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDH,pEC->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
ECDH_generateSharedSecret(PEllipticCurvePtr pEC,
                            const ubyte* pointByteString,
                            sbyte4 pointByteStringLen,
                            ConstPFEPtr scalarMultiplier,
                            ubyte** sharedSecret,
                            sbyte4* sharedSecretLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    PFEPtr pX = 0;
    PFEPtr pY = 0;
    PrimeFieldPtr pFld;

    if (!pEC || !pointByteString || !scalarMultiplier ||
        !sharedSecret || !sharedSecretLen)
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDH,pEC->pPF->curveId);

    pFld = pEC->pPF;

    /* convert point byte string to point */
    if (OK > (status = EC_byteStringToPoint( pEC, pointByteString,
                                                pointByteStringLen, &pX, &pY)))
    {
        goto exit;
    }

    if (OK > (status = ECDH_generateSharedSecretAux( pEC, pX, pY,
                                                        scalarMultiplier,
                                                        sharedSecret,
                                                        sharedSecretLen,
                                                        1))) /* X coordinate only */
    {
        goto exit;
    }

exit:

    PRIMEFIELD_deleteElement( pFld, &pX);
    PRIMEFIELD_deleteElement( pFld, &pY);

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDH,pEC->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECDH_MODES__
MSTATUS ECDH_keyAgreementSchemePrimeCurve(
    ubyte4 mode, 
    ECCKey *pStatic, 
    ECCKey *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    ubyte *pSS1 = NULL;
    sbyte4 ss1Len = 0;
    ubyte *pSS2 = NULL;
    sbyte4 ss2Len = 0;
    ECCKey *pOtherStatic = NULL;
    ECCKey *pOtherEphemeral = NULL;
    PFEPtr pMQV = NULL;

    if (NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;

    switch (mode)
    {
        case FULL_UNIFIED:
            
            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve || NULL == pEphemeral->pCurve)
                goto exit;

            status = ERR_EC_DIFFERENT_CURVE;
            if (pStatic->pCurve != pEphemeral->pCurve)
                goto exit;
            
            /* calculate Z_s */
            status = ECDH_generateSharedSecret(pStatic->pCurve, (const ubyte *) pOtherPartysStatic, otherStaticLen, pStatic->k, &pSS1, &ss1Len);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = ECDH_generateSharedSecret(pEphemeral->pCurve, (const ubyte *) pOtherPartysEphemeral, otherEphemeralLen, pEphemeral->k, &pSS2, &ss2Len);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = (ubyte4) (ss1Len + ss2Len);
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

#ifndef __DISABLE_DIGICERT_ECC_MQV__
        case FULL_MQV:   
 
            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve || NULL == pEphemeral->pCurve)
                goto exit;

            status = ERR_EC_DIFFERENT_CURVE;
            if (pStatic->pCurve != pEphemeral->pCurve)
                goto exit;

            status = EC_newKey(pStatic->pCurve, &pOtherStatic);
            if (OK != status)
                goto exit;

            status = EC_newKey(pEphemeral->pCurve, &pOtherEphemeral);
            if (OK != status)
                goto exit;

            status = EC_setKeyParameters(pOtherStatic, (const ubyte *) pOtherPartysStatic, otherStaticLen, NULL, 0);
            if (OK != status)
                goto exit;           

            status = EC_setKeyParameters(pOtherEphemeral, (const ubyte *) pOtherPartysEphemeral, otherEphemeralLen, NULL, 0);
            if (OK != status)
                goto exit;

            status = ECMQV_generateSharedSecret(pStatic, pEphemeral, pOtherStatic, pOtherEphemeral, &pMQV);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_getAsByteString( pStatic->pCurve->pPF, pMQV, &pSS, (sbyte4 *) &ssLen);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;
#endif /* __DISABLE_DIGICERT_ECC_MQV__ */
        case EPHEMERAL_UNIFIED:

            if (NULL == pEphemeral || NULL == pOtherPartysEphemeral)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pEphemeral->pCurve)
                goto exit;
            
            /* calculate Z = Z_e */
            status = ECDH_generateSharedSecret(pEphemeral->pCurve, (const ubyte *) pOtherPartysEphemeral, otherEphemeralLen, pEphemeral->k, &pSS, &ssLen);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;
            
        case ONE_PASS_UNIFIED_U:

            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve || NULL == pEphemeral->pCurve)
                goto exit;

            status = ERR_EC_DIFFERENT_CURVE;
            if (pStatic->pCurve != pEphemeral->pCurve)
                goto exit;
            
            /* calculate Z_s */
            status = ECDH_generateSharedSecret(pStatic->pCurve, (const ubyte *) pOtherPartysStatic, otherStaticLen, pStatic->k, &pSS1, &ss1Len);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = ECDH_generateSharedSecret(pEphemeral->pCurve, (const ubyte *) pOtherPartysStatic, otherStaticLen, pEphemeral->k, &pSS2, &ss2Len);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = (ubyte4) (ss1Len + ss2Len);
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case ONE_PASS_UNIFIED_V:

            if (NULL == pStatic || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve)
                goto exit;
            
            /* calculate Z_s */
            status = ECDH_generateSharedSecret(pStatic->pCurve, (const ubyte *) pOtherPartysStatic, otherStaticLen, pStatic->k, &pSS1, &ss1Len);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = ECDH_generateSharedSecret(pStatic->pCurve, (const ubyte *) pOtherPartysEphemeral, otherEphemeralLen, pStatic->k, &pSS2, &ss2Len);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = (ubyte4) (ss1Len + ss2Len);
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

#ifndef __DISABLE_DIGICERT_ECC_MQV__
        case ONE_PASS_MQV_U:

            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve || NULL == pEphemeral->pCurve)
                goto exit;

            status = ERR_EC_DIFFERENT_CURVE;
            if (pStatic->pCurve != pEphemeral->pCurve)
                goto exit;

            status = EC_newKey(pStatic->pCurve, &pOtherStatic);
            if (OK != status)
                goto exit;

            status = EC_setKeyParameters(pOtherStatic, (const ubyte *) pOtherPartysStatic, otherStaticLen, NULL, 0);
            if (OK != status)
                goto exit;           

            /* ONE PASS U uses the other partys static key twice */
            status = ECMQV_generateSharedSecret(pStatic, pEphemeral, pOtherStatic, pOtherStatic, &pMQV);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_getAsByteString( pStatic->pCurve->pPF, pMQV, &pSS, (sbyte4 *) &ssLen);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case ONE_PASS_MQV_V:

            if (NULL == pStatic || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve)
                goto exit;

            status = EC_newKey(pStatic->pCurve, &pOtherStatic);
            if (OK != status)
                goto exit;

            status = EC_newKey(pStatic->pCurve, &pOtherEphemeral);
            if (OK != status)
                goto exit;

            status = EC_setKeyParameters(pOtherStatic, (const ubyte *) pOtherPartysStatic, otherStaticLen, NULL, 0);
            if (OK != status)
                goto exit;           

            status = EC_setKeyParameters(pOtherEphemeral, (const ubyte *) pOtherPartysEphemeral, otherEphemeralLen, NULL, 0);
            if (OK != status)
                goto exit;    

            /* ONE PASS V uses the our static key twice */
            status = ECMQV_generateSharedSecret(pStatic, pStatic, pOtherStatic, pOtherEphemeral, &pMQV);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_getAsByteString( pStatic->pCurve->pPF, pMQV, &pSS, (sbyte4 *) &ssLen);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;
#endif
        case ONE_PASS_DH_U:

            if (NULL == pEphemeral || NULL == pOtherPartysStatic)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pEphemeral->pCurve)
                goto exit;
            
            /* calculate Z */
            status = ECDH_generateSharedSecret(pEphemeral->pCurve, (const ubyte *) pOtherPartysStatic, otherStaticLen, pEphemeral->k, &pSS, &ssLen);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case ONE_PASS_DH_V:

            if (NULL == pStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve)
                goto exit;
            
            /* calculate Z */
            status = ECDH_generateSharedSecret(pStatic->pCurve, (const ubyte *) pOtherPartysEphemeral, otherEphemeralLen, pStatic->k, &pSS, &ssLen);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case STATIC_UNIFIED:

            if (NULL == pStatic || NULL == pOtherPartysStatic)
                goto exit;

            status = ERR_EC_UNALLOCATED_KEY;
            if (NULL == pStatic->pCurve)
                goto exit;
            
            /* calculate Z = Z_s */
            status = ECDH_generateSharedSecret(pStatic->pCurve, (const ubyte *) pOtherPartysStatic, otherStaticLen, pStatic->k, &pSS, &ssLen);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        default:
            status = ERR_INVALID_ARG;
    }

exit:

    if (NULL != pSS)
    {
        (void) DIGI_MEMSET_FREE(&pSS, ssLen);
    }

    if (NULL != pSS1)
    {
        (void) DIGI_MEMSET_FREE(&pSS1, ss1Len);
    }

    if (NULL != pSS2)
    {
        (void) DIGI_MEMSET_FREE(&pSS2, ss2Len);
    }

    if (NULL != pOtherStatic)
    {
        (void) EC_deleteKey(&pOtherStatic);
    }

    if (NULL != pOtherEphemeral)
    {
        (void) EC_deleteKey(&pOtherEphemeral);
    }

    /* MQV can only be allocated if pStatic is defined */
    if (NULL != pMQV)
    {
        (void) PRIMEFIELD_deleteElement(pStatic->pCurve->pPF, &pMQV);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_ECDH_MODES__ */
#endif /* __DISABLE_DIGICERT_ECDH__ */

/*---------------------------------------------------------------------------*/

MSTATUS
EC_newKey( PEllipticCurvePtr pEC, ECCKey** ppNewKey)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ECCKey* pNew;
    ubyte*  storage;
    ubyte4  elemSize;
    ubyte4  keySize;

    if (!pEC || !ppNewKey)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECC,pEC->pPF->curveId);

    elemSize = pEC->pPF->n * sizeof(pf_unit);

    keySize = MOC_PAD( sizeof(ECCKey), sizeof(pf_unit));

    /* allocate all the storage in one block */
    status = DIGI_CALLOC((void **) &pNew, 1, keySize + elemSize * 3);
    if (OK != status)
        goto exit;

    storage = (( ubyte*) (pNew)) + keySize;

    pNew->privateKey = FALSE;
    pNew->pCurve = pEC;
    pNew->Qx = (PFEPtr) storage;
    storage += elemSize;
    pNew->Qy = (PFEPtr) storage;
    storage += elemSize;
    pNew->k = (PFEPtr) storage;

    *ppNewKey = pNew;

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_ECC,pEC->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
EC_cloneKey( ECCKey** ppNew, const ECCKey* pSrc)
{
    MSTATUS status = OK;
    ubyte4  elemSize, keySize;
    ubyte*  storage;
    ECCKey* pNew;

    if (!ppNew || !pSrc)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = EC_newKey( pSrc->pCurve, ppNew)))
    {
        return status;
    }

    elemSize = pSrc->pCurve->pPF->n * sizeof(pf_unit);

    pNew = *ppNew;

    keySize = MOC_PAD( sizeof(ECCKey), sizeof(pf_unit));

    DIGI_MEMCPY( (ubyte*) *ppNew, (const ubyte*)pSrc, keySize + elemSize * 3);

    /* fix the internal pointers */
    storage = (( ubyte*) (pNew)) + keySize;
    pNew->Qx = (PFEPtr) storage;
    storage += elemSize;
    pNew->Qy = (PFEPtr) storage;
    storage += elemSize;
    pNew->k = (PFEPtr) storage;

    return OK;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_deleteKey(ECCKey** ppKey )
{
    FIPS_LOG_DECL_SESSION;
    ECCKey* pKey;
    ubyte4 elemSize, keySize;

    if (!ppKey || !(*ppKey))
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECC,0);

    pKey = *ppKey;

    elemSize = pKey->pCurve->pPF->n * sizeof(pf_unit);

    keySize = MOC_PAD(sizeof(ECCKey), sizeof(pf_unit));

#ifdef __ZEROIZE_TEST__
    {
        int counter = 0;

        FIPS_PRINT("\nEC Delete Key - Before Zeroization\n");
        for (counter = 0; counter < keySize + elemSize * 3; counter++)
        {
            FIPS_PRINT("%02x", *((ubyte*)pKey + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

    /* for FIPS: set all memory to zero before free */
    DIGI_MEMSET((ubyte *) pKey, 0x00, keySize + elemSize * 3);

#ifdef __ZEROIZE_TEST__
    {
        int counter = 0;

        FIPS_PRINT("\nEC Delete Key - After Zeroization\n");
        for (counter = 0; counter < keySize + elemSize * 3; counter++)
        {
            FIPS_PRINT("%02x", *((ubyte*)pKey + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

    FREE( *ppKey);
    *ppKey = 0;

    FIPS_LOG_END_ALG(FIPS_ALGO_ECC,0);
    return OK;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_equalKey(const ECCKey* pKey1, const ECCKey* pKey2, byteBoolean* res)
{
    PrimeFieldPtr pPF;

    if ( !pKey1 || !pKey2 || !res)
        return ERR_NULL_POINTER;
    if (!pKey1->pCurve || !pKey2->pCurve)
        return ERR_NULL_POINTER;

    *res = FALSE;

    /* compare only the public key part */

    /* make sure this is the same curve first */
    /* curves are singletons so comparing pointers is OK */
    if (!EC_compareEllipticCurves(pKey1->pCurve, pKey2->pCurve))
        return OK;

    pPF = pKey1->pCurve->pPF;

    *res = ( PRIMEFIELD_match(pPF, pKey1->Qx, pKey2->Qx) &&
            PRIMEFIELD_match(pPF, pKey1->Qy, pKey2->Qy));
    return OK;

}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_setKeyParameters( ECCKey* pKey, const ubyte* point, ubyte4 pointLen,
                    const ubyte* scalar, ubyte4 scalarLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    /* one of scalar or point is required, 0 length point will fail in EC_setPointToByteString */
    if (NULL == pKey || NULL == pKey->pCurve || (NULL == point && (NULL == scalar || !scalarLen)))
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECC,pKey->pCurve->pPF->curveId);

    pKey->privateKey = FALSE;

    if ( scalar && scalarLen)
    {
        if ( OK > (status = PRIMEFIELD_setToByteString( pKey->pCurve->pPF,
                                                pKey->k, scalar, scalarLen)))
        {
            goto exit;
        }
        pKey->privateKey = TRUE;
    }

    if (NULL != point)  /* we assume point is correct and just set it */
    {
        status = EC_setPointToByteString( pKey->pCurve, point, pointLen, pKey->Qx, pKey->Qy);
    }
    else   /* we calculate the point from the private key, point is NULL so scalar was not */
    {
        status = EC_multiplyPoint(pKey->pCurve->pPF, pKey->Qx, pKey->Qy,
                   pKey->k, pKey->pCurve->pPx, pKey->pCurve->pPy);
    }

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_ECC,pKey->pCurve->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS
EC_setPrivateKey( ECCKey *pKey, ubyte *pScalar, ubyte4 scalarLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    /* 0 length will fail in PRIMEFIELD_setToByteString */
    if (NULL == pKey || NULL == pKey->pCurve || NULL == pScalar)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECC,pKey->pCurve->pPF->curveId);

    if ( OK > (status = PRIMEFIELD_setToByteString( pKey->pCurve->pPF, pKey->k, pScalar, scalarLen)))
    {
        goto exit;
    }

    pKey->privateKey = TRUE;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_ECC,pKey->pCurve->pPF->curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

intBoolean
EC_compareEllipticCurves(
    PEllipticCurvePtr pEC1, PEllipticCurvePtr pEC2)
{
    if ( (NULL == pEC1) || (NULL == pEC2) )
    {
        return FALSE;
    }

    return PRIMEFIELD_comparePrimeFields(pEC1->pPF, pEC2->pPF);
}

#endif /* if (!defined(__ENABLE_MSVB_SMALL_CODE_SIZE__)) */

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static void ECDSA_triggerFail(void)
{
    ecdsa_fail = 1;
}

static FIPS_entry_fct ecdsa_table[] = {
    { ECDSA_TRIGGER_FAIL_F_ID,     (s_fct*)ECDSA_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* ECDSA_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return ecdsa_table;

    return NULL;
}

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#endif /* __ENABLE_DIGICERT_ECC__ */
