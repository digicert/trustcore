/*
 * primefld_priv.h
 *
 * Prime Field Arithmetic -- Private data types definitions
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

#ifndef __PRIMEFLD_PRIV_HEADER__
#define __PRIMEFLD_PRIV_HEADER__

#if (defined(__ENABLE_MOCANA_ECC__) || defined(__ENABLE_MOCANA_RSA_SIMPLE__))

#include "../common/vlong.h"

#ifdef __cplusplus
extern "C" {
#endif

/* we should typedef the "word" used to represent numbers in the prime field */
/* the code is not cleaned up yet (i.e. ubyte4 is used instead of pf_unit ) */
#ifdef __ENABLE_MOCANA_64_BIT__
typedef ubyte8 pf_unit;
#else
typedef ubyte4 pf_unit;
#endif

/* use with extreme caution. Buffers must have the proper size k
and k + 1 for pN and pMu */
MOC_EXTERN MSTATUS BI_modExp( sbyte4 k, pf_unit* pResult, const pf_unit* pN,
  ubyte4 e, const pf_unit* pModulo, const pf_unit* pMu);
MOC_EXTERN MSTATUS BI_modExpEx( sbyte4 k, pf_unit pResult[/*k*/], 
    const pf_unit pN[/*2*k*/], sbyte4 eLen, const pf_unit pE[/*eLen*/],
    const pf_unit pModulo[/*k+1*/], const pf_unit pMu[/*k+1*/]);
MOC_EXTERN MSTATUS BI_barrettMu( sbyte4 k, pf_unit mu[/*k+1*/],
  const pf_unit modulus[/*k+1*/]);
MOC_EXTERN sbyte4 BI_cmp(sbyte4 n, const pf_unit* a, const pf_unit* b);
MOC_EXTERN pf_unit BI_add( sbyte4 n, pf_unit* a_s, const pf_unit* b);
MOC_EXTERN pf_unit BI_sub( sbyte4 n, pf_unit* a_s, const pf_unit* b);
MOC_EXTERN void BI_mul( sbyte4 n, pf_unit hilo[/*2*n*/],
  const pf_unit a[/*n*/], const pf_unit b[/*n*/],
  sbyte4 x_limit);
MOC_EXTERN MSTATUS BI_barrettReduction( sbyte4 n,
  pf_unit c[/*2*n*/],
  pf_unit r[/*n*/],
  pf_unit mulBuffer[/*2*n+2*/],
  const pf_unit mu[/*n+1*/],
  const pf_unit m[/*n+1*/]);
MOC_EXTERN MSTATUS BI_modularInverse(sbyte4 n, const pf_unit a[/*n*/],
  const pf_unit m[/*n*/],
  pf_unit inv[/*n*/]);
MOC_EXTERN void BI_setUnitsToByteString( sbyte4 n, pf_unit* a,
  const ubyte* b, sbyte4 bLen);
MOC_EXTERN void BI_shiftREx( sbyte4 n, pf_unit* a_s, sbyte4 shift);

#if (defined(__ENABLE_MOCANA_ECC__))

/*------------------------------------------------------------------------*/
/* Multiplication routines */
MOC_EXTERN MSTATUS PRIMEFIELD_multiplyAux( PrimeFieldPtr pField, PFEPtr pProduct,
  ConstPFEPtr pA, ConstPFEPtr pB, pf_unit* hilo);
MOC_EXTERN MSTATUS PRIMEFIELD_squareAux( PrimeFieldPtr pField, PFEPtr pProduct,
  ConstPFEPtr pA, pf_unit* hilo);

MOC_EXTERN MSTATUS PRIMEFIELD_exp(PrimeFieldPtr pField, PFEPtr pResult, ConstPFEPtr pA,
  ConstPFEPtr pExp, pf_unit* hilo);


/*---------------------------------------------------------------------------*/

/* data types */

typedef void (*PRIMEFIELD_reduceFun)( const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField);

/* Implements PRIMEFIELD_reduceFun.
 */
MOC_EXTERN void fastReductionP192 (
  const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField
  );

MOC_EXTERN void fastReductionP224 (
  const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField
  );

MOC_EXTERN void fastReductionP256 (
  const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField
  );

MOC_EXTERN void fastReductionP384 (
  const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField
  );
    
MOC_EXTERN void fastReductionP448 (
  const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField
  );

MOC_EXTERN void fastReductionP521 (
  const pf_unit* toReduce,
  pf_unit* reduce,
  PrimeFieldPtr pField
  );

/*---------------------------------------------------------------------------*/

struct PrimeField
{
  const pf_unit*          units; /*.i.e prime p */
  const pf_unit*          p1d4; /* (p+1)/4 */
  sbyte4                  n;
  ubyte4                  numBits;
  PRIMEFIELD_reduceFun    reduceFun;      /* to reduce a big number */
  ubyte4                  curveId;
};


struct PFE
{
  pf_unit  units[1];
};

#ifdef __ENABLE_MOCANA_ECC_P192__
extern const struct PrimeField PrimeFieldP192;
#endif

#ifndef __DISABLE_MOCANA_ECC_P224__
extern const struct PrimeField PrimeFieldP224;
#endif

#ifndef __DISABLE_MOCANA_ECC_P256__
extern const struct PrimeField PrimeFieldP256;
#endif

#ifndef __DISABLE_MOCANA_ECC_P384__
extern const struct PrimeField PrimeFieldP384;
#endif
    
#if defined(__ENABLE_MOCANA_ECC_EDDSA_448__) || defined(__ENABLE_MOCANA_ECC_EDDH_448__) || defined(__ENABLE_MOCANA_FIPS_MODULE__)
extern const struct PrimeField PrimeFieldP448;
#endif

#ifndef __DISABLE_MOCANA_ECC_P521__
extern const struct PrimeField PrimeFieldP521;
#endif

#endif /* if defined(__ENABLE_MOCANA_ECC) */

#ifdef __cplusplus
}
#endif

#endif /* if (defined(__ENABLE_MOCANA_ECC__) etc. */
#endif
