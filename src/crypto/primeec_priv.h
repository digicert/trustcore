/*
 * primeec_priv.h
 *
 * Prime Field Elliptic Curve Cryptography -- Private data types definitions
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

#ifndef __PRIMEEC_PRIV_HEADER__
#define __PRIMEEC_PRIV_HEADER__

#if defined(__ENABLE_MOCANA_ECC__)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Reduced an integer by the order of a curve's large cyclic group.
 *
 * @details Reduced an integer, stored as a prime field element, in-place, by the order of
 *          the associated curve's large cyclic group.
 *
 * @param pEC    The globally defined prime curve in question.
 * @param x      The integer to be reduced, stored as a prime field element.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS EC_modOrder( PEllipticCurvePtr pEC, PFEPtr x);

/* NIST curves */
struct PrimeEllipticCurve
{
    PrimeFieldPtr       pPF;
    ConstPFEPtr         pPx;  /* point */
    ConstPFEPtr         pPy;
    ConstPFEPtr         b;    /* b parameter, a = -3 */
    ConstPFEPtr         n;    /* order of point */
    ConstPFEPtr         mu;   /* special barrett constant */
#ifdef __ENABLE_MOCANA_FIPS_MODULE__
    ubyte4              h;    /* cofactor */
#endif
};

#ifdef __cplusplus
}
#endif

#endif
#endif

