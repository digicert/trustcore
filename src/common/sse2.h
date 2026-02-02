/*
 * sse2.h
 *
 * Routines using the Intel SSE2 instructions.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __SSE2_HEADER__
#define __SSE2_HEADER__

#if __SSE2__

#ifdef __cplusplus
extern "C" {
#endif
    MOC_EXTERN void SSE2_ADD_64(ubyte4* r, ubyte4* dest);
    MOC_EXTERN void SSE2_ADD_DOUBLE(ubyte4* h, ubyte4* r);
    MOC_EXTERN void SSE2_multiply_00( const ubyte4 *a, const ubyte4* b,ubyte4 *result);
    MOC_EXTERN void SSE2_multiply_01( const ubyte4 *a, const ubyte4* b,ubyte4 *result);
    MOC_EXTERN void SSE2_multiply_10( const ubyte4 *a, const ubyte4* b,ubyte4 *result);
    MOC_EXTERN void SSE2_multiply_11( const ubyte4 *a, const ubyte4* b,ubyte4 *result);


#ifdef __cplusplus
}
#endif

#endif /* __SSE2__ */

#endif /* __SSE2_HEADER__ */
