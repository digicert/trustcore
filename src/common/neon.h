/*
 * neon.h
 *
 * Routines using the ARM NEON instructions.
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

#ifndef __NEON_HEADER__
#define __NEON_HEADER__

#if __ARM_NEON__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN void NEON_INIT();
MOC_EXTERN void NEON_INIT2();
MOC_EXTERN void NEON_MULT(ubyte4* a, ubyte4* b);
MOC_EXTERN void NEON_MULT2(ubyte4* a, ubyte4* b);
MOC_EXTERN void NEON_FINAL(ubyte4* r);
MOC_EXTERN void NEON_ADD_DOUBLE();

#ifdef __cplusplus
}
#endif

#endif /* __ARM_NEON__ */

#endif /* __NEON_HEADER__ */
