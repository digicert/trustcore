/*
 * neon.h
 *
 * Routines using the ARM NEON instructions.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
