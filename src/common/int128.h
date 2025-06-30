/*
 * int128.h
 *
 * Support for 128 bit integer
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

/*------------------------------------------------------------------*/

#ifndef __INT128_HEADER__
#define __INT128_HEADER__

MOC_EXTERN ubyte16 u16_Shl( ubyte16 a, ubyte4 n);
MOC_EXTERN void u16_Incr32( ubyte16* pa, ubyte4 b);

#if __MOCANA_MAX_INT__ == 64
#define ZERO_U16(a) (a).upper64 = (a).lower64 = 0
#define U16INIT( U16, U81, U82) (U16).upper64 = U81; (U16).lower64 = U82
#define W1_U16(a) ((ubyte4) ((((a).upper64) >> 32 ) & 0xFFFFFFFF))
#define W2_U16(a) ((ubyte4) (((a).upper64  & 0xFFFFFFFF)))
#define W3_U16(a) ((ubyte4) ((((a).lower64) >> 32 ) & 0xFFFFFFFF))
#define W4_U16(a) ((ubyte4) (((a).lower64  & 0xFFFFFFFF)))
#else
#define ZERO_U16(a) (a).w1 = (a).w2 = (a).w3 = (a).w4 = 0
#define U16INIT( U16, U41, U42, U43, U44)   (U16).w1 = (U41); (U16).w2 = (U42); \
                                            (U16).w3 = (U43); (U16).w4 = (U44)
#define W1_U16(a) (a).w1
#define W2_U16(a) (a).w2
#define W3_U16(a) (a).w3
#define W4_U16(a) (a).w4

#endif

#endif
