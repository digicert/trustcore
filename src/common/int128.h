/*
 * int128.h
 *
 * Support for 128 bit integer
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

/*------------------------------------------------------------------*/

#ifndef __INT128_HEADER__
#define __INT128_HEADER__

MOC_EXTERN ubyte16 u16_Shl( ubyte16 a, ubyte4 n);
MOC_EXTERN void u16_Incr32( ubyte16* pa, ubyte4 b);

#if __DIGICERT_MAX_INT__ == 64
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
