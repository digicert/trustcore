/*
 * int64.h
 *
 * Support for 64 bit integers
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

#ifndef __INT64_HEADER__
#define __INT64_HEADER__



#if __DIGICERT_MAX_INT__ == 64
#define ZERO_U8(a) (a) = 0
#define ISZERO_U8(a) (0 == (a))
#define INCR_U8(a) (++(a))
#define LOW_U8(a)  ((ubyte4) ((a) & 0xFFFFFFFF))
#define HI_U8(a)   ((ubyte4) (((a)>>32) & 0xFFFFFFFF))
/* Preferable not to use U8INIT for 64 bit */
#define U8INIT(u,h,l)   u = ((((ubyte8)h) << 32) | (l))
#define U8INIT_LO(u,l)  u = ((u & 0xffffffff00000000ull) | (l))
#define U8INIT_HI(u,h)  u = ((u & 0xffffffffull) | (((ubyte8)h) << 32))
#define U8INT(h,l)  ((((ubyte8)h) << 32) | (l))

/* use macros instead of function since compiler can't match speed */
#define u8_Not(a)           (~ ((ubyte8)a) )
#define u8_Shl(a,n)         ( ((ubyte8) a) << (n))
#define u8_Shr(a,n)         ( ((ubyte8) a) >> (n))
#define u8_Add(a, b)        ( ((ubyte8) a) + ((ubyte8)b) )
#define u8_Add32(a, b)      ( ((ubyte8) a) + ((ubyte8)b) )
#define u8_Incr(pa, b)      ( *((ubyte8*)pa) += ((ubyte8)b) )
#define u8_Incr32(pa, b)    ( *((ubyte8*)pa) += ((ubyte8)b) )
#define u8_And(a, b)        (  ((ubyte8) a) & ((ubyte8) b) )
#define u8_Or(a, b)         (  ((ubyte8) a) | ((ubyte8) b) )
#define u8_Xor(a, b)        (  ((ubyte8) a) ^ ((ubyte8) b) )

#else
#define ZERO_U8(a)      (a).lower32 = (a).upper32 = 0
#define ISZERO_U8(a)    ((0 == (a).lower32) && (0 == (a).upper32))
#define INCR_U8(a)      u8_Incr32(&(a), 1);
#define LOW_U8(a)       (a).lower32
#define HI_U8(a)        (a).upper32
#define U8INIT(u,h,l)   (u).upper32 = (h); (u).lower32 = (l)
#define U8INIT_LO(u,l)  (u).lower32 = (l)
#define U8INIT_HI(u,h)  (u).upper32 = (h)
#define U8INT(h,l)   { (h), (l) }

MOC_EXTERN ubyte8 u8_Not( ubyte8 a);
MOC_EXTERN ubyte8 u8_Shl( ubyte8 a, ubyte4 n);
MOC_EXTERN ubyte8 u8_Shr( ubyte8 a, ubyte4 n);
MOC_EXTERN ubyte8 u8_Add( ubyte8 a, ubyte8 b);
MOC_EXTERN ubyte8 u8_Add32( ubyte8 a, ubyte4 b);
MOC_EXTERN void u8_Incr( ubyte8* pa, ubyte8 b);
MOC_EXTERN void u8_Incr32( ubyte8* pa, ubyte4 b);
MOC_EXTERN ubyte8 u8_And( ubyte8 a, ubyte8 b);
MOC_EXTERN ubyte8 u8_Or( ubyte8 a, ubyte8 b);
MOC_EXTERN ubyte8 u8_Xor( ubyte8 a, ubyte8 b);

#endif /* __ENABLE_DIGICERT_64_BIT__ */


#endif
