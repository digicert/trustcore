/*
 * int64.c
 *
 * Mocana Support for Int64 operations
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

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"

#include "../common/int64.h"


#if __DIGICERT_MAX_INT__ < 64

ubyte8 u8_Not( ubyte8 a)
{
    a.upper32 = ~(a.upper32);
    a.lower32 = ~(a.lower32);
    return a;
}

ubyte8 u8_Shl( ubyte8 a, ubyte4 n)
{
    if ( n > 0 )
    {
        if ( n < 32)
        {
            a.upper32 <<= n;
            a.upper32 |= ((a.lower32) >> (32-n));
            a.lower32 <<= n;
        }
        else if ( n < 64)
        {
            a.upper32 = ((a.lower32) << (n - 32));
            a.lower32 = 0;
        }
        else if ( n >= 64)
        {
            a.lower32 = a.upper32 = 0;
        }
    }
    return a;
}

ubyte8 u8_Shr( ubyte8 a, ubyte4 n)
{
    if ( n > 0 )
    {
        if ( n < 32)
        {
            a.lower32 >>= n;
            a.lower32 |= ((a.upper32) << (32-n));
            a.upper32 >>= n;
        }
        else if ( n < 64)
        {
            a.lower32 = ((a.upper32) >> (n - 32));
            a.upper32 = 0;
        }
        else if ( n >= 64)
        {
            a.lower32 = a.upper32 = 0;
        }
    }
    return a;
}

ubyte8 u8_Add( ubyte8 a, ubyte8 b)
{
    a.lower32 += b.lower32;
    a.upper32 += (b.upper32) + (( a.lower32 < b.lower32) ? 1 : 0);
    return a;
}

ubyte8 u8_Add32( ubyte8 a, ubyte4 b)
{
    a.lower32 += b;
    a.upper32 += (( a.lower32 < b) ? 1 : 0);
    return a;
}


void u8_Incr( ubyte8* pa, ubyte8 b)
{
    pa->lower32 += b.lower32;
    pa->upper32 += (b.upper32) + (( pa->lower32 < b.lower32) ? 1 : 0);
}

void u8_Incr32( ubyte8* pa, ubyte4 b)
{
    pa->lower32 += b;
    pa->upper32 += (( pa->lower32 < b) ? 1 : 0);
}

ubyte8 u8_And( ubyte8 a, ubyte8 b)
{
    a.lower32 &= b.lower32;
    a.upper32 &= b.upper32;
    return a;
}

ubyte8 u8_Or( ubyte8 a, ubyte8 b)
{
    a.lower32 |= b.lower32;
    a.upper32 |= b.upper32;
    return a;
}

ubyte8 u8_Xor( ubyte8 a, ubyte8 b)
{
    a.lower32 ^= b.lower32;
    a.upper32 ^= b.upper32;
    return a;
}

#endif
