/*
 * int128.c
 *
 * Mocana Support for Int128 operations
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

#include "../common/int128.h"

/* only used for SHA 512 and SHA 384 for the moment */
#if !defined(__DISABLE_MOCANA_SHA512__) || !defined(__DISABLE_MOCANA_SHA384__)

#if __MOCANA_MAX_INT__ == 64

ubyte16 u16_Shl( ubyte16 a, ubyte4 n)
{
    if ( n > 0 )
    {
        if ( n < 64)
        {
            a.upper64 <<= n;
            a.upper64 |= ((a.lower64) >> (64-n));
            a.lower64 <<= n;
        }
        else if ( n < 128)
        {
            a.upper64 = ((a.lower64) << (n - 64));
            a.lower64 = 0;
        }
        else if ( n >= 128)
        {
            a.lower64 = a.upper64 = 0;
        }
    }
    return a;
}


void u16_Incr32( ubyte16* pa, ubyte4 b)
{
    pa->lower64 += b;
    pa->upper64 += ((pa->lower64 < b) ? 1 : 0);
}


#else

ubyte16 u16_Shl( ubyte16 a, ubyte4 n)
{
    if ( n > 0 )
    {
        if ( n < 32)
        {
            a.w1 <<= n;
            a.w1 |= ((a.w2) >> (32-n));
            a.w2 <<= n;
            a.w2 |= ((a.w3) >> (32-n));
            a.w3 <<= n;
            a.w3 |= ((a.w4) >> (32-n));
            a.w4 <<= n;
        }
        else if ( 32 == n)
        {
            a.w1 = a.w2;
            a.w2 = a.w3;
            a.w3 = a.w4;
            a.w4 = 0;
        }
        else if ( n < 64)
        {
            a.w1 = ((a.w2) << (n - 32));
            a.w1 |= ((a.w3) >> (64 - n));
            a.w2 = ((a.w3) << (n - 32));
            a.w2 |= ((a.w4) >> (64 - n));
            a.w3 = ((a.w4) << (n - 32));
            a.w4 = 0;
        }
        else if ( 64 == n)
        {
            a.w1 = a.w3;
            a.w2 = a.w4;
            a.w3 = 0;
            a.w4 = 0;
        }
        else if ( n < 96)
        {
            a.w1 = ((a.w3) << (n - 64));
            a.w1 |= ((a.w4) >> (96 - n));
            a.w2 = ((a.w4) << (n - 64));
            a.w3 = a.w4 = 0;
        }
        else if ( n < 128)
        {
            a.w1 = ((a.w4) << (n - 96));
            a.w2 = a.w3 = a.w4 = 0;
        }
        else if ( n >= 128)
        {
            a.w1 = a.w2 = a.w3 = a.w4 = 0;
        }
    }
    return a;
}


void u16_Incr32( ubyte16* pa, ubyte4 b)
{
    pa->w4 += b;
    if ( pa->w4 < b)
    {
        ++(pa->w3);
        if ( 0 == pa->w3)
        {
            ++(pa->w2);
            if ( 0 == pa->w2)
            {
                ++(pa->w1);
            }
        }
    }
}

#endif /* __ENABLE_MOCANA_64_BIT__ */

#endif /* __DISABLE_MOCANA_SHA512__ */
