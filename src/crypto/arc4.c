/*
 * arc4.c
 *
 * "alleged rc4" algorithm
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

/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (!defined(__DISABLE_ARC4_CIPHERS__) && !defined(__ARC4_HARDWARE_CIPHER__))

#include "../crypto/arc4.h"

#define SWAP_BYTE( a, b) { ubyte __swap; __swap = a; a = b; b = __swap; }

void prepare_key(ubyte *key_data_ptr, sbyte4 key_data_len, rc4_key *key)
{
    ubyte index1;
    ubyte index2;
    ubyte* state;
    short counter;

    state = key->state;
    for(counter = 0; counter < 256; counter++)
    {
        state[counter] = (ubyte)counter;
    }
    key->x = 0;
    key->y = 0;
    index1 = 0;
    index2 = 0;
    for (counter = 0; counter < 256; counter++)
    {
        index2 = (ubyte)(key_data_ptr[index1] + state[counter] + index2);
        SWAP_BYTE(state[counter], state[index2]);
        index1 = (ubyte)((index1 + 1) % key_data_len);
    }
}

#if !defined(__ENABLE_DIGICERT_64_BIT__)
void rc4(ubyte *buffer_ptr, sbyte4 buffer_len, rc4_key *key)
#else
static void rc4_8(ubyte *buffer_ptr, sbyte4 buffer_len, rc4_key *key)
#endif
{
    ubyte x, state_x;
    ubyte y, state_y;
    ubyte* state;
    ubyte xorIndex;
    sbyte4 counter;

    x = key->x;
    y = key->y;

    state = key->state;
    for(counter = 0; counter < buffer_len; counter ++)
    {
        x = (ubyte)(x + 1);
        state_x = state[x];
        y = (ubyte)(state_x + y);
        state_y = state[y];

        state[x] = state_y;
        state[y] = state_x;

        xorIndex = (ubyte)(state_x + state_y);

        buffer_ptr[counter] ^= state[xorIndex];
    }

    key->x = x;
    key->y = y;
}

#if defined(__ENABLE_DIGICERT_64_BIT__)

/* accumulating the xor bytes and prefetching is what seems to
make the speed go up. Doing one without the other does not seem to
help. Also adapting this code for 32 bit does not seem to improve
performance! */

#define RC4_LOOP(w, v,state_w, state_v,i) \
            (state_w) = state[w]; \
            xorIndex = (ubyte) ((state_v)+state_y); \
            state[v] = (ubyte) state_y; \
            cache.bVal[i] = state[xorIndex]; \
            y = (ubyte) (y + (state_w)); \
            state_y = state[y]; \
            (v) = (ubyte) ((w) + 1) ; \
            state[y] = (ubyte) (state_w);


typedef union arc4_64_state
{
    ubyte8 lVal;
    ubyte  bVal[8];
} arc4_64_state;

/*--------------------------------------------------------------------------*/

static void rc4_64(ubyte *buffer, sbyte4 len, rc4_key *key)
{
    ubyte state_x, state_y;
    sbyte4 len8, counter;
    ubyte x, y;
    ubyte* state;

    state = key->state;
    x = key->x ;
    y = key->y ;

    x = (ubyte) (x + 1);
    state_x = state[x];
    y = (ubyte) (y + state_x);

    len8 = (len - 8) >> 3;
    if(len8 > 0)
    {
        arc4_64_state cache;
        ubyte next_x, next_state_x, xorIndex;
        ubyte8* buffer8;
        sbyte4 totalChunkLen;

        buffer8 = (ubyte8*) buffer;
        state_y = state[y];
        state[y] = (ubyte) state_x;
        next_x = (ubyte) (x + 1);

        for (counter = 0; counter < len8; ++counter)
        {
            RC4_LOOP(next_x,x,next_state_x,state_x,0);
            RC4_LOOP(x,next_x,state_x,next_state_x,1);
            RC4_LOOP(next_x,x,next_state_x,state_x,2);
            RC4_LOOP(x,next_x,state_x,next_state_x,3);
            RC4_LOOP(next_x,x,next_state_x,state_x,4);
            RC4_LOOP(x,next_x,state_x,next_state_x,5);
            RC4_LOOP(next_x,x,next_state_x,state_x,6);
            RC4_LOOP(x,next_x,state_x,next_state_x,7);

            *buffer8++ ^= cache.lVal;
        }

        totalChunkLen = (len8 << 3);
        buffer += totalChunkLen;
        len -= totalChunkLen;

        next_state_x = state[next_x];
        xorIndex = (ubyte) (state_x + state_y);
        state[x] = (ubyte) state_y;
        y = (ubyte) (y + next_state_x);
        *buffer++ ^= (ubyte) (state[xorIndex]);
        --len;

        x = next_x;
        state_x = next_state_x;
    }

    for (counter = 0; counter < len; ++counter)
    {
        state_y = state[y];
        state[y] = (ubyte) state_x;
        state[x] = (ubyte) state_y;
        x = (ubyte) (x + 1);
        *buffer++ ^= state[(ubyte)(state_x+state_y) ];
        state_x = state[x];
        y = (ubyte) (y + state_x);
    }

    key->y = (y - state_x) & 0xff;
    key->x = (x - 1) & 0xff;
}


void rc4(ubyte *buffer, sbyte4 len, rc4_key *key)
{
    if (len < 16)
    {
        rc4_8(buffer, len, key);
    }
    else
    {
        sbyte4 pad =  8 - (((ubyte8) ((uintptr)buffer)) & 7);
        if (pad < 8)
        {
            rc4_8( buffer, pad, key);
            len -= pad;
            buffer += pad;
        }

        rc4_64( buffer, len, key);
    }
}

#endif /* defined(__ENABLE_DIGICERT_64_BIT__) */


#endif /* (!defined(__DISABLE_ARC4_CIPHERS__) && !defined(__ARC4_HARDWARE_CIPHER__)) */

