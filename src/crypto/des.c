/*
 * des.c
 *
 * DES Encipher & Decipher
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

/**
@file       des.c
@brief      C source code for the NanoCrypto DES API.
@details    This file contains the NanoCrypto DES API functions.

@copydoc    overview_des

@flags
To enable the DES functions, define the following flag:
+ \c \__ENABLE_DES_CIPHER__
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DES_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (((defined(__ENABLE_DES_CIPHER__)) || \
     (!defined(__DISABLE_3DES_CIPHERS__)))) || \
     defined(__ENABLE_DES_ALGORITHM__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/des.h"

/*------------------------------------------------------------------*/

#define EN0 0 /* MODE == encrypt */
#define DE1 1 /* MODE == decrypt */

/*------------------------------------------------------------------*/

static void deskey(const ubyte *, sbyte2, ubyte4 *destKey);
static void desfunc(ubyte4 *, ubyte4 *);
static void cookey(ubyte4 *, ubyte4 *);

/*------------------------------------------------------------------*/

static const ubyte2 bytebit[8] =
{
    0200, 0100, 040, 020, 010, 04, 02, 01
};

static const ubyte4 bigbyte[24] =
{
    0x800000L, 0x400000L, 0x200000L, 0x100000L,
    0x80000L, 0x40000L, 0x20000L, 0x10000L,
    0x8000L, 0x4000L, 0x2000L, 0x1000L,
    0x800L, 0x400L, 0x200L, 0x100L,
    0x80L, 0x40L, 0x20L, 0x10L,
    0x8L, 0x4L, 0x2L, 0x1L
};

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */
static const ubyte pc1[56] =
{
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
};

static const ubyte totrot[16] =
{
    1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
};

static const ubyte pc2[48] =
{
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
};

/*------------------------------------------------------------------*/

static void
deskey(const ubyte *key, sbyte2 edf, ubyte4 *destKey)
{
    register ubyte4 i, j, l, m, n;
    ubyte pc1m[56] = { 0 }, pcr[56] = { 0 };
    ubyte4 kn[32]= { 0 };

    for ( j = 0; j < 56; j++ )
    {
        l = pc1[j];
        m = l & 07;
        pc1m[j] = (ubyte)((key[l >> 3] & bytebit[m]) ? 1 : 0);
    }

    for( i = 0; i < 16; i++ )
    {
        if (edf == DE1)
            m = (15 - i) << 1;
        else
            m = i << 1;

        n = m + 1;
        kn[m] = kn[n] = 0L;

        for( j = 0; j < 28; j++ )
        {
            l = j + totrot[i];

            if (l < 28)
                pcr[j] = pc1m[l];
            else if ((l - 28) < 56)
                pcr[j] = pc1m[l - 28];
        }

        for( j = 28; j < 56; j++ )
        {
            l = j + totrot[i];

            if (l < 56)
                pcr[j] = pc1m[l];
            else if ((l - 28) < 56)
                pcr[j] = pc1m[l - 28];
        }

        for( j = 0; j < 24; j++ )
        {
            if (pcr[pc2[j]])
                kn[m] |= bigbyte[j];

            if (pcr[pc2[j+24]])
                kn[n] |= bigbyte[j];
        }
    }

    cookey(kn, destKey);

    return;
}


/*------------------------------------------------------------------*/

static void
cookey(register ubyte4 *raw1, ubyte4 *destKey)
{
    register ubyte4 *cook, *raw0;
    register sbyte4 i;

    cook = destKey;

    for (i = 0; i < 16; i++, raw1++)
    {
        raw0 = raw1++;
        *cook = (*raw0 & 0x00fc0000) << 6;
        *cook |= (*raw0 & 0x00000fc0) << 10;
        *cook |= (*raw1 & 0x00fc0000) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0) >> 6;
        *cook = (*raw0 & 0x0003f000) << 12;
        *cook |= (*raw0 & 0x0000003f) << 16;
        *cook |= (*raw1 & 0x0003f000) >> 4;
        *cook++ |= (*raw1 & 0x0000003f);
    }

    return;
}


/*------------------------------------------------------------------*/

static const ubyte4 DES_SP1[64] =
{
    0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
    0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
    0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
    0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
    0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
    0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
    0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
    0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
    0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
    0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
    0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
    0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
    0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
    0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L
};

static const ubyte4 DES_SP2[64] =
{
    0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
    0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
    0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
    0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
    0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
    0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
    0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
    0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
    0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
    0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
    0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
    0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
    0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
    0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
    0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
    0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L
};

static const ubyte4 DES_SP3[64] =
{
    0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
    0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
    0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
    0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
    0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
    0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
    0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
    0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
    0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
    0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
    0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
    0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
    0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
    0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
    0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
    0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L
};

static const ubyte4 DES_SP4[64] =
{
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
    0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
    0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
    0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
    0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
    0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
    0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
    0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
    0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L
};

static const ubyte4 DES_SP5[64] =
{
    0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
    0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
    0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
    0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
    0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
    0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
    0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
    0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
    0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
    0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
    0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
    0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
    0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
    0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
    0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
    0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L
};

static const ubyte4 DES_SP6[64] =
{
    0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
    0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
    0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
    0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
    0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
    0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
    0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
    0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
    0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
    0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
    0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
    0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
    0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
    0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L
};

static const ubyte4 DES_SP7[64] =
{
    0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
    0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
    0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
    0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
    0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
    0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
    0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
    0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
    0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
    0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
    0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
    0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
    0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
    0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
    0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
    0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L
};

static const ubyte4 DES_SP8[64] =
{
    0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
    0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
    0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
    0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
    0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
    0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
    0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
    0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
    0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
    0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
    0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
    0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
    0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
    0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
    0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
    0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L
};


/*------------------------------------------------------------------*/

static void
desfunc(register ubyte4 *block, register ubyte4 *keys)
{
    register ubyte4 fval, work, right, leftt;
    register sbyte4 round;

    leftt = block[0];
    right = block[1];

    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);
    right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;

    for( round = 0; round < 8; round++ )
    {
        work = (right << 28) | (right >> 4);
        work ^= *keys++;
        fval = DES_SP7[ work & 0x3fL];
        fval |= DES_SP5[(work >> 8) & 0x3fL];
        fval |= DES_SP3[(work >> 16) & 0x3fL];
        fval |= DES_SP1[(work >> 24) & 0x3fL];
        work = right ^ *keys++;
        fval |= DES_SP8[ work & 0x3fL];
        fval |= DES_SP6[(work >> 8) & 0x3fL];
        fval |= DES_SP4[(work >> 16) & 0x3fL];
        fval |= DES_SP2[(work >> 24) & 0x3fL];
        leftt ^= fval;
        work = (leftt << 28) | (leftt >> 4);
        work ^= *keys++;
        fval = DES_SP7[ work & 0x3fL];
        fval |= DES_SP5[(work >> 8) & 0x3fL];
        fval |= DES_SP3[(work >> 16) & 0x3fL];
        fval |= DES_SP1[(work >> 24) & 0x3fL];
        work = leftt ^ *keys++;
        fval |= DES_SP8[ work & 0x3fL];
        fval |= DES_SP6[(work >> 8) & 0x3fL];
        fval |= DES_SP4[(work >> 16) & 0x3fL];
        fval |= DES_SP2[(work >> 24) & 0x3fL];
        right ^= fval;
    }

    right = (right << 31) | (right >> 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = (leftt << 31) | (leftt >> 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);

    *block++ = right;
    *block = leftt;

    return;
}


/*------------------------------------------------------------------*/

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/
extern MSTATUS
DES_initKey(des_ctx *p_desContext, const ubyte *pKey, sbyte4 keyLen)
{
    /* ignore keyLen for DES */
    MSTATUS status = OK;

    if ((NULL == p_desContext) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (DES_KEY_LENGTH != keyLen)
    {
        status = ERR_DES_BAD_KEY_LENGTH;
        goto exit;
    }

    deskey(pKey,EN0,p_desContext->ek);
    deskey(pKey,DE1,p_desContext->dk);

exit:
    return status;

} /* DES_initKey */


/*------------------------------------------------------------------*/

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/
extern MSTATUS
DES_encipher(des_ctx *p_desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes)
{
    ubyte4  halfBlocks[2];                           /* two half blocks */
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    MSTATUS status = OK;

    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (blocks * DES_BLOCK_SIZE != numBytes)
    {
        /* numBytes MUST be a multiple of DES_BLOCK_SIZE */
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    while (0 < blocks)
    {
        halfBlocks[0]  = (ubyte4)pSrc[0] << 24;
        halfBlocks[0] |= (ubyte4)pSrc[1] << 16;
        halfBlocks[0] |= (ubyte4)pSrc[2] <<  8;
        halfBlocks[0] |= (ubyte4)pSrc[3];

        halfBlocks[1]  = (ubyte4)pSrc[4] << 24;
        halfBlocks[1] |= (ubyte4)pSrc[5] << 16;
        halfBlocks[1] |= (ubyte4)pSrc[6] <<  8;
        halfBlocks[1] |= (ubyte4)pSrc[7];

        desfunc(halfBlocks, p_desContext->ek);

        pDest[0] = (ubyte)(halfBlocks[0] >> 24);
        pDest[1] = (ubyte)(halfBlocks[0] >> 16);
        pDest[2] = (ubyte)(halfBlocks[0] >>  8);
        pDest[3] = (ubyte)(halfBlocks[0]);

        pDest[4] = (ubyte)(halfBlocks[1] >> 24);
        pDest[5] = (ubyte)(halfBlocks[1] >> 16);
        pDest[6] = (ubyte)(halfBlocks[1] >>  8);
        pDest[7] = (ubyte)(halfBlocks[1]);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

exit:
    return status;

} /* DES_encipher */


/*------------------------------------------------------------------*/

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/
extern MSTATUS
DES_decipher(des_ctx *p_desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes)
{
    ubyte4  halfBlocks[2];                           /* two half blocks */
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    MSTATUS status = OK;

    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (blocks * DES_BLOCK_SIZE != numBytes)
    {
        /* numBytes MUST be a multiple of DES_BLOCK_SIZE */
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    while (0 < blocks)
    {
        halfBlocks[0]  = (ubyte4)pSrc[0] << 24;
        halfBlocks[0] |= (ubyte4)pSrc[1] << 16;
        halfBlocks[0] |= (ubyte4)pSrc[2] <<  8;
        halfBlocks[0] |= (ubyte4)pSrc[3];

        halfBlocks[1]  = (ubyte4)pSrc[4] << 24;
        halfBlocks[1] |= (ubyte4)pSrc[5] << 16;
        halfBlocks[1] |= (ubyte4)pSrc[6] <<  8;
        halfBlocks[1] |= (ubyte4)pSrc[7];

        desfunc(halfBlocks,p_desContext->dk);

        pDest[0] = (ubyte)(halfBlocks[0] >> 24);
        pDest[1] = (ubyte)(halfBlocks[0] >> 16);
        pDest[2] = (ubyte)(halfBlocks[0] >>  8);
        pDest[3] = (ubyte)(halfBlocks[0]);

        pDest[4] = (ubyte)(halfBlocks[1] >> 24);
        pDest[5] = (ubyte)(halfBlocks[1] >> 16);
        pDest[6] = (ubyte)(halfBlocks[1] >>  8);
        pDest[7] = (ubyte)(halfBlocks[1]);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

exit:
    return status;

} /* DES_decipher */

/*------------------------------------------------------------------*/

MSTATUS DES_clearKey(des_ctx *p_desContext)
{
    /* DIGI_MEMSET will handle NULL check of p_desContext */
    return DIGI_MEMSET((ubyte *)p_desContext, 0x00, sizeof(des_ctx));
}

/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DES_CIPHER__) && (!defined(__DES_HARDWARE_CIPHER__))))

static MSTATUS
DES_encipherCBC(des_ctx* p_desContext, ubyte *pSrc,
                ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte4  halfBlocks[2];
    ubyte4  ivBlock0;
    ubyte4  ivBlock1;
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    MSTATUS status = OK;

    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (blocks * DES_BLOCK_SIZE != numBytes)
    {
        /* numBytes MUST be a multiple of DES_BLOCK_SIZE */
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    ivBlock0  = (ubyte4)pIV[0] << 24;
    ivBlock0 |= (ubyte4)pIV[1] << 16;
    ivBlock0 |= (ubyte4)pIV[2] << 8;
    ivBlock0 |= (ubyte4)pIV[3];

    ivBlock1  = (ubyte4)pIV[4] << 24;
    ivBlock1 |= (ubyte4)pIV[5] << 16;
    ivBlock1 |= (ubyte4)pIV[6] << 8;
    ivBlock1 |= (ubyte4)pIV[7];

    while (0 < blocks)
    {
        halfBlocks[0]  = (ubyte4)pSrc[0] << 24;
        halfBlocks[0] |= (ubyte4)pSrc[1] << 16;
        halfBlocks[0] |= (ubyte4)pSrc[2] <<  8;
        halfBlocks[0] |= (ubyte4)pSrc[3];

        halfBlocks[1]  = (ubyte4)pSrc[4] << 24;
        halfBlocks[1] |= (ubyte4)pSrc[5] << 16;
        halfBlocks[1] |= (ubyte4)pSrc[6] <<  8;
        halfBlocks[1] |= (ubyte4)pSrc[7];

        halfBlocks[0] ^= ivBlock0;
        halfBlocks[1] ^= ivBlock1;

        desfunc(halfBlocks, p_desContext->ek);

        ivBlock0 = halfBlocks[0];
        ivBlock1 = halfBlocks[1];

        pDest[0] = (ubyte)(halfBlocks[0] >> 24);
        pDest[1] = (ubyte)(halfBlocks[0] >> 16);
        pDest[2] = (ubyte)(halfBlocks[0] >>  8);
        pDest[3] = (ubyte)(halfBlocks[0]);

        pDest[4] = (ubyte)(halfBlocks[1] >> 24);
        pDest[5] = (ubyte)(halfBlocks[1] >> 16);
        pDest[6] = (ubyte)(halfBlocks[1] >>  8);
        pDest[7] = (ubyte)(halfBlocks[1]);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

    pIV[0] = (ubyte)(ivBlock0 >> 24);
    pIV[1] = (ubyte)(ivBlock0 >> 16);
    pIV[2] = (ubyte)(ivBlock0 >> 8);
    pIV[3] = (ubyte)(ivBlock0);

    pIV[4] = (ubyte)(ivBlock1 >> 24);
    pIV[5] = (ubyte)(ivBlock1 >> 16);
    pIV[6] = (ubyte)(ivBlock1 >> 8);
    pIV[7] = (ubyte)(ivBlock1);

exit:
    return status;

} /* DES_encipherCBC */


/*------------------------------------------------------------------*/

static MSTATUS
DES_decipherCBC(des_ctx* p_desContext, ubyte *pSrc,
                ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte4  halfBlocks[2];
    ubyte4  ivBlock0;
    ubyte4  ivBlock1;
    ubyte4  tmpBlock0;
    ubyte4  tmpBlock1;
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    MSTATUS status = OK;

    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (blocks * DES_BLOCK_SIZE != numBytes)
    {
        /* numBytes MUST be a multiple of DES_BLOCK_SIZE */
        status = ERR_BLOWFISH_BAD_LENGTH;
        goto exit;
    }

    ivBlock0  = (ubyte4)pIV[0] << 24;
    ivBlock0 |= (ubyte4)pIV[1] << 16;
    ivBlock0 |= (ubyte4)pIV[2] << 8;
    ivBlock0 |= (ubyte4)pIV[3];

    ivBlock1  = (ubyte4)pIV[4] << 24;
    ivBlock1 |= (ubyte4)pIV[5] << 16;
    ivBlock1 |= (ubyte4)pIV[6] << 8;
    ivBlock1 |= (ubyte4)pIV[7];

    while (0 < blocks)
    {
        halfBlocks[0]  = (ubyte4)pSrc[0] << 24;
        halfBlocks[0] |= (ubyte4)pSrc[1] << 16;
        halfBlocks[0] |= (ubyte4)pSrc[2] <<  8;
        halfBlocks[0] |= (ubyte4)pSrc[3];

        halfBlocks[1]  = (ubyte4)pSrc[4] << 24;
        halfBlocks[1] |= (ubyte4)pSrc[5] << 16;
        halfBlocks[1] |= (ubyte4)pSrc[6] <<  8;
        halfBlocks[1] |= (ubyte4)pSrc[7];

        tmpBlock0 = halfBlocks[0];
        tmpBlock1 = halfBlocks[1];

        desfunc(halfBlocks, p_desContext->dk);

        halfBlocks[0] ^= ivBlock0;
        halfBlocks[1] ^= ivBlock1;

        ivBlock0 = tmpBlock0;
        ivBlock1 = tmpBlock1;

        pDest[0] = (ubyte)(halfBlocks[0] >> 24);
        pDest[1] = (ubyte)(halfBlocks[0] >> 16);
        pDest[2] = (ubyte)(halfBlocks[0] >>  8);
        pDest[3] = (ubyte)(halfBlocks[0]);

        pDest[4] = (ubyte)(halfBlocks[1] >> 24);
        pDest[5] = (ubyte)(halfBlocks[1] >> 16);
        pDest[6] = (ubyte)(halfBlocks[1] >>  8);
        pDest[7] = (ubyte)(halfBlocks[1]);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

    pIV[0] = (ubyte)(ivBlock0 >> 24);
    pIV[1] = (ubyte)(ivBlock0 >> 16);
    pIV[2] = (ubyte)(ivBlock0 >> 8);
    pIV[3] = (ubyte)(ivBlock0);

    pIV[4] = (ubyte)(ivBlock1 >> 24);
    pIV[5] = (ubyte)(ivBlock1 >> 16);
    pIV[6] = (ubyte)(ivBlock1 >> 8);
    pIV[7] = (ubyte)(ivBlock1);

exit:
    return status;

} /* DES_decipherCBC */


/*------------------------------------------------------------------*/

extern BulkCtx
CreateDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    des_ctx* p_desContext = (des_ctx*) MALLOC(sizeof(des_ctx));
    MOC_UNUSED(encrypt);

    if (NULL != p_desContext)
    {
        DIGI_MEMSET((ubyte *)p_desContext, 0x00, sizeof(des_ctx));

        if (OK > DES_initKey(p_desContext, keyMaterial, keyLength))
        {
            FREE(p_desContext);  p_desContext = NULL;
        }
    }

    return p_desContext;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DeleteDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    des_ctx *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(des_ctx));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(des_ctx));
    if (OK != status)
        goto exit;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DoDES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    des_ctx*    pDesContext = (des_ctx *)ctx;
    MSTATUS     status;

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = DES_encipherCBC(pDesContext, data, data, dataLength, iv);
    else
        status = DES_decipherCBC(pDesContext, data, data, dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT,(sbyte*) "DoDES: cipher failed, error = ", status);
#endif

exit:
    return status;
}

#endif /* ((defined(__ENABLE_DES_CIPHER__) && (!defined(__DES_HARDWARE_CIPHER__))) */

#endif /* (((defined(__ENABLE_DES_CIPHER__)) || \
        (!defined(__DISABLE_3DES_CIPHERS__)))) */
