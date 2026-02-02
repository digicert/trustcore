/*
 * arc2.c
 *
 * "alleged rc2" algorithm
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

#if (defined(__ENABLE_ARC2_CIPHERS__) && !defined(__ARC2_HARDWARE_CIPHER__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../crypto/arc2.h"


/*------------------------------------------------------------------*/

/**********************************************************************\
* Expand a variable-length user key (between 1 and 128 bytes) to a     *
* 64-short working rc2 key, of at most "bits" effective key bits.      *
* The effective key bits parameter looks like an export control hack.  *
* For normal use, it should always be set to 1024.  For convenience,   *
* zero is accepted as an alias for 1024.                               *
\**********************************************************************/
void
rc2_keyschedule(ubyte2 xkey[64],
                     const ubyte *key,
                     ubyte4 len,
                     ubyte4 bits )
{
    ubyte x;
    ubyte4 i;
    /* 256-entry permutation table, probably derived somehow from pi */
    static const ubyte permute[256] =
    {
        217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
        198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
         23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
        189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
         84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
         18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
        111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
        248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
          8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
        150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
        194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
        153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
         45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
        211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
         13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
        197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
    };

    /* assert(len > 0 && len <= 128); */
    /* assert(bits <= 1024); */
    if (!bits)
    {
        bits = 1024;
    }

    DIGI_MEMCPY((ubyte*)xkey, key, len);

    /* Phase 1: Expand input key to 128 bytes */
    if (len < 128)
    {
        i = 0;
        x = ((ubyte *)xkey)[len-1];
        do
        {
            x = permute[(x + ((ubyte *)xkey)[i++]) & 255];
            ((ubyte *)xkey)[len++] = x;

        } while (len < 128);
    }

    /* Phase 2 - reduce effective key size to "bits" */
    len = (bits+7) >> 3;
    i = 128-len;
    x = permute[((ubyte *)xkey)[i] & (255 >> (7 & (0 - bits)))];
    ((ubyte *)xkey)[i] = x;

    while (i--)
    {
        x = permute[ x ^ ((ubyte *)xkey)[i+len] ];
        ((ubyte *)xkey)[i] = x;
    }

    /* Phase 3 - copy to xkey in little-endian order */
    i = 63;

    do
    {
        xkey[i] =  (ubyte2)(((ubyte2)((ubyte *)xkey)[2*i]) + (((ubyte2)(((ubyte *)xkey)[2*i+1])) << 8));

    } while (i--);
}


/*------------------------------------------------------------------*/

extern void
rc2_encrypt(const ubyte2 xkey[64], const ubyte *plain, ubyte *cipher)
{
    ubyte4 x76, x54, x32, x10, i;

    x76 = (((ubyte4)plain[7]) << 8) + (ubyte4)plain[6];
    x54 = (((ubyte4)plain[5]) << 8) + (ubyte4)plain[4];
    x32 = (((ubyte4)plain[3]) << 8) + (ubyte4)plain[2];
    x10 = (((ubyte4)plain[1]) << 8) + (ubyte4)plain[0];

    for (i = 0; i < 16; i++)
    {
        x10 += (x32 & ~x76) + (x54 & x76) + xkey[4*i+0];
        x10 = (x10 << 1) + (x10 >> 15 & 1);

        x32 += (x54 & ~x10) + (x76 & x10) + xkey[4*i+1];
        x32 = (x32 << 2) + (x32 >> 14 & 3);

        x54 += (x76 & ~x32) + (x10 & x32) + xkey[4*i+2];
        x54 = (x54 << 3) + (x54 >> 13 & 7);

        x76 += (x10 & ~x54) + (x32 & x54) + xkey[4*i+3];
        x76 = (x76 << 5) + (x76 >> 11 & 31);

        if (i == 4 || i == 10)
        {
            x10 += (ubyte4)xkey[x76 & 63];
            x32 += (ubyte4)xkey[x10 & 63];
            x54 += (ubyte4)xkey[x32 & 63];
            x76 += (ubyte4)xkey[x54 & 63];
        }
    }

    cipher[0] = (ubyte)x10;
    cipher[1] = (ubyte)(x10 >> 8);
    cipher[2] = (ubyte)x32;
    cipher[3] = (ubyte)(x32 >> 8);
    cipher[4] = (ubyte)x54;
    cipher[5] = (ubyte)(x54 >> 8);
    cipher[6] = (ubyte)x76;
    cipher[7] = (ubyte)(x76 >> 8);
}


/*------------------------------------------------------------------*/

extern void
rc2_decrypt(const ubyte2 xkey[64], ubyte *plain, const ubyte *cipher)
{
    ubyte4 x76, x54, x32, x10, i;

    x76 = ((ubyte4)cipher[7] << 8) + (ubyte4)cipher[6];
    x54 = ((ubyte4)cipher[5] << 8) + (ubyte4)cipher[4];
    x32 = ((ubyte4)cipher[3] << 8) + (ubyte4)cipher[2];
    x10 = ((ubyte4)cipher[1] << 8) + (ubyte4)cipher[0];

    i = 15;
    do
    {
        x76 &= 65535;
        x76 = (x76 << 11) + (x76 >> 5);
        x76 -= (x10 & ~x54) + (x32 & x54) + xkey[4*i+3];

        x54 &= 65535;
        x54 = (x54 << 13) + (x54 >> 3);
        x54 -= (x76 & ~x32) + (x10 & x32) + xkey[4*i+2];

        x32 &= 65535;
        x32 = (x32 << 14) + (x32 >> 2);
        x32 -= (x54 & ~x10) + (x76 & x10) + xkey[4*i+1];

        x10 &= 65535;
        x10 = (x10 << 15) + (x10 >> 1);
        x10 -= (x32 & ~x76) + (x54 & x76) + xkey[4*i+0];

        if (i == 5 || i == 11)
        {
            x76 -= xkey[x54 & 63];
            x54 -= xkey[x32 & 63];
            x32 -= xkey[x10 & 63];
            x10 -= xkey[x76 & 63];
        }
    } while (i--);

    plain[0] = (ubyte)x10;
    plain[1] = (ubyte)(x10 >> 8);
    plain[2] = (ubyte)x32;
    plain[3] = (ubyte)(x32 >> 8);
    plain[4] = (ubyte)x54;
    plain[5] = (ubyte)(x54 >> 8);
    plain[6] = (ubyte)x76;
    plain[7] = (ubyte)(x76 >> 8);
}


#ifdef _ARC2TEST_

/* TEST CODE BELOW */
/* -- test vectors from RFC2268 -- */

typedef struct RC2Test
{
    ubyte4 keyLen;
    ubyte4 effectiveBits;
    ubyte* key;
    ubyte* plainText;
    ubyte* cipherText;
} RC2Test;

RC2Test gTests[] =
{
    { 8, 63,
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xeb\xb7\x73\xf9\x93\x27\x8e\xff"},
    { 8, 64,
        "\xff\xff\xff\xff\xff\xff\xff\xff",
        "\xff\xff\xff\xff\xff\xff\xff\xff",
        "\x27\x8b\x27\xe4\x2e\x2f\x0d\x49"},
    { 8, 64,
        "\x30\x00\x00\x00\x00\x00\x00\x00",
        "\x10\x00\x00\x00\x00\x00\x00\x01",
        "\x30\x64\x9e\xdf\x9b\xe7\xd2\xc2" },
    { 1, 64,
        "\x88",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x61\xa8\xa2\x44\xad\xac\xcc\xf0" },
    { 7, 64,
        "\x88\xbc\xa9\x0e\x90\x87\x5a",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x6c\xcf\x43\x08\x97\x4c\x26\x7f" },
    { 16, 64,
        "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x1a\x80\x7d\x27\x2b\xbe\x5d\xb1" },
    { 16, 128,
        "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x22\x69\x55\x2a\xb0\xf8\x5c\xa6" },
    { 33, 129,
        "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2"
        "\x16\xf8\x0a\x6f\x85\x92\x05\x84\xc4\x2f\xce\xb0\xbe\x25\x5d\xaf\x1e",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x5b\x78\xd3\xa4\x3d\xff\xf1\xf1" }
};

int gNumTests = sizeof( gTests) / sizeof ( gTests[0]);

int DoTest( const RC2Test* pTest)
{
    ubyte2 xkey[64];
    ubyte output[RC2_BLOCK_SIZE];
    sbyte4 res;
    int retVal = 0;

    rc2_keyschedule( xkey, pTest->key, pTest->keyLen, pTest->effectiveBits);
    /* encrypt test */
    rc2_encrypt( xkey, pTest->plainText, output);

    DIGI_CTIME_MATCH( output, pTest->cipherText, RC2_BLOCK_SIZE, &res);

    if ( res != 0) { ++retVal; }

    /* decrypt test */
    rc2_decrypt( xkey, output, output); /* use the same buffer */
    DIGI_CTIME_MATCH( output, pTest->plainText, RC2_BLOCK_SIZE, &res);
    if ( res != 0) { ++retVal; }

    rc2_encrypt( xkey, output, output); /* use the same buffer */
    DIGI_CTIME_MATCH( output, pTest->cipherText, RC2_BLOCK_SIZE, &res);
    if ( res != 0) { ++retVal; }

    return retVal;
}

int main( int argc, char* argv[])
{
    int retVal = 0;
    int i;
    for ( i = 0; i < gNumTests; ++i)
    {
        retVal += DoTest( gTests+i);
    }
    printf("Completed with %d errors\n", retVal);
    return retVal;
}

#endif

#endif /* (defined(__ENABLE_ARC2_CIPHERS__) && !defined(__ARC2_HARDWARE_CIPHER__)) */
