/*
 * cast128_test.c
 *
 * unit test for cast128.c
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/cast128.h"

#include "../../common/absstream.h"
#include "../../common/tree.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/crypto.h"
#include "../../crypto/pkcs5.h"

#include "../../harness/harness.h"
#include "../../../unit_tests/unittest.h"

/* From RFC 2144 :

B.1. Single Plaintext-Key-Ciphertext Sets

   In order to ensure that the algorithm is implemented correctly, the
   following test vectors can be used for verification (values given in
   hexadecimal notation).

   128-bit key         = 01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A
           plaintext   = 01 23 45 67 89 AB CD EF
           ciphertext  = 23 8B 4F E5 84 7E 44 B2

   80-bit  key         = 01 23 45 67 12 34 56 78 23 45
                       = 01 23 45 67 12 34 56 78 23 45 00 00 00 00 00 00
           plaintext   = 01 23 45 67 89 AB CD EF
           ciphertext  = EB 6A 71 1A 2C 02 27 1B

   40-bit  key         = 01 23 45 67 12
                       = 01 23 45 67 12 00 00 00 00 00 00 00 00 00 00 00
           plaintext   = 01 23 45 67 89 AB CD EF
           ciphertext  = 7A C8 16 D1 6E 9B 30 2E

B.2. Full Maintenance Test

   A maintenance test for CAST-128 has been defined to verify the
   correctness of implementations.  It is defined in pseudo-code as
   follows, where a and b are 128-bit vectors, aL and aR are the
   leftmost and rightmost halves of a, bL and bR are the leftmost and
   rightmost halves of b, and encrypt(d,k) is the encryption in ECB mode
   of block d under key k.

   Initial a = 01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A (hex)
   Initial b = 01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A (hex)

   do 1,000,000 times
   {
       aL = encrypt(aL,b)
       aR = encrypt(aR,b)
       bL = encrypt(bL,a)
       bR = encrypt(bR,a)
   }

Verify a == EE A9 D0 A2 49 FD 3B A6 B3 43 6F B8 9D 6D CA 92 (hex)
Verify b == B2 C9 5E B0 0C 31 AD 71 80 AC 05 B8 E8 3D 69 6E (hex)


*/ 

/*------------------------------------------------------------------*/

#ifdef __ENABLE_CAST128_CIPHER__

static void cast128_maintenance_round( ubyte* block, ubyte* key)
{
    cast128_ctx ctx;

    CAST128_initKey( &ctx, key, 16);
    CAST128_encryptBlock( &ctx, block, block);
    CAST128_encryptBlock( &ctx, block+8, block+8);
}
#endif



/*------------------------------------------------------------------*/

int cast128_test_maintenance()
{
#ifdef __ENABLE_CAST128_CIPHER__
    ubyte a[] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 
                  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };

    ubyte b[] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 
                  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };

    const ubyte final_a[] = { 0xEE, 0xA9, 0xD0, 0xA2, 0x49, 0xFD, 0x3B, 0xA6, 
                              0xB3, 0x43, 0x6F, 0xB8, 0x9D, 0x6D, 0xCA, 0x92 };

    const ubyte final_b[] = { 0xB2, 0xC9, 0x5E, 0xB0, 0x0C, 0x31, 0xAD, 0x71,
                              0x80, 0xAC, 0x05, 0xB8, 0xE8, 0x3D, 0x69, 0x6E };

    sbyte4 i, res;
    int retVal = 0;

    for (i = 0; i < 1000000; ++i)
    {
        cast128_maintenance_round(a, b);
        cast128_maintenance_round(b, a);        
    }
 
    DIGI_MEMCMP(a, final_a, 16, &res);
    retVal += UNITTEST_INT(0, res, 0);

    DIGI_MEMCMP(b, final_b, 16, &res);
    retVal += UNITTEST_INT(0, res, 0);

    return retVal;
#else

    return 0;
#endif
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_CAST128_CIPHER__

typedef struct 
{
    sbyte4 keySize;
    ubyte ect[CAST128_BLOCK_SIZE];
} cast128_single_test_case;


cast128_single_test_case gTests[] = 
{
    { 16, { 0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2}},
    { 10, { 0xEB, 0x6A, 0x71, 0x1A, 0x2C, 0x02, 0x27, 0x1B}},
    {5, {0x7A, 0xC8, 0x16, 0xD1, 0x6E, 0x9B, 0x30, 0x2E}}
};

int single_cast128_test(int hint, const ubyte* k, sbyte4 keySize, 
                        ubyte* ept, ubyte* ect)
{
    int retVal;
    ubyte res[CAST128_BLOCK_SIZE];
    cast128_ctx key;
    sbyte4 resCmp;

    CAST128_initKey(&key, k, keySize);

    CAST128_encryptBlock( &key, ept, res);
    DIGI_MEMCMP( res, ect, CAST128_BLOCK_SIZE, &resCmp);
    retVal = UNITTEST_INT(hint, resCmp, 0);

    CAST128_decryptBlock( &key, ect, res);
    DIGI_MEMCMP( res, ept, CAST128_BLOCK_SIZE, &resCmp);
    retVal += UNITTEST_INT( hint, resCmp, 0);

    return retVal;
}
#endif

/*------------------------------------------------------------------*/

int cast128_test_single()
{
#ifdef __ENABLE_CAST128_CIPHER__
    ubyte k[] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 
                  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };

    ubyte pt[] = {  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    int retVal = 0;
    sbyte4 i;

    for (i = 0; i < COUNTOF(gTests); ++i)
    {
        retVal += single_cast128_test(i, k, gTests[i].keySize,
                                      pt, gTests[i].ect);
    }

    return retVal;
#else
    return 0;
#endif
}

