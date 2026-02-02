/*
 * pkcs5_test.c
 *
 * unit test for pkcs5.c
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
#include "../pkcs5.c"

#include "../../../unit_tests/unittest.h"

/* Test vectors from RFC 3962 */
typedef struct PKCS5_TestVector
{
    ubyte4 iterationCount;
    sbyte* password;
    sbyte* salt;
    ubyte* output;
} PKCS5_TestVector;

PKCS5_TestVector gTestVectors[] = 
{
    {   
        1,
        (sbyte*) "password",
        (sbyte*) "ATHENA.MIT.EDUraeburn",
        (ubyte*) "\xcd\xed\xb5\x28\x1b\xb2\xf8\x01\x56\x5a\x11\x22\xb2\x56\x35\x15"
                 "\x0a\xd1\xf7\xa0\x4b\xb9\xf3\xa3\x33\xec\xc0\xe2\xe1\xf7\x08\x37"
    },
    {   
        2,
        (sbyte*) "password",
        (sbyte*) "ATHENA.MIT.EDUraeburn",
        (ubyte*) "\x01\xdb\xee\x7f\x4a\x9e\x24\x3e\x98\x8b\x62\xc7\x3c\xda\x93\x5d"
                 "\xa0\x53\x78\xb9\x32\x44\xec\x8f\x48\xa9\x9e\x61\xad\x79\x9d\x86"
    },
    {
        1200,
        (sbyte*) "password",
        (sbyte*) "ATHENA.MIT.EDUraeburn",
        (ubyte*) "\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"
                 "\xa7\xe5\x2d\xdb\xc5\xe5\x14\x2f\x70\x8a\x31\xe2\xe6\x2b\x1e\x13"
    },
    {
        5,
        (sbyte*) "password",
        (sbyte*) "\x12\x34\x56\x78\x78\x56\x34\x12",
        (ubyte*) "\xd1\xda\xa7\x86\x15\xf2\x87\xe6\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"
                 "\x3f\x98\xd2\x03\xe6\xbe\x49\xa6\xad\xf4\xfa\x57\x4b\x6e\x64\xee"
    }, 
    {
        1200,
        (sbyte*) "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        (sbyte*) "pass phrase equals block size",
        (ubyte*) "\x13\x9c\x30\xc0\x96\x6b\xc3\x2b\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"
                 "\xc5\xec\x59\xf1\xa4\x52\xf5\xcc\x9a\xd9\x40\xfe\xa0\x59\x8e\xd1"
     },
     { 
        1200,
        (sbyte*) "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        (sbyte*) "pass phrase exceeds block size",
        (ubyte*) "\x9c\xca\xd6\xd4\x68\x77\x0c\xd5\x1b\x10\xe6\xa6\x87\x21\xbe\x61"
                 "\x1a\x8b\x4d\x28\x26\x01\xdb\x3b\x36\xbe\x92\x46\x91\x5e\xc8\x2a"
     },
     {
        50,
        (sbyte*) "\xf0\x9d\x84\x9e",
        (sbyte*) "EXAMPLE.COMpianist",
        (ubyte*) "\x6b\x9c\xf2\x6d\x45\x45\x5a\x43\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"
                 "\xe7\xfe\x37\xa0\xc4\x1e\x02\xc2\x81\xff\x30\x69\xe1\xe9\x4f\x52"
     }
};

int pkcs5_test_pbkdf2()
{
    int i, retVal = 0;
    sbyte4 res;
    ubyte output[32] = {0};
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    for (i = 0; i < COUNTOF(gTestVectors); ++i)
    {
        ubyte4 pwLen, saltLen;

        pwLen = DIGI_STRLEN(gTestVectors[i].password);
        saltLen = DIGI_STRLEN(gTestVectors[i].salt);

        retVal += UNITTEST_STATUS( i, 
            PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx) gTestVectors[i].salt, saltLen, 
                                   gTestVectors[i].iterationCount,
                                   ht_sha1, gTestVectors[i].password,
                                   pwLen, 32, output));

        DIGI_MEMCMP( gTestVectors[i].output, output, 32, &res);
        retVal += UNITTEST_INT(i, res, 0);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}