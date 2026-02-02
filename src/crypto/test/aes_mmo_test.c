/*
 * aes_mmo_test.c
 *
 * unit test for aes_mmo.c
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

/* Uses the currently defined moptions.h */
#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../aes_mmo.c"
#include "../../../unit_tests/unittest.h"

typedef struct AES_MMO_TestVector
{
    const ubyte*    message;
    sbyte4          messageLen;
    const ubyte     mac[AES_BLOCK_SIZE];

} AES_MMO_TestVector;


static AES_MMO_TestVector mmoTV[] =
{
    /* Test vectors from Zigbee spec */
    /* 1 */
    {
         "\xc0",
        1,
        {
            0xae, 0x3a, 0x10, 0x2a, 0x28, 0xd4, 0x3e, 0xe0,
            0xd4, 0xa0, 0x9e, 0x22, 0x78, 0x8b, 0x20, 0x6c
        }
    },

    /* 2 */
    {
         "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf",
        16,
        {
            0xa7, 0x97, 0x7e, 0x88, 0xbc, 0x0b, 0x61, 0xe8,
            0x21, 0x08, 0x27, 0x10, 0x9a, 0x22, 0x8f, 0x2d
        }
    }
};


/*---------------------------------------------------------------------------*/

static int
test_vector_test(AES_MMO_TestVector* pWhichTest, int hint)
{
    AES_MMO_CTX ctx;
    int         errors = 0;
    sbyte4      i, cmpRes;
    ubyte       mac[AES_MMO_DIGESTSIZE];
    MSTATUS     status;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    /* special case */
    if ( 0 == pWhichTest->messageLen)
    {
        status = AES_MMO_init(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);

        status = AES_MMO_final(MOC_SYM(hwAccelCtx) &ctx, mac);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_MMO_DIGESTSIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);

        goto exit;
    }

    /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
    for (i = 1; i <= pWhichTest->messageLen; ++i)
    {
        sbyte4 sent = 0;

        status = AES_MMO_init(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = AES_MMO_update(MOC_SYM(hwAccelCtx)
                        &ctx, pWhichTest->message + sent, toSend);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;
        }
        DIGI_MEMSET(mac, 0, AES_MMO_DIGESTSIZE);
        status = AES_MMO_final(MOC_SYM(hwAccelCtx) &ctx, mac);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_MMO_DIGESTSIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return errors;
}


/*---------------------------------------------------------------------------*/

int aes_mmo_test_vectors()
{
    int retVal = 0;
    int i;

    for (i = 0; i < COUNTOF(mmoTV); ++i)
    {
        retVal +=  test_vector_test( mmoTV+i, i);
    }

    return retVal;
}


/*--------------------------------------------------------------------------------*/

//main()
//{
//    aes_mmo_test_vectors();
//}
