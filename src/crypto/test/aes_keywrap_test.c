/*
 *  aes_keywrap_test.c
 *
 *   unit test for aes_keywrap.c
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
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../hw_accel.h"
#include "../aes_keywrap.h"
#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

/* TestVectors from RFC3394 
4.1 Wrap 128 bits of Key Data with a 128-bit KEK

   Input:
   KEK:            000102030405060708090A0B0C0D0E0F
   Key Data:       00112233445566778899AABBCCDDEEFF

   Output:
   Ciphertext:  1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5

   Plaintext  A6A6A6A6A6A6A6A6 0011223344556677 8899AABBCCDDEEFF

   Output:
   Key Data:  00112233445566778899AABBCCDDEEFF

4.2 Wrap 128 bits of Key Data with a 192-bit KEK

   Input:
   KEK:        000102030405060708090A0B0C0D0E0F1011121314151617
   Key Data:   00112233445566778899AABBCCDDEEFF
   Output:
   Ciphertext:  96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D

   Plaintext A6A6A6A6A6A6A6A6 0011223344556677 8899AABBCCDDEEFF

   Output:
   Key Data:  00112233445566778899AABBCCDDEEFF

4.3 Wrap 128 bits of Key Data with a 256-bit KEK

   Input:
   KEK:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
   Key Data:    00112233445566778899AABBCCDDEEFF
   Output:
   Ciphertext:  64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7

   Plaintext A6A6A6A6A6A6A6A6 0011223344556677 8899AABBCCDDEEFF

   Output:
   Key Data:  00112233445566778899AABBCCDDEEFF

4.4 Wrap 192 bits of Key Data with a 192-bit KEK

   Input:
   KEK:       000102030405060708090A0B0C0D0E0F1011121314151617
   Key Data:  00112233445566778899AABBCCDDEEFF0001020304050607

   Output:
   Ciphertext  031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93
               6BA814915C6762D2


   Plaintext  A6A6A6A6A6A6A6A6 0011223344556677
              8899AABBCCDDEEFF 0001020304050607
   Output:
   Key Data:  00112233445566778899AABBCCDDEEFF0001020304050607


4.5 Wrap 192 bits of Key Data with a 256-bit KEK

   Input:
   KEK:
     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
   Key Data:    00112233445566778899AABBCCDDEEFF0001020304050607

   Ciphertext   A8F9BC1612C68B3F F6E6F4FBE30E71E4
                769C8B80A32CB895 8CD5D17D6B254DA1

   Plaintext  A6A6A6A6A6A6A6A6 0011223344556677
              8899AABBCCDDEEFF 0001020304050607
   Output:
   Key Data:  00112233445566778899AABBCCDDEEFF0001020304050607

4.6 Wrap 256 bits of Key Data with a 256-bit KEK

   Input:
   KEK:
     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
   Key Data:
     00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F



   Output:
   Ciphertext  28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326
               CBC7F0E71A99F43B FB988B9B7A02DD21

   Plaintext  A6A6A6A6A6A6A6A6 0011223344556677 8899AABBCCDDEEFF
              0001020304050607 08090A0B0C0D0E0F

   Output:
   Key Data:
        00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F

*/

typedef struct AESKeywrapTestVector
{
    const char* KEK;
    const char* Key;
    const char* WrappedKey;
} AESKeywrapTestVector;


AESKeywrapTestVector gAESKeywrapVectors[] =
{
    {
        "000102030405060708090A0B0C0D0E0F",
        "00112233445566778899AABBCCDDEEFF",
        "1FA68B0A8112B447" "AEF34BD8FB5A7B82" "9D3E862371D2CFE5"
    },
    {
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF",
        "96778B25AE6CA435" "F92B5B97C050AED2" "468AB8A17AD84E5D"
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF",
        "64E8C3F9CE0F5BA2" "63E9777905818A2A" "93C8191E7D6E8AE7"
    },
    {
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "031D33264E15D332" "68F24EC260743EDC" "E1C6C7DDEE725A93"
        "6BA814915C6762D2"
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "A8F9BC1612C68B3F" "F6E6F4FBE30E71E4"
        "769C8B80A32CB895" "8CD5D17D6B254DA1"
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "28C9F404C4B810F4" "CBCCB35CFB87F826" "3F5786E2D80ED326"
        "CBC7F0E71A99F43B" "FB988B9B7A02DD21"
     }
};



AESKeywrapTestVector gAESKeywrapExVectors[] =
{
    {
        "5840df6e29b02af1" "ab493b705bf16ea1" "ae8338f4dcc176a8",
        "c37b7e6492584340" "bed1220780894115" "5068f738",
        "138bdeaa9b8fa7fc" "61f97742e72248ee" "5ae6ae5360d1ae6a"
        "5f54f373fa543b6a"
    },

    {
        "5840df6e29b02af1" "ab493b705bf16ea1" "ae8338f4dcc176a8",
        "466f7250617369",
        "afbeb0f07dfbf541" "9200f2ccb50bb24f"
    }
};



/*---------------------------------------------------------------------------*/

static int AESKeywrapTest( MOC_SYM(hwAccelDescr hwAccelCtx) int hint, 
                           const AESKeywrapTestVector* pTestVector)
{
    int retVal = 0;
    ubyte* kek = 0;
    ubyte4 kekLen;
    ubyte* key = 0;
    ubyte4 keyLen;
    ubyte* wrapKey = 0;
    ubyte4 wrapKeyLen;
    ubyte result[40];
    ubyte4 resultLen;
    sbyte4 resCmp;
    MSTATUS status;

    kekLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->KEK, &kek);
    keyLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->Key, &key);
    wrapKeyLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->WrappedKey, &wrapKey);

    retVal += UNITTEST_TRUE(hint, wrapKeyLen == keyLen + 8);
    retVal += UNITTEST_STATUS(hint, AESKWRAP_encrypt(MOC_SYM(hwAccelCtx)
                                kek, kekLen, key, keyLen, result));

    DIGI_MEMCMP( result, wrapKey, wrapKeyLen, &resCmp);
    retVal += UNITTEST_TRUE(hint, 0 == resCmp);

    /* decrypt with legacy API */
    retVal += UNITTEST_STATUS(hint, AESKWRAP_decrypt(MOC_SYM(hwAccelCtx)
                                kek, kekLen, wrapKey, wrapKeyLen, result));

    DIGI_MEMCMP( result, key, keyLen, &resCmp);
    retVal += UNITTEST_TRUE(hint, 0 == resCmp);

    /* decrypt with new API */
    retVal += UNITTEST_STATUS(hint, AESKWRAP_decryptEx(MOC_SYM(hwAccelCtx)
                                                       kek, kekLen,
                                                       wrapKey, wrapKeyLen,
                                                       result, &resultLen));

    retVal += UNITTEST_TRUE(hint, resultLen == keyLen);
    DIGI_MEMCMP( result, key, keyLen, &resCmp);
    retVal += UNITTEST_TRUE(hint, 0 == resCmp);
    
    /* negative test */
    *wrapKey ^= (1 << (hint & 7));

    status = AESKWRAP_decrypt(MOC_SYM(hwAccelCtx) kek, kekLen,
                              wrapKey, wrapKeyLen, result);

    retVal += UNITTEST_TRUE(hint, status < OK);

    FREE(kek);
    FREE(key);
    FREE(wrapKey);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int aes_keywrap_test_vectors()
{
    int retVal = 0;
    int i;
    hwAccelDescr hwAccelCtx;

    retVal += UNITTEST_STATUS(0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    for (i = 0; i < COUNTOF(gAESKeywrapVectors); ++i)
    {
        retVal += AESKeywrapTest( MOC_SYM(hwAccelCtx) i, gAESKeywrapVectors+i);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*---------------------------------------------------------------------------*/

static int AESKeywrapExTest( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
                             const AESKeywrapTestVector* pTestVector)
{
    int retVal = 0;
    ubyte* kek = 0;
    ubyte4 kekLen;
    ubyte* key = 0;
    ubyte4 keyLen;
    ubyte* wrapKey = 0;
    ubyte4 wrapKeyLen;
    ubyte result[40];
    ubyte4 resultLen;
    ubyte* encrypted = 0;
    ubyte4 encryptedLen;
    sbyte4 resCmp;
    MSTATUS status;

    kekLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->KEK, &kek);
    keyLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->Key, &key);
    wrapKeyLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->WrappedKey, &wrapKey);

    retVal += UNITTEST_STATUS(hint, AESKWRAP_encryptEx(MOC_SYM(hwAccelCtx)
                                                       kek, kekLen, key, keyLen,
                                                       &encrypted, &encryptedLen));

    retVal += UNITTEST_TRUE(hint, wrapKeyLen == encryptedLen);
    DIGI_MEMCMP( encrypted, wrapKey, wrapKeyLen, &resCmp);
    retVal += UNITTEST_TRUE(hint, 0 == resCmp);

    retVal += UNITTEST_STATUS(hint, AESKWRAP_decryptEx(MOC_SYM(hwAccelCtx)
                                                       kek, kekLen,
                                                       wrapKey, wrapKeyLen,
                                                       result, &resultLen));

    retVal += UNITTEST_TRUE(hint, resultLen == keyLen);
    DIGI_MEMCMP( result, key, keyLen, &resCmp);
    retVal += UNITTEST_TRUE(hint, 0 == resCmp);

    /* negative test */
    *wrapKey ^= (1 << (hint & 7));

    status = AESKWRAP_decryptEx(MOC_SYM(hwAccelCtx) kek, kekLen,
                                wrapKey, wrapKeyLen, result, &resultLen);

    retVal += UNITTEST_TRUE(hint, status < OK);

    FREE(kek);
    FREE(key);
    FREE(wrapKey);
    FREE(encrypted);

    return retVal;
}



/*---------------------------------------------------------------------------*/

static int AESKeywrapExTest2( MOC_SYM(hwAccelDescr hwAccelCtx) int hint,
                              const AESKeywrapTestVector* pTestVector)
{
    int retVal = 0;
    ubyte* kek = 0;
    ubyte4 kekLen;
    ubyte* key = 0;
    ubyte4 keyLen;
    ubyte result[40];
    ubyte4 resultLen;
    ubyte* encrypted = 0;
    ubyte4 encryptedLen;
    sbyte4 resCmp;
    MSTATUS status;

    kekLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->KEK, &kek);
    keyLen = UNITTEST_UTILS_str_to_byteStr(pTestVector->Key, &key);

    retVal += UNITTEST_STATUS(hint, AESKWRAP_encryptEx(MOC_SYM(hwAccelCtx)
                                                       kek, kekLen, key, keyLen,
                                                       &encrypted, &encryptedLen));


    retVal += UNITTEST_STATUS(hint, AESKWRAP_decryptEx(MOC_SYM(hwAccelCtx)
                                                       kek, kekLen,
                                                       encrypted,
                                                       encryptedLen,
                                                       result,
                                                       &resultLen));

    retVal += UNITTEST_TRUE(hint, resultLen == keyLen);
    DIGI_MEMCMP( result, key, keyLen, &resCmp);
    retVal += UNITTEST_TRUE(0, 0 == resCmp);


    FREE(kek);
    FREE(key);
    FREE(encrypted);

    return retVal;
}

static int AESKeywrapDecSpecialTest(MOC_SYM(hwAccelDescr hwAccelCtx) int hint)
{
    MSTATUS status = OK;
    int retVal = 0;

    /* second vector from Sec 6, rfc5649, 16 byte wrap will trigger decrypt special */
    ubyte kek[24] = {0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 
                     0x5b, 0xf1, 0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8};
    ubyte wrap[16] = {0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2, 0x4f};
    ubyte expKey[7] = {0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69};
    ubyte recKey[8] = {0};
    ubyte4 keyLen = 0;
    sbyte4 cmp = -1;

    status = AESKWRAP_decrypt5649 (MOC_SYM (hwAccelCtx) kek, sizeof(kek), wrap, sizeof(wrap), recKey, sizeof(recKey), &keyLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (keyLen != sizeof(expKey))
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    status = DIGI_MEMCMP(recKey, expKey, keyLen, &cmp);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        retVal += UNITTEST_STATUS(hint, -1);
    }

exit:

    return retVal;
}

/*---------------------------------------------------------------------------*/

int aes_keywrap_test_vectorsEx()
{
    int retVal = 0;
    int i;
    hwAccelDescr hwAccelCtx;

    retVal += UNITTEST_STATUS(0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));

    /* encrypt/decrypt for ExVectors */
    for (i = 0; i < COUNTOF(gAESKeywrapExVectors); ++i)
    {
        retVal += AESKeywrapExTest( MOC_SYM(hwAccelCtx) i, gAESKeywrapExVectors+i);
    }

    /* same test for old RFC 3394 vectors , we don't have their wrap values */
    for (i = 0; i < COUNTOF(gAESKeywrapVectors); ++i)
    {
        retVal += AESKeywrapExTest2( MOC_SYM(hwAccelCtx) i, gAESKeywrapVectors+i);
    }

    retVal += AESKeywrapDecSpecialTest( MOC_SYM(hwAccelCtx) 0);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return retVal;
}
