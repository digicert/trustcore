/*
 *  aes_eax_test.c
 *
 *   unit test for aes_eax.c
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

#include "../aes_eax.c"

#include "../../../unit_tests/unittest.h"

/* Test vectors ***********************************
MSG:
KEY: 233952DEE4D5ED5F9B9C6D6FF80FF478
NONCE: 62EC67F9C3A4A407FCB2A8C49031A8B3
HEADER: 6BFB914FD07EAE6B
CIPHER: E037830E8389F27B025A2D6527E79D01

MSG: F7FB
KEY: 91945D3F4DCBEE0BF45EF52255F095A4
NONCE: BECAF043B0A23D843194BA972C66DEBD
HEADER: FA3BFD4806EB53FA
CIPHER: 19DD5C4C9331049D0BDAB0277408F67967E5

MSG: 1A47CB4933
KEY: 01F74AD64077F2E704C0F60ADA3DD523
NONCE: 70C3DB4F0D26368400A10ED05D2BFF5E
HEADER: 234A3463C1264AC6
CIPHER: D851D5BAE03A59F238A23E39199DC9266626C40F80

MSG: 481C9E39B1
KEY: D07CF6CBB7F313BDDE66B727AFD3C5E8
NONCE: 8408DFFF3C1A2B1292DC199E46B7D617
HEADER: 33CCE2EABFF5A79D
CIPHER: 632A9D131AD4C168A4225D8E1FF755939974A7BEDE

MSG: 40D0C07DA5E4
KEY: 35B6D0580005BBC12B0587124557D2C2
NONCE: FDB6B06676EEDC5C61D74276E1F8E816
HEADER: AEB96EAEBE2970E9
CIPHER: 071DFE16C675CB0677E536F73AFE6A14B74EE49844DD

MSG: 4DE3B35C3FC039245BD1FB7D
KEY: BD8E6E11475E60B268784C38C62FEB22
NONCE: 6EAC5C93072D8E8513F750935E46DA1B
HEADER: D4482D1CA78DCE0F
CIPHER: 835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F

MSG: 8B0A79306C9CE7ED99DAE4F87F8DD61636
KEY: 7C77D6E813BED5AC98BAA417477A2E7D
NONCE: 1A8C98DCD73D38393B2BF1569DEEFC19
HEADER: 65D2017990D62528
CIPHER: 02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2

MSG: 1BDA122BCE8A8DBAF1877D962B8592DD2D56
KEY: 5FFF20CAFAB119CA2FC73549E20F5B0D
NONCE: DDE59B97D722156D4D9AFF2BC7559826
HEADER: 54B9F04E6A09189A
CIPHER: 2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A

MSG: 6CF36720872B8513F6EAB1A8A44438D5EF11
KEY: A4A4782BCFFD3EC5E7EF6D8C34A56123
NONCE: B781FCF2F75FA5A8DE97A9CA48E522EC
HEADER: 899A175897561D7E
CIPHER: 0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700

MSG: CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7
KEY: 8395FCF1E95BEBD697BD010BC766AAC3
NONCE: 22E7ADD93CFC6393C57EC0B3C17D6B44
HEADER: 126735FCC320D25A
CIPHER: CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E
****************************************************************/

typedef struct AES_EAX_TestVector
{
    const ubyte*    message;
    sbyte4          messageLen;
    const ubyte*    key;
    sbyte4          keyLen;
    const ubyte*    nonce;
    sbyte4          nonceLen;
    const ubyte*    header;
    sbyte4          headerLen;
    const ubyte*    result;
    /* reusltLen = msgLen + AES_BLOCK_SIZE (whole tag) */
} AES_EAX_TestVector;


static AES_EAX_TestVector eaxTV[] =
{
    {
        (const ubyte *) "\x00",                                                             0,
        (const ubyte *) "\x23\x39\x52\xDE\xE4\xD5\xED\x5F\x9B\x9C\x6D\x6F\xF8\x0F\xF4\x78", 16,
        (const ubyte *) "\x62\xEC\x67\xF9\xC3\xA4\xA4\x07\xFC\xB2\xA8\xC4\x90\x31\xA8\xB3", 16,
        (const ubyte *) "\x6B\xFB\x91\x4F\xD0\x7E\xAE\x6B",                                 8,
        (const ubyte *) "\xE0\x37\x83\x0E\x83\x89\xF2\x7B\x02\x5A\x2D\x65\x27\xE7\x9D\x01",
    },
    {
        (const ubyte *) "\xF7\xFB",                                                         2,
        (const ubyte *) "\x91\x94\x5D\x3F\x4D\xCB\xEE\x0B\xF4\x5E\xF5\x22\x55\xF0\x95\xA4", 16,
        (const ubyte *) "\xBE\xCA\xF0\x43\xB0\xA2\x3D\x84\x31\x94\xBA\x97\x2C\x66\xDE\xBD", 16,
        (const ubyte *) "\xFA\x3B\xFD\x48\x06\xEB\x53\xFA",                                 8,
        (const ubyte *) "\x19\xDD\x5C\x4C\x93\x31\x04\x9D\x0B\xDA\xB0\x27\x74\x08\xF6\x79\x67\xE5",
    },
    {
        (const ubyte *) "\x1A\x47\xCB\x49\x33",                                             5,
        (const ubyte *) "\x01\xF7\x4A\xD6\x40\x77\xF2\xE7\x04\xC0\xF6\x0A\xDA\x3D\xD5\x23", 16,
        (const ubyte *) "\x70\xC3\xDB\x4F\x0D\x26\x36\x84\x00\xA1\x0E\xD0\x5D\x2B\xFF\x5E", 16,
        (const ubyte *) "\x23\x4A\x34\x63\xC1\x26\x4A\xC6",                                 8,
        (const ubyte *) "\xD8\x51\xD5\xBA\xE0\x3A\x59\xF2\x38\xA2\x3E\x39\x19\x9D\xC9\x26\x66\x26\xC4\x0F\x80",
    },
    {
        (const ubyte *) "\x48\x1C\x9E\x39\xB1",                                             5,
        (const ubyte *) "\xD0\x7C\xF6\xCB\xB7\xF3\x13\xBD\xDE\x66\xB7\x27\xAF\xD3\xC5\xE8", 16,
        (const ubyte *) "\x84\x08\xDF\xFF\x3C\x1A\x2B\x12\x92\xDC\x19\x9E\x46\xB7\xD6\x17", 16,
        (const ubyte *) "\x33\xCC\xE2\xEA\xBF\xF5\xA7\x9D",                                 8,
        (const ubyte *) "\x63\x2A\x9D\x13\x1A\xD4\xC1\x68\xA4\x22\x5D\x8E\x1F\xF7\x55\x93\x99\x74\xA7\xBE\xDE",
    },
    {
        (const ubyte *) "\x40\xD0\xC0\x7D\xA5\xE4",                                         6,
        (const ubyte *) "\x35\xB6\xD0\x58\x00\x05\xBB\xC1\x2B\x05\x87\x12\x45\x57\xD2\xC2", 16,
        (const ubyte *) "\xFD\xB6\xB0\x66\x76\xEE\xDC\x5C\x61\xD7\x42\x76\xE1\xF8\xE8\x16", 16,
        (const ubyte *) "\xAE\xB9\x6E\xAE\xBE\x29\x70\xE9",                                 8,
        (const ubyte *) "\x07\x1D\xFE\x16\xC6\x75\xCB\x06\x77\xE5\x36\xF7\x3A\xFE\x6A\x14\xB7\x4E\xE4\x98\x44\xDD",
    },
    {
        (const ubyte *) "\x4D\xE3\xB3\x5C\x3F\xC0\x39\x24\x5B\xD1\xFB\x7D",                 12,
        (const ubyte *) "\xBD\x8E\x6E\x11\x47\x5E\x60\xB2\x68\x78\x4C\x38\xC6\x2F\xEB\x22", 16,
        (const ubyte *) "\x6E\xAC\x5C\x93\x07\x2D\x8E\x85\x13\xF7\x50\x93\x5E\x46\xDA\x1B", 16,
        (const ubyte *) "\xD4\x48\x2D\x1C\xA7\x8D\xCE\x0F",                                 8,
        (const ubyte *) "\x83\x5B\xB4\xF1\x5D\x74\x3E\x35\x0E\x72\x84\x14\xAB\xB8\x64\x4F"
                        "\xD6\xCC\xB8\x69\x47\xC5\xE1\x05\x90\x21\x0A\x4F",
    },
    {
        (const ubyte *) "\x8B\x0A\x79\x30\x6C\x9C\xE7\xED\x99\xDA\xE4\xF8\x7F\x8D\xD6\x16\x36",  17,
        (const ubyte *) "\x7C\x77\xD6\xE8\x13\xBE\xD5\xAC\x98\xBA\xA4\x17\x47\x7A\x2E\x7D", 16,
        (const ubyte *) "\x1A\x8C\x98\xDC\xD7\x3D\x38\x39\x3B\x2B\xF1\x56\x9D\xEE\xFC\x19", 16,
        (const ubyte *) "\x65\xD2\x01\x79\x90\xD6\x25\x28",                                 8,
        (const ubyte *) "\x02\x08\x3E\x39\x79\xDA\x01\x48\x12\xF5\x9F\x11\xD5\x26\x30\xDA"
                        "\x30\x13\x73\x27\xD1\x06\x49\xB0\xAA\x6E\x1C\x18\x1D\xB6\x17\xD7\xF2",
    },
    {
        (const ubyte *) "\x1B\xDA\x12\x2B\xCE\x8A\x8D\xBA\xF1\x87\x7D\x96\x2B\x85\x92\xDD\x2D\x56", 18,
        (const ubyte *) "\x5F\xFF\x20\xCA\xFA\xB1\x19\xCA\x2F\xC7\x35\x49\xE2\x0F\x5B\x0D", 16,
        (const ubyte *) "\xDD\xE5\x9B\x97\xD7\x22\x15\x6D\x4D\x9A\xFF\x2B\xC7\x55\x98\x26", 16,
        (const ubyte *) "\x54\xB9\xF0\x4E\x6A\x09\x18\x9A",                                 8,
        (const ubyte *) "\x2E\xC4\x7B\x2C\x49\x54\xA4\x89\xAF\xC7\xBA\x48\x97\xED\xCD\xAE"
                        "\x8C\xC3\x3B\x60\x45\x05\x99\xBD\x02\xC9\x63\x82\x90\x2A\xEF\x7F\x83\x2A",
    },
    {
        (const ubyte *) "\x6C\xF3\x67\x20\x87\x2B\x85\x13\xF6\xEA\xB1\xA8\xA4\x44\x38\xD5\xEF\x11", 18,
        (const ubyte *) "\xA4\xA4\x78\x2B\xCF\xFD\x3E\xC5\xE7\xEF\x6D\x8C\x34\xA5\x61\x23", 16,
        (const ubyte *) "\xB7\x81\xFC\xF2\xF7\x5F\xA5\xA8\xDE\x97\xA9\xCA\x48\xE5\x22\xEC", 16,
        (const ubyte *) "\x89\x9A\x17\x58\x97\x56\x1D\x7E",                                 8,
        (const ubyte *) "\x0D\xE1\x8F\xD0\xFD\xD9\x1E\x7A\xF1\x9F\x1D\x8E\xE8\x73\x39\x38"
                        "\xB1\xE8\xE7\xF6\xD2\x23\x16\x18\x10\x2F\xDB\x7F\xE5\x5F\xF1\x99\x17\x00",
    },
    {
        (const ubyte *) "\xCA\x40\xD7\x44\x6E\x54\x5F\xFA\xED\x3B\xD1\x2A\x74\x0A\x65\x9F\xFB\xBB\x3C\xEA\xB7", 21,
        (const ubyte *) "\x83\x95\xFC\xF1\xE9\x5B\xEB\xD6\x97\xBD\x01\x0B\xC7\x66\xAA\xC3", 16,
        (const ubyte *) "\x22\xE7\xAD\xD9\x3C\xFC\x63\x93\xC5\x7E\xC0\xB3\xC1\x7D\x6B\x44", 16,
        (const ubyte *) "\x12\x67\x35\xFC\xC3\x20\xD2\x5A",                                 8,
        (const ubyte *) "\xCB\x89\x20\xF8\x7A\x6C\x75\xCF\xF3\x96\x27\xB5\x6E\x3E\xD1\x97"
                        "\xC5\x52\xD2\x95\xA7\xCF\xC4\x6A\xFC\x25\x3B\x46\x52\xB1\xAF\x37"
                        "\x95\xB1\x24\xAB\x6E",
    }
};


/*---------------------------------------------------------------------------*/

static int test_vector_test_encrypt(  const AES_EAX_TestVector* pWhichTest, int hint)
{
    int errors = 0;
    AES_EAX_Ctx ctx;
    MSTATUS status;
    sbyte4 i, cmpRes;
    ubyte* buffer = NULL;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    buffer = MALLOC( pWhichTest->messageLen + AES_BLOCK_SIZE);
    /* special case */
    if (  0 == pWhichTest->messageLen)
    {
        status = AES_EAX_init(MOC_SYM(hwAccelCtx)
                              pWhichTest->key, pWhichTest->keyLen,
                              pWhichTest->nonce, pWhichTest->nonceLen, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        status = AES_EAX_updateHeader(MOC_SYM(hwAccelCtx) pWhichTest->header, pWhichTest->headerLen, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        status = AES_EAX_final(MOC_SYM(hwAccelCtx) buffer, AES_BLOCK_SIZE, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( buffer, pWhichTest->result, AES_BLOCK_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);
        
        status = AES_EAX_clear(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
    }
    else
    {
        /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
        for ( i = 1; i <= pWhichTest->messageLen; ++i)
        {
            sbyte4 sent = 0;

            DIGI_MEMCPY( buffer, pWhichTest->message, pWhichTest->messageLen);

            status = AES_EAX_init(MOC_SYM(hwAccelCtx)
                                  pWhichTest->key, pWhichTest->keyLen,
                                  pWhichTest->nonce, pWhichTest->nonceLen, &ctx);
            errors += UNITTEST_STATUS( hint, status);

            /* update the header here if i is odd */
            if ( i & 1)
            {
                AES_EAX_updateHeader(MOC_SYM(hwAccelCtx)
                                     pWhichTest->header,
                                     pWhichTest->headerLen, &ctx);
            }

            while ( sent < pWhichTest->messageLen)
            {
                sbyte4 toSend;
                toSend = i;
                if ( toSend > pWhichTest->messageLen - sent)
                {
                    toSend = pWhichTest->messageLen - sent;
                }
                status = AES_EAX_encryptMessage(MOC_SYM(hwAccelCtx) buffer + sent, toSend, &ctx);
                errors += UNITTEST_STATUS( hint, status);
                sent += toSend;
            }

            /* update the header here if i is even */
            if (!( i & 1))
            {
                AES_EAX_updateHeader(MOC_SYM(hwAccelCtx) pWhichTest->header, pWhichTest->headerLen, &ctx);
            }

            status = AES_EAX_final(MOC_SYM(hwAccelCtx) buffer + pWhichTest->messageLen, AES_BLOCK_SIZE, &ctx);
            errors += UNITTEST_STATUS( hint, status);

            DIGI_MEMCMP( buffer, pWhichTest->result,
                        pWhichTest->messageLen + AES_BLOCK_SIZE, &cmpRes);
            errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */
            
            status = AES_EAX_clear(MOC_SYM(hwAccelCtx) &ctx);
            errors += UNITTEST_STATUS( hint, status);
        }
    }

    if (buffer)
    {
        FREE(buffer);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return errors;
}

/*---------------------------------------------------------------------------*/

static int test_vector_test_decrypt(const AES_EAX_TestVector* pWhichTest, int hint)
{
    int errors = 0;
    AES_EAX_Ctx ctx;
    MSTATUS status;
    sbyte4 i, cmpRes;
    ubyte* buffer = NULL;
    hwAccelDescr hwAccelCtx;
    ubyte tag[AES_BLOCK_SIZE] = {0};
    
    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;
    
    /*
     no need to check special case of 0 length plaintext. Tag of such is already verified
     to be the correct value of such in the encrypt test.
     */
    if ( 0 != pWhichTest->messageLen)
    {
        buffer = MALLOC( pWhichTest->messageLen);
        if (!buffer)
        {
            errors += UNITTEST_STATUS( hint, -1);
            return errors;
        }
        
        /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
        for ( i = 1; i <= pWhichTest->messageLen; ++i)
        {
            sbyte4 sent = 0;
            
            /* copy the result, ie ciphertext to the buffer */
            DIGI_MEMCPY( buffer, pWhichTest->result, pWhichTest->messageLen);
            
            status = AES_EAX_init(MOC_SYM(hwAccelCtx)
                                  pWhichTest->key, pWhichTest->keyLen,
                                  pWhichTest->nonce, pWhichTest->nonceLen, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            
            /* update the header here if i is odd */
            if ( i & 1)
            {
                AES_EAX_updateHeader(MOC_SYM(hwAccelCtx)
                                     pWhichTest->header,
                                     pWhichTest->headerLen, &ctx);
            }
            
            while ( sent < pWhichTest->messageLen)
            {
                sbyte4 toSend;
                toSend = i;
                if ( toSend > pWhichTest->messageLen - sent)
                {
                    toSend = pWhichTest->messageLen - sent;
                }
                status = AES_EAX_decryptMessage(MOC_SYM(hwAccelCtx) buffer + sent, toSend, &ctx);
                errors += UNITTEST_STATUS( hint, status);
                sent += toSend;
            }
            
            /* update the header here if i is even */
            if (!( i & 1))
            {
                AES_EAX_updateHeader(MOC_SYM(hwAccelCtx) pWhichTest->header, pWhichTest->headerLen, &ctx);
            }
            
            /* get the tag */
            status = AES_EAX_final(MOC_SYM(hwAccelCtx) tag, AES_BLOCK_SIZE, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            
            /* compare the plaintext */
            DIGI_MEMCMP( buffer, pWhichTest->message, pWhichTest->messageLen, &cmpRes);
            errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */
            
            /* compare the tag */
            DIGI_MEMCMP( tag, pWhichTest->result + pWhichTest->messageLen, AES_BLOCK_SIZE, &cmpRes);
            errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */
            
            status = AES_EAX_clear(MOC_SYM(hwAccelCtx) &ctx);
            errors += UNITTEST_STATUS( hint, status);
        }
    }
    
    if (buffer)
    {
        FREE(buffer);
    }
    
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return errors;
}

/*---------------------------------------------------------------------------*/

/* Tests decryption/verification via the AES_EAX_getPlainText and AES_EAX_generateTag APIs */
static int test_vector_test_decrypt_alt(  const AES_EAX_TestVector* pWhichTest, int hint)
{
    int errors = 0;
    AES_EAX_Ctx ctx;
    MSTATUS status;
    sbyte4 i, cmpRes;
    ubyte* buffer = NULL;
    hwAccelDescr hwAccelCtx;
    ubyte tag[AES_BLOCK_SIZE] = {0};
    
    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    /*
     no need to check special case of 0 length plaintext. Tag of such is already verified
     to be the correct value of such in the encrypt test.
     */
    if ( 0 != pWhichTest->messageLen)
    {
        buffer = MALLOC( pWhichTest->messageLen);
        if (!buffer)
        {
            errors += UNITTEST_STATUS( hint, -1);
            return errors;
        }
        
        /* verify the tag first which is a one shot API */
        
        status = AES_EAX_init(MOC_SYM(hwAccelCtx)
                              pWhichTest->key, pWhichTest->keyLen,
                              pWhichTest->nonce, pWhichTest->nonceLen, &ctx);
        errors += UNITTEST_STATUS( hint, status);
        
        status = AES_EAX_generateTag( MOC_SYM(hwAccelCtx) pWhichTest->result, pWhichTest->messageLen,
                                      pWhichTest->header, pWhichTest->headerLen,
                                      tag, AES_BLOCK_SIZE, &ctx);
        
        /* compare the tag */
        DIGI_MEMCMP( tag, pWhichTest->result + pWhichTest->messageLen, AES_BLOCK_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0); /* trick to get the i info in error message */
        
        /* clear the context for iterative tests of AES_EAX_getPlainText */
        status = AES_EAX_clear(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
        
        /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
        for ( i = 1; i <= pWhichTest->messageLen; ++i)
        {
            sbyte4 sent = 0;
            
            /* copy the result, ie ciphertext to the buffer */
            DIGI_MEMCPY( buffer, pWhichTest->result, pWhichTest->messageLen);
            
            status = AES_EAX_init(MOC_SYM(hwAccelCtx)
                                  pWhichTest->key, pWhichTest->keyLen,
                                  pWhichTest->nonce, pWhichTest->nonceLen, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            
            while ( sent < pWhichTest->messageLen)
            {
                sbyte4 toSend;
                toSend = i;
                if ( toSend > pWhichTest->messageLen - sent)
                {
                    toSend = pWhichTest->messageLen - sent;
                }
                status = AES_EAX_getPlainText(MOC_SYM(hwAccelCtx) buffer + sent, toSend, &ctx);
                errors += UNITTEST_STATUS( hint, status);
                sent += toSend;
            }
            
            /* compare the plaintext */
            DIGI_MEMCMP( buffer, pWhichTest->message, pWhichTest->messageLen, &cmpRes);
            errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */
            
            status = AES_EAX_clear(MOC_SYM(hwAccelCtx) &ctx);
            errors += UNITTEST_STATUS( hint, status);
        }
    }
    
    if (buffer)
    {
        FREE(buffer);
    }
    
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    
    return errors;
}

/*---------------------------------------------------------------------------*/

int aes_eax_test_vectors()
{
    int retVal = 0;
    int i;

    for (i = 0; i < COUNTOF(eaxTV); ++i)
    {
        retVal +=  test_vector_test_encrypt( eaxTV + i, i);
        retVal +=  test_vector_test_decrypt( eaxTV + i, i);
        retVal +=  test_vector_test_decrypt_alt( eaxTV + i, i);
    }

    return retVal;
}

