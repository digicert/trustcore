/*
 * aes_ctr_ipsec_test.c
 *
 * Unit test AES-CTR for IPsec as per RFC 3686.
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
#include "../../common/mstdlib.h"
#include "../../crypto/fips.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"

/* Test vectors from RFC 3686
 *
 * Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key
 *    AES Key          : AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E
 *    AES-CTR IV       : 00 00 00 00 00 00 00 00
 *    Nonce            : 00 00 00 30
 *    Plaintext String : 'Single block msg'
 *    Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
 *    Counter Block (1): 00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01
 *    Key Stream    (1): B7 60 33 28 DB C2 93 1B 41 0E 16 C8 06 7E 62 DF
 *    Ciphertext       : E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8
 *
 * Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key
 *    AES Key          : 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63
 *    AES-CTR IV       : C0 54 3B 59 DA 48 D9 0B
 *    Nonce            : 00 6C B6 DB
 *    Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                     : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *    Counter Block (1): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01
 *    Key Stream    (1): 51 05 A3 05 12 8F 74 DE 71 04 4B E5 82 D7 DD 87
 *    Counter Block (2): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 02
 *    Key Stream    (2): FB 3F 0C EF 52 CF 41 DF E4 FF 2A C4 8D 5C A0 37
 *    Ciphertext       : 51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88
 *                     : EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28
 *
 * Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key
 *    AES Key          : 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC
 *    AES-CTR IV       : 27 77 7F 3F  4A 17 86 F0
 *    Nonce            : 00 E0 01 7B
 *    Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                     : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *                     : 20 21 22 23
 *    Counter Block (1): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01
 *    Key Stream    (1): C1 CE 4A AB 9B 2A FB DE C7 4F 58 E2 E3 D6 7C D8
 *    Counter Block (2): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 02
 *    Key Stream    (2): 55 51 B6 38 CA 78 6E 21 CD 83 46 F1 B2 EE 0E 4C
 *    Counter Block (3): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 03
 *    Key Stream    (3): 05 93 25 0C 17 55 36 00 A6 3D FE CF 56 23 87 E9
 *    Ciphertext       : C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7
 *                     : 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53
 *                     : 25 B2 07 2F
 *
 * Test Vector #4: Encrypting 16 octets using AES-CTR with 192-bit key
 *    AES Key          : 16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED
 *                     : 86 3D 06 CC FD B7 85 15
 *    AES-CTR IV       : 36 73 3C 14 7D 6D 93 CB
 *    Nonce            : 00 00 00 48
 *    Plaintext String : 'Single block msg'
 *    Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
 *    Counter Block (1): 00 00 00 48 36 73 3C 14 7D 6D 93 CB 00 00 00 01
 *    Key Stream    (1): 18 3C 56 28 8E 3C E9 AA 22 16 56 CB 23 A6 9A 4F
 *    Ciphertext       : 4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28
 *
 *    Test Vector #5: Encrypting 32 octets using AES-CTR with 192-bit key
 *    AES Key          : 7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C
 *                     : 67 8C 3D B8 E6 F6 A9 1A
 *    AES-CTR IV       : 02 0C 6E AD C2 CB 50 0D
 *    Nonce            : 00 96 B0 3B
 *    Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                     : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *    Counter Block (1): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 01
 *    Key Stream    (1): 45 33 41 FF 64 9E 25 35 76 D6 A0 F1 7D 3C C3 90
 *    Counter Block (2): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 02
 *    Key Stream    (2): 94 81 62 0F 4E C1 B1 8B E4 06 FA E4 5E E9 E5 1F
 *    Ciphertext       : 45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F
 *                     : 84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00
 *
 * Test Vector #6: Encrypting 36 octets using AES-CTR with 192-bit key
 *    AES Key          : 02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B
 *                     : F5 9B 60 A7 86 D3 E0 FE
 *    AES-CTR IV       : 5C BD 60 27 8D CC 09 12
 *    Nonce            : 00 07 BD FD
 *    Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                     : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *                     : 20 21 22 23
 *    Counter Block (1): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 01
 *    Key Stream    (1): 96 88 3D C6 5A 59 74 28 5C 02 77 DA D1 FA E9 57
 *    Counter Block (2): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 02
 *    Key Stream    (2): C2 99 AE 86 D2 84 73 9F 5D 2F D2 0A 7A 32 3F 97
 *    Counter Block (3): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 03
 *    Key Stream    (3): 8B CF 2B 16 39 99 B2 26 15 B4 9C D4 FE 57 39 98
 *    Ciphertext       : 96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58
 *                     : D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88
 *                     : AB EE 09 35
 *
 * Test Vector #7: Encrypting 16 octets using AES-CTR with 256-bit key
 *    AES Key          : 77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C
 *                     : 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04
 *    AES-CTR IV       : DB 56 72 C9 7A A8 F0 B2
 *    Nonce            : 00 00 00 60
 *    Plaintext String : 'Single block msg'
 *    Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
 *    Counter Block (1): 00 00 00 60 DB 56 72 C9 7A A8 F0 B2 00 00 00 01
 *    Key Stream    (1): 47 33 BE 7A D3 E7 6E A5 3A 67 00 B7 51 8E 93 A7
 *    Ciphertext       : 14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0
 *
 * Test Vector #8: Encrypting 32 octets using AES-CTR with 256-bit key
 *    AES Key          : F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86
 *                     : C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84
 *    AES-CTR IV       : C1 58 5E F1 5A 43 D8 75
 *    Nonce            : 00 FA AC 24
 *    Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                     : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *    Counter block (1): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 01
 *    Key stream    (1): F0 5F 21 18 3C 91 67 2B 41 E7 0A 00 8C 43 BC A6
 *    Counter block (2): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 02
 *    Key stream    (2): A8 21 79 43 9B 96 8B 7D 4D 29 99 06 8F 59 B1 03
 *    Ciphertext       : F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9
 *                     : B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C
 *
 * Test Vector #9: Encrypting 36 octets using AES-CTR with 256-bit key
 *    AES Key          : FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2
 *                     : AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D
 *    AES-CTR IV       : 51 A5 1D 70 A1 C1 11 48
 *    Nonce            : 00 1C C5 B7
 *    Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                     : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *                     : 20 21 22 23
 *    Counter block (1): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 01
 *    Key stream    (1): EB 6D 50 81 19 0E BD F0 C6 7C 9E 4D 26 C7 41 A5
 *    Counter block (2): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 02
 *    Key stream    (2): A4 16 CD 95 71 7C EB 10 EC 95 DA AE 9F CB 19 00
 *    Counter block (3): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 03
 *    Key stream    (3): 3E E1 C4 9B C6 B9 CA 21 3F 6E E2 71 D0 A9 33 39
 *    Ciphertext       : EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA
 *                     : B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F
 *                     : 1E C0 E6 B8
 *
 */

#ifdef __ENABLE_DIGICERT_IPSEC_SERVICE__

typedef struct
{
    ubyte pKeyMat[36];
    ubyte4 keyMatLen;
    ubyte pIv[8];
    ubyte *pPlainText;
    ubyte *pCipherText;
    ubyte4 dataLen;
} AesCtrIpsecTV;

#define TEST_VECTOR_SIZE 6
static AesCtrIpsecTV gpTestVector[TEST_VECTOR_SIZE] = {
    {
        .pKeyMat = {
            0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
            0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E,
            0x00, 0x00, 0x00, 0x30
        },
        .keyMatLen = 20,
        .pIv = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        .pPlainText = (ubyte *) "Single block msg",
        .pCipherText = (ubyte *)
            "\x0E4\x009\x05D\x04F\x0B7\x0A7\x0B3\x079"
            "\x02D\x061\x075\x0A3\x026\x013\x011\x0B8",
        .dataLen = 16
    },
    {
        .pKeyMat = {
            0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
            0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63,
            0x00, 0x6C, 0xB6, 0xDB
        },
        .keyMatLen = 20,
        .pIv = {
            0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B
        },
        .pPlainText = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00A\x00B\x00C\x00D\x00E\x00F"
            "\x010\x011\x012\x013\x014\x015\x016\x017"
            "\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F",
        .pCipherText = (ubyte *)
            "\x051\x004\x0A1\x006\x016\x08A\x072\x0D9"
            "\x079\x00D\x041\x0EE\x08E\x0DA\x0D3\x088"
            "\x0EB\x02E\x01E\x0FC\x046\x0DA\x057\x0C8"
            "\x0FC\x0E6\x030\x0DF\x091\x041\x0BE\x028",
        .dataLen = 32
    },
    {
        .pKeyMat = {
            0x16, 0xAF, 0x5B, 0x14, 0x5F, 0xC9, 0xF5, 0x79,
            0xC1, 0x75, 0xF9, 0x3E, 0x3B, 0xFB, 0x0E, 0xED,
            0x86, 0x3D, 0x06, 0xCC, 0xFD, 0xB7, 0x85, 0x15,
            0x00, 0x00, 0x00, 0x48
        },
        .keyMatLen = 28,
        .pIv = {
            0x36, 0x73, 0x3C, 0x14, 0x7D, 0x6D, 0x93, 0xCB
        },
        .pPlainText = (ubyte *) "Single block msg",
        .pCipherText = (ubyte *)
            "\x04B\x055\x038\x04F\x0E2\x059\x0C9\x0C8"
            "\x04E\x079\x035\x0A0\x003\x0CB\x0E9\x028",
        .dataLen = 16
    },
    {
        .pKeyMat = {
            0x7C, 0x5C, 0xB2, 0x40, 0x1B, 0x3D, 0xC3, 0x3C,
            0x19, 0xE7, 0x34, 0x08, 0x19, 0xE0, 0xF6, 0x9C,
            0x67, 0x8C, 0x3D, 0xB8, 0xE6, 0xF6, 0xA9, 0x1A,
            0x00, 0x96, 0xB0, 0x3B
        },
        .keyMatLen = 28,
        .pIv = {
            0x02, 0x0C, 0x6E, 0xAD, 0xC2, 0xCB, 0x50, 0x0D
        },
        .pPlainText = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00A\x00B\x00C\x00D\x00E\x00F"
            "\x010\x011\x012\x013\x014\x015\x016\x017"
            "\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F",
        .pCipherText = (ubyte *)
            "\x045\x032\x043\x0FC\x060\x09B\x023\x032"
            "\x07E\x0DF\x0AA\x0FA\x071\x031\x0CD\x09F"
            "\x084\x090\x070\x01C\x05A\x0D4\x0A7\x09C"
            "\x0FC\x01F\x0E0\x0FF\x042\x0F4\x0FB\x000",
        .dataLen = 32
    },
    {
        .pKeyMat = {
            0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F,
            0x4C, 0x8A, 0x05, 0x42, 0xC8, 0x69, 0x6F, 0x6C,
            0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96, 0xB4, 0xD3,
            0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04,
            0x00, 0x00, 0x00, 0x60
        },
        .keyMatLen = 36,
        .pIv = {
            0xDB, 0x56, 0x72, 0xC9, 0x7A, 0xA8, 0xF0, 0xB2
        },
        .pPlainText = (ubyte *) "Single block msg",
        .pCipherText = (ubyte *)
            "\x014\x05A\x0D0\x01D\x0BF\x082\x04E\x0C7"
            "\x056\x008\x063\x0DC\x071\x0E3\x0E0\x0C0",
        .dataLen = 16
    },
    {
        .pKeyMat = {
            0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB,
            0x07, 0x96, 0x36, 0x58, 0x79, 0xEF, 0xF8, 0x86,
            0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74,
            0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84,
            0x00, 0xFA, 0xAC, 0x24
        },
        .keyMatLen = 36,
        .pIv = {
            0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75
        },
        .pPlainText = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00A\x00B\x00C\x00D\x00E\x00F"
            "\x010\x011\x012\x013\x014\x015\x016\x017"
            "\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F",
        .pCipherText = (ubyte *)
            "\x0F0\x05E\x023\x01B\x038\x094\x061\x02C"
            "\x049\x0EE\x000\x00B\x080\x04E\x0B2\x0A9"
            "\x0B8\x030\x06B\x050\x08F\x083\x09D\x06A"
            "\x055\x030\x083\x01D\x093\x044\x0AF\x01C",
        .dataLen = 32
    }
};

static int single_block()
{
    MSTATUS status = OK, fstatus;
    ubyte4 index;
    sbyte4 cmpRes;
    AesCtrIpsecTV *pCurTest = NULL;
    BulkCtx pAesCtrCtx = NULL;
    ubyte pIv[8];
    ubyte *pOutput = NULL;
    ubyte4 outLen;

    for (index = 0; index < TEST_VECTOR_SIZE; ++index)
    {
        pCurTest = gpTestVector + index;

        outLen = pCurTest->dataLen;

        status = DIGI_MALLOC((void **) &pOutput, outLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pOutput, pCurTest->pPlainText, outLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pIv, pCurTest->pIv, sizeof(pIv));
        if (OK != status)
            goto exit;

        status = ERR_NULL_POINTER;
        pAesCtrCtx = CreateAesCtrCtx(pCurTest->pKeyMat, pCurTest->keyMatLen, 1);
        if (NULL == pAesCtrCtx)
            goto exit;

        status = DoAesCtr(pAesCtrCtx, pOutput, outLen, 1, pIv);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCMP(pOutput, pCurTest->pCipherText, outLen, &cmpRes);
        if (OK != status)
            goto exit;

        status = ERR_CMP;
        if (0 != cmpRes)
            goto exit;

        status = DeleteAESCTRCtx(&pAesCtrCtx);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pIv, pCurTest->pIv, sizeof(pIv));
        if (OK != status)
            goto exit;

        status = ERR_NULL_POINTER;
        pAesCtrCtx = CreateAesCtrCtx(pCurTest->pKeyMat, pCurTest->keyMatLen, 0);
        if (NULL == pAesCtrCtx)
            goto exit;

        status = DoAesCtr(pAesCtrCtx, pOutput, outLen, 0, pIv);
        if (OK != status)
            goto exit;

        status = DeleteAESCTRCtx(&pAesCtrCtx);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCMP(pOutput, pCurTest->pPlainText, outLen, &cmpRes);
        if (OK != status)
            goto exit;

        status = ERR_CMP;
        if (0 != cmpRes)
            goto exit;

        status = DIGI_FREE((void **) &pOutput);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != pOutput)
    {
        fstatus = DIGI_FREE((void **) &pOutput);
        if (OK == status)
            status = fstatus;
    }

    return ((int) status);
}

static int multi_block()
{
    MSTATUS status = OK, fstatus;
    ubyte4 index;
    sbyte4 cmpRes;
    AesCtrIpsecTV *pCurTest = NULL;
    BulkCtx pAesCtrCtx = NULL;
    ubyte pIv[8];
    ubyte *pOutput = NULL;
    ubyte4 outLen, temp;

    for (index = 0; index < TEST_VECTOR_SIZE; ++index)
    {
        pCurTest = gpTestVector + index;

        outLen = pCurTest->dataLen;

        status = DIGI_MALLOC((void **) &pOutput, outLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pOutput, pCurTest->pPlainText, outLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pIv, pCurTest->pIv, sizeof(pIv));
        if (OK != status)
            goto exit;

        status = ERR_NULL_POINTER;
        pAesCtrCtx = CreateAesCtrCtx(pCurTest->pKeyMat, pCurTest->keyMatLen, 1);
        if (NULL == pAesCtrCtx)
            goto exit;

        temp = outLen;

        while (0 != temp)
        {
            status = DoAesCtr(pAesCtrCtx, pOutput + (outLen - temp), 8, 1, pIv);
            if (OK != status)
                goto exit;

            temp -= 8;
        }

        status = DIGI_MEMCMP(pOutput, pCurTest->pCipherText, outLen, &cmpRes);
        if (OK != status)
            goto exit;

        status = ERR_CMP;
        if (0 != cmpRes)
            goto exit;

        status = DeleteAESCTRCtx(&pAesCtrCtx);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pIv, pCurTest->pIv, sizeof(pIv));
        if (OK != status)
            goto exit;

        status = ERR_NULL_POINTER;
        pAesCtrCtx = CreateAesCtrCtx(pCurTest->pKeyMat, pCurTest->keyMatLen, 0);
        if (NULL == pAesCtrCtx)
            goto exit;

        temp = outLen;

        while (0 != temp)
        {
            status = DoAesCtr(pAesCtrCtx, pOutput + (outLen - temp), 8, 1, pIv);
            if (OK != status)
                goto exit;

            temp -= 8;
        }

        status = DeleteAESCTRCtx(&pAesCtrCtx);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCMP(pOutput, pCurTest->pPlainText, outLen, &cmpRes);
        if (OK != status)
            goto exit;

        status = ERR_CMP;
        if (0 != cmpRes)
            goto exit;

        status = DIGI_FREE((void **) &pOutput);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != pOutput)
    {
        fstatus = DIGI_FREE((void **) &pOutput);
        if (OK == status)
            status = fstatus;
    }

    return ((int) status);
}

int aes_ctr_ipsec_test_init()
{
    int ret = 0;

    ret += single_block();
    ret += multi_block();

    return ret;
}

#else /* __ENABLE_DIGICERT_IPSEC_SERVICE__ */

int aes_ctr_ipsec_test_init()
{
    return 0;
}

#endif /* __ENABLE_DIGICERT_IPSEC_SERVICE__ */