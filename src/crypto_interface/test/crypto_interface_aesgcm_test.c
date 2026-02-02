/*
*  crypto_interface_aesgcm_test.c
*
*   unit test for AES-GCM
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto/gcm.h"
#include "../../crypto_interface/crypto_interface_aes_gcm.h"

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_aes_tap.h"
#include "../../crypto_interface/crypto_interface_aes_gcm_tap.h"
#endif

/* #define __DEBUG_TEST_VECTORS__ */

#ifdef __DEBUG_TEST_VECTORS__
#include<stdio.h>
#endif

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
/* speed test headers */
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdio.h>

#define ENCRYPT_ITERATIONS      3000000
#define DECRYPT_ITERATIONS      3000000
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

typedef BulkCtx (*GcmCreate)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte *pKey,
    sbyte4 keyLen,
    sbyte4 encrypt
    );

typedef MSTATUS (*GcmDelete)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx *ppCtx
    );

typedef MSTATUS (*GcmInit)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAad,
    ubyte4 aadLen
    );

typedef MSTATUS (*GcmFinal)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    ubyte pTag[]
    );

typedef MSTATUS (*GcmCipher)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 verifyLen,
    sbyte4 encrypt
    );

typedef MSTATUS (*GcmClone)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

/* struct that can be used for update nonce, update aad, update data and even final_ex */
typedef MSTATUS (*GcmUpdate)(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    ubyte *pData,
    ubyte4 dataLen
);

typedef struct
{
    GcmCreate create;
    GcmDelete delete;
    GcmInit init;
    GcmUpdate encrypt;
    GcmUpdate decrypt;
    GcmFinal final;
    GcmCipher cipher;
    GcmClone clone;
    GcmUpdate updateNonce;
    GcmUpdate updateAad;
    GcmUpdate updateData;
    GcmUpdate finalEx;
} GcmTestSuite;

typedef struct
{
    ubyte4 keyLen;
    ubyte *pKey;
    ubyte4 ivLen;
    ubyte *pIv;
    ubyte4 plainLen;
    ubyte *pPlainText;
    ubyte4 aadLen;
    ubyte *pAad;
    ubyte4 cipherLen;
    ubyte *pCipherText;
    ubyte4 tagLen;
    ubyte *pTag;
} GcmKat; /* GCM Known Answer Tests (KAT) */

static GcmKat pTestData[] = {
    {
        .keyLen = 16,
        .pKey = (ubyte *)
        "\x0AD\x07A\x02B\x0D0\x03E\x0AC\x083\x05A"
        "\x06F\x062\x00F\x0DC\x0B5\x006\x0B3\x045",
        .ivLen = 12,
        .pIv = (ubyte *)
        "\x012\x015\x035\x024\x0C0\x089\x05E\x081"
        "\x0B2\x0C2\x084\x065",
        .plainLen = 0,
        .pPlainText = NULL,
        .aadLen = 70,
        .pAad = (ubyte *)
        "\x0D6\x009\x0B1\x0F0\x056\x063\x07A\x00D\x046\x0DF\x099\x08D\x088\x0E5\x022\x02A"
        "\x0B2\x0C2\x084\x065\x012\x015\x035\x024\x0C0\x089\x05E\x081\x008\x000\x00F\x010"
        "\x011\x012\x013\x014\x015\x016\x017\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F\x020"
        "\x021\x022\x023\x024\x025\x026\x027\x028\x029\x02A\x02B\x02C\x02D\x02E\x02F\x030"
        "\x031\x032\x033\x034\x000\x001",
        .cipherLen = 0,
        .pCipherText = NULL,
        .tagLen = 16,
        .pTag = (ubyte *)
        "\x0F0\x094\x078\x0A9\x0B0\x090\x007\x0D0\x06F\x046\x0E9\x0B6\x0A1\x0DA\x025\x0DD"
    },
    {
        .keyLen = 32,
        .pKey = (ubyte *)
        "\x0E3\x0C0\x08A\x08F\x006\x0C6\x0E3\x0AD\x095\x0A7\x005\x057\x0B2\x03F\x075\x048"
        "\x03C\x0E3\x030\x021\x0A9\x0C7\x02B\x070\x025\x066\x062\x004\x0C6\x09C\x00B\x072",
        .ivLen = 12,
        .pIv = (ubyte *)
        "\x012\x015\x035\x024\x0C0\x089\x05E\x081"
        "\x0B2\x0C2\x084\x065",
        .plainLen = 0,
        .pPlainText = NULL,
        .aadLen = 70,
        .pAad = (ubyte *)
        "\x0D6\x009\x0B1\x0F0\x056\x063\x07A\x00D\x046\x0DF\x099\x08D\x088\x0E5\x022\x02A"
        "\x0B2\x0C2\x084\x065\x012\x015\x035\x024\x0C0\x089\x05E\x081\x008\x000\x00F\x010"
        "\x011\x012\x013\x014\x015\x016\x017\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F\x020"
        "\x021\x022\x023\x024\x025\x026\x027\x028\x029\x02A\x02B\x02C\x02D\x02E\x02F\x030"
        "\x031\x032\x033\x034\x000\x001",
        .cipherLen = 0,
        .pCipherText = NULL,
        .tagLen = 16,
        .pTag = (ubyte *)
        "\x02F\x00B\x0C5\x0AF\x040\x09E\x006\x0D6\x009\x0EA\x08B\x07D\x00F\x0A5\x0EA\x050"
    },
    {
        .keyLen = 16,
        .pKey = (ubyte *)
            "\x07f\x0dd\x0b5\x074\x053\x0c2\x041\x0d0"
            "\x03e\x0fb\x0ed\x03a\x0c4\x04e\x037\x01c",
        .ivLen = 12,
        .pIv = (ubyte *)
            "\x0ee\x028\x03a\x03f\x0c7\x055\x075\x0e3"
            "\x03e\x0fd\x048\x087",
        .plainLen = 16,
        .pPlainText = (ubyte *)
            "\x0d5\x0de\x042\x0b4\x061\x064\x06c\x025"
            "\x05c\x087\x0bd\x029\x062\x0d3\x0b9\x0a2",
        .aadLen = 0,
        .pAad = NULL,
        .cipherLen = 16,
        .pCipherText = (ubyte *)
            "\x02c\x0cd\x0a4\x0a5\x041\x05c\x0b9\x01e"
            "\x013\x05c\x02a\x00f\x078\x0c9\x0b2\x0fd",
        .tagLen = 16,
        .pTag = (ubyte *)
            "\x0b3\x06d\x01d\x0f9\x0b9\x0d5\x0e5\x096"
            "\x0f8\x03e\x08b\x07f\x052\x097\x01c\x0b3"
    },
    {
        .keyLen = 16,
        .pKey = (ubyte *)
            "\x077\x054\x0f5\x086\x048\x0b1\x095\x067"
            "\x01c\x0e8\x04c\x044\x09b\x087\x095\x00e",
        .ivLen = 128,
        .pIv = (ubyte *)
            "\x0cb\x096\x0b0\x090\x047\x099\x028\x034"
            "\x02a\x0d3\x0ea\x04e\x096\x052\x0c3\x036"
            "\x023\x0f4\x022\x059\x041\x0fa\x075\x035"
            "\x090\x02f\x0c7\x0bd\x027\x092\x0fd\x083"
            "\x035\x0d8\x08f\x0e3\x0e8\x0da\x052\x08e"
            "\x092\x049\x024\x074\x0d2\x031\x037\x067"
            "\x072\x00e\x026\x005\x045\x049\x0f2\x0e3"
            "\x094\x0da\x0f4\x006\x032\x0bb\x02c\x0db"
            "\x0b3\x0af\x03c\x02e\x094\x02e\x06c\x035"
            "\x0f6\x004\x04d\x040\x04a\x0cc\x04b\x023"
            "\x08d\x084\x084\x083\x04b\x013\x01f\x0c5"
            "\x078\x048\x0b6\x084\x0e2\x052\x03d\x0cd"
            "\x0ac\x006\x08e\x081\x053\x0a2\x0b9\x088"
            "\x067\x0fd\x0ad\x00d\x03c\x0b3\x035\x0a5"
            "\x0a0\x022\x049\x0ea\x0d7\x02d\x0d9\x086"
            "\x0c4\x058\x049\x066\x07f\x050\x0b9\x026",
        .plainLen = 13,
        .pPlainText = (ubyte *)
            "\x044\x055\x068\x039\x041\x0bc\x0f4\x058"
            "\x07d\x003\x063\x07d\x0ca",
        .aadLen = 48,
        .pAad = (ubyte *)
            "\x041\x08b\x0b4\x0f7\x0ad\x087\x087\x063"
            "\x0c1\x090\x03c\x0fb\x0c0\x05a\x093\x0cc"
            "\x0b4\x04e\x0ce\x011\x0a6\x0b7\x0ef\x03c"
            "\x07e\x09c\x058\x078\x08c\x01b\x0d6\x0e8"
            "\x0c2\x091\x0b9\x085\x0f9\x024\x007\x04d"
            "\x01a\x007\x0dc\x0b9\x031\x0f5\x0b3\x0b0",
        .cipherLen = 13,
        .pCipherText = (ubyte *)
            "\x0d4\x0bc\x041\x0c9\x0b5\x05a\x0a4\x089"
            "\x09f\x0cf\x0c6\x0d3\x092",
        .tagLen = 4,
        .pTag = (ubyte *)
            "\x074\x083\x0f6\x09c"
    },
    {
        .keyLen = 24,
        .pKey = (ubyte *)
            "\x0fb\x0c0\x0b4\x0c5\x06a\x071\x04c\x083"
            "\x021\x07b\x02d\x01b\x0ca\x0dd\x02e\x0d2"
            "\x0e9\x0ef\x0b0\x0dc\x0ac\x06c\x0c1\x09f",
        .ivLen = 12,
        .pIv = (ubyte *)
            "\x05f\x04b\x043\x0e8\x011\x0da\x09c\x047"
            "\x00d\x06a\x09b\x001",
        .plainLen = 16,
        .pPlainText = (ubyte *)
            "\x0d2\x0ae\x038\x0c4\x037\x059\x054\x083"
            "\x05d\x075\x0b8\x0e4\x0c2\x0f9\x0bb\x0b4",
        .aadLen = 0,
        .pAad = NULL,
        .cipherLen = 16,
        .pCipherText = (ubyte *)
            "\x069\x048\x029\x057\x0e6\x0be\x05c\x054"
            "\x088\x02d\x000\x031\x04e\x002\x059\x0cf",
        .tagLen = 16,
        .pTag = (ubyte *)
            "\x019\x01e\x09f\x029\x0be\x0f6\x03a\x026"
            "\x086\x00c\x01e\x002\x00a\x021\x013\x07e"
      },
      {
        .keyLen = 24,
        .pKey = (ubyte *)
            "\x090\x0fa\x0b6\x038\x057\x05f\x00b\x0cc"
            "\x0c2\x016\x069\x069\x0c4\x071\x06a\x044"
            "\x03d\x0e5\x067\x072\x01f\x07a\x0c6\x065",
        .ivLen = 128,
        .pIv = (ubyte *)
            "\x099\x05a\x0d8\x098\x077\x087\x0c8\x0bb"
            "\x019\x03e\x0e1\x00e\x097\x058\x083\x017"
            "\x06e\x00e\x06b\x0f2\x078\x009\x0bb\x09a"
            "\x037\x063\x094\x0bf\x062\x0dd\x0fc\x08a"
            "\x0bb\x0b6\x048\x098\x08b\x0ba\x022\x066"
            "\x022\x051\x02e\x080\x0ed\x083\x028\x01b"
            "\x0d3\x0ca\x010\x019\x034\x00e\x0de\x049"
            "\x013\x0c1\x0f1\x0fc\x0f4\x0b6\x0e6\x0bb"
            "\x0d9\x047\x010\x058\x030\x023\x03d\x024"
            "\x0dd\x033\x063\x07d\x0fb\x0cf\x00c\x038"
            "\x0b8\x01a\x0f2\x05f\x00c\x082\x0fe\x0e9"
            "\x0b5\x01a\x077\x058\x05f\x0d8\x0cf\x017"
            "\x069\x0da\x037\x0d4\x060\x0d7\x03c\x077"
            "\x024\x056\x007\x01c\x0d4\x008\x073\x0b4"
            "\x03c\x072\x0a1\x070\x079\x0d9\x086\x07a"
            "\x0a7\x0ee\x0ac\x04b\x0b2\x0dc\x070\x016",
        .plainLen = 32,
        .pPlainText = (ubyte *)
            "\x04a\x022\x065\x0a3\x03f\x07e\x05f\x041"
            "\x066\x05f\x0fa\x08f\x061\x031\x019\x016"
            "\x083\x097\x066\x069\x061\x0f6\x0b1\x08a"
            "\x090\x057\x04d\x03f\x059\x0f4\x0ba\x0b9",
        .aadLen = 90,
        .pAad = (ubyte *)
            "\x0b4\x072\x00e\x06c\x049\x0d9\x068\x02a"
            "\x050\x079\x0f1\x07e\x0ed\x035\x042\x0d5"
            "\x032\x0a4\x004\x0cc\x060\x0ff\x029\x06f"
            "\x07e\x00c\x04e\x01c\x090\x028\x012\x027"
            "\x025\x024\x0bc\x029\x073\x023\x00e\x081"
            "\x083\x0bc\x014\x019\x08d\x066\x097\x0a0"
            "\x085\x00d\x096\x03b\x04f\x060\x0cb\x032"
            "\x097\x08c\x0f7\x0fd\x0c9\x0f6\x081\x0a3"
            "\x0ee\x0d8\x043\x0dc\x02e\x081\x0f3\x05c"
            "\x0a1\x0d8\x022\x056\x0c7\x0d4\x0ea\x0d8"
            "\x016\x049\x0d3\x056\x0d3\x051\x023\x050"
            "\x035\x01d",
        .cipherLen = 32,
        .pCipherText = (ubyte *)
            "\x05d\x0ca\x086\x0fa\x0c9\x0e7\x09a\x033"
            "\x038\x08c\x017\x0b1\x0cb\x095\x0af\x0d7"
            "\x04c\x007\x07e\x0fc\x0ab\x0a0\x008\x04d"
            "\x088\x05d\x055\x0e1\x0fb\x090\x01c\x00f",
        .tagLen = 8,
        .pTag = (ubyte *)
            "\x0a6\x00b\x007\x033\x024\x08b\x067\x0f6"
      },
      {
        .keyLen = 32,
        .pKey = (ubyte *)
            "\x056\x069\x007\x098\x097\x08c\x015\x04f"
            "\x0f2\x050\x0ba\x078\x0e4\x063\x076\x05f"
            "\x02f\x00c\x0e6\x097\x009\x0a4\x055\x01b"
            "\x0d8\x0cb\x03a\x0dd\x0ed\x0a0\x087\x0b6",
        .ivLen = 12,
        .pIv = (ubyte *)
            "\x0cf\x037\x0c2\x086\x0c1\x08a\x0d4\x0ea"
            "\x03d\x00b\x0a6\x0a0",
        .plainLen = 16,
        .pPlainText = (ubyte *)
            "\x02d\x032\x081\x024\x0a8\x0d5\x08d\x056"
            "\x0d0\x077\x05e\x0ed\x093\x0de\x01a\x088",
        .aadLen = 0,
        .pAad = NULL,
        .cipherLen = 16,
        .pCipherText = (ubyte *)
            "\x03b\x00a\x002\x067\x0f6\x0ec\x0de\x03a"
            "\x078\x0b3\x009\x003\x0eb\x0d4\x0ca\x06e",
        .tagLen = 16,
        .pTag = (ubyte *)
            "\x01f\x0d2\x000\x064\x009\x0fc\x063\x063"
            "\x079\x0f3\x0d4\x006\x07e\x0ca\x009\x088"
      },
      {
        .keyLen = 32,
        .pKey = (ubyte *)
            "\x065\x0b7\x017\x01b\x055\x0b2\x02e\x0dd"
            "\x071\x01a\x007\x06f\x02e\x0b6\x0a1\x025"
            "\x0e8\x073\x099\x03e\x08d\x054\x056\x04c"
            "\x0d6\x02d\x003\x0c6\x065\x0cd\x063\x074",
        .ivLen = 128,
        .pIv = (ubyte *)
            "\x054\x0d1\x018\x0d3\x02a\x056\x013\x08f"
            "\x004\x021\x026\x084\x0b1\x0e4\x07c\x05d"
            "\x068\x008\x0c1\x028\x099\x06e\x01d\x06e"
            "\x0bf\x073\x09e\x0f9\x0ff\x013\x08a\x0ac"
            "\x011\x081\x0fc\x0de\x082\x00a\x05f\x068"
            "\x074\x09e\x01f\x0ed\x079\x013\x014\x0c7"
            "\x03c\x054\x016\x09a\x0ee\x055\x056\x0bf"
            "\x020\x069\x098\x0d9\x054\x032\x071\x09f"
            "\x0c9\x0ff\x0e2\x02f\x0bb\x0c4\x092\x05f"
            "\x032\x077\x04d\x031\x0e0\x075\x039\x03c"
            "\x009\x007\x0e2\x07c\x03f\x040\x0da\x002"
            "\x0c4\x024\x0b4\x002\x0ef\x0f5\x096\x0f6"
            "\x030\x00b\x088\x01b\x08f\x056\x01d\x05a"
            "\x0e4\x053\x05a\x01f\x0a9\x0d4\x0ba\x0fe"
            "\x086\x0dd\x067\x051\x0b0\x0da\x024\x05a"
            "\x0e7\x0b7\x04d\x0dc\x0c3\x0f5\x003\x03c",
        .plainLen = 51,
        .pPlainText = (ubyte *)
            "\x005\x021\x0e4\x01d\x082\x07d\x061\x004"
            "\x0ec\x0da\x0b1\x0f8\x0e7\x0fb\x070\x0cd"
            "\x08a\x0bc\x0a8\x075\x000\x0ec\x0d3\x06e"
            "\x065\x090\x061\x094\x032\x07b\x01b\x061"
            "\x001\x04f\x0d3\x010\x0f4\x0e1\x0bf\x07d"
            "\x05b\x0f3\x056\x0a5\x0d7\x031\x0c0\x0d0"
            "\x0d4\x07c\x07e",
        .aadLen = 90,
        .pAad = (ubyte *)
            "\x04a\x03b\x004\x0de\x0cb\x0ec\x00a\x054"
            "\x096\x066\x0e8\x070\x036\x0e7\x084\x033"
            "\x0b8\x096\x027\x007\x092\x0e7\x093\x028"
            "\x010\x0c3\x08e\x0b0\x063\x013\x09a\x0de"
            "\x06a\x04b\x0ef\x0d4\x0df\x0db\x038\x0d5"
            "\x03c\x0db\x095\x0ac\x0cb\x0de\x0e7\x0ad"
            "\x054\x078\x0c3\x0bc\x055\x0a2\x012\x026"
            "\x0c2\x0b0\x0fa\x079\x0fe\x07c\x030\x026"
            "\x02f\x0a5\x038\x03d\x0e3\x0d3\x0b4\x05e"
            "\x095\x01d\x07e\x0f9\x055\x0f3\x0a1\x08b"
            "\x096\x089\x078\x038\x098\x0be\x0db\x066"
            "\x0f0\x0b8",
        .cipherLen = 51,
        .pCipherText = (ubyte *)
            "\x02e\x0cf\x07a\x03a\x035\x0ab\x0b5\x00d"
            "\x021\x025\x088\x0c2\x0ef\x050\x088\x002"
            "\x012\x0b5\x03c\x005\x027\x038\x076\x07c"
            "\x09e\x0a2\x015\x070\x092\x008\x0af\x0ae"
            "\x06e\x094\x0ac\x0d6\x089\x080\x020\x07b"
            "\x0f6\x033\x082\x049\x05b\x0e1\x0ac\x0de"
            "\x078\x04b\x092",
        .tagLen = 16,
        .pTag = (ubyte *)
            "\x049\x056\x03e\x012\x079\x07e\x0ef\x0be"
            "\x0e2\x0fd\x075\x0a1\x0e8\x044\x086\x09b"
      }
};

static ubyte4 gpUpdateDataIndices[][2] =
{
    {0,0},
    {0,1},
    {0,15},
    {0,16},
    {0,17},
    {0,31},
    {0,32},
    {0,33},
    {1,16},
    {1,17},
    {1,31},
    {1,32},
    {1,33},
    {15,16},
    {15,17},
    {15,31},
    {15,32},
    {15,33},
    {16,17},
    {16,31},
    {16,32},
    {16,33},
    {17,18},
    {17,31},
    {17,32},
    {17,33},
    {31,32},
    {31,33},
    {32,33}
};

/*----------------------------------------------------------------------------*/

int testAesGCMOneShot(
    GcmTestSuite *pGcm,
    GcmKat *pTestData
    )
{
    MSTATUS status;
    void *pCtx = NULL;
    sbyte4 cmpRes = -1;
    ubyte4 outputLen = 0;
    ubyte *pOutput = NULL;

    /* Test encrypt */
    outputLen = pTestData->plainLen + pTestData->tagLen;

    status = DIGI_CALLOC((void **) &pOutput, 1, outputLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != pTestData->plainLen)
    {
        status = DIGI_MEMCPY(pOutput, pTestData->pPlainText, pTestData->plainLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, 1);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx)
        pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad,
        pTestData->aadLen, pOutput, pTestData->plainLen, pTestData->tagLen, TRUE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Compare the ciphertext */
    if (0 != pTestData->cipherLen)
    {
        status = DIGI_MEMCMP(pOutput, pTestData->pCipherText, pTestData->cipherLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

    }
    cmpRes = -1;

    /* Compare the tag */
    status = DIGI_MEMCMP(
        pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Test decrypt */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, 0);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx)
        pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad,
        pTestData->aadLen, pOutput, pTestData->cipherLen, pTestData->tagLen, FALSE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    cmpRes = -1;

    if (0 != pTestData->plainLen)
    {
        status = DIGI_MEMCMP(pOutput, pTestData->pPlainText, pTestData->plainLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }

    if (OK == status)
        return 0;
    else
        return 1;
}

static int testAesGCMevpSingleUpdate(
       GcmTestSuite *pGcm,
       GcmKat *pTestData
       )
{
    MSTATUS status;
    void *pCtx = NULL;
    sbyte4 cmpRes = -1;
    ubyte4 outputLen = 0;
    ubyte *pOutput = NULL;

    /* Test encrypt */

    /* Add 16 bytes for the tag in all cases, old style APIs don't support smaller tag sizes. */
    outputLen = pTestData->plainLen + 16;

    status = DIGI_CALLOC((void **) &pOutput, 1, outputLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* we'll encrypt in-place, so copy plaintext to pOutput for now */
    if (0 != pTestData->plainLen)
    {
        status = DIGI_MEMCPY(pOutput, pTestData->pPlainText, pTestData->plainLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad, pTestData->aadLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != pTestData->plainLen)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput, pTestData->plainLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + pTestData->plainLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != pTestData->cipherLen)
    {
        /* Compare the ciphertext */
        status = DIGI_MEMCMP(pOutput, pTestData->pCipherText, pTestData->cipherLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    cmpRes = -1;

    /* Compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* delete the ctx and zero out the tag */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pOutput + pTestData->cipherLen, 0x00, pTestData->tagLen);

    /* Test decrypt */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad, pTestData->aadLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != pTestData->cipherLen)
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput, pTestData->cipherLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    /* we store the tag again at the end of the pOutput buffer */
    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + pTestData->cipherLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Compare the plaintext */

    cmpRes = -1;

    if (0 != pTestData->plainLen)
    {
        status = DIGI_MEMCMP(pOutput, pTestData->pPlainText, pTestData->plainLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    /* compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }

    if (OK == status)
        return 0;
    else
        return 1;

}

/*----------------------------------------------------------------------------*/

static int testAesGCMClone(
       GcmTestSuite *pGcm,
       GcmKat *pTestData
       )
{
    MSTATUS status;
    void *pCtx = NULL;
    void *pCloneCtx = NULL;
    sbyte4 cmpRes = -1;
    ubyte4 outputLen = 0;
    ubyte *pOutput = NULL;

    /* Test encrypt */

    /* Add 16 bytes for the tag in all cases, old style APIs don't support smaller tag sizes. */
    outputLen = pTestData->plainLen + 16;

    status = DIGI_CALLOC((void **) &pOutput, 1, outputLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* we'll encrypt in-place, so copy plaintext to pOutput for now */
    if (0 != pTestData->plainLen)
    {
        status = DIGI_MEMCPY(pOutput, pTestData->pPlainText, pTestData->plainLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad, pTestData->aadLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->clone(MOC_SYM(gpHwAccelCtx) pCtx, &pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Delete the original context now to verify this is not a shallow copy */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != pTestData->plainLen)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCloneCtx, pOutput, pTestData->plainLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCloneCtx, pOutput + pTestData->plainLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != pTestData->cipherLen)
    {
        /* Compare the ciphertext */
        status = DIGI_MEMCMP(pOutput, pTestData->pCipherText, pTestData->cipherLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    cmpRes = -1;

    /* Compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* delete the ctx and zero out the tag */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pOutput + pTestData->cipherLen, 0x00, pTestData->tagLen);

    /* Test decrypt */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad, pTestData->aadLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->clone(MOC_SYM(gpHwAccelCtx) pCtx, &pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Delete the original context now to verify this is not a shallow copy */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != pTestData->cipherLen)
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCloneCtx, pOutput, pTestData->cipherLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    /* we store the tag again at the end of the pOutput buffer */
    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCloneCtx, pOutput + pTestData->cipherLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Compare the plaintext */

    cmpRes = -1;

    if (0 != pTestData->plainLen)
    {
        status = DIGI_MEMCMP(pOutput, pTestData->pPlainText, pTestData->plainLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    /* compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }

    if (OK == status)
        return 0;
    else
        return 1;

}

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
/*----------------------------------------------------------------------------*/

int testAesGcmSpeed(
    GcmTestSuite *pGcm
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = 667;
    gcm_ctx_256b *pCtx = NULL;
    ubyte tagE[AES_BLOCK_SIZE] = { 0 };

    ubyte tagD[AES_BLOCK_SIZE] = { 0 };

    /* this is the nonce, used at IV */
    unsigned char pIv[] = {
        0x8a, 0xae, 0xb1, 0xc3, 0x5b, 0xfb, 0x39, 0x31, 0xd0, 0xe6, 0x27, 0xcf
    };
    unsigned int ivLen = 12;

    /* key value */
    unsigned char pKey[] = {
        0xac, 0x04, 0x6f, 0x94, 0x2a, 0x82, 0xa9, 0xdd, 0x04, 0x1e, 0x4a, 0xaf,
        0x27, 0xac, 0x23, 0xa0, 0xaf, 0x57, 0xd5, 0x91, 0x4b, 0x9f, 0xa0, 0x02,
        0x24, 0xfe, 0xcf, 0x64, 0x34, 0x2b, 0x3b, 0x55
    };
    unsigned int keyLen = 32;

    unsigned char pPlainText[] = {
        0x77, 0xa0, 0xa4, 0xa5, 0x94, 0xd8, 0xde, 0x61, 0x6b, 0x86, 0xba, 0xb5,
        0x58
    };
    unsigned int plainTextLen = 13;

    /* expected tag */
    unsigned char pExpectedTag[] = {
        0x87, 0xa0, 0xdc, 0x46, 0x60, 0x66, 0x8d, 0x21, 0x7c, 0xd9, 0x8b, 0x99
    };
    unsigned int expectedTagLen = 12;

    unsigned char pExpectedCipherText[] = {
        0x17, 0x8b, 0x93, 0x02, 0x40, 0x40, 0xa2, 0xd2, 0x32, 0x7b, 0x80, 0xc9,
        0xb5
    };
    unsigned int expectedCipherTextLen = 13;

    int i;
    struct tms tstart;
    struct tms tend;
    double diffTime;

    ubyte *pOutputFormat = "%-25s: %5g seconds\n";
    FILE *fp = NULL;
    /* buffer for output of encryption and decryption */
    if(NULL == (fp = fopen(
        "../../../projects/cryptointerface_unittest/speed_test.txt", "a")))
        goto exit;
    ubyte pDataBuffer[13] = { 0 };
    status = DIGI_MEMCPY(pDataBuffer, pPlainText, plainTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    ubyte4 dataBufferLen = plainTextLen;

    /* cipher operations are done in place, this is a copy of message
     * to compare decyption output to. */

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    diffTime = 0.0;
    for(i = 0;i < ENCRYPT_ITERATIONS; i++){

        status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pIv, ivLen, NULL, 0);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }

        status = DIGI_MEMCPY(pDataBuffer, pPlainText, plainTextLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        times(&tstart);
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pDataBuffer, dataBufferLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
        times(&tend);

        diffTime += tend.tms_utime - tstart.tms_utime;
        status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, tagE);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }

    }

    fprintf(fp, pOutputFormat, "AES encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat,"AES encrypt speed",
            diffTime / sysconf(_SC_CLK_TCK));
    /* compare computed tag with expected tag */
    status = DIGI_MEMCMP(tagE, pExpectedTag, expectedTagLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;

    }

    cmpRes = 667;
    /* compare computed cipher text with expected cipher text */
    status = DIGI_MEMCMP(pDataBuffer, pExpectedCipherText,
        expectedCipherTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;

    }

    /* delete context, so we don't have memory leak */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) (BulkCtx *) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* new context for decryption operation */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* feed cipher text */
    diffTime = 0.0;
    for(i = 0;i < DECRYPT_ITERATIONS; i++){
        status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pIv, ivLen, NULL, 0);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
        status = DIGI_MEMCPY(pDataBuffer, pExpectedCipherText,
            expectedCipherTextLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        /* provide buffer for decryption operation */
        times(&tstart);
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pDataBuffer, dataBufferLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
        times(&tend);
        diffTime += tend.tms_utime - tstart.tms_utime;

        status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, tagD);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }

    }

    fprintf(fp, pOutputFormat, "AES decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat,"AES decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

    cmpRes = 667;
    /* compare tags */
    status = DIGI_MEMCMP(tagD, pExpectedTag, expectedTagLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if(0 != cmpRes){
        status = ERR_CMP;
        goto exit;
    }

    cmpRes = 667;
    /* compare plain text */
    status = DIGI_MEMCMP(pPlainText, pDataBuffer, plainTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if(0 != cmpRes){
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);

    if(NULL != fp)
        fclose(fp);
    if (OK > status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

static int testAesGCMevp(GcmTestSuite *pGcm, GcmKat *pTestData, ubyte4 firstIndex, ubyte4 secondIndex)
{
    MSTATUS status;
    void *pCtx = NULL;
    sbyte4 cmpRes = -1;
    ubyte4 outputLen = 0;
    ubyte *pOutput = NULL;

    /* Test encrypt */

    /* Add 16 bytes for the tag in all cases, old style APIs don't support smaller tag sizes. */
    outputLen = pTestData->plainLen + 16;

    status = DIGI_CALLOC((void **) &pOutput, 1, outputLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* we'll encrypt in-place, so copy plaintext to pOutput for now */
    status = DIGI_MEMCPY(pOutput, pTestData->pPlainText, pTestData->plainLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad, pTestData->aadLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* make up to 3 calls to update */
    if (0 != firstIndex)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput, firstIndex);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + firstIndex, secondIndex - firstIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + secondIndex, pTestData->plainLen - secondIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + pTestData->plainLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Compare the ciphertext */
    status = DIGI_MEMCMP(pOutput, pTestData->pCipherText, pTestData->cipherLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    cmpRes = -1;

    /* Compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* delete the ctx and zero out the tag */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pOutput + pTestData->cipherLen, 0x00, pTestData->tagLen);

    /* Test decrypt */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen, pTestData->pAad, pTestData->aadLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* make up to 3 calls to update */
    if (0 != firstIndex)
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput, firstIndex);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + firstIndex, secondIndex - firstIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + secondIndex, pTestData->cipherLen - secondIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* we store the tag again at the end of the pOutput buffer */
    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + pTestData->cipherLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Compare the plaintext */
    cmpRes = -1;

    status = DIGI_MEMCMP(pOutput, pTestData->pPlainText, pTestData->plainLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, pTestData->tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }

    if (OK == status)
        return 0;
    else
        return 1;

}

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
static int testAesGCMevpAAD(GcmTestSuite *pGcm, GcmKat *pTestData, ubyte4 firstIndex, ubyte4 secondIndex, ubyte4 tagLen)
{
    MSTATUS status;
    void *pCtx = NULL;
    sbyte4 cmpRes = -1;
    ubyte4 outputLen = 0;
    ubyte *pOutput = NULL;

    if (pTestData->tagLen < tagLen) /* some vectors may have a smaller tag, it's already tested so return OK */
        return OK;

    /* Test encrypt */

    /* Add 16 bytes for the tag in all cases, old style APIs don't support smaller tag sizes. */
    outputLen = pTestData->plainLen + tagLen;

    status = DIGI_CALLOC((void **) &pOutput, 1, outputLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* we'll encrypt in-place, so copy plaintext to pOutput for now */
    status = DIGI_MEMCPY(pOutput, pTestData->pPlainText, pTestData->plainLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->updateNonce(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* make up to 3 calls to updateAad */
    if (0 != firstIndex)
    {
        status = pGcm->updateAad(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pAad, firstIndex);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->updateAad(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pAad + firstIndex, secondIndex - firstIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->updateAad(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pAad + secondIndex, pTestData->aadLen - secondIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* make up to 3 calls to update data */
    if (0 != firstIndex)
    {
        status = pGcm->updateData(MOC_SYM(gpHwAccelCtx) pCtx, pOutput, firstIndex);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->updateData(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + firstIndex, secondIndex - firstIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->updateData(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + secondIndex, pTestData->plainLen - secondIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->finalEx(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + pTestData->plainLen, tagLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Compare the ciphertext */
    status = DIGI_MEMCMP(pOutput, pTestData->pCipherText, pTestData->cipherLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    cmpRes = -1;

    /* Compare the tag */
    status = DIGI_MEMCMP(pOutput + pTestData->cipherLen, pTestData->pTag, tagLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* delete the ctx and zero out the tag */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Test decrypt */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pTestData->pKey, pTestData->keyLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = pGcm->updateNonce(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pIv, pTestData->ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* make up to 3 calls to updateAad */
    if (0 != firstIndex)
    {
        status = pGcm->updateAad(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pAad, firstIndex);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->updateAad(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pAad + firstIndex, secondIndex - firstIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->updateAad(MOC_SYM(gpHwAccelCtx) pCtx, pTestData->pAad + secondIndex, pTestData->aadLen - secondIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* make up to 3 calls to update data */
    if (0 != firstIndex)
    {
        status = pGcm->updateData(MOC_SYM(gpHwAccelCtx) pCtx, pOutput, firstIndex);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = pGcm->updateData(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + firstIndex, secondIndex - firstIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = pGcm->updateData(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + secondIndex, pTestData->cipherLen - secondIndex);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* we verify the tag still at the end of the pOutput buffer */
    status = pGcm->finalEx(MOC_SYM(gpHwAccelCtx) pCtx, pOutput + pTestData->cipherLen, tagLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* Compare the plaintext */
    cmpRes = -1;

    status = DIGI_MEMCMP(pOutput, pTestData->pPlainText, pTestData->plainLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* tag was verified in finalEx, nothing to compare */

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }

    if (OK == status)
        return 0;
    else
        return 1;

}
#endif

/*----------------------------------------------------------------------------*/

static int testErrorCases(GcmTestSuite *pGcm)
{
    int errorCount = 0;

    MSTATUS status ;
    BulkCtx pCtx = NULL;
    BulkCtx pCtxDec = NULL;

    ubyte pKey[16] = {0};
    sbyte4 keyLen = 16;

    ubyte pNonce[1] = {0};
    ubyte4 nonceLen = 1;

    ubyte pAad[1] = {0};
    ubyte4 aadLen = 1;

    ubyte pData[1] = {0};
    ubyte4 dataLen = 1;

    ubyte pTag[4] = {0};
    ubyte4 tagLen = 4;

    /******* GCM_createCtx *******/

    /* null params */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) NULL, keyLen, TRUE);
    if (NULL != pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, 0, ERR_NULL_POINTER);
    }

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) NULL, keyLen, FALSE);
    if (NULL != pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, 0, ERR_NULL_POINTER);
    }

    /* bad keyLen */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, 15, TRUE);
    if (NULL != pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, 0, ERR_NULL_POINTER);
    }

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, 33, FALSE);
    if (NULL != pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, 0, ERR_NULL_POINTER);
    }

    /* Correctly create an encrypt context for further tests */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if (NULL == pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, ERR_NULL_POINTER, 0);
    }

    pCtxDec = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
    if (NULL == pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, ERR_NULL_POINTER, 0);
    }

    /******* GCM_init *******/

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) NULL, pNonce, nonceLen, pAad, aadLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, NULL, nonceLen, pAad, aadLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pNonce, nonceLen, NULL, aadLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->init(MOC_SYM(gpHwAccelCtx) pCtx, pNonce, 0, pAad, aadLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /******* GCM_updateEncrypt *******/

    status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) NULL, pData, dataLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, NULL, dataLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /*
     We can Error Test GCM_updateDecrypt now even though the pCtx was
     created for encrypt. Calling GCM_updateDecrypt for such a pCtx
     is not an error as of itself */

    /******* GCM_updateDecrypt *******/

    status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) NULL, pData, dataLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtxDec, NULL, dataLen);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* GCM_final *******/

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) NULL, pTag);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, NULL);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* GCM_cipher *******/

    /* null params */
    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) NULL, pNonce, nonceLen, pAad, aadLen, pData, dataLen, tagLen, TRUE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtx, NULL, nonceLen, pAad, aadLen, pData, dataLen, tagLen, TRUE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtx, pNonce, nonceLen, NULL, aadLen, pData, dataLen, tagLen, TRUE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtx, pNonce, nonceLen, pAad, aadLen, NULL, dataLen, tagLen, TRUE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) NULL, pNonce, nonceLen, pAad, aadLen, pData, dataLen, tagLen, FALSE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtxDec, NULL, nonceLen, pAad, aadLen, pData, dataLen, tagLen, FALSE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtxDec, pNonce, nonceLen, NULL, aadLen, pData, dataLen, tagLen, FALSE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtxDec, pNonce, nonceLen, pAad, aadLen, NULL, dataLen, tagLen, FALSE);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    /* invalid verifyLen */
    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, 0, TRUE);
    errorCount += UNITTEST_TRUE(__MOC_LINE__, status);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, 0, FALSE);
    errorCount += UNITTEST_TRUE(__MOC_LINE__, status);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtxDec, pNonce, nonceLen, pAad, aadLen, pData, dataLen, 11, TRUE);
    errorCount += UNITTEST_TRUE(__MOC_LINE__, status);

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx) pCtxDec, pNonce, nonceLen, pAad, aadLen, pData, dataLen, 11, FALSE);
    errorCount += UNITTEST_TRUE(__MOC_LINE__, status);
#endif

    /******* GCM_delete *******/

    /* no tests, NULL and uncreated ctx are ok to pass in */

    /* properly delete to free memory */
    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtxDec);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

    return errorCount;
}

static int testMemLeakRoutines(
    GcmTestSuite *pGcm,
    ubyte4 cryptFlag
    )
{
    MSTATUS status;
    int errorCount = 0;
    BulkCtx pCtx = NULL;
    ubyte pKey[16] = { 0 };
    ubyte pNonce[32] = { 0 };
    ubyte pAad[20] = { 0 };
    ubyte pData[47] = { 0 };
    ubyte pTag[16] = { 0 };
    ubyte pDataAndTag[] = {
        0x00, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x97, 0x12, 0xfe, 0xd5, 0x51, 0xb1, 0xfd, 0x8b,
        0x49, 0xd4, 0x40, 0xef, 0xf6, 0x97, 0x58, 0x6d
    };

    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, sizeof(pKey), cryptFlag);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* 1) Initialize
     * 2) Initialize
     * 3) Encrypt/Decrypt
     */
    status = pGcm->init(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad));
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = pGcm->init(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad));
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (1 == cryptFlag)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* 1) Initialize
     * 2) Encrypt/Decrypt
     * 3) Encrypt/Decrypt
     */
    status = pGcm->init(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad));
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (1 == cryptFlag)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    if (1 == cryptFlag)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* 1) Initialize
     * 2) Encrypt/Decrypt
     * 3) Final
     */
    status = pGcm->init(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad));
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (1 == cryptFlag)
    {
        status = pGcm->encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = pGcm->decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pData, sizeof(pData));
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, pTag);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* 1) Initialize
     * 2) Final
     * 3) Cipher
     */
    status = pGcm->init(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad));
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = pGcm->final(MOC_SYM(gpHwAccelCtx) pCtx, pTag);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pDataAndTag, 0x00, sizeof(pData) - 16);
    if (OK != status)
        goto exit;

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pDataAndTag,
        sizeof(pData) - 16, 16, cryptFlag);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* 1) Initialize
     * 2) Cipher
     * 3) Cipher
     */
    status = pGcm->init(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad));
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pDataAndTag, 0x00, sizeof(pData) - 16);
    if (OK != status)
        goto exit;

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pDataAndTag,
        sizeof(pData) - 16, 16, cryptFlag);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pDataAndTag, 0x00, sizeof(pData) - 16);
    if (OK != status)
        goto exit;

    status = pGcm->cipher(MOC_SYM(gpHwAccelCtx)
        pCtx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pDataAndTag,
        sizeof(pData) - 16, 16, cryptFlag);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = pGcm->delete(MOC_SYM(gpHwAccelCtx) &pCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

exit:

    return errorCount;
}

/* IMPORTANT: This test is used to test against memory leaks. Normally the
 * Mocana debug memory flag can be used to check against memory leaks, but since
 * the Crypto Interface allows any algorithm implementation underneath, the
 * debug memory flag will not pick up any allocations made by the underneath
 * implementation. Ideally, when checking for memory leaks this test should be
 * run through valgrind.
 */
static int testMemLeak(
    GcmTestSuite *pGcm
    )
{
    int errorCount = 0;

   errorCount += testMemLeakRoutines(pGcm, 1);
   errorCount += testMemLeakRoutines(pGcm, 0);

   return errorCount;
}

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__)
static int testCryptoInterface(GcmTestSuite *pGcm)
{
    int errorCount = 0;
    BulkCtx pCtx = NULL;

    ubyte pKey[16] = {0};
    sbyte4 keyLen = 16;
    MocSymCtx pTest = NULL;
    sbyte4 encrypt = 0;

    /* Correctly create an encrypt context for further tests */
    pCtx = pGcm->create(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if (NULL == pCtx)
    {   /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, ERR_NULL_POINTER, 0);
    }

    if (pGcm->create == GCM_createCtx_256b)
    {
        pTest = ((gcm_ctx_256b *) pCtx)->pMocSymCtx;
        encrypt = ((gcm_ctx_256b *) pCtx)->encrypt;
    }
    else if (pGcm->create == GCM_createCtx_4k)
    {
        pTest = ((gcm_ctx_4k *) pCtx)->pMocSymCtx;
        encrypt = ((gcm_ctx_4k *) pCtx)->encrypt;
    }
    else /* pGcm->create == GCM_createCtx_64k */
    {
        pTest = ((gcm_ctx_64k *) pCtx)->pMocSymCtx;
        encrypt = ((gcm_ctx_64k *) pCtx)->encrypt;
    }

#ifdef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
    if (NULL == pTest)
    {
        /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, -1, 0);
    }
#else
    if (NULL != pTest)
    {
        /* force error */
        errorCount += UNITTEST_INT(__MOC_LINE__, -1, 0);
    }
#endif

    errorCount += pGcm->delete(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pCtx);

    return errorCount;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__) */

/*----------------------------------------------------------------------------*/

static int testSingleShot(ubyte4 keyLenBits, ubyte4 mode, ubyte4 tagLen)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    ubyte4 i = 0;
    ubyte pPlain[48] = {0};
    ubyte pCipher[64] = {0};
    BulkCtx pCtx = NULL;

    intBoolean wasNonceUsed = FALSE;

    ubyte pKey[32] = {0x01, 0x02, 0x03, 0xff, }; /* big enough for all keys */
    ubyte4 keySize = keyLenBits/8;
    ubyte pAad[8] = {0x0f, 0x0e, 0x0d, 0xcc, };
    ubyte4 aadLen = 8;
    ubyte pIv[16] = {0xff, 0xee, 0xdd, 0x01, };
    ubyte4 ivLen = 16;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_AES_GCM_newCtx(MOC_SYM(gpHwAccelCtx) &pCtx, mode, pKey, keySize, 1);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pCipher, pPlain, 48);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    status = CRYPTO_INTERFACE_AES_GCM_encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pIv, &ivLen, &wasNonceUsed, pAad, aadLen, pCipher, 48, tagLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* non-tap operators or passthrough are required to use nonce */
    retVal += UNITTEST_INT(__MOC_LINE__, wasNonceUsed, TRUE);

    status = CRYPTO_INTERFACE_AES_GCM_deleteCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Now test decrypt */
    status = CRYPTO_INTERFACE_AES_GCM_newCtx(MOC_SYM(gpHwAccelCtx) &pCtx, mode, pKey, keySize, 0);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AES_GCM_decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPlain, pCipher, 48, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtx)
    {
        status = CRYPTO_INTERFACE_AES_GCM_deleteCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKAT(ubyte4 keySize, ubyte4 mode)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    BulkCtx pCtxHw = NULL;
    BulkCtx pCtxSw = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pAad[16] = {0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00,0xff};
    ubyte pInput[80] = {0};
    ubyte pInputCopy[80] = {0};

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < 64; ++i)
    {
        pInput[i] = pInputCopy[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[32] = {0}; /* big enough for all tests */
    for (i = 0; i < keySize/8; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    switch(keySize)
    {
        case 128:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_128;
            break;

        case 192:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_192;
            break;

        case 256:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_256;
            break;

        default:
            goto exit;
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.aesInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize/8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, mode, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    switch(mode)
    {
        case GCM_MODE_256B:

            pCtxSw = CRYPTO_INTERFACE_GCM_createCtx_256b (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, TRUE);
            if (NULL == pCtxSw)
            {
                retVal += UNITTEST_STATUS(keySize, -1);
                goto exit;
            }

            status = CRYPTO_INTERFACE_GCM_cipher_256b (MOC_SYM(gpHwAccelCtx) pCtxHw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInput, 64, 16, TRUE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_cipher_256b (MOC_SYM(gpHwAccelCtx) pCtxSw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInputCopy, 64, 16, TRUE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(gpHwAccelCtx) &pCtxHw);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(gpHwAccelCtx) &pCtxSw);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            break;

        case GCM_MODE_4K:

            pCtxSw = CRYPTO_INTERFACE_GCM_createCtx_4k (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, TRUE);
            if (NULL == pCtxSw)
            {
                retVal += UNITTEST_STATUS(keySize, -1);
                goto exit;
            }

            status = CRYPTO_INTERFACE_GCM_cipher_4k (MOC_SYM(gpHwAccelCtx) pCtxHw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInput, 64, 16, TRUE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_cipher_4k (MOC_SYM(gpHwAccelCtx) pCtxSw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInputCopy, 64, 16, TRUE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(gpHwAccelCtx) &pCtxHw);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(gpHwAccelCtx) &pCtxSw);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            break;

        case GCM_MODE_64K:

            pCtxSw = CRYPTO_INTERFACE_GCM_createCtx_64k (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, TRUE);
            if (NULL == pCtxSw)
            {
                retVal += UNITTEST_STATUS(keySize, -1);
                goto exit;
            }

            status = CRYPTO_INTERFACE_GCM_cipher_64k (MOC_SYM(gpHwAccelCtx) pCtxHw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInput, 64, 16, TRUE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_cipher_64k (MOC_SYM(gpHwAccelCtx) pCtxSw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInputCopy, 64, 16, TRUE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(gpHwAccelCtx) &pCtxHw);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(gpHwAccelCtx) &pCtxSw);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            break;
    }

    status = DIGI_MEMCMP(pInput, pInputCopy, 80, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Now repeat for decrypt */

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, mode, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    switch(mode)
    {
        case GCM_MODE_256B:

            pCtxSw = CRYPTO_INTERFACE_GCM_createCtx_256b (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, FALSE);
            if (NULL == pCtxSw)
            {
                retVal += UNITTEST_STATUS(keySize, -1);
                goto exit;
            }

            status = CRYPTO_INTERFACE_GCM_cipher_256b (MOC_SYM(gpHwAccelCtx) pCtxHw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInput, 64, 16, FALSE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_cipher_256b (MOC_SYM(gpHwAccelCtx) pCtxSw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInputCopy, 64, 16, FALSE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            break;

        case GCM_MODE_4K:

            pCtxSw = CRYPTO_INTERFACE_GCM_createCtx_4k (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, FALSE);
            if (NULL == pCtxSw)
            {
                retVal += UNITTEST_STATUS(keySize, -1);
                goto exit;
            }

            status = CRYPTO_INTERFACE_GCM_cipher_4k (MOC_SYM(gpHwAccelCtx) pCtxHw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInput, 64, 16, FALSE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_cipher_4k (MOC_SYM(gpHwAccelCtx) pCtxSw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInputCopy, 64, 16, FALSE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            break;

        case GCM_MODE_64K:

            pCtxSw = CRYPTO_INTERFACE_GCM_createCtx_64k (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, FALSE);
            if (NULL == pCtxSw)
            {
                retVal += UNITTEST_STATUS(keySize, -1);
                goto exit;
            }

            status = CRYPTO_INTERFACE_GCM_cipher_64k (MOC_SYM(gpHwAccelCtx) pCtxHw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInput, 64, 16, FALSE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_GCM_cipher_64k (MOC_SYM(gpHwAccelCtx) pCtxSw, pIv, sizeof(pIv), pAad, sizeof(pAad), pInputCopy, 64, 16, FALSE);
            retVal += UNITTEST_STATUS(keySize, status);
            if (OK != status)
                goto exit;

            break;
    }

    status = DIGI_MEMCMP(pInput, pInputCopy, 64, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    switch(mode)
    {
        case GCM_MODE_256B:

            status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(gpHwAccelCtx) &pCtxHw);
            retVal += UNITTEST_STATUS(keySize, status);

            status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(gpHwAccelCtx) &pCtxSw);
            retVal += UNITTEST_STATUS(keySize, status);

            break;

        case GCM_MODE_4K:

            status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(gpHwAccelCtx) &pCtxHw);
            retVal += UNITTEST_STATUS(keySize, status);

            status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(gpHwAccelCtx) &pCtxSw);
            retVal += UNITTEST_STATUS(keySize, status);

            break;

        case GCM_MODE_64K:

            status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(gpHwAccelCtx) &pCtxHw);
            retVal += UNITTEST_STATUS(keySize, status);

            status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(gpHwAccelCtx) &pCtxSw);
            retVal += UNITTEST_STATUS(keySize, status);

            break;
    }

    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);

    return retVal;
}

static int tapTestEx(ubyte4 keySize, ubyte *pIv, ubyte4 ivLen, ubyte *pAad, ubyte4 aadLen, ubyte4 tagLen, ubyte4 mode, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    ubyte4 i = 0;
    ubyte pPlain[48] = {0};
    ubyte pCipher[64] = {0};
    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;
    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;
    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed.*/
    status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, mode, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pCipher, pPlain, 48);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    switch(mode)
    {
        case GCM_MODE_256B:
            status = CRYPTO_INTERFACE_GCM_cipher_256b (MOC_SYM(gpHwAccelCtx)
                pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen, TRUE);
            break;

        case GCM_MODE_4K:
            status = CRYPTO_INTERFACE_GCM_cipher_4k (MOC_SYM(gpHwAccelCtx)
                pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen, TRUE);
            break;

        case GCM_MODE_64K:
            status = CRYPTO_INTERFACE_GCM_cipher_64k (MOC_SYM(gpHwAccelCtx)
                pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen, TRUE);
            break;

    }
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesGcmGetKeyInfo (pCtx, mode, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* delete the context */
    switch(mode)
    {
        case GCM_MODE_256B:
            status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(gpHwAccelCtx) &pCtx);
            break;

        case GCM_MODE_4K:
            status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(gpHwAccelCtx) &pCtx);
            break;

        case GCM_MODE_64K:
            status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(gpHwAccelCtx) &pCtx);
            break;
    }
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = DIGI_FREE((void **)&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, mode, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesGcmDeferKeyUnload(pCtx, mode, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    switch(mode)
    {
        case GCM_MODE_256B:
            status = CRYPTO_INTERFACE_GCM_cipher_256b (MOC_SYM(gpHwAccelCtx)
                pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen, FALSE);
            break;

        case GCM_MODE_4K:
            status = CRYPTO_INTERFACE_GCM_cipher_4k (MOC_SYM(gpHwAccelCtx)
                pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen, FALSE);
            break;

        case GCM_MODE_64K:
            status = CRYPTO_INTERFACE_GCM_cipher_64k (MOC_SYM(gpHwAccelCtx)
                pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen, FALSE);
            break;
    }
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPlain, pCipher, 48, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    switch(mode)
    {
        case GCM_MODE_256B:
            status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(gpHwAccelCtx) &pCtx);
            break;

        case GCM_MODE_4K:
            status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(gpHwAccelCtx) &pCtx);
            break;

        case GCM_MODE_64K:
            status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(gpHwAccelCtx) &pCtx);
            break;
    }
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    /* Remember to free SymWrapper after use */
    if (NULL != pSymWrapper)
    {
        (void) DIGI_FREE((void **)&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    return retVal;
}

/*----------------------------------------------------------------------------*/

static int tapTestSingleShot(ubyte4 keySize, ubyte *pIv, ubyte4 ivLen, ubyte *pAad, ubyte4 aadLen, ubyte4 tagLen, ubyte4 mode, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    ubyte4 i = 0;
    ubyte pPlain[48] = {0};
    ubyte pCipher[64] = {0};
    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;
    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;
    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    intBoolean wasNonceUsed = FALSE;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* We'll only test deferred unload  with this method in the case of GCM_MODE_GENERAL */
    if (GCM_MODE_GENERAL != mode && testDeferredUnload)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        return 1;
    }

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed.*/

    /* if testing mode = GCM_GENERAL we pass in the top level context, otherwise the tbl context */
    if (GCM_MODE_GENERAL == mode)
    {
        status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx, mode, MOCANA_SYM_TAP_ENCRYPT);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_CALLOC(&pCtx, 1, sizeof(AES_GCM_CTX));
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        ((AES_GCM_CTX *) pCtx)->tableSize = mode;

        status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (pSymWrapper, &((AES_GCM_CTX *) pCtx)->pTblCtx, mode, MOCANA_SYM_TAP_ENCRYPT);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = DIGI_MEMCPY(pCipher, pPlain, 48);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    status = CRYPTO_INTERFACE_AES_GCM_encrypt(MOC_SYM(gpHwAccelCtx) pCtx, pIv, &ivLen, &wasNonceUsed, pAad, aadLen, pCipher, 48, tagLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesGcmGetKeyInfo (pCtx, mode, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_AES_GCM_deleteCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = DIGI_FREE((void **)&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    if (GCM_MODE_GENERAL == mode)
    {
        status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx, mode, MOCANA_SYM_TAP_DECRYPT);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_CALLOC(&pCtx, 1, sizeof(AES_GCM_CTX));
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        ((AES_GCM_CTX *) pCtx)->tableSize = mode;

        status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc (pSymWrapper, &((AES_GCM_CTX *) pCtx)->pTblCtx, mode, MOCANA_SYM_TAP_DECRYPT);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesGcmDeferKeyUnload(pCtx, mode, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_AES_GCM_decrypt(MOC_SYM(gpHwAccelCtx) pCtx, pIv, ivLen, pAad, aadLen, pCipher, 48, tagLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPlain, pCipher, 48, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtx)
    {
        status = CRYPTO_INTERFACE_AES_GCM_deleteCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* Remember to free SymWrapper after use */
    if (NULL != pSymWrapper)
    {
        (void) DIGI_FREE((void **)&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    return retVal;
}

/*----------------------------------------------------------------------------*/

static int tapTest(ubyte4 keySize)
{
    int errorCount = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pAad[16] = {0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0xff};

#ifdef __ENABLE_DIGICERT_SOFTHSM_TEST_SET__
    errorCount += tapTestEx (
        keySize, pIv, 16, NULL, 0, 16, GCM_MODE_256B, FALSE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, pAad, 16, 16, GCM_MODE_256B, FALSE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, NULL, 0, 16, GCM_MODE_4K, FALSE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, pAad, 16, 16, GCM_MODE_4K, FALSE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, NULL, 0, 16, GCM_MODE_64K, FALSE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, pAad, 16, 16, GCM_MODE_64K, FALSE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, pAad, 16, 16, GCM_MODE_256B, TRUE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, pAad, 16, 16, GCM_MODE_4K, TRUE);
    if (errorCount)
        goto exit;

    errorCount += tapTestEx (
        keySize, pIv, 16, NULL, 0, 16, GCM_MODE_64K, TRUE);
    if (errorCount)
        goto exit;

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, pAad, 16, 16, GCM_MODE_256B, FALSE);

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, pAad, 16, 16, GCM_MODE_4K, FALSE);

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, pAad, 16, 16, GCM_MODE_64K, FALSE);
#endif

    /* Only use 12 byte IV and modeless for cloudhsm test set */
    errorCount += tapTestSingleShot(
        keySize, pIv, 12, pAad, 16, 16, GCM_MODE_GENERAL, FALSE);

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, pAad, 16, 12, GCM_MODE_GENERAL, FALSE);

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, NULL, 0, 16, GCM_MODE_GENERAL, FALSE);

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, NULL, 0, 8, GCM_MODE_GENERAL, FALSE);

    errorCount += tapTestSingleShot(
        keySize, pIv, 12, pAad, 16, 16, GCM_MODE_GENERAL, TRUE);

exit:

    return errorCount;
}
#endif


/*----------------------------------------------------------------------------*/

int crypto_interface_aesgcm_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0, retVal = 0, index, testIndex, updateIndices;
    ubyte4 modNum = 1;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    GcmTestSuite gcmTests[3] = {
        {
            .create = GCM_createCtx_256b,
            .delete = GCM_deleteCtx_256b,
            .init = GCM_init_256b,
            .encrypt = GCM_update_encrypt_256b,
            .decrypt = GCM_update_decrypt_256b,
            .final = GCM_final_256b,
            .cipher = GCM_cipher_256b,
            .clone = GCM_clone_256b,
            .updateNonce = GCM_update_nonce_256b,
            .updateAad = GCM_update_aad_256b,
            .updateData = GCM_update_data_256b,
            .finalEx = GCM_final_ex_256b
        },
        {
            .create = GCM_createCtx_4k,
            .delete = GCM_deleteCtx_4k,
            .init = GCM_init_4k,
            .encrypt = GCM_update_encrypt_4k,
            .decrypt = GCM_update_decrypt_4k,
            .final = GCM_final_4k,
            .cipher = GCM_cipher_4k,
            .clone = GCM_clone_4k,
            .updateNonce = GCM_update_nonce_4k,
            .updateAad = GCM_update_aad_4k,
            .updateData = GCM_update_data_4k,
            .finalEx = GCM_final_ex_4k
        },
        {
            .create = GCM_createCtx_64k,
            .delete = GCM_deleteCtx_64k,
            .init = GCM_init_64k,
            .encrypt = GCM_update_encrypt_64k,
            .decrypt = GCM_update_decrypt_64k,
            .final = GCM_final_64k,
            .cipher = GCM_cipher_64k,
            .clone = GCM_clone_64k,
            .updateNonce = GCM_update_nonce_64k,
            .updateAad = GCM_update_aad_64k,
            .updateData = GCM_update_data_64k,
            .finalEx = GCM_final_ex_64k
        }
    };

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
    errorCount = (errorCount + testAesGcmSpeed(&(gcmTests[0])));
#else

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
    }

    errorCount += tapTest(128);
    errorCount += tapTest(192);
    errorCount += tapTest(256);

#ifdef __ENABLE_DIGICERT_SOFTHSM_TEST_SET__
    errorCount += tapKAT(128, GCM_MODE_256B);
    errorCount += tapKAT(192, GCM_MODE_256B);
    errorCount += tapKAT(256, GCM_MODE_256B);

    errorCount += tapKAT(128, GCM_MODE_4K);
    errorCount += tapKAT(192, GCM_MODE_4K);
    errorCount += tapKAT(256, GCM_MODE_4K);

    errorCount += tapKAT(128, GCM_MODE_64K);
    errorCount += tapKAT(192, GCM_MODE_64K);
    errorCount += tapKAT(256, GCM_MODE_64K);
#endif
#endif /* __ENABLE_DIGICERT_TAP__ */

    /* non-tap single shot API tests */
    errorCount += testSingleShot(128, GCM_MODE_256B, 16);
    errorCount += testSingleShot(128, GCM_MODE_256B, 12);
    errorCount += testSingleShot(128, GCM_MODE_256B, 8);
    errorCount += testSingleShot(128, GCM_MODE_4K, 16);
    errorCount += testSingleShot(128, GCM_MODE_64K, 16);
    errorCount += testSingleShot(192, GCM_MODE_256B, 16);
    errorCount += testSingleShot(192, GCM_MODE_4K, 16);
    errorCount += testSingleShot(192, GCM_MODE_64K, 16);
    errorCount += testSingleShot(256, GCM_MODE_256B, 16);
    errorCount += testSingleShot(256, GCM_MODE_4K, 16);
    errorCount += testSingleShot(256, GCM_MODE_64K, 16);

/* no passthough gor GCM_MODE_GENERAL, test only if mbed */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__)
    errorCount += testSingleShot(128, GCM_MODE_GENERAL, 16);
    errorCount += testSingleShot(128, GCM_MODE_GENERAL, 12);
    errorCount += testSingleShot(128, GCM_MODE_GENERAL, 8);
    errorCount += testSingleShot(192, GCM_MODE_GENERAL, 16);
    errorCount += testSingleShot(256, GCM_MODE_GENERAL, 16);
#endif

    /* TESTS GO HERE */
    for (index = 0; index < 3; ++index)
    {
        retVal = testAesGCMClone(&(gcmTests[index]), &pTestData[0]);
        errorCount += retVal;

        for (testIndex = 0; testIndex < (sizeof(pTestData)/sizeof(pTestData[0])); ++testIndex)
        {
            retVal = testAesGCMevpSingleUpdate(&(gcmTests[index]), &pTestData[testIndex]);
            errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
            if (retVal) printf("FAIL: testAesGCMevpSingleUpdate, test suite = %d, vector number = %d\n", index, testIndex);
#endif

            retVal = testAesGCMOneShot(&(gcmTests[index]), &pTestData[testIndex]);
            errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
            if (retVal) printf("FAIL: testAesGCMOneShot, test suite = %d, vector number = %d\n", index, testIndex);
#endif

            /* If plainLen is at least 34 we test multiple update calls over varying sizes */
            if (pTestData[testIndex].plainLen >= 34)
            {
                for (updateIndices = 0; updateIndices < sizeof(gpUpdateDataIndices)/sizeof(gpUpdateDataIndices[0]); ++updateIndices)
                {
                    retVal = testAesGCMevp(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1]);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d\n", index, testIndex, updateIndices);
#endif
                }
            }

#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
            /* If plainLen and aadLen is at least 34 we test the update APIs, test also each standard tagLen */
            if (pTestData[testIndex].plainLen >= 34 && pTestData[testIndex].aadLen >= 34)
            {
                for (updateIndices = 0; updateIndices < sizeof(gpUpdateDataIndices)/sizeof(gpUpdateDataIndices[0]); ++updateIndices)
                {
                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 4);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 4\n", index, testIndex, updateIndices);
#endif

                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 8);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 8\n", index, testIndex, updateIndices);
#endif

                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 12);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 12\n", index, testIndex, updateIndices);
#endif

                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 13);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 13\n", index, testIndex, updateIndices);
#endif

                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 14);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 14\n", index, testIndex, updateIndices);
#endif

                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 15);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 15\n", index, testIndex, updateIndices);
#endif

                    retVal = testAesGCMevpAAD(&(gcmTests[index]), &pTestData[testIndex], gpUpdateDataIndices[updateIndices][0], gpUpdateDataIndices[updateIndices][1], 16);
                    errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
                    if (retVal) printf("FAIL: testAesGCMevp, test suite = %d, vector number = %d, updateIndices = %d, tagLen = 16\n", index, testIndex, updateIndices);
#endif
                }
            }
#endif /* __ENABLE_DIGICERT_MBED_SYM_OPERATORS__ */
        }

        retVal = testErrorCases(&(gcmTests[index]));
        errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
        if (retVal) printf("FAIL: testErrorCases, test suite = %d\n", index);
#endif

        retVal = testMemLeak(&(gcmTests[index]));
        errorCount += retVal;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__)
        retVal = testCryptoInterface(&(gcmTests[index]));
        errorCount += retVal;
#ifdef __DEBUG_TEST_VECTORS__
        if (retVal) printf("FAIL: testCryptoInterface, test suite = %d\n", index);
#endif
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__) */
    }
#endif

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    TAP_EXAMPLE_clean();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
