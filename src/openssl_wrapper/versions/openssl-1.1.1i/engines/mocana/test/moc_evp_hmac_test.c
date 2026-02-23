/*
 * moc_evp_hmac_test.c
 *
 * Test program to verify HMAC functions
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include <string.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>

#define MAX_HMAC_OUTPUT_LEN   128

typedef struct
{
    char *pKey;
    int keyLen;
    char *pData;
    int dataLen;
    char *pMac;
} HmacTestData;

typedef struct
{
    char *pStr;
    const EVP_MD *(*pDigest)(void);
    HmacTestData *pVectors;
    int vectorCount;
} HmacDigestData;

/* Test vectors for HMAC MD5
 */
HmacTestData pHmacMd5TestVectors[] = {
    {
        
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b",
        16,
        
            "Hi There",
        8,
        
            "\x092\x094\x072\x07a\x036\x038\x0bb\x01c"
            "\x013\x0f4\x08e\x0f8\x015\x08b\x0fc\x09d"
    },
    {
        
            "Jefe",
        4,
        
            "what do ya want for nothing?",
        28,
        
            "\x075\x00c\x078\x03e\x06a\x0b0\x0b5\x003"
            "\x0ea\x0a8\x06e\x031\x00a\x05d\x0b7\x038"
    },
    {
        
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa",
        16,
        
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd",
        50,
        
            "\x056\x0be\x034\x052\x01d\x014\x04c\x088"
            "\x0db\x0b8\x0c7\x033\x0f0\x0e8\x0b3\x0f6"
    },
    {
        
            "\x001\x002\x003\x004\x005\x006\x007\x008"
            "\x009\x00a\x00b\x00c\x00d\x00e\x00f\x010"
            "\x011\x012\x013\x014\x015\x016\x017\x018"
            "\x019",
        25,
        
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd",
        50,
        
            "\x069\x07e\x0af\x00a\x0ca\x03a\x03a\x0ea"
            "\x03a\x075\x016\x047\x046\x0ff\x0aa\x079"
    },
    {
        
            "\x00c\x00c\x00c\x00c\x00c\x00c\x00c\x00c"
            "\x00c\x00c\x00c\x00c\x00c\x00c\x00c\x00c",
        16,
        
            "Test With Truncation",
        20,
        
            "\x056\x046\x01e\x0f2\x034\x02e\x0dc\x000"
            "\x0f9\x0ba\x0b9\x095\x069\x00e\x0fd\x04c"
    },
    {
        
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa",
        80,
        
            "Test Using Larger Than Block-Size Key - Hash Key First",
        54,
        
            "\x06b\x01a\x0b7\x0fe\x04b\x0d7\x0bf\x08f"
            "\x00b\x062\x0e6\x0ce\x061\x0b9\x0d0\x0cd"
    },
    {
        
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa",
        80,
        
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        73,
        
            "\x06f\x063\x00f\x0ad\x067\x0cd\x0a0\x0ee"
            "\x01f\x0b1\x0f5\x062\x0db\x03a\x0a5\x03e"
    }
};

HmacDigestData hmacMd5TestInfo = {
    "HMAC MD5",
    EVP_md5,
    pHmacMd5TestVectors,
    sizeof(pHmacMd5TestVectors)/sizeof(pHmacMd5TestVectors[0])
};

/* Test vectors for HMAC SHA1
 */
HmacTestData pHmacSha1TestVectors[] = {
    {
        
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b",
        20,
        
            "Hi There",
        8,
        
            "\x0b6\x017\x031\x086\x055\x005\x072\x064"
            "\x0e2\x08b\x0c0\x0b6\x0fb\x037\x08c\x08e"
            "\x0f1\x046\x0be\x000"
    },
    {
        
            "Jefe",
        4,
        
            "what do ya want for nothing?",
        28,
        
            "\x0ef\x0fc\x0df\x06a\x0e5\x0eb\x02f\x0a2"
            "\x0d2\x074\x016\x0d5\x0f1\x084\x0df\x09c"
            "\x025\x09a\x07c\x079"
    },
    {
        
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa",
        20,
        
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd\x0dd"
            "\x0dd\x0dd",
        50,
        
            "\x012\x05d\x073\x042\x0b9\x0ac\x011\x0cd"
            "\x091\x0a3\x09a\x0f4\x08a\x0a1\x07b\x04f"
            "\x063\x0f1\x075\x0d3"
    },
    {
        
            "\x001\x002\x003\x004\x005\x006\x007\x008"
            "\x009\x00a\x00b\x00c\x00d\x00e\x00f\x010"
            "\x011\x012\x013\x014\x015\x016\x017\x018"
            "\x019",
        25,
        
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd\x0cd"
            "\x0cd\x0cd",
        50,
        
            "\x04c\x090\x007\x0f4\x002\x062\x050\x0c6"
            "\x0bc\x084\x014\x0f9\x0bf\x050\x0c8\x06c"
            "\x02d\x072\x035\x0da"
    },
    {
        
            "\x00c\x00c\x00c\x00c\x00c\x00c\x00c\x00c"
            "\x00c\x00c\x00c\x00c\x00c\x00c\x00c\x00c"
            "\x00c\x00c\x00c\x00c",
        20,
        
            "Test With Truncation",
        20,
        
            "\x04c\x01a\x003\x042\x04b\x055\x0e0\x07f"
            "\x0e7\x0f2\x07b\x0e1\x0d5\x08b\x0b9\x032"
            "\x04a\x09a\x05a\x004"
    },
    {
        
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa",
        80,
        
            "Test Using Larger Than Block-Size Key - Hash Key First",
        54,
        
            "\x0aa\x04a\x0e5\x0e1\x052\x072\x0d0\x00e"
            "\x095\x070\x056\x037\x0ce\x08a\x03b\x055"
            "\x0ed\x040\x021\x012"
    },
    {
        
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa"
            "\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa\x0aa",
        80,
        
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        73,
        
            "\x0e8\x0e9\x09d\x00f\x045\x023\x07d\x078"
            "\x06d\x06b\x0ba\x0a7\x096\x05c\x078\x008"
            "\x0bb\x0ff\x01a\x091"
    }
};

HmacDigestData hmacSha1TestInfo = {
    "HMAC SHA1",
    EVP_sha1,
    pHmacSha1TestVectors,
    sizeof(pHmacSha1TestVectors)/sizeof(pHmacSha1TestVectors[0])
};

/* Test vectors for HMAC SHA224
 */
HmacTestData pHmacSha224TestVectors[] = {
    {
        
            "\x075\x0ad\x07c\x05f\x0b3\x0eb\x016\x0cc"
            "\x0f6\x0c8\x0ce\x0f6\x0c0\x0cd\x0d7\x0d2"
            "\x088\x0a4\x006\x073\x060\x029\x090\x0c6"
            "\x0d5\x0c3\x014\x07f\x017\x0f5\x0dc\x053"
            "\x05a\x030\x060\x068\x07b\x0ec\x00b\x00a"
            "\x0e7\x0f7\x042\x09f\x0b9\x00c\x0a3\x0dd"
            "\x022\x0a7",
        50,
        
            "\x056\x0cd\x0b7\x038\x069\x06e\x086\x0f5"
            "\x0f2\x0d2\x09e\x026\x036\x0b8\x010\x0a4"
            "\x080\x0d5\x00d\x0ee\x01e\x0c9\x007\x0c0"
            "\x0ac\x052\x013\x0e7\x095\x0bf\x092\x053"
            "\x0d6\x0a8\x010\x06e\x005\x0dd\x06c\x0ac"
            "\x092\x09c\x039\x063\x04e\x007\x065\x0de"
            "\x029\x0d4\x018\x0ad\x040\x047\x0df\x03e"
            "\x017\x05d\x00a\x0b2\x022\x04b\x053\x0e9"
            "\x08b\x026\x0c0\x0df\x02f\x0e4\x0ca\x03c"
            "\x0ea\x083\x0be\x026\x014\x088\x064\x05a"
            "\x04b\x0ab\x0df\x07b\x073\x0d1\x0d4\x0a9"
            "\x0fc\x03a\x0ce\x056\x063\x0fc\x0e1\x055"
            "\x0fc\x0b0\x08e\x034\x0ee\x06b\x0e7\x0cc"
            "\x07f\x0f0\x0f3\x016\x092\x023\x054\x041"
            "\x06d\x0c1\x027\x001\x0c0\x04f\x02c\x029"
            "\x0e3\x050\x027\x07c\x060\x0bb\x086\x0c0",
        128,
        
            "\x0a3\x0b6\x04a\x07e\x0e8\x0ff\x0e8\x0db"
            "\x072\x05a\x05f\x0b3\x085\x047\x075\x06e"
            "\x0d4\x07d\x084\x0ec\x0d2\x076\x085\x0ca"
            "\x028\x077\x0f5\x002"
    }
};

HmacDigestData hmacSha224TestInfo = {
    "HMAC SHA224",
    EVP_sha224,
    pHmacSha224TestVectors,
    sizeof(pHmacSha224TestVectors)/sizeof(pHmacSha224TestVectors[0])
};

/* Test vectors for HMAC SHA256
 */
HmacTestData pHmacSha256TestVectors[] = {
    {
        
            "\x097\x079\x0d9\x012\x006\x042\x079\x07f"
            "\x017\x047\x002\x05d\x05b\x022\x0b7\x0ac"
            "\x060\x07c\x0ab\x008\x0e1\x075\x08f\x02f"
            "\x03a\x046\x0c8\x0be\x01e\x025\x0c5\x03b"
            "\x08c\x06a\x08f\x058\x0ff\x0ef\x0a1\x076",
        40,
        
            "\x0b1\x068\x09c\x025\x091\x0ea\x0f3\x0c9"
            "\x0e6\x060\x070\x0f8\x0a7\x079\x054\x0ff"
            "\x0b8\x017\x049\x0f1\x0b0\x003\x046\x0f9"
            "\x0df\x0e0\x0b2\x0ee\x090\x05d\x0cc\x028"
            "\x08b\x0af\x04a\x092\x0de\x03f\x040\x001"
            "\x0dd\x09f\x044\x0c4\x068\x0c3\x0d0\x07d"
            "\x06c\x06e\x0e8\x02f\x0ac\x0ea\x0fc\x097"
            "\x0c2\x0fc\x00f\x0c0\x060\x017\x019\x0d2"
            "\x0dc\x0d0\x0aa\x02a\x0ec\x092\x0d1\x0b0"
            "\x0ae\x093\x03c\x065\x0eb\x006\x0a0\x03c"
            "\x09c\x093\x05c\x02b\x0ad\x004\x059\x081"
            "\x002\x041\x034\x07a\x0b8\x07e\x09f\x011"
            "\x0ad\x0b3\x004\x015\x042\x04c\x06c\x07f"
            "\x05f\x022\x0a0\x003\x0b8\x0ab\x08d\x0e5"
            "\x04f\x06d\x0ed\x00e\x03a\x0b9\x024\x05f"
            "\x0a7\x095\x068\x045\x01d\x0fa\x025\x08e",
        128,
        
            "\x076\x09f\x000\x0d3\x0e6\x0a6\x0cc\x01f"
            "\x0b4\x026\x0a1\x04a\x04f\x076\x0c6\x046"
            "\x02e\x061\x049\x072\x06e\x00d\x0ee\x00e"
            "\x0c0\x0cf\x097\x0a1\x066\x005\x0ac\x08b"
    }
};

HmacDigestData hmacSha256TestInfo = {
    "HMAC SHA256",
    EVP_sha256,
    pHmacSha256TestVectors,
    sizeof(pHmacSha256TestVectors)/sizeof(pHmacSha256TestVectors[0])
};

/* Test vectors for HMAC SHA384
 */
HmacTestData pHmacSha384TestVectors[] = {
    {
        
            "\x05e\x0ab\x00d\x0fa\x027\x031\x012\x060"
            "\x0d7\x0bd\x0dc\x0f7\x071\x012\x0b2\x03d"
            "\x08b\x042\x0eb\x07a\x05d\x072\x0a5\x0a3"
            "\x018\x0e1\x0ba\x07e\x079\x027\x0f0\x007"
            "\x09d\x0bb\x070\x013\x017\x0b8\x07a\x033"
            "\x040\x0e1\x056\x0db\x0ce\x0e2\x08e\x0c3"
            "\x0a8\x0d9",
        50,
        
            "\x0f4\x013\x080\x012\x03c\x0cb\x0ec\x04c"
            "\x052\x07b\x042\x056\x052\x064\x011\x091"
            "\x0e9\x00a\x017\x0d4\x05e\x02f\x062\x006"
            "\x0cf\x001\x0b5\x0ed\x0be\x093\x02d\x041"
            "\x0cc\x08a\x024\x005\x0c3\x019\x056\x017"
            "\x0da\x02f\x042\x005\x035\x0ee\x0d4\x022"
            "\x0ac\x060\x040\x0d9\x0cd\x065\x031\x042"
            "\x024\x0f0\x023\x0f3\x0ba\x073\x00d\x019"
            "\x0db\x098\x044\x0c7\x01c\x032\x09c\x08d"
            "\x09d\x073\x0d0\x04d\x08c\x05f\x024\x04a"
            "\x0ea\x080\x048\x082\x092\x0dc\x080\x03e"
            "\x077\x024\x002\x0e7\x02d\x02e\x09f\x01b"
            "\x0ab\x0a5\x0a6\x000\x04f\x000\x006\x0d8"
            "\x022\x0b0\x0b2\x0d6\x05e\x09e\x04a\x030"
            "\x02d\x0d4\x0f7\x076\x0b4\x07a\x097\x022"
            "\x050\x005\x01a\x070\x01f\x0ab\x02b\x070",
        128,
        
            "\x07c\x0f5\x0a0\x061\x056\x0ad\x03d\x0e5"
            "\x040\x05a\x05d\x026\x01d\x0e9\x002\x075"
            "\x0f9\x0bb\x036\x0de\x045\x066\x07f\x084"
            "\x0d0\x08f\x0bc\x0b3\x008\x0ca\x08f\x053"
            "\x0a4\x019\x0b0\x07d\x0ea\x0b3\x0b5\x0f8"
            "\x0ea\x023\x01c\x05b\x003\x06f\x088\x075"
    }
};

HmacDigestData hmacSha384TestInfo = {
    "HMAC SHA384",
    EVP_sha384,
    pHmacSha384TestVectors,
    sizeof(pHmacSha384TestVectors)/sizeof(pHmacSha384TestVectors[0])
};

/* Test vectors for HMAC SHA512
 */
HmacTestData pHmacSha512TestVectors[] = {
    {
        
            "\x057\x0c2\x0eb\x067\x07b\x050\x093\x0b9"
            "\x0e8\x029\x0ea\x04b\x0ab\x0b5\x00b\x0de"
            "\x055\x0d0\x0ad\x059\x0fe\x0c3\x04a\x061"
            "\x089\x073\x080\x02b\x02a\x0d9\x0b7\x08e"
            "\x026\x0b2\x004\x05d\x0da\x078\x04d\x0f3"
            "\x0ff\x090\x0ae\x00f\x02c\x0c5\x01c\x0e3"
            "\x09c\x0f5\x048\x067\x032\x00a\x0c6\x0f3"
            "\x0ba\x02c\x06f\x00d\x072\x036\x004\x080"
            "\x0c9\x066\x014\x0ae\x066\x058\x01f\x026"
            "\x06c\x035\x0fb\x079\x0fd\x028\x077\x04a"
            "\x0fd\x011\x03f\x0a5\x018\x07e\x0ff\x092"
            "\x006\x0d7\x0cb\x0e9\x00d\x0d8\x0bf\x067"
            "\x0c8\x044\x0e2\x002",
        100,
        
            "\x024\x023\x0df\x0f4\x08b\x031\x02b\x0e8"
            "\x064\x0cb\x034\x090\x064\x01f\x079\x03d"
            "\x02b\x09f\x0b6\x08a\x077\x063\x0b8\x0e2"
            "\x098\x0c8\x06f\x042\x024\x05e\x045\x040"
            "\x0eb\x001\x0ae\x04d\x02d\x045\x000\x037"
            "\x00b\x018\x086\x0f2\x03c\x0a2\x0cf\x097"
            "\x001\x070\x04c\x0ad\x05b\x0d2\x01b\x0a8"
            "\x07b\x081\x01d\x0af\x07a\x085\x04e\x0a2"
            "\x04a\x056\x056\x05c\x0ed\x042\x05b\x035"
            "\x0e4\x00e\x01a\x0cb\x0eb\x0e0\x036\x003"
            "\x0e3\x05d\x0cf\x04a\x010\x00e\x057\x021"
            "\x084\x008\x0a1\x0d8\x0db\x0cc\x03b\x099"
            "\x029\x06c\x0fe\x0a9\x031\x0ef\x0e3\x0eb"
            "\x0d8\x0f7\x019\x0a6\x0d9\x0a1\x054\x087"
            "\x0b9\x0ad\x067\x0ea\x0fe\x0df\x015\x055"
            "\x09c\x0a4\x024\x045\x0b0\x0f9\x0b4\x02e",
        128,
        
            "\x033\x0c5\x011\x0e9\x0bc\x023\x007\x0c6"
            "\x027\x058\x0df\x061\x012\x05a\x098\x00e"
            "\x0e6\x04c\x0ef\x0eb\x0d9\x009\x031\x0cb"
            "\x091\x0c1\x037\x042\x0d4\x071\x04c\x006"
            "\x0de\x040\x003\x0fa\x0f3\x0c4\x01c\x006"
            "\x0ae\x0fc\x063\x08a\x0d4\x07b\x021\x090"
            "\x06e\x06b\x010\x048\x016\x0b7\x02d\x0e6"
            "\x026\x09e\x004\x05a\x01f\x044\x029\x0d4"
    }
};

HmacDigestData hmacSha512TestInfo = {
    "HMAC SHA512",
    EVP_sha512,
    pHmacSha512TestVectors,
    sizeof(pHmacSha512TestVectors)/sizeof(pHmacSha512TestVectors[0])
};

static int testHmac(HmacDigestData *pTestInfo)
{
    int ret = 0, status, count, update;
    unsigned int outLen;
    HMAC_CTX *pCtx = NULL;
    HmacTestData *pCurTest;
    unsigned char pOutput[MAX_HMAC_OUTPUT_LEN];

    pCtx = HMAC_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: HMAC_CTX_new failed\n");
        ret = -1;
        goto exit;
    }

    for (count = 0; count < pTestInfo->vectorCount; count++)
    {
        pCurTest = pTestInfo->pVectors + count;

        status = HMAC_Init_ex(
            pCtx, pCurTest->pKey, pCurTest->keyLen, pTestInfo->pDigest(), NULL);
        if (1 != status)
        {
            goto err;
        }

        status = HMAC_Update(
            pCtx, (const unsigned char *) pCurTest->pData, pCurTest->dataLen);
        if (1 != status)
        {
            goto err;
        }

        status = HMAC_Final(pCtx, pOutput, &outLen);
        if (1 != status)
        {
            goto err;
        }

        HMAC_CTX_reset(pCtx);

        if (outLen != EVP_MD_size(pTestInfo->pDigest()))
        {
            goto err;
        }

        if (memcmp(pOutput, pCurTest->pMac, outLen))
        {
            goto err;
        }

        memset(pOutput, 0x00, sizeof(pOutput));

        status = HMAC_Init_ex(
            pCtx, pCurTest->pKey, pCurTest->keyLen, pTestInfo->pDigest(), NULL);
        if (1 != status)
        {
            goto err;
        }

        for (update = 0; update < pCurTest->dataLen; update++)
        {
            status = HMAC_Update(
                pCtx, (const unsigned char *) pCurTest->pData + update, 1);
            if (1 != status)
            {
                goto err;
            }
        }

        status = HMAC_Final(pCtx, pOutput, &outLen);
        if (1 != status)
        {
            goto err;
        }

        HMAC_CTX_reset(pCtx);

        if (outLen != EVP_MD_size(pTestInfo->pDigest()))
        {
            goto err;
        }

        if (memcmp(pOutput, pCurTest->pMac, outLen))
        {
            goto err;
        }

        continue;

err:

        fprintf(
            stderr, "ERROR: %s test vector %d failed\n", pTestInfo->pStr,
            count + 1);
        ret = -1;
    }

exit:

    if (NULL != pCtx)
    {
        HMAC_CTX_free(pCtx);
    }

    return ret;
}

int main()
{
    int ret = 0;
    ENGINE *pEng;

    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
    ENGINE_load_builtin_engines();

    pEng = ENGINE_by_id("mocana");
    if (NULL == pEng)
    {
        ret = -1;
        fprintf(stderr, "ERROR: Failed to load Mocana engine\n");
    }

#ifdef __ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__
    if (0 == ENGINE_set_default(pEng, ENGINE_METHOD_ALL))
    {
        fprintf(stderr, "ERROR: Failed to set the dynamic engine\n");
        ret = -1;
    }
#endif /* __ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__ */

    if (0 != testHmac(&hmacMd5TestInfo))
    {
        ret = -1;
    }

    if (0 != testHmac(&hmacSha1TestInfo))
    {
        ret = -1;
    }

    if (0 != testHmac(&hmacSha224TestInfo))
    {
        ret = -1;
    }

    if (0 != testHmac(&hmacSha256TestInfo))
    {
        ret = -1;
    }

    if (0 != testHmac(&hmacSha384TestInfo))
    {
        ret = -1;
    }

    if (0 != testHmac(&hmacSha512TestInfo))
    {
        ret = -1;
    }

    ENGINE_free(pEng);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();

    if (-1 == ret)
    {
        fprintf(stdout, "HMAC Test Failed\n");
    }
    else
    {
        fprintf(stdout, "HMAC Test Passed\n");
    }

    return ret;
}
