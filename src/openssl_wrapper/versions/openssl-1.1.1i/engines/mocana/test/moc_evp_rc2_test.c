/*
 * moc_evp_rc2_test.c
 *
 * Test program to verify RC2 EVP functions
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
#include <openssl/crypto.h>

typedef struct
{
    char *pKey;
    int keyLen;
    int effectiveKeyBits;
    char *pIv;
    char *pPlain;
    int plainLen;
    char *pCipher;
    int cipherLen;
} Rc2TestData;

typedef struct
{
    char *pStr;
    const EVP_CIPHER *(*pCipher)(void);
    Rc2TestData *pVectors;
    int vectorCount;
} Rc2CipherMode;

Rc2TestData pRc2EcbTestVectors[] = {
    {
        
            "\x026\x01E\x057\x08E\x0C9\x062\x0BF\x0B8"
            "\x03E\x096",
        10,
        80,
        NULL,
        
            "\x011\x022\x033\x044\x055\x066\x077\x088"
            "\x099\x0AA\x0BB\x0CC\x0DD\x0EE\x0FF\x000"
            "\x011\x022\x033\x044\x055\x066\x077\x088"
            "\x099\x0AA\x0BB\x0CC\x0DD\x0EE\x0FF\x000",
        32,
        
            "\x0F9\x09A\x03A\x0DB\x000\x03B\x07A\x0EB"
            "\x081\x0E3\x06B\x0A9\x0E5\x037\x010\x0D1"
            "\x0F9\x09A\x03A\x0DB\x000\x03B\x07A\x0EB"
            "\x081\x0E3\x06B\x0A9\x0E5\x037\x010\x0D1",
        32
    },
    {
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        63,
        NULL,
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        
            "\x0eb\x0b7\x073\x0f9\x093\x027\x08e\x0ff",
        8
    },
    {
        
            "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff",
        8,
        64,
        NULL,
        
            "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff",
        8,
        
            "\x027\x08b\x027\x0e4\x02e\x02f\x00d\x049",
        8
    },
    {
        
            "\x030\x000\x000\x000\x000\x000\x000\x000",
        8,
        64,
        NULL,
        
            "\x010\x000\x000\x000\x000\x000\x000\x001",
        8,
        
            "\x030\x064\x09e\x0df\x09b\x0e7\x0d2\x0c2",
        8
    },
    {
        
            "\x088",
        1,
        64,
        NULL,
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        
            "\x061\x0a8\x0a2\x044\x0ad\x0ac\x0cc\x0f0",
        8
    },
    {
        
            "\x088\x0bc\x0a9\x00e\x090\x087\x05a",
        7,
        64,
        NULL,
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        
            "\x06c\x0cf\x043\x008\x097\x04c\x026\x07f",
        8
    },
    {
        
            "\x088\x0bc\x0a9\x00e\x090\x087\x05a\x07f"
            "\x00f\x079\x0c3\x084\x062\x07b\x0af\x0b2",
        16,
        64,
        NULL,
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        
            "\x01a\x080\x07d\x027\x02b\x0be\x05d\x0b1",
        8
    },
    {
        
            "\x088\x0bc\x0a9\x00e\x090\x087\x05a\x07f"
            "\x00f\x079\x0c3\x084\x062\x07b\x0af\x0b2",
        16,
        128,
        NULL,
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        
            "\x022\x069\x055\x02a\x0b0\x0f8\x05c\x0a6",
        8
    },
    {
        
            "\x088\x0bc\x0a9\x00e\x090\x087\x05a\x07f"
            "\x00f\x079\x0c3\x084\x062\x07b\x0af\x0b2"
            "\x016\x0f8\x00a\x06f\x085\x092\x005\x084"
            "\x0c4\x02f\x0ce\x0b0\x0be\x025\x05d\x0af"
            "\x01e",
        33,
        129,
        NULL,
        
            "\x000\x000\x000\x000\x000\x000\x000\x000",
        8,
        
            "\x05b\x078\x0d3\x0a4\x03d\x0ff\x0f1\x0f1",
        8
    }
};

Rc2CipherMode rc2EcbTestInfo = {
    "RC2 ECB",
     EVP_rc2_ecb,
    pRc2EcbTestVectors,
    sizeof(pRc2EcbTestVectors)/sizeof(pRc2EcbTestVectors[0])
};

Rc2TestData pRc2CbcTestVectors[] = {
    {
        
            "\x026\x01E\x057\x08E\x0C9\x062\x0BF\x0B8"
            "\x03E\x096",
        10,
        40,
        
            "\x001\x002\x003\x004\x005\x006\x007\x008",
        
            "\x011\x022\x033\x044\x055\x066\x077\x088"
            "\x099\x0AA\x0BB\x0CC\x0DD\x0EE\x0FF\x000"
            "\x011\x022\x033\x044\x055\x066\x077\x088"
            "\x099\x0AA\x0BB\x0CC\x0DD\x0EE\x0FF\x000",
        32,
        
            "\x071\x02D\x011\x099\x0C9\x0A0\x078\x04F"
            "\x0CD\x0F1\x01E\x03D\x0FD\x021\x07E\x0DB"
            "\x0B2\x06E\x00D\x0A4\x072\x0BC\x031\x051"
            "\x048\x0EF\x04E\x068\x03B\x0DC\x0CD\x07D",
        32
    }
};

Rc2CipherMode rc2CbcTestInfo = {
    "RC2 CBC",
     EVP_rc2_cbc,
    pRc2CbcTestVectors,
    sizeof(pRc2CbcTestVectors)/sizeof(pRc2CbcTestVectors[0])
};

Rc2CipherMode rc2Cbc40TestInfo = {
    "RC2 40 CBC",
     EVP_rc2_40_cbc,
    pRc2CbcTestVectors,
    sizeof(pRc2CbcTestVectors)/sizeof(pRc2CbcTestVectors[0])
};

int testRc2Vector(Rc2CipherMode *pTestInfo, Rc2TestData *pCurTest, int updateMode)
{
    int ret = -1, outLen = 0, status, rounds, i, tempLen, keyBits;
    EVP_CIPHER_CTX *pCtx = NULL;
    unsigned char *pOutput = NULL;

    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new\n");
        goto exit;
    }

    status = EVP_EncryptInit_ex(
        pCtx, pTestInfo->pCipher(), NULL, NULL, NULL);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex\n");
        goto exit;
    }

    status = EVP_CIPHER_CTX_set_padding(pCtx, 0);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_padding\n");
        goto exit;
    }
    
    status = EVP_CIPHER_CTX_ctrl(
        pCtx, EVP_CTRL_GET_RC2_KEY_BITS, 0, &keyBits);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (get)\n");
        goto exit;
    }

    if (keyBits != pCurTest->effectiveKeyBits)
    {
        status = EVP_CIPHER_CTX_ctrl(
            pCtx, EVP_CTRL_SET_RC2_KEY_BITS, pCurTest->effectiveKeyBits,
            NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (set)\n");
            goto exit;
        }
    }

    status = EVP_CIPHER_CTX_set_key_length(pCtx, pCurTest->keyLen);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_key_length\n");
        goto exit;
    }

    status = EVP_EncryptInit_ex(
        pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
        (const unsigned char *) pCurTest->pIv);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex (call 2)\n");
        goto exit;
    }

    if (NULL != pOutput)
    {
        OPENSSL_free(pOutput);
        pOutput = NULL;
    }

    pOutput = OPENSSL_malloc(pCurTest->cipherLen);

    if (updateMode)
    {
        if ( 0 != (pCurTest->plainLen % 8) )
        {
            fprintf(stderr, "ERROR: invalid test vector (plainLen)\n");
            goto exit;
        }

        outLen = 0;
        rounds = pCurTest->plainLen / 8;

        for (i = 0; i < rounds; i++)
        {
            status = EVP_EncryptUpdate(
                pCtx, pOutput + outLen, &tempLen,
                (const unsigned char *) (pCurTest->pPlain + (i * 8)), 8);
            if (1 != status)
            {
                fprintf(stderr, "ERROR: EVP_DecryptUpdate (updateMode 1)\n");
                goto exit;
            }

            outLen += tempLen;
        }
    }
    else
    {
        status = EVP_EncryptUpdate(
            pCtx, pOutput, &tempLen, (const unsigned char *) pCurTest->pPlain,
            pCurTest->plainLen);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate (updateMode 0)\n");
            goto exit;
        }

        outLen += tempLen;
    }
    
    status = EVP_EncryptFinal_ex(pCtx, pOutput + outLen, &tempLen);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_EncryptFinal_ex\n");
        goto exit;
    }
    outLen += tempLen;
    
    if (outLen != pCurTest->cipherLen)
    {
        fprintf(stderr, "ERROR: invalid cipherLen, value %d but expected %d\n", outLen, pCurTest->cipherLen);
        goto exit;
    }

    if (memcmp(pOutput, pCurTest->pCipher, outLen))
    {
        fprintf(stderr, "ERROR: invalid ciphertext\n");
        goto exit;
    }

    EVP_CIPHER_CTX_free(pCtx);
    pCtx = NULL;

    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new (decrypt)\n");
        goto exit;
    }

    status = EVP_DecryptInit_ex(
        pCtx, pTestInfo->pCipher(), NULL, NULL, NULL);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex\n");
        goto exit;
    }

    status = EVP_CIPHER_CTX_set_padding(pCtx, 0);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_padding (decrypt)\n");
        goto exit;
    }
    
    status = EVP_CIPHER_CTX_ctrl(
        pCtx, EVP_CTRL_GET_RC2_KEY_BITS, 0, &keyBits);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (get, decrypt)\n");
        goto exit;
    }

    if (keyBits != pCurTest->effectiveKeyBits)
    {
        status = EVP_CIPHER_CTX_ctrl(
            pCtx, EVP_CTRL_SET_RC2_KEY_BITS, pCurTest->effectiveKeyBits,
            NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (set, decrypt)\n");
            goto exit;
        }
    }

    status = EVP_CIPHER_CTX_set_key_length(pCtx, pCurTest->keyLen);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_key_length (decrypt)\n");
        goto exit;
    }

    status = EVP_DecryptInit_ex(
        pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
        (const unsigned char *) pCurTest->pIv);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex (call 2)\n");
        goto exit;
    }

    if (NULL != pOutput)
    {
        OPENSSL_free(pOutput);
        pOutput = NULL;
    }

    pOutput = OPENSSL_malloc(pCurTest->cipherLen);
    outLen = 0;
    
    if (updateMode)
    {
        if ( 0 != (pCurTest->cipherLen % 8) )
        {
            fprintf(stderr, "ERROR: invalid test vector (cipherLen)\n");
            goto exit;
        }

        outLen = 0;
        rounds = pCurTest->cipherLen / 8;

        for (i = 0; i < rounds; i++)
        {
            status = EVP_DecryptUpdate(
                pCtx, pOutput + outLen, &tempLen,
                (const unsigned char *) (pCurTest->pCipher + (i * 8)), 8);
            if (1 != status)
            {
                fprintf(stderr, "ERROR: EVP_DecryptUpdate (updateMode 1)\n");
                goto exit;
            }

            outLen += tempLen;
        }
    }
    else
    {
        status = EVP_DecryptUpdate(
            pCtx, pOutput, &tempLen, (const unsigned char *) pCurTest->pCipher,
            pCurTest->cipherLen);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate (updateMode 0)\n");
            goto exit;
        }
        outLen += tempLen;
    }
    
    status = EVP_DecryptFinal_ex(pCtx, pOutput + outLen, &tempLen);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_DecryptFinal_ex\n");
        goto exit;
    }
    outLen += tempLen;

    if (outLen != pCurTest->plainLen)
    {
        fprintf(stderr, "ERROR: invalid recovered plainLen\n");
        goto exit;
    }

    if (memcmp(pOutput, pCurTest->pPlain, outLen))
    {
        fprintf(stderr, "ERROR: invalid recovered plaintext\n");
        goto exit;
    }

    ret = 0;

exit:

    if (NULL != pCtx)
    {
        EVP_CIPHER_CTX_free(pCtx);
    }

    if (NULL != pOutput)
    {
        OPENSSL_free(pOutput);
    }

    return ret;
}

int testRc2(Rc2CipherMode *pTestInfo)
{
    int ret = 0, count;
    Rc2TestData *pCurTest;

    for (count = 0; count < pTestInfo->vectorCount; count++)
    {
        pCurTest = pTestInfo->pVectors + count;

        if (0 != testRc2Vector(pTestInfo, pCurTest, 0))
        {
            fprintf(
                stderr, "ERROR - testRc2Vector - single update: %s test vector %d failed\n",
                pTestInfo->pStr, count + 1);
            ret = -1;
        }

        if (0 != testRc2Vector(pTestInfo, pCurTest, 1))
        {
            fprintf(
                stderr, "ERROR - testRc2Vector - multi update: %s test vector %d failed\n",
                pTestInfo->pStr, count + 1);
            ret = -1;
        }
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

    if (0 != testRc2(&rc2EcbTestInfo))
    {
        ret = -1;
    }

    if (0 != testRc2(&rc2CbcTestInfo))
    {
        ret = -1;
    }

    if (0 != testRc2(&rc2Cbc40TestInfo))
    {
        ret = -1;
    }

    if (-1 == ret)
    {
        fprintf(stdout, "RC2 Test Failed\n");
    }
    else
    {
        fprintf(stdout, "RC2 Test Passed\n");
    }

    ENGINE_free(pEng);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();

    return ret;
}
