/*
 * moc_evp_rc5_test.c
 *
 * Test program to verify RC5 EVP functions
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

#define MOC_RC5_TEST_BLOCK_SIZE 8
#define MOC_RC5_TEST_MAX_KEY_SIZE 16
#define MOC_RC5_TEST_IV_SIZE MOC_RC5_TEST_BLOCK_SIZE

#define LOAD_KEY_AND_IV 0
#define LOAD_KEY_THEN_IV 1
#define LOAD_IV_THEN_KEY 2

/* Test structure for Rc5 tests */
typedef struct Rc5TestCase
{
    int roundCount;
    int keyLen;
    char *pKey;
    int ivLen;
    char *pIv;
    int plainLen;
    char *pPlain;
    int cipherLen;
    char *pCipher;
    int padFlag;
    
} Rc5TestData;

typedef struct
{
    char *pStr;
    const EVP_CIPHER *(*pCipher)(void);
    Rc5TestData *pVectors;
    int vectorCount;
    
} Rc5CipherMode;

Rc5TestData pRc5EcbTestVectors[] =
{
    {
        12,
        16, "\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000",
        0, "",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x021\x0A5\x0DB\x0EE\x015\x04B\x08F\x06D",
        0
    },
    {
        12,
        16, "\x091\x05f\x046\x019\x0be\x041\x0b2\x051\x063\x055\x0a5\x001\x010\x0a9\x0ce\x091",
        0, "",
        8, "\x021\x0A5\x0DB\x0EE\x015\x04B\x08F\x06D",
        8, "\x0F7\x0C0\x013\x0AC\x05B\x02B\x089\x052",
        0
    },
    {
        12,
        16, "\x091\x05f\x046\x019\x0be\x041\x0b2\x051\x063\x055\x0a5\x001\x010\x0a9\x0ce\x091",
        0, "",
        16, "\x021\x0A5\x0DB\x0EE\x015\x04B\x08F\x06D\x021\x0A5\x0DB\x0EE\x015\x04B\x08F\x06D",
        16, "\x0F7\x0C0\x013\x0AC\x05B\x02B\x089\x052\x0F7\x0C0\x013\x0AC\x05B\x02B\x089\x052",
        0
    }
};

Rc5TestData pRc5CbcTestVectors[] =
{
    {
        12,
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff",
        8, "\x0e4\x093\x0f1\x0c1\x0bb\x04d\x06e\x08c",
        0
    },
    {
        8,
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x05c\x04c\x004\x01e\x00f\x021\x07a\x0c3",
        0
    },
    {
        12,
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x092\x01f\x012\x048\x053\x073\x0b4\x0f7",
        0
    },
    {
        16,
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x05b\x0a0\x0ca\x06b\x0be\x07f\x05f\x0ad",
        0
    },
    {
        8,
        16, "\x001\x002\x003\x004\x005\x006\x007\x008\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x0c5\x033\x077\x01c\x0d0\x011\x00e\x063",
        0
    },
    {
        12,
        16, "\x001\x002\x003\x004\x005\x006\x007\x008\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x029\x04d\x0db\x046\x0b3\x027\x08d\x060",
        0
    },
    {
        16,
        16, "\x001\x002\x003\x004\x005\x006\x007\x008\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x001\x002\x003\x004\x005\x006\x007\x008",
        8, "\x010\x020\x030\x040\x050\x060\x070\x080",
        8, "\x0da\x0d6\x0bd\x0a9\x0df\x0e8\x0f7\x0e8",
        0
    },
    {
        12,
        5, "\x001\x002\x003\x004\x005",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff",
        8, "\x097\x0e0\x078\x078\x037\x0ed\x031\x07f",
        0
    },
    {
        8,
        5, "\x001\x002\x003\x004\x005",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff",
        8, "\x078\x075\x0db\x0f6\x073\x08c\x064\x078",
        0
    },
    {
        8,
        5, "\x001\x002\x003\x004\x005",
        8, "\x078\x075\x0db\x0f6\x073\x08c\x064\x078",
        8, "\x008\x008\x008\x008\x008\x008\x008\x008",
        8, "\x08f\x034\x0c3\x0c6\x081\x0c9\x096\x095",
        0
    },
    {
        8,
        5, "\x001\x002\x003\x004\x005",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff",
        16, "\x078\x075\x0db\x0f6\x073\x08c\x064\x078\x08f\x034\x0c3\x0c6\x081\x0c9\x096\x095",
        1
    },
    {
        8,
        5, "\x001\x002\x003\x004\x005",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        8, "\x07c\x0b3\x0f1\x0df\x034\x0f9\x048\x011",
        0
    },
    {
        8,
        5, "\x001\x002\x003\x004\x005",
        8, "\x07c\x0b3\x0f1\x0df\x034\x0f9\x048\x011",
        8, "\x011\x022\x033\x044\x055\x066\x077\x001",
        8, "\x07f\x0d1\x0a0\x023\x0a5\x0bb\x0a2\x017",
        0
    },
    {
        8,
        5, "\x001\x002\x003\x004\x005",
        8, "\x000\x000\x000\x000\x000\x000\x000\x000",
        23, "\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff\x078\x075\x0db\x0f6\x073\x08c\x064\x078\x011\x022\x033\x044\x055\x066\x077",
        24, "\x078\x075\x0db\x0f6\x073\x08c\x064\x078\x07c\x0b3\x0f1\x0df\x034\x0f9\x048\x011\x07f\x0d1\x0a0\x023\x0a5\x0bb\x0a2\x017",
        1
    }
};

#ifndef OPENSSL_NO_RC5
Rc5CipherMode rc5EcbTestInfo = {
    .pStr = "RC5 ECB",
    .pCipher = EVP_rc5_32_12_16_ecb,
    .pVectors = pRc5EcbTestVectors,
    .vectorCount = sizeof(pRc5EcbTestVectors)/sizeof(pRc5EcbTestVectors[0])
};

Rc5CipherMode rc5CbcTestInfo = {
    .pStr = "RC5 CBC",
    .pCipher = EVP_rc5_32_12_16_cbc,
    .pVectors = pRc5CbcTestVectors,
    .vectorCount = sizeof(pRc5CbcTestVectors)/sizeof(pRc5CbcTestVectors[0])
};
#endif

int testRc5Vector(Rc5CipherMode *pTestInfo, Rc5TestData *pCurTest, int updateMode, int initMode)
{
    int ret = -1, outLen = 0, status, tempLen, numRounds;
    EVP_CIPHER_CTX *pCtx = NULL;
    unsigned char *pOutput = NULL;
    
    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new (first call)\n");
        goto exit;
    }
    
    status = EVP_EncryptInit_ex(pCtx, pTestInfo->pCipher(), NULL, NULL, NULL);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex (first call)\n");
        goto exit;
    }
    
    if (!pCurTest->padFlag)
    {
        /* first make sure plaintext length is a multiple of the block size */
        if ((pCurTest->plainLen) % MOC_RC5_TEST_BLOCK_SIZE)
        {
            fprintf(stderr, "ERROR: bad test vector\n");
            goto exit;
        }
        
        status = EVP_CIPHER_CTX_set_padding(pCtx, 0);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_padding\n");
            goto exit;
        }
    }
    /* else leave padding to the default of padded */
    
    /* get the number of rounds, which should be 12 by default */
    status = EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GET_RC5_ROUNDS, 0, &numRounds);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (first call)\n");
        goto exit;
    }
    
    if (12 != numRounds)
        goto exit;
    
    /* if our vector is different set the number of rounds */
    if (12 != pCurTest->roundCount)
    {
        status = EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_SET_RC5_ROUNDS, pCurTest->roundCount, NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (second call)\n");
            goto exit;
        }
    }
    
    status = EVP_CIPHER_CTX_set_key_length(pCtx, pCurTest->keyLen);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_key_length\n");
        goto exit;
    }


    if (initMode == LOAD_KEY_AND_IV)
    {
        /* must call init again to make sure all the above params are set */
        status = EVP_EncryptInit_ex(pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
                                    (const unsigned char *) pCurTest->pIv);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptInit_ex (second call)\n");
            goto exit;
        }
    }
    else if (initMode == LOAD_IV_THEN_KEY)
    {
        /* must call init again to make sure all the above params are set */
        status = EVP_EncryptInit_ex(pCtx, NULL, NULL, (const unsigned char *) NULL,
                                    (const unsigned char *) pCurTest->pIv);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptInit_ex (second call)\n");
            goto exit;
        }

        status = EVP_EncryptInit_ex(pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
                                    (const unsigned char *) NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptInit_ex (third call)\n");
            goto exit;
        }
    }
    else if (initMode == LOAD_KEY_THEN_IV)
    {
        /* must call init again to make sure all the above params are set */
        status = EVP_EncryptInit_ex(pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
                                    (const unsigned char *) NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptInit_ex (second call)\n");
            goto exit;
        }

        status = EVP_EncryptInit_ex(pCtx, NULL, NULL, (const unsigned char *) NULL,
                                    (const unsigned char *) pCurTest->pIv);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptInit_ex (third call)\n");
            goto exit;
        }
    }

    pOutput = OPENSSL_malloc(pCurTest->cipherLen);
    
    if (updateMode)
    {
        /* we update one block at a time although partial block updates should be supported */
        int plainLeft = pCurTest->plainLen;
        int chunkSize;
        
        while (plainLeft)
        {
            chunkSize = plainLeft < MOC_RC5_TEST_BLOCK_SIZE ? plainLeft : MOC_RC5_TEST_BLOCK_SIZE;
            
            status = EVP_EncryptUpdate(pCtx, pOutput + outLen, &tempLen,
                                       (const unsigned char *) (pCurTest->pPlain + pCurTest->plainLen - plainLeft), chunkSize);
            if (1 != status)
            {
                fprintf(stderr, "ERROR: EVP_EncryptUpdate (updateMode 1) \n");
                goto exit;
            }
            
            plainLeft -= chunkSize;
            outLen += tempLen;
        }
    }
    else
    {
        status = EVP_EncryptUpdate(pCtx, pOutput, &tempLen, (const unsigned char *) pCurTest->pPlain,
                                   pCurTest->plainLen);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptUpdate (updateMode 0)\n");
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
        fprintf(stderr, "ERROR: invalid ciherLen\n");
        goto exit;
    }
    
    if (memcmp(pOutput, pCurTest->pCipher, outLen))
    {
        fprintf(stderr, "ERROR: invalid ciphertext\n");
        goto exit;
    }
    
    EVP_CIPHER_CTX_free(pCtx);
    pCtx = NULL;
    
    if (NULL != pOutput)
    {
        OPENSSL_free(pOutput);
        pOutput = NULL;
    }

    outLen = 0;
    
    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new (second call)\n");
        goto exit;
    }
    
    status = EVP_DecryptInit_ex(pCtx, pTestInfo->pCipher(), NULL, NULL, NULL);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex\n");
        goto exit;
    }
    
    if (!pCurTest->padFlag)
    {
        status = EVP_CIPHER_CTX_set_padding(pCtx, 0);

        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_padding (decrypt call)\n");
            goto exit;
        }
    }
    /* else leave padding to the default of padded, no check of cipherlen needed */
    
    /* if our vector is different set the number of rounds */
    if (12 != pCurTest->roundCount)
    {
        status = EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_SET_RC5_ROUNDS, pCurTest->roundCount, NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (decrypt call)\n");
            goto exit;
        }
    }

    status = EVP_CIPHER_CTX_set_key_length(pCtx, pCurTest->keyLen);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_set_key_length (decrypt call)\n");
        goto exit;
    }

    if (initMode == LOAD_KEY_AND_IV)
    {
        /* iv and key might be mangled during the encryption, use the copies */
        status = EVP_DecryptInit_ex( pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
                                    (const unsigned char *) pCurTest->pIv);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptInit_ex (second call)\n");
            goto exit;
        }
    }
    else if (initMode == LOAD_IV_THEN_KEY)
    {
        /* iv and key might be mangled during the encryption, use the copies */
        status = EVP_DecryptInit_ex( pCtx, NULL, NULL, (const unsigned char *) NULL,
                                    (const unsigned char *) pCurTest->pIv);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptInit_ex (second call)\n");
            goto exit;
        }

        status = EVP_DecryptInit_ex( pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
                                    (const unsigned char *) NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptInit_ex (second call)\n");
            goto exit;
        }
    }
    else if (initMode == LOAD_KEY_THEN_IV)
    {
        /* iv and key might be mangled during the encryption, use the copies */
        status = EVP_DecryptInit_ex( pCtx, NULL, NULL, (const unsigned char *) pCurTest->pKey,
                                    (const unsigned char *) NULL);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptInit_ex (second call)\n");
            goto exit;
        }

        status = EVP_DecryptInit_ex( pCtx, NULL, NULL, (const unsigned char *) NULL,
                                    (const unsigned char *) pCurTest->pIv);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptInit_ex (second call)\n");
            goto exit;
        }
    }

    pOutput = OPENSSL_malloc(pCurTest->cipherLen);
    
    if (updateMode)
    {
        int cipherLeft = pCurTest->cipherLen;
        
        /* we update one block at a time although partial block updates should be supported. */
        while (cipherLeft > 0)
        {
            status = EVP_DecryptUpdate(pCtx, pOutput + outLen, &tempLen,
                                       (const unsigned char *) (pCurTest->pCipher + pCurTest->cipherLen - cipherLeft), MOC_RC5_TEST_BLOCK_SIZE);
            if (1 != status)
            {
                fprintf(stderr, "ERROR: EVP_DecryptUpdate\n");
                goto exit;
            }
            
            outLen += tempLen;
            cipherLeft -= MOC_RC5_TEST_BLOCK_SIZE;
        }
    }
    else
    {
        status = EVP_DecryptUpdate(pCtx, pOutput, &tempLen, (const unsigned char *) pCurTest->pCipher,
                                   pCurTest->cipherLen);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate\n");
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
        fprintf(stderr, "ERROR: invalid recovered plainLen, %d, expected %d\n", outLen, pCurTest->plainLen);
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

int testRc5(Rc5CipherMode *pTestInfo)
{
    int ret = 0, count;
    Rc5TestData *pCurTest;
    
    for (count = 0; count < pTestInfo->vectorCount; count++)
    {
        pCurTest = pTestInfo->pVectors + count;
        
        if (0 != testRc5Vector(pTestInfo, pCurTest, 0, LOAD_KEY_AND_IV))
        {
            fprintf(stderr, "ERROR - testRc5Vector - single update: %s test vector %d failed\n",
                    pTestInfo->pStr, count + 1);
            ret = -1;
        }

        if (0 != testRc5Vector(pTestInfo, pCurTest, 0, LOAD_KEY_THEN_IV))
        {
            fprintf(stderr, "ERROR - testRc5Vector - single update: %s test vector %d failed\n",
                    pTestInfo->pStr, count + 1);
            ret = -1;
        }

        if (0 != testRc5Vector(pTestInfo, pCurTest, 0, LOAD_IV_THEN_KEY))
        {
            fprintf(stderr, "ERROR - testRc5Vector - single update: %s test vector %d failed\n",
                    pTestInfo->pStr, count + 1);
            ret = -1;
        }

        if (0 != testRc5Vector(pTestInfo, pCurTest, 1, LOAD_KEY_AND_IV))
        {
            fprintf(stderr, "ERROR - testRc5Vector - multi update: %s test vector %d failed\n",
                    pTestInfo->pStr, count + 1);
            ret = -1;
        }

        if (0 != testRc5Vector(pTestInfo, pCurTest, 1, LOAD_KEY_THEN_IV))
        {
            fprintf(stderr, "ERROR - testRc5Vector - multi update: %s test vector %d failed\n",
                    pTestInfo->pStr, count + 1);
            ret = -1;
        }

        if (0 != testRc5Vector(pTestInfo, pCurTest, 1, LOAD_IV_THEN_KEY))
        {
            fprintf(stderr, "ERROR - testRc5Vector - multi update: %s test vector %d failed\n",
                    pTestInfo->pStr, count + 1);
            ret = -1;
        }
    }
    
    return ret;
}

int main()
{
    int ret = 0;
#ifdef OPENSSL_NO_RC5
    fprintf(stdout, "No RC5 Support\n");
#else
    ENGINE *pEng;

    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
    ENGINE_load_builtin_engines();
    
    pEng = ENGINE_by_id("mocana");
    
    if (NULL == pEng)
    {
        ret = -1;
        fprintf(stderr, "ERROR: Failed to load Mocana engine\n");
    }
    
    if (0 != testRc5(&rc5EcbTestInfo))
    {
        ret = -1;
    }
    
    if (0 != testRc5(&rc5CbcTestInfo))
    {
        ret = -1;
    }

    if (-1 == ret)
    {
        fprintf(stdout, "RC5 Test Failed\n");
    }
    else
    {
        fprintf(stdout, "RC5 Test Passed\n");
    }

    ENGINE_free(pEng);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();

#endif /* OPENSSL_NO_RC5 */
    
    return ret;
}
