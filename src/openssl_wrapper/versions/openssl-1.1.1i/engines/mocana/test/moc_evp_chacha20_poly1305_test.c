/*
 * moc_evp_chacha20_poly1305_test.c
 *
 * Test ChaCha20-Poly1305 encryption and decryption
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

#define MOC_CHACHA_TEST_BLOCK_SIZE 64
#define MOC_CHACHA_TEST_KEY_SIZE 32
#define MOC_CHACHA_TEST_NONCE_SIZE 12
#define MOC_CHACHA_TEST_AAD_SIZE 12
#define MOC_CHACHA_TEST_TEXT_SIZE 114
#define MOC_CHACHA_TEST_TAG_SIZE 16

/*---------------------------------------------------------------------*/

int testChaChaPoly(int updateMode)
{
    int ret = -1, outLen = 0, tempLen, status, i;
    EVP_CIPHER_CTX *pCtx = NULL;
    
    unsigned char pKey[MOC_CHACHA_TEST_KEY_SIZE];
    unsigned char pNonce[MOC_CHACHA_TEST_NONCE_SIZE] =
    {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    
    unsigned char pAAD[MOC_CHACHA_TEST_AAD_SIZE] =
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
        0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };
    
    const char* pPlainText = "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.";
   
    int plainLen = MOC_CHACHA_TEST_TEXT_SIZE;
    int cipherLen = MOC_CHACHA_TEST_TEXT_SIZE;
    
    /* buffer to hold resulting output and tag */
    unsigned char pOutput[MOC_CHACHA_TEST_TEXT_SIZE];
    unsigned char pTag[MOC_CHACHA_TEST_TAG_SIZE];
    
    /* expected ciphertext */
    unsigned char pCipherText[MOC_CHACHA_TEST_TEXT_SIZE] =
    {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    
    /* expected tag */
    unsigned char pExpTag[MOC_CHACHA_TEST_TAG_SIZE] =
    {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    
    /* the key used in RFC 7539 */
    for (i = 0; i < 32; ++i)
    {
        pKey[i] = 0x80 + ((unsigned char) i) ;
    }
    
    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new (first call)\n");
        goto exit;
    }
    
    status = EVP_EncryptInit_ex(pCtx, EVP_chacha20_poly1305(), NULL, (const unsigned char *) pKey,
                                (const unsigned char *) pNonce);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex\n");
        goto exit;
    }

    if (updateMode)
    {
        /* we update one block at a time although partial block updates should be supported */
        int plainLeft = plainLen;
        int chunkSize;
        
        /* update AAD first. we split it in half and do two update calls */
        status = EVP_EncryptUpdate(pCtx, NULL, &tempLen, pAAD, MOC_CHACHA_TEST_AAD_SIZE/2);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptUpdate (aad, first call) \n");
            goto exit;
        }
        
        outLen += tempLen;
        
        status = EVP_EncryptUpdate(pCtx, NULL, &tempLen, pAAD + MOC_CHACHA_TEST_AAD_SIZE/2, MOC_CHACHA_TEST_AAD_SIZE/2);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptUpdate (aad, second call) \n");
            goto exit;
        }
        
        outLen += tempLen;
        
        if (MOC_CHACHA_TEST_AAD_SIZE != outLen)
        {
            fprintf(stderr, "ERROR: invalid outLen (aad) \n");
            goto exit;
        }
        
        /* now update with plaintext */
        outLen = 0;
        
        while (plainLeft)
        {
            chunkSize = plainLeft < MOC_CHACHA_TEST_BLOCK_SIZE ? plainLeft : MOC_CHACHA_TEST_BLOCK_SIZE;
            
            status = EVP_EncryptUpdate(pCtx, pOutput + outLen, &tempLen,
                                       (const unsigned char *) (pPlainText + plainLen - plainLeft), chunkSize);
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
        /* update AAD first. we split it in half and do two update calls */
        status = EVP_EncryptUpdate(pCtx, NULL, &tempLen, pAAD, MOC_CHACHA_TEST_AAD_SIZE);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_EncryptUpdate (aad) \n");
            goto exit;
        }
        
        outLen += tempLen;
        
        if (MOC_CHACHA_TEST_AAD_SIZE != outLen)
        {
            fprintf(stderr, "ERROR: invalid outLen (aad) \n");
            goto exit;
        }
        
        outLen = 0;
        
        status = EVP_EncryptUpdate(pCtx, pOutput, &tempLen, (const unsigned char *) pPlainText, plainLen);
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

    if (outLen != cipherLen)
    {
        fprintf(stderr, "ERROR: invalid ciherLen\n");
        goto exit;
    }
    
    /* compare against the expected ciphertext */
    if (memcmp(pOutput, pCipherText, outLen))
    {
        fprintf(stderr, "ERROR: invalid ciphertext\n");
        goto exit;
    }
    
    status = EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_AEAD_GET_TAG, MOC_CHACHA_TEST_TAG_SIZE, pTag);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (EVP_CTRL_AEAD_GET_TAG)\n");
        goto exit;
    }
    
     /* compare against the expected tag */
    if (memcmp(pTag, pExpTag, MOC_CHACHA_TEST_TAG_SIZE))
    {
        fprintf(stderr, "ERROR: invalid tag\n");
        goto exit;
    }

    EVP_CIPHER_CTX_free(pCtx);
    pCtx = NULL;
    
    outLen = 0;
    
    /* now test decrypt */
    
    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new (decrypt, first call)\n");
        goto exit;
    }
    
    status = EVP_DecryptInit_ex(pCtx, EVP_chacha20_poly1305(), NULL, (const unsigned char *) pKey,
                                (const unsigned char *) pNonce);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex\n");
        goto exit;
    }
    
    /* set the tag */
    status = EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_AEAD_SET_TAG, MOC_CHACHA_TEST_TAG_SIZE, pExpTag);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl (EVP_CTRL_AEAD_SET_TAG)\n");
        goto exit;
    }
    
    if (updateMode)
    {
        /* we update one block at a time although partial block updates should be supported */
        int cipherLeft = cipherLen;
        int chunkSize;
        
        /* update AAD first. we split it in half and do two update calls */
        status = EVP_DecryptUpdate(pCtx, NULL, &tempLen, pAAD, MOC_CHACHA_TEST_AAD_SIZE/2);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate (aad, first call) \n");
            goto exit;
        }
        
        outLen += tempLen;
        
        status = EVP_DecryptUpdate(pCtx, NULL, &tempLen, pAAD + MOC_CHACHA_TEST_AAD_SIZE/2, MOC_CHACHA_TEST_AAD_SIZE/2);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate (aad, second call) \n");
            goto exit;
        }
        
        outLen += tempLen;
        
        if (MOC_CHACHA_TEST_AAD_SIZE != outLen)
        {
            fprintf(stderr, "ERROR: invalid outLen (aad, decrypt) \n");
            goto exit;
        }
        
        outLen = 0;
        
        while (cipherLeft)
        {
            chunkSize = cipherLeft < MOC_CHACHA_TEST_BLOCK_SIZE ? cipherLeft : MOC_CHACHA_TEST_BLOCK_SIZE;
            
            status = EVP_DecryptUpdate(pCtx, pOutput + outLen, &tempLen,
                                       (const unsigned char *) (pCipherText + cipherLen - cipherLeft), chunkSize);
            if (1 != status)
            {
                fprintf(stderr, "ERROR: EVP_DecryptUpdate (updateMode 1) \n");
                goto exit;
            }
            
            cipherLeft -= chunkSize;
            outLen += tempLen;
        }
    }
    else
    {
        status = EVP_DecryptUpdate(pCtx, NULL, &tempLen, pAAD, MOC_CHACHA_TEST_AAD_SIZE);
        if (1 != status)
        {
            fprintf(stderr, "ERROR: EVP_DecryptUpdate (aad) \n");
            goto exit;
        }
        
        outLen += tempLen;
        
        if (MOC_CHACHA_TEST_AAD_SIZE != outLen)
        {
            fprintf(stderr, "ERROR: invalid outLen (aad, decrypt) \n");
            goto exit;
        }
        
        outLen = 0;
        
        status = EVP_DecryptUpdate(pCtx, pOutput, &tempLen, (const unsigned char *) pCipherText, cipherLen);
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
    
    /* stream cipher, plaintext and ciphertext have same length */
    if (outLen != plainLen)
    {
        fprintf(stderr, "ERROR: invalid recovered plainLen\n");
        goto exit;
    }
    
    if (memcmp(pOutput, (unsigned char *) pPlainText, outLen))
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
        return ret;
    }
    
    if (0 != testChaChaPoly(0))
        ret = -1;
    
    if (0 != testChaChaPoly(1))
        ret = -1;
    
    if (-1 == ret)
        fprintf(stdout, "ChaChaPoly Test Failed\n");
    else
        fprintf(stdout, "ChaChaPoly Test Passed\n");

    ENGINE_free(pEng);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return ret;
}
