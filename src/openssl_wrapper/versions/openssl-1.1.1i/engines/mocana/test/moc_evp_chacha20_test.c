/*
 * moc_evp_chacha20_test.c
 *
 * Test code for ChaCha20 EVP cipher implementation
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
#define MOC_CHACHA_TEST_IV_SIZE 16
#define MOC_CHACHA_TEST_TEXT_SIZE 114

/*---------------------------------------------------------------------*/

int testChaCha(int updateMode)
{
    int ret = -1, outLen = 0, tempLen, status, i;
    EVP_CIPHER_CTX *pCtx = NULL;
    
    unsigned char pKey[MOC_CHACHA_TEST_KEY_SIZE];
    unsigned char pIv[MOC_CHACHA_TEST_IV_SIZE] =
    {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    
    const char* pPlainText = "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.";
   
    int plainLen = MOC_CHACHA_TEST_TEXT_SIZE;
    int cipherLen = MOC_CHACHA_TEST_TEXT_SIZE;
    
    unsigned char pOutput[MOC_CHACHA_TEST_TEXT_SIZE];
    
    unsigned char pCipherText[MOC_CHACHA_TEST_TEXT_SIZE] =
    {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };
    
    /* the key used in RFC 7539 */
    for (i = 0; i < MOC_CHACHA_TEST_KEY_SIZE; ++i)
    {
        pKey[i] = (unsigned char) i ;
    }
    
    pCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCtx)
    {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new (first call)\n");
        goto exit;
    }
    
    status = EVP_EncryptInit_ex(pCtx, EVP_chacha20(), NULL, (const unsigned char *) pKey,
                                (const unsigned char *) pIv);
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
    
    if (memcmp(pOutput, pCipherText, outLen))
    {
        fprintf(stderr, "ERROR: invalid ciphertext\n");
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
    
    status = EVP_DecryptInit_ex(pCtx, EVP_chacha20(), NULL, (const unsigned char *) pKey,
                                (const unsigned char *) pIv);
    if (1 != status)
    {
        fprintf(stderr, "ERROR: EVP_DecryptInit_ex\n");
        goto exit;
    }
    
    if (updateMode)
    {
        /* we update one block at a time although partial block updates should be supported */
        int cipherLeft = cipherLen;
        int chunkSize;
        
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
    }
    
    if (0 != testChaCha(0))
        ret = -1;
    
    if (0 != testChaCha(1))
        ret = -1;
    
    if (-1 == ret)
        fprintf(stdout, "ChaCha Test Failed\n");
    else
        fprintf(stdout, "ChaCha Test Passed\n");

    ENGINE_free(pEng);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();

    return ret;
}
