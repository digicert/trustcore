/**
 * test_cipher.c
 *
 * Test of the digicert OSSL 3.0 provider
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

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGI_PROVIDER_TEST__

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../crypto/aes.h"

#include "openssl/evp.h"
#include "openssl/provider.h"

#include <stdio.h>

static void set_aes_mode(char *pAlgoStr, ubyte4 *pKeyLen, sbyte4 *pMode)
{
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-ECB"))
    {
        *pKeyLen = 16;
        *pMode = MODE_ECB;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-192-ECB"))
    {
        *pKeyLen = 24;
        *pMode = MODE_ECB;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-ECB"))
    {
        *pKeyLen = 32;
        *pMode = MODE_ECB;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-CBC"))
    {
        *pKeyLen = 16;
        *pMode = MODE_CBC;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-192-CBC"))
    {
        *pKeyLen = 24;
        *pMode = MODE_CBC;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-CBC"))
    {
        *pKeyLen = 32;
        *pMode = MODE_CBC;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-OFB"))
    {
        *pKeyLen = 16;
        *pMode = MODE_OFB;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-192-OFB"))
    {
        *pKeyLen = 24;
        *pMode = MODE_OFB;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-OFB"))
    {
        *pKeyLen = 32;
        *pMode = MODE_OFB;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-CFB"))
    {
        *pKeyLen = 16;
        *pMode = MODE_CFB128;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-192-CFB"))
    {
        *pKeyLen = 24;
        *pMode = MODE_CFB128;
    }
    if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-CFB"))
    {
        *pKeyLen = 32;
        *pMode = MODE_CFB128;
    }
}

int test_aes(OSSL_LIB_CTX *pLibCtx, char *pAlgoStr)
{
    MSTATUS status = ERR_GENERAL;
    int ret = 1;    
    ubyte4 keyLen = 0;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char iv2[16];
    unsigned char plaintext[32];
    unsigned char ciphertext[48];
    unsigned char decryptedtext[48];
    unsigned char plaintext2[32];
    unsigned char ciphertext2[48];
    int decryptedtext_len = 0, ciphertext_len = 0, plaintext_len, plaintext_len2;
    int len = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *pCipher = NULL;
    sbyte4 cmp = 1;
    BulkCtx pCtx = NULL;
    size_t i;
    sbyte4 mode = 0;

    set_aes_mode(pAlgoStr, &keyLen, &mode);

    for (i = 0; i < keyLen; i++)
    {
        key[i] = i+2;
    }
    
    plaintext_len = 32;
    plaintext_len2 = 32;
    for (i = 0; i < plaintext_len; i++)
    {
        plaintext[i] = i+10;
        plaintext2[i] = i+10;
    }

    for (i = 0; i < 16; i++)
    {
        iv[i] = i+1;
        iv2[i] = i+1;
    }

    switch(mode)
    {
        case MODE_CBC:
        {
            pCtx = CreateAESCtx(key, keyLen, TRUE);
            if (NULL == pCtx)
            {
                goto exit;
            }
        }
        break;

        case MODE_OFB:
        {
            pCtx = CreateAESOFBCtx(key, keyLen, TRUE);
            if (NULL == pCtx)
            {
                goto exit;
            }
        }
        break;

        case MODE_CFB128:
        {
            pCtx = CreateAESCFBCtx(key, keyLen, TRUE);
            if (NULL == pCtx)
            {
                goto exit;
            }
        }
        break;

        case MODE_ECB:
        {
            status = DIGI_MALLOC((void **)&pCtx, sizeof(aesCipherContext));
            if (OK != status)
                goto exit;

            status = AESALGO_makeAesKeyEx(pCtx, keyLen * 8, key, 1, MODE_ECB);
            if (OK != status)
                goto exit;
        }
        break;

        default:
            goto exit;
    }
    
    DIGI_MEMCPY(ciphertext2, plaintext2, (ubyte4) plaintext_len2);
    DIGI_MEMSET(ciphertext2 + plaintext_len2, 16, 16);
    status = DoAES(pCtx, ciphertext2, (ubyte4) plaintext_len2 + 16, 1, iv2);
    if (OK != status)
        goto exit;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("ERROR EVP_CIPHER_CTX_new\n");
        goto exit;
    }

    pCipher = EVP_CIPHER_fetch(pLibCtx, pAlgoStr, NULL);
    if (NULL == pCipher)
    {
        printf("ERROR EVP_CIPHER_fetch\n");
        goto exit;
    }

#if defined(__ENABLE_MULTIPLE_INIT_TEST_2__)
    if (MODE_ECB != mode) /* ECB does not allow for generic EVP_CipherInit_ex with -1 direction */
    {
        if(1 != EVP_CipherInit_ex(ctx, pCipher, NULL, NULL, iv, -1))
        {
            printf("ERROR EVP_CipherInit_ex\n");
            goto exit;
        }

        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
        {
            printf("ERROR EVP_EncryptInit_ex\n");
            goto exit;
        }
    }
    else
#endif
    {
        if(1 != EVP_EncryptInit_ex(ctx, pCipher, NULL, key, iv))
        {
            printf("ERROR EVP_EncryptInit_ex\n");
            goto exit;
        }
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        printf("ERROR EVP_EncryptUpdate\n");
        goto exit;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        printf("ERROR EVP_EncryptFinal_ex\n");
        goto exit;
    }
    ciphertext_len += len;

    status = DIGI_MEMCMP(ciphertext, ciphertext2, (ubyte4) ciphertext_len, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        printf("ERROR ciphertext does not match expected value\n");
        goto exit;
    }
    else
    {
        ret = 0;
    }

    /* Reset */
    EVP_CIPHER_CTX_reset(ctx);

    if(1 != EVP_DecryptInit_ex(ctx, pCipher, NULL, key, iv))
    {
        printf("ERROR EVP_DecryptInit_ex\n");
        goto exit;
    }

    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
    {
        printf("ERROR EVP_DecryptUpdate\n");
        goto exit;
    }
    decryptedtext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len))
    {
        printf("ERROR EVP_DecryptFinal_ex\n");
        goto exit;
    }
    decryptedtext_len += len;

    status = DIGI_MEMCMP(decryptedtext, plaintext, (ubyte4) plaintext_len, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        printf("ERROR decrypted text did not match original plaintext\n");
    }
    else
    {
        ret = 0;
    }

exit:

    if (NULL != pCtx)
    {
        DeleteAESCtx(&pCtx);
    }
    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (NULL != pCipher)
    {
        EVP_CIPHER_free(pCipher);
    }

    return ret;
}

int test_cipher(OSSL_LIB_CTX *pLibCtx, char *pAlgoStr)
{
    MSTATUS status = ERR_GENERAL;
    int ret = 1;    
    ubyte4 keyLen = 0;
    unsigned char key[64] = {0};
    unsigned char iv[16] = {0};
    unsigned char *pIv = NULL;
    unsigned char plaintext[32] = {0};
    unsigned char ciphertext[48] = {0};
    unsigned char decryptedtext[48] = {0};
    int decryptedtext_len = 0, ciphertext_len = 0, plaintext_len = 0;
    int len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *pCipher = NULL;
    sbyte4 cmp = 1;
    size_t i = 0;
    int isECB = 0;

    if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-CTR"))
    {
        keyLen = 128/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "AES-192-CTR"))
    {
        keyLen = 192/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-CTR"))
    {
        keyLen = 256/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-XTS"))
    {   /* XTS uses 2 keys, keyLen is double the AES key size */
        keyLen = 256/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-XTS"))
    {
        keyLen = 512/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "DES-EDE3-ECB"))
    {
        keyLen = 192/8;
        isECB = 1;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "DES-EDE3-CBC"))
    {
        keyLen = 192/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "DES-ECB"))
    {
        keyLen = 64/8;
        isECB = 1;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "DES-CBC"))
    {
        keyLen = 64/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "BF-ECB"))
    {
        keyLen = 128/8;
        isECB = 1;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "BF-CBC"))
    {
        keyLen = 128/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "RC5-ECB"))
    {
        keyLen = 128/8;
        isECB = 1;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "RC5-CBC"))
    {
        keyLen = 128/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "RC4"))
    {
        keyLen = 128/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "RC4-40"))
    {
        keyLen = 40/8;
        pIv = (unsigned char *) &iv;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "ChaCha20"))
    {
        keyLen = 256/8;
        pIv = (unsigned char *) &iv;
    }

    for (i = 0; i < keyLen; i++)
    {
        key[i] = (ubyte)(i+2 & 0xff);
    }
    
    plaintext_len = 32;
    for (i = 0; i < plaintext_len; i++)
    {
        plaintext[i] = i+10;
    }

    for (i = 0; i < 16; i++)
    {
        iv[i] = i+1;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("ERROR EVP_CIPHER_CTX_new\n");
        goto exit;
    }

    pCipher = EVP_CIPHER_fetch(pLibCtx, pAlgoStr, NULL);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if ( (1 == EVP_default_properties_is_fips_enabled(NULL)) &&
         ((0 == DIGI_STRCMP(pAlgoStr, "DES-ECB")) ||
          (0 == DIGI_STRCMP(pAlgoStr, "DES-CBC"))) )
    {
        if (NULL != pCipher)
        {
            printf("ERROR EVP_CIPHER_fetch FIPS expected failure\n");
        }
        else
        {
            ret = 0;
        }
        goto exit;
    }
#endif
    if (NULL == pCipher)
    {
        printf("ERROR EVP_CIPHER_fetch\n");
        goto exit;
    }

#if defined(__ENABLE_MULTIPLE_INIT_TEST_2__)
    if (!isECB) /* ECB modes don't allow EVP_CipherInit_Ex with -1 direction */
    {
        if(1 != EVP_CipherInit_ex(ctx, pCipher, NULL, NULL, pIv, -1))
        {
            printf("ERROR EVP_CipherInit_ex\n");
            goto exit;
        }

        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
        {
            printf("ERROR EVP_EncryptInit_ex\n");
        }
    }
    else
#endif
    {
        if(1 != EVP_EncryptInit_ex(ctx, pCipher, NULL, key, pIv))
        {
            printf("ERROR EVP_EncryptInit_ex\n");
            goto exit;
        }
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        printf("ERROR EVP_EncryptUpdate\n");
        goto exit;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        printf("ERROR EVP_EncryptFinal_ex\n");
        goto exit;
    }
    ciphertext_len += len;

    /* Reset */
    EVP_CIPHER_CTX_reset(ctx);

    if(1 != EVP_DecryptInit_ex(ctx, pCipher, NULL, key, pIv))
    {
        printf("ERROR EVP_DecryptInit_ex\n");
        goto exit;
    }

    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
    {
        printf("ERROR EVP_DecryptUpdate\n");
        goto exit;
    }
    decryptedtext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len))
    {
        printf("ERROR EVP_DecryptFinal_ex\n");
        goto exit;
    }
    decryptedtext_len += len;

    status = DIGI_MEMCMP(decryptedtext, plaintext, (ubyte4) plaintext_len, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        printf("ERROR decrypted text did not match original plaintext\n");
    }
    else
    {
        ret = 0;
    }

exit:

    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (NULL != pCipher)
    {
        EVP_CIPHER_free(pCipher);
    }

    return ret;
}

int test_cipher_aead(OSSL_LIB_CTX *pLibCtx, char *pAlgoStr)
{
    MSTATUS status = ERR_GENERAL;
    int ret = 1;
    ubyte4 keyLen = 0;
    unsigned char aad[16] = {0xc0, 0xff, 0xee};
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char tag[16] = {0};
    unsigned char *pIv = (unsigned char *) &iv;
    unsigned char plaintext[32];
    unsigned char ciphertext[48];
    unsigned char decryptedtext[48];
    int decryptedtext_len = 0, ciphertext_len = 0, plaintext_len;
    int len = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *pCipher = NULL;
    sbyte4 cmp = 1;
    size_t i;
    byteBoolean isGcm = FALSE;
    byteBoolean isCcm = FALSE;

    if (0 == DIGI_STRCMP(pAlgoStr + 8, "GCM"))
    {
        isGcm = TRUE;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr + 8, "CCM"))
    {
        isCcm = TRUE;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "ChaCha20-Poly1305"))
    {
        keyLen = 256/8;
    }

    if (0 == DIGI_STRCMP(pAlgoStr, "AES-128-GCM") || 0 == DIGI_STRCMP(pAlgoStr, "AES-128-CCM"))
    {
        keyLen = 128/8;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "AES-192-GCM") || 0 == DIGI_STRCMP(pAlgoStr, "AES-192-CCM"))
    {
        keyLen = 192/8;
    }
    else if (0 == DIGI_STRCMP(pAlgoStr, "AES-256-GCM") || 0 == DIGI_STRCMP(pAlgoStr, "AES-256-CCM"))
    {
        keyLen = 256/8;
    }

    for (i = 0; i < keyLen; i++)
    {
        key[i] = i+2;
    }
    
    plaintext_len = 32;
    for (i = 0; i < plaintext_len; i++)
    {
        plaintext[i] = i+10;
    }

    for (i = 0; i < 16; i++)
    {
        iv[i] = i+1;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("ERROR EVP_CIPHER_CTX_new\n");
        goto exit;
    }

    pCipher = EVP_CIPHER_fetch(pLibCtx, pAlgoStr, NULL);
    if (NULL == pCipher)
    {
        printf("ERROR EVP_CIPHER_fetch\n");
        goto exit;
    }

    if(1 != EVP_EncryptInit_ex(ctx, pCipher, NULL, NULL, NULL))
    {
        printf("ERROR EVP_EncryptInit_ex\n");
        goto exit;
    }

    if(isGcm)
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;
        }
    }
    else if (isCcm)
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 12, NULL))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;
        }
    }

#if defined(__ENABLE_MULTIPLE_INIT_TEST__)
    if(1 != EVP_CipherInit_ex(ctx, pCipher, NULL, key, NULL, -1))
    {
        printf("ERROR EVP_CipherInit_ex\n");
        goto exit;
    }

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, pIv))
    {
        printf("ERROR EVP_EncryptInit_ex\n");
        goto exit;
    }
#elif defined(__ENABLE_MULTIPLE_INIT_TEST_2__)
    if(1 != EVP_CipherInit_ex(ctx, pCipher, NULL, NULL, pIv, -1))
    {
        printf("ERROR EVP_CipherInit_ex\n");
        goto exit;
    }

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
    {
        printf("ERROR EVP_EncryptInit_ex\n");
    }
#else
    if(1 != EVP_EncryptInit_ex(ctx, pCipher, NULL, key, pIv))
    {
        printf("ERROR EVP_EncryptInit_ex\n");
        goto exit;
    }
#endif

    /* ccm requires the plaintext len before the aad */
    if (isCcm) 
    {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
        {
            printf("ERROR EVP_EncryptUpdate\n");
            goto exit;         
        }
    }

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)))
    {
        printf("ERROR EVP_EncryptUpdate\n");
        goto exit;
    }

    if (isGcm)
    {
        int localLen = 0;
        len = 0;

        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &localLen, plaintext, 5))
        {
            printf("ERROR EVP_EncryptUpdate\n");
            goto exit;
        }
        len += localLen;
        
        if(1 != EVP_EncryptUpdate(ctx, ciphertext + len, &localLen, plaintext + 5, 17))
        {
            printf("ERROR EVP_EncryptUpdate\n");
            goto exit;
        }
        len += localLen;
        
        if(1 != EVP_EncryptUpdate(ctx, ciphertext + len, &localLen, plaintext + 22, 10))
        {
            printf("ERROR EVP_EncryptUpdate\n");
            goto exit;
        }
        len += localLen;
    }
    else
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        {
            printf("ERROR EVP_EncryptUpdate\n");
            goto exit;
        }
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        printf("ERROR EVP_EncryptFinal_ex\n");
        goto exit;
    }
    ciphertext_len += len;

    if (isGcm)
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;     
        }
    }
    else if (isCcm)
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 12, tag))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;     
        }
    }
    else
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;     
        }
    }

    /* Reset */
    EVP_CIPHER_CTX_reset(ctx);

    if(1 != EVP_DecryptInit_ex(ctx, pCipher, NULL, NULL, NULL))
    {
        printf("ERROR EVP_DecryptInit_ex\n");
        goto exit;
    }

    if (isGcm)
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;
        }

        if(1 != EVP_DecryptInit_ex(ctx, pCipher, NULL, key, pIv))
        {
            printf("ERROR EVP_DecryptInit_ex\n");
            goto exit;
        }

        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;        
        }
    }
    else if (isCcm)
    {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;
        }

        if(1 != EVP_DecryptInit_ex(ctx, pCipher, NULL, key, pIv))
        {
            printf("ERROR EVP_DecryptInit_ex\n");
            goto exit;
        }

        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 12, tag))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;        
        }
                
        /* ccm requires the cuphertext_len before the aad */
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
        {
            printf("ERROR EVP_DecryptUpdate\n");
            goto exit;         
        }

    }
    else
    {
        if(1 != EVP_DecryptInit_ex(ctx, pCipher, NULL, key, pIv))
        {
            printf("ERROR EVP_DecryptInit_ex\n");
            goto exit;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        {
            printf("ERROR EVP_CIPHER_CTX_ctrl\n");
            goto exit;     
        }
    }

    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)))
    {
        printf("ERROR EVP_DecryptUpdate\n");
        goto exit;
    }

    if (isGcm)
    {
        int localLen = 0;
        len = 0;

        if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &localLen, ciphertext, 5))
        {
            printf("ERROR EVP_DecryptUpdate\n");
            goto exit;
        }
        len += localLen;

        if(1 != EVP_DecryptUpdate(ctx, decryptedtext + len, &localLen, ciphertext + 5, 10))
        {
            printf("ERROR EVP_DecryptUpdate\n");
            goto exit;
        }
        len += localLen;
        
        if(1 != EVP_DecryptUpdate(ctx, decryptedtext + len, &localLen, ciphertext + 15, 17))
        {
            printf("ERROR EVP_DecryptUpdate\n");
            goto exit;
        }
        len += localLen;
    }
    else
    {
        if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
        {
            printf("ERROR EVP_DecryptUpdate\n");
            goto exit;
        }
    }
    decryptedtext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len))
    {
        printf("ERROR EVP_DecryptFinal_ex\n");
        goto exit;
    }
    decryptedtext_len += len;

    status = DIGI_MEMCMP(decryptedtext, plaintext, (ubyte4) plaintext_len, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        printf("ERROR decrypted text did not match original plaintext\n");
    }
    else
    {
        ret = 0;
    }

exit:

    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (NULL != pCipher)
    {
        EVP_CIPHER_free(pCipher);
    }

    return ret;
}
#endif
