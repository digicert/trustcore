/**
 * test_rsa_enc_dec.c
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

#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

#include <stdio.h>

int my_pem_password_cb(char *buf, int size, int rwflag, void *userdata);

int test_rsa_enc_dec(OSSL_LIB_CTX *pLibCtx, int bits, byteBoolean isOaep)
{
    MSTATUS status = ERR_GENERAL;
    int cmp = -1;

    EVP_PKEY *pKey = NULL;
    EVP_PKEY_CTX *pCtx = NULL;

    unsigned char out[1024] = {0}; /* big enough for any test */
    unsigned char in[24] = "Message to be encrypted";
    unsigned char rec[1024] = {0};
    size_t outlen = 0, inlen = 23, reclen = 0;

    pCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, "RSA", NULL);
    if (NULL == pCtx)
    {
        printf("ERROR fetching RSA algo\n");
        return 1;
    }

    if (1 != EVP_PKEY_keygen_init(pCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_CTX_set_rsa_keygen_bits(pCtx, bits))
    {
        printf("ERROR EVP_PKEY_CTX_set_rsa_keygen_bits\n");
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(pCtx, &pKey))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }

    (void) EVP_PKEY_CTX_free(pCtx);

    pCtx = EVP_PKEY_CTX_new_from_pkey(pLibCtx, pKey, NULL);
    if (NULL == pCtx)
    {
        printf("Error EVP_PKEY_CTX_new_from_pkey\n");
        goto exit;
    }                  

    if (1 != EVP_PKEY_encrypt_init(pCtx)) 
    {
        printf("Error in encrypt_init pCtx\n");
        goto exit;
    }

    if (isOaep)
    {
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pCtx, RSA_PKCS1_OAEP_PADDING))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_padding\n");
            goto exit;
        }
    }

    if (1 != EVP_PKEY_encrypt(pCtx, NULL, &outlen, (const unsigned char *)in, inlen))
    {
        printf("Error in encrypt\n");
        goto exit;
    }

    if (bits/8 != outlen)
    {
        printf("Error in encrypt returned length\n");
        goto exit;
    }

    if (1 != EVP_PKEY_encrypt(pCtx, out, &outlen, (const unsigned char *)in, inlen)) 
    {
        printf("Error in encrypt\n");
        goto exit;
    }

    if (1 != EVP_PKEY_decrypt_init(pCtx)) 
    {
        printf("decrypt_init returns error\n");
        goto exit;
    }

    if (isOaep)
    {
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pCtx, RSA_PKCS1_OAEP_PADDING))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_padding\n");
            goto exit;
        }
    }
    
    if (1 != EVP_PKEY_decrypt(pCtx, NULL, &reclen, out, outlen)) 
    {
        printf("decrypt returns error\n");
        goto exit;
    }

    if (bits/8 != reclen)
    {
        printf("decrypt does not return correct length\n");
        goto exit;
    }

    if (1 != EVP_PKEY_decrypt(pCtx, rec, &reclen, out, outlen)) 
    {
        printf("decrypt returns error\n");
        goto exit;
    }

    if (reclen != inlen)
    {
        printf("Recovered plaintext length does't match the original length\n");
        goto exit;
    }

    (void) DIGI_MEMCMP(in, rec, reclen, &cmp);

    if (cmp)
    {
        printf("Recovered plaintext does not match original\n");
        goto exit;
    }

    status = OK;

exit:

    if (NULL != pCtx)
    {
        EVP_PKEY_CTX_free(pCtx);
    }
    if (NULL != pKey)
    {
        EVP_PKEY_free(pKey);
    }

    return (status == OK) ? 0 : 1;
}

int test_rsa_enc_dec_pem(OSSL_LIB_CTX *pLibCtx, char *pPemFile, char *pw)
{
    MSTATUS status = ERR_GENERAL;
    int cmp = -1;

    EVP_PKEY *pKey = NULL;
    EVP_PKEY_CTX *pCtx = NULL;

    unsigned char out[1024] = {0}; /* big enough for any test */
    unsigned char in[24] = "Message to be encrypted";
    unsigned char rec[1024] = {0};
    size_t outlen = 0, inlen = 23, reclen = 0;

    FILE *fp_priv = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;

    if (NULL == pPemFile)
    {
        printf("ERROR, NULL input file\n");
        return 1;
    }

    fp_priv = fopen(pPemFile, "r");
    if (NULL == fp_priv)
    {
        printf("ERROR, Can't open %s\n", pPemFile);
        return 1;
    }    
    
    pKey = PEM_read_PrivateKey(fp_priv, NULL, NULL == pw ? my_pem_password_cb : NULL, (void *) pw);
    if (NULL == pKey)
    {
        printf("ERROR PEM_read_PrivateKey\n");
        return 1;
    }   

    pCtx = EVP_PKEY_CTX_new(pKey, NULL);
    if (NULL == pCtx)
    {
        printf("ERROR fetching RSA algo\n");
        return 1;
    }

    if (1 != EVP_PKEY_encrypt_init(pCtx)) 
    {
        printf("Error in encrypt_init pCtx\n");
        goto exit;
    }

    if (1 != EVP_PKEY_encrypt(pCtx, NULL, &outlen, (const unsigned char *)in, inlen))
    {
        printf("Error in encrypt\n");
        goto exit;
    }

    if (1 != EVP_PKEY_encrypt(pCtx, out, &outlen, (const unsigned char *)in, inlen)) 
    {
        printf("Error in encrypt\n");
        goto exit;
    }

    if (1 != EVP_PKEY_decrypt_init(pCtx)) 
    {
        printf("decrypt_init returns error\n");
        goto exit;
    }
    
    if (1 != EVP_PKEY_decrypt(pCtx, NULL, &reclen, out, outlen)) 
    {
        printf("decrypt returns error\n");
        goto exit;
    }

    if (1 != EVP_PKEY_decrypt(pCtx, rec, &reclen, out, outlen)) 
    {
        printf("decrypt returns error\n");
        goto exit;
    }

    if (reclen != inlen)
    {
        printf("Recovered plaintext length does't match the original length\n");
        goto exit;
    }

    (void) DIGI_MEMCMP(in, rec, reclen, &cmp);

    if (cmp)
    {
        printf("Recovered plaintext does not match original\n");
        goto exit;
    }

    status = OK;

exit:

    if (NULL != pCtx)
    {
        EVP_PKEY_CTX_free(pCtx);
    }
    if (NULL != pKey)
    {
        EVP_PKEY_free(pKey);
    }
    if (NULL != fp_priv)
    {
        fclose(fp_priv);
    }

    return (status == OK) ? 0 : 1;
}
#endif
