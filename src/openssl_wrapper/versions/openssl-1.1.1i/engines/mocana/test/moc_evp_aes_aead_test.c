/*
 * moc_evp_aes_aead_test.c
 *
 * Test AES AEAD encryption and decryption
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

/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_MOCANAENG
#ifndef __RTOS_WIN32__
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef __RTOS_WIN32__
#include "getopt.inc"
#if defined(_MSC_VER) && _MSC_VER < 1900
#define __func__ __FUNCTION__
#endif
#endif

/* Use a buffer size which is not aligned to block size */
static int verbose;


static void
rgk_hex_prn(unsigned char *x, int len, char *buf)
{
    int i;
    char hstr[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    for (i=0; i < len; ++i) {
	buf[2*i] = hstr[(x[i] & 0xF0) >> 4];
	buf[2*i+1] = hstr[x[i] & 0xF];
    }
    buf[2*i] = '\0';
}

static char prn_buf[512];

static const unsigned char gcm_key[] = { 0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
                          0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
                          0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f };
static const unsigned char gcm_iv[] = { 0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84 };
static const unsigned char gcm_pt[] = { 0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
                           0xcc, 0x2b, 0xf2, 0xa5 };
static const unsigned char gcm_aad[] = { 0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
                                  0x7f, 0xec, 0x78, 0xde };

static const unsigned char ccm_key[] = {
    0xce, 0xb0, 0x09, 0xae, 0xa4, 0x45, 0x44, 0x51, 0xfe, 0xad, 0xf0, 0xe6,
    0xb3, 0x6f, 0x45, 0x55, 0x5d, 0xd0, 0x47, 0x23, 0xba, 0xa4, 0x48, 0xe8,
    0xb3, 0x6f, 0x45, 0x55, 0x5d, 0xd0, 0x47, 0x23
};

static const unsigned char ccm_iv[] = {
    0x76, 0x40, 0x43, 0xc4, 0x94, 0x60, 0xb7
};

static const unsigned char ccm_aad[] = {
    0x6e, 0x80, 0xdd, 0x7f, 0x1b, 0xad, 0xf3, 0xa1, 0xc9, 0xab, 0x25, 0xc7,
    0x5f, 0x10, 0xbd, 0xe7, 0x8c, 0x23, 0xfa, 0x0e, 0xb8, 0xf9, 0xaa, 0xa5,
    0x3a, 0xde, 0xfb, 0xf4, 0xcb, 0xf7, 0x8f, 0xe4
};

static const unsigned char ccm_pt[] = {
    0xc8, 0xd2, 0x75, 0xf9, 0x19, 0xe1, 0x7d, 0x7f, 0xe6, 0x9c, 0x2a, 0x1f,
    0x58, 0x93, 0x9d, 0xfe, 0x4d, 0x40, 0x37, 0x91, 0xb5, 0xdf, 0x13, 0x10
};
static int test_mocana_aes_256_gcm(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    /*unsigned char outbuf[512];*/
    unsigned char ebuf[512];
    unsigned char dbuf[512];
    unsigned char tagbuf[16];
    int encl, encf, decl;
    int status = 0;
    

    if (verbose) printf("e=%p for GCM\n", e);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    
	rgk_hex_prn((unsigned char *)gcm_pt, sizeof(gcm_pt), prn_buf);
	if (verbose) printf("Plaintext=%s\n", prn_buf);

    if( !(EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), e, NULL, NULL, 1)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)
        && EVP_CipherInit_ex(ctx, NULL, e, gcm_key, gcm_iv, 1)
        && EVP_CipherUpdate(ctx, NULL, &encl, gcm_aad, sizeof(gcm_aad))
        && EVP_CipherUpdate(ctx, ebuf, &encl, gcm_pt, sizeof(gcm_pt))))
    {
	    fprintf(stderr, "%s() failed encryption\n", __func__);
	    goto end;
    }
    else
    {
	    rgk_hex_prn(ebuf, encl, prn_buf);
	    if (verbose) printf("ENCR=%s\n", prn_buf);
        if( !EVP_CipherFinal_ex(ctx, ebuf + encl, &encf))
        {
    	    fprintf(stderr, "%s() failed encryption\n", __func__);
    	    goto end;
        }
        else if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagbuf))
        {
    	    fprintf(stderr, "%s() failed to read tag\n", __func__);
    	    goto end;
        }
        else
        {
	        rgk_hex_prn(tagbuf, 16, prn_buf);
	        if (verbose) printf("Tag=%s\n", prn_buf);
        }
    }

    if(!(EVP_CIPHER_CTX_cleanup(ctx)
        && EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), e, NULL, NULL, 0)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagbuf)
        && EVP_CipherInit_ex(ctx, NULL, e, gcm_key, gcm_iv, 0)
        && EVP_CipherUpdate(ctx, NULL, &decl, gcm_aad, sizeof(gcm_aad))
        && EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)))
    {
	    fprintf(stderr, "%s() failed decryption\n", __func__);
	    goto end;
    }
    else
    {
	    rgk_hex_prn(dbuf, decl, prn_buf);
	    if (verbose) printf("DECR=%s\n", prn_buf);
        status = 1;
    }

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aes_256_ccm(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char ebuf[512];
    unsigned char dbuf[512];
    unsigned char tagbuf[16];
    int encl, encf, decl;
    int status = 0;
    
    if (verbose) printf("e=%p for CCM\n", e);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    
	rgk_hex_prn((unsigned char *)ccm_pt, sizeof(ccm_pt), prn_buf);
	if (verbose) printf("Plaintext=%s\n", prn_buf);
    if(!(EVP_CipherInit_ex(ctx, EVP_aes_256_ccm(), e, NULL, NULL, 1)
          && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL)
          && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL)
        && EVP_CipherInit_ex(ctx, NULL, e, ccm_key, ccm_iv, 1)
        && EVP_CipherUpdate(ctx, NULL, &encl, NULL, sizeof(ccm_pt))
        && EVP_CipherUpdate(ctx, NULL, &encl, ccm_aad, sizeof(ccm_aad))
        && EVP_CipherUpdate(ctx, ebuf, &encl, ccm_pt, sizeof(ccm_pt))))
    {
	    fprintf(stderr, "%s() failed encryption\n", __func__);
	    goto end;
    }
    else
    {
	    rgk_hex_prn(ebuf, encl, prn_buf);
	    if (verbose) printf("ENCR=%s\n", prn_buf);
        if(!EVP_CipherFinal_ex(ctx, ebuf + encl, &encf))
        {
    	    fprintf(stderr, "%s() failed encryption\n", __func__);
    	    goto end;
        }
        else if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tagbuf))
        {
    	    fprintf(stderr, "%s() failed to read tag\n", __func__);
    	    goto end;
        }
        else
        {
	        rgk_hex_prn(tagbuf, 16, prn_buf);
	        if (verbose) printf("Tag=%s\n", prn_buf);
        }
    }

    if(!(EVP_CIPHER_CTX_cleanup(ctx)
        && EVP_CipherInit_ex(ctx, EVP_aes_256_ccm(), e, NULL, NULL, 0)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tagbuf)
        && EVP_CipherInit_ex(ctx, NULL, e, ccm_key, ccm_iv, 0)
        && EVP_CipherUpdate(ctx, NULL, &decl, NULL, encl)
        && EVP_CipherUpdate(ctx, NULL, &decl, ccm_aad, sizeof(ccm_aad))
        && EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)))
    {
	    fprintf(stderr, "%s() failed decryption\n", __func__);
	    goto end;
    }
    else
    {
	    rgk_hex_prn(dbuf, decl, prn_buf);
	    if (verbose) printf("DECR=%s\n", prn_buf);
        status = 1;
    }

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

int MocanaEvpAesGcmNullTest(ENGINE *pEngine)
{
    unsigned char pKey[32] = { 0 };
    unsigned char pIv[16] = { 0 };
    unsigned char pInput[32] = { 0 };
    unsigned char pOutput[32] = { 0 };
    unsigned char pTag[16] = { 0 };
    unsigned char pExpectedTag[] = {
        0x53, 0x0F, 0x8A, 0xFB, 0xC7, 0x45, 0x36, 0xB9,
        0xA9, 0x63, 0xB4, 0xF1, 0xC4, 0xCB, 0x73, 0x8B
    };
    EVP_CIPHER_CTX *pCipherCtx = NULL;
    int outLen = 0, retVal = -1, i;
    int encryptFinalRet = 0;
#if OPENSSL_VERSION_NUMBER >= 0x1010109F
    encryptFinalRet = 1;
#endif

    pCipherCtx = EVP_CIPHER_CTX_new();
    if (NULL == pCipherCtx)
        goto exit;

    if (1 != EVP_EncryptInit_ex(pCipherCtx, EVP_aes_256_gcm(), pEngine, pKey, pIv))
        goto exit;
    
    if (1 != EVP_EncryptUpdate(pCipherCtx, NULL, &outLen, NULL, 0))
        goto exit;

    if (encryptFinalRet != EVP_EncryptFinal_ex(pCipherCtx, NULL, &outLen))
        goto exit;
    
    if (1 != EVP_CIPHER_CTX_ctrl(pCipherCtx, EVP_CTRL_GCM_GET_TAG, 16, pTag))
        goto exit;

    for (i = 0; i < 16; ++i)
        if (pTag[i] != pExpectedTag[i])
            goto exit;
    
    retVal = 0;

exit:

    EVP_CIPHER_CTX_free(pCipherCtx);

    return retVal;
}

int main(int argc, char **argv)
{
    ENGINE *e;
    int opt, ret = 0;

    while ((opt = getopt(argc, argv, "v")) != -1) {
	    switch (opt) {
	        case 'v':
	            verbose = 1;
	            break;
	        default:
	            fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
	            exit(1);
	    }
    }
    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
    

    ENGINE_load_builtin_engines();

    e = ENGINE_by_id("mocana");
    if (e == NULL) {
        /*
         * A failure to load is probably a platform environment problem so we
         * don't treat this as an OpenSSL test failure, i.e. we return 0
         */
        fprintf(stderr,
                "Mocana Test: Failed to load Mocana Engine - skipping test\n");
        return 0;
    }
#if defined(__ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__)
    if (0 == ENGINE_set_default(e, ENGINE_METHOD_ALL))
    {
        printf("Setting the Engine methods failed");
        return -1;
    }
#endif
    ENGINE_set_default_ciphers(e);

    if (MocanaEvpAesGcmNullTest(e))
    {
        ret = 1;
        goto end;
    }
    else
    {
        if (verbose)
            printf("MocanaEvpAesGcmNullTest() PASSED\n");
    }
    

    if (test_mocana_aes_256_gcm(e) == 0) {
        ret = 1;
        goto end;
    } else {
	    if (verbose) printf("aes_gcm PASSED\n");
    }
#ifndef __DISABLE_AES_CCM__
    if (test_mocana_aes_256_ccm(e) == 0) {
        ret = 1;
        goto end;
    } else {
	    if (verbose) printf("aes_ccm PASSED\n");
    }
#endif
    printf("PASS\n");
end:
    ENGINE_free(e);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
  
#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif
    return ret;
}

#else  /* OPENSSL_NO_MOCANAENG */

int main(int argc, char **argv)
{
    fprintf(stderr, "Mocana not supported - skipping Mocana tests\n");
    printf("PASS\n");
    return 0;
}

#endif
