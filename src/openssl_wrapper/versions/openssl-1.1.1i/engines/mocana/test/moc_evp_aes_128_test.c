/*
 * moc_evp_aes_128_test.c
 *
 * Test program for AES-128 EVP cipher implementation
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
#define BUFFER_SIZE     (8 * 1024) - 13
static int verbose = 1;

static int test_mocana_aes_128_cbc(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\
                           \x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\
                          \xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    RAND_bytes(in, BUFFER_SIZE);

    if (       !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)
            || !EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)
            || !EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
        fprintf(stderr, "%s() failed encryption\n", __func__);
        goto end;
    }
    encl += encf;

    if (       !EVP_CIPHER_CTX_cleanup(ctx)
            || !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)
            || !EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)
            || !EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl += decf;

    if (       decl != BUFFER_SIZE
            || memcmp(dbuf, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() failed Dec(Enc(P)) != P\n", __func__);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aes_128_ecb(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_ecb();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\
                           \x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\
                          \xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    RAND_bytes(in, BUFFER_SIZE);

    if (       !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)
            || !EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)
            || !EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
        fprintf(stderr, "%s() failed encryption\n", __func__);
        goto end;
    }
    encl += encf;

    if (       !EVP_CIPHER_CTX_cleanup(ctx)
            || !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)
            || !EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)
            || !EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl += decf;

    if (       decl != BUFFER_SIZE
            || memcmp(dbuf, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() failed Dec(Enc(P)) != P\n", __func__);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aes_128_ofb(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_ofb();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    RAND_bytes(in, BUFFER_SIZE);

    if (       !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)
            || !EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)
            || !EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
        fprintf(stderr, "%s() failed encryption\n", __func__);
        goto end;
    }
    encl += encf;

    if (       !EVP_CIPHER_CTX_cleanup(ctx)
            || !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)
            || !EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)
            || !EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl += decf;

    if (       decl != BUFFER_SIZE
            || memcmp(dbuf, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() failed Dec(Enc(P)) != P\n", __func__);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aes_128_cfb(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_cfb();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\
                           \x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\
                          \xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    RAND_bytes(in, BUFFER_SIZE);

    if (       !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)
            || !EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)
            || !EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
        fprintf(stderr, "%s() failed encryption\n", __func__);
        goto end;
    }
    encl += encf;

    if (       !EVP_CIPHER_CTX_cleanup(ctx)
            || !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)
            || !EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)
            || !EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl += decf;

    if (       decl != BUFFER_SIZE
            || memcmp(dbuf, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() failed Dec(Enc(P)) != P\n", __func__);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aes_128_ctr(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_ctr();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\
                           \x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\
                          \xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    RAND_bytes(in, BUFFER_SIZE);

    if (!EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)) {
        fprintf(stderr, "%s() - init failed encryption\n", __func__);
        goto end;
    }
    if (!EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() - update failed encryption\n", __func__);
        goto end;
    }
    encl = BUFFER_SIZE;

    if (!EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
        fprintf(stderr, "%s() - final failed encryption\n", __func__);
        goto end;
    }
    encl += encf;

    if (!EVP_CIPHER_CTX_cleanup(ctx)) {
        fprintf(stderr, "%s() - cleanup failed decryption\n", __func__);
        goto end;
    }
    if (!EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)) {
        fprintf(stderr, "%s() - init failed decryption\n", __func__);
        goto end;
    }
    if (!EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)) {
        fprintf(stderr, "%s() - update failed decryption\n", __func__);
        goto end;
    }
    decl = encl;
    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() - final failed decryption\n", __func__);
        goto end;
    }

    if (memcmp(dbuf, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() failed Dec(Enc(P)) != P\n", __func__);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

int main(int argc, char **argv)
{
    ENGINE *e;
    int opt;

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

#if (OPENSSL_VERSION_NUMBER == 0x10101000)
# ifndef OPENSSL_NO_STATIC_ENGINE
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_MOCANA, NULL);
# endif
#endif
    
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
    if (test_mocana_aes_128_cbc(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_128_cbc PASSED\n");
    }
    if (test_mocana_aes_128_ecb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_128_ecb PASSED\n");
    }
    if (test_mocana_aes_128_ofb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_128_ofb PASSED\n");
    }
    if (test_mocana_aes_128_cfb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_128_cfb PASSED\n");
    }
#ifndef __DISABLE_AES_CTR_CIPHER__
    if (test_mocana_aes_128_ctr(NULL) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_128_ctr PASSED\n");
    }
#endif
    ENGINE_free(e);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    printf("PASS\n");
  
#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif
    return 0;
}

#else  /* OPENSSL_NO_MOCANAENG */

int main(int argc, char **argv)
{
    fprintf(stderr, "Mocana not supported - skipping Mocana tests\n");
    printf("PASS\n");
    return 0;
}

#endif
