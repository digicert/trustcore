/*
 * moc_evp_aes_test.c
 *
 * Test AES encryption and decryption
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

static unsigned char aes_key256[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55\x22\x33\x54\x65\x76\x82\x44\x55";

#define TEST_MOCANA_AES(klen, mode, nmode) \
    static int test_mocana_aes_##klen##_##mode(ENGINE *e) {	     \
    EVP_CIPHER_CTX *ctx;					     \
    const EVP_CIPHER *cipher = EVP_aes_##klen##_##mode();	     \
    unsigned char *key = aes_key##klen;				     \
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08"; \
    unsigned char in[BUFFER_SIZE];				     \
    unsigned char ebuf[BUFFER_SIZE + 32];			     \
    unsigned char dbuf[BUFFER_SIZE + 32];			     \
    int encl, encf, decl, decf;					     \
    unsigned int status = 0;					     \
    cipher = EVP_aes_##klen##_##mode();				     \
    if (verbose) {						     \
	printf("e=%p for " #mode " " "\n", e);			     \
    }								     \
    ctx = EVP_CIPHER_CTX_new();					     \
    if (ctx == NULL) {						     \
        fprintf(stderr, #mode "," ": error alloc ctx\n");	     \
        return 0;						     \
    }								     \
    RAND_bytes(in, BUFFER_SIZE);				     \
    if (!EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)		     \
	|| !EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)	     \
	|| !EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {	     \
        fprintf(stderr, #mode "," " failed encrypt\n");		     \
        goto end;						     \
    }								     \
    encl += encf;						     \
    if (!EVP_CIPHER_CTX_cleanup(ctx)				     \
	|| !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)	     \
	|| !EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)	     \
	|| !EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {	     \
        fprintf(stderr, #mode "," " failed decrypt\n");		     \
        goto end;						     \
    }								     \
    decl += decf;						     \
    if (decl != BUFFER_SIZE					     \
	|| memcmp(dbuf, in, BUFFER_SIZE)) {			     \
        fprintf(stderr, #mode "," #klen "failed Dec(Enc(P)) != P\n"); \
        goto end;						     \
    }								     \
    status = 1;							     \
      end:							     \
    EVP_CIPHER_CTX_free(ctx);           \
    return status;						     \
}

TEST_MOCANA_AES(256, ecb, ecb)
TEST_MOCANA_AES(256, cbc, cbc)
TEST_MOCANA_AES(256, ofb, ofb128)
TEST_MOCANA_AES(256, cfb, cfb128)


static int test_mocana_aeswrap_128(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_wrap();

    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char in[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf, i;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for aeswrap_128\n", e);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    
    if( EVP_CIPHER_mode( cipher ) == EVP_CIPH_WRAP_MODE ) EVP_CIPHER_CTX_set_flags( ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    printf("Input Key Data: \n");
    for (i = 0; i < 16; i++) {
        printf("%x ", in[i]);
    }
    printf ("\n");

    if(!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 1)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherInit_ex\n", __func__);
        goto end;
    }

    if(!EVP_CipherUpdate(ctx, ebuf, &encl, in, 16)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherUpdate\n", __func__);
        goto end;
    }

    if(!EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherFinal_ex\n", __func__);
        goto end;
    }
    
    encl += encf;

    printf("Encrypted Key Data: \n");
    for (i = 0; i < encl; i++) {
        printf("%x ", ebuf[i]);
    }
    printf ("\n");

    if (!EVP_CIPHER_CTX_cleanup(ctx)) {
        fprintf(stderr, "%s() failed decryption - EVP_CIPHER_CTX_cleanup\n", __func__);
        goto end;
    }

    if( EVP_CIPHER_mode( cipher ) == EVP_CIPH_WRAP_MODE ) EVP_CIPHER_CTX_set_flags( ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 0)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherInit_ex\n", __func__);
        goto end;
    }
 
    if (!EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherUpdate\n", __func__);
        goto end;
    }

    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherFinal_ex\n", __func__);
        goto end;
    }

    decl += decf;

    printf("Decrypted Key Data: \n");
    for (i = 0; i < decl; i++) {
        printf("%x ", dbuf[i]);
    }
    printf ("\n");

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aeswrap_192(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_wrap();

    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char in[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";

    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf, i;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for aeswrap_192\n", e);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    
    printf("Input Key Data: \n");
    for (i = 0; i < sizeof(in); i++) {
        if(in[i] == 0)
            break;
        printf("%x ", in[i]);
    }
    printf ("\n");

    if( EVP_CIPHER_mode( cipher ) == EVP_CIPH_WRAP_MODE ) EVP_CIPHER_CTX_set_flags( ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if(!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 1)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherInit_ex\n", __func__);
        goto end;
    }

    if(!EVP_CipherUpdate(ctx, ebuf, &encl, in, 24)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherUpdate\n", __func__);
        goto end;
    }

    if(!EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherFinal_ex\n", __func__);
        goto end;
    }
    
    encl += encf;
    
    printf("Encrypted Key Data: \n");
    for (i = 0; i < sizeof(ebuf); i++) {
        if(ebuf[i] == 0)
            break;
        printf("%x ", ebuf[i]);
    }
    printf ("\n");

    if (!EVP_CIPHER_CTX_cleanup(ctx)) {
        fprintf(stderr, "%s() failed decryption - EVP_CIPHER_CTX_cleanup\n", __func__);
        goto end;
    }

    if( EVP_CIPHER_mode( cipher ) == EVP_CIPH_WRAP_MODE ) EVP_CIPHER_CTX_set_flags( ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 0)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherInit_ex\n", __func__);
        goto end;
    }
 
    if (!EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherUpdate\n", __func__);
        goto end;
    }

    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherFinal_ex\n", __func__);
        goto end;
    }

    decl += decf;

    printf("Decrypted Key Data: \n");
    for (i = 0; i < sizeof(dbuf); i++) {
        if(dbuf[i] == 0)
            break;
        printf("%x ", dbuf[i]);
    }
    printf ("\n");

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}


static int test_mocana_aeswrap_256(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_wrap();

    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char in[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55\x22\x33\x54\x65\x76\x82\x44\x55";

    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf, i;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for aeswrap_256\n", e);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    
    if( EVP_CIPHER_mode( cipher ) == EVP_CIPH_WRAP_MODE ) EVP_CIPHER_CTX_set_flags( ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    printf("Input Key Data: \n");
    for (i = 0; i < sizeof(in); i++) {
        if(in[i] == 0)
            break;
        printf("%x ", in[i]);
    }
    printf ("\n");

    if(!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 1)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherInit_ex\n", __func__);
        goto end;
    }

    if(!EVP_CipherUpdate(ctx, ebuf, &encl, in, 32)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherUpdate\n", __func__);
        goto end;
    }

    if(!EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
	fprintf(stderr, "%s() failed encryption - EVP_CipherFinal_ex\n", __func__);
        goto end;
    }
    
    encl += encf;

    printf("Encrypted Key Data: \n");
    for (i = 0; i < sizeof(ebuf); i++) {
        if(ebuf[i] == 0)
            break;
        printf("%x ", ebuf[i]);
    }
    printf ("\n");

    if (!EVP_CIPHER_CTX_cleanup(ctx)) {
        fprintf(stderr, "%s() failed decryption - EVP_CIPHER_CTX_cleanup\n", __func__);
        goto end;
    }

    if( EVP_CIPHER_mode( cipher ) == EVP_CIPH_WRAP_MODE ) EVP_CIPHER_CTX_set_flags( ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 0)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherInit_ex\n", __func__);
        goto end;
    }
 
    if (!EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherUpdate\n", __func__);
        goto end;
    }

    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption - EVP_CipherFinal_ex\n", __func__);
        goto end;
    }

    decl += decf;

    printf("Decrypted Key Data: \n");
    for (i = 0; i < sizeof(dbuf); i++) {
        if(dbuf[i] == 0)
            break;
        printf("%x ", dbuf[i]);
    }
    printf ("\n");

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}


static int test_mocana_aes_128_cbc(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;
    if (verbose) {
      printf("e=%p for CBC\n", e);
    }
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
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for ECB\n", e);
    }

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

    if (verbose) {
      printf("e=%p for ECB\n", e);
    }
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
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for CFB\n", e);
    }
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
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for CTR\n", e);
    }
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
        fprintf(stderr, "%s() failed encryption\n", __func__);
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

static int test_mocana_aes_192_ctr(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_ctr();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for CTR\n", e);
    }
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
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl = encl;
    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
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

static int test_mocana_aes_256_ctr(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_ctr();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for CTR\n", e);
    }
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
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl = encl;
    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
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

static int test_mocana_aes_192_cbc(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_cbc();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;
    if (verbose) {
      printf("e=%p for CBC\n", e);
    }
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

static int test_mocana_aes_192_ecb(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_ecb();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for ECB\n", e);
    }

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

static int test_mocana_aes_192_ofb(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_ofb();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for ECB\n", e);
    }
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

static int test_mocana_aes_192_cfb(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_cfb();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if (verbose) {
      printf("e=%p for CFB\n", e);
    }
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


static int test_mocana_aes_cfb(int keylength, ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_192_cfb();
    unsigned char key128[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char key192[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char key256[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\x1D\x83\x27\xDE\xB8\x82\xCF\x99\x22\x33\x54\x65\x76\x82\x44\x55\x22\x33\x54\x65\x76\x82\x44\x55";
    unsigned char *key;
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    switch(keylength) {
    case 128:
	cipher = EVP_aes_192_cfb();
	key = key128;
	break;
    case 192:
	cipher = EVP_aes_192_cfb();
	key = key192;
	break;
    case 256:
	cipher = EVP_aes_256_cfb();
	key = key256;
	break;
    default:
	fprintf(stderr, "keylength %d not supported\n", keylength);
	return 0;
    }
    if (verbose) {
	printf("e=%p for CFB keylength %d\n", e, keylength);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() keylength=%d failed to allocate ctx\n", __func__, keylength);
        return 0;
    }
    RAND_bytes(in, BUFFER_SIZE);

    if (       !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)
            || !EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE)
            || !EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
        fprintf(stderr, "%s() keylength=%dfailed encryption\n", __func__, keylength);
        goto end;
    }
    encl += encf;

    if (       !EVP_CIPHER_CTX_cleanup(ctx)
            || !EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0)
            || !EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)
            || !EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() keylength=%d failed decryption\n", __func__, keylength);
        goto end;
    }
    decl += decf;

    if (       decl != BUFFER_SIZE
            || memcmp(dbuf, in, BUFFER_SIZE)) {
        fprintf(stderr, "%s() keylength=%d failed Dec(Enc(P)) != P\n", __func__, keylength);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static int test_mocana_aes_xts(int keyLen, ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_xts();
    unsigned char key32[32];
    unsigned char key64[64];
    unsigned char *key;
    unsigned char iv[16];

    unsigned char in[32];
    unsigned char ebuf[64];
    unsigned char dbuf[64];
    int encl, encf, decl, decf;
    unsigned int status = 0;

    if(keyLen == 128)
    {
        cipher = EVP_aes_128_xts();
        key = key32;
    }
    else if(keyLen == 256)
    {
        cipher = EVP_aes_256_xts();
        key = key64;
    }
    else
    {
        fprintf(stderr, "Invalid key length %d\n", keyLen);
        return 0;
    }
    if (verbose) {
      printf("e=%p for XTS KeyLength %d\n", e, keyLen);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    RAND_bytes(in, sizeof(in));

    if (!EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1)) {
        fprintf(stderr, "%s() - init failed encryption\n", __func__);
        goto end;
    }

    if (!EVP_CipherUpdate(ctx, ebuf, &encl, in, sizeof(in))) {
        fprintf(stderr, "%s() - update failed encryption\n", __func__);
        goto end;
    }

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
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }

    if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
        fprintf(stderr, "%s() failed decryption\n", __func__);
        goto end;
    }
    decl += decf;

    if ( (decl != encl) || (memcmp(dbuf, in, sizeof(in)))) {
        fprintf(stderr, "%s() failed Dec(Enc(P)) != P\n", __func__);
        goto end;
    }

    status = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static const int pStreamCiphers[] = {
    NID_aes_128_ofb128,
    NID_aes_192_ofb128,
    NID_aes_256_ofb128,
    NID_aes_128_cfb128,
    NID_aes_192_cfb128,
    NID_aes_256_cfb128,
    NID_aes_128_ctr,
    NID_aes_192_ctr,
    NID_aes_256_ctr
};

#define STREAM_CIPHER_COUNT (sizeof(pStreamCiphers)/sizeof(pStreamCiphers[0]))

static const EVP_CIPHER_CTX *pOpensslCiphers[STREAM_CIPHER_COUNT] = { 0 };
static const EVP_CIPHER_CTX *pMocanaCiphers[STREAM_CIPHER_COUNT] = { 0 };

void createCipherCtx(const EVP_CIPHER_CTX **ppCtxList, ENGINE *pEngine)
{
    int i;
    for (i = 0; i < STREAM_CIPHER_COUNT; i++)
    {
        ppCtxList[i] = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ppCtxList[i], EVP_get_cipherbynid(pStreamCiphers[i]), pEngine, NULL, NULL, 0);
    }
}

void deleteCipherCtx(const EVP_CIPHER_CTX **ppCtxList)
{
    int i;
    for (i = 0; i < STREAM_CIPHER_COUNT; i++)
    {
        EVP_CIPHER_CTX_free(ppCtxList[i]);
    }
}

int testNonBlockSize()
{
    int i, j, k, retVal = 0;
    unsigned char pIv[16] = { 0 };
    unsigned char pKey[32] = { 0 };
    unsigned char pMocPlaintext[100] = { 0 };
    unsigned char pMocCiphertext[100] = { 0 };
    unsigned char pOsslPlaintext[100] = { 0 };
    unsigned char pOsslCiphertext[100] = { 0 };
    int size, mocOutLen = 0, osslOutLen = 0, temp;

    for (i = 0; i < STREAM_CIPHER_COUNT; i++)
    {
        EVP_CIPHER_CTX *pOpensslCtx = pOpensslCiphers[i];
        EVP_CIPHER_CTX *pMocanaCtx = pMocanaCiphers[i];

        size = EVP_CIPHER_CTX_block_size(pOpensslCtx);
        size = (2 * size) - 1;

        for (j = 0; j < 2; j++)
        {
            if (j == 1)
            {
                size = EVP_CIPHER_CTX_block_size(pMocanaCtx);
                size = (2 * size) - 1;
            }

            if (0 == EVP_CipherInit(pOpensslCtx, NULL, pKey, pIv, 1))
            {
                goto exit;
            }
            if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext, &osslOutLen, pOsslPlaintext, size))
            {
                goto exit;
            }
            if (0 == EVP_EncryptFinal_ex(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp))
            {
                goto exit;
            }
            osslOutLen += temp;

            if (0 == EVP_CipherInit(pMocanaCtx, NULL, pKey, pIv, 1))
            {
                goto exit;
            }
            if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext, &mocOutLen, pMocPlaintext, size))
            {
                goto exit;
            }
            if (0 == EVP_EncryptFinal_ex(pMocanaCtx, pMocCiphertext + mocOutLen, &temp))
            {
                goto exit;
            }
            mocOutLen += temp;

            if (mocOutLen != osslOutLen)
            {
                goto exit;
            }

            if (0 != memcmp(pMocCiphertext, pOsslCiphertext, mocOutLen))
            {
                goto exit;
            }

            if (0 == EVP_CipherInit(pOpensslCtx, NULL, pKey, pIv, 0))
            {
                goto exit;
            }
            if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext, &osslOutLen, pOsslCiphertext, size))
            {
                goto exit;
            }
            if (0 == EVP_DecryptFinal_ex(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp))
            {
                goto exit;
            }
            osslOutLen += temp;

            for (k = 0; k < osslOutLen; k++)
            {
                pMocPlaintext[k] = pOsslPlaintext[k] + 1;
            }

            if (0 == EVP_CipherInit(pMocanaCtx, NULL, pKey, pIv, 0))
            {
                goto exit;
            }
            if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext, &mocOutLen, pMocCiphertext, size))
            {
                goto exit;
            }
            if (0 == EVP_DecryptFinal_ex(pMocanaCtx, pMocPlaintext + mocOutLen, &temp))
            {
                goto exit;
            }
            mocOutLen += temp;

            if (mocOutLen != osslOutLen)
            {
                goto exit;
            }

            if (0 != memcmp(pMocPlaintext, pOsslPlaintext, mocOutLen))
            {
                goto exit;
            }
        }
    }

    retVal = 1;

exit:

    return retVal;
}

int testZeroInput()
{
    int i, k, retVal = 0;
    unsigned char pIv[16] = { 0 };
    unsigned char pKey[32] = { 0 };
    unsigned char pMocPlaintext[100] = { 0 };
    unsigned char pMocCiphertext[100] = { 0 };
    unsigned char pOsslPlaintext[100] = { 0 };
    unsigned char pOsslCiphertext[100] = { 0 };
    int size, mocOutLen = 0, osslOutLen = 0, temp, index;

    for (i = 0; i < STREAM_CIPHER_COUNT; i++)
    {
        EVP_CIPHER_CTX *pOpensslCtx = pOpensslCiphers[i];
        EVP_CIPHER_CTX *pMocanaCtx = pMocanaCiphers[i];

        size = EVP_CIPHER_CTX_block_size(pMocanaCtx) - 2;
        switch (pStreamCiphers[i])
        {
            case NID_aes_128_ctr:
            case NID_aes_192_ctr:
            case NID_aes_256_ctr:
                size = 16 - 2;
                break;
        }

        if (0 == EVP_CipherInit(pOpensslCtx, NULL, pKey, pIv, 1))
        {
            goto exit;
        }
        index = 0;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext, &temp, pOsslPlaintext + index, 0))
        {
            goto exit;
        }
        osslOutLen = temp;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 1))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += 1;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, size))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += size;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 1))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += 1;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 1))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += 1;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_EncryptUpdate(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp, pOsslPlaintext + index, size * 3))
        {
            goto exit;
        }
        index += (size * 3);
        osslOutLen += temp;
        if (0 == EVP_EncryptFinal_ex(pOpensslCtx, pOsslCiphertext + osslOutLen, &temp))
        {
            goto exit;
        }
        osslOutLen += temp;

        if (0 == EVP_CipherInit(pMocanaCtx, NULL, pKey, pIv, 1))
        {
            goto exit;
        }
        index = 0;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext, &temp, pMocPlaintext + index, 0))
        {
            goto exit;
        }
        mocOutLen = temp;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 1))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += 1;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, size))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += size;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 1))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += 1;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 1))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += 1;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_EncryptUpdate(pMocanaCtx, pMocCiphertext + mocOutLen, &temp, pMocPlaintext + index, size * 3))
        {
            goto exit;
        }
        index += (size * 3);
        mocOutLen += temp;
        if (0 == EVP_EncryptFinal_ex(pMocanaCtx, pMocCiphertext + mocOutLen, &temp))
        {
            goto exit;
        }
        mocOutLen += temp;

        if (mocOutLen != osslOutLen)
        {
            goto exit;
        }

        if (0 != memcmp(pMocCiphertext, pOsslCiphertext, mocOutLen))
        {
            goto exit;
        }

        if (0 == EVP_CipherInit(pOpensslCtx, NULL, pKey, pIv, 0))
        {
            goto exit;
        }
        index = 0;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        osslOutLen = temp;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 1))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += 1;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, size))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += size;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 1))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += 1;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 1))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += 1;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        osslOutLen += temp;
        if (0 == EVP_DecryptUpdate(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp, pOsslCiphertext + index, size * 3))
        {
            goto exit;
        }
        osslOutLen += temp;
        index += (size * 3);
        if (0 == EVP_DecryptFinal_ex(pOpensslCtx, pOsslPlaintext + osslOutLen, &temp))
        {
            goto exit;
        }
        osslOutLen += temp;

        for (k = 0; k < osslOutLen; k++)
        {
            pMocPlaintext[k] = pOsslPlaintext[k] + 1;
        }

        if (0 == EVP_CipherInit(pMocanaCtx, NULL, pKey, pIv, 0))
        {
            goto exit;
        }
        index = 0;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        mocOutLen = temp;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 1))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += 1;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, size))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += size;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 1))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += 1;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 1))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += 1;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, 0))
        {
            goto exit;
        }
        mocOutLen += temp;
        if (0 == EVP_DecryptUpdate(pMocanaCtx, pMocPlaintext + mocOutLen, &temp, pOsslCiphertext + index, size * 3))
        {
            goto exit;
        }
        mocOutLen += temp;
        index += (size * 3);
        if (0 == EVP_DecryptFinal_ex(pMocanaCtx, pMocPlaintext + mocOutLen, &temp))
        {
            goto exit;
        }
        mocOutLen += temp;

        if (mocOutLen != osslOutLen)
        {
            goto exit;
        }

        if (0 != memcmp(pMocPlaintext, pOsslPlaintext, mocOutLen))
        {
            goto exit;
        }
    }

    retVal = 1;

exit:

    return retVal;
}

static int test_mocana_aes_stream_cipher(ENGINE *e)
{
    int retVal = 1;
    
    if (0 == testNonBlockSize())
    {
        retVal = 0;
        printf("testNonBlockSize failed\n");
    }

    if (0 == testZeroInput())
    {
        retVal = 0;
        printf("testZeroInput failed\n");
    }

    return retVal;
}

int main(int argc, char **argv)
{
    ENGINE *e;
    int opt;

    OpenSSL_add_all_algorithms();
    createCipherCtx(pOpensslCiphers, NULL);

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
    createCipherCtx(pMocanaCiphers, e);
    
    if (test_mocana_aeswrap_128(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
        if (verbose) printf("aeswrap_128 PASSED\n");
    }

    if (test_mocana_aeswrap_192(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
        if (verbose) printf("aeswrap_192 PASSED	\n");
    }

    if (test_mocana_aeswrap_256(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
        if (verbose) printf("aeswrap_256 PASSED\n");
    }

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
    if (test_mocana_aes_128_ctr(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_128_ctr PASSED\n");
    }
    if (test_mocana_aes_192_ctr(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_192_ctr PASSED\n");
    }
    if (test_mocana_aes_256_ctr(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_256_ctr PASSED\n");
    }
#endif

    if (test_mocana_aes_192_cbc(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_192_cbc PASSED\n");
    }

    if (test_mocana_aes_192_ecb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_192_ecb PASSED\n");
    }

    if (test_mocana_aes_192_ofb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_192_ofb PASSED\n");
    }
    if (test_mocana_aes_192_cfb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_192_cfb PASSED\n");
    }

    if (test_mocana_aes_256_ecb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_256_ecb PASSED\n");
    }

    if (test_mocana_aes_256_cbc(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_256_cbc PASSED\n");
    }
    if (test_mocana_aes_256_ofb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_256_ofb PASSED\n");
    }
    if (test_mocana_aes_256_cfb(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_256_cfb PASSED\n");
    }
    if (test_mocana_aes_cfb(256, e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	if (verbose) printf("aes_256_cfb PASSED\n");
    }

#ifndef __DISABLE_AES_XTS__
    if (test_mocana_aes_xts(128, e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	    if (verbose) printf("aes_128_xts PASSED\n");
    }
    if (test_mocana_aes_xts(256, e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	    if (verbose) printf("aes_256_xts PASSED\n");
    }
#endif
    if (test_mocana_aes_stream_cipher(e) == 0) {
        ENGINE_free(e);
        return 1;
    } else {
	    if (verbose) printf("aes stream cipher PASSED\n");
    }
    deleteCipherCtx(pOpensslCiphers);
    deleteCipherCtx(pMocanaCiphers);
    ENGINE_free(e);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
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
