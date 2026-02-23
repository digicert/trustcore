/*
 * moc_evp_rc4_test.c
 *
 * Test program to verify RC4 EVP functions
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

static int test_mocana_rc4(ENGINE *e)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_rc4();
    unsigned char key[16] = "0011223300112233";
    unsigned char text[28] = "The eagle flies at midnight.";
    

    unsigned char ebuf[28];
    unsigned char dbuf[28];
    int encl, encf, decl, decf;
    unsigned int status = 0;
    if (verbose) {
      printf("e=%p for rc4\n", e);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return 0;
    }
    

    if (       !EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 1)) {
	printf("Error in CipherInit");
    } else if (!EVP_CipherUpdate(ctx, ebuf, &encl, text, 28)) {
	printf("Error in cipherUpdate\n");
    } else {
	rgk_hex_prn(ebuf, encl, prn_buf);
	printf("ENCR=%s\n", prn_buf);
	if (!EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)) {
	    fprintf(stderr, "%s() failed encryption\n", __func__);
	    goto end;
	} else {
	    rgk_hex_prn(ebuf+encl, encf, prn_buf);
	    printf("ENCR2=%s\n", prn_buf);
	}
    }
    encl += encf;

    if (!EVP_CIPHER_CTX_cleanup(ctx))
	printf("Error in cleanup\n");
    else if (!EVP_CipherInit_ex(ctx, cipher, e, key, NULL, 0)) {
	printf("Error in CipherInit\n");
    } else if (!EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl)) {
	printf("Error in CipherUpdate\n");
    } else {
	rgk_hex_prn(dbuf, decl, prn_buf);
	printf("DECR=%s\n", prn_buf);
	if (!EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)) {
	    fprintf(stderr, "%s() failed decryption\n", __func__);
	    goto end;
	} else {
	    rgk_hex_prn(dbuf+decl, decf, prn_buf);
	    printf("DECR2=%s\n", prn_buf);
	}
    }
    decl += decf;

    if (       decl != 28
            || memcmp(dbuf, text, 28)) {
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

    if (test_mocana_rc4(e) == 0) {
        ret = 1;
        goto end;
    } else {
		if (verbose) printf("rc4 PASSED\n");
    }
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
