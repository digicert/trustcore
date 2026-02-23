/*
 * moc_evp_rsa_keypair_gen_test.c
 *
 * Test program to verify RSA key pair generation
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
#include <sys/types.h>
#ifndef __RTOS_WIN32__
#include <sys/errno.h>
#include <unistd.h>
#include <getopt.h>
#endif
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#ifdef __RTOS_WIN32__
#include <ms/applink.c>
#include "getopt.inc"
#endif

#define MAX_NUM_CLEAR_TEXTS	100
char *clear_texts[MAX_NUM_CLEAR_TEXTS] = {
	{
		"This is a duck"
	}
};
static int num_clear_texts = 1;

static void prn_b64(unsigned char *in, int inlen);

#define OPER_ENCRYPT	1
#define OPER_SIGN	2

static int operation = OPER_ENCRYPT;

void
prn_usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-s] [-c <cleartext>] [-d]\n"
			"    -s - Request Sign & verify operation (default is encrypt/decrypt)\n"
			"    -c <string> - Cleartext string to be encrypted or signed. It can be\n"
			"                  given multiple times. The requested operation will be\n"
			"                  performed on each string\n"
			"    -d - Enable debug prints\n"
			,prog);
}

static char result[512];
static int debug;

int main(int argc, char *argv[])
{

	EVP_PKEY_CTX *pctx;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL, *params = NULL;
	int 	rv;
	X509      * cert = NULL;
	size_t 	outlen, inlen;
	char      * out = NULL;
	int		c;
	size_t 	reslen;
	int		n;
	char      * clear;
	BIO               *outbio = NULL;
	unsigned char hash[SHA_DIGEST_LENGTH];
    ENGINE *e = NULL;

	while ((c = getopt(argc, argv, "c:sd")) != -1) {
		switch(c) {
			case 'c':
				if (num_clear_texts >= MAX_NUM_CLEAR_TEXTS) {
					printf("Ignoring clear text string (limit of %d exceeded)", MAX_NUM_CLEAR_TEXTS);
					break;
				}
#ifdef __RTOS_WIN32__
				clear_texts[num_clear_texts++] = _strdup(optarg);
#else
				clear_texts[num_clear_texts++] = strdup(optarg);
#endif
				break;
			case 'd':
				++debug;
				break;
			case 's':
				operation = OPER_SIGN;
				break;
			default:
				prn_usage(argv[0]);
				exit(0);
		}
	}
	FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	ENGINE_load_builtin_engines();  

#if defined(__ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__)
    e = ENGINE_by_id("mocana");
    if (e == NULL) {
        /*
         * A failure to load is probably a platform environment problem so we
         * don't treat this as an OpenSSL test failure, i.e. we return 0
         */
        fprintf(stderr,
                "Mocana Test: Failed to load Mocana Engine - skipping test\n");
        return -1;
    }
    if (0 == ENGINE_set_default(e, ENGINE_METHOD_ALL))
    {
        printf("Setting the Engine methods failed");
        return -1;
    }
#endif		  

	/*outbio  = BIO_new(BIO_s_file());*/
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

        /* Parameter generation for RSA is not supported through EVP */

	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) 
		printf("Error in RSA key generation\n");

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(pctx)) 
		printf("Error in RSA key generation 1\n");

        if(!EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048)) 
		printf("Error in RSA key generation 2\n");

	if (1 != EVP_PKEY_keygen(pctx, &pkey)) 
		printf("Error in RSA key generation 3\n");

	/* Test */
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	/*ctx = kctx;*/
	if (!ctx) {
		/* Error occurred */
		printf("Error creating context\n");
		exit(1);
	}
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	for (n = 0; n < num_clear_texts; ++n) {
		clear = clear_texts[n];
		inlen = strlen(clear);
		if (debug) {
			if (OPER_ENCRYPT == operation)
				printf("Encrypting %d bytes of cleartext: %s\n", (int)inlen, clear);
			else
				printf("Signing %d bytes of digest: %s\n", (int)inlen, clear);
		}

		if (OPER_ENCRYPT == operation) {
			if (EVP_PKEY_encrypt_init(ctx) <= 0) {
				printf("Error in encrypt_init ctx\n");
				exit(1);
			}
			if (EVP_PKEY_encrypt(ctx, NULL, &outlen, clear, inlen) <= 0) {
				printf("Error in encrypt\n");
				exit(1);
			}
		} else {
			if (EVP_PKEY_sign_init(ctx) <= 0) {
				printf("Error in sign_init ctx\n");
				exit(1);
			}
            EVP_Digest(clear, strlen((char *)clear), hash, NULL, EVP_sha1(), NULL);
			if (EVP_PKEY_sign(ctx, NULL, &outlen, hash, SHA_DIGEST_LENGTH) <= 0) {
				printf("Error in sign with NULL buffer\n");
				exit(1);
			}
		}
		out = OPENSSL_malloc(outlen);
		if (OPER_ENCRYPT == operation) {
			if (EVP_PKEY_encrypt(ctx, out, &outlen, clear, inlen) <= 0) {
				printf("Error in encrypt\n");
			}
		} else {
			if (EVP_PKEY_sign(ctx, out, &outlen, hash, SHA_DIGEST_LENGTH) <= 0) {
				printf("Error in sign with NULL buffer\n");
				exit(1);
			}
		}
		if (debug) {
			if (OPER_ENCRYPT == operation)
				printf("%d bytes of Ciphertext\n", (int)outlen);
			else
				printf("%d bytes of Signature\n", (int)outlen);
			if (debug > 1) {
				prn_b64(out, outlen);
			}
		}
		if (OPER_ENCRYPT == operation) {
			if (0 >= (rv = EVP_PKEY_decrypt_init(ctx))) {
				printf("decrypt_init returns error\n");
				exit(1);
			}
		} else {
			if (0 >= (rv = EVP_PKEY_verify_init(ctx))) {
				printf("verify_init returns error\n");
				exit(1);
			}
		}
		reslen = sizeof(result);
		if (OPER_ENCRYPT == operation) {
			if (0 >= (rv = EVP_PKEY_decrypt(ctx, result, &reslen, out, outlen))) {	
				printf("decrypt returns error\n");
				exit(1);
			}
			result[reslen] = '\0';
			printf("Recovered plaintext: %s\n", result);
		} else {
			if (0 >= (rv = EVP_PKEY_verify(ctx, out, outlen, hash, SHA_DIGEST_LENGTH))) {	
				printf("verification returns error\n");
				exit(1);
			} else if (rv == 1) {
				printf("Signature verified OK for %s\n", clear);
			}
		}
		OPENSSL_free(out);
		out = NULL;
	}
    if(pkey) EVP_PKEY_free(pkey);
    if (params) EVP_PKEY_free(params);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    if(pctx) EVP_PKEY_CTX_free(pctx);
    if(outbio) BIO_free_all(outbio);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif
 return 0;
}

static void
prn_b64(unsigned char *in, int inlen)
{
	BIO	      * b64, *bio;
	BUF_MEM   * bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_write(bio, in, inlen);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	printf("%s", (*bufferPtr).data);
	fflush(stdout);
}
