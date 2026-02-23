/*
 * moc_evp_ec_keypair_gen.c
 *
 * Test code for EC key pair generation
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

static int operation = OPER_SIGN;

void
prn_usage(char *prog)
{
    fprintf(stderr, "Usage: %s [-c <cleartext>] [-d]\n"
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
    EVP_PKEY_CTX *pctx, *kctx;
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
    unsigned char hash[SHA_DIGEST_LENGTH];

    ENGINE *e;
    
    while ((c = getopt(argc, argv, "c:d")) != -1) {
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
	default:
	    prn_usage(argv[0]);
	    exit(0);
	}
    }

    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    ENGINE_load_builtin_engines();   

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
#if defined(__ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__)
    if (0 == ENGINE_set_default(e, ENGINE_METHOD_ALL))
    {
        printf("Setting the Engine methods failed");
        return -1;
    }
#endif	    

    /* Context for parameter generation */
    /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) 
        printf("Error in EC key generation\n");

    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx)) 
        printf("Error in EC key generation\n");

    /* We're going to use the ANSI X9.62 Prime 192v1 curve */
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) 
        printf("Error in EC key generation\n");

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) 
        printf("Error in EC key generation\n");


    /* Context for keygeneration */
    /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) 
        printf("Error in EC key generation 1 \n");

    /* Generate the key */
    if(1 != EVP_PKEY_keygen_init(kctx)) 
        printf("Error in EC key generation 2\n");

    if (1 != EVP_PKEY_keygen(kctx, &pkey)) 
        printf("Error in EC key generation 3\n");

    /* Test sign and verify using the pkey */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    /*ctx = kctx;*/
    if (!ctx) {
      /* Error occurred */
      printf("Error creating context\n");
      exit(1);
    }
     for (n = 0; n < num_clear_texts; ++n) {
	clear = clear_texts[n];
	inlen = strlen(clear);
	if (debug) {
            printf("Signing %d bytes of digest: %s\n", (int)inlen, clear);
	}
	if (EVP_PKEY_sign_init(ctx) <= 0) {
	    printf("Error in sign_init ctx\n");
	    exit(1);
	}

    EVP_Digest(clear, strlen((char *)clear), hash, NULL, EVP_sha1(), NULL);

	if (EVP_PKEY_sign(ctx, NULL, &outlen, hash, SHA_DIGEST_LENGTH) <= 0) {
	    printf("Error in sign with NULL buffer\n");
	    exit(1);
	}
	
	out = OPENSSL_malloc(outlen);
    if (EVP_PKEY_sign(ctx, out, &outlen, hash, SHA_DIGEST_LENGTH) <= 0) {
        printf("Error in sign with NULL buffer\n");
	    exit(1);
	}

	if (debug) {
   	    printf("%d bytes of Signature\n", (int)outlen);
	    if (debug > 1) {
		prn_b64(out, outlen);
	    }
	}
        if (0 >= (rv = EVP_PKEY_verify_init(ctx))) {
	    printf("verify_init returns error\n");
	    exit(1);
	}

	reslen = sizeof(result);
    if (0 >= (rv = EVP_PKEY_verify(ctx, out, outlen, hash, SHA_DIGEST_LENGTH))) {	
	    printf("verification returns error\n");
	    exit(1);
 	} else if (rv == 1) {
	    printf("Signature verified OK for %s\n", clear);
	}

	OPENSSL_free(out);
	out = NULL;
    }
    if (pkey)
        EVP_PKEY_free(pkey);
    if (params)
        EVP_PKEY_free(params);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);

    ENGINE_free(e);
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

