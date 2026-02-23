/*
 * moc_evp_dh_derive_test.c
 *
 * Test code for DH key derivation
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
#include <string.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
/*#define PRINT_HEX*/
static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
#ifndef PRINT_HEX
    return;
#else
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\n%04x", n);
        fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
#endif
}

int main(int argc, char* argv[]) {

    EVP_PKEY_CTX *aCtx = NULL, *bCtx = NULL;
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
    unsigned char *aSKey = NULL, *bSKey = NULL;
    size_t aSkeylen, bSkeylen;
    EVP_PKEY *pkey = NULL, *peerkey = NULL, *params = NULL;
    ENGINE    * e = NULL;

    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
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

     /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL))) {
        printf("Error EVP_PKEY_CTX_new_id\n");
        goto error;
    }

    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx)) {
        printf("Error in EVP_PKEY_paramgen_init\n");
        goto error;
    }

   /* We're going to use the ANSI X9.62 Prime 192v1 curve */
    if(1 != EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, 2)) {
        printf("Error in EVP_PKEY_CTX_set_dh_paramgen_generator\n");
        goto error;
    }

  /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) {
        printf("Error in EVP_PKEY_paramgen\n");
        goto error;
    }


   /* Context for keygeneration */
   /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
        printf("Error in EVP_PKEY_CTX_new \n");
        goto error;
    }

    /* Generate the key for  */
    if(1 != EVP_PKEY_keygen_init(kctx)) {
        printf("Error in EVP_PKEY_keygen_init\n");
        goto error;
    }

    printf("Generating dh key 1\n");
    if (1 != EVP_PKEY_keygen(kctx, &pkey)) {
        printf("Error in EVP_PKEY_keygen\n");
        goto error;
    }

    printf("Generating dh peer key\n");    
    /* peerkey */
    if (1 != EVP_PKEY_keygen(kctx, &peerkey)) {
        printf("Error in EVP_PKEY_keygen for peer key\n");
        goto error;
    }


    aCtx = EVP_PKEY_CTX_new(pkey, NULL);
    if (aCtx == NULL) {
        printf("Error in EVP_PKEY_CTX_new\n");
	goto error;
    }

    bCtx = EVP_PKEY_CTX_new(peerkey, NULL);
    if (bCtx == NULL) {
        printf("Error in EVP_PKEY_CTX_new for peer key\n");
	goto error;
    }

    if (EVP_PKEY_derive_init(aCtx) <= 0) {
        printf("ERROR in EVP_PKEY_derive_init on ALICE\n");
        goto error;
    }

    if (EVP_PKEY_derive_set_peer(aCtx, peerkey) <= 0) {
        printf("ERROR in EVP_PKEY_derive_set_peer on ALICE\n");
        goto error;
    }


     /* Determine buffer length */
     if (EVP_PKEY_derive(aCtx, NULL, &aSkeylen) <= 0) {
         printf("ERROR in EVP_PKEY_derive on ALICE\n");
        goto error;
    }


     aSKey = OPENSSL_malloc(aSkeylen);

     if (!aSKey) {
         printf("ERROR in OPENSSL_malloc on ALICE\n");
        goto error;
    }

    printf("Generating shared secret using DH for ALICE\n"); 
    if (EVP_PKEY_derive(aCtx, aSKey, &aSkeylen) <= 0) {
         printf("ERROR in EVP_PKEY_derive in shared secret generate on ALICE\n");
        goto error;
    }



    if (EVP_PKEY_derive_init(bCtx) <= 0) {
        printf("ERROR in EVP_PKEY_derive_init on BOB \n");
        goto error;
    }

    if (EVP_PKEY_derive_set_peer(bCtx, pkey) <= 0) {
        printf("ERROR in EVP_PKEY_derive_set_peer on BOB \n");
        goto error;
    }


     /* Determine buffer length */
     if (EVP_PKEY_derive(bCtx, NULL, &bSkeylen) <= 0) {
         printf("ERROR in EVP_PKEY_derive on BOB\n");
         goto error;
    }


     bSKey = OPENSSL_malloc(bSkeylen);

     if (!bSKey) {
         printf("ERROR in OPENSSL_malloc on BOB\n");
         goto error;
    }

     printf("Generating shared secret using DH for BOB\n"); 
     if (EVP_PKEY_derive(bCtx, bSKey, &bSkeylen) <= 0) {
         printf("ERROR in EVP_PKEY_derive in shared secret generate on BOB\n");
         goto error;
    }
    hexdump(stderr, "SHARED SECRET: ALICE:", aSKey, aSkeylen);
    hexdump(stderr, "SHARED SECRET: BOB:", bSKey, bSkeylen);

     if ((aSkeylen == bSkeylen) && (memcmp(aSKey,bSKey, aSkeylen) == 0)) {
         printf("Shared secret matched.\n");
         goto error;
    }

error:
    if (bSKey != NULL)
	OPENSSL_free(bSKey);
    if (aSKey != NULL)
	OPENSSL_free(aSKey);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (kctx != NULL)
        EVP_PKEY_CTX_free(kctx);
    if (aCtx != NULL)
        EVP_PKEY_CTX_free(aCtx);
    if (bCtx != NULL)
        EVP_PKEY_CTX_free(bCtx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (peerkey != NULL)
        EVP_PKEY_free(peerkey);
    if (params != NULL)
        EVP_PKEY_free(params);

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
