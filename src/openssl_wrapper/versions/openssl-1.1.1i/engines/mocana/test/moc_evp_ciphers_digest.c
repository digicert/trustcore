/*
 * moc_evp_ciphers_digest.c
 *
 * EVP cipher and digest test program
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

/* Written by Ben Laurie, 2001 */
/*
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>

#include "../e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/conf.h>

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

static int convert(unsigned char *s)
{
    unsigned char *d;
    int digits = 0;

    for (d = s; *s; s += 2, ++d) {
        unsigned int n;

        if (!s[1]) {
            fprintf(stderr, "Odd number of hex digits!");
            EXIT(4);
        }
        sscanf((char *)s, "%2x", &n);
        *d = (unsigned char)n;
        digits++;
    }
    return digits;
}

static char *sstrsep(char **string, const char *delim)
{
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, 256);
    isdelim[0] = 1;

    while (*delim) {
        isdelim[(unsigned char)(*delim)] = 1;
        delim++;
    }

    while (!isdelim[(unsigned char)(**string)]) {
        (*string)++;
    }

    if (**string) {
        **string = 0;
        (*string)++;
    }

    return token;
}

static unsigned char *ustrsep(char **p, const char *sep)
{
    return (unsigned char *)sstrsep(p, sep);
}

static int test1_exit(int ec)
{
    /*EXIT(ec);*/
    printf("Failed with code %d\n", ec);
    return (0 - ec);                 /* To keep some compilers quiet */
}

static int test1(const EVP_CIPHER *c, const unsigned char *key, int kn,
                  const unsigned char *iv, int in,
                  const unsigned char *plaintext, int pn,
                  const unsigned char *ciphertext, int cn,
                  const unsigned char *aad, int an,
                  const unsigned char *tag, int tn, int encdec)
{
    EVP_CIPHER_CTX *pCtx = NULL;
    unsigned char out[4096];
    int outl, outl2, mode;
    
    pCtx = EVP_CIPHER_CTX_new();

    printf("Testing cipher %s%s\n", EVP_CIPHER_name(c),
           (encdec ==
            1 ? "(encrypt)" : (encdec ==
                               0 ? "(decrypt)" : "(encrypt/decrypt)")));
    hexdump(stdout, "Key", key, kn);
    if (in)
        hexdump(stdout, "IV", iv, in);
    hexdump(stdout, "Plaintext", plaintext, pn);
    hexdump(stdout, "Ciphertext", ciphertext, cn);
    if (an)
        hexdump(stdout, "AAD", aad, an);
    if (tn)
        hexdump(stdout, "Tag", tag, tn);
    mode = EVP_CIPHER_mode(c);
    if (kn != EVP_CIPHER_key_length(c)) {
        fprintf(stderr, "Key length doesn't match, got %d expected %lu\n", kn,
                (unsigned long)EVP_CIPHER_key_length(c));
        return test1_exit(5);
    }
    EVP_CIPHER_CTX_init(pCtx);
    EVP_CIPHER_CTX_set_flags(pCtx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (encdec != 0) {
        if (mode == EVP_CIPH_GCM_MODE) {
            if (!EVP_EncryptInit_ex(pCtx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(11);
            }
            if (!EVP_EncryptInit_ex(pCtx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/IV set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(pCtx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(13);
            }
        } else if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_EncryptInit_ex(pCtx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_CCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(11);
            }
            if (!EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_CCM_SET_TAG, tn, NULL)) {
                fprintf(stderr, "Tag length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(11);
            }
            if (!EVP_EncryptInit_ex(pCtx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/IV set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(12);
            }
            if (!EVP_EncryptUpdate(pCtx, NULL, &outl, NULL, pn)) {
                fprintf(stderr, "Plaintext length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(pCtx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(13);
            }
        } else if (mode == EVP_CIPH_WRAP_MODE) {
            if (!EVP_EncryptInit_ex(pCtx, c, NULL, key, in ? iv : NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(10);
            }
        } else if (!EVP_EncryptInit_ex(pCtx, c, NULL, key, iv)) {
            fprintf(stderr, "EncryptInit failed\n");
            ERR_print_errors_fp(stderr);
            return test1_exit(10);
        }
        EVP_CIPHER_CTX_set_padding(pCtx, 0);

        if (!EVP_EncryptUpdate(pCtx, out, &outl, plaintext, pn)) {
            fprintf(stderr, "Encrypt failed\n");
            ERR_print_errors_fp(stderr);
            return test1_exit(6);
        }
        if (!EVP_EncryptFinal_ex(pCtx, out + outl, &outl2)) {
            fprintf(stderr, "EncryptFinal failed\n");
            ERR_print_errors_fp(stderr);
            return test1_exit(7);
        }

        if ((mode != EVP_CIPH_XTS_MODE) && (mode != EVP_CIPH_CTR_MODE)) {
            if (outl + outl2 != cn) {
                fprintf(stderr, "Ciphertext length mismatch got %d expected %d\n",
                        outl + outl2, cn);
                return test1_exit(8);
            }
        }

        if (memcmp(out, ciphertext, cn)) {
            fprintf(stderr, "Ciphertext mismatch\n");
            hexdump(stderr, "Got", out, cn);
            hexdump(stderr, "Expected", ciphertext, cn);
            return test1_exit(9);
        }
        if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE) {
            unsigned char rtag[16];
            /*
             * Note: EVP_CTRL_CCM_GET_TAG has same value as
             * EVP_CTRL_GCM_GET_TAG
             */
            if (!EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_GET_TAG, tn, rtag)) {
                fprintf(stderr, "Get tag failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(14);
            }
            if (memcmp(rtag, tag, tn)) {
                fprintf(stderr, "Tag mismatch\n");
                hexdump(stderr, "Got", rtag, tn);
                hexdump(stderr, "Expected", tag, tn);
                return test1_exit(9);
            }
        }
    }

	if(encdec != 0 && encdec != 1) {	
		EVP_CIPHER_CTX_cleanup(pCtx);
    	EVP_CIPHER_CTX_init(pCtx);
		EVP_CIPHER_CTX_set_flags(pCtx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	}

    if (encdec <= 0) {
        if (mode == EVP_CIPH_GCM_MODE) {
            if (!EVP_DecryptInit_ex(pCtx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(11);
            }
            if (!EVP_DecryptInit_ex(pCtx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/IV set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(12);
            }
            if (!EVP_CIPHER_CTX_ctrl
                (pCtx, EVP_CTRL_GCM_SET_TAG, tn, (void *)tag)) {
                fprintf(stderr, "Set tag failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(14);
            }
            if (an && !EVP_DecryptUpdate(pCtx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(13);
            }
        } else if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_DecryptInit_ex(pCtx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "DecryptInit failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_CCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(11);
            }
            if (!EVP_CIPHER_CTX_ctrl
                (pCtx, EVP_CTRL_CCM_SET_TAG, tn, (void *)tag)) {
                fprintf(stderr, "Tag length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(11);
            }
            if (!EVP_DecryptInit_ex(pCtx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/Nonce set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(12);
            }
            if (!EVP_DecryptUpdate(pCtx, NULL, &outl, NULL, pn)) {
                fprintf(stderr, "Plaintext length set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(12);
            }
            if (an && !EVP_DecryptUpdate(pCtx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(13);
            }
        } else if (mode == EVP_CIPH_WRAP_MODE) {
            if (!EVP_DecryptInit_ex(pCtx, c, NULL, key, in ? iv : NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                return test1_exit(10);
            }
        } else if (!EVP_DecryptInit_ex(pCtx, c, NULL, key, iv)) {
            fprintf(stderr, "DecryptInit failed\n");
            ERR_print_errors_fp(stderr);
            return test1_exit(11);
        }
        EVP_CIPHER_CTX_set_padding(pCtx, 0);

        if (!EVP_DecryptUpdate(pCtx, out, &outl, ciphertext, cn)) {
            fprintf(stderr, "Decrypt failed\n");
            ERR_print_errors_fp(stderr);
            return test1_exit(6);
        }
        if (mode != EVP_CIPH_CCM_MODE
            && !EVP_DecryptFinal_ex(pCtx, out + outl, &outl2)) {
            fprintf(stderr, "DecryptFinal failed\n");
            ERR_print_errors_fp(stderr);
            return test1_exit(7);
        }

        if (mode != EVP_CIPH_XTS_MODE) {
            if (outl + outl2 != pn) {
                fprintf(stderr, "Plaintext length mismatch got %d expected %d\n",
                        outl + outl2, pn);
                return test1_exit(8);
            }
        }

        if (memcmp(out, plaintext, pn)) {
            fprintf(stderr, "Plaintext mismatch\n");
            hexdump(stderr, "Got", out, pn);
            hexdump(stderr, "Expected", plaintext, pn);
            return test1_exit(9);
        }
    }

    EVP_CIPHER_CTX_cleanup(pCtx);
    EVP_CIPHER_CTX_free(pCtx);

    printf("Passed!\n");
    return 1;
}

static int test_cipher(const char *cipher, const unsigned char *key, int kn,
                       const unsigned char *iv, int in,
                       const unsigned char *plaintext, int pn,
                       const unsigned char *ciphertext, int cn,
                       const unsigned char *aad, int an,
                       const unsigned char *tag, int tn, int encdec)
{
    const EVP_CIPHER *c;

    c = EVP_get_cipherbyname(cipher);
    if (!c)
        return 0;

    return test1(c, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an, tag, tn,
          encdec);
}

static int test_digest(const char *digest,
                       const unsigned char *plaintext, int pn,
                       const unsigned char *ciphertext, unsigned int cn)
{
    const EVP_MD *d;
    EVP_MD_CTX *ctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdn;

    d = EVP_get_digestbyname(digest);
    if (!d)
        return 0;

    printf("Testing digest %s\n", EVP_MD_name(d));
    hexdump(stdout, "Plaintext", plaintext, pn);
    hexdump(stdout, "Digest", ciphertext, cn);

    ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(ctx, d, NULL)) {
        fprintf(stderr, "DigestInit failed\n");
        ERR_print_errors_fp(stderr);
        return -100;
    }
    if (!EVP_DigestUpdate(ctx, plaintext, pn)) {
        fprintf(stderr, "DigestUpdate failed\n");
        ERR_print_errors_fp(stderr);
        return -101;
    }
    if (!EVP_DigestFinal_ex(ctx, md, &mdn)) {
        fprintf(stderr, "DigestFinal failed\n");
        ERR_print_errors_fp(stderr);
        return -101;
    }
    EVP_MD_CTX_reset(ctx);

    if (mdn != cn) {
        fprintf(stderr, "Failed: Digest length mismatch, got %d expected %d\n", mdn,
                cn);
        return -102;
    }

    if (memcmp(md, ciphertext, cn)) {
        fprintf(stderr, "Failed: Digest mismatch\n");
        hexdump(stderr, "Got", md, cn);
        hexdump(stderr, "Expected", ciphertext, cn);
        return -103;
    }

    printf("Passed!\n");

    EVP_MD_CTX_free(ctx);

    return 1;
}

int main(int argc, char **argv)
{
    const char *szTestFile;
    FILE *f;
    ENGINE    * e = NULL;

    if (argc != 2) {
        fprintf(stderr, "%s evptest.txt\n", argv[0]);
        EXIT(1);
    }
    FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
    

    szTestFile = argv[1];

    f = fopen(szTestFile, "r");
    if (!f) {
        perror(szTestFile);
        EXIT(2);
    }
    ERR_load_crypto_strings();
    /* Load up the software EVP_CIPHER and EVP_MD definitions */
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
#ifndef OPENSSL_NO_ENGINE
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
#endif
#if 0
    OPENSSL_config();
#endif
#ifndef OPENSSL_NO_ENGINE

#if defined(__ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__)
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
    if (0 == ENGINE_set_default(e, ENGINE_METHOD_ALL))
    {
        printf("Setting the Engine methods failed");
        return -1;
    }
#endif
    /*
     * Register all available ENGINE implementations of ciphers and digests.
     * This could perhaps be changed to "ENGINE_register_all_complete()"?
     */
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
    /*
     * If we add command-line options, this statement should be switchable.
     * It'll prevent ENGINEs being ENGINE_init()ialised for cipher/digest use
     * if they weren't already initialised.
     */
    /* ENGINE_set_cipher_flags(ENGINE_CIPHER_FLAG_NOINIT); */
#endif

    for (;;) {
        char line[4096];
        char *p;
        char *cipher;
        unsigned char *iv, *key, *plaintext, *ciphertext, *aad, *tag;
        int encdec;
        int kn, in, pn, cn;
        int an = 0;
        int tn = 0;

        if (!fgets((char *)line, sizeof line, f))
            break;
        if (line[0] == '#' || line[0] == '\n')
            continue;
        p = line;
        cipher = sstrsep(&p, ":");
        key = ustrsep(&p, ":");
        iv = ustrsep(&p, ":");
        plaintext = ustrsep(&p, ":");
        ciphertext = ustrsep(&p, ":");
        if (p[-1] == '\n') {
            encdec = -1;
            p[-1] = '\0';
            tag = aad = NULL;
            an = tn = 0;
        } else {
            aad = ustrsep(&p, ":");
            tag = ustrsep(&p, ":");
            if (tag == NULL) {
                p = (char *)aad;
                tag = aad = NULL;
                an = tn = 0;
            }
            if (p[-1] == '\n') {
                encdec = -1;
                p[-1] = '\0';
            } else
                encdec = atoi(sstrsep(&p, "\n"));
        }

        kn = convert(key);
        in = convert(iv);
        pn = convert(plaintext);
        cn = convert(ciphertext);
        if (aad) {
            an = convert(aad);
            tn = convert(tag);
        }

        if (0 == test_cipher
            (cipher, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an,
             tag, tn, encdec)
            && !test_digest(cipher, plaintext, pn, ciphertext, cn)) {
#ifdef OPENSSL_NO_AES
            if (strstr(cipher, "AES") == cipher) {
                fprintf(stdout, "Cipher disabled, skipping %s\n", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_DES
            if (strstr(cipher, "DES") == cipher) {
                fprintf(stdout, "Cipher disabled, skipping %s\n", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_RC4
            if (strstr(cipher, "RC4") == cipher) {
                fprintf(stdout, "Cipher disabled, skipping %s\n", cipher);
                continue;
            }
#endif
            fprintf(stderr, "Can't find %s\n", cipher);
            EXIT(3);
        }
    }
    fclose(f);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    
    /* Enable the below statement for checking memory leak. */
    /*CRYPTO_mem_leaks_fp(stderr);*/

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif
    return 0;
}
