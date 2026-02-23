/*
 * ossl_rsa.c
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

#define OPENSSL_SUPPRESS_DEPRECATED

#ifdef __RTOS_WIN32__
#include <Windows.h>
#endif

#include "openssl/opensslconf.h"

/*
 * VxWorks7 & VxWorks6.9 have openssl .h files in different locations
 */
#ifdef __RTOS_VXWORKS__
#include <openssl/x509.h>
#include "../openssl_wrapper/ossl_pem.h"
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <internal/evp_int.h>
#include <rsa/rsa_locl.h>
#include <dsa/dsa_locl.h>
#include <openssl/err.h>
#include <internal/o_dir.h>
#include <openssl/crypto.h>
#else /* !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include <err.h>
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#else
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include "crypto/rsa/rsa_locl.h"
#include "crypto/dsa/dsa_locl.h"
#else
#include "crypto/rsa/rsa_local.h"
#include "crypto/dsa/dsa_local.h"
#endif
#include "../openssl_wrapper/ossl_pem.h"
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include "crypto/include/internal/evp_int.h"
#else
#include "include/crypto/evp.h"
#endif
#include <include/openssl/err.h>
#include <include/internal/o_dir.h>
#else
#include "crypto/x509/x509.h"
#include "../openssl_wrapper/ossl_pem.h"
#include <crypto/err/err.h>
#include "crypto/o_dir.h"
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/vlong.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../ssl/ssl.h"
#include "../crypto/dsa.h"
#include "../crypto/rsa.h"

#include "openssl_shim.h"
#include "ossl_types.h"
#include "ossl_cert_convert.h"
#include "../openssl_wrapper/ssl.h"

#include <string.h>

#if defined( __RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_CYGWIN__) || \
    defined(__RTOS_SOLARIS__) || defined(__RTOS_IRIX__) || defined(__RTOS_OPENBSD__) || \
    defined(__RTOS_ANDROID__) || defined(__RTOS_FREEBSD__) || defined(__RTOS_OSX__)
#include <signal.h>
#include <termios.h>
#endif

#define MOC_OSSL_INVALID_EX_DATA   -1

int dsaExAppDataIndex = MOC_OSSL_INVALID_EX_DATA;
int rsaExAppDataIndex = MOC_OSSL_INVALID_EX_DATA;
int eccExAppDataIndex = MOC_OSSL_INVALID_EX_DATA;

static char *aliasString = "openssl_key_cert_alias";
static ubyte4 aliasStringLength = 23; /* length of aliasString + 1 */

/* Extended externs for Mocana */
#ifdef __ENABLE_DIGICERT_TPM__
#include "../crypto/secmod/moctap.h"
#endif

#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)
static EVP_PKEY *DIGI_PEM_read_bio_PrivateKey(
    BIO *pBio,
    EVP_PKEY **ppRetEvpPkey,
    pem_password_cb *pPasswordCallback,
    void *pPasswordCallbackInfo
    );
int OPENSSL_register_pem_bio_handler(
    EVP_PKEY *(*handler)(BIO *, EVP_PKEY**, pem_password_cb *, void *)
    );
#endif

#if !(defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__))
int ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new
                           *new_func, CRYPTO_EX_dup *dup_func,
                           CRYPTO_EX_free *free_func);
int ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

extern int moc_get_decrypted_content(BIO *pB, unsigned char **pData,
                                     long *pLen, pem_password_cb *cb,void *u);

static int
ends_with_extension(const char *name, const char *extension, size_t length)
{
    const char *lDot = strrchr(name, '.');
    if (lDot != NULL)
    {
        if (length == 0)
        {
            length = strlen(extension);
        }
        return strncmp(lDot + 1, extension, length) == 0;
    }
    return 0;
}

#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)
int register_pem_bio_handler()
{
    return OPENSSL_register_pem_bio_handler(DIGI_PEM_read_bio_PrivateKey);
}
#endif

int ssl_cert_type(X509 *x, EVP_PKEY *pkey)
{
     EVP_PKEY * pk;
     int 	i;
     if (pkey == NULL)
	  pk = X509_get_pubkey(x);
     else
	  pk = pkey;
     i = pk->type;
     if (i == EVP_PKEY_RSA)
     {
	  return OSSL_PKEY_RSA;
     } else if (i == EVP_PKEY_DSA)
     {
	  return OSSL_PKEY_DSA;
     } else if (i == EVP_PKEY_EC)
     {
	  return OSSL_PKEY_EC;
     }
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     else if (i == EVP_PKEY_ED448)
     {
         return OSSL_EVP_PKEY_ED448;
     }
     else if (i == EVP_PKEY_ED25519)
     {
         return OSSL_EVP_PKEY_ED25519;
     }
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

     return -1;
}

static int ssl_set_cert(SSL_CTX *ctx, X509 *x)
{
    EVP_PKEY *pkey;
    int i;

    pkey = X509_get_pubkey(x);
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_SET_CERT, SSL_R_X509_LIB);
        return (0);
    }

    i = ssl_cert_type(x, pkey);
    if (i < 0) {
        SSLerr(SSL_F_SSL_SET_CERT, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        EVP_PKEY_free(pkey);
        return (0);
    }

    if (ctx->privatekey[i] != NULL) {
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pkey, ctx->privatekey[i]);
        ERR_clear_error();
    }

    EVP_PKEY_free(pkey);

    if (ctx->cert_x509 != NULL)
        X509_free(ctx->cert_x509);
    ctx->ossl_pkey_idx	= i;
    ctx->cert_x509 	= x;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    X509_up_ref(x);
#else
    CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
#endif
    ctx->cert_valid	= 0;

    /* If we already have a key, then try to load cert and key into cert store */
    if (1 == ctx->privateKeyPending)
    {
        ctx->privatekey[i] = ctx->privatekey[OSSL_PKEY_MAX];
        ctx->privatekey[OSSL_PKEY_MAX] = NULL;

        ctx->privateKeyPending = 0;

        if (ctx->pKeyAlias != NULL)
        {
            OSSL_FREE(ctx->pKeyAlias);
        }

        ctx->pKeyAlias = OSSL_MALLOC(aliasStringLength + 1);

        if (ctx->pKeyAlias != NULL)
        {
            snprintf((char *) ctx->pKeyAlias, aliasStringLength + 1, "%s%d", aliasString, ctx->ossl_pkey_idx);
            ctx->keyAliasLength = aliasStringLength;
        }

        if (0 > ossl_CERT_STORE_addGenericIdentity(ctx, ctx->privatekey[i]))
        {
            return 0;
        }
    }

    return (1);
}

#ifdef __ENABLE_DIGICERT_TPM__
extern sbyte4
OSSL_KeyAssociateTapContext(MOCTAP_HANDLE mh, SSL_CTX *ctx)
{
    MSTATUS status;
    if(ctx == NULL)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    status = NSSL_CHK_CALL(keyAssociateTapContext, mh, ctx->pCertStore);

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_TPM__ */


int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    return (ssl_set_cert(ctx, x));
}

static void
ossl_ctx_clear_chain_certs(SSL_CTX *ctx)
{
     int	i;
     X509     * x;

     for (i = 0; i < ctx->cert_x509_list.count; ++i) {
	  x = ctx->cert_x509_list.certs[i];
	  X509_free(x);
	  ctx->cert_x509_list.certs[i] = NULL;
     }
     ctx->cert_x509_list.count = 0;
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == X509_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == X509_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
#if defined(__ENABLE_DIGICERT_OSSL_FORCE_CERT_CHAIN__)
        x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
#else
        x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
#endif
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);

    /* If certificate is loaded successfully clear the errors */
    if (1 == ret)
    {
        ERR_clear_error();
    }

#if defined(__ENABLE_DIGICERT_OSSL_FORCE_CERT_CHAIN__)
    if (ERR_peek_error() != 0)
        ret = 0;                /* Key/certificate mismatch doesn't imply
                                 * ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to the CA
         * certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        ossl_ctx_clear_chain_certs(ctx);

        while ((ca = PEM_read_bio_X509(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata))
               != NULL) {
            r = SSL_CTX_add0_chain_cert(ctx, ca);
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
            /*
             * Note that we must not free r if it was successfully added to
             * the chain (while we must free the main certificate, since its
             * reference count is increased by SSL_CTX_use_certificate).
             */
        }
        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM
            && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0;            /* some real error */
    }
#endif

end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}

/*
 * This is NOT the function that MOD_SSL calls to configure the Server Cert
 * chain ! The function to do that is SSL_CTX_ctrl():SSL_CTRL_EXTRA_CHAIN_CERT
 * MOD_SSL calls SSL_CTX_use_certificate_file() above to set the public key
 * The MOD_SSL function ssl_init_server_certs() has calls to both _file() and
 * _chain_file() but I think the condition to call the latter is never hit
 */
MOC_EXTERN int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
     BIO *in;
     int ret = 0;
     X509 *x = NULL;

     ERR_clear_error();          /* clear error stack for
				  * SSL_CTX_use_certificate() */

     in = BIO_new(BIO_s_file_internal());
     if (in == NULL) {
	  SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
	  goto end;
     }

     if (BIO_read_filename(in, file) <= 0) {
	  SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
	  goto end;
     }

     x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback,
			       ctx->default_passwd_callback_userdata);
     if (x == NULL) {
	  SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
	  goto end;
     }

     ret = SSL_CTX_use_certificate(ctx, x);

     if (ERR_peek_error() != 0)
	  ret = 0;                /* Key/certificate mismatch doesn't imply
				   * ret==0 ... */
     if (ret) {
	  /*
	   * If we could set up our certificate, now proceed to the CA
	   * certificates.
	   */
	  X509 	      * ca;
	  int 		r=0;
	  unsigned long err;

	  ossl_ctx_clear_chain_certs(ctx);

	  while ((ca = PEM_read_bio_X509(in, NULL,
					 ctx->default_passwd_callback,
					 ctx->default_passwd_callback_userdata))
		 != NULL) {
	       r = SSL_CTX_add0_chain_cert(ctx, ca);
	       if (!r) {
	            X509_free(ca);
	            ret = 0;
	            goto end;
	       }
	       /*
	        * Note that we must not free r if it was successfully added to
	        * the chain (while we must free the main certificate, since its
	        * reference count is increased by SSL_CTX_use_certificate).
	        */     
	  }
	  /* When the while loop ends, it's usually just EOF. */
	  err = ERR_peek_last_error();
	  if (ERR_GET_LIB(err) == ERR_LIB_PEM
	      && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
	       ERR_clear_error();
	  else
	       ret = 0;            /* some real error */
     }
end:
    if (x != NULL)
        X509_free(x);

     if (in != NULL)
	  BIO_free(in);
     return (ret);
}

extern int
SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
     int	i;
     int    ret = 0;
     if (!ctx || !pkey)
	  return 0;
     i = ctx->ossl_pkey_idx;
     if (OSSL_PKEY_MAX == i)
     {
        ctx->privateKeyPending = 1;
     }

     if (ctx->privatekey[i])
     {
        EVP_PKEY_free(ctx->privatekey[i]);
        ctx->privatekey[i] = NULL;
     }

    ctx->privatekey[i] = pkey;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    EVP_PKEY_up_ref(pkey);
#else
    CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif
    if (0 == ctx->privateKeyPending)
    {
        if (ctx->pKeyAlias != NULL)
        {
            OSSL_FREE(ctx->pKeyAlias);
        }

        ctx->pKeyAlias = OSSL_MALLOC(aliasStringLength + 1);

        if (ctx->pKeyAlias != NULL)
        {
            snprintf((char *) ctx->pKeyAlias, aliasStringLength + 1, "%s%d", aliasString, ctx->ossl_pkey_idx);
            ctx->keyAliasLength = aliasStringLength;
        }

        ret = ossl_CERT_STORE_addGenericIdentity(ctx, pkey);
    }

    if (ret < 0 ) {
        return 0;
    }
    return 1;
}


EVP_PKEY *ssl_get_evp_pkey_from_file(SSL_CTX *ctx, const char *file, int type)
{
    int j;
    EVP_PKEY *pkey = NULL;
    BIO *in;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto exit;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto exit;
    }
    if (type == X509_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)
        pkey = DIGI_PEM_read_bio_PrivateKey(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata);
#else
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata);
#endif
    } else if (type == X509_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto exit;
    }
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        goto exit;
    }

exit:
    if (in != NULL)
        BIO_free(in);
    return pkey;
}

/* RGK: I cut-n-pasted function SSL_CTX_use_PrivateKey_file() from ssl_rsa.c
 * and added the "_ex" suffix to it so it can be called from ossl_ssl.c that
 * defines SSL_CTX_use_PrivateKey_file()
 */
int SSL_CTX_use_PrivateKey_file_ex(SSL_CTX *ctx, const char *file, int type)
{
    int ret = 0;
    EVP_PKEY *pkey;

    pkey = ssl_get_evp_pkey_from_file(ctx, file, type);
    if (NULL == pkey)
        goto end;

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);

 end:
    return (ret);
}

/*------------------------------------------------------------------*/

static MSTATUS LoadKeyFromDSATemplate(DSA *pKey, MDsaKeyTemplate *pTemplate)
{
    MSTATUS status;

    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pTemplate) )
        goto exit;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (NULL != pTemplate->pP)
        pKey->params.p = BN_bin2bn(pTemplate->pP, pTemplate->pLen, NULL);
    else
        pKey->params.p = NULL;

    if (NULL != pTemplate->pQ)
        pKey->params.q = BN_bin2bn(pTemplate->pQ, pTemplate->qLen, NULL);
    else
        pKey->params.q = NULL;

    if (NULL != pTemplate->pG)
        pKey->params.g = BN_bin2bn(pTemplate->pG, pTemplate->gLen, NULL);
    else
        pKey->params.g = NULL;
#else
    if (NULL != pTemplate->pP)
        pKey->p = BN_bin2bn(pTemplate->pP, pTemplate->pLen, NULL);
    else
        pKey->p = NULL;

    if (NULL != pTemplate->pQ)
        pKey->q = BN_bin2bn(pTemplate->pQ, pTemplate->qLen, NULL);
    else
        pKey->q = NULL;

    if (NULL != pTemplate->pG)
        pKey->g = BN_bin2bn(pTemplate->pG, pTemplate->gLen, NULL);
    else
        pKey->g = NULL;
#endif

    if (NULL != pTemplate->pY)
        pKey->pub_key = BN_bin2bn(pTemplate->pY, pTemplate->yLen, NULL);
    else
        pKey->pub_key = NULL;

    if (NULL != pTemplate->pX)
        pKey->priv_key = BN_bin2bn(pTemplate->pX, pTemplate->xLen, NULL);
    else
        pKey->priv_key = NULL;

    status = OK;

exit:
    return status;

}

static MSTATUS LoadKeyFromTemplate(
    RSA *pKey,
    MRsaKeyTemplate *pTemplate
    )
{
    MSTATUS status;
    BIGNUM *pR0 = NULL, *pR1 = NULL, *pR2 = NULL;
    BN_CTX *pCtx = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pTemplate) )
        goto exit;

    status = ERR_RSA_INVALID_KEY;

    if (NULL != pTemplate->pE)
        pKey->e = BN_bin2bn(pTemplate->pE, pTemplate->eLen, NULL);
    else
        pKey->e = NULL;

    if (NULL != pTemplate->pN)
        pKey->n = BN_bin2bn(pTemplate->pN, pTemplate->nLen, NULL);
    else
        pKey->n = NULL;

    if (NULL != pTemplate->pP)
        pKey->p = BN_bin2bn(pTemplate->pP, pTemplate->pLen, NULL);
    else
        pKey->p = NULL;

    if (NULL != pTemplate->pQ)
        pKey->q = BN_bin2bn(pTemplate->pQ, pTemplate->qLen, NULL);
    else
        pKey->q = NULL;

    if (NULL != pTemplate->pDp)
        pKey->dmp1 = BN_bin2bn(pTemplate->pDp, pTemplate->dpLen, NULL);
    else
        pKey->dmp1 = NULL;

    if (NULL != pTemplate->pDq)
        pKey->dmq1 = BN_bin2bn(pTemplate->pDq, pTemplate->dqLen, NULL);
    else
        pKey->dmq1 = NULL;

    if (NULL != pTemplate->pQinv)
        pKey->iqmp = BN_bin2bn(pTemplate->pQinv, pTemplate->qInvLen, NULL);
    else
        pKey->iqmp = NULL;

    if (NULL != pTemplate->pD)
    {
        pKey->d = BN_bin2bn(pTemplate->pD, pTemplate->dLen, NULL);
    }
    else
    {
        pCtx = BN_CTX_new();
        if (NULL == pCtx)
        {
            goto exit;
        }

        BN_CTX_start(pCtx);

        pR0 = BN_CTX_get(pCtx);
        pR1 = BN_CTX_get(pCtx);
        pR2 = BN_CTX_get(pCtx);

        if (!BN_sub(pR1, pKey->p, BN_value_one()))
            goto exit;

        if (!BN_sub(pR2, pKey->q, BN_value_one()))
            goto exit;

        if (!BN_mul(pR0, pR1, pR2, pCtx))
            goto exit;

        if (!BN_mod_inverse(pKey->d, pKey->e, pR0, pCtx))
            goto exit;
    }

    status = OK;

exit:

    if (NULL != pCtx)
    {
        BN_CTX_end(pCtx);
        BN_CTX_free(pCtx);
    }

    return status;
}

#ifdef __RTOS_WIN32__
static TCHAR
WIN32_getch()
{
    DWORD mode, cc;
    TCHAR c = 0;
    HANDLE h = GetStdHandle (STD_INPUT_HANDLE);

    if (h == NULL)
    {
        return 0; /* Error */
    }
    GetConsoleMode (h, &mode);
    SetConsoleMode (h, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));

    ReadConsole (h, &c, 1, &cc, NULL);

    SetConsoleMode  (h, mode);
    return c;
}

static MSTATUS getPassword(
    void *pCallbackInfo,
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    ubyte4 i;
    int c = 0;

    printf ("Enter PEM pass phrase : ");

    i = 0;
    do
    {
        c = WIN32_getch();

        switch (c)
        {
            case 0x00:
                break;

            case 0x08:          /* backspace */
                if (i > 1)
                    --i;
                break;

            case 0x0D:
                break;

            default:
                if (c >= 20)
                {
                    if (i < bufferLen)
                    {
                        pBuffer[i++] = c;
                    }
                }
                break;
        }
    } while (c != 0x0D);

    printf("\n");

    *pOutLen = i;

    return OK;
}

#endif

#if defined( __RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_IRIX__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_ANDROID__) || defined(__RTOS_FREEBSD__) || defined(__RTOS_OSX__)

static MSTATUS getEnteredPassword(char *pBuffer, ubyte4 bufferLen) 
{
    MSTATUS status = OK;
    int c;
    ubyte4 pos = 0;
    struct termios term;

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);

	while ((c=fgetc(stdin)) != '\n') 
    {
		pBuffer[pos++] = (char) c;
		if (pos >= bufferLen)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }		
	}
	pBuffer[pos] = '\0';

exit:
	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);
    return status;
}

static MSTATUS getPassword(
    void *pCallbackInfo,
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    MSTATUS status;
    sbyte pPassword[MAX_PASSWORD_SIZE + 1] = {0};
    ubyte4 passwordLen = 0;

    if (NULL == pBuffer)
        return ERR_NULL_POINTER;

    *pOutLen = 0;

#ifdef __RTOS_ANDROID__
    status = ERR_INVALID_INPUT;
#else
    printf("Enter PEM pass phrase : ");
    status = getEnteredPassword(pPassword, MAX_PASSWORD_SIZE + 1);
    printf("\n");
#endif
    if (OK != status)
        goto exit;

    passwordLen = strlen((const char *)pPassword);
    if (passwordLen > bufferLen)
        passwordLen = bufferLen;

    memcpy(pBuffer, pPassword, passwordLen);

    status = OK;
    *pOutLen = passwordLen;

exit:

    memset(pPassword, 0, MAX_PASSWORD_SIZE + 1);

    return status;
}

#endif

#ifdef __ENABLE_DIGICERT_ECC__

static MSTATUS LoadEccKey(
    EC_KEY *eckey,
    AsymmetricKey *pAsymKey
    )
{
    MSTATUS status;
    int osslStatus;
    EC_POINT *pPubPoint = NULL;
    BIGNUM *pPriScalar = NULL;
    MEccKeyTemplate *pTemplate = NULL;

    if ( (NULL == eckey) || (NULL == pAsymKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Retrieve the EC key data. If the key is a public key then only
        * the public portion will be loaded. If the key is a private key
        * then both the private and public portion will be loaded.
        */
    status = NSSL_CHK_CALL(
        extractEcKeyData, pAsymKey, &pTemplate);
    if (OK != status)
        goto exit;

    status = ERR_EC;

    /* Create a public point.
        */
    pPubPoint = EC_POINT_new(EC_KEY_get0_group(eckey));
    if (NULL == pPubPoint)
        goto exit;

    /* Load the public point from the template into the EC_POINT object.
        */
    osslStatus = EC_POINT_oct2point(
        EC_KEY_get0_group(eckey), pPubPoint, pTemplate->pPublicKey,
        pTemplate->publicKeyLen, NULL);
    if (1 != osslStatus)
        goto exit;

    /* Load the public point into the key object.
        */
    osslStatus = EC_KEY_set_public_key(eckey, pPubPoint);
    if (1 != osslStatus)
        goto exit;

    /* Free the public point.
        */
    EC_POINT_free(pPubPoint);

    /* If there is a private key value then load that in.
        */
    if (NULL != pTemplate->pPrivateKey)
    {
        pPriScalar = BN_bin2bn(
            pTemplate->pPrivateKey, pTemplate->privateKeyLen, NULL);
        if (NULL == pPriScalar)
            goto exit;

        osslStatus = EC_KEY_set_private_key(eckey, pPriScalar);
        if (1 != osslStatus)
            goto exit;
    }

    status = OK;

exit:

    if (NULL != pPriScalar)
    {
        /* Clear the private value then free it.
         */
        BN_clear_free(pPriScalar);
    }

    NSSL_CHK_CALL(freeEcKeyData, NULL, &pTemplate);

    return status;
}


#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static MSTATUS LoadECXKey(ECX_KEY *pECXKey, AsymmetricKey *pAsymKey)
{
    MSTATUS status;
    MEccKeyTemplate *pTemplate = NULL;

    status = NSSL_CHK_CALL(extractEcKeyData, pAsymKey, &pTemplate);
    if (OK != status)
        goto exit;

    if ((NULL == pECXKey) || (NULL == pAsymKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pTemplate->publicKeyLen > 0)
    {
        memcpy(pECXKey->pubkey, pTemplate->pPublicKey, pTemplate->publicKeyLen);
    }

    if (pTemplate->privateKeyLen > 0)
    {
        pECXKey->privkey = OPENSSL_secure_malloc(pTemplate->privateKeyLen);
        if (NULL == pECXKey->privkey)
            goto exit;

        memcpy(pECXKey->privkey, pTemplate->pPrivateKey, pTemplate->privateKeyLen);
    }

exit:
    NSSL_CHK_CALL(freeEcKeyData, NULL, &pTemplate);

    return status;
}
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
/*-----------------------------------------------------------------*/
static MSTATUS moc_get_asymmetric_key_from_pem(AsymmetricKey *pAsymKey,
                                               const char *key_id,
                                               OSSL_KeyBlobInfo **ppKeyBlobInfo,
                                               pemPasswordInfo *pPasswordInfo)
{
    /* Read PEM file and convert to keyblob */
    ubyte4 contentsLen;
    ubyte *pContents = NULL;
    MSTATUS status = -1;
    OSSL_KeyBlobInfo *pKeyBlobInfo = NULL;

    if (!ppKeyBlobInfo)
    {
        goto exit;
    }

    pKeyBlobInfo = (OSSL_KeyBlobInfo *)OSSL_MALLOC(sizeof(OSSL_KeyBlobInfo));
    if (NULL == pKeyBlobInfo)
    {
        goto exit;
    }

    pKeyBlobInfo->pKeyBlob = NULL;
    pKeyBlobInfo->keyBlobLength = 0;
    pKeyBlobInfo->type = akt_undefined;

    /*
     * If the given key is Mocana custom Key which ends with .dat
     * then directly deserialize the Key.
     */

    if (OK > (status = NSSL_CHK_CALL(
        readFile, (const char *)key_id, &pContents, &contentsLen)))
    {
        goto exit;
    }

    if(!pContents)
    {
        status = -1;
        goto exit;
    }

    if(ends_with_extension(key_id, "pem", 3) == 1 ||
       ends_with_extension(key_id, "PEM", 3) == 1)
    {
        status = NSSL_CHK_CALL(decryptPKCS8PemKey, pContents, contentsLen, &pAsymKey, pPasswordInfo, TRUE);
        if (OK <= status)
        {
            goto makekeyblob;
        }

    }
#if defined(__ENABLE_DIGICERT_TAP__)
    status = NSSL_CHK_CALL(deserializeAsymKey, pContents, contentsLen, pAsymKey);

    if (OK == status)
    {
        status = NSSL_CHK_CALL(serializeAsymKeyAlloc, pAsymKey,
            &(pKeyBlobInfo->pKeyBlob), &(pKeyBlobInfo->keyBlobLength));
        if (OK > status)
        {
            goto exit;
        }

        *ppKeyBlobInfo = pKeyBlobInfo;
    }
    else
#endif /* __ENABLE_DIGICERT_TAP__ */
    {
        if (OK > (status = NSSL_CHK_CALL(deserializeKey, pContents,
                                         contentsLen, pAsymKey)))
        {
            goto exit;
        }

makekeyblob:
        status = NSSL_CHK_CALL(makeKeyBlobEx, pAsymKey, &(pKeyBlobInfo->pKeyBlob), &(pKeyBlobInfo->keyBlobLength));

        if (OK > status)
        {
            goto exit;
        }
        *ppKeyBlobInfo = pKeyBlobInfo;
    }
exit:

    if (pContents)
    {
        OSSL_FREE((void *) pContents);
        pContents = NULL;
    }

    if (OK > status && pKeyBlobInfo)
    {
        OSSL_FREE(pKeyBlobInfo);
        pKeyBlobInfo = NULL;
    }
    return status;
}

/*-----------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static EVP_PKEY *EVP_PKEY_moc_load_from_pem_file(SSL_CTX *ctx, const char *file, int type,
                                                 pemPasswordInfo *pPasswordInfo)
{
    EVP_PKEY *pKey = NULL;
    RSA *rsa = NULL;
    DSA *dsa = NULL;
    AsymmetricKey asymKey = {0};
    MSTATUS status;
    OSSL_KeyBlobInfo *pKeyBlobInfo = NULL; /* only used for the blob and length */
#if (defined(__ENABLE_DIGICERT_ECC__))
    EC_KEY *eckey = NULL;
    int curveName;
    ubyte4 curveId;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
    ECX_KEY *pECXKey = NULL;
    int ecxKeyType   = 0;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
#endif

    status = NSSL_CHK_CALL(initAsymmetricKey, &asymKey);
    if (status)
    {
        SSLerr(SSL_ERROR_SSL, ERR_R_MALLOC_FAILURE);
        goto exit1;
    }

    /* if successful, certBlobAndLength will be allocated inside the function */
    status = moc_get_asymmetric_key_from_pem(&asymKey, file, &pKeyBlobInfo, pPasswordInfo);
    if (0 <= status)
    {
        /* RSA[current support, EC and DSA will be handled through OpenSSL BIO APIs.]
           Key de serialized
        initialise with default values and
         MOC_EVP_KEY_DATA in extra_data in OpenSSL Key Structure */
        if (NULL == (pKey = EVP_PKEY_new()))
        {
            goto exit;
        }

        switch (asymKey.type)
        {
            case akt_dsa:
            {
                MDsaKeyTemplate template = { 0 };
                pKey->type = EVP_PKEY_DSA;

                if (NULL == (dsa = DSA_new()))
                {
                    goto exit;
                }

                if (MOC_OSSL_INVALID_EX_DATA == dsaExAppDataIndex)
                {
                    dsaExAppDataIndex = DSA_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);

                    /* If an invalid index was returned then default to the
                     * 0th index.
                     */
                    if (MOC_OSSL_INVALID_EX_DATA == dsaExAppDataIndex)
                    {
                        dsaExAppDataIndex = 0;
                    }
                }

                if (pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
                    pKeyBlobInfo->keyBlobLength > 0)
                {
                    DSA_set_ex_data(dsa, dsaExAppDataIndex, (void *) pKeyBlobInfo);
                }
                else
                {
                    goto exit;
                }

                if (OK > (status = NSSL_CHK_CALL(extractDsaKeyData, &asymKey,
                                                 &template, MOC_GET_PRIVATE_KEY_DATA)))
                {
                    goto exit;
                }

                if (OK > (status = LoadKeyFromDSATemplate(dsa, &template)))
                {
                    goto exit;
                }

                NSSL_CHK_CALL(freeDsaKeyTemplate, &asymKey, &template);

                pKey->type = EVP_PKEY_DSA;
                pKey->pkey.dsa = dsa;
                EVP_PKEY_assign_DSA(pKey, dsa);
                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);
                return pKey;
            }

            case akt_rsa:
            case akt_tap_rsa:
                rsa = RSA_new();
                if (NULL == rsa)
                    goto exit;

                if (MOC_OSSL_INVALID_EX_DATA == rsaExAppDataIndex)
                {
                    rsaExAppDataIndex = RSA_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);

                    /* If an invalid index was returned then default to the
                     * 0th index.
                     */
                    if (MOC_OSSL_INVALID_EX_DATA == rsaExAppDataIndex)
                    {
                        rsaExAppDataIndex = 0;
                    }
                }
                if (pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
                    pKeyBlobInfo->keyBlobLength > 0)
                {
                    RSA_set_ex_data(rsa, rsaExAppDataIndex, (void *)pKeyBlobInfo);
                }
                else
                {
                    goto exit;
                }

                if (asymKey.type != akt_tap_rsa)
                {
                    MRsaKeyTemplate template = { 0 };
                    status = NSSL_CHK_CALL(
                        extractRsaKeyData, &asymKey, &template,
                        MOC_GET_PRIVATE_KEY_DATA);
                    if (OK != status)
                        goto exit;

                    status = LoadKeyFromTemplate(rsa, &template);
                    NSSL_CHK_CALL(freeRsaKeyTemplate, &asymKey, &template);
                    if (OK != status)
                        goto exit;
                }

                pKey->type = EVP_PKEY_RSA;
                pKey->pkey.rsa = rsa;
                EVP_PKEY_assign_RSA(pKey, rsa);

                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);

                return pKey;

#ifdef __ENABLE_DIGICERT_ECC__
            case akt_ecc:
            case akt_tap_ecc:

                status = NSSL_CHK_CALL(getEcCurveId, &asymKey, &curveId);
                if (OK != status)
                    goto exit;

                switch (curveId)
                {
                    case cid_EC_P192:
                        curveName = NID_X9_62_prime192v1;
                        break;

                    case cid_EC_P224:
                        curveName = NID_secp224r1;
                        break;

                    case cid_EC_P256:
                        curveName = NID_X9_62_prime256v1;
                        break;

                    case cid_EC_P384:
                        curveName = NID_secp384r1;
                        break;

                    case cid_EC_P521:
                        curveName = NID_secp521r1;
                        break;

                    default:
                        goto exit;
                }

                eckey = EC_KEY_new_by_curve_name(curveName);
                if (NULL == eckey)
                    goto exit;

                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

                if (MOC_OSSL_INVALID_EX_DATA == eccExAppDataIndex)
                {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
                    eccExAppDataIndex = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);
#else
                    eccExAppDataIndex = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

                    /* If an invalid index was returned then default to the
                     * 0th index.
                     */
                    if (MOC_OSSL_INVALID_EX_DATA == eccExAppDataIndex)
                    {
                        eccExAppDataIndex = 0;
                    }
                }

                if (pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
                    pKeyBlobInfo->keyBlobLength > 0)
                {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
                    EC_KEY_set_ex_data(eckey, eccExAppDataIndex, (void *)pKeyBlobInfo);
#else
                    ECDSA_set_ex_data(eckey, eccExAppDataIndex, (void *)pKeyBlobInfo);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
                }
                else
                {
                    goto exit;
                }

                if (asymKey.type != akt_tap_ecc)
                {
                    status = LoadEccKey(eckey, &asymKey);
                    if (OK != status)
                        goto exit;
                }

                pKey->type = EVP_PKEY_EC;
                pKey->pkey.ec = eckey;
                EVP_PKEY_assign_EC_KEY(pKey, eckey);

                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);
                return pKey;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
            case akt_ecc_ed:
                status = NSSL_CHK_CALL(getEcCurveId, &asymKey, &curveId);
                if (OK != status)
                    goto exit;

                switch (curveId)
                {
                    case cid_EC_Ed25519:
                        ecxKeyType = EVP_PKEY_ED25519;
                        break;
                    case cid_EC_Ed448:
                        ecxKeyType = EVP_PKEY_ED448;
                        break;
                    default:
                        goto exit;
                }

                pECXKey = OPENSSL_zalloc(sizeof(ECX_KEY));
                if (NULL == pECXKey)
                    goto exit;

                status = LoadECXKey(pECXKey, &asymKey);
                if (OK != status)
                    goto exit;

                EVP_PKEY_assign(pKey, ecxKeyType, pECXKey);

                /* This pKeyBlobInfo is not stored in extended Data. There is not ex data for ECX_KEY.
                 * So free the pKeyBlobInfo
                 */
                if (pKeyBlobInfo)
                {
                    DIGI_PKEY_EX_DATA_free(NULL, pKeyBlobInfo, NULL, 0, 0, NULL);
                }

                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);

                return pKey;

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
#if defined(__ENABLE_ALL_DEBUGGING__)
            default:
                PRINT("Unknown asymKey.type 0x%x\n", asymKey.type);
#endif
        } /* end switch */
    }

exit:
    if (!(pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
          pKeyBlobInfo->keyBlobLength > 0))
    {
        NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);
    }

    if(pKey != NULL)
    {
        EVP_PKEY_free(pKey);
    }
    if(rsa != NULL)
    {
        RSA_free(rsa);
    }
#if (defined(__ENABLE_DIGICERT_ECC__))
    if (NULL != eckey)
    {
        EC_KEY_free(eckey);
    }
#endif

exit1:
    return NULL;
}
#endif

#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)

static MSTATUS moc_get_asymmetric_key_from_pem_buf(
    AsymmetricKey *pAsymKey,
    const ubyte *key_id,
    ubyte4 contentsLen,
    OSSL_KeyBlobInfo **ppKeyBlobInfo,
    pemPasswordInfo *pPasswordInfo
    )
{
    /* Read PEM file and convert to keyblob */
    ubyte *pContents = NULL;
    MSTATUS status = -1;
    OSSL_KeyBlobInfo *pKeyBlobInfo = NULL;

    if (!ppKeyBlobInfo)
    {
        goto exit;
    }

    pKeyBlobInfo = (OSSL_KeyBlobInfo *)OSSL_MALLOC(sizeof(OSSL_KeyBlobInfo));
    if (NULL == pKeyBlobInfo)
    {
        goto exit;
    }

    pKeyBlobInfo->pKeyBlob = NULL;
    pKeyBlobInfo->keyBlobLength = 0;
    pKeyBlobInfo->type = akt_undefined;

    /*
     * If the given key is Mocana custom Key which ends with .dat
     * then directly deserialize the Key.
     */

    pContents = (ubyte *)key_id;
    if(!pContents || !contentsLen)
    {
        status = -1;
        goto exit;
    }

    status = NSSL_CHK_CALL(decryptPKCS8PemKey, pContents, contentsLen, &pAsymKey, pPasswordInfo, FALSE);
    if (OK == status)
        goto makekeyblob;

#if defined(__ENABLE_DIGICERT_TAP__)
    status = NSSL_CHK_CALL(deserializeAsymKey, pContents, contentsLen, pAsymKey);

    if (OK == status)
    {
        status = NSSL_CHK_CALL(serializeAsymKeyAlloc, pAsymKey,
            &(pKeyBlobInfo->pKeyBlob), &(pKeyBlobInfo->keyBlobLength));
        if (OK > status)
        {
            goto exit;
        }

        *ppKeyBlobInfo = pKeyBlobInfo;
    }
    else
#endif /* __ENABLE_DIGICERT_TAP__ */
    {
        if (OK > (status = NSSL_CHK_CALL(deserializeKey, pContents,
                                         contentsLen, pAsymKey)))
        {
            goto exit;
        }

makekeyblob:
        status = NSSL_CHK_CALL(makeKeyBlobEx, pAsymKey, &(pKeyBlobInfo->pKeyBlob), &(pKeyBlobInfo->keyBlobLength));

        if (OK > status)
        {
            goto exit;
        }
        *ppKeyBlobInfo = pKeyBlobInfo;
    }
exit:
    if (OK > status && pKeyBlobInfo)
    {
        OSSL_FREE(pKeyBlobInfo);
        pKeyBlobInfo = NULL;
    }
    return status;
}


static EVP_PKEY *EVP_PKEY_moc_load_from_pem_buf(
    const ubyte *buf,
    ubyte4 bufLen,
    int type,
    pemPasswordInfo *pPasswordInfo
    )
{
    EVP_PKEY *pKey = NULL;
    RSA *rsa = NULL;
    AsymmetricKey asymKey = {0};
    MSTATUS status;
    BN_CTX *ctx = NULL;
    OSSL_KeyBlobInfo *pKeyBlobInfo = NULL; /* only used for the blob and length */
#if (defined(__ENABLE_DIGICERT_ECC__))
    EC_KEY *eckey = NULL;
    int curveName;
    ubyte4 curveId;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ECX_KEY *pECXKey = NULL;
    int ecxKeyType   = 0;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif
    MRsaKeyTemplate template = { 0 };
    status = NSSL_CHK_CALL(initAsymmetricKey, &asymKey);
    if (status)
    {
        SSLerr(SSL_ERROR_SSL, ERR_R_MALLOC_FAILURE);
        goto exit1;
    }

    /* if successful, certBlobAndLength will be allocated inside the function */
    status = moc_get_asymmetric_key_from_pem_buf(&asymKey, buf, bufLen, &pKeyBlobInfo, pPasswordInfo);
    if (0 <= status)
    {
        /* RSA[current support, EC and DSA will be handled through OpenSSL BIO APIs.]
           Key de serialized
        initialise with default values and
         MOC_EVP_KEY_DATA in extra_data in OpenSSL Key Structure */

       if (NULL == (pKey = EVP_PKEY_new()))
        {
            goto exit;
        }

        switch (asymKey.type)
        {
            case akt_rsa:
            case akt_tap_rsa:

                rsa = RSA_new();
                if (NULL == rsa)
                    goto exit;

                if (MOC_OSSL_INVALID_EX_DATA == rsaExAppDataIndex)
                {
                    rsaExAppDataIndex = RSA_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);

                    /* If an invalid index was returned then default to the
                     * 0th index.
                     */
                    if (MOC_OSSL_INVALID_EX_DATA == rsaExAppDataIndex)
                    {
                        rsaExAppDataIndex = 0;
                    }
                }

                if (pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
                    pKeyBlobInfo->keyBlobLength > 0)
                {
                    RSA_set_ex_data(rsa, rsaExAppDataIndex, (void *)pKeyBlobInfo);
                }
                else
                {
                    goto exit;
                }

                if (asymKey.type != akt_tap_rsa)
                {
                    status = NSSL_CHK_CALL(
                        extractRsaKeyData, &asymKey, &template,
                        MOC_GET_PRIVATE_KEY_DATA);
                    if (OK != status)
                        goto exit;

                    status = LoadKeyFromTemplate(rsa, &template);
                    NSSL_CHK_CALL(freeRsaKeyTemplate, &asymKey, &template);
                    if (OK != status)
                        goto exit;
                }

                pKey->type = EVP_PKEY_RSA;
                pKey->pkey.rsa = rsa;
                EVP_PKEY_assign_RSA(pKey, rsa);

                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);

                return pKey;

#ifdef __ENABLE_DIGICERT_ECC__
            case akt_ecc:
            case akt_tap_ecc:

                status = NSSL_CHK_CALL(getEcCurveId, &asymKey, &curveId);
                if (OK != status)
                    goto exit;

                switch (curveId)
                {
                    case cid_EC_P192:
                        curveName = NID_X9_62_prime192v1;
                        break;

                    case cid_EC_P224:
                        curveName = NID_secp224r1;
                        break;

                    case cid_EC_P256:
                        curveName = NID_X9_62_prime256v1;
                        break;

                    case cid_EC_P384:
                        curveName = NID_secp384r1;
                        break;

                    case cid_EC_P521:
                        curveName = NID_secp521r1;
                        break;

                    default:
                        goto exit;
                }

                eckey = EC_KEY_new_by_curve_name(curveName);
                if (NULL == eckey)
                    goto exit;

                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

                if (MOC_OSSL_INVALID_EX_DATA == eccExAppDataIndex)
                {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
                    eccExAppDataIndex = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);
#else
                    eccExAppDataIndex = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, DIGI_PKEY_EX_DATA_free);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

                    /* If an invalid index was returned then default to the
                     * 0th index.
                     */
                    if (MOC_OSSL_INVALID_EX_DATA == eccExAppDataIndex)
                    {
                        eccExAppDataIndex = 0;
                    }
                }

                if (pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
                    pKeyBlobInfo->keyBlobLength > 0)
                {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
                    EC_KEY_set_ex_data(eckey, eccExAppDataIndex, (void *)pKeyBlobInfo);
#else
                    ECDSA_set_ex_data(eckey, eccExAppDataIndex, (void *)pKeyBlobInfo);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
                }
                else
                {
                    goto exit;
                }

                if (asymKey.type != akt_tap_ecc)
                {
                    status = LoadEccKey(eckey, &asymKey);
                    if (OK != status)
                        goto exit;
                }

                pKey->type = EVP_PKEY_EC;
                pKey->pkey.ec = eckey;
                EVP_PKEY_assign_EC_KEY(pKey, eckey);

                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);

                return pKey;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
            case akt_ecc_ed:
                status = NSSL_CHK_CALL(getEcCurveId, &asymKey, &curveId);
                if (OK != status)
                    goto exit;

                switch (curveId)
                {
                    case cid_EC_Ed25519:
                        ecxKeyType = EVP_PKEY_ED25519;
                        break;
                    case cid_EC_Ed448:
                        ecxKeyType = EVP_PKEY_ED448;
                        break;
                    default:
                        goto exit;
                }

                pECXKey = OPENSSL_zalloc(sizeof(ECX_KEY));
                if (NULL == pECXKey)
                    goto exit;

                status = LoadECXKey(pECXKey, &asymKey);
                if (OK != status)
                    goto exit;

                EVP_PKEY_assign(pKey, ecxKeyType, pECXKey);

                /* This pKeyBlobInfo is not stored in extended Data. There is not ex data for ECX_KEY.
                 * So free the pKeyBlobInfo
                 */
                if (pKeyBlobInfo)
                {
                    DIGI_PKEY_EX_DATA_free(NULL, pKeyBlobInfo, NULL, 0, 0, NULL);
                }

                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);

                return pKey;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
#if defined(__ENABLE_ALL_DEBUGGING__)
            default:
                PRINT("Unknown asymKey.type 0x%x\n", asymKey.type);
#endif
        } /* end switch */
    }

exit:
    if (!(pKeyBlobInfo && pKeyBlobInfo->pKeyBlob &&
          pKeyBlobInfo->keyBlobLength > 0))
    {
        NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);
    }

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
#endif
    if(pKey != NULL)
    {
        EVP_PKEY_free(pKey);
    }
    if(rsa != NULL)
    {
        RSA_free(rsa);
    }
#if (defined(__ENABLE_DIGICERT_ECC__))
    if (eckey != NULL)
    {
        EC_KEY_free(eckey);
    }
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
    if (pECXKey != NULL)
    {
        OPENSSL_free(pECXKey);
    }
#endif
#endif

exit1:
    return NULL;
}

#endif /* __ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__ */

static MSTATUS OSSL_pemUserPasswordCallback(
    void *pCallbackInfo,
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    MSTATUS status;
    sbyte4 passwordLen;

    OSSL_PemPasswordCallback *pInfo = pCallbackInfo;

    *pOutLen = 0;

    /* Call the user provided callback.
     */
    passwordLen = (sbyte4) pInfo->pCallback(
        (char *) pBuffer, (int) bufferLen, 0, pInfo->pCallbackInfo);

    /* If the length is invalid then return an error. OpenSSL performs the
     * check against 0, however it does not perform the check against the max
     * buffer size. That check is added just in case, if it breaks anything
     * feel free to remove it.
     */
    status = ERR_BAD_LENGTH;
    if ( (0 > passwordLen) || ((sbyte4) bufferLen < passwordLen) )
        goto exit;

    /* If no error occured then set the output length.
     */
    *pOutLen = (ubyte4) passwordLen;

    status = OK;

exit:

    return status;
}

#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)

static EVP_PKEY *DIGI_PEM_read_bio_PrivateKey(
    BIO *pBio,
    EVP_PKEY **ppRetEvpPkey,
    pem_password_cb *pPasswordCallback,
    void *pPasswordCallbackInfo
    )
{
    EVP_CIPHER_INFO cipherInfo;
    char *pHeader = NULL, *pName = NULL;
    unsigned char *pData = NULL;
    long dataLen;

    OSSL_PemPasswordCallback osslPasswordInfo;
    pemPasswordInfo passwordInfo;

    EVP_PKEY *pRetKey = NULL;

    osslPasswordInfo.pCallback = pPasswordCallback;
    osslPasswordInfo.pCallbackInfo = pPasswordCallbackInfo;

    passwordInfo.pCallback = NULL;
    passwordInfo.pCallbackInfo = &osslPasswordInfo;

    /* Read the BIO data directly. The header will contain information regarding
     * whether the PEM was encrypted or not.
     */
    if (!PEM_read_bio(pBio, &pName, &pHeader, &pData, &dataLen))
        return NULL;

    /* Determine the cipher algorithm to use based on the header info. We won't
     * actually use the OpenSSL cipher API to decrypt the PEM. Instead the
     * decryption will be handled by the Mocana code. Note that the header will
     * only be set if the PEM message was encrypted using PKCS#5 PBE (password
     * based encryption).
     */
    if (!PEM_get_EVP_CIPHER_INFO(pHeader, &cipherInfo))
        goto exit;

    /* If there is a cipher algorithm (this means the PEM message is PKCS#5
     * PBE encrypted) or if the "name" of the PEM indicates that the PEM is
     * PKCS#8 encrypted, then set the callback information. The "name" of the
     * PEM will just be the type of key that the PEM contains (this means the
     * "name" will typically just be "ENCRYPTED PRIVATE KEY" if
     * "-------BEGIN ENCRYPTED PRIVATE KEY------" was the starting guard and
     * "-------END ENCRYPTED PRIVATE KEY------" was the ending guard).
     *
     * If there is cipher information AND the user provided a callback then
     * parse the key using the caller provided callback.
     *
     * If there is cipher information AND there is no user provided callback
     * then call the default callback.
     */
    if ( (NULL != cipherInfo.cipher) ||
         (0 == strcmp(pName, PEM_STRING_PKCS8)) )
    {
        if (NULL == pPasswordCallback)
            passwordInfo.pCallback = getPassword;
        else
            passwordInfo.pCallback = OSSL_pemUserPasswordCallback;
    }

    /* Parse the PEM file using the Mocana API calls.
     */
    pRetKey = EVP_PKEY_moc_load_from_pem_buf(
        pData, dataLen, X509_FILETYPE_PEM, &passwordInfo);
    if (NULL == pRetKey)
        PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, ERR_R_ASN1_LIB);

    if (NULL != ppRetEvpPkey)
        *ppRetEvpPkey = pRetKey;

exit:

    OSSL_FREE(pName);
    OSSL_FREE(pHeader);
    OPENSSL_cleanse(pData, dataLen);
    OSSL_FREE(pData);

    return pRetKey;
}
#endif

/*------------------------------------------------------------------*/

extern int
SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    EVP_PKEY *pkey = NULL;
    int retval;

    pemPasswordInfo passwordInfo = { 0 };

    OSSL_PemPasswordCallback osslPasswordInfo = { 0 };

    if (!ctx || !file)
        return 0;

    osslPasswordInfo.pCallback = ctx->default_passwd_callback;
    osslPasswordInfo.pCallbackInfo = ctx->default_passwd_callback_userdata;

    if (ctx->default_passwd_callback)
    {
        passwordInfo.pCallback = OSSL_pemUserPasswordCallback;
    }
    else
    {
        passwordInfo.pCallback = getPassword;
    }

    passwordInfo.pCallbackInfo = &osslPasswordInfo;

    retval = 0;

    /* If EVP_PKEY_moc_load_from_pem_file() was able to decode the key data then
     * load in the EVP_PKEY. Otherwise, its possible that OpenSSL provided a key
     * file which has a non-standard encoding. If the key is in a non-standard
     * encoding then EVP_PKEY_moc_load_from_pem_file() will fail and return a
     * NULL key. When this happens call the default OpenSSL private key
     * deserialization routine to load in the key.
     *
     * NOTE: If the redefine flag (__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)
     * has been enabled then the non-standard key deserialization flow will
     * call back into the Mocana deserialization routine and fail again.
     */
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    pkey = EVP_PKEY_moc_load_from_pem_file(ctx, file, type, &passwordInfo);
    if (pkey)
    {
        retval = SSL_CTX_use_PrivateKey(ctx, pkey);
        EVP_PKEY_free(pkey);
    }
    else
#endif
    {
        retval = SSL_CTX_use_PrivateKey_file_ex(ctx, file, type);
    }
    return retval;
}

int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
{
    int ret;
    EVP_PKEY *pkey;

    if (rsa == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if ((pkey = EVP_PKEY_new()) == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return (0);
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0)
    {
        RSA_free(rsa);
        return 0;
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    return (ret);
}

int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == X509_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == X509_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         ctx->default_passwd_callback,
                                         ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);/* ref count is maintained; Freed only if ref count goes down to 0 */
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,
                               STACK_OF(X509_NAME) *name_list)
{
    if (*ca_list != NULL)
        sk_X509_NAME_pop_free(*ca_list, X509_NAME_free);

    *ca_list = name_list;
}

static void OSSL_setClientCAList(STACK_OF(X509_NAME) *name_list)
{
    OSSL_SizedBuffer *pCAList = NULL;
    int numCAList = 0;
    int i = 0;
    X509_NAME *name = NULL;
    ubyte* pData = NULL;

    numCAList = sk_X509_NAME_num(name_list);
    if (numCAList <= 0)
        return;

    pCAList = OSSL_CALLOC(numCAList * sizeof(OSSL_SizedBuffer), 1);
    if (NULL == pCAList)
        return;

    for ( i = 0; i < numCAList; i++)
    {
        int length = 0;
        name = sk_X509_NAME_value(name_list, i);
        /* Get the length of the name */
        length = i2d_X509_NAME(name, NULL);
        if (0 > length)
        {
            goto exit;
        }

        /* Allocate memory in OSSL_SizedBuffer list */
        OSSL_SB_Allocate(&(pCAList[i]), length);

        pData = pCAList[i].data;
        pCAList[i].length = i2d_X509_NAME(name, &pData);
    }
    
    NSSL_CHK_CALL(setClientCAList, pCAList, numCAList);

exit:
    /* Free the list */
    if (pCAList != NULL)
    {
        for (i = 0; i < numCAList ; i++)
        {
            if (pCAList[i].data != NULL)
                OSSL_SB_Free(&(pCAList[i]));
        }
    }

    OSSL_FREE(pCAList);
}

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)
{
     set_client_CA_list(&(s->client_CA), name_list);
     if (name_list != NULL)
     {
        OSSL_setClientCAList(name_list);
     }

}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)
{
     set_client_CA_list(&(ctx->client_CA), name_list);
     if (name_list != NULL)
     {
        OSSL_setClientCAList(name_list);
     }
}

static int xname_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
{
     MOC_UNUSED(ctx);

     return NULL; /* RGK_LATER */
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn;
    STACK_OF(X509_NAME) *ret = NULL, *sk;

    sk = sk_X509_NAME_new(xname_cmp);

    in = BIO_new(BIO_s_file_internal());

    if ((sk == NULL) || (in == NULL)) {
        SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if (ret == NULL) {
            ret = sk_X509_NAME_new_null();
            if (ret == NULL) {
                SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        /* check for duplicates */
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(sk, xn) >= 0)
            X509_NAME_free(xn);
        else {
            sk_X509_NAME_push(sk, xn);
            sk_X509_NAME_push(ret, xn);
        }
    }

    if (0) {
 err:
        if (ret != NULL)
            sk_X509_NAME_pop_free(ret, X509_NAME_free);
        ret = NULL;
    }
    if (sk != NULL)
        sk_X509_NAME_free(sk);
    if (in != NULL)
        BIO_free(in);
    if (x != NULL)
        X509_free(x);
    if (ret != NULL)
        ERR_clear_error();
    return (ret);
}

/*
 * Add a file of certs to a stack.
 * return 1 for success, 0 for failure.
 * Note that in the case of failure some certs may have been added to stack.
 */

int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                        const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    int ret = 0;
    int (*oldcmp) (const X509_NAME *const *a, const X509_NAME *const *b);

    oldcmp = sk_X509_NAME_set_cmp_func(stack, xname_cmp);

    in = BIO_new(BIO_s_file_internal());

    if (in == NULL)
    {
        SSLerr(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK, ERR_R_MALLOC_FAILURE);
        goto exit;
    }

    if (!BIO_read_filename(in, file))
    {
        goto exit;
    }

    for (;;)
    {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
        {
            break;
        }

        if ((xn = X509_get_subject_name(x)) == NULL)
        {
            goto exit;
        }
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
        {
            goto exit;
        }
        if (sk_X509_NAME_find(stack, xn) >= 0)
        {
            X509_NAME_free(xn);
        }
        else
        {
            sk_X509_NAME_push(stack, xn);
        }
    }

    ret = 1;
    ERR_clear_error();

exit:
    if (in != NULL)
    {
        BIO_free(in);
    }
    if (x != NULL)
    {
        X509_free(x);
    }

    (void)sk_X509_NAME_set_cmp_func(stack, oldcmp);

    return ret;
}

/*
 * Add a directory of certs to a stack.
 * return 1 for success, 0 for failure.
 * Note that in the case of failure some certs may have already been added to stack.
 */

int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                       const char *dir)
{
    OPENSSL_DIR_CTX *d = NULL;
    const char *filename;
    int ret = 0;

    /* CAs will be sorted by name */
    while ((filename = OPENSSL_DIR_read(&d, dir)))
    {
        char buf[1024];
        int r = 0;

        if (strlen(dir) + strlen(filename) + 2 > sizeof(buf))
        {
            SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK, SSL_R_PATH_TOO_LONG);
            goto exit;
        }

        r = BIO_snprintf(buf, sizeof(buf), "%s/%s", dir, filename);
        if (r <= 0 || r >= (int)sizeof(buf))
        {
            SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK, ERR_R_SYS_LIB);
            goto exit;
        }

        if (!SSL_add_file_cert_subjects_to_stack(stack, buf))
        {
            SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK, ERR_R_SYS_LIB);
            goto exit;
        }
    }

    ret = 1;

exit:
    if (d)
    {
        OPENSSL_DIR_end(&d);
    }
    return ret;
}
