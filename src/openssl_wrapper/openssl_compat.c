/*
 * openssl_compat.c
 *
 * OpenSSL ASN1 interface for DIGICERT
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include <string.h>

/*
 * VxWorks7 has openssl .h files in different locations
 */
#if defined(__RTOS_VXWORKS__)
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
#include <openssl/err.h>
#else
#include <err.h>
#endif
#else
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
#include <include/openssl/err.h>
#else
#include <crypto/err/err.h>
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
#include <include/internal/refcount.h>
#endif
#endif

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../ssl/ssl.h"

#include "../openssl_wrapper/ossl_types.h"
/* .. then openssl/ssl.h.  This is due to overloading of SSL_connect() and
 *    SSL_shutdown
 */
#include "../openssl_wrapper/ssl.h"
#include "openssl_shim.h"

#include <openssl/pem.h>

/* Used by SSL_alert_type_string* functions */
# define SSL3_AL_WARNING                 1
# define SSL3_AL_FATAL                   2

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
void ossl_statem_clear(SSL *s);
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
void ossl_statem_clear(SSL_CONNECTION *s);
#endif

const char *SSLeay_version(int t)
{
    if (t == SSLEAY_VERSION)
        return OPENSSL_VERSION_TEXT;
    return ("not available");
}

/*
 * Return a human-readable description string for an SSL/TLS alert value.
 *
 * Only the low-order 8 bits of |value| are considered (value & 0xff),
 * matching the on-the-wire alert description code. Known SSLv3/TLSv1(+)
 * alert codes are mapped to descriptive strings; any unrecognized value
 * results in the string "unknown".
 *
 * This function is intended for logging and diagnostics only and does
 * not perform any validation beyond the simple mapping shown below.
 */
const char *SSL_alert_desc_string_long(int value)
{
    const char *str;

    switch (value & 0xff) {
    case SSL3_AD_CLOSE_NOTIFY:
        str = "close notify";
        break;
    case SSL3_AD_UNEXPECTED_MESSAGE:
        str = "unexpected_message";
        break;
    case SSL3_AD_BAD_RECORD_MAC:
        str = "bad record mac";
        break;
    case SSL3_AD_DECOMPRESSION_FAILURE:
        str = "decompression failure";
        break;
    case SSL3_AD_HANDSHAKE_FAILURE:
        str = "handshake failure";
        break;
    case SSL3_AD_NO_CERTIFICATE:
        str = "no certificate";
        break;
    case SSL3_AD_BAD_CERTIFICATE:
        str = "bad certificate";
        break;
    case SSL3_AD_UNSUPPORTED_CERTIFICATE:
        str = "unsupported certificate";
        break;
    case SSL3_AD_CERTIFICATE_REVOKED:
        str = "certificate revoked";
        break;
    case SSL3_AD_CERTIFICATE_EXPIRED:
        str = "certificate expired";
        break;
    case SSL3_AD_CERTIFICATE_UNKNOWN:
        str = "certificate unknown";
        break;
    case SSL3_AD_ILLEGAL_PARAMETER:
        str = "illegal parameter";
        break;
    case TLS1_AD_DECRYPTION_FAILED:
        str = "decryption failed";
        break;
    case TLS1_AD_RECORD_OVERFLOW:
        str = "record overflow";
        break;
    case TLS1_AD_UNKNOWN_CA:
        str = "unknown CA";
        break;
    case TLS1_AD_ACCESS_DENIED:
        str = "access denied";
        break;
    case TLS1_AD_DECODE_ERROR:
        str = "decode error";
        break;
    case TLS1_AD_DECRYPT_ERROR:
        str = "decrypt error";
        break;
    case TLS1_AD_EXPORT_RESTRICTION:
        str = "export restriction";
        break;
    case TLS1_AD_PROTOCOL_VERSION:
        str = "protocol version";
        break;
    case TLS1_AD_INSUFFICIENT_SECURITY:
        str = "insufficient security";
        break;
    case TLS1_AD_INTERNAL_ERROR:
        str = "internal error";
        break;
    case TLS1_AD_USER_CANCELLED:
        str = "user canceled";
        break;
    case TLS1_AD_NO_RENEGOTIATION:
        str = "no renegotiation";
        break;
    case TLS1_AD_UNSUPPORTED_EXTENSION:
        str = "unsupported extension";
        break;
    case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
        str = "certificate unobtainable";
        break;
    case TLS1_AD_UNRECOGNIZED_NAME:
        str = "unrecognized name";
        break;
    case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        str = "bad certificate status response";
        break;
    case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
        str = "bad certificate hash value";
        break;
    case TLS1_AD_UNKNOWN_PSK_IDENTITY:
        str = "unknown PSK identity";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}

const char *SSL_alert_type_string(int value)
{
    value >>= 8;
    if (value == SSL3_AL_WARNING)
        return ("W");
    else if (value == SSL3_AL_FATAL)
        return ("F");
    else
        return ("U");
}

const char *SSL_alert_type_string_long(int value)
{
    value >>= 8;
    if (value == SSL3_AL_WARNING)
        return ("warning");
    else if (value == SSL3_AL_FATAL)
        return ("fatal");
    else
        return ("unknown");
}

const char *SSL_state_string_long(const SSL *s)
{
     if(s == NULL)
        return NULL;

     return "Unsupported";
}

#define MAX_HANDSHAKE_ATTEMPT (2)

int SSL_state(const SSL *ssl)
{
     int doHandshakeCount = 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
     const SSL_CONNECTION *s = NULL;
#else
     const SSL *s = NULL;
#endif

     if(ssl == NULL)
        return -1;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
     s = (const SSL_CONNECTION *)ssl;
#else
     s = ssl;
#endif
 
     if(1 == NSSL_CHK_CALL(isEstablished,s->instance))
	    return (SSL_ST_OK);
     else
     {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        if ((s->orig_state == SSL_ST_OK) || (s->orig_state == SSL_ST_RENEGOTIATE))
        {
            return SSL_ST_OK;
        }
        else if ((s->orig_state & SSL_ST_ACCEPT) && (s->state & SSL_ST_ACCEPT_NEGOTIATING))
        {
            do
            {
                doHandshakeCount++;
                if (OK >= SSL_do_handshake((SSL *) ssl))
                    return -1;

            } while (SSL_ST_OK != s->orig_state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);
            if (SSL_ST_OK == s->orig_state)
            {
                return SSL_ST_OK;
            }
        }
#else
        if ((s->orig_s.state == SSL_ST_OK) || (s->orig_s.state == SSL_ST_RENEGOTIATE))
        {
            return SSL_ST_OK;
        }
        else if ((s->orig_s.state & SSL_ST_ACCEPT) && (s->state & SSL_ST_ACCEPT_NEGOTIATING))
        {
            do
            {
                doHandshakeCount++;
                if (OK >= SSL_do_handshake((SSL *) ssl))
                    return -1;

            } while (SSL_ST_OK != s->orig_s.state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);
            if (SSL_ST_OK == s->orig_s.state)
            {
                return SSL_ST_OK;
            }
        }
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        if (SSL_SERVER_FLAG == s->clientServerFlag)
#else
        if (SSL_SERVER_METHOD == s->ssl_ctx->ssl_method->server_or_client)
#endif
        {
           return (SSL_ST_ACCEPT);
        }
        else
        {
           return SSL_ST_CONNECT;
        }
     }
}
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl)
{
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    const SSL_CONNECTION *s = NULL;
#else
    const SSL *s = NULL;
#endif
    
    if (ssl == NULL)
        return TLS_ST_BEFORE;
    
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    s = (const SSL_CONNECTION *)ssl;
#else
    s = ssl;
#endif
    
    return s->orig_s.statem.hand_state;
}
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
int SSL_get_state(const SSL *s)
{
    int state = TLS_ST_BEFORE;/* This is the default state */
    intBoolean isServer;
    sbyte4 nsslState = -2;
    sbyte4 status = 0;

    if (NULL == s)
        goto exit;

    isServer = (SSL_SERVER_FLAG == s->clientServerFlag) ? TRUE : FALSE;

    status = NSSL_CHK_CALL(sslGetState, s->instance, &nsslState);

    if (1 == status)
    {
        /* Connection is established */
        state = TLS_ST_OK;
        goto exit;
    }
    else if (0 > status)
    {
        /* Error case */
        goto exit;
    }

    switch (nsslState)
    {
        case SSL_CLIENT_HELLO:
            if (isServer)
                state = TLS_ST_SR_CLNT_HELLO;
            else
                state = TLS_ST_CW_CLNT_HELLO;
            break;
        case SSL_SERVER_HELLO:
            if (isServer)
                state = TLS_ST_SW_SRVR_HELLO;
            else
                state = TLS_ST_CR_SRVR_HELLO;
            break;
        case SSL_SERVER_HELLO_VERIFY_REQUEST:
            if (isServer)
                state = DTLS_ST_SW_HELLO_VERIFY_REQUEST;
            else
                state = DTLS_ST_CR_HELLO_VERIFY_REQUEST;
            break;
        case SSL_NEW_SESSION_TICKET:
            if (isServer)
                state = TLS_ST_SW_SESSION_TICKET;
            else
                state = TLS_ST_CR_SESSION_TICKET;
            break;
        case SSL_CLIENT_END_OF_EARLY_DATA:
            if (isServer)
                state = TLS_ST_SR_END_OF_EARLY_DATA;
            else
                state = TLS_ST_CW_END_OF_EARLY_DATA;
            break;
        case SSL_HELLO_RETRY_REQUEST:
            if (isServer)
                state = TLS_ST_SW_HELLO_REQ;
            else
                state = TLS_ST_CR_HELLO_REQ;
            break;
        case SSL_ENCRYPTED_EXTENSIONS:
            if (isServer)
                state = TLS_ST_SW_ENCRYPTED_EXTENSIONS;
            else
                state = TLS_ST_CR_ENCRYPTED_EXTENSIONS;
            break;
        case SSL_CERTIFICATE:
            if (isServer)
                state = TLS_ST_SR_CERT;
            else
                state = TLS_ST_CR_CERT;
            break;
        case SSL_SERVER_KEY_EXCHANGE:
            if (isServer)
                state = TLS_ST_SW_KEY_EXCH;
            else
                state = TLS_ST_CR_KEY_EXCH;
            break;
        case SSL_CERTIFICATE_REQUEST:
            if (isServer)
                state = TLS_ST_SW_CERT_REQ;
            else
                state = TLS_ST_CR_CERT_REQ;
            break;
        case SSL_SERVER_HELLO_DONE:
            if (isServer)
                state = TLS_ST_SW_SRVR_DONE;
            else
                state = TLS_ST_CR_SRVR_DONE;
            break;
        case SSL_CLIENT_CERTIFICATE_VERIFY:
            /* NanoSSL maintains the state information upon reading this message only */
            if (isServer)
                state = TLS_ST_SR_CERT_VRFY;
            else
                state = TLS_ST_CR_CERT_VRFY;
            break;
        case SSL_CLIENT_KEY_EXCHANGE:
            if (isServer)
                state = TLS_ST_SR_KEY_EXCH;
            else
                state = TLS_ST_CW_KEY_EXCH;
            break;
        case SSL_EXPECTING_FINISHED:
            if (isServer)
                state = TLS_ST_SR_FINISHED;
            else
                state = TLS_ST_CW_FINISHED;
            break;
        case SSL_FINISHED:
            if (isServer)
                state = TLS_ST_SR_FINISHED;
            else
                state = TLS_ST_CR_FINISHED;
            break;
        case SSL_CERTIFICATE_STATUS:
            if (isServer)
                state = TLS_ST_SW_CERT_STATUS;
            else
                state = TLS_ST_CR_CERT_STATUS;
            break;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        case SSL_KEY_UPDATE:
        {
            sbyte4 keyUpdateType = 0;

            keyUpdateType = s->orig_s.key_update;
            if (SSL_KEY_UPDATE_NONE == keyUpdateType)
            {
                /* No KeyUpdate was sent. Received a keyUpdate message from peer */
                if (isServer)
                    state = TLS_ST_SR_KEY_UPDATE;
                else
                    state = TLS_ST_CR_KEY_UPDATE;
            }
            else
            {
                if (isServer)
                    state = TLS_ST_SW_KEY_UPDATE;
                else
                    state = TLS_ST_CW_KEY_UPDATE;
            }
            break;
        }
#endif
        default:
            break;
    }

exit:
    return state;
}
#endif

const char *SSL_state_string(const SSL *s)
{
    const char *str;


    if(s == NULL)
        return NULL;

    switch (SSL_state(s)) {
    case SSL_ST_ACCEPT:
        str = "AINIT ";
        break;
    case SSL_ST_CONNECT:
        str = "CINIT ";
        break;
    case SSL_ST_OK:
        str = "SSLOK ";
        break;
    default:
        str = "UNKWN ";
        break;
    }
    return (str);
}

void SSL_set_connect_state(SSL *s)
{
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    SSL_CONNECTION *ssl = (SSL_CONNECTION *) s;
#else
    SSL *ssl = s;
#endif
    if(ssl)
    {
        ssl->clientServerFlag = SSL_CLIENT_FLAG;
        ssl->orig_s.shutdown = 0;
        ssl->state = SSL_ST_CONNECT | SSL_ST_BEFORE;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        ossl_statem_clear(ssl);
#endif
    }
}





/***************** Start of functions req. for client example *****************/
/* These functions are needed for the NanoSSL_toosl/client example to compile */
/* These are duplicated from ossl_ssl.c */

extern SSL_SESSION*
SSL_SESSION_new(void)
{
    SSL_SESSION *ss;
 
    ss = (SSL_SESSION *) OSSL_CALLOC(1,sizeof(SSL_SESSION));
    if (ss == NULL)
    {
        SSLerr(SSL_F_SSL_SESSION_NEW, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    /* Start reference at 1, same as OpenSSL */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    if (!CRYPTO_NEW_REF(&ss->references, 1)) {
        OPENSSL_free(ss);
        return NULL;
    }
#else
    ss->references = 1;
#endif
    ss->session_id_length = 0;
    return ss;
}

extern int
SSL_SESSION_up_ref(SSL_SESSION *ses)
{
    if (ses == NULL)
        return 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    int i;

    if (CRYPTO_UP_REF(&ses->references, &i) <= 0)
        return 0;
    return ((i > 1) ? 1 : 0);
#else
    ses->references++;
    return 1;
#endif
}

extern void
SSL_SESSION_free(SSL_SESSION *ses)
{
    if (ses)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        int i;
        CRYPTO_DOWN_REF(&ses->references, &i);
        if (i > 0)
            return;
#else
        if (--ses->references > 0)
	        return;
#endif

        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ses, &ses->ex_data);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        CRYPTO_THREAD_lock_free(ses->lock);
#endif

        if (NULL != ses->ext.alpn_selected)
        {
            OPENSSL_free(ses->ext.alpn_selected);
        }

        if (NULL != ses->ext.hostname)
        {
            OSSL_FREE(ses->ext.hostname);
        }

        if (NULL != ses->ext.tick)
        {
            OSSL_FREE(ses->ext.tick);
        }

        if (NULL != ses->peer_chain)
        {
            sk_X509_pop_free(ses->peer_chain, X509_free);
        }
#else
        if (NULL != ses->tlsext_hostname)
        {
            OSSL_FREE(ses->tlsext_hostname);
        }


        if (NULL != ses->tlsext_tick)
        {
            OSSL_FREE(ses->tlsext_tick);
        }

        if (NULL != ses->sess_cert)
        {
            sk_X509_pop_free(ses->sess_cert->cert_chain, X509_free);
            OPENSSL_free(ses->sess_cert);
            ses->sess_cert = NULL;
        }
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        CRYPTO_FREE_REF(&ses->references);
#endif
        memset((ubyte*)ses, 0, sizeof(SSL_SESSION));
        OSSL_FREE(ses);
    }
}

extern SSL_SESSION *
SSL_get1_session(SSL *ssl)
{
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    SSL_CONNECTION *s = NULL;
#else
    SSL *s = NULL;
#endif

    if(NULL != ssl) 
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        s = (SSL_CONNECTION *)ssl;
#else
        s = ssl;
#endif
        if(NULL != s->session) 
        {
            return SSL_SESSION_reference(SSL_get_session(ssl)); 
        }
    }
    return NULL;
}

extern SSL_SESSION*
SSL_SESSION_reference(SSL_SESSION* ses)
{
    if (ses)
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    {
        int i;

        if (CRYPTO_UP_REF(&ses->references, &i) <= 0)
            return NULL;
    }
#else
        ses->references++;
#endif
    return ses;
}


extern int
SSL_set_session(SSL *to, SSL_SESSION *session)
{
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    SSL_CONNECTION *s = NULL;
#else
    SSL *s = NULL;
#endif

    if (!to)
        return 0; /* invalid argument */

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    s = (SSL_CONNECTION *)to;
#else
    s = to;
#endif

    /* If passed session is NULL free the session */
    if (!session)
        if (s->session)
        {
            SSL_SESSION_free(s->session);
            s->session = NULL;
            return 1;
        }

    if (s->session)
        SSL_SESSION_free(s->session);

    if(NULL != (s->session = SSL_SESSION_reference(session))) {
        s->verify_result = session->verify_result;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    SSL_set_psk_use_session_callback(to, NULL);
    s->registerRetrievePSK = 1;
#endif

    return 1;
}
/********************** End of functions req. for client example **************/





STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)
{
    STACK_OF(X509)* pCertChain = NULL;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    const SSL_CONNECTION *sc = NULL;
#else
    const SSL *sc = NULL;
#endif

    if(s == NULL)
        return NULL;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    sc = (const SSL_CONNECTION *)s;
#else
    sc = s;
#endif

    if(sc->session == NULL)
    {
        return NULL;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    pCertChain = sc->session->peer_chain;
#else
    if (sc->session->sess_cert != NULL)
    {
        pCertChain = sc->session->sess_cert->cert_chain;
    }
#endif

    return pCertChain;
}

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)

STACK_OF(X509) *SSL_get0_verified_chain(const SSL *s)
{
    if (NULL == s)
        return NULL;

    return s->verified_chain;
}

#endif

int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x)
{

    if (x == NULL)
        goto err;
    if (BIO_puts(bp, "SSL-Session: To Be Implemented\n") <= 0)
        goto err;
    return (1);
 err:
    return (0);
}

int SSL_set_ex_data(SSL *s, int idx, void *arg)
{
    if (s == NULL)
        return 0;

    return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                int (*cb) (SSL *ssl,
                                           const unsigned char **out,
                                           unsigned char *outlen,
                                           const unsigned char *in,
                                           unsigned int inlen,
                                           void *arg), void *arg)
{
    if (ctx == NULL)
        return;

    ctx->alpn_select_cb = cb;
    ctx->alpn_select_cb_arg = arg;
}

int SSL_CTX_set_srp_username_callback(SSL_CTX *ctx,
                                      int (*cb) (SSL *, int *, void *))
{
     MOC_UNUSED(cb);
 
     if(ctx == NULL)
        return 0;

     return 0;
}

int SSL_CTX_set_srp_cb_arg(SSL_CTX *ctx, void *arg)
{
     MOC_UNUSED(arg);

     if(ctx == NULL)
        return 0;

     return 0;
}

#if 0
int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
     return 0;
}
#endif
int SSL_get_verify_mode(const SSL *s)
{
     if(s == NULL)
        return 0;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    const SSL_CONNECTION *sc = (const SSL_CONNECTION *)s;
#else
    const SSL *sc = s;
#endif

     return sc->orig_s.verify_mode;
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx)) (int, X509_STORE_CTX *) {
    if(ctx == NULL)
        return NULL;

     return ctx->verify_callback;
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
     if(ctx == NULL)
        return 0;

     return ctx->verify_mode;
}

void SSL_set_verify(SSL *s, int mode,
                    int (*callback) (int ok, X509_STORE_CTX *ctx))
{
    ubyte4 sslFlags  = 0;
    int authModeFlag = 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    SSL_CONNECTION *sc = NULL;
#else
    SSL *sc = NULL;
#endif

    if(s == NULL)
        return;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    sc = (SSL_CONNECTION *)s;
#else
    sc = s;
#endif

    sc->orig_s.verify_mode = mode;
    if (callback != NULL)
    {
        sc->orig_s.verify_callback = callback;
    }

    if((sc->orig_s.verify_mode & SSL_VERIFY_PEER) || (sc->ssl_ctx->verify_mode & SSL_VERIFY_PEER)){
        /* allow mutual auth */
        authModeFlag = 1L/*SSL_FLAG_REQUIRE_MUTUAL_AUTH*/;
    } else {
        authModeFlag = 2L/*SSL_FLAG_NO_MUTUAL_AUTH_REQUEST*/;
    }

    if (OK > NSSL_CHK_CALL(getSessionFlags, sc->instance, &sslFlags))
    {
        return;
    }

    /* Reset the flags before setting */
    sslFlags &= ~(1L/*SSL_FLAG_NO_MUTUAL_AUTH_REQUEST*/);
    sslFlags &= ~(2L/*SSL_FLAG_REQUIRE_MUTUAL_AUTH*/);

    if (OK > NSSL_CHK_CALL(setSessionFlags, sc->instance, (sslFlags | authModeFlag)))
    {
        return;
    }
}

const char *SSL_get_servername(const SSL *s, const int type)
{
    if (NULL == s || type != TLSEXT_NAMETYPE_host_name)
        return NULL;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    const SSL_CONNECTION *sc = (const SSL_CONNECTION *)s;
#else
    const SSL *sc = s;
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    return sc->session && !sc->tlsext_hostname ?
         (const char *) sc->session->ext.hostname : (const char *) sc->tlsext_hostname;
#else
    return sc->session && !sc->tlsext_hostname ?
        (const char *) sc->session->tlsext_hostname : (const char *) sc->tlsext_hostname;
#endif

}

int SSL_get_servername_type(const SSL *s)
{
    char *pHostname = NULL;

    if (NULL == s)
        return -1;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    const SSL_CONNECTION *sc = (const SSL_CONNECTION *)s;
#else
    const SSL *sc = s;
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    pHostname  = (!sc->tlsext_hostname ? sc->session->ext.hostname : sc->tlsext_hostname);
#else
    pHostname = (!sc->tlsext_hostname ? sc->session->tlsext_hostname : sc->tlsext_hostname);
#endif

    if (sc->session && (pHostname))
        return TLSEXT_NAMETYPE_host_name;
    return -1;
}

char *SSL_get_srp_username(SSL *s)
{
     if(s == NULL)
        return NULL;

     return NULL;
}

int SSL_get_verify_depth(const SSL *s)
{
     if(s == NULL)
        return -1;

     return 0;
}

long SSL_SESSION_set_time(SSL_SESSION *s, long t)
{
     if (s == NULL)
        return (0);

     s->time = t;
     return (1);
}

long SSL_SESSION_set_timeout(SSL_SESSION *s, long t)
{
     MOC_UNUSED(t);
     if(s == NULL)
        return 0;

     return 0;
}

const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
                                        unsigned int *len)
{
     if(s == NULL)
        return NULL;

     if (len)
	  *len = (unsigned int)s->session_id_length;
     return s->session_id;
}

long SSL_SESSION_get_time(const SSL_SESSION *s)
{
     if(s == NULL)
        return 0;

     return s->time;
}

int SSL_set_srp_server_param(SSL *s, const BIGNUM *N, const BIGNUM *g,
                             BIGNUM *sa, BIGNUM *v, char *info)
{
     MOC_UNUSED(N);
     MOC_UNUSED(g);
     MOC_UNUSED(sa);
     MOC_UNUSED(v);
     MOC_UNUSED(info);

     if(s == NULL)
        return -1;

     return -1;/* -1 on failure */
}

char *SSL_get_srp_userinfo(SSL *s)
{
     if(s == NULL)
        return NULL;

     return 0;
}

unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s)
{
     if(s == NULL)
        return (unsigned int)-1;

     return 0;
}

/* This function will deserialize a SSL session. If the caller
 * provides a SSL_SESSION struct then that SSL_SESSION struct
 * will be populated with data. Otherwise this function will
 * allocate a SSL_SESSION struct and return it to the caller.
 */
SSL_SESSION *d2i_SSL_SESSION(
    SSL_SESSION **ppRetSession,
    const unsigned char **ppBuffer,
    long bufferLen
    )
{
    MSTATUS status;
    ubyte *pSessionId = NULL, *pMasterSecret = NULL;
    sbyte *pDNSName = NULL;
    ubyte4 sessionIdLength, masterSecretLen, dnsNameLen;
    SSL_SESSION *pNewSession = NULL, *pRet = NULL;
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    OSSL_sessionTicket *pTicketData = NULL;
#endif

    if (NULL == ppBuffer)
    {
        goto exit;
    }

    /* Attempt to deserialize as a session ticket first. If that fails then
     * attempt to read it as a session ID. Function returns a refernce within
     * the buffer so no need to free the session ID and master secret buffer.
     */
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    status = NSSL_CHK_CALL(
        deserializeTicket, (ubyte *) *ppBuffer, bufferLen, &pTicketData);
    if (OK != status)
#endif
    {
        status = NSSL_CHK_CALL(
            asn1DecodeSslSession, (ubyte *) *ppBuffer, bufferLen, &pSessionId,
            &sessionIdLength, &pMasterSecret, &masterSecretLen, &pDNSName,
            &dnsNameLen);
    }
    if (OK != status)
        goto exit;

    /* Ensure the session ID and master secret are of proper length.
     */
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (NULL == pTicketData)
#endif
    {
        if ( (0 == sessionIdLength) || (SSL_MAXSESSIONIDSIZE < sessionIdLength) ||
             (SSL_MASTERSECRETSIZE != masterSecretLen) )
        {
            goto exit;
        }
    }

    /* Allocate memory for the SSL_SESSION or use the caller provided
     * SSL_SESSION.
     */
    if ( (NULL == ppRetSession) || (NULL == *ppRetSession) )
    {
        pNewSession = (SSL_SESSION *) SSL_SESSION_new();
        if (NULL == pNewSession)
        {
            goto exit;
        }
        pNewSession->cipher = NULL;
    }
    else
    {
        pNewSession = *ppRetSession;
    }

    /* Only copy in the session ID and the master secret. All other variables in
     * the SSL_SESSION object are ignored.
     */
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (NULL != pTicketData)
    {
        /* Store ticket values in OpenSSL session structure */
        pNewSession->cipher_id = pTicketData->cipherId;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
        pNewSession->ext.tick = OSSL_MALLOC(bufferLen);
        memcpy(pNewSession->ext.tick, *ppBuffer, bufferLen);
        pNewSession->ext.ticklen = bufferLen;
        pNewSession->ext.tick_lifetime_hint = pTicketData->lifeTimeHintInSec;
#else
        pNewSession->tlsext_tick = OSSL_MALLOC(bufferLen);
        memcpy(pNewSession->tlsext_tick, *ppBuffer, bufferLen);
        pNewSession->tlsext_ticklen = bufferLen;
        pNewSession->tlsext_tick_lifetime_hint = pTicketData->lifeTimeHintInSec;
#endif

        memcpy(pNewSession->master_key, pTicketData->masterSecret, SSL_MASTERSECRETSIZE);
        pNewSession->master_key_length = SSL_MASTERSECRETSIZE; 
    }
    else
#endif
    {
        memcpy(pNewSession->session_id, pSessionId, sessionIdLength);
        pNewSession->session_id_length = sessionIdLength;

        memcpy(pNewSession->master_key, pMasterSecret, masterSecretLen);

        if (NULL != pDNSName)
        {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
            pNewSession->ext.hostname = OSSL_MALLOC(dnsNameLen + 1);
            memcpy(pNewSession->ext.hostname, pDNSName, dnsNameLen);
            pNewSession->ext.hostname[dnsNameLen] = '\0';
#else
            pNewSession->tlsext_hostname = OSSL_MALLOC(dnsNameLen + 1);
            memcpy(pNewSession->tlsext_hostname, pDNSName, dnsNameLen);
            pNewSession->tlsext_hostname[dnsNameLen] = '\0';
#endif
        }
    }

    pRet = pNewSession;
    pNewSession = NULL;

exit:
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (NULL != pTicketData)
    {
        (void) NSSL_CHK_CALL(freeTicket, &pTicketData);
    }
#endif

    /* No need to free pNewSession in case of error. Only place pNewSession can
     * fail is during allocation */

    return pRet;
}

/* This function will serialize a SSL_SESSION struct.
 * The data that will be serialized will only be the
 * session ID and the master key. The caller must provide
 * a buffer big enough to store the ASN.1 encoding. To get
 * the proper size, the caller can pass in NULL as the output
 * buffer and this function will return the amount of bytes
 * that will be output.
 */
int i2d_SSL_SESSION(
    SSL_SESSION *pSession,
    unsigned char **ppRetBuffer
    )
{
    MSTATUS status;
    int retVal = 0;
    unsigned char *pBuffer = NULL;
    char *pHostname = NULL;

    if (NULL == pSession)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    pHostname = pSession->ext.hostname;
#else
    pHostname = pSession->tlsext_hostname;
#endif

    if (NULL != ppRetBuffer)
    {
        pBuffer = *ppRetBuffer;
    }
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)
    if (NULL != pSession->ext.tick)
    {
        if (pBuffer)
            memcpy(pBuffer, pSession->ext.tick, pSession->ext.ticklen);

        retVal = pSession->ext.ticklen;
    } else
#else
    if (NULL != pSession->tlsext_tick)
    {
        if (pBuffer)
            memcpy(pBuffer, pSession->tlsext_tick, pSession->tlsext_ticklen);

        retVal = pSession->tlsext_ticklen;
    } else
#endif
#endif
    if (0 != pSession->session_id_length)
    {
        status = NSSL_CHK_CALL(
            asn1EncodeSslSession, pSession->session_id, (ubyte4) pSession->session_id_length,
            pSession->master_key, SSL_MASTERSECRETSIZE, (sbyte *) pHostname,
            pBuffer, &retVal);
        if (OK != status)
            goto exit;
    }

exit:

    return retVal;
}

/*------------------------------------------------------------------*/

SSL_SESSION *PEM_read_bio_SSL_SESSION(
    BIO *bp, SSL_SESSION **x, pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read_bio(
        (d2i_of_void *)d2i_SSL_SESSION, "SSL SESSION PARAMETERS", bp,
        (void **)x, cb, u);
}

/*------------------------------------------------------------------*/

SSL_SESSION *PEM_read_SSL_SESSION(
    FILE *fp, SSL_SESSION **x, pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read(
        (d2i_of_void *)d2i_SSL_SESSION, "SSL SESSION PARAMETERS", fp,
        (void **)x, cb, u);
}

/*------------------------------------------------------------------*/

int PEM_write_SSL_SESSION(FILE *fp, SSL_SESSION *x)
{
    return PEM_ASN1_write(
        (i2d_of_void *)i2d_SSL_SESSION,"SSL SESSION PARAMETERS", fp, x, NULL,
        NULL, 0, NULL, NULL);
}

/*------------------------------------------------------------------*/

int PEM_write_bio_SSL_SESSION(BIO *bp, SSL_SESSION *x)
{
    return PEM_ASN1_write_bio(
        (i2d_of_void *)i2d_SSL_SESSION, "SSL SESSION PARAMETERS", bp, x, NULL,
        NULL, 0, NULL, NULL);
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_5__)

size_t SSL_SESSION_get_master_key(
    const SSL_SESSION *pSession,
    unsigned char *pOut,
    size_t outLen
    )
{
    if ( (NULL == pSession) || (NULL == pOut) )
        return 0;

    if (0 == outLen)
        return SSL_MASTERSECRETSIZE;

    if (outLen > SSL_MASTERSECRETSIZE)
        outLen = SSL_MASTERSECRETSIZE;

    memcpy(pOut, pSession->master_key, outLen);
    return outLen;
}

void SSL_SESSION_get0_ticket(
    const SSL_SESSION *s,
    const unsigned char **tick,
    size_t *len
    )
{
    if (NULL == s)
        return;

    if (NULL != tick)
        *tick = s->ext.tick;

    if (NULL != len)
        *len = s->ext.ticklen;

    return;
}

int SSL_SESSION_has_ticket(const SSL_SESSION *s)
{
    if (NULL == s)
    {
        return -1;
    }

    return (s->ext.ticklen > 0) ? 1 : 0;
}

unsigned long SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION *s)
{
    if (NULL == s)
    {
        return -1;
    }

    return s->ext.tick_lifetime_hint;
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_5__ */
