/*
 * ossl_typesv3.h
 *
 * OpenSSL types interface for DIGICERT
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

#ifndef OSSL_TYPESV3_HEADER
#define OSSL_TYPESV3_HEADER

#define EVP_MAX_MD_SIZE 64

#define SSL3_RANDOM_SIZE       32
#define SSL3_CT_NUMBER          9


struct ssl_comp_st {
    int id;
    const char *name;
    COMP_METHOD *method;
};

typedef struct ssl_comp_st SSL_COMP;

typedef struct ssl3_buffer_st {
    /* at least SSL3_RT_MAX_PACKET_SIZE bytes, see ssl3_setup_buffers() */
    unsigned char *buf;
    /* buffer size */
    size_t len;
    /* where to 'copy from' */
    int offset;
    /* how many bytes left */
    int left;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    /* 'buf' is from application for KTLS */
    int app_buffer;
#endif
} SSL3_BUFFER;

typedef struct ssl3_record_st {
    /* type of record */
    /*
     * r
     */ int type;
    /* How many bytes available */
    /*
     * rw
     */ unsigned int length;
    /* read/write offset into 'buf' */
    /*
     * r
     */ unsigned int off;
    /* pointer to the record data */
    /*
     * rw
     */ unsigned char *data;
    /* where the decode bytes are */
    /*
     * rw
     */ unsigned char *input;
    /* only used with decompression - malloc()ed */
    /*
     * r
     */ unsigned char *comp;
    /* epoch number, needed by DTLS1 */
    /*
     * r
     */ unsigned long epoch;
    /* sequence number, needed by DTLS1 */
    /*
     * r
     */ unsigned char seq_num[8];
} SSL3_RECORD;

typedef struct ssl3_state_st {
    long flags;
    int delay_buf_pop_ret;
    unsigned char read_sequence[8];
    int read_mac_secret_size;
    unsigned char read_mac_secret[EVP_MAX_MD_SIZE];
    unsigned char write_sequence[8];
    int write_mac_secret_size;
    unsigned char write_mac_secret[EVP_MAX_MD_SIZE];
    unsigned char server_random[SSL3_RANDOM_SIZE];
    unsigned char client_random[SSL3_RANDOM_SIZE];
    /* flags for countermeasure against known-IV weakness */
    int need_empty_fragments;
    int empty_fragment_done;
    /* The value of 'extra' when the buffers were initialized */
    int init_extra;
    SSL3_BUFFER rbuf;           /* read IO goes into here */
    SSL3_BUFFER wbuf;           /* write IO goes into here */
    SSL3_RECORD rrec;           /* each decoded record goes in here */
    SSL3_RECORD wrec;           /* goes out from here */
    /*
     * storage for Alert/Handshake protocol data received but not yet
     * processed by ssl3_read_bytes:
     */
    unsigned char alert_fragment[2];
    unsigned int alert_fragment_len;
    unsigned char handshake_fragment[4];
    unsigned int handshake_fragment_len;
    /* partial write - check the numbers match */
    unsigned int wnum;          /* number of bytes sent so far */
    int wpend_tot;              /* number bytes written */
    int wpend_type;
    int wpend_ret;              /* number of bytes submitted */
    const unsigned char *wpend_buf;
    /* used during startup, digest all incoming/outgoing packets */
    BIO *handshake_buffer;
    /*
     * When set of handshake digests is determined, buffer is hashed and
     * freed and MD_CTX-es for all required digests are stored in this array
     */
    EVP_MD_CTX **handshake_dgst;
    /*
     * Set whenever an expected ChangeCipherSpec message is processed.
     * Unset when the peer's Finished message is received.
     * Unexpected ChangeCipherSpec messages trigger a fatal alert.
     */
    int change_cipher_spec;
    int warn_alert;
    int fatal_alert;
    /*
     * we allow one fatal and one warning alert to be outstanding, send close
     * alert via the warning alert
     */
    int alert_dispatch;
    unsigned char send_alert[2];
    /*
     * This flag is set when we should renegotiate ASAP, basically when there
     * is no more data in the read or write buffers
     */
    int renegotiate;
    int total_renegotiations;
    int num_renegotiations;
    int in_read_app_data;
    /*
     * Opaque PRF input as used for the current handshake. These fields are
     * used only if TLSEXT_TYPE_opaque_prf_input is defined (otherwise, they
     * are merely present to improve binary compatibility)
     */
    void *client_opaque_prf_input;
    size_t client_opaque_prf_input_len;
    void *server_opaque_prf_input;
    size_t server_opaque_prf_input_len;
    struct {
        /* actually only needs to be 16+20 */
        unsigned char cert_verify_md[EVP_MAX_MD_SIZE * 2];
        /* actually only need to be 16+20 for SSLv3 and 12 for TLS */
        unsigned char finish_md[EVP_MAX_MD_SIZE * 2];
        int finish_md_len;
        unsigned char peer_finish_md[EVP_MAX_MD_SIZE * 2];
        int peer_finish_md_len;
        unsigned long message_size;
        int message_type;
        /* used to hold the new cipher we are going to use */
        const struct ssl_cipher_st *new_cipher;
#  ifndef OPENSSL_NO_DH
        DH *dh;
#  endif
#  ifndef OPENSSL_NO_ECDH
        EC_KEY *ecdh;           /* holds short lived ECDH key */
#  endif
        /* used when SSL_ST_FLUSH_DATA is entered */
        int next_state;
        int reuse_message;
        /* used for certificate requests */
        int cert_req;
        int ctype_num;
        char ctype[SSL3_CT_NUMBER];
        STACK_OF(X509_NAME) *ca_names;
        int use_rsa_tmp;
        int key_block_length;
        unsigned char *key_block;
        const EVP_CIPHER *new_sym_enc;
        const EVP_MD *new_hash;
        int new_mac_pkey_type;
        int new_mac_secret_size;
#  ifndef OPENSSL_NO_COMP
        const SSL_COMP *new_compression;
#  else
        char *new_compression;
#  endif
        int cert_request;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__
        /* Certificate authorities list peer sent */
        STACK_OF(X509_NAME) *peer_ca_names;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
    } tmp;

    /* Connection binding to prevent renegotiation attacks */
    unsigned char previous_client_finished[EVP_MAX_MD_SIZE];
    unsigned char previous_client_finished_len;
    unsigned char previous_server_finished[EVP_MAX_MD_SIZE];
    unsigned char previous_server_finished_len;
    int send_connection_binding; /* TODOEKR */

#  ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * Set if we saw the Next Protocol Negotiation extension from our peer.
     */
    int next_proto_neg_seen;
#  endif

#  ifndef OPENSSL_NO_TLSEXT
#   ifndef OPENSSL_NO_EC
    /*
     * This is set to true if we believe that this is a version of Safari
     * running on OS X 10.6 or newer. We wish to know this because Safari on
     * 10.8 .. 10.8.3 has broken ECDHE-ECDSA support.
     */
    char is_probably_safari;
#   endif                       /* !OPENSSL_NO_EC */

    /*
     * ALPN information (we are in the process of transitioning from NPN to
     * ALPN.)
     */

    /*
     * In a server these point to the selected ALPN protocol after the
     * ClientHello has been processed. In a client these contain the protocol
     * that the server selected once the ServerHello has been processed.
     */
    unsigned char *alpn_selected;
    unsigned alpn_selected_len;
#  endif                        /* OPENSSL_NO_TLSEXT */
} SSL3_STATE;

#endif
