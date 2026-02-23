
/*
 * ossl_types.h
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

#ifndef OSSL_SSL_HEADER
#define OSSL_SSL_HEADER 

#define SSL_ENC_DES_IDX         0
#define SSL_ENC_3DES_IDX        1
#define SSL_ENC_RC4_IDX         2
#define SSL_ENC_RC2_IDX         3
#define SSL_ENC_IDEA_IDX        4
#define SSL_ENC_NULL_IDX        5
#define SSL_ENC_AES128_IDX      6
#define SSL_ENC_AES256_IDX      7
#define SSL_ENC_CAMELLIA128_IDX 8
#define SSL_ENC_CAMELLIA256_IDX 9
#define SSL_ENC_GOST89_IDX      10
#define SSL_ENC_SEED_IDX        11
#define SSL_ENC_AES128GCM_IDX   12
#define SSL_ENC_AES256GCM_IDX   13
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
# define SSL_ENC_AES128CCM_IDX   14
# define SSL_ENC_AES256CCM_IDX   15
# define SSL_ENC_AES128CCM8_IDX  16
# define SSL_ENC_AES256CCM8_IDX  17
# define SSL_ENC_GOST8912_IDX    18
# define SSL_ENC_CHACHA_IDX      19
# define SSL_ENC_ARIA128GCM_IDX  20
# define SSL_ENC_ARIA256GCM_IDX  21
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
# define SSL_ENC_MAGMA_IDX       22
# define SSL_ENC_KUZNYECHIK_IDX  23
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif
/* SSL_ENC_NUM_IDX macro is used in ossl_ciph.c when declaring the cipher table
 * list. Different versions of OpenSSL support different sets of cipher
 * algorithms. When adding support for a new version, update the macro
 * appropriately and the cipher list in ossl_ciph.c.
 */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define SSL_ENC_NUM_IDX         24
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#define SSL_ENC_NUM_IDX         22
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
#define SSL_ENC_NUM_IDX         20
#else
#define SSL_ENC_NUM_IDX         14
#endif

#define SSL_MD_MD5_IDX  0
#define SSL_MD_SHA1_IDX 1
#define SSL_MD_GOST94_IDX 2
#define SSL_MD_GOST89MAC_IDX 3
#define SSL_MD_SHA256_IDX 4
#define SSL_MD_SHA384_IDX 5

# define SSL_EXP_MASK            0x00000003L
# define SSL_STRONG_MASK         0x000001fcL

# define SSL_NOT_EXP             0x00000001L
# define SSL_EXPORT              0x00000002L

# define SSL_STRONG_NONE         0x00000004L
# define SSL_EXP40               0x00000008L
# define SSL_MICRO               (SSL_EXP40)
# define SSL_EXP56               0x00000010L
# define SSL_MINI                (SSL_EXP56)
# define SSL_LOW                 0x00000020L
# define SSL_MEDIUM              0x00000040L
# define SSL_HIGH                0x00000080L
# define SSL_FIPS                0x00000100L
# define SSL_NOT_DEFAULT         0x00000200L

/* SSL ioctl settings */
#define SSL_SET_VERSION                         (1)

/* SSL runtime flags */
#define SSL_FLAG_REQUIRE_MUTUAL_AUTH         (0x00000001L)
#define SSL_FLAG_NO_MUTUAL_AUTH_REQUEST      (0x00000002L)       /* for server */
#define SSL_FLAG_NO_MUTUAL_AUTH_REPLY        (0x00000002L)       /* for client */
#define SSL_FLAG_ENABLE_SEND_EMPTY_FRAME     (0x00000004L)
#define SSL_FLAG_ENABLE_SEND_BUFFER          (0x00000008L)
#define SSL_FLAG_ENABLE_RECV_BUFFER          (0x00000010L)
#define SSL_FLAG_ALLOW_INSECURE_REHANDSHAKE  (0x00000080L)       /* permit legacy renegotiation */

/* Bits for algorithm_mac (symmetric authentication) */

# define SSL_MD5                 0x00000001L
# define SSL_SHA1                0x00000002L
# define SSL_GOST94      0x00000004L
# define SSL_GOST89MAC   0x00000008L
# define SSL_SHA256              0x00000010L
# define SSL_SHA384              0x00000020L
/* Not a real MAC, just an indication it is part of cipher */
# define SSL_AEAD                0x00000040U
# define SSL_GOST12_256          0x00000080U
# define SSL_GOST89MAC12         0x00000100U
# define SSL_GOST12_512          0x00000200U

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
# define SSL_MD_MD5_IDX  0
# define SSL_MD_SHA1_IDX 1
# define SSL_MD_GOST94_IDX 2
# define SSL_MD_GOST89MAC_IDX 3
# define SSL_MD_SHA256_IDX 4
# define SSL_MD_SHA384_IDX 5
# define SSL_MD_GOST12_256_IDX  6
# define SSL_MD_GOST89MAC12_IDX 7
# define SSL_MD_GOST12_512_IDX  8
# define SSL_MD_MD5_SHA1_IDX 9
# define SSL_MD_SHA224_IDX 10
# define SSL_MD_SHA512_IDX 11
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
# define SSL_MD_MAGMAOMAC_IDX 12
# define SSL_MD_KUZNYECHIKOMAC_IDX 13
# define SSL_MAX_DIGEST 14

#define SSL_MD_NUM_IDX  SSL_MAX_DIGEST
#else
# define SSL_MAX_DIGEST 12
#endif

/* Bits for algorithm2 (handshake digests and other extra flags) */

/* Bits 0-7 are handshake MAC */
# define SSL_HANDSHAKE_MAC_MASK  0xFF
# define SSL_HANDSHAKE_MAC_MD5_SHA1 SSL_MD_MD5_SHA1_IDX
# define SSL_HANDSHAKE_MAC_SHA256   SSL_MD_SHA256_IDX
# define SSL_HANDSHAKE_MAC_SHA384   SSL_MD_SHA384_IDX
# define SSL_HANDSHAKE_MAC_GOST94 SSL_MD_GOST94_IDX
# define SSL_HANDSHAKE_MAC_GOST12_256 SSL_MD_GOST12_256_IDX
# define SSL_HANDSHAKE_MAC_GOST12_512 SSL_MD_GOST12_512_IDX
# define SSL_HANDSHAKE_MAC_DEFAULT  SSL_HANDSHAKE_MAC_MD5_SHA1

/* Bits 8-15 bits are PRF */
# define TLS1_PRF_DGST_SHIFT 8
# define TLS1_PRF_SHA1_MD5 (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256 (SSL_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384 (SSL_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST94 (SSL_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_256 (SSL_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_512 (SSL_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF            (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)

/*
 * Stream MAC for GOST ciphersuites from cryptopro draft (currently this also
 * goes into algorithm2)
 */
# define TLS1_STREAM_MAC 0x10000
#else
/* Bits for algorithm2 (handshake digests and other extra flags) */

# define SSL_HANDSHAKE_MAC_MD5 0x10
# define SSL_HANDSHAKE_MAC_SHA 0x20
# define SSL_HANDSHAKE_MAC_GOST94 0x40
# define SSL_HANDSHAKE_MAC_SHA256 0x80
# define SSL_HANDSHAKE_MAC_SHA384 0x100
# define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)

/*
 * When adding new digest in the ssl_ciph.c and increment SSM_MD_NUM_IDX make
 * sure to update this constant too
 */
# define SSL_MAX_DIGEST 6

# define TLS1_PRF_DGST_MASK      (0xff << TLS1_PRF_DGST_SHIFT)

# define TLS1_PRF_DGST_SHIFT 10
# define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST94 (SSL_HANDSHAKE_MAC_GOST94 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)

/*
 * Stream MAC for GOST ciphersuites from cryptopro draft (currently this also
 * goes into algorithm2)
 */
# define TLS1_STREAM_MAC 0x04
#endif

#define SSL_MD_NUM_IDX  SSL_MAX_DIGEST

# define SSL_kRSAPSK             0x00000040U
# define SSL_kECDHEPSK           0x00000080U
# define SSL_kDHEPSK             0x00000100U

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/*
 * Define the Bitmasks for SSL_CIPHER.algorithms.
 * This bits are used packed as dense as possible. If new methods/ciphers
 * etc will be added, the bits a likely to change, so this information
 * is for internal library use only, even though SSL_CIPHER.algorithms
 * can be publicly accessed.
 * Use the according functions for cipher management instead.
 *
 * The bit mask handling in the selection and sorting scheme in
 * ssl_create_cipher_list() has only limited capabilities, reflecting
 * that the different entities within are mutually exclusive:
 * ONLY ONE BIT PER MASK CAN BE SET AT A TIME.
 */

/* Bits for algorithm_mkey (key exchange algorithm) */
/* RSA key exchange */
# define SSL_kRSA                0x00000001U
/* tmp DH key no DH cert */
# define SSL_kDHE                0x00000002U
/* synonym */
# define SSL_kEDH                SSL_kDHE
/* ephemeral ECDH */
# define SSL_kECDHE              0x00000004U
/* synonym */
# define SSL_kEECDH              SSL_kECDHE
/* PSK */
# define SSL_kPSK                0x00000008U
/* GOST key exchange */
# define SSL_kGOST               0x00000010U
/* SRP */
# define SSL_kSRP                0x00000020U


/* all PSK */

# define SSL_PSK     (SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK)

/* Any appropriate key exchange algorithm (for TLS 1.3 ciphersuites) */
# define SSL_kANY                0x00000000U

/* Bits for algorithm_auth (server authentication) */
/* RSA auth */
# define SSL_aRSA                0x00000001U
/* DSS auth */
# define SSL_aDSS                0x00000002U
/* no auth (i.e. use ADH or AECDH) */
# define SSL_aNULL               0x00000004U
/* ECDSA auth*/
# define SSL_aECDSA              0x00000008U
/* PSK auth */
# define SSL_aPSK                0x00000010U
/* GOST R 34.10-2001 signature auth */
# define SSL_aGOST01             0x00000020U
/* SRP auth */
# define SSL_aSRP                0x00000040U
/* GOST R 34.10-2012 signature auth */
# define SSL_aGOST12             0x00000080U
/* Any appropriate signature auth (for TLS 1.3 ciphersuites) */
# define SSL_aANY                0x00000000U
/* All bits requiring a certificate */
#define SSL_aCERT \
    (SSL_aRSA | SSL_aDSS | SSL_aECDSA | SSL_aGOST01 | SSL_aGOST12)
#else
/*
 * Define the Bitmasks for SSL_CIPHER.algorithms.
 * This bits are used packed as dense as possible. If new methods/ciphers
 * etc will be added, the bits a likely to change, so this information
 * is for internal library use only, even though SSL_CIPHER.algorithms
 * can be publicly accessed.
 * Use the according functions for cipher management instead.
 *
 * The bit mask handling in the selection and sorting scheme in
 * ssl_create_cipher_list() has only limited capabilities, reflecting
 * that the different entities within are mutually exclusive:
 * ONLY ONE BIT PER MASK CAN BE SET AT A TIME.
 */

/* Bits for algorithm_mkey (key exchange algorithm) */
/* RSA key exchange */
# define SSL_kRSA                0x00000001L
/* DH cert, RSA CA cert */
# define SSL_kDHr                0x00000002L
/* DH cert, DSA CA cert */
# define SSL_kDHd                0x00000004L
/* tmp DH key no DH cert */
# define SSL_kEDH                0x00000008L
/* forward-compatible synonym */
# define SSL_kDHE                SSL_kEDH
/* Kerberos5 key exchange */
# define SSL_kKRB5               0x00000010L
/* ECDH cert, RSA CA cert */
# define SSL_kECDHr              0x00000020L
/* ECDH cert, ECDSA CA cert */
# define SSL_kECDHe              0x00000040L
/* ephemeral ECDH */
# define SSL_kEECDH              0x00000080L
/* forward-compatible synonym */
# define SSL_kECDHE              SSL_kEECDH
/* PSK */
# define SSL_kPSK                0x00000100L
/* GOST key exchange */
# define SSL_kGOST       0x00000200L
/* SRP */
# define SSL_kSRP        0x00000400L

/* Bits for algorithm_auth (server authentication) */
/* RSA auth */
# define SSL_aRSA                0x00000001L
/* DSS auth */
# define SSL_aDSS                0x00000002L
/* no auth (i.e. use ADH or AECDH) */
# define SSL_aNULL               0x00000004L
/* Fixed DH auth (kDHd or kDHr) */
# define SSL_aDH                 0x00000008L
/* Fixed ECDH auth (kECDHe or kECDHr) */
# define SSL_aECDH               0x00000010L
/* KRB5 auth */
# define SSL_aKRB5               0x00000020L
/* ECDSA auth*/
# define SSL_aECDSA              0x00000040L
/* PSK auth */
# define SSL_aPSK                0x00000080L
/* GOST R 34.10-94 signature auth */
# define SSL_aGOST94                             0x00000100L
/* GOST R 34.10-2001 signature auth */
# define SSL_aGOST01                     0x00000200L
/* SRP auth */
# define SSL_aSRP                0x00000400L
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

/* Bits for algorithm_enc (symmetric encryption) */
# define SSL_DES                 0x00000001L
# define SSL_3DES                0x00000002L
# define SSL_RC4                 0x00000004L
# define SSL_RC2                 0x00000008L
# define SSL_IDEA                0x00000010L
# define SSL_eNULL               0x00000020L
# define SSL_AES128              0x00000040L
# define SSL_AES256              0x00000080L
# define SSL_CAMELLIA128         0x00000100L
# define SSL_CAMELLIA256         0x00000200L
# define SSL_eGOST2814789CNT     0x00000400L
# define SSL_SEED                0x00000800L
# define SSL_AES128GCM           0x00001000L
# define SSL_AES256GCM           0x00002000L
# define SSL_AES128CCM           0x00004000U
# define SSL_AES256CCM           0x00008000U
# define SSL_AES128CCM8          0x00010000U
# define SSL_AES256CCM8          0x00020000U
# define SSL_eGOST2814789CNT12   0x00040000U
# define SSL_CHACHA20POLY1305    0x00080000U
# define SSL_ARIA128GCM          0x00100000U
# define SSL_ARIA256GCM          0x00200000U

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
# define SSL_AESGCM              (SSL_AES128GCM | SSL_AES256GCM)
# define SSL_AESCCM              (SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8)
# define SSL_AES                 (SSL_AES128|SSL_AES256|SSL_AESGCM|SSL_AESCCM)
# define SSL_CAMELLIA            (SSL_CAMELLIA128|SSL_CAMELLIA256)
# define SSL_CHACHA20            (SSL_CHACHA20POLY1305)
# define SSL_ARIAGCM             (SSL_ARIA128GCM | SSL_ARIA256GCM)
# define SSL_ARIA                (SSL_ARIAGCM)
#else
# define SSL_AES                 (SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM | SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8)
# define SSL_CHACHA20            (SSL_CHACHA20POLY1305)
# define SSL_CAMELLIA            (SSL_CAMELLIA128|SSL_CAMELLIA256)
#endif

/* Bits for algorithm_ssl (protocol version) */
# define SSL_SSLV2               0x00000001UL
# define SSL_SSLV3               0x00000002UL
# define SSL_TLSV1               SSL_SSLV3/* for now */
# define SSL_TLSV1_2             0x00000004UL
# define SSL_TLSV1_3             0x00000008UL

/* OpenSSL version macros */
# define SSL2_VERSION            0x0002
# define SSL2_VERSION_MAJOR      0x00
# define SSL2_VERSION_MINOR      0x02

# define SSL3_VERSION            0x0300
# define SSL3_VERSION_MAJOR      0x03
# define SSL3_VERSION_MINOR      0x00

# define SSL3_RT_ALERT             21

/* Special value for method supporting multiple versions */
# define TLS_ANY_VERSION         0x10000

# define TLS1_VERSION            0x0301
# define TLS1_1_VERSION          0x0302
# define TLS1_2_VERSION          0x0303
# define TLS1_3_VERSION          0x0304
# define TLS1_VERSION_MAJOR      0x03

# define TLS1_VERSION_MAJOR      0x03
# define TLS1_VERSION_MINOR      0x01

# define TLS1_1_VERSION_MAJOR    0x03
# define TLS1_1_VERSION_MINOR    0x02

# define TLS1_2_VERSION_MAJOR    0x03
# define TLS1_2_VERSION_MINOR    0x03

# define TLS1_3_VERSION_MAJOR    0x03
# define TLS1_3_VERSION_MINOR    0x04

# define DTLS1_VERSION           0xFEFF
# define DTLS1_2_VERSION         0xFEFD
# define DTLS1_VERSION_MAJOR     0xFE

# define DTLS1_BAD_VER                   0x0100

/* Special value for method supporting multiple versions */
# define DTLS_ANY_VERSION        0x1FFFF

/* These are used to specify which ciphers to use and not to use */

# define SSL_TXT_EXP40           "EXPORT40"
# define SSL_TXT_EXP56           "EXPORT56"
# define SSL_TXT_LOW             "LOW"
# define SSL_TXT_MEDIUM          "MEDIUM"
# define SSL_TXT_HIGH            "HIGH"
# define SSL_TXT_FIPS            "FIPS"

# define SSL_TXT_kFZA            "kFZA"/* unused! */
# define SSL_TXT_aFZA            "aFZA"/* unused! */
# define SSL_TXT_eFZA            "eFZA"/* unused! */
# define SSL_TXT_FZA             "FZA"/* unused! */

# define SSL_TXT_aNULL           "aNULL"
# define SSL_TXT_eNULL           "eNULL"
# define SSL_TXT_NULL            "NULL"

# define SSL_TXT_kRSA            "kRSA"
# define SSL_TXT_kDHr            "kDHr"
# define SSL_TXT_kDHd            "kDHd"
# define SSL_TXT_kDH             "kDH"
# define SSL_TXT_kEDH            "kEDH"
# define SSL_TXT_kDHE            "kDHE"/* alias for kEDH */
# define SSL_TXT_kKRB5           "kKRB5"
# define SSL_TXT_kECDHr          "kECDHr"
# define SSL_TXT_kECDHe          "kECDHe"
# define SSL_TXT_kECDH           "kECDH"
# define SSL_TXT_kEECDH          "kEECDH"
# define SSL_TXT_kECDHE          "kECDHE"/* alias for kEECDH */
# define SSL_TXT_kPSK            "kPSK"
# define SSL_TXT_kRSAPSK         "kRSAPSK"
# define SSL_TXT_kECDHEPSK       "kECDHEPSK"
# define SSL_TXT_kDHEPSK         "kDHEPSK"
# define SSL_TXT_kGOST           "kGOST"
# define SSL_TXT_kSRP            "kSRP"

# define SSL_TXT_aRSA            "aRSA"
# define SSL_TXT_aDSS            "aDSS"
# define SSL_TXT_aDH             "aDH"
# define SSL_TXT_aECDH           "aECDH"
# define SSL_TXT_aKRB5           "aKRB5"
# define SSL_TXT_aECDSA          "aECDSA"
# define SSL_TXT_aPSK            "aPSK"
# define SSL_TXT_aGOST94         "aGOST94"
# define SSL_TXT_aGOST01         "aGOST01"
# define SSL_TXT_aGOST12         "aGOST12"
# define SSL_TXT_aGOST           "aGOST"
# define SSL_TXT_aSRP            "aSRP"

# define SSL_TXT_DSS             "DSS"
# define SSL_TXT_DH              "DH"
# define SSL_TXT_EDH             "EDH"/* same as "kEDH:-ADH" */
# define SSL_TXT_DHE             "DHE"/* alias for EDH */
# define SSL_TXT_ADH             "ADH"
# define SSL_TXT_RSA             "RSA"
# define SSL_TXT_ECDH            "ECDH"
# define SSL_TXT_EECDH           "EECDH"/* same as "kEECDH:-AECDH" */
# define SSL_TXT_ECDHE           "ECDHE"/* alias for ECDHE" */
# define SSL_TXT_AECDH           "AECDH"
# define SSL_TXT_ECDSA           "ECDSA"
# define SSL_TXT_KRB5            "KRB5"
# define SSL_TXT_PSK             "PSK"
# define SSL_TXT_SRP             "SRP"

# define SSL_TXT_DES             "DES"
# define SSL_TXT_3DES            "3DES"
# define SSL_TXT_RC4             "RC4"
# define SSL_TXT_RC2             "RC2"
# define SSL_TXT_IDEA            "IDEA"
# define SSL_TXT_SEED            "SEED"
# define SSL_TXT_AES128          "AES128"
# define SSL_TXT_AES256          "AES256"
# define SSL_TXT_AES             "AES"
# define SSL_TXT_AES_GCM         "AESGCM"
# define SSL_TXT_AES_CCM         "AESCCM"
# define SSL_TXT_AES_CCM_8       "AESCCM8"
# define SSL_TXT_CAMELLIA128     "CAMELLIA128"
# define SSL_TXT_CAMELLIA256     "CAMELLIA256"
# define SSL_TXT_CAMELLIA        "CAMELLIA"
# define SSL_TXT_CHACHA20        "CHACHA20"
# define SSL_TXT_GOST            "GOST89"
# define SSL_TXT_ARIA            "ARIA"
# define SSL_TXT_ARIA_GCM        "ARIAGCM"
# define SSL_TXT_ARIA128         "ARIA128"
# define SSL_TXT_ARIA256         "ARIA256"

# define SSL_TXT_MD5             "MD5"
# define SSL_TXT_SHA1            "SHA1"
# define SSL_TXT_SHA             "SHA"/* same as "SHA1" */
# define SSL_TXT_GOST94          "GOST94"
# define SSL_TXT_GOST89MAC       "GOST89MAC"
# define SSL_TXT_GOST12          "GOST12"
# define SSL_TXT_GOST89MAC12     "GOST89MAC12"
# define SSL_TXT_SHA256          "SHA256"
# define SSL_TXT_SHA384          "SHA384"

# define SSL_TXT_SSLV2           "SSLv2"
# define SSL_TXT_SSLV3           "SSLv3"
# define SSL_TXT_TLSV1           "TLSv1"
# define SSL_TXT_TLSV1_1         "TLSv1.1"
# define SSL_TXT_TLSV1_2         "TLSv1.2"

# define SSL_TXT_EXP             "EXP"
# define SSL_TXT_EXPORT          "EXPORT"

# define SSL_TXT_ALL             "ALL"


/* Cipher Kind Values for SSL2*/
# define SSL2_CK_NULL_WITH_MD5                   0x02000000/* v3 */
# define SSL2_CK_RC4_128_WITH_MD5                0x02010080
# define SSL2_CK_RC4_128_EXPORT40_WITH_MD5       0x02020080
# define SSL2_CK_RC2_128_CBC_WITH_MD5            0x02030080
# define SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5   0x02040080
# define SSL2_CK_IDEA_128_CBC_WITH_MD5           0x02050080
# define SSL2_CK_DES_64_CBC_WITH_MD5             0x02060040
# define SSL2_CK_DES_64_CBC_WITH_SHA             0x02060140/* v3 */
# define SSL2_CK_DES_192_EDE3_CBC_WITH_MD5       0x020700c0
# define SSL2_CK_DES_192_EDE3_CBC_WITH_SHA       0x020701c0/* v3 */
# define SSL2_CK_RC4_64_WITH_MD5                 0x02080080/* MS hack */

# define SSL2_CK_DES_64_CFB64_WITH_MD5_1         0x02ff0800/* SSLeay */
# define SSL2_CK_NULL                            0x02ff0810/* SSLeay */

/* draft-ietf-tls-chacha20-poly1305-03 */
# define TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305         0x0300CCA8
# define TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       0x0300CCA9
# define TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305           0x0300CCAA
# define TLS1_CK_PSK_WITH_CHACHA20_POLY1305               0x0300CCAB
# define TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305         0x0300CCAC
# define TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305           0x0300CCAD
# define TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305           0x0300CCAE

/* draft-ietf-tls-chacha20-poly1305-03 */
# define TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305         "ECDHE-RSA-CHACHA20-POLY1305"
# define TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       "ECDHE-ECDSA-CHACHA20-POLY1305"
# define TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305           "DHE-RSA-CHACHA20-POLY1305"
# define TLS1_TXT_PSK_WITH_CHACHA20_POLY1305               "PSK-CHACHA20-POLY1305"
# define TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305         "ECDHE-PSK-CHACHA20-POLY1305"
# define TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305           "DHE-PSK-CHACHA20-POLY1305"
# define TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305           "RSA-PSK-CHACHA20-POLY1305"

# define SSL2_TXT_DES_64_CFB64_WITH_MD5_1        "DES-CFB-M1"
# define SSL2_TXT_NULL_WITH_MD5                  "NULL-MD5"
# define SSL2_TXT_RC4_128_WITH_MD5               "RC4-MD5"
# define SSL2_TXT_RC4_128_EXPORT40_WITH_MD5      "EXP-RC4-MD5"
# define SSL2_TXT_RC2_128_CBC_WITH_MD5           "RC2-CBC-MD5"
# define SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5  "EXP-RC2-CBC-MD5"
# define SSL2_TXT_IDEA_128_CBC_WITH_MD5          "IDEA-CBC-MD5"
# define SSL2_TXT_DES_64_CBC_WITH_MD5            "DES-CBC-MD5"
# define SSL2_TXT_DES_64_CBC_WITH_SHA            "DES-CBC-SHA"
# define SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5      "DES-CBC3-MD5"
# define SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA      "DES-CBC3-SHA"
# define SSL2_TXT_RC4_64_WITH_MD5                "RC4-64-MD5"
# define SSL2_TXT_NULL                           "NULL"

# define SSL3_TXT_RSA_NULL_MD5                   "NULL-MD5"
# define SSL3_TXT_RSA_NULL_SHA                   "NULL-SHA"
# define SSL3_TXT_RSA_RC4_40_MD5                 "EXP-RC4-MD5"
# define SSL3_TXT_RSA_RC4_128_MD5                "RC4-MD5"
# define SSL3_TXT_RSA_RC4_128_SHA                "RC4-SHA"
# define SSL3_TXT_RSA_RC2_40_MD5                 "EXP-RC2-CBC-MD5"
# define SSL3_TXT_RSA_IDEA_128_SHA               "IDEA-CBC-SHA"
# define SSL3_TXT_RSA_DES_40_CBC_SHA             "EXP-DES-CBC-SHA"
# define SSL3_TXT_RSA_DES_64_CBC_SHA             "DES-CBC-SHA"
# define SSL3_TXT_RSA_DES_192_CBC3_SHA           "DES-CBC3-SHA"

# define SSL3_TXT_DH_DSS_DES_40_CBC_SHA          "EXP-DH-DSS-DES-CBC-SHA"
# define SSL3_TXT_DH_DSS_DES_64_CBC_SHA          "DH-DSS-DES-CBC-SHA"
# define SSL3_TXT_DH_DSS_DES_192_CBC3_SHA        "DH-DSS-DES-CBC3-SHA"
# define SSL3_TXT_DH_RSA_DES_40_CBC_SHA          "EXP-DH-RSA-DES-CBC-SHA"
# define SSL3_TXT_DH_RSA_DES_64_CBC_SHA          "DH-RSA-DES-CBC-SHA"
# define SSL3_TXT_DH_RSA_DES_192_CBC3_SHA        "DH-RSA-DES-CBC3-SHA"

# define SSL3_TXT_DHE_DSS_DES_40_CBC_SHA         "EXP-DHE-DSS-DES-CBC-SHA"
# define SSL3_TXT_DHE_DSS_DES_64_CBC_SHA         "DHE-DSS-DES-CBC-SHA"
# define SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA       "DHE-DSS-DES-CBC3-SHA"
# define SSL3_TXT_DHE_RSA_DES_40_CBC_SHA         "EXP-DHE-RSA-DES-CBC-SHA"
# define SSL3_TXT_DHE_RSA_DES_64_CBC_SHA         "DHE-RSA-DES-CBC-SHA"
# define SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA       "DHE-RSA-DES-CBC3-SHA"

/*
 * This next block of six "EDH" labels is for backward compatibility with
 * older versions of OpenSSL.  New code should use the six "DHE" labels above
 * instead:
 */
# define SSL3_TXT_EDH_DSS_DES_40_CBC_SHA         "EXP-EDH-DSS-DES-CBC-SHA"
# define SSL3_TXT_EDH_DSS_DES_64_CBC_SHA         "EDH-DSS-DES-CBC-SHA"
# define SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA       "EDH-DSS-DES-CBC3-SHA"
# define SSL3_TXT_EDH_RSA_DES_40_CBC_SHA         "EXP-EDH-RSA-DES-CBC-SHA"
# define SSL3_TXT_EDH_RSA_DES_64_CBC_SHA         "EDH-RSA-DES-CBC-SHA"
# define SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA       "EDH-RSA-DES-CBC3-SHA"

# define SSL3_TXT_ADH_RC4_40_MD5                 "EXP-ADH-RC4-MD5"
# define SSL3_TXT_ADH_RC4_128_MD5                "ADH-RC4-MD5"
# define SSL3_TXT_ADH_DES_40_CBC_SHA             "EXP-ADH-DES-CBC-SHA"
# define SSL3_TXT_ADH_DES_64_CBC_SHA             "ADH-DES-CBC-SHA"
# define SSL3_TXT_ADH_DES_192_CBC_SHA            "ADH-DES-CBC3-SHA"

# define SSL3_CK_FALLBACK_SCSV                   0x03005600

# define SSL3_CK_RSA_NULL_MD5                    0x03000001
# define SSL3_CK_RSA_NULL_SHA                    0x03000002
# define SSL3_CK_RSA_RC4_40_MD5                  0x03000003
# define SSL3_CK_RSA_RC4_128_MD5                 0x03000004
# define SSL3_CK_RSA_RC4_128_SHA                 0x03000005
# define SSL3_CK_RSA_RC2_40_MD5                  0x03000006
# define SSL3_CK_RSA_IDEA_128_SHA                0x03000007
# define SSL3_CK_RSA_DES_40_CBC_SHA              0x03000008
# define SSL3_CK_RSA_DES_64_CBC_SHA              0x03000009
# define SSL3_CK_RSA_DES_192_CBC3_SHA            0x0300000A

# define SSL3_CK_DH_DSS_DES_40_CBC_SHA           0x0300000B
# define SSL3_CK_DH_DSS_DES_64_CBC_SHA           0x0300000C
# define SSL3_CK_DH_DSS_DES_192_CBC3_SHA         0x0300000D
# define SSL3_CK_DH_RSA_DES_40_CBC_SHA           0x0300000E
# define SSL3_CK_DH_RSA_DES_64_CBC_SHA           0x0300000F
# define SSL3_CK_DH_RSA_DES_192_CBC3_SHA         0x03000010

# define SSL3_CK_EDH_DSS_DES_40_CBC_SHA          0x03000011
# define SSL3_CK_DHE_DSS_DES_40_CBC_SHA          SSL3_CK_EDH_DSS_DES_40_CBC_SHA
# define SSL3_CK_EDH_DSS_DES_64_CBC_SHA          0x03000012
# define SSL3_CK_DHE_DSS_DES_64_CBC_SHA          SSL3_CK_EDH_DSS_DES_64_CBC_SHA
# define SSL3_CK_EDH_DSS_DES_192_CBC3_SHA        0x03000013
# define SSL3_CK_DHE_DSS_DES_192_CBC3_SHA        SSL3_CK_EDH_DSS_DES_192_CBC3_SHA
# define SSL3_CK_EDH_RSA_DES_40_CBC_SHA          0x03000014
# define SSL3_CK_DHE_RSA_DES_40_CBC_SHA          SSL3_CK_EDH_RSA_DES_40_CBC_SHA
# define SSL3_CK_EDH_RSA_DES_64_CBC_SHA          0x03000015
# define SSL3_CK_DHE_RSA_DES_64_CBC_SHA          SSL3_CK_EDH_RSA_DES_64_CBC_SHA
# define SSL3_CK_EDH_RSA_DES_192_CBC3_SHA        0x03000016
# define SSL3_CK_DHE_RSA_DES_192_CBC3_SHA        SSL3_CK_EDH_RSA_DES_192_CBC3_SHA

# define SSL3_CK_ADH_RC4_40_MD5                  0x03000017
# define SSL3_CK_ADH_RC4_128_MD5                 0x03000018
# define SSL3_CK_ADH_DES_40_CBC_SHA              0x03000019
# define SSL3_CK_ADH_DES_64_CBC_SHA              0x0300001A
# define SSL3_CK_ADH_DES_192_CBC_SHA             0x0300001B

# define TLS1_TXT_RSA_WITH_AES_128_SHA                   "AES128-SHA"
# define TLS1_TXT_DH_DSS_WITH_AES_128_SHA                "DH-DSS-AES128-SHA"
# define TLS1_TXT_DH_RSA_WITH_AES_128_SHA                "DH-RSA-AES128-SHA"
# define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA               "DHE-DSS-AES128-SHA"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA               "DHE-RSA-AES128-SHA"
# define TLS1_TXT_ADH_WITH_AES_128_SHA                   "ADH-AES128-SHA"

# define TLS1_TXT_RSA_WITH_AES_256_SHA                   "AES256-SHA"
# define TLS1_TXT_DH_DSS_WITH_AES_256_SHA                "DH-DSS-AES256-SHA"
# define TLS1_TXT_DH_RSA_WITH_AES_256_SHA                "DH-RSA-AES256-SHA"
# define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA               "DHE-DSS-AES256-SHA"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA               "DHE-RSA-AES256-SHA"
# define TLS1_TXT_ADH_WITH_AES_256_SHA                   "ADH-AES256-SHA"

/* ECC ciphersuites from RFC4492 */
# define TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA               "ECDH-ECDSA-NULL-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA            "ECDH-ECDSA-RC4-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA       "ECDH-ECDSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA        "ECDH-ECDSA-AES128-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA        "ECDH-ECDSA-AES256-SHA"

# define TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA              "ECDHE-ECDSA-NULL-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA           "ECDHE-ECDSA-RC4-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA      "ECDHE-ECDSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       "ECDHE-ECDSA-AES128-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       "ECDHE-ECDSA-AES256-SHA"

# define TLS1_TXT_ECDH_RSA_WITH_NULL_SHA                 "ECDH-RSA-NULL-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA              "ECDH-RSA-RC4-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA         "ECDH-RSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA          "ECDH-RSA-AES128-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA          "ECDH-RSA-AES256-SHA"

# define TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA                "ECDHE-RSA-NULL-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA             "ECDHE-RSA-RC4-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA        "ECDHE-RSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA         "ECDHE-RSA-AES128-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA         "ECDHE-RSA-AES256-SHA"

# define TLS1_TXT_ECDH_anon_WITH_NULL_SHA                "AECDH-NULL-SHA"
# define TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA             "AECDH-RC4-SHA"
# define TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA        "AECDH-DES-CBC3-SHA"
# define TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA         "AECDH-AES128-SHA"
# define TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA         "AECDH-AES256-SHA"

/* PSK ciphersuites from RFC 4279 */
# define TLS1_TXT_PSK_WITH_RC4_128_SHA                   "PSK-RC4-SHA"
# define TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA              "PSK-3DES-EDE-CBC-SHA"
# define TLS1_TXT_PSK_WITH_AES_128_CBC_SHA               "PSK-AES128-CBC-SHA"
# define TLS1_TXT_PSK_WITH_AES_256_CBC_SHA               "PSK-AES256-CBC-SHA"

/* SRP ciphersuite from RFC 5054 */
# define TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA          "SRP-3DES-EDE-CBC-SHA"
# define TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA      "SRP-RSA-3DES-EDE-CBC-SHA"
# define TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA      "SRP-DSS-3DES-EDE-CBC-SHA"
# define TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA           "SRP-AES-128-CBC-SHA"
# define TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA       "SRP-RSA-AES-128-CBC-SHA"
# define TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA       "SRP-DSS-AES-128-CBC-SHA"
# define TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA           "SRP-AES-256-CBC-SHA"
# define TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA       "SRP-RSA-AES-256-CBC-SHA"
# define TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA       "SRP-DSS-AES-256-CBC-SHA"

/* Camellia ciphersuites from RFC4132 */
# define TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA          "CAMELLIA128-SHA"
# define TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA       "DH-DSS-CAMELLIA128-SHA"
# define TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA       "DH-RSA-CAMELLIA128-SHA"
# define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA      "DHE-DSS-CAMELLIA128-SHA"
# define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA      "DHE-RSA-CAMELLIA128-SHA"
# define TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA          "ADH-CAMELLIA128-SHA"

# define TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA          "CAMELLIA256-SHA"
# define TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA       "DH-DSS-CAMELLIA256-SHA"
# define TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA       "DH-RSA-CAMELLIA256-SHA"
# define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA      "DHE-DSS-CAMELLIA256-SHA"
# define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA      "DHE-RSA-CAMELLIA256-SHA"
# define TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA          "ADH-CAMELLIA256-SHA"

/* SEED ciphersuites from RFC4162 */
# define TLS1_TXT_RSA_WITH_SEED_SHA                      "SEED-SHA"
# define TLS1_TXT_DH_DSS_WITH_SEED_SHA                   "DH-DSS-SEED-SHA"
# define TLS1_TXT_DH_RSA_WITH_SEED_SHA                   "DH-RSA-SEED-SHA"
# define TLS1_TXT_DHE_DSS_WITH_SEED_SHA                  "DHE-DSS-SEED-SHA"
# define TLS1_TXT_DHE_RSA_WITH_SEED_SHA                  "DHE-RSA-SEED-SHA"
# define TLS1_TXT_ADH_WITH_SEED_SHA                      "ADH-SEED-SHA"

/* TLS v1.2 ciphersuites */
# define TLS1_TXT_RSA_WITH_NULL_SHA256                   "NULL-SHA256"
# define TLS1_TXT_RSA_WITH_AES_128_SHA256                "AES128-SHA256"
# define TLS1_TXT_RSA_WITH_AES_256_SHA256                "AES256-SHA256"
# define TLS1_TXT_DH_DSS_WITH_AES_128_SHA256             "DH-DSS-AES128-SHA256"
# define TLS1_TXT_DH_RSA_WITH_AES_128_SHA256             "DH-RSA-AES128-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256            "DHE-DSS-AES128-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256            "DHE-RSA-AES128-SHA256"
# define TLS1_TXT_DH_DSS_WITH_AES_256_SHA256             "DH-DSS-AES256-SHA256"
# define TLS1_TXT_DH_RSA_WITH_AES_256_SHA256             "DH-RSA-AES256-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256            "DHE-DSS-AES256-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256            "DHE-RSA-AES256-SHA256"
# define TLS1_TXT_ADH_WITH_AES_128_SHA256                "ADH-AES128-SHA256"
# define TLS1_TXT_ADH_WITH_AES_256_SHA256                "ADH-AES256-SHA256"

/* TLS v1.2 GCM ciphersuites from RFC5288 */
# define TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256            "AES128-GCM-SHA256"
# define TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384            "AES256-GCM-SHA384"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256        "DHE-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384        "DHE-RSA-AES256-GCM-SHA384"
# define TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256         "DH-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384         "DH-RSA-AES256-GCM-SHA384"
# define TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256        "DHE-DSS-AES128-GCM-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384        "DHE-DSS-AES256-GCM-SHA384"
# define TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256         "DH-DSS-AES128-GCM-SHA256"
# define TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384         "DH-DSS-AES256-GCM-SHA384"
# define TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256            "ADH-AES128-GCM-SHA256"
# define TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384            "ADH-AES256-GCM-SHA384"

/* CCM ciphersuites */
# define TLS1_TXT_RSA_WITH_AES_128_CCM                   "AES128-CCM"
# define TLS1_TXT_RSA_WITH_AES_256_CCM                   "AES256-CCM"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM               "DHE-RSA-AES128-CCM"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM               "DHE-RSA-AES256-CCM"
# define TLS1_TXT_RSA_WITH_AES_128_CCM_8                 "AES128-CCM8"
# define TLS1_TXT_RSA_WITH_AES_256_CCM_8                 "AES256-CCM8"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8             "DHE-RSA-AES128-CCM8"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8             "DHE-RSA-AES256-CCM8"
# define TLS1_TXT_PSK_WITH_AES_128_CCM                   "PSK-AES128-CCM"
# define TLS1_TXT_PSK_WITH_AES_256_CCM                   "PSK-AES256-CCM"
# define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM               "DHE-PSK-AES128-CCM"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM               "DHE-PSK-AES256-CCM"
# define TLS1_TXT_PSK_WITH_AES_128_CCM_8                 "PSK-AES128-CCM8"
# define TLS1_TXT_PSK_WITH_AES_256_CCM_8                 "PSK-AES256-CCM8"
# define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8             "DHE-PSK-AES128-CCM8"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8             "DHE-PSK-AES256-CCM8"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM           "ECDHE-ECDSA-AES128-CCM"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM           "ECDHE-ECDSA-AES256-CCM"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8         "ECDHE-ECDSA-AES128-CCM8"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8         "ECDHE-ECDSA-AES256-CCM8"

# define TLS1_RFC_RSA_WITH_AES_128_CCM                   "TLS_RSA_WITH_AES_128_CCM"
# define TLS1_RFC_RSA_WITH_AES_256_CCM                   "TLS_RSA_WITH_AES_256_CCM"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_CCM               "TLS_DHE_RSA_WITH_AES_128_CCM"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_CCM               "TLS_DHE_RSA_WITH_AES_256_CCM"
# define TLS1_RFC_RSA_WITH_AES_128_CCM_8                 "TLS_RSA_WITH_AES_128_CCM_8"
# define TLS1_RFC_RSA_WITH_AES_256_CCM_8                 "TLS_RSA_WITH_AES_256_CCM_8"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8             "TLS_DHE_RSA_WITH_AES_128_CCM_8"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8             "TLS_DHE_RSA_WITH_AES_256_CCM_8"
# define TLS1_RFC_PSK_WITH_AES_128_CCM                   "TLS_PSK_WITH_AES_128_CCM"
# define TLS1_RFC_PSK_WITH_AES_256_CCM                   "TLS_PSK_WITH_AES_256_CCM"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_CCM               "TLS_DHE_PSK_WITH_AES_128_CCM"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_CCM               "TLS_DHE_PSK_WITH_AES_256_CCM"
# define TLS1_RFC_PSK_WITH_AES_128_CCM_8                 "TLS_PSK_WITH_AES_128_CCM_8"
# define TLS1_RFC_PSK_WITH_AES_256_CCM_8                 "TLS_PSK_WITH_AES_256_CCM_8"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8             "TLS_PSK_DHE_WITH_AES_128_CCM_8"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8             "TLS_PSK_DHE_WITH_AES_256_CCM_8"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM           "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM           "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8         "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8         "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"

# define TLS1_CK_RSA_WITH_AES_128_CCM                    0x0300C09C
# define TLS1_CK_RSA_WITH_AES_256_CCM                    0x0300C09D
# define TLS1_CK_DHE_RSA_WITH_AES_128_CCM                0x0300C09E
# define TLS1_CK_DHE_RSA_WITH_AES_256_CCM                0x0300C09F
# define TLS1_CK_RSA_WITH_AES_128_CCM_8                  0x0300C0A0
# define TLS1_CK_RSA_WITH_AES_256_CCM_8                  0x0300C0A1
# define TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8              0x0300C0A2
# define TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8              0x0300C0A3
# define TLS1_CK_PSK_WITH_AES_128_CCM                    0x0300C0A4
# define TLS1_CK_PSK_WITH_AES_256_CCM                    0x0300C0A5
# define TLS1_CK_DHE_PSK_WITH_AES_128_CCM                0x0300C0A6
# define TLS1_CK_DHE_PSK_WITH_AES_256_CCM                0x0300C0A7
# define TLS1_CK_PSK_WITH_AES_128_CCM_8                  0x0300C0A8
# define TLS1_CK_PSK_WITH_AES_256_CCM_8                  0x0300C0A9
# define TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8              0x0300C0AA
# define TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8              0x0300C0AB
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM            0x0300C0AC
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM            0x0300C0AD
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8          0x0300C0AE
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8          0x0300C0AF

/* TLS v1.3 ciphersuites */
# define TLS1_3_RFC_AES_128_GCM_SHA256                   "TLS_AES_128_GCM_SHA256"
# define TLS1_3_RFC_AES_256_GCM_SHA384                   "TLS_AES_256_GCM_SHA384"
# define TLS1_3_RFC_CHACHA20_POLY1305_SHA256             "TLS_CHACHA20_POLY1305_SHA256"
# define TLS1_3_RFC_AES_128_CCM_SHA256                   "TLS_AES_128_CCM_SHA256"
# define TLS1_3_RFC_AES_128_CCM_8_SHA256                 "TLS_AES_128_CCM_8_SHA256"

# define TLS1_3_RFC_AES_128_GCM_SHA256_2                 "TLS13-AES-128-GCM-SHA256"
# define TLS1_3_RFC_AES_256_GCM_SHA384_2                 "TLS13-AES-256-GCM-SHA256"
# define TLS1_3_RFC_CHACHA20_POLY1305_SHA256_2           "TLS13-AES-128-CCM-SHA256"
# define TLS1_3_RFC_AES_128_CCM_SHA256_2                 "TLS13-AES-128-CCM-8-SHA256"
# define TLS1_3_RFC_AES_128_CCM_8_SHA256_2               "TLS13-CHACHA20-POLY1305-SHA256"

/* TLS v1.3 ciphersuites */
# define TLS1_3_CK_AES_128_GCM_SHA256                     0x03001301
# define TLS1_3_CK_AES_256_GCM_SHA384                     0x03001302
# define TLS1_3_CK_CHACHA20_POLY1305_SHA256               0x03001303
# define TLS1_3_CK_AES_128_CCM_SHA256                     0x03001304
# define TLS1_3_CK_AES_128_CCM_8_SHA256                   0x03001305

/* Aria ciphersuites from RFC6209 */
# define TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256             0x0300C050
# define TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384             0x0300C051
# define TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256         0x0300C052
# define TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384         0x0300C053
# define TLS1_CK_DH_RSA_WITH_ARIA_128_GCM_SHA256          0x0300C054
# define TLS1_CK_DH_RSA_WITH_ARIA_256_GCM_SHA384          0x0300C055
# define TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256         0x0300C056
# define TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384         0x0300C057
# define TLS1_CK_DH_DSS_WITH_ARIA_128_GCM_SHA256          0x0300C058
# define TLS1_CK_DH_DSS_WITH_ARIA_256_GCM_SHA384          0x0300C059
# define TLS1_CK_DH_anon_WITH_ARIA_128_GCM_SHA256         0x0300C05A
# define TLS1_CK_DH_anon_WITH_ARIA_256_GCM_SHA384         0x0300C05B
# define TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     0x0300C05C
# define TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     0x0300C05D
# define TLS1_CK_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      0x0300C05E
# define TLS1_CK_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      0x0300C05F
# define TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       0x0300C060
# define TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       0x0300C061
# define TLS1_CK_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        0x0300C062
# define TLS1_CK_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        0x0300C063
# define TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256             0x0300C06A
# define TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384             0x0300C06B
# define TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256         0x0300C06C
# define TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384         0x0300C06D
# define TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256         0x0300C06E
# define TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384         0x0300C06F

/* a bundle of RFC standard cipher names, generated from ssl3_ciphers[] */
# define TLS1_RFC_RSA_WITH_AES_128_SHA                   "TLS_RSA_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_DHE_DSS_WITH_AES_128_SHA               "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_SHA               "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_ADH_WITH_AES_128_SHA                   "TLS_DH_anon_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_RSA_WITH_AES_256_SHA                   "TLS_RSA_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_DHE_DSS_WITH_AES_256_SHA               "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_SHA               "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_ADH_WITH_AES_256_SHA                   "TLS_DH_anon_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_RSA_WITH_NULL_SHA256                   "TLS_RSA_WITH_NULL_SHA256"
# define TLS1_RFC_RSA_WITH_AES_128_SHA256                "TLS_RSA_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_RSA_WITH_AES_256_SHA256                "TLS_RSA_WITH_AES_256_CBC_SHA256"
# define TLS1_RFC_DHE_DSS_WITH_AES_128_SHA256            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_SHA256            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_DHE_DSS_WITH_AES_256_SHA256            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_SHA256            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
# define TLS1_RFC_ADH_WITH_AES_128_SHA256                "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_ADH_WITH_AES_256_SHA256                "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
# define TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256            "TLS_RSA_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384            "TLS_RSA_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_GCM_SHA256        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_GCM_SHA384        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_DHE_DSS_WITH_AES_128_GCM_SHA256        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_DHE_DSS_WITH_AES_256_GCM_SHA384        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_ADH_WITH_AES_128_GCM_SHA256            "TLS_DH_anon_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_ADH_WITH_AES_256_GCM_SHA384            "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_RSA_WITH_AES_128_CCM                   "TLS_RSA_WITH_AES_128_CCM"
# define TLS1_RFC_RSA_WITH_AES_256_CCM                   "TLS_RSA_WITH_AES_256_CCM"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_CCM               "TLS_DHE_RSA_WITH_AES_128_CCM"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_CCM               "TLS_DHE_RSA_WITH_AES_256_CCM"
# define TLS1_RFC_RSA_WITH_AES_128_CCM_8                 "TLS_RSA_WITH_AES_128_CCM_8"
# define TLS1_RFC_RSA_WITH_AES_256_CCM_8                 "TLS_RSA_WITH_AES_256_CCM_8"
# define TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8             "TLS_DHE_RSA_WITH_AES_128_CCM_8"
# define TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8             "TLS_DHE_RSA_WITH_AES_256_CCM_8"
# define TLS1_RFC_PSK_WITH_AES_128_CCM                   "TLS_PSK_WITH_AES_128_CCM"
# define TLS1_RFC_PSK_WITH_AES_256_CCM                   "TLS_PSK_WITH_AES_256_CCM"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_CCM               "TLS_DHE_PSK_WITH_AES_128_CCM"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_CCM               "TLS_DHE_PSK_WITH_AES_256_CCM"
# define TLS1_RFC_PSK_WITH_AES_128_CCM_8                 "TLS_PSK_WITH_AES_128_CCM_8"
# define TLS1_RFC_PSK_WITH_AES_256_CCM_8                 "TLS_PSK_WITH_AES_256_CCM_8"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8             "TLS_PSK_DHE_WITH_AES_128_CCM_8"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8             "TLS_PSK_DHE_WITH_AES_256_CCM_8"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM           "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM           "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8         "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8         "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
# define TLS1_3_RFC_AES_128_GCM_SHA256                   "TLS_AES_128_GCM_SHA256"
# define TLS1_3_RFC_AES_256_GCM_SHA384                   "TLS_AES_256_GCM_SHA384"
# define TLS1_3_RFC_CHACHA20_POLY1305_SHA256             "TLS_CHACHA20_POLY1305_SHA256"
# define TLS1_3_RFC_AES_128_CCM_SHA256                   "TLS_AES_128_CCM_SHA256"
# define TLS1_3_RFC_AES_128_CCM_8_SHA256                 "TLS_AES_128_CCM_8_SHA256"
# define TLS1_RFC_ECDHE_ECDSA_WITH_NULL_SHA              "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
# define TLS1_RFC_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_ECDHE_RSA_WITH_NULL_SHA                "TLS_ECDHE_RSA_WITH_NULL_SHA"
# define TLS1_RFC_ECDHE_RSA_WITH_DES_192_CBC3_SHA        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_ECDHE_RSA_WITH_AES_128_CBC_SHA         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_ECDHE_RSA_WITH_AES_256_CBC_SHA         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_ECDH_anon_WITH_NULL_SHA                "TLS_ECDH_anon_WITH_NULL_SHA"
# define TLS1_RFC_ECDH_anon_WITH_DES_192_CBC3_SHA        "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_ECDH_anon_WITH_AES_128_CBC_SHA         "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_ECDH_anon_WITH_AES_256_CBC_SHA         "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_SHA256        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_SHA384        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
# define TLS1_RFC_ECDHE_RSA_WITH_AES_128_SHA256          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_ECDHE_RSA_WITH_AES_256_SHA384          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_ECDHE_RSA_WITH_AES_128_GCM_SHA256      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_PSK_WITH_NULL_SHA                      "TLS_PSK_WITH_NULL_SHA"
# define TLS1_RFC_DHE_PSK_WITH_NULL_SHA                  "TLS_DHE_PSK_WITH_NULL_SHA"
# define TLS1_RFC_RSA_PSK_WITH_NULL_SHA                  "TLS_RSA_PSK_WITH_NULL_SHA"
# define TLS1_RFC_PSK_WITH_3DES_EDE_CBC_SHA              "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_PSK_WITH_AES_128_CBC_SHA               "TLS_PSK_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_PSK_WITH_AES_256_CBC_SHA               "TLS_PSK_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_DHE_PSK_WITH_3DES_EDE_CBC_SHA          "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA           "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA           "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_RSA_PSK_WITH_3DES_EDE_CBC_SHA          "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA           "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA           "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_PSK_WITH_AES_128_GCM_SHA256            "TLS_PSK_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_PSK_WITH_AES_256_GCM_SHA384            "TLS_PSK_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_GCM_SHA256        "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_GCM_SHA384        "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_RSA_PSK_WITH_AES_128_GCM_SHA256        "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
# define TLS1_RFC_RSA_PSK_WITH_AES_256_GCM_SHA384        "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
# define TLS1_RFC_PSK_WITH_AES_128_CBC_SHA256            "TLS_PSK_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_PSK_WITH_AES_256_CBC_SHA384            "TLS_PSK_WITH_AES_256_CBC_SHA384"
# define TLS1_RFC_PSK_WITH_NULL_SHA256                   "TLS_PSK_WITH_NULL_SHA256"
# define TLS1_RFC_PSK_WITH_NULL_SHA384                   "TLS_PSK_WITH_NULL_SHA384"
# define TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA256        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA384        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
# define TLS1_RFC_DHE_PSK_WITH_NULL_SHA256               "TLS_DHE_PSK_WITH_NULL_SHA256"
# define TLS1_RFC_DHE_PSK_WITH_NULL_SHA384               "TLS_DHE_PSK_WITH_NULL_SHA384"
# define TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA256        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA384        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
# define TLS1_RFC_RSA_PSK_WITH_NULL_SHA256               "TLS_RSA_PSK_WITH_NULL_SHA256"
# define TLS1_RFC_RSA_PSK_WITH_NULL_SHA384               "TLS_RSA_PSK_WITH_NULL_SHA384"
# define TLS1_RFC_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA        "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA         "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA         "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA256      "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
# define TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA384      "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
# define TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA                "TLS_ECDHE_PSK_WITH_NULL_SHA"
# define TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA256             "TLS_ECDHE_PSK_WITH_NULL_SHA256"
# define TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA384             "TLS_ECDHE_PSK_WITH_NULL_SHA384"
# define TLS1_RFC_SRP_SHA_WITH_3DES_EDE_CBC_SHA          "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA      "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA      "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
# define TLS1_RFC_SRP_SHA_WITH_AES_128_CBC_SHA           "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_SRP_SHA_RSA_WITH_AES_128_CBC_SHA       "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_SRP_SHA_DSS_WITH_AES_128_CBC_SHA       "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
# define TLS1_RFC_SRP_SHA_WITH_AES_256_CBC_SHA           "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_SRP_SHA_RSA_WITH_AES_256_CBC_SHA       "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_SRP_SHA_DSS_WITH_AES_256_CBC_SHA       "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
# define TLS1_RFC_DHE_RSA_WITH_CHACHA20_POLY1305         "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_ECDHE_RSA_WITH_CHACHA20_POLY1305       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_ECDHE_ECDSA_WITH_CHACHA20_POLY1305     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_PSK_WITH_CHACHA20_POLY1305             "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_ECDHE_PSK_WITH_CHACHA20_POLY1305       "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_DHE_PSK_WITH_CHACHA20_POLY1305         "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_RSA_PSK_WITH_CHACHA20_POLY1305         "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"
# define TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA256       "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256   "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA256       "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA256       "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
# define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256   "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
# define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256   "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
# define TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA256       "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"
# define TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA          "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
# define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA      "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
# define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA      "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
# define TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA          "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"
# define TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA          "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
# define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA      "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
# define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA      "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
# define TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA          "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"
# define TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
# define TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"
# define TLS1_RFC_PSK_WITH_CAMELLIA_128_CBC_SHA256       "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_PSK_WITH_CAMELLIA_256_CBC_SHA384       "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"
# define TLS1_RFC_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
# define TLS1_RFC_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256   "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384   "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"
# define TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
# define TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
# define TLS1_RFC_RSA_WITH_SEED_SHA                      "TLS_RSA_WITH_SEED_CBC_SHA"
# define TLS1_RFC_DHE_DSS_WITH_SEED_SHA                  "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
# define TLS1_RFC_DHE_RSA_WITH_SEED_SHA                  "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
# define TLS1_RFC_ADH_WITH_SEED_SHA                      "TLS_DH_anon_WITH_SEED_CBC_SHA"
# define TLS1_RFC_ECDHE_PSK_WITH_RC4_128_SHA             "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
# define TLS1_RFC_ECDH_anon_WITH_RC4_128_SHA             "TLS_ECDH_anon_WITH_RC4_128_SHA"
# define TLS1_RFC_ECDHE_ECDSA_WITH_RC4_128_SHA           "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
# define TLS1_RFC_ECDHE_RSA_WITH_RC4_128_SHA             "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
# define TLS1_RFC_PSK_WITH_RC4_128_SHA                   "TLS_PSK_WITH_RC4_128_SHA"
# define TLS1_RFC_RSA_PSK_WITH_RC4_128_SHA               "TLS_RSA_PSK_WITH_RC4_128_SHA"
# define TLS1_RFC_DHE_PSK_WITH_RC4_128_SHA               "TLS_DHE_PSK_WITH_RC4_128_SHA"
# define TLS1_RFC_RSA_WITH_ARIA_128_GCM_SHA256           "TLS_RSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_RSA_WITH_ARIA_256_GCM_SHA384           "TLS_RSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_DHE_RSA_WITH_ARIA_128_GCM_SHA256       "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_DHE_RSA_WITH_ARIA_256_GCM_SHA384       "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_DH_RSA_WITH_ARIA_128_GCM_SHA256        "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_DH_RSA_WITH_ARIA_256_GCM_SHA384        "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_DHE_DSS_WITH_ARIA_128_GCM_SHA256       "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_DHE_DSS_WITH_ARIA_256_GCM_SHA384       "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_DH_DSS_WITH_ARIA_128_GCM_SHA256        "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_DH_DSS_WITH_ARIA_256_GCM_SHA384        "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_DH_anon_WITH_ARIA_128_GCM_SHA256       "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_DH_anon_WITH_ARIA_256_GCM_SHA384       "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256   "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384   "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256    "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384    "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256     "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384     "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_ECDH_RSA_WITH_ARIA_128_GCM_SHA256      "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_ECDH_RSA_WITH_ARIA_256_GCM_SHA384      "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_PSK_WITH_ARIA_128_GCM_SHA256           "TLS_PSK_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_PSK_WITH_ARIA_256_GCM_SHA384           "TLS_PSK_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_DHE_PSK_WITH_ARIA_128_GCM_SHA256       "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_DHE_PSK_WITH_ARIA_256_GCM_SHA384       "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"
# define TLS1_RFC_RSA_PSK_WITH_ARIA_128_GCM_SHA256       "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"
# define TLS1_RFC_RSA_PSK_WITH_ARIA_256_GCM_SHA384       "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"

/*
 * XXX Backward compatibility alert: Older versions of OpenSSL gave some DHE
 * ciphers names with "EDH" instead of "DHE".  Going forward, we should be
 * using DHE everywhere, though we may indefinitely maintain aliases for
 * users or configurations that used "EDH"
 */
# define TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA               "DHE-DSS-RC4-SHA"

# define TLS1_TXT_PSK_WITH_NULL_SHA                      "PSK-NULL-SHA"
# define TLS1_TXT_DHE_PSK_WITH_NULL_SHA                  "DHE-PSK-NULL-SHA"
# define TLS1_TXT_RSA_PSK_WITH_NULL_SHA                  "RSA-PSK-NULL-SHA"

/* AES ciphersuites from RFC3268 */
# define TLS1_TXT_RSA_WITH_AES_128_SHA                   "AES128-SHA"
# define TLS1_TXT_DH_DSS_WITH_AES_128_SHA                "DH-DSS-AES128-SHA"
# define TLS1_TXT_DH_RSA_WITH_AES_128_SHA                "DH-RSA-AES128-SHA"
# define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA               "DHE-DSS-AES128-SHA"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA               "DHE-RSA-AES128-SHA"
# define TLS1_TXT_ADH_WITH_AES_128_SHA                   "ADH-AES128-SHA"

# define TLS1_TXT_RSA_WITH_AES_256_SHA                   "AES256-SHA"
# define TLS1_TXT_DH_DSS_WITH_AES_256_SHA                "DH-DSS-AES256-SHA"
# define TLS1_TXT_DH_RSA_WITH_AES_256_SHA                "DH-RSA-AES256-SHA"
# define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA               "DHE-DSS-AES256-SHA"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA               "DHE-RSA-AES256-SHA"
# define TLS1_TXT_ADH_WITH_AES_256_SHA                   "ADH-AES256-SHA"

/* ECC ciphersuites from RFC4492 */
# define TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA               "ECDH-ECDSA-NULL-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA            "ECDH-ECDSA-RC4-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA       "ECDH-ECDSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA        "ECDH-ECDSA-AES128-SHA"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA        "ECDH-ECDSA-AES256-SHA"

# define TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA              "ECDHE-ECDSA-NULL-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA           "ECDHE-ECDSA-RC4-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA      "ECDHE-ECDSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       "ECDHE-ECDSA-AES128-SHA"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       "ECDHE-ECDSA-AES256-SHA"

# define TLS1_TXT_ECDH_RSA_WITH_NULL_SHA                 "ECDH-RSA-NULL-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA              "ECDH-RSA-RC4-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA         "ECDH-RSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA          "ECDH-RSA-AES128-SHA"
# define TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA          "ECDH-RSA-AES256-SHA"

# define TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA                "ECDHE-RSA-NULL-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA             "ECDHE-RSA-RC4-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA        "ECDHE-RSA-DES-CBC3-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA         "ECDHE-RSA-AES128-SHA"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA         "ECDHE-RSA-AES256-SHA"

# define TLS1_TXT_ECDH_anon_WITH_NULL_SHA                "AECDH-NULL-SHA"
# define TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA             "AECDH-RC4-SHA"
# define TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA        "AECDH-DES-CBC3-SHA"
# define TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA         "AECDH-AES128-SHA"
# define TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA         "AECDH-AES256-SHA"

/* PSK ciphersuites from RFC 4279 */
# define TLS1_TXT_PSK_WITH_RC4_128_SHA                   "PSK-RC4-SHA"
# define TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA              "PSK-3DES-EDE-CBC-SHA"
# define TLS1_TXT_PSK_WITH_AES_128_CBC_SHA               "PSK-AES128-CBC-SHA"
# define TLS1_TXT_PSK_WITH_AES_256_CBC_SHA               "PSK-AES256-CBC-SHA"

# define TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA               "DHE-PSK-RC4-SHA"
# define TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA          "DHE-PSK-3DES-EDE-CBC-SHA"
# define TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA           "DHE-PSK-AES128-CBC-SHA"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA           "DHE-PSK-AES256-CBC-SHA"
# define TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA               "RSA-PSK-RC4-SHA"
# define TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA          "RSA-PSK-3DES-EDE-CBC-SHA"
# define TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA           "RSA-PSK-AES128-CBC-SHA"
# define TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA           "RSA-PSK-AES256-CBC-SHA"

/* PSK ciphersuites from RFC 5487 */
# define TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256            "PSK-AES128-GCM-SHA256"
# define TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384            "PSK-AES256-GCM-SHA384"
# define TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256        "DHE-PSK-AES128-GCM-SHA256"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384        "DHE-PSK-AES256-GCM-SHA384"
# define TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256        "RSA-PSK-AES128-GCM-SHA256"
# define TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384        "RSA-PSK-AES256-GCM-SHA384"

# define TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256            "PSK-AES128-CBC-SHA256"
# define TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384            "PSK-AES256-CBC-SHA384"
# define TLS1_TXT_PSK_WITH_NULL_SHA256                   "PSK-NULL-SHA256"
# define TLS1_TXT_PSK_WITH_NULL_SHA384                   "PSK-NULL-SHA384"

# define TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256        "DHE-PSK-AES128-CBC-SHA256"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384        "DHE-PSK-AES256-CBC-SHA384"
# define TLS1_TXT_DHE_PSK_WITH_NULL_SHA256               "DHE-PSK-NULL-SHA256"
# define TLS1_TXT_DHE_PSK_WITH_NULL_SHA384               "DHE-PSK-NULL-SHA384"

# define TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256        "RSA-PSK-AES128-CBC-SHA256"
# define TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384        "RSA-PSK-AES256-CBC-SHA384"
# define TLS1_TXT_RSA_PSK_WITH_NULL_SHA256               "RSA-PSK-NULL-SHA256"
# define TLS1_TXT_RSA_PSK_WITH_NULL_SHA384               "RSA-PSK-NULL-SHA384"

/* SRP ciphersuite from RFC 5054 */
# define TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA          "SRP-3DES-EDE-CBC-SHA"
# define TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA      "SRP-RSA-3DES-EDE-CBC-SHA"
# define TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA      "SRP-DSS-3DES-EDE-CBC-SHA"
# define TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA           "SRP-AES-128-CBC-SHA"
# define TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA       "SRP-RSA-AES-128-CBC-SHA"
# define TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA       "SRP-DSS-AES-128-CBC-SHA"
# define TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA           "SRP-AES-256-CBC-SHA"
# define TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA       "SRP-RSA-AES-256-CBC-SHA"
# define TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA       "SRP-DSS-AES-256-CBC-SHA"

/* Camellia ciphersuites from RFC4132 */
# define TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA          "CAMELLIA128-SHA"
# define TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA       "DH-DSS-CAMELLIA128-SHA"
# define TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA       "DH-RSA-CAMELLIA128-SHA"
# define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA      "DHE-DSS-CAMELLIA128-SHA"
# define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA      "DHE-RSA-CAMELLIA128-SHA"
# define TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA          "ADH-CAMELLIA128-SHA"

# define TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA          "CAMELLIA256-SHA"
# define TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA       "DH-DSS-CAMELLIA256-SHA"
# define TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA       "DH-RSA-CAMELLIA256-SHA"
# define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA      "DHE-DSS-CAMELLIA256-SHA"
# define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA      "DHE-RSA-CAMELLIA256-SHA"
# define TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA          "ADH-CAMELLIA256-SHA"

/* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
# define TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256               "CAMELLIA128-SHA256"
# define TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256            "DH-DSS-CAMELLIA128-SHA256"
# define TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256            "DH-RSA-CAMELLIA128-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256           "DHE-DSS-CAMELLIA128-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256           "DHE-RSA-CAMELLIA128-SHA256"
# define TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256               "ADH-CAMELLIA128-SHA256"

# define TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256               "CAMELLIA256-SHA256"
# define TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256            "DH-DSS-CAMELLIA256-SHA256"
# define TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256            "DH-RSA-CAMELLIA256-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256           "DHE-DSS-CAMELLIA256-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256           "DHE-RSA-CAMELLIA256-SHA256"
# define TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256               "ADH-CAMELLIA256-SHA256"

# define TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256               "PSK-CAMELLIA128-SHA256"
# define TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384               "PSK-CAMELLIA256-SHA384"
# define TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256           "DHE-PSK-CAMELLIA128-SHA256"
# define TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384           "DHE-PSK-CAMELLIA256-SHA384"
# define TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256           "RSA-PSK-CAMELLIA128-SHA256"
# define TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384           "RSA-PSK-CAMELLIA256-SHA384"
# define TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256         "ECDHE-PSK-CAMELLIA128-SHA256"
# define TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384         "ECDHE-PSK-CAMELLIA256-SHA384"

/* SEED ciphersuites from RFC4162 */
# define TLS1_TXT_RSA_WITH_SEED_SHA                      "SEED-SHA"
# define TLS1_TXT_DH_DSS_WITH_SEED_SHA                   "DH-DSS-SEED-SHA"
# define TLS1_TXT_DH_RSA_WITH_SEED_SHA                   "DH-RSA-SEED-SHA"
# define TLS1_TXT_DHE_DSS_WITH_SEED_SHA                  "DHE-DSS-SEED-SHA"
# define TLS1_TXT_DHE_RSA_WITH_SEED_SHA                  "DHE-RSA-SEED-SHA"
# define TLS1_TXT_ADH_WITH_SEED_SHA                      "ADH-SEED-SHA"

/* TLS v1.2 ciphersuites */
# define TLS1_TXT_RSA_WITH_NULL_SHA256                   "NULL-SHA256"
# define TLS1_TXT_RSA_WITH_AES_128_SHA256                "AES128-SHA256"
# define TLS1_TXT_RSA_WITH_AES_256_SHA256                "AES256-SHA256"
# define TLS1_TXT_DH_DSS_WITH_AES_128_SHA256             "DH-DSS-AES128-SHA256"
# define TLS1_TXT_DH_RSA_WITH_AES_128_SHA256             "DH-RSA-AES128-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256            "DHE-DSS-AES128-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256            "DHE-RSA-AES128-SHA256"
# define TLS1_TXT_DH_DSS_WITH_AES_256_SHA256             "DH-DSS-AES256-SHA256"
# define TLS1_TXT_DH_RSA_WITH_AES_256_SHA256             "DH-RSA-AES256-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256            "DHE-DSS-AES256-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256            "DHE-RSA-AES256-SHA256"
# define TLS1_TXT_ADH_WITH_AES_128_SHA256                "ADH-AES128-SHA256"
# define TLS1_TXT_ADH_WITH_AES_256_SHA256                "ADH-AES256-SHA256"

/* TLS v1.2 GCM ciphersuites from RFC5288 */
# define TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256            "AES128-GCM-SHA256"
# define TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384            "AES256-GCM-SHA384"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256        "DHE-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384        "DHE-RSA-AES256-GCM-SHA384"
# define TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256         "DH-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384         "DH-RSA-AES256-GCM-SHA384"
# define TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256        "DHE-DSS-AES128-GCM-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384        "DHE-DSS-AES256-GCM-SHA384"
# define TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256         "DH-DSS-AES128-GCM-SHA256"
# define TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384         "DH-DSS-AES256-GCM-SHA384"
# define TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256            "ADH-AES128-GCM-SHA256"
# define TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384            "ADH-AES256-GCM-SHA384"

/* CCM ciphersuites from RFC6655 */
# define TLS1_TXT_RSA_WITH_AES_128_CCM                   "AES128-CCM"
# define TLS1_TXT_RSA_WITH_AES_256_CCM                   "AES256-CCM"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM               "DHE-RSA-AES128-CCM"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM               "DHE-RSA-AES256-CCM"

# define TLS1_TXT_RSA_WITH_AES_128_CCM_8                 "AES128-CCM8"
# define TLS1_TXT_RSA_WITH_AES_256_CCM_8                 "AES256-CCM8"
# define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8             "DHE-RSA-AES128-CCM8"
# define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8             "DHE-RSA-AES256-CCM8"

# define TLS1_TXT_PSK_WITH_AES_128_CCM                   "PSK-AES128-CCM"
# define TLS1_TXT_PSK_WITH_AES_256_CCM                   "PSK-AES256-CCM"
# define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM               "DHE-PSK-AES128-CCM"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM               "DHE-PSK-AES256-CCM"

# define TLS1_TXT_PSK_WITH_AES_128_CCM_8                 "PSK-AES128-CCM8"
# define TLS1_TXT_PSK_WITH_AES_256_CCM_8                 "PSK-AES256-CCM8"
# define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8             "DHE-PSK-AES128-CCM8"
# define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8             "DHE-PSK-AES256-CCM8"

/* CCM ciphersuites from RFC7251 */
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM       "ECDHE-ECDSA-AES128-CCM"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM       "ECDHE-ECDSA-AES256-CCM"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8     "ECDHE-ECDSA-AES128-CCM8"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8     "ECDHE-ECDSA-AES256-CCM8"

/* ECDH HMAC based ciphersuites from RFC5289 */
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256    "ECDHE-ECDSA-AES128-SHA256"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384    "ECDHE-ECDSA-AES256-SHA384"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256     "ECDH-ECDSA-AES128-SHA256"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384     "ECDH-ECDSA-AES256-SHA384"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256      "ECDHE-RSA-AES128-SHA256"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384      "ECDHE-RSA-AES256-SHA384"
# define TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256       "ECDH-RSA-AES128-SHA256"
# define TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384       "ECDH-RSA-AES256-SHA384"

/* ECDH GCM based ciphersuites from RFC5289 */
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    "ECDHE-ECDSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    "ECDHE-ECDSA-AES256-GCM-SHA384"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256     "ECDH-ECDSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384     "ECDH-ECDSA-AES256-GCM-SHA384"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256      "ECDHE-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384      "ECDHE-RSA-AES256-GCM-SHA384"
# define TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256       "ECDH-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384       "ECDH-RSA-AES256-GCM-SHA384"

/* TLS v1.2 PSK GCM ciphersuites from RFC5487 */
# define TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256            "PSK-AES128-GCM-SHA256"
# define TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384            "PSK-AES256-GCM-SHA384"

/* ECDHE PSK ciphersuites from RFC 5489 */
# define TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA               "ECDHE-PSK-RC4-SHA"
# define TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA          "ECDHE-PSK-3DES-EDE-CBC-SHA"
# define TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA           "ECDHE-PSK-AES128-CBC-SHA"
# define TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA           "ECDHE-PSK-AES256-CBC-SHA"

# define TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256        "ECDHE-PSK-AES128-CBC-SHA256"
# define TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384        "ECDHE-PSK-AES256-CBC-SHA384"

# define TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA                  "ECDHE-PSK-NULL-SHA"
# define TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256               "ECDHE-PSK-NULL-SHA256"
# define TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384               "ECDHE-PSK-NULL-SHA384"

/* Camellia-CBC ciphersuites from RFC6367 */
# define TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 "ECDHE-ECDSA-CAMELLIA128-SHA256"
# define TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 "ECDHE-ECDSA-CAMELLIA256-SHA384"
# define TLS1_TXT_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  "ECDH-ECDSA-CAMELLIA128-SHA256"
# define TLS1_TXT_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  "ECDH-ECDSA-CAMELLIA256-SHA384"
# define TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   "ECDHE-RSA-CAMELLIA128-SHA256"
# define TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   "ECDHE-RSA-CAMELLIA256-SHA384"
# define TLS1_TXT_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    "ECDH-RSA-CAMELLIA128-SHA256"
# define TLS1_TXT_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    "ECDH-RSA-CAMELLIA256-SHA384"

/* draft-ietf-tls-chacha20-poly1305-03 */
# define TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305         "ECDHE-RSA-CHACHA20-POLY1305"
# define TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       "ECDHE-ECDSA-CHACHA20-POLY1305"
# define TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305           "DHE-RSA-CHACHA20-POLY1305"
# define TLS1_TXT_PSK_WITH_CHACHA20_POLY1305               "PSK-CHACHA20-POLY1305"
# define TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305         "ECDHE-PSK-CHACHA20-POLY1305"
# define TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305           "DHE-PSK-CHACHA20-POLY1305"
# define TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305           "RSA-PSK-CHACHA20-POLY1305"

/* Aria ciphersuites from RFC6209 */
# define TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256             "ARIA128-GCM-SHA256"
# define TLS1_TXT_RSA_WITH_ARIA_256_GCM_SHA384             "ARIA256-GCM-SHA384"
# define TLS1_TXT_DHE_RSA_WITH_ARIA_128_GCM_SHA256         "DHE-RSA-ARIA128-GCM-SHA256"
# define TLS1_TXT_DHE_RSA_WITH_ARIA_256_GCM_SHA384         "DHE-RSA-ARIA256-GCM-SHA384"
# define TLS1_TXT_DH_RSA_WITH_ARIA_128_GCM_SHA256          "DH-RSA-ARIA128-GCM-SHA256"
# define TLS1_TXT_DH_RSA_WITH_ARIA_256_GCM_SHA384          "DH-RSA-ARIA256-GCM-SHA384"
# define TLS1_TXT_DHE_DSS_WITH_ARIA_128_GCM_SHA256         "DHE-DSS-ARIA128-GCM-SHA256"
# define TLS1_TXT_DHE_DSS_WITH_ARIA_256_GCM_SHA384         "DHE-DSS-ARIA256-GCM-SHA384"
# define TLS1_TXT_DH_DSS_WITH_ARIA_128_GCM_SHA256          "DH-DSS-ARIA128-GCM-SHA256"
# define TLS1_TXT_DH_DSS_WITH_ARIA_256_GCM_SHA384          "DH-DSS-ARIA256-GCM-SHA384"
# define TLS1_TXT_DH_anon_WITH_ARIA_128_GCM_SHA256         "ADH-ARIA128-GCM-SHA256"
# define TLS1_TXT_DH_anon_WITH_ARIA_256_GCM_SHA384         "ADH-ARIA256-GCM-SHA384"
# define TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     "ECDHE-ECDSA-ARIA128-GCM-SHA256"
# define TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     "ECDHE-ECDSA-ARIA256-GCM-SHA384"
# define TLS1_TXT_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      "ECDH-ECDSA-ARIA128-GCM-SHA256"
# define TLS1_TXT_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      "ECDH-ECDSA-ARIA256-GCM-SHA384"
# define TLS1_TXT_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       "ECDHE-ARIA128-GCM-SHA256"
# define TLS1_TXT_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       "ECDHE-ARIA256-GCM-SHA384"
# define TLS1_TXT_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        "ECDH-ARIA128-GCM-SHA256"
# define TLS1_TXT_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        "ECDH-ARIA256-GCM-SHA384"
# define TLS1_TXT_PSK_WITH_ARIA_128_GCM_SHA256             "PSK-ARIA128-GCM-SHA256"
# define TLS1_TXT_PSK_WITH_ARIA_256_GCM_SHA384             "PSK-ARIA256-GCM-SHA384"
# define TLS1_TXT_DHE_PSK_WITH_ARIA_128_GCM_SHA256         "DHE-PSK-ARIA128-GCM-SHA256"
# define TLS1_TXT_DHE_PSK_WITH_ARIA_256_GCM_SHA384         "DHE-PSK-ARIA256-GCM-SHA384"
# define TLS1_TXT_RSA_PSK_WITH_ARIA_128_GCM_SHA256         "RSA-PSK-ARIA128-GCM-SHA256"
# define TLS1_TXT_RSA_PSK_WITH_ARIA_256_GCM_SHA384         "RSA-PSK-ARIA256-GCM-SHA384"


/* Any appropriate key exchange algorithm (for TLS 1.3 ciphersuites) */
# define SSL_kANY                0x00000000U

/* Any appropriate signature auth (for TLS 1.3 ciphersuites) */
# define SSL_aANY                0x00000000U

/* ECDH HMAC based ciphersuites from RFC5289 */

# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256    "ECDHE-ECDSA-AES128-SHA256"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384    "ECDHE-ECDSA-AES256-SHA384"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256     "ECDH-ECDSA-AES128-SHA256"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384     "ECDH-ECDSA-AES256-SHA384"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256      "ECDHE-RSA-AES128-SHA256"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384      "ECDHE-RSA-AES256-SHA384"
# define TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256       "ECDH-RSA-AES128-SHA256"
# define TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384       "ECDH-RSA-AES256-SHA384"

/* ECDH GCM based ciphersuites from RFC5289 */
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    "ECDHE-ECDSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    "ECDHE-ECDSA-AES256-GCM-SHA384"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256     "ECDH-ECDSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384     "ECDH-ECDSA-AES256-GCM-SHA384"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256      "ECDHE-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384      "ECDHE-RSA-AES256-GCM-SHA384"
# define TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256       "ECDH-RSA-AES128-GCM-SHA256"
# define TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384       "ECDH-RSA-AES256-GCM-SHA384"

/* PSK ciphersuites from 4279 */
# define TLS1_CK_PSK_WITH_RC4_128_SHA                    0x0300008A
# define TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA               0x0300008B
# define TLS1_CK_PSK_WITH_AES_128_CBC_SHA                0x0300008C
# define TLS1_CK_PSK_WITH_AES_256_CBC_SHA                0x0300008D
# define TLS1_CK_DHE_PSK_WITH_RC4_128_SHA                0x0300008E
# define TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA           0x0300008F
# define TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA            0x03000090
# define TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA            0x03000091
# define TLS1_CK_RSA_PSK_WITH_RC4_128_SHA                0x03000092
# define TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA           0x03000093
# define TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA            0x03000094
# define TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA            0x03000095

/* PSK ciphersuites from 5487 */
# define TLS1_CK_PSK_WITH_AES_128_GCM_SHA256             0x030000A8
# define TLS1_CK_PSK_WITH_AES_256_GCM_SHA384             0x030000A9
# define TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256         0x030000AA
# define TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384         0x030000AB
# define TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256         0x030000AC
# define TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384         0x030000AD
# define TLS1_CK_PSK_WITH_AES_128_CBC_SHA256             0x030000AE
# define TLS1_CK_PSK_WITH_AES_256_CBC_SHA384             0x030000AF
# define TLS1_CK_PSK_WITH_NULL_SHA256                    0x030000B0
# define TLS1_CK_PSK_WITH_NULL_SHA384                    0x030000B1
# define TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256         0x030000B2
# define TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384         0x030000B3
# define TLS1_CK_DHE_PSK_WITH_NULL_SHA256                0x030000B4
# define TLS1_CK_DHE_PSK_WITH_NULL_SHA384                0x030000B5
# define TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256         0x030000B6
# define TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384         0x030000B7
# define TLS1_CK_RSA_PSK_WITH_NULL_SHA256                0x030000B8
# define TLS1_CK_RSA_PSK_WITH_NULL_SHA384                0x030000B9

/* NULL PSK ciphersuites from RFC4785 */
# define TLS1_CK_PSK_WITH_NULL_SHA                       0x0300002C
# define TLS1_CK_DHE_PSK_WITH_NULL_SHA                   0x0300002D
# define TLS1_CK_RSA_PSK_WITH_NULL_SHA                   0x0300002E

/* AES ciphersuites from RFC3268 */
# define TLS1_CK_RSA_WITH_AES_128_SHA                    0x0300002F
# define TLS1_CK_DH_DSS_WITH_AES_128_SHA                 0x03000030
# define TLS1_CK_DH_RSA_WITH_AES_128_SHA                 0x03000031
# define TLS1_CK_DHE_DSS_WITH_AES_128_SHA                0x03000032
# define TLS1_CK_DHE_RSA_WITH_AES_128_SHA                0x03000033
# define TLS1_CK_ADH_WITH_AES_128_SHA                    0x03000034
# define TLS1_CK_RSA_WITH_AES_256_SHA                    0x03000035
# define TLS1_CK_DH_DSS_WITH_AES_256_SHA                 0x03000036
# define TLS1_CK_DH_RSA_WITH_AES_256_SHA                 0x03000037
# define TLS1_CK_DHE_DSS_WITH_AES_256_SHA                0x03000038
# define TLS1_CK_DHE_RSA_WITH_AES_256_SHA                0x03000039
# define TLS1_CK_ADH_WITH_AES_256_SHA                    0x0300003A

/* TLS v1.2 ciphersuites */
# define TLS1_CK_RSA_WITH_NULL_SHA256                    0x0300003B
# define TLS1_CK_RSA_WITH_AES_128_SHA256                 0x0300003C
# define TLS1_CK_RSA_WITH_AES_256_SHA256                 0x0300003D
# define TLS1_CK_DH_DSS_WITH_AES_128_SHA256              0x0300003E
# define TLS1_CK_DH_RSA_WITH_AES_128_SHA256              0x0300003F
# define TLS1_CK_DHE_DSS_WITH_AES_128_SHA256             0x03000040

/* Camellia ciphersuites from RFC4132 */
# define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA           0x03000041
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA        0x03000042
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA        0x03000043
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA       0x03000044
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA       0x03000045
# define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA           0x03000046

/* TLS v1.2 ciphersuites */
# define TLS1_CK_DHE_RSA_WITH_AES_128_SHA256             0x03000067
# define TLS1_CK_DH_DSS_WITH_AES_256_SHA256              0x03000068
# define TLS1_CK_DH_RSA_WITH_AES_256_SHA256              0x03000069
# define TLS1_CK_DHE_DSS_WITH_AES_256_SHA256             0x0300006A
# define TLS1_CK_DHE_RSA_WITH_AES_256_SHA256             0x0300006B
# define TLS1_CK_ADH_WITH_AES_128_SHA256                 0x0300006C
# define TLS1_CK_ADH_WITH_AES_256_SHA256                 0x0300006D

/* Camellia ciphersuites from RFC4132 */
# define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA           0x03000084
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA        0x03000085
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA        0x03000086
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA       0x03000087
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA       0x03000088
# define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA           0x03000089

/* SEED ciphersuites from RFC4162 */
# define TLS1_CK_RSA_WITH_SEED_SHA                       0x03000096
# define TLS1_CK_DH_DSS_WITH_SEED_SHA                    0x03000097
# define TLS1_CK_DH_RSA_WITH_SEED_SHA                    0x03000098
# define TLS1_CK_DHE_DSS_WITH_SEED_SHA                   0x03000099
# define TLS1_CK_DHE_RSA_WITH_SEED_SHA                   0x0300009A
# define TLS1_CK_ADH_WITH_SEED_SHA                       0x0300009B

/* TLS v1.2 GCM ciphersuites from RFC5288 */
# define TLS1_CK_RSA_WITH_AES_128_GCM_SHA256             0x0300009C
# define TLS1_CK_RSA_WITH_AES_256_GCM_SHA384             0x0300009D
# define TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256         0x0300009E
# define TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384         0x0300009F
# define TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256          0x030000A0
# define TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384          0x030000A1
# define TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256         0x030000A2
# define TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384         0x030000A3
# define TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256          0x030000A4
# define TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384          0x030000A5
# define TLS1_CK_ADH_WITH_AES_128_GCM_SHA256             0x030000A6
# define TLS1_CK_ADH_WITH_AES_256_GCM_SHA384             0x030000A7

/* CCM ciphersuites from RFC6655 */
# define TLS1_CK_RSA_WITH_AES_128_CCM                    0x0300C09C
# define TLS1_CK_RSA_WITH_AES_256_CCM                    0x0300C09D
# define TLS1_CK_DHE_RSA_WITH_AES_128_CCM                0x0300C09E
# define TLS1_CK_DHE_RSA_WITH_AES_256_CCM                0x0300C09F
# define TLS1_CK_RSA_WITH_AES_128_CCM_8                  0x0300C0A0
# define TLS1_CK_RSA_WITH_AES_256_CCM_8                  0x0300C0A1
# define TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8              0x0300C0A2
# define TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8              0x0300C0A3
# define TLS1_CK_PSK_WITH_AES_128_CCM                    0x0300C0A4
# define TLS1_CK_PSK_WITH_AES_256_CCM                    0x0300C0A5
# define TLS1_CK_DHE_PSK_WITH_AES_128_CCM                0x0300C0A6
# define TLS1_CK_DHE_PSK_WITH_AES_256_CCM                0x0300C0A7
# define TLS1_CK_PSK_WITH_AES_128_CCM_8                  0x0300C0A8
# define TLS1_CK_PSK_WITH_AES_256_CCM_8                  0x0300C0A9
# define TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8              0x0300C0AA
# define TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8              0x0300C0AB

/* CCM ciphersuites from RFC7251 */
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM            0x0300C0AC
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM            0x0300C0AD
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8          0x0300C0AE
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8          0x0300C0AF

/* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
# define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256                0x030000BA
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256             0x030000BB
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256             0x030000BC
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256            0x030000BD
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256            0x030000BE
# define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256                0x030000BF

# define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256                0x030000C0
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256             0x030000C1
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256             0x030000C2
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256            0x030000C3
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256            0x030000C4
# define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256                0x030000C5

/* ECC ciphersuites from RFC4492 */
# define TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA                0x0300C001
# define TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA             0x0300C002
# define TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA        0x0300C003
# define TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA         0x0300C004
# define TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA         0x0300C005

# define TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA               0x0300C006
# define TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA            0x0300C007
# define TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA       0x0300C008
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA        0x0300C009
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA        0x0300C00A

# define TLS1_CK_ECDH_RSA_WITH_NULL_SHA                  0x0300C00B
# define TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA               0x0300C00C
# define TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA          0x0300C00D
# define TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA           0x0300C00E
# define TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA           0x0300C00F

# define TLS1_CK_ECDHE_RSA_WITH_NULL_SHA                 0x0300C010
# define TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA              0x0300C011
# define TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA         0x0300C012
# define TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA          0x0300C013
# define TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA          0x0300C014

# define TLS1_CK_ECDH_anon_WITH_NULL_SHA                 0x0300C015
# define TLS1_CK_ECDH_anon_WITH_RC4_128_SHA              0x0300C016
# define TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA         0x0300C017
# define TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA          0x0300C018
# define TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA          0x0300C019

/* SRP ciphersuites from RFC 5054 */
# define TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA           0x0300C01A
# define TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA       0x0300C01B
# define TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA       0x0300C01C
# define TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA            0x0300C01D
# define TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA        0x0300C01E
# define TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA        0x0300C01F
# define TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA            0x0300C020
# define TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA        0x0300C021
# define TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA        0x0300C022

/* ECDH HMAC based ciphersuites from RFC5289 */
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256         0x0300C023
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384         0x0300C024
# define TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256          0x0300C025
# define TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384          0x0300C026
# define TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256           0x0300C027
# define TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384           0x0300C028
# define TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256            0x0300C029
# define TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384            0x0300C02A

/* ECDH GCM based ciphersuites from RFC5289 */
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     0x0300C02B
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     0x0300C02C
# define TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256      0x0300C02D
# define TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384      0x0300C02E
# define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256       0x0300C02F
# define TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384       0x0300C030
# define TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256        0x0300C031
# define TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384        0x0300C032

/* ECDHE PSK ciphersuites from RFC5489 */
# define TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA              0x0300C033
# define TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA         0x0300C034
# define TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA          0x0300C035
# define TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA          0x0300C036

# define TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256       0x0300C037
# define TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384       0x0300C038

/* NULL PSK ciphersuites from RFC4785 */
# define TLS1_CK_ECDHE_PSK_WITH_NULL_SHA                 0x0300C039
# define TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256              0x0300C03A
# define TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384              0x0300C03B

/* Camellia-CBC ciphersuites from RFC6367 */
# define TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 0x0300C072
# define TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 0x0300C073
# define TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  0x0300C074
# define TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  0x0300C075
# define TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   0x0300C076
# define TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   0x0300C077
# define TLS1_CK_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    0x0300C078
# define TLS1_CK_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    0x0300C079

# define TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256         0x0300C094
# define TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384         0x0300C095
# define TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256     0x0300C096
# define TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384     0x0300C097
# define TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256     0x0300C098
# define TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384     0x0300C099
# define TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   0x0300C09A
# define TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   0x0300C09B

/* draft-ietf-tls-chacha20-poly1305-03 */
# define TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305         0x0300CCA8
# define TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       0x0300CCA9
# define TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305           0x0300CCAA
# define TLS1_CK_PSK_WITH_CHACHA20_POLY1305               0x0300CCAB
# define TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305         0x0300CCAC
# define TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305           0x0300CCAD
# define TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305           0x0300CCAE

/* TLS v1.3 ciphersuites */
# define TLS1_3_CK_AES_128_GCM_SHA256                     0x03001301
# define TLS1_3_CK_AES_256_GCM_SHA384                     0x03001302
# define TLS1_3_CK_CHACHA20_POLY1305_SHA256               0x03001303
# define TLS1_3_CK_AES_128_CCM_SHA256                     0x03001304
# define TLS1_3_CK_AES_128_CCM_8_SHA256                   0x03001305

/* Aria ciphersuites from RFC6209 */
# define TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256             0x0300C050
# define TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384             0x0300C051
# define TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256         0x0300C052
# define TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384         0x0300C053
# define TLS1_CK_DH_RSA_WITH_ARIA_128_GCM_SHA256          0x0300C054
# define TLS1_CK_DH_RSA_WITH_ARIA_256_GCM_SHA384          0x0300C055
# define TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256         0x0300C056
# define TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384         0x0300C057
# define TLS1_CK_DH_DSS_WITH_ARIA_128_GCM_SHA256          0x0300C058
# define TLS1_CK_DH_DSS_WITH_ARIA_256_GCM_SHA384          0x0300C059
# define TLS1_CK_DH_anon_WITH_ARIA_128_GCM_SHA256         0x0300C05A
# define TLS1_CK_DH_anon_WITH_ARIA_256_GCM_SHA384         0x0300C05B
# define TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     0x0300C05C
# define TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     0x0300C05D
# define TLS1_CK_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      0x0300C05E
# define TLS1_CK_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      0x0300C05F
# define TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       0x0300C060
# define TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       0x0300C061
# define TLS1_CK_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        0x0300C062
# define TLS1_CK_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        0x0300C063
# define TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256             0x0300C06A
# define TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384             0x0300C06B
# define TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256         0x0300C06C
# define TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384         0x0300C06D
# define TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256         0x0300C06E
# define TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384         0x0300C06F

/* PSK ciphersuites from 4279 */
# define TLS1_CK_PSK_WITH_RC4_128_SHA                    0x0300008A
# define TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA               0x0300008B
# define TLS1_CK_PSK_WITH_AES_128_CBC_SHA                0x0300008C
# define TLS1_CK_PSK_WITH_AES_256_CBC_SHA                0x0300008D

/*
 * Additional TLS ciphersuites from expired Internet Draft
 * draft-ietf-tls-56-bit-ciphersuites-01.txt (available if
 * TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES is defined, see s3_lib.c).  We
 * actually treat them like SSL 3.0 ciphers, which we probably shouldn't.
 * Note that the first two are actually not in the IDs.
 */
# define TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5          0x03000060/* not in
                                                                    * ID */
# define TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5      0x03000061/* not in
                                                                    * ID */
# define TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA         0x03000062
# define TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA     0x03000063
# define TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA          0x03000064
# define TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA      0x03000065
# define TLS1_CK_DHE_DSS_WITH_RC4_128_SHA                0x03000066

/* AES ciphersuites from RFC3268 */
# define TLS1_CK_RSA_WITH_AES_128_SHA                    0x0300002F
# define TLS1_CK_DH_DSS_WITH_AES_128_SHA                 0x03000030
# define TLS1_CK_DH_RSA_WITH_AES_128_SHA                 0x03000031
# define TLS1_CK_DHE_DSS_WITH_AES_128_SHA                0x03000032
# define TLS1_CK_DHE_RSA_WITH_AES_128_SHA                0x03000033
# define TLS1_CK_ADH_WITH_AES_128_SHA                    0x03000034

# define TLS1_CK_RSA_WITH_AES_256_SHA                    0x03000035
# define TLS1_CK_DH_DSS_WITH_AES_256_SHA                 0x03000036
# define TLS1_CK_DH_RSA_WITH_AES_256_SHA                 0x03000037
# define TLS1_CK_DHE_DSS_WITH_AES_256_SHA                0x03000038
# define TLS1_CK_DHE_RSA_WITH_AES_256_SHA                0x03000039
# define TLS1_CK_ADH_WITH_AES_256_SHA                    0x0300003A

/* TLS v1.2 ciphersuites */
# define TLS1_CK_RSA_WITH_NULL_SHA256                    0x0300003B
# define TLS1_CK_RSA_WITH_AES_128_SHA256                 0x0300003C
# define TLS1_CK_RSA_WITH_AES_256_SHA256                 0x0300003D
# define TLS1_CK_DH_DSS_WITH_AES_128_SHA256              0x0300003E
# define TLS1_CK_DH_RSA_WITH_AES_128_SHA256              0x0300003F
# define TLS1_CK_DHE_DSS_WITH_AES_128_SHA256             0x03000040

/* Camellia ciphersuites from RFC4132 */
# define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA           0x03000041
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA        0x03000042
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA        0x03000043
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA       0x03000044
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA       0x03000045
# define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA           0x03000046

/* TLS v1.2 ciphersuites */
# define TLS1_CK_DHE_RSA_WITH_AES_128_SHA256             0x03000067
# define TLS1_CK_DH_DSS_WITH_AES_256_SHA256              0x03000068
# define TLS1_CK_DH_RSA_WITH_AES_256_SHA256              0x03000069
# define TLS1_CK_DHE_DSS_WITH_AES_256_SHA256             0x0300006A
# define TLS1_CK_DHE_RSA_WITH_AES_256_SHA256             0x0300006B
# define TLS1_CK_ADH_WITH_AES_128_SHA256                 0x0300006C
# define TLS1_CK_ADH_WITH_AES_256_SHA256                 0x0300006D

/* Camellia ciphersuites from RFC4132 */
# define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA           0x03000084
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA        0x03000085
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA        0x03000086
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA       0x03000087
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA       0x03000088
# define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA           0x03000089

/* SEED ciphersuites from RFC4162 */
# define TLS1_CK_RSA_WITH_SEED_SHA                       0x03000096
# define TLS1_CK_DH_DSS_WITH_SEED_SHA                    0x03000097
# define TLS1_CK_DH_RSA_WITH_SEED_SHA                    0x03000098
# define TLS1_CK_DHE_DSS_WITH_SEED_SHA                   0x03000099
# define TLS1_CK_DHE_RSA_WITH_SEED_SHA                   0x0300009A
# define TLS1_CK_ADH_WITH_SEED_SHA                       0x0300009B

/* TLS v1.2 GCM ciphersuites from RFC5288 */
# define TLS1_CK_RSA_WITH_AES_128_GCM_SHA256             0x0300009C
# define TLS1_CK_RSA_WITH_AES_256_GCM_SHA384             0x0300009D
# define TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256         0x0300009E
# define TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384         0x0300009F
# define TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256          0x030000A0
# define TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384          0x030000A1
# define TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256         0x030000A2
# define TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384         0x030000A3
# define TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256          0x030000A4
# define TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384          0x030000A5
# define TLS1_CK_ADH_WITH_AES_128_GCM_SHA256             0x030000A6
# define TLS1_CK_ADH_WITH_AES_256_GCM_SHA384             0x030000A7

/*
 * ECC ciphersuites from draft-ietf-tls-ecc-12.txt with changes soon to be in
 * draft 13
 */
# define TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA                0x0300C001
# define TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA             0x0300C002
# define TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA        0x0300C003
# define TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA         0x0300C004
# define TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA         0x0300C005

# define TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA               0x0300C006
# define TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA            0x0300C007
# define TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA       0x0300C008
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA        0x0300C009
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA        0x0300C00A

# define TLS1_CK_ECDH_RSA_WITH_NULL_SHA                  0x0300C00B
# define TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA               0x0300C00C
# define TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA          0x0300C00D
# define TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA           0x0300C00E
# define TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA           0x0300C00F

# define TLS1_CK_ECDHE_RSA_WITH_NULL_SHA                 0x0300C010
# define TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA              0x0300C011
# define TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA         0x0300C012
# define TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA          0x0300C013
# define TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA          0x0300C014

# define TLS1_CK_ECDH_anon_WITH_NULL_SHA                 0x0300C015
# define TLS1_CK_ECDH_anon_WITH_RC4_128_SHA              0x0300C016
# define TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA         0x0300C017
# define TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA          0x0300C018
# define TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA          0x0300C019

/* SRP ciphersuites from RFC 5054 */
# define TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA           0x0300C01A
# define TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA       0x0300C01B
# define TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA       0x0300C01C
# define TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA            0x0300C01D
# define TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA        0x0300C01E
# define TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA        0x0300C01F
# define TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA            0x0300C020
# define TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA        0x0300C021
# define TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA        0x0300C022

/* ECDH HMAC based ciphersuites from RFC5289 */

# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256         0x0300C023
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384         0x0300C024
# define TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256          0x0300C025
# define TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384          0x0300C026
# define TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256           0x0300C027
# define TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384           0x0300C028
# define TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256            0x0300C029
# define TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384            0x0300C02A

/* ECDH GCM based ciphersuites from RFC5289 */
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     0x0300C02B
# define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     0x0300C02C
# define TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256      0x0300C02D
# define TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384      0x0300C02E
# define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256       0x0300C02F
# define TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384       0x0300C030
# define TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256        0x0300C031
# define TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384        0x0300C032

/* a bundle of RFC standard cipher names, generated from ssl3_ciphers[] */
# define SSL3_RFC_RSA_NULL_MD5                   "TLS_RSA_WITH_NULL_MD5"
# define SSL3_RFC_RSA_NULL_SHA                   "TLS_RSA_WITH_NULL_SHA"
# define SSL3_RFC_RSA_DES_192_CBC3_SHA           "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA       "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA       "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_ADH_DES_192_CBC_SHA            "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_RSA_IDEA_128_SHA               "TLS_RSA_WITH_IDEA_CBC_SHA"
# define SSL3_RFC_RSA_RC4_128_MD5                "TLS_RSA_WITH_RC4_128_MD5"
# define SSL3_RFC_RSA_RC4_128_SHA                "TLS_RSA_WITH_RC4_128_SHA"
# define SSL3_RFC_ADH_RC4_128_MD5                "TLS_DH_anon_WITH_RC4_128_MD5"

/* Suite B modes, takes same values as certificate verify flags */
#define SSL_CERT_FLAG_SUITEB_128_LOS_ONLY       0x10000
/* Suite B 192 bit only mode */
#define SSL_CERT_FLAG_SUITEB_192_LOS            0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
#define SSL_CERT_FLAG_SUITEB_128_LOS            0x30000

/* DTLS SRTP */
#define SRTP_AES128_CM_SHA1_80 0x0001
#define SRTP_AES128_CM_SHA1_32 0x0002
#define SRTP_AES128_F8_SHA1_80 0x0003
#define SRTP_AES128_F8_SHA1_32 0x0004
#define SRTP_NULL_SHA1_80      0x0005
#define SRTP_NULL_SHA1_32      0x0006
/* AEAD SRTP protection profiles from RFC 7714 */
#define SRTP_AEAD_AES_128_GCM  0x0007
#define SRTP_AEAD_AES_256_GCM  0x0008

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/* OPENSSL_INIT flag 0x010000 reserved for internal use */
#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS    0x00100000L
#define OPENSSL_INIT_LOAD_SSL_STRINGS       0x00200000L

/* Standard initialisation options */
# define OPENSSL_INIT_ADD_ALL_CIPHERS        0x00000004L
# define OPENSSL_INIT_ADD_ALL_DIGESTS        0x00000008L
/* Max OPENSSL_INIT flag value is 0x80000000 */


# if !defined(CRYPTO_ONCE_STATIC_INIT)
typedef unsigned int CRYPTO_ONCE;
typedef unsigned int CRYPTO_THREAD_LOCAL;
typedef unsigned int CRYPTO_THREAD_ID;
#  define CRYPTO_ONCE_STATIC_INIT 0
# endif

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));

/*
 * DEFINE_RUN_ONCE_STATIC: Define an initialiser function that should be run
 * exactly once. This function will be declared as static within the file. It
 * takes no arguments and returns and int result (1 for success or 0 for
 * failure). Typical usage might be:
 *
 * DEFINE_RUN_ONCE_STATIC(myinitfunc)
 * {
 *     do_some_initialisation();
 *     if (init_is_successful())
 *         return 1;
 *
 *     return 0;
 * }
 */
#define DEFINE_RUN_ONCE_STATIC(init)            \
    static int init(void);                     \
    static int init##_ossl_ret_ = 0;            \
    static void init##_ossl_(void)              \
    {                                           \
        init##_ossl_ret_ = init();              \
    }                                           \
    static int init(void)

/*
 * RUN_ONCE - use CRYPTO_THREAD_run_once, and check if the init succeeded
 * @once: pointer to static object of type CRYPTO_ONCE
 * @init: function name that was previously given to DEFINE_RUN_ONCE,
 *        DEFINE_RUN_ONCE_STATIC or DECLARE_RUN_ONCE.  This function
 *        must return 1 for success or 0 for failure.
 *
 * The return value is 1 on success (*) or 0 in case of error.
 *
 * (*) by convention, since the init function must return 1 on success.
 */
#define RUN_ONCE(once, init)                                            \
    (CRYPTO_THREAD_run_once(once, init##_ossl_) ? init##_ossl_ret_ : 0)
#endif
/*-
 * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
 * ciphers normally not being used.
 * Example: "RC4" will activate all ciphers using RC4 including ciphers
 * without authentication, which would normally disabled by DEFAULT (due
 * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
 * will make sure that it is also disabled in the specific selection.
 * COMPLEMENTOF* identifiers are portable between version, as adjustments
 * to the default cipher setup will also be included here.
 *
 * COMPLEMENTOFDEFAULT does not experience the same special treatment that
 * DEFAULT gets, as only selection is being done and no sorting as needed
 * for DEFAULT.
 */
# define SSL_TXT_CMPALL          "COMPLEMENTOFALL"
# define SSL_TXT_CMPDEF          "COMPLEMENTOFDEFAULT"

#define REHANDSHAKE_MAX_BYTE_COUNT   1024 * 1024 * 10
#define REHANDSHAKE_MAX_TIMER_COUNT  60 * 60 * 1000

static const SSL_CIPHER cipher_aliases[] = {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* "ALL" doesn't include eNULL (must be specifically enabled) */
    {0, SSL_TXT_ALL, NULL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    /* "COMPLEMENTOFALL" */
    {0, SSL_TXT_CMPALL, NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /*
     * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in
     * ALL!)
     */
    {0, SSL_TXT_CMPDEF, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT, 0, 0, 0},

    /*
     * key exchange aliases (some of those using only a single bit here
     * combine multiple key exchange algs according to the RFCs, e.g. kDHE
     * combines DHE_DSS and DHE_RSA)
     */
    {0, SSL_TXT_kRSA, NULL, 0, SSL_kRSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kEDH, NULL, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHE, NULL, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DH, NULL, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kEECDH, NULL, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHE, NULL, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDH, NULL, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kPSK, NULL, 0, SSL_kPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kRSAPSK, NULL, 0, SSL_kRSAPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHEPSK, NULL, 0, SSL_kECDHEPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHEPSK, NULL, 0, SSL_kDHEPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kSRP, NULL, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kGOST, NULL, 0, SSL_kGOST, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* server authentication aliases */
    {0, SSL_TXT_aRSA, NULL, 0, 0, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aDSS, NULL, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DSS, NULL, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aNULL, NULL, 0, 0, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDSA, NULL, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDSA, NULL, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aPSK, NULL, 0, 0, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST01, NULL, 0, 0, SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST12, NULL, 0, 0, SSL_aGOST12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST, NULL, 0, 0, SSL_aGOST01 | SSL_aGOST12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aSRP, NULL, 0, 0, SSL_aSRP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* aliases combining key exchange and server authentication */
    {0, SSL_TXT_EDH, NULL, 0, SSL_kDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DHE, NULL, 0, SSL_kDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_EECDH, NULL, 0, SSL_kECDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDHE, NULL, 0, SSL_kECDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_NULL, NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RSA, NULL, 0, SSL_kRSA, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ADH, NULL, 0, SSL_kDHE, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AECDH, NULL, 0, SSL_kECDHE, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_PSK, NULL, 0, SSL_PSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SRP, NULL, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* symmetric encryption aliases */
    {0, SSL_TXT_3DES, NULL, 0, 0, 0, SSL_3DES, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC4, NULL, 0, 0, 0, SSL_RC4, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC2, NULL, 0, 0, 0, SSL_RC2, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_IDEA, NULL, 0, 0, 0, SSL_IDEA, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SEED, NULL, 0, 0, 0, SSL_SEED, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_eNULL, NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST, NULL, 0, 0, 0, SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES128, NULL, 0, 0, 0,
     SSL_AES128 | SSL_AES128GCM | SSL_AES128CCM | SSL_AES128CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES256, NULL, 0, 0, 0,
     SSL_AES256 | SSL_AES256GCM | SSL_AES256CCM | SSL_AES256CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES, NULL, 0, 0, 0, SSL_AES, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_GCM, NULL, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_CCM, NULL, 0, 0, 0,
     SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_CCM_8, NULL, 0, 0, 0, SSL_AES128CCM8 | SSL_AES256CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA128, NULL, 0, 0, 0, SSL_CAMELLIA128, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA256, NULL, 0, 0, 0, SSL_CAMELLIA256, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA, NULL, 0, 0, 0, SSL_CAMELLIA, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CHACHA20, NULL, 0, 0, 0, SSL_CHACHA20, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_ARIA, NULL, 0, 0, 0, SSL_ARIA, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ARIA_GCM, NULL, 0, 0, 0, SSL_ARIA128GCM | SSL_ARIA256GCM, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ARIA128, NULL, 0, 0, 0, SSL_ARIA128GCM, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ARIA256, NULL, 0, 0, 0, SSL_ARIA256GCM, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* MAC aliases */
    {0, SSL_TXT_MD5, NULL, 0, 0, 0, 0, SSL_MD5, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA1, NULL, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA, NULL, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST94, NULL, 0, 0, 0, 0, SSL_GOST94, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST89MAC, NULL, 0, 0, 0, 0, SSL_GOST89MAC | SSL_GOST89MAC12, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA256, NULL, 0, 0, 0, 0, SSL_SHA256, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA384, NULL, 0, 0, 0, 0, SSL_SHA384, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST12, NULL, 0, 0, 0, 0, SSL_GOST12_256, 0, 0, 0, 0, 0, 0, 0, 0},

    /* protocol version aliases */
    {0, SSL_TXT_SSLV3, NULL, 0, 0, 0, 0, 0, SSL3_VERSION, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1, NULL, 0, 0, 0, 0, 0, TLS1_VERSION, 0, 0, 0, 0, 0, 0, 0},
    {0, "TLSv1.0", NULL, 0, 0, 0, 0, 0, TLS1_VERSION, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1_2, NULL, 0, 0, 0, 0, 0, TLS1_2_VERSION, 0, 0, 0, 0, 0, 0, 0},

    /* strength classes */
    {0, SSL_TXT_LOW, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_LOW, 0, 0, 0},
    {0, SSL_TXT_MEDIUM, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_MEDIUM, 0, 0, 0},
    {0, SSL_TXT_HIGH, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_HIGH, 0, 0, 0},
    /* FIPS 140-2 approved ciphersuite */
    {0, SSL_TXT_FIPS, NULL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, SSL_FIPS, 0, 0, 0},

    /* "EDH-" aliases to "DHE-" labels (for backward compatibility) */
    {0, SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA, NULL, 0,
     SSL_kDHE, SSL_aDSS, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS, 0, 0, 0},
    {0, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA, NULL, 0,
     SSL_kDHE, SSL_aRSA, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS, 0, 0, 0},
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
    /* "ALL" doesn't include eNULL (must be specifically enabled) */
    {0, SSL_TXT_ALL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    /* "COMPLEMENTOFALL" */
    {0, SSL_TXT_CMPALL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /*
     * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in
     * ALL!)
     */
    {0, SSL_TXT_CMPDEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT, 0, 0, 0},

    /*
     * key exchange aliases (some of those using only a single bit here
     * combine multiple key exchange algs according to the RFCs, e.g. kDHE
     * combines DHE_DSS and DHE_RSA)
     */
    {0, SSL_TXT_kRSA, 0, SSL_kRSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kEDH, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHE, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DH, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kEECDH, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHE, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDH, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kPSK, 0, SSL_kPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kRSAPSK, 0, SSL_kRSAPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHEPSK, 0, SSL_kECDHEPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHEPSK, 0, SSL_kDHEPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kSRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kGOST, 0, SSL_kGOST, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* server authentication aliases */
    {0, SSL_TXT_aRSA, 0, 0, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aDSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aNULL, 0, 0, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aPSK, 0, 0, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST01, 0, 0, SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST12, 0, 0, SSL_aGOST12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST, 0, 0, SSL_aGOST01 | SSL_aGOST12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aSRP, 0, 0, SSL_aSRP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* aliases combining key exchange and server authentication */
    {0, SSL_TXT_EDH, 0, SSL_kDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DHE, 0, SSL_kDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_EECDH, 0, SSL_kECDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDHE, 0, SSL_kECDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RSA, 0, SSL_kRSA, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ADH, 0, SSL_kDHE, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AECDH, 0, SSL_kECDHE, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_PSK, 0, SSL_PSK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* symmetric encryption aliases */
    {0, SSL_TXT_3DES, 0, 0, 0, SSL_3DES, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC4, 0, 0, 0, SSL_RC4, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC2, 0, 0, 0, SSL_RC2, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_IDEA, 0, 0, 0, SSL_IDEA, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SEED, 0, 0, 0, SSL_SEED, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_eNULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST, 0, 0, 0, SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES128, 0, 0, 0,
     SSL_AES128 | SSL_AES128GCM | SSL_AES128CCM | SSL_AES128CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES256, 0, 0, 0,
     SSL_AES256 | SSL_AES256GCM | SSL_AES256CCM | SSL_AES256CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES, 0, 0, 0, SSL_AES, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_GCM, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_CCM, 0, 0, 0,
     SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_CCM_8, 0, 0, 0, SSL_AES128CCM8 | SSL_AES256CCM8, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA128, 0, 0, 0, SSL_CAMELLIA128, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA256, 0, 0, 0, SSL_CAMELLIA256, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA, 0, 0, 0, SSL_CAMELLIA, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CHACHA20, 0, 0, 0, SSL_CHACHA20, 0, 0, 0, 0, 0, 0, 0, 0, 0},

    /* MAC aliases */
    {0, SSL_TXT_MD5, 0, 0, 0, 0, SSL_MD5, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA1, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST94, 0, 0, 0, 0, SSL_GOST94, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST89MAC, 0, 0, 0, 0, SSL_GOST89MAC | SSL_GOST89MAC12, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA256, 0, 0, 0, 0, SSL_SHA256, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA384, 0, 0, 0, 0, SSL_SHA384, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST12, 0, 0, 0, 0, SSL_GOST12_256, 0, 0, 0, 0, 0, 0, 0, 0},

    /* protocol version aliases */
    {0, SSL_TXT_SSLV3, 0, 0, 0, 0, 0, SSL3_VERSION, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1, 0, 0, 0, 0, 0, TLS1_VERSION, 0, 0, 0, 0, 0, 0, 0},
    {0, "TLSv1.0", 0, 0, 0, 0, 0, TLS1_VERSION, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1_2, 0, 0, 0, 0, 0, TLS1_2_VERSION, 0, 0, 0, 0, 0, 0, 0},

    /* strength classes */
    {0, SSL_TXT_LOW, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_LOW, 0, 0, 0},
    {0, SSL_TXT_MEDIUM, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_MEDIUM, 0, 0, 0},
    {0, SSL_TXT_HIGH, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_HIGH, 0, 0, 0},
    /* FIPS 140-2 approved ciphersuite */
    {0, SSL_TXT_FIPS, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, SSL_FIPS, 0, 0, 0},

    /* "EDH-" aliases to "DHE-" labels (for backward compatibility) */
    {0, SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA, 0,
     SSL_kDHE, SSL_aDSS, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS, 0, 0, 0},
    {0, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA, 0,
     SSL_kDHE, SSL_aRSA, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS, 0, 0, 0},
#else
    /* "ALL" doesn't include eNULL (must be specifically enabled) */
    {0, SSL_TXT_ALL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, 0},
    /* "COMPLEMENTOFALL" */
    {0, SSL_TXT_CMPALL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},

    /*
     * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in
     * ALL!)
     */
    {0, SSL_TXT_CMPDEF, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT, 0, 0, 0},

    /*
     * key exchange aliases (some of those using only a single bit here
     * combine multiple key exchange algs according to the RFCs, e.g. kEDH
     * combines DHE_DSS and DHE_RSA)
     */
    {0, SSL_TXT_kRSA, 0, SSL_kRSA, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kDHr, 0, SSL_kDHr, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHd, 0, SSL_kDHd, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDH, 0, SSL_kDHr | SSL_kDHd, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kEDH, 0, SSL_kEDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHE, 0, SSL_kEDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DH, 0, SSL_kDHr | SSL_kDHd | SSL_kEDH, 0, 0, 0, 0, 0, 0, 0,
     0},

    {0, SSL_TXT_kKRB5, 0, SSL_kKRB5, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kECDHr, 0, SSL_kECDHr, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHe, 0, SSL_kECDHe, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDH, 0, SSL_kECDHr | SSL_kECDHe, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kEECDH, 0, SSL_kEECDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHE, 0, SSL_kEECDH, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDH, 0, SSL_kECDHr | SSL_kECDHe | SSL_kEECDH, 0, 0, 0, 0, 0,
     0, 0, 0},

    {0, SSL_TXT_kPSK, 0, SSL_kPSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kSRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kGOST, 0, SSL_kGOST, 0, 0, 0, 0, 0, 0, 0, 0},

    /* server authentication aliases */
    {0, SSL_TXT_aRSA, 0, 0, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aDSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aKRB5, 0, 0, SSL_aKRB5, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aNULL, 0, 0, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    /* no such ciphersuites supported! */
    {0, SSL_TXT_aDH, 0, 0, SSL_aDH, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDH, 0, 0, SSL_aECDH, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aPSK, 0, 0, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST94, 0, 0, SSL_aGOST94, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST01, 0, 0, SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST, 0, 0, SSL_aGOST94 | SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aSRP, 0, 0, SSL_aSRP, 0, 0, 0, 0, 0, 0, 0},

    /* aliases combining key exchange and server authentication */
    {0, SSL_TXT_EDH, 0, SSL_kEDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DHE, 0, SSL_kEDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_EECDH, 0, SSL_kEECDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDHE, 0, SSL_kEECDH, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_KRB5, 0, SSL_kKRB5, SSL_aKRB5, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RSA, 0, SSL_kRSA, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ADH, 0, SSL_kEDH, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AECDH, 0, SSL_kEECDH, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_PSK, 0, SSL_kPSK, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0},

    /* symmetric encryption aliases */
    {0, SSL_TXT_DES, 0, 0, 0, SSL_DES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_3DES, 0, 0, 0, SSL_3DES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC4, 0, 0, 0, SSL_RC4, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC2, 0, 0, 0, SSL_RC2, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_IDEA, 0, 0, 0, SSL_IDEA, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SEED, 0, 0, 0, SSL_SEED, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_eNULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES128, 0, 0, 0, SSL_AES128 | SSL_AES128GCM, 0, 0, 0, 0, 0,
     0},
    {0, SSL_TXT_AES256, 0, 0, 0, SSL_AES256 | SSL_AES256GCM, 0, 0, 0, 0, 0,
     0},
    {0, SSL_TXT_AES, 0, 0, 0, SSL_AES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_GCM, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM, 0, 0, 0, 0,
     0, 0},
    {0, SSL_TXT_CAMELLIA128, 0, 0, 0, SSL_CAMELLIA128, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA256, 0, 0, 0, SSL_CAMELLIA256, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA, 0, 0, 0, SSL_CAMELLIA128 | SSL_CAMELLIA256, 0, 0, 0,
     0, 0, 0},

    /* MAC aliases */
    {0, SSL_TXT_MD5, 0, 0, 0, 0, SSL_MD5, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA1, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST94, 0, 0, 0, 0, SSL_GOST94, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST89MAC, 0, 0, 0, 0, SSL_GOST89MAC, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA256, 0, 0, 0, 0, SSL_SHA256, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA384, 0, 0, 0, 0, SSL_SHA384, 0, 0, 0, 0, 0},

    /* protocol version aliases */
    {0, SSL_TXT_SSLV2, 0, 0, 0, 0, 0, SSL_SSLV2, 0, 0, 0, 0},
    {0, SSL_TXT_SSLV3, 0, 0, 0, 0, 0, SSL_SSLV3, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1, 0, 0, 0, 0, 0, SSL_TLSV1, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1_2, 0, 0, 0, 0, 0, SSL_TLSV1_2, 0, 0, 0, 0},

    /* export flag */
    {0, SSL_TXT_EXP, 0, 0, 0, 0, 0, 0, SSL_EXPORT, 0, 0, 0},
    {0, SSL_TXT_EXPORT, 0, 0, 0, 0, 0, 0, SSL_EXPORT, 0, 0, 0},

    /* strength classes */
    {0, SSL_TXT_EXP40, 0, 0, 0, 0, 0, 0, SSL_EXP40, 0, 0, 0},
    {0, SSL_TXT_EXP56, 0, 0, 0, 0, 0, 0, SSL_EXP56, 0, 0, 0},
    {0, SSL_TXT_LOW, 0, 0, 0, 0, 0, 0, SSL_LOW, 0, 0, 0},
    {0, SSL_TXT_MEDIUM, 0, 0, 0, 0, 0, 0, SSL_MEDIUM, 0, 0, 0},
    {0, SSL_TXT_HIGH, 0, 0, 0, 0, 0, 0, SSL_HIGH, 0, 0, 0},
    /* FIPS 140-2 approved ciphersuite */
#endif
};


#endif /* OSSL_SSL_HEADER */
