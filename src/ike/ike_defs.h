/**
 * @file  ike_defs.h
 * @brief IKE protocol definitions.
 *
 * @details    IKEv1 and IKEv2 protocol constants, payload structures, and definitions.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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


/*------------------------------------------------------------------*/
/* internal use only */

#ifndef __IKE_DEFS_HEADER__
#define __IKE_DEFS_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/* Exchange Types */

/* [v1] */
#define ISAKMP_XCHG_IDPROT      2   /* ID Protection (Main) */
#define ISAKMP_XCHG_AGGR        4   /* Aggressive */
#define ISAKMP_XCHG_INFO        5   /* Informational */
#define ISAKMP_XCHG_CFG         6   /* Configuration */
#define ISAKMP_XCHG_QUICK       32  /* Oakley Quick Mode */

#define ISAKMP_XCHG_GPULL       32  /* GDOI PULL */
#define ISAKMP_XCHG_GPUSH       33  /* GDOI PUSH */

#define ISAKMP_XCHG_BASE        1
#define ISAKMP_XCHG_AO          3   /* Authentication Only */
#define ISAKMP_XCHG_NGRP        33  /* Oakley New Group Mode */
#define ISAKMP_XCHG_ACK_INFO    34  /* Oakley Acknowledged Informational */

/* [v2] */
#define IKE_XCHG_INIT           34  /* IKE_SA_INIT */
#define IKE_XCHG_AUTH           35  /* IKE_AUTH */
#define IKE_XCHG_CHILD          36  /* CREATE_CHILD_SA */
#define IKE_XCHG_INFO           37  /* INFORMATIONAL */


/*------------------------------------------------------------------*/
/* Header Flags */

/* [v1] */
#define ISAKMP_FLAG_ENCRYPTION  0x1
#define ISAKMP_FLAG_COMMIT      0x2
#define ISAKMP_FLAG_AUTH_ONLY   0x4

/* [v2] */
#define IKE_FLAG_INITIATOR      0x8
#define IKE_FLAG_VERSION        0x10
#define IKE_FLAG_RESPONSE       0x20


/*------------------------------------------------------------------*/
/* Next Payload Types */

/* [v1] */
#define ISAKMP_NEXT_NONE        0
#define ISAKMP_NEXT_SA          1    /* Security Association */
#define ISAKMP_NEXT_P           2    /* Proposal */
#define ISAKMP_NEXT_T           3    /* Transform */
#define ISAKMP_NEXT_KE          4    /* Key Exchange */
#define ISAKMP_NEXT_ID          5    /* Identification */
#define ISAKMP_NEXT_CERT        6    /* Certificate */
#define ISAKMP_NEXT_CR          7    /* Certificate Request */
#define ISAKMP_NEXT_HASH        8    /* Hash */
#define ISAKMP_NEXT_SIG         9    /* Signature */
#define ISAKMP_NEXT_NONCE       10   /* Nonce */
#define ISAKMP_NEXT_N           11   /* Notification */
#define ISAKMP_NEXT_D           12   /* Delete */
#define ISAKMP_NEXT_VID         13   /* Vendor ID */
#define ISAKMP_NEXT_ATTR        14   /* Attributes, e.g. Mode Config */
#define ISAKMP_NEXT_NAT_D       20   /* NAT Discovery (RFC 3947) */
#define ISAKMP_NEXT_NAT_OA      21   /* NAT Original Address (RFC 3947) */
        /* draft-ietf-ipsec-nat-t-ike-04...08 */
#define ISAKMP_NEXT_NAT_D_DRAFTS_48     15  /* NAT Discovery */
#define ISAKMP_NEXT_NAT_OA_DRAFTS_48    16  /* NAT Original Address */
        /* draft-ietf-ipsec-nat-t-ike-00...03 */
#define ISAKMP_NEXT_NAT_D_DRAFTS        130 /* NAT Discovery */
#define ISAKMP_NEXT_NAT_OA_DRAFTS       131 /* NAT Original Address */
#define ISAKMP_NEXT_FRAGMENT    132  /* Fragment */

#define ISAKMP_NEXT_SAK         15   /* GDOI [RFC6407] */
#define ISAKMP_NEXT_SAT         16
#define ISAKMP_NEXT_KD          17
#define ISAKMP_NEXT_SEQ         18
#define ISAKMP_NEXT_GAP         22

/* [v2] */
#define IKE_NEXT_NONE           0
#define IKE_NEXT_SA             33  /* Security Association */
#define IKE_NEXT_KE             34  /* Key Exchange */
#define IKE_NEXT_ID_I           35  /* Identification - Initiator (IDi) */
#define IKE_NEXT_ID_R           36  /* Identification - Responder (IDr) */
#define IKE_NEXT_CERT           37  /* Certificate */
#define IKE_NEXT_CERTREQ        38  /* Certificate Request */
#define IKE_NEXT_AUTH           39  /* Authentication */
#define IKE_NEXT_NONCE          40  /* Nonce (Ni, Nr) */
#define IKE_NEXT_N              41  /* Notify */
#define IKE_NEXT_D              42  /* Delete */
#define IKE_NEXT_V              43  /* Vendor ID */
#define IKE_NEXT_TS_I           44  /* Traffic Selector - Initiator (TSi) */
#define IKE_NEXT_TS_R           45  /* Traffic Selector - Responder (TSr) */
#define IKE_NEXT_E              46  /* Encrypted */
#define IKE_NEXT_CP             47  /* Configuration */
#define IKE_NEXT_EAP            48  /* Extensible Authentication */
#define IKE_NEXT_EF             53  /* Encrypted Fragment */
        /* private use          128-255 */


/*------------------------------------------------------------------*/
/* [v1] SA Payload */

#define ISAKMP_DOI_IPSEC        1
#define ISAKMP_GDOI             2   /* [RFC6407] */

#define SIT_IDENTITY_ONLY       0x01
#define SIT_SECRECY             0x02
#define SIT_INTEGRITY           0x04


/*------------------------------------------------------------------*/
/* Proposal Protocol ID's */

#define PROTO_ISAKMP            1
#define PROTO_IPSEC_AH          2
#define PROTO_IPSEC_ESP         3

#define PROTO_IPCOMP            4   /* [v1] */
#define PROTO_GIGABEAM_RADIO    5   /* [RFC4705] */
#define PROTO_FC_ESP_HEADER     4   /* [RFC4595] */
#define PROTO_FC_CT_AUTH        5


/*------------------------------------------------------------------*/
/* [v1] Phase 1 Transform Payload */

/* transform id */

#define KEY_IKE         1

/* attribute type */

#define OAKLEY_ENCRYPTION_ALGORITHM    1
#define OAKLEY_HASH_ALGORITHM          2
#define OAKLEY_AUTHENTICATION_METHOD   3
#define OAKLEY_GROUP_DESCRIPTION       4
#define OAKLEY_GROUP_TYPE              5
#define OAKLEY_GROUP_PRIME             6    /* B/V */
#define OAKLEY_GROUP_GENERATOR_ONE     7    /* B/V */
#define OAKLEY_GROUP_GENERATOR_TWO     8    /* B/V */
#define OAKLEY_GROUP_CURVE_A           9    /* B/V */
#define OAKLEY_GROUP_CURVE_B          10    /* B/V */
#define OAKLEY_LIFE_TYPE              11
#define OAKLEY_LIFE_DURATION          12    /* B/V */
#define OAKLEY_PRF                    13
#define OAKLEY_KEY_LENGTH             14
#define OAKLEY_FIELD_SIZE             15
#define OAKLEY_GROUP_ORDER            16    /* B/V */
#define OAKLEY_BLOCK_SIZE             17

#define NUM_OAKLEY_ATTRIBUTE_TYPE     18

/* attribute value */

/* encryption algorithm */
#define OAKLEY_DES_CBC          1
#define OAKLEY_IDEA_CBC         2
#define OAKLEY_BLOWFISH_CBC     3
#define OAKLEY_RC5_R16_B64_CBC  4
#define OAKLEY_3DES_CBC         5
#define OAKLEY_CAST_CBC         6
#define OAKLEY_AES_CBC          7
#define OAKLEY_CAMELLIA_CBC     8

/* hash algorithm */
#define OAKLEY_MD5              1
#define OAKLEY_SHA              2
#define OAKLEY_TIGER            3
#define OAKLEY_SHA2_256         4
#define OAKLEY_SHA2_384         5
#define OAKLEY_SHA2_512         6

#define OAKLEY_HASH_NA          0xffff  /* internal use only */

        /* private use          65001-65535 */
#define OAKLEY_BLAKE2_2B        65201
#define OAKLEY_BLAKE2_2S        65202


/* authentication method */
#define OAKLEY_PRESHARED_KEY    1
#define OAKLEY_DSS_SIG          2
#define OAKLEY_RSA_SIG          3
#define OAKLEY_RSA_ENC          4
#define OAKLEY_RSA_ENC_REV      5
#define OAKLEY_ELGAMAL_ENC      6
#define OAKLEY_ELGAMAL_ENC_REV  7
#define OAKLEY_ECDSA_SIG        8       /* Paul Fahn, <pfahn&certicom.com>, January 2000. */
#define OAKLEY_ECDSA_256        9       /* [RFC4754] */
#define OAKLEY_ECDSA_384        10
#define OAKLEY_ECDSA_521        11

/* Authentication Method Private use 65001-65535 */
#define OAKLEY_P256_MLDSA_44    63301
#define OAKLEY_P256_FNDSA512    63302
#define OAKLEY_P384_MLDSA_65    63306
#define OAKLEY_P521_FNDSA1024   63311
#define OAKLEY_P521_MLDSA_87    63312

#ifdef __ENABLE_IKE_HYBRID_RSA__
        /* draft-ietf-ipsec-isakmp-hybrid-auth-05 */
#define HYBRID_INIT_RSA             64221
#define HYBRID_RESP_RSA             64222
#endif /* __ENABLE_IKE_HYBRID_RSA__ */

/* group description */
#define OAKLEY_GROUP_MODP768        1
#define OAKLEY_GROUP_MODP1024       2
#define OAKLEY_GROUP_MODP1536       5
#define OAKLEY_GROUP_MODP2048       14
#define OAKLEY_GROUP_MODP3072       15
#define OAKLEY_GROUP_MODP4096       16
#define OAKLEY_GROUP_MODP6144       17
#define OAKLEY_GROUP_MODP8192       18
#define OAKLEY_GROUP_ECP256         19  /* [RFC4753] */
#define OAKLEY_GROUP_ECP384         20
#define OAKLEY_GROUP_ECP521         21
#define OAKLEY_GROUP_MODP2048_256   24  /* [RFC5114 3.2.] */
#define OAKLEY_GROUP_ECP192         25
#define OAKLEY_GROUP_ECP224         26
#define OAKLEY_GROUP_ED25519        31
#define OAKLEY_GROUP_ED448          32

#define OAKLEY_GROUP_P256_MLKEM512          2223
#define OAKLEY_GROUP_P384_MLKEM768          2227
#define OAKLEY_GROUP_P521_MLKEM1024         2232


#define OAKLEY_GROUP_DEFAULT        0xffff  /* (ubyte2)(-1) */

/* group type */
#define OAKLEY_GROUP_TYPE_MODP  1       /* modular exponentiation group */
#define OAKLEY_GROUP_TYPE_ECP   2       /* elliptic curve group over GF[P] */
#define OAKLEY_GROUP_TYPE_EC2N  3       /* elliptic curve group over GF[2^N] */

/* life type */
#define OAKLEY_LIFE_SECONDS     1
#define OAKLEY_LIFE_KILOBYTES   2


/*------------------------------------------------------------------*/
/* [v1] Phase 2 Transform Payloads */

/* AH transform payload */

/* transform id */
#define AH_MD5                  2
#define AH_SHA                  3
#define AH_DES                  4
#define AH_SHA2_256             5
#define AH_SHA2_384             6
#define AH_SHA2_512             7
#define AH_RIPEMD               8   /* [RFC2857] (!) */
#define AH_AES_XCBC             9
#define AH_RSA                  10  /* [RFC4359] (!) */
#define AH_AES_128_GMAC         11  /* [RFC4543][Errata1821] (!) */
#define AH_AES_192_GMAC         12
#define AH_AES_256_GMAC         13

        /* private use          249-255 */
#define AH_BLAKE2B              254
#define AH_BLAKE2S              255

/* ESP transform payload */

/* transform id's */
#define ESP_DES_IV64            1
#define ESP_DES                 2
#define ESP_3DES                3
#define ESP_RC5                 4
#define ESP_IDEA                5
#define ESP_CAST                6
#define ESP_BLOWFISH            7
#define ESP_3IDEA               8
#define ESP_DES_IV32            9
#define ESP_RC4                 10
#define ESP_NULL                11
#define ESP_AES                 12
#define ESP_AES_CTR             13  /* [RFC3686] */
#define ESP_AES_CCM_8           14  /* [RFC4309 7.3.] (!) */
#define ESP_AES_CCM_12          15
#define ESP_AES_CCM_16          16
#define ESP_AES_GCM_8           18  /* [RFC4106 8.3.] */
#define ESP_AES_GCM_12          19
#define ESP_AES_GCM_16          20
#define ESP_SEED_CBC            21  /* [RFC4196 5.2.] (!) */
#define ESP_CAMELLIA            22  /* [RFC4312] (!) */
#define ESP_NULL_AES_GMAC       23  /* [RFC4543 9.][Errata1821] */
#define ESP_CHACHA20_POLY1305   28  /* [RFC7634] */
        /* private use          249-255 */
#define ESP_MARS                249
#define ESP_RC6                 250
#define ESP_SERPENT             252
#define ESP_TWOFISH             253

/* IPCOMP transform payload (!) */

/* transform id's */
#define IPCOMP_OUI              1
#define IPCOMP_DEFLATE          2   /* [RFC2394] */
#define IPCOMP_LZS              3   /* [RFC2395] */
#define IPCOMP_LZJH             4   /* [RFC3051] */


/* attribute type */

#define SA_LIFE_TYPE            1
#define SA_LIFE_DURATION        2   /* B/V */
#define GROUP_DESCRIPTION       3
#define ENCAPSULATION_MODE      4
#define AUTH_ALGORITHM          5
#define KEY_LENGTH              6
#define KEY_ROUNDS              7
#define COMPRESS_DICT_SIZE      8
#define COMPRESS_PRIVATE_ALG    9   /* B/V */
#define ECN_TUNNEL              10  /* 1 or 2   [RFC3168] */
#define EXT_SEQ_NO              11  /* 1        [RFC4304] */
#define AUTH_KEY_LENGTH         12  /* B/V      [RFC4359] */
#define SIG_ENC_ALGORITHM       13  /*          [RFC4359] */


/* attribute value */

/* life type */
#define SA_LIFE_TYPE_SECONDS    1
#define SA_LIFE_TYPE_KBYTES     2

/* encapsulation mode */
#define ENCAPSULATION_MODE_TUNNEL               1
#define ENCAPSULATION_MODE_TRANSPORT            2
#define ENCAPSULATION_MODE_UDP_TUNNEL           3
#define ENCAPSULATION_MODE_UDP_TRANSPORT        4
        /* draft-ietf-ipsec-nat-t-ike-00...03 */
#define ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS    61443
#define ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS 61444

/* authentication algorithm */
#define AUTH_ALGORITHM_HMAC_MD5         1
#define AUTH_ALGORITHM_HMAC_SHA         2
#define AUTH_ALGORITHM_DES_MAC          3
#define AUTH_ALGORITHM_KPDK             4
#define AUTH_ALGORITHM_HMAC_SHA2_256    5
#define AUTH_ALGORITHM_HMAC_SHA2_384    6
#define AUTH_ALGORITHM_HMAC_SHA2_512    7
#define AUTH_ALGORITHM_HMAC_RIPEMD      8       /* [RFC2857] (!) */
#define AUTH_ALGORITHM_AES_XCBC_MAC     9
#define AUTH_ALGORITHM_SIG_RSA          10      /* [RFC4359] (!) */

        /* private use                  61440-65535 */
#define AUTH_ALGORITHM_HMAC_BLAKE2_2B   62225
#define AUTH_ALGORITHM_HMAC_BLAKE2_2S   62226


/*------------------------------------------------------------------*/
/* [v2] Transform Payloads */

/* Transform Types */
#define TFM_ENCR                1   /* Encryption Algorithm (IKE and ESP) */
#define TFM_PRF                 2   /* Pseudo-random Function (IKE) */
#define TFM_INTEG               3   /* Integrity Algorithm (IKE, AH, optional in ESP) */
#define TFM_DH                  4   /* Diffie-Hellman Group (IKE, optional in AH & ESP) */
#define TFM_ESN                 5   /* Extended Sequence Numbers (AH and ESP) */

#define MIN_TFM_TYPE            TFM_ENCR
#define NUM_TFM_TYPE            5

/* Transform ID's */

/* Encryption Algorithm (1) */
#define ENCR_DES                2
#define ENCR_3DES               3
#define ENCR_BLOWFISH           7
#define ENCR_NULL               11
#define ENCR_AES_CBC            12
#define ENCR_AES_CTR            13  /* [RFC3686]        ESP */
#define ENCR_AES_CCM_8          14  /* [RFC5282 7.2.]   IKEv2 Identifier */
#define ENCR_AES_CCM_12         15
#define ENCR_AES_CCM_16         16
#define ENCR_AES_GCM_8          18  /* [RFC5282 7.2.]   IKEv2 Identifier */
#define ENCR_AES_GCM_12         19
#define ENCR_AES_GCM_16         20
#define ENCR_NULL_AES_GMAC      21  /* [RFC4543 9.]     ESP */
#define ENCR_CHACHA20_POLY1305  28  /* [RFC7634] */

/* Pseudo-random Function (2) */
#define PRF_HMAC_MD5            1
#define PRF_HMAC_SHA1           2
#define PRF_AES128_XCBC         4   /* [RFC4434] */
#define PRF_HMAC_SHA2_256       5   /* [RFC4868] */
#define PRF_HMAC_SHA2_384       6
#define PRF_HMAC_SHA2_512       7

        /* private use                  1024-65535 */
#define PRF_HMAC_BLAKE2_2B      2049
#define PRF_HMAC_BLAKE2_2S      2050
#define PRF_NA                  0xffff /* internal use only */

/* Integrity Algorithm (3) */
#define AUTH_HMAC_MD5_96        1
#define AUTH_HMAC_SHA1_96       2
#define AUTH_AES_XCBC_96        5
#define AUTH_HMAC_SHA2_256_128  12  /* [RFC4868] */
#define AUTH_HMAC_SHA2_384_192  13
#define AUTH_HMAC_SHA2_512_256  14

        /* private use                  1024-65535 */
#define AUTH_HMAC_BLAKE2_2B     2051
#define AUTH_HMAC_BLAKE2_2S     2052


/* Transform Attribute Type */
#define ATTR_KEY_LENGTH         14

#define MIN_ATTR_TYPE           ATTR_KEY_LENGTH
#define NUM_ATTR_TYPE           1


/*------------------------------------------------------------------*/
/* [v2] Auth Methods */

#define AUTH_MTD_RSA_SIG        1   /* RSA Digital Signature */
#define AUTH_MTD_SHARED_KEY     2   /* Shared Key Message Integrity Code */
#define AUTH_MTD_DSS_SIG        3   /* DSS Digital Signature */
#define AUTH_MTD_ECDSA_256      9   /* ECDSA with SHA-256 on the P-256 curve [RFC4754] */
#define AUTH_MTD_ECDSA_384      10  /* ECDSA with SHA-384 on the P-384 curve */
#define AUTH_MTD_ECDSA_521      11  /* ECDSA with SHA-512 on the P-521 curve */
#define AUTH_MTD_SIG            14  /* Digital Signature [RFC7427] */
#define AUTH_MTD_EAP            31  /* internal use only; for Multi-Auth */

#define AUTH_MTD_P256_MLDSA_44  234
#define AUTH_MTD_P256_FNDSA512  235
#define AUTH_MTD_P384_MLDSA_65  239
#define AUTH_MTD_P521_FNDSA1024 244
#define AUTH_MTD_P521_MLDSA_87  245

/* hash algorithm for AUTH_MTD_SIG [RFC7427] */
#define HASH_SHA1               1
#define HASH_SHA2_256           2
#define HASH_SHA2_384           3
#define HASH_SHA2_512           4
#define HASH_IDENTITY           5    /* RFC 8420 */
#define NUM_SIGAUTH_HASH        5


/*------------------------------------------------------------------*/
/* [v2] Traffic Selector Types */

#define TS_IPV4_ADDR_RANGE      7
#define TS_IPV6_ADDR_RANGE      8
#define TS_FC_ADDR_RANGE        9   /* [RFC4595] */


/*------------------------------------------------------------------*/
/* [v1] IKECFG or [v2] CP Configuration Types */

#define CFG_REQUEST             1
#define CFG_REPLY               2
#define CFG_SET                 3
#define CFG_ACK                 4
        /* draft-ietf-ipsec-isakmp-xauth-02 */
#define CFG_AUTH_OK             5
#define CFG_AUTH_FAILED         6
        /* draft-ietf-ipsec-isakmp-xauth-01 */
#define CFG_AUTH_OK_1           105
#define CFG_AUTH_FAILED_1       106


/*------------------------------------------------------------------*/
/* [v1] XAUTH Basic Attribute Values; see 'IKE_XAUTH_ATTR_T' */

/* Authentication Type (i.e. XAUTH_TYPE) */
#define XAUTH_TYPE_GENERIC      0 /* default if no XAUTH_TYPE is present */
#define XAUTH_TYPE_RADIUS_CHAP  1
#define XAUTH_TYPE_OTP          2
#define XAUTH_TYPE_SKEY         3
#define XAUTH_TYPE_OPTIONAL     0xffff /* [internal] 'optional' TYPE_GENERIC */

/* Authentication Status (i.e. XAUTH_STATUS) */
#define XAUTH_STATUS_FAIL       0
#define XAUTH_STATUS_OK         1


/*------------------------------------------------------------------*/
/* [GDOI] SA KEK Payload (SAK) */

/* attribute type */
#define KEK_MANAGEMENT_ALGORITHM    1   /* B */ /* PUSH */
#define KEK_ALGORITHM               2   /* B */
#define KEK_KEY_LENGTH              3   /* B */
#define KEK_KEY_LIFETIME            4   /* V */
#define SIG_HASH_ALGORITHM          5   /* B */
#define SIG_ALGORITHM               6   /* B */
#define SIG_KEY_LENGTH              7   /* B */

/* attribute value */

/* KEK_ALGORITHM */
#define KEK_ALG_DES             1
#define KEK_ALG_3DES            2
#define KEK_ALG_AES             3

/* SIG_HASH_ALGORITHM */
#define SIG_HASH_MD5            1
#define SIG_HASH_SHA1           2
#define SIG_HASH_SHA256         3
#define SIG_HASH_SHA384         4
#define SIG_HASH_SHA512         5

/* SIG_ALGORITHM */
#define SIG_ALG_RSA             1
#define SIG_ALG_DSS             2   /* (!) */
#define SIG_ALG_ECDSS           3   /* (!) */
#define SIG_ALG_ECDSA_256       4
#define SIG_ALG_ECDSA_384       5
#define SIG_ALG_ECDSA_521       6

#define SIG_ALG_P256_MLDSA_44  151
#define SIG_ALG_P256_FNDSA512  152
#define SIG_ALG_P384_MLDSA_65  156
#define SIG_ALG_P521_FNDSA1024 161
#define SIG_ALG_P521_MLDSA_87  162

/*------------------------------------------------------------------*/
/* [GDOI] GAP Payload */

/* attribute type */
#define ACTIVATION_TIME_DELAY   1   /* B */
#define DEACTIVATION_TIME_DELAY 2   /* B */
#define SENDER_ID_REQUEST       3   /* B */ /* PULL, GM */


/*------------------------------------------------------------------*/
/* [GDOI] SA TEK Payload (SAT) */

/* Protocol ID */
#define GDOI_PROTO_IPSEC_ESP    1
#define GDOI_PROTO_IPSEC_AH     2


/*------------------------------------------------------------------*/
/* GDOI: KD Payload */

/* KD Type */
#define KD_TYPE_TEK             1
#define KD_TYPE_KEK             2
#define KD_TYPE_LKH             3
#define KD_TYPE_SID             4   /* PULL */

/* TEK attribute type */
#define TEK_ALGORITHM_KEY       1   /* V */
#define TEK_INTEGRITY_KEY       2   /* V */
#define TEK_SOURCE_AUTH_KEY     3   /* V */

/* KEK attribute type */
#define KEK_ALGORITHM_KEY       1   /* V */
#define SIG_ALGORITHM_KEY       2   /* V */

/* LKH attribute type */
#define LKH_DOWNLOAD_ARRAY      1   /* V */
#define LKH_UPDATE_ARRAY        2   /* V */
#define LKH_SIG_ALGO_KEY        3   /* V */

/* SID attribute type */
#define NUMBER_OF_SID_BITS      1   /* B */
#define SID_VALUE               2   /* V */


/*------------------------------------------------------------------*/
/* [v2] EAP protocol Type */

/* should match 'eapMethodType' in "eap/eap_proto.h" */
typedef enum
{
    EAP_PROTO_NONE=             0,
    EAP_PROTO_MD5=              4,
    EAP_PROTO_GTC=              6,
    EAP_PROTO_TLS=              13,
    EAP_PROTO_LEAP=             17,
    EAP_PROTO_SIM=              18,
    EAP_PROTO_SRP=              19,
    EAP_PROTO_TTLS=             21,
    EAP_PROTO_AKA=              23,
/*  EAP_PROTO_PEAP=             25, */
    EAP_PROTO_MSCHAPv2=         26,
/*  EAP_PROTO_FAST=             43, */
    EAP_PROTO_PSK=              47,
    EAP_PROTO_ANY=              252, /* private use */
    EAP_PROTO_PERP=             253, /* private use */
    EAP_PROTO_RADIUS=           255, /* private use */

} IKE_EAP_PROTO_T;


/*------------------------------------------------------------------*/
/* Identification Type */

typedef enum
{
    ID_IPV4_ADDR=               1,
    ID_FQDN=                    2,
    ID_USER_FQDN=               3,  /* [v1] */
    ID_RFC822_ADDR=             3,  /*  [v2] */
    ID_IPV4_ADDR_SUBNET=        4,  /* [v1] */
    ID_IPV6_ADDR=               5,
    ID_IPV6_ADDR_SUBNET=        6,  /* [v1] */
    ID_IPV4_ADDR_RANGE=         7,  /* [v1] */
    ID_IPV6_ADDR_RANGE=         8,  /* [v1] */
    ID_DER_ASN1_DN=             9,
    ID_DER_ASN1_GN=             10,
    ID_KEY_ID=                  11,
    ID_SCTP_LIST=               12, /* [RFC3554] */
    ID_FC_NAME=                 12, /* [RFC4595] */

} IKE_ID_T;


/*------------------------------------------------------------------*/
/* Certificate Encoding */

typedef enum
{
    CERT_PKCS7_WRAPPED_X509=    1,  /* PKCS #7 wrapped X.509 certificate */
    CERT_PGP=                   2,  /* PGP Certificate  */
    CERT_DNS_SIGNED_KEY=        3,  /* DNS Signed Key */
    CERT_X509_SIGNATURE=        4,  /* X.509 Certificate - Signature */
    CERT_X509_KEY_EXCHANGE=     5,  /* [v1] */
    CERT_KERBEROS_TOKENS=       6,  /* Kerberos Token */
    CERT_CRL=                   7,  /* Certificate Revocation List (CRL) */
    CERT_ARL=                   8,  /* Authority Revocation List (ARL) */
    CERT_SPKI=                  9,  /* SPKI Certificate */
    CERT_X509_ATTRIBUTE=        10, /* X.509 Certificate - Attribute */
    CERT_RAW_RSA=               11, /* Raw RSA Key */
    CERT_URL_X509=              12, /*  [v2] Hash and URL of X.509 certificate */
    CERT_URL_X509_BUNDLE=       13, /*  [v2] Hash and URL of X.509 bundle */
    CERT_OCSP_CONTENT=          14, /* [RFC4806] */

} IKE_CERT_T;


/*------------------------------------------------------------------*/
/* Notify Message Type */

typedef enum
{
    /* [v1] error type */
    INVALID_PAYLOAD_TYPE =      1,
    DOI_NOT_SUPPORTED =         2,
    SITUATION_NOT_SUPPORTED =   3,
    INVALID_COOKIE =            4,
    INVALID_MAJOR_VERSION =     5,
    INVALID_MINOR_VERSION =     6,
    INVALID_EXCHANGE_TYPE =     7,
    INVALID_FLAGS =             8,
    INVALID_MESSAGE_ID =        9,
    INVALID_PROTOCOL_ID =       10,
    INVALID_SPI =               11,
    INVALID_TRANSFORM_ID =      12,
    ATTRIBUTES_NOT_SUPPORTED =  13,
    NO_PROPOSAL_CHOSEN =        14,
    BAD_PROPOSAL_SYNTAX =       15,
    PAYLOAD_MALFORMED =         16,
    INVALID_KEY_INFORMATION =   17,
    INVALID_ID_INFORMATION =    18,
    INVALID_CERT_ENCODING =     19,
    INVALID_CERTIFICATE =       20,
    CERT_TYPE_UNSUPPORTED =     21,
    INVALID_CERT_AUTHORITY =    22,
    INVALID_HASH_INFORMATION =  23,
    AUTHENTICATION_FAILED =     24,
    INVALID_SIGNATURE =         25,
    ADDRESS_NOTIFICATION =      26,
    NOTIFY_SA_LIFETIME =        27,
    CERTIFICATE_UNAVAILABLE =   28,
    UNSUPPORTED_EXCHANGE_TYPE = 29,
    UNEQUAL_PAYLOAD_LENGTHS =   30,

    /* [v1] status type */
    CONNECTED =                 16384,

    /* IPSEC DOI additions; status types (RFC2407 IPSEC DOI 4.6.3)
     * These must be sent under the protection of an ISAKMP SA.
     */
    IPSEC_RESPONDER_LIFETIME =  24576,
    IPSEC_REPLAY_STATUS =       24577,
    IPSEC_INITIAL_CONTACT =     24578,

    /* RFC 3706 (DPD) */
    R_U_THERE =                 36136,
    R_U_THERE_ACK =             36137,

    PRESHARED_KEY_HASH =        40503,

    /* [v2] error types (0 - 16383) */
    UNSUPPORTED_CRITICAL_PAYLOAD =  1,
    INVALID_IKE_SPI =               4,
/*  INVALID_MAJOR_VERSION =         5,*/
    INVALID_SYNTAX =                7,
/*  INVALID_MESSAGE_ID =            9,
    INVALID_SPI =                   11,
    NO_PROPOSAL_CHOSEN =            14,*/
    INVALID_KE_PAYLOAD =            17,
/*  AUTHENTICATION_FAILED =         24,*/
    SINGLE_PAIR_REQUIRED =          34,
    NO_ADDITIONAL_SAS =             35,
    INTERNAL_ADDRESS_FAILURE =      36,
    FAILED_CP_REQUIRED =            37,
    TS_UNACCEPTABLE =               38,
    INVALID_SELECTORS =             39,
    /* [RFC4555] MOBIKE */
    UNACCEPTABLE_ADDRESSES =        40,
    UNEXPECTED_NAT_DETECTED =       41,
    /* [RFC5026] */
    USE_ASSIGNED_HoA =              42,
    /* [RFC5996] */
    TEMPORARY_FAILURE =             43,
    CHILD_SA_NOT_FOUND =            44,

    /* Private Use - Errors         8192 - 16383 */

    /* [v2] status types */
    INITIAL_CONTACT =               16384,
    SET_WINDOW_SIZE =               16385,
    ADDITIONAL_TS_POSSIBLE =        16386,
    IPCOMP_SUPPORTED =              16387,
    NAT_DETECTION_SOURCE_IP =       16388,
    NAT_DETECTION_DESTINATION_IP =  16389,
    NOTIFY_COOKIE =                 16390,
    USE_TRANSPORT_MODE =            16391,
    HTTP_CERT_LOOKUP_SUPPORTED =    16392,
    NOTIFY_REKEY_SA =               16393,
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
    NON_FIRST_FRAGMENTS_ALSO =      16395,
    /* [RFC4555] MOBIKE */
    MOBIKE_SUPPORTED =              16396,
    ADDITIONAL_IP4_ADDRESS =        16397,
    ADDITIONAL_IP6_ADDRESS =        16398,
    NO_ADDITIONAL_ADDRESSES =       16399,
    UPDATE_SA_ADDRESSES =           16400,
    COOKIE2 =                       16401,
    NO_NATS_ALLOWED =               16402,
    /* [RFC4478] Repeated Auth. */
    AUTH_LIFETIME =                 16403,
    /* [RFC4739] Multi. Auth. Exchanges */
    MULTIPLE_AUTH_SUPPORTED =       16404,
    ANOTHER_AUTH_FOLLOWS =          16405,
    /* [RFC5685] Redirect Supported */
    REDIRECT_SUPPORTED =            16406,
    REDIRECT =                      16407,
    REDIRECTED_FROM =               16408,
    /* [RFC5998] EAP-Only Auth. */
    EAP_ONLY_AUTHENTICATION =       16417,
    /* [RFC7383] IKEv2 Message Fragmentation */
    IKEV2_FRAGMENTATION_SUPPORTED = 16430,
    /* [RFC7427] IKEv2 Signature Authentication */
    SIGNATURE_HASH_ALGORITHMS =     16431,
     /* [RFC 8784] Post quantum Preshared key support */
    USE_PPK                   =     16435,
    PPK_IDENTITY              =     16436,
    NO_PPK_AUTH               =     16437,
    /* Private Use - STATUS TYPES   40960 - 65535 */

} IKE_NOTIFY_T;


/*------------------------------------------------------------------*/
/* [v1] MODE_CFG or [v2] Configuration Attribute Type */

typedef enum
{
    INTERNAL_IP4_ADDRESS=       1,
    INTERNAL_IP4_NETMASK=       2,
    INTERNAL_IP4_DNS=           3,
    INTERNAL_IP4_NBNS=          4,
    INTERNAL_ADDRESS_EXPIRY=    5, /* removed [RFC5996] */
    INTERNAL_IP4_DHCP=          6,
    APPLICATION_VERSION=        7,
    INTERNAL_IP6_ADDRESS=       8,
    INTERNAL_IP6_NETMASK=       9,  /* [v1] */
    INTERNAL_IP6_DNS=           10,
    INTERNAL_IP6_NBNS=          11, /* removed [RFC5996] */
    INTERNAL_IP6_DHCP=          12,
    INTERNAL_IP4_SUBNET=        13,
    SUPPORTED_ATTRIBUTES=       14,
    INTERNAL_IP6_SUBNET=        15,
    MIP6_HOME_PREFIX=           16, /* [RFC5026] Multi-Valued YES, 0 or 21 octets */

    CISCO_BANNER=               0x7000,
    //CISCO_SAVE_PWD=           0x7001, /* B */
    INTERNAL_DFLT_DOMAIN_CISCO= 0x7002,
    CISCO_SPLIT_DNS=            0x7003,
    INTERNAL_IP4_SUBNET_CISCO=  0x7004,
    //CISCO_UDP_ENCAP_PORT=     0x7005, /* ? */
    //CISCO_UNKNOWN=            0x7006, /* Include Local LAN ? */
    CISCO_DO_PFS=               0x7007, /* B */
    CISCO_FW_TYPE=              0x7008,
    //CISCO_BACKUP_SERVER=      0x7009,
    CISCO_DDNS_HOSTNAME=        0x700a,

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    MOCANA_TUNNEL_MTU=          0x6000,
#endif

} IKE_CFG_ATTR_T;


/*------------------------------------------------------------------*/
/* [v1] XAUTH Attribute Type */

typedef enum
{
    /* draft-ietf-ipsec-isakmp-xauth-01 */
    XAUTH_TYPE_1=               101,
    XAUTH_USER_NAME_1=          102,
    XAUTH_USER_PASSWORD_1=      103,
    XAUTH_PASSCODE_1=           104,
    XAUTH_MESSAGE_1=            105,
    XAUTH_CHALLENGE_1=          106,
    XAUTH_DOMAIN_1=             107,

    /* draft-ietf-ipsec-isakmp-xauth-02...05 */
    XAUTH_TYPE_25=              13,
    XAUTH_USER_NAME_25=         14,
    XAUTH_USER_PASSWORD_25=     15,
    XAUTH_PASSCODE_25=          16,
    XAUTH_MESSAGE_25=           17,
    XAUTH_CHALLENGE_25=         18,
    XAUTH_DOMAIN_25=            19,

    /* draft-ietf-ipsec-isakmp-xauth-03...05 */
    XAUTH_STATUS_35=            20,

    /* draft-ietf-ipsec-isakmp-xauth-03...04 */
    XAUTH_REQ_NUMBER=           21,     /* Basic */

    /* draft-ietf-ipsec-isakmp-xauth-06... */
    XAUTH_TYPE=                 16520,  /*  Basic */
    XAUTH_USER_NAME=            16521,  /* Variable */
    XAUTH_USER_PASSWORD=        16522,  /* V */
    XAUTH_PASSCODE=             16523,  /* V */
    XAUTH_MESSAGE=              16524,  /* V */
    XAUTH_CHALLENGE=            16525,  /* V */
    XAUTH_DOMAIN=               16526,  /* V */
    XAUTH_STATUS=               16527,  /*  B */

    /* draft-beaulieu-ike-xauth-00... */
    XAUTH_NEXT_PIN=             16528,  /* V */
    XAUTH_ANSWER=               16529,  /* V */

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    /* Digicert private policy enrollment reporting protocol */
    XAUTH_MOCANA_PERP=          22542,  /* V */
#endif

    /* Cisco ASA Sends this attribute between
     * user-name and passcode when integrated
     * with RSA Secure ID over SDI Protocol.
     * We need to ignore/skip this in order to
     * process the ones needed.
    */
    XAUTH_PRIVATE_VENDOR_EXT1=  32136,  /* 0x7d88 */

} IKE_XAUTH_ATTR_T;

typedef enum
{
    REDIRECT_GW_TYPE_IPV4=      1,
    REDIRECT_GW_TYPE_IPV6=      2,
    REDIRECT_GW_TYPE_FQDN=      3,
} REDIRECT_GW_TYPE_T;


/*------------------------------------------------------------------*/

/*
 * Some build environments implement #pragma pack() differently.
 * Call these out with a separate #define. (DRY)
 */
#if defined(__RTOS_OSX__)
# define __DIGICERT_ALTERNATE_PACK_CONVENTION__
#endif

#ifdef __DIGICERT_ALTERNATE_PACK_CONVENTION__
# pragma pack(push,1)
#else
# pragma pack()
#endif

#ifndef IKE_PACKED
#define IKE_PACKED
#endif

#ifndef IKE_PACKED_POST
#define IKE_PACKED_POST
#endif


/*------------------------------------------------------------------*/
/* IKE Header */

IKE_PACKED
struct ikeHdr
{
    ubyte   poCky_I[8];     /* IKE_COOKIE_SIZE x 2*/
    ubyte   poCky_R[8];
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oVersion;       /* major: higher 4 bits */
    ubyte   oExchange;      /* exchange type */
    ubyte   oFlags;
    ubyte4  dwMsgId;        /* message ID */
    ubyte4  dwLength;       /* total message length */
}
IKE_PACKED_POST;

#define SIZEOF_ISAKMP_HDR 28


/*------------------------------------------------------------------*/
/* Generic Payload Header */

IKE_PACKED
struct ikeGenHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* total payload length */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_GEN_HDR 4


/*------------------------------------------------------------------*/
/* [v1] SA (Security Association) Payload Header */

IKE_PACKED
struct ikeSaHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including all proposal and transform payloads */

    ubyte   oUnused[3];
    ubyte   oDoi;           /* DOI */
    ubyte   oUnused1[3];
    ubyte   oSit;           /* situation */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_SA_HDR 12


/*------------------------------------------------------------------*/
/* Proposal Payload Header */

IKE_PACKED
struct ikePpsHdr
{
    ubyte   oNextPayload;   /* next payload type; 0 (last) or 2 */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including all tranforms and attributes that follow */

    ubyte   oNum;
    ubyte   oProtoId;       /* PROTO_ISAKMP, PROTO_IPSEC_AH, PROTO_IPSEC_ESP or [v1] PROTO_IPCOMP */
    ubyte   oSpiSize;       /*  [v2] for IKE_SA, must be 0 for initial negotiation and 8 for rekeying */
    ubyte   oTfmLen;        /* # of transforms */

#define SIZEOF_IKE_PPS_HDR 8

    ubyte4  dwSpi;
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* Transform Payload Header */

#define SIZEOF_IKE_TFM_HDR 8

/* [v1] */
IKE_PACKED
struct ikeTfmHdr
{
    ubyte   oNextPayload;   /* next payload type; 0 (last) or 3 */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Header and Attributes */

    ubyte   oNum;
    ubyte   oAttrId;        /* e.g. IKE_KEY, AH_MD5, ESP_3DES, IPCOMP_DEFLATE, etc. */
    ubyte2  wReserved;
}
IKE_PACKED_POST;

/* [v2] */
IKE_PACKED
struct ike2TfmHdr
{
    ubyte   oNextPayload;   /* next payload type; 0 (last) or 3 */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Header and Attributes */

    ubyte   oType;          /* Transform Type */
    ubyte   oReserved1;
    ubyte2  wTfmId;         /* Transform ID */
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* [GDOI] Security Association Payload */

IKE_PACKED
struct gdoiSaHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including all TEK & KEK payloads */

    ubyte   oUnused[3];
    ubyte   oDoi;           /* DOI */
    ubyte   oUnused1[3];
    ubyte   oSit;           /* situation */

    ubyte   oUnused2;
    ubyte   oNextSaaPayload;/* next SA Attribute payload type */
    ubyte2  wReserved2;     /* e.g. ISAKMP_NEXT_{SAK | GAP | SAT} */
}
IKE_PACKED_POST;

#define SIZEOF_GDOI_SA_HDR 16


/*------------------------------------------------------------------*/
/* [GDOI] SA KEK/TEK Payload (SAK/SAT) Header */

IKE_PACKED
struct gdoiSaaHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including TEK Protocol-Specific Payload */

    ubyte   oProtoId;       /* GDOI_PROTO_IPSEC_{ESP|AH} for SAT, UDP for SAK */
}
IKE_PACKED_POST;

#define SIZEOF_GDOI_SAA_HDR 5

#define SIZEOF_GDOI_SAA_ID 5


/*------------------------------------------------------------------*/
/* [GDOI] KD Payload Header */

IKE_PACKED
struct gdoiKdHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Header & Key Packets */

    ubyte2  wNum;           /* # of Key Packets */
    ubyte2  wReserved2;
}
IKE_PACKED_POST;

#define SIZEOF_GDOI_KD_HDR 8

IKE_PACKED
struct gdoiKP
{
    ubyte   oType;          /* KD_TYPE_{TEK | KEK | LKH | SID} */
    ubyte   oReserved;
    ubyte2  wLength;        /* KD Length: including Header, SPI & Attributes */

    ubyte   oSpiSize;
}
IKE_PACKED_POST;

#define SIZEOF_GDOI_KP 5


/*------------------------------------------------------------------*/
/* Data Attributes */

IKE_PACKED
struct ikeAttr0
{
    ubyte   oAF;
    ubyte   oReserved;
    ubyte2  wReserved;
}
IKE_PACKED_POST;

IKE_PACKED
struct ikeAttr
{
    ubyte2  wAFtype;
    ubyte2  wLenVal;

#define SIZEOF_IKE_ATTR 4

    ubyte4  dwValue;    /* [v1] */
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* [v2] Key Exchange Payload Header */

IKE_PACKED
struct ikeKeHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Key Exchange Data */

    ubyte2  wGrpNo;         /* DH Group # */
    ubyte2  wReserved;
}
IKE_PACKED_POST;

#define SIZEOF_IKE_KE_HDR 8


/*------------------------------------------------------------------*/
/* Identification Payload Header */

IKE_PACKED
struct ikeIdHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including identification data */

    ubyte   oType;          /* see IKE_ID_T */
    ubyte   oProtocol;      /* [v1] */
    ubyte2  wPort;          /* [v1] */

#define SIZEOF_IKE_ID_HDR 8

    ubyte4  dwIpAddr;
    ubyte4  dwIpAddrEnd;    /* [v1] */
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* Certificate Payload Header */

IKE_PACKED
struct ikeCertHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including certificate encoding/data */

    ubyte   oEncoding;      /* see IKE_CERT_T */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_CERT_HDR 5


/*------------------------------------------------------------------*/
/* Certificate Request Payload Header */

IKE_PACKED
struct ikeCRHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including certificate type/authority */

    ubyte   oType;          /* see IKE_CERT_T */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_CR_HDR 5


/*------------------------------------------------------------------*/
/* [v2] Authentication Payload Header */

IKE_PACKED
struct ikeAuthHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Authentication Data */

    ubyte   oMethod;
    ubyte   oReserved1[3];
}
IKE_PACKED_POST;

#define SIZEOF_IKE_AUTH_HDR 8


/*------------------------------------------------------------------*/
/* Notify Payload Header */

/* [v1] */
IKE_PACKED
struct ikeNotifyHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including SPI and notification data */

    ubyte   oUnused[3];
    ubyte   oDoi;           /* 0 or ISAKMP_DOI_IPSEC */

    ubyte   oProtoId;       /* PROTO_ISAKMP, PROTO_IPSEC_AH, PROTO_IPSEC_ESP, etc. */
    ubyte   oSpiSize;       /* 0-16 for ISAKMP, 4 for IPsec */
    ubyte2  wMsgType;       /* see IKE_NOTIFY_T */

#define SIZEOF_IKE_NOTIFY_HDR 12

    ubyte4  dwSpi;
}
IKE_PACKED_POST;

/* [v2] */
IKE_PACKED
struct ike2NotifyHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including SPI and notification data */

    ubyte   oProtoId;       /* PROTO_ISAKMP, PROTO_IPSEC_AH, PROTO_IPSEC_ESP, or 0 */
    ubyte   oSpiSize;       /* must be 0 for IKE or if no SPI is applicable */
    ubyte2  wMsgType;       /* see IKE_NOTIFY_T */

#define SIZEOF_IKE2_NOTIFY_HDR 8

    ubyte4  dwValue;
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* Delete Payload Header */

/* [v1] */
IKE_PACKED
struct ikeDelHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including SPI's */

    ubyte   oUnused[3];
    ubyte   oDoi;           /* DOI */

    ubyte   oProtoId;       /* e.g. PROTO_ISAKMP, PROTO_IPSEC_AH, PROTO_IPSEC_ESP. etc. */
    ubyte   oSpiSize;
    ubyte2  wSpiNum;

#define SIZEOF_IKE_DEL_HDR 12

    ubyte4  adwSpi[65536];
}
IKE_PACKED_POST;

/* [v2] */
IKE_PACKED
struct ike2DelHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including SPI's */

    ubyte   oProtoId;       /* PROTO_ISAKMP, PROTO_IPSEC_AH, or PROTO_IPSEC_ESP */
    ubyte   oSpiSize;       /* must be 0 for IKE (SPI is in message header) */
    ubyte2  wSpiLen;        /* # of SPI's */

#define SIZEOF_IKE2_DEL_HDR 8

    ubyte4  adwSpi[65536];
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* [v2] Traffic Selector */

IKE_PACKED
struct ikeTS
{
    ubyte   oType;          /* TS_IPV4_ADDR_RANGE or TS_IPV6_ADDR_RANGE */
    ubyte   oProtocol;      /* e.g. IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, etc. */
    ubyte2  wLength;        /* total selector length */

    ubyte2  wPort;
    ubyte2  wPortEnd;

#define SIZEOF_IKE_TS 8

    ubyte4  dwIpAddr, dwIpAddrEnd; /* for IPv4 */
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* [v2] Traffic Selector Payload Header */

IKE_PACKED
struct ikeTsHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Traffic Selectors */

    ubyte   oTsLen;         /* # of TS's */
    ubyte   oReserved1[3];
}
IKE_PACKED_POST;

#define SIZEOF_IKE_TS_HDR 8


/*------------------------------------------------------------------*/
/* [v1] IKECFG ATTR or [v2] CP Configuration Payload Header */

IKE_PACKED
struct ikeCfgHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including Attributes */

    ubyte   oType;          /* CFG_{REQUEST | REPLY | SET | ACK} */
    ubyte   oReserved1;

    ubyte2  wIdentifier;    /* [v1] */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_CFG_HDR 8


/*------------------------------------------------------------------*/
/* [v1] IKECFG or [v2] CP Configuration Attribute Header */

IKE_PACKED
struct ikeCfgAttrHdr
{
    ubyte2  wType;          /* see IKE_{CFG | XAUTH}_ATTR_T; 1st bit is reserved */
    ubyte2  wLength;        /* length in octets of Value (or basic value in some XAUTH cases) */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_CFG_ATTR_HDR 4


/*------------------------------------------------------------------*/
/* [v2] EAP Message Header */

IKE_PACKED
struct eapMsgHdr
{
    ubyte   oCode;
    ubyte   oIdentifier;
    ubyte2  wLength;        /* message length */

#define SIZEOF_EAP_MSG_HDR 4

    ubyte   oType;
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* [v1] NAT-OA Payload Header */

IKE_PACKED
struct ikeNatOaHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including IP address */

    ubyte   oIdType;        /* ID_IPV4_ADDR or ID_IPV6_ADDR */
    ubyte   oReserved1[3];

#define SIZEOF_IKE_NATOA_HDR 8

    ubyte4  dwIpAddr;       /* for IPv4 */
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* NAT ESP Marker */

IKE_PACKED
struct ikeNatEspMarker
{
    ubyte4  dwSpi;
    ubyte4  dwUnused;
}
IKE_PACKED_POST;


/*------------------------------------------------------------------*/
/* Fragment Payload */

/* [v1] */
IKE_PACKED
struct ikeFragHdr
{
    ubyte   oNextPayload;   /* next payload type */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including hdr length */

    ubyte2  wFragId;
    ubyte   oFragNum;
    ubyte   oFlags;
}
IKE_PACKED_POST;

/* [v2] */
IKE_PACKED
struct ike2FragHdr
{
    ubyte   oNextPayload;   /* next payload type; only valid for 1st fragment */
    ubyte   oReserved;
    ubyte2  wLength;        /* payload length; including hdr length */

    ubyte2  wFragNum;       /* != 0 */
    ubyte2  wTotalFragments;/* >= wFragNum */
}
IKE_PACKED_POST;

#define SIZEOF_IKE_FRAG_HDR 8


/*------------------------------------------------------------------*/
/* [v2] Notify Payload NO_NATS_ALLOWED data (MOBIKE) */

IKE_PACKED
struct ikeNoNatsA
{
    ubyte4 dwSrcAddr;
    ubyte4 dwDstAddr;
    ubyte2 wSrcPort;
    ubyte2 wDstPort;
}
IKE_PACKED_POST;

#define SIZEOF_IKE_NNA_DATA 12

IKE_PACKED
struct ikeNoNatsA6
{
    ubyte srcAddr[16];
    ubyte dstAddr[16];
    ubyte2 wSrcPort;
    ubyte2 wDstPort;
}
IKE_PACKED_POST;

IKE_PACKED
struct ikeRedirect
{
    ubyte   gwIdType;
    ubyte   gwIdLen;
    ubyte4  gwAddr;
    ubyte   nonce[IKE_NONCE_SIZE];
}
IKE_PACKED_POST;

#define SIZEOF_IKE_NNA6_DATA 36


/*------------------------------------------------------------------*/

#ifdef __DIGICERT_ALTERNATE_PACK_CONVENTION__
# pragma pack(pop)
#endif


/*------------------------------------------------------------------*/
/* Protocols */

#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4    4       /* IPv4 encapsulation */
#endif

#ifndef IPPROTO_ESP
#define IPPROTO_ESP     50      /* IPv6 Encap Sec. Payload */
#endif

#ifndef IPPROTO_AH
#define IPPROTO_AH      51      /* IPv6 Auth Header */
#endif


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_DEFS_HEADER__ */

