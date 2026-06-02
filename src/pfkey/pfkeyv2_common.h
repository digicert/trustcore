/* PF_KEY user interface, this is defined by rfc2367 so
 * do not make arbitrary modifications or else this header
 * file will not be compliant.
 */

#ifndef __PFKEY_COMMON_HEADER__
#define __PFKEY_COMMON_HEADER__

#ifndef AF_INET
#define AF_INET         2
#endif

#ifndef PF_KEY
#define PF_KEY          15
#endif

#define PF_KEY_V2       2


/*------------------------------------------------------------------*/

/* Some flavors may need this... */
/* #pragma pack(push,1) */

#ifndef PFKEY_PACKED
#define PFKEY_PACKED
#endif

#ifndef PFKEY_PACKED_POST
#if defined(__LINUX_RTOS__)
#define PFKEY_PACKED_POST   __attribute__((packed))
#else
#define PFKEY_PACKED_POST
#endif
#endif


/*------------------------------------------------------------------*/

PFKEY_PACKED
struct sadb_msg
{
    ubyte       sadb_msg_version;
    ubyte       sadb_msg_type;
    ubyte       sadb_msg_errno;
    ubyte       sadb_msg_satype;
    ubyte2      sadb_msg_len;
    ubyte2      sadb_msg_reserved;
    ubyte4      sadb_msg_seq;
    ubyte4      sadb_msg_pid;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_msg) == 16 */

PFKEY_PACKED
struct sadb_ext
{
    ubyte2      sadb_ext_len;
    ubyte2      sadb_ext_type;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_ext) == 4 */

PFKEY_PACKED
struct sadb_sa
{
    ubyte2      sadb_sa_len;
    ubyte2      sadb_sa_exttype;
    ubyte4      sadb_sa_spi;
    ubyte       sadb_sa_replay;
    ubyte       sadb_sa_state;
    ubyte       sadb_sa_auth;
    ubyte       sadb_sa_encrypt;
    ubyte4      sadb_sa_flags;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_sa) == 16 */

PFKEY_PACKED
struct sadb_lifetime
{
    ubyte2      sadb_lifetime_len;
    ubyte2      sadb_lifetime_exttype;
    ubyte4      sadb_lifetime_allocations;
    ubyte8      sadb_lifetime_bytes;
    ubyte8      sadb_lifetime_addtime;
    ubyte8      sadb_lifetime_usetime;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_lifetime) == 32 */

PFKEY_PACKED
struct sadb_address
{
    ubyte2      sadb_address_len;
    ubyte2      sadb_address_exttype;
    ubyte       sadb_address_proto;
    ubyte       sadb_address_prefixlen;
    ubyte2      sadb_address_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_address) == 8 */

PFKEY_PACKED
struct sadb_key
{
    ubyte2      sadb_key_len;
    ubyte2      sadb_key_exttype;
    ubyte2      sadb_key_bits;
    ubyte2      sadb_key_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_key) == 8 */

PFKEY_PACKED
struct sadb_ident
{
    ubyte2      sadb_ident_len;
    ubyte2      sadb_ident_exttype;
    ubyte2      sadb_ident_type;
    ubyte2      sadb_ident_reserved;
    ubyte8      sadb_ident_id;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_ident) == 16 */

PFKEY_PACKED
struct sadb_sens
{
    ubyte2      sadb_sens_len;
    ubyte2      sadb_sens_exttype;
    ubyte4      sadb_sens_dpd;
    ubyte       sadb_sens_sens_level;
    ubyte       sadb_sens_sens_len;
    ubyte       sadb_sens_integ_level;
    ubyte       sadb_sens_integ_len;
    ubyte4      sadb_sens_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_sens) == 16 */

/* followed by:
    ubyte8  sadb_sens_bitmap[sens_len];
    ubyte8  sadb_integ_bitmap[integ_len];  */

PFKEY_PACKED
struct sadb_prop
{
    ubyte2      sadb_prop_len;
    ubyte2      sadb_prop_exttype;
    ubyte       sadb_prop_replay;
    ubyte       sadb_prop_reserved[3];
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_prop) == 8 */

/* followed by:
    struct sadb_comb sadb_combs[(sadb_prop_len +
        sizeof(ubyte8) - sizeof(struct sadb_prop)) /
        sizeof(struct sadb_comb)]; */

PFKEY_PACKED
struct sadb_comb
{
    ubyte       sadb_comb_auth;
    ubyte       sadb_comb_encrypt;
    ubyte2      sadb_comb_flags;
    ubyte2      sadb_comb_auth_minbits;
    ubyte2      sadb_comb_auth_maxbits;
    ubyte2      sadb_comb_encrypt_minbits;
    ubyte2      sadb_comb_encrypt_maxbits;
    ubyte4      sadb_comb_reserved;
    ubyte4      sadb_comb_soft_allocations;
    ubyte4      sadb_comb_hard_allocations;
    ubyte8      sadb_comb_soft_bytes;
    ubyte8      sadb_comb_hard_bytes;
    ubyte8      sadb_comb_soft_addtime;
    ubyte8      sadb_comb_hard_addtime;
    ubyte8      sadb_comb_soft_usetime;
    ubyte8      sadb_comb_hard_usetime;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_comb) == 72 */

PFKEY_PACKED
struct sadb_supported
{
    ubyte2      sadb_supported_len;
    ubyte2      sadb_supported_exttype;
    ubyte4      sadb_supported_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_supported) == 8 */

/* followed by:
    struct sadb_alg sadb_algs[(sadb_supported_len +
        sizeof(ubyte8) - sizeof(struct sadb_supported)) /
        sizeof(struct sadb_alg)]; */

PFKEY_PACKED
struct sadb_alg
{
    ubyte       sadb_alg_id;
    ubyte       sadb_alg_ivlen;
    ubyte2      sadb_alg_minbits;
    ubyte2      sadb_alg_maxbits;
    ubyte2      sadb_alg_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_alg) == 8 */

PFKEY_PACKED
struct sadb_spirange
{
    ubyte2      sadb_spirange_len;
    ubyte2      sadb_spirange_exttype;
    ubyte4      sadb_spirange_min;
    ubyte4      sadb_spirange_max;
    ubyte4      sadb_spirange_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_spirange) == 16 */

PFKEY_PACKED
struct sadb_x_sa2
{
    ubyte2      sadb_x_sa2_len;
    ubyte2      sadb_x_sa2_exttype;
    ubyte       sadb_x_sa2_mode;
    ubyte       sadb_x_sa2_reserved1;
    ubyte2      sadb_x_sa2_reserved2;
    ubyte4      sadb_x_sa2_sequence;
    ubyte4      sadb_x_sa2_reqid;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_x_sa2) == 16 */

PFKEY_PACKED
struct sadb_x_policy
{
    ubyte2      sadb_x_policy_len;
    ubyte2      sadb_x_policy_exttype;
    ubyte2      sadb_x_policy_type;
    ubyte       sadb_x_policy_dir;
    ubyte       sadb_x_policy_reserved;
    ubyte4      sadb_x_policy_id;
    ubyte4      sadb_x_policy_priority;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_x_policy) == 16 */

PFKEY_PACKED
struct sadb_x_ipsecrequest
{
    ubyte2      sadb_x_ipsecrequest_len;
    ubyte2      sadb_x_ipsecrequest_proto;
    ubyte       sadb_x_ipsecrequest_mode;
    ubyte       sadb_x_ipsecrequest_level;
    ubyte2      sadb_x_ipsecrequest_reserved1;
    ubyte4      sadb_x_ipsecrequest_reqid;
    ubyte4      sadb_x_ipsecrequest_reserved2;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_x_ipsecrequest) == 16 */

/* This defines the TYPE of Nat Traversal in use.  Currently only one
 * type of NAT-T is supported, draft-ietf-ipsec-udp-encaps-06
 */
PFKEY_PACKED
struct sadb_x_nat_t_type
{
    ubyte2      sadb_x_nat_t_type_len;
    ubyte2      sadb_x_nat_t_type_exttype;
    ubyte       sadb_x_nat_t_type_type;
    ubyte       sadb_x_nat_t_type_reserved[3];
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_x_nat_t_type) == 8 */

/* Pass a NAT Traversal port (Source or Dest port) */
PFKEY_PACKED
struct sadb_x_nat_t_port
{
    ubyte2      sadb_x_nat_t_port_len;
    ubyte2      sadb_x_nat_t_port_exttype;
    ubyte2      sadb_x_nat_t_port_port;
    ubyte2      sadb_x_nat_t_port_reserved;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_x_nat_t_port) == 8 */

/* Generic LSM security context */
PFKEY_PACKED
struct sadb_x_sec_ctx
{
    ubyte2      sadb_x_sec_len;
    ubyte2      sadb_x_sec_exttype;
    ubyte       sadb_x_ctx_alg;  /* LSMs: e.g., selinux == 1 */
    ubyte       sadb_x_ctx_doi;
    ubyte2      sadb_x_ctx_len;
}
PFKEY_PACKED_POST;
/* sizeof(struct sadb_sec_ctx) = 8 */


/*------------------------------------------------------------------*/

/* Some flavors need this... */
/* #pragma pack(pop) */


/*------------------------------------------------------------------*/

/* Message types */
#define SADB_RESERVED               0
#define SADB_GETSPI                 1
#define SADB_UPDATE                 2
#define SADB_ADD                    3
#define SADB_DELETE                 4
#define SADB_GET                    5
#define SADB_ACQUIRE                6
#define SADB_REGISTER               7
#define SADB_EXPIRE                 8
#define SADB_FLUSH                  9
#define SADB_DUMP                   10
#define SADB_X_PROMISC              11
#define SADB_X_PCHANGE              12
#define SADB_X_SPDUPDATE            13
#define SADB_X_SPDADD               14
#define SADB_X_SPDDELETE            15
#define SADB_X_SPDGET               16
#define SADB_X_SPDACQUIRE           17
#define SADB_X_SPDDUMP              18
#define SADB_X_SPDFLUSH             19
#define SADB_X_SPDSETIDX            20
#define SADB_X_SPDEXPIRE            21
#define SADB_X_SPDDELETE2           22
#define SADB_X_NAT_T_NEW_MAPPING    23
#define SADB_MAX                    23

/* Security Association flags */
#define SADB_SAFLAGS_PFS            1
#define SADB_SAFLAGS_NOPMTUDISC     0x20000000
#define SADB_SAFLAGS_DECAP_DSCP     0x40000000
#define SADB_SAFLAGS_NOECN          0x80000000

/* Security Association states */
#define SADB_SASTATE_LARVAL         0
#define SADB_SASTATE_MATURE         1
#define SADB_SASTATE_DYING          2
#define SADB_SASTATE_DEAD           3
#define SADB_SASTATE_MAX            3

/* Security Association types */
#define SADB_SATYPE_UNSPEC          0
#define SADB_SATYPE_AH              2
#define SADB_SATYPE_ESP             3
#define SADB_SATYPE_RSVP            5
#define SADB_SATYPE_OSPFV2          6
#define SADB_SATYPE_RIPV2           7
#define SADB_SATYPE_MIP             8
#define SADB_X_SATYPE_IPCOMP        9
#define SADB_SATYPE_MAX             9

/*
    Authentication algorithms
    (MUST match AH_ transform ID's in "ike_defs.h")
 */
#define SADB_AALG_NONE              0
#define SADB_AALG_MD5HMAC           2
#define SADB_AALG_SHA1HMAC          3
#define SADB_X_AALG_SHA2_256HMAC    5
#define SADB_X_AALG_SHA2_384HMAC    6
#define SADB_X_AALG_SHA2_512HMAC    7
#define SADB_X_AALG_RIPEMD160HMAC   8
#define SADB_X_AALG_AES_XCBCMAC     9
#define SADB_X_AALG_NULL            251
#define SADB_AALG_MAX               251

/*
    Encryption algorithms
    (MUST match ESP_ transform ID's in "ike_defs.h")
 */
#define SADB_EALG_NONE              0
#define SADB_EALG_DESCBC            2
#define SADB_EALG_3DESCBC           3
#define SADB_X_EALG_CASTCBC         6
#define SADB_X_EALG_BLOWFISHCBC     7
#define SADB_EALG_NULL              11
#define SADB_X_EALG_AESCBC          12
#define SADB_X_EALG_AESCTR          13
#define SADB_EALG_MAX               253 /* last EALG */
/* private allocations should use 249-255 (RFC2407) */
#define SADB_X_EALG_SERPENTCBC      252 /* draft-ietf-ipsec-ciph-aes-cbc-00 */
#define SADB_X_EALG_TWOFISHCBC      253 /* draft-ietf-ipsec-ciph-aes-cbc-00 */

/* Compression algorithms */
#define SADB_X_CALG_NONE            0
#define SADB_X_CALG_OUI             1
#define SADB_X_CALG_DEFLATE         2
#define SADB_X_CALG_LZS             3
#define SADB_X_CALG_LZJH            4
#define SADB_X_CALG_MAX             4

/* Extension Header values */
#define SADB_EXT_RESERVED           0
#define SADB_EXT_SA                 1
#define SADB_EXT_LIFETIME_CURRENT   2
#define SADB_EXT_LIFETIME_HARD      3
#define SADB_EXT_LIFETIME_SOFT      4
#define SADB_EXT_ADDRESS_SRC        5
#define SADB_EXT_ADDRESS_DST        6
#define SADB_EXT_ADDRESS_PROXY      7
#define SADB_EXT_KEY_AUTH           8
#define SADB_EXT_KEY_ENCRYPT        9
#define SADB_EXT_IDENTITY_SRC       10
#define SADB_EXT_IDENTITY_DST       11
#define SADB_EXT_SENSITIVITY        12
#define SADB_EXT_PROPOSAL           13
#define SADB_EXT_SUPPORTED_AUTH     14
#define SADB_EXT_SUPPORTED_ENCRYPT  15
#define SADB_EXT_SPIRANGE           16
#define SADB_X_EXT_KMPRIVATE        17
#define SADB_X_EXT_POLICY           18
#define SADB_X_EXT_SA2              19
/* The next four entries are for setting up NAT Traversal */
#define SADB_X_EXT_NAT_T_TYPE       20
#define SADB_X_EXT_NAT_T_SPORT      21
#define SADB_X_EXT_NAT_T_DPORT      22
#define SADB_X_EXT_NAT_T_OA         23
#define SADB_X_EXT_SEC_CTX          24
#define SADB_EXT_MAX                24

/* Identity Extension values */
#define SADB_IDENTTYPE_RESERVED   0
#define SADB_IDENTTYPE_PREFIX     1
#define SADB_IDENTTYPE_FQDN       2
#define SADB_IDENTTYPE_USERFQDN   3
#define SADB_IDENTTYPE_MAX        3

#define IPSEC_PORT_ANY      0
#define IPSEC_ULPROTO_ANY   255
#define IPSEC_PROTO_ANY     255
#define IPSEC_DIR_ANY       0

enum
{
    IPSEC_POLICY_DISCARD    = 0,
    IPSEC_POLICY_NONE       = 1,
    IPSEC_POLICY_IPSEC      = 2,
    IPSEC_POLICY_ENTRUST    = 3,
    IPSEC_POLICY_BYPASS     = 4
};

MOC_EXTERN MSTATUS pfkey_buildBase(ubyte4 seqNo, ubyte4 pid, ubyte proto, ubyte msgType, ubyte errNo, ubyte2 msgLen, struct sadb_msg *pBase);
MOC_EXTERN MSTATUS pfkey_buildAssocExtension(ubyte4 dwSpi,
                                         ubyte authAlgo, ubyte encrAlgo, ubyte aeadTag,
                                         struct sadb_sa *pSa, ubyte state, ubyte flag);
MOC_EXTERN MSTATUS pfkey_parseAddressExtension(struct sadb_address *pExt, MOC_IP_ADDRESS_S *pAddr, ubyte *pProto, ubyte2 *pPort);
MOC_EXTERN MSTATUS pfkey_buildAddressExtension(ubyte2 extType, MOC_IP_ADDRESS addr, struct sadb_address *pAddr);
MOC_EXTERN MSTATUS pfkey_buildKeyExtension(struct sadb_key *pKey, ubyte2 extType, ubyte *keyData, ubyte2 keyDataLen);

#endif /*  __PFKEY_COMMON_HEADER__ */
