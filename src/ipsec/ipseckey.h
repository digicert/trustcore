/**
 * @file  ipseckey.h
 * @brief NanoSec IPsec SADB management API.
 *
 * @details    This file contains NanoSec IPsec Security Association Database (SADB)
 *             management function declarations.
 * @since      1.41
 * @version    5.3 and later
 *
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

#ifndef __IPSECKEY_HEADER__
#define __IPSECKEY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#include "../common/hash_table.h"
#include "../common/hash_value.h"
#endif

/*------------------------------------------------------------------*/

#define IPSEC_SA_FLAG_INUSE         0x00000001
#define IPSEC_SA_FLAG_DELETED       0x00000002
#define IPSEC_SA_FLAG_INBOUND       0x00000004
#define IPSEC_SA_FLAG_INITIATOR     0x00000008
#define IPSEC_SA_FLAG_MATURE        0x00000010

/* used in "ipseckey.h" only */
#define IPSEC_SA_FLAG_MIRRORED      0x00000100
#define IPSEC_SA_FLAG_IP6           0x00000200
#define IPSEC_SA_FLAG_IKE2          0x00000400
#define IPSEC_SA_FLAG_PFS           0x00000800

/* internal use only */
#define IPSEC_SA_FLAG_NAT_PEER      0x00100000
#define IPSEC_SA_FLAG_CONNECT2      0x00200000
#define IPSEC_SA_FLAG_HEXKEY        0x00400000 /* for IPSEC_keyAddEx() */
#define IPSEC_SA_FLAG_ASCIIKEY      0x00800000 /* for IPSEC_keyAdd() */
#define IPSEC_SA_FLAG_GDOI          0x01000000
#define IPSEC_SA_FLAG_ESN           0x02000000
#define IPSEC_SA_FLAG_RESERVED      0x80000000

#define MOC_MAX_FQDN_LEN 20

#ifndef MAX_IP_IN_FQDN
#define MAX_IP_IN_FQDN 32
#endif
/* See "ipsec_defs.h" for constants */

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#define FQDN_NAME_MAPPING_INIT_HASH_VALUE (0xe0f2418e)

#define GEN_FQDNNAME_MAPPING_HASH_VALUE(_fqdnName, fqdnLen, _hv) \
    HASH_VALUE_hashGen(_fqdnName, fqdnLen, \
                       FQDN_NAME_MAPPING_INIT_HASH_VALUE, &(_hv));

typedef struct fqdnNameMappingConfig {
    ubyte fqdnName[MOC_MAX_FQDN_LEN]; /* store fqdn here*/
    ubyte4 fqdnUniqueKey;
} fqdnNameMappingConfig;
#endif

#ifdef __ENABLE_RB_SADB__
typedef struct outboundMappingConfig {
    ubyte fqdnName[MOC_MAX_FQDN_LEN]; /* store fqdn here*/
    MOC_IP_ADDRESS_S destIp;
    MOC_IP_ADDRESS_S destIpEnd;
    ubyte4          timenow;    /* current time to check the expiry value*/
} outboundMappingConfig;
#endif


/*------------------------------------------------------------------*/

/**
@brief      Configuration settings for IPsec manual keys.

@details    This structure is used for IPsec manual key configuration (see
            IPSEC_keyAdd()). This data structure is also used as a parameter for
            other IPsec SADB functions, such as IPSEC_keyDelete().

@ifnot __INCLUDE_DOXYGEN_FOR_NanoMCP__
@sa     For information about policies and rules, see the "Security Policies"
section of @ref ipsec_provisioning.
@sa     See ipsec_defs.h for constants or macros used in the member fields.
@endif

@since 1.41
@version 5.3 and later
*/
typedef struct ipsecKey
{
    /**
     @brief      Transport layer security protocol.
     @details    Transport layer security protocol; e.g. IPPROTO_ESP,
                 IPPROTO_AH, or 0 (any).
     */
    ubyte   oProtocol;          /* transport layer protocol e.g. IPPROTO_AH, IPPROTO_ESP, or 0 (any) */

    /**
     @brief      SPI value.
     @details    SPI value (in host byte order).
     */
    ubyte4  dwSpi;              /* SPI to use */

#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
    /**
     @brief      Destination IP address.
     @details    Destination IP address.
     */
    ubyte4  dwDestAddr;         /* destination IP address (in host byte order) */

    /**
     @brief      Source IP address.
     @details    Source IP address.
     */
    ubyte4  dwSrcAddr;          /* source IP address (in host byte order); 0=unspecified */
#else
    /** @private @internal */
    ubyte8 dwDestAddr;
    /** @private @internal */
    ubyte8 dwSrcAddr;
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    /**
     @brief      UDP-encapsulation port.
     @details    UDP-encapsulation port.
     @note       This field is defined only if the
                 \c \__ENABLE_IPSEC_NAT_T__ flag is defined in moptions.h.
     */
    ubyte2  wUdpEncPort;
#else
    /** @private @internal */
    ubyte2  wReserved;
#endif
    /**
     @brief      Security mode.
     @details    Security mode; e.g. IPSEC_MODE_TRANSPORT or IPSEC_MODE_TUNNEL.
     */
    ubyte   oMode;              /* IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0 (don't care) */

    /* For IPSEC_keyAdd and PF_KEY, etc.*/
    /**
     @brief      Athentication algorithm.
     @details    Athentication algorithm; 0=none or N/A.
     */
    ubyte   oAuthAlgo;          /* authentication algorithm ID; 0=none or N/A */
    /**
     @brief      Athentication key string.
     @details    Athentication key; denoted by a hexadecimal character string.
     */
    sbyte*  pAuthKey;           /* authentication key; denoted by a hexadecimal character string */
    /**
     @brief      Athentication key string length.
     @details    Athentication key string length (in bytes).
     */
    ubyte2  wAuthKeyLen;        /* authentication key string length */

    /**
     @brief      Encryption algorithm.
     @details    Encryption algorithm; 0=none or N/A.
     */
    ubyte   oEncrAlgo;          /* encryption algorithm ID; 0=none or N/A */
    /**
     @brief      Encryption key string.
     @details    Encryption key; denoted by a hexadecimal character string.
     */
    sbyte*  pEncrKey;           /* encryption key; denoted by a hexadecimal character string */
    /**
     @brief      Encryption key string length.
     @details    Encryption key string length (in bytes).
     */
    ubyte2  wEncrKeyLen;        /* encryption key string length */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    /** @private @internal */
    ubyte   oNonceLen;          /* salt size (in bytes), e.g. 4; included in 'wEncrKeyLen'!!! */

    /** @private @internal */
    ubyte   oAeadIcvLen;        /* tag size (in bytes) for ESP Aead algo; e.g. 16, 12, 8, or 0=N/A */

    /** @private @internal */
    ubyte4  dwExpSecs;          /* expire after so many seconds elasped */

    /** @private @internal */
    ubyte4  dwExpKBytes;        /* expire after so many kbytes passed */
#endif
    /**
     @brief      Destination port.
     @details    Transport layer destination port number.
     */
    ubyte2  wDestPort;          /* destination port number; 0=any or N/A */

    /**
     @brief      Source port.
     @details    Transport layer source port number.
     */
    ubyte2  wSrcPort;           /* source port number; 0=any or N/A */

    /**
     @brief      Upper transport layer protocol.
     @details    Upper transport layer protocol; e.g. IPPROTO_TCP, 0=any.
     */
    ubyte   oUlp;               /* upper layer protocol; 0=any o/w, see "ipsec_protos.h" */

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    /** @private @internal */
    ubyte4  cookie;             /* developer customizable cookie (e.g. VLan id) or PF_KEY reqid */
#endif
    /** @private @internal */
    ubyte4  dwSeqNo;            /* e.g. PF_KEY sadb_msg_seq */

    /**
     @brief      Specify auxiliary flags.
     @details    Specifies auxiliary flags; e.g. when the
                 \c \__ENABLE_DIGICERT_IPV6__ flag is defined, set the
                 value by OR-ing the following flag (defined in ipseckey.h) as
                 desired:
                 + \c IPSEC_SA_FLAG_IP6 (indicates that fields \c dwDestAddr and
                   \c dwSrcAddr are cast from IPv6 address types)
     */
    ubyte4  flags;              /* Note: Set IPSEC_SA_FLAG_IP6 if 'dwDestAddr'
                                   and 'dwSrcAddr' are cast from pointers to
                                   IPv6 addresses. */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /**
     @brief      IKE_SA ID.
     @details    IKE_SA ID; 0=N/A.
     @note       This field is defined only if the
                 \c \__ENABLE_DIGICERT_IKE_SERVER__ flag is defined in moptions.h.
     */
    ubyte4  dwIkeSaId;          /* IPSEC_keyDelete, IPSEC_keyUpdate */

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    /**
     @brief      Interface ID; 0=any.
     @details    Interface ID; 0=any.
     @note       This field is defined only if the
                 \c \__ENABLE_IPSEC_INTERFACE_ID__ flag is defined in moptions.h.
     */
    sbyte4  ifid;               /* IPSEC_keyInitiate */
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
    /* PF_KEY async callback, e.g. IPSEC_keySpi() */
    /** @private @internal */
    sbyte4 (*funcPtrPfkeyCb)(sbyte4 status, void *cbData);
#endif
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

    /** @private @internal */
    sbyte4  status;             /* [internal] return status for kernel call */

} *IPSECKEY;


/*------------------------------------------------------------------*/
/* internal use only */

/**
 * @private
 * @internal
 */
typedef struct ipsecKeyEx
{
    ubyte4  flags;              /* direction, initiator, replay, etc. */

    ubyte   oProtocol;          /* IPPROTO_AH or IPPROTO_ESP */
    ubyte4  dwSpi;              /* SPI to use */

    MOC_IP_ADDRESS dwDestAddr;  /* destination IP address */
    MOC_IP_ADDRESS dwSrcAddr;   /* source IP address */

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4  cookie;             /* developer customizable cookie (e.g. VLan id) or PF_KEY reqid */
#endif
#if 1 /* defined(__ENABLE_IPSEC_NAT_T__) */
    ubyte2  wUdpEncPort;        /* peer's UDP-encapsulation port number; 0=no UDP-encap. */
#endif
    ubyte2  wDestPort;          /* destination port number; 0=any or N/A */
    ubyte2  wSrcPort;           /* source port number; 0=any or N/A */
    ubyte   oUlp;               /* upper layer protocol; 0=any o/w, see "ipsec_protos.h" */

#if 1 /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) */
    ubyte   oMode;              /* IPSEC_MODE_TRANSPORT or IPSEC_MODE_TUNNEL */
    MOC_IP_ADDRESS dwDestIP, dwDestIPEnd;  /* private destination IP range; tunnel mode only */
    MOC_IP_ADDRESS dwSrcIP, dwSrcIPEnd;    /* private source IP range; tunnel mode only */
#endif
    ubyte   oAuthAlgo;          /* authentication algorithm ID; 0=none or N/A, see "ipsec_defs.h" */
    ubyte*  poAuthKey;          /* authentication key */
    ubyte2  wAuthKeyLen;        /* authentication key length (in bytes) */

    ubyte   oEncrAlgo;          /* encryption algorithm ID; 0=none or N/A, see "ipsec_defs.h" */
    ubyte*  poEncrKey;          /* encryption key */
    ubyte2  wEncrKeyLen;        /* encryption key length (in bytes) */
    /** @private @internal */
    ubyte   oNonceLen;          /* salt size (in bytes), e.g. 4; included in 'wEncrKeyLen'!!! */

    ubyte   oAeadIcvLen;        /* tag size (in bytes) for ESP Aead algo; e.g. 16, 12, 8, or 0=N/A */

    ubyte4  dwExpSecs;          /* expire after so many seconds elasped */
    ubyte4  dwExpKBytes;        /* expire after so many kbytes passed */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4  dwSpiM;             /* mirrored SPI */

    sbyte4  spdIndex;           /* index to trigger SP */
    ubyte4  dwSpdId;            /* ID of trigger SP */
    sbyte4  iNest;              /* SA bundle index in the SP */

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    sbyte4  ifid;               /* IPSEC_keyReady */
#endif
    ubyte4  dwIkeSaId;          /* parent IKE_SA's internal ID */
    sbyte4  ikeSaLoc;           /* parent IKE_SA's locator */

    ubyte4  dwTimeStart;        /* time elapsed (in ms) since quick mode start */

#ifdef __ENABLE_DIGICERT_PFKEY__
    ubyte4  sadb_msg_seq;
    ubyte   sadb_sa_replay;
#endif
#ifdef __ENABLE_DIGICERT_IPCOMP__
    ubyte   oCompAlgo;          /* IPComp algorithm ID; 0=none, see "ike_defs.h" */
    ubyte2  wCpi, wCpiM;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    /** @private @internal */

    MOC_IP_ADDRESS dwDestAddrList[MAX_IP_IN_FQDN];
    ubyte4  dwDestAddrCount;

    /** @private @internal */
    MOC_IP_ADDRESS dwSrcAddrList[MAX_IP_IN_FQDN];
    ubyte4  dwSrcAddrCount;

    ubyte fqdn[MOC_MAX_FQDN_LEN]; /* store fqdn here*/
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    ubyte4 fqdnUniqueKey;
#endif
#endif
    intBoolean  inbound;
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

} *IPSECKEY_EX;


/*------------------------------------------------------------------*/

/**
@brief      Add IPsec manual keys to the SADB.

@details    This function adds IPsec manual keys to the SADB (security
            association database). If there are any errors while adding a key,
            this function exits and returns the number of keys that were
            successfully added before the error.

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@param axKey    Pointer to an array of SA structures, i.e. struct ipsecKey.
@param num      Number of SAs in the SA array (that is, the number of elements
                in \p axKey).

@inc_file ipseckey.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
extern sbyte4 IPSEC_EXAMPLE_addKeys(void)
{
    return IPSEC_keyAdd(g_ipsecKeyData, sizeof(g_ipsecKeyData) / sizeof(struct ipsecKey));
}
@endcode

@funcdoc    ipseckey.h
*/
MOC_EXTERN sbyte4 IPSEC_keyAdd(IPSECKEY axKey, sbyte4 num);  /* manual keying */

/**
@brief      Delete an IPsec SA.

@details    This function deletes the IPsec SA specified by the given selectors.

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@param pxKey    Selectors are \c struct ipsecKey fields \c oProtocol, \c dwSpi,
                \c dwDestAddr, and \c dwSrcAddr. All remaining fields are
                ignored and should be set to 0.

@inc_file ipseckey.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
struct ipsecKey key;
key.oProtocol = IPPROTO_ESP;
key.dwSpi = 0;
key.dwDestAddr = 0xc8c8c8f0;    // in host byte order
key.dwSrcAddr = 0;
status = IPSEC_keyDelete(&key);  // del. all SAs of type ESP for dest. 0xc8c8c8f0
@endcode

@funcdoc    ipseckey.h
*/
MOC_EXTERN sbyte4 IPSEC_keyDelete(IPSECKEY pxKey);

/**
@brief      Flush (remove) every IPsec SA from the SADB.

@details    This function flushes (removes) every IPsec SA from the SADB.

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipseckey.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ipseckey.h
*/
MOC_EXTERN sbyte4 IPSEC_keyFlush(void);


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_SERVER__

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Initiate IKE negotiation of an IPsec SA.

@details    Given traffic selectors, this function consults local (IPsec)
            policies and acquires IPsec SAs by triggering IKE initiation of
            negotiation with a peer.

@ingroup    ipsec_functions

@since 4.0
@version 4.0 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@param pxKey    IPsec key descriptor. Specify the traffic selectors in the
                following \c struct ipsecKey fields: \c oUlp, \c dwDestAddr,
                \c dwSrcAddr, \c wDestPort, and \c wSrcPort. All remaining
                fields are ignored and should be set to zero (0).

@inc_file ipseckey.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
struct ipsecKey key = { 0 };
key.oUlp  = IPPROTO_ICMP;
key.dwDestAddr = 0xc8c8c8f0;    // in host byte order
key.dwSrcAddr  = 0xc8c8c801;    // in host byte order
status = IPSEC_keyInitiate(&key);
@endcode

@funcdoc    ipseckey.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IPSEC_keyInitiate(IPSECKEY pxKey);

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_keyUpdate(IPSECKEY pxKey);


/*------------------------------------------------------------------*/
/* internal use only */

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_keyAddEx(IPSECKEY_EX pxKey);    /* automatic keying - IKE */

#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
MOC_EXTERN sbyte4 IPSEC_groupKeyAdd(IPSECKEY_EX pxKey);    /* automatic keying - IKE */
#endif

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
MOC_EXTERN sbyte4 IPSEC_sendIfmapInfo(void *ifmap_arr);
#endif

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_keyReady(IPSECKEY_EX pxKey);

#if 1 //def __ENABLE_DIGICERT_GDOI_SERVER__
/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_keyGet(IPSECKEY pxKey); /* manual key only */

MOC_EXTERN sbyte4 IPSEC_keyGetEx(IPSECKEY_EX pxKey); /* manual key only */
#endif

#ifdef __ENABLE_DIGICERT_PFKEY__
/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_keySpi(IPSECKEY pxKey);
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */


#ifdef __cplusplus
}
#endif

#endif /* __IPSECKEY_HEADER__ */

