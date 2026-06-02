/**
 * @file  ipsecconf.h
 * @brief NanoSec IPsec SPD table configuration API.
 *
 * @details    This header file contains structures and function declarations
 *             used for NanoSec SPD table configuration.
 * @since      1.41
 * @version    5.3 and later
 *
 * @flags      Whether the following flags are defined determines which structure fields are defined:
 *     + \c \__DISABLE_IPSEC_TUNNEL_MODE__
 *     + \c \__ENABLE_IPSEC_COOKIE__
 *     + \c \__ENABLE_IPSEC_PORT_RANGE__
 *
 *             Whether the following flags are defined determines which functions are enabled:
 *     + \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
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

#ifndef __IPSECCONF_HEADER__
#define __IPSECCONF_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#ifndef MAX_IP_IN_FQDN
#define MAX_IP_IN_FQDN 32
#endif

#ifndef MOC_MAX_FQDN_LEN
#define MOC_MAX_FQDN_LEN 20
#endif

/* Maximum number of entries in address_translation.conf */
#ifndef MAX_PORTS_PER_POLICY
#define MAX_PORTS_PER_POLICY 32
#endif

/* See "ipsec_defs.h" for constants */


/*------------------------------------------------------------------*/

/**
@brief      SA cryptographic attributes for IPsec policies.

@details    This structure specifies the cryptographic attributes of an SA
            (security assocaition). It is usually used as part of IPsec policy
            configuration (see IPSEC_confAdd() and struct ipsecConf).

@ifnot __INCLUDE_DOXYGEN_FOR_NanoMCP__
@sa     For information about policies and rules, see the "Security Policies"
section of @ref ipsec_provisioning.
@sa     See ipsec_defs.h for constants or macros used in the member fields.
@endif

@since 1.41
@version 5.3 and later
*/
struct sainfo
{
    /**
     @brief      Security protocol.
     @details    Security protocol.
     */
    ubyte   oSecuProto;     /* IPSEC_PROTO_{AH | ESP | ESP_AUTH | ESP_NULL} */
    /**
     @brief      Authentication algorithm.
     @details    Authentication algorithm; 0=any or N/A.
     */
    ubyte   oAuthAlgo;      /* hash algorithm ID; 0=any or N/A */
    /**
     @brief      Encryption algorithm.
     @details    Encryption algorithm; 0=any or N/A.
     */
    ubyte   oEncrAlgo;      /* encryption algorithm ID; 0=any or N/A */
    /**
     @brief      Encryption key length (in bytes).
     @details    Encryption key length (in bytes); 0=N/A or any applicable
                 legnth (for variable key-length encryption algorithm, e.g. AES).
     */
    ubyte   oEncrKeyLen;    /* encryption key length (in bytes); 0=N/A or any
                               for variable key-length encr. algo. */
    /**
     @brief      Tag size (in bytes).
     @details    Tag size (in bytes); 0=N/A or unspecified for ESP-AEAD algorithm.
     */
    ubyte   aeadTag;        /* tag size (in bytes); 0=N/A or unspecified
                               for ESP-AEAD algo */
};

typedef enum MCP_PORT_CONFIG_TYPE
{
    MCP_NO_PORT,
    MCP_SINGLE_PORT,
    MCP_PORT_RANGE,
    MCP_PORT_LIST
} MCP_PORT_CONFIG_TYPE;

/*------------------------------------------------------------------*/

/**
@brief      Configuration settings for IPsec policies.

@details    This structure is used for IPsec policy configuration (see
            IPSEC_confAdd()). This data structure is
            also used as a parameter for the IPsec policy removal function,
            IPSEC_confDelete().

@ifnot __INCLUDE_DOXYGEN_FOR_NanoMCP__
@sa     For information about policies and rules, see the "Security Policies"
        section of @ref ipsec_provisioning.
@endif


@since 1.41
@version 5.3 and later
*/
typedef struct ipsecConf
{
#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
    /**
    @brief      Source IP address (in host byte order); 0=any.
    @details    Source IP address (in host byte order); 0=any.
    @note       This field is a \c ubyte8 for 64-bit IPv6 implementations;
                  otherwise it's a \c ubyte4.
    */
    ubyte4  dwSrcIP;
    /**
    @brief      (Optional) source IP range upper limit; 0=unused.
    @details    (Optional) source IP range upper limit; 0=unused.
    @note       This field is a \c ubyte8 for 64-bit IPv6 implementations;
                  otherwise it's a \c ubyte4.
    */
    ubyte4  dwSrcIPEnd;
#else
    /**
     * @private
     * @internal
     */
    ubyte8  dwSrcIP, /** @private @internal */ dwSrcIPEnd;
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
    /**
     @brief      Destination IP address.
     @details    Destination IP address.
     */
    ubyte4  dwDestIPList[MAX_IP_IN_FQDN - 1];         /* destination IP address (in host byte order) */
    ubyte4  dwDestIPCount;
    /**
     @brief      Source IP address.
     @details    Source IP address.
     */
    ubyte4  dwSrcIPList[MAX_IP_IN_FQDN - 1];          /* source IP address (in host byte order); 0=unspecified */
    ubyte4  dwSrcIPCount;
#else
    /** @private @internal */
    ubyte8  dwDestIPList[MAX_IP_IN_FQDN - 1];
    ubyte4  dwDestIPCount;

    /** @private @internal */
    ubyte8  dwSrcIPList[MAX_IP_IN_FQDN - 1];
    ubyte4  dwSrcIPCount;
#endif
#endif

    /**
    @brief       port number; 0=any or N/A.
    @details     port number; 0=any or N/A.
    */
    ubyte2  wPortList[MAX_PORTS_PER_POLICY];  /* it will override the src and destination port settings*/
    ubyte2  wPortCount;  /* represent the numbers of ports present in the port list 0 represent not configured*/


    /**
    @brief      Source port number; 0=any or N/A.
    @details    Source port number; 0=any or N/A.
    */
    ubyte2  wSrcPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    /**
    @brief      (Optional) Source port range upper limit; 0=unused.
    @details    (Optional) Source port range upper limit; 0=unused.

    @note       This field is defined only if the
                \c \__ENABLE_IPSEC_PORT_RANGE__ flag is defined in moptions.h.
    */
    ubyte2  wSrcPortEnd;
#endif
    MCP_PORT_CONFIG_TYPE srcPortType;

#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
    /**
    @brief      Destination IP address (in host byte order); 0=any.
    @details    Destination IP address (in host byte order); 0=any.
    @note       This field is a \c ubyte8 for 64-bit IPv6 implementations;
                  otherwise it's a \c ubyte4.
    */
    ubyte4  dwDestIP;
    /**
    @brief      (Optional) Destination IP range upper limit; 0=unused.
    @details    (Optional) Destination IP range upper limit; 0=unused.
    @note       This field is a \c ubyte8 for 64-bit IPv6 implementations;
                  otherwise it's a \c ubyte4.
    */
    ubyte4  dwDestIPEnd;
#else
    /**
     * @private
     * @internal
     */
    ubyte8  dwDestIP, /** @private @internal */ dwDestIPEnd;
#endif

    /**
    @brief      Destination port number; 0=any or N/A.
    @details    Destination port number; 0=any or N/A.
    */
    ubyte2  wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    /**
    @brief      (Optional) Destination port range upper limit; 0=unused.
    @details    (Optional) Destination port range upper limit; 0=unused.
    @note       This field is defined only if the
                \c \__ENABLE_IPSEC_PORT_RANGE__ flag is defined in moptions.h.
    */
    ubyte2  wDestPortEnd;
#endif
    /**
    @brief      Destination port number list for dual-mode; 0=any or N/A.
    @details    Destination port number list for dual-mode; 0=any or N/A.
    */
    ubyte2  wDestPortCount;
    ubyte2  wDestPortList[MAX_PORTS_PER_POLICY];
    MCP_PORT_CONFIG_TYPE destPortType;

    /**
    @brief      Upper layer protocol; 0=any, otherwise see ipsec_protos.h.
    @details    Upper layer protocol; 0=any, otherwise see ipsec_protos.h.
    */
    ubyte   oProto;

    /**
    @brief      IPSEC_ACTION_{APPLY | PERMIT | DROP | BYPASS}.
    @details    IPSEC_ACTION_{APPLY | PERMIT | DROP | BYPASS}.
    */
    ubyte   oAction;

    /**
    @brief      IPSEC_DIR_INBOUND, IPSEC_DIR_OUTBOUND, or 0 (N/A) [ |
                  IPSEC_DIR_MIRRORED ] for mirrored policies.
    @details    IPSEC_DIR_INBOUND, IPSEC_DIR_OUTBOUND, or 0 (N/A) [ |
                  IPSEC_DIR_MIRRORED ] for mirrored policies.
    */
    ubyte   oDir;
    /**
    @brief      SA bundle size.
    @details    SA bundle size.
    */
    ubyte   oSaLen;
    /**
    @brief      SA bundle; innermost first.
    @details    SA bundle; innermost first.
    */
    struct sainfo *pxSa;

#if 1 /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) */
    /**
    @brief      IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0 (don't care).
    @details    IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0 (don't care).
    */
    ubyte   oMode;

#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
    /**
    @brief      Tunnel destination IP address (in host byte order).
    @details    Tunnel destination IP address (in host byte order).
    @note       This field is a \c ubyte8 for 64-bit IPv6 implementations;
                  otherwise it's a \c ubyte4.
    */
    ubyte4  dwTunlDestIP;
    /**
    @brief      Tunnel source IP address (in host byte order).
    @details    Tunnel source IP address (in host byte order).
    @note       This field is a \c ubyte8 for 64-bit IPv6 implementations;
                  otherwise it's a \c ubyte4.
    */
    ubyte4  dwTunlSrcIP;
#else
    /**
     * @private
     * @internal
     */
    ubyte8  dwTunlDestIP, /** @private @internal */ dwTunlSrcIP;
#endif
#endif

    /**
    @brief      SPD %index; valid if > 0.
    @details    SPD %index; valid if > 0.
    */
    sbyte4  index;

#if 1 /* defined(__ENABLE_IPSEC_INTERFACE_ID__) */
    /**
    @brief      Interface ID; 0=any.
    @details    Interface ID; 0=any.
    @note       This field is defined only if the
                  \c \__ENABLE_IPSEC_INTERFACE_ID__ flag is defined in
                  moptions.h.
    @note       This field is used to match the ID of the interface (physical
                  or virtual) from which a packet arrives, if applicable.
    */
    sbyte4  ifid;
#endif

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    /**
    @brief      Developer customizable %cookie; for example, VLan id.
    @details    Developer customizable %cookie; for example, VLan id.
    @note       This field is defined only if either the
                  \c \__ENABLE_IPSEC_COOKIE__ flag or the
                  \c \__ENABLE_DIGICERT_PFKEY__ flag is defined in moptions.h.
    */
    ubyte4  cookie;
#endif

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /**
    @brief      Child SA lifetime in seconds; 0=unspecified.
    @details    Child SA lifetime in seconds; 0=unspecified.
    @note       This field is defined only if the
                  \c \__ENABLE_DIGICERT_IKE_SERVER__ flag is defined in moptions.h.
    */
    ubyte4  dwSaSecs;

    /**
    @brief      Child SA lifetime in bytes; 0=unspecified.
    @details    Child SA lifetime in bytes; 0=unspecified.
    @note       This field is defined only if the
                  \c \__ENABLE_DIGICERT_IKE_SERVER__ flag is defined in moptions.h.
    */
    ubyte4  dwSaBytes;

    /**
     * @private
     * @internal
     */
    ubyte4  dwIkeSaId;
#endif

    /**
    @brief      Specify backward compatibility of IPv6 policies to IPv4.
    @details    Specifies backward compatibility of IPv6 policies to IPv4 when
                  the \c \__ENABLE_DIGICERT_IPV6__ flag is defined. Set the
                  value by OR-ing the following flags (defined in spd.h) as
                  desired:
                  + \c IPSEC_SP_FLAG_IP6 (indicates that fields \c dwSrcIP,
                    \c dwSrcIPEnd, \c dwDestIP, and \c dwDestIPEnd are cast
                    from IPv6 address types)
                  + \c IPSEC_SP_FLAG_IP6_TUNNEL (indicates that fields
                    \c dwTunlSrcIP and \c dwTunlDestIP are cast from IPv6
                    address types).
    */
    ubyte4  flags;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    ubyte isGdoi; /* whether or not gdoi is enabled*/
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    sbyte fqdn[MOC_MAX_FQDN_LEN];
    ubyte isUnicastGDOI; /* whether or not gdoi is enabled*/
    MOC_IP_ADDRESS_S fqdnUniqueKey;
#endif

} *IPSECCONF;


#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
/**
*/
typedef struct fqdnMappingConfig {

    MOC_IP_ADDRESS_S fqdnIp;
    MOC_IP_ADDRESS_S fqdnUniqueKey;
} fqdnMappingConfig;
#endif

/*------------------------------------------------------------------*/

/**
@brief      Configure NanoSec IPsec policies to apply to IP packets.

@details    This function configures NanoSec IPsec policies to apply to
            IP packets.

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipsecconf.h

@return     Value >= 0 is the number of policy structures successfully added;
            otherwise a negative number error code definition from merrors.h. To
            retrieve a string containing an English text error identifier
            corresponding to the function's returned error status, use the
            \c DISPLAY_ERROR macro.

@param axConf   Pointer to an array of policy structures, i.e. struct ipsecConf.
@param num      Number of policies in the policy array (that is, the number of
                elements in \p auxConf).

@note       It's generally easier to use a policy script than to build the
            policy structures and call IPSEC_confAdd() from your application
            code.

@sa         ipsec_policy_scripts.

@code
extern sbyte4 IPSEC_EXAMPLE_addPolicies(void)
{
    return  IPSEC_confAdd(g_ipsecInitConf, sizeof(g_ipsecInitConf) / sizeof(struct ipsecConf));
}
@endcode

@funcdoc    ipsecconf.h
*/
MOC_EXTERN sbyte4 IPSEC_confAdd(IPSECCONF axConf, sbyte4 num);

/**
@brief      Delete the specified IPsec policy.

@details    This function deletes the IPsec policy specified by the selectors,
            resulting in the removal of the policy's associated IPsec
            automatically-keyed SAs.

@ingroup    ipsec_functions

@since 1.41
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipsecconf.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@param pxConf   Selectors are \c struct ipsecConf fields \c index, \c oAction, and
                \c oDir:
                + \c index must be > 0, and is obtained by listing policies
                  (in or out separately) ordered by creation time (unless the
                  policy is created with a given index).
                + \c oAction and \c oDir should be set to 0 if not used.
                + All other selectors are ignored.

@funcdoc    ipsecconf.h
*/
MOC_EXTERN sbyte4 IPSEC_confDelete(IPSECCONF pxConf);

/**
@brief      Flush (remove) every IPsec policy from the system.

@details    This function flushes (removes) every IPsec policy from the system.

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipsecconf.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ipsecconf.h
*/
MOC_EXTERN sbyte4 IPSEC_confFlush(void);

/**
@brief      Configure the GDOI here even for unicast ip adddress if GDOI client is enabled then this flag will mean sdriver will initiate the GDOI session even for unicast ip  address.

@details    This functionsets the GDOi seeion enable to true

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
__ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__

@inc_file ipsecconf.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ipsecconf.h
*/
/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_confAdd1(IPSECCONF pxConf); /* internal use only */

#ifdef __ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__
#define MOC_MCP_UNICAST_LIST   1
#define MOC_MCP_UNICAST_RANGE  2
#define MOC_MCP_UNICAST_SUBNET 3
#endif

/* Maximum number of multicast group */
#ifndef MAX_MULTICAST_GROUP
#define MAX_MULTICAST_GROUP 128
#endif
#ifndef MAX_UNICAST_GROUP
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
#define MAX_UNICAST_GROUP 251*250/2     /* 31375 groups, 1 PKDC, 1 SKDC , broadcast , .0 and .1 left out*/
#else
#define MAX_UNICAST_GROUP 384
#endif
#endif
#ifndef MAX_GROUP_NEGOTIATION
#define MAX_GROUP_NEGOTIATION (MAX_MULTICAST_GROUP + MAX_UNICAST_GROUP)
#endif
#ifndef MAX_SKDC_KEY_NEGOTIATION
#define MAX_SKDC_KEY_NEGOTIATION 256        /* max number of keys that can be exchanged between PKDC and SKDC*/
#endif

#ifndef MAX_UNICAST_RANGE
#define MAX_UNICAST_RANGE 4
#endif
#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
#define FQDN_MAPPING_INIT_HASH_VALUE (0xc0f2418e)
#ifdef __ENABLE_DIGICERT_IPV6__
#define GEN_FQDNMAPPING_HASH_VALUE(_baseAddr, _hv) \
    if (AF_INET6 == (_baseAddr).family) \
        HASH_VALUE_hashGen((const void *)RET_MOC_IPADDR6(_baseAddr), 16, \
                           FQDN_MAPPING_INIT_HASH_VALUE, &(_hv)); \
    else \
        HASH_VALUE_hashGen((const void *)&(RET_MOC_IPADDR4(_baseAddr)), 4, \
                            FQDN_MAPPING_INIT_HASH_VALUE, &(_hv));

#else
#define GEN_FQDNMAPPING_HASH_VALUE(_baseAddr, _hv) \
    HASH_VALUE_hashGen(&(_baseAddr), sizeof(_baseAddr), \
                       FQDN_MAPPING_INIT_HASH_VALUE, &(_hv));
#endif

/* extern RTOS_MUTEX m_mtxFqdnMapping; */
#endif

#ifdef __cplusplus
}
#endif

#endif /* __IPSECCONF_HEADER__ */

