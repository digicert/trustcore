/**
 * @file  ipsec.h
 * @brief NanoSec IPsec developer API.
 *
 * @details    This file contains NanoSec IPsec developer API function declarations.
 * @since      1.41
 * @version    5.3 and later
 *
 * @flags      Whether the following flags are defined determines which functions are enabled:
 *     + \c \__ENABLE_DIGICERT_IKE_SERVER__
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

#ifndef __IPSEC_HEADER__
#define __IPSEC_HEADER__

/* To enable IPsec, #define __ENABLE_DIGICERT_IPSEC_SERVICE__ in "moptions.h". */

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/* To customize, #define the following symbols in "moptions.h".     */

/* internal sizes */
#ifndef IPSEC_SADB_MAX
#if defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
#if defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#define IPSEC_SADB_MAX          (64000)   /* maximum # of IPsec SA's */
#else
#define IPSEC_SADB_MAX          (2048)   /* maximum # of IPsec SA's */
#endif
#else
#define IPSEC_SADB_MAX          (128)   /* maximum # of IPsec SA's */
#endif
#endif
#ifndef IPSEC_SPD_MAX
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__) || defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
#define IPSEC_SPD_MAX           (512)    /* maximum # of IPsec policies (per direction); <= 0x3fffffff) */
#else
#define IPSEC_SPD_MAX           (16)    /* maximum # of IPsec policies (per direction); <= 0x3fffffff) */
#endif
#endif
#ifndef IPSEC_SPD_MATCH
#define IPSEC_SPD_MATCH           (16)    /* maximum # of IPsec policies to match for ikev2 narrowing*/
#endif
#ifndef IPSEC_NEST_MAX
#define IPSEC_NEST_MAX          (2)     /* maximum SA bundle size; e.g. 2=AH+ESP */
#endif



#if defined(__ENABLE_IPSEC_NULL_TUNNEL__) && defined(__DISABLE_IPSEC_TUNNEL_MODE__)
#undef __ENABLE_IPSEC_NULL_TUNNEL__
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
#define MOC_COOKIE(c)           , ubyte4 c
#define MOC_COOKIE_VALUE(c)     , c
#define MOC_COOKIE_REQ_VALUE    MOC_COOKIE_VALUE
#define MOC_COOKIE1(c)          ubyte4 c
#define MOC_COOKIE1_VALUE(c)    c
#define SET_MOC_COOKIE(d, s)    d = (s);
#define MOC_COOKIE_UNUSED(c)
#ifndef USE_MOC_COOKIE
    #define USE_MOC_COOKIE
#endif
#else
#define MOC_COOKIE(c)
#define MOC_COOKIE_VALUE(c)
#define MOC_COOKIE_REQ_VALUE(c) , 0
#define MOC_COOKIE1(c)          void
#define MOC_COOKIE1_VALUE(c)
#define SET_MOC_COOKIE(d, s)
#define MOC_COOKIE_UNUSED(c)    MOC_UNUSED(c);
#ifdef USE_MOC_COOKIE
    #undef USE_MOC_COOKIE
#endif
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
#define MOC_INTF(i)             , sbyte4 i
#define MOC_INTF_ID(i)          , i
#define MOC_INTF_REQ_ID(i)      , i
#define MOC_INTF_OPAQ(o, i)     , intBoolean o, sbyte4 i
#define MOC_INTF_OPAQ_ID(o, i)  , o, i
#define MOC_INTF_UNUSED(i)
#else
#define MOC_INTF(i)
#define MOC_INTF_ID(i)
#define MOC_INTF_REQ_ID(i)      , 0
#define MOC_INTF_OPAQ(o, i)
#define MOC_INTF_OPAQ_ID(o, i)
#define MOC_INTF_UNUSED(i)      MOC_UNUSED(i);
#endif


/*------------------------------------------------------------------*/

/**
@brief      Initialize IPsec internal structures and counters.

@details    This function initializes IPsec internal structures and counters.
            This function must be called before adding IPsec rules or keys to
            apply when sending packets, and rules to permit received packets.

@ingroup    ipsec_functions

@since 1.41
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipsec.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@ifnot __INCLUDE_DOXYGEN_FOR_NanoMCP__
@sa         For information about policies and rules, see the "Security Policies"
            section of @ref ipsec_provisioning.
@endif

@code
NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT        DriverObject,
    IN PUNICODE_STRING       RegistryPath
    )
// BEGIN_MOCANA
    if (OK == IPSEC_init()) {
        IPSEC_EXAMPLE_addKeys();
        IPSEC_EXAMPLE_addPolicies();
    }
    else {
        Status = NDIS_STATUS_FAILURE;
        NdisTerminateWrapper(NdisWrapperHandle, NULL);
    }
// END_MOCANA

    return(Status);
}
@endcode

@funcdoc    ipsec.h
*/
/**
@todo_65
*/
MOC_EXTERN sbyte4 IPSEC_init(void);

/**
@brief      Release rules from the SPD and keys from the SADB.

@details    This function releases rules from the SPD (Security Policy Database)
            and keys from the SADB (Security Association Database) within the
            IPsec stack. Rules define policies to apply and permit IPsec traffic.

@ingroup    ipsec_functions

@since 1.41
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipsec.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
VOID PtUnload(IN PDRIVER_OBJECT DriverObject)
// PassThru driver unload function
{
    UNREFERENCED_PARAMETER(DriverObject);

    DBGPRINT(("PtUnload: entered\n"));
// BEGIN_MOCANA
    NdisAcquireSpinLock(&GlobalLock);
    IPSEC_flush();
    NdisReleaseSpinLock(&GlobalLock);
// should wait a little here
// END_MOCANA
    PtUnloadProtocol();
    NdisIMDeregisterLayeredMiniport(DriverHandle);
    DBGPRINT(("PtUnload: done!\n"));
}
@endcode

@funcdoc    ipsec.h
*/
/**
@todo_65
*/
MOC_EXTERN sbyte4 IPSEC_flush(void);


/*------------------------------------------------------------------*/
/* Apply IPsec policies to an outbound packet. If security is re-   */
/* quired, security associations (SAs) are applied to protect the   */
/* packet.                                                          */

#ifdef USE_MOC_COOKIE
/**
@brief      Apply IPsec policies to an outbound packet.

@details    This function applies IPsec policies to an outbound packet.

@ingroup    ipsec_functions

@since 1.41
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@inc_file ipsec.h

@param pBuffer      Data buffer containing a raw outbound IP packet. The
                    buffer should be large enough for the resulting
                    encapsulated packet. (For more information about packet
                    size, see "Buffer Padding".)
@param wBufSize     Number of bytes in \p pBuffer.
@param pwLength     On return, pointer to number of bytes in the IPsec
                    encapsulated outbound packet.
@param pwOffset     At function call, number of bytes to skip from the start of
                    \p pBuffer to get to the start of the raw packet, or NULL
                    to ignore the parameter and use 0 offset on function call
                    and return. On return, pointer to the offset (number of
                    bytes to skip from the start of \p pBuffer) to the start
                    of the resulting encapsulated packet (will be 0 if NULL
                    specified at function call).
@param cookie       Custom data.

@todo_techpubs      (add page for "Buffer Padding" reference (in the \p pBuffer
                    param)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
NdisAcquireSpinLock(&GlobalLock);
status = IPSEC_apply((UCHAR *)pBuffer + sizeof(struct ether_header),
                     wBufferSize - sizeof(struct ether_header),
                     pwBytesReturned);
NdisReleaseSpinLock(&GlobalLock);
@endcode

@funcdoc    ipsec.h
*/
/**
@todo_65
*/
MOC_EXTERN sbyte4 IPSEC_apply(ubyte *pBuffer, ubyte2 wBufSize,
                              ubyte2 *pwLength, ubyte2 *pwOffset,
                              ubyte4 cookie);
#else
#define IPSEC_apply(b,s,l,o,c) IPSEC_applyEx(b,s,l,o,NULL)
#endif


/*------------------------------------------------------------------*/
/* Check if the inbound packet should be permitted to pass through  */
/* to the upper IP layers. IPsec processing is performed on a pro-  */
/* tected packet (i.e. with an AH or ESP payload).                  */

#ifdef USE_MOC_COOKIE
/**
@brief      Determine whether an incoming IPsec packet should be permitted to
            pass through to the upper IP layers.

@details    This function determines whether the incoming IPsec packet should
            be permitted to pass through to the upper IP layers. If so, the
            inbound packet (\p pBuffer) is modified, decapsulated, and returned.

@ingroup    ipsec_functions

@since 1.41
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@param pBuffer      Pointer to an inbound packet.
@param wBufSize     Number of bytes in \p pBuffer.
@param pwLength     On return, pointer to number of bytes in the decapsulated
                    inbound packet.
@param pwOffset     On return, pointer to the offset (number of bytes to skip
                    from the start of \p pBuffer) to the start of the
                    resulting decapsulated packet.
@param cookie       Custom data.

@inc_file ipsec.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
NdisAcquireSpinLock(&GlobalLock);
status = IPSEC_permit((UCHAR *)pBuffer + sizeof(struct ether_header),
                      wBufferSize - sizeof(struct ether_header),
                      pwBytesReturned);
NdisReleaseSpinLock(&GlobalLock);
@endcode

@funcdoc    ipsec.h
*/
/**
@todo_65
*/
MOC_EXTERN sbyte4 IPSEC_permit(ubyte *pBuffer, ubyte2 wBufSize,
                               ubyte2 *pwLength, ubyte2 *pwOffset,
                               ubyte4 cookie);
#else
#define IPSEC_permit(b,s,l,o,c) IPSEC_permitEx(b,s,l,o,NULL)
#endif


/*------------------------------------------------------------------*/
/* internal use only */

struct spd;

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IPSEC_ready(MOC_IP_ADDRESS dwDestAddr,
                              MOC_IP_ADDRESS dwSrcAddr,
                              ubyte oProto,
                              intBoolean bFragOff, intBoolean bMoreFrags,
                              ubyte2 wDestPort, ubyte2 wSrcPort,
                              intBoolean bInbound, struct spd **ppxSP,
                              sbyte4 ifid, ubyte4 cookie);


struct ipsecCtx;

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IPSEC_applyEx(ubyte *pBuffer, ubyte2 wBufSize,
                                ubyte2 *pwLength, ubyte2 *pwOffset,
                                struct ipsecCtx *ctx);


/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IPSEC_permitEx(ubyte *pBuffer, ubyte2 wBufSize,
                                 ubyte2 *pwLength, ubyte2 *pwOffset,
                                 struct ipsecCtx *ctx);


/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IPSEC_setIkeSettings(void *pIkeSettings);

/*------------------------------------------------------------------*/

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__

#include "../ipsec/ipsec_defs.h"

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__))
struct sk_buff;
struct nf_info;
#elif ((defined(__QNX_RTOS__) && defined(_KERNEL)) || \
       (defined(__VXWORKS_RTOS__) && !defined(IPCOM_KERNEL)))
struct mbuf;
#elif ((defined(__OSE_RTOS__) || defined(__VXWORKS_RTOS__)) && defined(IPCOM_KERNEL))
struct Ipcom_pkt_struct;
struct Ipnet_netif_struct;
#endif

#endif

struct sadb;

/**
@todo_add_ask   (We said to not include this for NanoMCP, but what about SoTP?)
*/
/**
 * @private
 * @internal
 */
typedef struct ipsecCtx
{

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    sbyte4 ifid;
#endif
#ifdef USE_MOC_COOKIE
    ubyte4 cookie;
#endif

    struct spd *pxSp;
    struct sadb *axSaUsed[IPSEC_NEST_MAX];

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    intBoolean bAsyncEnabled;

    sbyte4 status;

#ifdef __ENABLE_DIGICERT_HARNESS__
    intBoolean bCryptoAlloc;
    ubyte *pBuffer;
#endif
    ubyte2 wBufSize;    /* out */
    ubyte2 wOffset;     /* out */

    ubyte *poPayload;   /* in */

#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte *poNextHeader;
#endif
    ubyte2 wIpHdrLen;
    ubyte2 wLength;
    MOC_IP_ADDRESS_S dwSrcAddr;
    MOC_IP_ADDRESS_S dwDestAddr;

    ubyte2 wIcvLen;
    ubyte2 wIPsecHdrLen;/* in */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte  oMode;       /* in */
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort;
#endif
    sbyte4 counter;

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    ubyte4 adwSeql[IPSEC_NEST_MAX];   /* in */
#ifdef __ENABLE_IPSEC_ESN__
    ubyte4 adwSeqh[IPSEC_NEST_MAX];
#endif
#endif
    hwAccelDescr hwAccelCtx;

#ifdef __ENABLE_DIGICERT_HARNESS__
    ubyte poAuthKey[IPSEC_AUTHKEY_MAX];
#endif
    ubyte poDigest[IPSEC_DIGEST_MAX];
    ubyte poIv[IPSEC_IV_MAX];           /* out */

    BulkCtx pCipherCtx;

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__))
    struct sk_buff *skb;
    struct nf_info *info;
#elif ((defined(__QNX_RTOS__) && defined(_KERNEL)) || \
       (defined(__VXWORKS_RTOS__) && !defined(IPCOM_KERNEL)))
    struct mbuf *mb;
    ubyte *data;
#elif ((defined(__OSE_RTOS__) || defined(__VXWORKS_RTOS__)) && defined(IPCOM_KERNEL))
    struct Ipcom_pkt_struct *pkt;
    struct Ipnet_netif_struct *netif;
    void *rt;
    void *nexthop;
    ubyte flags;
#endif

#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

} *IPSECCTX;


#ifdef __cplusplus
}
#endif

#endif /* __IPSEC_HEADER__ */

