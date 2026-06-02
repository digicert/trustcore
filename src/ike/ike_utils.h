/**
 * @file  ike_utils.h
 * @brief IKE utility functions.
 *
 * @details    IKE helper function declarations.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, one of the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_PFKEY__
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

#ifndef __IKE_UTILS_HEADER__
#define __IKE_UTILS_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_PFKEY__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#if defined(MOC_BIG_ENDIAN) && !defined(MOC_LITTLE_ENDIAN)

#define GET_NTOHL(n) n
#define GET_NTOHS(n) n
#define SET_NTOHL(h, n) h = n
#define SET_NTOHS(h, n) h = n
#define SET_NTOHL_1(v)
#define SET_NTOHS_1(v)
#define SET_HTONL(n, h) n = (ubyte4)(h)
#define SET_HTONS(n, h) n = (ubyte2)(h)
#define SET_HTONL_1(v)
#define SET_HTONS_1(v)

#else

#define GET_NTOHL(n)    DIGI_NTOHL((ubyte *)&(n))
#define GET_NTOHS(n)    DIGI_NTOHS((ubyte *)&(n))
#define SET_NTOHL(h, n) h = GET_NTOHL(n)
#define SET_NTOHS(h, n) h = GET_NTOHS(n)
#define SET_NTOHL_1(v)  SET_NTOHL(v, v)
#define SET_NTOHS_1(v)  SET_NTOHS(v, v)
#define SET_HTONL(n, h) DIGI_HTONL((ubyte *)&(n), (ubyte4)(h))
#define SET_HTONS(n, h) DIGI_HTONS((ubyte *)&(n), (ubyte2)(h))
#define SET_HTONL_1(v)  SET_HTONL(v, v)
#define SET_HTONS_1(v)  SET_HTONS(v, v)

#endif /* defined(MOC_BIG_ENDIAN) && !defined(MOC_LITTLE_ENDIAN) */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_IPV6__

#define MOC_IPADDR_NONE         0
#define ZERO_MOC_IPADDR(a)      a = 0
#ifndef ISZERO_MOC_IPADDR
#define ISZERO_MOC_IPADDR(a)    (0 == (a))
#endif
#ifndef SAME_MOC_IPADDR
#define SAME_MOC_IPADDR(a, b)   ((a) == (b))
#endif
#define REF_MOC_IPADDR(a)       a
#define DEREF_MOC_IPADDR(a)     a
#define GET_MOC_IPADDR4(a)      a
#ifndef SET_MOC_IPADDR4
#define SET_MOC_IPADDR4(a, v)   a = (ubyte4)(v)
#endif
#ifndef LT_MOC_IPADDR4
#define LT_MOC_IPADDR4(a, b)    ((a) < (b))
#endif
#define LT_MOC_IPADDR           LT_MOC_IPADDR4
#define IF_MOC_IPADDR6(s, _c)
#define TEST_MOC_IPADDR6(a, _c)
#define CAST_MOC_IPADDR         ubyte4

#else

#ifndef AF_INET
#define AF_INET     2   /* Internet IP Protocol */
#endif

#ifndef AF_INET6        /* IP version 6 */
#if defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)
#define AF_INET6    10
#elif defined (__WIN32_RTOS__)
#define AF_INET6    23
#elif defined (__VXWORKS_RTOS__)
#define AF_INET6    28
#elif defined (__INTEGRITY_RTOS__)
#define AF_INET6    24
#else
#error Must define AF_INET6
#endif
#endif

#define MOC_IPADDR_NONE         { 0 }
#define ZERO_MOC_IPADDR(s)      (s).family = 0;\
                                (s).uin.addr6[0] = (s).uin.addr6[1] =\
                                (s).uin.addr6[2] = (s).uin.addr6[3] =\
                                (s).uin.addr6[4] = 0
#define ISZERO_MOC_IPADDR(s)    (0 == (s).family)
#define SAME_MOC_IPADDR(a, s)   ((a) && ((a)->family == (s).family) &&\
                                 (((AF_INET == (a)->family) &&\
                                   ((a)->uin.addr == (s).uin.addr))\
                                  ||\
                                  ((AF_INET6 == (a)->family) &&\
                                   ((a)->uin.addr6[0] == (s).uin.addr6[0]) &&\
                                   ((a)->uin.addr6[1] == (s).uin.addr6[1]) &&\
                                   ((a)->uin.addr6[2] == (s).uin.addr6[2]) &&\
                                   ((a)->uin.addr6[3] == (s).uin.addr6[3]))\
                                  ))
#define REF_MOC_IPADDR(s)       &(s)
#define DEREF_MOC_IPADDR(a)     *(a)
#define GET_MOC_IPADDR4(a)      (a)->uin.addr
#define SET_MOC_IPADDR4(s, v)   (s).family = AF_INET; (s).uin.addr = (ubyte4)(v)
#define LT_MOC_IPADDR4(x, y)    ((x).uin.addr < (y).uin.addr)

#define IF_MOC_IPADDR6(s, _c)   if (AF_INET6 == (s).family) _c else
#define TEST_MOC_IPADDR6(a, _c) if (AF_INET6 == (a)->family) _c else

#define GET_MOC_IPADDR6(a)      (const ubyte *) (a)->uin.addr6
#define SET_MOC_IPADDR6(s, v)   (s).family = AF_INET6; (s).uin.addr6[4] = 0;\
                                DIGI_MEMCPY((ubyte *) (s).uin.addr6, (const ubyte *)(v), 16)
#define LT_MOC_IPADDR6(x, y)    ((GET_NTOHL((x).uin.addr6[0]) < GET_NTOHL((y).uin.addr6[0])) ||\
                                 (((x).uin.addr6[0] == (y).uin.addr6[0]) &&\
                                  ((GET_NTOHL((x).uin.addr6[1]) < GET_NTOHL((y).uin.addr6[1])) ||\
                                   (((x).uin.addr6[1] == (y).uin.addr6[1]) &&\
                                    ((GET_NTOHL((x).uin.addr6[2]) < GET_NTOHL((y).uin.addr6[2])) ||\
                                     (((x).uin.addr6[2] == (y).uin.addr6[2]) &&\
                                      (GET_NTOHL((x).uin.addr6[3]) < GET_NTOHL((y).uin.addr6[3]))))))))
#define LT_MOC_IPADDR(p, q)     (((p).family != (q).family) ||\
                                 ((AF_INET == (p).family) ? LT_MOC_IPADDR4(p, q) : LT_MOC_IPADDR6(p, q)))
#ifdef __ENABLE_DIGICERT_64_BIT__
#define CAST_MOC_IPADDR         ubyte8
#else
#define CAST_MOC_IPADDR         ubyte4
#endif

#endif /* __ENABLE_DIGICERT_IPV6__ */

#define INIT_MOC_IPADDR(a, s)   MOC_IP_ADDRESS a = REF_MOC_IPADDR(s);
#ifndef COPY_MOC_IPADDR
#define COPY_MOC_IPADDR(s, a)   s = DEREF_MOC_IPADDR(a)
#endif


/*------------------------------------------------------------------*/

struct ikesa;
struct ike_context;

extern MSTATUS IKE_getPsk(ubyte **ppoPsk, ubyte4 *pdwPskLen,
                          struct ikesa *pxSa,
                          sbyte4 dir);  /* [v1] 0=both, or [v2] 1=in/peer, 2=out/host */

extern intBoolean IKE_isEmptyCky(const ubyte cky[8]); /* IKE_COOKIE_SIZE */

extern void IKE_scanHexKey(sbyte4 keyDataLen, const sbyte *poKeyData,
                           sbyte4 keyLen, ubyte *poKey);

MOC_EXTERN_DATA_DECL MSTATUS IKE_travAttrs(const ubyte *attrs, ubyte2 len, void *cb,
                             MSTATUS(*funcPtrCallback)(void *cb,
                                ubyte2          /* type */,
                                intBoolean      /* Basic (TRUE) or Variable (FALSE) */,
                                ubyte2          /* value (B) or length (V)*/,
                                const ubyte *   /* data {V} */));

extern MSTATUS IKE_travMsg(const ubyte *poMsg, ubyte4 dwLength, void *cb,
                           MSTATUS(*funcPtrCallback)(void * /* cb */,
                                                     ubyte /* payload type */,
                                                     const ubyte * /* payload */,
                                                     intBoolean * /* stop */));

extern MSTATUS MCP_getFullPath(const sbyte *pDirPath, const sbyte *pCertName, ubyte **ppFullPath);

/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)

extern void debug_printr(const ubyte *data, sbyte4 len, intBoolean br);
extern void debug_printk(sbyte *label, const ubyte *data, ubyte2 len);
extern void debug_printd(sbyte *label, const ubyte *data, ubyte2 len);
/*extern void debug_printb(sbyte *label, ubyte *data, sbyte4 len);*/
extern void debug_print_ip(MOC_IP_ADDRESS ipAddr);
extern void debug_print_ip_proto(ubyte oProto);
extern void debug_print_ikehdr(ubyte *poHdr);
extern void debug_print_ike_payload(ubyte oPayload);
extern void debug_print_ike_proto(ubyte oProtoId);
extern void debug_print_ike_tfmid(ubyte oAttrId, ubyte oProtoId);
extern void debug_print_ike_notify(ubyte2 wMsgType);
extern void debug_print_ike_p1_attr_t(ubyte2 wType);
extern void debug_print_ike_p1_attr_v(ubyte2 wValue, ubyte2 wType);
extern void debug_print_ike_p2_attr_v(ubyte2 wValue, ubyte2 wType);
extern void debug_print_ike_dn(ubyte *poDn, ubyte2 wDnLen);
extern void debug_print_ike_id2(ubyte *poHdr, intBoolean bInitiator);
extern void debug_print_ike_cfgtype(ubyte type);
extern void debug_print_ike_cfgattr(ubyte2 type, ubyte2 len, const ubyte *data);
extern void debug_print_ike_cfg_attrs(const ubyte *attrs, ubyte2 len, sbyte *indent, intBoolean xauth);
extern void debug_print_status(sbyte *file, sbyte4 lineno, sbyte4 status);
extern void debug_print_st(sbyte4 st);

#define debug_printnl(_s)           DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)(_s))
#define debug_print(_s)             DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)(_s))
#define debug_int(_s)               DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)(_s))
#define debug_uint(_s)              DEBUG_UINT(DEBUG_IKE_MESSAGES, _s)
#define debug_hexint(_s)            DEBUG_HEXINT(DEBUG_IKE_MESSAGES, _s)
#define debug_print3(_s, _t, _u)    DEBUG_PRINT3(DEBUG_IKE_MESSAGES, (sbyte *)(_s), (sbyte *)(_t), (sbyte *)(_u))
#define debug_uptime()              DEBUG_UPTIME(DEBUG_IKE_MESSAGES)

/* IKEv2 */
extern void debug_print_ike2_notify(ubyte2 wMsgType);
extern void debug_print_ike2_tfm(ubyte2 wTfmId, ubyte oType);
extern void debug_print_ike2_ts(ubyte *poHdr, intBoolean bInitiator);

#else

#define debug_printr(data, len, br)
#define debug_printk(label, data, len)
#define debug_printd(label, data, len)
/*#define debug_printb(label, data, len)*/
#define debug_print_ip(dwIpAddr)
#define debug_print_ip_proto(oProto)
#define debug_print_ikehdr(pxHdr)
#define debug_print_ike_payload(oPayload)
#define debug_print_ike_proto(oProtoId)
#define debug_print_ike_tfmid(oAttrId, oProtoId)
#define debug_print_ike_notify(wMsgType)
#define debug_print_ike_p1_attr_t(wType)
#define debug_print_ike_p1_attr_v(wValue, wType)
#define debug_print_ike_p2_attr_v(wValue, wType)
#define debug_print_ike_dn(poDn, wDnLen)
#define debug_print_ike_id2(poHdr, bInitiator)
#define debug_print_ike_cfgtype(type)
#define debug_print_ike_cfgattr(type, len, data)
#define debug_print_ike_cfg_attrs(attrs, len, indent, xauth)
#define debug_print_status(file, lineno, status)
#define debug_print_st(st)

#define debug_printnl(_s)
#define debug_print(_s)
#define debug_int(_s)
#define debug_uint(_s)
#define debug_hexint(_s)
#define debug_print3(_s, _t, _u)
#define debug_uptime()

/* IKEv2 */
#define debug_print_ike2_notify(wMsgType)
#define debug_print_ike2_tfm(wTfmId, oType)
#define debug_print_ike2_ts(poHdr, bInitiator)

#endif /* defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) */


#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_PFKEY__) */

#endif /* __IKE_UTILS_HEADER__ */

