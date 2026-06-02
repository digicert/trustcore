/**
 * @file  ipsec_utils.h
 * @brief NanoSec IPsec utility routines header.
 *
 * @details    This file contains IPsec utility function declarations.
 * @flags      Compilation flags required:
 *     To enable this file's functions, at least one of the following flags must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
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

#ifndef __IPSEC_UTILS_HEADER__
#define __IPSEC_UTILS_HEADER__

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) || defined(__ENABLE_DIGICERT_IKE_SERVER__)

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#include <linux/bitops.h>
#include <net/checksum.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#if defined(MOC_BIG_ENDIAN) && !defined(MOC_LITTLE_ENDIAN)

#define GET_NTOHL(n) n
#define GET_NTOHS(n) n
#define SET_NTOHL(h, n) h = n
#define SET_NTOHS(h, n) h = n
#define SET_NTOHS_1(v)
#define SET_HTONL(n, h) n = (ubyte4)(h)
#define SET_HTONS(n, h) n = (ubyte2)(h)

#else

#define GET_NTOHL(n)    DIGI_NTOHL((ubyte *)&(n))
#define GET_NTOHS(n)    DIGI_NTOHS((ubyte *)&(n))
#define SET_NTOHL(h, n) h = GET_NTOHL(n)
#define SET_NTOHS(h, n) h = GET_NTOHS(n)
#define SET_NTOHS_1(v)  SET_NTOHS(v, v)
#define SET_HTONL(n, h) DIGI_HTONL((ubyte *)&(n), (ubyte4)(h))
#define SET_HTONS(n, h) DIGI_HTONS((ubyte *)&(n), (ubyte2)(h))

#endif /* defined(MOC_BIG_ENDIAN) && !defined(MOC_LITTLE_ENDIAN) */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_IPV6__

#define MOC_IPADDR_NONE         0
#define ZERO_MOC_IPADDR(a)      a = 0
#define ISZERO_MOC_IPADDR(a)    (0 == (a))
#define SAME_MOC_IPADDR(a, b)   ((a) == (b))
#define COPY_MOC_IPADDR(s, a)   s = a
#define UPD_MOC_IPADDR(a, s)    a = s
#define REF_MOC_IPADDR(a)       a
#define DEREF_MOC_IPADDR(a)     a
#define RET_MOC_IPADDR4(a)      a
#define GET_MOC_IPADDR4(a)      a
#define SET_MOC_IPADDR4(a, v)   a = (ubyte4)(v)
#define GT_MOC_IPADDR4(a, b)    ((a) > (b))
#define GT_MOC_IPADDR           GT_MOC_IPADDR4
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
#define SAME_MOC_IPADDR(a, s)   (((a) == &(s)) ||\
                                 ((a) && ((a)->family == (s).family) &&\
                                  (((AF_INET == (a)->family) &&\
                                    ((a)->uin.addr == (s).uin.addr))\
                                   ||\
                                   ((AF_INET6 == (a)->family) &&\
                                    (0 == CmpIpAddr6((ubyte *) (a)->uin.addr6, (ubyte *) (s).uin.addr6))))))
#define COPY_MOC_IPADDR(s, a)   s = *(a)
#define UPD_MOC_IPADDR(a, s)    *(a) = s
#define REF_MOC_IPADDR(s)       &(s)
#define DEREF_MOC_IPADDR(a)     *(a)
#define RET_MOC_IPADDR4(s)      (s).uin.addr
#define GET_MOC_IPADDR4(a)      (a)->uin.addr
#define SET_MOC_IPADDR4(s, v)   (s).family = AF_INET; (s).uin.addr = (ubyte4)(v)
#define GT_MOC_IPADDR4(x, y)    ((x)->uin.addr > (y)->uin.addr)

#define IF_MOC_IPADDR6(s, _c)   if (AF_INET6 == (s).family) _c else
#define TEST_MOC_IPADDR6(a, _c) if (AF_INET6 == (a)->family) _c else

#define RET_MOC_IPADDR6(s)      (const ubyte *) (s).uin.addr6
#define GET_MOC_IPADDR6(a)      (const ubyte *) (a)->uin.addr6
#define SET_MOC_IPADDR6(s, v)   (s).family = AF_INET6; (s).uin.addr6[4] = 0;\
                                DIGI_MEMCPY((ubyte *) (s).uin.addr6, (const ubyte *)(v), 16)
#define GT_MOC_IPADDR6(x, y)    ((GET_NTOHL((x)->uin.addr6[0]) > GET_NTOHL((y)->uin.addr6[0])) ||\
                                 (((x)->uin.addr6[0] == (y)->uin.addr6[0]) &&\
                                  ((GET_NTOHL((x)->uin.addr6[1]) > GET_NTOHL((y)->uin.addr6[1])) ||\
                                   (((x)->uin.addr6[1] == (y)->uin.addr6[1]) &&\
                                    ((GET_NTOHL((x)->uin.addr6[2]) > GET_NTOHL((y)->uin.addr6[2])) ||\
                                     (((x)->uin.addr6[2] == (y)->uin.addr6[2]) &&\
                                      (GET_NTOHL((x)->uin.addr6[3]) > GET_NTOHL((y)->uin.addr6[3]))))))))
#define GT_MOC_IPADDR(p, q)     (((p)->family != (q)->family) ||\
                                 ((AF_INET == (p)->family) ? GT_MOC_IPADDR4(p, q) : GT_MOC_IPADDR6(p, q)))
#ifdef __ENABLE_DIGICERT_64_BIT__
#define CAST_MOC_IPADDR         ubyte8
#else
#define CAST_MOC_IPADDR         ubyte4
#endif

#endif /* __ENABLE_DIGICERT_IPV6__ */

/*#define INIT_MOC_IPADDR(a, s)   MOC_IP_ADDRESS a = REF_MOC_IPADDR(s);*/


/*------------------------------------------------------------------*/

#if defined(__LINUX_RTOS__) && defined(__KERNEL__) && defined(MOC_BIG_ENDIAN)
/* ip_compute_csum() returns in network byte order! */
#define Checksum16(data, len) ip_compute_csum(data, (int)(len))
#else
MOC_EXTERN ubyte2 Checksum16(ubyte *poData, ubyte2 wLen);
#endif

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#define SET_IPHDR_CSUM(_s, _h, _l) \
    _s = 0;\
    _s = ip_compute_csum(_h, (int)(_l));
#else
#define SET_IPHDR_CSUM(_s, _h, _l) \
    SET_HTONS(_s, 0);\
    SET_HTONS(_s, Checksum16(_h, _l));
#endif

MOC_EXTERN void ScanHexKey(ubyte2 wKeyDataLen, sbyte *poKeyData, ubyte2 wKeyLen, ubyte *poKey);

MOC_EXTERN sbyte4 checkIpinList(MOC_IP_ADDRESS ipAddr, MOC_IP_ADDRESS ipAddrList[], ubyte listCount);

MOC_EXTERN sbyte4 CheckIpRange(MOC_IP_ADDRESS dwIP, MOC_IP_ADDRESS dwIPEnd,
                               MOC_IP_ADDRESS dwAddr, MOC_IP_ADDRESS dwAddrEnd);

MOC_EXTERN sbyte4 IntersectIpRange(MOC_IP_ADDRESS dwIP1, MOC_IP_ADDRESS dwIP1End,
                                   MOC_IP_ADDRESS dwIP2, MOC_IP_ADDRESS dwIP2End);

MOC_EXTERN sbyte4 CheckPortList(ubyte2 * port_list, ubyte4 port_count, ubyte2 port);

#ifdef __ENABLE_IPSEC_PORT_RANGE__
MOC_EXTERN sbyte4 CheckPortRange(ubyte2 wPortStart, ubyte2 wPortEnd, ubyte2 wPort);
MOC_EXTERN sbyte4 IntersectPortRange(ubyte2 wPort1, ubyte2 wPort1End,
                                     ubyte2 wPort2, ubyte2 wPort2End);
#endif

MOC_EXTERN void SetUdpChecksum(ubyte *udp_hdr, ubyte4 ip_src, ubyte4 ip_dst);
MOC_EXTERN void SetTcpChecksum(ubyte *tcp_hdr, ubyte4 ip_src, ubyte4 ip_dst, ubyte2 len);

#ifdef __ENABLE_DIGICERT_IPV6__

MOC_EXTERN sbyte4 CmpIpAddr6(const ubyte *poIP1, const ubyte *poIP2);
MOC_EXTERN void SetUdp6Checksum(ubyte *udp_hdr, const ubyte *saddr, const ubyte *daddr);
MOC_EXTERN void SetTcp6Checksum(ubyte *tcp_hdr, const ubyte *saddr, const ubyte *daddr, ubyte2 len);
MOC_EXTERN void SetIcmp6Checksum(ubyte *icmp6_hdr, const ubyte *saddr, const ubyte *daddr, ubyte2 len);

#endif


#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) || defined(__ENABLE_DIGICERT_IKE_SERVER__) */

#endif /* __IPSEC_UTILS_HEADER__ */

