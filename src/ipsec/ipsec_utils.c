/**
 * @file  ipsec_utils.c
 * @brief NanoSec IPsec utility routines implementation.
 *
 * @details    This file contains IPsec utility function implementations.
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) || defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"


/*------------------------------------------------------------------*/

#if !(defined(__LINUX_RTOS__) && defined(__KERNEL__) && defined(MOC_BIG_ENDIAN))
extern ubyte2
Checksum16(ubyte *poData, ubyte2 wLen)
{
  ubyte4 dwSum = 0;

  /* check for an unaligned length - form a 16 bit word of
   * that octet with padding zeros on the right side
   */
  if (wLen & 1)
  {
    /* add the high byte (of the last octet) padded with zeros on the right */
    dwSum += ((ubyte4)*(poData + wLen - 1) << 8);
  }
  wLen>>=1; /* divide by 2 to get number of WORDs */

  /* for potential unaligned start of packet we need the following */
  if ((uintptr)poData & 1L) /* odd address */
  {
    /* mechanism here still does WORD reads for efficiency
     * at the cost of an extra shift & mask
     */
#if 1
    ubyte oMsb = *poData;
    ubyte2 *pwData = (ubyte2 *)(poData + 1);
    while (wLen--)
    {
      ubyte2 wData = *pwData++;
      SET_NTOHS_1(wData);
/*    ubyte2 wData = DIGI_NTOHS((ubyte *) pwData++);*/
/*    ubyte2 wData = NTOHS(*pwData++);*/
      dwSum += ((ubyte4)oMsb<<8) | (wData>>8);
      oMsb  = (ubyte)(wData & 0x00ff); /* grab LSB for next checksum MSB */
    }
#else
    /* alternative implementation possibly better if 'memory reads'
     * are more efficient
     */
    while (wLen--)
    {
      dwSum  += (((ubyte4)*poData) << 8) | *(poData + 1);
      poData += 2;
    }
#endif
  }
  else
  {
    ubyte2 *pwData = (ubyte2 *)poData;
    while (wLen--)
    {
      ubyte2 wData = *pwData++;
      SET_NTOHS_1(wData);
      dwSum += wData;
/*    dwSum += DIGI_NTOHS((ubyte *) pwData++);*/
/*    dwSum += NTOHS(*pwData++);*/
    }
  }

  /* 1s complement sum
   * Calculate using possible carry
   */
  dwSum = (dwSum >> 16) + (dwSum & 0xffff);
  dwSum += dwSum >> 16; /* add possible carry */

  /* Invert for result */
  return ((ubyte2)~dwSum);
} /* Checksum16 */
#endif


#ifdef __ENABLE_DIGICERT_IPV6__

/*------------------------------------------------------------------*/

extern sbyte4
CmpIpAddr6(const ubyte *poIP1, const ubyte *poIP2)
{
    sbyte4 status = 0;
    sbyte4 i;

    if (poIP1 != poIP2)
    {
        if (!poIP1) status = -1;
        else if (!poIP2) status = 1;
        else
        for (i=0; i < 4; i++)
        {
            ubyte4 x = DIGI_NTOHL(poIP1 + (i * 4));
            ubyte4 y = DIGI_NTOHL(poIP2 + (i * 4));
            if (x < y) { status = -1; break; }
            if (x > y) { status = 1; break; }
        }
    }

    return status;
} /* CmpIpAddr6 */


/*------------------------------------------------------------------*/

static sbyte4
CheckIpRange6(const ubyte *poAddr, const ubyte *poIP, const ubyte* poIPEnd)
{
    sbyte4 status;

    if ((0 <= (status = CmpIpAddr6(poAddr, poIP))) &&
        (0 >= (status = CmpIpAddr6(poAddr, poIPEnd))))
    {
        status = 0;
    }
    return status;
} /* CheckIpRange6 */

#endif /* __ENABLE_DIGICERT_IPV6__ */


/*------------------------------------------------------------------*/
extern sbyte4
checkIpinList(MOC_IP_ADDRESS ipAddr, MOC_IP_ADDRESS ipAddrList[], ubyte listCount)
{
    sbyte4 status = -1, i =0;
#ifdef __ENABLE_DIGICERT_IPV6__
#endif
    for (i = 0; i < listCount; i++)
    {
        if (ipAddrList[i] == ipAddr)
        {
            status = 0;
            break;  /* ip found*/
        }
    }
    return status;
}
/*------------------------------------------------------------------*/

extern sbyte4
CheckIpRange(MOC_IP_ADDRESS snAddr, MOC_IP_ADDRESS snAddrEnd,
             MOC_IP_ADDRESS ipAddr, MOC_IP_ADDRESS ipAddrEnd)
{
    sbyte4 status = 0;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == ipAddr->family)
    {
        if (AF_INET6 == snAddr->family)
        {
            if (0 == (status = CheckIpRange6(GET_MOC_IPADDR6(ipAddr),
                                             GET_MOC_IPADDR6(snAddr),
                                             GET_MOC_IPADDR6(snAddrEnd))))
            {
                if (ipAddrEnd)
                {
                    status = CheckIpRange6(GET_MOC_IPADDR6(ipAddrEnd),
                                           GET_MOC_IPADDR6(snAddr),
                                           GET_MOC_IPADDR6(snAddrEnd));
                }
            }
        }
        else status = 1;
    }
    else if (AF_INET6 == snAddr->family) status = -1;
    else
#endif
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte4 dwIP = GET_MOC_IPADDR4(snAddr);
        ubyte4 dwIPEnd = GET_MOC_IPADDR4(snAddrEnd);
        ubyte4 dwAddr = GET_MOC_IPADDR4(ipAddr);
        ubyte4 dwAddrEnd = (ipAddrEnd ? GET_MOC_IPADDR4(ipAddrEnd) : 0);
#else
        #define dwIP        snAddr
        #define dwIPEnd     snAddrEnd
        #define dwAddr      ipAddr
        #define dwAddrEnd   ipAddrEnd
#endif
        if (!dwIPEnd) /* just in case */
            dwIPEnd = (dwIP ? dwIP : ~((ubyte4)0));

        if (dwAddr < dwIP) status = -1;
        else if (dwAddr > dwIPEnd) status = 1;

        if (!status)
        {
            if (!dwAddrEnd && !dwAddr) /* just in case */
                dwAddrEnd = ~((ubyte4)0);

            if (dwAddrEnd)
            {
                if (dwAddrEnd < dwIP) status = -1;
                else if (dwAddrEnd > dwIPEnd) status = 1;
            }
        }
#ifndef __ENABLE_DIGICERT_IPV6__
        #undef dwIP
        #undef dwIPEnd
        #undef dwAddr
        #undef dwAddrEnd
#endif
    }

    return status;
} /* CheckIpRange */


/*------------------------------------------------------------------*/

extern sbyte4
IntersectIpRange(MOC_IP_ADDRESS dwIP1, MOC_IP_ADDRESS dwIP1End,
                 MOC_IP_ADDRESS dwIP2, MOC_IP_ADDRESS dwIP2End)
{
    sbyte4 ret = 0; /* no intersection */

    TEST_MOC_IPADDR6(dwIP1,
    {
        TEST_MOC_IPADDR6(dwIP2End, {})
        goto exit;
    })
    {
        TEST_MOC_IPADDR6(dwIP2End, { goto exit; }) {}
    }

    if (GT_MOC_IPADDR(dwIP1, dwIP2End) ||
        GT_MOC_IPADDR(dwIP2, dwIP1End))
        goto exit;

    ret = -1; /* intersect! */

    if (GT_MOC_IPADDR(dwIP1, dwIP2) ||
        GT_MOC_IPADDR(dwIP2End, dwIP1End))
        goto exit;

    ret = 1; /* IP1 includes IP2 */

exit:
    return ret;
} /* IntersectIpRange */


#ifdef __ENABLE_IPSEC_PORT_RANGE__

/*------------------------------------------------------------------*/

extern sbyte4
CheckPortRange(ubyte2 wPortStart, ubyte2 wPortEnd, ubyte2 wPort)
{
    sbyte4 status = 0;

    if (0 == wPortEnd)
    {
        if (0 == wPortStart) goto exit;
        wPortEnd = wPortStart;
    }

    if (wPort < wPortStart) status = -1;
    else if (wPort > wPortEnd) status = 1;

exit:
    return status;
} /* CheckPortRange */


/*------------------------------------------------------------------*/

extern sbyte4
IntersectPortRange(ubyte2 wPort1, ubyte2 wPort1End,
                   ubyte2 wPort2, ubyte2 wPort2End)
{
    sbyte4 ret = 0; /* no intersection */

    if (0 == wPort1End)
        wPort1End = (wPort1 ? wPort1 : 0xffff);

    if (0 == wPort2End)
        wPort2End = (wPort2 ? wPort2 : 0xffff);

    if ((wPort1 > wPort2End) || (wPort2 > wPort1End))
        goto exit;

    ret = -1; /* intersect! */

    if ((wPort1 > wPort2) || (wPort2End > wPort1End))
        goto exit;

    ret = 1; /* port range 1 includes port range 2 */

exit:
    return ret;
} /* IntersectPortRange */

#endif /* __ENABLE_IPSEC_PORT_RANGE__ */

extern sbyte4
CheckPortList(ubyte2 * port_list, ubyte4 port_count, ubyte2 port)
{
    ubyte j = 0;
    for (j = 0; j < port_count; j++)
    {
        /* found */
        if (port == port_list[j])
        {
            /* right entry found; use this id */
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n mapping port: %d  passed port: %d", (int)port_list[j], (int)port);
#endif
            return j;
        }
    }
    return -1;
}

/*------------------------------------------------------------------*/

extern void
ScanHexKey(ubyte2 wKeyDataLen, sbyte *poKeyData, ubyte2 wKeyLen, ubyte *poKey)
{
    ubyte2 i;

    DIGI_MEMSET(poKey, 0x00, wKeyLen);

    if (NULL != poKeyData)

    for (i=0; i < wKeyDataLen; i++)
    {
        char c = poKeyData[i];
        sbyte4 j = i / 2;

        if (j >= wKeyLen) break;

        if (('0' <= c) && ('9' >= c))
        {
            c -= '0';
        }
        else if (('A' <= c) && ('F' >= c))
        {
            c -= 'A' - 10;
        }
        else if (('a' <= c) && ('f' >= c))
        {
            c -= 'a' - 10;
        }

        poKey[j] |= c << ((i % 2) ? 0 : 4);
    }
} /* ScanHexKey */


/*------------------------------------------------------------------*/

extern void
SetUdpChecksum(ubyte *udp_hdr, ubyte4 ip_src, ubyte4 ip_dst)
{
    ubyte2 len;
    ubyte4 csum;
    struct ulpPsHdr ps_hdr;

    SET_NTOHS(len, ((struct udpHdr *)udp_hdr)->uh_ulen);
    SET_HTONS(((struct udpHdr *)udp_hdr)->uh_sum, 0);

    SET_HTONL(ps_hdr.dwSrcIP, ip_src);
    SET_HTONL(ps_hdr.dwDstIP, ip_dst);
#if 1
/*    SET_HTONL(ps_hdr.dwNilProtLen, ((IPPROTO_UDP << 16) | len));*/
    DIGI_HTONL((ubyte*) &(ps_hdr.dwNilProtLen), ((IPPROTO_UDP << 16) | len));
#else
              ps_hdr.oNull  = 0;
              ps_hdr.oProt  = IPPROTO_UDP;
    SET_HTONS(ps_hdr.wLen,    len);
#endif

    csum = (~((ubyte4)Checksum16((ubyte *)&ps_hdr, sizeof(struct ulpPsHdr))) & 0x0000FFFF) +
           (~((ubyte4)Checksum16(udp_hdr, len)) & 0x0000FFFF);
    if (csum & 0xFFFF0000)
        csum = (csum + 1) & 0x0000FFFF;

    SET_HTONS(((struct udpHdr *)udp_hdr)->uh_sum, ~csum);
} /* SetUdpChecksum */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__

extern void
SetUdp6Checksum(ubyte *udp_hdr, const ubyte *saddr, const ubyte *daddr)
{
    ubyte2 len;
    ubyte4 csum;
    struct ulpPsHdr6 ps_hdr;

    SET_NTOHS(len, ((struct udpHdr *)udp_hdr)->uh_ulen);
    SET_HTONS(((struct udpHdr *)udp_hdr)->uh_sum, 0);

    DIGI_MEMCPY(ps_hdr.saddr, saddr, 16);
    DIGI_MEMCPY(ps_hdr.daddr, daddr, 16);
    SET_HTONL( ps_hdr.len,   len);
    DIGI_MEMSET(ps_hdr.zero,  0x00,  3);
               ps_hdr.proto= IPPROTO_UDP;

    csum = (~((ubyte4)Checksum16((ubyte *)&ps_hdr, sizeof(struct ulpPsHdr6))) & 0x0000FFFF) +
           (~((ubyte4)Checksum16(udp_hdr, len)) & 0x0000FFFF);
    if (csum & 0xFFFF0000)
        csum = (csum + 1) & 0x0000FFFF;

    SET_HTONS(((struct udpHdr *)udp_hdr)->uh_sum, ~csum);
} /* SetUdp6Checksum */

#endif


/*------------------------------------------------------------------*/

extern void
SetTcpChecksum(ubyte *tcp_hdr, ubyte4 ip_src, ubyte4 ip_dst, ubyte2 len)
{
    ubyte4 csum;
    struct ulpPsHdr ps_hdr;

    SET_HTONS(((struct tcpHdr *)tcp_hdr)->th_sum, 0);

    SET_HTONL(ps_hdr.dwSrcIP, ip_src);
    SET_HTONL(ps_hdr.dwDstIP, ip_dst);
#if 1
/*    SET_HTONL(ps_hdr.dwNilProtLen, ((IPPROTO_TCP << 16) | len));*/
    DIGI_HTONL((ubyte*) &(ps_hdr.dwNilProtLen), ((IPPROTO_TCP << 16) | len));
#else
              ps_hdr.oNull  = 0;
              ps_hdr.oProt  = IPPROTO_TCP;
    SET_HTONS(ps_hdr.wLen,    len);
#endif

    csum = (~((ubyte4)Checksum16((ubyte *)&ps_hdr, sizeof(struct ulpPsHdr))) & 0x0000FFFF) +
           (~((ubyte4)Checksum16(tcp_hdr, len)) & 0x0000FFFF);
    if (csum & 0xFFFF0000)
        csum = (csum + 1) & 0x0000FFFF;

    SET_HTONS(((struct tcpHdr *)tcp_hdr)->th_sum, ~csum);
} /* SetTcpChecksum */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__

extern void
SetTcp6Checksum(ubyte *tcp_hdr, const ubyte *saddr, const ubyte *daddr, ubyte2 len)
{
    ubyte4 csum;
    struct ulpPsHdr6 ps_hdr;

    SET_HTONS(((struct tcpHdr *)tcp_hdr)->th_sum, 0);

    DIGI_MEMCPY(ps_hdr.saddr, saddr, 16);
    DIGI_MEMCPY(ps_hdr.daddr, daddr, 16);
    SET_HTONL( ps_hdr.len,   len);
    DIGI_MEMSET(ps_hdr.zero,  0x00,  3);
               ps_hdr.proto= IPPROTO_TCP;

    csum = (~((ubyte4)Checksum16((ubyte *)&ps_hdr, sizeof(struct ulpPsHdr6))) & 0x0000FFFF) +
           (~((ubyte4)Checksum16(tcp_hdr, len)) & 0x0000FFFF);
    if (csum & 0xFFFF0000)
        csum = (csum + 1) & 0x0000FFFF;

    SET_HTONS(((struct tcpHdr *)tcp_hdr)->th_sum, ~csum);
} /* SetTcp6Checksum */


/*------------------------------------------------------------------*/

extern void
SetIcmp6Checksum(ubyte *icmp6_hdr, const ubyte *saddr, const ubyte *daddr, ubyte2 len)
{
    ubyte4 csum;
    struct ulpPsHdr6 ps_hdr;

    SET_HTONS(((struct icmp6Hdr *)icmp6_hdr)->icmp6_csum, 0);

    DIGI_MEMCPY(ps_hdr.saddr, saddr, 16);
    DIGI_MEMCPY(ps_hdr.daddr, daddr, 16);
    SET_HTONL( ps_hdr.len,   len);
    DIGI_MEMSET(ps_hdr.zero,  0x00,  3);
               ps_hdr.proto= IPPROTO_ICMPV6;

    csum = (~((ubyte4)Checksum16((ubyte *)&ps_hdr, sizeof(struct ulpPsHdr6))) & 0x0000FFFF) +
           (~((ubyte4)Checksum16(icmp6_hdr, len)) & 0x0000FFFF);
    if (csum & 0xFFFF0000)
        csum = (csum + 1) & 0x0000FFFF;

    SET_HTONS(((struct icmp6Hdr *)icmp6_hdr)->icmp6_csum, ~csum);
} /* SetIcmp6Checksum */

#endif


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_STDLIB__) && !defined(__KERNEL__))

#include <stdio.h>

extern void
IPSEC_dump(char *pMessage, unsigned char *pPkt, int pktLen)
{
    int i;

    printf("%s\n========================\n", pMessage);
    printf("IP Header Length: %d\n", pPkt[0] & 0xf);
    printf("IP Version: %d\n", ((pPkt[0] >> 4) & 0xf));
    printf("IP Type Service: %d\n", pPkt[1]);
    printf("IP Total Length: %d (%d)\n", (pPkt[2] << 8)+pPkt[3], pktLen);
    printf("IP Identification: %d\n", (pPkt[4] << 8)+pPkt[5]);
    printf("IP Fragmentation Offset: %d\n", (pPkt[6] << 8)+pPkt[7]);
    printf("IP TTL: %d\n", pPkt[8]);
    printf("IP Protocol: %d\n", pPkt[9]);
    printf("IP Sum: %d\n", (pPkt[10] << 8)+pPkt[11]);
    printf("IP Src Addr: %d.%d.%d.%d\n", 0xff & pPkt[12], 0xff & pPkt[13], 0xff & pPkt[14], 0xff & pPkt[15]);
    printf("IP Dst Addr: %d.%d.%d.%d\n", 0xff & pPkt[16], 0xff & pPkt[17], 0xff & pPkt[18], 0xff & pPkt[19]);

    printf("Packet Payload:\n");

    if (128 < pktLen)
        pktLen = 128;

    for (i = 20; i < pktLen;)
    {
        if (0 == ((i - 20) % 0x10))
            printf("%03x: ", i);

        printf("%02x ", pPkt[i]);

        i++;

        if (0 == ((i - 20) % 0x10))
            printf("\n");
    }

    if (0 != ((i - 20) % 0x10))
        printf("\n");

} /* IPSEC_dump */

#endif /* (!defined(__DISABLE_STDLIB__) && !defined(__KERNEL__)) */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) || defined(__ENABLE_DIGICERT_IKE_SERVER__) */

