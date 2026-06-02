/**
 * @file  ipsec_protos.h
 * @brief NanoSec IPsec network protocols definitions header.
 *
 * @details    This file contains network protocol structure definitions for IPsec.
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

#ifndef __IPSEC_PROTOS_HEADER__
#define __IPSEC_PROTOS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/* Some flavors may need this... */
/* #pragma pack(push,1) */

#ifndef IPSEC_PACKED
#define IPSEC_PACKED
#endif

#ifndef IPSEC_PACKED_POST
#define IPSEC_PACKED_POST
#endif


/*------------------------------------------------------------------*/
/* Authentication Header */

IPSEC_PACKED
struct authHdr
{
    ubyte   oNextHeader;
    ubyte   oPayloadLen;
    ubyte2  wReserved;
    ubyte4  dwSpi;
    ubyte4  dwSeqNbr;
}
IPSEC_PACKED_POST;


/*------------------------------------------------------------------*/
/* ESP Header */

IPSEC_PACKED
struct espHdr
{
    ubyte4  dwSpi;
    ubyte4  dwSeqNbr;
}
IPSEC_PACKED_POST;


/*------------------------------------------------------------------*/
/* UDP Header */

IPSEC_PACKED
struct udpHdr
{
    ubyte2  uh_sport;       /* source port */
    ubyte2  uh_dport;       /* destination port */
    ubyte2  uh_ulen;        /* udp length */
    ubyte2  uh_sum;         /* udp checksum */
}
IPSEC_PACKED_POST;


/*------------------------------------------------------------------*/
/* TCP Header */

IPSEC_PACKED
struct tcpHdr
{
    ubyte2  th_sport;       /* source port */
    ubyte2  th_dport;       /* destination port */

    ubyte4  th_seq;         /* sequence number */
    ubyte4  th_ack;         /* acknowledgement number */
    ubyte   th_offx2;       /* data offset | (unused) */
    ubyte   th_flags;

    ubyte2  th_win;         /* window */
    ubyte2  th_sum;         /* checksum */
    ubyte2  th_urp;         /* urgent pointer */
}
IPSEC_PACKED_POST;


/*------------------------------------------------------------------*/
/* ICMP Header (partial) */

IPSEC_PACKED
struct icmpHdr
{
    ubyte   icmp_type;      /* type of message */
    ubyte   icmp_code;      /* type sub code */
}
IPSEC_PACKED_POST;


/*------------------------------------------------------------------*/
/* IP Header */

IPSEC_PACKED
struct ipHdr
{
    ubyte   ip_vhl;         /* version | header length */
    ubyte   ip_tos;         /* type of service */
#ifndef IP_ECN
#define IP_ECN 0x03         /* ECN field */
#endif
    ubyte2  ip_len;         /* total length */
    ubyte2  ip_id;          /* identification */
    ubyte2  ip_off;         /* fragment offset field */
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    ubyte   ip_ttl;         /* time to live */
    ubyte   ip_p;           /* protocol */
    ubyte2  ip_sum;         /* checksum */
    ubyte4  ip_src,ip_dst;  /* source and dest address */
}
IPSEC_PACKED_POST;

#define IP_ECT_1    0x01 /* 01 */
#define IP_ECT_0    0x02 /* 10 */
#define IP_CE       0x03 /* 11 */


/*------------------------------------------------------------------*/
/* IPv6 Header */

IPSEC_PACKED
struct ip6Hdr
{
    ubyte4  ip6_vtf;
#ifndef IP6_TC
#define IP6_TC 0x0ff00000   /* Traffic Class */
#endif
#ifndef IP6_ECN
#define IP6_ECN 0x00300000  /* ECN field */
#endif
#ifndef IP6_FL
#define IP6_FL 0x000fffff   /* Flow Label */
#endif
    ubyte2  ip6_payload_len;
    ubyte   ip6_nexthdr;
    ubyte   ip6_hop_limit;
    ubyte   ip6_saddr[16];
    ubyte   ip6_daddr[16];
}
IPSEC_PACKED_POST;

#define SIZEOF_IP6_HDR 40

#define IP6_TC_SHIFT 20

#define IP6_ECT_1   0x00100000
#define IP6_ECT_0   0x00200000
#define IP6_CE      0x00300000


/*------------------------------------------------------------------*/
/* IPv6 generic Extension Header */
/* e.g. Hop-by-Hop or Destination Options */

IPSEC_PACKED
struct extHdr6
{
    ubyte   oNextHeader;
    ubyte   oHdrExtLen;
}
IPSEC_PACKED_POST;

#define SIZEOF_EXT_HDR6     2


/*------------------------------------------------------------------*/
/* Routing Header (IPv6) */

IPSEC_PACKED
struct rtnHdr6
{
    ubyte   oNextHeader;
    ubyte   oHdrExtLen;
    ubyte   oType;
    ubyte   oSegmentLeft;
    ubyte4  dwReserved;
}
IPSEC_PACKED_POST;

#define SIZEOF_RTN_HDR6     8


/*------------------------------------------------------------------*/
/* Fragment Header (IPv6) */

IPSEC_PACKED
struct fragHdr6
{
    ubyte   oNextHeader;
    ubyte   oHdrExtLen;
    ubyte2  wOffset;
#ifndef IP6_MF
#define IP6_MF 0x0001               /* 'M'ore fragments */
#endif
#ifndef IP6_OFFMASK
#define IP6_OFFMASK(w) ((w) >> 3)   /* Fragment Offset */
#endif
    ubyte4  dwId;
}
IPSEC_PACKED_POST;

#define SIZEOF_FRAG_HDR6    8


/*------------------------------------------------------------------*/
/* ICMPv6 Header */

IPSEC_PACKED
struct icmp6Hdr
{
    ubyte   icmp6_type;     /* type of message */
    ubyte   icmp6_code;     /* type sub code */
    ubyte2  icmp6_csum;     /* Checksum */
}
IPSEC_PACKED_POST;

/* Neighbor Discovery for IPv6 (RFC 2461) - ICMPv6 messgae type */
#define ICMPV6_ND_RSOL  133 /* Router Solicitation */
#define ICMPV6_ND_RADV  134 /* Router Advertisement  */
#define ICMPV6_ND_SOL   135 /* Neighbor Solicitation */
#define ICMPV6_ND_ADV   136 /* Neighbor Advertisement  */
#define ICMPV6_ND_RDIR  137 /* Redirect */


/*------------------------------------------------------------------*/

/* Some flavors need this... */
/* #pragma pack(pop) */


/*------------------------------------------------------------------*/
/* TCP/UDP pseudo-header */

struct ulpPsHdr
{
    ubyte4  dwSrcIP;
    ubyte4  dwDstIP;
    ubyte4 dwNilProtLen;
};


/*------------------------------------------------------------------*/
/* TCP/UDP/ICMPv6 pseudo-header (IPv6) */

struct ulpPsHdr6
{
    ubyte   saddr[16];
    ubyte   daddr[16];
    ubyte4  len;
    ubyte   zero[3];
    ubyte   proto;
};


/*------------------------------------------------------------------*/
/* Protocols */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP    1       /* control message protocol */
#endif
#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4    4       /* IPv4 encapsulation */
#endif
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP    IPPROTO_IPV4    /* for compatibility */
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6       /* tcp */
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP     17      /* user datagram protocol */
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP     50      /* Encap Sec. Payload */
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH      51      /* Auth Header */
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6        41  /* IPv6-in-IP tunnelling */
#endif

#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS     0   /* IPv6 hop-by-hop options */
#endif

#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING     43  /* IPv6 routing header */
#endif

#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT    44  /* IPv6 fragmentation header */
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6      58  /* ICMPv6 */
#endif

#ifndef IPPROTO_NONE
#define IPPROTO_NONE        59  /* IPv6 no next header */
#endif

#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS     60  /* IPv6 destination options */
#endif

#ifdef __cplusplus
}
#endif


#endif /* __IPSEC_PROTOS_HEADER__ */

