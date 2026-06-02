/**
 * @file  spd.h
 * @brief NanoSec IPsec Security Policy Database (SPD) header.
 *
 * @details    This file contains SPD data structures and function declarations.
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

#ifndef __SPD_HEADER__
#define __SPD_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#define IPSEC_SP_FLAG_INUSE         0x00000001
#define IPSEC_SP_FLAG_DELETED       0x00000002
#define IPSEC_SP_FLAG_INBOUND       0x00000004
#define IPSEC_SP_FLAG_MIRRORED      0x00000008

#define IPSEC_SP_FLAG_PFP_LADDR     0x00000100
#define IPSEC_SP_FLAG_PFP_RADDR     0x00000200
#define IPSEC_SP_FLAG_PFP_LPORT     0x00000400
#define IPSEC_SP_FLAG_PFP_RPORT     0x00000800
#define IPSEC_SP_FLAG_PFP_ULP       0x00001000
#define IPSEC_SP_MASK_PFP               0x00001f00

#define IPSEC_SP_FLAG_DF            0x00002000
#define IPSEC_SP_FLAG_DF_BIT        0x00004000
#define IPSEC_SP_MASK_DF                0x00006000

#define IPSEC_SP_FLAG_DSCP          0x00008000
#define IPSEC_SP_FLAG_ECN           0x00010000

/* used in "ipsecconf.h" only */
#define IPSEC_SP_FLAG_IP6           0x00000010
#define IPSEC_SP_FLAG_IP6_TUNNEL    0x00000020
#define IPSEC_SP_FLAG_INIT          0x00000040


/*------------------------------------------------------------------*/
/* Security Policy (SP) */

typedef struct spd
{
  void     *pNext;          /* for 'free' list or 'deleted' list */

  sbyte4    index;          /* SPD index; [1...IPSEC_SPD_MAX] */
  ubyte4    flags;          /* see flag constants above */

  MOC_IP_ADDRESS_S dwDestIP;    /* destination IP range lower limit */
  MOC_IP_ADDRESS_S dwDestIPEnd; /* destination IP range upper limit */
  ubyte2    wDestPort;      /* destination port number; 0=any or N/A */
#ifdef __ENABLE_IPSEC_PORT_RANGE__
  ubyte2    wDestPortEnd;   /* (optional) destination port range upper limit; 0=unused */
#endif
  ubyte2  wDestPortCount;
  ubyte2  wDestPortList[MAX_PORTS_PER_POLICY];
  MCP_PORT_CONFIG_TYPE wDestPortType;

  MOC_IP_ADDRESS_S dwSrcIP;     /* source IP range lower limit */
  MOC_IP_ADDRESS_S dwSrcIPEnd;  /* source IP range upper limit */
  ubyte2    wPortList[MAX_PORTS_PER_POLICY];        /*list of  port numbers; 0 for empty list*/
  ubyte2    wPortCount;       /* number of ports in port list number; 0=not defined or N/A */
  ubyte2    wSrcPort;       /* source port number; 0=any or N/A */
#ifdef __ENABLE_IPSEC_PORT_RANGE__
  ubyte2    wSrcPortEnd;    /* (optional) source port range upper limit; 0=unused */
#endif
  ubyte     oProto;         /* transport layer protocol; 0=any o/w see "ipsec_protos.h" */
  ubyte     oAction;        /* IPSEC_ACTION_{APPLY | PERMIT | DROP | BYPASS} */

#if 1 /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) */
  ubyte     oMode;          /* IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0=N/A */
  MOC_IP_ADDRESS_S dwTunlDestIP;    /* tunnel destination IP address; 0=N/A or no gateway */
  MOC_IP_ADDRESS_S dwTunlSrcIP;     /* tunnel source IP address; 0=N/A or no gateway */
#endif
  ubyte     oSaLen;                     /* SA bundle size */
  struct sainfo pxSa[IPSEC_NEST_MAX];   /* SA bundle; outermost first */

  ubyte4    dwCurPackets;   /* current count of protected packets */
  ubyte2    wCurBytes;      /* current count of protected bytes < 1k */
  ubyte4    dwCurKBytes;    /* current count of protected kbytes */

  ubyte4    dwTotPackets;   /* number of packets processed */

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
  sbyte4    ifid;           /* ID of interface via which a packet arrives, if applicable */
#endif
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
  ubyte4    cookie;         /* developer customizable cookie, e.g. VLan id */
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
  ubyte4    dwSaSecs;       /* child SA lifetime in seconds; 0=unspecified */
  ubyte4    dwSaBytes;      /* child SA lifetime in bytes; 0=unspecified */

  ubyte4    dwIkeSaId;
#endif
#ifdef CUSTOM_IPSEC_MAP_DSCP
  void     *pDscpMapping;
#endif
  ubyte4    dwId;           /* internal ID */

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
  void     *ob_hashEntry;
#endif
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
  ubyte isGdoi; /* whether or not gdoi is enabled*/
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
  MOC_IP_ADDRESS_S dwSrcIPList[MAX_IP_IN_FQDN - 1];     /* As the IP list must have MCP agent own IP and Security policy
                                                        will not be added for self IP so 1 entry is removed from total number of entries. while in case of ipsec key same data structure is used by PKDC and MCP agent so all IP entries are required. */

  MOC_IP_ADDRESS_S dwDestIPList[MAX_IP_IN_FQDN - 1];

  ubyte4  dwDestIPCount;
  ubyte4  dwSrcIPCount;

  ubyte isUnicastGDOI; /* whether or not gdoi is enabled*/
  sbyte fqdn[MOC_MAX_FQDN_LEN];
#endif

} *SPD, **PSPD;


/*------------------------------------------------------------------*/

MOC_EXTERN SPD IPSEC_enumSp(SPD pxSp);
MOC_EXTERN SPD IPSEC_indexSp(sbyte4 index, intBoolean bInbound);


/*------------------------------------------------------------------*/
/* internal use only */

MOC_EXTERN MSTATUS  IPSEC_initSpd(void);
MOC_EXTERN MSTATUS  IPSEC_flushSpd(void);
MOC_EXTERN SPD      IPSEC_getSpd(sbyte4 *numEntries);

MOC_EXTERN MSTATUS  IPSEC_newSp(struct ipsecConf *pxConf);
MOC_EXTERN MSTATUS  IPSEC_delSp(SPD pxSp);

MOC_EXTERN SPD      IPSEC_getSp(MOC_IP_ADDRESS dwDAddr, MOC_IP_ADDRESS dwSAddr,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                        MOC_IP_ADDRESS dwDAddrEnd, MOC_IP_ADDRESS dwSAddrEnd,
#endif
                        ubyte oProto,
                        intBoolean bCheckPorts,
                        ubyte2 wDPort, ubyte2 wSPort,
                        intBoolean bInbound
                        MOC_INTF_OPAQ(bOpaque, ifid)
                        MOC_COOKIE(cookie));

struct ipsecKeyEx;
struct sadb;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
extern MSTATUS      IPSEC_getSp2(struct ipsecKeyEx *pxKey);
#endif

extern MSTATUS      IPSEC_checkSp(struct ipsecKeyEx *pxKey, SPD pxSp);
extern intBoolean   IPSEC_matchSp(struct ipsecKeyEx *pxKey, struct sadb *pxSa,
                                  SPD pxSp, sbyte4 i);


#ifdef __cplusplus
}
#endif

#endif /* __SPD_HEADER__ */

