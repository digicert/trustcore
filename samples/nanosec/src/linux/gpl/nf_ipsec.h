/*
 * nf_ipsec.h
 *
 * Linux IPsec kernel module interface header
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Linking this program statically or dynamically with other modules is
 * making a combined work based on this program.  Thus, the terms and
 * conditions of the GNU General Public License cover the whole combination.
 *
 * As a special exception, the copyright holders of this program give you
 * permission to link this program with independent modules that
 * communicate with this program solely through the IPSEC_ interface,
 * regardless of the license terms of these independent modules, and to
 * copy and distribute the resulting combined work under terms of your
 * choice, provided that every copy of the combined work is accompanied by
 * a complete copy of the source code of this program (the version of this
 * program used to produce the combined work), being distributed under the
 * terms of the GNU General Public License plus this exception.
 * An independent module is a module which is not derived from or based on
 * this program.
 *
 * Note that people who make modified versions of this program are not
 * obligated to grant this special exception for their modified versions;
 * it is their choice whether to do so.  The GNU General Public License
 * gives permission to release a modified version without this exception;
 * this exception also makes it possible to release a modified version
 * which carries forward this exception.
 */

#ifndef __NF_IPSEC_H__
#define __NF_IPSEC_H__

#include "mtypes.h"
#include "merrors.h"
#include "mrtos.h"
#include "ipsec.h"
#include "ipseckey.h"
#include "ipsecconf.h"
#include "spd.h"
#include "sadb.h"
#include "kmem_part.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STORE_LEN 20
/* IOCMD command code for ipsec driver */
typedef enum {
    IOC_ADD_KEY             = 1000,
    IOC_ADD_KEY_EX,
    IOC_DEL_KEY,
    IOC_KEY_READY,
    IOC_KEY_INIT,
    IOC_FLUSH_SA,
    IOC_DUMP_SA,
    IOC_GET_SADB_SIZE,
    IOC_KEY_UPDATE,
    IOC_GET_KEY,

    IOC_ADD_CONF            = 1010,
    IOC_DEL_CONF,
    IOC_FLUSH_SPD,
    IOC_DUMP_SPD,

    IOC_TRACE               = 1020,
    IOC_DUMP_STATS,
    IOC_ENABLE,
    IOC_SET_RUNFLAGS,
    IOC_TEST_SIG,

    IOC_REGISTER_IKE_EVENTQ = 1030,
    IOC_GET_KEY_EX,

    IOC_GET_IFMAP = 1040,
    IOC_END
} IpsIoctlCmd_e;

/* IOCTL argument structure for key creation/deletion */
typedef struct {
    struct ipsecKey key;
    sbyte           authKey[128];       /* Key storage */
    sbyte           encrKey[128];
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte           dstAddr[16], srcAddr[16];
#endif
} ExtIpSecKey_t;

/* this is 32bit compat structure for struct ipsecKey */
typedef struct ipsecKeyCompat
{
    ubyte   oProtocol;          /* transport layer protocol e.g. IPPROTO_AH, IPPROTO_ESP, or 0 (any) */

    ubyte4  dwSpi;              /* SPI to use */

    ubyte4  dwDestAddr;         /* destination IP address (in host byte order) */

    ubyte4  dwSrcAddr;          /* source IP address (in host byte order); 0=unspecified */

#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2  wUdpEncPort;
#else
    ubyte2  wReserved;
#endif
    ubyte   oMode;              /* IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0 (don't care) */

    /* For IPSEC_keyAdd and PF_KEY, etc.*/
    ubyte   oAuthAlgo;          /* authentication algorithm ID; 0=none or N/A */
    ubyte4  pAuthKey;           /* authentication key; denoted by a hexadecimal character string */
    ubyte2  wAuthKeyLen;        /* authentication key string length */

    ubyte   oEncrAlgo;          /* encryption algorithm ID; 0=none or N/A */
    ubyte4  pEncrKey;           /* encryption key; denoted by a hexadecimal character string */
    ubyte2  wEncrKeyLen;        /* encryption key string length */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    ubyte   oNonceLen;          /* salt size (in bytes), e.g. 4; included in 'wEncrKeyLen'!!! */

    ubyte   oAeadIcvLen;        /* tag size (in bytes) for ESP Aead algo; e.g. 16, 12, 8, or 0=N/A */

    ubyte4  dwExpSecs;          /* expire after so many seconds elasped */

    ubyte4  dwExpKBytes;        /* expire after so many kbytes passed */
#endif
    ubyte2  wDestPort;          /* destination port number; 0=any or N/A */

    ubyte2  wSrcPort;           /* source port number; 0=any or N/A */

    ubyte   oUlp;               /* upper layer protocol; 0=any o/w, see "ipsec_protos.h" */

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4  cookie;             /* developer customizable cookie (e.g. VLan id) or PF_KEY reqid */
#endif
    /** @private @internal */
    ubyte4  dwSeqNo;            /* e.g. PF_KEY sadb_msg_seq */

    ubyte4  flags;              /* Note: Set IPSEC_SA_FLAG_IP6 if 'dwDestAddr'
                                   and 'dwSrcAddr' are cast from pointers to
                                   IPv6 addresses. */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4  dwIkeSaId;          /* IPSEC_keyDelete, IPSEC_keyUpdate */

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    sbyte4  ifid;               /* IPSEC_keyInitiate */
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
    /* PF_KEY async callback, e.g. IPSEC_keySpi() */
    ubyte4 dummyfn;
#endif
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

    sbyte4  status;             /* [internal] return status for kernel call */

} *IPSECKEY_COMPAT;

typedef struct {
    struct ipsecKeyCompat key;
    sbyte           authKey[128];       /* Key storage */
    sbyte           encrKey[128];
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte           dstAddr[16], srcAddr[16];
#endif
} ExtIpSecKeyCompat_t;



typedef struct {
    struct ipsecKeyEx key;
    sbyte             authKey[128];     /* Key storage */
    sbyte             encrKey[128];
#ifdef __ENABLE_DIGICERT_IPV6__
    MOC_IP_ADDRESS_S  dstAddr, srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_IP_ADDRESS_S  dstIP, dstIPend;
    MOC_IP_ADDRESS_S  srcIP, srcIPend;
#endif
#endif
} ExtIpSecKeyEx_t;

typedef struct ipsecKeyExCompat
{
    ubyte4  flags;              /* direction, initiator, replay, etc. */

    ubyte   oProtocol;          /* IPPROTO_AH or IPPROTO_ESP */
    ubyte4  dwSpi;              /* SPI to use */

    ubyte4 dwDestAddr;  /* destination IP address */
    ubyte4 dwSrcAddr;   /* source IP address */

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
    ubyte4 dwDestIP, dwDestIPEnd;  /* private destination IP range; tunnel mode only */
    ubyte4 dwSrcIP, dwSrcIPEnd;    /* private source IP range; tunnel mode only */
#endif
    ubyte   oAuthAlgo;          /* authentication algorithm ID; 0=none or N/A, see "ipsec_defs.h" */
    ubyte4  poAuthKey;          /* authentication key */
    ubyte2  wAuthKeyLen;        /* authentication key length (in bytes) */

    ubyte   oEncrAlgo;          /* encryption algorithm ID; 0=none or N/A, see "ipsec_defs.h" */
    ubyte4  poEncrKey;          /* encryption key */
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

    ubyte4 dwDestAddrList[MAX_IP_IN_FQDN];
    ubyte4  dwDestAddrCount;

    /** @private @internal */
    ubyte4 dwSrcAddrList[MAX_IP_IN_FQDN];
    ubyte4  dwSrcAddrCount;

    ubyte fqdn[MOC_MAX_FQDN_LEN]; /* store fqdn here*/
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    ubyte4 fqdnUniqueKey;
#endif
#endif
    intBoolean  inbound;
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

} *IPSECKEY_EX_COMPAT;

typedef struct {
    struct ipsecKeyExCompat key;
    sbyte             authKey[128];     /* Key storage */
    sbyte             encrKey[128];
#ifdef __ENABLE_DIGICERT_IPV6__
    MOC_IP_ADDRESS_S  dstAddr, srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_IP_ADDRESS_S  dstIP, dstIPend;
    MOC_IP_ADDRESS_S  srcIP, srcIPend;
#endif
#endif
} ExtIpSecKeyExCompat_t;


typedef struct spdCompat
{
  ubyte4    pNext;          /* for 'free' list or 'deleted' list */

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
  ubyte4    pDscpMapping;
#endif
  ubyte4    dwId;           /* internal ID */

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
  ubyte4    ob_hashEntry;
#endif
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
  ubyte isGdoi; /* whether or not gdoi is enabled*/
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
  MOC_IP_ADDRESS_S dwSrcIPList[MAX_IP_IN_FQDN - 1];     /* As the IP list must have MCP agent own IP and Security policy
                                                        will not be added for self IP so 1 entry is removed from Total number of entries. WHile in case of ipsec key same data strectre is used by PKDC and MCP agent so all IP entries are required.*/

  MOC_IP_ADDRESS_S dwDestIPList[MAX_IP_IN_FQDN - 1];

  ubyte4  dwDestIPCount;
  ubyte4  dwSrcIPCount;

  ubyte isUnicastGDOI; /* whether or not gdoi is enabled*/
  char  fqdn[MOC_MAX_FQDN_LEN];
#endif

} *SPDCOMPAT;


/* IOCTL argument structure for SPD/SA.  Note that the actual data must follow
 * the ExtIpSecDump_t in memory.  For example, do not malloc an additional
 * buffer for pBuf and then set pBuf; instead, malloc the entire struct like
 * this: malloc(sizeof(ExtIpSecDump_t) + sizeOfMyPBuf);
 */
typedef struct {
    ubyte4 ip;
    ubyte4 bufLen;
    ubyte pBuf[0];
} ExtIpSecDump_t;

typedef struct ipsecConfCompat
{
    ubyte4  dwSrcIP;
    ubyte4  dwSrcIPEnd;

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    ubyte4  dwDestIPList[MAX_IP_IN_FQDN - 1];         /* destination IP address (in host byte order) */
    ubyte4  dwDestIPCount;
    ubyte4  dwSrcIPList[MAX_IP_IN_FQDN - 1];          /* source IP address (in host byte order); 0=unspecified */
    ubyte4  dwSrcIPCount;
#endif

    ubyte2  wPortList[MAX_PORTS_PER_POLICY];  /* it will override the src and destination port settings*/
    ubyte2  wPortCount;  /* represent the numbers of ports present in the port list 0 represent not configured*/


    ubyte2  wSrcPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    ubyte2  wSrcPortEnd;
#endif
    MCP_PORT_CONFIG_TYPE srcPortType;

    ubyte4  dwDestIP;
    ubyte4  dwDestIPEnd;

    ubyte2  wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    ubyte2  wDestPortEnd;
#endif
    ubyte2  wDestPortCount;
    ubyte2  wDestPortList[MAX_PORTS_PER_POLICY];
    MCP_PORT_CONFIG_TYPE destPortType;

    ubyte   oProto;

    ubyte   oAction;

    ubyte   oDir;
    ubyte   oSaLen;
    ubyte4  pxSa;

#if 1 /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) */
    ubyte   oMode;

    ubyte4  dwTunlDestIP;
    ubyte4  dwTunlSrcIP;
#endif

    sbyte4  index;

#if 1 /* defined(__ENABLE_IPSEC_INTERFACE_ID__) */
    sbyte4  ifid;
#endif

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4  cookie;
#endif

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4  dwSaSecs;

    ubyte4  dwSaBytes;

    ubyte4  dwIkeSaId;
#endif

    ubyte4  flags;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    ubyte isGdoi; /* whether or not gdoi is enabled*/
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    char  fqdn[MOC_MAX_FQDN_LEN];
    ubyte isUnicastGDOI; /* whether or not gdoi is enabled*/
    MOC_IP_ADDRESS_S fqdnUniqueKey;
#endif

} *IPSECCONF_COMPAT;

typedef struct {
    struct ipsecConfCompat conf;
    struct sainfo    sa[2];             /* Max nesting is 2 */
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte            srcIP[16], srcIPend[16];
    ubyte            dstIP[16], dstIPend[16];
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte            tunDstIP[16], tunSrcIP[16];
#endif
#endif
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    intBoolean       rekeyForever;
#endif
} ExtIpSecConfCompat_t;

/* IOCTL argument structure for conf creation/deletion */
typedef struct {
    struct ipsecConf conf;
    struct sainfo    sa[2];             /* Max nesting is 2 */
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte            srcIP[16], srcIPend[16];
    ubyte            dstIP[16], dstIPend[16];
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte            tunDstIP[16], tunSrcIP[16];
#endif
#endif
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    intBoolean       rekeyForever;
#endif
} ExtIpSecConf_t;

struct task_struct;

typedef struct {
#ifdef __ENABLE_DIGICERT_MISSIU__
#define IKEQUEUE_TEMPLATE  "/missiuXXXXXX"
    char               name[sizeof(IKEQUEUE_TEMPLATE)];
#else
    int                tid;             /* IKE task PID */
    int                signal;          /* Signal when send */
    CircBuffer_t       *msgQueue;       /* Queue to send message to */
    struct task_struct *taskStruct;
#endif
} ExtIkeEventQ_t;

typedef struct {
#ifdef __ENABLE_DIGICERT_MISSIU__
#define IKEQUEUE_TEMPLATE  "/missiuXXXXXX"
    char               name[sizeof(IKEQUEUE_TEMPLATE)];
#else
    int                tid;             /* IKE task PID */
    int                signal;          /* Signal when send */
    ubyte8             msgQueue;       /* Queue to send message to */
#endif
} ExtIkeEventQIoctl_t;

/* Keep some statistics */
typedef struct {
    ubyte4 all;                         /* All packet thru filter */
    ubyte4 bytes;                       /* # of bytes */
    ubyte4 applied;                     /* All packets applied */
    ubyte4 errors;                      /* Error counts */
    ubyte4 maxSize;                     /* Largest packet sent/rec */
    ubyte4 nIpFrags;                    /* # of times fragment done */
    ubyte4 numFragments;                /* # of fragments */
    sbyte4 lastErr;                     /* Last error */
    ubyte4 ikeMsgs;
} Counter_t;

/* Driver operation structure */
typedef struct {
    ubyte     active;
    ubyte     trace;
    ubyte     runFlags;

    int            msgQid;              /* IKE notification qid */

    Counter_t      input;
    Counter_t      output;

    ExtIkeEventQ_t ikeQueue;

} ModStats_t;

typedef sbyte4 (*IPSEC_keyFlush_funcptr)(void);
typedef SADB (*IPSEC_enumSa_funcptr)(SADB);
typedef MSTATUS (*queue_put_tail_funcptr)(CircBuffer_t *, ubyte *, int);
typedef sbyte4 (*IPSEC_confFlush_funcptr)(void);
typedef MSTATUS (*DIGI_MEMSET_funcptr)(ubyte *, ubyte, usize);
typedef sbyte4 (*IPSEC_keyGet_funcptr)(IPSECKEY);
typedef sbyte4 (*IPSEC_keyGetEx_funcptr)(IPSECKEY_EX);

typedef sbyte4 (*IPSEC_confAdd1_funcptr)(IPSECCONF);

typedef sbyte4 (*IPSEC_groupKeyAdd_funcptr)(IPSECKEY_EX);

typedef sbyte4 (*IPSEC_keyAdd_funcptr)(IPSECKEY, sbyte4);
typedef sbyte4 (*IPSEC_keyAddEx_funcptr)(IPSECKEY_EX);

typedef sbyte4 (*IPSEC_keyDelete_funcptr)(IPSECKEY);

typedef sbyte4 (*IPSEC_keyInitiate_funcptr)(IPSECKEY);
typedef MSTATUS (*DIGI_MEMCPY_funcptr)(void *, const void *, sbyte4);

#ifdef __ENABLE_DIGICERT_IPV6__
typedef void (*SetUdp6Checksum_funcptr)(ubyte *, const ubyte *, const ubyte *);
typedef void (*SetTcp6Checksum_funcptr)(ubyte *, const ubyte *, const ubyte *, ubyte2);
typedef sbyte4 (*CmpIpAddr6_funcptr)(const ubyte *, const ubyte *);
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_MISSIU__)
extern int ipsec_ioctl(unsigned int cmd, unsigned long arg);
#elif defined(__KERNEL__)
struct file;
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)) )
extern long ipsec_ioctl(struct file *file,
#else
struct inode;
extern int ipsec_ioctl(struct inode *inode, struct file *file,
#endif
                       unsigned int cmd, unsigned long arg);
#endif

#if defined(__KERNEL__)
struct file;
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)) )
extern long
ipsec_compat_ioctl(struct file *file,
            unsigned int cmd, unsigned long arg);
#endif
#endif

/* extra space needed for IPsec outbound processing */
/*              head_room   tail_room
 ESP:sha1-3des      16      21
 ESP:sha256-3des    16      25
 ESP:sha384-3des    16      33
 ESP:sha512-3des    16      41
 ESP:sha1-aes       24      29
 ESP:sha256-aes     24      33
 ESP:sha384-aes     24      41
 ESP:sha512-aes     24      49
 ESP:gcm/gmac       16      21

 AH:sha1            24
 AH:sha256          28
 AH:sha384          36
 AH:sha512          44

 AH:sha1+ESP:3des   40      9
 AH:sha256+ESP:3des 44      9
 AH:sha384+ESP:3des 52      9
 AH:sha512+ESP:3des 60      9
 AH:sha1+ESP:aes    48      17
 AH:sha256+ESP:aes  52      17
 AH:sha384+ESP:aes  60      17
 AH:sha512+ESP:aes  68      17

 Note: 'head_room' excludes tunnel mode outer IP (20|40) and NAT-T UDP (8) headers.
*/

#ifdef __ENABLE_DIGICERT_IPV6__
#define HEAD_XTRA  88
#else
#define HEAD_XTRA  68   /* Tunnel AH:sha1+ESP:aes */
#endif

#ifndef TAIL_XTRA
#define TAIL_XTRA  33   /* ESP:sha256-aes */
#endif

#define PAD_XTRA    (HEAD_XTRA + TAIL_XTRA)


extern IPSEC_keyFlush_funcptr gM_IPSEC_keyFlush_ptr;
extern IPSEC_enumSa_funcptr gM_IPSEC_enumSa_ptr;
extern queue_put_tail_funcptr gM_queue_put_tail_ptr;
extern IPSEC_confFlush_funcptr gM_IPSEC_confFlush_ptr;
extern DIGI_MEMSET_funcptr gM_DIGI_MEMSET_ptr;
extern DIGI_MEMCPY_funcptr gM_DIGI_MEMCPY_ptr;
extern IPSEC_keyGet_funcptr gM_IPSEC_keyGet_ptr;
extern IPSEC_keyGetEx_funcptr gM_IPSEC_keyGetEx_ptr;
extern IPSEC_keyAdd_funcptr gM_IPSEC_keyAdd_ptr;
extern IPSEC_keyAddEx_funcptr gM_IPSEC_keyAddEx_ptr;
extern IPSEC_keyInitiate_funcptr gM_IPSEC_keyInitiate_ptr;
extern IPSEC_confAdd1_funcptr gM_IPSEC_confAdd1_ptr;
extern IPSEC_groupKeyAdd_funcptr gM_IPSEC_groupKeyAdd_ptr;
extern IPSEC_keyDelete_funcptr gM_IPSEC_keyDelete_ptr;
typedef sbyte4 (*IPSEC_keyReady_funcptr)(IPSECKEY_EX);
extern IPSEC_keyReady_funcptr gM_IPSEC_keyReady_ptr;
typedef SPD (*IPSEC_getSpd_funcptr)(sbyte4 *);
extern IPSEC_getSpd_funcptr gM_IPSEC_getSpd_ptr;
typedef sbyte4 (*IPSEC_confDelete_funcptr)(IPSECCONF);
extern IPSEC_confDelete_funcptr gM_IPSEC_confDelete_ptr;
typedef ubyte4 (*DIGI_deltaMS_funcptr)(const moctime_t*, moctime_t*);
extern DIGI_deltaMS_funcptr gM_DIGI_deltaMS_ptr;

#ifdef __ENABLE_DIGICERT_IPV6__
extern SetUdp6Checksum_funcptr gM_SetUdp6Checksum_ptr;
extern SetTcp6Checksum_funcptr gM_SetTcp6Checksum_ptr;
extern CmpIpAddr6_funcptr gM_CmpIpAddr6_ptr;
#endif

#ifdef __cplusplus
}
#endif

#endif                                  /* __NF_IPSEC_H__ */

