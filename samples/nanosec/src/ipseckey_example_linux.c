/*
 * ipseckey_example_linux.c
 *
 * Linux Platform Only - Example code for integrating IKE server with IPsec stack
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
 */

#include "moptions.h"

#if defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)
#if defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
#if (defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__)) && !defined(__ENABLE_DIGICERT_PFKEY__)

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#ifdef __PLATFORM_HAS_GETOPT__
#include <stdlib.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/route.h>
#include <net/if.h>
#include <signal.h>
#include <linux/sockios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>


#include "mtypes.h"
#include "mocana.h"
#include "hw_accel.h"

#include "mdefs.h"
#include "merrors.h"
#include "mstdlib.h"
#include "mrtos.h"

#include "debug_console.h"
#include "mem_part.h"
#include "ipsec.h"
#include "ipsec_defs.h"
#include "ipsecconf.h"
#include "ipseckey.h"
#include "ike.h"
#include "ike_defs.h"
#include "ikekey.h"
#include "ike_event.h"
#include "ike_utils.h"
#include "kmem_part.h"

#define IPS2IKE_SIGNAL  (SIGUSR2)

#include "nf_ipsec.h"

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
MOC_EXTERN intBoolean is_mcp_infinite_timeout();
#endif

static sbyte4 IPSEC_sendIoCtl(IpsIoctlCmd_e command, void *arg);

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
extern sbyte4
IPSEC_sendIfmapInfo(void *ifmap_arr)
{
    sbyte status;
    status = IPSEC_sendIoCtl(IOC_GET_IFMAP, ifmap_arr);
    if(status < 0)
        return -1;
    return 0;
}
#endif

/* The following functions are common functions used by both the kernel and
 * userspace linux builds
 */
extern sbyte4
IPSEC_prepareKeyAddEx(IPSECKEY_EX pxKey, ExtIpSecKeyEx_t *keyInfo)
{

    if ((pxKey->wAuthKeyLen > sizeof(keyInfo->authKey)) ||
        (pxKey->wEncrKeyLen > sizeof(keyInfo->encrKey)))
    {
        return -1;
    }

    DIGI_MEMSET((void *)keyInfo, 0, sizeof(ExtIpSecKeyEx_t));
    keyInfo->key = *pxKey;

    if (pxKey->poAuthKey)
        DIGI_MEMCPY((void *)&keyInfo->authKey, pxKey->poAuthKey, pxKey->wAuthKeyLen);

    if (pxKey->poEncrKey)
        DIGI_MEMCPY((void *)&keyInfo->encrKey, pxKey->poEncrKey, pxKey->wEncrKeyLen);

#ifdef __ENABLE_DIGICERT_IPV6__
    if (pxKey->dwDestAddr) keyInfo->dstAddr = *(pxKey->dwDestAddr);
    if (pxKey->dwSrcAddr)  keyInfo->srcAddr = *(pxKey->dwSrcAddr);
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (pxKey->dwDestIP)    keyInfo->dstIP    = *(pxKey->dwDestIP);
    if (pxKey->dwDestIPEnd) keyInfo->dstIPend = *(pxKey->dwDestIPEnd);
    if (pxKey->dwSrcIP)     keyInfo->srcIP    = *(pxKey->dwSrcIP);
    if (pxKey->dwSrcIPEnd)  keyInfo->srcIPend = *(pxKey->dwSrcIPEnd);
#endif
#endif
    return 0;
}

#ifdef __ENABLE_DIGICERT_IPV6__
extern sbyte4
IPSEC_prepareKeyReady(IPSECKEY_EX pxKey, ExtIpSecKeyEx_t *keyInfo)
{
    DIGI_MEMSET((void *)keyInfo, 0, sizeof(ExtIpSecKeyEx_t));
    keyInfo->key = *pxKey;

    if (pxKey->dwDestAddr) keyInfo->dstAddr = *(pxKey->dwDestAddr);
    if (pxKey->dwSrcAddr)  keyInfo->srcAddr = *(pxKey->dwSrcAddr);
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (pxKey->dwDestIP)    keyInfo->dstIP    = *(pxKey->dwDestIP);
    if (pxKey->dwDestIPEnd) keyInfo->dstIPend = *(pxKey->dwDestIPEnd);
    if (pxKey->dwSrcIP)     keyInfo->srcIP    = *(pxKey->dwSrcIP);
    if (pxKey->dwSrcIPEnd)  keyInfo->srcIPend = *(pxKey->dwSrcIPEnd);
#endif
    return 0;
}

extern void
IPSEC_finalizeKeyReady(IPSECKEY_EX pxKey, ExtIpSecKeyEx_t *keyInfo, sbyte4 status)
{
    if (!pxKey->dwSpdId)
    {
        pxKey->dwSpdId = keyInfo->key.dwSpdId;
        pxKey->spdIndex = keyInfo->key.spdIndex;
    }
    pxKey->dwExpSecs = keyInfo->key.dwExpSecs;
    pxKey->dwExpKBytes = keyInfo->key.dwExpKBytes;

    if (STATUS_SPD_NARROWED == status) /* [v2] */
    {
        /* get new TS */
        if (!pxKey->oUlp) pxKey->oUlp = keyInfo->key.oUlp;
        if (pxKey->oUlp)
        {
            if (!pxKey->wDestPort) pxKey->wDestPort = keyInfo->key.wDestPort;
            if (!pxKey->wSrcPort) pxKey->wSrcPort = keyInfo->key.wSrcPort;
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT != pxKey->oMode)
        {
            if (pxKey->dwDestIP)    *(pxKey->dwDestIP)    = keyInfo->dstIP;
            if (pxKey->dwDestIPEnd) *(pxKey->dwDestIPEnd) = keyInfo->dstIPend;
            if (pxKey->dwSrcIP)     *(pxKey->dwSrcIP)     = keyInfo->srcIP;
            if (pxKey->dwSrcIPEnd)  *(pxKey->dwSrcIPEnd)  = keyInfo->srcIPend;
        }
#endif
    }
}

extern sbyte4
IPSEC_prepareKeyDelete(IPSECKEY pxKey, ExtIpSecKey_t *keyInfo)
{
    DIGI_MEMSET((void *)keyInfo, 0, sizeof(ExtIpSecKey_t));
    keyInfo->key = *pxKey;

    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        if (pxKey->dwDestAddr)
            DIGI_MEMCPY((void *) keyInfo->dstAddr, (const void *) pxKey->dwDestAddr, 16);

        if (pxKey->dwSrcAddr)
            DIGI_MEMCPY((void *) keyInfo->srcAddr, (const void *) pxKey->dwSrcAddr, 16);
    }
    return 0;
}

extern sbyte4
IPSEC_prepareKeyInitiate(IPSECKEY pxKey, ExtIpSecKey_t *keyInfo)
{
    DIGI_MEMSET((void *)&keyInfo, 0, sizeof(ExtIpSecKey_t));
    keyInfo->key = *pxKey;

    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        if (pxKey->dwDestAddr)
            DIGI_MEMCPY((void *) keyInfo->dstAddr, (const void *) pxKey->dwDestAddr, 16);

        if (pxKey->dwSrcAddr)
            DIGI_MEMCPY((void *) keyInfo->srcAddr, (const void *) pxKey->dwSrcAddr, 16);
    }
    return 0;
}
#endif /* __ENABLE_DIGICERT_IPV6__ */

extern sbyte4
IPSEC_prepareConfAdd1(IPSECCONF pxConf, ExtIpSecConf_t *ioBuf)
{
    memcpy(&ioBuf->conf, pxConf,       sizeof(ioBuf->conf));
    memcpy(&ioBuf->sa,   pxConf->pxSa, sizeof(ioBuf->sa));

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    ioBuf->rekeyForever = is_mcp_infinite_timeout();
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SP_FLAG_IP6 & pxConf->flags)
    {
        if (pxConf->dwSrcIP)
            memcpy(ioBuf->srcIP,    (ubyte *) pxConf->dwSrcIP,    16);
        if (pxConf->dwSrcIPEnd)
            memcpy(ioBuf->srcIPend, (ubyte *) pxConf->dwSrcIPEnd, 16);
        if (pxConf->dwDestIP)
            memcpy(ioBuf->dstIP,    (ubyte *) pxConf->dwDestIP,    16);
        if (pxConf->dwDestIPEnd)
            memcpy(ioBuf->dstIPend, (ubyte *) pxConf->dwDestIPEnd, 16);
    }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_SP_FLAG_IP6_TUNNEL & pxConf->flags)
    {
        if (pxConf->dwTunlDestIP)
            memcpy(ioBuf->tunDstIP, (ubyte *) pxConf->dwTunlDestIP, 16);
        if (pxConf->dwTunlSrcIP)
            memcpy(ioBuf->tunSrcIP, (ubyte *) pxConf->dwTunlSrcIP,  16);
    }
#endif
#endif /* __ENABLE_DIGICERT_IPV6__ */
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    ioBuf->conf.isGdoi = pxConf->isGdoi;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    ioBuf->conf.isUnicastGDOI = pxConf->isUnicastGDOI;
#endif

    return 0;
}

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
extern sbyte4
IPSEC_prepareKeyAdd(IPSECKEY pxKey, ExtIpSecKey_t *ioBuf)
{
    memcpy(&ioBuf->key, pxKey, sizeof(ioBuf->key));

    if (pxKey->pAuthKey)
        memcpy(ioBuf->authKey, pxKey->pAuthKey, pxKey->wAuthKeyLen);
    if (pxKey->pEncrKey)
        memcpy(ioBuf->encrKey, pxKey->pEncrKey, pxKey->wEncrKeyLen);

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        if (pxKey->dwDestAddr)
            memcpy(ioBuf->dstAddr, (ubyte *) pxKey->dwDestAddr, 16);
        if (pxKey->dwSrcAddr)
            memcpy(ioBuf->srcAddr, (ubyte *) pxKey->dwSrcAddr, 16);
    }
#endif
    return 0;
}
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
extern sbyte4
IPSEC_prepareKeyGetEx(IPSECKEY_EX pxKey, ExtIpSecKeyEx_t *ioBuf)
{
    memcpy(&ioBuf->key, pxKey, sizeof(ioBuf->key));

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        memcpy(ioBuf->dstAddr, (ubyte *) pxKey->dwDestAddr, 16);
    }
#endif
    return 0;
}

extern sbyte4
IPSEC_prepareKeyGet(IPSECKEY pxKey, ExtIpSecKey_t *ioBuf)
{
    memcpy(&ioBuf->key, pxKey, sizeof(ioBuf->key));

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        memcpy(ioBuf->dstAddr, (ubyte *) pxKey->dwDestAddr, 16);
    }
#endif
    return 0;
}
#endif

#ifndef __ENABLE_DIGICERT_MISSIU__

#define IPS2IKE_SIGNAL  (SIGUSR2)

#if (defined(__ENABLE_DIGICERT_VPN_EXAMPLE__))

/* Note.. Please Use the interface dummy0 for VPN App. Do the following on the system insmod dummy.ko from the relevant to create the dummy adaptor
*/
extern sbyte4       m_NTEContext ;

/*==============================================================================
/ function: add_dest_routes
/ description: sets routes to the dummy interface
/==============================================================================
*/

static int
add_dest_routes( int sockfd, in_addr_t dest, in_addr_t in_mask, in_addr_t gip )
{
    struct sockaddr_in *dst, *gw, *mask;
    struct rtentry route;

    memset(&route,0,sizeof(struct rtentry));

    dst = (struct sockaddr_in *)(&(route.rt_dst));
    gw = (struct sockaddr_in *)(&(route.rt_gateway));
    mask = (struct sockaddr_in *)(&(route.rt_genmask));

/* Make sure we're talking about IP here */
    dst->sin_family = AF_INET;
    gw->sin_family = AF_INET;
    mask->sin_family = AF_INET;

/* Set up the data for adding the route */
    dst->sin_addr.s_addr = dest;
    gw->sin_addr.s_addr = 0;
    mask->sin_addr.s_addr = in_mask;
    route.rt_metric = 1;
    route.rt_flags = RTF_UP ;
    route.rt_dev  = "dummy0" ;

/* Add the  route */
    if( ioctl(sockfd,SIOCADDRT,&route) == -1 )
    {
        perror("Adding Route");
        fprintf( stderr,"Adding  route: %d", errno);
        return -1;
    }

    return 0;
}


/*==============================================================================
/ function: set_default_gw
/ description: sets routing table's default gateway to the sock peer
/==============================================================================
*/

static int
set_default_gw( int sockfd, in_addr_t dest, in_addr_t in_mask, in_addr_t gip )
{
    struct sockaddr_in *dst, *gw, *mask;
    struct rtentry route;

    memset(&route,0,sizeof(struct rtentry));

    dst = (struct sockaddr_in *)(&(route.rt_dst));
    gw = (struct sockaddr_in *)(&(route.rt_gateway));
    mask = (struct sockaddr_in *)(&(route.rt_genmask));

/* Make sure we're talking about IP here */
    dst->sin_family = AF_INET;
    gw->sin_family = AF_INET;
    mask->sin_family = AF_INET;

/* Set up the data for removing the default route */
    dst->sin_addr.s_addr = 0;
    gw->sin_addr.s_addr = 0;
    mask->sin_addr.s_addr = 0;
    route.rt_flags = RTF_UP | RTF_GATEWAY;

/* Remove the default route */
    ioctl(sockfd,SIOCDELRT,&route);

/* Set up the data for adding the default route */
    dst->sin_addr.s_addr = 0;
    gw->sin_addr.s_addr = gip;
    mask->sin_addr.s_addr = 0;
    route.rt_metric = 1;
    route.rt_flags = RTF_UP | RTF_GATEWAY;

/* Remove this route if it already exists */
    ioctl(sockfd,SIOCDELRT,&route);

/* Add the default route */
    if( ioctl(sockfd,SIOCADDRT,&route) == -1 )
    {
        fprintf( stderr,"Adding default route: %d", errno);
        return -1;
    }

    return 0;
}


/*==============================================================================
/ function: UpdateIP
/ description: updates the networks parameters
/==============================================================================
*/

extern void
UpdateIP(const char *ifname, in_addr_t ip, in_addr_t mask, in_addr_t gip)
{
    struct ifreq ifr;
    char *myip;
    int sock = socket(AF_INET,SOCK_DGRAM,0);
    in_addr_t IP;
    struct rtentry rt;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    memset(&rt, 0, sizeof(rt));

    /* Get the interface IP address*/
    strcpy( ifr.ifr_name, ifname );
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl( sock, SIOCGIFADDR, &ifr ) < 0)
        perror( "SIOCGIFADDR" );
    myip = inet_ntoa( ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr );

    IP = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = ip;
    if (ioctl( sock, SIOCSIFADDR, &ifr ) < 0)
        perror( "SIOCSIFADDR" );

    if (ip)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~(IFF_UP);

    if (ioctl( sock, SIOCSIFFLAGS, &ifr ) < 0)
        perror( "SIOCSIFFLAGS" );

    shutdown(sock,SHUT_RDWR);
}


extern sbyte4
OnAddIP(sbyte4 IfIndex, MOC_IP_ADDRESS Address, MOC_IP_ADDRESS IpMask, sbyte* m_NTEContext, MOC_IP_ADDRESS DNSAddr )
{
     UpdateIP("dummy0", Address, IpMask, 0);
     return 0;
}


extern sbyte4
Add_Route( sbyte4 destination, sbyte4 gateway, MOC_IP_ADDRESS mask, sbyte4 direct )
{
    int sock = socket(AF_INET,SOCK_DGRAM,0);
    add_dest_routes(sock, destination, mask, gateway);
    shutdown(sock,SHUT_RDWR);
    return 0;
}


extern sbyte4
OnIp2Intf(MOC_IP_ADDRESS * ipAddr,sbyte4 *rIfIndex)
{
    struct ifreq ifreqs[20];
    int sock = socket(AF_INET,SOCK_DGRAM,0);
    struct ifconf ifconf;
    int i, nifaces;
    struct sockaddr_in *b;
    memset (&ifconf,0, sizeof(ifconf));

    ifconf.ifc_buf = (char *)(ifreqs);
    ifconf.ifc_len = sizeof(ifreqs);

    if (ioctl( sock, SIOCGIFCONF, (char *)&ifconf ) < 0)
    {
        perror( "SIOCGIFCONF" );
        return -1;
    }

    close (sock);

    nifaces = ifconf.ifc_len/sizeof(struct ifreq);

    for (i=0;i < nifaces;i++)
    {
        b = (struct sockaddr_in *)&(ifreqs[i].ifr_addr);
        if (!strncmp(ifreqs[i].ifr_name,"lo",strlen("lo")))
            continue;
        if (!strncmp(ifreqs[i].ifr_name,"dummy0",strlen("dummy0")))
            continue;
        printf("\t%-10s %x\n",ifreqs[i].ifr_name, b->sin_addr.s_addr);
        *ipAddr = b->sin_addr.s_addr;
        return 0;
    }

    return 0;
}


extern sbyte4
OnIp2MultiIntf(MOC_IP_ADDRESS * ipAddr, sbyte4 maxInst,sbyte4 *rIfIndex)
{
    struct ifreq ifreqs[20];
    int sock = socket(AF_INET,SOCK_DGRAM,0);
    struct ifconf ifconf;
    int i,j, nifaces;
    struct sockaddr_in *b;
    memset (&ifconf,0, sizeof(ifconf));

    ifconf.ifc_buf = (char *)(ifreqs);
    ifconf.ifc_len = sizeof(ifreqs);

    if (ioctl( sock, SIOCGIFCONF, (char *)&ifconf ) < 0)
    {
        perror( "SIOCGIFCONF" );
        return -1;
    }

    close (sock);

    nifaces = ifconf.ifc_len/sizeof(struct ifreq);

    for (i=0;i < nifaces;i++)
    {
        b = (struct sockaddr_in *)&(ifreqs[i].ifr_addr);
        if (!strncmp(ifreqs[i].ifr_name,"lo",strlen("lo")))
            continue;
        if (!strncmp(ifreqs[i].ifr_name,"dummy0",strlen("dummy0")))
            continue;
        printf("\t%-10s %x\n",ifreqs[i].ifr_name, b->sin_addr.s_addr);
        ipAddr[j++] = b->sin_addr.s_addr;
        if (j >= maxInst)
            return 0;
    }

    return 0;
}


extern void
GetAllIntf(MOC_IP_ADDRESS * ipAddr, sbyte4  maxInst)
{
    return (OnIp2MultiIntf(ipAddr, maxInst,0));
}


extern void
OnDelIP(ubyte4 m_NTEContext)
{
    UpdateIP("dummy0", 0, 0, 0);
}

#endif /* (defined(__ENABLE_DIGICERT_VPN_EXAMPLE__)) */


/*------------------------------------------------------------------*/

static sbyte4 ipsecFid = -1;

static sbyte4
IPSEC_sendIoCtl(IpsIoctlCmd_e command, void *arg)
{
    sbyte4 status;

    if (0 > ipsecFid)
    {
        ipsecFid = open("/dev/moc_ipsec", O_RDWR);
    }

    if (0 > ipsecFid)
    {
        perror("Error opening moc_ipsec");
        status = -1;
        goto exit;
    }

    status = ioctl(ipsecFid, command, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyAddEx(IPSECKEY_EX pxKey)
{
    ExtIpSecKeyEx_t keyInfo;
    sbyte4 status;

    status = IPSEC_prepareKeyAddEx(pxKey, &keyInfo);
    if (OK > status)
        goto exit;

    DBUG_PRINT(DEBUG_IKE_MESSAGES, ("Trying to add key (spdid = %x)", pxKey->dwSpdId));

    status = IPSEC_sendIoCtl(IOC_ADD_KEY_EX, &keyInfo);
    pxKey->dwSpdId = keyInfo.key.dwSpdId;
    pxKey->spdIndex = keyInfo.key.spdIndex;

    if (0 > status) goto exit;
    DBUG_PRINT(DEBUG_IKE_MESSAGES, ("Key (spdid = %x) added", pxKey->dwSpdId));

exit:
    return status;
} /* IPSEC_keyAddEx */

/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_groupKeyAdd(IPSECKEY_EX pxKey) /* Wrapper function to make windows and linux API calls generic */
{
    sbyte4 status;
    status = IPSEC_keyAddEx(pxKey);
    return status;
} /* IPSEC_groupKeyAdd */

/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyReady(IPSECKEY_EX pxKey)
{
    sbyte4 status;

#ifndef __ENABLE_DIGICERT_IPV6__
    status = IPSEC_sendIoCtl(IOC_KEY_READY, pxKey);
#else
    ExtIpSecKeyEx_t keyInfo;

    status = IPSEC_prepareKeyReady(pxKey, &keyInfo);
    if (OK > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_KEY_READY, &keyInfo);

    IPSEC_finalizeKeyReady(pxKey, &keyInfo, status);

#endif /* __ENABLE_DIGICERT_IPV6__ */

    return status;
} /* IPSEC_keyReady */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyDelete(IPSECKEY pxKey)
{
    sbyte4 status;

#ifndef __ENABLE_DIGICERT_IPV6__
    status = IPSEC_sendIoCtl(IOC_DEL_KEY, pxKey);
#else
    ExtIpSecKey_t keyInfo;

    status = IPSEC_prepareKeyDelete(pxKey, &keyInfo);
    if (OK > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_DEL_KEY, &keyInfo);
#endif

    return status;
} /* IPSEC_keyDelete */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyInitiate(IPSECKEY pxKey)
{
    sbyte4 status;

#ifndef __ENABLE_DIGICERT_IPV6__
    status = IPSEC_sendIoCtl(IOC_KEY_INIT, pxKey);
#else
    ExtIpSecKey_t keyInfo;

    status = IPSEC_prepareKeyInitiate(pxKey, &keyInfo);
    if (OK > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_KEY_INIT, &keyInfo);

    pxKey->dwSeqNo = keyInfo.key.dwSeqNo;
#endif

    return status;
} /* IPSEC_keyInitiate */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOBIKE__

extern sbyte4
IPSEC_keyUpdate(IPSECKEY pxKey)
{
    sbyte4 status;

#ifndef __ENABLE_DIGICERT_IPV6__
    status = IPSEC_sendIoCtl(IOC_KEY_UPDATE, pxKey);
#else
    ExtIpSecKey_t keyInfo;

    status = IPSEC_prepareKeyInitiate(pxKey, &keyInfo);
    if (OK > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_KEY_UPDATE, &keyInfo);
#endif

    return status;
} /* IPSEC_keyUpdate */

#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)

extern sbyte4
IPSEC_keyAdd(IPSECKEY pxKey, sbyte4 num)
{
    sbyte4 status = 0;

    sbyte4 i;
    for (i = 0; i < num; i++)
    {
        IPSECKEY pxKeyTmp = pxKey + i;

        ExtIpSecKey_t keyInfo;

        status = IPSEC_prepareKeyAdd(pxKeyTmp, &keyInfo);
        if (0 > status)
            return status;

        status = IPSEC_sendIoCtl(IOC_ADD_KEY, &keyInfo);

        if (1 > status)
        {
            if (0 > status) pxKeyTmp->status = status;
            else pxKeyTmp->status = keyInfo.key.status;
            break;
        }
    }

    if (i || (0 <= status)) /* !!! */
    {
        status = i;
    }
    return status;
} /* IPSEC_keyAdd */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyFlush(void)
{
    sbyte4 value = 0;

    return IPSEC_sendIoCtl(IOC_FLUSH_SA, &value);
} /* IPSEC_keyFlush */

#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__

extern sbyte4
IPSEC_keyGetEx(IPSECKEY_EX pxKey)
{
    ExtIpSecKeyEx_t keyInfo;

    sbyte4 status = IPSEC_prepareKeyGetEx(pxKey, &keyInfo);
    if (0 > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_GET_KEY_EX, &keyInfo);
    if (0 <= status)
    {
        sbyte *pAuthKey = (sbyte *) pxKey->poAuthKey;
        sbyte *pEncrKey = (sbyte *) pxKey->poEncrKey;

        memcpy(pxKey, &keyInfo.key, sizeof(keyInfo.key));

        pxKey->poAuthKey = (ubyte *) pAuthKey;
        pxKey->poEncrKey = (ubyte *) pEncrKey;

        if (pxKey->oAuthAlgo)
            memcpy(pAuthKey, keyInfo.authKey, pxKey->wAuthKeyLen);
        if (pxKey->oEncrAlgo)
            memcpy(pEncrKey, keyInfo.encrKey, pxKey->wEncrKeyLen);
    }
    return status;
} /* IPSEC_keyGetEx */

extern sbyte4
IPSEC_keyGet(IPSECKEY pxKey)
{
    ExtIpSecKey_t keyInfo;

    sbyte4 status = IPSEC_prepareKeyGet(pxKey, &keyInfo);
    if (0 > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_GET_KEY, &keyInfo);
    if (0 <= status)
    {
        sbyte *pAuthKey = pxKey->pAuthKey;
        sbyte *pEncrKey = pxKey->pEncrKey;

        memcpy(pxKey, &keyInfo.key, sizeof(keyInfo.key));

        pxKey->pAuthKey = pAuthKey;
        pxKey->pEncrKey = pEncrKey;

        if (pxKey->oAuthAlgo)
            memcpy(pAuthKey, keyInfo.authKey, pxKey->wAuthKeyLen);
        if (pxKey->oEncrAlgo)
            memcpy(pEncrKey, keyInfo.encrKey, pxKey->wEncrKeyLen);
    }
    return status;
} /* IPSEC_keyGet */

#endif


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confAdd1(IPSECCONF pxConf)
{
    sbyte4 status;
    ExtIpSecConf_t ioBuf;

    status = IPSEC_prepareConfAdd1(pxConf, &ioBuf);
    if (OK > status)
        return status;

    status = IPSEC_sendIoCtl(IOC_ADD_CONF, &ioBuf);

    pxConf->index = ioBuf.conf.index;

    return status;
} /* IPSEC_confAdd1 */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confFlush(void)
{
    sbyte4 value = 0;

    return IPSEC_sendIoCtl(IOC_FLUSH_SPD, &value);
} /* IPSEC_confFlush */


/*------------------------------------------------------------------*/

static sbyte4
ike_handleIpsecEvent(ExtIkeEventQ_t *eventQueue)
{
    struct ike_event event;
    sbyte4           status     = 0;
    int              eventCount = 0;

    while (OK == queue_get_head(eventQueue->msgQueue,
                                (ubyte *)&event, sizeof(event)))
    {
        DUMP_LONGS((ubyte *)&event, sizeof(event), 80, "IPSEC event");

        eventCount++;

        if (NULL == IKE_ikeSettings()->funcPtrIkeEvtSend)
        {
            ERROR_PRINT(("EVENT failed: Function \"funcPtrIkeEvtSend\" not set!"));
            status = (sbyte4)ERR_IKE_CONFIG;
        }
        else
        {
            MOC_IP_ADDRESS hostAddr;
            if (0 > (status = (sbyte4) IKE_evtGetAddr(&event, &hostAddr, NULL)))
            {
                ERROR_PRINT(("Unknown event received: %d", (int)event.type));
                continue;
            }

            status = IKE_ikeSettings()->funcPtrIkeEvtSend((ubyte *)&event,
                                        sizeof(event), hostAddr
                                        MOC_COOKIE_REQ_VALUE(event.cookie));
        }
    }

    DBUG_PRINT(DEBUG_IKE_MESSAGES,("%d events processed", eventCount));
    return status;
}


/*------------------------------------------------------------------*/

static ExtIkeEventQ_t ikeQueue = {0};

static void
sigHandler(int signo)
{
    static int isRunning = 0;

    if (isRunning)
        return;
    isRunning = 1;
    ike_handleIpsecEvent(&ikeQueue);
    isRunning = 0;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSECKEY_EXAMPLE_main(void)
{
    memPartDescr   *pMemPartition = NULL;
    CircBuffer_t   *msgQueue      = NULL;
    int            size           = sizeof(struct ike_event)*MAX_GROUP_NEGOTIATION + 1024;
    sbyte4         status         = 0;
    ExtIkeEventQIoctl_t eventQueue;

    if (0 > (status = (sbyte4) KMEM_PART_createPartition(&pMemPartition, size)))
    {
        ERROR_PRINT(("KMEM_PART_createPartition() failed: %d", status));
        goto exit;
    }
    if (NULL == (msgQueue = queue_create(pMemPartition, MAX_GROUP_NEGOTIATION,
                              sizeof(struct ike_event))))
    {
        status = -1;
        goto exit;
    }

    DIGI_MEMSET((void *)&eventQueue, 0, sizeof(eventQueue));
    eventQueue.tid      = getpid();
    eventQueue.signal   = IPS2IKE_SIGNAL;

    /* When send to kernel, map to kernel address 1st */
    if (0 > (status = (sbyte4) MEM_PART_mapToKernelAddress(pMemPartition,
                        (void *)msgQueue, (ubyte8 *)&eventQueue.msgQueue)))
    {
        ERROR_PRINT(("MEM_PART_mapToKernelAddress() failed: %d", status));
        goto exit;
    }

    /* Save to operation parameters */
    ikeQueue.tid      = getpid();
    ikeQueue.signal   = IPS2IKE_SIGNAL;
    ikeQueue.msgQueue = msgQueue;

    /* Arm my handler */
    if (SIG_ERR == signal(IPS2IKE_SIGNAL, sigHandler))
    {
        status = -1;
        goto exit;
    }

    /* Notify IPSEC to start using it */
    status = IPSEC_sendIoCtl(IOC_REGISTER_IKE_EVENTQ, (void *)&eventQueue);

exit:
    if (0 > status)
    {
        if (msgQueue)
        {
            if (pMemPartition)
                queue_delete(pMemPartition, msgQueue);
            msgQueue = NULL;
        }

        if (pMemPartition)
        {
            MEM_PART_freePartition(&pMemPartition);
            pMemPartition = NULL;
        }
    }

    return status;
} /* IPSECKEY_EXAMPLE_main */

#endif /* __ENABLE_DIGICERT_MISSIU__ */

#endif
#endif /* (defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) && defined(__ENABLE_DIGICERT_EXAMPLES__)) */
#endif

