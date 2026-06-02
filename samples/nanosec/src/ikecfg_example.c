/*
 * ikecfg_example.c
 *
 * Sample implementation of IKECFG handlers
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__

#if defined(__ENABLE_IKE_XAUTH__) || defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)

#include <string.h>
#include <stdio.h>
#if defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
  #define WIN32_LEAN_AND_MEAN
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0400
  #endif

  #include <windows.h>
  #include <winsock2.h>
  #include <Ws2tcpip.h>
  #include <iphlpapi.h>
#endif
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/otp.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/spd.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_utils.h"
#include "../ike/ikesa.h"

#if ((defined(__RTOS_WINCE__) || defined(__RTOS_WIN32__) || defined(__RTOS_LINUX__)) && defined(__ENABLE_DIGICERT_VPN_EXAMPLE__))
#include "ikeConfig.h"
#include "paragon/ui/dialog_interface.h"

#ifndef __PARAGON__
#define __PARAGON__
#endif
#else
#ifdef __PARAGON__
#undef __PARAGON__
#endif
#endif


/*------------------------------------------------------------------*/
/* XAUTH Client [v1]                                                */
/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_XAUTH__

sbyte *m_XuserName = (sbyte *)"root";
sbyte *m_Xpassword = (sbyte *)"mocana";


/*------------------------------------------------------------------*/

static sbyte4
IKECFG_SAMPLE_InteractWithUser(void* xauthTrans,
                               sbyte** userName, sbyte** password,
                               sbyte** passCode, sbyte** nextPin, sbyte** answer,
                               const sbyte* message, const sbyte* domain,
                               XAUTH_userCallbackFun userCallback,
                               sbyte4 serverInstance)
{
    sbyte4 status = OK;

    MOC_UNUSED(xauthTrans);
    MOC_UNUSED(passCode);
    MOC_UNUSED(nextPin);
    MOC_UNUSED(answer);
    MOC_UNUSED(userCallback);
    MOC_UNUSED(serverInstance);

    if (message)
    {
        printf("XAUTH:%s %s\n", (domain ? domain : (const sbyte *)""), message);
    }

    /* Note: To respond asynchronously, return STATUS_IKE_PENDING here
       and invoke 'userCallback' function at a later time. */

    if (userName && *userName) *userName = m_XuserName;
    if (password && *password) *password = m_Xpassword;

    return status;
} /* IKECFG_SAMPLE_InteractWithUser */


/*------------------------------------------------------------------*/

static sbyte4
IKECFG_SAMPLE_InteractWithAAA(void* xauthTrans, ubyte2 cfgId,
                              sbyte** userName,
                              sbyte** password, ubyte2 passwordLen,
                              sbyte** passCode, sbyte** nextPin,
                              sbyte* answer, sbyte** message, sbyte** domain,
                              sbyte **challenge, ubyte2 *challengeLen,
                              ubyte *cfgType, ubyte2 *authTypeOrStatus,
                              XAUTH_aaaCallbackFun aaaCallback,
                              sbyte4 serverInstance)
{
    sbyte4 status = OK;

#ifdef __ENABLE_DIGICERT_OTP__
    static char otp_seed[16];
    static ubyte4 otp_count = 0;
    static char otp_challenge[32];
    static ubyte4 otp_sequence = 0;
    static ubyte otp_res[OTP_RESULT_SIZE];
#endif

    /* Transaction Identifier MUST be the same for all messages in an XAUTH transaction */
    MOC_UNUSED(cfgId);
    MOC_UNUSED(xauthTrans);
    MOC_UNUSED(serverInstance);

    /* initiate XAUTH transaction */
    if (NULL == aaaCallback) /* !!! */
    {
        // <-- REQUEST(NAME="" PASSWORD="")
        *cfgType = CFG_REQUEST;
        *authTypeOrStatus = XAUTH_TYPE_OPTIONAL;
        *userName = (sbyte *)"";
        *password = (sbyte *)"";
        goto exit; /* !!! */
    }

    /* handle REPLY from the client */
    if (answer)
    {
        printf("XAUTH: %s\n", answer);
    }

    /* Note: To respond asynchronously, return STATUS_IKE_PENDING here
       and invoke 'aaaCallback' function at a later time. */

    if (*userName && !strcmp((const char *)*userName, (const char *)m_XuserName) &&
        *password && !strcmp((const char *)*password, (const char *)m_Xpassword))
    {
        goto success;
    }

    // <-- SET(STATUS=FAIL)
    *cfgType = CFG_SET;
    *authTypeOrStatus = XAUTH_STATUS_FAIL;
    goto done;

success:
    // <-- SET(STATUS=OK)
    *cfgType = CFG_SET;
    *authTypeOrStatus = XAUTH_STATUS_OK;

done:
    /* MUST set all other attributes to NULL !!! */
    *userName   = (sbyte *)NULL;
    *password   = (sbyte *)NULL;
    *passCode   = (sbyte *)NULL;
    *nextPin    = (sbyte *)NULL;
    *message    = (sbyte *)NULL;
    *domain     = (sbyte *)NULL;
    *challenge  = (sbyte *)NULL;
    *challengeLen = 0;

exit:
    return status;
} /* IKECFG_SAMPLE_InteractWithAAA */

#endif /* __ENABLE_IKE_XAUTH__ */


#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)

/*------------------------------------------------------------------*/
/* MODE-CFG [v1] of CP [v2]                                         */
/*------------------------------------------------------------------*/

extern void     IKE_EXAMPLE_sprintIpAddr(char *addr, int len, MOC_IP_ADDRESS ipAddr);
extern sbyte4   IKE_SAMPLE_ikeGetHostAddr(MOC_IP_ADDRESS_S *pHostAddr, sbyte4 serverInstance);

sbyte4      m_vpnAgent  = 0;    /* 1=client, 2=server, o/w none */

#ifdef __ENABLE_IKE_MODE_CFG__
/*
    PULL: Client initiates "Request/Response" transaction (or Quick Mode)
    PUSH: Server initiates "Set/Ack" transaction (or Quick Mode)
 */
intBoolean  m_bPullCfg  = TRUE; /* TRUE (PULL) or FALSE (PUSH) */
intBoolean  m_bInitQM   = TRUE;
#endif

#ifdef __PARAGON__
extern sbyte4 m_IfIndex;
#ifdef __RTOS_LINUX__
extern sbyte4 OnAddIP(sbyte4 IfIndex, MOC_IP_ADDRESS Address, MOC_IP_ADDRESS IpMask, sbyte* m_NTEContext, MOC_IP_ADDRESS DNSAddr );
extern sbyte4 Add_Route( sbyte4 destination, sbyte4 gateway, MOC_IP_ADDRESS mask, sbyte4 direct );

sbyte4       m_NTEContext = 0;

#else
extern DWORD OnAddIP(DWORD IfIndex, IPAddr Address, IPMask IpMask, PULONG m_NTEContext, IPAddr DNSAddr );
extern DWORD Add_Route( DWORD destination, DWORD gateway, DWORD mask, DWORD direct );

ULONG       m_NTEContext = 0;
#endif
#endif


/*------------------------------------------------------------------*/

static MSTATUS
UpdatePolicy(MOC_IP_ADDRESS localAddr,
             MOC_IP_ADDRESS hostAddr,
             MOC_IP_ADDRESS peerAddr,
             ubyte4 dwIkeId, intBoolean bInitQM)
{
    MSTATUS status;

    struct ipsecConf conf = { 0 };

    struct sainfo saInfo = { IPSEC_PROTO_ESP_AUTH }; /* for now */
    conf.pxSa = &saInfo;
    conf.oSaLen = 1;

    TEST_MOC_IPADDR6(localAddr,
    {
        conf.flags |= IPSEC_SP_FLAG_IP6;
        if (1 == m_vpnAgent) /* client */
            conf.dwSrcIP = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(localAddr);
        else /* server */
            conf.dwDestIP = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(localAddr);
    })
    {
        if (1 == m_vpnAgent) /* client */
            conf.dwSrcIP = GET_MOC_IPADDR4(localAddr);
        else /* server */
            conf.dwDestIP = GET_MOC_IPADDR4(localAddr);
    }

    conf.oAction = IPSEC_ACTION_APPLY;
    conf.oDir = IPSEC_DIR_MIRRORED;

    conf.oMode = IPSEC_MODE_TUNNEL;

    TEST_MOC_IPADDR6(hostAddr,
    {
        conf.flags |= IPSEC_SP_FLAG_IP6_TUNNEL;
        conf.dwTunlSrcIP = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(hostAddr);
        conf.dwTunlDestIP = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(peerAddr);
    })
    {
        conf.dwTunlSrcIP = GET_MOC_IPADDR4(hostAddr);
        conf.dwTunlDestIP = GET_MOC_IPADDR4(peerAddr);
    }

    conf.dwIkeSaId = dwIkeId;

    if (bInitQM) conf.flags |= IPSEC_SP_FLAG_INIT;

    IPSEC_confFlush();

    status = IPSEC_confAdd1(&conf);

#if defined(__ENABLE_ALL_DEBUGGING__)
    {
        char *pol_fmt = "{ %s %s } ipsec { encr_algs any encr_auth_algs any tladdr %s traddr %s %s}";
#ifdef __ENABLE_DIGICERT_IPV6__
        #define ADDR_LEN 48
#else
        #define ADDR_LEN 16
#endif
        char laddr[ADDR_LEN]="", tladdr[ADDR_LEN]="", traddr[ADDR_LEN]="";
        char policy[256];

        IKE_EXAMPLE_sprintIpAddr(laddr, ADDR_LEN-1, localAddr);
        IKE_EXAMPLE_sprintIpAddr(tladdr, ADDR_LEN-1, hostAddr);
        IKE_EXAMPLE_sprintIpAddr(traddr, ADDR_LEN-1, peerAddr);
        sprintf(policy, pol_fmt, ((1==m_vpnAgent) ? "laddr" : "raddr"),
                laddr, tladdr, traddr, (bInitQM ? "sa init " : ""));

        DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKECFG_EXAMPLE: Add IPsec policy, status = ");
        DEBUG_INT(DEBUG_IKE_EXAMPLE, status);
        DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)", policy = ");
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)policy);
    }
#endif

    return status;
} /* UpdatePolicy */


/*------------------------------------------------------------------*/

#define ipv4_addr(a,b,c,d) ((a<<24)+(b<<16)+(c<<8)+d)

static ubyte clientAttrs[] =
{
    0x00, APPLICATION_VERSION,  0x00, 0x00,
    0x00, SUPPORTED_ATTRIBUTES, 0x00, 0x00,

    0x00, INTERNAL_IP4_ADDRESS, 0x00, 0x00,
    0x00, INTERNAL_IP4_DNS,     0x00, 0x00,
    0x00, INTERNAL_IP4_NETMASK, 0x00, 0x00,
    0x00, INTERNAL_IP4_SUBNET,  0x00, 0x00
};

/* Note:
     INTERNAL_IP6_ADDRESS must be 16 in MODE-CFG [v1] and 17 in CP [v2].
     INTERNAL_IP6_NETMASK is only supported in MODE-CFG [v1].
     INTERNAL_IP6_SUBNET with 0 length is prohibited in CP [v2].
*/

#ifdef __ENABLE_DIGICERT_IPV6__
static ubyte clientAttrs6[] =
{
    0x00, APPLICATION_VERSION,  0x00, 0x00,
    0x00, SUPPORTED_ATTRIBUTES, 0x00, 0x00,

    0x00, INTERNAL_IP6_ADDRESS, 0x00, 0x00,
    0x00, INTERNAL_IP6_DNS,     0x00, 0x00,

    0x00, INTERNAL_IP6_NETMASK, 0x00, 0x00, /* [v1] */
    0x00, INTERNAL_IP6_SUBNET,  0x00, 0x00  /* [v1] */
};

#define SIZEOF_CLIENT_ATTRS6    sizeof(clientAttrs6)
#define SIZEOF_CLIENT_ATTRS6_2  (sizeof(clientAttrs6) - 8)
#endif

static ubyte serverAttrs[] =
{
    0x00, INTERNAL_IP4_ADDRESS, 0x00, 0x04,
    0x0a, 0x08, 0x0a, 0x8f,     /* assign client�s private IP address here */
                                /* and its network mask (see below) */
    0x00, INTERNAL_IP4_NETMASK, 0x00, 0x04,
    0xff, 0xff, 0xff, 0x00,

    0x00, INTERNAL_IP4_SUBNET,  0x00, 0x08,
    0x0b, 0x0a, 0x00, 0x00,     /* protected sub-network's starting IP address */
    0xff, 0xff, 0x00, 0x00      /* and its netmask */
};

#ifdef __ENABLE_DIGICERT_IPV6__
static ubyte serverAttrs6[] =
{
    0x00, INTERNAL_IP6_ADDRESS, 0x00, 0x10,
    0x0a, 0x08, 0x0a, 0x8f, 0x0a, 0x08, 0x0a, 0x8f, 0x0a, 0x08, 0x0a, 0x8f, 0x0a, 0x08, 0x0a, 0x8f,

    0x00, INTERNAL_IP6_NETMASK, 0x00, 0x10, /* [v1] */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00,

    0x00, INTERNAL_IP6_SUBNET,  0x00, 0x11,
    0x0b, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, 0x02, 0x03, 0x04, 0x00, 0x00,
    112 /* protected sub-network prefix */
};

static ubyte serverAttrs6_2[] =
{
    0x00, INTERNAL_IP6_ADDRESS, 0x00, 0x11,
    0x0a, 0x08, 0x0a, 0x8f, 0x0a, 0x08, 0x0a, 0x8f, 0x0a, 0x08, 0x0a, 0x8f, 0x0a, 0x08, 0x0a, 0x8f,
    112, /* [v2] prefix */

    0x00, INTERNAL_IP6_SUBNET,  0x00, 0x11,
    0x0b, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, 0x02, 0x03, 0x04, 0x00, 0x00,
    112 /* protected sub-network prefix */
};
#endif

#define IKE_MAX_SUBNET 10

#ifdef __ENABLE_IKE_MODE_CFG__

/*------------------------------------------------------------------*/
typedef struct putattrs_cb
{
    ubyte2 flags;
    sbyte4 count;
    ubyte4 dwExpSecs;
    MOC_IP_ADDRESS_S localAddr;
    MOC_IP_ADDRESS_S dnsAddr;
    MOC_IP_ADDRESS_S netMask;
    MOC_IP_ADDRESS_S subnet[IKE_MAX_SUBNET];
    MOC_IP_ADDRESS_S subnetMask[IKE_MAX_SUBNET];
    ubyte2 ikeSubnetCount;

} *putattrs_cb;


static struct ikeCfgAttrHdr m_ackAttrs[32] = { {0} };

static MSTATUS
DoPutAttrs(void* cb_,
           ubyte2 wType, intBoolean bBasic,
           ubyte2 wLen, const ubyte *poAttr)
{
    MSTATUS status = OK;
    putattrs_cb cb = (putattrs_cb)(cb_);

    ubyte2 flags = cb->flags;

    /* ckeck valid length */
    ubyte2 wLenMin = 0;
    switch (wType)
    {
    case INTERNAL_ADDRESS_EXPIRY :  /* 4 */
    case INTERNAL_IP4_ADDRESS :
    case INTERNAL_IP4_DNS :
    case INTERNAL_IP4_NETMASK :
        wLenMin = 4;
        break;
    case INTERNAL_IP4_SUBNET :      /* 8 */
        wLenMin = 8;
        break;
#ifdef __ENABLE_DIGICERT_IPV6__
    case INTERNAL_IP6_ADDRESS :     /* 16 [v1] or 17 [v2] */
        /* [v1] only - fall through! */
    case INTERNAL_IP6_DNS :         /* 16 */
    case INTERNAL_IP6_NETMASK :     /* 16 [v1] */
        wLenMin = 16;
        break;
    case INTERNAL_IP6_SUBNET :      /* 17 */
        wLenMin = 17;
        break;
#else
    case INTERNAL_IP6_ADDRESS :
    case INTERNAL_IP6_DNS :
    case INTERNAL_IP6_NETMASK :
    case INTERNAL_IP6_SUBNET :
    /*case INTERNAL_IP6_NBNS :*//* removed [RFC5996] */
    case INTERNAL_IP6_DHCP :
#endif
    case APPLICATION_VERSION :
    case SUPPORTED_ATTRIBUTES :
        goto exit;
        break;
    default :
        goto next;
        break;
    }

    if (wLen < wLenMin)
    {
        status = ERR_IKE_BAD_ATTR;
        goto exit;
    }

next:
    /* check family consistency */
#ifdef __ENABLE_DIGICERT_IPV6__
    switch (wType)
    {
    case INTERNAL_IP4_ADDRESS :
    case INTERNAL_IP4_NETMASK :
    case INTERNAL_IP4_SUBNET :
        if (((1 << INTERNAL_IP6_ADDRESS) & flags) ||
            ((1 << INTERNAL_IP6_NETMASK) & flags) ||
            ((1 << INTERNAL_IP6_SUBNET) & flags))
        {
            /* only accept 1 family - for now */
            goto exit;
        }
        break;
    case INTERNAL_IP6_ADDRESS :
    case INTERNAL_IP6_NETMASK :
    case INTERNAL_IP6_SUBNET :
        if (((1 << INTERNAL_IP4_ADDRESS) & flags) ||
            ((1 << INTERNAL_IP4_NETMASK) & flags) ||
            ((1 << INTERNAL_IP4_SUBNET) & flags))
        {
            /* only accept 1 family - for now */
            goto exit;
        }
        break;
    default :
        break;
    }
#endif

    /* get info on address(es) */
    switch (wType)
    {
    case INTERNAL_ADDRESS_EXPIRY :
        cb->dwExpSecs = DIGI_NTOHL(poAttr);
        break;
    case INTERNAL_IP4_ADDRESS :
        if ((1 << INTERNAL_IP4_ADDRESS) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR4(cb->localAddr, DIGI_NTOHL(poAttr));
        break;
    case INTERNAL_IP4_NETMASK :
        if ((1 << INTERNAL_IP4_NETMASK) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR4(cb->netMask, DIGI_NTOHL(poAttr));
        break;
    case INTERNAL_IP4_DNS :
        if ((1 << INTERNAL_IP4_DNS) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR4(cb->dnsAddr, DIGI_NTOHL(poAttr));
        break;
    case INTERNAL_IP4_SUBNET :
        if (IKE_MAX_SUBNET <= cb->ikeSubnetCount)
        {
            break;
        }
        SET_MOC_IPADDR4(cb->subnet[cb->ikeSubnetCount], DIGI_NTOHL(poAttr));
        SET_MOC_IPADDR4(cb->subnetMask[cb->ikeSubnetCount++], DIGI_NTOHL(poAttr + 4));
        break;
#ifdef __ENABLE_DIGICERT_IPV6__
    case INTERNAL_IP6_ADDRESS :
        if ((1 << INTERNAL_IP6_ADDRESS) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR6(cb->localAddr, poAttr);
        break;
#endif
    default :
        break;
    }

    if (16 > wType) /* !!! */
        cb->flags |= (1 << wType);

    SET_HTONS(m_ackAttrs[cb->count++].wType,
              (bBasic ? (0x8000 | wType) : wType));

exit:
    return status;
} /* DoPutAttrs */


/*------------------------------------------------------------------*/
/* (-> Set) client */

static sbyte4
IKECFG_SAMPLE_putAttrs(ubyte **ppoAck, ubyte2 *pwAckLen,
                       ubyte *poSet, ubyte2 wSetLen,                /* Config. Attrs. (i.e. ATTR SET body) */
                       ubyte *poId, ubyte2 wIdLen, sbyte4 idType,   /* peer ID; see IKE_ID_T in "ike_defs.h" */
                       MOC_IP_ADDRESS peerAddr,
                       sbyte4 serverInstance,
                       void *data)
{
    MSTATUS status = ERR_IKE_CONFIG;

    IKESA pxSa = (IKESA)data;

    MOC_UNUSED(poId);
    MOC_UNUSED(wIdLen);
    MOC_UNUSED(idType);

    *ppoAck = NULL;
    *pwAckLen = 0;

    /* (<- Ack) client */
    if (1 == m_vpnAgent)
    {
        struct putattrs_cb cb = { 0 };

        if (OK > (status = IKE_travAttrs(poSet, wSetLen, &cb, DoPutAttrs)))
            goto exit;

        *pwAckLen = (ubyte2)(4 * cb.count);
        *ppoAck = (ubyte *)m_ackAttrs;

        if (((1 << INTERNAL_IP4_ADDRESS) & cb.flags)
#ifdef __ENABLE_DIGICERT_IPV6__
         || ((1 << INTERNAL_IP6_ADDRESS) & cb.flags)
#endif
            )
        {
            MOC_IP_ADDRESS_S hostAddr;
            if (OK > (status = IKE_SAMPLE_ikeGetHostAddr(&hostAddr, serverInstance)))
                goto exit;

            IPSEC_confFlush();
#ifdef __PARAGON__
            {
#ifdef __RTOS_LINUX__
                MOC_IP_ADDRESS IpMask = inet_addr("255.255.255.0");
                MOC_IP_ADDRESS Address = REF_MOC_IPADDR(cb.localAddr);
                MOC_IP_ADDRESS DNSAddr = REF_MOC_IPADDR(cb.dnsAddr);
#else
                IPMask IpMask = inet_addr("255.255.255.0");
                IPAddr Address = REF_MOC_IPADDR(cb.localAddr);
                IPAddr DNSAddr = REF_MOC_IPADDR(cb.dnsAddr);
#endif
                ubyte  i = 0;

                if (cb.netMask)
                {
                    IpMask = REF_MOC_IPADDR(cb.netMask);
                    IpMask = htonl(IpMask);
                }
                if (0 <= m_IfIndex)
                {
                    status = OnAddIP(m_IfIndex, htonl(Address), IpMask, &m_NTEContext, htonl(DNSAddr) );
                    DEBUG_PRINT(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: Add IP Address :Status ");
                    DEBUG_INT(DEBUG_COMMON, status);

                    MVC_DIALOG_sendEvent(MVC_IP_CONFIGURED, (void *)&(cb.localAddr));

                    for (i = 0; i < cb.ikeSubnetCount; i++)
                        Add_Route(htonl(cb.subnet[i]), htonl(Address), htonl(cb.subnetMask[i]), 1) ;
                }
            }
#endif
            /* update IPsec policy */
            status = UpdatePolicy(REF_MOC_IPADDR(cb.localAddr),
                                  REF_MOC_IPADDR(hostAddr),
                                  peerAddr, pxSa->dwId, m_bInitQM);
        }
    }

exit:
    return (sbyte4)status;
} /* IKECFG_SAMPLE_putAttrs */

#endif /* __ENABLE_IKE_MODE_CFG__ */


/*------------------------------------------------------------------*/
/* (-> Request) server */

static sbyte4
IKECFG_SAMPLE_getAttrs(ubyte **ppoResp, ubyte2 *pwRespLen,
                       ubyte *poReq, ubyte2 wReqLen,                /* Config. Attrs. (i.e. ATTR REQUEST body) */
                       ubyte *poId, ubyte2 wIdLen, sbyte4 idType,   /* peer ID (e.g. [v2] IDi); see IKE_ID_T in "ike_defs.h" */
                       ubyte *identity, ubyte4 id_len,              /* [v2] EAP identity or [v1] XAUTH client username (TBD) */
                       MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                       sbyte4 serverInstance,
                       void *data)
{
    MSTATUS status = ERR_IKE_CONFIG;

    IKESA pxSa = (IKESA)data;
    intBoolean bIke2 = IS_IKE2_SA(pxSa);

    MOC_IP_ADDRESS_S remoteAddr;

    MOC_UNUSED(poId);
    MOC_UNUSED(wIdLen);
    MOC_UNUSED(idType);
    MOC_UNUSED(identity);
    MOC_UNUSED(id_len);
    MOC_UNUSED(peerAddr);
    MOC_UNUSED(wPeerPort);
    MOC_UNUSED(serverInstance);

    *ppoResp = NULL;
    *pwRespLen = 0;

    /* (<- Response) server */
    if (2 == m_vpnAgent)
    {
        /* put your custom code here */
        MOC_UNUSED(poReq);
        MOC_UNUSED(wReqLen);

#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == peerAddr->family)
        {
            if (bIke2)
            {
                *ppoResp = serverAttrs6_2;
                *pwRespLen = sizeof(serverAttrs6_2);
                SET_MOC_IPADDR6(remoteAddr, &serverAttrs6_2[4]);
            }
            else
            {
                *ppoResp = serverAttrs6;
                *pwRespLen = sizeof(serverAttrs6);
                SET_MOC_IPADDR6(remoteAddr, &serverAttrs6[4]);
            }
        }
        else
#endif
        {
            *ppoResp = serverAttrs;
            *pwRespLen = sizeof(serverAttrs);

            SET_MOC_IPADDR4(remoteAddr, ipv4_addr(10, 8, 10, 143));
        }

        /* update IPsec policy */
        status = UpdatePolicy(REF_MOC_IPADDR(remoteAddr),
                              REF_MOC_IPADDR(pxSa->dwHostAddr),
                              peerAddr, pxSa->dwId,
#ifdef __ENABLE_IKE_MODE_CFG__
                              (m_bInitQM && !bIke2) ? TRUE :
#endif
                              FALSE);
    }

    return (sbyte4)status;
} /* IKECFG_SAMPLE_getAttrs */


/*------------------------------------------------------------------*/
/* PULL/PUSH initiator */

static sbyte4
IKECFG_SAMPLE_initAttrs(ubyte **ppoAttrs_I, ubyte2 *pwAttrsLen_I,   /* [output] Config. Attrs. (ATTR body) */
                        ubyte *poCfgType,                           /* [output]             REQUEST or SET */
                        ubyte2 wCfgId,                              /* transaction identifier */
                        ubyte4 dwIkeId, void *data)
{
    MSTATUS status = ERR_IKE_CONFIG;

    IKESA pxSa = (IKESA)data;
    intBoolean bIke2 = IS_IKE2_SA(pxSa);

    MOC_UNUSED(wCfgId);
    MOC_UNUSED(dwIkeId);

    /* client PULL (Request ->) */
    if ((1 == m_vpnAgent)
#ifdef __ENABLE_IKE_MODE_CFG__
        && (bIke2 || m_bPullCfg)
#endif
        )
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == pxSa->dwPeerAddr.family)
        {
            *ppoAttrs_I = clientAttrs6;
            *pwAttrsLen_I = bIke2 ? SIZEOF_CLIENT_ATTRS6_2 :
                            SIZEOF_CLIENT_ATTRS6;
        }
        else
#endif
        {
            *ppoAttrs_I = clientAttrs;
            *pwAttrsLen_I = sizeof(clientAttrs);
        }

        *poCfgType = CFG_REQUEST;
        status = OK;
    }

    /* server PUSH (Set ->) */
    else if ((2 == m_vpnAgent) &&
#ifdef __ENABLE_IKE_MODE_CFG__
             !m_bPullCfg &&
#endif
             !bIke2) /* !!! */
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == pxSa->dwPeerAddr.family)
        {
            *ppoAttrs_I = serverAttrs6;
            *pwAttrsLen_I = sizeof(serverAttrs6);
        }
        else
#endif
        {
            *ppoAttrs_I = serverAttrs;
            *pwAttrsLen_I = sizeof(serverAttrs);
        }

        *poCfgType = CFG_SET;
        status = OK;
    }

    return (sbyte4)status;
} /* IKECFG_SAMPLE_initAttrs */


/*------------------------------------------------------------------*/

typedef struct respattrs_cb
{
    ubyte2 flags;
    IKESA  pxSa;
    ubyte4 dwExpSecs;
    MOC_IP_ADDRESS_S localAddr;
    MOC_IP_ADDRESS_S dnsAddr;
    MOC_IP_ADDRESS_S netMask;
    MOC_IP_ADDRESS_S subnet[IKE_MAX_SUBNET];
    MOC_IP_ADDRESS_S subnetMask[IKE_MAX_SUBNET];
    ubyte2 ikeSubnetCount;

} *respattrs_cb;


static MSTATUS
DoRespAttrs(void* cb_,
            ubyte2 wType, intBoolean bBasic,
            ubyte2 wLen, const ubyte *poAttr)
{
    MSTATUS status = OK;
    respattrs_cb cb = (respattrs_cb)(cb_);

    ubyte2 flags = cb->flags;

    /* ckeck valid length */
    ubyte2 wLenMin = 0;
    switch (wType)
    {
    case INTERNAL_ADDRESS_EXPIRY :  /* 4 */
    case INTERNAL_IP4_ADDRESS :
    case INTERNAL_IP4_DNS :
    case INTERNAL_IP4_NETMASK :
        wLenMin = 4;
        break;
    case INTERNAL_IP4_SUBNET :      /* 8 */
        wLenMin = 8;
        break;
#ifdef __ENABLE_DIGICERT_IPV6__
    case INTERNAL_IP6_ADDRESS :     /* 16 [v1] or 17 [v2] */
        if (IS_IKE2_SA(cb->pxSa))
        {
            wLenMin = 17;
            break;
        }
    case INTERNAL_IP6_DNS :         /* 16 */
    case INTERNAL_IP6_NETMASK :     /* 16 [v1] */
        wLenMin = 16;
        break;
    case INTERNAL_IP6_SUBNET :      /* 17 */
        wLenMin = 17;
        break;
#endif
/*  case APPLICATION_VERSION :
    case SUPPORTED_ATTRIBUTES : */
    default :                       /* skip */
        goto exit;
        break;
    }

    if (wLen < wLenMin)
    {
        status = ERR_IKE_BAD_ATTR;
        goto exit;
    }

    /* check family consistency */
#ifdef __ENABLE_DIGICERT_IPV6__
    switch (wType)
    {
    case INTERNAL_IP4_ADDRESS :
    case INTERNAL_IP4_NETMASK :
    case INTERNAL_IP4_SUBNET :
        if (((1 << INTERNAL_IP6_ADDRESS) & flags) ||
            ((1 << INTERNAL_IP6_NETMASK) & flags) ||
            ((1 << INTERNAL_IP6_SUBNET) & flags))
        {
            /* only accept 1 family - for now */
            goto exit;
        }
        break;
    case INTERNAL_IP6_ADDRESS :
    case INTERNAL_IP6_NETMASK :
    case INTERNAL_IP6_SUBNET :
        if (((1 << INTERNAL_IP4_ADDRESS) & flags) ||
            ((1 << INTERNAL_IP4_NETMASK) & flags) ||
            ((1 << INTERNAL_IP4_SUBNET) & flags))
        {
            /* only accept 1 family - for now */
            goto exit;
        }
        break;
    default :
        break;
    }
#endif

    /* get info on address(es) */
    switch (wType)
    {
    case INTERNAL_ADDRESS_EXPIRY :
        cb->dwExpSecs = DIGI_NTOHL(poAttr);
        break;
    case INTERNAL_IP4_ADDRESS :
        if ((1 << INTERNAL_IP4_ADDRESS) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR4(cb->localAddr, DIGI_NTOHL(poAttr));
        break;
    case INTERNAL_IP4_NETMASK :
        if ((1 << INTERNAL_IP4_NETMASK) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR4(cb->netMask, DIGI_NTOHL(poAttr));
        break;
    case INTERNAL_IP4_DNS :
        if ((1 << INTERNAL_IP4_DNS) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR4(cb->dnsAddr, DIGI_NTOHL(poAttr));
        break;
    case INTERNAL_IP4_SUBNET :
        if (IKE_MAX_SUBNET <= cb->ikeSubnetCount)
        {
            break;
        }
        SET_MOC_IPADDR4(cb->subnet[cb->ikeSubnetCount], DIGI_NTOHL(poAttr));
        SET_MOC_IPADDR4(cb->subnetMask[cb->ikeSubnetCount++], DIGI_NTOHL(poAttr + 4));
        break;
#ifdef __ENABLE_DIGICERT_IPV6__
    case INTERNAL_IP6_ADDRESS :
        if ((1 << INTERNAL_IP6_ADDRESS) & flags)
        {
            /* only accept 1 private address - for now */
            goto exit;
        }
        SET_MOC_IPADDR6(cb->localAddr, poAttr);
        break;
#endif
    default :
        break;
    }

    cb->flags |= (1 << wType);

    MOC_UNUSED(bBasic);

exit:
    return status;
} /* DoRespAttrs */


/*------------------------------------------------------------------*/

static sbyte4
IKECFG_SAMPLE_respAttrs(const ubyte *poAttrs_R, ubyte2 wAttrsLen_R, /* Config. Attrs. (ATTR RESPONSE or ACK body) */
                        ubyte2 wCfgId,                              /* transaction identifier */
                        ubyte4 dwIkeId, void *data)
{
    MSTATUS status = OK;

    IKESA pxSa = (IKESA)data;
    intBoolean bIke2 = IS_IKE2_SA(pxSa);

    MOC_UNUSED(wCfgId);
    MOC_UNUSED(dwIkeId);

    /* client PULL (Response <-) */
    if ((1 == m_vpnAgent)
#ifdef __ENABLE_IKE_MODE_CFG__
        && (bIke2 || m_bPullCfg)
#endif
        )
    {
        struct respattrs_cb cb = { 0 };
        cb.pxSa = pxSa;

        if (OK > (status = IKE_travAttrs(poAttrs_R, wAttrsLen_R, &cb, DoRespAttrs)))
            goto exit;

        if (((1 << INTERNAL_IP4_ADDRESS) & cb.flags)
#ifdef __ENABLE_DIGICERT_IPV6__
         || ((1 << INTERNAL_IP6_ADDRESS) & cb.flags)
#endif
            )
        {
#ifdef __PARAGON__
#ifdef __RTOS_LINUX__
            MOC_IP_ADDRESS IpMask = inet_addr("255.255.255.0");
            MOC_IP_ADDRESS Address = REF_MOC_IPADDR(cb.localAddr);
            MOC_IP_ADDRESS DNSAddr = REF_MOC_IPADDR(cb.dnsAddr);
#else
            IPMask IpMask = inet_addr("255.255.255.0");
            IPAddr Address = REF_MOC_IPADDR(cb.localAddr);
            IPAddr DNSAddr = REF_MOC_IPADDR(cb.dnsAddr);
#endif
            ubyte2 i = 0;
            if (bIke2)
                MVC_DIALOG_sendEvent(MVC_IKE_SA_DONE, NULL);
            MVC_DIALOG_sendEvent(MVC_IP_CONFIGURED, (void *)&(cb.localAddr));

            if (cb.netMask)
            {
                IpMask = REF_MOC_IPADDR(cb.netMask);
                IpMask = htonl(IpMask);
            }
            if (0 <= m_IfIndex)
            {
                status = OnAddIP(m_IfIndex, htonl(Address), IpMask, &m_NTEContext, htonl(DNSAddr) );
                DEBUG_PRINT(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: Add IP Address :Status ");
                DEBUG_INT(DEBUG_COMMON, status);

                for (i = 0; i < cb.ikeSubnetCount; i++)
                    Add_Route(htonl(cb.subnet[i]), htonl(Address), htonl(cb.subnetMask[i]),1) ;
            }
#endif
            /* update IPsec policy */
            status = UpdatePolicy(REF_MOC_IPADDR(cb.localAddr),
                                  REF_MOC_IPADDR(pxSa->dwHostAddr),
                                  REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                  dwIkeId,

#ifdef __ENABLE_IKE_MODE_CFG__
                                  (m_bInitQM && !bIke2) ? TRUE :
#endif
                                  FALSE);
        }
        else
        {
            status = ERR_IKE_CONFIG;
            goto exit;
        }
    }

    /* server PUSH (Ack <-) */
    else if ((2 == m_vpnAgent) &&
#ifdef __ENABLE_IKE_MODE_CFG__
             !m_bPullCfg &&
#endif
             !bIke2) /* !!! */
    {
        /* TODO: */
    }

exit:
    return (sbyte4)status;
} /* IKECFG_SAMPLE_respAttrs */

#endif /* defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__) */


/*------------------------------------------------------------------*/

extern sbyte4
IKECFG_EXAMPLE_initUpcalls(void)
{
#ifdef __ENABLE_IKE_XAUTH__
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    if (2 == m_vpnAgent) /* server  */
        IKE_ikeSettings()->funcPtrInteractWithAAA = IKECFG_SAMPLE_InteractWithAAA;
    else
#endif
    IKE_ikeSettings()->funcPtrInteractWithUser  = IKECFG_SAMPLE_InteractWithUser;
#endif
#ifdef __ENABLE_IKE_MODE_CFG__
    IKE_ikeSettings()->funcPtrIkePutCfg         = IKECFG_SAMPLE_putAttrs;
#endif
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    IKE_ikeSettings()->funcPtrIkeGetCfg         = IKECFG_SAMPLE_getAttrs;
    IKE_ikeSettings()->funcPtrIkeInitCfg        = IKECFG_SAMPLE_initAttrs;
    IKE_ikeSettings()->funcPtrIkeRespCfg        = IKECFG_SAMPLE_respAttrs;
#endif
    return (sbyte4)OK;
} /* IKECFG_EXAMPLE_initUpcalls */


#endif /* defined(__ENABLE_IKE_XAUTH__) || defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__) */

#endif /* __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__ */
#endif /* defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__) */

