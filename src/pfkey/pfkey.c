/**
 * @file  pfkey.c
 * @brief PF_KEY Kernel Interface - Core Implementation
 *
 * @since      3.2
 * @version    4.0 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_PFKEY__)

#if defined(__WIN32_RTOS__)
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>

#elif defined(__LINUX_RTOS__) || defined(__OPENBSD_RTOS__) || defined(__VXWORKS_RTOS__) || defined(__QNX_RTOS__) || defined(__SOLARIS_RTOS__) || defined(__CYGWIN_RTOS__)
#include <sys/types.h>
#include <sys/socket.h>

#if defined(__OPENBSD_RTOS__) || defined(__SOLARIS_RTOS__)
#include <netinet/in.h>
#endif

#if defined(__LINUX_RTOS__)
#include <linux/in.h>
#include <linux/in6.h>
#endif

#if defined(__CYGWIN_RTOS__)
#include <cygwin/in.h>
#endif

#if defined(__VXWORKS_RTOS__)
#include <netinet/in.h>
#endif

#endif

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/int64.h"
#include "../crypto/crypto.h"

#include "../pfkey/pfkey.h"
#include "../pfkey/pfkeyv2_common.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"

#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_event.h"
#include "../ike/ikekey.h"
#include "../ike/ike_childsa.h"


/*------------------------------------------------------------------*/

/* useful macro for making sure we don't integer overflow from an attack */
#define ADJUST_LEN_MACRO(X) { if (len < (ubyte2)(X)) { status = ERR_PFKEY_PARSE_BAD_LENGTH; goto exit; } len = len - (ubyte2)(X); }


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildLifetimeExtension(struct ipsecKeyEx *pKeyEx,
                             struct sadb_lifetime *pLifetime, ubyte2 extType)
{
    pLifetime->sadb_lifetime_len     = (sizeof(struct sadb_lifetime) / 8);
    pLifetime->sadb_lifetime_exttype = extType;
    pLifetime->sadb_lifetime_bytes = u8_Add32(pLifetime->sadb_lifetime_bytes,(ubyte4)(pKeyEx->dwExpKBytes * 1024));
    pLifetime->sadb_lifetime_addtime = u8_Add32(pLifetime->sadb_lifetime_addtime, (ubyte4)pKeyEx->dwExpSecs);
    pLifetime->sadb_lifetime_usetime = u8_Add32(pLifetime->sadb_lifetime_usetime, (ubyte4) pKeyEx->dwExpSecs);

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildXAssoc2Extension(ubyte mode, ubyte4 reqid,
                            struct sadb_x_sa2 *pSa)
{
    MSTATUS status = OK;

    pSa->sadb_x_sa2_len = sizeof(struct sadb_x_sa2)/8;
    pSa->sadb_x_sa2_exttype = SADB_X_EXT_SA2;

    pSa->sadb_x_sa2_mode = mode;
    pSa->sadb_x_sa2_reqid = reqid;

    return status;
}

/*------------------------------------------------------------------*/

#if 1 /* defined( __ENABLE_IPSEC_NAT_T__) */
static MSTATUS
pfkey_buildXNatTExtensions(ubyte *pTemp, ubyte2 sport, ubyte2 dport)
{
    MSTATUS status = OK;

    struct sadb_x_nat_t_type *pType;
    struct sadb_x_nat_t_port *pPort;

    pType = (struct sadb_x_nat_t_type *)pTemp;
    pType->sadb_x_nat_t_type_len = sizeof(struct sadb_x_nat_t_type)/8;
    pType->sadb_x_nat_t_type_exttype = SADB_X_EXT_NAT_T_TYPE;
    pType->sadb_x_nat_t_type_type = 2; /* !!! */
    pTemp = (ubyte *)(pType + 1);

    pPort = (struct sadb_x_nat_t_port *)pTemp;
    pPort->sadb_x_nat_t_port_len = sizeof(struct sadb_x_nat_t_port)/8;
    pPort->sadb_x_nat_t_port_exttype = SADB_X_EXT_NAT_T_SPORT;
    DIGI_HTONS((ubyte *)&(pPort->sadb_x_nat_t_port_port), sport);
    pTemp = (ubyte *)(pPort + 1);

    pPort = (struct sadb_x_nat_t_port *)pTemp;
    pPort->sadb_x_nat_t_port_len = sizeof(struct sadb_x_nat_t_port)/8;
    pPort->sadb_x_nat_t_port_exttype = SADB_X_EXT_NAT_T_DPORT;
    DIGI_HTONS((ubyte *)&(pPort->sadb_x_nat_t_port_port), dport);
/*  pTemp = (ubyte *)(pPort + 1);*/

    return status;
}
#endif


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseGetSpi(struct sadb_msg *pBase, ubyte2 len,
                  pfKeyGetSpiResponse **ppSpiResp)
{
    struct sadb_ext*        pExt;
    ubyte*                  pTemp;
    pfKeyGetSpiResponse*    pResp = NULL;
    MSTATUS                 status = OK;

    if (ppSpiResp) *ppSpiResp = NULL;

    pResp = MALLOC(sizeof(pfKeyGetSpiResponse));
    if (NULL == pResp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pResp, 0x00, sizeof(pfKeyGetSpiResponse));

    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));
    pExt = (struct sadb_ext *)(pBase + 1);
    pTemp = (ubyte *)pExt;

    while (len)
    {
        if (8 > len)
        {
            break;
            /*status = ERR_PFKEY_INVALID_LEN;
            goto exit;*/
        }

        ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                struct sadb_sa *pSa = (struct sadb_sa *)pTemp;
                if ((pSa->sadb_sa_len * 8) < sizeof(struct sadb_sa))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                pResp->dwSpi = DIGI_NTOHL((ubyte *)&pSa->sadb_sa_spi);

                pTemp += pSa->sadb_sa_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_SRC:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &(pResp->dwSrc), NULL, NULL)))
                {
                    goto exit;
                }

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &(pResp->dwDst), NULL, NULL)))
                {
                    goto exit;
                }

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            default:
            {
                pTemp += pExt->sadb_ext_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }
        }
    } /* while */

    if (ppSpiResp)
    {
        *ppSpiResp = pResp;
        pResp = NULL;
    }

exit:
    if (pResp)
        FREE(pResp);

    return status;
} /* pfkey_parseGetSpi */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseExpire(pfKeyCb *pPfkey, struct sadb_msg *pBase, ubyte2 len)
{
    struct sadb_ext*    pExt = (struct sadb_ext *)(pBase + 1);
    ubyte*              pTemp;
    MSTATUS             status = OK;
    struct ike_event    ikeEvt;

    DIGI_MEMSET((ubyte *)&ikeEvt, 0x00, sizeof(struct ike_event));

    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));
    pTemp = (ubyte *)pExt;

    while (len)
    {
        if (8 > len)
        {
            break;
            /*status = ERR_PFKEY_INVALID_LEN;
            goto exit;*/
        }

        ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                struct sadb_sa *pSa = (struct sadb_sa *)pTemp;
                if ((pSa->sadb_sa_len * 8) < sizeof(struct sadb_sa))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                ikeEvt.dwSpi = DIGI_NTOHL((ubyte *)&pSa->sadb_sa_spi);

                pTemp += pSa->sadb_sa_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_LIFETIME_CURRENT:
            case SADB_EXT_LIFETIME_HARD:
            case SADB_EXT_LIFETIME_SOFT:
            {
                pTemp += pExt->sadb_ext_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_SRC:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &(ikeEvt.dwSrcAddr), NULL, NULL)))
                {
                    goto exit;
                }

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &(ikeEvt.dwDestAddr), NULL, NULL)))
                {
                    goto exit;
                }

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_PROXY:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            default:
            {
                pTemp += pExt->sadb_ext_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }
        }
    } /* while */

    /* traverse through the table to find a match. Then call IKE_evtRecv()
     * with IKE_KEY_TYPE_DELETED
     */
    if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
    {
        ikeEvt.oProtocol = IPPROTO_ESP;
    }
    else if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
    {
        ikeEvt.oProtocol = IPPROTO_AH;
    }
    else
    {
        status = ERR_PFKEY_PROTOCOL_TYPE;
        goto exit;
    }

    ikeEvt.type = IKE_KEY_TYPE_DELETED;

    if (NULL != pPfkey->fnCallBack.pfkey_funcPtrRequest)
    {
        struct pfKeyRequest_t rqst;
        rqst.pfkeyCmd = SADB_EXPIRE;
        rqst.pfkeySeq = pBase->sadb_msg_seq;
        rqst.pData = (void *)&ikeEvt;

        pPfkey->fnCallBack.pfkey_funcPtrRequest(&rqst);
    }

exit:
    return status;
} /* pfkey_parseExpire */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseAddResponse(ubyte *pMsg, ubyte2 msgLen,
                       struct ipsecKey **ppKey)
{
    struct sadb_msg*    pBase = (struct sadb_msg *)pMsg;
    struct sadb_ext*    pExt = (struct sadb_ext *)(pBase + 1);
    ubyte2              len;
    ubyte*              pTemp;
    struct ipsecKey*    pKey = NULL;
    MSTATUS             status = OK;

    /* length check */
    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
              sizeof(struct sockaddr_in)), 8)) * 8) +
          (2 * sizeof(struct sadb_key));

    if (msgLen < len)
    {
        status = ERR_PFKEY_INVALID_LEN;
        goto exit;
    }

    if (ppKey) *ppKey = NULL;

    pKey = (struct ipsecKey *)
#ifdef __ENABLE_DIGICERT_IPV6__
           MALLOC(sizeof(struct ipsecKey) + (2 * 16));
#else
           MALLOC(sizeof(struct ipsecKey));
#endif
    if (NULL == pKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pKey, 0, sizeof(struct ipsecKey));

    if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
        pKey->oProtocol = IPPROTO_AH;
    else if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
        pKey->oProtocol = IPPROTO_ESP;

    len = (ubyte2)(msgLen - sizeof(struct sadb_msg));
    pTemp = (ubyte *)pExt;

    while (len)
    {
        if (8 > len)
        {
            break;
            /*status = ERR_PFKEY_INVALID_LEN;
            goto exit;*/
        }

        ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                struct sadb_sa *pSa = (struct sadb_sa *)pTemp;
                if ((pSa->sadb_sa_len * 8) < sizeof(struct sadb_sa))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                pKey->dwSpi = DIGI_NTOHL((ubyte *) &pSa->sadb_sa_spi);

                switch (pSa->sadb_sa_auth)
                {
                    case SADB_AALG_NONE:
                    case SADB_X_AALG_NULL:
                    {
                        pKey->oAuthAlgo = 0;
                        break;
                    }
                    default:
                    {
                        CHILDSA_authInfo *pAuthAlgo =
                            CHILDSA_findAuthAlgo(0, pSa->sadb_sa_auth, 0, 0);

                        if (NULL == pAuthAlgo)
                        {
                            pKey->oAuthAlgo = pSa->sadb_sa_auth;
                            /*status = ERR_PFKEY_INVALID_PARAMETER;
                            goto exit;*/
                        }
                        else
                        {
                            pKey->oAuthAlgo = pAuthAlgo->oAuthAlgo;
                        }
                        break;
                    }
                } /* switch (pSa->sadb_sa_auth) */

                switch (pSa->sadb_sa_encrypt)
                {
                    case SADB_EALG_NONE:
                    case SADB_EALG_NULL:
                    {
                        pKey->oEncrAlgo = 0;
                        break;
                    }
                    default:
                    {
                        CHILDSA_encrInfo *pEncrAlgo =
                            CHILDSA_findEncrAlgo(pSa->sadb_sa_encrypt, 0, 0, 0, NULL);

                        if (NULL == pEncrAlgo)
                        {
                            pKey->oEncrAlgo = pSa->sadb_sa_encrypt;
                            /*status = ERR_PFKEY_INVALID_PARAMETER;
                            goto exit;*/
                        }
                        else
                        {
                            pKey->oEncrAlgo = pEncrAlgo->oEncrAlgo;
                        }
                        break;
                    }
                } /* switch (pSa->sadb_sa_encrypt) */

                pTemp += pSa->sadb_sa_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }
            case SADB_EXT_ADDRESS_SRC:
            {
                MOC_IP_ADDRESS_S ipAddr;
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &ipAddr, NULL, NULL)))
                {
                    goto exit;
                }

                IF_MOC_IPADDR6(ipAddr,
                {
                    ubyte *addr6 = (ubyte *)(pKey + 1);
                    DIGI_MEMCPY(addr6, GET_MOC_IPADDR6(REF_MOC_IPADDR(ipAddr)), 16);
                    pKey->dwSrcAddr = (CAST_MOC_IPADDR)addr6;
                    pKey->flags |= IPSEC_SA_FLAG_IP6;
                })
                pKey->dwSrcAddr = GET_MOC_IPADDR4(REF_MOC_IPADDR(ipAddr));

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                MOC_IP_ADDRESS_S ipAddr;
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &ipAddr, NULL, NULL)))
                {
                    goto exit;
                }

                IF_MOC_IPADDR6(ipAddr,
                {
                    ubyte *addr6 = (ubyte *)(pKey + 1) + 16;
                    DIGI_MEMCPY(addr6, GET_MOC_IPADDR6(REF_MOC_IPADDR(ipAddr)), 16);
                    pKey->dwDestAddr = (CAST_MOC_IPADDR)addr6;
                    pKey->flags |= IPSEC_SA_FLAG_IP6;
                })
                pKey->dwDestAddr = GET_MOC_IPADDR4(REF_MOC_IPADDR(ipAddr));

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_X_EXT_SA2:
            {
                struct sadb_x_sa2 *pSa2 = (struct sadb_x_sa2 *)pTemp;
                if ((pSa2->sadb_x_sa2_len * 8) < sizeof(struct sadb_x_sa2))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                pKey->oMode = pSa2->sadb_x_sa2_mode;
                pKey->cookie = pSa2->sadb_x_sa2_reqid;

                pTemp += pSa2->sadb_x_sa2_len *8 ;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            default:
            {
                pTemp += pExt->sadb_ext_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }
        }
    } /* while */

    if (ppKey)
    {
        *ppKey = pKey;
        pKey = NULL;
    }

exit:
    if (pKey)
        FREE(pKey);

    return status;
} /* pfkey_parseAddResponse */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseGet(struct sadb_msg *pBase, ubyte2 len)
{
    struct sadb_ext*              pExt;
    struct sadb_address*          pAddr;
    struct sadb_key*              pKey;
    ubyte*                        pTemp;
    struct sadb_sa*               pSa;
    ubyte4                        dwSpi;
    struct sockaddr_in*           pSockAddr;
    MSTATUS                       status = OK;

    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));
    pExt = (struct sadb_ext *)(pBase + 1);
    pTemp = (ubyte *)pExt;

    while ((len) && (pExt))
    {
        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                pSa = (struct sadb_sa *)pTemp;
                dwSpi = DIGI_NTOHL((ubyte *)(ubyte *)&pSa->sadb_sa_spi);
                pTemp += (pSa->sadb_sa_len * 8);
                pExt = (struct sadb_ext *)pTemp;
                ADJUST_LEN_MACRO(pSa->sadb_sa_len * 8);
                break;
            }

            case SADB_EXT_ADDRESS_SRC:
            {
                ubyte4 dwSrcAddr;
                pAddr = (struct sadb_address *)pTemp;
                pSockAddr = (struct sockaddr_in *)(pTemp +
                                                  sizeof(struct sadb_address));
                dwSrcAddr = DIGI_NTOHL((ubyte *)&pSockAddr->sin_addr.s_addr);
                pTemp += pAddr->sadb_address_len*8;
                pExt = (struct sadb_ext *)pTemp;
                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                ubyte4 dwDestAddr;
                pAddr = (struct sadb_address *)pTemp;
                pSockAddr = (struct sockaddr_in *)(pTemp +
                                                  sizeof(struct sadb_address));
                dwDestAddr = DIGI_NTOHL((ubyte *)&pSockAddr->sin_addr.s_addr);
                pTemp += pAddr->sadb_address_len*8;
                pExt = (struct sadb_ext *)pTemp;
                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);
                break;
            }

            case SADB_EXT_ADDRESS_PROXY:
            {
                pAddr = (struct sadb_address *)pTemp;
                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);
                break;
            }

            case SADB_EXT_LIFETIME_CURRENT:
            case SADB_EXT_LIFETIME_HARD:
            case SADB_EXT_LIFETIME_SOFT:
            {
                pTemp += sizeof(struct sadb_lifetime);
                pExt = (struct sadb_ext *)pTemp;
                ADJUST_LEN_MACRO(sizeof(struct sadb_lifetime));
                break;
            }

            case SADB_EXT_KEY_AUTH:
            case SADB_EXT_KEY_ENCRYPT:
            {
                pKey = (struct sadb_key *)pExt;
                pTemp += pKey->sadb_key_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                ADJUST_LEN_MACRO(pKey->sadb_key_len * 8);
                break;
            }

            default:
            {
                if (pExt)
                {
                    pTemp = (ubyte *)pExt;
                    ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);
                    pTemp += (pExt->sadb_ext_len*8);
                    pExt = (struct sadb_ext *)pTemp;
                }

                break;
            }
        }
    }

exit:
    return status;
} /* pfkey_parseGet */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseRegisterResponse(ubyte *pMsg,
                            pfKeyRegisterResponse **ppRegResp)
{
    struct sadb_supported*  pSupp;
    struct sadb_alg*        pSuppAlgo;
    struct sadb_ext*        pExt;
    ubyte2                  numSupported;
    ubyte2                  i;
    ubyte2                  num;
    ubyte2                  len;
    pfKeySuppAlgo*          pTrav;
    pfKeyRegisterResponse*  pRegResp = NULL;
    struct sadb_msg*        pBase = (struct sadb_msg *)pMsg;
    ubyte*                  pTemp;
    MSTATUS                 status = OK;

    *ppRegResp = NULL;

    if ((pBase->sadb_msg_len * 8) < sizeof(struct sadb_msg))
    {
        status = ERR_PFKEY_INVALID_LEN;
        goto exit;
    }
    pTemp = pMsg + sizeof(struct sadb_msg);

    len = pBase->sadb_msg_len * 8;
    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));
    pExt = (struct sadb_ext *)pTemp;

    pRegResp = MALLOC(sizeof(pfKeyRegisterResponse));
    if (NULL == pRegResp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pRegResp, 0x00, sizeof(pfKeyRegisterResponse));
    i = 0;

    while (len)
    {
        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SUPPORTED_AUTH:
            {
                pSupp = (struct sadb_supported *)pExt;
                numSupported = ((pSupp->sadb_supported_len * 8) -
                         sizeof(struct sadb_supported))/sizeof(struct sadb_alg);
                pSuppAlgo = (struct sadb_alg *)(pSupp + 1);
                pTrav = &(pRegResp->algoInfo[i]);

                for (num = 0; num < numSupported; num++, pSuppAlgo++)
                {
                    CHILDSA_authInfo *pAuthAlgo =
                        CHILDSA_findAuthAlgo(0, pSuppAlgo->sadb_alg_id, 0, 0);

                    if (NULL == pAuthAlgo) continue;
                    pAuthAlgo->bSupported = TRUE;

                    if (PFKEY_MAX_SUPPORTED_ALGO > i)
                    {
                        pTrav->algId = pAuthAlgo->oAuthAlgo;
                        pTrav->algType = PFKEY_ALGTYPE_AUTH;
                        pTrav->algMinBits = pSuppAlgo->sadb_alg_minbits;
                        pTrav->algMaxBytes = pSuppAlgo->sadb_alg_maxbits;
                        pTrav->ivLen = pSuppAlgo->sadb_alg_ivlen;
                        pTrav++;

                        pRegResp->numSupported++;
                        i++;
                    }
                }

                pExt = (struct sadb_ext *)pSuppAlgo;
                ADJUST_LEN_MACRO(pSupp->sadb_supported_len * 8);
                /* len -= pSupp->sadb_supported_len * 8; */
                break;
            }

            case SADB_EXT_SUPPORTED_ENCRYPT:
            {
                pSupp = (struct sadb_supported *)pExt;
                numSupported = ((pSupp->sadb_supported_len * 8) -
                         sizeof(struct sadb_supported))/sizeof(struct sadb_alg);
                pSuppAlgo = (struct sadb_alg *)(pSupp + 1);
                pTrav = &(pRegResp->algoInfo[i]);

                for (num = 0; num < numSupported; num++, pSuppAlgo++)
                {
                    ubyte2 wEncrKeyLen = (ubyte2)(pSuppAlgo->sadb_alg_minbits / 8);
                    ubyte2 wEncrKeyLenEnd = (ubyte2)(pSuppAlgo->sadb_alg_maxbits / 8);
                    CHILDSA_encrInfo *pEncrAlgoFound = NULL;

                    sbyte4 j;
                    for (j=0; ;j++)
                    {
                        CHILDSA_encrInfo *pEncrAlgo = CHILDSA_getEncrAlgo(j);
                        if (NULL == pEncrAlgo) break;

                        if ((pEncrAlgo->oTfmId != pSuppAlgo->sadb_alg_id) ||
                            (wEncrKeyLenEnd < pEncrAlgo->wKeyLen) ||
                            (wEncrKeyLen > pEncrAlgo->wKeyLenEnd))
                            continue;

                        pEncrAlgo->bSupported = TRUE;
                        pEncrAlgoFound = pEncrAlgo;

                        if ((wEncrKeyLenEnd <= pEncrAlgo->wKeyLenEnd) &&
                            (wEncrKeyLen >= pEncrAlgo->wKeyLen))
                            break;
                    } /* for */

                    if ((NULL != pEncrAlgoFound) && (PFKEY_MAX_SUPPORTED_ALGO > i))
                    {
                        pTrav->algId = pEncrAlgoFound->oEncrAlgo;
                        pTrav->algType = PFKEY_ALGTYPE_ENCRYPT;
                        pTrav->algMinBits = pSuppAlgo->sadb_alg_minbits;
                        pTrav->algMaxBytes = pSuppAlgo->sadb_alg_maxbits;
                        pTrav->ivLen = pSuppAlgo->sadb_alg_ivlen;
                        pTrav++;

                        pRegResp->numSupported++;
                        i++;
                    }
                }

                pExt = (struct sadb_ext *)pSuppAlgo;
                ADJUST_LEN_MACRO(pSupp->sadb_supported_len * 8);
                break;
            }

            default:
            {
                pTemp += pExt->sadb_ext_len * 8;
                ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);
                pExt = (struct sadb_ext *)pTemp;
                break;
            }
        }
    }

    *ppRegResp = pRegResp;
    pRegResp = NULL;

exit:
    if (pRegResp)
        FREE(pRegResp);

    return status;
} /* pfkey_parseRegisterResponse */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseAcquire(pfKeyCb *pPfKey, struct sadb_msg *pBase, ubyte2 len)
{
    struct sadb_ext*        pExt = (struct sadb_ext *)(pBase + 1);
    struct ike_event        ikeEvt;
    ubyte4                  i;
    ubyte                   proto;
    MSTATUS                 status = OK;

    DIGI_MEMSET((ubyte *)&ikeEvt, 0x00, sizeof(struct ike_event));

    switch (pBase->sadb_msg_satype)
    {
        case SADB_SATYPE_AH:
        {
            proto = IPPROTO_AH;
            break;
        }

        case SADB_SATYPE_ESP:
        {
            proto = IPPROTO_ESP;
            break;
        }

        default:
        {
            status = ERR_PFKEY_PROTOCOL_TYPE;
            goto exit;
            break;
        }
    }

    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));

    while (len)
    {
        if (8 > len)
        {
            break;
            /*status = ERR_PFKEY_INVALID_LEN;
            goto exit;*/
        }

        ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_ADDRESS_SRC:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pExt;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &ikeEvt.dwSrcAddr,
                                        &ikeEvt.oUlp,
                                        &ikeEvt.wSrcPort)))
                {
                    goto exit;
                }

                pExt = (struct sadb_ext *)((ubyte *)pExt + (pAddr->sadb_address_len * 8));
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                struct sadb_address *pAddr = (struct sadb_address *)pExt;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &ikeEvt.dwDestAddr,
                                        &ikeEvt.oUlp,
                                        &ikeEvt.wDestPort)))
                {
                    goto exit;
                }

                pExt = (struct sadb_ext *)((ubyte *)pExt + (pAddr->sadb_address_len * 8));
                break;
            }

            case SADB_X_EXT_POLICY:
            {
                struct sadb_x_policy *pPol = (struct sadb_x_policy *)pExt;
                if ((pPol->sadb_x_policy_len * 8) < sizeof(struct sadb_x_policy))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                ikeEvt.dwSpdId = pPol->sadb_x_policy_id;

                pExt = (struct sadb_ext *)((ubyte *)pExt + (pPol->sadb_x_policy_len * 8));
                break;
            }

            case SADB_EXT_PROPOSAL:
            {
                struct sadb_comb*   pComb;
                ubyte4              numCombs;
                struct sainfo *pxSaInfo = &(ikeEvt.pxSa[0]);

                struct sadb_prop *pProp = (struct sadb_prop *)pExt;
                if ((pProp->sadb_prop_len * 8) < sizeof(struct sadb_prop))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                ikeEvt.oReplay = pProp->sadb_prop_replay;

                numCombs = (pProp->sadb_prop_len*8 - sizeof(struct sadb_prop))
                         / sizeof(struct sadb_comb);
                pComb = (struct sadb_comb *)(pProp + 1);

                for (i=0; i < numCombs; i++, pComb++)
                {
                    CHILDSA_encrInfo *pEncrAlgo;
                    ubyte oEncrKeyLen=0, oEncrKeyLenEnd=0;

                    if (PFKEY_COMB_MAX <= ikeEvt.oCombLen)
                        continue;

                    DIGI_MEMSET((ubyte *)pxSaInfo, 0x00, sizeof(struct sainfo)); /* jic */

                    switch (pComb->sadb_comb_auth)
                    {
                        case SADB_AALG_NONE:
                        case SADB_X_AALG_NULL:
                        {
                            if (IPPROTO_AH == proto) continue;
                            pxSaInfo->oSecuProto = IPSEC_PROTO_ESP;
                            break;
                        }

                        default:
                        {
                            CHILDSA_authInfo *pAuthAlgo =
                                CHILDSA_findAuthAlgo(0, pComb->sadb_comb_auth, 0, 0);

                            if (NULL == pAuthAlgo) continue;

                            pxSaInfo->oAuthAlgo = pAuthAlgo->oAuthAlgo;
                            pxSaInfo->oSecuProto = (IPPROTO_AH == proto)
                                                 ? IPSEC_PROTO_AH : IPSEC_PROTO_ESP_NULL;
                            break;
                        }
                    }

                    if (IPPROTO_AH == proto) goto next;

                    switch (pComb->sadb_comb_encrypt)
                    {
                        case SADB_EALG_NONE:
                        case SADB_EALG_NULL:
                        {
                            if (IPSEC_PROTO_ESP == pxSaInfo->oSecuProto)
                                continue;
                            break;
                        }

                        default:
                        {
                            oEncrKeyLen = (ubyte)(pComb->sadb_comb_encrypt_minbits / 8);
                            oEncrKeyLenEnd = (ubyte)(pComb->sadb_comb_encrypt_maxbits / 8);
                            if ((0 == oEncrKeyLen) || (0 == oEncrKeyLenEnd) || (oEncrKeyLen > oEncrKeyLenEnd))
                                continue;

                            pEncrAlgo = CHILDSA_findEncrAlgo(pComb->sadb_comb_encrypt, 0, 0,
                                            ((oEncrKeyLen == oEncrKeyLenEnd) ? oEncrKeyLen : 0),
                                             NULL);
                            if (NULL == pEncrAlgo) continue;

                            pxSaInfo->oEncrAlgo = pEncrAlgo->oEncrAlgo;
                            pxSaInfo->aeadTag = pEncrAlgo->oTagLen;

                            if (IPSEC_PROTO_ESP_NULL == pxSaInfo->oSecuProto)
                                pxSaInfo->oSecuProto = IPSEC_PROTO_ESP_AUTH;

                            break;
                        }
                    }

                    if (IPSEC_PROTO_ESP_NULL != pxSaInfo->oSecuProto)
                    {
                        if (oEncrKeyLen == oEncrKeyLenEnd)
                            pxSaInfo->oEncrKeyLen = oEncrKeyLen;
                        else
                        {
                            sbyte4 j;
                            for (j=0; ; j++)
                            {
                                if (NULL == (pEncrAlgo = CHILDSA_getEncrAlgo(j)))
                                    break;

                                if ((pEncrAlgo->oEncrAlgo != pxSaInfo->oEncrAlgo) ||
                                    ((ubyte2)oEncrKeyLenEnd < pEncrAlgo->wKeyLen) ||
                                    ((ubyte2)oEncrKeyLen > pEncrAlgo->wKeyLenEnd))
                                    continue;

                                pxSaInfo->oEncrKeyLen = (oEncrKeyLenEnd <= pEncrAlgo->wKeyLenEnd)
                                                      ? oEncrKeyLenEnd : (ubyte) pEncrAlgo->wKeyLenEnd;

                                pxSaInfo = &(ikeEvt.pxSa[++ikeEvt.oCombLen]);
                                if (PFKEY_COMB_MAX <= ikeEvt.oCombLen)
                                    break;

                                *pxSaInfo = *(pxSaInfo - 1);

                                if (((ubyte2)oEncrKeyLenEnd <= pEncrAlgo->wKeyLenEnd) &&
                                    ((ubyte2)oEncrKeyLen >= pEncrAlgo->wKeyLen))
                                    break;
                            } /* for */

                            continue; /* !!! */
                        }
                    }
next:
                    pxSaInfo = &(ikeEvt.pxSa[++ikeEvt.oCombLen]);

                } /* for (i=0; i < numCombs; i++, pComb++) */

                pExt = (struct sadb_ext *)((ubyte *)pExt + (pProp->sadb_prop_len * 8));
                break;
            } /* SADB_EXT_PROPOSAL */

            default:
            {
                pExt = (struct sadb_ext *)((ubyte *)pExt + (pExt->sadb_ext_len * 8));
                break;
            }
        }
    } /* while */

    ikeEvt.type = IKE_KEY_TYPE_ACQUIRE;
    ikeEvt.dwSeqNo = pBase->sadb_msg_seq; /* copy over seq no. */

    if (NULL != pPfKey->fnCallBack.pfkey_funcPtrRequest)
    {
        struct pfKeyRequest_t rqst;
        rqst.pfkeyCmd = SADB_ACQUIRE;
        rqst.pfkeySeq = pBase->sadb_msg_seq;
        rqst.pData = (void *)&ikeEvt;

        pPfKey->fnCallBack.pfkey_funcPtrRequest(&rqst);
    }

exit:
    return status;
} /* pfkey_parseAcquire */


/*------------------------------------------------------------------*/

static void
ipv6_prefix2range(const ubyte *addr, ubyte prefix,
                  ubyte *addr_start, ubyte *addr_end)
{
    /* note: 'prefix' should be less than 128 */
    sbyte4 i;
    for (i=0; i < 16; i++)
    {
        if (8 <= prefix)
        {
            addr_start[i] = addr_end[i] = addr[i];
            prefix -= 8;
        }
        else if (prefix)
        {
            ubyte m = (ubyte)0xFF << (8 - prefix);
            addr_start[i] = (ubyte)(addr[i] & m);
            addr_end[i] = (ubyte)(addr[i] | (ubyte)(~m));
            prefix = 0;
        }
        else
        {
            addr_start[i] = (ubyte)0x00;
            addr_end[i] = (ubyte)0xFF;
        }
    }

    return;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseSpdGet(ubyte *pMsg, ubyte2 msgLen,
                  struct ipsecConf **ppConf)
{
    struct sadb_msg*    pBase = (struct sadb_msg *)pMsg;
    struct sadb_ext*    pExt = (struct sadb_ext *)(pBase + 1);
    ubyte2              len;
    ubyte*              pTemp;
    struct ipsecConf*   pConf = NULL;
    MSTATUS             status = OK;

    /* length check */
    len = sizeof(struct sadb_msg) + sizeof(struct sadb_x_policy);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
              sizeof(struct sockaddr_in)), 8)) * 8);

    if (msgLen < len)
    {
        status = ERR_PFKEY_INVALID_LEN;
        goto exit;
    }

    if (ppConf) *ppConf = NULL;

    pConf = (struct ipsecConf *)
#ifdef __ENABLE_DIGICERT_IPV6__
            MALLOC(sizeof(struct ipsecConf) + sizeof(struct sainfo) + (6 * 16));
#else
            MALLOC(sizeof(struct ipsecConf) + sizeof(struct sainfo));
#endif
    if (NULL == pConf)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pConf, 0x00, sizeof(struct ipsecConf) + sizeof(struct sainfo));
    pConf->pxSa = (struct sainfo *)(pConf + 1);

    len = (ubyte2)(msgLen - sizeof(struct sadb_msg));
    pTemp = (ubyte *)pExt;

    while (len)
    {
        if (8 > len)
        {
            break;
            /*status = ERR_PFKEY_INVALID_LEN;
            goto exit;*/
        }

        ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_ADDRESS_SRC:
            {
                ubyte prefix;
                MOC_IP_ADDRESS_S ipAddr;
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &ipAddr, &pConf->oProto, &pConf->wSrcPort)))
                {
                    goto exit;
                }

                if (IPSEC_ULPROTO_ANY == pConf->oProto)
                    pConf->oProto = 0;

                prefix = pAddr->sadb_address_prefixlen;

                IF_MOC_IPADDR6(ipAddr,
                {
                    ubyte *addr6 = (ubyte *)(pConf + 1) + sizeof(struct sainfo);
                    pConf->dwSrcIP = (CAST_MOC_IPADDR)addr6;
                    pConf->dwSrcIPEnd = (CAST_MOC_IPADDR)(addr6 + 16);

                    if (prefix && (128 > prefix))
                    {
                        ipv6_prefix2range(GET_MOC_IPADDR6(REF_MOC_IPADDR(ipAddr)),
                                          prefix, addr6, addr6 + 16);
                    }
                    else
                    {
                        DIGI_MEMCPY(addr6, GET_MOC_IPADDR6(REF_MOC_IPADDR(ipAddr)), 16);
                        DIGI_MEMCPY(addr6 + 16, addr6, 16);
                    }
                    pConf->flags |= IPSEC_SP_FLAG_IP6;
                })
                {
                    pConf->dwSrcIP = GET_MOC_IPADDR4(REF_MOC_IPADDR(ipAddr));

                    if (prefix && (32 > prefix))
                    {
                        ubyte4 dwIPaddr = (ubyte4) pConf->dwSrcIP;
                        ubyte4 m = (ubyte4)0xFFFFFFFF;
                        m <<= (32 - prefix);
                        pConf->dwSrcIP = (dwIPaddr & m);
                        pConf->dwSrcIPEnd = (dwIPaddr | (~m));
                    }
                    else pConf->dwSrcIPEnd = pConf->dwSrcIP;
                }

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                ubyte prefix;
                MOC_IP_ADDRESS_S ipAddr;
                struct sadb_address *pAddr = (struct sadb_address *)pTemp;
                if (pAddr->sadb_address_len <
                    (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                if (OK > (status = pfkey_parseAddressExtension(pAddr,
                                        &ipAddr, &pConf->oProto, &pConf->wDestPort)))
                {
                    goto exit;
                }

                if (IPSEC_ULPROTO_ANY == pConf->oProto)
                    pConf->oProto = 0;

                prefix = pAddr->sadb_address_prefixlen;

                IF_MOC_IPADDR6(ipAddr,
                {
                    ubyte *addr6 = (ubyte *)(pConf + 1) + (sizeof(struct sainfo) + 32);
                    pConf->dwDestIP = (CAST_MOC_IPADDR)addr6;
                    pConf->dwDestIPEnd = (CAST_MOC_IPADDR)(addr6 + 16);

                    if (prefix && (128 > prefix))
                    {
                        ipv6_prefix2range(GET_MOC_IPADDR6(REF_MOC_IPADDR(ipAddr)),
                                          prefix, addr6, addr6 + 16);
                    }
                    else
                    {
                        DIGI_MEMCPY(addr6, GET_MOC_IPADDR6(REF_MOC_IPADDR(ipAddr)), 16);
                        DIGI_MEMCPY(addr6 + 16, addr6, 16);
                    }
                    pConf->flags |= IPSEC_SP_FLAG_IP6;
                })
                {
                    pConf->dwDestIP = GET_MOC_IPADDR4(REF_MOC_IPADDR(ipAddr));

                    if (prefix && (32 > prefix))
                    {
                        ubyte4 dwIPaddr = (ubyte4) pConf->dwDestIP;
                        ubyte4 m = (ubyte4)0xFFFFFFFF;
                        m <<= (32 - prefix);
                        pConf->dwDestIP = (dwIPaddr & m);
                        pConf->dwDestIPEnd = (dwIPaddr | (~m));
                    }
                    else pConf->dwDestIPEnd = pConf->dwDestIP;
                }

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_EXT_LIFETIME_HARD:
            case SADB_EXT_LIFETIME_SOFT:
            case SADB_EXT_LIFETIME_CURRENT:
            {
                /* We currently don't have any parallel field in
                 * struct ipsecConf, so ignor lifetimes.
                 */
                pTemp += pExt->sadb_ext_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            case SADB_X_EXT_POLICY:
            {
                struct sadb_x_policy *pPol = (struct sadb_x_policy *)pTemp;
                if ((pPol->sadb_x_policy_len * 8) < sizeof(struct sadb_x_policy))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                pConf->index = (sbyte4) pPol->sadb_x_policy_id;
                pConf->oDir = pPol->sadb_x_policy_dir;

                switch (pPol->sadb_x_policy_type)
                {
                    case IPSEC_POLICY_DISCARD:
                    {
                        pConf->oAction = IPSEC_ACTION_DROP;
                        break;
                    }

                    case IPSEC_POLICY_NONE:
                    case IPSEC_POLICY_ENTRUST:
                    case IPSEC_POLICY_BYPASS:
                    {
                        pConf->oAction = IPSEC_ACTION_BYPASS;
                        break;
                    }

                    case IPSEC_POLICY_IPSEC:
                    {
                        struct sadb_x_ipsecrequest *pIpsecReq;

                        if (IPSEC_DIR_INBOUND == pPol->sadb_x_policy_dir)
                            pConf->oAction = IPSEC_ACTION_PERMIT;
                        else
                            pConf->oAction = IPSEC_ACTION_APPLY;

                        if ((pPol->sadb_x_policy_len * 8) <
                            (sizeof(struct sadb_x_policy) + sizeof(struct sadb_x_ipsecrequest)))
                        {
                            status = ERR_PFKEY_PARSE_BAD_LENGTH;
                            goto exit;
                        }

                        pIpsecReq = (struct sadb_x_ipsecrequest *)(pPol + 1);
                        pConf->cookie = pIpsecReq->sadb_x_ipsecrequest_reqid;
                        pConf->oSaLen = 1;

                        switch (pIpsecReq->sadb_x_ipsecrequest_proto)
                        {
                        case IPPROTO_AH:
                            pConf->pxSa->oSecuProto = IPSEC_PROTO_AH;
                            break;
                        case IPPROTO_ESP:
                            pConf->pxSa->oSecuProto = (1 << IPSEC_PROTO_ESP)
                                                    | (1 << IPSEC_PROTO_ESP_AUTH)
                                                    | (1 << IPSEC_PROTO_ESP_NULL);
                            break;
                        default:
                            status = ERR_PFKEY_PROTOCOL_TYPE;
                            goto exit;
                            break;
                        }

                        pConf->oMode = pIpsecReq->sadb_x_ipsecrequest_mode;
                        if (IPSEC_MODE_TUNNEL == pConf->oMode)
                        {
                            struct sockaddr_in *pSockAddr;

                            if ((pPol->sadb_x_policy_len * 8) <
                                (sizeof(struct sadb_x_policy) + sizeof(struct sadb_x_ipsecrequest) +
                                 ((PFKEY_DIVROUNDUP((2 *sizeof(struct sockaddr_in)), 8)) * 8)))
                            {
                                status = ERR_PFKEY_PARSE_BAD_LENGTH;
                                goto exit;
                            }

                            pSockAddr = (struct sockaddr_in *)(pIpsecReq + 1);
                            if (AF_INET == pSockAddr->sin_family)
                            {
                                pConf->dwTunlSrcIP = DIGI_NTOHL((ubyte *) &pSockAddr->sin_addr.s_addr);
                                pSockAddr++;
                                pConf->dwTunlDestIP = DIGI_NTOHL((ubyte *) &pSockAddr->sin_addr.s_addr);
                            }
                            else
                            {
#ifdef __ENABLE_DIGICERT_IPV6__
                                struct sockaddr_in6 *pSockAddr6 = (struct sockaddr_in6 *)pSockAddr;
                                if (AF_INET6 == pSockAddr6->sin6_family)
                                {
                                    ubyte *addr6 = (ubyte *)(pConf + 1) + (sizeof(struct sainfo) + 64);

                                    if ((pPol->sadb_x_policy_len * 8) <
                                        (sizeof(struct sadb_x_policy) + sizeof(struct sadb_x_ipsecrequest) +
                                         ((PFKEY_DIVROUNDUP((2 *sizeof(struct sockaddr_in6)), 8)) * 8)))
                                    {
                                        status = ERR_PFKEY_PARSE_BAD_LENGTH;
                                        goto exit;
                                    }

                                    DIGI_MEMCPY(addr6, (ubyte *) pSockAddr6->sin6_addr.s6_addr, 16);
                                    pConf->dwTunlSrcIP = (CAST_MOC_IPADDR)addr6;

                                    pSockAddr6++; addr6 += 16;

                                    DIGI_MEMCPY(addr6, (ubyte *) pSockAddr6->sin6_addr.s6_addr, 16);
                                    pConf->dwTunlDestIP = (CAST_MOC_IPADDR)addr6;

                                    pConf->flags |= IPSEC_SP_FLAG_IP6_TUNNEL;
                                }
                                else
#endif
                                {
                                    status = ERR_PFKEY_PROTOCOL_TYPE;
                                    goto exit;
                                }
                            }
                        }

                        break;
                    }

                    default:
                    {
                        status = ERR_PFKEY_INVALID_PARAMETER;
                        goto exit;
                        break;
                    }
                }

                pTemp += pPol->sadb_x_policy_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }

            default:
            {
                pTemp += pExt->sadb_ext_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                break;
            }
        }
    } /* while */

    if (ppConf)
    {
        *ppConf = pConf;
        pConf = NULL;
    }

exit:
    if (pConf)
        FREE(pConf);

    return status;
} /* pfkey_parseSpdGet */


/*------------------------------------------------------------------*/

/**
@brief      Initialize a PF_KEY interface instance.

@details    This function initializes a PF_KEY interface instance. Any key
            management application that needs to use the PF_KEY interface for
            communication with IPsec must call this function before making any
            other PF_KEY function calls. The PF_KEY handle returned through the
            \p ppPfkeyCb parameter must be passed to all subsequent PF_KEY
            function calls.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param ppPfkeyCb    On return, pointer to PF_KEY control block handle.
@param pid          Application's process ID.
@param pFnCallback  Pointer to callback functions to register for this PF_KEY
                      instance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_init(pfKeyCb **ppPfkeyCb, ubyte4 pid, pfKeyCallback *pFnCallback)
{
    pfKeyCb*    pPfkey = NULL;
    MSTATUS     status = OK;

    *ppPfkeyCb = NULL;

    if (!pid)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    pPfkey = MALLOC(sizeof(pfKeyCb));
    if (NULL == pPfkey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pPfkey, 0x00, sizeof(pfKeyCb));

    pPfkey->pid = pid;
    DIGI_MEMCPY(&pPfkey->fnCallBack, pFnCallback, sizeof(pfKeyCallback));

    *ppPfkeyCb = pPfkey;
    pPfkey = NULL;

exit:
    if (pPfkey)
        FREE(pPfkey);

    return status;
} /* PFKEY_init */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_REGISTER message to register a key socket's ability
            to acquire new SAs for the kernel.

@details    This function builds an SADB_REGISTER message, enabling NanoSec
            IKE to register its key socket as able to acquire new security
            associations (SAs) for the kernel.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param proto    Protocol type (\c IPPROTO_AH or \c IPPROTO_ESP).
@param ppMsg    Address of pointer which on return points to the SADB_REGISTER
                  message.
@param pLen     On return, pointer to number of bytes in SADB_REGISTER message          (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_register(pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen)
{
    struct sadb_msg*    pMsg = NULL;
    MSTATUS             status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    if (IPPROTO_AH != proto && IPPROTO_ESP != proto)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    /* send SADB_REGISTER */
    if (NULL == (pMsg = (struct sadb_msg *) *ppMsg))
    {
        pMsg = (struct sadb_msg *) MALLOC(sizeof(struct sadb_msg));
        if (NULL == pMsg)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (sizeof(struct sadb_msg) > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET((ubyte *)pMsg, 0x00, sizeof(struct sadb_msg));

    pMsg->sadb_msg_version = PF_KEY_V2;
    pMsg->sadb_msg_type = SADB_REGISTER;

    if (IPPROTO_AH == proto)
        pMsg->sadb_msg_satype = SADB_SATYPE_AH;
    else/* if (IPPROTO_ESP == proto)*/
        pMsg->sadb_msg_satype = SADB_SATYPE_ESP;

    pMsg->sadb_msg_len = sizeof(struct sadb_msg) / 8;
    pMsg->sadb_msg_seq = ++pPfkey->seqNo;
    pMsg->sadb_msg_pid = pPfkey->pid;

    /* return values */
    *ppMsg = (ubyte *)pMsg;
    pMsg = NULL;
    *pLen = sizeof(struct sadb_msg);

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_register */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_ADD message with the specified key data.

@details    This function builds an SADB_ADD message. Data for the key to be
            added is specified in the \p pKeyEx parameter.

@ingroup    pfkey_functions

@since 3.2
@version 4.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param pKeyEx   Pointer to data to use for the added key.
@param ppMsg    Address of pointer which on return contains the SADB_ADD message.
@param pLen     On return, pointer to number of bytes in SADB_ADD message
                  (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_add(pfKeyCb *pPfkey, struct ipsecKeyEx *pKeyEx, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*                  pMsg = NULL;
    ubyte*                  pTemp;
    struct sadb_sa*         pSa;
    struct sadb_x_sa2*      pSa2;
    struct sadb_address*    pAddr;
    ubyte2                  len, addr_len;
    MSTATUS                 status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    if (!pKeyEx)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    TEST_MOC_IPADDR6(pKeyEx->dwDestAddr,
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in6)), 8)) * 8);
    })
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)) * 8);
    }

    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa) + sizeof(struct sadb_x_sa2);
    len += 2 * addr_len;

    /* allocate for soft & hard lifetimes */
    if ((0 != pKeyEx->dwExpKBytes) || (0 != pKeyEx->dwExpSecs))
        len += 2*sizeof(struct sadb_lifetime);

    if ((0 != pKeyEx->wEncrKeyLen) || (IPPROTO_ESP == pKeyEx->oProtocol))
        len += sizeof(struct sadb_key) + (PFKEY_DIVROUNDUP(pKeyEx->wEncrKeyLen, 8) * PFKEY_ALIGN);

    if (0 != pKeyEx->wAuthKeyLen)
        len += sizeof(struct sadb_key) + (PFKEY_DIVROUNDUP(pKeyEx->wAuthKeyLen, 8) * PFKEY_ALIGN);

#if 1 /* defined( __ENABLE_IPSEC_NAT_T__) */
    if (pKeyEx->wUdpEncPort)
        len += sizeof(struct sadb_x_nat_t_type) + (2 * sizeof(struct sadb_x_nat_t_port));
#endif

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(pKeyEx->sadb_msg_seq, pPfkey->pid, pKeyEx->oProtocol,
                                       SADB_ADD, 0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the Association extension parameters */
    pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));
    if (OK > (status = pfkey_buildAssocExtension(pKeyEx->dwSpi, pKeyEx->oAuthAlgo,
                                                 pKeyEx->oEncrAlgo, pKeyEx->oAeadIcvLen,
                                                 pSa, SADB_SASTATE_MATURE, 0)))
    {
        goto exit;
    }

    pSa->sadb_sa_replay = pKeyEx->sadb_sa_replay;

    if (IPSEC_SA_FLAG_PFS & pKeyEx->flags)
        pSa->sadb_sa_flags = SADB_SAFLAGS_PFS;

    if (!pKeyEx->oEncrAlgo && (IPPROTO_ESP == pKeyEx->oProtocol))
        pSa->sadb_sa_encrypt = SADB_EALG_NULL;

    /* Fill in SADB_X_EXT_SA2 extension */
    pTemp = (ubyte *)(pSa + 1);
    pSa2 = (struct sadb_x_sa2 *)pTemp;
    pfkey_buildXAssoc2Extension(pKeyEx->oMode, pKeyEx->cookie, pSa2);
    pAddr = (struct sadb_address *)(pSa2 + 1);

    /* Fill in the lifetime extension parameters, if necessary */
    if (0 != pKeyEx->dwExpKBytes || 0 != pKeyEx->dwExpSecs)
    {
        pTemp = (ubyte *)(pSa2 + 1);
        status = pfkey_buildLifetimeExtension(pKeyEx, (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_SOFT);

        if (OK > status)
            goto exit;

        pTemp += sizeof(struct sadb_lifetime);
        status = pfkey_buildLifetimeExtension(pKeyEx, (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_HARD);

        if (OK > status)
            goto exit;

        pAddr = (struct sadb_address *)(pTemp + sizeof(struct sadb_lifetime));
    }

    /* Fill in the address extension parameters */
    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, pKeyEx->dwSrcAddr, pAddr)))
        goto exit;

    pTemp = (ubyte *)pAddr + addr_len;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST, pKeyEx->dwDestAddr, (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    if (0 != pKeyEx->wAuthKeyLen)
    {
        status = pfkey_buildKeyExtension((struct sadb_key *)pTemp,
                                         SADB_EXT_KEY_AUTH,
                                         pKeyEx->poAuthKey,
                                         pKeyEx->wAuthKeyLen * 8);

        if (OK > status)
            goto exit;

        pTemp += (PFKEY_DIVROUNDUP(sizeof(struct sadb_key) + pKeyEx->wAuthKeyLen, 8)) * 8;
    }

    if ((0 != pKeyEx->wEncrKeyLen) || (IPPROTO_ESP == pKeyEx->oProtocol))
    {
        status = pfkey_buildKeyExtension((struct sadb_key *)pTemp,
                                         SADB_EXT_KEY_ENCRYPT,
                                         pKeyEx->poEncrKey,
                                         pKeyEx->wEncrKeyLen * 8);

        if (OK > status)
            goto exit;

        pTemp += (PFKEY_DIVROUNDUP(sizeof(struct sadb_key) + pKeyEx->wEncrKeyLen, 8)) * 8;
    }

#if 1 /* defined( __ENABLE_IPSEC_NAT_T__) */
    if (pKeyEx->wUdpEncPort)
    {
        if (IPSEC_SA_FLAG_INBOUND & pKeyEx->flags)
            pfkey_buildXNatTExtensions(pTemp, pKeyEx->wUdpEncPort, 4500);
        else
            pfkey_buildXNatTExtensions(pTemp, 4500, pKeyEx->wUdpEncPort);

        pTemp += sizeof(struct sadb_x_nat_t_type) + (2 * sizeof(struct sadb_x_nat_t_port));
    }
#endif

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_add */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_DELETE message for the specified key.

@details    This function builds an SADB_DELETE message for the specified key.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param pKey     Pointer to key to delete.
@param ppMsg    Address of pointer which on return contains the SADB_DELETE
                  message.
@param pLen     On return, pointer to number of bytes in SADB_DELETE message
                  (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_delete(pfKeyCb *pPfkey, struct ipsecKey *pKey, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*              pMsg = NULL;
    ubyte*              pTemp;
    struct sadb_sa*     pSa;
    ubyte2              len, addr_len;
    MSTATUS             status = OK;

    MOC_IP_ADDRESS_S    dwSrcAddr, dwDestAddr;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    if (!pKey)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & pKey->flags)
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in6)), 8)) * 8);

        if (pKey->dwSrcAddr)
        {
            SET_MOC_IPADDR6(dwSrcAddr, pKey->dwSrcAddr);
        }
        else
        {
            ZERO_MOC_IPADDR(dwSrcAddr);
            dwSrcAddr.family = AF_INET6;
        }

        if (pKey->dwDestAddr)
        {
            SET_MOC_IPADDR6(dwDestAddr, pKey->dwDestAddr);
        }
        else
        {
            ZERO_MOC_IPADDR(dwDestAddr);
            dwDestAddr.family = AF_INET6;
        }
    }
    else
#endif
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)) * 8);

        SET_MOC_IPADDR4(dwSrcAddr, pKey->dwSrcAddr);
        SET_MOC_IPADDR4(dwDestAddr, pKey->dwDestAddr);
    }

    len = sizeof(struct sadb_msg);

    if (pKey->dwSpi) /* !!! */
        len += sizeof(struct sadb_sa);
    len += 2 * addr_len;

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    pPfkey->seqNo++;
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, pKey->oProtocol,
                                       SADB_DELETE, 0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the spi field in the Association extension, all other fields
     * will be ignored by the PFKEY server
     */
    if (pKey->dwSpi) /* !!! */
    {
        pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));
        if (OK > (status = pfkey_buildAssocExtension(pKey->dwSpi, 0, 0, 0, pSa,
                                                     SADB_SASTATE_MATURE, 1)))
        {
            goto exit;
        }
        pTemp = (ubyte *)(pSa + 1);
    }
    else
    {
        pTemp = pMsg + sizeof(struct sadb_msg);
    }

    /* Fill in the address extension parameters */
    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, REF_MOC_IPADDR(dwSrcAddr), (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST, REF_MOC_IPADDR(dwDestAddr), (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_delete */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_UPDATE message for the specified key.

@details    This function builds an SADB_UPDATE message. Data for the key to
            be updated is specified in the \p pKeyEx parameter.

@ingroup    pfkey_functions

@since 3.2
@version 4.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param pKeyEx   Pointer to data to use for the updated key.
@param ppMsg    Address of pointer which on return contains the SADB_UPDATE
                  message.
@param pLen     On return, pointer to number of bytes in SADB_UPDATE message
                  (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_update(pfKeyCb *pPfkey, struct ipsecKeyEx *pKeyEx, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*                  pMsg = NULL;
    ubyte*                  pTemp;
    struct sadb_sa*         pSa;
    struct sadb_x_sa2*      pSa2;
    struct sadb_address*    pAddr;
    ubyte2                  len, addr_len;
    MSTATUS                 status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    if (!pKeyEx)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    TEST_MOC_IPADDR6(pKeyEx->dwDestAddr,
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in6)), 8)) * 8);
    })
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)) * 8);
    }

    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa) + sizeof(struct sadb_x_sa2);
    len += 2 * addr_len;

    /* allocate for soft & hard lifetimes */
    if ((0 != pKeyEx->dwExpKBytes) || (0 != pKeyEx->dwExpSecs))
        len += 2*sizeof(struct sadb_lifetime);

    if ((0 != pKeyEx->wEncrKeyLen) || (IPPROTO_ESP == pKeyEx->oProtocol))
        len += sizeof(struct sadb_key) + (PFKEY_DIVROUNDUP(pKeyEx->wEncrKeyLen, 8) * PFKEY_ALIGN);

    if (0 != pKeyEx->wAuthKeyLen)
        len += sizeof(struct sadb_key) + (PFKEY_DIVROUNDUP(pKeyEx->wAuthKeyLen, 8) * PFKEY_ALIGN);

#if 1 /* defined( __ENABLE_IPSEC_NAT_T__) */
    if (pKeyEx->wUdpEncPort)
        len += sizeof(struct sadb_x_nat_t_type) + (2 * sizeof(struct sadb_x_nat_t_port));
#endif

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(pKeyEx->sadb_msg_seq, pPfkey->pid, pKeyEx->oProtocol,
                                       SADB_UPDATE, 0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the Association extension parameters */
    pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));
    if (OK > (status = pfkey_buildAssocExtension(pKeyEx->dwSpi, pKeyEx->oAuthAlgo,
                                                 pKeyEx->oEncrAlgo, pKeyEx->oAeadIcvLen,
                                                 pSa, 0/*SADB_SASTATE_MATURE*/, 0)))
    {
        goto exit;
    }

    pSa->sadb_sa_replay = pKeyEx->sadb_sa_replay;

    if (IPSEC_SA_FLAG_PFS & pKeyEx->flags)
        pSa->sadb_sa_flags = SADB_SAFLAGS_PFS;

    if (!pKeyEx->oEncrAlgo && (IPPROTO_ESP == pKeyEx->oProtocol))
        pSa->sadb_sa_encrypt = SADB_EALG_NULL;

    /* Fill in SADB_X_EXT_SA2 extension */
    pTemp = (ubyte *)(pSa + 1);
    pSa2 = (struct sadb_x_sa2 *)pTemp;
    pfkey_buildXAssoc2Extension(pKeyEx->oMode, pKeyEx->cookie, pSa2);
    pAddr = (struct sadb_address *)(pSa2 + 1);

    /* Fill in the lifetime extension parameters, if necessary */
    if (0 != pKeyEx->dwExpKBytes || 0 != pKeyEx->dwExpSecs)
    {
        pTemp = (ubyte *)(pSa2 + 1);
        status = pfkey_buildLifetimeExtension(pKeyEx, (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_SOFT);

        if (OK > status)
            goto exit;

        pTemp += sizeof(struct sadb_lifetime);
        status = pfkey_buildLifetimeExtension(pKeyEx, (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_HARD);

        if (OK > status)
            goto exit;

        pAddr = (struct sadb_address *)(pTemp + sizeof(struct sadb_lifetime));
    }

    /* Fill in the address extension parameters */
    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, pKeyEx->dwSrcAddr, pAddr)))
        goto exit;

    pTemp = (ubyte *)pAddr + addr_len;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST, pKeyEx->dwDestAddr, (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    if (0 != pKeyEx->wAuthKeyLen)
    {
        status = pfkey_buildKeyExtension((struct sadb_key *)pTemp,
                                         SADB_EXT_KEY_AUTH,
                                         pKeyEx->poAuthKey,
                                         pKeyEx->wAuthKeyLen * 8);
        if (OK > status)
            goto exit;

        pTemp += (PFKEY_DIVROUNDUP(sizeof(struct sadb_key) + pKeyEx->wAuthKeyLen, 8)) * 8;
    }

    if ((0 != pKeyEx->wEncrKeyLen) || (IPPROTO_ESP == pKeyEx->oProtocol))
    {
        status = pfkey_buildKeyExtension((struct sadb_key *)pTemp,
                                         SADB_EXT_KEY_ENCRYPT,
                                         pKeyEx->poEncrKey,
                                         pKeyEx->wEncrKeyLen * 8);
        if (OK > status)
            goto exit;

        pTemp += (PFKEY_DIVROUNDUP(sizeof(struct sadb_key) + pKeyEx->wEncrKeyLen, 8)) * 8;
    }

#if 1 /* defined( __ENABLE_IPSEC_NAT_T__) */
    if (pKeyEx->wUdpEncPort)
    {
        if (IPSEC_SA_FLAG_INBOUND & pKeyEx->flags)
            pfkey_buildXNatTExtensions(pTemp, pKeyEx->wUdpEncPort, 4500);
        else
            pfkey_buildXNatTExtensions(pTemp, 4500, pKeyEx->wUdpEncPort);

        pTemp += sizeof(struct sadb_x_nat_t_type) + (2 * sizeof(struct sadb_x_nat_t_port));
    }
#endif

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_update */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_GET message to retrieve an SA that matches specified
            values.

@details    This function builds an SADB_GET message, which retrieves an SA
            that matches specified values.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey       PF_KEY instance handle, previously returned by PFKEY_init().
@param dwSpi        SPI of SA to retrieve.
@param proto        Protocol of SA to retrieve.
@param dwSrcAddr    Source IP address of SA to retrieve.
@param dwDstAddr    Destination IP address of SA to retrieve.
@param ppMsg        Address of pointer which on return contains the SADB_GET
                      message.
@param pLen         On return, pointer to number of bytes in SADB_GET message
                      (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_get(pfKeyCb *pPfkey, ubyte4 dwSpi, ubyte proto,
          MOC_IP_ADDRESS dwSrcAddr, MOC_IP_ADDRESS dwDstAddr,
          ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*              pMsg = NULL;
    ubyte*              pTemp;
    ubyte2              len, addr_len;
    struct sadb_sa*     pSa;
    MSTATUS             status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    TEST_MOC_IPADDR6(dwDstAddr,
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in6)), 8)) * 8);
    })
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)) * 8);
    }

    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 * addr_len;

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    pPfkey->seqNo++;
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, proto,
                                       SADB_GET, 0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the Association extension parameters */
    pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));

    if (OK > (status = pfkey_buildAssocExtension(dwSpi, 0, 0, 0, pSa, SADB_SASTATE_MATURE, 1)))
        goto exit;

    pTemp = (ubyte *)(pSa + 1);

    /* Fill in the address extension parameters */
    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, dwSrcAddr, (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST, dwDstAddr, (struct sadb_address *)pTemp)))
        goto exit;

    /*pTemp += addr_len;*/

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_get */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_GETSPI message to get an SPI value.

@details    This function builds an SADB_GETSPI message, which applications
            use to get an SA's SPI value (security parameter index that
            uniquely identifies an SA) before adding the SA.

@ingroup    pfkey_functions

@since 3.2
@version 4.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey       PF_KEY instance handle, previously returned by PFKEY_init().
@param pKey         Pointer to data to use for the returned SPI.
@param ppMsg        Address of pointer which on return contains the
                      SADB_GETSPI message.
@param pLen         On return, pointer to number of bytes in SADB_GETSPI
                      message (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_getSPI(pfKeyCb *pPfkey, struct ipsecKey *pKey, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*              pMsg = NULL;
    ubyte*              pTemp;
    ubyte2              len, addr_len;
    MSTATUS             status = OK;

    MOC_IP_ADDRESS_S    dwSrcAddr, dwDestAddr;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    if (!pKey)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & pKey->flags)
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in6)), 8)) * 8);

        SET_MOC_IPADDR6(dwSrcAddr, pKey->dwSrcAddr);
        SET_MOC_IPADDR6(dwDestAddr, pKey->dwDestAddr);
    }
    else
#endif
    {
        addr_len = (ubyte2)
                   ((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                       sizeof(struct sockaddr_in)), 8)) * 8);

        SET_MOC_IPADDR4(dwSrcAddr, pKey->dwSrcAddr);
        SET_MOC_IPADDR4(dwDestAddr, pKey->dwDestAddr);
    }

    len = sizeof(struct sadb_msg);
    len += 2 * addr_len;
    len += sizeof(struct sadb_x_sa2);

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    if ((IPSEC_SA_FLAG_INITIATOR & pKey->flags) || pKey->dwSeqNo)
    {
        if (OK > (status = pfkey_buildBase(pKey->dwSeqNo, pPfkey->pid, pKey->oProtocol,
                                           SADB_GETSPI, 0, len, (struct sadb_msg *)pMsg)))
        {
            goto exit;
        }
    }
    else
    {
        pPfkey->seqNo++;
        if (!pPfkey->seqNo) pPfkey->seqNo = 1; /* jic */

        if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, pKey->oProtocol,
                                           SADB_GETSPI, 0, len, (struct sadb_msg *)pMsg)))
        {
            goto exit;
        }
        pKey->dwSeqNo = pPfkey->seqNo;
    }

    pTemp = (ubyte *)(pMsg + sizeof(struct sadb_msg));

    /* Fill in the address extension parameters */
    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, REF_MOC_IPADDR(dwSrcAddr), (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST, REF_MOC_IPADDR(dwDestAddr), (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += addr_len;

    /* Fill in SADB_X_EXT_SA2 extension */
    pfkey_buildXAssoc2Extension(pKey->oMode, pKey->cookie, (struct sadb_x_sa2 *)pTemp);
    /*ptemp += sizeof(struct sadb_x_sa2);*/

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_getSPI */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_DUMP message to send to IPsec to get information
            about all SAs of the specified type.

@details    This function builds an SADB_DUMP message to send to NanoSec IPsec
            to retrieve information about all SAs of the specified type.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param proto    SA protocol (IPPROTO_AH, IPPROTO_ESP, or 0 for both).
@param ppMsg    Address of pointer which on return contains the SADB_DUMP
                  message.
@param pLen     On return, pointer to number of bytes in SADB_DUMP message
                  (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_dump(pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*  pMsg = NULL;
    ubyte2  len;
    MSTATUS status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    len = sizeof(struct sadb_msg);

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    pPfkey->seqNo++;
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, proto,
                                       SADB_DUMP, 0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_dump */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_FLUSH message to send to IPsec to flush all SAs of
            the specified type.

@details    This function builds an SADB_FLUSH message to send to NanoSec 
            IPsec to flush all SAs of the specified type.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param proto    SA protocol (IPPROTO_AH, IPPROTO_ESP, or 0 for both).
@param ppMsg    Address of pointer which on return contains the SADB_FLUSH
                  message.
@param pLen     On return, pointer to number of bytes in SADB_FLUSH message
                  (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_flush(pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*  pMsg = NULL;
    ubyte2  len;
    MSTATUS status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    len = sizeof(struct sadb_msg);

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    pPfkey->seqNo++;
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, proto,
                                       SADB_FLUSH, 0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_flush */


/*------------------------------------------------------------------*/

/* The key mgmt might want to send an SADB_ACQUIRE in case of failure.
 * Not a typical scenario, but still needs to be taken care of as defined in
 * the rfc
 */

/**
@brief      Build an SADB_ACQUIRE message to send to the kernel to indicate a
            failure.

@details    This function builds an SADB_ACQUIRE message, which applications
            send to the kernel to indicate a failure after previously
            receiving an SADB_ACQUIRE message from the kernel.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param proto    SA protocol (\c IPPROTO_AH or \c IPPROTO_ESP).
@param errorNo  Error number to send to IPsec.
@param ppMsg    Address of pointer which on return contains the SADB_GETSPI
                  message.
@param pLen     On return, pointer to number of bytes in SADB_ACQUIRE message
                  (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_acquire(pfKeyCb *pPfkey, ubyte proto, ubyte errorNo, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*  pMsg = NULL;
    ubyte2  len;
    MSTATUS status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    len = sizeof(struct sadb_msg);

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, proto,
                                       SADB_ACQUIRE, errorNo, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_acquire */


/*------------------------------------------------------------------*/

/* This is the entry point for msgs received from the kernel. This api should
 * be called in order to pass them to the IKE server.
 */

/**
@brief      Parse a PF_KEY message received from NanoSec IPsec.

@details    This function parses a PF_KEY message received from IPsec, and
            takes appropriate action. Additionally, this function parses the
            responses for the PF_KEY msgs sent by the application.

In case of error, the error callback function, fnCallBack::pfkey_funcPtrError
(which is registered in PFKEY_init()) will be invoked. The
fnCallBack::pfkey_funcPtrResponse is invoked to pass back any necessary
information to the application.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfKey   PF_KEY instance handle, previously returned by PFKEY_init().
@param pMsg     Pointer to received PF_KEY message to parse.
@param msgLen   Number of bytes in received message (\p pPfkey).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_parse(pfKeyCb *pPfKey, ubyte *pMsg, ubyte2 msgLen)
{
    struct sadb_msg*    pBase = (struct sadb_msg *)pMsg;
    pfKeyResponse       pfKeyResp = { 0 };
    pfKeyError          pfKeyErr;

    MSTATUS             status = OK;

    if ((!pPfKey) || (!pBase) || (msgLen < (ubyte2)(8 * pBase->sadb_msg_len)))
    {
        status = ERR_PFKEY_PARSE;
        goto exit;
    }

    /* do a check on msgLen */
    if (PF_KEY_V2 != pBase->sadb_msg_version)
    {
        status = ERR_PFKEY_VERSION;
        goto exit;
    }

#if defined(__ENABLE_ALL_DEBUGGING__)
    printf("%s: cmd=%d seq=%d pid=%d\n", __FUNCTION__,
           (int)pBase->sadb_msg_type,
           (int)pBase->sadb_msg_seq,
           (int)pBase->sadb_msg_pid);
#endif

    switch (pBase->sadb_msg_type)
    {
        case SADB_REGISTER:
        {
            pfKeyRegisterResponse* pRegResp;

            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }

            if (pBase->sadb_msg_errno)
            {
                if (pPfKey->fnCallBack.pfkey_funcPtrError)
                {
                    pfKeyErr.errnum = pBase->sadb_msg_errno;
                    pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                    pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                    pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                }
                break;
            }

            if (OK > (status = pfkey_parseRegisterResponse(pMsg, &pRegResp)))
                pfKeyResp.pfkeyStatus = status;
            else
                pfKeyResp.pData = pRegResp;

            /* issue a callback to the application with the response */
            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                pfKeyResp.pfkeyCmd = SADB_REGISTER;
                pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        case SADB_UPDATE:
        case SADB_ADD:
        {
            struct ipsecKey *pKey = NULL;

            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }

            if (pBase->sadb_msg_errno)
            {
                DEBUG_PRINT(DEBUG_PFKEY_MESSAGE, (sbyte *)"Msg type -");
                DEBUG_INT(DEBUG_PFKEY_MESSAGE, pBase->sadb_msg_type);
                DEBUG_ERROR(DEBUG_PFKEY_MESSAGE, (sbyte *)"received error -",
                            pBase->sadb_msg_errno);

                if (pPfKey->fnCallBack.pfkey_funcPtrError)
                {
                    pfKeyErr.errnum = pBase->sadb_msg_errno;
                    pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                    pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                    pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                }
                break;
            }

            if (OK > (status = pfkey_parseAddResponse(pMsg, msgLen, &pKey)))
                pfKeyResp.pfkeyStatus = status;
            else
                pfKeyResp.pData = pKey;

            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                pfKeyResp.pfkeyCmd = pBase->sadb_msg_type;
                pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        case SADB_DELETE:
        {
            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }

            if (pBase->sadb_msg_errno)
            {
                if (pPfKey->fnCallBack.pfkey_funcPtrError)
                {
                    pfKeyErr.errnum = pBase->sadb_msg_errno;
                    pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                    pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                    pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                }
                break;
            }
/*
            if (OK > (status = pfkey_parseDeleteResponse(pMsg, msgLen)))
                pfKeyResp.pfkeyStatus = status;
*/
            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                pfKeyResp.pfkeyCmd = SADB_DELETE;
                pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        case SADB_ACQUIRE:
        {
            /* this msg has to be from the kernel */
            if (0 != pBase->sadb_msg_pid)
            {
                goto exit;
            }

            status = pfkey_parseAcquire(pPfKey, pBase, msgLen);
            break;
        }

        case SADB_EXPIRE:
        {
            /* this msg has to be from the kernel */
            if (0 != pBase->sadb_msg_pid)
            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }

            status = pfkey_parseExpire(pPfKey, pBase, msgLen);
            break;
        }

        case SADB_GETSPI:
        {
            pfKeyGetSpiResponse *pSpiResp;

            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }

            if (pBase->sadb_msg_errno)
            {
                if (pPfKey->fnCallBack.pfkey_funcPtrError)
                {
                    pfKeyErr.errnum = pBase->sadb_msg_errno;
                    pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                    pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                    pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                }
                break;
            }

            if (OK > (status = pfkey_parseGetSpi(pBase, msgLen, &pSpiResp)))
                pfKeyResp.pfkeyStatus = status;
            else
                pfKeyResp.pData = pSpiResp;

            /* issue a callback to the application with the */
            /* registered response */
            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                pfKeyResp.pfkeyCmd = SADB_GETSPI;
                pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        case SADB_FLUSH:
        case SADB_X_SPDFLUSH:
        {
            if (pBase->sadb_msg_errno)
            {
                if (pPfKey->pid == pBase->sadb_msg_pid) /* for me */
                {
                    if (pPfKey->fnCallBack.pfkey_funcPtrError)
                    {
                        pfKeyErr.errnum = pBase->sadb_msg_errno;
                        pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                        pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                        pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                    }
                }
                break;
            }

            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                if (pPfKey->pid == pBase->sadb_msg_pid) /* for me */
                {
                    pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                }

                pfKeyResp.pfkeyCmd = pBase->sadb_msg_type;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        case SADB_GET:
        case SADB_DUMP:
        {
            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }

            if (pBase->sadb_msg_errno)
            {
                if (pPfKey->fnCallBack.pfkey_funcPtrError)
                {
                    pfKeyErr.errnum = pBase->sadb_msg_errno;
                    pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                    pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                    pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                }
                break;
            }

            if (OK > (status = pfkey_parseGet(pBase, msgLen)))
                pfKeyResp.pfkeyStatus = status;

            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                pfKeyResp.pfkeyCmd = pBase->sadb_msg_type;
                pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        case SADB_X_SPDGET:
        case SADB_X_SPDDUMP:
            if (pPfKey->pid != pBase->sadb_msg_pid)
            {
                /* Not for me */
                goto exit;
            }
            /* fall through */
        case SADB_X_SPDUPDATE:
        case SADB_X_SPDADD:
        case SADB_X_SPDDELETE:
        {
            struct ipsecConf *pConf = NULL;

            if (pBase->sadb_msg_errno)
            {
                if (pPfKey->pid == pBase->sadb_msg_pid) /* for me */
                if (pPfKey->fnCallBack.pfkey_funcPtrError)
                {
                    pfKeyErr.errnum = pBase->sadb_msg_errno;
                    pfKeyErr.pfkeyCmd = pBase->sadb_msg_type;
                    pfKeyErr.pfkeySeq = pBase->sadb_msg_seq;

                    pPfKey->fnCallBack.pfkey_funcPtrError(&pfKeyErr);
                }
                break;
            }

            if (OK > (status = pfkey_parseSpdGet(pMsg, msgLen, &pConf)))
            {
                if (pPfKey->pid != pBase->sadb_msg_pid) /* not for me */
                    goto exit;

                pfKeyResp.pfkeyStatus = status;
            }
            else
            {
                pfKeyResp.pData = pConf;
            }

            if (pPfKey->fnCallBack.pfkey_funcPtrResponse)
            {
                if (pPfKey->pid == pBase->sadb_msg_pid) /* for me */
                pfKeyResp.pfkeySeq = pBase->sadb_msg_seq;
                pfKeyResp.pfkeyCmd = pBase->sadb_msg_type;
                pPfKey->fnCallBack.pfkey_funcPtrResponse(&pfKeyResp);
            }
            break;
        }

        default:
        {
            status = ERR_PFKEY_INVALID_MSGTYPE;
            goto exit;
            break;
        }
    }

#if defined(__ENABLE_ALL_DEBUGGING__)
    if (OK > status)
        printf("%s: status=%d\n", __FUNCTION__, (int)status);
#endif

exit:
    if (pfKeyResp.pData) FREE(pfKeyResp.pData);
    return status;
} /* PFKEY_parse */


/*------------------------------------------------------------------*/

/**
@brief      Build an SADB_X_SPDDUMP message to send to the kernel.

@details    This function builds an SADB_X_SPDDUMP message, which applications
            send to the kernel so that it will print all existing SPD entries
            to the console.

@ingroup    pfkey_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PFKEY__

@inc_file pfkey.h

@param pPfkey   PF_KEY instance handle, previously returned by PFKEY_init().
@param proto    Protocol type for SAs to be dumped (printed).
@param ppMsg    Address of pointer which on return contains the SADB_X_SPDDUMP
                  message.
@param pLen     On return, pointer to number of bytes in SADB_X_SPDDUMP
                  message (\p ppMsg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pfkey.c
*/
extern MSTATUS
PFKEY_spdDump(pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen)
{
    ubyte*  pMsg = NULL;
    ubyte2  len;
    MSTATUS status = OK;

    if (!ppMsg || !pLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPfkey)
    {
        status = ERR_PFKEY_INVALID_HANDLE;
        goto exit;
    }

    if ((IPPROTO_AH != proto) && (IPPROTO_ESP != proto))
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    len = sizeof(struct sadb_msg);

    if (NULL == (pMsg = *ppMsg))
    {
        if (NULL == (pMsg = MALLOC(len)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        if (len > *pLen)
        {
            status = ERR_MEM_ALLOC_SIZE;
            goto exit;
        }
    }

    DIGI_MEMSET(pMsg, 0x00, len);

    /* Fill in the base parameters */
    pPfkey->seqNo++;
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pPfkey->pid, proto, SADB_X_SPDDUMP, 0, len,
                                       (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* return values */
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = len;

exit:
    if ((OK > status) && pLen)
        *pLen = 0;

    if (pMsg && !(ppMsg && *ppMsg))
        FREE(pMsg);

    return status;
} /* PFKEY_spdDump */


#endif /* __ENABLE_DIGICERT_PFKEY__ */

