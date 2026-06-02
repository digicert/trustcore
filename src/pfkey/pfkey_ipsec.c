/**
 * @file  pfkey_ipsec.c
 * @brief PF_KEY Kernel Interface - IPSec Integration
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_PFKEY__
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
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

#if defined(__ENABLE_DIGICERT_PFKEY__ ) && defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)
#if defined(__LINUX_RTOS__)
#include <linux/in.h>
#endif
#if defined(__OPENBSD_RTOS__) || defined(__SOLARIS_RTOS__)
#include <netinet/in.h>
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
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/sadb.h"

#include "../pfkey/pfkeyv2_common.h"
#include "../pfkey/pfkey_ipsec.h"


/*------------------------------------------------------------------*/

/* useful macro for making sure we don't integer overflow from an attack */
#define ADJUST_LEN_MACRO(X)       { if (len < (X)) { status = ERR_PFKEY_PARSE_BAD_LENGTH; printk("len = %d, X = %d\n", len,X); goto exit; } len -= (X); }

#define PROTO_MOC_TO_SADB(X)      { if (IPPROTO_AH == (X)) { proto = SADB_SATYPE_AH; } else if (IPPROTO_ESP == (X)) { proto = SADB_SATYPE_ESP; } else { status = ERR_PFKEY_PROTOCOL_TYPE; goto exit;}}

#define PROTO_SADB_TO_MOC(X)      { if (SADB_SATYPE_AH == (X)) { proto = IPPROTO_AH; } else if (SADB_SATYPE_ESP == (X)) { proto = IPPROTO_ESP; } else { status = ERR_PFKEY_PROTOCOL_TYPE; goto exit;}}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildErrorResponse(ubyte *pMsg, ubyte err, ubyte **ppResp, ubyte2 *pLen)
{
    struct sadb_msg*       pBase;
    ubyte*                 pResp = NULL;
    ubyte2                 respLen = 0;
    MSTATUS                status;

    respLen = sizeof(struct sadb_msg);
    pResp = KERNEL_MALLOC(respLen);
    if (NULL == pResp)
    {
        printk("alloc failure \n");
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pResp, pMsg, respLen);

    pBase = (struct sadb_msg *)pResp;
    pBase->sadb_msg_len = respLen/8;
    pBase->sadb_msg_errno = err;

    *pLen = respLen;
    *ppResp = pResp;
    pResp = NULL;

exit:
    if (pResp)
        KERNEL_FREE(pResp);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildLifetimeExtension(ubyte4 expBytes, ubyte4 addTime, ubyte4 useTime,
                             struct sadb_lifetime *pLifetime, ubyte2 extType)
{
    printk("Inside pfkey_buildLifetimeExtension bytes = %d,addtime = %d, usetime = %d\n", expBytes, addTime, useTime);
    pLifetime->sadb_lifetime_len     = (sizeof(struct sadb_lifetime) / 8);
    pLifetime->sadb_lifetime_exttype = extType;
    pLifetime->sadb_lifetime_bytes   = u8_Add32(pLifetime->sadb_lifetime_bytes, expBytes);
    pLifetime->sadb_lifetime_addtime = u8_Add32(pLifetime->sadb_lifetime_addtime, addTime);
    pLifetime->sadb_lifetime_usetime = u8_Add32(pLifetime->sadb_lifetime_usetime, useTime);

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildProposalExtension(ubyte numProp, pfKeyProposal *pProp, ubyte *pTemp)
{
    struct sadb_prop*   pSadbProp = (struct sadb_prop *)pTemp;
    struct sadb_comb*   pComb;
    ubyte               i;
    MSTATUS             status = OK;

    pSadbProp->sadb_prop_exttype = SADB_EXT_PROPOSAL;
    pSadbProp->sadb_prop_len = (sizeof(struct sadb_prop) + PFKEY_DIVROUNDUP(numProp * sizeof(struct sadb_comb), 8) * 8) / 8;

    pComb = (struct sadb_comb *)(pSadbProp + 1);

    for (i=0; i < numProp; i++, pProp++)
    {
        switch (pProp->authAlgo)
        {
            case IPSEC_AUTHALG_MD5:
            {
                pComb->sadb_comb_auth  = SADB_AALG_MD5HMAC;
                break;
            }

            case IPSEC_AUTHALG_SHA1:
            {
                pComb->sadb_comb_auth = SADB_AALG_SHA1HMAC;
                break;
            }

            case IPSEC_AUTHALG_SHA256:
            {
                pComb->sadb_comb_auth = SADB_X_AALG_SHA2_256HMAC;
                break;
            }

            case IPSEC_AUTHALG_SHA384:
            {
                pComb->sadb_comb_auth = SADB_X_AALG_SHA2_384HMAC;
                break;
            }

            case IPSEC_AUTHALG_SHA512:
            {
                pComb->sadb_comb_auth = SADB_X_AALG_SHA2_512HMAC;
                break;
            }

            default:
            {
                printk("Unknown auth algo\n");
                status = ERR_PFKEY_INVALID_PARAMETER;
                goto exit;
            }
        }

        switch (pProp->encrAlgo)
        {
            case IPSEC_ENCALG_ANY:
            {
                pComb->sadb_comb_encrypt = SADB_EALG_NONE;
                break;
            }

            case IPSEC_ENCALG_DES:
            {
                pComb->sadb_comb_encrypt = SADB_EALG_DESCBC;
                break;
            }

            case IPSEC_ENCALG_3DES:
            {
                pComb->sadb_comb_encrypt = SADB_EALG_3DESCBC;
                break;
            }

            case IPSEC_ENCALG_BLOWFISH:
            {
                pComb->sadb_comb_encrypt = SADB_X_EALG_BLOWFISHCBC;
                break;
            }

            case IPSEC_ENCALG_AES:
            {
                pComb->sadb_comb_encrypt = SADB_X_EALG_AESCBC;
                break;
            }

            default:
            {
                printk("Unknown encrypt algo\n");
                status = ERR_PFKEY_INVALID_PARAMETER;
                goto exit;
            }

        } /* switch (pProp->encrAlgo) */

        pComb->sadb_comb_auth_minbits = pProp->authAlgMinBytes * 8;
        pComb->sadb_comb_auth_maxbits = pProp->authAlgMaxBytes * 8;
        pComb->sadb_comb_encrypt_minbits = pProp->encrAlgMinBytes * 8;
        pComb->sadb_comb_encrypt_maxbits = pProp->encrAlgMaxBytes * 8;
        pComb->sadb_comb_soft_allocations =  pProp->softAllocs;
        pComb->sadb_comb_hard_allocations =  pProp->hardAllocs;
        pComb->sadb_comb_soft_bytes = u8_Add(pComb->sadb_comb_soft_bytes, pProp->softBytes);
        pComb->sadb_comb_hard_bytes = u8_Add(pComb->sadb_comb_hard_bytes, pProp->hardBytes);
        pComb->sadb_comb_soft_addtime = u8_Add(pComb->sadb_comb_soft_addtime, pProp->softAddtime);
        pComb->sadb_comb_hard_addtime = u8_Add(pComb->sadb_comb_hard_addtime, pProp->hardAddtime);
        pComb->sadb_comb_soft_usetime = u8_Add(pComb->sadb_comb_soft_usetime, pProp->softUsetime);
        pComb->sadb_comb_hard_usetime = u8_Add(pComb->sadb_comb_hard_usetime, pProp->hardUsetime);
        pComb++;

    } /* for */

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PFKEY_expire(ubyte4 seq, ubyte4 pid, SADB ppxSa, ubyte **ppMsg, ubyte2 *pLen)
{
    ubyte*                  pMsg = NULL;
    ubyte*                  pTemp;
    struct sadb_sa*         pSa;
    struct sadb_address*    pAddr = NULL;
    ubyte2                  len;
    ubyte                   state = 0;
    MSTATUS                 status = OK;
    ubyte                   authAlgo = 0;
    ubyte                   encrAlgo = 0;

    *ppMsg = NULL;
    *pLen = 0;

    printk("PFKEY_expire called\n");

    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) + sizeof(struct sockaddr_in)), 8)) * 8);
    /* allocate for current and one of soft & hard lifetimes */
    len += 2*sizeof(struct sadb_lifetime);

    pMsg = KERNEL_MALLOC(len);
    if (NULL == pMsg)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(seq, pid, ppxSa->oSaProto, SADB_EXPIRE,
                                       0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the Association extension parameters */
    if (ppxSa->saFlags & IPSEC_SA_FLAG_DELETED)
        state = SADB_SASTATE_DEAD;
    else if (ppxSa->saFlags & IPSEC_SA_FLAG_MATURE)
        state = SADB_SASTATE_MATURE;

    if (ppxSa->pHmacSuite)
    {
        authAlgo = ppxSa->pHmacSuite->oAuthAlgo;
    }

    if (ppxSa->pCipherSuite)
    {
        encrAlgo = ppxSa->pCipherSuite->oEncrAlgo;
    }

    pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));
    if (OK > (status = pfkey_buildAssocExtension(ppxSa->dwSaSpi,
                                                 authAlgo,
                                                 encrAlgo, 0,
                                                 pSa, state, 0)))
    {
        goto exit;
    }

    /* Fill in the lifetime extension parameters, if necessary */
    if ((0 != ppxSa->dwSaExpKBytes) || (0 != ppxSa->dwSaExpSecs))
    {
        pTemp = (ubyte *)(pSa + 1);
        printk("adding soft lifetime, %d\n", ppxSa->dwSaExpSecs);

        status = pfkey_buildLifetimeExtension(ppxSa->dwSaExpKBytes * 1024,
                                              ppxSa->dwSaExpSecs,
                                              ppxSa->dwSaExpSecs,
                                              (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_SOFT);

        if (OK > status)
            goto exit;

        pTemp += sizeof(struct sadb_lifetime);

        status = pfkey_buildLifetimeExtension((ubyte4)(ppxSa->dwSaCurKBytes * 1024 + ppxSa->wSaCurBytes),
                                              ppxSa->dwSaEstablished,
                                              ppxSa->dwSaFirstUsed,
                                              (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_CURRENT);

        if (OK > status)
            goto exit;

        pAddr = (struct sadb_address *)(pTemp + sizeof(struct sadb_lifetime));
    }

    /* Fill in the address extension parameters */
    if (!pAddr)
        pAddr = (struct sadb_address *)(pSa + 1);

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, ppxSa->dwSaSrcAddr, pAddr)))
        goto exit;

    pTemp = (ubyte *)pAddr +
             (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST,
                                                  ppxSa->dwSaDestAddr, (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;
    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = (ubyte4)len;

exit:
    if (pMsg)
        KERNEL_FREE(pMsg);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PFKEY_acquire(pfKeyIpsecCb *pPfkey, ubyte4 pid, SPD pxSp, ubyte numProp, pfKeyProposal *pProp,
              ubyte **ppMsg, ubyte2 *pLen)
{
    ubyte*                  pMsg = NULL;
    ubyte*                  pTemp;
    struct sadb_address*    pAddr = NULL;
    ubyte2                  len;
    MSTATUS                 status = OK;

    *ppMsg = NULL;
    *pLen = 0;

    if (!pxSp || !pProp || 0 == numProp)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    len = sizeof(struct sadb_msg);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) + sizeof(struct sockaddr_in)), 8)) * 8);
    len += sizeof(struct sadb_prop) + (PFKEY_DIVROUNDUP(numProp * sizeof(struct sadb_comb), 8) * 8);

    pMsg = KERNEL_MALLOC(len);
    if (NULL == pMsg)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pMsg, 0x00, len);
    pPfkey->seqNo++;

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(pPfkey->seqNo, pid, pxSp->oProto, SADB_ACQUIRE,
                                       0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the address extension parameters */
    pAddr = (struct sadb_address *)(pMsg + sizeof(struct sadb_msg));

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC,
                                                   pxSp->dwSrcIP, pAddr)))
    {
        goto exit;
    }

    pTemp = (ubyte *)pAddr +
             (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST,
                                                   pxSp->dwDestIP, (struct sadb_address *)pTemp)))
    {
        goto exit;
    }

    pTemp += (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    if (OK > (status = pfkey_buildProposalExtension(numProp, pProp, pTemp)))
    {
        goto exit;
    }

    *ppMsg = pMsg;
    pMsg = NULL;
    *pLen = (ubyte4)len;
    pPfkey->acquireSentFlag = 1;

exit:
    if (pMsg)
        KERNEL_FREE(pMsg);

    return status;
}

/*------------------------------------------------------------------*/


extern MSTATUS
PFKEY_IPSEC_init(ubyte **ppPfkeyCb)
{
    MSTATUS             status = OK;
    pfKeyIpsecCb*       pPfkey = NULL;

    if (!ppPfkeyCb)
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    *ppPfkeyCb = NULL;

    pPfkey = KERNEL_MALLOC(sizeof(pfKeyIpsecCb));
    if (NULL == pPfkey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET( (ubyte *)pPfkey, 0, sizeof( pfKeyIpsecCb ));

    *ppPfkeyCb = (ubyte *)pPfkey;

    pPfkey = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildFlushResponse(ubyte proto, ubyte4 seqNo, ubyte4 pid,
                         ubyte **ppFlushResp, ubyte2 *pLen)
{
    ubyte*    pMsg = NULL;
    ubyte2    len;
    MSTATUS   status = OK;

    *ppFlushResp = NULL;
    *pLen = 0;

    len = sizeof(struct sadb_msg);

    pMsg = KERNEL_MALLOC(len);
    if (NULL == pMsg)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(seqNo, pid, proto, SADB_FLUSH,
                                       0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    *ppFlushResp = pMsg;
    pMsg = NULL;
    *pLen = (ubyte4)len;

exit:
    if (pMsg)
        KERNEL_FREE(pMsg);

    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
pfkey_parseFlush(struct sadb_msg *pBase, ubyte4 len,
                  ubyte **ppFlushResp, ubyte2 *pLen)
{
    ubyte   proto = 0;
    MSTATUS status = OK;

    *ppFlushResp = NULL;

    if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
        proto = IPPROTO_AH;
    else if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
        proto = IPPROTO_ESP;

    /* Currently, there is no function to flush SAs of a particular type, so
     * we flush the complete SADB. In future, if there is such a function
     * available, proto can be passed to it as a parameter.
     */
    status = IPSEC_flushSadb();

    if (OK == status)
    {
        printk("FLUSH success\n");
        status = pfkey_buildFlushResponse(proto, pBase->sadb_msg_seq,
                                      pBase->sadb_msg_pid,
                                          ppFlushResp, pLen);
    }
    else
    {
        printk("FLUSH failure\n");
        pfkey_buildErrorResponse((ubyte *)pBase, 0, ppFlushResp, pLen);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildGetSpiResponse(ubyte4 dwSpi, ubyte proto, ubyte4 seqNo, ubyte4 pid,
                          MOC_IP_ADDRESS dwSrcAddr, MOC_IP_ADDRESS dwDestAddr,
                          ubyte **ppGetSpiResp, ubyte2 *pLen)
{
    ubyte*                  pMsg = NULL;
    ubyte*                  pTemp;
    struct sadb_sa*         pSa;
    struct sadb_address*    pAddr = NULL;
    ubyte2                  len;
    MSTATUS                 status = OK;

    *ppGetSpiResp = NULL;
    *pLen = 0;

    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) + sizeof(struct sockaddr_in)), 8)) * 8);

    pMsg = KERNEL_MALLOC(len);
    if (NULL == pMsg)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(seqNo, pid, proto, SADB_GETSPI,
                                       0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the Association extension parameters */
    pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));
    if (OK > (status = pfkey_buildAssocExtension(dwSpi, 0, 0, 0, pSa, 0, 1)))
    {
        goto exit;
    }

    /* Fill in the address extension parameters */
    pAddr = (struct sadb_address *)(pSa + 1);

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, dwSrcAddr, pAddr)))
        goto exit;

    pTemp = (ubyte *)pAddr +
             (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST, dwDestAddr, (struct sadb_address *)pTemp)))
        goto exit;

    pTemp += (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    *ppGetSpiResp = pMsg;
    pMsg = NULL;
    *pLen = (ubyte4)len;

exit:
    if (pMsg)
        KERNEL_FREE(pMsg);

    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
pfkey_parseGetSpi(struct sadb_msg *pBase, ubyte4 len,
                  ubyte **ppGetSpiResp, ubyte2 *pLen)
{
    struct sadb_ext*        pExt;
    struct sadb_address*    pAddr;
    struct sadb_spirange*   pSpiRange;
    ubyte4                  spiMin;
    ubyte4                  spiMax;
    ubyte4                  dwSpi = 0;
    ubyte                   proto = 0;
    MOC_IP_ADDRESS          dwSrcAddr;
    MOC_IP_ADDRESS          dwDestAddr;
    ubyte*                  pTemp;
    MSTATUS                 status = OK;

    *ppGetSpiResp = NULL;

    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));

    pExt = (struct sadb_ext *)(pBase + 1);
    pTemp = (ubyte *)pExt;

    while ((len) && (pExt))
    {
        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_ADDRESS_SRC:
            {
                pAddr = (struct sadb_address *)pTemp;
                pfkey_parseAddressExtension(pAddr, &dwSrcAddr, NULL, NULL);

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);

                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                pAddr = (struct sadb_address *)pTemp;
                pfkey_parseAddressExtension(pAddr, &dwDestAddr, NULL, NULL);

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);

                break;
            }

            case SADB_EXT_SPIRANGE:
            {
                pSpiRange = (struct sadb_spirange *)pTemp;
                spiMin = ntohl(pSpiRange->sadb_spirange_min);
                spiMax = ntohl(pSpiRange->sadb_spirange_max);

                pTemp += pSpiRange->sadb_spirange_len * 8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pSpiRange->sadb_spirange_len * 8);

                break;
            }

            default:
            {
                if (pExt)
                {
                    pTemp = (ubyte *)pExt;
                    printk("case default\n");

                    ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

                    pTemp += (pExt->sadb_ext_len*8);
                    pExt = (struct sadb_ext *)pTemp;
                }

                break;
            }
        }

    }

    /* Call internal IPSEC function to generate SPI */
    /* status = RANDOM_numberGenerator(g_pRandomContext, (ubyte *)&dwSpi,
                                       sizeof(ubyte4));
     * but how do we get a no. within the specified range??
     *
     */
    if (OK == status)
    {
        if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
            proto = IPPROTO_AH;
        else if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
            proto = IPPROTO_ESP;

        status = pfkey_buildGetSpiResponse(dwSpi, proto, pBase->sadb_msg_seq,
                                           pBase->sadb_msg_pid,
                                           dwSrcAddr, dwDestAddr,
                                           ppGetSpiResp, pLen);
        if (OK > status)
            goto exit;

    }
    else
    {
        /* If the requested SPI is not available, we need to return error EEXIST */
        pfkey_buildErrorResponse((ubyte *)pBase, EEXIST, ppGetSpiResp, pLen);
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
pfkey_buildGetResponse(SADB ppxSa, ubyte4 seqNo, ubyte4 pid, ubyte **pGetResp, ubyte2 *pLen)
{
    ubyte*                  pMsg = NULL;
    ubyte*                  pTemp;
    struct sadb_sa*         pSa;
    struct sadb_address*    pAddr = NULL;
    ubyte2                  len;
    ubyte                   state = 0;
    ubyte                   authAlgo = 0;
    ubyte                   encrAlgo = 0;
    MSTATUS                 status = OK;

    *pGetResp = NULL;
    *pLen = 0;

    if (!ppxSa )
    {
        printk("pfkey_buildGetResponse:  ERR_PFKEY_INVALID_PARAMETER 1\n");
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    if ((!ppxSa->pHmacSuite) && (!ppxSa->pCipherSuite))
    {
        printk("pfkey_buildGetResponse: returning ERR_PFKEY_INVALID_PARAMETER 2\n");
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) + sizeof(struct sockaddr_in)), 8)) * 8);

    if (ppxSa->pHmacSuite->wKeyLen != 0)
    {
        len += (sizeof(struct sadb_key) + (PFKEY_DIVROUNDUP(ppxSa->pHmacSuite->wKeyLen, 8) * PFKEY_ALIGN));
    }

    /* allocate for soft & hard lifetimes */
    if ((0 != ppxSa->dwSaExpKBytes) || (0 != ppxSa->dwSaExpSecs))
        len += 3*sizeof(struct sadb_lifetime);

    if (0 != ppxSa->wEncrKeyLen)
        len += sizeof(struct sadb_key) + (PFKEY_DIVROUNDUP(ppxSa->wEncrKeyLen, 8) * PFKEY_ALIGN);

    printk("pfkey_buildGetResponse: len = %d\n", len);

    pMsg = KERNEL_MALLOC(len);
    if (NULL == pMsg)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pMsg, 0x00, len);

    /* Fill in the base parameters */
    if (OK > (status = pfkey_buildBase(seqNo, pid, ppxSa->oSaProto, SADB_GET,
                                       0, len, (struct sadb_msg *)pMsg)))
    {
        goto exit;
    }

    /* Fill in the Association extension parameters */
    if (ppxSa->saFlags & IPSEC_SA_FLAG_DELETED)
    {
        printk("setting state to SADB_SASTATE_DEAD\n");
        state = SADB_SASTATE_DEAD;
    }
    else if (ppxSa->saFlags & IPSEC_SA_FLAG_MATURE)
    {
        printk("setting state to SADB_SASTATE_MATURE\n");
        state = SADB_SASTATE_MATURE;
    }

    if (ppxSa->pHmacSuite)
        authAlgo = ppxSa->pHmacSuite->oAuthAlgo;

    if (ppxSa->pCipherSuite)
        encrAlgo = ppxSa->pCipherSuite->oEncrAlgo;

    pSa = (struct sadb_sa *)(pMsg + sizeof(struct sadb_msg));
    if (OK > (status = pfkey_buildAssocExtension(ppxSa->dwSaSpi,
                                                 authAlgo,
                                                 encrAlgo, 0,
                                                 pSa, state, 0)))
    {
        printk("pfkey_buildGetResponse: pfkey_buildAssocExtension failed\n");
        goto exit;
    }

    /* Fill in the lifetime extension parameters, if necessary */
    if ((0 != ppxSa->dwSaExpKBytes) || (0 != ppxSa->dwSaExpSecs))
    {
        pTemp = (ubyte *)(pSa + 1);

        status = pfkey_buildLifetimeExtension(ppxSa->dwSaExpKBytes * 1024,
                                              ppxSa->dwSaExpSecs,
                                              ppxSa->dwSaExpSecs,
                                              (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_SOFT);

        if (OK > status)
        {
            printk("pfkey_buildGetResponse: pfkey_buildLifetimeExtension 1 failed\n");
            goto exit;
        }

        pTemp += sizeof(struct sadb_lifetime);

        status = pfkey_buildLifetimeExtension(ppxSa->dwSaExpKBytes * 1024,
                                              ppxSa->dwSaExpSecs,
                                              ppxSa->dwSaExpSecs,
                                              (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_HARD);

        if (OK > status)
        {
            printk("pfkey_buildGetResponse: pfkey_buildLifetimeExtension 2 failed\n");
            goto exit;
        }

        pTemp += sizeof(struct sadb_lifetime);

        status = pfkey_buildLifetimeExtension((ubyte4)(ppxSa->dwSaCurKBytes * 1024 + ppxSa->wSaCurBytes),
                                              ppxSa->dwSaEstablished,
                                              ppxSa->dwSaFirstUsed,
                                              (struct sadb_lifetime *)pTemp,
                                              SADB_EXT_LIFETIME_CURRENT);

        if (OK > status)
        {
            printk("pfkey_buildGetResponse: pfkey_buildLifetimeExtension 3 failed\n");
            goto exit;
        }

        pAddr = (struct sadb_address *)(pTemp + sizeof(struct sadb_lifetime));
    }

    /* Fill in the address extension parameters */
    if (!pAddr)
        pAddr = (struct sadb_address *)(pSa + 1);

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_SRC, ppxSa->dwSaSrcAddr, pAddr)))
    {
        printk("pfkey_buildGetResponse: pfkey_buildAddressExtension 1 failed\n");
        goto exit;
    }

    pTemp = (ubyte *)pAddr + (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    if (OK > (status = pfkey_buildAddressExtension(SADB_EXT_ADDRESS_DST,
                                                  ppxSa->dwSaDestAddr, (struct sadb_address *)pTemp)))
    {
        printk("pfkey_buildGetResponse: pfkey_buildAddressExtension 2 failed\n");
        goto exit;
    }

    pTemp += (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                sizeof(struct sockaddr_in)), 8))*8;

    if (0 != ppxSa->pHmacSuite->wKeyLen)
    {
        printk("pfkey_buildGetResponse: keylen = %d\n", ppxSa->pHmacSuite->wKeyLen);
        printk("key = %x%x%x%x%x%x%x\n", ppxSa->poAuthKey[0], ppxSa->poAuthKey[1],ppxSa->poAuthKey[2],ppxSa->poAuthKey[3],ppxSa->poAuthKey[4],ppxSa->poAuthKey[5],ppxSa->poAuthKey[6]);

        status = pfkey_buildKeyExtension((struct sadb_key *)pTemp,
                                          SADB_EXT_KEY_AUTH,
                                          ppxSa->poAuthKey,
                                          ppxSa->pHmacSuite->wKeyLen * 8);

        if (OK > status)
        {
            printk("pfkey_buildGetResponse: pfkey_buildKeyExtension AUTH failed\n");
            goto exit;
        }

        pTemp += (PFKEY_DIVROUNDUP(sizeof(struct sadb_key) + ppxSa->pHmacSuite->wKeyLen, 8)) * 8;
    }

    if (0 != ppxSa->wEncrKeyLen)
    {
        printk("pfkey_buildGetResponse: keylen 2 = %d\n", ppxSa->pHmacSuite->wKeyLen);
        status = pfkey_buildKeyExtension((struct sadb_key *)pTemp,
                                         SADB_EXT_KEY_ENCRYPT,
                                         ppxSa->poEncrKey,
                                         ppxSa->wEncrKeyLen * 8);

        if (OK > status)
        {
            printk("pfkey_buildGetResponse: pfkey_buildKeyExtension ENCR failed\n");
            goto exit;
        }

        pTemp += (PFKEY_DIVROUNDUP(sizeof(struct sadb_key) + ppxSa->wEncrKeyLen, 8)) * 8;
    }

    *pGetResp = pMsg;
    pMsg = NULL;
    *pLen = (ubyte4)len;

exit:
    if (pMsg)
        KERNEL_FREE(pMsg);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseGet(pfKeyIpsecCb *pPfkey, ubyte *pMsg, ubyte4 len, ubyte **ppGetResp, ubyte2 *pLen)
{
    struct sadb_msg*           pBase = (struct sadb_msg *)pMsg;
    struct sadb_ext*           pExt;
    struct sadb_address*       pAddr;
    ubyte*                     pTemp;
    struct sadb_sa*            pSa;
    ubyte4                     dwSpi = 0;
    MOC_IP_ADDRESS             dwSrcAddr;
    MOC_IP_ADDRESS             dwDestAddr;
    SADB                       pxSa;
    ubyte                      oProto;
    MSTATUS                    status = OK;

    printk("Called pfkey_parseGet\n");

    if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
    {
        oProto = IPPROTO_AH;
    }
    else if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
    {
        oProto = IPPROTO_ESP;
    }
    else
    {
        status = ERR_PFKEY_PROTOCOL_TYPE;
        goto exit;
    }

    ADJUST_LEN_MACRO(sizeof(struct sadb_msg));

    pExt = (struct sadb_ext *)(pBase + 1);
    pTemp = (ubyte *)pExt;

    while (len && pExt)
    {
        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                pSa = (struct sadb_sa *)pTemp;

                dwSpi = DIGI_NTOHL((ubyte *)&pSa->sadb_sa_spi);

                pTemp += (pSa->sadb_sa_len * 8);
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pSa->sadb_sa_len * 8);

                break;
            }

            case SADB_EXT_ADDRESS_SRC:
            {
                pAddr = (struct sadb_address *)pTemp;

                status = pfkey_parseAddressExtension(pAddr, &dwSrcAddr, NULL, NULL);

                pTemp += pAddr->sadb_address_len*8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);

                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                pAddr = (struct sadb_address *)pTemp;

                status = pfkey_parseAddressExtension(pAddr, &dwDestAddr, NULL, NULL);

                pTemp += pAddr->sadb_address_len*8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);
                break;
            }

            default:
            {
                if (pExt)
                {
                    pTemp = (ubyte *)pExt;
                    printk("case default\n");

                    ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

                    pTemp += (pExt->sadb_ext_len*8);
                    pExt = (struct sadb_ext *)pTemp;
                }

                break;
            }
        }
    }

    printk("Calling IPSEC_findSa\n");
    status = IPSEC_findSa(dwSpi, dwDestAddr, dwSrcAddr, oProto, &pxSa);

    if ((OK == status) && (pxSa))
    {
        printk("IPSEC_findSa successful\n");
        status = pfkey_buildGetResponse(pxSa, pBase->sadb_msg_seq,
                                    pBase->sadb_msg_pid,
                                        ppGetResp, pLen);
    }
    else
    {
        printk("IPSEC_findSa failed\n");
        pfkey_buildErrorResponse(pMsg, ESRCH, ppGetResp, pLen);
    }

exit:
    return status;
}/* pfkey_parseGet */

/*------------------------------------------------------------------*/


static MSTATUS
pfkey_buildDeleteResponse(ubyte *pMsg, ubyte **ppResp, ubyte2 *pLen)
{
    struct sadb_msg*    pBase = (struct sadb_msg *)pMsg;
    ubyte*              pResp = NULL;
    ubyte2              respLen = 0;
    MSTATUS             status;

    respLen = (pBase->sadb_msg_len * 8);
    pResp = KERNEL_MALLOC(respLen);
    if (NULL == pResp)
    {
        printk("alloc failure \n");
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pResp, pMsg, respLen);

    *ppResp = pResp;
    *pLen = respLen;
    pResp = NULL;

exit:
    if (pResp)
        KERNEL_FREE(pResp);

    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
pfkey_parseDelete(ubyte *pMsg, ubyte4 msgLen, ubyte **ppDelResponse, ubyte2 *pLen)
{
    struct ipsecKey       delKey;
    struct sadb_msg*      pBase = (struct sadb_msg *)pMsg;
    struct sadb_sa*       pSa;
    struct sadb_ext*      pExt;
    struct sadb_address*  pAddr;
    ubyte*                pTemp;
    ubyte4                len;
    MSTATUS               status = OK;

    *ppDelResponse = NULL;
    *pLen = 0;

    /* length check */
    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) + \
              sizeof(struct sockaddr_in)), 8)) * 8);

    if (msgLen < len)
    {
        status = ERR_PFKEY_INVALID_LEN;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&delKey, 0, sizeof(struct ipsecKeyEx));

    if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
        delKey.oProtocol = IPPROTO_AH;
    else if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
        delKey.oProtocol = IPPROTO_ESP;

    len = msgLen - sizeof(struct sadb_msg);
    pExt = (struct sadb_ext *)(pBase + 1);
    pTemp = (ubyte *)pExt;

    while ((len)  &&  (pExt))
    {
        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                pSa = (struct sadb_sa *)pTemp;
                delKey.dwSpi = DIGI_NTOHL((ubyte *)&pSa->sadb_sa_spi);

                pTemp += (pSa->sadb_sa_len * 8);
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pSa->sadb_sa_len * 8);

                break;
            }

            case SADB_EXT_ADDRESS_SRC:
            {
                pAddr = (struct sadb_address *)pTemp;
                status = pfkey_parseAddressExtension(pAddr, (MOC_IP_ADDRESS *)(&(delKey.dwSrcAddr)), NULL, NULL);

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);
                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                pAddr = (struct sadb_address *)pTemp;
                status = pfkey_parseAddressExtension(pAddr, (MOC_IP_ADDRESS *)(&(delKey.dwDestAddr)), NULL, NULL);

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);
                break;
            }

            default:
            {
                if (pExt)
                {
                    pTemp = (ubyte *)pExt;
                    printk("case default\n");

                    ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

                    pTemp += (pExt->sadb_ext_len*8);
                    pExt = (struct sadb_ext *)pTemp;
                }
                break;
            }
        }
    } /* while */

    printk("Calling IPSEC_keyDelete\n");
    status = IPSEC_keyDelete(&delKey);
    if (OK == status)
    {
        printk("IPSEC_keyDelete returned OK\n");
        status = pfkey_buildDeleteResponse(pMsg, ppDelResponse, pLen);
    }
    else
    {
        printk("IPSEC_keyDelete returned Failure\n");
        pfkey_buildErrorResponse(pMsg, EINVAL, ppDelResponse, pLen);
    }

exit:
    return status;

}/* pfkey_parseDelete */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildAddResponse(ubyte *pMsg, ubyte2 authKeyLen, ubyte2 encrKeyLen,
                             ubyte **ppResp, ubyte2 *pLen)
{
    struct sadb_msg*       pBase = (struct sadb_msg *)pMsg;
    ubyte*                 pResp;
    ubyte*                 pTemp;
    ubyte*                 ptr;
    ubyte2                 len;
    sbyte4                 extLen;
    struct sadb_ext*       pExt;
    MSTATUS                status = OK;
    ubyte2                 respLen = 0;

    respLen = (pBase->sadb_msg_len * 8) - ((2 * sizeof(struct sadb_key)) + (authKeyLen) + (encrKeyLen));

    pResp = KERNEL_MALLOC(respLen);
    if (NULL == pResp)
    {
        printk("alloc failure \n");
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pResp, pBase, sizeof(struct sadb_msg));

    ((struct sadb_msg *)pResp)->sadb_msg_len = respLen / 8;

    len = pBase->sadb_msg_len * 8 - sizeof(struct sadb_msg);
    pExt =  (struct sadb_ext *) (pBase + 1);
    pTemp = pResp + sizeof(struct sadb_msg);

    while ((len) && (pExt))
    {
        extLen = (sbyte4)(pExt->sadb_ext_len * 8);

        if ((SADB_EXT_KEY_AUTH != pExt->sadb_ext_type) && (SADB_EXT_KEY_ENCRYPT != pExt->sadb_ext_type))
        {
            DIGI_MEMCPY(pTemp, pExt, extLen);
            pTemp += extLen;
            printk("copying ext type %d, len %d\n", pExt->sadb_ext_type, extLen);
        }

        ptr = (ubyte *)pExt;
        ptr += extLen;
        pExt = (struct sadb_ext *)ptr;

        ADJUST_LEN_MACRO(extLen);
    }

    *ppResp = pResp;
    *pLen = respLen;
    pResp = NULL;

exit:
    if (pResp)
        KERNEL_FREE(pResp);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseAdd(ubyte *pMsg, ubyte4 msgLen, ubyte **ppAddResponse, ubyte2 *pLen)
{
    struct ipsecKey            addKey;
    struct sadb_msg*           pBase = (struct sadb_msg *)pMsg;
    struct sadb_sa*            pSa;
    struct sadb_key*           pKey;
    struct sadb_ext*           pExt;
    struct sadb_lifetime*      pLifeTime;
    struct sadb_address*       pAddr;
    ubyte4                     len;
    ubyte*                     pTemp;
    ubyte*                     keyPtr;
    sbyte4                     spdId;
    MSTATUS                    status = OK;

    printk("Called parseAdd\n");
    *ppAddResponse = NULL;
    *pLen = 0;

    /* length check */
    len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa);
    len += 2 *((PFKEY_DIVROUNDUP((sizeof(struct sadb_address) + \
              sizeof(struct sockaddr_in)), 8)) * 8) + \
              (2 * sizeof(struct sadb_key));

    if (msgLen < len)
    {
        printk("Returning ERR_PFKEY_INVALID_LEN\n");
        status = ERR_PFKEY_INVALID_LEN;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&addKey, 0, sizeof(struct ipsecKey));

    if (SADB_SATYPE_AH == pBase->sadb_msg_satype)
        addKey.oProtocol = IPPROTO_AH;
    else if (SADB_SATYPE_ESP == pBase->sadb_msg_satype)
        addKey.oProtocol = IPPROTO_ESP;

    addKey.oMode = IPSEC_MODE_TRANSPORT;

    len = msgLen - sizeof(struct sadb_msg);
    pExt = (struct sadb_ext *)(pBase + 1);
    pTemp = (ubyte *)pExt;

    while ((len) && (pExt))
    {
        switch (pExt->sadb_ext_type)
        {
            case SADB_EXT_SA:
            {
                pSa = (struct sadb_sa *)pTemp;
                addKey.dwSpi = DIGI_NTOHL((ubyte *)&pSa->sadb_sa_spi);

                switch (pSa->sadb_sa_auth)
                {
                    case SADB_AALG_MD5HMAC:
                    {
                        addKey.oAuthAlgo = IPSEC_AUTHALG_MD5;
                        break;
                    }

                    case SADB_AALG_SHA1HMAC:
                    {
                        addKey.oAuthAlgo = IPSEC_AUTHALG_SHA1;
                        break;
                    }

                    case SADB_X_AALG_SHA2_256HMAC:
                    {
                        addKey.oAuthAlgo = IPSEC_AUTHALG_SHA256;
                        break;
                    }

                    case SADB_X_AALG_SHA2_384HMAC:
                    {
                        addKey.oAuthAlgo = IPSEC_AUTHALG_SHA384;
                        break;
                    }

                    case SADB_X_AALG_SHA2_512HMAC:
                    {
                        addKey.oAuthAlgo = IPSEC_AUTHALG_SHA512;
                        break;
                    }

                    default:
                    {
                        status = ERR_PFKEY_INVALID_PARAMETER;
                        printk( "Unknown auth algo\n");

                        goto exit;
                    }

                } /* switch (pSa->sadb_sa_auth) */

                switch (pSa->sadb_sa_encrypt)
                {
                    case SADB_EALG_NONE:
                    {
                        pSa->sadb_sa_encrypt = IPSEC_ENCALG_ANY;
                        break;
                    }

                    case SADB_EALG_DESCBC:
                    {
                        pSa->sadb_sa_encrypt = IPSEC_ENCALG_DES;
                        break;
                    }

                    case SADB_EALG_3DESCBC:
                    {
                        pSa->sadb_sa_encrypt = IPSEC_ENCALG_3DES;
                        break;
                    }

                    case SADB_X_EALG_BLOWFISHCBC:
                    {
                        pSa->sadb_sa_encrypt = IPSEC_ENCALG_BLOWFISH;
                        break;
                    }

                    case SADB_X_EALG_AESCBC:
                    {
                        pSa->sadb_sa_encrypt = IPSEC_ENCALG_AES;
                        break;
                    }

                    default:
                    {
                        status = ERR_PFKEY_INVALID_PARAMETER;
                        printk("Unknown encrypt algo\n");
                        goto exit;
                    }

                } /* switch (pSa->sadb_sa_encrypt) */

                pTemp += (pSa->sadb_sa_len * 8);
                pExt = (struct sadb_ext *)pTemp;
                printk("case SADB_EXT_SA\n");

                ADJUST_LEN_MACRO(pSa->sadb_sa_len * 8);

                break;
            }
            case SADB_EXT_ADDRESS_SRC:
            {
                pAddr = (struct sadb_address *)pTemp;

                status = pfkey_parseAddressExtension(pAddr, (MOC_IP_ADDRESS *)(&(addKey.dwSrcAddr)), NULL, NULL);
                /* !!!!!!!! addKey.dwSrcIP = addKey.dwSrcIPEnd = addKey.dwSrcAddr;    */

                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;
                printk("case SADB_ADDRESS_SRC address = %x\n", addKey.dwSrcAddr);
                printk("len = %d\n", len);

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);

                break;
            }

            case SADB_EXT_ADDRESS_DST:
            {
                pAddr = (struct sadb_address *)pTemp;
                status = pfkey_parseAddressExtension(pAddr, (MOC_IP_ADDRESS *)(&(addKey.dwDestAddr)), NULL, NULL);

                /* !!!!!!!!!!!! addKey.dwDestIP = addKey.dwDestIPEnd = addKey.dwDestAddr; */
                pTemp += pAddr->sadb_address_len * 8;
                pExt = (struct sadb_ext *)pTemp;

                printk("case SADB_ADDRESS_DST\n");

                ADJUST_LEN_MACRO(pAddr->sadb_address_len * 8);

                break;
            }

            case SADB_EXT_KEY_AUTH:
            {
                pKey = (struct sadb_key *)pTemp;
                keyPtr = (ubyte *)(pKey + 1);

                addKey.wAuthKeyLen = pKey->sadb_key_bits/8;

                /* Validate that the declared key bits actually fit within
                 * the extension as advertised by sadb_key_len, and within
                 * the remaining message buffer, before allocating/copying. */
                if ((((ubyte4)pKey->sadb_key_len) * 8 < sizeof(struct sadb_key)) ||
                    (addKey.wAuthKeyLen > (((ubyte4)pKey->sadb_key_len) * 8 - sizeof(struct sadb_key))) ||
                    (((ubyte4)pKey->sadb_key_len) * 8 > len))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                addKey.pAuthKey = KERNEL_MALLOC(addKey.wAuthKeyLen);

                if (NULL == addKey.pAuthKey)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                printk("Copying key: %x%x%x%x%x%x\n", keyPtr[0],keyPtr[1],keyPtr[2],keyPtr[3],keyPtr[4],keyPtr[5]);
                DIGI_MEMCPY(addKey.pAuthKey, (pKey + 1), addKey.wAuthKeyLen);

                pTemp += pKey->sadb_key_len*8;
                pExt = (struct sadb_ext *)pTemp;
                printk("case SADB_EXT_KEY_AUTH\n");

                ADJUST_LEN_MACRO(pKey->sadb_key_len * 8);

                break;
            }

            case SADB_EXT_KEY_ENCRYPT:
            {
                pKey = (struct sadb_key *)pTemp;

                addKey.wEncrKeyLen = pKey->sadb_key_bits/8;

                /* Validate that the declared key bits actually fit within
                 * the extension as advertised by sadb_key_len, and within
                 * the remaining message buffer, before allocating/copying. */
                if ((((ubyte4)pKey->sadb_key_len) * 8 < sizeof(struct sadb_key)) ||
                    (addKey.wEncrKeyLen > (((ubyte4)pKey->sadb_key_len) * 8 - sizeof(struct sadb_key))) ||
                    (((ubyte4)pKey->sadb_key_len) * 8 > len))
                {
                    status = ERR_PFKEY_PARSE_BAD_LENGTH;
                    goto exit;
                }

                addKey.pEncrKey = KERNEL_MALLOC(addKey.wEncrKeyLen);
                if (NULL == addKey.pEncrKey)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(addKey.pEncrKey, (pKey + 1), addKey.wEncrKeyLen);

                pTemp += pKey->sadb_key_len*8;
                pExt = (struct sadb_ext *)pTemp;
                printk("case SADB_EXT_KEY_ENCRYPT\n");

                ADJUST_LEN_MACRO(pKey->sadb_key_len * 8);

                break;
            }

            default:
            {
                if (pExt)
                {
                    printk("case default\n");

                    pTemp = (ubyte *)pExt;

                    ADJUST_LEN_MACRO(pExt->sadb_ext_len * 8);

                    pTemp += (pExt->sadb_ext_len*8);
                    pExt = (struct sadb_ext *)pTemp;
                }
                break;
            }
        }
    } /* while */

    printk("Calling IPSEC_keyAddEx\n");
    spdId = IPSEC_keyAdd(&addKey, 1);

    if (0 < spdId)
        printk("IPSEC_keyAddEx successful\n");
    else
        printk("IPSEC_keyAddEx failed\n");

exit:
    if (OK > status)
    {
        pfkey_buildErrorResponse(pMsg, EINVAL, ppAddResponse, pLen);
    }
    else
    {
        status = pfkey_buildAddResponse(pMsg, addKey.wAuthKeyLen,
                                        addKey.wEncrKeyLen,
                                        ppAddResponse, pLen);
    }

    return status;
} /* pfkey_parseAdd */


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildSupportedAlgo(ubyte2 ext, sbyte4 maxAlgos, ubyte *pTemp)
{
    struct sadb_supported*      pSupp = (struct sadb_supported *)pTemp;
    struct sadb_alg*            pAlgo;
    sbyte4                      i;
    SADB_hmacSuiteInfo*         pHmacSuite;
    SADB_cipherSuiteInfo*       pCipherSuite;
    MSTATUS                     status = OK;

    pSupp->sadb_supported_len = PFKEY_DIVROUNDUP((sizeof(struct sadb_supported) + maxAlgos * sizeof(struct sadb_alg)), 8);

    pSupp->sadb_supported_exttype = ext;
    pAlgo = (struct sadb_alg *) (pSupp + 1);

    if (SADB_EXT_SUPPORTED_AUTH == ext)
    {
        for (i = 0; i < maxAlgos && pAlgo; i++, pAlgo++)
        {
            pHmacSuite = IPSEC_getHmacSuite(i);

            if (!pHmacSuite)
                break;

            printk("Got a valid pHmacSuite, algo = %d\n", pHmacSuite->oAuthAlgo);
            switch (pHmacSuite->oAuthAlgo)
            {
                case IPSEC_AUTHALG_MD5:
                {
                    pAlgo->sadb_alg_id = SADB_AALG_MD5HMAC;
                    break;
                }

                case IPSEC_AUTHALG_SHA1:
                {
                    pAlgo->sadb_alg_id = SADB_AALG_SHA1HMAC;
                    break;
                }

                case IPSEC_AUTHALG_SHA256:
                {
                    pAlgo->sadb_alg_id = SADB_X_AALG_SHA2_256HMAC;
                    break;
                }

                case IPSEC_AUTHALG_SHA384:
                {
                    pAlgo->sadb_alg_id = SADB_X_AALG_SHA2_384HMAC;
                    break;
                }

                case IPSEC_AUTHALG_SHA512:
                {
                    pAlgo->sadb_alg_id = SADB_X_AALG_SHA2_512HMAC;
                    break;
                }

                default:
                {
                    continue;
                }
            }

            pAlgo->sadb_alg_minbits = pAlgo->sadb_alg_maxbits = pHmacSuite->wKeyLen * 8;

        } /* for */
    } /* if */
    else if (SADB_EXT_SUPPORTED_ENCRYPT == ext)
    {
        for (i = 0; i < maxAlgos && pAlgo; i++, pAlgo++)
        {
            pCipherSuite = IPSEC_getCipherSuite(i);
            printk("Got a valid pCipherSuite, algo = %d\n", pCipherSuite->oEncrAlgo);

            if (!pCipherSuite)
                break;

            switch (pCipherSuite->oEncrAlgo)
            {
                case IPSEC_ENCALG_ANY:
                {
                    pAlgo->sadb_alg_id = SADB_EALG_NONE;
                    break;
                }

                case IPSEC_ENCALG_DES:
                {
                    pAlgo->sadb_alg_id = SADB_EALG_DESCBC;
                    break;
                }

                case IPSEC_ENCALG_3DES:
                {
                    pAlgo->sadb_alg_id = SADB_EALG_3DESCBC;
                    break;
                }

                case IPSEC_ENCALG_BLOWFISH:
                {
                    pAlgo->sadb_alg_id = SADB_X_EALG_BLOWFISHCBC;
                    break;
                }

                case IPSEC_ENCALG_AES:
                {
                    pAlgo->sadb_alg_id = SADB_X_EALG_AESCBC;
                    break;
                }

                default:
                {
                    continue;
                }
            }

            pAlgo->sadb_alg_minbits = pCipherSuite->wKeyLen * 8;
            pAlgo->sadb_alg_maxbits = pCipherSuite->wKeyLenEnd * 8;
            pAlgo->sadb_alg_ivlen = pCipherSuite->wIvLen;

        } /* for */

    } /* if (SADB_EXT_SUPPORTED_ENCRYPT == ext) */

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_buildRegisterResponse(struct sadb_msg *pBase, ubyte proto,
                            ubyte **ppResp, ubyte2 *pLen)
{
    ubyte2       len = 0;
    sbyte4       maxAuthAlgos;
    sbyte4       maxEncrAlgos;
    ubyte*       pResp;
    ubyte*       pTemp;
    MSTATUS      status = OK;

    maxEncrAlgos = IPSEC_getMaxCipherSuites();
    maxAuthAlgos = IPSEC_getMaxHmacSuites();

    printk("maxAuthAlgos = %d\n",maxAuthAlgos);
    printk("maxEncrAlgos = %d\n",maxEncrAlgos);

    len = sizeof(struct sadb_msg);
    printk("len = %d\n", len);

    if (maxAuthAlgos > 0)
    {
        len += (sizeof(struct sadb_supported) + (maxAuthAlgos * sizeof(struct sadb_alg)));
    }

    if (maxEncrAlgos > 0)
    {
        len += (sizeof(struct sadb_supported) + (maxEncrAlgos * sizeof(struct sadb_alg)));
    }

    pResp = KERNEL_MALLOC(len);
    if (NULL == pResp)
    {
        printk("alloc failure \n");
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pResp, 0x00, len);

    if (OK > (status = pfkey_buildBase(pBase->sadb_msg_seq,
                                       pBase->sadb_msg_pid, proto,
                                       SADB_REGISTER,
                                       0, len, (struct sadb_msg *)pResp)))
    {
        goto exit;
    }

    pTemp = (ubyte *)(pResp + sizeof(struct sadb_msg));

    if (OK > (status = pfkey_buildSupportedAlgo(SADB_EXT_SUPPORTED_AUTH,
                                                maxAuthAlgos, pTemp)))
    {
        goto exit;
    }

    pTemp += (sizeof(struct sadb_supported) +
             maxAuthAlgos * sizeof(struct sadb_alg));

    if (OK > (status = pfkey_buildSupportedAlgo(SADB_EXT_SUPPORTED_ENCRYPT,
                                                maxEncrAlgos, pTemp)))
    {
        goto exit;
    }

    *ppResp = pResp;
    *pLen = len;
    pResp = NULL;

exit:
    if (pResp)
        KERNEL_FREE(pResp);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
pfkey_parseRegister(ubyte *pMsg, ubyte **ppResp, ubyte2 *pLen)
{
    struct sadb_msg *pBase = (struct sadb_msg *)pMsg;
    ubyte proto = 0;
    MSTATUS status = OK;

    PROTO_SADB_TO_MOC(pBase->sadb_msg_satype);

    status = pfkey_buildRegisterResponse(pBase, proto, ppResp, pLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PFKEY_IPSEC_parse(pfKeyIpsecCb *pPfkey, ubyte *pMsg, ubyte4 msgLen, ubyte **ppReply, ubyte2 *pReplyLen)
{
    struct sadb_msg*  pBase = (struct sadb_msg *)pMsg;
    MSTATUS           status = OK;

    if ((!pBase) || (!ppReply) || (!pReplyLen) || (msgLen < (8 * pBase->sadb_msg_len)))
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

    *ppReply = NULL;
    *pReplyLen = 0;
    printk("PFKEY_IPSEC_parse called with msg type %d\n", pBase->sadb_msg_type);

    switch (pBase->sadb_msg_type)
    {
        case SADB_REGISTER:
        {
            status = pfkey_parseRegister(pMsg, (ubyte **)ppReply, pReplyLen);
            break;
        }

        case SADB_ADD:
        {
            status = pfkey_parseAdd(pMsg, msgLen, (ubyte **)ppReply, pReplyLen);
            break;
        }

        case SADB_DELETE:
        {
            status = pfkey_parseDelete(pMsg, msgLen, (ubyte **)ppReply, pReplyLen);
            break;
        }

        case SADB_GETSPI:
        {
            /* compare seq nos. in earlier ACQUIRE and this GETSPI */
            if (pPfkey->acquireSentFlag)
            {
                if (pPfkey->seqNo != pBase->sadb_msg_seq)
                {
                    status = ERR_PFKEY_SEQ_NUM;
                    goto exit;
                }
            }

            if (OK > (status = pfkey_parseGetSpi((struct sadb_msg *)pMsg,
                                    msgLen, (ubyte **)ppReply, pReplyLen)))
            {
                goto exit;
            }

            break;
        }

        case SADB_UPDATE:
        {
            /* compare seq nos. in earlier ACQUIRE and this UPDATE */
            if (pPfkey->acquireSentFlag)
            {
                if (pPfkey->seqNo != pBase->sadb_msg_seq)
                {
                    status = ERR_PFKEY_SEQ_NUM;
                    goto exit;
                }
            }

            if (OK > (status = pfkey_parseAdd(pMsg, msgLen, ppReply, pReplyLen)))
            {
                goto exit;
            }

            break;
        }

        case SADB_GET:
        {
            status = pfkey_parseGet(pPfkey, pMsg, msgLen, ppReply, pReplyLen);
            break;
        }

        case SADB_FLUSH:
        {
            status = pfkey_parseFlush(pBase, msgLen, ppReply, pReplyLen);
            break;
        }

        default:
        {
            status = ERR_PFKEY_INVALID_MSGTYPE;
            break;
        }
    }

exit:
    return status;

} /* PFKEY_IPSEC_parse */

#endif /* __ENABLE_DIGICERT_PFKEY__ */
