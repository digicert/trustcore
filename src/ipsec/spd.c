/**
 * @file  spd.c
 * @brief NanoSec IPsec Security Policy Database (SPD) implementation.
 *
 * @details    This file contains the SPD management implementation for NanoSec IPsec.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
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

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/crypto.h"
#include "../common/debug_console.h"

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
#include "../common/hash_table.h"
#include "../common/hash_value.h"
#include "../common/mem_pool.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"
#include "../ipsec/sadb.h"
#include "../ike/ike.h"


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPSEC_SPD_MALLOC__
static struct spd *m_ipsecSpd = NULL;
#else
static struct spd m_ipsecSpd[IPSEC_SPD_MAX * 2] = { {0} };
#endif
static sbyte4 m_ipsecSpdNum = 0;
static SPD m_ipsecSpdEnd = NULL;

static ubyte4 m_ipsecSpdId = 0;


/*------------------------------------------------------------------*/

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__

static poolHeaderDescr spdPoolHdrDescr = { NULL };

#if (defined(ENABLE_DIGICERT_GDOI_CLIENT) || defined(ENABLE_DIGICERT_GDOI_SERVER)) && defined(ENABLE_DIGICERT_MULTICAST_MCP)
#define OUTBOUND_TABLE_SIZE  2047
#else
#define OUTBOUND_TABLE_SIZE  511
#endif
#define OUTBOUND_INIT_HASH_VALUE (0x823fd782)

static hashTableOfPtrs *pOutboundSpdTable = NULL;

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
extern MSTATUS matchFqdnIp(fqdnMappingConfig *fqdnMapping, fqdnMappingConfig *testFqdnMapping, intBoolean *isMatch);
extern hashTableOfPtrs *m_hashTableFqdnMapping;
#endif

static MSTATUS
allocHashElement(void *ptr, hashTablePtrElement **ppElement)
{
    *ppElement = (hashTablePtrElement *) MALLOC(sizeof(hashTablePtrElement));
    DIGI_MEMSET((ubyte *)*ppElement, 0x00, sizeof(hashTablePtrElement));
    return OK;
}

static MSTATUS
freeHashElement(void *ptr, hashTablePtrElement *pElement)
{
    FREE(pElement);
    return OK;
}

typedef struct
{
    MOC_IP_ADDRESS_S dwTunlDestAddr;
    // ubyte2 wPortRangeStart;  // For later use
    // ubyte2 wPortRangeEnd;    // For later use

    SPD pxSP;
    MOC_IP_ADDRESS_S dwTunlSrcAddr;
} outboundHashEntry;

typedef struct
{
    MOC_IP_ADDRESS_S dwTunlDestAddr;
    ubyte2 wDestPort;
    ubyte2 wSrcPort;
    MOC_IP_ADDRESS_S dwTunlSrcAddr;
    ubyte  wProto;
    intBoolean bCheckPorts;
    intBoolean bIke;
} outboundMetadata;

static ubyte4
getHash(MOC_IP_ADDRESS_S *pDestAddr)
{
    ubyte4 hash;
    HASH_VALUE_hashGen(pDestAddr, sizeof(MOC_IP_ADDRESS_S),
                       OUTBOUND_INIT_HASH_VALUE, &hash);
    return hash;
}

static MSTATUS
matchHashElement(void *pAppData, void *pTestData, intBoolean *isMatch)
{
    outboundHashEntry *entry = (outboundHashEntry *) pAppData;
    outboundMetadata *test = (outboundMetadata *) pTestData;
    *isMatch = 0;

    /* TODO: also check other paramaters i.e. fqdn list mapping and end ip*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if (!((0 == entry->pxSP->oProto) || (entry->pxSP->oProto == test->wProto)))
    {
        return OK;
    }

    if(((entry->pxSP->isUnicastGDOI && (!checkIpinList(test->dwTunlDestAddr,
                entry->pxSP->dwDestIPList, entry->pxSP->dwDestIPCount))) ||
        (!entry->pxSP->dwDestIPCount && (!CheckIpRange(REF_MOC_IPADDR(entry->pxSP->dwDestIP),
                          REF_MOC_IPADDR(entry->pxSP->dwDestIPEnd), test->dwTunlDestAddr, 0)))||
        SAME_MOC_IPADDR(entry->dwTunlDestAddr, test->dwTunlDestAddr)) &&
        (!test->dwTunlSrcAddr || (entry->pxSP->isUnicastGDOI && (!checkIpinList(test->dwTunlSrcAddr,
                entry->pxSP->dwSrcIPList, entry->pxSP->dwSrcIPCount))) ||
                ((!entry->pxSP->dwSrcIPCount && (!CheckIpRange(REF_MOC_IPADDR(entry->pxSP->dwSrcIP),
                          REF_MOC_IPADDR(entry->pxSP->dwSrcIPEnd), test->dwTunlSrcAddr, 0))))))
#else
    if (SAME_MOC_IPADDR(entry->dwTunlDestAddr, test->dwTunlDestAddr) )
#endif
    {
        /* Also need to have a range check here!! */
        *isMatch = 1; /* !!! */

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_TUNNEL_MODE__)
        if (test->bIke)
        {
            switch (entry->pxSP->oAction)
            {
                case IPSEC_ACTION_BYPASS :
                case IPSEC_ACTION_DROP :
                    break;
                default :
                    if ((IPSEC_MODE_TRANSPORT == entry->pxSP->oMode) ||
                        ((ISZERO_MOC_IPADDR(entry->pxSP->dwTunlDestIP) ||
                          SAME_MOC_IPADDR(test->dwTunlDestAddr, entry->pxSP->dwTunlDestIP)) &&
                         (ISZERO_MOC_IPADDR(entry->pxSP->dwTunlSrcIP) ||
                          SAME_MOC_IPADDR(test->dwTunlSrcAddr, entry->pxSP->dwTunlSrcIP))))
                    {
    #ifdef MOCANA_IPSEC_DEBUGGING
                        DB_PRINT("\n ipsec_getsp continue here pxSp->dwTunlDestIP=%x pxSp->dwTunlSrcIP=%x",entry->pxSP->dwTunlDestIP, entry->pxSP->dwTunlSrcIP);
    #endif
                        *isMatch = 0;   /* skip this packet as the bike enable means we need to skip this packet*/
                        return OK;
                    }
                break;
            }
        }
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (!test->bCheckPorts)
        {
            return OK;
        }

/* port config will override everything else if port is configured no need to check the dest port , src port mapping*/
        if (entry->pxSP->wPortCount)
        {
            /* special condition if test src and dest port is 0 then no need to check further as this is keyinitae*/
            if (!(test->wDestPort||test->wSrcPort) ||
                (-1 != CheckPortList(entry->pxSP->wPortList, entry->pxSP->wPortCount, test->wSrcPort)) ||
                (-1 != CheckPortList(entry->pxSP->wPortList, entry->pxSP->wPortCount, test->wDestPort)))
            {
                *isMatch = 1;
                return OK; /* found!!! */
            }
            *isMatch = 0; /* not found*/
            return OK;
        }
#ifndef __ENABLE_IPSEC_PORT_RANGE__
        if (!entry->pxSP->wSrcPort || (entry->pxSP->wSrcPort == test->wSrcPort))
#else
        if (!CheckPortRange(entry->pxSP->wSrcPort, entry->pxSP->wSrcPortEnd, wSPort))
#endif
        {
            /* ICMP special case!!! */
            if ((IPPROTO_ICMP == test->wProto) ||
                (IPPROTO_ICMPV6 == test->wProto))
                return OK;

#ifndef __ENABLE_IPSEC_PORT_RANGE__
            if ((MCP_NO_PORT== entry->pxSP->wDestPortType)||(!test->wDestPort ||
                (entry->pxSP->wDestPortType == MCP_SINGLE_PORT && (entry->pxSP->wDestPort == test->wDestPort))||
                    (entry->pxSP->wDestPortType == MCP_PORT_LIST &&
                        (-1 != CheckPortList(entry->pxSP->wDestPortList,entry->pxSP->wDestPortCount,test->wDestPort)))))
#else
            if ((MCP_NO_PORT== entry->pxSP->wDestPortType)|| (!test->wDestPort || (entry->pxSP->wDestPortType == MCP_PORT_LIST &&
                        (-1 != CheckPortList(entry->pxSP->wDestPortList,entry->pxSP->wDestPortCount,test->wDestPort)))
                        ||!CheckPortRange(entry->pxSP->wDestPort, entry->pxSP->wDestPortEnd, test->wDestPort)))
#endif
            {
                *isMatch = 1;
                return OK; /* found!!! */
            }
        }
        *isMatch = 0; /* reset if no condition found */

#endif
    }
    return OK;
}

static MSTATUS
HT_check(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    outboundHashEntry *entry = (outboundHashEntry *) pAppData;

    *pRetIsMatch = ((entry->pxSP == pTestData) ? TRUE : FALSE);
    return OK;
} /* HT_check */


#endif /* __DISABLE_EXTENDED_SPD_LOOKUP__ */

/*------------------------------------------------------------------*/

extern SPD
IPSEC_getSpd(sbyte4 *numEntries)
{
    *numEntries = m_ipsecSpdNum;
    return m_ipsecSpd;
} /* IPSEC_getSpd */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_initSpd(void)
{
    MSTATUS status = OK;

    if (m_ipsecSpdNum) IPSEC_flushSpd();
    m_ipsecSpdNum = IPSEC_SPD_MAX * 2;

#ifdef __ENABLE_DIGICERT_IPSEC_SPD_MALLOC__
    if (NULL == m_ipsecSpd)
    {
        m_ipsecSpd = (struct spd*)MALLOC((IPSEC_SPD_MAX * 2) * sizeof(struct spd));
        if(!m_ipsecSpd)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte *)m_ipsecSpd, 0x00, (IPSEC_SPD_MAX * 2) * sizeof(struct spd));
    }
#endif

/*
    DIGI_MEMSET((ubyte *)m_ipsecSpd, 0x00, m_ipsecSpdNum * sizeof(struct spd));
*/
    m_ipsecSpdEnd = &(m_ipsecSpd[m_ipsecSpdNum]);

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
    if (OK > (status = MEM_POOL_initPool(&spdPoolHdrDescr, m_ipsecSpd,
                                         (m_ipsecSpdNum * sizeof(struct spd)),
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                                          sizeof(struct spd) )))
#else
                                          2 * sizeof(struct spd) ))) /* pair! */
#endif
    {
        goto exit;
    }

    status = HASH_TABLE_createPtrsTable(&pOutboundSpdTable, OUTBOUND_TABLE_SIZE,
                                        NULL, &allocHashElement, &freeHashElement);
exit:
#endif
    return status;
} /* IPSEC_initSpd */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_flushSpd(void)
{
    MSTATUS status = OK;

    sbyte4 i;
    for (i=0; i < m_ipsecSpdNum; i++)
    {
        SPD pxSp = &(m_ipsecSpd[i]);
        if (IPSEC_SP_FLAG_INUSE & pxSp->flags)
        {
            if (!(IPSEC_SP_FLAG_DELETED & pxSp->flags))
            {
                status = IPSEC_delSp(pxSp); /* delete */
            }
            DIGI_MEMSET((ubyte *)pxSp, 0x00, sizeof(struct spd)); /* clean up */
        }
    }
    m_ipsecSpdNum = 0;
    m_ipsecSpdEnd = NULL;
#ifdef __ENABLE_DIGICERT_IPSEC_SPD_MALLOC__
    if(m_ipsecSpd)
        FREE(m_ipsecSpd);
    m_ipsecSpd = NULL;
#endif

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
    HASH_TABLE_removePtrsTable(pOutboundSpdTable, NULL);
    pOutboundSpdTable = NULL;
#endif
    return status;
} /* IPSEC_flushSpd */


/*------------------------------------------------------------------*/

extern SPD
IPSEC_enumSp(SPD pxSp)
{
    if (NULL == pxSp)
        pxSp = &(m_ipsecSpd[0]);
    else
        ++pxSp;

    for (; pxSp < m_ipsecSpdEnd; ++pxSp)
    {
        if ((IPSEC_SP_FLAG_INUSE & pxSp->flags) &&
            !(IPSEC_SP_FLAG_DELETED & pxSp->flags))
        {
            goto exit;
        }
    }
    pxSp = NULL;

exit:
    return pxSp;
} /* IPSEC_enumSp */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_delSp(SPD pxSp)
{
    MSTATUS status = OK;

    SPD pxSpM = (IPSEC_SP_FLAG_INBOUND & pxSp->flags)
              ? (pxSp + 1) : (pxSp - 1);

    pxSp->dwId = 0;

    if (IPSEC_SP_FLAG_MIRRORED & pxSp->flags)
    {
        pxSpM->flags &= ~(IPSEC_SP_FLAG_MIRRORED);
    }

    pxSp->flags |= IPSEC_SP_FLAG_DELETED;

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
    if (pxSp->ob_hashEntry != NULL)
    {
        void *entry;
        intBoolean found;
        outboundMetadata test;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if(pxSp->isUnicastGDOI && pxSp->oAction == IPSEC_ACTION_PERMIT)    /* more than 1 entry here*/
        {
          /*  SET_MOC_IPADDR4(temp_addr, pxSp->dwSrcIPList[0]);*/
            SET_MOC_IPADDR4(test.dwTunlDestAddr, pxSp->dwSrcIPList[0]);
            SET_MOC_IPADDR4(test.dwTunlSrcAddr, pxSp->dwDestIPList[0]);
        }
        else if(pxSp->isUnicastGDOI)
        {
            SET_MOC_IPADDR4(test.dwTunlDestAddr, pxSp->dwDestIPList[0]);
    /*   SET_MOC_IPADDR4(temp_addr, pxSp->dwDestIPList[0]);*/
            SET_MOC_IPADDR4(test.dwTunlSrcAddr, pxSp->dwSrcIPList[0]);

            /* Flush entries from the fqdnMapping hash table */
            ubyte4 listIndex = 0, ipListhashValue = 0;
            fqdnMappingConfig *fqdnMapping = NULL, *fqdnFoundMapping = NULL;
            intBoolean isEntryFound = FALSE;
            while (listIndex < pxSp->dwDestIPCount)
            {
                DIGI_MALLOC((void **)&fqdnMapping, sizeof(fqdnMappingConfig));
                COPY_MOC_IPADDR(fqdnMapping->fqdnUniqueKey, pxSp->dwDestIPList[0]);

                GEN_FQDNMAPPING_HASH_VALUE(pxSp->dwDestIPList[listIndex], ipListhashValue)
                COPY_MOC_IPADDR(fqdnMapping->fqdnIp, pxSp->dwDestIPList[listIndex]);

                status = HASH_TABLE_deletePtr(m_hashTableFqdnMapping, ipListhashValue, fqdnMapping,
                            (funcPtrExtraMatchTest)matchFqdnIp, (void **)&fqdnFoundMapping, &isEntryFound);

                if (isEntryFound && fqdnFoundMapping != NULL)
                    FREE(fqdnFoundMapping);

                if(fqdnMapping)
                    FREE(fqdnMapping);
                listIndex++;
            }
        }
        else
#endif
        {
            SET_MOC_IPADDR4(test.dwTunlDestAddr, pxSp->dwDestIP);
        }

        /*MOC_IP_ADDRESS addr = IPSEC_mapIpToKey(pxSp->dwDestIP?pxSp->dwDestIP:pxSp->dwDestIP);*/
        ubyte4 hash = getHash(&test.dwTunlDestAddr);
      /*  SET_MOC_IPADDR4(test.dwTunlDestAddr, pxSp->dwDestIP);

        test.dwTunlSrcAddr = 0;*/
        test.wDestPort = 0;
        status = HASH_TABLE_deletePtr(pOutboundSpdTable, hash, pxSp,
                                      &HT_check, &entry, &found);
        if (found && entry != NULL)
        {
            FREE(entry);
        }
    }

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    /* mempool object is a pair of SPD entries, i.e. [inbound, outbound] */
    status = MEM_POOL_putPoolObject(&spdPoolHdrDescr, (void**)&pxSp);
#else
    if ((IPSEC_SP_FLAG_DELETED & pxSpM->flags) ||
        !(IPSEC_SP_FLAG_INUSE & pxSpM->flags))
    {
        if (!(IPSEC_SP_FLAG_INBOUND & pxSp->flags))
        {
            pxSp = pxSpM;
        }
        /* mempool object is a pair of SPD entries, i.e. [inbound, outbound] */
        status = MEM_POOL_putPoolObject(&spdPoolHdrDescr, (void**)&pxSp);
    }
#endif
#endif
    return status;
} /* IPSEC_delSp */


/*------------------------------------------------------------------*/

extern SPD
IPSEC_indexSp(sbyte4 index, intBoolean bInbound)
{
    SPD pxSpRet = NULL;

    if (0 < index)
    {
        sbyte4 i = ((index - 1) * 2) + (bInbound ? 0 : 1);
        SPD pxSp = &(m_ipsecSpd[i]);

        if ((pxSp < m_ipsecSpdEnd) && /* just in case */
            (IPSEC_SP_FLAG_INUSE & pxSp->flags) &&
            !(IPSEC_SP_FLAG_DELETED & pxSp->flags))
        {
            pxSpRet = pxSp;
        }
    }

    return pxSpRet;
} /* IPSEC_indexSp */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_newSp(IPSECCONF pxConf)
{
    MSTATUS status = ERR_SPD;
    sbyte4 index = -1;
    ubyte4 list_index = 0;

    sbyte4 i, j, k;
    SPD pxSp;
#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
    SPD  pxSPTemp;
#endif

    CAST_MOC_IPADDR dwSrcIP     = pxConf->dwSrcIP;
    CAST_MOC_IPADDR dwSrcIPEnd  = pxConf->dwSrcIPEnd;

    CAST_MOC_IPADDR dwDestIP    = pxConf->dwDestIP;
    CAST_MOC_IPADDR dwDestIPEnd = pxConf->dwDestIPEnd;

    ubyte2 wSrcPort     = pxConf->wSrcPort;
    ubyte2 wDestPort    = pxConf->wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    ubyte2 wSrcPortEnd  = pxConf->wSrcPortEnd;
    ubyte2 wDestPortEnd = pxConf->wDestPortEnd;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
     intBoolean bIPv6 = (IPSEC_SP_FLAG_IP6 & pxConf->flags);
     intBoolean bIPv6Tunl = (IPSEC_SP_FLAG_IP6_TUNNEL & pxConf->flags);
     ubyte4 dwIPEnd[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
#endif

    /* get action/direction(s) */
    ubyte oAction = pxConf->oAction;
    intBoolean bDir[2] = {FALSE, FALSE};    /* inbound/outbound */
    intBoolean bSwap[2] = {FALSE, FALSE};   /* swap dest/src */
    intBoolean bMirrored = (IPSEC_DIR_MIRRORED & (pxConf->oDir & 0xf0)) ? TRUE : FALSE;

    intBoolean bInbound;
    switch (oAction)
    {
    case IPSEC_ACTION_PERMIT :
        bInbound = TRUE;
        break;
    case IPSEC_ACTION_APPLY :
        bInbound = FALSE;
        break;
    case IPSEC_ACTION_BYPASS :
    case IPSEC_ACTION_DROP :
        switch (pxConf->oDir & 0x0f)
        {
        case IPSEC_DIR_INBOUND :
            bInbound = TRUE;
            break;
        case IPSEC_DIR_OUTBOUND :
            bInbound = FALSE;
            break;
        default : /* should not get here */
            status = ERR_IPSECCONF_DIR;
            goto exit;
        }
        break;
    default : /* should not get here */
        status = ERR_IPSECCONF_ACTION;
        goto exit;
    }

    bDir[bInbound ? 0 : 1] = TRUE;
    if (bMirrored)
    {
        bDir[bInbound ? 1 : 0] = TRUE;
        bSwap[bInbound ? 1 : 0] = TRUE;
    }

    /* adjust */
    if (0 == dwSrcIPEnd)
    {
        if (0 == (dwSrcIPEnd = dwSrcIP))
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (bIPv6) dwSrcIPEnd = (CAST_MOC_IPADDR)dwIPEnd;
            else
#endif
            dwSrcIPEnd = ~((ubyte4)0);
        }
    }
    else if ((
#ifdef __ENABLE_DIGICERT_IPV6__
              bIPv6 && dwSrcIP &&
              (0 < CmpIpAddr6((ubyte *)dwSrcIP, (ubyte *)dwSrcIPEnd))) ||
             (!bIPv6 &&
#endif
              (dwSrcIP > dwSrcIPEnd) ))
    {
        dwSrcIP = pxConf->dwSrcIPEnd;
        dwSrcIPEnd = pxConf->dwSrcIP;
    }

    if (0 == dwDestIPEnd)
    {
        if (0 == (dwDestIPEnd = dwDestIP))
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (bIPv6) dwDestIPEnd = (CAST_MOC_IPADDR)dwIPEnd;
            else
#endif
            dwDestIPEnd = ~((ubyte4)0);
        }
    }
    else if ((
#ifdef __ENABLE_DIGICERT_IPV6__
              bIPv6 && dwDestIP &&
              (0 < CmpIpAddr6((ubyte *)dwDestIP, (ubyte *)dwDestIPEnd))) ||
             (!bIPv6 &&
#endif
              (dwDestIP > dwDestIPEnd) ))
    {
        dwDestIP = pxConf->dwDestIPEnd;
        dwDestIPEnd = pxConf->dwDestIP;
    }

#ifdef __ENABLE_IPSEC_PORT_RANGE__
    if ((!wSrcPort && (0xffff == wSrcPortEnd)) ||
        (wSrcPort == wSrcPortEnd))
    {
        wSrcPortEnd = 0;
    }
    else if (wSrcPortEnd && (wSrcPort > wSrcPortEnd))
    {
        wSrcPort = pxConf->wSrcPortEnd;
        wSrcPortEnd = pxConf->wSrcPort;
    }

    if ((!wDestPort && (0xffff == wDestPortEnd)) ||
        (wDestPort == wDestPortEnd))
    {
        wDestPortEnd = 0;
    }
    else if (wDestPortEnd && (wDestPort > wDestPortEnd))
    {
        wDestPort = pxConf->wDestPortEnd;
        wDestPortEnd = pxConf->wDestPort;
    }
#endif

    /* update specific SPD entry */
    if (0 < pxConf->index)
    {
        i = (pxConf->index - 1) * 2;
        if (i < m_ipsecSpdNum) /* just in case */
        {
            for (j=0; j < 2; j++)
            {
                if (!bDir[j]) continue;

                pxSp = &(m_ipsecSpd[i+j]);
                if (IPSEC_SP_FLAG_INUSE & pxSp->flags)
                {
                    if (!(IPSEC_SP_FLAG_DELETED & pxSp->flags))
                        IPSEC_delSp(pxSp); /* delete */
                }
            }

            index = pxConf->index;
        }
    }
    else
#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
    /* mempool object is a pair of SPD entries, i.e. [inboubd, outbound] */
    if (OK <= (status = MEM_POOL_getPoolObject(&spdPoolHdrDescr, (void **)&pxSp)))
    {
        if (IPSEC_SP_FLAG_INUSE & pxSp->flags)
        {
            index = pxSp->index;
        }
        else
        {
            if (OK > (status = MEM_POOL_getIndexForObject(&spdPoolHdrDescr,
                                                          pxSp, &index)))
            {
                MEM_POOL_putPoolObject(&spdPoolHdrDescr, (void**)&pxSp);
            }
            else
            {
                index++;
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                index = index / 2 + 1;
#endif
            }
        }
    }
#else
    {
        /* find unused slot(s) */
        for (i = m_ipsecSpdNum - 2; i >= 0; i -= 2)
        {
            intBoolean bAvail = TRUE;

            for (j=0; j < 2; j++)
            {
                if (!bDir[j]) continue;

                /* cannot add randomly - only append at the end of SPD table */
                /* or insert into empty slot while retaining priority */
                pxSp = &(m_ipsecSpd[i+j]);
                if ((IPSEC_SP_FLAG_INUSE & pxSp->flags) &&
                    !(IPSEC_SP_FLAG_DELETED & pxSp->flags))
                {
                    ubyte2 destPort = wDestPort, srcPort = wSrcPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
                    ubyte2 destPortEnd = wDestPortEnd, srcPortEnd = wSrcPortEnd;
#endif
                    MOC_IP_ADDRESS_S destIP, destIPEnd, srcIP, srcIPEnd;
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (bIPv6)
                    {
                        if (0 == dwSrcIP)
                        {
                            ZERO_MOC_IPADDR(srcIP);
                            srcIP.family = AF_INET6;
                        }
                        else
                        {
                            SET_MOC_IPADDR6(srcIP, dwSrcIP);
                        }
                        SET_MOC_IPADDR6(srcIPEnd, dwSrcIPEnd);

                        if (0 == dwDestIP)
                        {
                            ZERO_MOC_IPADDR(destIP);
                            destIP.family = AF_INET6;
                        }
                        else
                        {
                            SET_MOC_IPADDR6(destIP, dwDestIP);
                        }
                        SET_MOC_IPADDR6(destIPEnd, dwDestIPEnd);
                    }
                    else
#endif
                    {
                        SET_MOC_IPADDR4(srcIP, dwSrcIP);
                        SET_MOC_IPADDR4(srcIPEnd, dwSrcIPEnd);

                        SET_MOC_IPADDR4(destIP, dwDestIP);
                        SET_MOC_IPADDR4(destIPEnd, dwDestIPEnd);
                    }

                    if (bSwap[j])
                    {
                        MOC_IP_ADDRESS_S tmpIP;
                        ubyte2 tmpPort;

                        tmpIP = destIP; destIP = srcIP; srcIP = tmpIP;
                        tmpIP = destIPEnd; destIPEnd = srcIPEnd; srcIPEnd = tmpIP;

                        tmpPort = destPort; destPort = srcPort; srcPort = tmpPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
                        tmpPort = destPortEnd; destPortEnd = srcPortEnd; srcPortEnd = tmpPort;
#endif
                    }

                    if (!IntersectIpRange(REF_MOC_IPADDR(pxSp->dwDestIP),
                                          REF_MOC_IPADDR(pxSp->dwDestIPEnd),
                                          REF_MOC_IPADDR(destIP),
                                          REF_MOC_IPADDR(destIPEnd))    ||
                        !IntersectIpRange(REF_MOC_IPADDR(pxSp->dwSrcIP),
                                          REF_MOC_IPADDR(pxSp->dwSrcIPEnd),
                                          REF_MOC_IPADDR(srcIP),
                                          REF_MOC_IPADDR(srcIPEnd))     ||
#ifdef __ENABLE_IPSEC_PORT_RANGE__
                        !IntersectPortRange(pxSp->wSrcPort, pxSp->wSrcPortEnd,
                                            srcPort, srcPortEnd)        ||
                        !IntersectPortRange(pxSp->wDestPort, pxSp->wDestPortEnd,
                                            destPort, destPortEnd)      ||
#else
                        (pxSp->wSrcPort && srcPort && (srcPort != pxSp->wSrcPort)) ||
                        (pxSp->wDestPort && destPort && (destPort != pxSp->wDestPort)) ||
#endif
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
                        (pxSp->ifid && pxConf->ifid && (pxConf->ifid != pxSp->ifid)) ||
#endif
                        (pxSp->oProto && pxConf->oProto && (pxConf->oProto != pxSp->oProto)))
                    {
                        bAvail = FALSE;
                        continue;
                    }

                    goto done;
                }
            }

            if (bAvail) index = (i / 2) + 1;
        }
    }

done:
#endif /* __DISABLE_EXTENDED_SPD_LOOKUP__ */

    if (0 >= index) /* not found */
    {
        status = ERR_IPSECCONF_SPD;
        goto exit;
    }

    /* add */
    for (i=0; i < 2; i++)
    {
        if (!bDir[i]) continue;

        pxSp = &(m_ipsecSpd[(index - 1) * 2 + i]);

        /*if (IPSEC_SP_FLAG_INUSE & pxSp->flags)*/
        DIGI_MEMSET((ubyte *)pxSp, 0x00, sizeof(struct spd)); /* clean up */
#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
        pxSp->pNext = &m_ipsecSpd[(index - 1) * 2 + i + 1];
#endif

        pxSp->index             = index;

        if (0==i)       pxSp->flags |= IPSEC_SP_FLAG_INBOUND;
        if (bMirrored)  pxSp->flags |= IPSEC_SP_FLAG_MIRRORED;

        /* TODO: doesn't really guarantee unique ID - should use BITMAP */
        if (0x7fffffff == m_ipsecSpdId) m_ipsecSpdId = 0;
        pxSp->dwId              = ++m_ipsecSpdId;
        if (1==i) pxSp->dwId   |= 0x80000000; /* outbound */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        pxSp->dwIkeSaId         = pxConf->dwIkeSaId;
#endif
        pxSp->oProto            = pxConf->oProto;
        pxSp->oAction           = oAction;

#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
        if(IPSEC_ACTION_DROP == pxSp->oAction && 0 == i)  /* for drop only 1 entry exist so remove next memory pool entry*/
        {
            MEM_POOL_getPoolObject(&spdPoolHdrDescr, (void **)&pxSPTemp); /* empty spd entry*/
        }
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (pxConf->isUnicastGDOI)
        {
            DIGI_MEMCPY(pxSp->fqdn, pxConf->fqdn, MOC_MAX_FQDN_LEN);
            /* copy dest ip and src ip list*/

            DIGI_MEMCPY(pxSp->dwSrcIPList, pxConf->dwSrcIPList, (pxConf->dwSrcIPCount)*(sizeof(ubyte4)));
            pxSp->dwSrcIPCount = pxConf->dwSrcIPCount;

            DIGI_MEMCPY(pxSp->dwDestIPList, pxConf->dwDestIPList, (pxConf->dwDestIPCount)*(sizeof(ubyte4)));
            pxSp->dwDestIPCount = pxConf->dwDestIPCount;
        }
#endif

        while (list_index < pxConf->wDestPortCount)
        {
            pxSp->wDestPortList[list_index] = pxConf->wDestPortList[list_index];
            list_index++;
        }
        list_index = 0;
        while (list_index < pxConf->wPortCount)
        {
            pxSp->wPortList[list_index] = pxConf->wPortList[list_index];
            list_index++;
        }
        pxSp->wPortCount  = pxConf->wPortCount;
        pxSp->wDestPortCount = pxConf->wDestPortCount;
        pxSp->wDestPortType = pxConf->destPortType;

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
        pxSp->ifid              = pxConf->ifid;
#endif
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
        pxSp->cookie            = pxConf->cookie;
#endif
        if (!bSwap[i])
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (bIPv6)
            {
                if (0 == dwSrcIP) pxSp->dwSrcIP.family = AF_INET6; else {
                SET_MOC_IPADDR6(pxSp->dwSrcIP, dwSrcIP); }
                SET_MOC_IPADDR6(pxSp->dwSrcIPEnd, dwSrcIPEnd);

                if (0 == dwDestIP) pxSp->dwDestIP.family = AF_INET6; else {
                SET_MOC_IPADDR6(pxSp->dwDestIP, dwDestIP); }
                SET_MOC_IPADDR6(pxSp->dwDestIPEnd, dwDestIPEnd);
            }
            else
#endif
            {
                SET_MOC_IPADDR4(pxSp->dwSrcIP, dwSrcIP);
                SET_MOC_IPADDR4(pxSp->dwSrcIPEnd, dwSrcIPEnd);

                SET_MOC_IPADDR4(pxSp->dwDestIP, dwDestIP);
                SET_MOC_IPADDR4(pxSp->dwDestIPEnd, dwDestIPEnd);
            }

            pxSp->wSrcPort      = wSrcPort;
            pxSp->wDestPort     = wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
            pxSp->wSrcPortEnd   = wSrcPortEnd;
            pxSp->wDestPortEnd  = wDestPortEnd;
#endif

            /* ICMP special case!!! */
            if (!bMirrored)
            {
                switch (pxConf->oProto)
                {
                case IPPROTO_ICMP :
                case IPPROTO_ICMPV6 :
                    pxSp->wDestPort     = 0;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
                    pxSp->wDestPortEnd  = 0;
#endif
                    break;
                }
            }
        }
        else
        {
            switch (oAction)
            {
            case IPSEC_ACTION_APPLY :
                pxSp->oAction   = IPSEC_ACTION_PERMIT;
                break;
            case IPSEC_ACTION_PERMIT :
                pxSp->oAction   = IPSEC_ACTION_APPLY;
                break;
            default :
                break;
            }

#ifdef __ENABLE_DIGICERT_IPV6__
            if (bIPv6)
            {
                if (0 == dwDestIP) pxSp->dwSrcIP.family = AF_INET6; else {
                SET_MOC_IPADDR6(pxSp->dwSrcIP, dwDestIP); }
                SET_MOC_IPADDR6(pxSp->dwSrcIPEnd, dwDestIPEnd);

                if (0 == dwSrcIP) pxSp->dwDestIP.family = AF_INET6; else {
                SET_MOC_IPADDR6(pxSp->dwDestIP, dwSrcIP); }
                SET_MOC_IPADDR6(pxSp->dwDestIPEnd, dwSrcIPEnd);
            }
            else
#endif
            {
                SET_MOC_IPADDR4(pxSp->dwSrcIP, dwDestIP);
                SET_MOC_IPADDR4(pxSp->dwSrcIPEnd, dwDestIPEnd);

                SET_MOC_IPADDR4(pxSp->dwDestIP, dwSrcIP);
                SET_MOC_IPADDR4(pxSp->dwDestIPEnd, dwSrcIPEnd);
            }

            pxSp->wSrcPort      = wDestPort;
            pxSp->wDestPort     = wSrcPort;
            pxSp->wDestPortType = pxConf->srcPortType;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
            pxSp->wSrcPortEnd   = wDestPortEnd;
            pxSp->wDestPortEnd  = wSrcPortEnd;
#endif
        }
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        pxSp->isUnicastGDOI = pxConf->isUnicastGDOI;
#endif
#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
        if (i==1) /* For OUTBOUND only */
        {
            outboundHashEntry *entry = (outboundHashEntry *) MALLOC( sizeof(outboundHashEntry));
            DIGI_MEMSET((ubyte *)entry, 0x00, sizeof(outboundHashEntry));
            if (entry)
            {
                MSTATUS hstatus;
                ubyte4 hash;

                /*TODO: to be check whether to store only ip address or more variables here*/
                /*if permit API needs to add the src ip list 0 entry*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                if(pxSp->isUnicastGDOI && pxSp->oAction == IPSEC_ACTION_PERMIT)    /* more than 1 entry here*/
                {
                  /*  SET_MOC_IPADDR4(temp_addr, pxSp->dwSrcIPList[0]);*/
                    SET_MOC_IPADDR4(entry->dwTunlDestAddr, pxSp->dwSrcIPList[0]);
                    SET_MOC_IPADDR4(entry->dwTunlSrcAddr, pxSp->dwDestIPList[0]);
                }
                else if(pxSp->isUnicastGDOI)
                {
                    SET_MOC_IPADDR4(entry->dwTunlDestAddr, pxSp->dwDestIPList[0]);
            /*   SET_MOC_IPADDR4(temp_addr, pxSp->dwDestIPList[0]);*/
                    SET_MOC_IPADDR4(entry->dwTunlSrcAddr, pxSp->dwSrcIPList[0]);
                }
                else
#endif
                {
                    SET_MOC_IPADDR4(entry->dwTunlDestAddr, pxSp->dwDestIP);
                }
                entry->pxSP = pxSp;

                HASH_VALUE_hashGen(&entry->dwTunlDestAddr, sizeof(MOC_IP_ADDRESS_S),
                                   OUTBOUND_INIT_HASH_VALUE, &hash);

                hstatus = HASH_TABLE_addPtr(pOutboundSpdTable, hash, (void *)entry);
                if (hstatus == OK)
                {
                    pxSp->ob_hashEntry = (void *)entry;
                }
                else
                {
                    FREE((void *)entry);
                }
            }
        }
#endif
        /* PROTECT traffic */
        if ((IPSEC_ACTION_APPLY == oAction) ||
            (IPSEC_ACTION_PERMIT == oAction))
        {
            /* PFP flags (outbound) */
            if (1==i)
                pxSp->flags |= (IPSEC_SP_MASK_PFP & pxConf->flags);

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            /* TunnelOptions */
            if (IPSEC_MODE_TUNNEL == pxConf->oMode)
            {
                pxSp->oMode = IPSEC_MODE_TUNNEL;

                /* DF/DSCP (outbound) */
                if (1==i)
                {
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (!(bIPv6 || bIPv6Tunl)) /* IPv4 */
#endif
                    pxSp->flags |= (IPSEC_SP_MASK_DF & pxConf->flags);
                    pxSp->flags |= (IPSEC_SP_FLAG_DSCP & pxConf->flags);
                }

                /* ECN (inbound) */
                if (0==i)
                    pxSp->flags |= (IPSEC_SP_FLAG_ECN & pxConf->flags);

                /* set tunnel endpoints */
                if (!bSwap[i])
                {
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (bIPv6Tunl)
                    {
                        if (pxConf->dwTunlDestIP) {
                            SET_MOC_IPADDR6(pxSp->dwTunlDestIP, pxConf->dwTunlDestIP); }
                        if (pxConf->dwTunlSrcIP) {
                            SET_MOC_IPADDR6(pxSp->dwTunlSrcIP, pxConf->dwTunlSrcIP); }
                    }
                    else
#endif
                    {
                        if (pxConf->dwTunlDestIP) {
                            SET_MOC_IPADDR4(pxSp->dwTunlDestIP, pxConf->dwTunlDestIP); }
                        if (pxConf->dwTunlSrcIP) {
                            SET_MOC_IPADDR4(pxSp->dwTunlSrcIP, pxConf->dwTunlSrcIP); }
                    }
                }
                else
                {
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (bIPv6Tunl)
                    {
                        if (pxConf->dwTunlSrcIP) {
                            SET_MOC_IPADDR6(pxSp->dwTunlDestIP, pxConf->dwTunlSrcIP); }
                        if (pxConf->dwTunlDestIP) {
                            SET_MOC_IPADDR6(pxSp->dwTunlSrcIP, pxConf->dwTunlDestIP); }
                    }
                    else
#endif
                    {
                        if (pxConf->dwTunlSrcIP) {
                            SET_MOC_IPADDR4(pxSp->dwTunlDestIP, pxConf->dwTunlSrcIP); }
                        if (pxConf->dwTunlDestIP) {
                            SET_MOC_IPADDR4(pxSp->dwTunlSrcIP, pxConf->dwTunlDestIP); }
                    }
                }
            }
            else
#endif
            {
                pxSp->oMode = IPSEC_MODE_TRANSPORT;
            }

            /* set SA bundle info */
            pxSp->oSaLen = pxConf->oSaLen;

            for (j = pxConf->oSaLen - 1, k=0; j >= 0; j--, k++)
            {
                /* Note: store outermost header first */
                struct sainfo *si = &(pxSp->pxSa[k]);
                *si = pxConf->pxSa[j];

                /* adjust config. */
                switch (si->oSecuProto)
                {
                case IPSEC_PROTO_AH :
                case IPSEC_PROTO_ESP_NULL :
                    si->oEncrAlgo = 0;
                    si->oEncrKeyLen = 0;
                    si->aeadTag = 0;
                    break;
                case IPSEC_PROTO_ESP :
                    si->oAuthAlgo = 0;
                    break;
/*              case IPSEC_PROTO_ESP_AUTH :
                    break;*/
                default :
                    break;
                }
            } /* for (j */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            pxSp->dwSaSecs  = pxConf->dwSaSecs;
            pxSp->dwSaBytes = pxConf->dwSaBytes;
#endif
        } /* end of PROTECT */

        pxSp->flags |= IPSEC_SP_FLAG_INUSE;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        pxSp->isGdoi = pxConf->isGdoi;
        if (pxSp->isGdoi && dwDestIP != dwDestIPEnd) /* For unicast IP range make sure its not a single ip*/
        {
            SET_MOC_IPADDR4(pxSp->dwSrcIP, dwDestIP); /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
            SET_MOC_IPADDR4(pxSp->dwSrcIPEnd, dwDestIPEnd);
        }
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        pxSp->isUnicastGDOI = pxConf->isUnicastGDOI;
#endif

    } /* for (i=0; ... */

    pxConf->index = index;
    status = OK;

    /* initiate IKE_SA negotiation */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (bDir[1] && /* outbound */
        (IPSEC_SP_FLAG_INIT & pxConf->flags) && /* initiate */
        ((IPSEC_ACTION_APPLY == oAction) || (IPSEC_ACTION_PERMIT == oAction)))
    {
        struct ipsecKey key = { 0 };

#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        /* IP addresses need to be specified for transport mode */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL != pxConf->oMode)
#endif
        {
            if (!dwSrcIP || !dwDestIP) goto exit;

            if (dwSrcIPEnd != dwSrcIP)
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                if (!bIPv6 || CmpIpAddr6((ubyte *)dwSrcIP, (ubyte *)dwSrcIPEnd))
#endif
                goto exit;
            }
            if (dwDestIPEnd != dwDestIP)
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                if (!bIPv6 || CmpIpAddr6((ubyte *)dwDestIP, (ubyte *)dwDestIPEnd))
#endif
                goto exit;
            }
        }
#endif
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        if (wSrcPortEnd || wDestPortEnd) goto exit;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        if (bIPv6)
            key.flags       = IPSEC_SA_FLAG_IP6;
#endif
        if (bSwap[1])
        {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            if (pxConf->isUnicastGDOI)
            {
                key.dwSrcAddr = pxConf->dwDestIPList[0];
                key.dwDestAddr = pxConf->dwSrcIPList[0];
            }
            else
#endif
            {
                key.dwSrcAddr = dwDestIP;
                key.dwDestAddr = dwSrcIP;
            }
            key.wSrcPort    = wDestPort;
            key.wDestPort   = wSrcPort;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            if (pxConf->isUnicastGDOI)
            {
                key.dwSrcAddr = pxConf->dwSrcIPList[0];
                key.dwDestAddr = pxConf->dwDestIPList[0];
            }
            else
#endif
            {
                key.dwSrcAddr = dwSrcIP;
                key.dwDestAddr = dwDestIP;
            }
            key.wSrcPort    = wSrcPort;
            key.wDestPort   = wDestPort;
        }

        key.oUlp            = pxConf->oProto;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
        key.ifid            = pxConf->ifid;
#endif
#if defined(__VXWORKS_RTOS__)
        IPSEC_keyInitiate_ex(&key);
#else
        IPSEC_keyInitiate(&key);
#endif
    }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

exit:
    return status;
} /* IPSEC_newSp */


/*------------------------------------------------------------------*/

extern SPD
IPSEC_getSp(MOC_IP_ADDRESS dwDAddr, MOC_IP_ADDRESS dwSAddr,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            MOC_IP_ADDRESS dwDAddrEnd, MOC_IP_ADDRESS dwSAddrEnd,
#endif
            ubyte oProto,
            intBoolean bCheckPorts,
            ubyte2 wDPort, ubyte2 wSPort,
            intBoolean bInbound
            MOC_INTF_OPAQ(bOpaque, ifid)
            MOC_COOKIE(cookie))
{
    SPD pxSp = NULL;
    sbyte4 i;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /* special handling for IKE traffic (i.e. udp 500/4500) */
    intBoolean bIke =
       (bCheckPorts &&
        (IPPROTO_UDP == oProto) &&
        ((IKE_DEFAULT_UDP_PORT == wSPort)   ||
#ifdef __ENABLE_IPSEC_NAT_T__
         (IKE_NAT_UDP_PORT == wSPort)       ||
         (IKE_NAT_UDP_PORT == wDPort)       ||
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
         (IKE_GDOI_UDP_PORT == wSPort)      ||
         (IKE_GDOI_UDP_PORT == wDPort)      ||
#endif
         (IKE_DEFAULT_UDP_PORT == wDPort)));

#ifdef __DISABLE_IPSEC_TUNNEL_MODE__
    if (bIke) goto exit;
#endif
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */


#ifdef __DISABLE_EXTENDED_SPD_LOOKUP__
        if (!bInbound)
        {
            /* calculate HASH using the base key*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            MOC_IP_ADDRESS addr = IPSEC_mapIpToKey(dwDAddr);
            ubyte4 hash = getHash(&addr);
#else
            ubyte4 hash = getHash(&dwDAddr);
#endif
            outboundMetadata test;
            test.wDestPort = wDPort;
            test.wProto = oProto;
            test.bCheckPorts = bCheckPorts;
            test.wSrcPort = wSPort;
            test.bIke = bIke;

            SET_MOC_IPADDR4(test.dwTunlDestAddr, dwDAddr);
            SET_MOC_IPADDR4(test.dwTunlSrcAddr, dwSAddr);
            outboundHashEntry *entry;
            intBoolean found;
            MSTATUS hstatus = HASH_TABLE_findPtr(pOutboundSpdTable, hash, &test,
                                                 &matchHashElement, (void**)&entry, &found);
            if (hstatus == OK && found)
            {
                if (entry->pxSP != NULL)
                {
                    return entry->pxSP;
                }
            }
            return pxSp;    /* if not found no need to do linear search*/
        }
#endif

    /* traverse SPD */
    i = (bInbound ? 0 : 1);
    for (; i < m_ipsecSpdNum; i += 2, pxSp = NULL)
    {
        pxSp = &(m_ipsecSpd[i]);

        if (!(IPSEC_SP_FLAG_INUSE & pxSp->flags) ||
            (IPSEC_SP_FLAG_DELETED & pxSp->flags))
    {
            continue;
    }
#ifdef MOCANA_IPSEC_DEBUGGING
        DB_PRINT("\n ipsec_getsp  oProto=%d bCheckPorts=%d , wDport=%d wSPort=%d bInbound=%d",oProto, bCheckPorts , wDPort, wSPort, bInbound);
        DB_PRINT("\n ipsec_getsp transverse i=%d dwDestIP=%x dwDestIPEnd=%x, dwSrcIP=%x dwSrcIPEnd=%x prooto=%d oAction=%d pxSp->flags=%x",
                i, pxSp->dwDestIP, pxSp->dwDestIPEnd, pxSp->dwSrcIP, pxSp->dwSrcIPEnd ,pxSp->oProto, pxSp->oAction,pxSp->flags);
#endif

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
        if (bOpaque)
        {
            if (pxSp->ifid)
            {
                switch (pxSp->oAction)
                {
                case IPSEC_ACTION_BYPASS :
                case IPSEC_ACTION_DROP :
                    continue;
                }
            }
        }
        else
        {
            if (pxSp->ifid && (ifid != pxSp->ifid))
                continue;
        }
#endif

#ifdef USE_MOC_COOKIE
        if (pxSp->cookie && (cookie != pxSp->cookie))
            continue;
#endif

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_TUNNEL_MODE__)
        if (bIke)
        {
            switch (pxSp->oAction)
            {
            case IPSEC_ACTION_BYPASS :
            case IPSEC_ACTION_DROP :
                continue;
/*          case IPSEC_ACTION_PERMIT :
            case IPSEC_ACTION_APPLY :*/
            default :
                if ((IPSEC_MODE_TRANSPORT == pxSp->oMode) ||
                    ((ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP) ||
                      SAME_MOC_IPADDR(dwDAddr, pxSp->dwTunlDestIP)) &&
                     (ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP) ||
                      SAME_MOC_IPADDR(dwSAddr, pxSp->dwTunlSrcIP))))
                {
#ifdef MOCANA_IPSEC_DEBUGGING
                    DB_PRINT("\n ipsec_getsp continue here pxSp->dwTunlDestIP=%x pxSp->dwTunlSrcIP=%x",pxSp->dwTunlDestIP, pxSp->dwTunlSrcIP);
#endif
                    continue;
                }
                break;
            }
        }
#endif

        if (((0 == pxSp->oProto) || (pxSp->oProto == oProto)
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_TUNNEL_MODE__)
             || (bIke && (IPSEC_MODE_TUNNEL == pxSp->oMode) &&
                 ((IPPROTO_ESP == pxSp->oProto) || (IPPROTO_AH == pxSp->oProto)))
#endif
            ) &&
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            ((pxSp->isUnicastGDOI && (!checkIpinList(dwDAddr,
                pxSp->dwDestIPList, pxSp->dwDestIPCount)))||
            (!pxSp->dwDestIPCount &&
#endif
            (!CheckIpRange(REF_MOC_IPADDR(pxSp->dwDestIP),
                          REF_MOC_IPADDR(pxSp->dwDestIPEnd),
                          dwDAddr,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                          dwDAddrEnd
#else
                          0
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            ))
#endif
            )) &&
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            ((pxSp->isUnicastGDOI && (!checkIpinList(dwSAddr,
                pxSp->dwSrcIPList, pxSp->dwSrcIPCount))) ||
            (!pxSp->dwSrcIPCount &&
#endif
             (!CheckIpRange(REF_MOC_IPADDR(pxSp->dwSrcIP),
                          REF_MOC_IPADDR(pxSp->dwSrcIPEnd),
                          dwSAddr,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                          dwSAddrEnd
#else
                          0
#endif
                          ))
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
             ))
#endif
            )
        {
#ifdef MOCANA_IPSEC_DEBUGGING
            DB_PRINT("\n ipsec_getsp checking range success bCheckPorts=%d",bCheckPorts);
#endif
            if (!bCheckPorts) break; /* !!! */

            /* port config will override everything else if port is configured no need to check the dest port , src port mapping*/
            if(pxSp->wPortCount)
            {
                if((-1 != CheckPortList(pxSp->wPortList, pxSp->wPortCount,wSPort)) ||
                    (-1 != CheckPortList(pxSp->wPortList, pxSp->wPortCount, wDPort)))
                    break;      /* pxSp found*/
                else
                    continue;   /* not match try next entry*/
            }

#ifndef __ENABLE_IPSEC_PORT_RANGE__
            if (!pxSp->wSrcPort || (pxSp->wSrcPort == wSPort))
#else
            if (!CheckPortRange(pxSp->wSrcPort, pxSp->wSrcPortEnd, wSPort))
#endif
            {
                /* ICMP special case!!! */
                if ((IPPROTO_ICMP == oProto) ||
                    (IPPROTO_ICMPV6 == oProto))
                    break;

#ifndef __ENABLE_IPSEC_PORT_RANGE__
                if ((MCP_NO_PORT== pxSp->wDestPortType)||(pxSp->wDestPortType == MCP_SINGLE_PORT && (pxSp->wDestPort == wDPort))||
                        (pxSp->wDestPortType == MCP_PORT_LIST &&
                            (-1 != CheckPortList(pxSp->wDestPortList,pxSp->wDestPortCount,wDPort))))
#else
                if ((MCP_NO_PORT== pxSp->wDestPortType)||(pxSp->wDestPortType == MCP_PORT_LIST &&
                    (-1 != CheckPortList(pxSp->wDestPortList,pxSp->wDestPortCount,wDPort)))
                    ||!CheckPortRange(pxSp->wDestPort, pxSp->wDestPortEnd, wDPort))
#endif
                    break; /* found!!! */
            }
        }

    } /* for */

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__DISABLE_IPSEC_TUNNEL_MODE__)
exit:
#endif
    return pxSp;
} /* IPSEC_getSp */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_SERVER__

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
#ifndef __ENABLE_DIGICERT_IPV6__
#define DEC_MOC_IPADDR(a)   --(a)
#define INC_MOC_IPADDR(a)   ++(a)
#else
#define DEC_MOC_IPADDR(a)   if (AF_INET6 == (a)->family) DecIpAdrr6(a); else --((a)->uin.addr)
#define INC_MOC_IPADDR(a)   if (AF_INET6 == (a)->family) IncIpAddr6(a); else ++((a)->uin.addr)

static void
DecIpAdrr6(MOC_IP_ADDRESS addr6)
{
    sbyte4 i;
    for (i=3; 0 <= i; i--)
    {
        ubyte4 v = GET_NTOHL(addr6->uin.addr6[i]);
        SET_HTONL(addr6->uin.addr6[i], v - 1);
        if (v) break;
    }
    return;
}

static void
IncIpAddr6(MOC_IP_ADDRESS addr6)
{
    sbyte4 i;
    for (i=3; 0 <= i; i--)
    {
        ubyte4 v = GET_NTOHL(addr6->uin.addr6[i]) + 1;
        SET_HTONL(addr6->uin.addr6[i], v);
        if (v) break;
    }
    return;
}

#endif /* __ENABLE_DIGICERT_IPV6__ */
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */


/*------------------------------------------------------------------*/

static MSTATUS
MoreNarrowing(IPSECKEY_EX pxKey, sbyte4 numSp, SPD axSp[], MSTATUS aStat[])
{
    MSTATUS status = OK;

    sbyte4 i;

    ubyte oProto = pxKey->oUlp;
    ubyte2 wSPort = pxKey->wSrcPort;
    ubyte2 wDPort = pxKey->wDestPort;

    for (i=0; i < numSp; i++)
    {
        SPD pxSp = axSp[i];

        if (pxSp->oProto && (oProto != pxSp->oProto))
            continue;

#ifndef __ENABLE_IPSEC_PORT_RANGE__
        if ((pxSp->wSrcPort && (wSPort != pxSp->wSrcPort)) ||
            (pxSp->wDestPort && (wDPort != pxSp->wDestPort)))
            continue;
#else
        if ((!wSPort && (pxSp->wSrcPort || pxSp->wSrcPortEnd)) ||
            (!wDPort && (pxSp->wDestPort || pxSp->wDestPortEnd)))
            continue;

        if ((wSPort && CheckPortRange(pxSp->wSrcPort, pxSp->wSrcPortEnd, wSPort)) ||
            (wDPort && CheckPortRange(pxSp->wDestPort, pxSp->wDestPortEnd, wDPort)))
            continue;
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TRANSPORT != pxKey->oMode)
        {
            sbyte4 retSrc, retDest;

            MOC_IP_ADDRESS saSrcAddr, saSrcAddrEnd;
            MOC_IP_ADDRESS saDestAddr, saDestAddrEnd;

            MOC_IP_ADDRESS_S dwSrcIP, dwSrcIPEnd;
            MOC_IP_ADDRESS_S dwDestIP, dwDestIPEnd;

            saSrcAddr    = pxKey->dwSrcIP;
            saSrcAddrEnd = pxKey->dwSrcIPEnd;

            dwSrcIP      = pxSp->dwSrcIP;
            dwSrcIPEnd   = pxSp->dwSrcIPEnd;

            retSrc = IntersectIpRange(REF_MOC_IPADDR(dwSrcIP), REF_MOC_IPADDR(dwSrcIPEnd),
                                      saSrcAddr, saSrcAddrEnd);
            if (!retSrc) continue;

            saDestAddr    = pxKey->dwDestIP;
            saDestAddrEnd = pxKey->dwDestIPEnd;

            dwDestIP      = pxSp->dwDestIP;
            dwDestIPEnd   = pxSp->dwDestIPEnd;

            retDest = IntersectIpRange(REF_MOC_IPADDR(dwDestIP), REF_MOC_IPADDR(dwDestIPEnd),
                                       saDestAddr, saDestAddrEnd);
            if (!retDest) continue;

            if (0 > retSrc) /* TS of selected policy is not subset of a previously rejected policy */
            {
                if (GT_MOC_IPADDR(REF_MOC_IPADDR(dwSrcIP), saSrcAddr) &&
                    !GT_MOC_IPADDR(saSrcAddrEnd, REF_MOC_IPADDR(dwSrcIPEnd)))
                {
                    UPD_MOC_IPADDR(pxKey->dwSrcIPEnd, dwSrcIP);
                    DEC_MOC_IPADDR(pxKey->dwSrcIPEnd);
                }
                else
                if (GT_MOC_IPADDR(saSrcAddrEnd, REF_MOC_IPADDR(dwSrcIPEnd)) &&
                    !GT_MOC_IPADDR(REF_MOC_IPADDR(dwSrcIP), saSrcAddr))
                {
                    UPD_MOC_IPADDR(pxKey->dwSrcIP, dwSrcIPEnd);
                    INC_MOC_IPADDR(pxKey->dwSrcIP);
                }
                continue;
            }

            if (0 > retDest) /* see above */
            {
                if (GT_MOC_IPADDR(REF_MOC_IPADDR(dwDestIP), saDestAddr) &&
                    !GT_MOC_IPADDR(saDestAddrEnd, REF_MOC_IPADDR(dwDestIPEnd)))
                {
                    UPD_MOC_IPADDR(pxKey->dwDestIPEnd, dwDestIP);
                    DEC_MOC_IPADDR(pxKey->dwDestIPEnd);
                }
                else
                if (GT_MOC_IPADDR(saDestAddrEnd, REF_MOC_IPADDR(dwDestIPEnd)) &&
                    !GT_MOC_IPADDR(REF_MOC_IPADDR(dwDestIP), saDestAddr))
                {
                    UPD_MOC_IPADDR(pxKey->dwDestIP, dwDestIPEnd);
                    INC_MOC_IPADDR(pxKey->dwDestIP);
                }
                continue;
            }
        }
#endif
        status = aStat[i]; /* conflict! */
        break;
    }

    return status;
} /* MoreNarrowing */


/*------------------------------------------------------------------*/

static void
DoNarrowing(IPSECKEY_EX pxKey, SPD pxSp)
{
    if (!pxKey->oUlp && pxSp->oProto)
        pxKey->oUlp = pxSp->oProto;

    if (!pxKey->wDestPort)
    {
        if (pxSp->wDestPort)
            pxKey->wDestPort = pxSp->wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        else pxKey->wDestPort = pxSp->wDestPortEnd;
#endif
    }

    if (!pxKey->wSrcPort)
    {
        if (pxSp->wSrcPort)
            pxKey->wSrcPort = pxSp->wSrcPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        else pxKey->wSrcPort = pxSp->wSrcPortEnd;
#endif
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TRANSPORT != pxKey->oMode)
    {
        MOC_IP_ADDRESS_S dwDestIP     = pxSp->dwDestIP;
        MOC_IP_ADDRESS_S dwDestIPEnd  = pxSp->dwDestIPEnd;

        MOC_IP_ADDRESS_S dwSrcIP      = pxSp->dwSrcIP;
        MOC_IP_ADDRESS_S dwSrcIPEnd   = pxSp->dwSrcIPEnd;

        if (GT_MOC_IPADDR(REF_MOC_IPADDR(dwDestIP), pxKey->dwDestIP))
        {
            UPD_MOC_IPADDR(pxKey->dwDestIP, dwDestIP);
        }

        if (GT_MOC_IPADDR(pxKey->dwDestIPEnd, REF_MOC_IPADDR(dwDestIPEnd)))
        {
            UPD_MOC_IPADDR(pxKey->dwDestIPEnd, dwDestIPEnd);
        }

        if (GT_MOC_IPADDR(REF_MOC_IPADDR(dwSrcIP), pxKey->dwSrcIP))
        {
            UPD_MOC_IPADDR(pxKey->dwSrcIP, dwSrcIP);
        }

        if (GT_MOC_IPADDR(pxKey->dwSrcIPEnd, REF_MOC_IPADDR(dwSrcIPEnd)))
        {
            UPD_MOC_IPADDR(pxKey->dwSrcIPEnd, dwSrcIPEnd);
        }
    }
#endif

    return;
} /* DoNarrowing */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_getSp2(IPSECKEY_EX pxKey)
{
    /* [v2] match incoming proposal - called by IPSEC_keyReady() only */
    MSTATUS status = ERR_SPD_UNACCEPTABLE_TS;

    SPD pxSp = NULL;
    sbyte4 i, iNest = pxKey->iNest;

    ubyte oProto = pxKey->oUlp;
    ubyte2 wSPort = pxKey->wSrcPort;
    ubyte2 wDPort = pxKey->wDestPort;

    MOC_IP_ADDRESS saDestAddr, saSrcAddr;
    MOC_IP_ADDRESS saDestAddrEnd, saSrcAddrEnd;

    SPD axSp[IPSEC_SPD_MATCH] = { NULL }; /* unchosen policies (matched TS) */
    MSTATUS aStat[IPSEC_SPD_MATCH];
    sbyte4 numSp = 0;

    /* special handling for IKE traffic (i.e. udp 500/4500) */
    intBoolean bIke =
       ((IPPROTO_UDP == oProto) &&
        ((IKE_DEFAULT_UDP_PORT == wSPort)   ||
#ifdef __ENABLE_IPSEC_NAT_T__
         (IKE_NAT_UDP_PORT == wSPort)       ||
         (IKE_NAT_UDP_PORT == wDPort)       ||
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
         (IKE_GDOI_UDP_PORT == wSPort)      ||
         (IKE_GDOI_UDP_PORT == wDPort)      ||
#endif
         (IKE_DEFAULT_UDP_PORT == wDPort)));

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TRANSPORT != pxKey->oMode)
    {
        saDestAddr = pxKey->dwDestIP;
        saSrcAddr = pxKey->dwSrcIP;
        saDestAddrEnd = pxKey->dwDestIPEnd;
        saSrcAddrEnd = pxKey->dwSrcIPEnd;
    }
    else
#endif
    {
        if (bIke) goto exit; /* !!! */

        saDestAddr = pxKey->dwDestAddr;
        saSrcAddr = pxKey->dwSrcAddr;
        saDestAddrEnd = saDestAddr;
        saSrcAddrEnd = saSrcAddr;
    }

    /* traverse SPD */
    for (i=0; i < m_ipsecSpdNum; i += 2, pxSp = NULL)
    {
        sbyte4 ret;
        intBoolean bNarrow = FALSE;

        pxSp = &(m_ipsecSpd[i]);

        if (!(IPSEC_SP_FLAG_INUSE & pxSp->flags) ||
            (IPSEC_SP_FLAG_DELETED & pxSp->flags))
            continue;

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
        if (pxSp->ifid)
        {
            switch (pxSp->oAction)
            {
            case IPSEC_ACTION_BYPASS :
            case IPSEC_ACTION_DROP :
                continue;
            }
        }
#endif

#ifdef USE_MOC_COOKIE
        if (pxSp->cookie && (pxKey->cookie != pxSp->cookie))
            continue;
#endif

        /* match traffic selector */
        if (pxSp->oProto)
        {
            if (oProto)
            {
                if (oProto != pxSp->oProto) continue;
            }
            else bNarrow = TRUE;
        }
#ifndef __ENABLE_IPSEC_PORT_RANGE__
        if (pxSp->wDestPort)
        {
            if (wDPort)
            {
                if (wDPort != pxSp->wDestPort) continue;
            }
            else bNarrow = TRUE;
        }

        if (pxSp->wSrcPort)
        {
            if (wSPort)
            {
                if (wSPort != pxSp->wSrcPort) continue;
            }
            else bNarrow = TRUE;
        }
#else
        if ((wDPort && CheckPortRange(pxSp->wDestPort, pxSp->wDestPortEnd, wDPort)) ||
            (wSPort && CheckPortRange(pxSp->wSrcPort, pxSp->wSrcPortEnd, wSPort)))
            continue;

        if ((!wDPort && (pxSp->wDestPort || pxSp->wDestPortEnd)) ||
            (!wSPort && (pxSp->wSrcPort || pxSp->wSrcPortEnd)))
            bNarrow = TRUE;
#endif
        ret = IntersectIpRange(REF_MOC_IPADDR(pxSp->dwDestIP),
                               REF_MOC_IPADDR(pxSp->dwDestIPEnd),
                               saDestAddr, saDestAddrEnd);
        if (!ret) continue;
        if (0 > ret) bNarrow = TRUE;

        ret = IntersectIpRange(REF_MOC_IPADDR(pxSp->dwSrcIP),
                               REF_MOC_IPADDR(pxSp->dwSrcIPEnd),
                               saSrcAddr, saSrcAddrEnd);
        if (!ret) continue;
        if (0 > ret) bNarrow = TRUE;

        /* match proposal */
        switch (pxSp->oAction)
        {
        case IPSEC_ACTION_BYPASS :
        case IPSEC_ACTION_DROP :
            status = ERR_SPD_UNACCEPTABLE_TS;
            break;
        default :
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if (bIke && /* must be tunnel mode */
                (ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP) ||
                 (SAME_MOC_IPADDR(saDestAddr, pxSp->dwTunlDestIP) &&
                  SAME_MOC_IPADDR(saDestAddrEnd, pxSp->dwTunlDestIP))) &&
                (ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP) ||
                 (SAME_MOC_IPADDR(saSrcAddr, pxSp->dwTunlSrcIP) &&
                  SAME_MOC_IPADDR(saSrcAddrEnd, pxSp->dwTunlSrcIP))))
            {
                status = ERR_SPD_UNACCEPTABLE_TS;
                break;
            }
#endif
            if (OK > (status = IPSEC_checkSp(pxKey, pxSp)))
                break;

            if ((0 > iNest) || (iNest >= pxSp->oSaLen)) /* jic */
            {
                status = ERR_SPD_INVALID_BUNDLE;
                break;
            }

            if (!IPSEC_matchSp(pxKey, NULL, pxSp, iNest))
                status = ERR_SPD_UNMATCHED_ALGOS;

            break;
        }

        if (OK > status) /* no proposal chosen */
        {
            if (!bNarrow) /* stop */
            {
                if (0 < numSp) pxSp = NULL;
                goto exit;
            }
            axSp[numSp] = pxSp; /* store this policy (thread-safe???) */
            aStat[numSp++] = status;
            if(IPSEC_SPD_MATCH <= numSp)
            {
                pxSp = NULL;
                goto exit;
            }
            continue;
        }

        /* narrowing */
        if (bNarrow) DoNarrowing(pxKey, pxSp);

        /* check against traffic selectors in previously stored policies */
        if (0 < numSp)
        {
            if (OK > (status = MoreNarrowing(pxKey, numSp, axSp, aStat)))
            {
                pxSp = NULL;
                goto exit;
            }
        }

        if (bNarrow) status = STATUS_SPD_NARROWED;

        pxKey->dwExpSecs = pxSp->dwSaSecs;
        pxKey->dwExpKBytes = (pxSp->dwSaBytes + 1023) / (ubyte4)1024;

        break; /* found */
    } /* for */

exit:
    if (NULL != pxSp)
    {
        pxKey->spdIndex = pxSp->index;
        pxKey->dwSpdId = pxSp->dwId;
    }

    return status;
} /* IPSEC_getSp2 */

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_checkSp(IPSECKEY_EX pxKey, SPD pxSp)
{
    MSTATUS status = OK;

#ifdef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxKey->oMode) /* jic */
    {
        status = ERR_SPD_INVALID_MODE;
        goto exit;
    }
    MOC_UNUSED(pxSp);
#else
    if ((0 != pxSp->oMode) && (pxKey->oMode != pxSp->oMode))
    {
        status = ERR_SPD_INVALID_MODE;
        goto exit;
    }

    if ((IPSEC_MODE_TRANSPORT != pxKey->oMode) &&
        ((!SAME_MOC_IPADDR(pxKey->dwDestAddr, pxSp->dwTunlDestIP) &&
          !ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP)) ||
         (!SAME_MOC_IPADDR(pxKey->dwSrcAddr, pxSp->dwTunlSrcIP) &&
          !ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP))))
    {
        status = ERR_SPD_INVALID_ID_INFO;
        goto exit;
    }
#endif

exit:
    return status;
} /* IPSEC_checkSp */


/*------------------------------------------------------------------*/

extern intBoolean
IPSEC_matchSp(IPSECKEY_EX pxKey, SADB pxSa, SPD pxSp, sbyte4 i)
{
    intBoolean bResult = FALSE;

    struct sainfo *pSaInfo = &(pxSp->pxSa[i]);
    ubyte oSecuProto    = pSaInfo->oSecuProto;  /* AH, ESP, ESP_AUTH, or ESP_NULL */
    ubyte oAuthAlgo     = pSaInfo->oAuthAlgo;   /* hash algorithm ID */
    ubyte oEncrAlgo     = pSaInfo->oEncrAlgo;   /* encryption algorithm ID */
    ubyte oEncrKeyLen   = pSaInfo->oEncrKeyLen;
    ubyte aeadTag       = pSaInfo->aeadTag;     /* tag size - for ESP-AEAD algo */

    AeadAlgo *pAeadAlgo = NULL;
    ubyte oSaAeadIcvLen = 0;

    ubyte2 wSaEncrKeyLen = 0;
    ubyte oSaProto, oSaAuth, oSaEncr;

    SADB_cipherSuiteInfo *pCipherSuite = NULL;

    if (pxKey) /* __ENABLE_DIGICERT_IKE_SERVER__ */
    {
        oSaProto    = pxKey->oProtocol;
        oSaAuth     = pxKey->oAuthAlgo;
        oSaEncr     = pxKey->oEncrAlgo;

        if (oSaEncr)
        {
            wSaEncrKeyLen = pxKey->wEncrKeyLen;
            oSaAeadIcvLen = pxKey->oAeadIcvLen;

            if (!wSaEncrKeyLen || /* key-length must be specified */
                (NULL == (pCipherSuite = IPSEC_cipherSuite(oSaEncr,
                                                           oSaAeadIcvLen,
                                                           wSaEncrKeyLen, NULL))))
            {
                goto exit; /* unsupported */
            }

            pAeadAlgo = pCipherSuite->pAeadAlgo;

            if ((NULL != pAeadAlgo) && /* AEAD algo */
                !oSaAeadIcvLen) /* tag-size must be specified */
            {
                goto exit;
            }
        }
    }
    else if (pxSa)
    {
        SADB_hmacSuiteInfo *pHmacSuite = pxSa->pHmacSuite;
        oSaAuth = (pHmacSuite ? pHmacSuite->oAuthAlgo : 0);

        oSaProto = pxSa->oSaProto;

        pCipherSuite = pxSa->pCipherSuite;
        oSaEncr = (pCipherSuite ? pCipherSuite->oEncrAlgo : 0);
        if (oSaEncr)
        {
            wSaEncrKeyLen = pxSa->wEncrKeyLen;

            pAeadAlgo = pCipherSuite->pAeadAlgo;
            oSaAeadIcvLen = (ubyte)(pAeadAlgo ? pAeadAlgo->tagSize : 0);
        }
    }
    else goto exit; /* jic */

    /* match protocols */
    switch (oSecuProto)
    {
    case IPSEC_PROTO_AH :
        if (oSaProto && (IPPROTO_AH != oSaProto))
        {
            goto exit; /* mismatch */
        }
        break;
    case IPSEC_PROTO_ESP :
    case IPSEC_PROTO_ESP_AUTH :
    case IPSEC_PROTO_ESP_NULL :
        if (oSaProto && (IPPROTO_ESP != oSaProto))
        {
            goto exit; /* mismatch */
        }
        break;
    default : /* unsupported protocol */
        goto exit; /* jic */
    }

    /* match authentication */
    switch (oSecuProto)
    {
    case IPSEC_PROTO_ESP :
        if (oSaAuth) goto exit;
        break;

    case IPSEC_PROTO_ESP_AUTH :
        if (((IPSEC_ENCALG_AES_GCM == oSaEncr) ||
                (IPSEC_ENCALG_AES_CCM == oSaEncr) ||
                (IPSEC_ENCALG_CHACHA20_POLY1305 == oSaEncr)) && /* special case */
            !oAuthAlgo && /* 'any' hash algo specified in SPD */
            !oSaAuth) /* SA/key has no hash algo */
            break;
#ifdef __ENABLE_DIGICERT_GCM__
    case IPSEC_PROTO_ESP_NULL : /* TODO */
        if ((IPSEC_ENCALG_AES_GMAC == oSaEncr) && /* special case */
            !oAuthAlgo && /* 'any' hash algo specified in SPD */
            !oSaAuth) /* SA/key has no hash algo */
            goto match;
#endif
/*  case IPSEC_PROTO_ESP_AUTH :
    case IPSEC_PROTO_ESP_NULL :
    case IPSEC_PROTO_AH :*/
    default :
        if (!oSaAuth || /* this SA has no hash algo. */
            (oAuthAlgo && (oAuthAlgo != oSaAuth)))
        {
            goto exit; /* mismatch */
        }
        break;
    }

    /* match encryption */
    switch (oSecuProto)
    {
    case IPSEC_PROTO_ESP_NULL :
        if (oSaEncr) goto exit;
    case IPSEC_PROTO_AH :
        goto match;
/*  case IPSEC_PROTO_ESP_AUTH :
    case IPSEC_PROTO_ESP :*/
    default :
        break;
    }

    if (!oSaEncr || /* this SA has no encr. algo. */
        (oEncrAlgo && (oEncrAlgo != oSaEncr)))
    {
        goto exit; /* mismatch */
    }

    /* key-length */
    if (oEncrKeyLen)
    {
        /* add 'nonce' length (e.g. AEAD 'salt' or aes-ctr) */
        oEncrKeyLen = oEncrKeyLen + pCipherSuite->oNonceLen;
        if (wSaEncrKeyLen != (ubyte2)oEncrKeyLen)
        {
            goto exit; /* mismatch */
        }
    }

    /* check AEAD algo */
    if (aeadTag) /* specific tag size */
    {
        if (aeadTag != oSaAeadIcvLen) /* mismatch */
        {
            goto exit;
        }
    }

match:
    bResult = TRUE; /* matched */

exit:
    return bResult;
} /* IPSEC_matchSp */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

