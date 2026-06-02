/**
 * @file  ipseckey.c
 * @brief NanoSec IPsec SADB key management implementation.
 *
 * @details    This file contains IPsec Security Association key management implementation.
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
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"
#include "../ipsec/sadb.h"
/*#include "../ike/ike.h"*/
#include "../ike/ikekey.h"
#ifdef __ENABLE_RB_SADB__
#include "../common/hash_table.h"
#include "../common/hash_value.h"
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;
#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
extern hashTableOfPtrs *m_hashTableFqdnNameMapping;
extern ubyte m_fqdnName[MAX_UNICAST_GROUP][MOC_MAX_FQDN_LEN];
extern ubyte4 m_fqdnConfigured;
#endif

#if defined(__ENABLE_RB_SADB__)
#if defined(DECL_RB_LOCK) || defined(INIT_RB_LOCK) || defined(DOWN_RB_LOCK) || defined(UP_RB_LOCK) || defined(FREE_RB_LOCK)
#ifndef DECL_RB_LOCK
#error "Must define DECL_RB_LOCK(_)"
#endif
#ifndef INIT_RB_LOCK
#error "Must define INIT_RB_LOCK(_)"
#endif
#ifndef DOWN_RB_LOCK
#error "Must define DOWN_RB_LOCK(_)"
#endif
#ifndef UP_RB_LOCK
#error "Must define UP_RB_LOCK(_)"
#endif
#ifndef FREE_RB_LOCK
#error "Must define FREE_RB_LOCK(_)"
#endif

#elif defined(__LINUX_RTOS__) && defined(__KERNEL__)
#define DECL_RB_LOCK(_m)  static spinlock_t _m;
#define INIT_RB_LOCK(_m)  spin_lock_init(&(_m));
#define DOWN_RB_LOCK(_m)  spin_lock_bh(&(_m));
#define UP_RB_LOCK(_m)    spin_unlock_bh(&(_m));
#define FREE_RB_LOCK(_m)

#elif defined(__QNX_RTOS__) && defined(_KERNEL)
#define DECL_RB_LOCK(_m)  static pthread_spinlock_t _m;
#define INIT_RB_LOCK(_m)  pthread_spin_init(&(_m), PTHREAD_PROCESS_SHARED);
#define DOWN_RB_LOCK(_m)  pthread_spin_lock(&(_m));
#define UP_RB_LOCK(_m)    pthread_spin_unlock(&(_m));
#define FREE_RB_LOCK(_m)

#elif defined(__VXWORKS_RTOS__)
#define DECL_RB_LOCK(_m)    static Ipcom_mutex _m = NULL;
#define INIT_RB_LOCK(_m)    if(OK > (status = ipcom_mutex_create(&(_m)))) goto exit;
#define DOWN_RB_LOCK(_m)    ipcom_mutex_lock(_m);
#define UP_RB_LOCK(_m)      ipcom_mutex_unlock(_m);
#define FREE_RB_LOCK(_m)    if(_m) ipcom_mutex_delete(&(_m));

#else
#define DECL_RB_LOCK(_m)  static RTOS_MUTEX _m = NULL;
#define INIT_RB_LOCK(_m)  if (OK > (status = RTOS_mutexCreate(&(_m), 0, 1))) goto exit;
#define DOWN_RB_LOCK(_m)  RTOS_mutexWait(_m);
#define UP_RB_LOCK(_m)    RTOS_mutexRelease(_m);
#define FREE_RB_LOCK(_m)  if (_m) RTOS_mutexFree(&(_m));
#endif

#define RB_SYNC(_m, _e) \
    DOWN_RB_LOCK(_m) \
    _e ; \
    UP_RB_LOCK(_m)


#define IPSEC_SAOUTBND_INIT_HASH_VALUE  (0x0641517c)
#ifdef __ENABLE_DIGICERT_IPV6__
#define GEN_OUTBND_HASH_VALUE(_daddr, _hv) \
    if (AF_INET6 == (_daddr).family) \
        HASH_VALUE_hashGen((const void *)RET_MOC_IPADDR6(_daddr), 16, \
                           IPSEC_SAOUTBND_INIT_HASH_VALUE, &(_hv)); \
    else \
        HASH_VALUE_hashGen((const void *)&(RET_MOC_IPADDR4(_daddr)), 4, \
                           IPSEC_SAOUTBND_INIT_HASH_VALUE, &(_hv));

#else
#define GEN_OUTBND_HASH_VALUE(_daddr, _hv) \
    HASH_VALUE_hashGen(&(_daddr), sizeof(_daddr), \
                       IPSEC_SAOUTBND_INIT_HASH_VALUE, &(_hv));

#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
MOC_EXTERN RTOS_MUTEX m_mtxOutbnd;
MOC_EXTERN hashTableOfPtrs *m_hashTableOutbnd;
#endif
#endif


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyAdd_ex(IPSECKEY axKey, sbyte4 num)
#else
extern sbyte4
IPSEC_keyAdd(IPSECKEY axKey, sbyte4 num)
#endif
{
    MSTATUS status = ERR_IPSEC;

    /* check key info */
    sbyte4 i;
    for (i=0; i < num; i++)
    {
        IPSECKEY pxKey = &(axKey[i]);

        if (0 == pxKey->dwDestAddr)
        {
            /* dest addr must not be a 'wildcard' - for now */
            goto exit;
        }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        /* check mode */
        switch (pxKey->oMode)
        {
        case IPSEC_MODE_DONTCARE : /* 0 */
        case IPSEC_MODE_TRANSPORT :
        case IPSEC_MODE_TUNNEL :
            break;
        default :
            goto exit;
        }
#endif
        /* check protocol vs. algos. */
        switch (pxKey->oProtocol)
        {
        case 0 :
        case IPPROTO_AH :
            if (0 == pxKey->oAuthAlgo) goto exit;
            break;
        case IPPROTO_ESP :
            if ((0 == pxKey->oAuthAlgo) && (0 == pxKey->oEncrAlgo))
                goto exit;
            break;
        default :
            goto exit;
            /*break;*/
        }

        /* check auth. key */
        if (0 != pxKey->oAuthAlgo)
        {
            if ((NULL == pxKey->pAuthKey) || (0 == pxKey->wAuthKeyLen))
                goto exit;
        }

        /* check encr. key */
        if ((0 != pxKey->oEncrAlgo) && (IPPROTO_AH != pxKey->oProtocol))
        {
            if ((NULL == pxKey->pEncrKey) || (0 == pxKey->wEncrKeyLen))
                goto exit;

#ifdef __ENABLE_DIGICERT_GCM__
            /* TODO: should other AEAD algorithms be added to this list? */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            if (!(IPSEC_SA_FLAG_GDOI & pxKey->flags))
#endif
            switch (pxKey->oEncrAlgo)
            {
            case IPSEC_ENCALG_AES_GCM :
            case IPSEC_ENCALG_AES_GMAC :
                /* MUST NOT use manual keying; see RFC4106 2. & RFC4543 2. */
                goto exit;
            }
#endif
        }
    } /* for */

    /* add new SA's */
    for (i=0; i < num; i++)
    {
        MSTATUS st;
        struct ipsecKeyEx keyEx = { 0 };
        IPSECKEY pxKey = &(axKey[i]);

#ifndef __ENABLE_DIGICERT_IPV6__
        #define destAddr pxKey->dwDestAddr
        #define srcAddr pxKey->dwSrcAddr
#else
        MOC_IP_ADDRESS_S destAddr, srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        MOC_IP_ADDRESS_S snIP, snIPEnd;
#endif
        if (pxKey->dwDestAddr)
        {
            if (IPSEC_SA_FLAG_IP6 & pxKey->flags) {
                SET_MOC_IPADDR6(destAddr, pxKey->dwDestAddr); }
            else {
                SET_MOC_IPADDR4(destAddr, pxKey->dwDestAddr); }
        }
        else {
            ZERO_MOC_IPADDR(destAddr); }

        if (pxKey->dwSrcAddr)
        {
            if (IPSEC_SA_FLAG_IP6 & pxKey->flags) {
                SET_MOC_IPADDR6(srcAddr, pxKey->dwSrcAddr); }
            else {
                SET_MOC_IPADDR4(srcAddr, pxKey->dwSrcAddr); }
        }
        else {
            ZERO_MOC_IPADDR(srcAddr); }
#endif /* __ENABLE_DIGICERT_IPV6__ */

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        if (IPSEC_SA_FLAG_GDOI & pxKey->flags)
            keyEx.flags         = IPSEC_SA_FLAG_GDOI;
#endif
        if (!(IPSEC_SA_FLAG_ASCIIKEY & pxKey->flags))
        keyEx.flags            |= IPSEC_SA_FLAG_HEXKEY;

        keyEx.oProtocol         = pxKey->oProtocol;
        keyEx.dwSpi             = pxKey->dwSpi;

        keyEx.dwDestAddr        = REF_MOC_IPADDR(destAddr);
        keyEx.dwSrcAddr         = REF_MOC_IPADDR(srcAddr);

#ifdef __ENABLE_IPSEC_NAT_T__
        keyEx.wUdpEncPort       = pxKey->wUdpEncPort;
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if ((keyEx.oMode        = pxKey->oMode) != IPSEC_MODE_TRANSPORT)
        {
            /* special case !!! */
#ifndef __ENABLE_DIGICERT_IPV6__
            keyEx.dwDestIPEnd   =
            keyEx.dwSrcIPEnd    = 0xffffffff;
#else
            if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
            {
                ubyte4 dwIPEnd[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
                ZERO_MOC_IPADDR(snIP); snIP.family = AF_INET6;
                SET_MOC_IPADDR6(snIPEnd, dwIPEnd);
            }
            else
            {
                SET_MOC_IPADDR4(snIP, 0);
                SET_MOC_IPADDR4(snIPEnd, 0xffffffff);
            }

            keyEx.dwDestIP      =
            keyEx.dwSrcIP       = REF_MOC_IPADDR(snIP);
            keyEx.dwDestIPEnd   =
            keyEx.dwSrcIPEnd    = REF_MOC_IPADDR(snIPEnd);

#endif /* __ENABLE_DIGICERT_IPV6__*/
        }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

        if ((keyEx.oAuthAlgo    = pxKey->oAuthAlgo) != 0)
        {
            keyEx.wAuthKeyLen   = pxKey->wAuthKeyLen;
            keyEx.poAuthKey     = (ubyte *) pxKey->pAuthKey;
        }

        if ((IPPROTO_AH != pxKey->oProtocol) &&
            ((keyEx.oEncrAlgo   = pxKey->oEncrAlgo) != 0))
        {
            keyEx.wEncrKeyLen   = pxKey->wEncrKeyLen;
            keyEx.poEncrKey     = (ubyte *) pxKey->pEncrKey;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            keyEx.oAeadIcvLen   = pxKey->oAeadIcvLen;
        }
        keyEx.dwExpSecs         = pxKey->dwExpSecs;
        keyEx.dwExpKBytes       = pxKey->dwExpKBytes;
#else
        }
#endif
        keyEx.wDestPort = pxKey->wDestPort;
        keyEx.wSrcPort = pxKey->wSrcPort;
        keyEx.oUlp = pxKey->oUlp;

        SET_MOC_COOKIE(keyEx.cookie, pxKey->cookie)

        if (OK > (st = IPSEC_newSa(&keyEx, NULL
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                                 , NULL
#endif
                                   )))
        {
            axKey[i].status = (sbyte4)st;
            break;
        }

#ifndef __ENABLE_DIGICERT_IPV6__
        #undef destAddr
        #undef srcAddr
#endif
    } /* for */

    return i; /* returns # of SA's added */

exit:
    return (sbyte4)status;
} /* IPSEC_keyAdd */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)

static MSTATUS
matchFqdnName(fqdnNameMappingConfig *fqdnMapping, fqdnNameMappingConfig *testFqdnMapping, intBoolean *isMatch)
{
    MSTATUS status = OK;
    *isMatch = FALSE;

    if ((!fqdnMapping) || (!testFqdnMapping))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == DIGI_STRCMP(fqdnMapping->fqdnName, testFqdnMapping->fqdnName))
    {
        *isMatch = TRUE;
    }
exit:
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
addFqdnNameMappingInHash(IPSECKEY_EX pxKey)
{
    MSTATUS status = OK;
    ubyte4 ipListhashValue = 0;
    intBoolean isEntryFound = FALSE;
    fqdnNameMappingConfig *fqdnFoundKey = NULL, *fqdnKey = NULL;

    if (NULL == pxKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if ((pxKey->fqdn[0]) && (!(pxKey->inbound)))
    {
        /* Generate a new FQDN to be added in the fqdn mapping hash*/
        DIGI_MALLOC((void **)&fqdnKey, sizeof(fqdnNameMappingConfig));
        DIGI_MEMSET((ubyte *)fqdnKey, '\0', sizeof(fqdnNameMappingConfig));
        DIGI_MEMCPY(fqdnKey->fqdnName, pxKey->fqdn, DIGI_STRLEN((sbyte *)pxKey->fqdn));
        fqdnKey->fqdnUniqueKey = pxKey->fqdnUniqueKey;

        /* Use the FQDN Name as the key for FQDN Name Mapping table */
        GEN_FQDNNAME_MAPPING_HASH_VALUE(pxKey->fqdn,
            DIGI_STRLEN((sbyte *)pxKey->fqdn), ipListhashValue)

        /* Check if entry already exists in Fqdn Name Mapping hash table */
        status = HASH_TABLE_findPtr(m_hashTableFqdnNameMapping, ipListhashValue, fqdnKey,
                    (funcPtrExtraMatchTest)matchFqdnName, (void **)&fqdnFoundKey, &isEntryFound);

        if (!isEntryFound)
        {
            /* Add new entry in FQDN Name Mapping hash table */
            status = HASH_TABLE_addPtr(m_hashTableFqdnNameMapping, ipListhashValue, fqdnKey);
            if (OK > status)
            {
                DIGI_FREE((void **)&fqdnKey);
                goto exit;
            }
            if(m_fqdnConfigured < MAX_UNICAST_GROUP)
            {
                DIGI_MEMSET((ubyte *)m_fqdnName[m_fqdnConfigured], '\0', MOC_MAX_FQDN_LEN);
                DIGI_MEMCPY(m_fqdnName[m_fqdnConfigured], pxKey->fqdn, DIGI_STRLEN((sbyte *)pxKey->fqdn));
                m_fqdnConfigured++;
            }
            else
            {
                DB_PRINT("list mapping entries are more than max unicast group");
            }
        }
        else
        {
            DIGI_FREE((void **)&fqdnKey);
        }
    }
exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/
#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_groupKeyAdd_ex(IPSECKEY_EX pxKey)
#else
extern sbyte4
IPSEC_groupKeyAdd(IPSECKEY_EX pxKey)
#endif
{
    MSTATUS status = ERR_IPSEC;
    MSTATUS st;
    struct ipsecKeyEx keyEx = { 0 };

    /* check key info */
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if (0 == pxKey->dwDestAddr && pxKey->fqdn[0] == 0)
#else
    if (0 == pxKey->dwDestAddr)
#endif
    {
        /* dest addr must not be a 'wildcard' - for now */
        goto exit;
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* check mode */
    switch (pxKey->oMode)
    {
        case IPSEC_MODE_DONTCARE: /* 0 */
        case IPSEC_MODE_TRANSPORT:
        case IPSEC_MODE_TUNNEL:
            break;
        default:
            goto exit;
    }
#endif
    switch (pxKey->oProtocol)
    {
        case 0:
        case IPPROTO_AH:
            if (0 == pxKey->oAuthAlgo) goto exit;
            break;
        case IPPROTO_ESP:
            if ((0 == pxKey->oAuthAlgo) && (0 == pxKey->oEncrAlgo))
                goto exit;
            break;
        default:
            goto exit;
            /*break;*/
    }
    /* check auth. key */
    if (0 != pxKey->oAuthAlgo)
    {
        if ((NULL == pxKey->poAuthKey) || (0 == pxKey->wAuthKeyLen))
        {
            goto exit;
        }
    }

    /* check encr. key */
    if ((0 != pxKey->oEncrAlgo) && (IPPROTO_AH != pxKey->oProtocol))
    {
        if ((NULL == pxKey->poEncrKey) || (0 == pxKey->wEncrKeyLen))
        {
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_GCM__
            /* TODO: should other AEAD algorithms be added to this list? */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        if (!(IPSEC_SA_FLAG_GDOI & pxKey->flags))
#endif
            switch (pxKey->oEncrAlgo)
            {
            case IPSEC_ENCALG_AES_GCM:
            case IPSEC_ENCALG_AES_GMAC:
                /* MUST NOT use manual keying; see RFC4106 2. & RFC4543 2. */
                goto exit;
            }
#endif
    }


    /* add new SA's */


#ifndef __ENABLE_DIGICERT_IPV6__
#define destAddr pxKey->dwDestAddr
#define srcAddr pxKey->dwSrcAddr
#else
        MOC_IP_ADDRESS_S destAddr, srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        MOC_IP_ADDRESS_S snIP, snIPEnd;
#endif

        if (pxKey->dwDestAddr)
        {
            if (IPSEC_SA_FLAG_IP6 & pxKey->flags) {
                SET_MOC_IPADDR6(destAddr, pxKey->dwDestAddr);
            }
            else {
                SET_MOC_IPADDR4(destAddr, pxKey->dwDestAddr);
            }
        }
        else {
            ZERO_MOC_IPADDR(destAddr);
        }

        if (pxKey->dwSrcAddr)
        {
            if (IPSEC_SA_FLAG_IP6 & pxKey->flags) {
                SET_MOC_IPADDR6(srcAddr, pxKey->dwSrcAddr);
            }
            else {
                SET_MOC_IPADDR4(srcAddr, pxKey->dwSrcAddr);
            }
        }
        else {
            ZERO_MOC_IPADDR(srcAddr);
        }
#endif /* __ENABLE_DIGICERT_IPV6__ */

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        if (IPSEC_SA_FLAG_GDOI & pxKey->flags)
            keyEx.flags = IPSEC_SA_FLAG_GDOI;
#endif
        if (!(IPSEC_SA_FLAG_ASCIIKEY & pxKey->flags))
            keyEx.flags |= IPSEC_SA_FLAG_HEXKEY;

        keyEx.oProtocol = pxKey->oProtocol;
        keyEx.dwSpi = pxKey->dwSpi;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        DIGI_MEMCPY(keyEx.dwSrcAddrList, pxKey->dwSrcAddrList, (pxKey->dwSrcAddrCount )*(sizeof(MOC_IP_ADDRESS)));
        keyEx.dwSrcAddrCount = pxKey->dwSrcAddrCount;

        DIGI_MEMCPY(keyEx.dwDestAddrList, pxKey->dwDestAddrList, (pxKey->dwDestAddrCount)*(sizeof(MOC_IP_ADDRESS)));
        keyEx.dwDestAddrCount = pxKey->dwDestAddrCount;

        DIGI_MEMCPY(keyEx.fqdn, pxKey->fqdn, MOC_MAX_FQDN_LEN);
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        keyEx.fqdnUniqueKey = pxKey->fqdnUniqueKey;
#endif
        keyEx.inbound = pxKey->inbound;
#endif

        keyEx.dwDestAddr = REF_MOC_IPADDR(destAddr);
        keyEx.dwSrcAddr = REF_MOC_IPADDR(srcAddr);

#ifdef __ENABLE_IPSEC_NAT_T__
        keyEx.wUdpEncPort = pxKey->wUdpEncPort;
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if ((keyEx.oMode = pxKey->oMode) != IPSEC_MODE_TRANSPORT)
        {
            /* special case !!! */
#ifndef __ENABLE_DIGICERT_IPV6__
            /* keyEx.dwDestIPEnd =
                keyEx.dwSrcIPEnd = 0xffffffff; */ /* overwritten after assignment */
#else
            if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
            {
                ubyte4 dwIPEnd[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
                ZERO_MOC_IPADDR(snIP); snIP.family = AF_INET6;
                SET_MOC_IPADDR6(snIPEnd, dwIPEnd);
            }
            else
            {
                SET_MOC_IPADDR4(snIP, 0);
                SET_MOC_IPADDR4(snIPEnd, 0xffffffff);
            }

            keyEx.dwDestIP =
                keyEx.dwSrcIP = REF_MOC_IPADDR(snIP);
            keyEx.dwDestIPEnd =
                keyEx.dwSrcIPEnd = REF_MOC_IPADDR(snIPEnd);

#endif /* __ENABLE_DIGICERT_IPV6__*/
        }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

        keyEx.dwDestIPEnd = pxKey->dwDestIPEnd;
        keyEx.dwSrcIPEnd = pxKey->dwSrcIPEnd;
        keyEx.dwDestIP = pxKey->dwDestIP;
        keyEx.dwSrcIP = pxKey->dwSrcIP;
        if ((keyEx.oAuthAlgo = pxKey->oAuthAlgo) != 0)
        {
            keyEx.wAuthKeyLen = pxKey->wAuthKeyLen;
            keyEx.poAuthKey = (ubyte *)pxKey->poAuthKey;
        }

        if ((IPPROTO_AH != pxKey->oProtocol) &&
            ((keyEx.oEncrAlgo = pxKey->oEncrAlgo) != 0))
        {
            keyEx.wEncrKeyLen = pxKey->wEncrKeyLen;
            keyEx.poEncrKey = (ubyte *)pxKey->poEncrKey;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            keyEx.oAeadIcvLen = pxKey->oAeadIcvLen;
        }
        keyEx.dwExpSecs = pxKey->dwExpSecs;
        keyEx.dwExpKBytes = pxKey->dwExpKBytes;
#else
    }
#endif
        keyEx.wDestPort = pxKey->wDestPort;
        keyEx.wSrcPort = pxKey->wSrcPort;
        keyEx.oUlp = pxKey->oUlp;

        SET_MOC_COOKIE(keyEx.cookie, pxKey->cookie)

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        st = addFqdnNameMappingInHash(pxKey);
#endif

            if (OK > (st = IPSEC_newSa(&keyEx, NULL
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                , NULL
#endif
            )))
            {
                return st;
            }
        status = st;
#ifndef __ENABLE_DIGICERT_IPV6__
#undef destAddr
#undef srcAddr
#endif


exit:
    return (sbyte4)status;
} /* IPSEC_groupKeyAdd */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_RB_SADB__)
extern MSTATUS
matchKeySa(SADB pxSa, outboundMappingConfig *testOutboundConfig, intBoolean *isMatch)
{
    MSTATUS status = OK;
    *isMatch = FALSE;

    if (!pxSa || !testOutboundConfig ||/* jic */
        (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) ||
        IPSEC_expireSa(testOutboundConfig->timenow, pxSa))
    {
        goto exit;
    }
    if ((!pxSa) || (!testOutboundConfig))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if(testOutboundConfig->fqdnName[0])
    {
        if (0 == DIGI_STRCMP(testOutboundConfig->fqdnName, pxSa->fqdn))
            *isMatch = TRUE;
    }
    else
#endif
    {
        if (SAME_MOC_IPADDR(testOutboundConfig->destIp, pxSa->dwSaDestAddr))
            *isMatch = TRUE;

        if (pxSa->dwSaDestIPEnd)
        {
            if (SAME_MOC_IPADDR(testOutboundConfig->destIpEnd, pxSa->dwSaDestIPEnd))
                *isMatch = TRUE;
            else
                *isMatch = FALSE;
        }
    }
exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyGetEx_ex(IPSECKEY_EX pxKey)
#else
extern sbyte4
IPSEC_keyGetEx(IPSECKEY_EX pxKey)
#endif
{
    MSTATUS status = ERR_IPSEC_DROP_FINDSA_FAIL;
    SADB pxSa = NULL, pxSaFound = NULL;

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    ubyte4 dwSaExpSecs = 0;
#endif

    /* check key info */
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    sbyte4 result = 0;
    if (0 == pxKey->dwDestAddr && '\0' == pxKey->fqdn[0])
#else
    if (0 == pxKey->dwDestAddr)
#endif
    {
        /* dest addr must not be a 'wildcard' - for now */
        goto exit;
    }

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    ubyte4 hashValue = 0;
    intBoolean isEntryFound = FALSE;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        ubyte4 dtime = 0;
#endif
#if defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
    fqdnNameMappingConfig *fqdnFoundKey = NULL;
    fqdnNameMappingConfig fqdnKey;
    MOC_IP_ADDRESS_S temp_addr;

    /* Get the Outbound table key for the corresponding group */
    if (pxKey->fqdn[0])
    {
        /* Generate a new FQDN to be looked up in the fqdn Name mapping hash*/
        DIGI_MEMSET((ubyte *)&fqdnKey, '\0', sizeof(fqdnNameMappingConfig));
        DIGI_MEMCPY(fqdnKey.fqdnName, pxKey->fqdn, DIGI_STRLEN((sbyte *)pxKey->fqdn));

        /* Use the FQDN Name as the key for FQDN Name Mapping table */
        GEN_FQDNNAME_MAPPING_HASH_VALUE(fqdnKey.fqdnName,
            DIGI_STRLEN((sbyte *)fqdnKey.fqdnName), hashValue)

        status = HASH_TABLE_findPtr(m_hashTableFqdnNameMapping, hashValue, &fqdnKey,
                    (funcPtrExtraMatchTest)matchFqdnName, (void **)&fqdnFoundKey, &isEntryFound);

        if ((isEntryFound) && (fqdnFoundKey))
        {
            GEN_OUTBND_HASH_VALUE(fqdnFoundKey->fqdnUniqueKey, hashValue)
            DB_PRINT("FQDN mapping found in fqdnNameMapping hash table for FQDN - [ %s ] key - [ %d ]", fqdnKey.fqdnName,
                fqdnFoundKey->fqdnUniqueKey);
        }
        else
        {
            status = ERR_NULL_POINTER;
            DB_PRINT("FQDN mapping not found in fqdnNameMapping hash table for FQDN - [ %s ]", fqdnKey.fqdnName);
            goto exit;
        }

    }
    else if (pxKey->dwDestIP)
    {
        temp_addr = (MOC_IP_ADDRESS_S)(pxKey->dwDestIP);
        GEN_OUTBND_HASH_VALUE(temp_addr, hashValue)
    }
    else
    {
        temp_addr = (MOC_IP_ADDRESS_S)(pxKey->dwDestAddr);
        GEN_OUTBND_HASH_VALUE(temp_addr, hashValue)
    }

#else
    GEN_OUTBND_HASH_VALUE(pxKey->dwDestAddr, hashValue)
#endif

    outboundMappingConfig outboundConfig;
    DIGI_MEMSET((ubyte *)&outboundConfig, '\0', sizeof(outboundMappingConfig));

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if (pxKey->fqdn[0])
    {
        DIGI_MEMCPY(outboundConfig.fqdnName, pxKey->fqdn, DIGI_STRLEN((sbyte *)pxKey->fqdn));
    }
    else
#endif
    {
        outboundConfig.destIp = (MOC_IP_ADDRESS_S)(pxKey->dwDestIP);
        outboundConfig.destIpEnd = (MOC_IP_ADDRESS_S)(pxKey->dwDestIPEnd);
    }
    outboundConfig.timenow = RTOS_deltaMS(&gStartTime, NULL);
    RB_SYNC(m_mtxOutbnd,
        status = HASH_TABLE_findPtr(m_hashTableOutbnd, hashValue, &outboundConfig,
            (funcPtrExtraMatchTest)matchKeySa,
            (void **)&pxSaFound, &isEntryFound));
    if (OK > status)
        goto exit;

    if (!isEntryFound)
    {
        /*
        if (pxKey->fqdn[0])
           DB_PRINT("Entry not found in outbound SA hash table for FQDN group - %s", pxKey->fqdn);
        else
           DB_PRINT("Entry not found in outbound SA hash table for dest addr - %x", pxKey->dwDestIP);
        */
        goto exit;
    }
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    if (pxSaFound->dwSaExpSecs)
    {
        ubyte4 timenow = 0;
        timenow = RTOS_deltaMS(&gStartTime, NULL);
        dtime = (timenow - pxSaFound->dwSaEstablished) / (ubyte4)1000;
        dwSaExpSecs = pxSaFound->dwSaExpSecs - dtime;
    }
#endif
#else
    /* traverse SADB */
    while (NULL != (pxSa = IPSEC_enumSa(pxSa)))
    {
        ubyte4 timenow = 0;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        ubyte4 dtime = 0;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        MOC_IP_ADDRESS_S destAddr;
#else
#define destAddr pxKey->dwDestAddr
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL != pxSa->pxSp) /* skip auto. key */
            continue;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
        {
            SET_MOC_IPADDR6(destAddr, pxKey->dwDestAddr);
        }
        else
        {
            SET_MOC_IPADDR4(destAddr, pxKey->dwDestAddr);
        }
#endif
#ifndef  __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        if (!SAME_MOC_IPADDR(REF_MOC_IPADDR(destAddr), pxSa->dwSaDestAddr))
            continue;
#else/* in case of the unicast ip range compare start and end ip instead of the destination address*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        /* fqdn entry here*/
        if (pxSa->fqdn[0] != '\0' && !((OK == DIGI_MEMCMP(pxSa->fqdn , pxKey->fqdn, MOC_MAX_FQDN_LEN, &result)) && result == 0))
            continue;
#endif

        if (pxSa->dwSaDestIP && !SAME_MOC_IPADDR(REF_MOC_IPADDR(pxKey->dwDestIP), pxSa->dwSaDestIP))
            continue;

        if (pxSa->dwSaDestIPEnd && !SAME_MOC_IPADDR(REF_MOC_IPADDR(pxKey->dwDestIPEnd), pxSa->dwSaDestIPEnd))
            continue;
#endif

        if (pxSa->oSaUlp && pxKey->oUlp &&
            (pxSa->oSaUlp != pxKey->oUlp))
            continue;

        if (pxSa->wSaDestPort && pxKey->wDestPort &&
            (pxSa->wSaDestPort != pxKey->wDestPort))
            continue;

        /* get usage time */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        if (pxSa->dwSaExpSecs)
        {
            timenow = RTOS_deltaMS(&gStartTime, NULL);
            dtime = (timenow - pxSa->dwSaEstablished) / (ubyte4)1000;
            if (dtime >= pxSa->dwSaExpSecs) continue; /* expired already */
        }
#endif
        /* get the most recent */
        if (pxSaFound)
        {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            /* always choose GDOI key over non-GDOI key */
            if (!(IPSEC_SA_FLAG_GDOI & pxSa->saFlags) &&
                (IPSEC_SA_FLAG_GDOI & pxSaFound->saFlags))
                continue;

            if ((IPSEC_SA_FLAG_GDOI & pxSa->saFlags) ==
                (IPSEC_SA_FLAG_GDOI & pxSaFound->saFlags))
#endif
            {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                if (!timenow)
#endif
                    timenow = RTOS_deltaMS(&gStartTime, NULL);
                if ((timenow - pxSa->dwSaEstablished) >
                    (timenow - pxSaFound->dwSaEstablished))
                    continue;
            }
        }

        /* found */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        dwSaExpSecs = pxSa->dwSaExpSecs - dtime; /* remaining time!!! */
#endif
        pxSaFound = pxSa;
        status = OK;

#ifndef __ENABLE_DIGICERT_IPV6__
#undef destAddr
#endif
    } /* while */
#endif

    if (NULL != pxSaFound)
    {
        struct SADB_hmacSuiteInfo *pHmacSuite;
        struct SADB_cipherSuiteInfo *pCipherSuite;

        pxSa = pxSaFound;

        pxKey->oProtocol = pxSa->oSaProto;
        pxKey->dwSpi = pxSa->dwSaSpi;

        pxKey->wDestPort = pxSa->wSaDestPort;
        pxKey->oUlp = pxSa->oSaUlp;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        pxKey->oMode = pxSa->oSaMode;
#endif
        if (NULL != (pHmacSuite = pxSa->pHmacSuite))
        {
            pxKey->oAuthAlgo = pHmacSuite->oAuthAlgo;
            pxKey->wAuthKeyLen = pHmacSuite->wKeyLen;
            DIGI_MEMCPY(pxKey->poAuthKey, pxSa->poAuthKey, pxKey->wAuthKeyLen);
        }
        else
        {
            pxKey->oAuthAlgo = 0; /* jic */
        }

        if (NULL != (pCipherSuite = pxSa->pCipherSuite))
        {
            pxKey->oEncrAlgo = pCipherSuite->oEncrAlgo;
            pxKey->wEncrKeyLen = pxSa->wEncrKeyLen;
            DIGI_MEMCPY(pxKey->poEncrKey, pxSa->poEncrKey, pxKey->wEncrKeyLen);

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            if (NULL != pCipherSuite->pAeadAlgo)
            {
                pxKey->oNonceLen = (ubyte)pCipherSuite->pAeadAlgo->implicitNonceSize;
                pxKey->oAeadIcvLen = (ubyte)pCipherSuite->pAeadAlgo->tagSize;
            }
            else /* for CTR*/
            {
                pxKey->oNonceLen = (ubyte)pCipherSuite->oNonceLen;
            }
#endif
        }
        else
        {
            pxKey->oEncrAlgo = 0; /* jic */
        }

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        pxKey->dwExpSecs = dwSaExpSecs;
        pxKey->dwExpKBytes = pxSa->dwSaExpKBytes;
#endif
    }

exit:
    return (sbyte4)status;
} /* IPSEC_keyGetEx */


#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyGet_ex(IPSECKEY pxKey)
#else
extern sbyte4
IPSEC_keyGet(IPSECKEY pxKey)
#endif
{
    MSTATUS status = ERR_IPSEC_DROP_FINDSA_FAIL;

    SADB pxSa = NULL, pxSaFound = NULL;

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    ubyte4 dwSaExpSecs = 0;
#endif

    /* check key info */
    if (0 == pxKey->dwDestAddr)
    {
        /* dest addr must not be a 'wildcard' - for now */
        goto exit;
    }

    /* traverse SADB */
    while (NULL != (pxSa = IPSEC_enumSa(pxSa)))
    {
        ubyte4 timenow = 0;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        ubyte4 dtime = 0;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        MOC_IP_ADDRESS_S destAddr;
#else
        #define destAddr pxKey->dwDestAddr
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL != pxSa->pxSp) /* skip auto. key */
            continue;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
        {
            SET_MOC_IPADDR6(destAddr, pxKey->dwDestAddr);
        }
        else
        {
            SET_MOC_IPADDR4(destAddr, pxKey->dwDestAddr);
        }
#endif
        if (!SAME_MOC_IPADDR(REF_MOC_IPADDR(destAddr), pxSa->dwSaDestAddr))
            continue;

        if (pxSa->oSaUlp && pxKey->oUlp &&
            (pxSa->oSaUlp != pxKey->oUlp))
            continue;

        if (pxSa->wSaDestPort && pxKey->wDestPort &&
            (pxSa->wSaDestPort != pxKey->wDestPort))
            continue;

        /* get usage time */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        if (pxSa->dwSaExpSecs)
        {
            timenow = RTOS_deltaMS(&gStartTime, NULL);
            dtime = (timenow - pxSa->dwSaEstablished) / (ubyte4)1000;
            if (dtime >= pxSa->dwSaExpSecs) continue; /* expired already */
        }
#endif
        /* get the most recent */
        if (pxSaFound)
        {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            /* always choose GDOI key over non-GDOI key */
            if (!(IPSEC_SA_FLAG_GDOI & pxSa->saFlags) &&
                (IPSEC_SA_FLAG_GDOI & pxSaFound->saFlags))
                continue;

            if ((IPSEC_SA_FLAG_GDOI & pxSa->saFlags) ==
                (IPSEC_SA_FLAG_GDOI & pxSaFound->saFlags))
#endif
            {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                if (!timenow)
#endif
                timenow = RTOS_deltaMS(&gStartTime, NULL);
                if ((timenow - pxSa->dwSaEstablished) >
                    (timenow - pxSaFound->dwSaEstablished))
                    continue;
            }
        }

        /* found */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        dwSaExpSecs = pxSa->dwSaExpSecs - dtime; /* remaining time!!! */
#endif
        pxSaFound = pxSa;
        status = OK;

#ifndef __ENABLE_DIGICERT_IPV6__
#undef destAddr
#endif
    } /* while */

    if (NULL != pxSaFound)
    {
        struct SADB_hmacSuiteInfo *pHmacSuite;
        struct SADB_cipherSuiteInfo *pCipherSuite;

        pxSa = pxSaFound;

        pxKey->oProtocol = pxSa->oSaProto;
        pxKey->dwSpi = pxSa->dwSaSpi;

        pxKey->wDestPort = pxSa->wSaDestPort;
        pxKey->oUlp = pxSa->oSaUlp;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        pxKey->oMode = pxSa->oSaMode;
#endif
        if (NULL != (pHmacSuite = pxSa->pHmacSuite))
        {
            pxKey->oAuthAlgo = pHmacSuite->oAuthAlgo;
            pxKey->wAuthKeyLen = pHmacSuite->wKeyLen;
            DIGI_MEMCPY(pxKey->pAuthKey, pxSa->poAuthKey, pxKey->wAuthKeyLen);
        }
        else
        {
            pxKey->oAuthAlgo = 0; /* jic */
        }

        if (NULL != (pCipherSuite = pxSa->pCipherSuite))
        {
            pxKey->oEncrAlgo = pCipherSuite->oEncrAlgo;
            pxKey->wEncrKeyLen = pxSa->wEncrKeyLen;
            DIGI_MEMCPY(pxKey->pEncrKey, pxSa->poEncrKey, pxKey->wEncrKeyLen);

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            if (NULL != pCipherSuite->pAeadAlgo)
            {
                pxKey->oNonceLen = (ubyte) pCipherSuite->pAeadAlgo->implicitNonceSize;
                pxKey->oAeadIcvLen = (ubyte) pCipherSuite->pAeadAlgo->tagSize;
            }
#endif
        }
        else
        {
            pxKey->oEncrAlgo = 0; /* jic */
        }

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        pxKey->dwExpSecs = dwSaExpSecs;
        pxKey->dwExpKBytes = pxSa->dwSaExpKBytes;
#endif
    }

exit:
    return (sbyte4)status;
} /* IPSEC_keyGet */


#ifdef __ENABLE_DIGICERT_IKE_SERVER__

/*------------------------------------------------------------------*/

static MSTATUS
CheckKeySp(IPSECKEY_EX pxKey, SPD pxSp)
{
    MSTATUS status = OK;
    sbyte4 iNest = pxKey->iNest;

    if ((0 > iNest) || (IPSEC_NEST_MAX <= iNest)) /* jic */
    {
        status = ERR_SPD_INVALID_BUNDLE;
        goto exit;
    }

    if (iNest < pxSp->oSaLen)
    {
        if (OK > (status = IPSEC_checkSp(pxKey, pxSp)))
            goto exit;

        if (!IPSEC_matchSp(pxKey, NULL, pxSp, iNest))
        {
            status = ERR_SPD_UNMATCHED_ALGOS;
            goto exit;
        }
    }
    else /* only to verify SA bundle size */
    {
        if (pxKey->oAuthAlgo || pxKey->oEncrAlgo
            || pxKey->oProtocol
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            || pxKey->oMode
#endif
            )
        {
            status = ERR_SPD_INVALID_BUNDLE;
            goto exit;
        }
    }

exit:
    return status;
} /* CheckKeySp */


/*------------------------------------------------------------------*/

static MSTATUS
GetKeySp(IPSECKEY_EX pxKey, SPD *ppxSp)
{
    MSTATUS status = OK;
    SPD pxSp = NULL;

    intBoolean bInbound = (IPSEC_SA_FLAG_INBOUND & pxKey->flags)
                        ? TRUE : FALSE;

#ifdef __DISABLE_IPSEC_TUNNEL_MODE__
    #define saDestAddr pxKey->dwDestAddr
    #define saSrcAddr pxKey->dwSrcAddr
#else
    MOC_IP_ADDRESS saDestAddr, saSrcAddr;
    MOC_IP_ADDRESS saDestAddrEnd, saSrcAddrEnd;

    if (IPSEC_MODE_TRANSPORT == pxKey->oMode)
    {
        saDestAddr = pxKey->dwDestAddr;
        saSrcAddr = pxKey->dwSrcAddr;
        saDestAddrEnd = 0;
        saSrcAddrEnd = 0;
    }
    else
    {
        saDestAddr = pxKey->dwDestIP;
        saSrcAddr = pxKey->dwSrcIP;
        saDestAddrEnd = pxKey->dwDestIPEnd;
        saSrcAddrEnd = pxKey->dwSrcIPEnd;
    }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

    /* check against SPD */
    if ((NULL == (pxSp = IPSEC_getSp(saDestAddr, saSrcAddr,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                     saDestAddrEnd, saSrcAddrEnd,
#endif
                                     pxKey->oUlp,
                                     TRUE, /* check ports */
                                     pxKey->wDestPort, pxKey->wSrcPort,
                                     bInbound
                                     MOC_INTF_OPAQ_ID(TRUE, 0)
                                     MOC_COOKIE_VALUE(pxKey->cookie))))
         || (IPSEC_ACTION_BYPASS == pxSp->oAction)
         || (IPSEC_ACTION_DROP == pxSp->oAction))
    {
        status = ERR_SPD_UNACCEPTABLE_TS;
        goto exit;
    }

exit:
    if (NULL != pxSp)
    {
        pxKey->spdIndex = pxSp->index;
        pxKey->dwSpdId = pxSp->dwId;
    }
    else
    {
        pxKey->spdIndex = 0;
        pxKey->dwSpdId = 0;
    }
    *ppxSp = pxSp;
    return status;
} /* GetKeySp */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyAddEx_vx(IPSECKEY_EX pxKey)
#else
extern sbyte4
IPSEC_keyAddEx(IPSECKEY_EX pxKey)
#endif
{
    MSTATUS status = OK;

    SPD pxSp = NULL;
    sbyte4 index = pxKey->spdIndex;
    ubyte4 dwSpdId = pxKey->dwSpdId;
    intBoolean bInbound = (IPSEC_SA_FLAG_INBOUND & pxKey->flags) ? TRUE : FALSE;
    intBoolean bInitiator = (IPSEC_SA_FLAG_INITIATOR & pxKey->flags) ? TRUE : FALSE;

    /* locate SPD entry, if applicable */
    if (0 != dwSpdId)
    {
        intBoolean bInSp = TRUE;

        if (NULL == (pxSp = IPSEC_indexSp(index, TRUE)))
        {
            if (NULL == (pxSp = IPSEC_indexSp(index, FALSE)))
            {
                pxKey->spdIndex = 0x80000000 | index;
                pxKey->dwSpdId = 0;
                status = ERR_SPD_BAD_INDEX;
                goto exit;
            }
            bInSp = FALSE;
        }

        /* check invalid SPD id */
        if (dwSpdId != pxSp->dwId)
        {
            if (bInSp) ++pxSp; else --pxSp;

            if (dwSpdId != pxSp->dwId)
            {
                pxKey->spdIndex = 0x80000000 | index;
                pxKey->dwSpdId = 0;
                status = ERR_SPD_BAD_ID;
                goto exit;
            }
            bInSp = bInSp ? FALSE : TRUE;
        }

        if (bInbound == bInSp)
        {
            /* Rare: nested bundle only, iNest > 0, non-mirrored policy */
            if (IPSEC_SA_FLAG_CONNECT2 & pxKey->flags) /* special case */
            {
                if (bInbound != bInitiator) /* _R - we must be initiator! */
                    goto check;
            }
            else
            {
                if (bInbound == bInitiator) /* _I */
                    goto check;
            }

            goto add;
        }

        if (IPSEC_SP_FLAG_MIRRORED & pxSp->flags) /* mirrored */
        {
            if (bInbound) (pxSp--); else (pxSp++);
            /*pxKey->dwSpdId =*/ /* do not update!!! */
            goto add;
        }

        pxSp = NULL; /* !!! */
    } /* if */

    /* check SPD to add selectively */
    if (OK > (status = GetKeySp(pxKey, &pxSp)))
    {
        pxKey->spdIndex |= 0x80000000;
        goto exit;
    }

    index = pxKey->spdIndex;

check:
    if (OK > (status = CheckKeySp(pxKey, pxSp)))
    {
        pxKey->spdIndex |= 0x80000000;
        goto exit;
    }

    if (pxKey->iNest >= pxSp->oSaLen) /* jic */
        goto exit;

add:
    /* add new SA */
    if (OK > (status = IPSEC_newSa(pxKey, NULL, pxSp)))
    {
        pxKey->spdIndex = 0x80000000 | index;
        pxKey->dwSpdId = 0;
        goto exit;
    }

exit:
    return (sbyte4)status;
} /* IPSEC_keyAddEx */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyReady_ex(IPSECKEY_EX pxKey)
#else
extern sbyte4
IPSEC_keyReady(IPSECKEY_EX pxKey)
#endif
{
    MSTATUS status = OK;

    SPD pxSp = NULL;
    ubyte4 dwSpdId = pxKey->dwSpdId;

    /* must be inbound! */
    if (!(IPSEC_SA_FLAG_INBOUND & pxKey->flags))
    {
        status = ERR_IPSEC_MISMATCH_DIR;
        goto exit;
    }

    /* locate SPD entry, if applicable */
    if (0 != dwSpdId)
    {
        sbyte4 index = pxKey->spdIndex;

        /* search SPD by index */
        if (NULL == (pxSp = IPSEC_indexSp(index, TRUE)))
        {
            status = ERR_SPD_BAD_INDEX;
            goto exit;
        }
        else
        {
            /* check SPD id */
            if (dwSpdId != pxSp->dwId)
            {
                status = ERR_SPD_BAD_ID;
                goto exit;
            }
        }
    }
    else
    {
        /* check SPD to add selectively */
        if (IPSEC_SA_FLAG_IKE2 & pxKey->flags) /* [v2] */
        {
            status = IPSEC_getSp2(pxKey);
            goto exit;
        }

        if (OK > (status = GetKeySp(pxKey, &pxSp)))
            goto exit;
    }

    if (OK > (status = CheckKeySp(pxKey, pxSp)))
        goto exit;

    /* adjust lifetime (based on SP) */
    if (pxSp->dwSaSecs &&
        (!pxKey->dwExpSecs || (pxKey->dwExpSecs > pxSp->dwSaSecs)))
        pxKey->dwExpSecs = pxSp->dwSaSecs;

    if (pxSp->dwSaBytes)
    {
        ubyte4 dwSaKBytes = (pxSp->dwSaBytes + 1023) / (ubyte4)1024;

        if (!pxKey->dwExpKBytes || (pxKey->dwExpKBytes > dwSaKBytes))
            pxKey->dwExpKBytes = dwSaKBytes;
    }

exit:
    return (sbyte4)status;
} /* IPSEC_keyReady */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyUpdate_ex(IPSECKEY pxKey)
#else
extern sbyte4
IPSEC_keyUpdate(IPSECKEY pxKey)
#endif
{
    MSTATUS status = STATUS_IPSEC_FINDSA_NULL;

    SADB pxSa = NULL;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte oMode = pxKey->oMode;
#endif
    ubyte4 dwIkeSaId = pxKey->dwIkeSaId;

    /* traverse SADB */
    while (NULL != (pxSa = IPSEC_enumSa(pxSa)))
    {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if ((0 == oMode) || (oMode == pxSa->oSaMode))
#endif
        if (dwIkeSaId == pxSa->dwIkeSaId)
        {
            /* found */
            SPD pxSp = pxSa->pxSp;
            if (NULL != pxSp) /* jic - skip manual key */
            {
                CAST_MOC_IPADDR dwDestAddr, dwSrcAddr;
                status = OK;

                if ((IPSEC_SA_FLAG_INBOUND & pxKey->flags) ==
                    (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags))
                {
                    dwDestAddr = pxKey->dwDestAddr;
                    dwSrcAddr  = pxKey->dwSrcAddr;
                }
                else
                {
                    dwDestAddr = pxKey->dwSrcAddr;
                    dwSrcAddr  = pxKey->dwDestAddr;
                }

                /* inform IKE to suspend event */
                if ((dwDestAddr ||
#ifdef __ENABLE_IPSEC_NAT_T__
                     (pxKey->wUdpEncPort != pxSa->wSaUdpEncPort) ||
#endif
                     dwSrcAddr) &&
                    !(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags)) /* outbound */
                {
                    IKE_keyAcqExp(pxSa, IKE_KEY_TYPE_SUSPEND);
                }

#ifdef __ENABLE_RB_SADB__
                /* remove from hashtables */
                IPSEC_delSaIndex(pxSa);
#endif
                if (dwDestAddr) /* update dest. addr. */
                {
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
                    {
                        SET_MOC_IPADDR6(pxSa->dwSaDestAddr, dwDestAddr);
                    }
                    else
#endif
                    {
                        SET_MOC_IPADDR4(pxSa->dwSaDestAddr, dwDestAddr);
                    }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                    if (IPSEC_MODE_TUNNEL == pxSa->oSaMode)
                    {
                        if (!ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP))
                            pxSp->dwTunlDestIP = pxSa->dwSaDestAddr;
                    }
                    else
#endif
                    {
                        MOC_IP_ADDRESS destIP = REF_MOC_IPADDR(pxSp->dwDestIP);
                        if (!SAME_MOC_IPADDR(destIP, pxSa->dwSaDestAddr) &&
                            SAME_MOC_IPADDR(destIP, pxSp->dwDestIPEnd))
                            pxSp->dwDestIPEnd =
                            pxSp->dwDestIP = pxSa->dwSaDestAddr;
                    }
                }

                if (dwSrcAddr) /* update source addr. */
                {
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
                    {
                        SET_MOC_IPADDR6(pxSa->dwSaSrcAddr, dwSrcAddr);
                    }
                    else
#endif
                    {
                        SET_MOC_IPADDR4(pxSa->dwSaSrcAddr, dwSrcAddr);
                    }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                    if (IPSEC_MODE_TUNNEL == pxSa->oSaMode)
                    {
                        if (!ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP))
                            pxSp->dwTunlSrcIP = pxSa->dwSaSrcAddr;
                    }
                    else
#endif
                    {
                        MOC_IP_ADDRESS srcIP = REF_MOC_IPADDR(pxSp->dwSrcIP);
                        if (!SAME_MOC_IPADDR(srcIP, pxSa->dwSaSrcAddr) &&
                            SAME_MOC_IPADDR(srcIP, pxSp->dwSrcIPEnd))
                            pxSp->dwSrcIPEnd =
                            pxSp->dwSrcIP = pxSa->dwSaSrcAddr;
                    }
                }

#ifdef __ENABLE_IPSEC_NAT_T__
                /* update UDP encap. port */
                pxSa->wSaUdpEncPort = pxKey->wUdpEncPort;

                if (IPSEC_SA_FLAG_NAT_PEER & pxKey->flags)
                    pxSa->saFlags |= IPSEC_SA_FLAG_NAT_PEER;
                else
                    pxSa->saFlags &= ~(IPSEC_SA_FLAG_NAT_PEER);
#endif
#ifdef __ENABLE_RB_SADB__
                /* add to hashtables */
                if (OK > (/*status = */IPSEC_addSaIndex(pxSa)))
                {
                    IPSEC_delSa(pxSa, TRUE);
                }
#endif
            }
        }
    } /* while */

    return (sbyte4)status;
} /* IPSEC_keyUpdate */

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyDelete_ex(IPSECKEY pxKey)
#else
extern sbyte4
IPSEC_keyDelete(IPSECKEY pxKey)
#endif
{
    /* Note: IPSEC_keyDelete() checks the following fields in 'pxKey':  */
    /*     oProtocol, dwSpi, dwDestAddr, dwSrcAddr                      */
    MSTATUS status = STATUS_IPSEC_FINDSA_NULL;

    SADB pxSa = NULL;
    ubyte oProtocol     = pxKey->oProtocol;     /* IPPROTO_AH, IPPROTO_ESP, or 0 (both) */
    ubyte4 dwSpi        = pxKey->dwSpi;         /* 0=wildcard */
    CAST_MOC_IPADDR dwDestAddr = pxKey->dwDestAddr;    /* 0=any */
    CAST_MOC_IPADDR dwSrcAddr  = pxKey->dwSrcAddr;     /* 0=any */
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort  = pxKey->wUdpEncPort;
#endif
#ifdef USE_MOC_COOKIE
    ubyte4 cookie       = pxKey->cookie;
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4 dwIkeSaId    = pxKey->dwIkeSaId;
#endif
    intBoolean bMirrored = (IPSEC_SA_FLAG_MIRRORED & pxKey->flags);
    intBoolean bOnce = (0 != dwDestAddr) && (0 != dwSpi) && (0 != oProtocol) && !bMirrored;

#ifndef __ENABLE_DIGICERT_IPV6__
    #define destAddr dwDestAddr
    #define srcAddr dwSrcAddr
#else
    MOC_IP_ADDRESS_S destAddr, srcAddr;

    if (dwDestAddr)
    {
        if (IPSEC_SA_FLAG_IP6 & pxKey->flags) {
            SET_MOC_IPADDR6(destAddr, dwDestAddr); }
        else {
            SET_MOC_IPADDR4(destAddr, dwDestAddr); }
    }

    if (dwSrcAddr)
    {
        if (IPSEC_SA_FLAG_IP6 & pxKey->flags) {
            SET_MOC_IPADDR6(srcAddr, dwSrcAddr); }
        else {
            SET_MOC_IPADDR4(srcAddr, dwSrcAddr); }
    }
#endif /* __ENABLE_DIGICERT_IPV6__ */

    /* traverse SADB */
    while (NULL != (pxSa = IPSEC_enumSa(pxSa)))
    {
        if (((0 == oProtocol) || (oProtocol == pxSa->oSaProto)) &&
            ((0 == dwSpi) || (dwSpi == pxSa->dwSaSpi)) &&
            ((0 == dwDestAddr) ||
             (SAME_MOC_IPADDR(REF_MOC_IPADDR(destAddr), pxSa->dwSaDestAddr) ||
              (bMirrored && SAME_MOC_IPADDR(REF_MOC_IPADDR(destAddr), pxSa->dwSaSrcAddr)))) &&
            ((0 == dwSrcAddr) ||
             (SAME_MOC_IPADDR(REF_MOC_IPADDR(srcAddr), pxSa->dwSaSrcAddr) ||
              (bMirrored && SAME_MOC_IPADDR(REF_MOC_IPADDR(srcAddr), pxSa->dwSaDestAddr)))))
#ifdef USE_MOC_COOKIE
        if  ((0 == cookie) || (cookie == pxSa->cookie))
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if  ((0 == dwIkeSaId) || (dwIkeSaId == pxSa->dwIkeSaId))
#endif
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            /* make sure peer NAT port is the same!!! */
            if (bOnce ||
                (wUdpEncPort == pxSa->wSaUdpEncPort) ||
                ((0 == wUdpEncPort) &&
                 (!(IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                  || (0 != dwIkeSaId)
#endif
                  )))
#endif
            status = IPSEC_delSa(pxSa, FALSE);
            if (bOnce) break;
        }
    } /* while */

#ifndef __ENABLE_DIGICERT_IPV6__
    #undef destAddr
    #undef srcAddr
#endif
    return (sbyte4)status;
} /* IPSEC_keyDelete */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyFlush_ex(void)
#else
extern sbyte4
IPSEC_keyFlush(void)
#endif
{
    MSTATUS status = OK;

    SADB pxSa = NULL;
    while (NULL != (pxSa = IPSEC_enumSa(pxSa)))
    {
        status = IPSEC_delSa(pxSa, TRUE);
    }

    return (sbyte4)status;
} /* IPSEC_keyFlush */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

