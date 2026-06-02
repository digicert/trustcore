/**
 * @file  sadb.c
 * @brief NanoSec IPsec Security Association Database (SADB) implementation.
 *
 * @details    This file contains the SADB management implementation for NanoSec IPsec.
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
#ifdef __IPSEC_SADB_MALLOC__
#include "../common/dynarray.h"
#endif
#ifdef __ENABLE_RB_SADB__
#include "../common/hash_table.h"
#include "../common/hash_value.h"
#endif
#ifdef __ENABLE_IPSEC_ESN__
#include "../common/int64.h"
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
#include "../ipsec/script.h"
/*#include "../ike/ike.h"*/
#include "../ike/ikekey.h"
#include "../common/debug_console.h"


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
intBoolean m_ipsecSadbForever = FALSE;
#endif

/*------------------------------------------------------------------*/

#ifndef LOG_SADB_DELETE
#define LOG_SADB_DELETE(_proto, _spi, _sa)
#endif


/*------------------------------------------------------------------*/

static sbyte4 m_ipsecSadbNum = 0;

#ifndef __IPSEC_SADB_MALLOC__

static struct sadb m_ipsecSadb[IPSEC_SADB_MAX] = { {0} };

#define NEXT_SA(_el, _i) _el = &(m_ipsecSadb[_i]);

#define GET_SA_LOC(_el, _loc, _st) \
    if ((m_ipsecSadb <= _el) && (&(m_ipsecSadb[IPSEC_SADB_MAX]) > _el) && \
        !(((usize)((ubyte*)_el - (ubyte*)m_ipsecSadb)) % sizeof(struct sadb))) \
    { \
        _loc = (sbyte4) \
            (((usize)((ubyte*)_el - (ubyte*)m_ipsecSadb)) / sizeof(struct sadb)); \
        _st = OK; \
    } \
    else _st = ERR_MEM_POOL;

#define NEW_SA(_el) \
    _el = &(m_ipsecSadb[m_ipsecSadbNum++]); \
    INIT_SA_LOCK(_el)

#else

static DynArray m_ipsecSadb = { 0 };

#define NEXT_SA(_el, _i) \
    if (OK > DYNARR_Get(&m_ipsecSadb, _i, &(_el))) break; \
    if (NULL == _el) continue;

#define GET_SA_LOC(_el, _loc, _st) \
    SADB _tmp = NULL; \
    if (OK <= (_st = DYNARR_Get(&m_ipsecSadb, (_el)->loc, &_tmp))) \
    { \
        if (_tmp != _el) _st = ERR_INDEX_OOB; \
        else _loc = (_el)->loc ; \
    }

#define NEW_SA(_el) \
    if (NULL != (_el = (SADB) MALLOC(sizeof(struct sadb)))) \
    { \
        if (OK > DYNARR_Append(&m_ipsecSadb, &(_el))) \
        { \
            FREE(_el); _el = NULL; \
        } \
        else \
        { \
            DIGI_MEMSET((ubyte *)_el, 0x00, sizeof(struct sadb)); \
            /*  DYNARR_GetElementCount(&m_ipsecSadb, &m_ipsecSadbNum);*/ \
            (_el)->loc = m_ipsecSadbNum++; \
            INIT_SA_LOCK(_el) \
        } \
    }

#endif /* __IPSEC_SADB_MALLOC__ */

#define ZEROIZE_SA(_el) \
    DOWN_SA_LOCK(_el) \
    DeleteCipherCtx(_el); \
    DIGI_MEMSET((ubyte*)_el, 0x00, OFFSETOF(struct sadb, loc)); \
    UP_SA_LOCK(_el)

static ubyte4 m_ipsecSadbId = 0;


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
MOC_EXTERN ubyte m_unicastRangeCount;
MOC_EXTERN MOC_IP_ADDRESS_S m_startUnicastIP[MAX_UNICAST_RANGE];
MOC_EXTERN MOC_IP_ADDRESS_S m_endUnicastIP[MAX_UNICAST_RANGE];
#endif

#if defined(__ENABLE_RB_SADB__)
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
extern MSTATUS matchFqdnIp(fqdnMappingConfig *fqdnMapping, fqdnMappingConfig *testFqdnMapping, intBoolean *isMatch);
#endif
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

static SADB m_freeQueueHead = NULL, m_freeQueueTail = NULL, m_freeQueueDeleted = NULL;; /* 'free' SA's */
DECL_RB_LOCK(m_mtxFree)

#define PUSH_SA(_el) \
    DOWN_RB_LOCK(m_mtxFree) \
    if (NULL == m_freeQueueTail) m_freeQueueHead = _el; \
    else m_freeQueueTail->pNext = _el; \
    (_el)->pNext = NULL; m_freeQueueTail = _el; \
    UP_RB_LOCK(m_mtxFree)

#define POP_SA(_el) \
    DOWN_RB_LOCK(m_mtxFree) \
    if ((NULL != (_el = m_freeQueueHead)) && \
        (NULL == (m_freeQueueHead = (_el)->pNext))) m_freeQueueTail = NULL; \
    UP_RB_LOCK(m_mtxFree)

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
static hashTableOfPtrs *m_hashTableInbnd = NULL; /* inbound auto. key only */
DECL_RB_LOCK(m_mtxInbnd)
#endif
static hashTableOfPtrs *m_hashTableInSpi = NULL;
DECL_RB_LOCK(m_mtxInSpi)

#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
static hashTableOfPtrs *m_hashTableOutbnd = NULL;
DECL_RB_LOCK(m_mtxOutbnd)
#else
RTOS_MUTEX m_mtxOutbnd = NULL;
hashTableOfPtrs *m_hashTableOutbnd = NULL;
#endif

#if defined(__ENABLE_RB_SADB__)
extern MSTATUS matchKeySa(SADB pxSa, outboundMappingConfig *testOutboundConfig, intBoolean *isMatch);
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
hashTableOfPtrs *m_hashTableFqdnMapping = NULL;
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
extern hashTableOfPtrs *m_hashTableFqdnNameMapping = NULL;
ubyte m_fqdnName[MAX_UNICAST_GROUP][MOC_MAX_FQDN_LEN] = {0};    /* This will maintain a list of configured fqdn names which can be used to
                                clear the hash memory allocated once all the sadb entried are freed*/
ubyte4 m_fqdnConfigured = 0;
#endif
/* DECL_RB_LOCK(m_mtxFqdnMapping) */
#endif

#if (defined(ENABLE_DIGICERT_GDOI_CLIENT) || defined(ENABLE_DIGICERT_GDOI_SERVER)) && defined(ENABLE_DIGICERT_MULTICAST_MCP)
#ifndef IPSEC_SA_INBND_HASH_TABLE_SIZE_MASK
#define IPSEC_SA_INBND_HASH_TABLE_SIZE_MASK   (2047) /* needs to be 2^n -1 */
#endif

#ifndef IPSEC_SA_INSPI_HASH_TABLE_SIZE_MASK
#define IPSEC_SA_INSPI_HASH_TABLE_SIZE_MASK   (2047)
#endif

#ifndef IPSEC_SA_OUTBND_HASH_TABLE_SIZE_MASK
#define IPSEC_SA_OUTBND_HASH_TABLE_SIZE_MASK  (2047)
#endif

#else

#ifndef IPSEC_SA_INBND_HASH_TABLE_SIZE_MASK
#define IPSEC_SA_INBND_HASH_TABLE_SIZE_MASK   (511) /* needs to be 2^n -1 */
#endif
#ifndef IPSEC_SA_INSPI_HASH_TABLE_SIZE_MASK
#define IPSEC_SA_INSPI_HASH_TABLE_SIZE_MASK   (511)
#endif
#ifndef IPSEC_SA_OUTBND_HASH_TABLE_SIZE_MASK
#define IPSEC_SA_OUTBND_HASH_TABLE_SIZE_MASK  (511)
#endif

#endif

#ifndef IPSEC_SA_FQDN_MAPPING_HASH_TABLE_SIZE_MASK
#ifdef ENABLE_DIGICERT_GDOI_SERVER
#define IPSEC_SA_FQDN_MAPPING_HASH_TABLE_SIZE_MASK  (0xffff)
#else
#define IPSEC_SA_FQDN_MAPPING_HASH_TABLE_SIZE_MASK  (0x3fff)
#endif
#endif


#define IPSEC_SAINBND_INIT_HASH_VALUE   (0xa0f2418e)
#define IPSEC_SAINSPI_INIT_HASH_VALUE   (0xf74a9031)
#define IPSEC_SAOUTBND_INIT_HASH_VALUE  (0x0641517c)

#define GEN_INSPI_HASH_VALUE(_spi, _hv) \
    HASH_VALUE_hashGen(&(_spi), sizeof(_spi), \
                       IPSEC_SAINSPI_INIT_HASH_VALUE, &(_hv));

#ifdef __ENABLE_DIGICERT_IPV6__
#define GEN_INBND_HASH_VALUE(_saddr, _hv) \
    if (AF_INET6 == (_saddr).family) \
        HASH_VALUE_hashGen((const void *)RET_MOC_IPADDR6(_saddr), 16, \
                           IPSEC_SAINBND_INIT_HASH_VALUE, &(_hv)); \
    else \
        HASH_VALUE_hashGen((const void *)&(RET_MOC_IPADDR4(_saddr)), 4, \
                            IPSEC_SAINBND_INIT_HASH_VALUE, &(_hv)); \

#define GEN_OUTBND_HASH_VALUE(_daddr, _hv) \
    if (AF_INET6 == (_daddr).family) \
        HASH_VALUE_hashGen((const void *)RET_MOC_IPADDR6(_daddr), 16, \
                           IPSEC_SAOUTBND_INIT_HASH_VALUE, &(_hv)); \
    else \
        HASH_VALUE_hashGen((const void *)&(RET_MOC_IPADDR4(_daddr)), 4, \
                           IPSEC_SAOUTBND_INIT_HASH_VALUE, &(_hv));

#else
#define GEN_INBND_HASH_VALUE(_saddr, _hv) \
    HASH_VALUE_hashGen(&(_saddr), sizeof(_saddr), \
                       IPSEC_SAINBND_INIT_HASH_VALUE, &(_hv));

#define GEN_OUTBND_HASH_VALUE(_daddr, _hv) \
    HASH_VALUE_hashGen(&(_daddr), sizeof(_daddr), \
                       IPSEC_SAOUTBND_INIT_HASH_VALUE, &(_hv));
#endif

typedef struct sadb_test
{
    MOC_IP_ADDRESS  dwDestAddr;
    MOC_IP_ADDRESS  dwSrcAddr;
    ubyte4          dwSaSpi ;
    ubyte           oProto ;
    MOC_IP_ADDRESS  dwSrcIpInList;
    /* Note: don't change the order of the above members */

#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2          wUdpEncPort;
    intBoolean      bPeerNat;
#endif
    SPD             pxSp;
    sbyte4          iNest;

    ubyte           oUlp;
    ubyte2          wSrcPort;
    ubyte2          wDestPort;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte2          oMode;
#endif
    ubyte4          timenow;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_IP_ADDRESS  dwDestIP, dwDestIPEnd;
    MOC_IP_ADDRESS  dwSrcIP, dwSrcIPEnd;
#endif
    SADB            pxSaOld;
    intBoolean      bMature;
    ubyte4          dwTimeStart;
#endif
#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_IPSEC_NAT_T__)
    sbyte4          oSaLen ;
#endif
    MOC_IP_ADDRESS  saDestAddr;
    MOC_IP_ADDRESS  saSrcAddr;

    SADB            pxSaRet;
    ubyte4          timethenRet;
#ifdef USE_MOC_COOKIE
    void           *cookie;
#endif
#ifdef CUSTOM_IPSEC_FILTER_DSCP
    ubyte           oDscp;
#endif

} *SADB_TEST;


/*------------------------------------------------------------------*/

static MSTATUS
HT_alloc(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement)
{
    /* we could use a memory pool here to reduce probability of fragmentation */
    MSTATUS status = OK;

    MOC_UNUSED(pHashCookie);

    if (NULL == (*ppRetNewHashElement = MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
} /* HT_alloc */


/*------------------------------------------------------------------*/

static MSTATUS
HT_free(void *pHashCookie, hashTablePtrElement *pFreeHashElement)
{
    MOC_UNUSED(pHashCookie);

    FREE(pFreeHashElement);

    return OK;
} /* HT_free */


/*------------------------------------------------------------------*/

static MSTATUS
HT_check(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    *pRetIsMatch = ((pAppData == pTestData) ? TRUE : FALSE);
    return OK;
} /* HT_check */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_addSaIndex(SADB pxSa)
{
    MSTATUS status;

    ubyte4 hashValue = 0, hashValueTmp = 0;
    SADB pxSaTmp;
    intBoolean isFound;

    if (NULL == pxSa)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) /* inbound auto. key */
    {
        /* Note: IPSEC_SA_FLAG_INBOUND is never set for manual key */
        GEN_INSPI_HASH_VALUE(pxSa->dwSaSpi, hashValue)
        RB_SYNC(m_mtxInSpi,
        status = HASH_TABLE_addPtr(m_hashTableInSpi, hashValue, pxSa) )
        if (OK > status) goto exit;

        hashValueTmp = hashValue;
        GEN_INBND_HASH_VALUE(pxSa->dwSaSrcAddr, hashValue)
        RB_SYNC(m_mtxInbnd,
        status = HASH_TABLE_addPtr(m_hashTableInbnd, hashValue, pxSa) )
        if (OK > status)
        {
            RB_SYNC(m_mtxInSpi,
            HASH_TABLE_deletePtr(m_hashTableInSpi, hashValueTmp, pxSa,
                                 HT_check, (void **)&pxSaTmp, &isFound) )
            goto exit;
        }
    }
    else /* outbound */
#endif
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (pxSa->fqdn[0])
        {
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
            GEN_OUTBND_HASH_VALUE(pxSa->fqdnUniqueKey, hashValue)
#else
            if(pxSa->inbound == 0)
               GEN_OUTBND_HASH_VALUE(pxSa->dwSaDestIPList[0], hashValue)
            else
               GEN_OUTBND_HASH_VALUE(pxSa->dwSaSrcIPList[0], hashValue)
#endif
        }
        else if (pxSa->dwSaDestIP)
#else
        if (pxSa->dwSaDestIP)
#endif
        {
            GEN_OUTBND_HASH_VALUE(pxSa->dwSaDestIP, hashValue)
        }
        else
        {
            GEN_OUTBND_HASH_VALUE(pxSa->dwSaDestAddr, hashValue)
        }

        RB_SYNC(m_mtxOutbnd,
        status = HASH_TABLE_addPtr(m_hashTableOutbnd, hashValue, pxSa))
        if (OK > status) goto exit;

#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL == pxSa->pxSp) /* manual key */
#endif
        {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            if (!pxSa->fqdn[0] || (pxSa->fqdn[0] && pxSa->inbound == 1))
#endif
            {
                /* also add to inbound hashtable */
                hashValueTmp = hashValue;
                GEN_INSPI_HASH_VALUE(pxSa->dwSaSpi, hashValue)
                RB_SYNC(m_mtxInSpi,
                    status = HASH_TABLE_addPtr(m_hashTableInSpi, hashValue, pxSa))
                if (OK > status)
                {
                    RB_SYNC(m_mtxOutbnd,
                        HASH_TABLE_deletePtr(m_hashTableOutbnd, hashValueTmp, pxSa,
                            HT_check, (void **)&pxSaTmp, &isFound))
                        goto exit;
                }
            }
        }
#endif
    }

exit:
    return status;
} /* IPSEC_addSaIndex */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_delSaIndex(SADB pxSa)
{
    MSTATUS status = OK;

    ubyte4 hashValue;
    SADB pxSaTmp;
    intBoolean isFound;

    if (NULL == pxSa)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) /* inbound auto. key */
    {
        /* Note: IPSEC_SA_FLAG_INBOUND is never set for manual key */
        GEN_INSPI_HASH_VALUE(pxSa->dwSaSpi, hashValue)
        RB_SYNC(m_mtxInSpi,
        HASH_TABLE_deletePtr(m_hashTableInSpi, hashValue, pxSa,
                             HT_check, (void **)&pxSaTmp, &isFound) )

        GEN_INBND_HASH_VALUE(pxSa->dwSaSrcAddr, hashValue)
        RB_SYNC(m_mtxInbnd,
        HASH_TABLE_deletePtr(m_hashTableInbnd, hashValue, pxSa,
                             HT_check, (void **)&pxSaTmp, &isFound) )
    }
    else  /* outbound */
#endif
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        /* Get the Outbound table key for the corresponding group */
        if (pxSa->fqdn[0])
        {
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
            /*ubyte4 fqdnhashValue = 0;
            fqdnNameMappingConfig *fqdnFoundKey = NULL, *fqdnKey = NULL;
            DIGI_MALLOC((void **)&fqdnKey, sizeof(fqdnNameMappingConfig));
            DIGI_MEMSET((ubyte *)fqdnKey, '\0', sizeof(fqdnNameMappingConfig));

            DIGI_MEMCPY(fqdnKey->fqdnName, pxSa->fqdn, DIGI_STRLEN((sbyte *)pxSa->fqdn));
            fqdnKey->fqdnUniqueKey = pxSa->fqdnUniqueKey;

            GEN_FQDNNAME_MAPPING_HASH_VALUE(pxSa->fqdn,
                DIGI_STRLEN((sbyte *)pxSa->fqdn), fqdnhashValue)

            HASH_TABLE_deletePtr(m_hashTableFqdnNameMapping, fqdnhashValue, fqdnKey,
                    HT_check, (void **)&fqdnFoundKey, &isFound);*/

            GEN_OUTBND_HASH_VALUE(pxSa->fqdnUniqueKey, hashValue)
#else
            if(pxSa->inbound == 0)
               GEN_OUTBND_HASH_VALUE(pxSa->dwSaDestIPList[0], hashValue)
            else
               GEN_OUTBND_HASH_VALUE(pxSa->dwSaSrcIPList[0], hashValue)
#endif
        }
        else if (pxSa->dwSaDestIP)
#else
        if (pxSa->dwSaDestIP)
#endif
        {
            GEN_OUTBND_HASH_VALUE(pxSa->dwSaDestIP, hashValue)
        }
        else
        {
            GEN_OUTBND_HASH_VALUE(pxSa->dwSaDestAddr, hashValue)
        }

        RB_SYNC(m_mtxOutbnd,
        HASH_TABLE_deletePtr(m_hashTableOutbnd, hashValue, pxSa,
                             HT_check, (void **)&pxSaTmp, &isFound) )

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL == pxSa->pxSp) /* manual key */
#endif
        {
            /* also remove from inbound hashtable */
            GEN_INSPI_HASH_VALUE(pxSa->dwSaSpi, hashValue)
            RB_SYNC(m_mtxInSpi,
            HASH_TABLE_deletePtr(m_hashTableInSpi, hashValue, pxSa,
                                 HT_check, (void **)&pxSaTmp, &isFound) )
        }
    }

exit:
    return status;
} /* IPSEC_delSaIndex */

#endif /* __ENABLE_RB_SADB__ */


/*------------------------------------------------------------------*/

static MSTATUS
DeleteCipherCtx(SADB pxSa)
{
    MSTATUS status = OK;

    BulkCtx pCipherCtx;
    SADB_cipherSuiteInfo* pCipherSuite;

    if (NULL == pxSa)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pCipherCtx = pxSa->pCipherCtx))
    {
        goto exit;
    }

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    if (0 < pxSa->users)
    {
        status = -1; /* FOR NOW */
        goto exit;
    }
#endif

    if (NULL == (pCipherSuite = pxSa->pCipherSuite))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    else
    {
#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
        hwAccelDescr hwAccelCtx;
        if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx,
                                                   IPSEC_SA_FLAG_INBOUND & pxSa->saFlags)))
        {
            goto exit;
        }
        else
#endif
        {
            AeadAlgo *pAeadAlgo = pCipherSuite->pAeadAlgo;
            if (pAeadAlgo)
            {
                pAeadAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &pCipherCtx);
                if (pxSa->pCipherCtxM)
                {
                    pAeadAlgo->deleteFunc(MOC_SYM(hwAccelCtx)
                                          &pxSa->pCipherCtxM);
                }
            }
            else
            {
                pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx)
                                                  &pCipherCtx);
                if (pxSa->pCipherCtxM)
                {
                    pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx)
                                                      &pxSa->pCipherCtxM);
                }
            }
#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
            IPSEC_releaseHwAccelChannel(&hwAccelCtx);
#endif
            pxSa->pCipherCtx = NULL;
            pxSa->pCipherCtxM = NULL;
        }
    }

exit:
    return status;
} /* DeleteCipherCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_initSadb(void)
{
    MSTATUS status = OK;

    IPSEC_flushSadb();

#if defined(__ENABLE_RB_SADB__)
    INIT_RB_LOCK(m_mtxFree)

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    INIT_RB_LOCK(m_mtxInbnd)
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableInbnd,
                                    IPSEC_SA_INBND_HASH_TABLE_SIZE_MASK, NULL,
                                    HT_alloc, HT_free)))
    {
        goto exit;
    }
#endif
    INIT_RB_LOCK(m_mtxInSpi)
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableInSpi,
                                    IPSEC_SA_INSPI_HASH_TABLE_SIZE_MASK, NULL,
                                    HT_alloc, HT_free)))
    {
        goto exit;
    }

    INIT_RB_LOCK(m_mtxOutbnd)
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableOutbnd,
                                    IPSEC_SA_OUTBND_HASH_TABLE_SIZE_MASK, NULL,
                                    HT_alloc, HT_free)))
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
    /* INIT_RB_LOCK(m_mtxFqdnMapping) */
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableFqdnMapping,
                                    IPSEC_SA_FQDN_MAPPING_HASH_TABLE_SIZE_MASK, NULL,
                                    HT_alloc, HT_free)))
    {
        goto exit;
    }
#else
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableFqdnNameMapping,
                                    IPSEC_SA_FQDN_MAPPING_HASH_TABLE_SIZE_MASK, NULL,
                                    HT_alloc, HT_free)))
    {
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_GDOI_SERVER__ */
#endif /* __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__ */
#endif /*__ENABLE_RB_SADB__ */

#ifdef __IPSEC_SADB_MALLOC__
    status = DYNARR_Init(sizeof(struct sadb *), &m_ipsecSadb);
#endif

#ifdef __ENABLE_RB_SADB__
exit:
#endif
    return status;
} /* IPSEC_initSadb */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_flushSadb(void)
{
    MSTATUS status = OK;

    sbyte4 i;
    SADB pxSa;

#ifdef __ENABLE_RB_SADB__
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    intBoolean isFound = 0;
        /* CLear the SADB entried HASH as after flushing no key negotiation is supported*/
    for( i = 0; i < m_fqdnConfigured ; i++)
    {
        ubyte4 fqdnhashValue = 0;
        fqdnNameMappingConfig *fqdnFoundKey = NULL;
        fqdnNameMappingConfig fqdnKey ;

        DIGI_MEMSET((ubyte *)&fqdnKey, '\0', sizeof(fqdnNameMappingConfig));

        DIGI_MEMCPY(fqdnKey.fqdnName, m_fqdnName[i], DIGI_STRLEN((sbyte *)m_fqdnName[i]));

        GEN_FQDNNAME_MAPPING_HASH_VALUE(m_fqdnName[i],
            DIGI_STRLEN((sbyte *)m_fqdnName[i]), fqdnhashValue)

        HASH_TABLE_deletePtr(m_hashTableFqdnNameMapping, fqdnhashValue, &fqdnKey,
                NULL, (void **)&fqdnFoundKey, &isFound);

        if (isFound && fqdnFoundKey != NULL)
        {
            FREE(fqdnFoundKey);
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (m_hashTableInbnd)
    {
        HASH_TABLE_removePtrsTable(m_hashTableInbnd, NULL);
        m_hashTableInbnd = NULL;
    }
    FREE_RB_LOCK(m_mtxInbnd)
#endif
    if (m_hashTableInSpi)
    {
        HASH_TABLE_removePtrsTable(m_hashTableInSpi, NULL);
        m_hashTableInSpi = NULL;
    }
    FREE_RB_LOCK(m_mtxInSpi)

    if (m_hashTableOutbnd)
    {
        HASH_TABLE_removePtrsTable(m_hashTableOutbnd, NULL);
        m_hashTableOutbnd = NULL;
    }
    FREE_RB_LOCK(m_mtxOutbnd)

    #ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
    if (m_hashTableFqdnMapping)
    {
        HASH_TABLE_removePtrsTable(m_hashTableFqdnMapping, NULL);
        m_hashTableFqdnMapping = NULL;
    }
#else
    if (m_hashTableFqdnNameMapping)
    {
        HASH_TABLE_removePtrsTable(m_hashTableFqdnNameMapping, NULL);
        m_hashTableFqdnNameMapping= NULL;
    }
#endif /* __ENABLE_DIGICERT_GDOI_SERVER__ */
#endif /* __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__ */
#endif /* __ENABLE_RB_SADB__ */

    for (i=0; i < m_ipsecSadbNum; i++)
    {
        NEXT_SA(pxSa, i)

        if ((IPSEC_SA_FLAG_INUSE & pxSa->saFlags) &&
            !(IPSEC_SA_FLAG_DELETED & pxSa->saFlags))
        {
            IPSEC_delSa(pxSa, TRUE); /* delete */
        }
    }

    for (i=0; i < m_ipsecSadbNum; i++)
    {
        NEXT_SA(pxSa, i)
        ZEROIZE_SA(pxSa) /* clean up */
#ifdef __IPSEC_SADB_MALLOC__
        FREE(pxSa);
#endif
    }

#ifdef __ENABLE_RB_SADB__
    m_freeQueueHead = m_freeQueueTail = NULL;
    FREE_RB_LOCK(m_mtxFree)
#endif
#ifdef __IPSEC_SADB_MALLOC__
    DYNARR_Uninit(&m_ipsecSadb);
#endif

    m_ipsecSadbNum = 0;

    return status;
} /* IPSEC_flushSadb */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || \
    defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)

extern intBoolean
IPSEC_expireSa(ubyte4 timenow, SADB pxSa)
{
    intBoolean status = TRUE;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4 dwSeqNbr = 0;
#ifdef __ENABLE_IPSEC_ESN__
    ubyte8 seq;
#endif
#endif
    ubyte4 timeout = 0, timedlt = 0;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    SPD pxSp = pxSa->pxSp;
    if (NULL == pxSp) /* check if auto. keyed !!! */
#endif
    {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        if (pxSa->dwSaExpSecs || pxSa->dwSaExpKBytes) goto check;
#endif
        status = FALSE; /* manual key does not expire */
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /* check valid policy */
    if (pxSa->dwSpdId != pxSp->dwId)
        goto exit;

    /* check sequence number overflow for anti-replay */
    if (!(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags))
    {
        /* Note: anti-replay may be selected only if data origin is specified
           and the authentication service also is enabled, where the latter
           will be checked during runtime */
#ifdef __ENABLE_IPSEC_ESN__
        seq = ATOMIC_GET(pxSa->u.o.seq);
        dwSeqNbr = LOW_U8(seq);
        if (!(IPSEC_SA_FLAG_ESN & pxSa->saFlags) || (0xFFFFFFFF == HI_U8(seq)))
#else
        dwSeqNbr = ATOMIC_GET(pxSa->u.o.seq);
#endif
        if (0 == (dwSeqNbr + 1))
            goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
check:
#endif
    /* check lifetime secs */
    if (pxSa->dwSaExpSecs)
    {
        timeout = 1000 * pxSa->dwSaExpSecs;
        timedlt = timenow - pxSa->dwSaEstablished;
        if (timeout < timedlt)
        {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (NULL == pxSp)
#endif
            /* save GDOI key expiration time to provide grace period for
               smoother key rotation */
            if (0 == pxSa->dwSaLastRekey) /* jic */
                pxSa->dwSaLastRekey = pxSa->dwSaEstablished + timeout;
#endif
            goto exit;
        }
    }

    /* check lifetime kbytes */
    if (pxSa->dwSaExpKBytes && (pxSa->dwSaExpKBytes <= pxSa->dwSaCurKBytes))
    {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL == pxSp)
#endif
        if (0 == pxSa->dwSaLastRekey) /* jic */
            pxSa->dwSaLastRekey = timenow;
#endif
        goto exit;
    }

    status = FALSE;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    if (NULL == pxSp) goto exit;
#endif

    /* auto. rekeying */
    /*  We need to rekey even when we are a responder if we are IKEV2. Otherwise
     * we delete the SA and the traffic will be blocked till the IPSec SAs are created
     * again. So relax the check if V2.
     */
    if (
        !(IPSEC_SP_FLAG_INBOUND & pxSp->flags) && /* outbound */
        ((IPSEC_SA_FLAG_IKE2 & pxSa->saFlags) ||
        (IPSEC_SA_FLAG_INITIATOR & pxSa->saFlags))) /* initiator */
    {
        /* FOR NOW */
        ubyte4 timeoutIdle = 600000/* 1000*60*10 */;    /* idle < 10 minutes */
        ubyte4 timeoutEvent = 60000/* 1000*60 */;       /* rekeyed > 60 seconds */

        if ((pxSa->dwSaLastUsed && ((timenow - pxSa->dwSaLastUsed) < timeoutIdle)) && /* !idle */
            (!pxSa->dwSaLastRekey || ((timenow - pxSa->dwSaLastRekey) > timeoutEvent))) /* !rekeyed */
        {
            ubyte4 warning;

            if (pxSa->dwSaExpSecs)
            {
                warning = 30000/* 1000*15*2 */; /* 15 seconds x 2 - FOR NOW */
                if ((timedlt > (ubyte4)(timeout/2)) && /* old enough */
                    (timeout < (timedlt + warning))) /* expiring soon */
                {
                    goto rekey;
                }
            }

            if (pxSa->dwSaExpKBytes)
            {
                warning = 6; /* 6K - FOR NOW */
                if ((pxSa->dwSaCurKBytes > (ubyte4)(pxSa->dwSaExpKBytes/2)) && /* old enough */
                    ((pxSa->dwSaExpKBytes < (pxSa->dwSaCurKBytes + warning)) || /* expiring soon */
                     (pxSa->dwSaCurKBytes > (pxSa->dwSaCurKBytes + warning)))) /* jic KBytes wraps back to 0 */
                {
                    goto rekey;
                }

                /* check mirrored inbound SA */
                else
                {
                    SADB pxSaM = pxSa->pxSaM;
                    if (pxSaM && (pxSaM->dwId == pxSa->dwIdM) &&
                        pxSaM->dwSaExpKBytes && /* jic */
                        (pxSaM->dwSaCurKBytes > (ubyte4)(pxSaM->dwSaExpKBytes/2)) &&
                        ((pxSaM->dwSaExpKBytes < (pxSaM->dwSaCurKBytes + warning)) ||
                         (pxSaM->dwSaCurKBytes > (pxSaM->dwSaCurKBytes + warning))))
                    {
                        goto rekey;
                    }
                }
            }

#ifdef __ENABLE_IPSEC_ESN__
            if (!(IPSEC_SA_FLAG_ESN & pxSa->saFlags) || (0xFFFFFFFF == HI_U8(seq)))
#endif
            {
                warning = 64; /* 64 packets - FOR NOW */
                if ((dwSeqNbr + warning) < dwSeqNbr)
                {
                    goto rekey;
                }
            }

            goto exit;
rekey:
            if (OK <= IKE_keyAcqExp(pxSa, IKE_KEY_TYPE_ACQUIRE))
            {
                pxSa->dwSaLastRekey = timenow;
            }
        }
    } /* end of auto. rekeying */
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

exit:
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    if (pxSa->avoidExpire)
    {
        status = FALSE;
    }
#endif

    if (status) IPSEC_delSa(pxSa, FALSE);

    return status;
} /* IPSEC_expireSa */

#else
extern intBoolean
IPSEC_expireSa(ubyte4 timenow, SADB pxSa)
{
    MOC_UNUSED(timenow);
    MOC_UNUSED(pxSa);
    return FALSE;
}
#endif


/*------------------------------------------------------------------*/

extern SADB
IPSEC_enumSa(SADB pxSa)
{
    sbyte4 i=0;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    if (pxSa)
    {
        MSTATUS status;

        GET_SA_LOC(pxSa, i, status)
        pxSa = NULL;

        if ((OK > status) || (0 > i))
        {
            goto exit;
        }
        i++;
    }

    for (; i < m_ipsecSadbNum; i++, pxSa = NULL)
    {
        NEXT_SA(pxSa, i)

        if ((IPSEC_SA_FLAG_INUSE & pxSa->saFlags) &&
            !(IPSEC_SA_FLAG_DELETED & pxSa->saFlags) &&
            !IPSEC_expireSa(timenow, pxSa))
        {
            goto exit;
        }
    }

exit:
    return pxSa;
} /* IPSEC_enumSa */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_RB_SADB__

static MSTATUS
matchSpi(SADB pxSa, SADB_TEST testSa, intBoolean *isMatch)
{
    MSTATUS status = OK;

    *isMatch = FALSE;

    if (!pxSa || /* jic */
        (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) ||
        IPSEC_expireSa(testSa->timenow, pxSa))
    {
        goto exit;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if ((testSa->wUdpEncPort != pxSa->wSaUdpEncPort) &&
        (testSa->bPeerNat || (IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)))
    {
        goto exit;
    }
#endif

    /* check existing SPI */
    while ((testSa->dwSaSpi == pxSa->dwSaSpi) &&
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    ((!pxSa->fqdn[0]&&(((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
        REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
        testSa->dwDestAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
            || SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr)))) ||
            (pxSa->fqdn[0] && (pxSa->dwSaDestIPCount && (!checkIpinList(testSa->dwDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount))))) &&
#else
        SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr) &&
#endif
           ((testSa->oProto == pxSa->oSaProto) ||
            (0 == pxSa->oSaProto) || (0 == testSa->oProto)))
    {
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if ((NULL == testSa->pxSp) && (NULL == pxSa->pxSp))
#endif
        {
/*            DB_PRINT("\n matchspi test params testSa->dwDestAddr=%x testSa->dwSrcAddr=%x testSa->dwSrcIpInList=%x pxSa->dwSaSrcIPList[0]=%x, pxSa->dwSaDestIPList[0]=%x",
                testSa->dwDestAddr, testSa->dwSrcAddr, testSa->dwSrcIpInList, pxSa->dwSaSrcIPList[0], pxSa->dwSaDestIPList[0]);*/
            if (!ISZERO_MOC_IPADDR(DEREF_MOC_IPADDR(testSa->dwSrcAddr)) ||
                  !ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr) ||
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                  ((!pxSa->fqdn[0] &&(((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                      REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* as in case of unicats src and dest will be part of same unicast range*/
                      testSa->dwDestAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP == pxSa->dwSaDestIPEnd)) &&
                      (!SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr))))) ||
                          (pxSa->fqdn[0] && pxSa->dwSaSrcIPCount && (checkIpinList(testSa->dwSrcIpInList, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)))))
#else
                !SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr))
#endif
            {
                /* different source IP address */
                break;
            }
        }
        status = STATUS_IPSEC_KEYADD_EXSTING;
        goto exit;
    }

exit:
    return status;
} /* matchSpi */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
static MSTATUS
matchSa(SADB pxSa, SADB_TEST testSa, intBoolean *isMatch)
{
     *isMatch = FALSE;

    if (!pxSa || /* jic */
        (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) ||
        IPSEC_expireSa(testSa->timenow, pxSa))
    {
        goto exit;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if ((testSa->wUdpEncPort != pxSa->wSaUdpEncPort) &&
        (testSa->bPeerNat || (IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)))
    {
        goto exit;
    }
#endif

    /*  find existing SA */
    if ((NULL != testSa->pxSp) &&  /* auto. key */
        (testSa->pxSp == pxSa->pxSp) &&
        (testSa->iNest == pxSa->iNest) &&
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        ((((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
            REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
            testSa->dwDestAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
                || SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr))) ||
                (pxSa->fqdn[0] && (pxSa->dwSaDestIPCount && (!checkIpinList(testSa->dwDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount))))) &&
#else
        SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr) &&
#endif
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        (((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
            REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* as in case of unicats src and dest will be part of same unicast range*/
            testSa->dwSrcAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) ||
            ((pxSa->fqdn == 0) && SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr))) ||
                (pxSa->fqdn[0] && pxSa->dwSaSrcIPCount && (!checkIpinList(testSa->dwSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)))) &&
#else
        SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr) &&
#endif
#ifdef USE_MOC_COOKIE
        ((testSa->cookie == pxSa->cookie) || (0 == testSa->cookie)) &&
#endif
        ((pxSa->wSaDestPort == testSa->wDestPort) || (0 == testSa->wDestPort)) &&
        ((pxSa->wSaSrcPort == testSa->wSrcPort) || (0 == testSa->wSrcPort)) &&
        ((pxSa->oSaUlp == testSa->oUlp) || (0 == testSa->oUlp)))
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (((pxSa->oSaMode == testSa->oMode) || (IPSEC_MODE_DONTCARE == testSa->oMode)) &&
        ((IPSEC_MODE_TRANSPORT == pxSa->oSaMode) ||
         (!CheckIpRange(testSa->dwDestIP, testSa->dwDestIPEnd,
                        REF_MOC_IPADDR(pxSa->dwSaDestIP),
                        REF_MOC_IPADDR(pxSa->dwSaDestIPEnd)) &&
          !CheckIpRange(testSa->dwSrcIP, testSa->dwSrcIPEnd,
                        REF_MOC_IPADDR(pxSa->dwSaSrcIP),
                        REF_MOC_IPADDR(pxSa->dwSaSrcIPEnd)))))
#endif
    {
        intBoolean bMature = (IPSEC_SA_FLAG_MATURE & pxSa->saFlags);

        if (/*(testSa->bMature || !bMature) &&*/
            (!testSa->bMature || bMature || /* should avoid race condition btw peers */
             ((/*testSa->timenow - */testSa->dwTimeStart) <
              (testSa->timenow - pxSa->dwSaEstablished))))
        {
            /* match */
            pxSa->pNext = testSa->pxSaOld;
            testSa->pxSaOld = pxSa;
        }
    }

exit:
    return OK;
} /* matchSa */
#endif


/*------------------------------------------------------------------*/

static MSTATUS
matchOutbndSa(SADB pxSa, SADB_TEST testSa, intBoolean *isMatch)
{
    MSTATUS status = OK;

    *isMatch = FALSE;

    /* check existing SPI */
    if (OK > (status = matchSpi(pxSa, testSa, isMatch)))
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /* find existing SA */
    status = matchSa(pxSa, testSa, isMatch);
#endif

exit:
    return status;
} /* matchOutbndSa */

#endif /* __ENABLE_RB_SADB__ */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_RB_SADB__) || defined(__DISABLE_EXTENDED_SPD_LOOKUP__)
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
extern ubyte4
IPSEC_mapIpToKey(MOC_IP_ADDRESS_S destAddr)
{
    MSTATUS status = OK;
    ubyte4 fqdnHashValue = 0;
    intBoolean isEntryFound = FALSE;
    MOC_IP_ADDRESS_S temp_addr;
    fqdnMappingConfig *fqdnMapping = NULL, *fqdnFoundMapping = NULL;

   /* fqdnFoundKey = DIGI_MALLOC(sizeof(MOC_IP_ADDRESS_S));*/

    /* Check if the Destination address lies in the FQDN group */
    GEN_FQDNMAPPING_HASH_VALUE(destAddr, fqdnHashValue)

    DIGI_MALLOC((void **)&fqdnMapping, sizeof(fqdnMappingConfig));
    COPY_MOC_IPADDR(fqdnMapping->fqdnIp, destAddr);
    status = HASH_TABLE_findPtr(m_hashTableFqdnMapping, fqdnHashValue, fqdnMapping,
                (funcPtrExtraMatchTest)matchFqdnIp, (void **)&fqdnFoundMapping, &isEntryFound);
    DIGI_FREE((void **)&fqdnMapping);
    if (isEntryFound)
    {
        temp_addr = (MOC_IP_ADDRESS_S)(fqdnFoundMapping->fqdnUniqueKey);
/*        DIGI_FREE(fqdnFoundKey);*/
        return temp_addr;
    }

    /* Check if the destination address match with the boundary values of
     * Unicast Range configured */
    ubyte rangeIndex = 0;
    while (rangeIndex < m_unicastRangeCount)
    {
        if (destAddr == m_startUnicastIP[rangeIndex])
        {
            /* Destination address match with this Unicast range */
            isEntryFound = TRUE;
            return m_startUnicastIP[rangeIndex];
        }
        rangeIndex++;
    }

    /* If the entry is not found in FQDN group and the boundary values of Unicast range,
       check if the entry lies within the Unicast Range */
    rangeIndex = 0;
    while (rangeIndex < m_unicastRangeCount)
    {
        if (!CheckIpRange( m_startUnicastIP[rangeIndex],
            m_endUnicastIP[rangeIndex], destAddr, 0))
        {
            /* Destination address lie in this Unicast Range */
            isEntryFound = TRUE;
            return m_startUnicastIP[rangeIndex];
        }
        rangeIndex++;
    }
    return destAddr;
}
#endif
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_newSa(IPSECKEY_EX pxKey, SADB *ppxSa
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
          , SPD pxSp
#endif
            )
{
    MSTATUS status = OK;

    SADB pxSa = NULL, pxSaTmp;

    SADB_hmacSuiteInfo* pHmacSuite = NULL;
    SADB_cipherSuiteInfo* pCipherSuite = NULL;
    ubyte2 wEncrKeyLen;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    ubyte4  flags       = pxKey->flags;
    ubyte   oSaProto    = pxKey->oProtocol;
    ubyte4  dwSpi       = pxKey->dwSpi;
    MOC_IP_ADDRESS dwDestAddr = pxKey->dwDestAddr;
    MOC_IP_ADDRESS dwSrcAddr  = pxKey->dwSrcAddr;

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    ubyte  fqdn[MOC_MAX_FQDN_LEN];
    ubyte4 dwSaSrcIPCount = 0, dwSaDestIPCount=0 ;
    sbyte4 result = 0;
#endif
    ubyte   oSaUlp      = pxKey->oUlp;
    ubyte2  wSaSrcPort  = pxKey->wSrcPort;
    ubyte2  wSaDestPort = pxKey->wDestPort;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4 cookie       = pxKey->cookie;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort  = pxKey->wUdpEncPort;
    intBoolean bPeerNat =  (IPSEC_SA_FLAG_NAT_PEER & flags) ? TRUE : FALSE;
#endif
    intBoolean bInitiator = (IPSEC_SA_FLAG_INITIATOR & flags) ? TRUE : FALSE;
    intBoolean bInbound =
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                          (NULL != pxSp) ? /* automatic key */
                          ((IPSEC_SA_FLAG_INBOUND & flags) ? TRUE : FALSE) :
#endif
                          FALSE; /* manual key; no direction */
#ifdef __ENABLE_RB_SADB__
    ubyte4 hashValue;
    intBoolean isMatch;
    struct sadb_test saTest = { dwDestAddr, dwSrcAddr, dwSpi, oSaProto };
#else
    sbyte4 i;
    ubyte4 timedlt = 0;
#endif

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    intBoolean bMature  = (IPSEC_SA_FLAG_MATURE & flags) ? TRUE : FALSE;

    sbyte4 iNest        = pxKey->iNest;
    ubyte4 dwTimeStart  = pxKey->dwTimeStart; /* ms ago */

#ifndef __ENABLE_RB_SADB__
    SADB pxSaIdle = NULL;
#endif
    SADB pxSaOld = NULL;
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    /* copy content of pxkey to pxSa*/
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (pxKey->fqdn)
    {
        dwSaDestIPCount = pxKey->dwDestAddrCount;
        /* copy dest ip and src ip list*/

        dwSaSrcIPCount = pxKey->dwSrcAddrCount;
    }
#endif

    DIGI_MEMCPY(fqdn, pxKey->fqdn, MOC_MAX_FQDN_LEN);
#endif
    /* ICMP special case!!! */
    switch (oSaUlp)
    {
    case IPPROTO_ICMP :
    case IPPROTO_ICMPV6 :
        wSaDestPort = 0;
        break;
    }

    /* authentication */
    if (0 != pxKey->oAuthAlgo)
    {
        if (NULL == (pHmacSuite = IPSEC_hmacSuite(pxKey->oAuthAlgo)))
        {
            status = ERR_IPSEC;
            goto exit; /* not supported/specified */
        }
    }

    /* encryption */
    if (0 != pxKey->oEncrAlgo)
    {
        if (IPSEC_SA_FLAG_HEXKEY & flags)
            wEncrKeyLen = (pxKey->wEncrKeyLen / 2) + (pxKey->wEncrKeyLen % 2);
        else
            wEncrKeyLen = pxKey->wEncrKeyLen;

        if (NULL == (pCipherSuite = IPSEC_cipherSuite(pxKey->oEncrAlgo,
                                                      pxKey->oAeadIcvLen,
                                                      wEncrKeyLen, &wEncrKeyLen)))
        {
            status = ERR_IPSEC;
            goto exit; /* not supported/specified */
        }
    }

    /* ESN */
    if (IPSEC_SA_FLAG_ESN & flags)
#ifdef __ENABLE_IPSEC_ESN__
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (NULL == pxSp) /* manual key */
#endif
#endif
    {
        status = ERR_IPSEC;
        goto exit; /* must not specify ESN */
    }

#ifdef __ENABLE_RB_SADB__
#ifdef __ENABLE_IPSEC_NAT_T__
    saTest.wUdpEncPort  = wUdpEncPort;
    saTest.bPeerNat     = bPeerNat;
#endif
    saTest.timenow      = timenow;
#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
    saTest.pxSp         = pxSp;
    saTest.iNest        = iNest;
#ifdef USE_MOC_COOKIE
    saTest.cookie       = cookie;
#endif
    saTest.oUlp         = oSaUlp;
    saTest.wSrcPort     = wSaSrcPort;
    saTest.wDestPort    = wSaDestPort;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    saTest.oMode        = pxKey->oMode;
    saTest.dwDestIP     = pxKey->dwDestIP;
    saTest.dwDestIPEnd  = pxKey->dwDestIPEnd;
    saTest.dwSrcIP      = pxKey->dwSrcIP;
    saTest.dwSrcIPEnd   = pxKey->dwSrcIPEnd;
#endif
    saTest.bMature      = bMature;
    saTest.dwTimeStart  = dwTimeStart;
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
    if (pxKey->fqdn[0])
    {
        saTest.dwDestAddr = pxKey->dwDestAddrList[0];
        saTest.dwSrcIpInList = pxKey->dwSrcAddrList[0];
    }
#endif

#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
    if (bInbound || pxKey->inbound)
    {
        /* check existing SPI */
        GEN_INSPI_HASH_VALUE(dwSpi, hashValue)
        RB_SYNC(m_mtxInSpi,
        status = HASH_TABLE_findPtr(m_hashTableInSpi, hashValue, &saTest,
                                    (funcPtrExtraMatchTest)matchSpi,
                                    (void **)&pxSaTmp, &isMatch) )
        if (OK > status) goto exit;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        /* find existing SA's */
        if (NULL != pxSp) /* auto. key only */
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            MOC_IP_ADDRESS_S SA_SRC_ADDR = DEREF_MOC_IPADDR(dwSrcAddr);
#else
            #define SA_SRC_ADDR dwSrcAddr
#endif
            GEN_INBND_HASH_VALUE(SA_SRC_ADDR, hashValue)
            RB_SYNC(m_mtxInbnd,
            status = HASH_TABLE_findPtr(m_hashTableInbnd, hashValue, &saTest,
                                        (funcPtrExtraMatchTest)matchSa,
                                        (void **)&pxSaTmp, &isMatch) )
            if (OK > status) goto exit;
        }
#endif
    }
    else /* outbound */
#endif
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        MOC_IP_ADDRESS_S SA_DEST_ADDR = DEREF_MOC_IPADDR(dwDestAddr);
#else
        #define SA_DEST_ADDR dwDestAddr
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        /* Get the Outbound table key for the corresponding group */
        if (pxKey->fqdn[0])
        {
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
            GEN_OUTBND_HASH_VALUE(pxKey->fqdnUniqueKey, hashValue)
#else
            GEN_OUTBND_HASH_VALUE(pxKey->dwDestAddrList[0], hashValue)
#endif
        }
        else if (pxKey->dwDestIP)
#else
        if (pxKey->dwDestIP)
#endif
        {
            GEN_OUTBND_HASH_VALUE(pxKey->dwDestIP, hashValue)
        }
        else
        {
            GEN_OUTBND_HASH_VALUE(SA_DEST_ADDR, hashValue)
        }
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        outboundMappingConfig *outboundConfig = NULL;
        DIGI_MALLOC((void **)&outboundConfig, sizeof(outboundMappingConfig));
        DIGI_MEMSET((ubyte *)outboundConfig, '\0', sizeof(outboundMappingConfig));

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (pxKey->fqdn[0])
        {
            DIGI_MEMCPY(outboundConfig->fqdnName, pxKey->fqdn, DIGI_STRLEN((sbyte *)pxKey->fqdn));
        }
        else
#endif
        {
            outboundConfig->destIp = (MOC_IP_ADDRESS_S)(pxKey->dwDestIP);
        }
        RB_SYNC(m_mtxOutbnd,
            status = HASH_TABLE_findPtr(m_hashTableOutbnd, hashValue, outboundConfig,
                        (funcPtrExtraMatchTest)matchKeySa,
                        (void **)&pxSaTmp, &isMatch));
        DIGI_FREE((void **)&outboundConfig);
#else
        /* check existing SPI & find existing SA's */
        RB_SYNC(m_mtxOutbnd,
        status = HASH_TABLE_findPtr(m_hashTableOutbnd, hashValue, &saTest,
                                    (funcPtrExtraMatchTest)matchOutbndSa,
                                    (void **)&pxSaTmp, &isMatch) )
#endif
        if (OK > status) goto exit;
    }

    if (IPSEC_SADB_MAX > m_ipsecSadbNum)
    {
        NEW_SA(pxSa)
    }

    if (NULL == pxSa)
    {
        POP_SA(pxSa)
    }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pxSaOld = saTest.pxSaOld;

    if ((NULL == pxSa) && (NULL != pxSaOld))
    {
        /* override older SA */
        pxSa = pxSaOld;
        pxSaOld = pxSaOld->pNext;
    }
#endif

#else  /* __ENABLE_RB_SADB__ */
    /* keep deleted inbound or GDOI SA as long as possible (grace period) */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    #define IS_INBND_SA(_sa) ((IPSEC_SA_FLAG_GDOI|IPSEC_SA_FLAG_INBOUND) & (_sa)->saFlags)
#else
    #define IS_INBND_SA(_sa) (IPSEC_SA_FLAG_INBOUND & (_sa)->saFlags)
#endif
#else
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    #define IS_INBND_SA(_sa) (IPSEC_SA_FLAG_GDOI & (_sa)->saFlags)
#else
    #define IS_INBND_SA(_sa) FALSE
#endif
#endif
    /* find available slot */
    for (i=0 ; i < m_ipsecSadbNum; i++)
    {
        ubyte4 timedltTmp;

        NEXT_SA(pxSaTmp, i)

        /* unused? */
        if (!(IPSEC_SA_FLAG_INUSE & pxSaTmp->saFlags))
        {
            if ((NULL == pxSa) ||
                (IPSEC_SA_FLAG_INUSE & pxSa->saFlags))
                pxSa = pxSaTmp;
            continue;
        }

        if (pxSaTmp->dwSaLastUsed)
            timedltTmp = timenow - pxSaTmp->dwSaLastUsed;
        else
            timedltTmp = timenow - pxSaTmp->dwSaEstablished;

        /* deleted? */
        if ((IPSEC_SA_FLAG_DELETED & pxSaTmp->saFlags) ||
            IPSEC_expireSa(timenow, pxSaTmp))
        {
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            if (0 >= pxSaTmp->users)
#endif
            if ((NULL == pxSa) ||
                ((IPSEC_SA_FLAG_INUSE & pxSa->saFlags) &&
                 IS_INBND_SA(pxSa) &&
                 (!IS_INBND_SA(pxSaTmp) ||
                  (timedltTmp > timedlt))))
            {
                pxSa = pxSaTmp;
                timedlt = timedltTmp;
            }
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            /* If deleted GDOI SA is re-added, it needs to recycle the old SA
               in order to provide grace period; see IPSEC_findSa() in "ipsec.c"
             */
            if (!(IPSEC_SA_FLAG_GDOI & pxSaTmp->saFlags)
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
             || !((NULL == pxSp) && (NULL == pxSaTmp->pxSp))
#endif
                )
#endif
            continue;
        }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        /* find least active idle SA */
        if ((NULL == pxSa) &&
            (NULL != pxSaTmp->pxSp)) /* auto. keyed */
        {
            ubyte4 timeoutIdle = 600000/* 1000*60*10 */;    /* 10 minutes; FOR NOW */
            if (timedltTmp > timeoutIdle) /* idle */
            {
                if (((NULL == pxSaIdle) ||
                     ((IPSEC_SA_FLAG_INBOUND & pxSaIdle->saFlags) &&
                      !(IPSEC_SA_FLAG_INBOUND & pxSaTmp->saFlags)))
                    ||
                    (((IPSEC_SA_FLAG_INBOUND & pxSaIdle->saFlags) ||
                      !(IPSEC_SA_FLAG_INBOUND & pxSaTmp->saFlags)) &&
                     (timedltTmp > timedlt)))
                {
                    pxSaIdle = pxSaTmp;
                    timedlt = timedltTmp;
                }
            }
        }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
        if ((wUdpEncPort != pxSaTmp->wSaUdpEncPort) &&
            (bPeerNat || (IPSEC_SA_FLAG_NAT_PEER & pxSaTmp->saFlags)))
            continue;
#endif

        /* check existing spi */
        if ((dwSpi == pxSaTmp->dwSaSpi) &&
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            (dwDestAddr!=0 && SAME_MOC_IPADDR(dwDestAddr, pxSaTmp->dwSaDestAddr) ||
                    (fqdn[0]!=0 && (OK == DIGI_MEMCMP(pxSaTmp->fqdn , fqdn, MOC_MAX_FQDN_LEN, &result)&& result == 0)&&
                    (pxSaTmp->dwSaDestIPCount == dwSaDestIPCount) && (pxSaTmp->dwSaSrcIPCount == dwSaSrcIPCount)&&
                        (pxSaTmp->inbound == pxKey->inbound)))&&    /* check needed so that 2 SA with same SPI but different flow can be added for the mcp agent*/
#else
            SAME_MOC_IPADDR(dwDestAddr, pxSaTmp->dwSaDestAddr) &&
#endif
            ((oSaProto == pxSaTmp->oSaProto) ||
             (0 == pxSaTmp->oSaProto) || (0 == oSaProto)))
        {
            DB_PRINT("dwSpi:%d  pxSaTmp->dwSaSpi:%d  dwDestAddr:%x pxSaTmp->dwSaDestAddr:%x oSaProto:%d pxSaTmp->oSaProto:%d\n",
                    dwSpi,pxSaTmp->dwSaSpi,dwDestAddr,pxSaTmp->dwSaDestAddr,oSaProto,pxSaTmp->oSaProto );
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if ((NULL != pxSp) && (NULL != pxSaTmp->pxSp))
            {
#ifdef __IKE_MULTI_HOMING__
                if ((IPSEC_SA_FLAG_INBOUND & flags) !=
                    (IPSEC_SA_FLAG_INBOUND & pxSaTmp->saFlags))
                {
                    continue;
                }
#endif
            }
            else if ((NULL == pxSp) && (NULL == pxSaTmp->pxSp))
#endif
            {
                if (!(ISZERO_MOC_IPADDR(DEREF_MOC_IPADDR(dwSrcAddr)) ||
                      ISZERO_MOC_IPADDR(pxSaTmp->dwSaSrcAddr) ||
                      SAME_MOC_IPADDR(dwSrcAddr, pxSaTmp->dwSaSrcAddr)))
                {
                    continue;
                }
            }

            /* duplicate! */
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            if (IPSEC_SA_FLAG_DELETED & pxSaTmp->saFlags)
            {
                pxSa = pxSaTmp;
                goto cleanup;
            }
#endif
            status = STATUS_IPSEC_KEYADD_EXSTING;
            pxSa = NULL; /* !!! */
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        /* matching existing SA, if applicable */
        if ((NULL != pxSp) &&           /* auto. keying */
            (pxSp == pxSaTmp->pxSp) &&
            (iNest == pxSaTmp->iNest) &&
            SAME_MOC_IPADDR(dwDestAddr, pxSaTmp->dwSaDestAddr) &&
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            (SAME_MOC_IPADDR(dwSrcAddr, pxSaTmp->dwSaSrcAddr) ||
             (OK == DIGI_MEMCMP(pxSaTmp->fqdn , fqdn, MOC_MAX_FQDN_LEN, &result)&& result == 0)) &&
#else
            (SAME_MOC_IPADDR(dwSrcAddr, pxSaTmp->dwSaSrcAddr)) &&
#endif
#ifdef USE_MOC_COOKIE
            ((cookie == pxSaTmp->cookie) || (0 == cookie)) &&
#endif
#ifdef __IKE_MULTI_HOMING__
            ((IPSEC_SA_FLAG_INBOUND & flags) ==
             (IPSEC_SA_FLAG_INBOUND & pxSaTmp->saFlags)) &&
#endif
            ((pxSaTmp->wSaDestPort == wSaDestPort) || (0 == wSaDestPort)) &&
            ((pxSaTmp->wSaSrcPort == wSaSrcPort) || (0 == wSaSrcPort)) &&
            ((pxSaTmp->oSaUlp == oSaUlp) || (0 == oSaUlp)))
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (((pxSaTmp->oSaMode == pxKey->oMode) || (IPSEC_MODE_DONTCARE == pxKey->oMode)) &&
            ((IPSEC_MODE_TRANSPORT == pxSaTmp->oSaMode) ||
             (!CheckIpRange(pxKey->dwDestIP, pxKey->dwDestIPEnd,
                            REF_MOC_IPADDR(pxSaTmp->dwSaDestIP),
                            REF_MOC_IPADDR(pxSaTmp->dwSaDestIPEnd)) &&
              !CheckIpRange(pxKey->dwSrcIP, pxKey->dwSrcIPEnd,
                            REF_MOC_IPADDR(pxSaTmp->dwSaSrcIP),
                            REF_MOC_IPADDR(pxSaTmp->dwSaSrcIPEnd)))))
#endif
        {
            intBoolean bMatureTmp = (IPSEC_SA_FLAG_MATURE & pxSaTmp->saFlags);

            if (/*(bMature || !bMatureTmp) &&*/
                (!bMature || bMatureTmp || /* should avoid race condition btw peers */
                 ((/*timenow - */dwTimeStart) < (timenow - pxSaTmp->dwSaEstablished))))
            {
                /* match */
                pxSaTmp->pNext = pxSaOld;
                pxSaOld = pxSaTmp;
            }
        }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */
    } /* for */

    if ((IPSEC_SADB_MAX > m_ipsecSadbNum) &&
        ((NULL == pxSa) || (IPSEC_SA_FLAG_INUSE & pxSa->saFlags)))
    {
        NEW_SA(pxSaTmp)
        if (pxSaTmp) pxSa = pxSaTmp;
    }

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /* override older SA? */
    if (NULL != pxSaOld)
    {
        if ((NULL == pxSa) ||
            (!bInbound &&
             (IPSEC_SA_FLAG_INUSE & pxSa->saFlags) &&
             IS_INBND_SA(pxSa)))
        {
            pxSa = pxSaOld;
            pxSaOld = pxSaOld->pNext;
        }
    }
    else if (NULL == pxSa)
    {
        /* delete the least active idle SA */
        pxSa = pxSaIdle;
    }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __ENABLE_RB_SADB__ */

    if (NULL == pxSa)
    {
        status = STATUS_IPSEC_KEYADD_ABORT;
        goto exit; /* not found */
    }

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_RB_SADB__)
cleanup:
#endif
    /* clean up */
    if (IPSEC_SA_FLAG_INUSE & pxSa->saFlags)
    {
        if (!(IPSEC_SA_FLAG_DELETED & pxSa->saFlags))
        {
            IPSEC_delSa(pxSa, TRUE);
#ifdef __ENABLE_RB_SADB__
            /*  'pxSa' is pushed to 'free' list by above call */
            POP_SA(pxSa) /* pop from 'free' list */
            if (NULL == pxSa) /* jic */
            {
                status = STATUS_IPSEC_KEYADD_ABORT;
                goto exit;
            }
#endif
        }
#ifdef __ENABLE_RB_SADB__
        else
        {
            /* This (already deleted) SA may no longer exist in any hashtable,
               e.g. old (rekeyed) outbound SA. However, attemp to remove it
               from hashtables will not cause any issue.
             */
        }
        IPSEC_delSaIndex(pxSa); /* remove from hashtables */
#endif
        ZEROIZE_SA(pxSa)
    }

    /* initialize */
    if (bInbound)
        pxSa->saFlags |= IPSEC_SA_FLAG_INBOUND;

    if (bInitiator)
        pxSa->saFlags |= IPSEC_SA_FLAG_INITIATOR;

    pxSa->oSaProto      = oSaProto;
    pxSa->dwSaSpi       = dwSpi;

    COPY_MOC_IPADDR(pxSa->dwSaDestAddr, dwDestAddr);
    COPY_MOC_IPADDR(pxSa->dwSaSrcAddr, dwSrcAddr);

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pxSa->cookie        = cookie;
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    pxSa->wSaUdpEncPort = pxKey->wUdpEncPort;
    if (bPeerNat)
        pxSa->saFlags |= IPSEC_SA_FLAG_NAT_PEER;
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    if (IPSEC_MODE_TRANSPORT != (pxSa->oSaMode = pxKey->oMode))
#endif
    {
        pxSa->oSaMode = pxKey->oMode;
        /* get private network */
        COPY_MOC_IPADDR(pxSa->dwSaDestIP, pxKey->dwDestIP);
        COPY_MOC_IPADDR(pxSa->dwSaDestIPEnd, pxKey->dwDestIPEnd);

        COPY_MOC_IPADDR(pxSa->dwSaSrcIP, pxKey->dwSrcIP);
        COPY_MOC_IPADDR(pxSa->dwSaSrcIPEnd, pxKey->dwSrcIPEnd);
    }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    /* copy content of pxkey to pxSa*/
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (pxKey->fqdn != 0)
    {
        /* copy dest ip and src ip list*/
        DIGI_MEMCPY(pxSa->dwSaSrcIPList, pxKey->dwSrcAddrList, (pxKey->dwSrcAddrCount)*(sizeof(MOC_IP_ADDRESS)));
        pxSa->dwSaSrcIPCount = pxKey->dwSrcAddrCount;

        DIGI_MEMCPY(pxSa->dwSaDestIPList, pxKey->dwDestAddrList, (pxKey->dwDestAddrCount)*(sizeof(MOC_IP_ADDRESS)));
        pxSa->dwSaDestIPCount = pxKey->dwDestAddrCount;
        pxSa->inbound = pxKey->inbound;
    }
#endif
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    DIGI_MEMCPY(pxSa->fqdn, pxKey->fqdn, MOC_MAX_FQDN_LEN);
#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    pxSa->fqdnUniqueKey = pxKey->fqdnUniqueKey;
#endif
#endif

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    pxSa->avoidExpire = FALSE;
#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
    ubyte4 j=0;
    for (j = 0; j < m_ipsecSadbNum; j++)
    {
        NEXT_SA(pxSaTmp, j)

        if ((NULL != pxSaTmp) && (IPSEC_SA_FLAG_INUSE & pxSaTmp->saFlags) &&
            ((pxSa->fqdn[0] && pxSaTmp->fqdn[0] && pxSa->inbound == pxSaTmp->inbound && !DIGI_STRCMP(pxSa->fqdn, pxSaTmp->fqdn))||    /* if both Sa have valid fqdn and have samre direction only then compare the fqdn */
            (!pxSa->fqdn[0] && (pxSa->dwSaDestIP == pxSaTmp->dwSaDestIP) && (pxSa->dwSaDestIPEnd == pxSaTmp->dwSaDestIPEnd)))
            && (pxSa->oSaUlp == pxSaTmp->oSaUlp))
        {
            pxSaTmp->avoidExpire = FALSE;
        }
    }

    pxSa->avoidExpire = m_ipsecSadbForever;
#endif
#endif

    pxSa->wSaDestPort   = wSaDestPort;
    pxSa->wSaSrcPort    = wSaSrcPort;
    pxSa->oSaUlp        = oSaUlp;

    pxSa->dwSaEstablished = timenow;

    pxSa->dwSaExpSecs   = pxKey->dwExpSecs;
    pxSa->dwSaExpKBytes = pxKey->dwExpKBytes;

    if (0xffffffff == m_ipsecSadbId) m_ipsecSadbId = 0;
    pxSa->dwId          = ++m_ipsecSadbId;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    if (bMature)
        pxSa->saFlags |= IPSEC_SA_FLAG_MATURE;

    if (NULL != pxSp) /* auto. keying */
    {
        pxSa->pxSp      = pxSp;
        pxSa->iNest     = iNest;
        pxSa->dwSpdId   = pxSp->dwId;

        pxSa->dwIkeSaId = pxKey->dwIkeSaId;
        pxSa->ikeSaLoc = pxKey->ikeSaLoc;

        /* get mirrored SA */
        if (bInitiator == bInbound) /* _I */
        {
            SADB pxSaM;
            if ((OK == IPSEC_findSa(pxKey->dwSpiM,
                                    dwSrcAddr, dwDestAddr,
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                                    fqdn,
#endif
                                    oSaProto,
                                    !bInbound,
                                    &pxSaM))
                && (NULL != pxSaM))
            {
                pxSa->pxSaM = pxSaM;
                pxSa->dwIdM = pxSaM->dwId;
                pxSaM->pxSaM = pxSa;
                pxSaM->dwIdM = pxSa->dwId; /* pxSa->dwId must be set *before* this! */
            }
        }

#ifdef IPSEC_REPLAY_SIZE
        if (bInbound)
            pxSa->u.i.poReplayWindow[0] = 0x1;
#endif
    }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#ifdef __ENABLE_IPSEC_ESN__
    if (IPSEC_SA_FLAG_ESN & flags)
        pxSa->saFlags |= IPSEC_SA_FLAG_ESN;
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    if (IPSEC_SA_FLAG_GDOI & flags)
        pxSa->saFlags |= IPSEC_SA_FLAG_GDOI;
#endif

    /* store auth. key */
    if (NULL != pHmacSuite)
    {
        ubyte2 wAuthKeyLen = pHmacSuite->wKeyLen;
        pxSa->pHmacSuite = pHmacSuite;

        if (IPSEC_SA_FLAG_HEXKEY & flags)
        {
            ScanHexKey(pxKey->wAuthKeyLen, (sbyte *) pxKey->poAuthKey,
                       wAuthKeyLen, pxSa->poAuthKey);
        }
        else
        {
            if (wAuthKeyLen > pxKey->wAuthKeyLen)
            {
                DIGI_MEMSET(pxSa->poAuthKey, 0x00, wAuthKeyLen); /* redundant? */
                wAuthKeyLen = pxKey->wAuthKeyLen;
            }
            DIGI_MEMCPY(pxSa->poAuthKey, pxKey->poAuthKey, wAuthKeyLen);
        }

#ifdef __IPSEC_SINGLE_PASS_SUPPORT__
        if (NULL != pCipherSuite)
        {
            pxSa->dwSinglePassCookie = IPSEC_getSinglePassType(pCipherSuite, pHmacSuite, bInbound);
        }
#endif
    }

    /* store encryption key */
    if (NULL != pCipherSuite)
    {
        ubyte *poEncrKey = pxSa->poEncrKey;
        AeadAlgo *pAeadAlgo = pCipherSuite->pAeadAlgo;

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
        hwAccelDescr hwAccelCtx;
        if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx, bInbound)))
            goto exit;
#endif
        pxSa->wEncrKeyLen = wEncrKeyLen;
        pxSa->pCipherSuite = pCipherSuite;

        /* get key first */
        if (IPSEC_SA_FLAG_HEXKEY & flags)
        {
            ScanHexKey(pxKey->wEncrKeyLen, (sbyte *) pxKey->poEncrKey,
                       wEncrKeyLen, poEncrKey);
        }
        else if (wEncrKeyLen > pxKey->wEncrKeyLen)
        {
            DIGI_MEMSET(poEncrKey, 0x00, wEncrKeyLen); /* redundant? */
            DIGI_MEMCPY(poEncrKey, pxKey->poEncrKey, pxKey->wEncrKeyLen);
        }
        else
        {
            DIGI_MEMCPY(poEncrKey, pxKey->poEncrKey, wEncrKeyLen);
        }

        /* create cipher context */
        if (NULL != pAeadAlgo)
        {
            ubyte oSaltLen = (ubyte) pAeadAlgo->implicitNonceSize;

            pxSa->pCipherCtx = pAeadAlgo->createFunc(MOC_SYM(hwAccelCtx)
                                                     poEncrKey,
                                                     wEncrKeyLen - oSaltLen,
                                                     !bInbound);
            if (NULL == pxSa->pCipherCtx)
            {
                status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            }
            else
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (NULL == pxSp) /* manual key */
#endif
            {
                pxSa->pCipherCtxM = pAeadAlgo->createFunc(MOC_SYM(hwAccelCtx)
                                                          poEncrKey,
                                                          wEncrKeyLen - oSaltLen,
                                                          bInbound);
                if (NULL == pxSa->pCipherCtxM)
                {
                    status = ERR_HARDWARE_ACCEL_NO_MEMORY;
                }
            }
        }
        else
        {
            pxSa->pCipherCtx = pCipherSuite->pBEAlgo->createFunc(MOC_SYM(hwAccelCtx)
                                            poEncrKey, wEncrKeyLen, !bInbound);
            if (NULL == pxSa->pCipherCtx)
            {
                status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            }
            else
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (NULL == pxSp) /* manual key */
#endif
            {
                pxSa->pCipherCtxM = pCipherSuite->pBEAlgo->createFunc(MOC_SYM(hwAccelCtx)
                                            poEncrKey, wEncrKeyLen, bInbound);
                if (NULL == pxSa->pCipherCtxM)
                {
                    status = ERR_HARDWARE_ACCEL_NO_MEMORY;
                }
            }
        }

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
        IPSEC_releaseHwAccelChannel(&hwAccelCtx);
#endif
        if (OK > status)
        {
            goto exit;
        }
    }

#ifdef __ENABLE_RB_SADB__
    /* add to hashtables */
    if (OK > (status = IPSEC_addSaIndex(pxSa)))
    {
        goto exit;
    }
#endif

    pxSa->saFlags |= IPSEC_SA_FLAG_INUSE;
    if (IPSEC_SA_FLAG_IKE2 & pxKey->flags)
        pxSa->saFlags |= IPSEC_SA_FLAG_IKE2;

    /* done */
    if (ppxSa) *ppxSa = pxSa;
    pxSa = NULL;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    /* delete older SA's */
    while (NULL != pxSaOld)
    {
        pxSaTmp = pxSaOld->pNext;
        IPSEC_delSa(pxSaOld, TRUE); /* delete */

#ifdef __ENABLE_RB_SADB__
        /* If this is an outbound SA, it will not be used again.
           Remove it from hashtables now to avoid unnecessary matching!
         */
        if (!bInbound)
        {
            IPSEC_delSaIndex(pxSaOld);
            /* Note: not zeroized! */
        }
#endif
        pxSaOld = pxSaTmp;
    }
#endif

exit:
    if (NULL != pxSa) /* recyle aborted SA */
    {
        ZEROIZE_SA(pxSa)
#ifdef __ENABLE_RB_SADB__
        /* Note: not in any hashtables! */
        PUSH_SA(pxSa) /* push to 'free' list */
#endif
    }

#ifdef __ENABLE_RB_SADB__
    /* tranverse from deleted to tail to see if any node can be removed from HASH or not*/
    if(NULL == m_freeQueueDeleted)
    {
        m_freeQueueDeleted = m_freeQueueTail;
    }
    if(m_freeQueueDeleted)
    {
        /* transverse from deleted to tail here*/
        while(m_freeQueueDeleted->pNext != m_freeQueueTail  && m_freeQueueDeleted->pNext != NULL)
        {
            IPSEC_delSaIndex(m_freeQueueDeleted);   /* delete the curret node from HASH table*/
            m_freeQueueDeleted = m_freeQueueDeleted->pNext;
        }
    }
#endif
    return status;
} /* IPSEC_newSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_delSa(SADB pxSa, intBoolean bInfo)
{
    MSTATUS status = OK;

    intBoolean bDeleted;

    DOWN_SA_LOCK(pxSa)

    if (!(IPSEC_SA_FLAG_INUSE & pxSa->saFlags)) /* jic */
    {
        goto exit;
    }
    bDeleted = (IPSEC_SA_FLAG_DELETED & pxSa->saFlags);


#ifndef __ENABLE_DIGICERT_IKE_SERVER__
    MOC_UNUSED(bInfo);
#else
    /* inform IKE of SA deletion, if necessary */
    if (NULL != pxSa->pxSp) /* auto. keyed */
    {
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
        ubyte2 type = 0;

        if (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) /* inbound SA */
        {
            if (!bDeleted)
            {
                pxSa->dwSaLastRekey = timenow;

                if (bInfo)
                {
                    /* should stop re-transmission of final quick mode message? */
                    if (!(IPSEC_SA_FLAG_MATURE & pxSa->saFlags) &&
                        ((timenow - pxSa->dwSaEstablished) < (ubyte4)30000)) /* 30 secs - FOR NOW */
                    {
                        type = IKE_KEY_TYPE_ABORTED;
                    }
                    else
                    {
                        type = IKE_KEY_TYPE_DELETED;
                    }
                }
                else
                {
                    type = IKE_KEY_TYPE_DELETED | IKE_KEY_MOD_PRIVATE;
                }
            }
            else if (bInfo)
            {
                type = IKE_KEY_TYPE_DELETED;
            }
        }
        else  /* outbound SA */
        {
            if (!bDeleted)
            {
                type = IKE_KEY_TYPE_DELETED | IKE_KEY_MOD_OUTBOUND;
                if (!bInfo) type |= IKE_KEY_MOD_PRIVATE;
            }
        }

        if (type)
        {
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
            if (OK == IKE_keyInfoEx(pxSa,
#ifdef __ENABLE_IPSEC_NAT_T__
                                    ((IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)
                                     ? pxSa->wSaUdpEncPort : 0),
#endif
                                    pxSa->dwSaSpi, type))
#else
            if (OK == IKE_keyInform(REF_MOC_IPADDR(pxSa->dwSaDestAddr),
                                    REF_MOC_IPADDR(pxSa->dwSaSrcAddr),
#ifdef __ENABLE_IPSEC_NAT_T__
                                    ((IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)
                                     ? pxSa->wSaUdpEncPort : 0),
#endif
                                    pxSa->dwSaSpi, pxSa->oSaProto,
                                    pxSa->dwIkeSaId, pxSa->ikeSaLoc,
                                    type MOC_COOKIE_VALUE(pxSa->cookie)))
#endif
            {
                pxSa->dwSaFirstUsed = timenow;
            }
        }
    }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

    if (!bDeleted)
    {
        pxSa->saFlags |= IPSEC_SA_FLAG_DELETED;
#ifdef LOG_SADB_DELETE
        LOG_SADB_DELETE(pxSa->oSaProto, pxSa->dwSaSpi, pxSa)
#endif

#ifdef __ENABLE_RB_SADB__
        PUSH_SA(pxSa)
	/* don't delete hash entry from here , can cause deadlock*/
        /* Note: pxSa is *not* removed from hashtables! */
#endif
    }
    pxSa->dwId = 0;

exit:
    UP_SA_LOCK(pxSa)
    return status;
} /* IPSEC_delSa */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_RB_SADB__

static MSTATUS
ipsec_findSa(SADB pxSa, SADB_TEST testSa, intBoolean *isMatch)
{
    *isMatch = FALSE;

    if (pxSa && (IPSEC_SA_FLAG_INUSE & pxSa->saFlags) && /* redundant */
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    ((((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
        REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
        testSa->dwDestAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
            || ((pxSa->fqdn[0] == 0) && SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr)))) ||
            (pxSa->fqdn[0] && (pxSa->dwSaDestIPCount && (!checkIpinList(testSa->dwDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount))))) &&
#else
        SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr) &&
#endif
        (testSa->dwSaSpi == pxSa->dwSaSpi) &&
        ((testSa->oProto == pxSa->oSaProto) || (0 == pxSa->oSaProto)))
    {
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL != pxSa->pxSp) /* auto. key */
        {
            if (!(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags)) /* outbound */
            {
                if (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) goto exit;
            }
            else if (!(IPSEC_SA_FLAG_DELETED & pxSa->saFlags)) /* inbound */
            {
                IPSEC_expireSa(testSa->timenow, pxSa); /* expired? */
            }
        }
        else
#endif
        /* manual key */
        if (!ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr) &&
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        (((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
            REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* as in case of unicats src and dest will be part of same unicast range*/
            testSa->dwSrcAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP == pxSa->dwSaDestIPEnd)) &&
            ((pxSa->fqdn[0] == 0) && !SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr))) ||
                (pxSa->fqdn[0] && pxSa->dwSaSrcIPCount && (checkIpinList(testSa->dwSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)))))
#else
            !SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr))
#endif
        {
            goto exit;
        }
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        else if (IPSEC_SA_FLAG_GDOI & pxSa->saFlags)
        {
            if (!(IPSEC_SA_FLAG_DELETED & pxSa->saFlags))
            {
                IPSEC_expireSa(testSa->timenow, pxSa);
            }
        }
#endif
        else if (IPSEC_SA_FLAG_DELETED & pxSa->saFlags)
        {
            goto exit;
        }

        /* found */
        *isMatch = TRUE;
    }

exit:
    return OK;
}

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_findSa(ubyte4 dwSpi,
             MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
             ubyte* fqdn,
#endif
             ubyte oSaProto,
             intBoolean bInbound,
             SADB *ppxSa)
{
    MSTATUS status = ERR_IPSEC_DROP_FINDSA_FAIL;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    sbyte4 result = 0;
#endif
    SADB pxSa = NULL;
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
#endif

#ifdef __ENABLE_RB_SADB__
    ubyte4 hashValue;
    intBoolean isMatch = FALSE;
    struct sadb_test saTest = { dwDestAddr, dwSrcAddr, dwSpi, oSaProto };
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    saTest.timenow = timenow;
#endif
    if (!bInbound)
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        MOC_IP_ADDRESS_S DEST_ADDR = DEREF_MOC_IPADDR(dwDestAddr);
#else
        #define DEST_ADDR dwDestAddr
#endif
#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
        MOC_IP_ADDRESS_S temp_addr;

        /* Get the Outbound table key for the corresponding group */
        temp_addr = IPSEC_mapIpToKey(DEST_ADDR);

        GEN_OUTBND_HASH_VALUE(temp_addr, hashValue)
#else
        GEN_OUTBND_HASH_VALUE(DEST_ADDR, hashValue)
#endif

        RB_SYNC(m_mtxOutbnd,
        status = HASH_TABLE_findPtr(m_hashTableOutbnd, hashValue, &saTest,
                                    (funcPtrExtraMatchTest)ipsec_findSa,
                                    (void **)&pxSa, &isMatch) )
    }
    else
    {
        GEN_INSPI_HASH_VALUE(dwSpi, hashValue)
        RB_SYNC(m_mtxInSpi,
        status = HASH_TABLE_findPtr(m_hashTableInSpi, hashValue, &saTest,
                                    (funcPtrExtraMatchTest)ipsec_findSa,
                                    (void **)&pxSa, &isMatch) )
    }

    if ((OK > status) || !isMatch)
    {
        pxSa = NULL; /* jic */
    }
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    else if (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) /* already deleted */
    {
        status = ERR_IPSEC_DROP_FINDSA_FAIL; /* !!! */
    }
#endif
#else

    sbyte4 i;
#ifdef MOCANA_IPSEC_DEBUGGING
    DB_PRINT("\n ipsec_findsa for incoming pkt dwDestAddr=%x dwSAddr=%x proto=%d ",dwDestAddr, dwSrcAddr, oSaProto);
#endif
    for (i=0; i < m_ipsecSadbNum; i++, pxSa = NULL)
    {
        NEXT_SA(pxSa, i)
        if(NULL != pxSa)
        {
#ifdef MOCANA_IPSEC_DEBUGGING
            DB_PRINT("\n ipsec_findsa params dwDestAddr=%x pxSa->saFlags=%x pxSa->dwSaDestAddr=%x pxSa->dwSaDestIPEnd=%x pxSa->dwSaDestIP=%x  dwSpi=%x pxSa->dwSaSpi=%x ,oSaProto=%d pxSa->oSaProto=%d pxSa->dwSaSrcAddr=%x",
                dwDestAddr, pxSa->saFlags, pxSa->dwSaDestAddr,pxSa->dwSaDestIPEnd, pxSa->dwSaDestIP, dwSpi, pxSa->dwSaSpi,oSaProto, pxSa->oSaProto ,pxSa->dwSaSrcAddr  );
#endif
        }

        if ((IPSEC_SA_FLAG_INUSE & pxSa->saFlags) &&
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
            SAME_MOC_IPADDR(dwDestAddr, pxSa->dwSaDestAddr) &&
#else
        ((((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                        REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
                        dwDestAddr,0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
             || SAME_MOC_IPADDR(dwDestAddr, pxSa->dwSaDestAddr)))||
             (pxSa->fqdn && (((!pxSa->dwSaDestIPCount) && (OK == DIGI_MEMCMP(pxSa->fqdn , fqdn, MOC_MAX_FQDN_LEN, &result)&& result == 0))||
             (pxSa->dwSaDestIPCount && (!checkIpinList(dwDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount)))))) &&
#endif
            (dwSpi == pxSa->dwSaSpi) &&
            ((oSaProto == pxSa->oSaProto) || (0 == pxSa->oSaProto)))
        {
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (NULL != pxSa->pxSp) /* auto. key */
            {
#ifdef __IKE_MULTI_HOMING__
                if ((bInbound && !(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags)) ||
                    (!bInbound && (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags)))
                    continue;
#endif
                if (!bInbound) /* outbound */
                {
                    if (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) continue;
                }
                else /* inbound */
                if ((IPSEC_SA_FLAG_DELETED & pxSa->saFlags) || /* already deleted */
                    IPSEC_expireSa(timenow, pxSa)) /* expired */
                    goto exit;
            }
            else
#endif
            /* manual key */
            if (!(ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr) ||
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                  SAME_MOC_IPADDR(dwSrcAddr, pxSa->dwSaSrcAddr)))
#else
                  (((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                        REF_MOC_IPADDR(pxSa->dwSaDestIPEnd),    /* as in case of unicats src iup should be in the range of all the ips that have been negotiated*/
                        dwSrcAddr,0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
                        || SAME_MOC_IPADDR(dwSrcAddr, pxSa->dwSaSrcAddr))||
                        (pxSa->fqdn && pxSa->dwSaSrcIPCount && (!checkIpinList(dwSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount))))))
#endif
            {
                continue;
            }
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            else if (IPSEC_SA_FLAG_GDOI & pxSa->saFlags)
            {
                if ((IPSEC_SA_FLAG_DELETED & pxSa->saFlags) || /* already deleted */
                    IPSEC_expireSa(timenow, pxSa)) /* expired */
                    goto exit;
            }
#endif
            else if (IPSEC_SA_FLAG_DELETED & pxSa->saFlags)
            {
                continue;
            }

            /* found */
            break;
        }
    }
    status = OK;

#ifndef __ENABLE_DIGICERT_IKE_SERVER__
    MOC_UNUSED(bInbound);
#endif

exit:
#endif /*__ENABLE_RB_SADB__*/

    *ppxSa = pxSa;
    return status;
} /* IPSEC_findSa */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_RB_SADB__

static MSTATUS
ipsec_getSa(SADB pxSa, SADB_TEST testSa, intBoolean *isMatch)
{
    ubyte4 timethen;

    *isMatch = FALSE;

            /* skipping SA */
            if (!pxSa || !(IPSEC_SA_FLAG_INUSE & pxSa->saFlags) || /* redundant */
                (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) ||
                IPSEC_expireSa(testSa->timenow, pxSa))
            {
                goto exit;
            }

            /* matching SA against SP */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (pxSa->pxSp) /* auto. keyed */
            {
#ifdef __DISABLE_IPSEC_COMP_GETSA__
                if ((testSa->pxSp != pxSa->pxSp) || (testSa->iNest != pxSa->iNest))
                    goto exit;
            }
            else
#else
                if (testSa->iNest != pxSa->iNest)
                    goto exit;

                if (testSa->pxSp != pxSa->pxSp) /* !!! */
                {
                    /* SA w/ 'compatible' (but not associated) SP may be OK
                       unless we've already found SA w/ matching associated SP
                     */
                    if (testSa->pxSaRet && (testSa->pxSp == testSa->pxSaRet->pxSp))
                        goto exit;
                }
            }

            if (testSa->pxSp != pxSa->pxSp) /* check only SA not associated with SP */
#endif
#endif
            {
                /* check mode & algorithms */
                if (!(
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                      ((testSa->oMode == pxSa->oSaMode) || (IPSEC_MODE_DONTCARE == pxSa->oSaMode)) &&
#endif
                      IPSEC_matchSp(NULL, pxSa, testSa->pxSp, testSa->iNest)))
                {
                    goto exit;
                }

                /* check endpoint IP addresses */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                if (((testSa->oSaLen - 1) == testSa->iNest) &&
                    (IPSEC_MODE_TUNNEL == testSa->oMode))
                {
                    if ((testSa->saDestAddr && !SAME_MOC_IPADDR(testSa->saDestAddr, pxSa->dwSaDestAddr)) ||
                        (testSa->saSrcAddr && !SAME_MOC_IPADDR(testSa->saSrcAddr, pxSa->dwSaSrcAddr)))
                    {
                        goto exit;
                    }
                }
                else
#endif
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                if (!SAME_MOC_IPADDR(testSa->saDestAddr, pxSa->dwSaDestAddr) ||
#else
                if (((!pxSa->fqdn[0] && ((( pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                    REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
                    testSa->saDestAddr, 0)) || (( pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP == pxSa->dwSaDestIPEnd))
                        && !SAME_MOC_IPADDR(testSa->saDestAddr, pxSa->dwSaDestAddr)))) ||
                        (pxSa->fqdn[0] && (pxSa->dwSaDestIPCount && (checkIpinList(testSa->saDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount))))) ||
#endif
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                    (!SAME_MOC_IPADDR(testSa->saSrcAddr, pxSa->dwSaSrcAddr) &&
#else
                    (((!pxSa->fqdn[0] && (((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                        REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* as in case of unicats src and dest will be part of same unicast range*/
                        testSa->saSrcAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP == pxSa->dwSaDestIPEnd)) &&
                        !SAME_MOC_IPADDR(testSa->saSrcAddr, pxSa->dwSaSrcAddr)))) ||
                            (pxSa->fqdn[0] && pxSa->dwSaSrcIPCount && (checkIpinList(testSa->saSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)))) &&
#endif
                     !ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr)))
                {
                    goto exit;
                }
            }

#ifdef __ENABLE_IPSEC_NAT_T__
            /* check NAT-T udp encap. port */
            if ((testSa->wUdpEncPort != pxSa->wSaUdpEncPort) &&
                (testSa->wUdpEncPort || ((testSa->oSaLen - 1) != testSa->iNest)))
            {
                goto exit;
            }
#endif
            /* matching SA against flow */
            if (!(((testSa->wDestPort == pxSa->wSaDestPort) || (0 == pxSa->wSaDestPort)) &&
                  ((testSa->wSrcPort == pxSa->wSaSrcPort) || (0 == pxSa->wSaSrcPort))    &&
                  ((testSa->oProto == pxSa->oSaUlp) || (0 == pxSa->oSaUlp))              &&
#ifdef USE_MOC_COOKIE
                  ((testSa->cookie == pxSa->cookie) || (0 == pxSa->cookie))              &&
#endif
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                  ((IPSEC_MODE_TRANSPORT == testSa->oMode) ||
                   (!CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                                  REF_MOC_IPADDR(pxSa->dwSaDestIPEnd),
                                  testSa->dwDestAddr, 0) &&
                    !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaSrcIP),
                                  REF_MOC_IPADDR(pxSa->dwSaSrcIPEnd),
                                  testSa->dwSrcAddr, 0)))                                &&
#endif
                  (
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                   (IPSEC_MODE_TUNNEL == testSa->oMode) ||
#endif
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                   (((!pxSa->fqdn[0] && (((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                       REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* In case of unicast src ip should be in the range of all the ips that have been negotiated */
                       testSa->dwDestAddr, 0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
                           || SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr)))) ||
                           (pxSa->fqdn[0] && (pxSa->dwSaDestIPCount && (!checkIpinList(testSa->dwDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount))))) &&
#else
                      (SAME_MOC_IPADDR(testSa->dwDestAddr, pxSa->dwSaDestAddr) &&
#endif
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                      (((!pxSa->fqdn[0] && ((( pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                          REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* as in case of unicats src and dest will be part of same unicast range*/
                          testSa->dwSrcAddr, 0)) || (( pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) ||
                          SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr)))) ||
                              (pxSa->fqdn[0] && pxSa->dwSaSrcIPCount && (!checkIpinList(testSa->dwSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)))) ||
#else
                      (SAME_MOC_IPADDR(testSa->dwSrcAddr, pxSa->dwSaSrcAddr) ||
#endif
                     ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr))))
                 ))
            {
                goto exit;
            }

            /* DSCP-specific filtering */
#ifdef CUSTOM_IPSEC_FILTER_DSCP
            if (pxSa->pDscpValues)
            {
                if (OK > CUSTOM_IPSEC_FILTER_DSCP(testSa->oDscp, pxSa->pDscpValues))
                    goto exit;
            }
#endif
            /* match found */
            if (0 == (timethen = pxSa->dwSaLastUsed))
                timethen = pxSa->dwSaEstablished;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            /* check mirrored inbound SA */
            if (pxSa->pxSp)
            {
                SADB pxSaM = pxSa->pxSaM;
                if (pxSaM && (pxSaM->dwId == pxSa->dwIdM))
                {
                    ubyte4 timethenM = pxSaM->dwSaLastUsed;
                    if (timethenM &&
                        ((testSa->timenow - timethenM) < (testSa->timenow - timethen)))
                        timethen = timethenM;
                }
            }
#endif
            /* get the most recent */
            if (testSa->pxSaRet)
            {
                SADB pxSaRet = testSa->pxSaRet;

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_COMP_GETSA__)
                /* always choose SA w/ matching SP over SA w/ 'compatible' SP */
                if ((testSa->pxSp == pxSa->pxSp) && (testSa->pxSp != pxSaRet->pxSp) && pxSaRet->pxSp)
                    goto ret;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                /* always choose GDOI key over non-GDOI key */
                if (!(IPSEC_SA_FLAG_GDOI & pxSa->saFlags))
                {
                    if (IPSEC_SA_FLAG_GDOI & pxSaRet->saFlags)
                        goto exit;
                }
                else
                {
                    if (!(IPSEC_SA_FLAG_GDOI & pxSaRet->saFlags))
                        goto ret;

                    /* choose GDOI key with expiration */
                    if (!(pxSa->dwSaExpSecs || pxSa->dwSaExpKBytes))
                    {
                        if (pxSaRet->dwSaExpSecs || pxSaRet->dwSaExpKBytes)
                            goto exit;
                    }
                    else
                    {
                        if (!(pxSaRet->dwSaExpSecs || pxSaRet->dwSaExpKBytes))
                            goto ret;

                        /* choose older GDOI key !!! */
                        if ((testSa->timenow - pxSa->dwSaEstablished) >
                            (testSa->timenow - pxSaRet->dwSaEstablished))
                            goto ret;

                        goto exit;
                    }
                }
#endif
                if ((testSa->timenow - testSa->timethenRet) > (testSa->timenow - timethen))
                    goto ret;

                goto exit; /* !!! */
            }
ret:
            testSa->pxSaRet = pxSa;
            testSa->timethenRet = timethen;

exit:
    return OK;
}

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_getSa(MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
            ubyte oProto, ubyte2 wDestPort, ubyte2 wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            MOC_IP_ADDRESS dwTunlDestIP, MOC_IP_ADDRESS dwTunlSrcIP,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
            ubyte2 wUdpEncPort,
#endif
#ifdef CUSTOM_IPSEC_FILTER_DSCP
            ubyte oDscp,
#endif
            SPD pxSp, SADB *axSa MOC_COOKIE(cookie))
{
    MSTATUS status = OK;

    sbyte4 iNest;
    ubyte oSaLen = pxSp->oSaLen;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

#ifdef __ENABLE_RB_SADB__
    ubyte4 hashValue;
    struct sadb_test saTest = { 0 };
    intBoolean isMatch = FALSE;
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_IP_ADDRESS saDestAddr, saSrcAddr;

    ubyte oMode = pxSp->oMode;
    if (IPSEC_MODE_TUNNEL == oMode) /* tunnel mode */
    {
        saDestAddr = dwTunlDestIP;
        saSrcAddr = dwTunlSrcIP;
    }
    else /* transport mode */
    {
        oMode = IPSEC_MODE_TRANSPORT; /* jic */
        saDestAddr = dwDestAddr;
        saSrcAddr = dwSrcAddr;
    }
#else
#define saDestAddr dwDestAddr
#define saSrcAddr dwSrcAddr
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

    /* start with innermost SA */
    for (iNest = oSaLen - 1; iNest >= 0; iNest--)
    {
        SADB pxSaRet = NULL;

        /* find match in SADB */
#ifdef __ENABLE_RB_SADB__
#ifdef __ENABLE_DIGICERT_IPV6__
        MOC_IP_ADDRESS_S DESTADDR;
#else
        #define DESTADDR saDestAddr
#endif
        if (!saDestAddr) saDestAddr = dwDestAddr; /* jic - for now */
#ifdef __ENABLE_DIGICERT_IPV6__
        DESTADDR = DEREF_MOC_IPADDR(saDestAddr);
#endif
        saTest.timenow = timenow;
        saTest.pxSp = pxSp;
        saTest.iNest = iNest;
#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_IPSEC_NAT_T__)
        saTest.oSaLen = oSaLen;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        saTest.wUdpEncPort = wUdpEncPort;
#endif
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        saTest.oMode = oMode;
#endif
        saTest.saDestAddr =  saDestAddr;
        saTest.saSrcAddr  =  saSrcAddr;
        saTest.wDestPort  =  wDestPort;
        saTest.wSrcPort   =  wSrcPort;
        saTest.oProto     =  oProto;
#ifdef USE_MOC_COOKIE
        saTest.cookie     =  cookie;
#endif
#ifdef CUSTOM_IPSEC_FILTER_DSCP
        saTest.oDscp      =  oDscp;
#endif
        saTest.dwDestAddr  = dwDestAddr;
        saTest.dwSrcAddr   = dwSrcAddr ;

        saTest.pxSaRet = NULL;
        saTest.timethenRet = 0;

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        MOC_IP_ADDRESS temp_addr;
        /* Get the Outbound table key for the corresponding group */
        temp_addr = IPSEC_mapIpToKey(DESTADDR);
        GEN_OUTBND_HASH_VALUE(temp_addr, hashValue)
#else
		GEN_OUTBND_HASH_VALUE(DESTADDR, hashValue)
#endif

        RB_SYNC(m_mtxOutbnd,
        status = HASH_TABLE_findPtr(m_hashTableOutbnd, hashValue, &saTest,
                                    (funcPtrExtraMatchTest)ipsec_getSa,
                                    (void **)&pxSaRet, &isMatch) )
        if (OK > status) goto exit;

        pxSaRet = saTest.pxSaRet;
#else

        ubyte4 timethenRet = 0;

        sbyte4 i;
        for (i=0; i < m_ipsecSadbNum; i++)
        {
            ubyte4 timethen;

            SADB pxSa;
            NEXT_SA(pxSa, i)

            /* skipping SA */
            if (!(IPSEC_SA_FLAG_INUSE & pxSa->saFlags) ||
                (IPSEC_SA_FLAG_DELETED & pxSa->saFlags) ||
                IPSEC_expireSa(timenow, pxSa))
            {
                continue;
            }

            /* matching SA against SP */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (pxSa->pxSp) /* auto. keyed */
            {
#ifdef __DISABLE_IPSEC_COMP_GETSA__
                if ((pxSp != pxSa->pxSp) || (iNest != pxSa->iNest))
                    continue;
            }
            else
#else
                if (iNest != pxSa->iNest)
                    continue;

                if (pxSp != pxSa->pxSp) /* !!! */
                {
                    /* SA w/ 'compatible' (but not associated) SP may be OK
                       unless we've already found SA w/ matching associated SP
                     */
                    if (pxSaRet && (pxSp == pxSaRet->pxSp))
                        continue;
                }
            }

            if (pxSp != pxSa->pxSp) /* check only SA not associated with SP */
#endif
#endif
            {
                /* check mode & algorithms */
                if (!(
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                      ((oMode == pxSa->oSaMode) || (IPSEC_MODE_DONTCARE == pxSa->oSaMode)) &&
#endif
                      IPSEC_matchSp(NULL, pxSa, pxSp, iNest)))
                {
                    continue;
                }

                /* check endpoint IP addresses */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                if (((oSaLen - 1) == iNest) &&
                    (IPSEC_MODE_TUNNEL == oMode))
                {
                    if ((saDestAddr && !SAME_MOC_IPADDR(saDestAddr, pxSa->dwSaDestAddr)) ||
                        (saSrcAddr && !SAME_MOC_IPADDR(saSrcAddr, pxSa->dwSaSrcAddr)))
                    {
                        continue;
                    }
                }
                else
#endif
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                if (!SAME_MOC_IPADDR(saDestAddr, pxSa->dwSaDestAddr) ||
                    (!SAME_MOC_IPADDR(saSrcAddr, pxSa->dwSaSrcAddr) &&
                     !ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr)))
                {
                    continue;
                }
#else

                if (pxSa->dwSaDestAddr && pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd))
                {
                    if((0 != CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                                      REF_MOC_IPADDR(pxSa->dwSaDestIPEnd),
                                      saDestAddr, 0))||
                        (!SAME_MOC_IPADDR(saSrcAddr, pxSa->dwSaSrcAddr) &&
                         !ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr)))
                    {
                        continue;
                    }
                }
                else if (pxSa->fqdn && (pxSa->dwSaSrcIPCount|| pxSa->dwSaDestIPCount))
                {
                    if ((pxSa->dwSaSrcIPCount && checkIpinList(saSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)) ||
                            (pxSa->dwSaDestIPCount && checkIpinList(saDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount)))
                    {
                        continue;
                    }
                }
                else
                {
                    if (!SAME_MOC_IPADDR(saDestAddr, pxSa->dwSaDestAddr) ||
                        (!SAME_MOC_IPADDR(saSrcAddr, pxSa->dwSaSrcAddr) &&
                         !ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr)))
                    {
                        continue;
                    }
                }
#endif
            }

#ifdef __ENABLE_IPSEC_NAT_T__
            /* check NAT-T udp encap. port */
            if ((wUdpEncPort != pxSa->wSaUdpEncPort) &&
                (wUdpEncPort || ((oSaLen - 1) != iNest)))
            {
                continue;
            }
#endif
            /* matching SA against flow */
            if (!(((wDestPort == pxSa->wSaDestPort) || (0 == pxSa->wSaDestPort)) &&
                  ((wSrcPort == pxSa->wSaSrcPort) || (0 == pxSa->wSaSrcPort))    &&
                  ((oProto == pxSa->oSaUlp) || (0 == pxSa->oSaUlp))              &&
#ifdef USE_MOC_COOKIE
                  ((cookie == pxSa->cookie) || (0 == pxSa->cookie))              &&
#endif
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                  ((IPSEC_MODE_TRANSPORT == oMode) ||
                   (!CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                                  REF_MOC_IPADDR(pxSa->dwSaDestIPEnd),
                                  dwDestAddr, 0) &&
                    !CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaSrcIP),
                                  REF_MOC_IPADDR(pxSa->dwSaSrcIPEnd),
                                  dwSrcAddr, 0)))                                &&
#endif
                  (
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                   (IPSEC_MODE_TUNNEL == oMode) ||
#endif
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                   (SAME_MOC_IPADDR(dwDestAddr, pxSa->dwSaDestAddr) &&
                    (SAME_MOC_IPADDR(dwSrcAddr, pxSa->dwSaSrcAddr) ||
                     ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr))))
#else
                   (((((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && (!CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                                              REF_MOC_IPADDR(pxSa->dwSaDestIPEnd),
                                              dwDestAddr, 0))) ||
                   ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) || (SAME_MOC_IPADDR(dwDestAddr, pxSa->dwSaDestAddr)))) ||
                       (pxSa->fqdn[0] && pxSa->dwSaDestIPCount && (!checkIpinList(dwDestAddr, pxSa->dwSaDestIPList, pxSa->dwSaDestIPCount)))) &&
                    ((pxSa->fqdn[0] && pxSa->dwSaSrcIPCount && (!checkIpinList(dwSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount))) ||
                    SAME_MOC_IPADDR(dwSrcAddr, pxSa->dwSaSrcAddr) ||
                     ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr))))
#endif
                 ))
            {
                continue;
            }

            /* DSCP-specific filtering */
#ifdef CUSTOM_IPSEC_FILTER_DSCP
            if (pxSa->pDscpValues)
            {
                if (OK > CUSTOM_IPSEC_FILTER_DSCP(oDscp, pxSa->pDscpValues))
                    continue;
            }
#endif
            /* match found */
            if (0 == (timethen = pxSa->dwSaLastUsed))
                timethen = pxSa->dwSaEstablished;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            /* check mirrored inbound SA */
            if (pxSa->pxSp)
            {
                SADB pxSaM = pxSa->pxSaM;
                if (pxSaM && (pxSaM->dwId == pxSa->dwIdM))
                {
                    ubyte4 timethenM = pxSaM->dwSaLastUsed;
                    if (timethenM &&
                        ((timenow - timethenM) < (timenow - timethen)))
                        timethen = timethenM;
                }
            }
#endif
            /* get the most recent */
            if (pxSaRet)
            {
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_COMP_GETSA__)
                /* always choose SA w/ matching SP over SA w/ 'compatible' SP */
                if ((pxSp == pxSa->pxSp) && (pxSp != pxSaRet->pxSp) && pxSaRet->pxSp)
                    goto ret;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                /* always choose GDOI key over non-GDOI key */
                if (!(IPSEC_SA_FLAG_GDOI & pxSa->saFlags))
                {
                    if (IPSEC_SA_FLAG_GDOI & pxSaRet->saFlags)
                        continue;
                }
                else
                {
                    if (!(IPSEC_SA_FLAG_GDOI & pxSaRet->saFlags))
                        goto ret;

                    /* choose GDOI key with expiration */
                    if (!(pxSa->dwSaExpSecs || pxSa->dwSaExpKBytes))
                    {
                        if (pxSaRet->dwSaExpSecs || pxSaRet->dwSaExpKBytes)
                            continue;
                    }
                    else
                    {
                        if (!(pxSaRet->dwSaExpSecs || pxSaRet->dwSaExpKBytes))
                            goto ret;

                        /* choose older GDOI key !!! */
                        if ((timenow - pxSa->dwSaEstablished) >
                            (timenow - pxSaRet->dwSaEstablished))
                            goto ret;

                        continue;
                    }
                }
#endif
                if ((timenow - timethenRet) > (timenow - timethen))
                    goto ret;

                continue; /* !!! */
            }
ret:
            pxSaRet = pxSa;
            timethenRet = timethen;

        } /* for (i */

#endif  /* __ENABLE_RB_SADB__ */

        if (!pxSaRet) /* no match */
        {
            status = ERR_IPSEC_DROP_GETSA_FAIL;
            goto exit;
        }

        if (axSa) axSa[iNest] = pxSaRet;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (((oSaLen - 1) == iNest) &&
            (IPSEC_MODE_TUNNEL == oMode))
        {
            if (!saDestAddr && !ISZERO_MOC_IPADDR(pxSaRet->dwSaDestAddr))
                saDestAddr = REF_MOC_IPADDR(pxSaRet->dwSaDestAddr);
            if (!saSrcAddr && !ISZERO_MOC_IPADDR(pxSaRet->dwSaSrcAddr))
                saSrcAddr = REF_MOC_IPADDR(pxSaRet->dwSaSrcAddr);

            /* jic */
            if (!saDestAddr) saDestAddr = dwDestAddr;
            if (!saSrcAddr) saSrcAddr = dwSrcAddr;
        }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
        if (!wUdpEncPort && ((oSaLen - 1) == iNest))
            wUdpEncPort = pxSaRet->wSaUdpEncPort;
#endif

    } /* for (iNest */

exit:
    return status;
} /* IPSEC_getSa */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

