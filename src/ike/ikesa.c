/**
 * @file  ikesa.c
 * @brief IKE Security Association (SA) management.
 *
 * @details    IKE (ISAKMP) SA lifecycle management and state handling.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#ifdef __IKE_MULTI_THREADED__
#ifndef __IKE_SADB_MEMPOOL__
#error "Must also define __IKE_SADB_MEMPOOL____ with __IKE_MULTI_THREADED__!"
#endif
#endif
#if defined(__IKE_SADB_MALLOC__)
#ifdef __IKE_SADB_MEMPOOL__
#error "Must not define both __IKE_SADB_MALLOC__ and __IKE_SADB_MEMPOOL__!"
#endif
#include "../common/dynarray.h"
#elif defined(__IKE_SADB_MEMPOOL__)
#include "../common/mem_pool.h"
#endif
#if defined(IKE_SA_CKY_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ADDR_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ID_HASH_TABLE_SIZE_MASK)
#include "../common/hash_value.h"
#include "../common/hash_table.h"
#endif
#include "../crypto/dh.h"
#include "../crypto/crypto.h"
#include "../crypto/ca_mgmt.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../harness/harness.h"
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#if defined(__IKE_UPDATE_TIMER__) || defined(__ENABLE_IKE_FRAGMENTATION__) || defined(__ENABLE_IKE_REDIRECT__)
#include "../common/timer.h"
#endif

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"

#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_childsa.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ike_event.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"
#include "../ike/ike_cert.h"
#include "../ike/ikekey.h"
#ifdef __ENABLE_IKE_FRAGMENTATION__
#include "../ike/ike_frag.h"
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dh.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern ikeSettings m_ikeSettings;

#ifdef __IKE_UPDATE_TIMER__
extern ubyte *m_ikeTimer;
#endif

extern IKE_MUTEX g_ikeMtx;


/*------------------------------------------------------------------*/

sbyte4 m_ikeSaNum = 0;

#ifndef __IKE_SADB_MALLOC__
struct ikesa m_ikeSa[IKE_SA_MAX] = { { 0 } };

#define GET_NEXT_ELEMENT(_el, _i) _el = &(m_ikeSa[_i]);

#define GET_ELEMENT(_el, _loc) \
    if ((0 > _loc) || (_loc >= m_ikeSaNum)) goto exit;\
    _el = &(m_ikeSa[_loc]);

#ifdef __IKE_SADB_MEMPOOL__
poolHeaderDescr ikePoolHdrDescr = { NULL };

#ifdef __IKE_MULTI_THREADED__
RTOS_MUTEX m_ikePoolLock = NULL;
#define LOCK_POOL(_st)  if (OK <= (_st = RTOS_mutexWait(m_ikePoolLock)))
#define UNLOCK_POOL     RTOS_mutexRelease(m_ikePoolLock);
#else
#define LOCK_POOL(_st)
#define UNLOCK_POOL
#endif

#define PUSH_ELEMENT(_el) \
    { \
        MSTATUS st; \
        LOCK_POOL(st) \
        { \
            if (OK > (st = MEM_POOL_putPoolObject(&ikePoolHdrDescr, (void**)&_el))) \
            { \
                DEBUG_ERROR(DEBUG_IKE_MESSAGES, \
                    (sbyte *)"MEM_POOL_putPoolObject() returns error ", st); \
            } \
            UNLOCK_POOL \
        } \
    }

#define POP_ELEMENT(_el, _st) \
    LOCK_POOL(_st) \
    { \
        _st = MEM_POOL_getPoolObject(&ikePoolHdrDescr, (void **)&_el); \
        UNLOCK_POOL \
    }

#define GET_ELEMENT_LOCATOR(_el, _loc, _st) \
    _st = MEM_POOL_getIndexForObject(&ikePoolHdrDescr, _el, &_loc);

#else
#define PUSH_ELEMENT(_el)  /* nothing to be done.*/
#endif

#else

DynArray m_ikeSa = { 0 };

#define GET_NEXT_ELEMENT(_el, _i) \
    if (OK > DYNARR_Get(&m_ikeSa, _i, &(_el))) break;\
    if (NULL == _el) continue;

#define GET_ELEMENT(_el, _loc) \
    if ((OK > (status = DYNARR_Get(&m_ikeSa, _loc, &(_el)))) ||\
        (NULL == _el)) goto exit;

#define PUSH_ELEMENT(_el)  /* nothing to be done.*/

#endif /* __IKE_SADB_MALLOC__ */

static ubyte4 m_ikeSaId = 0;
static sbyte4 m_ikeSaLoc = 0; /* used by IKE_getSaById() */

#ifdef __IKE_MULTI_THREADED__
RTOS_RWLOCK m_ikeSaRwLock = NULL;
#endif


/*------------------------------------------------------------------*/

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
/* HASH: Find IKE SA based on initiator and repsponbder cookies */
static hashTableOfPtrs *m_hashTableCky = NULL;
#ifdef __IKE_MULTI_THREADED__
static RTOS_RWLOCK m_hashTableCkyLock = NULL;
#define LOCK_HASH_CKY_W     RTOS_rwLockWaitW(m_hashTableCkyLock)
#define UNLOCK_HASH_CKY_W   RTOS_rwLockReleaseW(m_hashTableCkyLock)
#define LOCK_HASH_CKY_R     RTOS_rwLockWaitR(m_hashTableCkyLock)
#define UNLOCK_HASH_CKY_R   RTOS_rwLockReleaseR(m_hashTableCkyLock)
#else
#define LOCK_HASH_CKY_W
#define UNLOCK_HASH_CKY_W
#define LOCK_HASH_CKY_R
#define UNLOCK_HASH_CKY_R
#endif
#endif

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
/* HASH: Find IKE SA based on initiator IP address */
static hashTableOfPtrs *m_hashTableAddr = NULL;
#ifdef __IKE_MULTI_THREADED__
static RTOS_RWLOCK m_hashTableAddrLock = NULL;
#define LOCK_HASH_ADDR_W    RTOS_rwLockWaitW(m_hashTableAddrLock)
#define UNLOCK_HASH_ADDR_W  RTOS_rwLockReleaseW(m_hashTableAddrLock)
#define LOCK_HASH_ADDR_R    RTOS_rwLockWaitR(m_hashTableAddrLock)
#define UNLOCK_HASH_ADDR_R  RTOS_rwLockReleaseR(m_hashTableAddrLock)
#else
#define LOCK_HASH_ADDR_W
#define UNLOCK_HASH_ADDR_W
#define LOCK_HASH_ADDR_R
#define UNLOCK_HASH_ADDR_R
#endif
#endif

#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
/* HASH: Find IKE SA based on IKE SA Identifier */
static hashTableOfPtrs *m_hashTableId = NULL;
#ifdef __IKE_MULTI_THREADED__
static RTOS_RWLOCK m_hashTableIdLock = NULL;
#define LOCK_HASH_ID_W    RTOS_rwLockWaitW(m_hashTableIdLock)
#define UNLOCK_HASH_ID_W  RTOS_rwLockReleaseW(m_hashTableIdLock)
#define LOCK_HASH_ID_R    RTOS_rwLockWaitR(m_hashTableIdLock)
#define UNLOCK_HASH_ID_R  RTOS_rwLockReleaseR(m_hashTableIdLock)
#else
#define LOCK_HASH_ID_W
#define UNLOCK_HASH_ID_W
#define LOCK_HASH_ID_R
#define UNLOCK_HASH_ID_R
#endif
#endif

#define IKE_SA_CKY_INIT_HASH_VALUE   (0xa0f2418e)
#define IKE_SA_ADDR_INIT_HASH_VALUE  (0x0641517c)
#define IKE_SA_ID_INIT_HASH_VALUE    (IKE_SA_CKY_INIT_HASH_VALUE)

#if defined(IKE_SA_CKY_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ADDR_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ID_HASH_TABLE_SIZE_MASK)
static MSTATUS HT_alloc(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement);
static MSTATUS HT_free(void *pHashCookie, hashTablePtrElement *pFreeHashElement);
#endif


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#ifdef __ENABLE_DIGICERT_HARNESS__
#define _CRYPTO_ALLOC_(_h, _d, _s) \
    if (OK > (status = CRYPTO_ALLOC(_h, _s, TRUE, (void**) &(_d)))) goto exit;
#define _CRYPTO_FREE_(_h, _d) if (_d) CRYPTO_FREE(_h, TRUE, (void**) &(_d));
#else
#define _CRYPTO_ALLOC_(_h, _d, _s)
#define _CRYPTO_FREE_(_h, _d)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_initSadb(void)
{
    MSTATUS status = OK;

    if (m_ikeSaNum) IKE_flushSadb();

    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                    (ubyte *)&m_ikeSaId, sizeof(m_ikeSaId))))
        goto exit;

    m_ikeSaId &= 0x7fffffff;
    m_ikeSaLoc = ((sbyte4)m_ikeSaId + 1) % IKE_SA_MAX;

#ifndef __IKE_SADB_MALLOC__
    m_ikeSaNum = IKE_SA_MAX;
#ifdef __IKE_SADB_MEMPOOL__
    if (OK > (status = MEM_POOL_initPool(&ikePoolHdrDescr, m_ikeSa,
                                         sizeof(m_ikeSa),
                                         (sizeof(m_ikeSa) / IKE_SA_MAX))))
        goto exit;

#ifdef __IKE_MULTI_THREADED__
    if (OK > (status = RTOS_mutexCreate(&m_ikePoolLock, IKE_MT_MUTEX, 0)))
        goto exit;
#endif
#endif /* __IKE_SADB_MEMPOOL__ */
#else
    DYNARR_Init(sizeof(struct ikesa *), &m_ikeSa);
#endif

#ifdef __IKE_MULTI_THREADED__
    if (OK > (status = RTOS_rwLockCreate(&m_ikeSaRwLock)))
        goto exit;
#endif

    /* set up hash tables */

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
#ifdef __IKE_MULTI_THREADED__
    if (OK > (status = RTOS_rwLockCreate(&m_hashTableCkyLock)))
        goto exit;
#endif
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableCky,
                                                  IKE_SA_CKY_HASH_TABLE_SIZE_MASK,
                                                  NULL, HT_alloc, HT_free)))
        goto exit;

    DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"Hash table (CKY) created.");
#endif

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
#ifdef __IKE_MULTI_THREADED__
    if (OK > (status = RTOS_rwLockCreate(&m_hashTableAddrLock)))
        goto exit;
#endif
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableAddr,
                                                  IKE_SA_ADDR_HASH_TABLE_SIZE_MASK,
                                                  NULL, HT_alloc, HT_free)))
        goto exit;

    DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"Hash table (ADDR) created.");
#endif

#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
#ifdef __IKE_MULTI_THREADED__
    if (OK > (status = RTOS_rwLockCreate(&m_hashTableIdLock)))
        goto exit;
#endif
    if (OK > (status = HASH_TABLE_createPtrsTable(&m_hashTableId,
                                                  IKE_SA_ID_HASH_TABLE_SIZE_MASK,
                                                  NULL, HT_alloc, HT_free)))
        goto exit;

    DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"Hash table (ID) created.");
#endif

exit:
    return status;
} /* IKE_initSadb */


/*------------------------------------------------------------------*/

extern intBoolean
IKE_checkExpSa(ubyte4 timenow, IKESA pxSa)
{
    intBoolean status = FALSE;
    intBoolean bIKEv2 = IS_IKE2_SA(pxSa);
    MSTATUS merror = OK;

    if ((bIKEv2 && IS_IKE2_SA_AUTHED(pxSa)) ||
        (!bIKEv2 && IS_IKE_SA_AUTHED(pxSa))) /* IKE_SA authenticated */
    {
        /* lifetimes seconds */
        if (pxSa->dwExpSecs && ((ubyte4)(1000 * pxSa->dwExpSecs) < (timenow - pxSa->dwTimeCreated)))
        {
            merror = STATUS_IKE_LIFETIME_SECONDS;
            status = TRUE;
        }

        else
        /* lifetime kbytes */
        if (pxSa->dwExpKBytes && (pxSa->dwExpKBytes <= pxSa->dwCurKBytes))
        {
            merror = STATUS_IKE_LIFETIME_KBYTES;
            status = TRUE;
        }

        else
        /* Repeated Auth (rfc4478) */
        if (bIKEv2 && !(IKE_SA_FLAG_ORIG_INITR & pxSa->flags) && /* original responder */
            (pxSa->u.v2.dwExpAuthSecs &&
             ((ubyte4)(1000 * pxSa->u.v2.dwExpAuthSecs) < (timenow - pxSa->u.v2.dwTimeAuthed))))
        {
            merror = STATUS_IKE_LIFETIME_REAUTH;
            status = TRUE;
        }
    }
    else /* still in progress */
    {
        if ((ubyte4)(1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation) < (timenow - pxSa->dwTimeStart))
        {
            merror = ERR_IKE_TIMEOUT;
            status = TRUE;
        }
    }

    if (status) /* expired!!! */
    {
        if (bIKEv2)
        {
            if (!pxSa->merror) pxSa->merror = merror;
        }
        else
        {
            IKE_delSa(pxSa, FALSE, merror);
        }
    }

    return status;
} /* IKE_checkExpSa */


/*------------------------------------------------------------------*/

static MSTATUS
FlushSa(IKESA pxSa)
{
    MSTATUS status = OK;

    if (IKE_SA_FLAG_INUSE & pxSa->flags)
    {
        if (!(IKE_SA_FLAG_DELETED & pxSa->flags))
        {
            /* Note: IKE?_delSa() does not remove pxSa from hashtables! */
            if (IS_IKE2_SA(pxSa))
            {
                status = IKE2_delSa(pxSa, TRUE, OK);

                if (IKE_SA_FLAG_DELETING & pxSa->flags)
                    status = IKE2_delSa(pxSa, FALSE, OK);
            }
            else
            {
                ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                if (!IKE_checkExpSa(timenow, pxSa))
                    status = IKE_delSa(pxSa, TRUE, OK);
            }
        }
#ifndef __IKE_SADB_MALLOC__
        DIGI_MEMSET((ubyte *)pxSa, 0x00, sizeof(struct ikesa));
#endif
    }
#ifdef __IKE_SADB_MALLOC__
    FREE(pxSa);
#endif

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_delSa: error encountered ", status);
    }
#endif
    return status;
} /* FlushSa */


/*------------------------------------------------------------------*/

#if defined(IKE_SA_CKY_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ADDR_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ID_HASH_TABLE_SIZE_MASK)

static MSTATUS
HT_flushsa(void *pAppData)
{
    if (NULL == pAppData)
    {
        goto exit;
    }

    FlushSa((IKESA)pAppData);

exit:
    /* This function is called within the context of an interator, so
     * returning error will stop processing the iterator; we don't want to
     * stop iterating so always return OK
     */
    return OK;
} /* HT_flushsa */

static MSTATUS
HT_DelPeerEntrysa(void *pAppData, void *cookie)
{
    MSTATUS status = OK;
    IKESA pxSa = (IKESA)pAppData;
    ikePeerConfig* config = (ikePeerConfig *)cookie;

    if ((NULL == pxSa) || (NULL == config))
    {
        goto exit;
    }
    if (pxSa->ikePeerConfig == config)
    {
        if (IS_VALID(pxSa))
        {
            if (IS_IKE2_SA(pxSa))
            {
                status = IKE2_delSa(pxSa, TRUE, OK);

                if (IKE_SA_FLAG_DELETING & pxSa->flags)
                    status = IKE2_delSa(pxSa, FALSE, OK);
            }
            else
            {
                ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                if (!IKE_checkExpSa(timenow, pxSa))
                    status = IKE_delSa(pxSa, TRUE, OK);
            }
        }
        pxSa->ikePeerConfig = NULL;
    }

exit:
    /* This function is called within the context of an interator, so
     * returning error will stop processing the iterator; we don't want to
     * stop iterating so always return OK
     */
    return OK;
} /* HT_flushsa */

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_flushSadb(void)
{
    MSTATUS status = OK;

    sbyte4 i;

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    if (m_hashTableCky)
    {
        HASH_TABLE_traversePtrTable(m_hashTableCky, HT_flushsa);
    }
    else
#endif
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    if (m_hashTableAddr)
    {
        HASH_TABLE_traversePtrTable(m_hashTableAddr, HT_flushsa);
    }
    else
#endif
#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
    if (m_hashTableId)
    {
        HASH_TABLE_traversePtrTable(m_hashTableId, HT_flushsa);
    }
    else
#endif
    for (i=0; i < m_ikeSaNum; i++)
    {
        IKESA pxSa;
        GET_NEXT_ELEMENT(pxSa, i)

        status = FlushSa(pxSa);
    }

#ifdef __IKE_SADB_MALLOC__
    DYNARR_Uninit(&m_ikeSa);
#else
#if defined(__IKE_SADB_MEMPOOL__) && defined(__IKE_MULTI_THREADED__)
    if (m_ikePoolLock)
    {
        RTOS_mutexFree(&m_ikePoolLock);
        m_ikePoolLock = NULL;
    }
#endif
#endif
    m_ikeSaNum = 0;

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    if (m_hashTableCky)
    {
        HASH_TABLE_removePtrsTable(m_hashTableCky, NULL);
        m_hashTableCky = NULL;
    }
#ifdef __IKE_MULTI_THREADED__
    if (m_hashTableCkyLock)
    {
        RTOS_rwLockFree(&m_hashTableCkyLock);
        m_hashTableCkyLock = NULL;
    }
#endif
#endif

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    if (m_hashTableAddr)
    {
        HASH_TABLE_removePtrsTable(m_hashTableAddr, NULL);
        m_hashTableAddr = NULL;
    }
#ifdef __IKE_MULTI_THREADED__
    if (m_hashTableAddrLock)
    {
        RTOS_rwLockFree(&m_hashTableAddrLock);
        m_hashTableAddrLock = NULL;
    }
#endif
#endif

#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
    if (m_hashTableId)
    {
        HASH_TABLE_removePtrsTable(m_hashTableId, NULL);
        m_hashTableId = NULL;
    }
#ifdef __IKE_MULTI_THREADED__
    if (m_hashTableIdLock)
    {
        RTOS_rwLockFree(&m_hashTableIdLock);
        m_hashTableIdLock = NULL;
    }
#endif
#endif

#ifdef __IKE_MULTI_THREADED__
    if (m_ikeSaRwLock)
    {
        RTOS_rwLockFree(&m_ikeSaRwLock);
        m_ikeSaRwLock = NULL;
    }
#endif

    return status;
} /* IKE_flushSadb */


extern MSTATUS
IKEDelPeerEntrySadb(ikePeerConfig* config)
{
    MSTATUS status = OK;

    sbyte4 i;
    IKESA pxSa = NULL;

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    if (m_hashTableCky)
    {
        HASH_TABLE_traversePtrTableExt(m_hashTableCky, (void *)config,  HT_DelPeerEntrysa);
    }
    else
#endif
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    if (m_hashTableAddr)
    {
        HASH_TABLE_traversePtrTableExt(m_hashTableAddr, (void *)config,  HT_DelPeerEntrysa);
    }
    else
#endif
#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
    if (m_hashTableId)
    {
        HASH_TABLE_traversePtrTableExt(m_hashTableId, (void *)config,  HT_DelPeerEntrysa);
    }
    else
#endif
    for (i=0; i < m_ikeSaNum; i++)
    {
        GET_NEXT_ELEMENT(pxSa, i)

        if (pxSa && pxSa->ikePeerConfig == config)
        {
            if (IS_VALID(pxSa))
            {
                if (IS_IKE2_SA(pxSa))
                {
                    status = IKE2_delSa(pxSa, TRUE, OK);

                    if (IKE_SA_FLAG_DELETING & pxSa->flags)
                        status = IKE2_delSa(pxSa, FALSE, OK);
                }
                else
                {
                    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                    if (!IKE_checkExpSa(timenow, pxSa))
                        status = IKE_delSa(pxSa, TRUE, OK);
                }
            }
            pxSa->ikePeerConfig = NULL;
        }

    }
    return status;
}
/*------------------------------------------------------------------*/

static intBoolean
HasNoChild(IKESA pxSa)
{
    intBoolean bRet = TRUE;

    sbyte4 i;
    for (i=0; i < IKE_P2_MAX; i++)
    {
        P2XG pxXg = &(pxSa->u.v1.p2Xg[i]);

        /* check if there's any ongoing phase 2 exchanges */
        if (IS_VALID_XCHG(pxXg))
        {
            bRet = FALSE; /* yes */
            break;
        }
    }

    return bRet;
} /* HasNoChild */


/*------------------------------------------------------------------*/

#ifndef __IKE_UPDATE_TIMER__

#ifdef __IKE_MULTI_THREADED__
extern sbyte4
IKE_dpcUpdateSa(IKE_DPC_STATE_CB us, ubyte4 usSize)
{
    MSTATUS status = OK;

    if ((sizeof(struct dpcStateCB) <= usSize) &&
        (sizeof(struct dpcStateCB) == us->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE_dpcUpdateSa == us->hdr.dpc_func) &&
        us->data /* jic */)
    {
        if (1 == us->version)
            status = IKE_updateSa((IKESA) us->data);
        else if (2 == us->version)
            status = IKE2_updateSa((IKESA) us->data);
    }
    return (sbyte4)status;
} /* IKE_dpcStateCallback */
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_updateSa(IKESA pxSa)
{
    MSTATUS status = OK;

    sbyte4 j;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 timewaitRetx = m_ikeSettings.ikeWaitRetransmit;

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bKeepalive;
#endif

    IKE_LOCK_R;

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!IS_VALID(pxSa) || IS_IKE2_SA(pxSa))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcStateCB);
            struct dpcStateCB us;
            us.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcUpdateSa;
            us.hdr.dpc_len = (ubyte2)size;
            us.version = 1;
            us.data = pxSa;
            status = (MSTATUS)
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid, (ubyte *)&us, size);
        }
        else
        {
            status = ERR_IKE_CONFIG;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

        if (!IKE_checkExpSa(timenow, pxSa))
        {
            intBoolean bFinalState = IS_P1_FINAL_STATE(pxSa->oState);
            intBoolean bRetransmit = TRUE;

            ubyte4 timeidled = timenow - pxSa->dwTimeStamp;
            ubyte4 timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;
            ubyte4 timeoutDpd = 0;

            if (bFinalState)
            {
                /* already rekeyed? */
                if ((IKE_SA_FLAG_REKEYED & pxSa->flags) &&
                    HasNoChild(pxSa))
                {
                    IKE_delSa(pxSa, TRUE, STATUS_IKE_REKEY); /* yes, delete it */
                    goto exit;
                }

                /* re-transmit final phase 1 message? */
                if (IS_MATURE(pxSa)) bRetransmit = FALSE;
                else
#ifdef __ENABLE_IKE_XAUTH__
                if (!(IKE_SA_FLAG_XAUTH & pxSa->flags))
#endif
                {
                    if (timeout < (timenow - pxSa->dwTimeStart))
                    {
                        /* may do redundant work here, but OK */
                        IKE_finalizeSa(pxSa, timenow);
                        bRetransmit = FALSE;
                    }
                }
            }
            else
            {
                if (STATUS_IKE_PENDING == pxSa->merror) /* !!! */
                {
                    goto exit;
                }
            }

            if (bRetransmit && (timewaitRetx <= timeidled))
            {
                struct ike_context ctx = { NULL };
                ctx.pxSa = pxSa;
                --(pxSa->oState); /* go back to previous state */

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                if (STATE_AGGR_I2c == pxSa->oState) /* special case */
                    --(pxSa->oState);               /* skip COMMIT state */
#endif
#ifdef __ENABLE_IKE_FRAGMENTATION__
                if (IKE_SA_FLAG_FRAGMENTATION & pxSa->flags)
                {
                    if (0 != pxSa->reassemblyTimerId)
                    {
                        TIMER_checkTimer(pxSa->reassemblyTimerId);
                    }
                }

                ctx.u.v1.bIsRtx = TRUE;
#endif
                if (OK > IKE_xchgOut(&ctx))
                    goto exit;
            }

            if (!bFinalState) goto exit;

            /* traverse pending phase 2 negotiations */
            for (j=0; j < IKE_P2_MAX; j++)
            {
                P2XG pxXg = &(pxSa->u.v1.p2Xg[j]);

                if (IS_VALID_XCHG(pxXg))
                {
                    /* check timeout */
                    if (timeout < abs((sbyte4) timenow - (sbyte4) pxXg->dwTimeStart)) /* expired */
                    {
                        IKE_delXchg(pxXg, pxSa, ERR_IKE_TIMEOUT); /* delete it */
                        continue;
                    }

                    if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags) /* !!! */
                        continue;

                    /* re-transmission */
                    if (timewaitRetx <= abs((sbyte4) timenow - (sbyte4) pxXg->dwTimeStamp))
                    {
                        struct ike_context ctx = { NULL };

                        if (IS_QUICK_MODE_STATE(pxXg->oState))
                        {
                            IPSECSA pxIPsecSa = P2XG_IPSECSA(pxXg);

                            if (IKE_CHILD_FLAG_DELETED & pxIPsecSa->c_flags) /* jic */
                            {
                                /* quick mode exchange already deleted (e.g. "ike_event.c") */
                                IKE_delXchg(pxXg, pxSa, OK);
                                continue;
                            }

                            if (STATE_QUICK_I == pxXg->oState) /* special case */
                                --(pxXg->oState);              /* skip COMMIT state */
                            --(pxXg->oState); /* go back to previous state */

                            if (!IS_P2_FINAL_STATE(pxIPsecSa->oState)) /* !!! */
                                pxIPsecSa->oState = pxXg->oState;
                        }
                        else /* IKECFG */
                        {
                            if (!IS_XCHG_INITIATOR(pxXg) && pxXg->dwTimeStamp)
                                goto exit; /* for responder, re-transmit only if necessary */

                            --(pxXg->oState);
                        }

                        ctx.pxP2Xg = pxXg;
                        ctx.pxSa = pxSa;
#ifdef __ENABLE_IKE_FRAGMENTATION__
                        ctx.u.v1.bIsRtx = TRUE;
#endif
                        IKE_xchgOut(&ctx);
                    }
                }
            } /* for */

#ifdef __ENABLE_IKE_XAUTH__
            if (IKE_SA_FLAG_XAUTH & pxSa->flags)
                goto exit;
#endif
            if (IKE_SA_FLAG_REKEYED & pxSa->flags)
                goto exit;

#ifdef __ENABLE_IPSEC_NAT_T__
            bKeepalive = m_ikeSettings.ikeIntervalKeepalive &&
                         ((timenow - pxSa->dwTimeStampOut) > (ubyte4)
                          (1000 * m_ikeSettings.ikeIntervalKeepalive));

            /* send NAT-T Keepalive's */
            if (bKeepalive && IS_HOST_BEHIND_NAT(pxSa))
            {
                if (m_ikeSettings.funcPtrIkeXchgSend) /* jic */
                {
                    ubyte b = 0xFF;
                    m_ikeSettings.
                        funcPtrIkeXchgSend(REF_MOC_IPADDR(pxSa->dwPeerAddr), pxSa->wPeerPort,
                                           (ubyte *)&b, sizeof(ubyte)
                                           MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                                           TRUE);
                    pxSa->dwTimeStampOut = timenow;
                }
            }
#endif
            /* DPD */
            if (pxSa->u.v1.dwDpdSeqNo) /* DPD is supported by peer */
            {
                ubyte4 timestart = pxSa->u.v1.dwDpdTimeStart;
                ubyte4 dwSeqNo = pxSa->u.v1.dwDpdSeqNo;
#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
                if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeoutDpd,
                                    REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                    0, IS_INITIATOR(pxSa)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
                    timeoutDpd = 1000 * timeoutDpd;
                else
#endif
                    timeoutDpd = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;

                if (!timeoutDpd || /* passive */
                    (timeoutDpd >= timeidled)) /* not quite the time yet */
                    goto exit_dpd;

                if (timestart)
                {
                    if ((timenow - timestart) <= timeout) /* in progress */
                    {
                        if ((timenow - pxSa->u.v1.dwDpdTimeStamp) < timewaitRetx)
                            goto exit_dpd; /* wait */

                        /* will re-transmit DPD msg */
                        dwSeqNo--;
                    }
                    else if (!(pxSa->flags & IKE_SA_FLAG_DPD))
                    {
                        /* dead peer detected */
                        pxSa->flags |= IKE_SA_FLAG_DPD;

                        /* TODO - SHOULD assume its peer to be unreachable and
                           delete IPSec and IKE SAs to the peer (RFC3706 5.4)
                         */
                        if (m_ikeSettings.funcPtrIkeStatHdlr)
                            m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_DPD,
                                                    pxSa->dwId, pxSa, NULL);

                        goto exit_dpd;
                    }
                    else /* already dead */
                    {
                        ubyte4 timewait = timeoutDpd + (ubyte4)
                                          ((timeidled - timeoutDpd) / 5);
                        if ((ubyte4)1800000 < timewait)
                            timewait = (ubyte4)1800000; /* max 30 mins */

                        if ((timenow - timestart) < timewait)
                            goto exit_dpd; /* wait */

                        /* will start DPD again */
                    }
                }

                /* send DPD informational exchange message */
                {
                    struct ike_info_notify notifyInfo = { PROTO_ISAKMP, R_U_THERE, 0, 0, NULL, 0, NULL };
                    struct ike_info info = { NULL };
                    struct ike_context ctx = { NULL };

                    SET_HTONL_1(dwSeqNo);

                    notifyInfo.wDataLen = (ubyte2) sizeof(ubyte4);
                    notifyInfo.poData = (ubyte *) &dwSeqNo;
                    notifyInfo.oSpiSize = IKE_P1_SPI_SIZE;
                    info.pxNotify = &notifyInfo;

                    ctx.pxInfo = &info;
                    ctx.pxSa = pxSa;

                    if (OK > IKE_xchgOut(&ctx))
                        goto exit_dpd;

                    pxSa->u.v1.dwDpdTimeStamp = timenow;

                    if (!timestart || ((timenow - timestart) > timeout))
                    {
                        /* not a re-transmit */
                        if (0 == ++(pxSa->u.v1.dwDpdSeqNo))
                            pxSa->u.v1.dwDpdSeqNo = 1; /* jic */

                        pxSa->u.v1.dwDpdTimeStart = timenow;
                    }
                }
            } /* End of DPD */
exit_dpd:

            /* auto. rekeying */
            if (IS_INITIATOR(pxSa) && IS_MATURE(pxSa) && /* initiator, mature */
                !(IKE_SA_FLAG_REKEYED & pxSa->flags)) /* not rekeyed */
            {
                ubyte4 warning;

                IKESA pxSaRekey = pxSa->pxSaRekey;
                if (pxSaRekey)
                {
#ifdef __IKE_MULTI_THREADED__
                    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
                    if (IS_VALID(pxSaRekey) &&
                        (pxSaRekey->dwId == pxSa->dwSaRekeyId))
                    {
                        /* old or being rekeyed */
#ifdef __IKE_MULTI_THREADED__
                        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
                        goto exit;
                    }
                }
#ifdef __IKE_MULTI_THREADED__
                RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

                if ((timeoutDpd && (timeidled > timeoutDpd)) ||
                    ((pxSa->dwTimeStamp - pxSa->dwTimeStart) < timeout))
                {
                    /* idle or no interesting activity */
                    goto exit;
                }

                if (pxSa->dwExpSecs)
                {
                    ubyte4 timeexp = 1000 * pxSa->dwExpSecs;
                    ubyte4 timedlt = timenow - pxSa->dwTimeCreated;

                    warning = timeout;

                    if ((timedlt > (ubyte4)(timeexp/2)) && /* old enough */
                        (timeexp < (timedlt + warning))) /* expiring soon */
                    {
                        goto rekey;
                    }
#ifdef __ENABLE_SAMSUNG_CAC__
                    else
                    {
                        /* get the cac pin 1 min before rekeying */
                        ubyte4 warning_cacPin = warning + 60000;

                        if ((timedlt > (ubyte4)(timeexp/2)) && /* old enough */
                            (timeexp < (timedlt + warning_cacPin)) &&
                            m_ikeSettings.funcPtrIkeStatHdlr)
                        {
                            m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_CACPIN,
                                                             pxSa->dwId, pxSa, NULL);
                        }
                    }
#endif
                }

                if (pxSa->dwExpKBytes)
                {
                    warning = 6; /* 6K - FOR NOW */
                    if ((pxSa->dwCurKBytes > (ubyte4)(pxSa->dwExpKBytes/2)) && /* old enough */
                        ((pxSa->dwExpKBytes < (pxSa->dwCurKBytes + warning)) || /* expiring soon */
                         (pxSa->dwCurKBytes > (pxSa->dwCurKBytes + warning)))) /* jic KBytes wraps back to 0 */
                    {
                        goto rekey;
                    }
                }

                goto exit;
rekey:
                /* new IKE SA for phase 1 exchange */
                if (NULL != (pxSaRekey = IKE_newSa(pxSa->ikePeerConfig, REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                            pxSa->wPeerPort, NULL
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                                          , ((STATE_AGGR_I == pxSa->oState)
                                            ? ISAKMP_XCHG_AGGR : ISAKMP_XCHG_IDPROT)
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                                          , ((IKE_SA_FLAG_GDOI & pxSa->flags) ? TRUE : FALSE)
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                                          , USE_NATT_PORT(pxSa)
#endif
                                            MOC_MTHM_VALUE(pxSa->serverInstance))))
                {
                    struct ike_context ctx = { NULL };
                    ctx.pxSa = pxSaRekey;

                    if (OK <= (status = IKE_xchgOut(&ctx)))
                    {
                        /* rekeying */
                        pxSa->pxSaRekey = pxSaRekey;
                        pxSa->dwSaRekeyId = pxSaRekey->dwId;

                    }
                }
            } /* END of auto. rekeying */

        }

exit:
    IKE_UNLOCK_R;
    return status;
} /* IKE_updateSa */


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
 be included in the API documentation.
 */
extern MSTATUS
IKE_updateSadb(void)
{
    MSTATUS status = OK;

    sbyte4 i;
    for (i=0; i < m_ikeSaNum; i++)
    {
        IKESA pxSa;
        GET_NEXT_ELEMENT(pxSa, i)

        status = IKE_updateSa(pxSa);
    }

    return status;
} /* IKE_updateSadb */

#endif /* !__IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

extern IKESA
IKE_enumSa(IKESA pxSa, sbyte4 serverInstance)
{
    sbyte4 i=0;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
#endif

    if (pxSa)
    {
        i = pxSa->loc + 1;
        pxSa = NULL;
        if (0 > i) goto exit; /* jic */
    }

    for (; i < m_ikeSaNum; i++, pxSa = NULL)
    {
        GET_NEXT_ELEMENT(pxSa, i)

        if (IS_VALID(pxSa))
#ifdef __IKE_MULTI_HOMING__
        if ((0 == serverInstance) ||
            (serverInstance == pxSa->serverInstance))
#endif
        {
            break; /* found */
        }
    }

exit:
    return pxSa;
} /* IKE_enumSa */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_keyFlush(void)
{
    MSTATUS status = OK;
    IKESA pxSa = NULL;

    IKE_LOCK_W; /* !!! */

    while (NULL != (pxSa = IKE_enumSa(pxSa, 0)))
    {
        if (IS_IKE2_SA(pxSa))
            status = IKE2_delSa(pxSa, TRUE, OK);
        else
            status = IKE_delSa(pxSa, TRUE, OK);
    }

    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_keyFlush */


/*------------------------------------------------------------------*/

typedef struct ikesa_kd_test
{
    ubyte2 wPeerPort;
#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bDelNattPeer;
#endif
} *IKESA_KD_TEST;


static MSTATUS
MatchKeyDelete(IKESA pxSa, void *pData, intBoolean *pIsMatch)
{
#define pTest ((IKESA_KD_TEST)pData)
    MSTATUS status = OK;

#ifdef __ENABLE_IPSEC_NAT_T__
    if (pTest->bDelNattPeer || !IS_PEER_BEHIND_NAT(pxSa))
#endif
    if (!pTest->wPeerPort || (pTest->wPeerPort == pxSa->wPeerPort))
    {
        if (IS_IKE2_SA(pxSa))
            /*status = */IKE2_delSa(pxSa, TRUE, OK);
        else
            /*status = */IKE_delSa(pxSa, TRUE, OK);
    }

    *pIsMatch = FALSE; /* find next! */

    return status;
#undef pTest
} /* MatchKeyDelete */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_keyDelete(MOC_IP_ADDRESS peerAddr, sbyte4 serverInstance,
              ubyte2 wPeerPort, intBoolean bDelNattPeer)
{
    MSTATUS status;

    struct ikesa_kd_test saTest;
    saTest.wPeerPort = wPeerPort;
#ifdef __ENABLE_IPSEC_NAT_T__
    saTest.bDelNattPeer = bDelNattPeer;
#endif
    IKE_LOCK_W; /* !!! */

    status = IKE_getSaByAddr(peerAddr, NULL,
                             &saTest, MatchKeyDelete
                             MOC_MTHM_VALUE(serverInstance));

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
#endif
#ifndef __ENABLE_IPSEC_NAT_T__
    MOC_UNUSED(bDelNattPeer);
#endif
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_keyDelete */


/*------------------------------------------------------------------*/

#if defined(IKE_SA_CKY_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ADDR_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ID_HASH_TABLE_SIZE_MASK)

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

#endif /* defined(IKE_SA_CKY_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ADDR_HASH_TABLE_SIZE_MASK) || defined(IKE_SA_ID_HASH_TABLE_SIZE_MASK) */


/*------------------------------------------------------------------*/

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK

extern void
IKE_delSaCkyIndex(IKESA pxSa)
{
    ubyte4 hashValue;
    intBoolean isFound;

    HASH_VALUE_hashGen(pxSa->poCky_I, IKE_COOKIE_SIZE,
                       IKE_SA_CKY_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                     | pxSa->serverInstance
#endif
                     , &hashValue);

    LOCK_HASH_CKY_W;
    if (m_hashTableCky)
    {
        HASH_TABLE_deletePtr(m_hashTableCky, hashValue, pxSa,
                             HT_check, (void **)&pxSa, &isFound);
    }
    UNLOCK_HASH_CKY_W;

    return;
} /* IKE_delSaCkyIndex */


/*------------------------------------------------------------------*/

extern void
IKE_addSaCkyIndex(IKESA pxSa)
{
    MSTATUS status;
    ubyte4 hashValue;

    HASH_VALUE_hashGen(pxSa->poCky_I, IKE_COOKIE_SIZE,
                       IKE_SA_CKY_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                     | pxSa->serverInstance
#endif
                     , &hashValue);

    LOCK_HASH_CKY_W;
    if (m_hashTableCky)
    {
        if (OK > (status = HASH_TABLE_addPtr(m_hashTableCky,
                                             hashValue, pxSa)))
        {
#ifdef __ENABLE_ALL_DEBUGGING__
            DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_addSaCkyIndex: HASH_TABLE_addPtr(CKY) returns error ", status);
#else
            DIGICERT_log(MOCANA_IKE, LS_MINOR, (sbyte *)"Cannot add to hash table (CKY).");
#endif
            HASH_TABLE_removePtrsTable(m_hashTableCky, NULL);
            m_hashTableCky = NULL;
        }
    }
    UNLOCK_HASH_CKY_W;

    return;
} /* IKE_addSaCkyIndex */

#endif /* IKE_SA_CKY_HASH_TABLE_SIZE_MASK */


/*------------------------------------------------------------------*/

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK

extern void
IKE_delSaAddrIndex(IKESA pxSa)
{
    ubyte4 hashValue;
    intBoolean isFound;

    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == peerAddr->family)
        HASH_VALUE_hashGen(GET_MOC_IPADDR6(peerAddr), 16,
                           IKE_SA_ADDR_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                         | pxSa->serverInstance
#endif
                         , &hashValue);
    else
#endif
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);
        HASH_VALUE_hashWord(&dwPeerAddr, 1,
                            IKE_SA_ADDR_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                          | pxSa->serverInstance
#endif
                          , &hashValue);
    }

    LOCK_HASH_ADDR_W;
    if (m_hashTableAddr)
    {
        HASH_TABLE_deletePtr(m_hashTableAddr, hashValue, pxSa,
                             HT_check, (void **)&pxSa, &isFound);
    }
    UNLOCK_HASH_ADDR_W;

    return;
} /* IKE_delSaAddrIndex */


/*------------------------------------------------------------------*/

extern void
IKE_addSaAddrIndex(IKESA pxSa)
{
    MSTATUS status;
    ubyte4 hashValue;

    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == peerAddr->family)
        HASH_VALUE_hashGen(GET_MOC_IPADDR6(peerAddr), 16,
                           IKE_SA_ADDR_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                         | pxSa->serverInstance
#endif
                         , &hashValue);
    else
#endif
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);
        HASH_VALUE_hashWord(&dwPeerAddr, 1,
                            IKE_SA_ADDR_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                          | pxSa->serverInstance
#endif
                          , &hashValue);
    }

    LOCK_HASH_ADDR_W;
    if (m_hashTableAddr)
    {
        if (OK > (status = HASH_TABLE_addPtr(m_hashTableAddr,
                                             hashValue, pxSa)))
        {
#ifdef __ENABLE_ALL_DEBUGGING__
            DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_addSaAddrIndex: HASH_TABLE_addPtr(ADDR) returns error ", status);
#else
            DIGICERT_log(MOCANA_IKE, LS_MINOR, (sbyte *)"Cannot add to hash table (ADDR).");
#endif
            HASH_TABLE_removePtrsTable(m_hashTableAddr, NULL);
            m_hashTableAddr = NULL;
        }
    }
    UNLOCK_HASH_ADDR_W;

    return;
} /* IKE_addSaAddrIndex */

#endif /* IKE_SA_ADDR_HASH_TABLE_SIZE_MASK */


/*------------------------------------------------------------------*/

#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK

extern void
IKE_delSaIdIndex(IKESA pxSa)
{
    ubyte4 hashValue;
    intBoolean isFound;

    HASH_VALUE_hashGen(&pxSa->dwId, sizeof(pxSa->dwId),
                       IKE_SA_ID_INIT_HASH_VALUE, &hashValue);

    LOCK_HASH_ID_W;
    if (m_hashTableId)
    {
        HASH_TABLE_deletePtr(m_hashTableId, hashValue, pxSa,
                             HT_check, (void **)&pxSa, &isFound);
    }
    UNLOCK_HASH_ID_W;

    return;
} /* IKE_delSaIdIndex */


/*------------------------------------------------------------------*/

extern void
IKE_addSaIdIndex(IKESA pxSa)
{
    MSTATUS status;
    ubyte4 hashValue;

    HASH_VALUE_hashGen(&pxSa->dwId, sizeof(pxSa->dwId),
                       IKE_SA_ID_INIT_HASH_VALUE, &hashValue);

    LOCK_HASH_ID_W;
    if (m_hashTableId)
    {
        if (OK > (status = HASH_TABLE_addPtr(m_hashTableId,
                                             hashValue, pxSa)))
        {
#ifdef __ENABLE_ALL_DEBUGGING__
            DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_addSaIdIndex: HASH_TABLE_addPtr(ID) returns error ", status);
#else
            DIGICERT_log(MOCANA_IKE, LS_MINOR, (sbyte *)"Cannot add to hash table (ID).");
#endif
            HASH_TABLE_removePtrsTable(m_hashTableId, NULL);
            m_hashTableId = NULL;
        }
    }
    UNLOCK_HASH_ID_W;

    return;
} /* IKE_addSaIdIndex */

#endif /* IKE_SA_ID_HASH_TABLE_SIZE_MASK */


/*------------------------------------------------------------------*/

#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)

extern MSTATUS
IKE_customDhGroups(ubyte2 **ppwGroups, sbyte4 *num, intBoolean bInitiator,
                   IKESA pxSa, IKESA pxSa0)
{
    MSTATUS status = OK;

    ubyte2 *pwDhGrps = NULL;
    sbyte4 numDhGrps = IKE_DH_MAX;

    sbyte4 i, j;

    *ppwGroups = NULL;
    *num = 0;

    if (NULL == pxSa0)
    {
#ifndef CUSTOM_IKE_GET_P1_DHGRP
        goto exit;
#else
        if (NULL == pxSa)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
#endif
    }
    else /* CHILD_SA or [v2] REKEY_SA */
    {
        if(NULL == pxSa)   /* CHILD_SA */
        {
#ifndef CUSTOM_IKE_GET_P2_PFS
        goto exit;
#endif
        } else    /* REKEY SA */
        {
#ifndef CUSTOM_IKE_GET_P1_DHGRP
            goto exit;
#endif
        }
    }

    if (NULL == (pwDhGrps = (ubyte2 *) MALLOC(IKE_DH_MAX * sizeof(ubyte2))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pwDhGrps, 0x00, IKE_DH_MAX * sizeof(ubyte2));

    if (NULL == pxSa0)
    {
#ifdef CUSTOM_IKE_GET_P1_DHGRP
        if (OK > CUSTOM_IKE_GET_P1_DHGRP(pwDhGrps, &numDhGrps,
                                    REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                    (IS_IKE2_SA(pxSa) ? 2 : 1), bInitiator
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
            goto exit;
#endif
    }
    else
    {
#ifdef CUSTOM_IKE_GET_P2_PFS
        if (OK > CUSTOM_IKE_GET_P2_PFS(pwDhGrps, &numDhGrps,
                                    REF_MOC_IPADDR(pxSa0->dwPeerAddr),
                                    (IS_IKE2_SA(pxSa0) ? 2 : 1), bInitiator
                                    MOC_MTHM_REQ_VALUE(pxSa0->serverInstance)))
            goto exit;
#endif
    }

    /* double-check valid DH groups */
    for (i=0; i < numDhGrps && (IKE_DH_MAX > i); i++)
    {
        ubyte2 wDhGrp = pwDhGrps[i];

        if (NULL != pxSa0)
        {
#ifdef CUSTOM_IKE_GET_P2_PFS
            if (OAKLEY_GROUP_DEFAULT == wDhGrp)
            {
                /* use parent IKE_SA's DH group */
                pwDhGrps[(*num)++] = (IS_IKE2_SA(pxSa0) ? pxSa0->wDhGrp :
                            pxSa0->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION]);
                continue;
            }

            if ((NULL != pxSa) && (0 == wDhGrp)) /* [v2] IKE_SA rekeying */
            {
                /* PFS is required; see [RFC7296][RFC5996] 1.3.2 */
                pwDhGrps[(*num)++] = pxSa0->wDhGrp; /* use parent DH group */
                continue;
            }

            if (NULL != IKE_dhGroupEx(pxSa0->ikePeerConfig, wDhGrp))
                pwDhGrps[(*num)++] = wDhGrp;
#endif
        }
        else
        {
#ifdef CUSTOM_IKE_GET_P1_DHGRP
            if (0 == wDhGrp)
            {
                /* use any DH group */
                for (i=0; (IKE_DH_MAX > *num); i++)
                {
                    IKE_dhGroupInfo *pGroup = IKE_getDhGroupEx(pxSa->ikePeerConfig, i);
                    if (NULL == pGroup) break;

                    if (pGroup->wTfmId)
                        pwDhGrps[(*num)++] = pGroup->wTfmId;
                }
                break;
            }

            if (NULL != IKE_dhGroupEx(pxSa->ikePeerConfig, wDhGrp))
                pwDhGrps[(*num)++] = wDhGrp;
#endif
        }
    } /* for */

    if (0 >= (numDhGrps = *num))
    {
        status = ERR_IKE_MISMATCH_DH_GROUP;
        goto exit;
    }

    /* remove duplicates */
    for (i = numDhGrps - 1; i > 0; i--)
    {
        ubyte2 wDhGrp = pwDhGrps[i];

        for (j=0; j < i; j++)
        {
            if (wDhGrp == pwDhGrps[j])
            {
                for (j = i + 1; j < numDhGrps; j++)
                    pwDhGrps[j-1] = pwDhGrps[j];

                *num = --numDhGrps;
                break;
            }
        }
    }

    *ppwGroups = pwDhGrps;
    pwDhGrps = NULL;

exit:
    if (NULL != pwDhGrps) FREE(pwDhGrps);
    return status;
} /* IKE_customDhGroups */

#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_HASH_ALGO

static MSTATUS
IKE_customHashAlgos(IKESA pxSa)
{
    MSTATUS status = OK;

    intBoolean bIKEv2 = IS_IKE2_SA(pxSa);

#define NUM_HASH_ALGOS 8 /* FOR NOW */
    sbyte4 numAlgos = NUM_HASH_ALGOS;
    ubyte2 *pwAlgos = NULL;

    sbyte4 i, j;

    if (NULL == (pwAlgos = (ubyte2 *) MALLOC(NUM_HASH_ALGOS * sizeof(ubyte2))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pwAlgos, 0x00, NUM_HASH_ALGOS * sizeof(ubyte2));

    if (OK > CUSTOM_IKE_GET_HASH_ALGO(pwAlgos, &numAlgos,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                (bIKEv2 ? 2 : 1), IS_INITIATOR(pxSa)
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        /* use default */
        goto exit;
    }

    /* check valid algorithms */
    for (i=0; i < numAlgos && (NUM_HASH_ALGOS > i); i++)
    {
        ubyte2 wAlgo = pwAlgos[i];
        IKE_hashSuiteInfo *pHashSuite = IKE_hashSuiteEx(pxSa->ikePeerConfig,
                                                      (bIKEv2 ? 0 : wAlgo),
                                                      (bIKEv2 ? wAlgo : 0));
        if (NULL != pHashSuite)
        {
            pwAlgos[(pxSa->numHashAlgos)++] = wAlgo;
        }
    }

    if (0 >= (numAlgos = pxSa->numHashAlgos))
    {
        status = ERR_IKE_MISMATCH_HASH_ALGO;
        goto exit;
    }

    /* remove duplicates */
    for (i = numAlgos - 1; i > 0; i--)
    {
        ubyte2 wAlgo = pwAlgos[i];

        for (j=0; j < i; j++)
        {
            if (wAlgo == pwAlgos[j])
            {
                for (j = i + 1; j < numAlgos; j++)
                    pwAlgos[j-1] = pwAlgos[j];

                pxSa->numHashAlgos = --numAlgos;
                break;
            }
        }
    }

    pxSa->pwHashAlgos = pwAlgos;
    pwAlgos = NULL;

exit:
    if (NULL != pwAlgos) FREE(pwAlgos);
    return status;
} /* IKE_customHashAlgos */

#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_INTEG_ALGO /* [v2] */

static MSTATUS
IKE_customMacAlgos(IKESA pxSa)
{
    MSTATUS status = OK;

#define NUM_MAC_ALGOS 8 /* FOR NOW */
    sbyte4 numAlgos = NUM_MAC_ALGOS;
    ubyte2 *pwAlgos = NULL;

    sbyte4 i, j;

    if (NULL == (pwAlgos = (ubyte2 *) MALLOC(NUM_MAC_ALGOS * sizeof(ubyte2))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pwAlgos, 0x00, NUM_MAC_ALGOS * sizeof(ubyte2));

    if (OK > CUSTOM_IKE_GET_INTEG_ALGO(pwAlgos, &numAlgos,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                2, IS_INITIATOR(pxSa)
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        /* use default */
        goto exit;
    }

    /* check valid algorithms */
    for (i=0; i < numAlgos && (NUM_MAC_ALGOS > i); i++)
    {
        ubyte2 wAlgo = pwAlgos[i];
        IKE_macSuiteInfo *pMacSuite = IKE_macSuiteEx(pxSa->ikePeerConfig, wAlgo);
        if (NULL != pMacSuite)
        {
            pwAlgos[(pxSa->numMacAlgos)++] = wAlgo;
        }
    }

    if (0 >= (numAlgos = pxSa->numMacAlgos))
    {
        status = ERR_IKE_MISMATCH_AUTH_ALGO;
        goto exit;
    }

    /* remove duplicates */
    for (i = numAlgos - 1; i > 0; i--)
    {
        ubyte2 wAlgo = pwAlgos[i];

        for (j=0; j < i; j++)
        {
            if (wAlgo == pwAlgos[j])
            {
                for (j = i + 1; j < numAlgos; j++)
                    pwAlgos[j-1] = pwAlgos[j];

                pxSa->numMacAlgos = --numAlgos;
                break;
            }
        }
    }

    pxSa->pwMacAlgos = pwAlgos;
    pwAlgos = NULL;

exit:
    if (NULL != pwAlgos) FREE(pwAlgos);
    return status;
} /* IKE_customMacAlgos */

#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_ENCR_ALGO

static MSTATUS
IKE_customEncrAlgos(IKESA pxSa)
{
    MSTATUS status = OK;

    intBoolean bInitiator = IS_INITIATOR(pxSa);
    intBoolean bIKEv2 = IS_IKE2_SA(pxSa);

#define NUM_ENCR_ALGOS 16 /* FOR NOW */
    sbyte4 numAlgos = NUM_ENCR_ALGOS;
    ubyte2 *pwAlgos = NULL;
    ubyte2 *pwKeylens = NULL;

    sbyte4 i, j;

    if (NULL == (pwAlgos = (ubyte2 *) MALLOC(NUM_ENCR_ALGOS * sizeof(ubyte2))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pwAlgos, 0x00, NUM_ENCR_ALGOS * sizeof(ubyte2));

    if (NULL == (pwKeylens = (ubyte2 *) MALLOC(NUM_ENCR_ALGOS * sizeof(ubyte2))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pwKeylens, 0x00, NUM_ENCR_ALGOS * sizeof(ubyte2));

    if (OK > CUSTOM_IKE_GET_ENCR_ALGO(pwAlgos, pwKeylens, &numAlgos,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                (bIKEv2 ? 2 : 1), bInitiator
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        /* use default */
        goto exit;
    }

    /* check valid algorithms */
    for (i=0; i < numAlgos && (NUM_ENCR_ALGOS > i); i++)
    {
        ubyte2 wAlgo = pwAlgos[i];
        ubyte2 wKeylen = pwKeylens[i];

        if (bInitiator && !wKeylen) /* initiator, unspecified keylength */
        {
            continue; /* for now */
        }

        if (NULL != IKE_cipherSuiteEx(pxSa->ikePeerConfig,
                                    (bIKEv2 ? 0 : wAlgo), (bIKEv2 ? wAlgo : 0),
                                    wKeylen, NULL))
        {
            pwKeylens[pxSa->numEncrAlgos] = wKeylen;
            pwAlgos[(pxSa->numEncrAlgos)++] = wAlgo;
        }
    }

    if (0 >= (numAlgos = pxSa->numEncrAlgos))
    {
        status = ERR_IKE_MISMATCH_ENCR_ALGO;
        goto exit;
    }

    /* remove duplicates */
    for (i = numAlgos - 1; i > 0; i--)
    {
        ubyte2 wAlgo = pwAlgos[i];
        ubyte2 wKeylen = pwKeylens[i];

        for (j=0; j < i; j++)
        {
            if (wAlgo == pwAlgos[j])
            {
                if (wKeylen != pwKeylens[j]) /* !!! */
                {
                    if (bInitiator || pwKeylens[j])
                        continue;
                }

                for (j = i + 1; j < numAlgos; j++)
                {
                    pwAlgos[j-1] = pwAlgos[j];
                    pwKeylens[j-1] = pwKeylens[j];
                }
                pxSa->numEncrAlgos = --numAlgos;
                break;
            }
        }
    }

    pxSa->pwEncrAlgos = pwAlgos;
    pwAlgos = NULL;

    pxSa->pwEncrKeyLens = pwKeylens;
    pwKeylens = NULL;

exit:
    if (NULL != pwAlgos) FREE(pwAlgos);
    if (NULL != pwKeylens) FREE(pwKeylens);
    return status;
} /* IKE_customEncrAlgos */

#endif


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__

#ifdef __IKE_MULTI_THREADED__
#define EXIT_SA goto exit_sa;
#else
#define EXIT_SA goto exit;
#endif

static void
ExpTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_EXPIRATION]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_EXPIRATION]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = ExpTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_EXPIRATION] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_EXPIRATION] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (IS_IKE2_SA(pxSa))
    {
        IKE2_delSa(pxSa, TRUE, ERR_IKE_TIMEOUT);
    }
    else
    {
        IKE_delSa(pxSa, FALSE, ERR_IKE_TIMEOUT);
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* ExpTimerEvent */

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_allocSa(ikePeerConfig* config,
            MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort, ubyte *poCky,
            IKESA *ppxSa, IKESA pxSa0, sbyte4 version
            MOC_NATT(bUseNattPort)
            MOC_MTHM(serverInstance))
{
    MSTATUS status = OK;

    IKESA pxSa = NULL;

#ifndef __IKE_SADB_MEMPOOL__
    IKESA pxSaDel = NULL, pxSaIdle = NULL;
    ubyte4 timeidled=0;
    sbyte4 i;
#endif
    sbyte4 loc;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    MOC_IP_ADDRESS_S hostAddr;
    sbyte4 (*hostAddrFunc)(MOC_IP_ADDRESS_S *, sbyte4 s) = m_ikeSettings.funcPtrIkeGetHostAddr;

    ubyte2 wHostPort;
    sbyte4 (*hostPortFunc)(ubyte2 *, intBoolean, sbyte4 s) = m_ikeSettings.funcPtrIkeGetHostPort;

#ifdef __IKE_MULTI_THREADED__
    sbyte4 (*getThreadIdFunc)(RTOS_THREAD *, const ubyte *, sbyte4, intBoolean, sbyte4) = NULL;
    intBoolean bIsLocked = FALSE;
#endif
#ifdef USE_MOC_COOKIE
    sbyte4 (*getCookieFunc)(ubyte4 *c, sbyte4 s)= m_ikeSettings.funcPtrIkeGetCookie;
    ubyte4 cookie = 0;

    /* get cutom cookie; e.g. VLAN id */
    if (NULL == getCookieFunc)
    {
        status = ERR_IKE_CONFIG;
        goto nocleanup;
    }
    else
    if (OK > (status = getCookieFunc(&cookie MOC_MTHM_REQ_VALUE(serverInstance))))
        goto nocleanup;
#endif

    /* get host IP address */
    if (NULL == hostAddrFunc) /* jic */
    {
        status = ERR_IKE_CONFIG;
        goto nocleanup;
    }
    if (OK > (status = (MSTATUS) hostAddrFunc(&hostAddr
                                    MOC_MTHM_REQ_VALUE(serverInstance))))
    {
        goto nocleanup;
    }

    if (NULL == config)
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto nocleanup;
    }

    if (NULL != hostPortFunc)
    {
        if (OK > (status = (MSTATUS) hostPortFunc(&wHostPort
                                        MOC_NATT_REQ_VALUE(bUseNattPort)
                                        MOC_MTHM_REQ_VALUE(serverInstance))))
        {
            goto nocleanup;
        }
    }
    else
    {
        wHostPort =
#ifdef __ENABLE_IPSEC_NAT_T__
            bUseNattPort ? IKE_NAT_UDP_PORT :
#endif
                           IKE_DEFAULT_UDP_PORT;
    }

#ifdef __IKE_MULTI_THREADED__
    if (((NULL == poCky) || (NULL != pxSa0)) && /* initiator or [v2] REKEY_SA */
        (NULL == (getThreadIdFunc = m_ikeSettings.funcPtrIkeGetThreadId)))
    {
        status = ERR_IKE_CONFIG;
        goto nocleanup;
    }
#endif

    /* sanity check */
    IF_MOC_IPADDR6(hostAddr,
    {
        const ubyte *addr6 = GET_MOC_IPADDR6(REF_MOC_IPADDR(hostAddr));
        if (0xFF == addr6[0]) /* multicast */
        {
            status = ERR_IKE_CONFIG;
            goto nocleanup;
        }
    })
    {
        ubyte4 dwHostAddr = GET_MOC_IPADDR4(REF_MOC_IPADDR(hostAddr));
        if ((0 == dwHostAddr) || /* jic */
            ((dwHostAddr & 0xe0000000) == 0xe0000000)) /* multicast/broadcast */
        {
            status = ERR_IKE_CONFIG;
            goto nocleanup;
        }
    }

#ifdef __IKE_SADB_MALLOC__
    if ((IKE_SA_MAX > m_ikeSaNum) &&
        (NULL != (pxSa = (IKESA) MALLOC(sizeof(struct ikesa)))))
    {
        if (OK > DYNARR_Append(&m_ikeSa, &pxSa))
        {
            FREE(pxSa); pxSa = NULL;
        }
        else
        {
/*          DYNARR_GetElementCount(&m_ikeSa, &m_ikeSaNum);*/
            loc = m_ikeSaNum++;
            if (IKE_SA_MAX <= m_ikeSaNum)
                DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"IKE_SA table fully occupied.");
            goto _new;
        }
    }
#endif

    /* find available SA slot */
#ifdef __IKE_SADB_MEMPOOL__
    POP_ELEMENT(pxSa, status)
    if (OK <= status)
    {
        if (!(IKE_SA_FLAG_INUSE & pxSa->flags))
        {
            GET_ELEMENT_LOCATOR(pxSa, loc, status)
            if (OK > status) /* jic */
            {
                PUSH_ELEMENT(pxSa)
                goto nocleanup;
            }
            goto _init; /* unused */
        }

        goto _cleanup; /* deleted */
    }
#else
    for (i=0; i < m_ikeSaNum; i++, pxSa = NULL)
    {
        GET_NEXT_ELEMENT(pxSa, i)

        if (pxSa == pxSa0) continue; /* [v2] */

        if (!(IKE_SA_FLAG_INUSE & pxSa->flags))
        {
            loc = i;
            goto _init; /* unused */
        }

        pxSa->flags &= ~(IKE_SA_FLAG_RESERVED);

        if ((IKE_SA_FLAG_DELETED & pxSa->flags) ||
            IKE_checkExpSa(timenow, pxSa))
        {
            /* deleted or expired */
            if ((NULL == pxSaDel) ||
                ((timenow - pxSa->dwTimeStamp) > (timenow - pxSaDel->dwTimeStamp)))
                pxSaDel = pxSa;
            continue;
        }

        if ((NULL == pxSaDel) && /* find least active idle */
            (pxSa->dwTimeStamp || !IS_IKE2_SA(pxSa)))
        {
            ubyte4 timeoutIdle = 600000/* 1000*60*10 */;    /* 10 minutes; FOR NOW */
            ubyte4 timedlt = timenow - pxSa->dwTimeStamp;
            if (timedlt > timeoutIdle) /* idle */
            {
                if ((NULL == pxSaIdle) || (timedlt > timeidled))
                {
                    pxSaIdle = pxSa;
                    timeidled = timedlt;
                }
            }
        }
    } /* for */

    if (NULL != (pxSa = pxSaDel))
    {
        if (IS_VALID(pxSa)) goto _delete; /* [v2]? */
        goto _cleanup;
    }
    if (NULL != (pxSa = pxSaIdle))
        goto _delete;

    /* find duplicate SA */
    for (i=0; i < m_ikeSaNum; i++, pxSa = NULL)
    {
        sbyte4 j;
        intBoolean bIKEv2;

        GET_NEXT_ELEMENT(pxSa, i)

        if ((pxSa == pxSa0) || /* [v2] */
            (IKE_SA_FLAG_RESERVED & pxSa->flags))
            continue;

        bIKEv2 = IS_IKE2_SA(pxSa);
        if ((bIKEv2 && IS_IKE2_SA_AUTHED(pxSa)) ||
            (!bIKEv2 && IS_IKE_SA_AUTHED(pxSa)))
        {
            INIT_MOC_IPADDR(peerAddr0, pxSa->dwPeerAddr)
#ifdef __IKE_MULTI_HOMING__
            sbyte4 serverInst0 = pxSa->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
            ubyte2 wPeerPort0 = pxSa->wPeerPort;
            intBoolean bPeerNat0 = IS_PEER_BEHIND_NAT(pxSa);
#endif
            ubyte4 timedlt0 = (timenow - pxSa->dwTimeCreated);

            pxSa->flags |= IKE_SA_FLAG_RESERVED;

            for (j=i+1; j < m_ikeSaNum; j++)
            {
                IKESA pxSaTmp;
                GET_NEXT_ELEMENT(pxSaTmp, j)

                if ((pxSaTmp == pxSa0) || /* [v2] */
                    (IS_IKE2_SA(pxSaTmp) != bIKEv2) ||
                    (IKE_SA_FLAG_RESERVED & pxSaTmp->flags))
                    continue;

                if ((bIKEv2 && !IS_IKE2_SA_AUTHED(pxSaTmp)) ||
                    (!bIKEv2 && !IS_IKE_SA_AUTHED(pxSaTmp)))
                {
                    pxSaTmp->flags |= IKE_SA_FLAG_RESERVED;
                    continue;
                }

                if (SAME_MOC_IPADDR(peerAddr0, pxSaTmp->dwPeerAddr))
#ifdef __IKE_MULTI_HOMING__
                if (serverInst0 == pxSaTmp->serverInstance)
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                /* See RFC 3947 6. p.11 */
                if ((wPeerPort0 == pxSaTmp->wPeerPort) ||
                    !(bPeerNat0 || IS_PEER_BEHIND_NAT(pxSaTmp)))
#endif
                {
                    pxSa->flags &= ~(IKE_SA_FLAG_RESERVED);
                    if (timedlt0 < (timenow - pxSaTmp->dwTimeCreated))
                    {
                        IKESA pxSaOld = pxSaTmp;
                        pxSaTmp = pxSa;
                        pxSa = pxSaOld;
                    }
                }
            } /* for (j=i+1; */

            if (!(IKE_SA_FLAG_RESERVED & pxSa->flags)) /* delete duplicate SA */
                goto _delete;
        }
    } /* for (i=0; */

    status = ERR_IKE_NEWSA_FAIL;
#endif /* !__IKE_SADB_MEMPOOL__ */

    goto nocleanup; /* not found */

#ifndef __IKE_SADB_MEMPOOL__
_delete:
    if (IS_IKE2_SA(pxSa))
    {
        IKE2_delSa(pxSa, TRUE, ((pxSa == pxSaIdle)
                ? STATUS_IKE_IDLE : STATUS_IKE_REKEY));

        if (IKE_SA_FLAG_DELETING & pxSa->flags)
            IKE2_delSa(pxSa, FALSE, OK);
    }
    else
    {
        IKE_delSa(pxSa, TRUE, ((pxSa == pxSaIdle)
                ? STATUS_IKE_IDLE : STATUS_IKE_REKEY));
    }
#endif

_cleanup:
    loc = pxSa->loc;

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    IKE_delSaCkyIndex(pxSa);
#endif
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    IKE_delSaAddrIndex(pxSa);
#endif
#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
    IKE_delSaIdIndex(pxSa);
#endif

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_rwLockOwnerW(g_ikeMtx))
    {
        RTOS_rwLockWaitW(m_ikeSaRwLock);
        bIsLocked = TRUE;
    }
#endif

#ifdef __IKE_SADB_MALLOC__
_new:
#endif
_init:
    DIGI_MEMSET((ubyte *)pxSa, 0x00, sizeof(struct ikesa));

    /* initialize */
    pxSa->ikePeerConfig = config;

    if (0x7fffffff == m_ikeSaId) m_ikeSaId = 0;
    pxSa->dwId = ++m_ikeSaId;

    if (2 == version) /* [v2] */
    {
        pxSa->dwId |= 0x80000000; /* !!! */
    }

    if (NULL != pxSa0) /* [v2] REKEY_SA */
    {
        pxSa->dwId0 = pxSa0->dwId0; /* inherit from old IKE_SA */
    }
    else
    {
        pxSa->dwId0 = pxSa->dwId; /* !!! */
    }

    pxSa->loc = loc;

    COPY_MOC_IPADDR(pxSa->dwPeerAddr, peerAddr);
    pxSa->wPeerPort = wPeerPort;
#ifdef __IKE_MULTI_HOMING__
    pxSa->serverInstance = serverInstance;
#endif
    pxSa->dwHostAddr = hostAddr;
    pxSa->wHostPort = wHostPort;

    SET_MOC_COOKIE(pxSa->cookie, cookie)

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    if (m_ikeSettings.funcPtrGetInterfaceId)
    {
        m_ikeSettings.funcPtrGetInterfaceId(&pxSa->ifid, peerAddr
                                            MOC_MTHM_REQ_VALUE(serverInstance));
    }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort)
        pxSa->natt_flags |= (IKE_NATT_FLAG_USE_NPORT | IKE_NATT_FLAG_NPORT_USED);
#endif
    if (NULL == poCky) /* initiator */
    {
        pxSa->flags |= IKE_SA_FLAG_INITIATOR;

        poCky = pxSa->poCky_I;

        pxSa->poNonce[_I] = pxSa->nonce;
        pxSa->wNonceLen[_I] = IKE_NONCE_SIZE;
    }
    else /* responder */
    {
        DIGI_MEMCPY(pxSa->poCky_I, poCky, IKE_COOKIE_SIZE); /* store initiator cookie */

        poCky = pxSa->poCky_R;

        pxSa->poNonce[_R] = pxSa->nonce;
        pxSa->wNonceLen[_R] = IKE_NONCE_SIZE;
    }

    /* set cookie, nonce */
    if ((OK > (status = RANDOM_numberGenerator(g_pRandomContext, poCky, IKE_COOKIE_SIZE))) ||
        (OK > (status = RANDOM_numberGenerator(g_pRandomContext, pxSa->nonce, IKE_NONCE_SIZE))))
    {
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    /* set thread ID */
    if (getThreadIdFunc) /* initiator or IKEv2 REKEY */
    {
        if (OK > (status = (MSTATUS) getThreadIdFunc(&pxSa->tid, pxSa->poCky_I,
                                            version, (poCky ? FALSE : TRUE)
                                            MOC_MTHM_REQ_VALUE(serverInstance))))
        {
            goto exit;
        }
    }
    else
    {
        pxSa->tid = RTOS_currentThreadId();
    }
#endif

#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)
    if (OK > (status = IKE_customDhGroups(&pxSa->pwDhGrps, &pxSa->numDhGrps,
                                    (IKE_SA_FLAG_INITIATOR & pxSa->flags),
                                     pxSa, pxSa0)))
    {
        goto exit;
    }
#endif

#ifdef CUSTOM_IKE_GET_HASH_ALGO
    if (OK > (status = IKE_customHashAlgos(pxSa)))
    {
        goto exit;
    }
#endif

#ifdef CUSTOM_IKE_GET_INTEG_ALGO /* [v2] */
    if ((2 == version) &&
        (OK > (status = IKE_customMacAlgos(pxSa))))
    {
        goto exit;
    }
#endif

#ifdef CUSTOM_IKE_GET_ENCR_ALGO
    if (OK > (status = IKE_customEncrAlgos(pxSa)))
    {
        goto exit;
    }
#endif

#ifndef __IKE_UPDATE_TIMER__
#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (1 == version)
    if (!config->bNoIkeFrag)
    {
        if (OK > (status = TIMER_createTimer(IKE_fragReassemblyTimerExpiry,
                                             &(pxSa->reassemblyTimerId))))
        {
            goto exit;
        }
    }
#endif
#endif
#ifdef __ENABLE_IKE_REDIRECT__
    if (2 == version)
    if (OK > (status = TIMER_createTimer(IKE_redirectTimerExpiry,
                                         &(pxSa->redirectTimerId))))
    {
        goto exit;
    }
#endif

#ifdef __IKE_UPDATE_TIMER__
    if (NULL == pxSa0) /* [v2] no expiration timer for REKEY_SA initially */
    if (OK > (status = IKE_ADD_TIMER_EVT((1000 * config->ikeTimeoutNegotiation),
                                         0, pxSa,
                                         ExpTimerEvent, "TO1",
                                         pxSa->timerIDs[IKESA_TIMER_EXPIRATION],
                                         pxSa->timerHdls[IKESA_TIMER_EXPIRATION])))
    {
        goto exit;
    }
#endif

    /* done */
    pxSa->flags |= IKE_SA_FLAG_INUSE;
    pxSa->dwTimeStart = timenow;

#ifdef __IKE_MULTI_THREADED__
    if (TRUE == bIsLocked)
        RTOS_rwLockReleaseW(m_ikeSaRwLock);
#endif

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    IKE_addSaCkyIndex(pxSa);
#endif
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    IKE_addSaAddrIndex(pxSa);
#endif
#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
    IKE_addSaIdIndex(pxSa);
#endif

    *ppxSa = pxSa;
    pxSa = NULL;

exit:
    if (NULL != pxSa)
    {
#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)
        if (NULL != pxSa->pwDhGrps)
            FREE(pxSa->pwDhGrps);
#endif
#ifdef CUSTOM_IKE_GET_HASH_ALGO
        if (NULL != pxSa->pwHashAlgos)
            FREE(pxSa->pwHashAlgos);
#endif
#ifdef CUSTOM_IKE_GET_INTEG_ALGO /* [v2] */
        if (NULL != pxSa->pwMacAlgos)
            FREE(pxSa->pwMacAlgos);
#endif
#ifdef CUSTOM_IKE_GET_ENCR_ALGO
        if (NULL != pxSa->pwEncrAlgos)
            FREE(pxSa->pwEncrAlgos);

        if (NULL != pxSa->pwEncrKeyLens)
            FREE(pxSa->pwEncrKeyLens);
#endif
#ifndef __IKE_UPDATE_TIMER__
#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (NULL != pxSa->reassemblyTimerId)
            TIMER_destroyTimer(pxSa->reassemblyTimerId);
#endif
#endif
#ifdef __ENABLE_IKE_REDIRECT__
        if (NULL != pxSa->redirectTimerId)
            TIMER_destroyTimer(pxSa->redirectTimerId);
#endif
        DIGI_MEMSET((ubyte *)pxSa, 0x00, sizeof(struct ikesa));

#ifdef __IKE_MULTI_THREADED__
        if (TRUE == bIsLocked)
            RTOS_rwLockReleaseW(m_ikeSaRwLock);
#endif
        PUSH_ELEMENT(pxSa) /* do this *after* MEMSET! */
    }

nocleanup:
    if (OK > status)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_allocSa() returns error ", status);
#else
        DIGICERT_log(MOCANA_IKE, LS_MAJOR, (sbyte *)"IKE_allocSa() failed.");
#endif
    }
    return status;
} /* IKE_allocSa */


/*------------------------------------------------------------------*/

extern IKESA
IKE_newSa(ikePeerConfig* config, MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort, ubyte *poCky
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        , ubyte oExchange
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        , intBoolean bGdoi
#endif
          MOC_NATT(bUseNattPort)
          MOC_MTHM(serverInstance))
{
    IKESA pxSa = NULL;

    MSTATUS status;
    if (OK > (status = IKE_allocSa(config, peerAddr, wPeerPort, poCky,
                                   &pxSa, NULL, 1
                                   MOC_NATT_VALUE(bUseNattPort)
                                   MOC_MTHM_VALUE(serverInstance))))
    {
        pxSa = NULL; /* jic */
        goto exit;
    }

    /* initialize */
    if (NULL != poCky) /* responder */
    {
        pxSa->oState = (ubyte)(
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                                (ISAKMP_XCHG_AGGR == oExchange)
                              ? STATE_AGGR_R1 :
#endif
                                STATE_MAIN_R1);
    }
    else /* initiator */
    {
#ifdef CUSTOM_IKE_GET_P1_DHGRP
        if (0 < pxSa->numDhGrps)
        {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            if (ISAKMP_XCHG_AGGR == oExchange)
                pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION] = pxSa->pwDhGrps[0];
#endif
        }
        else
#endif
        {
            ubyte2 wDhGrp = config->ikeP1DHgroup;
            if (0 != wDhGrp)
                pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION] = wDhGrp;
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            else if (ISAKMP_XCHG_AGGR == oExchange)
            {
                /* find default DH group */
                sbyte4 i;
                for (i=0; ; i++)
                {
                    IKE_dhGroupInfo *pDhGroup = IKE_getDhGroupEx(config, i);
                    if (NULL == pDhGroup) break;

                    if (!pDhGroup->bDisabled[0][_I] &&
                        (0 != (wDhGrp = pDhGroup->wTfmId)))
                    {
                        pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION] = wDhGrp;
                        break; /* found */
                    }
                }
            }
#endif
        }

        pxSa->oState = (ubyte)(
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                               (ISAKMP_XCHG_AGGR == oExchange)
                              ? STATE_AGGR_I1 :
#endif
                                STATE_MAIN_I1);

#ifdef CUSTOM_IKE_GET_P1_LIFESECS
        if (OK > CUSTOM_IKE_GET_P1_LIFESECS(&pxSa->dwExpSecs,
                                peerAddr, _I, TRUE
                                MOC_MTHM_REQ_VALUE(serverInstance)))
#endif
        if (0 == (pxSa->dwExpSecs = config->ikeP1LifeSecs))
            pxSa->dwExpSecs = config->ikeP1LifeSecsMax;

        if (IKE_LIFE_SECS_MAX < pxSa->dwExpSecs)
            pxSa->dwExpSecs = IKE_LIFE_SECS_MAX;

#ifdef CUSTOM_IKE_GET_P1_LIFEKBYTES
        if (OK > CUSTOM_IKE_GET_P1_LIFEKBYTES(&pxSa->dwExpKBytes,
                                peerAddr, _I, TRUE
                                MOC_MTHM_REQ_VALUE(serverInstance)))
#endif
        if (0 == (pxSa->dwExpKBytes = config->ikeP1LifeKBytes))
            pxSa->dwExpKBytes = config->ikeP1LifeKBytesMax;
    }

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    if (bGdoi)
    {
        pxSa->flags |= IKE_SA_FLAG_GDOI;

#ifdef __ENABLE_IPSEC_NAT_T__
        if (!bUseNattPort)
#endif
        if (NULL == m_ikeSettings.funcPtrIkeGetHostPort)
        {
            pxSa->wHostPort = IKE_GDOI_UDP_PORT;
        }
    }
#endif

exit:
    return pxSa;
} /* IKE_newSa */


/*------------------------------------------------------------------*/

static void FreeSa(IKESA pxSa)
{
    sbyte4 i;
    for (i=_I; i <= _R; i++)
    {
        if (NULL != pxSa->poNonce[i])
        {
            if (pxSa->poNonce[i] != pxSa->nonce)
                FREE(pxSa->poNonce[i]);
            pxSa->poNonce[i] = NULL;
            pxSa->wNonceLen[i] = 0;
        }

#ifndef __ENABLE_IKE_MODE_CFG__
        if (NULL != pxSa->pxID[i])
        {
            FREE(pxSa->pxID[i]);
            pxSa->pxID[i] = NULL;
        }
#endif
    }

    if (NULL != pxSa->poMsg[_I])
    {
        FREE(pxSa->poMsg[_I]);
        pxSa->poMsg[_I] = NULL;
        pxSa->dwMsgLen[_I] = 0;
    }

    if (NULL != pxSa->p_dhContext)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxSa->p_dhContext), NULL, NULL);
#else
        DH_freeDhContext(&(pxSa->p_dhContext), NULL);
#endif
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pxSa->p_eccKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxSa->p_eccKey));
#else
        EC_deleteKey(&(pxSa->p_eccKey));
#endif
    }

    if (NULL != pxSa->poEccSharedSecret)
    {
        DIGI_MEMSET(pxSa->poEccSharedSecret, 0, pxSa->eccSharedSecretLen);
        FREE(pxSa->poEccSharedSecret);
        pxSa->poEccSharedSecret = NULL;
        pxSa->eccSharedSecretLen = 0;
    }

    if (NULL != pxSa->p_eccKeyPeer)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxSa->p_eccKeyPeer));
#else
        EC_deleteKey(&(pxSa->p_eccKeyPeer));
#endif
    }

    if (NULL != pxSa->poEcdsaSig)
    {
        FREE(pxSa->poEcdsaSig);
        pxSa->poEcdsaSig = NULL;
        pxSa->wEcdsaSigLen = 0;
    }
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pxSa->pQsCtx)
    {
        CRYPTO_INTERFACE_QS_deleteCtx(&(pxSa->pQsCtx));
    }

    if (NULL != pxSa->pQsCipherText)
    {
        DIGI_MEMSET(pxSa->pQsCipherText, 0x00, pxSa->qsCipherTextLen);
        FREE(pxSa->pQsCipherText);
        pxSa->pQsCipherText = NULL;
        pxSa->qsCipherTextLen = 0;
    }

    if (NULL != pxSa->pQsSharedSecret)
    {
        DIGI_MEMSET(pxSa->pQsSharedSecret, 0x00, pxSa->qsSharedSecretLen);
        FREE(pxSa->pQsSharedSecret);
        pxSa->pQsSharedSecret = NULL;
        pxSa->qsSharedSecretLen = 0;
    }
#endif

    if (NULL != pxSa->pDhPeerPubKey)
    {
        FREE(pxSa->pDhPeerPubKey);
        pxSa->pDhPeerPubKey = NULL;
        pxSa->dhPeerPubKeyLen = 0;
    }

    if (NULL != pxSa->pDhSharedSecret)
    {
        DIGI_MEMSET(pxSa->pDhSharedSecret, 0, pxSa->dhSharedSecretLen);
        FREE(pxSa->pDhSharedSecret);
        pxSa->pDhSharedSecret = NULL;
        pxSa->dhSharedSecretLen = 0;
    }

#ifdef CUSTOM_IKE_GET_P1_DHGRP
    if (NULL != pxSa->pwDhGrps)
    {
        FREE(pxSa->pwDhGrps);
        pxSa->pwDhGrps = NULL;
        pxSa->numDhGrps = 0;
    }
#endif

#ifdef CUSTOM_IKE_GET_HASH_ALGO
    if (NULL != pxSa->pwHashAlgos)
    {
        FREE(pxSa->pwHashAlgos);
        pxSa->pwHashAlgos = NULL;
        pxSa->numHashAlgos = 0;
    }
#endif

#ifdef CUSTOM_IKE_GET_ENCR_ALGO
    if (NULL != pxSa->pwEncrAlgos)
    {
        FREE(pxSa->pwEncrAlgos);
        pxSa->pwEncrAlgos = NULL;
        FREE(pxSa->pwEncrKeyLens);
        pxSa->pwEncrKeyLens = NULL;
        pxSa->numEncrAlgos = 0;
    }
#endif

    if (NULL != pxSa->pCertChain)
    {
        if (pxSa->ikePeerConfig->ikeCertChain != pxSa->pCertChain)
        {
            IKE_certUnsetChain(pxSa->pCertChain, pxSa->certChainLen);
            FREE(pxSa->pCertChain);
        }
        pxSa->pCertChain = NULL;
        pxSa->certChainLen = 0;
    }

#ifdef __IKE_UPDATE_TIMER__
    IKE_DEL_TIMER_EVT(pxSa->u.v1.rtxTimerId, pxSa->u.v1.rtxTimerHdl)

    if (NULL != pxSa->u.v1.poRtxMsg)
    {
        FREE(pxSa->u.v1.poRtxMsg);
        pxSa->u.v1.poRtxMsg = NULL;
    }
    pxSa->u.v1.dwRtxMsgLen = 0;
#endif

    return;
} /* FreeSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_delSa(IKESA pxSa, intBoolean bInfo, MSTATUS merror)
{
    MSTATUS status = OK;
#ifndef __IKE_MULTI_THREADED__
    /* Protection against race conditions between IKE threads and timer thread */
    intBoolean bIsMutexLocked;
#endif

#ifndef __IKE_MULTI_THREADED__
    /* Protection against race conditions between IKE threads and timer thread */
    IKE_AUTO_LOCK(bIsMutexLocked);
#endif

#ifdef __IKE_MULTI_THREADED__
    if (!pxSa || !IS_VALID(pxSa)) goto exit;
#else
    if(!pxSa) goto exit;
    intBoolean bDelete = (pxSa->flags & IKE_SA_FLAG_DELETED) ? FALSE : TRUE;
#endif

    /* send delete payload in an informational exchange message */
    if (bInfo && IS_P1_FINAL_STATE(pxSa->oState))
    {
        struct ike_info_delete deleteInfo = { PROTO_ISAKMP, 0, NULL, NULL };
        struct ike_info info = { NULL };
        struct ike_context ctx = { NULL };

        IKESA pxSaCtx = pxSa;
#ifndef __IKE_MULTI_THREADED__
        if (!bDelete && (IKE_SA_FLAG_REKEYED & pxSa->flags))
        {
            /* already deleted - check if a new IKE_SA exists */
            IKESA pxSaRekey = pxSa->pxSaRekey;
            if ((NULL != pxSaRekey) && /* jic */
                (pxSaRekey->dwId == pxSa->dwSaRekeyId) &&
                IS_VALID(pxSaRekey) && IS_MATURE(pxSaRekey))
            {
                /* use the new IKE_SA to delete the old */
                pxSaCtx = pxSaRekey;
            }
        }
#endif
        deleteInfo.pxSa = pxSa;
        info.pxDelete = &deleteInfo;

        ctx.pxInfo = &info;
        ctx.pxSa = pxSaCtx;

        status = IKE_xchgOut(&ctx);
    }

#ifndef __IKE_MULTI_THREADED__
    if (bDelete)
#endif
    {
        sbyte4 i;

        if (merror && !pxSa->merror)
            pxSa->merror = merror;

        if (m_ikeSettings.funcPtrIkeStatHdlr)
        {
            m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA,
                (IS_IKE_SA_AUTHED(pxSa) ? IST_DELETED : IST_FAIL),
                pxSa->dwId, pxSa, NULL);
        }

        if (IS_P1_FINAL_STATE(pxSa->oState))
        {
            for (i=0; i < IKE_P2_MAX; i++)
            {
                P2XG pxXg = &(pxSa->u.v1.p2Xg[i]);

                if (IS_VALID_XCHG(pxXg))
                    status = IKE_delXchg(pxXg, pxSa, pxSa->merror);
            }
        }

#ifdef __ENABLE_IKE_MODE_CFG__
        for (i=_I; i <= _R; i++)
        {
            if (NULL != pxSa->pxID[i])
            {
                FREE(pxSa->pxID[i]);
                pxSa->pxID[i] = NULL;
            }
        }
#endif

#ifdef __ENABLE_IKE_FRAGMENTATION__
        /* Flush reassemble queue in case there are fragments left
         * due to incomplete negotiation
         */
#ifdef __IKE_UPDATE_TIMER__
        if ((IKE_TIMER_EVT_T)0 != pxSa->timerIDs[IKESA_TIMER_REASSEMBLY])
        {
            IKE_flushFragReassemble(pxSa);
        }
#else
        if (NULL != pxSa->reassemblyTimerId)
        {
            IKE_flushFragReassemble(pxSa);
            TIMER_destroyTimer(pxSa->reassemblyTimerId);
            pxSa->reassemblyTimerId = NULL;
        }
#endif
#endif

#ifdef __IKE_UPDATE_TIMER__
        for (i=0; i < IKESA_TIMER_MAX; i++)
        {
            IKE_DEL_TIMER_EVT(pxSa->timerIDs[i], pxSa->timerHdls[i])
        }
#endif
        FreeSa(pxSa);
        pxSa->flags |= IKE_SA_FLAG_DELETED;

        PUSH_ELEMENT(pxSa)
        /* Note: pxSa is *not* removed from hashtables! */
    }

exit:
#ifndef __IKE_MULTI_THREADED__
    /* Protection against race conditions between IKE threads and timer thread */
    if (FALSE == bIsMutexLocked)
    {
        IKE_AUTO_UNLOCK;
    }
#endif
    return status;
} /* IKE_delSa */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

extern sbyte4
IKE_dpcDelSa(IKE_DPC_DEL_SA pxDel, ubyte4 dwDelSize)
{
    MSTATUS status = OK;
    IKESA pxSa;

    IKE_LOCK_R;

    if ((sizeof(struct dpcDelSa) > dwDelSize) ||
        (sizeof(struct dpcDelSa) != pxDel->hdr.dpc_len) ||
        ((IKE_dpcFunc)IKE_dpcDelSa != pxDel->hdr.dpc_func) ||
        (NULL == (pxSa = pxDel->pxSa)))
    {
        goto exit;
    }

    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (pxDel->dwSaId != pxSa->dwId))
    {
        goto exit_sa;
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* in the wrong thread - abort! */
        goto exit_sa;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);

    if (IS_IKE2_SA(pxSa))
    {
        status = IKE2_delSa(pxSa, pxDel->bInfo, pxDel->merror);
    }
    else
    {
        status = IKE_delSa(pxSa, pxDel->bInfo, pxDel->merror);
    }

exit:
    IKE_UNLOCK_R;
    return (sbyte4)status;

exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return (sbyte4)status;
} /* IKE_dpcDelSa */


#define DPC_DELSA(_gl, _sa0, _sas, _sa, _b, _m) \
if (FALSE == _gl) \
{ \
    if (TRUE == RTOS_sameThreadId((_sa)->tid, (_sa0)->tid)) \
    { \
        (_sa)->pNext = _sas; \
        _sas = _sa; \
    } \
    else \
    { \
        /* relay this call to the proper thread */ \
        if (m_ikeSettings.funcPtrIkeThreadSend) \
        { \
            struct dpcDelSa ds; \
            ds.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcDelSa; \
            ds.hdr.dpc_len = (ubyte2)sizeof(ds); \
            ds.pxSa = _sa; \
            ds.dwSaId = (_sa)->dwId; \
            ds.bInfo = _b; \
            ds.merror = _m; \
            m_ikeSettings.funcPtrIkeThreadSend((_sa)->tid, \
                                        (ubyte *)&ds, (ubyte4)sizeof(ds)); \
        } \
    } \
} \
else \

#define DPC2_DELSA(_gl, _sa0, _sas, _sa, _b, _m) DPC_DELSA(_gl, _sa0, _sas, _sa, _b, _m)


/*------------------------------------------------------------------*/

typedef struct ikesa_ic_test
{
    IKESA pxSa;
    IKESA pxSaDel;
    intBoolean bIsGlobalLocked;

} *IKESA_IC_TEST;

#endif /* __IKE_MULTI_THREADED__ */


static MSTATUS
MatchInitCont(IKESA pxSaPrev, void *pData, intBoolean *pIsMatch)
{
#ifdef __IKE_MULTI_THREADED__
#define pTest ((IKESA_IC_TEST)pData)
    IKESA pxSa = pTest->pxSa;
#else
#define pxSa ((IKESA)pData)
#endif
    MSTATUS status = OK;

    *pIsMatch = FALSE; /* will continue to find next! */

    if (pxSa == pxSaPrev) goto exit;

#ifdef __ENABLE_IPSEC_NAT_T__
    /* See RFC 3947 6. p.11 */
    if ((pxSa->wPeerPort != pxSaPrev->wPeerPort) &&
        (IS_PEER_BEHIND_NAT(pxSa) || IS_PEER_BEHIND_NAT(pxSaPrev)))
        goto exit;
#endif

    if (IS_IKE2_SA(pxSaPrev))
    {
        if (!IS_IKE2_SA_AUTHED(pxSaPrev) && IS_INITIATOR(pxSaPrev))
            goto exit;

#ifdef __IKE_MULTI_THREADED__
        DPC2_DELSA(pTest->bIsGlobalLocked, pxSa, pTest->pxSaDel,
                   pxSaPrev, FALSE, STATUS_IKE_INITIAL_CONTACT)
#endif
        IKE2_delSa(pxSaPrev, FALSE, STATUS_IKE_INITIAL_CONTACT);
        debug_print("    IKE2_delSa(spi={");
    }
    else
    {
        if (!IS_IKE_SA_AUTHED(pxSaPrev) && IS_INITIATOR(pxSaPrev))
            goto exit;

#ifdef __IKE_MULTI_THREADED__
        DPC_DELSA(pTest->bIsGlobalLocked, pxSa, pTest->pxSaDel,
                  pxSaPrev, FALSE, STATUS_IKE_INITIAL_CONTACT)
#endif
        IKE_delSa(pxSaPrev, FALSE, STATUS_IKE_INITIAL_CONTACT);
        debug_print("    IKE_delSa(cookies={");
    }

    debug_printr(pxSaPrev->poCky_I, IKE_COOKIE_SIZE, FALSE);
    debug_print(" ");
    debug_printr(pxSaPrev->poCky_R, IKE_COOKIE_SIZE, FALSE);
    debug_printnl("})");

exit:
    return status;
#ifdef __IKE_MULTI_THREADED__
#undef pTest
#else
#undef pxSa
#endif
} /* MatchInitCont */


/*------------------------------------------------------------------*/

extern void
IKE_initContSa(IKESA pxSa)
{
    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)
#if defined(__ENABLE_DIGICERT_PFKEY__) || defined(__IKE_MULTI_HOMING__)
    INIT_MOC_IPADDR(hostAddr, pxSa->dwHostAddr)
#endif
    struct ipsecKey key = { 0 };

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte4 st;
#endif

    /* delete old IKE_SA's */
#ifdef __IKE_MULTI_THREADED__
    IKESA pxSaTmp;
    struct ikesa_ic_test saTest;
    saTest.pxSa = pxSa;
    saTest.pxSaDel = NULL;
    saTest.bIsGlobalLocked = RTOS_rwLockOwnerW(g_ikeMtx);

    IKE_getSaByAddr(peerAddr, NULL, &saTest, MatchInitCont
                    MOC_MTHM_VALUE(pxSa->serverInstance));

    for (pxSaTmp = saTest.pxSaDel; NULL != pxSaTmp;)
    {
        IKESA pxSaDel = pxSaTmp;
        pxSaTmp = pxSaTmp->pNext;
        if (IS_IKE2_SA(pxSaDel))
            IKE2_delSa(pxSaDel, FALSE, STATUS_IKE_INITIAL_CONTACT);
        else
            IKE_delSa(pxSaDel, FALSE, STATUS_IKE_INITIAL_CONTACT);
    }
#else
    IKE_getSaByAddr(peerAddr, NULL, (void *)pxSa, MatchInitCont
                    MOC_MTHM_VALUE(pxSa->serverInstance));
#endif

    /* delete CHILD_SA's */
#if defined(__ENABLE_DIGICERT_PFKEY__)
    { sbyte4 i, j; for (i=0; i < 2; i++) for (j=0; j < 2; j++) {

    MOC_IP_ADDRESS dstAddr = (j ? hostAddr : peerAddr);
    MOC_IP_ADDRESS srcAddr = (j ? peerAddr : hostAddr);

    key.oProtocol = (i ? IPPROTO_AH : IPPROTO_ESP); /* !!! */
#else
    #define dstAddr peerAddr
    #define srcAddr hostAddr

    key.flags |= IPSEC_SA_FLAG_MIRRORED;
#endif
    TEST_MOC_IPADDR6(dstAddr,
    {
        key.flags |= IPSEC_SA_FLAG_IP6;
        key.dwDestAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(dstAddr);
    })
    key.dwDestAddr = GET_MOC_IPADDR4(dstAddr);

#if defined(__ENABLE_DIGICERT_PFKEY__) || defined(__IKE_MULTI_HOMING__)
    TEST_MOC_IPADDR6(srcAddr, {
        key.dwSrcAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(srcAddr);
    })
    key.dwSrcAddr = GET_MOC_IPADDR4(srcAddr);

    SET_MOC_COOKIE(key.cookie, pxSa->cookie)
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_PEER_BEHIND_NAT(pxSa))
        key.wUdpEncPort = pxSa->wPeerPort;
#endif
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    st =
#endif
    IPSEC_keyDelete(&key);

#if defined(__ENABLE_DIGICERT_PFKEY__)
    }}
#endif
    debug_print("    IPSEC_keyDelete(raddr=");
    debug_print_ip(peerAddr);
    debug_print(")");
    debug_print_st(st);

    if (m_ikeSettings.funcPtrIkeStatHdlr)
    {
        m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_INITIAL_CONTACT,
                                         pxSa->dwId, pxSa, NULL);
    }

    return;
} /* IKE_initContSa */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
static void
RekeyedTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_OLDSA]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_OLDSA]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RekeyedTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_OLDSA] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_OLDSA] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (HasNoChild(pxSa))
    {
        IKE_delSa(pxSa, TRUE, STATUS_IKE_REKEY); /* yes, delete it */
    }
    else
    {
        if (OK > IKE_ADD_TIMER_EVT(
                            (1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation),
                            0, pxSa,
                            RekeyedTimerEvent, "OLD",
                            pxSa->timerIDs[IKESA_TIMER_OLDSA],
                            pxSa->timerHdls[IKESA_TIMER_OLDSA]))
        {
            goto exit;
        }
    }

    MOC_UNUSED(cookie);

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RekeyedTimerEvent */
#endif


/*------------------------------------------------------------------*/

typedef struct ikesa_fs_test
{
    IKESA pxSa;
#ifdef __IKE_MULTI_THREADED__
    IKESA pxSaDel;
    intBoolean bIsGlobalLocked;
#endif
    ubyte4 timenow;
    ubyte4 timedlt;

} *IKESA_FS_TEST;


static MSTATUS
MatchFinalizeSa(IKESA pxSaTmp, void *pData, intBoolean *pIsMatch)
{
#define pTest ((IKESA_FS_TEST)pData)
    MSTATUS status = OK;

    IKESA pxSa = pTest->pxSa;
    ubyte4 timenow = pTest->timenow;
    ubyte4 timedlt = pTest->timedlt;

    if (!IS_IKE2_SA(pxSaTmp) &&
        (pxSa != pxSaTmp) &&
#ifdef __ENABLE_IPSEC_NAT_T__
        /* See RFC 3947 6. p.11 */
        ((pxSa->wPeerPort == pxSaTmp->wPeerPort) ||
         !(IS_PEER_BEHIND_NAT(pxSa) || IS_PEER_BEHIND_NAT(pxSaTmp))) &&
#endif
#ifndef __IKE_MULTI_THREADED__
        !IKE_checkExpSa(timenow, pxSaTmp) &&
#endif
        (!timedlt || (timedlt < (timenow - pxSaTmp->dwTimeCreated))))
    {
        /* found */
        if (IS_IKE_SA_AUTHED(pxSaTmp))
        {
            intBoolean bMature = IS_MATURE(pxSa);
            intBoolean bMatureTmp = IS_MATURE(pxSaTmp);

            if ((bMature || !bMatureTmp) &&
                (!bMature || bMatureTmp || /* should avoid race condition btw peers */
                 ((timenow - pxSa->dwTimeStart) < (timenow - pxSaTmp->dwTimeCreated))))
            {
                pxSaTmp->pxSaRekey = pxSa;
                pxSaTmp->dwSaRekeyId = pxSa->dwId;
                pxSaTmp->flags |= IKE_SA_FLAG_REKEYED;

                /* delete old IKE_SA immediately, if applicable */
                if (!timedlt && IS_INITIATOR(pxSa) && HasNoChild(pxSaTmp))
                {
#ifdef __IKE_MULTI_THREADED__
                    DPC_DELSA(pTest->bIsGlobalLocked, pxSa, pTest->pxSaDel,
                              pxSaTmp, TRUE, STATUS_IKE_REKEY)
#endif
                    IKE_delSa(pxSaTmp, TRUE, STATUS_IKE_REKEY);
                }
#ifdef __IKE_UPDATE_TIMER__
                else if ((IKE_TIMER_EVT_T)0 == pxSaTmp->timerIDs[IKESA_TIMER_OLDSA]) /* jic */
                {
                    if (OK > (status = IKE_ADD_TIMER_EVT(
                                    (1000 * pxSaTmp->ikePeerConfig->ikeTimeoutNegotiation),
                                    0, pxSaTmp,
                                    RekeyedTimerEvent, "OLD",
                                    pxSaTmp->timerIDs[IKESA_TIMER_OLDSA],
                                    pxSaTmp->timerHdls[IKESA_TIMER_OLDSA])))
                    {
                        //goto exit;
                    }
                }
#endif
            }
            else
            {
                pxSa->flags |= IKE_SA_FLAG_NEW; /* keep old IKE_SA */
            }
        }
        else if (!timedlt)
        {
            /* remove incomplete SA's */
            ubyte oState = pxSaTmp->oState;
#ifdef __ENABLE_IKE_XAUTH__
            if (!IS_P1_FINAL_STATE(oState))
#endif
            switch (++oState)
            {
            case STATE_MAIN_I :
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            case STATE_AGGR_R :
            case STATE_AGGR_I : /* non-COMMIT state */
#endif
                break;
            default :
#ifdef __IKE_MULTI_THREADED__
                DPC_DELSA(pTest->bIsGlobalLocked, pxSa, pTest->pxSaDel,
                          pxSaTmp, FALSE, STATUS_IKE_REKEY)
#endif
                IKE_delSa(pxSaTmp, FALSE, STATUS_IKE_REKEY);
                break;
            }
        }
    } /* if */

    *pIsMatch = FALSE; /* find next! */

    return status;
#undef pTest
} /* MatchFinalizeSa */


/*------------------------------------------------------------------*/

extern void
IKE_finalizeSa(IKESA pxSa, ubyte4 timenow)
{
    ubyte4 timedlt = timenow - pxSa->dwTimeCreated;
    intBoolean bMature = IS_MATURE(pxSa);

    if (!timedlt)
    {
        pxSa->merror = OK;

        if (m_ikeSettings.funcPtrIkeStatHdlr)
        {
            m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_SUCCESS,
                                             pxSa->dwId, pxSa, NULL);
        }
    }

    if (bMature || timedlt)
    {
        FreeSa(pxSa); /* free up temp. storage */
    }

    /* find older SA's */
    if (!timedlt ||
        (bMature && (IKE_SA_FLAG_NEW & pxSa->flags)))
    {
        struct ikesa_fs_test saTest;
        saTest.pxSa = pxSa;
#ifdef __IKE_MULTI_THREADED__
        saTest.pxSaDel = NULL;
        saTest.bIsGlobalLocked = RTOS_rwLockOwnerW(g_ikeMtx);
#endif
        saTest.timenow = timenow;
        saTest.timedlt = timedlt;

        IKE_getSaByAddr(REF_MOC_IPADDR(pxSa->dwPeerAddr),
                        NULL, &saTest, MatchFinalizeSa
                        MOC_MTHM_VALUE(pxSa->serverInstance));

#ifdef __IKE_MULTI_THREADED__
        for (pxSa = saTest.pxSaDel; NULL != pxSa;)
        {
            IKESA pxSaDel = pxSa;
            pxSa = pxSa->pNext;
            IKE_delSa(pxSaDel, (IS_IKE_SA_AUTHED(pxSaDel) ? TRUE : FALSE),
                      STATUS_IKE_REKEY);
        }
#endif
    }

    return;
} /* IKE_finalizeSa */


/*------------------------------------------------------------------*/

typedef struct ikesa_test
{
    const ubyte *poCky_I;
    const ubyte *poCky_R;

    intBoolean bIKEv2;
    intBoolean bInitiator;

    MOC_IP_ADDRESS peerAddr;

#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance;
#endif
    void *pData;
    MSTATUS(*funcPtrCheck)(const IKESA sa, void *data);

} *IKESA_TEST;


static MSTATUS
MatchSa(IKESA pxSa, void *pData, intBoolean *pIsMatch)
{
#define pTest ((IKESA_TEST)pData)
    MSTATUS status = OK;
    sbyte4 compareResult;

    *pIsMatch = FALSE;

#ifdef __IKE_MULTI_THREADED__
    if (!pxSa || /* jic */
        (OK > (status = RTOS_rwLockWaitR(m_ikeSaRwLock))))
        goto nocleanup;
#else
    if (!pxSa) goto exit; /* jic */
#endif

    if (!(IKE_SA_FLAG_INUSE & pxSa->flags))
        goto exit;

#ifdef __IKE_MULTI_HOMING__
    if (pTest->serverInstance != pxSa->serverInstance)
        goto exit;
#endif

    /* check IKE version */
    if (pTest->bIKEv2) /* [v2] */
    {
        if (!IS_IKE2_SA(pxSa) ||
            (IS_INITIATOR(pxSa) != pTest->bInitiator))
            goto exit;
    }
    else if (IS_IKE2_SA(pxSa)) goto exit;

    /* check CKY-I */
    if (OK > (status = DIGI_MEMCMP(pTest->poCky_I, pxSa->poCky_I,
                                  IKE_COOKIE_SIZE, &compareResult)))
        goto exit;

    if (0 != compareResult) goto exit;

    if (IKE_isEmptyCky(pxSa->poCky_R))
    {
        /* Note: We initiated this IKE_SA. */
        if (pTest->bIKEv2) ; /* [v2] */
        else if (!SAME_MOC_IPADDR(pTest->peerAddr, pxSa->dwPeerAddr))
            goto exit;
            /* [v1] but a peer may initiate with the same CKY-I. (rare) */
    }
    else if (IKE_isEmptyCky(pTest->poCky_R))
    {
        /* Note: (rare) If this IKE_SA is initiated by a peer, it's
           possible for other peers to initiate with the same
           CKY-I.
         */
        if (pTest->bIKEv2) /* [v2] */
        {
            if (!IS_INITIATOR(pxSa) &&
                !SAME_MOC_IPADDR(pTest->peerAddr, pxSa->dwPeerAddr))
                goto exit;
        }
        else
        {
            /* [v1] If this IKE_SA is initiated by us, the 2nd message
               (from the peer) has already been received by us, so
               consider this a new message.
             */
            if (IS_INITIATOR(pxSa) ||
                !SAME_MOC_IPADDR(pTest->peerAddr, pxSa->dwPeerAddr))
                goto exit;
        }
    }
    else
    {
        /* check CKY-R */
        if (OK > (status = DIGI_MEMCMP(pTest->poCky_R, pxSa->poCky_R,
                                      IKE_COOKIE_SIZE, &compareResult)))
            goto exit;

        if (0 != compareResult)
        {
            if (pTest->bIKEv2 && IS_INITIATOR(pxSa)) /* [v2] */
                status = ERR_IKE_GETSA_FAIL; /* FOR NOW */
            goto exit;
        }
    }

    if (pTest->funcPtrCheck &&
        (OK > (status = pTest->funcPtrCheck(pxSa, pTest->pData))))
        goto exit;

    *pIsMatch = TRUE; /* found */

exit:
#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockReleaseR(m_ikeSaRwLock);

nocleanup:
#endif
    return status;
#undef pTest
} /* MatchSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getSa(ubyte *poCky_I, ubyte *poCky_R, sbyte4 flag, MOC_IP_ADDRESS peerAddr,
          IKESA *ppxSa, void *pExtraData,
          MSTATUS(*funcPtrExtraCheck)(const IKESA sa, void *data)
          MOC_MTHM(serverInstance))
{
    MSTATUS status = OK;

    sbyte4 i;
    IKESA pxSa = NULL;
    intBoolean isMatch = FALSE;

    struct ikesa_test saTest = { NULL };

    saTest.poCky_I = poCky_I;
    saTest.poCky_R = poCky_R;

    if (flag) /* [v2] */
    {
        saTest.bIKEv2 = TRUE;
        saTest.bInitiator = (((1 << _I) & flag) ? TRUE : FALSE);
    }

    saTest.peerAddr = peerAddr;
#ifdef __IKE_MULTI_HOMING__
    saTest.serverInstance = serverInstance;
#endif
    saTest.pData = pExtraData;
    saTest.funcPtrCheck = funcPtrExtraCheck;

    if (ppxSa) *ppxSa = NULL;

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    LOCK_HASH_CKY_R;
    if (m_hashTableCky)
    {
        ubyte4 hashValue;
        HASH_VALUE_hashGen(poCky_I, IKE_COOKIE_SIZE,
                           IKE_SA_CKY_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                         | serverInstance
#endif
                         , &hashValue);

        if (OK > (status = HASH_TABLE_findPtr(m_hashTableCky,
                                              hashValue, &saTest,
                                              (funcPtrExtraMatchTest)MatchSa,
                                              (void **)&pxSa, &isMatch)))
        {
            UNLOCK_HASH_CKY_R;
            goto exit;
        }
        UNLOCK_HASH_CKY_R;
    }
    else
    {
        UNLOCK_HASH_CKY_R;
#endif
        for (i=0; i < m_ikeSaNum; i++, pxSa = NULL)
        {
            GET_NEXT_ELEMENT(pxSa, i)

            if (OK > (status = MatchSa(pxSa, &saTest, &isMatch)))
                goto exit;

            if (isMatch) break;
        }
#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
    }
#endif

    if (isMatch && pxSa) /* found */
    {
        if (ppxSa) *ppxSa = pxSa;

#ifndef __IKE_MULTI_THREADED__
        if ((IKE_SA_FLAG_DELETED & pxSa->flags)) /* already deleted */
        {
            if (ppxSa) *ppxSa = NULL;
            status = ERR_IKE_GETSA_FAIL;
        }
        else if ((!flag && /* or just expired [v1] */
             IKE_checkExpSa(RTOS_deltaMS(&gStartTime, NULL), pxSa)))
        {
            status = ERR_IKE_GETSA_FAIL;
        }
#endif
    }

exit:
    return status;
} /* IKE_getSa */


/*------------------------------------------------------------------*/

typedef struct ikesa_addr_test
{
    MOC_IP_ADDRESS peerAddr;

#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance;
#endif
    void *pData;
    MSTATUS(*funcPtrMatch)(IKESA sa, void *data, intBoolean *match);

} *IKESA_ADDR_TEST;


static MSTATUS
MatchSaAddr(IKESA pxSa, void *pData, intBoolean *pIsMatch)
{
#define pTest ((IKESA_ADDR_TEST)pData)
    MSTATUS status = OK;

#ifdef __IKE_MULTI_THREADED__
    intBoolean bIsGlobalLocked;
#endif
    *pIsMatch = FALSE;

#ifdef __IKE_MULTI_THREADED__
    if (!pxSa || /* jic */
        ((FALSE == (bIsGlobalLocked = RTOS_rwLockOwnerW(g_ikeMtx))) &&
         (OK > (status = RTOS_rwLockWaitR(m_ikeSaRwLock)))))
    {
        goto nocleanup;
    }
#else
    if (!pxSa) goto exit; /* jic */
#endif

    if (!IS_VALID(pxSa) ||
#ifdef __IKE_MULTI_HOMING__
        (pTest->serverInstance != pxSa->serverInstance) ||
#endif
        !SAME_MOC_IPADDR(pTest->peerAddr, pxSa->dwPeerAddr))
    {
        goto exit;
    }

    if (pTest->funcPtrMatch)
    {
        status = pTest->funcPtrMatch(pxSa, pTest->pData, pIsMatch);
        goto exit;
    }

    *pIsMatch = TRUE;

exit:
#ifdef __IKE_MULTI_THREADED__
    if (FALSE == bIsGlobalLocked)
        RTOS_rwLockReleaseR(m_ikeSaRwLock);

nocleanup:
#endif
    return status;
#undef pTest
} /* MatchSaAddr */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getSaByAddr(MOC_IP_ADDRESS peerAddr, IKESA *ppxSa,void *pExtraData,
                MSTATUS(*funcPtrExtraMatch)(IKESA sa, void *data, intBoolean *match)
                MOC_MTHM(serverInstance))
{
    MSTATUS status = OK;

    sbyte4 i;
    IKESA pxSa = NULL;
    intBoolean isMatch = FALSE;

    struct ikesa_addr_test saTest = { 0 };

    saTest.peerAddr = peerAddr;
#ifdef __IKE_MULTI_HOMING__
    saTest.serverInstance = serverInstance;
#endif
    saTest.pData = pExtraData;
    saTest.funcPtrMatch = funcPtrExtraMatch;

    if (ppxSa) *ppxSa = NULL;

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    LOCK_HASH_ADDR_R;
    if (m_hashTableAddr)
    {
        ubyte4 hashValue;

#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == peerAddr->family)
            HASH_VALUE_hashGen(GET_MOC_IPADDR6(peerAddr), 16,
                               IKE_SA_ADDR_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                             | serverInstance
#endif
                             , &hashValue);
        else
#endif
        {
            ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);
            HASH_VALUE_hashWord(&dwPeerAddr, 1,
                                IKE_SA_ADDR_INIT_HASH_VALUE
#ifdef __IKE_MULTI_HOMING__
                              | serverInstance
#endif
                              , &hashValue);
        }

        if (OK > (status = HASH_TABLE_findPtr(m_hashTableAddr,
                                              hashValue, &saTest,
                                              (funcPtrExtraMatchTest)MatchSaAddr,
                                              (void **)&pxSa, &isMatch)))
        {
            UNLOCK_HASH_ADDR_R;
            goto exit;
        }
        UNLOCK_HASH_ADDR_R;
    }
    else
    {
        UNLOCK_HASH_ADDR_R;
#endif
        for (i=0; i < m_ikeSaNum; i++, pxSa = NULL)
        {
            GET_NEXT_ELEMENT(pxSa, i)

            if (OK > (status = MatchSaAddr(pxSa, &saTest, &isMatch)))
                goto exit;

            if (isMatch) break;
        }
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
    }
#endif

    if (isMatch && ppxSa) *ppxSa = pxSa; /* found */

exit:
    return status;
} /* IKE_getSaByAddr */


/*------------------------------------------------------------------*/

#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK

static MSTATUS
MatchSaId(IKESA pxSa, void *pData, intBoolean *pIsMatch)
{
    *pIsMatch = FALSE;

    if (!pxSa || /* jic */
        !(IKE_SA_FLAG_INUSE & pxSa->flags) ||
        (*((ubyte4 *)pData) != pxSa->dwId))
    {
        goto exit;
    }

    *pIsMatch = TRUE;

exit:
    return OK;
} /* MatchSaId */

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getSaById(ubyte4 dwId, sbyte4 loc, IKESA *ppxSa)
{
    MSTATUS status = OK;
    IKESA pxSa = NULL, pxSaOld = NULL;

    if (ppxSa) *ppxSa = NULL;
    if (!dwId || !m_ikeSaNum) goto exit; /* jic */

    if ((0 > loc) || (loc >= m_ikeSaNum)) /* invalid locator */
    {
#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
        if (m_hashTableId)
        {
            intBoolean isMatch = FALSE;

            ubyte4 hashValue;
            HASH_VALUE_hashGen(&dwId, sizeof(dwId),
                               IKE_SA_ID_INIT_HASH_VALUE, &hashValue);

            if (OK > (status = HASH_TABLE_findPtr(m_hashTableId,
                                                  hashValue, &dwId,
                                                  (funcPtrExtraMatchTest)MatchSaId,
                                                  (void **)&pxSa, &isMatch)))
            {
                goto exit;
            }
        }
        else
#endif
        {
            sbyte4 i;

            loc = ((sbyte4)(0x7fffffff & dwId) % IKE_SA_MAX) - m_ikeSaLoc;
            if (0 > loc) loc += IKE_SA_MAX;
            loc = loc % m_ikeSaNum;

            for (i=0; i < m_ikeSaNum; i++, pxSa = NULL)
            {
                GET_NEXT_ELEMENT(pxSa, loc)

                if ((IKE_SA_FLAG_INUSE & pxSa->flags) &&
                    (dwId == pxSa->dwId))
                {
                    break; /* found */
                }
                loc = (loc + 1) % m_ikeSaNum;
            }
        }
    }
    else
    {
        GET_ELEMENT(pxSa, loc)
    }

    for (;;)
    {
        if ((NULL == pxSa) ||
            !(IKE_SA_FLAG_INUSE & pxSa->flags) ||
            ((dwId != pxSa->dwId) && (dwId != pxSa->dwId0)))
        {
            if (NULL == (pxSa = pxSaOld))
                goto exit;
        }
        else if (IKE_SA_FLAG_REKEYED & pxSa->flags)
        {
            /* note: established IKE_SA only!!! */
            if (!IS_IKE2_SA(pxSa))
                dwId = pxSa->dwSaRekeyId;
            else
                dwId = pxSa->dwId0;

            pxSaOld = pxSa;
            pxSa = pxSa->pxSaRekey;
            continue;
        }

        break;
    } /* for */

    if (pxSa) /* found - jic */
    {
        if (ppxSa) *ppxSa = pxSa;

        if (IKE_SA_FLAG_DELETED & pxSa->flags) /* deleted */
        {
            status = ERR_IKE_GETSA_FAIL;
        }
    }

exit:
    return status;
} /* IKE_getSaById */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getSaByLoc(sbyte4 loc, IKESA *ppxSa)
{
    MSTATUS status = OK;
    IKESA pxSa = NULL;

    if (NULL == ppxSa)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppxSa = NULL;

    GET_ELEMENT(pxSa, loc)
    *ppxSa = pxSa;

exit:
    return status;
} /* IKE_getSaByLoc */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
static void
XchgExpTimerEvent(sbyte4 i, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    P2XG pxXg;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId))
    {
        EXIT_SA
    }
#endif

    pxXg = &(pxSa->u.v1.p2Xg[i]);
    if (!IS_VALID_XCHG(pxXg))
    {
        EXIT_SA
    }
    if (timerId != pxXg->expTimerId)
    {
        EXIT_SA
    }

#ifdef __IKE_MULTI_THREADED__

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = XchgExpTimerEvent;
            evt.cookie = i;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxXg->expTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxXg->expTimerHdl = (IKE_TIMER_HDL_T)NULL;

    IKE_delXchg(pxXg, pxSa, ERR_IKE_TIMEOUT); /* delete it */

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* XchgExpTimerEvent */
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_newXchg(IKESA pxSa, ubyte4 dwMsgId, P2XG *ppxXg)
{
    MSTATUS status = OK;

    P2XG pxXg = NULL, pxXgDel = NULL;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;

#ifdef __ENABLE_DIGICERT_HARNESS__
    ubyte* poIv/*[IKE_IV_MAX]*/ = NULL;
#endif
    sbyte4 i;
#ifdef __IKE_UPDATE_TIMER__
    sbyte4 cookie = -1;
#endif
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx;

    if (OK > (status = IKE_getHwAccelChannel(&hwAccelCtx)))
        goto nocleanup;
#endif

    /* find available slot */
    for (i=0; i < IKE_P2_MAX; i++, pxXg = NULL)
    {
        pxXg = &(pxSa->u.v1.p2Xg[i]);

        if (!(IKE_XCHG_FLAG_INUSE & pxXg->x_flags))
        {
#ifdef __IKE_UPDATE_TIMER__
            cookie = i;
#endif
            goto _init; /* unused */
        }

        if (!(IKE_XCHG_FLAG_DELETED & pxXg->x_flags))
        {
            if (timeout > (timenow - pxXg->dwTimeStart))
                continue;

            IKE_delXchg(pxXg, pxSa, ERR_IKE_TIMEOUT); /* expired, delete it */
        }

        /* deleted */
        if ((NULL == pxXgDel) ||
            ((timenow - pxXg->dwTimeStart) > (timenow - pxXgDel->dwTimeStart)))
        {
            pxXgDel = pxXg;
#ifdef __IKE_UPDATE_TIMER__
            cookie = i;
#endif
        }
    }

    if (NULL == (pxXg = pxXgDel))
    {
        status = ERR_IKE_NEWSA_FAIL;
        goto exit; /* not found */
    }

     /* prevent replay attack */
#ifdef IKE_P2_REPLAY_SIZE
    pxSa->u.v1.pdwMsgId[pxSa->u.v1.msgRplyIdx] = pxXg->dwMsgId;
    if (IKE_P2_REPLAY_SIZE <= ++(pxSa->u.v1.msgRplyIdx))
        pxSa->u.v1.msgRplyIdx = 0;
#endif

    /* clean up */
    DIGI_MEMSET((ubyte *)pxXg, 0x00, sizeof(struct p2xg));

_init:
    /* iv */
    pxXg->dwMsgId = dwMsgId;

    _CRYPTO_ALLOC_(hwAccelCtx, poIv, IKE_IV_MAX)

    if (OK != (status = IKE_newSaIv(MOC_HASH(hwAccelCtx) pxSa,
                                    &(pxXg->dwMsgId),
#ifndef __ENABLE_DIGICERT_HARNESS__
                                    pxXg->
#endif
                                          poIv)))
        goto exit;

#ifdef __ENABLE_DIGICERT_HARNESS__
    DIGI_MEMCPY(pxXg->poIv, poIv, pxSa->pCipherSuite->wIvLen);
#endif
    DIGI_MEMCPY(pxXg->poIvOld, pxXg->poIv, pxSa->pCipherSuite->wIvLen);

#ifdef __IKE_UPDATE_TIMER__
    if (OK > (status = IKE_ADD_TIMER_EVT(timeout, cookie, pxSa,
                                         XchgExpTimerEvent, "TO2",
                                         pxXg->expTimerId, pxXg->expTimerHdl)))
    {
        goto exit;
    }
#endif

    /* done */
    if (0 == dwMsgId)
        pxXg->x_flags |= IKE_XCHG_FLAG_INITIATOR;
    pxXg->x_flags |= IKE_XCHG_FLAG_INUSE;
    pxXg->dwTimeStart = timenow;
    *ppxXg = pxXg;
    pxXg = NULL;

exit:
    if (NULL != pxXg)
    {
        DIGI_MEMSET((ubyte*)pxXg, 0x00, sizeof(struct p2xg));
    }
    _CRYPTO_FREE_(hwAccelCtx, poIv)

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    IKE_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
#endif
    return status;
} /* IKE_newXchg */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_newIPsecSa(IKESA pxSa, ubyte4 dwMsgId, P2XG *ppxXg)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = NULL;
    P2XG pxXg = NULL;

    intBoolean bInitiator = (0 == dwMsgId);

#ifdef __IKE_SADB_MALLOC__
    if (NULL == (pxIPsecSa = (IPSECSA) MALLOC(sizeof(struct ipsecsa))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pxIPsecSa, 0x00, sizeof(struct ipsecsa)); /* clean up */
#endif

    /* create new exchange */
    if (OK > (status = IKE_newXchg(pxSa, dwMsgId, &pxXg)))
        goto exit;

    /* initialize */
#ifdef __IKE_SADB_MALLOC__
    pxXg->pxIPsecSa = pxIPsecSa;
#else
    pxIPsecSa = &(pxXg->ipsecSa);
#endif

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    if ((IKE_SA_FLAG_GDOI | IKE_SA_FLAG_GDOI_PUSH) & pxSa->flags)
    {
        intBoolean bPush = (IKE_SA_FLAG_GDOI_PUSH & pxSa->flags) ? TRUE : FALSE;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (bInitiator && !bPush)
        {
            pxIPsecSa->oState = (ubyte)STATE_GPULL_I1;
        }
        else if (!bInitiator && bPush)
        {
            pxIPsecSa->oState = (ubyte)STATE_GPUSH_R1;
        }
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        if (!bInitiator && !bPush)
        {
            pxIPsecSa->oState = (ubyte)STATE_GPULL_R1;
        }
        else if (bInitiator && bPush)
        {
            pxIPsecSa->oState = (ubyte)STATE_GPUSH_I1;
        }
#endif
        pxXg->oState = pxIPsecSa->oState;
    }
    else
#endif
    {
        pxXg->oState =
        pxIPsecSa->oState = (ubyte)((bInitiator) ? STATE_QUICK_I1 : STATE_QUICK_R1);
    }

#ifdef CUSTOM_IKE_GET_P2_PFS
    if (OK > (status = IKE_customDhGroups(&pxIPsecSa->pwDhGrps,
                                          &pxIPsecSa->numDhGrps,
                                          bInitiator, NULL, pxSa)))
        goto exit;
#endif

    if (bInitiator)
    {
        pxIPsecSa->c_flags |= IKE_CHILD_FLAG_INITIATOR;

    /* PFS */
#ifdef CUSTOM_IKE_GET_P2_PFS
        if (0 < pxIPsecSa->numDhGrps)
        {
            pxIPsecSa->wPFS = pxIPsecSa->pwDhGrps[0];
        }
        else
#endif
        if (OAKLEY_GROUP_DEFAULT ==
            (pxIPsecSa->wPFS = pxSa->ikePeerConfig->ikeP2PFS))
        {
            pxIPsecSa->wPFS = pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION]; /* use P1 DH group */
        }
    }

    /* nonce */
    if (bInitiator)
    {
        pxIPsecSa->poNi_b = pxIPsecSa->poNonce;
        pxIPsecSa->wNi_bLen = IKE_NONCE_SIZE;
    }
    else
    {
        pxIPsecSa->poNr_b = pxIPsecSa->poNonce;
        pxIPsecSa->wNr_bLen = IKE_NONCE_SIZE;
    }
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, pxIPsecSa->poNonce, IKE_NONCE_SIZE)))
        goto exit;

    /* done */
    pxIPsecSa->dwTimeStart = pxXg->dwTimeStart;
    pxIPsecSa->c_flags |= IKE_CHILD_FLAG_INUSE;
    pxIPsecSa = NULL;

    *ppxXg = pxXg;
    pxXg = NULL;

exit:
#ifdef CUSTOM_IKE_GET_P2_PFS
    if ((NULL != pxIPsecSa) && (NULL != pxIPsecSa->pwDhGrps))
        FREE(pxIPsecSa->pwDhGrps);
#endif
#ifdef __IKE_SADB_MALLOC__
    if (NULL != pxIPsecSa) FREE(pxIPsecSa);
#endif
    if (NULL != pxXg)
        DIGI_MEMSET((ubyte*)pxXg, 0x00, sizeof(struct p2xg));

    return status;
} /* IKE_newIPsecSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getXchg(IKESA pxSa, ubyte4 dwMsgId, P2XG *ppxXg)
{
    MSTATUS status = ERR_IKE_GETSA_FAIL;

    P2XG pxXg = NULL;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;

    sbyte4 i;
    for (i=0; i < IKE_P2_MAX; i++, pxXg = NULL)
    {
        pxXg = &(pxSa->u.v1.p2Xg[i]);

        if ((IKE_XCHG_FLAG_INUSE & pxXg->x_flags) &&
            (dwMsgId == pxXg->dwMsgId))
        {
            /* found */
            if (IKE_XCHG_FLAG_DELETED & pxXg->x_flags) /* already deleted */
                goto exit;
            else
            {
                if (timeout < (timenow - pxXg->dwTimeStart)) /* expired */
                {
                    IKE_delXchg(pxXg, pxSa, ERR_IKE_TIMEOUT); /* delete it */
                    goto exit;
                }
                else if (IS_QUICK_MODE_STATE(pxXg->oState))
                {
                    IPSECSA pxIPsecSa = P2XG_IPSECSA(pxXg);
                    if (IKE_CHILD_FLAG_DELETED & pxIPsecSa->c_flags) /* jic */
                    {
                        /* quick mode exchange already deleted (e.g. "ike_event.c") */
                        IKE_delXchg(pxXg, pxSa, OK);
                        goto exit;
                    }
                }
            }
            break;
        }
    }

#ifdef IKE_P2_REPLAY_SIZE
    if (NULL == pxXg)
    {
        ubyte4 *pdwMsgId = pxSa->u.v1.pdwMsgId;

        for (i=0; i < IKE_P2_REPLAY_SIZE; i++)
        {
            /* Note: dwMsgId != 0 */
            if (dwMsgId == pdwMsgId[i]) goto exit;
        }
    }
#endif

    status = OK;

exit:
    *ppxXg = pxXg;
    return status;
} /* IKE_getXchg */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_delIPsecSa(IPSECSA pxIPsecSa, IKESA pxSa)
{
    MSTATUS status = OK;

    ubyte oState = pxIPsecSa->oState;

    /* reset event, if applicable */
    IKEEVT_EX pxEvt = pxIPsecSa->pxEvt;
    if (NULL != pxEvt) /* initiator only */
    {
        if ((pxEvt->dwId == pxIPsecSa->dwEvtId) &&
            (pxEvt->pxIPsecSa == pxIPsecSa)) /* jic */
        {
            ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

            if (IS_P2_FINAL_STATE(oState))
            {
                /* prevent re-keying for a brief time */
                ubyte4 timeout = 1000 * m_ikeSettings.ikeTimeoutEvent;
                pxEvt->dwTimeQueued = timenow - timeout + 10000; /* 10 secs - FOR NOW */
#ifdef __IKE_UPDATE_TIMER__
                IKE_DEL_TIMER_EVT(pxEvt->expTimerId, pxEvt->expTimerHdl)

                if (OK > IKE_ADD_TIMER_EVT(10000, 0, pxEvt,
                                           IKE_evtExpTimerEvent, "TOE",
                                           pxEvt->expTimerId, pxEvt->expTimerHdl))
                {
                    debug_printnl("Failed to schedule timer for event timeout.");
                }
#endif
            }
            else
            {
                /* special case - detection of dead IKE SA */
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                if (pxSa && ((STATE_QUICK_I2 == oState) || (STATE_GPULL_I2 == oState)))
#else
                if (pxSa && (STATE_QUICK_I2 == oState))
#endif
                {
                    if (IS_IKE2_SA(pxSa) ||
                        !IS_MATURE(pxSa) ||
                        ((timenow - pxSa->dwTimeStamp) >
                         (timenow - pxIPsecSa->dwTimeStart)))
                    {
                        /* will rekey or use a more recent IKE SA */
                        pxEvt->dwOldIkeSaId = pxSa->dwId;
                    }
                }
                pxEvt->flags &= ~(IKE_EVENT_FLAG_INXCHG);
#ifdef __IKE_UPDATE_TIMER__
                IKE_DEL_TIMER_EVT(pxEvt->initTimerId, pxEvt->initTimerHdl) /* jic */

                if (OK > IKE_ADD_TIMER_EVT(1000, 1000, pxEvt,
                                           IKE_evtInitTimerEvent, "RTE",
                                           pxEvt->initTimerId, pxEvt->initTimerHdl))
                {
                    debug_printnl("Failed to schedule timer for event initiation.");
                }
#endif
            }

            pxEvt->pxIPsecSa = NULL;
        }

        pxIPsecSa->pxEvt = NULL; /* jic */
    }

    if (IS_VALID_CHILD(pxIPsecSa) && /* jic */
        !IS_P2_FINAL_STATE(oState) &&
        m_ikeSettings.funcPtrIkeStatHdlr)
    {
        m_ikeSettings.funcPtrIkeStatHdlr(ISC_CHILDSA, IST_FAIL,
                        pxIPsecSa->axP2Sa[0].dwSeqNo,
                        pxIPsecSa, pxSa);
    }

    /* free up space */
    if (NULL != pxIPsecSa->poNi_b)
    {
        if (pxIPsecSa->poNi_b != pxIPsecSa->poNonce)
            FREE(pxIPsecSa->poNi_b);
        pxIPsecSa->poNi_b = NULL;
        pxIPsecSa->wNi_bLen = 0;
    }
    if (NULL != pxIPsecSa->poNr_b)
    {
        if (pxIPsecSa->poNr_b != pxIPsecSa->poNonce)
            FREE(pxIPsecSa->poNr_b);
        pxIPsecSa->poNr_b = NULL;
        pxIPsecSa->wNr_bLen = 0;
    }

    if (NULL != pxIPsecSa->p_dhContext)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxIPsecSa->p_dhContext), NULL, NULL);
#else
        DH_freeDhContext(&(pxIPsecSa->p_dhContext), NULL);
#endif
    }

    if (NULL != pxIPsecSa->pDhPeerPubKey)
    {
        FREE(pxIPsecSa->pDhPeerPubKey);
        pxIPsecSa->pDhPeerPubKey = NULL;
        pxIPsecSa->dhPeerPubKeyLen = 0;
    }

    if (NULL != pxIPsecSa->pDhSharedSecret)
    {
        DIGI_MEMSET(pxIPsecSa->pDhSharedSecret, 0, pxIPsecSa->dhSharedSecretLen);
        FREE(pxIPsecSa->pDhSharedSecret);
        pxIPsecSa->pDhSharedSecret = NULL;
        pxIPsecSa->dhSharedSecretLen = 0;
    }

#ifdef CUSTOM_IKE_GET_P2_PFS
    if (NULL != pxIPsecSa->pwDhGrps)
    {
        FREE(pxIPsecSa->pwDhGrps);
        pxIPsecSa->pwDhGrps = NULL;
        pxIPsecSa->numDhGrps = 0;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pxIPsecSa->p_eccKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxIPsecSa->p_eccKey));
#else
        EC_deleteKey(&(pxIPsecSa->p_eccKey));
#endif
    }

    if (NULL != pxIPsecSa->poEccSharedSecret)
    {
        DIGI_MEMSET(pxIPsecSa->poEccSharedSecret, 0x00, pxIPsecSa->eccSharedSecretLen);
        FREE(pxIPsecSa->poEccSharedSecret);
        pxIPsecSa->poEccSharedSecret = NULL;
        pxIPsecSa->eccSharedSecretLen = 0;
    }
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pxIPsecSa->pQsCtx)
    {
        CRYPTO_INTERFACE_QS_deleteCtx(&(pxIPsecSa->pQsCtx));
    }

    if (NULL != pxIPsecSa->pQsCipherText)
    {
        DIGI_MEMSET(pxIPsecSa->pQsCipherText, 0x00, pxIPsecSa->qsCipherTextLen);
        FREE(pxIPsecSa->pQsCipherText);
        pxIPsecSa->pQsCipherText = NULL;
        pxIPsecSa->qsCipherTextLen = 0;
    }

    if (NULL != pxIPsecSa->pQsSharedSecret)
    {
        DIGI_MEMSET(pxIPsecSa->pQsSharedSecret, 0x00, pxIPsecSa->qsSharedSecretLen);
        FREE(pxIPsecSa->pQsSharedSecret);
        pxIPsecSa->pQsSharedSecret = NULL;
        pxIPsecSa->qsSharedSecretLen = 0;
    }
#endif

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (NULL != pxIPsecSa->axP2Sa[0].axChildSa[0].pxIPsecPps)
    {
        FREE(pxIPsecSa->axP2Sa[0].axChildSa[0].pxIPsecPps);
        pxIPsecSa->axP2Sa[0].axChildSa[0].pxIPsecPps = NULL;
        pxIPsecSa->axP2Sa[0].axChildSa[0].oIPsecPpsNum = 0;
    }
#endif

    pxIPsecSa->c_flags |= IKE_CHILD_FLAG_DELETED;

    return status;
} /* IKE_delIPsecSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_delXchg(P2XG pxXg, IKESA pxSa, MSTATUS merror)
{
    MSTATUS status = OK;

    ubyte oState = pxXg->oState;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(pxXg);

#ifdef __IKE_SADB_MALLOC__
    if (NULL != pxIPsecSa) /* jic */
    {
#endif
        if (IS_VALID_CHILD(pxIPsecSa) &&
            IS_QUICK_MODE_STATE(oState)) /* quick mode */
        {
            if (merror && !pxIPsecSa->merror &&
                !IS_P2_FINAL_STATE(pxIPsecSa->oState))
                pxIPsecSa->merror = merror;

            status = IKE_delIPsecSa(pxIPsecSa, pxSa);
        }
#ifdef __IKE_SADB_MALLOC__
        FREE(pxIPsecSa);
        pxXg->pxIPsecSa = NULL;
    }
#endif

    /* IKECFG */
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
    if (IS_VALID_XCHG(pxXg) &&
        IS_IKECFG_STATE(oState))
    {
        switch (oState)
        {
        case STATE_CFG_I :
        case STATE_CFG_R :
#ifdef __ENABLE_IKE_XAUTH__
        case STATE_CFG_Ixc :
        case STATE_CFG_Ix :
        case STATE_CFG_Rx : /* draft-ietf-ipsec-isakmp-xauth-01...02 (CFG_AUTH_OK/FAILED) */
#endif
            break;
        default :
            if (merror && !pxXg->merror)
                pxXg->merror = merror;

            if (m_ikeSettings.funcPtrIkeStatHdlr)
                m_ikeSettings.funcPtrIkeStatHdlr(ISC_CFG, IST_FAIL,
                                (ubyte4) pxXg->wCfgId, pxXg, pxSa);
            break;
        }
    }

    if (NULL != pxXg->poCfgAttrs)
    {
        FREE(pxXg->poCfgAttrs);
        pxXg->poCfgAttrs = NULL;
        pxXg->wCfgAttrsLen = 0;
    }
#endif

#ifdef __IKE_UPDATE_TIMER__
    IKE_DEL_TIMER_EVT(pxXg->expTimerId, pxXg->expTimerHdl)

    IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
    pxXg->rtxCount = 0;

    if (NULL != pxXg->poRtxMsg)
    {
        FREE(pxXg->poRtxMsg);
        pxXg->poRtxMsg = NULL;
    }
    pxXg->dwRtxMsgLen = 0;
#endif

    pxXg->x_flags |= IKE_XCHG_FLAG_DELETED;

    return status;
} /* IKE_delXchg */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_findPps(IPSECSA pxIPsecSa, ubyte oProtoId, ubyte4 dwSpi)
{
    sbyte4 i, j;

    for (i = pxIPsecSa->oP2SaNum - 1; i >= 0; i--)
    {
        for (j = pxIPsecSa->axP2Sa[i].oChildSaLen - 1; j >= 0; j--)
        {
            IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);

            if ((oProtoId == pxIPsecPps->oProtocol) &&
                ((dwSpi == pxIPsecPps->dwSpi[_R]) ||
                 (dwSpi == pxIPsecPps->dwSpi[_I])))
            {
                goto exit; /* found */
            }
        }
    }

exit:
    return i;
} /* IKE_findPps */


/*------------------------------------------------------------------*/

extern IPSECSA
IKE_findIPsecSa(IKESA pxSa, ubyte oProtoId, ubyte4 dwSpi)
{
    IPSECSA pxIPsecSa = NULL;

    sbyte4 i;
    for (i=0; i < IKE_P2_MAX; i++, pxIPsecSa = NULL)
    {
        P2XG pxXg = &(pxSa->u.v1.p2Xg[i]);

        if (IS_VALID_XCHG(pxXg) &&
            IS_QUICK_MODE_STATE(pxXg->oState))
        {
            pxIPsecSa = P2XG_IPSECSA(pxXg);

            if (IS_VALID_CHILD(pxIPsecSa) &&
                IS_P2_FINAL_STATE(pxIPsecSa->oState))
            {
                if (0 <= IKE_findPps(pxIPsecSa, oProtoId, dwSpi))
                    break;
            }
        }
    }

    return pxIPsecSa;
} /* IKE_findIPsecSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_newSaIv(MOC_HASH(hwAccelDescr hwAccelCtx) IKESA pxSa, ubyte4 *pdwMsgId, ubyte *poIv)
{
    /* calculate iv for quick mode and informational exchange */
    MSTATUS status;

    BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    BulkCtx hashCtxt = NULL;

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    intBoolean hasHwAccelCtx = FALSE;

    if (0 == hwAccelCtx)
    {
        if (OK > (status = IKE_getHwAccelChannel(&hwAccelCtx)))
            goto nocleanup;

        hasHwAccelCtx = TRUE;
    }
#endif

    if (0 == *pdwMsgId)
    {
        if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, (ubyte *)pdwMsgId, sizeof(ubyte4))))
            goto exit;
    }

    if (OK > (status = pBHAlgo->allocFunc(MOC_HASH(hwAccelCtx) &hashCtxt)) ||
        OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) hashCtxt)) ||
        OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) hashCtxt, pxSa->u.v1.poIv, pxSa->pCipherSuite->wIvLen)) ||
        OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) hashCtxt, (ubyte *)pdwMsgId, sizeof(ubyte4))) ||
        OK > (status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) hashCtxt, poIv)))
        goto exit;

exit:
    pBHAlgo->freeFunc(MOC_HASH(hwAccelCtx) &hashCtxt);

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hasHwAccelCtx)
        IKE_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
#endif
    return status;
} /* IKE_newSaIv */


/*------------------------------------------------------------------*/

/*
IPsec                   IKE

IPPROTO_AH              PROTO_IPSEC_AH
IPPROTO_ESP             PROTO_IPSEC_ESP

IPSEC_AUTHALG_MD5       AUTH_ALGORITHM_HMAC_MD5     AH_MD5
IPSEC_AUTHALG_SHA1      AUTH_ALGORITHM_HMAC_SHA     AH_SHA

IPSEC_ENCALG_DES                                    ESP_DES
IPSEC_ENCALG_3DES                                   ESP_3DES
IPSEC_ENCALG_BLOWFISH                               ESP_BLOWFISH
IPSEC_ENCALG_AES                                    ESP_AES

                                                    ESP_NULL

IPSEC_MODE_TRANSPORT    ENCAPSULATION_MODE_TRANSPORT
IPSEC_MODE_TUNNEL       ENCAPSULATION_MODE_TUNNEL
*/

extern void
IKE_initIPsecKey(IPSECKEY_EX pxKey,
                 IKESA pxSa, IPSECSA pxIPsecSa, IPSECPPS pxIPsecPps,
                 ubyte *poKey, ubyte oSaIndex, sbyte4 iNest, sbyte4 _r)
{
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);
    intBoolean bInbound = ((_r && !bInitiator) || (!_r && bInitiator));
    ubyte2 wKeyLen = 0;

    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(pxSa->pCipherSuite->wTfmId, pxSa->wEncrKeyLen);
#endif


    INIT_MOC_IPADDR(hostAddr, pxSa->dwHostAddr)
    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

    if (bInitiator) pxKey->flags |= IPSEC_SA_FLAG_INITIATOR;
    if (bInbound) pxKey->flags |= IPSEC_SA_FLAG_INBOUND;
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (IKE_SA_FLAG_GDOI & pxSa->flags) pxKey->flags |= IPSEC_SA_FLAG_GDOI;
#endif

    if (IS_IKE2_SA(pxSa))
    {
        pxKey->flags |= IPSEC_SA_FLAG_IKE2;

        if (IKE_CHILD_FLAG_CONNECT2 & pxIPsecSa->c_flags)
            pxKey->flags |= IPSEC_SA_FLAG_CONNECT2;
    }

    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
        pxKey->oProtocol = IPPROTO_AH;
    else if (PROTO_IPSEC_ESP == pxIPsecPps->oProtocol)
        pxKey->oProtocol = IPPROTO_ESP;

    pxKey->dwSpi        = pxIPsecPps->dwSpi[_r];
    pxKey->dwSpiM       = pxIPsecPps->dwSpi[(_r+1)%2];

    pxKey->dwDestAddr   = (bInbound ? hostAddr : peerAddr);
    pxKey->dwSrcAddr    = (bInbound ? peerAddr : hostAddr);

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pxKey->cookie       = pxIPsecSa->axP2Sa[oSaIndex].cookie;
#ifndef __ENABLE_DIGICERT_PFKEY__
    if (!pxKey->cookie) pxKey->cookie = pxSa->cookie;
#endif
#endif

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pxKey->ifid         = pxIPsecSa->axP2Sa[oSaIndex].ifid;
    if (!pxKey->ifid) pxKey->ifid = pxSa->ifid;
#endif

    pxKey->wDestPort    = pxIPsecSa->wPort[_r];
    pxKey->wSrcPort     = pxIPsecSa->wPort[(_r+1)%2];
    pxKey->oUlp         = pxIPsecSa->oUlp;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    switch (pxIPsecPps->wMode)
    {
    case ENCAPSULATION_MODE_TRANSPORT :
        pxKey->oMode    = IPSEC_MODE_TRANSPORT;
        break;
    case ENCAPSULATION_MODE_TUNNEL :
        pxKey->oMode    = IPSEC_MODE_TUNNEL;
        break;
    }
#else
    pxKey->oMode = IPSEC_MODE_TRANSPORT;
#endif

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    if (
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        (IPSEC_MODE_TUNNEL == pxKey->oMode) ||
#else
        ((IPSEC_MODE_TUNNEL == pxKey->oMode)||(IPSEC_MODE_TRANSPORT == pxKey->oMode)) ||
#endif
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        (IKE_SA_FLAG_GDOI & pxSa->flags) ||
#endif
        FALSE)
    {
        pxKey->dwDestIP     = REF_MOC_IPADDR(pxIPsecSa->dwIP[_r]);
        pxKey->dwDestIPEnd  = REF_MOC_IPADDR(pxIPsecSa->dwIPEnd[_r]);

        pxKey->dwSrcIP      = REF_MOC_IPADDR(pxIPsecSa->dwIP[(_r+1)%2]);
        pxKey->dwSrcIPEnd   = REF_MOC_IPADDR(pxIPsecSa->dwIPEnd[(_r+1)%2]);

    }
    else if (IPSEC_MODE_TRANSPORT != pxKey->oMode) /* jic */
    {
        pxKey->dwDestIP = pxKey->dwDestIPEnd = pxKey->dwDestAddr;
        pxKey->dwSrcIP  = pxKey->dwSrcIPEnd = pxKey->dwSrcAddr;
    }
#endif

#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
    if (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags)
        pxKey->flags |= IPSEC_SA_FLAG_ESN;
#endif

    if (pxIPsecPps->oEncrAlgo)
    {
        wKeyLen = pxIPsecPps->wEncrKeyLen;
        CHILDSA_encrInfo *pEncrAlgo =
            CHILDSA_findEncrAlgoWithConstraint(bitStrength, pxIPsecPps->oEncrAlgo, 0, 0, wKeyLen, &wKeyLen);

        if (NULL != pEncrAlgo) /* jic - redundant? */
        {
            pxKey->oEncrAlgo = pEncrAlgo->oEncrAlgo;
            pxKey->poEncrKey = poKey;
            pxKey->wEncrKeyLen = wKeyLen + pEncrAlgo->oNonceLen;
            pxKey->oAeadIcvLen = pEncrAlgo->oTagLen;
            pxKey->oNonceLen = pEncrAlgo->oNonceLen;
        }
    }

    if (pxIPsecPps->wAuthAlgo)
    {
        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(pxIPsecPps->wAuthAlgo, 0, 0, 0);
        if (NULL != pAuthAlgo) /* jic - redundant? */
        {
            pxKey->oAuthAlgo = pAuthAlgo->oAuthAlgo;
            pxKey->wAuthKeyLen = pAuthAlgo->wKeyLen;
            if (NULL != poKey) /* !!! */
            pxKey->poAuthKey = poKey + pxKey->wEncrKeyLen;
        }
    }

#ifdef __ENABLE_DIGICERT_IPCOMP__
    if (pxIPsecPps->oCompAlgo)
    {
        pxKey->oCompAlgo    = pxIPsecPps->oCompAlgo;
        pxKey->wCpi         = pxIPsecPps->wCpi[_r];
        pxKey->wCpiM        = pxIPsecPps->wCpi[(_r+1)%2];
    }
#endif

    pxKey->dwSpdId = pxIPsecSa->axP2Sa[oSaIndex].dwSpdId;
    pxKey->spdIndex = pxIPsecSa->axP2Sa[oSaIndex].spdIndex;
    pxKey->iNest = iNest;

} /* IKE_initIPsecKey */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)

extern void
PrintIPsecKey(IPSECKEY_EX pxKey, MSTATUS st,
#ifndef __ENABLE_DIGICERT_PFKEY__
              sbyte4 spdIndex
#else
              ubyte4 dwSpdId
#endif
              )
{
    debug_print("  ");
    debug_print(((IPPROTO_AH == pxKey->oProtocol) ? "AH" : "ESP"));
    debug_print(" spi=");
    debug_hexint(pxKey->dwSpi);

    debug_print(" ");

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (IPSEC_SA_FLAG_GDOI & pxKey->flags)
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (pxKey->fqdn[0])
        {
            debug_print(pxKey->fqdn);
        }
        else
#endif
        {
            INIT_MOC_IPADDR(destIP, pxKey->dwDestIP)
            debug_print_ip(destIP);
            if (!SAME_MOC_IPADDR(destIP, pxKey->dwDestIPEnd))
            {
                debug_print("~");
                debug_print_ip(REF_MOC_IPADDR(pxKey->dwDestIPEnd));
            }
        }
    }
    else
#endif
    debug_print_ip(pxKey->dwDestAddr);

    if (0 != pxKey->wDestPort)
    {
        debug_print("[");
        debug_int(pxKey->wDestPort);
        debug_print("]");
    }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TRANSPORT != pxKey->oMode)
        debug_print(" << ");
    else
#endif
    debug_print(" < ");

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (IPSEC_SA_FLAG_GDOI & pxKey->flags)
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (pxKey->fqdn[0])
        {
            debug_print_ip(pxKey->dwSrcIP);
        }
        else
#endif
        {
            INIT_MOC_IPADDR(srcIP, pxKey->dwSrcIP)
            debug_print_ip(srcIP);
            if (!SAME_MOC_IPADDR(srcIP, pxKey->dwSrcIPEnd))
            {
                debug_print("~");
                debug_print_ip(REF_MOC_IPADDR(pxKey->dwSrcIPEnd));
            }
        }
    }
    else
#endif
    debug_print_ip(pxKey->dwSrcAddr);

    if (0 != pxKey->wSrcPort)
    {
        debug_print("[");
        debug_int(pxKey->wSrcPort);
        debug_print("]");
    }

    if (0 != pxKey->oUlp)
    {
        debug_print(" ");
        debug_print_ip_proto(pxKey->oUlp);
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if (0 != pxKey->wUdpEncPort)
    {
        debug_print(" udp-enc");
        if (IKE_NAT_UDP_PORT != pxKey->wUdpEncPort)
        {
            debug_print("[");
            debug_int(pxKey->wUdpEncPort);
            debug_print("]");
        }
        if (IPSEC_SA_FLAG_NAT_PEER & pxKey->flags)
            debug_print("*");
    }
#endif
    debug_printnl(NULL);

    if (OK > st)
    {
#ifndef __ENABLE_DIGICERT_PFKEY__
        sbyte4 spdIndexRet = (pxKey->spdIndex & 0x7fffffff);
        if (spdIndexRet) /* SPD index */
        {
            debug_print("  spd=");
            debug_int(spdIndexRet);
            debug_printnl(NULL);
        }
#else
        ubyte4 dwSpdIdRet = pxKey->dwSpdId;
        if (dwSpdIdRet) /* SPD id */
        {
            debug_print("  spd=");
            debug_int(dwSpdIdRet);
            debug_printnl(NULL);
        }
#endif
    }
    else
    {
        debug_print("  spd=");
#ifndef __ENABLE_DIGICERT_PFKEY__
        debug_int(spdIndex);
        debug_print("[");
        debug_int(pxKey->iNest);
        debug_print("]");
#else
        debug_uint(dwSpdId);
#endif
#ifdef __ENABLE_IPSEC_ESN__
        if (IPSEC_SA_FLAG_ESN & pxKey->flags)
        {
            debug_print(" esn");
        }
#endif
        if (pxKey->dwExpSecs || pxKey->dwExpKBytes)
        {
            debug_print(" exp=");
            if (pxKey->dwExpSecs)
            {
                debug_uint(pxKey->dwExpSecs);
                debug_print(" secs");
                if (pxKey->dwExpKBytes) debug_print(", ");
            }
            if (pxKey->dwExpKBytes)
            {
                debug_uint(pxKey->dwExpKBytes);
                debug_print(" kbytes");
            }
        }
        debug_printnl(NULL);
    }

    if (NULL != pxKey->poAuthKey)
    {
        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(0, 0, 0,
                                                           pxKey->oAuthAlgo);
        debug_print("  auth=");

        if (NULL != pAuthAlgo)
            debug_print(pAuthAlgo->name);
        else
            debug_int(pxKey->oAuthAlgo);

        if (OK > st)
            debug_printnl(NULL);
        else
            debug_printk((sbyte *)"", pxKey->poAuthKey, pxKey->wAuthKeyLen);
    }

    if (NULL != pxKey->poEncrKey)
    {
        CHILDSA_encrInfo *pEncrAlgo =
                CHILDSA_findAeadAlgo(0, 0, pxKey->oEncrAlgo,
                                     pxKey->oAeadIcvLen,
                                     0, NULL);
        debug_print("  encr=");

        if (NULL != pEncrAlgo)
            debug_print(pEncrAlgo->name);
        else
            debug_int(pxKey->oEncrAlgo);

        if (OK > st)
            debug_printnl(NULL);
        else
            debug_printk((sbyte *)"", pxKey->poEncrKey, pxKey->wEncrKeyLen);
    }

#ifdef __ENABLE_DIGICERT_IPCOMP__
    if (pxKey->oCompAlgo)
    {
        CHILDSA_compInfo *pCompAlgo = CHILDSA_findCompAlgo(pxKey->oCompAlgo);

        debug_print("  IPCOMP cpi=");
        debug_int(pxKey->wCpi);
        debug_print(" alg=");

        if (NULL != pCompAlgo)
            debug_print(pCompAlgo->name);
        else
            debug_int(pxKey->oCompAlgo);

        debug_printnl(NULL);
    }
#endif

    if (OK > st)
    {
        debug_print("    IPSEC_keyAddEx()");
        debug_print_st((sbyte4)st);
    }
    else debug_printnl(NULL);

    return;
} /* PrintIPsecKey */

#else
#define PrintIPsecKey(_key, _st, _spdid)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_addIPsecKey(IKE_context ctx)
{
    MSTATUS status = STATUS_IPSEC_KEYADD_ABORT;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (IS_IKE2_SA(pxSa) ? ctx->pxXg->pxIPsecSa
                                          : P2XG_IPSECSA(ctx->pxP2Xg));
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);
    intBoolean bMature = IS_MATURE_CHILD(pxIPsecSa);

    sbyte4 i, j, k;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    debug_print(" IKE_addIPsecKey(");
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    if (IS_IKE2_SA(pxSa))
    {
        debug_print("ike=");
        debug_hexint(pxSa->dwId);
        if (pxSa->dwId0 != pxSa->dwId)
        {
            debug_print("/");
            debug_hexint(pxSa->dwId0);
        }
    }
    else
    {
        debug_print("isakmp=");
        debug_hexint(pxSa->dwId);
    }
#endif
    debug_printnl(")");

    /* traverse all */
    for (i=0; i < pxIPsecSa->oP2SaNum; i++)
    {
        intBoolean bAborted = FALSE;
        intBoolean bSuspend = !bInitiator ||
                              (IKE_CHILD_FLAG_CONNECT2 & pxIPsecSa->c_flags); /* !!! */
        ubyte4 dwSpdId[2];
        sbyte4 spdIndex[2];
        dwSpdId[_I] = dwSpdId[_R] = pxIPsecSa->axP2Sa[i].dwSpdId;
        spdIndex[_I] = spdIndex[_R] = pxIPsecSa->axP2Sa[i].spdIndex;

        for (j=0; j < pxIPsecSa->axP2Sa[i].oChildSaLen; j++)
        {
            intBoolean bInfo = FALSE;
            struct ipsecKeyEx keyEx = { 0 };

            IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);

            /* convert from IKE to IPsec */
            IKE_initIPsecKey(&keyEx, pxSa, pxIPsecSa, pxIPsecPps,
                             pxIPsecSa->axP2Sa[i].axChildSa[j].poKey[_R],
                             (ubyte)i, j, _R);
            keyEx.dwSpdId = dwSpdId[_R];
            keyEx.spdIndex = spdIndex[_R];

#ifdef __ENABLE_DIGICERT_PFKEY__
            keyEx.sadb_msg_seq = pxIPsecSa->axP2Sa[i].dwSeqNo;
            keyEx.sadb_sa_replay = pxIPsecSa->axP2Sa[i].oReplay;

            if (pxIPsecSa->wPFS) keyEx.flags |= IPSEC_SA_FLAG_PFS;
#endif
            if (bMature) keyEx.flags |= IPSEC_SA_FLAG_MATURE;

#ifdef __ENABLE_IPSEC_NAT_T__
            if (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags)
            {
                if (IS_PEER_BEHIND_NAT(pxSa))
                    keyEx.flags |= IPSEC_SA_FLAG_NAT_PEER;

                keyEx.wUdpEncPort = pxSa->wPeerPort;
            }
#endif
            keyEx.dwExpSecs = pxIPsecPps->dwExpSecs;
            keyEx.dwExpKBytes = pxIPsecPps->dwExpKBytes;

            /* [v1] adjust lifetime */
            if (!bInitiator && !IS_IKE2_SA(pxSa)) /* responder only */
            {
                if (0 != pxIPsecPps->dwAdjSecs)
                    keyEx.dwExpSecs = pxIPsecPps->dwAdjSecs;
                else
                if ((0 == pxIPsecPps->dwExpSecs) && (0 == pxIPsecPps->dwExpKBytes))
                    keyEx.dwExpSecs = 28800; /* 8 hours (RFC2407 4.5, p.13) */

                if (0 != pxIPsecPps->dwAdjKBytes)
                    keyEx.dwExpKBytes = pxIPsecPps->dwAdjKBytes;
            }

            keyEx.dwIkeSaId = pxSa->dwId0;
            keyEx.ikeSaLoc = pxSa->loc;

            keyEx.dwTimeStart = timenow - pxIPsecSa->dwTimeStart; /* ms ago */

            for (k = _R; k >= _I; k--) /* {R, I} */
            {
                MSTATUS st;

                /* aborted already? */
                if (bAborted || bInfo)
                {
                    if (!IS_IKE2_SA(pxSa)) /* [v1] */
                    {
                        /* send deletion info. */
                        struct ike_info_delete deleteInfo = { 0 };
                        struct ike_info info = { NULL };

                        deleteInfo.oProtoId = pxIPsecPps->oProtocol;
                        deleteInfo.dwSpi = bInitiator
                                         ? pxIPsecPps->dwSpi[_I] : pxIPsecPps->dwSpi[_R];

                        info.pxDelete = &deleteInfo;
                        ctx->pxInfo = &info;
                        IKE_xchgOut(ctx);
                    }
                    break;
                }

                if (_I == k)
                {
                    ubyte4 dwTemp; ubyte2 wTemp;
                    MOC_IP_ADDRESS addrTemp;

                    if (IPSEC_SA_FLAG_INBOUND & keyEx.flags)
                        keyEx.flags &= ~(IPSEC_SA_FLAG_INBOUND);
                    else
                        keyEx.flags |= IPSEC_SA_FLAG_INBOUND;

                    dwTemp = keyEx.dwSpi;
                    keyEx.dwSpi = keyEx.dwSpiM;
                    keyEx.dwSpiM = dwTemp;

#ifdef __ENABLE_DIGICERT_IPCOMP__
                    wTemp = keyEx.wCpi;
                    keyEx.wCpi = keyEx.wCpiM;
                    keyEx.wCpiM = wTemp;
#endif
                    addrTemp = keyEx.dwDestAddr;
                    keyEx.dwDestAddr = keyEx.dwSrcAddr;
                    keyEx.dwSrcAddr = addrTemp;

                    wTemp = keyEx.wDestPort;
                    keyEx.wDestPort = keyEx.wSrcPort;
                    keyEx.wSrcPort = wTemp;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                    addrTemp = keyEx.dwDestIP;
                    keyEx.dwDestIP = keyEx.dwSrcIP;
                    keyEx.dwSrcIP = addrTemp;

                    addrTemp = keyEx.dwDestIPEnd;
                    keyEx.dwDestIPEnd = keyEx.dwSrcIPEnd;
                    keyEx.dwSrcIPEnd = addrTemp;
#endif
                    if (0 != keyEx.wEncrKeyLen)
                        keyEx.poEncrKey = &(pxIPsecSa->axP2Sa[i].axChildSa[j].
                                            poKey[_I][0]);

                    if (0 != keyEx.wAuthKeyLen)
                        keyEx.poAuthKey = &(pxIPsecSa->axP2Sa[i].axChildSa[j].
                                            poKey[_I][keyEx.wEncrKeyLen]);

                    keyEx.dwSpdId = dwSpdId[_I];
                    keyEx.spdIndex = spdIndex[_I];
                }

                /* add to IPsec SADB */
                st = IPSEC_keyAddEx(&keyEx);
#ifdef __ENABLE_DIGICERT_PFKEY__
                if (STATUS_IKE_PENDING == st)
                {
                    st = OK;
                }
#endif
                if (OK > st) /* error */
                {
                    /* prepare Delete notification, as needed */
                    if (_R == k)
                    {
                        pxIPsecSa->merror = st;
                        bAborted = TRUE;
                        bSuspend = FALSE;
                        status = st;
                    }

                    /* (_I == k) */
                    else if (bInitiator) /* inbound */
                    {
#ifndef __ENABLE_DIGICERT_PFKEY__
                        /* To maintain interoperability, do the following only
                           when it's safe to do so.  Some implementations (e.g.
                           Windows) delete SA's in pairs as a result! */
                        if ((keyEx.spdIndex & 0x7fffffff) && !keyEx.dwSpdId)
                        {
                            bInfo = TRUE; /* will inform deletion */
                            k = _R; /* will re-iterate */
                        }
#endif
                    }
                    else /* responder, outbound */
                    {
                        bSuspend = FALSE;
                    }
                }
                else /* get mirrored policy ID, if necessary */
                {
                    if (0 == j) /* do this only once! (if nested) */
                    {
                        if (IPSEC_SA_FLAG_CONNECT2 & keyEx.flags) /* special case! */
                        {
                            if (_R == k)
                            {
                                dwSpdId[_R] = keyEx.dwSpdId;
                                spdIndex[_R] = keyEx.spdIndex;
                            }
                        }
                        else
                        {
                            if (_I == k)
                            {
                                dwSpdId[_I] = keyEx.dwSpdId;
                                spdIndex[_I] = keyEx.spdIndex;
                            }
                        }
                    }
                }

                PrintIPsecKey(&keyEx, st,
#ifndef __ENABLE_DIGICERT_PFKEY__
                              spdIndex[k]
#else
                              dwSpdId[k]
#endif
                              );
            } /* for (k */
        } /* for (j */

        if (!bAborted) status = OK; /* !!! */

        if (m_ikeSettings.funcPtrIkeStatHdlr)
        {
            m_ikeSettings.funcPtrIkeStatHdlr(ISC_CHILDSA,
                                        (bAborted ? IST_FAIL : IST_SUCCESS),
                                        pxIPsecSa->axP2Sa[i].dwSeqNo,
                                        pxIPsecSa, pxSa);
        }

        if (bSuspend)
        {
#ifndef __IKE_MULTI_THREADED__ /* for now */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            intBoolean _bTransport = (ENCAPSULATION_MODE_TRANSPORT ==
                            pxIPsecSa->axP2Sa[i].axChildSa[0].ipsecPps.wMode);
#else
            #define _bTransport TRUE
#endif
            IKE_evtAcquire(pxSa, pxIPsecSa, IKE_KEY_TYPE_SUSPEND,
                           dwSpdId[bInitiator ? _R : _I], _bTransport);
#endif
        }
    } /* for (i */

    return status;
} /* IKE_addIPsecKey */


/*------------------------------------------------------------------*/

extern void
IKE_resetP1StartTime(void)
{
    IKESA pxSa = NULL;
    ubyte4 timenow = 0, adj = 1000, timestart;

    IKE_LOCK_W; /* !!! */

    timenow = RTOS_deltaMS(&gStartTime, NULL);

    if (adj > timenow)
    {
        adj = 0xffffffff - timenow + 1;
    }
    timestart = timenow - adj;

    while (NULL != (pxSa = IKE_enumSa(pxSa, 0)))
    {
        /* not authenticated yet */
        if (!IS_IKE2_SA(pxSa) && !IS_IKE_SA_AUTHED(pxSa))
        {
            pxSa->dwTimeStart = timestart;
        }
        else if (IS_IKE2_SA(pxSa) && !IS_IKE2_SA_AUTHED(pxSa))
        {
            pxSa->dwTimeStart = timestart;
            pxSa->u.v2.pxXg[IS_INITIATOR(pxSa) ? _I : _R][0].dwTimeStart = timestart;
        }
    }

    IKE_UNLOCK_W;
    return;
} /* IKE_resetP1StartTime */

#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */
