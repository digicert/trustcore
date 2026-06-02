/**
 * @file  radius.c
 * @brief RADIUS client core implementation
 *
 * @details    Core RADIUS client functions for authentication
 * @since      1.41
 * @version    3.2 and later
 *
 * @flags      Compilation flags required:
 *     Whether the following flags are defined determines which definitions are enabled:
 *     +   \c \__ENABLE_RFC3576__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
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

#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/mudp.h"
#include "../common/mbitmap.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#ifndef __DISABLE_DIGICERT_SHA256__
#include "../crypto/sha256.h"
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
#include "../crypto/sha512.h"
#endif
#include "../crypto/hmac.h"
#include "../radius/radius.h"
#include "../radius/radius_req.h"
#include "../common/debug_console.h"


/*------------------------------------------------------------------*/

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))
#define REQUEST_RECORD_IN_USE(p)    ((p)->inUse || 0 != (p)->recvPort )
#else
#define REQUEST_RECORD_IN_USE(p)    ((p)->inUse)
#endif

#define SERVER_PTR_TO_ID(p)         ((sbyte4)p)
#define SERVER_ID_TO_PTR(id)        ((RADIUS_RqstRecord*)p)
#define SERVER_PTR_IN_USE(p)        ((p)->pServerName != NULL)

#ifndef RFC3576_NASPORT
#define RFC3576_NASPORT             (3799)
#endif

#ifndef RADIUS_SERVER_PORT
#define RADIUS_SERVER_PORT            (1812)
#endif


/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_IPV6__

#define ISZERO_MOC_IPADDR(s)    (0 == (s))
#define ZERO_MOC_IPADDR(s)      s = 0
#define COPY_MOC_IPADDR(s, a)   s = a
#define REF_MOC_IPADDR(s)       s
#define LT_MOC_IPADDR4(x, y)    ((x) < (y))
#define GT_MOC_IPADDR4(x, y)    ((x) > (y))
#define SAME_MOC_IPADDR(x, y)   ((x) == (y))

#else

#ifdef __WIN32_RTOS__
#pragma message ("IPv6 server address is not supported")
#else
#warning "IPv6 server address is not supported"
#endif
/* See radius_serverCompare() */

#ifndef AF_INET
#define AF_INET     2   /* Internet IP Protocol */
#endif

#ifndef AF_INET6        /* IP version 6 */
#if defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)
#define AF_INET6    10
#elif defined (__WIN32_RTOS__)
#define AF_INET6    23
#elif defined (__VXWORKS_RTOS__)
#define AF_INET6    28
#elif defined (__INTEGRITY_RTOS__)
#define AF_INET6    24
#else
#error Must define AF_INET6
#endif
#endif

#define ISZERO_MOC_IPADDR(s)    (0 == (s).family)
#define ZERO_MOC_IPADDR(s)      (s).family = 0;\
                                (s).uin.addr6[0] = (s).uin.addr6[1] =\
                                (s).uin.addr6[2] = (s).uin.addr6[3] = 0
#define COPY_MOC_IPADDR(s, a)   s = *(a)
#define REF_MOC_IPADDR(s)       &(s)
#define LT_MOC_IPADDR4(x, y)    ((x).uin.addr < (y).uin.addr)
#define GT_MOC_IPADDR4(x, y)    ((x).uin.addr > (y).uin.addr)
#define SAME_MOC_IPADDR(x, y)   (((x).family == (y).family) &&\
                                 (((AF_INET == (x).family) &&\
                                   ((x).uin.addr == (y).uin.addr))\
                                  ||\
                                  ((AF_INET6 == (x).family) &&\
                                   ((x).uin.addr6[0] == (y).uin.addr6[0]) &&\
                                   ((x).uin.addr6[1] == (y).uin.addr6[1]) &&\
                                   ((x).uin.addr6[2] == (y).uin.addr6[2]) &&\
                                   ((x).uin.addr6[3] == (y).uin.addr6[3]))))

#endif


/*------------------------------------------------------------------*/


static ubyte supportedRspCodes[] =
{
    RADIUS_CODE_ACCESS_ACCEPT,
    RADIUS_CODE_ACCESS_REJECT,
    RADIUS_CODE_ACCOUNTING_RESPONSE,
    RADIUS_CODE_ACCESS_CHALLENGE
};

#define SUPPORTED_RSP_CODES_COUNT   COUNTOF(supportedRspCodes)

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))
static ubyte supportedReqCodes[] =
{
#if (defined(__ENABLE_RFC3576__))
    RADIUS_CODE_DISCONNECT_REQUEST,
    RADIUS_CODE_COA_REQUEST,
#endif
#if (defined(__ENABLE_RADIUS_SERVER__))
    RADIUS_CODE_ACCESS_REQUEST
#endif
};

#define SUPPORTED_REQ_CODES_COUNT   COUNTOF(supportedReqCodes)

#define AUTHORIZE_ONLY_STR  ("Authorize Only")
#define AUTHORIZE_ONLY_LEN  (14) /* Length of "Authorize Only" */

#endif


/*------------------------------------------------------------------*/

RADIUS_Globals gRADIUS_globals;

static MSTATUS radius_serverCompare(const void *appCookie,
                                    const void *p1, const void *p2,
                                    sbyte4 *compareResults);

static void    radius_releaseRequestsForServer(sbyte4 serverId);
static sbyte4  radius_repeatRequest(RADIUS_RqstRecord *r);
static sbyte4  RADIUS_deleteServerSrcPortList(RADIUS_ServerRecord *r);

static MSTATUS radius_addSrcPort(RADIUS_ServerRecord *r,
                                 RADIUS_ServerSrcPortRec **inst);

static RADIUS_RESULT lookForResponse(RADIUS_ServerRecord *server,
                                     RADIUS_RqstRecord **request);

static sbyte4 RADIUS_getNextRRServer(sbyte4 instanceId, ubyte reqType,
                                     sbyte4 currentServerID, sbyte4 *retID);


/*------------------------------------------------------------------*/

static ubyte4
radius_round_robin(RADIUS_ServerRecord *pSrvr)
{
    sbyte4 whichPort = pSrvr->whichServerSrcPort;
    pSrvr->whichServerSrcPort = (whichPort % pSrvr->numSrcPorts) + 1;
    DEBUG_ERROR(DEBUG_RADIUS, "newRequestRecord : srPort = ", whichPort);
    return whichPort;
}


static sbyte4
radius_getInstancePtrFromId(sbyte4 instanceId, RADIUS_Instance **instPtr)
{
    MSTATUS            status = OK;
    RADIUS_Instance    tInst, *pInst;
    *instPtr = NULL;
    tInst.instanceId = instanceId;
    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    if ((NULL == pInst) || (OK > status))
    {
        if (OK == status)
            status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }
    *instPtr = pInst;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_getRadiusReqId(RADIUS_RqstRecord *pRqst)
{
    MSTATUS status;
    ubyte2 i;
    RADIUS_ServerRecord *pServer = NULL;
    RADIUS_ServerSrcPortRec *pSportRec = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        return status;

    pSportRec = pServer->srcPortListHead;
    for (i = 0; i < pServer->numSrcPorts; i++)
    {
        if (pSportRec->srcPortNum == pRqst->serverSrcPortNum)
            break;
    }
    status = MBITMAP_findVacantIndex((bitmapDescr*)pSportRec->idMap,
                                     &pRqst->requestId);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_nextRadiusReqId(RADIUS_RqstRecord *pRqst)
{
    MSTATUS status;
    ubyte2 i;
    RADIUS_ServerRecord *pServer = NULL;
    RADIUS_ServerSrcPortRec *pSportRec = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        return status;

    pSportRec = pServer->srcPortListHead;

    for (i = 0; i < pServer->numSrcPorts; i++)
    {
        if (pSportRec->srcPortNum == pRqst->serverSrcPortNum)
            break;
        pSportRec = pSportRec->next;
    }
    status = MBITMAP_findVacantIndex((bitmapDescr*)pSportRec->idMap,
                                     &pRqst->requestId);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_freeRadiusReqId(RADIUS_RqstRecord *pRqst)
{
    MSTATUS status;
    ubyte2 i;
    RADIUS_ServerRecord *pServer = NULL;
    RADIUS_ServerSrcPortRec *pSportRec = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        return status;

    pSportRec = pServer->srcPortListHead;

    for (i = 0; i < pServer->numSrcPorts; i++)
    {
        if (pSportRec->srcPortNum == pRqst->serverSrcPortNum)
            break;
        pSportRec = pSportRec->next;
    }

    status = MBITMAP_clearIndex((bitmapDescr*)pSportRec->idMap,
                                (pRqst->requestId));

    return status;
}


/*------------------------------------------------------------------*/

static void
RADIUS_timerCallBack(void *request, ubyte *type)
{
    RADIUS_RqstRecord   *pRqst  = (RADIUS_RqstRecord *) request;
    RADIUS_ServerRecord *pSrvr  = NULL;
    RADIUS_RqstRecord   *pTRqst = NULL;
    RADIUS_Instance     *pInst = NULL;
    MSTATUS status = OK;

    if (!pRqst)
    {
        goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pSrvr)))
        goto exit;

    if (!pSrvr)
    {
        goto exit;
    }

    if (OK > (status = radius_getInstancePtrFromId(pSrvr->radiusInstanceId,
                                                  &pInst)))
    {
        goto exit;
    }

    status = REDBLACK_find(pSrvr->requestTree, (const void *)pRqst, (const void **)&pTRqst);

    if ((pTRqst != pRqst) || (OK > status))
    {
        DEBUG_ERROR(DEBUG_RADIUS,"Could not locate request - status: ", status);
        goto exit;
    }

    if ( RADIUS_LB_NONE == pSrvr->cfgPtr->loadBalAlgo )
    {
        if (pTRqst->sentCount > (sbyte4)pSrvr->cfgPtr->radiusFailoverCount &&
           FALSE == pSrvr->calledFailoverInd)
        {
            pSrvr->calledFailoverInd = TRUE;
            if (pSrvr->cfgPtr->funcPtrRadiusFailoverInd)
            {
                pSrvr->cfgPtr->funcPtrRadiusFailoverInd(pTRqst->userCookie,
                                                        RADIUS_FAILOVER,
                                                        pRqst->serverID);
            }
        }
        if (pTRqst->sentCount > (sbyte4)pSrvr->cfgPtr->radiusRetryCount)
        {
            status = (MSTATUS) RADIUS_RETRIES_EXCEEDED;
        }
        else
        {
            if ((status = radius_repeatRequest(pTRqst)) !=OK)
            {
                goto exit;
            }
        }
    }
    else  /* Some Load balancing has been Configured */
    {
        if (pTRqst->sentCount > (sbyte4)pSrvr->cfgPtr->radiusRetryCount)
        {
            if (pTRqst->timesChangedServer > pInst->availableServers)
            {
                pTRqst->retriesExceeded = TRUE;
                status = (MSTATUS) RADIUS_RETRIES_EXCEEDED;
            }
            else /* Get the next Server To Send To based upon scheme */
            {
                status = radius_repeatRequest(pTRqst);
            }

        }
        else
        {
            status = radius_repeatRequest(pTRqst);
        }

    }

exit:
    if ((OK != status) && (pTRqst))
    {
        pTRqst->retriesExceeded = TRUE;
        if (pSrvr->cfgPtr->funcPtrRadiusInd)
        {
            pSrvr->cfgPtr->funcPtrRadiusInd(pTRqst->userCookie,
                                            (RADIUS_RESULT) status,
                                            pTRqst);
        }
    }
    return;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_requestCompare(const void * appCookie, const void *p1, const void *p2, sbyte4 * compareResults)
{
    RADIUS_RqstRecord*  req1 = (RADIUS_RqstRecord *)p1;
    RADIUS_RqstRecord*  req2 = (RADIUS_RqstRecord *)p2;

    sbyte4 result = 0;

    if (req1->serverID < req2->serverID)
    {
        result = -1;
    }
    else if (req1->serverID > req2->serverID)
    {
        result = 1;
    }
    else
    {
        if (req1->serverSrcPortNum < req2->serverSrcPortNum)
        {
            result = -1;
        }
        else if (req1->serverSrcPortNum > req2->serverSrcPortNum)
      {
          result = 1;
      }
      else
      {
          if ((req1->requestId) < (req2->requestId))
          {
              result = -1;
          }
          else if ((req1->requestId) > (req2->requestId))
          {
              result = 1;
          }
      }
  }

  *compareResults = result;

  return OK;
}


/*----------------------------------------------------------------- */

static MSTATUS
radius_serverCompareId (const void *appCookie,
                      const void *p1,
                      const void *p2,
                      sbyte4 *compareResults)
{
    RADIUS_ServerRecord* a = (RADIUS_ServerRecord *)p1;
    RADIUS_ServerRecord* b = (RADIUS_ServerRecord *)p2;

    *compareResults = 0;

    if (a->serverId < b->serverId)
        *compareResults = -1;
    else if (a->serverId > b->serverId)
        *compareResults = 1;

    return OK;
}

static MSTATUS
radius_serverCompare (const void *appCookie,
                      const void *p1,
                      const void *p2,
                      sbyte4 *compareResults)
{
    RADIUS_ServerRecord* a = (RADIUS_ServerRecord *)p1;
    RADIUS_ServerRecord* b = (RADIUS_ServerRecord *)p2;

    *compareResults = 0;

    /* Note: The following does not handle IPv6 address! */
    if (LT_MOC_IPADDR4(a->serverAddress, b->serverAddress))
        *compareResults = -1;
    else if (GT_MOC_IPADDR4(a->serverAddress, b->serverAddress))
        *compareResults = 1;

    if (a->port < b->port)
        *compareResults = -1;
    else if (a->port > b->port)
        *compareResults = 1;

    /* If we have the Src addr Bound to the default Interface Ignore the
       Specific Interface */
    if (!ISZERO_MOC_IPADDR(b->srcAddr))
    {
        if (LT_MOC_IPADDR4(a->srcAddr, b->srcAddr))
            *compareResults = -1;
        else if (GT_MOC_IPADDR4(a->srcAddr, b->srcAddr))
            *compareResults = 1;
    }


    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_instanceCompare(const void *appCookie,
                       const void *p1,
                       const void *p2,
                       sbyte4 * compareResults)
{
    RADIUS_Instance    *inst1 = (RADIUS_Instance*)p1;
    RADIUS_Instance    *inst2 = (RADIUS_Instance*)p2;

    *compareResults = 0;

    if (inst1->instanceId < inst2->instanceId)
        *compareResults = -1;
    else if (inst1->instanceId > inst2->instanceId)
        *compareResults = 1;

    return OK;
}


/*------------------------------------------------------------------*/

static void
RADIUS_generateAccountingAuthenticator( ubyte* pPkt,
                                       sbyte4 statedLen,
                                       RADIUS_ServerRecord* pServer,
                                       ubyte inDigest[MD5_RESULT_SIZE],
                                       ubyte outDigest[MD5_RESULT_SIZE])
{
    MD5_CTX *pCtx = NULL;
    MSTATUS status;

    DIGI_MEMSET(outDigest, 0x00, MD5_RESULT_SIZE);

    status = MD5Alloc_m(MOC_HASH(gRADIUS_globals.hwAccelCtx)(BulkCtx *) &pCtx);
    if (OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;

    /* Code + Identifier + Length */
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, pPkt,
                RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE +
                RADIUS_LENGTH_FIELD_SIZE);
    if (OK != status)
        goto exit;

    /* 16 zero octets */
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, inDigest, MD5_RESULT_SIZE);
    if (OK != status)
        goto exit;

    if (statedLen < RADIUS_ATTRIBUTES_OFFSET)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    /* request attributes */
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, pPkt + RADIUS_ATTRIBUTES_OFFSET,
                statedLen - RADIUS_ATTRIBUTES_OFFSET);
    if (OK != status)
        goto exit;

    /* shared secret */
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, pServer->sharedSecret,
                pServer->sharedSecretLength);
    if (OK != status)
        goto exit;

    /* final result */
    status = MD5Final_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, outDigest);

exit:
    /* free context */
    MD5Free_m(MOC_HASH(gRADIUS_globals.hwAccelCtx)(BulkCtx *) &pCtx);
}


/*------------------------------------------------------------------*/

/*! Get a pointer to a response's raw data.
This function returns a pointer to a request/response record's response data
(exclusive of the corresponding request and all header data). Typically your
application will not need to use this function, but it is provided to enable
retrieval of message's raw data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Pointer to request/response record containing desired data.

\return Pointer to the response record's $rspData$ field; $NULL$ if specified request is $NULL$.

*/
extern ubyte*
RADIUS_getRequestResponseBuffer(RADIUS_RqstRecord *pRequest)
{
    if (NULL == pRequest)
        return NULL;

    return ((RADIUS_RqstRecord*)pRequest)->rspData;
}


/*------------------------------------------------------------------*/

/*! Get the length of a response's raw data.
This function returns the length of a request/response record's response data
(exclusive of the corresponding request and all header data). Typically your
application will not need to use this function, but it is provided to enable
retrieval of message's raw data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Pointer to request/response record containing desired data.

\return Pointer to the response record's $rspLength$ field; 0 if specified request is $NULL$.

*/
extern ubyte2
RADIUS_getRequestResponseBufferLength(RADIUS_RqstRecord *pRequest)
{
    if (NULL == pRequest)
        return 0;

    return ((RADIUS_RqstRecord*)pRequest)->rspLength;
}


/*------------------------------------------------------------------*/

/*! Get a pointer to a requests's raw data.
This function returns a pointer to a request/response record's request data
(exclusive of the corresponding response and all header data). Typically your
application will not need to use this function, but it is provided to enable
retrieval of message's raw data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Pointer to request/response record containing desired data.

\return Pointer to the request record's $rqstData$ field; $NULL$ if specified request is $NULL$.

*/
extern ubyte*
RADIUS_getRequestRequestBuffer(RADIUS_RqstRecord *pRequest)
{
    if (NULL == pRequest)
        return NULL;

    return ((RADIUS_RqstRecord*)pRequest)->rqstData;
}


/*------------------------------------------------------------------*/

/*! Get the length of a request's raw data.
This function returns the length of a request/response record's request data
(exclusive of the corresponding response and all header data). Typically your
application will not need to use this function, but it is provided to enable
retrieval of message's raw data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Pointer to request/response record containing desired data.

\return Pointer to the request record's $rqstLength$ field; 0 if specified request is $NULL$.

*/
extern ubyte2
RADIUS_getRequestRequestBufferLength(RADIUS_RqstRecord *pRequest)
{
    if (NULL == pRequest)
        return 0;

    return ((RADIUS_RqstRecord*)pRequest)->rqstLength;
}


/*------------------------------------------------------------------*/

/*! Save and associate data with a specific request.
This function saves any data you want to associate with a specific request so
that it can be retrieved at any time (by calling RADIUS_getRequestUserCookie).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\note If you allocate memory in which to store the cookie, be sure to prevent
memory leak by freeing the memory before releasing the request.

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param pCookie  Pointer to the data to save as the cookie associated with the
specified request.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
static int radius_EXAMPLE_sendOne(int serverID, MOC_IP_ADDRESS addr, int cookie)
{
    int                 status = -1;
    RADIUS_RqstRecord*  pRqst;
    static const ubyte  papUserName[] = "johndoe", papPassword[] = "abcdwxyz";

    if (OK > (status = RADIUS_requestNew(&pRqst, serverID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    RADIUS_setRequestUserCookie(pRqst, (void*)cookie);

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRqst, RADIUS_ATTR_USER_NAME, (ubyte *)papUserName)))
        goto exit;
    if (OK > (status = RADIUS_requestAppendUserPassword(pRqst, (ubyte *)papPassword, sizeof(papPassword) - 1)))
        goto exit;
    if (addr)
    {
        if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRqst, RADIUS_ATTR_NAS_IP_ADDRESS, addr)))
            goto exit;
    }
    if (OK > (status = RADIUS_requestSend(pRqst)))
        goto exit;

    status = OK;

exit:
    return status;
}
\endexample
*/
extern sbyte4
RADIUS_setRequestUserCookie(RADIUS_RqstRecord *pRequest, void *pCookie)
{
    if (NULL == pRequest)
        return ERR_NULL_POINTER;

    ((RADIUS_RqstRecord*)pRequest)->userCookie = pCookie;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Get data saved from a previous request.
This function retrieves data that was saved from a previous request (by a call
to RADIUS_setRequestUserCookie).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.

\return Pointer to the request record's user cookie; 0 if specified request is $NULL$.

\example
case RADIUS_FOUND:
        printf("Got a response\n");
        printf("Response %s authentication\n",
            RADIUS_responseIsAuthenticated(pRqst) ? "passed" : "failed");
        cookie = (unsigned long)RADIUS_getRequestUserCookie(pRqst);
        printf("Response Cookie: %lx\n", cookie);
        RADIUS_responseGetCode(pRqst, &code);
        printf("Response Code: %d\n", (int)code);

        RADIUS_requestRelease(pRqst);

       // fall through
\endexample
*/
extern void*
RADIUS_getRequestUserCookie(RADIUS_RqstRecord *pRequest)
{
    if (NULL == pRequest)
        return NULL;

    return ((RADIUS_RqstRecord*)pRequest)->userCookie;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
RADIUS_countAttributes(ubyte* pBuffer, ubyte4 bufSize, ubyte4 *pCount)
{
    ubyte*  p;
    ubyte*  opl;
    ubyte   len;
    sbyte4  status = OK;

    *pCount = 0;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* opl = one past last, but since an attribute must be at least
     * 3 bytes long I'm subtracting that here. */
    opl = pBuffer + bufSize - RADIUS_MIN_LEN;

    for (p = pBuffer; p < opl; )
    {
        len = *(p + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

        if (len < RADIUS_MIN_LEN)
        {
            status = ERR_RADIUS_BAD_RESPONSE;
            break;
        }

        (*pCount)++;
        p += len;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the first attribute of the specified type from a data packet.
This function evaluates the specified $pPkt$ parameter's data and returns the
first attribute it finds that matches the specified type.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pPkt     Pointer to packet data containing desired attribute.
\param pktLen   Number of bytes in $pPkt$.
\param type     Desired attribute's type (see "Attribute Types").
\param ppValue  On return, pointer to address of desired attribute's data.
\param pLength  On return, pointer to length of desired attribute's data.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (NULL == (p = RADIUS_getRequestResponseBuffer(pRequest)))
{
    status = ERR_RADIUS_NO_RESPONSE;
    goto exit;
}

length = RADIUS_getRequestResponseBufferLength(pRequest);

status = RADIUS_getAttributeByType(p, length, type, ppValue, pLength);
\endexample
*/
extern sbyte4
RADIUS_getAttributeByType(ubyte *pPkt, ubyte2 pktLen, ubyte type,
                          ubyte **ppValue, ubyte *pLength)
{
    ubyte*  p;
    ubyte*  opl;
    ubyte   len;
    sbyte4  status = ERR_NOT_FOUND;

    *ppValue = NULL;
    *pLength = 0;

    if (NULL == pPkt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p = pPkt;
    opl = p + pktLen;
    p += RADIUS_ATTRIBUTES_OFFSET;

    while (p < opl)
    {
        len = *(p + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

        if (len < RADIUS_MIN_LEN)
        {
            status = ERR_BAD_LENGTH;
            break;
        }

        if (type == *p)
        {
            *ppValue = p + RADIUS_ATTRIBUTE_DATA_OFFSET;
            *pLength = (ubyte)(len - RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);
            status = OK;
            break;
        }

        p += len;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern sbyte4
RADIUS_getAttributeByTypeRaw(ubyte *pPkt, ubyte2 pktLen, ubyte type,
                          ubyte **ppValue, ubyte *pLength)
{
    ubyte*  p;
    ubyte*  opl;
    ubyte   len;
    sbyte4  status = ERR_NOT_FOUND;

    *ppValue = NULL;
    *pLength = 0;

    if (NULL == pPkt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p = pPkt;
    opl = p + pktLen;

    while (p < opl)
    {
        len = *(p + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

        if (len < RADIUS_MIN_LEN)
        {
            status = ERR_BAD_LENGTH;
            break;
        }

        if (type == *p)
        {
            *ppValue = p + RADIUS_ATTRIBUTE_DATA_OFFSET;
            *pLength = (ubyte)(len - RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);
            status = OK;
            break;
        }

        p += len;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/
/*
 * Caller should be doing the arg sanity checking. pAttrs must point
 * to the beginning of the TLV list of attrs (either attributes proper or
 * to sub-attributes of a Vendor-Specific attribute.)
 */
static MSTATUS
radius_getAttributeByIndex(ubyte *pAttrs, ubyte2 attrsLen, sbyte4 index,
                           ubyte *pType, ubyte* pLength, ubyte** ppValue)
{
    ubyte*  p;
    ubyte*  opl;
    sbyte4  i = 0;
    sbyte4  status = ERR_INDEX_OOB;

    *pType = 0;
    *pLength = 0;
    *ppValue = NULL;

    p = pAttrs;
    opl = p + attrsLen;

    while (p < opl)
    {
        ubyte len = *(p + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

        if (len < RADIUS_MIN_LEN)
        {
            status = ERR_BAD_LENGTH;
            break;
        }

        if (i == index)
        {
            *pType = *(p + RADIUS_ATTRIBUTE_TYPE_OFFSET);
            *ppValue = p + RADIUS_ATTRIBUTE_DATA_OFFSET;
            *pLength = (ubyte)(len - RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);
            status = OK;
            break;
        }

        p += len;
        i++;
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified attribute from a data packet.
This function evaluates the specified $pPkt$ parameter's data and returns the
zero-based index attribute through the $ppValue$ parameter, along with its length
(through the $pLength$ parameter) and type (through the $pType$ parameter).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pPkt     Pointer to packet data containing desired attribute.
\param pktLen   Number of bytes in $pPkt$.
\param index    Zero-based index of desired attribute.
\param pType    On return, pointer to desired attribute's type (see "Attribute Types").
\param ppValue  On return, pointer to address of desired attribute's data.
\param pLength  On return, pointer to length of desired attribute's data.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
while (!done)
{
    status = RADIUS_getAttributeByIndex(pData, pLength, i, &type, &pVal, &len);

    switch (status)
    {
        case ERR_INDEX_OOB:
        {
            done = TRUE;
            break;
        }
        case OK:
        {
            if (RADIUS_ATTR_USER_PASSWORD != type)
                if (OK > (status = RADIUS_requestAppendAttribute(pNewRequest, type, pVal, len)))
                    goto exit;
            break;
        }
        default:
        {
            goto exit;
        }
    }

    i++;
}
\endexample
*/
extern sbyte4
RADIUS_getAttributeByIndex(ubyte *pPkt, ubyte2 pktLen, sbyte4 index,
                       ubyte *pType, ubyte **ppValue, ubyte *pLength)
{
    sbyte4  status;

    *pType = 0;
    *pLength = 0;
    *ppValue = NULL;

    if (NULL == pPkt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pktLen < RADIUS_ATTRIBUTES_OFFSET)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    status = radius_getAttributeByIndex(pPkt+RADIUS_ATTRIBUTES_OFFSET,
                                        (ubyte2)(pktLen-RADIUS_ATTRIBUTES_OFFSET), index,
                                        pType, pLength, ppValue);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern sbyte4
RADIUS_getAttributeByIndexRaw(ubyte *pPkt, ubyte2 pktLen, sbyte4 index,
                       ubyte *pType, ubyte **ppValue, ubyte *pLength)
{
    sbyte4  status;

    *pType = 0;
    *pLength = 0;
    *ppValue = NULL;

    if (NULL == pPkt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = radius_getAttributeByIndex(pPkt,
                                        (ubyte2)(pktLen), index,
                                        pType, pLength, ppValue);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified subattribute from a data packet.
This function evaluates the specified $pAttr$ parameter's data and returns the
zero-based index attribute through the $ppSubValue$ parameter, along with its length
(through the $pSubLength$ parameter) and type (through the $pSubType$ parameter).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\note You should call this function only for vendor-specific attributes, and
only if you know that the attribute has subfields (as determined by a call to
RADIUS_attributeHasSubAttributes).
\note If an invalid $index$ is specified, $ERR_INDEX_OOB$ is returned.

#Include %file:#&nbsp;&nbsp;radius.h

\param pAttr        Pointer to buffer containing desired subattribute.
\param attrLen      Number of bytes in $pAttr$.
\param index        Zero-based index of desired subattribute.
\param pSubType     On return, pointer to desired subattribute's type (see "Attribute Types").
\param ppSubValue   On return, pointer to address of subattribute's data.
\param pSubLength   On return, pointer to length of subattribute's data.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
{
    printf("Attribute has sub-attributes\n");
    done = FALSE;
    j = 0;

    while (!done)
    {
        if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
        {
            printf("    Sub-Attribute: #%d\n", j);
            printf("             Type: %d\n", (int)subType);
            printf("            Value: ");
            radius_printChars(pSubData, subLength);
            printf("\n");
            j++;
        }
        else
        {
            done = TRUE;
        }
    }
}
\endexample

*/
extern sbyte4
RADIUS_getSubAttributeByIndex(ubyte *pAttr, ubyte attrLen, sbyte4 index,
                              ubyte *pSubType, ubyte **ppSubValue,
                              ubyte *pSubLength)
{
    sbyte4  status;

    *pSubType   = 0;
    *pSubLength = 0;
    *ppSubValue = NULL;

    if (NULL == pAttr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = radius_getAttributeByIndex(pAttr, attrLen, index, pSubType,
                                        pSubLength, ppSubValue);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Determine whether a vendor-specific attribute has any subattributes.
This function determines whether a vendor-specific attribute has any
subattributes.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\note You should call this function only for vendor-specific attributes.

#Include %file:#&nbsp;&nbsp;radius.h

\param pAttr    Pointer to buffer containing attributes to evaluate.
\param attrLen  Number of bytes in $pAttr$.

\return $TRUE$ (1) if the vendor-specific attribute has any subattributes;
otherwise $FALSE$ (0).

\example
if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
{
    printf("Vendor-Specific attribute\n");
    printf("Vendor ID: %d\n", vendorID);

    if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
    {
        printf("Attribute has sub-attributes\n");
        done = FALSE;
        j = 0;

        while (!done)
        {
            if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
            {
                printf("    Sub-Attribute: #%d\n", j);
                printf("             Type: %d\n", (int)subType);
                printf("            Value: ");
                radius_printChars(pSubData, subLength);
                printf("\n");
                j++;
            }
            else
            {
                done = TRUE;
            }
        }
    }
    else {
        printf("Attribute has no sub-attributes\n");
    }
}
\endexample
*/
extern intBoolean
RADIUS_attributeHasSubAttributes(ubyte *pAttr, ubyte2 attrLen)
{
    ubyte*      p;
    ubyte*      opl;
    ubyte       len;
    intBoolean  ret = FALSE;

    if (attrLen < RADIUS_MIN_LEN)
        goto exit;

    p = pAttr;
    opl = p + attrLen;

    while (p < opl)
    {
        len = *(p + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

        if (len < RADIUS_MIN_LEN)
            goto exit;

        p += len;
    }

    if (p == opl)
        ret = TRUE;

exit:
    return ret;
}


/*------------------------------------------------------------------*/

static sbyte4
RADIUS_deleteServerSrcPortList(RADIUS_ServerRecord *pServer)
{
    sbyte4 status = 0;
    RADIUS_ServerSrcPortRec*   tmp = NULL, *tmpHead = NULL;

    tmpHead = pServer->srcPortListHead;

    while (pServer->numSrcPorts  > 0)
    {
        tmp = tmpHead->next;
        tmpHead->next = tmpHead->next->next;

        if (tmp->udpInfo)
        {
            (pServer->cfgPtr->funcPtrUnBindUDP)(&tmp->udpInfo);
            MBITMAP_releaseMap((bitmapDescr**)&(tmp->idMap));
        }
        FREE(tmp);
        pServer->numSrcPorts--;
    }

    pServer->srcPortListHead = NULL;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_addSrcPort(RADIUS_ServerRecord *pServer,
             RADIUS_ServerSrcPortRec **ppServerSrcPort)
{
    RADIUS_ServerSrcPortRec    *pSportRec = NULL;
    MOC_IP_ADDRESS_S           ipAddr;
    MSTATUS                    status = ERR_RADIUS_SERVER_ADD_SRC_PORT_FAILED;

    pSportRec =
      (RADIUS_ServerSrcPortRec *) MALLOC(sizeof(RADIUS_ServerSrcPortRec));

    if (NULL == pSportRec)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = MBITMAP_createMap((bitmapDescr**)&pSportRec->idMap, 0, 255);
    if (OK >  status)
    {
        DEBUG_ERROR(DEBUG_RADIUS,
                "radius_addSrcPort: MBITMAP_createMap() failed, status = ",
        status);
        goto exit;
    }
    /* start the UDP connection here */
    if (OK > ( status =
          pServer->cfgPtr->funcPtrBindUDP(REF_MOC_IPADDR(pServer->srcAddr),
                                          pServer->pServerName,
                                          pServer->port,
                                          &pSportRec->udpInfo)))
    {
        goto exit;
    }

#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
    status = UDP_getSrcPortAddr(pSportRec->udpInfo,
                        &pSportRec->srcPort,
                        &ipAddr);
    if (OK > status)
        goto exit;
#endif


    if (0 == pServer->numSrcPorts)
    {
        pSportRec->next = pSportRec;
        pServer->srcPortListHead = pSportRec;
    }
    else
    {
        pSportRec->next = pServer->srcPortListHead->next;
        pServer->srcPortListHead->next = pSportRec;
    }
    pServer->numSrcPorts++;
    pSportRec->srcPortNum = pServer->numSrcPorts;
    *ppServerSrcPort = pSportRec;
    pSportRec = NULL;
    status = OK;

exit:
    if (NULL != pSportRec)
    {
        MBITMAP_releaseMap((bitmapDescr**)&pSportRec->idMap);
        FREE(pSportRec);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Add a source port to a RADIUS server, effectively creating multiple server connections.
This function adds a source port to a RADIUS server, effectively creating
multiple server connections. By using this function, you can exceed the RADIUS
protocol's 255 maximum for pending requests from a single %client.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverId     ID of RADIUS server (returned by RADIUS_addServer) to
add a source port to.
\param pUDPCookie   On return, pointer to UDP connection cookie (containing a
file descriptor).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_addSrcPortForServer(sbyte4 serverId, void **pUDPCookie)
{
    sbyte4                     status = ERR_RADIUS_SERVER_ADD_SRC_PORT_FAILED;
    RADIUS_ServerRecord        *pServer = NULL;
    RADIUS_ServerSrcPortRec    *newRec;

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pServer)))
        goto exit;

    status = radius_addSrcPort(pServer, (RADIUS_ServerSrcPortRec **)&newRec);
    if (OK > status)
        goto exit;

    *pUDPCookie = newRec->udpInfo;

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/*! Register a server for the RADIUS %client to query or to send accounting data to.
This function registers a server for the RADIUS %client to query or to send
accounting data to. This function should be called for every server before
using it in a call to the RADIUS_addBackupToServer function.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId           Instance ID returned from an _initInstance call.
\param srcAddr              IP address to use as the source identifier when
sending a UDP datagram.
\param serverIPAddress      String representation of the RADIUS server's IP
address.
\param port                 UDP listen port of the RADIUS %server.
\param pSharedSecret        Shared secret required for authenticated RADIUS
server-client communication.
\param sharedSecretLength   Number of bytes in $pSharedSecret$.
\param retID                On return, ID of the RADIUS %server.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
++gMocanaAppsRunning;

if (OK == UDP_getIfAddr( sServerAddr, &addr))
{
    if ( addr != ( 127 << 24) + 1) // localhost ?
    {
        if (OK > UDP_getIfAddr(NULL, &addr))
                    addr = MOC_UDP_ANY_ADDR;  // not critical, but you may wish to customize
    }
    // otherwise also use localhost for the source address
}

RADIUS_EXAMPLE_InstallUpcalls();

if (OK > (status = RADIUS_init()))
    goto exit;

if ((OK > (status = RADIUS_addServer(addr, sServerAddr, portAuth, sharedSecret, sizeof(sharedSecret) - 1, &authServerID))) ||
    (OK > (status = RADIUS_addServer(addr, sServerAddr, portAcct, sharedSecret, sizeof(sharedSecret) - 1, &acctServerID))))
{
  goto exit;
}
\endexample
*/
extern sbyte4
RADIUS_addServer(sbyte4 instanceId, MOC_IP_ADDRESS srcAddr,
                 sbyte *serverIPAddress, sbyte4 port, ubyte* pSharedSecret,
                 ubyte4 sharedSecretLength, sbyte4 *retID)
{
    RADIUS_ServerRecord*        pServer = NULL, *pTServer;
    ubyte*                      p = NULL;
    ubyte*                      pSS = NULL;
    ubyte4                      strSz;
    MSTATUS                     status = ERR_RADIUS;
    RADIUS_ServerSrcPortRec*    pSportRec;
    RADIUS_Instance             tInst, *pInst;
    ubyte                       workingOnInstance = FALSE;
    ubyte                       releaseServer = TRUE;

    *retID = RADIUS_INVALID_SERVER_ID;

    tInst.instanceId = instanceId;
    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addServer:Failed to acquire mutex, status = ", status);
        goto exit;
    }
    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    if ((NULL == pInst) || (OK > status))
    {
        status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }
    workingOnInstance = TRUE;
    pInst->instRef++;
    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if (NULL == (pServer = MALLOC(sizeof(RADIUS_ServerRecord))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        DEBUG_ERROR(DEBUG_RADIUS,"RADIUS_addServer: malloc() failed, status = ", status);
        goto exit;
    }

    strSz = DIGI_STRLEN(serverIPAddress) + 1;

    if (NULL == (p = MALLOC(DIGI_STRLEN(serverIPAddress) + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (sharedSecretLength)
    {
        if (NULL == (pSS = MALLOC(sharedSecretLength)))
        {
            FREE(p);
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    DIGI_MEMCPY(p, (ubyte *)serverIPAddress, strSz);
    pServer->pServerName = (sbyte *)p;

    /* copy over IP address */
    COPY_MOC_IPADDR(pServer->srcAddr, srcAddr);

    /* get the IP address of the server  */
    status = UDP_getAddrOfHost(pServer->pServerName,
                               &pServer->serverAddress);
    if (OK > status)
    {
        if (p)
            FREE(p);

        if (pSS)
            FREE(pSS);

        FREE(pServer);

        return (sbyte4)status;
    }

    pServer->port = port;

    status = REDBLACK_find(pInst->serverTree, (const void *)pServer, (const void **)&pTServer);

    if ((pTServer != NULL) || (status > OK))
    {
        if (OK == status)
            status = ERR_RADIUS_SERVER_EXISTS;
        DEBUG_ERROR(DEBUG_RADIUS, "Radius Server exists. Use RADIUS_server \
         add instance to add an instance, status = ", status);
        if (p)
            FREE(p);

        if (pSS)
            FREE(pSS);

        FREE(pServer);

        return (sbyte4)status;
    }

    /* server not found. adding new server first time */
    DIGI_MEMCPY(pSS, pSharedSecret, sharedSecretLength);

    pServer->sharedSecret = pSS;
    pServer->sharedSecretLength = sharedSecretLength;

    DIGI_MEMSET((ubyte *)&pServer->counters, 0, sizeof(pServer->counters));

    pServer->serverStatus = RADIUS_SERVER_UP;
    pServer->sendToBackup = FALSE;
    pServer->backupServerIdPtr = NULL;
    pServer->numBackupServers = 0;
    pServer->srcPortListHead = NULL;
    pServer->numSrcPorts = 0;
    pServer->whichServerSrcPort = 1;
    pServer->cfgPtr = &pInst->config;
    pServer->radiusInstanceId = instanceId;
    pServer->skipCounter = 0;
    pServer->calledFailoverInd = FALSE;

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.serverTreeMutex)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addServer(): failed to acquire mutex status = ", status);
        goto exit;
    }

    status = MBITMAP_findVacantIndex((bitmapDescr*)gRADIUS_globals.serverIdMap, (ubyte4 *)&pServer->serverId);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addServer(): failed to find free ID status = ", status);
        RTOS_mutexRelease(gRADIUS_globals.serverTreeMutex);
        status = ERR_RBTREE_INSERT_FAILED;
        goto exit;
    }

    //DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addServer(): Insert server ID = ", pServer->serverId);
    status = REDBLACK_findOrInsert(gRADIUS_globals.serverTree, (const void *)pServer, (const void **)&pTServer);
    if ((NULL != pTServer) || (OK > status))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addServer(): failed to insert in global status = ", status);
        MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.serverIdMap,
                           pServer->serverId);
        RTOS_mutexRelease(gRADIUS_globals.serverTreeMutex);
        status = ERR_RBTREE_INSERT_FAILED;
        goto exit;
    }

    gRADIUS_globals.numServers++;
    RTOS_mutexRelease(gRADIUS_globals.serverTreeMutex);

    /* Add to the rbtree */
    if (OK > (status = REDBLACK_findOrInsert (pInst->serverTree, (const void *)pServer, (const void **)&pTServer)))
    {
        goto exit;
    }

    if (NULL != pTServer)
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_allocTree(&pServer->requestTree, NULL, NULL, radius_requestCompare, NULL, NULL)))
    {
        releaseServer = TRUE;
        goto exit;
    }

    status = radius_addSrcPort(pServer,
                               (RADIUS_ServerSrcPortRec**)&pSportRec);
    if (OK > status)
    {
        releaseServer = TRUE;
        goto exit;
    }
    status = OK;

    *retID = pServer->serverId;

    pInst->availableServers++;
    pInst->totalServers++;
    /* reset the last Used */
    pInst->lastUsedServerID  = NULL;

exit:
    if (TRUE == workingOnInstance)
    {
        MSTATUS mutexStatus = OK;
        mutexStatus = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex);
        if (OK == mutexStatus)
        {
            workingOnInstance = FALSE;
            pInst->instRef--;
            RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        }
        else
        {
            status = mutexStatus;
        }
    }

    if ((OK > status) && (TRUE == releaseServer) && (NULL != pServer))
    {
        RADIUS_releaseServer(pServer->serverId);
    }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/
/* For Round Robin Request form Multiple Users */

/*! Get the next radius server in a round robin scheme.
This function returns the next serverID in a round robin scheme from the list
of configured RADIUS servers. If the server has already been skipped due
to inactivity more than a preconfigured number of times, the server will not
be returned. (To reset the skipCount, call RADIUS_resetServerSkipCounter.)

\since 3.2
\version 3.2 and later

The use of this function is deprecated.

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Instance ID returned from an _initInstance call.
\param reqType      The request type.
\param currentServerID The current server ID.
\param retID        On return, the next server's id (or $NULL$ if the next
active server is not found).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_getNextServer
\sa RADIUS_resetServerSkipCounter
\sa RADIUS_getSkippedServerList

*/
static sbyte4
RADIUS_getNextRRServer(sbyte4 instanceId, ubyte reqType, sbyte4 currentServerID, sbyte4 *retID)
{
    RADIUS_ServerRecord*        pServer = NULL;
    MSTATUS                     status = ERR_RADIUS;
    RADIUS_Instance             tInst, *pInst;
    redBlackListDescr           *rbList;
    byteBoolean bFound = FALSE;

    *retID = RADIUS_INVALID_SERVER_ID;

    //DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_nextRRServer: Called with currentServer ", currentServerID);

    tInst.instanceId = instanceId;
    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_nextRRServer:Failed to acquire mutex, status = ", status);
        goto exit;
    }
    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    if ((NULL == pInst) || (OK > status))
    {
        status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }

    if (pInst->serverTree)
    {
        if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
        {
            RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
            goto exit;
        }

        while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
        {
            if (pServer->numBackupServers > 0)
            {
                if (pInst->availableServers == 1)
                {
                    RADIUS_ServerRecord* pTempServer = NULL;
                    RADIUS_getServerRecordFromID(currentServerID, &pTempServer);
                    if (pTempServer->serverStatus == RADIUS_SERVER_UP)
                    {
                        *retID = currentServerID;
                        bFound = TRUE;
                        break;
                    }
                }

                if (currentServerID == pServer->serverId)
                {
                    sbyte4 i;
                    for (i = 0; (ubyte4) i < pServer->numBackupServers; i++)
                    {
                        RADIUS_ServerRecord* bSrvr = NULL;
                        RADIUS_getServerRecordFromID(pServer->backupServerIdPtr[i], &bSrvr);
                        if (bSrvr->serverStatus == RADIUS_SERVER_DOWN)
                        {
                            continue;
                        }
                        if ((bSrvr->port != 1812) &&
                            (RADIUS_CODE_ACCESS_REQUEST == reqType))
                        {
                            continue;
                        }
                        if ((bSrvr->port != 1813) &&
                            (RADIUS_CODE_ACCOUNTING_REQUEST == reqType))
                        {
                            continue;
                        }

                        if (pServer->skipCounter == pServer->cfgPtr->maxSkipCounter)
                        {
                            pServer->sendToBackup = TRUE;
                        }
                        pServer->backupServerIndex = i;
                        *retID = bSrvr->serverId;
                        bFound = TRUE;
                        break;
                    }
                }
                else
                {
                    pServer->backupServerIndex++;
                    if (pServer->backupServerIndex == pServer->numBackupServers)
                    {
                        if (pServer->serverStatus == RADIUS_SERVER_UP)
                        {
                            *retID = pServer->serverId;
                            bFound = TRUE;
                        }
                        pServer->backupServerIndex = 0;
                    }
                    if (FALSE == bFound)
                    {
                        ubyte4 temp_index = pServer->backupServerIndex;
                        sbyte4 i = 0;
                        for (i = 0; (ubyte4) i < pServer->numBackupServers; i++, ++temp_index)
                        {
                            RADIUS_ServerRecord* bSrvr = NULL;
                            temp_index = (temp_index == pServer->numBackupServers) ? 0 : temp_index;
                            RADIUS_getServerRecordFromID(pServer->backupServerIdPtr[temp_index], &bSrvr);

                            if (bSrvr->serverStatus == RADIUS_SERVER_DOWN)
                            {
                                continue;
                            }
                            if ((bSrvr->port != 1812) &&
                            (RADIUS_CODE_ACCESS_REQUEST == reqType))
                            {
                                continue;
                            }
                            if ((bSrvr->port != 1813) &&
                                (RADIUS_CODE_ACCOUNTING_REQUEST == reqType))
                            {
                                continue;
                            }
                            if (pServer->skipCounter == pServer->cfgPtr->maxSkipCounter)
                            {
                                pServer->sendToBackup = TRUE;
                            }
                            pServer->backupServerIndex = temp_index;
                            *retID = bSrvr->serverId;
                            bFound = TRUE;
                            break;
                        }
                    }
                }
                break;
            }
        }

        REDBLACK_traverseListFree (&rbList);
    }

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
    if (FALSE == bFound)
    {
        status = ERR_RADIUS_SERVER_NOT_FOUND;
        //DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_nextRRServer: Found No Backup!", status);
    }
    else
    {
        status = OK;
        //DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_nextRRServer: Found Backup: ", *retID);
    }

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/
/* Get the Next Server ID from the current one  */

/*! Get the next RADIUS server in the list.
This function returns the next serverID in in the list (relative to the current
server's ID). If the current server's ID is 0, the first available server is
returned. A server's skipCounter determines whether that server will be
returned: if the skipCounter exceeds a preconfigured maximum, the server will
not be returned as the next server.

\since 3.2
\version 3.2 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId       Instance ID returned from an _initInstance call.
\param currentServerID  Current server's Id, or 0 to return the first available server.
\param retID            On return, the next server's id (or $NULL$ if the next
active server is not found).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_getNextRRServer
\sa RADIUS_resetServerSkipCounter
\sa RADIUS_getSkippedServerList

*/
extern MSTATUS
RADIUS_getNextServer(sbyte4 instanceId, sbyte4 currentServerID, sbyte4 *retID)
{
    RADIUS_ServerRecord*        pServer = NULL;
    RADIUS_ServerRecord*        pFirstServer = NULL;
    intBoolean                  isFound = FALSE;
    MSTATUS                     status = ERR_RADIUS;
    RADIUS_Instance             tInst, *pInst;
    redBlackListDescr           *rbList;

    *retID = RADIUS_INVALID_SERVER_ID;

    tInst.instanceId = instanceId;
    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_getNextServer:Failed to acquire mutex, status = ", status);
        goto exit;
    }
    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    if ((NULL == pInst) || (OK > status))
    {
        status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }

    if (pInst->serverTree)
    {
        if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
        {
            RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
            goto exit;
        }

        while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
        {

            if (pServer->skipCounter > pServer->cfgPtr->maxSkipCounter)
            {
                pServer = NULL;
                continue;
            }

            if (isFound)
            {
                *retID = pServer->serverId;
                break;
            }

            if (!pFirstServer)
                pFirstServer = pServer;

            if (!currentServerID)
            {
                /* return the first one */
                isFound = TRUE;
                *retID = pServer->serverId;
                break;
            }

            if (currentServerID  == pServer->serverId)
            {
                isFound = TRUE;
            }
        }

        if (OK != status)
        {
            /* Reset the isFound*/
            isFound = FALSE;
        }

        if (!isFound)
            if (pFirstServer)
                *retID = pFirstServer->serverId;

        REDBLACK_traverseListFree (&rbList);
    }

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
    if (*retID == RADIUS_INVALID_SERVER_ID)
        status = ERR_RADIUS_SERVER_NOT_FOUND;
    else
        status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the list of RADIUS servers that have exceeded the maxSkipCount.
This function returns the list of serverIDs that have exceeded the maxSkipCount.
To reset a server's skip counter, call RADIUS_resetServerSkipCounter.

\note The maximum number of servers that can be returned is defined by
$RADIUS_INSTANCE_ID_END$ in radius.h.

\since 3.2
\version 3.2 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId       Instance ID returned from an _initInstance call.
\param retServerList    On return, pointer to the returned list of servers.
\param listCount        On return, pointer to the number of servers in the
returned list ($retServerList$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_getNextRRServer
\sa RADIUS_getNextServer
\sa RADIUS_resetServerSkipCounter

*/
extern MSTATUS
RADIUS_getSkippedServerList(sbyte4 instanceId, sbyte4 **retServerList, sbyte4 *listCount)
{
    RADIUS_ServerRecord*        pServer = NULL;
    RADIUS_Instance             tInst, *pInst;
    redBlackListDescr           *rbList;
    MSTATUS status = OK;
    static sbyte4 serverList[RADIUS_SERVER_ID_END-RADIUS_SERVER_ID_START+1];

    if ((!retServerList) || (!listCount))
        goto exit;

    *retServerList = serverList;
    *listCount =  0;

    tInst.instanceId = instanceId;
    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_getSkippedServer:Failed to acquire mutex, status = ", status);
        goto exit;
    }
    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    if ((NULL == pInst) || (OK > status))
    {
        status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }

    if (pInst->serverTree)
    {
        if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
        {
            RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
            goto exit;
        }

        while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
        {
            if (*listCount > (RADIUS_SERVER_ID_END-RADIUS_SERVER_ID_START))
                break;
            if (pServer->skipCounter == pServer->cfgPtr->maxSkipCounter)
            {
                serverList[(*listCount)++] = pServer->serverId;
            }
        }

        REDBLACK_traverseListFree (&rbList);
    }

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/
/*! Update (change) the shared secret used between a RADIUS %client and server.
This function updates (changes) the shared secret used between a RADIUS %client and
server.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverID             ID of the RADIUS server (returned by
RADIUS_addServer) of interest.
\param pSharedSecret        Pointer to new shared secret.
\param sharedSecretLength   Number of bytes in $pSharedSecret$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_updateServerSharedSecret( sbyte4 serverID,
                                 ubyte* pSharedSecret,
                                 ubyte4 sharedSecretLength)
{
    MSTATUS status = OK;
    RADIUS_ServerRecord *pServer;
    ubyte *pSS = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(serverID, &pServer)))
        goto exit;

    if (pServer->sharedSecret)
    {
        FREE(pServer->sharedSecret);
        pServer->sharedSecret = NULL;
        pServer->sharedSecretLength = 0;
    }

    if (sharedSecretLength)
    {
        if (NULL == (pSS = MALLOC(sharedSecretLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    DIGI_MEMCPY(pSS, pSharedSecret, sharedSecretLength);

    pServer->sharedSecret = pSS;
    pServer->sharedSecretLength = sharedSecretLength;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a server's information record.
This function retrieves information about the specified server from its server
record.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverID     ID of the RADIUS server (returned by RADIUS_addServer) of interest.
\param ppServer     On return, pointer to address of server's associated server record.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_getServerRecordFromID(sbyte4 serverID, RADIUS_ServerRecord **ppServer)
{
    MSTATUS              status = OK;
    RADIUS_ServerRecord  tServer, *pServer;

    *ppServer = NULL;

    tServer.serverId = serverID;
    status = REDBLACK_find(gRADIUS_globals.serverTree, (const void *)&tServer, (const void **)&pServer);
    if ((NULL == pServer) || (OK > status))
    {
        if (OK == status)
        {
            status = RADIUS_INVALID_SERVER_ID;
            goto exit;
        }
    }

    *ppServer = pServer;
    //    DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_getServerRecordFromID: Server ID = ", (*ppServer)->serverId);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a server's UDP cookie.
This function retrieves information about the specified server from its server
record UDP cookie.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note Most RADIUS Client implementations don't need to access this data outside
of the UDP abstraction layer code.

\param serverID     ID of the RADIUS server (returned by RADIUS_addServer) of interest.
\param ppUDPCookie  On return, pointer to the server record's UDP cookie, which was created by the funcPtrBindUDP upcall.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_getUDPCookieFromServerID(sbyte4 serverID, void **ppUDPCookie)
{
    sbyte4                  status;
    RADIUS_ServerRecord*    pServer;

    *ppUDPCookie = NULL;

    if (0 > (status = RADIUS_getServerRecordFromID(serverID, &pServer)))
        goto exit;

    *ppUDPCookie = pServer->srcPortListHead->udpInfo;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Retrieve the ID of the RADIUS server that sent a specific packet.
This function retrieves the ID of the RADIUS server that sent a specific packet.
First the UDP source port and address is extracted, and then the configured
server ID is determined.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId       Virtual instance ID to which this interface belongs;
previously returned from RADIUS_addInstance.
\param serverAddress    IP address of the RADIUS server from which the response arrived.
\param serverPort       UDP source port on which the response arrived.
\param srcAddr          Local interface address on which the packet was received.
\param serverID         On return, pointer to desired RADIUS server ID.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_getServerIDFromAddrPort(sbyte4 instanceId, MOC_IP_ADDRESS serverAddress, ubyte2 serverPort,MOC_IP_ADDRESS srcAddr, sbyte4 *serverID)
{
    sbyte4                  status = OK;
    RADIUS_ServerRecord     server;
    RADIUS_ServerRecord     *pServer = NULL;
    RADIUS_Instance         tInst,*pInst;

    tInst.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        goto exit;
    }

    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if ((NULL == pInst) || (OK > status))
    {
        if (OK == status)
            status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }

    COPY_MOC_IPADDR(server.serverAddress, serverAddress);
    server.port          = serverPort;
    COPY_MOC_IPADDR(server.srcAddr, srcAddr);

    status = REDBLACK_find(pInst->serverTree, (const void *)&server, (const void **)&pServer);

    if ((NULL == pServer) || (status > OK))
    {
        if (OK == status)
            status = ERR_RADIUS_SERVER_NOT_FOUND;
        goto exit;
    }

    *serverID = pServer->serverId;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Initialize RADIUS %client and open channels with all registered RADIUS servers.
This function initializes NanoRADIUS %client states and opens communication
channel(s) with all registered RADIUS servers (those added by calls to
RADIUS_addServer).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note Be sure to call this function before any other RADIUS functions.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
++gMocanaAppsRunning;

if (OK == UDP_getIfAddr( sServerAddr, &addr))
{
    if ( addr != ( 127 << 24) + 1) // localhost ?
    {
        if (OK > UDP_getIfAddr(NULL, &addr))
                    addr = MOC_UDP_ANY_ADDR;  // not critical, but you may wish to customize
    }
    // otherwise also use localhost for the source address
}

RADIUS_EXAMPLE_InstallUpcalls();

if (OK > (status = RADIUS_init()))
    goto exit;

if ((OK > (status = RADIUS_addServer(addr, sServerAddr, portAuth, sharedSecret, sizeof(sharedSecret) - 1, &authServerID))) ||
    (OK > (status = RADIUS_addServer(addr, sServerAddr, portAcct, sharedSecret, sizeof(sharedSecret) - 1, &acctServerID))))
{
    goto exit;
}
\endexample
*/
extern sbyte4
RADIUS_init()
{
    MSTATUS status = OK;

    status = MBITMAP_createMap((bitmapDescr**)&gRADIUS_globals.instanceIdMap,RADIUS_INSTANCE_ID_START, RADIUS_INSTANCE_ID_END);
    if (OK >  status)
    {
        DEBUG_ERROR(DEBUG_RADIUS,
                "RADIUS_init: MBITMAP_createMap() failed, status = ", status);
        goto exit;
    }


    if (OK > (status = RTOS_mutexCreate(&gRADIUS_globals.instanceTreeMutex, 0, 1)))
    {
        DEBUG_ERROR(RADIUS_ERROR, "RADIUS_init(): RTOS_mutexCreate failed, status = ", status);
        goto exit;
    }

    if (OK > (status = REDBLACK_allocTree(&gRADIUS_globals.instanceTree, NULL, NULL, radius_instanceCompare, NULL, NULL)))
    {
        goto exit;
    }

    status = MBITMAP_createMap((bitmapDescr**)&gRADIUS_globals.serverIdMap,RADIUS_SERVER_ID_START, RADIUS_SERVER_ID_END);
    if (OK >  status)
    {
        DEBUG_ERROR(DEBUG_RADIUS,
		    "RADIUS_init(): MBITMAP_createMap() failed, status = ", status);
        goto exit;
    }


    if (OK > (status = RTOS_mutexCreate(&gRADIUS_globals.serverTreeMutex, 0, 1)))
    {
        DEBUG_ERROR(RADIUS_ERROR, "RADIUS_init(): RTOS_mutexCreate failed, status = ", status);
        goto exit;
    }

    if (OK > (status = REDBLACK_allocTree(&gRADIUS_globals.serverTree, NULL, NULL, radius_serverCompareId, NULL, NULL)))
    {
        goto exit;
    }

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_RADIUS, &gRADIUS_globals.hwAccelCtx)))
    {
        goto exit;
    }

    gRADIUS_globals.numInstances = 0;
    gRADIUS_globals.numServers = 0;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_RADIUS,
                "RADIUS_init:  failed, status = ", status);
        status = RTOS_mutexFree(&gRADIUS_globals.instanceTreeMutex);
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_checkConfig(const RADIUS_Config *config)
{
    MSTATUS status = OK;
    if ((NULL == config->funcPtrBindUDP) || (NULL == config->funcPtrSendUDP) ||
        (NULL == config->funcPtrPollUDP) || (NULL == config->funcPtrUnBindUDP))
    {
        status = ERR_RADIUS_BAD_CONFIG;
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Enable or disable a RADIUS server.
This function enables or disables a RADIUS server.

If you disable an enabled primary server, transactions are automatically sent to
that server's backup server. If you disable a primary server's backup server,
the backup server remains in the primary server's backup list, but will not be
used as long as it remains disabled.

\since 5.4
\version 5.4 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverId     ID of the RADIUS server (returned by RADIUS_addServer).
\param status       One of the following definitions (see radius.h):\n
\n
&bull; $RADIUS_SERVER_UP$&mdash;Enables the server.\n
&bull; $RADIUS_SERVER_DOWN$&mdash;Disables the server.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern void
RADIUS_setServerStatus(sbyte4 serverId, sbyte4 status)
{
    RADIUS_ServerRecord    *pSrvr = NULL;
    RADIUS_Instance*       pInst  = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pSrvr)))
        return;

    if (OK > radius_getInstancePtrFromId(pSrvr->radiusInstanceId,
                                                  &pInst))
    {
        return;
    }

    if ((RADIUS_SERVER_UP == status) && (RADIUS_SERVER_DOWN == pSrvr->serverStatus))
    {
        pSrvr->calledFailoverInd = FALSE;
        if (TRUE == pSrvr->sendToBackup)
        {
            pSrvr->sendToBackup = FALSE;
        }
        pSrvr->skipCounter = 0;
        pInst->availableServers++;
    }
    pSrvr->serverStatus = status;
}


/*------------------------------------------------------------------*/

/*! Add a RADIUS %client virtual instance.
This function adds a RADIUS %client virtual instance, using the specified
configuration settings.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note RADIUS server IDs are created for a particular virtual instance and cannot
be shared by multiple virtual %client instances.

\param instanceId   On return, pointer to virtual instance ID.
\param config       Pointer to desired %client configuration settings and
callback function pointers.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_deleteInstance

*/
extern sbyte4
RADIUS_addInstance(sbyte4 *instanceId, const RADIUS_Config *config)
{
#ifdef __ENABLE_RFC3576__
    sbyte2             i;
#endif
    RADIUS_Instance    *pInst, *pTInst;
    MSTATUS            status = OK;

    if (NULL == (pInst = MALLOC(sizeof(RADIUS_Instance))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addInstance: malloc() failed, status =", status);
        goto exit;
    }

    if (OK > (status = radius_checkConfig(config)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addInstance(): config check failed with  status = ", status);
        goto exit;
    }

    if (OK > (status = TIMER_initTimer()))
    {
        goto exit;
    }

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_addInstance(): failed to acquire mutex status = ", status);
        FREE(pInst);
        goto exit;
    }

    if (OK > (status = TIMER_createTimer(RADIUS_timerCallBack,
                                        &pInst->retryTimer)))
    {
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        FREE(pInst);
        goto exit;
    }

    if (OK > (status = REDBLACK_allocTree(&pInst->serverTree, NULL, NULL, radius_serverCompare, NULL,NULL)))
    {
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        FREE(pInst);
        goto exit;
    }

    status = MBITMAP_findVacantIndex((bitmapDescr*)gRADIUS_globals.instanceIdMap, (ubyte4 *)&pInst->instanceId);

    if (OK != status)
    {
        MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.instanceIdMap,
                           pInst->instanceId);
        REDBLACK_freeTree(&pInst->serverTree, NULL, NULL, NULL);
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        FREE(pInst);
        goto exit;
    }

    status = REDBLACK_findOrInsert(gRADIUS_globals.instanceTree, (const void *)pInst, (const void **)&pTInst);

    if ((NULL != pTInst) || (OK > status))
    {
        MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.instanceIdMap,
                           pInst->instanceId);
        REDBLACK_freeTree(&pInst->serverTree, NULL, NULL, NULL);
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        FREE(pInst);
        if (OK == status)
            status = ERR_RBTREE_INSERT_FAILED;
        goto exit;
    }

    DIGI_MEMCPY((ubyte*)&pInst->config,(const ubyte *)config,
               sizeof(RADIUS_Config));

    if ( 0 == pInst->config.radiusRetryIntervalMS )
        pInst->config.radiusRetryIntervalMS = RADIUS_RETRY_INTERVAL_MS;
    if ( 0 == pInst->config.radiusFailoverCount )
        pInst->config.radiusFailoverCount = RADIUS_FAILOVER_COUNT;
    if ( 0 == pInst->config.radiusRetryCount )
        pInst->config.radiusRetryCount = RADIUS_RETRY_COUNT;

    pInst->instRef = 0;
    pInst->availableServers = 0;
    pInst->totalServers = 0;


#ifdef __ENABLE_RFC3576__

    pInst->pUDPRecv = (void **)
                      (MALLOC(sizeof(void*) * pInst->config.numInterfaces));

    if (NULL == pInst->pUDPRecv && pInst->config.numInterfaces > 0)
    {
        MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.instanceIdMap,
                           pInst->instanceId);
        REDBLACK_freeTree(&pInst->serverTree, NULL, NULL, NULL);
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        FREE(pInst);
        goto exit;
    }

    for (i = 0; i < (sbyte2) pInst->config.numInterfaces; i++)
    {
        status = UDP_simpleBind(&(*(pInst->pUDPRecv+i)),
                                pInst->config.interfaceArrayPtr[i],
                                RFC3576_NASPORT,
                                TRUE);
    }

#endif /* __ENABLE_RFC3576__*/
#ifdef __ENABLE_RADIUS_SERVER__

    pInst->pUDPServerRecv = (void **)
                      (MALLOC(sizeof(void*) * pInst->config.numInterfaces));

    if (NULL == pInst->pUDPServerRecv && pInst->config.numInterfaces > 0)
    {
        MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.instanceIdMap,
                           pInst->instanceId);
        REDBLACK_freeTree(&pInst->serverTree, NULL, NULL, NULL);
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        FREE(pInst);
        goto exit;
    }

    for (i = 0; i < pInst->config.numInterfaces; i++)
    {
        status = UDP_simpleBind(&(*(pInst->pUDPServerRecv+i)),
                                pInst->config.interfaceArrayPtr[i],
                                RADIUS_SERVER_PORT,
                                TRUE);
    }

#endif /* __ENABLE_RADIUS_SERVER__*/

    *instanceId = pInst->instanceId;
    gRADIUS_globals.numInstances++;
    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Add one or more backup RADIUS servers to use in case the primary RADIUS server stops responding.
This function adds one or more backup RADIUS servers to use in case the primary
RADIUS server goes down (stops responding to queries). The primary and all
backup servers must already have been added by a call to RADIUS_addServer. When
it's necessary to make a switch to a backup server, the backup servers are
tried in the order specified by the $backupId$ parameter.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverId     ID of primary RADIUS server (returned by RADIUS_addServer) to
add backup servers to.
\param backupId     Pointer to array of backup server IDs.
\param numBackup    Number of backup servers to add.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_modifyBackupToServer
\sa RADIUS_sendToBackup

*/
extern sbyte4
RADIUS_addBackupToServer(sbyte4 serverId, sbyte4 *backupId, ubyte4 numBackup)
{
    ubyte4                 i = 0;
    MSTATUS                status = OK;
    RADIUS_ServerRecord    *pSrvr = NULL;
    sbyte4                 bkupId = 0;
    RADIUS_ServerRecord    *tSrvr = NULL;

    if (NULL == backupId)
    {

        status = ERR_RADIUS_NULL_BACKUP_POINTER;
        goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pSrvr)))
        goto exit;

    if (pSrvr->backupServerIdPtr)
    {
        status = ERR_RADIUS_BACKUPS_EXIST;
        goto exit;

    }

    for (i = 0; i < numBackup; i++)
    {
        bkupId = *(backupId + i);
        RADIUS_getServerRecordFromID(bkupId, &tSrvr);

        if (tSrvr->serverStatus != RADIUS_SERVER_UP)
        {
            status = ERR_RADIUS_SERVER_NOT_ACTIVE;
            goto exit;
        }
    }

    pSrvr->backupServerIdPtr = (sbyte4 *)MALLOC(sizeof(sbyte4) * numBackup);

    if (NULL == pSrvr->backupServerIdPtr)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)pSrvr->backupServerIdPtr,(const ubyte*)backupId,
               sizeof(sbyte4)*numBackup);

    pSrvr->numBackupServers = numBackup;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Modify the list of backup RADIUS servers to use in case the primary RADIUS server stops responding.
This function modifies the list of backup RADIUS servers to use in case the
primary RADIUS server goes down (stops responding to queries). The primary and
all backup servers must already have been added by a call to RADIUS_addServer.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note You can delete all entries from the backup list by specifying 0 for the
$numBackup$ parameter and $NULL$ for the $backupId$.
\note You can use this function even if the primary RADIUS server does not have
any backup servers already configured.

\param serverId     ID of primary RADIUS server (returned by RADIUS_addServer) to
add backup servers to.
\param backupId     Pointer to array of backup server IDs.
\param numBackup    Number of backup servers to add.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_addBackupToServer
\sa RADIUS_sendToBackup

*/
extern sbyte4
RADIUS_modifyBackupToServer(sbyte4 serverId, sbyte4 *backupId, ubyte4 numBackup)
{
    ubyte4                 i = 0;
    MSTATUS                status = OK;
    RADIUS_ServerRecord    *pSrvr = NULL;
    sbyte4                 bkupId = 0;
    RADIUS_ServerRecord    *tSrvr = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pSrvr)))
        goto exit;

    if ((NULL == backupId) || (0 == numBackup))
    {
        if (pSrvr->numBackupServers > 0)
        {
            if (pSrvr->backupServerIdPtr)
            {
                FREE(pSrvr->backupServerIdPtr);
                pSrvr->backupServerIdPtr = NULL;
            }
        }

        pSrvr->numBackupServers = 0;

        goto exit;
    }
    for (i = 0; i < numBackup; i++)
    {
        bkupId = *(backupId + i);
        RADIUS_getServerRecordFromID(bkupId, &tSrvr);

        if (tSrvr->serverStatus != RADIUS_SERVER_UP)
        {
            status = ERR_RADIUS_SERVER_NOT_ACTIVE;
            goto exit;
        }
    }

    if (pSrvr->numBackupServers != numBackup)
    {
        if (pSrvr->backupServerIdPtr)
        {
            FREE(pSrvr->backupServerIdPtr);
            pSrvr->backupServerIdPtr = NULL;
        }

        pSrvr->backupServerIdPtr =(sbyte4*) MALLOC(sizeof(sbyte4) * numBackup);

        if (NULL == pSrvr->backupServerIdPtr)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    DIGI_MEMSET((ubyte*)pSrvr->backupServerIdPtr, 0,
                numBackup*sizeof(sbyte4));

    DIGI_MEMCPY((ubyte*)pSrvr->backupServerIdPtr,(const ubyte*)backupId,
               sizeof(sbyte4)*numBackup);

    pSrvr->sendToBackup = FALSE;
    pSrvr->numBackupServers = numBackup;

exit:
    return status;
}


/*------------------------------------------------------------------*/
/*! Reset a server's skip counter.
This function resets a server's skip counter so it can be used when allocating
RADIUS servers.

\since 3.2
\version 3.2 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverId     Desired server's instance ID (returned from an _initInstance call).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_getNextServer
\sa RADIUS_getNextRRServer
\sa RADIUS_getSkippedServerList

*/

extern MSTATUS
RADIUS_resetServerSkipCounter(sbyte4 serverId)
{
    MSTATUS                status = OK;
    RADIUS_ServerRecord    *pSrvr = NULL;
    RADIUS_Instance        *pInst = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pSrvr)))
        return status;

    pSrvr->skipCounter = 0;
    pSrvr->calledFailoverInd = FALSE;
    if (OK > (status = radius_getInstancePtrFromId(pSrvr->radiusInstanceId,
                                                  &pInst)))
    {
        return status;
    }
    pInst->availableServers++;

    return 0;
}


/*------------------------------------------------------------------*/

static void
radius_freeRequestRecordFields(RADIUS_RqstRecord *pRqst)
{

    if (pRqst->serverID)
    {
      radius_freeRadiusReqId(pRqst);
    }
    if (NULL != pRqst->rqstData)
    {
        FREE(pRqst->rqstData);
        pRqst->rqstData = NULL;
        pRqst->rqstLength = 0;
    }

    if (NULL != pRqst->rspData)
    {
        FREE(pRqst->rspData);
        pRqst->rspData = NULL;
        pRqst->rspLength = 0;
    }
}


/*------------------------------------------------------------------*/

static void
radius_requestDelete(RADIUS_RqstRecord *pRequest, RADIUS_Instance *pInst)
{
    RADIUS_RqstRecord*      pTRqst;
    RADIUS_ServerRecord*    pSrvr;
    MSTATUS                 status = OK;

    if (NULL == pRequest)
    {
        DEBUG_ERROR(DEBUG_RADIUS,"null request passed to releaseRequest ",0);
        goto exit;
    }

    RADIUS_getServerRecordFromID(pRequest->serverID, &pSrvr);
    status = REDBLACK_delete(pSrvr->requestTree, (const void *)pRequest, (const void **)&pTRqst);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_RADIUS, (sbyte*)"Status error code: ", status);
        goto exit;
    }

    if (pTRqst == pRequest)
    {
        DEBUG_PRINT(DEBUG_RADIUS, "Freeing request from request tree");
        /* DEBUG_HEXINT(DEBUG_RADIUS, (sbyte4)pRequest); */
        DEBUG_PRINTNL(DEBUG_RADIUS, (sbyte *)".");
    }

    TIMER_unTimer((void *)pRequest, pInst->retryTimer);
    radius_freeRequestRecordFields(pRequest);

    pRequest->inUse = FALSE; /* marks as unused */
    pRequest->retriesExceeded = 0;

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))
    pRequest->recvPort = 0; /* marks as unused */
#endif

    FREE(pRequest);

exit:
    return;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern void
RADIUS_releaseRequest(RADIUS_RqstRecord *pRqst)
{
    RADIUS_Instance    *pInst;
    RADIUS_ServerRecord    *pSrvr = NULL;

    if (OK > RADIUS_getServerRecordFromID(pRqst->serverID, &pSrvr))
    {
        goto exit;
    }
    if (OK > radius_getInstancePtrFromId(pSrvr->radiusInstanceId, &pInst))
    {
        goto exit;
    }

    radius_requestDelete(pRqst, pInst);

exit:
    return;
}


/*------------------------------------------------------------------*/

static void
radius_releaseRequestsForServer(sbyte4 serverId)
{
    RADIUS_RqstRecord      *pRqst;
    RADIUS_ServerRecord    *pServer = NULL;
    redBlackListDescr      *rbList;
    MSTATUS                status = OK;

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pServer)))
        return;

    if (NULL == pServer->requestTree)
    {
        return;
    }

    if (OK > (status = REDBLACK_traverseListInit(pServer->requestTree, &rbList)))
    {
        DEBUG_ERROR(DEBUG_RADIUS,"RBtraverseListInit Returned Error  ", status);
        return;
    }

    while (OK == (status = REDBLACK_traverseListGetNext (rbList, (const void **)&pRqst)))
    {
        RADIUS_releaseRequest(pRqst);
    }

    REDBLACK_traverseListFree(&rbList);
    REDBLACK_freeTree(&pServer->requestTree,NULL, NULL, NULL);
}


/*------------------------------------------------------------------*/

static void
radius_serverDelete(sbyte4 serverID, RADIUS_Instance *pInst)
{
    RADIUS_ServerRecord     *pServer = NULL;
    RADIUS_ServerRecord     *pTServer = NULL;
    MSTATUS                 status;

    RADIUS_getServerRecordFromID(serverID, &pServer);

    if (pServer->srcPortListHead)
    {
        RADIUS_deleteServerSrcPortList(pServer);
    }

    if (NULL != pServer->pServerName)
    {
        FREE(pServer->pServerName);   /* This also frees the shared Secret */
        pServer->pServerName = NULL;
    }

    if (NULL != pServer->sharedSecret)
    {
        FREE(pServer->sharedSecret);
        pServer->sharedSecret = NULL;
        pServer->sharedSecretLength =  0;
    }

    if (pServer->backupServerIdPtr)
    {
        FREE(pServer->backupServerIdPtr);
        pServer->backupServerIdPtr = NULL;
        pServer->numBackupServers = 0;
    }

    radius_releaseRequestsForServer(serverID);

    if (OK >  (status = REDBLACK_delete(gRADIUS_globals.serverTree, (const void *)pServer, (const void **)&pTServer)))
    {
        //??
    }

    /* Remove from the Tree */
    status = REDBLACK_delete (pInst->serverTree, (const void *)pServer, (const void **)&pTServer);

    if ((pTServer != pServer) || (OK > status))
    {
        /* ??? */
    }

    ZERO_MOC_IPADDR(pServer->serverAddress);
    pServer->port = 0;
    pServer->sharedSecret = NULL;
    pServer->sharedSecretLength = 0;
    if (pServer->skipCounter <= pServer->cfgPtr->maxSkipCounter)
        pInst->availableServers--;
    pInst->totalServers--;
    /* reset the last Used */
    pInst->lastUsedServerID  = NULL;

    if (OK > (status = MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.serverIdMap, pServer->serverId)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_deleteServer: MBITMAP_clearIndex fialed, status = ", status);
    }
    FREE(pServer);
    gRADIUS_globals.numServers--;
}


/*------------------------------------------------------------------*/

/*! Discontinue communication with a RADIUS server.
This function discontinues communication with the specified RADIUS server by
removing it from the RADIUS Client's list of registered servers.

\since 1.41
\version 1.41 and later

#Include %file:#&nbsp;&nbsp;radius.h

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\param serverID ID of the RADIUS server (returned by RADIUS_addServer) to
remove from server-%client communication.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
extern void RADIUS_shutdown(void)
{
    sbyte4                     i;
    RADIUS_RqstRecord*      pRqst;
    RADIUS_ServerRecord*    pServer;

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_RADIUS, &gRADIUS_globals.hwAccelCtx);

    for (i = RADIUS_MAX_CONNECTIONS, pRqst = gRqstRecords; i--; pRqst++)
        RADIUS_releaseRequest(pRqst);

    for (i = RADIUS_MAX_SERVERS, pServer = gRADIUS_globals.servers; i--; pServer++)
    {
        if (NULL == pServer->udpInfo)
            continue;

        (gRADIUS_globals.funcPtrUnBindUDP)(&pServer->udpInfo);
        RADIUS_releaseServer(SERVER_PTR_TO_ID(pServer));
    }
}
\endexample
*/
extern sbyte4
RADIUS_releaseServer(sbyte4 serverID)
{
    RADIUS_ServerRecord     *pServer = NULL;
    RADIUS_Instance         tInst, *pInst = NULL;
    sbyte4                  status;

    RADIUS_getServerRecordFromID(serverID, &pServer);
    if (NULL == pServer )
    {
        status = ERR_RADIUS_INVALID_SERVER_ID;
        goto exit;
    }

    tInst.instanceId = pServer->radiusInstanceId;

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        goto exit;
    }

    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);
    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if ((NULL == pInst) || (OK > status))
    {
        if (OK == status)
            status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }

    radius_serverDelete(serverID,pInst);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_instanceDelete(RADIUS_Instance *pInst)
{
#ifdef __ENABLE_RFC3576__
    sbyte4                  i;
#endif
    RADIUS_ServerRecord*    pServer;
    redBlackListDescr      *rbList;
    RADIUS_Instance*        tInst;
    MSTATUS                 status = OK;

    if (pInst->instRef > 0)
    {
        status = ERR_RADIUS_INSTANCE_REF_NOT_ZERO;
        goto exit;
    }

    if (OK >  (status = REDBLACK_delete(gRADIUS_globals.instanceTree, (const void *)pInst, (const void **)&tInst)))
    {
        goto exit;
    }

    if (pInst->serverTree)
    {
        if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
        {
            goto exit;
        }

        while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
        {
            radius_serverDelete(pServer->serverId, pInst);
        }

        REDBLACK_traverseListFree (&rbList);
        REDBLACK_freeTree(&pInst->serverTree, NULL, NULL, NULL);
    }

    status = TIMER_destroyTimer(pInst->retryTimer);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "RADIUS_deleteInstance: TIMER_destroyTimer() failed, status = ", status);
    }

#ifdef __ENABLE_RFC3576__
    if (NULL != pInst->pUDPRecv)
    {
        for (i = 0; i < (sbyte4) pInst->config.numInterfaces; i++)
        {
            if (NULL != *(pInst->pUDPRecv+i))
                UDP_unbind(&(*(pInst->pUDPRecv + i)));
        }
        FREE(pInst->pUDPRecv);
    }
#endif
#ifdef __ENABLE_RADIUS_SERVER__
    if (NULL != pInst->pUDPServerRecv)
    {
        for (i = 0; i < pInst->config.numInterfaces; i++)
        {
            if (NULL != *(pInst->pUDPServerRecv+i))
                UDP_unbind(&(*(pInst->pUDPServerRecv + i)));
        }
        FREE(pInst->pUDPServerRecv);
    }
#endif

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_RADIUS, &pInst->config.hwAccelCtx);

    if (OK > (status = MBITMAP_clearIndex((bitmapDescr*)gRADIUS_globals.instanceIdMap, pInst->instanceId)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_deleteInstance: MBITMAP_clearIndex fialed, status = ", status);
    }


    FREE(pInst);
    gRADIUS_globals.numInstances--;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Delete a virtual RADIUS %client instance.
This function deletes a virtual RADIUS %client instance (an instance previously
created by RADIUS_addInstance), including freeing all its resources.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Virtual instance ID previously returned by RADIUS_addInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_addInstance

*/
extern sbyte4
RADIUS_deleteInstance(sbyte4 instanceId)
{
    sbyte4 status = OK;
    RADIUS_Instance *pInst;
    if (OK > (status = radius_getInstancePtrFromId(instanceId, &pInst)))
    {
        return status;
    }
    return radius_instanceDelete(pInst);
}


/*------------------------------------------------------------------*/

/*! Shut down the RADIUS stack, release RADIUS servers, and release memory associated with the RADIUS Client.
This function shuts down the RADIUS stack, calls RADIUS_releaseServer for
each open server ID, and releases all memory associated with the RADIUS Client.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\return None.

\example
RADIUS_shutdown();
--gMocanaAppsRunning;
\endexample
*/
extern void
RADIUS_shutdown(void)
{
    RADIUS_Instance*    pInst;
    redBlackListDescr  *rbList;
    MSTATUS status;

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_RADIUS, &gRADIUS_globals.hwAccelCtx);

    /* Clean up all instances first */
    RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex);

    if (gRADIUS_globals.instanceTree)
    {
        if (OK > (status = REDBLACK_traverseListInit(gRADIUS_globals.instanceTree, &rbList)))
        {
            RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
            return;
        }

        while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pInst)))
        {
            pInst->instRef = 0;
            radius_instanceDelete(pInst);
        }

        REDBLACK_traverseListFree(&rbList);
        REDBLACK_freeTree(&gRADIUS_globals.instanceTree,NULL, NULL, NULL);
    }

    MBITMAP_releaseMap((bitmapDescr**)&gRADIUS_globals.instanceIdMap);
    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
    RTOS_mutexFree(&gRADIUS_globals.instanceTreeMutex);

    /* Clean up all servers */
    if (OK == RTOS_mutexWait(gRADIUS_globals.serverTreeMutex))
    {
        if (gRADIUS_globals.serverTree)
        {
            if (OK == (status = REDBLACK_traverseListInit(gRADIUS_globals.serverTree, &rbList)))
            {
                REDBLACK_traverseListFree(&rbList);
            }
            REDBLACK_freeTree(&gRADIUS_globals.serverTree, NULL, NULL, NULL);
            gRADIUS_globals.serverTree = NULL;
        }

        if (gRADIUS_globals.serverIdMap)
        {
            MBITMAP_releaseMap((bitmapDescr**)&gRADIUS_globals.serverIdMap);
            gRADIUS_globals.serverIdMap = NULL;
        }

        RTOS_mutexRelease(gRADIUS_globals.serverTreeMutex);
    }

    RTOS_mutexFree(&gRADIUS_globals.serverTreeMutex);

    TIMER_deInitTimer();
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
/* concurrency issues. If called from within multiple threads this must be
 * protected with a semaphore */
 /* do not export in radius.h. */
extern MSTATUS
RADIUS_newRequestRecord(RADIUS_RqstRecord **ppRequest,
                        sbyte4 serverID)
{
    RADIUS_RqstRecord*      pRqst;
    MSTATUS                 status = ERR_RADIUS_TOO_MANY_REQUESTS;
    static sbyte4           whichSrcPort = 0;
    RADIUS_ServerRecord*    pServer = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(serverID, &pServer)))
    {
        return status;
    }

    whichSrcPort = (whichSrcPort % pServer->numSrcPorts) + 1;

    DEBUG_ERROR(DEBUG_RADIUS, "newRequestRecord : srcPort #", whichSrcPort);

    *ppRequest = NULL;


    if (NULL == (pRqst = MALLOC(sizeof(RADIUS_RqstRecord))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pRqst, 0x00, sizeof(RADIUS_RqstRecord));

    if (NULL == (pRqst->rqstData = MALLOC(RADIUS_REQUEST_ALLOCATION)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pRqst->rqstData, 0x00, sizeof(RADIUS_RqstRecord));
    pRqst->inUse = TRUE;
    pRqst->serverID = serverID;
    pRqst->serverSrcPortNum = whichSrcPort;
    pRqst->sentCount = 0;
    pRqst->rspAuthenticated = FALSE;
    pRqst->retriesExceeded = FALSE;
    pRqst->userCookie = NULL;
    pRqst->timesChangedServer = 0;

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))
    pRqst->recvPort = 0;
#endif

    *ppRequest = pRqst;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

#define PW_MULTIPLE_OF              MD5_DIGESTSIZE
#define ADJUST_PASSWORD_LENGTH(x)   ((((x) + 15) >> 4) << 4)

static MSTATUS
radius_encryptPassword(ubyte *password, ubyte passwordLength,
                       ubyte *authenticator, ubyte *sharedSecret,
                       ubyte sharedSecretSize, ubyte *outBuffer)
{
    ubyte*      p1;
    ubyte       tBuff[PW_MULTIPLE_OF];
    ubyte       digest[MD5_DIGESTSIZE];
    sbyte4      i, j;
    MD5_CTX     *pCtx = NULL;
    sbyte4      done1st = 0;
    MSTATUS     status = OK;

    if (passwordLength > RADIUS_MAX_PASSWORD_CHARS)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    p1 = outBuffer;

    while (0 < passwordLength)
    {
        for (i = 0; i < PW_MULTIPLE_OF; i++)
        {
            if (0 < passwordLength)
            {
                tBuff[i] = *password++;
                passwordLength--;
            }
            else
            {
                tBuff[i] = 0; /* padding */
            }
        }

        status = MD5Alloc_m(MOC_HASH(gRADIUS_globals.hwAccelCtx)(BulkCtx *) &pCtx);
        if (OK != status)
            goto exit;

        status = MD5Init_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx);
        if (OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, sharedSecret, sharedSecretSize);
        if (OK != status)
            goto exit;

        if (!done1st)
        {
            status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, authenticator, RADIUS_AUTHENTICATOR_SIZE);
            if (OK != status)
                goto exit;
            done1st = 1;
        }
        else
        {
            status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, p1, PW_MULTIPLE_OF);
            if (OK != status)
                goto exit;
            p1 += PW_MULTIPLE_OF;
        }

        status = MD5Final_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, digest);
        if (OK != status)
            goto exit;

        for (j = 0; j < MD5_DIGESTSIZE; j++)
            *(p1 + j) = (ubyte)(digest[j] ^ tBuff[j]);
    }

exit:
    MD5Free_m(MOC_HASH(gRADIUS_globals.hwAccelCtx)(BulkCtx *) &pCtx);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_generateAuthenticator(ubyte *authenticator)
{
    return RANDOM_numberGenerator(g_pRandomContext, authenticator, RADIUS_AUTHENTICATOR_SIZE);
}


/*------------------------------------------------------------------*/

/*! If the shared secret of the new RADIUS server is different than the previous shared secret using which the transactions occured, then the request needs to be reconstructed using the new shared secret. In this case NanoRADIUS calls the callback funcPtrRadiusRebuildReq() to allow the application to reconstruct the request. If the request is of an accounting type, then RADIUS_insertAccountingAuthenticator () must be called, and should be accessible to the application.

\since 5.4
\version 5.4 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pServer RADIUS_ServerRecord * ID of the RADIUS server returned by RADIUS_addServer(). You can typecast the sbyte4 to RADIUS_ServerRecord to satisfy the compiler.
\param pPkt  ubyte * Pointer to request packet that needs insertion of accounting authenticator.
\param pktLen ubyte2 Number of bytes in pPkt.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_addBackupToServer
\sa RADIUS_sendToBackup
\sa RADIUS_setServerStatus

*/
extern MSTATUS
RADIUS_insertAccountingAuthenticator(RADIUS_ServerRecord *pServer,
                                     ubyte *pPkt, ubyte2 pktLen)
{
    ubyte    *pAuth;

    pAuth = pPkt + RADIUS_AUTHENTICATOR_OFFSET;
    /* 16 zero octets */
    DIGI_MEMSET(pAuth, 0, RADIUS_AUTHENTICATOR_SIZE);

    RADIUS_generateAccountingAuthenticator(pPkt, pktLen, pServer, pAuth, pAuth);

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
/* do not export in radius.h */
extern MSTATUS
RADIUS_generateRequestHeader(RADIUS_RqstRecord *pRqst, ubyte code)
{
    MSTATUS                 status;
    ubyte*                  p;
    RADIUS_RqstRecord*      pTRqst;
    RADIUS_ServerRecord*    pServer;

    /* this must be the first routine called when constructing a request */
    if (0 != pRqst->rqstLength)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    pServer = NULL;
    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        goto exit;

    p = pRqst->rqstData;

    *p++ = code;

    status = radius_nextRadiusReqId(pRqst);

    if (status != OK)
    {
      goto exit;
    }
    *p++ = (pRqst->requestId);
    p += RADIUS_LENGTH_FIELD_SIZE;  /* wait til end */

    if (!RADIUS_IS_ACCOUNTING_REQUEST_CODE(pRqst->rqstData))
        radius_generateAuthenticator(p);   /* need to encrypt User-Password */

    p += RADIUS_AUTHENTICATOR_SIZE;

    pRqst->rqstLength = (ubyte2)(p - pRqst->rqstData);

    if (OK > (status = REDBLACK_findOrInsert (pServer->requestTree,(const void *)pRqst, (const void **)&pTRqst)))
        goto exit;

    if (NULL != pTRqst)
    {
      status = ERR_RBTREE_INSERT_FAILED;
      goto exit;
    }

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
/* do not export to radius.h. */
extern MSTATUS
RADIUS_appendUserPassword(RADIUS_RqstRecord *pRequest, ubyte* password,
                          ubyte passwordLength)
{
    MSTATUS                 status;
    RADIUS_RqstRecord*      pRqst = (RADIUS_RqstRecord*)pRequest;
    RADIUS_ServerRecord*    pServer;
    ubyte                   adjustedPWLength;
    ubyte*                  p;
    ubyte*                  pAuth;

    if ((NULL == pRqst) || (NULL == password) || (0 == passwordLength))
    {
        status = (MSTATUS) RADIUS_ERROR;
        goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        goto exit;

    adjustedPWLength = (ubyte)(ADJUST_PASSWORD_LENGTH(passwordLength));

    if (RADIUS_REQUEST_ALLOCATION < (pRqst->rqstLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE + adjustedPWLength))
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    pAuth = pRqst->rqstData + RADIUS_AUTHENTICATOR_OFFSET;
    p = pRqst->rqstData + pRqst->rqstLength;

    *p++ = RADIUS_ATTR_USER_PASSWORD;
    *p++ = (ubyte)(adjustedPWLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);

    if (0 > (status = radius_encryptPassword(password, passwordLength, pAuth,
                                             pServer->sharedSecret,
                                             (ubyte)pServer->sharedSecretLength, p)))
    {
        goto exit;
    }

    p += adjustedPWLength;

    pRqst->rqstLength = (ubyte2)(p - pRqst->rqstData);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Create a custom subattribute buffer.
This function creates a custom attribute buffer which can be appended as a
subattribute to a request/response buffer's attribute data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note To avoid memory leaks, be sure to free the resultant buffer by calling
RADIUS_releaseVendorSpecificAttributeBuffer.

\param ppAttr   On return, pointer to address of buffer containing a copy of the attribute's data.
\param vendorID Application-specific ID that indicates the desired vendor.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
// create/bind a custom attribute to the request
if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
    goto exit;

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
    goto exit;

// send the request
status = RADIUS_requestSend(pRadiusReq);
\endexample

*/
extern sbyte4
RADIUS_newVendorSpecificAttributeBuffer(ubyte **ppAttr, ubyte4 vendorID)
{
    ubyte*  p;
    ubyte*  q;
    sbyte4  status = OK;

    *ppAttr = NULL;

    if (NULL == (p = MALLOC(VENDOR_SPECIFIC_ATTR_MEM_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    q = p;
    *q++ = RADIUS_ATTR_VENDOR_SPECIFIC;
    q++;       /* set length later */

    *q++ = (ubyte)(vendorID >> 24);
    *q++ = (ubyte)(vendorID >> 16);
    *q++ = (ubyte)(vendorID >> 8);
    *q++ = (ubyte)(vendorID);

    *(p + RADIUS_ATTRIBUTE_LENGTH_OFFSET) = (ubyte)(q - p);

    *ppAttr = p;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Append a subattribute to a buffer.
This function appends the specified subattribute to an attribute buffer that
will be used in a RADIUS request record.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pAttr        On return, pointer to buffer containing appended subattribute.
\param type         Value representing type of subattribute to add (see "Attribute Types").
\param pData        Pointer to the buffer containing the subattribute data to add.
\param dataLength   Number of bytes in $pData$ (not the length of the subattribute itself).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
// create/bind a custom attribute to the request
if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
    goto exit;

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
    goto exit;

// send the request
status = RADIUS_requestSend(pRadiusReq);
\endexample
*/
extern sbyte4
RADIUS_appendSubAttributeToAttributeBuffer(ubyte *pAttr, ubyte type,
                                           ubyte *pData, ubyte dataLength)
{
    ubyte*  q;
    ubyte   curLen;
    sbyte4  status = OK;

    if ((NULL == pAttr) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    curLen = *(pAttr + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

    if (VENDOR_SPECIFIC_ATTR_MEM_SIZE < (curLen + dataLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE))
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    q = pAttr + curLen;
    *q++ = type;
    *q++ = (ubyte)(dataLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);

    DIGI_MEMCPY(q, pData, dataLength);
    q += dataLength;
    *(pAttr + RADIUS_ATTRIBUTE_LENGTH_OFFSET) = (ubyte)(q - pAttr);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Free memory allocated for vendor-specific attribute management.
This function frees memory allocated for vendor-specific attribute management
(see RADIUS_newVendorSpecificAttributeBuffer).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pAttr    Pointer to buffer to free.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
// create/bind a custom attribute to the request
if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
    goto exit;

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
    goto exit;

// send the request
status = RADIUS_requestSend(pRadiusReq);

exit:
if (NULL != pVSAttr)
    RADIUS_releaseVendorSpecificAttributeBuffer(pVSAttr);
\endexample
*/
extern void
RADIUS_releaseVendorSpecificAttributeBuffer(ubyte *pAttr)
{
    FREE(pAttr);
}


/*------------------------------------------------------------------*/

/*! Specify which RADIUS server is the primary (UP) server to which all transactions are sent.
This function specifies which RADIUS server is the primary (UP) server to which
all transactions are sent.

Your application can use this function to mark the current server (the
$serverId$ parameter value) either UP or DOWN. If it's marked UP (by specifying
$FALSE$ for the $isTrue$ parameter), the current server continues as the primary
server. However, if the current server is marked DOWN (by specifying $TRUE$ for
the $isTrue$ parameter), the specified backup server (the $index$ parameter) is
selected as the new primary server, and is marked UP.

\since 5.4
\version 5.4 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverId ID of RADIUS server (returned by RADIUS_addServer).
\param isTrue   $TRUE$ to switch the primary from the current server to the
specified backup server; $FALSE$ for no changes to the primary and backup
servers.
\param index    Backup server to mark as the new primary server, specified as a
0-based index into the current server's $backupId$ array (previously set by
RADIUS_addBackupToServer or RADIUS_modifyBackupToServer).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\sa RADIUS_addBackupToServer
\sa RADIUS_modifyBackupToServer
\sa RADIUS_setServerStatus

*/
extern MSTATUS
RADIUS_sendToBackup(sbyte4 serverId, ubyte isTrue, ubyte4 index)
{
    MSTATUS                status = OK;
    RADIUS_ServerRecord    *bkupSrvr, *tbkupSrvr;
    RADIUS_ServerRecord    *pSrvr = NULL;
    RADIUS_Instance        tInst, *pInst;

    if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pSrvr)))
        goto exit;

    if (FALSE == isTrue)
    {
        pSrvr->serverStatus = RADIUS_SERVER_UP;
        pSrvr->calledFailoverInd = FALSE;
        pSrvr->sendToBackup = FALSE;
        goto exit;
    }

    if (index >= pSrvr->numBackupServers)
    {
        status = ERR_RADIUS_INVALID_SERVER_ID;
        goto exit;
    }

    RADIUS_getServerRecordFromID(pSrvr->backupServerIdPtr[index], &bkupSrvr);

    tInst.instanceId = pSrvr->radiusInstanceId;

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        goto exit;
    }
    status = REDBLACK_find(gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst);

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if ((NULL == pInst) || (OK > status))
    {
        if (OK == status)
            status = ERR_RADIUS_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }

    status = REDBLACK_find(pInst->serverTree, (const void *)bkupSrvr, (const void **)&tbkupSrvr);

    if ((NULL == tbkupSrvr) || (OK > status))
    {
        if (OK == status)
            status = ERR_RADIUS_INVALID_SERVER_ID;
        goto exit;
    }
    pSrvr->backupServerIndex = index;
    pSrvr->sendToBackup = TRUE;
    pSrvr->serverStatus = RADIUS_SERVER_DOWN;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_reconf_rqstNextServer(RADIUS_RqstRecord *pRqst, RADIUS_ServerRecord *pSrvr, RADIUS_ServerRecord *newSrvr)
{
    MSTATUS                status = OK;
    RADIUS_RqstRecord      *pTRqst;
    sbyte4                 cmp;
    ubyte                  *pRqData;

    /* remove this request from the request tree of the server which
     * is down
     */
    if (OK > (status = REDBLACK_delete(pSrvr->requestTree, (void *)pRqst, (const void **)&pTRqst)))
        goto exit;

    if (pTRqst != pRqst)
    {
        status = ERR_RADIUS_REQUEST_NOT_FOUND;
        goto exit;
    }

    if (OK > (status = radius_freeRadiusReqId(pRqst)))
        goto exit;

    pRqst->serverID = newSrvr->serverId;
    pRqst->serverSrcPortNum = radius_round_robin(newSrvr);
    pRqst->sentCount = 0;

    DIGI_MEMCMP(pSrvr->sharedSecret,newSrvr->sharedSecret,
               newSrvr->sharedSecretLength,&cmp);

    if ((pSrvr->sharedSecretLength != newSrvr->sharedSecretLength) || (cmp))
    {
        if (pSrvr->cfgPtr->funcPtrRadiusRebuildReq)
        {
            if (OK > (status = radius_getRadiusReqId(pRqst)))
            {
                RADIUS_releaseRequest(pRqst);
                goto exit;
            }
            pRqData = pRqst->rqstData;
            *(pRqData+1) = (pRqst->requestId);

            status = pSrvr->cfgPtr->funcPtrRadiusRebuildReq(pRqst,
                                                            pRqst->serverID);
            if (OK > status)
            {
                RADIUS_releaseRequest(pRqst);
                goto exit;
            }
        }
        else
        {
            status = ERR_RADIUS_NO_REBUILD_CALLBACK;
            goto exit;
        }
    }
    else
    {
        if (OK > (status = radius_nextRadiusReqId(pRqst)))
            goto exit;
        pRqData = pRqst->rqstData;
        *(pRqData+1) = (pRqst->requestId);
        if (pSrvr->cfgPtr->funcPtrRadiusRebuildReq)
        {
            status = pSrvr->cfgPtr->funcPtrRadiusRebuildReq(pRqst, pRqst->serverID);
            if (OK > status)
            {
                RADIUS_releaseRequest(pRqst);
                goto exit;
            }
        }
        else
        {
            status = ERR_RADIUS_NO_REBUILD_CALLBACK;
            goto exit;
        }
    }
    /* now insert the request that was just deleted into the request tree
     * of the new radius server
     */
    if (OK > (status = REDBLACK_findOrInsert (newSrvr->requestTree,(const void *)pRqst, (const void **)&pTRqst)))
        goto exit;

    if (NULL != pTRqst)
    {
        status = ERR_RBTREE_INSERT_FAILED;
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_reconf_rqst(RADIUS_RqstRecord *pRqst, RADIUS_ServerRecord *pSrvr,
                   RADIUS_ServerRecord **newSrvr)
{
    MSTATUS                status = OK;
    RADIUS_ServerRecord    *bkupSrvr;
    RADIUS_RqstRecord      *pTRqst;
    ubyte4                 index;
    sbyte4                 cmp;
    ubyte                  *pRqData;

    *newSrvr = NULL;

    index = pSrvr->backupServerIndex;

    if (index >= pSrvr->numBackupServers)
    {
        status = ERR_RADIUS_INVALID_BACKUP_INDEX;
        goto exit;
    }

    RADIUS_getServerRecordFromID(pSrvr->backupServerIdPtr[index], &bkupSrvr);
    if (RADIUS_SERVER_UP != bkupSrvr->serverStatus)
    {
        status = ERR_RADIUS_BACKUP_NOT_ACTIVE;
        goto exit;
    }

    /* remove this request from the request tree of the server which
     * is down
     */
    if (OK > (status = REDBLACK_delete(pSrvr->requestTree, (void *)pRqst, (const void **)&pTRqst)))
        goto exit;

    if (pTRqst != pRqst)
    {
        status = ERR_RADIUS_REQUEST_NOT_FOUND;
        goto exit;
    }

    if (OK > (status = radius_freeRadiusReqId(pRqst)))
        goto exit;

    pRqst->serverID = pSrvr->backupServerIdPtr[index];
    pRqst->serverSrcPortNum = radius_round_robin(bkupSrvr);
    pRqst->sentCount = 0;

   DIGI_MEMCMP(pSrvr->sharedSecret,bkupSrvr->sharedSecret,
              bkupSrvr->sharedSecretLength,&cmp);

    if ((pSrvr->sharedSecretLength != bkupSrvr->sharedSecretLength) || (cmp))
    {
        if (pSrvr->cfgPtr->funcPtrRadiusRebuildReq)
        {
            if (OK > (status = radius_getRadiusReqId(pRqst)))
            {
                RADIUS_releaseRequest(pRqst);
                goto exit;
            }
            pRqData = pRqst->rqstData;
            *(pRqData+1) = (pRqst->requestId);

            status = pSrvr->cfgPtr->funcPtrRadiusRebuildReq(pRqst,
                                                            pRqst->serverID);
            if (OK > status)
            {
                RADIUS_releaseRequest(pRqst);
                goto exit;
            }
        }
        else
        {
            status = ERR_RADIUS_NO_REBUILD_CALLBACK;
            goto exit;
        }
    }
    else
    {
        if (OK > (status = radius_nextRadiusReqId(pRqst)))
            goto exit;

        pRqData = pRqst->rqstData;
        *(pRqData+1) = (pRqst->requestId);
        if (pSrvr->cfgPtr->funcPtrRadiusRebuildReq)
        {
            status = pSrvr->cfgPtr->funcPtrRadiusRebuildReq(pRqst, pRqst->serverID);
            if (OK > status)
            {
                RADIUS_releaseRequest(pRqst);
                goto exit;
            }
        }
        else
        {
            status = ERR_RADIUS_NO_REBUILD_CALLBACK;
            goto exit;
        }
    }
    /* now insert the request that was just deleted into the request tree
     * of the backup radius server
     */
    if (OK > (status = REDBLACK_findOrInsert (bkupSrvr->requestTree,(const void *)pRqst, (const void **)&pTRqst)))
        goto exit;

    if (NULL != pTRqst)
    {
        status = ERR_RBTREE_INSERT_FAILED;
        goto exit;
    }
    *newSrvr = bkupSrvr;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
/* do not export to radius.h */
extern MSTATUS
RADIUS_sendRequest(RADIUS_RqstRecord *pRqst)
{
    RADIUS_ServerRecord     *pServer;
    RADIUS_Instance         *pInst;
    ubyte*                  p;
    ubyte2                  len;
    ubyte                   temp;
    sbyte4                  status;
    ubyte4          i;
    ubyte2                  len_save, auth_offset;
    ubyte                   result[MD5_DIGESTSIZE];

    RADIUS_ServerSrcPortRec *pSportRec = NULL;

    if ((NULL == pRqst) || (RADIUS_MIN_PKT_LEN > pRqst->rqstLength)
        || (0 != pRqst->sentCount))
    {
        status = RADIUS_ERROR;
        goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        goto exit;

    // RFC 2869 section 5.14
    // Secure Hardening: Enforce adding the Message-Authenticator attribute in Access-Request

    // if Message-Authenticator attribute is not included in Access-Request, add this attribute
    if (OK > ( status = RADIUS_requestGetAttributeByType(pRqst, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, &p, &temp)))
    {

        len_save = pRqst->rqstLength;
        DIGI_MEMSET(result, 0, MD5_DIGESTSIZE);

        if (OK > (status = RADIUS_requestAppendAttribute(pRqst,
                                             RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                                             result, MD5_DIGESTSIZE)))
        {
            goto exit;
        }
        auth_offset = len_save + 2;

        len = pRqst->rqstLength;
        p = pRqst->rqstData + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE;

        *p++ = (ubyte)(len >> 8);
        *p++ = (ubyte)(len);

        HMAC_MD5(MOC_HASH(hwAccelCtx) pServer->sharedSecret, (ubyte)pServer->sharedSecretLength,
                 pRqst->rqstData, len, 0, 0, result);

        DIGI_MEMCPY(pRqst->rqstData + auth_offset, result, MD5_DIGESTSIZE);
    }

    if (OK > (status = radius_getInstancePtrFromId(pServer->radiusInstanceId,
                                                  &pInst)))
    {
        goto exit;
    }

    if (pServer->sendToBackup && (RADIUS_SERVER_DOWN == pServer->serverStatus))
    {
        RADIUS_ServerRecord *newSrvr = NULL;
        if ( RADIUS_LB_NONE == pServer->cfgPtr->loadBalAlgo )
        {
            if (OK > (status = radius_reconf_rqst(pRqst,pServer,&newSrvr)))
            {
                goto exit;
            }
        }
        else if ( RADIUS_LB_ROUNDROBIN == pServer->cfgPtr->loadBalAlgo )
        {
            if (RADIUS_IS_AUTH_REQUEST_CODE(pRqst->rqstData))
            {
                sbyte4 newServerID;
                if (OK > (status = RADIUS_getNextRRServer(pServer->radiusInstanceId, RADIUS_CODE_ACCESS_REQUEST,
                                                          pServer->backupServerIdPtr[pServer->backupServerIndex], &newServerID)))
                {
                    goto exit;
                }
                if (OK > (status = RADIUS_getServerRecordFromID(newServerID, &newSrvr)))
                {
                    goto exit;
                }
            }
            else if (RADIUS_IS_ACCOUNTING_REQUEST_CODE(pRqst->rqstData))
            {
                sbyte4 newServerID;
                if (OK > (status = RADIUS_getNextRRServer(pServer->radiusInstanceId, RADIUS_CODE_ACCOUNTING_REQUEST,
                                                          pServer->backupServerIdPtr[pServer->backupServerIndex], &newServerID)))
                {
                    goto exit;
                }
                if (OK > (status = RADIUS_getServerRecordFromID(newServerID, &newSrvr)))
                {
                    goto exit;
                }
            }

            if (OK > (status = radius_reconf_rqst(pRqst, pServer, &newSrvr)))
            {
                goto exit;
            }

        }
        if (NULL == newSrvr)
        {
            status = ERR_RADIUS_SERVER_NOT_FOUND;
            goto exit;
        }
        pServer = newSrvr;
    }

    if (RADIUS_SERVER_DOWN == pServer->serverStatus)
    {
        status = ERR_RADIUS_SERVER_NOT_ACTIVE;
        goto exit;
    }

    pSportRec = pServer->srcPortListHead;

    for (i = 0; i < pServer->numSrcPorts; i++)
    {
        if (pSportRec->srcPortNum == pRqst->serverSrcPortNum)
            break;
        pSportRec = pSportRec->next;
    }

    /* set length field */
    len = pRqst->rqstLength;
    p = pRqst->rqstData + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE;
    *p++ = (ubyte)(len >> 8);
    *p++ = (ubyte)(len);

    /* set authenticator field */
    if (RADIUS_IS_ACCOUNTING_REQUEST_CODE(pRqst->rqstData))
      RADIUS_insertAccountingAuthenticator(pServer, pRqst->rqstData, len);

    status = pServer->cfgPtr->funcPtrSendUDP(pSportRec->udpInfo,
                                             pRqst->rqstData, len);
    if ((OK == status) ||
       ((ERR_UDP_WRITE == status) && (RADIUS_LB_NONE != pServer->cfgPtr->loadBalAlgo )))

    {   /* As of Now Override this for Situations where Multiserver has been specified  */
        if (ERR_UDP_WRITE == status)
        {
            status = OK;
            pRqst->sentCount = (sbyte4)pServer->cfgPtr->radiusRetryCount;
            pServer->counters.txFails++;
        }
        else
            pServer->counters.txPacket++;

        TIMER_queueTimer((void *)pRqst, pInst->retryTimer,
                      pServer->cfgPtr->radiusRetryIntervalMS/1000,0);
    }
    pRqst->sentCount++;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
radius_repeatRequest(RADIUS_RqstRecord *pRqst)
{
    RADIUS_ServerRecord*        pServer;
    RADIUS_ServerSrcPortRec*    pSportRec;
    RADIUS_Instance*            pInst;
    RADIUS_ServerRecord*        newSrvr = NULL;
    sbyte4                      status;
    ubyte4                      i;

    if ((NULL == pRqst) || (0 == pRqst->sentCount))
    {
      status = RADIUS_ERROR;
      goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        goto exit;

    if (OK > (status = radius_getInstancePtrFromId(pServer->radiusInstanceId,
                                                  &pInst)))
    {
        goto exit;
    }

    if ( RADIUS_LB_NONE == pServer->cfgPtr->loadBalAlgo )
    {
        if (pServer->sendToBackup && (RADIUS_SERVER_DOWN == pServer->serverStatus))
        {
            if (OK > (status = radius_reconf_rqst(pRqst,pServer,&newSrvr)))
            {
                goto exit;
            }
            pServer = newSrvr;
        }

        if (RADIUS_SERVER_DOWN == pServer->serverStatus)
        {
            status = ERR_RADIUS_SERVER_NOT_ACTIVE;
            goto exit;
        }
    }
    else /* Get the next Server if required */
    {
        if (pRqst->sentCount > (sbyte4)pServer->cfgPtr->radiusRetryCount)
        {
            if (RADIUS_IS_AUTH_REQUEST_CODE(pRqst->rqstData))
            {
                sbyte4 newServerID;
                if (OK > (status = RADIUS_getNextRRServer(pServer->radiusInstanceId, RADIUS_CODE_ACCESS_REQUEST, pServer->serverId, &newServerID)))
                {
                    goto exit;
                }
                if (OK > (status = RADIUS_getServerRecordFromID(newServerID, &newSrvr)))
                {
                    goto exit;
                }
            }
            else if (RADIUS_IS_ACCOUNTING_REQUEST_CODE(pRqst->rqstData))
            {
                sbyte4 newServerID;
                if (OK > (status = RADIUS_getNextRRServer(pServer->radiusInstanceId, RADIUS_CODE_ACCOUNTING_REQUEST, pServer->serverId, &newServerID)))
                {
                    goto exit;
                }
                if (OK > (status = RADIUS_getServerRecordFromID(newServerID, &newSrvr)))
                {
                    goto exit;
                }
            }

            if ((OK > status) || (NULL == newSrvr))
            {
                if (NULL == newSrvr)
                {
                    status = ERR_RADIUS_SERVER_NOT_ACTIVE;
                }
                goto exit;
            }

            if ( (FALSE == pServer->calledFailoverInd) && (pServer->skipCounter < pServer->cfgPtr->maxSkipCounter))
            {
                pServer->skipCounter++;
            }

            if ((pServer->skipCounter == pServer->cfgPtr->maxSkipCounter)  &&
                (pServer->calledFailoverInd == FALSE))
            {
                pInst->availableServers--;
                pServer->calledFailoverInd = TRUE;
                pServer->serverStatus = RADIUS_SERVER_DOWN;
                if (pServer->backupServerIdPtr && (pServer->numBackupServers > 0) )
                {
                    pServer->sendToBackup = TRUE;
                }
                if (pServer->cfgPtr->funcPtrRadiusFailoverInd)
                {
                    pServer->cfgPtr->funcPtrRadiusFailoverInd(pRqst->userCookie,
                                                            RADIUS_MAX_SKIP_EXCEEDED,
                                                            pRqst->serverID);
                }
            }

            if (OK > (status = radius_reconf_rqstNextServer(pRqst,pServer,newSrvr)))
            {
                goto exit;
            }

            pRqst->timesChangedServer++;
            /* Change to the New Server */
            pServer = newSrvr;
        }
    }

    pSportRec = pServer->srcPortListHead;

    for (i = 0; i < pServer->numSrcPorts; i++)
    {
        if (pSportRec->srcPortNum == pRqst->serverSrcPortNum)
            break;
        pSportRec = pSportRec->next;
    }

    status = pServer->cfgPtr->funcPtrSendUDP(pSportRec->udpInfo,
                                             pRqst->rqstData,
                                             pRqst->rqstLength);

    if ((OK == status) ||
       ((ERR_UDP_WRITE == status) && (RADIUS_LB_NONE != pServer->cfgPtr->loadBalAlgo )))

    {   /* As of Now Override this for Situations where Multiserver has been specified  */
        if (ERR_UDP_WRITE == status)
        {
            status = OK;
            pRqst->sentCount = (sbyte4)pServer->cfgPtr->radiusRetryCount;
            pServer->counters.txFails++;
        }
        else
            pServer->counters.txPacket++;

        TIMER_queueTimer((void *)pRqst, pInst->retryTimer,
                      pServer->cfgPtr->radiusRetryIntervalMS/1000,0);
    }
    else
    {
        pServer->counters.txFails++;
    }
    pRqst->sentCount++;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
radius_validateResponseAuthenticator(RADIUS_RqstRecord *pRqst,
                                     ubyte *rspBuffer, ubyte4 rspLength, sbyte4 *isOK)
{
    RADIUS_ServerRecord*    pServer;
    ubyte                   digest[MD5_DIGESTSIZE];
    sbyte4                  compare;
    MSTATUS                 status;

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        goto exit;

    RADIUS_generateAccountingAuthenticator( rspBuffer, rspLength, pServer, pRqst->rqstData + RADIUS_AUTHENTICATOR_OFFSET, digest);

    if (OK > (status = DIGI_MEMCMP(digest, rspBuffer + RADIUS_AUTHENTICATOR_OFFSET, RADIUS_AUTHENTICATOR_SIZE, &compare)))
       goto exit;

    *isOK = (0 == compare) ? TRUE : FALSE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Verify that a packet contains a properly formatted RADIUS request.
This function verifies that a packet contains a properly formatted RADIUS
request, as specified by RFC&nbsp;2865.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note Typically you will not need to call this function because response packets
are automatically validated by RADIUS_pollForResponse before the response
is attached to the request cookie.
\note This function does not verify the authenticator because doing so would
require knowing this response's corresponding request.

\param pPkt     Pointer to packet to verify.
\param pktLen   Number of bytes in pPkt.
\param serverID ID of the RADIUS server (returned by RADIUS_addServer) for which
the request was intended.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_pktValidate(ubyte *pPkt, ubyte4 pktLen, sbyte4 serverID)
{
    RADIUS_ServerRecord*    pServer;
    RADIUS_Counters         ctrs;
    RADIUS_Counters*        pCtrs;
    sbyte4                  statedLen;
    ubyte4                  i;
    ubyte                   statedCode;
    sbyte4                  codeOK = 0;
    ubyte*                  p;
    ubyte*                  opl;
    sbyte4                  status = ERR_RADIUS_BAD_RESPONSE;

    /* below, if fails, the worst is that the stats won't get incremented. */
    if (OK > RADIUS_getServerRecordFromID(serverID, &pServer))
        pCtrs = &ctrs;    /* dummy record so we don't have to check ptrs */
    else
        pCtrs = &pServer->counters;

    if ((pktLen < RADIUS_MIN_PKT_LEN) || (pktLen > RADIUS_MAX_PKT_LEN))
    {
        pCtrs->rxBadLength++;
        goto exit;
    }

    statedLen = *(pPkt+RADIUS_LENGTH_OFFSET);
    statedLen = (statedLen << 8) + *(pPkt+RADIUS_LENGTH_OFFSET+1);

    if ((statedLen < RADIUS_MIN_PKT_LEN) || (statedLen > RADIUS_MAX_PKT_LEN))
    {
        pCtrs->rxBadLength++;
        goto exit;
    }

    statedCode = *(pPkt + RADIUS_CODE_OFFSET);

    for (i = 0; i < SUPPORTED_RSP_CODES_COUNT; i++)
    {
        if (supportedRspCodes[i] == statedCode)
        {
            codeOK = 1;
            break;
        }
    }

    if (1 != codeOK)
    {
        pCtrs->rxBadCode++;
        goto exit;
    }

    if (((sbyte4)pktLen) < statedLen)
    {
        pCtrs->rxBadLength++;
        goto exit;
    }

    /* walk attributes and make sure they're ok */
    p = pPkt + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE + RADIUS_LENGTH_FIELD_SIZE + RADIUS_AUTHENTICATOR_SIZE;

    opl = pPkt + statedLen;

    while (p < opl)
        p += *(p + 1);

    if (p != opl)
    {
        pCtrs->rxBadAttributes++;
        goto exit;
    }

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Validate a response's authenticator and return the corresponding original request.
This function validates a response's authenticator and returns the response's
corresponding original request.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverID ID of RADIUS server (returned by RADIUS_addServer).
\param srcPort  Response's UDP listen port field value.
\param pBuffer  Pointer to response data.
\param buflen   Number of bytes of response data ($pBuffer$).
\param pRqst    On return, pointer to response record containing the original
request and the validated response.
\param pResult  On return, pointer to one of the following $RADIUS_RESULT$ values:
$RADIUS_NOT_FOUND$, $RADIUS_FOUND$, $RADIUS_ERROR$, or
$RADIUS_RETRIES_EXCEEDED$. (None of the other $RADIUS_RESULT$ values will be
returned.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseCallback(sbyte4 serverID, ubyte2 srcPort,
                ubyte *pBuffer ,ubyte4 buflen,
                        RADIUS_RqstRecord **pRqst, RADIUS_RESULT* pResult )
{
    ubyte4                      i;
    sbyte4                      ok;
    RADIUS_RESULT               result = RADIUS_NOT_FOUND;
    RADIUS_ServerRecord*        pServer = NULL;
    RADIUS_ServerSrcPortRec*    pSportRec;
    RADIUS_RqstRecord*          pRecord = NULL;
    RADIUS_Instance*            pInst = NULL;
    RADIUS_RqstRecord           tmpRecord;
    sbyte4                      status = OK;

    if (OK > (status = RADIUS_getServerRecordFromID(serverID, &pServer)))
        goto exit;

    if (OK > (status = radius_getInstancePtrFromId(pServer->radiusInstanceId,
                                                  &pInst)))
    {
        goto exit;
    }

    pSportRec = pServer->srcPortListHead;

    if (0 < buflen)
    {
        for (i = 0; i < pServer->numSrcPorts; i++)
        {
            if (pSportRec->srcPort == srcPort )
                break;
            pSportRec = pSportRec->next;
        }
        if (OK > (status = RADIUS_pktValidate(pBuffer, buflen, serverID)))
            goto exit;

       tmpRecord.serverID = serverID;
       tmpRecord.serverSrcPortNum = pSportRec->srcPortNum;
       (tmpRecord.requestId) = *(pBuffer + RADIUS_IDENTIFIER_OFFSET);

       if (OK > (status = REDBLACK_find ( pServer->requestTree, (const void *)&tmpRecord, (const void **)&pRecord)))
           goto exit;

       if (NULL == pRecord)
       {
           status = RADIUS_NOT_FOUND;
           goto exit;
       }

       if (NULL != pRecord->rspData)
           FREE(pRecord->rspData);

       if (NULL == (pRecord->rspData = MALLOC(buflen)))
       {
           status = RADIUS_ERROR;
           goto exit;
       }

       radius_freeRadiusReqId(pRecord);

       DIGI_MEMCPY(pRecord->rspData, pBuffer, buflen);
       pRecord->rspLength = (ubyte2)buflen;
       result = RADIUS_FOUND;
       *pRqst = pRecord;

       radius_validateResponseAuthenticator(pRecord, pBuffer, buflen, &ok);

       if (!ok)
       {
           /* just continue for now */
           pServer->counters.rxBadAuthenticator++;
       }
       else
       {

           pRecord->rspAuthenticated = TRUE;
           pServer->counters.rxGoodPacket++;
       }
       /*The Server is sending responses */
       if (pServer->skipCounter == pServer->cfgPtr->maxSkipCounter)
       {
           pInst->availableServers++;
           pServer->calledFailoverInd = FALSE;
       }
       pServer->skipCounter = 0;
   }

exit:
    *pResult = result;
    return status;
}


/*------------------------------------------------------------------*/

/*! Check a RADIUS client's timer to provide time to the RADIUS stack.
This function checks a RADIUS client's timer. Your application should call
this function on every clock tick (every 300 to 500 milliseconds) to provide
time to the RADIUS stack.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Virtual instance ID previously returned by RADIUS_addInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_periodic(sbyte4 instanceId)
{

/* Currently handle Timeout etc being called by the Calling App */
/* TODO Change this to a Timer Callback */

    MSTATUS            status = OK;
    RADIUS_Instance    *pInst;

    if (OK == (status = radius_getInstancePtrFromId(instanceId, &pInst)))
    {
        TIMER_checkTimer(pInst->retryTimer);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Read response data for any request or a specific request.
This function reads (receives) data corresponding to a specified request or for
any requests, depending on the value you specify for the request pointer:\n
\n
- #Valid, non-NULL#&mdash;The value returned through $pResult$ indicates
whether there is data available corresponding to the specified request.
- #NULL#&mdash;The function enables your RADIUS %client to read (receive) any
data (in which case $RADIUS_FOUND$ is returned through $pResult$), and/or retransmit
unacknowledged requests (in which case $RADIUS_FOUND$ or $RADIUS_NOT_FOUND$ is
returned through $pResult$).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Instance ID returned from an _initInstance call.
\param pRqst        $NULL$ or descriptor for a RADIUS authentication/accounting request.
\param pResult      On return, pointer to one of the following $RADIUS_RESULT$
values: $RADIUS_NOT_FOUND$, $RADIUS_FOUND$, $RADIUS_ERROR$, or
$RADIUS_RETRIES_EXCEEDED$. (None of the other $RADIUS_RESULT$ values will be
returned.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
while (pending)
    {
        RTOS_sleepMS(500);  // a select() or some other mechanism would be preferable to catch UDP packets
                            // for portability the example code does a simple sleep

        // give RADIUS time. Do not rely on "result" to determine if
         * data is available, because multiple packets might have been
         * read in previously, and result == RADIUS_FOUND only if
         * NEW data is read in.

        if (OK > (status = RADIUS_pollForResponse(NULL, &result)))
        {
            goto exit;
        }

        if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))
        {
            status = ERR_RADIUS;
            goto exit;
        }

        switch (result)
        {
          ...
            default:
                goto exit;  // too odd to continue
        }

    } // while (pending)
\endexample

*/
extern sbyte4
RADIUS_pollForResponse(sbyte4 instanceId,RADIUS_RqstRecord *pRqst,
                       RADIUS_RESULT* pResult)
{
    ubyte*                  pBuffer;
    ubyte4                  i, buflen;
    sbyte4                  dos_loop, ok;
    RADIUS_RESULT           result = RADIUS_NOT_FOUND;
    RADIUS_ServerRecord*    pServer;
    RADIUS_RqstRecord       pRecord, *pTRecord;
    sbyte4                  status = OK;
    redBlackListDescr       *rbList = NULL;
    RADIUS_Instance         tInst, *pInst;

    if (NULL == (pBuffer = MALLOC(RADIUS_MAX_PKT_LEN)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    tInst.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        goto exit;
    }

    if (OK > (status  = REDBLACK_find (gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst)))
    {
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if (NULL == pInst)
    {
       goto exit;
    }


    TIMER_checkTimer(pInst->retryTimer);

    if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
    {
        goto exit;
    }

    while (OK == (REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
    {
        /* Then read from all open sockets. */

        buflen = 0;     /* remove false compilation warning */

      for (i = 0; i < pServer->numSrcPorts; i++)
      {
          RADIUS_ServerSrcPortRec *pSportRec = pServer->srcPortListHead;
          for (dos_loop = 0; dos_loop < 10 ; dos_loop++)
          {

              /* we attempt to receive a UDP packet on a port in the
               * hopes of scrubbing a way any bad packets
               */

              buflen = 0;

              if (OK > (status = (pServer->cfgPtr->funcPtrPollUDP)(pSportRec->udpInfo, pBuffer, RADIUS_MAX_PKT_LEN, &buflen)))
              {
                  goto exit;  /* error in reading UDP socket */
              }

              if (0 < buflen)
              {
                  if (OK > (status = RADIUS_pktValidate(pBuffer, buflen,
                                                        pServer->serverId)))
                  {
                      /* invalid packet was received, remove it and
                       * try to get another UDP packet from socket
                       */
                      continue;
                  }
                  else
                      break;
              }
          }

          if (0 == buflen)
          {
              break;
          }

          if (pServer->skipCounter > pServer->cfgPtr->maxSkipCounter)
          {
              pInst->availableServers++;
              pServer->calledFailoverInd = FALSE;
          }
          pServer->skipCounter = 0;

          pRecord.serverID = pServer->serverId;
          pRecord.serverSrcPortNum = pSportRec->srcPortNum;
          pRecord.requestId = (ubyte2)*(pBuffer + RADIUS_IDENTIFIER_OFFSET);

          status = REDBLACK_find(pServer->requestTree, (const void *)&pRecord, (const void **)&pTRecord);

          if ((NULL == pTRecord ) || (OK > status))
          {
              break;
          }

          if (NULL != pTRecord->rspData)
          {
              FREE(pTRecord->rspData);
          }

          if (NULL == (pTRecord->rspData = MALLOC(buflen)))
          {
              status = RADIUS_ERROR;
              goto exit;
          }

          DIGI_MEMCPY(pTRecord->rspData, pBuffer, buflen);
          pTRecord->rspLength = (ubyte2)buflen;
          result = RADIUS_FOUND;

          radius_validateResponseAuthenticator(pTRecord,pBuffer,buflen,&ok);

          if (!ok)
          {
              pServer->counters.rxBadAuthenticator++;
          }
          else
          {
              pTRecord->rspAuthenticated = TRUE;
              pServer->counters.rxGoodPacket++;
          }
          pSportRec = pSportRec->next;

          break;

        }

        if (RADIUS_FOUND == result)
        {
          break;
        }
    }

    /*
     * Finally, look for the record you're interested in.
     * It's ok to call this routine and pass in NULL, though.
     */
    if (NULL != pRqst)
    {
        /* Now, look for response for the request */
        /* note this may override result's previous value. */
        result = RADIUS_getResponseStatus(pRqst);
    }

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);
    if (rbList)
        REDBLACK_traverseListFree(&rbList);
    *pResult = result;

    return status;
}


/*------------------------------------------------------------------*/

/*! Determine whether a response has been received for a request.
This function determines whether a response has been received for the specified
request, and returns the result as a $RADIUS_RESULT$ value (see
"Request/Response Result Codes").

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.

\return One of the following $RADIUS_RESULT$ values: $RADIUS_NOT_FOUND$,
$RADIUS_FOUND$, or $RADIUS_ERROR$. (None of the other $RADIUS_RESULT$ values
will be returned.)

\note Unless your %client code allocates time to the RADIUS processing by calling
RADIUS_pollForResponse, no responses will ever be received, and the
$RADIUS_RESULT$ return value will never be $RADIUS_FOUND$.

*/
extern RADIUS_RESULT
RADIUS_getResponseStatus(RADIUS_RqstRecord *pRequest)
{
    if (NULL == pRequest)
        return RADIUS_ERROR;

    if (TRUE == ((RADIUS_RqstRecord*)pRequest)->retriesExceeded)
        return RADIUS_RETRIES_EXCEEDED;

    return (NULL == ((RADIUS_RqstRecord*)pRequest)->rspData) ? RADIUS_NOT_FOUND : RADIUS_FOUND;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
/* do not export to radius.h. */
extern intBoolean
RADIUS_getResponseAuthenticated(RADIUS_RqstRecord *pRequest)
{
    intBoolean  result = FALSE;

    if (RADIUS_FOUND == RADIUS_getResponseStatus(pRequest))
        result = ((RADIUS_RqstRecord*)pRequest)->rspAuthenticated;

    return result;
}


/*------------------------------------------------------------------*/

/*! Get a request pointer that corresponds to a request for which a response has been received.
This function retrieves a request pointer that corresponds to a request for
which a response has been received.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Instance ID returned from an _initInstance call.
\param ppRequest    Pointer into which this function returns a RADIUS request descriptor corresponding to a request for which a response has been received.

\return One of the following $RADIUS_RESULT$ values: $RADIUS_NOT_FOUND$,
$RADIUS_FOUND$, or $RADIUS_ERROR$. (None of the other $RADIUS_RESULT$ values
will be returned.)

\note Unless your client code allocates time to the RADIUS processing by calling
RADIUS_pollForResponse, no responses will ever be
received, and the $RADIUS_RESULT$ return value will never be $RADIUS_FOUND$.

\example
while (pending)
{
    RTOS_sleepMS(1);

    // give RADIUS time. Do not rely on "result" to determine if data is available
    // because multiple packets might have been read i npreviously, and
    // result == RADIUS_FOUND only if NEW data is read in.
    if (OK > (status = RADIUS_pollForResponse(NULL, &result)))
    {
        goto exit;
    }
    if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))
    {
        status = ERR_RADIUS;
        goto exit;
    }

    switch (result)
    {
        case RADIUS_RETRIES_EXCEEDED:
            printf("Retries Exceeded.\n");
            if (OK == RADIUS_requestGetUsername(pRadiusReq, &nm, &nmLen))
            {
                printf("request username: ");
                radius_printChars(nm, nmLen);
                printf("\n");
            }
            RADIUS_requestRelease(&pRadiusReq);
            pending--;
            break;
        case RADIUS_NOT_FOUND:
            continue;
    }
}
\endexample
*/
extern RADIUS_RESULT
RADIUS_getAResponse(sbyte4 instanceId,RADIUS_RqstRecord **ppRequest)
{
    RADIUS_RESULT       result = RADIUS_NOT_FOUND;
    RADIUS_ServerRecord *pServer;
    redBlackListDescr   *rbList = NULL;
    RADIUS_Instance     tInst, *pInst;
    MSTATUS             status ;

    *ppRequest = NULL;

    if (OK > (RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        goto exit;
    }

    tInst.instanceId = instanceId;
    if (OK > (status  = REDBLACK_find (gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst)))
    {
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if (NULL == pInst)
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
    {
        goto exit;
    }

    while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
    {
        if (pServer->requestTree != NULL)
        {
            result = lookForResponse(pServer, ppRequest);
            if (RADIUS_FOUND == result  || RADIUS_RETRIES_EXCEEDED == result)
            {
                break;
            }
        }
        else
        {
            continue;
        }
    }
    REDBLACK_traverseListFree(&rbList);

exit:
   return result;
}


/*------------------------------------------------------------------*/

static RADIUS_RESULT
lookForResponse(RADIUS_ServerRecord *pServer, RADIUS_RqstRecord **ppRequest)
{
    redBlackListDescr *rbList;
    RADIUS_RqstRecord *pRqst;
    RADIUS_RESULT result = RADIUS_NOT_FOUND;
    MSTATUS  status = OK;

    if (OK > (status = REDBLACK_traverseListInit(pServer->requestTree, &rbList)))
    {
        DEBUG_ERROR(DEBUG_RADIUS,"RBtraverseListInit Returned Error  ", status);
        goto exit;
    }

    while (OK == (status = REDBLACK_traverseListGetNext (rbList, (const void **)&pRqst)))
    {
        if (NULL != pRqst->rspData)
        {
            result = RADIUS_FOUND;
           *ppRequest = pRqst;
          break;
        }

        if (TRUE == pRqst->retriesExceeded)
        {
            result = RADIUS_RETRIES_EXCEEDED;
            *ppRequest = pRqst;
            break;
        }
    }
    REDBLACK_traverseListFree(&rbList);

exit:
    return result;
}


/*------------------------------------------------------------------*/

/*! Get a request matching the specified $User-Name$ attribute.
This function evaluates the requests/responses array and returns the first
request it finds that contains an attribute matching the specified $User-Name$
attribute. If no match is found, $NULL$ is returned.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note The first match found is returned, regardless of whether there are
additional matches in the requests/responses array.

\param pName    Desired name to match against the requests' $User-Name$ attribute.
\param namelen  Number of bytes in $pName$.
\param serverID ID of the RADIUS server (returned by RADIUS_addServer) for which the request was intended.

\return Pointer to the request record; $NULL$ if no match found.

*/
extern RADIUS_RqstRecord*
RADIUS_getRequestRecordFromName(ubyte *pName, ubyte4 namelen, sbyte4 serverID)
{
    MSTATUS             status;
    sbyte4              compare;
    RADIUS_RqstRecord*  pRqst;
    ubyte*              pRqstName;
    ubyte               rqstNameLength;
    RADIUS_RqstRecord*  p = NULL;
    redBlackListDescr   *rbList;
    RADIUS_ServerRecord *pServer = NULL;

    if (OK > (status = RADIUS_getServerRecordFromID(serverID, &pServer)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_getServerRecordFromID: Server ID invalid, status = ", status);
        return NULL;
    }

    if (OK > (status = REDBLACK_traverseListInit(pServer->requestTree, &rbList)))
    {
        DEBUG_ERROR(DEBUG_RADIUS, "RADIUS_getRequestRecordFromName: rbopenlist() failed, status = ", status);
        return NULL;
    }

    while (OK == (status = REDBLACK_traverseListGetNext (rbList, (const void **)&pRqst)))
    {
        status = RADIUS_requestGetAttributeByType(pRqst, RADIUS_ATTR_USER_NAME,
                                                  &pRqstName, &rqstNameLength);

        if (ERR_NOT_FOUND != status)
        {
            if (OK == status)
            {
                if ((rqstNameLength != namelen) ||
                    (OK > (status = DIGI_MEMCMP(pRqstName, pName, namelen, &compare))) ||
                    (0 != compare) || (pRqst->serverID != serverID) )
                {
                    continue;
                }

                p = pRqst;
            }
            break;
        }
    }
    REDBLACK_traverseListFree(&rbList);

    return p;
}


/*------------------------------------------------------------------*/

/*! Generate a new request in response to a RADIUS server challenge.
This function generates a new request in response to a RADIUS server challenge,
which is itself a response to an initial request by the RADIUS Client
($pOriginalRequest$).\n
\n
On return, the $ppNewRequest$ value points to a reference to the new request,
which in the case of a $SUCCESSFUL$ return is typically another RADIUS request.
(The $pOriginalRequest$ value is still valid, and typically you should immediately
call RADIUS_requestRelease for that request.)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pOriginalRequest Pointer to original %client request record.
\param ppNewRequest     On return, pointer to address of new request.
\param pResponse        Pointer to response buffer containing information to complete the authentication.
\param responseLength   Number of bytes in response buffer ($pResponse$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
static int radius_EXAMPLE_doChallenge(RADIUS_RqstRecord *pRequest)
{
    sbyte*              defaultPrompt = "Enter Response: ", prompt;
    char                pResponse[RADIUS_EXAMPLE_RESPONSE_MAX+1], *q;
    RADIUS_RqstRecord*  pNewRequest;

    if (OK != RADIUS_responseGetAttributeAsCString(pRequest, RADIUS_ATTR_REPLY_MESSAGE, &prompt))
        prompt = defaultPrompt;

    printf("%s\nType in your response: ", prompt);
    fgets(pResponse, RADIUS_EXAMPLE_RESPONSE_MAX, stdin);

    if (prompt != defaultPrompt)
        RADIUS_responseFreeString(&prompt);

    // get rid newline char(s) at end of response
    for (q = pResponse + DIGI_STRLEN(pResponse) - 1; q >= pResponse; q--)
    {
        if (*q <= ' ')    // kill trailing wsp and ctl chars too while at it
        {
            *q = 0;
        }
        else break;
    }

    return RADIUS_respondToAccessChallenge(pRequest, &pNewRequest, (ubyte*)pResponse, DIGI_STRLEN(pResponse));
}
\endexample
*/
extern sbyte4
RADIUS_respondToAccessChallenge(RADIUS_RqstRecord *pOriginalRequest,
                                RADIUS_RqstRecord **ppNewRequest,
                                ubyte* pResponse, ubyte4 responseLength)
{
    RADIUS_RqstRecord*  pORqst = (RADIUS_RqstRecord*)pOriginalRequest;
    RADIUS_RqstRecord*  pNewRequest = NULL;
    ubyte               type;
    ubyte*              pData;
    ubyte2              pLength;
    ubyte               len;
    ubyte*              pVal;
    sbyte4              i;
    intBoolean          done;
    sbyte4              status;

    *ppNewRequest = pNewRequest;

    /* Make sure
        - pOriginalRequest is reasonable
        - the response is an Access-Challenge
    */
    if (OK > (status = RADIUS_requestNew(&pNewRequest, pORqst->serverID, RADIUS_CODE_ACCESS_REQUEST)))
    {
        goto exit;
    }

    /* should not be a problem that the password is in front of the User-Name.
     * From RFC 2865: "A RADIUS server or client MUST NOT have any dependencies
     * on the order of attributes of different types."
     */
    if (OK > (status = RADIUS_requestAppendUserPassword(pNewRequest, pResponse, (ubyte)responseLength)))
        goto exit;

    /* Append (most) of the original request attributes */
    pData = pORqst->rqstData;
    pLength = pORqst->rqstLength;
    i = 0;
    done = FALSE;

    while (!done)
    {
        status = RADIUS_getAttributeByIndex(pData, pLength, i, &type, &pVal, &len);

        switch (status)
        {
            case ERR_INDEX_OOB:
            {
                done = TRUE;
                break;
            }

            case OK:
            {
                if (RADIUS_ATTR_USER_PASSWORD != type)
                    if (OK > (status = RADIUS_requestAppendAttribute(pNewRequest, type, pVal, len)))
                        goto exit;

                break;
            }

            default:
            {
                goto exit;
            }
        }

        i++;
    }

    /* Append some of the Access-Challenge attributes */
    pData = pORqst->rspData;
    pLength = pORqst->rspLength;
    i = 0;
    done = FALSE;

    while (!done)
    {
        status = RADIUS_getAttributeByIndex(pData, pLength, i, &type, &pVal, &len);

        switch (status)
        {
            case OK:
            {
                switch (type)
                {
                    case RADIUS_ATTR_STATE:
                    {
                        if (OK > (status = RADIUS_requestAppendAttribute(pNewRequest, type, pVal, len)))
                            goto exit;

                        break;
                    }

                    default:
                    {
                        break;
                    }
                }

                break;
            }

            case ERR_INDEX_OOB:
            {
                done = TRUE;
                break;
            }

            default:
            {
                goto exit;
            }
        }

        i++;
    }

    if (OK > (status = RADIUS_requestSend(pNewRequest)))
        goto exit;

    *ppNewRequest = pNewRequest;
    pNewRequest = NULL;

exit:
    if (NULL != pNewRequest)
        RADIUS_releaseRequest(pNewRequest);

    return status;
}


/*------------------------------------------------------------------*/

/*! Get the statistics (counters) between the RADIUS Client and a server.
This function retrieves the statistics (counters) for communication between the
RADIUS Client and the specified server.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param serverID     ID of the RADIUS server (returned by RADIUS_addServer for which the statistics are requested.
\param pCounters    Pointer to valid, allocated memory into which this function returns the counter results.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK == RADIUS_getCounters(authServerID, &counters))
    {
        printf("Counters for auth server:\n");
        radius_EXAMPLE_printCounters(&counters);
    }

    if (OK == RADIUS_getAllCounters(&counters))
    {
        printf("Counters for all servers:\n");
        radius_EXAMPLE_printCounters(&counters);
    }
\endexample
*/
extern sbyte4
RADIUS_getCounters(sbyte4 serverID, RADIUS_Counters *pCounters)
{
    sbyte4 status;
    RADIUS_ServerRecord *pServer = NULL;

    if (NULL == pCounters)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(serverID, &pServer)))
        goto exit;

    DIGI_MEMCPY((ubyte*)pCounters, (ubyte*)&pServer->counters, sizeof(*pCounters));

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the sum of the statistics (counters) between the RADIUS Client and its registered servers.
This function retrieves the sum of the statistics (counters) of communication
between the RADIUS Client and all its currently registered servers.

\since 1.41
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Instance ID returned from an _initInstance call.
\param pCounters    Pointer to valid, allocated memory into which this function
returns the counter results. (See RADIUS_Counters.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK == RADIUS_getCounters(authServerID, &counters))
    {
        printf("Counters for auth server:\n");
        radius_EXAMPLE_printCounters(&counters);
    }

    if (OK == RADIUS_getAllCounters(&counters))
    {
        printf("Counters for all servers:\n");
        radius_EXAMPLE_printCounters(&counters);
    }
\endexample
*/
extern sbyte4
RADIUS_getAllCounters(sbyte4 instanceId,RADIUS_Counters *pCounters)
{
    RADIUS_Instance     tInst, *pInst;
    RADIUS_ServerRecord *pServer;
    redBlackListDescr *rbList;
    sbyte4 status;

    if (NULL == pCounters)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = RTOS_mutexWait(gRADIUS_globals.instanceTreeMutex)))
    {
        goto exit;
    }

    tInst.instanceId = instanceId;

    if (OK > (status  = REDBLACK_find (gRADIUS_globals.instanceTree, (const void *)&tInst, (const void **)&pInst)))
    {
        RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);
        goto exit;
    }

    RTOS_mutexRelease(gRADIUS_globals.instanceTreeMutex);

    if (NULL == pInst)
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
    {
        goto exit;
    }

    DIGI_MEMSET((ubyte*)pCounters, 0, sizeof(*pCounters));

    while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
    {
            pCounters->txPacket             += pServer->counters.txPacket;
            pCounters->txFails              += pServer->counters.txFails;
            pCounters->txRetries            += pServer->counters.txRetries;
            pCounters->rxGoodPacket         += pServer->counters.rxGoodPacket;
            pCounters->rxBadCode            += pServer->counters.rxBadCode;
            pCounters->rxBadLength          += pServer->counters.rxBadLength;
            pCounters->rxBadAttributes      += pServer->counters.rxBadAttributes;
            pCounters->rxBadAuthenticator   += pServer->counters.rxBadAuthenticator;
    }

    REDBLACK_traverseListFree(&rbList);
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/


#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))
/*------------------------------------------------------------------*/

static MSTATUS
RADIUS_reqPktValidate( ubyte* pPkt, /*in out*/ubyte4* pktLen, RADIUS_ServerRecord* pServer)
{
    ubyte4      statedLen;
    ubyte4      i;
    ubyte       statedCode;
    intBoolean  codeOK = FALSE;
    ubyte*      p;
    ubyte*      opl;
    /* array initialized to 0 to use as input to MD5 first, then as MD5 hash */
    ubyte       digest[MD5_RESULT_SIZE] = {0};
    sbyte4      cmpResult;
    MSTATUS     status = ERR_RADIUS_BAD_REQUEST;

    if ((*pktLen < RADIUS_MIN_PKT_LEN) || (*pktLen > RADIUS_MAX_PKT_LEN))
    {
        pServer->counters.rxBadLength++;
        goto exit;
    }

    statedLen = *(pPkt+RADIUS_LENGTH_OFFSET);
    statedLen = (statedLen << 8) + *(pPkt+RADIUS_LENGTH_OFFSET+1);

    if ((statedLen < RADIUS_MIN_PKT_LEN) || (statedLen > RADIUS_MAX_PKT_LEN))
    {
        pServer->counters.rxBadLength++;
        goto exit;
    }

    if (*pktLen < statedLen)
    {
        pServer->counters.rxBadLength++;
        goto exit;
    }
    /* ok for buffer to be bigger than statedLen -> return the correct one*/
    *pktLen = statedLen;

    statedCode = *(pPkt + RADIUS_CODE_OFFSET);

    for (i = 0; i < SUPPORTED_REQ_CODES_COUNT; i++)
    {
        if (supportedReqCodes[i] == statedCode)
        {
            codeOK = TRUE;
            break;
        }
    }

    if (!codeOK)
    {
        pServer->counters.rxBadCode++;
        goto exit;
    }

#ifndef __ENABLE_RADIUS_SERVER__
    /* validate the authenticator (same as accounting authenticator) */
    RADIUS_generateAccountingAuthenticator( pPkt, statedLen, pServer, digest, digest);

    /* not testing return value of DIGI_MEMCMP */
    DIGI_MEMCMP( pPkt + RADIUS_AUTHENTICATOR_OFFSET, digest, MD5_RESULT_SIZE, &cmpResult);
    if ( cmpResult)
    {
        pServer->counters.rxBadAuthenticator++;
        goto exit;
    }
#endif

    /* walk attributes and make sure they're ok */
    p = pPkt + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE + RADIUS_LENGTH_FIELD_SIZE + RADIUS_AUTHENTICATOR_SIZE;

    opl = pPkt + statedLen;

    while (p < opl)
        p += *(p + 1);

    if (p != opl)
    {
        pServer->counters.rxBadAttributes++;
        goto exit;
    }

    pServer->counters.rxGoodPacket++;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the next request received on any configured interface.
This function retrieves the next request received on any of the interfaces
configured to receive RFC&nbsp;3576 CoA (Change-of-Authorization) messages on
port&nbsp;3799.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\note Be sure to call this function before registering the RADIUS servers.

\param instanceId   Instance ID returned from an _initInstance call.
\param ppRequest    On return, pointer to address of request record received.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK > (status = RADIUS_pollForRequest(&pServerRequest)))
    goto exit;

if  (pServerRequest )
{
    ubyte responseCode;

    gotOne = 1;
    // process it and send a response
    // first step is to see if there is a forced response code
    if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
        goto exit;

    if (0 == responseCode)
    {
        // no forced response so we will sent ACK always in this example

        ...

    }

    // send a response with the response code
    if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
        goto exit;

    if (OK > (status = RADIUS_responseSend( pServerRequest)))
        goto exit;
}

exit:
if (pServerRequest)
{
    RADIUS_requestRelease( &pServerRequest);
}
\endexample
*/
extern MSTATUS
RADIUS_pollForRequest(sbyte4 instanceId, RADIUS_RqstRecord **ppRequest)
{
    sbyte4                i;
    ubyte4                buffLen = 0;
    ubyte*                pBuffer = 0;
    RADIUS_ServerRecord   *pServer;
    MSTATUS               status = OK;
    MOC_IP_ADDRESS_S      recvFromAddr;
    ubyte2                recvFromPort;
    redBlackListDescr     *rbList;
    RADIUS_Instance       *pInst;

    /* allocate a buffer for the read */
    if (NULL == (pBuffer = MALLOC(RADIUS_MAX_PKT_LEN)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = radius_getInstancePtrFromId(instanceId, &pInst);
    if (OK > status)
    {
        goto exit;
    }

    for (i = 0; i < (sbyte4) pInst->config.numInterfaces; i++)
    {
#ifdef __ENABLE_RFC3576__
        if (OK > (status = UDP_recvFrom(*(pInst->pUDPRecv+i),
                        &recvFromAddr, &recvFromPort,
                                        pBuffer, RADIUS_MAX_PKT_LEN, &buffLen)))
        {
            goto exit;
        }
        if (buffLen > 0)
        {
            break;
        }
#endif
#ifdef __ENABLE_RADIUS_SERVER__
        if (OK > (status = UDP_recvFrom(*(pInst->pUDPServerRecv+i),
                        &recvFromAddr, &recvFromPort,
                                        pBuffer, RADIUS_MAX_PKT_LEN, &buffLen)))
        {
            goto exit;
        }
        if (buffLen > 0)
        {
            break;
        }
#endif

    }

    /* in case we have tried reading from all fd's and received nothing */
    if (buffLen <= 0)
    {
        goto exit;
    }

    if (NULL == pInst->serverTree)
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_traverseListInit(pInst->serverTree, &rbList)))
    {
        goto exit;
    }

    while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&pServer)))
    {
#ifdef __ENABLE_RFC3576__
        if (ISZERO_MOC_IPADDR(pServer->serverAddress) ||
            SAME_MOC_IPADDR(pServer->serverAddress, recvFromAddr))
    	            break;
#endif
#ifdef __ENABLE_RADIUS_SERVER__
        MOC_IP_ADDRESS myAddr = pServer->cfgPtr->interfaceArrayPtr[i];
        /* If Listenning on all interfaces  or a specific interface*/
        if (!myAddr || SAME_MOC_IPADDR(myAddr, recvFromAddr))
            break;
#endif
    }

    REDBLACK_traverseListFree(&rbList);

    if (NULL == pServer)
    {
        goto exit;
    }

    /* verify it makes sense */
    if (OK > (status = RADIUS_reqPktValidate(pBuffer, &buffLen, pServer)))
        goto exit;

    /* build a new RADIUS_RqstRecord with this */
    if (OK > (status = RADIUS_newRequestRecord( ppRequest, pServer->serverId)))
        goto exit;

    /* fill in the specific fields */
    (*ppRequest)->interfaceNum = i;
    (*ppRequest)->recvPort = recvFromPort;
    /* exchange the buffers allocated by RADIUS_newRequestRecord */
    (*ppRequest)->rspData = (*ppRequest)->rqstData;
    (*ppRequest)->rqstData = pBuffer;
    pBuffer = 0;
    (*ppRequest)->rqstLength = (ubyte2) buffLen;

exit:
    if (pBuffer)
    {
        FREE(pBuffer);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a response record's response code.
This function extracts the response code from the specified response record and
returns the response code through the $forcedResponseCode$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRqst                Pointer to response record.
\param forcedResponseCode   On return, pointer to response code.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
    goto exit;

if (0 == responseCode)
{
    // no forced response so we will sent ACK always in this example
    ubyte requestCode;
    if (OK > (status = RADIUS_requestGetCode( pServerRequest, &requestCode)))
        goto exit;
    if (RADIUS_CODE_DISCONNECT_REQUEST == requestCode)
    {
        responseCode = RADIUS_CODE_DISCONNECT_ACK;
    }
    else if (RADIUS_CODE_COA_REQUEST  == requestCode)
    {
        responseCode = RADIUS_CODE_COA_ACK;
    }
    else
    {
        status = ERR_RADIUS_BAD_REQUEST;
        goto exit;
    }
}

// send a response with the response code
if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
    goto exit;

if (OK > (status = RADIUS_responseSend( pServerRequest)))
    goto exit;

exit:
if (pServerRequest)
{
RADIUS_requestRelease( &pServerRequest);
}
\endexample
*/
extern MSTATUS
RADIUS_responseForcedCode(RADIUS_RqstRecord* pRqst, ubyte* forcedResponseCode)
{
    ubyte   requestCode, serviceTypeAttrLen;
    ubyte*  serviceTypeAttr;
    MSTATUS status;


    if (NULL == forcedResponseCode)
        return ERR_NULL_POINTER;

    *forcedResponseCode = 0; /* means no forcedResponseCode */

    /* we don't test for NULL pointer here because the next call to
        RADIUS_requestGetCode will do it for us */
    if  (OK > (status = RADIUS_requestGetCode( pRqst, &requestCode)))
        goto exit;

    if  (OK > ( status = RADIUS_requestGetAttributeByType( pRqst, RADIUS_ATTR_SERVICE_TYPE,
                                                            &serviceTypeAttr, &serviceTypeAttrLen)))
    {
        /*this will return either an error or ERR_NOT_FOUND this is OK */
        if ( ERR_NOT_FOUND == status)
        {
            status = OK;
        }
        goto exit;
    }

    /* if the Service-Type Attr is "Authorize Only", then there is a forced response
        cf pages 6-7 of RFC 3576 */

    if ( AUTHORIZE_ONLY_LEN == serviceTypeAttrLen)
    {
        sbyte4 cmpResult;
        DIGI_MEMCMP((ubyte*) AUTHORIZE_ONLY_STR, serviceTypeAttr, AUTHORIZE_ONLY_LEN, &cmpResult);
        if ( 0 == cmpResult)
        {
            if (RADIUS_CODE_DISCONNECT_REQUEST == requestCode)
            {
                *forcedResponseCode = RADIUS_CODE_DISCONNECT_NAK;
            }
            else if (RADIUS_CODE_COA_REQUEST  == requestCode)
            {
                *forcedResponseCode = RADIUS_CODE_COA_NAK;
            }
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Build a response record.
This function builds a response record and returns it through the $pRqst$
parameter. After this function is called, attributes can be added by calling
additional functions.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param pRqst        On return, pointer to response record.
\param responseCode Response code to use in the response record.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
    goto exit;

if (0 == responseCode)
{
    // no forced response so we will sent ACK always in this example
    ubyte requestCode;
    if (OK > (status = RADIUS_requestGetCode( pServerRequest, &requestCode)))
        goto exit;
    if (RADIUS_CODE_DISCONNECT_REQUEST == requestCode)
    {
        responseCode = RADIUS_CODE_DISCONNECT_ACK;
    }
    else if (RADIUS_CODE_COA_REQUEST  == requestCode)
    {
        responseCode = RADIUS_CODE_COA_ACK;
    }
    else
    {
        status = ERR_RADIUS_BAD_REQUEST;
        goto exit;
    }
}

// send a response with the response code
if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
    goto exit;

if (OK > (status = RADIUS_responseSend( pServerRequest)))
    goto exit;
\endexample
*/
extern MSTATUS
RADIUS_responsePrepare(RADIUS_RqstRecord* pRqst, ubyte responseCode)
{
    MSTATUS status;
    ubyte*  pResponse;
    ubyte*  pRequest;

    if ( 0 == pRqst)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( 0 == pRqst->rqstData || 0 == pRqst->rspData)
    {
        status = ERR_RADIUS_BAD_REQUEST;
        goto exit;
    }

    /* this must be the first routine called when constructing a response */
    if (0 != pRqst->rspLength)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    pResponse = pRqst->rspData;
    pRequest = pRqst->rqstData;

    *pResponse++ = responseCode;
    *pResponse++ = pRequest[1]; /* copy the ID from the request */

    pResponse += RADIUS_LENGTH_FIELD_SIZE +  /* wait til end */
                    RADIUS_AUTHENTICATOR_SIZE;

    pRqst->rspLength = (ubyte)(pResponse - pRqst->rspData);

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Send a prepared response.
This function sends a prepared response record as specified by its headers.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius.h

\param instanceId   Instance ID returned from an _initInstance call.
\param pRqst        Pointer to response record to send.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error %status, use the
$DISPLAY_ERROR$ macro.

\example
// send a response with the response code
if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
    goto exit;

if (OK > (status = RADIUS_responseSend( pServerRequest)))
    goto exit;

\endexample
*/
extern MSTATUS
RADIUS_responseSend(sbyte4 instanceId, RADIUS_RqstRecord *pRqst)
{
    RADIUS_Instance         *pInst;
    RADIUS_ServerRecord*    pServer;
    ubyte*                  p;
    ubyte2                  len;
    sbyte4                  status;

    if ((NULL == pRqst) || (RADIUS_MIN_PKT_LEN > pRqst->rspLength))
    {
        status = RADIUS_ERROR;
        goto exit;
    }

    if (OK > (status = radius_getInstancePtrFromId(instanceId, &pInst)))
        goto exit;

    if (OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID, &pServer)))
        goto exit;

    /* set length field */
    len = pRqst->rspLength;
    p = pRqst->rspData + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE;
    *p++ = (ubyte)(len >> 8);
    *p++ = (ubyte)(len);

    /* set authenticator field */
    RADIUS_generateAccountingAuthenticator( pRqst->rspData, len, pServer,
                        pRqst->rqstData + RADIUS_AUTHENTICATOR_OFFSET,
                        pRqst->rspData + RADIUS_AUTHENTICATOR_OFFSET);

    /* just fire away the packet - no retries  */
#ifdef __ENABLE_RFC3576__
    if (OK <= (status = UDP_sendTo(*(pInst->pUDPRecv + pRqst->interfaceNum),
                                    REF_MOC_IPADDR(pServer->serverAddress), pRqst->recvPort,
                                    pRqst->rspData, len)))
#else
    if (OK <= (status = UDP_sendTo(*(pInst->pUDPServerRecv + pRqst->interfaceNum),
                                    REF_MOC_IPADDR(pServer->serverAddress), pRqst->recvPort,
                                    pRqst->rspData, len)))

#endif
    {
        pServer->counters.txPacket++;
    }
    else
    {
        pServer->counters.txFails++;
    }

exit:
    return status;
}

#endif


/*------------------------------------------------------------------*/

/* don't export! this is only for testing, and makes no sense in
 * the real world. Also, not bothering with error checking. */

#ifdef RADIUS_TESTING
extern void
RADIUS_FakeResponse(RADIUS_RqstRecord *pRequest)
{
    RADIUS_RqstRecord*      pRqst = (RADIUS_RqstRecord*)pRequest;

    pRqst->rspData = MALLOC(pRqst->rqstLength);
    DIGI_MEMCPY(pRqst->rspData, pRqst->rqstData, pRqst->rqstLength);
    pRqst->rspLength = pRqst->rqstLength;
}
#endif /* RADIUS_TESTING */

#endif /* __ENABLE_DIGICERT_RADIUS_CLIENT__ */

