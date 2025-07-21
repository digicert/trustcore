/*
 * ssh.c
 *
 * SSH Developer API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
@file       ssh.c 
@brief      NanoSSH Server developer API.
@details    This file contains NanoSSH Server API functions.

@since 1.41
@version 4.2 and later

@flags
To enable any of this file's functions, the following flag must be defined in
moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__

Whether the following flags are defined determines which functions are enabled:
+ \c \__DISABLE_MOCANA_INIT__
+ \c \__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__
+ \c \__ENABLE_MOCANA_SSH_PING__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__
+ \c \__USE_MOCANA_SSH_SERVER__

@filedoc    ssh.c
*/

#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_SERVER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/circ_buf.h"
#include "../common/debug_console.h"
#include "../common/int64.h"
#include "../common/sizedbuffer.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/rsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto/ecc.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_trans.h"
#include "../ssh/ssh_session.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh_server.h"
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh_in_mesg.h"
#include "../ssh/ssh_out_mesg.h"
#include "../ssh/ssh_ftp.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh.h"
#include "../harness/harness.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#endif

/*------------------------------------------------------------------*/

static volatile sbyte4  m_instance;
static sshSettings      m_sshSettings;

/**
@cond
*/
sbyte4           g_sshMaxConnections;
sshConnectDescr* g_connectTable;

#define NUM_SSH_CONNECTIONS ((g_sshMaxConnections > m_sshSettings.sshMaxConnections) ? (m_sshSettings.sshMaxConnections) : (g_sshMaxConnections))
/**
@endcond
*/

/*------------------------------------------------------------------*/

/* prototypes */
extern sbyte4 SSH_INTERNAL_API_setOpenState(sbyte4 connectionInstance);
extern sbyte4 SSH_sendErrMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);


#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static sbyte4 getPfSessionFromChannel(sshContext * pContextSSH, ubyte4 channel, sshPfSession** ppPfSession)
{
    MSTATUS status = ERR_SSH_BAD_ID;
    sshPfSession*   pTemp = pContextSSH->pPfSessionHead;

    while ( NULL != pTemp )
    {
        if ( channel == pTemp->pfSessionData.recipientChannel )
        {
            (*ppPfSession) = pTemp;
            status = OK;
            break;
        }
        else
        {
            pTemp = pTemp->pNextSession;
        }
    } /* End of while loop */

    return status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */


/*------------------------------------------------------------------*/

extern sshSettings *
SSH_sshSettings(void)
{
    return &m_sshSettings;
}


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
static sbyte4
sshProtocolUpcall(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent,
                  ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  numBytesWritten;
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if (connectionInstance == g_connectTable[index].instance)
        {
            ubyte           tmpBuf[3];
            circBufDescr*   pCircBufDescr = g_connectTable[index].pCircBufDescr;

            if ((SSH_SESSION_DATA == sessionEvent) || (SSH_SESSION_STDERR == sessionEvent) ||
                (SSH_PF_DATA == sessionEvent)      || (SSH_SESSION_OPEN_EXEC == sessionEvent))
            {
                ubyte4 numBytesToWrite;

                /* nothing to do, just break */
                if (0 == mesgLen)
                {
                    status = OK;
                    break;
                }

                if (MAX_SESSION_WINDOW_SIZE < mesgLen)
                    mesgLen = MAX_SESSION_WINDOW_SIZE;  /*!-!-! should never happen */

                /* store the length of the data */
                if (1 == mesgLen)
                {
                    tmpBuf[0] = (ubyte)sessionEvent;
                    numBytesToWrite = 1;
                }
                else if (256 > mesgLen)
                {
                    tmpBuf[0] = (ubyte)(sessionEvent | 0x80);
                    tmpBuf[1] = (ubyte)(mesgLen & 0xff);
                    numBytesToWrite = 2;
                }
                else
                {
                    tmpBuf[0] = (ubyte)(sessionEvent | 0xc0);
                    tmpBuf[1] = (ubyte)((mesgLen >> 8) & 0xff);
                    tmpBuf[2] = (ubyte)(mesgLen & 0xff);
                    numBytesToWrite = 3;
                }

                if (OK > (status = CIRC_BUF_write(pCircBufDescr, tmpBuf, numBytesToWrite, &numBytesWritten)))
                    break;

                if (numBytesToWrite != numBytesWritten)
                {
                    status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
                    break;
                }

                /* store the data */
                if (OK > (status = CIRC_BUF_write(pCircBufDescr, pMesg, mesgLen, &numBytesWritten)))
                    break;

                if (mesgLen != numBytesWritten)
                {
                    status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
                    break;
                }
            }
            else
            {
                tmpBuf[0] = (ubyte)sessionEvent;

                if (OK > (status = CIRC_BUF_write(pCircBufDescr, tmpBuf, 1, &numBytesWritten)))
                    break;

                if (1 != numBytesWritten)
                {
                    status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
                    break;
                }
            }

            break;
        }
    }

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_init(sbyte4 sshMaxConnections)
{
    sbyte4          index;
    hwAccelDescr    hwAccelCookie;
    intBoolean      isHwAccelInit = FALSE;
    MSTATUS         status;

#ifndef __DISABLE_MOCANA_INIT__
    gMocanaAppsRunning++;
#endif

#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__) || defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_createCombMutexes();
#else
    status = EC_createCombMutexes();
#endif
    if (OK != status)
        goto exit;
#endif

#if ((defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__)) || \
     (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) )
    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCookie)))
        goto exit;

    isHwAccelInit = TRUE;
#endif

    MOC_MEMSET((ubyte *)&m_sshSettings, 0x00, sizeof(sshSettings));

    if (NULL == g_connectTable)
    {
        /* num indices in array */
        g_sshMaxConnections = sshMaxConnections;

        if (NULL == (g_connectTable = MALLOC(sizeof(sshConnectDescr) * sshMaxConnections)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        MOC_MEMSET((ubyte *)g_connectTable, 0x00, sizeof(sshConnectDescr) * sshMaxConnections);
    }
    else
    {
        if (g_sshMaxConnections < sshMaxConnections)
        {
            status = ERR_SSH_CONFIG;
            goto exit;
        }
    }

    m_sshSettings.sshListenPort                 = SSH_DEFAULT_TCPIP_PORT;
    m_sshSettings.sshMaxAuthAttempts            = MAX_SSH_AUTH_ATTEMPTS;
    m_sshSettings.sshTimeOutOpen                = TIMEOUT_SSH_OPEN;
    m_sshSettings.sshTimeOutKeyExchange         = TIMEOUT_SSH_KEX;
    m_sshSettings.sshTimeOutNewKeys             = TIMEOUT_SSH_NEWKEYS;
    m_sshSettings.sshTimeOutServiceRequest      = TIMEOUT_SSH_SERVICE_REQUEST;
    m_sshSettings.sshTimeOutAuthentication      = TIMEOUT_SSH_AUTH_LOGON;
    m_sshSettings.sshTimeOutDefaultOpenState    = TIMEOUT_SSH_OPEN_STATE;
    m_sshSettings.sshMaxConnections             = sshMaxConnections;

    m_sshSettings.funcPtrSessionOpen            = sshProtocolUpcall;
    m_sshSettings.funcPtrPtyRequest             = sshProtocolUpcall;
    m_sshSettings.funcPtrOpenShell              = sshProtocolUpcall;
    m_sshSettings.funcPtrOpenSftp               = sshProtocolUpcall;
    m_sshSettings.funcPtrWindowChange           = sshProtocolUpcall;
    m_sshSettings.funcPtrReceivedData           = sshProtocolUpcall;
    m_sshSettings.funcPtrStdErr                 = sshProtocolUpcall;
    m_sshSettings.funcPtrEof                    = sshProtocolUpcall;
    m_sshSettings.funcPtrClosed                 = sshProtocolUpcall;
    m_sshSettings.funcPtrCloseChannel           = sshProtocolUpcall;
    m_sshSettings.funcPtrBreakOp                = sshProtocolUpcall;
    m_sshSettings.funcPtrExec                   = sshProtocolUpcall;
    m_sshSettings.funcPtrReplyPing              = sshProtocolUpcall;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        g_connectTable[index].connectionState     = CONNECT_DISABLED;
        g_connectTable[index].pReadBuffer         = NULL;
        g_connectTable[index].pReadBufferPosition = NULL;
        g_connectTable[index].numBytesRead        = 0;
    }

    if (OK > (status = SSH_STR_HOUSE_initStringBuffers()))
        goto exit;

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    if (OK > (status = SSH_FTP_initStringBuffers()))
        goto exit;
#endif

#if (!defined(__DISABLE_MOCANA_SSH_RSA_KEY_EXCHANGE__) && defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
    if (OK > (status = SSH_TRANS_initRsaKeyExchange(hwAccelCookie)))
        goto exit;
#endif

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = SSH_TRANS_initSafePrimesDHG(hwAccelCookie)))
        goto exit;
#endif
#endif

    m_instance = 0x1000;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        g_connectTable[index].connectionState = CONNECT_CLOSED;
        g_connectTable[index].pContextSSH     = NULL;
        g_connectTable[index].isSocketClosed  = TRUE;
    }

exit:
    if (TRUE == isHwAccelInit)
    {
        HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCookie);
    }

    DEBUG_PRINT(DEBUG_SSH_MESSAGES, "SSH_init: completed after = (");
    DEBUG_UPTIME(DEBUG_SSH_MESSAGES);
    DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)(") milliseconds."));

    return (sbyte4)status;

} /* SSH_init */
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/
extern sbyte4
SSH_getInstanceFromSocket(TCP_SOCKET socket)
{
    sbyte4     index;
    sbyte4     status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (((TCP_SOCKET)socket == g_connectTable[index].socket) &&
            (CONNECT_CLOSED < g_connectTable[index].connectionState))
        {
            status = g_connectTable[index].instance;
            break;
        }

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
sshGetNextInstance(void)
{
    sbyte4      index;
    sbyte4      instance = ++m_instance;

    if (0 > instance)
    {
        /* this would take many, many decades to wrap */
        instance = ((instance + 0x1000) & 0x7fffffff);

        if (0x1000 > instance)
            instance = 0x1000;

        index = 0;

        while (index < g_sshMaxConnections)
        {
            if (instance == g_connectTable[index].instance)
            {
                /* we found our instance in the table, so we need to start over again */
                index = 0;
                instance++;
                continue;
            }

            index++;
        }
    }

    return instance;
}


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_acceptConnection(TCP_SOCKET tempSocket)
{
    /* a mutex is not necessary, this function should be called after accept */
    /* within the ssh connection daemon */
    sbyte4      index, count, temp;
    TCP_SOCKET  socket   = tempSocket;
    sbyte4      instance = sshGetNextInstance();
    MSTATUS     status   = ERR_SSH_TOO_MANY_CONNECTIONS;

    for (count = index = 0; index < g_sshMaxConnections; index++)
        if (CONNECT_CLOSED < g_connectTable[index].connectionState)
            count++;

    temp = NUM_SSH_CONNECTIONS;

    if (temp <= count)
        goto exit;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (CONNECT_CLOSED == g_connectTable[index].connectionState)
        {
            if (NULL == (g_connectTable[index].pReadBuffer = MALLOC(SSH_SYNC_BUFFER_SIZE)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            if (OK > (status = SSH_CONTEXT_allocStructures(&(g_connectTable[index].pContextSSH))))
            {
                FREE(g_connectTable[index].pReadBuffer);
                g_connectTable[index].pReadBuffer = NULL;
                goto exit;
            }

            SOCKET(g_connectTable[index].pContextSSH)              = socket;
            CONNECTION_INSTANCE(g_connectTable[index].pContextSSH) = instance;

            g_connectTable[index].socket              = socket;
            g_connectTable[index].connectionState     = CONNECT_NEGOTIATE;
            g_connectTable[index].instance            = instance;
            g_connectTable[index].isSocketClosed      = FALSE;
            status                                    = (MSTATUS)instance;
            break;
        }

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
static MSTATUS
doProtocol(sshContext *pContextSSH, sbyte4 index, intBoolean useTimeout, ubyte4 timeout)
{
    ubyte4  numBytesPending;
    ubyte4  adjustedTimeout;
    MSTATUS status;
    ubyte4 isReKeyStarted = FALSE;
    ubyte4 isReKeyDone = FALSE;

    if (TRUE == pContextSSH->isReKeyOccuring)
    {
        isReKeyStarted = TRUE;
    }

    if (TRUE == useTimeout)
    {
        RTOS_deltaMS(NULL, &SSH_TIMER_START_TIME(pContextSSH));
        SSH_TIMER_MS_EXPIRE(pContextSSH)  = timeout;
    }

    do
    {
        /* handle across events time outs */
        timeout   = SSH_TIMER_MS_EXPIRE(pContextSSH);

#ifdef __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__
        if (0 < pContextSSH->maxSessionTimeLimit)
        {
            useTimeout = TRUE;

            /* did we expire? */
            if (RTOS_deltaMS(&SSH_TIMER_START_TIME(pContextSSH), NULL) >= pContextSSH->maxSessionTimeLimit)
            {
                status = ERR_SSH_MAX_SESSION_TIME_LIMIT_EXCEEDED;
                goto exit;
            }

            if (0 == timeout)
            {
                /* if no timeout, use the max session time limit as a timeout */
                timeout = pContextSSH->maxSessionTimeLimit - RTOS_deltaMS(&pContextSSH->sessionStartTime, NULL);
            }
            else
            {
                /* handles if timeout is greater than max session time limit remaining...*/
                if (timeout > pContextSSH->maxSessionTimeLimit - RTOS_deltaMS(&pContextSSH->sessionStartTime, NULL))
                    timeout = pContextSSH->maxSessionTimeLimit - RTOS_deltaMS(&pContextSSH->sessionStartTime, NULL);
            }
        }
#endif /* __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__ */

        if (TCP_NO_TIMEOUT != timeout)
        {
            adjustedTimeout = RTOS_deltaMS(&SSH_TIMER_START_TIME(pContextSSH), NULL);

            if (adjustedTimeout >= timeout)
            {
                status = ERR_TCP_READ_TIMEOUT;
                goto exit;
            }

            adjustedTimeout = timeout - adjustedTimeout;
        }
        else
        {
            adjustedTimeout = TCP_NO_TIMEOUT;  /* timeout */
        }

        if (0 != g_connectTable[index].numBytesRead)
        {
            status = SSH_IN_MESG_processMessage(pContextSSH,
                                                &g_connectTable[index].pReadBufferPosition,
                                                &g_connectTable[index].numBytesRead);
        }
        else if (OK <= (status = TCP_READ_AVL(SOCKET(pContextSSH), (sbyte *)g_connectTable[index].pReadBuffer,
                                              SSH_SYNC_BUFFER_SIZE, &g_connectTable[index].numBytesRead, adjustedTimeout)))
        {
            g_connectTable[index].pReadBufferPosition = g_connectTable[index].pReadBuffer;

            if (0 != g_connectTable[index].numBytesRead)
            {
                status = SSH_IN_MESG_processMessage(pContextSSH,
                                                    &g_connectTable[index].pReadBufferPosition,
                                                    &g_connectTable[index].numBytesRead);
            }
        }
        if ((TRUE == isReKeyStarted) && (FALSE == pContextSSH->isReKeyOccuring))
        {
            isReKeyDone = TRUE;
        }
    }
    while ((FALSE == isReKeyDone) && (OK == status) && ((OK == (status = CIRC_BUF_bytesAvail(g_connectTable[index].pCircBufDescr, &numBytesPending))) && (0 == numBytesPending)) );

exit:
#ifdef __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__
    if ((ERR_TCP_READ_TIMEOUT == status) && (0 < pContextSSH->maxSessionTimeLimit))
    {
        /* did we reach time limit? */
        if (RTOS_deltaMS(&pContextSSH->sessionStartTime, NULL) > pContextSSH->maxSessionTimeLimit)
            status = ERR_SSH_MAX_SESSION_TIME_LIMIT_EXCEEDED;   /* change error code */
    }
#endif /* __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__ */

#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
    {
#ifdef __DISABLE_MOCANA_SSHS_TIMEOUT_WARNING__
        if (status != ERR_TCP_READ_TIMEOUT)
#endif
        {
            DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH:doProtocol(), returning status = ", status);
        }
    }
#endif

    return status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_negotiateConnection(sbyte4 connectionInstance)
{
    /* for multiple concurrent sessions, a thread should be spawned for this call */
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  == g_connectTable[index].connectionState))
        {
            if (OK > (status = CIRC_BUF_create(&g_connectTable[index].pCircBufDescr, 2 * MAX_SESSION_WINDOW_SIZE)))
                goto exit;

            if (OK > (status = SSH_TRANS_versionExchange(g_connectTable[index].pContextSSH)))
                goto exit;

            if (OK > (status = SSH_TRANS_setMessageTimer(g_connectTable[index].pContextSSH, m_sshSettings.sshTimeOutKeyExchange)))
                goto exit;

            SSH_UPPER_STATE(g_connectTable[index].pContextSSH) = kTransAlgorithmExchange;

            g_connectTable[index].numBytesRead = 0;

#ifdef __ENABLE_MOCANA_SSH_STREAM_API__
            g_connectTable[index].lenStream = 0;
#endif

            status = doProtocol(g_connectTable[index].pContextSSH, index, FALSE, 0);

            if (OK <= status)
                g_connectTable[index].connectionState = CONNECT_OPEN;

            break;
        }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_negotiateConnection() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if ((NULL == pBuffer) || (NULL == pBytesSent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
#ifdef __ENABLE_MOCANA_SSH_SENDER_RECV__
            if (((MAX_SESSION_WINDOW_SIZE / 8) >= g_connectTable[index].pContextSSH->sessionState.windowSize) ||
                (bufferSize >= g_connectTable[index].pContextSSH->sessionState.windowSize))
            {
                /* read data to prevent blocking on SSH transport window changes */
                if (OK > (status = doProtocol(g_connectTable[index].pContextSSH, index, TRUE, 100)))
                {
                    if (ERR_TCP_READ_TIMEOUT != status)
                        goto exit;
                }
            }
#endif

            status = SSH_SESSION_sendMessage(g_connectTable[index].pContextSSH,
                                             (ubyte *)pBuffer,
                                             (ubyte4)bufferSize,
                                             (ubyte4 *)pBytesSent);
            break;
        }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_sendMessage() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __ENABLE_MOCANA_SSH_PING__
extern sbyte4
SSH_sendPing(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
#ifdef __ENABLE_MOCANA_SSH_SENDER_RECV__
            if ((MAX_SESSION_WINDOW_SIZE / 8) >= g_connectTable[index].pContextSSH->sessionState.windowSize) {
                /* read data to prevent blocking on SSH transport window changes */
                if (OK > (status = doProtocol(g_connectTable[index].pContextSSH, index, TRUE, 100)))
                {
                    if (ERR_TCP_READ_TIMEOUT != status)
                        goto exit;
                }
            }
#endif

            if (TRUE == g_connectTable[index].pContextSSH->isReKeyOccuring)
            {
                /* session is open, but we're in a re-key exchange state */
                status = ERR_SSH_KEYEX_IN_PROGRESS;
                goto exit;
            }

            status = SSH_SESSION_sendPingMessage(g_connectTable[index].pContextSSH);
            break;
        }
    }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_sendPing() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_sendErrMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if ((NULL == pBuffer) || (NULL == pBytesSent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
#ifdef __ENABLE_MOCANA_SSH_SENDER_RECV__
            if (0 == g_connectTable[index].pContextSSH->sessionState.windowSize)
            {
                /* read data to prevent blocking on SSH transport window changes */
                if (OK > (status = doProtocol(g_connectTable[index].pContextSSH, index, TRUE, 5)))
                {
                    if (ERR_TCP_READ_TIMEOUT != status)
                        goto exit;
                }
            }
#endif

            if (TRUE == g_connectTable[index].pContextSSH->isReKeyOccuring)
            {
                /* session is open, but we're in a re-key exchange state */
                *pBytesSent = 0;
                status = OK;
                goto exit;
            }

            status = SSH_SESSION_sendStdErrMessage(g_connectTable[index].pContextSSH,
                                                   (ubyte *)pBuffer,
                                                   (ubyte4)bufferSize,
                                                   (ubyte4 *)pBytesSent);

            break;
        }
    }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_sendErrMessage() returns status = ", status);
#endif

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
extern sbyte4
SSH_sendPortForwardMessage(sbyte4 connectionInstance, sbyte4 channel, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;
    sshPfSession*  pPfSession = NULL;

    if ((NULL == pBuffer) || (NULL == pBytesSent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
#ifdef __ENABLE_MOCANA_SSH_SENDER_RECV__
            if (0 == g_connectTable[index].pContextSSH->sessionState.windowSize)
            {
                /* read data to prevent blocking on SSH transport window changes */
                if (OK > (status = doProtocol(g_connectTable[index].pContextSSH, index, TRUE, 5)))
                {
                    if (ERR_TCP_READ_TIMEOUT != status)
                        goto exit;
                }
            }
#endif
            /* Get the Port Forward Session Data through the client side channel number */
            if ( OK > ( status = getPfSessionFromChannel( g_connectTable[index].pContextSSH,
                                                          channel,
                                                          &pPfSession ) ) )
                break;

            if (TRUE == g_connectTable[index].pContextSSH->isReKeyOccuring)
            {
                /* session is open, but we're in a re-key exchange state */
                *pBytesSent = 0;
                status = OK;
                goto exit;
            }

            status = SSH_SESSION_forwardMessage(g_connectTable[index].pContextSSH,
                                             (ubyte *)pBuffer,
                                             (ubyte4)bufferSize,
                                             (ubyte4 *)pBytesSent,
                                             pPfSession);
            break;
        }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_sendPortForwardMessage() returns status = ", status);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4 SSH_sendPortForwardClose(sbyte4 connectionInstance, sbyte4 channel)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;
    sshPfSession*  pPfSession = NULL;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
            /* Get the Port Forward Session Data through the client side channel number */
            if ( OK > ( status = getPfSessionFromChannel( g_connectTable[index].pContextSSH,
                                                          channel,
                                                          &pPfSession ) ) )
                break;

            if (TRUE == g_connectTable[index].pContextSSH->isReKeyOccuring)
            {
                /* session is open, but we're in a re-key exchange state */
                status = ERR_SSH_KEYEX_IN_PROGRESS;
                goto exit;
            }

            status = SSH_SESSION_lpfSendClose(g_connectTable[index].pContextSSH,
                                              pPfSession);
            break;
        }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_sendPortForwardClose() returns status = ", status);
exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/**
@coming_soon
@ingroup    func_ssh_server_ungrouped
*/
extern sbyte4 SSH_sendPortFwdOpen(sbyte4 connectionInstance, ubyte* pConnectHost,ubyte4 connectPort,ubyte* pSrc, ubyte4 srcPort,ubyte4 *myChannel)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if(NULL == pConnectHost || NULL == pSrc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
            status = SSH_SESSION_sendPortFwdOpen(g_connectTable[index].pContextSSH, pConnectHost, connectPort, pSrc, srcPort, myChannel);
        }

exit:
    return status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
static MSTATUS
SSH_sendAck(sshContext *pContextSSH, ubyte4 index, enum sshSessionTypes sessionEvent)
{
    sshSession* pSshSession = &(pContextSSH->sessionState);
    ubyte4      ackRecvdData = pSshSession->ackRecvdData;
    ubyte4      numBytesPending;
    intBoolean  boolSendAck = FALSE;
    MSTATUS     status = OK;

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    if (SSH_PF_DATA == sessionEvent)
        pSshSession = &(pContextSSH->portForwardingSessionState);
#endif

    if (TRUE == pContextSSH->isReKeyOccuring)
    {
        /* session is open, but we're in a re-key exchange state */
        if (SSH_SESSION_DATA == sessionEvent)
            pContextSSH->prevMesgType = sessionEvent;
        goto exit;
    }

    /* nothing to do */
    if (0 == ackRecvdData)
        goto exit;

    if (OK > (status = CIRC_BUF_bytesAvail(g_connectTable[index].pCircBufDescr, &numBytesPending)))
        goto exit;

    if ((0 == numBytesPending) || (500 < ackRecvdData))
    {
        boolSendAck = TRUE;
    }
    else
    {
        if (RTOS_deltaMS(&pSshSession->timeOfLastAck, NULL) > 4000)
        {
            boolSendAck = TRUE;
        }
    }

    if (TRUE == boolSendAck)
    {
        if (OK > (status = SSH_SESSION_sendWindowAdjust(pContextSSH, sessionEvent, ackRecvdData)))
            goto exit;

        pSshSession->ackRecvdData   -= ackRecvdData;
        pSshSession->unAckRecvdData -= ackRecvdData;
        RTOS_deltaMS(NULL, &pSshSession->timeOfLastAck);
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
static MSTATUS
SSH_ackData(sshContext *pContextSSH, ubyte4 index, enum sshSessionTypes sessionEvent, ubyte4 numBytesToAck)
{
    sshSession* pSshSession = &(pContextSSH->sessionState);
    MSTATUS     status;

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    if (SSH_PF_DATA == sessionEvent)
        pSshSession = &(pContextSSH->portForwardingSessionState);
#endif

    if (0 != numBytesToAck)
    {
        if (numBytesToAck > (pSshSession->unAckRecvdData - pSshSession->ackRecvdData))
        {
            /* this should never happen */
            numBytesToAck = (pSshSession->unAckRecvdData - pSshSession->ackRecvdData);
        }

        pSshSession->ackRecvdData += numBytesToAck;
    }

    status = SSH_sendAck(pContextSSH, index, sessionEvent);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && (!defined(__ENABLE_MOCANA_SSH_STREAM_API__)))
extern sbyte4
SSH_recvMessage(sbyte4 connectionInstance, sbyte4 *pMessageType,
                sbyte *pRetMessage, sbyte4 *pNumBytesReceived, ubyte4 timeout)
{
    ubyte4  numBytesToRead;
    ubyte4  numBytesRead;
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;
    ubyte   tmpBuf[4];
    intBoolean isReKeyStarted = FALSE;

    *pMessageType = SSH_SESSION_NOTHING;
    *pNumBytesReceived = 0;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
            /* attempt to read data from circular buffer */
            if (OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, tmpBuf, 1, &numBytesRead)))
                goto exit;

            if (TRUE == g_connectTable[index].pContextSSH->isReKeyOccuring)
            {
                isReKeyStarted = TRUE;
            }

            if (0 == numBytesRead)
            {
                /* read any data available on the socket */
                if (OK > (status = doProtocol(g_connectTable[index].pContextSSH, index, TRUE, timeout)))
                {
                    if (ERR_TCP_READ_TIMEOUT != status)
                        goto exit;
                }

                /* attempt to read data from circular buffer */
                if ((OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, tmpBuf, 1, &numBytesRead))) || (0 == numBytesRead))
                {
                    if ((OK == status) && (TRUE == isReKeyStarted) && (FALSE == g_connectTable[index].pContextSSH->isReKeyOccuring) && (0 == numBytesRead))
                    {
                        /* we completed re-key exchange, send acknowledgement of previous message */
                        if (SSH_SESSION_DATA == g_connectTable[index].pContextSSH->prevMesgType)
                        {
                            status = SSH_sendAck(g_connectTable[index].pContextSSH, index, g_connectTable[index].pContextSSH->prevMesgType);
                            g_connectTable[index].pContextSSH->prevMesgType = SSH_SESSION_NOTHING;
                        }
                    }
                    goto exit;
                }
            }

            *pMessageType = tmpBuf[0] & 0x3f;

            if (0xc0 == (0xc0 & tmpBuf[0]))
                numBytesToRead = 2;
            else if (0x80 == (0xc0 & tmpBuf[0]))
                numBytesToRead = 1;
            else
                numBytesToRead = 0;

            if (numBytesToRead)
            {
                if (OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, tmpBuf, numBytesToRead, &numBytesRead)))
                    goto exit;

                if (numBytesRead != numBytesToRead)
                {
                    status = ERR_SSH_CIRCULAR_BUFFER_UNDERFLOW;
                    goto exit;
                }
            }

            if (2 == numBytesToRead)
                *pNumBytesReceived = (((ubyte4)tmpBuf[0]) << 8) + ((ubyte4)tmpBuf[1]);
            else if (1 == numBytesToRead)
                *pNumBytesReceived = tmpBuf[0];
            else if ((SSH_SESSION_DATA == *pMessageType) || (SSH_SESSION_STDERR == *pMessageType) ||
                     (SSH_PF_DATA == *pMessageType)      || (SSH_SESSION_OPEN_EXEC == *pMessageType))
            {
                *pNumBytesReceived = 1;
            }

            if (0 != *pNumBytesReceived)
            {
                if (OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, (ubyte *)pRetMessage, *pNumBytesReceived, &numBytesRead)))
                    goto exit;

                if ((sbyte4)numBytesRead != *pNumBytesReceived)
                {
                    status = ERR_SSH_CIRCULAR_BUFFER_UNDERFLOW;
                    goto exit;
                }
            }

            /* ack the received data */
            status = SSH_ackData(g_connectTable[index].pContextSSH, index, (enum sshSessionTypes)*pMessageType, *pNumBytesReceived);

            break;
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_recvMessage() returns status = ", status);

    return (sbyte4)status;
}
#endif /* ((!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && (!defined(__ENABLE_MOCANA_SSH_STREAM_API__))) */


/*------------------------------------------------------------------*/

#if ((!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && defined(__ENABLE_MOCANA_SSH_STREAM_API__))
extern sbyte4
SSH_recv(sbyte4 connectionInstance, sbyte4 *pMessageType,
         ubyte *pRetBuffer, ubyte4 bufferSize,
         sbyte4 *pNumBytesReceived, ubyte4 timeout)
{
    ubyte4  numBytesRead;
    ubyte4  numBytesToRead;
    ubyte4  toCopy;
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;
    ubyte   tmpBuf[4];
    intBoolean isReKeyStarted = FALSE;

    if ((NULL == pRetBuffer) || (NULL == pMessageType) || (NULL == pNumBytesReceived))
        return ERR_NULL_POINTER;

    *pMessageType = SSH_SESSION_NOTHING;
    *pNumBytesReceived = 0;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
            /* check if we have processed the current stream of data */
            if (0 == g_connectTable[index].lenStream)
            {
                /* attempt to read mesgType from circular buffer */
                if (OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, tmpBuf, 1, &numBytesRead)))
                    goto exit;

                if (TRUE == g_connectTable[index].pContextSSH->isReKeyOccuring)
                {
                    isReKeyStarted = TRUE;
                }

                if (0 == numBytesRead)
                {
                    /* read any data available on the socket */
                    if (OK > (status = doProtocol(g_connectTable[index].pContextSSH, index, TRUE, timeout)))
                    {
                        if (ERR_TCP_READ_TIMEOUT != status)
                            goto exit;
                    }

                    /* attempt to read data from circular buffer */
                    if ((OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, tmpBuf, 1, &numBytesRead))) || (0 == numBytesRead))
                    {
                        if ((OK == status) && (TRUE == isReKeyStarted) && (FALSE == g_connectTable[index].pContextSSH->isReKeyOccuring) && (0 == numBytesRead))
                        {
                            /* we completed re-key exchange, send acknowledgement of previous message */
                            if (SSH_SESSION_DATA == g_connectTable[index].pContextSSH->prevMesgType)
                            {
                                status = SSH_sendAck(g_connectTable[index].pContextSSH, index, g_connectTable[index].pContextSSH->prevMesgType);
                                g_connectTable[index].pContextSSH->prevMesgType = SSH_SESSION_NOTHING;
                            }
                        }
                        goto exit;
                    }
                }

                g_connectTable[index].mesgType = tmpBuf[0] & 0x3f;

                if (0xc0 == (0xc0 & tmpBuf[0]))
                    numBytesToRead = 2;
                else if (0x80 == (0xc0 & tmpBuf[0]))
                    numBytesToRead = 1;
                else
                    numBytesToRead = 0;

                /* fetch optional length bytes */
                if (numBytesToRead)
                {
                    if (OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, tmpBuf, numBytesToRead, &numBytesRead)))
                        goto exit;

                    if (numBytesRead != numBytesToRead)
                    {
                        status = ERR_SSH_CIRCULAR_BUFFER_UNDERFLOW;
                        goto exit;
                    }
                }

                /* process length bytes */
                if (2 == numBytesToRead)
                    g_connectTable[index].lenStream = (((ubyte4)tmpBuf[0]) << 8) + ((ubyte4)tmpBuf[1]);
                else if (1 == numBytesToRead)
                    g_connectTable[index].lenStream = tmpBuf[0];
                else if ((SSH_SESSION_DATA == g_connectTable[index].mesgType) || (SSH_SESSION_STDERR == g_connectTable[index].mesgType) ||
                        (SSH_PF_DATA == g_connectTable[index].mesgType)      || (SSH_SESSION_OPEN_EXEC == g_connectTable[index].mesgType))
                {
                    g_connectTable[index].lenStream = 1;
                }
            }

            /* set up for return */
            *pMessageType = g_connectTable[index].mesgType;
            toCopy = (bufferSize > (g_connectTable[index].lenStream)) ? (g_connectTable[index].lenStream) : bufferSize;

            if (0 != toCopy)
            {
                /* copy out a message from the circular buffer */
                if (OK > (status = CIRC_BUF_read(g_connectTable[index].pCircBufDescr, (ubyte *)pRetBuffer, toCopy, &numBytesRead)))
                    goto exit;

                if (numBytesRead != toCopy)
                {
                    status = ERR_SSH_CIRCULAR_BUFFER_UNDERFLOW;
                    goto exit;
                }
            }

            *pNumBytesReceived = (sbyte4)toCopy;
            g_connectTable[index].lenStream -= toCopy;

            /* ack the received data */
            status = SSH_ackData(g_connectTable[index].pContextSSH, index, (ubyte)*pMessageType, *pNumBytesReceived);

            break;
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_recv() returns status = ", status);

    return (sbyte4)status;
}
#endif /* ((!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && defined(__ENABLE_MOCANA_SSH_STREAM_API__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && defined(__ENABLE_MOCANA_SSH_STREAM_API__))
extern sbyte4
SSH_recvPending(sbyte4 connectionInstance, sbyte4 *pRetBooleanIsPending)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if (NULL == pRetBooleanIsPending)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetBooleanIsPending = FALSE;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
            if (0 < g_connectTable[index].lenStream)
                *pRetBooleanIsPending = TRUE;

            status = OK;
            break;
        }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_recvPending() returns status = ", (sbyte4)status);

    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_closeConnection(sbyte4 connectionInstance)
{
    /* for multi-concurrent sessions, a thread should be spawned for this call */
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            MOCANA_log((sbyte4)MOCANA_SSH, (sbyte4)LS_INFO, (sbyte *)"SSH close connection.");

            if (NULL != g_connectTable[index].pContextSSH)
            {
                SSH_SESSION_sendClose(g_connectTable[index].pContextSSH);
                SSH_CONTEXT_deallocStructures(&(g_connectTable[index].pContextSSH));
            }

            if (NULL != g_connectTable[index].pReadBuffer)
            {
                FREE(g_connectTable[index].pReadBuffer);
                g_connectTable[index].pReadBuffer = NULL;
            }

            CIRC_BUF_release(&g_connectTable[index].pCircBufDescr);

            g_connectTable[index].instance = -1;
            g_connectTable[index].connectionState = CONNECT_CLOSED;
            status = OK;

            break;
        }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_closeConnection() returns status = ", status);

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSH_INTERNAL_API_setOpenState(sbyte4 connectionInstance)
{
    /* for multi-concurrent sessions, a thread should be spawned for this call */
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            g_connectTable[index].connectionState = CONNECT_OPEN;
            status = OK;
            break;
        }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_getCookie(sbyte4 connectionInstance, sbyte4 *pCookie)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            *pCookie = g_connectTable[index].pContextSSH->cookie;
            status = OK;
            break;
        }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_setCookie(sbyte4 connectionInstance, sbyte4 cookie)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            g_connectTable[index].pContextSSH->cookie = cookie;
            status = OK;
            break;
        }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_getTerminalSettingDescr(sbyte4 connectionInstance, terminalState **ppTerminalSettings)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            *ppTerminalSettings = g_connectTable[index].pContextSSH->pTerminal;
            status = OK;
            break;
        }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __USE_MOCANA_SSH_SERVER__
extern sbyte4
SSH_startServer(void)
{
    return (sbyte4)SSH_SERVER_start();
}
#endif /* __USE_MOCANA_SSH_SERVER__ */
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __USE_MOCANA_SSH_SERVER__
extern void
SSH_stopServer(void)
{
    SSH_SERVER_stop();
}
#endif /* __USE_MOCANA_SSH_SERVER__ */
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __USE_MOCANA_SSH_SERVER__
extern void
SSH_disconnectAllClients(void)
{
    SSH_SERVER_disconnectClients();
}
#endif /* __USE_MOCANA_SSH_SERVER__ */
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

/* stops the server, disconnects all clients and cleans up SSH server */
extern sbyte4
SSH_shutdown(void)
{
    MOCANA_log((sbyte4)MOCANA_SSH, (sbyte4)LS_INFO, (sbyte *)"SSH server shutting down.");

#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__) || defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_deleteAllCombsAndMutexes();
#else
    EC_deleteAllCombsAndMutexes();
#endif
#endif

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __USE_MOCANA_SSH_SERVER__
    SSH_SERVER_stop();
    SSH_SERVER_disconnectClients();
#endif /* __USE_MOCANA_SSH_SERVER__ */
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */

    SSH_STR_HOUSE_freeStringBuffers();

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    SSH_FTP_freeStringBuffers();
#endif /* __ENABLE_MOCANA_SSH_FTP_SERVER__ */

#ifndef __DISABLE_MOCANA_INIT__
    gMocanaAppsRunning--;
#endif

    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

/* call after all upper layer threads are stopped and SSH_shutdown() */
extern sbyte4
SSH_releaseTables(void)
{
    if (NULL != g_connectTable)
    {
        FREE(g_connectTable);
        g_connectTable = NULL;
    }

    SSH_TRANS_releaseStaticKeys();

#ifdef __USE_MOCANA_SSH_SERVER__
    SSH_SERVER_releaseMutex();
#endif

    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_compareAuthKeys(const ubyte *pPubKey,  ubyte4 pubKeyLength,
                    const ubyte *pFileKey, ubyte4 fileKeyLength,
                    sbyte4 *pRetIsMatch)
{
    AsymmetricKey p_keyDescr = {0};
    AsymmetricKey p_keyFileContext = {0};
    MSTATUS       status;
    hwAccelDescr  hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    if ((NULL == pPubKey) || (NULL == pFileKey) || (NULL == pRetIsMatch))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    status = CRYPTO_initAsymmetricKey(&p_keyDescr);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&p_keyFileContext);
    if (OK != status)
        goto exit;

    if (OK > (status = CA_MGMT_extractKeyBlobEx((ubyte *)pPubKey, pubKeyLength, &p_keyDescr)))
        goto exit;

    if (OK > (status = SSH_UTILS_sshParseAuthPublicKeyFile((sbyte *)pFileKey, fileKeyLength, &p_keyFileContext)))
        goto exit;

    if (p_keyDescr.type != p_keyFileContext.type)
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (akt_dsa == p_keyDescr.type)
    {
#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DSA_equalKey(MOC_DSA(hwAccelCtx) p_keyDescr.key.pDSA, p_keyFileContext.key.pDSA, (byteBoolean*)pRetIsMatch);
#else
        status = DSA_equalKey(MOC_DSA(hwAccelCtx) p_keyDescr.key.pDSA, p_keyFileContext.key.pDSA, (byteBoolean*)pRetIsMatch);
#endif
        if (OK != status)
            goto exit;
#endif
    }
    else if (akt_rsa == p_keyDescr.type)
    {
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_equalKey(MOC_RSA(hwAccelCtx) p_keyDescr.key.pRSA, p_keyFileContext.key.pRSA, (byteBoolean*)pRetIsMatch);
    if (OK != status)
        goto exit;
#else
    status = RSA_equalKey(MOC_RSA(hwAccelCtx) p_keyDescr.key.pRSA, p_keyFileContext.key.pRSA, (byteBoolean*)pRetIsMatch);
    if (OK != status)
        goto exit;
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_SSH_RSA_SUPPORT__ */
    }
    else if ((akt_ecc == p_keyDescr.type) || (akt_ecc_ed == p_keyDescr.type))
    {
#ifdef __ENABLE_MOCANA_ECC__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
       status = CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) p_keyDescr.key.pECC, p_keyFileContext.key.pECC, (byteBoolean*)pRetIsMatch);
       if (OK != status)
            goto exit;
#else
       status = EC_equalKeyEx(MOC_ECC(hwAccelCtx) p_keyDescr.key.pECC, p_keyFileContext.key.pECC, (byteBoolean*)pRetIsMatch);
       if (OK != status)
            goto exit;
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_ECC__ */
    }
#ifdef __ENABLE_MOCANA_PQC__
    else if (akt_qs == p_keyDescr.type)
    {
        status = CRYPTO_INTERFACE_QS_equalKey(p_keyDescr.pQsCtx, p_keyFileContext.pQsCtx, MOC_ASYM_KEY_TYPE_PUBLIC, (byteBoolean*)pRetIsMatch);
        if (OK != status)
            goto exit;
    }
    else if (akt_hybrid == p_keyDescr.type)
    {
        /* NOTE: if hybrid with RSA is ever allowed this will need an RSA branch */
        status = CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) p_keyDescr.key.pECC, p_keyFileContext.key.pECC, (byteBoolean*)pRetIsMatch);
        if (OK != status)
            goto exit;
        
        if (FALSE == *pRetIsMatch)
        {
            goto exit;
        }

        status = CRYPTO_INTERFACE_QS_equalKey(p_keyDescr.pQsCtx, p_keyFileContext.pQsCtx, MOC_ASYM_KEY_TYPE_PUBLIC, (byteBoolean*)pRetIsMatch);
    }
#endif
    else
    {
        status = ERR_BAD_KEY_TYPE;
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    CRYPTO_uninitAsymmetricKey(&p_keyDescr, NULL);
    CRYPTO_uninitAsymmetricKey(&p_keyFileContext, NULL);

nocleanup:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_verifyPublicKeyFile(sbyte *pKeyFileData, ubyte4 fileSize)
{
    AsymmetricKey   p_keyFileContext;
    MSTATUS         status;

    if (NULL == pKeyFileData)
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    if (OK > (status = CRYPTO_initAsymmetricKey(&p_keyFileContext)))
        goto nocleanup;

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFileData, fileSize, &p_keyFileContext);

    CRYPTO_uninitAsymmetricKey(&p_keyFileContext, NULL);

nocleanup:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_init(sbyte4 sshMaxConnections)
{
    sbyte4      index;
    hwAccelDescr    hwAccelCookie;
    intBoolean      isHwAccelInit = FALSE;
    MSTATUS     status = OK;

#ifndef __DISABLE_MOCANA_INIT__
    gMocanaAppsRunning++;
#endif

#if ((defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__)) || \
     (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) )
    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCookie)))
        goto exit;

    isHwAccelInit = TRUE;
#endif

    MOC_MEMSET((ubyte *)&m_sshSettings, 0x00, sizeof(sshSettings));

    if (NULL == g_connectTable)
    {
        /* num indices in array */
        g_sshMaxConnections = sshMaxConnections;

        if (NULL == (g_connectTable = MALLOC(sizeof(sshConnectDescr) * sshMaxConnections)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        MOC_MEMSET((ubyte *)g_connectTable, 0x00, sizeof(sizeof(sshConnectDescr) * sshMaxConnections));
    }
    else
    {
        if (g_sshMaxConnections < sshMaxConnections)
        {
            status = ERR_SSH_CONFIG;
            goto exit;
        }
    }

    m_sshSettings.sshListenPort                 = SSH_DEFAULT_TCPIP_PORT;
    m_sshSettings.sshMaxAuthAttempts            = MAX_SSH_AUTH_ATTEMPTS;
    m_sshSettings.sshTimeOutOpen                = TIMEOUT_SSH_OPEN;
    m_sshSettings.sshTimeOutKeyExchange         = TIMEOUT_SSH_KEX;
    m_sshSettings.sshTimeOutNewKeys             = TIMEOUT_SSH_NEWKEYS;
    m_sshSettings.sshTimeOutServiceRequest      = TIMEOUT_SSH_SERVICE_REQUEST;
    m_sshSettings.sshTimeOutAuthentication      = TIMEOUT_SSH_AUTH_LOGON;
    m_sshSettings.sshTimeOutDefaultOpenState    = TIMEOUT_SSH_OPEN_STATE;
    m_sshSettings.sshMaxConnections             = sshMaxConnections;

    for (index = 0; index < g_sshMaxConnections; index++)
        g_connectTable[index].connectionState = CONNECT_DISABLED;

    if (OK > (status = SSH_STR_HOUSE_initStringBuffers()))
        goto exit;

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    if (OK > (status = SSH_FTP_initStringBuffers()))
        goto exit;
#endif

#if (!defined(__DISABLE_MOCANA_SSH_RSA_KEY_EXCHANGE__) && defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
    if (OK > (status = SSH_TRANS_initRsaKeyExchange(hwAccelCookie)))
        goto exit;
#endif

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = SSH_TRANS_initSafePrimesDHG(hwAccelCookie)))
        goto exit;
#endif
#endif

    m_instance = 0x1000;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        g_connectTable[index].connectionState = CONNECT_CLOSED;
        g_connectTable[index].pContextSSH     = NULL;
        g_connectTable[index].isSocketClosed  = TRUE;
    }

exit:
    if (TRUE == isHwAccelInit)
    {
        HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCookie);
    }

    DEBUG_PRINT(DEBUG_SSH_MESSAGES, "SSH_ASYNC_init: completed after = (");
    DEBUG_UPTIME(DEBUG_SSH_MESSAGES);
    DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, ") milliseconds.");

    return (sbyte4)status;

} /* SSH_ASYNC_init */

#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_setListeningPort(ubyte4 listeningPort)
{
    MSTATUS     status = OK;

    m_sshSettings.sshListenPort = listeningPort;

    return (sbyte4)status;

} /* SSH_ASYNC_setListeningPort */

#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */



/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_acceptConnection(TCP_SOCKET tempSocket,
                           ubyte *pClientHelloString,
                           ubyte4 clientHelloStringLength,
                           ubyte *pServerHelloString,
                           ubyte4 serverHelloStringLength)
{
    /* a mutex is not necessary, this function should be called after accept */
    /* within the ssh connection daemon */
    sbyte4      index, count, temp;
    TCP_SOCKET  socket                = tempSocket;
    sbyte4      instance              = sshGetNextInstance();
    ubyte*      pTempClientHelloClone = NULL;
    ubyte*      pTempServerHelloClone = NULL;
    sshContext* pContextSSH           = NULL;
    MSTATUS     status                = ERR_SSH_TOO_MANY_CONNECTIONS;

    for (count = index = 0; index < g_sshMaxConnections; index++)
        if (CONNECT_CLOSED < g_connectTable[index].connectionState)
            count++;

    temp = NUM_SSH_CONNECTIONS;

    if (temp <= count)
        goto exit;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (CONNECT_CLOSED == g_connectTable[index].connectionState)
        {

            if (OK > (status = SSH_CONTEXT_allocStructures(&pContextSSH)))
                goto exit;

            if (OK > (status = MOC_STREAM_open(&(pContextSSH->pSocketOutStreamDescr), socket, MOCANA_SSH_SOCKET_STREAM_SIZE, (funcStreamWriteData)TCP_WRITE)))
                goto exit;

            SOCKET(pContextSSH)                   = socket;
            CONNECTION_INSTANCE(pContextSSH)      = instance;

            g_connectTable[index].socket          = socket;
            g_connectTable[index].connectionState = CONNECT_NEGOTIATE;
            g_connectTable[index].instance        = instance;
            g_connectTable[index].isSocketClosed  = FALSE;

            if (NULL != pClientHelloString)
            {
                DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, "SSH_ASYNC_acceptConnection: using client string provided");

                /* guard client string length */
                if (MAX_CLIENT_VERSION_STRING < clientHelloStringLength)
                {
                    /* string longer than RFC maximum length */
                    status = ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
                    goto exit;
                }

                if (NULL == (pTempClientHelloClone = MALLOC(clientHelloStringLength)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                MOC_MEMCPY(pTempClientHelloClone, pClientHelloString, clientHelloStringLength);
            }
            else
            {
                DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_ASYNC_acceptConnection: receive client string; INBOUND_STATE = ", kReceiveInitClientHelloListen);

                /* set initial state to listen for client hello string */
                INBOUND_STATE(pContextSSH) = kReceiveInitClientHelloListen;
            }

            /* allocate for our default server hello string */
            if (NULL == pServerHelloString)
                serverHelloStringLength = sizeof(SERVER_HELLO_STRING) - 1;
            else
                serverHelloStringLength = serverHelloStringLength + (sizeof(SERVER_HELLO_VERSION_STRING) - 1);

            /* guard server string length */
            if (MAX_SERVER_VERSION_STRING < serverHelloStringLength)
            {
                /* string longer than RFC maximum length */
                status = ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
                goto exit;
            }

            if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, serverHelloStringLength, TRUE, &pTempServerHelloClone)))
                goto exit;

            if (NULL != pServerHelloString)
            {
                DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, "SSH_ASYNC_acceptConnection: use provided server hello string");

                MOC_MEMCPY(pTempServerHelloClone, SERVER_HELLO_VERSION_STRING, sizeof(SERVER_HELLO_VERSION_STRING) -1);
                MOC_MEMCPY((pTempServerHelloClone + sizeof(SERVER_HELLO_VERSION_STRING) -1), pServerHelloString, (serverHelloStringLength - sizeof(SERVER_HELLO_VERSION_STRING) + 1));

            }
            else
            {
                DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, "SSH_ASYNC_acceptConnection: send default server hello string");

                /* copy default server hello string */
                MOC_MEMCPY(pTempServerHelloClone, (ubyte *)SERVER_HELLO_STRING, serverHelloStringLength);

            }

            SERVER_HELLO_COMMENT_LEN(pContextSSH) = serverHelloStringLength;
            SERVER_HELLO_COMMENT(pContextSSH)     = pTempServerHelloClone;
            pTempServerHelloClone = NULL;
            /* send the server hello string */
            if (OK > (status = SSH_TRANS_sendServerHello(pContextSSH)))
                goto exit;

            if (NULL != pClientHelloString)
            {
                CLIENT_HELLO_COMMENT_LEN(pContextSSH) = clientHelloStringLength;
                CLIENT_HELLO_COMMENT(pContextSSH) = pTempClientHelloClone;
                pTempClientHelloClone = NULL;
            }

            g_connectTable[index].pContextSSH = pContextSSH; pContextSSH = NULL;
            status = (MSTATUS)instance;
            break;
        }

exit:
    if (NULL != pTempClientHelloClone)
        FREE(pTempClientHelloClone);

    if (NULL != pTempServerHelloClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pTempServerHelloClone);

    if (NULL != pContextSSH)
        SSH_CONTEXT_deallocStructures(&pContextSSH);

    if (OK > status)
    {
        if (ERR_SSH_TOO_MANY_CONNECTIONS != status)
        {
            g_connectTable[index].connectionState = CONNECT_CLOSED;
            g_connectTable[index].isSocketClosed  = TRUE;
        }
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_acceptConnection() returns status = ", status);
    }

    return (sbyte4)status;

} /* SSH_ASYNC_acceptConnection */

#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_startProtocolV2(sbyte4 connectionInstance)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            if (OK > (status = SSH_TRANS_sendServerAlgorithms(g_connectTable[index].pContextSSH)))
                goto exit;

            if (OK > (status = SSH_TRANS_setMessageTimer(g_connectTable[index].pContextSSH, m_sshSettings.sshTimeOutKeyExchange)))
                goto exit;

            SSH_UPPER_STATE(g_connectTable[index].pContextSSH) = kTransAlgorithmExchange;
            break;
        }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_startProtocolV2() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_recvMessage(sbyte4 connectionInstance,
                      ubyte *pBytesReceived, ubyte4 numBytesReceived)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if (NULL == pBytesReceived)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            sshContext *pContextSSH = g_connectTable[index].pContextSSH;


#ifdef __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__
            if (0 < pContextSSH->maxSessionTimeLimit)
            {
                /* did we reach time limit? */
                if (RTOS_deltaMS(&pContextSSH->sessionStartTime, NULL) > pContextSSH->maxSessionTimeLimit)
                {
                    status = ERR_SSH_MAX_SESSION_TIME_LIMIT_EXCEEDED;
                    goto exit;
                }
            }
#endif /* __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__ */

            /* check if we're waiting for any events */
            if (kNotWaiting != pContextSSH->waitEvent)
            {
                if (kWaitingForAuth == pContextSSH->waitEvent)
                {
                    status = ERR_SSH_ASYNC_WAITING_AUTH;
                    goto exit;
                }

                status = ERR_SSH_ASYNC_WAITING_HW_OFFLOAD;
                goto exit;
            }

            status = OK;

            while ((OK == status) && (0 < numBytesReceived))
            {
                /* process back-to-back messages */
                status = SSH_IN_MESG_processMessage(pContextSSH,
                                                    &pBytesReceived,
                                                    &numBytesReceived);

                /* check if we are waiting for crypto or remote authentication */
                if ((OK <= status) && (kNotWaiting != pContextSSH->waitEvent))
                {
                    status = pContextSSH->waitEvent;

                    /* nothing to do */
                    if (0 != numBytesReceived)
                    {
                        if (NULL == (pContextSSH->pAsyncCacheMessage = pContextSSH->pAsyncCacheTemp = MALLOC(numBytesReceived)))
                        {
                            status = ERR_MEM_ALLOC_FAIL;
                            goto exit;
                        }

                        MOC_MEMCPY(pContextSSH->pAsyncCacheMessage, pBytesReceived, numBytesReceived);
                        pContextSSH->asyncCacheMessageLength = numBytesReceived;

                        numBytesReceived = 0;
                    }
                }
            }

            break;
        }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_recvMessage() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_ackReceivedMessageBytes(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte4 numBytesAck)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            sshContext *pContextSSH = g_connectTable[index].pContextSSH;
            sshSession* pSshSession = &(pContextSSH->sessionState);
            ubyte4      unAckRecvdData = pSshSession->unAckRecvdData;

            if (0 == numBytesAck)
            {
                status = OK;
                break;
            }

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
            if (SSH_PF_DATA == sessionEvent)
                pSshSession = &(pContextSSH->portForwardingSessionState);
#endif

            /* make sure app is not acking more than received */
            if (numBytesAck > unAckRecvdData)
                numBytesAck = unAckRecvdData;

            /* ack the received data */
            status = SSH_SESSION_sendWindowAdjust(pContextSSH, sessionEvent, numBytesAck);

            pSshSession->unAckRecvdData -= numBytesAck;

            break;
        }

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
extern sbyte4
SSH_ackPortFwdReceivedMessageBytes(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte4 numBytesAck, ubyte4 channel)
{
    sbyte4       index;
    MSTATUS      status = ERR_SSH_BAD_ID;
    sshContext   *pContextSSH = NULL;
    sshPfSession *pSshSession = NULL;
    ubyte4       unAckRecvdData = 0;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if (connectionInstance == g_connectTable[index].instance)
        {
            pContextSSH = g_connectTable[index].pContextSSH;
            /* Get the Port Forward Session Data through the client side channel number */
            if ( OK > ( status = getPfSessionFromChannel( pContextSSH,channel,&pSshSession ) ) )
                break;

            if (TRUE == pContextSSH->isReKeyOccuring)
            {
                /* session is open, but we're in a re-key exchange state */
                status = OK;
                break;
            }

            unAckRecvdData = pSshSession->pfSessionData.unAckRecvdData;

            if (0 == numBytesAck)
            {
                status = OK;
                break;
            }

            /* make sure app is not acking more than received */
            if (numBytesAck > unAckRecvdData)
                numBytesAck = unAckRecvdData;

            /* ack the received data */
            status = SSH_SESSION_sendPortFwdWindowAdjust(pContextSSH, sessionEvent, numBytesAck, channel);

            pSshSession->pfSessionData.unAckRecvdData -= numBytesAck;

            break;
        }
    } /* End of for loop */

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__*/


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_recvContinueMessage(sbyte4 connectionInstance, sbyte4 result)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            sshContext *pContextSSH = g_connectTable[index].pContextSSH;

            if (kWaitingForAuth == pContextSSH->waitEvent)
            {
                /* handle authentication result */
                if (OK > (status = SSH_AUTH_continueAuthFromWait(pContextSSH, result)))
                    goto exit;
            }
            else
            {
                /*!!!! continue processing data */
            }

            /* set waitEvent state back to operational */
            pContextSSH->waitEvent = kNotWaiting;
            status = OK;

            /* is data waiting? */
            if (NULL == pContextSSH->pAsyncCacheMessage)
                goto exit;

            while ((OK == status) && (0 < pContextSSH->asyncCacheMessageLength))
            {
                /* process back-to-back messages */
                status = SSH_IN_MESG_processMessage(pContextSSH,
                                                    &pContextSSH->pAsyncCacheTemp,
                                                    &pContextSSH->asyncCacheMessageLength);

                /* check if all cached data has been processed */
                if (0 == pContextSSH->asyncCacheMessageLength)
                {
                    FREE(pContextSSH->pAsyncCacheMessage);
                    pContextSSH->pAsyncCacheMessage = pContextSSH->pAsyncCacheTemp = NULL;
                }

                /* check if we jumped back into a crypto or remote authentication wait state */
                if ((OK <= status) && (kNotWaiting != pContextSSH->waitEvent))
                    status = pContextSSH->waitEvent;
            }

            break;
        }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_recvContinueMessage() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if ((NULL == pBuffer) || (NULL == pBytesSent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_OPEN       == g_connectTable[index].connectionState))
        {
            status = SSH_SESSION_sendMessage(g_connectTable[index].pContextSSH,
                                             (ubyte *)pBuffer,
                                             (ubyte4)bufferSize,
                                             (ubyte4 *)pBytesSent);
            break;
        }

exit:
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_sendMessage() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_sendMessagePending(sbyte4 connectionInstance, ubyte4 *pRetNumBytesPending)
{
#if defined(__ENABLE_MOCANA_SSH_FTP_SERVER__)
    ubyte4  numSftpBytesPending = 0;
#endif
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            sshContext *pContextSSH = g_connectTable[index].pContextSSH;

            if (OK > (status = MOC_STREAM_flush(pContextSSH->pSocketOutStreamDescr, pRetNumBytesPending, NULL)))
                break;

#if defined(__ENABLE_MOCANA_SSH_FTP_SERVER__)
            if (NULL != pContextSSH->sessionState.pSftpOutStreamDescr)
                if (OK > (status = MOC_STREAM_flush(pContextSSH->sessionState.pSftpOutStreamDescr, &numSftpBytesPending, NULL)))
                    break;

            if (pRetNumBytesPending)
                *pRetNumBytesPending = *pRetNumBytesPending + numSftpBytesPending;
#endif

            break;
        }
    }

#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_sendMessagePending() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
extern sbyte4
SSH_ASYNC_closeConnection(sbyte4 connectionInstance)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            MOCANA_log((sbyte4)MOCANA_SSH, (sbyte4)LS_INFO, (sbyte *)"SSH close connection.");

            if (NULL != g_connectTable[index].pContextSSH)
            {
                SSH_SESSION_sendClose(g_connectTable[index].pContextSSH);
                SSH_CONTEXT_deallocStructures(&(g_connectTable[index].pContextSSH));
            }

            g_connectTable[index].instance = -1;
            g_connectTable[index].connectionState = CONNECT_CLOSED;
            status = OK;
            break;
        }

#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_ASYNC_closeConnection() returns status = ", status);
#endif

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_getSessionCryptoInfo(sbyte4 connectionInstance,
                         sbyte **ppInCipherName,  sbyte **ppInMacName,
                         sbyte **ppOutCipherName, sbyte **ppOutMacName)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            if (NULL != ppInCipherName)
                *ppInCipherName = INBOUND_CIPHER_SUITE_INFO(g_connectTable[index].pContextSSH)->pCipherName;

            if (NULL != ppInMacName)
                *ppInMacName = INBOUND_MAC_INFO(g_connectTable[index].pContextSSH)->pHmacName;

            if (NULL != ppOutCipherName)
                *ppOutCipherName = OUTBOUND_CIPHER_SUITE_INFO(g_connectTable[index].pContextSSH)->pCipherName;

            if (NULL != ppOutMacName)
                *ppOutMacName = OUTBOUND_MAC_INFO(g_connectTable[index].pContextSSH)->pHmacName;

            status = OK;
            break;
        }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_getNextConnectionInstance(sbyte4 connectionInstance)
{
    sbyte4     index;
    sbyte4     retInstance = 0;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance < g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            /* find the 'next' instance */
            if ((0 < retInstance) && (retInstance < g_connectTable[index].instance))
                continue;

            retInstance = g_connectTable[index].instance;
        }

    return retInstance;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_getSocketId(sbyte4 connectionInstance, TCP_SOCKET *pRetSocket)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if (NULL == pRetSocket)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            *pRetSocket = g_connectTable[index].socket;
            status = OK;
            break;
        }

exit:

#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSH_getSocketId() returns status = ", status);
#endif

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
extern sbyte4
SSH_setUserPortForwardingPermissions(sbyte4 connectionInstance, ubyte4 memberGroups)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            g_connectTable[index].pContextSSH->portForwardingPermissions = memberGroups;
            status = OK;
            break;
        }

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSH_setErrorCode(sbyte4 connectionInstance, sbyte4 errorCode)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            if (NULL != g_connectTable[index].pContextSSH)
            {
                g_connectTable[index].pContextSSH->errorCode = errorCode;
                status = OK;
            }
            break;
        }
    }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_useThisList(sbyte4 connectionInstance, ubyte *pList, ubyte4 list_index0, ubyte4 list_index1)
{
    /* a mutex is not necessary, this function should be called after accept, but before negotiate! */
    sbyte4      index;
    MSTATUS     status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  == g_connectTable[index].connectionState))
        {
            if (NULL != g_connectTable[index].pContextSSH)
            {
                status = ERR_INVALID_ARG;

                if (10 > list_index0)
                {
                    if (NULL != g_connectTable[index].pContextSSH->useThisList[list_index0].pString)
                    {
                        FREE(g_connectTable[index].pContextSSH->useThisList[list_index0].pString);
                        g_connectTable[index].pContextSSH->useThisList[list_index0].pString = NULL;
                    }

                    if (OK > (status = SSH_STR_HOUSE_initStringBuffer(&(g_connectTable[index].pContextSSH->useThisList[list_index0]), (sbyte *)pList)))
                        goto exit;
                }

                if (10 > list_index1)
                {
                    if (NULL != g_connectTable[index].pContextSSH->useThisList[list_index1].pString)
                    {
                        FREE(g_connectTable[index].pContextSSH->useThisList[list_index1].pString);
                        g_connectTable[index].pContextSSH->useThisList[list_index1].pString = NULL;
                    }

                    if (OK > (status = SSH_STR_HOUSE_initStringBuffer(&(g_connectTable[index].pContextSSH->useThisList[list_index1]), (sbyte *)pList)))
                        goto exit;
                }
            }
            break;
        }
    }


exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_useThisList: on exit, return status = ", status);
    }

    return (sbyte4)status;

} /* SSH_useThisList */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_useThisCipherList(sbyte4 connectionInstance, ubyte *pCipherList)
{
    /* a mutex is not necessary, this function should be called after accept, but before negotiate! */
    return (sbyte4)SSH_useThisList(connectionInstance, pCipherList, 2, 3);

} /* SSH_useThisCipherList */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_useThisHmacList(sbyte4 connectionInstance, ubyte *pHmacList)
{
    /* a mutex is not necessary, this function should be called after accept, but before negotiate! */
    return (sbyte4)SSH_useThisList(connectionInstance, pHmacList, 4, 5);

} /* SSH_useThisHmacList */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_ioctl(sbyte4 connectionInstance, ubyte4 ioctlSelector, ubyte4 ioctlValue)
{
    /* a mutex is not necessary, this function should be called after accept, but before negotiate! */
    sbyte4      index;
    MSTATUS     status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  <= g_connectTable[index].connectionState))
        {
            if (NULL != g_connectTable[index].pContextSSH)
            {
                switch (ioctlSelector)
                {
#ifdef __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__
                    case SET_SSH_MAX_SESSION_TIME_LIMIT:
                    {
                        g_connectTable[index].pContextSSH->maxSessionTimeLimit = ioctlValue;            /* 0 means no time limit */
                        RTOS_deltaMS(NULL, &g_connectTable[index].pContextSSH->sessionStartTime);

                        status = OK;
                        break;
                    }
#endif

                    default:
                    {
                        status = ERR_SSH_BAD_IOCTL_SELECTOR;
                    }
                }
            }
            break;
        }
    }

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_ioctl: on exit, return status = ", status);
    }

    return (sbyte4)status;

} /* SSH_ioctl */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_assignCertificateStore(sbyte4 connectionInstance, certStorePtr pCertStore)
{
    /* a mutex is not necessary, this function should be called after accept, but before negotiate! */
    sbyte4      index;
    MSTATUS     status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if ((connectionInstance == g_connectTable[index].instance) &&
            (CONNECT_NEGOTIATE  == g_connectTable[index].connectionState))
        {
            if (NULL != g_connectTable[index].pContextSSH)
            {
                g_connectTable[index].pContextSSH->pCertStore = pCertStore;
                status = OK;
            }

            break;
        }
    }

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_assignCertificateStore: on exit, return status = ", status);
    }

    return (sbyte4)status;

} /* SSH_assignCertificateStore */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_OLD_DSA_CONVERSION__) && defined(__ENABLE_MOCANA_DSA__))
extern sbyte4
SSH_convertOldKeyBlobToNew(ubyte *pOldDsaPublicKeyBlob, ubyte4 oldDsaPublicKeyBlobLength,
                           ubyte *pOldDsaPrivateKeyBlob, ubyte4 oldDsaPrivateKeyBlobLength,
                           ubyte **ppRetNewKeyBlob, ubyte4 *pRetNewKeyBlobLength)
{
    /* a mutex is not necessary, this function should be called after accept, but before negotiate! */
    AsymmetricKey   key;
    MSTATUS         status = ERR_SSH_BAD_ID;

    if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
        return status;

    if (OK > (status = CRYPTO_createDSAKey(&key, NULL)))
        goto exit;

    if (OK > (status = SSH_UTILS_extractKeyBlob(pOldDsaPublicKeyBlob, oldDsaPublicKeyBlobLength, SSH_PUBLIC_KEY_BLOB, key.key.pDSA)))
        goto exit;

    if (OK > (status = SSH_UTILS_extractKeyBlob(pOldDsaPrivateKeyBlob, oldDsaPrivateKeyBlobLength, SSH_PRIVATE_KEY_BLOB, key.key.pDSA)))
        goto exit;

    status = CA_MGMT_makeKeyBlobEx(&key, ppRetNewKeyBlob, pRetNewKeyBlobLength);

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_convertOldKeyBlobToNew: on exit, return status = ", status);
    }

    return (sbyte4)status;

} /* SSH_convertOldKeyBlobToNew */

#endif /* (defined(__ENABLE_MOCANA_SSH_OLD_DSA_CONVERSION__) && defined(__ENABLE_MOCANA_DSA__)) */


/*------------------------------------------------------------------*/

extern sbyte4
SSH_initiateReKey(sbyte4 connectionInstance, ubyte4 msAllowToComply)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        if (connectionInstance == g_connectTable[index].instance)
        {
            sshContext *pContextSSH = g_connectTable[index].pContextSSH;

            if (kOpenState != SSH_UPPER_STATE(pContextSSH))
            {
                /* either calling us before the first handshake has completed, */
                /* or calling us when re-key has occurred */
                status = ERR_SSH_KEYEX_IN_PROGRESS;
                goto exit;
            }

            pContextSSH->isReKeyInitiatedByMe = TRUE;

            if (0 == msAllowToComply)
            {
                pContextSSH->isReKeyStrict = FALSE;
            }
            else
            {
                pContextSSH->isReKeyStrict = TRUE;

                /* set starting time */
                RTOS_deltaMS(NULL, &pContextSSH->timeOfReKey);
                pContextSSH->numMilliSecForReKey = msAllowToComply;

                if (OK > (status = SSH_TRANS_sendServerAlgorithms(pContextSSH)))
                    goto exit;

                /* flag to stop sending non-key exchange related messages */
                pContextSSH->isReKeyOccuring = TRUE;
            }

            status = OK;
            break;
        }
    }

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_numBytesTransmitted(sbyte4 connectionInstance, ubyte8 *pRetNumBytes)
{
    sbyte4  index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if (NULL == pRetNumBytes)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
    {
        sshContext *pContextSSH = g_connectTable[index].pContextSSH;

        if ((connectionInstance == g_connectTable[index].instance) && (NULL != pContextSSH))
        {
            /* macro tricks */
            ZERO_U8((*pRetNumBytes));
            u8_Incr(pRetNumBytes, pContextSSH->bytesTransmitted);

            status = OK;
            break;
        }
    }

exit:
    return (sbyte4)status;
}

#endif /* __ENABLE_MOCANA_SSH_SERVER__ */
