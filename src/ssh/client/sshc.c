/*
 * sshc.c
 *
 * SSH Client API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 *
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

/**
@file       sshc.c
@brief      NanoSSH Client developer API.
@details    This file contains NanoSSH Client API functions.

@since 1.41
@version 5.4 and later

@todo_version (cookie-function signatures changed...)

@flags
To enable any of this file's functions, the following flag must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__
Whether the following flags are defined determines which functions are enabled:
+ \c \__ENABLE_DIGICERT_SSH_FTP_CLIENT__
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

@filedoc    sshc.c
*/

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/mem_pool.h"
#include "../../common/circ_buf.h"
#include "../../common/int64.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto/ecc.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_utils.h"


/*------------------------------------------------------------------*/

/* module variables */
static volatile sbyte4          m_instanceClient;
static sshClientSettings        m_sshcSettings;
static sshcConnectDescr*        m_sshcConnectTable;
static sbyte4                   m_sshMaxConnections;
#ifdef __ENABLE_DIGICERT_SSH_FTP_CLIENT__
static sftpClientSettings       m_sftpcSettings;
#endif

/* Forward Declarations */
static MSTATUS    sshcProtocolUpcall(sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);
static intBoolean funcProtocolSesssionTest(sshcConnectDescr *pDescr, void *cookie);
static intBoolean funcProtocolRecvTest(sshcConnectDescr *pDescr, void *cookie);
static MSTATUS    doProtocolConnect(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout);
extern MSTATUS    SSHC_doProtocolSession(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout);
extern MSTATUS    SSHC_doProtocolCloseChannel(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout);
extern MSTATUS    SSHC_doProtocolCheckWindowSize(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout);
static sbyte4     SSHC_releaseConnection(sshcConnectDescr* pDescr);


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
typedef sbyte4(*SSHC_FuncPtrRequest)(sbyte4 connectionInstance);
static sbyte4     SSHC_negotiateRequest(sbyte4 connectionInstance, SSHC_FuncPtrRequest func, intBoolean doCheckWindowSize);


/*------------------------------------------------------------------*/

extern sshClientSettings *
SSHC_sshClientSettings(void)
{
    return &m_sshcSettings;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_FTP_CLIENT__
/**
@brief      Get a NanoSSH SFTP client's configuration and callback settings.

@details    This function retrieves a NanoSSH SFTP client's configuration and
            callback settings.

@ingroup    func_ssh_sftp_client_general

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__
+ \c \__ENABLE_DIGICERT_SSH_FTP_CLIENT__

@inc_file sshc_filesys.h

@return     Pointer to \c sftpClientSettings structure containing the NanoSSH
            SFTP client's configuration and callback settings.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.c
*/
extern sftpClientSettings *
SSHC_sftpClientSettings(void)
{
    return &m_sftpcSettings;
}
#endif

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
static sbyte4 doLocalPortForwarding(sshClientContext *pContextSSH, sshcConnectDescr *pDescr,intBoolean useTimeout, ubyte4 timeout)
{
    MSTATUS status = OK;
    intBoolean loopContinue = TRUE;
    ubyte4 mesgTimeout = 1;

    if ( TRUE == useTimeout )
    {
        mesgTimeout = timeout;
    }
    while ( TRUE == loopContinue && OK <= status)
    {
        if (0 != pDescr->numBytesRead)
        {
            status = SSHC_IN_MESG_processMessage(pContextSSH,
                                                &pDescr->pReadBufferPosition,
                                                &pDescr->numBytesRead);
        }
        else if (OK <= (status = TCP_READ_AVL(SOCKET(pContextSSH), (sbyte *)pDescr->pReadBuffer,
                                              SSHC_BUFFER_SIZE, &pDescr->numBytesRead, mesgTimeout )))
        {
            pDescr->pReadBufferPosition = pDescr->pReadBuffer;

            if (0 != pDescr->numBytesRead)
            {
                status = SSHC_IN_MESG_processMessage(pContextSSH,
                                                    &pDescr->pReadBufferPosition,
                                                    &pDescr->numBytesRead);
            }
        }
        else
        {
            loopContinue = FALSE;
            if ( ERR_TCP_READ_TIMEOUT == status )
                status = OK;
        }
    } /* End of while loop */

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSHC, "SSH:doLocalPortForwarding(), returning status = ", status);

    return status;

} /* doLocalPortForwarding */

#endif /* __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */
/*------------------------------------------------------------------*/

static void
initConnDescr(sshcConnectDescr *pConn)
{
    pConn->connectionState     = CONNECT_CLOSED;
    pConn->pReadBuffer         = NULL;
    pConn->pReadBufferPosition = NULL;
    pConn->numBytesRead        = 0;
    pConn->pContextSSH         = NULL;
    pConn->isSocketClosed      = TRUE;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_init(sbyte4 numClientConnections)
{
    sbyte4      index;
    MSTATUS     status = OK;
    sshcConnectDescr *pConn;

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning++;
#endif

#if (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_createCombMutexes();
#else
    status = EC_createCombMutexes();
#endif
    if (OK != status)
        goto exit;
#endif

    m_sshMaxConnections = numClientConnections;

    DIGI_MEMSET((ubyte *)&m_sshcSettings, 0x00, sizeof(m_sshcSettings));

    if (NULL == (m_sshcConnectTable = MALLOC(sizeof(sshcConnectDescr) * numClientConnections)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)m_sshcConnectTable, 0x00, sizeof(sshcConnectDescr) * numClientConnections);

    m_sshcSettings.sshMaxAuthAttempts            = MAX_SSHC_AUTH_ATTEMPTS;
    m_sshcSettings.sshTimeOutOpen                = TIMEOUT_SSHC_OPEN;
    m_sshcSettings.sshTimeOutKeyExchange         = TIMEOUT_SSHC_KEX;
    m_sshcSettings.sshTimeOutNewKeys             = TIMEOUT_SSHC_NEWKEYS;
    m_sshcSettings.sshTimeOutServiceRequest      = TIMEOUT_SSHC_SERVICE_REQUEST;
    m_sshcSettings.sshTimeOutAuthentication      = TIMEOUT_SSHC_AUTH_LOGON;
    m_sshcSettings.sshTimeOutDefaultOpenState    = TIMEOUT_SSHC_OPEN_STATE;
    m_sshcSettings.sshMaxConnections             = numClientConnections;

    /* currently these must not be changed. */
    m_sshcSettings.funcPtrSessionOpen            = sshcProtocolUpcall;
    m_sshcSettings.funcPtrPtyRequest             = sshcProtocolUpcall;
    m_sshcSettings.funcPtrOpenShell              = sshcProtocolUpcall;
    m_sshcSettings.funcPtrOpenSftp               = sshcProtocolUpcall;
    m_sshcSettings.funcPtrWindowChange           = sshcProtocolUpcall;
    m_sshcSettings.funcPtrReceivedData           = sshcProtocolUpcall;
    m_sshcSettings.funcPtrStdErr                 = sshcProtocolUpcall;
    m_sshcSettings.funcPtrEof                    = sshcProtocolUpcall;
    m_sshcSettings.funcPtrClosed                 = sshcProtocolUpcall;
    m_sshcSettings.funcPtrBreakOp                = sshcProtocolUpcall;

#ifdef __ENABLE_DIGICERT_SSH_AUTH_BANNER__
    m_sshcSettings.funcPtrDisplayBanner           = NULL;
#endif

    for (index = m_sshMaxConnections, pConn = m_sshcConnectTable; 0 < index; index--, pConn++)
    {
        initConnDescr(pConn);
        pConn->instance = -1;
    }

    m_instanceClient = 0x110000L;

    if (OK > (status = SSHC_STR_HOUSE_initStringBuffers()))
        goto exit;

exit:
    return status;

} /* SSHC_init */


/*------------------------------------------------------------------*/
/**
@brief      Get a NanoSSH client connection's descriptor.

@details    This function retrieves a NanoSSH client connection's descriptor.

@ingroup    func_ssh_core_client

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__

@param connectionInstance   Connection instance returned from SSHC_connect().

@inc_file sshc_trans.h

@return     Pointer to SSHC connection descriptor if \c connectionInstance value
            is valid; otherwise \c NULL.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.c
*/
extern sshcConnectDescr *SSHC_getConnectionFromInstance(sbyte4 connectionInstance)
{
    sbyte4 i;
    sshcConnectDescr *pConn;
    sshcConnectDescr *pResult = NULL;

    if ((NULL == m_sshcConnectTable) || (-1 == connectionInstance))
        goto exit;

    for (i = m_sshMaxConnections, pConn = m_sshcConnectTable; 0 < i; i--, pConn++)
    {
        if (connectionInstance == pConn->instance)
        {
            pResult = pConn;
            break;
        }
    }

exit:
    return pResult;

} /* SSHC_getConnectionFromInstance */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_connect(TCP_SOCKET tempSocket, sbyte4 *pConnectionInstance, sbyte *pCommonName, struct certStore* pCertStore)
{
    /* a mutex is required around the call of this function, if multiple threads may invoke this API */
    sbyte4              index;
    TCP_SOCKET          connectSocket   = (TCP_SOCKET)tempSocket;
    sbyte4              instance        = ++m_instanceClient;
    sshcConnectDescr*   pConn           = NULL;
    MSTATUS             status          = ERR_SSH_DISCONNECT_TOO_MANY_CONNECTIONS;

    for (index = m_sshMaxConnections, pConn = m_sshcConnectTable; 0 < index; index--, pConn++)
    {
        if (CONNECT_CLOSED == pConn->connectionState)
        {
            /* clear out previous settings */
            DIGI_MEMSET((ubyte *)pConn, 0x00, sizeof(sshcConnectDescr));

            /* take ownership */
            pConn->connectionState = CONNECT_NEGOTIATE;
            pConn->numBytesRead    = 0;
            pConn->instance        = instance;

            if (OK > (status = CIRC_BUF_create(&pConn->pCircBufDescr, 2 * MAX_SESSION_WINDOW_SIZE)))
                goto exit;

            if (NULL == (pConn->pReadBuffer = MALLOC(SSHC_BUFFER_SIZE)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            if (OK > (status = SSHC_CONTEXT_allocStructures(&(pConn->pContextSSH))))
                goto exit;

            pConn->socket = pConn->pContextSSH->socket = connectSocket;
            CONNECTION_INSTANCE(pConn->pContextSSH)    = instance;

#ifdef __ENABLE_DIGICERT_SSH_X509V3_SIGN_SUPPORT__
            /* Keep a copy of common name */
            if (pCommonName)
            {
                int len = DIGI_STRLEN(pCommonName);

                if (NULL == (pConn->pContextSSH->pCommonName = MALLOC(len + 1)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(pConn->pContextSSH->pCommonName, pCommonName, len);
                pConn->pContextSSH->pCommonName[len] = 0;
            }
            else
                pConn->pContextSSH->pCommonName = pCommonName;

            /* Note: for now, we do allow a null pCommonName and pCertStore - it will be detected later */
            pConn->pContextSSH->pCertStore = pCertStore;
#endif

            /* SSHC_ExtraClient should initiate the hello, if we use SSL client as model */
            if (OK > (status = SSHC_TRANS_versionExchange(pConn->pContextSSH)))
                goto exit;

            *pConnectionInstance = instance;  /* caller needs this */
            status = OK;
            break;
        }
    }

    if (0 == index)
    {
        pConn = NULL;
    }

exit:
    if ((OK > status) && (NULL != pConn))
    {
        SSHC_CONTEXT_deallocStructures(&(pConn->pContextSSH));
        SSHC_releaseConnection(pConn);
    }

    return (sbyte4)status;

} /* SSHC_connect */


/*------------------------------------------------------------------*/

static sbyte4
SSHC_releaseConnection(sshcConnectDescr* pDescr)
{
    if (NULL != pDescr->pReadBuffer)
    {
        FREE(pDescr->pReadBuffer);
        pDescr->pReadBuffer = NULL;
    }

    CIRC_BUF_release(&pDescr->pCircBufDescr);

    initConnDescr(pDescr);
    pDescr->instance = -1;

    return OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_useThisCipher(sbyte4 connectionInstance, ubyte *pCipher)
{
    /* a mutex is not necessary, this function should be called after connect (?) */
    intBoolean        isCipherAvailable = FALSE;
    sshcConnectDescr* pDescr = NULL;
    MSTATUS           status = ERR_SSH_BAD_ID;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
         goto exit;

    if (NULL != pDescr->pContextSSH)
    {
        if ((OK > (status = SSHC_TRANS_cipherVerify(pCipher, &isCipherAvailable))) || (FALSE == isCipherAvailable))
        {
            /* unknown cipher selected */
            status = ERR_SSH_UNKNOWN_CIPHER;
            goto exit;
        }

        if (OK > (status = SSHC_STR_HOUSE_initStringBuffer(&(pDescr->pContextSSH->sshc_algorithmMethods[2]), (sbyte *)pCipher)))
            goto exit;

        status = SSHC_STR_HOUSE_initStringBuffer(&(pDescr->pContextSSH->sshc_algorithmMethods[3]), (sbyte *)pCipher);
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSHC, "SSHC_useThisCipher: on exit, return status = ", status);
    }

    return (sbyte4)status;

} /* SSHC_useThisCipher */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_useThisHmac(sbyte4 connectionInstance, ubyte *pHmac)
{
    /* a mutex is not necessary, this function should be called after connect (?) */
    intBoolean        isHmacAvailable = FALSE;
    sshcConnectDescr* pDescr = NULL;
    MSTATUS           status = ERR_SSH_BAD_ID;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
         goto exit;

    if (NULL != pDescr->pContextSSH)
    {
        if ((OK > (status = SSHC_TRANS_hmacVerify(pHmac, &isHmacAvailable))) || (FALSE == isHmacAvailable))
        {
            /* unknown hmac selected */
            status = ERR_SSH_UNKNOWN_HMAC;
            goto exit;
        }

        if (OK > (status = SSHC_STR_HOUSE_initStringBuffer(&(pDescr->pContextSSH->sshc_algorithmMethods[4]), (sbyte *)pHmac)))
            goto exit;

        status = SSHC_STR_HOUSE_initStringBuffer(&(pDescr->pContextSSH->sshc_algorithmMethods[5]), (sbyte *)pHmac);
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSHC, "SSHC_useThisHmac: on exit, return status = ", status);
    }

    return (sbyte4)status;

} /* SSHC_useThisHmac */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_negotiateConnection(sbyte4 connectionInstance)
{
    /* a mutex is not necessary, this function should be called after connect (?) */
    sshcConnectDescr* pDescr = NULL;
    MSTATUS           status = ERR_SSH_BAD_ID;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
         goto exit;

    if (OK <= (status = doProtocolConnect(connectionInstance, TRUE, TIMEOUT_SSHC_NEWKEYS)))
    {
        DIGICERT_log(MOCANA_SSH, LS_INFO, (sbyte *)"SSH client negotiated connection.");
        pDescr->connectionState = CONNECT_OPEN;
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSHC, "SSHC_negotiateConnection() returns status = ", status);
    }

    return (sbyte4)status;

} /* SSHC_negotiateConnection */


/*------------------------------------------------------------------*/

static MSTATUS
sshcProtocolUpcall(sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent,
                   ubyte *pMesg, ubyte4 mesgLen)
{
    sshcConnectDescr*   pDescr;
    ubyte4              numBytesWritten;
    ubyte               tmpBuf[3];
    circBufDescr*       pCircBufDescr;
    MSTATUS             status = OK;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
        status = ERR_SSH_BAD_ID;
        goto exit;
    }

    pCircBufDescr    = pDescr->pCircBufDescr;
    pDescr->mesgType = (sbyte4)sessionEvent;  /* see SSHC_negotiateRequest */

    if ((SSH_SESSION_DATA == sessionEvent) || (SSH_SESSION_STDERR == sessionEvent))
    {
        ubyte4 numBytesToWrite;

        /* nothing to do, just break */
        if (0 == mesgLen)
            goto exit;

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
            goto exit;

        if (numBytesToWrite != numBytesWritten)
        {
            status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
            goto exit;
        }

        /* store the data */
        if (OK > (status = CIRC_BUF_write(pCircBufDescr, pMesg, mesgLen, &numBytesWritten)))
            goto exit;

        if (mesgLen != numBytesWritten)
        {
            status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
            goto exit;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SSHC_negotiateRequest(sbyte4 connectionInstance, SSHC_FuncPtrRequest func, intBoolean doCheckWindowSize)
{
    MSTATUS           status;
    sshcConnectDescr* pDescr;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if ((TRUE == doCheckWindowSize) &&
        (0 == pDescr->pContextSSH->sessionState.windowSize))
    {
        /* wait for the window to grow before continuing */
        if (OK > (status = SSHC_doProtocolCheckWindowSize(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER)))
            goto exit;
    }

    pDescr->mesgType = SSH_SESSION_NOTHING;
    if (0 > (status = (func)(connectionInstance)))
        goto exit;


    status = SSHC_doProtocolSession(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER);

exit:
    return (sbyte4)status;

} /* SSHC_negotiateRequest */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_negotiateSession(sbyte4 connectionInstance)
{
    return (sbyte4)(SSHC_negotiateRequest(connectionInstance, SSHC_SESSION_OpenSessionChannel, FALSE));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_negotiateCloseChannel(sbyte4 connectionInstance, sbyte4 channelNumber)
{
    MOC_UNUSED(channelNumber);
    MSTATUS           status;
    sshcConnectDescr* pDescr;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    pDescr->mesgType = SSH_SESSION_NOTHING;
    if (0 > (status = SSHC_SESSION_CloseSessionChannel(connectionInstance)))
        goto exit;


    status = SSHC_doProtocolCloseChannel(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER);

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_negotiateSubsystemSFTPChannelRequest(sbyte4 connectionInstance)
{
    return (sbyte4)(SSHC_negotiateRequest(connectionInstance, SSHC_SESSION_SendSubsystemSFTPChannelRequest, FALSE));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_negotiatePtyTerminalChannelRequest(sbyte4 connectionInstance)
{
    return (sbyte4)(SSHC_negotiateRequest(connectionInstance, SSHC_SESSION_sendPtyOpenRequest, FALSE));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_negotiateShellChannelRequest(sbyte4 connectionInstance)
{
    return (sbyte4)(SSHC_negotiateRequest(connectionInstance, SSHC_SESSION_sendShellOpenRequest, FALSE));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sendMessage(sbyte4 connectionInstance, ubyte *pBuffer, ubyte4 bufferSize, ubyte4 *pBytesSent)
{
    sshcConnectDescr*   pDescr = NULL;
    MSTATUS             status = ERR_SSH_BAD_ID;

    if ((NULL == pBuffer) || (NULL == pBytesSent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (TRUE == pDescr->pContextSSH->isReKeyOccuring)
    {
        /* Re-key is in progress */
        *pBytesSent = 0;
        status = OK;
        goto exit;
    }

    if (CONNECT_OPEN == pDescr->connectionState)
    {
        if (((MAX_SESSION_WINDOW_SIZE / 8) >= pDescr->pContextSSH->sessionState.windowSize) ||
            (bufferSize >= pDescr->pContextSSH->sessionState.windowSize))
        {
            /* read data to prevent blocking on SSH transport window changes */
            status = SSHC_doProtocolCommon(connectionInstance, TRUE, 100, funcProtocolRecvTest, pDescr);

            if (OK > status)
            {
                if (ERR_TCP_READ_TIMEOUT != status)
                    goto exit;
            }
        }

        status = SSHC_SESSION_sendMessage(pDescr->pContextSSH,
                                          pBuffer, bufferSize, pBytesSent);
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSHC_sendMessage() returns status = ", status);
#endif

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_sendAck(sshClientContext *pContextSSH, sshcConnectDescr *pDescr, enum sshcSessionTypes sessionEvent)
{
    sshClientSession*   pSshSession = &(pContextSSH->sessionState);
    ubyte4              ackRecvdData = pSshSession->ackRecvdData;
    ubyte4              numBytesPending;
    intBoolean          boolSendAck = FALSE;
    MSTATUS             status = OK;

    if (TRUE == pContextSSH->isReKeyOccuring)
    {
        /* Re-key is in progress */
        goto exit;
    }

    /* nothing to do */
    if (0 == ackRecvdData)
        goto exit;

    if (OK > (status = CIRC_BUF_bytesAvail(pDescr->pCircBufDescr, &numBytesPending)))
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
        if (OK > (status = SSHC_SESSION_sendWindowAdjust(pContextSSH, sessionEvent, ackRecvdData)))
            goto exit;

        pSshSession->ackRecvdData   -= ackRecvdData;
        pSshSession->unAckRecvdData -= ackRecvdData;
        RTOS_deltaMS(NULL, &pSshSession->timeOfLastAck);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_ackData(sshClientContext *pContextSSH, sshcConnectDescr *pDescr, enum sshcSessionTypes sessionEvent, ubyte4 numBytesToAck)
{
    sshClientSession*   pSshSession = &(pContextSSH->sessionState);
    MSTATUS             status;

    if (0 != numBytesToAck)
    {
        if (numBytesToAck > (pSshSession->unAckRecvdData - pSshSession->ackRecvdData))
        {
            /* this should never happen */
            numBytesToAck = (pSshSession->unAckRecvdData - pSshSession->ackRecvdData);
        }

        pSshSession->ackRecvdData += numBytesToAck;
    }

    status = SSHC_sendAck(pContextSSH, pDescr, sessionEvent);

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_recvMessage(sbyte4 connectionInstance, sbyte4 *pMessageType,
                 sbyte *pRetMessage, sbyte4 *pNumBytesReceived, ubyte4 timeout)
{
    sshcConnectDescr*   pDescr = NULL;
    ubyte4              numBytesToRead;
    ubyte4              numBytesRead;
    ubyte               tmpBuf[4];
    MSTATUS             status = ERR_SSH_BAD_ID;

    *pMessageType = SSH_SESSION_NOTHING;
    *pNumBytesReceived = 0;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (CONNECT_OPEN == pDescr->connectionState)
    {
        /* attempt to read data from circular buffer */
        if (OK > (status = CIRC_BUF_read(pDescr->pCircBufDescr, tmpBuf, 1, &numBytesRead)))
            goto exit;

        if (0 == numBytesRead)
        {
            pDescr->mesgType = SSH_SESSION_NOTHING;

            /* read any data available on the socket */
            status = SSHC_doProtocolCommon(connectionInstance, (0 != timeout) ? TRUE : FALSE, timeout,
                                           funcProtocolRecvTest, pDescr);

            if (OK > status)
            {
                if (ERR_TCP_READ_TIMEOUT != status)
                    goto exit;
            }

            /* attempt to read data from circular buffer */
            if ((OK > (status = CIRC_BUF_read(pDescr->pCircBufDescr, tmpBuf, 1, &numBytesRead))) || (0 == numBytesRead))
                goto exit;
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
            if (OK > (status = CIRC_BUF_read(pDescr->pCircBufDescr, tmpBuf, numBytesToRead, &numBytesRead)))
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
        else if ((SSH_SESSION_DATA == *pMessageType) || (SSH_SESSION_STDERR == *pMessageType))
        {
            *pNumBytesReceived = 1;
        }

        if (0 != *pNumBytesReceived)
        {
            if (OK > (status = CIRC_BUF_read(pDescr->pCircBufDescr, (ubyte *)pRetMessage, *pNumBytesReceived, &numBytesRead)))
                goto exit;

            if ((sbyte4)numBytesRead != *pNumBytesReceived)
            {
                status = ERR_SSH_CIRCULAR_BUFFER_UNDERFLOW;
                goto exit;
            }
        }

        /* ack the received data */
        status = SSHC_ackData(pDescr->pContextSSH, pDescr, (enum sshcSessionTypes)*pMessageType, *pNumBytesReceived);
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_MESSAGES, "SSHC_recvMessage() returns status = ", status);

    return (sbyte4)status;

} /* SSHC_recvMessage */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_setTerminalTextWindowSize(sbyte4 connectionInstance, ubyte4 width, ubyte4 height)
{
    sshcConnectDescr*   pDescr = NULL;
    MSTATUS             status = ERR_SSH_BAD_ID;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
         goto exit;

    if (TRUE == pDescr->pContextSSH->isReKeyOccuring)
    {
        status = ERR_SSH_KEYEX_IN_PROGRESS;
        goto exit;
    }

    if (CONNECT_OPEN == pDescr->connectionState)
        status = SSHC_SESSION_sendWindowChangeChannelRequest(pDescr->pContextSSH, width, height);

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_FTP_CLIENT__
extern sbyte4
SSHC_negotiateSFTPHello(sbyte4 connectionInstance)
{
    return SSHC_negotiateRequest(connectionInstance, SSHC_FTP_SendFTPHello, TRUE);
}
#endif


/*------------------------------------------------------------------*/

static sbyte4
doProtocolCommon(sshClientContext *pContextSSH, sshcConnectDescr *pDescr,
                 intBoolean useTimeout, ubyte4 timeout,
                 SSHC_FuncPtrProtocolTest testFunc, void *cookie)
{
    ubyte4  adjustedTimeout;
    MSTATUS status;

    if (TRUE == useTimeout)
    {
        RTOS_deltaMS(NULL, &(SSH_TIMER_START_TIME(pContextSSH)));
        SSH_TIMER_MS_EXPIRE(pContextSSH) = timeout;
    }

    do
    {
        /* handle across events time outs */
        if (TRUE == useTimeout)
        timeout   = SSH_TIMER_MS_EXPIRE(pContextSSH);

        if (TCP_NO_TIMEOUT != timeout)
        {
            adjustedTimeout = RTOS_deltaMS(&(SSH_TIMER_START_TIME(pContextSSH)), NULL);

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

        if (0 != pDescr->numBytesRead)
        {
            status = SSHC_IN_MESG_processMessage(pContextSSH,
                                                &pDescr->pReadBufferPosition,
                                                &pDescr->numBytesRead);
        }
        else if (OK <= (status = TCP_READ_AVL(SOCKET(pContextSSH), (sbyte *)pDescr->pReadBuffer,
                                              SSHC_BUFFER_SIZE, &pDescr->numBytesRead, adjustedTimeout)))
        {
            pDescr->pReadBufferPosition = pDescr->pReadBuffer;

            if (0 != pDescr->numBytesRead)
            {
                status = SSHC_IN_MESG_processMessage(pContextSSH,
                                                    &pDescr->pReadBufferPosition,
                                                    &pDescr->numBytesRead);
            }
        }
    }
    while ((OK == status) && (FALSE == (*testFunc)(pDescr, cookie)));

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSHC, "SSH:doProtocolCommon(), returning status = ", status);

    return status;

} /* doProtocolCommon */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSHC_doProtocolCommon(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout,
                        SSHC_FuncPtrProtocolTest testFunc, void *cookie)
{
    sshcConnectDescr *pDescr;
    MSTATUS status;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }
    status = doProtocolCommon(pDescr->pContextSSH, pDescr, useTimeout,
                                timeout, testFunc, cookie);
exit:
    return status;
} /* SSHC_doProtocolCommon */


/*------------------------------------------------------------------*/

static intBoolean funcProtocolConnectTest(sshcConnectDescr *pDescr, void *cookie)
{
    MOC_UNUSED(cookie);

    return (intBoolean)(pDescr->pContextSSH->upperStateIn == kOpenState);
}


/*------------------------------------------------------------------*/

static MSTATUS
doProtocolConnect(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout)
{
    return SSHC_doProtocolCommon(connectionInstance, useTimeout, timeout, funcProtocolConnectTest, NULL);
}


/*------------------------------------------------------------------*/

static intBoolean funcProtocolSesssionTest(sshcConnectDescr *pDescr, void *cookie)
{
    MOC_UNUSED(cookie);

    return (intBoolean)(!((SSH_SESSION_NOTHING == pDescr->mesgType) || (SSH_SESSION_WINDOW_CHANGE == pDescr->mesgType)));
}


/*------------------------------------------------------------------*/

static intBoolean
funcProtocolRecvTest(sshcConnectDescr *pDescr, void *cookie)
{
    MOC_UNUSED(cookie);

    return (intBoolean)(!((SSH_SESSION_NOTHING == pDescr->mesgType)
			    || (SSH_SESSION_WINDOW_CHANGE == pDescr->mesgType)
			    || (pDescr->numBytesRead != 0)));
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSHC_doProtocolSession(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout)
{
    return SSHC_doProtocolCommon(connectionInstance, useTimeout, timeout, funcProtocolSesssionTest, NULL);
}


/*------------------------------------------------------------------*/

static intBoolean funcProtocolWindowTest(sshcConnectDescr *pDescr, void *cookie)
{
    MOC_UNUSED(cookie);

    return (intBoolean)(pDescr->pContextSSH->sessionState.windowSize);
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSHC_doProtocolCheckWindowSize(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout)
{
    return SSHC_doProtocolCommon(connectionInstance, useTimeout, timeout, funcProtocolWindowTest, NULL);
}


/*------------------------------------------------------------------*/

static intBoolean funcProtocolChannelClosedTest(sshcConnectDescr *pDescr, void *cookie)
{
    MOC_UNUSED(cookie);
    return pDescr->pContextSSH->sessionState.rxdClosed;
}

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSHC_doProtocolCloseChannel(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout)
{
    return SSHC_doProtocolCommon(connectionInstance, useTimeout, timeout, funcProtocolChannelClosedTest, NULL);
}

/*------------------------------------------------------------------*/

extern void
SSHC_close(sbyte4 connectionInstance)
{
    sshcConnectDescr* pDescr;

    if (NULL != (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
        SSHC_SESSION_Close(pDescr);
        SSHC_CONTEXT_deallocStructures(&(pDescr->pContextSSH));
        SSHC_releaseConnection(pDescr);
    }

} /* SSHC_close */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_getCookie(sbyte4 connectionInstance, void **pRetCookie)
{
    sshcConnectDescr* pDescr;
    MSTATUS           status = ERR_SSH_BAD_ID;

    if (NULL == pRetCookie)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
        *pRetCookie = pDescr->cookie;
        status = OK;
    }

exit:
    return status;

} /* SSHC_getCookie */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_setCookie(sbyte4 connectionInstance, void* cookie)
{
    sshcConnectDescr* pDescr;
    MSTATUS           status = ERR_SSH_BAD_ID;

    if (NULL != (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
        pDescr->cookie = cookie;
        status = OK;
    }

    return status;

} /* SSHC_setCookie */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_shutdown(void)
{
    DIGICERT_log((sbyte4)MOCANA_SSH, (sbyte4)LS_INFO, (sbyte *)"SSH client shutting down.");

#if (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_deleteAllCombsAndMutexes();
#else
    EC_deleteAllCombsAndMutexes();
#endif
#endif

    if (NULL != m_sshcConnectTable)
    {
        FREE(m_sshcConnectTable);
        m_sshcConnectTable = NULL;
    }

    SSHC_STR_HOUSE_freeStringBuffers();

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning--;
#endif

    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

/* exportable client authentication key */
extern MSTATUS
SSHC_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLen, ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen)
{
    return SSHC_UTILS_generateServerAuthKeyFile(pKeyBlob, keyBlobLen, ppRetEncodedAuthKey, pRetEncodedAuthKeyLen);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SSHC_parsePublicKeyBuffer(ubyte* pKeyBlob, ubyte4 keyBlobLen,
    AsymmetricKey *pAsymKey)
{
    return SSHC_UTILS_sshParseAuthPublicKey((sbyte *) pKeyBlob, keyBlobLen, pAsymKey);
}

/*------------------------------------------------------------------*/

extern MSTATUS SSHC_parseServerAuthKeyFile(ubyte* pKeyFile, ubyte4 keyFileLen,
    AsymmetricKey *pAsymKey)
{
    return SSHC_UTILS_sshParseAuthPublicKeyFile((sbyte *) pKeyFile, keyFileLen, pAsymKey);
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_freeGenerateServerAuthKeyFile(ubyte **ppFreeEncodedAuthKey)
{
    return SSHC_UTILS_freeGenerateServerAuthKeyFile(ppFreeEncodedAuthKey);
}

/*-------------------------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
/*-------------------------------------------------------------------------------------*/

extern sbyte4
SSHC_doProtocolProcessPortForwardSession(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout)
{
    sshcConnectDescr *pDescr = NULL;
    MSTATUS status;

    MOC_UNUSED(useTimeout);
    MOC_UNUSED(timeout);

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }
    status = doLocalPortForwarding(pDescr->pContextSSH, pDescr,useTimeout,timeout);
exit:
    return status;
}

/*-------------------------------------------------------------------------------------*/

extern sbyte4 SSHC_lpfRegisterConnection( sbyte4 connectionInstance, ubyte4* pChannel)
{
    MSTATUS            status = OK;
    ubyte4             channel = 0;
    sshcConnectDescr*  pSessDesc = NULL;

    if ( NULL == ( pSessDesc = SSHC_getConnectionFromInstance( connectionInstance ) ) )
    {
        status = ERR_SESSION;
        goto exit;
    }

    if ( OK > ( status = SSHC_SESSION_createLocalPortFwdSession( pSessDesc, (sbyte4*)pChannel ) ) )
        goto exit;

exit:
    return status;
}

/*-------------------------------------------------------------------------------------*/

/**
@coming_soon
@ingroup    func_sshc_port_forwarding
*/
extern MSTATUS
SSHC_startRemotePortForwarding(sbyte4 connectionInstance, sbyte *pBindAddr, ubyte4 bindPort, sbyte *pHostAddr, ubyte4 hostPort)
{
    MSTATUS             status = OK;
    sshcConnectDescr*   pSessDesc = NULL;
    ubyte4              i = 0;
    sshClientContext*   pContextSSH = NULL;

    if(NULL == pBindAddr || NULL == pHostAddr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( NULL == ( pSessDesc = SSHC_getConnectionFromInstance( connectionInstance ) ) )
    {
        status = ERR_SESSION;
        goto exit;
    }

    pContextSSH = pSessDesc->pContextSSH;
    /* Add an entry to rpf table */
    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        /* check if entry is already present. If so, then this is a duplicate request */
        if (pContextSSH->rpfTable[i].inUse)
        {
            if((!DIGI_STRCMP((sbyte *)pContextSSH->rpfTable[i].pBindAddr, pBindAddr)) &&
               (pContextSSH->rpfTable[i].bindPort == bindPort)  &&
               (!DIGI_STRCMP((sbyte *)pContextSSH->rpfTable[i].pHostAddr, pHostAddr)) &&
               (pContextSSH->rpfTable[i].hostPort == hostPort))
                goto exit;
        }
    }

    /* find an empty slot */
    for (i=0; (i < SSH_MAX_RPF_HOSTS) && (pContextSSH->rpfTable[i].inUse); i++);

    if ( i < SSH_MAX_RPF_HOSTS)
    {
        /* empty slot found */
        pContextSSH->rpfTable[i].isConfirmed = FALSE;
        pContextSSH->rpfTable[i].inUse = TRUE;
        if (OK > (status =  DIGI_MALLOC((void **)&pContextSSH->rpfTable[i].pBindAddr, DIGI_STRLEN(pBindAddr) + 1)))
            goto exit;

        DIGI_STRCBCPY((sbyte *)pContextSSH->rpfTable[i].pBindAddr, DIGI_STRLEN(pBindAddr) + 1, pBindAddr);
        pContextSSH->rpfTable[i].bindPort = bindPort;

        if (OK > (status =  DIGI_MALLOC((void **)&pContextSSH->rpfTable[i].pHostAddr, DIGI_STRLEN(pHostAddr) + 1)))
            goto exit;

        DIGI_STRCBCPY((sbyte *)pContextSSH->rpfTable[i].pHostAddr, DIGI_STRLEN(pHostAddr) + 1, pHostAddr);
        pContextSSH->rpfTable[i].hostPort = hostPort;

        DIGI_MEMSET( (ubyte*)pContextSSH->rpfTable[i].channelList, 0x00, SSH_MAX_REMOTE_PORT_FWD_CHANNEL );

        if (OK > (status = (sendRpfStart(pContextSSH, (ubyte *) pBindAddr, bindPort))))
        {
            pContextSSH->rpfTable[i].inUse = FALSE;
            if(NULL != pContextSSH->rpfTable[i].pBindAddr)
                FREE(pContextSSH->rpfTable[i].pBindAddr);
            if(NULL != pContextSSH->rpfTable[i].pHostAddr)
                FREE(pContextSSH->rpfTable[i].pHostAddr);
            goto exit;
        }
    }

exit:
    return status;
}

/*-------------------------------------------------------------------------------------*/

/**
@coming_soon
@ingroup    func_ssh_client_ungrouped
*/
extern MSTATUS
SSHC_cancelRemotePortForwarding(sbyte4 connectionInstance, sbyte *pHostAddr, ubyte4 hostPort)
{
    MSTATUS             status = OK;
    sshcConnectDescr*   pSessDesc = NULL;
    ubyte4              i = 0, j = 0;
    sshClientContext*   pContextSSH = NULL;

    if(NULL == pHostAddr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( NULL == ( pSessDesc = SSHC_getConnectionFromInstance( connectionInstance ) ) )
    {
        status = ERR_SESSION;
        goto exit;
    }

    pContextSSH = pSessDesc->pContextSSH;
    /* Add an entry to rpf table */
    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        /* check if entry is already present. If so, then this is a duplicate request */
        if (pContextSSH->rpfTable[i].inUse)
        {
            if((!DIGI_STRCMP((sbyte *)pContextSSH->rpfTable[i].pHostAddr, pHostAddr)) &&
                  (pContextSSH->rpfTable[i].hostPort == hostPort))
            {
                if (OK > (status = (sendCancelRpfReq(pContextSSH,
                                                     pContextSSH->rpfTable[i].pBindAddr,
                                                     pContextSSH->rpfTable[i].bindPort,
                                                     (ubyte *) pHostAddr, hostPort))))
                    goto exit;

                pContextSSH->rpfTable[i].inUse = FALSE;
                pContextSSH->rpfTable[i].hostPort = -1;
                pContextSSH->rpfTable[i].bindPort = -1;
                for(j = 0; j < SSH_MAX_REMOTE_PORT_FWD_CHANNEL; j++)
                {
                    if(SSHC_sshClientSettings()->funcPtrPortForwardClosed != NULL)
                        SSHC_sshClientSettings()->funcPtrPortForwardClosed(connectionInstance, 0, NULL, 0, pContextSSH->rpfTable[i].channelList[j]);
                    else
                        status = ERR_NULL_POINTER;
                }
                FREE(pContextSSH->rpfTable[i].pBindAddr);
                FREE(pContextSSH->rpfTable[i].pHostAddr);
                break;
            }
        }
    }

    if(SSH_MAX_RPF_HOSTS == i)
    {
        status = ERR_NOT_FOUND;
    }
exit:
        return status;
}

/*-------------------------------------------------------------------------------------*/

extern sbyte4 SSHC_lpfStartConnection( sbyte4 connectionInstance, ubyte4 channel,
                                       ubyte* pConnectHost, ubyte4 connectPort,
                                       ubyte* pSrcHost, ubyte4 srcPort)
{
    MSTATUS           status = OK;
    sshcConnectDescr*  pSessDesc = NULL;

    if ( NULL == ( pSessDesc = SSHC_getConnectionFromInstance( connectionInstance ) ) )
    {
        status = ERR_SESSION;
        goto exit;
    }

    if ( OK > ( status = SSHC_SESSION_startPortFwdSession( pSessDesc, channel,
                                                           pConnectHost, connectPort,
                                                           pSrcHost, srcPort ) ) )
        goto exit;
exit:
    return status;
}

/*-------------------------------------------------------------------------------------*/

extern sbyte4 SSHC_lpfStopConnection(sbyte4 connectionInstance, ubyte4 channel)
{
    MSTATUS           status = OK;
    sshcConnectDescr*  pSessDesc = NULL;

    if ( NULL == ( pSessDesc = SSHC_getConnectionFromInstance( connectionInstance ) ) )
    {
        status = ERR_SESSION;
        goto exit;
    }

    if ( OK > ( status = SSHC_SESSION_sendLocalPortFwdClose( pSessDesc, channel ) ) )
        goto exit;

exit:
    return status;
}

/*-------------------------------------------------------------------------------------*/

extern sbyte4 SSHC_lpfSendMessage(sbyte4 connectionInstance, ubyte4 channel, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    MSTATUS           status = OK;
    sshcConnectDescr*  pSessDesc = NULL;

    if ( NULL == ( pSessDesc = SSHC_getConnectionFromInstance( connectionInstance ) ) )
    {
        status = ERR_SESSION;
        goto exit;
    }

    if (TRUE == pSessDesc->pContextSSH->isReKeyOccuring)
    {
        /* Re-key is in progress */
        *pBytesSent = 0;
        status = OK;
        goto exit;
    }

    if ( OK > ( status = SSHC_SESSION_sendLocalPortFwdMessage( pSessDesc, channel,
                                                               (ubyte *) pBuffer, bufferSize,
                                                               (ubyte4 *) pBytesSent ) ) )
        goto exit;

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_initiateReKey(sbyte4 connectionInstance, ubyte4 msAllowToComply)
{
    sshcConnectDescr*   pDescr;
    MSTATUS             status = ERR_SSH_BAD_ID;

    if ((NULL != (pDescr = SSHC_getConnectionFromInstance(connectionInstance))) && (NULL != pDescr->pContextSSH))
    {
        sshClientContext *pContextSSH = pDescr->pContextSSH;

        if (kOpenState != SSH_UPPER_STATE(pContextSSH))
        {
            /* either calling us before the first handshake has completed, */
            /* or calling us while re-keyex is occurring */
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

            if (OK > (status = SSHC_TRANS_sendClientAlgorithms(pContextSSH)))
                goto exit;

            /* flag to stop sending non-key exchange related messages */
            pContextSSH->isReKeyOccuring = TRUE;
        }

        status = OK;
    }

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_numBytesTransmitted(sbyte4 connectionInstance, ubyte8 *pRetNumBytes)
{
    sshcConnectDescr*   pDescr;
    MSTATUS             status = ERR_SSH_BAD_ID;

    if (NULL == pRetNumBytes)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((NULL != (pDescr = SSHC_getConnectionFromInstance(connectionInstance))) && (NULL != pDescr->pContextSSH))
    {
        sshClientContext *pContextSSH = pDescr->pContextSSH;

        /* macro tricks */
        ZERO_U8((*pRetNumBytes));
        u8_Incr(pRetNumBytes, pContextSSH->bytesTransmitted);

        status = OK;
    }

exit:
    return (sbyte4)status;
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */
