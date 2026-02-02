/*
 * tap_client_comm.c
 *
 * Trust Anchor Platform Client communication APIs
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

#ifndef __RTOS_FREERTOS__
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __RTOS_WIN32__
#include <unistd.h>
#else
#include <Winsock2.h>
#include <Ws2tcpip.h>
#endif
#include <fcntl.h>
#if defined(__LINUX_RTOS__)
#include <signal.h>
#endif
#endif

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_TAP__

#ifdef __ENABLE_TAP_REMOTE__
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mprintf.h"
#include "../common/mtcp.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/moc_config.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/aes.h"
#include "../common/base64.h"
/* DSA and ECC needed for now since including keyblob */
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif

#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"

#include "tap.h"
#include "tap_conf_common.h"
#include "tap_remote.h"
#include "tap_client_comm.h"
#include "tap_serialize.h"
#include "tap_serialize_smp.h"
#include "tap_serialize_remote.h"
#include "smp_serialize_interface.h"

MOC_EXTERN_DATA_DEF TAP_OPERATIONAL_INFO tapClientInfo = {0};
MOC_EXTERN_DATA_DEF ubyte tapRemoteInitDone = 0;
static ubyte tapCleanupCertStore = 0;

extern MSTATUS 
TAP_initRemoteSession()
{
    MSTATUS status = OK;

    if (!tapRemoteInitDone)
    {
        /* Load configuration if not already done earlier */
        if (OK != (status = parseCommConfiguration(&tapClientInfo, 
                        NULL)))
        {
            goto exit;
        }
#ifdef __ENABLE_SECURE_COMM__
        if (!tapClientInfo.enableunsecurecomms)
        {
            if (0 > (status = SSL_init(MAX_SSL_SERVER_CONNECTIONS_ALLOWED, MAX_SSL_CLIENT_CONNECTIONS)))
            {
                DB_PRINT("%s.%d: Unable to initialize SSL\n", __FUNCTION__,
                        __LINE__);
                goto exit;
            }
            if(!tapClientInfo.isNonFsMode)
            {
                if (OK != (status = TAP_CONF_COMMON_setCertStore(&tapClientInfo)))
                {
                    goto exit;
                } 
                if (tapClientInfo.enableMutualAuth)
                {
                    if (OK != (status = TAP_CONF_COMMON_loadCertificateAndKey(tapClientInfo.certificateFileName,
                                    tapClientInfo.certificateKeyFileName,
                                    tapClientInfo.pSslCertStore)))
                        goto exit;
                }
            }
            tapCleanupCertStore = 1;
        }
#endif
        tapRemoteInitDone = 1;
    }

exit:

    return status;
}

extern MSTATUS
TAP_unInitRemoteSession()
{
    MSTATUS status = OK;

    if (tapRemoteInitDone)
    {
#ifdef __ENABLE_SECURE_COMM__
        if (!tapClientInfo.enableunsecurecomms || tapCleanupCertStore)
        {
            if (!tapClientInfo.isNonFsMode)
            {
                /* Cleanup SSL certificates */
                if (OK != (status = TAP_CONF_COMMON_freeCertStore(&tapClientInfo)))
                {
                    DB_PRINT("Error %d freeing certificate store\n", (int)status);
                }
            }

            /* Clean up SSL stack */
            SSL_releaseTables();
            status = SSL_shutdownStack();
        }
        tapCleanupCertStore = 0;
        if (OK != (status = TAP_CONF_COMMON_freeCertFilenameBuffers(&tapClientInfo)))
        {
            DB_PRINT("Error %d freeing certificate filename buffers\n", (int)status);
        }

#endif
        tapRemoteInitDone = 0;
    }

    return status;
}

extern MSTATUS
TAP_OpenSession(TAP_SessionInfo *pSessionInfo)
{
    MSTATUS status = OK;
    MOC_IP_ADDRESS serverMOCIP = {0};
    char serverIP[20];
    ubyte4 ipv4Addr = 0;
    TCP_SOCKET sc = {0};
#ifdef __ENABLE_SECURE_COMM__
    int connectionInstance = 0;
#endif
    TAP_ConnectionInfo *pConnInfo = NULL;
    sbyte *pServerName = NULL;

    if (NULL == pSessionInfo)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    
    pConnInfo = &pSessionInfo->connInfo;

    /* Handle default values from tapc.conf file if user does not specify connection information */
    if (!pConnInfo->serverPort)
        pConnInfo->serverPort = tapClientInfo.serverPort;
    
    if (pConnInfo->serverName.bufferLen && pConnInfo->serverName.pBuffer)
        pServerName = (sbyte *)pConnInfo->serverName.pBuffer;

    if (!pServerName)
        pServerName = tapClientInfo.pServerName;

#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
    if(TAP_UNIX_DOMAIN_SOCKET == pConnInfo->serverPort )
    {
        if (!pServerName)
            pServerName = DEFAULT_UNIX_DOMAIN_PATH;

        if(OK > (status = UNIXDOMAIN_CONNECT(&sc, pServerName)))
        {
            DB_PRINT("%s.%d: Unable to connect to TPM Server domain socket\n", __FUNCTION__,
                __LINE__);
            goto exit;
        }
        tapClientInfo.enableunsecurecomms = 1;
        pSessionInfo->sockfd = sc;
        pSessionInfo->sslSessionId = 0;
        pSessionInfo->sessionInit = 1;
        goto exit;
    }
#endif
    /* Establish connection */
    if (OK > (status = UDP_init()))
        goto exit;

    if (OK > (status = UDP_getAddrOfHost(pServerName, &serverMOCIP)))
    {
        DB_PRINT("%s.%d: Unable to resolve Remote TPM Server address\n", __FUNCTION__,
            __LINE__);
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_IPV6__
    inet_ntop(AF_INET, &(serverMOCIP.uin.addr), serverIP, sizeof(serverIP));
#else
    ipv4Addr = ntohl(serverMOCIP);
    inet_ntop(AF_INET, &(ipv4Addr), serverIP, sizeof(serverIP));
#endif
    if ( OK > (status = TCP_CONNECT(&sc, (sbyte *)serverIP, pConnInfo->serverPort)))
    {
        DB_PRINT("%s.%d: Unable to establish TCP connection with %s on port %d\n", __FUNCTION__,
                __LINE__, serverIP, (int)pConnInfo->serverPort);
    }
    else 
    {
#ifdef __ENABLE_SECURE_COMM__
        if (!tapClientInfo.enableunsecurecomms)
        {
        if (OK > (connectionInstance = SSL_connect(sc, 0,
                            NULL, 
                            NULL, 
                            (const sbyte *)pConnInfo->serverName.pBuffer, 
                            tapClientInfo.pSslCertStore))) 
            {
                DB_PRINT("%s.%d: Unable to establish SSL connection with %s on port %d\n", __FUNCTION__,
                        __LINE__, pConnInfo->serverName.pBuffer, (int)pConnInfo->serverPort);
                TCP_CLOSE_SOCKET(sc);
            }
            else 
            {
                if (OK > (status = SSL_setServerNameIndication(connectionInstance, 
                                (const char *)pConnInfo->serverName.pBuffer)))
                {
                    DB_PRINT("%s.%d: Unable to establish SSL server name indication, error %d\n", __FUNCTION__,
                            __LINE__, (int)status);
                    SSL_closeConnection(connectionInstance);
                    TCP_CLOSE_SOCKET(sc);
                }
                else 
                {
                    if (OK > (status = SSL_negotiateConnection(connectionInstance)))
                    {
                        DB_PRINT("%s.%d: Unable to negotiate SSL connection, error %d\n", __FUNCTION__,
                                __LINE__, (int)status);
                        SSL_closeConnection(connectionInstance);
                        TCP_CLOSE_SOCKET(sc);
                    }
                    else 
                    {
                        /* Connection is open */
                        pSessionInfo->sockfd = sc;
                        pSessionInfo->sslSessionId = connectionInstance;
                        pSessionInfo->sessionInit = 1;

                        /* get the session info before closing the connection (SSL_closeConnection destroys SSLSocket) */
                        /* SSL_getClientSessionInfo( connectionInstance, &sessionIdLen, sessionId, masterSecret); */
                    }
                }
            }
        }
        else
#endif
        {
            /* Connection is open */
            pSessionInfo->sockfd = sc;
            pSessionInfo->sslSessionId = 0;
            pSessionInfo->sessionInit = 1;
        }
    }

exit:
    return status;
}

extern MSTATUS 
TAP_CloseSession(TAP_SessionInfo *pSessionInfo)
{
    MSTATUS status = OK;
#ifdef __ENABLE_TAP_REMOTE_TCP_CLOSE_MSG__
    sbyte reqHdrBuffer[sizeof(TAP_CmdReqHdr)] = { 0 };
    ubyte4 bytesWritten = 0;
#endif
#ifdef __ENABLE_TAP_REMOTE_UNIX_DOMAIN__
    TAP_ConnectionInfo *pConnInfo = NULL;
#endif

    if (NULL == pSessionInfo)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#ifdef __ENABLE_TAP_REMOTE_TCP_CLOSE_MSG__
    if (tapClientInfo.enableunsecurecomms)
    {
        (void) TCP_WRITE_ALL(
            pSessionInfo->sockfd, reqHdrBuffer, sizeof(reqHdrBuffer), &bytesWritten);
    }
#endif
#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
    pConnInfo = &pSessionInfo->connInfo;
    if(TAP_UNIX_DOMAIN_SOCKET == pConnInfo->serverPort)
    {
        UNIXDOMAIN_CLOSE(pSessionInfo->sockfd);
        pSessionInfo->sessionInit = 0;
        goto exit;
    }
#endif
#ifdef __ENABLE_SECURE_COMM__
    if (!tapClientInfo.enableunsecurecomms)
    {
        /* Close connection */
        SSL_closeConnection(pSessionInfo->sslSessionId);
    }
#endif

    UDP_shutdown();
    /* Close socket */
    TCP_CLOSE_SOCKET(pSessionInfo->sockfd);

    pSessionInfo->sessionInit = 0;

exit:
    return status;
}


extern MSTATUS 
TAP_TransmitReceive(TAP_SessionInfo *pSessionInfo, 
        TAP_CmdReqHdr *pReqHdr,
        ubyte4 txBufferLen, ubyte *pTxBuffer,
        ubyte4 *pRxBufferLen, ubyte *pRxBuffer,
        MSTATUS *pRetCode)
{
    MSTATUS status = OK;
    TAP_CmdRspHdr rspHdr = {0};
    ubyte4 byteCount = 0;
    sbyte rspHdrBuffer[sizeof(TAP_CmdRspHdr)];
    ubyte4 bytesXmitted = 0;
    ubyte4 offset = 0;
    sbyte reqHdrBuffer[sizeof(TAP_CmdReqHdr)];
#ifdef __ENABLE_SECURE_COMM__
    ubyte4 rc = 0;
#endif

    if ((NULL == pRxBuffer) || (NULL == pTxBuffer) ||
            (0 == txBufferLen) || (NULL == pRxBufferLen) ||
            (NULL == pReqHdr) || (NULL == pRetCode))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pSessionInfo)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if ((pReqHdr->cmdType != TAP_CMD_TYPE_TAP) && (pReqHdr->cmdType != TAP_CMD_TYPE_SMP))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    if ((pReqHdr->cmdDest != TAP_CMD_DEST_MODULE) && (pReqHdr->cmdDest != TAP_CMD_DEST_SERVER))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Verify connection */
    if (0 == pSessionInfo->sessionInit)
    {
        status = ERR_TAP_INVALID_SESSION;
        goto exit;
    }

    pReqHdr->totalBytes = sizeof(TAP_CmdReqHdr) + txBufferLen;

    /* Serialize command header */
    offset = 0;
    status = TAP_SERIALIZE_serialize(&TAP_REMOTE_SHADOW_TAP_CmdReqHdr, TAP_SD_IN,
            (ubyte *)pReqHdr, sizeof(TAP_CmdReqHdr),
            (void *)reqHdrBuffer, sizeof(reqHdrBuffer), &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Command header serialize error, status %d", __FUNCTION__,
                __LINE__, (int)status);
    }

#ifdef __ENABLE_SECURE_COMM__
    if (!tapClientInfo.enableunsecurecomms)
    {
        /* Send command header */
        if (sizeof(reqHdrBuffer) != (rc = SSL_send(pSessionInfo->sslSessionId, (sbyte *)reqHdrBuffer,
                        sizeof(reqHdrBuffer))))
        {
            status = ERR_TCP_WRITE_ERROR;
            DB_PRINT("%s.%d: SSL_send error xmitting cmd header, status %d, sent %d, expected %d", __FUNCTION__,
                    __LINE__, (int)status, rc, sizeof(reqHdrBuffer));
            goto exit;
        }

        /* Send command */
        if (txBufferLen != (rc = SSL_send(pSessionInfo->sslSessionId, (sbyte *)pTxBuffer,
                        txBufferLen)))
        {
            status = ERR_TCP_WRITE_ERROR;
            DB_PRINT("%s.%d: SSL_send error, xmitting cmd status %d, sent %d, expected %d", __FUNCTION__,
                    __LINE__, (int)status, rc, txBufferLen);
            goto exit;
        }

        /* Receive response */
        if (OK != (status = SSL_recv(pSessionInfo->sslSessionId,
                        rspHdrBuffer,
                        sizeof(rspHdrBuffer),
                        (sbyte4 *)&byteCount,
                        0)))
        {
            DB_PRINT("%s.%d: SSL_recv error, status %d", __FUNCTION__,
                    __LINE__, (int)status);
            goto exit;
        }

        if (byteCount != sizeof(rspHdrBuffer))
        {
            DB_PRINT("%s.%d: Response header size mismatch, expecting %d, received %d\n", __FUNCTION__,
                    __LINE__, (int)sizeof(rspHdrBuffer), (int)byteCount);
            goto exit;
        }

        /* Deserialize response header */
        offset = 0;
        status = TAP_SERIALIZE_serialize(&TAP_REMOTE_SHADOW_TAP_CmdRspHdr, TAP_SD_OUT,
                (ubyte *)rspHdrBuffer, byteCount,
                (void *)&rspHdr, sizeof(rspHdr), &offset);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to serialize TAP_CmdRspHdr, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (rspHdr.totalBytes >= byteCount)
        {
            rspHdr.totalBytes -= byteCount;

            /* Make sure caller has passed large enough buffer */
            if (rspHdr.totalBytes > *pRxBufferLen)
            {
                DB_PRINT("%s.%d Error insufficient buffer length, need %d, given %d bytes\n", 
                        __FUNCTION__, __LINE__, rspHdr.totalBytes, *pRxBufferLen);
                status = ERR_BAD_LENGTH;
                goto exit;
            }

            /* Some commands may not have a response, just pick the header and leave */
            if (rspHdr.totalBytes)
            {
                /* Read the rest of the response */
                if (OK != (status = SSL_recv(pSessionInfo->sslSessionId,
                                (sbyte *)pRxBuffer,
                                rspHdr.totalBytes,
                                (sbyte4 *)pRxBufferLen,
                                0)))
                {
                    DB_PRINT("%s.%d: SSL_recv returned status %d", __FUNCTION__,
                            __LINE__, (int)status);
                    goto exit;
                }
            }
            else
            {
                /* Return error code from response header for commands 
                   that do not have a response */
                *pRetCode = rspHdr.cmdStatus;
                *pRxBufferLen = 0;
            }
        }
        else
        {
            status = ERR_BAD_LENGTH; 
        }
    }
    else
#endif
    {
        /* Send command header */
        if (OK != (status = TCP_WRITE_ALL(pSessionInfo->sockfd, (sbyte *)reqHdrBuffer,
                        sizeof(reqHdrBuffer), &bytesXmitted)))
        {
            DB_PRINT("%s.%d: socket write error sending command, status %d", __FUNCTION__,
                    __LINE__, (int)status);
            goto exit;
        }

        /* Send command */
        if (OK != (status = TCP_WRITE_ALL(pSessionInfo->sockfd,
                        (sbyte *)pTxBuffer,
                        txBufferLen,
                        &bytesXmitted)))
        {
            DB_PRINT("%s.%d: socket write error, sending %d bytes, sent %d", __FUNCTION__,
                    __LINE__, (int)txBufferLen, bytesXmitted);
        }

        /* Receive response header */
        if (OK != (status = TCP_READ_ALL(pSessionInfo->sockfd, rspHdrBuffer, sizeof(rspHdrBuffer), &byteCount,
                        0)))
        {
            DB_PRINT("%s.%d: Error reading TAP response header, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            /* Drop connection and exit */
            goto exit;
        }

        if (byteCount != sizeof(rspHdrBuffer))
        {
            DB_PRINT("%s.%d: Response header size mismatch, expecting %d, received %d\n", __FUNCTION__,
                    __LINE__, (int)sizeof(rspHdrBuffer), (int)byteCount);
            goto exit;
        }

        /* Deserialize response header */
        offset = 0;
        status = TAP_SERIALIZE_serialize(&TAP_REMOTE_SHADOW_TAP_CmdRspHdr, TAP_SD_OUT,
                (ubyte *)rspHdrBuffer, byteCount,
                (void *)&rspHdr, sizeof(rspHdr), &offset);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to serialize TAP_CmdRspHdr, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (rspHdr.totalBytes >= byteCount)
        {
            rspHdr.totalBytes -= byteCount;

            /* Make sure caller has passed large enough buffer */
            if (rspHdr.totalBytes > *pRxBufferLen)
            {
                DB_PRINT("%s.%d Error insufficient buffer length, need %d, given %d bytes\n", 
                        __FUNCTION__, __LINE__, rspHdr.totalBytes, *pRxBufferLen);
                status = ERR_BAD_LENGTH;
                goto exit;
            }

            /* Some commands may not have a response, just pick the header and leave */
            if (rspHdr.totalBytes)
            {
                /* Read the rest of the response */
                if (OK != (status = TCP_READ_ALL(pSessionInfo->sockfd, 
                                (sbyte *)pRxBuffer, 
                                rspHdr.totalBytes, 
                                pRxBufferLen,
                                0)))
                {
                    DB_PRINT("%s.%d: Error reading TAP response payload, status %d = %s\n", __FUNCTION__,
                            __LINE__, status, MERROR_lookUpErrorCode(status));
                    /* Drop connection and exit */
                    goto exit;
                }
            }
            else
            {
                /* Return error code from response header for commands 
                   that do not have a response */
                *pRetCode = rspHdr.cmdStatus;
                *pRxBufferLen = 0;
            }
        }
        else
        {
            status = ERR_BAD_LENGTH; 
        }
    }

exit:
    return status;
}

#endif   /* __ENABLE_TAP_REMOTE__ */

#endif
