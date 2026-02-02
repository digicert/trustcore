/*  tcti_win.c
 *
 *  This file contains the windows implementation of the TCTI layer
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

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))

#if defined(__RTOS_WIN32__)
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tbs.h>

#include "../../../../common/mtypes.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "tcti.h"
#include "tcti_os.h"
#include "../tpm_common/tpm_error_utils.h"

#define MUTEX_NAME_GLOBAL_NAMEPSPACE     "Global\\"

#define TCTI_WIN_MUTEX_TIMEOUT_SEC      5
#define TCTI_WIN_MAX_MUTEX_NAME_SIZE    256
#define TCTI_WIN_MAX_DEVICE_NAME_SIZE   256

/* Connection Type for TPM communication on Windows */
typedef ubyte TCTI_CONNECTION_TYPE;
#define TCTI_CONNECTION_TYPE_EMULATOR   1
#define TCTI_CONNECTION_TYPE_DEVICE     2

static const char*  pDefaultDeviceName      = "localhost";
static const char*  pDefaultMutexName       = "Global\\MOCANA_TCTI_REMOTE_MUTEX";
static const char*  pDefaultSimulatorMutex  = "Global\\MOCANA_TCTI_SIMULATOR_MUTEX";
static const char*  pDefaultSimulatorName   = "localhost";
static const ubyte2 defaultSimulatorPort    = 2321;


/* Context info for TPM emulator on windows */
typedef struct {
    /* Mutex details */
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    RTOS_GLOBAL_MUTEX tpmMutex;
    char mutexName[TCTI_WIN_MAX_MUTEX_NAME_SIZE];
#endif
    /* Connection details */
    ubyte2 port;
    char deviceName[TCTI_WIN_MAX_DEVICE_NAME_SIZE];

    SOCKET hSocket;
} TCTI_WIN_EMULATOR_CONTEXT_INFO;

/* Context info for TPM device on windows */
typedef struct {
    /* Windows TPM Context object handle */
    TBS_HCONTEXT hContext;
} TCTI_WIN_DEVICE_CONTEXT_INFO;

typedef union
{
    TCTI_WIN_DEVICE_CONTEXT_INFO    deviceContextInfo;
    TCTI_WIN_EMULATOR_CONTEXT_INFO  emulatorContextInfo;
} TCTI_WIN_CONTEXT_INFO;

typedef struct {
    /* Connection Type*/
    TCTI_CONNECTION_TYPE            connectionType;
    /* Context type is dependent on connectionType */
    TCTI_WIN_CONTEXT_INFO  contextInfo;
} TCTI_WIN_CONTEXT;



/****************************************************************************/

static TSS2_RC TCTI_WIN_openSocket(
        const char *pServerName,
        ubyte2 serverPort,
        SOCKET *pFd
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SOCKET fd = INVALID_SOCKET;
    struct hostent *pHost = NULL;
    struct sockaddr_in addr = { 0 };
    WSADATA wsaData = {0};
    int socketResult = NO_ERROR;

    if (!pServerName || !pFd)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    socketResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (NO_ERROR != socketResult)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d WSAStartup failed with error %d. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, socketResult, rc, tss2_err_string(rc));
        goto exit;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (INVALID_SOCKET != fd)
    {
        pHost = gethostbyname((const char *)pServerName);
        if (NULL == pHost)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("[MAJOR] open_device: Failed to connect to device %s. Errno %d = %s\n",
                    pServerName, rc, tss2_err_string(rc));
            goto exit;
        }

        addr.sin_family = pHost->h_addrtype;
        addr.sin_port   = htons(serverPort);
        memcpy(&addr.sin_addr, pHost->h_addr, pHost->h_length);
        if (SOCKET_ERROR == connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("[MAJOR] open_device: Failed to connect to device %s. Errno %d = %s\n",
                    pServerName, errno, strerror(errno));
            goto exit;
        }
    }

    *pFd = fd;
    rc = TSS2_RC_SUCCESS;

exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (INVALID_SOCKET != fd)
        {
            closesocket(fd);
        }
        WSACleanup();
    }

    return rc;
}


static TSS2_RC TCTI_WIN_closeSocket(SOCKET *pFd)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (NULL == pFd)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (INVALID_SOCKET != *pFd)
    {
        if (SOCKET_ERROR == closesocket(*pFd))
        {
            rc = TSS2_FAPI_RC_IO_ERROR;
            DB_PRINT("[MAJOR] close_socket: Failed to close\n");
            goto exit;       
        }
        if (SOCKET_ERROR == WSACleanup())
        {
            rc = TSS2_FAPI_RC_IO_ERROR;
            DB_PRINT("%s.%d WSACleanup failed with error - %d. rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, WSAGetLastError(), rc, tss2_err_string(rc));
            goto exit;
        }

        *pFd = INVALID_SOCKET;
    }

    rc = TSS2_RC_SUCCESS;

exit:
    return rc;
}


static void TCTI_WIN_replaceSlashFromString(char *pString)
{
    char *pRunner = pString;
    if (pRunner)
    {
        while (*pRunner)
        {
            if (('/' == *pRunner))
                *pRunner = 'z';
            pRunner++;
        }
    }
    return;
}

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
static TSS2_RC TCTI_WIN_getMutexName(
        ubyte *pServerName, ubyte4 serverNameLen, 
        char *pMutexName, ubyte4 pMutexNameLen
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pMutexName || (0 == pMutexNameLen) 
            || !pServerName || (0 == serverNameLen))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((DIGI_STRLEN(MUTEX_NAME_GLOBAL_NAMEPSPACE) + serverNameLen) >
            pMutexNameLen)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Insufficient buffer size for mutex name. "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    /* Copy Global namepsace string */
    DIGI_STRCBCPY((void *)pMutexName, pMutexNameLen,  
                (const sbyte*)MUTEX_NAME_GLOBAL_NAMEPSPACE);
    
    /* concatenate server-name */
    DIGI_STRCAT((void *)pMutexName, (void *)pServerName);
    
    TCTI_WIN_replaceSlashFromString(pMutexName);

    rc = TSS2_RC_SUCCESS;

exit:
    return rc;
}
#endif


/****************************************************************************/

TSS2_RC TCTI_WIN_openDevice(TBS_HCONTEXT* pDeviceContext)
{
    TSS2_RC  rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TBS_RESULT tbsResult;
    TBS_CONTEXT_PARAMS2 tbsContextParams = {
                                            .version = TBS_CONTEXT_VERSION_TWO,
                                            .includeTpm12 = 0,
                                            .includeTpm20 = 1,
                                        };

    tbsResult = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&tbsContextParams, pDeviceContext);
    if (TBS_SUCCESS != tbsResult)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("[MAJOR] open_device: Error 0x%08x creating TBS context\n",
                (unsigned int)tbsResult);
        goto exit;
    }
    
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}


/****************************************************************************/

TSS2_RC TCTI_WIN_closeDevice(TBS_HCONTEXT* pDeviceContext)
{
    TSS2_RC  rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TBS_RESULT tbsResult = TBS_SUCCESS;

    if (NULL == pDeviceContext || NULL == *pDeviceContext)
    {
        rc = TSS2_TCTI_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid context references, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    tbsResult = Tbsip_Context_Close(*pDeviceContext);
    if (TBS_SUCCESS != tbsResult) 
    {
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
        goto exit;
    }

    *pDeviceContext = NULL;
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/****************************************************************************/

TSS2_RC TCTI_WIN_emulatorContextInit(TctiContextInitIn *pIn, 
                                    TCTI_WIN_EMULATOR_CONTEXT_INFO *pEmulatorContextInfo)
{
    TSS2_RC             rc = TSS2_SYS_RC_GENERAL_FAILURE;
    const char*         pMutexName = NULL;
    const char*         pDeviceName = NULL;
    ubyte2              port = 0;

    /* Set device and port */
    pDeviceName = (const char *)(pIn->pServerName);

    port = (0 == pIn->serverPort) ? defaultSimulatorPort: 
                                                pIn->serverPort;
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    /* Get mutex name from server/port */
    rc = TCTI_WIN_getMutexName((ubyte *)pIn->pServerName, pIn->serverNameLen,
                                pEmulatorContextInfo->mutexName,
                                sizeof(pEmulatorContextInfo->mutexName));
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get mutex name for device, rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pMutexName = pEmulatorContextInfo->mutexName;

    /* Create the mutex */
    if (OK != RTOS_globalMutexCreate((char *)pMutexName, 
                        &pEmulatorContextInfo->tpmMutex))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to create/get reference to TPM mutex, "
                "rc 0x%02x = %s, errno-%d\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc), errno);
        goto exit;
    }

    if (OK != DIGI_MEMCPY((void *)pEmulatorContextInfo->mutexName, pMutexName,
        DIGI_STRLEN((const sbyte*)pMutexName)))
    {
        DB_PRINT("%s.%d Memcpy failed, rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif
    rc = TCTI_WIN_openSocket((const char *)pDeviceName, port,
        &pEmulatorContextInfo->hSocket);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to open socket, rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
    * For emulator, close the file descriptor. For some reason, opening
    * and closing the file descriptor, works faster than keeping the socket open.
    * For emulator, socket is opened and closed during transmit-recieve.
    */
    if (!gShouldReuseContext)
    {
        TCTI_WIN_closeSocket(&pEmulatorContextInfo->hSocket);
    }

    if (OK != DIGI_MEMCPY((void *)pEmulatorContextInfo->deviceName, pDeviceName,
            DIGI_STRLEN((const sbyte*)pDeviceName)))
        {
            DB_PRINT("%s.%d Memcpy failed, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    pEmulatorContextInfo->port = port;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/****************************************************************************/

TSS2_RC TCTI_WIN_emulatorContextUninit(TCTI_WIN_EMULATOR_CONTEXT_INFO *pEmulatorContextInfo)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (pEmulatorContextInfo->hSocket)
    {
        rc = TCTI_WIN_closeSocket(&pEmulatorContextInfo->hSocket);
    }

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    if (pEmulatorContextInfo->tpmMutex)
    {
        RTOS_globalMutexFree((char *)pEmulatorContextInfo->mutexName,
            &pEmulatorContextInfo->tpmMutex);
    }
#endif

exit:
    return rc;
}

TSS2_RC TCTI_WIN_deviceContextInit(TctiContextInitIn *pIn, TCTI_WIN_DEVICE_CONTEXT_INFO *pDeviceContextInfo)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    /*
    * Open the TPM device on windows only once in the beginning.
    * Do not close it, as the windows device driver needs to be communicated
    * with using same open context.
    */
    /* Check if device is already open */
    if (NULL != pDeviceContextInfo->hContext)
    {
        DB_PRINT("%s.%d TPM device already initialized\n",
            __FUNCTION__, __LINE__);
        rc = TSS2_RC_SUCCESS;
        goto exit;
    }

    rc = TCTI_WIN_openDevice(&(pDeviceContextInfo->hContext));
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to open device, rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

exit:
    return rc;
}


/****************************************************************************/

TSS2_RC TCTI_WIN_deviceContextUninit(TCTI_WIN_DEVICE_CONTEXT_INFO *pDeviceContextInfo)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    rc = TCTI_WIN_closeDevice(&(pDeviceContextInfo->hContext));
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to close device, rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

exit:
    return rc;
}

/****************************************************************************/

TSS2_RC TCTI_WIN_contextUnint(void **ppTctiOsContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TCTI_WIN_CONTEXT *pContextToFree = NULL;

    if (!ppTctiOsContext || !*ppTctiOsContext)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pContextToFree = (TCTI_WIN_CONTEXT *)(*ppTctiOsContext);
    
    switch (pContextToFree->connectionType)
    {
        case TCTI_CONNECTION_TYPE_DEVICE:
            rc = TCTI_WIN_deviceContextUninit(&(pContextToFree->contextInfo.deviceContextInfo));
            break;
        case TCTI_CONNECTION_TYPE_EMULATOR:
        default:
            rc = TCTI_WIN_emulatorContextUninit(&(pContextToFree->contextInfo.emulatorContextInfo));
            break;
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Context Uninitialization failed. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    
    
    rc = TSS2_RC_SUCCESS;
exit:
    DIGI_FREE(ppTctiOsContext);
    return rc;
}


/****************************************************************************/

TSS2_RC TCTI_WIN_contextInit(TctiContextInitIn *pIn, void **ppTctiOsContext)
{
    TSS2_RC             rc      = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS             status  = ERR_GENERAL;
    TCTI_WIN_CONTEXT*   pNewContext = NULL;

    if (!pIn || !ppTctiOsContext || *ppTctiOsContext ||
        (pIn->serverNameLen > TCTI_WIN_MAX_DEVICE_NAME_SIZE))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pNewContext, 1, sizeof(*pNewContext)))
    {
        rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Could not allocate memory for Windows TCTI"
            "context, rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* If servername is not provided, use default device, else emulator */
    pNewContext->connectionType = 
        (!pIn->pServerName || (0 == pIn->serverNameLen)) ? 
            TCTI_CONNECTION_TYPE_DEVICE : TCTI_CONNECTION_TYPE_EMULATOR;

    switch (pNewContext->connectionType)
    {
        case TCTI_CONNECTION_TYPE_DEVICE:
            rc = TCTI_WIN_deviceContextInit(pIn, 
                    &pNewContext->contextInfo.deviceContextInfo);
            break;
        case TCTI_CONNECTION_TYPE_EMULATOR:
        default:
            rc = TCTI_WIN_emulatorContextInit(pIn, 
                    &pNewContext->contextInfo.emulatorContextInfo);
            break;
    }
    *ppTctiOsContext = pNewContext;

exit:
    if (pNewContext && (rc != TSS2_RC_SUCCESS))
    {
        TCTI_WIN_contextUnint((void **)&pNewContext);
    }

    return rc;
}


/****************************************************************************/

TSS2_RC TCTI_WIN_emulatorTransmitRecieve(
                TCTI_WIN_EMULATOR_CONTEXT_INFO *pEmulatorContextInfo, 
                TctiTransmitRecieveIn *pIn, TctiTransmitRecieveOut *pOut)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte locality = 0;
    ubyte4 tpmSendCommand = 0;
    ubyte4 length = 0;
    ubyte4 ret = 0;
    int numBytes = 0;
    byteBoolean releaseMutex = FALSE;
    byteBoolean closeSocket = FALSE;
    ubyte4 returnlength = 0;
    ubyte4 acknowledgement = 0;

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    if (OK != RTOS_globalMutexWait(pEmulatorContextInfo->tpmMutex, 
                                    TCTI_WIN_MUTEX_TIMEOUT_SEC))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Mutex wait failed. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    releaseMutex = TRUE;
#endif

    /*
     * Open and connect to socket, since we close socket for the emulator
     * during context init.
     */
    rc = TCTI_WIN_openSocket((const char *)pEmulatorContextInfo->deviceName,
                            pEmulatorContextInfo->port, 
                            &pEmulatorContextInfo->hSocket);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to open socket, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    closeSocket = gShouldReuseContext ? FALSE : TRUE;

    /* Write emulator specific messages */
    tpmSendCommand = htonl(0x8);
    length = htonl(pIn->transmitBufLen);

    ret = send(pEmulatorContextInfo->hSocket, 
                (const char*)&tpmSendCommand, sizeof(ubyte4),0);
    if (ret == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }
    ret = send(pEmulatorContextInfo->hSocket, 
                &locality, sizeof(ubyte),0);
    if (ret == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }
    ret = send(pEmulatorContextInfo->hSocket,
                (const char*)&length, sizeof(ubyte4),0);
    if (ret == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }

    /* Write the actual transmit buffer */
    numBytes = send(pEmulatorContextInfo->hSocket, 
                    pIn->pTransmitBuf, pIn->transmitBufLen,0);
    if (numBytes != pIn->transmitBufLen)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to write all commands bytes.. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    ret = recv(pEmulatorContextInfo->hSocket,
                (ubyte *)&returnlength, sizeof(ubyte4),0);
    if (ret == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }
    returnlength = ntohl(returnlength);

    numBytes = recv(pEmulatorContextInfo->hSocket,
                    pIn->pReceiveBuf, returnlength,0);
    if (numBytes == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }

    ret = recv(pEmulatorContextInfo->hSocket,
                (ubyte *)&acknowledgement, sizeof(ubyte4),0);
    if (ret == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }

    acknowledgement = ntohl(acknowledgement);

    pOut->recievedLen = returnlength;
    rc = TSS2_RC_SUCCESS;

exit:
    if (TRUE == closeSocket)
    {
        TCTI_WIN_closeSocket(&pEmulatorContextInfo->hSocket);
    }
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    if (TRUE == releaseMutex)
    {
        RTOS_globalMutexRelease(pEmulatorContextInfo->tpmMutex);
    }
#endif
    return rc;
}


/****************************************************************************/


TSS2_RC TCTI_WIN_deviceTransmitRecieve(
                        TCTI_WIN_DEVICE_CONTEXT_INFO *pDeviceContextInfo, 
                        TctiTransmitRecieveIn *pIn, 
                        TctiTransmitRecieveOut *pOut)
{
    TSS2_RC             rc = TSS2_TCTI_RC_IO_ERROR;
    int                 numBytes;
    TBS_RESULT          tbsResult;

    if (NULL == pDeviceContextInfo->hContext)
    {
        rc = TSS2_TCTI_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to open device, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    numBytes = pIn->receiveBufLen;
    tbsResult = Tbsip_Submit_Command(pDeviceContextInfo->hContext,
                                     TBS_COMMAND_LOCALITY_ZERO, 
                                     TBS_COMMAND_PRIORITY_NORMAL,
                                     pIn->pTransmitBuf, 
                                     pIn->transmitBufLen,
                                     pIn->pReceiveBuf,
                                     (UINT32*)&numBytes);
    if (TBS_SUCCESS != tbsResult)
    {
        DB_PRINT("[MAJOR] Tbsip_Submit_Command: failed with error code "
                "0x%08x\n", (unsigned int)tbsResult);
        goto exit;
    }

    if (0 > numBytes)
    {
        DB_PRINT("%s.%d Failed to read from device. rc 0x%02x = %s\n",
                 __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        rc = TSS2_TCTI_RC_IO_ERROR;
        goto exit;
    }
    else if (0 == numBytes)
    {
        rc = TSS2_TCTI_RC_IO_ERROR;
        DB_PRINT("%s.%d Zero bytes read from device. rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (numBytes > pIn->receiveBufLen)
    {
        rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Read %d bytes from device, but only have room for %d. rc 0x%02x = %s\n",
            __FUNCTION__, __LINE__, numBytes, pIn->receiveBufLen, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->recievedLen = numBytes;
    rc = TSS2_RC_SUCCESS;

exit:
    return rc;
}


/****************************************************************************/

TSS2_RC TCTI_WIN_transmitRecieve(void *pTctiOsCtx, TctiTransmitRecieveIn *pIn, TctiTransmitRecieveOut *pOut)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TCTI_WIN_CONTEXT *pContext = NULL;

    if (!pTctiOsCtx || !pIn || !pOut ||
            (!pIn->pTransmitBuf) || (0 == pIn->transmitBufLen) ||
            (!pIn->pReceiveBuf) || (0 == pIn->receiveBufLen))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pContext = (TCTI_WIN_CONTEXT *)pTctiOsCtx;
    switch (pContext->connectionType)
    {
        case TCTI_CONNECTION_TYPE_DEVICE:
            rc = TCTI_WIN_deviceTransmitRecieve(
                            &(pContext->contextInfo.deviceContextInfo),
                            pIn, pOut);
            break;
        case TCTI_CONNECTION_TYPE_EMULATOR:
        default:
            rc = TCTI_WIN_emulatorTransmitRecieve(
                            &(pContext->contextInfo.emulatorContextInfo),
                            pIn, pOut);
            break;
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Transmit-Receive Failed. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

exit:
    return rc;
}


/****************************************************************************/

TCTI_OS_OPS tcti_win_ops = {
        .contextInit = TCTI_WIN_contextInit,
        .contextUnint = TCTI_WIN_contextUnint,
        .transmitRecieve = TCTI_WIN_transmitRecieve,
};

#endif /* __RTOS_WIN32__ */
#endif /* __ENABLE_DIGICERT_TPM2__ */
