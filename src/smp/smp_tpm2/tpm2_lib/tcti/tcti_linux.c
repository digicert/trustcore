/*  tcti_linux.c
 *
 *  This file contains the linux implementation of the TCTI layer
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


#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "../../../../common/mtypes.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "tcti.h"
#include "tcti_os.h"
#include "../tpm_common/tpm_error_utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/un.h>

#define TCTI_LINUX_MUTEX_TIMEOUT_SEC 5
#define TCTI_LINUX_MAX_MUTEX_NAME_SIZE 256
#define TCTI_LINUX_MAX_DEVICE_NAME_SIZE 256
static const char *pDefaultDeviceName = "/dev/tpm0";
static const char *pDefaultMutexName = "/MOCANA_DEV_TPM0";
static const char *pDefaultSimulatorMutex = "/MOCANA_SIM_TPM";
static const char *pDefaultSimulatorName = "localhost";
static const ubyte2 defaultSimulatorPort = 6543;

typedef struct {
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    RTOS_GLOBAL_MUTEX tpmMutex;
    char mutexName[TCTI_LINUX_MAX_MUTEX_NAME_SIZE];
#endif
    int deviceFileDesc;
    ubyte2 port;
    char deviceName[TCTI_LINUX_MAX_DEVICE_NAME_SIZE];
    byteBoolean isSocketFd;
    byteBoolean isEmulator;
} TCTI_LINUX_CONTEXT;

static void TCTI_LINUX_replaceSlashFromString(char *pString)
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
static TSS2_RC TCTI_LINUX_getMutextNameFromServerName(
        ubyte *pServerName, ubyte4 serverNameLen, char *pMutexName,
        ubyte4 pMutexNameLen
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pMutexName || (0 == pMutexNameLen) || !pServerName || (0 == serverNameLen)
            || (serverNameLen > pMutexNameLen))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMCPY((void *)pMutexName, (void *)pServerName, serverNameLen))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Cannot copy memory. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TCTI_LINUX_replaceSlashFromString(pMutexName);

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif

static TSS2_RC TCTI_LINUX_openSocket(
        const char *pServerName,
        ubyte2 serverPort,
        int *pFd
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    int fd = -1;
    struct hostent *pHost = NULL;
    struct sockaddr_in addr = { 0 };

    if (!pServerName || !pFd)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0)
    {
        pHost = gethostbyname((const char *)pServerName);
        if (NULL != pHost)
        {
            addr.sin_family = pHost->h_addrtype;
            addr.sin_port   = htons(serverPort);
            memcpy(&addr.sin_addr, pHost->h_addr, pHost->h_length);
            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            {
                DB_PRINT("[MAJOR] open_device: Failed to connect to device %s. Errno %d = %s\n",
                        pServerName, errno, strerror(errno));
                goto exit;
            }
        }
    }

    *pFd = fd;
    rc = TSS2_RC_SUCCESS;
exit:
    if ((TSS2_RC_SUCCESS != rc) && (fd >= 0))
        close(fd);
    return rc;
}

static TSS2_RC TCTI_LINUX_openDevice(
        const char *pServerName,
        int *pFd
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    int fd = -1;

    if (NULL == pFd)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        goto exit;
    }

    fd = open((char *)(pServerName), O_RDWR);
    if (-1 == fd)
    {
        DB_PRINT("[MAJOR] Failed to open device.  Errno %d = %s\n", errno, strerror(errno));
        goto exit;
    }

    *pFd = fd;
    rc = TSS2_RC_SUCCESS;
exit:
    if ((TSS2_RC_SUCCESS != rc) && (fd >= 0))
        close(fd);
    return rc;
}

static void TCTI_LINUX_closeFD(int *pFd)
{
    if (NULL != pFd && 0 != *pFd)
    {
        close(*pFd);
        *pFd= 0;
    }
}

TSS2_RC TCTI_LINUX_contextUnint(void **ppTctiOsContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TCTI_LINUX_CONTEXT *pContextToFree = NULL;

    if (!ppTctiOsContext || !*ppTctiOsContext)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pContextToFree = (TCTI_LINUX_CONTEXT *)(*ppTctiOsContext);

    if (pContextToFree->deviceFileDesc)
    {
        TCTI_LINUX_closeFD(&(pContextToFree->deviceFileDesc));
    }
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    if (pContextToFree->tpmMutex)
        RTOS_globalMutexFree((char *)pContextToFree->mutexName, &pContextToFree->tpmMutex);
#endif

    DIGI_FREE(ppTctiOsContext);
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC TCTI_LINUX_contextInit(TctiContextInitIn *pIn, void **ppTctiOsContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TCTI_LINUX_CONTEXT *pNewContext = NULL;
    MSTATUS status = ERR_GENERAL;
    const char *pMutexName = NULL;
    const char *pDeviceName = NULL;
    ubyte2 port = 0;

    if (!pIn || !ppTctiOsContext || *ppTctiOsContext ||
            (pIn->serverNameLen > TCTI_LINUX_MAX_DEVICE_NAME_SIZE))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pNewContext, 1, sizeof(*pNewContext)))
    {
        rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Could not allocate memory for Linux TCTI"
                "context, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
       If port number is specified, we assume emulator
     */
    if (pIn->serverPort)
        pNewContext->isEmulator = TRUE;

    /*
     * if server name is not provided, use default device.
     * if port is the emulator port, we talk to the default emulator.
     * if not we use default device of /dev/tpm0. Port is ignored.
     *
     */
    if (!pIn->pServerName || (0 == pIn->serverNameLen))
    {
        if (pNewContext->isEmulator || (pIn->serverPort == 0))
        {
            /* Set default simulator settings when server-name and port are not provided */
            pMutexName = pDefaultSimulatorMutex;
            pDeviceName = pDefaultSimulatorName;
            port = defaultSimulatorPort; /* Should we not set serverPort if it is non-zero */
            pNewContext->isEmulator = TRUE;
        }
        else
        {
            pMutexName = pDefaultMutexName;
            pDeviceName = pDefaultDeviceName;
        }
    }
    else
    {
        /*
         * Get mutex name from server name.
         */
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
        rc = TCTI_LINUX_getMutextNameFromServerName((ubyte *)pIn->pServerName, pIn->serverNameLen, pNewContext->mutexName,
                sizeof(pNewContext->mutexName));
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get mutex name for device, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pMutexName = pNewContext->mutexName;
#endif
        pDeviceName = (const char *)(pIn->pServerName);
        port = pIn->serverPort;
    }

    /*
     * Create the mutex
     */
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    status = RTOS_globalMutexCreate((char *)pMutexName, &pNewContext->tpmMutex);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to create/get reference to TPM mutex, rc 0x%02x = %s, errno-%d\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc), errno);
        goto exit;
    }

    if (OK != DIGI_MEMCPY((void *)pNewContext->mutexName, pMutexName,
            DIGI_STRLEN((const sbyte*)pMutexName)))
    {
        DB_PRINT("%s.%d Memcpy failed, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif
    /*
     * Open the device and create the file descriptor. If port is not 0, we create a socket,
     * if port is 0, we open a device. Note that if serverName or serverLen and input port
     * are 0, port is set to the defualt emulator port, and hence a socket is opened.
     */
    if (port)
    {
        /*
         * Open a socket and hang onto the file descriptor
         */
        rc = TCTI_LINUX_openSocket((const char *)pDeviceName, port,
                &pNewContext->deviceFileDesc);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to open socket, rc 0x%02x = %s\n",
                     __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pNewContext->isSocketFd = TRUE;
        pNewContext->port = port;

        /*
         * If this is an emulator, close the file descriptor. For some reason, opening
         * and closing the file descriptor, works faster than keeping the socket open.
         * For emulator, socket is opened and closed during transmit-recieve.
         */
        if ( (pNewContext->isEmulator) && !(gShouldReuseContext) )
        {
            TCTI_LINUX_closeFD(&(pNewContext->deviceFileDesc));
        }
    }
    else
    {
        /* Open the device */
        rc = TCTI_LINUX_openDevice((const char *)pDeviceName, &pNewContext->deviceFileDesc);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to open device, rc 0x%02x = %s\n",
                     __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!(gShouldReuseContext))
        {
            TCTI_LINUX_closeFD(&(pNewContext->deviceFileDesc));
        }
    }

    if (OK != DIGI_MEMCPY((void *)pNewContext->deviceName, pDeviceName,
            DIGI_STRLEN((const sbyte*)pDeviceName)))
    {
        DB_PRINT("%s.%d Memcpy failed, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *ppTctiOsContext = pNewContext;
    rc = TSS2_RC_SUCCESS;
exit:
    if (pNewContext && (TSS2_RC_SUCCESS != rc))
    {
        TCTI_LINUX_contextUnint((void **)&pNewContext);
    }

    return rc;
}


TSS2_RC TCTI_LINUX_transmitRecieve(void *pTctiOsCtx, TctiTransmitRecieveIn *pIn, TctiTransmitRecieveOut *pOut)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TCTI_LINUX_CONTEXT *pContext = NULL;
    ubyte locality = 0;
    ubyte4 tpmSendCommand = 0;
    ubyte4 length = 0;
    sbyte4 ret = 0;
    sbyte4 numBytes = 0;
    byteBoolean releaseMutex = FALSE;
    ubyte4 returnlength = 0;
    ubyte4 acknowledgement = 0;

    if (!pTctiOsCtx || !pIn || !pOut ||
            (!pIn->pTransmitBuf) || (0 == pIn->transmitBufLen) ||
            (!pIn->pReceiveBuf) || (0 == pIn->receiveBufLen))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pContext = (TCTI_LINUX_CONTEXT *)pTctiOsCtx;

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    if (OK != RTOS_globalMutexWait(pContext->tpmMutex, TCTI_LINUX_MUTEX_TIMEOUT_SEC))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Mutex wait failed. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    releaseMutex = TRUE;
#endif

    if ( !(pContext->isSocketFd) && !(gShouldReuseContext) )
    {
        /*
         * Open the device, if it succeeds, close the file descriptor. The linux device driver only
         * allows the driver to be opened once, at given point in time.
         */
        rc = TCTI_LINUX_openDevice((const char *)pContext->deviceName, &(pContext->deviceFileDesc));
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to open device, rc 0x%02x = %s\n",
                     __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pContext->isEmulator)
    {
        if (!(gShouldReuseContext))
        {
            /*
             * Open and connect to socket, since we close socket for the emulator
             * during context init.
             */
            rc = TCTI_LINUX_openSocket((const char *)pContext->deviceName, pContext->port,
                    &pContext->deviceFileDesc);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to open socket, rc 0x%02x = %s\n",
                         __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

        tpmSendCommand = htonl(0x8);
        length = htonl(pIn->transmitBufLen);

        ret = (sbyte4) write(pContext->deviceFileDesc, &tpmSendCommand, sizeof(ubyte4));
        if (ret == -1)
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            goto exit;
        }
        ret = (sbyte4) write(pContext->deviceFileDesc, &locality, sizeof(ubyte));
        if (ret == -1)
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            goto exit;
        }
        ret = (sbyte4) write(pContext->deviceFileDesc, &length, sizeof(ubyte4));
        if (ret == -1)
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            goto exit;
        }
    }

    numBytes = (sbyte4) write(pContext->deviceFileDesc, pIn->pTransmitBuf, pIn->transmitBufLen);
    if (numBytes != (sbyte4) pIn->transmitBufLen)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to write all commands byets.. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pContext->isEmulator)
    {
        ret = (sbyte4) read(pContext->deviceFileDesc, (ubyte *)&returnlength, sizeof(ubyte4));
        if (ret == -1)
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            goto exit;
        }

        returnlength = ntohl(returnlength);
    }
    else
    {
        returnlength = pIn->receiveBufLen;
    }

    numBytes = (sbyte4) read(pContext->deviceFileDesc, pIn->pReceiveBuf, returnlength);
    if (numBytes == -1)
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        goto exit;
    }

    if (pContext->isEmulator)
    {
        ret = (sbyte4) read(pContext->deviceFileDesc, (ubyte *)&acknowledgement, sizeof(ubyte4));
        if (ret == -1)
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            goto exit;
        }

        acknowledgement = ntohl(acknowledgement);

    }
    else
    {
        returnlength = numBytes;
    }

    pOut->recievedLen = returnlength;
    rc = TSS2_RC_SUCCESS;
exit:
    if ((pContext) &&
        (!pContext->isSocketFd || pContext->isEmulator) &&
        !(gShouldReuseContext) )
    {
        TCTI_LINUX_closeFD(&(pContext->deviceFileDesc));
    }

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
    if (releaseMutex)
        RTOS_globalMutexRelease(pContext->tpmMutex);
#endif
    return rc;
}

TCTI_OS_OPS tcti_posix_ops = {
        .contextInit = TCTI_LINUX_contextInit,
        .contextUnint = TCTI_LINUX_contextUnint,
        .transmitRecieve = TCTI_LINUX_transmitRecieve,
};
#endif
#endif /* __ENABLE_DIGICERT_TPM2__ */
