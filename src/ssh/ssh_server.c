/*
 * ssh_server.c
 *
 * SSH Server
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
#include "../common/mocana.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/circ_buf.h"
#include "../common/moc_stream.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh_server.h"
#include "../ssh/ssh.h"


/*------------------------------------------------------------------*/

extern sbyte4           g_sshMaxConnections;
extern sshConnectDescr* g_connectTable;


/*------------------------------------------------------------------*/

#if (!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__) && defined(__USE_MOCANA_SSH_SERVER__))

static TCP_SOCKET mListenSocket;
static intBoolean mBreakServer;
static RTOS_MUTEX sshServerMutex;

#ifdef __WIN32_RTOS__

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400

#include <windows.h>

BOOL WINAPI HandlerRoutine(DWORD s)
{
    MOC_UNUSED(s);

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __USE_MOCANA_SSH_SERVER__
    TCP_CLOSE_SOCKET(mListenSocket);
#endif
#endif
    return TRUE;
}

#endif


/*------------------------------------------------------------------*/

static sbyte4
getIndex(sbyte4 connectionInstance)
{
    sbyte4 index;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
            return index;

    return -1;
}


/*------------------------------------------------------------------*/

static void
threadEntryPoint(void* hconnectionInstance)
{
    sbyte4         index;
    sbyte4         connectionInstance = (sbyte4) hconnectionInstance;

    if (-1 != (index = getIndex(connectionInstance)))
    {
        SSH_sshSettings()->funcPtrConnection(connectionInstance);

        if (OK > RTOS_mutexWait(sshServerMutex))
            goto exit;

        if (FALSE == g_connectTable[index].isSocketClosed)
        {
            TCP_CLOSE_SOCKET(g_connectTable[index].socket);
            g_connectTable[index].isSocketClosed = TRUE;
        }

        SSH_closeConnection(connectionInstance, OK);

        RTOS_mutexRelease(sshServerMutex);
    }

exit:
    return;
}


/*------------------------------------------------------------------*/

extern void
SSH_SERVER_disconnectClients(void)
{
    sbyte4 index;

    if (NULL == g_connectTable)
        return;

    for (index = 0; index < g_sshMaxConnections; index++)
        if ((CONNECT_CLOSED < g_connectTable[index].connectionState) &&
            (FALSE == g_connectTable[index].isSocketClosed))
        {
            if (OK <= RTOS_mutexWait(sshServerMutex))
            {
                TCP_CLOSE_SOCKET(g_connectTable[index].socket);
                g_connectTable[index].isSocketClosed = TRUE;
                SSH_closeConnection(g_connectTable[index].instance, OK);

                RTOS_mutexRelease(sshServerMutex);
            }
        }
}


/*------------------------------------------------------------------*/

static intBoolean isMutexInit = FALSE;

extern MSTATUS
SSH_SERVER_start(void)
{
    MSTATUS     status;

    mBreakServer = FALSE;

    if (FALSE == isMutexInit)
    {
        if (OK > (status = RTOS_mutexCreate(&sshServerMutex, SSH_SERVER_MUTEX, 0)))
            goto nocleanup;

        isMutexInit = TRUE;
    }

    if (OK > (status = TCP_LISTEN_SOCKET(&mListenSocket, ((ubyte2)SSH_sshSettings()->sshListenPort))))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_SERVER_start: Could not create listen socket");
        goto nocleanup;
    }


#ifdef __WIN32_RTOS__
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#endif

    DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_SERVER_start: SSH server listening on port ", SSH_sshSettings()->sshListenPort);

    MOCANA_log((sbyte4)MOCANA_SSH, (sbyte4)LS_INFO, (sbyte *)"SSH server listening for clients");

    while (1)
    {
        TCP_SOCKET  socketClient;
        sbyte4      ci;
        RTOS_THREAD tid;

        if (TRUE == mBreakServer)
            goto exit;

        if (OK > (status = TCP_ACCEPT_SOCKET(&socketClient, mListenSocket, &mBreakServer)))
            goto exit;

        if (TRUE == mBreakServer)
            goto exit;

        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_SERVER_start: Connection accepted on socket: ", socketClient);

        if (OK > (ci = SSH_acceptConnection(socketClient)))
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_SERVER_start: Too many open connections.");
            TCP_CLOSE_SOCKET(socketClient);
            continue;
        }

        if (NULL != SSH_sshSettings()->funcPtrPostAccept)
            (SSH_sshSettings()->funcPtrPostAccept)(ci, (sbyte4)socketClient);

#ifdef __SINGLE_THREAD_SSH_SERVER__
        if (NULL != SSH_sshSettings()->funcPtrConnection)
        {
            (SSH_sshSettings()->funcPtrConnection)(ci);
        }

        TCP_CLOSE_SOCKET(socketClient);
#else
        if (NULL != SSH_sshSettings()->funcPtrConnection)
        {
            if (OK > (status = RTOS_createThread(threadEntryPoint, (void*)ci, SSH_SESSION, &tid)))
                goto exit;

            if (tid != NULL)
                RTOS_destroyThread(tid);

            tid = NULL;

        }
#endif
    }

exit:
    TCP_CLOSE_SOCKET(mListenSocket);

nocleanup:
    return status;

} /* SSH_SERVER_start */


/*------------------------------------------------------------------*/

extern void
SSH_SERVER_releaseMutex(void)
{
    if (TRUE == isMutexInit)
    {
        RTOS_mutexFree(&sshServerMutex);
        isMutexInit = FALSE;
    }
}


/*------------------------------------------------------------------*/

extern void
SSH_SERVER_stop(void)
{
    mBreakServer = TRUE;
}

#endif /* (!defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__) && defined(__USE_MOCANA_SSH_SERVER__)) */
#endif /* __ENABLE_MOCANA_SSH_SERVER__ */



