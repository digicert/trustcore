/*
 * ssh_example_async.c
 *
 * Example code for integrating SSH Server Stack with asynchronous API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/sizedbuffer.h"
#include "../crypto/hw_accel.h"
#include "../crypto/cert_store.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../ssh/ssh_filesys.h"
#include "../ssh/sftp.h"
#include "../ssh/ssh.h"
#ifdef __ENABLE_MOCANA_MEM_PART__
#include "../common/mem_part.h"
#endif

#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#define MAX_PORT_FORWARD_CONNECTION       (4)
#define MAX_PORT_FORWARD_RX_BUFF_SIZE     (512)
static unsigned short ssh_exampleServerPort = SSH_DEFAULT_TCPIP_PORT;

static sbyte4 mBreakServer;
static certStorePtr pSshCertStore;

#define SSH_EXAMPLE_banner "Mocana NanoSSH server!!\n"

#ifdef __ENABLE_MOCANA_MEM_PART__
extern memPartDescr *gMemPartDescr;
#endif

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
typedef struct
{
    TCP_SOCKET      pfSocket;
    sbyte4          connInstance;
    sbyte4          channel;
    intBoolean      isUsedFlag;
} portForwardTable;
#endif /*__ENABLE_MOCANA_SSH_PORT_FORWARDING__*/

typedef struct
{
      sbyte4       connInstance;
      TCP_SOCKET   socketClient;
} SSH_ClientInstance;

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
extern void SFTP_EXAMPLE_init(void);
#endif

/* WARNING: Hardcoded credentials used below are for illustrative purposes ONLY.
   DO NOT use hardcoded credentials in production. */
#define USERNAME    "admin"
#define PASSWORD    "secure"

#ifdef __RTOS_VXWORKS__
#define PUBLIC_HOST_KEY_FILE_NAME       "NVRAM:/sshkeys.pub"
#define PRIVATE_HOST_KEY_FILE_NAME      "NVRAM:/sshkeys.prv"
#define AUTH_KEYFILE_NAME               "NVRAM:/id_dsa.pub"
#else
#define PUBLIC_HOST_KEY_FILE_NAME       "sshkeys.pub"
#define PRIVATE_HOST_KEY_FILE_NAME      "sshkeys.prv"
#define AUTH_KEYFILE_NAME               "id_dsa.pub"
#endif

#define MAX_SSH_CONNECTIONS_ALLOWED     (4)

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static portForwardTable    pfTable[MAX_PORT_FORWARD_CONNECTION];
static ubyte               pfRxBuff[MAX_PORT_FORWARD_RX_BUFF_SIZE];


/*------------------------------------------------------------------*/

static sbyte4
SSHPF_EXAMPLE_init( void )
{
    MOC_MEMSET((ubyte*)pfTable,0x00,sizeof(portForwardTable)*MAX_PORT_FORWARD_CONNECTION);
    return 0;
}

#endif /*__ENABLE_MOCANA_SSH_PORT_FORWARDING__*/
/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_authMethod(sbyte4 connectionInstance)
{
    MOC_UNUSED(connectionInstance);

    /* allows dynamic enable / disable of authentication methods */
    return (MOCANA_SSH_AUTH_PUBLIC_KEY | MOCANA_SSH_AUTH_PASSWORD | MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE);
}


/*------------------------------------------------------------------*/

/* for interactive-keyboard authentication */
enum exampleAuthStates
{
    EXAMPLE_PASSWORD = 0,
    EXAMPLE_CHANGE_PASSWORD = 1,
    EXAMPLE_DONE = 2
};

static sbyte *
m_exampleMessages[] =
{
    (sbyte *)"Password Authentication",
    (sbyte *)"Password Expired",
    (sbyte *)"Your password has expired.",
    (sbyte *)"Password changed",
    (sbyte *)"Password successfully changed for "
};

static keyIntPrompt
m_passwordPrompts[] =
{
    { (sbyte *)"Password: ",           10, AUTH_NO_ECHO },
    { (sbyte *)"Enter new password: ", 20, AUTH_NO_ECHO },
    { (sbyte *)"Enter it again: ",     16, AUTH_NO_ECHO }
};


/*------------------------------------------------------------------*/
#if defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
extern int
SSH_RADIUS_EXAMPLE_authPasswordFunction(int connectionInstance,
                    const unsigned char *pUser,     unsigned int userLength,
                    const unsigned char *pPassword, unsigned int passwordLength);
#endif

static sbyte4
SSH_EXAMPLE_authPasswordFunction(sbyte4 connectionInstance,
                                 const ubyte *pUser,     ubyte4 userLength,
                                 const ubyte *pPassword, ubyte4 passwordLength)
{
    MOC_UNUSED(connectionInstance);

    /* we're going to assume everyone has a username and password */
    /* we do not force you to assume this policy */
    if ((0 == userLength) || (0 == passwordLength))
        return AUTH_FAIL;

    /* always check the lengths first, there may not be a username or password */
    if (userLength != (sizeof(USERNAME) - 1))
        return AUTH_FAIL;

    if (passwordLength != (sizeof(PASSWORD) - 1))
        return AUTH_FAIL;

    if ((0 != memcmp(pUser,     USERNAME, userLength)) ||
        (0 != memcmp(pPassword, PASSWORD, passwordLength)))
    {
        return AUTH_FAIL;
    }

    /* return authentication succeeded */
    return AUTH_PASS;

} /* SSH_EXAMPLE_authPasswordFunction */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_keyboardInteractiveAuth(sbyte4                  connectionInstance,
                                    const ubyte*            pUser,
                                    ubyte4                  userLength,
                                    keyIntInfoResp*         pAuthResponse,    /* if NULL, an initial request message */
                                    keyIntInfoReq*          pAuthRequest,
                                    sbyte4*                 pAuthState)
{
    sbyte4 prevState = pAuthRequest->cookie;
    sbyte4 result    = AUTH_MORE;

    if ((NULL == pAuthResponse) || (EXAMPLE_PASSWORD == pAuthRequest->cookie))
    {
        sbyte4 isAuth    = 0;

        /* you can use the connectionInstance cookie, if you prefer */
        /* use the cookie, however you please */
        pAuthRequest->cookie = EXAMPLE_PASSWORD;

        /* if pAuthResponse is null, assume inital log on state */
        if (0 != pAuthResponse)
        {
#if defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
            isAuth = SSH_RADIUS_EXAMPLE_authPasswordFunction(connectionInstance,
#else
            isAuth = SSH_EXAMPLE_authPasswordFunction(connectionInstance,
#endif
                                                      pUser, userLength,
                                                      pAuthResponse->responses[0]->pResponse,        /* password */
                                                      pAuthResponse->responses[0]->responseLen);     /* password length */

            if (1 == isAuth)
            {
                /* fake password expiration simulation */
                pAuthRequest->cookie = EXAMPLE_CHANGE_PASSWORD;
            }
            else
            {
                result = AUTH_FAIL_MORE;
            }
        }

        if (0 == isAuth)
        {
            /* build info request */
            pAuthRequest->pName           = m_exampleMessages[0];           /* "Password Authentication" */
            pAuthRequest->nameLen         = strlen((const char *)m_exampleMessages[0]);
            pAuthRequest->pInstruction    = 0;
            pAuthRequest->instructionLen  = 0;
            pAuthRequest->numPrompts      = 1;
            pAuthRequest->prompts[0]      = &m_passwordPrompts[0];
        }
    }

    if (EXAMPLE_CHANGE_PASSWORD == pAuthRequest->cookie)
    {
        sbyte4 isPasswordChanged = 0;

        if (EXAMPLE_CHANGE_PASSWORD == prevState)
        {
            /* before reaching this handler, the engine verifies */
            /* that we receive the expected number of responses */
            if ((0 < pAuthResponse->responses[0]->responseLen) &&
                (pAuthResponse->responses[0]->responseLen == pAuthResponse->responses[1]->responseLen) &&
                (0 == memcmp((sbyte *)pAuthResponse->responses[0]->pResponse,
                             (sbyte *)pAuthResponse->responses[1]->pResponse,
                             pAuthResponse->responses[0]->responseLen)) )
            {
                /* new passwords match, fake password change completed */
                isPasswordChanged = 1;
            }
        }

        if (0 == isPasswordChanged)
        {
            /* build info request */
            pAuthRequest->pName           = m_exampleMessages[1];           /* "Password Expired" */
            pAuthRequest->nameLen         = strlen((const char *)m_exampleMessages[1]);
            pAuthRequest->pInstruction    = m_exampleMessages[2];           /* "Your password has expired." */
            pAuthRequest->instructionLen  = strlen((const char *)m_exampleMessages[2]);
            pAuthRequest->numPrompts      = 2;
            pAuthRequest->prompts[0]      = &m_passwordPrompts[1];
            pAuthRequest->prompts[1]      = &m_passwordPrompts[2];
        }
        else
        {
            /* dynamic string example */
            sbyte*           pString;
            sbyte            buf[2];
            ubyte4    index;

            /* note: see SSH_EXAMPLE_releaseKeyboardInteractiveRequest() example */
            if (0 == (pString = MALLOC(strlen((const char *)m_exampleMessages[4]) + userLength + 2)))
                return -1;  /* Note: negative returns are handled as an error by the caller */

            /* "Password successfully changed for <user>." */
            buf[1] = *pString = '\0';
            strcat((char *)pString, (const char *)m_exampleMessages[4]);

            /* Note: user string is not terminated, therefore byte copy */
            for (index = 0; index < userLength; index++)
            {
                buf[0] = pUser[index];
                strcat((char *)pString, (const char *)buf);
            }

            strcat((char *)pString, ".");

            /* build info request */
            pAuthRequest->pName           = m_exampleMessages[3];           /* "Password changed" */
            pAuthRequest->nameLen         = strlen((const char *)m_exampleMessages[3]);
            pAuthRequest->pInstruction    = pString;                        /* "Password successfully changed for user23." */
            pAuthRequest->instructionLen  = strlen((const char *)pString);
            pAuthRequest->numPrompts      = 0;

            /* Note: if we returned AUTH_PASS, there would be no message indicating password */
            /* change was successful.  */
            pAuthRequest->cookie  = EXAMPLE_DONE;
        }
    }

    if (EXAMPLE_DONE == prevState)
    {
        /* let the server know authentication was successful */
        result = AUTH_PASS;
    }

    *pAuthState = result;
    return OK;      /* Note: negative returns are handled as an error by the caller */

} /* SSH_EXAMPLE_keyboardInteractiveAuth */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_releaseKeyboardInteractiveRequest(sbyte4 connectionInstance,
                                              keyIntInfoReq* pAuthRequest)
{
    MOC_UNUSED(connectionInstance);

    /*!-!-!-! if necessary, free strings here */
    if ((EXAMPLE_DONE == pAuthRequest->cookie) && (NULL != pAuthRequest->pInstruction))
    {
        FREE(pAuthRequest->pInstruction);
        pAuthRequest->pInstruction = NULL;     /* prevent a double-free */
    }

    return 0;            /* Note: negative returns are handled as an error by the caller */
}


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_testHostKeys(void)
{
    ubyte*  pRetPublicKey  = NULL;
    ubyte*  pRetPrivateKey = NULL;
    ubyte4    publicKeyLength;
    ubyte4    privateKeyLength;
    sbyte4             status;

    if (0 > (status = MOCANA_readFile(PUBLIC_HOST_KEY_FILE_NAME, &pRetPublicKey, &publicKeyLength)))
        goto exit;

    status = MOCANA_readFile(PRIVATE_HOST_KEY_FILE_NAME, &pRetPrivateKey, &privateKeyLength);

exit:
    MOCANA_freeReadFile(&pRetPublicKey);
    MOCANA_freeReadFile(&pRetPrivateKey);

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_pubkeyNotify(sbyte4 connectionInstance,
                         const ubyte *pUser,   ubyte4 userLength,
                         const ubyte *pPubKey, ubyte4 pubKeyLength,
                         ubyte4 keyType)
{
    ubyte* pStoredPublicKey = NULL;
    ubyte4   storedPublicKeyLength;
    sbyte4            result = 0;
    MOC_UNUSED(connectionInstance);


    /* The SSH Server will only call this function, if the client's */
    /* public key matched the signature provided.  We need to now */
    /* verify that the public key is an acceptable public key (i.e. on record) */

    /* we're going to continue to assume everyone has a username */
    /* we do not force you to assume this policy */
    if (0 == userLength)
        goto exit;

    /* always check the lengths first, there may not be a username or password */
    if (userLength != (sizeof(USERNAME) - 1))
        goto exit;

    if (0 != memcmp(pUser, USERNAME, userLength))
        goto exit;

    /* make sure the client provided pubkey matches a pub key on file */
    if (0 > MOCANA_readFile(AUTH_KEYFILE_NAME, &pStoredPublicKey, &storedPublicKeyLength))
        goto exit;

    /* write code to compare keys here */
    if (0 > SSH_compareAuthKeys(pPubKey, pubKeyLength, pStoredPublicKey, storedPublicKeyLength, &result))
        goto exit;

    /* if necessary, do additional checks here */

exit:
    if (NULL != pStoredPublicKey)
        MOCANA_freeReadFile(&pStoredPublicKey);

    return result;

} /* SSH_EXAMPLE_pubkeyNotify */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
static sbyte4
SSH_EXAMPLE_sftpSessionStarted(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent,
                               ubyte *pMesg, ubyte4 mesgLen)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(sessionEvent);
    MOC_UNUSED(pMesg);
    MOC_UNUSED(mesgLen);

    /* do any initialization here for the SFTP session. */
    /* note: the cookie is accessible. */
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_sftpSessionStarted: SFTP session established.");

    return 0;
}
#endif


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_simpleAsyncCLI(sbyte4 connInstance, enum sshSessionTypes sessionEvent,
                           ubyte *pMesg, ubyte4 mesgLen)
{
    sbyte4 status = 0;
    sbyte4 bytesSent;

    /* you could delay acking if some processing was required, for this example we ack immediately */
    SSH_ASYNC_ackReceivedMessageBytes(connInstance, sessionEvent, mesgLen);

    /* echo client input */
    switch (sessionEvent)
    {
        case SSH_SESSION_NOTHING:
            break;
        case SSH_SESSION_OPEN:
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        case SSH_SESSION_OPEN_PF:
        /* All the work is done by "pSSHContext->funcPtrConnect" callback function */
#endif
            break;
        case SSH_SESSION_OPEN_SHELL:
            break;
        case SSH_SESSION_OPEN_EXEC:
            status = SSH_ASYNC_sendMessage(connInstance, "got exec command", 8, &bytesSent);
            break;
        case SSH_SESSION_DATA:
            status = SSH_ASYNC_sendMessage(connInstance, (sbyte *)pMesg, mesgLen, &bytesSent);    /* echo input */
            break;
        case SSH_SESSION_STDERR:
            status = SSH_ASYNC_sendMessage(connInstance, "<stderr>", 8, &bytesSent);
            break;
        case SSH_SESSION_EOF:
            mBreakServer = TRUE;
            break;
        case SSH_SESSION_CLOSED:
            break;
        default:
            status = SSH_ASYNC_sendMessage(connInstance, "<default>", 9, &bytesSent);
            break;
    }

    if (0 > status)
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simpleAsyncCLI: status = ", status);
        mBreakServer = TRUE;
    }

    return status;

} /* SSH_EXAMPLE_simpleAsyncCLI */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static sbyte4
SSH_EXAMPLE_addPortForwardConnection(sbyte4      connectionInstance,
                                     TCP_SOCKET  socket,
                                     sbyte4      channel)
{
    sbyte4 status  = -1;
    sbyte4 counter = 0;

    for ( counter = 0; counter < MAX_PORT_FORWARD_CONNECTION; counter++ )
    {
        if ( FALSE == pfTable[counter].isUsedFlag )
        {
            pfTable[counter].isUsedFlag   = TRUE;
            pfTable[counter].channel      = channel;
            pfTable[counter].connInstance = connectionInstance;
            pfTable[counter].pfSocket     = socket;

            status = 0; /* Mark it as success */
            goto exit;
        }
    }

exit:
    return status;
} /* SSH_EXAMPLE_addPortForwardConnection */

static sbyte4
SSH_EXAMPLE_removePortForwardConnection( sbyte4      connectionInstance,
                                         TCP_SOCKET  socket,
                                         sbyte4      channel)
{
    sbyte4 status  = -1;
    sbyte4 counter = 0;

    for ( counter = 0; counter < MAX_PORT_FORWARD_CONNECTION; counter++ )
    {
        if ( ( TRUE == pfTable[counter].isUsedFlag ) &&
             ( connectionInstance == pfTable[counter].connInstance ) &&
             ( channel == pfTable[counter].channel ) )
        {
            pfTable[counter].isUsedFlag   = FALSE; /* This channel is done */
            pfTable[counter].channel      = 0;
            pfTable[counter].connInstance = 0;
            pfTable[counter].pfSocket     = 0;

            status = 0; /* Mark it as success */
            goto exit;
        }
    }

exit:
    return status;
} /* SSH_EXAMPLE_removePortForwardConnection */

static sbyte4
SSH_EXAMPLE_getSocketFromChannel(sbyte4       connectionInstance,
                                 TCP_SOCKET*  pSocket,
                                 sbyte4       channel)
{
    sbyte4 status  = -1;
    sbyte4 counter = 0;

    for ( counter = 0; counter < MAX_PORT_FORWARD_CONNECTION; counter++ )
    {
        if ( ( TRUE == pfTable[counter].isUsedFlag ) &&
             ( connectionInstance == pfTable[counter].connInstance ) &&
             ( channel == pfTable[counter].channel ) )
        {
            (*pSocket) = pfTable[counter].pfSocket;

            status = 0; /* Mark it as success */
            goto exit;
        }
    }

exit:
    return status;
} /* SSH_EXAMPLE_getSocketFromChannel */

/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_simplePortForwardConnect(sbyte4 connectionInstance,
                                     sbyte4 sessionNum,
                                     ubyte *pConnectHost,
                                     ubyte2 port,
                                     sbyte4 *pIgnoreRequest,
                                     sbyte4 channel)
{
    sbyte4                  status = 0;
    sbyte4                  bytesSent;
    TCP_SOCKET              mySocket;
    char*                   serverIpAddress = (char*)pConnectHost;
    unsigned short          serverPort = (unsigned short)port;
    /* We don't need sending ACK as it was already sent by the Session Open Callback */

    if (OK > (status = TCP_CONNECT(&mySocket, serverIpAddress, serverPort)))
        goto exit;

    if (OK > (status = SSH_EXAMPLE_addPortForwardConnection( connectionInstance,
                                                             mySocket,
                                                             channel ) ) )
        goto exit;

    (*pIgnoreRequest) = 0;
exit:
    if (0 > status)
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simplePortForwardConnect: status = ", status);
        mBreakServer = TRUE;
    }

    return status;

} /* SSH_EXAMPLE_simplePortForwardConnect */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_simplePortForwardClose(sbyte4 connectionInstance,
                                   enum sshSessionTypes sessionEvent,
                                   ubyte *pMesg,
                                   ubyte4 mesgLen,
                                   ubyte4 channel)
{
    sbyte4                  status = 0;
    sbyte4                  bytesSent;
    TCP_SOCKET              mySocket;

    /* you could delay acking if some processing was required, for this example we ack immediately */
    SSH_ackPortFwdReceivedMessageBytes(connectionInstance, sessionEvent, mesgLen, channel);

    if (OK > (status = SSH_EXAMPLE_getSocketFromChannel(connectionInstance,&mySocket, channel)))
        goto exit;

    if (OK > (status = TCP_CLOSE_SOCKET(mySocket)))
        goto exit;

    if (OK > (status = SSH_EXAMPLE_removePortForwardConnection( connectionInstance,
                                                                mySocket,
                                                                channel ) ) )
        goto exit;

exit:
    if (0 > status)
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simplePortForwardClose: status = ", status);
        mBreakServer = TRUE;
    }

    return status;

} /* SSH_EXAMPLE_simplePortForwardClose */

static sbyte4
SSH_EXAMPLE_simplePortForwardEof(sbyte4 connectionInstance,
                                   enum sshSessionTypes sessionEvent,
                                   ubyte *pMesg,
                                   ubyte4 mesgLen,
                                   ubyte4 channel)
{
    sbyte4                  status = 0;

    /* !!!! WARNING --- TBD - CODE TO BE ADDED !!!! */
    return status;

} /* SSH_EXAMPLE_simplePortForwardEof */

/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_portForwardReceiveData(sbyte4 connectionInstance,
                                   enum sshSessionTypes sessionEvent,
                                   ubyte *pMesg,
                                   ubyte4 mesgLen,
                                   ubyte4 channel)
{
    sbyte4                  status = 0;
    TCP_SOCKET              mySocket;
    ubyte4                  numBytesWritten = 0;
    ubyte4                  numBytesRead = 0;

    if ( SSH_PF_DATA != sessionEvent )
    {
        status = -1;
        goto exit;
    }

    /* you could delay acking if some processing was required, for this example we ack immediately */
    SSH_ackPortFwdReceivedMessageBytes(connectionInstance, sessionEvent, mesgLen, channel);

    if (OK > (status = SSH_EXAMPLE_getSocketFromChannel(connectionInstance,&mySocket, channel)))
        goto exit;

    /*****************Start -- This code is only for a simple Echo server **********************/
    if ( OK > (status = TCP_WRITE(mySocket, (sbyte *)pMesg,mesgLen, &numBytesWritten)))
        goto exit;
    if ((OK <= status) && (numBytesWritten != mesgLen))
    {
        status = ERR_TCP_WRITE_BLOCK_FAIL;
        goto exit;
    }

    MOC_MEMSET( pfRxBuff, 0x00, MAX_PORT_FORWARD_RX_BUFF_SIZE );
    if (OK > (status = TCP_READ_AVL(mySocket, pfRxBuff, MAX_PORT_FORWARD_RX_BUFF_SIZE, &numBytesRead, 500)))
    {
        if ( ERR_TCP_READ_TIMEOUT == status )
        {
            status = OK;
        }
        else
        {
            /* Send Close to the client */
            if ( OK > ( status = SSH_sendPortForwardClose( connectionInstance, channel ) ) )
                goto exit;
        }
    }
    status = SSH_sendPortForwardMessage(connectionInstance, channel, pfRxBuff, numBytesRead, &numBytesWritten);
    /*****************End   -- This code is only for a simple Echo server **********************/

exit:
    if (0 > status)
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simplePortForwardConnect: status = ", status);
        mBreakServer = TRUE;
    }

    return status;

} /* SSH_EXAMPLE_portForwardReceiveData */

/*------------------------------------------------------------------*/
ubyte 
CheckPortForwardDataReceive(sbyte4 connInstance)
{

    fd_set*             pSocketList = NULL;
    ubyte               i;
    sbyte4              status = -1;
    sbyte4              pfBytesReceived;
    sbyte4              pfBytesSent;
    struct timeval      timeout;
    int                 numHandles;

    /* allocate memory for select socket list */
    if (NULL == (pSocketList = (fd_set*)malloc(sizeof(fd_set))))
        goto exit;

    
    FD_ZERO(pSocketList);
    
    /* set socket for all port forward channels */
    for ( i = 0; i < MAX_PORT_FORWARD_CONNECTION; i++ )
    {
        if ((TRUE == pfTable[i].isUsedFlag ) &&
        ( connInstance == pfTable[i].connInstance))
        {
        FD_SET(pfTable[i].pfSocket, pSocketList);
        }
    }

    timeout.tv_sec  = 100 / 1000;
    timeout.tv_usec = (100 % 1000) * 1000;

    if (0 > (numHandles = select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout)))
        goto exit;

    /* no ssh data, skip SSH recv */
    if (numHandles > 0)
    {
        /* received data from pfSock, move bytes from server side to client side */
        for ( i = 0; i < MAX_PORT_FORWARD_CONNECTION; i++ )
        {
            /* make sure we send data to current connInstance */
            if (( TRUE == pfTable[i].isUsedFlag ) &&
            ( connInstance == pfTable[i].connInstance) &&
            (0 != FD_ISSET(pfTable[i].pfSocket, pSocketList)))
            {
                /* clear buffer before recv */
                memset( pfRxBuff, 0x00, MAX_PORT_FORWARD_RX_BUFF_SIZE );

                /* read bytes from pfSock */
                if (0 > (status = TCP_READ_AVL(pfTable[i].pfSocket, pfRxBuff, MAX_PORT_FORWARD_RX_BUFF_SIZE,
                                   &pfBytesReceived, 50)))
                {
                    if ( ERR_TCP_READ_TIMEOUT == status )
                    {
                        status = OK;
                    }
                    else
                    {
                        /* Send Close to the client */
                        if ( OK > (status = SSH_sendPortForwardClose(connInstance, pfTable[i].channel)) )
                            goto exit;
                    }
                }

                /* forward data to socket */
                if (0 < pfBytesReceived)
                {
                    if (0 > (SSH_sendPortForwardMessage(connInstance, pfTable[i].channel,
                                    pfRxBuff, pfBytesReceived, &pfBytesSent)))
                    goto exit;
                }
            }
        }
    }
exit:
    return status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

extern sbyte4
SSH_EXAMPLE_asyncServer(void)
{
    /* simulates an asynchronous TCP/IP stack */
    TCP_SOCKET          listenSocket;
    sbyte*              pInBuffer = NULL;
    ubyte4              numBytesRead;
    sbyte4              status = -1;
    sbyte4              nFlags;
    SSH_ClientInstance  Client[4];
    ubyte               index;
    sbyte4              nonBlocking = TRUE;

    /* Initialise the socket client */
    for(index = 0; index < 4; index++)
    {
        Client[index].socketClient = 0;
        Client[index].connInstance = 0;
    }

    mBreakServer = FALSE;

    if (NULL == (pInBuffer = MALLOC(MAX_SESSION_WINDOW_SIZE)))
        goto nocleanup;

    if (OK > (status = TCP_LISTEN_SOCKET(&listenSocket, ((ubyte2)SSH_sshSettings()->sshListenPort))))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_asyncServer: Could not create listen socket");
        FREE(pInBuffer);
        goto nocleanup;
    }

    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_asyncServer: SSH server listening on port ");
    DEBUG_INT(DEBUG_SSH_EXAMPLE, (sbyte4)SSH_sshSettings()->sshListenPort);
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, NULL);

    MOCANA_log(MOCANA_SSH, LS_INFO, "SSH server listening for clients");
  
    /* Make the socket nonblocking It will not stuck at TCP_ACCEPT_SOCKET */ 
    nFlags = fcntl(listenSocket, F_GETFL, 0);
    nFlags |= O_NONBLOCK;
    if (fcntl(listenSocket, F_SETFL, nFlags) == -1)
        DEBUG_PRINT(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_asyncServer: Port working in blocking mode");

    while (1)
    {
        for (index = 0; ((Client[index].socketClient !=0) && (index < 4)); index++);

        if(index < 4)  
        {
            if (OK > (status = TCP_ACCEPT_SOCKET(&Client[index].socketClient, listenSocket, &nonBlocking)))
                goto exit;

    
            if(Client[index].socketClient != 0)
            { 
                MOCANA_log(MOCANA_SSH, LS_INFO, "client accepted.");


                if (0 > (Client[index].connInstance = SSH_ASYNC_acceptConnection(Client[index].socketClient, NULL, 0, NULL, 0)))
                    goto exit;

                if (OK > (status = SSH_assignCertificateStore(Client[index].connInstance, pSshCertStore)))
                    goto exit;

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
          /* We need to do it to allow protocols like FTP, HTTP to be port forwarded */
                if (OK > (status = SSH_setUserPortForwardingPermissions(Client[index].connInstance, ( MOCANA_SSH_ALLOW_DIRECT_TCPIP | MOCANA_SSH_ALLOW_PRIVILEGED_DIRECT_TCPIP ) )))
                    goto exit;
#endif

                    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_asyncServer: Connection accepted on socket: ");
                    DEBUG_INT(DEBUG_SSH_EXAMPLE, (sbyte4)Client[index].socketClient);
                    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, NULL);
            }
        }
    
        /* Check data on each available socket client */
        for(index = 0; index < 4; index++) 
        {
            if(Client[index].socketClient != 0)
            {
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
                CheckPortForwardDataReceive(Client[index].connInstance);
#endif
                if (OK <= (status = TCP_READ_AVL(Client[index].socketClient, pInBuffer, SSH_SYNC_BUFFER_SIZE, &numBytesRead, 500)))
                if (0 != numBytesRead)
                    status = SSH_ASYNC_recvMessage(Client[index].connInstance, (ubyte *)pInBuffer, numBytesRead);
    
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;

                if (OK == status)
                    status = SSH_ASYNC_sendMessagePending(Client[index].connInstance, NULL);

                if((OK > status) || (TRUE == mBreakServer))
                {
                    SSH_ASYNC_closeConnection(Client[index].connInstance);
                    MOCANA_log(MOCANA_SSH, LS_INFO, "session closed.");
                    TCP_CLOSE_SOCKET(Client[index].socketClient);
                    Client[index].socketClient = 0;
                    Client[index].connInstance = 0;
                    mBreakServer = FALSE;
                }
            }
        }


    }

exit:
    FREE(pInBuffer);

    TCP_CLOSE_SOCKET(listenSocket);

nocleanup:
    return status;

} /* SSH_EXAMPLE_asyncServer */


/*------------------------------------------------------------------*/

typedef struct sshExamplekeyFilesDescr
{
    ubyte*      pFilename;
    ubyte4      keyType;
    ubyte4      keySize;

} sshExamplekeyFilesDescr;


/*------------------------------------------------------------------*/

static sshExamplekeyFilesDescr mNakedKeyFiles[] =
{
#ifdef __ENABLE_MOCANA_SSH_DSA_SUPPORT__
    { "ssh_dss.key", akt_dsa, 2048 },
#endif
#ifdef __ENABLE_MOCANA_SSH_RSA_SUPPORT__
    { "ssh_rsa.key", akt_rsa, 2048 },
#endif
#ifdef __ENABLE_MOCANA_ECC__
    { "ssh_ecdsa.key", akt_ecc, 384 },
#endif
    { NULL, akt_undefined, 0 }
};

#define SSH_EXAMPLE_NUM_KEY_FILES   ((sizeof(mNakedKeyFiles) / sizeof(sshExamplekeyFilesDescr)) - 1)


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_sshCertStoreInit(certStorePtr *ppNewStore)
{
    ubyte*  pKeyBlob;
    ubyte4  keyBlobLength;
    sbyte4  index;
    sbyte4  status;

    if (OK > (status = CERT_STORE_createStore(ppNewStore)))
        goto exit;

    for (index = 0; index < SSH_EXAMPLE_NUM_KEY_FILES; index++)
    {
        pKeyBlob      = NULL;
        keyBlobLength = 0;

        if (NULL == mNakedKeyFiles[index].pFilename)        /* skip past null strings; this happens if there is a dangling comma in mNakedKeyFiles[] */
            continue;

        /* check for pre-existing set of host keys */
        if (0 > (status = MOCANA_readFile(mNakedKeyFiles[index].pFilename, &pKeyBlob, &keyBlobLength)))
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_sshCertStoreInit: host key does not exist, computing new key...");

            /* if not, compute new host keys */
            if (0 > (status = CA_MGMT_generateNakedKey(mNakedKeyFiles[index].keyType, mNakedKeyFiles[index].keySize, &pKeyBlob, &keyBlobLength)))
                goto exit;

            if (0 > (status = MOCANA_writeFile(mNakedKeyFiles[index].pFilename, pKeyBlob, keyBlobLength)))
                goto exit;

            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_sshCertStoreInit: host key computation completed.");

            if (OK > (status = CERT_STORE_addIdentityNakedKey(*ppNewStore, pKeyBlob, keyBlobLength)))
                goto exit;

            CA_MGMT_freeNakedKey(&pKeyBlob);
        }
        else
        {
            if (OK > (status = CERT_STORE_addIdentityNakedKey(*ppNewStore, pKeyBlob, keyBlobLength)))
                goto exit;

            MOCANA_freeReadFile(&pKeyBlob);
        }
    }

exit:
    if(NULL != pKeyBlob)
        FREE(pKeyBlob);

    return status;
}

/*------------------------------------------------------------------*/
 
static void
SSH_EXAMPLE_displayHelp(char *prog)
{

    printf("  option:\n");
    printf("    -port <port>       sets listen port\n");

    printf("\n");
    return;
} /*SSH_EXAMPLE_displayHelp */

/*------------------------------------------------------------------*/

extern sbyte4
SSH_EXAMPLE_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;
    int i = 0;
    int portSet = 0;

    if ((2 <= argc) && ('?' == argv[1][0]))
    {
        SSH_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }
    
    for (i = 1; i < argc; i++) /*Skiping argv[0] which is example progam name*/
    {
        if  (strcmp(argv[i], "-port") == 0)
        {
            portSet = 1; /*Port should not be set to default*/
            i++;
            ssh_exampleServerPort = atoi(argv[i]);
            continue;
        }

    } /*for*/
    
    return status;
} /* SSH_EXAMPLE_getArgs */ 

/*------------------------------------------------------------------*/

void SSH_EXAMPLE_main(sbyte4 dummy)
{
    MOC_UNUSED(dummy);

    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_main: Starting up single user async example SSH Server");

#ifdef __ENABLE_MOCANA_MEM_PART__
    if (NULL != gMemPartDescr)
    {
        /* make sure it's thread-safe! */
        MEM_PART_enableMutexGuard(gMemPartDescr);
    }
#endif

    /* initialize the SSH tables and structures */
    if (0 > SSH_ASYNC_init(MAX_SSH_CONNECTIONS_ALLOWED))
        goto exit;

    /* if necessary, create host keys */
    if (0 > SSH_EXAMPLE_sshCertStoreInit(&pSshCertStore))
        goto exit;

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    SFTP_EXAMPLE_init();
    SSH_sshSettings()->funcPtrOpenSftp         = SSH_EXAMPLE_sftpSessionStarted;
#endif

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    SSHPF_EXAMPLE_init();
    SSH_sshSettings()->funcPtrConnect                   = SSH_EXAMPLE_simplePortForwardConnect;
    SSH_sshSettings()->funcPortFwdReceivedData          = SSH_EXAMPLE_portForwardReceiveData;
    SSH_sshSettings()->funcPortFwdPtrClosed             = SSH_EXAMPLE_simplePortForwardClose;
    SSH_sshSettings()->funcPortFwdPtrEof                = SSH_EXAMPLE_simplePortForwardEof;
#endif
    /* customize SSH settings and callbacks here */
    SSH_sshSettings()->funcPtrSessionOpen               = SSH_EXAMPLE_simpleAsyncCLI;
    SSH_sshSettings()->funcPtrOpenShell                 = SSH_EXAMPLE_simpleAsyncCLI;
    SSH_sshSettings()->funcPtrWindowChange              = SSH_EXAMPLE_simpleAsyncCLI;
    SSH_sshSettings()->funcPtrReceivedData              = SSH_EXAMPLE_simpleAsyncCLI;
    SSH_sshSettings()->funcPtrStdErr                    = SSH_EXAMPLE_simpleAsyncCLI;
    SSH_sshSettings()->funcPtrEof                       = SSH_EXAMPLE_simpleAsyncCLI;

    SSH_sshSettings()->pBannerString                    = SSH_EXAMPLE_banner;
    SSH_sshSettings()->funcPtrGetAuthAdvertizedMethods  = SSH_EXAMPLE_authMethod;
#if defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
    SSH_sshSettings()->funcPtrPasswordAuth              = SSH_RADIUS_EXAMPLE_authPasswordFunction;
#else
    SSH_sshSettings()->funcPtrPasswordAuth              = SSH_EXAMPLE_authPasswordFunction;
#endif
    SSH_sshSettings()->funcPtrPubKeyAuth                = SSH_EXAMPLE_pubkeyNotify;
    SSH_sshSettings()->funcPtrKeyIntAuthReq             = SSH_EXAMPLE_keyboardInteractiveAuth;
    SSH_sshSettings()->funcPtrReleaseKeyIntReq          = SSH_EXAMPLE_releaseKeyboardInteractiveRequest;

    SSH_sshSettings()->sshListenPort                    = ssh_exampleServerPort;

    /* startup the SSH Server */
    SSH_EXAMPLE_asyncServer();

exit:
    SSH_shutdown();
    SSH_releaseTables();

    CERT_STORE_releaseStore(&pSshCertStore);
}

#endif /* defined( __ENABLE_MOCANA_SSH_SERVER_EXAMPLE__ ) && defined( __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ ) */

