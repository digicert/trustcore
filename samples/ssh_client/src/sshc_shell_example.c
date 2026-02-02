/*
 * sshc_shell_example.c
 *
 * SSHC Shell Example Code
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

#if (defined(__ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE__) && !defined(__ENABLE_DIGICERT_SSH_PORT_FORWARDING__) && !defined(__ENABLE_DIGICERT_SSH_FTP_CLIENT__) && (defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)))

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/client/sshc.h"
#include "../ssh/client/sshc_filesys.h"
#include "../ssh/ssh_defs.h"

#include <string.h>
#include <stdio.h>

#define MAX_SSHC_CONNECTIONS_ALLOWED    1

/* WARNING: Hardcoded credentials used below are for illustrative purposes ONLY.
   DO NOT use hardcoded credentials in production. */
/* Defaults */
#define DEFAULT_USERNAME                              "admin"
#define DEFAULT_PASSWORD                              "secure"
#define DEFAULT_IP                                    "127.0.0.1"
#define DEFAULT_PORT                                  22



/*------------------------------------------------------------------*/

#define KEYBLOB_AUTH_KEY_FILE_NAME                      "sshckeys.dat"
#define AUTH_KEYFILE_NAME                               "sshc_id_dsa.pub"

#ifdef __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__
#define SSHC_EXAMPLE_AUTH_METHOD                        MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE 
#else
#define SSHC_EXAMPLE_AUTH_METHOD                        MOCANA_SSH_AUTH_PASSWORD
#endif

static char * sshc_exampleUserName     = NULL;
static ubyte uname[16];
static char * sshc_examplePassword     = NULL;
static ubyte password[16];
static char * sshc_exampleIPAddress     = NULL;
static unsigned short sshc_exampleServerPort = DEFAULT_PORT;

static sbyte4 mBreakServer;

/*------------------------------------------------------------------*/

static int
SSHC_EXAMPLE_retrieveAuthKeys(int connectionInstance,
                              unsigned char **ppRetKeyBlob, unsigned int *pRetKeyBlobLength)
{
    int             status;
    MOC_UNUSED(connectionInstance);

    *ppRetKeyBlob = NULL;
    *pRetKeyBlobLength = 0;

    if (0 > (status = DIGICERT_readFile(KEYBLOB_AUTH_KEY_FILE_NAME, ppRetKeyBlob, pRetKeyBlobLength)))
        status = ERR_SSH_MISSING_KEY_FILE;

    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE_AUTH__
static int
SSHC_EXAMPLE_testAuthKeys(void)
{
    sbyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLength;
    int     status;

    if (0 <= (status = DIGICERT_readFile(KEYBLOB_AUTH_KEY_FILE_NAME, &pKeyBlob, &keyBlobLength)))
        DIGICERT_freeReadFile(&pKeyBlob);

    return status;
}
#endif /* __ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE_AUTH__ */


/*------------------------------------------------------------------*/

static sbyte4
SSHC_EXAMPLE_releaseAuthKeys(sbyte4 connectionInstance, ubyte **ppFreeKeyBlob)
{
    MOC_UNUSED(connectionInstance);

    DIGICERT_freeReadFile(ppFreeKeyBlob);

    return 0;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE_AUTH__
static int
SSHC_EXAMPLE_computeAuthKeys(void)
{
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLen;
    int     status;


    RTOS_sleepMS(1000);

    /* check for pre-existing set of host keys */
    if (0 > (status = SSHC_EXAMPLE_testAuthKeys()))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSHC_EXAMPLE_computeAuthKeys: host key does not exist, computing new key...");

        /* if not, compute new host keys */
#ifdef __ENABLE_DIGICERT_SSH_RSA_SUPPORT__
        if (0 > (status = CA_MGMT_generateNakedKey(akt_rsa, 2048, &pKeyBlob, &keyBlobLen)))
#elif __ENABLE_DIGICERT_SSH_DSA_SUPPORT__
        if (0 > (status = CA_MGMT_generateNakedKey(akt_dsa, 2048, &pKeyBlob, &keyBlobLen)))
#endif
            goto exit;

        status = DIGICERT_writeFile(KEYBLOB_AUTH_KEY_FILE_NAME, pKeyBlob, keyBlobLen);

        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSHC_EXAMPLE_computeAuthKeys: host key computation completed.");

        /* At this point, the client's public key can generated in the BASE64 encoded format, so that it is 
         * ready to be exported to the server. The following code snippet will do the needful.
         *
         * Example code snippet for generating and exporting the client's public key in BASE64 format:
         * SSHC_generateServerAuthKeyFile(pKeyBlob, keyBlobLen, &pEncodedKeyBlob, &encodedKeyBlobLen);
         * DIGICERT_writeFile("id_dsa.pub", pEncodedKeyBlob, encodedKeyBlobLen);
         * SSHC_freeGenerateServerAuthKeyFile(&pEncodedKeyBlob);
         */
    }

exit:
    if (NULL != pKeyBlob)
        CA_MGMT_freeNakedKey(&pKeyBlob);

    return status;
}
#endif /* __ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE_AUTH__ */


/*------------------------------------------------------------------*/

static int
SSHC_EXAMPLE_ServerPubKeyAuthUpcall(int connectionInstance,
                                    const unsigned char *pPubKey, unsigned int pubKeyLength)
{
    ubyte*  pStoredHostPublicKey = NULL;
    ubyte4  storedHostPublicKeyLength;
    sbyte4  result = 0;
    MOC_UNUSED(connectionInstance);

    /* The SSH Client will only call this function, if the server's */
    /* public key matched the signature provided.  We need to now */
    /* verify that the public key is an acceptable public key (i.e. on record) */

    /* we would want to extract the server's IP address from connectionInstance */
    /* then use that to look up the appropriate host key stored file */

    /* make sure the server provided pubkey matches a pub key on file */
    if (0 > DIGICERT_readFile(AUTH_KEYFILE_NAME, &pStoredHostPublicKey, &storedHostPublicKeyLength))
    {
        /* save the server's host key for the next time we connect */
        /* this code should be smarter; needs to save host key based on server identity */
        DIGICERT_writeFile(AUTH_KEYFILE_NAME, (ubyte *)pPubKey, pubKeyLength);

        /* we accept first time server host keys */
        result = 1;
        goto exit;
    }

    /* write code to compare keys here */
    if ((pubKeyLength != storedHostPublicKeyLength) || (0 != memcmp(pPubKey, pStoredHostPublicKey, pubKeyLength)))
        goto exit;

    /* if necessary, do additional checks here */

    /* finally, if we do not recognize this IP address we should store the ip address in a file */
    /* a simple scheme filename convention: /keys/host/sshc/ip_<ip.ad.dr.ess>.pubkey */

    result = 1; /* we made it to the end! */

exit:
    if (NULL != pStoredHostPublicKey)
        DIGICERT_freeReadFile(&pStoredHostPublicKey);

    return result;
}


/*------------------------------------------------------------------*/

static int
SSHC_EXAMPLE_UserAuthRequestInfoUpcall(int connectionInstance,
                                       unsigned char *pAuthNameList, unsigned int authNameListLen,
                                       unsigned char **ppUserName, unsigned int *pUserNameLength,
                                       unsigned int *pMethod)
{
    int status = 0;
    MOC_UNUSED(connectionInstance);
 
    if(SSHC_EXAMPLE_AUTH_METHOD == MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE)
    {
        printf("Username: ");
        scanf("%s",uname);
        *ppUserName = (unsigned char*)uname;
        *pUserNameLength = (unsigned int)strlen((const char *)uname);
    }
    else
    {
        *ppUserName = (unsigned char*)sshc_exampleUserName;
        *pUserNameLength = (strlen(sshc_exampleUserName));
    }

    *pMethod = SSHC_EXAMPLE_AUTH_METHOD;

    return status;
}


/*------------------------------------------------------------------*/

static int
SSHC_EXAMPLE_UserPasswordUpcall(int connectionInstance,
                                unsigned char *pUserName, unsigned int userNameLength,
                                unsigned char **ppUserPassword, unsigned int *pUserPasswordLength)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(pUserName);
    MOC_UNUSED(userNameLength);

    if(SSHC_EXAMPLE_AUTH_METHOD == MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE)
    {
        printf("Password: ");
        scanf("%s",password);     /* For unix/linux/BSD getpass() can be used for getting password */
        *ppUserPassword = (unsigned char*)password;
        *pUserPasswordLength = (unsigned int)strlen((const char *)password);
    }
    else
    { 
        *ppUserPassword = (unsigned char*)sshc_examplePassword;
        *pUserPasswordLength = (unsigned int)strlen(sshc_examplePassword);
    }

    return 0;
}


/*------------------------------------------------------------------*/

static void
SSHC_EXAMPLE_AuthOpen(int connectionInstance)
{
    printf("Connection authenticated: %d\n", connectionInstance);
}


/*------------------------------------------------------------------*/

static void
setParameter(char ** param, char *value)
{
    *param = MALLOC((strlen(value))+1);
    DIGI_MEMCPY(*param, value, strlen(value));
    (*param)[strlen(value)] = '\0';
}

/*------------------------------------------------------------------*/
 
static void
SSHC_EXAMPLE_displayHelp(char *prog)
{

    printf("  option:\n");
    printf("    -ip <ipaddr>    sets remote IP address \n");
    printf("    -username <username>       sets username for remote host\n");
    printf("    -password <password>       sets password for remote host\n");
    printf("    -port <port>       sets port for remote host\n");

    printf("\n");
    return;
} /*SSHC _EXAMPLE_displayHelp */

/*------------------------------------------------------------------*/

static MSTATUS
SSHC_EXAMPLE_reKeyFunction(sbyte4 connectionInstance,
                                 intBoolean initiatedByRemote)
{
 printf("SSHC_EXAMPLE_reKeyFunction: ... initiatedByRemote = %d\n", initiatedByRemote);
 return OK;

}  /* SSHC_EXAMPLE_reKeyFunction */

extern sbyte4
SSHC_EXAMPLE_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;
    int i, opt;
    int ipSet=0, portSet=0, userSet=0, pwdSet=0;
    char * temp;

    if ((2 <= argc) && ('?' == argv[1][0]))
    {
        SSHC_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

    for (i = 1; i < argc; i++) /*Skiping argv[0] which is example progam name*/
    {
        if (strcmp(argv[i], "-ip") == 0)
        {
            ipSet = 1; /*Ip should not be set to dafault*/
            i++;
            setParameter(&sshc_exampleIPAddress, argv[i]);
            continue;
        }
        else if (strcmp(argv[i], "-port") == 0)
        {
            portSet = 1; /*Port should not be set to default*/
            i++;
            temp = argv[i];
            sshc_exampleServerPort = atoi(argv[i]);
            continue;
        }
        else if (strcmp(argv[i], "-username") == 0) 
        {
            userSet = 1; /*Username should not be set to default*/
            i++;
            setParameter(&sshc_exampleUserName, argv[i]);
            continue;
        }
        else if (strcmp(argv[i], "-password") == 0) 
        {
            pwdSet = 1; /*password should not be set to default*/
            i++;
            setParameter(&sshc_examplePassword, argv[i]);
            continue;
        } 
    } /*for*/
    
    /*Set defaults if nothing entered from command line*/
    if (!ipSet)
    {
        setParameter(&sshc_exampleIPAddress, DEFAULT_IP);
    }
    if (!userSet)
    {
        setParameter(&sshc_exampleUserName, DEFAULT_USERNAME);
    }
    if (!pwdSet)
    {
        setParameter(&sshc_examplePassword, DEFAULT_PASSWORD);
    }
    /*End of defaults*/

    return status;
  
} /* SSHC_EXAMPLE_getArgs */ 

/*------------------------------------------------------------------*/

extern void
SSH_CLIENTEXAMPLE_main(int dummy)
{
    int                     connectionInstance = -1;
    TCP_SOCKET              mySocket;
    char*                   serverIpAddress = (char*)sshc_exampleIPAddress;
    unsigned short          serverPort = (unsigned short)sshc_exampleServerPort;
    ubyte4                  bytesSent;
    int                     status = OK;
    sbyte                   mesg[MAX_SESSION_WINDOW_SIZE];
    sbyte4                  mesgType;
    ubyte8                  pRetNumBytes = 0;
    MOC_UNUSED(dummy);

#ifdef __FREERTOS_RTOS__
    /* Suspend till DIGICERT_initDigicert has completed its work */
    RTOS_taskSuspend(NULL);
    /* After resumption if initMocana has returned an error then we need to exit out */
    if (0 > gMocanaAppsRunning)
        goto exit;
#endif

    if (0 > (status = SSHC_init(MAX_SSHC_CONNECTIONS_ALLOWED)))
        goto exit;

    SSHC_sshClientSettings()->funcPtrServerPubKeyAuth              = SSHC_EXAMPLE_ServerPubKeyAuthUpcall;
    SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfo   = SSHC_EXAMPLE_UserAuthRequestInfoUpcall;
    SSHC_sshClientSettings()->funcPtrRetrieveUserPassword          = SSHC_EXAMPLE_UserPasswordUpcall;
    SSHC_sshClientSettings()->funcPtrAuthOpen                      = SSHC_EXAMPLE_AuthOpen;

    SSHC_sshClientSettings()->funcPtrRetrieveNakedAuthKeys         = SSHC_EXAMPLE_retrieveAuthKeys;
    SSHC_sshClientSettings()->funcPtrReleaseNakedAuthKeys          = SSHC_EXAMPLE_releaseAuthKeys;
    SSHC_sshClientSettings()->funcPtrSessionReKey                  = SSHC_EXAMPLE_reKeyFunction;

#ifdef __ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE_AUTH__
    /* if using public key authentication, create client auth keys */
    /* this is optional, in most instance you will probably use password authentication */
    if (0 > SSHC_EXAMPLE_computeAuthKeys())
        goto exit;
#endif

    if (OK > (status = TCP_CONNECT(&mySocket, (sbyte *)serverIpAddress, serverPort)))
        goto exit;

    if (OK > (status = SSHC_connect(mySocket, &connectionInstance, NULL, NULL)))
        goto exit;

    /* in between connect and negotiate you can customize the session establishment here */

#if 0
    /* for example, rather than the default behavior chosing the strongest cipher */
    /* available, we can chose a particular cipher suite */
    if (OK > (status = SSHC_useThisCipher(connectionInstance, "3des-cbc")))
        goto exit;
#endif

    /* setup a secure, fully authenticated session */
    if (OK > (status = SSHC_negotiateConnection(connectionInstance)))
        goto exit;

    /* open up state */
    if (OK > (status = SSHC_negotiateSession(connectionInstance)))
        goto exit;

    /* negotiate PTY */
    if (OK > (status = SSHC_negotiatePtyTerminalChannelRequest(connectionInstance)))
        goto exit;

    /* negotiate shell */
    if (OK > (status = SSHC_negotiateShellChannelRequest(connectionInstance)))
        goto exit;

    while(1)
    {
        if (OK > (status = SSHC_sendMessage(connectionInstance, (ubyte *)"Hello World!", 12, (ubyte4 *)&bytesSent)))
            goto exit;

        if (OK > (status = SSHC_recvMessage(connectionInstance, &mesgType, mesg, (sbyte4 *)&bytesSent, 0)))
        {
            printf("\nSSHC_recvMessage: return status = %d.\n", status);
            goto exit;
        }

        if (OK > (status = SSHC_setTerminalTextWindowSize(connectionInstance, 40, 20)))
        {
            printf("\nSSHC_setTerminalTextWindowSize: return status = %d.\n", status);
            goto exit;
        }

        if (OK > (status = SSHC_recvMessage(connectionInstance, &mesgType, mesg, (sbyte4 *)&bytesSent, 0)))
        {
            printf("\nSSHC_recvMessage: return status = %d.\n", status);
            goto exit;
        }

        /* This change is to demonstrate re-keying after 10000 Bytes */
        SSHC_numBytesTransmitted(connectionInstance, &pRetNumBytes);

        if (pRetNumBytes != 0)
        {
            if(pRetNumBytes >= 10000)
            {
                status = SSHC_initiateReKey(connectionInstance, 10000);
                printf("\nStatus after SSHC_initiateRekey: %d\n", status);

                if (OK > (status = SSHC_negotiateConnection(connectionInstance)))
                    printf("\nSSHC_negotiateConnection: return status = %d.\n", status);
                /* the 'break' below ensure that the re-key will happen only once */
                break; 
            }
        }
    }
exit:
    SSHC_close(connectionInstance);

    if (sshc_exampleIPAddress)
        FREE(sshc_exampleIPAddress);

    if (sshc_examplePassword)
        FREE(sshc_examplePassword);

    if(sshc_exampleUserName)
        FREE(sshc_exampleUserName);

    SSHC_shutdown();

    return;

} /* SSH_CLIENTEXAMPLE_main */

#endif /* (defined(__ENABLE_DIGICERT_SSH_CLIENT_EXAMPLE__) && defined(__ENABLE_DIGICERT_SSH_FTP_CLIENT__) && defined(__ENABLE_DIGICERT_EXAMPLES__)) */
