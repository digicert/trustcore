/*
 * openssl_server.c
 *
 * Implementation of secure openssl server
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifndef __RTOS_WIN32__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#else
#include <WinSock2.h>
#include "ossl_sample_utils.h"
#include <ms/applink.c>
#endif

#include <openssl/opensslconf.h>
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <ssl/ssl_locl.h>
#else
#include <ssl/ssl_local.h>
#endif
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#if defined(__ENABLE_DIGICERT_TAP__)
#include "smp/smp_cc.h"
#include "tap/tap_api.h"
#include "tap/tap_utils.h"
#include "tap/tap_smp.h"
#include "crypto/mocasym.h"
#include "crypto/mocasymkeys/tap/rsatap.h"
#include "crypto/mocasymkeys/tap/ecctap.h"
#include "crypto_interface/cryptointerface.h"
#endif
#include "common/tpm2_path.h"


#define OK                  0

#define SERVER_NAME_LEN     256
#define SERVER_IP_LEN       15
#define CERT_MAX_LEN        256
#define KEY_MAX_LEN         256
#define PORTNUMBER_LEN      6
#define TAP_CONFIG_FILE_LEN 128

typedef int sbyte4;

#ifdef __ENABLE_DIGICERT_TAP__
    static TAP_Context *g_pTapContext                 = NULL;
    static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
    static TAP_CredentialList *g_pTapKeyCred          = NULL;
    static TAP_ModuleList g_moduleList                = {0};
    char tapConfigFile[TAP_CONFIG_FILE_LEN+1]         = "\0";
    char tapKeySource[TAP_CONFIG_FILE_LEN]           = "\0";
    static ubyte2 sslsTapProvider = 0;

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    char tapServer[SERVER_NAME_LEN+1] = "\0";
    char tapServerPortString[PORTNUMBER_LEN+1] = "\0";
#endif
#endif

char portNumberString[PORTNUMBER_LEN+1] = "\0";
char serverName[SERVER_NAME_LEN+1] = "\0";
char certFile[CERT_MAX_LEN+1] = "\0";
char cacertFile[CERT_MAX_LEN+1] = "\0";
char keyFile[KEY_MAX_LEN+1] = "\0";
char keyStoreFolder[CERT_MAX_LEN+1]       = "\0";
static unsigned short  sslsServerPort     = 0;

char *getFullPath(const char *directory, const char *name, char **ppFull)
{
    int len;

    /* clean up */
    if (*ppFull)
        free(*ppFull);

    /* allocate enough memory for directory+name+separators+padding */
    len = strlen(directory);
    len += strlen(name);
    len += 10;
    *ppFull = malloc(len);
    if (NULL == *ppFull)
        return *ppFull;

    /* Create concatenated string */
    strcpy(*ppFull, directory);
    strcat(*ppFull, "/");
    strcat(*ppFull, name);

    printf("Full path is:  %s\n", *ppFull);
    return *ppFull;
}

void
printUsage(char *program)
{
    (void) printf(" Usage: %s\n", program);
    (void) printf("  options:\n");
    (void) printf("    --h                                 Help\n");
    (void) printf("    --ssl_port <port>                   SSL server port\n");
    (void) printf("    --ssl_servername <server_name>      SSL server name\n");
    (void) printf("    --ssl_certpath <path_to_files>      directory path to the cert files\n");
    (void) printf("    --ssl_server_cert <cert_name>       name of the server cert \n");
    (void) printf("    --ssl_server_keyblob <blob_name>    name of the server keyblob\n");
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    (void) printf("    --ssl_ca_cert <cert_name>           name of the CA cert \n");
#endif
#if (defined(__ENABLE_DIGICERT_TAP__))
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    (void) printf("    --tap_server_port <tap_server_port> TAP server port\n");
    (void) printf("    --tap_server_name <tap_server_name> TAP server name\n");
#endif
    (void) printf("    --tap_keysource <TPM2|TPM1.2|PKCS11> key source\n");
    (void) printf("    --tap_config_file <tap_config_file> TAP config file\n");
#endif
    (void) printf("\n");
}

void
setDefaultArguments()
{
    const char defaultServerName[] = "webapptap.securitydemos.net";
    const char defaultServerIp[] = "127.0.0.1";
    const char defaultPortNum[] = "1440";
    const char defaultTapFile[] = TPM2_CONFIGURATION_FILE;
    const char defaultTapKeySource[] = "TPM2";

    const char defaultCertFile[] = "ECCCertCA384.pem";
    const char defaultKeyFile[]  = "ECCCertCA384Key.pem";
    const char defaultCaFile[]   = "ClientECCCertCA384.pem";
#ifdef __RTOS_WIN32__
    /* Sample gets output to where .dll's so the bin_win32 path doesn't have to be
     * added to the PATH environment variable. For windows check for the keystore
     * in the current directory.
     */
    const char defaultKeyFolder[] = "./keystore";
#else
    const char defaultKeyFolder[] = "../../../bin/keystore";
#endif

    strncpy(portNumberString, defaultPortNum, sizeof(portNumberString));

    /* use the ip address by default */
    strncpy(serverName, defaultServerIp, sizeof(serverName));

    strncpy(certFile, defaultCertFile, sizeof(certFile));
    strncpy(keyFile, defaultKeyFile, sizeof(keyFile));

    strncpy(keyStoreFolder, defaultKeyFolder, sizeof(defaultKeyFolder));

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    strncpy(cacertFile, defaultCaFile, sizeof(cacertFile));
#endif

#if (defined(__ENABLE_DIGICERT_TAP__))
    strncpy(tapConfigFile, defaultTapFile, sizeof(tapConfigFile));
    strncpy(tapKeySource, defaultTapKeySource, sizeof(tapKeySource));
#endif

}

void printAllArguments()
{

    printf("serverName : %s\n", serverName);
    printf("portNumber : %d\n", sslsServerPort);
    printf("certFile : %s\n",   certFile);
    printf("keyFile : %s\n",    keyFile);
    printf("keyStoreFolder : %s\n", keyStoreFolder);
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    printf("cacertFile : %s\n", cacertFile);
#endif
#if (defined(__ENABLE_DIGICERT_TAP__))
    printf("tapConfigFile : %s\n", tapConfigFile);
    printf("tapKeySource : %s\n",  tapKeySource);
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    printf("tap_server_name : %s\n", tapServer);
    printf("tap_server_port : %s\n", tapServerPortString);
#endif
#endif
}

int processArguments(int argc, char **argv)
{
    int c;
    int digit_optind = 0;
    int certPresent = 0, keyfilePresent = 0, serverIpPresent = 0;
    int serverNamePresent = 0;
    int serverPort = 0;
    /* set the default */
    setDefaultArguments();
    char *shortOptStr = NULL;

    while (1)
    {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
                {"ssl_port",           required_argument, 0, 'p'},
                {"ssl_servername",     required_argument, 0, 's'},
                {"ssl_ca_cert",        required_argument, 0, 'a'},
                {"ssl_server_cert",    required_argument, 0, 'c'},
                {"ssl_server_keyblob", required_argument, 0, 'k'},
                {"ssl_certpath",       required_argument, 0, 'f'},
#if (defined(__ENABLE_DIGICERT_TAP__))
            {"tap_config_file",        required_argument, 0, 't'},
            {"tap_keysource",          required_argument, 0, 'm'},
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
            {"tap_server_name",    required_argument, 0, 'v'},
            {"tap_server_port",    required_argument, 0, 'o'},
#endif
#endif
                {"help",               no_argument,       0, 'h'},
                {0,                    0,                 0, 0},
        };

#ifndef __RTOS_WIN32__
#if (defined(__ENABLE_DIGICERT_TAP__))
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
       shortOptStr = "p:s:c:a:k:t:v:o::m:f:h";
#else
        /* local */
        shortOptStr = "p:s:c:a:k:t:f:h";
#endif /* __ENABLE_DIGICERT_TAP_REMOTE__ */
#else
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
        shortOptStr = "p:s:c:a:k:f:h";
#else
        shortOptStr = "p:s:c:k:f:h";
#endif
#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* ! __RTOS_WIN32__ */

        c = getopt_long(argc, argv, shortOptStr, long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
            case 'p':
                strncpy(portNumberString, optarg, PORTNUMBER_LEN);
                break;

            case 's':
                serverNamePresent = 1;
                strncpy(serverName, optarg, SERVER_NAME_LEN);
                break;

            case 'f':
                strncpy(keyStoreFolder, optarg, CERT_MAX_LEN);
                break;

            case 'c':
                certPresent = 1;
                strncpy(certFile, optarg, CERT_MAX_LEN);
                break;
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
            case 'a':
                strncpy(cacertFile, optarg, CERT_MAX_LEN);
                break;
#endif
            case 'k':
                keyfilePresent = 1;
                strncpy(keyFile, optarg, KEY_MAX_LEN);
                break;
#if (defined(__ENABLE_DIGICERT_TAP__))
            case 't':
                strncpy(tapConfigFile, optarg, TAP_CONFIG_FILE_LEN);
                break;
            case 'm':
                strncpy(tapKeySource, optarg, TAP_CONFIG_FILE_LEN);
                break;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
            case 'v':
                strncpy(tapServer, optarg, SERVER_NAME_LEN);
                break;

            case 'o':
                strncpy(tapServerPortString, optarg, PORTNUMBER_LEN);
                break;
#endif
#endif
            case 'h':
            default:
                return (1);
        }
    }

    serverPort = atoi(portNumberString) ;
    if ( serverPort )
    {
        sslsServerPort = serverPort;
    }

#if (defined(__ENABLE_DIGICERT_TAP__))
    if(DIGI_STRCMP((const sbyte *)tapKeySource, (const sbyte *)"TPM2") == 0)
    {
        sslsTapProvider = TAP_PROVIDER_TPM2;
    }
    else if(DIGI_STRCMP((const sbyte *)tapKeySource, (const sbyte *)"PKCS11") == 0)
    {
        sslsTapProvider = TAP_PROVIDER_PKCS11;
    }
    else
    {
        printf("ERROR : TAP Provider %s not available\n", tapKeySource);
        return 1;
    }
#endif
    return (0);
}

#if (defined(__ENABLE_DIGICERT_TAP__))
static sbyte4
SSL_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Module *pModule = NULL;

    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        if (sslsTapProvider == TAP_PROVIDER_PKCS11)
        {
            int i = 0;
            for (i = 0; i < g_moduleList.numModules; i++)
            {
                /* moduleId:0 is for software */
                if (0 != g_moduleList.pModuleList[i].moduleId)
                {
                    pModule = &g_moduleList.pModuleList[i];
                    break;
                }
            }
        }
        else
        {
            pModule = &g_moduleList.pModuleList[0];
        }

        /* Initialize context on first module */
        if (NULL == g_pTapContext)
        {
            status = TAP_initContext(pModule,
                                    g_pTapEntityCred, NULL,
                                    &g_pTapContext, pErrContext);
            if (OK != status)
            {
                printf("TAP_initContext : %d\n", status);
                goto exit;
            }
        }

        *ppTapEntityCred = g_pTapEntityCred;
        *ppTapKeyCred    = g_pTapKeyCred;

        *ppTapContext    = g_pTapContext;
    }
    else
    {
#if 0
        /* Destroy the TAP context */
        if (OK > (status = TAP_uninitContext(ppTapContext, pErrContext)))
        {
            printf("SSL_EXAMPLE: TAP_uninitContext failed with status: %d\n", status);
        }
#endif
    }

exit:
    return status;
}

static MSTATUS
SSL_InitializeTap(ubyte *pTpm2ConfigFile,
                  TAP_EntityCredentialList **ppTapEntityCred,
                  TAP_CredentialList **ppTapKeyCred)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = { 0 };
    TAP_Module *pModule = NULL;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    status = TAP_readConfigFile(pTpm2ConfigFile, &configInfoList.pConfig[0].configInfo, 0);
    if (OK != status)
    {
        printf("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = sslsTapProvider;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("TAP_init : %d", status);
        goto exit;
    }
    tapInit = TRUE;

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    connInfo.serverName.bufferLen = DIGI_STRLEN(tapServer) + 1;
    status = DIGI_CALLOC((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY((void *)(connInfo.serverName.pBuffer), (void *)tapServer, DIGI_STRLEN(tapServer));
    if (OK != status)
    goto exit;

    connInfo.serverPort = atoi(tapServerPortString);

    status = TAP_getModuleList(&connInfo, sslsTapProvider, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, sslsTapProvider, NULL,
                               &g_moduleList, pErrContext);
#endif
    if (OK != status)
    {
        printf("TAP_getModuleList : %d \n", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == g_moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
        goto exit;
    }

    if (sslsTapProvider == TAP_PROVIDER_PKCS11)
    {
        int i = 0;
        for (i = 0; i < g_moduleList.numModules; i++)
        {
            /* moduleId:0 is for software */
            if (0 != g_moduleList.pModuleList[i].moduleId)
            {
                pModule = &g_moduleList.pModuleList[i];
                break;
            }
        }
    }
    else
    {
        pModule = &g_moduleList.pModuleList[0];
    }

    /* For local TAP, parse the config file and get the Entity Credentials */
#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = TAP_getModuleCredentials(pModule,
                                      pTpm2ConfigFile, 0,
                                      &pEntityCredentials,
                                      pErrContext);

    if (OK != status)
    {
        printf("Failed to get credentials from Credential configuration file %d\n", status);
        goto exit;
    }
#endif

    *ppTapEntityCred = pEntityCredentials;
    *ppTapKeyCred    = pKeyCredentials;

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            printf("TAP_UTILS_freeConfigInfoList : %d\n", status);
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))

    if((void **)&(connInfo.serverName.pBuffer))
        free((void *)connInfo.serverName.pBuffer);

#endif

exit:
    return status;

}
#endif /*defined(__ENABLE_DIGICERT_TAP__) */

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )

SSL_SESSION *pSessionListHeader = NULL;
const unsigned char* pPskticket = NULL ;
size_t pskTicketLen = 0;
char *pSetNumTickets       = "config SSL_set_num_tickets ";
char *pSetMaxEarlyDataSize = "config SSL_set_max_early_data ";

void free_session_list()
{
    SSL_SESSION *pSessList = pSessionListHeader;
    SSL_SESSION *pSessFree = NULL;

    while ( NULL != pSessList )
    {
        pSessFree = pSessList;
        pSessList = pSessList->next;
        SSL_SESSION_free(pSessFree);
        pSessFree = NULL;
    }

}

static int find_session_cb(SSL *ssl, const unsigned char *pIdentity,
                           size_t identityLen, SSL_SESSION **Psess)
{
    SSL_SESSION *pPrevSessNode = pSessionListHeader;

    SSL_SESSION *pSessList = pSessionListHeader;
    const unsigned char* pPskticket = NULL ;
    size_t pskTicketLen = 0;

    while ( NULL != pSessList )
    {
        SSL_SESSION_get0_ticket(pSessList, &pPskticket, &pskTicketLen);

        if (0 == memcmp(pPskticket, pIdentity, identityLen ))
        {
            *Psess = (SSL_SESSION *)SSL_SESSION_dup(pSessList);
            /* delete the node after finding, it enables single session ticket */
            pPrevSessNode->next = pSessList->next;
            SSL_SESSION_free(pSessList);
            return 1;
        }

        pPrevSessNode = pSessList;
        pSessList = pSessList->next;
    }

    return 0;
}

static SSL_SESSION *get_session_cb(SSL *ssl, const unsigned char *pIdentity,
                                   int identityLen, int *do_copy)
{
    SSL_SESSION *pSess         = NULL;
    SSL_SESSION *pPrevSessNode = NULL;
    SSL_SESSION *pSessList     = pSessionListHeader;
    *do_copy = 0;

    while ( NULL != pSessList )
    {
        if ((identityLen == (int)pSessList->session_id_length) &&
            (!memcmp(pSessList->session_id, pIdentity, identityLen)))
        {
            pSess = (SSL_SESSION *)SSL_SESSION_dup(pSessList);
            /* delete the node after finding, it enables single session ticket */
            if (pPrevSessNode)
            {
                pPrevSessNode->next = pSessList->next;
            }
            else
            {
                pSessionListHeader = pSessList->next;
            }
            SSL_SESSION_free(pSessList);
            return pSess;
        }

        pPrevSessNode = pSessList;
        pSessList = pSessList->next;
    }

    return pSess;
}

static void del_session_cb(SSL_CTX *pCtx, SSL_SESSION *pSession)
{
    SSL_SESSION *pPrevSessNode = NULL;
    SSL_SESSION *pSessList     = pSessionListHeader;

    while ( NULL != pSessList )
    {
        if ((pSession->session_id_length == pSessList->session_id_length) &&
            (!memcmp(pSessList->session_id, pSession->session_id, pSession->session_id_length)))
        {
            /* delete the node after finding */
            if (pPrevSessNode)
            {
                pPrevSessNode->next = pSessList->next;
            }
            else
            {
                pSessionListHeader = pSessList->next;
            }
            SSL_SESSION_free(pSessList);
        }

        pPrevSessNode = pSessList;
        pSessList = pSessList->next;
    }
}
static int new_session_cb(SSL *s, SSL_SESSION *pSess)
{
    BIO *bio_c_out = NULL;
    SSL_SESSION *pNewSessNode;
    SSL_SESSION *pSessList = pSessionListHeader;

    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    bio_c_out  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* SSL_SESSION_get0_ticket(SSL_get_session(ssl), &pPskticket, &pskTicketLen); */
    pNewSessNode = (SSL_SESSION *)SSL_SESSION_dup(pSess);

    /* Add a new node to the bottom of a list */
    while ( (NULL != pSessList ) && (NULL != pSessList->next))
    {
            pSessList = pSessList->next;
    }

    if (NULL != pSessList)
    {
        pSessList->next = pNewSessNode;
    }
    else
    {
        pSessionListHeader = pNewSessNode;
    }

    BIO_printf(bio_c_out, "---\n New Session Ticket generated :\n" );
    if (bio_c_out)
        BIO_free(bio_c_out);
    return 1;

}
#endif

/*
 *  client_hello_cb returns
 *  SSL_CLIENT_HELLO_SUCCESS    on success
 *  SSL_CLIENT_HELLO_ERROR      on failure
 *  SSL_CLIENT_HELLO_RETRY      to suspend processing
 */
static int client_hello_cb(SSL *s, int *al, void *arg)
{
    int legacy_version; 
    const unsigned char *random;
    size_t random_len;
    const unsigned char *session_id;
    size_t session_id_len;
    const unsigned char *ciphers;
    size_t ciphers_len;
    const unsigned char *compression_methods;
    size_t compression_methods_len;
    int *extensions;
    size_t extensions_len;
    int ext_type;
    size_t ext_len;
    const unsigned char *ext_value;
    int ret;

    printf("client hello callback:\n");
    if (s == NULL || al == NULL)
    {
        ret = SSL_CLIENT_HELLO_ERROR;
        goto exit;
    }

    legacy_version = SSL_client_hello_get0_legacy_version(s);

    random_len = SSL_client_hello_get0_random(s, &random);
    session_id_len = SSL_client_hello_get0_session_id(s, &session_id);
    ciphers_len = SSL_client_hello_get0_ciphers(s, &ciphers);
    compression_methods_len = SSL_client_hello_get0_compression_methods(s, &compression_methods);
    if(!SSL_client_hello_get1_extensions_present(s, &extensions, &extensions_len))
    {
        printf("SSL_client_hello_get1_extensions_present return bad status\n");
        ret = SSL_CLIENT_HELLO_ERROR;
        goto exit;
    }

    printf("legacy version: %04x\n", legacy_version);
    printf("random (%ld): ", session_id_len);
    for (int i = 0;i < random_len; i++)
    {
        printf("%02x ", random[i]);
    }
    printf("\n");

    printf("session ID (%ld): ", session_id_len);
    if (session_id_len > 0)
    {
        for (int i = 0;i < session_id_len; i++)
        {
            printf("%02x:", session_id[i]);
        }
    }
    printf("\n");

    printf("ciphers (%ld):\n", ciphers_len);
    if (ciphers_len > 0)
    {
        for (int i = 0;i < ciphers_len-1; i+=2)
        {
            printf("  %04x\n", (ciphers[i] << 8) | ciphers[i+1]);
        }
    }

    printf("compression methods (%ld):\n", compression_methods_len);
    if (compression_methods_len > 0)
    {
        for (int i = 0;i < compression_methods_len; i++)
        {
            printf("  %02x\n", compression_methods[i]);
        }
    }
    printf("extensions list (%ld):\n", extensions_len);
    if (extensions_len > 0)
    {
        for (int i = 0;i < extensions_len; i++)
        {
            ext_type = extensions[i];
            if (!SSL_client_hello_get0_ext(s, ext_type, &ext_value, &ext_len))
            {
                printf("%02x extension not found\n", ext_type);
                ret = SSL_CLIENT_HELLO_ERROR;
                goto exit;
            }
            printf("type:   %02x\n", ext_type);
            printf("length: %ld\n", ext_len);
            printf("value:\n    ");
            for (int i = 0;i < ext_len ; i++)
            {
                printf("%02x ", ext_value[i]);
                if (i%16 == 15) printf("\n    ");
            }
            printf("\n");
        }

        free(extensions);
    }

    ret = SSL_CLIENT_HELLO_SUCCESS;
exit:
    return ret;
}

int main(int argc, char *argv[])
{
    SSL_CTX* ctx = NULL;
    int fd,ret;
    BIO* bio = NULL;
    BIO* outbio = NULL;
    SSL* ssl = NULL;
    struct sockaddr_in server_addr;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    X509 *cert = NULL;
    X509_NAME *certname = NULL;
    const SSL_METHOD *method = NULL;
    char buffer[256];
    int retval;
    int status;
    int client;
    char * fullpath = NULL;
    int faultCounter = 0;
    int setNumTicketsValue = 0;
    int setMaxEarlyDataSizeValue = 0;
    int readEarlyDataRequest = 0;
    size_t readbytes = 0;
    int s_server_session_id_context = 1;
    int option = 1;

#if (defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    TAP_ErrorContext *pErrContext = NULL;
#endif

    /* ---------------------------------------------------------- *
    * Process command line arguments.                            *
    * ---------------------------------------------------------- */
    if (processArguments(argc, argv) != 0)
    {
        printUsage(argv[0]);
        exit (EXIT_FAILURE);
    }
    printAllArguments();
    /* EVP_default_properties_enable_fips() sets the 'fips=yes' to be a default property
     * if enable is non zero, otherwise it clears 'fips' from the default property query
     * for the given libctx. */
    EVP_default_properties_enable_fips(NULL, getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);

    /* ---------------------------------------------------------- *
    * These function calls initialize openssl for correct work.  *
    * VxWorks builds call these as part of init, so don't call   *
    * them here.                                                 *
    * ---------------------------------------------------------- */
#ifndef __RTOS_VXWORKS__
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
#endif

    /* ---------------------------------------------------------- *
    * Create the BIOs.                                           *
    * ---------------------------------------------------------- */
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
    * initialize SSL library and register algorithms             *
    * ---------------------------------------------------------- */
    if (SSL_library_init() < 0)
    {
        BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
    }

    /* ---------------------------------------------------------- *
    * Set SSLv23                                *
    * ---------------------------------------------------------- */
    method = SSLv23_server_method();

    /* ---------------------------------------------------------- *
    * Try to create a new SSL context                            *
    * ---------------------------------------------------------- */
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        BIO_printf(outbio, "Unable to create a new SSL context structure.\n");
        goto EXIT;
    }

    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);

    /* ---------------------------------------------------------- *
    * These should be enabled for mutual auth                    *
    * ---------------------------------------------------------- */
 #if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || (defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__)) )
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_id_context(ctx, (void *)&s_server_session_id_context,
                        sizeof(s_server_session_id_context));
#endif

  /* ---------------------------------------------------------- *
   * Initialize TAP info                                        *
   * ---------------------------------------------------------- */
#if (defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK != (status = SSL_InitializeTap(tapConfigFile,
                                               &g_pTapEntityCred,
                                               &g_pTapKeyCred)))
    {
        printf("SSL_InitializeTap failed. status = %d\n", status);
        goto EXIT;
    }
    else
    {
        printf("SSL_InitializeTap worked!\n");
    }

    if (OK > (status = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSL_getTapContext)))
    {
        printf("CRYPTO_INTERFACE_registerTapCtxCallback failed. status = %d\n", status);
        goto EXIT;
    }
    else
    {
        printf("CRYPTO_INTERFACE_registerTapCtxCallback worked!\n");
    }
#endif

    getFullPath(keyStoreFolder, certFile, &fullpath);

    if (1 != (status = SSL_CTX_use_certificate_file(ctx, fullpath, SSL_FILETYPE_PEM)))
    {
        printf("Error: SSL_CTX_use_certificate_file() failed | status = %d\n", status);
        goto EXIT;
    }

    printf("Status after certificate_file : %d \n", status);

    getFullPath(keyStoreFolder, keyFile, &fullpath);

    if(1 != (status = SSL_CTX_use_PrivateKey_file(ctx, fullpath, SSL_FILETYPE_PEM)))
    {
        printf("Error: SSL_CTX_use_PrivateKey_file() failed | status : %d\n", status);
        goto EXIT;
    }
    printf("Status after PrivateKey_file : %d \n", status);

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    getFullPath(keyStoreFolder, cacertFile, &fullpath);
    SSL_CTX_load_verify_locations(ctx, fullpath, NULL);
#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined( __ENABLE_DIGICERT_TLS13_0RTT__ ) )
    SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
    SSL_CTX_set_session_cache_mode(ctx,  SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_get_cb(ctx, get_session_cb);
    SSL_CTX_sess_set_remove_cb(ctx, del_session_cb);
#endif

    /* ---------------------------------------------------------- *
    * Make the tcp connection                      *
    * ---------------------------------------------------------- */
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(sslsServerPort);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    fd = socket(AF_INET, SOCK_STREAM, 0);
#ifndef __RTOS_WIN32__
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
#else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&option, sizeof(option));
#endif

    if (0 > (ret= bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))))
    {
        printf("Error: Bind %s\n", strerror(errno));
        goto EXIT;
    }

    if ( listen(fd, 1) < 0)
    {
        printf("Error: Unable to listen %s\n", strerror(errno));
    }

    while ( 1 )
    {

NEWCONNECT:
        printf("\n waiting for new connection ... \n");
        len = sizeof(server_addr);
        client = accept(fd, (struct sockaddr*)&server_addr, &len);
        if (client < 0)
        {
            printf("Unable to accept");
            status = 0;
            goto EXIT;
        }
        /* free the memory */
        if (ssl)
        {
            SSL_free(ssl);
            ssl = NULL;
        }


        printf("Creating new SSL connection state object\n");
        ssl = SSL_new(ctx);
        if (( (ctx==NULL) && (ssl==NULL)) ||
            ( (ctx==NULL) && (ssl!=NULL)) ||
            ( (ctx!=NULL) && (ssl==NULL)) )
        {
            printf("SSL_new created");
            return 0;
        }
        if ( (ctx!=NULL) && (ssl!=NULL))
        {
            printf("SSL_new::PASSED");
        }

        printf("Attempting to attach the SSL session to the socket descriptor\n");
        SSL_set_fd(ssl, client);
        SSL_set_accept_state(ssl);

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )
        SSL_set_num_tickets(ssl, setNumTicketsValue);
#endif
#if ( defined( __ENABLE_DIGICERT_TLS13_0RTT__ ) )
        SSL_set_max_early_data(ssl, setMaxEarlyDataSizeValue);
#endif

        if (1 == readEarlyDataRequest)
        {
            faultCounter= 0;
            while(1)
            {
                memset(buffer, 0 , sizeof(buffer));
                retval = SSL_read_early_data(ssl, buffer, sizeof(buffer), &readbytes);
                if ( 0 == retval )
                {
                    faultCounter++;
                    if (3 < faultCounter)
                    {
                        goto EXIT;
                    }
                }
                if (SSL_READ_EARLY_DATA_SUCCESS == retval)
                {
                    printf("SSL READ %s \n", (char *)buffer);

                }
                else if (SSL_READ_EARLY_DATA_FINISH == retval)
                {
                    printf("SSL READ %s \n", (char *)buffer);
                    break;
                }
           }
        }
        else
        {
            while (1)
            {
                if ((ret=SSL_do_handshake(ssl)) != 1)
                {
                    printf("Error %d\n", SSL_get_error (ssl, ret));
                    printf( "Error: Could not build a SSL session. %s %d\n", strerror(errno), errno);
                    faultCounter++;
                    if (3 < faultCounter)
                    {
                        goto EXIT;
                    }
                }
                else
                {
                    printf("Successfully enabled SSL/TLS session.\n");
                    break;
                }
            }
        }
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
        /* ---------------------------------------------------------- *
        * Get the remote certificate into the X509 structure         *
        * ---------------------------------------------------------- */
        cert = SSL_get_peer_certificate(ssl);
        if (cert == NULL)
        {
          printf("Error: Could not get certificate\n");
        }
        else
        {
            /* ---------------------------------------------------------- *
            * extract various certificate information                    *
            * -----------------------------------------------------------*/
            certname = X509_get_subject_name(cert);

            /* ---------------------------------------------------------- *
            * display the cert subject here                              *
            * -----------------------------------------------------------*/
            printf("Displaying the certificate subject data \n");
            X509_NAME_print_ex(outbio, certname, 0, 0);
            printf("\n");
        }
#endif

        /* ---------------------------------------------------------- *
        * Send and Receive Data Over ssl connection                 *
        * -----------------------------------------------------------*/

READ:
        memset(buffer, 0 , sizeof(buffer));
        faultCounter = 0;
        while (1)
        {
            retval = SSL_read(ssl, buffer, sizeof (buffer));
            if (retval < 0)
            {
                faultCounter++;
                if (3 < faultCounter)
                {
                    goto EXIT;
                }
            }
            if ( (0 == strcmp(buffer, "r"  ) ) || (0 == strcmp(buffer, "R"  ) ) ||
                 (0 == strcmp(buffer, "r\n") ) || (0 == strcmp(buffer, "R\n") ) )
            {
                SSL_renegotiate(ssl);
                goto READ;

            }
            switch (SSL_get_error(ssl, retval))
            {
                case SSL_ERROR_NONE:
                        printf("SSL READ %s \n", (char *)buffer);
                        goto WRITE;
            }
        }

WRITE:
#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )
          if (0 == strncmp(buffer, pSetNumTickets, strlen(pSetNumTickets)))
          {
               setNumTicketsValue = atoi(buffer+strlen(pSetNumTickets) + 1);
               (void) sprintf((char  *)buffer, "%s", "a" );
          }

          if (0 == strncmp(buffer, pSetMaxEarlyDataSize, strlen(pSetMaxEarlyDataSize)))
          {
              setMaxEarlyDataSizeValue = atoi(buffer+strlen(pSetMaxEarlyDataSize) + 1);
              (void) sprintf((char  *)buffer, "%s", "a" );
          }
#endif
#if defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__)
          if (0 == strncmp(buffer, "post", 4))
          {
             SSL_verify_client_post_handshake(ssl);
          }
#endif
        faultCounter = 0;
        while(1)
        {
            retval = SSL_write(ssl, buffer , strlen(buffer));

            if (retval < 0)
            {
                faultCounter++;
                if (3 < faultCounter)
                {
                    goto EXIT;
                }
            }

            switch (SSL_get_error(ssl, retval))
            {
                case SSL_ERROR_NONE:
                    printf("SSL_write status (SSL write return value = %d, ssl read buffer len %d) \n", retval, (int)strlen(buffer));

                    if ( (0 == strcmp(buffer, "q"  ) ) || (0 == strcmp(buffer, "Q"  ) ) ||
                         (0 == strcmp(buffer, "q\n") ) || (0 == strcmp(buffer, "Q\n") ) )
                    {
                        goto EXIT;
                    }
                    if ( (0 == strcmp(buffer, "r"  ) ) || (0 == strcmp(buffer, "R"  ) ) ||
                         (0 == strcmp(buffer, "r\n") ) || (0 == strcmp(buffer, "R\n") ) )
                    {
                        SSL_renegotiate(ssl);
                        goto READ;

                    }
                    if ( (0 == strcmp(buffer, "n"  ) ) || (0 == strcmp(buffer, "N"  ) ) ||
                         (0 == strcmp(buffer, "n\n") ) || (0 == strcmp(buffer, "N\n") ) )
                    {
                        readEarlyDataRequest = 0;
                        SSL_shutdown(ssl);
                        goto NEWCONNECT;

                    }
                    if ( (0 == strcmp(buffer, "readEarlyMode"  ) ) || (0 == strcmp(buffer, "readEarlyMode"  ) ) ||
                         (0 == strcmp(buffer, "readEarlyMode\n") ) || (0 == strcmp(buffer, "readEarlyMode\n") ) )
                    {
                        readEarlyDataRequest = 1;
                        SSL_shutdown(ssl);
                        goto NEWCONNECT;
                    }
                    else
                    {
                        goto READ;
                    }
            }
        }

    }
    /* ---------------------------------------------------------- *
     * Free the structures we don't need any more                  *
     * -----------------------------------------------------------*/
EXIT:

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )
    free_session_list();
#endif

    if (ssl)
        SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);

    X509_free(cert);
#ifndef __RTOS_VXWORKS__
    ERR_free_strings();
    EVP_cleanup();
    SSL_COMP_free_compression_methods();
    CRYPTO_cleanup_all_ex_data();
#endif

#if (defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (g_pTapEntityCred)
    {
        TAP_UTILS_clearEntityCredentialList(g_pTapEntityCred);
        DIGI_FREE((void **)&g_pTapEntityCred);
    }

    if (g_pTapKeyCred)
    {
        TAP_UTILS_clearCredentialList(g_pTapKeyCred);
        DIGI_FREE((void **)&g_pTapKeyCred);
    }

    TAP_freeModuleList(&g_moduleList);
    TAP_uninitContext(&g_pTapContext, pErrContext);
    TAP_uninit(pErrContext);
#endif

  printf("Finished TLS connection with server: \n");
  if (outbio)
    BIO_free(outbio);
  free(fullpath);
  return(0);
}
