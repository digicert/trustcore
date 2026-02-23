/* ------------------------------------------------------------- *
 * file:        openssl_client_tpm.c                             *
 * purpose:     Example code for building a SSL connection and   *
 *              retrieving the server certificate.               *
 *                                                               *
 *              This example was modified for using TAP-         *
 *              generated keys for client authentication.        *
 *                                                               *
 * author:      06/12/2012 Frank4DD                              *
 *              04/19/2018 - updated to use TAP                  *
 * source:      http://fm4dd.com/openssl/sslconnect.htm          *
 *                                                               *
 * ------------------------------------------------------------- */

/*
 * openssl_client_tap.c
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

#ifndef __ENABLE_DIGICERT_TAP__
#error "This can only be compiled with tap=true!"
#endif /* __ENABLE_DIGICERT_TAP__ */

#if defined(__ENABLE_DIGICERT_TAP__)
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#ifndef __RTOS_WIN32__
#include <getopt.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <WinSock2.h>
#include "ossl_sample_utils.h"
#include <ms/applink.c>
#endif
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "smp/smp_cc.h"
#include "tap/tap_api.h"
#include "tap/tap_utils.h"
#include "tap/tap_smp.h"
#include "crypto/mocasym.h"
#include "crypto/mocasymkeys/tap/rsatap.h"
#include "crypto/mocasymkeys/tap/ecctap.h"
#include "crypto_interface/cryptointerface.h"
#include "common/tpm2_path.h"

#define OK                  0
#define ERR_GENERAL         6000

#define SERVER_NAME_LEN     256
#define SERVER_IP_LEN       15
#define CERT_MAX_LEN        256
#define KEY_MAX_LEN         256
#define PORTNUMBER_LEN      6
#define TAP_CONFIG_FILE_LEN 128

#define CERT_FORMAT_PEM     (const sbyte*)"PEM"
#define CERT_FORMAT_DER     (const sbyte*)"DER"

typedef int sbyte4;

static TAP_Context *g_pTapContext                 = NULL;
static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList *g_pTapKeyCred    = NULL;
static TAP_ModuleList g_moduleList          = {0};

char portnumberstring[PORTNUMBER_LEN+1] = "\0";
char servername[SERVER_NAME_LEN+1] = "\0";
char serverip[SERVER_IP_LEN+1] = "\0";
char certfile[CERT_MAX_LEN+1] = "\0";
char cacertfile[CERT_MAX_LEN+1] = "\0";
char keyfile[KEY_MAX_LEN+1] = "\0";
char tapconfigfile[TAP_CONFIG_FILE_LEN+1] = "\0";
int  certFormat = SSL_FILETYPE_PEM;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
char tapserver[SERVER_NAME_LEN+1] = "\0";
char tapserverportstring[PORTNUMBER_LEN+1] = "\0";
#endif

/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
int create_socket(char[], BIO *);

void
printUsage(char *program)
{
    printf("Usage: %s\n"
        "\t[--help|-h|?]\n"
        "\t[--cert|-c <client certificate>]\n"
        "\t[--certform|-f [PEM|DER]\n"
        "\t[--key|-k <client certificate key file>]\n"
        "\t[--rsa|-r || --ecdsa|-e]\n"
        "\t[--tapconfig|-t <tap config file>]\n"
        "\t[--servername|-s <server name>]\n"
        "\t[--cacert|-a <CA cert file>]\n"
        "\t[--serverip|-i <server ip>]\n"
        "\t[--port|-p <port number to connect>]\n"
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        "\t[--tapservername|-v <tap server name>]\n"
        "\t[--tapserverport|-o <port number to connect>]\n"
#endif
        ,program ? program : "PROGRAMNAME");
}

void
setDefaultArguments()
{
    const char defaultservername[] = "webapptap.securitydemos.net";
    const char defaultserverip[] = "127.0.0.1";
    const char defaultportnum[] = "1440";
    const char defaulttapfile[] = TPM2_CONFIGURATION_FILE;
    const char defaultkeyfile[] ="tpm2-ecdsa-256-key.pem";
    const char defaultcertfile[] = "tpm2-ecdsa-256-cert.pem";
    const char defaultcafile[] = "../../../bin/keystore/RSACertCA.pem";

    strncpy(portnumberstring, defaultportnum, sizeof(portnumberstring));

    /* use the ip address by default */
    strncpy(servername, defaultserverip, sizeof(servername));
    strncpy(serverip, defaultserverip, sizeof(serverip));

    strncpy(certfile, defaultcertfile, sizeof(certfile));
    strncpy(keyfile, defaultkeyfile, sizeof(keyfile));
    strncpy(tapconfigfile, defaulttapfile, sizeof(tapconfigfile));
    strncpy(cacertfile, defaultcafile, sizeof(cacertfile));
}

void printAllArguments()
{

    printf("servername : %s\n", servername);
    printf("serverip : %s\n", serverip);
    printf("portNumber : %s\n", portnumberstring);
    printf("certfile : %s\n", certfile);
    printf("keyfile : %s\n", keyfile);
    printf("tapconfigfile : %s\n", tapconfigfile);
    printf("cacertfile : %s\n", cacertfile);
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    printf("tapservername : %s\n", tapserver);
    printf("tapserverport : %s\n", tapserverportstring);
#endif
}

int processArguments(int argc, char **argv)
{
    int c;
    int digit_optind = 0;
    int certpresent = 0, keyfilepresent = 0, serverippresent = 0;
    int servernamepresent = 0;
    char *shortOptStr = NULL;
    /* set the default */
    setDefaultArguments();

    while (1)
    {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"port",         required_argument, 0, 'p'},
            {"servername",   required_argument, 0, 's'},
            {"serverip",     required_argument, 0, 'i'},
            {"cacert",       required_argument, 0, 'a'},
            {"cert",         required_argument, 0, 'c'},
            {"certform",     required_argument, 0, 'f'},
            {"key",          required_argument, 0, 'k'},
            {"tapconfig",    required_argument, 0, 't'},
            {"help",         no_argument,       0, 'h'},
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
            {"tapservername",    required_argument, 0, 'v'},
            {"tapserverport",required_argument, 0, 'o'},
#endif
            {0, 0, 0, 0 },
        };

#ifndef __RTOS_WIN32__
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        shortOptStr = "p:s:i:c:a:k:t:v:o:h";
#else
        /* local */
        shortOptStr = "p:s:i:c:a:k:t:h";
#endif /* __ENABLE_DIGICERT_TAP_REMOTE__ */
#endif /* !__RTOS_WIN32__ */
        c = getopt_long(argc, argv, shortOptStr, long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
            case 'p':
                strncpy(portnumberstring, optarg, PORTNUMBER_LEN);
                break;

            case 's':
                servernamepresent = 1;
                strncpy(servername, optarg, SERVER_NAME_LEN);
                break;

            case 'i':
                strncpy(serverip, optarg, SERVER_IP_LEN);
                serverippresent = 1;
                break;

            case 'c':
                certpresent = 1;
                strncpy(certfile, optarg, CERT_MAX_LEN);
                break;

            case 'f':
                if(0 == DIGI_STRNICMP(CERT_FORMAT_DER,
                              (const sbyte*)optarg, (ubyte4)strlen(optarg)))
                {
                    certFormat = SSL_FILETYPE_ASN1;
                }
                else if(0 == DIGI_STRNICMP(CERT_FORMAT_PEM,
                              (const sbyte*)optarg, strlen(optarg)))
                {
                    certFormat = SSL_FILETYPE_PEM;
                }
                else
                {
                    printf("Invalid certificate format value: \"%s\". Using PEM by default\n",
                          optarg);
                    certFormat = SSL_FILETYPE_PEM;
                }
                break;


            case 'a':
                strncpy(cacertfile, optarg, CERT_MAX_LEN);
                break;

            case 'k':
                keyfilepresent = 1;
                strncpy(keyfile, optarg, KEY_MAX_LEN);
                break;

            case 't':
                strncpy(tapconfigfile, optarg, TAP_CONFIG_FILE_LEN);
                break;

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
            case 'v':
                strncpy(tapserver, optarg, SERVER_NAME_LEN);
                break;

            case 'o':
                strncpy(tapserverportstring, optarg, PORTNUMBER_LEN);
                break;
#endif
            case 'h':
            default:
                return (1);
        }
    }

    if (!servernamepresent && serverippresent)
    {
        strncpy(servername, serverip, SERVER_NAME_LEN);
    }

    return (0);
}

#if (!defined(__ENABLE_DIGICERT_TAP_EXTERN__))
static sbyte4
SSL_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;

    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        /* Initialize context on first module */
        if (NULL == g_pTapContext)
        {
            status = TAP_initContext(&(g_moduleList.pModuleList[0]),
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
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1,
sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    status = TAP_readConfigFile((const char *) pTpm2ConfigFile,
&configInfoList.pConfig[0].configInfo, 0);
    if (OK != status)
    {
        printf("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("TAP_init : %d", status);
        goto exit;
    }
    tapInit = TRUE;

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    connInfo.serverName.bufferLen = strlen(tapserver)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)tapserver, strlen(tapserver));
    if (OK != status)
    goto exit;

    connInfo.serverPort = atoi(tapserverportstring);

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
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

    /* For local TAP, parse the config file and get the Entity Credentials */
#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = TAP_getModuleCredentials(&(g_moduleList.pModuleList[0]),
                                      (const char *) pTpm2ConfigFile, 0,
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
        FREE((void *)connInfo.serverName.pBuffer);

#endif

exit:
    return status;

}
#endif /*!defined(__ENABLE_DIGICERT_TAP_EXTERN__) */

sbyte4 doData(SSL* ssl)
{
  char data[1024];
  char buf[1024];
  sbyte4 status;
  int bytes;

  (void) sprintf((char  *)data, "GET /%s HTTP/1.0\r\n\r\n", "Test");
  printf("Calling SSL_write\n");
  if(OK > (status = SSL_write(ssl, data, strlen(data))))
  {
    printf("Error: SSL_write error : %d \n", status);
    return -1;
  }

  printf("Calling SSL_read\n");
  if(0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
  {
    printf("Error: SSL_read error : %d \n", bytes);
    return -1;
  }

  printf("Message received from Server : %s \n", buf);
  return OK;
}

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
/* it sends renegotiate cmd 'r' to the server */
int sendRenegotiateCmd(SSL* ssl)
{
    char data[2] = {0};
    int  status;

    (void) sprintf((char  *)data, "r");
    printf("send renegotiate cmd to server \n");
    if (0 > (status = SSL_write(ssl, data, strlen(data))))
    {
        printf("Error sendRenegotiateCmd SSL_write : %d \n", status);
        return -1;
    }

    return 0;
}
#endif

#ifdef __ENABLE_DIGICERT_SSL_SEND_QUIT_CMD__
/* it sends quit cmd 'q' and waits for reply from server  */
int sendQuitCmd(SSL* ssl)
{
    char data[2] = {0}, buf[256] = {0};
    int status, bytes;

    (void) sprintf((char  *)data, "q");
    printf("send quit cmd to server \n");
    if (0 > (status = SSL_write(ssl, data, strlen(data))))
    {
        printf("Error sendQuitCmd SSL_write : %d \n", status);
        return -1;
    }

    printf("Calling SSL_read\n");

    if (0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
    {
        printf("Error sendQuitCmd SSL_read : %d \n", bytes);
        return -1;
    }

    printf("Message received from Server for quit command : %s \n", buf);
    return 0;
}

#endif

int main(int argc, char *argv[])
{

  char dest_url[SERVER_NAME_LEN+PORTNUMBER_LEN+10] = "\0";
  BIO *outbio = NULL;
  X509 *cert = NULL;
  X509_NAME *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  sbyte4 status;
  sbyte4 connectionInstance = ERR_GENERAL;
  TAP_ErrorContext *pErrContext = NULL;

  /* ---------------------------------------------------------- *
   * Process command line arguments.                            *
   * ---------------------------------------------------------- */
  if (processArguments(argc, argv) != 0)
  {
    printUsage(argv[0]);
    exit (EXIT_FAILURE);
  }

  printAllArguments();

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
#if !defined(__ENABLE_DIGICERT_OSSL_LOAD_ALL_ALGORITHMS__)
  /* If Underlying NanoSSL library and this sample client is built with this flag,
   * the below function is invoked by NanoSSL in OSSL_init */
  OpenSSL_add_all_algorithms();
#endif
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0)
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   * ---------------------------------------------------------- */
  method = SSLv23_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
  if ( (ctx = SSL_CTX_new(method)) == NULL)
    BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

  /* ---------------------------------------------------------- *
   * Initialize TAP info                                        *
   * ---------------------------------------------------------- */
#if (!defined(__ENABLE_DIGICERT_TAP_EXTERN__))
  if (OK != (status = SSL_InitializeTap((ubyte *) tapconfigfile,
                                               &g_pTapEntityCred,
                                               &g_pTapKeyCred)))
  {
    printf("SSL_InitializeTap failed. status = %d\n", status);
    goto exit;
  }
  else
  {
    printf("SSL_InitializeTap worked!\n");
  }

  if (OK > (status = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSL_getTapContext)))
  {
    printf("CRYPTO_INTERFACE_registerTapCtxCallback failed. status = %d\n", status);
    goto exit;
  }
  else
  {
    printf("CRYPTO_INTERFACE_registerTapCtxCallback worked!\n");
  }
#endif

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
  snprintf(dest_url, sizeof(dest_url), "https://%s:%s",
        servername, portnumberstring);
  server = create_socket(dest_url, outbio);
  if(server != 0)
  {
    BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", dest_url);
  }
  else
  {
    goto exit;
  }

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, server);

  SSL_set_tlsext_host_name(ssl, servername);
  /* do we need to provide a cert verify callback here? */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if(SSL_CTX_use_certificate_file(ctx, certfile, certFormat) < 0)
  {
    BIO_printf(outbio, "Error: SSL_CTX_use_certificate_file() failed\n");
  }

  if(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) < 0)
  {
    BIO_printf(outbio, "Error: SSL_CTX_use_PrivateKey_file() failed\n");
  }

  SSL_CTX_load_verify_locations(ctx, cacertfile, NULL);
  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
  connectionInstance = SSL_connect(ssl);
  if(connectionInstance != 1)
  {
      BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
      exit(1);
  }
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s | connectionInstance : %d\n", dest_url, connectionInstance);

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
  else
    BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/
  certname = X509_NAME_dup(X509_get_subject_name(cert));

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

  if(OK > doData(ssl))
  {
    printf("Error doData\n");
  }

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
  /* client initiated rehandshake */
  if (0 > SSL_renegotiate(ssl))
  {
      printf("Error SSL_renegotiate: client initiated rehandshake\n");
      goto exit;
  }

  if (0 > doData(ssl))
  {
      printf("Error doData:client initiated rehandshake\n");
      goto exit;
  }

  /* server initiated rehandshake */
  if (0 > sendRenegotiateCmd(ssl))
  {
      printf("Error sendRenegotiateCmd:server initiated rehandshake \n");
      goto exit;
  }

  if (0 > doData(ssl))
  {
      printf("Error doData:server initiated rehandshake \n");
      goto exit;
  }

#endif

#ifdef __ENABLE_DIGICERT_SSL_SEND_QUIT_CMD__
  if (0 > sendQuitCmd(ssl))
  {
      printf("Error send quit Cmd \n");
      goto exit;
  }
#endif
  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
exit:

#if (!defined(__ENABLE_DIGICERT_TAP_EXTERN__))
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
#endif


  SSL_free(ssl);
  X509_NAME_free(certname);
  X509_free(cert);
  SSL_CTX_free(ctx);
#if (!defined(__ENABLE_DIGICERT_TAP_EXTERN__))
  TAP_uninitContext(&g_pTapContext, pErrContext);
  TAP_uninit(pErrContext);
#endif
  ERR_free_strings();
  EVP_cleanup();
  SSL_COMP_free_compression_methods();
  CRYPTO_cleanup_all_ex_data();

  if (outbio)
    BIO_free(outbio);
  return(0);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "\0";
  char proto[80] = "\0";
  char portnum[6] = "\0";
  char *tmp_ptr = NULL;
  struct hostent *host = NULL;
  int port;
  struct sockaddr_in dest_addr;

  /* ---------------------------------------------------------- *
   * Remove the final / from url_str, if there is one           *
   * ---------------------------------------------------------- */
  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

  /* ---------------------------------------------------------- *
   * the first : ends the protocol string, i.e. http            *
   * ---------------------------------------------------------- */
  strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

  /* ---------------------------------------------------------- *
   * the hostname starts after the "://" part                   *
   * ---------------------------------------------------------- */
  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

  /* ---------------------------------------------------------- *
   * if the hostname contains a colon :, we got a port number   *
   * ---------------------------------------------------------- */
  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
  }

  if ( (host = gethostbyname(hostname)) == NULL ) {
    BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
    abort();
  }
  port = atoi(portnum);

    printf("Connecting to %s:%d\n", hostname, port);
  /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  /* ---------------------------------------------------------- *
   * Zeroing the rest of the struct                             *
   * ---------------------------------------------------------- */
  memset(&(dest_addr.sin_zero), '\0', 8);

  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  /* ---------------------------------------------------------- *
   * Try to make the host connect here                          *
   * ---------------------------------------------------------- */
  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
             hostname, tmp_ptr, port);
    return 0;
  }

  return sockfd;
}
#endif /* defined(__ENABLE_DIGICERT_TAP__) */
