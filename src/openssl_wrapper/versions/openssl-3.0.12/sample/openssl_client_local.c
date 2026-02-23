/* ------------------------------------------------------------ *
 * file:        openssl_client_local.c                          *
 * purpose:     Example code for building a SSL connection and  *
 *              retrieving the server certificate.              *
 *                                                              *
 *              This example was modified for environments      *
 *              where system certificate keychain is not        *
 *              available to validate the server certificate.   *
 *              The certificate will be loaded from a PEM file  *
 *              specified in 'server_certificate' variable.     *
 *                                                              *
 * author:      06/12/2012 Frank4DD                             *
 * source:      http://fm4dd.com/openssl/sslconnect.htm         *
 *                                                              *
 * gcc -Werror -o openssl_client_local openssl_client_local.c \ *
 *     -I../include -I../../../src -L ../../../bin_static \     *
 *     -lopenssl_shim -lnanossl -lcrypto -lnanocrypto \         *
 *     -lpthread -lrt -ldl                                      *
 * ------------------------------------------------------------ */

/*
 * openssl_client_local.c
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

#ifndef __RTOS_WIN32__
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#else
#include <WinSock2.h>
#include "ossl_sample_utils.h"
#include <ms/applink.c>
#endif
#include <string.h>

#include <openssl/opensslconf.h>
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <ssl/ssl_locl.h>
#else
#include <ssl/ssl_local.h>
#endif
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/engine.h>
#include <time.h>
#if defined(__ENABLE_DIGICERT_OCSP_EXAMPLE__)
#include <openssl/ocsp.h>
#endif

typedef enum TestCaseChoice
{
    defaultTestChoice,
    sslRehandshakeTest,
    sslTls13PskTest,
    sslTls13ORttTest,
    sslTls13KeyUpdateTest,
    sslTls13PostAuthTest,
} testChoice;

typedef enum postActionChoice
{
    NoCmdChoice,
    requestForCloseSession,
    requestForNew0RttConnection,
    sendQuitCmd,
} CmdChoice;

typedef enum serverConfigChoice
{
    noServerConfig,
    setNumTickets,
    setMaxDataEarlySize,
} configCmdChoice;

/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
int create_socket(BIO *);
const char* host_ip = "127.0.0.1";
int port = 1440;
char *pSetNumTickets       = "config SSL_set_num_tickets ";
char *pSetMaxEarlyDataSize = "config SSL_set_max_early_data ";
char *pEarlyDataBuffer     = "early data from client";

#define OK                  0
#define SERVER_NAME_LEN     256
#define SERVER_IP_LEN       15
#define CERT_MAX_LEN        256
#define KEY_MAX_LEN         256
#define FILE_MAX_LEN        256
#define PORTNUMBER_LEN      6
#define RESUME_NONE                 (0x00)
#define RESUME_BY_SESSION_ID        (0x01)
#define RESUME_BY_SESSION_TICKET    (0x02)

char portNumberString[PORTNUMBER_LEN+1] = "\0";
char serverName[SERVER_NAME_LEN+1]      = "\0";
char certFile[CERT_MAX_LEN+1]           = "\0";
char cacertFile[CERT_MAX_LEN+1]         = "\0";
char keyFile[KEY_MAX_LEN+1]             = "\0";
char keyStoreFolder[CERT_MAX_LEN+1]     = "\0";
static unsigned short  sslsServerPort   = 0;
char testChoiceStr[CERT_MAX_LEN+1]   = "\0";
char dhParamsSet = 0;
char dhParamsFile[FILE_MAX_LEN+1] = "\0";
char resumeType = RESUME_NONE;
char resumeByBuffer = 0;

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
    (void) printf("    --ssl_ca_cert <cert_name>           name of the CA cert \n");
    (void) printf("    --ssl_testrun <test choice>         Test choice: all or default or psk or 0rtt or keyupdate or posthandshake or rehandshake \n");
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    (void) printf("    --ssl_client_cert <cert_name>       name of the client cert \n");
    (void) printf("    --ssl_client_keyblob <blob_name>    name of the client keyblob\n");
#endif
#ifdef __ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__
    (void) printf("    --ssl_resume_by_ticket              To enable session ticket");
    (void) printf("    --ssl_resume_by_buffer              To enable session ticket using buffer");
#endif
    (void) printf("    --ssl_dh_params <dh_param_file>     Path to DH parameter file");

    (void) printf("\n");
}

void
setDefaultArguments()
{
    const char defaultServerName[] = "webapptap.securitydemos.net";
    const char defaultPortNum[] = "1440";

    const char defaultCertFile[] = "ClientECCCertCA384.pem";
    const char defaultKeyFile[]  = "ClientECCCertCA384Key.pem";
    const char defaultCaFile[]   = "ECCCertCA384.pem";
#ifdef __RTOS_WIN32__
    /* Sample gets output to where .dll's so the bin_win32 path doesn't have to be
     * added to the PATH environment variable. For windows check for the keystore
     * in the current directory.
     */
    const char defaultKeyFolder[] = "./keystore";
#else
    const char defaultKeyFolder[] = "../../../bin/keystore";
#endif
    const char defaultTestChoice[] = "default";

    strncpy(portNumberString, defaultPortNum, sizeof(portNumberString));

    strncpy(serverName, defaultServerName, sizeof(defaultServerName));

    strncpy(keyStoreFolder, defaultKeyFolder, sizeof(defaultKeyFolder));

    strncpy(cacertFile, defaultCaFile, sizeof(cacertFile));
    strncpy(testChoiceStr, defaultTestChoice, sizeof(defaultTestChoice));

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    strncpy(certFile, defaultCertFile, sizeof(certFile));
    strncpy(keyFile, defaultKeyFile, sizeof(keyFile));
#endif

}

void printAllArguments()
{

    printf("serverName : %s\n", serverName);
    printf("portNumber : %d\n", sslsServerPort);
    printf("keyStoreFolder : %s\n", keyStoreFolder);
    printf("cacertFile : %s\n", cacertFile);
    printf("testChoiceStr : %s\n", testChoiceStr);
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
    printf("certFile : %s\n",   certFile);
    printf("keyFile : %s\n",    keyFile);
#endif

}

int processArguments(int argc, char **argv)
{
    int c;
    int digit_optind = 0;
    int certPresent = 0, keyfilePresent = 0, serverIpPresent = 0;
    int serverNamePresent = 0;
    int serverPort = 0;
    char *shortOptStr = NULL;
    /* set the default */
    setDefaultArguments();

    while (1)
    {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
                {"ssl_port",             required_argument, 0, 'p'},
                {"ssl_servername",       required_argument, 0, 's'},
                {"ssl_ca_cert",          required_argument, 0, 'a'},
                {"ssl_client_cert",      required_argument, 0, 'c'},
                {"ssl_client_keyblob",   required_argument, 0, 'k'},
                {"ssl_certpath",         required_argument, 0, 'f'},
                {"ssl_testrun",          required_argument, 0, 't'},
                {"ssl_resume_by_id",     no_argument,       0, 'i'},
#ifdef __ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__
                {"ssl_resume_by_ticket", no_argument,       0, 'u'},
                {"ssl_resume_by_buffer", no_argument,       0, 'b'},
#endif
                {"ssl_dh_params",        required_argument, 0, 'd'},
                {"help",         no_argument,       0, 'h'},
                {0, 0, 0, 0 },
        };

#ifndef __RTOS_WIN32__
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
        shortOptStr = "p:s:c:k:f:t:h:i:u:b";
#else
        shortOptStr = "p:s:c:a:k:f:t:h:i:u:b";
#endif
#endif /* ! __RTOS_WIN32__ */
        c = getopt_long(argc, argv, shortOptStr , long_options, &option_index);
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
            case 'a':
                strncpy(cacertFile, optarg, CERT_MAX_LEN);
                break;
            case 't':
                strncpy(testChoiceStr, optarg, CERT_MAX_LEN);
                break;
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
            case 'c':
                certPresent = 1;
                strncpy(certFile, optarg, CERT_MAX_LEN);
                break;
            case 'k':
                keyfilePresent = 1;
                strncpy(keyFile, optarg, KEY_MAX_LEN);
                break;
#endif
            case 'i':
                resumeType = RESUME_BY_SESSION_ID;
                break;
            case 'u':
                resumeType = RESUME_BY_SESSION_TICKET;
                break;
            case 'b':
                resumeByBuffer = 1;
                break;
            case 'd':
                dhParamsSet = 1;
                strncpy(dhParamsFile, optarg, FILE_MAX_LEN);
                break;
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
    return (0);
}

void delay(int number_of_seconds)
{
    /* Converting time into milli_seconds */
    int milli_seconds = 1000 * number_of_seconds;

    /* save the start time */
    clock_t start_time = clock();

    /* looping till required time is not acheived */
    while (clock() < start_time + milli_seconds)
        ;
}

int doConfigData(SSL* ssl, char *pConfigData, int value )
{
    char data[1024];
    char buf[1024] = { 0 };
    int bytes;
    int status;

    (void) sprintf((char  *)data, "%s#%d", pConfigData, value );
    printf("Calling SSL_write\n");
    if(0 > (status = SSL_write(ssl, data, strlen(data))))
    {
        printf("Error doConfigData: SSL_write error : %d \n", status);
        return -1;
    }

    printf("Calling SSL_read\n");
    if(0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
    {
        printf("Error doConfigData: SSL_read error : %d \n", bytes);
        return -1;
    }

    printf("Message received from Server : %s \n", buf);
    if ( (0 == strncmp(buf, "a" , 1) ) || (0 == strncmp(buf, "A",1 )))
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

int doData(SSL* ssl)
{
  char data[1024] = { 0 };
  char buf[1024] = { 0 };
  int bytes;
  int status;

  (void) sprintf((char  *)data, "GET /%s HTTP/1.0\r\n\r\n", "Test");
  printf("Calling SSL_write\n");
  if(0 > (status = SSL_write(ssl, data, strlen(data))))
  {
    printf("Error: SSL_write error : %d \n", status);
    return -1;
  }

  delay(3);

  printf("Calling SSL_read\n");
  if(0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
  {
    printf("Error: SSL_read error : %d \n", bytes);
    return -1;
  }

  printf("Message received from Server : %s \n", buf);
  return 0;
}

int sendCloseSessionCmd(SSL* ssl)
{
    char data[2] = {0}, buf[256] = {0};
    int status, bytes;

    (void) sprintf((char  *)data, "n");
    printf("sending close session cmd to server \n");
    if (0 > (status = SSL_write(ssl, data, strlen(data))))
    {
        printf("Error psk Cmd SSL_write : %d \n", status);
        return -1;
    }

    printf("Calling SSL_read, waiting for ack for close session cmd \n");

    if (0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
    {
        printf("Error psk cmd SSL_read : %d \n", bytes);
        return -1;
    }

    printf("Server ack for close connection cmd : %s \n", buf);
    return 0;
}

int sendNew0RttConnectionCmd(SSL* ssl)
{
    char data[30] = {0}, buf[256] = {0};
    int status, bytes;

    (void) sprintf((char  *)data, "readEarlyMode");
    printf("restart server \n");
    if (0 > (status = SSL_write(ssl, data, strlen(data))))
    {
        printf("Error psk Cmd SSL_write : %d \n", status);
        return -1;
    }

    printf("Calling SSL_read\n");

    if (0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
    {
        printf("Error psk cmd SSL_read : %d \n", bytes);
        return -1;
    }

    printf("Message received from Server for readEarly command : %s \n", buf);
    return 0;
}

int sendPostHandshakeCmd(SSL* ssl)
{
    char data[30] = {0}, buf[256] = {0};
    int status, bytes;

    (void) sprintf((char  *)data, "post");
    printf("ssl write: sending post handshake cmd \n");
    if (0 > (status = SSL_write(ssl, data, strlen(data))))
    {
        printf("Error post handshake Cmd SSL_write : %d \n", status);
        return -1;
    }

    printf("Calling SSL_read\n");

    if (0 >= (bytes = SSL_read(ssl, buf, sizeof(buf))))
    {
        printf("Error posthand shake cmd SSL_read : %d \n", bytes);
        return -1;
    }

    printf("Message received from Server for post command : %s \n", buf);
    return 0;
}

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
/* it sends renegotiate cmd 'r' to the server */
int sendRenegotiateCmd(SSL* ssl)
{
  char data[2] = {0};
  int status;

  (void) sprintf((char  *)data, "r");
  printf("send renegotiate cmd to server \n");
  if (0 > (status = SSL_write(ssl, data, strlen(data))))
  {
    printf("Error: SSL_write error : %d \n", status);
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
  printf("send renegotiate cmd to server \n");
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

#if ( defined( __ENABLE_DIGICERT_SSL_ALERT_CALLBACK_SUPPORT__ ) )

void alert_msg_cb(int write_p, int version, int contentType,
                        const void *buf, size_t len, SSL *ssl, void *arg)
{
    int i = 0;
    printf("Alert Callback :\n");
    printf("Version : %d\n", version);
    printf("Content Type : %d\n", contentType);
    printf("Alert buffer :");


    for (i = 0; i < len; i++)
    {
        printf("%02x\n", ((uint8_t*)buf)[i]);
    }

    return;
}

#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )

SSL_SESSION *pSessionListHeader = NULL;
SSL_SESSION *pCurSession = NULL;

SSL_SESSION *clientpsk = NULL;
const unsigned char* pPskticket = NULL ;
size_t pskTicketLen = 0;

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
static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **ppId,
                          size_t *pIdlen, SSL_SESSION **ppSess)
{
    SSL_SESSION *pSessList = pSessionListHeader;
    const unsigned char* pPskticket = NULL ;
    size_t pskTicketLen = 0;

    while ( NULL != pSessList )
    {
        if (NULL != pSessList->cipher)
        {
            if ((NULL != md) && (SSL_CIPHER_get_handshake_digest(pSessList->cipher) != md))
            {
                /* PSK not usable, ignore it */
                *ppId = NULL;
                *pIdlen = 0;
                *ppSess = NULL;
            }
            else
            {
                SSL_SESSION_get0_ticket(pSessList, &pPskticket, &pskTicketLen);
                break;
            }
        }
        pSessList = pSessList->next;
    }

    *ppId = (const unsigned char *)pPskticket;
    *pIdlen = pskTicketLen;
    *ppSess = pSessList;

    return 1;
}

SSL_SESSION *getSessionFromSavedList()
{
    SSL_SESSION *pSessList = pCurSession;
    SSL_SESSION *pSess = NULL;

    if(NULL != pSessList)
    {
        pSess = pSessList;
        pCurSession = pSessList->next;
    }
    return pSess;
}

static int new_session_cb(SSL *s, SSL_SESSION *pSess)
{
    BIO *bio_c_out = NULL;
    SSL_SESSION *pNewSessNode;
    SSL_SESSION *pSessList = pSessionListHeader ;
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
        pCurSession = pSessionListHeader;
    }

    BIO_printf(bio_c_out, "---\n New Session Ticket is arrived :\n" );
    if (bio_c_out)
        BIO_free(bio_c_out);
    return 1;
}
#endif

enum cmdtype
{
     /* if testrun cmd is all = 0x3F, default = 0x02, psk = 0x04, 0rtt = 0x08,
     * keyupdate = 0x10, posthandshakecmd = 0x20 */
    defaultTest   = 0x02,
    pskTest       = 0x04,
    rttTest       = 0x08,
    keyupdateTest = 0x10,
    postauthTest  = 0x20,
    rehandshakeTest = 0x40,
    allTests      = 0x4F,
};

int findCmd(char *pBuffer, int bufferSize)
{
    int i, cmdLen;
    unsigned int result = 0;

    /* if testrun cmd is all = 0x4F, default = 0x02, psk = 0x04, 0rtt = 0x08,
     * keyupdate = 0x10, posthandshakecmd = 0x20, rehandshake = 0x40 */
    char *pTestRunCmd[7] = {"all", "default","psk","0rtt","keyupdate","posthandshake", "rehandshake"};

    for(int count = 0;count < 7 ; count++)
    {
        cmdLen = strlen(pTestRunCmd[count]);
        i = 0;
        while (i <= (bufferSize - cmdLen))
        {
            if (pBuffer[i] == *pTestRunCmd[count])
            {
                if (0 == strncmp((char * )(pBuffer + i), (char *) pTestRunCmd[count], cmdLen))
                {
                    if(0 == count)
                    {
                        /* */
                        result = allTests;
                        goto exit;
                    }
                    else
                    {
                        result = result | (0x01 << count);
                    }
                    break;
                }
            }
            ++i;
        }
    }
exit:
    return result;
}
#if defined(__ENABLE_DIGICERT_OCSP_EXAMPLE__)
static int SSL_CTX_OCSP_callback(SSL *s, void *arg)
{
    const unsigned char *p;
    int len;
    OCSP_RESPONSE *rsp;
    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    BIO_puts(arg, "OCSP response: ");
    if (!p) {
        BIO_puts(arg, "no response sent\n");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        BIO_puts(arg, "response parse error\n");
        BIO_dump_indent(arg, (char *)p, len, 4);
        return 0;
    }
    BIO_puts(arg, "\n======================================\n");
    OCSP_RESPONSE_print(arg, rsp, 0);
    BIO_puts(arg, "======================================\n");
    OCSP_RESPONSE_free(rsp);
    return 1;
}
#endif

static EVP_PKEY *gpClienCertCbKey = NULL;
static X509 *gpClientCertCbCert = NULL;

static int clientCertCallback(SSL *s, X509 **ppCert, EVP_PKEY **ppKey)
{
    FILE *certFp = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x03000000L
    FILE *keyFp = NULL;
#else
    ENGINE *e = NULL;
#endif
    char *pFullpath = NULL;
    char *pKey = NULL;
    char *pEngineName = NULL;
    int ret = -1;

    getFullPath(keyStoreFolder, certFile, &pFullpath);
    if (NULL == pFullpath)
        goto exit;

    certFp = fopen(pFullpath, "r");
    if (NULL == certFp)
    {
        printf("Error: Loading certificate file failed\n");
        goto exit;
    }

    PEM_read_X509(certFp, ppCert, 0, NULL);
    fclose(certFp);

    if (NULL == *ppCert)
    {
        printf("Error: Parsing certificate file failed\n");
        goto exit;
    }
    gpClientCertCbCert = *ppCert;

    getFullPath(keyStoreFolder, keyFile, &pFullpath);
    if (NULL == pFullpath)
        goto exit;

#if OPENSSL_VERSION_NUMBER >= 0x03000000L
    keyFp = fopen(pFullpath, "r");
    if (NULL == keyFp)
    {
        printf("Error: Failed to open private key file\n");
        goto exit;
    }
    *ppKey = PEM_read_PrivateKey(keyFp, NULL, NULL, NULL);
    if (NULL == *ppKey)
    {
        printf("Error: Loading private key file\n");
    }
    fclose(keyFp);
#else
    ENGINE_load_builtin_engines();
    pEngineName = getenv("OPENSSL_SIGN_ENGINE");
    if (NULL == pEngineName)
    {
        printf("Error Engine Name\n");
        goto exit;
    }

    e = ENGINE_by_id(pEngineName);
    if (NULL == e)
    {
        printf("Error: Loading mocana engine failed\n");
        goto exit;
    }
    ENGINE_set_default_RAND(e);

    if (NULL == (*ppKey = ENGINE_load_private_key(e, pFullpath, NULL, NULL)))
    {
        printf("Error loading private key file\n");
        goto exit;
    }
#endif
    gpClienCertCbKey = *ppKey;
    ret = 1;

exit:

#if OPENSSL_VERSION_NUMBER < 0x03000000L
    if (NULL != e)
    {
        ENGINE_free(e);
    }
#endif

    if (NULL != pFullpath)
        free(pFullpath);
    return ret;
}

static DH *readDhParams(char *pDhParamsFile)
{
    DH *pNewDh = NULL;
    BIO *pFileBio = NULL;

    pFileBio = BIO_new(BIO_s_file());
    if (NULL == pFileBio)
    {
        return NULL;
    }

    if (1 != BIO_read_filename(pFileBio, pDhParamsFile))
    {
        return NULL;
    }

    pNewDh = PEM_read_bio_DHparams(pFileBio, NULL, NULL, NULL);
    BIO_free(pFileBio);
    return pNewDh;
}

int create_ssl_connection(int testCase, int serverConfig, int postAction)
{
    BIO *outbio = NULL;
    X509 *cert = NULL;
    X509_NAME *certname = NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *pFullpath = NULL;
#ifdef __ENABLE_DIGICERT_PEM_READ_BIO_PRIVATE_KEY__
    EVP_PKEY *pKey = NULL;
    BIO *pFileBio = NULL;
#endif
    int server = 0;
    size_t earlyDataBytes;
    int connectionInstance = -1;
    SSL_SESSION *pSess = NULL;
    SSL_SESSION *sess = NULL, *sessFromBuffer = NULL;
    int sessLen;
    unsigned char *pSessBuffer = NULL, *pSessTemp;
    DH *dh = NULL;

    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
     * set the tls method                                         *
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

    if ( 1 != SSL_CTX_set_ciphersuites(ctx, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"))
    {
        printf("Failed to set the cipher ================== \n");
    }

    /* add all ctx conditions before the ssl create */
    switch (testCase)
    {
        case sslTls13PskTest:
#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT
                                            | SSL_SESS_CACHE_NO_INTERNAL_STORE);
            SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
            SSL_CTX_set_psk_use_session_callback(ctx, use_session_cb);
#endif
            break;
        default:
            break;
    }
#if defined(__ENABLE_DIGICERT_OCSP_EXAMPLE__)
  if (1 != SSL_CTX_set_tlsext_status_cb(ctx, SSL_CTX_OCSP_callback))
  {
      BIO_printf(outbio, "Error: SSL_CTX_set_tlsext_status_cb() failed\n");
      goto exit;
  }

  if (1 != SSL_CTX_set_tlsext_status_arg(ctx, outbio))
  {
      BIO_printf(outbio, "Error: SSL_CTX_set_tlsext_status_arg() failed\n");
      goto exit;
  }
#endif

    if (RESUME_BY_SESSION_ID == resumeType)
    {
        /* Disable session ticket handling. */
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }

    /* ---------------------------------------------------------- *
     * Set DH parameters if provided                              *
     * ---------------------------------------------------------- */
    if (dhParamsSet)
    {
        getFullPath(keyStoreFolder, dhParamsFile, &pFullpath);
        if (NULL == pFullpath)
            goto exit;

        dh = readDhParams(pFullpath);
        if (NULL == dh)
        {
            BIO_printf(outbio, "Error: readDhParams() failed\n");
            goto exit;
        }
        if (1 != SSL_CTX_set_tmp_dh(ctx, dh))
        {
            BIO_printf(outbio, "Error: SSL_CTX_set_tmp_dh() failed\n");
            goto exit;
        }
    }

    /* ---------------------------------------------------------- *
     * Create new SSL connection state object                     *
     * ---------------------------------------------------------- */
    ssl = SSL_new(ctx);

    /* ---------------------------------------------------------- *
     * Make the underlying TCP socket connection                  *
     * ---------------------------------------------------------- */
    server = create_socket(outbio);
    if(server != 0)
        BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", host_ip);

    /* ---------------------------------------------------------- *
     * Attach the SSL session to the socket descriptor            *
     * ---------------------------------------------------------- */
    SSL_set_fd(ssl, server);

    SSL_set_tlsext_host_name(ssl, serverName);
    /* ---------------------------------------------------------- *
     * Enable the server certificate verification                 *
     * ---------------------------------------------------------- */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__))
#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__)
    SSL_CTX_set_client_cert_cb(ctx, clientCertCallback);
#else
    getFullPath(keyStoreFolder, certFile, &pFullpath);
    if (NULL == pFullpath)
        goto exit;

    if(SSL_CTX_use_certificate_file(ctx, pFullpath, SSL_FILETYPE_PEM) < 0)
    {
         BIO_printf(outbio, "Error: SSL_CTX_use_certificate_file() failed\n");
    }

#ifdef __ENABLE_DIGICERT_PEM_READ_BIO_PRIVATE_KEY__

    pFileBio = BIO_new(BIO_s_file_internal());

    if (NULL == pFileBio)
    {
        BIO_printf(outbio, "Error: BIO_new failed on line %d\n", __LINE__);
    }

    getFullPath(keyStoreFolder, keyFile, &pFullpath);
    if (NULL == pFullpath)
        goto exit;

    if (1 != BIO_read_filename(pFileBio, pFullpath))
    {
        BIO_printf(outbio, "Error: BIO_read_filename failed on line %d\n", __LINE__);
    }

    pKey = PEM_read_bio_PrivateKey(pFileBio, NULL, NULL, NULL);
    if (NULL == pKey)
    {
        BIO_printf(outbio, "Error: PEM_read_bio_PrivateKey failed on line %d\n", __LINE__);
    }

    if (1 != SSL_CTX_use_PrivateKey(ctx, pKey))
    {
        BIO_printf(outbio, "Error: SSL_CTX_use_PrivateKey failed on line %d\n", __LINE__);
    }
#else
    getFullPath(keyStoreFolder, keyFile, &pFullpath);
    if (NULL == pFullpath)
        goto exit;

    if(SSL_CTX_use_PrivateKey_file(ctx, pFullpath, SSL_FILETYPE_PEM) < 0)
    {
        BIO_printf(outbio, "Error: SSL_CTX_use_PrivateKey_file() failed\n");
    }
#endif
#endif /* __ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__ */
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ ||  __ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__ */

    getFullPath(keyStoreFolder, cacertFile, &pFullpath);
    if (NULL == pFullpath)
        goto exit;

    SSL_CTX_load_verify_locations(ctx, pFullpath, NULL);
#if defined(__ENABLE_DIGICERT_OCSP_EXAMPLE__)
  if (1 != SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp))
  {
    BIO_printf(outbio, "Error: SSL_set_tlsext_status_type() failed\n");
  }
#endif

#if ( defined( __ENABLE_DIGICERT_SSL_ALERT_CALLBACK_SUPPORT__ ) )
    SSL_set_msg_callback(ssl, alert_msg_cb);
    SSL_set_msg_callback_arg(ssl, NULL);
#endif

    /* add all ssl preconditions before the connection */
    switch (testCase)
    {
        case sslTls13PskTest:
        case sslTls13ORttTest:
#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined( __ENABLE_DIGICERT_TLS13_0RTT__ ) )
            pSess = getSessionFromSavedList();
            if (NULL != pSess)
            {
                SSL_set_session(ssl, pSess);
            }
#endif
            break;
#if (defined( __ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__ ))
        case sslTls13PostAuthTest:
            SSL_set_post_handshake_auth(ssl, 1);
            break;
#endif
        default:
            break;
    }

    /*  use either ssl_write_early_data or ssl_connect */
    switch (testCase)
    {
#if ( defined( __ENABLE_DIGICERT_TLS13_0RTT__ ) )
        case sslTls13ORttTest:
                /* Write early data */
                if ((NULL == pSess) ||
                    (0 == (SSL_write_early_data(ssl, pEarlyDataBuffer, strlen(pEarlyDataBuffer), &earlyDataBytes))))
                {
                    BIO_printf(outbio, "Error: Early data failure: %s.\n", host_ip);
                    goto exit;
                }
            break;
#endif
            /* post handshake auth flow , basic tls1.3 flow or psk or tls1.2 , requires ssl_connect */
        default:
            /* ---------------------------------------------------------- *
             * Try to SSL-connect here, returns 1 for success             *
             * ---------------------------------------------------------- */
            connectionInstance = SSL_connect(ssl);

            if(connectionInstance != 1)
            {
                BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", host_ip);
                goto exit;
            }
            else
                BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s | connectionInstance : %d\n", host_ip, connectionInstance);

            break;
    }
    /* ---------------------------------------------------------- *
     * Get the remote certificate into the X509 structure         *
     * ---------------------------------------------------------- */
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
        BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", host_ip);
    else
        BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", host_ip);

    /* ---------------------------------------------------------- *
     * extract various certificate information                    *
     * -----------------------------------------------------------*/
    certname = X509_get_subject_name(cert);

    /* ---------------------------------------------------------- *
     * display the cert subject here                              *
     * -----------------------------------------------------------*/
    BIO_printf(outbio, "Displaying the certificate subject data:\n");
    X509_NAME_print_ex(outbio, certname, 0, 0);
    BIO_printf(outbio, "\n");

    if (RESUME_NONE != resumeType)
    {
        SSL_SESSION *sess = NULL;
#ifndef __ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__
        if (RESUME_BY_SESSION_TICKET == resumeType)
        {
            printf("Error session ticket resumption not enabled\n");
            exit(1);
        }
#endif

        printf("Resuming by ");
        if (RESUME_BY_SESSION_TICKET == resumeType)
        printf("session ticket");
        else if (RESUME_BY_SESSION_ID == resumeType)
        printf("session id");
        else
        printf("unknown");
        printf("\n");

        sess = SSL_get1_session(ssl); /* Collect the session */
        SSL_shutdown(ssl);
        SSL_free(ssl);

        if (resumeByBuffer)
        {
            printf("Calling i2d_SSL_SESSION and d2i_SSL_SESSION\n");
            sessLen = i2d_SSL_SESSION(sess, NULL);
            pSessBuffer = malloc(sessLen);
            pSessTemp = pSessBuffer;
            sessLen = i2d_SSL_SESSION(sess, &pSessTemp);
            pSessTemp = pSessBuffer;
            sessFromBuffer = d2i_SSL_SESSION(NULL, (const unsigned char **) &pSessTemp, sessLen);
            free(pSessBuffer);
            SSL_SESSION_free(sess);
            sess = sessFromBuffer;
        }

        ssl = SSL_new(ctx);

        /* ---------------------------------------------------------- *
        * Make the underlying TCP socket connection                  *
        * ---------------------------------------------------------- */
        server = create_socket(outbio);
        if(server != 0)
            BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", host_ip);

        /* ---------------------------------------------------------- *
        * Attach the SSL session to the socket descriptor            *
        * ---------------------------------------------------------- */
        SSL_set_fd(ssl, server);

        SSL_set_session(ssl, sess); /* And resume it */
        connectionInstance = SSL_connect(ssl);
        if(connectionInstance != 1)
        {
            BIO_printf(outbio, "Error: Could not build a SSL session using session ticket to: %s.\n", host_ip);
            exit(1);
        }
        else
            BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s | connectionInstance : %d\n", host_ip, connectionInstance);

        if (1 == SSL_session_reused(ssl))
        {
            SSL_SESSION_free(sess);
        }

        if(0 > doData(ssl))
        {
            printf("Error doData\n");
        }
    }

    delay(3);

    switch(serverConfig)
    {
        case sslTls13PskTest:
            if ( 0 > doConfigData(ssl, pSetNumTickets, 1))
            {
                printf("Error doConfigData: server config SetNumTickets command failed \n");
                goto exit;
            }
            break;
        case sslTls13ORttTest:
            if ( 0 > doConfigData(ssl, pSetNumTickets, 2))
            {
                printf("Error doConfigData: server config SetNumTickets command failed \n");
                goto exit;
            }
            if ( 0 > doConfigData(ssl, pSetMaxEarlyDataSize, 200))
            {
                printf("Error doConfigData: server config SetMaxEarlyDataSize command failed \n");
                goto exit;
            }
            break;
        default:
            break;
    }

    if (0 > doData(ssl))
    {
        printf("Error doData\n");
    }

    switch (testCase)
    {
#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
        case sslRehandshakeTest:
            /* client initiated rehandshake */
            if (0 > SSL_renegotiate(ssl))
            {
                printf("Error SSL_renegotiate: client initiated rehandshake \n");
                goto exit;
            }

            if (0 > doData(ssl))
            {
               printf("Error doData: client initiated rehandshake\n");
               goto exit;
            }

            /* server initiated rehandshake */
            if (0 > sendRenegotiateCmd(ssl))
            {
               printf("Error sendRenegotiateCmd: server initiated rehandshake\n");
               goto exit;
            }

            if (0 > doData(ssl))
            {
               printf("Error doData: server initiated rehandshake\n");
               goto exit;
            }
            break;
#endif
#ifdef __ENABLE_DIGICERT_TLS13_KEYUPDATE__
        case sslTls13KeyUpdateTest:

            if (0 == SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED))
            {
                printf("Error SSL_key_update: SSL_KEY_UPDATE_NOT_REQUESTED failed \n");
                goto exit;
            }
            if (0 > doData(ssl))
            {
                printf("Error doData: client keyupdate SSL_KEY_UPDATE_NOT_REQUESTED \n");
                goto exit;
            }
            if (0 == SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED))
            {
                printf("Error SSL_key_update: SSL_KEY_UPDATE_REQUESTED failed \n");
                goto exit;
            }
            if (0 > doData(ssl))
            {
                printf("Error doData: client keyupdate SSL_KEY_UPDATE_NOT_REQUESTED \n");
                goto exit;
            }
            break;
#endif

#if (defined( __ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__ ))
        case sslTls13PostAuthTest:
            sendPostHandshakeCmd(ssl);
            break;
#endif
        default :
            break;

    }

exit:
    switch (postAction)
    {
        case requestForCloseSession:
            delay(3);
            sendCloseSessionCmd(ssl);
            break;
        case requestForNew0RttConnection:
            delay(3);
            sendNew0RttConnectionCmd(ssl);
            break;
#ifdef __ENABLE_DIGICERT_SSL_SEND_QUIT_CMD__
        case sendQuitCmd:
            if (0 > sendQuitCmd(ssl))
            {
               printf("Error sending quit cmd\n");
            }
            break;
#endif
        default:
            break;
    }

    if (NULL != gpClientCertCbCert)
    {
        X509_free(gpClientCertCbCert);
    }
    if (NULL != gpClienCertCbKey)
    {
        EVP_PKEY_free(gpClienCertCbKey);
    }

    DH_free(dh);
    SSL_shutdown(ssl);
    /* ---------------------------------------------------------- *
     * Free the structures we don't need anymore                  *
     * -----------------------------------------------------------*/
    SSL_free(ssl);
    X509_free(cert);
    SSL_CTX_free(ctx);
#ifdef __ENABLE_DIGICERT_PEM_READ_BIO_PRIVATE_KEY__
    BIO_free(pFileBio);
#endif

    if (outbio)
        BIO_free(outbio);
    ERR_free_strings();
    EVP_cleanup();
    SSL_COMP_free_compression_methods();
    CRYPTO_cleanup_all_ex_data();
    
    if (NULL != pFullpath) 
        free(pFullpath);

    return connectionInstance;
}

int main(int argc, char *argv[])
{

  BIO *outbio = NULL;
  unsigned int sslTestRun = 0;

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

  /* if testrun cmd is 'all' = 0x3F, 'default' = 0x02, 'psk' = 0x04, '0rtt' = 0x08,
  * 'keyupdate' = 0x10, 'posthandshake' = 0x20 */

  sslTestRun = findCmd(testChoiceStr, strlen(testChoiceStr));
  if (sslTestRun & defaultTest)
  {
      /* default testing */
      create_ssl_connection(defaultTestChoice, noServerConfig, requestForCloseSession);
  }

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
  if (sslTestRun & rehandshakeTest)
  {
      create_ssl_connection(sslRehandshakeTest, noServerConfig, requestForCloseSession);
  }
#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) )
  if (sslTestRun & pskTest)
  {
      /* it set sends server config command , set number of tickets 2 */
      create_ssl_connection(defaultTestChoice, sslTls13PskTest, requestForCloseSession);
      /* it saves the session tickets */
      create_ssl_connection(sslTls13PskTest, noServerConfig, requestForCloseSession);
      /* it resues the session tickets */
      create_ssl_connection(sslTls13PskTest, noServerConfig, requestForCloseSession);
  }
#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_0RTT__ ) )
  if(sslTestRun & rttTest)
  {
      /* it set sends server config command , set number of tickets 2, max early data size 200 */
      create_ssl_connection(defaultTestChoice, sslTls13ORttTest, requestForCloseSession);
      /* it saves the session tickets */
      create_ssl_connection(sslTls13PskTest, noServerConfig, requestForNew0RttConnection);
      /* it resues the session tickets and sends early data */
      create_ssl_connection(sslTls13ORttTest, noServerConfig, requestForCloseSession);
  }
#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_KEYUPDATE__ ) )
  if(sslTestRun & keyupdateTest)
  {
      create_ssl_connection(sslTls13KeyUpdateTest, noServerConfig, requestForCloseSession);
  }
#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__ ) )
  if(sslTestRun & postauthTest)
  {
      create_ssl_connection(sslTls13PostAuthTest, noServerConfig, requestForCloseSession);
  }
#endif

#if ( defined( __ENABLE_DIGICERT_TLS13_PSK__ ) || defined(__ENABLE_DIGICERT_TLS13_0RTT__) )
  free_session_list();
#endif
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", host_ip);
  if (outbio)
    BIO_free(outbio);
  return(0);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(BIO *out)
{
  int sockfd;
  char hostname[256] = "";

  char *tmp_ptr = NULL;
  struct sockaddr_in dest_addr;

  /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(sslsServerPort);
  dest_addr.sin_addr.s_addr = inet_addr(host_ip);

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
             host_ip, tmp_ptr, port);
  }

  return sockfd;
}
