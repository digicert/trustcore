/*
 * openssl_dtls_client.c
 *
 * DTLS client sample
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
#include <stdlib.h>
#ifndef __RTOS_WIN32__
#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>
#include <arpa/inet.h>
#else
#include <WinSock2.h>
#include "ossl_sample_utils.h"
#include <ws2tcpip.h>
#include <ms/applink.c>
#endif
#include <string.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define SERVER_NAME_LEN     256
#define SERVER_IP_LEN       15
#define CERT_MAX_LEN        256
#define KEY_MAX_LEN         256
#define PORTNUMBER_LEN      6


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
    (void) printf("    --ssl_ca_cert <cert_name>           name of the CA cert \n");
    (void) printf("\n");
}


void
setDefaultArguments()
{
    const char defaultServerName[] = "webapptap.securitydemos.net";
    const char defaultServerIp[] = "127.0.0.1";
    const char defaultPortNum[] = "1440";

    const char defaultCertFile[] = "ClientRSACert.pem";
    const char defaultKeyFile[]  = "ClientRSACertKey.pem";
    const char defaultCaFile[]   = "RSACertCA.pem";
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

    strncpy(cacertFile, defaultCaFile, sizeof(cacertFile));

}

void printAllArguments()
{

    printf("serverName : %s\n", serverName);
    printf("portNumber : %d\n", sslsServerPort);
    printf("certFile : %s\n",   certFile);
    printf("keyFile : %s\n",    keyFile);
    printf("keyStoreFolder : %s\n", keyStoreFolder);
    printf("cacertFile : %s\n", cacertFile);
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
                {"help",               no_argument,       0, 'h'},
                {0,                    0,                 0, 0},
        };

#ifndef __RTOS_WIN32__
        shortOptStr = "p:s:a:c:k:f:h";
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
            case 'a':
                strncpy(cacertFile, optarg, CERT_MAX_LEN);
                break;
            case 'k':
                keyfilePresent = 1;
                strncpy(keyFile, optarg, KEY_MAX_LEN);
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

#ifdef __ENABLE_DIGICERT_ENCRYPTED_PEM__
static int load_mocana_evp_engine()
{
    ENGINE *e = NULL;

    /* Loading Mocana engine for cryptograpic functionality */
    ENGINE_load_builtin_engines();

    e = ENGINE_by_id("mocana");

    if (e == NULL) {

        /*
         * A failure to load is probably a platform environment problem so we
         * don't treat this as an OpenSSL test failure, i.e. we return 0
         */
        fprintf(stderr, "Mocana Test: Failed to load Mocana Engine - skipping test\n");
        return 0;
    }

    ENGINE_set_default_ciphers(e);
    ENGINE_set_default_digests(e);

    return 1;
}
#endif

#if ( defined( __ENABLE_DIGICERT_SSL_ALERT_CALLBACK_SUPPORT__ ) )

void alert_msg_cb(int pWrite, int version, int contentType,
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

int main(int argc, char *argv[])
{
  SSL_CTX* ctx = NULL;
  int fd,ret;
  BIO* bio = NULL;
  BIO* outbio = NULL;
  SSL* ssl = NULL;
  struct sockaddr_in server_addr;
  X509 *cert = NULL;
  X509_NAME *certname = NULL;
  const SSL_METHOD *method = NULL;
  char   buffer[256];
  int retval;
  int status;
  char * fullpath = NULL;

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
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  /* ---------------------------------------------------------- *
   * Create the BIOs.                                           *
   * ---------------------------------------------------------- */
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0)
  {
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
  }

  /* ---------------------------------------------------------- *
   * Set DTLSv1						        *
   * ---------------------------------------------------------- */
  method = DTLS_client_method();

#ifdef __ENABLE_DIGICERT_ENCRYPTED_PEM__
  /* -----------------------------------------------------------*
   * Load Mocana EVP engine for performing crypto opeartions    *
   * ---------------------------------------------------------- */
  if (load_mocana_evp_engine() == 0)
  {
    BIO_printf(outbio, "Could not initialize the Mocana Engine !\n");
  }
#endif

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
  ctx = SSL_CTX_new(method);
  if(ctx == NULL)
  {
    BIO_printf(outbio, "Unable to create a new SSL context structure.\n");
  }

  /*SSL_CTX_set_cipher_list(ctx,"AESGCM");*/

  /* ---------------------------------------------------------- *
   * These should be enabled for mutual auth                    *
   * ---------------------------------------------------------- */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  getFullPath(keyStoreFolder, certFile, &fullpath);

  if(1 != (status = SSL_CTX_use_certificate_file(ctx, fullpath, SSL_FILETYPE_PEM)))
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

  getFullPath(keyStoreFolder, cacertFile, &fullpath);

  /* ---------------------------------------------------------- *
   * Load the server certificate into client trustchain	        *
   * ---------------------------------------------------------- */
  SSL_CTX_load_verify_locations(ctx, fullpath, NULL);


  /* ---------------------------------------------------------- *
   * Make the underlying UDP connection          	        *
   * ---------------------------------------------------------- */
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(sslsServerPort);
#ifdef __RTOS_WIN32__
  inet_pton(AF_INET, serverName, (struct in_addr* )&server_addr.sin_addr.s_addr);
#else
  inet_aton(serverName, (struct in_addr* )&server_addr.sin_addr.s_addr);
#endif

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  connect(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));


  /* ---------------------------------------------------------- *
   * Create a BIO for UDP socket                       	        *
   * ---------------------------------------------------------- */
  bio = BIO_new_dgram(fd, BIO_NOCLOSE);
  BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

#if ( defined( __ENABLE_DIGICERT_SSL_ALERT_CALLBACK_SUPPORT__ ) )
    SSL_set_msg_callback(ssl, alert_msg_cb);
    SSL_set_msg_callback_arg(ssl, NULL);
#endif

  /* ---------------------------------------------------------- *
   * Set the BIO and connect state                              *
   * ---------------------------------------------------------- */
  SSL_set_bio(ssl, bio, bio);
  SSL_set_connect_state(ssl);

  /*SSL_connect(ssl);*/
  /* ---------------------------------------------------------- *
   * Try to SSL_do_handshake, returns 1 for success             *
   * ---------------------------------------------------------- */
  if((ret=SSL_do_handshake(ssl)) != 1)
  {
      printf("Error %d\n",SSL_get_error (ssl, ret));
      BIO_printf(outbio, "Error: Could not build a SSL session.\n");
      exit(1);
  }
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session.\n");

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
  {
    printf("Error: Coudl not get certificate\n");
  }

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

  /* ---------------------------------------------------------- *
   * Send and Receive Data Over DTLS connection                 *
   * -----------------------------------------------------------*/

  sprintf((char*)buffer, "GET /%s HTTP/1.0\r\n\r\n", "Test");
  printf("Buffer %s\n",buffer);
  while(1)
  {
    retval = SSL_write(ssl,buffer,strlen(buffer));
    switch (SSL_get_error (ssl, retval))
        {
            case SSL_ERROR_NONE:
                if (retval == sizeof (buffer))
                {
                    fprintf (stderr, "%s(): Am done with my write\n", __func__);
                    goto READ;
                }
        break;
    }
    break;
   }

READ:
	memset(buffer,0,sizeof(buffer));
    int i;
    while(1)
    {
     	retval = SSL_read (ssl, buffer, sizeof (buffer));
		switch (SSL_get_error (ssl, retval))
		{
			case SSL_ERROR_NONE:
                    printf(" %s \n",buffer);
                    goto EXIT;
            default:
                printf("Case Default\n");
		}
	}

    /* ---------------------------------------------------------- *
     * Free the structures we don't need anymore                  *
     * -----------------------------------------------------------*/
EXIT:

  if(fullpath)
    free(fullpath);

  if(ssl)
    SSL_free(ssl);
  if(ctx)
    SSL_CTX_free(ctx);
  if(cert)
    X509_free(cert);

  ENGINE_cleanup();
  ERR_free_strings();
  EVP_cleanup();
  SSL_COMP_free_compression_methods();
  CRYPTO_cleanup_all_ex_data();

  printf("Finished DTLS connection with server: \n");
  BIO_free(outbio);
  return(0);
}
