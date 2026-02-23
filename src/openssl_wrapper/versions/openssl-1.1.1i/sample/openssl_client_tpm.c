/* ------------------------------------------------------------- *
 * file:        openssl_client_tpm.c                             *
 * purpose:     Example code for building a SSL connection and   *
 *              retrieving the server certificate.               *
 *                                                               *
 *              This example was modified for using TPM-         *
 *              generated keys for client authentication.        *
 *                                                               *
 * author:      06/12/2012 Frank4DD                              *
 * source:      http://fm4dd.com/openssl/sslconnect.htm          *
 *                                                               *
 * gcc -D__ENABLE_DIGICERT_HW_SECURITY_MODULE__ \                  *
 *     -D__ENABLE_DIGICERT_TPM__ \                                 *
 *     -D__RTOS_LINUX__ \                                        *
 *     -o openssl_client_tpm openssl_client_tpm.c \              *
 *     -I../include -I../../../src -L ../../../bin_static \      *
 *     -lopenssl_shim -lnanossl -lcrypto -lnanocrypto \          *
 *     -lpthread -lrt -ldl                                       *
 * ------------------------------------------------------------- */

/*
 * openssl_client_tpm.c
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
#else
#include <WinSock2.h>
#include <ms/applink.c>
#endif
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#ifdef __ENABLE_DIGICERT_TPM__
#include "../../../src/openssl_wrapper/ossl_tap.h"

/* If running client against a server hosted on localhost
 * and port 1440 enable define USE_LOCALHOST flag.
 * If not defined we run the client against https://www.google.com
 *
 * */
#define USE_LOCALHOST

/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
int create_socket(char[], BIO *);


MSTATUS doData(SSL* ssl)
{
  char data[1024];
  char buf[1024];
  MSTATUS status;
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

int main()
{

#ifdef USE_LOCALHOST
  char dest_url[] = "127.0.0.1";
#else
  char dest_url[] = "https://www.google.com";
#endif
  BIO *outbio = NULL;
  X509 *cert = NULL;
  X509_NAME *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  const char *private_key_file = "../../../bin/keystore/client_tpm_key.pem";
  const char *certificate_file = "../../../bin/keystore/client_tpm_cert.pem";
  const char *server_certificate = "../../../bin/keystore/RSACertCA.pem";
  MSTATUS status;
  MOCTAP_HANDLE mh;
  sbyte4 connectionInstance = ERR_GENERAL;
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
#ifdef __ENABLE_DIGICERT_TPM__
#ifdef __ENABLE_DIGICERT_TPM_EMULATOR__
  if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"localhost", &mh)))
#else
  if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"/dev/tpm0", &mh)))
#endif
  {
    printf("Error Unable to initialize MOCTAP Context");
    exit(1);
  }
#endif

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
  server = create_socket(dest_url, outbio);
  if(server != 0)
    BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, server);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if(SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM) < 0)
  {
    BIO_printf(outbio, "Error: SSL_CTX_use_certificate_file() failed\n");
  }

  if(SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) < 0)
  {
    BIO_printf(outbio, "Error: SSL_CTX_use_PrivateKey_file() failed\n");
  }

  SSL_CTX_load_verify_locations(ctx, server_certificate, NULL);
  if(OK > OSSL_KeyAssociateTapContext(mh, ctx))
  {
    BIO_printf(outbio, "Error: Could not associate the Key with TAP context \n");
    exit(1);
  }
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
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

#ifdef USE_LOCALHOST
  if(OK > doData(ssl))
  {
	printf("Error doData\n");
  }
#endif
  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  SSL_free(ssl);
  X509_free(cert);
  SSL_CTX_free(ctx);
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
  return(0);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "";

#ifdef USE_LOCALHOST
  char portnum[6] = "1440";
#else
  char portnum[6] = "443";
#endif

  char *tmp_ptr = NULL;
  int port;
  struct sockaddr_in dest_addr;

#ifndef USE_LOCALHOST
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
#endif
  port = atoi(portnum);

  /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
#ifdef USE_LOCALHOST
  dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
#else
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
#endif
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
  }

  return sockfd;
}
#endif /* __ENABLE_DIGICERT_TPM__ */
