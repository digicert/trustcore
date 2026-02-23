/* ------------------------------------------------------------ *
 * file:        openssl_client.c                                *
 * purpose:     Example code for building a SSL connection and  *
 *              retrieving the server certificate.              *
 * author:      06/12/2012 Frank4DD                             *
 * source:      http://fm4dd.com/openssl/sslconnect.htm         *
 *                                                              *
 * gcc -o openssl_client openssl_client.c -lssl -lcrypto        *
 * ------------------------------------------------------------ */

/*
 * openssl_client.c
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

#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
int create_socket(char[], BIO *);

int doData(SSL* ssl)
{
  char data[1024] = {0};
  char buf[1024] = {0};
  int status;
  int bytes;

  /* This GET request should return a 404 NOT FOUND response */
  (void) sprintf((char  *)data, "GET /%s HTTP/1.0\r\n\r\n", "Test");
  printf("Calling SSL_write\n");
  if(0 >= (status = SSL_write(ssl, data, strlen(data))))
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
  return 1;
}

int main() {

  char dest_url[] = "https://www.rediff.com";
  BIO *outbio = NULL;
  X509 *cert = NULL;
  X509_NAME *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL_CIPHER *cipher;
  SSL *ssl;
  int server = 0;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
#if !defined(__ENABLE_DIGICERT_OSSL_LOAD_ALL_ALGORITHMS__)
  /* If Underlying NanoSSL library and this sample client is built with this flag,
   * the below function is invoked by NanoSSL in OSSL_init */
  OpenSSL_add_all_algorithms();
#endif

  ENGINE_load_builtin_engines();

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
   * Set server name indication (SNI)                           *
   * ---------------------------------------------------------- */
  if (1 != SSL_set_tlsext_host_name(ssl, "www.rediff.com"))
  {
    BIO_printf(outbio, "Error: Could not set SNI using SSL_set_tlsext_host_name\n");
  }

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

  /* ---------------------------------------------------------- *
   * Enable the server certificate verification                 *
   * ---------------------------------------------------------- */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
  if ( SSL_connect(ssl) != 1 )
  {
      BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
      exit(1);
  }
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

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
  certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Retrieve selected cipher suite                             *
   * -----------------------------------------------------------*/

  cipher= (SSL_CIPHER*) SSL_get_current_cipher(ssl);
  BIO_printf(outbio," Selected cipher suite is : %s id:- %d\n",
        SSL_CIPHER_get_name(cipher),SSL_CIPHER_get_id(cipher));

  if(0 > doData(ssl))
  {
	printf("Error doData\n");
  }
  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  SSL_free(ssl);
  X509_free(cert);
  SSL_CTX_free(ctx);

  ENGINE_cleanup();
  ERR_free_strings();
  EVP_cleanup();
  SSL_COMP_free_compression_methods();
  CRYPTO_cleanup_all_ex_data();

  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
  
  if(outbio) {
    BIO_free_all(outbio);
  }
  return(0);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "";
  char portnum[6] = "443";
  char proto[6] = "";
  char *tmp_ptr = NULL;
  int port;
  struct hostent *host;
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

  port = atoi(portnum);

  if ( (host = gethostbyname(hostname)) == NULL ) {
    BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
    abort();
  }

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
  }

  return sockfd;
}
