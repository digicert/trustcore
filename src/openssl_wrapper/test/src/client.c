/* ------------------------------------------------------------ *
 * file:        client.c                                		*
 * author:      04/27/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#include "client.h"

/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
int create_socket(char* dest_str, int Port) 
{
    int    sockfd;
    char   hostname[256]           = "";
    char   portnum[6]              = "";
    char   url_str[MAX_URL_LENGTH] = "";
    char   proto[6]                = "";
    char  *tmp_ptr                 = NULL;
    int    port                    = Port;
    struct hostent *host;
    struct sockaddr_in dest_addr;
    strcpy(url_str, dest_str);

   /* ---------------------------------------------------------- *
    * Remove the final / from url_str, if there is one           *
    * ---------------------------------------------------------- */
    if (url_str[strlen(url_str)] == '/')
    {
        url_str[strlen(url_str)] = '\0';
    }

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
    if (strchr(hostname, ':')) 
    {
        tmp_ptr = strchr(hostname, ':');
       /*the last : starts the port number, if avail, i.e. 8443 */
        strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
        *tmp_ptr = '\0';
        port = atoi(portnum);
    }

    if ((host = gethostbyname(hostname)) == NULL ) 
    {
        LOG_PRINT("Error: Cannot resolve hostname %s.\n",  hostname);
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
    if (connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1) 
    {
        LOG_PRINT("Error: Cannot connect to host %s [%s] on port %d.\n",
		                hostname, tmp_ptr, port);
        return EXIT_FAIL;
    }

    return sockfd;
}

int Client_Init_Test(struct Config* config)
{
    int status = EXIT_PASS;
    int ret;
    SSL_CTX *ctx;
    const SSL_METHOD *method;
    char strFunctionName[50];
    long* sslctxOptions;

    printf("\nClient initialization started\n");
   /* ---------------------------------------------------------- *
    * These function calls initialize openssl for correct work.  *
    * ---------------------------------------------------------- */
    printf("Adding all algorithms to the table (digests and ciphers)\n");
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    printf("Loading crypto error strings\n");
    ERR_load_crypto_strings();
    printf("Loading ssl error strings\n");
    SSL_load_error_strings();

   /* ---------------------------------------------------------- *
    * initialize SSL library and register algorithms             *
    * ---------------------------------------------------------- */
    printf("Initializing SSL library and register algorithms\n");
    if (SSL_library_init() < 0)
    {
        LOG_PRINT("Could not initialize the OpenSSL library! Error:: %s",
        ossl_err_as_string());
        status = EXIT_FAIL;
        goto end;
    }

   /* ---------------------------------------------------------- *
    * Set SSLv3/SSLv23/TSLv1/TSLv1_1/TSLv1_2 client hello        *
    * ---------------------------------------------------------- */
    if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                         SSLV3_CLIENT_METHOD)))
    {
        printf("Setting SSLv3 client hello\n");
        method = SSLv3_client_method();
        strcpy(strFunctionName, "SSLv3_client_method");
    }
    else if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                              TLSV1_CLIENT_METHOD)))
    {
        printf("Setting TSLv1 client hello\n");
        method = TLSv1_client_method();
        strcpy(strFunctionName, "TLSv1_client_method");
    }
    else if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                              TLSV1_1_CLIENT_METHOD)))
    {
        printf("Setting TSLv1_1 client hello\n");
        method = TLSv1_1_client_method();
        strcpy(strFunctionName, "TLSv1_1_client_method");
    }
    else if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                              TLSV1_2_CLIENT_METHOD)))
    {
        printf("Setting TSLv1_2 client hello\n");
        method = TLSv1_2_client_method();
        strcpy(strFunctionName, "TLSv1_2_client_method");
    }
    else
    {
        printf("Setting SSLv2 client hello, also announce SSLv3 and TLSv1\n");
        method = SSLv23_client_method();
        strcpy(strFunctionName, "SSLv23_client_method");
    }
    if (method != NULL)
    {
        LOG_PRINT("%s::PASSED", strFunctionName);
    }
    else
    {
        check_ssl_api_error(strFunctionName);
        status = EXIT_FAIL;
        goto end;
    }

    printf("Setting new CTX\n");
    ctx = SSL_CTX_new(method);
    if((method==NULL && ctx==NULL) ||
       (method==NULL && ctx!=NULL) ||
       (method!=NULL && ctx==NULL))
    {
        LOG_PRINT("Unable to create a new SSL context structure.");
        check_ssl_api_error("SSL_CTX_new");
        status = EXIT_FAIL;
        goto end;
    }
    if(method!=NULL && ctx!=NULL)
        LOG_PRINT("SSL_CTX_new::PASSED");

   /*Setting SSL CONTEXT Options*/
    if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                         SSL_CTX_SET_OPTIONS)))
    {
        if(EXIT_PASS!=(status=(CheckSSLCTXSetOptions(ctx))))
           goto end;
    }

   /*Get SSL Context Option*/
    if(EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                        SSL_CTX_GET_OPTIONS)))
    {
       if(EXIT_PASS!=(status==CheckSSLCTXGetOptions(ctx, sslctxOptions)))
          goto end;
    }
    /*Clear SSL context value*/
    if(EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                        SSL_CTX_CLEAR_OPTIONS)))
    {
       if(EXIT_PASS!=(status==CheckSSLCTXClearOptions(ctx)))
          goto end;
    }

   
    printf("Client initialization completed\n");

    if (EXIT_PASS!=(status=CheckTestCase
              (config->testCases.handshakeCases, CLIENT_HANDSHAKE)))
    {
        printf("Basic test group id %d for Client handshake is Not Found. "
               "Test aborted\n", CLIENT_HANDSHAKE);
        goto end;
    }
    else
    {
        if (EXIT_PASS!=(status = Client_Handshake_Test(config, ctx)))
        {
            printf("Client handshake failed. Please refer logs.\n");
            goto end;
        }
    }

end:
  return status;
}

int Client_Handshake_Test(struct Config* config, SSL_CTX* ctx)
{
    int          status  = EXIT_PASS;
    int          ret;
    int          server; 
    int          count   = 1;
    SSL_SESSION *session = NULL;
    SSL         *ssl     = NULL;
    int          session_reuse =0;

reuse:
   /* ---------------------------------------------------------- *
    * Make the underlying TCP socket connection                  *
    * create_socket() creates the socket & TCP-connect to server *
    * ---------------------------------------------------------- */
    printf("\nClient handshake started\n");
   /* ---------------------------------------------------------- *
    * Create new SSL connection state object                     *
    * ---------------------------------------------------------- */
    printf("Creating new SSL connection state object\n");
    ssl = SSL_new(ctx);
    if((ctx==NULL && ssl==NULL) ||
       (ctx==NULL && ssl!=NULL) ||
       (ctx!=NULL && ssl==NULL))
    {
        check_ssl_api_error("SSL_new");
        status = EXIT_FAIL;
        goto end;
    }
    if(ctx!=NULL && ssl!=NULL)
    {
        LOG_PRINT("SSL_new::PASSED");
    }
    if (EXIT_PASS==(status=CheckTestCase
              (config->testCases.initCases, SSL_SET_SESSION)))
    {
        if (NULL != session)
        {
            printf("Setting Session for reuse\n"); 
            ret = SSL_set_session(ssl, session); 
            if (ret!=1)
            {
                check_ssl_api_error("SSL_set_session");
                status = EXIT_FAIL;
                goto end;
            }
            else
            {
                LOG_PRINT("SSL_set_session::PASSED");
            }
        } 
    }

    printf("Attempting to create a TCP socket connection\n");
    server = create_socket(config->dest_url, config->port);
    if (server > 0)
    {
        LOG_PRINT("Successfully created the socket.");
        printf("Successfully created the socket\n");
    }
    else
    {
        printf("Failed to created the socket\n");
        status = EXIT_FAIL;
        goto end;
    }

   /* ---------------------------------------------------------- *
    * Attach the SSL session to the socket descriptor            *
    * ---------------------------------------------------------- */
    printf("Atempting to attach the SSL session to the socket descriptor\n");
    ret=SSL_set_fd(ssl, server);
    if ((ssl==NULL && ret <=0) ||
        (ssl==NULL && ret ==1) ||
        (ssl!=NULL && ret<=0))
    {
        check_ssl_api_error("SSL_set_fd");
        status = EXIT_FAIL;
        goto end;
    }
    if (ssl!=NULL && ret ==1)
    {
        LOG_PRINT("SSL_set_fd::PASSED");
    }
   /* ---------------------------------------------------------- *
    * Try to SSL-connect here, returns 1 for success             *
    * ---------------------------------------------------------- */
    printf("Atempting for SSL_connect\n");
    ret = SSL_connect(ssl);
    if ( ret != 1 )
    {
        check_ssl_api_error("SSL_connect");
        LOG_PRINT("Error: Could not build a SSL session to: %s", config->dest_url);
        status = EXIT_FAIL;
        goto end;
    }
    else
        LOG_PRINT("Successfully enabled SSL/TLS session to: %s", config->dest_url);

    if ((ssl==NULL && ret <=0) ||
        (ssl==NULL && ret ==1) ||
        (ssl!=NULL && ret <=0))
    {
        check_ssl_api_error("SSL_connect");
        status = EXIT_FAIL;
        goto end;
    }
    if(ssl!=NULL && ret ==1)
    {
       LOG_PRINT("SSL_connect::PASSED");
    }

    if (EXIT_PASS==(status=CheckTestCase
              (config->testCases.handshakeCases, SSL_GET1_SESSION)))
    {
        	printf("Getting Session for reuse\n");
        	session = SSL_get1_session(ssl);
        	if (NULL!=session)
        	{
            		printf("Session re-used. Session id is -->  %d\n",
                                    (unsigned char)session->session_id[0]);
        	}
     }

    printf("Client handshake completed\n");

    if (EXIT_PASS!=(status=CheckTestCase
              (config->testCases.data_exchCases, CLIENT_DATA_EXCH)))
    {
        printf("Basic test group id %d for Client data-exchange is Not Found. "
               "Test aborted\n", CLIENT_DATA_EXCH);
        goto end;
    }
    else
    {
        printf("\nClient data-exchange started\n");
        if (EXIT_PASS!=(status=Client_Data_Exchange_Test(config,ssl, server,session_reuse)))
        {
            printf("Client Data Exchange failed. Please refer logs.\n");
            goto end;
        }
    }

    if (EXIT_PASS==(status=CheckTestCase
              (config->testCases.initCases, SSL_SET_SESSION)))
    {
        if (config->max_session_reuse > count)
        {
            count++;
            session_reuse = 1;
            goto reuse;
        }
    }

end:
    return status;
}

int Client_Data_Exchange_Test(struct Config* config, SSL* ssl, int server, int session_reuse)
{
    int        status   = EXIT_PASS;
    X509_NAME *certname = NULL;
    BIO       *outbio   = NULL;
    X509      *cert     = NULL;
    const char reply[]  = "OpenSSL_TestHarness Client Message\n";
    char buf[1024];
    int bytes;

   if (session_reuse)
   {
     goto DATA_EXCHANGE;
   }
   /* ---------------------------------------------------------- *
    * Get the remote certificate into the X509 structure         *
    * ---------------------------------------------------------- */
    printf("Getting the remote certificate into the X509 structure\n");
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        check_ssl_api_error("SSL_get_peer_certificate");
        LOG_PRINT("Error: Could not get a certificate from: %s",
                   config->dest_url);
        status = EXIT_FAIL;
        goto end;
    }
    else
    {
        LOG_PRINT("Retrieved the server's certificate from: %s",
                  config->dest_url);
    }

    if ((ssl == NULL && cert == NULL) ||
        (ssl == NULL && cert != NULL) ||
        (ssl != NULL && cert == NULL))
    {
         check_ssl_api_error("SSL_get_peer_certificate");
         status = EXIT_FAIL;
         goto end;
    }
    if (ssl != NULL && cert != NULL)
    {
        LOG_PRINT("SSL_get_peer_certificate::PASSED");
    }

DATA_EXCHANGE:

    if (EXIT_PASS==(status=CheckTestCase(config->testCases.data_exchCases,
                                         SSL_WRITE)))
    {
        printf("Calling ssl_write\n");
        if (SSL_write(ssl, reply, strlen(reply))<=0)
        {
            check_ssl_api_error("SSL_write");
        }
    }

    if (EXIT_PASS==(status=CheckTestCase(config->testCases.data_exchCases,
                                         SSL_READ)))
    {
        printf("Calling ssl_read\n");
        if ((bytes=SSL_read(ssl, buf, sizeof(buf)))<=0)
        {
            check_ssl_api_error("SSL_read");
        }
        else
        {
            buf[bytes]=0;
            printf("-------------------------------\n");
            printf("Message Recieved from Server: %s", buf);
            printf("-------------------------------\n");
        }
    }

    printf("Client data-exchange completed\n");

    if (EXIT_PASS!=(status=CheckTestCase
              (config->testCases.cleanupCases, CLIENT_CLEANUP)))
    {
        printf("Basic test group id %d for Client cleanup is Not Found. "
               "Test aborted\n", CLIENT_CLEANUP);
        goto end;
    }
    else
    {
        printf("\nClient cleanup started\n");
        if (EXIT_PASS!=(status=Client_CleanUp_Test(config, ssl, server)))
        {
            printf("Client Cleanup failed. Please refer logs.\n");
            goto end;
        }
    }

end:
    return status;
}

int Client_CleanUp_Test(struct Config* config, SSL* ssl, int server)
{
    int status = EXIT_PASS;
    printf("Attempting to cleanup\n");
    close(server);
    SSL_free(ssl);
    LOG_PRINT("Finished SSL/TLS connection with server: %s", config->dest_url);
    printf("Finished SSL/TLS connection with server: %s\n", config->dest_url);
    printf("Client cleanup completed\n");

end:
    return status;
}
