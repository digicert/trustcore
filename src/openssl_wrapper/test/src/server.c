/* ------------------------------------------------------------ *
 * file:        server.c                                        *
 * author:      04/27/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#include "server.h"

int create_socket_server(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }
    return s;
}

int Server_Init_Test(struct Config* config)
{
    int status = EXIT_PASS;
    long *sslctxOptions;
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    int sock, ret;
    char strFunctionName[50];

    printf("\nServer initialization started\n");
   /* ---------------------------------------------------------- *
    * These function calls initialize openssl for correct work.  *
    * ---------------------------------------------------------- */
    printf("Adding all algorithms to the table (digests and ciphers\n");
    OpenSSL_add_ssl_algorithms();
    printf("Loading crypto error strings\n");
    ERR_load_crypto_strings();
    printf("Loading ssl error strings\n");
    SSL_load_error_strings();

    if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                         SSLV3_SERVER_METHOD)))
    {
        printf("Setting SSLv3 server hello\n");
        method = SSLv3_server_method();
        strcpy(strFunctionName, "SSLv3_server_method");
    }
    else if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                              TLSV1_SERVER_METHOD)))
    {
        printf("Setting TSLv1 server hello\n");
        method = TLSv1_server_method();
        strcpy(strFunctionName, "TLSv1_server_method");
    }
    else if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                              TLSV1_1_SERVER_METHOD)))
    {
        printf("Setting TSLv1_1 server hello\n");
        method = TLSv1_1_server_method();
        strcpy(strFunctionName, "TLSv1_1_server_method");
    }
    else if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                              TLSV1_2_SERVER_METHOD)))
    {
        printf("Setting TSLv1_2 server hello\n");
        method = TLSv1_2_server_method();
        strcpy(strFunctionName, "TLSv1_2_server_method");
    }
    else
    {
        printf("Setting SSLv2 server hello, also announce SSLv3 and TLSv1\n");
        method = SSLv23_server_method();
        strcpy(strFunctionName, "SSLv23_server_method");
    }
    if (method != NULL)
        LOG_PRINT(strFunctionName);
    else
    {
        check_ssl_api_error(strFunctionName);
        status = EXIT_FAIL;
        goto end;
    }
    if (method != NULL)
    {
        LOG_PRINT(strFunctionName);
    }
    else
    {
        check_ssl_api_error(strFunctionName);
        status = EXIT_FAIL;
        goto end;
    }

    printf("Setting new CTX\n");
    ctx = SSL_CTX_new(method);
    if ((method==NULL && ctx==NULL) ||
        (method==NULL && ctx!=NULL) ||
        (method==NULL && ctx!=NULL))
    {
        check_ssl_api_error("SSL_CTX_new");
        status = EXIT_FAIL;
        goto end;
    }
    if (method!=NULL && ctx!=NULL)
    {
        LOG_PRINT("SSL_CTX_new::PASSED");
    }

   /*Setting SSL CONTEXT Options*/
    if (EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                         SSL_CTX_SET_OPTIONS)))
    {
        if (EXIT_PASS!=(status=(CheckSSLCTXSetOptions(ctx))))
            goto end;
    }

   /*Get SSL Context Option*/
    if(EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                        SSL_CTX_GET_OPTIONS)))
    {
       if (EXIT_PASS!=(status==CheckSSLCTXGetOptions(ctx, sslctxOptions)))
           goto end;
    }
    /*Clear SSL context value*/
    if(EXIT_PASS==(status=CheckTestCase(config->testCases.initCases,
                                        SSL_CTX_CLEAR_OPTIONS)))
    {
       if (EXIT_PASS!=(status==CheckSSLCTXClearOptions(ctx)))
           goto end;
    }

    printf("Setting certificate file \"%s\" for server\n",
           config->certificate_file);
    if (EXIT_PASS>=(status=SSL_CTX_use_certificate_file
              (ctx, config->certificate_file, SSL_FILETYPE_PEM)))
    {
        check_ssl_api_error("SSL_CTX_use_certificate_file");
        goto end;
    }

    printf("Setting private key file  \"%s\" for server\n",
           config->private_key_file);
    if (EXIT_PASS>=(status=SSL_CTX_use_PrivateKey_file
              (ctx, config->private_key_file, SSL_FILETYPE_PEM)))
    {
        check_ssl_api_error("SSL_CTX_use_PrivateKey_file");
        goto end;
    }
    sock = create_socket_server(config->port);
    printf("Server initialization completed\n");

    if (EXIT_PASS!=(status=CheckTestCase
              (config->testCases.handshakeCases, SERVER_HANDSHAKE)))
    {
        printf("Basic test group id %d for Server handshake is Not Found. "
               "Test aborted\n", SERVER_HANDSHAKE);
        goto end;
    }
    else
    {
        printf("\nServer handshake started\n");
        if (EXIT_PASS!=(status=Server_Handshake_Test(config, ctx, sock)))
        {
            printf("Server handshake failed. Please refer logs.\n");
            goto end;
        }
    }

end:
    return status;
}

int Server_Handshake_Test(struct Config* config, SSL_CTX* ctx, int sock)
{
    int client;
    int status = EXIT_PASS;
    struct sockaddr_in addr;
    uint len;
    SSL *ssl;

    //Handle connections
    while(1)
    {
        printf("\nwaiting for new connection ... \n");
        len = sizeof(addr);
        client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            status = EXIT_FAIL;
            goto end;
        }
        printf("Creating new SSL connection state object\n");
        ssl = SSL_new(ctx);
        if ((ctx==NULL && ssl==NULL) ||
            (ctx==NULL && ssl!=NULL) ||
            (ctx!=NULL && ssl==NULL))
        {
            check_ssl_api_error("SSL_new");
            return EXIT_FAIL;
        }
        if (ctx!=NULL && ssl!=NULL)
        {
            LOG_PRINT("SSL_new::PASSED");
        }

        printf("Atempting to attach the SSL session to the socket descriptor\n");
        SSL_set_fd(ssl, client);
        printf("Calling SSL_accept\n");
        if (SSL_accept(ssl)>0)
        {
            if (EXIT_PASS!=(status=CheckTestCase
                     (config->testCases.data_exchCases,SERVER_DATA_EXCH)))
            {
                printf("Basic test group id %d for Server data-exchange is "
                       "Not Found. Test aborted\n", SERVER_DATA_EXCH);
                goto end;
            }
            else
            {
                if (EXIT_PASS!=(status=Server_Data_Exchange_Test(config, ssl)))
                {
                    printf("Server data-exchange failed. Please refer logs.\n");
                    goto end;
                }
            }
        }
        else
        {
            check_ssl_api_error("SSL_accept");
            status = EXIT_FAIL;
            goto end;
        }

        printf("Calling SSL_free\n");
        SSL_free(ssl);
        printf("Closing the connection with the client\n");
        close(client);
    }
    printf("\nServer handshake completed\n");

    if(EXIT_PASS!=(status=CheckTestCase
            (config->testCases.cleanupCases, SERVER_CLEANUP)))
    {
       printf("Basic test group id %d for Server cleanup is "
              "Not Found. Test aborted\n", SERVER_CLEANUP);
       goto end;
    }
    else
    {
       if (EXIT_PASS!=(status=Server_CleanUp_Test(config, sock)))
       {
           printf("Server connection cleanup failed. Please refer logs.\n");
           goto end;
       }
    }

end:
    return status;
}

int Server_Data_Exchange_Test(struct Config* config, SSL* ssl)
{
    int status = EXIT_PASS;
    const char reply[] = "OpenSSL_TestHarness Server Message\n";
    printf("\nServer data_exchange started\n");
    char buf[1024];
    int bytes;

    if (EXIT_PASS==(status=CheckTestCase(config->testCases.data_exchCases,
                                         SSL_WRITE)))
    {
        printf("Calling ssl_write\n");
        if (SSL_write(ssl, reply, strlen(reply))<=0)
        {
            check_ssl_api_error("SSL_write");
        }
        else
        {
            LOG_PRINT("SSL_write::PASSED");
        }
    }

    if (EXIT_PASS==(status=CheckTestCase(config->testCases.data_exchCases,
                                        SSL_READ)))
    {
        if((bytes=SSL_read(ssl, buf, sizeof(buf)))<=0)
        {
            check_ssl_api_error("SSL_read");
        }
        else
        {
            buf[bytes]=0;
            printf("-------------------------------\n");
            printf("Message Recieved from client: %s", buf);
            printf("-------------------------------\n");
            LOG_PRINT("SSL_read::PASSED");
        }
    }
    printf("Server data_exchange completed\n");

end:
    return status;
}

int Server_CleanUp_Test(struct Config* config, int sock)
{
    int status = EXIT_PASS;
    printf("\nServer cleanup started\n");
    close(sock);
    LOG_PRINT("Finished SSL/TLS connection with client:");
    printf("Server cleanup completed\n");

end:
    return status;
}
