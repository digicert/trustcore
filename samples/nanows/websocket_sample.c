/*
 * websocket_sample.c
 *
 * Simple WebSocket bidirectional messaging client.
 * Connects to a WebSocket server, sends lines read from stdin as binary
 * frames, and prints received data to stdout.
 *
 * Supports plain WebSocket (ws://) and WebSocket over TLS (wss://).
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 */

#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

#include <stdio.h>
#include <string.h>
#include "websocket.h"
#include "mocana.h"
#include "debug_console.h"

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#include "ssl.h"
#include "cert_store.h"

static MSTATUS acceptAnyCert(sbyte4 connInst, struct certChain *pChain, MSTATUS status)
{
    MOC_UNUSED(connInst);
    MOC_UNUSED(pChain);
    MOC_UNUSED(status);
    return OK;
}
#endif

/*----------------------------------------------------------------------------*/

#define DEFAULT_HOST        "localhost"
#define DEFAULT_PORT_WS     8080
#define DEFAULT_PORT_WSS    8443
#define DEFAULT_SUBPROTOCOL "mqtt"
#define DEFAULT_PATH        "/"
#define RECV_TIMEOUT        5000
#define LINE_BUF_SIZE       4096
#define RECV_BUF_SIZE       4096

/*----------------------------------------------------------------------------*/

static void printUsage(const char *pProg)
{
    fprintf(stderr,
        "Usage: [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -h HOST         Server hostname       (default: localhost)\n"
        "  -p PORT         Server port           (default: 8080 or 8443 with --tls)\n"
        "  -P PATH         WebSocket path        (default: /)\n"
        "  -s SUBPROTOCOL  WebSocket subprotocol (default: mqtt)\n"
        "  --tls           Use TLS (wss://)\n"
        "  --ca-cert FILE  DER-encoded CA certificate for server verification\n"
        "  --insecure      Skip server certificate verification\n"
        "  --ssl-log       Enable SSL debug logging\n"
        "  --help          Show this help message\n"
    );
}

/*----------------------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    MSTATUS      status        = OK;
    sbyte4       initDone      = 0;
    TCP_SOCKET   sock          = 0;
    sbyte4       sockOpen      = 0;
    WsContext    *pWsCtx       = NULL;
    sbyte        lineBuf[LINE_BUF_SIZE];
    sbyte        recvBuf[RECV_BUF_SIZE];
    ubyte4       nRecv         = 0;
    byteBoolean  timedOut      = FALSE;
    const sbyte  *pHost        = (const sbyte *)DEFAULT_HOST;
    ubyte2       port          = 0;
    const sbyte  *pSubProtocol = (const sbyte *)DEFAULT_SUBPROTOCOL;
    const sbyte  *pPath        = (const sbyte *)DEFAULT_PATH;
    sbyte4       useTLS        = 0;
    sbyte4       insecure      = 0;
    sbyte4       sslLog        = 0;
    const char   *pCaCertFile  = NULL;
    int          i;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    sbyte4       sslInited     = 0;
    sbyte4       sslConnInst   = -1;
    certStorePtr pCertStore    = NULL;
    ubyte        *pCaCertData  = NULL;
    ubyte4       caCertLen     = 0;
#endif

    for (i = 1; i < argc; i++)
    {
        if (0 == strcmp(argv[i], "--help") || 0 == strcmp(argv[i], "-?"))
        {
            printUsage(argv[0]);
            return 0;
        }
        else if (0 == strcmp(argv[i], "--tls"))
        {
            useTLS = 1;
        }
        else if (0 == strcmp(argv[i], "--insecure"))
        {
            insecure = 1;
        }
        else if (0 == strcmp(argv[i], "--ssl-log"))
        {
            sslLog = 1;
        }
        else if (0 == strcmp(argv[i], "--ca-cert") && (i + 1) < argc)
        {
            pCaCertFile = argv[++i];
        }
        else if (0 == strcmp(argv[i], "-h") && (i + 1) < argc)
        {
            pHost = (const sbyte *)argv[++i];
        }
        else if (0 == strcmp(argv[i], "-p") && (i + 1) < argc)
        {
            port = (ubyte2)DIGI_ATOL((const sbyte *)argv[++i], NULL);
        }
        else if (0 == strcmp(argv[i], "-P") && (i + 1) < argc)
        {
            pPath = (const sbyte *)argv[++i];
        }
        else if (0 == strcmp(argv[i], "-s") && (i + 1) < argc)
        {
            pSubProtocol = (const sbyte *)argv[++i];
        }
        else
        {
            fprintf(stderr, "Unknown option: %s\n\n", argv[i]);
            printUsage(argv[0]);
            return 1;
        }
    }

    if (0 == port)
    {
        port = useTLS ? (ubyte2)DEFAULT_PORT_WSS : (ubyte2)DEFAULT_PORT_WS;
    }

    if (useTLS && !insecure && !pCaCertFile)
    {
        fprintf(stderr, "Error: --tls requires --ca-cert <file> or --insecure\n");
        return 1;
    }

#if !defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (useTLS)
    {
        fprintf(stderr,
                "Error: TLS not available (built without __ENABLE_DIGICERT_SSL_CLIENT__)\n");
        return 1;
    }
#endif

    if (0 != (status = (MSTATUS)DIGICERT_initDigicert()))
    {
        fprintf(stderr, "DIGICERT_initDigicert failed: %d\n", (int)status);
        goto exit;
    }
    initDone = 1;

    if (!sslLog)
    {
        DEBUG_CONSOLE_unsetPrintClass(DEBUG_SSL_MESSAGES);
    }

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (useTLS)
    {
        status = (MSTATUS)SSL_init(0, 1);
        if (OK != status)
        {
            fprintf(stderr, "SSL_init failed: %d\n", (int)status);
            goto exit;
        }

        sslInited = 1;

        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
        {
            fprintf(stderr, "CERT_STORE_createStore failed: %d\n", (int)status);
            goto exit;
        }

        if (NULL != pCaCertFile)
        {
            status = (MSTATUS)DIGICERT_readFile(pCaCertFile, &pCaCertData, &caCertLen);
            if (OK != status)
            {
                fprintf(stderr, "Failed to read CA cert '%s': %d\n",
                        pCaCertFile, (int)status);
                goto exit;
            }

            status = CERT_STORE_addTrustPoint(pCertStore, pCaCertData, caCertLen);
            if (OK != status)
            {
                fprintf(stderr, "CERT_STORE_addTrustPoint failed: %d\n", (int)status);
                goto exit;
            }
        }
    }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

    status = TCP_CONNECT(&sock, (sbyte *)pHost, port);
    if (OK != status)
    {
        fprintf(stderr, "TCP_CONNECT to %s:%d failed: %d\n",
                pHost, (int)port, (int)status);
        goto exit;
    }
    sockOpen = 1;

    status = WS_createContext(&pWsCtx, WS_PAYLOAD_BUF_SIZE);
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (useTLS)
    {
        printf("Connecting to wss://%s:%d%s%s ...\n",
               pHost, (int)port, pPath, insecure ? " (insecure)" : "");

        sslConnInst = SSL_connect(sock, 0, NULL, NULL,
                                  (const sbyte *)pHost,
                                  insecure ? NULL : pCertStore);
        if (0 > sslConnInst)
        {
            fprintf(stderr, "SSL_connect failed: %d\n", (int)sslConnInst);
            status = (MSTATUS)sslConnInst;
            goto exit;
        }

        if (insecure)
        {
            SSL_setCertAndStatusCallback(sslConnInst, acceptAnyCert);
        }

        status = (MSTATUS)SSL_negotiateConnection(sslConnInst);
        if (OK != status)
        {
            fprintf(stderr, "SSL_negotiateConnection failed: %d\n", (int)status);
            goto exit;
        }

        status = WS_connectSSL(pWsCtx, sslConnInst, pHost, port, pSubProtocol, pPath);
    }
    else
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
    {
        printf("Connecting to ws://%s:%d%s ...\n", pHost, (int)port, pPath);
        status = WS_connect(pWsCtx, sock, pHost, port, pSubProtocol, pPath);
    }

    if (OK != status)
    {
        fprintf(stderr, "WS handshake failed: %d\n", (int)status);
        goto exit;
    }

    printf("Connected. Type messages and press Enter (Ctrl-D to quit).\n\n");
    printf("Client sends -> ");

    while (NULL != fgets(lineBuf, LINE_BUF_SIZE, stdin))
    {
        ubyte4 len = DIGI_STRLEN(lineBuf);

        if (0 == len)
        {
            continue;
        }

        status = WS_mqttTransportSend(0, pWsCtx, lineBuf, len);
        if (OK != status)
        {
            fprintf(stderr, "Send failed: %d\n", (int)status);
            break;
        }

        timedOut = FALSE;
        status = WS_mqttTransportRecv(0, pWsCtx, recvBuf,
                                      (ubyte4)(RECV_BUF_SIZE - 1),
                                      &nRecv, RECV_TIMEOUT, &timedOut);

        if (ERR_WS_CLOSE_RECEIVED == status)
        {
            printf("\nServer closed the connection.\n");
            status = OK;
            break;
        }

        if (OK != status)
        {
            fprintf(stderr, "Recv failed: %d\n", (int)status);
            break;
        }

        if (TRUE == timedOut || 0 == nRecv)
        {
            printf("(no response within %d ms)\n", RECV_TIMEOUT);
            continue;
        }

        recvBuf[nRecv] = '\0';
        printf("Server replies -> %s", recvBuf);
        if ('\n' != recvBuf[nRecv - 1])
        {
            printf("\n");
        }

        printf("Client sends -> ");
    }

    if (feof(stdin))
    {
        printf("\nDisconnecting...\n");
        status = OK;
    }

exit:
    if (NULL != pWsCtx)
    {
        WS_close(pWsCtx, WS_CLOSE_NORMAL);
        WS_freeContext(&pWsCtx);
    }

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }

    if (NULL != pCaCertData)
    {
        DIGI_FREE((void **)&pCaCertData);
    }

    if (sslInited)
    {
        SSL_shutdownStack();
    }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

    if (sockOpen)
    {
        TCP_CLOSE_SOCKET(sock);
    }

    if (initDone)
    {
        DIGICERT_freeDigicert();
    }

    return (OK == status) ? 0 : 1;
}

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */
