/*
 * websocket_handshake.c
 *
 * WebSocket HTTP/1.1 Upgrade Handshake (RFC 6455 §4)
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */


#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

#include "websocket.h"
#include "../common/random.h"
#include "../common/base64.h"
#include "../crypto/sha1.h"
#include "websocket_handshake.h"

#include <stdio.h>

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#include "../ssl/ssl.h"
#endif

/*----------------------------------------------------------------------------*/

static byteBoolean WS_strCaseEq(const sbyte *pA, ubyte4 lenA, const sbyte *pB, ubyte4 lenB)
{
    ubyte4 i;
    if (lenA != lenB)
    {
        return FALSE;
    }

    for (i = 0; i < lenA; i++)
    {
        if (MTOLOWER(pA[i]) != MTOLOWER(pB[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static byteBoolean WS_containsCRLF(const sbyte *pValue)
{
    while ('\0' != *pValue)
    {
        if ('\r' == *pValue || '\n' == *pValue)
        {
            return TRUE;
        }
        pValue++;
    }

    return FALSE;
}

/*
 * Find the first \r\n in pBuf[0..len-1].
 * Sets *pLineLen to the byte count before \r\n and returns a pointer
 * to the first byte after \r\n (the start of the next line).
 * Returns NULL if no \r\n is found.
 */
static const sbyte *WS_findCRLF(const sbyte *pBuf, ubyte4 len, ubyte4 *pLineLen)
{
    ubyte4 i;
    for (i = 0; i + 1 < len; i++)
    {
        if ('\r' == pBuf[i] && '\n' == pBuf[i + 1])
        {
            *pLineLen = i;
            return pBuf + i + 2;
        }
    }
    return NULL;
}

/*
 * Check that the Connection header value contains the "Upgrade" token
 */
static byteBoolean WS_connectionHasUpgrade(const sbyte *pVal, ubyte4 valLen)
{
    ubyte4 i = 0;
    ubyte4 tokenStart = 0;
    ubyte4 tokenEnd   = 0;

    while (i < valLen)
    {
        tokenStart = i;
        while (i < valLen && ',' != pVal[i])
        {
            i++;
        }

        tokenEnd = i;

        /* remove leading whitespaces */
        while (tokenStart < tokenEnd && ('\x20' == pVal[tokenStart] || '\x09' == pVal[tokenStart]))
        {
            tokenStart++;
        }

        /* remove trailing whitespaces */
        while (tokenEnd > tokenStart && ('\x20' == pVal[tokenEnd - 1] || '\x09' == pVal[tokenEnd - 1]))
        {
            tokenEnd--;
        }

        if (WS_strCaseEq(pVal + tokenStart, tokenEnd - tokenStart, "Upgrade", 7))
        {
            return TRUE;
        }

        if (i < valLen)
        {
            /* skip comma */
            i++;
        }
    }

    return FALSE;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_generateKey(ubyte *pRawKey16, sbyte *pBase64Key)
{
    MSTATUS status     = OK;
    ubyte   *pEncoded  = NULL;
    ubyte4  encodedLen = 0;

    status = RANDOM_numberGenerator(g_pRandomContext, pRawKey16, WS_KEY_NONCE_LEN);
    if (OK != status)
    {
        goto exit;
    }

    status = BASE64_encodeMessage(pRawKey16, WS_KEY_NONCE_LEN, &pEncoded, &encodedLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY((ubyte *)pBase64Key, pEncoded, WS_KEY_BASE64_LEN);
    if (OK != status)
    {
        goto exit;
    }

    pBase64Key[WS_KEY_BASE64_LEN] = '\0';

exit:
    if (NULL != pEncoded)
    {
        status = BASE64_freeMessage(&pEncoded);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_computeAccept(const sbyte *pBase64Key, sbyte *pAcceptOut)
{
    MSTATUS status = OK;
    /* pBase64Key (24) + WS_GUID (36) = 60 bytes */
    ubyte  concat[60];
    ubyte  digest[SHA1_RESULT_SIZE];
    ubyte  *pEncoded  = NULL;
    ubyte4 encodedLen = 0;

    status = DIGI_MEMCPY(concat, (const ubyte *)pBase64Key, WS_KEY_BASE64_LEN);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(concat + WS_KEY_BASE64_LEN, (const ubyte *)WS_GUID, DIGI_STRLEN(WS_GUID));
    if (OK != status)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_SHA1_completeDigest(concat, 60, digest);
#else
    status = SHA1_completeDigest(concat, 60, digest);
#endif

    if (OK != status)
    {
        goto exit;
    }

    status = BASE64_encodeMessage(digest, SHA1_RESULT_SIZE, &pEncoded, &encodedLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY((ubyte *)pAcceptOut, pEncoded, encodedLen);
    if (OK != status)
    {
        goto exit;
    }

    pAcceptOut[encodedLen] = '\0';

exit:
    if (NULL != pEncoded)
    {
        status = BASE64_freeMessage(&pEncoded);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_buildUpgradeRequest(
    const sbyte  *pHost,
    ubyte2       port,
    const sbyte  *pPath,
    const sbyte  *pSubProtocol,
    const sbyte  *pBase64Key,
    sbyte        *pBuf,
    ubyte4       bufLen,
    ubyte4       *pWritten)
{
    MSTATUS status = OK;
    byteBoolean hasSubProtocol = (NULL != pSubProtocol && '\0' != *pSubProtocol);
    sbyte4 n = 0;

    if (NULL == pHost || NULL == pPath ||
        WS_containsCRLF(pHost) || WS_containsCRLF(pPath) ||
        (TRUE == hasSubProtocol && WS_containsCRLF(pSubProtocol)))
    {
        status = ERR_WS_HANDSHAKE_FAILED;
        goto exit;
    }

    if (0 != port)
    {
        if (hasSubProtocol)
        {
            n = snprintf((char *)pBuf, (size_t)bufLen,
                "GET %s HTTP/1.1\r\n"
                "Host: %s:%u\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Protocol: %s\r\n"
                "\r\n",
                pPath, pHost, (unsigned)port, pBase64Key, pSubProtocol);
        }
        else
        {
            n = snprintf((char *)pBuf, (size_t)bufLen,
                "GET %s HTTP/1.1\r\n"
                "Host: %s:%u\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n",
                pPath, pHost, (unsigned)port, pBase64Key);
        }
    }
    else
    {
        if (hasSubProtocol)
        {
            n = snprintf((char *)pBuf, (size_t)bufLen,
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Protocol: %s\r\n"
                "\r\n",
                pPath, pHost, pBase64Key, pSubProtocol);
        }
        else
        {
            n = snprintf((char *)pBuf, (size_t)bufLen,
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n",
                pPath, pHost, pBase64Key);
        }
    }

    if (n <= 0 || n >= (sbyte4)bufLen)
    {
        status = ERR_WS_HANDSHAKE_FAILED;
        goto exit;
    }

    *pWritten = (ubyte4)n;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_parseUpgradeResponse(
    const sbyte  *pResponse,
    ubyte4       responseLen,
    const sbyte  *pSubProtocol,
    const sbyte  *pBase64Key)
{
    MSTATUS      status     = ERR_WS_HANDSHAKE_FAILED;
    const sbyte  *pLine     = pResponse;
    ubyte4       remaining  = responseLen;
    const sbyte  *pNextLine = NULL;
    ubyte4       lineLen    = 0;
    byteBoolean  gotUpgrade = FALSE;
    byteBoolean  gotConn    = FALSE;
    byteBoolean  gotAccept  = FALSE;
    byteBoolean  gotSubProtocol = FALSE;
    sbyte        expectedAccept[29];
    sbyte4       cmpResult  = -1;
    const sbyte  *pName     = NULL;
    const sbyte  *pVal      = NULL;
    ubyte4       nameLen    = 0;
    ubyte4       valLen     = 0;
    ubyte4       colonIdx   = 0;
    byteBoolean  foundColon = FALSE;
    ubyte4       statusCode = 0;
    ubyte4       codeIdx    = 0;

    pNextLine = WS_findCRLF(pLine, remaining, &lineLen);
    if (NULL == pNextLine)
    {
        goto exit;
    }

    /* HTTP/1.1 101 Switching Protocols */
    if (lineLen < 12)
    {
        goto exit;
    }

    status = DIGI_MEMCMP((const ubyte *)pLine, (const ubyte *)"HTTP/1.1 ", 9, &cmpResult);
    if (OK != status)
    {
        goto exit;
    }

    status = ERR_WS_HANDSHAKE_FAILED;

    if (0 != cmpResult || (lineLen > 12 && ' ' != pLine[12]))
    {
        goto exit;
    }

    for (codeIdx = 9; codeIdx < 12; codeIdx++)
    {
        if ('0' > pLine[codeIdx] || '9' < pLine[codeIdx])
        {
            goto exit;
        }

        statusCode = (statusCode * 10) + (ubyte4)(pLine[codeIdx] - '0');
    }

    if (101 != statusCode)
    {
        if (401 == statusCode || 403 == statusCode || 407 == statusCode)
        {
            status = ERR_HTTP_RESPONSE;
        }

        goto exit;
    }

    remaining -= (ubyte4)(pNextLine - pLine);
    pLine = pNextLine;

    while (remaining > 0)
    {
        pNextLine = WS_findCRLF(pLine, remaining, &lineLen);
        if (NULL == pNextLine)
        {
            goto exit;
        }

        remaining -= (ubyte4)(pNextLine - pLine);

        /* end of headers */
        if (0 == lineLen)
        {
            break;
        }

        pName = NULL;
        pVal = NULL;
        nameLen = 0;
        valLen = 0;
        colonIdx = 0;
        foundColon = FALSE;

        for (colonIdx = 0; colonIdx < lineLen; colonIdx++)
        {
            if (':' == pLine[colonIdx])
            {
                foundColon = TRUE;
                break;
            }
        }

        if (FALSE == foundColon)
        {
            /* skip malformed header */
            pLine = pNextLine;
            continue;
        }

        pName   = pLine;
        nameLen = colonIdx;
        pVal    = pLine + colonIdx + 1;
        valLen  = lineLen - colonIdx - 1;

        /* remove leading whitespaces */
        while (valLen > 0 && ('\x20' == pVal[0] || '\x09' == pVal[0]))
        {
            pVal++;
            valLen--;
        }

        /* remove trailing whitespaces */
        while (valLen > 0 && ('\x20' == pVal[valLen - 1] || '\x09' == pVal[valLen - 1]))
        {
            valLen--;
        }

        if (WS_strCaseEq(pName, nameLen, "Upgrade", 7))
        {
            if (!WS_strCaseEq(pVal, valLen, "websocket", 9))
            {
                goto exit;
            }

            gotUpgrade = TRUE;
        }
        else if (WS_strCaseEq(pName, nameLen, "Connection", 10))
        {
            if (!WS_connectionHasUpgrade(pVal, valLen))
            {
                goto exit;
            }

            gotConn = TRUE;
        }
        else if (WS_strCaseEq(pName, nameLen, "Sec-WebSocket-Accept", 20))
        {
            status = WS_computeAccept(pBase64Key, expectedAccept);
            if (OK != status)
            {
                goto exit;
            }

            cmpResult = -1;
            status = DIGI_MEMCMP((const ubyte *)pVal, (const ubyte *)expectedAccept, 28, &cmpResult);
            if (OK != status)
            {
                goto exit;
            }

            if (28 != valLen || 0 != cmpResult)
            {
                status = ERR_WS_HANDSHAKE_FAILED;
                goto exit;
            }

            gotAccept = TRUE;
        }
        else if (WS_strCaseEq(pName, nameLen, "Sec-WebSocket-Extensions", 24))
        {
            /* this implementation doesn't support extensions */
            goto exit;
        }
        else if (WS_strCaseEq(pName, nameLen, "Sec-WebSocket-Protocol", 22))
        {
            /* Fail if server returns a subprotocol we didn't request
             * or returns one that doesn't match what we asked for.
             */
            if (NULL == pSubProtocol || '\0' == *pSubProtocol ||
                !WS_strCaseEq(pVal, valLen, pSubProtocol, DIGI_STRLEN(pSubProtocol)))
            {
                status = ERR_WS_SUBPROTOCOL_MISMATCH;
                goto exit;
            }
            gotSubProtocol = TRUE;
        }

        pLine = pNextLine;
    }

    if (pSubProtocol != NULL && '\0' != *pSubProtocol && FALSE == gotSubProtocol)
    {
        status = ERR_WS_SUBPROTOCOL_MISMATCH;
        goto exit;
    }

    if (FALSE == gotUpgrade || FALSE == gotConn || FALSE == gotAccept)
    {
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_performHandshake(
    WsContext    *pCtx,
    const sbyte  *pHost,
    ubyte2       port,
    const sbyte  *pSubProtocol,
    const sbyte  *pPath)
{
    MSTATUS status = OK;
    ubyte rawKey16[WS_KEY_NONCE_LEN];
    sbyte base64Key[WS_KEY_BASE64_LEN + 1];
    ubyte4 i          = 0;
    ubyte4 reqLen     = 0;
    ubyte4 respLen    = 0;
    ubyte4 headerEnd  = 0;
    ubyte4 scanFrom   = 0;
    byteBoolean found = FALSE;
    sbyte *pReqBuf    = NULL;
    sbyte *pRespBuf   = NULL;
    ubyte4 scanEnd;

    pCtx->state = WS_STATE_CONNECTING;

    status = DIGI_MALLOC((void **)&pReqBuf, WS_RAW_BUF_SIZE);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pRespBuf, WS_RAW_BUF_SIZE);
    if (OK != status)
    {
        goto exit;
    }

    status = WS_generateKey(rawKey16, base64Key);
    if (OK != status)
    {
        goto exit;
    }

    status = WS_buildUpgradeRequest(pHost, port, pPath, pSubProtocol, base64Key,
                                    pReqBuf, WS_RAW_BUF_SIZE, &reqLen);
    if (OK != status)
    {
        goto exit;
    }

    if (WS_TRANSPORT_TCP == pCtx->transportType)
    {
        ubyte4 written = 0;
        status = TCP_WRITE(pCtx->socket, pReqBuf, reqLen, &written);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        sbyte4 sent = SSL_send(pCtx->sslConnInst, pReqBuf, (sbyte4)reqLen);
        if (sent < 0)
        {
            status = (MSTATUS) sent;
            goto exit;
        }
        if (sent != (sbyte4)reqLen)
        {
            status = ERR_WS_HANDSHAKE_FAILED;
            goto exit;
        }
#else
        status = ERR_WS_HANDSHAKE_FAILED;
        goto exit;
#endif
    }

    /* Read HTTP 101 response until \r\n\r\n found or buffer full */
    while (FALSE == found)
    {
        if (WS_TRANSPORT_TCP == pCtx->transportType)
        {
            ubyte4 nRead = 0;
            status = TCP_READ_AVL_EX(pCtx->socket,
                                     pRespBuf + respLen,
                                     (ubyte4)(WS_RAW_BUF_SIZE - respLen),
                                     &nRead,
                                     WS_HANDSHAKE_TIMEOUT_MS);
            if (OK != status || 0 == nRead)
            {
                status = ERR_WS_HANDSHAKE_FAILED;
                goto exit;
            }

            respLen += nRead;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
            sbyte4 nRecv = 0;
            status = SSL_recv(pCtx->sslConnInst,
                              pRespBuf + respLen,
                              (sbyte4)(WS_RAW_BUF_SIZE - respLen),
                              &nRecv,
                              WS_HANDSHAKE_TIMEOUT_MS);
            if (OK != status)
            {
                goto exit;
            }
            if (0 >= nRecv)
            {
                status = ERR_WS_HANDSHAKE_FAILED;
                goto exit;
            }

            respLen += (ubyte4)nRecv;
#else
            status = ERR_WS_HANDSHAKE_FAILED;
            goto exit;
#endif
        }

        /* optimal way to scan for end of response */
        scanEnd = (respLen >= 3) ? respLen - 3 : 0;
        for (i = scanFrom; i < scanEnd; i++)
        {
            if ('\r' == pRespBuf[i] && '\n' == pRespBuf[i + 1] &&
                '\r' == pRespBuf[i + 2] && '\n' == pRespBuf[i + 3])
            {
                headerEnd = i;
                found = TRUE;
                break;
            }
        }
        if (FALSE == found)
        {
            scanFrom = (respLen >= 3) ? respLen - 3 : 0;
        }

        if (FALSE == found && respLen >= WS_RAW_BUF_SIZE)
        {
            status = ERR_WS_HANDSHAKE_FAILED;
            goto exit;
        }
    }

    status = WS_parseUpgradeResponse(pRespBuf, headerEnd + 4, pSubProtocol, base64Key);
    if (OK != status)
    {
        goto exit;
    }

    pCtx->state = WS_STATE_OPEN;

exit:
    if (OK != status)
    {
        pCtx->state = WS_STATE_CLOSED;
    }

    if (NULL != pReqBuf)
    {
        DIGI_FREE((void**)&pReqBuf);
    }

    if (NULL != pRespBuf)
    {
        DIGI_FREE((void**)&pRespBuf);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */
