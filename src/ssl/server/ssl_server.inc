/*
 * ssl_server.inc
 *
 * SSL Server Specific Functionality
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __SSL_SERVER_INC__
#define __SSL_SERVER_INC__

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
#include "../../dtls/server/dtls_server.inc"
#endif

/*------------------------------------------------------------------*/

extern RTOS_MUTEX gSslSessionCacheMutex;

#ifdef __ENABLE_DIGICERT_TLS13__
/* TLS 1.3 : Random value that identifies HRR.
 * RFC : 4.1.3.  Server Hello.
 */
const ubyte serverHrrRandom[] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

const ubyte serverTls12Random[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

const ubyte serverTls11Random[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};

MSTATUS SSL_SOCK_constructTLSExtSupportedVersions(SSLSocket* pSSLSock, ubyte** ppVersionBuffer,ubyte versionMask);


#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined( __ENABLE_DIGICERT_TLS13_0RTT__))
MSTATUS
SSL_SOCK_constructTLSExtEarlyData(SSLSocket *pSSLSock, ubyte handshakeType, ubyte **ppPacket);
#endif


#endif /* __ENABLE_DIGICERT_TLS13__ */

/* SESSION RESUMPTION */
/* array used for session resumption */
typedef struct SessionInfo
{
    SESSIONID               m_sessionId;
    const CipherSuiteInfo*  m_pCipherSuite;
    ubyte                   m_masterSecret[SSL_MASTERSECRETSIZE];
    moctime_t               startTime;
    ubyte                   m_minorVersion;
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    const SrtpProfileInfo*  m_pSrtpProfile;
#endif
    ubyte2                  m_signatureAlgo; /* for TLS 1.2 */
	ubyte4                  m_clientECCurves;
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    intBoolean              isExtendedMasterSecret;
#endif

} SessionInfo;

static SESSIONID gNextSessionId;

#define SESSION_CACHE_SIZE (10)
static SessionInfo gSessionCache[SESSION_CACHE_SIZE];

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
static ubyte gSessionTicketKeyName[SSL_SESSION_TICKET_KEY_NAME_SIZE];
static ubyte gSessionTicketEncKey[SSL_SESSION_TICKET_ENC_KEY_SIZE];
static ubyte gSessionTicketMacKey[SSL_SESSION_TICKET_MAC_KEY_SIZE];
#endif

/* This is used for CRYPTO_INTERFACE_DH_generateKeyPairExt */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#define MOCANA_DEFAULT_DH_NUM_Y_BYTES 24
#endif

/* END SESSION RESUMPTION */

#ifndef MOCANA_MAX_MODULUS_SIZE
#define MOCANA_MAX_MODULUS_SIZE     (1024)
#endif

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
static ubyte4 calculateExtraFragmentHeader(SSLSocket *pSSLSock, ubyte4 numBufs);
static MSTATUS fragmentHandshakeMessages(SSLSocket *pSSLSock, ubyte4 fragmentLen);
#if defined(__ENABLE_DIGICERT_DTLS_SRTP__)
static sbyte4 SSLSOCK_selectSrtpProfile( const SSLSocket* pSSLSock, sbyte4 start,
                            ubyte* clientSrtpProfiles, sbyte4 clientSrtpProfileLen);
#endif
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
static MSTATUS acknowledgeCurrentRecord(SSLSocket *pSSLSock);
static MSTATUS addReceivedRecord(SSLSocket* pSSLSock);
#endif

static MSTATUS
SSLSOCK_setClientTrafficKeyMaterial(SSLSocket *pSSLSock, ubyte *pSecret);
/*------------------------------------------------------------------*/
static MSTATUS
constructTLSExtCookie(SSLSocket *pSSLSock, ubyte **ppPacket)
{
    MSTATUS status = OK;

    setShortValue(*ppPacket, (ubyte2)tlsExt_cookie);
    *ppPacket += sizeof(ubyte2);

    /* Total Length */
    setShortValue(*ppPacket, (ubyte2)((pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize)+2));
    *ppPacket += sizeof(ubyte2);

    /* cookie Length */
    setShortValue(*ppPacket, (ubyte2)pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize);
    *ppPacket += sizeof(ubyte2);

    /* RFC 8446 Section 4.2.2.
     *
     * Calculate the cookie value which is the digest of the ClientHello. For
     * the HelloRetryRequest the cookie value is the digest of the ClientHello
     * sent by the client.
     */
    if (OK > (status = SSLSOCK_calcTranscriptHashForBuffer(MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
        (ubyte *) pSSLSock->pReceiveBuffer,
        pSSLSock->recordSize, pSSLSock->helloCookie)))
    {
        DIGI_MEMSET(pSSLSock->helloCookie, '\0', pSSLSock->helloCookieLen);
        pSSLSock->helloCookieLen = 0;
        goto exit;
    }

    pSSLSock->helloCookieLen = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize;
    DIGI_MEMCPY(*ppPacket, pSSLSock->helloCookie, pSSLSock->helloCookieLen);
    *ppPacket += pSSLSock->helloCookieLen;

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
constructHelloRetryRequestCookie(SSLSocket *pSSLSock, ubyte **ppPacket)
{
    return constructTLSExtCookie(pSSLSock,ppPacket);
}
#endif /* __ENABLE_DIGICERT_TLS13__ */
/*------------------------------------------------------------------*/

static MSTATUS
SSLSOCK_selectApplicationLayerProtocol(SSLSocket* pSSLSock,
                                       ubyte *alpnList,
                                       sbyte4 alpnListLen)
{
    MSTATUS status = OK;
    ubyte** nextProtocols = NULL;
    sbyte4 numNextProtocols;
    ubyte* pAlpnBuffer = NULL;
    const ubyte* found;
    sbyte4 i=0;
    sbyte4 j=0;
    ubyte4 totalLen = 0;
    ubyte* tmp;

    if(!alpnList || !alpnListLen)
    { /* Empty List */
        goto exit;
    }

#ifndef __DISABLE_DIGICERT_ALPN_CALLBACK__
    if (NULL !=  pSSLSock->funcPtrAlpnCallback) /* callback is defined */
    {
     /* Invoke the callback */
        status = pSSLSock->funcPtrAlpnCallback(SSL_findConnectionInstance(pSSLSock),&nextProtocols ,&numNextProtocols,alpnList, alpnListLen);
        if (!nextProtocols || !numNextProtocols)
        {
            status = OK;
            goto exit;
        }
        /* Convert the from String Array */
        totalLen = 0;
        /* first loop: verify data is correct and compute total length */
        for (i = 0; i < numNextProtocols; ++i)
        {
            ubyte4 protocolLen = DIGI_STRLEN((const sbyte*) nextProtocols[i]);
            if (0 == protocolLen || protocolLen > 0xFF)
            {
                /*protocol must not be empty and be less than 0xFF in length*/
                status = ERR_SSL_EXTENSION_INVALID_ALPN_PROTOCOL;
                goto exit;
            }
            totalLen += 1 + protocolLen;
        }

        if (totalLen > 0xFFFF)
        {
            status = ERR_SSL_EXTENSION_INVALID_ALPN_PROTOCOL;
            goto exit;
        }

        pAlpnBuffer = (ubyte*) MALLOC( totalLen);
        if (NULL == pAlpnBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET(pAlpnBuffer, '\0', totalLen);
        tmp = pAlpnBuffer;
        /* second loop: copy data */
        for (i = 0; i < numNextProtocols; ++i)
        {
            *tmp = (ubyte) DIGI_STRLEN((const sbyte*) nextProtocols[i]);
            DIGI_MEMCPY(tmp+1, nextProtocols[i], *tmp);
            tmp += 1 + *tmp;
        }
        /* Update the session ALPN List with computed Values */
        if (NULL != pSSLSock->alpnProtocols)
        {
          FREE(pSSLSock->alpnProtocols);
        }
        pSSLSock->alpnProtocols = pAlpnBuffer;
        pSSLSock->alpnProtocolsLen = totalLen;
    }
#endif

   if (!pSSLSock->alpnProtocols || !pSSLSock->alpnProtocolsLen)
   {
     /* if the client does not send any protocol or there
       was no protocol specified for the server -- no error */
       status = OK;
       goto exit;
   }

    /* Initialize status to NO MATCH */
    status = ERR_SSL_EXTENSION_NO_ALPN_MATCH;
    /* look for match in the server order of preference */
    while (j < pSSLSock->alpnProtocolsLen)
    {
        status = SSLSOCK_findPascalStringInList( pSSLSock->alpnProtocols + j,
                                                alpnList, alpnListLen,
                                                &found);
        /* if status is FOUND, done */
        if (ERR_NOT_FOUND != status)
        {
            pSSLSock->selectedALPN = pSSLSock->alpnProtocols + j;
            goto exit;
        }
        /* protocol not found, increment index */
        j += 1 + pSSLSock->alpnProtocols[j];
    }

exit:
    return status;
}

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
static MSTATUS validatePskBinder(SSLSocket *pSSLSock, ubyte *pPskBinder, 
                ubyte numOfBinders, ubyte2 selectedIdentityIndex)
{
    MSTATUS status = OK;
    ubyte*  pPartialClientHello;
    ubyte4  partialClientHelloLength = 0;
    ubyte*  pSHSH;
    ubyte4  sizeofHandshakeHeader;
    sbyte4  recLen;
    ubyte2  totalBinderLength = pSSLSock->roleSpecificInfo.server.bindersLength;
    ubyte2  binderLength = 0;
    ubyte2  binderOffset = 0;
    ubyte   index = 0;
    ubyte *ppPartialDigests[NUM_SSL_SUPPORTED_HASH_ALGORITHMS] = { 0 };
    ubyte4 hashIndex;

    pSHSH = (ubyte*)pSSLSock->pReceiveBuffer;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        recLen = getMediumValue(((DTLSHandshakeHeader *)pSHSH)->handshakeSize);
        recLen += sizeofHandshakeHeader;
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        recLen = getMediumValue(((SSLHandshakeHeader *)pSHSH)->handshakeSize);
        recLen += sizeofHandshakeHeader;
    }

    if (recLen <= (totalBinderLength + BINDER_LENGTH_VARIABLE))
    {
        status = ERR_SSL_EXTENSION_LENGTH;
        goto exit;
    }

    partialClientHelloLength = recLen - totalBinderLength - BINDER_LENGTH_VARIABLE;
    pPartialClientHello      = pSHSH;

    binderLength = *pPskBinder;
    pPskBinder++;

    binderOffset += (binderLength + 1);

    while(totalBinderLength >= binderOffset)
    {
        /* RFC 8446 Section 4.2.11
         *
         * The binder value is defined as
         *
         *   opaque PskBinderEntry<32..255>;
         *
         * Ensure that binder value retrieved does not exceed the RFC defined
         * minimum length. The maximum length is defined as 255 but the length
         * is stored as a single byte so there is no upper bound check required.
         */
        if (SSL_PSK_TLS13_MIN_BINDER_LENGTH > binderLength)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        if (index == selectedIdentityIndex)
        {
            ubyte* pTempBinder = NULL;
            ubyte4 tempBinderLen = 0;
            sbyte4 cmpResult = -1;
            const BulkHashAlgo *pHashAlgo = NULL;

            pHashAlgo = getHashSuite((ubyte4)pSSLSock->roleSpecificInfo.server.pSelectedPSK->hashAlgo);
            if (NULL == pHashAlgo)
            {
                status = ERR_SSL_HASH_ALGO_NULL;
                goto exit;
            }

            status = SSLSOCK_computePartialDigests(
                pSSLSock, ppPartialDigests, NUM_SSL_SUPPORTED_HASH_ALGORITHMS,
                pPartialClientHello, partialClientHelloLength, pHashAlgo,
                &hashIndex);
            if (OK > status)
            {
                goto exit;
            }

            /* We have traversed to the binder for selected PSK; This should be validated now */
            if (OK > (status = SSLSOCK_pskBinderEntry(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock, ppPartialDigests[hashIndex], pHashAlgo->digestSize,
                                                      pSSLSock->roleSpecificInfo.server.pSelectedPSK->pskTLS13,
                                                      pSSLSock->roleSpecificInfo.server.pSelectedPSK->pskTLS13Length,
                                                      pSSLSock->roleSpecificInfo.server.pSelectedPSK->isExternal,
                                                      pHashAlgo, (ubyte**)&pTempBinder, &tempBinderLen)))
            {
                goto exit1;
            }
            if (tempBinderLen != ((ubyte4)binderLength))
            {
                goto exit1;
            }

            if (OK > (status = DIGI_MEMCMP(pTempBinder, pPskBinder, binderLength, &cmpResult)))
            {
                goto exit1;
            }

            if (cmpResult != 0)
            {
                status = ERR_SSL_PSK_BAD_CONFIG;
                goto exit1;
            }

exit1:
            if (pTempBinder)
            {
                DIGI_FREE((void**)&pTempBinder);
            }

            if (OK > status)
            {
                goto exit;
            }
            break;
        }
        if (totalBinderLength <= binderOffset)
            break;
        index++;
        pPskBinder += binderLength;
        binderLength = *pPskBinder;
        pPskBinder++;
        binderOffset += (binderLength + 1);
    }

exit:
    for (hashIndex = 0; hashIndex < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; hashIndex++)
    {
        DIGI_FREE((void **) &(ppPartialDigests[hashIndex]));
    }
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS validateTicketAge(
    SSLSocket *pSSLSock, tls13PSK *pPsk, ubyte4 age, byteBoolean *isValid)
{
    MSTATUS status = OK;
    ubyte4 clientTime;

    if (pPsk->isExternal)
    {
        *isValid = TRUE;
    }
    else
    {
        clientTime = (age - pPsk->pskTLS13AgeAdd) / 1000;

        if (clientTime > pPsk->pskTLS13LifetimeHint)
        {
            *isValid = FALSE;
        }
        else
        {
            *isValid = TRUE;
        }
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_TLS13_PSK__ */

/*------------------------------------------------------------------*/

static MSTATUS
SSLSOCK_extractServerNameIndication(SSLSocket* pSSLSock,
                                    ubyte *pServerNameList,
                                    sbyte4 serverNameListLen)
{
    ubyte4  nameLength;
    MSTATUS status = OK;
    ubyte   nameType;

    if (3 > serverNameListLen)
    {
        status = ERR_SSL_EXTENSION_SERVER_LIST_LENGTH;
        goto exit;
    }

    nameType = *pServerNameList;
    if (0 != nameType)
    {
        /* expected name_type (0) */
        status = ERR_SSL_EXTENSION_SERVER_LIST_LENGTH;
        goto exit;
    }

    /* skip past name_type */
    pServerNameList++;
    serverNameListLen--;

    /* skip past host_name length field */
    nameLength = getShortValue(pServerNameList);
    pServerNameList += 2;
    serverNameListLen -= 2;

    if ((sbyte4)nameLength > serverNameListLen)
    {
        /* they lied, bad length */
        status = ERR_SSL_EXTENSION_SERVER_NAME_LENGTH;
        goto exit;
    }
    else if ((sbyte4) nameLength < serverNameListLen)
    {
        /* RFC 6066; only one nameType allowed, duplicates not allowed */
        status = ERR_SSL_EXTENSION_DUPLICATE_NAMETYPE_SNI;
        goto exit;
    }

    /* skip past host_name string */
    FREE(pSSLSock->serverNameIndication);
    pSSLSock->serverNameIndication = MALLOC(nameLength + 1);
    if (!pSSLSock->serverNameIndication)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pSSLSock->serverNameIndication, pServerNameList, nameLength)))
        goto exit;

    pSSLSock->serverNameIndication[nameLength] = 0;

exit:
    return status;
}

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_SERVER__))
/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_setCipherById( SSLSocket* pSSLSock, ubyte2 cipherId)
{
    sbyte4 cipherIndex;

    if ( !pSSLSock)
        return ERR_NULL_POINTER;

    /* retrieve the cipher suite */
    cipherIndex = SSL_SOCK_getCipherTableIndex(pSSLSock, cipherId);

    if (cipherIndex < 0)
        return ERR_FALSE; /* not a supported cipher */

    pSSLSock->pHandshakeCipherSuite = gCipherSuites + cipherIndex;
    return OK;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_SERVER__))
static MSTATUS
processPACOpaque(SSLSocket* pSSLSock, ubyte* pPacOpaque, ubyte4 pacOpaqueLen)
{
    MSTATUS status;

    if (!SSL_sslSettings()->funcPtrPACOpaqueCallback)
        return ERR_EAP_FAST_NO_PACOPAQUECALLBACK;

    if (OK > (status = (MSTATUS)SSL_sslSettings()->funcPtrPACOpaqueCallback(
            SSL_findConnectionInstance(pSSLSock), pPacOpaque, pacOpaqueLen, pSSLSock->pacKey)))
    {
        return status;
    }

    /* do the rest only if we are not resuming already */
    if ( E_NoSessionResume == pSSLSock->sessionResume)
    {
        /* the cipher is fixed */
        if ( OK > ( status = SSL_SOCK_setCipherById( pSSLSock, 0x0005)))
        {
            return status;
        }

        pSSLSock->sessionResume = E_SessionEAPFASTResume;
    }

    return OK;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_OPENSSL_SHIM__)
static MSTATUS
retrieveClientHelloExtensions(SSLSocket* pSSLSock, ubyte4 sizeofHandshakeHeader,
                 ubyte** ppClientHelloVersion, sbyte4 recLen,ubyte* noExtensions)
{
    MSTATUS status = OK;
    ubyte* pData;
    ubyte* pSHSH;
    sbyte4 totalExtensionsLen = 0;
    sbyte4 cipherSuiteLen = 0;
    ubyte* pClientVersion = NULL;
    ubyte2 remainingLength = 0;
    ubyte sessionIDLen = 0;
    ubyte compressionLen = 0;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    ubyte cookieLen = 0;
    ubyte *pHelloCookie = NULL;
    ubyte4 helloCookieLen;
    sbyte4 cmpCookieResult;
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte2 extensionType;
    ubyte2 extensionLen;
    ubyte supportedVersionExtension = 0;
    intBoolean cookieReceived;
    ubyte *pTemp = NULL;
    ubyte versionLen = 0;
#endif

    pSHSH = (ubyte*)pSSLSock->pReceiveBuffer;
    remainingLength = recLen;
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    ClientHelloData helloData;
#endif

    if ((2 /*version*/ + SSL_RANDOMSIZE + 1 /* sessionIdLen */) > recLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* If the version is lower than TLS 1.2, then there should not be a "supported_versions" extension.
       If there is "supported_version" extension, the version in this field should be TLS 1.2 or DTLS 1.2
       if negotiating DTLS 1.3. 
    */
    pClientVersion = pSHSH + sizeofHandshakeHeader;
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    helloData.legacy_version = getShortValue(pClientVersion);
#endif

    /* Jump 2 bytes for version */
    pData = pSHSH + sizeofHandshakeHeader + 2;
    remainingLength -= 2;
    
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    helloData.random = pData;
    helloData.random_len = SSL_RANDOMSIZE; 
#endif

    /* Jump RANDOMSIZE bytes */
    pData += SSL_RANDOMSIZE;
    remainingLength -= SSL_RANDOMSIZE;

    /* Jump 1(sessionIdLen) + sessionIdLen */
    sessionIDLen = *pData;
    pData += 1;
    remainingLength -= 1;

#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    helloData.session_id = pData;
    helloData.session_id_len = sessionIDLen;
#endif

    if (remainingLength < sessionIDLen)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }
    pData += sessionIDLen;
    remainingLength -= sessionIDLen;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        /* Jump  1(cookie len) + cookie length bytes*/
        if (remainingLength < 1)
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }
        cookieLen = *pData;
        pData += 1;
        remainingLength -= 1;

        if (remainingLength < cookieLen)
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }
        pData += cookieLen;
        remainingLength -= cookieLen;
    }
#endif

    /* Make sure we have valid cipher suite */
    if (2 >= remainingLength)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    cipherSuiteLen = getShortValue(pData);
    pData += 2;
    remainingLength -= 2;

#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    helloData.ciphers = pData;
    helloData.ciphers_len = cipherSuiteLen;
#endif

    if (cipherSuiteLen >= remainingLength)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    pData += cipherSuiteLen;
    remainingLength -= cipherSuiteLen;

    if (1 >= remainingLength)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    compressionLen = *pData;
    pData += 1;
    remainingLength -= 1;

#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    helloData.compression_methods = pData;
    helloData.compression_methods_len = compressionLen;
#endif

    /* SSLv3 ClientHello may not send any extensions or extensionslength field */
    if (compressionLen > remainingLength)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    pData += compressionLen;
    remainingLength -= compressionLen;

    /* Now we arrive at the extensions...!! */
    /* Make sure we have extensions of length greater than 0 */
    /* SSLv3 ClientHello may not have any extensions;
     * check for the version field before trying to read extensions
     */
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if(pClientVersion[1] <= SSL3_MINORVERSION)
    {
        goto exit;
    }
#endif

    if (2 > remainingLength)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    totalExtensionsLen = getShortValue(pData);
    pData += 2;
    remainingLength -= 2;

#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    helloData.extensions = pData;
    helloData.extensions_len = totalExtensionsLen;
#endif
    if (totalExtensionsLen > remainingLength)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    if(totalExtensionsLen == 0)
    {
        status = ERR_SSL_PROTOCOL_VERSION;
        *noExtensions = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    cookieReceived = FALSE;
    while(totalExtensionsLen > 0)
    {
        if (4 > totalExtensionsLen)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        extensionType = getShortValue(pData);
        pData += 2;
        totalExtensionsLen -= 2;

        extensionLen = getShortValue(pData);
        pData += 2;
        totalExtensionsLen -= 2;

        if (extensionLen > totalExtensionsLen)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        if(extensionType == tlsExt_supported_versions)
        {
            ubyte minSupportedVersion;
            status = ERR_SSL_PROTOCOL_VERSION;

            supportedVersionExtension = 1;
            if (pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET)
            {
                minSupportedVersion = pSSLSock->minFallbackMinorVersion;
            }
            else
            {
                minSupportedVersion = SSL3_MINORVERSION;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    minSupportedVersion = MIN_DTLS_MINORVERSION;
                }
#endif
            }

            /* Check that the version in legacy version field is TLS 1.2, if this extension is found */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                if(pClientVersion[1] != DTLS12_MINORVERSION)
                {
                    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, "Legacy version not set correctly \n");
                    status = ERR_SSL_PROTOCOL;
                    continue; /* we might still be looking for cookie extension */
                }
            }
            else
#endif
            {
                if(pClientVersion[1] != TLS12_MINORVERSION)
                {
                    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, "Legacy version not set correctly \n");
                    status = ERR_SSL_PROTOCOL;
                    goto exit;
                }
            }
            /*Skip version Length*/
            if (extensionLen < 1)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            pTemp = pData;
            versionLen = *pTemp;
            pTemp++;
            if (versionLen != (extensionLen - 1) || versionLen & 1)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            /* If version is set on Server via SSL_ioctl,
               parse through the versions provided by client
               - select the one configured on server and
                 make sure that is >= minimum supported version
               - If there is no match, then thrown an error*/
            if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
            {
                ubyte2 pVersion;
                while (versionLen > 0)
                {
                    pVersion = getShortValue(pTemp);
                    if ((pSSLSock->advertisedMinorVersion == (pVersion & 0x00FF)) &&
                       (minSupportedVersion <= (pVersion & 0x00FF)))
                    {
                        pClientVersion = pTemp;
                        status = OK;
                        goto exit;
                    }
                    versionLen -= 2; /* Each version specified are 2 bytes long */
                    pTemp += 2;
                }

                DEBUG_PRINT(DEBUG_SSL_TRANSPORT, "advertised \n");
                status = ERR_SSL_PROTOCOL_VERSION;
                goto exit;
            }
            else
            {
                /* If no version is set, then select the first version offered by client,
                   which is supported by the server */
                ubyte maxSupportedVersion = SSL_sslSettings()->sslMaxProtoVersion;
                ubyte2 pVersion;
                while (versionLen > 0)
                {
                    pVersion = getShortValue(pTemp);
                    if ((!pSSLSock->isDTLS && minSupportedVersion <= (pVersion & 0x00FF) && (pVersion & 0x00FF) <= maxSupportedVersion) ||
                         (pSSLSock->isDTLS && minSupportedVersion >= (pVersion & 0x00FF) && (pVersion & 0x00FF) >= maxSupportedVersion))
                    {
                        switch(pVersion & 0x00FF)
                        {
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
#ifndef __ENABLE_DIGICERT_OPENSSL_SHIM__
                            /* OpenSSL connector only supports DTLS 1.2 or lower */
                            case DTLS13_MINORVERSION:
#endif
                            case DTLS12_MINORVERSION:
                            case DTLS10_MINORVERSION:
                                if (pSSLSock->isDTLS)
                                {
                                    pClientVersion = pTemp;
                                    status = OK;
                                }
                                break;
#endif
                            case TLS13_MINORVERSION:
                            case TLS12_MINORVERSION:
                            case TLS11_MINORVERSION:
                            case TLS10_MINORVERSION:
                            case SSL3_MINORVERSION:
                                pClientVersion = pTemp;
                                status = OK;
                                goto exit;
                            default:
                                break;
                        }
                    }
                    versionLen -= 2;
                    pTemp += 2;
                }
            }
        } else if(extensionType == tlsExt_cookie)
        {
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                /* If we are receiving a cookie extension during a DTLSconnection, 
                 * we know we are negotiating DTLS 1.3 */
                pTemp = pData;
                cookieLen = getShortValue(pTemp);
                pTemp += sizeof(ubyte2);

                status = DIGI_MALLOC((void **)&pHelloCookie, SHA512_RESULT_SIZE + 1);
                if (OK != status)
                    goto exit;

                status = generateHelloCookie(MOC_AND(pSSLSock->peerDescr.peerAddr), pSHSH + sizeofHandshakeHeader,
                    (0 == cookieLen? 255 : *(pTemp)), pHelloCookie, &helloCookieLen, DTLS13_MINORVERSION);
                if (OK != status)
                {
                    DIGI_FREE((void **)&pHelloCookie);
                    goto exit;
                }

                if ((0 == helloCookieLen) || (helloCookieLen != cookieLen))
                {
                    DIGI_FREE((void **)&pHelloCookie);
                    status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
                    goto exit;
                }

                DIGI_CTIME_MATCH(pTemp, pHelloCookie, helloCookieLen, &cmpCookieResult);

                if (0 != cmpCookieResult)
                {
                    DIGI_FREE((void **)&pHelloCookie);
                    status = ERR_DTLS_BAD_HELLO_COOKIE;
                    goto exit;
                }

                status = DIGI_MEMCPY(pSSLSock->helloCookie, pHelloCookie, helloCookieLen > 255 ? 255 : helloCookieLen);
                if (OK != status)
                {
                    DIGI_FREE((void **)&pHelloCookie);
                    goto exit;
                }
                pSSLSock->helloCookieLen = helloCookieLen;

                DIGI_FREE((void **)&pHelloCookie);
                pSSLSock->helloRetryRequest = 0;
                cookieReceived = TRUE;
            }
#endif
        }

        pData += extensionLen;
        totalExtensionsLen -= extensionLen;
    }

    if ((FALSE == cookieReceived) && (pSSLSock->isDTLS) && (pClientVersion[1] == DTLS13_MINORVERSION))
    {
        /* When negotiating DTLS 1.3, HRR is used to sent a cookie
           to the client.  */
        pSSLSock->helloRetryRequest = 1;
    }

    /* RFC 4.2.1: If this extension is not present, servers which are compliant with
     * this specification and which also support TLS 1.2 MUST negotiate
     * TLS 1.2 or prior as specified in [RFC5246], even if
     * ClientHello.legacy_version is 0x0304 or later.
     */
    if(!supportedVersionExtension)
    {
        /* RFC: 4.2.1: Servers MAY abort the
         * handshake upon receiving a ClientHello with legacy_version 0x0304 or
         * later.
         */
        if(pClientVersion[1] == TLS13_MINORVERSION)
        {
            status = ERR_SSL_PROTOCOL_VERSION;
        }
    }
#endif /* __ENABLE_DIGICERT_TLS13__ */
exit:
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    if (pSSLSock->clientHelloCallback && OK == status)
    {
        if (OK != pSSLSock->clientHelloCallback(&helloData, pSSLSock->clientHelloCallbackArg))
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        }
    }
#endif

    *ppClientHelloVersion = pClientVersion;
    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
/*------------------------------------------------------------------*/

static MSTATUS
processKeyShareSupportedGroups(SSLSocket *pSSLSock,  enum tlsExtNamedCurves clientSupportedGroups[MAX_SUPPORTED_NAMED_GROUPS], ubyte2 numClientSupportedGroups,
                               ubyte *pKeyShareExt, ubyte2 keyShareExtLen)
{
    MSTATUS status   = OK;
    ubyte2 curve = 0;
    ubyte4 receivedCurve = 0;
    ubyte  supportedGroupFound   = 0;
    ubyte  supportedGroupOverlap = 0;
    ubyte2 keyShareEntryLength   = 0;
    ubyte4 i = 0;

    for (i = 0; i < numClientSupportedGroups; i++)
    {
        ubyte* pTempKeyShareExt    = pKeyShareExt;
        ubyte4 tempKeyShareExtLen = keyShareExtLen;

        pSSLSock->roleSpecificInfo.server.selectedGroup = clientSupportedGroups[i];

        pSSLSock->roleSpecificInfo.server.clientECCurves |= (1 << clientSupportedGroups[i]);
        supportedGroupOverlap = 1;
        receivedCurve = 0;

        /* RFC - 4.2.8. Key Share: A list of offered KeyShareEntry
         * values in descending order of client preference.
         * This vector MAY be empty if the client is requesting a
         * HelloRetryRequest.
         *
         * If the key share is of length 0 and the server has found a group
         * which it supports then the supportedGroupOverlap flag is set to 1
         * and supportedGroupFound flag is 0. From this info the server knows to
         * perform a HelloRetryRequest.
         */
        while (tempKeyShareExtLen > 0)
        {
            if (4 > tempKeyShareExtLen)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            curve = getShortValue(pTempKeyShareExt);
            pTempKeyShareExt += 2;
            tempKeyShareExtLen -= 2;

            keyShareEntryLength = getShortValue(pTempKeyShareExt);
            pTempKeyShareExt += 2;
            tempKeyShareExtLen -= 2;

            if (keyShareEntryLength > tempKeyShareExtLen)
            {
                /* length of each keyShareEntry should not exceed the total KeyShare extension data length */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            /* RFC: 4.2.8: Key Share
             * Client MUST NOT offer multiple KeyShareEntry values
             * for the same group.
             */
            if(!(receivedCurve & (1 << curve)))
            {
                receivedCurve = ( 1 << curve);
            }
            else
            {
                status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                        SSL_ALERT_ILLEGAL_PARAMETER,
                        SSLALERTLEVEL_FATAL);
#endif
                goto exit;
            }

            if (curve == clientSupportedGroups[i])
            {
                supportedGroupFound    = 1;
                /* TODO: Other legs of code generate key share here, but
                 * key share gets generated during construction of key
                 * share extension. Don't need to generate key share
                 * in other legs of code */
                if ( FFDH_SUPPORTED_GROUP_MASK == ( curve & SUPPORTED_GROUP_MASK ))
                {
                    if (NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
                    {
                        DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.server.receivedPubKey);
                    }

                    if(OK > (status = DIGI_MALLOC((void**)&pSSLSock->roleSpecificInfo.server.receivedPubKey, keyShareEntryLength)))
                    {
                        goto exit;
                    }

                    if(NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
                    {
                        DIGI_MEMCPY(pSSLSock->roleSpecificInfo.server.receivedPubKey, pTempKeyShareExt, keyShareEntryLength);
                    }

                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen = keyShareEntryLength;

                    if (NULL != pSSLSock->pDHcontext)
                    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        status = CRYPTO_INTERFACE_DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
#else
                        status = DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
#endif
                        if (OK != status)
                        {
                            goto exit;
                        }
                    }

                    status = generateKeyShareEntryFFDH(MOC_DH(pSSLSock->hwAccelCookie) curve, &(pSSLSock->pDHcontext));
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = getNamedGroupLength(curve, &(pSSLSock->roleSpecificInfo.server.selectedCurveLength));
                    if (OK != status)
                    {
                        goto exit;
                    }

                }
#ifdef __ENABLE_DIGICERT_ECC__
                else if ( ECDH_SUPPORTED_GROUP_MASK == ( curve & SUPPORTED_GROUP_MASK ))
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    ubyte4 curveId = 0;
#else
                    PEllipticCurvePtr pCurve = 0;
#endif
                    ECCKey *pECCKey;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    curveId = SSL_SOCK_getCurveIdFromName(curve);
                    if (0 == curveId)
#else
                    pCurve = SSL_SOCK_getCurveFromName(curve);
                    if ( !pCurve)
#endif
                    {
                        status = ERR_SSL_UNSUPPORTED_CURVE;
                        goto next_curve;
                    }

                    if (pSSLSock->roleSpecificInfo.server.receivedPubKey != NULL)
                    {
                        DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.server.receivedPubKey);
                    }

                    if(OK > (status = DIGI_MALLOC((void**)&pSSLSock->roleSpecificInfo.server.receivedPubKey, keyShareEntryLength)))
                    {
                        goto exit;
                    }

                    if(NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
                    {
                        DIGI_MEMCPY(pSSLSock->roleSpecificInfo.server.receivedPubKey, pTempKeyShareExt, keyShareEntryLength);
                    }

                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen = keyShareEntryLength;

                    /* allocate the key here */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    if (OK > (status = CRYPTO_createECCKeyEx( &pSSLSock->ecdheKey, curveId)))
#else
                    if (OK > (status = CRYPTO_createECCKey(&pSSLSock->ecdheKey, pCurve)))
#endif
                        goto exit;

                    pECCKey = pSSLSock->ecdheKey.key.pECC;

                    /* generate it */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    if ( OK > ( status = CRYPTO_INTERFACE_EC_generateKeyPairAux(MOC_ECC(pSSLSock->hwAccelCookie) pECCKey, pSSLSock->rngFun, pSSLSock->rngFunArg)))
#else
                    if ( OK > ( status = EC_generateKeyPair(pCurve, pSSLSock->rngFun, pSSLSock->rngFunArg,
                                                            pECCKey->k, pECCKey->Qx, pECCKey->Qy)))
#endif
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(curveId, &pSSLSock->roleSpecificInfo.server.selectedCurveLength)))
#else
                    if (OK > (status = EC_getPointByteStringLen(pCurve,(sbyte4 *)&pSSLSock->roleSpecificInfo.server.selectedCurveLength)))
#endif
                    {
                        goto exit;
                    }

                }
#endif /* __ENABLE_DIGICERT_ECC__*/
#ifdef __ENABLE_DIGICERT_PQC__
                else if ( HYBRID_SUPPORTED_GROUP_MASK == ( curve & SUPPORTED_GROUP_MASK ))
                {
                    if (NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
                    {
                        DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.server.receivedPubKey);
                    }

                    if(OK > (status = DIGI_MALLOC((void**)&pSSLSock->roleSpecificInfo.server.receivedPubKey, keyShareEntryLength)))
                    {
                        goto exit;
                    }

                    if(NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
                    {
                        DIGI_MEMCPY(pSSLSock->roleSpecificInfo.server.receivedPubKey, pTempKeyShareExt, keyShareEntryLength);
                    }

                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen = keyShareEntryLength;
                }
#endif
                else
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }

                /* A supportedGroup overlapping
                 * - key_share extension supported group
                 * - supportedGroup extension
                 * - Server supported/configured
                 * is found and keyShare key was generated.
                 * Exit this function
                 */
                status = OK;
                goto exit;

            }
next_curve:
            pTempKeyShareExt  += keyShareEntryLength;
            tempKeyShareExtLen -= keyShareEntryLength;
        }
    }

    if(supportedGroupOverlap)
    {

        /*  RFC: 4.1.1 :If the server selects an (EC)DHE group and the client did not offer a
         * compatible "key_share" extension in the initial ClientHello, the
         * server MUST respond with a HelloRetryRequest (Section 4.1.4) message.
         * i.e. If preffered group by server is not present in KeyShare entry
         * then send HRR.
         */
        if(!supportedGroupFound)
        {
            pSSLSock->helloRetryRequest = 1;
        }
    }
    else
    {
        /* From RFC : 4.1.1. Cryptographic Negotiation
         * If there is no overlap between the received
         * "supported_groups" and the groups supported by the server then the
         * server MUST abort the handshake with a "handshake_failure" or an
         * "insufficient_security" alert.
         */
        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                SSL_ALERT_INSUFFICIENT_SECURITY,
                SSLALERTLEVEL_FATAL);
#endif
    }


exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
static MSTATUS
processSessionTicket(SSLSocket *pSSLSock, ubyte *pTicket, sbyte4 ticketLen)
{
    MSTATUS status;
    ubyte *pTemp;
    ubyte padding;
    ubyte4 tempLen, i, length;
    sbyte4 cmpRes;
    BulkCtx pAesCbcCtx = NULL;
    ubyte pMac[SSL_SESSION_TICKET_MAC_SIZE];
    TimeDate td, tdExpire;
    ubyte sslMinorVersion;
    ubyte2 cipherSuiteId;
    ubyte2 useExtendedMasterSecret = 0;
    ubyte *pSessionTicket = NULL, *pStartOfTicket = NULL;
    sbyte4 sessionTicketLen;
    ubyte2 ticketVersion = 0;

    /* Copy session ticket message to a buffer. Decryption will be done in place
     * so we do not want to modify the original buffer.
     */
    if (OK > (status = DIGI_MALLOC((void **) &pSessionTicket, ticketLen)))
        goto exit;

    pStartOfTicket = pSessionTicket;

    DIGI_MEMCPY(pSessionTicket, pTicket, ticketLen);
    sessionTicketLen = ticketLen;

    /* First value is the key name */
    if (sessionTicketLen < SSL_SESSION_TICKET_KEY_NAME_SIZE)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exitcont;
    }

    if (OK > (status = DIGI_MEMCMP(pSessionTicket, gSessionTicketKeyName,
            SSL_SESSION_TICKET_KEY_NAME_SIZE, &cmpRes)))
        goto exit;

    /* Ticket issued by this NanoSSL server instance */
    if (0 == cmpRes)
    {
        if (sessionTicketLen < (SSL_SESSION_TICKET_MAC_SIZE + SSL_SESSION_TICKET_KEY_NAME_SIZE))
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }

        /* Validate the MAC */
        if (OK > (status = HMAC_SHA256(MOC_HASH(pSSLSock->hwAccelCookie)
                gSessionTicketMacKey, SSL_SESSION_TICKET_MAC_KEY_SIZE,
                pSessionTicket, sessionTicketLen - SSL_SESSION_TICKET_MAC_SIZE,
                NULL, 0, pMac)))
            goto exitcont;

        if (OK > (status = DIGI_MEMCMP(
                pSessionTicket + sessionTicketLen - SSL_SESSION_TICKET_MAC_SIZE,
                pMac, SSL_SESSION_TICKET_MAC_SIZE, &cmpRes)))
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_SSL_INVALID_MAC;
            goto exitcont;
        }

        /* Key name has been verified and used for the MAC computation, move
         * past it.
         */
        pSessionTicket += SSL_SESSION_TICKET_KEY_NAME_SIZE;
        sessionTicketLen -= SSL_SESSION_TICKET_KEY_NAME_SIZE;

        /* Create AES-CBC context to decrypt the session data
         */
        pAesCbcCtx = CRYPTO_INTERFACE_CreateAESCtx(
            MOC_SYM(pSSLSock->hwAccelCookie) gSessionTicketEncKey,
            SSL_SESSION_TICKET_ENC_KEY_SIZE, 0);
        if (NULL == pAesCbcCtx)
        {
            status = ERR_NULL_POINTER;
            goto exitcont;
        }

        tempLen = sessionTicketLen - SSL_SESSION_TICKET_IV_SIZE - 2 - SSL_SESSION_TICKET_MAC_SIZE;
        if (tempLen <= 0)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }

        pTemp = pSessionTicket + SSL_SESSION_TICKET_IV_SIZE + 2;


        /* Decrypt in place */
        if (OK > (status = CRYPTO_INTERFACE_DoAES(MOC_SYM(pSSLSock->hwAccelCookie) pAesCbcCtx, pTemp, tempLen, 0, pSessionTicket)))
            goto exitcont;

        /* Check padding bytes */
        padding = pTemp[tempLen - 1];
        for (i = 0; i < padding; i++)
        {
            if (pTemp[tempLen - 1 - i] != padding)
            {
                status = ERR_SSL_INVALID_PADDING;
                goto exitcont;
            }
        }

        pSessionTicket += (SSL_SESSION_TICKET_IV_SIZE + 2);
        sessionTicketLen -= (SSL_SESSION_TICKET_IV_SIZE + 2);

        if (2 >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        sslMinorVersion = getShortValue(pSessionTicket) & 0xFF;

        /* Protocol - validated later */
        pSessionTicket += 2;
        sessionTicketLen -= 2;

        if (2 >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        cipherSuiteId = getShortValue(pSessionTicket);

        /* Ciphersuite */
        pSessionTicket += 2;
        sessionTicketLen -= 2;

        /* Compression method */
        if (1 >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        pSessionTicket += 1;
        sessionTicketLen -= 1;

        pTemp = pSessionTicket;

        /* Master secret */
        if (SSL_MASTERSECRETSIZE >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        pSessionTicket += SSL_MASTERSECRETSIZE;
        sessionTicketLen -= SSL_MASTERSECRETSIZE;

        if (1 >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        if (SSL_SESSION_TICKET_CLIENT_AUTH_TYPE_ANON == *pSessionTicket)
        {
            pSessionTicket++;
            sessionTicketLen--;
        }
        else
        {
            pSessionTicket++;
            sessionTicketLen--;

            if (3 >= sessionTicketLen)
            {
                status = ERR_SSL_INVALID_MSG_SIZE;
                goto exit;
            }
            length = getMediumValue(pSessionTicket);

            pSessionTicket += 3;
            sessionTicketLen -= 3;

            if ((sbyte4) length >= sessionTicketLen)
            {
                status = ERR_SSL_INVALID_MSG_SIZE;
                goto exit;
            }
            pSessionTicket += length;
            sessionTicketLen -= length;
        }

        if (2 >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        length = getShortValue(pSessionTicket);
        pSessionTicket += 2;
        sessionTicketLen -= 2;

        if ((sbyte4) length >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }

        if (OK > (status = DATETIME_convertFromValidityString2(pSessionTicket, length, &td)))
            goto exitcont;

        pSessionTicket += length;
        sessionTicketLen -= length;

        /* Legacy ticket would fail this check; Legacy ticket does not have the ticketVersion (2 bytes) */
        if (sessionTicketLen >= (2 + padding + SSL_SESSION_TICKET_MAC_SIZE))
        {
            /* New version of ticket, Read the version */
            ticketVersion = getShortValue(pSessionTicket);
            pSessionTicket += 2;
            sessionTicketLen -= 2;

            if (SSL_SESSION_TICKET_VERSION == ticketVersion)
            {
                /* Version 2 of session ticket should have 2 bytes to indicate if
                 * extended master secret was used in the original connection
                 */
                if (sessionTicketLen != (2 + padding + SSL_SESSION_TICKET_MAC_SIZE))
                {
                    status = ERR_SSL_INVALID_MSG_SIZE;
                    goto exit;
                }
                useExtendedMasterSecret = getShortValue(pSessionTicket);
                pSessionTicket += 2;
                sessionTicketLen -= 2;
            }
        }

        if (padding >= sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        pSessionTicket += padding;
        sessionTicketLen -= padding;

        if (SSL_SESSION_TICKET_MAC_SIZE > sessionTicketLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
        pSessionTicket += SSL_SESSION_TICKET_MAC_SIZE;
        sessionTicketLen -= SSL_SESSION_TICKET_MAC_SIZE;

        if (0 != sessionTicketLen)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        if (ticketVersion != SSL_SESSION_TICKET_VERSION)
        {
            /* Legacy ticket; Ignore the ticket and fallback to full handshake */
            goto exitcont;
        }

        /* Validate ticket lifetime has not expired
         */
        if (OK > (status = DATETIME_getNewTime(&td, TICKET_LIFETIME_TWO_HOURS, &tdExpire)))
            goto exitcont;

        if (OK > (status = RTOS_timeGMT(&td)))
            goto exitcont;

        if (OK > (status = DATETIME_diffTime(&tdExpire, &td, &cmpRes)))
            goto exitcont;

        /* Only use ticket if it is not expired */
        if (cmpRes > 0)
        {
            if (pSSLSock->sslMinorVersion != sslMinorVersion)
            {
                status = ERR_SSL_BAD_HEADER_VERSION;
                goto exitcont;
            }

            if (OK > (status = DIGI_MEMCPY(pSSLSock->pSecretAndRand, pTemp,
                    SSL_MASTERSECRETSIZE)))
                goto exit;

            pSSLSock->roleSpecificInfo.server.ticketCipherSuiteId = cipherSuiteId;
            pSSLSock->roleSpecificInfo.server.ticketUseExtendedMasterSecret = (ubyte) useExtendedMasterSecret;
            pSSLSock->sessionResume = E_SessionTicketResume;
        }

        /* If the Session Ticket has expired or will expire in 30s, send a new session ticket */
        if (cmpRes <= TICKET_RESEND_TIME_30_SECONDS)
        {
            pSSLSock->roleSpecificInfo.server.sendSessionTicket = TRUE;
        }
    }

exitcont:
    if (OK > status)
    {
        /* If we get an error with processing of SessionTicket ignore the ticket and error;
         * If the error is packet length error throw the error
         */
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"processSessionTicket() status = ", status);
        status = OK;
    }

exit:
    if (NULL != pAesCbcCtx)
    {
        CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(pSSLSock->hwAccelCookie) &pAesCbcCtx);
    }

    if (NULL != pStartOfTicket)
    {
        DIGI_MEMSET(pStartOfTicket, 0x00, ticketLen);
        DIGI_FREE((void **) &pStartOfTicket);
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"processSessionTicket() returns status = ", status);

    return status;
}
#endif

static MSTATUS
processClientHelloExtension(SSLSocket* pSSLSock, ubyte2 extensionType,
                                ubyte2 extensionSize, ubyte* pExtension)
{
    MSTATUS status = OK;
#if defined(__ENABLE_DIGICERT_TLS13__)
    ubyte   *cookie = NULL;
#endif

    switch (extensionType)
    {
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        case tlsExt_renegotiated_connection:
        {
            /* due to problems using "hello extensions" with SSLv3, we don't support SSLv3 rehandshakes. */
            ubyte4  renegotiatedConnLength = 0;
            ubyte4  expectedRenegotiationLength = 0;
            sbyte4  result;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            ubyte4  verifyDataSize = (SSL3_MINORVERSION == pSSLSock->sslMinorVersion) ? SSL_VERIFY_DATA : TLS_VERIFYDATASIZE;
#else
            ubyte4 verifyDataSize = TLS_VERIFYDATASIZE;
#endif
            pSSLSock->isRehandshakeExtPresent = TRUE;

            if (0 < pSSLSock->handshakeCount)
            {
                expectedRenegotiationLength = verifyDataSize;
            }

            if (extensionSize < 1)
            {
                status = ERR_SSL_CLIENT_RENEGOTIATE_LENGTH;
                goto exit;
            }
            renegotiatedConnLength = *pExtension;

            if ((expectedRenegotiationLength != renegotiatedConnLength) ||
                (extensionSize != 1 + expectedRenegotiationLength))
            {
                status = ERR_SSL_SERVER_RENEGOTIATE_LENGTH;
                goto exit;
            }

            if (0 < expectedRenegotiationLength)
            {
                if (OK > (status = DIGI_CTIME_MATCH(1 + pExtension, pSSLSock->client_verify_data, verifyDataSize, &result)))
                    goto exit;

                if (0 != result)
                {
                    status = ERR_SSL_SERVER_RENEGOTIATE_CLIENT_VERIFY;
                    goto exit;
                }
            }

            if (0 == pSSLSock->handshakeCount)
                pSSLSock->isRehandshakeAllowed = TRUE;
        }
        break;
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */

        case tlsExt_server_name:
        {
            sbyte4 serverNameListLength;

            if ( extensionSize < 2)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            serverNameListLength = getShortValue(pExtension);
            if ( serverNameListLength + 2 > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            if (OK > (status = SSLSOCK_extractServerNameIndication(pSSLSock,
                                                                   pExtension+2,
                                                                   serverNameListLength)))
            {
                goto exit;
            }
        }
        break;

        case tlsExt_applicationLayerProtocolNegotiation:
        {
            sbyte4 alpnLength;

            if ( extensionSize < 2)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            alpnLength = getShortValue(pExtension);
            if ( alpnLength + 2 != extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            if (OK > (status = SSLSOCK_selectApplicationLayerProtocol(pSSLSock,
                                                            pExtension+2,
                                                            alpnLength)))
            {
                if (ERR_SSL_EXTENSION_NO_ALPN_MATCH == status)
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                            SSL_ALERT_NO_APPLICATION_PROTOCOL,
                            SSLALERTLEVEL_FATAL);
#endif
                }
                /* otherwise this is an error in the format of the message */
                goto exit;
            }

        }
        break;

        case tlsExt_status_request:
        {
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

            if (OK > (status = SSLSOCK_sanityCertificateStatusRequestExtension(pSSLSock,
                        pExtension, extensionSize)))
            {
                goto exit;
            }

            pSSLSock->recvStatusReqExt = TRUE;
#endif
        }
        break;

        case tlsExt_supportedSignatureAlgorithms:
        {
            /* verify we are at 1.2 or above */
            if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
                (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
            {
                sbyte4 signatureAlgoListLength;
                if ( extensionSize < 2)
                {
                    /* buffer overrun attack? */
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                signatureAlgoListLength = getShortValue(pExtension);
                if ( (signatureAlgoListLength + 2 > extensionSize) ||
                     (signatureAlgoListLength & 1))
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                /* Copy over the signature algorithm list provided by the
                 * peer */
                DIGI_FREE((void **) &(pSSLSock->signatureAlgoList));
                if (OK > (status = DIGI_MALLOC((void **) &(pSSLSock->signatureAlgoList),
                                                          signatureAlgoListLength)))
                {
                    goto exit;
                }

                DIGI_MEMCPY(pSSLSock->signatureAlgoList, pExtension+2,
                           signatureAlgoListLength);
                pSSLSock->signatureAlgoListLength = signatureAlgoListLength;
            }

#if defined(__ENABLE_DIGICERT_TLS13__)
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
                (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                pSSLSock->roleSpecificInfo.server.receivedExtensions = TLS13_SET_SIGNATURE_ALGO_EXT_RX(pSSLSock);
            }
#endif
        }
        break;

#ifdef __ENABLE_DIGICERT_TLS13__
        case tlsExt_signatureAlgorithmCerts:
        {
            if ((!pSSLSock->isDTLS && pSSLSock->sslMinorVersion > TLS12_MINORVERSION) ||
                (pSSLSock->isDTLS && pSSLSock->sslMinorVersion < DTLS12_MINORVERSION))
            {
                sbyte4 sigCertAlgoListLen;

                if (extensionSize < 2)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                sigCertAlgoListLen = getShortValue(pExtension);
                if ((sigCertAlgoListLen + 2 > extensionSize) ||
                    (sigCertAlgoListLen & 1))
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                pSSLSock->signatureAlgoCertList = pExtension + 2;
                pSSLSock->signatureAlgoCertListLength = sigCertAlgoListLen;
            }
        }
        break;
#endif

#if defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
        case tlsExt_ECPointFormat:
        /* must verify we understand it */
        {
            sbyte4 i, numFormats;

            if ( extensionSize < 2) /* minimal size */
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            numFormats = *pExtension++;
            if ( numFormats + 1 != extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            for ( i = 0; i < numFormats; ++i)
            {
                if ( *pExtension > tlsExtECPointFormat_ansiX962_compressed_char2)
                {
                    status = ERR_SSL_EXTENSION_UNKNOWN_FORMAT;
                    goto exit;
                }
            }
        }
        break;
        case tlsExt_supportedGroups:
        {
#if defined(__ENABLE_DIGICERT_TLS13__)
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
                (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                ubyte2 supportedGroupCount;
                sbyte4 numCurves, i;
                ubyte4 j;
                ubyte2 curve;

                if ( extensionSize < 2) /* minimal size */
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                

                /* Total length of group entries*/
                numCurves = getShortValue( pExtension);

                if ((numCurves + 2 > extensionSize) ||
                    (numCurves & 1))
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                pExtension += sizeof(ubyte2);

                supportedGroupCount = 0;
                for ( i = 0; i < numCurves; i += 2)
                {
                    /* Get group name */
                    curve = getShortValue(pExtension);
                    pExtension += sizeof(ubyte2);

                    /* Check if the group is supported */
                    for (j = 0; j < pSSLSock->supportedGroupListLength; j++)
                    {
                        if (pSSLSock->pSupportedGroupList[j] == curve)
                        {
                            pSSLSock->roleSpecificInfo.server.clientSupportedGroups[supportedGroupCount] = curve;
                            supportedGroupCount++;
                            break;
                        }
                    }

                    /* If all possible supported groups are set then no need
                     * to process remaining groups */
                    if (supportedGroupCount == MAX_SUPPORTED_NAMED_GROUPS)
                    {
                        break;
                    }
                }
    
                pSSLSock->roleSpecificInfo.server.numSupportedGroupReceived = supportedGroupCount;
                pSSLSock->roleSpecificInfo.server.receivedExtensions = TLS13_SET_SUPPORTED_GROUPS_EXT_RX(pSSLSock);

                if (1 == TLS13_GET_KEY_SHARE_EXT_RX(pSSLSock))
                {
                    if (OK > (status = processKeyShareSupportedGroups(pSSLSock,
                                                                      pSSLSock->roleSpecificInfo.server.clientSupportedGroups,
                                                                      pSSLSock->roleSpecificInfo.server.numSupportedGroupReceived,
                                                                      pSSLSock->roleSpecificInfo.server.pKeyShareExt,
                                                                      pSSLSock->roleSpecificInfo.server.keyShareExtLength)))
                    {
                        goto exit;
                    }
                }
            }
            else
#endif  /*__ENABLE_DIGICERT_TLS13__*/
            {
                sbyte4 numCurves, i;

                if ( extensionSize < 2) /* minimal size */
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                numCurves = getShortValue( pExtension);
                if ((numCurves + 2 > extensionSize) ||
                    (numCurves & 1))
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                pExtension += sizeof(ubyte2);
                /* need to verify that the client supports all the
                needed curves --- ECDH but also ECDSA keys used for signing
                this info is stored in the ecCurves member of pSSLSock */
                pSSLSock->roleSpecificInfo.server.clientECCurves = 0;
                for ( i = 0; i < numCurves; i += 2)
                {
                    ubyte2 curve = getShortValue(pExtension);
                    pExtension += sizeof(ubyte2);

                    if ( curve < 32)
                    {
                        pSSLSock->roleSpecificInfo.server.clientECCurves |= ( 1 << curve);
                    }
                }

                /* mask the curves with the ones we allow for the connection */
                pSSLSock->roleSpecificInfo.server.clientECCurves &= pSSLSock->supportedGroups;
                pSSLSock->roleSpecificInfo.server.clientECCurves &= SUPPORTED_GROUPS_FLAGS_TLS12;

                /* that's it. Even if the clientECCurves is 0, meaning there's no common
                curve, this is OK since we might pick a non EC-based cipher */
            }
        }
        break;

#endif  /* __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__  ||
        __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__  ||
        __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__*/

        case tlsExt_ticket:
        {
#if defined(__ENABLE_DIGICERT_EAP_FAST__)
            sbyte4 ticketLength = 0;
#endif

            if (1 == extensionSize)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_EAP_FAST__)
            pSSLSock->roleSpecificInfo.server.sendSessionTicket = FALSE; /* don't send a ticket extension back */
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
                (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                /* Ignore non-zero extension sizes.
                 */
                if (extensionSize == 0)
                {
                    if (pSSLSock->roleSpecificInfo.server.numOfSessionTickets <= 0)
                    {
                        /* Server application has set the number of PSKs to 0;
                         * Stack should not send any PSKs.
                         */
                        pSSLSock->roleSpecificInfo.server.sendSessionTicket = FALSE;
                    }
                    else
                    {
                        pSSLSock->roleSpecificInfo.server.sendSessionTicket = TRUE;
                    }
                }
#endif
            }
            else
#endif
            {
                /* 2 options: either the ticket is non empty -> try to see if we use it */
                /* or it is empty -> request for a new ticket */
#if defined(__ENABLE_DIGICERT_EAP_FAST__)
                if (extensionSize)
                {
                    ticketLength = getShortValue(pExtension);

                    if (ticketLength + 2 > extensionSize)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                    }
                    else
                    {
                        status = processPACOpaque( pSSLSock, pExtension+2, ticketLength);
                        if (OK <= status)
                            break;
                    }
                }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
                /* Client sent a ticket to be used for session resumption */
                if (extensionSize > 0)
                {
                    status = processSessionTicket(pSSLSock, pExtension, extensionSize);
                    if (OK > status)
                        goto exit;
                }
                else
                {
                    status = OK;
                    pSSLSock->roleSpecificInfo.server.sendSessionTicket = TRUE;
                }
#elif defined(__ENABLE_DIGICERT_EAP_FAST__)
                if (OK > status)
                    goto exit;
#endif
            }
        }

        break;
#if defined(__ENABLE_DIGICERT_TLS13__)
        case tlsExt_encrypt_then_mac:
        {
            if (0 != extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            pSSLSock->encryptThenMac = 1;
        }
        break;
#endif
        case tlsExt_extendedMasterSecret:
        {
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
            if (pSSLSock->supportExtendedMasterSecret)
            {
                if (0 != extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                pSSLSock->receivedExtendedMasterSecret = TRUE;
            }
#endif
        }
        break;

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
        case tlsExt_SRP:
        {
            if (extensionSize > 1)
            {
                ubyte identityLen = *pExtension;
                if (identityLen + 1 > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                pSSLSock->srpIdentity = (ubyte*) MALLOC(1 + identityLen);
                if (!pSSLSock->srpIdentity)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                /* copy the identity with its length */
                if (OK > (status = DIGI_MEMCPY( pSSLSock->srpIdentity, pExtension, 1 + identityLen)))
                    goto exit;
            }
        }
        break;
#endif

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
        case dtlsExt_use_srtp:
        {
            sbyte4 srtpProfileListLength;
            ubyte4 srtpMkiLength;
            sbyte4 selectedProfile;

            if (!pSSLSock->isDTLS)
                goto exit;

            if ( extensionSize < 2)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            srtpProfileListLength = getShortValue(pExtension);
            if ( srtpProfileListLength + 1 > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            pExtension += 2;
            extensionSize -= 2;

            if (E_NoSessionResume == pSSLSock->sessionResume)
            {
                /* server pick a profile */
                selectedProfile = SSLSOCK_selectSrtpProfile(pSSLSock, 0, pExtension, srtpProfileListLength>>1);

                if (selectedProfile < 0)
                {
                    status = ERR_DTLS_SRTP_NO_PROFILE_MATCH;
                    goto exit;
                }

                pSSLSock->pHandshakeSrtpProfile = gSrtpProfiles + selectedProfile;
            }

            pExtension += srtpProfileListLength;
            extensionSize -= srtpProfileListLength;

            /* srtp_mki */
            if (extensionSize < 1)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            srtpMkiLength = (ubyte4)(*pExtension);

            if ((srtpMkiLength > 256) || (extensionSize < srtpMkiLength + 1))
            {
                /* TODO: probably need to change to another error */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            if (srtpMkiLength > 0)
            {
                /* reuse buffer if they have the same length */
                if ((NULL != pSSLSock->srtpMki) && (srtpMkiLength != *(pSSLSock->srtpMki)))
                {
                    FREE(pSSLSock->srtpMki);
                    pSSLSock->srtpMki = NULL;
                }

                if (NULL == pSSLSock->srtpMki)
                    pSSLSock->srtpMki = MALLOC(srtpMkiLength + 1);

                if (OK > (status = DIGI_MEMCPY(pSSLSock->srtpMki, pExtension, srtpMkiLength + 1)))
                    goto exit;
            }
            pSSLSock->useSrtp = TRUE;

        }
        break;
#endif

        case tlsExt_innerApplication:
        {
            if (2 != extensionSize )
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_INNER_APP__)
            pSSLSock->receivedInnerAppValue = getShortValue(pExtension);
            pSSLSock->receivedInnerApp      = TRUE;
#endif
        }
        break;

#if defined(__ENABLE_DIGICERT_TLS13__)
        case tlsExt_supported_versions:
        /* This extension has already been parsed at the beginning of parsing ClientHello.
           Nothing to do here*/
        break;

        case tlsExt_key_share:
        {
            ubyte2 keyShareLength;

            if (extensionSize < 2)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            keyShareLength = getShortValue(pExtension);
            pExtension += 2;


            if ((2 + keyShareLength) > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            pSSLSock->roleSpecificInfo.server.pKeyShareExt       = pExtension;
            pSSLSock->roleSpecificInfo.server.keyShareExtLength  = keyShareLength;
            pSSLSock->roleSpecificInfo.server.receivedExtensions = TLS13_SET_KEY_SHARE_EXT_RX(pSSLSock);

            if (1 == TLS13_GET_SUPPORTED_GROUPS_EXT_RX(pSSLSock))
            {
                if (OK > (status = processKeyShareSupportedGroups(pSSLSock,
                                                                  pSSLSock->roleSpecificInfo.server.clientSupportedGroups,
                                                                  pSSLSock->roleSpecificInfo.server.numSupportedGroupReceived,
                                                                  pSSLSock->roleSpecificInfo.server.pKeyShareExt,
                                                                  pSSLSock->roleSpecificInfo.server.keyShareExtLength)))
                {
                    goto exit;
                }
            }
        }
        break;

        /* enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
         *
         *  struct {
         *      PskKeyExchangeMode ke_modes<1..255>;
         *  } PskKeyExchangeModes;
         */
        case tlsExt_psk_key_exchange_modes:
        {
            /* Get the exchange mode. For TLS 1.3, if PSK is used, this extensions should be provided */
            ubyte4 extensionIndex = 0;
            intBoolean dhePsk = FALSE;
            ubyte4 pskModeLength;
            if(2 > extensionSize || 256 < extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            pskModeLength = *pExtension++;
            if (pskModeLength + 1 != extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            while (extensionIndex < pskModeLength)
            {
                if (psk_dhe_ke == *pExtension)
                {
                    dhePsk = TRUE;
                }

                if (psk_dhe_ke != *pExtension && psk_ke != *pExtension)
                {
                    /* Unknown key exchange mode */
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                pExtension++;
                extensionIndex++;
            }

            if (TRUE == dhePsk)
            {
                pSSLSock->roleSpecificInfo.server.keyExchangeMode = psk_dhe_ke;
            }
            else
            {
                pSSLSock->roleSpecificInfo.server.keyExchangeMode = psk_ke;
            }
        }
        break;
        case tlsExt_postHandshakeAuth:
        {
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
            pSSLSock->postHandshakeAuth = 1;
#endif
        }
        break;
#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
        case tlsExt_early_data:
        {
            if (0 != extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            /* Initialize the earlyDataExtAccepted flag to 0. Enable this flag in
              pre_shared_key extension if all the conditions are met correctly.  */
            pSSLSock->earlyDataExtAccepted = 0;
            pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_SET_FALLBACK(pSSLSock);
        }
        break;
#endif
        case tlsExt_pre_shared_key:
        {
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
            ubyte2 totalIdentityLength,identityLength;
            ubyte numOfBinder = 0, i;
            ubyte identitySelected = 0;
            byteBoolean valid = FALSE;
            sbyte4 selectedIndex = 0;
            ubyte2 tempLen = 0;

            /* Client has sent a PSK */
            pSSLSock->roleSpecificInfo.server.receivedExtensions = TLS13_SET_PRE_SHARED_KEY_EXT_RX(pSSLSock);

            if (extensionSize < 2)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            totalIdentityLength = getShortValue(pExtension);
            pExtension += 2;
            tempLen += 2;

            if (totalIdentityLength > extensionSize + 2)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            i = 0;
            while (totalIdentityLength > 1/* should be atleast 2 bytes to read the length */)
            {
                identityLength = getShortValue(pExtension);
                pExtension += 2;
                tempLen += 2;

                if ((tempLen + identityLength + sizeof(ubyte4)/* Ticket Age */) > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                totalIdentityLength = totalIdentityLength - 2;

                if(!identitySelected)
                {
                    tls13PSK *pTempPSK = NULL;
                    ubyte *pPsk = NULL;
                    ubyte4 pskLen = 0;
                    intBoolean freeMemory = FALSE;

                    /* Copy this PSK into the Server pSSLSock */
                    if (NULL != SSL_sslSettings()->funcPtrLookupPSKParams)
                    {
                        if (OK > (status = (MSTATUS)(SSL_sslSettings()->funcPtrLookupPSKParams(SSL_findConnectionInstance(pSSLSock),
                                            pExtension, identityLength,
                                            &pPsk, &pskLen, &freeMemory))))
                        {
                            goto exit;
                        }

                        if (NULL != pPsk)
                        {
                            if (OK > (status = SSLSOCK_tls13DeserializePsk(
                                pPsk, pskLen, &pTempPSK)))
                            {
                                goto exit;
                            }
                            if (TRUE == freeMemory)
                            {
                                status = DIGI_FREE((void **) &pPsk);
                                if (OK != status)
                                    goto exit1;
                            }
                        }

                        pSSLSock->roleSpecificInfo.server.pSelectedPSK = pTempPSK;
                    }

                    /* Identity */
                    pExtension += identityLength;
                    totalIdentityLength = totalIdentityLength - identityLength;
                    tempLen += identityLength;

                    /* Ticket Age */
                    if (pSSLSock->roleSpecificInfo.server.pSelectedPSK != NULL)
                    {
                        pSSLSock->roleSpecificInfo.server.selectedPskAge = DIGI_NTOHL(pExtension);
                    }
                    pExtension += sizeof(ubyte4);
                    totalIdentityLength = totalIdentityLength - sizeof(ubyte4);
                    tempLen += sizeof(ubyte4);

                    if (NULL != pSSLSock->roleSpecificInfo.server.pSelectedPSK)
                    {
                        /* RFC 8446 Section 4.2.11.1
                         *
                         * 
                         */
                        status = validateTicketAge(
                            pSSLSock,
                            pSSLSock->roleSpecificInfo.server.pSelectedPSK,
                            pSSLSock->roleSpecificInfo.server.selectedPskAge,
                            &valid);
                        if (OK != status)
                        {
                            goto exit1;
                        }

                        if (TRUE == valid)
                        {
                            pSSLSock->roleSpecificInfo.server.selectedPskIdentityIndex = i;
                            identitySelected = 1;
                        }
                        else
                        {
                            /* PSK ticket age invalid, free PSK and initialize
                             * pSelectedPSK to NULL */
                            SSLSOCK_freePSK(&pTempPSK);
                            pSSLSock->roleSpecificInfo.server.pSelectedPSK = NULL;
                        }
                    }
exit1:
                    if (OK > status)
                    {
                        if (pTempPSK != NULL)
                            SSLSOCK_freePSK(&pTempPSK);

                        goto exit;
                    }
                }
                else
                {
                    /* Identity */
                    pExtension += identityLength;
                    totalIdentityLength = totalIdentityLength - identityLength;
                    tempLen += identityLength;

                    /* Ticket Age */
                    pExtension += sizeof(ubyte4);
                    totalIdentityLength = totalIdentityLength - sizeof(ubyte4);
                    tempLen += sizeof(ubyte4);
                }

                i = i + 1;
            }

            /* RFC 8446 Section E.6
             *
             * Servers can be run with both PSK and certificates enabled or just
             * in PSK mode. NanoSSL runs with both PSKs and certificates. This
             * alert from section 6.2 does not apply for servers which support
             * both PSKs and certificates.
             */

            if (pSSLSock->roleSpecificInfo.server.pSelectedPSK != NULL)
            {
                pSSLSock->roleSpecificInfo.server.pSelectedPSK->hashAlgo = getHashIdFromSuite(pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo);

                if (0 == pSSLSock->roleSpecificInfo.server.pSelectedPSK->hashAlgo)
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }

                pSSLSock->isPSKSelected = 1;
                if ((tempLen + 2) > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                pSSLSock->roleSpecificInfo.server.bindersLength = getShortValue(pExtension);
                pExtension += 2;
                tempLen += 2;
                if (tempLen + pSSLSock->roleSpecificInfo.server.bindersLength > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
                /* RFC : 4.2.11: Servers SHOULD NOT attempt to validate multiple binders;
                 * rather, they SHOULD select a single PSK and validate solely the
                 * binder that corresponds to that PSK.
                 *
                 * Use selectedPskIdentityIndex for index into PSK extension.
                 */
                if ( OK > (status = validatePskBinder(pSSLSock, pExtension, numOfBinder,
                            pSSLSock->roleSpecificInfo.server.selectedPskIdentityIndex)))
                {
                    status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                            SSL_ALERT_ILLEGAL_PARAMETER,
                            SSLALERTLEVEL_FATAL);
#endif
                    goto exit;
                }
                selectedIndex = pSSLSock->roleSpecificInfo.server.selectedPskIdentityIndex;
                tempLen += pSSLSock->roleSpecificInfo.server.bindersLength;

                valid = TRUE;
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                /* RFC 8446:
                   Section 4.2.10. If client opts to send early_data in its first flight, it MUST supply both the "pre_shared_key" and
                   "early_data" extensions.

                   Page 54: In order to accept early data, the server MUST have accepted a PSK cipher suite and
                   selected the first key offered in the client's "pre_shared_key" extension.

                 */
                if (1 == TLS13_0RTT_GET_FALLBACK(pSSLSock))
                {
                    if ((0 == selectedIndex) && (TRUE == valid))
                    {
                        pSSLSock->earlyDataExtAccepted = 1;
                        pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_RESET_FALLBACK(pSSLSock);
                    }
                }
#endif
#endif
            }
            /* RFC 4.2.11 Pre-shared Key
               if no acceptable PSKs are found, then the server should perform
               a non-PSK handshake if possible. */
            if (FALSE == valid)
            {
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                if (NULL != SSL_sslSettings()->funcPtrServerDeletePSK)
                {
                    if (OK > (status = (MSTATUS)(SSL_sslSettings()->funcPtrServerDeletePSK(SSL_findConnectionInstance(pSSLSock), 
                                        pSSLSock->serverNameIndication,
                                        (pSSLSock->serverNameIndication != NULL) ? DIGI_STRLEN((sbyte *) pSSLSock->serverNameIndication) : 0,
                                        NULL, 0,
                                        NULL))))
                    {   
                        goto exit;
                    }
                }
#endif
                pSSLSock->roleSpecificInfo.server.receivedExtensions = TLS13_RESET_PRE_SHARED_KEY_EXT_RX(pSSLSock);
            }
#endif
        }
        break;

        case tlsExt_cookie:
        {
            sbyte4  isNotCookieMatch;
            ubyte2  cookieLength;
            status = ERR_SSL_EXTENSION_LENGTH;

            if (2 > extensionSize )
            {
                goto exit;
            }
            cookieLength = getShortValue(pExtension);
            pExtension += 2;
            extensionSize -= 2;
            if (cookieLength > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            if (cookieLength > 0)
            {
                if(OK > (status = DIGI_MALLOC((void**)&cookie,cookieLength)))
                {
                    goto exit;
                }

                DIGI_MEMCPY(cookie, pExtension, cookieLength);

                DIGI_MEMCMP(cookie, pSSLSock->helloCookie, cookieLength, &isNotCookieMatch);

                if(isNotCookieMatch)
                {
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                    if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                    {
                        /* RFC 9147 Section 5.1
                        If a server receives a ClientHello with an invalid cookie, it MUST 
                        terminate the handshake with an "illegal_parameter" alert */
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, FALSE /* not yet encrypted */,
                            SSL_ALERT_ILLEGAL_PARAMETER,
                            SSLALERTLEVEL_FATAL);
#endif
                    }
#endif /* __ENABLE_DIGICERT_DTLS_SERVER__ */
                    goto exit;
                }
                else
                {
                    /* Set status OK, only if cookie received matched */
                    status = OK;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                    if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                    {
                        if (OK > (status = SSL_SOCK_initHashPool(pSSLSock)))
                            goto exit;

                        /* get server messages */
                        ubyte *pClientMessage = NULL;
                        ubyte4 clientMessageLen = 0;
                        ubyte *pServerMessage = NULL;
                        ubyte4 serverMessageLen = 0;

                        status = lookUpCookieDtls13(pSSLSock->helloCookie, pSSLSock->helloCookieLen,
                            &pClientMessage, &clientMessageLen, &pServerMessage, &serverMessageLen);
                        if (OK > status)
                        {
                            /* if we did not find cookie it is an error */
                            goto exit;
                        }
                        status = addHrrClientHelloToHandshakeHash(
                            pSSLSock, (ubyte *) pClientMessage, clientMessageLen);
                        DIGI_FREE((void **)&pClientMessage);
                        if (OK > status)
                        {
                            goto exit;
                        }

                        /* add to handshakeHash once and only once */
                        addToHandshakeHash(pSSLSock, (ubyte *)pServerMessage, serverMessageLen);
                        DIGI_FREE((void **)&pServerMessage);
                    }
#endif
                }
            }
        }
        break; 
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
        case tlsExt_heartbeat:
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            ubyte heartbeatMode = 0;
            if (extensionSize != 1)
                goto exit;

            heartbeatMode = *pExtension;
            pExtension++;

            if ((heartbeatMode != 1) && (heartbeatMode != 2))
            {
                goto exit;
            }

            status = OK;
            pSSLSock->rxHeartbeatExtension = heartbeatMode;
        }
        break;
#endif
        default:
            break;
    }

    /* callback handler for protected extension types */
    if ((64 > extensionType) && (NULL != SSL_sslSettings()->funcPtrExtensionRequestCallback))
        status = (MSTATUS)SSL_sslSettings()->funcPtrExtensionRequestCallback(
            SSL_findConnectionInstance(pSSLSock), extensionType, pExtension, extensionSize);

exit:
#if defined(__ENABLE_DIGICERT_TLS13__)
    if(cookie)
    {
        DIGI_FREE((void**)&cookie);
    }

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    /* if negotiating dtls 1.3, we need to keep cookie for searching
     * hello messages that were done before SSLSocket was initialized. */
    if (!pSSLSock->isDTLS || (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion))
#endif
    {
        DIGI_MEMSET(pSSLSock->helloCookie, '\0', pSSLSock->helloCookieLen);
        pSSLSock->helloCookieLen = 0;
    }
#endif

    return status;
}


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
static sbyte4
findRenegotiationScsvV2( ubyte* clientCipherSuite, sbyte4 clientCipherSuiteLen )
{
    sbyte4 index;

    /* see if SCSV exist */
    for (index = 0; index < clientCipherSuiteLen; index += 3)
    {
        if ((0 == clientCipherSuite[index]) &&
            ( (((ubyte2)clientCipherSuite[index+1] << 8) | (ubyte2)clientCipherSuite[index+2]) ==
                0x00FF))
        {
            DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
            return 1;
        }
    }

    return 0;
}
#endif


/*------------------------------------------------------------------*/

static sbyte4
findFallbackScsvV2( ubyte* clientCipherSuite, sbyte4 clientCipherSuiteLen )
{
    sbyte4 index;

    /* see if TLS_FALLBACK_SCSV exist */
    for (index = 0; index < clientCipherSuiteLen; index += 3)
    {
        if ((0 == clientCipherSuite[index]) &&
            ( (((ubyte2)clientCipherSuite[index+1] << 8) | (ubyte2)clientCipherSuite[index+2]) ==
                0x5600))
        {
            DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"TLS_FALLBACK_SCSV");
            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
            return 1;
        }
    }

    return 0;
}

/*------------------------------------------------------------------*/

static sbyte4
SSLSOCK_selectCipherSuiteV2( const SSLSocket* pSSLSock, sbyte4 start,
                            ubyte* clientCipherSuite, sbyte4 clientCipherSuiteLen)
{
    sbyte4 i;

    /* see if we support one of the cipher suites */
    for (i = start; i < (sbyte4)NUM_CIPHER_SUITES; i++)
    {
        sbyte4 index;

        if (gCipherSuites[i].supported)
        {
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
            if ((!pSSLSock->isCipherTableInit) ||
                (pSSLSock->isCipherEnabled[i]) )
#endif
            {
                for (index = 0; index < clientCipherSuiteLen; index += 3)
                {
                    if ((0 == clientCipherSuite[index]) &&
                        ( (((ubyte2)clientCipherSuite[index+1] << 8) | (ubyte2)clientCipherSuite[index+2]) ==
                            gCipherSuites[i].cipherSuiteId))
                    {
                        /* matches one of our cipher suites and is not using EC crypto */
                        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLSOCK_selectCipherSuiteV2: CipherSuite selected = 0x");
                        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientCipherSuite[index+1]);
                        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientCipherSuite[index+2]);
                        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
                        return i;
                    }
                }
            }
        }
    }

    return -1;
}


/*------------------------------------------------------------------*/

static MSTATUS
processClientHello2(SSLSocket* pSSLSock)
{
    ubyte* rest;
    sbyte4 selCipherIndex = -1;
#ifdef __ENABLE_ALL_DEBUGGING__
    ubyte4 i;
#endif

    /* already read one byte get the rest of the header */
    SSLClientHelloV2* pClientHello = &(((SSLSharedInBuffer *)(pSSLSock->pSharedInBuffer))->clientHello);
    MSTATUS status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;

    /* The record size is based on the record length. There must be at least 9
     * bytes which contain the remaining data for the record.
     */
    if (pClientHello->record.recordLen < 9)
        goto exit;

    /* verifications */
    if ((pClientHello->record.msgType      != 1)  ||
        (pClientHello->record.majorVersion < SSL3_MAJORVERSION)  ||      /* DO NOT CHECK MINOR VERSION 0 FOR SSL 1 FOR TLS */
        (pClientHello->record.challengeLen < 16)  ||
        (pClientHello->record.challengeLen > 32))
    {
        goto exit;
    }

    /* Ensure the record length is within range of the total amount of cipher
     * suites specified to avoid looping through an invalid set of cipher suite
     * data.
     */
    if (pClientHello->record.cipherSuiteLen + 9 > pClientHello->record.recordLen)
        goto exit;

    /* get the rest of it */
    rest =  ((ubyte *)pClientHello) + sizeof(SSLClientHelloV2Fixed);

	if (findFallbackScsvV2(rest, pClientHello->record.cipherSuiteLen))
    {
        /* this TLS_FALLBACK_SCSV means client tried to renegotiate with lower SSL version */
    	ubyte highestSSLVerSupported = ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)?
                                        pSSLSock->advertisedMinorVersion : SSL_sslSettings()->sslMaxProtoVersion);

        if (highestSSLVerSupported > pClientHello->record.minorVersion)
        {
            /* higher SSL version is supported by server as well as client hence error */
            status = ERR_SSL_SERVER_INAPPROPRIATE_FALLBACK_SCSV;
            goto exit;
        }
    }

    if (pClientHello->record.majorVersion == SSL3_MAJORVERSION)
    {
        /* note the version we received -- used for RSA later on */
        pSSLSock->clientHelloMinorVersion = pClientHello->record.minorVersion;
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        /* for a rehandshake, check if the version matches the last one */
        if (0 < pSSLSock->handshakeCount)
        {
            if (pSSLSock->sslMinorVersion != pClientHello->record.minorVersion)
            {
                status = ERR_SSL_PROTOCOL_VERSION;
                goto exit;
            }
        }
#endif

        /* if a version is specified via SSL_ioctl and it doesn't match */
        if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
        {
            pSSLSock->sslMinorVersion = (ubyte)(pSSLSock->advertisedMinorVersion);

			if ((pSSLSock->advertisedMinorVersion > pClientHello->record.minorVersion) ||
                (pSSLSock->advertisedMinorVersion == 0 && pClientHello->record.minorVersion > 0))
            {
                status = ERR_SSL_PROTOCOL_VERSION;
                goto exit;
            }
        }
        else
        {
            pSSLSock->sslMinorVersion = (ubyte)(pClientHello->record.minorVersion > SSL_sslSettings()->sslMaxProtoVersion ? SSL_sslSettings()->sslMaxProtoVersion : pClientHello->record.minorVersion);
        }
    }
    else
    {
        /* returning an error here. Will provision for higher versions later when we actually support them */
        status = ERR_SSL_PROTOCOL_VERSION;
        goto exit;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    {
    	DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"SSL version = ");
    	DEBUG_INT(DEBUG_SSL_TRANSPORT, pSSLSock->sslMinorVersion);
		DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"");


        DEBUG_PRINT(DEBUG_SSL_TRANSPORT,(sbyte *)"RecordLength = ");
        DEBUG_INT(DEBUG_SSL_TRANSPORT, pClientHello->record.recordLen);
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)", Components = ");
        DEBUG_INT(DEBUG_SSL_TRANSPORT, pClientHello->record.cipherSuiteLen + pClientHello->record.sessionLen + pClientHello->record.challengeLen);
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)".");

        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"Client Hello Ciphers:");

        for ( i = 0; i < pClientHello->record.cipherSuiteLen;  i+=3)
        {
            if (0 == rest[i])
            {
                DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"CipherSuite = 0x");
                DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, rest[i+1]);
                DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, rest[i+2]);
                DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"");
            }
        }
    }
#endif /* __ENABLE_ALL_DEBUGGING__ */

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if (findRenegotiationScsvV2(rest, pClientHello->record.cipherSuiteLen))
    {
        if (0 < pSSLSock->handshakeCount)
        {
            /* SCSV should not be present during renegotitation */
            status = ERR_SSL_SERVER_RENEGOTIATE_ILLEGAL_SCSV;
            goto exit;
        }

        pSSLSock->isRehandshakeAllowed = TRUE;
    }
#endif


    pSSLSock->pHandshakeCipherSuite = NULL;
    selCipherIndex = SSLSOCK_selectCipherSuiteV2(pSSLSock, 0, rest,
                                                pClientHello->record.cipherSuiteLen);
    if (selCipherIndex >= 0 )
    {
        /* found one we like -- set the member pCipherSuite ....*/
        pSSLSock->pHandshakeCipherSuite = gCipherSuites + selCipherIndex;
        if (OK > (status = SSL_SOCK_setServerCert(pSSLSock)))
            goto exit;
        /* client hello version 2 does not support extensions
        assumes the client can deal with any elliptic curves we will use */
    }

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if (0 < pSSLSock->handshakeCount)
    {
        if (pSSLSock->isRehandshakeAllowed)
        {
            /* if client supports secure renegotiation,
            assume it will not use version 2 hello for renegotiation */
            status = ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED;
            goto exit;
        }

        /* allow legacy (insecure) renegotiation only if session flag is set */
        if ( !pSSLSock->isRehandshakeAllowed &&
             !(pSSLSock->runtimeFlags & SSL_FLAG_ALLOW_INSECURE_REHANDSHAKE) )
        {
            status = ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED;
            goto exit;
        }
    }
#endif

    if (NULL != pSSLSock->pHandshakeCipherSuite)
    {
        /* initialize hash pool and hash context */
        if (OK > (status = SSL_SOCK_initHashPool(pSSLSock)))
            goto exit;

        /* we do not deal with session id here: assumes a client will use a
        SSL version 3.0 hello to resume a session */
        pSSLSock->sessionResume = E_NoSessionResume;
        /* get the challenge and save it; challenge can be 16 to 32 chars incl.*/
        /* pad with zero ON THE LEFT if less than 32 */
        if (OK > (status = DIGI_MEMSET(START_RANDOM(pSSLSock), 0, SSL_RANDOMSIZE - pClientHello->record.challengeLen)))
            goto exit;
        if (OK > (status = DIGI_MEMCPY(START_RANDOM(pSSLSock) + SSL_RANDOMSIZE - pClientHello->record.challengeLen,
               rest + pClientHello->record.cipherSuiteLen + pClientHello->record.sessionLen,
               pClientHello->record.challengeLen)))
            goto exit;

        if (OK > (status = DIGI_MEMCPY(pSSLSock->pClientRandHello, START_RANDOM(pSSLSock), SSL_RANDOMSIZE)))  /*!!!!*/
            goto exit;

        /* add to handshake hashes once and only once */
        addToHandshakeHash(pSSLSock, pClientHello->array + 2, pClientHello->record.recordLen);
        status = OK;
    }
    else
    {
        status = ERR_SSL_NO_CIPHER_MATCH;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"processClientHello2() returns status = ", status);

    return status;
}


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
static sbyte4
findRenegotiationScsvV3( ubyte* clientCipherSuite, sbyte4 clientCipherSuiteLen )
{
    sbyte4 index;

    /* see if SCSV exist */
    for (index = 0; index < clientCipherSuiteLen; index +=2)
    {
        if ( (((ubyte2)clientCipherSuite[index] << 8) | (ubyte2)clientCipherSuite[index+1]) ==
                0x00FF )
        {
            DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
            return 1;
        }
    }

    return 0;
}
#endif


/*------------------------------------------------------------------*/

static sbyte4
findFallbackScsvV3( ubyte* clientCipherSuite, sbyte4 clientCipherSuiteLen )
{
    sbyte4 index;

    /* see if TLS_FALLBACK_SCSV exist */
    for (index = 0; index < clientCipherSuiteLen; index += 2)
    {
        if ((((ubyte2)clientCipherSuite[index] << 8) | (ubyte2)clientCipherSuite[index+1]) ==
                0x5600 )
        {
            DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"TLS_FALLBACK_SCSV");
            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
            return 1;
        }
    }

    return 0;
}


/*---------------------------------------------------------------------------*/

static sbyte4
SSLSOCK_selectCipherSuiteV3( const SSLSocket* pSSLSock, sbyte4 start,
                            ubyte* clientCipherSuite, sbyte4 clientCipherSuiteLen)

{
    sbyte4 i;

    for (i = start; i < (sbyte4)NUM_CIPHER_SUITES; i++)
    {
        sbyte4  index;

        if (gCipherSuites[i].supported)
        {
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
            if ((!pSSLSock->isCipherTableInit) ||
                (pSSLSock->isCipherEnabled[i]) )
#endif
            {
                for (index = 0; index < clientCipherSuiteLen; index +=2)
                {
                    if ( (((ubyte2)clientCipherSuite[index] << 8) | (ubyte2)clientCipherSuite[index+1]) ==
                        gCipherSuites[i].cipherSuiteId )
                    {
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                        if (pSSLSock->isDTLS)
                        {
                            /* DTLS does not support stream ciphers */
                            if (isCipherIdExcludedForDTLS(gCipherSuites[i].cipherSuiteId))
                            {
                                continue;
                            }

                            /* cipher supported for this version?. Convert DTLS version to SSL
                             * version by using 256 - dtlsVersion , dtls 1.0 value is 255, dtls 1.2 value is 253.
                             * Incase of dtls 1.0 :  checking for 2nd bit position(0x02) if it is 0 than skip it,
                             * Incase of dtls 1.2 :  checking for 4nd bit position(0x08) if it is 0 than skip it
                             */

                            if (0 == ((gCipherSuites[i].sslVersion >> (256 - pSSLSock->sslMinorVersion)) & 0x01))
                            {
                                continue;
                            }
                        }
                        else
#endif
                        {
                            /* it uses the bit field positions to check the protocol version, ssl3 = 0, tls1.0 = 1,
                             * tls1.1 = 2 , tls1.2 = 3, tls1.3 = 4
                             * example : gCipherSuites[i].sslVersion = 0x0E, ( It supports tls1.2, tls1.1, tls1.0 )
                             * when pSSLSock->sslMinorVersion = 0 (ssl3),    ((0x0E >> 0) & 0x01 )  is 0, means it doesnt supports ssl3
                             * when pSSLSock->sslMinorVersion = 1 (tls1.0),  ((0x0E >> 1) & 0x01 )  is 1, means it supports tls1.0
                             */
                            if (0 == ((gCipherSuites[i].sslVersion >> pSSLSock->sslMinorVersion) & 0x01))
                            {
                                continue;
                            }
                        }

                        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLSOCK_selectCipherSuiteV3: CipherSuite selected = 0x");
                        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientCipherSuite[index]);
                        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientCipherSuite[index+1]);
                        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");

                        return i;
                    }
                }
            }
        }
    }

    return -1;
}


/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
static sbyte4
SSLSOCK_selectSrtpProfile( const SSLSocket* pSSLSock, sbyte4 start,
                            ubyte* clientSrtpProfiles, sbyte4 clientSrtpProfileLen)

{
    sbyte4 i;

    for (i = start; i < (sbyte4)NUM_SRTP_PROFILES; i++)
    {
        sbyte4  index;

        if (gSrtpProfiles[i].supported)
        {
#ifdef __ENABLE_DIGICERT_SRTP_PROFILES_SELECT__
            if ((!pSSLSock->isSrtpProfileTableInit) ||
                (pSSLSock->isSrtpProfileEnabled[i]) )
#endif
            {
                for (index = 0; index < clientSrtpProfileLen; index +=2)
                {
                    if ( (((ubyte2)clientSrtpProfiles[index] << 8) | (ubyte2)clientSrtpProfiles[index+1]) ==
                            gSrtpProfiles[i].profileId )
                    {
                        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLSOCK_selectSrtpProtectionProfile: profile selected = 0x");
                        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientSrtpProfiles[index]);
                        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientSrtpProfiles[index+1]);
                        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");

                        return i;
                    }
                }
            }
        }
    }

    return -1;
}
#endif

/*------------------------------------------------------------------*/

static sbyte4
resetExtensionData(SSLSocket *pSSLSock)
{
    MSTATUS status = OK;
    /* Free all the information sent in extesions if already populated (renegotiation) */
    if (pSSLSock->serverNameIndication != NULL)
    {
        if (OK > (status = DIGI_FREE((void**)&(pSSLSock->serverNameIndication))))
        {
            goto exit;
        }
    }

    if (pSSLSock->alpnProtocols != NULL)
    {
        if (OK > (status = DIGI_FREE((void**)&(pSSLSock->alpnProtocols))))
        {
            goto exit;
        }
        pSSLSock->alpnProtocolsLen = 0;
        pSSLSock->selectedALPN = NULL;
    }

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    pSSLSock->certStatusReqExt = FALSE;
#endif

#if defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
    pSSLSock->roleSpecificInfo.server.clientECCurves = 0;
#endif

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    pSSLSock->pHandshakeSrtpProfile = NULL; /* This is pointer into the gSrtpProfiles list; Dont free it */
    if (pSSLSock->srtpMki != NULL)
    {
        if (OK > (status = DIGI_FREE((void **)&(pSSLSock->srtpMki))))
        {
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_INNER_APP__)
    pSSLSock->receivedInnerAppValue = 0;
    pSSLSock->receivedInnerApp      = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    SSLSOCK_freeHashCtxList(pSSLSock);
#endif

exit:
    return status;
}

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
static MSTATUS checkExtendedMasterSecret(SSLSocket* pSSLSock, intBoolean isExtendedMasterSecret, intBoolean* pResume)
{
    MSTATUS status = OK;
    *pResume = TRUE;
    if (TRUE == isExtendedMasterSecret)
    {
        /* This is abbreviated handshake, original handshake used extended master secret */
        if (FALSE == pSSLSock->receivedExtendedMasterSecret)
        {
            /* If extended_master_secret is not received, throw error */
            *pResume = FALSE;
            status = ERR_SSL_EXTENDED_MASTERSECRET_NOT_SUPPORTED;
        }
    }
    else
    {
        if (TRUE == pSSLSock->receivedExtendedMasterSecret)
        {
            /* If extended_master_secret was not used in original connection,
             * go through full handshake
             */
            *pResume = FALSE;
            pSSLSock->useExtendedMasterSecret = FALSE;
        }
    }
    return status;
}
#endif

static MSTATUS
processClientHello3(SSLSocket* pSSLSock)
{
    ubyte*              rest;
    ubyte               sessionIdLen;
    ubyte               compressionMethodsLen;
    ubyte*              pSHSH;
    sbyte4              recLen; /* length of handshake record */
    sbyte4              lenTotal = 0; /* Maintains the running count of bytes read */
    ubyte*              pClientHelloVer = NULL;
    ubyte4              MAJORVERSION = 0;
    ubyte4              MINORVERSION = 1;
    ubyte4              sessionMinorVersion = 0;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
    sbyte4              cacheIndex = 0;
#if defined(__ENABLE_DIGICERT_TLS13__) || defined (__ENABLE_DIGICERT_OPENSSL_SHIM__)
    ubyte               noExtensions = 0;
#endif
#ifdef __ENABLE_ALL_DEBUGGING__
    ubyte4 i;
#endif

    /* Free extension data if any from the previous connection.
     * Free all the extension data in case of renegotiation.
     */
    if (0 < pSSLSock->handshakeCount)
    {
        if (OK > (status = resetExtensionData(pSSLSock)))
        {
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    pSSLSock->isPSKSelected = 0;
    pSSLSock->roleSpecificInfo.server.receivedExtensions = TLS13_RESET_PRE_SHARED_KEY_EXT_RX(pSSLSock);
#endif
    /* RFC #8446, section 4.1.2 Client Hello:
      Because TLS 1.3 forbids renegotiation, if a server has negotiated 
      TLS 1.3 and receives a ClientHello at any other time, it MUST 
      terminate the connection with an unexpected_message alert.
     */
#if (defined(__ENABLE_DIGICERT_TLS13__))
    if (((!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION) ||
         (pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)) &&
        (0 < pSSLSock->handshakeCount))
    {
        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, TRUE,
                SSL_ALERT_UNEXPECTED_MESSAGE,
                SSLALERTLEVEL_FATAL);
#endif
        goto exit;
    }

    /* When processing ClientHello, make sure pHashCtx is freed;
     * Do NOT free in case the ClientHello is in response to
     * Hello Retry Request message
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if ((pSSLSock->pHashCtx) && (0 == pSSLSock->helloRetryRequest))
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pHashCtx);
        pSSLSock->pHashCtx = NULL;
    }
#endif

    /* If this Client Hello was in response to a retry request, reset the flag */
    if (1 == pSSLSock->helloRetryRequest)
    {
        pSSLSock->helloRetryRequest = 0;
        pSSLSock->roleSpecificInfo.server.hrrClientHello = 1;
    }
#endif

    /* verifications */
    pSHSH = (ubyte*)pSSLSock->pReceiveBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        recLen = getMediumValue(((DTLSHandshakeHeader *)pSHSH)->handshakeSize);
        if ((((DTLSHandshakeHeader *)pSHSH)->handshakeType != SSL_CLIENT_HELLO)  ||
            (recLen + (sbyte4) sizeofHandshakeHeader != pSSLSock->recordSize))
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        recLen = getMediumValue(((SSLHandshakeHeader *)pSHSH)->handshakeSize);
        if ((((SSLHandshakeHeader *)pSHSH)->handshakeType != SSL_CLIENT_HELLO)  ||
            (recLen + (sbyte4) sizeofHandshakeHeader != pSSLSock->recordSize))
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }
    }

    lenTotal += (sbyte4) sizeofHandshakeHeader;

    if (recLen <= 0)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* version is 2 bytes */
    if (lenTotal + 2 > recLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    if( OK > (status = retrieveClientHelloExtensions(pSSLSock, sizeofHandshakeHeader,
                                        &pClientHelloVer, recLen,&noExtensions)))
    {
        if( status == ERR_SSL_PROTOCOL_VERSION)
        {
            /* 4.1.2: Client Hello: TLS 1.3 servers might receive ClientHello messages without an
             * extensions field from prior versions of TLS.
             */
            if(!noExtensions)
            {
                DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)" SSL Legacy version is 1.3 or more with no Extensions present",status);
                goto exit;
            }
            else
            {
                /* This means TLS 1.3 Client Hello is without extensions. So, this may be negotiating
                 * with older version. Eventually, the further condition is handled in fillServerHello 
                 * as per RFC: 4.1.3.
                 */
                if((pClientHelloVer[MINORVERSION] != 0) && (pClientHelloVer[MINORVERSION] < TLS13_MINORVERSION) && (!pSSLSock->isDTLS))
                {
                    pClientHelloVer[MINORVERSION] = TLS12_MINORVERSION;
                    DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"No extensions in TLS 1.3 and Legacy is not lower than 1.3",status);
                }
            }
        }
        else
        {
            goto exit;
        }
    }

#else
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    if (pSSLSock->clientHelloCallback && OK == status)
    {
        status = retrieveClientHelloExtensions(pSSLSock, sizeofHandshakeHeader,
                                            &pClientHelloVer, recLen,&noExtensions);
        if (status != OK)
        {
            goto exit;
        }
    }
#endif
    pClientHelloVer = pSHSH + sizeofHandshakeHeader;
#endif

    /* here we have the complete information for the clientHelloData and some processing has happened. */

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        /* verify versions */
        if (pClientHelloVer[MAJORVERSION] != DTLS1_MAJORVERSION)  /* do not check minor version here */
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }

        pSSLSock->clientHelloMinorVersion = pClientHelloVer[MINORVERSION];
        status = OK;

        if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
        {
            pSSLSock->sslMinorVersion = pSSLSock->advertisedMinorVersion;
			if (pSSLSock->advertisedMinorVersion != pClientHelloVer[MINORVERSION])
            {
                status = ERR_SSL_PROTOCOL_VERSION;
            }
        }
        else
        {
            pSSLSock->sslMinorVersion = (ubyte)(pClientHelloVer[MINORVERSION] < MAX_DTLS_MINORVERSION ?
                                                MAX_DTLS_MINORVERSION : pClientHelloVer[MINORVERSION]);

#if MIN_DTLS_MINORVERSION != (255)
            if (MIN_DTLS_MINORVERSION < pClientHelloVer[MINORVERSION])
            {
                status = ERR_SSL_PROTOCOL_VERSION;
            }
#endif
        }

        if (NULL != pSSLSock->funcPtrVersionCallback)
        {
            pSSLSock->funcPtrVersionCallback(
                pSSLSock->sslMinorVersion,
                pSSLSock->clientHelloMinorVersion, status);
        }
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        /* verify versions */
        if ((pClientHelloVer[MAJORVERSION] < SSL3_MAJORVERSION))  /* do not check minor version here */
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }

        /* note the version we received -- used for RSA later on */
        pSSLSock->clientHelloMinorVersion = pClientHelloVer[MINORVERSION];

        if ((pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET) )
        {
            sessionMinorVersion = pSSLSock->minFallbackMinorVersion;
        }
        else
        {
            sessionMinorVersion =  MIN_SSL_MINORVERSION;
        }

        status = OK;

        if (pClientHelloVer[MAJORVERSION] == SSL3_MAJORVERSION)
        {
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
            /* for a rehandshake, check if the version matches the last one */
            if (0 < pSSLSock->handshakeCount)
            {
                if (pSSLSock->sslMinorVersion != pClientHelloVer[MINORVERSION])
                {
                    status = ERR_SSL_PROTOCOL_VERSION;
                    goto exit;
                }
            }
#endif
            /* if version is set via SSL_ioctl, it has to match the one advertised by client */
            if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
            {
				/*Need to set this to determine correct Alert to send*/
				pSSLSock->sslMinorVersion = pSSLSock->advertisedMinorVersion;
				if (pSSLSock->advertisedMinorVersion > pClientHelloVer[MINORVERSION])
                {
                    status = ERR_SSL_PROTOCOL_VERSION;
                }
            }
            else
            {
                pSSLSock->sslMinorVersion = (ubyte)(pClientHelloVer[MINORVERSION] > SSL_sslSettings()->sslMaxProtoVersion ?
                                                    SSL_sslSettings()->sslMaxProtoVersion : pClientHelloVer[MINORVERSION]);

                if (sessionMinorVersion > pClientHelloVer[MINORVERSION])
                {
                    status = ERR_SSL_PROTOCOL_VERSION;
                }
            }
            if (NULL != pSSLSock->funcPtrVersionCallback)
            {
                pSSLSock->funcPtrVersionCallback(
                    pSSLSock->sslMinorVersion,
                    pSSLSock->clientHelloMinorVersion, status);
            }
            if (OK != status)
                goto exit;
        }
        else
        {
            /* returning an error here. Will provision for higher versions later when we actually support them */
            status = ERR_SSL_PROTOCOL_VERSION;
            goto exit;
        }
    }

    /* Version is 2 bytes */
    lenTotal += 2;

    /* Immediately after version negotiated is known, compute the list of supported signature algorithms */
    if (OK > (status =  SSL_SOCK_filterSupportedSignatureAlgorithm(pSSLSock, TRUE)))
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    /* If we negotiated TLS 1.3, we need the legacy version */
    if (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
    {
        pSSLSock->legacySSLMinorVersion = DTLS12_MINORVERSION;
    }
    else if (pSSLSock->sslMinorVersion == TLS13_MINORVERSION)
    {
        pSSLSock->legacySSLMinorVersion = TLS12_MINORVERSION;
    }
#endif

    /* Set supported groups based on which version was negotiated.
     */
    SSL_SOCK_filterSupportedGroups(pSSLSock);

    /* copy the next 32 bit as client random */
    rest = pSHSH + sizeofHandshakeHeader + 2;

    if (lenTotal + SSL_RANDOMSIZE > recLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pSSLSock->pClientRandHello, rest, SSL_RANDOMSIZE)))
        goto exit;

    if (OK > (status = DIGI_MEMCPY(START_RANDOM(pSSLSock), rest, SSL_RANDOMSIZE)))
        goto exit;

    rest += SSL_RANDOMSIZE;
    lenTotal += SSL_RANDOMSIZE;

    /* id len */
    sessionIdLen = *rest++;

    if (sessionIdLen > 32)  /* 0..32 */
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
        goto exit;
    }

    lenTotal += 1 + sessionIdLen;

    if (lenTotal > recLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    /* RFC 5077 Section 3.4 Interaction with TLS Session ID
     *
     * When presenting a ticket, the client MAY generate and include a
     * Session ID in the TLS ClientHello.  If the server accepts the ticket
     * and the Session ID is not empty, then it MUST respond with the same
     * Session ID present in the ClientHello.
     */
    if (TLS10_MINORVERSION <= pSSLSock->sslMinorVersion)
#else
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
#endif
    {
        pSSLSock->roleSpecificInfo.server.sessionIdEchoLen = sessionIdLen;
        DIGI_MEMCPY(pSSLSock->roleSpecificInfo.server.sessionIdEcho, rest, sessionIdLen);
    }
#endif
    pSSLSock->sessionResume = E_NoSessionResume;

    if (sizeof(SESSIONID) == sessionIdLen) /* might be one of ours */
    {
        /* look in our cache */
        SESSIONID sessionId;
        /* get sessionId */
        /* &sessionId and rest are always not NULL, return check not needed */
        (void) DIGI_MEMCPY( (ubyte*) &sessionId, rest, sizeof(SESSIONID));
        /* cacheIndex is session modulo SESSION_CACHE_SIZE */
        cacheIndex = sessionId % SESSION_CACHE_SIZE;

        if (OK > (status = RTOS_mutexWait(gSslSessionCacheMutex)))
            goto exit;

#ifndef __DISABLE_DIGICERT_SSL_SESSION_CACHE__
        /* is there a match? */
        if (sessionId == gSessionCache[cacheIndex].m_sessionId)
        {
            if (gSessionResumeTimeout > RTOS_deltaMS(&gSessionCache[cacheIndex].startTime, NULL))
            {
                pSSLSock->sessionResume = E_SessionIDResume;
                if (pSSLSock->sslMinorVersion != gSessionCache[cacheIndex].m_minorVersion)
                {
                    status = ERR_SSL_BAD_HEADER_VERSION;
                    /* already returning bad status, no need to check mutex release */
                    (void) RTOS_mutexRelease(gSslSessionCacheMutex);
                    goto exit;
                }
                /* don't set the cipher suite there blindly, first
                 verify that the client hello matches the one in the session cache
                pSSLSock->pHandshakeCipherSuite = gSessionCache[cacheIndex].m_pCipherSuite; */
                pSSLSock->roleSpecificInfo.server.sessionId = sessionId;
                if (OK > (status = DIGI_MEMCPY(pSSLSock->pSecretAndRand,
                           gSessionCache[cacheIndex].m_masterSecret,
                           SSL_MASTERSECRETSIZE)))
                {
                    /* already returning status */
                    (void) RTOS_mutexRelease(gSslSessionCacheMutex);
                    goto exit;
                }

#if ( defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__))
                if (pSSLSock->isDTLS)
                {
                    pSSLSock->pHandshakeSrtpProfile = gSessionCache[cacheIndex].m_pSrtpProfile;
                }
#endif
                if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
                    (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
                {
                    pSSLSock->signatureAlgo = gSessionCache[cacheIndex].m_signatureAlgo;
                }

				pSSLSock->roleSpecificInfo.server.clientECCurves = gSessionCache[cacheIndex].m_clientECCurves;
            }
        }
#endif

        if ((E_SessionIDResume != pSSLSock->sessionResume) && (sessionId == (1 + gNextSessionId)))
        {
            gNextSessionId++;
        }

        if (OK > (status = RTOS_mutexRelease(gSslSessionCacheMutex)))
            goto exit;

    }

    /* in all cases, jump over the session id*/
    rest += sessionIdLen;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {

#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            /* RFC 9147 Section 5.3
            legacy_cookie: A DTLS 1.3-only client MUST set the legacy_cookie field to zero length. 
            If a DTLS 1.3 ClientHello is received with any other value in this field, the server 
            MUST abort the handshake with an "illegal_parameter" alert.
            */
            if (0x00 != *rest)
            {
                status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, FALSE /* not yet encrypted */,
                        SSL_ALERT_ILLEGAL_PARAMETER,
                        SSLALERTLEVEL_FATAL);
#endif
                goto exit;
            }
            rest += 1;
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            /* verify cookie is done already (before initialize SSLSock) */
            rest += (*rest) + 1;
        } 
        pSSLSock->nextRecvSeq++;
    }
#endif /* __ENABLE_DIGICERT_DTLS_SERVER__ */

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    pSSLSock->isRehandshakeExtPresent = FALSE;
#endif

    status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;

    /* determine the cipher suite from the client hello in all cases */
    {
        ubyte*  clientCipherSuite;
        sbyte4  cipherSuiteLen;
        sbyte4  selCipherIndex = -1;
        /* check to see if we can fetch the next two bytes for cipherSuiteLen */
        if ( rest + 2 - (pSHSH + sizeofHandshakeHeader) >= recLen)
            goto exit;

        cipherSuiteLen = getShortValue(rest);

        /* 2-bytes is used to denote a single cipher suite */
        if (cipherSuiteLen < 2)
        {
            goto exit;
        }

        /* check cipher suite length */
        if (2 + cipherSuiteLen + rest - (pSHSH + sizeofHandshakeHeader) >= recLen)
            goto exit;

        rest += 2;

        clientCipherSuite = rest;
        rest += cipherSuiteLen;

        /*
         * Cipher Suites are denoted by 2 bytes each. If the cipher Suite length is odd,
         * do not process the last byte;
         */
        if ((cipherSuiteLen % 2) != 0)
        {
            cipherSuiteLen--;
        }

#ifdef __ENABLE_ALL_DEBUGGING__
        {
        	DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"SSL version = ");
    		DEBUG_INT(DEBUG_SSL_TRANSPORT, pSSLSock->sslMinorVersion);
    		DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"");

            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"Client Hello Ciphers (v3):");

            for (i = 0; (sbyte4)i < cipherSuiteLen;  i+=2)
            {
                DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"CipherSuite = 0x");
                DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientCipherSuite[i]);
                DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, clientCipherSuite[i+1]);
                DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"");
            }
        }
#endif /* __ENABLE_ALL_DEBUGGING__ */

        if (findFallbackScsvV3(clientCipherSuite, cipherSuiteLen))
        {
            /* this TLS_FALLBACK_SCSV means client tried to renegotiate with lower SSL version */
            ubyte highestSSLVerSupported = (ubyte)-1;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if(pSSLSock->isDTLS)
            {
                highestSSLVerSupported = ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)?
                                          pSSLSock->advertisedMinorVersion : DTLS12_MINORVERSION);
                if (highestSSLVerSupported < pClientHelloVer[MINORVERSION])
                {
                    /* higher SSL version is supported by server as well as client hence error */
                    status = ERR_SSL_SERVER_INAPPROPRIATE_FALLBACK_SCSV;
                    goto exit;
                }
            }
            else
#endif
            {
                highestSSLVerSupported = ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)?
                                          pSSLSock->advertisedMinorVersion : TLS12_MINORVERSION);
                if (highestSSLVerSupported > pClientHelloVer[MINORVERSION])
                {
                    /* higher SSL version is supported by server as well as client hence error */
                    status = ERR_SSL_SERVER_INAPPROPRIATE_FALLBACK_SCSV;
                    goto exit;
                }
            }
        }

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        if (findRenegotiationScsvV3(clientCipherSuite, cipherSuiteLen))
        {
            if (0 < pSSLSock->handshakeCount)
            {
                /* SCSV should not be present during renegotiation */
                status = ERR_SSL_SERVER_RENEGOTIATE_ILLEGAL_SCSV;
                goto exit;
            }

            pSSLSock->isRehandshakeAllowed = TRUE;
        }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((pSSLSock->isDTLS && (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)) || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
#endif
        {
            pSSLSock->pHandshakeCipherSuite = NULL;
        }

        if (NULL == pSSLSock->pHandshakeCipherSuite)
        {
            selCipherIndex = SSLSOCK_selectCipherSuiteV3( pSSLSock, 0, clientCipherSuite, cipherSuiteLen);
            if (OK > selCipherIndex)
            {
                status = ERR_SSL_NO_CIPHER_MATCH;
                goto exit;
            }
            pSSLSock->pHandshakeCipherSuite = gCipherSuites + selCipherIndex;
        }

        /* skip past compression methods */
        compressionMethodsLen = *rest;
        rest += 1;
#ifdef __ENABLE_DIGICERT_TLS13__
        /*
           RFC 8446, page 30, legacy_compression_methods:
           For every TLS 1.3 ClientHello, this vector
           MUST contain exactly one byte, set to zero, which corresponds to
           the "null" compression method in prior versions of TLS.  If a
           TLS 1.3 ClientHello is received with any other value in this
           field, the server MUST abort the handshake with an
           "illegal_parameter" alert.
         */
        if ((pSSLSock->sslMinorVersion == TLS13_MINORVERSION) || (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION))
        {
            if (*rest != 0)
            {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                        SSL_ALERT_ILLEGAL_PARAMETER,
                        SSLALERTLEVEL_FATAL);
#endif
                status = ERR_SSL_FATAL_ALERT;
                goto exit;
            }
        }
#endif
        rest += compressionMethodsLen;

        /* set the clientECCurves to 0xFFFF -> the client can deal with any curves if
        there is no ECCurve Hello Extension */
		if (E_SessionIDResume != pSSLSock->sessionResume)
        {
			pSSLSock->roleSpecificInfo.server.clientECCurves = 0xFFFFFFFF;
        }

        if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) || (selCipherIndex >= 0))
        {
            /* extension is only supported in TLS
               but minimal support is added in SSL 3.0 for secure renegotiation */
            /* if we successfully found a cipher suite, and the version is TLS 1.0+ proceed */
            if ( rest + 2 - (pSHSH+sizeofHandshakeHeader) < recLen)
            {
                /* check the extension length */
                ubyte4 extensionsLength = getShortValue(rest);
                rest += 2;
                if ( rest + extensionsLength - (pSHSH+sizeofHandshakeHeader) <= recLen)
                {
                    if (OK > (status = processHelloExtensions(pSSLSock, rest, extensionsLength, SSL_CLIENT_HELLO)))
                        goto exit;
                }
            }
#ifdef __ENABLE_DIGICERT_TLS13__
            if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion || DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                /* RFC: 9.2.  Mandatory-to-Implement Extensions
                 * If containing a "supported_groups" extension, it MUST also contain
                 * a "key_share" extension, and vice versa.  An empty
                 * KeyShare.client_shares vector is permitted.
                 */
                if (TLS13_GET_KEY_SHARE_EXT_RX(pSSLSock) ^ TLS13_GET_SUPPORTED_GROUPS_EXT_RX(pSSLSock))
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                                    SSL_ALERT_MISSING_EXTENSION,
                                    SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    goto exit;
                }
                /* RFC: 9.2. Mandatory-to-Implement Extensions
                 * If not containing a "pre_shared_key" extension, it MUST contain
                 * both a "signature_algorithms" extension and a "supported_groups"
                 * extension.
                 */
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                /* RFC :9.2: Mandtory-to-Implement Extensions
                 * Servers requiring this extension SHOULD respond to a ClientHello
                 * lacking a "server_name" extension by terminating the connection with
                 * a "missing_extension" alert.
                 */
                /* Commented out because Chrome does not send Server Name Indication with PSK;
                 * OpenSSL allows this case
                 */

                if (!TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock))
                {
                    if (!((1 == TLS13_GET_SUPPORTED_GROUPS_EXT_RX(pSSLSock)) &
                         (1 == TLS13_GET_SIGNATURE_ALGO_EXT_RX(pSSLSock))))
                    {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                                    SSL_ALERT_MISSING_EXTENSION,
                                    SSLALERTLEVEL_FATAL);
#endif
                        status = ERR_SSL_FATAL_ALERT;
                        goto exit;
                    }
                }

                /* RFC: 9.2.  Mandatory-to-Implement Extensions.
                 * "signature_algorithms" is REQUIRED for certificate authentication.
                 */
#else /* __ENABLE_DIGICERT_TLS13_PSK__ */
                if (0 == TLS13_GET_SIGNATURE_ALGO_EXT_RX(pSSLSock))
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, TRUE,
                    SSL_ALERT_MISSING_EXTENSION,
                    SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    goto exit;
                }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
        }
#endif /* __ENABLE_DIGICERT_TLS13__ */

            /* now that we have parsed the extensions call the
            function to get a certificate repeatedly until sure it can be used*/
#ifdef __ENABLE_DIGICERT_TLS13__
            if ((pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                /* For PSK there is no need to select a server certificate. The
                 * same goes for 0-RTT. If 0-RTT is being performed then a PSK
                 * has been selected.
                 */
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                if (NULL == pSSLSock->roleSpecificInfo.server.pSelectedPSK)
#endif
                {
                    intBoolean found = FALSE;

                    status = SSL_SOCK_setCertTLS13(
                        pSSLSock, pSSLSock->pCertStore, pSSLSock->signatureAlgoList,
                        pSSLSock->signatureAlgoListLength,
                        pSSLSock->signatureAlgoCertList,
                        pSSLSock->signatureAlgoCertListLength,
                        pSSLSock->serverNameIndication, &(pSSLSock->handshakeKey),
                        &(pSSLSock->roleSpecificInfo.server.certificates),
                        &(pSSLSock->roleSpecificInfo.server.numCertificates),
                        &pSSLSock->signatureAlgo, &found);
                    if (OK == status && FALSE == found)
                    {
                        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    }
                    if (OK != status)
                    {
                        goto exit;
                    }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
                    if (OK > (status = SSLSOCK_setKeyAndTokenHandle(pSSLSock, TRUE /* isServer */)))
                    {
                        goto exit;
                    }
#endif
                }
            }
            else
#endif /* __ENABLE_DIGICERT_TLS13__ */
            {
                while (selCipherIndex >= 0 )
                {

                    pSSLSock->pHandshakeCipherSuite = gCipherSuites + selCipherIndex;
                    status = SSL_SOCK_setServerCert(pSSLSock);
                    if (0 <= status)
                    {
                        /* cipher is good to use */
                        break;
                    }
                    /* otherwise loop and try again */
                    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"Incompatible EC curves returned by SSL_setServerCert: ");
                    DEBUG_HEXINT(DEBUG_SSL_TRANSPORT, pSSLSock->roleSpecificInfo.server.clientECCurves);
                    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
                    pSSLSock->pHandshakeCipherSuite = NULL;
                    selCipherIndex = SSLSOCK_selectCipherSuiteV3( pSSLSock, selCipherIndex + 1,
                                                                    clientCipherSuite, cipherSuiteLen);
                }
            }
#if (defined(__ENABLE_DIGICERT_TLS13__) && (__ENABLE_DIGICERT_TLS13_PSK__))
            if (((DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) || (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
                (pSSLSock->isPSKSelected) &&
                (TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)))
            {
                pSSLSock->roleSpecificInfo.server.pSelectedPSK->hashAlgo = getHashIdFromSuite(pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo);

                if (0 == pSSLSock->roleSpecificInfo.server.pSelectedPSK->hashAlgo)
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }

#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                /* RFC #8446, Section 4.2.10, Page 54:
                   Server MUST verify that the following values are the same as those associated with the
                   selected PSK. TLS version number, selected cipher suite, selected ALPN. */
                if (1 == pSSLSock->earlyDataExtAccepted)
                {
                    if (((pSSLSock->roleSpecificInfo.server.pSelectedPSK->pSelectedTlsVersion & 0xff) != pSSLSock->clientHelloMinorVersion) ||
                            (pSSLSock->roleSpecificInfo.server.pSelectedPSK->selectedCipherSuiteId != pSSLSock->pHandshakeCipherSuite->cipherSuiteId) ||
                            ((NULL != pSSLSock->selectedALPN) && (DIGI_STRNICMP((const sbyte *) pSSLSock->roleSpecificInfo.server.pSelectedPSK->selectedALPN,
                                          (const sbyte *) pSSLSock->selectedALPN, *(pSSLSock->roleSpecificInfo.server.pSelectedPSK->selectedALPN)))))
                    {
                        pSSLSock->earlyDataExtAccepted = 0;
                    }
                }
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ */
            }
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_TLS13_PSK__*/
        }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
        if (((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
            (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))) &&
            (pSSLSock->sessionResume != E_NoSessionResume))
        {
            intBoolean isExtendedMasterSecret = FALSE;
            intBoolean resume = TRUE;

            if (pSSLSock->sessionResume == E_SessionIDResume)
                isExtendedMasterSecret = gSessionCache[cacheIndex].isExtendedMasterSecret;
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
            else if (pSSLSock->sessionResume == E_SessionTicketResume)
                isExtendedMasterSecret = pSSLSock->roleSpecificInfo.server.ticketUseExtendedMasterSecret;
#endif

            if (OK > (status = checkExtendedMasterSecret(pSSLSock, isExtendedMasterSecret, &resume)))
                goto exit;

            if (FALSE == resume)
            {
                /* New Client Hello does not support the  */
                pSSLSock->sessionResume = E_NoSessionResume;
            }
        }
#endif

        /* fferino@mocana.com: current code: if we are resuming a session, makes sure the selected handshake suite
         is the same as before */
        if ((pSSLSock->sessionResume == E_SessionIDResume) &&
            (pSSLSock->pHandshakeCipherSuite != gSessionCache[cacheIndex].m_pCipherSuite))
        {
            status = ERR_SSL_PROTOCOL;
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        if ((pSSLSock->sessionResume == E_SessionTicketResume) &&
            (NULL == pSSLSock->pHandshakeCipherSuite ||
             pSSLSock->pHandshakeCipherSuite->cipherSuiteId != pSSLSock->roleSpecificInfo.server.ticketCipherSuiteId))
        {
            status = ERR_SSL_PROTOCOL;
            goto exit;
        }
#endif
    }

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if (0 < pSSLSock->handshakeCount)
    {
        if ( (pSSLSock->isRehandshakeAllowed && !pSSLSock->isRehandshakeExtPresent) ||
             (!pSSLSock->isRehandshakeAllowed && pSSLSock->isRehandshakeExtPresent) )
        {
            status = ERR_SSL_SERVER_RENEGOTIATE_ILLEGAL_EXTENSION;
            goto exit;
        }

        /* allow legacy (insecure) renegotiation only if session flag is set */
        if ( (!pSSLSock->isRehandshakeAllowed && !pSSLSock->isRehandshakeExtPresent) &&
             !(pSSLSock->runtimeFlags & SSL_FLAG_ALLOW_INSECURE_REHANDSHAKE) )
        {
            status = ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED;
            goto exit;
        }
    }
#endif

    if (pSSLSock->pHandshakeCipherSuite)
    {
#if defined(__ENABLE_DIGICERT_EAP_FAST__)
        /* it must be RC4 SHA1 */
        if ( E_SessionEAPFASTResume == pSSLSock->sessionResume &&
            pSSLSock->pHandshakeCipherSuite->cipherSuiteId != 0x05)
        {
            status = ERR_EAP_FAST_WRONG_CIPHER;
            goto exit;
        }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
        /* In case of retry, hashPool is already initialized */
        if (0 == pSSLSock->roleSpecificInfo.server.hrrClientHello &&
            ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion > DTLS13_MINORVERSION) || !pSSLSock->isDTLS))
#endif
        {
            /* initialize hash pool and hash context */
            if (OK > (status = SSL_SOCK_initHashPool(pSSLSock)))
                goto exit;
        }

#if defined(__ENABLE_DIGICERT_TLS13__)
        if ( ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
              (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) && 
               1 == pSSLSock->helloRetryRequest )
        {
            status = addHrrClientHelloToHandshakeHash(
                pSSLSock, (ubyte *) pSSLSock->pReceiveBuffer, pSSLSock->recordSize);
            if (OK > status)
            {
                goto exit;
            }
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            /* add to handshakeHash once and only once */
            addToHandshakeHash(pSSLSock, (ubyte *)pSSLSock->pReceiveBuffer, pSSLSock->recordSize);
        }

#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            ubyte *psk = NULL;
            ubyte4 pskLen = 0;

            if (pSSLSock->isPSKSelected && 
                TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock))
            {
                psk = pSSLSock->roleSpecificInfo.server.pSelectedPSK->pskTLS13;
                pskLen = pSSLSock->roleSpecificInfo.server.pSelectedPSK->pskTLS13Length;
            }

            /* Client Hello has been processed.
             * Do NOT derive secrets if helloRetryRequest is being sent out
             */
            if (0 == pSSLSock->roleSpecificInfo.server.hrrClientHello)
            {
                if (OK > (status = SSLSOCK_pskEarlySecretDerive(
                                pSSLSock, psk, pskLen,
                                pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo)))
                {
                    goto exit;
                }
            }

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
            if ((pSSLSock->roleSpecificInfo.server.pSelectedPSK) &&
                (1 == pSSLSock->roleSpecificInfo.server.pSelectedPSK->isPSKavailable) &&
                (1 == pSSLSock->earlyDataExtAccepted))
            {
                if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock, pSSLSock->pClientEarlyTrafficSecret)))
                {
                    goto exit;
                }

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
                if (pSSLSock->isDTLS)
                {
                    pSSLSock->peerSeqnumHigh = (pSSLSock->peerSeqnumHigh & 0x0000ffff) + 0x10000;
                    pSSLSock->peerSeqnum = 0;
                    pSSLSock->currentPeerEpoch = 0x01;
                    releaseRetransmissionBuffer(pSSLSock);
                }
#endif
            }
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ && __ENABLE_DIGICERT_TLS13_PSK__ */
        }
#endif/* __ENABLE_DIGICERT_TLS13__  */
        status = OK;
    }
    else
    {
        status = ERR_SSL_NO_CIPHER_MATCH;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
    /* if we picked a SSL_SRP cipher, verify there was an identity extension */
    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_SRP_BIT)
    {
        if (!pSSLSock->srpIdentity)
        {
            status = ERR_SSL_SRP_NO_IDENTITY;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, TRUE,
                              SSL_ALERT_UNKNOWN_PSK_IDENTITY,
                              SSLALERTLEVEL_FATAL);
#endif
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    if (pSSLSock->useSrtp && NULL == pSSLSock->pHandshakeSrtpProfile)
    {
        status = ERR_DTLS_SRTP_NO_PROFILE_MATCH;
        goto exit;
    }
#endif

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"processClientHello3() returns status = ", status);
    return status;

} /* processClientHello3 */


/*------------------------------------------------------------------*/

static MSTATUS
sslHelloStateMachine(SSLSocket* pSSLSock)
{
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
    pid_t pid = getpid();
#else
    ubyte4 pid = 0xFF;
#endif /* defined(__RTOS_LINUX__) ||  defined(__RTOS_OSX__) */
    /* Deferred gNextSessionId initialization for multi-process environment */
    if (gNextSessionId == 0xFFFFFFF0)
    {
        if (OK > (status = SSL_rngFun(sizeof(SESSIONID), (ubyte*)&gNextSessionId)))
        {
            goto exit;
        }
        gNextSessionId = (gNextSessionId & 0x00FFFFFF) | ((ubyte4)(pid) << 24);
    }
#endif /* __ENABLE_DIGICERT_OPENSSL_SHIM__ */

    switch (pSSLSock->protocol)
    {
        case SSLV2_HELLO_CLIENT:
            status = processClientHello2(pSSLSock);
            break;

        case SSL_HANDSHAKE:
            status = processClientHello3(pSSLSock);
            break;

        default:
            status = ERR_SSL_PROTOCOL_BAD_STATE;
            break;
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"sslHelloStateMachine() returns status = ", status);

#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"Resume state = ");
    DEBUG_INT(DEBUG_SSL_TRANSPORT, pSSLSock->sessionResume);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)".");
#endif

#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
exit:
#endif

    return status;
}


#if (defined(__ENABLE_DIGICERT_SSL_SRP__))

/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_SRPGenerateB( SSLSocket* pSSLSock, const ubyte* modulus,
                      sbyte4 modulusLen, const ubyte* generator,
                      sbyte4 generatorLen, const ubyte* kBytes)
{
    MSTATUS status;
    vlong* g = 0;
    vlong* N = 0;
    vlong* k = 0;
    vlong* tmp = 0;
    vlong* pVlongQueue = 0;
    sbyte4 BLen;


    if (OK > (status = VLONG_vlongFromByteString(modulus, modulusLen,
                                                 &N, 0)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(generator, generatorLen,
                                                 &g, 0)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(kBytes, SHA1_RESULT_SIZE,
                                                 &k, 0)))
    {
        goto exit;
    }

    /* compute B = kv + g^b % N */
    if (OK > ( status = VLONG_modexp(g, pSSLSock->roleSpecificInfo.server.srpb,
                                     N, &tmp, &pVlongQueue)))
    {
        goto exit;
    }

    /* reuse g as a temp for kv */
    if (OK > ( status = VLONG_unsignedMultiply(g, k,
                                               pSSLSock->roleSpecificInfo.server.srpVerifier)))
    {
        goto exit;
    }

    if (OK > ( status = VLONG_addSignedVlongs(g, tmp, &pVlongQueue)))
    {
        goto exit;
    }

    VLONG_freeVlong(&tmp, &pVlongQueue);
    if (OK > ( status = VLONG_operatorModSignedVlongs(g, N, &tmp, &pVlongQueue)))
    {
        goto exit;
    }

    /* store the B for use in handshake */
    if (OK > ( status = SSL_SOCK_SerializeVLong(tmp,
                                                &pSSLSock->roleSpecificInfo.server.srpB,
                                                &BLen)))
    {
        goto exit;
    }

    pSSLSock->roleSpecificInfo.server.srpBLen = (ubyte2) BLen;

exit:

    VLONG_freeVlong(&tmp, 0);
    VLONG_freeVlong(&k, 0);
    VLONG_freeVlong(&g, 0);
    VLONG_freeVlong(&N, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_SRPServerPremasterSecret(SSLSocket* pSSLSock, ubyte* pA, sbyte4 aLen,
                                  ubyte** premaster, sbyte4* premasterLen,
                                  vlong** ppVlongQueue)
{
    MSTATUS status;
    vlong* u = 0;
    vlong* a = 0;
    vlong* vu = 0;
    vlong* N = 0;
    const ubyte* modulus;
    sbyte4 modulusLen;
    const ubyte* generator;
    sbyte4 generatorLen;
    const ubyte* kBytes;

    ubyte shaResult[SHA1_RESULT_SIZE];

    if (OK > ( status = SRP_getGroupParameters2(pSSLSock->srpNumBits,
                                                &modulus, &modulusLen,
                                                &generator, &generatorLen, &kBytes)))
    {
        goto exit;
    }

    if (OK > ( status = VLONG_vlongFromByteString(modulus, modulusLen,
                                                  &N, ppVlongQueue)))
    {
        goto exit;
    }


    /* u */
    if (OK > ( status = SSL_SOCK_SRPConcatPadSha(pSSLSock,
                                                 pA, aLen,
                                                 pSSLSock->roleSpecificInfo.server.srpB,
                                                 pSSLSock->roleSpecificInfo.server.srpBLen,
                                                 modulusLen, shaResult)))
    {
        goto exit;
    }

    if (OK > ( status = VLONG_vlongFromByteString(shaResult, SHA1_RESULT_SIZE,
                                                  &u, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > ( status = VLONG_modexp(pSSLSock->roleSpecificInfo.server.srpVerifier,
                                     u, N, &vu, ppVlongQueue)))
    {
        goto exit;
    }

    /* a */
    if (OK > ( status = VLONG_vlongFromByteString(pA, aLen, &a, ppVlongQueue)))
    {
        goto exit;
    }

    /* A * v^u % N */
    if (OK > ( status = VLONG_unsignedMultiply(u, a, vu)))
    {
        goto exit;
    }

    VLONG_freeVlong(&a, ppVlongQueue);
    if (OK > ( status = VLONG_operatorModSignedVlongs(u, N, &a, ppVlongQueue)))
    {
        goto exit;
    }

    VLONG_freeVlong(&u,ppVlongQueue);
    if (OK > ( status = VLONG_modexp(a,
                                     pSSLSock->roleSpecificInfo.server.srpb, N,
                                     &u, ppVlongQueue)))
    {
        goto exit;
    }

    /* serialize premaster */
    if (OK > (status = SSL_SOCK_SerializeVLong(u, premaster, premasterLen)))
    {
        goto exit;
    }

exit:

    VLONG_freeVlong(&u, ppVlongQueue);
    VLONG_freeVlong(&a, ppVlongQueue);
    VLONG_freeVlong(&vu, ppVlongQueue);
    VLONG_freeVlong(&N, ppVlongQueue);

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_getSRPParametersForIdentity(SSLSocket* pSSLSock,
                                     ubyte salt[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                     ubyte4* saltLen,
                                     const ubyte** modulus, sbyte4* modulusLen,
                                     const ubyte** generator, sbyte4* generatorLen)
{
    MSTATUS status;
    static const ubyte* secretSeed = (const ubyte*) "\xed\x6c\x13\xd7\x8c\x1b\x85\xd6\x07\xb6\x19\x78\xa3\x70\x16\x6a";

    ubyte* verifier = 0;
    ubyte4 verifierLen;
    sbyte4 generate = TRUE;
    ubyte bBytes[32];
    const ubyte* k;
    /* retrieve the parameters for the identity: group, salt, verifier
     if there's none (user unknowm) fake them so that no information
     is leaked about valid user identities */

    if (!SSL_sslSettings()->funcPtrSRPCallback)
    {
        status = ERR_SSL_CONFIG;
        goto exit;
    }

    if (pSSLSock->srpIdentity == NULL)
    {
        status = ERR_SSL_SRP_INVALID_PARAMS;
        goto exit;
    }

    if (OK == SSL_sslSettings()->funcPtrSRPCallback(SSL_findConnectionInstance(pSSLSock),
                                                    pSSLSock->srpIdentity + 1,
                                                    pSSLSock->srpIdentity[0],
                                                    &pSSLSock->srpNumBits,
                                                    salt, saltLen,
                                                    &verifier, &verifierLen))
    {
        /* sanity checking */
        if (*saltLen > SSL_PSK_SERVER_IDENTITY_LENGTH)
        {
            status = ERR_SSL_SRP_CALLBACK_OVERFLOW_BUF;
            goto exit;
        }

        if ((sbyte4) verifierLen * 8 > pSSLSock->srpNumBits)
        {
            status = ERR_SSL_SRP_INVALID_PARAMS;
            goto exit;
        }

        generate = FALSE;
    }

    if (generate)
    {
        /* generate the same salt for a given identity */
        P_hash(pSSLSock, secretSeed, 16,
               pSSLSock->srpIdentity + 1,
               pSSLSock->srpIdentity[0],
               salt, 16, &SHA1Suite);
        *saltLen = 16;

        pSSLSock->srpNumBits = __DIGICERT_MIN_SRP_BITS__;

        verifierLen = __DIGICERT_MIN_SRP_BITS__/8;
        /* generate a random verifier */
        verifier = (ubyte*) MALLOC(verifierLen);
        if (!verifier)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        pSSLSock->rngFun( pSSLSock->rngFunArg, verifierLen, verifier);
    }


    if (OK > ( status = SRP_getGroupParameters2(pSSLSock->srpNumBits,
                                                modulus, modulusLen,
                                                generator, generatorLen,
                                                &k)))
    {
        if (generate)
        {
            /* __DIGICERT_MIN_SRP_BITS__ is not correctly defined */
            status = ERR_SSL_CONFIG;
        }
        goto exit;
    }

    /* convert the verifier to vlong */
    if (OK > ( status = VLONG_vlongFromByteString( verifier, verifierLen,
                                                  &pSSLSock->roleSpecificInfo.server.srpVerifier,
                                                  0)))
    {
        goto exit;
    }

    /* generate b */
    pSSLSock->rngFun( pSSLSock->rngFunArg, 32, bBytes);
    if (OK > ( status = VLONG_vlongFromByteString(bBytes, sizeof(bBytes),
                                                  &pSSLSock->roleSpecificInfo.server.srpb,
                                                  0)))
    {
        goto exit;
    }


    /* generate B */
    if (OK > ( status = SSL_SOCK_SRPGenerateB(pSSLSock, *modulus, *modulusLen,
                                              *generator, *generatorLen, k)))
    {
        goto exit;
    }

exit:

    FREE(verifier);

    return status;
}

#endif


/*------------------------------------------------------------------*/

static MSTATUS
fillServerHello(SSLSocket* pSSLSock, ubyte* pHSRec, ubyte versionMask, intBoolean sendCookie)
{
    ubyte* pVarPart;
    ubyte* pExtensionsLength = NULL;
    ubyte2 totalExtensionsLength = 0;
    ubyte  sslMinorVersion = pSSLSock->sslMinorVersion;
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    ubyte4 cookieLen;
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte4 curveLength;
    ubyte4 extCount = 0;

    DIGI_MEMSET((void *) pSSLSock->sentExtensions, 0x00, MAX_EXTENSIONS_SENT);
#endif /*  __ENABLE_DIGICERT_TLS13__ */

    /* pointer to variable part */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        pVarPart = (ubyte *)(((DTLSHandshakeHeader*)pHSRec) + 1);
        /* Server Hello */
        if (versionMask & 0x01)
        {
            *pVarPart++ = DTLS1_MAJORVERSION; /* major version */
        }

#ifdef __ENABLE_DIGICERT_TLS13__
        if (VERSION_MASK_2 == versionMask)
        {

            setShortValue(pVarPart, pSSLSock->tls13EncryptedExtensionsLength);
            pVarPart += sizeof(ubyte2);
        }
#endif
    } else
#endif
    {
        pVarPart = (ubyte *)(((SSLHandshakeHeader*)pHSRec) + 1);
        /* Server Hello */
        if (versionMask & 0x01)
        {
            *pVarPart++ = SSL3_MAJORVERSION; /* major version */
        }

        /* Encrypted Extensions */
#ifdef __ENABLE_DIGICERT_TLS13__
        if (VERSION_MASK_2 == versionMask)
        {

            setShortValue(pVarPart, pSSLSock->tls13EncryptedExtensionsLength);
            pVarPart += sizeof(ubyte2);
        }
#endif
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (DTLS13_MINORVERSION == sslMinorVersion)
    {
        if (pSSLSock->isDTLS)
        {
            if ((versionMask == VERSION_MASK_1) || ((versionMask == VERSION_MASK_3)))
            {
                *pVarPart++ = pSSLSock->legacySSLMinorVersion; /* minor version */
            }

            /* Add Random number only for ServerHello */
            if (versionMask & VERSION_MASK_1)
            {
                if(pSSLSock->helloRetryRequest == 1)
                {
                    DIGI_MEMCPY(pVarPart, serverHrrRandom, SSL_RANDOMSIZE);
                }
                else
                {
                    (void) DIGI_MEMCPY(pVarPart,
                    pSSLSock->pSecretAndRand + SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE,
                    SSL_RANDOMSIZE);
                }
                pVarPart += SSL_RANDOMSIZE;
            }
        }
    }
    else
#endif
    if (TLS13_MINORVERSION == sslMinorVersion)
    {
        if ((versionMask == VERSION_MASK_1) || ((versionMask == VERSION_MASK_3)))
        {
            *pVarPart++ = pSSLSock->legacySSLMinorVersion; /* minor version */
        }

        /* Add Random number only for ServerHello */
        if (versionMask & VERSION_MASK_1)
        {
            if(pSSLSock->helloRetryRequest == 1)
            {
                DIGI_MEMCPY(pVarPart, serverHrrRandom, SSL_RANDOMSIZE);
            }
            else
            {
                (void) DIGI_MEMCPY(pVarPart,
                pSSLSock->pSecretAndRand + SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE,
                SSL_RANDOMSIZE);
            }
            pVarPart += SSL_RANDOMSIZE;
        }
    }
    else
#endif
    {
        *pVarPart++ = sslMinorVersion; /* minor version */
        (void) DIGI_MEMCPY(pVarPart,
                pSSLSock->pSecretAndRand + SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE,
                SSL_RANDOMSIZE);

        pVarPart += SSL_RANDOMSIZE;
    }

    if ((versionMask == VERSION_MASK_1) || versionMask == VERSION_MASK_3)
    {
#if defined(__ENABLE_DIGICERT_TLS13__)
        /* RFC 8446, section 4.1.3. legacy_session_id_echo
         * TLS 1.3, the session ID received in Client Hello should be echoed back in Server Hello
         */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__

        if (DTLS13_MINORVERSION == sslMinorVersion)
        {
            if (pSSLSock->isDTLS)
            {
                ubyte sessionIdEchoLen = pSSLSock->roleSpecificInfo.server.sessionIdEchoLen;
                *pVarPart++ = sessionIdEchoLen;
                DIGI_MEMCPY(pVarPart, pSSLSock->roleSpecificInfo.server.sessionIdEcho, sessionIdEchoLen);
                pVarPart += sessionIdEchoLen;
            }
        }
        else
#endif
        if (TLS13_MINORVERSION == sslMinorVersion)
        {
            ubyte sessionIdEchoLen = pSSLSock->roleSpecificInfo.server.sessionIdEchoLen;
            *pVarPart++ = sessionIdEchoLen;
            DIGI_MEMCPY(pVarPart, pSSLSock->roleSpecificInfo.server.sessionIdEcho, sessionIdEchoLen);
            pVarPart += sessionIdEchoLen;
        }
        else
#endif
        {
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
            if (E_SessionTicketResume == pSSLSock->sessionResume && 0 != pSSLSock->roleSpecificInfo.server.sessionIdEchoLen)
            {
                *pVarPart++ = pSSLSock->roleSpecificInfo.server.sessionIdEchoLen;
                DIGI_MEMCPY(pVarPart,
                            pSSLSock->roleSpecificInfo.server.sessionIdEcho,
                            pSSLSock->roleSpecificInfo.server.sessionIdEchoLen);
                pVarPart += pSSLSock->roleSpecificInfo.server.sessionIdEchoLen;
            }
            else
#endif
            {
                /* bottleneck : generate session id here if not resume session */
                if ( E_SessionIDResume != pSSLSock->sessionResume)
                {
                    if (OK > (status = RTOS_mutexWait(gSslSessionCacheMutex)))
                    {
                        goto exit;
                    }

                    /*increment gNextSessionId and make sure it is not zero */
                    ++gNextSessionId;
                    if ( 0 == gNextSessionId)
                    {
                        ++gNextSessionId;
                    }

                    pSSLSock->roleSpecificInfo.server.sessionId = gNextSessionId;
                    if (OK > (status = RTOS_mutexRelease(gSslSessionCacheMutex)))
                    {
                        goto exit;
                    }
                }

                *pVarPart++ = sizeof(SESSIONID); /* session id len */

                /* fill session id part */
                /* src and dst in DIGI_MEMCPY are always non-NULL, no return check needed */
                (void) DIGI_MEMCPY( pVarPart, (ubyte*) &pSSLSock->roleSpecificInfo.server.sessionId, sizeof(SESSIONID));
                pVarPart += sizeof(SESSIONID);
            }
        }
        *pVarPart++ = (ubyte)(pSSLSock->pHandshakeCipherSuite->cipherSuiteId >> 8); /* cipher suite byte 1 */
        *pVarPart++ = (ubyte)(pSSLSock->pHandshakeCipherSuite->cipherSuiteId); /* cipher suite byte 2 */
        *pVarPart++ = 0; /* compression */
    }

    if ((versionMask == VERSION_MASK_1) || versionMask == VERSION_MASK_3)
    {
        pExtensionsLength = pVarPart;
        pVarPart += 2;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((pSSLSock->isDTLS && DTLS13_MINORVERSION < sslMinorVersion) || (!pSSLSock->isDTLS && TLS13_MINORVERSION > sslMinorVersion))
#endif
    {
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        if (pSSLSock->isRehandshakeAllowed)
        {
            ubyte4  renegotiatedConnLength = 0;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            ubyte4  verifyDataSize = (SSL3_MINORVERSION == sslMinorVersion) ? SSL_VERIFY_DATA : TLS_VERIFYDATASIZE;
#else
            ubyte4   verifyDataSize = TLS_VERIFYDATASIZE;
#endif
            if (0 < pSSLSock->handshakeCount)
            {
                renegotiatedConnLength = (2 * verifyDataSize);
            }

            /* type(2) + extLen(2) + renegotiated_connection<0..255> */
            totalExtensionsLength += 2 + 2 + 1 + renegotiatedConnLength;

            /* write extension type */
            setShortValue(pVarPart, (ubyte2)tlsExt_renegotiated_connection);
            pVarPart += sizeof(ubyte2);

            /* write extension length */
            setShortValue(pVarPart, (ubyte2)(1 + renegotiatedConnLength));
            pVarPart += sizeof(ubyte2);

            /* write renegotiated_connection<0..255> length */
            *pVarPart = (ubyte) renegotiatedConnLength;
            pVarPart += 1;

            if (0 < renegotiatedConnLength)
            {
                /* write renegotiated_connection string */
                (void) DIGI_MEMCPY(pVarPart, pSSLSock->client_verify_data, verifyDataSize);
                (void) DIGI_MEMCPY(verifyDataSize + pVarPart, pSSLSock->server_verify_data, verifyDataSize);
                pVarPart += renegotiatedConnLength;
#ifdef __ENABLE_DIGICERT_TLS13__
                pSSLSock->sentExtensions[extCount++] = tlsExt_renegotiated_connection;
#endif
            }
        }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((SSL3_MINORVERSION < sslMinorVersion) && (VERSION_MASK_2 & versionMask))
#else
    if (SSL3_MINORVERSION < sslMinorVersion)
#endif
    {
        if (pSSLSock->serverNameIndication)
        {
            totalExtensionsLength += 4;

            setShortValue( pVarPart, tlsExt_server_name);/* type */
            pVarPart+=2;
            setShortValue( pVarPart, 0); /* size */
            pVarPart+=2;
            /* As per RFC 6066, Page 7, Last but one paragraph:
             * A server that receives a client hello containing the "server_name"  extension
             * MAY use the information contained in the extension to guide its selection
             * of an appropriate certificate to return to the client, and/or other aspects
             * of security policy.  In this event, the server SHALL include an extension of
             * type "server_name" in the (extended) server hello.  The "extension_data" field
             * of this extension SHALL be empty.
             */

#ifdef __ENABLE_DIGICERT_TLS13__
            pSSLSock->sentExtensions[extCount++] = tlsExt_server_name;
#endif

        }

        if (pSSLSock->selectedALPN)
        {
            ubyte protocolLen = *(pSSLSock->selectedALPN);

            totalExtensionsLength += 7 + protocolLen;
            setShortValue( pVarPart, tlsExt_applicationLayerProtocolNegotiation);/* type */
            pVarPart+=2;
            setShortValue( pVarPart, protocolLen + 3); /* size of extension */
            pVarPart+=2;
            setShortValue( pVarPart, protocolLen + 1); /* size of list */
            pVarPart+=2;
            (void) DIGI_MEMCPY(pVarPart, pSSLSock->selectedALPN, 1 + protocolLen); /* size + protocol */
            pVarPart+= 1 + protocolLen;
#ifdef __ENABLE_DIGICERT_TLS13__
            pSSLSock->sentExtensions[extCount++] = tlsExt_applicationLayerProtocolNegotiation;
#endif
        }

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
        if (pSSLSock->recvStatusReqExt && ((pSSLSock->isDTLS) || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion)))
        {
            totalExtensionsLength += 4;

            setShortValue( pVarPart, tlsExt_status_request);/* type */
            pVarPart+=2;
            setShortValue( pVarPart, 0); /* size */
            pVarPart+=2;
        }
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
        if(((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion)) &&
          (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock) || pSSLSock->roleSpecificInfo.server.keyExchangeMode == psk_dhe_ke))
        {
            if (OK > (status = constructTLSExtSupportedGroup(pSSLSock, &pVarPart, (ubyte2)pSSLSock->supportedGroupListLength, pSSLSock->supportedGroups)))
            {
                goto exit;
            }
            pSSLSock->sentExtensions[extCount++] = tlsExt_supportedGroups;
        }
#endif

#ifdef __ENABLE_DIGICERT_INNER_APP__
        if (pSSLSock->roleSpecificInfo.server.innerApp && pSSLSock->receivedInnerApp)
        {
            totalExtensionsLength += 6;

            setShortValue( pVarPart, tlsExt_innerApplication);/* type */
            pVarPart+=2;
            setShortValue( pVarPart, 2); /* size */
            pVarPart+=2;
            setShortValue( pVarPart, (ubyte2) pSSLSock->roleSpecificInfo.server.innerAppValue); /* Shoudl be Based upon Session Resumption Also */
            pVarPart+=2;
        }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        if ((TRUE == pSSLSock->roleSpecificInfo.server.sendSessionTicket) &&
            (pSSLSock->isDTLS || TLS12_MINORVERSION >= pSSLSock->sslMinorVersion))
        {
            setShortValue( pVarPart, tlsExt_ticket); /* type */
            pVarPart += 2;
            setShortValue( pVarPart, 0); /* size */
            pVarPart += 2;

            totalExtensionsLength += 4;
        }
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
        if ((TRUE == pSSLSock->receivedExtendedMasterSecret) &&
            ((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
            (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))))
        {
            /* write extension type */
            setShortValue(pVarPart, (ubyte2) tlsExt_extendedMasterSecret);
            pVarPart += sizeof(ubyte2);

            /* write extension length */
            setShortValue(pVarPart, 0);
            pVarPart += sizeof(ubyte2);
            totalExtensionsLength += 4;

            pSSLSock->useExtendedMasterSecret = TRUE;
        }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_SRTP__))
        if (pSSLSock->isDTLS && pSSLSock->useSrtp)
        {
            ubyte4 useSrtpExtLen;
            /* type(2) + extLen(2) + profileLen(2) + profile(2) + srtpMkiLen(1) + srtpMki */
            useSrtpExtLen = 2 + 2 + 2 + 2 + 1 + ((NULL != pSSLSock->srtpMki) ? *(pSSLSock->srtpMki) : 0);
            totalExtensionsLength += useSrtpExtLen;

            setShortValue( pVarPart, dtlsExt_use_srtp);/* type */
            pVarPart += 2;
            setShortValue( pVarPart, useSrtpExtLen - 2 - 2); /* size */
            pVarPart += 2;
            /* set profile size */
            setShortValue( pVarPart, 2); /* size */
            pVarPart += 2;
            /* set the server chosen srtp protection profile */
            setShortValue( pVarPart, pSSLSock->pHandshakeSrtpProfile->profileId);
            pVarPart += 2;
            if (NULL != pSSLSock->srtpMki)
            {
                (void) DIGI_MEMCPY(pVarPart, pSSLSock->srtpMki, 1 + *(pSSLSock->srtpMki));
                pVarPart += 1 + *(pSSLSock->srtpMki);
            }
            else
            {
                *pVarPart = 0;
                pVarPart += 1;
            }
#ifdef __ENABLE_DIGICERT_TLS13__
            pSSLSock->sentExtensions[extCount++] = dtlsExt_use_srtp;
#endif
        }
#endif

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
        if (1 == pSSLSock->earlyDataExtAccepted)
        {
            if (OK != SSL_SOCK_constructTLSExtEarlyData(pSSLSock, ((SSLHandshakeHeader*)pHSRec)->handshakeType, &pVarPart))
            {
                goto exit;
            }
            totalExtensionsLength += 4; /* extension type (2) +
                                           extension length (2) +
                                           Data length (0) */
            pSSLSock->sentExtensions[extCount++] = tlsExt_early_data;
        }
#endif
#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
            if (pSSLSock->sendHeartbeatMessage != noHeartbeatMessages)
            {
                /* write extension type */
                setShortValue(pVarPart, (ubyte2)tlsExt_heartbeat);
                pVarPart += sizeof(ubyte2);

                setShortValue(pVarPart, (ubyte2)1);
                pVarPart += sizeof(ubyte2);

                *pVarPart = pSSLSock->sendHeartbeatMessage;
                pVarPart++;

                totalExtensionsLength += 5;
            }
#endif
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if(versionMask != VERSION_MASK_2)
    {
        if(TLS13_MINORVERSION == sslMinorVersion)
        {
            if (OK > (status = SSL_SOCK_constructTLSExtSupportedVersions(pSSLSock, &pVarPart, versionMask)))
            {
                goto exit;
            }
            totalExtensionsLength += 6; /* extension type (2) +
                                       extension length (2) +
                                       supported_version (2)*/
            pSSLSock->sentExtensions[extCount++] = tlsExt_supported_versions;
        }
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        else if (DTLS13_MINORVERSION == sslMinorVersion)
        {
            if (OK > (status = SSL_SOCK_constructTLSExtSupportedVersions(pSSLSock, &pVarPart, versionMask)))
            {
                goto exit;
            }
            totalExtensionsLength += 6; /* extension type (2) +
                                       extension length (2) +
                                       supported_version (2)*/
            pSSLSock->sentExtensions[extCount++] = tlsExt_supported_versions;
        }
#endif
    }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        if(versionMask != VERSION_MASK_2)
        {
            if(pSSLSock->helloRetryRequest)
            {
                /* RFC 9147 Section 5
                    * DTLS reuses TLS 1.3's "cookie" extension to provide a return-routability
                    * check as part of connection establishment.
                    */
                if (sendCookie == TRUE)
                {
                    /* Extension name */
                    setShortValue(pVarPart, (ubyte2)tlsExt_cookie);
                    pVarPart += sizeof(ubyte2);

                    /* Total length */
                    setShortValue(pVarPart, (ubyte2)(SHA512_RESULT_SIZE + 1 + 2));
                    pVarPart += sizeof(ubyte2);

                    /* Cookie length */
                    setShortValue(pVarPart, (ubyte2)(SHA512_RESULT_SIZE + 1));
                    pVarPart += sizeof(ubyte2);

                    if (OK > (status = generateHelloCookie(MOC_AND(pSSLSock->peerDescr.peerAddr), (ubyte*)pSSLSock->pReceiveBuffer + sizeof(DTLSHandshakeHeader), 0, pVarPart, &cookieLen, pSSLSock->sslMinorVersion)))
                    {
                        goto exit;
                    }

                    pVarPart += cookieLen;

                    totalExtensionsLength += (SHA512_RESULT_SIZE + 1) + 6;
                    if ((SHA512_RESULT_SIZE + 1) != cookieLen)
                    {
                        goto exit;
                    }
                    pSSLSock->sentExtensions[extCount++] = tlsExt_cookie;
                }
                goto dtls_cookie_hello;
            }
        }
    }
#endif

    if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        if(versionMask != VERSION_MASK_2)
        {
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                if((pSSLSock->roleSpecificInfo.server.keyExchangeMode == psk_dhe_ke) || (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)))
#endif
                {
                    ubyte2 pointLen = 0;
                    if(OK > (status = constructTLSExtKeyShare(pSSLSock,&pVarPart,&pointLen)))
                    {
                        goto exit;
                    }
                    pSSLSock->sentExtensions[extCount++] = tlsExt_key_share;
                    if(pSSLSock->helloRetryRequest)
                    {
                        /* If Key Share sent from Client in Hello does not match, then the selected group is sent in
                         * keyshare entry
                         */
                        totalExtensionsLength += 6;
                    }
                    else
                    {
                        /* If it's not PSK then it will always send selected key_share entry */
#ifdef __ENABLE_DIGICERT_PQC__
                        if (HYBRID_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pSSLSock->roleSpecificInfo.server.selectedGroup))
                        {
                            /* On the server side, for KEM the ciphertext must
                             * be sent */
                            status = getNamedGroupCipherTextLen(
                                pSSLSock->roleSpecificInfo.server.selectedGroup,
                                &curveLength);
                            if (OK != status)
                            {
                                goto exit;
                            }
                        }
                        else
#endif /* __ENABLE_DIGICERT_PQC__ */
                        {
                            status = getNamedGroupLength(pSSLSock->roleSpecificInfo.server.selectedGroup, &curveLength);
                            if (OK != status)
                            {
                                goto exit;
                            }
                        }

                        totalExtensionsLength += 2 + (2*1) + 2 + 2 + curveLength;
                    }
                }
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                else if (pSSLSock->roleSpecificInfo.server.keyExchangeMode == psk_ke)
                {
                    /* If the server found a public key from the key share, free
                     * it. For psk_ke, the key share shouldn't be used to
                     * compute a shared secret.
                     */
                    DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.server.receivedPubKey);
                }
                /* RFC: 4.1.1: Cryptographic Negotiation: If the server selects a PSK,
                 * then it MUST also select a key establishment mode from the set indicated
                 * by the client's "psk_key_exchange_modes" extension (at present, PSK alone
                 * or with (EC)DHE).
                 */
                else
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                                    SSL_ALERT_NO_APPLICATION_PROTOCOL,
                                    SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    goto exit;
                }
#endif
                if((!pSSLSock->isDTLS) && (pSSLSock->helloRetryRequest))
                {
                    /* RFC: 4.2.2 Cookie
                     * When sending a HelloRetryRequest, the server MAY provide a "cookie"
                     * extension to the client (this is an exception to the usual rule that
                     * the only extensions that may be sent are those that appear in the
                     * ClientHello).
                     */
                    if (sendCookie == TRUE)
                    {
                        if (OK > (status = constructHelloRetryRequestCookie(pSSLSock, &pVarPart)))
                        {
                            goto exit;
                        }
                        totalExtensionsLength += pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize + 6;
                        pSSLSock->sentExtensions[extCount++] = tlsExt_cookie;
                    }
                }
            }
    }
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
    if((TLS13_MINORVERSION == sslMinorVersion || DTLS13_MINORVERSION == sslMinorVersion) && (versionMask & VERSION_MASK_1))
    {
        if(!pSSLSock->helloRetryRequest)
        {
            if (pSSLSock->roleSpecificInfo.server.pSelectedPSK != NULL)
            {
                /* RFC: 4.1.1.  Cryptographic Negotiation
                 * If PSK is being used, then the server will send a "pre_shared_key"
                 * extension indicating the selected key.
                 */
                if ((1 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)) &&
                    (1 == pSSLSock->isPSKSelected))
                {
                    setShortValue(pVarPart, tlsExt_pre_shared_key);
                    pVarPart += 2;
                    setShortValue(pVarPart,2); /* Size of extension*/
                    pVarPart += 2;

                    setShortValue(pVarPart,pSSLSock->roleSpecificInfo.server.selectedPskIdentityIndex); /*send Index 0*/
                    pVarPart += 2;
                    totalExtensionsLength += 6; /* extension type PSK identity index) +
                                               extension length (2) +
                                               PSK identity index (2) */
                    pSSLSock->sentExtensions[extCount++] = tlsExt_pre_shared_key;
                }
            }
        }
    }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
dtls_cookie_hello:
#endif
#endif /* __ENABLE_DIGICERT_TLS13__ */

    /* set total extensions length now */
    if (((versionMask == VERSION_MASK_1) || (versionMask == VERSION_MASK_3)) &&
        (0 != totalExtensionsLength))
    {
        setShortValue( pExtensionsLength, totalExtensionsLength);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static ubyte *
fillCertificate(SSLSocket* pSSLSock, ubyte* pHSRec)
{
    ubyte4 i;
    ubyte* pVarPart;
    ubyte2 hsSize;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        pVarPart = (ubyte *)(((DTLSHandshakeHeader*)pHSRec) + 1);
        hsSize = getMediumValue(((DTLSHandshakeHeader*)pHSRec)->handshakeSize);
    } 
    else
#endif
    {
        pVarPart = (ubyte *)(((SSLHandshakeHeader*)pHSRec) + 1);
        hsSize = getMediumValue(((SSLHandshakeHeader*)pHSRec)->handshakeSize);
    }
#if defined(__ENABLE_DIGICERT_TLS13__)
    /* Certificate request context is of length 0 for server */
    if (pSSLSock->sslMinorVersion == TLS13_MINORVERSION || pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
    {
        *pVarPart = 0;
        pVarPart++;

        setMediumValue(pVarPart, (ubyte2)(hsSize - (SSL_MEDIUMSIZE + 1 ))); /* 1 is length of certificate request context*/
        pVarPart += SSL_MEDIUMSIZE;
    }
    else
#endif
    {
        setMediumValue(pVarPart, (ubyte2)(hsSize - SSL_MEDIUMSIZE)); /* certificate chain length */
        pVarPart += SSL_MEDIUMSIZE;
    }

    /* for each certificate, store value in medium and then certificate     */
    for (i = 0; i < pSSLSock->roleSpecificInfo.server.numCertificates; ++i)
    {
        ubyte2 certLen = pSSLSock->roleSpecificInfo.server.certificates[i].length;

        setMediumValue(pVarPart, certLen);
        pVarPart += SSL_MEDIUMSIZE;

        (void) DIGI_MEMCPY(pVarPart,
                pSSLSock->roleSpecificInfo.server.certificates[i].data,
                certLen);

        pVarPart += certLen;

#if defined(__ENABLE_DIGICERT_TLS13__)
        if (pSSLSock->sslMinorVersion == TLS13_MINORVERSION || pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
        {
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
            /* Only handle OCSP request for the leaf certificate.
             */
            if (1 == pSSLSock->recvStatusReqExt && 0 == i)
            {
                ubyte2 extensionsLen = 2/* extension type */ + 2 /* extension length */ +
                                       1/* response type */ + SSL_MEDIUMSIZE/* response length */ +
                                       pSSLSock->ocspResponseLen;
                /* Extensions length */
                setShortValue(pVarPart, extensionsLen);
                pVarPart += 2;

                setShortValue(pVarPart, tlsExt_status_request);
                pVarPart += 2;

                setShortValue(pVarPart, extensionsLen - 4);
                pVarPart += 2;

                *pVarPart = certStatusType_ocsp;
                pVarPart++;

                setMediumValue(pVarPart, (ubyte2)pSSLSock->ocspResponseLen);
                pVarPart += SSL_MEDIUMSIZE;

                DIGI_MEMCPY(pVarPart, pSSLSock->pOcspResponse, pSSLSock->ocspResponseLen);
                pVarPart += pSSLSock->ocspResponseLen;

            }
            else
#endif
            {
                /* Extensions length is 0 */
                setShortValue(pVarPart, 0);
                pVarPart += 2;
            }
        }
#endif
    }

    return pVarPart;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__

static ubyte *
fillCertificateStatus(SSLSocket* pSSLSock, ubyte* pHSRec, ubyte* pOcspResponse, ubyte4 responseLen)
{
    ubyte* pVarPart;

    pVarPart = (ubyte *)(((SSLHandshakeHeader*)pHSRec) + 1);

    /* Fill in Certificate status */
    *pVarPart = 1; /* Certificate status type */
    pVarPart ++;

    setMediumValue(pVarPart, responseLen);
    pVarPart += SSL_MEDIUMSIZE;

    (void) DIGI_MEMCPY(pVarPart, pOcspResponse, responseLen);
    pVarPart += responseLen;

    return pVarPart;
}

#endif

/*------------------------------------------------------------------*/

#if ( defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) )
static MSTATUS
signServerKeyExchangeECC(SSLSocket* pSSLSock, ubyte* pData, ubyte4 dataLen,
                         ubyte4* pMsgSize)
{
    ubyte*          pHashResult = NULL;
    SHA1_CTX*       pShaContext = NULL;
    BulkCtx         pHashCtx = NULL;
    hashSuite       *pHashSuite = NULL;
    ubyte4          hashLen;
    ubyte*          pDest;
    ECCKey*         pECCKey;
    sbyte4          elementLen;
    ubyte*          pStorageBuffer = 0;
    ubyte*          pR;
    ubyte*          pS;
    DER_ITEMPTR     pSignature = 0;
    ubyte4          remainingBufferLen;
    MSTATUS         status;
    intBoolean      isTLSorDTLS12 = FALSE;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    ubyte*          pSignatureBuffer = 0;
    ubyte4          signatureBufferLength = 0;
    ubyte4          sigLength = 0;
#else
    PEllipticCurvePtr pCurve;
    PFEPtr          r = 0, s = 0;
    PrimeFieldPtr   pPF = 0;
#endif

    if ( akt_ecc != (pSSLSock->handshakeKey.type & 0xff))
        return ERR_BAD_KEY_TYPE;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        isTLSorDTLS12 = TRUE;
    }

    if (!isTLSorDTLS12)
    {
        hashLen = SHA1_RESULT_SIZE;
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext))))
            goto exit;

        DIGI_MEMSET((ubyte *)pShaContext, 0, sizeof(shaDescrHS));

        if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pData, dataLen)))
            goto exit;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pHashResult)))
            goto exit;
    }
    else
    {
        /* For TLS1.2, the hash algo comes from the sigAlgo ubyte2 before the signature */
        ubyte2  sigAlgo = pSSLSock->signatureAlgo;
        ubyte4 i;
        for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++)
        {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
            if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
            {
                if (gSupportedHashAlgorithms[i].hashType == ((sigAlgo >> 8) & 0xff))
                {
                    pHashSuite = &gSupportedHashAlgorithms[i];
                    break;
                }
            }
        }

        if (!pHashSuite)
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }

        hashLen = pHashSuite->algo->digestSize;

        if (OK > (status = pHashSuite->algo->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx )))
            goto exit;

        /* compute the hash of the data */
        if (OK > (status = pHashSuite->algo->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx)))
            goto exit;

        if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pData, dataLen)))
            goto exit;

        if (OK > (status = pHashSuite->algo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pHashResult )))
            goto exit;
    }

    if (*pMsgSize < dataLen)
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    /* for TLS1.2 and above, add sigalgo */
    if (isTLSorDTLS12)
    {
        setShortValue(pData + dataLen, pSSLSock->signatureAlgo);
    }

    pECCKey = pSSLSock->handshakeKey.key.pECC;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
        pECCKey, (ubyte4 *)&elementLen, pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }

    sigLength = elementLen * 2;
    pSignatureBuffer = (ubyte *)MALLOC(sigLength);
    if (NULL == pSignatureBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_ECDSA_signDigest(MOC_ECC(pSSLSock->hwAccelCookie) pECCKey, pSSLSock->rngFun,
                                                         pSSLSock->rngFunArg,
                                                         pHashResult, hashLen,
                                                         pSignatureBuffer, sigLength,
                                                         &signatureBufferLength,
                                                         pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }

    if (signatureBufferLength > sigLength)
    {
        status = ERR_SSL_INVALID_SIGNATURE;
        goto exit;
    }
#else
    pCurve = pECCKey->pCurve;
    pPF = EC_getUnderlyingField(pCurve);

    if ( OK > (status = PRIMEFIELD_getElementByteStringLen( pPF, &elementLen)))
        goto exit;

    /* store signature */
    if (OK > ( status = PRIMEFIELD_newElement( pPF, &r)))
        goto exit;

    if (OK > (status = PRIMEFIELD_newElement( pPF, &s)))
        goto exit;

    if (OK > ( status =  ECDSA_signDigestAux( pECCKey->pCurve, pECCKey->k, pSSLSock->rngFun,
                                        pSSLSock->rngFunArg, pHashResult, hashLen,
                                        r, s)))
    {
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    /* allocate buffer for the elements */
    /* add 2 more bytes for the possible zero padding */
    pStorageBuffer = (ubyte*) MALLOC( 2 + 2 * elementLen);
    if ( !pStorageBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* zero padding */
    pR = pStorageBuffer;
    *pR = 0x00; /* leading 0 */
    pS = pStorageBuffer + 1 + elementLen;
    *pS = 0x00; /* leading 0 */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = DIGI_MEMCPY(pR + 1, pSignatureBuffer, (signatureBufferLength / 2))))
    {
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pS + 1, pSignatureBuffer + (signatureBufferLength / 2),
                                  (signatureBufferLength / 2))))
    {
        goto exit;
    }
#else
    /* write R */
    /* write to buffer */
    if ( OK > (status = PRIMEFIELD_writeByteString( pPF, r, pR+1, elementLen)))
        goto exit;
    if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, s, pS+1, elementLen)))
        goto exit;
#endif

    /* create the ASN.1 sequence */
    if ( OK > ( status = DER_AddSequence(NULL, &pSignature)))
        goto exit;
    if ( OK > ( status = DER_AddInteger( pSignature, elementLen+1, pR, NULL)))
        goto exit;
    if ( OK > ( status = DER_AddInteger( pSignature, elementLen+1, pS, NULL)))
        goto exit;

    /* serialize to the destination buffer */
    /* TLS1.2 has a signatureAndHashAlgorithm ubyte2 before signature */
    pDest = pData + dataLen+ (isTLSorDTLS12? 2 : 0);
    remainingBufferLen = *pMsgSize - dataLen - 2 - (isTLSorDTLS12? 2 : 0);
    if (OK > ( status = DER_SerializeInto( pSignature, pDest + 2, &remainingBufferLen)))
        goto exit;

    /* set the short size before the signature */
    setShortValue( pDest, (ubyte2) remainingBufferLen);
    /* adjust size */
    *pMsgSize = dataLen + 2 + remainingBufferLen + (isTLSorDTLS12? 2 : 0);

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        if (pShaContext)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_freeCloneHashCtx(pShaContext);
#endif
            MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext));
        }
    } else
    {
        if (pHashCtx)
            pHashSuite->algo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (pSignatureBuffer)
    {
        FREE(pSignatureBuffer);
    }
#else
    PRIMEFIELD_deleteElement( pPF, &r);
    PRIMEFIELD_deleteElement( pPF, &s);
#endif

    if ( pSignature)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSignature);
    }

    if ( pStorageBuffer)
    {
        FREE(pStorageBuffer);
    }

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) */

/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
static MSTATUS
signServerKeyExchangeRSA( SSLSocket* pSSLSock, ubyte* pData, ubyte4 dataLen)
{
    ubyte*      pHashResult = NULL;
    ubyte4      hashLen = 0;
    sbyte4      lenRsaKey;
    RSAKey*     pRSAKey;
    ubyte*      pDest;
    vlong*      pVlongQueue = NULL;
    MSTATUS     status;
    intBoolean  isTLSorDTLS12 = FALSE;
    MD5_CTX*    pMd5Context = NULL;
    SHA1_CTX*   pShaContext = NULL;
#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    AsymmetricKey pubKey = {0};
#endif
    AsymmetricKey *pPubKey = NULL;
    ubyte4 verifyHashLen;
    ubyte *pHashCpy = NULL;
#endif
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    ubyte* pTapSignature = NULL;
#endif

    if ( akt_rsa != (pSSLSock->handshakeKey.type & 0xff))
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        isTLSorDTLS12 = TRUE;
    }

    if (isTLSorDTLS12)
    {
        if (OK > (status = calculateTLS12KeyExchangeRSASignature(pSSLSock, pData, dataLen,
                                                            pSSLSock->signatureAlgo, pHashResult,
                                                            &hashLen)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Context))))
            goto exit;

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext))))
            goto exit;

        DIGI_MEMSET((ubyte *)pMd5Context, 0, sizeof(MD5_CTXHS));
        DIGI_MEMSET((ubyte *)pShaContext, 0, sizeof(shaDescrHS));

        if (OK > (status = MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pData, dataLen)))
            goto exit;

        if (OK > (status = MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pHashResult)))
            goto exit;

        if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pData, dataLen)))
            goto exit;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pHashResult + MD5_DIGESTSIZE)))
            goto exit;

        hashLen = MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE;
    }

    pRSAKey = pSSLSock->handshakeKey.key.pRSA;

    /* store signature */
    /* TLS1.2 has a signatureAndHashAlgorithm ubyte2 before signature */
    pDest = pData + dataLen+ (isTLSorDTLS12? 2 : 0);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &lenRsaKey,
                                                               pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC ((void **)&pTapSignature, lenRsaKey, 1)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                                        pHashResult, hashLen, pTapSignature,
                                                        &pVlongQueue, pSSLSock->handshakeKey.type)))
	{
		goto exit;
	}

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
    /* invalid read/write if plaintext buffer smaller than signature length */
    status = DIGI_MALLOC_MEMCPY((void **)&pHashCpy, lenRsaKey, (void *)pHashResult, hashLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_getPublicKey((AsymmetricKey *)&pSSLSock->handshakeKey, &pubKey);
    if (OK != status)
        goto exit;
    pPubKey = &pubKey;

    status = CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(pSSLSock->hwAccelCookie) pPubKey->key.pRSA,
                                                  pTapSignature, pHashCpy, &verifyHashLen,
                                                  &pVlongQueue, pSSLSock->handshakeKey.type);
    if (OK != status)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validation failed.");
#endif
        goto exit;
    }

    if (hashLen != verifyHashLen) /* jic */
    {
        status = ERR_SSL_INVALID_SIGNATURE;
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validation failed.");
#endif
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validated.");
#endif
#endif /* __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__ */
    setShortValue(pDest, (ubyte2)lenRsaKey);
    if (OK > (status = DIGI_MEMCPY(pDest + 2, pTapSignature, lenRsaKey)))
    {
        goto exit;
    }

#else
    if (akt_rsa == pSSLSock->handshakeKey.type)
    {
        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &lenRsaKey)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_SSL_INVALID_KEY_TYPE;
        goto exit;
    }

    setShortValue(pDest, (ubyte2)lenRsaKey);
    status = RSA_signMessage(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                             pHashResult, hashLen,
                             2 + pDest, &pVlongQueue);

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
    /* invalid read/write if plaintext buffer smaller than signature length */
    status = DIGI_MALLOC_MEMCPY((void **)&pHashCpy, lenRsaKey, (void *)pHashResult, hashLen);
    if (OK != status)
        goto exit;

    status = RSA_verifySignature(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                                  2 + pDest, pHashCpy, &verifyHashLen,
                                                  &pVlongQueue);
    if (OK != status)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validation failed.");
#endif
        goto exit;
    }

    if (hashLen != verifyHashLen) /* jic */
    {
        status = ERR_SSL_INVALID_SIGNATURE;
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validation failed.");
#endif
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validated.");
#endif
#endif /* __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__ */
#endif

exit:

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
    if (NULL != pHashCpy)
    {
        DIGI_FREE((void **) &pHashCpy);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (akt_tap_rsa == pSSLSock->handshakeKey.type)
    {
        CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    }
#endif
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (pTapSignature)
    {
        DIGI_FREE((void **)&pTapSignature);
    }
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pMd5Context)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pMd5Context);
    }
    if (pShaContext)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pShaContext);
    }
#endif
    MEM_POOL_putPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Context));
    MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext));
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));
    VLONG_freeVlongQueue( &pVlongQueue);

    return status;
}
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
static MSTATUS
signServerKeyExchangeDSA( SSLSocket* pSSLSock, ubyte* pHSH, ubyte* pData, ubyte4 dataLen)
{
    ubyte*      pHashResult = NULL;
    ubyte4      hashLen = 0;
    sbyte4      lenDsaKey;
    DSAKey*     pDSAKey = NULL;
    ubyte*      pDest;
    vlong*      pVlongQueue = NULL;
    MSTATUS     status;
    intBoolean  isTLSorDTLS12 = FALSE;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    struct MDsaKeyTemplate dsaParameters = {0};
    ubyte*      pR = NULL;
    ubyte*      pS = NULL;
    ubyte4  rLen = 0, sLen = 0;
#else
    vlong*      pM              = NULL;
    vlong*  pR = NULL;
    vlong*  pS = NULL;
#endif
    ubyte	DsaRstr[2*SHA_HASH_BLOCK_SIZE] = {0};
    ubyte	DsaSstr[2*SHA_HASH_BLOCK_SIZE] = {0};
    ubyte	extraRByte=0;
    ubyte	extraSByte=0;
    sbyte4      qLen = 0;
    ubyte4  	msgSize;
    hashSuite  *pHashSuite = NULL;
    SHA1_CTX*   pShaContext = NULL;
	BulkCtx     pHashCtx = NULL;

    if ( akt_dsa != pSSLSock->handshakeKey.type)
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        isTLSorDTLS12 = TRUE;
    }
    if (isTLSorDTLS12)
    {
	ubyte2 signatureAlgo = pSSLSock->signatureAlgo;
	ubyte4      i;

	for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++) {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
        if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
        {
            if (gSupportedHashAlgorithms[i].hashType == ((signatureAlgo >> 8) & 0xff))
            {
                pHashSuite = &gSupportedHashAlgorithms[i];
                break;
            }
        }
	}

	if (!pHashSuite) {
	    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
	    goto exit;
	}

	hashLen = pHashSuite->algo->digestSize;
	if (OK > (status = pHashSuite->algo->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx )))
	    goto exit;

	/* compute the hash of the data */
	if (OK > (status = pHashSuite->algo->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx)))
	    goto exit;

	if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
	    goto exit;

	if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
	    goto exit;

	if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pData, dataLen)))
	    goto exit;

	if (OK > (status = pHashSuite->algo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pHashResult)))
	    goto exit;
    }
    /* No change in DSS signature encoding in TLS1.2 */
    else
    {
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext))))
            goto exit;

        DIGI_MEMSET((ubyte *)pShaContext, 0, sizeof(shaDescrHS));

        if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pData, dataLen)))
            goto exit;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pHashResult)))
            goto exit;

        hashLen = SHA_HASH_RESULT_SIZE;
    }

    pDSAKey = pSSLSock->handshakeKey.key.pDSA;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(MOC_DSA(pSSLSock->hwAccelCookie) pDSAKey, &dsaParameters, MOC_GET_PRIVATE_KEY_DATA)))
    {
        goto exit;
    }

    qLen = dsaParameters.qLen;
    if (qLen < (sbyte4) hashLen)
    {
        hashLen = (ubyte4) qLen;
    }

    if (OK > (status = CRYPTO_INTERFACE_DSA_computeSignatureAux(MOC_DSA(pSSLSock->hwAccelCookie) g_pRandomContext, pDSAKey, pHashResult, hashLen,
                                               NULL, &pR, &rLen, &pS, &sLen, &pVlongQueue)))
    {
        goto exit;
    }

    if ((pR != NULL) && (rLen != 0))
    {
        if (OK > (status = DIGI_MEMCPY(DsaRstr, pR, hashLen)))
        {
            goto exit;
        }
    }

    if ((pS != NULL) && (sLen != 0))
    {
        if (OK > (status = DIGI_MEMCPY(DsaSstr, pS, hashLen)))
        {
            goto exit;
        }
    }
#else
    qLen = (VLONG_bitLength(DSA_Q(pDSAKey)) + 7) / 8;

    if (qLen < hashLen)
        hashLen = qLen;

    if (OK > (status = VLONG_vlongFromByteString(pHashResult, hashLen, &pM, &pVlongQueue)))
        goto exit;
    if (OK > (status = DSA_computeSignature(MOC_DSA(pSSLSock->hwAccelCookie) g_pRandomContext, pDSAKey, pM, NULL, &pR, &pS,
					    &pVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_fixedByteStringFromVlong(pR, DsaRstr, hashLen)))
        goto exit;
    if (OK > (status = VLONG_fixedByteStringFromVlong(pS, DsaSstr, hashLen)))
        goto exit;
#endif
    lenDsaKey = 2/*SEQ_type+len*/ + 2*(2/*INT type+len*/) + 2*hashLen;
    if (DsaRstr[0] & 0x80) {extraRByte = 1; ++lenDsaKey;} /* insert a 0x0 as leading byte of int value */
    if (DsaSstr[0] & 0x80) {extraSByte = 1; ++lenDsaKey;} /* insert a 0x0 as leading byte of int value */
    /* store signature */
    pDest = pData + dataLen + (isTLSorDTLS12? 2 : 0);
    setShortValue(pDest, (ubyte2)lenDsaKey);
    pDest += 2; /* skip past TLS len field */
    /* insert DER encoded Dss-Sig-Value (RFC 2246, 4.7) */
    *pDest++ = 0x30; /* SEQUENCE */
    *pDest++ = lenDsaKey-2;
    *pDest++ = 0x2; /* ASN.1 INT */
    *pDest++ = hashLen + extraRByte;
    if (extraRByte) *pDest++ = 0x0;
    (void) DIGI_MEMCPY(pDest, DsaRstr, hashLen);
    pDest += hashLen;
    *pDest++ = 0x2; /* ASN.1 INT */
    *pDest++ = hashLen + extraSByte;
    if (extraSByte) *pDest++ = 0x0;
    (void) DIGI_MEMCPY(pDest, DsaSstr, hashLen);
    /* Reduce Handshake Hdr len by at most 2 if DER of R & S did not need leading 0 */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        msgSize = getMediumValue(((DTLSHandshakeHeader*)pHSH)->handshakeSize);
    } else
#endif
    {
        msgSize = getMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize);
    }
    msgSize -= (2-(extraRByte + extraSByte));
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
      {
	setMediumValue(((DTLSHandshakeHeader*)pHSH)->handshakeSize, (ubyte2) msgSize);
      } else
#endif
      {
	setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2) msgSize);
      }
exit:

    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));
    if (pShaContext)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_freeCloneHashCtx(pShaContext);
#endif
        MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext));
    }

    if (pHashCtx)
    {
        status = pHashSuite->algo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    DSA_freeKeyTemplate(pDSAKey, &dsaParameters);
    if (pR != NULL)
    {
        DIGI_FREE((void **) &pR);
    }

    if (pS != NULL)
    {
        DIGI_FREE((void **) &pS);
    }
#else
    if (pR != NULL)
    {
        VLONG_freeVlong(&pR, &pVlongQueue);
    }
    if (pS != NULL)
    {
        VLONG_freeVlong(&pS, &pVlongQueue);
    }
    if (pM != NULL)
    {
        VLONG_freeVlong(&pM, &pVlongQueue);
    }
#endif

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))
static MSTATUS
fillServerKeyExchange(SSLSocket* pSSLSock, ubyte* pHSH, ubyte *pPskHint, ubyte4 pskHintLength)
{
#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MDhKeyTemplate      template = {0};
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */  

    sbyte4              lenP;
    sbyte4              lenG;
    sbyte4              lenYs;
#endif
    ubyte*              p_storeData;
    ubyte*              pStartData;
    MSTATUS             status = OK;
#ifndef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
    MOC_UNUSED(pPskHint);
    MOC_UNUSED(pskHintLength);
#endif

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        pStartData = p_storeData = (ubyte *)(pHSH + sizeof(DTLSHandshakeHeader));
    } else
#endif
    {
        pStartData = p_storeData = (ubyte *)(pHSH + sizeof(SSLHandshakeHeader));
    }

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
    /* calc lengths */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(pSSLSock->hwAccelCookie) &template, pSSLSock->pDHcontext, MOC_GET_PUBLIC_KEY_DATA, NULL);
    if (OK != status)
        goto exit;

    lenP = template.pLen;
    lenG = template.gLen;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    lenYs = lenP;
#else
    lenYs = template.fLen;
#endif
#else
    lenP  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_p)) / 8;
    lenG  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_g)) / 8;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    lenYs = lenP;
#else
    lenYs = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_f)) / 8;
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
    /* store PSK hint */
   if ((SSL_PSK_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags))
    {
        /* store psk hint length */
        setShortValue(p_storeData, (ubyte2)pskHintLength);

        /* dup psk hint */
        (void) DIGI_MEMCPY(2 + p_storeData, pPskHint, pskHintLength);

        /* update position */
        p_storeData += 2 + pskHintLength;
    }
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
    /* make sure DH is the key exchange algorithm */
    if (0 == (SSL_KEYEX_DHE_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags))
        goto exit;

    /* store p */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    setShortValue(p_storeData, (ubyte2)lenP);

    status = DIGI_MEMCPY(2 + p_storeData, template.pP, lenP);
    if (OK != status)
        goto exit;

    p_storeData += 2 + lenP;

    setShortValue(p_storeData, (ubyte2)lenG);

    status = DIGI_MEMCPY(2 + p_storeData, template.pG, lenG);
    if (OK != status)
        goto exit;

    p_storeData += 2 + lenG;

    setShortValue(p_storeData, (ubyte2)lenYs);

#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    while (lenYs > template.fLen)
    {
        *(p_storeData + 2) = 0x00;
        p_storeData++;
        lenYs--;
    }
#endif

    status = DIGI_MEMCPY(2 + p_storeData, template.pF, lenYs);
    if (OK != status)
        goto exit;

    p_storeData += 2 + lenYs;
#else
    setShortValue(p_storeData, (ubyte2)lenP);

    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_p, 2 + p_storeData, lenP)))
        goto exit;

    p_storeData += 2 + lenP;

    /* store g */
    setShortValue(p_storeData, (ubyte2)lenG);

    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_g, 2 + p_storeData, lenG)))
        goto exit;

    p_storeData += 2 + lenG;

    /* store Ys */
    setShortValue(p_storeData, (ubyte2)lenYs);

    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_f, 2 + p_storeData, lenYs)))
        goto exit;

    p_storeData += 2 + lenYs;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
    if (SSL_DH_ANON == pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
        goto exit;
#endif

    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT)
    {
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
        if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            /* add signatureAndHashAlgorithm ubyte2 */
            setShortValue(p_storeData, (ubyte2)pSSLSock->signatureAlgo);
        }
        /* create data to be signed */
        /* pSecret = (0 == pSSLSock->advertisedMinorVersion) ? START_RANDOM(pSSLSock) : */
        if (OK > ( status = signServerKeyExchangeRSA( pSSLSock, pStartData, (ubyte4)(p_storeData - pStartData))))
        {
            goto exit;
        }
#else
        status = ERR_RSA_DISABLED;
#endif /* ((defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)) && (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))) */
    }

    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_DSA_BIT)
    {
#if ((defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)))
        if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            /* add signatureAndHashAlgorithm ubyte2 */
            setShortValue(p_storeData, (ubyte2)pSSLSock->signatureAlgo);
        }
        /* create data to be signed */
        /* pSecret = (0 == pSSLSock->advertisedMinorVersion) ? START_RANDOM(pSSLSock) : */
        if (OK > ( status = signServerKeyExchangeDSA( pSSLSock, pHSH, pStartData, (ubyte4)(p_storeData - pStartData))))
        {
            goto exit;
        }
#else
        status = ERR_SSL_INVALID_KEY_TYPE;
#endif /* ((defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)) && (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))) */
    }
#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */

exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pSSLSock->pDHcontext, &template, NULL);
#endif
    return status;

} /* fillServerKeyExchange */
#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (   defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
static MSTATUS
fillServerEcdheKeyExchange(SSLSocket* pSSLSock, ubyte* pHSH,
                           ubyte *pPskHint, ubyte4 pskHintLength)
{
    ubyte*  pMsg;
    sbyte4  ephemeralKeyLen;
    ECCKey* pECCKey;
    MSTATUS status;
    ubyte4  msgSize;
    ubyte4 curveId;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte4 keyType;
#endif

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        pMsg = (ubyte *)(pHSH + sizeof(DTLSHandshakeHeader));
        msgSize = getMediumValue(((DTLSHandshakeHeader*)pHSH)->handshakeSize);
    } else
#endif
    {
        pMsg = (ubyte *)(pHSH + sizeof(SSLHandshakeHeader));
        msgSize = getMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize);
    }

    if ( akt_ecc != pSSLSock->ecdheKey.type)
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
    /* store PSK hint */
    if ((SSL_PSK_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags))
    {
        /* store psk hint length */
        setShortValue(pMsg, (ubyte2)pskHintLength);

        /* dup psk hint */
        (void) DIGI_MEMCPY(2 + pMsg, pPskHint, pskHintLength);

        /* update position */
        pMsg += 2 + pskHintLength;
    }
#endif

    pECCKey = pSSLSock->ecdheKey.key.pECC;

    /* fill the message */
    pMsg[0] =  tlsECCurveType_named_curve;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    keyType = pSSLSock->ecdheKey.type;

    if (OK > (status = CRYPTO_INTERFACE_EC_getCurveIdFromKey(pECCKey, &curveId, keyType)))
    {
        goto exit;
    }
    setShortValue( pMsg+1, SSL_getNamedCurveOfCurveId(curveId));

    if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenEx(pECCKey, (ubyte4 *)&ephemeralKeyLen, keyType)))
        goto exit;

    /* write byte length */
    pMsg[3] = (ubyte) ephemeralKeyLen;

    if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBuffer(MOC_ECC(pSSLSock->hwAccelCookie) pECCKey, pMsg + 4, ephemeralKeyLen, keyType)))
        goto exit;

#else
    curveId = CRYPTO_getECCurveId(&pSSLSock->ecdheKey);
    setShortValue( pMsg+1, SSL_getNamedCurveOfCurveId(curveId));

    /* ECPoint */
    if (OK > ( status = EC_getPointByteStringLen( pECCKey->pCurve, &ephemeralKeyLen)))
        goto exit;
    /* write byte length */
    pMsg[3] = (ubyte) ephemeralKeyLen;
    /* write point (uncompressed format) */
    if ( OK > ( status = EC_writePointToBuffer( pECCKey->pCurve, pECCKey->Qx, pECCKey->Qy,
                                                pMsg + 4, ephemeralKeyLen)))
    {
        goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
    if (SSL_AUTH_ANON_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
         setShortValue(pMsg + 4 + ephemeralKeyLen, pSSLSock->signatureAlgo ); /* ubyte2 SignatureAndHashAlgorithm */
    }

    /* signature */
    switch ( pSSLSock->handshakeKey.type & 0xff)
    {
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
        case akt_rsa:
            if (OK > (status = signServerKeyExchangeRSA(pSSLSock, pMsg, 4 + ephemeralKeyLen)))
            {
                goto exit;
            }
            break;
#endif
        case akt_ecc:
            if (OK > (status = signServerKeyExchangeECC(pSSLSock, pMsg, 4 + ephemeralKeyLen, &msgSize)))
            {
                goto exit;
            }
            /* msgSize might have changed -- business with DER encoding of INTEGER --  */
            /* communicate it by setting the medium in the HandshakeHeader -- not very elegant... */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                setMediumValue(((DTLSHandshakeHeader*)pHSH)->handshakeSize, (ubyte2) msgSize);
            } else
#endif
            {
                setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2) msgSize);
            }
            break;

        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
            break;
    }
#endif

exit:

    return status;

} /* fillServerEcdheKeyExchange */
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))
static MSTATUS
fillServerPskKeyExchange(SSLSocket* pSSLSock, ubyte* pHSH, ubyte *pPskHint, ubyte4 pskHintLength)
{
    ubyte*              p_storeData;
    MSTATUS             status = OK;
    MOC_UNUSED(pSSLSock);

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        p_storeData = (ubyte *)(pHSH + sizeof(DTLSHandshakeHeader));
    } else
#endif
    {
        p_storeData = (ubyte *)(pHSH + sizeof(SSLHandshakeHeader));
    }

    /* store PSK hint */
    if ((0 < pskHintLength) && (NULL != pPskHint))
    {
        /* store psk hint length */
        setShortValue(p_storeData, (ubyte2)pskHintLength);

        /* dup psk hint */
        (void) DIGI_MEMCPY(2 + p_storeData, pPskHint, pskHintLength);
    }

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) */



/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SRP__))
static MSTATUS
fillServerSrpKeyExchange(SSLSocket* pSSLSock, ubyte* pHSH,
                         ubyte *salt, ubyte4 saltLength)
{
    const ubyte* g;
    const ubyte* N;
    const ubyte* k;
    sbyte4 NLen, gLen;
    ubyte* p_storeData;
    ubyte* pStartData;
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        pStartData = p_storeData = (ubyte *)(pHSH + sizeof(DTLSHandshakeHeader));
    } else
#endif
    {
        pStartData = p_storeData = (ubyte *)(pHSH + sizeof(SSLHandshakeHeader));
    }

    /* TO DO */
    if (OK > ( status = SRP_getGroupParameters2(pSSLSock->srpNumBits,
                                                &N, &NLen, &g, &gLen, &k)))
    {
        goto exit;
    }

    /* store N, g, salt, B */
    setShortValue(p_storeData, (ubyte2)NLen);
    (void) DIGI_MEMCPY(p_storeData + 2, N, NLen);
    p_storeData += 2 + NLen;

    /* store g */
    setShortValue(p_storeData, (ubyte2)gLen);
    (void) DIGI_MEMCPY(p_storeData + 2, g, gLen);
    p_storeData += 2 + gLen;

    /* store salt, length is only one byte */
    *p_storeData = (ubyte) saltLength;
    (void) DIGI_MEMCPY(p_storeData + 1, salt, saltLength);
    p_storeData += 1 + saltLength;

    /* store B */
    setShortValue(p_storeData, pSSLSock->roleSpecificInfo.server.srpBLen);
    (void) DIGI_MEMCPY(p_storeData + 2, pSSLSock->roleSpecificInfo.server.srpB,
               pSSLSock->roleSpecificInfo.server.srpBLen);
    p_storeData += 2 + pSSLSock->roleSpecificInfo.server.srpBLen;

    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT)
    {
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
        if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            /* add signatureAndHashAlgorithm ubyte2 */
            setShortValue(p_storeData, (ubyte2)pSSLSock->signatureAlgo);
        }
        if (OK > ( status = signServerKeyExchangeRSA( pSSLSock, pStartData,
                                                     (ubyte4)(p_storeData - pStartData))))
        {
            goto exit;
        }
#else
        status = status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }

exit:
    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_SSL_SRP__)) */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
#ifdef __ENABLE_DIGICERT_TLS13__
static MSTATUS
fillCertificateRequest3(SSLSocket* pSSLSock, ubyte* pHSH, ubyte4 extensionLen, ubyte4 distNameLen, ubyte isPostHandshakeAuth)
{
    ubyte     *p_storeData  = NULL;
    MSTATUS    status       = OK;
    ubyte4     i            = 0;

    ubyte2* pSupportedSignatureAlgoList = NULL;
    ubyte4  supportedSignatureAlgoListLength = 0;

    pSupportedSignatureAlgoList      = pSSLSock->pSupportedSignatureAlgoList;
    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        p_storeData = (ubyte *)(pHSH + sizeof(DTLSHandshakeHeader));
    } else
#endif
    {
        p_storeData = (ubyte *)(pHSH + sizeof(SSLHandshakeHeader));
    }

    if (1 == isPostHandshakeAuth)
	{
        *p_storeData = (ubyte)pSSLSock->certificateRequestContextLength;
        p_storeData++;
		/*
		 * When requesting post-handshake
		 * authentication, the server SHOULD make the context unpredictable
		 * to the client (e.g., by randomly generating it) in order to
		 * prevent an attacker who has temporary access to the client's
		 * private key from pre-computing valid CertificateVerify messages.
		 */
		if (OK != (status = DIGI_MEMCPY(p_storeData, pSSLSock->certificateRequestContext,
						pSSLSock->certificateRequestContextLength)))
		{
			goto exit;
		}
		p_storeData += pSSLSock->certificateRequestContextLength;
	}
    else
    {
        /* 
         * certificate_request_context field SHALL be zero length unless used
         * for the post-handshake authentication exchanges.
         */
        *p_storeData = 0;
        p_storeData++;
    }

    /* write the total extensions length */
    setShortValue(p_storeData, pSSLSock->certReqTotalExtensionsLength);
    p_storeData += sizeof(ubyte2);

    /* write extension type */
    setShortValue(p_storeData, (ubyte2)tlsExt_supportedSignatureAlgorithms);
    p_storeData += sizeof(ubyte2);

    /* write extension length */
    setShortValue(p_storeData, (ubyte2) (2 +  supportedSignatureAlgoListLength * 2));
    p_storeData += sizeof(ubyte2);

    /* write supportedSignatureAlgorithmListLength */
    setShortValue(p_storeData, (ubyte2)( supportedSignatureAlgoListLength * 2));
    p_storeData += sizeof(ubyte2);

    /* write extension specific data */
    for ( i = 0; i < supportedSignatureAlgoListLength; ++i)
    {
        setShortValue( p_storeData, pSupportedSignatureAlgoList[i]);
        p_storeData += sizeof(ubyte2);
    }

    if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
         (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
        (NULL != pSSLSock->pConfiguredSignatureCertAlgoList) )
    {
        setShortValue(p_storeData, (ubyte2) tlsExt_signatureAlgorithmCerts);
        p_storeData += sizeof(ubyte2);

        setShortValue(p_storeData, (ubyte2) (2 + pSSLSock->configuredSignatureCertAlgoListLength * 2));
        p_storeData += sizeof(ubyte2);

        setShortValue(p_storeData, (ubyte2) (pSSLSock->configuredSignatureCertAlgoListLength * 2));
        p_storeData += sizeof(ubyte2);

        for (i = 0; i < pSSLSock->configuredSignatureCertAlgoListLength; ++i)
        {
            setShortValue(p_storeData, pSSLSock->pConfiguredSignatureCertAlgoList[i]);
            p_storeData += sizeof(ubyte2);
        }
    }

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    /* Empty status_request extension */
    if (pSSLSock->certStatusReqExt)
    {
        /* write extension type */
        setShortValue(p_storeData, (ubyte2)tlsExt_status_request);
        p_storeData += sizeof(ubyte2);

        /* write extension length */
        setShortValue(p_storeData, (ubyte2)(pSSLSock->certStatusReqExtLen));
        p_storeData += sizeof(ubyte2);

        /* write extension specific data */
        DIGI_MEMCPY(p_storeData, pSSLSock->certStatusReqExtData, pSSLSock->certStatusReqExtLen);
        p_storeData += pSSLSock->certStatusReqExtLen;
    }
#endif

    if ((SSL_sslSettings()->pClientCANameList != NULL) && (distNameLen > 0))
    {
        status = constructTLSExtCertificateAuthorities(pSSLSock, &p_storeData, distNameLen);
    }
exit:
    return status;
}

extern MSTATUS
SSL_SERVER_sendPostHandshakeAuthCertificateRequest(SSLSocket* pSSLSock)
{
    ubyte4     length                = 0;
    ubyte4     extLength             = 0;
    ubyte*     pHSH                  = NULL;
    ubyte*     pSRH                  = NULL;
    ubyte4     sslFlags              = pSSLSock->runtimeFlags;
    ubyte4     sizeofRecordHeader    = 0;
    ubyte4     sizeofHandshakeHeader = 0;
    ubyte4     sizeofHandshakeRecord = 0;
    MSTATUS    status                = OK;
    ubyte4  supportedSignatureAlgoListLength = 0;
    ubyte4      distNameLen          = 0;

    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;

    if ((TLS13_MINORVERSION > pSSLSock->sslMinorVersion) ||
        (pSSLSock->postHandshakeAuth != 1) || /* If client supports post handshake auth, certificate request should be sent after the handshake */
        (pSSLSock->isPSKSelected))
    {
        status = ERR_SSL_BAD_STATE;
        goto exit;
    }

    if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
            (SSL_FLAG_NO_MUTUAL_AUTH_REQUEST != (sslFlags & SSL_FLAG_NO_MUTUAL_AUTH_REQUEST)) )
    {
        if ((0    == pSSLSock->certificateRequestContextLength) ||
            (NULL == pSSLSock->certificateRequestContext))
        {
            pSSLSock->certificateRequestContextLength = CERTIFICATE_REQ_CONTEXT_LEN; /* 32 */

            if (OK > (status = DIGI_MALLOC((void **)&pSSLSock->certificateRequestContext,
                                                    pSSLSock->certificateRequestContextLength)))
            {
                goto exit;
            }

            if (OK > (status = SSL_rngFun(pSSLSock->certificateRequestContextLength,
                                          pSSLSock->certificateRequestContext)))
            {
                goto exit;
            }
        }

        if (pSSLSock->buffers[0].pHeader != NULL)
        {
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->buffers[0].pHeader));
        }

        pSSLSock->buffers[0].pHeader = NULL;
        pSSLSock->buffers[0].data    = NULL;
        pSSLSock->buffers[0].length  = 0;
        pSSLSock->bufIndex   = 0;
        pSSLSock->numBuffers = 1;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
#ifdef __ENABLE_DIGICERT_TLS13__
            if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                sizeofRecordHeader = DTLS13_MOC_RECORD_HEADER_LEN;
                sizeofHandshakeRecord = sizeof(DTLSHandshakeHeader) + DTLS13_MOC_RECORD_HEADER_LEN;
            }
            else
#endif
            {
                sizeofRecordHeader = sizeof(DTLSRecordHeader);
                sizeofHandshakeRecord = sizeof(DTLSHandshakeRecord);
            }
            sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        }
        else
#endif
        {
            sizeofRecordHeader = sizeof(SSLRecordHeader);
            sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
            sizeofHandshakeRecord = sizeof(SSLHandshakeRecord);
        }

        length = 1 + pSSLSock->certificateRequestContextLength;/* length + certificate_request_context */

        length += 2; /* Extensions length */
        /* Assuming only signature_algorithms extension is sent */
        extLength += 2 + 2 + 2; /* Extension type + length + num of supports algorithms*/
        extLength += supportedSignatureAlgoListLength * 2;

        if (NULL != pSSLSock->pConfiguredSignatureCertAlgoList)
        {
            length += 2;
            extLength += 2 + 2 + 2 + pSSLSock->configuredSignatureCertAlgoListLength * 2;
        }
        
        if (SSL_sslSettings()->pClientCANameList != NULL)
        {
            ubyte4 i = 0;
            extLength += 6; /* Extension name and extension length */
            for (i = 0; i < SSL_sslSettings()->numClientCANames; i++)
            {
                 distNameLen += 2 /* to store length */ + SSL_sslSettings()->pClientCANameList[i].length;
            }
        }
        extLength += distNameLen;

        pSSLSock->certReqTotalExtensionsLength = extLength;
        length += extLength;

        pSSLSock->buffers[0].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + length);

        if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, pSSLSock->buffers[0].length,
                                        TRUE, (void **)&(pSSLSock->buffers[0].pHeader))))
        {
            goto exit;
        }

        pSSLSock->buffers[0].data = pSSLSock->buffers[0].pHeader + sizeofRecordHeader;

        pSSLSock->isMutualAuthNegotiated = TRUE;

        pSRH = pSSLSock->buffers[0].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
            DTLS_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->sslMinorVersion, pSSLSock->ownSeqnumHigh, pSSLSock->ownSeqnum, pSSLSock->buffers[0].length - sizeofRecordHeader);

            /* When DTLS 1.3 is implemented, the post handshake message may
             * overflow the sequence number. TLS 1.3 section 5.3 specifies the
             * connection may be terminated or a key update may be sent. Will
             * not handle until DTLS 1.3 is implemented
             */
            if (0 == (++pSSLSock->ownSeqnum))
                pSSLSock->ownSeqnumHigh = (pSSLSock->ownSeqnumHigh & 0xffff0000) | ((pSSLSock->ownSeqnumHigh + 1) & 0xffff);

            pHSH = pSSLSock->buffers[0].data;
            DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pHSH),
                    pSSLSock->nextSendSeq++,
                    (ubyte2)(pSSLSock->buffers[0].length - sizeofHandshakeRecord));

            setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize,
                    (ubyte2)(pSSLSock->buffers[0].length - sizeofHandshakeRecord));

            ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE_REQUEST;
        }
        else
#endif
        {
            SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->sslMinorVersion,
                    pSSLSock->buffers[0].length - sizeofRecordHeader);

            pHSH = pSSLSock->buffers[0].data;

            setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize,
                    (ubyte2)(pSSLSock->buffers[0].length - sizeofHandshakeRecord));
            ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE_REQUEST;
        }

        if (OK > (status = fillCertificateRequest3(pSSLSock, pHSH, length, distNameLen, 1/* Post Handhsake Certificate Request */)))
        {
            goto exit;
        }

        addToHandshakeHash(pSSLSock, pSSLSock->buffers[0].data, (pSSLSock->buffers[0].length - sizeofRecordHeader));
        status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock);
        if (OK > status)
        {
            goto exit;
        }

        pSSLSock->postHandshakeMessages |= (1 << CERTIFICATE_REQUEST);
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_TLS13__ */

static MSTATUS
fillCertificateRequest(SSLSocket* pSSLSock, ubyte* pHSH, ubyte4 distNameLen)
{
    ubyte*  p_storeData;
    MSTATUS status = OK;
    ubyte2* pSupportedSignatureAlgoList = NULL;
    ubyte4  supportedSignatureAlgoListLength = 0;
    ubyte   clientCertTypes = NUM_CLIENT_CERT_TYPES;

    pSupportedSignatureAlgoList      = pSSLSock->pSupportedSignatureAlgoList;
    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        p_storeData = (ubyte *)(pHSH + sizeof(DTLSHandshakeHeader));
    } 
    else
#endif
    {
        p_storeData = (ubyte *)(pHSH + sizeof(SSLHandshakeHeader));
    }

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    if (FALSE == SSL_sslSettings()->allowDSASigAlg)
    {
        clientCertTypes--;
    }
#endif

    *p_storeData++ = clientCertTypes;      /* number of client certificate types accepted */
#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__))
    if (TRUE == SSL_sslSettings()->allowDSASigAlg)
    {
        *p_storeData++ = tlsClientCertType_dsa_sign;
    }
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__))
    *p_storeData++ = tlsClientCertType_rsa_sign;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    *p_storeData++ = tlsClientCertType_ecdsa_sign;
    *p_storeData++ = tlsClientCertType_rsa_fixed_ecdh;
    *p_storeData++ = tlsClientCertType_ecdsa_fixed_ecdh;
#endif

    /* TLS1.2 introduced a supported signature algorithms field */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        ubyte4 i;

        setShortValue(p_storeData, supportedSignatureAlgoListLength * 2);

        p_storeData += 2;
        for ( i = 0; i < supportedSignatureAlgoListLength; ++i)
        {
            setShortValue( p_storeData, pSupportedSignatureAlgoList[i]);
            p_storeData += sizeof(ubyte2);
        }
    }

    /* number of certificate authorities */
    if (SSL_sslSettings()->pClientCANameList != NULL)
    {
        ubyte4 i = 0;
        setShortValue(p_storeData, distNameLen);
        p_storeData += sizeof(ubyte2);

        for (i = 0; i < SSL_sslSettings()->numClientCANames; i++)
        {
            ubyte4 length = SSL_sslSettings()->pClientCANameList[i].length;
            setShortValue(p_storeData, length);
            p_storeData += sizeof(ubyte2);

            DIGI_MEMCPY(p_storeData, SSL_sslSettings()->pClientCANameList[i].data, length);
            p_storeData += length;
        }
    }
    else
    {
        *p_storeData++ = 0x00;
        *p_storeData++ = 0x00;
    }

    return status;

} /* fillCertificateRequest */
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */


/*------------------------------------------------------------------*/

/*******************************************************************************
*      SSL_SERVER_sendServerHello
* send serverhello if sessionResume = E_SessionIDResume or sessionResume = E_SessionEAPFASTResume
* send serverhello, newsessionticket if sessionResume = E_SessionTicketResume and we renew session tickets
* send serverhello, certificate and serverhellodone if sessionResume = E_NoSessionResume
*/
static MSTATUS
SSL_SERVER_sendServerHello(SSLSocket* pSSLSock)
{
    intBoolean          isRehandshake = (pSSLSock->pActiveOwnCipherSuite) ? TRUE : FALSE;
    intBoolean          sendCookie = FALSE;

#if (defined(__ENABLE_DIGICERT_SSL_SRP__) || \
    defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) ||  \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
    ubyte               pskHint[SSL_PSK_SERVER_IDENTITY_LENGTH];
    ubyte4              pskHintLength = 0;
#endif
#ifdef __ENABLE_DIGICERT_SSL_SRP__
    const ubyte* srpN = NULL;
    const ubyte* srpg = NULL;
    sbyte4 srpNLen = 0, srpgLen = 0;
#endif
    ubyte4              i;
    sbyte4              bufIndex     = 0;
    sbyte4              numBufs      = 0;
    ubyte4              totalLen     = 0;
    ubyte4              fragmentLen  = 0;
    ubyte*              pHSH;
    ubyte*              pSRH;
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    ubyte4              sslFlags     = pSSLSock->runtimeFlags;
    ubyte4              distNameLen  = 0;
#endif
    ubyte4              numBytesSent = 0;
    intBoolean          isServerKeyExchangePresent = FALSE;
    ubyte4              totalExtensionsLength = 0;
    ubyte4              sizeofRecordHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    ubyte4              sizeofCipherRecordHeader;
    ubyte4              sizeofCipherHandshakeRecord;
#endif
    ubyte4              sizeofHandshakeHeader;
    ubyte4              sizeofHandshakeRecord;
    MSTATUS             status       = OK;
    intBoolean          isTLSorDTLS12 = FALSE;
#if defined (__ENABLE_DIGICERT_OCSP_CLIENT__)
    ubyte*              pOcspResponse = NULL;
    ubyte4              responseLen   = 0;
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    ubyte4              certificateReqExtLen = 0;
#endif /*  __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
    ubyte4              curveLength;
    ubyte               tls13ExtensionsLength = 0;
    ubyte2              certificateLength = 0;
#endif
    ubyte               sslMinorVersion = pSSLSock->sslMinorVersion;
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    ubyte4  supportedSignatureAlgoListLength = 0;
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    intBoolean          isValid = FALSE;
    ubyte4              privKeyLen;
#endif

    pSSLSock->buffers[0].pHeader = NULL;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;
#endif /*  __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        sizeofCipherRecordHeader = (DTLS13_MINORVERSION == sslMinorVersion) ? DTLS13_MOC_RECORD_HEADER_LEN : sizeof(DTLSRecordHeader); /* 1 byte, sequence 2 bytes, length 2 bytes */
        sizeofRecordHeader = sizeof(DTLSRecordHeader);
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        sizeofHandshakeRecord = sizeof(DTLSHandshakeRecord);
        sizeofCipherHandshakeRecord = sizeofCipherRecordHeader + sizeofHandshakeHeader;
    }
    else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        sizeofHandshakeRecord = sizeof(SSLHandshakeRecord);
    }

    if ((pSSLSock->isDTLS && (sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && sslMinorVersion >= TLS12_MINORVERSION))
    {
        isTLSorDTLS12 = TRUE;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    /* For TLS 1.3, Cipher Suite is set after processing Client Hello;
     * So, the isRehandshake is set to true. There is no rehandshake
     * in TLS 1.3; Hence setting this flag to FALSE explicitly
     */
    if (TLS13_MINORVERSION == sslMinorVersion || DTLS13_MINORVERSION == sslMinorVersion)
    {
        isRehandshake = FALSE;
    }
#endif

    if ((pSSLSock->isDTLS) || (TLS13_MINORVERSION > sslMinorVersion))
    {
#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
        if (SSL_PSK_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
        {
            if (NULL != SSL_sslSettings()->funcPtrGetHintPSK)
            {
                if (OK > (status = (MSTATUS)(SSL_sslSettings()->funcPtrGetHintPSK(SSL_findConnectionInstance(pSSLSock), pskHint, &pskHintLength))))
                    goto exit;
            }
        }
#endif

#ifdef __ENABLE_DIGICERT_SSL_SRP__
        if (SSL_SRP_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
        {
            /* salt will be in pskHint, others are longer lived and will be in the pSSLSock */
            if (OK > ( status = SSL_SOCK_getSRPParametersForIdentity( pSSLSock,
                                                                     pskHint, &pskHintLength,
                                                                     &srpN, &srpNLen,
                                                                     &srpg, &srpgLen)))
            {
                goto exit;
            }
        }
#endif
    }

    /* generate server random */
    /*
     * if selectedVersion == TLS13; no change
     *                    == TLS12; last 8 bytes = 44 4f 57 4e 47 52 44 01
     *                    == TLS11; last 8 bytes = 44 4f 57 4e 47 52 44 00 --- This applies to TLS 12 servers as well.
     */
    pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_RANDOMSIZE,
                        pSSLSock->pSecretAndRand + SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE);

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (TLS13_MINORVERSION == SSL_sslSettings()->sslMaxProtoVersion)
    {
        if (TLS12_MINORVERSION == pSSLSock->sslMinorVersion)
        {
             /* Over-write the last 8 bytes with tls12Random */
             (void) DIGI_MEMCPY(pSSLSock->pSecretAndRand + (SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE + SSL_RANDOMSIZE - 8), serverTls12Random, 8);
        }
        else if (TLS11_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            /* Over-write the last 8 bytes with tls11Random */
            (void) DIGI_MEMCPY(pSSLSock->pSecretAndRand + (SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE + SSL_RANDOMSIZE - 8), serverTls11Random, 8);
        }
    }
#endif

    if (OK > (status = DIGI_MEMCPY(pSSLSock->pServerRandHello, pSSLSock->pSecretAndRand + SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE, SSL_RANDOMSIZE)))
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)

    /* Hello Retry Request message in case of TLS 1.3 or DTLS 1.3 */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (DTLS13_MINORVERSION == sslMinorVersion)
    {
        if(pSSLSock->helloRetryRequest)
        {
            /* supported_version (extension type + length + version number) */
            totalExtensionsLength += 2 + 2 + 2;

            sendCookie = TRUE;

            /* Cookie: ext_type(2) + ext_len(2) + cookie_len(2) + Cookie (1 byte version + SHA256) */
            totalExtensionsLength += 2 + 2 + 2 + (SHA512_RESULT_SIZE + 1);

            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + /* Record layer header */
                                                         sizeofHandshakeHeader + /* Handshake header */
                                                         2 + /* legacy version */
                                                         SSL_RANDOMSIZE + /* random */
                                                         1 + /* legacy sesion ID length */
                                                         pSSLSock->roleSpecificInfo.server.sessionIdEchoLen + /* legacy session ID */
                                                         2 + /* cipher suite */
                                                         1 + /* legacy compression method */
                                                         2 + /* extension length */
                                                         totalExtensionsLength /* extensions */);

            if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, pSSLSock->buffers[0].length, TRUE,
                                            (void **)&(pSSLSock->buffers[bufIndex].pHeader))))
            {
                goto exit;
            }

            pSRH = pSSLSock->buffers[bufIndex].pHeader;

            DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

            pSSLSock->buffers[bufIndex].data = pSSLSock->buffers[bufIndex].pHeader + sizeofRecordHeader;
            pHSH = pSSLSock->buffers[bufIndex].data;


            DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
            setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize,  (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));


            ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_SERVER_HELLO;

            if (OK > (status = fillServerHello(pSSLSock, pHSH, VERSION_MASK_1, sendCookie)))
            {
                goto exit;
            }

            addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));

            totalLen = pSSLSock->buffers[bufIndex].length;
            bufIndex++;
            numBufs++;
            goto send_server_hello;
        }
    }
    else
#endif
    if (TLS13_MINORVERSION == sslMinorVersion)
    {
        /* Supported version + KeyShare*/
        if(pSSLSock->helloRetryRequest)
        {
            /* supported_version (extension type + length + version number) */
            totalExtensionsLength += 2 + 2 + 2;

            /* Key Share : ext_type(2) + ext_len(2) + keyShareGroupName(2) */
            totalExtensionsLength += 2 + 2 + 2 ;

            sendCookie = TRUE;

            /* Cookie: ext_type(2) + ext_len(2) + cookie_len(2) + Cookie (digestSize) */
            totalExtensionsLength += 2 + 2 + 2 + pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize;

            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + /* Record layer header */
                                                         sizeofHandshakeHeader + /* Handshake header */
                                                         2 + /* legacy version */
                                                         SSL_RANDOMSIZE + /* random */
                                                         1 + /* legacy sesion ID length */
                                                         pSSLSock->roleSpecificInfo.server.sessionIdEchoLen + /* legacy session ID */
                                                         2 + /* cipher suite */
                                                         1 + /* legacy compression method */
                                                         2 + /* extension length */
                                                         totalExtensionsLength /* extensions */);

            if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, pSSLSock->buffers[0].length, TRUE,
                                            (void **)&(pSSLSock->buffers[bufIndex].pHeader))))
            {
                goto exit;
            }

            pSRH = pSSLSock->buffers[bufIndex].pHeader;
            SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->legacySSLMinorVersion,
                                  pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

            pSSLSock->buffers[bufIndex].data = pSSLSock->buffers[bufIndex].pHeader + sizeofRecordHeader;
            pHSH = pSSLSock->buffers[bufIndex].data;
            setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize,
                           (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
            ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_SERVER_HELLO;

            if (OK > (status = fillServerHello(pSSLSock, pHSH, VERSION_MASK_1, sendCookie)))
            {
                goto exit;
            }

            addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));

            totalLen = pSSLSock->buffers[bufIndex].length;
            bufIndex++;
            numBufs++;
            goto send_server_hello;
        }
    }
    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
    {
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        if (pSSLSock->isRehandshakeAllowed)
        {
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            ubyte4  verifyDataSize = (0 == sslMinorVersion) ? SSL_VERIFY_DATA : TLS_VERIFYDATASIZE;
#else
            ubyte4  verifyDataSize = TLS_VERIFYDATASIZE;
#endif

            /* extension type + extension length + renegotiated_connection length */
            totalExtensionsLength += (2 + 2 + 1);

            if (0 < pSSLSock->handshakeCount)
            {
                /* on rehandshakes, use verify data string from the previous handshake */
                totalExtensionsLength += (2 * verifyDataSize);
            }
        }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        if (SSL3_MINORVERSION < sslMinorVersion)
#endif
        {
            if (pSSLSock->serverNameIndication )
            {
                /* send a "server_name" with empty data response back;
                 the check for matching cert name was done earlier
                 when the certificate was selected in SSL_SOCK_setServerCert */
                totalExtensionsLength += 4;
            }

            if (pSSLSock->selectedALPN)
            {
                /* send a 'application_layer_protocol_negotiation'
                 with one protocol back total length =
                 type(2)+length(2) + alpn list length(2) + protocol length (1) +
                 protocol (n) */
                totalExtensionsLength += 7 + *(pSSLSock->selectedALPN);
            }

#ifdef __ENABLE_DIGICERT_INNER_APP__
            if (pSSLSock->roleSpecificInfo.server.innerApp && pSSLSock->receivedInnerApp)
            {
                totalExtensionsLength += 6;
            }
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
            if ((TRUE == pSSLSock->receivedExtendedMasterSecret) &&
                ((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
                (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))))
            {
                totalExtensionsLength += 4;/* extension type (2) + extension length(2) */
            }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
            if (TRUE == pSSLSock->roleSpecificInfo.server.sendSessionTicket)
            {
                /* type(2) + extLen(2) */
                totalExtensionsLength += 2 + 2;
            }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_SRTP__))
            if (pSSLSock->isDTLS && pSSLSock->useSrtp)
            {
                /* type(2) + extLen(2) + profileLen(2) + profile(2) + srtpMkiLen(1) + srtpMki */
                totalExtensionsLength += 2 + 2 + 2 + 2 + 1 + ((NULL != pSSLSock->srtpMki) ? *(pSSLSock->srtpMki) : 0);
            }
#endif
        }
    }

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
    if (pSSLSock->recvStatusReqExt)
    {
        /* Only attempt to get an OCSP response if a server certificate was
         * selected, otherwise send an empty OCSP response.
         */
        if (NULL != pSSLSock->roleSpecificInfo.server.certificates)
        {
            if (OK > (status =  SSL_OCSP_getOcspResponse(
                pSSLSock, pSSLSock->roleSpecificInfo.server.certificates,
                pSSLSock->roleSpecificInfo.server.numCertificates, gpOcspStore,
                &pOcspResponse, &responseLen)))
            {
                /* Send empty response if an error occurred */
                status = OK;
            }
        }

        /* Check for the response length */
        if ((0 < responseLen) && (NULL != pOcspResponse))
        {
            /* we have an ocsp response to send back */
#if defined(__ENABLE_DIGICERT_TLS13__)
            if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                certificateLength += 2/* extension type */ + 2 /* extension length */ +
                                     1/* response type */ + SSL_MEDIUMSIZE/* response length */ + responseLen;
                pSSLSock->pOcspResponse = pOcspResponse;
                pSSLSock->ocspResponseLen = responseLen;
            }
            else
#endif
            {
                totalExtensionsLength += 4;
            }
        }
        else
        {
            pSSLSock->recvStatusReqExt = FALSE;
        }
    }
#endif
#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
    if (((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) || (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)) &&
        (pSSLSock->sendHeartbeatMessage != noHeartbeatMessages))
    {
        totalExtensionsLength += 4; /* extension type (2) + extension length (2) */
        totalExtensionsLength += 1; /* HeartbeatMode is only 1 byte */
    }
#endif

    if (totalExtensionsLength || (TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||  (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        totalExtensionsLength += 2; /* For size of extensions */
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
    {
        /* supported_version (extension type+ length + version number)*/
        totalExtensionsLength += 2 + 2 + 2;

        /* pre_shared_key */
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
        if ((pSSLSock->roleSpecificInfo.server.pSelectedPSK != NULL) && (1 == pSSLSock->isPSKSelected) &&
            (1 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)))
        {
            /* extension_type(2) + extension_length(2) + selected identity(2) */
            totalExtensionsLength += 2 + 2 + 2;

#if defined( __ENABLE_DIGICERT_TLS13_0RTT__)
            if (1 == pSSLSock->earlyDataExtAccepted)
            {
                /* extension_type(2) + extension len(2)*/
                tls13ExtensionsLength += 4;
            }
#endif /*  __ENABLE_DIGICERT_TLS13_0RTT__ */
        }
#endif /*  __ENABLE_DIGICERT_TLS13_PSK__ */

        /* Supported groups extension */
        /* extension type  (2) + extension length (2) + size of curve list (2) */
        if (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock) || pSSLSock->roleSpecificInfo.server.keyExchangeMode == psk_dhe_ke)
        {
            tls13ExtensionsLength += 6;
            tls13ExtensionsLength += pSSLSock->supportedGroupListLength * 2;
        }

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
        if (pSSLSock->sendHeartbeatMessage != noHeartbeatMessages)
        {
            tls13ExtensionsLength += 4; /* extension type (2) + extension length (2) */
            tls13ExtensionsLength += 1; /* HeartbeatMode is only 1 byte */
        }
#endif

        /* If sending PSK, psk_key_exchange_mode extensions is required */
#ifdef __ENABLE_DIGICERT_PQC__
        if (HYBRID_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pSSLSock->roleSpecificInfo.server.selectedGroup))
        {
            /* On the server side, for KEM the ciphertext must
                * be sent */
            status = getNamedGroupCipherTextLen(
                pSSLSock->roleSpecificInfo.server.selectedGroup,
                &curveLength);
            if (OK != status)
            {
                goto exit;
            }
        }
        else
#endif /* __ENABLE_DIGICERT_PQC__ */
        {
            status = getNamedGroupLength(pSSLSock->roleSpecificInfo.server.selectedGroup, &curveLength);
            if (OK != status)
            {
                goto exit;
            }
        }

        if (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock) || pSSLSock->roleSpecificInfo.server.keyExchangeMode == psk_dhe_ke)
        {
            /* key_share type (2) + length (2) + group (2) + key length (2) */
            totalExtensionsLength += 2 + 2 + 2 + 2 + curveLength;
        }
   }
#endif /*  __ENABLE_DIGICERT_TLS13__ */


    /* For TLS13 (Non PSK): EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify */
    pSSLSock->buffers[1].length = pSSLSock->buffers[2].length = pSSLSock->buffers[3].length = pSSLSock->buffers[4].length = 0;

    /* compute the size of all three, four or five handshakes messages */
    /* SSL and TLS p.80 */
    /* server hello */

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((DTLS13_MINORVERSION == sslMinorVersion) || (TLS13_MINORVERSION == sslMinorVersion))
    {
        if (!pSSLSock->isPSKSelected)
        {
            pSSLSock->buffers[5].length = 0;
        }
        /* RFC 8446, section 4.1.3. legacy_session_id_echo
         * TLS 1.3, the session ID received in Client Hello should be echoed back in Server Hello
         */
        pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 2 +
                                             SSL_RANDOMSIZE + 1 + pSSLSock->roleSpecificInfo.server.sessionIdEchoLen +
                                             2 + 1 + totalExtensionsLength);
    }
    else
#endif
    {
        pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 2 +
                                             SSL_RANDOMSIZE + 1 + 2 + 1 + totalExtensionsLength);
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        if (E_SessionTicketResume == pSSLSock->sessionResume && 0 != pSSLSock->roleSpecificInfo.server.sessionIdEchoLen)
        {
            pSSLSock->buffers[bufIndex].length += pSSLSock->roleSpecificInfo.server.sessionIdEchoLen;
        }
        else
#endif
        {
            pSSLSock->buffers[bufIndex].length += sizeof(SESSIONID);
        }
    }
    bufIndex++;
    numBufs++;

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (((DTLS13_MINORVERSION == sslMinorVersion) || (TLS13_MINORVERSION == sslMinorVersion)))
    {
        /* Fill in the length of EncryptedExtensions Message; This message should
         * follow immediately after the ServerHello
         */
        if(pSSLSock->serverNameIndication)
        {
            /* As per RFC 6066, Page no 7, last but one paragraph.
             * Server responds with an empty SNI extension
             */
            tls13ExtensionsLength += 2 + 2;
        }

        if (pSSLSock->selectedALPN)
        {
            /* total length = type(2) + length(2) +
             *                alpn list length(2) +
             *                protocol length (1) +
             *                protocol (n)
             */
            tls13ExtensionsLength += 7 + *(pSSLSock->selectedALPN);
        }

        /* unified_hdr is used instead of DTLSRecordHeader when negotiating DTLS 1.3 */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofCipherRecordHeader + sizeofHandshakeHeader + 2 + tls13ExtensionsLength );
        }
        else
#endif
        {
            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 2 + tls13ExtensionsLength );
        }
        pSSLSock->tls13EncryptedExtensionsLength = tls13ExtensionsLength;

        bufIndex++;
        numBufs++;
    }

    /* RFC 4.3.2.  Certificate Request: For TLS13 CertificateRequest should follow EncryptedExtension */
#if defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if (((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion)) &&
        /*(pSSLSock->postHandshakeAuth != 1) && */ /* If client supports post handshake auth, certificate request should be sent after the handshake */
        ((!pSSLSock->isPSKSelected) ||
         (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock))))
    {
        if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
                (SSL_FLAG_NO_MUTUAL_AUTH_REQUEST != (sslFlags & SSL_FLAG_NO_MUTUAL_AUTH_REQUEST)) )
        {
            ubyte4 length = 0;

            length += 1; /* length (0 CR context ) */
            length += 2; /* Extensions length */

            /* Signature Algorithms */
            certificateReqExtLen = 2 + 2 + 2; /* Extension type + length + num of supports algorithms*/
            certificateReqExtLen += supportedSignatureAlgoListLength * 2;

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
            /* Empty status_request extension */
            if (pSSLSock->certStatusReqExt)
            {
                certificateReqExtLen += 2 + 2; /* extension type + extension length */
                certificateReqExtLen += pSSLSock->certStatusReqExtLen;
            }
#endif
            if (SSL_sslSettings()->pClientCANameList != NULL)
            {
                certificateReqExtLen += 6; /* Extension name and extension length */
                for (i = 0; i < SSL_sslSettings()->numClientCANames; i++)
                {
                     distNameLen += 2 /* to store length */ + SSL_sslSettings()->pClientCANameList[i].length;
                }
            }

            certificateReqExtLen += distNameLen;
            length += certificateReqExtLen;
            pSSLSock->certReqTotalExtensionsLength = certificateReqExtLen;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofCipherRecordHeader + sizeofHandshakeHeader + length);
            }
            else
#endif
            {
                pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + length);
            }
            bufIndex++;
            numBufs++;
        }
    }
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */

    if (E_NoSessionResume == pSSLSock->sessionResume)
    {
        /* SSL and TLS p.81 */
        if (0 == (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_ANON_BIT))
        {
#if defined(__ENABLE_DIGICERT_TLS13__)
            if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
            {
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                if(pSSLSock->isPSKSelected && (1 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)))
                {
                    pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader );
                }
                else
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
                {
                    /* certificate - Header + Certificate Request Context (1) + Certificate-list length(3) + Certificate Length (3)*/
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                    if (pSSLSock->isDTLS)
                    {
                        pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofCipherHandshakeRecord + 1 + SSL_MEDIUMSIZE +
                                (SSL_MEDIUMSIZE * pSSLSock->roleSpecificInfo.server.numCertificates));
                    }
                    else
#endif
                    {
                        pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofHandshakeRecord + 1 + SSL_MEDIUMSIZE +
                                (SSL_MEDIUMSIZE * pSSLSock->roleSpecificInfo.server.numCertificates));
                    }
                }
            }
            else
#endif /* __ENABLE_DIGICERT_TLS13__ */
            {
                /* Server Hello Done */
                pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader +
                        SSL_MEDIUMSIZE * (1 + pSSLSock->roleSpecificInfo.server.numCertificates));
            }

            /* now add length of certificates themselves */
#ifdef __ENABLE_DIGICERT_TLS13__
            if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
            {
                ubyte4 numCertificates = pSSLSock->roleSpecificInfo.server.numCertificates;

#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                if(!pSSLSock->isPSKSelected || (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)))
#endif
                {
                    for (i = 0; i < numCertificates; ++i)
                    {
                        if ((NULL != pSSLSock->roleSpecificInfo.server.certificates) &&
                            (NULL != pSSLSock->roleSpecificInfo.server.certificates[i].data))
                        {
                            certificateLength += pSSLSock->roleSpecificInfo.server.certificates[i].length + 2; /* Extensions length for each of the certificate */
                        }
                    }

                    pSSLSock->buffers[bufIndex].length += certificateLength;
                    bufIndex++;
                    numBufs++;
                }
            }
            else
#endif
            {
                for (i = 0; i < pSSLSock->roleSpecificInfo.server.numCertificates; ++i)
                {
                    if ((NULL != pSSLSock->roleSpecificInfo.server.certificates) &&
                        (NULL != pSSLSock->roleSpecificInfo.server.certificates[i].data))
                    {
                        pSSLSock->buffers[bufIndex].length = (ubyte2)(pSSLSock->buffers[bufIndex].length +
                                                              pSSLSock->roleSpecificInfo.server.certificates[i].length);
                    }
                }
                bufIndex++;
                numBufs++;
            }
        }

/* CertificateVerify message should be sent along with Certificate for TLS 1.3 */
#if defined(__ENABLE_DIGICERT_TLS13__)
        if (((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion)) &&
            ((!pSSLSock->isPSKSelected) || 
            (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock))))
        {
            sbyte4 lenSignature = 0;

                switch ( pSSLSock->handshakeKey.type & 0xFF)
            {
            case akt_rsa:
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)) && !(defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__))
                status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux( MOC_RSA(pSSLSock->hwAccelCookie)
                    pSSLSock->handshakeKey.key.pRSA, &lenSignature);
                if (OK != status)
                    goto exit;
#else
                lenSignature = ((7 + VLONG_bitLength(RSA_N(pSSLSock->handshakeKey.key.pRSA))) / 8);
#endif
                break;

#ifdef __ENABLE_DIGICERT_ECC__
            case akt_ecc_ed:
            case akt_ecc:
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                if (OK > (status = SSL_SOCK_getECCSignatureLength(pSSLSock->handshakeKey.key.pECC,
                                                                  &lenSignature,
                                                                  pSSLSock->handshakeKey.type)))
                {
                    goto exit;
                }
#else
                /* enough space for a SEQUENCE of 2 integers */
                if (OK > ( status = SSL_SOCK_getECCSignatureLength( pSSLSock->handshakeKey.key.pECC,
                                                                (sbyte4*) &lenSignature)))
                {
                    goto exit;
                }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
                break;
#ifdef __ENABLE_DIGICERT_PQC__
            case akt_hybrid:
                if (OK > (status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(pSSLSock->hwAccelCookie) 
                                                                          &pSSLSock->handshakeKey, TRUE, &lenSignature)))
                {
                    goto exit;
                }
                break;

            case akt_qs:
                if (OK > (status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pSSLSock->handshakeKey.pQsCtx, &lenSignature)))
                {
                    goto exit;
                }
                break;
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

            default:
                status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofCipherHandshakeRecord + 2 + lenSignature);
            }
            else
#endif
            {
                pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofHandshakeRecord + 2 + lenSignature);
            }

            if ( (pSSLSock->isDTLS && (sslMinorVersion <= DTLS12_MINORVERSION)) ||
                 (!pSSLSock->isDTLS && sslMinorVersion >= TLS12_MINORVERSION)  )
            {
                pSSLSock->buffers[bufIndex].length += 2;
            }
            bufIndex++;
            numBufs++;
        }
#endif /* __ENABLE_DIGICERT_TLS13__ */

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    if (((pSSLSock->isDTLS && (DTLS13_MINORVERSION < sslMinorVersion)) || (!(pSSLSock->isDTLS) && (TLS13_MINORVERSION > sslMinorVersion)))
        && (pSSLSock->recvStatusReqExt))
    {
        /* Add certificate status right after certificate if response is acquired */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofCipherRecordHeader + sizeofHandshakeHeader + 1 + SSL_MEDIUMSIZE + responseLen);
        }
        else
#endif
        {
            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 1 + SSL_MEDIUMSIZE + responseLen);
        }
        bufIndex ++;
        numBufs++;
    }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((pSSLSock->isDTLS && (DTLS13_MINORVERSION < sslMinorVersion)) || (!(pSSLSock->isDTLS) && (TLS13_MINORVERSION > sslMinorVersion)))
#endif
        {
#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
            /* for PSK ciphers, we need to send a ServerKeyExchange if there's a hint or
             the algo requires a ServerKeyExchange message: DHE or ECDHE */
            if ((pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_PSK_BIT) &&
                (pskHintLength > 0 ||
                 (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_DHE_BIT) ||
                 (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDHE_BIT) ))
            {
                pSSLSock->buffers[bufIndex].length = (ubyte2)(pSSLSock->buffers[bufIndex].length + 2 + pskHintLength);
                isServerKeyExchangePresent = TRUE;
            }
#endif

#ifdef __ENABLE_DIGICERT_SSL_SRP__
            if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_SRP_BIT)
            {
                sbyte4  signatureLen = 0;

                isServerKeyExchangePresent = TRUE;
                /* signature ? */
                if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT)
                {
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
                    AsymmetricKey* pPrivateKey;

                    pPrivateKey = &pSSLSock->handshakeKey;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pPrivateKey->key.pRSA,
                                                                                &signatureLen,
                                                                                pSSLSock->handshakeKey.type)))
                    {
                        goto exit;
                    }
#else
                    if ( akt_rsa != pPrivateKey->type)
                    {
                        status = ERR_SSL_INVALID_KEY_TYPE;
                        goto exit;
                    }

                    if (OK > (status = RSA_getCipherTextLength( MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA,
                                                            &signatureLen)))
                    {
                        goto exit;
                    }
#endif

                    signatureLen += 2;

                    if (isTLSorDTLS12)
                    {
                        signatureLen += 2; /* ubyte2 SignatureAndHashAlgorithm */
                    }
#else
                    status = ERR_RSA_DISABLED;
                    goto exit;
#endif
                }
                /* length of the server key exchange is 2 + N Length + 2 + g Length + 1 + s length + 2 + B len */
                pSSLSock->buffers[bufIndex].length = (ubyte2)(pSSLSock->buffers[bufIndex].length +
                                                              7 + srpNLen + srpgLen + pskHintLength +
                                                              pSSLSock->roleSpecificInfo.server.srpBLen +
                                                              signatureLen);
            }
#endif
#if (((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) || (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__))) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)))
            if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_DHE_BIT)
            {
                sbyte4  lenP;
                sbyte4  lenG;
                sbyte4  lenYs;
                sbyte4  signatureLen = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                MDhKeyTemplate template = {0};
#else
                vlong *pP = NULL;
                vlong *pG = NULL;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

                /* server key exchange for DHE support */
                isServerKeyExchangePresent = TRUE;

                if (NULL != pSSLSock->pDHcontext)
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
                    if (OK != status)
                        goto exit;
#else
                    if (OK > (status = DH_freeDhContext(&pSSLSock->pDHcontext, NULL)))
                        goto exit;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
                }

                if ((pSSLSock->pDHP != NULL) && (pSSLSock->pDHG != NULL))
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    if (OK > (status = DIGI_MALLOC((void **)&template.pP, pSSLSock->pLen)))
                        goto exit;
                    if (OK > (status = DIGI_MEMCPY(template.pP, pSSLSock->pDHP, pSSLSock->pLen)))
                        goto exit;
                    template.pLen = pSSLSock->pLen;

                    if (OK > (status = DIGI_MALLOC((void **)&template.pG, pSSLSock->gLen)))
                        goto exit;
                    if (OK > (status = DIGI_MEMCPY(template.pG, pSSLSock->pDHG, pSSLSock->gLen)))
                        goto exit;
                    template.gLen = pSSLSock->gLen; 


                    /* Allocate DH context memory */
                    status = CRYPTO_INTERFACE_DH_allocateExt(&(pSSLSock->pDHcontext), NULL);
                    if (OK != status)
                        goto exit;

                    /* Set P and G to context */
                    status = CRYPTO_INTERFACE_DH_setKeyParametersExt(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, &template, NULL);
                    if (OK != status)
                        goto exit;

                    status = CRYPTO_INTERFACE_DH_verifySafePG(pSSLSock->pDHcontext, &isValid, &privKeyLen, NULL);
                    if (OK != status)
                        goto exit;

                    if (FALSE == isValid)
                    {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_DIGICERT_STRICT_DH_GROUP__))
                        status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
                        goto exit;
#else
                        if (0 == pSSLSock->pLen)
                        {
                            privKeyLen = SSL_DH_CUSTOM_GROUP_PRI_LEN;
                        }
                        else
                        {
                            privKeyLen = pSSLSock->pLen;
                        }
#endif
                    }

                    /* Generate key pair for context */
                    status = CRYPTO_INTERFACE_DH_generateKeyPairExt(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, g_pRandomContext, privKeyLen, NULL);
                    if (OK != status)
                        goto exit;

                    /* pP and pG are no longer needed */
                    status = CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pSSLSock->pDHcontext, &template, NULL);
                    if (OK != status)
                    {
                        goto exit;
                    }

#else
                    if (OK > (status = DH_allocate(&pSSLSock->pDHcontext)))
                    {
                        goto exit;
                    }

                    if (OK > (status = VLONG_vlongFromByteString(pSSLSock->pDHP, pSSLSock->pLen, &pP, NULL)))
                        goto cleanup;

                    if (OK > (status = VLONG_vlongFromByteString(pSSLSock->pDHG, pSSLSock->gLen, &pG, NULL)))
                        goto cleanup;

                    status = DH_setPG(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->rngFunArg,
                                             pSSLSock->pLen,
                                             pSSLSock->pDHcontext,
                                             pP,
                                             pG);

                cleanup:
                    VLONG_freeVlong(&pP, 0);
                    VLONG_freeVlong(&pG, 0);

                    if (OK != status)
                        goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
                }
                else
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_DH_allocateServerExt(MOC_DH(pSSLSock->hwAccelCookie) g_pRandomContext,
                                                                   &(pSSLSock->pDHcontext), SSL_DEFAULT_DH_GROUP, NULL);
                    if (OK != status)
                        goto exit;
#else
                    if (OK > (status = DH_allocateServer(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->rngFunArg,
                                                         &(pSSLSock->pDHcontext),
                                                         SSL_DEFAULT_DH_GROUP)))
                    {
                        goto exit;
                    }
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
                }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(pSSLSock->hwAccelCookie) &template, pSSLSock->pDHcontext, MOC_GET_PUBLIC_KEY_DATA, NULL);
                if (OK != status)
                    goto exit;


                lenP = template.pLen;
                lenG = template.gLen;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
                lenYs = template.pLen;
#else
                lenYs = template.fLen;
#endif

                status = CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pSSLSock->pDHcontext, &template, NULL);
                if (OK != status)
                    goto exit;
#else
                lenP  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_p)) / 8;
                lenG  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_g)) / 8;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
                lenYs = lenP;
#else
                lenYs = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_f)) / 8;
#endif
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#if defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
            if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_DSA_BIT)
            {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                struct MDsaKeyTemplate dsaParameters = {0};
#endif
                AsymmetricKey* pPrivateKey;
		ubyte4		dsaSigLen;
                pPrivateKey = &pSSLSock->handshakeKey;
                if ( akt_dsa != pPrivateKey->type)
                {
                    status = ERR_SSL_INVALID_KEY_TYPE;
                    goto exit;
                }
                
                if (FALSE == SSL_sslSettings()->allowDSASigAlg)
                {
                    status = ERR_SSL_INVALID_KEY_TYPE;
                    goto exit;
                }

		if (isTLSorDTLS12) {
		    ubyte2 signatureAlgo = pSSLSock->signatureAlgo;
		    ubyte4 i;
		    hashSuite  *pHashSuite = NULL;
		    for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++) {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
            if (isHashAlgoSupported((gSupportedSignatureAlgorithms[i] >> 8) & 0xFF))
#endif
            {
                if (gSupportedHashAlgorithms[i].hashType == ((signatureAlgo >> 8) & 0xff))
                    {
                    pHashSuite = &gSupportedHashAlgorithms[i];
                    break;
                    }
                }
		    }

		    if (!pHashSuite) {
			status = ERR_SSL_UNSUPPORTED_ALGORITHM;
			goto exit;
		    }
		}
		/* Overestimate size by 2 assuming DER INT encoding will add leading 0 byte
		 * adj to correct sz after fillServerKeyExchange is called later in this func
		 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(pPrivateKey->key.pDSA, &dsaParameters, MOC_GET_PUBLIC_KEY_DATA)))
        {
            goto exit;
        }
        dsaSigLen = dsaParameters.qLen;
#else
        dsaSigLen = (7 + VLONG_bitLength(DSA_Q(pPrivateKey->key.pDSA))) / 8;
#endif
		signatureLen = 2+2*(2+1)+2*dsaSigLen; /* DER encoding Sec. 4.7 RFC5246*/
                signatureLen += 2; /* 2-byte length field preceding signature bytes */

                if (isTLSorDTLS12)
                {
                    signatureLen += 2; /* ubyte2 SignatureAndHashAlgorithm */
                }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                DSA_freeKeyTemplate(pPrivateKey->key.pDSA, &dsaParameters);
#endif
            }
#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
            if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT)
            {
                AsymmetricKey* pPrivateKey;

                pPrivateKey = &pSSLSock->handshakeKey;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA,
                                                                               &signatureLen,
                                                                               pPrivateKey->type)))
                    {
                        goto exit;
                    }
#else
                    if (akt_rsa == pPrivateKey->type)
                    {
                        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA, &signatureLen)))
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        status = ERR_SSL_INVALID_KEY_TYPE;
                        goto exit;
                    }
#endif

                    signatureLen += 2;

                    if (isTLSorDTLS12)
                    {
                        signatureLen += 2; /* ubyte2 SignatureAndHashAlgorithm */
                    }
                }
#endif /* ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */
#endif /* __ENABLE_DIGICERT_SSL_DHE_SUPPORT__ */
                pSSLSock->buffers[bufIndex].length = (ubyte2)(pSSLSock->buffers[bufIndex].length +
                                                              (6 + lenP + lenG + lenYs + signatureLen));
            }
#endif

#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)  || \
         defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
            if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDHE_BIT)
            {
                ubyte4 msgLen;
                sbyte4 tmpLen;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                PEllipticCurvePtr pCurve = 0;
#endif
                ECCKey *pECCKey;
                enum tlsExtNamedCurves chosenCurve = (enum tlsExtNamedCurves) 0;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                ubyte4 curveId;
#endif

                /* server key exchange for DHE support */
                isServerKeyExchangePresent = TRUE;

                /* allocate the key using the information in clientECCurves */
                if (SSL_sslSettings()->funcPtrChooseECCCurve)
                {
                    ubyte4 listLength = 0;
                    enum tlsExtNamedCurves possibleCurves[NUM_ECC_PCURVES];

                    for (i = 0; i < pSSLSock->supportedGroupListLength; ++i)
                    {
                        if ( ( 1 << (pSSLSock->pSupportedGroupList[i])) &
                            (pSSLSock->roleSpecificInfo.server.clientECCurves))
                        {
                            possibleCurves[listLength++] = (enum tlsExtNamedCurves) pSSLSock->pSupportedGroupList[i];
                        }
                    }

                    if (OK > (status = (MSTATUS)
                              (SSL_sslSettings()->funcPtrChooseECCCurve(
                                            SSL_findConnectionInstance(pSSLSock),
                                            pSSLSock->pHandshakeCipherSuite->cipherSuiteId,
                                            possibleCurves, listLength,
                                            &chosenCurve))))
                    {
                        goto exit;
                    }
                }
                else
                {
                    for (i = 0; i < pSSLSock->supportedGroupListLength; ++i)
                    {
                        if ( ( 1 << (pSSLSock->pSupportedGroupList[i])) &
                                (pSSLSock->roleSpecificInfo.server.clientECCurves))
                        {
                            chosenCurve = (enum tlsExtNamedCurves) pSSLSock->pSupportedGroupList[i];
                            break;
                        }
                    }
                }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                curveId = SSL_SOCK_getCurveIdFromName(chosenCurve);
                if (curveId == 0)
                {
                    status = ERR_SSL_UNSUPPORTED_CURVE;
                    goto exit;
                }
#else
                pCurve = SSL_SOCK_getCurveFromName(chosenCurve);
                if ( !pCurve)
                {
                    status = ERR_SSL_UNSUPPORTED_CURVE;
                    goto exit;
                }
#endif

                /* generate it */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                /* Note a global keyType is passed. This can be set by the user.
                 * This will be moved to the SSL_settings
                 */
                if (OK > (status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(pSSLSock->hwAccelCookie) curveId, (void **)&pECCKey,
                                                                            pSSLSock->rngFun, pSSLSock->rngFunArg,
                                                                            g_keyType, NULL)))
                {
                    goto exit;
                }

                if (pECCKey == NULL)
                {
                    status = ERR_NULL_POINTER;
                    goto exit;
                }

                /* Clear the existing key */
                CRYPTO_uninitAsymmetricKey(&pSSLSock->ecdheKey, NULL);

                /* Set the keyType */
                pSSLSock->ecdheKey.type = g_keyType;
                pSSLSock->ecdheKey.key.pECC = pECCKey;
#else
                /* allocate the key here */
                if (OK > (status = CRYPTO_createECCKey( &pSSLSock->ecdheKey, pCurve)))
                    goto exit;

                pECCKey =  pSSLSock->ecdheKey.key.pECC;

                if ( OK > ( status = EC_generateKeyPair( pCurve, pSSLSock->rngFun, pSSLSock->rngFunArg,
                                                        pECCKey->k, pECCKey->Qx, pECCKey->Qy)))
                {
                    goto exit;
                }
#endif
                msgLen = 4; /* named curve type (1) + named curve (2) + point length (1) */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenEx(pECCKey, (ubyte4 *)&tmpLen, g_keyType)))
                {
                    goto exit;
                }
#else
                if (OK > ( status = EC_getPointByteStringLen( pCurve, &tmpLen)))
                {
                    goto exit;
                }
#endif

                msgLen += (ubyte4) tmpLen;

#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)
                if ( pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & (SSL_AUTH_RSA_BIT | SSL_AUTH_ECDSA_BIT))
                {
                    /* add signature length */
                    switch (pSSLSock->handshakeKey.type & 0xFF)
                    {
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                        case akt_rsa:
                            if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA,
                                                                                       &tmpLen,
                                                                                       pSSLSock->handshakeKey.type)))
                            {
                                goto exit;
                            }
                            break;
#else
                        case akt_rsa:
                            if (OK > (status = RSA_getCipherTextLength( MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA,
                                                                        &tmpLen)))
                            {
                                goto exit;
                            }
                            break;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                        case akt_ecc:
                            /* the ECDSA signature is more complex -- needs its own function */
                            if ( OK > ( status = SSL_SOCK_getECCSignatureLength( pSSLSock->handshakeKey.key.pECC,
                                                                                 &tmpLen, pSSLSock->handshakeKey.type)))
                            {
                                goto exit;
                            }
                            msgLen += (ubyte4) (tmpLen + 2);
                            break;
#else
                        case akt_ecc:
                            /* the ECDSA signature is more complex -- needs its own function */
                            if ( OK > ( status = SSL_SOCK_getECCSignatureLength( pSSLSock->handshakeKey.key.pECC,
                                                                                 &tmpLen)))
                            {
                                goto exit;
                            }
                            msgLen += (ubyte4) (tmpLen + 2);
                            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
                        case akt_hybrid:
                            if (OK > (status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(pSSLSock->hwAccelCookie) 
                                                                                      &pSSLSock->handshakeKey, TRUE, &tmpLen)))
                            {
                                goto exit;
                            }
                            break;
                            
                        case akt_qs:
                            if (OK > (status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pSSLSock->handshakeKey.pQsCtx, &tmpLen)))
                            {
                                goto exit;
                            }
                            break;
#endif
                        default:
                            status = ERR_BAD_KEY_TYPE;
                            goto exit;
                            break;
                    }
                    msgLen += tmpLen + 2;

                    if (isTLSorDTLS12)
                    {
                        msgLen += 2; /* ubyte2 SignatureAndHashAlgorithm */
                    }
                }
#endif
                pSSLSock->buffers[bufIndex].length = (ubyte2)(pSSLSock->buffers[bufIndex].length + msgLen);
            }
#endif /* defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) ||
            defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) */
        }

        if (TRUE == isServerKeyExchangePresent)
        {
            pSSLSock->buffers[bufIndex].length = (ubyte2)(pSSLSock->buffers[bufIndex].length + sizeofRecordHeader + sizeofHandshakeHeader);
            bufIndex++;
            numBufs++;
        }

    /* For TLS1.2 CertificateRequest length.*/
#ifdef __ENABLE_DIGICERT_TLS13__
        if ((pSSLSock->isDTLS && (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)) || (!(pSSLSock->isDTLS) && (TLS13_MINORVERSION > pSSLSock->sslMinorVersion)))
#endif
        {
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
            if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
                    (SSL_FLAG_NO_MUTUAL_AUTH_REQUEST != (sslFlags & SSL_FLAG_NO_MUTUAL_AUTH_REQUEST)) )
            {
                ubyte2 clientCertTypes = NUM_CLIENT_CERT_TYPES;
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
                if (FALSE == SSL_sslSettings()->allowDSASigAlg)
                {
                    clientCertTypes--;
                }
#endif
                /* calc certificate request length */
                pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader +
                        (isTLSorDTLS12? 2 + supportedSignatureAlgoListLength * 2 :0) +
                        1 + clientCertTypes);
                /* If no distinguished name, 00 00 should be sent at the end
                 * indicating 0 length distinguished names. */
                if (SSL_sslSettings()->pClientCANameList != NULL)
                {
                    for (i = 0; i < SSL_sslSettings()->numClientCANames; i++)
                    {
                        distNameLen += 2 /* to store length */ + SSL_sslSettings()->pClientCANameList[i].length;
                    }
                }
                pSSLSock->buffers[bufIndex].length += distNameLen + 2/* Length of DistNames */;
                bufIndex++;
                numBufs++;
            }
#endif

            /* SSL and TLS p.85 */
            /* server hello done */
            pSSLSock->buffers[bufIndex].length =  (ubyte2) (sizeofRecordHeader + sizeofHandshakeHeader);
            numBufs++;
        }
    }

    /* allocate enough space for all records */
    for (bufIndex = 0; bufIndex < numBufs; bufIndex++)
        totalLen +=  pSSLSock->buffers[bufIndex].length;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
    {
        fragmentLen = calculateExtraFragmentHeader(pSSLSock, numBufs);
    }
#endif

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, totalLen+fragmentLen, TRUE, (void **)&(pSSLSock->buffers[0].pHeader))))
        goto exit;

    /* initialize other pointers */
    for (bufIndex = 0; bufIndex < numBufs; bufIndex++)
    {
        if (bufIndex < numBufs - 1)
        {
            pSSLSock->buffers[bufIndex + 1].pHeader = pSSLSock->buffers[bufIndex].pHeader + pSSLSock->buffers[bufIndex].length;
        }
        /* only server hello message is unencrypted, the rest of the messages require the cipher text header */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (bufIndex > 0 && pSSLSock->isDTLS)
        {
            pSSLSock->buffers[bufIndex].data = pSSLSock->buffers[bufIndex].pHeader + sizeofCipherRecordHeader;
        }
        else
#endif
        {
            pSSLSock->buffers[bufIndex].data = pSSLSock->buffers[bufIndex].pHeader + sizeofRecordHeader;
        }
    }

    bufIndex = 0;

    /* server hello ******************/
    pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
        pHSH = pSSLSock->buffers[bufIndex].data;
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
        setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
        ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_SERVER_HELLO;
    } else
#endif
    {
#if defined(__ENABLE_DIGICERT_TLS13__)
        if (TLS13_MINORVERSION == sslMinorVersion)
        {
            SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->legacySSLMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
        }
        else
#endif
        {
            SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
        }

        pHSH = pSSLSock->buffers[bufIndex].data;
        setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
        ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_SERVER_HELLO;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
    {
        status = fillServerHello(pSSLSock, pHSH, VERSION_MASK_1, sendCookie);
    }
    else
#endif
    {
        status = fillServerHello(pSSLSock, pHSH, VERSION_MASK_3, sendCookie);
    }

    if (OK > status)
    {
        goto exit;
    }

    addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
    bufIndex++;

#if defined(__ENABLE_DIGICERT_TLS13__)

    if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
    {
        if (OK > (status = SSLSOCK_computeHandshakeSecret(pSSLSock)))
        {
            goto exit;
        }

        if (OK > (status = SSLSOCK_setServerTrafficKeyMaterial(pSSLSock, pSSLSock->pServerHandshakeTrafficSecret)))
        {
            goto exit;
        }
        /* we need to use handshake traffic secret and epoch 2 for the EncryptedExtensions + Finished */
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        if (pSSLSock->isDTLS)
        {
            pSSLSock->ownSeqnumHigh = 0x20000; /* epoch value for authentication messages */
            pSSLSock->ownSeqnum = 0;
            releaseRetransmissionBuffer(pSSLSock);
        }
#endif

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined( __ENABLE_DIGICERT_TLS13_0RTT__))
        if (0 == pSSLSock->earlyDataExtAccepted)
#endif
        {
            if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock, pSSLSock->pClientHandshakeTrafficSecret)))
            {
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
            if (pSSLSock->isDTLS)
            {
                pSSLSock->peerSeqnumHigh = 0x20000;
                pSSLSock->peerSeqnum = 0;
                pSSLSock->currentPeerEpoch = DTLS_OWNEPOCH(pSSLSock);
                /* record the existing ciphersuite for re-transmission */
                pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
            }
#endif
        }
    }
#endif

    /* EncryptedExtensions ******************/
    if (E_NoSessionResume == pSSLSock->sessionResume)
    {
#if defined (__ENABLE_DIGICERT_TLS13__)
         /* All the extensions apart from
          *  - supported_versions
          *  - key_share
          *  - pre_shared_key
          * should be encrypted
         */
        if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
        {
            pSRH = pSSLSock->buffers[bufIndex].pHeader;
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
            if (pSSLSock->isDTLS)
            {
                pHSH = pSSLSock->buffers[bufIndex].data;
                DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherHandshakeRecord));
                setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherHandshakeRecord));
                ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_ENCRYPTED_EXTENSIONS;
            }
            else
#endif
            {
                SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->legacySSLMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
                pHSH = pSSLSock->buffers[bufIndex].data;
                setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_ENCRYPTED_EXTENSIONS;
            }

            if (OK > (status = fillServerHello(pSSLSock, pHSH, VERSION_MASK_2, FALSE/* Dont send cookie */)))
            {
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofCipherRecordHeader));
            }
            else
#endif
            {
                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
            }
            bufIndex++;
        }
#endif

    /* [TLS13] CertificateRequest ******************/
/* RFC 4.3.2.  Certificate Request: For TLS13 CertificateRequest should follow EncryptedExtension */
#if defined(__ENABLE_DIGICERT_TLS13__) && defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == sslMinorVersion) || 
             (pSSLSock->isDTLS && DTLS13_MINORVERSION == sslMinorVersion)) &&
            /*(pSSLSock->postHandshakeAuth != 1) &&*/ /* If client supports post handshake auth, certificate request should be sent after the handshake */
            ((!pSSLSock->isPSKSelected) ||
             (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock))))
        {
            /* (to client) certificate request */
            if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
                    (SSL_FLAG_NO_MUTUAL_AUTH_REQUEST != (sslFlags & SSL_FLAG_NO_MUTUAL_AUTH_REQUEST)) )
            {
                pSSLSock->isMutualAuthNegotiated = TRUE;

                pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {  
                    pHSH = pSSLSock->buffers[bufIndex].data;
                    
                    DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherHandshakeRecord));
                    setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherHandshakeRecord));
                    ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE_REQUEST;

                    if (OK > (status = fillCertificateRequest3(pSSLSock, pHSH, certificateReqExtLen, distNameLen, 0 /* Not Post Handshake Auth */)))
                        goto exit;
                
                    addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofCipherRecordHeader));
                }
                else
#endif
                {
                    SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->legacySSLMinorVersion, 
                            pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

                    pHSH = pSSLSock->buffers[bufIndex].data;
                    setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, 
                            (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE_REQUEST;
              
                    if (OK > (status = fillCertificateRequest3(pSSLSock, pHSH, certificateReqExtLen, distNameLen, 0 /* Not Post Handshake Auth */)))
                        goto exit;

                    addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
                }
                bufIndex++;
            }
        }
#endif


    /* Certificate ******************/
#ifdef __ENABLE_DIGICERT_TLS13__
        if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
        {
            if ((!pSSLSock->isPSKSelected) ||
                (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock)))
            {
                pSRH = pSSLSock->buffers[bufIndex].pHeader;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    /* certificate *******************/
                    setShortValue(pSRH + 3, pSSLSock->buffers[bufIndex].length - sizeofCipherRecordHeader);

                    pHSH = pSSLSock->buffers[bufIndex].data;
                    DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherHandshakeRecord));
                    setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherHandshakeRecord));
                    ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE;
                    fillCertificate(pSSLSock, pHSH);
                    addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofCipherRecordHeader));
                }
                else
#endif
                {
                    /* certificate *******************/
                    SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->legacySSLMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
                    pHSH = pSSLSock->buffers[bufIndex].data;
                    setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_CERTIFICATE;
                    fillCertificate(pSSLSock, pHSH);
                    addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
                }
                bufIndex++;
            }
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            if (0 == (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_ANON_BIT))
            {
                /* certificate *******************/
                pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
                    pHSH = pSSLSock->buffers[bufIndex].data;
                    DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    setMediumValue(((DTLSHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    ((DTLSHandshakeHeader*)pHSH)->handshakeType = SSL_CERTIFICATE;
                }
                else
#endif
                {
                    SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

                    pHSH = pSSLSock->buffers[bufIndex].data;
                    setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_CERTIFICATE;
                }

                fillCertificate(pSSLSock, pHSH);

                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
                bufIndex++;
            }
        }

    /* [TLS13] CertificateVerify ******************/
#if defined(__ENABLE_DIGICERT_TLS13__)
        /* Send Certificate Verify with certificate */
        if (((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion)) &&
            ((!pSSLSock->isPSKSelected) || (0 == TLS13_GET_PRE_SHARED_KEY_EXT_RX(pSSLSock))))
        {
            ubyte2 length, initLength;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if(pSSLSock->isDTLS)
            {
                length = initLength = (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofCipherRecordHeader);
            }
            else
#endif
            {
                length = initLength = (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
            }

            if (OK > (status = SSLSOCK_fillCertificateVerify(pSSLSock->signatureAlgo,
                                                             pSSLSock, pSSLSock->handshakeKey,
                                                             pSSLSock->buffers[bufIndex].data,
                                                             &length, NULL)))
            {
                goto exit;
            }

            if (length != initLength)
            {
                /* adjust pointers, length and headers ... */
                totalLen -= (initLength - length);
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    pSSLSock->buffers[bufIndex].length = (ubyte2) (length + sizeofCipherRecordHeader);
                }
                else
#endif
                {
                    pSSLSock->buffers[bufIndex].length = (ubyte2) (length + sizeofRecordHeader);
                }
                pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    if (DTLS13_MINORVERSION < sslMinorVersion)
                        DTLS_SET_RECORD_HEADER_EXT(pSRH, pSSLSock, SSL_HANDSHAKE, length);
                }
                else
#endif
                {
                    SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, length);
                }
            }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofCipherRecordHeader));
            }
            else
#endif
            {
                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
            }
            bufIndex++;

        }
#endif

    /* CertificateStatus ******************/
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
        if (((pSSLSock->isDTLS) || (TLS13_MINORVERSION > sslMinorVersion)) && (pSSLSock->recvStatusReqExt))
        {
            /* Certificate Status: Need to fill in certificate status response here */
            pSRH = pSSLSock->buffers[bufIndex].pHeader;
            SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

            pHSH = pSSLSock->buffers[bufIndex].data;
            setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
            ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_CERTIFICATE_STATUS;

            fillCertificateStatus(pSSLSock, pHSH, pOcspResponse, responseLen);

            addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
            bufIndex++;
        }
#endif

    /* ServerKeyExchange ******************/
#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) ||
            (!(pSSLSock->isDTLS) && (TLS13_MINORVERSION > pSSLSock->sslMinorVersion)))
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
#if defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)          ||  \
        defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)  ||  \
        defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)      ||  \
        defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)    ||  \
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
        /* server key exchange */
        if ((TRUE == isServerKeyExchangePresent) && (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->FillServerKEX))
        {
#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
            ubyte4 newBufferLen;
#endif

            pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
                pHSH = pSSLSock->buffers[bufIndex].data;
                DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                /* set the buffer lengths before calling the routine */
                setMediumValue(((DTLSHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                ((DTLSHandshakeHeader*)pHSH)->handshakeType = SSL_SERVER_KEY_EXCHANGE;
            } else
#endif
            {
                SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

                pHSH = pSSLSock->buffers[bufIndex].data;
                /* set the buffer lengths before calling the routine */
                setMediumValue(((SSLHandshakeHeader*)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_SERVER_KEY_EXCHANGE;
            }

            if (OK > (status = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->FillServerKEX(pSSLSock, pHSH, pskHint, pskHintLength)))
                goto exit;

#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
            /* the routine might have modified the buffer length  -- this is because of
            the unfortunate DSA and ECDSA DER encoding */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                newBufferLen = getMediumValue( ((DTLSHandshakeHeader*)pHSH)->handshakeSize);
                setMediumValue(((DTLSHandshakeHeader*)pHSH)->fragLength, newBufferLen);
            } else
#endif
            {
                newBufferLen = getMediumValue( ((SSLHandshakeHeader*)pHSH)->handshakeSize);
            }

            if ( newBufferLen > pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord )
            {
                /* the FillServerKEX increased the buffer size! something is wrong here! */
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
            else if ( newBufferLen < pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord)
            {
                /* adjust buffer length */
                pSSLSock->buffers[bufIndex].length = (ubyte2) (sizeofHandshakeRecord + newBufferLen);

                /* adjust SSLRecord size */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    setShortValue( ((DTLSRecordHeader*) pSRH)->recordLength,
                                    (ubyte2) (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
                } else
#endif
                {
                    setShortValue( ((SSLRecordHeader*) pSRH)->recordLength,
                                   (ubyte2) (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
                }

                /* need to adjust all the downstream buffers */
                for ( i = bufIndex; i < 5; ++i)
                {
                    pSSLSock->buffers[i+1].pHeader = pSSLSock->buffers[i].pHeader + pSSLSock->buffers[i].length;
                    pSSLSock->buffers[i+1].data = pSSLSock->buffers[i+1].pHeader + sizeofRecordHeader;
                }
                /* recompute totalLen too! */
                totalLen =  pSSLSock->buffers[0].length + pSSLSock->buffers[1].length + pSSLSock->buffers[2].length +
                            pSSLSock->buffers[3].length + pSSLSock->buffers[4].length + pSSLSock->buffers[5].length;
            }
#endif /* __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__ */

            addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
            bufIndex++;
        }
#endif
        }

    /* [TLS12] CertificateRequest ******************/
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
#ifdef __ENABLE_DIGICERT_TLS13__
        if ((pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) ||
            (!(pSSLSock->isDTLS) && (TLS13_MINORVERSION > pSSLSock->sslMinorVersion)))
#endif
        {
            /* (to client) certificate request */
            if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
                    (SSL_FLAG_NO_MUTUAL_AUTH_REQUEST != (sslFlags & SSL_FLAG_NO_MUTUAL_AUTH_REQUEST)) )
            {
                pSSLSock->isMutualAuthNegotiated = TRUE;

                pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS)
                {
                    DTLS_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->ownSeqnumHigh, pSSLSock->ownSeqnum, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

                    /* Sending of handshake message. Sequence number will not overflow */
                    if (0 == (++pSSLSock->ownSeqnum))
                        pSSLSock->ownSeqnumHigh = (pSSLSock->ownSeqnumHigh & 0xffff0000) | ((pSSLSock->ownSeqnumHigh + 1) & 0xffff);

                    pHSH = pSSLSock->buffers[bufIndex].data;
                    DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE_REQUEST;
                }
                else
#endif
                {
                    SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

                    pHSH = pSSLSock->buffers[bufIndex].data;
                    setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                    ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_CERTIFICATE_REQUEST;
                }
                if (OK > (status = fillCertificateRequest(pSSLSock, pHSH, distNameLen)))
                    goto exit;

                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
                bufIndex++;
            }
        }
#endif

        /* server hello done *************/
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
            if (DTLS13_MINORVERSION < sslMinorVersion)
            {
                pSRH = pSSLSock->buffers[bufIndex].pHeader;
                DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
                pHSH = pSSLSock->buffers[bufIndex].data;
                DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_SERVER_HELLO_DONE;
                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
            }
        }
        else
#endif
        {
            /* Sever Hello Done is NOT sent when negotiating TLS 1.3 */
            if (TLS13_MINORVERSION > sslMinorVersion)
            {
                pSRH = pSSLSock->buffers[bufIndex].pHeader;
                SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, sslMinorVersion, pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
                pHSH = pSSLSock->buffers[bufIndex].data;
                setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofHandshakeRecord));
                ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_SERVER_HELLO_DONE;
                addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
            }
        }
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
send_server_hello:
#endif
    /* send the handshakes records to SSL record layer *************/
    if (TRUE != isRehandshake)
    {
        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            numBytesSent =  0;
            status = (MSTATUS)totalLen;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_TLS13__)
            /* For TLS 1.3 we send only the Server Hello un-encrypted.
             * So using TCP_WRITE for the first buffer
             */
            if (TLS13_MINORVERSION == sslMinorVersion)
            {
                totalLen = pSSLSock->buffers[0].length;
            }
#endif

#ifndef __DIGICERT_IPSTACK__
        if (OK > (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)(pSSLSock->buffers[0].pHeader), totalLen, &numBytesSent)))
#else
        if (OK > (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)(pSSLSock->buffers[0].pHeader), totalLen, &numBytesSent)))
#endif
                  goto exit;
        }

        if (numBytesSent != totalLen)
        {

            /* In TLS 1.3 Server Hello message is NOT encrypted;
             * Subsequent messages are encrypted.
             * New memory allocation for Server Hello message is required because
             * SSLSOCK_sendEncryptedHandshakeBuffer API frees the buffer when
             * its constructing the encrypted messages. */
#if defined(__ENABLE_DIGICERT_TLS13__)
            if (TLS13_MINORVERSION == sslMinorVersion || DTLS13_MINORVERSION == sslMinorVersion)
            {
                ubyte *output = (ubyte *) MALLOC(pSSLSock->buffers[0].length);

                if (NULL == output)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                totalLen = pSSLSock->buffers[0].length;
                DIGI_MEMCPY(output, pSSLSock->buffers[0].pHeader, pSSLSock->buffers[0].length);
                pSSLSock->pOutputBufferBase = output;
                pSSLSock->pOutputBuffer     = output + numBytesSent;
                pSSLSock->outputBufferSize  = totalLen + fragmentLen;
                pSSLSock->numBytesToSend    = totalLen + fragmentLen - numBytesSent;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if(pSSLSock->isDTLS)
                {
                    releaseRetransmissionBuffer(pSSLSock);
                    addDataToRetransmissionBuffer(pSSLSock, SSL_HANDSHAKE, (const sbyte*)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
                }
#endif

                /* flush any pending bytes in synchronous mode */
                status = flushPendingBytes(pSSLSock);
                if (OK > status)
                    goto exit;
            }
            else
#endif
            {
                pSSLSock->pOutputBufferBase = pSSLSock->buffers[0].pHeader;
                pSSLSock->pOutputBuffer     = numBytesSent + pSSLSock->buffers[0].pHeader;
                pSSLSock->outputBufferSize  = totalLen + fragmentLen;
                pSSLSock->numBytesToSend    = totalLen + fragmentLen - numBytesSent;
            }
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS && DTLS13_MINORVERSION < sslMinorVersion)
            {
                /* fragment the records to meet PMTU */
                pSSLSock->bufIndex = 0;
                pSSLSock->numBuffers = numBufs;
                if (OK > (status = fragmentHandshakeMessages(pSSLSock, fragmentLen)))
                    goto exit;

                releaseRetransmissionBuffer(pSSLSock);
                addDataToRetransmissionBuffer(pSSLSock, SSL_HANDSHAKE, (const sbyte*)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
            }
#endif
            if ((!pSSLSock->isDTLS && (TLS13_MINORVERSION > sslMinorVersion)) ||
                (pSSLSock->isDTLS  && (DTLS12_MINORVERSION <= sslMinorVersion)))
            {
                pSSLSock->buffers[0].pHeader = NULL;
            }
        }
#if defined(__ENABLE_DIGICERT_TLS13__)
        /* For TLS 1.3 all the Handshake packets after Server Hello,
         * should be encrypted using server_handshake_traffic_secret.
         * In case of helloRetry, HelloRetryRequest message is already sent as plain text
         */
        if ((TLS13_MINORVERSION == sslMinorVersion) || (DTLS13_MINORVERSION == sslMinorVersion))
        {
            if (pSSLSock->helloRetryRequest != 1)
            {
                pSSLSock->bufIndex = 1; /* 0th buffer contains Server Hello */
                pSSLSock->numBuffers = numBufs;

                status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock);
            }
            else
            {
                /* No extensions are received */
                pSSLSock->roleSpecificInfo.server.receivedExtensions = 0;
            }
        }
#endif
    }
    else
    {
        pSSLSock->bufIndex = 0;
        pSSLSock->numBuffers = numBufs;

        status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock);
    }

exit:

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    if (NULL != pOcspResponse)
    {
        DIGI_FREE((void **) &pOcspResponse);
    }
#endif

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
    if (NULL != pSSLSock->roleSpecificInfo.server.pSelectedPSK)
    {
        if (NULL != pSSLSock->roleSpecificInfo.server.pSelectedPSK->pskTLS13Identity)
        {
            DIGI_FREE((void**)&pSSLSock->roleSpecificInfo.server.pSelectedPSK->pskTLS13Identity);
        }
        DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.server.pSelectedPSK);
    }
#endif

    if ((TRUE != isRehandshake) || (OK > status))
    {
        /* free the buffers */
        if (pSSLSock->buffers[0].pHeader)
        {
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->buffers[0].pHeader));
        }
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SERVER_sendServerHello() returns status = ", status);

    return status;

} /* SSL_SERVER_sendServerHello */

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)

/* Encrypted data put into session ticket message
 *
 *
 *  struct {
 *      uint32 ticket_lifetime_hint;
 *      opaque ticket<0..2^16-1>;
 *  } NewSessionTicket;
 *
 *  struct {
 *      opaque key_name[16];
 *      opaque iv[16];
 *      opaque encrypted_state<0..2^16-1>;
 *      opaque mac[32];
 *  } ticket;
 *
 * where encrypted_state is StatePlaintext encrypted
 *
 *  struct {
 *      ProtocolVersion protocol_version;
 *      CipherSuite cipher_suite;
 *      CompressionMethod compression_method;
 *      opaque master_secret[48];
 *      ClientIdentity client_identity;
 *      opaque UTC/Generalized timestamp<0..2^16-1>
 *      ubyte2 ticketVersion;
 *      ubyte2 isExtendedMasterSecret;
 *  } StatePlaintext;
 *
 *  enum {
 *     anonymous(0),
 *     certificate_based(1),
 *     psk(2)
 * } ClientAuthenticationType;
 *
 *  struct {
 *      ClientAuthenticationType client_authentication_type;
 *      select (ClientAuthenticationType) {
 *          case anonymous: struct {};
 *          case certificate_based:
 *              ASN.1Cert certificate_list<0..2^24-1>;
 *          case psk:
 *              opaque psk_identity<0..2^16-1>;   // from [RFC4279] not supported
 *      };
 *   } ClientIdentity;
 */
static MSTATUS
sendNewSessionTicket(SSLSocket *pSSLSock)
{
    MSTATUS status;
    ubyte *pSessionTicketMsg = NULL;
    ubyte *pTemp, *pEnc, *pMac;
    ubyte4 sessionTicketMsgLen = 0;
    ubyte4 numBytesSent, macLen;
    ubyte2 encryptedTicketLen = 0;
    ubyte4 ticketLifetime = TICKET_LIFETIME_TWO_HOURS;
    sbyte4 paddingLen;
    ubyte4 i;
    ubyte4 sizeofRecordHeader;
    ubyte4 sizeofHandshakeHeader;
    ubyte pIv[SSL_SESSION_TICKET_IV_SIZE];
    BulkCtx pAesCbcCtx = NULL;
    TimeDate td;
    sbyte pTimeBuf[16];
    ubyte4 timeBufLen;
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    const ubyte *pCert = NULL;
    ubyte4 certLen, certCount, totalCertLen = 0;
#endif

    /* Get current time */
    if (OK > (status = RTOS_timeGMT(&td)))
        goto exit;

    if (OK > (status = DATETIME_convertToValidityString(&td, pTimeBuf)))
        goto exit;

    timeBufLen = DIGI_STRLEN(pTimeBuf);

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            sizeofRecordHeader = DTLS13_MOC_RECORD_HEADER_LEN;
        }
        else
#endif
        {
            sizeofRecordHeader = sizeof(DTLSRecordHeader);
        }
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    }
    else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    sessionTicketMsgLen += sizeofRecordHeader;
    sessionTicketMsgLen += sizeofHandshakeHeader;

    /* uint32 ticket_lifetime_hint */
    sessionTicketMsgLen += 4;
    /* opaque ticket length */
    sessionTicketMsgLen += 2;

    /* opaque key_name[16] */
    sessionTicketMsgLen += SSL_SESSION_TICKET_KEY_NAME_SIZE;
    /* opaque iv[16] */
    sessionTicketMsgLen += SSL_SESSION_TICKET_IV_SIZE;
    /* opaque encrypted_state length */
    sessionTicketMsgLen += 2;

    /* ProtocolVersion protocol_version */
    encryptedTicketLen += 2;
    /* CipherSuite cipher_suite */
    encryptedTicketLen += 2;
    /* CompressionMethod compression_method */
    encryptedTicketLen += 1;
    /* opaque master_secret[48] */
    encryptedTicketLen += SSL_MASTERSECRETSIZE;

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if (NULL != pSSLSock->pCertChain)
    {
        /* ClientAuthenticationType - certificate authentication */
        encryptedTicketLen += 1;

        if (OK > (status = CERTCHAIN_numberOfCertificates(pSSLSock->pCertChain, &certCount)))
            goto exit;

        /* entire certificate chain length */
        encryptedTicketLen += 3;

        for (i = 0; i < certCount; i++)
        {
            /* certificate length */
            totalCertLen += 3;

            if (OK > (status = CERTCHAIN_getCertificate(pSSLSock->pCertChain, i, &pCert, &certLen)))
                goto exit;

            totalCertLen += certLen;
        }

        encryptedTicketLen += totalCertLen;
    }
    else
#endif
    {
        /* ClientAuthenticationType - anonymous */
        encryptedTicketLen += 1;
    }
    /* UTC/Generalized time length */
    encryptedTicketLen += 2;
    /* UTC/Generalized time */
    encryptedTicketLen += timeBufLen;

    /* ubyte2 ticket version */
    encryptedTicketLen += 2;

    /* ubyte2 isExtendedMasterSecret */
    encryptedTicketLen += 2;

    /* padding bytes */
    paddingLen = computePadLength(encryptedTicketLen, AES_BLOCK_SIZE);
    encryptedTicketLen += paddingLen;

    /* opaque encrypted_state */
    sessionTicketMsgLen += encryptedTicketLen;
    /* opaque mac[32] */
    sessionTicketMsgLen += SSL_SESSION_TICKET_MAC_SIZE;

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, sessionTicketMsgLen, TRUE, (void **) &pSessionTicketMsg)))
        goto exit;

    pTemp = pSessionTicketMsg;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
        {
            DTLS_SET_RECORD_HEADER(pTemp, SSL_HANDSHAKE, pSSLSock->sslMinorVersion, pSSLSock->ownSeqnumHigh, pSSLSock->ownSeqnum, sessionTicketMsgLen - sizeofRecordHeader);

            /* Sending of handshake message. Sequence number will not overflow */
            if (0 == (++pSSLSock->ownSeqnum))
                pSSLSock->ownSeqnumHigh = (pSSLSock->ownSeqnumHigh & 0xffff0000) | ((pSSLSock->ownSeqnumHigh + 1) & 0xffff);
        }

        pTemp += sizeofRecordHeader;
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pTemp), pSSLSock->nextSendSeq++, (ubyte2)(sessionTicketMsgLen - sizeofHandshakeHeader - sizeofRecordHeader));
        setMediumValue(((DTLSHandshakeHeader *)pTemp)->handshakeSize, (ubyte2)(sessionTicketMsgLen - sizeofHandshakeHeader - sizeofRecordHeader));
        ((DTLSHandshakeHeader *)pTemp)->handshakeType = SSL_NEW_SESSION_TICKET;
    }
    else
#endif
    {
        SSL_SET_RECORD_HEADER(pTemp, SSL_HANDSHAKE, pSSLSock->sslMinorVersion, sessionTicketMsgLen - sizeofRecordHeader);

        pTemp += sizeofRecordHeader;
        setMediumValue(((SSLHandshakeHeader *)pTemp)->handshakeSize, (ubyte2)(sessionTicketMsgLen - sizeofHandshakeHeader - sizeofRecordHeader));
        ((SSLHandshakeHeader *)pTemp)->handshakeType = SSL_NEW_SESSION_TICKET;
    }

    pTemp += sizeofHandshakeHeader;

    *pTemp++ = ticketLifetime >> 24;
    *pTemp++ = (ticketLifetime >> 16) & 0xFF;
    *pTemp++ = (ticketLifetime >>  8) & 0xFF;
    *pTemp++ = ticketLifetime & 0xFF;

    setShortValue(pTemp, sessionTicketMsgLen - sizeofHandshakeHeader - sizeofRecordHeader - 6);
    pTemp += sizeof(ubyte2);

    if (OK > (status = DIGI_MEMCPY(pTemp, gSessionTicketKeyName, sizeof(gSessionTicketKeyName))))
        goto exit;

    pMac = pTemp;
    macLen = SSL_SESSION_TICKET_KEY_NAME_SIZE + SSL_SESSION_TICKET_IV_SIZE + 2 + encryptedTicketLen;

    pTemp += sizeof(gSessionTicketKeyName);

    if (OK > (status = pSSLSock->rngFun(pSSLSock->rngFunArg, sizeof(pIv), pIv)))
        goto exit;

    if (OK > (status = DIGI_MEMCPY(pTemp, pIv, sizeof(pIv))))
        goto exit;

    pTemp += sizeof(pIv);

    setShortValue(pTemp, encryptedTicketLen);
    pTemp += sizeof(ubyte2);

    pEnc = pTemp;

    *pTemp++ = SSL3_MAJORVERSION;
    *pTemp++ = pSSLSock->sslMinorVersion;

    setShortValue(pTemp, pSSLSock->pHandshakeCipherSuite->cipherSuiteId);
    pTemp += sizeof(ubyte2);

    *pTemp++ = 0;

    if (OK > (status = DIGI_MEMCPY(pTemp, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE)))
        goto exit;

    pTemp += SSL_MASTERSECRETSIZE;

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if (NULL != pSSLSock->pCertChain)
    {
        /* ClientAuthenticationType - anonymous */
        *pTemp++ = SSL_SESSION_TICKET_CLIENT_AUTH_TYPE_CERT;

        setMediumValue(pTemp, (ubyte2) totalCertLen);
        pTemp += 3;

        for (i = 0; i < certCount; i++)
        {
            if (OK > (status = CERTCHAIN_getCertificate(pSSLSock->pCertChain, i, &pCert, &certLen)))
                goto exit;

            setMediumValue(pTemp, (ubyte2) certLen);
            pTemp += 3;

            if (OK > (status = DIGI_MEMCPY(pTemp, pCert, certLen)))
                goto exit;

            pTemp += certLen;
        }
    }
    else
#endif
    {
        /* ClientAuthenticationType - anonymous */
        *pTemp++ = SSL_SESSION_TICKET_CLIENT_AUTH_TYPE_ANON;
    }

    setShortValue(pTemp, (ubyte2) timeBufLen);
    pTemp += sizeof(ubyte2);

    /* UTC/Generalized time */
    DIGI_MEMCPY(pTemp, pTimeBuf, timeBufLen);
    pTemp += timeBufLen;

    setShortValue(pTemp, SSL_SESSION_TICKET_VERSION);
    pTemp += sizeof(ubyte2);

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    setShortValue(pTemp, (TRUE == pSSLSock->useExtendedMasterSecret) ? 1 : 0);
    pTemp += sizeof(ubyte2);
#else
    setShortValue(pTemp, 0);
    pTemp += sizeof(ubyte2);
#endif

    for (i = 0; i < (ubyte4) paddingLen; i++)
        *pTemp++ = paddingLen;

    pAesCbcCtx = CRYPTO_INTERFACE_CreateAESCtx(
        MOC_SYM(pSSLSock->hwAccelCookie) gSessionTicketEncKey,
        sizeof(gSessionTicketEncKey), 1);
    if (NULL == pAesCbcCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_DoAES(MOC_SYM(pSSLSock->hwAccelCookie) pAesCbcCtx, pEnc, encryptedTicketLen, 1, pIv)))
        goto exit;

    if (OK > (status = HMAC_SHA256(MOC_HASH(pSSLSock->hwAccelCookie)
            gSessionTicketMacKey, sizeof(gSessionTicketMacKey), pMac, macLen,
            NULL, 0, pEnc + encryptedTicketLen)))
        goto exit;

    addToHandshakeHash(pSSLSock, pSessionTicketMsg + sizeofRecordHeader, sessionTicketMsgLen - sizeofRecordHeader);

    if (NULL == pSSLSock->pActiveOwnCipherSuite)
    {
        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            numBytesSent = 0;

            if (NULL == pSSLSock->pOutputBufferBase)
            {
                if (NULL == (pSSLSock->pOutputBufferBase = (ubyte*) MALLOC(sessionTicketMsgLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                pSSLSock->pOutputBuffer      = pSSLSock->pOutputBufferBase;
                pSSLSock->outputBufferSize   = sessionTicketMsgLen;
                pSSLSock->numBytesToSend     = 0;
            }

            if ((sessionTicketMsgLen + pSSLSock->numBytesToSend) > pSSLSock->outputBufferSize)
            {
                /* Need to Realloc this buffer */
                ubyte * output = (ubyte*) MALLOC(pSSLSock->numBytesToSend + sessionTicketMsgLen);

                if (NULL == output)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(output, pSSLSock->pOutputBufferBase, pSSLSock->numBytesToSend);
                pSSLSock->outputBufferSize  += sessionTicketMsgLen;

                FREE(pSSLSock->pOutputBufferBase);
                pSSLSock->pOutputBufferBase = output;

            }
            else
            {
                if (pSSLSock->pOutputBufferBase != pSSLSock->pOutputBuffer)
                    DIGI_MEMMOVE(pSSLSock->pOutputBufferBase, pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
            }

            pSSLSock->pOutputBuffer   = pSSLSock->pOutputBufferBase + pSSLSock->numBytesToSend;
            DIGI_MEMCPY(pSSLSock->pOutputBuffer, pSessionTicketMsg, sessionTicketMsgLen);

            pSSLSock->numBytesToSend += sessionTicketMsgLen;
            pSSLSock->pOutputBuffer   = pSSLSock->pOutputBufferBase;
            status = (MSTATUS)pSSLSock->numBytesToSend;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            if (pSSLSock->isDTLS)
            {
                if (OK > (status = addDataToRetransmissionBuffer(pSSLSock, SSL_NEW_SESSION_TICKET, (const sbyte*) pSessionTicketMsg, sessionTicketMsgLen)))
                    goto exit;
            }
#endif

            goto exit;
        }
        else
        {
#ifndef __DIGICERT_IPSTACK__
            if (OK > (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSessionTicketMsg, sessionTicketMsgLen, &numBytesSent)))
#else
            if (OK > (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSessionTicketMsg, sessionTicketMsgLen, &numBytesSent)))
#endif
                goto exit;

            if (sessionTicketMsgLen != numBytesSent)
            {
                if (NULL == (pSSLSock->pOutputBufferBase = (ubyte*) MALLOC(sessionTicketMsgLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(pSSLSock->pOutputBufferBase, pSessionTicketMsg, sessionTicketMsgLen);

                pSSLSock->pOutputBuffer     = numBytesSent + pSSLSock->pOutputBufferBase;
                pSSLSock->outputBufferSize  = sessionTicketMsgLen;
                pSSLSock->numBytesToSend    = sessionTicketMsgLen - numBytesSent;
            }
        }
    }
    else
    {
        status = sendData(pSSLSock, SSL_HANDSHAKE, (const sbyte *) (pSessionTicketMsg + sizeofRecordHeader), sessionTicketMsgLen - sizeofRecordHeader, TRUE);
    }

exit:

    if (NULL != pAesCbcCtx)
    {
        CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(pSSLSock->hwAccelCookie) &pAesCbcCtx);
    }

    if (NULL != pSessionTicketMsg)
    {
        DIGI_MEMSET(pSessionTicketMsg, 0x00, sessionTicketMsgLen);
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSessionTicketMsg));
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"sendNewSessionTicket() returns status = ", status);

    return status;
}

#endif

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__)

/* Function to generate a new session ticket.
 *  This function allocates the memory for the new session ticket.
 *  Free the memory in the caller.
 *  It also returns the length of session ticket.
 *
 *   key_name[16]
 *   iv[16]
 *   encrypted_state_length[2]
 *   encrypted_state[0 to 2^16 -1]
 *   mac[32]
 *
 *   Use a 128 bit key for AES-CBC encryption to generate encrypted_state data
 *   Use a 256 bit key for HMAC-SHA-256 to generate the 32 byte mac
 *
 *   encrypted_state:
 *   protocol_version
 *   cipher_suite
 *   compression_method
 *   master_secret
 *   client_identity[anonymous, certificate_based[ASN.1 Certificates], psk[psk_identity]] --- NOT implementing this
 *   timestamp
 *   struct {
 *       uint32 ticket_lifetime;
 *       uint32 ticket_age_add;
 *       opaque ticket_nonce<0..255>;
 *       opaque ticket<1..2^16-1>;
 *       Extension extensions<0..2^16-2>;
 *   } NewSessionTicket;
 */
static MSTATUS
SSL_SERVER_sendNewSessionTicket(SSLSocket *pSSLSock)
{
    ubyte* pSessionTicket = NULL;
    ubyte* pHSH = NULL;
    ubyte* pMessage = NULL;
    ubyte  *pTemp = NULL;
    ubyte4 messageLen = 0;
    ubyte4 sizeofHandshakeHeader;
    ubyte4 ticketLifeTimeHint;
    ubyte4 extensionsLen = 0;
    MSTATUS status;
    ubyte4 ticketAgeAdd = 0;
    tls13PSK selectedPSK = {0};
    ubyte nonceLen = pSSLSock->roleSpecificInfo.server.sessionTicketNonceLen;
    ubyte *pNonce = NULL;
    ubyte *pPsk = NULL;
    ubyte4 pskLen = 0;
    ubyte4 pskIdentityLen = 0;
    ubyte *pPskIdentity = NULL;
    ubyte4 sessionTicketLen = 0;
    sbyte* pSNI = pSSLSock->serverNameIndication;
    ubyte4 sniLen;

    if (pSNI != NULL)
    {
        sniLen = DIGI_STRLEN((sbyte *) pSNI);
    }
    else
    {
        sniLen = 0;
    }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } 
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    messageLen += sizeofHandshakeHeader;
    messageLen += 4; /* ticket_lifetime_hint */

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        messageLen += 4; /* ticket_age_add */
        messageLen += 1; /* length of nonce */
        if (nonceLen > SSL_SESSION_TICKET_NONCE_SIZE)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }
        messageLen += nonceLen;
    }

    /* Session ID length in OpenSSL Connector is 32. pskIdentity is stored as session Id */
    pskIdentityLen = SSL_PSK_IDENTITY_TLS13_MAX_LENGTH - 2;

    messageLen += 2; /* Store length of Ticket Identity */
    messageLen += pskIdentityLen;

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
        /* early_data extension */
        if (pSSLSock->maxEarlyDataSize > 0)
        {
            extensionsLen += SSL_EARLY_DATA_EXTENSION_SIZE; /* early_data ext(2) + extension len(2) + maxEarlyDataSize(4) */
        }
#endif
    }
    messageLen += 2/* extension length */ + extensionsLen;

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, messageLen, TRUE, (void **)&(pMessage))))
        goto exit;

    if (OK > (status = DIGI_MEMSET(pMessage, 0, messageLen)))
    {
        goto exit;
    }

    pHSH = pMessage;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(messageLen - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pHSH)->handshakeType = SSL_NEW_SESSION_TICKET;

        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(messageLen - sizeofHandshakeHeader));
    } 
    else
#endif
    {
        setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(messageLen - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_NEW_SESSION_TICKET;
    }
    pTemp = pHSH + sizeofHandshakeHeader;

    ticketLifeTimeHint = TICKET_LIFETIME_TWO_HOURS;

    *pTemp++ = ticketLifeTimeHint >> 24;
    *pTemp++ = (ticketLifeTimeHint >> 16) & 0xFF;
    *pTemp++ = (ticketLifeTimeHint >>  8) & 0xFF;
    *pTemp++ = ticketLifeTimeHint & 0xFF;

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        /* ticket_age_add*/
        if (OK > (status = SSL_rngFun(sizeof(ubyte4), (ubyte *) &ticketAgeAdd)))
        {
            goto exit;
        }

        *pTemp++ = ticketAgeAdd >> 24;
        *pTemp++ = (ticketAgeAdd >> 16) & 0xFF;
        *pTemp++ = (ticketAgeAdd >>  8) & 0xFF;
        *pTemp++ = ticketAgeAdd & 0xFF;

        /* Generate and copy the nonce */
        if (OK > (status = DIGI_MALLOC((void **) &pNonce, nonceLen)))
        {
            goto exit;
        }

        if (OK > (status = DIGI_MEMSET(pNonce, 0, nonceLen)))
        {
            goto exit;
        }

        if (OK > (status = SSL_rngFun(nonceLen, pNonce)))
        {
            goto exit;
        }

        *pTemp = nonceLen;
        pTemp++;

        DIGI_MEMCPY(pTemp, pNonce, nonceLen);
        pTemp += nonceLen;
    }

    /* Ticket Identity. Use a random number generator to generate the identity */
    if (OK > (status = DIGI_MALLOC((void **) &pPskIdentity, pskIdentityLen)))
    {
        goto exit;
    }

    if (OK > (status = SSL_rngFun(pskIdentityLen, pPskIdentity)))
    {
        goto exit;
    }
    setShortValue(pTemp, (ubyte2)pskIdentityLen);
    pTemp += 2;

    DIGI_MEMCPY(pTemp, pPskIdentity, pskIdentityLen);
    pTemp += pskIdentityLen;

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        setShortValue(pTemp, (ubyte2)extensionsLen);
        pTemp += 2;
        if (extensionsLen > 0)
        {
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
            if (pSSLSock->maxEarlyDataSize > 0)
            {
                ubyte4 maxEarlyDataSize = pSSLSock->maxEarlyDataSize;

                setShortValue(pTemp, (ubyte2)tlsExt_early_data);
                pTemp += 2; /* early_data extension type(2) */
                setShortValue(pTemp, (ubyte2)sizeof(ubyte4));
                pTemp += 2; /* early_data extension length(2) */

                *pTemp++ = maxEarlyDataSize >> 24;
                *pTemp++ = (maxEarlyDataSize >> 16) & 0xFF;
                *pTemp++ = (maxEarlyDataSize >>  8) & 0xFF;
                *pTemp++ = maxEarlyDataSize & 0xFF;
            }
#endif
        }
    }

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        /* Generate the PSK and store it in the tls13PSK structre and pass it to application */
        if (OK > (status = SSLSOCK_generatePSKFromTicket(pSSLSock, pNonce, nonceLen,
                                                         pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
                                                         pSSLSock->pResumptionMasterSecret,
                                                         &pSessionTicket, &sessionTicketLen)))
        {
            goto exit;
        }

        /* Get the current time at which the PSK was generated. This data is
         * saved in the serialized PSK. Once the PSK is retrieved in a different
         * connection instance, the start time will be used to determine if the
         * PSK is valid or not.
         */
        status = RTOS_timeGMT(&(selectedPSK.startTime));
        if (OK != status)
        {
            goto exit;
        }

        selectedPSK.isExternal = 0;
        selectedPSK.isPSKavailable = 1;
        selectedPSK.pskTLS13LifetimeHint = ticketLifeTimeHint;
        selectedPSK.pskTLS13AgeAdd = ticketAgeAdd;
        DIGI_MEMCPY(selectedPSK.ticketNonce, pNonce, pSSLSock->roleSpecificInfo.server.sessionTicketNonceLen);
        DIGI_MEMCPY(selectedPSK.pskTLS13, pSessionTicket, sessionTicketLen);
        selectedPSK.pskTLS13Length = (ubyte2) sessionTicketLen;
        selectedPSK.pskTLS13Identity = pPskIdentity;
        selectedPSK.pskTLS13IdentityLength = pskIdentityLen;

        selectedPSK.hashAlgo = getHashIdFromSuite(pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo);

        if (0 == selectedPSK.hashAlgo)
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }


#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
        selectedPSK.maxEarlyDataSize = pSSLSock->maxEarlyDataSize;
#endif

        if (pSSLSock->selectedALPN != NULL)
        {
            DIGI_MEMCPY(selectedPSK.selectedALPN, pSSLSock->selectedALPN, (*(pSSLSock->selectedALPN)) + 1);
        }

        selectedPSK.selectedCipherSuiteId = pSSLSock->pHandshakeCipherSuite->cipherSuiteId;
        selectedPSK.pSelectedTlsVersion = (SSL3_MAJORVERSION << 8) | pSSLSock->sslMinorVersion;

        /* Store the session for use at resumption */
        if (NULL != SSL_sslSettings()->funcPtrServerSavePSK)
        {
            status = SSLSOCK_tls13SerializePsk(
                &selectedPSK, &pPsk, &pskLen);
            if (OK != status)
            {
                goto exit;
            }

            if (OK > (status = (MSTATUS)(SSL_sslSettings()->funcPtrServerSavePSK(SSL_findConnectionInstance(pSSLSock), 
                                (ubyte*)pSNI, sniLen, pPskIdentity, pskIdentityLen,
                                (ubyte*)pPsk, pskLen))))
            {   
                goto exit;
            }
        }
    }

    status = sendData(pSSLSock, SSL_HANDSHAKE, (sbyte *)pMessage, messageLen, TRUE);

exit:

    if (NULL != pNonce)
        DIGI_FREE((void**)&pNonce);

    if (NULL != pPsk)
        DIGI_FREE((void **) &pPsk);

    if (NULL != pPskIdentity)
        DIGI_FREE((void**) &pPskIdentity);

    if (pSessionTicket)
        DIGI_FREE((void**)&pSessionTicket);

    if (pMessage)
    {
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pMessage));
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SERVER_sendNewSessionTicket() returns status = ", status);

    return status;
}

#endif

/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static MSTATUS
processClientRsaKeyExchangeCore(SSLSocket* pSSLSock,
                             ubyte* pEncryptedPremasterSecret, ubyte2 mesgLen,
                             ubyte* pPlainText,
                             vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    ubyte4  realPlainTextLen;
    sbyte4  cipherTextLen;
    RSAKey* pRSAKey;
    ubyte   R[SSL_RSAPRESECRETSIZE]; /* Bleichenbacher attack */
    MSTATUS status;

    if (akt_rsa != pSSLSock->handshakeKey.type)
    {
        status = ERR_SSL_INVALID_KEY_TYPE;
        goto exit;
    }

    pRSAKey = pSSLSock->handshakeKey.key.pRSA;

    /* check that the actual record length matches the advertised record length */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &cipherTextLen,
                                                               pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &cipherTextLen)))
    {
        goto exit;
    }
#endif

    if (MOCANA_MAX_MODULUS_SIZE < cipherTextLen)
    {
        status = ERR_SSL_CLIENT_KEY_SIZE_TOO_LONG;
        goto exit;
    }

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        if ( cipherTextLen != mesgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
    }
    else
#endif
    {
        if (cipherTextLen != mesgLen)
        {
            if ((2 + cipherTextLen) != mesgLen)
            {
                status = ERR_SSL_INVALID_MSG_SIZE;
                goto exit;
            }

            pEncryptedPremasterSecret += 2; /* length */
        }
    }

    /* TLS 1.2 Bleichenbacher/Klima attacks: always generate the random data */
    R[0] = (pSSLSock->isDTLS) ? DTLS1_MAJORVERSION : SSL3_MAJORVERSION;
    R[1] = pSSLSock->clientHelloMinorVersion;
    pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_RSAPRESECRETSIZE - 2, R + 2);

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_RSA_decrypt(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                         pEncryptedPremasterSecret, pPlainText, &realPlainTextLen, pSSLSock->rngFun,
                         pSSLSock->rngFunArg, ppVlongQueue, pSSLSock->handshakeKey.type);
#else
    status = RSA_decrypt(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                         pEncryptedPremasterSecret, pPlainText, &realPlainTextLen, pSSLSock->rngFun,
                         pSSLSock->rngFunArg, ppVlongQueue);
#endif
    /* algorithm described in TLS 1.2*/
    if ((OK > status) ||
        (realPlainTextLen != SSL_RSAPRESECRETSIZE) )
    {
        if (OK > (status = DIGI_MEMCPY( pPlainText, R, SSL_RSAPRESECRETSIZE)))
            goto exit;
        else
            status = OK;
    }
    else if ( pPlainText[0] != R[0] || pPlainText[1] != R[1])
    {
        pPlainText[0] = R[0];
        pPlainText[1] = R[1];
        status = OK;
    }

exit:
    return status;

} /* processClientRsaKeyExchangeCore */
#endif


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static MSTATUS
processClientRsaKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                            ubyte **ppSecret, ubyte4 *pSecretLength,
                            vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    MSTATUS     status;

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, recLen, TRUE, (void **)(ppSecret))))
        goto exit;

    if (OK > (status = processClientRsaKeyExchangeCore(pSSLSock, pMessage, recLen, *ppSecret, ppVlongQueue)))
    {
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)(ppSecret));
        *pSecretLength = 0;
        goto exit;
    }

    *pSecretLength = SSL_RSAPRESECRETSIZE;

exit:
    return status;

} /* processClientRsaKeyExchange */
#endif


/*------------------------------------------------------------------*/
#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)  || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
processClientEccKeyExchangeCore(SSLSocket* pSSLSock, ECCKey* pECCKey,
                                ubyte* pMessage, ubyte2 recLen,
                                ubyte** ppSharedSecret,
                                sbyte4 *pSharedSecretLen, ubyte4 keyType)
#else
static MSTATUS
processClientEccKeyExchangeCore(SSLSocket* pSSLSock, ECCKey* pECCKey,
                                ubyte* pMessage, ubyte2 recLen,
                                ubyte** ppSharedSecret,
                                sbyte4 *pSharedSecretLen)
#endif
{
    /* the client key exchange contains the ECDH shared secret */
    MSTATUS             status;
    ubyte2              keyLen;

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    PrimeFieldPtr       pPF;
    PFEPtr              pQx = 0;
    PFEPtr              pQy = 0;
    pPF = EC_getUnderlyingField( pECCKey->pCurve);
#endif
    /* extract the generated public key from the message */
    /* redundant byte length */
    keyLen = *pMessage++;
    if ( keyLen != recLen - 1)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(pSSLSock->hwAccelCookie)
                                                                                      pECCKey,
                                                                                      pMessage, keyLen,
                                                                                      ppSharedSecret,
                                                                                      (ubyte4 *)pSharedSecretLen,
                                                                                      1/* X co-ordinate only */,
                                                                                      NULL, g_keyType)))
    {
        goto exit;
    }
#else
    if ( OK > ( status = EC_byteStringToPoint(pECCKey->pCurve, pMessage, keyLen, &pQx, &pQy)))
        goto exit;

    /* generate the shared secret by multiplying the public key by our private key*/
    if ( OK > ( status = ECDH_generateSharedSecretAux(pECCKey->pCurve, pQx, pQy, pECCKey->k,
                                                      ppSharedSecret, pSharedSecretLen,
                                                      1))) /* X coordinate only */
    {
        goto exit;
    }
#endif

exit:

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    PRIMEFIELD_deleteElement( pPF, &pQx);
    PRIMEFIELD_deleteElement( pPF, &pQy);
#endif

    return status;

} /* processClientEccKeyExchangeCore */


/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
processClientEccKeyExchange(SSLSocket* pSSLSock, ECCKey* pECCKey,
                            ubyte* pMessage, ubyte2 recLen, ubyte4 keyType,
                            ubyte **ppSecret, ubyte4 *pSecretLength)
#else
static MSTATUS
processClientEccKeyExchange(SSLSocket* pSSLSock, ECCKey* pECCKey,
                            ubyte* pMessage, ubyte2 recLen,
                            ubyte **ppSecret, ubyte4 *pSecretLength)
#endif
{
    /* the client key exchange contains the ECDH shared secret */
    MSTATUS             status;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > ( status = processClientEccKeyExchangeCore(pSSLSock, pECCKey,
                                                        pMessage, recLen,
                                                        ppSecret, (sbyte4 *) pSecretLength,
                                                        keyType)))
    {
        goto exit;
    }
#else
    if (OK > ( status = processClientEccKeyExchangeCore(pSSLSock, pECCKey,
                                                        pMessage, recLen,
                                                        ppSecret, (sbyte4 *) pSecretLength)))
    {
        goto exit;
    }
#endif

exit:
    return status;

} /* processClientEccKeyExchange */
#endif /* defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) ||
        defined( __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)  ||
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)*/


/*------------------------------------------------------------------*/
#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))

static MSTATUS
processClientEcdhKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage,
                         ubyte2 recLen, ubyte **ppSecret, ubyte4 *pSecretLength,
                         vlong **ppVlongQueue)
{
    /* the client key exchange contains the ECDH shared secret */
    if (akt_ecc != pSSLSock->handshakeKey.type)
    {
        return ERR_SSL_INVALID_KEY_TYPE;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    return processClientEccKeyExchange( pSSLSock,
                                        pSSLSock->handshakeKey.key.pECC,
                                        pMessage, recLen,
                                        pSSLSock->handshakeKey.type,
                                        ppSecret, pSecretLength);
#else
    return processClientEccKeyExchange( pSSLSock,
                                        pSSLSock->handshakeKey.key.pECC,
                                        pMessage, recLen,
                                        ppSecret, pSecretLength);
#endif
} /* processClientEcdhKeyExchange */
#endif /* defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) */


/*------------------------------------------------------------------*/

#if (defined( __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) ||   \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)    )

static MSTATUS
processClientEcdheKeyExchange(SSLSocket* pSSLSock, ubyte *pMessage,
                              ubyte2 recLen, ubyte **ppSecret, ubyte4 *pSecretLength,
                              vlong **ppVlongQueue)
{
    if (akt_ecc != pSSLSock->ecdheKey.type)
    {
        return ERR_BAD_KEY_TYPE;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    return processClientEccKeyExchange( pSSLSock,
                                        pSSLSock->ecdheKey.key.pECC,
                                        pMessage, recLen,
                                        pSSLSock->handshakeKey.type,
                                        ppSecret, pSecretLength);
#else
    return processClientEccKeyExchange( pSSLSock,
                                        pSSLSock->ecdheKey.key.pECC,
                                        pMessage, recLen,
                                        ppSecret, pSecretLength);
#endif
}

#endif /* defined( __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)  ||
            defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)*/

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))
static MSTATUS
processClientEcdhePskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                                 ubyte **ppSecret, ubyte4 *pSecretLength,
                                 vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    ubyte*      sharedSecret        = 0;
    sbyte4      sharedSecretLen;
    ubyte2      identityLengthPSK;
    ubyte*      pIdentityPSK;
    ubyte4      pskLength           = 0;
    MSTATUS     status;


    /* extract PSK identity */
    identityLengthPSK = getShortValue(pMessage);
    pIdentityPSK      = 2 + pMessage;

    if ((2 + identityLengthPSK) > recLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* skip past PSK identity */
    pMessage += (2 + identityLengthPSK);
    recLen    = (ubyte2)(recLen - (2 + identityLengthPSK));

    if (akt_ecc != pSSLSock->ecdheKey.type)
    {
        return ERR_BAD_KEY_TYPE;
    }

    /* compute premaster secret */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = processClientEccKeyExchangeCore(pSSLSock, pSSLSock->ecdheKey.key.pECC,
                                                       pMessage, recLen,
                                                       &sharedSecret,
                                                       &sharedSecretLen,
                                                       pSSLSock->ecdheKey.type)))
    {
        goto exit;
    }
#else
    if (OK > (status = processClientEccKeyExchangeCore(pSSLSock, pSSLSock->ecdheKey.key.pECC,
                                                       pMessage, recLen,
                                                       &sharedSecret,
                                                       &sharedSecretLen)))
    {
        goto exit;
    }
#endif

    /* allocate buffer for key material */
    if (NULL == (*ppSecret = (ubyte*) MALLOC(2 + sharedSecretLen + 2 + SSL_PSK_MAX_LENGTH)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set length for secret */
    setShortValue(*ppSecret, (ubyte2) sharedSecretLen);
    (void) DIGI_MEMCPY(*ppSecret+2, sharedSecret, sharedSecretLen);

    /* look up PSK */
    if (NULL != SSL_sslSettings()->funcPtrLookupPSK)
    {
        status = (MSTATUS)SSL_sslSettings()->funcPtrLookupPSK(SSL_findConnectionInstance(pSSLSock),
                                                              pIdentityPSK, identityLengthPSK,
                                                              *ppSecret+4+sharedSecretLen,
                                                              &pskLength);
    }

    if ((OK <= status) && (SSL_PSK_MAX_LENGTH < pskLength))
    {
        status = ERR_BUFFER_OVERFLOW;
    }

    if (OK > status)
        goto exit;

    /* set length for psk */
    setShortValue(*ppSecret+2+sharedSecretLen, (ubyte2)(pskLength));

    *pSecretLength = 2 + sharedSecretLen + 2 + pskLength;
exit:
    if (NULL != sharedSecret)
        FREE(sharedSecret);

    return status;

} /* processClientEcdhePskKeyExchange */

#endif /* (defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))
static MSTATUS
processClientRsaPskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                               ubyte **ppSecret, ubyte4 *pSecretLength,
                               vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    ubyte*      pKeyMaterialTemp;
    ubyte2      identityLengthPSK;
    ubyte*      pIdentityPSK;
    ubyte4      pskLength = 0;
    sbyte4      cipherTextLen;
    MSTATUS     status;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA,                                                               &cipherTextLen, pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA, &cipherTextLen)))
        goto exit;
#endif

    /* allocate buffer for key material */
    if (NULL == (pKeyMaterialTemp = *ppSecret = (ubyte*) MALLOC((2048 / 8) + 2 + SSL_PSK_MAX_LENGTH)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* extract PSK identity */
    identityLengthPSK = getShortValue(pMessage);
    pIdentityPSK      = 2 + pMessage;

    if ((2 + identityLengthPSK) > recLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* skip past PSK identity */
    pMessage += (2 + identityLengthPSK);
    recLen    = (ubyte2)(recLen - (2 + identityLengthPSK));

    /* set length for secret */
    *pKeyMaterialTemp = 0;
    pKeyMaterialTemp++;
    *pKeyMaterialTemp = (ubyte)SSL_RSAPRESECRETSIZE;
    pKeyMaterialTemp++;

    /* decrypt premaster secret */
    if (OK > (status = processClientRsaKeyExchangeCore(pSSLSock, pMessage, recLen, pKeyMaterialTemp, ppVlongQueue)))
        goto exit;

    pKeyMaterialTemp += SSL_RSAPRESECRETSIZE;

    /* look up PSK */
    if (NULL != SSL_sslSettings()->funcPtrLookupPSK)
        status = (MSTATUS)SSL_sslSettings()->funcPtrLookupPSK(SSL_findConnectionInstance(pSSLSock), pIdentityPSK, identityLengthPSK, 2 + pKeyMaterialTemp, &pskLength);

    if ((OK <= status) && (SSL_PSK_MAX_LENGTH < pskLength))
    {
        status = ERR_BUFFER_OVERFLOW;
    }

    if (OK > status)
        goto exit;

    /* set length for psk */
    setShortValue(pKeyMaterialTemp, (ubyte2)(pskLength));    pKeyMaterialTemp += 2;

    *pSecretLength = 2 + SSL_RSAPRESECRETSIZE + 2 + pskLength;

exit:
    return status;

} /* processClientRsaPskKeyExchange */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS
processClientDiffieHellmanCore(SSLSocket* pSSLSock,
                               ubyte* pMessage, ubyte2 recLen,
                               ubyte** ppRetK, ubyte4 *pRetLenK,
                               vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    ubyte*  pE = pMessage;
    ubyte4  lenE;
    ubyte*  pK = NULL;
    ubyte4  lenK;
    MSTATUS status;

    /* get length of Yc */
    lenE = getShortValue(pE);
    pE += 2;

    /* validate record length against length of Yc */
    if ((lenE + 2) != recLen)
    {
        status = ERR_BAD_CLIENT_E;
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_DH_MODES__
    status = CRYPTO_INTERFACE_DH_keyAgreementScheme(MOC_DH(pSSLSock->hwAccelCookie) DH_EPHEMERAL, g_pRandomContext, NULL, pSSLSock->pDHcontext, NULL, 0, pE, lenE, &pK, &lenK); 
#else
    status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, g_pRandomContext, pE, lenE, &pK, &lenK, NULL);
#endif
    if (OK != status)
        goto exit;
#else
    /* extract Yc, store in e */
    if (OK > (status = VLONG_vlongFromByteString(pE, lenE, &(pSSLSock->pDHcontext->dh_e), ppVlongQueue)))
        goto exit;

    /* calculate shared secret */
    if (OK > (status = DH_computeKeyExchange(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, ppVlongQueue)))
        goto exit;

    /* allocate buffer for shared secret */
    lenK  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_k)) / 8;

    if (NULL == (pK = (ubyte*) MALLOC(lenK)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* convert shared secret (k) into something digestible */
    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_k, pK, lenK)))
        goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    *ppRetK   = pK;     pK = NULL;
    *pRetLenK = lenK;

exit:
    if (NULL != pK)
        FREE(pK);

    return status;

} /* processClientDiffieHellmanCore */

#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS
processClientDiffieHellmanKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                                      ubyte **ppSecret, ubyte4 *pSecretLength,
                                      vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    MSTATUS     status;

    if (OK > (status = processClientDiffieHellmanCore(pSSLSock, pMessage, recLen, ppSecret, pSecretLength, ppVlongQueue)))
        goto exit;

exit:
    return status;

} /* processClientDiffieHellmanKeyExchange */

#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))
static MSTATUS
processClientDiffieHellmanPskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                                         ubyte **ppSecret, ubyte4 *pSecretLength,
                                         vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    ubyte*      pK                  = NULL;
    ubyte4      lenK;
    ubyte2      identityLengthPSK;
    ubyte*      pIdentityPSK;
    ubyte4      pskLength           = 0;
    MSTATUS     status;

    /* extract PSK identity */
    identityLengthPSK = getShortValue(pMessage);
    pIdentityPSK      = 2 + pMessage;

    if ((2 + identityLengthPSK) > recLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* skip past PSK identity */
    pMessage += (2 + identityLengthPSK);
    recLen    = (ubyte2)(recLen - (2 + identityLengthPSK));

    /* compute premaster secret */
    if (OK > (status = processClientDiffieHellmanCore(pSSLSock, pMessage,
                                                      recLen, &pK, &lenK,
                                                      ppVlongQueue)))
    {
        goto exit;
    }

    /* allocate buffer for key material */
    if (NULL == (*ppSecret = (ubyte*) MALLOC(2 + lenK + 2 + SSL_PSK_MAX_LENGTH)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set length for secret */
    setShortValue(*ppSecret, (ubyte2) lenK);
    /* dup pK */
    if (OK > (status = DIGI_MEMCPY(*ppSecret+2, pK, lenK)))
        goto exit;

    /* look up PSK */
    if (NULL != SSL_sslSettings()->funcPtrLookupPSK)
    {
        status = (MSTATUS)SSL_sslSettings()->funcPtrLookupPSK(SSL_findConnectionInstance(pSSLSock),
                                                              pIdentityPSK,
                                                              identityLengthPSK,
                                                              *ppSecret + lenK + 4,
                                                              &pskLength);
    }
    if ((OK <= status) && (SSL_PSK_MAX_LENGTH < pskLength))
    {
        status = ERR_BUFFER_OVERFLOW;
    }

    if (OK > status)
        goto exit;

    /* set length for psk */
    setShortValue(*ppSecret+2+lenK, (ubyte2)(pskLength));
    *pSecretLength = 2 + lenK + 2 + pskLength;

exit:
    if (NULL != pK)
        FREE(pK);

    return status;

} /* processClientDiffieHellmanPskKeyExchange */

#endif /* (defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))
static MSTATUS
processClientPskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                            ubyte **ppSecret, ubyte4 *pSecretLength,
                            vlong **ppVlongQueue)
{
    /* the client key exchange contains the encrypted premaster secret */
    ubyte*      pKeyMaterialTemp;
    ubyte2      identityLengthPSK;
    ubyte*      pIdentityPSK;
    ubyte4      pskLength           = 0;
    MSTATUS     status = ERR_SSL_PSK_BAD_CONFIG;
    MOC_UNUSED(ppVlongQueue);

    /* extract PSK identity */
    identityLengthPSK = getShortValue(pMessage);
    pIdentityPSK      = 2 + pMessage;

    if ((2 + identityLengthPSK) > recLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* skip past PSK identity */
    pMessage += (2 + identityLengthPSK);
    recLen    = (ubyte2)(recLen - (2 + identityLengthPSK));

    /* allocate buffer for key material */
    if (NULL == (pKeyMaterialTemp = *ppSecret = (ubyte*) MALLOC(2 + SSL_PSK_MAX_LENGTH + 2 + SSL_PSK_MAX_LENGTH)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* look up PSK */
    if (NULL != SSL_sslSettings()->funcPtrLookupPSK)
        status = (MSTATUS)SSL_sslSettings()->funcPtrLookupPSK(SSL_findConnectionInstance(pSSLSock), pIdentityPSK, identityLengthPSK, 2 + pKeyMaterialTemp, &pskLength);

    if ((OK <= status) && (SSL_PSK_MAX_LENGTH < pskLength))
    {
        status = ERR_BUFFER_OVERFLOW;
    }


    if (OK > status)
        goto exit;


    /* set length for secret */
    setShortValue(pKeyMaterialTemp, (ubyte2)(pskLength));    pKeyMaterialTemp += 2;

    /* move psk */
    /* DIGI_MEMCPY src and dst always non-NULL, no return check needed */
    (void) DIGI_MEMCPY(2 + pskLength + 2 + *ppSecret, 2 + *ppSecret, pskLength);

    /* clear "other" key material */
    DIGI_MEMSET(2 + *ppSecret, 0x00, pskLength);
    pKeyMaterialTemp += pskLength;

    /* set length for psk */
    setShortValue(pKeyMaterialTemp, (ubyte2)(pskLength));    pKeyMaterialTemp += 2;
    *pSecretLength = 2 + pskLength + 2 + pskLength;

exit:
    return status;

} /* processClientPskKeyExchange */

#endif /* (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SRP__))
static MSTATUS
processClientSrpKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen,
                            ubyte **ppSecret, ubyte4 *pSecretLength,
                            vlong **ppVlongQueue)

{
    /* the client key exchange contains the A value */
    sbyte4      premasterSecretLen;
    ubyte2      aLen;
    ubyte*      pA;
    MSTATUS     status;

    /* extract  client A value */
    aLen = getShortValue(pMessage);
    pA   = 2 + pMessage;

    if ((2 + aLen) > recLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    if (OK > ( status = SSL_SOCK_SRPServerPremasterSecret(pSSLSock, pA, aLen,
                                                          ppSecret,
                                                          (sbyte4 *) pSecretLength,
                                                          ppVlongQueue)))
    {
        goto exit;
    }

exit:
    return status;

} /* processClientSrpKeyExchange */

#endif /* (defined(__ENABLE_DIGICERT_SSL_SRP__)) */


/*------------------------------------------------------------------*/

static MSTATUS
handleServerHandshakeMessages(SSLSocket* pSSLSock)
{
    ubyte2  recordLen;
    sbyte*  pMsg        = pSSLSock->pReceiveBuffer;
#if defined(__ENABLE_DIGICERT_TLS13__)
    ubyte*  pTempMsg = NULL;
#endif

    vlong*  pVlongQueue = NULL;
    ubyte4  sizeofHandshakeHeader;
    MSTATUS status      = OK;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    recordLen = (ubyte2)(pSSLSock->recordSize);

#if defined(__ENABLE_DIGICERT_TLS13__)
    /* TLS 1.3 can fragment a handshake message into multiple encrypted records;
     * First fragment of a handshake message was read and partialHandshakeRecord flag is set;
     * Process the next packet record
     */
    if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
         (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
         (pSSLSock->isPartialHandshakeRecord) && (pSSLSock->pPartialHandshakeRecordBuffer != NULL))
    {
        /* Get the handshakeRecLen from the first partial read */
        ubyte2 handshakeRecLen = getMediumValue(((SSLHandshakeHeader*)pSSLSock->pPartialHandshakeRecordBuffer)->handshakeSize);

        /* This new packet read is not the last fragment; Append this to the partialHandshakeRecord buffer */
        if (handshakeRecLen > (recordLen + pSSLSock->partialHandshakeRecordBufferLen - sizeofHandshakeHeader))
        {
            if (OK > (status = DIGI_MEMCPY((void *)(pSSLSock->pPartialHandshakeRecordBuffer + pSSLSock->partialHandshakeRecordBufferLen),
                                          pMsg, recordLen)))
            {
                goto exit;
            }

            pSSLSock->partialHandshakeRecordBufferLen += recordLen;
            status = OK;
            goto exit;
        }
        else
        {
            /* This is the last fragment Handshake message
             * Note : This last packet might also have the subsequent handshake messages;
             */
            if (OK > (status = DIGI_MALLOC((void **)&pTempMsg, pSSLSock->partialHandshakeRecordBufferLen + recordLen)))
            {
                goto exit;
            }

            /* Copy the previous fragmented handshake records */
            if (OK > (status = DIGI_MEMCPY((void *)pTempMsg, pSSLSock->pPartialHandshakeRecordBuffer, pSSLSock->partialHandshakeRecordBufferLen)))
            {
                goto exit;
            }

            /* Copy the latest packet */
            if (OK > (status = DIGI_MEMCPY((void *)(pTempMsg + pSSLSock->partialHandshakeRecordBufferLen), pMsg, recordLen)))
            {
                goto exit;
            }

            /* Set pMsg and recordLen and process the handshake messages */
            pMsg = (sbyte*)pTempMsg;
            recordLen += pSSLSock->partialHandshakeRecordBufferLen;

            /* We read all the fragments of handshake message; Reset the flag and free the buffer */
            pSSLSock->isPartialHandshakeRecord = FALSE;
            pSSLSock->partialHandshakeRecordBufferLen = 0;
            if (pSSLSock->pPartialHandshakeRecordBuffer != NULL)
            {
                DIGI_FREE((void **)&pSSLSock->pPartialHandshakeRecordBuffer);
            }
        }
    }
#endif

    while ((status >= OK) && (recordLen > 0))
    {
        ubyte2 handshakeRecLen;
        sbyte4 handshakeType;
        ubyte* pSHSH = (ubyte*)pMsg;

        if (sizeofHandshakeHeader > recordLen)
        {
            status = ERR_SSL_PROTOCOL_BAD_LENGTH;
            break;
        }

        /* advance pointers */
        pMsg += sizeofHandshakeHeader;
        recordLen -= sizeofHandshakeHeader;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
            handshakeRecLen = getMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize);
            handshakeType = ((DTLSHandshakeHeader*)pSHSH)->handshakeType;
        } else
#endif
        {
            handshakeRecLen = getMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize);
            handshakeType = ((SSLHandshakeHeader*)pSHSH)->handshakeType;
        }

        /* check length */
        if ((ubyte2)handshakeRecLen > (ubyte2)recordLen)
        {
#ifdef __ENABLE_DIGICERT_TLS13__
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                pSSLSock->isPartialHandshakeRecord = TRUE;

                /* Copy the whole buffer with handshake header */
                pSSLSock->partialHandshakeRecordBufferLen = recordLen + sizeofHandshakeHeader;

                /* Free if not null, before allocating */
                if (pSSLSock->pPartialHandshakeRecordBuffer != NULL)
                {
                    DIGI_FREE((void **)&(pSSLSock->pPartialHandshakeRecordBuffer));
                }

                /* Allocate buffer to accomodate sizeofHandshakeHeader + handshakeRecLen
                 *
                 * sizeofHandshakeHeader: Needed to store the handshake header
                 * handshakeRecLen: Needed to store the entire handshake message
                 */
                if (OK > (status = DIGI_MALLOC((void **)&pSSLSock->pPartialHandshakeRecordBuffer,
                                              sizeofHandshakeHeader + handshakeRecLen)))
                {
                    goto exit;
                }

                if (OK > (status = DIGI_MEMCPY((void *)pSSLSock->pPartialHandshakeRecordBuffer, pSHSH,
                                              pSSLSock->partialHandshakeRecordBufferLen)))
                {
                    goto exit;
                }

                status = OK;
                goto exit;
            }
            else
#endif
            {
                status = ERR_SSL_PROTOCOL_BAD_LENGTH;
                break;
            }
        }

        status = ERR_SSL_PROTOCOL_SERVER;

        switch (handshakeType)
        {
            case SSL_CERTIFICATE:
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
                if (((SSL_BEGIN == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) && (pSSLSock->isMutualAuthNegotiated))
#if defined(__ENABLE_DIGICERT_TLS13__)
                    || ((SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) && (pSSLSock->postHandshakeAuth))
#endif /* __ENABLE_DIGICERT_TLS13__ */
                   )
                {
                    intBoolean isCertRequired = ((pSSLSock->runtimeFlags & SSL_FLAG_REQUIRE_MUTUAL_AUTH) ? TRUE : FALSE);

                    status = processCertificate(pSSLSock, pSHSH, handshakeRecLen, isCertRequired);
                    if (OK > status)
                        break;

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
                    if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                    {
                        /* save least significant byte of epoch and seqNum in record List */
                        status = addReceivedRecord(pSSLSock);
                        if (OK != status)
                            break;

                        /* We need a new server traffic secret before adding
                           anything more to the transcript hash */
                        status = SSLSOCK_pskCalcApplicationTrafficSecret(pSSLSock);
                        if (OK != status)
                            break;

                        status = SSLSOCK_setServerTrafficKeyMaterial(
                            pSSLSock, pSSLSock->pServerApplicationTrafficSecret);
                        if (OK != status)
                            break;
                    }
#endif
                    addToHandshakeHash(pSSLSock, (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);

                    if (akt_undefined == pSSLSock->mutualAuthKey.type)
                    {
                        pSSLSock->isMutualAuthNegotiated = FALSE;
                        pSSLSock->runtimeFlags &= ~(SSL_FLAG_REQUIRE_MUTUAL_AUTH);
                    }
                }
                else
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
                {
                    status = ERR_SSL_MUTUAL_AUTHENTICATION_NOT_REQUESTED;
                }
                break;

            case SSL_CLIENT_KEY_EXCHANGE:
                if (NULL == pSSLSock->pHandshakeCipherSuite)
                    break;

                if ((SSL3_MINORVERSION == pSSLSock->sslMinorVersion) &&
                    (SSL_BEGIN == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&
                    (pSSLSock->isMutualAuthNegotiated))
                {
                    pSSLSock->isMutualAuthNegotiated = FALSE;
                }

                /* mutual authentication required trumps all other combinations */
                if ((SSL_FLAG_REQUIRE_MUTUAL_AUTH == (pSSLSock->runtimeFlags & SSL_FLAG_REQUIRE_MUTUAL_AUTH)) &&
                    (SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)))
                {
                    pSSLSock->isMutualAuthNegotiated = TRUE;
                }

                if (((SSL_BEGIN       == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) && (!pSSLSock->isMutualAuthNegotiated)) ||
                     (SSL_CERTIFICATE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) )
                {
                    ubyte*  pMessage = pSHSH + sizeofHandshakeHeader;
                    ubyte2  mesgLen  = handshakeRecLen;
                    ubyte*  pSecret   = NULL;
                    ubyte4  secretLen = 0;

                    if (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->ProcessClientKEX)
                    {
                        /* process kex & auth */
                        status = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->ProcessClientKEX(pSSLSock, pMessage, mesgLen,
                                                                                                   &pSecret, &secretLen, &pVlongQueue);
                        if (OK > status)
                            break;
                    }

                    addToHandshakeHash(pSSLSock, (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);

                    status = SSL_SOCK_generateKeyMaterial(pSSLSock, pSecret, secretLen); 

                    if (pSecret != NULL)
                        DIGI_FREE((void **)&pSecret);
                }
                else
                {
                    status = ERR_SSL_MUTUAL_AUTHENTICATION_REQUEST_IGNORED;
                }

                break;

            case SSL_CLIENT_CERTIFICATE_VERIFY:
                {
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
                    ubyte correctState = 0;
#if defined(__ENABLE_DIGICERT_TLS13__)
                    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                    {
                        /* Post Handshake Auth or During Handshake Auth */
                        if ((SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                            (SSL_CERTIFICATE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
                        {
                            correctState = 1;
                        }
                    }
                    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
                    {
                        correctState = (SSL_CLIENT_KEY_EXCHANGE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ? 1 : 0;
                    }

                    if ((1 == correctState) && (pSSLSock->isMutualAuthNegotiated))
                    {
                        status = processCertificateVerify(pSSLSock, pSSLSock->mutualAuthKey, pSHSH, handshakeRecLen, &pVlongQueue);

                        if (OK > status)
                            break;

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
                        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                        {
                            /* upon successful verify, save least significant byte of epoch and seqNum in record List */
                            status = addReceivedRecord(pSSLSock);
                            if (OK > status)
                                break;
                        }
#endif
                        addToHandshakeHash(pSSLSock, (ubyte *)pSHSH,
                                           handshakeRecLen + sizeofHandshakeHeader);

                        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_CLIENT_CERTIFICATE_VERIFY;
                    }
                    else
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
                    {
                        status = ERR_SSL_MUTUAL_AUTHENTICATION_NOT_REQUESTED;
                    }

                    break;
                }
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
            case SSL_CLIENT_END_OF_EARLY_DATA:
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                {
                    /* RFC 9147 Section 5.6 "EndOfEarlyData message is omitted both from the 
                       wire and the handshake transcript." Don't accept */
                    status = ERR_SSL_PROTOCOL;
                    goto exit;
                }
                else
#endif
                {
                    pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_SET_END_OF_EARLY_DATA_RX(pSSLSock);
                    if (1 == pSSLSock->earlyDataExtAccepted)
                    {
                        /*
                        RFC #8446 Section 5.1
                        Handshake messages MUST not span key changes.  Implementations
                        MUST verify that all messages immediately preceding a key change
                        align with a record boundary; if not, then they MUST terminate the
                        connection with an "unexpected_message" alert.  Because the
                        ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
                        messages can immediately precede a key change, implementations
                        MUST send these messages in alignment with a record boundary.
                        */
                        /* TODO */
                    }
                    else
                    {
                        /* RFC #8446 Section 4.5
                        * If the server does not send an "early_data"
                        * extension in EncryptedExtensions, then the client MUST NOT send an
                        * EndOfEarlyData message.
                        * If pSSLSock->earlyDataExtAccepted is 1, then only server would have sent
                        * early_data extension.
                        */
                        status = ERR_SSL_PROTOCOL;
                        goto exit;
                    }

                    addToHandshakeHash(pSSLSock,
                            (ubyte *)pSHSH,
                            handshakeRecLen + sizeofHandshakeHeader);
                    status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock,
                                        pSSLSock->pClientHandshakeTrafficSecret);
                }
                break;
#endif

            case SSL_FINISHED:
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                /* RFC 9147 Sec 5.6 No EndOfEarlyData message needed for DTLS */
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
                if (!pSSLSock->isDTLS || DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
                {
                    if ((1 == pSSLSock->earlyDataExtAccepted) && (0 == TLS13_0RTT_GET_END_OF_EARLY_DATA_RX(pSSLSock)))
                    {
                        /*
                        *  RFC #8446 Section 4.5
                        *  If the server sent an "early_data" extension in EncryptedExtensions,
                        *  the client MUST send an EndOfEarlyData message after receiving the
                        *  server Finished

                        *  Server received Finished message from client, but not the endOfEarlyData message;
                        *  This is a fatal error and send back an alert
                        */
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_UNEXPECTED_MESSAGE, SSLALERTLEVEL_FATAL);
#endif
                        break;
                    }
                }
#endif
                if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                    ((pSSLSock->isDTLS) || ((TLS13_MINORVERSION > pSSLSock->sslMinorVersion) &&
                     (SSL_EXPECTING_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))))
                {

                    status = processFinished(pSSLSock, pSHSH, handshakeRecLen);

                    if (OK > status)
                        break;

                    /* For 1.3 create the traffic secrets before adding
                       anything more to the handshake hash. For mutual
                       auth we already did the first two calls in the 
                       SSL_CERTIFICATE step */
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
                    if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                    {
                        releaseRetransmissionBuffer(pSSLSock);
                        /* save least significant byte of epoch and seqNum in record List */
                        status = addReceivedRecord(pSSLSock);
                        if (OK != status)
                            break;

                        if (pSSLSock->isPSKSelected || !pSSLSock->isMutualAuthNegotiated)
                        {
                            status = SSLSOCK_pskCalcApplicationTrafficSecret(pSSLSock);
                            if (OK != status)
                                break;

                            status = SSLSOCK_setServerTrafficKeyMaterial(
                                pSSLSock, pSSLSock->pServerApplicationTrafficSecret);
                            if (OK != status)
                                break;
                        }

                        status = SSLSOCK_setClientTrafficKeyMaterial(
                            pSSLSock, pSSLSock->pClientApplicationTrafficSecret);
                        if (OK != status)
                            break;
                    }
#endif /* __ENABLE_DIGICERT_TLS13__ */

                    addToHandshakeHash(pSSLSock, (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);
                
#ifdef __ENABLE_DIGICERT_TLS13__
                    /* For DTLS we don't handle session ticket until after the send ACK */
                    if (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                    {
                        if (!(pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST)))
                        {
                            /* Create a copy of the transcript hash. For post
                             * handshake messages, only the transcript hash
                             * during the handshake is updated. Post handshake
                             * messages do not include other post handshake
                             * messages.
                             *
                             * Example:
                             *
                             *   1st post handshake mutual auth message
                             *     Transcript-Hash(Handshake messages)
                             *     Transcript-Hash(Post handshake mutual auth 1)
                             *
                             *   2nd post handshake mutual auth message
                             *     Transcript-Hash(Handshake messages)
                             *     Transcript-Hash(Post handshake mutual auth 2)
                             *
                             * The 2nd post handshake message does not update
                             * the transcript hash with the 1st post handshake
                             * message.
                             */
                            status = MEM_POOL_getPoolObject(
                                &(pSSLSock->hashPool),
                                (void **) &(pSSLSock->pHandshakeHashCtx));
                            if (OK != status)
                            {
                                break;
                            }

#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            status = CRYPTO_INTERFACE_cloneHashCtx( MOC_HASH(pSSLSock->hwAccelCookie)
                                pSSLSock->pHashCtx, pSSLSock->pHandshakeHashCtx,
                                pSSLSock->hashPool.poolObjectSize);
#else
                            status = DIGI_MEMCPY(
                                pSSLSock->pHandshakeHashCtx, pSSLSock->pHashCtx,
                                pSSLSock->hashPool.poolObjectSize);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
                            if (OK != status)
                            {
                                break;
                            }
#else
                            CopyCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHandshakeHashCtx,
                                pSSLSock->pHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif /* ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__ */

                            status = SSLSOCK_setClientTrafficKeyMaterial(
                                pSSLSock, pSSLSock->pClientApplicationTrafficSecret);
                            if (OK != status)
                                break;

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)

                            /* Calculate the master_resumption_secret only once after completing the handshake
                             * and receiving the Finished message
                             */
                            if (OK > (status = SSLSOCK_pskCalcResumptionMasterSecret(pSSLSock,
                                                pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo)))
                            {
                                break;
                            }

                            if (pSSLSock->roleSpecificInfo.server.enableTls13SessionTickets || TRUE == pSSLSock->roleSpecificInfo.server.sendSessionTicket)
                            {
                                ubyte4 i = 0;
                                for (i = 0; i < pSSLSock->roleSpecificInfo.server.numOfSessionTickets; i++)
                                {
                                    if (OK > (status = SSL_SERVER_sendNewSessionTicket(pSSLSock)))
                                        break;
                                }

                                if (OK > status)
                                {
                                    break;
                                }
                                /* Since the ticket was sent once, let the client request if it needs another ticket */
                                pSSLSock->roleSpecificInfo.server.sendSessionTicket = FALSE;
                                pSSLSock->roleSpecificInfo.server.enableTls13SessionTickets = FALSE;
                            }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
                        }
                        else
                        {
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
                            /* If server sent post handshake auth message,
                             * client responded with certificate, certificate verify and Finished
                             * messages, reset the flag; Post Handshake authentication is complete.
                             */
                            pSSLSock->postHandshakeMessages &= ~(1 << CERTIFICATE_REQUEST);
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pHashCtx);
#endif

                            /* Restore the original transcript hash (which
                             * should only contain the handshake messages).
                             */
#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__ 
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            status = CRYPTO_INTERFACE_cloneHashCtx( MOC_HASH(pSSLSock->hwAccelCookie)
                                pSSLSock->pHandshakeHashCtx, pSSLSock->pHashCtx,
                                pSSLSock->hashPool.poolObjectSize);
#else
                            status = DIGI_MEMCPY(
                                pSSLSock->pHashCtx, pSSLSock->pHandshakeHashCtx,
                                pSSLSock->hashPool.poolObjectSize);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
                            if (OK != status)
                            {
                                break;
                            }
#else
                            CopyCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx,
                                pSSLSock->pHandshakeHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif /* ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__ */
                        }
                    }
#endif /* __ENABLE_DIGICERT_TLS13__ */
                    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_BEGIN;
                }
                else
                {
                    status = ERR_SSL_MUTUAL_AUTHENTICATION_REQUEST_IGNORED;
                }
                break;

#if defined(__ENABLE_DIGICERT_TLS13__)
            case SSL_KEY_UPDATE:
                /* After Server processes Finished message from Client, remote state is set to SSL_BEGIN */
                if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                     (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
                    (SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) != SSL_FINISHED))
                {
                    /* If we recieve this message before SSL_FINISHED, we abort with an illegal_parameter alert */
                    status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_UNEXPECTED_MESSAGE, SSLALERTLEVEL_FATAL);
#endif

                    break;
                }
                status = processKeyUpdateRequest(pSSLSock, (ubyte*)pSHSH, handshakeRecLen);
                break;
#endif /*  __ENABLE_DIGICERT_TLS13__ */

            default:
                status = ERR_SSL_PROTOCOL_BAD_STATE;
                break;
        }

        /* if OK, advance state */
        if (status >= OK)
        {
            /* before advancing the state, we check if the routines called
             did not advance it already to a further state (client resuming session
             for example treats a SERVERHELLO as SERVERHELLODONE) */
#if defined(__ENABLE_DIGICERT_TLS13__)
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                /* Do NOT advance the remote state for KeyUpdate messages */
                if (SSL_KEY_UPDATE != handshakeType)
                {
                    if (SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) < handshakeType)
                    {
                        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = handshakeType;
                    }
                }
            }
            else
#endif
            {
                if (SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) < handshakeType)
                {
                    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = handshakeType;
                }
            }

            if (recordLen < handshakeRecLen)
            {
                status = ERR_SSL_PROTOCOL_BAD_LENGTH;
                break;
            }

            /* advance pointers */
            pMsg += handshakeRecLen;
            recordLen = (ubyte2)(recordLen - handshakeRecLen);
        }
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
exit:

    if (pTempMsg != NULL)
    {
        DIGI_FREE((void **)&pTempMsg);
    }
#endif

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"handleServerHandshakeMessages() returns status = ", status);

    /* function always returns OK, no need to check here */
    (void) VLONG_freeVlongQueue(&pVlongQueue);
    return status;

} /* handleServerHandshakeMessages */

/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_serverHandshakeSSL(SSLSocket* pSSLSock, intBoolean isWriter)
{
#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))
    sbyte4  doRehandshake       = FALSE;
#ifdef __ENABLE_DIGICERT_SSL_NEW_HANDSHAKE__
    sbyte4  doSessionResumption = FALSE;
#endif
#endif
    MSTATUS status = OK;
    sbyte4  available = 0;

    if(!pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* handle any data pending on a send */
    if ((NULL != pSSLSock->pOutputBuffer) &&
        (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)) )
    {
        goto exit;
    }

    switch (SSL_HANDSHAKE_STATE(pSSLSock))
    {
#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))
        case kSslOpenState:                                         /* rehandshake support */
        {
            if (TRUE == isWriter)
                break;

            SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_BEGIN;

            doRehandshake = TRUE;

#ifdef __ENABLE_DIGICERT_SSL_NEW_HANDSHAKE__
            if (NULL != SSL_sslSettings()->funcPtrNewHandshakeCallback)
                if (OK > (status = (MSTATUS)SSL_sslSettings()->funcPtrNewHandshakeCallback(SSL_findConnectionInstance(pSSLSock), &doRehandshake, &doSessionResumption)))
                    goto exit;
#endif

            if (FALSE == doRehandshake)
            {
                /* ignore rehandshake message */
                SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_BEGIN;
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslOpenState;
                break;
            }

           pSSLSock->isMutualAuthNegotiated = FALSE;

            /* FALL-THROUGH */
        }
#endif /* __ENABLE_DIGICERT_SSL_REHANDSHAKE__ */

        case kSslReceiveHelloInitState:
        {
            if (TRUE == isWriter)
                break;

            if (0 == pSSLSock->recordSize)                          /* do we have data to process? */
                break;
            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
            if (0 == pSSLSock->earlyDataExtAccepted)
#endif
            {
                if (OK > (status = sslHelloStateMachine(pSSLSock)))     /* receive here */
                    goto exit;

            }

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
            if ((1 == pSSLSock->earlyDataExtAccepted) &&
                (0 == TLS13_0RTT_GET_EARLY_DATA_RX(pSSLSock)))
            {
                status = OK;
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloInitState;
                SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;
                goto exit;
            }
            if (0 == pSSLSock->earlyDataExtAccepted)
#endif
            {
                pSSLSock->recordSize = 0;
            }

#if defined(__ENABLE_DIGICERT_TLS13__)
            if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
            }
#endif

            if (OK > (status = SSL_SERVER_sendServerHello(pSSLSock)))
                goto exit;

#ifdef __ENABLE_DIGICERT_TLS13__
            if((pSSLSock->sslMinorVersion == TLS13_MINORVERSION) &&
               (pSSLSock->helloRetryRequest != 1))
            {
                if (OK > (status = sendFinished(pSSLSock)))
                {
                    goto exit;
                }

                if (pSSLSock->roleSpecificInfo.server.hrrClientHello)
                {
                    pSSLSock->roleSpecificInfo.server.hrrClientHello = 0;
                }

                status = SSLSOCK_pskCalcApplicationTrafficSecret(pSSLSock);
                if (OK != status)
                    goto exit;

                status = SSLSOCK_setServerTrafficKeyMaterial(
                    pSSLSock, pSSLSock->pServerApplicationTrafficSecret);
                if (OK != status)
                    goto exit;
            }
#endif
            if (E_NoSessionResume != pSSLSock->sessionResume)
            {
#if defined( __ENABLE_DIGICERT_EAP_FAST__)
                if ( E_SessionEAPFASTResume == pSSLSock->sessionResume)
                {
                    /* need to generate master secret from PAC Key now
                    that we have the client hello, server hello and PAC key */
                    if (OK > (status = SSL_SOCK_generateEAPFASTMasterSecret(pSSLSock)))
                        goto exit;
                }
#endif
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState1;
            }
            else
            {
                /* session resumed */
#ifdef __ENABLE_DIGICERT_TLS13__
                if(pSSLSock->helloRetryRequest)
                {
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloInitState;
                    /* Dont reset the flag here. This information is needed when processing client Hello */
                    break;
                }
                else
#endif
                {
                    /* By default the next state is set to kSslReceiveUntil */
                    break;
                }
            }

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */;
        }

        case kSslReceiveHelloState1:
        {
            /* generate the key material here (presecret is unused and NULL) */
            if (OK > (status = SSL_SOCK_generateKeyMaterial(pSSLSock, NULL, 0)))
                goto exit;

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
                if (TRUE == pSSLSock->roleSpecificInfo.server.sendSessionTicket)
                {
                    if (OK > (status = sendNewSessionTicket(pSSLSock)))
                        goto exit;

                    pSSLSock->roleSpecificInfo.server.sendSessionTicket = FALSE;
                }
#endif

            if (OK > (status = sendChangeCipherSpec(pSSLSock)))
                goto exit;

            if (OK > (status = SSL_SOCK_setServerKeyMaterial(pSSLSock)))
                goto exit;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            pSSLSock->retransCipherInfo.pOldCipherSuite = pSSLSock->pActiveOwnCipherSuite;
#endif
            pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState2;

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */;
        }

        case kSslReceiveHelloState2:
        {
#if defined(__ENABLE_DIGICERT_TLS13__)
            /* For TLS 1.3, sendFinished was sent along with ServerHello message */
            if (pSSLSock->isDTLS || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
#endif
            {
                if (OK > (status = sendFinished(pSSLSock)))
                    goto exit;
            }

            pSSLSock->rehandshake = 0;

            /* handshake state is now like we received the CLIENT_KEY_EXCHANGE already*/
            SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)  = SSL_CLIENT_KEY_EXCHANGE;
            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;

            /* FALL-THROUGH */
        }
        case kSslReceiveUntil:
        {
            if (TRUE == isWriter)
                break;

            if (OK > (status = handleServerHandshakeMessages(pSSLSock)))   /* receive here */
                goto exit;

            status = (MSTATUS)(pSSLSock->numBytesToSend);

            if (SSL_FINISHED != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                break;

#ifdef __ENABLE_DIGICERT_TLS13__
            if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                if ((SSL_OPEN_STATE(pSSLSock) == kSslSecureSessionEstablished) &&
                    (keyUpdate_none != pSSLSock->keyUpdateRequested))
                {
                    /* We received a keyUpdate message;
                     * We send the KeyUpdate message in kSslReceiveUntil3 state.
                     */
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil3;
                }
            }
#endif

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil1;

            /* FALL-THROUGH */
        }

        case kSslReceiveUntil1:
        {
            /* send ChangeCipherSpec and Finished only if session was not
            resumed; they were sent before otherwise */
            if (E_NoSessionResume != pSSLSock->sessionResume)
            {
                SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslOpenState;

                if (OK > (status = SSL_INTERNAL_setConnectionState(SSL_findConnectionInstance(pSSLSock), CONNECT_OPEN)))
                    goto exit;

                if (OK > (status = SSLSOCK_doOpenUpcalls(pSSLSock)))
                    goto exit;

                break;
            }

            if (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)
            {
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
                if (TRUE == pSSLSock->roleSpecificInfo.server.sendSessionTicket)
                {
                    if (OK > (status = sendNewSessionTicket(pSSLSock)))
                        goto exit;

                    pSSLSock->roleSpecificInfo.server.sendSessionTicket = FALSE;
                }
#endif

                if (OK > (status = sendChangeCipherSpec(pSSLSock)))
                    goto exit;

                if (OK > (status = SSL_SOCK_setServerKeyMaterial(pSSLSock)))
                    goto exit;
            }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
            pSSLSock->retransCipherInfo.pOldCipherSuite = pSSLSock->pActiveOwnCipherSuite;
#endif
            pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil2;

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */
        }

        case kSslReceiveUntil2:
        {
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__)
            if ((pSSLSock->roleSpecificInfo.server.enableTls13SessionTickets ||
                TRUE == pSSLSock->roleSpecificInfo.server.sendSessionTicket) &&
                TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                if (0 == pSSLSock->earlyDataExtAccepted)
#endif
                {
                    ubyte4 i = 0;
                    for (i = 0; i < pSSLSock->roleSpecificInfo.server.numOfSessionTickets; i++)
                    {
                        if (OK > (status = SSL_SERVER_sendNewSessionTicket(pSSLSock)))
                            goto exit;
                    }
                    /* Since the ticket was sent once, let the client request if it needs another ticket */
                    pSSLSock->roleSpecificInfo.server.sendSessionTicket = FALSE;
                    pSSLSock->roleSpecificInfo.server.enableTls13SessionTickets = FALSE;
                }
            }
#endif

            /* send ChangeCipherSpec and Finished only if session was not
            resumed; they were sent before otherwise */
            /* Server sends Finished in this state for TLS 1.2 or lower versions.
             * For TLS 1.3, Finished message is already sent
             */
            if (pSSLSock->isDTLS || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
            {
                if (OK > (status = sendFinished(pSSLSock)))
                    goto exit;
            }
            /* For EAP */
            available = status;

            pSSLSock->rehandshake = 0;

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil3;

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */
        }

        case kSslReceiveUntil3:
        {

            SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;
            SSL_HANDSHAKE_STATE(pSSLSock) = kSslOpenState;

            if (OK > (status = SSL_INTERNAL_setConnectionState(SSL_findConnectionInstance(pSSLSock), CONNECT_OPEN)))
                goto exit;

            if (OK > (status = SSLSOCK_doOpenUpcalls(pSSLSock)))
            {
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_TLS13__
            if (TLS13_MINORVERSION <= pSSLSock->sslMinorVersion)
            {
               SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;
            }
#endif

            break;
        }

        default:
        {
            status = ERR_SSL_BAD_STATE;
            break;
        }
    }

exit:
    if (OK > status)
    {
        if ((pSSLSock) && (pSSLSock->sessionResume == E_SessionIDResume))
           SSLSOCK_clearServerSessionCache(pSSLSock);

        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_serverHandshake() returns status = ", status);
    }

    if (available)
        status = (MSTATUS)available;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_serverHandshake(SSLSocket* pSSLSock, intBoolean isWriter)
{
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    MSTATUS status = OK;
    ubyte2 msgSeq;
    ubyte2  recordLen = pSSLSock->recordSize;
    sbyte*  pMsg    = pSSLSock->pReceiveBuffer;
    DTLSHandshakeHeader* pSHSH = (DTLSHandshakeHeader *)pMsg;

    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (kSslOpenState == SSL_HANDSHAKE_STATE(pSSLSock) && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
        {
            if (OK > (status = defragment(pSSLSock, TRUE)))
                return status;

            /* check buffer to see whether we have any handshake message in buffer
            * ready to process */
            msgSeq = getShortValue(pSHSH->msgSeq);
            if (msgSeq == pSSLSock->nextRecvSeq)
            {
                while ( (pSSLSock->nextRecvSeq >= pSSLSock->msgBase) &&
                    (MAX_HANDSHAKE_MESG_IN_FLIGHT > (pSSLSock->nextRecvSeq - pSSLSock->msgBase)) &&
                    (pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].ptr) &&
                    (pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].firstHoleOffset == 65535) )
                {
                    pSSLSock->pReceiveBuffer = (sbyte*)pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].ptr;
                    pSSLSock->recordSize = pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].recordSize;

                    /* check to see if we are receiving a post-handshake message. */
                    if (pSSLSock->recordSize && SSL_KEY_UPDATE == pSSLSock->pReceiveBuffer[0])
                        status = SSL_SOCK_serverPostHandshakeDTLS(pSSLSock, &pSSLSock->postHandshakeState[kKeyUpdate], isWriter);
                    else if (pSSLSock->recordSize && SSL_NEW_SESSION_TICKET == pSSLSock->pReceiveBuffer[0])
                        status = SSL_SOCK_serverPostHandshakeDTLS(pSSLSock, &pSSLSock->postHandshakeState[kNewSessionTicket], isWriter);
                    else if (pSSLSock->recordSize && (SSL_CERTIFICATE == pSSLSock->pReceiveBuffer[0] ||
                            SSL_CLIENT_CERTIFICATE_VERIFY == pSSLSock->pReceiveBuffer[0] || SSL_FINISHED == pSSLSock->pReceiveBuffer[0]))
                        status = SSL_SOCK_serverPostHandshakeDTLS(pSSLSock, &pSSLSock->postHandshakeState[kCertificateRequest], isWriter);
                    else
                        return ERR_SSL_BAD_ID;

                    if(OK != status)
                    {

                        FREE(pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].ptr);
                        pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].ptr = NULL;
                        pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].recordSize = 0;

                        freeMsgBufferDescrRecords(&pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase]);
                        /* restore pReceiveBuffer */
                        pSSLSock->pReceiveBuffer = pMsg;
                        pSSLSock->recordSize = recordLen;
                        return status;
                    }
                    freeMsgBufferDescrRecords(&pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase]);

                    FREE(pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].ptr);
                    pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].ptr = NULL;
                    pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq - pSSLSock->msgBase].recordSize = 0;
                    pSSLSock->nextRecvSeq++;

                    if ((pSSLSock->nextRecvSeq - pSSLSock->msgBase)%MAX_HANDSHAKE_MESG_IN_FLIGHT == 0)
                    {
                        ubyte4 shiftAmount = 0;
                        for(int i = 0; i < MAX_HANDSHAKE_MESG_IN_FLIGHT; i++)
                        {
                            if (NULL == pSSLSock->msgBufferDescrs[i].ptr)
                                shiftAmount++;
                            else
                                break;
                        }

                        for(int i = shiftAmount; i < MAX_HANDSHAKE_MESG_IN_FLIGHT; i++)
                        {
                            pSSLSock->msgBufferDescrs[i - shiftAmount].ptr = pSSLSock->msgBufferDescrs[i].ptr;
                            pSSLSock->msgBufferDescrs[i - shiftAmount].recordSize = pSSLSock->msgBufferDescrs[i].recordSize;
                            pSSLSock->msgBufferDescrs[i - shiftAmount].firstHoleOffset = pSSLSock->msgBufferDescrs[i].firstHoleOffset;
                            pSSLSock->msgBufferDescrs[i - shiftAmount].pRecordNodeList = pSSLSock->msgBufferDescrs[i].pRecordNodeList;

                        }
                        pSSLSock->msgBase += shiftAmount;
                    }
                }
                pSSLSock->pReceiveBuffer = pMsg;
                pSSLSock->recordSize = recordLen;
            }
            else if (msgSeq < pSSLSock->nextRecvSeq)
            {
                status = acknowledgeCurrentRecord(pSSLSock);
            }
            return status;
        }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        return  SSL_SOCK_serverHandshakeDTLS(pSSLSock, isWriter);
    } else
#endif
    {
        return  SSL_SOCK_serverHandshakeSSL(pSSLSock, isWriter);
    }
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_initServerEngine(RNGFun rngFun, void* rngFunArg)
{
    sbyte4  cacheIndex;
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
    /*
     * gNextSessionId will be initialized when a request is received and
     * the request enters the SSL State Machine (sslHelloStateMachine())
     */
    gNextSessionId = 0xFFFFFFF0;
#else
	rngFun(rngFunArg, sizeof(SESSIONID), (ubyte*)&gNextSessionId);
#endif

    /* scramble initial session secrets */
    for (cacheIndex = 0; cacheIndex < SESSION_CACHE_SIZE; cacheIndex++)
    {
        sbyte4 index;

        /* make sure they are not reused -- this can happen if the same app
            is bringing down and up the TLS stack repeatedly */
        gSessionCache[cacheIndex].m_sessionId = 0;
        if (OK > (status = (MSTATUS) rngFun(rngFunArg, SSL_MASTERSECRETSIZE, gSessionCache[cacheIndex].m_masterSecret)))
            goto exit;

        for (index = 0; index < SSL_MASTERSECRETSIZE; index++)
        {
            gSessionCache[cacheIndex].m_masterSecret[index] ^= 0x5c;
            gSessionCache[cacheIndex].m_masterSecret[index] += 0x36;
        }
    }

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (OK > (status = (MSTATUS) rngFun(rngFunArg, sizeof(gSessionTicketKeyName), gSessionTicketKeyName)))
        goto exit;

    if (OK > (status = (MSTATUS) rngFun(rngFunArg, sizeof(gSessionTicketEncKey), gSessionTicketEncKey)))
        goto exit;

    if (OK > (status = (MSTATUS) rngFun(rngFunArg, sizeof(gSessionTicketMacKey), gSessionTicketMacKey)))
        goto exit;
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_initSocketExtraServer(SSLSocket* pSSLSock)
{
    resetCipher(pSSLSock, TRUE, TRUE);

    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloInitState;
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        DTLS_TIMER_STATE(pSSLSock) = kDtlsWaiting;
    }
#endif
    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_BEGIN;
    pSSLSock->server = 1;

#ifdef __ENABLE_RFC3456__
    pSSLSock->roleSpecificInfo.server.useSessionTicket = 0;
#endif

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_setServerCert( SSLSocket* pSSLSock)
{
    MSTATUS status = OK;
    ubyte*  signatureAlgoList = NULL;
    ubyte4  signatureAlgoListLength = 0;
    ubyte*  pLeafCert = NULL;
    ubyte4  leafCertLen = 0;
    ubyte2  certSignatureAlgo = 0;
    void*   iterator;
    const struct KeyExAuthSuiteInfo *pKeyExAuthAlgo = NULL;
    ubyte4 *pAlgoIds = NULL;
    ubyte4 algoIdsLen = 0;
    ubyte4 curveIds[5] = { 0 }; /* Max of 5 for the 5 NIST curves */
    ubyte4 curveIdsLen = 0;
    ubyte4 *pKeyIds = NULL;
    ubyte4 keyIdsLen = 0;

    if (pSSLSock->pHandshakeCipherSuite != NULL)
    {
        pKeyExAuthAlgo = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo;
    }

    signatureAlgoList       = pSSLSock->signatureAlgoList;
    signatureAlgoListLength = pSSLSock->signatureAlgoListLength;

    if (OK > (status = CRYPTO_uninitAsymmetricKey(&pSSLSock->handshakeKey, NULL)))
        goto exit;

    if ((NULL != pSSLSock->pCertStore) &&
        (NULL != pSSLSock->pHandshakeCipherSuite) &&
        (NULL != pKeyExAuthAlgo) &&
        (pKeyExAuthAlgo->flags & (SSL_AUTH_RSA_BIT | SSL_AUTH_DSA_BIT | SSL_AUTH_ECDSA_BIT)))
    {
        ubyte4 pubKeyType;
        const AsymmetricKey *pPrivateKey;

        /* initialize in case of failure */
        pSSLSock->roleSpecificInfo.server.certificates = NULL;
        pSSLSock->roleSpecificInfo.server.numCertificates = 0;

        /* get public keyType */
        if ((pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_ECDSA_BIT) ||
            (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDH_BIT))
        {
            convertEcGroupsToKeyIdList(
                (pSSLSock->roleSpecificInfo.server.clientECCurves & SUPPORTED_GROUPS_FLAGS), curveIds, &curveIdsLen);
            pKeyIds = curveIds;
            keyIdsLen = curveIdsLen;
            pubKeyType = akt_ecc;
        }
        else if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_DSA_BIT)
        {
            pubKeyType = akt_dsa;
        }
        else
        {
            pubKeyType = akt_rsa;
        }

        /* TO DO pubKeyType = akt_hybrid, the CERT_STORE function needs to handle it first though */

        /* convert client supported eccurves, sig algos into CERT_STORE_ALGO_FLAGS */
        status = convertToCertStoreAlgoIdList(pSSLSock, signatureAlgoList, signatureAlgoListLength, 
            &pAlgoIds, &algoIdsLen);
        if (OK != status)
            goto exit;

        status = CERT_STORE_findIdentityCertChainFirstFromList(pSSLSock->pCertStore,
                                                         pubKeyType,
                                                         pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->keyUsage,
                                                         pKeyIds, keyIdsLen, pAlgoIds, algoIdsLen,
                                                         &pPrivateKey,
                                                         &pSSLSock->roleSpecificInfo.server.certificates,
                                                         (ubyte4*) &pSSLSock->roleSpecificInfo.server.numCertificates,
                                                         &iterator);

        if (0 >= pSSLSock->roleSpecificInfo.server.numCertificates)
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM; /* no usable cert found */
            goto exit;
        }

        /* verify the name matches the required server name */
        if (pSSLSock->serverNameIndication )
        {
            /* Check if servermame can be recognized */
            if (OK > (status = SSL_SOCK_validateServerName(pSSLSock,
                                                           pSSLSock->roleSpecificInfo.server.certificates)))
            {
                for (;;)
                {
                    /* no: look for the next identity then */
                    status = CERT_STORE_findIdentityCertChainNextFromList(pSSLSock->pCertStore,
                                                                    pubKeyType,
                                                                    pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->keyUsage,
                                                                    pKeyIds, keyIdsLen, pAlgoIds, algoIdsLen,
                                                                    &pPrivateKey,
                                                                    &pSSLSock->roleSpecificInfo.server.certificates,
                                                                    (ubyte4*) &pSSLSock->roleSpecificInfo.server.numCertificates,
                                                                    &iterator);
                    if ( 0 == pSSLSock->roleSpecificInfo.server.numCertificates)
                    {
#if defined(__DISABLE_DIGICERT_SERVERNAME_VALIDATION__)
                      /* Server name indication was provided, but this flag picks the first macthing cert,
                       * if a certificate with matching servername was NOT found
                       * We dont check the response because, we have invoked this call before and a valid cert was obtained */
                         status = CERT_STORE_findIdentityCertChainFirstFromList(pSSLSock->pCertStore,
                                                         pubKeyType,
                                                         pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->keyUsage,
                                                         pKeyIds, keyIdsLen, pAlgoIds, algoIdsLen,
                                                         &pPrivateKey,
                                                         &pSSLSock->roleSpecificInfo.server.certificates,
                                                         (ubyte4*) &pSSLSock->roleSpecificInfo.server.numCertificates,
                                                         &iterator);

                         if ((OK == status)  &&  ( 0 != pSSLSock->roleSpecificInfo.server.numCertificates))
                         {
                            break;/* match */
                         }
#endif
                        /* ran out of certs to look for this combination */
                        status = ERR_SSL_EXTENSION_UNRECOGNIZED_NAME;
                        goto exit;
                    }

                    if (OK == (status = SSL_SOCK_validateServerName(pSSLSock,
                                                      pSSLSock->roleSpecificInfo.server.certificates)))
                    {
                        break; /* match */
                    }
                }
            }
        }

        /* save leaf certificate for later use */
        leafCertLen = pSSLSock->roleSpecificInfo.server.certificates[0].length;
        pLeafCert = pSSLSock->roleSpecificInfo.server.certificates[0].data;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_copyAsymmetricKey(&pSSLSock->handshakeKey, pPrivateKey);
#else
        status = CRYPTO_copyAsymmetricKey(&pSSLSock->handshakeKey, pPrivateKey);
#endif
        if (OK != status)
        {
            goto exit;
        }
    }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
    if (OK > (status = SSLSOCK_setKeyAndTokenHandle(pSSLSock, TRUE /* isServer */)))
    {
        goto exit;
    }
#endif

    if (((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
         (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION)) &&
         (NULL != pSSLSock->pHandshakeCipherSuite) &&
         (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo) &&
         (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & (SSL_AUTH_RSA_BIT | SSL_AUTH_DSA_BIT | SSL_AUTH_ECDSA_BIT)) )
    {
        ubyte  keyTlsAlgo = 0;

        switch(pSSLSock->handshakeKey.type & 0xff)
        {
            case akt_rsa: keyTlsAlgo = TLS_RSA;
                break;
            case akt_dsa: keyTlsAlgo = TLS_DSA;
                break;
            case akt_ecc: keyTlsAlgo = TLS_ECDSA;
                break;
            default: goto exit;
        }

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
        /* get leaf certificate signature algorithm */
        if ( (0 == certSignatureAlgo) &&
             (OK > (status = getCertSigAlgo(pLeafCert, leafCertLen, &certSignatureAlgo))) )
        {
            goto exit;
        }
#endif

        status = ERR_SSL_UNSUPPORTED_ALGORITHM;

		/* If this is a resumed session, check the signature algorithm retrieved from cache */
        if (pSSLSock->signatureAlgo & keyTlsAlgo)
        {
            status = OK;
        }
#ifdef __ENABLE_DIGICERT_TLS13__
        else if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
                 (1 == TLS13_GET_SIGNATURE_ALGO_EXT_RX(pSSLSock)))
        {
            ubyte2 clientSigAlgo = 0;
            ubyte4 i = 0;
            for (i = 0; i < signatureAlgoListLength; i += 2)
            {
                clientSigAlgo = (ubyte2) (signatureAlgoList[i] << 8 | signatureAlgoList[i+1]);
                if (certSignatureAlgo == clientSigAlgo)
                {
                    pSSLSock->signatureAlgo = clientSigAlgo;
                    status = OK;
                    break;
                }
            }

        }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        else if (0 < signatureAlgoListLength)
        {
			/* pick a hash/sig pair from signature Algo extension */
            ubyte4 i;
            ubyte2 clientSigAlgo = 0;
            for (i = 0; i < signatureAlgoListLength; i += 2)
            {
                clientSigAlgo = (ubyte2) (signatureAlgoList[i] << 8 | signatureAlgoList[i+1]);

                if ((clientSigAlgo & 0xff) == (keyTlsAlgo))
                {
                    switch((clientSigAlgo >> 8) & 0xff)
                    {
#ifndef __DISABLE_DIGICERT_SHA512__
                        case TLS_SHA512:
                            /* TAP does not support SHA512 */
                            if (pSSLSock->handshakeKey.type & 0xff0000)
                            {
                                break;
                            }
                            /* TPM 1.2 does not support SHA512 */
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
                            if ((keyTlsAlgo == TLS_RSA) &&
                                (pSSLSock->handshakeKey.key.pRSA->hsmInfo != NULL))
                            {
                                break;
                            }
#endif
                            pSSLSock->signatureAlgo = clientSigAlgo;
                            status = OK;
                            goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
                        case TLS_SHA384:
                            /* TAP does not support SHA384 */
                            if (pSSLSock->handshakeKey.type & 0xff0000)
                            {
                                break;
                            }
                            /* TPM 1.2 does not support SHA384 */
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
                            if ((keyTlsAlgo == TLS_RSA) &&
                                (pSSLSock->handshakeKey.key.pRSA->hsmInfo != NULL))
                            {
                                break;
                            }
#endif
                            pSSLSock->signatureAlgo = clientSigAlgo;
                            status = OK;
                            goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
                        case TLS_SHA256:
                            pSSLSock->signatureAlgo = clientSigAlgo;
                            status = OK;
                            goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
                        case TLS_SHA224:
                            /* TAP does not support SHA224 */
                            if (pSSLSock->handshakeKey.type & 0xff0000)
                            {
                                break;
                            }
                            /* TPM 1.2 does not support SHA224 */
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
                            if ((keyTlsAlgo == TLS_RSA) &&
                                (pSSLSock->handshakeKey.key.pRSA->hsmInfo != NULL))
                            {
                                break;
                            }
#endif
                            pSSLSock->signatureAlgo = clientSigAlgo;
                            status = OK;
                            goto exit;
#endif
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
                        case TLS_SHA1:
                            pSSLSock->signatureAlgo = clientSigAlgo;
                            status = OK;
                            goto exit;
#endif
                        default:
                            break;
                    }
                }
            }
        }
        else
        {
            /*
             * If the client does not send the signature_algorithms extension,
             * assume TLS_SHA1 as the default hash algorithm.
             *
             * For detail, see RFC 5246 section 7.4.1.4.1.
             */
            switch(pSSLSock->handshakeKey.type & 0xff)
            {
                case akt_rsa:
                    pSSLSock->signatureAlgo = (TLS_SHA1 << 8 | TLS_RSA);
                    break;

                case akt_ecc:
                    pSSLSock->signatureAlgo = (TLS_SHA1 << 8 | TLS_ECDSA);
                    break;

                case akt_dsa:
                    pSSLSock->signatureAlgo = (TLS_SHA1 << 8 | TLS_DSA);
                    break;

                default:
                    pSSLSock->signatureAlgo = 0;
                    break;
            }
        }
    }

exit:
   
    if (NULL != pAlgoIds)
    {
        (void) DIGI_FREE((void **) &pAlgoIds);
    }
   
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"MATCHED CLIENT CIPHER ");
    DEBUG_HEXINT(DEBUG_SSL_TRANSPORT,  pSSLSock->signatureAlgo);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)" ");
    return status;
}


/*------------------------------------------------------------------*/

#if (defined( __ENABLE_DIGICERT_SSL_REHANDSHAKE__))
extern MSTATUS
SSL_SOCK_sendServerHelloRequest(SSLSocket* pSSLSock)
{
    ubyte*              pHelloRequest = NULL;
    ubyte*              pSHSH;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status = OK;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHelloRequest))))
        goto exit;

    pSHSH = pHelloRequest;

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_HELLO_REQUEST;
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, 0);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pSHSH), 0, 0);
        if (OK > (status = DIGI_MEMCPY(pSSLSock->HSHBytes, pSHSH, sizeofHandshakeHeader)))
            goto exit;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_HELLO_REQUEST;
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, 0);
    }

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
    if (pSSLSock->isDTLS)
    {
        releaseRetransmissionBuffer(pSSLSock);
        resetRetransmissionSessionInfo(pSSLSock);
    }
#endif

    if (OK > (status = sendData(pSSLSock, SSL_HANDSHAKE, (sbyte *)pHelloRequest, sizeofHandshakeHeader, TRUE)))
	goto exit;

    pSSLSock->rehandshake = 1;

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHelloRequest));

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_REHANDSHAKE__ */
#endif
