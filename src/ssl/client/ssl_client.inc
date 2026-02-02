/*
 * ssl_client.inc
 *
 * SSL Client Specific Functionality
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
#ifndef __SSL_CLIENT_INC__
#define __SSL_CLIENT_INC__

static MSTATUS SSL_SOCK_clientHandshakeSSL(SSLSocket* pSSLSock, intBoolean isWriter);
static MSTATUS SSL_CLIENT_sendClientResponseBlock(SSLSocket* pSSLSock);
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
static ubyte4 calculateExtraFragmentHeader(SSLSocket *pSSLSock, ubyte4 numBufs);
static MSTATUS fragmentHandshakeMessages(SSLSocket *pSSLSock, ubyte4 fragmentLen);
#ifdef __ENABLE_DIGICERT_TLS13__
static MSTATUS acknowledgeCurrentRecord(SSLSocket *pSSLSock);
static MSTATUS addReceivedRecordNode(SSLSocket *pSSLSock, enum postHandshakeType type);
static void freeReceivedRecords(SSLSocket *pSSLSock);
static MSTATUS sendACK(SSLSocket* pSSLSock, RecordListNodePtr pRecords, ubyte4 recordsLen);
#endif
#include "../../dtls/client/dtls_client.inc"
#endif

/*------------------------------------------------------------------*/


#ifdef __ENABLE_DIGICERT_TLS13__
MSTATUS SSL_SOCK_constructTLSExtSupportedVersions(SSLSocket* pSSLSock, ubyte** ppVersionBuffer, ubyte versionMask);
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__

#ifdef __ENABLE_DIGICERT_ECC__
extern MSTATUS constructTLSExtKeyShare(SSLSocket *pSSLSock, ubyte **ppPacket, ubyte2 *pLength);
#endif

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined( __ENABLE_DIGICERT_TLS13_0RTT__))
MSTATUS
SSL_SOCK_constructTLSExtEarlyData(SSLSocket *pSSLSock, ubyte handshakeType, ubyte **ppPacket);
#endif

static MSTATUS
SSLSOCK_setClientTrafficKeyMaterial(SSLSocket *pSSLSock, ubyte *pSecret);

#endif
/* TLS 1.3 : Random value that identifies HRR.
 * RFC : 4.1.3.  Server Hello.
 */
const ubyte HrrRandom[] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

const ubyte tls12Random[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

const ubyte tls11Random[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};

#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS13__)
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
static MSTATUS
checkPSKVersion(SSLSocket *pSSLSock, ubyte2 tlsVersion)
{
    MSTATUS status = OK;

    if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
    {
        if ((tlsVersion & 0xff) != pSSLSock->advertisedMinorVersion)
        {
            status = ERR_SSL_PROTOCOL_VERSION;
            goto exit;
        }
    }
    else
    {
        ubyte valid = 0;
        valid = (ubyte)VALID_SSL_VERSION(((tlsVersion >> 8)& 0xff), (tlsVersion & 0xff));
        if (!valid)
        {
            status = ERR_SSL_PROTOCOL_VERSION;
            goto exit;
        }
    }

exit:
    return status;
}
#endif

static MSTATUS
checkSelectedCipherVersion(SSLSocket *pSSLSock)
{
    MSTATUS status = ERR_SSL_NO_CIPHERSUITE;
    sbyte4 i;

    for (i = 0; i < (sbyte4)NUM_CIPHER_SUITES; ++i)
    {
        if (gCipherSuites[i].supported)
        {
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
            if ((TRUE != pSSLSock->isCipherTableInit) ||
                (TRUE == pSSLSock->isCipherEnabled[i]) )
#endif
            {
                /* it uses the bit field positions to check for the version, ssl3 = 0 , tls1.0 = 1, tls1.1 = 2 ,
                 * tls1.2 = 3, tls1.3 = 4.
                 * example : gCipherSuites[i].sslVersion = 0x10, ( It supports only tls1.3 )
                 * TLS13_MINORVERSION is 4 (tls1.3),  ((0x10 >> 4) & 0x01 )  is 1, means it supports tls1.3
                 */
                if (1 == ((gCipherSuites[i].sslVersion >> TLS13_MINORVERSION) & 0x01))
                {
                    status = OK;
                    break;
                }
            }
        }
    }

    return status;
}
#endif

static ubyte maxVersionSet(ubyte tlsVersion)
{
    if ((tlsVersion >> TLS13_MINORVERSION) && 0x01)
        return TLS13_MINORVERSION;
    else if ((tlsVersion >> TLS12_MINORVERSION) && 0x01)
        return TLS12_MINORVERSION;
    else if ((tlsVersion >> TLS11_MINORVERSION) && 0x01)
        return TLS11_MINORVERSION;
    else if ((tlsVersion >> TLS10_MINORVERSION) && 0x01)
        return TLS10_MINORVERSION;
    else if ((tlsVersion >> SSL3_MINORVERSION) && 0x01)
        return SSL3_MINORVERSION;
    else
        return 0;
}

static ubyte minVersionSet(ubyte tlsVersion)
{
    if ((tlsVersion >> SSL3_MINORVERSION) & 0x01)
        return SSL3_MINORVERSION;
    else if ((tlsVersion >> TLS10_MINORVERSION) & 0x01)
        return TLS10_MINORVERSION;
    else if ((tlsVersion >> TLS11_MINORVERSION) & 0x01)
        return TLS11_MINORVERSION;
    else if ((tlsVersion >> TLS12_MINORVERSION) & 0x01)
        return TLS12_MINORVERSION;
    if ((tlsVersion >> TLS13_MINORVERSION) & 0x01)
        return TLS13_MINORVERSION;
    else
        return 0;
}

static ubyte2
SSL_CLIENT_numCipherSuites(SSLSocket* pSSLSock, ubyte4* flags, ubyte minimumVersion, ubyte maximumVersion)
{
    ubyte2 count = 0;
    sbyte2 i;
    ubyte4 algoFlags = 0;
#ifndef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
    MOC_UNUSED(pSSLSock);
#endif

    for (i = 0; i < (sbyte2) NUM_CIPHER_SUITES; i++)
    {
        if ((gCipherSuites[i].supported) &&
            (maxVersionSet(gCipherSuites[i].sslVersion) >= minimumVersion) &&
            (minVersionSet(gCipherSuites[i].sslVersion) <= maximumVersion))
        {
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
            if ((TRUE != pSSLSock->isCipherTableInit) ||
                (TRUE == pSSLSock->isCipherEnabled[i]) )
#endif
            {
                algoFlags |= gCipherSuites[i].pKeyExAuthAlgo->flags;
                count++;
            }
        }
    }

    *flags = algoFlags;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if ((TLS11_MINORVERSION > pSSLSock->minFallbackMinorVersion) &&
        (0 == pSSLSock->handshakeCount)
#if defined(__ENABLE_DIGICERT_TLS13__)
        && (0 == pSSLSock->helloRetryRequest)
#endif
        )
    {
        /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
        /* send only during initial SSL 3.0 hello */
        count++;
    }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */
#endif /* MIN_SSL_MINORVERSION <= SSL3_MINORVERSION */
	if(pSSLSock->runtimeFlags & SSL_FLAG_SCSV_FALLBACK_VERSION_SET)
	{
        /* TLS_FALLBACK_SCSV */
        /* send only if client is trying to connect with fallback version */
        count++;
	}

    return count;
}

/*------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__))

static ubyte2
numSrtpProfiles(SSLSocket* pSSLSock)
{
    ubyte2 count = 0;
    ubyte2 i;
#ifndef __ENABLE_DIGICERT_SRTP_PROFILES_SELECT__
    MOC_UNUSED(pSSLSock);
#endif

    for (i = 0; i < NUM_SRTP_PROFILES; i++)
    {
        if (gSrtpProfiles[i].supported)
        {
#ifdef __ENABLE_DIGICERT_SRTP_PROFILES_SELECT__
            if ((TRUE != pSSLSock->isSrtpProfileTableInit) ||
                (TRUE == pSSLSock->isSrtpProfileEnabled[i]) )
#endif
            {
                count++;
            }
        }
    }

    return count;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
/*
 * This function constructs the "psk_key_exchange_mode" extension.
 * Length of extension is 1 byte and it takes on of the values
 * defined in the enum tlsExtPskKeyExchangeMode.
 */
static MSTATUS
SSL_CLIENT_constructTLSExtPSKKeyExchangeModes(SSLSocket *pSSLSock, ubyte **ppPacket)
{
    MSTATUS status = OK;

    /* Write the extension type */
    setShortValue(*ppPacket, (ubyte2)tlsExt_psk_key_exchange_modes);
    *ppPacket += sizeof(ubyte2);

    /* Write the extension Length */
    setShortValue(*ppPacket, ((ubyte2)1+1));/* Length of extension data is 1 byte */
    *ppPacket += sizeof(ubyte2);

    /*Write length of Key exchange Mode Length*/
    **ppPacket = (ubyte)1; /*Selecting one exchange mode - 1 byte */
    *ppPacket += 1;

    if (pSSLSock->runtimeFlags & SSL_PSK_EXCHANGE_MODE_FLAG_SET)
    {
        **ppPacket = pSSLSock->roleSpecificInfo.client.pskKeyExchangeMode;
    }
    else
    {
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
        **ppPacket = psk_dhe_ke;
#else
        **ppPacket = psk_ke;
#endif
    }

    *ppPacket += 1;

    return status;
}

#ifdef __ENABLE_DIGICERT_TLS13_0RTT__
static MSTATUS
SSL_CLIENT_sendEndOfEarlyData(SSLSocket* pSSLSock)
{
    MSTATUS status                 = OK;
    ubyte*  pHSH                   = NULL;
    ubyte4  sizeofHandshakeHeader  = 0;
    ubyte   *pEndOfEarlyData       = NULL;

    sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pEndOfEarlyData))))
        goto exit;

    pHSH = pEndOfEarlyData;
    setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)0);
    ((SSLHandshakeHeader*)pHSH)->handshakeType = SSL_CLIENT_END_OF_EARLY_DATA;

    addToHandshakeHash(pSSLSock, pHSH, sizeofHandshakeHeader);/*  1 byte for handshake type + 3 bytes for length */

    status = sendData(pSSLSock, SSL_HANDSHAKE, (sbyte *)pHSH, sizeofHandshakeHeader, TRUE);

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pEndOfEarlyData));
    return status;
}
#endif
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_TLS13__)

extern MSTATUS
constructTLSpostHandShakeAuth(SSLSocket *pSSLSock, ubyte **ppPacket)
{
    MSTATUS status = OK;

    setShortValue(*ppPacket, (ubyte2)tlsExt_postHandshakeAuth);
    *ppPacket += sizeof(ubyte2);

    /* Send 0 length */
    setShortValue(*ppPacket,0);
    *ppPacket += sizeof(ubyte2);

    pSSLSock->postHandshakeAuth = 1; /* Set the post handshake auth supported flag */
    return status;
}

#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ && __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)

static MSTATUS SSL_SOCK_tls13CopyValidPsks(
    tls13PSKList *pPskList, tls13PSKList **ppRetPskList, ubyte2 *pRetLen)
{
    MSTATUS status;
    ubyte2 count = 0;
    tls13PSKList *pNewList = NULL;
    tls13PSKList **ppIter = &pNewList;
    TimeDate td;
    sbyte4 diffTime;

    /* Get the current time.
     */
    status = RTOS_timeGMT(&td);
    if (OK != status)
    {
        goto exit;
    }

    while (NULL != pPskList)
    {
        /* Get the time elapsed since the ticket was recieved.
         */
        if (0 == pPskList->pPSK->isExternal)
        {
            status = DATETIME_diffTime(
                &td, &(pPskList->pPSK->startTime), &diffTime);
            if (OK != status)
            {
                goto exit;
            }
        }
        else
        {
            /* For external PSKs initialize the diffTime to -1.
             */
            diffTime = -1;
        }

        /* Ensure the time elapsed is positive and is less then the number of
         * seconds stored in the ticket lifetime.
         */
        if ( ((diffTime >= 0) &&
              (diffTime < (sbyte4)pPskList->pPSK->pskTLS13LifetimeHint)) ||
             (1 == pPskList->pPSK->isExternal) )
        {
            status = DIGI_CALLOC((void **) ppIter, 1, sizeof(tls13PSKList));
            if (OK != status)
            {
                goto exit;
            }

            count++;

            /* Deserialize the current PSK into the PSK list.
             */
            status = SSLSOCK_tls13DeserializePsk(
                pPskList->pPskData, pPskList->pskDataLen, &((*ppIter)->pPSK));
            if (OK != status)
            {
                (void) SSLSOCK_clearPSKList(&pNewList, &count);
                goto exit;
            }

            /* RFC 8446 Section 4.2.11.1
             *
             * "The client's view of the age of a ticket is the time since the
             * receipt of the NewSessionTicket message."
             *
             * "The "obfuscated_ticket_age" field of each PskIdentity contains
             * an obfuscated version of the ticket age formed by taking the age
             * in milliseconds and adding the "ticket_age_add" value that was
             * included with the ticket (see Section 4.6.1), modulo 2^32."
             *
             * Obfuscate the age by adding the add age provided by the server.
             * Since the server provided the ticket, the server also has access
             * to the add age and will be able to calculate the client age
             * value.
             */
            if (0 == pPskList->pPSK->isExternal)
            {
                (*ppIter)->pPSK->obfuscatedTicketAge = (1000 * diffTime) + (*ppIter)->pPSK->pskTLS13AgeAdd;
            }

            ppIter = &((*ppIter)->pNextPSK);
        }

        pPskList = pPskList->pNextPSK;
    }

    *ppRetPskList = pNewList;
    *pRetLen = count;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
static intBoolean isTLSTicketSupported(SSLSocket *pSSLSock)
{
    if ((TLS10_MINORVERSION <= pSSLSock->minFallbackMinorVersion) && (TLS12_MINORVERSION >= pSSLSock->minFallbackMinorVersion))
        return TRUE;
    else
        return FALSE;
}

static MSTATUS SSL_CLIENT_getTlsSessionTicket(SSLSocket *pSSLSock, ubyte4 *pExtensionsLen)
{
    MSTATUS status;
    ubyte *pTicket = NULL;
    ubyte4 ticketLen = 0;
    intBoolean freeTicket = FALSE;
    ubyte4 dnsNameLen = pSSLSock->roleSpecificInfo.client.pDNSName ? (ubyte4) DIGI_STRLEN(pSSLSock->roleSpecificInfo.client.pDNSName) : 0;
    status = pSSLSock->funcPtrSSLClientRetrieveTicketCallback(
        SSL_findConnectionInstance(pSSLSock),
        (sbyte *) pSSLSock->roleSpecificInfo.client.pDNSName, dnsNameLen,
        NULL, &pTicket, &ticketLen, &freeTicket);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_sendClientHello : No valid ticket found");
        status = OK;
    }
    else if (NULL != pTicket && 0 != ticketLen)
    {
        status = SSLSOCK_deserializeSessionTicket(
            pTicket, ticketLen, &(pSSLSock->roleSpecificInfo.client.pTicketTls));
        if (TRUE == freeTicket)
        {
            DIGI_FREE((void **) &pTicket);
        }
        if (OK != status)
        {
            DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_sendClientHello : Unable to deserialize ticket");
            status = OK;
            goto exit;
        }

        /* Generate random session ID. If the server echo's this value back
        * in the ServerHello then we know the server is going to resume
        * the session using the session ticket */
        pSSLSock->roleSpecificInfo.client.sessionIdLen = SSL_MAXSESSIONIDSIZE;
        pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_MAXSESSIONIDSIZE, pSSLSock->roleSpecificInfo.client.sessionId);

        *pExtensionsLen += pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen;
    }

exit:
    return status;
}
#endif

/*********************************************************************************
*  SSL_CLIENT_sendClientHello
*   see page 77 of SSL and TLS essentials
*/
/* DTLS notes: because server don't keep state for unverified (cookie) client hello.
 * client hello can not fragment
 */
static MSTATUS
SSL_CLIENT_sendClientHello(SSLSocket* pSSLSock)
{
    intBoolean          isRehandshake = (pSSLSock->pActiveOwnCipherSuite) ? TRUE : FALSE;
    ubyte*              pSRH;
    ubyte*              pHSH;
    ubyte*              pTemp;
    sbyte4              i;
    ubyte4              numBytesSent = 0;
    ubyte4              extensionsLength = 0;
    ubyte4              fragmentLen = 0;
    ubyte4              sizeofRecordHeader;
    ubyte4              sizeofHandshakeHeader;
    ubyte4              sizeofHandshakeRecord;
    ubyte4              cipherFlags = 0;
    ubyte4              totalGroupLen = 0, groupLength;
    ubyte2              numCiphers;
    ubyte               minimumVersion = SSL_sslSettings()->sslMinProtoVersion;
    ubyte               maximumVersion = SSL_sslSettings()->sslMaxProtoVersion;
    ubyte4              totalLength = 0;
    MSTATUS             status = OK;
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte4 extCount    = 0;

#ifdef __ENABLE_DIGICERT_TLS13_PSK__
    tls13PSKList *pTLS13PSKList = NULL;
    tls13PSKList *pTempPSKList  = NULL;
    tls13PSKList *pCopyPSKList  = NULL;
    tls13PSK *pTempPSK      = NULL;
    intBoolean freeMemory = FALSE;
    ubyte2 numOfTLS13PSK = 0;
    ubyte selectedIndex = 0;
#ifdef __ENABLE_DIGICERT_TLS13_0RTT__
    ubyte earlyDataSet = 0;
#endif
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
    ubyte2 pointLen = 0;
#endif /* __ENABLE_DIGICERT_TLS13__ */
    ubyte2* pSupportedSignatureAlgoList = NULL;
    ubyte4  supportedSignatureAlgoListLength = 0;
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
    const BulkHashAlgo *pHashAlgo = NULL;
#endif

    /* enforce not rehandshake for DTLS13 when early data is possible */
#if defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__)
    if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        isRehandshake = 0;
    }
#endif

/* Make sure this flag is reset if we are sending CLientHello */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* Do NOT free the hash for previously exchanged messages in case of HRR
     * RFC 8446, section 2.1
     */
    if ((pSSLSock->pHashCtx)
#if defined(__ENABLE_DIGICERT_TLS13__)
         && (0 == pSSLSock->helloRetryRequest)
#endif
       )
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pHashCtx);
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    /* Make sure these flags are reset when sending ClientHello */
    pSSLSock->isMutualAuthNegotiated = FALSE;
    pSSLSock->generateEmptyCert      = FALSE;

    if (pSSLSock->rehandshake)
    {
        SSLSOCK_freeHashCtxList(pSSLSock);
    }
#endif
    pSSLSock->sentFinished = FALSE;
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (NULL != pSSLSock->roleSpecificInfo.client.pTicketTls)
    {
        DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pTicketTls->pTicket));
        DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pTicketTls));
    }
#endif

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion && isRehandshake)
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

    } else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        sizeofHandshakeRecord = sizeof(SSLHandshakeRecord);
    }
#ifdef __ENABLE_DIGICERT_TLS13__
    DIGI_MEMSET((ubyte *) pSSLSock->sentExtensions, 0x00, MAX_EXTENSIONS_SENT * sizeof(ubyte2));
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    /* Clear the flags if a new client Hello is being sent */
    pSSLSock->roleSpecificInfo.client.sentExtendedMasterSecret = FALSE;
    pSSLSock->receivedExtendedMasterSecret = FALSE;
#endif

    pSSLSock->buffers[0].pHeader = NULL;

    /* Check for rehandshake is true */
    if (0 == pSSLSock->rehandshake)
    {
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
        if ( pSSLSock->isDTLS )
        {
            /* minor version initialization: if MinorVer is set by SSL_ioctl, use it; else default to max supported */
            pSSLSock->sslMinorVersion = ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)?
                                         pSSLSock->advertisedMinorVersion : MAX_DTLS_MINORVERSION);

#if defined(__ENABLE_DIGICERT_OPENSSL_SHIM__)
            /* OpenSSL connector only supports DTLS 1.2 or lower */
            maximumVersion = TLS12_MINORVERSION;
#endif
        }
        else
#endif
        {
            /* minor version initialization: if MinorVer is set by SSL_ioctl, use it; else default to max supported */
            pSSLSock->sslMinorVersion = ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET) ?
                                         pSSLSock->advertisedMinorVersion : SSL_sslSettings()->sslMaxProtoVersion);
            if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
            {
                /* Use the version set by for the session */
                maximumVersion = pSSLSock->advertisedMinorVersion;
                minimumVersion = pSSLSock->advertisedMinorVersion;
            }
            else if (pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET)
            {
                /* Use the max version set in the global settings and the
                 * fallback version set for the session */
                maximumVersion = SSL_sslSettings()->sslMaxProtoVersion;
                minimumVersion = pSSLSock->minFallbackMinorVersion;
            }
            else
            {
                /* Default scenario, use the min and max version set in the
                 * global settings */
                maximumVersion = SSL_sslSettings()->sslMaxProtoVersion;
                minimumVersion = SSL_sslSettings()->sslMinProtoVersion;
            }
        }
    }

    /* generate client random in its usual place */
    /* don't re-generate random when received server HelloVerifyRequest */
    if (kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
    {
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_TLS13__)
        /* we do not want to generate a new client random if
         * we are negotiating DTLS 1.3 and this is an HRR */
        if (!pSSLSock->isDTLS || (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) || !pSSLSock->helloRetryRequest)
#endif
            pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_RANDOMSIZE, START_RANDOM(pSSLSock));
    }
#ifdef __ENABLE_DIGICERT_TLS13__
    if(pSSLSock->helloRetryRequest)
    {
        numCiphers = 1;
        cipherFlags |= pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags;
    }
    else
#endif
    {
        numCiphers = SSL_CLIENT_numCipherSuites( pSSLSock, &cipherFlags, minimumVersion, maximumVersion);
    }

    /* Cipher suite in Client Hello must be at least 2 bytes. Each cipher suite
     * consists of 2 bytes so there must at least be a single valid cipher in
     * the cipher suite list. Throw an error if no cipher suites are found.
     */
    if (numCiphers == 0)
    {
        status = ERR_SSL_NO_CIPHERSUITE;
        goto exit;
    }

    /* If there are no TLS 1.3 cipher suites supported then downgrade to a TLS
     * 1.2 Client Hello.
     */
#if defined(__ENABLE_DIGICERT_TLS13__)
    if ( (TLS13_MINORVERSION == pSSLSock->sslMinorVersion || DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
         (OK != checkSelectedCipherVersion(pSSLSock)) )
    {
#if defined(__ENABLE_DIGICERT_TLS12_FALLBACK__)
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
        if (pSSLSock->isDTLS)
        {
            pSSLSock->sslMinorVersion = DTLS12_MINORVERSION;
            pSSLSock->advertisedMinorVersion = DTLS12_MINORVERSION;            
        }
        else
#endif
        {
            pSSLSock->sslMinorVersion = TLS12_MINORVERSION;
            pSSLSock->advertisedMinorVersion = TLS12_MINORVERSION;
        }
#else
        status = ERR_SSL_NO_CIPHERSUITE;
        goto exit;
#endif
    }
#endif /* __ENABLE_DIGICERT_TLS13__ */

    SSL_SOCK_filterSupportedGroups(pSSLSock);

    if (OK > (status =  SSL_SOCK_filterSupportedSignatureAlgorithm(pSSLSock, FALSE)))
    {
        goto exit;
    }

    pSupportedSignatureAlgoList      = pSSLSock->pSupportedSignatureAlgoList;
    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    /* to interoperate with old server, SSL 3.0 should only
       send renegotiation extension during rehandshake */
    if ((SSL3_MINORVERSION < pSSLSock->sslMinorVersion ||
         (SSL3_MINORVERSION == pSSLSock->sslMinorVersion && pSSLSock->isRehandshakeAllowed))
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        && ((TLS11_MINORVERSION <= pSSLSock->minFallbackMinorVersion) || (pSSLSock->isRehandshakeAllowed))
#endif
       )
    {
        extensionsLength += (2 + 2 + 1); /* extension type + extension length + renegotiated_connection length */

        if (0 < pSSLSock->handshakeCount)
        {
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            ubyte4  verifyDataSize = (0 == pSSLSock->sslMinorVersion) ? SSL_VERIFY_DATA : TLS_VERIFYDATASIZE;
            /* on rehandshakes, use verify data string from the previous handshake */
            extensionsLength += verifyDataSize;
#else
            extensionsLength += TLS_VERIFYDATASIZE;
#endif
        }
    }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */


#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    /**** TLS extensions *****/
    if ( SSL3_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
    {
        /* server name extension */
        if (pSSLSock->serverNameIndication)
        {
            /* TLS 1.0+ feature */
            extensionsLength += 9; /* extension type (2) + extension length (2) +
                                     server name list length (2) +
                                    server name type (1) + server name length (2) */
            extensionsLength += DIGI_STRLEN((sbyte*) pSSLSock->serverNameIndication);
        }
        /* supported signature algorithms extension */
        if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            extensionsLength += 6; /* extension type (2) +
                                    extension length (2)  + list length (2) */
            extensionsLength += supportedSignatureAlgoListLength * 2;
#ifdef __ENABLE_DIGICERT_TLS13__
            if ( ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
                  (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION)) &&
                 (NULL != pSSLSock->pConfiguredSignatureCertAlgoList) )
            {
                extensionsLength += 6;
                extensionsLength += pSSLSock->configuredSignatureCertAlgoListLength * 2;
            }
#endif
        }
        if (pSSLSock->alpnProtocolsLen && pSSLSock->alpnProtocols)
        {
            extensionsLength += 6; /* extension type (2) +
                                    extension length (2)  + list length (2) */
            extensionsLength += pSSLSock->alpnProtocolsLen;
        }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
        /* If version is set less than or equal to TLSv1.2 || Min fallback version is less than or eqal to TLS 1.2 */
            /* If version is set less than or equal to TLSv1.2 ||
             * Min fallback version is less than or equal to TLS 1.2 ||
             * isDTLS and minor version set to DTLS 1.2
             */
        if ((!pSSLSock->isDTLS && (
               ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET) && TLS12_MINORVERSION >= pSSLSock->advertisedMinorVersion) ||
               ((pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET) && TLS12_MINORVERSION >= pSSLSock->minFallbackMinorVersion))) 
            || (pSSLSock->isDTLS && DTLS12_MINORVERSION == pSSLSock->sslMinorVersion && TRUE == pSSLSock->supportExtendedMasterSecret))
        {
            extensionsLength += 4;/* extension type (2) + extension length(2) */
        }
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
        if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION))
        {
            /* supported_version */
            extensionsLength += 5; /* extension type(2) +
                                      extension length(2) +
                                      list length(1) */

            if( (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET) ||
                (pSSLSock->helloRetryRequest) )
            {
                extensionsLength += 2; /* Only one version in the list */
                pSSLSock->roleSpecificInfo.client.numOfSharedVersions = 1;
            }
            else if (pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET)
            {
                /* TLS 1.3 does not allow SSLv3 to be negotiated.
                 */
                if (SSL3_MINORVERSION == pSSLSock->minFallbackMinorVersion)
                {
                    status = ERR_SSL_PROTOCOL_VERSION;
                    goto exit;
                }

                /* By default 4 versions are supported : TLS 1.0(1), TLS 1.1(2), TLS 1.2(3), TLS 1.3(4)
                 * Subtracting the minimim fallback version number from total number of supported versions,
                 * gives the number of supported versions.
                 */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                if (pSSLSock->isDTLS)
                {
                    /* for DTLS the min Fallback Version is a larger numeric value than the newest 1.3 version */
                    extensionsLength += (pSSLSock->minFallbackMinorVersion - DTLS13_MINORVERSION + 1) * 2;
                    pSSLSock->roleSpecificInfo.client.numOfSharedVersions = pSSLSock->minFallbackMinorVersion - DTLS13_MINORVERSION + 1;
                }
                else
#endif
                {
                    extensionsLength += (NUM_SUPPORTED_VERSIONS - pSSLSock->minFallbackMinorVersion + 1) * 2;
                    pSSLSock->roleSpecificInfo.client.numOfSharedVersions = NUM_SUPPORTED_VERSIONS - pSSLSock->minFallbackMinorVersion + 1;
                }
            }
            else
            {
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                if (pSSLSock->isDTLS)
                {
                    extensionsLength += NUM_SUPPORTED_VERSIONS_DTLS * 2;
                    pSSLSock->roleSpecificInfo.client.numOfSharedVersions = NUM_SUPPORTED_VERSIONS_DTLS;
                }
                else
#endif
                {
                    extensionsLength += NUM_SUPPORTED_VERSIONS * 2;
                    pSSLSock->roleSpecificInfo.client.numOfSharedVersions = NUM_SUPPORTED_VERSIONS;
                }
            }

            if (pSSLSock->roleSpecificInfo.client.numOfSharedVersions != 0)
            {
                if (NULL != pSSLSock->roleSpecificInfo.client.pSharedVersions)
                {
                    DIGI_FREE((void **)&pSSLSock->roleSpecificInfo.client.pSharedVersions);
                }
                if (OK > (status = DIGI_MALLOC((void **)&pSSLSock->roleSpecificInfo.client.pSharedVersions,
                                              pSSLSock->roleSpecificInfo.client.numOfSharedVersions * sizeof(ubyte2))))
                {
                    goto exit;
                }
            }

            /* "key_share" extension Length*/
            /* type(2) + type length(2)+key_share ext length(2) + 
             * group name(2*supportedGroupsListLength) +
             * Key Length(2*supportedGroupsListLength)+
             * legacy(1*supportedGroupsListLength) +
             * keyLength (SUM_OF_ALL_KEYS)*/ 
            if (pSSLSock->helloRetryRequest && pSSLSock->roleSpecificInfo.client.selectedGroup)
            {
                status = getNamedGroupLength(
                    pSSLSock->roleSpecificInfo.client.selectedGroup, &groupLength);
                if (OK != status)
                {
                    goto exit;
                }
                totalGroupLen = groupLength + totalGroupLen;
                extensionsLength += 2 + 2 + 2 +
                                    (2*1) +
                                    (2*1) +
                                    (totalGroupLen);
            }
            else
            {
                if (0 == pSSLSock->supportedGroupListLength)
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }

                /* Calculate the length of the key share based on all the
                 * supported groups.
                 */
                for (i = 0; i < (sbyte4) pSSLSock->supportedGroupListLength; i++)
                {
                    status = getNamedGroupLength(
                        pSSLSock->pSupportedGroupList[i], &groupLength);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    /* 2 bytes - named group
                     * 2 bytes - group data length
                     * x bytes - group data
                     */
                    totalGroupLen += 2 + 2 + groupLength;

                    /* Compiling with this flag will cause the client to send a key
                     * share entry for all the groups that are supported. If NanoSSL
                     * is compiled without this flag the client will only a key
                     * share entry for the first supported group sent.
                     */
#if !defined(__ENABLE_DIGICERT_ALL_KEYSHARE__)
                    break;
#endif
                }

                /* 2 bytes - extension type
                 * 2 bytes - extension length
                 * 2 bytes - key share length
                 * x bytes - all key shares
                 */
                extensionsLength += 2 + 2 + 2 + totalGroupLen;
            }

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)

            if (pSSLSock->funcPtrSSLClientRetrievePSKCallback != NULL)
            {
                ubyte2 pskCount;
                ubyte4 serverNameLen = 0;
                sbyte4 connectionInstance = SSL_findConnectionInstance(pSSLSock);

                if (0 > connectionInstance)
                {
                    status = ERR_SSL_BAD_ID;
                    goto exit;
                }

                if (NULL != pSSLSock->roleSpecificInfo.client.pDNSName)
                {
                    serverNameLen = DIGI_STRLEN(pSSLSock->roleSpecificInfo.client.pDNSName);
                }

                status = pSSLSock->funcPtrSSLClientRetrievePSKCallback(connectionInstance,
                                                                  (sbyte *) pSSLSock->roleSpecificInfo.client.pDNSName,
                                                                  serverNameLen, NULL, (void **)&pTLS13PSKList, &numOfTLS13PSK, &selectedIndex,
                                                                  &freeMemory);

                if (OK > status)
                {
                    DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_sendClientHello : No Valid PSK found");
                    status = OK; /* Fallback to Certificate */
                }

                pTempPSKList = pTLS13PSKList;

                for (pskCount = 0; pskCount < numOfTLS13PSK; pskCount++)
                {
                    status = SSLSOCK_tls13DeserializePsk(
                        pTempPSKList->pPskData, pTempPSKList->pskDataLen,
                        &(pTempPSKList->pPSK));
                    if (OK != status)
                    {
                        goto exit;
                    }

                    pTempPSKList = pTempPSKList->pNextPSK;
                }

                /* Make a copy of the valid PSKs.
                 */
                status = SSL_SOCK_tls13CopyValidPsks(
                    pTLS13PSKList, &pCopyPSKList, &pskCount);
                if (OK != status)
                {
                    goto exit;
                }

                if (TRUE == freeMemory)
                {
                    (void) SSLSOCK_clearPSKList(&pTLS13PSKList, &numOfTLS13PSK);
                }

                numOfTLS13PSK = pskCount;
            }

            if (NULL != pSSLSock->roleSpecificInfo.client.pTLS13PSKList)
            {
                (void) SSLSOCK_clearPSKList(&pSSLSock->roleSpecificInfo.client.pTLS13PSKList, &pSSLSock->roleSpecificInfo.client.numOfTLS13PSK);
            }

            pSSLSock->roleSpecificInfo.client.numOfTLS13PSK = numOfTLS13PSK;
            pSSLSock->roleSpecificInfo.client.pTLS13PSKList = pCopyPSKList;

            i = 0;
            pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

            while((i < numOfTLS13PSK) && (pTempPSKList != NULL))
            {
                pTempPSK = pTempPSKList->pPSK;

                if (NULL == pTempPSK)
                {
                    pTempPSKList = pTempPSKList->pNextPSK;
                    continue;
                }

                /* Check the version; The version negotiated when establising PSK
                 * should be one of the supported versions
                 */
                if (OK > (status = checkPSKVersion(pSSLSock, pTempPSK->pSelectedTlsVersion)))
                {
                    goto exit;
                }

                pHashAlgo = getHashSuite((ubyte4)pTempPSK->hashAlgo);
                if (NULL == pHashAlgo)
                {
                    status = ERR_SSL_HASH_ALGO_NULL;
                    goto exit;
                }

                i++;
                pTempPSKList = pTempPSKList->pNextPSK;
            }
            /* pre_sharedKey : ext_type(2) + ext_length(2) + total Identites length(2) +
             *                 identity_length (2) + Acutal Identity (stlrlen(identity) +
             *                  obfuscated tkt age (4) + Binder length(2) + numOfBinders (>32)
             */
            if (1 == TLS13_HRR_GET_RX(pSSLSock))
            {
                ubyte4 j = 0;
                pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

#if defined(__ENABLE_DIGICERT_TLS13_0RTT__) && defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
                /*
                    RFC 8446 says no early data extension in follow up ClientHello,
                    but RFC 9147 for DTLS does not clarify. Since followup ClientHello
                    is neccessary all the time we assume it should have the early data extension.
                */
                while((j < numOfTLS13PSK) && (pTempPSKList != NULL))
                {
                    pTempPSK = pTempPSKList->pPSK;

                    if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion && 0 == earlyDataSet && 
                        pTempPSK->maxEarlyDataSize > 0 && NULL != pSSLSock->pEarlyData)
                    {
                        /* For ClientHello early_data extension's extension_data field 
                            should be empty */
                        extensionsLength += 2 + 2; /* early_data extension type(2) + extension length(2) + empty(0)*/
                        earlyDataSet = 1;
                        pSSLSock->sendEarlyData = TRUE;

                        /* Set pSSLSock->pActiveOwnCipherSuite according to the 0th PSK if we are sending early data */
                        for (i = 0; i < (sbyte4) NUM_CIPHER_SUITES; i++)
                        {
                            if ((gCipherSuites[i].cipherSuiteId == pTempPSK->selectedCipherSuiteId) &&
                                    (gCipherSuites[i].supported))
                            {
                                pSSLSock->pHandshakeCipherSuite = pSSLSock->pActiveOwnCipherSuite = &gCipherSuites[i];
                                break;
                            }
                        }
                    }
                    j++;
                }
                j = 0;
#endif
                while ((j <= selectedIndex) && (pTempPSKList != NULL))
                {
                    if (j == selectedIndex)
                    {
                        pTempPSK = pTempPSKList->pPSK;
                        break;
                    }
                    j++;
                    pTempPSKList = pTempPSKList->pNextPSK;
                }

                if (pTempPSK != NULL)
                {
                    pHashAlgo = getHashSuite((ubyte4)pTempPSK->hashAlgo);
                    if (NULL == pHashAlgo)
                    {
                        status = ERR_SSL_HASH_ALGO_NULL;
                        goto exit;
                    }

                    extensionsLength += pTempPSK->pskTLS13IdentityLength;
                    extensionsLength += 2 + 2 + 2 + 2 + 4 + 2;
                    extensionsLength += pHashAlgo->digestSize + 1;
                }
            }
            else if (numOfTLS13PSK > 0)
            {
                ubyte4 j = 0;
                pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

                while((j < numOfTLS13PSK) && (pTempPSKList != NULL))
                {
                    pTempPSK = pTempPSKList->pPSK;
#ifdef __ENABLE_DIGICERT_TLS13_0RTT__
                    /*
					   RFC #8446 section 4.2.10:
					   Section 4.2.10, Page 54: A client MUST not include the "early_data" 
					   extension in its followup ClientHello

                       RFC 9147 for DTLS does not clarify but since followup ClientHello
                       is neccessary we assume it should have the extension.
					 */
                    if (0 == pSSLSock->helloRetryRequest
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__                    
                        || DTLS13_MINORVERSION == pSSLSock->sslMinorVersion
#endif
                        )
                    {
                        if ((0 == earlyDataSet) && (pTempPSK->maxEarlyDataSize > 0) && (NULL != pSSLSock->pEarlyData))
                        {
                            /* For ClientHello early_data extension's extension_data field 
                               should be empty */
                            extensionsLength += 2 + 2; /* early_data extension type(2) + extension length(2) + empty(0)*/
                            earlyDataSet = 1;
                            pSSLSock->sendEarlyData = TRUE;

                            /* Set pSSLSock->pActiveOwnCipherSuite according to the 0th PSK if we are sending early data */
                            for (i = 0; i < (sbyte4) NUM_CIPHER_SUITES; i++)
                            {
                                if ((gCipherSuites[i].cipherSuiteId == pTempPSK->selectedCipherSuiteId) &&
                                        (gCipherSuites[i].supported))
                                {
                                    pSSLSock->pHandshakeCipherSuite = pSSLSock->pActiveOwnCipherSuite = &gCipherSuites[i];
                                    break;
                                }
                            }
                        }
                    }
#endif
                    pHashAlgo = getHashSuite((ubyte4)pTempPSK->hashAlgo);
                    if (NULL == pHashAlgo)
                    {
                        status = ERR_SSL_HASH_ALGO_NULL;
                        goto exit;
                    }

                    extensionsLength += pTempPSK->pskTLS13IdentityLength;
                    extensionsLength += pHashAlgo->digestSize + 1;
                    pTempPSKList = pTempPSKList->pNextPSK;
                    j++;
                }
                extensionsLength += 2 + 2 + 2 + (pSSLSock->roleSpecificInfo.client.numOfTLS13PSK * (2 + 4)) + 2;
            }

            /* "psk_key_exchange_mode" extension */
            /* extension type(2) + extension length(2)+ Key exchange mode value length(1)
             * + Key exchange Mode (1)*/
            if (pSSLSock->roleSpecificInfo.client.numOfTLS13PSK > 0)
            {
                extensionsLength += 2 + 2 + 1 + 1;
            }
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
            else
            {
                /* If NO PSK is selected, early data should not be sent */
                pSSLSock->sendEarlyData = FALSE;
            }
#endif
#endif
            if (pSSLSock->helloRetryRequest)
            {
                /* Cookie 
                 * Extension type(2) + Extension Length(2)+ CookieLength(2) + ActualCookie
                 */
                if(pSSLSock->helloCookieLen > 0)
                {
                    extensionsLength += 2 + 2 + 2 + pSSLSock->helloCookieLen;
                }
            }

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
            /* post_handshake_auth */
            if (pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH)
            {
                extensionsLength += 4; /* extension Type (2), extensionLength(2) */
            }
#endif
        }
#endif /* __ENABLE_DIGICERT_TLS13__ */

#ifdef __ENABLE_DIGICERT_SSL_SRP__
        if (pSSLSock->srpIdentity)
        {
            /* extension type (2) + extension length (2) +  length (1) + identity length */
            extensionsLength += 5 + pSSLSock->srpIdentity[0];
        }
#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
        if (pSSLSock->certStatusReqExt)
        {
            /* TLS 1.0+ feature */
            extensionsLength += 4; /* extension type + extension length*/
            extensionsLength += pSSLSock->certStatusReqExtLen;
        }
#endif

#ifdef __ENABLE_DIGICERT_EAP_FAST__
        /* only if we have a ticket extension */
        if ( pSSLSock->roleSpecificInfo.client.ticket &&
            pSSLSock->roleSpecificInfo.client.ticketLength)
        {
            extensionsLength += 2; /* extension type */
#ifndef __DISABLE_EAP_FAST_EXTENSION_LENGTH__
            extensionsLength += 2; /* extension length */
#endif
            extensionsLength += 2; /* ticket length */

            extensionsLength += pSSLSock->roleSpecificInfo.client.ticketLength;
        }
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
        if (((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION)) &&
             0 == pSSLSock->handshakeCount && pSSLSock->roleSpecificInfo.client.requestSessionTicket == 1)
        {
            /* Add an empty extension of type tlsExt_ticket */
            extensionsLength += 2; /* extension type */
            extensionsLength += 2; /* extension length; this will be zero for an empty extension*/
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
            if ((TRUE == isTLSTicketSupported(pSSLSock)) && (NULL != pSSLSock->funcPtrSSLClientRetrieveTicketCallback))
            {
                status = SSL_CLIENT_getTlsSessionTicket(pSSLSock, &extensionsLength);
                if (OK != status)
                    goto exit;
            }
#endif
        }
#endif
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        if (((!pSSLSock->isDTLS && pSSLSock->sslMinorVersion != TLS13_MINORVERSION) ||
              (pSSLSock->isDTLS && pSSLSock->sslMinorVersion != DTLS13_MINORVERSION)) &&
            (TRUE == isTLSTicketSupported(pSSLSock)) &&
            (pSSLSock->roleSpecificInfo.client.requestSessionTicket == 1))
        {
            /* Add an empty extension of type tlsExt_ticket */
            extensionsLength += 2; /* extension type */
            extensionsLength += 2; /* extension length; this will be zero for an empty extension*/
            if (NULL != pSSLSock->funcPtrSSLClientRetrieveTicketCallback)
            {
                status = SSL_CLIENT_getTlsSessionTicket(pSSLSock, &extensionsLength);
                if (OK != status)
                    goto exit;
            }
        }
#endif
#ifdef __ENABLE_DIGICERT_INNER_APP__
        /* only if we have a ticket extension */
        if ( pSSLSock->roleSpecificInfo.client.innerApp )
        {
            extensionsLength += 6; /* extension type + App length + App  Value */
        }
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION))
        {
            /* add ECC related extensions only if the cipher suites include EC based ones */
            if ( cipherFlags & (SSL_KEYEX_ECDH_BIT | SSL_KEYEX_ECDHE_BIT))
            {
                /* supported elliptic curve extension */
                extensionsLength += 6; /* extension type  (2) +
                                    extension length (2) +
                                    size of curve list (2) */

                /* for DTLS 1.3, if server sent us a selcted group, do not send entire list. */
                if(!pSSLSock->helloRetryRequest || ((DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) && pSSLSock->roleSpecificInfo.client.selectedGroup == 0))
                {
                    extensionsLength += pSSLSock->supportedGroupListLength * 2;
                }
                else
                {
                    extensionsLength += 2;
                }
            }
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            /* add ECC related extensions only if the cipher suites include EC based ones */
            if ( cipherFlags & (SSL_KEYEX_ECDH_BIT | SSL_KEYEX_ECDHE_BIT))
            {
                /* supported elliptic curve extension */
                extensionsLength += 6; /* extension type  (2) +
                                        extension length (2) +
                                        size of curve list (2) */

                extensionsLength += pSSLSock->supportedGroupListLength * 2;
                /* supported point compression -- we don't -> always the same data */
                extensionsLength += 6; /* everything */
            }
        }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__))
        /* use_srtp extension */
        if (pSSLSock->isDTLS && pSSLSock->useSrtp)
        {
            ubyte4 profileCount = numSrtpProfiles(pSSLSock);

            /* dtls_srtp feature */
            extensionsLength += 6; /* extension type (2) + extension length (2) +
                                    SRTP protection profile list length  (2) */
            extensionsLength += 2*profileCount;
            extensionsLength += 1 + ((NULL != pSSLSock->srtpMki) ? *(pSSLSock->srtpMki) : 0); /* srtp_mki is variable length */
        }
#endif

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
        if (pSSLSock->sendHeartbeatMessage != noHeartbeatMessages)
        {
            extensionsLength += 4; /* extension type (2) + extension length (2) */
            extensionsLength += 1; /* HeartbeatMode is only 1 byte */
        }
#endif
    }

    if ( extensionsLength) /* do we have any extensions? */
    {
        extensionsLength += 2; /* length of extensions */
    }

    /* compute size of buffers */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        ubyte2 cookieLen = pSSLSock->helloCookieLen;
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            cookieLen = 0;
        }
#endif
        pSSLSock->buffers[0].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 2 + SSL_RANDOMSIZE +
                                      1 + pSSLSock->roleSpecificInfo.client.sessionIdLen +
                                      1 + cookieLen +
                                      2 + (2 * numCiphers) + 2 + extensionsLength);
        totalLength += pSSLSock->buffers[0].length;
    } else
#endif
    {
        pSSLSock->buffers[0].length = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 2 + SSL_RANDOMSIZE +
                                      1 + pSSLSock->roleSpecificInfo.client.sessionIdLen +
                                      2 + (2 * numCiphers) + 2 + extensionsLength);
        totalLength += pSSLSock->buffers[0].length;
    }

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        fragmentLen = calculateExtraFragmentHeader(pSSLSock, 1);
    }
#endif

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, fragmentLen + totalLength, TRUE, (void **)&(pSSLSock->buffers[0].pHeader))))
        goto exit;

    pSSLSock->buffers[0].data = pSSLSock->buffers[0].pHeader + sizeofRecordHeader;

    /* fill buffers */
    pSRH = pSSLSock->buffers[0].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,pSSLSock->buffers[0].length - sizeofRecordHeader);
        pHSH = pSSLSock->buffers[0].data;
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pHSH), pSSLSock->nextSendSeq++, (ubyte2)(pSSLSock->buffers[0].length - sizeofHandshakeRecord));
        setMediumValue(((DTLSHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[0].length - sizeofHandshakeRecord));
        ((DTLSHandshakeHeader *)pHSH)->handshakeType = SSL_CLIENT_HELLO;
    } else
#endif
    {
        /* set the record layer version to the same version as the
         handshake layer version number. This is not strictly necessary
         cf. Appendix E.1 of RFC 5246 */
        SSL_SET_RECORD_HEADER(pSRH,SSL_HANDSHAKE,
                              (pSSLSock->sslMinorVersion == TLS13_MINORVERSION) ?
                              TLS12_MINORVERSION : pSSLSock->sslMinorVersion,
                              pSSLSock->buffers[0].length - sizeofRecordHeader);
        pHSH = pSSLSock->buffers[0].data;
        setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[0].length - sizeofHandshakeRecord));
        ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_CLIENT_HELLO;
    }

    pTemp = (ubyte *)(pHSH + sizeofHandshakeHeader);

    /* Legacy version, as per RFCs 1.3 still, shows TLS1.2 or DLTS1.2 version */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        *pTemp++ = DTLS1_MAJORVERSION;
    } else
#endif
    {
        *pTemp++ = SSL3_MAJORVERSION;
    }

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if(pSSLSock->isDTLS)
    {
        if(pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
        {
            *pTemp++ = DTLS12_MINORVERSION;
        }
        else
        {
            *pTemp++ = pSSLSock->sslMinorVersion;
        }
    }
    else
#endif
    {
        if(pSSLSock->sslMinorVersion == TLS13_MINORVERSION)
        {
            *pTemp++ = TLS12_MINORVERSION;
        }
        else
        {
            *pTemp++ = pSSLSock->sslMinorVersion;
        }
    }
    /* client random */
    DIGI_MEMCPY(pTemp, START_RANDOM(pSSLSock), SSL_RANDOMSIZE);
    DIGI_MEMCPY(pSSLSock->pClientRandHello, START_RANDOM(pSSLSock), SSL_RANDOMSIZE);
    pTemp += SSL_RANDOMSIZE;

    /* session id */
    *pTemp++ = pSSLSock->roleSpecificInfo.client.sessionIdLen;
    if (pSSLSock->roleSpecificInfo.client.sessionIdLen > 0)
    {
        DIGI_MEMCPY(pTemp, pSSLSock->roleSpecificInfo.client.sessionId, pSSLSock->roleSpecificInfo.client.sessionIdLen);
        pTemp += pSSLSock->roleSpecificInfo.client.sessionIdLen;
    }

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    /* DTLS cookie */
    if (pSSLSock->isDTLS)
    {
        ubyte2 cookieLen = pSSLSock->helloCookieLen;
        /* For DTLS1.3 the cookie is in the extensions only, just a single 0x00 length byte needed */
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            cookieLen = 0;
        }
#endif
        *pTemp++ = cookieLen;
        if (cookieLen > 0)
        {
            DIGI_MEMCPY(pTemp, pSSLSock->helloCookie, cookieLen);
            pTemp += cookieLen;
        }
    }
#endif
    /* cipher suite */

    setShortValue(pTemp, (ubyte2)(2 * numCiphers));
    pTemp += sizeof(ubyte2);

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if ((TLS11_MINORVERSION > pSSLSock->minFallbackMinorVersion) &&
        (0 == pSSLSock->handshakeCount)
#if defined(__ENABLE_DIGICERT_TLS13__)
        && (0 == pSSLSock->helloRetryRequest)
#endif
        )
    {
        /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV {0x00, 0xFF} */
        /* send only during initial SSL 3.0 hello */
        /* DO NOT add SCSV to gCipherSuites;
         * This SCSV is not a true cipher suite (it does not correspond to any
         * valid set of algorithms) and cannot be negotiated.
         */
        *pTemp++ = (ubyte)0x00;
        *pTemp++ = (ubyte)0xFF;
    }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */
#endif /*  MIN_SSL_MINORVERSION <= SSL3_MINORVERSION */

	if(pSSLSock->runtimeFlags & SSL_FLAG_SCSV_FALLBACK_VERSION_SET)
	{
		/* TLS_FALLBACK_SCSV {0x56, 0x00} */
        /* send only when application is trying to re-negotiate with fall back version */
        /* DO NOT add SCSV to gCipherSuites;
         * This SCSV is not a true cipher suite (it does not correspond to any
         * valid set of algorithms) and cannot be negotiated.
         */
        *pTemp++ = (ubyte)0x56;
        *pTemp++ = (ubyte)0x00;
	}

#ifdef __ENABLE_DIGICERT_TLS13__
    /* RFC: 4.1.4.  Hello Retry Request:  in its updated ClientHello, 
     * the client SHOULD NOT offer any pre-shared keys associated with 
     * a hash other than that of the selected cipher suite.
     */
    if(pSSLSock->helloRetryRequest)
    {
        *pTemp++ = (ubyte) (pSSLSock->pHandshakeCipherSuite->cipherSuiteId >> 8);
        *pTemp++ = (ubyte) pSSLSock->pHandshakeCipherSuite->cipherSuiteId;
    }
    else
#endif
    {

        for (i = 0; i < (sbyte4) NUM_CIPHER_SUITES; ++i)
        {
            if ((gCipherSuites[i].supported) &&
                (maxVersionSet(gCipherSuites[i].sslVersion) >= minimumVersion) &&
                (minVersionSet(gCipherSuites[i].sslVersion) <= maximumVersion))
            {
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
                if ((TRUE != pSSLSock->isCipherTableInit) ||
                    (TRUE == pSSLSock->isCipherEnabled[i]) )
#endif
                {
                    *pTemp++ = (ubyte) (gCipherSuites[i].cipherSuiteId >> 8);
                    *pTemp++ = (ubyte) (gCipherSuites[i].cipherSuiteId);
                }
            }
        }
    }

    *pTemp++ = 1;
    *pTemp++ = 0; /* no compression  (cf SSL & TLS essentials p. 79) */

    if (extensionsLength)
    {
        /* write extensions length -- subtract 2 from the extensions length */
        setShortValue(pTemp, (ubyte2)(extensionsLength-2));
        pTemp += sizeof(ubyte2);

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        /* to interoperate with old server, SSL 3.0 should only
           send renegotiation extension during rehandshake */
        if ((SSL3_MINORVERSION < pSSLSock->sslMinorVersion ||
             (SSL3_MINORVERSION == pSSLSock->sslMinorVersion && pSSLSock->isRehandshakeAllowed))
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            && ((TLS11_MINORVERSION <= pSSLSock->minFallbackMinorVersion) || (pSSLSock->isRehandshakeAllowed))
#endif
           )
        {
            ubyte4  renegotiatedConnLength = 0;
#if MIN_SSL_MINORVERSION <= SSLV3_VERSION
            ubyte4  verifyDataSize = (SSL3_MINORVERSION == pSSLSock->sslMinorVersion) ?
                                    SSL_VERIFY_DATA : TLS_VERIFYDATASIZE;
#else
            ubyte4  verifyDataSize = TLS_VERIFYDATASIZE;
#endif
            if (0 < pSSLSock->handshakeCount)
            {
                /* TLS 1.0, 1.1 and 1.2 */
                renegotiatedConnLength = verifyDataSize;
            }

            /* write extension type */
            setShortValue(pTemp, (ubyte2)tlsExt_renegotiated_connection);
            pTemp += sizeof(ubyte2);

            /* write extension length */
            setShortValue(pTemp, (ubyte2)(1 + renegotiatedConnLength));
            pTemp += sizeof(ubyte2);

            /* write renegotiated_connection<0..255> length */
            *pTemp = (ubyte) renegotiatedConnLength;
            pTemp += 1;

            if (0 < renegotiatedConnLength)
            {
                /* write renegotiated_connection string */
                DIGI_MEMCPY(pTemp, pSSLSock->client_verify_data, verifyDataSize);
                pTemp += renegotiatedConnLength;
            }
#if defined(__ENABLE_DIGICERT_TLS13__)
            pSSLSock->sentExtensions[extCount++] = tlsExt_renegotiated_connection;
#endif

        }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        if (SSL3_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
        {
#ifdef __ENABLE_DIGICERT_TLS13__
            if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
                (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION))
            {
                if (OK > (status = SSL_SOCK_constructTLSExtSupportedVersions(pSSLSock, &pTemp, 0x00)))
                {
                    goto exit;
                }
            
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                if (pSSLSock->isDTLS)
                {
                    pSSLSock->legacySSLMinorVersion = DTLS12_MINORVERSION; /* Set the legacy field to DTLS1.2 */

                    if (DTLS13_MINORVERSION == pSSLSock->clientHelloMinorVersion)
                    {
                        pSSLSock->clientHelloMinorVersion = pSSLSock->legacySSLMinorVersion;
                    }
                }
                else
#endif
                {            
                    pSSLSock->legacySSLMinorVersion = TLS12_MINORVERSION; /* Set the legacy field to TLS1.2 */

                    if (TLS13_MINORVERSION == pSSLSock->clientHelloMinorVersion)
                    {
                        pSSLSock->clientHelloMinorVersion = pSSLSock->legacySSLMinorVersion;
                    }
                }

                pSSLSock->sentExtensions[extCount++] = tlsExt_supported_versions;
            }
            else
#endif
            {
                /* note the most preferred version we sent -- used for RSA later on 
                   For TLS v1.3, we set the first version sent in "supported_versions"
                   ext as the most preferred version. This is done in
                   SSL_SOCK_constructTLSExtSupportedVersions() */
                pSSLSock->clientHelloMinorVersion = pSSLSock->sslMinorVersion;
            }
            /* server name extension? */
            if (pSSLSock->serverNameIndication)
            {
                int serverNameIndicationLen = DIGI_STRLEN((sbyte*) pSSLSock->serverNameIndication);

                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_server_name);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, (ubyte2) (5 + serverNameIndicationLen));
                pTemp += sizeof(ubyte2);

                /* write serverNameListLength */
                setShortValue(pTemp, (ubyte2)(3 + serverNameIndicationLen));
                pTemp += sizeof(ubyte2);

                /* server name type = 0 (host_name) */
                *pTemp++ = 0;

                /* write serverNameLength */
                setShortValue(pTemp, (ubyte2)(serverNameIndicationLen));
                pTemp += sizeof(ubyte2);

                /* write extension specific data */
                DIGI_MEMCPY(pTemp, pSSLSock->serverNameIndication, serverNameIndicationLen);
                pTemp += serverNameIndicationLen;
#ifdef __ENABLE_DIGICERT_TLS13__
                pSSLSock->sentExtensions[extCount++] = tlsExt_server_name;
#endif
            }
            /* ALPN  */
            if (pSSLSock->alpnProtocolsLen && pSSLSock->alpnProtocols)
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_applicationLayerProtocolNegotiation);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, (ubyte2) (2 + pSSLSock->alpnProtocolsLen));
                pTemp += sizeof(ubyte2);

                /* write alpnProtocols Length */
                setShortValue(pTemp, (ubyte2)(pSSLSock->alpnProtocolsLen));
                pTemp += sizeof(ubyte2);

                /* alpnProtocols */
                DIGI_MEMCPY(pTemp, pSSLSock->alpnProtocols,
                           pSSLSock->alpnProtocolsLen);
                pTemp += pSSLSock->alpnProtocolsLen;
#ifdef __ENABLE_DIGICERT_TLS13__
                pSSLSock->sentExtensions[extCount++] = tlsExt_applicationLayerProtocolNegotiation;
#endif

            }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
            /* If version is set less than or equal to TLSv1.2 ||
             * Min fallback version is less than or equal to TLS 1.2 ||
             * isDTLS and minor version set to DTLS 1.2
             */
            if ((!pSSLSock->isDTLS && (
                    ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET) && TLS12_MINORVERSION >= pSSLSock->advertisedMinorVersion) ||
                    ((pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET) && TLS12_MINORVERSION >= pSSLSock->minFallbackMinorVersion)))
              || (pSSLSock->isDTLS && DTLS12_MINORVERSION == pSSLSock->sslMinorVersion && TRUE == pSSLSock->supportExtendedMasterSecret))
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2) tlsExt_extendedMasterSecret);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, 0);
                pTemp += sizeof(ubyte2);
                pSSLSock->roleSpecificInfo.client.sentExtendedMasterSecret = TRUE;
            }
#endif

            /* SRP */
#ifdef __ENABLE_DIGICERT_SSL_SRP__
            if (pSSLSock->srpIdentity)
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_SRP);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, (ubyte2) 1 + pSSLSock->srpIdentity[0]);
                pTemp += sizeof(ubyte2);

                /* write identity prefixed bylength */
                DIGI_MEMCPY(pTemp, pSSLSock->srpIdentity,
                           1 + pSSLSock->srpIdentity[0]);
                pTemp += 1 + pSSLSock->srpIdentity[0];
#ifdef __ENABLE_DIGICERT_TLS13__
                pSSLSock->sentExtensions[extCount++] = tlsExt_SRP;
#endif
            }
#endif


#if defined (__ENABLE_DIGICERT_OCSP_CLIENT__)
            if (pSSLSock->certStatusReqExt)
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_status_request);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, (ubyte2)(pSSLSock->certStatusReqExtLen));
                pTemp += sizeof(ubyte2);

                /* write extension specific data */
                DIGI_MEMCPY(pTemp, pSSLSock->certStatusReqExtData, pSSLSock->certStatusReqExtLen);
                pTemp += pSSLSock->certStatusReqExtLen;
#if defined (__ENABLE_DIGICERT_TLS13__)
                pSSLSock->sentExtensions[extCount++] = tlsExt_status_request;
#endif
            }
#endif

            /* TLS1.2: signature algorithms extension */
            if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
                (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_supportedSignatureAlgorithms);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, (ubyte2) (2 + supportedSignatureAlgoListLength * 2));
                pTemp += sizeof(ubyte2);

                /* write supportedSignatureAlgorithmListLength */
                setShortValue(pTemp, (ubyte2) (supportedSignatureAlgoListLength * 2));
                pTemp += sizeof(ubyte2);

                /* write extension specific data */
                for ( i = 0; i < (sbyte4) supportedSignatureAlgoListLength; ++i)
                {
                    setShortValue( pTemp, pSupportedSignatureAlgoList[i]);
                    pTemp += sizeof(ubyte2);
                }
#ifdef __ENABLE_DIGICERT_TLS13__
                pSSLSock->sentExtensions[extCount++] = tlsExt_supportedSignatureAlgorithms;

                /* TLS 1.3: signature algorithm certs extension */
                if (((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
                     (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION)) &&
                     NULL != pSSLSock->pConfiguredSignatureCertAlgoList )
                {
                    /* Extension type */
                    setShortValue(pTemp, (ubyte2) tlsExt_signatureAlgorithmCerts);
                    pTemp += sizeof(ubyte2);

                    /* Extension length */
                    setShortValue(pTemp, (ubyte2) (2 + pSSLSock->configuredSignatureCertAlgoListLength * 2));
                    pTemp += sizeof(ubyte2);

                    /* Extension data length */
                    setShortValue(pTemp, (ubyte2) (pSSLSock->configuredSignatureCertAlgoListLength * 2));
                    pTemp += sizeof(ubyte2);

                    for (i = 0; i < (sbyte4) pSSLSock->configuredSignatureCertAlgoListLength; i++)
                    {
                        setShortValue(pTemp, pSSLSock->pConfiguredSignatureCertAlgoList[i]);
                        pTemp += sizeof(ubyte2);
                    }

                    pSSLSock->sentExtensions[extCount++] = tlsExt_signatureAlgorithmCerts;
                }
#endif
            }
#ifdef __ENABLE_DIGICERT_EAP_FAST__
            /* ticket extension ? */
            /* only if we have a ticket extension */
            if ( pSSLSock->roleSpecificInfo.client.ticket &&
                pSSLSock->roleSpecificInfo.client.ticketLength)
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_ticket);
                pTemp += sizeof(ubyte2);

#ifndef __DISABLE_EAP_FAST_EXTENSION_LENGTH__
                /* write extension length */
                setShortValue(pTemp, (ubyte2) (2 + pSSLSock->roleSpecificInfo.client.ticketLength));
                pTemp += sizeof(ubyte2);
#endif

                /* write ticket size */
                setShortValue(pTemp, (ubyte2) pSSLSock->roleSpecificInfo.client.ticketLength);
                pTemp += sizeof(ubyte2);

                if ( pSSLSock->roleSpecificInfo.client.ticketLength)
                {
                    /* write extension specific data */
                    DIGI_MEMCPY(pTemp, pSSLSock->roleSpecificInfo.client.ticket,
                                pSSLSock->roleSpecificInfo.client.ticketLength);
                    pTemp += pSSLSock->roleSpecificInfo.client.ticketLength;
                }
            }
#endif /* __ENABLE_DIGICERT_EAP_FAST__ */
#ifdef __ENABLE_DIGICERT_TLS13__
            if (((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
                 (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION)) &&
                0 == pSSLSock->handshakeCount && pSSLSock->roleSpecificInfo.client.requestSessionTicket == 1)
            {
                /* empty ticket extension */
                setShortValue(pTemp, (ubyte2)tlsExt_ticket);
                pTemp += sizeof(ubyte2);

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
                if (NULL != pSSLSock->roleSpecificInfo.client.pTicketTls)
                {
                    setShortValue(pTemp, pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen);
                    pTemp += sizeof(ubyte2);
                    DIGI_MEMCPY(pTemp, pSSLSock->roleSpecificInfo.client.pTicketTls->pTicket, pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen);
                    pTemp += pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen;
                }
                else
#endif
                {
                    setShortValue(pTemp, (ubyte2)0);
                    pTemp += sizeof(ubyte2);
                }
                pSSLSock->sentExtensions[extCount++] = tlsExt_ticket;
            }
#endif
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        if (pSSLSock->sslMinorVersion != TLS13_MINORVERSION &&
            (TRUE == isTLSTicketSupported(pSSLSock) || (pSSLSock->isDTLS && pSSLSock->sslMinorVersion != DTLS13_MINORVERSION)) &&
            (pSSLSock->roleSpecificInfo.client.requestSessionTicket == 1))
        {
                /* empty ticket extension */
                setShortValue(pTemp, (ubyte2)tlsExt_ticket);
                pTemp += sizeof(ubyte2);
                if (NULL != pSSLSock->roleSpecificInfo.client.pTicketTls)
                {
                    setShortValue(pTemp, pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen);
                    pTemp += sizeof(ubyte2);
                    DIGI_MEMCPY(pTemp, pSSLSock->roleSpecificInfo.client.pTicketTls->pTicket, pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen);
                    pTemp += pSSLSock->roleSpecificInfo.client.pTicketTls->ticketLen;
                }
                else
                {
                    setShortValue(pTemp, (ubyte2)0);
                    pTemp += sizeof(ubyte2);
                }
        }
#endif
#ifdef __ENABLE_DIGICERT_INNER_APP__
            /* only if we have a inner application extension */
            if (pSSLSock->roleSpecificInfo.client.innerApp)
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_innerApplication);
                pTemp += sizeof(ubyte2);

                /* write innerApp size */
                setShortValue(pTemp, (ubyte2) sizeof(ubyte2));
                pTemp += sizeof(ubyte2);

                /* write innerApp Value */
                setShortValue(pTemp, (ubyte2) pSSLSock->roleSpecificInfo.client.innerAppValue);
                pTemp += sizeof(ubyte2);
            }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
            /* For DTLS1.3 server didn't send a group, so continue to the else leg even on retryRequest */
            if (pSSLSock->helloRetryRequest && pSSLSock->roleSpecificInfo.client.selectedGroup)
            {
                status = constructTLSExtSupportedGroup(
                    pSSLSock, &pTemp, 1, 1 << pSSLSock->roleSpecificInfo.client.selectedGroup);
                if (OK > status)
                {
                    goto exit;
                }
            }
            else
#endif /* __ENABLE_DIGICERT_TLS13__ */
            {
                if ( cipherFlags & (SSL_KEYEX_ECDH_BIT | SSL_KEYEX_ECDHE_BIT) )
                {
                    status = constructTLSExtSupportedGroup(
                        pSSLSock, &pTemp, pSSLSock->supportedGroupListLength, pSSLSock->supportedGroups);
                    if (OK > status)
                    {
                        goto exit;
                    }
                }
            }
#if defined(__ENABLE_DIGICERT_TLS13__)
            pSSLSock->sentExtensions[extCount++] = tlsExt_supportedGroups;
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__))
            /* use_srtp extension? */
            if (pSSLSock->isDTLS && pSSLSock->useSrtp)
            {
                /* TODO: do this once */
                ubyte4 profileCount = numSrtpProfiles(pSSLSock);

                /* write extension type */
                setShortValue(pTemp, (ubyte2)dtlsExt_use_srtp);
                pTemp += sizeof(ubyte2);

                /* write extension length */
                setShortValue(pTemp, (ubyte2) (2 + 2*profileCount + 1 + ((NULL != pSSLSock->srtpMki) ? *(pSSLSock->srtpMki) : 0)) );
                pTemp += sizeof(ubyte2);

                /* write SRTPProtectionProfileListLength */
                setShortValue(pTemp, (ubyte2)(2*profileCount));
                pTemp += sizeof(ubyte2);

                for (i = 0; i < (sbyte4)NUM_SRTP_PROFILES; ++i)
                {
                    if (gSrtpProfiles[i].supported)
                    {
#ifdef __ENABLE_DIGICERT_SRTP_PROFILES_SELECT__
                        if ((TRUE != pSSLSock->isSrtpProfileTableInit) ||
                            (TRUE == pSSLSock->isSrtpProfileEnabled[i]) )
#endif
                        {
                            *pTemp++ = (ubyte) (gSrtpProfiles[i].profileId >> 8);
                            *pTemp++ = (ubyte) (gSrtpProfiles[i].profileId);
                        }
                    }
                }

                /* write srtp_mki content if any */
                if (NULL != pSSLSock->srtpMki)
                {
                    DIGI_MEMCPY(pTemp, pSSLSock->srtpMki, 1 + *(pSSLSock->srtpMki));
                    pTemp += 1 + *(pSSLSock->srtpMki);
                }
                else
                {
                    *pTemp = 0;
                    pTemp += 1;
                }
            }
#endif

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
            if (pSSLSock->sendHeartbeatMessage != noHeartbeatMessages)
            {
                /* write extension type */
                setShortValue(pTemp, (ubyte2)tlsExt_heartbeat);
                pTemp += sizeof(ubyte2);

                setShortValue(pTemp, (ubyte2)1);
                pTemp += sizeof(ubyte2);

                *pTemp = pSSLSock->sendHeartbeatMessage;
                pTemp++;
            }
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
            if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
                (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION))
            {
#ifdef __ENABLE_DIGICERT_ECC__

                if (OK > (status = constructTLSExtKeyShare(pSSLSock, &pTemp, &pointLen)))
                {
                    goto exit;
                }
                pSSLSock->sentExtensions[extCount++] = tlsExt_key_share;
#endif
                /* RFC: 4.1.2: Including a "cookie" extension if one was provided in the
                 * HelloRetryRequest.
                 */
                if (pSSLSock->helloRetryRequest)
                {
                    if(pSSLSock->helloCookieLen > 0)
                    {
                        setShortValue( pTemp, (ubyte2) tlsExt_cookie);
                        pTemp += sizeof(ubyte2);

                        setShortValue(pTemp, (ubyte2)(pSSLSock->helloCookieLen) + 2);
                        pTemp += sizeof(ubyte2);

                        /* cookie Length */
                        setShortValue(pTemp, (ubyte2)pSSLSock->helloCookieLen);
                        pTemp += sizeof(ubyte2);

                        DIGI_MEMCPY(pTemp, pSSLSock->helloCookie, pSSLSock->helloCookieLen);
                        pTemp += pSSLSock->helloCookieLen;
                        pSSLSock->sentExtensions[extCount++] = tlsExt_cookie;
                    }
                }

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
                if (pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH)
                {
                    if (OK > (status = constructTLSpostHandShakeAuth(pSSLSock, &pTemp)))
                    {
                        goto exit;
                    }
                    pSSLSock->sentExtensions[extCount++] = tlsExt_postHandshakeAuth;
                }
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                /* Send PSK if we have a valid PSK to send */
                if (numOfTLS13PSK > 0)
                {
#if (defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                    if (1 == earlyDataSet)
                    {
                        if (OK > (status = SSL_SOCK_constructTLSExtEarlyData(pSSLSock,
                                                                    ((SSLHandshakeHeader *)pHSH)->handshakeType,
                                                                     &pTemp)))
                        {
                            goto exit;
                        }
                        pSSLSock->sentExtensions[extCount++] = tlsExt_early_data;
                    }
#endif

                    if (OK > (status = SSL_CLIENT_constructTLSExtPSKKeyExchangeModes(pSSLSock, &pTemp)))
                    {
                        goto exit;
                    }
                    pSSLSock->sentExtensions[extCount++] = tlsExt_psk_key_exchange_modes;

                    if (OK > (status = constructTLSExtPreSharedKey(pSSLSock, &pTemp, TLS13_HRR_GET_RX(pSSLSock), selectedIndex)))
                    {
                        goto exit;
                    }
                    pSSLSock->sentExtensions[extCount++] = tlsExt_pre_shared_key;
                }
#endif
            }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        }
    }
#ifdef __ENABLE_DIGICERT_TLS13__
    pSSLSock->numExtensions = extCount;
#endif

    /* add to the hashes */
    /* save client hello for hash calculation later: after processed server hello and know the version and cipher */
    if (pSSLSock->roleSpecificInfo.client.helloBuffer)
    {
        FREE(pSSLSock->roleSpecificInfo.client.helloBuffer);
    }

    pSSLSock->roleSpecificInfo.client.helloBuffer = (ubyte*) MALLOC( pSSLSock->buffers[0].length - sizeofRecordHeader);
    if (NULL == pSSLSock->roleSpecificInfo.client.helloBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.helloBuffer, pSSLSock->buffers[0].data, (pSSLSock->buffers[0].length - sizeofRecordHeader));
    pSSLSock->roleSpecificInfo.client.helloBufferLen = (pSSLSock->buffers[0].length - sizeofRecordHeader);
    if (TRUE != isRehandshake)
    {
        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            numBytesSent  = 0;
            status = (MSTATUS) pSSLSock->buffers[0].length;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
            if (NULL != pSSLSock->pTransportHandler)
            {
                if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
                {
                    if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId, 
                                                                                          (sbyte *)(pSSLSock->buffers[0].pHeader), 
                                                                                          totalLength, &numBytesSent)))
                    {
                        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                        goto exit;
                    }
                }
                else
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
            }
            else
#endif
            {
#ifndef __DIGICERT_IPSTACK__
                if (OK > (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)(pSSLSock->buffers[0].pHeader), totalLength, &numBytesSent)))
#else
                if (OK > (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)(pSSLSock->buffers[0].pHeader), totalLength, &numBytesSent)))
#endif
                    goto exit;
            }
        }

        if (numBytesSent != pSSLSock->buffers[0].length)
        {
            pSSLSock->pOutputBufferBase = pSSLSock->buffers[0].pHeader;
            pSSLSock->pOutputBuffer     = numBytesSent + pSSLSock->buffers[0].pHeader;
            pSSLSock->outputBufferSize  = pSSLSock->buffers[0].length + fragmentLen;
            pSSLSock->numBytesToSend    = pSSLSock->buffers[0].length + fragmentLen - numBytesSent;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
            if (pSSLSock->isDTLS)
            {
                /* fragment the records to meet PMTU */
                pSSLSock->bufIndex = 0;
                pSSLSock->numBuffers = 1;

                if (OK > (status = fragmentHandshakeMessages(pSSLSock, fragmentLen)))
                    goto exit;

                releaseRetransmissionBuffer(pSSLSock);
                addDataToRetransmissionBuffer(pSSLSock, SSL_HANDSHAKE, (const sbyte*)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
            }
#endif

            pSSLSock->buffers[0].pHeader              = NULL;
        }
    }
    else
    {
        pSSLSock->bufIndex = 0;
        pSSLSock->numBuffers = 1;
        status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock);
    }

exit:
    if ((TRUE != isRehandshake) || (OK > status))
    {
        /* free the buffers */
        if (pSSLSock->buffers[0].pHeader)
        {
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->buffers[0].pHeader));
        }
    }

    return status;

} /* SSL_CLIENT_sendClientHello */


/*------------------------------------------------------------------*/

static MSTATUS
fillClientCertificate(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length)
{
    ubyte*              pSHSH;
    ubyte*              pWriteCert = NULL;
    const SizedBuffer*  certificates = pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts;
    ubyte4              numCert = pSSLSock->roleSpecificInfo.client.numMutualAuthCert;
    ubyte4              sizeofHandshakeHeader;
    ubyte4              hSize = length;

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(hSize - sizeofHandshakeHeader));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(hSize - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CERTIFICATE;
        hSize = hSize - sizeofHandshakeHeader;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(hSize - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CERTIFICATE;
        hSize = hSize - sizeofHandshakeHeader;
    }

    pWriteCert = (ubyte*)(pSHSH + sizeofHandshakeHeader);

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
         (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        *pWriteCert = pSSLSock->certificateRequestContextLength;
        pWriteCert++;
        if (NULL != pSSLSock->certificateRequestContext)
        {
            DIGI_MEMCPY(pWriteCert, pSSLSock->certificateRequestContext, pSSLSock->certificateRequestContextLength);
            pWriteCert += pSSLSock->certificateRequestContextLength;
        }
        hSize = hSize - (1 + pSSLSock->certificateRequestContextLength);
    }
#endif

    /* store cert chain length */
    setMediumValue(pWriteCert, (ubyte2) (hSize - SSL_MEDIUMSIZE));
    pWriteCert += SSL_MEDIUMSIZE;

    if (0 != numCert)
    {
        ubyte4 i;
        /* for each certificate, store value in medium and then certificate     */
        for (i = 0; i < numCert; ++i)
        {
            ubyte4 certLen = certificates[i].length;
#if defined(__ENABLE_DIGICERT_TLS13__)
            ubyte2 extensionsLen = 0;
            ubyte *pExtLen;
#endif
            /* for non-qs we do not allow a certLen more than 16 bits */
            if (certLen & 0xffff0000)
            {
                return ERR_BAD_LENGTH;
            }

            /* TO DO, in QS version we need to use certLen as a ubyte4 and "setLongValue" */
            setMediumValue(pWriteCert, (ubyte2) certLen);
            pWriteCert += SSL_MEDIUMSIZE;

            DIGI_MEMCPY(pWriteCert, certificates[i].data, certLen);
            pWriteCert += certLen;

#if defined(__ENABLE_DIGICERT_TLS13__)
            /* Only send the OCSP response for the first certificate.
             *
             * RFC 8446 section 4.4.2 specifes that if an extension applies to
             * the entires chain then it SHOULD be included in the first
             * CertificateEntry. Since OCSP is sent as part of the ClientHello
             * for the client and part of the CertificateRequest for the server,
             * there currently is no way to specify an OCSP request for an
             * individual certificate, therefore only the first certificate
             * entry will contain the stapled OCSP response.
             */
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                 (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                pExtLen = pWriteCert;
                pWriteCert += 2;
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
                if ( (1 == pSSLSock->recvStatusReqExt) &&
                     (0 == i) && (NULL != pSSLSock->pOcspResponse) )
                {
                    extensionsLen += 2 /* extension type */ +
                                     2 /* extension length */ +
                                     1 /* response type */ +
                                     SSL_MEDIUMSIZE /* response length */ +
                                     pSSLSock->ocspResponseLen;

                    setShortValue(pWriteCert, tlsExt_status_request);
                    pWriteCert += 2;

                    setShortValue(pWriteCert, extensionsLen - 4);
                    pWriteCert += 2;

                    *pWriteCert = certStatusType_ocsp;
                    pWriteCert++;

                    setMediumValue(pWriteCert, (ubyte2)pSSLSock->ocspResponseLen);
                    pWriteCert += SSL_MEDIUMSIZE;

                    DIGI_MEMCPY(pWriteCert, pSSLSock->pOcspResponse, pSSLSock->ocspResponseLen);
                    pWriteCert += pSSLSock->ocspResponseLen;
                }
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

                /* Set the total extension length. */
                setShortValue(pExtLen, extensionsLen);
            }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        }
    }
    else
    {
        /* we have no key data, we're unable to perform a certificateVerify */
        pSSLSock->isMutualAuthNegotiated = FALSE;
    }

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    return OK;

} /* fillClientCertificate */



/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SRP__))

static MSTATUS
SSL_SOCK_SRPClientPremasterSecret(SSLSocket* pSSLSock,
                                  ubyte** premaster, sbyte4* premasterLen,
                                  ubyte* pA, vlong** ppVlongQueue)
{
    MSTATUS status;
    ubyte* BB;
    ubyte4 BBlen;
    sbyte4 ALen;
    ubyte aBytes[32];

    vlong* tmp1 = 0;
    vlong* tmp2 = 0;

    vlong* a = 0;
    vlong* A = 0;
    vlong* B = 0;

    vlong* k = 0;
    vlong* u = 0;
    vlong* x = 0;

    vlong* N = 0;
    vlong* g = 0;

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

    if (OK > (status = VLONG_vlongFromByteString(modulus, modulusLen,
                                                 &N, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(generator, generatorLen,
                                                 &g, ppVlongQueue)))
    {
        goto exit;
    }

    do
    {
        VLONG_freeVlong(&A, ppVlongQueue);
        VLONG_freeVlong(&a, ppVlongQueue);

        if (OK > (status = pSSLSock->rngFun( pSSLSock->rngFunArg, sizeof(aBytes), aBytes)))
        {
            goto exit;
        }

        if (OK >( status = VLONG_vlongFromByteString(aBytes, sizeof(aBytes), &a, 0)))
        {
            goto exit;
        }

        DIGI_MEMSET( aBytes, 0, sizeof(aBytes)); /* fwiw */

        /* 1.compute A = g^a % N */
        if (OK > (status = VLONG_modexp(MOC_MOD(pSSLSock->hwAccelCookie)
                                        g, a, N, &A, ppVlongQueue)))
        {
            goto exit;
        }

        /* we need to verify that A length is of the proper size
         because leading zeroes are not allowed */
        if (OK > ( status = VLONG_byteStringFromVlong(A, 0, &ALen)))
        {
            goto exit;
        }
    } while (ALen != modulusLen);

    /* write A out : length (2) + A bytes */
    setShortValue(pA, (ubyte2) modulusLen);
    /* write A value out */
    if (OK > (status = VLONG_byteStringFromVlong(A, pA+2, &ALen)))
    {
        goto exit;
    }

    BBlen = getShortValue(pSSLSock->roleSpecificInfo.client.srpSB + 1 + *(pSSLSock->roleSpecificInfo.client.srpSB));
    BB = pSSLSock->roleSpecificInfo.client.srpSB + 3 + *(pSSLSock->roleSpecificInfo.client.srpSB);

    /* B */
    if (OK > ( status = VLONG_vlongFromByteString(BB, BBlen, &B, ppVlongQueue)))
    {
        goto exit;
    }
    /* make sure B is not 0 % N -- required by RFC 5404 */
    if ( OK > ( status = VLONG_operatorModSignedVlongs(B, N, &tmp1, ppVlongQueue)))
    {
        goto exit;
    }

    if ( 0 == VLONG_compareUnsigned(tmp1, 0))
    {
        status = ERR_SSL_SRP_INVALID_PARAMS;
        goto exit;
    }

    /* k */
    if (OK >( status = VLONG_vlongFromByteString(kBytes, SHA1_RESULT_SIZE,
                                                 &k, ppVlongQueue)))
    {
        goto exit;
    }

    /* u */
    if (OK > ( status = SSL_SOCK_SRPConcatPadSha(pSSLSock,
                                                 pA + 2, modulusLen,
                                                 BB, BBlen,
                                                 modulusLen, shaResult)))
    {
        goto exit;
    }

    if (OK > ( status = VLONG_vlongFromByteString(shaResult, SHA1_RESULT_SIZE,
                                                  &u, ppVlongQueue)))
    {
        goto exit;
    }

    /* compute x  = SHA1(s | SHA1(I | ":" | P)) */
    /* remember that srpSB is salt (1 byte) followed by B (2 bytes) */
    if (OK > ( status = SSL_SOCK_SRPConcatPadSha(pSSLSock,
                                                 pSSLSock->roleSpecificInfo.client.srpSB + 1,
                                                 *(pSSLSock->roleSpecificInfo.client.srpSB),
                                                 pSSLSock->roleSpecificInfo.client.ipHash,
                                                 SHA1_RESULT_SIZE,
                                                 0, shaResult)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(shaResult, SHA1_RESULT_SIZE, &x, ppVlongQueue)))
    {
        goto exit;
    }

    /* compute tmp1 = g ^x % N */
    VLONG_freeVlong(&tmp1, ppVlongQueue);
    if (OK > (status = VLONG_modexp(MOC_MOD(pSSLSock->hwAccelCookie)
                                    g, x, N, &tmp1, ppVlongQueue)))
    {
        goto exit;
    }

    /* tmp2 = N */
    if (OK > (status = VLONG_makeVlongFromVlong(N, &tmp2, ppVlongQueue)))
    {
        goto exit;
    }

    /* tmp2 = N - g ^ x % N */
    if (OK > ( status = VLONG_subtractSignedVlongs(tmp2, tmp1, ppVlongQueue)))
    {
        goto exit;
    }

    /* tmp1 = k * (N - g^x) % N */
    if (OK > (status = VLONG_unsignedMultiply(tmp1, k, tmp2)))
    {
        goto exit;
    }

    /* B <- B - k * g^x %N */
    if (OK > (status = VLONG_addSignedVlongs(B, tmp1, ppVlongQueue)))
    {
    }

    /* 2.3 tmp 1= u.x */
    if (OK > (status = VLONG_unsignedMultiply(tmp1, u, x)))
    {
        goto exit;
    }

    /* 2.4 tmp = a + u.x  ( about 40 bytes long) */
    if (OK > ( status = VLONG_addSignedVlongs(tmp1, a, ppVlongQueue)))
    {
        goto exit;
    }

    /* final exponentiation */
    VLONG_freeVlong(&tmp2, ppVlongQueue);
    if (OK > ( status = VLONG_modexp(B, tmp1, N, &tmp2, ppVlongQueue)))
    {
        goto exit;
    }

    /* serialize premaster */
    if (OK > (status = SSL_SOCK_SerializeVLong(tmp2, premaster, premasterLen)))
    {
        goto exit;
    }

exit:

    VLONG_freeVlong(&tmp1, 0);
    VLONG_freeVlong(&tmp2, 0);

    VLONG_freeVlong(&a, 0);
    VLONG_freeVlong(&A, 0);
    VLONG_freeVlong(&B, 0);

    VLONG_freeVlong(&k, 0);
    VLONG_freeVlong(&u, 0);
    VLONG_freeVlong(&x, 0);

    VLONG_freeVlong(&N, 0);
    VLONG_freeVlong(&g, 0);

    VLONG_freeVlongQueue(ppVlongQueue);

    return status;
}
#endif

/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static MSTATUS
fillClientEncryptedRsaPresecret(SSLSocket* pSSLSock, ubyte *pPresecret,
                                ubyte *pEncryptedPresecret, vlong **ppVlongQueue)
{
    sbyte4              cipherTextLen;
    MSTATUS             status;
    RSAKey*             pRSAKey;

    /* generate presecret */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        pPresecret[0] = DTLS1_MAJORVERSION;
    } else
#endif
    {
        pPresecret[0] = SSL3_MAJORVERSION;
    }

    /* this needs to match the one we sent in client hello */
    pPresecret[1] = pSSLSock->clientHelloMinorVersion;

    /* generate rest of presecret */
    pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_RSAPRESECRETSIZE - 2, pPresecret + 2);

    pRSAKey = pSSLSock->handshakeKey.key.pRSA;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                                               &cipherTextLen,
                                                               pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }
#else
    if (akt_rsa == pSSLSock->handshakeKey.type)
    {
        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &cipherTextLen)))
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

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
    {
        setShortValue(pEncryptedPresecret, (ubyte2)cipherTextLen);
        pEncryptedPresecret += 2;
    }

    /* encrypt presecret with certificate key into the buffer */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_RSA_encrypt(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                   pPresecret, SSL_RSAPRESECRETSIZE, pEncryptedPresecret,
                                   pSSLSock->rngFun, pSSLSock->rngFunArg, ppVlongQueue,
                                   pSSLSock->handshakeKey.type)))
#else
    if (OK > (status = RSA_encrypt(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                   pPresecret, SSL_RSAPRESECRETSIZE, pEncryptedPresecret,
                                   pSSLSock->rngFun, pSSLSock->rngFunArg, ppVlongQueue)))
#endif
    {
        goto exit;
    }

exit:
    return status;

} /* fillClientEncryptedRsaPresecret */
#endif


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static MSTATUS
fillClientRsaKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    ubyte*              pSHSH;
    ubyte               presecret[SSL_RSAPRESECRETSIZE];
    sbyte4              cipherTextLen;
    ubyte*              encryptedPresecret;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;
    RSAKey*             pRSAKey;

    if ( akt_rsa != pSSLSock->handshakeKey.type)
    {
        status = ERR_SSL_INVALID_KEY_TYPE;
        goto exit;
    }

    pRSAKey = pSSLSock->handshakeKey.key.pRSA;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                                               &cipherTextLen,
                                                               pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }
#else
    if (akt_rsa == pSSLSock->handshakeKey.type)
    {
        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &cipherTextLen)))
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

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue( ((DTLSHandshakeHeader *)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader *)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue( ((SSLHandshakeHeader *)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader *)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }
    encryptedPresecret = (ubyte *)(pSHSH + sizeofHandshakeHeader);

    if (OK > (status = fillClientEncryptedRsaPresecret(pSSLSock, presecret,
                                    encryptedPresecret, ppVlongQueue)))
        goto exit;

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* we can generate the key material now */
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, presecret, SSL_RSAPRESECRETSIZE);

exit:
    return status;

} /* fillClientRsaKeyExchange */
#endif


/*---------------------------------------------------------------------------*/

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )

static MSTATUS fillClientEccKeyExchange(SSLSocket* pSSLSock, ECCKey* pECCKey,
                                        ubyte *pBuffer, ubyte2 length)
{
    ubyte*              pSHSH;
    MSTATUS             status;
    ubyte*              pSharedSecret = 0;
    ubyte*              pPayload;
    sbyte4              sharedSecretLen;
    ubyte4              sizeofHandshakeHeader;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    ECCKey *pNewKey = NULL;
    ubyte4 curveId;
#else
    PrimeFieldPtr       pPF;
    PFEPtr              k = 0, Qx = 0, Qy = 0;
#endif

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    pPF = EC_getUnderlyingField(pECCKey->pCurve);
#endif
    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue( ((DTLSHandshakeHeader *)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader *)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue( ((SSLHandshakeHeader *)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader *)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    /* generate a new ECDH key pair on the curve and send the public key
        The presecret is the shared secret generated by the ECDH operation */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    /* Note a global keyType is passed. This can be set by the user.
     * This will be moved to the SSL_settings
     */
    if (OK > (status = CRYPTO_INTERFACE_EC_getCurveIdFromKey(pECCKey, &curveId, g_keyType)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(pSSLSock->hwAccelCookie) curveId, (void **)&pNewKey,
                                                                pSSLSock->rngFun, pSSLSock->rngFunArg,
                                                                g_keyType, NULL)))
    {
        goto exit;
    }
#else
    if (OK > (status = PRIMEFIELD_newElement( pPF, &k)) ||
        OK > (status = PRIMEFIELD_newElement( pPF, &Qx)) ||
        OK > (status = PRIMEFIELD_newElement( pPF, &Qy)))
    {
        goto exit;
    }

    if (OK > (status = EC_generateKeyPair( pECCKey->pCurve, pSSLSock->rngFun,
                                            pSSLSock->rngFunArg, k, Qx, Qy)))
    {
        goto exit;
    }
#endif

    pPayload = (ubyte*)(pSHSH+sizeofHandshakeHeader);
    /* add the redundant byte for length (ECPoint ) */
    *pPayload++ = (ubyte) (length - 1 - sizeofHandshakeHeader);

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status =  CRYPTO_INTERFACE_EC_writePublicKeyToBuffer(MOC_ECC(pSSLSock->hwAccelCookie) pNewKey, pPayload,
                                                                   (length - sizeofHandshakeHeader),
                                                                   g_keyType)))
    {
        goto exit;
    }
#else
    if (OK > (status = EC_writePointToBuffer( pECCKey->pCurve, Qx, Qy, pPayload,
                                                length - sizeofHandshakeHeader)))
    {
        goto exit;
    }
#endif

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* we can generate the key material now */
    /* derive the presecret */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeys(MOC_ECC(pSSLSock->hwAccelCookie)
                                                                          pNewKey,
                                                                          pECCKey,
                                                                          &pSharedSecret,
                                                                          (ubyte4 *)&sharedSecretLen,
                                                                          1/* X co-ordinate only */,
                                                                          NULL, g_keyType)))
    {
        goto exit;
    }
#else
    if ( OK > ( status = ECDH_generateSharedSecretAux( pECCKey->pCurve,
                                                        pECCKey->Qx,
                                                        pECCKey->Qy,
                                                        k,
                                                        &pSharedSecret,
                                                        &sharedSecretLen,
                                                        1))) /* X coordinate only */
    {
        goto exit;
    }
#endif
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, pSharedSecret, sharedSecretLen);

exit:

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    CRYPTO_INTERFACE_EC_deleteKey((void **)&pNewKey, g_keyType);
#else
    PRIMEFIELD_deleteElement( pPF, &k);
    PRIMEFIELD_deleteElement( pPF, &Qx);
    PRIMEFIELD_deleteElement( pPF, &Qy);
#endif

    if ( pSharedSecret)
    {
        FREE( pSharedSecret);
    }

    return status;

} /* fillClientEccKeyExchange */
#endif /* (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__)
            || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) ||
            defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) ) */


/*---------------------------------------------------------------------------*/

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))

static MSTATUS fillClientEcdhKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer,
                                        ubyte2 length, vlong **ppVlongQueue)
{

    if ( akt_ecc != pSSLSock->handshakeKey.type)
    {
        return ERR_SSL_INVALID_KEY_TYPE;
    }

    return fillClientEccKeyExchange(pSSLSock,
                pSSLSock->handshakeKey.key.pECC,
                pBuffer,
                length);

} /* fillClientEcdhKeyExchange */
#endif /* (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__)) */


/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))

static MSTATUS fillClientEcdheKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer,
                                        ubyte2 length, vlong **ppVlongQueue)
{
    if ( akt_ecc != pSSLSock->ecdheKey.type)
    {
        return ERR_SSL_INVALID_KEY_TYPE;
    }
    return fillClientEccKeyExchange(pSSLSock,
                pSSLSock->ecdheKey.key.pECC,
                pBuffer,
                length);

} /* fillClientEcdheKeyExchange */
#endif /* (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) \\
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)) */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
static MSTATUS
fillClientPskKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    ubyte*              pSHSH;
    ubyte               presecret[2 + SSL_PSK_MAX_LENGTH + 2 + SSL_PSK_MAX_LENGTH];
    ubyte*              pPsk;
    sbyte4              pskLength;
    ubyte*              pPskIdentity;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;
    MOC_UNUSED(ppVlongQueue);

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue( ((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue( ((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    /* fill in the identity */
    pPskIdentity = (ubyte *)(pSHSH + sizeofHandshakeHeader);
    setShortValue(pPskIdentity, (ubyte2)(pSSLSock->roleSpecificInfo.client.pskIdentityLength));
    DIGI_MEMCPY(2 + pPskIdentity, pSSLSock->roleSpecificInfo.client.pskIdentity, pSSLSock->roleSpecificInfo.client.pskIdentityLength);

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* build shared secret */
    pPsk      = presecret;
    pskLength = pSSLSock->roleSpecificInfo.client.pskLength;

    setShortValue(pPsk, (ubyte2)(pskLength));    pPsk += 2;
    DIGI_MEMSET   (pPsk, 0x00, pskLength);        pPsk += pskLength;
    setShortValue(pPsk, (ubyte2)(pskLength));    pPsk += 2;
    DIGI_MEMCPY   (pPsk, pSSLSock->roleSpecificInfo.client.psk, pskLength);

    /* we can generate the key material now */
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, presecret, 2 + pskLength + 2 + pskLength);

    return status;

} /* fillClientPskKeyExchange */
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)))
static MSTATUS
fillClientRsaPskKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    ubyte*              pSHSH;
    ubyte               presecret[2 + SSL_RSAPRESECRETSIZE + 2 + SSL_PSK_MAX_LENGTH];
    ubyte*              pPsk;
    sbyte4              pskLength;
    ubyte*              pPskIdentity;
    ubyte4              pskIdentityLength;
    ubyte*              encryptedPresecret;
    sbyte4              cipherTextLen;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;

    /* allocate buffer big enough for the handshake record */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA,
                                                               &cipherTextLen,
                                                               pSSLSock->handshakeKey.type)))
    {
        goto exit;
    }
#else
    if (akt_rsa == pSSLSock->handshakeKey.type)
    {
        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->handshakeKey.key.pRSA, &cipherTextLen)))
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

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue( ((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue( ((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    /* fill in the identity */
    pPskIdentity = (ubyte *)(pSHSH + sizeofHandshakeHeader);
    pskIdentityLength = pSSLSock->roleSpecificInfo.client.pskIdentityLength;
    setShortValue(pPskIdentity, (ubyte2)(pskIdentityLength));
    DIGI_MEMCPY(2 + pPskIdentity, pSSLSock->roleSpecificInfo.client.pskIdentity, pskIdentityLength);

    encryptedPresecret = 2 + pPskIdentity + pskIdentityLength;

    /* fill in encrypted presecret and presecret */
    if (OK > (status = fillClientEncryptedRsaPresecret(pSSLSock, 2 + presecret, encryptedPresecret, ppVlongQueue)))
        goto exit;

    /* set length of RSA pre-secret */
    presecret[0] = 0;
    presecret[1] = (ubyte)SSL_RSAPRESECRETSIZE;

    /* fill in psk into shared secret */
    pPsk      = &(presecret[2 + SSL_RSAPRESECRETSIZE]);
    pskLength = pSSLSock->roleSpecificInfo.client.pskLength;

    setShortValue(pPsk, (ubyte2)(pskLength));    pPsk += 2;
    DIGI_MEMCPY   (pPsk, pSSLSock->roleSpecificInfo.client.psk, pskLength);

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* we can generate the key material now */
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, presecret, 2 + SSL_RSAPRESECRETSIZE + 2 + pskLength);

exit:
    return status;

} /* fillClientPskKeyExchange */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS
fillClientDiffieHellmanKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    ubyte*              pSHSH;
    ubyte*              pYc;
    ubyte4              lenYc;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;
    MOC_UNUSED(ppVlongQueue);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte*              pPublicKey = NULL;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    MDhKeyTemplate template = { 0 };
#else
    ubyte4              publicKeyLength = 0;
#endif
#else
    ubyte*              pK = NULL;
    ubyte4              lenK;
#endif

    /* get length of Yc */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(
        MOC_DH(pSSLSock->hwAccelCookie) &template, pSSLSock->pDHcontext,
        MOC_GET_PUBLIC_KEY_DATA, NULL);
    if (OK != status)
        goto exit;

    lenYc = template.pLen;
#else
    status = CRYPTO_INTERFACE_DH_getPublicKeyExt(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, &pPublicKey, &publicKeyLength, NULL);
    if (OK != status)
        goto exit;

    lenYc = publicKeyLength;
#endif
#else
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    lenYc = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_p)) / 8;
#else
    lenYc = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_f)) / 8;
#endif
#endif

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;

    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    pYc = (ubyte *)(pSHSH + sizeofHandshakeHeader);

    /* store Yc */
    setShortValue(pYc, (ubyte2)lenYc);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    while (lenYc > template.fLen)
    {
        *(pYc + 2) = 0x00;
        pYc++;
        lenYc--;
    }
#endif
    status = DIGI_MEMCPY(2 + pYc, pPublicKey, lenYc);
    if (OK != status)
        goto exit;
#else
    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_f, 2 + pYc, lenYc)))
        goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* allocate buffer for shared secret */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, pSSLSock->pSharedSecret, pSSLSock->sharedSecretLength);
#else
    lenK  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_k)) / 8;

    if (NULL == (pK =(ubyte*)  MALLOC(lenK)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* convert shared secret (k) into something digestible */
    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_k, pK, lenK)))
        goto exit;

    /* we can generate the key material now */
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, pK, lenK);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
exit:

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL != pK)
        FREE(pK);
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pSSLSock->pDHcontext, &template, NULL);
#endif
    if (NULL != pPublicKey)
        DIGI_FREE((void**)&pPublicKey);

    if (NULL != pSSLSock->pSharedSecret)
    {
        DIGI_MEMSET(pSSLSock->pSharedSecret, 0x00, pSSLSock->sharedSecretLength);
        DIGI_FREE((void**)&(pSSLSock->pSharedSecret));
    }
#endif

    return status;

} /* fillClientDiffieHellmanKeyExchange */
#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS
fillClientDiffieHellmanPskKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    ubyte*              pSHSH;
    ubyte*              pYc;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    ubyte*              pPub = NULL;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    MDhKeyTemplate template = { 0 };
#endif
#endif
    ubyte4              lenYc;
    ubyte4              lenK;
    ubyte*              pSecret = NULL;
    sbyte4              pskLength;
    ubyte*              pPskIdentity;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;
    MOC_UNUSED(ppVlongQueue);

    /* get length of Yc */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(
        MOC_DH(pSSLSock->hwAccelCookie) &template, pSSLSock->pDHcontext,
        MOC_GET_PUBLIC_KEY_DATA, NULL);
    if (OK != status)
        goto exit;

    lenYc = template.pLen;
#else
    status = CRYPTO_INTERFACE_DH_getPublicKeyExt( MOC_DH(pSSLSock->hwAccelCookie)
        pSSLSock->pDHcontext, &pPub, &lenYc, NULL);
    if (OK != status)
    {
        goto exit;
    }
#endif
#else
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    lenYc = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_p)) / 8;
#else
    lenYc = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_f)) / 8;
#endif
#endif

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;

    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    /* fill in the identity */
    pPskIdentity = (ubyte *)(pSHSH + sizeofHandshakeHeader);
    setShortValue(pPskIdentity, (ubyte2)(pSSLSock->roleSpecificInfo.client.pskIdentityLength));
    DIGI_MEMCPY(2 + pPskIdentity, pSSLSock->roleSpecificInfo.client.pskIdentity, pSSLSock->roleSpecificInfo.client.pskIdentityLength);

    pYc = (ubyte *)(pPskIdentity + 2 + pSSLSock->roleSpecificInfo.client.pskIdentityLength);

    /* store Yc */
    setShortValue(pYc, (ubyte2)lenYc);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    while (lenYc > template.fLen)
    {
        *(pYc + 2) = 0x00;
        pYc++;
        lenYc--;
    }
#endif
    status = DIGI_MEMCPY(pYc + 2, pPub, lenYc);
    if (OK != status)
    {
        goto exit;
    }
#else
    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_f, 2 + pYc, lenYc)))
        goto exit;
#endif

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* fill in psk into shared secret */
    pskLength = pSSLSock->roleSpecificInfo.client.pskLength;

    /* allocate buffer for shared secret plus psk */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    lenK = pSSLSock->sharedSecretLength;
#else
    lenK  = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_k)) / 8;
#endif

    if (NULL == (pSecret = (ubyte*) MALLOC(2 + lenK + 2 + pskLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* length of k */
    setShortValue(pSecret, (ubyte2)(lenK));
    /* convert shared secret (k) into something digestible */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = DIGI_MEMCPY(pSecret + 2, pSSLSock->pSharedSecret, lenK);
    if (OK != status)
    {
        goto exit;
    }
#else
    if (OK > (status = VLONG_fixedByteStringFromVlong(pSSLSock->pDHcontext->dh_k,
                                                      pSecret + 2, lenK)))
    {
        goto exit;
    }
#endif

    /* fill in psk into shared secret */
    setShortValue(pSecret + 2 + lenK, (ubyte2)(pskLength));
    DIGI_MEMCPY(pSecret + 2 + lenK + 2, pSSLSock->roleSpecificInfo.client.psk, pskLength);

    /* we can generate the key material now */
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, pSecret, 2 + lenK + 2 + pskLength);

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pSSLSock->pDHcontext, &template, NULL);
#endif
    if (NULL != pPub)
    {
        DIGI_FREE((void **) &pPub);
    }
#endif

    if (NULL != pSecret)
        FREE(pSecret);

    return status;

} /* fillClientDiffieHellmanPskKeyExchange */
#endif /* (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */



/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))
static MSTATUS
fillClientEcdhePskKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    ubyte*              pSHSH;
    MSTATUS             status;
    ubyte*              sharedSecret = 0;
    ubyte*              preSecret = 0;
    ubyte*              pTemp;
    sbyte4              sharedSecretLen;
    PrimeFieldPtr       pPF;
    ubyte4              sizeofHandshakeHeader;
    ECCKey*             pECCKey;
    sbyte4              pskLength;
    sbyte4              pskIdentityLength;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    ECCKey *pNewKey = NULL;
    ubyte4              curveId = 0;
#else
    PFEPtr              k = 0, Qx = 0, Qy = 0;
#endif

    if ( akt_ecc != pSSLSock->ecdheKey.type)
    {
        return ERR_SSL_INVALID_KEY_TYPE;
    }

    pECCKey = pSSLSock->ecdheKey.key.pECC;

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;

    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    /* fill in the identity */
    pskIdentityLength = pSSLSock->roleSpecificInfo.client.pskIdentityLength;

    pTemp = (ubyte *)(pSHSH + sizeofHandshakeHeader);
    setShortValue(pTemp, (ubyte2)(pSSLSock->roleSpecificInfo.client.pskIdentityLength));
    DIGI_MEMCPY(pTemp+2, pSSLSock->roleSpecificInfo.client.pskIdentity, pskIdentityLength);

    /* generate a new ECDH key pair on the curve and send the public key
     The presecret is the shared secret generated by the ECDH operation */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    /* Note a global keyType is passed. This can be set by the user.
     * This will be moved to the SSL_settings
     */
    if (OK > (status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(MOC_ECC(pSSLSock->hwAccelCookie) curveId, &pNewKey,
                                                                pSSLSock->rngFun, pSSLSock->rngFunArg)))
    {
        goto exit;
    }
#else
    pPF = EC_getUnderlyingField(pECCKey->pCurve);

    if (OK > (status = PRIMEFIELD_newElement( pPF, &k)) ||
        OK > (status = PRIMEFIELD_newElement( pPF, &Qx)) ||
        OK > (status = PRIMEFIELD_newElement( pPF, &Qy)))
    {
        goto exit;
    }

    if (OK > (status = EC_generateKeyPair( pECCKey->pCurve, pSSLSock->rngFun,
                                          pSSLSock->rngFunArg, k, Qx, Qy)))
    {
        goto exit;
    }
#endif

    pTemp += 2 + pskIdentityLength;
    /* add the redundant byte for length (ECPoint ) */
    *pTemp = (ubyte) (length - (1 + 2 + pskIdentityLength + sizeofHandshakeHeader));

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status =  CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(pSSLSock->hwAccelCookie) pNewKey,
                                                                   pTemp + 1, *pTemp)))
    {
        goto exit;
    }
#else
    if (OK > (status = EC_writePointToBuffer( pECCKey->pCurve, Qx, Qy, pTemp + 1,
                                             *pTemp)))
    {
        goto exit;
    }
#endif

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* we can generate the key material now */
    /* derive the presecret */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux(MOC_ECC(pSSLSock->hwAccelCookie)
                                                                          pNewKey,
                                                                          pECCKey,
                                                                          &sharedSecret,
                                                                          &sharedSecretLen,
                                                                          1/* X co-ordinate only */,
                                                                          NULL)))
    {
        goto exit;
    }
#else
    if ( OK > ( status = ECDH_generateSharedSecretAux( pECCKey->pCurve,
                                                      pECCKey->Qx,
                                                      pECCKey->Qy,
                                                      k,
                                                      &sharedSecret,
                                                      &sharedSecretLen,
                                                      1))) /* X coordinate only */
    {
        goto exit;
    }
#endif

    pskLength = pSSLSock->roleSpecificInfo.client.pskLength;

    /* allocate a buffer big enough for the presecret */
    if (NULL == (preSecret = (ubyte*) MALLOC( 2 + sharedSecretLen + 2 + pskLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setShortValue(preSecret, (ubyte2) sharedSecretLen);
    DIGI_MEMCPY(preSecret + 2, sharedSecret, sharedSecretLen);
    setShortValue(preSecret + 2 + sharedSecretLen, (ubyte2) pskLength);
    DIGI_MEMCPY(preSecret + 2 + sharedSecretLen + 2,
               pSSLSock->roleSpecificInfo.client.psk, pskLength);

    status = SSL_SOCK_generateKeyMaterial(pSSLSock, preSecret,
                                          2 + sharedSecretLen + 2 + pskLength);

exit:

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
#else
    PRIMEFIELD_deleteElement( pPF, &k);
    PRIMEFIELD_deleteElement( pPF, &Qx);
    PRIMEFIELD_deleteElement( pPF, &Qy);
#endif

    if ( sharedSecret)
    {
        FREE( sharedSecret);
    }

    if ( preSecret)
    {
        FREE( preSecret);
    }

    return status;
} /* fillClientEcdhePskKeyExchange */
#endif /* (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)) */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
static MSTATUS
fillClientSrpKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue)
{
    MSTATUS status;
    ubyte* presecret = 0;
    sbyte4 presecretLen;
    ubyte* pSHSH;
    ubyte* pA;
    ubyte4 sizeofHandshakeHeader;

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue( ((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue( ((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_KEY_EXCHANGE;
    }

    pA = (ubyte *)(pSHSH + sizeofHandshakeHeader);

    if (OK > ( status = SSL_SOCK_SRPClientPremasterSecret(pSSLSock,
                                                          &presecret,
                                                          &presecretLen,
                                                          pA,
                                                          ppVlongQueue)))
    {
        goto exit;
    }

    /* add to the hashes */
    addToHandshakeHash(pSSLSock, pBuffer, length);

    /* we can generate the key material now */
    status = SSL_SOCK_generateKeyMaterial(pSSLSock, presecret, presecretLen);

exit:
    if (NULL != presecret)
    {
        DIGI_MEMSET( presecret, 0, presecretLen);
        FREE(presecret);
    }
    return status;

} /* fillClientSrpExchange */
#endif /* defined(__ENABLE_DIGICERT_SSL_SRP__) */

/*------------------------------------------------------------------*/

static MSTATUS
SSL_CLIENT_sendClientResponseBlock(SSLSocket* pSSLSock)
{
    intBoolean  isRehandshake = (pSSLSock->pActiveOwnCipherSuite) ? TRUE : FALSE;
    ubyte*      pSRH;
    sbyte4      bufIndex     = 0;
    sbyte4      numBufs      = 0;
    ubyte4      totalLen;
    ubyte4      fragmentLen  = 0;
    ubyte4      numBytesSent = 0;
    vlong*      pVlongQueue  = NULL;
    ubyte4      pskIdentityLength = 0;
    ubyte4      sizeofRecordHeader = 0;
    ubyte4      sizeofHandshakeRecord;
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    ubyte4 dsaSignLen = 0;
#endif
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && \
    defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
    ubyte*      pOcspResponse   = NULL;
    ubyte4      responseLen     = 0;
#endif
    MSTATUS     status       = OK;

    if (NULL == pSSLSock->pHandshakeCipherSuite)
        return ERR_SSL_PROTOCOL;

    pSSLSock->buffers[0].pHeader = NULL;
    pSSLSock->buffers[0].length = pSSLSock->buffers[1].length = pSSLSock->buffers[2].length = pSSLSock->buffers[3].length = pSSLSock->buffers[4].length = 0;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
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
    }
    else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
        sizeofHandshakeRecord = sizeof(SSLHandshakeRecord);
    }

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    /* certificate record length */
    if (pSSLSock->isMutualAuthNegotiated)
    {
        ubyte4 i;
        ubyte2 certificateLength = 0;


#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
            (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            certificateLength += 1 + pSSLSock->certificateRequestContextLength;
            certificateLength += SSL_MEDIUMSIZE; /* Length of certificate list */

            /* now add length of certificates themselves */
            for (i = 0; i < pSSLSock->roleSpecificInfo.client.numMutualAuthCert; ++i)
            {
                certificateLength += (SSL_MEDIUMSIZE + pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts[i].length);
                certificateLength += 2; /* Extension length */
            }

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
            if (pSSLSock->recvStatusReqExt)
            {
                /* Only attempt to get an OCSP response if a client certificate was
                 * selected, otherwise send an empty OCSP response.
                 */
                if (NULL != pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts)
                {
                    if (OK > (status = SSL_OCSP_getOcspResponse(
                            pSSLSock,
                            pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts,
                            pSSLSock->roleSpecificInfo.client.numMutualAuthCert,
                            gpOcspStore, &pOcspResponse, &responseLen)))
                    {
                        /* Send empty response if an error occurred */
                        status = OK;
                    }
                }

                if ( (0 < responseLen) && (NULL != pOcspResponse) )
                {
                    pSSLSock->pOcspResponse = pOcspResponse;
                    pSSLSock->ocspResponseLen = responseLen;
                    certificateLength += 2/* extension type */ + 2 /* extension length */ +
                                        1/* response type */ + SSL_MEDIUMSIZE/* response length */ + responseLen;
                }
            }
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ && __ENABLE_DIGICERT_OCSP_STORE__ */
        }
        else
#endif
        {
            certificateLength = SSL_MEDIUMSIZE; /* total length of certificates */
            for (i = 0; i < pSSLSock->roleSpecificInfo.client.numMutualAuthCert; ++i)
            {
                certificateLength += (ubyte2)(SSL_MEDIUMSIZE + pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts[i].length);
            }
        }

        pSSLSock->buffers[bufIndex].length = (ubyte2)sizeofHandshakeRecord + certificateLength;

        bufIndex++;
        numBufs++;
    }
    else
#endif
    if (pSSLSock->generateEmptyCert)
    {
        /* RFC-4346 (pg 46):
         * If no suitable certificate is available, the client SHOULD send a
         * certificate message containing no certificates.  That is, the
         * certificate_list structure has a length of zero.
         */
        pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts = NULL;
        pSSLSock->roleSpecificInfo.client.numMutualAuthCert = 0;

        pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofHandshakeRecord + SSL_MEDIUMSIZE);
#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
            (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            /* 1 byte for the certificate request context length */
            pSSLSock->buffers[bufIndex].length++;
        }
#endif

        bufIndex++;
        numBufs++;
    }
#if defined(__ENABLE_DIGICERT_TLS13__)
    if ( (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) ||
         (!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) )
#endif
    {
#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
        if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_PSK_BIT)
            pskIdentityLength = 2 + pSSLSock->roleSpecificInfo.client.pskIdentityLength;
#endif

        /* client key exchange length */
        if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_RSA_BIT)
        {
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
            sbyte4 cipherTextLen;
            RSAKey* pRSAKey;

            if (akt_rsa != pSSLSock->handshakeKey.type)
            {
                status = ERR_SSL_INVALID_KEY_TYPE;
                goto exit;
            }

            pRSAKey = pSSLSock->handshakeKey.key.pRSA;
            /* allocate buffer big enough for the handshake record */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &cipherTextLen, pSSLSock->handshakeKey.type)))
            {
                goto exit;
            }
#else
            if (OK > (status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, &cipherTextLen)))
                goto exit;
#endif

            /* allocate the handshake record */
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            pSSLSock->buffers[bufIndex].length = (ubyte2)((sizeofHandshakeRecord + cipherTextLen) +
                                                          ((SSL3_MINORVERSION < pSSLSock->sslMinorVersion) ? 2 : 0) +
                                                          pskIdentityLength);
#else
            pSSLSock->buffers[bufIndex].length = (ubyte2)((sizeofHandshakeRecord + cipherTextLen) +
                                                          2 + pskIdentityLength);
#endif

#else
            status = ERR_SSL_CONFIG;
            goto exit;
#endif
        }
#if (defined(__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
        else if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDH_BIT)
        {
            sbyte4 publicKeyLen;
            ECCKey* pECCKey;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            ubyte4 keyType;
#endif
            if (akt_ecc != pSSLSock->handshakeKey.type)
            {
                status = ERR_SSL_INVALID_KEY_TYPE;
                goto exit;
            }

            pECCKey = pSSLSock->handshakeKey.key.pECC;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            keyType = pSSLSock->handshakeKey.type;
            if (OK > ( status = CRYPTO_INTERFACE_EC_getPointByteStringLenEx( pECCKey, (ubyte4 *)&publicKeyLen, keyType)))
                goto exit;
#else
            if (OK > ( status = EC_getPointByteStringLen( pECCKey->pCurve, &publicKeyLen)))
                goto exit;
#endif
            /* add one byte length + length of public key + sizeof HandshakeRecord */
            pSSLSock->buffers[bufIndex].length = (ubyte2) (sizeofHandshakeRecord + 1 + publicKeyLen);
        }
#endif

#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_BIT__) )
        else if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDHE_BIT)
        {
            sbyte4 publicKeyLen;
            ECCKey* pECCKey;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            ubyte4 keyType;
#endif

            if (akt_ecc != pSSLSock->ecdheKey.type)
            {
                status = ERR_SSL_INVALID_KEY_TYPE;
                goto exit;
            }

            pECCKey = pSSLSock->ecdheKey.key.pECC;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            keyType = pSSLSock->handshakeKey.type;
            if (OK > ( status = CRYPTO_INTERFACE_EC_getPointByteStringLenEx( pECCKey, (ubyte4 *)&publicKeyLen, keyType)))
                goto exit;
#else
            if (OK > ( status = EC_getPointByteStringLen( pECCKey->pCurve, &publicKeyLen)))
                goto exit;
#endif

            /* add one byte length + length of public key + sizeof SSLHandshakeRecord */
            pSSLSock->buffers[bufIndex].length = (ubyte2) (sizeofHandshakeRecord + 1 + publicKeyLen + pskIdentityLength);
        }
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
        else if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_DHE_BIT)
        {
            ubyte4              lenYc;
#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
            MDhKeyTemplate template = { 0 };
#else
            ubyte              *pPub = NULL;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_DH_MODES__
            status = CRYPTO_INTERFACE_DH_keyAgreementScheme(MOC_DH(pSSLSock->hwAccelCookie) DH_EPHEMERAL, 
                                                            g_pRandomContext, 
                                                            NULL, 
                                                            pSSLSock->pDHcontext,
                                                            NULL,
                                                            0, 
                                                            pSSLSock->pRemotePublicKey,
                                                            pSSLSock->remotePublicKeyLength,
                                                            &(pSSLSock->pSharedSecret),
                                                            &(pSSLSock->sharedSecretLength));
#else
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(pSSLSock->hwAccelCookie)
                                                                 pSSLSock->pDHcontext,
                                                                 g_pRandomContext,
                                                                 pSSLSock->pRemotePublicKey,
                                                                 pSSLSock->remotePublicKeyLength,
                                                                 &(pSSLSock->pSharedSecret),
                                                                 &(pSSLSock->sharedSecretLength),
                                                                 NULL);
#endif
            if (OK != status)
                goto exit;

            /* server public key is no longer needed */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            DIGI_FREE((void**)&(pSSLSock->pRemotePublicKey));
#endif
            pSSLSock->remotePublicKeyLength = 0;

#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
            status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(
                MOC_DH(pSSLSock->hwAccelCookie) &template, pSSLSock->pDHcontext,
                MOC_GET_PUBLIC_KEY_DATA, NULL);
            if (OK != status)
                goto exit;

            lenYc = template.pLen;
            CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pSSLSock->pDHcontext, &template, NULL);
#else
            status = CRYPTO_INTERFACE_DH_getPublicKeyExt( MOC_DH(pSSLSock->hwAccelCookie)
                pSSLSock->pDHcontext, &pPub, &lenYc, NULL);
            DIGI_FREE((void **) &pPub);
#endif
            if (OK != status)
            {
                goto exit;
            }
#else
            if (OK > (status = DH_computeKeyExchange(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, &pVlongQueue)))
                goto exit;

#if defined(__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__)
            lenYc = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_p)) / 8;
#else
            lenYc = (7 + VLONG_bitLength(pSSLSock->pDHcontext->dh_f)) / 8;
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofHandshakeRecord + 2 + lenYc + pskIdentityLength);
        }
#endif
#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
        else if (SSL_PSK == pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
        {
            pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofHandshakeRecord + pskIdentityLength);
        }
#endif
#ifdef __ENABLE_DIGICERT_SSL_SRP__
        else if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_SRP_BIT)
        {
            /* size of A + 2 length bytes: A is modulo N so size is same as N */
            pSSLSock->buffers[bufIndex].length = (ubyte2) (sizeofHandshakeRecord + 2 + pSSLSock->srpNumBits / 8);
        }
#endif
        else
        {
            status = ERR_SSL_CONFIG;
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
        if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_PSK_BIT)
            pskIdentityLength = 2 + pSSLSock->roleSpecificInfo.client.pskIdentityLength;
#endif

        bufIndex++;
        numBufs++;
    }

    /* certificate verify length */
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if (pSSLSock->isMutualAuthNegotiated)
    {
        ubyte4 lenSignature;

        switch ( pSSLSock->mutualAuthKey.type & 0xFF)
        {
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
        case akt_dsa:
            if (TRUE == SSL_sslSettings()->allowDSASigAlg)
            {
                DSAKey*  pDSAKey = pSSLSock->mutualAuthKey.key.pDSA;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                struct MDsaKeyTemplate dsaParameters = {0};
                if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(pDSAKey, &dsaParameters, MOC_GET_PRIVATE_KEY_DATA)))
                {
                    goto exit;
                }
                dsaSignLen = dsaParameters.qLen;
#else
                dsaSignLen    = ((7 + VLONG_bitLength(DSA_Q(pSSLSock->mutualAuthKey.key.pDSA))) / 8);
#endif
                lenSignature  = 2 + 2*(2 + 1) + (2 * dsaSignLen); /* DER encoding Sec. 4.7 RFC5246*/
                lenSignature += 2; /* 2-byte length field preceding signature bytes */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                DSA_freeKeyTemplate(pDSAKey, &dsaParameters);
#endif
                break;
            }
            else
            {
                status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                goto exit;
            }
#endif
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            case akt_rsa:
                if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pSSLSock->mutualAuthKey.key.pRSA,
                                                                           (sbyte4 *)&lenSignature,
                                                                           pSSLSock->mutualAuthKey.type)))
                {
                    goto exit;
                }
            break;
#else
        case akt_rsa:
            lenSignature = ((7 + VLONG_bitLength(RSA_N(pSSLSock->mutualAuthKey.key.pRSA))) / 8);
            break;
#endif
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        case akt_ecc:
        case akt_ecc_ed:
            /* enough space for a SEQUENCE of 2 integers */
            if (OK > ( status = SSL_SOCK_getECCSignatureLength(pSSLSock->mutualAuthKey.key.pECC,
                                                               (sbyte4*) &lenSignature,
                                                               pSSLSock->mutualAuthKey.type)))
            {
                goto exit;
            }
            break;
#else
        case akt_ecc:
            /* enough space for a SEQUENCE of 2 integers */
            if (OK > ( status = SSL_SOCK_getECCSignatureLength( pSSLSock->mutualAuthKey.key.pECC,
                                                               (sbyte4*) &lenSignature)))
            {
                goto exit;
            }
            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_hybrid:

            if (OK > (status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(pSSLSock->hwAccelCookie) 
                                                                    &pSSLSock->mutualAuthKey, TRUE, &lenSignature)))
            {
                goto exit;
            }
            break;

        case akt_qs:

            if (OK > (status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pSSLSock->mutualAuthKey.pQsCtx, &lenSignature)))
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

        pSSLSock->buffers[bufIndex].length = (ubyte2)(sizeofHandshakeRecord + 2 + lenSignature);

        if ( (pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
             (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION)  )
        {
            pSSLSock->buffers[bufIndex].length += 2;
        }
        bufIndex++;
        numBufs++;
    }
#endif

    /* allocate enough space for all records */
    totalLen =  pSSLSock->buffers[0].length + pSSLSock->buffers[1].length +
                    pSSLSock->buffers[2].length + pSSLSock->buffers[3].length +
                    pSSLSock->buffers[4].length;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        fragmentLen = calculateExtraFragmentHeader(pSSLSock, numBufs);
    }
#endif

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie,
                                    totalLen + fragmentLen + TLS_EAP_PAD, TRUE,
                                    (void **)&(pSSLSock->buffers[0].pHeader))))  /* EAP TEAM, why the pad? */
    {
        goto exit;
    }

    /* initialize other pointers */
    pSSLSock->buffers[1].pHeader = pSSLSock->buffers[0].pHeader + pSSLSock->buffers[0].length;
    pSSLSock->buffers[2].pHeader = pSSLSock->buffers[1].pHeader + pSSLSock->buffers[1].length;
    pSSLSock->buffers[3].pHeader = pSSLSock->buffers[2].pHeader + pSSLSock->buffers[2].length;
    pSSLSock->buffers[4].pHeader = pSSLSock->buffers[3].pHeader + pSSLSock->buffers[3].length;

    pSSLSock->buffers[0].data = pSSLSock->buffers[0].pHeader + sizeofRecordHeader;
    pSSLSock->buffers[1].data = pSSLSock->buffers[1].pHeader + sizeofRecordHeader;
    pSSLSock->buffers[2].data = pSSLSock->buffers[2].pHeader + sizeofRecordHeader;
    pSSLSock->buffers[3].data = pSSLSock->buffers[3].pHeader + sizeofRecordHeader;
    pSSLSock->buffers[4].data = pSSLSock->buffers[4].pHeader + sizeofRecordHeader;

    /* update record headers */
    for (bufIndex = 0; bufIndex < numBufs; bufIndex++)
    {
        pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
        if (pSSLSock->isDTLS)
        {
#ifdef __ENABLE_DIGICERT_TLS13__
            /* For 1.3 the record header is not placed here, these 5 bytes are unused */
            if (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
            {
                DTLS_SET_RECORD_HEADER_EXT(pSRH, pSSLSock, SSL_HANDSHAKE,
                                  pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
            }
        } 
        else
#endif
        {
            SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->sslMinorVersion,
                                  pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);
        }
    }

    bufIndex = 0;

    /* certificate */
    if ((pSSLSock->isMutualAuthNegotiated) || (pSSLSock->generateEmptyCert))
    {
        if (OK > (status = fillClientCertificate(pSSLSock, pSSLSock->buffers[bufIndex].data, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofRecordHeader))))
            goto exit;

        bufIndex++;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) || 
        (!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
#endif
    {
        /* client key exchange */
        if (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->FillClientKEX)
        {
            if (OK > (status = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->FillClientKEX(pSSLSock, pSSLSock->buffers[bufIndex].data, (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofRecordHeader), &pVlongQueue))) /* will also call generateKeyMaterial */
                goto exit;
        }
        else
        {
            status = ERR_SSL_CONFIG;
            goto exit;
        }

        bufIndex++;
    }

    /* certificate verify */
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if ((pSSLSock->isMutualAuthNegotiated) && (0 != pSSLSock->roleSpecificInfo.client.numMutualAuthCert))
    {
        /* unfortunately the ECC signature length cannot be computed in advance precisely since
            it's a SEQUENCE of 2 INTEGERs. And INTEGER will have a zero prefix depending on their value
            it's illegal to add a 0 octet if the first bit is 0.
            So we need to adjust the length...
        */
        ubyte2 length, initLength;

        length = initLength = (ubyte2)(pSSLSock->buffers[bufIndex].length - sizeofRecordHeader);

        if (OK > (status = SSLSOCK_fillCertificateVerify(pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo,
                                                         pSSLSock, pSSLSock->mutualAuthKey,
                                                         pSSLSock->buffers[bufIndex].data,
                                                         &length, &pVlongQueue)))
        {
            goto exit;
        }

        if (length != initLength)
        {
            /* adjust pointers, length and headers ... */
            totalLen -= (initLength - length);
            pSSLSock->buffers[bufIndex].length = (ubyte2) (length + sizeofRecordHeader);

            pSRH = pSSLSock->buffers[bufIndex].pHeader;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
            if (pSSLSock->isDTLS)
            {
#ifdef __ENABLE_DIGICERT_TLS13__
                /* For 1.3 the record header is not placed here, these 5 bytes are unused */
                if (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
                {
                    DTLS_SET_RECORD_HEADER_EXT(pSRH,pSSLSock,SSL_HANDSHAKE,length);
                }
            }
            else
#endif
            {
                SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->sslMinorVersion, length);
            }
            /* it's fortunate that the certificate verify is the last message
            there's nothing else to update */
        }
        addToHandshakeHash(pSSLSock, pSSLSock->buffers[bufIndex].data, (pSSLSock->buffers[bufIndex].length - sizeofRecordHeader));
        bufIndex++;
    }
#endif

    /* !reHandshake && (DTLS1.2 || TLS 1.2 or lower) */
    if ( (TRUE != isRehandshake) && 
         ((pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) || 
          (!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion)) )
    {
        /* send the handshakes records to SSL record layer *************/
        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            numBytesSent  = 0;
            status = (MSTATUS) totalLen;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
            if (NULL != pSSLSock->pTransportHandler)
            {
                if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
                {
                    if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId,
                                                                                         (sbyte *)(pSSLSock->buffers[0].pHeader),
                                                                                         totalLen, &numBytesSent)))
                    {
                        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                        goto exit;
                    }
                }
                else
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
            }
            else
#endif
            {
#ifndef __DIGICERT_IPSTACK__
                if (OK > (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)(pSSLSock->buffers[0].pHeader), totalLen, &numBytesSent)))
#else
                if (OK > (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)(pSSLSock->buffers[0].pHeader), totalLen, &numBytesSent)))
#endif
                    goto exit;
            }
        }

        if (numBytesSent != totalLen)
        {
            pSSLSock->pOutputBufferBase  = pSSLSock->buffers[0].pHeader;
            pSSLSock->pOutputBuffer      = numBytesSent + pSSLSock->buffers[0].pHeader;
            pSSLSock->outputBufferSize   = totalLen + fragmentLen;
            pSSLSock->numBytesToSend     = totalLen + fragmentLen - numBytesSent;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
            if (pSSLSock->isDTLS)
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
            pSSLSock->buffers[0].pHeader = NULL;
        }
    }
    else
    {
        pSSLSock->bufIndex = 0;
        pSSLSock->numBuffers = numBufs;

        status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock);
    }

exit:

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && \
    defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
    if (NULL != pOcspResponse)
    {
        DIGI_FREE((void **) &pOcspResponse);
    }
#endif

    if ((TRUE != isRehandshake) || (OK > status))
    {
        /* free the buffers */
        if (pSSLSock->buffers[0].pHeader)
        {
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE,
                        (void **)&(pSSLSock->buffers[0].pHeader));
        }
    }

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSL_CLIENT_sendClientResponseBlock */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS13__)

static MSTATUS copyKeyShareExtension(
    SSLSocket *pSSLSock, enum tlsExtNamedCurves groupName)
{
    MSTATUS status = ERR_SSL_UNSUPPORTED_ALGORITHM;
    sharedKey *pEntry = pSSLSock->roleSpecificInfo.client.ppSharedKeys + pSSLSock->roleSpecificInfo.client.sharedKeyIndex;
    MDhKeyTemplate template = { 0 };
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    ubyte4 privKeyLen;
#endif
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    intBoolean isValid = FALSE;
#endif

    if (FFDH_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pEntry->namedGroup))
    {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt( MOC_DH(pSSLSock->hwAccelCookie)
            &template, pEntry->pKey, MOC_GET_PUBLIC_KEY_DATA, NULL);
#else
        status = DH_getKeyParametersAllocExt( MOC_DH(pSSLSock->hwAccelCookie)
            &template, pEntry->pKey, MOC_GET_PUBLIC_KEY_DATA, NULL);
#endif
        if (OK != status)
        {
            goto exit;
        }

        if (NULL != pSSLSock->pDHcontext)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DH_freeDhContextExt(
                &(pSSLSock->pDHcontext), NULL, NULL);
#else
            status = DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
#endif
            if (OK != status)
            {
                goto exit;
            }
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_allocateExt(&(pSSLSock->pDHcontext), NULL);
#else
        status = DH_allocateExt(&(pSSLSock->pDHcontext), NULL);
#endif
        if (OK != status)
        {
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_setKeyParametersExt( MOC_DH(pSSLSock->hwAccelCookie)
            pSSLSock->pDHcontext, &template, NULL);
#else
        status = DH_setKeyParametersExt(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, &template, NULL);
#endif
        if (OK != status)
        {
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        /* privKeyLen is not used here, generation isn't done in this function */
        status = CRYPTO_INTERFACE_DH_verifySafePG(pSSLSock->pDHcontext, &isValid, &privKeyLen, NULL);
#else
        status = DH_verifySafePG(pSSLSock->pDHcontext, &isValid, &privKeyLen, NULL);
#endif
        if (OK != status)
        {
            goto exit;
        }

        if (FALSE == isValid)
        {
#if defined(__ENABLE_DIGICERT_STRICT_DH_GROUP__)
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
#endif
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif /* __DISABLE_DIGICERT_DIFFIE_HELLMAN__ */
    }
#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined( __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))
    else
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_copyAsymmetricKey(
            &(pSSLSock->ecdheKey), (const AsymmetricKey *) pEntry->pKey);
#else
        status = CRYPTO_copyAsymmetricKey(
            &(pSSLSock->ecdheKey), (const AsymmetricKey *) pEntry->pKey);
#endif
    }
#endif

exit:

    if (FFDH_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pEntry->namedGroup))
    {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pEntry->pKey, &template, NULL);
#else
        DH_freeKeyTemplateExt(pEntry->pKey, &template, NULL);
#endif
#endif
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13__ */

/*------------------------------------------------------------------*/

static MSTATUS
processServerHelloExtensions(SSLSocket* pSSLSock, ubyte2 extensionType,
                                ubyte2 extensionSize, ubyte* pExtension)
{
    MSTATUS status            = OK;

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
            ubyte4  verifyDataSize = (SSL3_MINORVERSION == pSSLSock->sslMinorVersion) ?
                                    SSL_VERIFY_DATA : TLS_VERIFYDATASIZE;
#else
            ubyte4  verifyDataSize = TLS_VERIFYDATASIZE;
#endif

            pSSLSock->isRehandshakeExtPresent = TRUE;

            if (0 < pSSLSock->handshakeCount)
            {
                /* TLS 1.0, 1.1 and 1.2 */
                expectedRenegotiationLength = (2 * verifyDataSize);
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
                status = ERR_SSL_CLIENT_RENEGOTIATE_LENGTH;
                goto exit;
            }

            if (0 < expectedRenegotiationLength)
            {
                if (OK > (status = DIGI_CTIME_MATCH(1 + pExtension, pSSLSock->client_verify_data, verifyDataSize, &result)))
                    goto exit;

                if (0 != result)
                {
                    status = ERR_SSL_CLIENT_RENEGOTIATE_CLIENT_VERIFY;
                    goto exit;
                }

                if (OK > (status = DIGI_CTIME_MATCH(verifyDataSize + 1 + pExtension, pSSLSock->server_verify_data, verifyDataSize, &result)))
                    goto exit;

                if (0 != result)
                {
                    status = ERR_SSL_CLIENT_RENEGOTIATE_SERVER_VERIFY;
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
            /*
             * According to RFC3546/RFC 6066:
             * The "extension_data" field of this extension SHALL be empty.
             */
            /* TLS 1.3: If HRR and server name was not sent then HRR should not have
             * tlsExt_server_name.
             */
#ifdef __ENABLE_DIGICERT_TLS13__
            if((pSSLSock->helloRetryRequest) && (pSSLSock->serverNameIndication == NULL))
            {
                status = ERR_SSL_FATAL_ALERT;
                goto exit;
            }
            else
#endif
            {
                if ( extensionSize != 0)
                {
                    sbyte4 serverNameListLength;
                    if ( extensionSize < 2)
                    {
                        /* buffer overrun attack? */
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    /* if there is a name extension, it should be empty */
                    serverNameListLength = getShortValue(pExtension);
                    if ( serverNameListLength )
                    {
                        status = ERR_SSL_EXTENSION_SERVER_NAME_LENGTH;
                        goto exit;
                    }
                }
            }
        }
        break;

        case tlsExt_applicationLayerProtocolNegotiation:
        {
            sbyte4 alpnLength;
            status = ERR_SSL_EXTENSION_LENGTH;
            /* make sure the extension is at least 4 bytes
             : 2 list length + 1 string length + 1 string */
            if ( extensionSize < 4)
            {
                /* buffer overrun attack? */
                goto exit;
            }

            alpnLength = getShortValue(pExtension);
            if ( alpnLength + 2 != extensionSize)
            {
                goto exit;
            }
            /* list must be one single "pascal" string */
            pExtension += 2;
            if (alpnLength - 1 !=  *pExtension)
            {
                goto exit;
            }
            status = SSLSOCK_findPascalStringInList(pExtension,
                                                    pSSLSock->alpnProtocols,
                                                    pSSLSock->alpnProtocolsLen,
                                                    &pSSLSock->selectedALPN);
            if (OK != status)
            {
                status = ERR_SSL_EXTENSION_NO_ALPN_MATCH;
                goto exit;
            }
        }
        break;

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))
        case tlsExt_status_request:
        {
            if (!pSSLSock->certStatusReqExt)
            {
                /* We are not expecting cert status req extension as we have
                               not send it in client hello */
                status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_UNSOLICITED;
                goto exit;
            }

            /*
             * According to RFC6066:
             * The "extension_data" field of this extension SHALL be empty.
             */
            if (extensionSize != 0)
            {
                status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_LENGTH;
                goto exit;
            }
            pSSLSock->didRecvCertStatusExt = TRUE;
        }
        break;
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
        case tlsExt_extendedMasterSecret:
        {
            if (FALSE == pSSLSock->roleSpecificInfo.client.sentExtendedMasterSecret)
            {
                status = ERR_SSL_EXTENDED_MASTERSECRET_MISSING;
                goto exit;
            }

            if (0 != extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            if ((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
                 (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion)))
            {
                pSSLSock->receivedExtendedMasterSecret = TRUE;
            }
        }
        break;
#endif

        case tlsExt_ticket:
        {
            /* the ticket should always be empty in ServerHello */
            if (extensionSize != 0)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            /* this extension was sent by the server
            so it indicates that a NewSessionTicket Handshake msg
            will be sent -> do we need to take note of that?*/
        }
        break;

#if defined(__ENABLE_DIGICERT_DTLS_SRTP__)
        case dtlsExt_use_srtp:
        {
            sbyte4 srtpProfileLength;
            ubyte4 srtpMkiLength;
            ubyte2 serverProfileId;
            ubyte4 i;

            if ( extensionSize < 2)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            srtpProfileLength = getShortValue(pExtension);
            pExtension += 2;
            extensionSize -= 2;

            if ( srtpProfileLength + 1 > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            if (srtpProfileLength>>1 != 1) /* server should have chosen one profile */
            {
                status = ERR_SSL_EXTENSION_LENGTH; /* TODO: should change to failure to negotiate */
                goto exit;
            }

            /* record profile picked by server */
            /* cipher id */
            serverProfileId = ((ubyte2)(*pExtension++) << 8);
            serverProfileId |= *pExtension++;
            extensionSize -= 2;

            pSSLSock->pHandshakeSrtpProfile = NULL;

            for ( i = 0; i < (sbyte4)NUM_SRTP_PROFILES; ++i)
            {
                if ((gSrtpProfiles[i].supported) &&
                    (gSrtpProfiles[i].profileId == serverProfileId))
                {
#ifdef __ENABLE_DIGICERT_SRTP_PROFILES_SELECT__
                    if ((TRUE != pSSLSock->isSrtpProfileTableInit) ||
                        (TRUE == pSSLSock->isSrtpProfileEnabled[i]) )
#endif
                    {
                        pSSLSock->pHandshakeSrtpProfile = gSrtpProfiles + i;
                        break;
                    }
                }
            }

            if (NULL == pSSLSock->pHandshakeSrtpProfile)
            {
                return ERR_DTLS_SRTP_NO_PROFILE_MATCH;
            }

            /* srtp_mki */
            if (extensionSize < 1)
            {
                /* buffer overrun attack? */
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            srtpMkiLength = (ubyte4)(*pExtension);
            pExtension += 1;
            extensionSize -= 1;

            if ((srtpMkiLength > extensionSize))
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            status = ERR_DTLS_SRTP_EXTENSION_FAILURE;

            /* check to see it's the same as recorded one */
            if (NULL != pSSLSock->srtpMki)
            {
                sbyte4 resCmp;

                if (srtpMkiLength != (ubyte4)*(pSSLSock->srtpMki))
                    goto exit;

                DIGI_CTIME_MATCH(pSSLSock->srtpMki + 1, pExtension, srtpMkiLength, &resCmp);

                /* mki matched */
                if (0 == resCmp)
                {
                    status = OK;
                }
            }
            else
            {
                /* empty mki */
                if (0 == srtpMkiLength)
                    status = OK;
            }

            if (OK > status)
                goto exit;
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
#ifdef __ENABLE_DIGICERT_TLS13__
        case tlsExt_cookie:
        {

            if (2 > extensionSize )
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            pSSLSock->helloCookieLen = getShortValue(pExtension);
            pExtension += 2;
            extensionSize -= 2;
            if (pSSLSock->helloCookieLen > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }
            if (pSSLSock->helloCookieLen > 0)
            { 
                /* RFC 8446 Section 4.2.2
                 *
                 * Cookie length can range from 1 - 2^16-1. For NanoSSL if the
                 * the cookie length exceeds 255 bytes (which it typically
                 * won't as the RFC specifies the server sends the cookie as
                 * the hash of the ClientHello) then throw an error
                 */
                if (SSL_HELLO_COOKIE_MAX_SIZE >= pSSLSock->helloCookieLen)
                {
                    DIGI_MEMSET(pSSLSock->helloCookie, 0, pSSLSock->helloCookieLen);
                    DIGI_MEMCPY(pSSLSock->helloCookie, pExtension, pSSLSock->helloCookieLen);
                }
                else
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
            
            }
            else
            {
                if(0 == DIGI_STRNICMP((const sbyte *)pSSLSock->helloCookie,(const sbyte*)pExtension, pSSLSock->helloCookieLen))
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */,
                            SSL_ALERT_UNEXPECTED_MESSAGE,
                            SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    goto exit;
                } 
            }
        }
        break;

        case tlsExt_supported_versions:
        {
            ubyte serverSelectedMajorVersion = 0;
            ubyte serverSelectedMinorVersion = 0;
            ubyte sharedVersionFound = 0, i;

            if(pSSLSock->roleSpecificInfo.client.sharedSupportedVersion !=1)
            {
                status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                 SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                 goto exit;
            }

            if(extensionSize != 2)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                break;
            }

            serverSelectedMajorVersion     = *pExtension;
            pExtension++;

            serverSelectedMinorVersion     = *pExtension;
            pExtension++;

            for(i = 0; i < pSSLSock->roleSpecificInfo.client.numOfSharedVersions; i++)
            {
                if (pSSLSock->roleSpecificInfo.client.pSharedVersions[i] ==
                    ((serverSelectedMajorVersion << 8) | serverSelectedMinorVersion))
                {
                    /* Found version which was shared in Client Hello*/
                    pSSLSock->roleSpecificInfo.client.serverSelectedVersion =((serverSelectedMajorVersion << 8) | serverSelectedMinorVersion);
                    sharedVersionFound = 1;
                    break;
                }
            }
            if(!sharedVersionFound)
            {
                /* RFC 4.2.1.  Supported Versions:
                 * If the "supported_versions" extension in the ServerHello contains a
                 * version not offered by the client or contains a version prior to TLS
                 * 1.3, the client MUST abort the handshake with an "illegal_parameter"
                 * alert.
                 */
                 status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                 SSLSOCK_sendAlert(pSSLSock, TRUE/* TLS 1.3 only - encrypt alert */, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                 goto exit;
            }

            pSSLSock->sslMinorVersion = (ubyte)serverSelectedMinorVersion;
            pSSLSock->roleSpecificInfo.client.isSupportedVersionPresent = 1;
        }
        break;

        case tlsExt_key_share:
        {
            ubyte2 keyShareLength;
            ubyte4 i = 0;
            ubyte sharedGroupInKeyShareFound =0;
            enum tlsExtNamedCurves groupName;
            ubyte2 tempLen = 0;

            /* Check if extension was sent in Client Hello*/
            if (TLS13_CLIENT_GET_KEY_SHARE_TX(pSSLSock) != 1)
            {
                status = ERR_SSL_FATAL_ALERT;
                goto exit;
            }

            if ((tempLen + 2) > extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            groupName = getShortValue(pExtension);
            pExtension += 2;
            tempLen += 2;

            if(groupName == 0)
            {
                goto exit;
            }

            /* RFC: 4.2.8.  Key Share 
             * (1) the selected_group field corresponds to a group
             * which was provided in the "supported_groups" extension in the
             * original ClientHello.
             */

            /* Check if the supported group provided by the server was one that
             * was sent by us.
             */
            if (pSSLSock->supportedGroups & GROUP_BIT_MASK(groupName))
            {
                /* Find the key share for the provided group.
                 */
                for (i = 0; i < pSSLSock->roleSpecificInfo.client.sharedKeyCount; i++)
                {
                    if (pSSLSock->roleSpecificInfo.client.ppSharedKeys[i].namedGroup == groupName)
                    {
                        pSSLSock->roleSpecificInfo.client.sharedKeyIndex = i;
                        break;
                    }
                }

                /* If the provided group does not have a key share then go into
                 * the HRR flow, otherwise copy over the key share to use for
                 * later.
                 */
                if (i < pSSLSock->roleSpecificInfo.client.sharedKeyCount)
                {
                    status = copyKeyShareExtension(pSSLSock, groupName);
                    if (OK > status)
                    {
                        goto exit;
                    }

                    sharedGroupInKeyShareFound = 1;
                }

                if (pSSLSock->helloRetryRequest) /* KeyShare received in HelloRetry Request */
                {
                    /* If the server sent back a HRR for a key share which the
                     * client has already provided then throw an error.
                     */
                    if (sharedGroupInKeyShareFound)
                    {
                        /* RFC: 4.2.8.  Key Share
                         * (2) the selected_group field does not
                         * correspond to a group which was provided in the "key_share" extension
                         * in the original ClientHello.
                         */
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                            goto exit;
                    }
                    else
                    {
                        pSSLSock->roleSpecificInfo.client.selectedGroup = groupName;
                    }
                }
                else                           /* KeyShare received in Server Hello */
                {
                    /* Server sent back normal ServerHello (non-HRR flow), if
                     * no key share was found then throw an error.
                     */
                    if (!sharedGroupInKeyShareFound)
                    {
                        /* RFC: 4.2.8.  Key Share
                         * If using (EC)DHE key establishment, servers offer exactly one
                         * KeyShareEntry in the ServerHello.  This value MUST be in the same
                         * group as the KeyShareEntry value offered by the client that the
                         * server has selected for the negotiated key exchange.
                         */
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                         goto exit;
                    }
                    else
                    {
                        pSSLSock->roleSpecificInfo.client.selectedGroup = groupName;
                    }

                    if ((tempLen + 2) > extensionSize)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    keyShareLength = getShortValue(pExtension);

                    pExtension += 2;
                    tempLen += 2;

                    if ((tempLen + keyShareLength) > extensionSize)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    if(OK > (status = DIGI_MALLOC((void**)&pSSLSock->roleSpecificInfo.client.receivedPubKey,keyShareLength)))
                    {
                        goto exit;
                    }

                    if(NULL != pSSLSock->roleSpecificInfo.client.receivedPubKey)
                    {
                        DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.receivedPubKey, pExtension, keyShareLength);
                    }
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen = keyShareLength;
                    pExtension += keyShareLength;
                }
            }
        }
        pSSLSock->roleSpecificInfo.client.extensions = TLS13_CLIENT_SET_KEY_SHARE_RX(pSSLSock);
        break;
#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
        case tlsExt_early_data:
        {
            if (extensionSize > 0)
            {
                /* This extension is received inside NewSessionTicket */
                if (extensionSize != 4) 
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                pSSLSock->maxEarlyDataSize = (ubyte4)(((ubyte4)pExtension[0] << 24) | (ubyte4)(pExtension[1] << 16) | (ubyte4)(pExtension[2] << 8) | (ubyte4)pExtension[3]);
                pExtension += 4; /* maxEarlyDataSize is a unint32 */
            }
            else
            {
                /* RFC 4.3.1 In all handshakes, the server MUST send the EncryptedExtensions
                   message immediately after the ServerHello message. 
                   So by the time we receive this early_data extension we should have 
                   received pre-shared key extension.

                   RFC #8446, Page 58.
                   If the server supplies an "early_data" extension, the client MUST
                   verify that the server's selected_identity is 0.  If any other value
                   is returned, the client MUST abort the handshake with an
                   "illegal_parameter" alert.
                 */
                if ((1 != TLS13_CLIENT_GET_PSK_RX(pSSLSock)) ||
                    (0 != pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex))
                {
                    status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                    goto exit;
                }
                pSSLSock->earlyDataExtAccepted = 1;
                /* Clean the early data content */
                if (pSSLSock->pEarlyData != NULL)
                {
                    pSSLSock->pEarlyData = NULL;
                }
            }
        }
        break;
#endif

        case tlsExt_pre_shared_key:
        {
            ubyte2 selectedIdentityIndex;
            ubyte4 i = 0;
            tls13PSK *pTls13Psk = NULL;
            tls13PSKList *pTempPSKList = NULL;

            if (2 !=  extensionSize)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            selectedIdentityIndex = getShortValue(pExtension);

            /* RFC: 4.2.11: Clients MUST verify that the server's selected_identity is within the
             * range supplied by the client.
             */
            if(!((pSSLSock->roleSpecificInfo.client.selectedIdentityIndex) & (1 << selectedIdentityIndex)))
            {
                status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                goto exit;
            }

            /* The list of PSKs sent to server in ClientHello */
            pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

            /* The index count starts from 0 */
            for (i = 0; i < selectedIdentityIndex; i++)
            {
                if (NULL == pTempPSKList)
                    break;
                pTempPSKList = pTempPSKList->pNextPSK;
            }

            if (pTempPSKList != NULL)
                pTls13Psk = pTempPSKList->pPSK;

            if (pTls13Psk != NULL)
            {
                if (pSSLSock->pHandshakeCipherSuite->cipherSuiteId != pTls13Psk->selectedCipherSuiteId)
                {
                    /* Server selected a valid PSK,
                     * but negotiated a different cipher suite
                     */
                    status = ERR_SSL_NO_CIPHER_MATCH;
                    break;
                }
            }

            /* Hold the selected Identity index as it will required in future.*/
            pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex = selectedIdentityIndex;
            pSSLSock->roleSpecificInfo.client.extensions = TLS13_CLIENT_SET_PSK_RX(pSSLSock);
        }
        break;
#endif /* __ENABLE_DIGICERT_TLS13__*/

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
        case tlsExt_heartbeat:
        {
            status = OK;
            ubyte heartbeatMode = 0;
            if (extensionSize != 1)
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            heartbeatMode = *pExtension;
            pExtension++;

            if ((heartbeatMode != 1) && (heartbeatMode != 2))
            {
                status = ERR_SSL_EXTENSION_LENGTH;
                goto exit;
            }

            pSSLSock->rxHeartbeatExtension = heartbeatMode;
        }
        break;
#endif

    }
    if (NULL != SSL_sslSettings()->funcPtrExtensionApprovedCallback)
    {
        status = (MSTATUS)SSL_sslSettings()->funcPtrExtensionApprovedCallback(
                    SSL_findConnectionInstance(pSSLSock), extensionType, NULL, 0);
    }

exit:
    return status;
}


#if defined(__ENABLE_DIGICERT_TLS13__)
static MSTATUS
getServerSelectedVersion(SSLSocket *pSSLSock, ubyte* pRecord, ubyte2 recordLen,
                         ubyte* majorVersion, ubyte* minorVersion)
{
    MSTATUS status = OK;
    ubyte* pMsg = NULL;
    ubyte   sessionIdLen;
    ubyte4  sizeofHandshakeHeader;
    ubyte2 remainingLen = 0;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    pMsg = (ubyte*) (pRecord + sizeofHandshakeHeader);
    remainingLen = recordLen;

    /* Store the legacy version; If we dont find the "supported_versions" extension, use this */
    *majorVersion = *pMsg++;
    *minorVersion = *pMsg++;

    remainingLen -= 2;

    /* Protocol version in this field should be not exceed TLS v1.2;
     * If server is negotiating TLS 1.3, it is indicated in supported_versions extension
     */
    if ((!pSSLSock->isDTLS && *minorVersion > TLS12_MINORVERSION) ||
         (pSSLSock->isDTLS && *minorVersion < DTLS12_MINORVERSION))
    {
        status = ERR_SSL_PROTOCOL_VERSION;
        goto exit;
    }

    /* Skip over the random number */
    pMsg += SSL_RANDOMSIZE;
    remainingLen -= SSL_RANDOMSIZE;

    /* Skip the sessionID */
    sessionIdLen = *pMsg++;
    remainingLen -= 1;

    if (remainingLen < sessionIdLen)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }
    pMsg += sessionIdLen;
    remainingLen -= sessionIdLen;

    /* Skip over the server Cipher */
    if (remainingLen < 2)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }
    pMsg += 2;
    remainingLen -= 2;

    /* Skip the compression */
    if (remainingLen < 1)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }
    pMsg++;
    remainingLen -= 1;

    /* Make sure there are atleast 2 bytes for toal extensions length */
    if (remainingLen >= 2)
    {
        ubyte2 totalExtensionsLength = 0;
        ubyte2 extensionType;
        ubyte2 extensionLength;

        totalExtensionsLength = getShortValue(pMsg);
        pMsg += 2;
        /* Extension Data length should be less than recordLen.
         * caller passes the record Length */
        if ( totalExtensionsLength  < recordLen)
        {
            while(totalExtensionsLength >= 4)
            {
                extensionType = getShortValue(pMsg);
                pMsg += 2;
                totalExtensionsLength -= 2;

                extensionLength = getShortValue(pMsg);
                pMsg += 2;
                totalExtensionsLength -= 2;

                /* Make sure there is no buffer overrun */
                if (extensionLength > totalExtensionsLength)
                {
                    status = ERR_SSL_PROTOCOL_VERSION;
                    goto exit;
                }

                if (extensionType == tlsExt_supported_versions)
                {
                    if (2 != extensionLength)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }
                    *majorVersion = *pMsg++;
                    *minorVersion = *pMsg++;

                    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION > *minorVersion) || 
                         (pSSLSock->isDTLS && DTLS13_MINORVERSION < *minorVersion))
                    {
                        status = ERR_SSL_PROTOCOL_VERSION;
                    }

                    goto exit;
                }

                pMsg += extensionLength;
                totalExtensionsLength -= extensionLength;
            }
        }
    }

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

static MSTATUS
processServerHello(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 recLen)
{
    sbyte4  i;
    ubyte   sessionIdLen;
    ubyte*  pTemp;
    ubyte2  tempLen = 0;
    ubyte   serverSSLMajorVersion;
    ubyte   serverSSLMinorVersion;
    MSTATUS status;
    ubyte2  serverCipherId;
    ubyte4  sizeofHandshakeHeader;
    const struct CipherSuiteInfo* pChosenCipherSuite = NULL;

#ifdef __ENABLE_DIGICERT_TLS13__
    sbyte4  isNotHelloRetryRequest = 1;
    sbyte4  previousHrr;
    sbyte4  isNotEqual;
#endif

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    if (recLen < (2/* Version */ + SSL_RANDOMSIZE + 1/* sessionIdLen */))
    {
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    previousHrr = pSSLSock->helloRetryRequest;

    status = getServerSelectedVersion(pSSLSock, pSHSH, recLen,
                                      &serverSSLMajorVersion,
                                      &serverSSLMinorVersion);
    if (status >= OK)
    {
        pTemp = (ubyte*) (pSHSH+sizeofHandshakeHeader);
        pTemp += 2; /* Skip the version */
    }
    else
#endif
    {
        /* first bytes are the version picked by the server */
        pTemp = (ubyte*) (pSHSH+sizeofHandshakeHeader);
        serverSSLMajorVersion = *pTemp++;
        serverSSLMinorVersion = *pTemp++;
    }

    /* when renegotiating, make sure version is consistent with initial handshake */
    if (pSSLSock->handshakeCount > 0 && serverSSLMinorVersion != pSSLSock->sslMinorVersion)
    {
        status = ERR_SSL_PROTOCOL_VERSION;
        goto exit;
    }

    tempLen += 2;

    /* validate the versions picked by server */
    /* TLS 1.3: Unless a advertisedMinorversion is set, we send TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0 and SSL3.
       So already existing validations suffice for TLS 1.3 */
    if ((pSSLSock->isDTLS && !VALID_DTLS_VERSION(serverSSLMajorVersion, serverSSLMinorVersion)) ||
        (!pSSLSock->isDTLS && !VALID_SSL_VERSION(serverSSLMajorVersion, serverSSLMinorVersion)) ||
        ((pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET) && pSSLSock->advertisedMinorVersion != serverSSLMinorVersion) ||
        ((pSSLSock->isDTLS && pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET) && pSSLSock->minFallbackMinorVersion < serverSSLMinorVersion) ||
        ((pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET) && pSSLSock->minFallbackMinorVersion > serverSSLMinorVersion))

    {
        status = ERR_SSL_PROTOCOL_VERSION;
    }
    else
    {
        pSSLSock->sslMinorVersion = serverSSLMinorVersion;
        status = OK;
    }

    if (NULL != pSSLSock->funcPtrVersionCallback)
    {
        pSSLSock->funcPtrVersionCallback(
            serverSSLMinorVersion, pSSLSock->sslMinorVersion, status);
    }
    if (OK != status)
        goto exit;

#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"SSL version = ");
    DEBUG_INT(DEBUG_SSL_TRANSPORT, pSSLSock->sslMinorVersion);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"");
#endif


    /* Immediately after version negotiated is known, recompute the list of supported signature algorithms */
    if (OK > (status =  SSL_SOCK_filterSupportedSignatureAlgorithm(pSSLSock, TRUE)))
    {
        goto exit;
    }

    /* SERVER RANDOM VALUE in its usual place */
    DIGI_MEMCPY(pSSLSock->pSecretAndRand + SSL_RSAPRESECRETSIZE + SSL_RANDOMSIZE,
            pTemp,
            SSL_RANDOMSIZE);
 
#ifdef __ENABLE_DIGICERT_TLS13__
    /*
       RFC #8446 Section 4.1.3, Page no 33, 3rd paragraph.
       A legacy TLS client performing renegotiation with TLS 1.2 or prior
       and which receives a TLS 1.3 ServerHello during renegotiation MUST
       abort the handshake with a "protocol_version" alert.  Note that
       renegotiation is not possible when TLS 1.3 has been negotiated.
     */
     /* TODO How to check for renegotiation */
     if ((0 < pSSLSock->handshakeCount) && ((!pSSLSock->isDTLS && TLS13_MINORVERSION == serverSSLMinorVersion) ||
                                            (pSSLSock->isDTLS && DTLS13_MINORVERSION == serverSSLMinorVersion)))
     {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                SSL_ALERT_PROTOCOL_VERSION,
                SSLALERTLEVEL_FATAL);
#endif
        status = ERR_SSL_FATAL_ALERT;
        goto exit;
    }

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
         (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        DIGI_MEMCMP(pTemp, HrrRandom, SSL_RANDOMSIZE, &isNotHelloRetryRequest);
    }
    if (0 != isNotHelloRetryRequest)
    {
        if (1 == TLS13_HRR_GET_RX(pSSLSock))
        {
            /* This is reply Server Hello to HRR*/

            /* RFC: 4.1.4: The value of selected_version in the HelloRetryRequest
             * "supported_versions" extension MUST be retained in the ServerHello,
             * and a client MUST abort the handshake with an "illegal_parameter"
             * alert if the value changes.
             */
            if(pSSLSock->roleSpecificInfo.client.hrrServerSSLMinorVersion != serverSSLMinorVersion)
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
        pSSLSock->helloRetryRequest = 0;
        /* RFC: 4.1.3
         * If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of
         * their Random value to the bytes:
         * 44 4F 57 4E 47 52 44 01
         * If negotiating TLS 1.1, TLS 1.3 servers MUST set the last 8 bytes of
         * their Random value to the bytes:
         * 44 4F 57 4E 47 52 44 00
         * TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
         * MUST check that the last 8 bytes are not equal to either of these
         * values. TLS 1.2 clients SHOULD also check that the last 8 bytes are
         * not equal to the second value if the ServerHello indicates TLS 1.1 or
         * below. If a match is found, the client MUST abort the handshake with
         * an "illegal_parameter" alert.
         */

        if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
             (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION > serverSSLMinorVersion) ||
                 (pSSLSock->isDTLS && DTLS13_MINORVERSION < serverSSLMinorVersion))
            {
                DIGI_MEMCMP(pTemp + (SSL_RANDOMSIZE - 8), tls12Random, 8, &isNotEqual);
                if(0 != isNotEqual)
                {
                    DIGI_MEMCMP(pTemp + (SSL_RANDOMSIZE - 8), tls11Random, 8, &isNotEqual);
                }
                if (0 == isNotEqual)
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                            SSL_ALERT_ILLEGAL_PARAMETER,
                            SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    goto exit;
                }

                pSSLSock->sslMinorVersion = serverSSLMinorVersion;
            }
        }
        else if (TLS12_MINORVERSION == pSSLSock->sslMinorVersion || DTLS12_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            if ((!pSSLSock->isDTLS && TLS13_MINORVERSION > serverSSLMinorVersion) ||
                 (pSSLSock->isDTLS && DTLS13_MINORVERSION < serverSSLMinorVersion))
            {
                DIGI_MEMCMP(pTemp + (SSL_RANDOMSIZE - 8), tls11Random, 8, &isNotEqual);
                if (0 == isNotEqual)
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, FALSE,
                            SSL_ALERT_ILLEGAL_PARAMETER,
                            SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    goto exit;
                }

                pSSLSock->sslMinorVersion = serverSSLMinorVersion;
            }
        }
    }
    else
    {
        if(!pSSLSock->helloRetryRequest)
        {
            pSSLSock->helloRetryRequest = 1;
            pSSLSock->roleSpecificInfo.client.hrrServerSSLMinorVersion = serverSSLMinorVersion;
            pSSLSock->roleSpecificInfo.client.hrr = TLS13_HRR_SET_RX(pSSLSock);
            pSSLSock->roleSpecificInfo.client.hrrBufferLen = recLen;
            if(OK > (status = DIGI_MALLOC((void**)&pSSLSock->roleSpecificInfo.client.hrrBuffer,recLen)))
            {
                goto exit;
            }
            if(pSSLSock->roleSpecificInfo.client.hrrBuffer !=NULL)
            {
                DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.hrrBuffer, (pTemp - 6),recLen);
            }
        }
        else
        {
            /* 4.1.4.  Hello Retry Request: If a client receives a second
             * HelloRetryRequest in the same connection (i.e., where the ClientHello
             * was itself in response to a HelloRetryRequest), it MUST abort the
             * handshake with an "unexpected_message" alert.
             */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                    SSL_ALERT_UNEXPECTED_MESSAGE,
                    SSLALERTLEVEL_FATAL);
#endif
            status = ERR_SSL_FATAL_ALERT;
            goto exit;
        }
    }
#endif
    DIGI_MEMCPY(pSSLSock->pServerRandHello, pTemp, SSL_RANDOMSIZE);
    pTemp += SSL_RANDOMSIZE;
    tempLen += SSL_RANDOMSIZE;

    /* SESSION ID */
    pSSLSock->sessionResume = E_NoSessionResume;
    sessionIdLen = (ubyte2)*pTemp++;
    tempLen++;

    if ((sessionIdLen > SSL_MAXSESSIONIDSIZE) || ((tempLen + sessionIdLen) > recLen))
    {
        /* too suspect */
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }

    if ((0 < sessionIdLen) && (sessionIdLen == pSSLSock->roleSpecificInfo.client.sessionIdLen))
    {
        /* could it be the same session id we requested in client hello? */
        sbyte4 memcmpRes;

        status = DIGI_CTIME_MATCH(pTemp, pSSLSock->roleSpecificInfo.client.sessionId,
                            sessionIdLen, &memcmpRes);
        if (OK > status)
        {
        /* RFC: 4.1.3: Server Hello: 
         * A client which receives a legacy_session_id_echo field that does not match what
         * it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
         */
#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                    SSL_ALERT_ILLEGAL_PARAMETER,
                    SSLALERTLEVEL_FATAL);
#endif
#endif
            goto exit;
        }

        /* Session can be resumed for TLS 1.2 and below versions */
        if (((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) || 
             (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)) && 0 == memcmpRes)
        {
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
            /* RFC 5077 section 3.4
             *
             * When presenting a ticket, the client MAY generate and include a
             * Session ID in the TLS ClientHello.  If the server accepts the ticket
             * and the Session ID is not empty, then it MUST respond with the same
             * Session ID present in the ClientHello.  This allows the client to
             * easily differentiate when the server is resuming a session from when
             * it is falling back to a full handshake.  Since the client generates a
             * Session ID, the server MUST NOT rely upon the Session ID having a
             * particular value when validating the ticket.  If a ticket is
             * presented by the client, the server MUST NOT attempt to use the
             * Session ID in the ClientHello for stateful session resumption.
             *
             * If our client sent a session ticket and ID then resume using
             * session ticket
             */
            if (pSSLSock->roleSpecificInfo.client.pTicketTls)
            {
                if (sizeof(pSSLSock->roleSpecificInfo.client.pTicketTls->masterSecret) != SSL_MASTERSECRETSIZE)
                {
                    status = ERR_SSL_PROTOCOL_BAD_LENGTH;
                    goto exit;
                }             
                pSSLSock->roleSpecificInfo.client.pMasterSecret = pSSLSock->roleSpecificInfo.client.pTicketTls->masterSecret;
                pSSLSock->sessionResume = E_SessionTicketResume;
            }
            else
#endif
            {
                pSSLSock->sessionResume = E_SessionIDResume; /* another check is needed for this - done below */
            }
        }
    }
    /* if the session id is different copy it to our buffer (otherwise already identical) */

    if ( E_NoSessionResume == pSSLSock->sessionResume)
    {
        pSSLSock->roleSpecificInfo.client.sessionIdLen = sessionIdLen;
        /* size check above */
        DIGI_MEMCPY( pSSLSock->roleSpecificInfo.client.sessionId, pTemp, sessionIdLen);
    }
    pTemp += sessionIdLen;
    tempLen += sessionIdLen;

    if ((tempLen + 2) > recLen)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }
    /* cipher id */
    serverCipherId = (ubyte2)((*pTemp++) << 8);
    serverCipherId |= (ubyte2) (*pTemp++);

    tempLen += 2;

    for ( i = 0; i < (sbyte4)NUM_CIPHER_SUITES; ++i)
    {
        /* it uses the bit field positions to check the protocol version, ssl3 = 0, tls1.0 = 1,
         * tls1.1 = 2 , tls1.2 = 3, tls1.3 = 4
         * example : gCipherSuites[i].sslVersion = 0x0E, ( It supports tls1.2, tls1.1, tls1.0 )
         * when pSSLSock->sslMinorVersion = 0 (ssl3),    ((0x0E >> 0) & 0x01 )  is 0, means it does not support ssl3
         * when pSSLSock->sslMinorVersion = 1 (tls1.0),  ((0x0E >> 1) & 0x01 )  is 1, means it support tls1.0
         */
        if ((gCipherSuites[i].supported) &&
            (pSSLSock->isDTLS || ((gCipherSuites[i].sslVersion >> pSSLSock->sslMinorVersion) & 0x01)) &&
            (gCipherSuites[i].cipherSuiteId == serverCipherId))
        {
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
            if ((TRUE != pSSLSock->isCipherTableInit) ||
                (TRUE == pSSLSock->isCipherEnabled[i]) )
#endif
            {
                pChosenCipherSuite = gCipherSuites + i;
                break;
            }
        }
    }

    if (NULL == pChosenCipherSuite)
    {
        /* RFC 8446 Section 4.1.3
         *
         * A client which receives a cipher suite that was not offered MUST
         * abort the handshake with an "illegal_parameter" alert.
         */
#if defined(__ENABLE_DIGICERT_TLS13__)
        if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
             (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                        SSL_ALERT_ILLEGAL_PARAMETER,
                        SSLALERTLEVEL_FATAL);
#endif
            status = ERR_SSL_FATAL_ALERT;
            goto exit;
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            return ERR_SSL_NO_CIPHER_MATCH;
        }
    }

    if (NULL == pSSLSock->pHandshakeCipherSuite)
    {
        pSSLSock->pHandshakeCipherSuite = pChosenCipherSuite;
    }
    else
    {
        if (pChosenCipherSuite->cipherSuiteId != pSSLSock->pHandshakeCipherSuite->cipherSuiteId)
        {
            /* If the previously selected cipher suite and current cipher suite do NOT match,
             * clean up all the data structures.
             * This can occur in 0-RTT flow, if server selected a different cipher suite
             */
            resetCipher(pSSLSock, TRUE, FALSE);
            pSSLSock->pHandshakeCipherSuite = pChosenCipherSuite;
        }
    }

#ifdef __ENABLE_DIGICERT_TLS13__

    if(pSSLSock->helloRetryRequest)
    {
        pSSLSock->roleSpecificInfo.client.hrrCipherSuiteInfo = pSSLSock->pHandshakeCipherSuite;
    }
    else
    {
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
	{
		pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
	}

        /* RFC:4.1.4: Upon receiving the ServerHello, clients MUST 
         * check that the cipher suite supplied in
         * the ServerHello is the same as that in the HelloRetryRequest and
         * otherwise abort the handshake with an "illegal_parameter" alert.
         */

        if (1 == TLS13_HRR_GET_RX(pSSLSock))
        {
            if(pSSLSock->roleSpecificInfo.client.hrrCipherSuiteInfo->cipherSuiteId != serverCipherId)
            {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                        SSL_ALERT_UNEXPECTED_MESSAGE,
                        SSLALERTLEVEL_FATAL);
#endif
                status = ERR_SSL_FATAL_ALERT;
                goto exit;
            }
        }
        pSSLSock->roleSpecificInfo.client.hrr = TLS13_HRR_RESET_RX(pSSLSock);
    }
#endif
    if ( (E_SessionIDResume == pSSLSock->sessionResume)
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
         || (E_SessionTicketResume == pSSLSock->sessionResume)
#endif
         )
    {
        /* if we resume session, put the master secret in its place for key generation */
        DIGI_MEMCPY( pSSLSock->pSecretAndRand,
                pSSLSock->roleSpecificInfo.client.pMasterSecret,
                SSL_MASTERSECRETSIZE);

        /* the handshake state is now logically  SSL_SERVER_HELLO_DONE */
        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) =  SSL_SERVER_HELLO_DONE;
    }
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    else if ( pSSLSock->roleSpecificInfo.client.ticket &&
        pSSLSock->roleSpecificInfo.client.ticketLength)
    {
        /* for EAP_FAST, use the pacKey to derive the master secret if
            we don't resume the session */
        if (OK > (status = SSL_SOCK_generateEAPFASTMasterSecret( pSSLSock)))
            goto exit;

        pSSLSock->sessionResume = E_SessionEAPFASTResume;
        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_SERVER_HELLO_DONE;
    }
#endif
    else
    {
        /* If this is a hello retry request then don't move the handshake
         * state forward.
         */
#if defined(__ENABLE_DIGICERT_TLS13__)
        if (!pSSLSock->helloRetryRequest)
#endif
            SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) =  SSL_SERVER_HELLO;
    }

    /* skip past compression choice */
    if ((tempLen + 1) > recLen)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_SERVER_HELLO;
        goto exit;
    }
    ++pTemp;
    tempLen += 1;

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    pSSLSock->isRehandshakeExtPresent = FALSE;
#endif


#if defined(__ENABLE_DIGICERT_EAP_FAST__)
    if ((NULL == pSSLSock->roleSpecificInfo.client.ticket) &&
        (0 == pSSLSock->roleSpecificInfo.client.ticketLength))
#endif
    {
        /* extension is only supported in TLS
           but minimal support is added in SSL 3.0 for secure renegotiation */
        /* if we successfully found a cipher suite, and the version is TLS 1.0+ proceed */
        if ( pTemp + 2 - (ubyte*)(pSHSH+sizeofHandshakeHeader) < recLen)
        {
            /* check the extension length */
            ubyte4 extensionsLength = getShortValue(pTemp);
            pTemp += 2;
            if ( pTemp + extensionsLength - (ubyte*)(pSHSH+sizeofHandshakeHeader) <= recLen)
            {

                if (OK > (status = processHelloExtensions(pSSLSock, pTemp, extensionsLength, SSL_SERVER_HELLO)))
                    goto exit;
            }
        }

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
        /* For TLS 1.2 and below. For TLS 1.3, OCSP status is sent as part of Certificate message */
        if ((pSSLSock->isDTLS) || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
        {
            /* Call back in case of certificate status extension */
            if (NULL != SSL_sslSettings()->funcPtrCertStatusCallback)
            {
                intBoolean certStatus = FALSE;

                /* Check if server responds to cert_status extension */
                if (pSSLSock->certStatusReqExt && pSSLSock->didRecvCertStatusExt)
                {
                    certStatus = TRUE;
                }

                status = (MSTATUS)SSL_sslSettings()->funcPtrCertStatusCallback(
                        SSL_findConnectionInstance(pSSLSock), certStatus);

                if (OK > status)
                {
                    goto exit;
                }
            }
        }
#endif
    }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
         (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))) &&
        (TRUE == pSSLSock->roleSpecificInfo.client.sentExtendedMasterSecret))
    {
        if (TRUE == pSSLSock->receivedExtendedMasterSecret)
        {
            pSSLSock->useExtendedMasterSecret = TRUE;
        }
        else if (TRUE == pSSLSock->useExtendedMasterSecret)
        {
            /* This is an abbreviated handshake, original handshake used the extened master secret;
             * New server hello does not contain extended master secret extension, abort the connection
             */
            status = ERR_SSL_EXTENDED_MASTERSECRET_NOT_SUPPORTED;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE, SSL_ALERT_HANDSHAKE_FAILURE, SSLALERTLEVEL_FATAL);
#endif
            goto exit;
        }
    }
#endif

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if (0 < pSSLSock->handshakeCount)
    {
        if ( (pSSLSock->isRehandshakeAllowed && !pSSLSock->isRehandshakeExtPresent) ||
             (!pSSLSock->isRehandshakeAllowed && pSSLSock->isRehandshakeExtPresent) )
        {
            status = ERR_SSL_CLIENT_RENEGOTIATE_ILLEGAL_EXTENSION;
            goto exit;
        }

        /* allow legacy (insecure) renegotiation only if session flag is set */
        if ( (!pSSLSock->isRehandshakeAllowed && !pSSLSock->isRehandshakeExtPresent) &&
             !(pSSLSock->runtimeFlags & SSL_FLAG_ALLOW_INSECURE_REHANDSHAKE) )
        {
            status = ERR_SSL_CLIENT_RENEGOTIATE_NOT_ALLOWED;
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    if (pSSLSock->useSrtp && NULL == pSSLSock->pHandshakeSrtpProfile)
    {
        return ERR_DTLS_SRTP_EXTENSION_FAILURE;
    }
#endif

    /* If the server sent a hello retry request or this is a normal server
     * hello which has not been preceeded by a hello retry request or if
     * there was early data then do not initialize the hash pool.
     *
     * For DTLS13 we initialize the hash pool whether early data or not
     */
#if defined(__ENABLE_DIGICERT_TLS13__)
    if ( !(((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
            (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
           ((1 == previousHrr)
#if defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__)
         || (NULL != pSSLSock->pEarlyData 
#if defined __ENABLE_DIGICERT_DTLS_CLIENT__         
         && DTLS13_MINORVERSION != pSSLSock->sslMinorVersion
#endif
            )
#endif
           )))
#endif
    {
        /* SSL_SOCK_initHashPool() is also called inside SSL_SOCK_sendEarlyData()
           function. So calling this function here based on the condition that
           the version is tls13 and earlydata is not present or if version is
           not tls13.
           */
        if (OK > (status = SSL_SOCK_initHashPool(pSSLSock)))
            goto exit;
    }

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
#ifdef __ENABLE_DIGICERT_TLS13__

/* Process a CertificateRequest message as per TLS 1.3
 *
 *     struct {
 *         opaque certificate_request_context<0..2^8-1>;
 *         Extension extensions<2..2^16-1>;
 *     } CertificateRequest;
 *
 * certificate_request_context
 *  - Echoed in the clients Certificate message
 *  - MUST be unique within the scope of the connection
 *  - Field SHALL be 0 length unless used for post-handshake authentication
 *
 * extensions
 *  - "signature_algorithms" extension MUST be specified
 *  - "signature_algorithms_cert" extension is optional
 *  - clients MUST ignore unrecognized extensions
 *  - "certificate_authorities" extension is used to specify the list of
 *    supported certificate authorities the server is willing to support
 *
 * Servers using a PSK MUST NOT send a CertificateRequest message in the
 * main handshake.
 */
static MSTATUS
processCertificateRequest3(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 recLen)
{
    MSTATUS         status                   = OK;
    ubyte          *pData                    = NULL;
    intBoolean      found                    = FALSE;
    ubyte2          extensionType;
    ubyte2          extensionsLen;
    ubyte2          extensionSize;
    ubyte4          sizeofHandshakeHeader;
    ubyte2* pSupportedSignatureAlgoList = NULL;
    ubyte4  supportedSignatureAlgoListLength = 0;
#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
    SizedBuffer*    pDistNameEntries = NULL;
    ubyte4          distNameEntryCount = 0;
    ubyte*          pStartDistName;
#endif
    ubyte2 remainingLen = 0;
    remainingLen = recLen;

    if (remainingLen < 1)
    {
        status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
        goto exit;
    }

    pSupportedSignatureAlgoList      = pSSLSock->pSupportedSignatureAlgoList;
    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    pData = (ubyte *)(pSHSH + sizeofHandshakeHeader);

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if ((pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH) &&
        (pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST)))
    {
        pSSLSock->certificateRequestContextLength = (ubyte4)(*pData);
        pData++;
        remainingLen -= 1;

        if (remainingLen < pSSLSock->certificateRequestContextLength)
        {
            status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
            goto exit;
        }

        if (OK != (status = DIGI_CALLOC((void**)&(pSSLSock->certificateRequestContext), 
                            1, 
                            pSSLSock->certificateRequestContextLength)))
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMCPY(pSSLSock->certificateRequestContext,
                        pData,
                        pSSLSock->certificateRequestContextLength)))
        {
            goto exit;
        }
        pData += pSSLSock->certificateRequestContextLength;
        remainingLen -= pSSLSock->certificateRequestContextLength;
    }
    else
#endif
    {
        /* Post-handshake authentication is not being performed. Ensure that
         * the certificate_request_context is 0 length.
         *
         * RFC 8446 Section 4.3.2
         */
        if (0 != *pData)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }
        pData++;
        remainingLen -= 1;
    }

    /* Get the length of the extensions from the next two bytes
     *
     *     Extension extensions<2..2^16-1>
     */

    if (remainingLen < 2)
    {
        status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
        goto exit;
    }
    extensionsLen = getShortValue(pData);
    pData += 2;
    remainingLen -= 2;

    if (remainingLen != extensionsLen)
    {
        status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
        goto exit;
    }

    while ((OK <= status) && (0 < extensionsLen))
    {
	    /* Extension should have 2 bytes of type and 2 bytes of length */
        if (extensionsLen < 4)
        {
            status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
            goto exit;
        }

        extensionType = getShortValue(pData);
        pData += 2;
        extensionsLen -= 2;

        extensionSize = getShortValue(pData);
        pData += 2;
        extensionsLen -= 2;

        if (extensionsLen < extensionSize)
        {
            status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
            goto exit;
        }

        switch(extensionType)
        {
            case tlsExt_supportedSignatureAlgorithms:
            {
                sbyte4 signatureAlgoListLength;
                ubyte2 clientSigAlgo = 0;
                ubyte4 i = 0, j = 0;
                byteBoolean match = 0;

                if (2 > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                signatureAlgoListLength = getShortValue(pData);
                pData += 2;
                if ( (signatureAlgoListLength + 2 > extensionSize) ||
                     (signatureAlgoListLength & 1) )
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

                DIGI_MEMCPY(pSSLSock->signatureAlgoList, pData, signatureAlgoListLength);
                pSSLSock->signatureAlgoListLength = signatureAlgoListLength;

                for (i = 0; i < pSSLSock->signatureAlgoListLength; i += 2)
                {
                    clientSigAlgo = getShortValue(pSSLSock->signatureAlgoList+i);

                    for ( j = 0; j < supportedSignatureAlgoListLength; ++j)
                    {
                        if ((clientSigAlgo == pSupportedSignatureAlgoList[j])
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
                            && isHashAlgoSupported((clientSigAlgo >> 8) & 0xff)
#endif
                            )
                        {
                            pSSLSock->signatureAlgo = clientSigAlgo;
                            match = 1;
                            break;
                        }
                        /*if (1 == match)
                            break;*/
                    }
                }

                pData += signatureAlgoListLength;

                if (match != 1)
                {
                    status = ERR_SSL_NO_SIGNATURE_ALGORITHM_MATCH;
                    goto exit;
                }
                break;
            }
            case tlsExt_signatureAlgorithmCerts:
            {
                sbyte4 sigAlgoCertListLen;

                if (2 > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                sigAlgoCertListLen = getShortValue(pData);
                pData += 2;

                if ( (sigAlgoCertListLen + 2 > extensionSize) ||
                     (sigAlgoCertListLen & 1) )
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                pSSLSock->signatureAlgoCertList = pData;
                pSSLSock->signatureAlgoCertListLength = sigAlgoCertListLen;

                pData += sigAlgoCertListLen;
                break;
            }
            case tlsExt_status_request:
            {
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
                if (OK > (status = SSLSOCK_sanityCertificateStatusRequestExtension(
                    pSSLSock, pData, extensionSize)))
                {
                    goto exit;
                }

                pSSLSock->recvStatusReqExt = TRUE;
#endif
                pData += extensionSize;
                break;
            }
            case tlsExt_certificateAuthorities:
            {
                sbyte4 certAuthExtLen, tempLen;

                if (2 > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                certAuthExtLen = getShortValue(pData);
                pData += 2;
                if (certAuthExtLen + 2 > extensionSize)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }
                
                pStartDistName = pData;
                while (certAuthExtLen)
                {
                    if (certAuthExtLen < 2)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    tempLen = getShortValue(pData);
                    pData += 2;
                    certAuthExtLen -= 2;
                    
                    if (tempLen > certAuthExtLen)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    pData += tempLen;
                    certAuthExtLen -= tempLen;
#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
                    distNameEntryCount++;
#endif
                }

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
                if ( (0 != distNameEntryCount) &&
                    (NULL != pSSLSock->funcPtrClientCertAuthorityCallback) )
                {
                    ubyte4 entryIndex;

                    status = DIGI_CALLOC(
                        (void **) &pDistNameEntries, distNameEntryCount,
                        sizeof(SizedBuffer));
                    if (OK != status)
                    {
                        goto exit;
                    }

                    for (entryIndex = 0; entryIndex < distNameEntryCount; entryIndex++)
                    {
                        /* TO DO for QS version this might need to be getLongValue and += 4 */
                        pDistNameEntries[entryIndex].length = (ubyte4) getShortValue(pStartDistName);
                        pStartDistName += 2;

                        pDistNameEntries[entryIndex].data = pStartDistName;
                        pStartDistName += pDistNameEntries[entryIndex].length;
                    }


                    status = pSSLSock->funcPtrClientCertAuthorityCallback(
                        SSL_findConnectionInstance(pSSLSock), pDistNameEntries,
                        distNameEntryCount);
                    if (OK != status)
                    {
                        DEBUG_ERROR(DEBUG_SSL_MESSAGES, "pSSLSock->funcPtrClientCertAuthorityCallback() returns status = ", status);
                        goto exit;
                    }
                }
#endif
                break;
            }
            default:
                /* Skip over the entire extension */ 
                pData += extensionSize;
                break;
        }
        extensionsLen -= extensionSize;
    }

    if (NULL != pSSLSock->pCertStore)
    {
        status = SSL_SOCK_setCertTLS13(
            pSSLSock, pSSLSock->pCertStore, pSSLSock->signatureAlgoList,
            pSSLSock->signatureAlgoListLength, pSSLSock->signatureAlgoCertList,
            pSSLSock->signatureAlgoCertListLength, NULL, &(pSSLSock->mutualAuthKey),
            &(pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts),
            (ubyte4 *) &(pSSLSock->roleSpecificInfo.client.numMutualAuthCert),
            &(pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo), &found);
        if (OK > status)
        {
            goto exit;
        }
    }

    if (FALSE == found)
    {
        if (pSSLSock->pMutualAuthCertStore == NULL)
        {
            if (pSSLSock->roleSpecificInfo.client.funcPtrClientCertCallback != NULL)
            {
                SizedBuffer *pCert   = NULL;
                ubyte       *pCACert = NULL;
                ubyte       *pKey    = NULL;
                ubyte4       numCerts   = 0;
                ubyte4       numCACerts = 0;
                ubyte4       keyLen     = 0;
                ubyte4       i          = 0;
                ubyte4       bufferSize = sizeof(SizedBuffer);

                sbyte4 connInstance = SSL_findConnectionInstance(pSSLSock);

                if (OK > (status = DIGI_MALLOC((void **)&pCert, bufferSize)))
                {
                    goto exit;
                }
                DIGI_MEMSET((ubyte *)pCert, 0x00, bufferSize);

                if (OK > (status = pSSLSock->roleSpecificInfo.client.funcPtrClientCertCallback(connInstance,
                                                                                               &pCert, &numCerts,
                                                                                               &pKey, &keyLen,
                                                                                               &pCACert, &numCACerts)))
                {
                    goto exit1;
                }

                /* Check if we have any certs */
                if (numCerts > 0)
                {
                    if (OK > (status = SSLSOCK_populateMutualAuthCertStore(pSSLSock,
                                                                        pCert, numCerts,
                                                                        pKey, keyLen,
                                                                        pCACert, numCACerts)))
                    {
                        goto exit1;
                    }
                }
exit1:
                if (NULL != pCert)
                {
                    for (i = 0; i < numCerts; i++)
                    {
                        if (NULL != pCert[i].data)
                        {
                            DIGI_FREE((void**)&(pCert[i].data));
                        }
                        pCert[i].data = NULL;
                        pCert[i].length = 0;
                    }
                    DIGI_FREE((void **)&pCert);
                }

                if (pKey != NULL)
                {
                    DIGI_FREE((void **)&pKey);
                }

                /* We did not add any certificates to the mutual auth certStore which was NULL before */
                if (0 == numCerts)
                {
                    pSSLSock->generateEmptyCert = TRUE;
                    status = OK;
                    goto exit;
                }
            }
        }

        if (NULL != pSSLSock->pMutualAuthCertStore)
        {
            status = SSL_SOCK_setCertTLS13(
                pSSLSock, pSSLSock->pMutualAuthCertStore, pSSLSock->signatureAlgoList,
                pSSLSock->signatureAlgoListLength, pSSLSock->signatureAlgoCertList,
                pSSLSock->signatureAlgoCertListLength, NULL, &(pSSLSock->mutualAuthKey),
                &(pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts),
                (ubyte4 *) &(pSSLSock->roleSpecificInfo.client.numMutualAuthCert),
                &(pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo), &found);
            if (OK > status)
            {
                goto exit;
            }
        }
    }

    if (TRUE == found)
    {
        pSSLSock->isMutualAuthNegotiated = TRUE;
        pSSLSock->generateEmptyCert = FALSE;
    }
    else
    {
        pSSLSock->generateEmptyCert = TRUE;
    }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
    if (OK > (status = SSLSOCK_setKeyAndTokenHandle(pSSLSock, FALSE /* isServer */)))
    {
        goto exit;
    }
#endif

exit:

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
    if (NULL != pDistNameEntries)
    {
        DIGI_FREE((void **) &pDistNameEntries);
    }
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_TLS13__ */


static MSTATUS
findCertificate(SSLSocket *pSSLSock, void *pCertStore, ubyte4 *pAlgoIds, ubyte4 algoIdsLen,
                const AsymmetricKey **ppPrivateKey,
                const SizedBuffer **ppCerts, ubyte4 *pNumCerts,
                ubyte *pCertTypes, ubyte4 certTypeLen)
{
    MSTATUS status = OK;
    ubyte4 offset = 0, i, j;
    ubyte4 pubKeyType;
    ASN1_ITEMPTR    pRoot = NULL;
    ubyte4 *pKeyAlgoIds = NULL;
    ubyte4 keyAlgoIdsLen = 0;
    ubyte4 *pFullAlgoList = NULL;
    ubyte4 fullAlgoListLen = 0;
    ubyte4 curveIds[NUM_ECC_PCURVES] = { 0 }; /* Max of 5 for the 5 NIST curves */
    ubyte4 curveIdsLen = 0;
    ubyte4 numHashes = NUM_SSL_ALL_CERT_STORE_HASH_ALGORITHMS; /* Max digests possible */

    /* Convert supported curves from SSL flags to CERT_STORE flags */
    convertEcGroupsToKeyIdList(SUPPORTED_GROUPS_FLAGS, curveIds, &curveIdsLen);
    
    /* Ed curves not checked here */

    /* Extend the pAlgoIds passed in for more entries, up to numHashes */
    status = DIGI_CALLOC((void **) &pFullAlgoList, algoIdsLen + numHashes, sizeof(ubyte4));
    if (OK != status)
        goto exit;

    /* copy over what was already there */
    status = DIGI_MEMCPY((ubyte *) pFullAlgoList, (ubyte *) pAlgoIds, algoIdsLen * sizeof(ubyte4));
    if (OK != status)
        goto exit;

    /* Before processing the certificate type, set all hash algorithms that are
     * supported.
     *
     * For TLS 1.1 and below the initial algorithm list is created based on
     * the cipher suite negotiated. The server may specify additional algorithms
     * through the cert type in the certificate request message.
     *
     * For TLS 1.2 the signature algorithms extension was introduced. This
     * extension allows the client to set the signature algorithms in the
     * initial list and setting them here is redundant. The signature algorithms
     * extension is optional so if the server does not provide it then this
     * loop is required. */
    for (i = 0; i < numHashes; i++)
    {
        for (j = 0; j < algoIdsLen; j++)
        {
            if (gAllCertStoreHashAlgorithms[j] == CERT_STORE_ALGO_ID_GET_HASH(pFullAlgoList[i]))
            {
                CERT_STORE_ALGO_ID_SET_HASH(pFullAlgoList[algoIdsLen + j], gAllCertStoreHashAlgorithms[j]);
            }
        }
    }

    do {
        /* reset back to the end of the copied ids */
        fullAlgoListLen = algoIdsLen;
        
        /* reinitiate certDescriptor */
        switch (pCertTypes[offset++])
        {
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
        case  tlsClientCertType_dsa_sign:
            pubKeyType = akt_dsa;
            setKeyTypeForAllHashes(pFullAlgoList, &fullAlgoListLen, akt_dsa);
            pKeyAlgoIds = NULL;
            keyAlgoIdsLen = 0;
            break;
#endif
        case tlsClientCertType_rsa_sign:
            pubKeyType = akt_rsa;
            setKeyTypeForAllHashes(pFullAlgoList, &fullAlgoListLen, akt_rsa);
            pKeyAlgoIds = NULL;
            keyAlgoIdsLen = 0;
            break;
#if defined(__ENABLE_DIGICERT_ECC__)
        case tlsClientCertType_ecdsa_sign:
        case tlsClientCertType_ecdsa_fixed_ecdh:
            pubKeyType = akt_ecc;
            setKeyTypeForAllHashes(pFullAlgoList, &fullAlgoListLen, akt_ecc);
            /* We need pKeyAlgoIds to be the passed in list that has the proper curves */
            pKeyAlgoIds = curveIds;
            keyAlgoIdsLen = curveIdsLen;
            break;

        case tlsClientCertType_rsa_fixed_ecdh:
            pubKeyType = akt_ecc;
            setKeyTypeForAllHashes(pFullAlgoList, &fullAlgoListLen, akt_rsa);
            /* We need pKeyAlgoIds to be the passed in list that has the proper curves */
            pKeyAlgoIds = curveIds;
            keyAlgoIdsLen = curveIdsLen;
            break;
#endif

        default:
            continue; /* keep going */
        }

        if ((pSSLSock->roleSpecificInfo.client.pCertAuthAlias != NULL) &&
            (pSSLSock->roleSpecificInfo.client.certAuthAliasLen > 0))
        {
            if (OK > (status = CERT_STORE_findIdentityByAliasAndAlgo(pCertStore, pubKeyType, 0,
                                                                     pKeyAlgoIds, keyAlgoIdsLen, pFullAlgoList, fullAlgoListLen,
                                                                     pSSLSock->roleSpecificInfo.client.pCertAuthAlias,
                                                                     pSSLSock->roleSpecificInfo.client.certAuthAliasLen,
                                                                     (struct AsymmetricKey **)ppPrivateKey,
                                                                     (struct SizedBuffer **)ppCerts, pNumCerts, NULL)))
            {
                /* No certificate with this alias and the algorithms; continue */
                continue;
            }
        }
        else
        {
            if (OK > (status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, pubKeyType, 0,
                                                                              pKeyAlgoIds, keyAlgoIdsLen, pFullAlgoList, fullAlgoListLen,
                                                                              ppPrivateKey, ppCerts,
                                                                              pNumCerts, NULL)))
            {
                continue; /* not found -- keep going */
            }
        }

        /* Check for a key and certificate.
         */
        if ((NULL != *ppPrivateKey) && (0 != *pNumCerts))
        {
            /* Possible that the key is empty. If it is empty then check if
             * the signature callback has been set. If it has been set then
             * store the public key of the certificate as the mutual auth
             * key.
             */
            if ((akt_undefined == (*ppPrivateKey)->type) &&
                (NULL != SSL_sslSettings()->funcPtrMutualAuthCertificateVerify))
            {
                MemFile mf;
                CStream cs;

                MF_attach( &mf, (*ppCerts[0]).length, (*ppCerts[0]).data);
                CS_AttachMemFile(&cs, &mf);

                status = ASN1_Parse(cs, &pRoot);
                if (OK != status)
                {
                    goto exit;
                }

                /* Extract the key into the mutual auth key.
                 */
                status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(pSSLSock->hwAccelCookie)
                    ASN1_FIRST_CHILD(pRoot), cs, &pSSLSock->mutualAuthKey);
                if (OK != status)
                {
                    goto exit;
                }

                *ppPrivateKey = &pSSLSock->mutualAuthKey;
            }

            /* If the key type that was retrieved is not undefined then
             * the certificate and key pair has been found.
             */
            if (akt_undefined != (*ppPrivateKey)->type)
            {
                break;    /* use the first certificate found */
            }

            break;
        }
    } while (offset < certTypeLen); /* while there is the next certificateType */

exit:

    if (NULL != pFullAlgoList)
    {
        (void) DIGI_FREE((void **) &pFullAlgoList);
    }

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }
    return status;
}


static MSTATUS
processCertificateRequest(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 recLen)
{
    ubyte4          lenTotal;
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_EDDSA__)
    ubyte4          curveId;
#endif
    ubyte2          lenCertTypes;
    ubyte2          lenSigHashAlgos = 0;
    ubyte2          lenDistinguishedNames;
    ubyte2          lenTempDistName;
    ubyte*          pStartCertTypes;
    ubyte*          pStartSigHashAlgos = NULL;
    ubyte*          pDistNameEntry;
    ubyte4          sizeofHandshakeHeader;
#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
    SizedBuffer*    pDistNameEntries = NULL;
    ubyte4          distNameEntryCount = 0;
    ubyte*          pStartDistName;
#endif
    MSTATUS         status = ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE;
    ubyte4          *pAlgoIds = NULL;
    ubyte4          algoIdsLen = 0;

    if (0 == recLen)
        goto exit;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    pDistNameEntry = (ubyte *)(pSHSH + sizeofHandshakeHeader);

    lenCertTypes = (ubyte2)(*pDistNameEntry);               pDistNameEntry += 1;

    pStartCertTypes = pDistNameEntry;

    lenTotal = (ubyte4)(1 + lenCertTypes);

    if (lenTotal >= recLen)
    {
        goto exit;
    }

    pDistNameEntry += lenCertTypes;

    /* tls1.2 added SignatureAndHashAlgorithms after certType */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        if ((lenTotal + 2) >= recLen)
        {
            goto exit;
        }

        lenSigHashAlgos = getShortValue(pDistNameEntry);
        pDistNameEntry += 2;
        lenTotal += 2;

        if (((lenTotal + lenSigHashAlgos) >= recLen) ||
            (lenSigHashAlgos & 1))
        {
            goto exit;
        }

        pStartSigHashAlgos = pDistNameEntry;
        pDistNameEntry += lenSigHashAlgos;
        lenTotal += lenSigHashAlgos;

        if (pSSLSock->signatureAlgoList != NULL)
        {
            DIGI_FREE((void **) &(pSSLSock->signatureAlgoList));
        }

        /* Copy over the signature algorithm list provided by the
         * peer.
         *
         * Don't set status here unless failure. Code afterwards checks for the
         * length and goes to exit without setting status. We don't want to
         * override the default error status. */
        if (OK > (DIGI_MALLOC((void **) &(pSSLSock->signatureAlgoList), lenSigHashAlgos)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pSSLSock->signatureAlgoList, pStartSigHashAlgos, lenSigHashAlgos);
        pSSLSock->signatureAlgoListLength = lenSigHashAlgos;
    }

    if ((lenTotal + 2) > recLen)
    {
        goto exit;
    }

    lenDistinguishedNames = getShortValue(pDistNameEntry);   pDistNameEntry += 2;

    lenTotal = lenTotal + 2;

    if ((lenDistinguishedNames + lenTotal) > recLen)
    {
        goto exit;
    }

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
    pStartDistName = pDistNameEntry;
#endif

    /* validate array of distinguished names */
    while (lenDistinguishedNames)
    {
        if ((lenTotal + 2) > recLen)
        {
            goto exit;
        }

        lenTempDistName = getShortValue(pDistNameEntry);    pDistNameEntry += 2;

        lenTotal = lenTotal + 2 + lenTempDistName;

        if (lenTotal > recLen)
            goto exit;

        pDistNameEntry += lenTempDistName;

        if ((2 + lenTempDistName) > lenDistinguishedNames)
            goto exit;

        lenDistinguishedNames = (ubyte2)(lenDistinguishedNames - (2 + lenTempDistName));
#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
        distNameEntryCount++;
#endif
    }

    /* Check all bytes have been processed */
    if (recLen != lenTotal)
    {
        goto exit;
    }

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
    if ( (0 != distNameEntryCount) &&
         (NULL != pSSLSock->funcPtrClientCertAuthorityCallback) )
    {
        ubyte4 entryIndex;

        status = DIGI_CALLOC(
            (void **) &pDistNameEntries, distNameEntryCount,
            sizeof(SizedBuffer));
        if (OK != status)
        {
            goto exit;
        }

        for (entryIndex = 0; entryIndex < distNameEntryCount; entryIndex++)
        {
            /* TO DO for QS this may need to be a getLongValue and +=4 */
            pDistNameEntries[entryIndex].length = (ubyte4) getShortValue(pStartDistName);
            pStartDistName += 2;

            pDistNameEntries[entryIndex].data = pStartDistName;
            pStartDistName += pDistNameEntries[entryIndex].length;
        }


        status = pSSLSock->funcPtrClientCertAuthorityCallback(
            SSL_findConnectionInstance(pSSLSock), pDistNameEntries,
            distNameEntryCount);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SSL_MESSAGES, "pSSLSock->funcPtrClientCertAuthorityCallback() returns status = ", status);
            goto exit;
        }
    }
#endif

    /* fetch certificate for future reference */
    /* after fetching the cert we check against signature algos offered by server */
    if ((NULL != pSSLSock->pCertStore) || (NULL != pSSLSock->pMutualAuthCertStore) ||
        (NULL != pSSLSock->roleSpecificInfo.client.funcPtrClientCertCallback))
    {
        const AsymmetricKey *pPrivateKey = 0;

        /* convert eccurve and server supported sig algos to algo id list */
        status = convertToCertStoreAlgoIdList(pSSLSock, pSSLSock->signatureAlgoList, pSSLSock->signatureAlgoListLength, 
            &pAlgoIds, &algoIdsLen);
        if (OK != status)
            goto exit;

        if (NULL != pSSLSock->pCertStore)
        {
            if (OK > (status = findCertificate(pSSLSock, pSSLSock->pCertStore, pAlgoIds, algoIdsLen,
                                              &pPrivateKey,
                                              &pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts,
                                              &pSSLSock->roleSpecificInfo.client.numMutualAuthCert,
                                              pStartCertTypes, lenCertTypes)))
            {
                goto exit;
            }
        }
        if (0 == pSSLSock->roleSpecificInfo.client.numMutualAuthCert)
        {
            if (pSSLSock->pMutualAuthCertStore == NULL)
            {
                if (pSSLSock->roleSpecificInfo.client.funcPtrClientCertCallback != NULL)
                {
                    SizedBuffer *pCert   = NULL;
                    ubyte       *pCACert = NULL;
                    ubyte       *pKey    = NULL;
                    ubyte4       numCerts   = 0;
                    ubyte4       numCACerts = 0;
                    ubyte4       keyLen     = 0;
                    ubyte4       i          = 0;
                    ubyte4       bufferSize = sizeof(SizedBuffer);

                    sbyte4 connInstance = SSL_findConnectionInstance(pSSLSock);

                    if (OK > (status = DIGI_MALLOC((void **)&pCert, bufferSize)))
                    {
                        goto exit;
                    }
                    DIGI_MEMSET((ubyte *) pCert, 0x00, bufferSize);

                    if (OK > (status = pSSLSock->roleSpecificInfo.client.funcPtrClientCertCallback(connInstance,
                                                                                                   &pCert, &numCerts,
                                                                                                   &pKey, &keyLen,
                                                                                                   &pCACert, &numCACerts)))
                    {
                        goto exit1;
                    }

                    /* Check if we have any certs */
                    if (numCerts > 0)
                    {
                        if (OK > (status = SSLSOCK_populateMutualAuthCertStore(pSSLSock,
                                                                            pCert, numCerts,
                                                                            pKey, keyLen,
                                                                            pCACert, numCACerts)))
                        {
                            goto exit1;
                        }
                    }
exit1:
                    if (NULL != pCert)
                    {
                        for (i = 0; i < numCerts; i++)
                        {
                            if (NULL != pCert[i].data)
                            {
                                DIGI_FREE((void**)&(pCert[i].data));
                            }
                            pCert[i].data = NULL;
                            pCert[i].length = 0;
                        }
                        DIGI_FREE((void **)&pCert);
                    }

                    if (pKey != NULL)
                    {
                        DIGI_FREE((void **)&pKey);
                    }

                    /* We did not add any certificates to the mutual auth certStore which was NULL before */
                    if (0 == numCerts)
                    {
                        pSSLSock->generateEmptyCert = TRUE;
                        status = OK;
                        goto exit;
                    }

                    if (OK > status)
                    {
                        goto exit;
                    }
                }
                else
                {
                    /* send empty cert if no valid certificate is found */
                    pSSLSock->generateEmptyCert = TRUE;
                    status = OK;
                    goto exit;
                }
            }

            if (OK > (status = findCertificate(pSSLSock, pSSLSock->pMutualAuthCertStore, pAlgoIds, algoIdsLen,
                                              &pPrivateKey,
                                              &pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts,
                                              &pSSLSock->roleSpecificInfo.client.numMutualAuthCert,
                                              pStartCertTypes, lenCertTypes)))
            {
                goto exit;
            }
        }


        if (0 == pSSLSock->roleSpecificInfo.client.numMutualAuthCert)
        {
            /* send empty cert if no valid certificate is found */
            pSSLSock->generateEmptyCert = TRUE;
            status = OK;
            goto exit;
        }

        /*
         * if loop exits without calling CERT_STORE_findIdentityCertChainFirstFromList(),
         * or if CERT_STORE_findIdentityCertChainFirstFromList() doesn't initialize pPrivateKey
         * NULL value of pPrivateKey will be used below and in switch below
         */
        if (NULL == pPrivateKey)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* When searching for an identity, if the identity does not have a
         * private key then the public key is extracted from the certificate and
         * stored in the pSSLSock->mutualAuthKey and the pointer for the private
         * key will also point to pSSLSock->mutualAuthKey. If these pointers
         * match then there is no need to copy the key into the SSLSocket
         * structure. (Key has been allocated from the certificate directly
         * into the SSLSocket structure)
         *
         * If a private key is found in the certificate store then pPrivateKey
         * will contain a reference to that key, which must be copied to
         * pSSLSock->mutualAuthKey. (Key is a reference and must be copied
         * over to the SSLSocket structure)
         */
        if (&(pSSLSock->mutualAuthKey) != pPrivateKey)
        {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            status = CRYPTO_INTERFACE_copyAsymmetricKey(&pSSLSock->mutualAuthKey, pPrivateKey);
#else
            status = CRYPTO_copyAsymmetricKey(&pSSLSock->mutualAuthKey, pPrivateKey);
#endif
            if (OK != status)
            {
                goto exit;
            }
        }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
        if (OK > (status = SSLSOCK_setKeyAndTokenHandle(pSSLSock, FALSE /* isServer */)))
        {
            goto exit;
        }
#endif

        if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            ubyte2  serverSigAlgo;
            ubyte keyTlsAlgo = 0;

            status = ERR_SSL_UNSUPPORTED_ALGORITHM;

            switch(pSSLSock->mutualAuthKey.type & 0xff)
            {
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
                case akt_rsa: keyTlsAlgo = TLS_RSA;
                    break;
#endif
#ifdef __ENABLE_DIGICERT_DSA__
                case akt_dsa: keyTlsAlgo = TLS_DSA;
                    break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
                case akt_ecc: keyTlsAlgo = TLS_ECDSA;
                    break;
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
                case akt_ecc_ed:
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pSSLSock->mutualAuthKey.key.pECC, &curveId);
#else
                    status = EC_getCurveIdFromKey(pSSLSock->mutualAuthKey.key.pECC, &curveId);
#endif
                    if (OK != status)
                        goto exit;

                    if (cid_EC_Ed25519 == curveId)
                    {
                        keyTlsAlgo = TLS_EDDSA25519;
                    }
                    else if (cid_EC_Ed448 == curveId)
                    {
                        keyTlsAlgo = TLS_EDDSA448;
                    }
                    break;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
                default: goto exit;
            }

            /* If this is a resumed session, check the signature algorithm retrieved from cache */
            if (pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo & keyTlsAlgo)
            {
                status = OK;
                pSSLSock->isMutualAuthNegotiated = TRUE;
                pSSLSock->generateEmptyCert      = FALSE;
                goto exit;
            }
            else if (0 < lenSigHashAlgos)
            {
                /* pick a hash/sig pair from signature Algo extension */
                ubyte4 i;

                for (i = 0; i < lenSigHashAlgos; i += 2)
                {
                    serverSigAlgo = (ubyte2) (pStartSigHashAlgos[i] << 8 | pStartSigHashAlgos[i+1]);

                    if ((serverSigAlgo & 0xff) == (keyTlsAlgo))
                    {
                        switch((serverSigAlgo >> 8) & 0xff)
                        {
#ifndef __DISABLE_DIGICERT_SHA512__
                            case TLS_SHA512:
                                /* TAP does not support SHA512 */
                                if (pSSLSock->mutualAuthKey.type & 0xff0000)
                                {
                                    break;
                                }
                                /* TPM 1.2 does not support SHA512 */
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
                                if ((keyTlsAlgo == TLS_RSA) &&
                                    (pSSLSock->mutualAuthKey.key.pRSA->hsmInfo != NULL))
                                {
                                    break;
                                }
#endif
                                pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = serverSigAlgo;
                                pSSLSock->isMutualAuthNegotiated = TRUE;
                                pSSLSock->generateEmptyCert = FALSE;
                                status = OK;
                                goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
                            case TLS_SHA384:
                                /* TAP does not support SHA384 */
                                if (pSSLSock->mutualAuthKey.type & 0xff0000)
                                {
                                    break;
                                }
                                /* TPM 1.2 does not support SHA512 */
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
                                if ((keyTlsAlgo == TLS_RSA) &&
                                    (pSSLSock->mutualAuthKey.key.pRSA->hsmInfo != NULL))
                                {
                                    break;
                                }
#endif
                                pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = serverSigAlgo;
                                pSSLSock->isMutualAuthNegotiated = TRUE;
                                pSSLSock->generateEmptyCert = FALSE;
                                status = OK;
                                goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
                            case TLS_SHA256:
                                pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = serverSigAlgo;
                                pSSLSock->isMutualAuthNegotiated = TRUE;
                                pSSLSock->generateEmptyCert = FALSE;
                                status = OK;
                                goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
                            case TLS_SHA224:
                                /* TAP does not support SHA224 */
                                if (pSSLSock->mutualAuthKey.type & 0xff0000)
                                {
                                    break;
                                }
                                /* TPM 1.2 does not support SHA224 */
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
                                if ((keyTlsAlgo == TLS_RSA) &&
                                    (pSSLSock->mutualAuthKey.key.pRSA->hsmInfo != NULL))
                                {
                                    break;
                                }
#endif
                                pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = serverSigAlgo;
                                pSSLSock->isMutualAuthNegotiated = TRUE;
                                pSSLSock->generateEmptyCert = FALSE;
                                status = OK;
                                goto exit;
#endif
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
                            case TLS_SHA1:
                                if (TRUE == SSL_sslSettings()->allowSha1SigAlg)
                                {
                                    pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = serverSigAlgo;
                                    pSSLSock->isMutualAuthNegotiated = TRUE;
                                    pSSLSock->generateEmptyCert = FALSE;
                                    status = OK;
                                    goto exit;
                                }
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
                switch(pSSLSock->mutualAuthKey.type & 0xff)
                {
                    case akt_rsa:
                        pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = (TLS_SHA1 << 8 | TLS_RSA);
                        pSSLSock->isMutualAuthNegotiated = TRUE;
                        pSSLSock->generateEmptyCert = FALSE;
                        status = OK;
                        goto exit;

                    case akt_ecc:
                        pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = (TLS_SHA1 << 8 | TLS_ECDSA);
                        pSSLSock->isMutualAuthNegotiated = TRUE;
                        pSSLSock->generateEmptyCert = FALSE;
                        status = OK;
                        goto exit;

                    case akt_dsa:
                        pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = (TLS_SHA1 << 8 | TLS_DSA);
                        pSSLSock->isMutualAuthNegotiated = TRUE;
                        pSSLSock->generateEmptyCert = FALSE;
                        status = OK;
                        goto exit;

                    default:
                        pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo = 0;
                        pSSLSock->isMutualAuthNegotiated = TRUE;
                        pSSLSock->generateEmptyCert = FALSE;
                        status = OK;
                        goto exit;
                }
            }

        } /* TLS 1.2 */
    }
    else
    {
        pSSLSock->generateEmptyCert = TRUE;
        status = OK;
        goto exit;
    }

    pSSLSock->isMutualAuthNegotiated = TRUE;
    pSSLSock->generateEmptyCert = FALSE;
    status = OK;

exit:

    if (NULL != pAlgoIds)
    {
        (void) DIGI_FREE((void **) &pAlgoIds);
    }

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__)
    if (NULL != pDistNameEntries)
    {
        DIGI_FREE((void **) &pDistNameEntries);
    }
#endif

    return status;

} /* processCertificateRequest */
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
static MSTATUS
processEncryptedExtensions(SSLSocket* pSSLSock, ubyte* pMesg, ubyte2 msgLength)
{
    MSTATUS status = OK;
    ubyte*  pTemp;
    ubyte4  sizeofHandshakeHeader = 0;
    ubyte2  extensionLength = 0;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } 
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    pTemp = (ubyte *) (pMesg + sizeofHandshakeHeader);

    if (2 > msgLength)
    {
        status = ERR_SSL_EXTENSION_LENGTH;
        goto exit;
    }

    extensionLength = getShortValue(pTemp);
    pTemp += sizeof(ubyte2);

    if (OK > (status = processHelloExtensions(pSSLSock, pTemp, extensionLength, SSL_ENCRYPTED_EXTENSIONS)))
        goto exit;

    if (status == OK)
    {
        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_ENCRYPTED_EXTENSIONS;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_TLS13__ */

/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
static MSTATUS
verifyServerKeyExchangeRSASignature(SSLSocket* pSSLSock, ubyte* pMesg,
                                    ubyte2 msgLen, ubyte2 dataLen,
                                    vlong** ppVlongQueue)
{
    ubyte*      pHashResult = NULL;
    ubyte2      sigLen;
    ubyte4      cipherLen;
    sbyte4      cmpRes;
    RSAKey*     pRSAKey;
    ubyte*      pDecrypt = 0;
    MSTATUS     status;
    ubyte4      hashLen = 0;
    ubyte2      sigAlgo = 0;
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_PKCS1__)
    ubyte*      pSignedData = NULL;
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_PKCS1__ */

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

    /* verify signature length */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        sigLen = getShortValue( pMesg + dataLen);
        /* total msg len = 2 + sigLen + dataLen */
        if ( sigLen + 2 + dataLen != msgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
    }
    else
    {
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_PKCS1__)
        ubyte hashId = 0;
        ubyte4 saltLen;
        ubyte4 sigAlgoIndex;
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_PKCS1__ */

        /* TLS1.2 is sigAlgo+signature */
        sigLen = getShortValue( pMesg + dataLen + 2);
        /* total msg len = 2 + 2+ sigLen + dataLen */
        if ( sigLen + 2 + 2 + dataLen != msgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_PKCS1__)
        /* Get the signature algorithm
         */
        sigAlgo = getShortValue(pMesg + dataLen);
        
        for (sigAlgoIndex = 0; sigAlgoIndex < NUM_SSL_SUPPORTED_SIGNATURE_ALGORITHMS; sigAlgoIndex++)
        {
            if (sigAlgo == gSupportedSignatureAlgorithms[sigAlgoIndex])
            {
                break;
            }
        }

        if (NUM_SSL_SUPPORTED_SIGNATURE_ALGORITHMS == sigAlgoIndex)
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }

        /* Check for RSA-PSS.
         */
        switch (sigAlgo)
        {
#ifndef __DISABLE_DIGICERT_SHA256__
            case SSL_RSA_PSS_RSAE_SHA256:
            case SSL_RSA_PSS_PSS_SHA256:
                hashId = ht_sha256;
                saltLen = 32;
                break;
#endif /* !__DISABLE_DIGICERT_SHA256__ */
#ifndef __DISABLE_DIGICERT_SHA384__
            case SSL_RSA_PSS_RSAE_SHA384:
            case SSL_RSA_PSS_PSS_SHA384:
                hashId = ht_sha384;
                saltLen = 48;
                break;
#endif /* !__DISABLE_DIGICERT_SHA384__ */
#ifndef __DISABLE_DIGICERT_SHA512__
            case SSL_RSA_PSS_RSAE_SHA512:
            case SSL_RSA_PSS_PSS_SHA512:
                hashId = ht_sha512;
                saltLen = 64;
                break;
#endif /* !__DISABLE_DIGICERT_SHA512__ */
        }

        /* If a digest ID was set then verify the signature using RSA-PSS.
         */
        if (hashId)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            ubyte4 isValid = 1;
#else
            intBoolean isValid = FALSE;
#endif

            status = DIGI_MALLOC(
                (void **) &pSignedData, (2 * SSL_RANDOMSIZE) + dataLen);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(
                pSignedData, pSSLSock->pClientRandHello,
                SSL_RANDOMSIZE);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(
                pSignedData + SSL_RANDOMSIZE, pSSLSock->pServerRandHello,
                SSL_RANDOMSIZE);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(
                pSignedData + (2 * SSL_RANDOMSIZE), pMesg, dataLen);
            if (OK != status)
            {
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_PSS_AUTO_RECOVER__)
            saltLen = -1;
#endif

            /* Verify the signature. Regardless of the return status exit out.
             */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify(MOC_RSA(pSSLSock->hwAccelCookie)
                pSSLSock->handshakeKey.key.pRSA, hashId, MOC_PKCS1_ALG_MGF1,
                hashId, pSignedData, (2 * SSL_RANDOMSIZE) + dataLen,
                pMesg + msgLen - sigLen, sigLen, (sbyte4) saltLen, &isValid);
            if ( (OK == status) && (0 != isValid) )
            {
                status = ERR_RSA_BAD_SIGNATURE;
            }
#else
            status = PKCS1_rsassaPssVerify(MOC_RSA(pSSLSock->hwAccelCookie)
                pSSLSock->handshakeKey.key.pRSA,
                hashId, PKCS1_MGF1_FUNC, pSignedData, (2 * SSL_RANDOMSIZE) + dataLen,
                pMesg + msgLen - sigLen, sigLen, (sbyte4) saltLen, &isValid);
            if ( (OK == status) && (FALSE == isValid) )
            {
                status = ERR_RSA_BAD_SIGNATURE;
            }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
            goto exit;
        }
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_PKCS1__ */

    }

    /* key type should have been verified before calling this function */
    pRSAKey = pSSLSock->handshakeKey.key.pRSA;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, (sbyte4 *)&cipherLen, pSSLSock->handshakeKey.type)))
        {
            goto exit;
        }
#else
    if (OK > ( status = RSA_getCipherTextLength(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey, (sbyte4*) &cipherLen)))
        goto exit;
#endif

    if (cipherLen != sigLen)
    {
        status = ERR_SSL_INVALID_SIGNATURE;
        goto exit;
    }

    /* verify signature matches */
    if (NULL == (pDecrypt = (ubyte*) MALLOC(cipherLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* decrypt the signature which is at pMesg + dataLen + 2 */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                            pMesg + msgLen - sigLen, pDecrypt,
                                            (ubyte4*) &cipherLen, ppVlongQueue,
                                            pSSLSock->handshakeKey.type)))
#else
    if (OK > (status = RSA_verifySignature(MOC_RSA(pSSLSock->hwAccelCookie) pRSAKey,
                                            pMesg + msgLen - sigLen, pDecrypt,
                                            (ubyte4*) &cipherLen, ppVlongQueue)))
#endif
    {
        goto exit;
    }

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        MD5_CTX*    pMd5Context = NULL;
        SHA1_CTX*   pShaContext = NULL;

        hashLen = MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE;

        if (hashLen != cipherLen)
        {
            status = ERR_SSL_INVALID_SIGNATURE;
            goto exit;
        }

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Context))))
            goto exit;

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext))))
            goto exit;

        DIGI_MEMSET((ubyte *)pMd5Context, 0, sizeof(MD5_CTXHS));
        DIGI_MEMSET((ubyte *)pShaContext, 0, sizeof(shaDescrHS));

        /* compute the hash of the data */
        if (OK > (status = MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context)))
            goto exit1;

        if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit1;

        if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit1;

        if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pMesg, dataLen)))
            goto exit1;

        if (OK > (status = MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Context, pHashResult)))
            goto exit1;

        if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext)))
            goto exit1;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit1;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit1;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pMesg, dataLen)))
            goto exit1;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pHashResult + MD5_DIGESTSIZE )))
            goto exit1;
exit1:
        if (pMd5Context)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_freeCloneHashCtx(pMd5Context);
#endif
            MEM_POOL_putPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Context));
        }
        if (pShaContext)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_freeCloneHashCtx(pShaContext);
#endif
            MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext));
        }
    } else
    {
        /* For TLS1.2, the hash algo comes from the sigAlgo ubyte2 before the signature */
        sigAlgo = getShortValue( pMesg + dataLen);

        if (OK > (status = calculateTLS12KeyExchangeRSASignature(pSSLSock, pMesg, dataLen,
                                                            sigAlgo, pHashResult, &hashLen)))
            goto exit;
    }

    DIGI_CTIME_MATCH(pDecrypt, pHashResult, hashLen, &cmpRes);

    status = (0 == cmpRes) ? OK : ERR_SSL_INVALID_SIGNATURE;

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_PKCS1__)
    if (pSignedData)
    {
        DIGI_FREE((void **) &pSignedData);
    }
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_PKCS1__ */

    if (pDecrypt)
    {
        FREE( pDecrypt);
    }

    return status;
}
#endif /* ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))) */

#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__)))
static MSTATUS
verifyServerKeyExchangeDSASignature(SSLSocket* pSSLSock, ubyte* pMesg,
                                    ubyte2 msgLen, ubyte2 dataLen,
                                    vlong** ppVlongQueue)
{
    ubyte*      pHashResult = NULL;
    ubyte2      sigLen;
    DSAKey*     pDSAKey = NULL;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    struct MDsaKeyTemplate dsaParameters = {0};
    ubyte4      lenDsaQ = 0;
#endif
    MSTATUS     status;
    ubyte4      hashLen = 0;
    ubyte*      pSig = 0;
    ubyte       *strR = 0, *strS = 0;
    vlong*      pVlongQueue = NULL;
    vlong*  	pM = NULL;
    vlong*  	pR = NULL;
    vlong*  	pS = NULL;
    intBoolean  isGoodSignature;
    ubyte	lenR, lenS;
    intBoolean  isTLSorDTLS12 = FALSE;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

    /* verify signature length */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        sigLen = getShortValue( pMesg + dataLen);
        /* total msg len = 2 + sigLen + dataLen */
        if ( sigLen + 2 + dataLen != msgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
	pSig = pMesg+dataLen+2;
	isTLSorDTLS12 = FALSE;
    }
    else
    {
        /* TLS1.2 is sigAlgo+signature */
        sigLen = getShortValue( pMesg + dataLen + 2);
        /* total msg len = 2 + 2+ sigLen + dataLen */
        if ( sigLen + 2 + 2 + dataLen != msgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
	pSig = pMesg+dataLen+2+2;
	isTLSorDTLS12 = TRUE;
    }

    /* key type should have been verified before calling this function */
    pDSAKey = pSSLSock->handshakeKey.key.pDSA;
    /* Parse DER encoding */
    if ((pSig[0] != 0x30) || (pSig + 2 + pSig[1] > pMesg + msgLen) || pSig[2] != 0x2) {
      status = ERR_SSL_INVALID_MSG_SIZE;
      goto exit;
    }
    lenR = pSig[3];
    if (pSig + 2 + 2 + lenR > (pMesg + msgLen)) {
      status = ERR_SSL_INVALID_MSG_SIZE;
      goto exit;
    }
    strR = pSig+4;
    if (pSig[4+lenR] != 0x2) {
      status = ERR_SSL_INVALID_MSG_SIZE;
      goto exit;
    }
    lenS = pSig[4 + lenR + 1];
    if ((strR + lenR + 2 + lenS) > (pMesg + msgLen)) {
      status = ERR_SSL_INVALID_MSG_SIZE;
      goto exit;
    }
    strS = strR + lenR + 2;
    if (0x0 == strR[0]) {
      ++strR;
      --lenR;
    }
    if (0x0 == strS[0]) {
      ++strS;
      --lenS;
    }
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = VLONG_vlongFromByteString(strR, lenR, &pR, &pVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_vlongFromByteString(strS, lenS, &pS, &pVlongQueue)))
        goto exit;
#endif

    if (isTLSorDTLS12) {
	ubyte2  signatureAlgo;
	ubyte4	i;
	hashSuite  *pHashSuite = NULL;
	BulkCtx     pHashCtx = NULL;

        signatureAlgo = getShortValue( pMesg + dataLen);
	for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++) {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
        if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
        {
            if (gSupportedHashAlgorithms[i].hashType == ((signatureAlgo >> 8) & 0xff)) {
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

	if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pMesg, dataLen)))
	    goto exit;

	if (OK > (status = pHashSuite->algo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pHashResult)))
	    goto exit;
	if (pHashCtx)
	    status = pHashSuite->algo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
    } else {
        SHA1_CTX*   pShaContext = NULL;
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext))))
            goto exit;

        DIGI_MEMSET((ubyte *)pShaContext, 0, sizeof(shaDescrHS));

        if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pMesg, dataLen)))
            goto exit;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pHashResult)))
            goto exit;

        hashLen = SHA_HASH_RESULT_SIZE;
        if (pShaContext)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_freeCloneHashCtx(pShaContext);
#endif
            MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext));
        }
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(pDSAKey, &dsaParameters, MOC_GET_PUBLIC_KEY_DATA)))
    {
        goto exit;
    }

    lenDsaQ = dsaParameters.qLen;
    if (lenDsaQ < hashLen)
    {
        hashLen = lenDsaQ;
    }

    if (OK > (status = CRYPTO_INTERFACE_DSA_verifySignatureAux(MOC_DSA(hwAccelDescr hwAccelCtx) pDSAKey,
                                              pHashResult, hashLen,
                                              strR, lenR, strS, lenS,
                                              &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = VLONG_vlongFromByteString(pHashResult, hashLen, &pM, &pVlongQueue)))
	goto exit;

    if (OK > (status = DSA_verifySignature(MOC_DSA(hwAccelDescr hwAccelCtx) pDSAKey,
					   pM, pR, pS, &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }
#endif

    status = (isGoodSignature) ? OK : ERR_SSL_INVALID_SIGNATURE;

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    DSA_freeKeyTemplate(pDSAKey, &dsaParameters);
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
    VLONG_freeVlongQueue( &pVlongQueue);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))
static MSTATUS
verifyServerKeyExchangeECDSASignature(SSLSocket* pSSLSock, ubyte* pMesg,
                                    ubyte2 msgLen, ubyte2 dataLen)
{
    ubyte*          pHashResult = NULL;
    SHA1_CTX*       pShaContext = NULL;
    BulkCtx         pHashCtx = NULL;
    hashSuite       *pHashSuite = NULL;
    ubyte4          hashLen;
    ubyte2          sigLen;
    ubyte4          offset;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pRootItem = 0;
    MSTATUS         status;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        hashLen = SHA1_RESULT_SIZE;
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext))))
            goto exit;

        DIGI_MEMSET((ubyte *)pShaContext, 0, sizeof(shaDescrHS));

        /* compute the hash of the data */
        if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pMesg, dataLen)))
            goto exit;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaContext, pHashResult)))
            goto exit;

    }
    else
    {
        /* For TLS1.2, the hash algo comes from the sigAlgo ubyte2 before the signature */
        ubyte2  sigAlgo;
        ubyte4 i;
        sigAlgo = getShortValue( pMesg + dataLen);

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

        if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pMesg, dataLen)))
            goto exit;

        if (OK > (status = pHashSuite->algo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pHashResult )))
            goto exit;

        if (OK > ( status = pHashSuite->algo->freeFunc( MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx )))
            goto exit;
    }

    /* parse the ASN.1 embedded in the message after the ECDHE params */
    /* verify signature length */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        sigLen = getShortValue( pMesg + dataLen);
        offset = 2 + dataLen;
        /* total msg len = 2 + sigLen + dataLen */
        if ( sigLen + 2 + dataLen != msgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
    }
    else
    {
        /* TLS1.2 has signatureAndHashAlgorigthm before the signature */
        sigLen = getShortValue( pMesg + dataLen+2);
        offset =  2 + 2 + dataLen;
        /* total msg len = 2 + sigLen + dataLen */
        if ( sigLen + 2 + 2 + dataLen != msgLen)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }
    }
    MF_attach( &mf, sigLen, pMesg + offset);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pRootItem)))
        goto exit;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > ( status = X509_verifyECDSASignatureEx(MOC_ECC(pSSLSock->hwAccelCookie) ASN1_FIRST_CHILD( pRootItem), cs,
                                                    pSSLSock->handshakeKey.key.pECC,
                                                    hashLen, pHashResult,
                                                    pSSLSock->handshakeKey.type)))
#else
    /* key type should have been verified before calling this function*/
    if (OK > ( status = X509_verifyECDSASignature(MOC_ECC(pSSLSock->hwAccelCookie) ASN1_FIRST_CHILD( pRootItem), cs,
                                                    pSSLSock->handshakeKey.key.pECC,
                                                    hashLen, pHashResult)))
#endif
    {
        goto exit;
    }

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));
    if (pSSLSock->isDTLS || pSSLSock->sslMinorVersion < TLS12_MINORVERSION)
    {
        if (pShaContext)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_freeCloneHashCtx(pShaContext);
#endif
            MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaContext));
        }
    }
    else
    {
        if (pHashCtx)
            pHashSuite->algo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
    }

    if ( pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS
processServerKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    /* Diffie-Hellman Ephemeral support */
    ubyte*      pParams = pMesg;
    ubyte*      pTemp;
    ubyte4      lenBigInt;
    ubyte4      lenTotal, paramLen;
    vlong*      pVlongQueue = NULL;
    MSTATUS     status;
    ubyte4      privKeyLen;
    intBoolean  isValid = FALSE;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MDhKeyTemplate template = {0};
#endif


    /* basic check for length -- previous check was incorrect --
    check only for the fields we are going to use now */
    if (mesgLen < 5) /* 2 2-byte length fields */
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    if (NULL != pSSLSock->pDHcontext)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContextExt(&(pSSLSock->pDHcontext), &pVlongQueue, NULL);
#else
        DH_freeDhContext(&pSSLSock->pDHcontext, &pVlongQueue);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    }


#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_allocateExt(&(pSSLSock->pDHcontext), NULL);
    if (OK != status)
        goto exit;
#else
    if (OK > (status = DH_allocateClient(MOC_DH(pSSLSock->hwAccelCookie)
                                         pSSLSock->rngFunArg,
                                         &(pSSLSock->pDHcontext),
                                         DH_GROUP_TBD)))
    {
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    pTemp = pParams;

    /* extract length of p */
    lenBigInt = getShortValue(pTemp);
    pTemp += 2;
    lenTotal = (2 + lenBigInt);

    if (lenTotal > mesgLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* extract p */
    
    /* check that the DH key is of sufficient size */
    status = ERR_SSL_DH_KEY_SIZE;
    if (lenBigInt > MAX_SSL_DH_SIZE/8)
    {
        goto exit;
    }
    else if (lenBigInt < (SSL_sslSettings()->minDHKeySize + 7)/8)
    {
        goto exit;
    }
    else
    {
        /* get the actual bit legnth, begin with it in bytes */
        ubyte4 actualLen = lenBigInt;
        ubyte4 i = 0;

        while (i < lenBigInt && 0x00 == pTemp[i])
        {
            i++;
            actualLen--;
        }

        if (i == lenBigInt)   /* prime is all 0x00 bytes */
        {
            goto exit; 
        }

        /* Now convert actual Len to bits */
        actualLen = ((actualLen - 1) * 8) + DIGI_BITLENGTH((ubyte4) pTemp[i]);
        if ( actualLen < SSL_sslSettings()->minDHKeySize)
        {
            goto exit; 
        }
    }

    status = OK;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    template.pP = pTemp;
    template.pLen = lenBigInt;
#else
    if (OK > (status = VLONG_vlongFromByteString(pTemp, lenBigInt,
                                                 &(pSSLSock->pDHcontext->dh_p),
                                                 &pVlongQueue)))
    {
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    /* extract length of g */
    pTemp += lenBigInt;
    lenBigInt = getShortValue(pTemp);
    pTemp += 2;
    lenTotal += (2 + lenBigInt);

    if (lenTotal > mesgLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* extract g */
    
    /* sanity check that g is not too large */
    if (lenBigInt > MAX_SSL_DH_SIZE/8)
    {
        status = ERR_SSL_DH_KEY_SIZE;
        goto exit;        
    }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    template.pG = pTemp;
    template.gLen = lenBigInt;
#else
    if (OK > (status = VLONG_vlongFromByteString(pTemp, lenBigInt,
                                                 &(pSSLSock->pDHcontext->dh_g),
                                                 &pVlongQueue)))
    {
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__*/

    /* extract length of Ys */
    pTemp += lenBigInt;
    lenBigInt = getShortValue(pTemp);
    pTemp += 2;
    lenTotal += (2 + lenBigInt);
    paramLen = lenTotal;

    if (lenTotal > mesgLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* extract Ys */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = DIGI_MALLOC((void**)&(pSSLSock->pRemotePublicKey), lenBigInt);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pSSLSock->pRemotePublicKey, pTemp, lenBigInt);
    if (OK != status)
        goto exit;
    pSSLSock->remotePublicKeyLength = lenBigInt;

#else
    if (OK > (status = VLONG_vlongFromByteString(pTemp, lenBigInt,
                                                 &(pSSLSock->pDHcontext->dh_e),
                                                 &pVlongQueue)))
    {
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    /* set template values to the DH context we created */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
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

    status = CRYPTO_INTERFACE_DH_generateKeyPairExt(MOC_DH(pSSLSock->hwAccelCookie) pSSLSock->pDHcontext, g_pRandomContext, privKeyLen, NULL);
    if (OK != status)
        goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
    if (SSL_DH_ANON == pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
    {
        if (lenTotal != (ubyte4)mesgLen)
        {
            /* record length should match what we found */
            /* and the signature should not be longer than the prime used */
            status = ERR_SSL_INVALID_MSG_SIZE;
        }
        goto exit;
    }
#endif

    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT)
    {
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
        if (akt_rsa != pSSLSock->handshakeKey.type)
        {
            status = ERR_SSL_INVALID_KEY_TYPE;
            goto exit;
        }

        if (OK > ( status = verifyServerKeyExchangeRSASignature( pSSLSock, pMesg, mesgLen,
                                                                (ubyte2) paramLen, &pVlongQueue)))
        {
            /* RFC 5246 7.2.2.  Error Alerts
             *
             *   decrypt_error
             *      A handshake cryptographic operation failed, including being unable
             *      to correctly verify a signature or validate a Finished message.
             *      This message is always fatal.
             */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE,
                    SSL_ALERT_DECRYPT_ERROR,
                    SSLALERTLEVEL_FATAL);
#endif
            goto exit;
        }
#else
        status = ERR_RSA_DISABLED;
#endif
    }

    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_DSA_BIT)
    {
#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
        if ((akt_dsa != pSSLSock->handshakeKey.type) || (FALSE == SSL_sslSettings()->allowDSASigAlg))
        {
            status = ERR_SSL_INVALID_KEY_TYPE;
            goto exit;
        }

        if (OK > ( status = verifyServerKeyExchangeDSASignature( pSSLSock, pMesg, mesgLen,
                                                                (ubyte2) paramLen, &pVlongQueue)))
        {
            /* RFC 5246 7.2.2.  Error Alerts
             *
             *   decrypt_error
             *      A handshake cryptographic operation failed, including being unable
             *      to correctly verify a signature or validate a Finished message.
             *      This message is always fatal.
             */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE,
                    SSL_ALERT_DECRYPT_ERROR,
                    SSLALERTLEVEL_FATAL);
#endif
            goto exit;
        }
#else
        status = ERR_CRYPTO_DSA_DISABLED;
#endif
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, "processServerKeyExchange() returns status = ", status);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        DIGI_FREE((void**)&(pSSLSock->pRemotePublicKey));
#endif
    }

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* processServerKeyExchange */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
static MSTATUS
processServerEcdheKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    /* Elliptic Curve Diffie-Hellman Ephemeral support */
    MSTATUS     status;
    ubyte2      curve;
    ubyte       i = 0;
    ubyte       length = 0;

    if (mesgLen < 5)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    if (pSSLSock->isDTLS || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
    {
        /* first byte should be tlsECCurveType_named_curve */
        if (pMesg[i] != tlsECCurveType_named_curve)
        {
            status = ERR_SSL_UNSUPPORTED_CURVE;
            goto exit;
        }
        i++;
    }

    /* initialize the ephemeral key */
    curve = getShortValue( pMesg + i);
    i += 2; /* Named Curve /Group */

    /* extract the key information */
    length = pMesg[i];
    i += 1; /* Length */

    if (length + 4 > mesgLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
    /* verify that the curve is one of the authorized one */
    if ( 0 == (( 1 << curve) & pSSLSock->supportedGroups) )
    {
        status = ERR_SSL_UNSUPPORTED_CURVE;
        goto exit;
    }
#endif

    if (OK > ( status = CRYPTO_setECCParameters(MOC_ECC(pSSLSock->hwAccelCookie) &pSSLSock->ecdheKey,
                                SSL_getCurveIdOfNamedCurve( curve),
                                pMesg + i, length, NULL, 0)))
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
    if (SSL_AUTH_ANON_BIT & pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags)
    {
        if (length + 4 != mesgLen)
        {
            /* record length should consist only of the key information */
            status = ERR_SSL_INVALID_MSG_SIZE;
        }
        goto exit;
    }
#endif /* defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) */

#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)
    /* verify the signature */
    switch ( pSSLSock->handshakeKey.type)
    {
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
        case akt_rsa:
            if (OK > (status = verifyServerKeyExchangeRSASignature( pSSLSock, pMesg, mesgLen,
                                                                    4 + length, NULL)))
            {
                /* RFC 5246 7.2.2.  Error Alerts
                 *
                 *   decrypt_error
                 *      A handshake cryptographic operation failed, including being unable
                 *      to correctly verify a signature or validate a Finished message.
                 *      This message is always fatal.
                 */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, FALSE,
                        SSL_ALERT_DECRYPT_ERROR,
                        SSLALERTLEVEL_FATAL);
#endif
                goto exit;
            }
            break;
#endif
        case akt_ecc_ed:
        case akt_ecc:
            if (OK > ( status = verifyServerKeyExchangeECDSASignature(pSSLSock, pMesg, mesgLen,
                                                                    4 + length)))
            {
                /* RFC 5246 7.2.2.  Error Alerts
                 *
                 *   decrypt_error
                 *      A handshake cryptographic operation failed, including being unable
                 *      to correctly verify a signature or validate a Finished message.
                 *      This message is always fatal.
                 */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, FALSE,
                        SSL_ALERT_DECRYPT_ERROR,
                        SSLALERTLEVEL_FATAL);
#endif
                goto exit;
            }
            break;

        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
            break;
    }
#endif /* defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) */

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, "processServerEcdheKeyExchange() returns status = ", status);

    return status;

} /* processEcdheServerKeyExchange */

#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))

static MSTATUS
processServerDiffieHellmanPskKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    ubyte4      pskHintLength;
    MSTATUS     status = ERR_SSL_PSK_BAD_LENGTH;

    /* basic quick check */
    if (2 > mesgLen)
        goto exit;

    /* extract identity hint */
    pskHintLength = getShortValue(pMesg);
    pMesg += 2;
    mesgLen = (ubyte2)(mesgLen - 2);

    /* another quick check */
    if (pskHintLength >= mesgLen)
        goto exit;

    status = ERR_SSL_PSK_BAD_CONFIG;

    /* fill the psk with random garbage, in case the callback does the wrong thing */
    pSSLSock->roleSpecificInfo.client.pskLength = SSL_PSK_MAX_LENGTH;
    pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_PSK_MAX_LENGTH, pSSLSock->roleSpecificInfo.client.psk);

    if (NULL != SSL_sslSettings()->funcPtrChoosePSK)
    {
        status = (MSTATUS) SSL_sslSettings()->funcPtrChoosePSK(SSL_findConnectionInstance(pSSLSock), pMesg, pskHintLength,
                                                    pSSLSock->roleSpecificInfo.client.pskIdentity, &(pSSLSock->roleSpecificInfo.client.pskIdentityLength),
                                                    pSSLSock->roleSpecificInfo.client.psk, &(pSSLSock->roleSpecificInfo.client.pskLength));
    }

    /* check if the callback overran our buffer */
    if ((OK <= status) &&
        ((SSL_PSK_SERVER_IDENTITY_LENGTH < pSSLSock->roleSpecificInfo.client.pskIdentityLength) ||
         (SSL_PSK_MAX_LENGTH             < pSSLSock->roleSpecificInfo.client.pskLength)) )
    {
        /* heap space may have been corrupted by the callback handler! */
        status = ERR_SSL_PSK_CALLBACK_OVERFLOW_BUF;
    }

    if (OK > status)
        goto exit;

    /* continue processing the message */
    pMesg   += pskHintLength;
    mesgLen  = (ubyte2)(mesgLen - pskHintLength);

    status = processServerKeyExchange(pSSLSock, pMesg, mesgLen);

exit:
    return status;
}

#endif /* ((defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */




/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))

static MSTATUS
processServerEcdhePskKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    ubyte4      pskHintLength;
    MSTATUS     status = ERR_SSL_PSK_BAD_LENGTH;

    /* basic quick check */
    if (2 > mesgLen)
        goto exit;

    /* extract identity hint */
    pskHintLength = getShortValue(pMesg);
    pMesg += 2;
    mesgLen = (ubyte2)(mesgLen - 2);

    /* another quick check */
    if (pskHintLength >= mesgLen)
        goto exit;

    status = ERR_SSL_PSK_BAD_CONFIG;

    /* fill the psk with random garbage, in case the callback does the wrong thing */
    pSSLSock->roleSpecificInfo.client.pskLength = SSL_PSK_MAX_LENGTH;
    pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_PSK_MAX_LENGTH, pSSLSock->roleSpecificInfo.client.psk);

    if (NULL != SSL_sslSettings()->funcPtrChoosePSK)
    {
        status = (MSTATUS) SSL_sslSettings()->funcPtrChoosePSK(SSL_findConnectionInstance(pSSLSock), pMesg, pskHintLength,
                                                     pSSLSock->roleSpecificInfo.client.pskIdentity, &(pSSLSock->roleSpecificInfo.client.pskIdentityLength),
                                                     pSSLSock->roleSpecificInfo.client.psk, &(pSSLSock->roleSpecificInfo.client.pskLength));
    }

    /* check if the callback overran our buffer */
    if ((OK <= status) &&
        ((SSL_PSK_SERVER_IDENTITY_LENGTH < pSSLSock->roleSpecificInfo.client.pskIdentityLength) ||
         (SSL_PSK_MAX_LENGTH             < pSSLSock->roleSpecificInfo.client.pskLength)) )
    {
        /* heap space may have been corrupted by the callback handler! */
        status = ERR_SSL_PSK_CALLBACK_OVERFLOW_BUF;
    }

    if (OK > status)
        goto exit;

    /* continue processing the message */
    pMesg   += pskHintLength;
    mesgLen  = (ubyte2)(mesgLen - pskHintLength);

    status = processServerEcdheKeyExchange(pSSLSock, pMesg, mesgLen);

exit:
    return status;
}

#endif /* ((defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__))

static MSTATUS
processServerPskKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    /* for RSA_PSK and PSK ciphers suites */
    ubyte4      pskHintLength;
    MSTATUS     status = ERR_SSL_PSK_BAD_LENGTH;

    /* IOT-563: there can be no KeyExchange message if the server does
     not send any hint. in that case that function is called with
     a zero length message */

    if ( 0 == mesgLen)
    {
        pskHintLength = 0;
    }
    else
    {
        /* basic quick check */
        if (2 > mesgLen)
            goto exit;

        /* extract identity hint */
        pskHintLength = getShortValue(pMesg);
        pMesg += 2;
        mesgLen = (ubyte2)(mesgLen - 2);

        /* another quick check */
        if (pskHintLength != mesgLen)
            goto exit;
    }

    status = ERR_SSL_PSK_BAD_CONFIG;

    /* in the event the callback does something improper, we fill the psk with random garbage */
    pSSLSock->roleSpecificInfo.client.pskLength = SSL_PSK_MAX_LENGTH;
    pSSLSock->rngFun(pSSLSock->rngFunArg, SSL_PSK_MAX_LENGTH, pSSLSock->roleSpecificInfo.client.psk);

    if (NULL != SSL_sslSettings()->funcPtrChoosePSK)
    {
        status = (MSTATUS) SSL_sslSettings()->funcPtrChoosePSK(SSL_findConnectionInstance(pSSLSock), pMesg, pskHintLength,
                                                    pSSLSock->roleSpecificInfo.client.pskIdentity, &(pSSLSock->roleSpecificInfo.client.pskIdentityLength),
                                                    pSSLSock->roleSpecificInfo.client.psk, &(pSSLSock->roleSpecificInfo.client.pskLength));
    }

    /* check if the callback overran our buffer */
    if ((OK <= status) &&
        ((SSL_PSK_SERVER_IDENTITY_LENGTH < pSSLSock->roleSpecificInfo.client.pskIdentityLength) ||
         (SSL_PSK_MAX_LENGTH             < pSSLSock->roleSpecificInfo.client.pskLength)) )
    {
        /* heap space may have been corrupted by the callback handler! */
        status = ERR_SSL_PSK_CALLBACK_OVERFLOW_BUF;
    }

exit:
    return status;
}

#endif /* (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)) */

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
extern MSTATUS
processTLSSessionTicket(SSLSocket *pSSLSock, ubyte *pMsg, ubyte2 msgLen)
{
    MSTATUS status = OK;
    ubyte4  sizeofHandshakeHeader;
    sessionTicket ticket = {0};

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    if(msgLen <= 8)
    {
        status = ERR_SSL;
        goto exit;
    }

    pMsg   += sizeofHandshakeHeader;

    ticket.cipherId = pSSLSock->pHandshakeCipherSuite->cipherSuiteId;
    DIGI_MEMCPY(ticket.masterSecret, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

    status = RTOS_timeGMT(&(ticket.startTime));
    if (OK != status)
    {
        goto exit;
    }

    ticket.lifeTimeHintInSec = (ubyte4)(((ubyte4)pMsg[0] << 24) | (ubyte4)(pMsg[1] << 16) | (ubyte4)(pMsg[2] << 8) | (ubyte4)pMsg[3]);
    pMsg += 4; /* Life time hint is a unint32 */
    msgLen = msgLen - 4;

    ticket.ticketLen = getShortValue(pMsg);
    pMsg += 2;
    msgLen -= 2;

    if (ticket.ticketLen > msgLen)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }

    /* RFC 5077, Section 3.3
     * If the server determines that it does not want to include a
     * ticket after it has included the SessionTicket extension in the
     * ServerHello, then it sends a zero-length ticket in the
     * NewSessionTicket handshake message.
     */
    if (0 == ticket.ticketLen)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }

    ticket.pTicket = pMsg;

    if (NULL != pSSLSock->funcPtrSSLClientSaveTicketCallback)
    {
        ubyte4 serverNameLen = 0;
        ubyte *pTicket = NULL;
        ubyte4 ticketLen = 0;

        status = SSLSOCK_serializeSessionTicket(&ticket, &pTicket, &ticketLen);
        if (OK != status)
        {
            goto exit;
        }

        if (pSSLSock->serverNameIndication)
        {
            serverNameLen = DIGI_STRLEN((sbyte*)pSSLSock->serverNameIndication);
        }

        status = pSSLSock->funcPtrSSLClientSaveTicketCallback(SSL_findConnectionInstance(pSSLSock),
                                                              pSSLSock->serverNameIndication, serverNameLen,
                                                              NULL, pTicket, ticketLen);
        DIGI_FREE((void **)&pTicket);
    }

exit:
    return status;
}
#endif

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
/* This function extracts ticket_lifetime_hint, ticket add age and ticket from the NewSessionTicket message,
 * and store the values for future use.
 * */
extern MSTATUS
processNewSessionTicket(SSLSocket *pSSLSock, ubyte *pMsg, ubyte2 msgLen)
{
    ubyte4      hint;
    ubyte4      addAge;
    tls13PSK    ticket = {0};
    ubyte4  sizeofHandshakeHeader;
    ubyte4 extensionsLen = 0;
    ubyte4 nonceLen = 0;
    ubyte* pPSK = NULL;
    ubyte4 pskLength = 0;
    MSTATUS status = OK;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } 
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    /* msgLen check not required before incrementing pointer */
    pMsg += sizeofHandshakeHeader;

    /* This checks for lifetime Hint (4), Age(4) and 1 byte for nonce;
     * This (4 + 4 + x) <= 8 evaluates to false, where x is atleast 1
     */
    if (msgLen <= 8)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }

    hint = (ubyte4)(((ubyte4)pMsg[0] << 24) | (ubyte4)(pMsg[1] << 16) | (ubyte4)(pMsg[2] << 8) | (ubyte4)pMsg[3]);
    pMsg += 4; /* LifetimeHint is a unint32 */
    msgLen = msgLen - 4;

    addAge = (ubyte4)(((ubyte4)pMsg[0] << 24) | (ubyte4)(pMsg[1] << 16) | (ubyte4)(pMsg[2] << 8) | (ubyte4)pMsg[3]);
    pMsg += 4; /* AgeAdd is a unint32 */
    msgLen = msgLen - 4;

    ticket.isExternal     = 0;
    ticket.isPSKavailable = 1;

    /* Rest of the message contains nonce, ticket and any extensions if present. So copy it */
    ticket.pskTLS13LifetimeHint = hint;
    ticket.pskTLS13AgeAdd       = addAge;

    /* Nonce Length */
    nonceLen = (ubyte4)*pMsg;
    msgLen -= 1;
    pMsg++;

    /* Nonce */
    if (nonceLen > msgLen || nonceLen > SSL_SESSION_TICKET_NONCE_SIZE)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }

    DIGI_MEMCPY(ticket.ticketNonce, pMsg, nonceLen);
    pMsg   += nonceLen;
    msgLen -= nonceLen;

    /* ticket */
    if (2 > msgLen)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }
    ticket.pskTLS13IdentityLength = getShortValue(pMsg);
    pMsg   += 2;
    msgLen -= 2;

    if (OK > (status = DIGI_MALLOC((void **)&ticket.pskTLS13Identity, ticket.pskTLS13IdentityLength)))
    {
        goto exit;
    }

    if (ticket.pskTLS13IdentityLength > msgLen)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }

    if (OK > (status = SSLSOCK_generatePSKFromTicket(pSSLSock, ticket.ticketNonce, nonceLen,
                                                     pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
                                                     pSSLSock->pResumptionMasterSecret,
                                                     &pPSK, &pskLength)))
    {
        goto exit;
    }

    /* PSK length check */
    if (pskLength > SSL_PSK_TLS13_MAX_LENGTH)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }

    ticket.pskTLS13Length = pskLength;
    DIGI_MEMCPY(ticket.pskTLS13, pPSK, ticket.pskTLS13Length);
    DIGI_MEMCPY(ticket.pskTLS13Identity, pMsg, ticket.pskTLS13IdentityLength);
    pMsg   += ticket.pskTLS13IdentityLength;
    msgLen -= ticket.pskTLS13IdentityLength;

    /*Extension */
    if (2 > msgLen)
    {
        status = ERR_SSL_PSK_BAD_LENGTH;
        goto exit;
    }
    extensionsLen = getShortValue(pMsg);
    pMsg += 2;
    msgLen = msgLen - 2;

    if (extensionsLen > 0)
    {
        if (OK > (status = processHelloExtensions(pSSLSock, pMsg, extensionsLen, SSL_NEW_SESSION_TICKET)))
            goto exit;

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined( __ENABLE_DIGICERT_TLS13_0RTT__))
        ticket.maxEarlyDataSize = pSSLSock->maxEarlyDataSize;
#endif
    }

    ticket.isExternal           = FALSE;
    ticket.selectedCipherSuiteId = pSSLSock->pHandshakeCipherSuite->cipherSuiteId;

    ticket.hashAlgo = getHashIdFromSuite(pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo);

    if (0 == ticket.hashAlgo)
    {
        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
        goto exit;
    }

    /* Store the time at which the ticket was recieved.
     */
    status = RTOS_timeGMT(&(ticket.startTime));
    if (OK != status)
    {
        goto exit;
    }

    ticket.pSelectedTlsVersion = (SSL3_MAJORVERSION << 8 | pSSLSock->sslMinorVersion);

    pSSLSock->roleSpecificInfo.client.numOfTLS13PSK++;

    /* RFC 8446 Section 4.6.1
     *
     * "Servers MUST NOT use any value greater than 604800 seconds (7 days).
     * The value of zero indicates that the ticket should be discarded
     * immediately. Clients MUST NOT cache tickets for longer than 7 days"
     *
     * If the ticket lifetime is zero or if the lifetime exceeds the maximum
     * allowed lifetime then don't invoke the callback to save the PSK.
     *
     * Only attempt to save the PSK if the client has requested a ticket.
     */
    if ( (NULL != pSSLSock->funcPtrSSLClientSavePSKCallback) &&
         (0 != ticket.pskTLS13LifetimeHint) &&
         (TICKET_LIFETIME_ONE_WEEK >= ticket.pskTLS13LifetimeHint) &&
         (pSSLSock->roleSpecificInfo.client.requestSessionTicket == 1) )
    {
        ubyte4 serverNameLen = 0;
        ubyte *pPskData = NULL;
        ubyte4 pskDataLen;

        status = SSLSOCK_tls13SerializePsk(
            &ticket, &pPskData, &pskDataLen);
        if (OK != status)
        {
            goto exit;
        }

        if (pSSLSock->serverNameIndication)
        {
            serverNameLen = DIGI_STRLEN((sbyte*)pSSLSock->serverNameIndication);
        }

        status = pSSLSock->funcPtrSSLClientSavePSKCallback(SSL_findConnectionInstance(pSSLSock),
                                                           pSSLSock->serverNameIndication,
                                                           serverNameLen, NULL, pPskData, pskDataLen);
        DIGI_FREE((void **) &pPskData);
    }

    /* FOR DTLS we need to record the record so that we can later properly send an ACK */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (OK == status && pSSLSock->isDTLS)
    {
        status = addReceivedRecordNode(pSSLSock, kNewSessionTicket);
    }
#endif

exit:
    
    if (NULL != pPSK)
    {
        DIGI_FREE((void **) &pPSK);
    }
    if (NULL != ticket.pskTLS13Identity)
    {
        DIGI_FREE((void **) &ticket.pskTLS13Identity);
    }
    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
/*------------------------------------------------------------------*/

static MSTATUS
processServerSrpKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    MSTATUS status;
    ubyte4 lenBigInt;
    const ubyte* N;
    sbyte4 nLen;
    const ubyte* g;
    sbyte4 gLen;
    const ubyte* k;
    const ubyte* SB;
    sbyte4 SBLen;
    intBoolean differ;
    sbyte4 len = (sbyte4) mesgLen;
    ubyte* buff = pMesg;

    /* N (2), g (2), s(1), B(2)  */
    /*              |--sAndB-- | */
    /* basic check for length -- 7 bytes for length
      + 1 byte at least for each field */
    if (len < 11)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* extract length of N */
    lenBigInt = getShortValue(buff);
    buff += 2;
    len -= 2;

    if ((sbyte4) lenBigInt > len)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* verify this matches one of the N we support */
    if (OK > (status = SRP_getGroupParameters2(lenBigInt * 8, &N, &nLen, &g, &gLen, &k)))
    {
        status = ERR_SSL_SRP_INVALID_PARAMS;
        goto exit;
    }

    if ((sbyte4) lenBigInt != nLen || (DIGI_CTIME_MATCH(N, buff, nLen, &differ), differ))
    {
        status = ERR_SSL_SRP_INVALID_PARAMS;
        goto exit;
    }

    /* remember this value for use later in fillClientSRPKeyExchange */
    pSSLSock->srpNumBits = lenBigInt * 8;

    buff += lenBigInt;
    len -= lenBigInt;

    /* extract length of G */
    lenBigInt = getShortValue(buff);
    buff += 2;
    len -= 2;

    if ((sbyte4) lenBigInt > len)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    if ((sbyte4) lenBigInt != gLen || (DIGI_CTIME_MATCH(g, buff, gLen, &differ), differ))
    {
        status = ERR_SSL_SRP_INVALID_PARAMS;
        goto exit;
    }

    buff += lenBigInt;
    len -= lenBigInt;

    SB = buff;

    /* extract s */
    lenBigInt = *buff++;
    --len;

    SBLen = 1 + (sbyte4) lenBigInt;

    if ((sbyte4) lenBigInt > len)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    buff += lenBigInt;
    len -= (sbyte4) lenBigInt;

    /* finally B */
    lenBigInt = getShortValue(buff);
    buff += 2;
    len -= 2;

    SBLen += 2 + lenBigInt;

    if ((sbyte4) lenBigInt > len)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    /* let's reject B with leading zeroes or that
     are less than 256 bits */
    if (0 == *buff || lenBigInt < 32)
    {
        status = ERR_SSL_SRP_INVALID_PARAMS;
        goto exit;
    }

    /* adjust the length for possible RSA verifiy signature routine */
    len -= (sbyte4) lenBigInt;

    if (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT)
    {
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
        if (akt_rsa != pSSLSock->handshakeKey.type)
        {
            status = ERR_SSL_INVALID_KEY_TYPE;
            goto exit;
        }

        if (OK > ( status = verifyServerKeyExchangeRSASignature( pSSLSock, pMesg, mesgLen,
                                                                (ubyte2) (mesgLen - len),
                                                                0)))
        {
            /* RFC 5246 7.2.2.  Error Alerts
             *
             *   decrypt_error
             *      A handshake cryptographic operation failed, including being unable
             *      to correctly verify a signature or validate a Finished message.
             *      This message is always fatal.
             */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, FALSE,
                    SSL_ALERT_DECRYPT_ERROR,
                    SSLALERTLEVEL_FATAL);
#endif
            goto exit;
        }
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }

    /* just store the values for use by fillClientSRPKeyExchange */
    pSSLSock->roleSpecificInfo.client.srpSB = (ubyte*) MALLOC( SBLen);
    if (!pSSLSock->roleSpecificInfo.client.srpSB)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.srpSB, SB, SBLen);
    pSSLSock->roleSpecificInfo.client.srpSBLen = SBLen;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, "processServerSrpKeyExchange() returns status = ", status);

    return status;

} /* processServerSrpKeyExchange */

#endif /* (defined(__ENABLE_DIGICERT_SSL_SRP__)) */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

static MSTATUS
processCertificateStatus(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen)
{
    MSTATUS status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
    MSTATUS ocspValidationStatus = OK;

    ubyte2 statusType = 0;

    statusType = (ubyte)(*pMesg);

    pMesg ++;

    if (certStatusType_ocsp == statusType)
    {
        ubyte2 responseLen = getMediumValue(pMesg);
        pMesg += 3;

        if ((responseLen + 3) > mesgLen)
        {
            goto exit;
        }

        status = SSL_OCSP_validateOcspResponse(pSSLSock, pMesg,responseLen);

        /* Pass this validation status to application */
        ocspValidationStatus = status;

        /* Check for OCSP callback. Allow the callback to override the OCSP
         * return value.
         */
        if (NULL != SSL_sslSettings()->funcPtrSingleCertStatusCallback)
        {
            /* Create a copy of certificate and pass to callback or
             * passing a reference is good enough?
             */
            const ubyte *pCert = NULL;
            ubyte4 certLen = 0;

            /* Possible that the session was re-established and no
             * certificate was provided. This handling is only for TLS 1.2
             * and below, so there is no need to check for TLS 1.3 PSK.
             */
            if (NULL != pSSLSock->pCertChain)
            {
                status = CERTCHAIN_getCertificate(
                    pSSLSock->pCertChain, 0, &pCert, &certLen);
                if (OK != status)
                {
                    goto exit;
                }
            }

            status = (MSTATUS)SSL_sslSettings()->funcPtrSingleCertStatusCallback(
                SSL_findConnectionInstance(pSSLSock), pCert, certLen,
                pMesg, responseLen, ocspValidationStatus);
            if (OK > status)
            {
                goto exit;
            }
        }
    }
exit:
    return status;
}

#endif

/*------------------------------------------------------------------*/

static MSTATUS
handleClientHandshakeMessages(SSLSocket* pSSLSock)
{
    ubyte2  recordLen;
    sbyte*  pMsg    = pSSLSock->pReceiveBuffer;
#if defined(__ENABLE_DIGICERT_TLS13__)
    ubyte*  pTempMsg = NULL;
#endif

    ubyte4  sizeofHandshakeHeader;
    MSTATUS status  = OK;
    vlong*  pVlongQueue = NULL;

#if (defined(__ENABLE_DIGICERT_TLS13__) && (__ENABLE_DIGICERT_TLS13_PSK__))
    tls13PSKList *pTempPSKList = NULL;
#endif

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
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

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
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

                /* Allocate buffer to accommodate sizeofHandshakeHeader + handshakeRecLen
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

        status = ERR_SSL_PROTOCOL;

        switch (handshakeType)
        {
            case SSL_HELLO_REQUEST:
                /* we ignore hello request at this layer, upper layer makes sense of it */
                status = OK;
                break;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
            case SSL_SERVER_HELLO_VERIFY_REQUEST:
                if ((SSL_BEGIN == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                    (SSL_HELLO_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                    (SSL_SERVER_HELLO_VERIFY_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
                {
                    status = processServerHelloVerifyRequest(pSSLSock, (ubyte*)(pSHSH+sizeofHandshakeHeader), handshakeRecLen);
                }
                break;
#endif

            case SSL_SERVER_HELLO:
                if ((SSL_BEGIN == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                    (SSL_HELLO_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                    (SSL_SERVER_HELLO_VERIFY_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
#else
                    (SSL_HELLO_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
#endif
                {
                    status = processServerHello(pSSLSock, pSHSH, handshakeRecLen);

                    if (OK > status)
                        break;

#ifdef __ENABLE_DIGICERT_TLS13__
                 if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                      (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                 {
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
                        /* RFC: 4.2.11: "key_share" extension is present if required by the ClientHello
                         * "psk_key_exchange_modes" extension.
                         */
                        if ((1 == TLS13_CLIENT_GET_PSK_RX(pSSLSock)) &&
                            (pSSLSock->roleSpecificInfo.client.pskKeyExchangeMode == psk_dhe_ke))
                        {
                            if (1 != TLS13_CLIENT_GET_KEY_SHARE_RX(pSSLSock))
                            {
                                status = ERR_SSL_FATAL_ALERT;
    #ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                                SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                                        SSL_ALERT_ILLEGAL_PARAMETER,
                                        SSLALERTLEVEL_FATAL);
    #endif
                                break;
                            }
                        }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
                    }
#endif /* __ENABLE_DIGICERT_TLS13__ */
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                    /* In TLS13 0-RTT flow ClientHello is added to handshakeHash in SSL_SOCK_sendEarlyData() function itself.
                       For DTLS13 it still will be added here */
                    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) || 
                         pSSLSock->isDTLS || FALSE == pSSLSock->sendEarlyData)
#endif
                    {
#if defined(__ENABLE_DIGICERT_TLS13__)
                        /* since we haven't yet hashed the client hello, will do it now */
                        if (pSSLSock->helloRetryRequest)
                        {
                            /* helloRetryRequest requires a modified version of
                             * the clientHello to added to the handshake
                             * hash.
                             */
                            addHrrClientHelloToHandshakeHash(
                                pSSLSock,
                                pSSLSock->roleSpecificInfo.client.helloBuffer,
                                pSSLSock->roleSpecificInfo.client.helloBufferLen);
                        }
                        else
#endif
                        {
                            if (!pSSLSock->isDTLS || (pSSLSock->isDTLS && ((DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                               || (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion && FALSE == pSSLSock->sendEarlyData)
#endif
                                )))
                            {
                                addToHandshakeHash(pSSLSock, pSSLSock->roleSpecificInfo.client.helloBuffer, pSSLSock->roleSpecificInfo.client.helloBufferLen);
                            }
                        }
                    }

#ifdef __ENABLE_DIGICERT_TLS13__
                    /* If the client early traffic secret hasn't been
                     * calculated then calculate it here. Note that the
                     * ClientHello must be added to the handshake hash before
                     * calculating the client early traffic secret.
                     *
                     * If Server did not select a PSK in-case of 0-RTT,
                     * re-compute pClientEarlyTrafficSecret.
                     * OR
                     * If server did not select the 0th PSK, recompute
                     * pClientEarlyTrafficSecret with correct PSK.
                     * OR
                     * If the server replied with a helloRetryRequest,
                     * recompute the keys with the updated transcript hash.
                     */
                    if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
                        ((NULL == pSSLSock->pClientEarlyTrafficSecret) ||
                        (0 == TLS13_CLIENT_GET_PSK_RX(pSSLSock)) ||
                        (pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex != 0) ||
                        (1 == TLS13_HRR_GET_REPLY_TX(pSSLSock))))
                    {
                        tls13PSK *pTls13Psk = NULL;
                        ubyte *ppsk = NULL;
                        ubyte4 pskLen = 0;

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                        ubyte4 i = 0;

                        if (1 == TLS13_CLIENT_GET_PSK_RX(pSSLSock))
                        {
                            pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

                            /* The index count starts from 0 */
                            for (i = 0; i < pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex; i++)
                            {
                                if (NULL == pTempPSKList)
                                    break;
                                pTempPSKList = pTempPSKList->pNextPSK;
                            }

                            if (pTempPSKList != NULL)
                                pTls13Psk = pTempPSKList->pPSK;
                        }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */

                        if (pTls13Psk != NULL)
                        {
                            ppsk = pTls13Psk->pskTLS13;
                            pskLen = pTls13Psk->pskTLS13Length;
                        }
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                        if (!pSSLSock->sendEarlyData || !pSSLSock->isDTLS || !(DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
#endif
                        {
                            status = SSLSOCK_pskEarlySecretDerive(
                                pSSLSock, ppsk, pskLen,
                                pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo);
                            if (OK != status)
                                break;
                        }
                    }
#endif /* __ENABLE_DIGICERT_TLS13__ */

                    /* Add the ServerHello to the handshake hash.
                     */
                    addToHandshakeHash(pSSLSock,
                                       (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);
#ifdef __ENABLE_DIGICERT_TLS13__
                    /* Calculate the (EC)DHE shared key. The call to this
                     * function should also populate the handshake traffic
                     * secret so the encrypted data after a ServerHello can be
                     * decrypted.
                     */
                    if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                         (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
                         (!pSSLSock->helloRetryRequest))
                    {
                        if (OK > (status = SSLSOCK_computeHandshakeSecret(pSSLSock)))
                        {
                            break;
                        }

                        if (OK > (status = SSLSOCK_setServerTrafficKeyMaterial(pSSLSock, pSSLSock->pServerHandshakeTrafficSecret)))
                        {
                            break;
                        }

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                        if ((FALSE == pSSLSock->sendEarlyData) ||
                            (pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex != 0) ||
                            (0 == TLS13_CLIENT_GET_PSK_RX(pSSLSock)))
#endif
                        {
                            if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock, pSSLSock->pClientHandshakeTrafficSecret)))
                            {
                                break;
                            }
                        }

                        /* For DTLS1.3 move now to epoch 2 */
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_TLS13__)
                        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                        {
                            pSSLSock->peerSeqnum = 0;
                            pSSLSock->peerSeqnumHigh = 0x20000;
                            pSSLSock->ownSeqnum = 0;
                            pSSLSock->ownSeqnumHigh = 0x20000;
                            pSSLSock->currentPeerEpoch = (ubyte2) 0x02;  
                            /* record the existing ciphersuite for re-transmission */
                            pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
                        }
#endif
                    }

                    /* we no longer need to buffer the client hello, release memory */
                    if (1 == TLS13_HRR_GET_REPLY_TX(pSSLSock))
                    {
                        (void) DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.client.helloBuffer);
                        (void) DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.client.hrrBuffer);
                        pSSLSock->roleSpecificInfo.client.hrrBufferLen = 0;
                        pSSLSock->roleSpecificInfo.client.helloBufferLen = 0;
                    }
#endif
                }
                break;

            case SSL_CERTIFICATE:
                if (NULL == pSSLSock->pHandshakeCipherSuite)
                    break;
#if (defined(__ENABLE_DIGICERT_TLS13__))
                if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                     (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                {
                    if (((SSL_ENCRYPTED_EXTENSIONS == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                        (SSL_CERTIFICATE_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))) &&
                            (0 == (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_ANON_BIT)))
                    {
                        status = processCertificate(pSSLSock, pSHSH, handshakeRecLen, TRUE);

                        if (OK > status)
                            break;
                    }
                    else
                    {
                        break;
                    }
                }
                else
#endif
                {
                    if ((SSL_SERVER_HELLO == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&
                            (0 == (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_ANON_BIT)))
                    {
                        status = processCertificate(pSSLSock, pSHSH, handshakeRecLen, TRUE);

                        if (OK > status)
                            break;
                    }
                    else
                    {
                        break;
                    }
                }
                addToHandshakeHash(pSSLSock,
                        (ubyte *)pSHSH,
                        handshakeRecLen + sizeofHandshakeHeader);

                break;

#if defined(__ENABLE_DIGICERT_TLS13__)
            case SSL_ENCRYPTED_EXTENSIONS:
                if (SSL_SERVER_HELLO == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                {
                    /* Encrypted Extensions message should be received
                     * only when we have received Server Hello
                     */
                    if (OK > (status = processEncryptedExtensions(pSSLSock, pSHSH, handshakeRecLen)))
                        break;

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined( __ENABLE_DIGICERT_TLS13_0RTT__))
                    /* RFC: 4.2.11 : If the server supplies an "early_data" extension, the client MUST
                     * verify that the server's selected_identity is 0.  If any other value
                     * is returned, the client MUST abort the handshake with an
                     * "illegal_parameter" alert.
                     */
                    if(pSSLSock->earlyDataExtAccepted)
                    {
                        if(pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex != 0)
                        {
                            status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                            SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */,
                                    SSL_ALERT_ILLEGAL_PARAMETER,
                                    SSLALERTLEVEL_FATAL);
#endif
                            break;
                        }
                    }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ && __ENABLE_DIGICERT_TLS13_0RTT__ */

                    addToHandshakeHash(pSSLSock, (ubyte *)pSHSH, handshakeRecLen + sizeofHandshakeHeader);
                }
                break;
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)         || \
     defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)     || \
     defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)       || \
     defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)   || \
     defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) )
            case SSL_SERVER_KEY_EXCHANGE:
                if ((SSL_SERVER_HELLO != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&
                    (SSL_CERTIFICATE  != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
                    && (SSL_CERTIFICATE_STATUS  != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
#endif
                )
                {
                    /* we got here from a bad state */
                    break;
                }

                if ((NULL != pSSLSock->pHandshakeCipherSuite) &&
                    (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo) &&
                    (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->ProcessServerKEX))
                {
                    status = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->ProcessServerKEX(pSSLSock, (ubyte *)(pSHSH + sizeofHandshakeHeader), handshakeRecLen);

                    if (OK > status)
                        break;

                    addToHandshakeHash(pSSLSock,
                                       (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);

                    pSSLSock->receivedServerKeyEx = TRUE;
                }
                break;
#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */

            case SSL_CERTIFICATE_REQUEST:
#if defined(__ENABLE_DIGICERT_TLS13__)
                if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                     (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                {
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
                    /* Client did NOT send post_handshake_auth extensions,
                     * Received CertificateRequest message and the current state is not ksslReceiveHelloState;
                     * The Server sent Certificaterequest message after handshake;
                     * Throw an "unexpected_message" fatal alert. RFC 8446, Section 4.6.2
                     */
                    if ((pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH) &&
                        (0 == pSSLSock->postHandshakeAuth) &&
                        (kSslReceiveHelloState != SSL_HANDSHAKE_STATE(pSSLSock)))
                    {
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_UNEXPECTED_MESSAGE, SSLALERTLEVEL_FATAL);
#endif
                        break;
                    }
#endif
                    if ((SSL_ENCRYPTED_EXTENSIONS == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                        ((pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH) &&
                         (SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))))
                    {
                        status = OK;

                        pSSLSock->generateEmptyCert = TRUE;

                        if (SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                        {
                            pSSLSock->postHandshakeMessages |= (1 << CERTIFICATE_REQUEST);
                        }
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                        else
                        {
                            /* Section 4.3.2
                             * Servers which are authenticating with a PSK MUST NOT send
                             * the CertificateRequest message in the main handshake,
                             * though they MAY send it in post-handshake authentication
                             * (see Section 4.6.2) provided that the client has sent the
                             * "post_handshake_auth" extension (see Section 4.2.6).
                             */
                            if (0 != pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex)
                            {
                                status = ERR_SSL_MUTUAL_AUTHENTICATION_REQUEST_IGNORED;
                                break;
                            }
                        }
#endif

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
                        if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
                                (SSL_FLAG_NO_MUTUAL_AUTH_REPLY != (pSSLSock->runtimeFlags & SSL_FLAG_NO_MUTUAL_AUTH_REPLY)))
                        {
                            status = processCertificateRequest3(pSSLSock, pSHSH, handshakeRecLen);
                            if (OK > status)
                            {
                                break;
                            }
                        }
#endif

                        addToHandshakeHash(pSSLSock,
                                (ubyte *)pSHSH,
                                handshakeRecLen + sizeofHandshakeHeader);
                    }
                }
                else
#endif
                {
                    if ((SSL_CERTIFICATE         == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                        (SSL_SERVER_KEY_EXCHANGE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) )
                    {
                        status = OK;

                        pSSLSock->generateEmptyCert = TRUE;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
                        if ((SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
                                (SSL_FLAG_NO_MUTUAL_AUTH_REPLY != (pSSLSock->runtimeFlags & SSL_FLAG_NO_MUTUAL_AUTH_REPLY)))
                        {
                            /* ignore certificate requests, if server is not authenticated */
                            status = processCertificateRequest(pSSLSock, pSHSH, handshakeRecLen);
                            if (OK > status)
                                break;
                        }
#endif

                        addToHandshakeHash(pSSLSock,
                                (ubyte *)pSHSH,
                                handshakeRecLen + sizeofHandshakeHeader);
                    }
                }
                break;
#ifdef __ENABLE_DIGICERT_TLS13__
            case SSL_CLIENT_CERTIFICATE_VERIFY:
                if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                    (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                {
                    if (SSL_CERTIFICATE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                    {
                        status = processCertificateVerify(pSSLSock, pSSLSock->handshakeKey, pSHSH, handshakeRecLen, &pVlongQueue);

                        if (OK > status)
                        {
                            DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "processCertificateVerify() returns status = ", status);
                            break;
                        }

                        addToHandshakeHash(pSSLSock,
                                (ubyte *)pSHSH,
                                handshakeRecLen + sizeofHandshakeHeader);

                        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_CLIENT_CERTIFICATE_VERIFY;
                    }
                    else
                    {
                        status = ERR_SSL_MUTUAL_AUTHENTICATION_NOT_REQUESTED;
                    }
                }
                break;
#endif /* __ENABLE_DIGICERT_TLS13__ */

            case SSL_SERVER_HELLO_DONE:
                if ((SSL_CERTIFICATE        == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
                    (SSL_CERTIFICATE_STATUS   == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
                    (SSL_SERVER_HELLO         == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                    (SSL_ENCRYPTED_EXTENSIONS == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
#endif
#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
                    /* IOT-563: no message between SERVER_HELLO and SERVER_HELLO_DONE
                     if there's no hint sent by server for PSK cipher suites */
                    (SSL_SERVER_HELLO         == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
#endif
                    (SSL_SERVER_KEY_EXCHANGE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                    (SSL_CERTIFICATE_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) )
                {
                    /* Server Key Message should be sent by the server in case of
                     * DHE_DSS, DHE_RSA, DH_anon, ECDHE_ECDSA, ECDHE_RSA, ECDH_anon
                     * key exchange algorithms being used in TLS 1.2 and below versions.
                     * All these above keyex algorithms can be checked using the
                     * SSL_KEYEX_ECDHE_BIT and SSL_KEYEX_DHE_BIT
                     */
                    intBoolean isServerKeyExMandatory = (NULL != pSSLSock->pHandshakeCipherSuite) &&
                                                        (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo) &&
                                                        ((pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDHE_BIT) ||
                                                        (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_DHE_BIT));

                    if ((TRUE == isServerKeyExMandatory) && (FALSE == pSSLSock->receivedServerKeyEx))
                    {
                        status = ERR_SSL_PROTOCOL;
                        break;
                    }

                    /* Set it to FALSE for rehandshake */
                    pSSLSock->receivedServerKeyEx = FALSE;

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
                    /* IOT-563: special case for PSK suites  -- it's possible we arrive
                     here without receiving a server KeyExchange */
                    intBoolean isPSK = (NULL != pSSLSock->pHandshakeCipherSuite) &&
                        (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo) &&
                        (NULL != pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->ProcessServerKEX) &&
                        (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_PSK_BIT);

                    /* if this is a PSK cipher, makes sure the callback is called */
                    if (isPSK && 0 == pSSLSock->roleSpecificInfo.client.pskIdentityLength)
                    {
                        status = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->ProcessServerKEX(pSSLSock, (ubyte *)(pSHSH + sizeofHandshakeHeader), 0);
                        if (OK > status)
                            break;
                    }

                    /* allow no server messages between server hello and server hello done
                     only if PSK */
                    if (SSL_SERVER_HELLO == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) && !isPSK)
                    {
                        status = ERR_SSL_PROTOCOL;
                        break;
                    }
#endif
                    /* easy message to process */
                    if (0 == handshakeRecLen)
                        status = OK;

                    /* fail out, if SSL_FLAG_REQUIRE_MUTUAL_AUTH is set and server did not require mutual authentication
                     * Except if Post-Handshake Auth is enabled
                     */
                    if ((pSSLSock->runtimeFlags & SSL_FLAG_REQUIRE_MUTUAL_AUTH) &&
                        (!(pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH)) &&
                        (SSL_CERTIFICATE_REQUEST != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&
                        (E_NoSessionResume == pSSLSock->sessionResume))
                    {
                        /* we expected the server to require mutual authentication */
                        /* as of now, SSL_CERTIFICATE_REQUEST is expected before SSL_SERVER_HELLO_DONE */
                        /* in the future, we might need to set a flag rather than inspecting SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) */
                        status = ERR_SSL_MUTUAL_AUTHENTICATION_NOT_REQUESTED;
                        break;
                    }

                    addToHandshakeHash(pSSLSock,
                                       (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);
#ifdef __ENABLE_DIGICERT_TLS13__
                    if (1 == TLS13_HRR_GET_RX(pSSLSock))
                    {
                        pSSLSock->roleSpecificInfo.client.hrr = TLS13_HRR_SET_SERVER_HELLO_RX(pSSLSock);
                    }
#endif
                }
                break;

            case SSL_FINISHED:
                /* client or server */

                /* Seems like the ChangeCipherSpec message is used to update the
                 * remote state to SSL_EXPECTING_FINISHED but for TLS 1.3 there
                 * is no ChangeCipherSpec message so if a finished message is
                 * recieved then just process it for TLS 1.3.
                 */
                if ( (SSL_EXPECTING_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) ||
                     (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                      (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) )
                {
                    status = processFinished(pSSLSock, pSHSH, handshakeRecLen);

                    if (OK > status)
                        break;

                    addToHandshakeHash(pSSLSock,
                                        (ubyte *)pSHSH,
                                        handshakeRecLen + sizeofHandshakeHeader);

#ifdef __ENABLE_DIGICERT_TLS13__
                    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                         (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                    {
                        if (OK > (status = SSLSOCK_pskCalcApplicationTrafficSecret(pSSLSock)))
                        {
                            break;
                        }

                        if (OK > (status = SSLSOCK_setServerTrafficKeyMaterial(
                            pSSLSock, pSSLSock->pServerApplicationTrafficSecret)))
                        {
                            break;
                        }

                        /* For DTLS1.3 move peer now to epoch 3, we move our own after sendFinished */
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_TLS13__)
                        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                        {
                            pSSLSock->peerSeqnum = 0;
                            pSSLSock->peerSeqnumHigh = 0x30000;
                            pSSLSock->currentPeerEpoch = (ubyte2) 0x03;
                            releaseRetransmissionBuffer(pSSLSock);
                        }
#endif

                        /* Set the active cipher suite here. The remaining
                         * client handshake messages for TLS 1.3 will all be
                         * encrypted.
                         */
                        pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
                    }
#endif
                }
                break;
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
            case SSL_CERTIFICATE_STATUS:
                /* Handle certficateStatus Message here */
                if ((SSL_CERTIFICATE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&
                    (pSSLSock->didRecvCertStatusExt))
                {
                    if (OK > (status = processCertificateStatus(pSSLSock, (ubyte *)pMsg, handshakeRecLen)))
                        break;

                     addToHandshakeHash(pSSLSock,
                                       (ubyte *)pSHSH,
                                       handshakeRecLen + sizeofHandshakeHeader);
                }
                break;
#endif
#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
            case SSL_NEW_SESSION_TICKET:
                /* Server sent a new session ticket (called as PSK in TLSv1.3) */
#if defined(__ENABLE_DIGICERT_TLS13__)
                if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                     (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                {
                    /* New session ticket only allowed once client has sent
                     * finished message */
                    if (FALSE == pSSLSock->sentFinished)
                    {
                        /* status already set to ERR_SSL_PROTOCOL */
                        break;
                    }
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                    if (OK > (status = processNewSessionTicket(pSSLSock, (ubyte*)pSHSH, handshakeRecLen)))
                    {
                        break;
                    }
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
                }
                else
#endif
                {
                    /* Session ticket only allowed once state is at server
                     * hello done */
                    if (SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) != SSL_SERVER_HELLO_DONE)
                    {
                        /* status already set to ERR_SSL_PROTOCOL */
                        break;
                    }

                    /* Process SessionTicket. For TLS 1.2, SessionTicket is
                     * part of handshake message, add it to the hash
                     */
#ifdef __ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__
                    if (OK > (status = processTLSSessionTicket(pSSLSock, (ubyte *)pSHSH, handshakeRecLen)))
                    {
                        break;
                    }
#endif

                    if (1 == pSSLSock->roleSpecificInfo.client.requestSessionTicket)
                    {
                         addToHandshakeHash(pSSLSock,
                                           (ubyte *)pSHSH,
                                           handshakeRecLen + sizeofHandshakeHeader);
                    }
                }
                status = OK;
                break;
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
            case SSL_KEY_UPDATE:
                if (((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) ||
                     (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)) || /* Should not receive this message for versions lower than TLS 1.3 */
                    ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion || DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
                     (SSL_FINISHED != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))) /* Received a finsihed message from server */
                {
                    /* If we recieve this message before SSL_FINISHED, we abort with an illegal_parameter alert */
                    status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif

                    break;
                }
                status = processKeyUpdateRequest(pSSLSock, (ubyte*)pSHSH, handshakeRecLen);
                break;

            case SSL_CLIENT_END_OF_EARLY_DATA:
                {
                    /* RFC 8446, Section 4.5. Servers MUST not send this message, and clients receiving it MUST
                       terminate the connection with an "unexpected_message" alert.*/ 
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                    SSLSOCK_sendAlert(pSSLSock, TRUE,
                            SSL_ALERT_UNEXPECTED_MESSAGE,
                            SSLALERTLEVEL_FATAL);
#endif
                    status = ERR_SSL_FATAL_ALERT;
                    break;
                }
#endif /* __ENABLE_DIGICERT_TLS13__ */

            default:
            {
                status = ERR_SSL_PROTOCOL_BAD_STATE;
                break;
            }
        }

        /* if OK, advance state */
        if (status >= OK)
        {
            /* before advancing the state, we check if the routines called
             did not advance it already to a further state (client resuming session
             for example treats a SERVERHELLO as SERVERHELLODONE) */
#ifdef __ENABLE_DIGICERT_TLS13__
            if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                  (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
                SSL_CERTIFICATE_REQUEST == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
            {
                SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = handshakeType;
            }
            else if (((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
                       (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) &&
                     (SSL_SERVER_HELLO == handshakeType) &&
                     (pSSLSock->helloRetryRequest))
            {
                /* If performing TLS 1.3 and the server has provided a hello
                 * retry request (indicated by pSSLSock->helloRetryRequest)
                 * then keep the state at SSL_HELLO_REQUEST so the client
                 * expects the next message to be a server hello.
                 */
                SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_HELLO_REQUEST;
            }
            else if (SSL_KEY_UPDATE != handshakeType) /* Do NOT advance the remote state for KeyUpdate messages */
#endif
            {
                if (SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) < handshakeType)
                {
                    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = handshakeType;
                }
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
            /* handle exception here as certificate status > all other handshakeType */
                else if ((SSL_CERTIFICATE_STATUS == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&
                         (SSL_CERTIFICATE < handshakeType))
                {
                    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = handshakeType;
                }
#endif
            }
            if (recordLen < handshakeRecLen)
            {
                status = ERR_SSL_PROTOCOL_BAD_LENGTH;
                goto exit;
            }

            /* advance pointers */
            pMsg += handshakeRecLen;
            recordLen = (ubyte2)(recordLen - handshakeRecLen);
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"handleClientHandshakeMessages() returns status = ", status);

    (void) VLONG_freeVlongQueue(&pVlongQueue);

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (pTempMsg != NULL)
    {
        DIGI_FREE((void **)&pTempMsg);
    }
#endif

    return status;

} /* handleClientHandshakeMessages */


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_clientHandshake(SSLSocket* pSSLSock, intBoolean isWriter)
{
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
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
                    pSSLSock->pReceiveBuffer = (sbyte*)pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].ptr;
                    pSSLSock->recordSize = pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].recordSize;
                    /* check to see if we are receiving a post-handshake message. */
                    if ((pSSLSock->recordSize && SSL_KEY_UPDATE == pSSLSock->pReceiveBuffer[0]))
                        status = SSL_SOCK_clientPostHandshakeDTLS(pSSLSock, &pSSLSock->postHandshakeState[kKeyUpdate], isWriter);
                    else if ((pSSLSock->recordSize && SSL_NEW_SESSION_TICKET == pSSLSock->pReceiveBuffer[0]))
                        status = SSL_SOCK_clientPostHandshakeDTLS(pSSLSock, &pSSLSock->postHandshakeState[kNewSessionTicket], isWriter);
                    else if ((pSSLSock->recordSize && SSL_CERTIFICATE_REQUEST == pSSLSock->pReceiveBuffer[0]))
                        status = SSL_SOCK_clientPostHandshakeDTLS(pSSLSock, &pSSLSock->postHandshakeState[kCertificateRequest], isWriter);
                    else
                        status = ERR_SSL_BAD_ID;

                    if (OK > status)
                    {
                        /* TODO: reset state if failed. */
                        FREE(pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].ptr);
                        pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].ptr = NULL;
                        pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].recordSize = 0;

#ifdef __ENABLE_DIGICERT_TLS13__
                        freeMsgBufferDescrRecords(&pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase]);
#endif
                        /* restore pReceiveBuffer */
                        pSSLSock->pReceiveBuffer = pMsg;
                        pSSLSock->recordSize = recordLen;
                        return status;
                    }
#ifdef __ENABLE_DIGICERT_TLS13__
                    freeMsgBufferDescrRecords(&pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase]);
#endif
                    FREE(pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].ptr);
                    pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].ptr = NULL;
                    pSSLSock->msgBufferDescrs[pSSLSock->nextRecvSeq-pSSLSock->msgBase].recordSize = 0;

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
#endif
        return SSL_SOCK_clientHandshakeDTLS(pSSLSock, isWriter);
    } else
#endif /* __ENABLE_DIGICERT_DTLS_CLIENT__ */
    {
        return SSL_SOCK_clientHandshakeSSL(pSSLSock, isWriter);
    }
}

/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_clientHandshakeSSL(SSLSocket* pSSLSock, intBoolean isWriter)
{
    MSTATUS status = OK;

#if 1   /*!!!! this needs to happen by the caller */
    /* handle any data pending on a send */
    if ((NULL != pSSLSock->pOutputBuffer) &&
        (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
    {
        goto exit;
    }
#endif

/* This label might not be required;
 * Clean up after the initial handshake handling is put in.
 */
#if defined(__ENABLE_DIGICERT_TLS13__)
handshake_state:
#endif
    switch (SSL_HANDSHAKE_STATE(pSSLSock))
    {
#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))
        case kSslOpenState:
        {
            sbyte4  doRehandshake       = FALSE;
            sbyte4  doSessionResumption = FALSE;

            /* rehandshake support */
            SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_BEGIN;

            doRehandshake = TRUE;

            /* Enable rehandshake flag */
            pSSLSock->rehandshake = 1;

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

            if (FALSE == doSessionResumption)
            {
                pSSLSock->roleSpecificInfo.client.sessionIdLen = 0;     /* prevent session resumption */
            }

            /* FALL-THROUGH */
        }
#endif

        case kSslReceiveHelloInitState:
        {
            status = SSL_CLIENT_sendClientHello(pSSLSock);
            if (OK > status)
            {
                goto exit;
            }

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
            /* The negotiated version is TLS 1.3 and we have early data to send */
            if (TRUE == pSSLSock->sendEarlyData)
            {
                if (OK > (status = SSL_SOCK_sendEarlyData(pSSLSock)))
                {
                    goto exit;
                }
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;
                break;
            }
            else
#endif
            {
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState;
            }

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */
        }

        case kSslReceiveHelloState:
        {
            if (isWriter)
                break;

#ifdef __ENABLE_DIGICERT_TLS13__
            if(!pSSLSock->helloRetryRequest)
            {
                if ((1 == TLS13_HRR_GET_RX(pSSLSock)) && (1 ==  TLS13_HRR_GET_SERVER_HELLO_RX(pSSLSock)))
                {
                    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_HELLO_REQUEST;
                }
            }
#endif
            if (OK > (status = handleClientHandshakeMessages(pSSLSock)))
                goto exit;

#ifdef __ENABLE_DIGICERT_TLS13__
            if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                if(pSSLSock->helloRetryRequest)
                {
                    if(pSSLSock->roleSpecificInfo.client.isSupportedVersionPresent)
                    {
                        status = SSL_CLIENT_sendClientHello(pSSLSock);
                        pSSLSock->roleSpecificInfo.client.hrr = TLS13_HRR_SET_REPLY_TX(pSSLSock);
                        DIGI_MEMSET(pSSLSock->helloCookie, 0, pSSLSock->helloCookieLen);
                        pSSLSock->helloCookieLen = 0;
                        break;
                    }
                    else
                    {
                        /* RFC 4.1.4 : Hello Retry Request
                         * The server's extensions MUST contain "supported_versions" and
                         * otherwise the server SHOULD send only the extensions necessary for
                         * the client to generate a correct ClientHello pair.
                         */
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                                          SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
                        DIGI_MEMSET(pSSLSock->helloCookie, 0, pSSLSock->helloCookieLen);
                        pSSLSock->helloCookieLen = 0;

                        break;
                    }

                }

                /* check if data is pending, if so break */
                if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                {
                    break;
                }

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                if ((1 == pSSLSock->earlyDataExtAccepted) &&
                    (SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
                {
                    /* RFC 9147 Sec 5.6 No EndOfEarlyData message needed for DTLS */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                    if (!pSSLSock->isDTLS)
#endif
                    {
                        if (OK > (status = SSL_CLIENT_sendEndOfEarlyData(pSSLSock)))
                        {
                            goto exit;
                        }
                    }

                    if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock, pSSLSock->pClientHandshakeTrafficSecret)))
                    {
                        goto exit;
                    }
                }
#endif /* (__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__ */
            }

            if (!pSSLSock->helloRetryRequest)
            {
                /* 4.2.1: A server which negotiates a version of TLS prior to TLS 1.3 MUST set
                 * ServerHello.version and MUST NOT send the "supported_versions"
                 * extension.
                 */
                if(pSSLSock->roleSpecificInfo.client.isSupportedVersionPresent)
                {
                    if(pSSLSock->sslMinorVersion == TLS12_MINORVERSION)
                    {
                        if((pSSLSock->roleSpecificInfo.client.serverSelectedVersion & 0x0F) != TLS13_MINORVERSION)
                        {
                        /* 4.2.1: If the "supported_versions" extension in the ServerHello contains a
                         * version not offered by the client or contains a version prior to
                         * TLS 1.3, the client MUST abort the handshake with an
                         * "illegal_parameter" alert.
                         */
                            status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                            SSLSOCK_sendAlert(pSSLSock, FALSE /* Key share not exchanged */,
                                    SSL_ALERT_ILLEGAL_PARAMETER,
                                    SSLALERTLEVEL_FATAL);
#endif
                            break;
                        }
                    }
                }

                if (1 == TLS13_HRR_GET_RX(pSSLSock))
                {
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloInitState;
                    break;
                }
            }
#endif /* __ENABLE_DIGICERT_TLS13__ */
            if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                if (SSL_FINISHED != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                    break;
            }
            else
            {
                if (SSL_SERVER_HELLO_DONE != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                    break;
            }

            /* if we resume sessions the path is a bit different */
            if (E_NoSessionResume != pSSLSock->sessionResume)
            {
                status = SSL_SOCK_generateKeyMaterial(pSSLSock, NULL, 0);

                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntilResume;
                break;
            }
            else /* if (SSL_ASYNC_STATE_HELLO_COMPLETED == SSL_ASYNC_STATE(pSSLSock)) */
            {
                /* TLS 1.2 || DTLS ||
                 * ((TLS 1.3 && Handshake NOT completed) ||
                 * (TLS 1.3 && Handshake completed && isPosthandshake Cert Request))
                 */
                if ((TLS13_MINORVERSION > pSSLSock->sslMinorVersion) || (pSSLSock->isDTLS)
#if defined(__ENABLE_DIGICERT_TLS13__)
                    ||
                    ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
                     ((SSL_OPEN_STATE(pSSLSock) != kSslSecureSessionEstablished) ||
                      (pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST))))
#endif
                  )
                {
                    status = SSL_CLIENT_sendClientResponseBlock(pSSLSock);
                    if (OK > status)
                    {
                        goto exit;
                    }
                }

#if defined(__ENABLE_DIGICERT_TLS13__)
                if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                {
                    if (!(pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST)))
                    {
                        /* If there is data to be sent out, transition to kSslReceiveUntil */
                        if (SSL_OPEN_STATE(pSSLSock) == kSslSecureSessionEstablished)
                        {
                            if (keyUpdate_none != pSSLSock->keyUpdateRequested)
                            {
                                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;
                                goto handshake_state;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
                else
#endif
                {
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState1;
                }
            }

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */
        }

        case kSslReceiveHelloState1:
        {
#if defined(__ENABLE_DIGICERT_TLS13__)
            if (pSSLSock->isDTLS || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
#endif
            {
                if (OK > (status = sendChangeCipherSpec(pSSLSock)))
                    goto exit;

            }

            if (OK > (status = SSL_SOCK_setClientKeyMaterial(pSSLSock)))
                goto exit;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
            pSSLSock->retransCipherInfo.pOldCipherSuite = pSSLSock->pActiveOwnCipherSuite;
#endif
            pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState2;

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */
        }

        case kSslReceiveHelloState2:
        {

            status = sendFinished(pSSLSock);
            if (OK > status)
                break;

#if defined (__ENABLE_DIGICERT_TLS13__)
            if (pSSLSock->sslMinorVersion == TLS13_MINORVERSION)
            {
                /* Only derive the key material if a post certificate request
                 * is not being handled.
                 */
                if (!(pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST)))
                {
                    /* Create a copy of the transcript hash. For post
                     * handshake messages, only the transcript hash during
                     * the handshake is updated. Post handshake messages do
                     * not include other post handshake messages.
                     *
                     * Example:
                     *
                     *   Server sends 1st post handshake mutual auth request
                     *     Transcript-Hash(Handshake messages)
                     *     Transcript-Hash(Post handshake mutual auth 1)
                     *
                     *   Server sends 2nd post handshake mutual auth request
                     *     Transcript-Hash(Handshake messages)
                     *     Transcript-Hash(Post handshake mutual auth 2)
                     *
                     * The 2nd post handshake message does not update the
                     * transcript hash with the 1st post handshake message.
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
                    /* Calculate the master_resumption_secret */
                    if (OK > (status = SSLSOCK_pskCalcResumptionMasterSecret(pSSLSock,
                                        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo)))
                    {
                        break;
                    }
#endif
                }
                else
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pHashCtx);
#endif

                    /* Restore the original transcript hash (which should only
                     * contain the handshake messages).
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

                    /* If the post handshake message bit is set and the send
                     * finished message has been sent then unset the post
                     * certificate request bit.
                     */
                    pSSLSock->postHandshakeMessages &= ~(1 << CERTIFICATE_REQUEST);
                }

                if (SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
                {
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState;
                    SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;

                    if (OK > (status = SSL_INTERNAL_setConnectionState(SSL_findConnectionInstance(pSSLSock), CONNECT_OPEN)))
                        goto exit;

                    status = SSLSOCK_doOpenUpcalls(pSSLSock);
                    if ( OK <= status )
                        status = (MSTATUS) pSSLSock->numBytesToSend;
                }
            }
            else
#endif
            {
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;
            }
            break;
        }
        case kSslReceiveUntilResume:
        {
            if (isWriter)
                break;

            /* if we resume sessions the path is a bit different */
            if (OK > (status = handleClientHandshakeMessages(pSSLSock)))
                goto exit;

            if (SSL_FINISHED != SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
            {
                break;
            }

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntilResume1;

            /* FALL-THROUGH */
        }

        case kSslReceiveUntilResume1:
        {
            if (OK > (status = sendChangeCipherSpec(pSSLSock)))
                goto exit;

            if (OK > (status = SSL_SOCK_setClientKeyMaterial(pSSLSock)))
                goto exit;

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
            pSSLSock->retransCipherInfo.pOldCipherSuite = pSSLSock->pActiveOwnCipherSuite;
#endif
            pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntilResume2;

            /* check if data is pending, if so break */
            if ((NULL != pSSLSock->pOutputBuffer) && (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
                break;

            /* FALL-THROUGH */
        }

        case kSslReceiveUntilResume2:
        {
            status = sendFinished(pSSLSock);

            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntilResume3;

            /* FALL-THROUGH */
        }

        case kSslReceiveUntilResume3:
        {
            SSL_HANDSHAKE_STATE(pSSLSock) = kSslOpenState;
            SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;

            if (OK > (status = SSL_INTERNAL_setConnectionState(SSL_findConnectionInstance(pSSLSock), CONNECT_OPEN)))
                goto exit;

            status = SSLSOCK_doOpenUpcalls(pSSLSock);

            if ( OK <= status )
                status = (MSTATUS) pSSLSock->numBytesToSend;

            break;
        }
        case kSslReceiveUntil:
        {
            if (isWriter)
                break;

            if (OK > (status = handleClientHandshakeMessages(pSSLSock)))
            {
                goto exit;
            }

            if (SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
            {
#if defined(__ENABLE_DIGICERT_TLS13__)
                if (pSSLSock->sslMinorVersion == TLS13_MINORVERSION)
                {
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;
                }
                else
#endif
                {
                    SSL_HANDSHAKE_STATE(pSSLSock) = kSslOpenState;
                }
                SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;

                if (OK > (status = SSL_INTERNAL_setConnectionState(SSL_findConnectionInstance(pSSLSock), CONNECT_OPEN)))
                    goto exit;

                status = SSLSOCK_doOpenUpcalls(pSSLSock);
            }
            if ( OK <= status )
                status = (MSTATUS) pSSLSock->numBytesToSend;

#if defined(__ENABLE_DIGICERT_TLS13__)
            if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                if ((1 == pSSLSock->postHandshakeAuth) &&
                    (pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST)) &&
                    (SSL_FINISHED == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
                {
                    /* Process the post Handshake Certificate Request message from server */
                    if (OK > (status = SSL_CLIENT_sendClientResponseBlock(pSSLSock)))
                    {
                        goto exit;
                    }

                    if (OK > (status = sendFinished(pSSLSock)))
                    {
                        goto exit;
                    }

                    pSSLSock->postHandshakeMessages |= ~(1 << CERTIFICATE_REQUEST);
                }
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
                SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState;
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
                if (keyUpdate_none != pSSLSock->keyUpdateRequested)
                {
                    if (OK > (status = SSLSOCK_sendKeyUpdateRequest(pSSLSock, pSSLSock->keyUpdateRequested)))
                    {
                        goto exit;
                    }
                }
            }
#endif /* (__ENABLE_DIGICERT_TLS13__) */
            break;
        }

        default:
        {
            status = ERR_SSL_BAD_STATE;
            break;
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_FAST__
extern MSTATUS
SSL_SOCK_setEAPFASTParams(SSLSocket* pSSLSock,
                          ubyte* pPacOpaque,
                          ubyte4 pacOpaqueLen,
                          ubyte  pacKey[PACKEY_SIZE])
{
    MSTATUS status = OK;

    if (!pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* store the PacKey */
    if (pacKey)
    {
        if (OK > (status = DIGI_MEMCPY(pSSLSock->pacKey, pacKey, PACKEY_SIZE)))
            goto exit;
    }

    if (pPacOpaque)
    {
        if (!pacOpaqueLen)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        resetTicket(pSSLSock);

        pSSLSock->roleSpecificInfo.client.ticket = MALLOC(pacOpaqueLen);
        if (!pSSLSock->roleSpecificInfo.client.ticket)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        status = DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.ticket, pPacOpaque, pacOpaqueLen);
        pSSLSock->roleSpecificInfo.client.ticketLength = pacOpaqueLen;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_EAP_FAST__ */


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_initSocketExtraClient(SSLSocket* pSSLSock,
                               ubyte sessionIdLen,
                               ubyte* pSessionId,
                               ubyte* pMasterSecret,
                               const sbyte* pDNSName,
                               certStorePtr certStore)
{
    MSTATUS status;

    if (!pSSLSock)
        return ERR_NULL_POINTER;

#if (!defined(__DISABLE_DIGICERT_SSL_COMMON_NAME_CHECK__))
    if (!pDNSName)
        return ERR_NULL_POINTER;
#endif

    /* cert store can be NULL */
    pSSLSock->pCertStore = certStore;

    if ( sessionIdLen && (!pSessionId || !pMasterSecret))
        return ERR_INVALID_ARG;

    pSSLSock->roleSpecificInfo.client.pDNSName = pDNSName;
#ifdef __ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__
    pSSLSock->roleSpecificInfo.client.pCNMatchInfos = 0;
#endif

    SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloInitState;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        pSSLSock->helloCookieLen = 0;
        DTLS_TIMER_STATE(pSSLSock) = kDtlsPreparing;
    }
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
    pSSLSock->helloCookieLen = 0;
#endif

    if (sessionIdLen > SSL_MAXSESSIONIDSIZE)
    {
        /* this is actually an error: a session id should never be more
        than 32 bytes long according to the SSL RFC*/
        pSSLSock->roleSpecificInfo.client.sessionIdLen = 0;
    }
    else
    {
        pSSLSock->roleSpecificInfo.client.sessionIdLen = sessionIdLen;
        if ( sessionIdLen > 0)
        {
            DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.sessionId,
                    pSessionId, sessionIdLen);
            pSSLSock->roleSpecificInfo.client.pMasterSecret = pMasterSecret;
        }
    }

#ifdef __ENABLE_DIGICERT_EAP_FAST__
    pSSLSock->roleSpecificInfo.client.ticket = 0;
    pSSLSock->roleSpecificInfo.client.ticketLength = 0;
#endif

    if (OK > (status = CRYPTO_initAsymmetricKey(&pSSLSock->handshakeKey)))
        goto exit;

    /* case kSslReceiveHelloInitState: */
    resetCipher(pSSLSock, TRUE, TRUE);
    SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_BEGIN;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        pSSLSock->sslMinorVersion = MAX_DTLS_MINORVERSION; /* highest DTLS version supported */
    } else
#endif
    {
        pSSLSock->sslMinorVersion = SSL_sslSettings()->sslMaxProtoVersion; /* highest TLS version supported */
    }
exit:
    return status;
}


#endif
