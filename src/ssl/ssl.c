/*
 * ssl.c
 *
 * SSL Developer API
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

/**
@file       ssl.c
@brief      NanoSSL developer API.
@details    This file contains functions used by NanoSSL servers and clients.

@since 1.41
@version 6.4 and later

@todo_version   (post-6.4 revisions to SSL_setOcspResponderUrl() and
                SSL_setCertifcateStatusRequestExtensions(). Added
                SSL_setApplicationLayerProtocol() and
                SSL_getSelectedApplicationProtocol().)

@flags
Whether the following flags are defined determines which additional header files are included:
+ \c \__DEBUG_SSL_TIMER__
+ \c \__ENABLE_ALL_DEBUGGING__
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__

Whether the following flags are defined determines which functions are enabled:
+ \c \__ENABLE_DIGICERT_EAP_FAST__
+ \c \__ENABLE_DIGICERT_INNER_APP__
+ \c \__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_CUSTOM_RNG__
+ \c \__ENABLE_DIGICERT_SSL_DUAL_MODE_API__
+ \c \__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_INTERNAL_STRUCT_ACCESS__
+ \c \__ENABLE_DIGICERT_SSL_KEY_EXPANSION__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@filedoc    ssl.c
*/

#if (defined(__DEBUG_SSL_TIMER__) || defined(__ENABLE_ALL_DEBUGGING__))
#include <stdio.h>
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) && \
    (defined(__ENABLE_DIGICERT_DTLS_EXT_API__) || defined(__ENABLE_DIGICERT_OPENSSL_SHIM__))
#if defined(__RTOS_VXWORKS__)
#include <sys/time.h> /* for 'struct timeval' */
#elif defined(__RTOS_WIN32__)
#include <windows.h>
#include <winsock.h> /* for 'struct timeval' */
#endif /*__RTOS_WIN32__*/
#endif

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__))
#include "../common/moc_net_system.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../ssl/ssl.h"
#include "../common/mdefs.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../common/mem_pool.h"
#include "../common/hash_value.h"
#include "../common/hash_table.h"
#include "../common/memfile.h"
#include "../common/datetime.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs_key.h"
#include "../crypto/des.h"
#include "../crypto/dh.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/cert_chain.h"
#include "../harness/harness.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#endif
#include "../ssl/ssl_priv.h"

#if defined(__ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__) && \
    defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#include "../asn1/parseasn1.h"
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#include "../common/circq.h"
#include "../dtls/dtls.h"
#include "../common/mudp.h"
#if (defined(__ENABLE_DIGICERT_DTLS_SRTP__))
#include "../dtls/dtls_srtp.h"
#endif
#include "../common/timer.h"
#endif
#include "../ssl/sslsock.h"
#include "../ssl/sslsock_priv.h"

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
#include "../ocsp/ocsp_store.h"
#include "../ssl/ssl_ocsp.h"
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_CRYPTO__)
#include "../ssl/hardware_accel_crypto.h"
#endif

#ifdef __ENABLE_DIGICERT_TPM__
#include "../smp/smp_tpm12/tpm12_lib/moctap.h"
#endif

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
#include "../crypto/fips.h"
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SERIALIZE__

#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
#define ALG_RSA 1
#else
#define ALG_RSA 0
#endif


#ifdef __ENABLE_DIGICERT_TPM__
#define ALG_TPM 1
#else
#define ALG_TPM 0
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#define ALG_ECC 1
#else
#define ALG_ECC 0
#endif

#define ALG_COUNT (ALG_RSA + ALG_TPM + ALG_ECC)

MKeySerialize gTPMSupportedAlgos[] = {
#ifdef __ENABLE_DIGICERT_TPM__
    KeySerializeTpmRsa,
#endif
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
    KeySerializeRsa,
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    KeySerializeEcc,
#endif
};

#endif /* __ENABLE_DIGICERT_SERIALIZE__ */

#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
MSTATUS SSLSOCK_sendKeyUpdateRequestDTLS(SSLSocket *pSSLSock, ubyte isRequest);
#endif
/**
 * @dont_show
 * @internal
 */
typedef struct
{
    ubyte2      age;
    sbyte4      instance;
    SSLSocket*  pSSLSock;
    sbyte4      connectionState;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    peerDescr   peerDescr;
#endif
    TCP_SOCKET  socket;
    intBoolean  isClient;

#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
    /* non-blocking read data buffers */
    ubyte*      pReadBuffer;
    ubyte*      pReadBufferPosition;
    ubyte4      numBytesRead;
#endif

#ifdef __PSOS_RTOS__
    unsigned long tid;
#endif

} sslConnectDescr;


/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
typedef struct ocspStatusRequest
{
    void*  pResponderIdList;
    ubyte4 responderIdListLen;

    /* Need to put extensions here */
    void*  pExtensionsList;
    ubyte4 extensionListLen;

} OCSPStatusRequest;

/**
 * @dont_show
 * @internal
 */
typedef struct certificateStatusRequest
{
    CertificateStatusType status_type;
    OCSPStatusRequest     ocspReq;
} CertificateStatusRequest;



/* session related bits and masks */
#define MASK_SSL_SESSION_INDEX            (0x0000ffff)
#define NUM_BITS_SSL_SESSION_INDEX        (0)

#define MASK_SSL_SESSION_AGE              (0xffff0000)
#define NUM_BITS_SSL_SESSION_AGE          (16)
#define SESSION_AGE(X)                     ((X)->age)

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__))
/**
 * @dont_show
 * @internal
 */
typedef struct
{
    peerDescr   peerDescr;
    ubyte4      startTime;
} sslConnectTimedWaitDescr;

static c_queue_t *m_sslConnectTimedWaitQueue = NULL;

#endif



/*------------------------------------------------------------------*/

static sslSettings      m_sslSettings;
static sslConnectDescr* m_sslConnectTable = NULL;
static RTOS_MUTEX       m_sslConnectTableMutex;
static sbyte4           m_sslMaxConnections;
static hashTableOfPtrs* m_sslConnectHashTable = NULL;

/* random number generator */
static RNGFun mSSL_rngFun;
static void*  mSSL_rngArg;

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))
#define SSL_EXTERN      MOC_EXTERN
#else
/* hide synchronous apis, if async enabled */
#define SSL_EXTERN      static
#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
/**
 * @dont_show
 * @internal
 */
RTOS_MUTEX gSslSessionCacheMutex;
#endif  /* __ENABLE_DIGICERT_SSL_SERVER__ */

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
ocspStorePtr              gpOcspStore;
#endif

/*------------------------------------------------------------------*/
/* INIT_HASH_VALUE is a seed value to throw off attackers */
#define INIT_HASH_VALUE   (0xab341c12)

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
typedef struct
{
    intBoolean isDTLS;
    peerDescr *pPeerDescr;
    TCP_SOCKET socket;

} testData;


/*---------------------------------------------------------------------------*/

static MSTATUS
allocHashPtrElement(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement)
{
    MSTATUS status = OK;

    if (NULL == (*ppRetNewHashElement = (hashTablePtrElement*) MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
freeHashPtrElement(void *pHashCookie, hashTablePtrElement *pFreeHashElement)
{
    if (NULL == pFreeHashElement)
        return ERR_NULL_POINTER;

    FREE(pFreeHashElement);

    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
hashtable_hashGen(intBoolean isDTLS, TCP_SOCKET socket, peerDescr *pPeerDescr, ubyte4 *pHashValue)
{
    ubyte4 addrLen = 0;
    MOC_IP_ADDRESS pMocAddr;

    if (isDTLS)
    {
        if (NULL == pPeerDescr)
            return ERR_NULL_POINTER;
        
        ubyte buf[2*sizeof(ubyte2) + 2*MOCADDRSIZE];
        DIGI_MEMCPY(buf, &pPeerDescr->srcPort, sizeof(ubyte2));
        addrLen = MOCADDRSIZE;
        pMocAddr = MOC_AND(pPeerDescr->srcAddr);
        DIGI_MEMCPY(buf+sizeof(ubyte2), MOCADDR( (MOC_STAR(pMocAddr)) ), addrLen);
        DIGI_MEMCPY(buf+sizeof(ubyte2)+addrLen, &pPeerDescr->peerPort, sizeof(ubyte2));
        /*TEST_MOC_IPADDR6(&pPeerDescr->peerAddr, {addrLen = 16; DIGI_MEMCPY(buf+sizeof(void*)+sizeof(ubyte2), GET_MOC_IPADDR6(&pPeerDescr->peerAddr), addrLen);})
        {addrLen = 4;  DIGI_MEMCPY(buf+sizeof(void*)+sizeof(ubyte2), GET_MOC_IPADDR4(&pPeerDescr->peerAddr), addrLen); }
        */
        pMocAddr = MOC_AND(pPeerDescr->peerAddr);
        DIGI_MEMCPY(buf+addrLen+2*sizeof(ubyte2), MOCADDR( (MOC_STAR(pMocAddr)) ), addrLen);

        /* pointer to udpDescr, ubyte2 port, and IP addr */
        HASH_VALUE_hashGen(buf, 2*sizeof(ubyte2) + 2*addrLen, INIT_HASH_VALUE, pHashValue);
    }
    else
    {
        HASH_VALUE_hashGen(&socket, sizeof(TCP_SOCKET), INIT_HASH_VALUE, pHashValue);
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
hashtable_insert(hashTableOfPtrs* pHashTable, intBoolean isDTLS, TCP_SOCKET socket, peerDescr *pPeerDescr, sslConnectDescr *pSslConnectDescr)
{
    ubyte4  hashValue;
    MSTATUS status;

    if (OK > (status = hashtable_hashGen(isDTLS, socket, pPeerDescr, &hashValue)))
        goto exit;

    if (OK > (status = HASH_TABLE_addPtr(pHashTable, hashValue, pSslConnectDescr)))
        goto exit;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
hashtable_extraMatchTest(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    sslConnectDescr *pSslConnectDescr = (sslConnectDescr*) pAppData;
    testData *pTestDataTemp = (testData*) pTestData;

    *pRetIsMatch = FALSE;

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    if (pTestDataTemp->isDTLS)
    {
        MOC_IP_ADDRESS srcAddrRef = REF_MOC_IPADDR(pTestDataTemp->pPeerDescr->srcAddr);
        MOC_IP_ADDRESS peerAddrRef = REF_MOC_IPADDR(pTestDataTemp->pPeerDescr->peerAddr);

        if (pTestDataTemp->pPeerDescr->srcPort == pSslConnectDescr->peerDescr.srcPort &&
            SAME_MOC_IPADDR(srcAddrRef, pSslConnectDescr->peerDescr.srcAddr) &&
            pTestDataTemp->pPeerDescr->peerPort == pSslConnectDescr->peerDescr.peerPort &&
            SAME_MOC_IPADDR(peerAddrRef, pSslConnectDescr->peerDescr.peerAddr))
        {
            *pRetIsMatch = TRUE;
        }
    } else
#endif
    if (pTestDataTemp->socket == pSslConnectDescr->socket)
    {
        *pRetIsMatch = TRUE;
    }
    return OK;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
hashtable_remove(hashTableOfPtrs* pHashTable, intBoolean isDTLS, TCP_SOCKET socket, peerDescr *pPeerDescr)
{
    ubyte4  hashValue;
    MSTATUS status;
    sslConnectDescr* pSslConnectDescrToDelete;
    intBoolean retFoundHashValue;
    testData testDataTemp;

    if (OK > (status = hashtable_hashGen(isDTLS, socket, pPeerDescr, &hashValue)))
	goto exit;

    testDataTemp.isDTLS = isDTLS;
    testDataTemp.socket = socket;
    testDataTemp.pPeerDescr = pPeerDescr;
    if (OK > (status = HASH_TABLE_deletePtr(pHashTable, hashValue, &testDataTemp, hashtable_extraMatchTest, (void**)&pSslConnectDescrToDelete, &retFoundHashValue)))
        goto exit;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/
static MSTATUS
hashtable_find(hashTableOfPtrs* pHashTable, intBoolean isDTLS, TCP_SOCKET socket, peerDescr *pPeerDescr, sslConnectDescr** ppSslConnectDescr)
{
    intBoolean  foundHashValue;
    ubyte4  hashValue;
    MSTATUS status;
    testData testDataTemp;

    hashtable_hashGen(isDTLS, socket, pPeerDescr, &hashValue);

    testDataTemp.isDTLS = isDTLS;
    testDataTemp.socket = socket;
    testDataTemp.pPeerDescr = pPeerDescr;

    if (OK > (status = HASH_TABLE_findPtr(pHashTable, hashValue, &testDataTemp, hashtable_extraMatchTest, (void**)ppSslConnectDescr, &foundHashValue)))
        goto exit;

    if (FALSE == foundHashValue)
        status = ERR_SSL_BAD_ID;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static sbyte4
getIndexFromConnectionInstance(sbyte4 connectionInstance)
{
    sbyte4 status;
    ubyte2 index = (ubyte2)((connectionInstance & MASK_SSL_SESSION_INDEX) >> NUM_BITS_SSL_SESSION_INDEX);

    if (index >= m_sslMaxConnections)
    {
        /* index wrong, a severe bug */
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    if (m_sslConnectTable == NULL)
    {
        status = ERR_SSL_BAD_STATE;
        goto exit;
    }

    if (CONNECT_CLOSED  == m_sslConnectTable[index].connectionState)
    {
        /* good index in table, but the connection is closed. */
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    if (((connectionInstance & MASK_SSL_SESSION_AGE) >> NUM_BITS_SSL_SESSION_AGE) != (ubyte4)((SESSION_AGE(&(m_sslConnectTable[index])))))
    {
        /* good index in table, but the age is wrong. */
        status = ERR_SSL_BAD_ID;
        goto exit;
    }


    status = index;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
setMessageTimer(SSLSocket *pSSLSock, sbyte4 connectionInstance, ubyte4 msTimeToExpire)
{
    MSTATUS status = OK;
#if !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
    MOC_UNUSED(connectionInstance);
#endif

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    (void) RTOS_deltaMS(NULL, &(SSL_TIMER_START_TIME(pSSLSock)));
    SSL_TIMER_MS_EXPIRE(pSSLSock)  = msTimeToExpire;  /* in milliseconds */

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
    if (IS_SSL_ASYNC(pSSLSock))
    {
        if (1 == pSSLSock->server)
        {
            if (NULL != m_sslSettings.funcPtrStartTimer)
                m_sslSettings.funcPtrStartTimer(connectionInstance, msTimeToExpire, 0);
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
    if (IS_SSL_ASYNC(pSSLSock))
    {
        if (0 == pSSLSock->server)
        {
            if (NULL != m_sslSettings.funcPtrClientStartTimer)
                m_sslSettings.funcPtrClientStartTimer(connectionInstance, msTimeToExpire, 0);
        }
    }
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
sendPendingBytes(SSLSocket* pSSLSock, sbyte4 index)
{
    ubyte4  numBytesSent = 0;
    MSTATUS status = OK;

    /* do we need to write any pending data? */
    if (!((NULL == pSSLSock->pOutputBuffer) || (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
    {
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
        if (NULL != pSSLSock->pTransportHandler)
        {
            if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
            {
                if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId,
                                                                                     (sbyte *) pSSLSock->pOutputBuffer,
                                                                                     pSSLSock->numBytesToSend, &numBytesSent)))
                {
                    DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                    goto exit;
                }

                if (numBytesSent > pSSLSock->numBytesToSend)
                    pSSLSock->numBytesToSend = numBytesSent = 0;        /**!!! should never happen */

                pSSLSock->pOutputBuffer  = numBytesSent + pSSLSock->pOutputBuffer;
                pSSLSock->numBytesToSend = pSSLSock->numBytesToSend - numBytesSent;
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
            if (OK <= (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend, &numBytesSent)))
#else
            if (OK <= (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend, &numBytesSent)))
#endif
            {
                if (numBytesSent > pSSLSock->numBytesToSend)
                    pSSLSock->numBytesToSend = numBytesSent = 0;        /**!!! should never happen */

                pSSLSock->pOutputBuffer  = numBytesSent + pSSLSock->pOutputBuffer;
                pSSLSock->numBytesToSend = pSSLSock->numBytesToSend - numBytesSent;
            }
        }
    }

    if (0 == pSSLSock->numBytesToSend)
    {
        if (NULL != pSSLSock->pOutputBufferBase)
            FREE(pSSLSock->pOutputBufferBase);

        pSSLSock->pOutputBufferBase = NULL;
        pSSLSock->pOutputBuffer     = NULL;

    }

    /* data is still pending, bail out */
    if (!((NULL == pSSLSock->pOutputBuffer) || (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)))
        goto exit;

    if ((NULL == pSSLSock->pOutputBuffer) && (NULL != pSSLSock->buffers[0].pHeader))
    {
        if (OK > (status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock)))
            goto exit;
    }

#if 1
    /**!!! need additional test here */
    if (kSslOpenState != SSL_HANDSHAKE_STATE(pSSLSock))
    {
        if (0 == pSSLSock->server)
        {
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
            status = SSL_SOCK_clientHandshake(pSSLSock, TRUE);
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
            status = SSL_SOCK_serverHandshake(pSSLSock, TRUE);
#endif
        }
    }
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
getSSLSocketFromConnectionInstance(sbyte4 connectionInstance, SSLSocket **ppSSLSock)
{
    MSTATUS status = OK;
    SSLSocket *pSSLSock = NULL;
    sbyte4 index = -1;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    *ppSSLSock = pSSLSock;

exit:
    return status;

}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)

extern sbyte4
SSL_ASYNC_getRecvPending(sbyte4 connectionInstance, sbyte4 *len)
{
    sbyte4      index;
    SSLSocket*  pSSLSock = NULL;
    MSTATUS     status   = ERR_SSL_BAD_ID;

    if (NULL == len)
        return ERR_NULL_POINTER;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_getRecvPending: connectionInstance not found.");
        goto exit;
    }

    if (IS_SSL_SYNC(pSSLSock))
        goto exit;

    status = OK;

    if (NULL == pSSLSock->pReceiveBuffer)
    {
        status = ERR_SSL_NO_DATA_TO_RECEIVE;
        goto exit;
    }

    *len =  SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) - SSL_RX_RECORD_BYTES_READ(pSSLSock);
exit:
    return (sbyte4)status;
}
#endif



/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
/**
@brief      Get a pointer to the connection's receive data buffer (the socket
            buffer itself).

@details    This function returns a pointer (through the \p data parameter) to
            the specified connection's most recently received data buffer (the
            socket buffer itself).

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param data                 On return, pointer to the address of the
                              connection's receive buffer.
@param len                  On return pointer to number of bytes in \p data.
@param pRetProtocol         On return, the SSL protocol type for \p data
                            (usually 23 == SSL Application Data)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_getRecvBuffer(sbyte4 connectionInstance, ubyte **data, ubyte4 *len, ubyte4 *pRetProtocol)
{
    sbyte4      index;
    SSLSocket*  pSSLSock = NULL;
    MSTATUS     status   = ERR_SSL_BAD_ID;

    if ((NULL == data) || (NULL == len))
        return ERR_NULL_POINTER;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (m_sslConnectTable[index].connectionState == CONNECT_CLOSED)
    {
        status = ERR_SSL_NOT_OPEN;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_getRecvBuffer: connectionInstance not found.");
        goto exit;
    }

    if (IS_SSL_SYNC(pSSLSock))
        goto exit;

    status = OK;

    if (SSL_RX_RECORD_STATE(pSSLSock) != SSL_ASYNC_RECEIVE_RECORD_COMPLETED)
    {
        *data = NULL;
        *len = 0;
        goto exit;
    }

    if (NULL == pSSLSock->pReceiveBuffer)
    {
        status = ERR_SSL_NO_DATA_TO_RECEIVE;
        goto exit;
    }

    *data = (ubyte *)pSSLSock->pReceiveBuffer;
    *len = pSSLSock->recordSize - pSSLSock->offset;

    pSSLSock->recordSize = pSSLSock->offset = 0;

    if (pRetProtocol)
        *pRetProtocol = pSSLSock->protocol;

exit:
    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSL_INTERNAL_setConnectionState(sbyte4 connectionInstance, sbyte4 connectionState)
{
    sbyte4      index;
    MSTATUS     status   = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    m_sslConnectTable[index].connectionState = connectionState;
    status = OK;
exit:
    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
/**
@brief      Get a copy of the connection's send data buffer.

@details    This function returns a copy (through the \p data parameter) of the
            specified connection's most recently sent data buffer.

@ingroup    func_ssl_async

@since 1.41
@version 6.4 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param data                 On return, pointer to the buffer containing the data
                              in the connection's send buffer.
@param len                  On return pointer to number of bytes in \p data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_getSendBuffer(sbyte4 connectionInstance, ubyte *data, ubyte4 *len)
{
    ubyte4      numBytesSent;
    SSLSocket*  pSSLSock = NULL;
    MSTATUS     status   = ERR_SSL_BAD_ID;
    ubyte       cpyBuffer = 1;

    /* Add use case where we just want the data len */
    if (NULL == len) {
        return ERR_NULL_POINTER;
    } else {
        if (NULL != data) {
	    /* Normal case */
	    numBytesSent = *len;
        } else {
	    /* Special case - Give len only */
            numBytesSent = 0xFFFFFF; /* LARGE - see below */
            cpyBuffer = 0;
	}
    }

    *len = 0;

    if (OK > (status = (MSTATUS) getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (m_sslConnectTable[status].connectionState == CONNECT_CLOSED)
    {
        status = ERR_SSL_NOT_OPEN;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[status].pSSLSock;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_getSendBuffer: connectionInstance not found.");
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (IS_SSL_SYNC(pSSLSock))
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    status   = OK;

    if (NULL == pSSLSock->pOutputBuffer)
    {
        status = ERR_SSL_NO_DATA_TO_SEND;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    /* for DTLS, mindful of record boundaries and pmtu !!! */
    if (pSSLSock->isDTLS)
    {
        if (numBytesSent > pSSLSock->dtlsPMTU)
            numBytesSent = pSSLSock->dtlsPMTU;

        if (numBytesSent > pSSLSock->numBytesToSend)
        {
            numBytesSent = pSSLSock->numBytesToSend ;        /**!!! should never happen */
        } else
        {
            if (OK > (status = getNumBytesSent(pSSLSock, pSSLSock->pOutputBuffer, numBytesSent, &numBytesSent)))
                goto exit;
        }
    } else
#endif
    {
        if (numBytesSent > pSSLSock->numBytesToSend)
            numBytesSent = pSSLSock->numBytesToSend ;        /**!!! should never happen */
    }

    if (cpyBuffer) {
        /* Normal case: Copy data and advance buffer */
        DIGI_MEMCPY(data,pSSLSock->pOutputBuffer,numBytesSent);
        pSSLSock->pOutputBuffer  = numBytesSent + pSSLSock->pOutputBuffer;
        pSSLSock->numBytesToSend = pSSLSock->numBytesToSend - numBytesSent;
	*len = numBytesSent;
    } else {
        /* Special case: Get length and return, not changing the buffer */
        *len = numBytesSent;
	goto exit;
    }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        if (0 == pSSLSock->numBytesToSend)
        {
            if (OK > (status = cleanupOutputBuffer(pSSLSock)))
                goto exit;
        }
    } else
#endif
    {
        if (0 == pSSLSock->numBytesToSend)
        {
            if (NULL != pSSLSock->pOutputBufferBase)
                FREE(pSSLSock->pOutputBufferBase);

            pSSLSock->pOutputBufferBase = NULL;
            pSSLSock->pOutputBuffer     = NULL;
        }
    }
exit:
    return (sbyte4)status;

} /* SSL_ASYNC_getSendBuffer */

/*------------------------------------------------------------------*/

/**
@brief      Get a pointer reference to the connection's send data buffer.

@details    This function returns the pointer (through the \p data parameter) of the
            specified connection's most recently sent data buffer. It is suitable for
	    Zero-Copy implementations. After the caller gets the pointer and transmits
	    all (or some) of the data, it must call SSL_ASYNC_freeSendBufferZeroCopy()
	    to indicate how much of data still remains to be transmitted before it
	    makes another call to SSL_ASYNC_getSendBuffer() to send fresh data.

@ingroup    func_ssl_async

@since 1.41
@version 7.0 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect() or
                            SSL_ASYNC_accept().
@param data                 On return, contains the address of the buffer containing
                            the data in the connection's send buffer. i.e \p *data
                            has the pointer to the connection's send buffer)
@param len                  Pass in a pointer to a ubyte4. On return this contains the
                            number of bytes in the connection's send buffer (i.e \p data)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_getSendBufferZeroCopy(sbyte4 connectionInstance, ubyte **data, ubyte4 *len)
{
    SSLSocket*  pSSLSock = NULL;
    MSTATUS     status   = ERR_SSL_BAD_ID;

    /* Add use case where we just want the data len */
    if ((NULL == len) || (NULL == data)) {
        return ERR_NULL_POINTER;
    }
    *len = 0;

    if (OK > (status = (MSTATUS) getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[status].pSSLSock;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_getSendBufferZeroCopy: connectionInstance not found.");
        goto exit;
    }

    if (IS_SSL_SYNC(pSSLSock))
        goto exit;

    status   = OK;
    if (NULL == pSSLSock->pOutputBuffer)
    {
        status = ERR_SSL_NO_DATA_TO_SEND;
        goto exit;
    }
    *len 	= pSSLSock->numBytesToSend;
    *data	= pSSLSock->pOutputBuffer;

exit:
    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

/**
@brief      Get a pointer reference to the connection's send data buffer.

@details    This function is used to indicate how many bytes of the most recently produced
            send data buffer was consumed by the caller. This call typically follows
            the call to SSL_ASYNC_getSendBufferZeroCopy() that returns the pointer to
            the send data buffer that is waiting to be transmitted. If \p numUnusedBytes
            is 0, then the send data buffer is freed. If it is not zero, then that much
            data is retained and the next call to SSL_ASYNC_getSendBufferZeroCopy() will
            return the saved data. This call is suitable for Zero-Copy implementations.

@ingroup    func_ssl_async

@since 1.41
@version 7.0 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect() or
                            SSL_ASYNC_accept().
@param numUnusedBytes       A ubyte4 value that indicates how many bytes is left over
                            from the data buffer obtained from a previous call to
                            SSL_ASYNC_getSendBufferZeroCopy().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_freeSendBufferZeroCopy(sbyte4 connectionInstance, ubyte4 numUnusedBytes)
{
     SSLSocket*  pSSLSock = NULL;
     MSTATUS     status   = ERR_SSL_BAD_ID;

     if (OK > (status = (MSTATUS) getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

     pSSLSock = m_sslConnectTable[status].pSSLSock;

     if (NULL == pSSLSock)
     {
	  DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_freeSendBufferZC: connectionInstance not found.");
	  goto exit;
     }

     if (IS_SSL_SYNC(pSSLSock))
	  goto exit;

     status   = OK;
     if (0 == numUnusedBytes)
     {
	  if (NULL != pSSLSock->pOutputBufferBase)
	       FREE(pSSLSock->pOutputBufferBase);
     	  pSSLSock->pOutputBufferBase 	= NULL;
	  pSSLSock->pOutputBuffer     	= NULL;
	  pSSLSock->numBytesToSend 	= 0;
     } else if (NULL != pSSLSock->pOutputBufferBase)
     {
	  if (numUnusedBytes > pSSLSock->numBytesToSend)
	       numUnusedBytes = pSSLSock->numBytesToSend;
	  pSSLSock->pOutputBuffer  += (pSSLSock->numBytesToSend - numUnusedBytes);
	  pSSLSock->numBytesToSend = numUnusedBytes;
     }
exit:
     return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))
static MSTATUS
doProtocol(SSLSocket *pSSLSock, sbyte4 index, intBoolean useTimeout,
           ubyte4 timeout, sbyte *pRetBuffer, sbyte4 bufferSize,
           sbyte4 *pRetNumBytesReceived)
{
    sbyte4  startState = m_sslConnectTable[index].connectionState;
    ubyte4  adjustedTimeout;
    MSTATUS status = OK;
    ubyte4  newTimeout = 0;
#if defined(__ENABLE_DIGICERT_SSL_PENDING_DATA_YIELD__)
    ubyte4 retryCount = 0;
#endif

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TRUE == useTimeout)
    {
        (void) RTOS_deltaMS(NULL, &(SSL_TIMER_START_TIME(pSSLSock)));
        SSL_TIMER_MS_EXPIRE(pSSLSock) = timeout;
    }

    do
    {
        /* don't spin loop, if writes fail, yield the processor briefly */
        if ((CONNECT_NEGOTIATE == m_sslConnectTable[index].connectionState) && (NULL != pSSLSock->pOutputBuffer))
            RTOS_sleepMS(SSL_WRITE_FAIL_RETRY_TIME);

#if defined(__ENABLE_DIGICERT_SSL_PENDING_DATA_YIELD__)
        /* This is for application data - will only trigger if multiple tries while flushing the send buffer */
        if ((CONNECT_OPEN == m_sslConnectTable[index].connectionState) && (NULL != pSSLSock->pOutputBuffer) && (retryCount > 0))
            RTOS_sleepMS(SSL_WRITE_FAIL_RETRY_TIME);
#endif

#ifndef __ENABLE_NONBLOCKING_SOCKET_CONNECT__
        /* handle across events time outs */
        timeout   = SSL_TIMER_MS_EXPIRE(pSSLSock);

        if (TCP_NO_TIMEOUT != timeout)
        {
            adjustedTimeout = RTOS_deltaMS(&(SSL_TIMER_START_TIME(pSSLSock)), NULL);

            if (adjustedTimeout >= timeout)
            {
                newTimeout = 0;
                if (m_sslSettings.funcPtrSSLHandleTimeout != NULL)
                {
                    if (OK <= (status = m_sslSettings.funcPtrSSLHandleTimeout(m_sslConnectTable[index].instance,
                                                                              &newTimeout)))
                    {
                        if (newTimeout > 0)
                        {
                           (void) RTOS_deltaMS(NULL, &(SSL_TIMER_START_TIME(pSSLSock)));
                           SSL_TIMER_MS_EXPIRE(pSSLSock) = newTimeout;
                           adjustedTimeout = newTimeout;
                        }
                    }
                }

                if (newTimeout == 0)
                {
                    status = ERR_TCP_READ_TIMEOUT;
                    goto exit;
                }

            }
            else
            {
                adjustedTimeout = timeout - adjustedTimeout;
            }
        }
        else
        {
            adjustedTimeout = TCP_NO_TIMEOUT;  /* timeout */
        }
#endif
        if (OK > (status = sendPendingBytes(pSSLSock, index)))
            goto exit;

        if ((NULL != pSSLSock->pOutputBuffer) || (startState != m_sslConnectTable[index].connectionState))
        {
            status = OK;
#if defined(__ENABLE_DIGICERT_SSL_PENDING_DATA_YIELD__)
            retryCount++;
#endif
            continue;
        }

        if ((CONNECT_OPEN == startState) &&
            (kRecordStateReceiveFrameComplete == SSL_SYNC_RECORD_STATE(pSSLSock)) &&
            (0 < (pSSLSock->recordSize - pSSLSock->offset)))
        {
            ubyte*  pDummy = NULL;
            ubyte4  dummy  = 0;

            status = (MSTATUS)SSL_SOCK_receive(pSSLSock, pRetBuffer,
                                               bufferSize, &pDummy, &dummy, pRetNumBytesReceived);
        }
        else
        {
            if (0 == m_sslConnectTable[index].numBytesRead)
            {
TCP_READ:
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
                if (NULL != pSSLSock->pTransportHandler)
                {
                    if (NULL != pSSLSock->pTransportHandler->funcPtrTransportRecv)
                    {
                        if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportRecv(pSSLSock->pTransportHandler->sslId,
                                                                                            (sbyte *)m_sslConnectTable[index].pReadBuffer,
                                                                                            SSL_SYNC_BUFFER_SIZE,
                                                                                            &m_sslConnectTable[index].numBytesRead,
                                                                                            adjustedTimeout)))
                        {
                            DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Recv Transport Handler failed, status = ", status);
                            goto exit;
                        }
                        m_sslConnectTable[index].pReadBufferPosition = m_sslConnectTable[index].pReadBuffer;
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
                    if (OK <= (status = TCP_READ_AVL_EX(pSSLSock->tcpSock,
                                                 (sbyte *)m_sslConnectTable[index].pReadBuffer,
                                                 SSL_SYNC_BUFFER_SIZE,
                                                 &m_sslConnectTable[index].numBytesRead,
                                                 adjustedTimeout)))
#else
                    if (OK <= (status = DIGI_TCP_READ_AVL(pSSLSock->tcpSock,
                                                 (sbyte *)m_sslConnectTable[index].pReadBuffer,
                                                 SSL_SYNC_BUFFER_SIZE,
                                                 &m_sslConnectTable[index].numBytesRead,
                                                 adjustedTimeout)))
#endif
                    {
                        m_sslConnectTable[index].pReadBufferPosition = m_sslConnectTable[index].pReadBuffer;
                    }

                    else if ((status == ERR_TCP_READ_TIMEOUT) && (m_sslSettings.funcPtrSSLHandleTimeout != NULL))
                    {
                        if (OK <= (status = m_sslSettings.funcPtrSSLHandleTimeout(m_sslConnectTable[index].instance,
                                                                              &adjustedTimeout)))
                        { /* retry TCP READ */
                            if (adjustedTimeout > 0)
                                goto TCP_READ;
                        }
                        goto exit;
                    }
                    else
                    {
                        goto exit;
                    }
                }
            }
            status = (MSTATUS)SSL_SOCK_receive(pSSLSock,
                                                pRetBuffer, bufferSize,
                                                &m_sslConnectTable[index].pReadBufferPosition,
                                                &m_sslConnectTable[index].numBytesRead,
                                                pRetNumBytesReceived);
        }

        if (TRUE == m_sslConnectTable[index].pSSLSock->alertCloseConnection)
        {
            *pRetNumBytesReceived = 0;
            goto exit;
        }

        if (CONNECT_NEGOTIATE == startState)
        {
            *pRetNumBytesReceived = 0;
        }

        if (OK < status)
            status = OK;
    }
    while ((OK == status) && (0 == *pRetNumBytesReceived) && (startState == m_sslConnectTable[index].connectionState));

exit:
    if (OK > status)
    {
        /* Do not set error status if it is a TCP read timeout. */
        if ((pSSLSock != NULL) && (status != ERR_TCP_READ_TIMEOUT))
            pSSLSock->lastErrorStatus = status;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL:doProtocol() returns status = ", (sbyte4)status);
#endif
    }

    return status;

} /* doProtocol */
#endif


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_findConnectionInstance(SSLSocket *pSSLSock)
{
    sslConnectDescr* pSslConnectDescr;

    if ((NULL == pSSLSock) || (NULL == m_sslConnectHashTable))
        goto exit;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        if (OK > (hashtable_find(m_sslConnectHashTable, pSSLSock->isDTLS, (TCP_SOCKET)-1, &pSSLSock->peerDescr, &pSslConnectDescr)))
            goto exit;
    } else
#endif
    {
        if (OK > (hashtable_find(m_sslConnectHashTable, FALSE, pSSLSock->tcpSock, NULL, &pSslConnectDescr)))
            goto exit;
    }

    if (CONNECT_CLOSED != pSslConnectDescr->connectionState)
    {
        return pSslConnectDescr->instance;
    }

exit:
    return (sbyte4)ERR_SSL_BAD_ID;
}

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__

static sbyte4
SSL_findConnectTimedWait(MOC_IP_ADDRESS srcAddr, ubyte2 srcPort, MOC_IP_ADDRESS peerAddr, ubyte2 peerPort)
{
    MSTATUS status = OK;
    ubyte4 head;
    ubyte4 tail;
    ubyte4 capacity;
    ubyte4 curTime;

    if (NULL == m_sslConnectTimedWaitQueue)
    {
        return ERR_NULL_POINTER;
    }

    curTime = RTOS_getUpTimeInMS();

    head = m_sslConnectTimedWaitQueue->head;
    tail = m_sslConnectTimedWaitQueue->tail;
    capacity = m_sslConnectTimedWaitQueue->capacity;

    /* check time and purge all expired connections */
    for (; head != tail; head = (head + 1) % (capacity + 1))
    {
        sslConnectTimedWaitDescr *descr = (sslConnectTimedWaitDescr *)m_sslConnectTimedWaitQueue->ppQueue[head];
        if ((curTime - descr->startTime) > 2*60*1000) /* timeout after 2 minutes */
        {
            CIRCQ_deq(m_sslConnectTimedWaitQueue, (ubyte**)&descr);
            FREE(descr);
        }
        else
            break;
    }
    for (; head != tail; head = (head + 1) % (capacity + 1))
    {
        sslConnectTimedWaitDescr *descr = (sslConnectTimedWaitDescr *)m_sslConnectTimedWaitQueue->ppQueue[head];
        if (descr->peerDescr.srcPort == srcPort &&
            SAME_MOC_IPADDR(srcAddr, descr->peerDescr.srcAddr) &&
            SAME_MOC_IPADDR(peerAddr, descr->peerDescr.peerAddr) &&
            descr->peerDescr.peerPort == peerPort)
        {
            status = ERR_DTLS_CONNECT_TIMED_WAIT;
            goto exit;
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (DTLS stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_getConnectionInstance(MOC_IP_ADDRESS srcAddr, ubyte2 srcPort, MOC_IP_ADDRESS peerAddr, ubyte2 peerPort)
{
    MSTATUS status;
    sslConnectDescr *pSslConnectDescr;
    peerDescr tempPeerDescr;

    if (OK > (status = SSL_findConnectTimedWait(srcAddr, srcPort, peerAddr, peerPort)))
        goto exit;

    tempPeerDescr.srcPort = srcPort;
    COPY_MOC_IPADDR(tempPeerDescr.srcAddr, srcAddr);
    tempPeerDescr.peerPort = peerPort;
    COPY_MOC_IPADDR(tempPeerDescr.peerAddr, peerAddr);

    if (OK > (status = hashtable_find(m_sslConnectHashTable, TRUE, (TCP_SOCKET)-1, &tempPeerDescr, &pSslConnectDescr)))
        goto exit;

    return pSslConnectDescr->instance;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (DTLS stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_removeConnectTimedWait(MOC_IP_ADDRESS srcAddr, ubyte2 srcPort, MOC_IP_ADDRESS peerAddr, ubyte2 peerPort)
{
    MSTATUS status = OK;
    ubyte4 head;
    ubyte4 tail;
    ubyte4 capacity;

    head = m_sslConnectTimedWaitQueue->head;
    tail = m_sslConnectTimedWaitQueue->tail;
    capacity = m_sslConnectTimedWaitQueue->capacity;

    /* check time and purge all expired connections */
    for (; head != tail; head = (head + 1) % (capacity + 1))
    {
        sslConnectTimedWaitDescr *descr = (sslConnectTimedWaitDescr *)m_sslConnectTimedWaitQueue->ppQueue[head];
        if (descr->peerDescr.srcPort == srcPort &&
            SAME_MOC_IPADDR(srcAddr, descr->peerDescr.srcAddr) &&
            SAME_MOC_IPADDR(peerAddr, descr->peerDescr.peerAddr) &&
            descr->peerDescr.peerPort == peerPort)
        {
            CIRCQ_deq(m_sslConnectTimedWaitQueue, (ubyte**)&descr);
            FREE(descr);
            break;
        }
    }

    return status;
}
#endif


#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
extern MSTATUS
SSL_TAP_clearKeyAndToken()
{
    return SSLSOCK_clearTAPKeyAndToken();
}
#endif

/*------------------------------------------------------------------*/

static intBoolean initialized  = FALSE;
static intBoolean initializing = FALSE;

/**
@brief      Clean up memory and mutexes and shut down the SSL stack.

@details    This function performs memory and mutex cleanup and shuts down the
            SSL stack. In rare instances, for example changing the port number
            to which an embedded device listens, you may need to completely
            stop the SSL/TLS Client/Server and all its resources. However, in
            most circumstances this is unnecessary because the NanoSSL
            %client/server is threadless.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
sbyte4 status = 0;

status = SSL_shutdownStack();
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_shutdownStack(void)
{
    DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSL stack shutting down.");

    /* Invoke Release table - free up memory */
    SSL_releaseTables();

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
    OCSP_STORE_releaseStore(&gpOcspStore);
#endif

    (void) RTOS_mutexFree( &m_sslConnectTableMutex);

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    (void) RTOS_mutexFree(&gSslSessionCacheMutex);
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
    if (m_sslSettings.pDHP)
    {
        DIGI_FREE((void **)&m_sslSettings.pDHP);
    }

    if (m_sslSettings.pDHG)
    {
        DIGI_FREE((void **)&m_sslSettings.pDHG);
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    if ((m_sslSettings.pClientCANameList != NULL) && (m_sslSettings.numClientCANames > 0))
    {
        ubyte4 length = m_sslSettings.numClientCANames;
        ubyte4 i = 0;

        for (i = 0; i < length; i++)
        {
            SB_Release(&(m_sslSettings.pClientCANameList[i]));
        }
        DIGI_FREE((void **) &(m_sslSettings.pClientCANameList));
    }
#endif

    m_sslConnectTable = NULL;
    m_sslConnectHashTable = NULL;
    initialized = FALSE;
    initializing = FALSE;

    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

/**
@brief      Release memory used by internal SSL/TLS memory tables.

@details    This function releases the SSL/TLS Client's or Server's internal
            memory tables. To resume communication with a device after
            calling this function, you must create a new connection and
            register encryption keys and an X.509 certificate.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
sbyte4 status;

status = SSL_releaseTables();
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_releaseTables(void)
{
    void *pRetHashCookie = NULL;
    MSTATUS status = OK;

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    sslConnectTimedWaitDescr *pDescr;
#endif

    if ((NULL != m_sslConnectTable) || (NULL != m_sslConnectHashTable))
    {
        /* Free Memory Tables */
        if (OK > (status = RTOS_mutexWait(m_sslConnectTableMutex)))
        {
            DIGICERT_log((sbyte4) MOCANA_SSL,
                       (sbyte4) LS_INFO,
                       (sbyte *) "RTOS_mutexWait() failed.");
            goto exit;
        }

        if (NULL != m_sslConnectTable)
        {
            FREE(m_sslConnectTable);
            m_sslConnectTable = NULL;
        }

        if (NULL != m_sslConnectHashTable)
        {
            (void) HASH_TABLE_removePtrsTable(m_sslConnectHashTable,
                                          &pRetHashCookie);
            m_sslConnectHashTable = NULL;
        }

        if (OK > (status = RTOS_mutexRelease(m_sslConnectTableMutex)))
        {
           DIGICERT_log((sbyte4) MOCANA_SSL,
                   (sbyte4) LS_INFO,
                    (sbyte *) "RTOS_mutexRelease() failed.");
            goto exit;
        }
    }

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    while (OK == CIRCQ_deq(m_sslConnectTimedWaitQueue, (ubyte**)&pDescr))
    {
        FREE(pDescr);
    }
    CIRCQ_deInit(m_sslConnectTimedWaitQueue);

    m_sslConnectTimedWaitQueue = NULL;
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/
#if ((!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)) || \
     defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__))
/**
@brief      Get a socket's connection instance.

@details    This function returns a connection instance for the specified
            socket identifier. The connection instance can be used as a
            parameter in subsequent calls to NanoSSL %client and server
            functions. This function is not applicable to ASYNC mode of operation
	    where the socket descriptor is not managed by (or known) to the SSL layer

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param socket   TCP/IP socket for which you want to retrieve a connection instance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
sbyte4 connectionInstance;
TCP_SOCKET socketClient;

connectionInstance = SSL_getInstanceFromSocket(socketClient);
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_getInstanceFromSocket(TCP_SOCKET socket)
{
    sbyte4  status;
    sslConnectDescr *pSslConnectDescr;
#ifdef __PSOS_RTOS__
    unsigned long tid;

    t_ident((char *)0, 0, &tid);
#endif

    if (OK > (status = hashtable_find(m_sslConnectHashTable, FALSE, socket, NULL, &pSslConnectDescr)))
        goto exit;

    if ((socket == pSslConnectDescr->socket) &&
#ifdef __PSOS_RTOS__
        (tid == pSslConnectDescr->tid) &&
#endif
        (CONNECT_CLOSED < pSslConnectDescr->connectionState))
    {
        status = pSslConnectDescr->instance;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if ((sbyte4)OK > status)
    {
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_getInstanceFromSocket() returns status = ", (sbyte4)status);
    }
#endif

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

/**
@brief      Get custom information for a connection instance.

@details    This function retrieves custom information stored in the
            connection instance's context. Your application should not call
            this function until after calls to SSL_setCookie().

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pCookie              On return, pointer to the cookie containing the
                              context's custom information.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
mySessionInfo *myCookie = NULL;

SSL_getCookie(connectionInstance, (int *)(&myCookie));
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_getCookie(sbyte4 connectionInstance, void* *pCookie)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pCookie)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    *pCookie = m_sslConnectTable[index].pSSLSock->cookie;
    status = OK;

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/**
@brief      Store custom information for a connection instance.

@details    This function stores information about the context connection.
            Your application should not call this function until after calling
            SSL_connect().

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param cookie               Custom information (cookie data) to store.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
mySessionInfo *mySession = malloc(sizeof(mySessionInfo));

SSL_setCookie(connectionInstance, (int)(&mySession));
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_setCookie(sbyte4 connectionInstance, void* cookie)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    m_sslConnectTable[index].pSSLSock->cookie = cookie;
    status = OK;
exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/**
@brief      Get a pointer to current context's configuration settings.

@details    This function returns a pointer to NanoSSL %client/server settings
            that can be dynamically adjusted during initialization or runtime.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@return     Pointer to NanoSSL %client/server settings that can be
            dynamically adjusted during initialization or runtime.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sslSettings *
SSL_sslSettings(void)
{
    return &m_sslSettings;
}


/*------------------------------------------------------------------*/
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_getSessionInfo(sbyte4 connectionInstance, ubyte* sessionIdLen,
                         ubyte sessionId[SSL_MAXSESSIONIDSIZE],
                         ubyte masterSecret[SSL_MASTERSECRETSIZE])
{
    sbyte4      index;
    MSTATUS     status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if ( pSSLSock)
    {
        ubyte* pInstanceSessionId = NULL;

        *sessionIdLen = 0;
        if (pSSLSock->server)
        {
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
            *sessionIdLen = sizeof(SESSIONID);
            pInstanceSessionId = (ubyte*)&pSSLSock->roleSpecificInfo.server.sessionId;
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
            *sessionIdLen = pSSLSock->roleSpecificInfo.client.sessionIdLen;
            pInstanceSessionId = pSSLSock->roleSpecificInfo.client.sessionId;
#endif
        }

        DIGI_MEMCPY( sessionId,
            pInstanceSessionId,
            *sessionIdLen);
        DIGI_MEMCPY( masterSecret,
            pSSLSock->pSecretAndRand,
            SSL_MASTERSECRETSIZE);
        status = OK;
    }

exit:
    return status;

} /* SSL_getSessionInfo */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
/**
@brief      Get connection instance's identifying information.

@details    This function retrieves identifying information for the connection
            instance's context. This information can be saved for SSL session
            reuse, allowing subsequent connections to be made much more
            quickly than the initial connection.

@ingroup    func_ssl_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect
@param sessionIdLen         Pointer to number of bytes in \p sessionId.
@param sessionId            Buffer for returned session ID.
@param masterSecret         Buffer for returned master secret.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous clients.

@funcdoc ssl.c
*/
extern sbyte4
SSL_getClientSessionInfo(sbyte4 connectionInstance, ubyte* sessionIdLen,
                         ubyte sessionId[SSL_MAXSESSIONIDSIZE],
                         ubyte masterSecret[SSL_MASTERSECRETSIZE])
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* This is SSL client &&
     * Connection is established and state is set to CONNECT_OPEN
     */
    if ((m_sslConnectTable[index].isClient == TRUE) &&
        (CONNECT_OPEN == m_sslConnectTable[index].connectionState))
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;
        if ( pSSLSock)
        {
            *sessionIdLen = pSSLSock->roleSpecificInfo.client.sessionIdLen;
            DIGI_MEMCPY( sessionId,
                pSSLSock->roleSpecificInfo.client.sessionId,
                *sessionIdLen);
            DIGI_MEMCPY( masterSecret,
                pSSLSock->pSecretAndRand,
                SSL_MASTERSECRETSIZE);
            status = OK;
        }
    }

exit:
    return status;

} /* SSL_getClientSessionInfo */

#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

extern sbyte4
SSL_getTlsUnique(sbyte4 connectionInstance, ubyte4 *pTlsUniqueLen,
                 ubyte **ppTlsUnique)
{
    sbyte4 index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket *pSSLSock = NULL;

    if ( (NULL == pTlsUniqueLen) || (NULL == ppTlsUnique) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppTlsUnique = NULL;
    *pTlsUniqueLen = 0;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (NULL == pSSLSock)
        goto exit;

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
         (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))) &&
        (TRUE == pSSLSock->supportExtendedMasterSecret) &&
        (FALSE == pSSLSock->useExtendedMasterSecret))
    {
        /* Version negotiated is TLS 1.2 or lower OR DTLS 1.2
         * Application enabled extended_master_secret at runtime,
         * but stack could not negotiate to use extended_master_secret,
         * do NOT export key material or TLS-unique
         */
        status = ERR_SSL_EXPORT_KEY_MATERIAL;
        goto exit;
    }
#endif

    /* Ensure the connection is in an open state
     */
    if (CONNECT_OPEN <= m_sslConnectTable[index].connectionState)
    {
        /* Allocate and copy the client finished message
            */
        status = DIGI_MALLOC(
            (void **) ppTlsUnique, pSSLSock->client_verify_data_len);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGI_MEMCPY(
            *ppTlsUnique, pSSLSock->client_verify_data,
            pSSLSock->client_verify_data_len);
        if (OK != status)
        {
            DIGI_FREE((void **) ppTlsUnique);
            goto exit;
        }

        *pTlsUniqueLen = pSSLSock->client_verify_data_len;
    }

exit:

    return status;
} /* SSL_getTlsUnique */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__) && \
    defined(__ENABLE_DIGICERT_SSL_CLIENT__)

/**
@brief      Specify a list of DNS names acceptable to the %client.

@details    This function specifies a list of DNS names that when matched to
            the certificate subject name will enable a connection.

@ingroup    func_ssl_core_client

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param cnMatchInfos         Pointer to CNMatchInfo structure (defined in
                              ca_mgmt.h) containing acceptable DNS names. The \p
                              flags field is a bit combination of \p matchFlag
                              enumerations (see ca_mgmt.h). The length of the
                              array is indicated by setting the \p name field of
                              the array's final element to \c NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
MatchInfo myMatchInfo[] = {  { 0, "yael.AMT.com"}, {1, ".intel.com"}, {0, NULL} };
SSL_setDNSNames( myConnection, myMatchInfo);
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_setDNSNames( sbyte4 connectionInstance, const CNMatchInfo* cnMatchInfos)
{
    sbyte4  index;
    ubyte4  i, j;
    CNMatchInfo *pCNMatchInfo = NULL;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (m_sslConnectTable[index].isClient == TRUE)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;
        if ( pSSLSock)
        {
            if (NULL != cnMatchInfos)
            {
                i = 0;
                while (NULL != cnMatchInfos[i].name)
                    i++;

                status = DIGI_CALLOC((void **) &pCNMatchInfo, 1, ((i + 1) * sizeof(CNMatchInfo)));
                if (OK > status)
                    goto exit;

                for (j = 0; j < i; j++)
                {
                    pCNMatchInfo[j].flags = cnMatchInfos[j].flags;

                    status = DIGI_MALLOC(
                        (void **) &(pCNMatchInfo[j].name),
                        DIGI_STRLEN(cnMatchInfos[j].name) + 1);
                    if (OK > status)
                        goto exit;

                    DIGI_STRCBCPY(
                        (sbyte *) pCNMatchInfo[j].name,
                        DIGI_STRLEN(cnMatchInfos[j].name) + 1,
                        cnMatchInfos[j].name);
                }

                /* Last argument should be NULL */
                pCNMatchInfo[j].flags = cnMatchInfos[i].flags;
                pCNMatchInfo[j].name = cnMatchInfos[i].name;
            }

            if (NULL != pSSLSock->roleSpecificInfo.client.pCNMatchInfos)
            {
                const CNMatchInfo *pInfo = pSSLSock->roleSpecificInfo.client.pCNMatchInfos;

                while (NULL != pInfo->name)
                {
                    DIGI_FREE((void **) &(pInfo->name));
                    pInfo++;
                }
                DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pCNMatchInfos));
            }

            pSSLSock->roleSpecificInfo.client.pCNMatchInfos = pCNMatchInfo;
            status = OK;
        }
    }

exit:

    if (OK > status)
    {
        if (pCNMatchInfo != NULL)
        {
            while (NULL != pCNMatchInfo->name)
            {
                DIGI_FREE((void **) &(pCNMatchInfo->name));
                pCNMatchInfo++;
            }
            DIGI_FREE((void **)&pCNMatchInfo);
        }
    }
    return status;

} /* SSL_setDNSNames */

#endif  /* defined(__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__) && \
    defined(__ENABLE_DIGICERT_SSL_CLIENT__) */


/*----------------------------------------------------------------------------*/

static sbyte4
SSL_initAux(sbyte4 numServerConnections, sbyte4 numClientConnections)
{
    sbyte4  sslMaxConnections = 0;
    sbyte4  index;
    MSTATUS status = OK;

    if (initialized == TRUE)
    {
        goto exit;
    }

    if (initializing == TRUE)
    {
        /* Initialization in progress; Sleep for 500 ms */
        RTOS_sleepMS(500);
        goto exit;
    }
    else
    {
        /* This being called first time. Set initializing to true */
        initializing = TRUE;
    }

    if (0 > numServerConnections)
        numServerConnections = 0;

    if (0 > numClientConnections)
        numClientConnections = 0;

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    sslMaxConnections += numServerConnections;
#else
    numServerConnections = 0;
#endif

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    sslMaxConnections += numClientConnections;
#else
    numClientConnections = 0;
#endif

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    DIGI_MEMSET((ubyte *)&gSslSessionCacheMutex, 0x00, sizeof(RTOS_MUTEX));
#endif
    DIGI_MEMSET((ubyte *)&m_sslConnectTableMutex, 0x00, sizeof(RTOS_MUTEX));

    if (0 == sslMaxConnections)
    {
        status = ERR_SSL_CONFIG;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
    if (SSL_MAX_NUM_CIPHERS < SSL_SOCK_numCiphersAvailable())
    {
        status = ERR_SSL_CONFIG;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    if (OK > (status = RTOS_mutexCreate(&gSslSessionCacheMutex, SSL_CACHE_MUTEX, 0)))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    if (OK > (status = SSL_SOCK_initServerEngine(mSSL_rngFun, mSSL_rngArg)))
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
    if (OK > (status = OCSP_STORE_createStore(&gpOcspStore)))
    {
        goto exit;
    }
#endif

    if (OK > (status = RTOS_mutexCreate(&m_sslConnectTableMutex, SSL_CACHE_MUTEX, 1)))
        goto exit;

    if (NULL == m_sslConnectTable)
    {
        ubyte4 remain;
        ubyte4 count = 0;
        m_sslMaxConnections = sslMaxConnections;

        if (NULL == (m_sslConnectTable = (sslConnectDescr*) MALLOC(sslMaxConnections * sizeof(sslConnectDescr))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        /* create hashtable for quick access from TCP_SOCKET or peerDescr to sslConnectDescr */
        /* find out the hashtable size */
        remain = sslMaxConnections;
        while (remain > 0)
        {
            remain = remain >> 1;
            count++;
        }
        if (OK > (status = HASH_TABLE_createPtrsTable(&m_sslConnectHashTable, (1 << count) - 1, NULL, allocHashPtrElement, freeHashPtrElement)))
            goto exit;
    }
    else
    {
        if (m_sslMaxConnections < sslMaxConnections)
        {
            status = ERR_SSL_CONFIG;
            goto exit;
        }
    }

    DIGI_MEMSET((ubyte *)m_sslConnectTable, 0x00, (usize)(sslMaxConnections * sizeof(sslConnectDescr)));
    DIGI_MEMSET((ubyte *)&m_sslSettings, 0x00, (usize)sizeof(sslSettings));

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    m_sslSettings.sslListenPort     = SSL_DEFAULT_TCPIP_PORT;
#if ((defined(__ENABLE_DIGICERT_TLS13__)) && (defined(__ENABLE_DIGICERT_TLS13_PSK__)) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
    m_sslSettings.recvEarlyDataSize = SSL_TLS13_RECV_EARLY_DATA_SIZE;
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_TLS13_PSK__ && __ENABLE_DIGICERT_TLS13_0RTT__ */
#endif
    m_sslSettings.sslTimeOutReceive = TIMEOUT_SSL_RECV;
    m_sslSettings.sslTimeOutHello   = TIMEOUT_SSL_HELLO;

    if (0 == m_sslSettings.minRSAKeySize)
    {
        m_sslSettings.minRSAKeySize = MIN_SSL_RSA_SIZE;
    }

    m_sslSettings.minDHKeySize = MIN_SSL_DH_SIZE;

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
    m_sslSettings.isFIPSEnabled = TRUE;

    if (TRUE == m_sslSettings.isFIPSEnabled)
    {
        ubyte4 minRSAKeySize;
#if defined(__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__)
        minRSAKeySize = 1024;
#else
        minRSAKeySize = 2048;
#endif
        if (minRSAKeySize > m_sslSettings.minRSAKeySize)
        {
            m_sslSettings.minRSAKeySize = minRSAKeySize;
        }

        if (2048 > m_sslSettings.minDHKeySize)
        {
            m_sslSettings.minDHKeySize = 2048;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
    m_sslSettings.allowSha1SigAlg = TRUE;
#endif

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    m_sslSettings.allowDSASigAlg = TRUE;
#endif

    for (index = 0; index < m_sslMaxConnections; index++)
        m_sslConnectTable[index].connectionState = CONNECT_DISABLED;

    for (index = 0; index < m_sslMaxConnections; index++)
    {
        if (index < numServerConnections)
        {
            m_sslConnectTable[index].connectionState = CONNECT_CLOSED;
        }
        else
        {
            m_sslConnectTable[index].connectionState = CONNECT_CLOSED;
            m_sslConnectTable[index].isClient        = TRUE;
        }

        m_sslConnectTable[index].pSSLSock        = NULL;
    }

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    m_sslSettings.sslTimeOutConnectTimedWait = TIMEOUT_DTLS_CONNECT_TIMED_WAIT;

    /* if numServerConnections is small we allocate 200 entries for the timedWaitQueue, else twice as many as numServerConnections */
    if (OK > (status = CIRCQ_init(&m_sslConnectTimedWaitQueue, (numServerConnections*2 > 200? numServerConnections*2 : 200))))
        goto exit;
#endif
    initialized = TRUE;
    initializing = FALSE;
    m_sslSettings.sslMinProtoVersion = MIN_SSL_MINORVERSION;
    m_sslSettings.sslMaxProtoVersion = MAX_SSL_MINORVERSION;

    if (OK <= status)
    {
        DEBUG_PRINT(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_init: completed after = (");
        DEBUG_UPTIME(DEBUG_SSL_MESSAGES);
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)") milliseconds.");
    }

exit:
    if (initialized != TRUE)
    {
        if (OK > status)
        {
            initializing = FALSE;
        }
        else
        {
            status = ERR_SSL_BAD_STATE;
        }
    }

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/**
@brief      Initialize NanoSSL %client or server internal structures.

@details    This function initializes NanoSSL %client/server internal
            structures. Your application should call this function before
            starting the HTTPS and application servers.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param numServerConnections     Maximum number of SSL/TLS %server connections to
                                  allow. (Each connection requires only a few
                                  bytes of memory.)
@param numClientConnections     Maximum number of SSL/TLS %client connections to
                                  allow.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
SSL_EXTERN sbyte4
SSL_init(sbyte4 numServerConnections, sbyte4 numClientConnections)
{
    mSSL_rngFun = RANDOM_rngFun;
    mSSL_rngArg = g_pRandomContext;

    /* Register the shutdown handler */
    if (NULL == g_sslShutdownHandler)
    {
        g_sslShutdownHandler = SSL_shutdownStack;
    }

    return SSL_initAux( numServerConnections, numClientConnections);
}


/*--------------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_SSL_CUSTOM_RNG__)

/**
@coming_soon
@ingroup    func_ssl_sync
@remark     This function is applicable to synchronous clients and servers.
*/
SSL_EXTERN sbyte4
SSL_initEx(sbyte4 numServerConnections, sbyte4 numClientConnections,
           RNGFun rngFun, void* rngArg)
{
    if ( rngFun)
    {
        mSSL_rngFun = rngFun;
        mSSL_rngArg = rngArg;

        return SSL_initAux( numServerConnections, numClientConnections);
    }

    /* NULL rngFun -> default to simpler function */
    return SSL_init( numServerConnections, numClientConnections);
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || \
    ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))) || \
    ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))) )
/**
@brief      Send data to a connected server/client.

@details    This function sends data to a connected server/client. It should
            not be called until a secure SSL connection is established between
            the %client and %server. A negative return value indicates that an
            error has occurred. A return value >= 0 indicates the number of
            bytes transmitted.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pBuffer              Pointer to buffer containing the data to send.
@param bufferSize           Number of bytes in \p pBuffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@code
char reply[1024];
sbyte4 status;
status = SSL_send(connectionInstance, reply, strlen(reply));
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4
SSL_send(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (IS_SSL_ASYNC(pSSLSock))
            goto exit;

        if (OK > (status = sendPendingBytes(pSSLSock, index)))
            goto exit;

        if (NULL != pSSLSock->pOutputBuffer)
        {
            /* if there is data still pending, we will send no new bytes */
            status = (MSTATUS)0;
            goto exit;
        }

        status = (MSTATUS)SSL_SOCK_send(pSSLSock, pBuffer, bufferSize);

        /* Rehandshake checks against bytes send */
        if ((OK <= status) && (m_sslSettings.maxByteCount > 0))
        {
            pSSLSock->sslByteSendCount += bufferSize;
            if (pSSLSock->sslByteSendCount > m_sslSettings.maxByteCount)
            {
#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))
                if (m_sslSettings.funcPtrClientRehandshakeRequest != NULL)
                {
                    status = m_sslSettings.funcPtrClientRehandshakeRequest(connectionInstance);
                }
                RTOS_deltaMS(NULL, &pSSLSock->sslRehandshakeTimerCount);
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
                if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                {
                    if (m_sslSettings.funcPtrKeyUpdateRequest != NULL)
                    {
                        status = m_sslSettings.funcPtrKeyUpdateRequest(connectionInstance);
                    }
                }
#endif
                pSSLSock->sslByteSendCount = 0;
            }
        }
    }

exit:

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL_send() returns status = ", (sbyte4)status);
#endif

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || \
    ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))) || \
    ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))) )
/**
@brief      Get data from a connected server/client.

@details    This function retrieves data from a connected server/client. It
            should not be called until an SSL connection is established
            between the %client and %server.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pRetBuffer           Pointer to the buffer in which to write the
                              received data.
@param bufferSize           Number of bytes in receive data buffer.
@param pNumBytesReceived    On return, pointer to the number of bytes received.
@param timeout              Number of milliseconds the client/server will wait
                              to receive the message. To specify no timeout (an
                              infinite wait), set this parameter to 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@code
static int GetSecurePageAux(int connectionInstance, const char* pageName)
{
    char            buffer[1025];
    unsigned int    bytesSent;
    int             result = 0;

    sprintf(buffer, "GET /%s HTTP/1.0\r\n\r\n", pageName);
    bytesSent = SSL_send(connectionInstance,
                         buffer, strlen(buffer));
    if (bytesSent == strlen(buffer)) {
        int bytesReceived;

        // how to receive
        while (0 <= result) {
            memset(buffer, 0x00, 1025);
            result = SSL_recv(connectionInstance,
                              buffer, 1024, &bytesReceived, 0);
            printf("%s", buffer);
        }
        return 0;
    }

    return -1;
}
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_recv(sbyte4 connectionInstance, sbyte *pRetBuffer, sbyte4 bufferSize, sbyte4 *pNumBytesReceived, ubyte4 timeout)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;

    if ((NULL == pRetBuffer) || (NULL == pNumBytesReceived))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 >= bufferSize)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
        if (IS_SSL_ASYNC(m_sslConnectTable[index].pSSLSock))
            goto exit;

        if (OK > m_sslConnectTable[index].pSSLSock->lastErrorStatus)
        {
            status = m_sslConnectTable[index].pSSLSock->lastErrorStatus;
            goto exit;
        }

        status = doProtocol(m_sslConnectTable[index].pSSLSock, index, TRUE, timeout, pRetBuffer, bufferSize, pNumBytesReceived);

        /* Received
         *  - close notification alert - Send close notify alert and close the connection
         *  - fatal alert - Close the connection
         */
        if (TRUE == m_sslConnectTable[index].pSSLSock->alertCloseConnection)
        {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            if (TRUE == m_sslConnectTable[index].pSSLSock->sendCloseNotifyAlert)
            {
                SSLSOCK_sendAlert(m_sslConnectTable[index].pSSLSock, TRUE, SSL_ALERT_CLOSE_NOTIFY, SSLALERTLEVEL_WARNING);
            }
#endif
            SSL_closeConnection(connectionInstance);
            /* SSL Socket for this connection is freed in SSL_closeConnection */
            goto exit;
        }
    }
#ifdef __ENABLE_ALL_DEBUGGING__
    else
    {
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL_recv: bad SSL connection state = ", m_sslConnectTable[index].connectionState);
    }
#endif

exit:

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL_recv() returns status = ", (sbyte4)status);
#endif

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || \
    ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))) || \
    ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))) )
/**
@brief      Determines whether there is data in a connection instance's SSL
            send buffer.

@details    This function determines whether there is data in a connection
            instance's SSL send buffer. If the send buffer is empty, zero
            (0) is returned through the \p pNumBytesPending parameter. If
            send data is pending, an attempt is made to send the data, and
            the subsequent number of bytes remaining to be sent is returned
            through the \p pNumBytesPending parameter. (A function return
            value of zero (0) indicates that the send was successful and
            that no data remains in the send buffer.)

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pNumBytesPending     On return, the number of bytes remaining in the SSL
send buffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_sendPending(sbyte4 connectionInstance, sbyte4 *pNumBytesPending)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;

    if (NULL == pNumBytesPending)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumBytesPending = 0;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (IS_SSL_ASYNC(pSSLSock))
            goto exit;

        /* try to push out any pending bytes */
        if (OK > (status = sendPendingBytes(pSSLSock, index)))
            goto exit;

        if (NULL == pSSLSock->pOutputBuffer)
            *pNumBytesPending = 0;
        else
            *pNumBytesPending = pSSLSock->numBytesToSend;

        status = OK;

    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL_sendPending() returns status = ", (sbyte4)status);
#endif

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || \
    ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))) || \
    ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))) )
/**
@brief      Test if a connection instance's SSL receive buffer contains data.

@details    This function determines whether there is data in a connection
            instance's SSL receive buffer, and returns either \c TRUE or \c
            FALSE accordingly.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pRetBooleanIsPending On return, contains \c TRUE if there is data to be
                              received, or \c FALSE if no data is pending
                              receipt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_recvPending(sbyte4 connectionInstance, sbyte4 *pRetBooleanIsPending)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;

    if (NULL == pRetBooleanIsPending)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetBooleanIsPending = FALSE;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (IS_SSL_ASYNC(pSSLSock))
            goto exit;

        if (kRecordStateReceiveFrameComplete == SSL_SYNC_RECORD_STATE(pSSLSock))
            *pRetBooleanIsPending = (0 == (pSSLSock->recordSize - pSSLSock->offset)) ? FALSE : TRUE;

        if (0 != m_sslConnectTable[index].numBytesRead)
            *pRetBooleanIsPending = TRUE;

        status = OK;

    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL_recvPending() returns status = ", (sbyte4)status);
#endif

    return status;
}
#endif


/*------------------------------------------------------------------*/

/**
@brief      Close an SSL session and release resources.

@details    This function closes a synchronous SSL session and releases all
            the resources that are managed by the NanoSSL %client/server.

@ingroup    func_ssl_sync

@since 1.41
@version 3.06 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
SSL_EXTERN sbyte4
SSL_closeConnection(sbyte4 connectionInstance)
{
    /* for multi-concurrent sessions, a thread should be spawned for this call */
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    intBoolean isMutexTaken = FALSE;

    if (OK > (status = RTOS_mutexWait( m_sslConnectTableMutex)))
    {
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"RTOS_mutexWait() failed.");
        goto exit;
    }
    isMutexTaken = TRUE;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE <= m_sslConnectTable[index].connectionState)
    {
        intBoolean isDTLS;
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;

#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
        if (IS_SSL_SYNC(pSSLSock))
        {
            FREE(m_sslConnectTable[index].pReadBuffer);
            m_sslConnectTable[index].pReadBuffer = NULL;
        }
#endif
        isDTLS = pSSLSock->isDTLS;

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
        if (isDTLS)
        {
            if (OK > (status = hashtable_remove(m_sslConnectHashTable, isDTLS, (TCP_SOCKET)-1, &(m_sslConnectTable[index].peerDescr))))
                goto exit;
        } else
#endif
        {
            if (OK > (status = hashtable_remove(m_sslConnectHashTable, isDTLS, m_sslConnectTable[index].socket, NULL)))
                goto exit;
        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (m_sslConnectTable[index].peerDescr.pUdpDescr)
        {
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            /* if connection is not yet established, put in timed-wait queue */
            if (isDTLS && m_sslConnectTable[index].connectionState < CONNECT_OPEN)
            {
                sslConnectTimedWaitDescr *pTimedWaitDescr;
                MOC_IP_ADDRESS srcAddrRef = REF_MOC_IPADDR(m_sslConnectTable[index].peerDescr.srcAddr);
                MOC_IP_ADDRESS peerAddrRef = REF_MOC_IPADDR(m_sslConnectTable[index].peerDescr.peerAddr);

                if (NULL == (pTimedWaitDescr = MALLOC(sizeof(sslConnectTimedWaitDescr))))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                pTimedWaitDescr->peerDescr.pUdpDescr = m_sslConnectTable[index].peerDescr.pUdpDescr;
                pTimedWaitDescr->peerDescr.srcPort = m_sslConnectTable[index].peerDescr.srcPort;
                COPY_MOC_IPADDR(pTimedWaitDescr->peerDescr.srcAddr, srcAddrRef);
                pTimedWaitDescr->peerDescr.peerPort = m_sslConnectTable[index].peerDescr.peerPort;
                COPY_MOC_IPADDR(pTimedWaitDescr->peerDescr.peerAddr, peerAddrRef);
                pTimedWaitDescr->startTime = RTOS_getUpTimeInMS();

                status = CIRCQ_enq(m_sslConnectTimedWaitQueue, (ubyte*)pTimedWaitDescr);
                if (OK > status)
                {
                    /* if queue is full, remove the oldest entry in queue and try again */
                    sslConnectTimedWaitDescr *pTimedWaitDescrToDel;
                    CIRCQ_deq(m_sslConnectTimedWaitQueue, (ubyte**)&pTimedWaitDescrToDel);
                    if (pTimedWaitDescrToDel)
                    {
                        FREE(pTimedWaitDescrToDel);
                    }
                    status = CIRCQ_enq(m_sslConnectTimedWaitQueue, (ubyte*)pTimedWaitDescr);
                    /* give up */
                    if (OK > status)
                    {
                        FREE(pTimedWaitDescr);
                        status = OK;
                    }
                }
            } else
#endif
            {
                m_sslConnectTable[index].peerDescr.pUdpDescr = NULL;
            }
        }
#endif

        m_sslConnectTable[index].pSSLSock        = NULL;
        m_sslConnectTable[index].instance        = -1;
        m_sslConnectTable[index].connectionState = CONNECT_CLOSED;

        isMutexTaken= FALSE;
        if (OK > (status = RTOS_mutexRelease(m_sslConnectTableMutex)))
        {
            DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"RTOS_mutexRelease() failed.");
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
        if(NULL != pSSLSock->pTransportHandler)
        {
            /* close the transport connection too, recursive call */
            (void) SSL_closeConnection(pSSLSock->pTransportHandler->sslId);
            (void) TCP_CLOSE_SOCKET(pSSLSock->pTransportHandler->sslSocket);
        }
#endif

        SSL_SOCK_uninit(pSSLSock);
        HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &(pSSLSock->hwAccelCookie));
        FREE(pSSLSock);

        status = OK;
    }

exit:
    if (isMutexTaken)
    {
        if (OK > RTOS_mutexRelease(m_sslConnectTableMutex))
        {
            DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"RTOS_mutexRelease() failed.");
        }
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_closeConnection() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
/**
@brief      Initialize NanoSSL %client or %server internal structures.

@details    This function initializes NanoSSL %client/server internal
            structures. Your application should call this function before
            starting the HTTPS and application servers.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param numServerConnections     Maximum number of SSL/TLS %server connections to
                                  allow. (Each connection requires only a few
                                  bytes of memory.) If operating in
                                  dual mode, this is the sum of the synchronous
                                  and asynchronous %server connections.
@param numClientConnections     Maximum number of SSL/TLS %client connections to
                                  allow. If operating in dual mode, this is the
                                  sum of the synchronous and asynchronous
                                  %client connections.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_init(sbyte4 numServerConnections, sbyte4 numClientConnections)
{
    return SSL_init(numServerConnections, numClientConnections);
}

/*--------------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_SSL_CUSTOM_RNG__)

/**
@coming_soon
@ingroup    func_ssl_async
@remark     This function is applicable to asynchronous clients and servers.
*/
extern sbyte4
SSL_ASYNC_initEx(sbyte4 numServerConnections, sbyte4 numClientConnections,
                 RNGFun rngFun, void* rngArg)
{
    return SSL_initEx(numServerConnections, numClientConnections,
                      rngFun, rngArg);
}
#endif

#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
/**
@brief      Get a copy of data received from a connected server/client.

@details    This function retrieves data from a connected server/client and
            copies it into a new buffer. It should be called from your
            TCP/IP receive upcall handler, or from your application after
            reading a packet of data. The engine decrypts and processes the
            packet, and then calls NanoSSL server's upcall function, \p
            funcPtrReceiveUpcall, to hand off the decrypted data.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect.
@param pBytesReceived       On return, pointer to the packet or message
                              received from the TCP/IP stack.
@param numBytesReceived     On return, number of bytes in \p pBytesReceived.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function is provided for backward compatibility with earlier
            Embedded SSL/TLS implementations. New NanoSSL implementations
            should use SSL_ASYNC_recvMessage2(). The SSL_ASYNC_recvMessage2()
            function returns a pointer to the full data buffer, eliminating
            the need to consider maximum buffer sizes and manage multiple read
            calls.

@todo_techpubs (revise the note that refers to "earlier Embedded SSL/TLS
            implementations", which is quite old relative to the DSF/SoTP
            usage)

@remark     This function is applicable to asynchronous clients and servers.

@code
while ((OK == status) && (TRUE != mBreakServer))
{
    if (OK <= (status = TCP_READ_AVL(socketClient,
                                     pInBuffer,
                                     SSH_SYNC_BUFFER_SIZE,
                                     &numBytesRead,
                                     20000)))
    {
        if (0 != numBytesRead)
            status = SSL_ASYNC_recvMessage(connInstance,
                                           pInBuffer,
                                           numBytesRead);
    }

    if (ERR_TCP_READ_TIMEOUT == status)
        status = OK;
}
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_recvMessage(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived)
{
    sbyte4  index;
    sbyte4  dummy = 0;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket* pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (IS_SSL_SYNC(pSSLSock))
        goto exit;

    if (OK > pSSLSock->lastErrorStatus)
    {
        status = pSSLSock->lastErrorStatus;
        goto exit;
    }

    status = OK;

    if ((CONNECT_NEGOTIATE < m_sslConnectTable[index].connectionState) && (OK <= status))
    {
        status = setMessageTimer(pSSLSock, connectionInstance, pSSLSock->timeOutReceive);
    }

    while ((OK <= status) && (0 < numBytesReceived))
    {
        status = (MSTATUS)SSL_SOCK_receive(pSSLSock, NULL, 0,
                                           &pBytesReceived, &numBytesReceived,
                                           &dummy);
    }

exit:
    if (OK > status)
    {
        if (pSSLSock != NULL)
            pSSLSock->lastErrorStatus = status;
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_recvMessage() returns status = ", (sbyte4)status);
#endif
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
#if defined(__ENABLE_DIGICERT_SSL_ASYNC_API_EXTENSIONS__)
/**
@brief      Get a pointer to the connection's most recently receiveed message.

@details    This function returns a pointer (through the \p pBytesReceived
            parameter) to the specified connection's most recently received
            message. Typically, you'll call this function and then, if the
            returned number of bytes of application data is greater than 0,
            call SSL_ASYNC_getRecvBuffer() to get the pointer to the
            decrypted data.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_API_EXTENSIONS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance       Connection instance returned from
                                  SSL_ASYNC_connect().
@param pBytesReceived           On return, pointer to the packet or message
                                  received from the TCP/IP stack.
@param numBytesReceived         On return, number of bytes in \p pBytesReceived.
@param ppRetBytesReceived       On return, pointer to buffer containing number
                                  of bytes remaining to be read.
@param pRetNumRxBytesRemaining  On return, pointer to number of bytes in \p
                                  ppRetBytesReceived.

@return     Value >= 0 is the number of bytes of application data available when
            the \c SSL_FLAG_ENABLE_RECV_BUFFER is set; otherwise a negative
            number error code definition from merrors.h. To retrieve a string
            containing an English text error identifier corresponding to the
            function's returned error %status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_recvMessage2(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived,
                       ubyte **ppRetBytesReceived, ubyte4 *pRetNumRxBytesRemaining)
{
    sbyte4  index;
    sbyte4  retNumBytesReceived = 0;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket* pSSLSock;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (m_sslConnectTable[index].connectionState == CONNECT_CLOSED)
    {
        status = ERR_SSL_NOT_OPEN;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (IS_SSL_SYNC(pSSLSock))
        goto exit;

    if (OK > pSSLSock->lastErrorStatus)
    {
        status = pSSLSock->lastErrorStatus;
        goto exit;
    }

    status = OK;

    if ((CONNECT_NEGOTIATE < m_sslConnectTable[index].connectionState) && (OK <= status))
    {
        status = setMessageTimer(pSSLSock, connectionInstance, pSSLSock->timeOutReceive);
    }

    if (OK > status)
        goto exit;

    /* in most instances, all of the data will be consumed */
    *ppRetBytesReceived      = NULL;
    *pRetNumRxBytesRemaining = 0;

    while (0 < numBytesReceived)
    {
        status = (MSTATUS)SSL_SOCK_receive(pSSLSock, NULL, 0,
                                           &pBytesReceived, &numBytesReceived,
                                           &retNumBytesReceived);
        if (OK > status)
        {
            pSSLSock->lastErrorStatus = status;
            goto exit;
        }

        if ((SSL_FLAG_ENABLE_RECV_BUFFER & pSSLSock->runtimeFlags) &&
            (0 < retNumBytesReceived))
        {
            /* this conditional prevents a second SSL frame from overwriting a first frame */
            *ppRetBytesReceived    = pBytesReceived;
            *pRetNumRxBytesRemaining = numBytesReceived;
            break;
        }
    }

exit:
    if (OK > status)
        return status;

    return retNumBytesReceived;

} /* SSL_ASYNC_recvMessage2 */
#endif
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
/**
@brief      Send data to a connected server/client.

@details    This function sends data to a connected server/client. It should
            not be called until a secure SSL connection is established between
            the %client and %server.

@ingroup    func_ssl_async

@since 1.41
@version 6.4 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect.
@param pBuffer              Pointer to buffer containing the data to send.
@param bufferSize           Number of bytes in \p pBuffer.
@param pBytesSent           On return, pointer to number of bytes successfully sent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function should not be called until after a \p
            funcPtrOpenStateUpcall upcall event.

@remark     This function is applicable to asynchronous clients and servers.

@code
static void SSL_EXAMPLE_helloWorld(int connectionInstance)
{
    sbyte4 bytesSent = 0;
    sbyte4 status;

    status = SSL_ASYNC_sendMessage(connInstance,
                                   "hello world!", 12,
                                   &bytesSent);
}
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
	 goto exit;

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (IS_SSL_SYNC(pSSLSock))
            goto exit;

        if (NULL != pBytesSent)
            *pBytesSent = 0;

        /* for DTLS, the send buffer should be cleared already */
        if (!pSSLSock->isDTLS)
        {
            /* send out any bytes that may be pending, before attempting to send "new" data */
            if (OK > (status = sendPendingBytes(pSSLSock, index)))
                goto exit;
        }

        if (NULL != pSSLSock->pOutputBuffer)
        {
            if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
            {
                /* Should Not Happen as in this case we shall be harvesting all */
                /* the data from the buffer */
                if (NULL != pBytesSent)
                {
                    *pBytesSent =  pSSLSock->numBytesToSend;
                }

                /* Should retry the buffer again */
                status = ERR_SSL_SEND_BUFFER_NOT_EMPTY;
                goto exit;
            }
        }

        if ((NULL == pSSLSock->pOutputBuffer) && (NULL != pSSLSock->buffers[0].pHeader))
        {
            if (OK > (status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock)))
                goto exit;
        }

        if (NULL == pSSLSock->pOutputBuffer)
        {
            status = (MSTATUS)SSL_SOCK_send(pSSLSock, pBuffer, bufferSize);

            if (OK > status)
                goto exit;

            if (NULL != pBytesSent)
                *pBytesSent = status;
        }

        /* return the number of bytes pending in the ssl send buffer */
        if (NULL == pSSLSock->pOutputBuffer)
            status = (MSTATUS) 0;
        else
            status = (MSTATUS)pSSLSock->numBytesToSend;

    }
    else if (CONNECT_NEGOTIATE== m_sslConnectTable[index].connectionState)
    {
        status = ERR_SSL_NEGOTIATION_STATE;
    }
exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_sendMessage() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
/**
@brief      Determines whether there is data in a connection instance's SSL
            send buffer.

@details    This function determines whether there is data in a connection
            instance's SSL send buffer. If the send buffer is empty, the
            function returns zero (0) as its status. If send data is pending,
            an attempt is made to send the data, and the subsequent number of
            bytes remaining to be sent is returned as the function status. (A
            function return value of zero (0) indicates that the send was
            successful and that no data remains in the send buffer.)

@ingroup    func_ssl_async

@since 1.41
@version 3.06 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_ASYNC_connect().

@return     \c OK (0) if the send buffer is empty or if this function
            successfully sent all remaining buffer data; otherwise the number
            of bytes remaining to be sent.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_sendMessagePending(sbyte4 connectionInstance)
{
    /* on success, returns the number of bytes still pending */
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (IS_SSL_SYNC(pSSLSock))
            goto exit;

        status = sendPendingBytes(pSSLSock, index);

        if (OK > status)
            goto exit;

        status = (MSTATUS) pSSLSock->numBytesToSend;
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_sendMessage() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
/**
@brief      Close an SSL session and release resources.

@details    This function closes an asynchronous SSL session and releases all
            the resources that are managed by the NanoSSL %client/server.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function does not close sockets or TCBs (transmission control
            blocks). Your integration code should explicitly close all TCP/IP
            sockets and TCBs.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_closeConnection(sbyte4 connectionInstance)
{
    return SSL_closeConnection(connectionInstance);
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSL_acceptConnectionCommon(intBoolean isDTLS, TCP_SOCKET tempSocket, peerDescr *pPeerDescr,
                           struct certStore* pCertStore,
                           ubyte4 initialInternalFlag)
{
    SSLSocket*  pSSLSock = NULL;
    TCP_SOCKET  socket   = tempSocket;
    sbyte4      instance = -1;
    sbyte4      index;
    intBoolean  isHwAccelInit = FALSE;
#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
    ubyte*      pReadBuffer = NULL;
#endif
    MSTATUS     status;

    sslConnectDescr* newConnEntry = NULL;

    if (OK > (status = RTOS_mutexWait( m_sslConnectTableMutex)))
    {
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"RTOS_mutexWait() failed.");
        goto exit;
    }
 
    /* No goto exit's until after MUTEX gets released */
    for (index = 0; index < m_sslMaxConnections; index++)
    {
        if ((CONNECT_CLOSED == m_sslConnectTable[index].connectionState) &&
            (FALSE == m_sslConnectTable[index].isClient))
        {
            m_sslConnectTable[index].connectionState = CONNECT_NEGOTIATE;
            m_sslConnectTable[index].age = ((m_sslConnectTable[index].age + 1) & 0x7fff);
            instance = ((sbyte4)(m_sslConnectTable[index].age << NUM_BITS_SSL_SESSION_AGE) | index);

            newConnEntry = &m_sslConnectTable[index];
            break;
        }
    }

    if (OK > (status = RTOS_mutexRelease(m_sslConnectTableMutex)))
    {
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"RTOS_mutexRelease() failed.");
        goto exit;
    }

    if (!(index < m_sslMaxConnections))
    {
        status = ERR_SSL_TOO_MANY_CONNECTIONS;
    }
    else
    {
#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
        if (initialInternalFlag & SSL_INT_FLAG_SYNC_MODE)
        {
            newConnEntry->numBytesRead = 0;

            if (NULL == (pReadBuffer = (ubyte*) MALLOC(SSL_SYNC_BUFFER_SIZE)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
        }
#endif /* defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) */

        if (NULL == (pSSLSock = (SSLSocket*) MALLOC(sizeof(SSLSocket))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pSSLSock, 0x00, sizeof(SSLSocket));

        HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &(pSSLSock->hwAccelCookie));

        isHwAccelInit = TRUE;

        pSSLSock->internalFlags = initialInternalFlag;

        /* setMessageTimer() requires that pSSLSock->server be set to the right value
         * This is a bug fix.
         */
	pSSLSock->pSslConnectDescr 	= (void *)newConnEntry;
        pSSLSock->server 		= 1;
        pSSLSock->pCertStore 		= pCertStore;

        pSSLSock->timeOutReceive = m_sslSettings.sslTimeOutReceive;

        if (OK > (status = setMessageTimer(pSSLSock, instance, m_sslSettings.sslTimeOutHello)))
        {
            goto exit;
        }

        if ((OK <= SSL_SOCK_init(pSSLSock, isDTLS, socket, pPeerDescr, mSSL_rngFun, g_pRandomContext)) &&
            (OK <= SSL_SOCK_initSocketExtraServer(pSSLSock)))
        {
            newConnEntry->instance        = instance ;
            newConnEntry->pSSLSock        = pSSLSock;

            if (m_sslSettings.sslMinProtoVersion && !pSSLSock->isDTLS)
            {
                pSSLSock->minFallbackMinorVersion = m_sslSettings.sslMinProtoVersion;
                pSSLSock->runtimeFlags |= SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET;
            }

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
            if (isDTLS)
            {
                MOC_IP_ADDRESS srcAddrRef = REF_MOC_IPADDR(pPeerDescr->srcAddr);
                MOC_IP_ADDRESS peerAddrRef = REF_MOC_IPADDR(pPeerDescr->peerAddr);

                newConnEntry->peerDescr.pUdpDescr    = pPeerDescr->pUdpDescr;
                newConnEntry->peerDescr.srcPort      = pPeerDescr->srcPort;
                COPY_MOC_IPADDR(newConnEntry->peerDescr.srcAddr, srcAddrRef);
                newConnEntry->peerDescr.peerPort     = pPeerDescr->peerPort;
                COPY_MOC_IPADDR(newConnEntry->peerDescr.peerAddr, peerAddrRef);

                if (OK > DTLS_setSessionFlags(instance, SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER))
                    goto exit;
            } else
#endif
            {
                newConnEntry->socket = socket;
            }

            if (OK > (status = hashtable_insert(m_sslConnectHashTable,
                                                isDTLS, socket, pPeerDescr, newConnEntry)))
            {
                goto exit;
            }

            status                                   = (MSTATUS)instance;

            pSSLSock                                 = NULL;
#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
            newConnEntry->pReadBuffer                = pReadBuffer;
            pReadBuffer                              = NULL;
#endif

#ifdef __PSOS_RTOS__
            t_ident((char *)0, 0, &(newConnEntry->tid));
#endif

            newConnEntry = NULL;
        }
        else
        {
            status = ERR_SSL_INIT_CONNECTION;
        }
    }

    if (OK <= status)
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSL server accept connection.");

exit:

#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
    if ((initialInternalFlag & SSL_INT_FLAG_SYNC_MODE) && (NULL != pReadBuffer))
        FREE(pReadBuffer);
#endif /* defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) */

    if (pSSLSock)
    {
        if (TRUE == isHwAccelInit)
        {
            HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &pSSLSock->hwAccelCookie);
        }

        SSL_SOCK_uninit(pSSLSock);
        FREE(pSSLSock);
    }

    if (newConnEntry)
    {
        newConnEntry->connectionState = CONNECT_CLOSED;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_acceptConnectionCommon() returns status = ", (sbyte4)status);
#endif

    return status;

} /* SSL_acceptConnectionCommon */
#endif


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)) || \
     (defined(__ENABLE_DIGICERT_SSL_SERVER__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)))
/**
@brief      Create a synchronous server connection context.

@details    This function performs SSL handshaking, establishing a secure
            connection between a %server and %client.

@ingroup    func_ssl_sync_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to accept().
@param pCertStore       Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function must be called from within the HTTPS daemon context.
            If you are using multiple HTTPS daemons,  you must use a semaphore
            (mutex) around this function call. @note If your web %server and
            application %server run as separate tasks, you should protect the
            call to SSL_acceptConnection with a semaphore to prevent race
            conditions.

@remark     This function is applicable to synchronous servers only.

@funcdoc ssl.c
*/
extern sbyte4
SSL_acceptConnection(TCP_SOCKET tempSocket, struct certStore* pCertStore)
{
    sbyte4 connectionInstance;
    sbyte4 index;
    SSLSocket *pSSLSock;

    connectionInstance = ERR_SSL;

    if (!TCP_IS_SOCKET_VALID(tempSocket))
    {
        goto exit;
    }

    connectionInstance = (sbyte4) SSL_acceptConnectionCommon(
        FALSE, tempSocket, NULL, pCertStore, SSL_INT_FLAG_SYNC_MODE);
    if (0 > connectionInstance)
    {
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
    if ((m_sslSettings.pDHP != NULL) && (m_sslSettings.pDHG))
    {
        if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
            goto exit;

        pSSLSock = m_sslConnectTable[index].pSSLSock;

        pSSLSock->pDHP    = m_sslSettings.pDHP;
        pSSLSock->pLen    = m_sslSettings.pLen;
        pSSLSock->pDHG    = m_sslSettings.pDHG;
        pSSLSock->gLen    = m_sslSettings.gLen;
        pSSLSock->lengthY = m_sslSettings.lengthY;
    }
#endif

exit:

    return connectionInstance;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || \
    ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))) || \
    ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))) )
/**
@brief      Establish a secure SSL client-server connection.

@details    This function performs SSL handshaking, establishing a secure
            connection between a %client and %server. Before calling this
            function, you must first create a connection context (instance) by
            calling SSL_connect().

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@code
sbyte4 connectionInstance;
int mySocket;

// connect to server
connect(mySocket, (struct sockaddr *)&server, sizeof(server))

// register connect, get connectionInstance
connectionInstance = SSL_connect(mySocket, 0, NULL, NULL, "mocana.com");

// set a cookie
SSL_setCookie(connectionInstance, (int)&someFutureContext);

// negotiate SSL secure connection
if (0 > SSL_negotiateConnection(connectionInstance))
    goto error;
@endcode

@funcdoc ssl.c
*/
extern sbyte4
SSL_negotiateConnection(sbyte4 connectionInstance)
{
    /* a mutex is not necessary, this function should be called after accept */
    /* within the ssl connection daemon */
    sbyte4      index;
    sbyte4      dummy = 0;
    sbyte4      status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        if (IS_SSL_ASYNC(pSSLSock))
            goto exit;

        if (OK > pSSLSock->lastErrorStatus)
        {
            status = pSSLSock->lastErrorStatus;
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
        if (m_sslConnectTable[index].isClient)
        {
            if (OK > (status = SSL_SOCK_clientHandshake(pSSLSock, FALSE)))
                goto exit;
        }
#endif

        status = doProtocol(pSSLSock, index, FALSE, 0, NULL, 0, &dummy);

        /* Received
         *  - close notification alert - Send close notify alert and close the connection
         *  - fatal alert - Close the connection
         */
        if (TRUE == pSSLSock->alertCloseConnection)
        {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            if (TRUE == pSSLSock->sendCloseNotifyAlert)
            {
                SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_CLOSE_NOTIFY, SSLALERTLEVEL_WARNING);
            }
#endif
            SSL_closeConnection(connectionInstance);
            /* SSL Socket for this connection is freed in SSL_closeConnection */
            goto exit;
        }
    }

#ifdef __ENABLE_HARDWARE_ACCEL_CRYPTO__
    if (index < m_sslMaxConnections)
    {
        MD5FreeCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pMd5Ctx);
        SHA1_FreeCtxHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pShaCtx);
        FreeCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx,
                          pSSLSock->hashPool.poolObjectSize);
    }
#endif

#if (defined( __ENABLE_DIGICERT_SSL_REHANDSHAKE__))
    if (OK <= status)
         RTOS_deltaMS(NULL, &pSSLSock->sslRehandshakeTimerCount);
#endif

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (0 <= status)
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSL server negotiated connection.");

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte *)"SSL_negotiateConnection() returns status = ", (sbyte4)status);
#endif
    return status;

} /* SSL_negotiateConnection */
#endif

/*------------------------------------------------------------------ */
/* Needed to get Apache MOD_SSL to work over NanoSSL instead of OpenSSL.
 * This API is needed to emulate OpenSSL calls for MOD_SSL
 */
extern sbyte4
SSL_isSecureConnectionEstablished(sbyte4 connectionInstance)
{
    sbyte4  	index;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        return 0;

    /* Check below is equivalent to kSslSecureSessionEstablished == SSL_OPEN_STATE(pSSLSock) */

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
#if defined(__ENABLE_DIGICERT_TLS13__)
        SSLSocket *pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {

            /* If !Certificate Request && keyUpdate == none,
             * handshake has been completed and no post handshake messages are being exchanged
             */
            if (!(pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST)))
            {
                return 1;
            }
        }
        else
#endif
        {
            if(!m_sslConnectTable[index].pSSLSock->rehandshake)
                return 1;
        }
    }
    else if (CONNECT_CLOSED == m_sslConnectTable[index].connectionState)
    {
        return -1;
    }
    return 0;
}


extern sbyte4 SSL_getLocalState(sbyte4 connectionInstance, sbyte4 *pState)
{
    sbyte4  	index;
    sbyte4      status;
    SSLSocket  *pSSLSock;

    if (NULL == pState)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pState = SSL_BEGIN;
    status = OK;

#if __ENABLE_DIGICERT_TLS13__
    if (pSSLSock->helloRetryRequest)
    {
        *pState = SSL_HELLO_RETRY_REQUEST;
        goto exit;
    }
#endif

    if (TRUE == pSSLSock->sentFinished)
    {
        *pState = SSL_FINISHED;
    }

exit:
    return status;
}


extern sbyte4 SSL_getState(sbyte4 connectionInstance, sbyte4 *pState)
{
    sbyte4  	index;
    SSLSocket * pSSLSock;
    sbyte4      status = OK;

    /* Error case */
    *pState = -2;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    if (1 == (status = SSL_isSecureConnectionEstablished(connectionInstance)))
    {
        /* Connection is already established */
        goto exit;
    }

    status = OK;
    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (pSSLSock != NULL)
        *pState = SSL_REMOTE_HANDSHAKE_STATE(pSSLSock);

exit:
    return status;
}

/* Needed to get Apache MOD_SSL to work over NanoSSL instead of OpenSSL.
 * This API is needed to emulate OpenSSL calls for MOD_SSL
 */
extern sbyte4
SSL_in_connect_init_moc(sbyte4 connectionInstance)
{
    sbyte4  	index;
    SSLSocket * pSSLSock;
    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        return 0;

    pSSLSock	= m_sslConnectTable[index].pSSLSock;
    if ((pSSLSock->server) ||
	(CONNECT_OPEN == m_sslConnectTable[index].connectionState))
	 return 0;
    else
	 return 1;
}

/* Needed to get Apache MOD_SSL to work over NanoSSL instead of OpenSSL.
 * This API is needed to emulate OpenSSL calls for MOD_SSL
 */
extern sbyte4
SSL_in_accept_init_moc(sbyte4 connectionInstance)
{
    sbyte4  	index;
    SSLSocket * pSSLSock;
    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        return 0;

    pSSLSock	= m_sslConnectTable[index].pSSLSock;
    if ((pSSLSock->server) &&
	(CONNECT_OPEN != m_sslConnectTable[index].connectionState))
	 return 1;
    else
	 return 0;
}

/*------------------------------------------------------------------*/
#if ((!defined(__ENABLE_DIGICERT_OPENSSL_SHIM__) || defined(__ENABLE_DIGICERT_SSL_SSLCONNECT_RENAME__) || defined(__ENABLE_DIGICERT_TAP_OSSL_REMOTE__)) && ((defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) || \
     (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))))
/**
@brief      Create a synchronous %client connection context.

@details    This function creates a connection context for a secure SSL/TLS
            synchronous connection with a remote %server.

@ingroup    func_ssl_sync_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to
                          connect().
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                          terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's
                          certificate.
@param certStore        Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients only.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4
SSL_connect(TCP_SOCKET tempSocket,
            ubyte sessionIdLen, ubyte* sessionId, ubyte* masterSecret,
            const sbyte* dnsName, certStorePtr certStore)
{
    /* a mutex is required around the call of this function, if multiple threads may invoke this API */
    sbyte4          index;
    hwAccelDescr    hwAccelCookie = 0;
    intBoolean      isHwAccelCookieInit = FALSE;
    TCP_SOCKET      connectSocket       = (TCP_SOCKET)tempSocket;
    sbyte4          instance;
    sbyte4         status, status1;

    if (!TCP_IS_SOCKET_VALID(tempSocket))
    {
        status = ERR_INVALID_ARG;
        goto exitNoMutexRelease;
    }

    if ( OK > (status = RTOS_mutexWait(m_sslConnectTableMutex)))
    {
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"RTOS_mutexWait() failed.");
        goto exitNoMutexRelease;
    }

    status = ERR_SSL_TOO_MANY_CONNECTIONS;

    for (index = 0; index < m_sslMaxConnections; index++)
    {
        if ((CONNECT_CLOSED == m_sslConnectTable[index].connectionState) &&
            (TRUE == m_sslConnectTable[index].isClient))
        {
            if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCookie)))
                goto exit;

            isHwAccelCookieInit = TRUE;

            m_sslConnectTable[index].connectionState = CONNECT_NEGOTIATE;

            status = ERR_MEM_ALLOC_FAIL;

            m_sslConnectTable[index].numBytesRead = 0;

            if (NULL == (m_sslConnectTable[index].pReadBuffer = (ubyte*) MALLOC(SSL_SYNC_BUFFER_SIZE)))
                goto exit;

            if (NULL == (m_sslConnectTable[index].pSSLSock = (SSLSocket*) MALLOC(sizeof(SSLSocket))))
                goto exit;

            DIGI_MEMSET((ubyte *)m_sslConnectTable[index].pSSLSock, 0x00, sizeof(SSLSocket));

	    m_sslConnectTable[index].pSSLSock->pSslConnectDescr = &m_sslConnectTable[index];
            m_sslConnectTable[index].pSSLSock->hwAccelCookie = hwAccelCookie;
            m_sslConnectTable[index].pSSLSock->internalFlags = SSL_INT_FLAG_SYNC_MODE;

            m_sslConnectTable[index].age = ((m_sslConnectTable[index].age + 1) & 0x7fff);
            instance = ((sbyte4)(m_sslConnectTable[index].age << NUM_BITS_SSL_SESSION_AGE) | index);

            if (OK > (status = setMessageTimer(m_sslConnectTable[index].pSSLSock, instance, m_sslSettings.sslTimeOutHello)))
                goto exit;

            if (OK > (status = SSL_SOCK_init(m_sslConnectTable[index].pSSLSock, FALSE, connectSocket, NULL,
                                                mSSL_rngFun, mSSL_rngArg)))
            {
                goto exit;
            }
            if (OK > (status = SSL_SOCK_initSocketExtraClient(m_sslConnectTable[index].pSSLSock, sessionIdLen, sessionId,
                                                              masterSecret, dnsName, certStore)))
            {
                SSL_SOCK_uninit(m_sslConnectTable[index].pSSLSock);
                goto exit;
            }

            if (m_sslSettings.sslMinProtoVersion && !(m_sslConnectTable[index].pSSLSock->isDTLS))
            {
                m_sslConnectTable[index].pSSLSock->minFallbackMinorVersion = m_sslSettings.sslMinProtoVersion;
                m_sslConnectTable[index].pSSLSock->runtimeFlags |= SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET;
            }

            m_sslConnectTable[index].instance        = instance ;

            m_sslConnectTable[index].pSSLSock->timeOutReceive = m_sslSettings.sslTimeOutReceive;

            if (OK > (status = hashtable_insert(m_sslConnectHashTable, FALSE, connectSocket, NULL, &m_sslConnectTable[index])))
                goto exit;

            m_sslConnectTable[index].socket = connectSocket;
            status = instance;
#ifdef __PSOS_RTOS__
            t_ident((char *)0, 0, &m_sslConnectTable[index].tid);
#endif

exit:
            if (OK > status)
            {
                m_sslConnectTable[index].connectionState = CONNECT_CLOSED;

                if (NULL != m_sslConnectTable[index].pSSLSock)
                {
                    FREE(m_sslConnectTable[index].pSSLSock);
                    m_sslConnectTable[index].pSSLSock = NULL;
                }

                if (NULL != m_sslConnectTable[index].pReadBuffer)
                {
                    FREE(m_sslConnectTable[index].pReadBuffer);
                    m_sslConnectTable[index].pReadBuffer = NULL;
                }

                if (TRUE == isHwAccelCookieInit)
                {
                    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCookie);
                }
            }

            break;
        }
    }

    status1 = RTOS_mutexRelease(m_sslConnectTableMutex);

    if ((OK <= status) && (OK > status1))
        status = status1;

exitNoMutexRelease:

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (0 <= status)
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSL client made connection.");

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_connect() returns status = ", (sbyte4)status);
#endif

    return status;           /* can be an instance or a status */

} /* SSL_connect */


#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__

/*------------------------------------------------------------------*/

/**
@brief      Create a synchronous %client connection context with transport handlers for
            creating a connection through an existing proxy server connection.

@details    This function creates a connection context for a secure SSL/TLS
            synchronous connection with a remote %server. Transport handlers can
            be defined for connecting through an existing SSL connection to a proxy server.

@ingroup    func_ssl_sync_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

@inc_file ssl.h

@param sslId            The id (ie connectionInstance) of the existing connection.
@param transportSend    Function pointer to the send handler that uses the existing connection.
@param transportRecv    Function pointer to the receive handler that uses the existing connection. 
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                          terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's
                          certificate.
@param certStore        Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients only.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4
SSL_PROXY_connect(TCP_SOCKET sslSocket, sbyte4 sslId, SSLTransportSend transportSend, SSLTransportRecv transportRecv, 
                  TCP_SOCKET tempSocket, ubyte sessionIdLen, ubyte* sessionId, ubyte* masterSecret,
                  const sbyte* dnsName, certStorePtr certStore)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 newId = 0;
    sbyte4 index = 0;
    SSLSocket *pSSLSock = NULL;
    SSL_Transport_Handler *pNewHandler = NULL;

    /* Other params validated in SSL_connect call below */
    if (NULL == transportSend || NULL == transportRecv)
        goto exit;

    if (!TCP_IS_SOCKET_VALID(sslSocket))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Create a new SSL connection on the same socket */
    newId = SSL_connect(tempSocket, sessionIdLen, sessionId, masterSecret, dnsName, certStore);
    if (OK > newId)
    {
        status = (MSTATUS) newId;
        goto exit;
    }

    /* Get the SSLSocket for the new connection */
    if (OK > (index = getIndexFromConnectionInstance(newId)))
    {
        status = (MSTATUS) index;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (NULL == pSSLSock)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* Allocate and set the Transport Handler so that it'll use the previous connection */
    status = DIGI_MALLOC((void **) &pNewHandler, sizeof(SSL_Transport_Handler));
    if (OK != status)
        goto exit;

    pNewHandler->sslSocket = sslSocket;
    pNewHandler->sslId = sslId;
    pNewHandler->funcPtrTransportSend = transportSend;
    pNewHandler->funcPtrTransportRecv = transportRecv;

    pSSLSock->pTransportHandler = pNewHandler; pNewHandler = NULL;

exit:

    if (OK != status && newId > 0)
    {
        (void) SSL_closeConnection(newId);
    }

    if (NULL != pNewHandler)
    {
        DIGI_FREE((void **) &pNewHandler);
    }

    if (OK == status)
    {
        status = (MSTATUS) newId;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_PROXY_CONNECT__ */
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
/**
@brief      Register a secure asynchronous SSL/TLS connection.

@details    This function registers a secure asynchronous SSL/TLS connection.

@ingroup    func_ssl_async_server

@since 1.41
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to accept().
@param pCertStore       Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers only.

@note       This function must be called from within the HTTPS daemon context.
            If you are using multiple HTTPS daemons,  you must use a semaphore
            (mutex) around this function call. @note If your web %server and
            application %server run as separate tasks, you should protect the
            call to SSL_ASYNC_acceptConnection() with a semaphore to prevent
            race conditions.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_acceptConnection(TCP_SOCKET tempSocket,
                           struct certStore* pCertStore)
{
    sbyte4 connectionInstance;
#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
    sbyte4 index;
    SSLSocket *pSSLSock;
#endif

    connectionInstance = (sbyte4) SSL_acceptConnectionCommon(
        FALSE, tempSocket, NULL, pCertStore, SSL_INT_FLAG_ASYNC_MODE);
    if (0 > connectionInstance)
    {
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))

    if ((m_sslSettings.pDHP != NULL) && (m_sslSettings.pDHG))
    {
        if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
            goto exit;

        pSSLSock = m_sslConnectTable[index].pSSLSock;

        pSSLSock->pDHP    = m_sslSettings.pDHP;
        pSSLSock->pLen    = m_sslSettings.pLen;
        pSSLSock->pDHG    = m_sslSettings.pDHG;
        pSSLSock->gLen    = m_sslSettings.gLen;
        pSSLSock->lengthY = m_sslSettings.lengthY;
    }
#endif

exit:

    return connectionInstance;
}
#endif /* __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSL_ASYNC_connectCommon(intBoolean isDTLS, TCP_SOCKET tempSocket,
                        peerDescr *pPeerDescr,
                        ubyte sessionIdLen, ubyte * sessionId,
                        ubyte * masterSecret, const sbyte* dnsName,
                        certStorePtr certStore)
{
    /* a mutex is required around the call of this function, if multiple threads may invoke this API */
    sbyte4          index;
    hwAccelDescr    hwAccelCookie = 0;
    intBoolean      isHwAccelCookieInit = FALSE;
    TCP_SOCKET      connectSocket       = (TCP_SOCKET)tempSocket;
    sbyte4          instance;
    MSTATUS         status, status1;

    if ( OK > ( status = RTOS_mutexWait( m_sslConnectTableMutex)))
        goto exitNoMutexRelease;

    status = ERR_SSL_TOO_MANY_CONNECTIONS;

    for (index = 0; index < m_sslMaxConnections; index++)
    {
        if ((CONNECT_CLOSED == m_sslConnectTable[index].connectionState) &&
            (TRUE == m_sslConnectTable[index].isClient))
        {
            if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCookie)))
                goto exit;

            isHwAccelCookieInit = TRUE;
            m_sslConnectTable[index].connectionState = CONNECT_NEGOTIATE;

            status = ERR_MEM_ALLOC_FAIL;

            if (NULL == (m_sslConnectTable[index].pSSLSock = (SSLSocket*) MALLOC(sizeof(SSLSocket))))
                goto exit;

            DIGI_MEMSET((ubyte *)m_sslConnectTable[index].pSSLSock, 0x00, sizeof(SSLSocket));

	    m_sslConnectTable[index].pSSLSock->pSslConnectDescr = (void *)&m_sslConnectTable[index];
            m_sslConnectTable[index].pSSLSock->hwAccelCookie = hwAccelCookie;
            m_sslConnectTable[index].pSSLSock->internalFlags = SSL_INT_FLAG_ASYNC_MODE;

            m_sslConnectTable[index].age = ((m_sslConnectTable[index].age + 1) & 0x7fff);
            instance = ((sbyte4)(m_sslConnectTable[index].age << NUM_BITS_SSL_SESSION_AGE) | index);

            if (OK > (status = hashtable_insert(m_sslConnectHashTable, isDTLS, connectSocket, pPeerDescr, &m_sslConnectTable[index])))
                goto exit;

            if (OK > (status = setMessageTimer(m_sslConnectTable[index].pSSLSock, instance, m_sslSettings.sslTimeOutHello)))
                goto exit;

            if (OK > (status = SSL_SOCK_init(m_sslConnectTable[index].pSSLSock, isDTLS, connectSocket, pPeerDescr, mSSL_rngFun, mSSL_rngArg)))
                goto exit;

            if (OK > (status = SSL_SOCK_initSocketExtraClient(m_sslConnectTable[index].pSSLSock, sessionIdLen, sessionId,
                                                              masterSecret, dnsName, certStore)))
            {
                SSL_SOCK_uninit(m_sslConnectTable[index].pSSLSock);
                goto exit;
            }

            if (m_sslSettings.sslMinProtoVersion && !(m_sslConnectTable[index].pSSLSock->isDTLS))
            {
                m_sslConnectTable[index].pSSLSock->minFallbackMinorVersion = m_sslSettings.sslMinProtoVersion;
                m_sslConnectTable[index].pSSLSock->runtimeFlags |= SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET;
            }

            m_sslConnectTable[index].instance        = instance ;

            m_sslConnectTable[index].pSSLSock->timeOutReceive = m_sslSettings.sslTimeOutReceive;

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
            if (isDTLS)
            {
                MOC_IP_ADDRESS srcAddrRef = REF_MOC_IPADDR(pPeerDescr->srcAddr);
                MOC_IP_ADDRESS peerAddrRef = REF_MOC_IPADDR(pPeerDescr->peerAddr);

                m_sslConnectTable[index].peerDescr.pUdpDescr = pPeerDescr->pUdpDescr;
                m_sslConnectTable[index].peerDescr.srcPort = pPeerDescr->srcPort;
                COPY_MOC_IPADDR(m_sslConnectTable[index].peerDescr.srcAddr, srcAddrRef);
                m_sslConnectTable[index].peerDescr.peerPort = pPeerDescr->peerPort;
                COPY_MOC_IPADDR(m_sslConnectTable[index].peerDescr.peerAddr, peerAddrRef);

                if (OK > SSL_setSessionFlags(instance, SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER))
                    goto exit;
            } else
#endif
            {
                m_sslConnectTable[index].socket = connectSocket;
            }
            status = (MSTATUS) instance;
            break;
        }
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (0 <= status)
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSL client made connection.");

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ASYNC_connect() returns status = ", (sbyte4)status);
#endif

exit:
    if ((OK > status) && (index < m_sslMaxConnections))
    {
        m_sslConnectTable[index].connectionState = CONNECT_CLOSED;

        if (TRUE == isHwAccelCookieInit)
        {
            HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCookie);
        }

        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            FREE(m_sslConnectTable[index].pSSLSock);
            m_sslConnectTable[index].pSSLSock = NULL;
        }
    }

    status1 = RTOS_mutexRelease(m_sslConnectTableMutex);

    if ((OK <= status) && (OK > status1))
        status = status1;

exitNoMutexRelease:

    return status;           /* can be an instance or a status */

} /* SSL_ASYNC_connectCommon */

/*------------------------------------------------------------------*/

/**
@brief      Create an asynchronous %client connection context.

@details    This function creates a connection context for a secure SSL/TLS
            asynchronous connection with a remote %server.

@ingroup    func_ssl_async_client

@since 1.41
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to connect().
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                          terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's certificate.
@param certStore        Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients only.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ASYNC_connect(TCP_SOCKET tempSocket, ubyte sessionIdLen, ubyte * sessionId,
                  ubyte * masterSecret, const sbyte* dnsName,
                  certStorePtr certStore)
{
    return SSL_ASYNC_connectCommon((intBoolean)FALSE, tempSocket, NULL,
                                   sessionIdLen, sessionId,
                                   masterSecret, dnsName, certStore);
}

#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
/**
@brief      Start establishing a secure client-server connection.

@details    This function begins the process of establishing a secure
            connection between a %client and %server by sending an SSL \c
            Hello message to a %server.

@ingroup    func_ssl_async_client

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients only.
*/
extern sbyte4
SSL_ASYNC_start(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if ((CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState) &&
        (TRUE               == m_sslConnectTable[index].isClient))
    {
        SSLSocket*  pSSLSock       = m_sslConnectTable[index].pSSLSock;

        if (IS_SSL_SYNC(pSSLSock))
            goto exit;

        if (kSslSecureSessionNotEstablished == SSL_OPEN_STATE(pSSLSock))
            status = SSL_SOCK_clientHandshake(pSSLSock, TRUE);
        else
            status = ERR_SSL_CLIENT_START;

    }

exit:
    return (sbyte4)status;

} /* SSL_ASYNC_start */
#endif

#if (defined(__ENABLE_DIGICERT_OPENSSL_SHIM__) && defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
extern sbyte4
SSL_DTLS_start(sbyte4 connectionInstance)
{
    return DTLS_start(connectionInstance);
}
#endif

extern MSTATUS
SSL_SOCK_getPeerCertificateBytes(sbyte4 connectionInstance, ubyte **ppCertBytes, ubyte4 *pCertLen)
{
    MSTATUS	status = ERR_NULL_POINTER;
    sbyte4	index;
    SSLSocket * pSSLSock;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock       = m_sslConnectTable[index].pSSLSock;
    *ppCertBytes   = NULL;
    if (NULL != pSSLSock->pCertChain) {
	 status = CERTCHAIN_getCertificate(pSSLSock->pCertChain, 0,
					   (const ubyte **)ppCertBytes, pCertLen);
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/


#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
extern MSTATUS SSL_populateMutualAuthCertStore(sbyte4 connectionInstance,
                                               const SizedBuffer *pCerts, ubyte4 numCerts,
                                               ubyte *pKey, ubyte4 keyLen,
                                               const ubyte *pCACert, ubyte4 caCertLength)
{
    MSTATUS	status = OK;
    sbyte4	index;
    SSLSocket * pSSLSock;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        status = ERR_SSL;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (OK > (status = SSLSOCK_populateMutualAuthCertStore(pSSLSock,
                                                           pCerts, numCerts,
                                                           pKey, keyLen,
                                                           pCACert, caCertLength)))
    {
        goto exit;
    }

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/


#ifndef __DISABLE_SSL_GET_SOCKET_API__
/**
@brief      Get a connection's socket identifier.

@details    This function returns the socket identifier for the specified
            connection instance.

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_GET_SOCKET_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pRetSocket           On return, pointer to the socket corresponding to
                              the connection instance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_getSocketId(sbyte4 connectionInstance, TCP_SOCKET *pRetSocket)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pRetSocket)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        *pRetSocket = m_sslConnectTable[index].socket;
        status = OK;
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_getSocketId() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_getPeerDescr(sbyte4 connectionInstance, const peerDescr **ppRetPeerDescr)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == ppRetPeerDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        *ppRetPeerDescr = &m_sslConnectTable[index].peerDescr;
        status = OK;
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_getPeerDescr() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}
#endif
#endif /* __DISABLE_SSL_GET_SOCKET_API__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_getNextConnectionInstance(ubyte4 *pCookie, sbyte4 *pConnectionInstance, const peerDescr **ppRetPeerDescr)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pCookie || NULL == pConnectionInstance || NULL == ppRetPeerDescr || NULL == m_sslConnectTable)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = *pCookie; index < m_sslMaxConnections; index++)
    {
        if ((index >= 0 && index < m_sslMaxConnections) &&
            (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState) &&
            ( !m_sslConnectTable[index].isClient ))
        {
            *pCookie = index+1;
            *pConnectionInstance = m_sslConnectTable[index].instance;
            *ppRetPeerDescr = &m_sslConnectTable[index].peerDescr;
            status = OK;
            break;
        }
    }

exit:
    return (sbyte4)status;
}
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_SSL_IS_SESSION_API__
/**
@brief      Determine whether a connection instance represents an SSL/TLS
            %server, an SSL/TLS %client, or an unrecognized connection (for
            example, SSH).

@details    This function determines whether a given connection instance
            represents an SSL/TLS %server, an SSL/TLS %client, or an
            unrecognized connection (for example, SSH). The returned value
            will be one of the following:
            + 0&mdash;Indicates an SSL/TLS %server connection
            + 1&mdash;Indicates an SSL/TLS %client connection
            + Negative number&mdash;Indicates an unknown connection type

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_IS_SESSION_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().

@return     0 if the connection instance is an SSL/TLS %server; 1 if an
            SSL/TLS %client; negative number if an unrecognized connection.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_isSessionSSL(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        status = (MSTATUS) m_sslConnectTable[index].isClient;     /* 0 == server, 1 == client, negative == bad connection instance */
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_isSessionSSL() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
/**
@todo_64
@ingroup    func_ssl_ungrouped
*/
extern sbyte4
SSL_isSessionDTLS(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        status = (MSTATUS) m_sslConnectTable[index].pSSLSock->isDTLS;     /* 0 == SSL, 1 == DTLS, negative == bad connection instance */
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_isSessionDTLS() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}
#endif

#endif /* __DISABLE_SSL_IS_SESSION_API__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_SSL_SESSION_FLAGS_API__
/**
@brief      Get a connection's context (its flags).

@details    This function returns a connection's context&mdash;its flags. Your
            application can call this function any time after it calls
            SSL_connect().

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_SESSION_FLAGS_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pRetFlagsSSL         Pointer to the connection's flags, which have been
                              set by SSL_setSessionFlags.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_getSessionFlags(sbyte4 connectionInstance, ubyte4 *pRetFlagsSSL)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pRetFlagsSSL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            /* don't return the SSL_FLAG_INTERNAL_USE settings. */
            *pRetFlagsSSL = m_sslConnectTable[index].pSSLSock->runtimeFlags & (~SSL_FLAG_INTERNAL_USE);
            status = OK;
        }

    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_getSessionFlags() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}
#endif /* __DISABLE_SSL_SESSION_FLAGS_API__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_SSL_SESSION_FLAGS_API__
/**
@brief      Store a connection's context (its flags).

@details    This function stores a connection's context&mdash;its flags. Your
            application can call this function any time after it calls
            SSL_connect().

The context flags are specified by OR-ing the desired bitmask flag
definitions, defined in ssl.h:
+ \c SSL_FLAG_ACCEPT_SERVER_NAME_LIST
+ \c SSL_FLAG_ENABLE_RECV_BUFFER
+ \c SSL_FLAG_ENABLE_SEND_BUFFER
+ \c SSL_FLAG_ENABLE_SEND_EMPTY_FRAME
+ \c SSL_FLAG_NO_MUTUAL_AUTH_REQ
+ \c SSL_FLAG_REQUIRE_MUTUAL_AUTH

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_SESSION_FLAGS_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param flagsSSL             Bitmask of flags to set for the given connection's
                              context. They can be retrieved by calling
                              SSL_getSessionFlags().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       To avoid clearing any flags that are already set, you should first
            call SSL_getSessionFlags(), then OR the returned value with the
            desired new flag, and only then call %SSL_setSessionFlags().

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_setSessionFlags(sbyte4 connectionInstance, ubyte4 flagsSSL)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    ubyte4 bitMask;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            /* SSL_FLAG_NO_MUTUAL_AUTH_REQUEST are incompatible SSL_FLAG_REQUIRE_MUTUAL_AUTH */
            if (SSL_FLAG_NO_MUTUAL_AUTH_REQUEST == (flagsSSL & SSL_FLAG_NO_MUTUAL_AUTH_REQUEST))
            {
                bitMask = ~SSL_FLAG_REQUIRE_MUTUAL_AUTH;
                m_sslConnectTable[index].pSSLSock->runtimeFlags =  bitMask & (m_sslConnectTable[index].pSSLSock->runtimeFlags & SSL_FLAG_INTERNAL_USE);
            } else if (SSL_FLAG_REQUIRE_MUTUAL_AUTH == (flagsSSL & SSL_FLAG_REQUIRE_MUTUAL_AUTH))
            {
                bitMask = ~SSL_FLAG_NO_MUTUAL_AUTH_REQUEST;
                m_sslConnectTable[index].pSSLSock->runtimeFlags =  bitMask & (m_sslConnectTable[index].pSSLSock->runtimeFlags & SSL_FLAG_INTERNAL_USE);
            }

            /* also add back the SSL_FLAG_INTERNAL_USE settings. */
            m_sslConnectTable[index].pSSLSock->runtimeFlags = flagsSSL | (m_sslConnectTable[index].pSSLSock->runtimeFlags & SSL_FLAG_INTERNAL_USE);
            status = OK;
        }

    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setSessionFlags() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}
#endif /* __DISABLE_SSL_SESSION_FLAGS_API__ */

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__))
extern MSTATUS
SSL_setMutualAuthCertificateAlias(sbyte4 connectionInstance, ubyte *pAlias, ubyte4 aliasLen)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket *pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (pSSLSock->roleSpecificInfo.client.pCertAuthAlias != NULL)
        {
            DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pCertAuthAlias));
        }

        if (OK > (status = DIGI_MALLOC((void **) &(pSSLSock->roleSpecificInfo.client.pCertAuthAlias), aliasLen)))
            goto exit;

        pSSLSock->roleSpecificInfo.client.certAuthAliasLen = aliasLen;
        status = DIGI_MEMCPY(pSSLSock->roleSpecificInfo.client.pCertAuthAlias, pAlias, aliasLen);
    }

exit:
    return (sbyte4)status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_generateExpansionKey(sbyte4 connectionInstance, ubyte *pKey,ubyte2 keyLen, ubyte *keyPhrase, ubyte2 keyPhraseLen)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            status = SSL_SOCK_generateKeyExpansionMaterial(m_sslConnectTable[index].pSSLSock,
                pKey ,keyLen,keyPhrase,keyPhraseLen);
        }
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_generateExpansionKey() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_DIGICERT_SSL_KEY_EXPANSION__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_generateTLSExpansionKey(sbyte4 connectionInstance, ubyte *pKey,ubyte2 keyLen, ubyte *keyPhrase, ubyte2 keyPhraseLen)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            status = SSL_SOCK_generateTLSKeyExpansionMaterial(m_sslConnectTable[index].pSSLSock,
                pKey ,keyLen,keyPhrase,keyPhraseLen);
        }
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_generateTLSExpansionKey() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}

extern sbyte4
SSL_generateTLSExpansionKeyWithContext(sbyte4 connectionInstance, ubyte *pKey, ubyte2 keyLen,
                                       ubyte *pKeyPhrase, ubyte2 keyPhraseLen,
                                       ubyte *pContext, ubyte2 contextLen)
{
    sbyte4  index;
    SSLSocket*  pSSLSock;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        pSSLSock = m_sslConnectTable[index].pSSLSock;
        if (NULL != pSSLSock)
        {
            status = SSL_SOCK_generateTLSKeyExpansionMaterialWithContext(pSSLSock,
                                                                         pKey, keyLen,
                                                                         pKeyPhrase, keyPhraseLen,
                                                                         pContext, contextLen);
        }
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_generateTLSExpansionKey() returns status = ", (sbyte4)status);
#endif

exit:
    return (sbyte4)status;
}

MOC_EXTERN sbyte4
SSL_generateExportKeyMaterial(sbyte4 connectionInstance, ubyte *pKey, ubyte2 keyLen,
                                ubyte *pKeyPhrase, ubyte2 keyPhraseLen,
                                ubyte *pContext, ubyte2 contextLen, int useContext)
{
    MSTATUS status = OK;
    if (!useContext)
    {
        status = SSL_generateTLSExpansionKey(connectionInstance, pKey, keyLen, pKeyPhrase, keyPhraseLen);
    }
    else
    {
        status = SSL_generateTLSExpansionKeyWithContext(connectionInstance, pKey, keyLen,
                                                        pKeyPhrase, keyPhraseLen,
                                                        pContext, contextLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_KEY_EXPANSION__ */


/*------------------------------------------------------------------*/

/**
@brief      Get a connection's status.

@details    This function returns a connection's status: \c
            SSL_CONNECTION_OPEN or \c SSL_CONNECTION_NEGOTIATE.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h
@param connectionInstance   Connection instance returned from SSL_connect().
@param pRetStatusSSL        On successful return, session's current status: \c
                              SSL_CONNECTION_OPEN or \c SSL_CONNECTION_NEGOTIATE.


@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_getSessionStatus(sbyte4 connectionInstance, ubyte4 *pRetStatusSSL)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pRetStatusSSL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
                *pRetStatusSSL = SSL_CONNECTION_OPEN;
            else
                *pRetStatusSSL = SSL_CONNECTION_NEGOTIATE;

            status = OK;
        }
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_getSessionStatus() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}

#if defined(__ENABLE_DIGICERT_OPENSSL_SHIM__)
extern sbyte4
SSL_getSessionStatusEx(sbyte4 connectionInstance, ubyte4 *pRetStatusSSL)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pRetStatusSSL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        if (NULL != m_sslConnectTable[index].pSSLSock)
        {
            if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
            {
                if (m_sslConnectTable[index].pSSLSock->rehandshake)
                {
                    *pRetStatusSSL = SSL_CONNECTION_RENEGOTIATE;
                }
                else
                {
                    *pRetStatusSSL = SSL_CONNECTION_OPEN;
                }
            }
            else
            {
                *pRetStatusSSL = SSL_CONNECTION_NEGOTIATE;
            }

            status = OK;
        }
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_getSessionStatusEx() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}
#endif

/*------------------------------------------------------------------*/


#ifndef __DISABLE_SSL_IOCTL_API__
extern sbyte4
SSL_Settings_Ioctl(ubyte4 setting, void *value)
{
    MSTATUS status = OK;
    sslSettings *pSSLSettings = NULL;
#if ((defined(__ENABLE_DIGICERT_TLS13__)) && (defined(__ENABLE_DIGICERT_TLS13_PSK__)) && (defined(__ENABLE_DIGICERT_TLS13_0RTT__)))
    SSLSocket *pSSLSock = NULL;
    sbyte4  index;
#endif

    pSSLSettings = SSL_sslSettings();
    if (NULL == pSSLSettings)
    {
        status =  ERR_SSL_BAD_ID;
        goto exit;
    }

    switch(setting)
    {
        case SSL_SETTINGS_MAX_BYTE_COUNT:
        {
            pSSLSettings->maxByteCount = (ubyte4) ((uintptr)value);
        }
        break;

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
        case SSL_SETTINGS_MAX_TIMER_COUNT:
        {
            pSSLSettings->maxTimerCountForRehandShake = (ubyte4) (uintptr)value;
        }
        break;
#endif

#if ((defined(__ENABLE_DIGICERT_TLS13__)) && (defined(__ENABLE_DIGICERT_TLS13_PSK__)) && (defined(__ENABLE_DIGICERT_TLS13_0RTT__)))
        case SSL_SETTINGS_GET_RECV_MAX_EARLY_DATA:
        {
            value = (void *)&pSSLSettings->recvEarlyDataSize;
        }
        break;

        case SSL_SETTINGS_SET_RECV_MAX_EARLY_DATA:
        {
            ubyte4 recvEarlyDataSize = (ubyte4) (uintptr)value;

            /* Ensure that the new recvEarlyDataSize is greater than
             * maxEarlyData size configured for all the session tickets
             */
            for (index = 0; index < m_sslMaxConnections; index++)
            {
                if ((CONNECT_OPEN == m_sslConnectTable[index].connectionState) && (FALSE == m_sslConnectTable[index].isClient))
                {
                    pSSLSock = m_sslConnectTable[index].pSSLSock;

                    if (pSSLSock != NULL)
                    {
                        if ((recvEarlyDataSize < SSL_TLS13_RECV_EARLY_DATA_SIZE) &&
                            (recvEarlyDataSize < pSSLSettings->recvEarlyDataSize))
                        {
                            status = ERR_SSL_INVALID_EARLY_DATA_SIZE;
                            goto exit;
                        }
                    }
                }
            }
            pSSLSettings->recvEarlyDataSize = recvEarlyDataSize;
        }
        break;
#endif
        default:
            status = ERR_SSL_BAD_ID;
            break;
    }

exit:
    return status;
}
/**
@brief      Enable dynamic management of a connection's features.

@details    This function enables dynamic management (enabling and disabling)
            of selected features for a specific SSL session's connection
            instance. (The initial value for these settings is defined in ssl.h.)

You can dynamically alter whether SSLv3, TLS 1.0, or TLS 1.1 is used by
calling this function for the \c SSL_SET_VERSION feature flag setting with
any of the following values:
- 0&mdash;Use SSLv3
- 1&mdash;Use TLS 1.0
- 2&mdash;Use TLS 1.1

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_IOCTL_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param setting              SSL feature flag to dynamically alter; see SSL
                              runtime flag definitions (\c SSL_FLAG_*) in ssl.h.
@param value                Value to assign to the \p setting flag.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_ioctl(sbyte4 connectionInstance, ubyte4 setting, void *value)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket *pSSLSock = m_sslConnectTable[index].pSSLSock;

        status = ERR_SSL_IOCTL_FAILED;

        if (NULL != pSSLSock)
        {
            switch (setting)
            {
            case SSL_SET_VERSION:
            {
                if (kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
                {
                    ubyte4 version = (ubyte4) (uintptr) value;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ioctl() version = ", (sbyte4)version);
#endif
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                    if (pSSLSock->isDTLS)
                    {
                        if ( version != DTLS10_MINORVERSION &&
                             version != DTLS12_MINORVERSION &&
                             version != DTLS13_MINORVERSION)
                        {
                            goto exit;
                        }
                    }
                    else
#endif
                    {
                        if ( version > MAX_SSL_MINORVERSION ||
                             version < MIN_SSL_MINORVERSION )
                        {
                            goto exit;
                        }
                    }
                    pSSLSock->advertisedMinorVersion = (ubyte)version;     /* SSLv3 and TLS 1.0 or TLS 1.1 */
                    pSSLSock->runtimeFlags |= SSL_FLAG_VERSION_SET;
                    status = OK;
                }

                break;
            }
            case SSL_SET_MINIMUM_VERSION:
            {
                if (kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
                {
                    ubyte4 version = (ubyte4) (uintptr) value;

                    if ( version > MAX_SSL_MINORVERSION ||
                         version < MIN_SSL_MINORVERSION )
                    {
                        goto exit;
                    }

                    pSSLSock->minFallbackMinorVersion = (ubyte)version;     /* SSLv3 and TLS 1.0 or TLS 1.1 */
                    pSSLSock->runtimeFlags |= SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET;
                    status = OK;
                }

                break;
            }
            case SSL_SET_SCSV_VERSION:
			{
				if (kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
				{
                    ubyte4 version = (ubyte4) (uintptr) value;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
					if (pSSLSock->isDTLS)
					{
						if ( version != DTLS10_MINORVERSION && version != DTLS12_MINORVERSION)
							goto exit;
					} else
#endif
					{
                        if ( version > MAX_SSL_MINORVERSION ||
                             version < MIN_SSL_MINORVERSION )
                        {
                            goto exit;
                        }
					}
					pSSLSock->advertisedMinorVersion = (ubyte)version;     /* SSLv3 and TLS 1.0 or TLS 1.1 */
					pSSLSock->runtimeFlags |= SSL_FLAG_VERSION_SET;
					pSSLSock->runtimeFlags |= SSL_FLAG_SCSV_FALLBACK_VERSION_SET;
					status = OK;
				}
				break;
			}
            case SSL_SET_RECV_TIMEOUT:
            {
                ubyte4 timeout = (ubyte4)((uintptr)value);
                pSSLSock->timeOutReceive = timeout;
                status = OK;
                break;
            }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            case DTLS_SET_HANDSHAKE_RETRANSMISSION_TIMER:
            {
                ubyte4 timeout = (ubyte4)((usize)value);

                if (pSSLSock->isDTLS && kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
                {
                    pSSLSock->dtlsHandshakeTimeout = timeout;
                    status = OK;
                }

                break;
            }
            case DTLS_SET_PMTU:
            {
                ubyte4 mtu = (ubyte4)((usize)value);

                if (pSSLSock->isDTLS && kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
                {
                    pSSLSock->dtlsPMTU = mtu;
                    status = OK;
                }

                break;
            }
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__))
            case DTLS_USE_SRTP:
            {
                if (pSSLSock->isDTLS)
                {
                    ubyte* mki = (ubyte*)value;

                    if (NULL != pSSLSock->srtpMki)
                        FREE(pSSLSock->srtpMki);

                    pSSLSock->srtpMki = NULL;

                    if (mki && *mki > 0)
                    {
                        if (NULL == (pSSLSock->srtpMki = MALLOC(*mki + 1)))
                            return ERR_MEM_ALLOC_FAIL;

                        DIGI_MEMCPY(pSSLSock->srtpMki, mki, (*mki+1));
                    }

                    pSSLSock->useSrtp = TRUE;
                    status = OK;
                }

                break;
            }
#endif

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
            case DTLS_SET_HELLO_VERIFIED:
            {
                intBoolean helloVerified = (intBoolean)((usize)value);

                if ( (1 == helloVerified) && pSSLSock->isDTLS &&
                    !(m_sslConnectTable[index].isClient) )
                {
                    if (kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock))
                    {
                        /* HelloVerifyRequest is sent, update sequence numbers */
                        pSSLSock->nextSendSeq = 1;
                        pSSLSock->nextRecvSeq = 1;
                        pSSLSock->ownSeqnum   = 1;
                        pSSLSock->msgBase     = pSSLSock->nextRecvSeq;
                    }

                    status = OK;
                }

                break;
            }
#endif

#endif /* (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) */

            case SSL_GET_CLIENT_RANDOM:
                if (!pSSLSock->isDTLS)
                {
                    status = DIGI_MEMCPY(
                        value, pSSLSock->pClientRandHello, SSL_RANDOMSIZE);
                }
                break;

            case SSL_GET_SERVER_RANDOM:
                if (!pSSLSock->isDTLS)
                {
                    status = DIGI_MEMCPY(
                        value, pSSLSock->pServerRandHello, SSL_RANDOMSIZE);
                }
                break;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && (defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__))
            case SSL_REQUEST_SESSION_TICKET:
            {
                ubyte *requestTicket = (ubyte *)value;
                pSSLSock->roleSpecificInfo.client.requestSessionTicket = *requestTicket;
                status = OK;
                break;
            }
#if defined(__ENABLE_DIGICERT_TLS13__)
            case SSL_PSK_KEY_EXCHANGE_MODE:
            {
                ubyte *pskExchangeMode = (ubyte *)value;
                pSSLSock->roleSpecificInfo.client.pskKeyExchangeMode = *pskExchangeMode;
                pSSLSock->runtimeFlags |= SSL_PSK_EXCHANGE_MODE_FLAG_SET;
                status = OK;
                break;
            }
#endif
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
#if defined(__ENABLE_DIGICERT_TLS13__)
            case SSL_GET_KEY_UPDATE_DATA_TYPE:
            {
                ubyte4 *pKeyUpdateRequested = (ubyte4 *)value;
                *pKeyUpdateRequested = pSSLSock->keyUpdateRequested;
                status = OK;
                break;
            }

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
            case SSL_SET_SESSION_TICKET_NONCE_LEN:
            {
                ubyte nonceLen = (ubyte) (uintptr)value;
                if (nonceLen > SSL_SESSION_TICKET_NONCE_SIZE)
                {
                    goto exit;
                }
                pSSLSock->roleSpecificInfo.server.sessionTicketNonceLen = (ubyte) (uintptr)value;
                status = OK;
                break;
            }
            case SSL_ENABLE_TLS13_SESSION_TICKETS:
            {
                ubyte enableSessionTicket = (ubyte) (uintptr)value;
                if ((0xFE & enableSessionTicket) > 0)
                {
                    goto exit;
                }
                pSSLSock->roleSpecificInfo.server.enableTls13SessionTickets = (ubyte) (uintptr)value;
                status = OK;
                break;
            }
            case SSL_SET_NUM_TICKETS:
            {
                pSSLSock->roleSpecificInfo.server.numOfSessionTickets = (ubyte) (uintptr)value;
                status = OK;
                break;
            }
            case SSL_GET_NUM_TICKETS:
            {
                ubyte4 *pNumofTLS13PSK = (ubyte4 *)value;
                *pNumofTLS13PSK = pSSLSock->roleSpecificInfo.server.numOfSessionTickets;
                status = OK;
                break;
            }
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
            case SSL_SET_SEND_EARLY_DATA:
            {
                ubyte4 sendEarlyData = (ubyte4) (uintptr)value;
                if (1 == sendEarlyData)
                {
                    pSSLSock->sendEarlyData = TRUE;
                }
                else
                {
                    pSSLSock->sendEarlyData = FALSE;
                }
                status = OK;
                break;
            }
            case SSL_GET_MAX_EARLY_DATA:
            {
                value = (void *)&pSSLSock->maxEarlyDataSize;
                status = OK;
                break;
            }
            case SSL_SET_MAX_EARLY_DATA:
            {
                ubyte4 maxEarlyDataSize = (ubyte4) (uintptr)value;

                if (maxEarlyDataSize > m_sslSettings.recvEarlyDataSize)
                {
                    status = ERR_SSL_INVALID_EARLY_DATA_SIZE;
                    goto exit;
                }
                pSSLSock->maxEarlyDataSize = maxEarlyDataSize;
                status = OK;
                break;
            }
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
            case SSL_GET_EARLY_DATA_STATUS:
            {
                value = (void *)&pSSLSock->earlyDataExtAccepted;
                status = OK;
                break;
            }
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ */
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
            case SSL_SET_USE_EXTENDED_MASTERSECRET:
            {
                ubyte4 supportExtendedMasterSecretExt = (ubyte4) (uintptr)value;

                if (1 == supportExtendedMasterSecretExt)
                    pSSLSock->supportExtendedMasterSecret = TRUE;

                status = OK;
                break;
            }
#endif
            default:
            {
                break;
            }
            }
        }

    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_ioctl() returns status = ", (sbyte4)status);
#endif

    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
extern sbyte4
SSL_parseAlert(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass, sbyte4 *pRetErrorCode)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pRetErrorCode)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket *pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (TRUE == SSLSOCK_parseAlert(pSSLSock, alertId, alertClass, pRetErrorCode))
        {
            status = OK;
        }
    }

exit:
    return (sbyte4)status;
}

/**
@brief      Get the SSL alert code for a Mocana error.

@details    This function returns the SSL alert code for the specified Mocana
            error (from merrors.h), as well as the alert class (\c
            SSLALERTLEVEL_WARNING or \c SSLALERTLEVEL_FATAL). See @ref
            ssl_alert_codes for the list of alert definitions.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param lookupError          Mocana error value to look up.
@param pRetAlertId          On return, pointer to SSL alert code.
@param pAlertClass          On return, pointer to alert class definition value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_lookupAlert(sbyte4 connectionInstance, sbyte4 lookupError, sbyte4 *pRetAlertId, sbyte4 *pAlertClass)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if ((NULL == pRetAlertId) || (NULL == pAlertClass))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket *pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (TRUE != SSLSOCK_lookupAlert(pSSLSock, lookupError, pRetAlertId, pAlertClass))
        {
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                *pRetAlertId = SSL_ALERT_CLOSE_NOTIFY;  /* there is no catch-all alert for SSLv3 */
                *pAlertClass = SSLALERTLEVEL_FATAL;     /* we set to fatal to indicate some other error */
            }
            else
#endif
            {
                *pRetAlertId = SSL_ALERT_INTERNAL_ERROR;
                *pAlertClass = SSLALERTLEVEL_FATAL;
            }
        }

        status = OK;

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
        /* on fatal alert, we want to scramble session cache's master secret */
        if (SSLALERTLEVEL_FATAL == *pAlertClass)
            status = SSLSOCK_clearServerSessionCache(pSSLSock);
#endif
    }


exit:
    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
/**
@brief      Send an SSL alert message to an SSL peer.

@details    This function sends an SSL alert message to an SSL peer. Typical
            usage is to look up an error code using SSL_lookupAlert(), and
            then send the alert message using this SSL_sendAlert() function.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param alertId              SSL alert code.
@param alertClass           SSL alert class definition value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_sendAlert(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock    = m_sslConnectTable[index].pSSLSock;
        intBoolean encryptBool = (CONNECT_NEGOTIATE == m_sslConnectTable[index].connectionState) ? FALSE : TRUE;

        status = SSLSOCK_sendAlert(pSSLSock, encryptBool, alertId, alertClass);
    }

exit:
    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_sendInnerApp(sbyte4 connectionInstance, InnerAppType innerApp,ubyte* pMsg, ubyte4 msgLen , ubyte4 * retMsgLen)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock    = m_sslConnectTable[index].pSSLSock;

        status = SSLSOCK_sendInnerApp(pSSLSock, innerApp, pMsg, msgLen , retMsgLen, m_sslConnectTable[index].isClient);     /* 0 == server, 1 == client, negative == bad connection instance */
    }

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_DIGICERT_INNER_APP__ */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_updateInnerAppSecret(sbyte4 connectionInstance, ubyte* session_key, ubyte4 sessionKeyLen)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock    = m_sslConnectTable[index].pSSLSock;

        status = SSLSOCK_updateInnerAppSecret(pSSLSock, session_key, sessionKeyLen);
    }

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_DIGICERT_INNER_APP__ */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_verifyInnerAppVerifyData(sbyte4 connectionInstance,ubyte *data,InnerAppType appType)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock    = m_sslConnectTable[index].pSSLSock;

        status = SSLSOCK_verifyInnerAppVerifyData(pSSLSock, data, appType, m_sslConnectTable[index].isClient);     /* 0 == server, 1 == client, negative == bad connection instance */
    }

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_DIGICERT_INNER_APP__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

/**
@brief      Enable specified ciphers.

@details    This function dynamically enables just those ciphers that are
            specified in the function call. If none of the specified ciphers
            match those supported by NanoSSL %client/server and enabled in
            your implementation, an error is returned.

The function must not be called before a connection is established (see
SSL_connect() for synchronous clients, SSL_ASYNC_connect() for asynchronous
clients), but must be called before SSL_negotiateConnection() (for either
synchronous or asynchronous clients).

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pCipherSuiteList     Pointer to value (or array of values) representing
                            the desired cipher ID(s).\n
                            Values are as specified per RFC 4346 for the TLS
                            Cipher Suite Registry; refer to the following Web
                            page:
                            http://www.iana.org/assignments/tls-parameters .
@param listLength           Number of entries in \p pCipherSuiteList.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_enableCiphers(sbyte4 connectionInstance, const ubyte2 *pCipherSuiteList,
                  ubyte4 listLength)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    ubyte2 *pUpdatedCipherList = NULL;
    ubyte4  updatedCipherListLength = 0;
    /* Note if the cipher table has been initialized */
    intBoolean cipherTableInitialized;
#if defined(__ENABLE_DIGICERT_FORCE_TLS13_CIPHERS__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    ubyte4 sessionFlags = 0;
#endif

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;
        sbyte4      cipherIndex, i;
        ubyte4      count;

        if (NULL == pSSLSock)
            goto exit;

        status = ERR_SSL_CONFIG;

        if (SSL_MAX_NUM_CIPHERS < SSL_SOCK_numCiphersAvailable())
        {
            /* bad news: we can't detect this problem at compile time */
            /* good news: the test monkeys should detect this problem */
            goto exit;
        }

        cipherTableInitialized = pSSLSock->isCipherTableInit;
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_FORCE_TLS13_CIPHERS__)

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    /* Set the postHandshake Auth flag.
     * This is needed in the renegotiate flow for OpenSSL-1.0.2x connector negotiating TLS 1.3
     */
    if (!pSSLSock->server)
    {
        if (OK <= SSL_getSessionFlags(connectionInstance, &sessionFlags))
        {
            /* Ignore the return type */
            SSL_setSessionFlags(connectionInstance, sessionFlags | SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH);
        }
    }
#endif
#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)
        updatedCipherListLength += 2; /* 0x1301, 0x1302 */

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
        updatedCipherListLength += 1; /* 0x1303 */
#endif

#if !defined(__DISABLE_AES128_CIPHER__)
#if defined(__ENABLE_DIGICERT_CCM__)
        updatedCipherListLength += 1; /* 0x1304 */
#ifdef __ENABLE_DIGICERT_CCM_8__
        updatedCipherListLength += 1; /* 0x1305 */
#endif /*  __ENABLE_DIGICERT_CCM_8__ */
#endif /* __ENABLE_DIGICERT_CCM__ */
#endif /* !__DISABLE_AES128_CIPHER__ */
#endif /* __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__ */

        if (updatedCipherListLength != 0)
        {
            ubyte4 i = 0;
            if (OK > (status = DIGI_MALLOC((void **)&pUpdatedCipherList,
                                          (sizeof(ubyte2) * (updatedCipherListLength + listLength)))))
            {
                goto exit;
            }

            DIGI_MEMSET((ubyte *) pUpdatedCipherList, 0x00, (sizeof(ubyte2) * (updatedCipherListLength + listLength)));
            updatedCipherListLength += listLength;

#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)
            pUpdatedCipherList[i] = 0x1301;
            i++;

            pUpdatedCipherList[i] = 0x1302;
            i++;

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
            pUpdatedCipherList[i] = 0x1303;
            i++;
#endif

#if !defined(__DISABLE_AES128_CIPHER__)
#if defined(__ENABLE_DIGICERT_CCM__)
            pUpdatedCipherList[i] = 0x1304;
            i++;
#ifdef __ENABLE_DIGICERT_CCM_8__
            pUpdatedCipherList[i] = 0x1305;
            i++;
#endif /*  __ENABLE_DIGICERT_CCM_8__ */
#endif /* __ENABLE_DIGICERT_CCM__ */
#endif /* !__DISABLE_AES128_CIPHER__ */
#endif /* __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__ */
            if (OK > (status = DIGI_MEMCPY(pUpdatedCipherList + i, pCipherSuiteList, sizeof(ubyte2) * listLength)))
            {
                if (updatedCipherListLength > listLength)
                {
                    DIGI_FREE((void **)&pUpdatedCipherList);
                }

                goto exit;
            }
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_FORCE_TLS13_CIPHERS__ */
        {
            pUpdatedCipherList      = (ubyte2 *) pCipherSuiteList;
            updatedCipherListLength = listLength;
        }

        for (i = 0; i < SSL_SOCK_numCiphersAvailable(); i++)
        {
            intBoolean cipherFound = FALSE;
            for (count = 0; count < updatedCipherListLength; count++)
            {
                /* ability to chose at run-time cipher suites to support */
                if ((0 <= (cipherIndex = SSL_SOCK_getCipherTableIndex(pSSLSock, pUpdatedCipherList[count]))) &&
                    (cipherIndex == i))
                {
                    /* If the cipher table is already initialized,
                     * do NOT reset the existing value.
                     */
                    if (FALSE == cipherTableInitialized)
                    {
                        /* mark the cipher as active */
                        pSSLSock->isCipherEnabled[cipherIndex] = TRUE;
                        pSSLSock->isCipherTableInit = TRUE;
                    }

                    /* we successfully enabled at least one cipher, so that is goodness */
                    cipherFound = TRUE;
                    status = OK;
                    break;
                }
            }

            /* If this cipher was not passed in the list, explicitly disable it */
            if (FALSE == cipherFound)
            {
                pSSLSock->isCipherEnabled[i] = FALSE;
                pSSLSock->isCipherTableInit = TRUE;
            }
        }
    }

exit:
    if (updatedCipherListLength > listLength)
    {
        DIGI_FREE((void **)&pUpdatedCipherList);
    }

    return (sbyte4)status;
} /* SSL_enableCiphers */

extern sbyte4
SSL_getCipherList(sbyte4 connectionInstance, ubyte2 **ppCipherIdList, ubyte4 *pCount)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket* pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL == pSSLSock)
        goto exit;

    status = SSL_SOCK_getCipherList(pSSLSock, ppCipherIdList, pCount);

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern sbyte4
SSL_disableCipherHashAlgorithm(sbyte4 connectionInstance, TLS_HashAlgorithm hashId)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL == pSSLSock)
            goto exit;

        status = SSL_SOCK_disableCipherHashAlgorithm(pSSLSock, hashId);
    }

exit:
    return (sbyte4)status;
} /* SSL_disableCipherHashAlgorithm */

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
extern sbyte4
SSL_setDSACiphers(sbyte4 connectionInstance, ubyte enableDSACiphers)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;
        intBoolean value    = (1 == enableDSACiphers) ? TRUE : FALSE;

        if (NULL == pSSLSock)
            goto exit;

        m_sslSettings.allowDSASigAlg = value;
        status = SSLSOCK_setDSACiphers(pSSLSock, value);
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */
#endif /* __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__)   || \
        defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)|| \
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
/**
@coming_soon
@ingroup    func_ssl_ungrouped
*/
extern sbyte4
SSL_enableECCCurves(sbyte4 connectionInstance,
                    enum tlsExtNamedCurves* pECCCurvesList,
                    ubyte4 listLength)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL == pSSLSock)
            goto exit;

        status = SSL_SOCK_enableECCCurves(pSSLSock, pECCCurvesList, listLength);
    }

exit:
    return (sbyte4)status;

} /* SSL_enableECCCurves */
#endif
#endif /* __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__ */

/*------------------------------------------------------------------*/

/**
@brief      Get a connection's ciphers and ecCurves.

@details    This function retrieves the specified connection's cipher and
            ecCurves.

@ingroup    func_ssl_core

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pCipherId            On return, pointer to the connection's cipher value.
@param pPeerEcCurves        On return, pointer to the connection's supported
                              ecCurves values (as a bit field built by OR-ing
                              together shift-left combinations of bits shifted
                              by the value of \c tlsExtNamedCurves enumerations).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_getCipherInfo( sbyte4 connectionInstance, ubyte2* pCipherId,
                  ubyte4* pPeerEcCurves)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    /* default values */
    *pCipherId = 0;
    *pPeerEcCurves = 0;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API can be called prior or after SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL == pSSLSock)
            goto exit;

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
        *pPeerEcCurves = pSSLSock->roleSpecificInfo.server.clientECCurves;
#endif
        status = SSL_SOCK_getCipherId( pSSLSock, pCipherId);
    }

exit:
    return (sbyte4)status;

} /* SSL_getCipherInfo */

extern MSTATUS
SSL_getSharedSignatureAlgorithm(sbyte4 connectionInstance, ubyte4 algoListIndex,
                                ubyte2 *pSigAlgo, ubyte isPeer)
{
    MSTATUS status = OK;
    sbyte4  index;
    SSLSocket *pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    status = SSL_SOCK_getSharedSignatureAlgorithm(pSSLSock, algoListIndex, pSigAlgo, isPeer);

exit:
    return status;
}

extern MSTATUS
SSL_setCipherAlgorithm(sbyte4 connectionInstance, ubyte2 *pList, ubyte4 listLength, ubyte4 listType)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket* pSSLSock = NULL;
    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;
#if defined(__ENABLE_DIGICERT_TLS13__)
    status = SSL_SOCK_setCipherAlgorithm(pSSLSock, pList, listLength, listType);
#else
    status = SSL_SOCK_setSupportedAlgorithm(pSSLSock, pList, listLength);
#endif

exit:
    return status;
}

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_PQC__)
extern MSTATUS
SSL_enforcePQCAlgorithm(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket* pSSLSock = NULL;
    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    status = SSL_SOCK_enforcePQCAlgorithm(pSSLSock);

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*------------------------------------------------------------------*/

/**
@brief      Get a connection's SSL/TLS version

@details    This function retrieves the specified connection's SSL/TLS version.

@todo_eng_review (is this for sync and/or async, client and/or server?)

@ingroup    func_ssl_ungrouped

@since 2.02
@version 2.02 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pVersion             On return, pointer to the connection's SSL version.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.


@funcdoc ssl.c
*/
extern sbyte4
SSL_getSSLTLSVersion(sbyte4 connectionInstance, ubyte4* pVersion)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    /* default values */
    *pVersion = 0xFFFFFFFF;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API can be called prior or after SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL == pSSLSock)
            goto exit;

        *pVersion = pSSLSock->sslMinorVersion;

        status = OK;
    }

exit:
    return (sbyte4)status;

} /* SSL_getSSLTLSVersion */


/*------------------------------------------------------------------*/

/**
@brief      Set the Application Layer Protocol Negotiation information.

@details    This function sets (defines) the application layer protocols to
            use during connection negotiations.

@ingroup    func_ssl_ungrouped

@since TBD  (added in commit [e6173b4], March 21, 2016)
@version TBD and later
@todo_version   When version number is decided, fix the \@since/\@version info.

@todo_eng_review    Please review the function and param descriptions to
                    ensure that the Tech Pubs edits are ok.

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param  connectionInstance  Connection instance returned from SSL_connect().
@param  numNextProtocols    Number of elements in the \p nextProtocols array
                              of protocols to use.
@param  nextProtocols       Array of protocols to use, in order of preference.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_setApplicationLayerProtocol(sbyte4 connectionInstance,
                                sbyte4 numNextProtocols,
                                const char** nextProtocols)
{
    sbyte4  i, index;
    ubyte4 totalLen;
    ubyte* tmp;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (pSSLSock->alpnProtocols)
        {
            FREE( pSSLSock->alpnProtocols);
        }

        pSSLSock->alpnProtocols = 0;
        pSSLSock->alpnProtocolsLen = 0;

        if (!nextProtocols || !numNextProtocols)
        {
            status = OK;
            goto exit;
        }

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

        pSSLSock->alpnProtocols = (ubyte*) MALLOC( totalLen);
        if (!pSSLSock->alpnProtocols)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        pSSLSock->alpnProtocolsLen = (ubyte2) totalLen;

        tmp = pSSLSock->alpnProtocols;
        /* second loop: copy data */
        for (i = 0; i < numNextProtocols; ++i)
        {
            *tmp = (ubyte) DIGI_STRLEN((const sbyte*) nextProtocols[i]);
            DIGI_MEMCPY(tmp+1, nextProtocols[i], *tmp);
            tmp += 1 + *tmp;
        }

        status = OK;
    }

exit:
    return (sbyte4)status;
} /* SSL_setApplicationLayerProtocol */


#if defined(__ENABLE_DIGICERT_TLS13__)
MOC_EXTERN MSTATUS
SSL_sendKeyUpdateRequest(sbyte4 connectionInstance, ubyte updateRequest)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined (__ENABLE_DIGICERT_DTLS_SERVER__)
        if (pSSLSock->isDTLS)
        {
            status = SSLSOCK_sendKeyUpdateRequestDTLS(pSSLSock, updateRequest);
            if (OK != status)
                goto exit;

            TIMER_unTimer((void *)pSSLSock, pSSLSock->postHandshakeState[kKeyUpdate].msgTimer);
            pSSLSock->postHandshakeState[kKeyUpdate].msgTimeout = 1000;
            TIMER_queueTimer((void*)pSSLSock, pSSLSock->postHandshakeState[kKeyUpdate].msgTimer,
                pSSLSock->postHandshakeState[kKeyUpdate].msgTimeout/1000, 0);
        }
        else
#endif
        {
            status = SSLSOCK_sendKeyUpdateRequest(pSSLSock, updateRequest);
        }
    }

exit:
    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) || \
     defined(__ENABLE_DIGICERT_SSL_SERVER__)

extern MSTATUS
SSL_getSignatureAlgo(sbyte4 connectionInstance, ubyte2 *pSigAlg)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (NULL == pSigAlg)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        status = OK;
        if (pSSLSock->server)
        {
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
            *pSigAlg = pSSLSock->signatureAlgo;
#else
            status = ERR_SSL_NOT_SUPPORTED;
#endif
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
            *pSigAlg = pSSLSock->roleSpecificInfo.client.mutualAuthSignAlgo;
#else
            status = ERR_SSL_NOT_SUPPORTED;
#endif
        }
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ && __ENABLE_DIGICERT_SSL_CLIENT__ */

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
MOC_EXTERN MSTATUS
SSL_sendPosthandshakeAuthCertificateRequest(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        status = SSL_SERVER_sendPostHandshakeAuthCertificateRequest(pSSLSock);
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        if (OK != status)
            goto exit;

        pSSLSock->postHandshakeState[kCertificateRequest].state = kDtlsWaiting;

        TIMER_unTimer((void *)pSSLSock, pSSLSock->postHandshakeState[kCertificateRequest].msgTimer);
        pSSLSock->postHandshakeState[kCertificateRequest].msgTimeout = 1000;
        TIMER_queueTimer((void*)pSSLSock, pSSLSock->postHandshakeState[kCertificateRequest].msgTimer,
            pSSLSock->postHandshakeState[kCertificateRequest].msgTimeout/1000, 0);
#endif
    }

exit:
    return status;
}
#endif

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
extern
sbyte4 SSL_setEarlyData(sbyte4 connectionInstance,
                               ubyte *pEarlyData, ubyte4 earlyDataSize)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        /* Shallow copy */
        pSSLSock->pEarlyData    = pEarlyData;
        pSSLSock->earlyDataSize = earlyDataSize;
        pSSLSock->sendEarlyData = TRUE;
        status = OK;
    }

exit:
    return (sbyte4)status;
}

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
/* Set early_data_state value based on */
sbyte4 SSL_getEarlyDataState(sbyte4 connectionInstance, ubyte4 *pEarlyDataState)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock;

    if (NULL == pEarlyDataState)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    *pEarlyDataState = pSSLSock->roleSpecificInfo.server.zeroRTT;

    status = OK;

exit:
    return status;
}

extern
sbyte4 SSL_setMaxEarlyDataSize(sbyte4 connectionInstance,
                               sbyte4 maxEarlyDataSize)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (maxEarlyDataSize > (sbyte4)m_sslSettings.recvEarlyDataSize)
    {
        status = ERR_SSL_INVALID_EARLY_DATA_SIZE;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;
        pSSLSock->maxEarlyDataSize = maxEarlyDataSize;
        status = OK;
    }

exit:
    return (sbyte4)status;
}

extern
sbyte4 SSL_setRecvEarlyDataSize(sbyte4 connectionInstance,
                                sbyte4 recvEarlyDataSize)
{
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket *pSSLSock = NULL;
    sbyte4 index;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (pSSLSock != NULL)
    {
        if ((recvEarlyDataSize < SSL_TLS13_RECV_EARLY_DATA_SIZE) &&
            (recvEarlyDataSize < (sbyte4)pSSLSock->maxEarlyDataSize))
        {
            status = ERR_SSL_INVALID_EARLY_DATA_SIZE;
            goto exit;
        }
    }

    m_sslSettings.recvEarlyDataSize = recvEarlyDataSize;

exit:
    return (sbyte4)status;
}

#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ && __ENABLE_DIGICERT_TLS13_0RTT__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */


/*------------------------------------------------------------------*/

/**
@brief      Retrieve the selected Application Layer Protocol.

@details    This function retrieves the index of the selected application
            layer protocol, and returns it in the \p .

@ingroup    func_ssl_ungrouped

@since TBD  (added in commit [e6173b4], March 21, 2016)
@version TBD and later
@todo_version   When version number is decided, fix the \@since/\@version info.

@todo_eng_review    Please review the function and param descriptions to
                    ensure that the Tech Pubs edits are ok.

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param  connectionInstance              Connection instance returned from
                                          SSL_connect().
@param  selectedApplicationProtocol     On input, application protocol to
                                          search for. On return, pointer to
                                          matching socket.
@param  selectedApplicationProtocolLen  On input, length (number of bytes) in
                                          the string representing the selected
                                          application protocol (\p selected
                                          ApplicationProtocol). On return,
                                          pointer to length of string
                                          representing the mathcing socket.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_getSelectedApplicationProtocol( sbyte4 connectionInstance,
                                   const ubyte** selectedApplicationProtocol,
                                   ubyte4* selectedApplicationProtocolLen)
{
    sbyte4 index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (!selectedApplicationProtocol || !selectedApplicationProtocolLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called after to SSL_negotiateConnection() */
    if (CONNECT_OPEN  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (pSSLSock->selectedALPN)
        {
            *selectedApplicationProtocol = pSSLSock->selectedALPN + 1;
            *selectedApplicationProtocolLen = *(pSSLSock->selectedALPN);
        }
        else
        {
            *selectedApplicationProtocol = 0;
            *selectedApplicationProtocolLen = 0;
        }

        status = OK;
    }

exit:
    return (sbyte4)status;
} /* SSL_getSelectedApplicationProtocol */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_setEAPFASTParams(sbyte4 connectionInstance, ubyte* pPacOpaque,
                     ubyte4 pacOpaqueLen, ubyte pPacKey[/*PACKEY_SIZE*/])
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        status = SSL_SOCK_setEAPFASTParams(m_sslConnectTable[index].pSSLSock,
            pPacOpaque, pacOpaqueLen, pPacKey);
    }

exit:
    return (sbyte4)status;

} /* SSL_setEAPFASTParams */
#endif /* __ENABLE_DIGICERT_EAP_FAST__ && __ENABLE_DIGICERT_SSL_CLIENT__*/


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_FAST__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_getEAPFAST_CHAPChallenge(sbyte4 connectionInstance, ubyte *challenge , ubyte4 challengeLen)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    status   = OK;

    if ((NULL == pSSLSock) || (NULL == pSSLSock->fastChapChallenge))
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *) "SSL_findSocket: connectionInstance not found.");
        goto exit;
    }

    DIGI_MEMCPY(challenge, pSSLSock->fastChapChallenge, (challengeLen > FAST_MSCHAP_CHAL_SIZE)? FAST_MSCHAP_CHAL_SIZE : challengeLen);


exit:
    return status;

}

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_getEAPFAST_IntermediateCompoundKey(sbyte4 connectionInstance, ubyte *s_imk,
                                       ubyte *msk, ubyte mskLen,
                                       ubyte *imk)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    status   = OK;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*) "SSL_findSocket: connectionInstance not found.");
        goto exit;
    }
    status = SSL_SOCK_generateEAPFASTIntermediateCompoundKey(pSSLSock,
                                                   s_imk, msk, mskLen, imk);

exit:
    return status;
}

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal (EAP stack) code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_generateEAPFASTSessionKeys(sbyte4 connectionInstance, ubyte* S_IMCK, sbyte4 s_imckLen,
                                    ubyte* MSK, sbyte4 mskLen, ubyte* EMSK, sbyte4 emskLen/*64 Len */)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    status   = OK;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*) "SSL_findSocket: connectionInstance not found.");
        goto exit;
    }
    status = SSL_SOCK_generateEAPFASTSessionKeys(pSSLSock, S_IMCK, s_imckLen, MSK, mskLen, EMSK, emskLen);

exit:
    return status;
}


#endif /* __ENABLE_DIGICERT_EAP_FAST__  */
/*------------------------------------------------------------------*/

extern sbyte4
SSL_setMinRSAKeySize(ubyte4 keySize)
{
    MSTATUS status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;

    if (0 == keySize)
    {
        goto exit;
    }

    /* Make sure keySize is a power of 2 */
    switch (keySize)
    {
#if defined(__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__)
        case 1024:
        case 4096:
#endif
        case 2048:
        case 3072:
            m_sslSettings.minRSAKeySize = keySize;
            status = OK;
            break;

        default:
            break;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
extern sbyte4
SSL_setSha1SigAlg(intBoolean setting)
{
    MSTATUS status;

    if ( (TRUE != setting) && (FALSE != setting) )
    {
        status = ERR_INVALID_INPUT;
    }
    else
    {
        m_sslSettings.allowSha1SigAlg = setting;
        status = OK;
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
extern sbyte4
SSL_setFIPSEnabled(ubyte isFIPSEnabled)
{
    MSTATUS status = OK;
    m_sslSettings.isFIPSEnabled = isFIPSEnabled;

    if (FALSE == isFIPSEnabled)
    {
        m_sslSettings.minDHKeySize = MIN_SSL_DH_SIZE;
    }
    else
    {
        if (2048 > m_sslSettings.minDHKeySize)
        {
            m_sslSettings.minDHKeySize = 2048;
        }
    }

    return status;
}

extern sbyte4
SSL_checkFIPS()
{
    MSTATUS status = OK;

    if (FIPS_ModeEnabled())
    {
        goto exit;
    }
    else
    {
        status = getFIPS_powerupStatus(FIPS_ALGO_ALL);
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
/**
@coming_soon
@ingroup    func_ssl_ungrouped
*/
extern sbyte4
SSL_setServerNameIndication(sbyte4 connectionInstance, const char* serverName)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if ( pSSLSock->serverNameIndication)
        {
            FREE( pSSLSock->serverNameIndication);
            pSSLSock->serverNameIndication = 0;
        }

        if (serverName && *serverName)
        {
            int serverNameLen = 1 + DIGI_STRLEN((const sbyte*) serverName);

            pSSLSock->serverNameIndication = (sbyte*) MALLOC( serverNameLen);
            if (!pSSLSock->serverNameIndication)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(pSSLSock->serverNameIndication, serverName, serverNameLen);
        }

        status = OK;
    }

exit:
    return (sbyte4)status;

} /* SSL_setServerNameIndication */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
MOC_EXTERN sbyte4 SSL_setClientSRPIdentity(sbyte4 connectionInstance,
                                           ubyte* userName, ubyte userNameLen,
                                           ubyte* pw, ubyte4 pwLen)
{
    MSTATUS status = ERR_SSL_BAD_ID;
    sbyte4 index;
    SSLSocket* pSSLSock = 0;

    if (!userName || !pw)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;


    if (CONNECT_NEGOTIATE == m_sslConnectTable[index].connectionState)
    {
        pSSLSock = m_sslConnectTable[index].pSSLSock;

        if ( pSSLSock->srpIdentity)
        {
            FREE( pSSLSock->srpIdentity);
            pSSLSock->srpIdentity = 0;
        }

        if (*userName)
        {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            SHA1_CTX *pShaCtx = NULL;
#else
            SHA1_CTX shaCtx = { 0 };
#endif

            pSSLSock->srpIdentity =
                (ubyte*) MALLOC( 1 + userNameLen);
            if (!pSSLSock->srpIdentity)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            pSSLSock->srpIdentity[0] = userNameLen;
            DIGI_MEMCPY(pSSLSock->srpIdentity + 1, userName, userNameLen);

            /*  compute the intermediate quantity -- we cannot use the shaPool
             here because it has not been initialized yet */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            status = CRYPTO_INTERFACE_SHA1_allocDigest(MOC_HASH(pSSLSock->hwAccelCookie) (BulkCtx *) &pShaCtx);
            if (OK != status)
                goto exit;

            CRYPTO_INTERFACE_SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCtx);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCtx, userName, userNameLen);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCtx, (ubyte*) ":", 1);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCtx, pw, pwLen);
            CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCtx,
                                      pSSLSock->roleSpecificInfo.client.ipHash);

            status = CRYPTO_INTERFACE_SHA1_freeDigest(MOC_HASH(pSSLSock->hwAccelCookie) (BulkCtx *) &pShaCtx);
            if (OK != status)
                goto exit;
#else
            SHA1_initDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) &shaCtx);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) &shaCtx, userName, userNameLen);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) &shaCtx, (ubyte*) ":", 1);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) &shaCtx, pw, pwLen);
            SHA1_finalDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) &shaCtx,
                                      pSSLSock->roleSpecificInfo.client.ipHash);
#endif
        }

        status = OK;
    }

exit:

    return (sbyte4)status;

}

#endif /* SSL_setClientSRPIdentity */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

static void
setShortValue(ubyte shortBuff[2], ubyte2 val)
{
    shortBuff[1] = (ubyte)(val & 0xFF);
    shortBuff[0] = (ubyte)((val >> 8) & 0xFF);
}

extern MSTATUS
SSL_setOCSPCallback(sbyte4 (*funcPtrSingleCertStatusCallback)(sbyte4 connectionInstance,
                                                              const ubyte *pCert, ubyte4 certLen,
                                                              ubyte* pOcspResp, ubyte4 ocspRespLen,
                                                              sbyte4 ocspStatus))
{
    if (funcPtrSingleCertStatusCallback == NULL)
    {
        return ERR_NULL_POINTER;
    }

    m_sslSettings.funcPtrSingleCertStatusCallback = funcPtrSingleCertStatusCallback;
    return OK;
}

/**
@coming_soon
@ingroup    func_ssl_ungrouped

@todo_version   (post-6.4 revision: commit  [43e8632], March 31, 2016:
                signature change; no more nonce adding)
*/
extern sbyte4
SSL_setCertifcateStatusRequestExtensions(sbyte4 connectionInstance,
    char** ppTrustedResponderCertPath, ubyte4 trustedResponderCertCount,
    extensions* pExts, ubyte4 extCount)
{
    MSTATUS     status = ERR_SSL_BAD_ID;
    sbyte4      index;
    CertificateStatusRequest request;
    ubyte4      offset = 0;

    if (((NULL == ppTrustedResponderCertPath) && trustedResponderCertCount) ||
        ((NULL == pExts) && extCount))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
           goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        pSSLSock->certStatusReqExt     = TRUE;
        pSSLSock->didRecvCertStatusExt = FALSE;

        /* Initialize ocsp Context */
        if (OK > (status = SSL_OCSP_initContext(&pSSLSock->pOcspContext)))
            goto exit;

        /* Request type is ocsp */
        request.status_type                 = certStatusType_ocsp;
        request.ocspReq.pExtensionsList     = NULL;
        request.ocspReq.pResponderIdList    = NULL;
        request.ocspReq.extensionListLen    = 0;
        request.ocspReq.responderIdListLen  = 0;

        /* Add trusted responder certificate to verify signed responses */
        if (0 < trustedResponderCertCount)
        {
            if (OK > (status = SSL_OCSP_createResponderIdList(pSSLSock->pOcspContext,
                            ppTrustedResponderCertPath, trustedResponderCertCount,
                            (ubyte **)&request.ocspReq.pResponderIdList,
                            &request.ocspReq.responderIdListLen)))
            {
                goto exit;
            }
        }

        if ((0 < extCount))
        {
            if (OK > (status = SSL_OCSP_createExtensionsList(pExts, extCount,
                                                             (ubyte **)&request.ocspReq.pExtensionsList,
                                                             &request.ocspReq.extensionListLen)))
            {
                goto exit;
            }
        }

        /* check that the values are less than 16 bits and can be properly encoded */
        if ((request.ocspReq.extensionListLen & 0xFFFF) != request.ocspReq.extensionListLen ||
            (request.ocspReq.responderIdListLen & 0xFFFF) != request.ocspReq.responderIdListLen)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;

        }
        /* Now fill the data */
        pSSLSock->certStatusReqExtLen  = 1 + 2 + request.ocspReq.responderIdListLen +
                                         2 + request.ocspReq.extensionListLen;

        if (NULL == (pSSLSock->certStatusReqExtData = MALLOC(pSSLSock->certStatusReqExtLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET(pSSLSock->certStatusReqExtData, 0x00, pSSLSock->certStatusReqExtLen);

        /* status type */
        offset = 0;

        DIGI_MEMCPY(pSSLSock->certStatusReqExtData + offset, &request.status_type, 1);
        offset += 1;

        /* Responder Id List Length */
        setShortValue(pSSLSock->certStatusReqExtData + offset,
            request.ocspReq.responderIdListLen);

        offset += 2;

        if (request.ocspReq.pResponderIdList)
        {
            DIGI_MEMCPY(pSSLSock->certStatusReqExtData + offset,
                request.ocspReq.pResponderIdList, request.ocspReq.responderIdListLen);

            offset += request.ocspReq.responderIdListLen;
        }

        setShortValue(pSSLSock->certStatusReqExtData + offset,
            request.ocspReq.extensionListLen);

        offset += 2;

        if (request.ocspReq.pExtensionsList) {
            DIGI_MEMCPY(pSSLSock->certStatusReqExtData + offset,
                request.ocspReq.pExtensionsList, request.ocspReq.extensionListLen);

            offset += request.ocspReq.extensionListLen;
        }
    }

    status = OK;

exit:
    return (sbyte4)status;

}

#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__*/
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)

#ifdef __ENABLE_DIGICERT_SSL_SRP__
MOC_EXTERN MSTATUS SSL_setFuncPtrSRPCallback(sbyte4(*funcPtrSRPCallback)
                                             (sbyte4 connectionInstance, const ubyte* identity,
                                              ubyte4 identityLength, sbyte4* numBits,
                                              ubyte salt[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                              ubyte4* saltLength,
                                              ubyte** verifier, ubyte4* verifierLength))
{
    if (NULL == funcPtrSRPCallback)
    {
        return ERR_NULL_POINTER;
    }

    SSL_sslSettings()->funcPtrSRPCallback = funcPtrSRPCallback;

    return OK;
}
#endif

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

/**
@coming_soon
@ingroup    func_ssl_ungrouped

@todo_version (post-6.4 revision; commit  [ca5eb79], March 30, 2016.)
*/
extern sbyte4
SSL_setOcspResponderUrl(sbyte4 connectionInstance, const char *pUrl)
{
    MSTATUS     status = ERR_SSL_BAD_ID;
    sbyte4      index;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
           goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;
        if(!pUrl)
        {
            if (pSSLSock->pResponderUrl)
                DIGI_FREE((void **) &(pSSLSock->pResponderUrl));
        }
        else
        {
            ubyte4 urlLen = DIGI_STRLEN((const sbyte*) pUrl);
            sbyte* urlCopy = MALLOC( urlLen+1);
            if (!urlCopy)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(urlCopy, pUrl, urlLen+1);
            if (NULL != pSSLSock->pResponderUrl)
                FREE(pSSLSock->pResponderUrl);
            pSSLSock->pResponderUrl = urlCopy;
        }
        status = OK;
    }

exit:
    return  status;

}

#endif  /* defined(__ENABLE_DIGICERT_OCSP_CLIENT__) */

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
/*------------------------------------------------------------------*/

extern sbyte4
SSL_getClientSRPIdentity(sbyte4 connectionInstance,
                         const ubyte** identity,
                         ubyte4* identityLength)
{
    MSTATUS     status = ERR_SSL_BAD_ID;
    sbyte4      index;
    SSLSocket*  pSSLSock;

    if (!identity || !identityLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (pSSLSock && pSSLSock->srpIdentity)
    {
        *identityLength = pSSLSock->srpIdentity[0];
        *identity = pSSLSock->srpIdentity+1;

    }
    else
    {
        *identityLength = 0;
        *identity = 0;
    }
    status = OK;

exit:

    return status;
}

#endif  /* defined(__ENABLE_DIGICERT_SSL_SRP__) */

#endif /* defined(__ENABLE_DIGICERT_SSL_SERVER__) */

#if defined(__ENABLE_DIGICERT_TLS13__)
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)

extern MSTATUS
SSL_deserializePSK(ubyte *pPsk, ubyte4 pskLen, tls13PSK **ppRetPsk)
{
    return SSLSOCK_tls13DeserializePsk(pPsk, pskLen, ppRetPsk);
}

extern MSTATUS
SSL_serializePSK(tls13PSK *pPsk, ubyte **ppPsk, ubyte4 *pPskLen)
{
    return SSLSOCK_tls13SerializePsk(pPsk, ppPsk, pPskLen);
}

extern MSTATUS
SSL_freePSK(tls13PSK **ppPsk)
{
    return SSLSOCK_freePSK(ppPsk);
}
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
MOC_EXTERN MSTATUS
SSL_setClientSavePSKCallback(sbyte4 connectionInstance,
                             sbyte4 (*cb)(sbyte4 connectionInstance,
                                          sbyte* ServerInfo, ubyte4 serverInfoLen,
                                          void *userData, ubyte *pPsk, ubyte4 pskLen))
{
    sbyte4 index;
    MSTATUS status = OK;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != cb)
    {
        pSSLSock->funcPtrSSLClientSavePSKCallback = cb;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_savePSKCallback() returns status = ", status);

    return status;
}

extern sbyte4
SSL_CLIENT_setRetrievePSKCallback(sbyte4 connectionInstance,
                          sbyte4 (*cb)(sbyte4 connectionInstance,
                                       sbyte* ServerInfo, ubyte4 serverInfoLen,
                                       void *userData, void **ppPSKs,
                                       ubyte2 *pNumPSKs, ubyte* selectedIndex,
                                       intBoolean *pFreeMemory))
{
    sbyte4 index;
    MSTATUS status = OK;
	SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != cb)
    {
        pSSLSock->funcPtrSSLClientRetrievePSKCallback = cb;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_setRetrievePSKCallback() returns status = ", status);

    return status;
}

#endif /* defined(__ENABLE_DIGICERT_SSL_CLIENT__) */

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
extern MSTATUS
SSL_setServerSavePSKCallback(sbyte4 (*cb)(sbyte4 connectionInstance,
                                          ubyte* ServerInfo, ubyte4 serverInfoLen,
                                          ubyte* pIdentityPSK, ubyte4 identityLengthPSK,
                                          ubyte* pPsk, ubyte4 pskLen))
{
    MSTATUS status = OK;

    if (NULL != cb)
    {
        m_sslSettings.funcPtrServerSavePSK = cb;
    }
    else
    {
        status = ERR_SSL;
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setServerSavePSKCallback() returns status = ", status);

    return status;
}

extern MSTATUS
SSL_setServerLookupPSKCallback(sbyte4 (*cb)(sbyte4 connectionInstance,
                                            ubyte* pIdentityPSK, ubyte4 identityLengthPSK,
                                            ubyte** ppPsk, ubyte4* pPskLen, intBoolean *pFreeMemory))
{
    MSTATUS status = OK;

    if (NULL != cb)
    {
        m_sslSettings.funcPtrLookupPSKParams = cb;
    }
    else
    {
        status = ERR_SSL;
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setServerLookupPSKCallback() returns status = ", status);

    return status;
}

extern MSTATUS
SSL_setServerDeletePSKCallback(sbyte4 (*cb)(sbyte4 connectionInstance,
                                          sbyte* ServerInfo, ubyte4 serverInfoLen,
                                          ubyte* pIdentityPSK, ubyte4 identityLengthPSK,
                                          ubyte* pPsk))
{
    MSTATUS status = OK;

    if (NULL != cb)
    {
        m_sslSettings.funcPtrServerDeletePSK = cb;
    }
    else
    {
        status = ERR_SSL;
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setServerDeletePSKCallback() returns status = ", status);

    return status;
}

#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */
#endif /* defined(__ENABLE_DIGICERT_TLS13_PSK__) */

#endif /* __ENABLE_DIGICERT_TLS13__*/

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__))
#if defined(__ENABLE_DIGICERT_OPENSSL_SHIM__)
static MSTATUS
SSL_deserializeSessionTicket(ubyte *pTicket, ubyte4 ticketLen, OSSL_sessionTicket **ppRetTicket)
{
    return SSLSOCK_deserializeSessionTicket(pTicket, ticketLen, (sessionTicket **) ppRetTicket);
}

static MSTATUS
SSL_freeSessionTicket(OSSL_sessionTicket **ppTicket)
{
    MSTATUS status = OK;
    if (NULL != ppTicket && NULL != *ppTicket)
    {
        if (NULL != (*ppTicket)->pTicket)
        {
            DIGI_FREE((void **) &((*ppTicket)->pTicket));
        }
        DIGI_FREE((void **) ppTicket);
    }
    return status;
}
#endif

extern MSTATUS
SSL_setClientSaveTicketCallback(sbyte4 connectionInstance,
                                sbyte4 (*cb)(sbyte4 connectionInstance,
                                             sbyte *serverInfo, ubyte4 serverInfoLen,
                                             void *userData, ubyte *pTicket, ubyte4 ticketLen))
{
    MSTATUS status = OK;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (status = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[status].pSSLSock;

    if (NULL != cb)
    {
        pSSLSock->funcPtrSSLClientSaveTicketCallback = cb;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_setSaveTicketCallback() returns status = ", status);

    return status;

}

extern MSTATUS
SSL_setClientRetrieveTicketCallback(sbyte4 connectionInstance,
                                    sbyte4 (*cb)(sbyte4 connectionInstance,
                                                 sbyte *serverInfo, ubyte4 serverInfoLen,
                                                 void *userData, ubyte **ppTicket, ubyte4 *pTicketLen,
                                                 intBoolean *pFreememory))
{
    MSTATUS status = OK;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (status = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[status].pSSLSock;

    if (NULL != cb)
    {
        pSSLSock->funcPtrSSLClientRetrieveTicketCallback = cb;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_CLIENT_setRetrieveTicketCallback() returns status = ", status);

    return status;

}

#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_setInnerApplicationExt(sbyte4 connectionInstance, ubyte4 innerAppValue)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to SSL_negotiateConnection() */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (TRUE == m_sslConnectTable[index].isClient)
        {
            pSSLSock->roleSpecificInfo.client.innerAppValue = innerAppValue;
            pSSLSock->roleSpecificInfo.client.innerApp      = TRUE;
        }
        else
        {
            pSSLSock->roleSpecificInfo.server.innerAppValue = innerAppValue;
            pSSLSock->roleSpecificInfo.server.innerApp      = TRUE;
        }
        status = OK;
    }

exit:
    return (sbyte4)status;

} /* SSL_setInnerApplicationExt */
#endif /*  defined(__ENABLE_DIGICERT_INNER_APP__) */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_INTERNAL_STRUCT_ACCESS__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
extern void *
SSL_returnPtrToSSLSocket(sbyte4 connectionInstance)
{
    sbyte4      index;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        pSSLSock = m_sslConnectTable[index].pSSLSock;
    }

exit:
    return (void *)pSSLSock;
}
#endif /* __ENABLE_DIGICERT_SSL_INTERNAL_STRUCT_ACCESS__ */


/*------------------------------------------------------------------*/

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) ||  \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
/**
@coming_soon
@ingroup    func_ssl_ungrouped
*/
ubyte2 SSL_getNamedCurveOfCurveId( ubyte4 curveId)
{
    switch ( curveId)
    {
    case cid_EC_P192:
        return tlsExtNamedCurves_secp192r1;
        break;

    case cid_EC_P224:
        return tlsExtNamedCurves_secp224r1;
        break;

    case cid_EC_P256:
        return tlsExtNamedCurves_secp256r1;
        break;

    case cid_EC_P384:
        return tlsExtNamedCurves_secp384r1;
        break;

    case cid_EC_P521:
        return tlsExtNamedCurves_secp521r1;
        break;

    default:
        break;
    }
    return 0;
}
#endif


/*------------------------------------------------------------------*/

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
     defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
     defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))
/**
@coming_soon
@ingroup    func_ssl_ungrouped
*/
ubyte4 SSL_getCurveIdOfNamedCurve( ubyte2 namedCurve)
{
    switch ( namedCurve)
    {
        case tlsExtNamedCurves_secp192r1:
            return cid_EC_P192;

        case tlsExtNamedCurves_secp224r1:
            return cid_EC_P224;

        case tlsExtNamedCurves_secp256r1:
            return cid_EC_P256;

        case tlsExtNamedCurves_secp384r1:
            return cid_EC_P384;

        case tlsExtNamedCurves_secp521r1:
            return cid_EC_P521;

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
        case tlsExtNamedCurves_x25519:
            return cid_EC_X25519;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
        case tlsExtNamedCurves_x448:
            return cid_EC_X448;
#endif

        default:
            break;
    }
    return 0;
}
#endif

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
extern sbyte4
CERT_STORE_createStoreAlt(void **ppNewStore)
{
     return CERT_STORE_createStore((certStorePtr *)ppNewStore);
}

extern MSTATUS
CERT_STORE_releaseStoreAlt(void **ppReleaseStore)
{
     return CERT_STORE_releaseStore((certStorePtr *)ppReleaseStore);

}

#if defined(__ENABLE_DIGICERT_MBEDTLS_SHIM__)

extern sbyte4
SSL_MSSL_AddTrustPoint(void *pCertStore, u_int8_t *pDerBuf, int derLen)
{
     MSTATUS    status;
     status = CERT_STORE_addTrustPoint((certStorePtr)pCertStore, pDerBuf, derLen);
     return status;
}

extern sbyte4
SSL_MSSL_decodeCertificate(ubyte*  pKeyFile, ubyte4 fileSize,
                          ubyte** ppDecodeFile, ubyte4 *pDecodedLength)
{
    MSTATUS    status = OK;
    status = CA_MGMT_decodeCertificate(pKeyFile,fileSize, ppDecodeFile, pDecodedLength);
    return status ;
}

sbyte4
SSL_MSSL_AddIdenCertChain(void *pCertStore, MSSL_SizedBuffer *certs, unsigned int numCerts,
              const u_int8_t *pKeyBlob, unsigned int keyBlobLength)
{
    MSTATUS        status = OK;

     status = CERT_STORE_addIdentityWithCertificateChain((certStorePtr)pCertStore,
               (SizedBuffer *)certs, numCerts, pKeyBlob, keyBlobLength);
exit:
     return status;
}

MSTATUS SSL_MSSL_MakeKeyBlobEx(const AsymmetricKey *pKey,
                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength)
{
    MSTATUS status = OK;

    status = KEYBLOB_makeKeyBlobEx(pKey, ppRetKeyBlob, pRetKeyLength);

    return status;
}

extern sbyte4
SSL_TCP_init()
{
    TCP_INIT();
    return OK;
}

extern sbyte4
SSL_TCP_connect(void *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    int status = OK;

    status = TCP_CONNECT((TCP_SOCKET *)pConnectSocket, pIpAddress, portNo);

    return status;
}

extern sbyte4
SSL_TCP_listen(void *listenSocket, ubyte2 portNumber)
{
    int status = OK;

    status = TCP_LISTEN_SOCKET((TCP_SOCKET *)listenSocket , portNumber);

    return status;

}

extern sbyte4
SSL_TCP_accept(void *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    int status = OK;

    status = TCP_ACCEPT_SOCKET((TCP_SOCKET * )clientSocket, listenSocket, isBreakSignalRequest);

    return status;
}

extern sbyte4
SSL_TCP_closeSocket(TCP_SOCKET socket)
{
    int status = OK;
    status = TCP_CLOSE_SOCKET(socket);

    return status;
}

extern sbyte4
SSL_TCP_shutdown()
{
    int status = OK;

    status  = TCP_SHUTDOWN();

    return status;
}

#endif /* __ENABLE_DIGICERT_MBEDTLS_SHIM__ */

#if defined( __ENABLE_DIGICERT_OPENSSL_SHIM__) || defined(__ENABLE_DIGICERT_MBEDTLS_SHIM__)
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined (__ENABLE_DIGICERT_DTLS_SERVER__)

#ifndef __DISABLE_SSL_IOCTL_API__

extern sbyte4
SSL_DTLS_ioctl(sbyte4 connectionInstance, ubyte4 setting, void *value)
{
    return DTLS_ioctl(connectionInstance, setting, (void *)value);
}
#endif /* __DISABLE_SSL_IOCTL_API__ */

extern sbyte4
SSL_DTLS_verifyClientHelloCookie(void *pPeerDescr, ubyte *pReceived, ubyte4 length, ubyte *pToSend, ubyte4 *pToSendLen)
{
    return DTLS_verifyClientHelloCookie(REF_MOC_IPADDR(((peerDescr *)pPeerDescr)->peerAddr), pReceived, length, pToSend, pToSendLen);
}

extern sbyte4
SSL_DTLS_init(sbyte4 numServerConnections, sbyte4 numClientConnections)
{
    return DTLS_init(numServerConnections,numClientConnections);
}

extern sbyte4
SSL_DTLS_connect(void *pPeerDescr, ubyte sessionIdLen, ubyte * sessionId,
             ubyte * masterSecret, const sbyte* dnsName, void *pCertStore)
{
    return DTLS_connect((peerDescr *)pPeerDescr,sessionIdLen, sessionId, masterSecret, dnsName, (certStorePtr)pCertStore);
}

extern sbyte4
SSL_DTLS_shutdown(void *arg)
{
    return DTLS_shutdown();
}

extern sbyte4
SSL_DTLS_getSendBuffer(sbyte4 connectionInstance, ubyte *data, ubyte4 *len)
{
    return DTLS_getSendBuffer(connectionInstance, data, len);
}

extern sbyte4
SSL_DTLS_parseSslBuf(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived,
                       ubyte **ppRetBytesReceived, ubyte4 *pRetNumRxBytesRemaining)
{
    return DTLS_recvMessage(connectionInstance, pBytesReceived, numBytesReceived,
            ppRetBytesReceived, pRetNumRxBytesRemaining);
}

extern sbyte4
SSL_DTLS_accept(void *pPeerDescr, void *pCertStore)
{
    return DTLS_acceptConnection((peerDescr *)pPeerDescr, (certStorePtr)pCertStore);
}

extern sbyte4
SSL_DTLS_readSslRec(sbyte4 connectionInstance, ubyte **data, ubyte4 *len, ubyte4 *pRetProtocol)
{
    return DTLS_getRecvBuffer(connectionInstance, data, len, pRetProtocol);
}

extern sbyte4
SSL_DTLS_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent)
{
    return DTLS_sendMessage(connectionInstance, pBuffer, bufferSize, pBytesSent);
}

/* This function doubles the timeout and restarts the timer with new timeout */
sbyte4 DTLS_doubleTimer(sbyte4 connectionInstance, ubyte4 maxTimeout)
{
    sbyte4 status = OK;
    sbyte4 index;
    SSLSocket *pSSLSock;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    pSSLSock->dtlsHandshakeTimeout *= 2;
    if(pSSLSock->dtlsHandshakeTimeout > maxTimeout)
        pSSLSock->dtlsHandshakeTimeout = maxTimeout;

    TIMER_unTimer((void *)&connectionInstance, pSSLSock->dtlsHandshakeTimer);
    TIMER_queueTimer((void*)&connectionInstance, pSSLSock->dtlsHandshakeTimer,
                                                pSSLSock->dtlsHandshakeTimeout, 0);

exit:
    return status;
}

extern sbyte4
SSL_DTLS_closeConnection(sbyte4 connectionInstance)
{
    return DTLS_closeConnection(connectionInstance);
}

#endif /* __ENABLE_DIGICERT_DTLS_CLIENT__ || __ENABLE_DIGICERT_DTLS_SERVER__*/

extern sbyte4
SSL_ASYNC_acceptConnectionAlt(TCP_SOCKET tempSocket, void* pCertStore)
{
     return SSL_ASYNC_acceptConnection(tempSocket, (struct certStore*)pCertStore);
}

extern sbyte4
SSL_ASYNC_connectAlt(TCP_SOCKET tempSocket, ubyte sessionIdLen, ubyte * sessionId,
             ubyte * masterSecret, const sbyte* dnsName,
             void *certStore)
{
     return SSL_ASYNC_connect(tempSocket, sessionIdLen, sessionId,
                  masterSecret, dnsName, (certStorePtr) certStore);
}

static sbyte4
SSL_DIGICERT_initDigicert(int arg)
{
    sbyte4 status = OK;

    status = DIGICERT_initDigicert();

    return (status);
}

static sbyte4
SSL_DIGICERT_free(void *arg)
{
    return DIGICERT_freeDigicert();
}

/* Called by NanoSSL Shim layer to deserialize the key */

#ifdef __ENABLE_DIGICERT_SERIALIZE__
#ifdef __ENABLE_DIGICERT_TAP__
extern MSTATUS
SSL_SerializeMocAsymKeyAlloc (
  AsymmetricKey *pKeyToSerialize,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
    return CRYPTO_serializeAsymKey(pKeyToSerialize,
        mocanaBlobVersion2, ppSerializedKey, pSerializedKeyLen);
}

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
extern MSTATUS
SSL_DeserializeMocAsymKeyWithCreds(
    ubyte *pSerializedKey,
    ubyte4 serializedKeyLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    AsymmetricKey *pDeserializedKey)
{
    return CRYPTO_deserializeAsymKeyWithCreds(pSerializedKey, serializedKeyLen,
                                        NULL, pPassword, passwordLen,
                                        NULL, pDeserializedKey);
}

static MSTATUS SSL_tapUnloadKey(
    AsymmetricKey *pAsymKey)
{
    return SSLSOCK_tapUnloadKey(pAsymKey);
}
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

extern MSTATUS
SSL_DeserializeMocAsymKey(
    ubyte *pSerializedKey,
    ubyte4 serializedKeyLen,
    AsymmetricKey *pDeserializedKey)
{
    return CRYPTO_deserializeAsymKey(pSerializedKey, serializedKeyLen,
                                        NULL, pDeserializedKey);
}

#endif /* __ENABLE_DIGICERT_TAP__ */
extern sbyte4
SSL_DeserializeKey(ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  AsymmetricKey *pDeserializedKey)
{
    MSTATUS status = OK;

    status = CRYPTO_deserializeKey(pSerializedKey, serializedKeyLen,
                                   gTPMSupportedAlgos, ALG_COUNT,
                                   pDeserializedKey);
    return status;
}
#endif /* __ENABLE_DIGICERT_SERIALIZE__ */

#if (defined(__ENABLE_DIGICERT_PEM_CONVERSION__) && defined(__ENABLE_DIGICERT_OPENSSL_SHIM__))
/*---------------------------------------------------------------------------*/
extern MSTATUS SSL_decryptPKCS8PemKey(
    ubyte *pContent,
    ubyte4 contentLength,
    AsymmetricKey** pKey,
    void *pPwInfo,
    intBoolean base64
    )
{
    MSTATUS status = OK;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLength = 0;
    ubyte* pw = NULL;
    ubyte4 pwLen = 0;
    pemPasswordInfo *pPasswordInfo = pPwInfo;
    hwAccelDescr hwAccelCtx = 0;

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    if (OK != status)
        goto exit;

    /* If the data is BASE-64 encoded then convert it to DER, otherwise just
     * copy the data directly into the keyblob.
     */
    if (TRUE == base64)
    {
        status = CA_MGMT_decodeCertificate(
            pContent, contentLength, &pKeyBlob, &keyBlobLength);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_MALLOC((void **)&pKeyBlob, contentLength);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pKeyBlob, pContent, contentLength);
        if (OK != status)
            goto exit;

        keyBlobLength = contentLength;
    }

    if (OK > ( status = CA_MGMT_extractKeyBlobEx((const ubyte*) pKeyBlob, keyBlobLength, *pKey)))
    {
        if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) pKeyBlob, keyBlobLength, (ubyte*)"", 0, *pKey)))
        {
            if ((ERR_PKCS8_ENCRYPTED_KEY == status) && (pPasswordInfo != NULL) && (pPasswordInfo->pCallback != NULL))
            {
                if (OK > (status = DIGI_CALLOC((void**)&pw, 1, MAX_PASSWORD_SIZE)))
                    goto exit;

                /* Invoke the password callback. The callback will take care of casting the callback information
                 * into the appropriate type. Upon success the password should be placed in the buffer and
                 * the function should output the length of the password as well. If the operation failed then
                 * the output length should be 0 and the status should indicate the type of error that occured.
                 */
                status = pPasswordInfo->pCallback(pPasswordInfo->pCallbackInfo, pw, MAX_PASSWORD_SIZE, &pwLen);
            }

            if ( (OK != status) || (0 >= pwLen) )
                goto exit;

            if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) pKeyBlob, keyBlobLength, pw, pwLen, *pKey)))
                goto exit;
        }

    }

exit:
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if (pw)
    {
        DIGI_MEMSET(pw, 0x00, MAX_PASSWORD_SIZE);
		FREE(pw);
    }

    if (pKeyBlob)
        FREE(pKeyBlob);

    if (OK > status)
        CRYPTO_uninitAsymmetricKey(*pKey, NULL);

    return status;
}
#endif
#endif /* defined(__ENABLE_DIGICERT_OPENSSL_SHIM__) || defined(__ENABLE_DIGICERT_MBEDTLS_SHIM__) */

#if defined( __ENABLE_DIGICERT_OPENSSL_SHIM__)
extern sbyte4
SSL_InitAsymmetricKey(AsymmetricKey* pAsymKey)
{
    MSTATUS status = OK;
    status = CRYPTO_initAsymmetricKey (pAsymKey);
    return status;
}

extern sbyte4
SSL_UninitAsymmetricKey(AsymmetricKey* pAsymKey)
{
    MSTATUS status = OK;
    status = CRYPTO_uninitAsymmetricKey (pAsymKey, NULL);
    return status;
}

extern MSTATUS SSL_clearAllSessionCache(void *pPtr)
{
    MOC_UNUSED(pPtr);
    return SSLSOCK_clearAllServerSessionCache();
}

#ifdef __ENABLE_DIGICERT_TPM__
extern sbyte4
SSL_KeyAssociateTapContext(MOCTAP_HANDLE mh, void* pCertStore)
{
    MSTATUS status = OK;
    AsymmetricKey* pRetKey = NULL;
    static void* reqKeyContext;

    if(mh == NULL || pCertStore == NULL)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if(OK > (status = CERT_STORE_findIdentityByTypeFirst(pCertStore,
                                                         CERT_STORE_AUTH_TYPE_RSA,
                                                         CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
                                                         (const struct AsymmetricKey **)&pRetKey,
                                                         NULL, NULL, NULL)))
    {
        goto exit;
    }

    if(OK > (status = MOCTAP_initializeTPMKeyContext(mh, pRetKey,
                                                     &reqKeyContext)))
    {
        goto exit;
    }

exit:
    if(OK > status)
    {
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte4*)"SSL_KeyAssociateTapContext() returns status = ", status);
    }
    return status;
}
#endif /* __ENABLE_DIGICERT_TPM__ */

/* Called by NanoSSL Shim layer to convert RSA private key into keyblob */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
MOC_EXTERN sbyte4 SSL_OSSL_RSAParamsToKeyBlob(
    OSSL_RSAParams *pRsaData,
    void **ppKeyBlob,
    unsigned int *pKeyBlobLen
    )
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = { 0 };
    RSAKey *pRsaKey = NULL;

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_RSA_createKey((void **) &pRsaKey, akt_rsa, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_RSA_setAllKeyData(
        pRsaKey, pRsaData->pE, pRsaData->lenE, pRsaData->pN, pRsaData->lenN,
        pRsaData->pP, pRsaData->lenP, pRsaData->pQ, pRsaData->lenQ, NULL,
        akt_rsa);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymKey, akt_rsa, (void **) &pRsaKey);
    if (OK != status)
        goto exit;

    status = KEYBLOB_makeKeyBlobEx(&asymKey, (ubyte **)ppKeyBlob, (ubyte4 *)pKeyBlobLen);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pRsaKey)
        CRYPTO_INTERFACE_RSA_freeKey((void **) &pRsaKey, NULL, akt_rsa);

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return ((sbyte4) status);
}
#else
extern sbyte4
SSL_OSSL_RSAParamsToKeyBlob(OSSL_RSAParams *pR, void **ppKeyBlob, unsigned int *pBlobLen)
{
     MSTATUS		status = OK;
     AsymmetricKey  asymKey;
     RSAKey	      * pRSAKey;
     ubyte 		flag =0;


     status = CRYPTO_initAsymmetricKey (&asymKey);
     if (OK != status)
        goto exit;
     flag = 1;
     if (OK > (status = RSA_createKey(&asymKey.key.pRSA))) {
	  goto exit;
     }
     asymKey.type	= akt_rsa; /* same as akt_rsa in ca_mgmt.h */
     pRSAKey	    = asymKey.key.pRSA; /* Pointer to Digicert RSA struct */
     pRSAKey->privateKey = 1;
     if (OK > (status = VLONG_vlongFromByteString((const ubyte *)pR->pN, pR->lenN, &RSA_N(pRSAKey), NULL)))
        goto exit;
     if (OK > (status = VLONG_vlongFromByteString((const ubyte *)pR->pE, pR->lenE, &RSA_E(pRSAKey), NULL)))
        goto exit;
     if (OK > (status = VLONG_vlongFromByteString((const ubyte *)pR->pP, pR->lenP, &RSA_P(pRSAKey), NULL)))
        goto exit;
     if (OK > (status = VLONG_vlongFromByteString((const ubyte *)pR->pQ, pR->lenQ, &RSA_Q(pRSAKey), NULL)))
        goto exit;
     RSA_prepareKey(MOC_RSA(hwAccelDescr hwAccelCtx) pRSAKey, NULL);
     if (OK > (status = KEYBLOB_makeKeyBlobEx(&asymKey, (ubyte **) ppKeyBlob, (ubyte4 *)pBlobLen)))
	  goto exit;
exit:
     if (flag)
     {
         CRYPTO_uninitAsymmetricKey(&asymKey, NULL);  /* always free this */
     }
     return status;
}
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
extern sbyte4
SSL_OSSL_DSAParamsToKeyBlob(OSSL_DSAParams *pD, void **ppKeyBlob, unsigned int *pBlobLen)
{
     MSTATUS		status = OK;
     AsymmetricKey  asymKey;
     DSAKey	      * pDSAKey;
     vlong     	      * pVlongQueue  = NULL;
     ubyte		flag = 0;

     status = CRYPTO_initAsymmetricKey (&asymKey);
     if (OK != status)
        goto exit;
     flag = 1;
     if (OK > (status = DSA_createKey(&asymKey.key.pDSA))) {
	  goto exit;
     }
     asymKey.type	= akt_dsa; /* same as akt_rsa in ca_mgmt.h */
     pDSAKey	= asymKey.key.pDSA; /* Pointer to Digicert DSA struct */
     if (NULL != pD->pX) {
	  if (OK > (status = DSA_setAllKeyParameters(MOC_RSA(hwAccelCtx) pDSAKey,
						     pD->pP, pD->lenP,
						     pD->pQ, pD->lenQ,
						     pD->pG, pD->lenG,
						     pD->pX, pD->lenX, &pVlongQueue))) {
	       goto exit;
	  }
     } else if (NULL != pD->pY) {
	  if (OK > (status = DSA_setPublicKeyParameters(pDSAKey, pD->pP, pD->lenP,
				 pD->pQ, pD->lenQ, pD->pG, pD->lenG,
				 pD->pY, pD->lenY, &pVlongQueue))) {

	       goto exit;
	  }
     }
     
     status = KEYBLOB_makeKeyBlobEx(&asymKey, (ubyte **)ppKeyBlob, (ubyte4 *)pBlobLen);
exit:
     if(flag)
     {
       CRYPTO_uninitAsymmetricKey(&asymKey, &pVlongQueue); /* always free this */
     }
     return status;
}
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
extern sbyte4
SSL_OSSL_ECCParamsToKeyBlob(OSSL_ECCParams *pEParams, void *ppKeyBlob, unsigned int *pBlobLen)
{
    MSTATUS status = OK;
    AsymmetricKey Akey = { 0 };
    ECCKey *pNewKey = NULL;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    ubyte4 curveId;
#else
    unsigned char *to;
    int tolen, tolenby2;
    PrimeFieldPtr pPF;
    PEllipticCurvePtr pEC;
#endif  /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    switch(pEParams->curve_name)
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case ossl_prime192v1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            curveId = cid_EC_P192;
            break;
#endif
        case ossl_secp224r1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            curveId = cid_EC_P224;
            break;
        case ossl_prime256v1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            curveId = cid_EC_P256;
            break;
        case ossl_secp384r1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            curveId = cid_EC_P384;
            break;
        case ossl_secp521r1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            curveId = cid_EC_P521;
            break;
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
        case ossl_eddsa_448:
            Akey.type = akt_ecc_ed;
            curveId = cid_EC_Ed448;
            break;
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
        case ossl_eddsa_25519:
            Akey.type = akt_ecc_ed;
            curveId = cid_EC_Ed25519;
            break;
#endif
#else
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case ossl_prime192v1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            pEC = EC_P192;
	        break;
#endif
        case ossl_secp224r1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            pEC = EC_P224;
	        break;
        case ossl_prime256v1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            pEC = EC_P256;
	        break;
        case ossl_secp384r1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            pEC = EC_P384;
	        break;
        case ossl_secp521r1:
            Akey.type	= akt_ecc; 	/* same as keyblob_type_ecc in keyblob.h */
            pEC = EC_P521;
	        break;
#endif
        default:
	        return -1;
	        break;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    /* Note a global keyType is passed. This can be set by the user.
     * This will be moved to the SSL_settings
     */
    if (OK > (status = CRYPTO_INTERFACE_EC_newKeyEx(curveId, &pNewKey, Akey.type, NULL)))
    {
        goto exit;
    }

    /* This is software only case. Hence hard-coding the keytype to akt_ecc */
    if (pEParams->pPriv)
    {
        if (OK > (status = CRYPTO_INTERFACE_EC_setKeyParameters(MOC_ECC(pSSLSock->hwAccelCookie) pNewKey,
                                                                pEParams->pPub, pEParams->lenPub,
                                                                pEParams->pPriv, pEParams->lenPriv,
                                                                Akey.type)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK > (status = CRYPTO_INTERFACE_EC_setKeyParameters(MOC_ECC(pSSLSock->hwAccelCookie) pNewKey,
                                                                pEParams->pPub, pEParams->lenPub,
                                                                NULL, 0,
                                                                Akey.type)))
        {
            goto exit;
        }
    }
#else
    if (OK > (status = EC_newKey( pEC, &pNewKey))) {
	return -1;
    }

    pPF 	= EC_getUnderlyingField(pNewKey->pCurve);
    to 		= pEParams->pPub;
    tolen	= pEParams->lenPub;
    tolenby2 = (tolen -1)/2;
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pNewKey->Qx, to+1, tolenby2))) {
	goto exit;
    }
    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pNewKey->Qy, to+1+tolenby2, tolenby2))) {
	goto exit;
    }
    if (pEParams->pPriv) {
	 if (OK > (status = PRIMEFIELD_setToByteString(pPF, pNewKey->k, pEParams->pPriv,
						       pEParams->lenPriv))) {
	      goto exit;
	 }
	 pNewKey->privateKey = 1;
    } else
	 pNewKey->privateKey = 0;
#endif  /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    Akey.key.pECC = pNewKey; /* Pointer to Digicert ECC struct */
    if (OK > (status = KEYBLOB_makeKeyBlobEx(&Akey, (ubyte **) ppKeyBlob, (ubyte4 *)pBlobLen)))
	  goto exit;
exit:
     CRYPTO_uninitAsymmetricKey(&Akey, NULL); /* always free this */

     return status;
}

extern MSTATUS SSL_extractEcKeyData(
    AsymmetricKey *pAsymKey,
    MEccKeyTemplate **ppTemplate
    )
{
    MSTATUS status;
    MEccKeyTemplate *pTemp = NULL;
    ubyte keyType = MOC_GET_PUBLIC_KEY_DATA;
    intBoolean isPrivate = FALSE;

    status = ERR_NULL_POINTER;
    if ( (NULL == pAsymKey) || (NULL == ppTemplate) )
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_isKeyPrivate(pAsymKey->key.pECC, &isPrivate);
#else
    status = EC_isKeyPrivate(pAsymKey->key.pECC, &isPrivate);
#endif

    if ((OK == status) && (TRUE == isPrivate))
        keyType = MOC_GET_PRIVATE_KEY_DATA;

    status = DIGI_CALLOC((void **) &pTemp, 1, sizeof(MEccKeyTemplate));
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getKeyParametersAlloc(MOC_ECC(pSSLSock->hwAccelCookie)
        pAsymKey->key.pECC, pTemp, keyType, pAsymKey->type);
#else
    status = EC_getKeyParametersAlloc(MOC_ECC(pSSLSock->hwAccelCookie)
        pAsymKey->key.pECC, pTemp, keyType);
#endif
    if (OK != status)
        goto exit;

    *ppTemplate = pTemp;
    pTemp = NULL;


exit:

    if (NULL != pTemp)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pAsymKey->key.pECC, pTemp);
#else
        EC_freeKeyTemplate(pAsymKey->key.pECC, pTemp);
#endif
        DIGI_FREE((void **) &pTemp);
    }

    return status;
}

extern MSTATUS SSL_freeEcKeyData(
    AsymmetricKey *pAsymKey,
    MEccKeyTemplate **ppTemplate
    )
{
    MSTATUS status = OK, fstatus;
    ECCKey *pKey = NULL;

    if (NULL == ppTemplate)
        goto exit;

    if (NULL != pAsymKey)
        pKey = pAsymKey->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pKey, *ppTemplate);
#else
    status = EC_freeKeyTemplate(pKey, *ppTemplate);
#endif

    fstatus = DIGI_FREE((void **) ppTemplate);
    if (OK == status)
        status = fstatus;

exit:

    return status;
}

extern MSTATUS SSL_getEcCurveId(
    AsymmetricKey *pAsymKey,
    ubyte4 *pCurveId
    )
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(
        pAsymKey->key.pECC, pCurveId);
#else
    return EC_getCurveIdFromKey(pAsymKey->key.pECC, pCurveId);
#endif
}

#endif

sbyte4
SSL_OSSL_AddTrustPoint(void *pCertStore, u_int8_t *pDerBuf, int derLen)
{
     MSTATUS	status;
     status = CERT_STORE_addTrustPoint((certStorePtr)pCertStore, pDerBuf, derLen);
     return status;
}

sbyte4
SSL_OSSL_AddIdenCertChain(void *pCertStore, OSSL_SizedBuffer *certs, unsigned int numCerts,
			  const u_int8_t *pKeyBlob, unsigned int keyBlobLength, ubyte* pKeyAlias, ubyte4 keyAliasLength)
{
     SizedBuffer      * certificates=NULL;
     OSSL_SizedBuffer * pc;
     int                sz;
     unsigned int       i;
     MSTATUS            status = OK;

     sz		= numCerts*sizeof(SizedBuffer);
     if (OK > (status = DIGI_MALLOC((void **)&certificates, sz)))
          goto exit;
     DIGI_MEMSET((ubyte *)certificates, 0, sz);
     for (i = 0; i < numCerts; ++i)
     {
          pc 	= &certs[i];
          if (OK > (status = SB_Allocate(&certificates[i], (ubyte4) pc->length)))
               goto exit;
	  DIGI_MEMCPY(certificates[i].data, pc->data, pc->length);
     }

     status = CERT_STORE_updateIdentityByAlias(
        (certStorePtr) pCertStore, pKeyAlias,
        keyAliasLength, certificates,
        numCerts, pKeyBlob, keyBlobLength);
     DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_OSSL_AddIdenCertChain: Updated identity for certificate by alias.");
     if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"CERT_STORE_updateIdentityByAlias() returns status = ", (sbyte4)status);

exit:
     for (i = 0; i < numCerts; ++i) {
        SB_Release(&certificates[i]);
     }
     DIGI_FREE((void *)&certificates);
     return status;
}

sbyte4
SSL_OSSL_AddIdenCertChainExtData(void *pCertStore, OSSL_SizedBuffer *certs, unsigned int numCerts,
			  const u_int8_t *pKeyBlob, unsigned int keyBlobLength, ubyte* pKeyAlias, ubyte4 keyAliasLength,
              ExtendedDataCallback extDataFunc, sbyte4 extDataIdentifier)
{
     SizedBuffer      * certificates=NULL;
     OSSL_SizedBuffer * pc;
     int                sz;
     unsigned int       i;
     MSTATUS            status = OK;

     sz		= numCerts*sizeof(SizedBuffer);
     if (OK > (status = DIGI_MALLOC((void **)&certificates, sz)))
          goto exit;
     DIGI_MEMSET((ubyte *)certificates, 0, sz);
     for (i = 0; i < numCerts; ++i)
     {
          pc 	= &certs[i];
          if (OK > (status = SB_Allocate(&certificates[i], (ubyte4) pc->length)))
               goto exit;
	  DIGI_MEMCPY(certificates[i].data, pc->data, pc->length);
     }

     status = CERT_STORE_updateIdentityByAliasExtData(
        (certStorePtr) pCertStore, pKeyAlias,
        keyAliasLength, certificates,
        numCerts, pKeyBlob, keyBlobLength,
        extDataFunc, extDataIdentifier);
     DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_OSSL_AddIdenCertChainExtData: Updated identity for certificate by alias.");
     if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"CERT_STORE_updateIdentityByAliasExtData() returns status = ", (sbyte4)status);

exit:
     for (i = 0; i < numCerts; ++i) {
        SB_Release(&certificates[i]);
     }
     DIGI_FREE((void *)&certificates);
     return status;
}
#endif /* __ENABLE_DIGICERT_OPENSSL_SHIM__ */

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#if (defined(__ENABLE_DIGICERT_DTLS_EXT_API__) || defined(__ENABLE_DIGICERT_OPENSSL_SHIM__))
/* Return the time remaining for until timeout */
extern sbyte4
SSL_DTLS_getTimeout(sbyte4 connectionInstance, void *pTime)
{
    sbyte4 index;
    sbyte4 status = OK;
    ubyte4 msDiff;
    ubyte4 msTimeRemaining;
    struct timeval *pTimeleft = (struct timeval *)pTime;
    SSLSocket* pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
      status = ERR_SSL_BAD_ID;
	  goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (OK > (status = TIMER_getTimerElapsed(pSSLSock,
                                             pSSLSock->dtlsHandshakeTimer,
                                             &msDiff)))
    {
        goto exit;
    }

    if (msDiff > pSSLSock->dtlsHandshakeTimeout)
    {
        /* time elapsed cannot be grerater than timeout */
        msTimeRemaining = 0;
    }
    else
    {
        msTimeRemaining = pSSLSock->dtlsHandshakeTimeout - msDiff;
    }

    pTimeleft->tv_usec = (msTimeRemaining % 1000) * 1000;
    pTimeleft->tv_sec  = msTimeRemaining / 1000;

exit:
    return status;
}

/* Returns 0 if timer has not expired/there is not timer
 * Returns -1 if timer has expired
 */
extern sbyte4 DTLS_isTimerExpired(sbyte4 connectionInstance)
{
    struct timeval timeleft;
    if((SSL_DTLS_getTimeout(connectionInstance, &timeleft) != OK))
    {
        return 0;
    }

    if(timeleft.tv_sec > 0 || timeleft.tv_usec > 0)
    {
        return 0;
    }

    return -1;
}

extern sbyte4 SSL_DTLS_handleTimeout(sbyte4 connectionInstance)
{
    MSTATUS status;
    if (OK > (status = DTLS_isTimerExpired(connectionInstance)))
    {
        goto exit;
    }

    if(OK > (status = DTLS_doubleTimer(connectionInstance, 60)))
    {
        goto exit;
    }

exit:
    return status;
}

#if (defined (__ENABLE_DIGICERT_DTLS_SRTP__) && defined (__ENABLE_DIGICERT_SRTP_PROFILES_SELECT__))

extern sbyte4
SSL_setSrtpInitCallback(sbyte4 (*cb)(sbyte4 connectionInstance, peerDescr *pChannelDescr,
                              const SrtpProfileInfo* pProfile, void* keyMaterials, ubyte* mki))
{
    MSTATUS status = OK;
    if (cb != NULL)
    {
        m_sslSettings.funcPtrSrtpInitCallback = cb;
    }
    else
    {
        status = ERR_SSL;
    }

    return status;
}

extern sbyte4
SSL_setSrtpEncodeCallback(sbyte4 (*cb)(sbyte4 connectionInstance, peerDescr *pChannelDescr,
                                const sbyte* pData, ubyte4 pDataLength,
                                ubyte** encodedData, ubyte4* encodedLength))
{
    MSTATUS status = OK;
    if (cb != NULL)
    {
        m_sslSettings.funcPtrSrtpEncodeCallback = cb;
    }
    else
    {
        status = ERR_SSL;
    }

    return status;
}

extern sbyte4
SSL_enableSrtpProfiles(sbyte4 connectionInstance, ubyte2 *pSrtpProfileList, ubyte4 listLength)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    /* this API must be called prior to start of handshake */
    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;
        sbyte4      profileIndex;
        ubyte4      count;

        if (NULL == pSSLSock)
            goto exit;

        status = ERR_SSL_CONFIG;

        if (SRTP_MAX_NUM_PROFILES < SSL_SOCK_numSrtpProfilesAvailable())
        {
            /* bad news: we can't detect this problem at compile time */
            /* good news: the test monkeys should detect this problem */
            goto exit;
        }

        for (count = 0; count < listLength; count++)
        {
            /* ability to chose at run-time srtp protection profiles to support */
            if (0 <= (profileIndex = SSL_SOCK_getSrtpProfileIndex(pSSLSock, pSrtpProfileList[count])))
            {
                /* mark the profile as active */
                pSSLSock->isSrtpProfileTableInit = TRUE;
                pSSLSock->isSrtpProfileEnabled[profileIndex] = TRUE;

                /* we successfully enabled at least one profile, so that is goodness */
                status = OK;
            }
        }
    }

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_DIGICERT_DTLS_SRTP__ && __ENABLE_DIGICERT_SRTP_PROFILES_SELECT__ */
#endif /* __ENABLE_DIGICERT_DTLS_EXT_API__ || __ENABLE_DIGICERT_OPENSSL_SHIM__ */
#endif /* __ENABLE_DIGICERT_DTLS_CLIENT__ || __ENABLE_DIGICERT_DTLS_SERVER__ */

#if defined(__ENABLE_DIGICERT_OPENSSL_SHIM__)
MSTATUS SSL_extractRsaKeyData(
    AsymmetricKey *pKey,
    MRsaKeyTemplate *pTemplate,
    ubyte reqType
    )
{
    MSTATUS status;

    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pTemplate) )
        goto exit;

    /* Extract the key data from the key.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(
        MOC_RSA(0) pKey->key.pRSA, pTemplate, reqType, pKey->type);
#else
    status = RSA_getKeyParametersAlloc(
        MOC_RSA(0) pKey->key.pRSA, pTemplate, reqType);
#endif
exit:
    return status;
}

MSTATUS SSL_freeRsaKeyTemplate(
    AsymmetricKey *pKey,
    MRsaKeyTemplate *pTemplate
    )
{
    RSAKey *pRsaKey = NULL;

    if (NULL != pKey)
        pRsaKey = pKey->key.pRSA;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pRsaKey, pTemplate);
#else
    return RSA_freeKeyTemplate(pRsaKey, pTemplate);
#endif
}

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
MSTATUS SSL_extractDsaKeyData(AsymmetricKey *pKey, MDsaKeyTemplate *pTemplate, ubyte reqType)
{
    MSTATUS status;

    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pTemplate) )
        goto exit;

    /* Extract the key data from the key.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(
        MOC_DSA(0) pKey->key.pDSA, pTemplate, reqType);
#else
    status =   DSA_getKeyParametersAlloc(
        MOC_DSA(0) pKey->key.pDSA, pTemplate, reqType);
#endif
exit:
    return status;

}

MSTATUS SSL_freeDsaKeyTemplate(
    AsymmetricKey *pKey,
    MDsaKeyTemplate *pTemplate
    )
{
    DSAKey *pDsaKey = NULL;

    if (NULL != pKey)
        pDsaKey = pKey->key.pDSA;

    return DSA_freeKeyTemplate(pDsaKey, pTemplate);
}

#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */
#endif /* __ENABLE_DIGICERT_OPENSSL_SHIM__ */

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
extern sbyte4
SSL_setDHParameters(ubyte *pP, ubyte4 pLen, ubyte *pG, ubyte4 gLen, ubyte4 lengthY)
{
    sbyte4 status = OK;

    if ((NULL == pP) || (NULL == pG))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pLen) || (0 == gLen))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Reset DH parameters */
    if (NULL != m_sslSettings.pDHP)
    {
        DIGI_FREE((void **) &m_sslSettings.pDHP);
        m_sslSettings.pLen = 0;
    }

    if (NULL != m_sslSettings.pDHG)
    {
        DIGI_FREE((void **) &m_sslSettings.pDHG);
        m_sslSettings.gLen = 0;
    }

    m_sslSettings.lengthY = 0;

    /* Set new DH parameters */
    status = DIGI_MALLOC((void **) &(m_sslSettings.pDHP), pLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(m_sslSettings.pDHP, pP, pLen);
    if (OK != status)
        goto exit;

    m_sslSettings.pLen = pLen;

    status = DIGI_MALLOC((void **) &(m_sslSettings.pDHG), gLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(m_sslSettings.pDHG, pG, gLen);
    if (OK != status)
        goto exit;

    m_sslSettings.gLen = gLen;

    m_sslSettings.lengthY = lengthY;

exit:

    return status;
}

#endif

MOC_EXTERN sbyte4
SSL_setMinProtoVersion(ubyte4 version)
{
    /* verify it is less than max version */
    if ( m_sslSettings.sslMaxProtoVersion < version )
    {
        return ERR_SSL_PROTOCOL_VERSION;
    }

    if ((version == TLS10_MINORVERSION ) ||
        (version == TLS11_MINORVERSION ) ||
        (version == TLS12_MINORVERSION ) ||
        (version == TLS13_MINORVERSION ) ||
        (version == SSL3_MINORVERSION ) ||
        (version == DTLS10_MINORVERSION ) ||
        (version == DTLS12_MINORVERSION ) ||
        (version == DTLS13_MINORVERSION ) )
    {
        m_sslSettings.sslMinProtoVersion = version;
        return OK;
    }
    return ERR_SSL_PROTOCOL_VERSION;
}

MOC_EXTERN ubyte4
SSL_getMinProtoVersion()
{
    return m_sslSettings.sslMinProtoVersion;
}

MOC_EXTERN sbyte4
SSL_setMaxProtoVersion(ubyte4 version)
{
    /* verify it is less than min version */
    if ( m_sslSettings.sslMinProtoVersion > version )
    {
        return ERR_SSL_PROTOCOL_VERSION;
    }

    if ((version == TLS10_MINORVERSION ) ||
        (version == TLS11_MINORVERSION ) ||
        (version == TLS12_MINORVERSION ) ||
        (version == TLS13_MINORVERSION ) ||
        (version == SSL3_MINORVERSION ) ||
        (version == DTLS10_MINORVERSION ) ||
        (version == DTLS12_MINORVERSION ) ||
        (version == DTLS13_MINORVERSION )
         )
    {
         m_sslSettings.sslMaxProtoVersion = version;
         return OK;
    }
    return ERR_SSL_PROTOCOL_VERSION;
}

MOC_EXTERN ubyte4
SSL_getMaxProtoVersion( )
{
    return m_sslSettings.sslMaxProtoVersion;
}

MOC_EXTERN sbyte4
SSL_getProtoVersion(sbyte4 connectionInstance )
{
    sbyte4  index;
    sbyte4  version = -1;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket *pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL != pSSLSock)
        {
          version = pSSLSock->sslMinorVersion;
        }
    }
exit:
    return version;

}

#if defined( __ENABLE_DIGICERT_OPENSSL_SHIM__)
MOC_EXTERN sbyte4 SSL_initializeVersion()
{
    sbyte4 status = 0;
    m_sslSettings.sslMaxProtoVersion = MAX_SSL_MINORVERSION;
    m_sslSettings.sslMinProtoVersion = MIN_SSL_MINORVERSION;
    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
extern MSTATUS SSL_sendHeartbeatMessage(sbyte4 connectionInstance)
{
    sbyte4 index = -1;
    SSLSocket *pSSLSock = NULL;
    MSTATUS status = ERR_SSL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS13_MINORVERSION))
    {
        status = OK;
        /* Heartbeat message SHOULD NOT be sent during handshakes */
        if ((CONNECT_OPEN == m_sslConnectTable[index].connectionState) &&
            (!pSSLSock->rehandshake) &&
            (pSSLSock->rxHeartbeatExtension == peerAllowedToSend))
        {
            status = SSL_SOCK_sendHeartbeatMessage(pSSLSock, pSSLSock->heartbeatPayload, HEARTBEAT_PAYLOAD_LENGTH, TRUE);
        }
    }
exit:
    return status;
}

extern MSTATUS SSL_enableHeartbeatSupport(sbyte4 connectionInstance, E_HeartbeatExtension value,
                                          sbyte4 (*heartbeatCb)(sbyte4 connectionInstance,
                                                                sbyte4 status, ubyte heartbeatType))
{
    sbyte4 index = -1;
    SSLSocket *pSSLSock = NULL;
    MSTATUS status = ERR_SSL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE < m_sslConnectTable[index].connectionState)
    {
        goto exit;
    }

    status = OK;
    pSSLSock = m_sslConnectTable[index].pSSLSock;

    /* Valid values are 1 and 2 */
    if ((peerAllowedToSend != value) && (peerNotAllowedToSend != value))
    {
        status = ERR_SSL_CONFIG;
        goto exit;
    }

    pSSLSock->sendHeartbeatMessage = value;

    if (heartbeatCb != NULL)
        pSSLSock->funcPtrHeatbeatMessageCallback = heartbeatCb;

exit:
    return status;
}

#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
extern MSTATUS SSL_setClientCAList(SizedBuffer *pClientCAList, ubyte4 numClientCANames)
{
    MSTATUS status = OK;

    if ((m_sslSettings.pClientCANameList != NULL) && (m_sslSettings.numClientCANames > 0))
    {
        ubyte4 length = m_sslSettings.numClientCANames;
        ubyte4 i = 0;

        for (i = 0; i < length; i++)
        {
            SB_Release(&(m_sslSettings.pClientCANameList[i]));
        }
        DIGI_FREE((void **) &(m_sslSettings.pClientCANameList));
    }


    SSL_sslSettings()->pClientCANameList = pClientCAList;
    SSL_sslSettings()->numClientCANames  = numClientCANames;

    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
static MSTATUS SSL_OSSL_setClientHelloCallback(sbyte4 connectionInstance, ClientHelloCallback callback, void *args)
{
    sbyte4 index = -1;
    SSLSocket *pSSLSock = NULL;
    MSTATUS status = ERR_SSL;

    if (NULL == callback)
    {
        goto exit;
    }

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE < m_sslConnectTable[index].connectionState)
    {
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    pSSLSock->clientHelloCallback    = callback;
    pSSLSock->clientHelloCallbackArg = args;

    status = OK;
exit:
    return status;
}

static MSTATUS SSL_OSSL_validateCertKeyChain(
    unsigned char *pKey, int keyLen, unsigned char *pCert, int certLen,
    unsigned char *pChain, int chainLen, int chainCount)
{
    MSTATUS status;
    certChainPtr pCertChain = NULL;
    AsymmetricKey certPubKey, priKey;
    certDescriptor *pCertDesc = NULL;
    int i;

    CRYPTO_initAsymmetricKey(&certPubKey);
    CRYPTO_initAsymmetricKey(&priKey);

    status = DIGI_CALLOC(
        (void **) &pCertDesc, sizeof(certDescriptor), chainCount + 1);
    if (OK != status)
    {
        goto exit;
    }

    pCertDesc[0].pCertificate = pCert;
    pCertDesc[0].certLength = certLen;

    for (i = 0; i < chainCount; i++)
    {
        pCertDesc[i + 1].certLength = *((ubyte4 *) pChain);
        pChain += sizeof(ubyte4);
        pCertDesc[i + 1].pCertificate = pChain;
        pChain += pCertDesc[i + 1].certLength;
    }

    /* Able to create certChain from provided certificates. No need to
     * validate.
     *
     * NOTE: Using IKE cert chain method to create a certificate chain since
     * it can take in an array of certificates. */
    status = CERTCHAIN_createFromIKE(&pCertChain, pCertDesc, chainCount + 1);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeKey(
        pKey, keyLen, gTPMSupportedAlgos, ALG_COUNT, &priKey);
    if (OK != status)
    {
        goto exit;
    }

    status = CERTCHAIN_getKey(pCertChain, 0, &certPubKey);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_matchPublicKey(&certPubKey, &priKey);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCertDesc)
    {
        DIGI_FREE((void **) &pCertDesc);
    }

    if (NULL != pCertChain)
    {
        CERTCHAIN_delete(&pCertChain);
    }

    CRYPTO_uninitAsymmetricKey(&certPubKey, NULL);
    CRYPTO_uninitAsymmetricKey(&priKey, NULL);

    return status;
}

/* Convert the OSSL_SizedBuffer to SizedBuffer */
MSTATUS OSSL_SSL_setClientCAList(OSSL_SizedBuffer *pClientCAList, ubyte4 numClientCANames)
{
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    SizedBuffer *pList = NULL;
    MSTATUS status     = OK;
    ubyte4 i = 0, size = 0;

    size = numClientCANames * sizeof(SizedBuffer);
    if (OK > (status = DIGI_MALLOC((void **)&pList, size)))
    {
        goto exit;
    }

    DIGI_MEMSET((ubyte*)pList, 0, size);

    for (i = 0; i < numClientCANames; i++)
    {
        ubyte4 length = (ubyte4) pClientCAList[i].length;
        if (OK > (status = SB_Allocate(&pList[i], length)))
        {
            goto exit;
        }

        DIGI_MEMCPY(pList[i].data, pClientCAList[i].data, length);
    }

    status = SSL_setClientCAList(pList, numClientCANames);

exit:
    if (OK > status)
    {
        if (pList != NULL)
        {
            for (i = 0; i < numClientCANames; i++)
            {
                if (pList[i].data != NULL)
                {
                    SB_Release(&pList[i]);
                }
            }
            DIGI_FREE((void **) &pList);
        }
    }

    return status;
#else
    return OK;
#endif
}


/* This function will create the following encoding.
 *
 * SEQ {
 *   OCTETSTRING sessionId,
 *   OCTETSTRING masterSecret,
 *   OCTETSTRING DNSName
 * }
 *
 * The caller must provide the session ID and master secret as arguments. The
 * output buffer is optional. If the output buffer is NULL then this function
 * will deposit the length into the provided length pointer. If the output
 * buffer is not NULL then it is assumed that the buffer is large enough to
 * store the encoded data.
 */
MSTATUS SSL_asn1EncodeSslSession(
    ubyte *pSessionId,
    ubyte4 sessionIdLen,
    ubyte *pMasterSecret,
    ubyte4 masterSecretLen,
    sbyte *pDNSName,
    unsigned char *pRetBuffer,
    int *pRetLen
    )
{
    MSTATUS status;
    DER_ITEMPTR pSessionEncoding = NULL;
    ubyte4 length;

    if ( (NULL == pSessionId) || (0 == sessionIdLen) ||
         (NULL == pMasterSecret) || (0 == masterSecretLen) ||
         (NULL == pRetLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Add the SEQUENCE
     */
    status = DER_AddSequence(NULL, &pSessionEncoding);
    if (OK != status)
        goto exit;

    /* Add the session ID as an OCTETSTRING
     */
    status = DER_AddItem(
        pSessionEncoding, OCTETSTRING, sessionIdLen, pSessionId, NULL);
    if (OK != status)
        goto exit;

    /* Add the master secret as an OCTETSTRING
     */
    status = DER_AddItem(
        pSessionEncoding, OCTETSTRING, masterSecretLen, pMasterSecret, NULL);
    if (OK != status)
        goto exit;

    if (NULL != pDNSName)
    {
        /* Add the DNS name as an OCTETSTRING
        */
        status = DER_AddItem(
            pSessionEncoding, OCTETSTRING, DIGI_STRLEN(pDNSName),
            (const ubyte *) pDNSName, NULL);
        if (OK != status)
            goto exit;
    }

    /* Get the total length of the encoding.
     */
    status = DER_GetLength(pSessionEncoding, &length);
    if (OK != status)
        goto exit;

    /* If a buffer was provided then copy the data into the buffer.
     */
    if (NULL != pRetBuffer)
    {
        status = DER_SerializeInto(
            pSessionEncoding, pRetBuffer, &length);
        if (OK != status)
            goto exit;
    }

    *pRetLen = (int) length;

exit:

    if (NULL != pSessionEncoding)
    {
        TREE_DeleteTreeItem((TreeItem *) pSessionEncoding);
    }

    return status;
}

/* This function will decode the following encoding.
 *
 * SEQ {
 *   OCTETSTRING sessionId,
 *   OCTETSTRING masterSecret,
 *   OCTETSTRING DNSName
 * }
 *
 * The caller must provide the encoded data and two double pointers which will
 * be for the session ID and master secret. Both the session ID and master
 * secret return values will be references within the actual data buffer itself
 * and do NOT need to be freed.
 */
MSTATUS SSL_asn1DecodeSslSession(
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte **ppRetSessionId,
    ubyte4 *pRetSessionIdLen,
    ubyte **ppRetMasterSecret,
    ubyte4 *pRetMasterSecretLen,
    sbyte **ppRetDNSName,
    ubyte4 *pRetDNSNameLen
    )
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pSessionEncoding = NULL, pNode = NULL;

    if ( (NULL == pBuffer) || (0 == bufferLen) || (NULL == ppRetSessionId) ||
         (NULL == pRetSessionIdLen) || (NULL == ppRetMasterSecret) ||
         (NULL == pRetMasterSecretLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    MF_attach(&mf, bufferLen, pBuffer);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pSessionEncoding);
    if (OK != status)
        goto exit;

    pNode = ASN1_FIRST_CHILD(pSessionEncoding);
    status = ASN1_VerifyType(pNode, SEQUENCE);
    if (OK != status)
        goto exit;

    /* Session ID
     */
    pNode = ASN1_FIRST_CHILD(pNode);
    status = ASN1_VerifyType(pNode, OCTETSTRING);
    if (OK != status)
        goto exit;

    *ppRetSessionId = pBuffer + pNode->dataOffset;
    *pRetSessionIdLen = pNode->length;

    /* Master Secret
     */
    pNode = ASN1_NEXT_SIBLING(pNode);
    status = ASN1_VerifyType(pNode, OCTETSTRING);
    if (OK != status)
        goto exit;

    *ppRetMasterSecret = pBuffer + pNode->dataOffset;
    *pRetMasterSecretLen = pNode->length;

    /* DNS name
     */
    pNode = ASN1_NEXT_SIBLING(pNode);

    if (NULL != pNode)
    {
        status = ASN1_VerifyType(pNode, OCTETSTRING);
        if (OK != status)
            goto exit;

        *ppRetDNSName = (sbyte *) pBuffer + pNode->dataOffset;
        *pRetDNSNameLen = pNode->length;
    }
    else
    {
        *ppRetDNSName = NULL;
        *pRetDNSNameLen = 0;
    }

exit:

    if (NULL != pSessionEncoding)
    {
        TREE_DeleteTreeItem((TreeItem *) pSessionEncoding);
    }

    return status;
}

static MSTATUS SSL_isSessionResumed(
    sbyte4 connectionInstance, intBoolean *pIsResumed)
{
    sbyte4  index;
    MSTATUS status;
    SSLSocket *pSSLSock = NULL;

    if (NULL == pIsResumed)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsResumed = FALSE;
    status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;
    if (NULL == pSSLSock)
        goto exit;

    if (E_NoSessionResume != pSSLSock->sessionResume)
    {
        *pIsResumed = TRUE;
    }

    status = OK;
exit:
    return status;
}

#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))

extern sbyte4
SSL_rehandshakeInit(
    ubyte4 maxByteCount, ubyte4 maxTimerCount,
    sbyte4(*funcPtrRehandshake)(sbyte4 connectionInstace))
{
    m_sslSettings.maxByteCount = maxByteCount;
    m_sslSettings.maxTimerCountForRehandShake = maxTimerCount;
    m_sslSettings.funcPtrClientRehandshakeRequest = funcPtrRehandshake;

    return OK;
}

#endif /* __ENABLE_DIGICERT_SSL_REHANDSHAKE__ */

extern sbyte4
SSL_OSSL_shutdown(void *arg)
{
    return SSL_shutdownStack();
}

extern sbyte4
SSL_OSSL_releaseTables(void *arg)
{
    return SSL_releaseTables();
}

extern sbyte4
SSL_bindShimMethods(nssl_methods_t *pMeth)
{
     if (NULL == pMeth)
	  return ERR_NULL_POINTER;
     pMeth->accept               = SSL_ASYNC_acceptConnectionAlt;
     pMeth->addIdenCertChain     = SSL_OSSL_AddIdenCertChain;
     pMeth->addIdenCertChainExtData = SSL_OSSL_AddIdenCertChainExtData;
     pMeth->addTrustPoint        = SSL_OSSL_AddTrustPoint;
     pMeth->validateCertKeyChain = SSL_OSSL_validateCertKeyChain;
     pMeth->closeConnection      = SSL_ASYNC_closeConnection;
     pMeth->connect              = SSL_ASYNC_connectAlt;
     pMeth->createCertStore      = CERT_STORE_createStoreAlt;
#if (defined(__ENABLE_DIGICERT_DSA__))
     pMeth->dsaParamsToKeyBlob   = SSL_OSSL_DSAParamsToKeyBlob;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
     pMeth->eccParamsToKeyBlob   = SSL_OSSL_ECCParamsToKeyBlob;
     pMeth->extractEcKeyData     = SSL_extractEcKeyData;
     pMeth->freeEcKeyData        = SSL_freeEcKeyData;
     pMeth->getEcCurveId         = SSL_getEcCurveId;
#endif
     pMeth->getPreparedSslRec    = SSL_ASYNC_getSendBuffer;
     pMeth->getPreparedSslRecZC  = SSL_ASYNC_getSendBufferZeroCopy;
     pMeth->inConnectInit        = SSL_in_connect_init_moc;
     pMeth->isEstablished        = SSL_isSecureConnectionEstablished;
     pMeth->libraryInit          = SSL_DIGICERT_initDigicert;
     pMeth->libraryUnInit        = SSL_DIGICERT_free;
#if !defined(__DISABLE_DIGICERT_INIT__)
     pMeth->libraryInitStaticMem = DIGICERT_initDigicertStaticMemory;
#endif
     pMeth->readFile             = DIGICERT_readFile;
     pMeth->hashTableAddPtr      = HASH_TABLE_addPtr;
     pMeth->hashTableCreatePtrsTable = HASH_TABLE_createPtrsTable;
     pMeth->hashTableDeletePtr   = HASH_TABLE_deletePtr;
     pMeth->hashTableFindPtr     = HASH_TABLE_findPtr;
     pMeth->hashTableRemovePtrsTable = HASH_TABLE_removePtrsTable;
     pMeth->sslShutdown          = SSL_OSSL_shutdown;
     pMeth->sslReleaseTables     = SSL_OSSL_releaseTables;
     pMeth->parseSslBuf          = SSL_ASYNC_recvMessage2;
     pMeth->prepareSslRec        = SSL_ASYNC_sendMessage;
     pMeth->readSslRec           = SSL_ASYNC_getRecvBuffer;
     pMeth->releaseCertStore     = CERT_STORE_releaseStoreAlt;
     pMeth->releaseZCsendBuffer  = SSL_ASYNC_freeSendBufferZeroCopy;
     pMeth->rsaParamsToKeyBlob   = SSL_OSSL_RSAParamsToKeyBlob;
#ifdef __ENABLE_DIGICERT_SERIALIZE__
#if defined(__ENABLE_DIGICERT_TAP__)
     pMeth->serializeAsymKeyAlloc = SSL_SerializeMocAsymKeyAlloc;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     pMeth->deserializeAsymKeyWithCreds = SSL_DeserializeMocAsymKeyWithCreds;
     pMeth->tapUnloadKey = SSL_tapUnloadKey;
#endif
     pMeth->deserializeAsymKey = SSL_DeserializeMocAsymKey;
#endif /* __ENABLE_DIGICERT_TAP__ */
     pMeth->deserializeKey       = SSL_DeserializeKey;
#endif
     pMeth->makeKeyBlobEx        = (NSSLmakeKeyBlobEx) KEYBLOB_makeKeyBlobEx;
     pMeth->decryptPKCS8PemKey   = (NSSLdecryptPKCS8PemKey) SSL_decryptPKCS8PemKey;
     pMeth->initAsymmetricKey    = SSL_InitAsymmetricKey;
     pMeth->uninitAsymmetricKey  = SSL_UninitAsymmetricKey;
#ifdef __ENABLE_DIGICERT_TPM__
     pMeth->keyAssociateTapContext = SSL_KeyAssociateTapContext;
#endif
     pMeth->setCiphers           = SSL_enableCiphers;
#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__)   || \
        defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)|| \
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))
     pMeth->setEccCurves         = (sbyte4 (*)(sbyte4, enum OSSL_tlsExtNamedCurves *,ubyte4))SSL_enableECCCurves;
#endif
     pMeth->disableCipherHash    = (sbyte4 (*)(sbyte4, OSSL_TLS_HashAlgorithm))SSL_disableCipherHashAlgorithm;
     pMeth->getCipherInfo        = SSL_getCipherInfo;
     pMeth->getSessionStatus     = SSL_getSessionStatusEx;
     pMeth->getPeerCertificateBytes = SSL_SOCK_getPeerCertificateBytes;
     pMeth->setSessionFlags      = SSL_setSessionFlags;
     pMeth->getSessionFlags      = SSL_getSessionFlags;
     pMeth->sslInit              = SSL_ASYNC_init;
     pMeth->triggerHello         = SSL_ASYNC_start;
     pMeth->get_alpn_selected    = SSL_getSelectedApplicationProtocol;
     pMeth->set_alpn_protos      = SSL_setApplicationLayerProtocol;
     pMeth->set_alpn_callback    = (NSSLset_alpn_callback) SSL_setAlpnCallback;
#if defined(__ENABLE_DIGICERT_SSL_ALERTS__)
     pMeth->set_alert_callback   = (NSSLset_alert_callback) SSL_setAlertCallback;
     pMeth->sslParseAlert        = SSL_parseAlert;
     pMeth->sslSendAlert         = SSL_sendAlert;
#endif
     pMeth->setClientHelloCallback = SSL_OSSL_setClientHelloCallback;
     pMeth->recvPending          = SSL_ASYNC_getRecvPending;
     pMeth->getClientSessionInfo = SSL_getClientSessionInfo;
     pMeth->sslIoctl             = SSL_ioctl;
     pMeth->sslSettingsIoctl     = SSL_Settings_Ioctl;
     pMeth->sslSetMinVersion     = SSL_setMinProtoVersion;
     pMeth->sslGetMinVersion     = SSL_getMinProtoVersion;
     pMeth->sslSetMaxVersion     = SSL_setMaxProtoVersion;
     pMeth->sslGetMaxVersion     = SSL_getMaxProtoVersion;
     pMeth->sslGetVersion        = SSL_getProtoVersion;
     pMeth->sslInitializeVersion = SSL_initializeVersion;
     pMeth->sslClearAllSessionCache = SSL_clearAllSessionCache;
#if defined(__ENABLE_DIGICERT_TLS13__)
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) || \
     defined(__ENABLE_DIGICERT_SSL_SERVER__)
     pMeth->sslGetSigAlgo        = SSL_getSignatureAlgo;
#endif
#endif
#if defined(__ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__) && \
    defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
     pMeth->parseDigestInfo      = ASN1_parseDigestInfo;
#endif
     pMeth->sslGetSSLTLSVersion  = SSL_getSSLTLSVersion;
#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
     pMeth->setCertAndStatusCallBack = SSL_setCertAndStatusCallback;
     pMeth->setClientCertAuthorityCallback = SSL_setClientCertAuthorityCallback;
#endif
     pMeth->setCertVerifySignCallback = SSL_setCertVerifySignCallback;
     pMeth->setClientCertCallback = SSL_setClientCertCallback;
     pMeth->setVersionCallback   = SSL_setVersionCallback;
     pMeth->setClientCAList      = OSSL_SSL_setClientCAList;
#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))
     pMeth->rehandshakeInit      = SSL_rehandshakeInit;
     pMeth->initiateRehandshake  = SSL_initiateRehandshake;
     pMeth->isRehandshakeAllowed = SSL_isRehandshakeAllowed;
     pMeth->getTlsUnique         = SSL_getTlsUnique;
#endif

#if defined(__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__) && \
    defined(__ENABLE_DIGICERT_SSL_CLIENT__)
     pMeth->setDNSNames          = SSL_setDNSNames;
#endif
     pMeth->setServerNameExtension   = SSL_setServerNameIndication;
#if defined (__ENABLE_DIGICERT_DTLS_SERVER__)
     pMeth->dtlsVerifyClientHelloCookie  =  SSL_DTLS_verifyClientHelloCookie;
#endif
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined (__ENABLE_DIGICERT_DTLS_SERVER__)
     pMeth->dtlsInit             = SSL_DTLS_init;
     pMeth->triggerDtlsHello     = SSL_DTLS_start;
     pMeth->dtlsConnect          = SSL_DTLS_connect;
     pMeth->dtlsAccept           = SSL_DTLS_accept;
#ifndef __DISABLE_SSL_IOCTL_API__
     pMeth->dtlsIoctl            = SSL_DTLS_ioctl;
#endif /* __DISABLE_SSL_IOCTL_API__ */
     pMeth->dtlsGetSendBuffer    = SSL_DTLS_getSendBuffer;
     pMeth->dtlsSendMessage      = SSL_DTLS_sendMessage;
     pMeth->dtlsParseSslBuf      = SSL_DTLS_parseSslBuf;
     pMeth->dtlsReadSslRec       = SSL_DTLS_readSslRec;
     pMeth->dtlsCloseConnection  = SSL_DTLS_closeConnection;
     pMeth->dtlsGetTimeout       = SSL_DTLS_getTimeout;
     pMeth->dtlsHandleTimeout    = SSL_DTLS_handleTimeout;
     pMeth->dtlsShutdown         = SSL_DTLS_shutdown;
#if (defined (__ENABLE_DIGICERT_DTLS_SRTP__) && defined (__ENABLE_DIGICERT_SRTP_PROFILES_SELECT__))
     pMeth->setSrtpProfiles       = SSL_enableSrtpProfiles;
     pMeth->setSrtpInitCallback   = (NSSLsetSrtpInitCallback)SSL_setSrtpInitCallback;
     pMeth->setSrtpEncodeCallback = (NSSLsetSrtpEncodeCallback)SSL_setSrtpEncodeCallback;
#endif
#endif /* __ENABLE_DIGICERT_DTLS_CLIENT__ || __ENABLE_DIGICERT_DTLS_SERVER__ */
#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
     pMeth->setDHParameters      = SSL_setDHParameters;
#endif

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
     pMeth->getExportKeyMaterial = SSL_generateExportKeyMaterial;
#endif
     pMeth->setSessionResumeTimeout = (NSSLsetSessionResumeTimeout) SSL_SOCK_setSessionResumeTimeout;
     pMeth->extractRsaKeyData    = SSL_extractRsaKeyData;
     pMeth->freeRsaKeyTemplate   = SSL_freeRsaKeyTemplate;
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
     pMeth->extractDsaKeyData    = SSL_extractDsaKeyData;
     pMeth->freeDsaKeyTemplate   = SSL_freeDsaKeyTemplate;
#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */
     pMeth->asn1EncodeSslSession = SSL_asn1EncodeSslSession;
     pMeth->asn1DecodeSslSession = SSL_asn1DecodeSslSession;
     pMeth->isSessionResumed     = SSL_isSessionResumed;
     pMeth->setMinRSAKeySize     = SSL_setMinRSAKeySize;
     pMeth->getSharedSignatureAlgorithm     = SSL_getSharedSignatureAlgorithm;

#if defined(__ENABLE_DIGICERT_TLS13_OPENSSL__)
    pMeth->sendPostHandshakeAuthCertRequest = SSL_sendPosthandshakeAuthCertificateRequest;
    pMeth->sendKeyUpdate                    = SSL_sendKeyUpdateRequest;
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
    pMeth->setPskUseSessionCb               = SSL_CLIENT_setRetrievePSKCallback;
    pMeth->savePskSessionCb                 = SSL_setClientSavePSKCallback;
    pMeth->setPskFindSessionCb              = SSL_setServerLookupPSKCallback;
    pMeth->saveServerPskSessionCb           = SSL_setServerSavePSKCallback;
    pMeth->deserializePsk                   = (MSTATUS (*)(ubyte *pPsk, ubyte4 pskLen, OSSL_tls13PSK **ppRetPsk))SSL_deserializePSK;
    pMeth->serializePsk                     = (MSTATUS (*)(OSSL_tls13PSK *pPsk, ubyte **ppPsk, ubyte4 *pPskLen))SSL_serializePSK;
    pMeth->freePsk                          = (MSTATUS (*)(OSSL_tls13PSK **pPsk))SSL_freePSK;
#ifdef __ENABLE_DIGICERT_TLS13_0RTT__
    pMeth->setEarlyData                     = SSL_setEarlyData;
    pMeth->getEarlyDataState                = SSL_getEarlyDataState;
#endif
#endif
#endif  /* __ENABLE_DIGICERT_TLS13_OPENSSL__ */

    pMeth->getLocalState         = SSL_getLocalState;
    pMeth->sslGetState           = SSL_getState;

    pMeth->setCipherAlgorithm    = SSL_setCipherAlgorithm;
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
     pMeth->setSha1SigAlg        = SSL_setSha1SigAlg;
#endif

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
     pMeth->setFIPSEnabled       = SSL_setFIPSEnabled;
     pMeth->sslCheckFIPS         = SSL_checkFIPS;
#endif
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
     pMeth->setDSACiphers     = SSL_setDSACiphers;
#endif
     pMeth->diffTime             = DATETIME_diffTime;
     pMeth->getNewTime           = DATETIME_getNewTime;
     pMeth->mocMalloc            = DIGI_MALLOC;
     pMeth->mocFree              = DIGI_FREE;

     pMeth->rtosMutexCreate      = RTOS_mutexCreate;
     pMeth->rtosMutexWait        = RTOS_mutexWait;
     pMeth->rtosMutexRelease     = RTOS_mutexRelease;
     pMeth->rtosMutexFree        = RTOS_mutexFree;
#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
     pMeth->setCertifcateStatusRequestExtensions = SSL_setCertifcateStatusRequestExtensions;
     pMeth->setOCSPCallback      = SSL_setOCSPCallback;
#endif
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
     pMeth->setClientSaveTicketCb     = SSL_setClientSaveTicketCallback;
     pMeth->setClientRetrieveTicketCb = SSL_setClientRetrieveTicketCallback;
     pMeth->deserializeTicket         = SSL_deserializeSessionTicket;
     pMeth->freeTicket                = SSL_freeSessionTicket;
#endif
     return OK;
}

#endif /* __ENABLE_DIGICERT_OPENSSL_SHIM__ */
#endif /* __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ || __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__ */

#ifdef __ENABLE_DIGICERT_MBEDTLS_SHIM__
sbyte4 SSL_bindMbedtlsShimMethods(mssl_methods_t *pMeth)
{
     if (NULL == pMeth)
      return ERR_NULL_POINTER;

     pMeth->accept               = SSL_ASYNC_acceptConnectionAlt;
     pMeth->closeConnection      = SSL_ASYNC_closeConnection;
     pMeth->isEstablished        = SSL_isSecureConnectionEstablished;
     pMeth->addTrustPoint        = SSL_MSSL_AddTrustPoint;
     pMeth->addIdenCertChain     = SSL_MSSL_AddIdenCertChain;
     pMeth->makeKeyBlobEx        = SSL_MSSL_MakeKeyBlobEx;
     pMeth->connect              = SSL_ASYNC_connectAlt;
     pMeth->createCertStore      = CERT_STORE_createStoreAlt;
     pMeth->decodeCertificate    = SSL_MSSL_decodeCertificate;
     pMeth->getPreparedSslRec    = SSL_ASYNC_getSendBuffer;
     pMeth->getPreparedSslRecZC  = SSL_ASYNC_getSendBufferZeroCopy;
     pMeth->inConnectInit        = SSL_in_connect_init_moc;
     pMeth->libraryInit          = SSL_DIGICERT_initDigicert;
     pMeth->libraryInitStaticMem = DIGICERT_initDigicertStaticMemory;
     pMeth->parseSslBuf          = SSL_ASYNC_recvMessage2;
     pMeth->prepareSslRec        = SSL_ASYNC_sendMessage;
     pMeth->readSslRec           = SSL_ASYNC_getRecvBuffer;
     pMeth->releaseZCsendBuffer  = SSL_ASYNC_freeSendBufferZeroCopy;
     pMeth->setCiphers           = SSL_enableCiphers;
     pMeth->setSessionFlags      = SSL_setSessionFlags;
     pMeth->sslInit              = SSL_ASYNC_init;
     pMeth->triggerHello         = SSL_ASYNC_start;
     pMeth->releaseCertStore     = CERT_STORE_releaseStoreAlt;
#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))
     pMeth->initiateRehandshake  = SSL_initiateRehandshake;
#endif
     pMeth->get_alpn_selected    = SSL_getSelectedApplicationProtocol;
     pMeth->set_alpn_protos      = SSL_setApplicationLayerProtocol;
     pMeth->set_alpn_callback    = SSL_setAlpnCallback;
     pMeth->recvPending          = SSL_ASYNC_getRecvPending;
     pMeth->getClientSessionInfo = SSL_getClientSessionInfo;
     pMeth->setDNSNames          = SSL_setDNSNames;
     pMeth->setServerNameIndication   = SSL_setServerNameIndication;
     pMeth->tcpInit              = SSL_TCP_init;
     pMeth->tcpConnect           = SSL_TCP_connect;
     pMeth->tcpListen            = SSL_TCP_listen;
     pMeth->tcpAccept            = SSL_TCP_accept;
     pMeth->tcpCloseSocket       = SSL_TCP_closeSocket;
     pMeth->tcpShutdown          = SSL_TCP_shutdown;
     pMeth->sslIoctl             = SSL_ioctl;
     pMeth->sslGetCipherInfo     = SSL_getCipherInfo;
     pMeth->initAsymmetricKey    = CRYPTO_initAsymmetricKey;
     pMeth->uninitAsymmetricKey  = SSL_UninitAsymmetricKey;
     pMeth->mocanaReadFile       = DIGICERT_readFile;
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined (__ENABLE_DIGICERT_DTLS_SERVER__)
     pMeth->dtlsInit             = SSL_DTLS_init;
     pMeth->udpConnect           = UDP_connect;
     pMeth->dtlsConnect          = SSL_DTLS_connect;
     pMeth->udpInit              = UDP_init;
     pMeth->triggerDtlsHello     = SSL_DTLS_start;
     pMeth->dtlsIoctl            = SSL_DTLS_ioctl;
     pMeth->dtlsGetSendBuffer    = SSL_DTLS_getSendBuffer;
     pMeth->udpGetSrcPortAddr    = UDP_getSrcPortAddr;
     pMeth->udpSimpleBind        = UDP_simpleBind;
     pMeth->udpRecvFrom          = UDP_recvFrom;
     pMeth->udpSendTo            = UDP_sendTo;
     pMeth->dtlsVerifyClientHelloCookie  =  DTLS_verifyClientHelloCookie;
     pMeth->dtlsAccept           = SSL_DTLS_accept;
     pMeth->dtlsParseSslBuf      = SSL_DTLS_parseSslBuf;
     pMeth->dtlsReadSslRec       = SSL_DTLS_readSslRec;
     pMeth->dtlsSendMessage      = SSL_DTLS_sendMessage;
     pMeth->dtlsDoubleTimer      = DTLS_doubleTimer;
     pMeth->dtlsCloseConnection  = SSL_DTLS_closeConnection;
     pMeth->udpShutdown          = UDP_shutdown;
     pMeth->udpUnbind            = UDP_unbind;
#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
     pMeth->setCertAndStatusCallback = SSL_setCertAndStatusCallback;
#endif
#endif

     return OK;
}

#endif /* __ENABLE_DIGICERT_MBEDTLS_SHIM__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__))

/**
@brief      Renegotiate an SSL/TLS session.

@details    This function renegotiates a %client or server SSL session.
            Renegotiation can be necessary in a variety of circumstances,
            including:
+ Reducing attack vulnerability after a connection has been active for a long
    time
+ Enhancing security by using stronger encryption
+ Performing mutual authentication

The peer can ignore the rehandshake request or send back an
\c SSL_ALERT_NO_RENEGOTIATION alert.

@ingroup    func_ssl_core

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_REHANDSHAKE__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/
extern sbyte4
SSL_initiateRehandshake(sbyte4 connectionInstance)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_OPEN <= m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL == pSSLSock)
            goto exit;

        status = SSLSOCK_initiateRehandshake(pSSLSock);
    }

exit:
    return (sbyte4)status;

} /* SSL_initiateRehandshake */

extern sbyte4
SSL_isRehandshakeAllowed(sbyte4 connectionInstance, intBoolean *pRehandshake)
{
    sbyte4  index;
    MSTATUS status = ERR_SSL_BAD_ID;
    SSLSocket *pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL == pSSLSock)
        goto exit;

    *pRehandshake = pSSLSock->isRehandshakeAllowed;
    status = OK;

exit:
    return status;
}

/**
@brief      Timer check for rehandshaking.

@details    This function checks whether a rehandshaking request for the server
            SSL session has timed out, and if so, calls the callback
            function. If timeout occurs, it will call the callback
            function to initiate the rehandshake.

@ingroup    func_ssl_sync

@since 5.8
@version 5.8 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_REHANDSHAKE__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
extern sbyte4
SSL_checkRehandshakeTimer(sbyte4 connectionInstance)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_OPEN == m_sslConnectTable[index].connectionState)
    {
        if (m_sslSettings.maxTimerCountForRehandShake > 0)
        {
            SSLSocket* pSSLSock = m_sslConnectTable[index].pSSLSock;
            if (((sbyte4)RTOS_deltaMS(&pSSLSock->sslRehandshakeTimerCount, NULL) > m_sslSettings.maxTimerCountForRehandShake) &&
                (m_sslSettings.funcPtrClientRehandshakeRequest != NULL))
            {
                status = m_sslSettings.funcPtrClientRehandshakeRequest(connectionInstance);
                pSSLSock->sslByteSendCount = 0;
                RTOS_deltaMS(NULL, &pSSLSock->sslRehandshakeTimerCount);
            }
        }
    }

exit:
    return status;

}

#endif /* (defined( __ENABLE_DIGICERT_SSL_REHANDSHAKE__)) */
/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSL_checkHandshakeTimer(sbyte4 connectionInstance)
{
    sbyte4  index;
    sbyte4 status = ERR_SSL_BAD_ID;
    SSLSocket*  pSSLSock       = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL == pSSLSock)
    {
        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_checkHandshakeTimer: connectionInstance not found.");
        goto exit;
    }

    if (IS_SSL_SYNC(pSSLSock))
        goto exit;

    /* check DTLS handshake timer. call timeout callback if timer expired */
    status = TIMER_checkTimer(pSSLSock->dtlsHandshakeTimer);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    /* check DTLS handshake timer. call timeout callback if timer expired */
    status = TIMER_checkTimer(pSSLSock->postHandshakeState[kNewSessionTicket].msgTimer);
    if (OK != status)
        goto exit;

    /* check DTLS handshake timer. call timeout callback if timer expired */
    status = TIMER_checkTimer(pSSLSock->postHandshakeState[kKeyUpdate].msgTimer);
    if (OK != status)
        goto exit;

    /* check DTLS handshake timer. call timeout callback if timer expired */
    status = TIMER_checkTimer(pSSLSock->postHandshakeState[kCertificateRequest].msgTimer);
    if (OK != status)
        goto exit;
#endif

exit:
    return status;
}


#endif /* (__ENABLE_DIGICERT_DTLS_CLIENT__) || (__ENABLE_DIGICERT_DTLS_SERVER__) */


/*-------------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSL_rngFun( ubyte4 len, ubyte* buff)
{
    return (MSTATUS) mSSL_rngFun( mSSL_rngArg, len, buff);
}


/*-------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ALPN_CALLBACK__
extern MSTATUS
SSL_setAlpnCallback(sbyte4 connectionInstance,
                    sbyte4 (*funcPtrAlpnCallback) (sbyte4 connectionInstance,
                                                   ubyte** out[],
                                                   sbyte4* outlen,
                                                   ubyte* in,
                                                   sbyte4 inlen))
{
    sbyte4 index;

    MSTATUS status = OK;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    if (CONNECT_NEGOTIATE  == m_sslConnectTable[index].connectionState)
    {
        SSLSocket*  pSSLSock = m_sslConnectTable[index].pSSLSock;

        if (NULL != funcPtrAlpnCallback)
        {
            pSSLSock->funcPtrAlpnCallback = funcPtrAlpnCallback;
        }
        else
        {
            status = ERR_SSL_ALPN_CALLBACK_MISSING;
            goto exit;
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setAlpnCallback() returns status = ", status);

    return status;
}
#endif /* __DISABLE_DIGICERT_ALPN_CALLBACK__ */

#if defined(__ENABLE_DIGICERT_SSL_ALERTS__)
extern MSTATUS
SSL_setAlertCallback(sbyte4 connectionInstance,
                    sbyte4 (*funcPtrAlertCallback) (sbyte4 connectionInstance,
                                                     sbyte4 alertId,
                                                     sbyte4 alertClass))
{
    MSTATUS status = OK;

    if (NULL != funcPtrAlertCallback)
    {
        m_sslSettings.funcPtrAlertCallback = funcPtrAlertCallback;
    }
    else
    {
        status = ERR_SSL_ALERT_CALLBACK_MISSING;
        goto exit;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setAlertCallback() returns status = ", status);

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_ALERTS__ */

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
MOC_EXTERN sbyte4
SSL_setReceiveApplicationDataCallback(sbyte4 (*funcPtrTLS13ApplicationDataCallback)(sbyte4 connectionInstance,
                                                                                   ubyte *pData, ubyte4 dataLen,
                                                                                   dataState state))
{
    MSTATUS status = OK;

    if (NULL != funcPtrTLS13ApplicationDataCallback)
    {
        SSL_sslSettings()->funcPtrSSLReceiveApplicationDataCallback = funcPtrTLS13ApplicationDataCallback;
    }
    else
    {
        status = ERR_SSL;
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setReceiveApplicationDataCallback() returns status = ", status);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__)) */

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
extern MSTATUS
SSL_setCertAndStatusCallback(sbyte4 connectionInstance,
    MSTATUS (*funcPtrGetCertAndStatusCallback) (sbyte4 connectionInstance,
                                                struct certChain* pCertChain,
                                                MSTATUS validationstatus))
{
    sbyte4 index;
    MSTATUS status = OK;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != funcPtrGetCertAndStatusCallback)
    {
        pSSLSock->funcPtrGetCertAndStatusCallback = funcPtrGetCertAndStatusCallback;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setCertAndStatusCallback() returns status = ", status);

    return status;

}

extern MSTATUS
SSL_setFullCertChainCallback(sbyte4 connectionInstance,
    void (*funcPtrGetOriginalCertChainCallback) (sbyte4 connectionInstance,
                                                struct certChain* pCertChain))
{
    sbyte4 index;
    MSTATUS status = OK;
    SSLSocket*  pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != funcPtrGetOriginalCertChainCallback)
    {
        pSSLSock->funcPtrGetOriginalCertChainCallback = funcPtrGetOriginalCertChainCallback;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setFullCertChainCallback() returns status = ", status);

    return status;

}

extern MSTATUS
SSL_setClientCertAuthorityCallback(sbyte4 connectionInstance,
    MSTATUS (*funcPtrClientCertAuthorityCallback) (sbyte4 connectionInstance,
                                             SizedBuffer *pCertAuthorities,
                                             ubyte4 certAuthorityCount))
{
    sbyte4 index;
    MSTATUS status = OK;
    SSLSocket *pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != funcPtrClientCertAuthorityCallback)
    {
        pSSLSock->funcPtrClientCertAuthorityCallback = funcPtrClientCertAuthorityCallback;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setClientCertAuthorityCallback() returns status = ", status);

    return status;
}
#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */

extern MSTATUS
SSL_setClientCertCallback(sbyte4 connInstance,
        MSTATUS (*funcPtrClientCertCallback)(sbyte4 connInstance,
                                            SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                                            ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                                            ubyte **ppRetCACert, ubyte4 *pRetNumCACerts))
{
    sbyte index;
    MSTATUS status = OK;

    if (OK > (index = getIndexFromConnectionInstance(connInstance)))
        goto exit;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (funcPtrClientCertCallback != NULL)
    {
        SSLSocket *pSSLSock = m_sslConnectTable[index].pSSLSock;
        if (!pSSLSock->server)
            pSSLSock->roleSpecificInfo.client.funcPtrClientCertCallback = funcPtrClientCertCallback;
        else
            status = ERR_SSL;
    }
    else
#endif
    {
        status = ERR_SSL;
    }

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__
MOC_EXTERN MSTATUS
SSL_setInvalidCertCallback(sbyte4 connectionInstance,
    MSTATUS (*funcPtrInvalidCertCallback) (sbyte4 connectionInstance,
                                           MSTATUS validationstatus))
{
    sbyte4 index;
    MSTATUS status = OK;

    SSLSocket *pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != funcPtrInvalidCertCallback)
    {
        pSSLSock->funcPtrInvalidCertCallback = funcPtrInvalidCertCallback;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setInvalidCertCallback() returns status = ", status);

    return status;


}
#endif /* __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__ */

/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
SSL_setVersionCallback(
    sbyte4 connectionInstance,
    MSTATUS (*funcPtrVersionCallback)(ubyte4 serverVersion,
                                      ubyte4 clientVersion,
                                      MSTATUS sslStatus))
{
    sbyte4 index;
    MSTATUS status = OK;

    SSLSocket *pSSLSock = NULL;

    if (OK > (index = getIndexFromConnectionInstance(connectionInstance)))
        goto exit;

    pSSLSock = m_sslConnectTable[index].pSSLSock;

    if (NULL != funcPtrVersionCallback)
    {
        pSSLSock->funcPtrVersionCallback = funcPtrVersionCallback;
    }
    else
    {
        status = ERR_SSL;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_setVersionCallback() returns status = ", status);

    return status;
}

MOC_EXTERN MSTATUS SSL_setMaxByteCount(ubyte4 byteCount)
{
    SSL_sslSettings()->maxByteCount = byteCount;
    return OK;
}

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
MOC_EXTERN MSTATUS SSL_setMaxTimerCountForRehandshake(ubyte4 timerCount)
{
    SSL_sslSettings()->maxTimerCountForRehandShake = timerCount;
    return OK;
}

MOC_EXTERN MSTATUS SSL_setFuncPtrClientRehandshakeRequest(sbyte4(*funcPtrClientRehandshakeRequest)
                                                                (sbyte4 connectionInstance))
{
    if (NULL == funcPtrClientRehandshakeRequest)
        return ERR_NULL_POINTER;

    SSL_sslSettings()->funcPtrClientRehandshakeRequest = funcPtrClientRehandshakeRequest;

    return OK;
}
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
MOC_EXTERN MSTATUS
SSL_setFuncPtrKeyUpdateRequest(sbyte4 (*funcPtrKeyUpdateRequest)(sbyte4 connectionInstance))
{
    if (NULL == funcPtrKeyUpdateRequest)
    {
        return ERR_NULL_POINTER;
    }

    SSL_sslSettings()->funcPtrKeyUpdateRequest = funcPtrKeyUpdateRequest;

    return OK;
}
#endif

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
MOC_EXTERN MSTATUS SSL_setFuncPtrAlertCallback(sbyte4 (*funcPtrAlertCallback)
                                                      (sbyte4 connectionInstance,
                                                       sbyte4 alertId,
                                                       sbyte4 alertClass))
{
    if (NULL == funcPtrAlertCallback)
        return ERR_NULL_POINTER;

    SSL_sslSettings()->funcPtrAlertCallback = funcPtrAlertCallback;

    return OK;
}
#endif

extern MSTATUS
SSL_setCertVerifySignCallback(sbyte4 (*funcPtrMutualAuthCertificateVerify)
                                      (sbyte4 connectionInstance,
                                       const ubyte* pHash, ubyte4 hashLen,
                                       ubyte* pResult, ubyte4 resultLength))
{
    SSL_sslSettings()->funcPtrMutualAuthCertificateVerify = funcPtrMutualAuthCertificateVerify;
    return OK;
}

/*------------------------------------------------------------------*/
#if (defined( __ENABLE_DIGICERT_SSL_PSK_SUPPORT__) || (defined(__ENABLE_DIGICERT_TLS13_PSK__)))
/**
@brief      Assign the given function pointer to funcPtrGetHintPSK in the sslSettings
            struct. Either ssl_server or ssl_client might not have correct offset.

@param pSSLSettings         Pointer to the sslSettings structure that gets function pointer.
@param funcPtrGetHintPSK     Pointer to the function that will return the hint for PSK.

 */
MOC_EXTERN MSTATUS SSL_setFuncPtrGetHintPSK(sbyte4 (*funcPtrGetHintPSK)
                                                   (sbyte4, ubyte hintPSK[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                                    ubyte4 *))
{
    if (NULL == funcPtrGetHintPSK)
        return ERR_NULL_POINTER;

    SSL_sslSettings()->funcPtrGetHintPSK = funcPtrGetHintPSK;

    return OK;
}



/**
@brief      Assign the given function pointer to funcPtrLookupPSK in the sslSettings
            struct. Either ssl_server or ssl_client might not have correct offset.

@param pSSLSettings         Pointer to the sslSettings structure that gets function pointer.
@param funcPtrLookupPSK     Pointer to the function that will find the Pre-Shared Key.

 */
MOC_EXTERN MSTATUS SSL_setFuncPtrLookupPSK(sbyte4 (*funcPtrLookupPSK)
                                                  (sbyte4, ubyte*, ubyte4,
                                                   ubyte[SSL_PSK_MAX_LENGTH],
                                                   ubyte4*))
{
    if (NULL == funcPtrLookupPSK)
        return ERR_NULL_POINTER;

    SSL_sslSettings()->funcPtrLookupPSK = funcPtrLookupPSK;

    return OK;
}

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
MOC_EXTERN MSTATUS SSL_setFuncPtrChoosePSK(sbyte4 (*funcPtrChoosePSK)
                                                  (sbyte4, ubyte *, ubyte4,
                                                   ubyte retPskIdentity[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                                   ubyte4 *, ubyte retPSK[SSL_PSK_MAX_LENGTH], ubyte4 *))
{
    if (NULL == funcPtrChoosePSK)
        return ERR_NULL_POINTER;

    SSL_sslSettings()->funcPtrChoosePSK = funcPtrChoosePSK;

    return OK;
}
#endif /*__ENABLE_DIGICERT_SSL_CLIENT__ */

#endif /* __ENABLE_DIGICERT_SSL_PSK_SUPPORT__ */

/*------------------------------------------------------------------*/

#endif /* (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__)) */
