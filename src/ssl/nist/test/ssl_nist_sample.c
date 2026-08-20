/*
 * ssl_nist_sample.c
 *
 * Sample code for testing TLS 1.2 against SP 800-135
 *
 */

#include "../../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

#include <stdio.h>
#include <string.h>

#include "../../../common/mtypes.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/merrors.h"
#include "../../../common/mstdlib.h"
#include "../../../common/mrtos.h"
#include "../../../common/mtcp.h"
#include "../../../common/moc_net.h"
#include "../../../common/random.h"
#include "../../../common/debug_console.h"
#include "../../../common/mem_pool.h"
#include "../../../crypto/hw_accel.h"
#include "../../../crypto/ca_mgmt.h"
#include "../../../crypto/pubcrypto.h"
#include "../../../crypto/pkcs_key.h"
#include "../../../crypto/sha1.h"
#include "../../../crypto/md5.h"
#include "../../../common/sizedbuffer.h"
#include "../../../crypto/cert_store.h"
#include "../../../ssl/ssl.h"
#include "../../../ssl/sslsock.h"
#include "../../../ssl/sslsock_priv.h"

#include "../../../ssl/nist/ssl_nist.h"

/* Utility functions used in sample code */
static ubyte UTILS_ValOfHexChar( sbyte c)
{
    if ('0' <= c && c <= '9')
    {
        return (ubyte) (c - '0');
    }
    else if ( 'A' <= c && c <= 'F')
    {
        return (ubyte) ( c + 10 - 'A');
    }
    else if ( 'a' <= c && c <= 'f')
    {
        return (ubyte) ( c + 10 - 'a');
    }
    return 0;
}

static ubyte4 UTILS_str_to_byteStr( const sbyte* s, ubyte** bs)
{
    ubyte* buffer = 0;
    ubyte4 bsLen;
    ubyte4 sLen = DIGI_STRLEN( s);
    ubyte* pTemp;

    bsLen = (sLen+1)/2;
    buffer = MALLOC( bsLen + 1); /* to prevent a malloc 0 */
    if (!buffer)
    {
        *bs = 0;
        return 0;
    }

    pTemp = buffer;

    if ( sLen & 1)
    {
        *pTemp++ = UTILS_ValOfHexChar(*s++);
    }
    while ( *s)
    {
        *pTemp = (ubyte) ((UTILS_ValOfHexChar(*s++)) << 4);
        *pTemp++ |= (UTILS_ValOfHexChar(*s++));
    }
    *bs = buffer;
    return bsLen;
}

/* Sample usage using sample vector from NIST */
MSTATUS sampleUsageSSL()
{
    MSTATUS status;
    SSLSocket *pSock = NULL;
    ubyte *pPreMaster = NULL;
    ubyte4 preMasterLen = 0;
    ubyte *pClientHello = NULL;
    ubyte4 clientHelloLen = 0;
    ubyte *pServerHello = NULL;
    ubyte4 serverHelloLen = 0;
    ubyte *pClientRandom = NULL;
    ubyte4 clientRandomLen = 0;
    ubyte *pServerRandom = NULL;
    ubyte4 serverRandomLen = 0;
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    ubyte *pSessionHash     = NULL;
    ubyte4 sessionHashLen   = 0;
    ubyte* pLabelAndHash    = NULL;
    ubyte4 labelAndHashSize = 0;
#endif
    ubyte *pMaster = NULL;
    ubyte4 masterLen = 0;
    ubyte *pKeyBlock = NULL;
    ubyte4 keyBlockLen = 0;
    ubyte4 i;

    /* DIGICERT_initDigicert must be called one time before operation */
    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;
    
    /* Prepare values from vector */
    preMasterLen = UTILS_str_to_byteStr(
        "f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc", &pPreMaster);
    clientHelloLen = UTILS_str_to_byteStr(
        "36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c", &pClientHello);
    serverHelloLen = UTILS_str_to_byteStr(
        "f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce", &pServerHello);
    clientRandomLen = UTILS_str_to_byteStr(
        "62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616", &pClientRandom);
    serverRandomLen = UTILS_str_to_byteStr(
        "ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868", &pServerRandom);
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    /* Hash algo used is SHA256 and the digest size is 32; Hence the random session hash value should be 32 bytes long */
    sessionHashLen = UTILS_str_to_byteStr(
        "36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c", &pSessionHash);
#endif

    /* Allocate and initialize SSL Socket structure */
    status = DIGI_CALLOC((void **)&pSock, 1, sizeof(SSLSocket));
    if (OK != status)
        goto exit;

    /* Current support for SP 800-135 testing is for TLS 1.2 only */
    pSock->sslMinorVersion = TLS12_MINORVERSION;

    status = SSL_SOCK_init(pSock, 0, 0, NULL, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    status = SSL_SOCK_initHashPool(pSock);
    if (OK != status)
        goto exit;

    /* Set the PRF hash algo and key block len as specified in vector */
    status = setSSLKeyBlockLen(pSock, 128);
    if (OK != status)
        goto exit;

    status = setSSLPRFHashAlgo(pSock, ht_sha256);
    if (OK != status)
        goto exit;

    /* Set client/server hello values from vector */
    status = setSSLValue(pSock, sslClientRandom, pClientHello, clientHelloLen);
    if (OK != status)
        goto exit;

    status = setSSLValue(pSock, sslServerRandom, pServerHello, serverHelloLen);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (OK > (status = DIGI_CALLOC((void **)&pMaster, 1, SSL_MASTERSECRETSIZE)))
        goto exit;

    labelAndHashSize = 32/* digest size of sha256 */ + TLS_EXTENDED_MASTERSECRET_LABEL_SIZE;

    if (OK > (status = DIGI_CALLOC((void **)&pLabelAndHash, 1, labelAndHashSize)))
        goto exit;

    /* copy label "extended master secret" */
    DIGI_MEMCPY(pLabelAndHash, (ubyte *)TLS_EXTENDED_MASTERSECRET_LABEL, TLS_EXTENDED_MASTERSECRET_LABEL_SIZE);

    DIGI_MEMCPY(pLabelAndHash + TLS_EXTENDED_MASTERSECRET_LABEL_SIZE, pSessionHash, sessionHashLen);

    if (OK > (status = generateMasterSecret(pSock, pPreMaster, preMasterLen, pLabelAndHash, labelAndHashSize,
                           pMaster,  SSL_MASTERSECRETSIZE)))
    {
        goto exit;
    }
    masterLen = SSL_MASTERSECRETSIZE;
#else
    /* Generate the master secret */
    status = SSL_SOCK_generateKeyMaterial(pSock, pPreMaster, preMasterLen);
    if (OK != status)
        goto exit;

    /* Get the generated master secret */
    status = getSSLValue(pSock, sslMasterSecret, &pMaster, &masterLen);
    if (OK != status)
        goto exit;

#endif
    printf("master key len: %d value:\n", masterLen);
    for (i = 0; i < masterLen; i++)
    {
        printf("%02x", pMaster[i]);
    }
    printf("\n");

    /* Set SSL resume value to prepare for key block generation */
    status = setSSLSessionResume(pSock, E_SessionIDResume);
    if (OK != status)
        goto exit;

    /* Set client/server random values */
    status = setSSLValue(pSock, sslClientRandom, pClientRandom, clientRandomLen);
    if (OK != status)
        goto exit;

    status = setSSLValue(pSock, sslServerRandom, pServerRandom, serverRandomLen);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    status = setSSLValue(pSock, sslMasterSecret, pMaster, masterLen);
    if (OK != status)
        goto exit;
#endif

    /* Generate the key block */
    status = SSL_SOCK_generateKeyMaterial(pSock, pPreMaster, preMasterLen);
    if (OK != status)
        goto exit;

    /* Get the generated key block */
    status = getSSLValue(pSock, sslKeyBlock, &pKeyBlock, &keyBlockLen);
    if (OK != status)
        goto exit;

    printf("key block len: %d value:\n", keyBlockLen);
    for (i = 0; i < keyBlockLen; i++)
    {
        printf("%02x", pKeyBlock[i]);
    }
    printf("\n");

exit:
    
    if (NULL != pSock)
    {
        SSL_SOCK_uninit(pSock);
        DIGI_FREE((void **)&pSock);
    }
    if (NULL != pMaster)
    {
        DIGI_FREE((void **)&pMaster);
    }
    if (NULL != pKeyBlock)
    {
        DIGI_FREE((void **)&pKeyBlock);
    }
    if (NULL != pPreMaster)
    {
        DIGI_FREE((void **)&pPreMaster);
    }
    if (NULL != pClientHello)
    {
        DIGI_FREE((void **)&pClientHello);
    }
    if (NULL != pServerHello)
    {
        DIGI_FREE((void **)&pServerHello);
    }
    if (NULL != pClientRandom)
    {
        DIGI_FREE((void **)&pClientRandom);
    }
    if (NULL != pServerRandom)
    {
        DIGI_FREE((void **)&pServerRandom);
    }
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (NULL != pSessionHash)
    {
        DIGI_FREE((void **)&pSessionHash);
    }
    if (NULL != pLabelAndHash)
    {
        DIGI_FREE((void **)&pLabelAndHash);
    }
#endif
    DIGICERT_freeDigicert();

    return status;
}

int main(int argc, char *argv[])
{
    MSTATUS status = OK;
    status = sampleUsageSSL();
    printf("sampleUsageSSL status = %d\n", status);
    return 0;
}
#endif
