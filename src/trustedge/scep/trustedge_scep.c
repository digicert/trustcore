/**
 * trustedge_scep.c
 *
 * @brief Trustedge certificate scep tool
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

/* Windows headers must be included first to avoid macro conflicts */
#if defined(__RTOS_WIN32__)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "../../common/moptions.h"
#include "../../common/mfmgmt.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/debug_console.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/msg_logger.h"
#include "../../common/datetime.h"
#include "../../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../../crypto/dsa.h"
#endif
#include "../../common/uri.h"
#include "../../asn1/oiddefs.h"
#include "../../crypto/crypto.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../common/base64.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/keyblob.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/derencoder.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/crypto_utils.h"
#include "../../crypto/asn1cert.h"
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../http/http_common.h"
#include "../../http/client/http_request.h"
#include "../../common/mtcp.h"
#include "../../asn1/parsecert.h"
#include "../../cert_enroll/cert_enroll.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/scep/trustedge_scep_defn.h"
#include "../../trustedge/scep/trustedge_scep_context.h"
#include "../../trustedge/scep/trustedge_scep_client.h"
#include "../../trustedge/scep/trustedge_scep_message.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"
#include "../../trustedge/utils/trustedge_tap.h"
#endif

#include "../../crypto/tools/crypto_keygen.h"
#include "../../trustedge/scep/trustedge_scep_api.h"
#include "../../trustedge/scep/trustedge_scep.h"

/*------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if !defined(__RTOS_WIN32__) && !defined(_WIN32)
#include <unistd.h>
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix
 *
 * Issue: The header file mqtt_client.h includes merrors.h and redefines OK to
 * MOC_OK for ESP32 builds. The ssl.h header below includes a ESP32 toolchain
 * header file which also defines OK which then gets redefined to MOC_OK causing
 * compilation errors.
 *
 * Fix: Undefine OK before including ssl.h, then redefine it back to MOC_OK
 */
#undef OK
#endif
#include <netdb.h>
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix - see comment above */
#define OK MOC_OK
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#define SCEP_ADDR_BUFFER     100
#define POLL_INTERVAL        3000
#define POLL_COUNT           10
#if !defined(__RTOS_ZEPHYR__)
/* zephyr defines this in fs_interface.h to 255 */
#define MAX_FILE_NAME        256
#endif

/* Same as in trustedge_certificate_main and crypto_keygen */
#define FORMAT_PEM 0
#define FORMAT_DER 1

/*------------------------------------------------------------------*/

static sbyte4 my_HttpTcpSend(httpContext *pHttpContext, sbyte4 socket,
                                ubyte *pDataToSend, ubyte4 numBytesToSend,
                                ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);
    TCP_WRITE(socket, (sbyte *)pDataToSend,numBytesToSend, pRetNumBytesSent);
    return 0;
}

static
MSTATUS getAddressInfo(sbyte *pHost, sbyte **ppAddr)
{
    struct addrinfo hints, *pRes = NULL, *pTmp = NULL;;
    int errcode;
    char addrStr[SCEP_ADDR_BUFFER];
    void *pData = NULL;
    MSTATUS status = OK;

    if (OK > (status = DIGI_MEMSET((ubyte*)&hints, 0, sizeof (hints))))
    {
        goto exit;
    }
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo ((char *) pHost, NULL, &hints, &pRes);
    if (errcode != 0)
    {
        status = ERR_HTTP;
        MSG_LOG_print(MSG_LOG_ERROR, "Failed to get addrinfo: %d\n", status);
        goto exit;
    }
    pTmp = pRes;
    while (pTmp)
    {
        inet_ntop (pTmp->ai_family, (void *) &(((struct sockaddr_in *)pTmp->ai_addr)->sin_addr), addrStr, SCEP_ADDR_BUFFER);

        switch (pTmp->ai_family)
        {
            case AF_INET:
                pData = &((struct sockaddr_in *) pTmp->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                pData = &((struct sockaddr_in6 *) pTmp->ai_addr)->sin6_addr;
                break;
        }
        inet_ntop (pTmp->ai_family, pData, addrStr, SCEP_ADDR_BUFFER);
        pTmp = pTmp->ai_next;
    }

    if (OK != (status = DIGI_CALLOC((void**)ppAddr, 1, DIGI_STRLEN((const sbyte*)addrStr)+1)))
    {
        goto exit;
    }

    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppAddr, addrStr, DIGI_STRLEN((const sbyte*)addrStr))))
    {
        goto exit;
    }

exit:
    if (pRes != NULL)
        freeaddrinfo(pRes);
    return status;
}

/*------------------------------------------------------------------*/

extern void
SCEP_CLIENT_LOG(TrustEdgeScepCtx *pArgs, byteBoolean isPem)
{
    MSG_LOG_print(MSG_LOG_INFO, "SCEP Server url               = %s\n", pArgs->pScepServerUrl);
    MSG_LOG_print(MSG_LOG_INFO, "SCEP keystore path            = %s\n", pArgs->pFilePath);
    MSG_LOG_print(MSG_LOG_INFO, "SCEP key alias                = %s\n", pArgs->pKeyAlias);
    MSG_LOG_print(MSG_LOG_INFO, "SCEP cert alias               = %s\n", pArgs->pCertAlias);
    MSG_LOG_print(MSG_LOG_INFO, "SCEP CA Cert                  = %s\n", isPem ? SCEP_CA_CERT_FILE_PEM : SCEP_CA_CERT_FILE_DER);
    MSG_LOG_print(MSG_LOG_INFO, "SCEP CEP CERT                 = %s\n", pArgs->pCepCertFileName);
    MSG_LOG_print(MSG_LOG_INFO, "SCEP XCHANGE CERT             = %s\n", isPem ? SCEP_XCHG_CERT_FILE_PEM : SCEP_XCHG_CERT_FILE_DER);

} /* SCEP_CLIENT_LOG */

/*------------------------------------------------------------------*/

static int
init(httpContext **ppHttpContext, sbyte *pScepUrl, sbyte4 maxRetryCount)
{
    MSTATUS status = 0;

    TCP_SOCKET socketServer;
    MSTATUS socket_status = 0;
    URI *uri = NULL;
    sbyte* host = NULL;
    sbyte *pAddr = NULL;
    sbyte2 port;
    sbyte4 attempts = 0;
    sbyte4 delay = 1;

    if((NULL == ppHttpContext))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    *ppHttpContext = NULL;

    /* initialize transport for HTTP */
    HTTP_httpSettings()->funcPtrHttpTcpSend   = my_HttpTcpSend;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = SCEP_CLIENT_http_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = SCEP_CLIENT_http_responseBodyCallback;

    /* start of SCEP operations */
    if (OK > (status = URI_ParseURI(pScepUrl, &uri))){
        goto exit;
    }

    if (OK > (status = URI_GetHost(uri, &host)))
    {
        goto exit;
    }

    if (OK > (status = getAddressInfo(host, &pAddr)))
    {
        goto exit;
    }

    if (OK > (status = URI_GetPort(uri, &port))){
        goto exit;
    }

    if (port == 0)
        port = 80;

    do {
        if (OK > (status = TCP_CONNECT(&socketServer, pAddr, port)))
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. Failed TCP connect to MQTT address %s on port %d\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pAddr, port);
            goto exit;
        }

        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. Failed TCP connect to MQTT address %s on port %d\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pAddr, port);

            RTOS_sleepMS(delay);
            delay *= 2;
            attempts++;
        }
    } while (OK != status && attempts < maxRetryCount);
    socket_status = 1;

    if (OK > (status = HTTP_connect(ppHttpContext, socketServer))){
        goto exit;
    }

exit:
    if (NULL != host) {
        FREE(host);
        host = NULL;
    }

    if (NULL != pAddr)
    {
        DIGI_FREE((void**)&pAddr);
    }

    if (NULL != uri)
        URI_DELETE(uri);

    if (OK > status)
    {
        HTTP_CONTEXT_releaseContext(ppHttpContext);
        if(ppHttpContext)
            *ppHttpContext = NULL;
        if (socket_status)
            TCP_CLOSE_SOCKET(socketServer);
    }

    return  status;
}

static SCEP_data *g_pScepData = NULL;

static
MSTATUS getScepData(SCEP_data **ppScepData)
{
    *ppScepData = g_pScepData;
    return OK;
}

extern MSTATUS TRUSTEDGE_SCEP_main(KeyGenArgs *pKeyArgs, TrustEdgeScepCtx *pScepArgs, TrustEdgeServiceCtx *pSrvCtx, void *pTapArgs)
{
	MSTATUS status = OK;
    sbyte *pKeyBlobFile = NULL;
    sbyte *pKeyBlobFileOld = NULL;
    sbyte *pKeyBlobFileBkp = NULL;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    requestInfo  *pReqInfo = NULL;
    AsymmetricKey asymKey = {0};
    ubyte* pLineCsr = 0;
    ubyte4 lineCsrLength;
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;
    httpContext *pHttpContext = NULL;
    ubyte *pCSRAttrBuffer = NULL;
    ubyte4 csrAttrBufferLen = 0;
    ubyte *pCsrBuffer = NULL;
    ubyte4 csrBufferLen = 0;

    ubyte *pExchangerCert = NULL;
    ubyte4 exchangerCertLen = 0;
    ubyte *pCaCert = NULL;
    ubyte4 caCertLen = 0;
    ubyte *pRaCert = NULL;
    ubyte4 raCertLen = 0;
    ubyte *pRequesterCert = NULL;
    ubyte4 requesterCertLen = 0;
    certDescriptor caCertDesc[1] = {{0}};
    certDescriptor raCertDesc[1] = {{0}};
    certDescriptor reqCertDesc = {0};
    ubyte *pOut = NULL;
    ubyte4 outLen = 0;
    sbyte *pTransId = NULL;
    ubyte4 transIdLen = 0;
    ubyte4 outStatus = 0;
    sbyte *pFullPath = NULL;
    ubyte *pOldKeyBlob = NULL;
    ubyte4 oldKeyBlobLen = 0;
    sbyte *pOldCertFileBkp = NULL;
    sbyte *pCertFileBkp = NULL;
    ubyte4 pkiOperation = 0;

    ubyte *pKeyPw = NULL;
    ubyte4 keyPwLen = 0;
    ubyte *pOldKeyPw = NULL;
    ubyte4 oldKeyPwLen = 0;
    byteBoolean freeKeyPw = FALSE;

    ubyte4 pemType = 0;
    ubyte *pTemp = NULL;
    ubyte *pSwap = NULL;
    ubyte4 tempLen = 0;
    sbyte *pDirPath = NULL;

    SCEP_messageType messageType = scep_UNKNOWN;
    SCEP_failInfo failInfo;

//TODO needed?
    gMocanaAppsRunning++;

    SCEP_CLIENT_LOG(pScepArgs, FORMAT_PEM == pKeyArgs->gInForm);

    if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)GET_CA_CERT))
    {
        messageType = scep_GetCACert;
        pScepArgs->pCertAlias = GET_CA_CERT_FILE;
    }
    else if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)GET_NEXT_CA_CERT))
    {
        messageType = scep_GetNextCACert;
        pScepArgs->pCertAlias = GET_NEXT_CA_CERT_FILE;
    }
    else if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)GET_CA_CAPS))
    {
        messageType = scep_GetCACaps;
        pScepArgs->pCertAlias = GET_CA_CAPS_FILE;
    }
    else if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)GET_CLIENT_CERT))
    {
        status = ERR_NOT_IMPLEMENTED;
        MSG_LOG_print(MSG_LOG_ERROR, "main::Operation not implemented::status:: %d\n", status);
        goto exit;
    }
    else if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)GET_CRL))
    {
        status = ERR_NOT_IMPLEMENTED;
        MSG_LOG_print(MSG_LOG_ERROR, "main::Operation not implemented::status:: %d\n", status);
        goto exit;
    }

    if (scep_UNKNOWN != messageType)
    {
        sbyte *fileExt;
        ubyte *pOutTemp = NULL;
        ubyte4 i = 0, certLen, tag;
        ubyte pOutCert[MAX_FILE_NAME];
        sbyte4 cmpRes = -1, tagAndCount;

        if ( OK > (status = init(&pHttpContext, pScepArgs->pScepServerUrl, pScepArgs->serviceCtx.maxRetryCount)))
        {
            MSG_LOG_print(MSG_LOG_ERROR,"TRUSTEDGE_SCEP init() return status = %d\n", status);
            goto exit;
        }

        status = SCEP_SAMPLE_fetchCertCRLCapsRequest(pHttpContext,
                                                     pScepArgs->supportsPost,
                                                     (ubyte *)pScepArgs->pScepServerUrl,
                                                     &pOut, &outLen,
                                                     &outStatus, messageType, &failInfo);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::SCEP_SAMPLE_fetchCertCRLCapsRequest::status: %d\n", status);
            goto exit;
        }

        if (FORMAT_PEM == pKeyArgs->gOutForm)
        {
            fileExt = TRUSTEDGE_SUFFIX_PEM;
        }
        else
        {
            fileExt = TRUSTEDGE_SUFFIX_DER;
        }

        if (scep_GetCRL == messageType)
        {
            fileExt = TRUSTEDGE_SUFFIX_CRL;
        }
        else if (scep_GetCACaps == messageType)
        {
            fileExt = TRUSTEDGE_SUFFIX_TXT;
        }

        (void) DIGI_FREE((void **) &pFullPath);
        status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, messageType == scep_GetCert ? KEYGEN_FOLDER_CERTS : KEYGEN_FOLDER_CA, pScepArgs->pCertAlias,
                                         fileExt, &pFullPath);
        if (OK != status)
        {
            goto exit;
        }

        if (scep_GetCACert == messageType)
        {
            pOutTemp = pOut;

            /* Check whether the certificate is in pem format. */
            if (outLen > 28)
            {
                status = DIGI_MEMCMP(pOutTemp, (ubyte *) "-----BEGIN CERTIFICATE-----", 27, &cmpRes);
                if (OK != status)
                {
                    goto exit;
                }
            }

            /* If the certificate is in X509 pem format then write it out to a file. This
            * will write out one or more certificates to a single file.
            */
            if (0 == cmpRes)
            {
                (void) DIGI_FREE((void **) &pFullPath);
                status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CA, pScepArgs->pCertAlias,
                                                 TRUSTEDGE_SUFFIX_PEM, &pFullPath);
                if (OK != status)
                {
                    goto exit;
                }
                if (OK > (status = DIGICERT_writeFile((const char *) pFullPath, pOutTemp, outLen)))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_writeFile::status: %d\n", status);
                }
                else
                {
                    MSG_LOG_print(MSG_LOG_DEBUG, "SCEP_TEST_SAMPLE: Received response with SUCCESS file - %s\n", pFullPath);
                }
            }
            else
            {
                cmpRes = -1;
                /* If the certificate is in der format then loop through each
                * certificate and write out each one to a file. If outform is PEM
                * consolidate the whole certificate chain in a single file.
                */
                while (outLen != 0)
                {
                    /* Get the certificate length.
                    */
                    status = ASN1_readTagAndLen(
                        pOutTemp, outLen, &tag, &certLen, &tagAndCount);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "main::ASN1_getTagLen::status: %d\n", status);
                        goto exit;
                    }

                    certLen += tagAndCount;

                    /* If the certificate length extends past the response length then throw
                    * an error.
                    */
                    if (outLen < certLen)
                    {
                        status = ERR_BAD_LENGTH;
                        MSG_LOG_print(MSG_LOG_ERROR, "main::Invalid certificate length::status: %d\n", status);
                        goto exit;
                    }

                    status = DIGI_MEMSET(pOutCert, 0x00, MAX_FILE_NAME);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "main::DIGI_MEMSET::status: %d\n", status);
                        goto exit;
                    }

                    status = DIGI_MEMCPY(pOutCert, pFullPath, DIGI_STRLEN(pFullPath) - 4);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "main::DIGI_MEMCPY::status: %d\n", status);
                        goto exit;
                    }

                    if (FORMAT_PEM == pKeyArgs->gOutForm)
                    {
                        cmpRes += 1;
                        snprintf((char *)pOutCert + DIGI_STRLEN((sbyte*)pOutCert), MAX_FILE_NAME - DIGI_STRLEN((sbyte*)pOutCert), "%s", TRUSTEDGE_SUFFIX_PEM);
                        if (0 == cmpRes)
                        {
                            FMGMT_remove((sbyte *) pOutCert, FALSE);
                        }

                        (void) DIGI_FREE((void**)&pTemp);
                        status = BASE64_makePemMessageAlloc(MOC_PEM_TYPE_CERT, pOutTemp, outLen, &pTemp, &tempLen);
                        if (OK != status)
                        {
                            goto exit;
                        }

                        /* Write the certificate out. */
                        status = DIGICERT_appendFile((const char *) pOutCert, pTemp, tempLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_appendFile::status: %d\n", status);
                            goto exit;
                        }

                        if (0 == cmpRes)
                        {
                            MSG_LOG_print(MSG_LOG_DEBUG, "SCEP_TEST_SAMPLE: Received response with SUCCESS file - %s\n", pOutCert);
                        }
                    }
                    else
                    {
                        if (i > 999) /* sanity check it's no more than 3 digits */
                        {
                            status = ERR_BUFFER_TOO_SMALL;
                            MSG_LOG_print(MSG_LOG_ERROR, "main: Too many certificates: status: %d\n", status);
                            goto exit;
                        }
                        snprintf((char *)pOutCert + DIGI_STRLEN((sbyte*)pOutCert), MAX_FILE_NAME - DIGI_STRLEN((sbyte*)pOutCert), "%d%s", (int)i, fileExt);

                        /* Write the certificate out. */
                        status = DIGICERT_writeFile((const char *) pOutCert, pOutTemp, certLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_writeFile::status: %d\n", status);
                            goto exit;
                        }
                        MSG_LOG_print(MSG_LOG_DEBUG, "SCEP_TEST_SAMPLE: Received response with SUCCESS file - %s\n", pOutCert);
                    }

                    outLen -= certLen;
                    pOutTemp += certLen;
                    i++;
                }
            }
        }
        else
        {
            if (FORMAT_PEM == pKeyArgs->gOutForm && scep_GetCACaps != messageType && scep_GetCRL != messageType)
            {
                status = BASE64_makePemMessageAlloc(MOC_PEM_TYPE_CERT, pOut, outLen, &pTemp, &tempLen);
                if (OK != status)
                    goto exit;

                pOutTemp = pOut;
                pOut = pTemp;
                pTemp = NULL;
                outLen = tempLen;
                tempLen = 0;

                (void) DIGI_FREE((void **) &pOutTemp);
            }

            if ( OK > ( status = DIGICERT_writeFile((char *)pFullPath, pOut, outLen)))
            {
                MSG_LOG_print(MSG_LOG_ERROR, "SCEP_TEST_SAMPLE: Received response with ERROR status - %d\n", status);
                goto exit;
            }
            MSG_LOG_print(MSG_LOG_DEBUG, "SCEP_TEST_SAMPLE: Received response with SUCCESS file - %s\n", pFullPath);
        }
    }
    else
    {
        if ((0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW)))
        {
            pkiOperation = 2;
        }
        else if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))
        {
            pkiOperation = 3;
        }
        else if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_ENROLL))
        {
            pkiOperation = 1;
        }
        else
        {
            status = ERR_UNSUPPORTED_OPERATION;
            MSG_LOG_print(MSG_LOG_ERROR, "main::Invalid operation::status:: %d\n", status);
            goto exit;
        }

        /* Below to test the sample APIs */
        /* 1. KEYGEN_generateKey */
        /* 2. SCEP_SAMPLE_generateCSRRequest */
        /* 3. SCEP_SAMPLE_sendEnrollmentRequest */

        if (0 != DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW))
        {
            AsymmetricKey newKey = {0};

            /* For rekey we have to get the old key and copy it over first */
            if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))
            {
                if (pKeyArgs->gGetSigningKeyPw)
                {
#ifndef __RTOS_ZEPHYR__
#if __ENABLE_DIGICERT_TAP__
                    if (pKeyArgs->gSignKeyTap)
                    {
                        status = KEYGEN_getPassword(&pOldKeyPw, &oldKeyPwLen, "TAP", "Original key");
                    }
                    else
#endif
                    {
                        status = KEYGEN_getPassword(&pOldKeyPw, &oldKeyPwLen, "PEM", "Original key");
                    }
                    if (OK != status)
                        goto exit;
#endif
                }

                /* read the old key */
                status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_KEYS, pScepArgs->pKeyAlias,
                                            pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER,
                                            (sbyte**) &pKeyBlobFile);
                if (OK != status)
                    goto exit;

                /* saving key file path in case of error so older file can be restored */
                CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_KEYS, pScepArgs->pKeyAlias,
                                            pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER,
                                            (sbyte**) &pKeyBlobFileBkp);

                status = DIGICERT_readFile((char *) pKeyBlobFile, &pOldKeyBlob, &oldKeyBlobLen);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Unable to read previously existing key: %s\n", pKeyBlobFile);
                    goto exit;
                }
                /* will copy it to alias.<pem/der>.old */
                status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_KEYS, pScepArgs->pKeyAlias,
                                                pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM_OLD : TRUSTEDGE_SUFFIX_DER_OLD,
                                                (sbyte**) &pKeyBlobFileOld);
                if (OK != status)
                    goto exit;

                status = DIGICERT_writeFile((char *) pKeyBlobFileOld, pOldKeyBlob, oldKeyBlobLen);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Unable to write previously existing key: %s\n", pKeyBlobFileOld);
                    goto exit;
                }
                MSG_LOG_print(MSG_LOG_INFO, "Moved old key to file: %s\n", pKeyBlobFileOld);
            }

            /* read the old key */
            (void) DIGI_FREE((void **) &pKeyBlobFile);
            status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_KEYS, pScepArgs->pKeyAlias,
                                        pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER,
                                        (sbyte**) &pKeyBlobFile);
            if (OK != status)
            {
                goto exit;
            }

            if ((FALSE == pScepArgs->serviceCtx.reuseKey) || (FALSE == FMGMT_pathExists(pKeyBlobFile, NULL)))
            {
                status = KEYGEN_generateKey(pKeyArgs, pTapArgs, &newKey, g_pRandomContext);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::KEYGEN_generateKey::status: %d\n", status);
                    goto exit;
                }

                if (NULL == pKeyArgs->gpOutFile)
                {
                    pKeyArgs->gpOutFile = pScepArgs->pKeyAlias;
                }

                /* Serialize the key, will handle TAP and PKCS8 */
                status = KEYGEN_outputPrivKey(pKeyArgs, &newKey, g_pRandomContext, TRUE, &pKeyBlob, &keyBlobLen);
                /* we later deserialize so unload and cleanup the newKey regardless of status */
#ifdef __ENABLE_DIGICERT_TAP__
                (void) TRUSTEDGE_TAP_unloadKey(&newKey);
#endif
                (void) CRYPTO_uninitAsymmetricKey(&newKey, NULL);

                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::KEYGEN_outputPrivKey::status: %d\n", status);
                    goto exit;
                }

                /* write the new key */
                /* reset the path to the key to be the output based on gOutForm */
                (void) DIGI_FREE((void **) &pKeyBlobFile);
                status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_KEYS, pScepArgs->pKeyAlias,
                                                pKeyArgs->gOutForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER,
                                                (sbyte**) &pKeyBlobFile);
                if (OK != status)
                    goto exit;

                if (FORMAT_PEM == pKeyArgs->gOutForm)
                {
                    MSG_LOG_print(MSG_LOG_DEBUG , "Writing Generated KEY-PAIR in PEM format: %s\n", pKeyBlobFile);
                }
                else
                {
                    MSG_LOG_print(MSG_LOG_DEBUG , "Writing Generated KEY-PAIR in DER format: %s\n", pKeyBlobFile);
                }

                if (OK > (status = DIGICERT_writeFile((char *) pKeyBlobFile, pKeyBlob, keyBlobLen)))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_writeFile::status: %d\n", status);
                    goto exit;
                }
            }
            else
            {
                if (OK != (status = DIGICERT_readFile((char*) pKeyBlobFile, &pKeyBlob, &keyBlobLen)))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile: name = %s, status: %d\n", pFullPath, status);
                    goto exit;
                }
            }

#ifdef __ENABLE_DIGICERT_TAP__
            if (pKeyArgs->gTap)
            {
                if (NULL != pTapArgs && NULL != ((KeyGenTapArgs *) pTapArgs)->gpTapCredList &&
                    ((KeyGenTapArgs *) pTapArgs)->gpTapCredList->numCredentials > 0)
                {
                    pKeyPw = ((KeyGenTapArgs *) pTapArgs)->gpTapCredList->pCredentialList[0].credentialData.pBuffer;
                    keyPwLen = ((KeyGenTapArgs *) pTapArgs)->gpTapCredList->pCredentialList[0].credentialData.bufferLen;
                }
            }
            else
#endif
            {
                if (NULL != pKeyArgs->gpPkcs8Pw && pKeyArgs->gPkcs8PwLen)
                {
                    pKeyPw = pKeyArgs->gpPkcs8Pw;
                    keyPwLen = pKeyArgs->gPkcs8PwLen;
                }
            }
        }
        else
        {
            /* renew case  */
            if (pKeyArgs->gGetSigningKeyPw)
            {
#ifndef __RTOS_ZEPHYR__
#ifdef __ENABLE_DIGICERT_TAP__
                if (pKeyArgs->gSignKeyTap)
                {
                    status = KEYGEN_getPassword(&pKeyPw, &keyPwLen, "TAP", "Original key");
                }
                else
#endif
                {
                    status = KEYGEN_getPassword(&pKeyPw, &keyPwLen, "PEM", "Original key");
                }
                if (OK != status)
                    goto exit;

                freeKeyPw = TRUE;
#endif
            }

            status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_KEYS, pScepArgs->pKeyAlias,
                                            pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER,
                                            (sbyte**) &pFullPath);
            if (OK != status)
                goto exit;

            if (OK != (status = DIGICERT_readFile((char*) pFullPath, &pKeyBlob, &keyBlobLen)))
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile: name = %s, status: %d\n", pFullPath, status);
                goto exit;
            }
        }

        /* 2. SCEP_SAMPLE_generateCSRRequest */
        if ((TRUE == pScepArgs->serviceCtx.serviceMode) || (NULL != pKeyArgs->gpInCsrFile))
        {
            if (TRUE == pScepArgs->serviceCtx.serviceMode)
            {
                pCSRAttrBuffer = pScepArgs->serviceCtx.pCSRAttrBuffer;
                csrAttrBufferLen = pScepArgs->serviceCtx.csrAttrBufferLen;
                pScepArgs->serviceCtx.pCSRAttrBuffer = NULL;
            }
            else
            {
                (void) DIGI_FREE((void **) &pFullPath);
                if (OK > (status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CONF, pKeyArgs->gpInCsrFile,
                                                        NULL, (sbyte**) &pFullPath)))
                {
                    goto exit;
                }

                if (OK > (status = DIGICERT_readFile((char *) pFullPath, &pCSRAttrBuffer, &csrAttrBufferLen)))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile Conf file missing: status = %d\n", status);
                    goto exit;
                }
            }

            status = SCEP_SAMPLE_generateCSRRequest(
                    pKeyArgs->gTap,
                    pKeyArgs->gHashAlgo,
                    pKeyBlob,
                    keyBlobLen,
                    pKeyPw,
                    keyPwLen,
                    pCSRAttrBuffer,
                    csrAttrBufferLen,
                    pScepArgs->pChallengePass,
                    DIGI_STRLEN((const sbyte *)pScepArgs->pChallengePass),
                    &pCsrBuffer,
                    &csrBufferLen,
                    &pReqInfo,
                    pScepArgs->serviceCtx.serviceMode);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::SCEP_SAMPLE_generateCSRRequest::status %d\n", status);
                goto exit;
            }
        }
        else
        {
            status = ERR_FILE_NOT_EXIST;
            MSG_LOG_print(MSG_LOG_ERROR, "ERROR: Please provide conf file - sample_scep_csr.cnf - status = %d\n", status);
            goto exit;
        }

        (void) DIGI_FREE((void **) &pFullPath);

        //TODO move old csr to .old also in a rekey case?

        if (FORMAT_PEM == pKeyArgs->gOutForm)
        {
            if (OK > (status = BASE64_encodeMessage(pCsrBuffer, csrBufferLen,
                            &pLineCsr, &lineCsrLength)))
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::BASE64_encodeMessage::status %d\n", status);
                goto exit;
            }

            if (OK > (status = SCEP_MESSAGE_breakIntoLines(pLineCsr, lineCsrLength,
                            &pCsr, &csrLen)))
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::SCEP_MESSAGE_breakIntoLines::status %d\n", status);
                goto exit;
            }

            /* Write CSR to a file in PEM */
            status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_REQ, pScepArgs->pCertAlias,
                                            (sbyte *) ".csr.pem", (sbyte**) &pFullPath);
            if (OK != status)
                goto exit;

            MSG_LOG_print(MSG_LOG_DEBUG, "Writing CSR File in PEM format: %s\n", pFullPath);

            if (OK > (status = DIGICERT_writeFile((char *) pFullPath, pCsr, csrLen)))
            {
                MSG_LOG_print(MSG_LOG_DEBUG, "main::DIGICERT_writeFile::status: %d\n", status);
                goto exit;
            }
        }
        else
        {
            /* Write CSR to a file in DER */
            status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_REQ, pScepArgs->pCertAlias,
                                            (sbyte *) ".csr.der", (sbyte**) &pFullPath);
            if (OK != status)
                goto exit;

            MSG_LOG_print(MSG_LOG_DEBUG, "Writing CSR File in DER format: %s\n", pFullPath);
            if (OK > (status = DIGICERT_writeFile((char *) pFullPath, pCsrBuffer, csrBufferLen)))
            {
                MSG_LOG_print(MSG_LOG_DEBUG, "main::DIGICERT_writeFile::status: %d\n", status);
                goto exit;
            }
        }

        /* 3. SCEP_SAMPLE_sendEnrollmentRequest */
        MSG_LOG_print(MSG_LOG_DEBUG, "\n send Enrollment request\n%s","");

        /* Prepare all the required parameters for enrollment */
        (void) DIGI_FREE((void **) &pFullPath);
        status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CA,
                                        (sbyte *) (FORMAT_PEM == pKeyArgs->gInForm ? SCEP_CA_CERT_FILE_PEM : SCEP_CA_CERT_FILE_DER),
                                        NULL, (sbyte**) &pFullPath);
        if (OK != status)
            goto exit;

        if (OK > (status = DIGICERT_readFile((char *)pFullPath, &pCaCert, &caCertLen)))
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile::status %d\n", status);
            goto exit;
        }

        if (FORMAT_PEM == pKeyArgs->gInForm) /* convert to DER */
        {
            status = BASE64_decodePemMessageAlloc (pCaCert, caCertLen, &pemType, &pTemp, &tempLen);
            if (OK != status)
                goto exit;

            if (MOC_PEM_TYPE_CERT != pemType)
            {
                status = ERR_INVALID_INPUT;
                MSG_LOG_print(MSG_LOG_ERROR, "Invalid PEM Form CA Certificate: status = %d\n",status);
                goto exit;
            }

            /* switch pointers */
            pSwap = pCaCert;
            pCaCert = pTemp; pTemp = NULL;
            caCertLen = tempLen; tempLen = 0;

            (void) DIGI_FREE((void **) &pSwap); /* free the PEM buffer */
        }

        caCertDesc[0].pCertificate = pCaCert;
        caCertDesc[0].certLength = caCertLen;

    //TODO in CERTS folder or CA?
        (void) DIGI_FREE((void **) &pFullPath);
        status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCepCertFileName,
                                        NULL, (sbyte**) &pFullPath);
        if (OK != status)
            goto exit;

        if (OK > (status = DIGICERT_readFile((char *)pFullPath, &pRaCert, &raCertLen)))
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile::status %d\n", status);
            goto exit;
        }

        if (FORMAT_PEM == pKeyArgs->gInForm) /* convert to DER */
        {
            status = BASE64_decodePemMessageAlloc (pRaCert, raCertLen, &pemType, &pTemp, &tempLen);
            if (OK != status)
                goto exit;

            if (MOC_PEM_TYPE_CERT != pemType)
            {
                status = ERR_INVALID_INPUT;
                MSG_LOG_print(MSG_LOG_ERROR, "Invalid PEM Form RA (CEP) Certificate: status = %d\n",status);
                goto exit;
            }

            /* switch pointers */
            pSwap = pRaCert;
            pRaCert = pTemp; pTemp = NULL;
            raCertLen = tempLen; tempLen = 0;

            (void) DIGI_FREE((void **) &pSwap); /* free the PEM buffer */
        }

        raCertDesc[0].pCertificate = pRaCert;
        raCertDesc[0].certLength = raCertLen;

        /* Initialize asymmetric key */
        if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::CRYPTO_initAsymmetricKey::status %d\n", status);
            goto exit;
        }

        if (NULL != pKeyPw && keyPwLen)
        {
            status = CRYPTO_deserializeAsymKeyWithCreds ( pKeyBlob, keyBlobLen, NULL, pKeyPw, keyPwLen, NULL, &asymKey);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::CRYPTO_deserializeAsymKeyWithCreds::status %d\n", status);
                goto exit;
            }
        }
        else
        {
            status = CRYPTO_deserializeAsymKey(pKeyBlob, keyBlobLen, NULL, &asymKey);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::CRYPTO_deserializeAsymKey::status %d\n", status);
                goto exit;
            }
        }

        status = KEYGEN_calculateEndDate(pKeyArgs);
        if (OK != status)
            goto exit; /* error already logged */

        status = CERT_ENROLL_setCertDates(pReqInfo->value.certInfoAndReqAttrs.pCsrCtx->pCertSubjectInfo, &(pKeyArgs->gStartDate), &(pKeyArgs->gEndDate));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::CERT_ENROLL_setCertDates::status %d\n", status);
            goto exit;
        }

        /* For renew the keys are the same */
        if (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW))
        {
            pOldKeyBlob = pKeyBlob;
            oldKeyBlobLen = keyBlobLen;
        }

        if ((0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW)) ||
                (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY)))
        {
            /* get the old certificate */
            (void) DIGI_FREE((void **) &pFullPath);
            status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCertAlias,
                                            pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER, &pFullPath);
            if (OK != status)
                goto exit;

            if (OK != (status = DIGICERT_readFile((char*) pFullPath, &pRequesterCert, &requesterCertLen)))
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile::status %d\n", status);
                goto exit;
            }

            /* saving new cert file path */
            CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCertAlias,
                                    pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER, &pCertFileBkp);

            /* copy it to .old */
            (void) DIGI_FREE((void **) &pFullPath);
            status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCertAlias,
                                            pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM_OLD : TRUSTEDGE_SUFFIX_DER_OLD, &pFullPath);
            if (OK != status)
                goto exit;

            status = DIGICERT_writeFile((char *)pFullPath, pRequesterCert, requesterCertLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Unable to copy old cert, file: %s status = %d\n", pFullPath, status);
                goto exit;
            }
            MSG_LOG_print(MSG_LOG_INFO, "Moved old cert to file: %s\n", pFullPath);

            /* saving old cert file path in case of error so old file can be restored */
            CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCertAlias,
                                    pKeyArgs->gInForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM_OLD : TRUSTEDGE_SUFFIX_DER_OLD, &pOldCertFileBkp);

            if (FORMAT_PEM == pKeyArgs->gInForm)
            {
                status = BASE64_decodePemMessageAlloc (pRequesterCert, requesterCertLen, &pemType, &pTemp, &tempLen);
                if (OK != status)
                    goto exit;

                if (MOC_PEM_TYPE_CERT != pemType)
                {
                    status = ERR_INVALID_INPUT;
                    MSG_LOG_print(MSG_LOG_ERROR, "Invalid PEM Form Signing Certificate: status = %d\n",status);
                    goto exit;
                }

                /* switch pointers */
                pSwap = pRequesterCert;
                pRequesterCert = pTemp; pTemp = NULL;
                requesterCertLen = tempLen; tempLen = 0;

                (void) DIGI_FREE((void **) &pSwap); /* free the PEM buffer */
            }
        }
        else /* generate a new self signed cert */
        {
            if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) &asymKey,
                            pReqInfo->value.certInfoAndReqAttrs.pCsrCtx->pCertSubjectInfo,
                            pKeyArgs->gHashAlgo,
                            pReqInfo->value.certInfoAndReqAttrs.pCsrCtx->reqAttr.pExtensions,
                            RANDOM_rngFun, g_pRandomContext,
                            &pRequesterCert, &requesterCertLen)))
            {
                MSG_LOG_print(MSG_LOG_ERROR, "main::ASN1CERT_generateSelfSignedCertificate::status %d\n", status);
                goto exit;
            }
        }
        reqCertDesc.pCertificate = pRequesterCert;
        reqCertDesc.certLength = requesterCertLen;
        if ( OK > (status = init(&pHttpContext, pScepArgs->pScepServerUrl, pScepArgs->serviceCtx.maxRetryCount)))
        {
            MSG_LOG_print(MSG_LOG_ERROR,"TRUSTEDGE_SCEP init() return status = %d\n", status);
            goto exit;
        }

        if (OK > (status = DIGI_CALLOC((void**)&g_pScepData, 1, sizeof(SCEP_data))))
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::DIGI_CALLOC::status %d\n", status);
            goto exit;
        }

        (void) DIGI_FREE((void **) &pFullPath);
        status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS,
                                        (sbyte *) (FORMAT_PEM == pKeyArgs->gInForm ? SCEP_XCHG_CERT_FILE_PEM : SCEP_XCHG_CERT_FILE_DER),
                                        NULL, &pFullPath);
        if (OK != status)
            goto exit;

        if (OK > (status = DIGICERT_readFile((char *) pFullPath, &pExchangerCert, &exchangerCertLen)))
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::DIGICERT_readFile::status %d\n", status);
        }

        if (FORMAT_PEM == pKeyArgs->gInForm) /* convert to DER */
        {
            status = BASE64_decodePemMessageAlloc (pExchangerCert, exchangerCertLen, &pemType, &pTemp, &tempLen);
            if (OK != status)
                goto exit;

            if (MOC_PEM_TYPE_CERT != pemType)
            {
                status = ERR_INVALID_INPUT;
                MSG_LOG_print(MSG_LOG_ERROR, "Invalid PEM Form Exchange Certificate: status = %d\n",status);
                goto exit;
            }

            /* switch pointers */
            pSwap = pExchangerCert;
            pExchangerCert = pTemp; pTemp = NULL;
            exchangerCertLen = tempLen; tempLen = 0;

            (void) DIGI_FREE((void **) &pSwap); /* free the PEM buffer */
        }

        /* Fill the SCEP Data */
        g_pScepData->pExchangerCertificate = pExchangerCert;
        g_pScepData->exchangerCertLen = exchangerCertLen;
        if ( (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY)))
        {
            g_pScepData->pPemKeyBlob = pOldKeyBlob;
            g_pScepData->pemKeyBlobLen = oldKeyBlobLen;
        }
        else
        {
            g_pScepData->pPemKeyBlob = pKeyBlob;
            g_pScepData->pemKeyBlobLen = keyBlobLen;
        }
        g_pScepData->pKeyPw = pKeyPw;
        g_pScepData->keyPwLen = keyPwLen;
        SCEP_SAMPLE_registerScepDataCallback(getScepData);

        status = SCEP_SAMPLE_sendEnrollmentRequest(
                pKeyArgs->gTap,
                pScepArgs->pEncAlgoOid, pScepArgs->pHashOid,
                pHttpContext,
                pKeyBlob, keyBlobLen,
                pKeyPw, keyPwLen,
                pCsrBuffer, csrBufferLen,
                &pReqInfo,
                pScepArgs->supportsPost,
                (ubyte *)pScepArgs->pScepServerUrl,
                caCertDesc, 1,
                raCertDesc, 1,
                &reqCertDesc, pkiOperation,
                pOldKeyBlob, oldKeyBlobLen,
                pOldKeyPw, oldKeyPwLen,
                pScepArgs->oaep, pScepArgs->pLabel, pScepArgs->oaepHashId,
                &pOut, &outLen,
                &pTransId, &transIdLen, &outStatus, &failInfo);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "main::SCEP_SAMPLE_sendEnrollmentRequest::status: %d\n", status);
            goto exit;
        }
        else
        {
            if (outStatus == scep_PENDING && pTransId != NULL)
            {
                if (pTransId == NULL)
                {
                    status = ERR_NULL_POINTER;
                    MSG_LOG_print(MSG_LOG_DEBUG, "TransactionId is null\n%s","");
                    goto exit;
                }
                MSG_LOG_print(MSG_LOG_DEBUG, "Received pending status. Retry pending request...\n%s","");

                if (((pScepArgs->serverType == GEN_GET_SERVER) || (pScepArgs->serverType == GEN_POST_SERVER)) &&
                    ((0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW)) ||
                        (0 == DIGI_STRCMP(pScepArgs->pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))))
                {
                    (void) DIGI_FREE((void **) &pRequesterCert);
                    if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) &asymKey,
                                    pReqInfo->value.certInfoAndReqAttrs.pCsrCtx->pCertSubjectInfo,
                                    pKeyArgs->gHashAlgo,
                                    pReqInfo->value.certInfoAndReqAttrs.pCsrCtx->reqAttr.pExtensions,
                                    RANDOM_rngFun, g_pRandomContext,
                                    &pRequesterCert, &requesterCertLen)))
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "main::ASN1CERT_generateSelfSignedCertificate::status %d\n", status);
                        goto exit;
                    }

                    reqCertDesc.pCertificate = pRequesterCert;
                    reqCertDesc.certLength = requesterCertLen;
                    g_pScepData->pPemKeyBlob = pKeyBlob;
                    g_pScepData->pemKeyBlobLen = keyBlobLen;
                }
                status = SCEP_SAMPLE_retryPendingEnrollmentRequest(
                        pKeyArgs->gTap,
                        pScepArgs->pEncAlgoOid, pScepArgs->pHashOid,
                        pHttpContext,
                        pKeyBlob, keyBlobLen,
                        pKeyPw, keyPwLen,
                        pCsrBuffer, csrBufferLen,
                        &pReqInfo,
                        pScepArgs->supportsPost,
                        (ubyte *)pScepArgs->pScepServerUrl,
                        caCertDesc, 1,
                        raCertDesc, 1,
                        &reqCertDesc, pkiOperation,
                        pOldKeyBlob, oldKeyBlobLen,
                        pOldKeyPw, oldKeyPwLen,
                        pTransId, transIdLen,
                        POLL_INTERVAL, POLL_COUNT,
                        pScepArgs->oaep, pScepArgs->pLabel, pScepArgs->oaepHashId,
                        &pOut, &outLen, &failInfo);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "main::SCEP_SAMPLE_retryPendingEnrollmentRequest::status: %d\n", status);
                    goto exit;
                }
                else
                {
                    (void) DIGI_FREE((void **) &pFullPath);
                    status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCertAlias,
                                                    pKeyArgs->gOutForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER, &pFullPath);
                    if (OK != status)
                        goto exit;

                    if (TRUE == pScepArgs->serviceCtx.serviceMode)
                    {
                        status = TRUSTEDGE_utilsGetCertInfo(pSrvCtx, pOut, outLen);
                        if (OK != status)
                        {
                            goto exit;
                        }
                    }

                    if (FORMAT_PEM == pKeyArgs->gOutForm)
                    {
                        ubyte *pTemp = NULL;
                        ubyte *pSwap = NULL;
                        ubyte4 tempLen = 0;

                        status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_CERT, pOut, outLen, &pTemp, &tempLen);
                        if (OK != status)
                            goto exit;

                        pSwap = pOut;
                        pOut = pTemp; pTemp = NULL;
                        outLen = tempLen; tempLen = 0;

                        (void) DIGI_FREE((void **) &pSwap);
                    }

                    if ( OK > ( status = DIGICERT_writeFile((char *) pFullPath, pOut, outLen)))
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "SCEP_TEST_SAMPLE: Received response with ERROR status - %d\n", status);
                        goto exit;
                    }
                    MSG_LOG_print(MSG_LOG_DEBUG, "SCEP_TEST_SAMPLE: Received response with SUCCESS file - %s\n", pFullPath);
                }
            }
            else
            {
                (void) DIGI_FREE((void **) &pFullPath);
                status = CERT_ENROLL_getFullPath(pScepArgs->pFilePath, KEYGEN_FOLDER_CERTS, pScepArgs->pCertAlias,
                                                pKeyArgs->gOutForm == FORMAT_PEM ? TRUSTEDGE_SUFFIX_PEM : TRUSTEDGE_SUFFIX_DER, &pFullPath);
                if (OK != status)
                    goto exit;

                if (TRUE == pScepArgs->serviceCtx.serviceMode)
                {
                    status = TRUSTEDGE_utilsGetCertInfo(pSrvCtx, pOut, outLen);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }

                if (FORMAT_PEM == pKeyArgs->gOutForm)
                {
                    ubyte *pTemp = NULL;
                    ubyte *pSwap = NULL;
                    ubyte4 tempLen = 0;

                    status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_CERT, pOut, outLen, &pTemp, &tempLen);
                    if (OK != status)
                        goto exit;

                    pSwap = pOut;
                    pOut = pTemp; pTemp = NULL;
                    outLen = tempLen; tempLen = 0;

                    (void) DIGI_FREE((void **) &pSwap);
                }

                if ( OK > ( status = DIGICERT_writeFile((char *)pFullPath, pOut, outLen)))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "SCEP_TEST_SAMPLE: Received response with ERROR status - %d\n", status);
                    goto exit;
                }
                MSG_LOG_print(MSG_LOG_DEBUG, "SCEP_TEST_SAMPLE: Received response with SUCCESS file - %s\n", pFullPath);
            }
        }
    }

    pScepArgs->serviceCtx.cmdStatus = outStatus;
    pScepArgs->serviceCtx.failInfo = failInfo;
exit:
   if (g_pScepData)
       DIGI_FREE((void**)&g_pScepData);
    if ((OK != status) && (NULL != pKeyBlobFileBkp) && (NULL != pKeyBlobFileOld))
    {
        FMGMT_rename(pKeyBlobFileOld, pKeyBlobFileBkp);
        FMGMT_remove(pKeyBlobFileOld, FALSE);
    }
    if ((OK != status) && (NULL != pOldCertFileBkp) && (NULL != pCertFileBkp))
    {
        FMGMT_rename(pOldCertFileBkp, pCertFileBkp);
        FMGMT_remove(pOldCertFileBkp, FALSE);
    }
    DIGI_FREE((void**)&pKeyBlobFileBkp);
    DIGI_FREE((void**)&pOldCertFileBkp);
    (void) DIGI_FREE((void**)&pDirPath);
    DIGI_FREE((void**)&pFullPath);
    DIGI_FREE((void**)&pCaCert);
    DIGI_FREE((void**)&pRaCert);
    DIGI_FREE((void**)&pRequesterCert);
    DIGI_FREE((void**)&pExchangerCert);
    DIGI_FREE((void**)&pTransId);
    DIGI_FREE((void**)&pCSRAttrBuffer);
    DIGI_FREE((void**)&pKeyBlobFile);
    DIGI_FREE((void**)&pKeyBlobFileOld);
    DIGI_FREE((void**)&pCertFileBkp);
    DIGI_FREE((void**)&pTemp);
    if (OK != status)
    {
        if (NULL != pReqInfo)
        {
            SCEP_CONTEXT_releaseRequestInfo(pReqInfo);
        }
    }

    if (freeKeyPw && NULL != pKeyPw)
    {
        (void) DIGI_MEMSET_FREE(&pKeyPw, keyPwLen);
    }
    if (NULL != pOldKeyPw)
    {
        (void) DIGI_MEMSET_FREE(&pOldKeyPw, oldKeyPwLen);
    }

    if (pCsrBuffer) DIGI_FREE((void**)&pCsrBuffer);
    if (pOut) DIGI_FREE((void**)&pOut);

    if (NULL != pOldKeyBlob && (uintptr) pOldKeyBlob != (uintptr) pKeyBlob)
    {
        DIGI_FREE((void**)&pOldKeyBlob);
    }
    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void**)&pKeyBlob);
    }
    if (pLineCsr) DIGI_FREE((void**)&pLineCsr);
    if (pCsr) DIGI_FREE((void**)&pCsr);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    if (pHttpContext != NULL)
        HTTP_CONTEXT_releaseContext(&pHttpContext);

    RTOS_sleepMS(1000); /* sleep for one second etc */
    gMocanaAppsRunning--;

    return status;
}
