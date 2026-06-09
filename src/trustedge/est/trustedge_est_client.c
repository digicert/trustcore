/*
 * trustedge_est_client.c
 *
 * Trustedge EST Client
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __RTOS_WIN32__
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#include <unistd.h>
#endif /* !__RTOS_AZURE__*/
#endif /* !__RTOS_FREERTOS__*/
#else
#include <Windows.h>
#endif /* !__RTOS_WIN32__ */

#ifdef __RTOS_VXWORKS__
#include <stat.h>
#else /* __RTOS_VXWORKS__ */
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#include <sys/stat.h>
#endif /* !__RTOS_AZURE__ */
#endif /* !__RTOS_FREERTOS__ */
#endif /* __RTOS_VXWORKS__ */

#if defined(__RTOS_LINUX__)
#include <fcntl.h>
#endif /* __RTOS_LINUX__ */

#include "../../common/moptions.h"
#include "../../common/moc_net_system.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../ssl/ssl.h"
#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/sizedbuffer.h"
#include "../../common/mstdlib.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/mjson.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/utils.h"
#include "../../crypto/hw_accel.h"
#include "../../common/base64.h"
#include "../../common/datetime.h"
#include "../../common/mfmgmt.h"
#include "../../common/int64.h"
#include "../../common/status_log.h"
#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
#include "../../common/tp_version.h"
#endif
#include "../../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../../crypto/dsa.h"
#include "../../crypto/dsa2.h"
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/keyblob.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/crypto_utils.h"
#include "../../http/http_context.h"
#include "../../http/http_common.h"
#include "../../http/http.h"
#include "../../http/http_auth.h"
#include "../../http/client/http_request.h"
#include "../../http/client/http_client_process.h"
#include "../../est/est_context.h"
#include "../../est/est_utils.h"
#include "../../trustedge/est/trustedge_est_include.h"
#include "../../asn1/derencoder.h"
#include "../../common/uri.h"
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#include "../../common/mtcp_async.h"
#endif /*!__RTOS_AZURE__*/
#endif /*!__RTOS_FREERTOS__*/
#include "../../crypto/md5.h"
#include "../../common/debug_console.h"
#include "../../common/msg_logger.h"
#include "../../est/est_cert_utils.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/ASN1TreeWalker.h"
#include "../../asn1/mocasn1.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../crypto_interface/crypto_interface_aes.h"
#include "../../crypto_interface/crypto_interface_hmac_kdf.h"
#include "../../crypto/hmac_kdf.h"
#include "../../crypto/moccms.h"
#include "../../crypto/moccms_util.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ecb.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs12.h"

#ifdef  __ENABLE_DIGICERT_TAP__
#include "../../tap/tap.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../crypto/mocasymkeys/tap/qstap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_tap.h"
#ifdef __ENABLE_DIGICERT_TEE__
#include "../../smp/smp_tee/smp_tap_tee.h"
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
#include "../../smp/smp_nanoroot/smp_nanoroot.h"
#include "../../tap/tap_common.h"
#endif
#endif
#include "../../est/est_client_api.h"
#include "../../crypto/tools/crypto_keygen.h"

#if defined (__FREERTOS_RTOS__) && !defined(__FREERTOS_SIMULATOR__) && !defined(__RTOS_FREERTOS_ESP32__)
#include "FreeRTOS.h"
#include "semphr.h"
#include "ff.h"
#endif
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/certificate/trustedge_certificate.h"
#include "../../common/mterm.h"

/*------------------------------------------------------------------*/

#ifdef __RTOS_WIN32__
#define SLEEP(X)    Sleep(X);
#elif (defined(__RTOS_FREERTOS__) || defined(__RTOS_AZURE__))
#define SLEEP(X)    RTOS_sleepMS(X*1000);
#else
#define SLEEP(X)    sleep(X);
#endif /* __RTOS_WIN32__ */

/*------------------------------------------------------------------*/
/* Global Variables                                                 */
/*------------------------------------------------------------------*/
sbyte4                 gSslConnectionInstance;
static hwAccelDescr    gHwAccelCtx = 0;
static sbyte * 		   estc_User           = NULL;
static sbyte * 		   estc_Pass           = NULL;
static sbyte *         estc_truststorePath = NULL;
static AsymmetricKey*  gpPrevAsymKey       = NULL;
static sbyte*          pPkiDatabase        = NULL;
struct certStore*      pCertStore          = NULL;

static MSTATUS TRUSTEDGE_EST_CB_validateRootCertificate(const void* arg, CStream cs, struct ASN1_ITEM* pCertificate, sbyte4 chainLength);

/* SDEC static VERBOSE METHODS */
/*****************************************************************************/
static void
verbosePrintString(sbyte4 level, char *pPrintString)
{
    if (NULL != pPrintString)
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s", (char *)pPrintString);
    }
}

static void
verbosePrintPointer(sbyte4 level, char *pPrintString, ubyte *ptr)
{
    MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s%p\n", pPrintString, ptr);
}

static void
verbosePrintNL(sbyte4 level, char *pPrintString)
{
    if (NULL != pPrintString)
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s\n", (char *)pPrintString);
    }
}

static void
verbosePrintLengthNL(sbyte4 level, char *pPrintString, sbyte4 length)
{
    if (NULL != pPrintString)
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%.*s\n", length, (char *)pPrintString);
    }
}

static void
verbosePrintString1Int1NL(sbyte4 level, char *pPrintString1, sbyte4 value1)
{
    if (NULL != pPrintString1)
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s%d\n", (char *)pPrintString1, value1);
    }
    else
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%d\n", value1);
    }
}

#if defined(__ENABLE_DIGICERT_TAP__)
static void
verbosePrintStringRaw(sbyte4 level, char *pPrintString)
{
    if (NULL != pPrintString)
    {
        MSG_LOG_printRaw(level, "%s", (char *)pPrintString);
    }
}

static void
verbosePrintString1Hex(sbyte4 level, ubyte value1)
{
    MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%02X", value1);
}

static void
verbosePrintString1Hex1NL(sbyte4 level, char *pPrintString1, ubyte8 value1)
{
    if (NULL != pPrintString1)
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s%llX", (char *)pPrintString1, value1);
    }
    else
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%llX", value1);
    }
}
#endif

static void
verbosePrintStringNL(sbyte4 level, char *pPrintString1, sbyte *pPrintString2)
{
    if (NULL != pPrintString1 || NULL != pPrintString2)
    {
        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s%s\n", (char *)pPrintString1, (char *)pPrintString2);
    }
}

static void
verbosePrintError(char *pPrintString, sbyte4 value)
{
    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s Status: %d (%s) \n", (pPrintString ? pPrintString : (char *)""), value, MERROR_lookUpErrorCode(value));
}

static void
verbosePrintStringError(char *pPrintString, sbyte *value)
{
    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s: %s\n", pPrintString, (sbyte *)value);
}

static void
verboseDumpResponse(sbyte4 level, ubyte *pResp, ubyte4 respLen, sbyte4 status)
{
    MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "HTTP status code= %d\n", status);
    if (pResp != NULL)
    {
        MSG_LOG_printRaw(level, " ; response message=%.*s\n", respLen, pResp);
    }
}

static ubyte
verbosePrintChar(ubyte theChar)
{
    if ((32 > theChar) || (126 < theChar))
        return '.';

    return theChar;
}

static void
verboseHexDump(sbyte4 level, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4 index = 0;
    ubyte pBuffer[106] = { 0 };
    sbyte4 i = 0;

    while (index < mesgLen)
    {
        ubyte4 min = (16 > (mesgLen - index)) ? mesgLen - index : 16;
        ubyte4 j, k;

        i = snprintf(pBuffer, sizeof(pBuffer), "  %08x: ", (unsigned int)index);
        for (j = 0; j < min; j++)
        {
            snprintf(pBuffer + i, sizeof(pBuffer) - i, "%02x ", (unsigned int) pMesg[index + j]);
            i += 3;
        }

        for (k = j; k < 16; k++)
        {
            snprintf(pBuffer + i, sizeof(pBuffer) - i, "   ");
            i += 3;
        }
        snprintf(pBuffer + i, sizeof(pBuffer) - i, "    ");
        i += 4;

        for (k = 0; k < j; k++)
        {
            snprintf(pBuffer + i, sizeof(pBuffer) - i, "%c", (int) verbosePrintChar(pMesg[index + k]));
            i += 1;
        }
        snprintf(pBuffer + i, sizeof(pBuffer) - i, "\n");

        MSG_LOG_printEx(level, "TRUSTEDGE-CERTIFICATE", "%s", pBuffer);
        index += 16;
    }
}

/*****************************************************************************/

MOC_EXTERN
MSTATUS TRUSTEDGE_EST_utilStrToInt(sbyte *pStr, ubyte8 *pInt)
{
    MSTATUS status;
    ubyte4 strLen, tmpLen, i;
    ubyte pHex[8] = {0};
    sbyte4 intVal = 0;
    sbyte *pMaxInt = (sbyte *) ESTC_MAX_INT;
    sbyte *pStop = NULL;

    if ( (NULL == pStr) || (NULL == pInt) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    strLen = DIGI_STRLEN(pStr);
    if (0 == strLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    tmpLen = DIGI_STRLEN((sbyte *)ESTC_HEX_IDENTIFIER);
    if ( (strLen >= tmpLen) &&
         (0 == DIGI_STRNICMP(pStr,(sbyte *)ESTC_HEX_IDENTIFIER, tmpLen)) )
    {
        strLen -= tmpLen;
        pStr += tmpLen;
        if (strLen > 16)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        tmpLen = (16 - strLen) >> 1;
        status = DIGI_convertHexString(
            (char *) pStr, pHex + tmpLen, sizeof(pHex) - tmpLen);
        if (OK != status)
        {
            goto exit;
        }

        U8INIT_HI(*pInt, DIGI_NTOHL(pHex));
        U8INIT_LO(*pInt, DIGI_NTOHL(pHex + 4));
    }
    else
    {
        tmpLen = DIGI_STRLEN(pMaxInt);
        if ( (strLen > tmpLen) || (FALSE == DIGI_ISDIGIT(pStr[0])) )
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        /* Check for overflow */
        if (strLen == tmpLen)
        {
            for (i = 0; i < tmpLen; i++)
            {
                if (FALSE == DIGI_ISDIGIT(pStr[i]))
                {
                    status = ERR_INVALID_INPUT;
                    goto exit;
                }

                if (pStr[i] > pMaxInt[i])
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }
                else if (pStr[i] < pMaxInt[i])
                {
                    break;
                }
            }
        }

        intVal = DIGI_ATOL(pStr, (const sbyte **) &pStop);
        if (*pStop != '\0')
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        U8INIT_HI(*pInt, 0);
        U8INIT_LO(*pInt, intVal);
        status = OK;
    }

exit:

    return status;
}

sbyte *TRUSTEDGE_EST_getTrustStorePathCopy()
{
    MSTATUS status = OK;
    sbyte *pRet = NULL;

    if (NULL == estc_truststorePath)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pRet, DIGI_STRLEN(estc_truststorePath) + 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pRet, estc_truststorePath, DIGI_STRLEN(estc_truststorePath) + 1);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if ( (NULL != pRet) && (OK != status) )
    {
        DIGI_FREE((void **) &pRet);
        pRet = NULL;
    }

    return pRet;
}

static
void TRUSTEDGE_EST_init_defaults(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs)
{
    MOC_UNUSED(pKeyArgs);
    estc_User = pEstArgs->pUserName;
    estc_Pass = pEstArgs->pUserPasswd;
    estc_truststorePath = pEstArgs->pTrustPath;
}

MOC_EXTERN sbyte4
TRUSTEDGE_EST_http_responseBodyCallback(httpContext *pHttpContext,
        ubyte *pDataReceived,
        ubyte4 dataLength,
        sbyte4 isContinueFromBlock)
{

    return EST_responseBodyCallbackHandle(pHttpContext,
            pDataReceived, dataLength,
            isContinueFromBlock);
}

extern sbyte4
TRUSTEDGE_EST_http_responseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock)
{
    /* do nothing */
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);
    return OK;
}


static sbyte4
TRUSTEDGE_EST_passwordPrompt(httpContext *pHttpContext, const ubyte* pChallenge, ubyte4 challengeLength,
        ubyte **ppUser, ubyte4* pUserLength, ubyte **ppPassword, ubyte4 *pPasswordLength, sbyte4 isContinueFromBlock)
{
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);
	MOC_UNUSED(pChallenge);
	MOC_UNUSED(challengeLength);
    *ppUser = (ubyte *)estc_User;
    *pUserLength = DIGI_STRLEN(estc_User);
    *ppPassword = (ubyte *)estc_Pass;
    *pPasswordLength = DIGI_STRLEN(estc_Pass);
    return OK;
}

extern sbyte4
TRUSTEDGE_EST_http_requestBodyCallback (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie)
{

    return EST_requestBodyCallback(pHttpContext, ppDataToSend, pDataLength, pRequestBodyCookie);
}

static sbyte4
TRUSTEDGE_EST_HttpTcpSend(httpContext *pHttpContext, TCP_SOCKET socket,
        ubyte *pDataToSend, ubyte4 numBytesToSend,
        ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MSTATUS status = OK;
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);

    verbosePrintString1Int1NL(MSG_LOG_VERBOSE, "numBytesToSend = ", numBytesToSend);
    status = TCP_WRITE(socket, (sbyte *)pDataToSend,numBytesToSend, pRetNumBytesSent);
    return status;
}

MOC_STATIC sbyte4
TRUSTEDGE_EST_HttpSslSend(httpContext *pHttpContext, TCP_SOCKET socket,
        ubyte *pDataToSend, ubyte4 numBytesToSend,
        ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);
#ifndef __ENABLE_DIGICERT_RELEASE__
    verbosePrintString1Int1NL(MSG_LOG_VERBOSE, "connectionInstance = ", gSslConnectionInstance);
#endif
    verbosePrintPointer(MSG_LOG_VERBOSE, "TRUSTEDGE_EST_HttpSslSend::pDataToSend: ", pDataToSend);
    verbosePrintString1Int1NL(MSG_LOG_VERBOSE, "TRUSTEDGE_EST_HttpSslSend Called numBytesToSend = ", numBytesToSend);
    verbosePrintLengthNL(MSG_LOG_VERBOSE, (char *)pDataToSend, numBytesToSend);
    verboseHexDump(MSG_LOG_VERBOSE, pDataToSend, numBytesToSend);

    sbyte4 sslConnectionInst = SSL_getInstanceFromSocket(socket);
    *pRetNumBytesSent = SSL_send(sslConnectionInst, (sbyte  *)pDataToSend, numBytesToSend);
    return OK;
}

static MSTATUS
TRUSTEDGE_EST_deserializeAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen,
    ubyte *pPass, ubyte4 passLen, AsymmetricKey *pAsymKey)
{
    MSTATUS status;
    ubyte *pDecodedKey = NULL;
    ubyte4 decodedKeyLen = 0;

    if ( (NULL == pKey) || (NULL == pAsymKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(pAsymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(
        MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, pAsymKey);
    if ( (OK != status) && (NULL != pPass) )
    {
        status = CA_MGMT_decodeCertificate(
            pKey, keyLen, &pDecodedKey, &decodedKeyLen);
        if (OK == status)
        {
            pKey = pDecodedKey;
            keyLen = decodedKeyLen;
        }

        status = PKCS_getPKCS8KeyEx(
            MOC_HW(hwAccelCtx) pKey, keyLen, pPass, passLen, pAsymKey);
    }

exit:

    if (NULL != pDecodedKey)
        DIGI_FREE((void **) &pDecodedKey);

    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__
static MSTATUS TRUSTEDGE_EST_removeNVIndex(
    ubyte8 index,
    TAP_AUTH_CONTEXT_PROPERTY inputAuthProp,
    KeyGenTapArgs *pEstTapContext)
{
    MSTATUS status;
    TAP_ObjectInfoList objectInfoList = {0};
    TAP_StorageInfo storageInfo = {0};
    ubyte4 i;

    status = TAP_getPolicyStorageList(
        pEstTapContext->gpTapCtx, pEstTapContext->gpTapEntityCredList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Remove index if it exists */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            storageInfo.index = index;
            storageInfo.size = 0;
            storageInfo.storageType = TAP_WRITE_OP_UNKNOWN;
            storageInfo.ownerPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                                | TAP_PERMISSION_BITMASK_DELETE) ;
            storageInfo.publicPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                                | TAP_PERMISSION_BITMASK_DELETE) ;
            storageInfo.pAttributes = NULL ;
            storageInfo.authContext = inputAuthProp;

            status = TAP_freePolicyStorage(
                pEstTapContext->gpTapCtx,
                pEstTapContext->gpTapEntityCredList, &storageInfo,
                NULL);
            break;
        }
    }

exit:

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    return status;
}

static MSTATUS TRUSTEDGE_EST_persistDataAtNVIndex(
    ubyte8 index, ubyte *pData, ubyte4 dataLen,
    TAP_AUTH_CONTEXT_PROPERTY inputAuthProp, KeyGenTapArgs *pEstTapContext)
{
    MSTATUS status;
    TAP_ObjectInfoList objectInfoList = {0};
    TAP_StorageInfo storageInfo = {0};
    TAP_CredentialList storageCredentials = {0};
    TAP_AttributeList setAttributes = {0};
    TAP_AUTH_CONTEXT_PROPERTY authContext = inputAuthProp;
    TAP_Attribute keyAttribute = {
        TAP_ATTR_AUTH_CONTEXT, sizeof(TAP_AUTH_CONTEXT_PROPERTY), &authContext
    };
    TAP_Buffer nvIn = { 0 };
    ubyte4 i;

    status = TAP_getPolicyStorageList(
        pEstTapContext->gpTapCtx, pEstTapContext->gpTapEntityCredList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify index does not exist */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            status = ERR_TAP_NV_INDEX_EXISTS;
            goto exit;
        }
    }

    storageInfo.index = index;
    storageInfo.size = dataLen;
    storageInfo.storageType = TAP_WRITE_OP_DIRECT;
    storageInfo.ownerPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE);
    storageInfo.publicPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE);
    storageInfo.pAttributes = NULL;
    storageInfo.authContext = authContext;

    /* Create index */
    status = TAP_allocatePolicyStorage(
        pEstTapContext->gpTapCtx, pEstTapContext->gpTapEntityCredList,
        &storageInfo, NULL, &storageCredentials, NULL);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    status = TAP_getPolicyStorageList(
        pEstTapContext->gpTapCtx, pEstTapContext->gpTapEntityCredList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify index exists */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            break;
        }
    }

    if (i == objectInfoList.count)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    nvIn.pBuffer = pData;
    nvIn.bufferLen = dataLen;

    if (TAP_AUTH_CONTEXT_PLATFORM == authContext)
    {
        setAttributes.listLen++;
        setAttributes.pAttributeList = &keyAttribute;
    }

    status = TAP_setPolicyStorage(
        pEstTapContext->gpTapCtx, pEstTapContext->gpTapEntityCredList,
        &objectInfoList.pInfo[i], &setAttributes, &nvIn, NULL);

exit:

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    return status;
}

MSTATUS TRUSTEDGE_EST_createTapAsymKey(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs,
                                       AsymmetricKey *pKey, ubyte *pKeyType, ubyte4 keySize,
                                       KeyGenTapArgs *pEstTapContext)
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pNewKey = NULL;
    ubyte4 numKeyAttrs = 0, i = 0;
    TAP_AttributeList *pKeyAttributes = NULL;
    TAP_AttributeList keyAttributes = { 0 };
    TAP_CREATE_KEY_TYPE keyType = TAP_CREATE_KEY_TYPE_PRIMARY;
    TAP_Buffer uniqueDataBuf = { 0 };
    ubyte4 keyNonceByteLen = 0;
    ubyte *pKeyNonce = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
#ifdef __ENABLE_DIGICERT_ECC__
    MEccTapKeyGenArgs eccTapArgs = {0};
    ubyte4 curveId;
#endif

    if (pKey != NULL)
    {
        status = CRYPTO_initAsymmetricKey(pKey);
        if (OK != status)
            goto exit;

        if (TRUE == pEstArgs->tapKeyPrimary)
        {
            numKeyAttrs += 3;

            status = DIGI_CALLOC(
                (void **) &(keyAttributes.pAttributeList), numKeyAttrs,
                sizeof(TAP_Attribute));
            if (OK != status)
            {
                goto exit;
            }
            keyAttributes.listLen = numKeyAttrs;

            keyAttributes.pAttributeList[i].type = TAP_ATTR_CREATE_KEY_TYPE;
            keyAttributes.pAttributeList[i].length = sizeof(TAP_CREATE_KEY_TYPE);
            keyAttributes.pAttributeList[i].pStructOfType = &keyType;
            i++;

            /* Get byte length relative to curve/key size */
            if (DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
            {
                /* RSA sizes are checked earlier when validating arguments and
                 * ensured to be a multiple of 8 */
                keyNonceByteLen = keySize / 8;
            }
#ifdef __ENABLE_DIGICERT_ECC__
            else
            {
                switch (keySize)
                {
                    case 192:
                        keyNonceByteLen = 24;
                        break;
                    case 224:
                        keyNonceByteLen = 28;
                        break;
                    case 256:
                        keyNonceByteLen = 32;
                        break;
                    case 384:
                        keyNonceByteLen = 48;
                        break;
                    case 521:
                        keyNonceByteLen = 66;
                        break;
                    default:
                        status = ERR_TAP_INVALID_CURVE_ID;
                        goto exit;
                }
            }
#endif

            status = DIGI_MALLOC((void **) &pKeyNonce, keyNonceByteLen);
            if (OK != status)
            {
                goto exit;
            }

            status = RANDOM_numberGenerator(
                g_pRandomContext, pKeyNonce, keyNonceByteLen);
            if (OK != status)
            {
                goto exit;
            }

            uniqueDataBuf.pBuffer = pKeyNonce;
            uniqueDataBuf.bufferLen = keyNonceByteLen;

            keyAttributes.pAttributeList[i].type = TAP_ATTR_CREATE_KEY_ENTROPY;
            keyAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
            keyAttributes.pAttributeList[i].pStructOfType = &uniqueDataBuf;
            i++;

            keyAttributes.pAttributeList[i].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
            keyAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
            keyAttributes.pAttributeList[i].pStructOfType = &pEstArgs->tapKeyHandle;
            i++;

            pKeyAttributes = &keyAttributes;
        }

        if (pKeyArgs->gProtected)
        {
            if (TRUE == pEstArgs->pkcs8InteractivePass)
            {
                status = KEYGEN_addCreds(pEstTapContext->gpTapCredList);
                if (OK != status)
                {
                    verbosePrintString(MSG_LOG_ERROR, "Unable to create password credential for TAP key.\n");
                    goto exit;
                }
            }
            else
            {
                ubyte *pPassBuf = NULL;
                TAP_Credential *pCredentialList = NULL;

                status = DIGI_CALLOC((void **) &pCredentialList, 1, sizeof(TAP_Credential));
                if (OK != status)
                {
                    verbosePrintError("Unable to allocate memory.", status);
                    goto exit;
                }

                pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
                pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
                pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;

                status = DIGI_MALLOC((void**)&pPassBuf, DIGI_STRLEN(pEstArgs->pPkcs8Pw));
                if (OK != status)
                {
                    verbosePrintError("Unable to allocate memory.", status);
                    goto exit;
                }

                status = DIGI_MEMCPY((ubyte*)pPassBuf, pEstArgs->pPkcs8Pw, DIGI_STRLEN(pEstArgs->pPkcs8Pw));
                if (OK != status)
                {
                    verbosePrintError("Unable to copy TAP key password.", status);
                    goto exit;
                }

                pCredentialList[0].credentialData.bufferLen = DIGI_STRLEN(pEstArgs->pPkcs8Pw);
                pCredentialList[0].credentialData.pBuffer = pPassBuf;
                pEstTapContext->gpTapCredList->numCredentials = 1;
                pEstTapContext->gpTapCredList->pCredentialList = pCredentialList;
            }
        }

        if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            if (pKeyArgs->gKeyUsage == TAP_KEY_USAGE_DECRYPT) {
                rsaTapArgs.algKeyInfo.rsaInfo.encScheme = pKeyArgs->gEncScheme;
            }
            else if (pKeyArgs->gKeyUsage == TAP_KEY_USAGE_GENERAL)
            {
                rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = pKeyArgs->gSigScheme;
                rsaTapArgs.algKeyInfo.rsaInfo.encScheme = pKeyArgs->gEncScheme;
            }
            else
            {
                rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = pKeyArgs->gSigScheme;
            }

            rsaTapArgs.tokenId = pEstArgs->tapTokenHierarchy;
            rsaTapArgs.keyUsage = pKeyArgs->gKeyUsage;
            rsaTapArgs.pTapCtx = pEstTapContext->gpTapCtx;
            rsaTapArgs.pEntityCredentials = pEstTapContext->gpTapEntityCredList;
            rsaTapArgs.pKeyCredentials = pEstTapContext->gpTapCredList;
            rsaTapArgs.pKeyAttributes = pKeyAttributes;
            status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gHwAccelCtx)
                NULL, &pNewKey, keySize, NULL, akt_tap_rsa,
                &rsaTapArgs);
            if (OK != status)
                goto exit;

            pKey->key.pRSA = pNewKey;
            pKey->type = akt_tap_rsa;
        }
#ifdef __ENABLE_DIGICERT_ECC__
        else
        {
            eccTapArgs.tokenId = pEstArgs->tapTokenHierarchy;
            eccTapArgs.keyUsage = pKeyArgs->gKeyUsage;
            eccTapArgs.pTapCtx = pEstTapContext->gpTapCtx;
            eccTapArgs.algKeyInfo.eccInfo.sigScheme = pKeyArgs->gSigScheme;
            eccTapArgs.pEntityCredentials = pEstTapContext->gpTapEntityCredList;
            eccTapArgs.pKeyCredentials = pEstTapContext->gpTapCredList;

            switch (keySize)
            {
                case 192:
                    curveId = cid_EC_P192;
                    break;
                case 224:
                    curveId = cid_EC_P224;
                    break;
                case 256:
                    curveId = cid_EC_P256;
                    break;
                case 384:
                    curveId = cid_EC_P384;
                    break;
                case 521:
                    curveId = cid_EC_P521;
                    break;
                default:
                    status = ERR_TAP_INVALID_CURVE_ID;
                    goto exit;
            }

            eccTapArgs.pKeyAttributes = pKeyAttributes;
            status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(gHwAccelCtx)
                curveId, &pNewKey, NULL, NULL, akt_tap_ecc, &eccTapArgs);
            if (OK != status)
                goto exit;

            pKey->key.pECC = pNewKey;
            pKey->type = akt_tap_ecc;
        }
#endif
        if (TRUE == pEstArgs->tapKeyPrimary)
        {
            if (OK == status)
            {
                if (TRUE == pEstArgs->tapKeyNonceNvIndexSet)
                {
                    /* Primary key was created successfully, persist the primary
                     * key nonce as well. Do not treat failure to store nonce as
                     * error */
                    if (OK == TRUSTEDGE_EST_persistDataAtNVIndex(
                        pEstArgs->tapKeyNonceNvIndex, pKeyNonce, keyNonceByteLen, TAP_AUTH_CONTEXT_PLATFORM, pEstTapContext))
                    {
                        verbosePrintString1Hex1NL(MSG_LOG_INFO, "Persisted primary key nonce at index: 0x", pEstArgs->tapKeyNonceNvIndex);
                    }
                    else
                    {
                        verbosePrintString1Hex1NL(MSG_LOG_INFO, "WARNING: Unable to persist primary key nonce at index: 0x", pEstArgs->tapKeyNonceNvIndex);
                    }
                }

                verbosePrintString(MSG_LOG_INFO, "Persisted primary key at index (or id): ");
            }
            else
            {
                verbosePrintString(MSG_LOG_INFO, "WARNING: Unable to persist/generate primary key at index (or id): ");
            }
            if (pEstArgs->isIdHex)
            {
                verbosePrintStringRaw(MSG_LOG_INFO, "0x");
                for (i = 0; i < pEstArgs->tapKeyHandle.bufferLen; i++)
                {
                    verbosePrintString1Hex(MSG_LOG_INFO, pEstArgs->tapKeyHandle.pBuffer[i]);
                }
            }
            else
            {
                verbosePrintStringRaw(MSG_LOG_INFO, (sbyte *)pEstArgs->tapKeyHandle.pBuffer);
            }
            verbosePrintStringRaw(MSG_LOG_INFO, "\n");
        }
    }
exit:
    if (NULL != pKeyNonce)
    {
        DIGI_FREE((void **) &pKeyNonce);
    }
    if (NULL != keyAttributes.pAttributeList)
    {
        DIGI_FREE((void **) &(keyAttributes.pAttributeList));
    }
    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

MSTATUS TRUSTEDGE_EST_storeMocKeyInCertstore(ubyte *pKeyBlob, ubyte4 keyBlobLen/*AsymmetricKey pKey*/, ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte *pCert, ubyte4 certLen)
{
	MSTATUS status = OK;
	ubyte* pAsymBlob = NULL; /* This is the blob of the from AsymmetricKey to be fed into CERT_STORE */
	ubyte4 asymBlobLen;
    AsymmetricKey asymKey = {0};

    if (OK != (status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx) pKeyBlob, keyBlobLen, NULL, &asymKey)))
    {
        verbosePrintNL(MSG_LOG_INFO, "Failed to deserialize the key, Please cleanup software keys from keystore if any.");
		verbosePrintError("Unable to deserialize the key. Please cleanup software keys from keystore if any.", status);
        goto exit;
    }

	if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &asymKey, mocanaBlobVersion2, &pAsymBlob, &asymBlobLen)))
	{
		verbosePrintError("Unable to serialize asymmetric key.", status);
		goto exit;
	}
	/* Add the KeyBlob to the CERT STORE */
    if (pCert == NULL)
    {
        if (OK != (status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                                           pKeyAlias, keyAliasLen,
                                                           pAsymBlob, asymBlobLen)))
        {
            verbosePrintError("Unable to add naked key to certstore.", status);
            goto exit;
        }
    }
    else
    {
        if (OK > (status = CERT_STORE_addIdentityEx(pCertStore,
                                                    pKeyAlias, keyAliasLen,
                                                    pCert, certLen,
                                                    pAsymBlob, asymBlobLen)))
        {
            goto exit;
        }
    }
exit:
    if(pAsymBlob)
        DIGI_FREE((void **)&pAsymBlob);

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return status;
}

static MSTATUS
TRUSTEDGE_EST_loadCertsAndKeysIntoCertStore(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs, ubyte *pKeyAlias, ubyte4 keyAliasLen,
                                            ubyte *pKeyType, ubyte4 keySize, void *pEstTapContext)
{
    MOC_UNUSED(pKeyArgs);
    MOC_UNUSED(pEstTapContext);
    MSTATUS status = OK;
    ubyte *pReadKeyBlob = NULL;
    ubyte4 readKeyBlobLen = 0;
    sbyte *pFileName = NULL;
    sbyte *pPemFileName = NULL;
#ifdef __ENABLE_DIGICERT_EST_TAP_PEM_FILE__
    sbyte *pTapPemFileName = NULL;
    ubyte4 tapPemFileNameLen = 0;
#endif
    ubyte4 fileNameLen = 0;
    ubyte4 keyType = akt_rsa;
    sbyte *pKeyPath = NULL;
    sbyte *pFullPathR = NULL;
    sbyte *pFullPathPemR = NULL;
    sbyte *pFullPathW = NULL;
    sbyte *pFullPathPemW = NULL;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    char *pCertPath = NULL;
    ubyte *pCertFileName = NULL;
    ubyte *pFullPath = NULL;
    ubyte *pContents = NULL;
    ubyte4 contentsLen = 0;
    ubyte *pSerializedPemKey = NULL;
    ubyte4 serializedPemKeyLen = 0;
    AsymmetricKey asymKey = {0};
    RSAKey *pRsaKey = NULL;
    ECCKey *pEccKey = NULL;
    edECCKey *pEdEccKey = NULL;
    ubyte4 getKeySize = keySize;
    MRsaKeyTemplate rsaTemplate = { 0 };
    byteBoolean foundOldKey = TRUE;

    /* Extra 4 bytes to account for the .der or .pem extension */
    fileNameLen = keyAliasLen + 4;

    if (OK > (status = DIGI_MALLOC((void**)&pFileName, fileNameLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MALLOC((void**)&pPemFileName, fileNameLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pFileName, 0x00, fileNameLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pPemFileName, 0x00, fileNameLen + 1)))
    {
        goto exit;
    }
    DIGI_STRCAT(pFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pPemFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pFileName, (const sbyte *)ESTC_EXT_DER);
    DIGI_STRCAT(pPemFileName, (const sbyte *)ESTC_EXT_PEM);
    (pFileName)[fileNameLen] = '\0';
    (pPemFileName)[fileNameLen] = '\0';

#ifdef __ENABLE_DIGICERT_EST_TAP_PEM_FILE__
    tapPemFileNameLen = keyAliasLen + DIGI_STRLEN((sbyte *) ESTC_EXT_TAPKEY_PEM);

    if (OK > (status = DIGI_CALLOC((void**)&pTapPemFileName, 1, tapPemFileNameLen + 1)))
    {
        goto exit;
    }
    DIGI_STRCAT(pTapPemFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pTapPemFileName, (const sbyte *)ESTC_EXT_TAPKEY_PEM);
    (pTapPemFileName)[tapPemFileNameLen] = '\0';
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
    if (pKeyArgs->gTap)
        keyType = akt_tap_rsa;
#endif

    pKeyPath = (sbyte*)EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, KEYS_PKI_COMPONENT);
    if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
    {
        keyType = akt_ecc;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
            keyType = akt_tap_ecc;
#endif
    }
    else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_EDDSA) == 0)
    {
        keyType = akt_ecc_ed;
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
        if (pKeyArgs->gTap)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }
#elif !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
        {
            keyType = akt_tap_ecc;
        }
#endif
#endif
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_QS) == 0)
    {
        keyType = akt_qs;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
            keyType = akt_tap_qs;
#endif
    }
#endif

    /* Below logic -
       Check if .der file exists. if exists get the keyblob.
       else check if .pem file exists. if exists get the keyblob and write to .der file.
       else creates both .der and .pem files and get the keyblob.
     */
    if (OK > (status = DIGICERT_readFile(
                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                        (char **)&pFullPathR), &pReadKeyBlob, &readKeyBlobLen)))
    {/*.der file not exists */
        ubyte4 keyContentLen;
        ubyte *pKeyContent = NULL;

        /* Check for .pem file */
        if (OK > (status = DIGICERT_readFile(
                        EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                            (char **)&pFullPathPemR), &pKeyContent, &keyContentLen)))

        { /* No PEM file also found, new Key to be generated */
           /* .pem or .der files not found. generate a new key and convert it
              to .pem and .der files */
            foundOldKey = FALSE;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            if (pKeyArgs->gTap)
            {
                ubyte *pKeyData = NULL;
                ubyte4 keyDataLen = 0;
                sbyte *pTapKeyBinFileName = NULL;
                sbyte *pFullPathbinW = NULL;
                AsymmetricKey tapAsymKey = { 0 };
                TAP_Key *pTapKey = NULL;
                ubyte *pBlob = NULL;
                ubyte4 blobLen = 0;

                ubyte *pSerializedPri = NULL;
                ubyte4 serializedPriLen = 0;

                if (OK != (status = TRUSTEDGE_EST_createTapAsymKey(pEstArgs, pKeyArgs, &tapAsymKey, pKeyType, keySize, (KeyGenTapArgs *)pEstTapContext)))
                {
                    verbosePrintError("Unable to create TAP asymmetric key.", status);
                    goto exit_tap_gen;
                }

                /*Serialize the key */
                /* Write out the TAP key in PKCS8 format here. TAP keys
                * ignore the PKCS8 password argument. */
                if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &tapAsymKey, privateKeyInfoDer, &pKeyBlob, &keyBlobLen)))
                {

                    verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                    goto exit_tap_gen;
                }

                /* Write key to file */
                if ( OK > ( status = DIGICERT_writeFile(
                                EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                    (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
                {
                    verbosePrintStringError("Unable to write DER-formatted TAP key to file", pFullPathW);
                    verbosePrintError("Unable to write DER-formatted TAP key to file.", status);
                    goto exit_tap_gen;
                }

                /* Serialize to PEM Format */
#ifdef __ENABLE_DIGICERT_EST_TAP_PEM_FILE__
                /* Create TAP PEM key with TAP PEM header */
                status = BASE64_makePemMessageAlloc(
                    MOC_PEM_TYPE_PRI_TAP_KEY, pKeyBlob, keyBlobLen,
                    &pSerializedPri, &serializedPriLen);
                if (OK > status)
                {
                    verbosePrintError("Unable to create PEM TAP key with TAP header format.", status);
                    goto exit_tap_gen;
                }

                if (OK > ( status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapPemFileName, (char **)&pFullPathPemW),
                                pSerializedPri, serializedPriLen)))
                {
                    verbosePrintError("Unable to write PEM-formatted TAP key to file.", status);
                    goto exit_tap_gen;
                }
                DIGI_FREE((void **) &pFullPathPemW);

                if (pSerializedPri != NULL && (OK != (status = DIGI_MEMSET_FREE ((ubyte **)&pSerializedPri, serializedPriLen))))
                {
                    verbosePrintError("Unable to free TAP key serialized data.", status);
                    goto exit_tap_gen;
                }
#endif /* __ENABLE_DIGICERT_EST_TAP_PEM_FILE__ */

                if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &tapAsymKey, privateKeyPem, &pSerializedPri, &serializedPriLen)))
                {
                    verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                    goto exit_tap_gen;
                }

                /* Write out the TAP key in PKCS8 format here. TAP keys
                    * ignore the PKCS8 password argument. */
                if (OK > ( status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName, (char **)&pFullPathPemW),
                                pSerializedPri, serializedPriLen)))
                {
                    verbosePrintError("Unable to write PEM-formatted TAP key to file.", status);
                    goto exit_tap_gen;
                }

                /* Write TAP key in BIN format */
                status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx)
                    &tapAsymKey, mocanaBlobVersion2, &pKeyData,
                    &keyDataLen);
                if (OK != status)
                {
                    verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                    goto exit_tap_gen;
                }

                /* Write private key to file */
                if (OK > (status = DIGI_MALLOC((void**)&pTapKeyBinFileName, (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                {
                    goto exit_tap_gen;
                }

                if (OK > (status = DIGI_MEMSET((ubyte*)pTapKeyBinFileName, 0x00,
                                                (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                {
                    goto exit_tap_gen;
                }
                DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)pKeyAlias);

                DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)ESTC_EXT_TAPKEY);
                (pTapKeyBinFileName)[(keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY))] = '\0';
                if(akt_tap_ecc == keyType)
                {
                    pBlob = pKeyData + MOC_ECC_TAP_BLOB_START_LEN;
                    blobLen = keyDataLen - MOC_ECC_TAP_BLOB_START_LEN;
                }
#ifdef __ENABLE_DIGICERT_PQC__
                else if (akt_tap_qs == keyType)
                {
                    pBlob = pKeyData + MOC_QS_TAP_BLOB_START_LEN;
                    blobLen = keyDataLen - MOC_QS_TAP_BLOB_START_LEN;
                }
#endif
                else
                {
                    pBlob = pKeyData + MOC_RSA_TAP_BLOB_START_LEN;
                    blobLen = keyDataLen - MOC_RSA_TAP_BLOB_START_LEN;
                }

                status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapKeyBinFileName,
                                    (char **)&pFullPathbinW), pBlob, blobLen);
                if (OK != status)
                {
                    verbosePrintStringError("Unable to write binary format TAP key to file", pFullPathbinW);
                    verbosePrintError("Unable to write binary format TAP key to file.", status);
                    goto exit_tap_gen;
                }

                if (FALSE == pEstArgs->tapKeyPrimary)
                {
                    status = TRUSTEDGE_utilsWriteSMPBlob(
                        pKeyPath, pKeyAlias, &tapAsymKey,
                        KEY_FORMAT_TAP_PRIVATE_BLOB | KEY_FORMAT_TAP_PUBLIC_BLOB);
                    if (OK != status)
                    {
                        verbosePrintError("Unable to write TAP key to keystore.", status);
                        goto exit_tap_gen;
                    }
                }

exit_tap_gen:
                if (OK == CRYPTO_INTERFACE_getTapKey(&tapAsymKey, &pTapKey))
                {
                    (void) TAP_unloadKey(pTapKey, NULL);
                }

                (void) CRYPTO_uninitAsymmetricKey(&tapAsymKey, NULL);

                if (NULL != pTapKeyBinFileName)
                    (void) DIGI_FREE((void **)&pTapKeyBinFileName);

                if (NULL != pFullPathbinW)
                    (void) DIGI_FREE((void **)&pFullPathbinW);

                if (NULL != pKeyData)
                    (void) DIGI_FREE((void **)&pKeyData);

                if (NULL != pSerializedPri)
                    (void) DIGI_MEMSET_FREE(&pSerializedPri, serializedPriLen);

                if (OK != status)
                    goto exit;
            }
            else
#endif
            {

#ifdef __ENABLE_DIGICERT_TEE__
                /* For secure storage, before generating a key, make sure we have a keyHandle */
                if (pEstArgs->useTEE && (NULL == pEstArgs->tapKeyHandle.pBuffer || 0 == pEstArgs->tapKeyHandle.bufferLen))
                {
                    status = ERR_INVALID_INPUT;
                    verbosePrintError("ERROR: Must provide key handle for generating a new key with source TEE.", status);
                    goto exit;
                }
#endif
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
                if (pEstArgs->useNanoRoot)
                {
                    sbyte *pTapKeyBinFileName = NULL;
                    sbyte *pFullPathbinW = NULL;
                    AsymmetricKey tapAsymKey = { 0 };
                    ubyte *pBlob = NULL;
                    ubyte4 blobLen = 0;

                    /* For nanoroot, before obtaining a key, make sure we have a keyHandle */
                    if (NULL == pEstArgs->tapKeyHandle.pBuffer || 0 == pEstArgs->tapKeyHandle.bufferLen)
                    {
                        status = ERR_INVALID_INPUT;
                        verbosePrintError("ERROR: Must provide key handle for generating a new key with source NANOROOT.", status);
                        goto exit_nanoroot_gen;
                    }

                    /* No key is actually generated, just serialize the id to PEM */
                    status = CRYPTO_serializeKeyId(pEstArgs->tapKeyHandle.pBuffer, pEstArgs->tapKeyHandle.bufferLen, NanoROOTTOKEN_ID,
                            privateKeyPem, &pSerializedPemKey, &serializedPemKeyLen);
                    if (OK != status)
                    {
                        verbosePrintError("ERROR: Unable to PEM serialize ID for the new key with source NANOROOT.", status);
                        goto exit_nanoroot_gen;
                    }

                    status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                        (char **)&pFullPathPemW), pSerializedPemKey, serializedPemKeyLen);
                    if (OK != status)
                    {
                        goto exit_nanoroot_gen;
                    }

                    /* Write TAP key in BIN format, we need to deserialize it first */
                    status = CRYPTO_deserializeAsymKey (pSerializedPemKey, serializedPemKeyLen, NULL, &tapAsymKey);
                    if (OK != status)
                    {
                        verbosePrintError("Unable to deserialize TAP asymmetric key.", status);
                        goto exit_nanoroot_gen;
                    }

                    status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx)
                        &tapAsymKey, mocanaBlobVersion2, &pKeyBlob,
                        &keyBlobLen);
                    if (OK != status)
                    {
                        verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                        goto exit_nanoroot_gen;
                    }

                    if (OK > (status = DIGI_MALLOC((void**)&pTapKeyBinFileName, (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                    {
                        goto exit_nanoroot_gen;
                    }

                    if (OK > (status = DIGI_MEMSET((ubyte*)pTapKeyBinFileName, 0x00,
                                                    (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                    {
                        goto exit_nanoroot_gen;
                    }
                    DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)pKeyAlias);

                    DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)ESTC_EXT_TAPKEY);
                    (pTapKeyBinFileName)[(keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY))] = '\0';
                    if(akt_tap_ecc == keyType)
                    {
                        pBlob = pKeyBlob + MOC_ECC_TAP_BLOB_START_LEN;
                        blobLen = keyBlobLen - MOC_ECC_TAP_BLOB_START_LEN;
                    }
#ifdef __ENABLE_DIGICERT_PQC__
                    else if (akt_tap_qs == keyType)
                    {
                        pBlob = pKeyBlob + MOC_QS_TAP_BLOB_START_LEN;
                        blobLen = keyBlobLen - MOC_QS_TAP_BLOB_START_LEN;
                    }
#endif
                    else
                    {
                        pBlob = pKeyBlob + MOC_RSA_TAP_BLOB_START_LEN;
                        blobLen = keyBlobLen - MOC_RSA_TAP_BLOB_START_LEN;
                    }

                    status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapKeyBinFileName,
                                        (char **)&pFullPathbinW), pBlob, blobLen);
                    if (OK != status)
                    {
                        verbosePrintStringError("Unable to write binary format TAP key to file", pFullPathbinW);
                        verbosePrintError("Unable to write binary format TAP key to file.", status);
                        goto exit_nanoroot_gen;
                    }
                    
exit_nanoroot_gen:

                    (void) CRYPTO_uninitAsymmetricKey(&tapAsymKey, NULL);

                    if (NULL != pTapKeyBinFileName)
                        (void) DIGI_FREE((void **)&pTapKeyBinFileName);

                    if (NULL != pFullPathbinW)
                        (void) DIGI_FREE((void **)&pFullPathbinW);

                    if (OK != status)
                        goto exit;
                }
                else
#endif
                {
#ifdef __ENABLE_DIGICERT_PQC__
                    if (akt_qs == keyType)
                    {
                        if (OK > (status = CA_MGMT_generateNakedKeyPQC(keyType, keySize, pKeyArgs->gQsAlg, &pKeyBlob, &keyBlobLen)))
                        {
                            verbosePrintError("Unable to generate new QS key.", status);
                            goto exit;
                        }
                    }
                    else
#endif
                    {
                        if (OK > (status = CA_MGMT_generateNakedKey(keyType, keySize, &pKeyBlob, &keyBlobLen)))
                        {
                            verbosePrintError("Unable to generate new key.", status);
                            goto exit;
                        }
                    }

                    /* Only write out Mocana key blob if the caller does not want
                     * a password protected key file (and we are not TEE)*/
#ifdef __ENABLE_DIGICERT_TEE__
                    if (NULL == pEstArgs->pPkcs8Pw && !pEstArgs->useTEE)
#else
                    if (NULL == pEstArgs->pPkcs8Pw)
#endif
                    {
                        if ( OK > ( status = DIGICERT_writeFile(
                                        EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                            (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
                        {
                            verbosePrintStringError("Unable to write key data to file", pFullPathW);
                            verbosePrintError("Unable to write key data to file.", status);
                            goto exit;
                        }
                    }
                    /* Convert pem key to keyblob and write to the keystore. */

                    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
                    {
                        goto exit;
                    }

                    if (OK > (status = KEYBLOB_extractKeyBlobEx(pKeyBlob, keyBlobLen,&asymKey)))
                    {
                        goto exit;
                    }

                    /* Serialize into PEM Format */
                    if (NULL != pEstArgs->pPkcs8Pw)
                    {
#ifdef __ENABLE_DIGICERT_TEE__
                        if (pEstArgs->useTEE)
                        {
                            status = ERR_NOT_IMPLEMENTED;
                            goto exit;
                        }
#endif
                        status = PKCS8_encodePrivateKeyPEM(
                            g_pRandomContext, pKeyBlob, keyBlobLen,
                            pEstArgs->pkcs8EncType, PKCS8_PrfType_undefined /* uses default */,
                            (ubyte *)pEstArgs->pPkcs8Pw, DIGI_STRLEN(pEstArgs->pPkcs8Pw),
                            &pSerializedPemKey, &serializedPemKeyLen);
                    }
                    else
                    {
#ifdef __ENABLE_DIGICERT_TEE__
                        if (pEstArgs->useTEE)
                        {
                            status = CRYPTO_serializeAsymKeyToStorage(MOC_ASYM(gHwAccelCtx) &asymKey,
                                privateKeyPem, pEstArgs->tapKeyHandle.pBuffer, pEstArgs->tapKeyHandle.bufferLen, TEE_SECURE_STORAGE,
                                &pSerializedPemKey, &serializedPemKeyLen);
                        }
                        else
#endif
                        {
                            status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx)
                                &asymKey, privateKeyPem, &pSerializedPemKey,
                                &serializedPemKeyLen);
                        }
                    }
                    if (OK != status)
                    {
                        goto exit;
                    }

                    if (OK > ( status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                                        (char **)&pFullPathPemW),
                                    pSerializedPemKey,
                                    serializedPemKeyLen)))
                    {
                        goto exit;
                    }
                    if (OK != (status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL)))
                    {
                        goto exit;
                    }
                }
            }
        } /* .pem or .der files does not exists */
        else
        { /*.pem file exists */

            /* .pem file exists. Get the keyblob and write to .der file */
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            if (pKeyArgs->gTap)
            {
                ubyte *pSerializedPri = NULL;
                ubyte4 serializedPriLen = 0;
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx) pKeyContent, keyContentLen, NULL, &asymKey);
                if (status < OK)
                    goto exit_tap_pem;
                /*Serialize the key */
                /* Write out the TAP key in PKCS8 format here. TAP keys
                 * ignore the PKCS8 password argument. */
                if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &asymKey, privateKeyInfoDer, &pSerializedPri, &serializedPriLen)))
                {

                    verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                    goto exit_tap_pem;
                }
                
                /* Write key to file */
                pKeyBlob = pSerializedPri; pSerializedPri = NULL;
                keyBlobLen = serializedPriLen; 
                if ( OK > ( status = DIGICERT_writeFile(
                                EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                    (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
                {
                    verbosePrintStringError("Unable to write TAP key data to file", pFullPathW);
                    verbosePrintError("Unable to write TAP key data to file.", status);
                    goto exit_tap_pem;
                }

exit_tap_pem:
                (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
                
                if (NULL != pKeyContent)
                    (void) DIGI_FREE((void**)&pKeyContent);

                if (NULL != pSerializedPri)
                    (void) DIGI_FREE((void**)&pSerializedPri);

                if (OK != status)
                    goto exit;
            }
            else
#endif
            {
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
                if (pEstArgs->useNanoRoot)
                {
                    sbyte *pTapKeyBinFileName = NULL;
                    sbyte *pFullPathbinW = NULL;
                    AsymmetricKey tapAsymKey = { 0 };
                    ubyte *pBlob = NULL;
                    ubyte4 blobLen = 0;

                    /* Write TAP key in BIN format, we need to deserialize it first */
                    status = CRYPTO_deserializeAsymKey (pKeyContent, keyContentLen, NULL, &tapAsymKey);
                    if (OK != status)
                    {
                        verbosePrintError("Unable to deserialize TAP asymmetric key.", status);
                        goto exit_nanoroot_pem;
                    }

                    /* validate we have the correct keytype */
                    if (keyType != tapAsymKey.type)
                    {
                        CRYPTO_uninitAsymmetricKey(&tapAsymKey, NULL);
                        status = ERR_KEY_TYPE_MISMATCH;
                        verbosePrintError("Existing key type and keyType argument not matching.", status);
                        goto exit_nanoroot_pem;
                    }
                    /* previous TAP flow had no keysize validation, need it here? */

                    status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx)
                        &tapAsymKey, mocanaBlobVersion2, &pKeyBlob,
                        &keyBlobLen);
                    if (OK != status)
                    {
                        verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                        goto exit_nanoroot_pem;
                    }

                    if (OK > (status = DIGI_MALLOC((void**)&pTapKeyBinFileName, (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                    {
                        goto exit_nanoroot_pem;
                    }

                    if (OK > (status = DIGI_MEMSET((ubyte*)pTapKeyBinFileName, 0x00,
                                                    (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                    {
                        goto exit_nanoroot_pem;
                    }
                    DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)pKeyAlias);

                    DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)ESTC_EXT_TAPKEY);
                    (pTapKeyBinFileName)[(keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY))] = '\0';
                    if(akt_tap_ecc == keyType)
                    {
                        pBlob = pKeyBlob + MOC_ECC_TAP_BLOB_START_LEN;
                        blobLen = keyBlobLen - MOC_ECC_TAP_BLOB_START_LEN;
                    }
#ifdef __ENABLE_DIGICERT_PQC__
                    else if (akt_tap_qs == keyType)
                    {
                        pBlob = pKeyBlob + MOC_QS_TAP_BLOB_START_LEN;
                        blobLen = keyBlobLen - MOC_QS_TAP_BLOB_START_LEN;
                    }
#endif
                    else
                    {
                        pBlob = pKeyBlob + MOC_RSA_TAP_BLOB_START_LEN;
                        blobLen = keyBlobLen - MOC_RSA_TAP_BLOB_START_LEN;
                    }

                    status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapKeyBinFileName,
                                        (char **)&pFullPathbinW), pBlob, blobLen);
                    if (OK != status)
                    {
                        verbosePrintStringError("Unable to write binary format TAP key to file", pFullPathbinW);
                        verbosePrintError("Unable to write binary format TAP key to file.", status);
                        goto exit_nanoroot_pem;
                    }
                    
exit_nanoroot_pem:

                    (void) CRYPTO_uninitAsymmetricKey(&tapAsymKey, NULL);

                    if (NULL != pTapKeyBinFileName)
                        (void) DIGI_FREE((void **)&pTapKeyBinFileName);

                    if (NULL != pFullPathbinW)
                        (void) DIGI_FREE((void **)&pFullPathbinW);

                    if (NULL != pKeyContent)
                        (void) DIGI_FREE((void**)&pKeyContent);    
                    
                    if (OK != status)
                        goto exit;
                }
                else
#endif
                {
                    /* TPM1.2 and SW Key */
                    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
                    {
                        goto exit_pem;
                    }
                    /* Pem file exists - deserialize to keyblob write the Keyblob file */
                    status = TRUSTEDGE_EST_deserializeAsymKey(
                        MOC_ASYM(gHwAccelCtx) pKeyContent, keyContentLen,
                        (ubyte *)pEstArgs->pPkcs8Pw, pEstArgs->pPkcs8Pw ? DIGI_STRLEN(pEstArgs->pPkcs8Pw) : 0,
                        &asymKey);
                    if (OK != status)
                    {
                        goto exit_pem;
                    }
                    if (OK > (status = KEYBLOB_makeKeyBlobEx(&asymKey, &pKeyBlob, &keyBlobLen)))
                    {
                        goto exit_pem;
                    }

                    /* Only write out key blob if file is not password protected (and not TEE nor NanoRoot) */
#ifdef __ENABLE_DIGICERT_TEE__
                    if (NULL == pEstArgs->pPkcs8Pw && !pEstArgs->useTEE)
#else
                    if (NULL == pEstArgs->pPkcs8Pw)
#endif
                    {
                        if ( OK > ( status = DIGICERT_writeFile(
                                        EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                            (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
                        {
                            verbosePrintStringError("Unable to write key data to file", pFullPathW);
                            verbosePrintError("Unable to write key data to file.", status);
                            goto exit_pem;
                        }
                    }
exit_pem:
                    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

                    if (NULL != pKeyContent)
                        (void) DIGI_FREE((void**) &pKeyContent);

                    if (OK != status)
                        goto exit;
                }
            }
        }/*Pem file exists */

    }/*.der file does not exits */
    else
    { /* .der file exists. Read KeyBlob file */
#ifdef __ENABLE_DIGICERT_TEE__
        if (pEstArgs->useTEE) /* For TEE we just use PEM format, pKeyBlob is the (software key) Mocana format */
        {
            status = ERR_NOT_IMPLEMENTED;
            verbosePrintError("DER format TEE keys not supported.", status);
            goto exit;
        }
        else
#elif __ENABLE_DIGICERT_SMP_NANOROOT__
        if (pEstArgs->useNanoRoot) /* For NanoROOT we just use PEM and .bin formats, pKeyBlob is the Mocana format */
        {
            status = ERR_NOT_IMPLEMENTED;
            verbosePrintError("DER format NanoROOT keys not supported.", status);
            goto exit;
        }
        else
#endif
        {
            pKeyBlob = pReadKeyBlob;
            keyBlobLen = readKeyBlobLen;
        }
    }

#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
    if (!pEstArgs->useNanoRoot)  /* For NanoROOT we do validations above so that we don't need to re-deserialize (ie re-init) */
#endif
    {
        if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
        {
            goto exit;
        }
        /* Pem file exists - deserialize to keyblob write the Keyblob file */
        status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
            pKeyBlob, keyBlobLen, NULL, &asymKey);
        if (OK != status)
        {
            goto exit;
        }

        if (keyType != asymKey.type)
        {
            status = ERR_KEY_TYPE_MISMATCH;
            verbosePrintError("Existing key type and keyType argument not matching.", status);
            goto exit;
        }
        else if (TRUE == foundOldKey)
        {
            if (keyType == akt_rsa)
            {
                pRsaKey = asymKey.key.pRSA;
                if (OK != RSA_getKeyParametersAlloc(pRsaKey, &rsaTemplate, MOC_GET_PUBLIC_KEY_DATA))
                {
                    verbosePrintError("Failed to get RSA public key length.", status);
                    goto exit;
                }

                getKeySize = rsaTemplate.nLen * 8;
            }
            else if (keyType == akt_ecc)
            {
                pEccKey = asymKey.key.pECC;
                if (NULL == pEccKey->pCurve || NULL == pEccKey->pCurve->pPF)
                {
                    status = ERR_NULL_POINTER;
                    goto exit;
                }

                getKeySize = asymKey.key.pECC->pCurve->pPF->numBits;
            }
            else if (keyType == akt_ecc_ed)
            {
                pEdEccKey = (edECCKey *)asymKey.key.pECC->pEdECCKey;
                if (NULL == pEdEccKey)
                {
                    goto exit;
                }

                if (curveEd25519 == pEdEccKey->curve)
                {
                    getKeySize = 255;
                }
                else if (curveEd448 == pEdEccKey->curve)
                {
                    getKeySize = 448;
                }
                else
                {
                    verbosePrintError("Unsupported Ed curve key.", status);
                    goto exit;
                }
            }

            if (getKeySize != keySize)
            {
                status = ERR_KEY_TYPE_MISMATCH;
                verbosePrintError("Existing key size and keySize argument not matching.", status);
                goto exit;
            }
        }
    }

    /*
       - Incase pEstArgs->pKeyAlias matches pEstArgs->pKeyAlias2(rekey), then store only the key.
       - Check if the scenario is RENEW or REKEY.
         - Yes RENEW or REKEY scenario - Then check if certificate with mentioned keyAlias is present or not.
           - Yes if either of the certifiders(.der/.pem) exists - Store the key along with certificate in certStore.
           - No None of the certificates not present - Throw error certificate not found.
         - NO its not RENEW or REKEY scenario - Simply store only the key in the certstore.
    */
    if ((DIGI_STRCMP((const sbyte*)pEstArgs->pKeyAlias, (const sbyte*)pKeyAlias) == 0) &&
        (((NULL != pEstArgs->fullCmcReq.pFullCmcReqType) &&
          ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
          (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))) ||
         ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) &&
          (NULL != pEstArgs->pKeyAlias2))))
    {
        if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, keyAliasLen + 5)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, keyAliasLen + 5)))
        {
            goto exit;
        }
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pKeyAlias);
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_DER);

        pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);

        if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                            (char **)&pFullPath), &pContents, &contentsLen)))
        {/*Certificate(.der) not found. check for .pem */
            ubyte *pPemCert = NULL;
            ubyte4 pemCertLen = 0;
            if (pCertFileName)
                DIGI_FREE((void **)&pCertFileName);
            if (pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if (pFullPath)
                DIGI_FREE((void **)&pFullPath);
            if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, keyAliasLen + 5)))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, keyAliasLen + 5)))
            {
                goto exit;
            }
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pKeyAlias);
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_PEM);
            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);

            if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                                (char **)&pFullPath), &pPemCert, &pemCertLen)))
            {/*.pem file does not exists. Generate a new certificate */
                verbosePrintError("Certificate with keyAlias name not found.", status);
                goto exit;
            }
            else
            {
                if (OK > (status = CA_MGMT_decodeCertificate(pPemCert, pemCertLen, &pContents, &contentsLen)))
                {
                    (void) DIGI_FREE((void **)&pPemCert);
                    goto exit;
                }

            }
            if (NULL != pPemCert)
                (void) DIGI_FREE((void **)&pPemCert);
        }
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
        if (pKeyArgs->gTap)
        {
            if (OK != (status = TRUSTEDGE_EST_storeMocKeyInCertstore(pKeyBlob, keyBlobLen, pKeyAlias, keyAliasLen, pContents, contentsLen)))
            {
                goto exit;
            }
        }
        else
#endif
        {
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
            if (pEstArgs->useNanoRoot)
            {
                /* Add the KeyBlob to the CERT STORE */
                if (NULL == pContents)
                {
                    if (OK != (status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                                                    pKeyAlias, keyAliasLen,
                                                                    pKeyBlob, keyBlobLen)))
                    {
                        verbosePrintError("Unable to add naked key to certstore.", status);
                        goto exit;
                    }
                }
                else
                {
                    if (OK > (status = CERT_STORE_addIdentityEx(pCertStore,
                                                                pKeyAlias, keyAliasLen,
                                                                pContents, contentsLen,
                                                                pKeyBlob, keyBlobLen)))
                    {
                        goto exit;
                    }
                }                
            }
            else
#endif
            {
                if (OK > (status = CERT_STORE_addIdentityEx(pCertStore,
                                pKeyAlias, keyAliasLen,
                                pContents, contentsLen,
                                pKeyBlob, keyBlobLen)))
                {
#if (defined(__ENABLE_DIGICERT_TAP__))
                    verbosePrintNL(MSG_LOG_INFO, "Failed to load the keys - please cleanup hardware keys from keystore if any");
#endif
                    verbosePrintError("Unable to load the keys. Please cleanup hardware keys from keystore if any.", status);
                    goto exit;
                }
            }
        }
    }
    else
    {
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
        if (pKeyArgs->gTap)
        {
            if (OK != (status = TRUSTEDGE_EST_storeMocKeyInCertstore(pKeyBlob, keyBlobLen, pKeyAlias, keyAliasLen, pContents, contentsLen)))
            {
                goto exit;
            }
        }
        else
#endif
        {
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
            if (pEstArgs->useNanoRoot)
            {
                /* Add the KeyBlob to the CERT STORE */
                if (OK != (status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                                                     pKeyAlias, keyAliasLen,
                                                                     pKeyBlob, keyBlobLen)))
                {
                    verbosePrintError("Unable to add naked key to certstore.", status);
                    goto exit;
                }               
            }
            else
#endif
            {
                /*Add the key to the EST Client Cert Store*/
                if(OK > (status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                pKeyAlias, keyAliasLen,
                                pKeyBlob, keyBlobLen)))
                {
#if (defined(__ENABLE_DIGICERT_TAP__))
                    verbosePrintNL(MSG_LOG_INFO, "Failed to load the keys - please cleanup hardware keys from keystore if any");
#endif
                    verbosePrintError("Unable to load the keys. Please cleanup hardware keys from keystore if any.", status);
                    goto exit;
                }
            }
        }
    }

exit:

    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    if (pKeyBlob)
        DIGI_FREE((void **)&pKeyBlob);
    if (pKeyPath)
        DIGI_FREE((void **)&pKeyPath);
    if (pFullPathR)
        DIGI_FREE((void **)&pFullPathR);
    if (pFullPathW)
        DIGI_FREE((void **)&pFullPathW);
    if (pFullPathPemR)
        DIGI_FREE((void **)&pFullPathPemR);
    if (pFullPathPemW)
        DIGI_FREE((void **)&pFullPathPemW);
    if (pFileName)
        DIGI_FREE((void **)&pFileName);
    if (pPemFileName)
        DIGI_FREE((void **)&pPemFileName);
    if(pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if(pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pCertFileName)
        DIGI_FREE((void **)&pCertFileName);
    if (pContents)
        DIGI_FREE((void **)&pContents);
    if (pSerializedPemKey)
        DIGI_FREE((void**)&pSerializedPemKey);
    if (pRsaKey)
        RSA_freeKeyTemplate(pRsaKey, &rsaTemplate);

    return status;
}

/* ------------------------------------------------------------- */

static sbyte4 TRUSTEDGE_EST_addTLSCert(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs, struct certStore* pCertStore)
{
    certDescriptor certDesc = {0};
    SizedBuffer *pCertificates = NULL;
    SizedBuffer certificate;
    ubyte4 certCount = 0;
    MSTATUS status;
    char *pCertPath = NULL;
    char *pFullPath = NULL;
    ubyte *pCertFileName = NULL;
    AsymmetricKey asymKey = {0};
    ubyte4 contentsLen;
    ubyte *pContents = NULL;
    ubyte *pPemCert = NULL;
    ubyte4 pemCertLen = 0;
    ubyte4 isPEMFile = 1;

    if (pEstArgs->pTlsCert == NULL)
    {
        status = ERR_NULL_POINTER;
        verbosePrintError("Please specify TLS Certificate alias.", status);
        goto exit;
    }

    /* Get TLS Certificate - Find cert file name using its alias */
    /* Create CertFile Name using alias */
    /* First Check for DER cert existance */
    if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, DIGI_STRLEN(pEstArgs->pTlsCert) + 5)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, DIGI_STRLEN(pEstArgs->pTlsCert) + 5)))
    {
        goto exit;
    }
    DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pEstArgs->pTlsCert);
    DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_PEM);

    pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, CERTS_PKI_COMPONENT);
    if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pCertFileName, &pFullPath), &pPemCert, &pemCertLen)))
    {
        /* PEM file not found, so check for DER */
        isPEMFile = 0;
        if (pCertFileName)
            DIGI_FREE((void **)&pCertFileName);
        if (pCertPath)
            DIGI_FREE((void **)&pCertPath);
        if (pFullPath)
            DIGI_FREE((void **)&pFullPath);
        if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, DIGI_STRLEN(pEstArgs->pTlsCert) + 5)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, DIGI_STRLEN(pEstArgs->pTlsCert) + 5)))
        {
            goto exit;
        }
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pEstArgs->pTlsCert);
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_DER);
        pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);
        if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                            (char **)&pFullPath), &certDesc.pCertificate, &certDesc.certLength)))
        {
            /* Given TLS Cert with alias not found */
            verbosePrintError("TLS Certificate with keyAlias name not found.", status);
            goto exit;
        }
    }
    else
    {
        if (OK > (status = CRYPTO_UTILS_readCertificates(MOC_ASYM(gHwAccelCtx)
            pPemCert, pemCertLen, &pCertificates, &certCount)))
        {
            verbosePrintError("Unable to parse PEM certificate(s).", status);
            goto exit;
        }
        if (pPemCert)
            DIGI_FREE((void **)&pPemCert);
    }

    if (pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);

    /* Get Key */
    /* Try with same file format of cert, if not exist then look for other format */
    pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, KEYS_PKI_COMPONENT);
    if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pCertFileName, &pFullPath), &pContents, &contentsLen)))
    {

        if (pCertFileName)
            DIGI_FREE((void **)&pCertFileName);
        if (pCertPath)
            DIGI_FREE((void **)&pCertPath);
        if (pFullPath)
            DIGI_FREE((void **)&pFullPath);

        if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, DIGI_STRLEN(pEstArgs->pTlsCert) + 5)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, DIGI_STRLEN(pEstArgs->pTlsCert) + 5)))
        {
            goto exit;
        }

        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pEstArgs->pTlsCert);
        if (isPEMFile == 1)
        {
            /* try for other format */
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_DER);
        }
        else
        {
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_PEM);
        }

        pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, KEYS_PKI_COMPONENT);
        if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                            (const char *)pCertFileName, &pFullPath), &pContents, &contentsLen)))
        {
            verbosePrintStringError("Unable to read TLS key file", (sbyte *)pFullPath);
            verbosePrintError("Unable to read TLS key file.", status);
            goto exit;
        }
    }
    if(pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if(pFullPath)
        DIGI_FREE((void **)&pFullPath);

#ifdef __ENABLE_DIGICERT_TAP__
    /* if we don't know the keySource apriori we then we'll retrieve it from the key itself */
    if (NULL == pEstArgs->pKeySource || 0 == DIGI_STRCMP((const sbyte *)pEstArgs->pKeySource, (const sbyte *)ESTC_DEF_KEYSOURCE))
    {
        byteBoolean isTap = FALSE;
        ubyte4 provider = 0;
        ubyte4 module = 0;

        /* see if it is a tap key and get the TAP provider and module from the key */
        status = CRYPTO_getKeyTapInfo(pContents, contentsLen, NULL, &isTap, &provider, &module);
        if (OK != status)
            goto exit;

        if (isTap)
        {
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
            pKeyArgs->gTapProvider = (ubyte2) provider;
#endif
            pKeyArgs->gModNum = (ubyte2) module;
        }
        /* not a tap key anyway, go on */
    }
#endif

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_EST_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
        pContents, contentsLen,
        (ubyte *)pEstArgs->pPkcs8Pw, pEstArgs->pPkcs8Pw ? DIGI_STRLEN(pEstArgs->pPkcs8Pw) : 0, &asymKey);
    if (OK != status)
    {
        verbosePrintError("Unable to deserialize TLS key.", status);
        goto exit;
    }

    /* Serialize the key */
    status = CRYPTO_serializeAsymKey(
        MOC_ASYM(gHwAccelCtx) &asymKey, mocanaBlobVersion2,
        &certDesc.pKeyBlob, &certDesc.keyBlobLength);
    if (OK != status)
    {
        verbosePrintError("Unable to serialize TLS key.", status);
        goto exit;
    }

    if (NULL != pCertificates)
    {
        status = CERT_STORE_addGenericIdentity (
            pCertStore, (ubyte *)pEstArgs->pTlsCert, DIGI_STRLEN(pEstArgs->pTlsCert), certDesc.pKeyBlob, certDesc.keyBlobLength,
            CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, pCertificates, certCount, NULL);
        if (OK != status)
        {
            myPrintError("TRUSTEDGE_EST_addTLSCert::CERT_STORE_addGenericIdentity::status ", status);
            goto exit;
        }
    }
    else
    {
        certificate.data = certDesc.pCertificate;
        certificate.length = certDesc.certLength;

        status = CERT_STORE_addGenericIdentity (
            pCertStore, (ubyte *)pEstArgs->pTlsCert, DIGI_STRLEN(pEstArgs->pTlsCert), certDesc.pKeyBlob, certDesc.keyBlobLength,
            CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, &certificate, 1, NULL);
        if (OK != status)
        {
            myPrintError("TRUSTEDGE_EST_addTLSCert::CERT_STORE_addGenericIdentity::status ", status);
            goto exit;
        }
    }

exit:
    if (pCertFileName)
        DIGI_FREE((void **)&pCertFileName);
    if(pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if(pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pContents)
        DIGI_FREE((void **)&pContents);
    if (pPemCert)
        DIGI_FREE((void **)&pPemCert);
    if (pCertificates)
        CRYPTO_UTILS_freeCertificates(&pCertificates, certCount);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

    return status;
}

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__

static sbyte4
myAlertCallback(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass)
{
    MOC_UNUSED(connectionInstance);


    myPrintError("Trustedge EST: AlertId: ", alertId);
    myPrintError("Trustedge EST: AlertClass: ", alertClass);

    return 0;
}

#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
static sbyte4
myOcspCallback(sbyte4 connectionInstance, intBoolean certStatus)
{
    MSTATUS status = OK;

    MOC_UNUSED(connectionInstance);

    if (pEstArgs->isOcspRequired)
    {
        verbosePrintString(MSG_LOG_INFO, "myOcspCallback::");
        if (TRUE == certStatus)
        {
            verbosePrintNL(MSG_LOG_INFO, "OCSP Extension Recieved");
            status = OK;
        }
        else
        {
            verbosePrintNL(MSG_LOG_INFO, "OCSP Extension Missing");
            status = ERR_OCSP;
        }
    }

    return status;
}
#endif


static MSTATUS TRUSTEDGE_EST_deleteFile(ubyte *pComponent, ubyte *pFile)
{
    MSTATUS status = OK;
    ubyte *pPath, *pCurFilePath;
    intBoolean fileExist;

    pPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, (char *) pComponent);
    pCurFilePath = (ubyte *) EST_CERT_UTIL_getFullPath(
        (char *) pPath, (char *) pFile, (char **) &pCurFilePath);

    /* Only delete the file if it exists.
     */
    status = DIGICERT_checkFile((char *) pCurFilePath, NULL, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        status = DIGICERT_deleteFile((char *) pCurFilePath);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:

    if (NULL != pPath)
    {
        FREE(pPath);
    }

    if (NULL != pCurFilePath)
    {
        FREE(pCurFilePath);
    }

    return status;
}

static MSTATUS TRUSTEDGE_EST_deleteFileByAlias(
    ubyte *pFile, ubyte4 baseLen, ubyte *pExt)
{
    MSTATUS status;

    status = DIGI_MEMCPY(
        pFile + baseLen, pExt, DIGI_STRLEN((sbyte *)pExt));
    if (OK != status)
    {
        goto exit;
    }
    pFile[baseLen + DIGI_STRLEN((sbyte *)pExt)] = '\0';

    status = TRUSTEDGE_EST_deleteFile((ubyte *)CERTS_PKI_COMPONENT, pFile);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFile((ubyte *)KEYS_PKI_COMPONENT, pFile);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static void TRUSTEDGE_EST_deleteCertsAndKeys(
    ubyte *pKeyAlias, ubyte4 keyAliasLen)
{
    MSTATUS status;
    ubyte *pCurFile = NULL;
    ubyte4 extLen;

    /* Get the largest extension length for the existing file.
     */
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Delete the files with the extension if they exist.
     */
    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PEM);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    return;
}

MOC_STATIC sbyte4
TRUSTEDGE_EST_initUpcallsAndCertStores(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs, void *pEstTapContext)
{
    certDescriptor certDesc = {0};
    certDescriptor skgCertDesc = {0};
    SizedBuffer skgCertificate;
    MSTATUS status = OK;

    char *pFullPath = NULL;
    char *pCertPath = NULL;
    ubyte *pPskSecret = NULL;
    ubyte4 pskSecretLen = 0;
    ubyte4 pskAliasLen = 0;
    ubyte4 keyAliasLen = 0;

    EST_CERT_UTIL_createPkiDB(pKeyArgs->gpKeyStorePath);
    pPkiDatabase = EST_CERT_UTIL_getPkiDBPtr();

    if (FALSE == pEstArgs->serviceCtx.reuseKey)
    {
        TRUSTEDGE_EST_deleteCertsAndKeys(pEstArgs->pKeyAlias, DIGI_STRLEN(pEstArgs->pKeyAlias));
    }

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    SSL_sslSettings()->funcPtrAlertCallback = myAlertCallback;
#endif
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    SSL_sslSettings()->funcPtrCertStatusCallback = myOcspCallback;
#endif

    HTTP_httpSettings()->funcPtrHttpTcpSend = TRUSTEDGE_EST_HttpTcpSend;
    HTTP_httpSettings()->funcPtrHttpTcpSend = TRUSTEDGE_EST_HttpSslSend;

    HTTP_httpSettings()->funcPtrRequestBodyCallback = TRUSTEDGE_EST_http_requestBodyCallback;
    HTTP_httpSettings()->funcPtrPasswordPrompt = TRUSTEDGE_EST_passwordPrompt;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = TRUSTEDGE_EST_http_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = TRUSTEDGE_EST_http_responseBodyCallback;

    if(!pCertStore)
    {
        if (OK > (status = CERT_STORE_createStore(&pCertStore)))
        {
            verbosePrintError("Unable to create certstore.", status);
            goto exit;
        }

        if (OK > (status = TRUSTEDGE_EST_constructCertStoreFromDir(pCertStore, NULL)))
        {
            verbosePrintError("Unable to load in CA certificates.", status);
        }
    }
    /* Don't create pEstArgs->pKeyAlias in case of cacerts and csrattrs request urls */
    if ((NULL == strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)) &&
        (NULL == strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD)) &&
        (NULL == strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD)) &&
        ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD)) ||
        (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) ||
        (NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD))))
    {
        keyAliasLen = DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias);
        if (NULL == strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD))
        {
            if (OK != (status = TRUSTEDGE_EST_loadCertsAndKeysIntoCertStore(pEstArgs, pKeyArgs, (ubyte*)pEstArgs->pKeyAlias, keyAliasLen,
                                                                            (ubyte*)pEstArgs->pKeyType, pEstArgs->usKeySize, pEstTapContext)))
            {
                verbosePrintError("Unable to load keyalias into certstore.", status);
                goto exit;
            }
        }
    }

    /* Create pEstArgs->pKeyAlias2 only in case of fullcmc rekey case or simplereenroll
     * rekey case */
    if ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
        ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) &&
         (NULL != pEstArgs->pKeyAlias2)))
    {
        keyAliasLen = DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias2);
        if (OK != (status = TRUSTEDGE_EST_loadCertsAndKeysIntoCertStore(pEstArgs, pKeyArgs, (ubyte*)pEstArgs->pKeyAlias2, keyAliasLen,
                                                                        (ubyte*)pEstArgs->pNewKeyType, pEstArgs->newKeySize, pEstTapContext)))
        {
            verbosePrintError("Unable to load re-key alias into certstore.", status);
            goto exit;
        }
    }

    /* If est_tls_cert enabled for Mutual Auth*/
    if (pEstArgs->pTlsCert)
    {
        if (OK > (status = TRUSTEDGE_EST_addTLSCert(pEstArgs, pKeyArgs, pCertStore)))
        {
            verbosePrintError("Unable to add TLS certificate into certstore.", status);
            goto exit;
        }
    }

    /* Load client cert, client key and psk only in case of serverkeygen */
    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)))
    {
        if(pEstArgs->pSkPskAlias)
        {
            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, PSK_PKI_COMPONENT);
            status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pEstArgs->pSkPskAlias, &pFullPath), &pPskSecret, &pskSecretLen);
            if (OK > status)
            {
                verbosePrintStringError("Unable to read PSK", (sbyte *)pFullPath);
                verbosePrintError("Unable to read PSK.", status);
                goto exit;
            }
            if(pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if(pFullPath)
                DIGI_FREE((void **)&pFullPath);

            pskAliasLen = DIGI_STRLEN((const sbyte *)pEstArgs->pSkPskAlias);
            while (pskAliasLen > 0 && pEstArgs->pSkPskAlias[pskAliasLen - 1] != '.')
            {
                pskAliasLen--;
            }
            if (pskAliasLen < 2)
            {
                status = ERR_BAD_LENGTH;
                verbosePrintStringError("Unable to get PSK alias", pEstArgs->pSkPskAlias);
                goto exit;
            }
            pskAliasLen--;

            if (OK > (status = CERT_STORE_addIdentityPSK(pCertStore, (ubyte*)pEstArgs->pSkPskAlias, pskAliasLen, NULL,
                            0, (ubyte*)pPskSecret, pskSecretLen)))
            {
                verbosePrintError("Unable to add PSK into certstore.", status);
                goto exit;
            }
        }
        else if(pEstArgs->pSkClntCert && pEstArgs->pSkClntKey)
        {
            DIGI_MEMSET((ubyte *)&skgCertificate, 0x00, sizeof(SizedBuffer));

            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, CERTS_PKI_COMPONENT);
            status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pEstArgs->pSkClntCert, &pFullPath), &skgCertDesc.pCertificate, &skgCertDesc.certLength);
            if (OK > status)
            {
                verbosePrintStringError("Unable to read est_skg_clientcert", (sbyte *)pFullPath);
                verbosePrintError("Unable to read est_skg_clientcert.", status);
                goto exit;
            }
            if(pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if(pFullPath)
                DIGI_FREE((void **)&pFullPath);

            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, KEYS_PKI_COMPONENT);
            status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pEstArgs->pSkClntKey, &pFullPath), &skgCertDesc.pKeyBlob, &skgCertDesc.keyBlobLength);
            if (OK > status)
            {
                verbosePrintStringError("Unable to read est_skg_clientkey", (sbyte *)pFullPath);
                verbosePrintError("Unable to read est_skg_clientkey.", status);
                goto exit;
            }
            if(pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if(pFullPath)
                DIGI_FREE((void **)&pFullPath);
            /* Check if the certificate or key is in PEM format if so convert it to decoded format */
            if (0 == DIGI_STRNICMP((sbyte*)ESTC_EXT_PEM, pEstArgs->pSkClntKey + DIGI_STRLEN(pEstArgs->pSkClntKey) - DIGI_STRLEN((sbyte*)ESTC_EXT_PEM),
                                  DIGI_STRLEN((sbyte*)ESTC_EXT_PEM)))
            {
                AsymmetricKey asymKey = {0};

                if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
                {
                    verbosePrintError("Unable to initialize asymmetric key.", status);
                    goto exit;
                }
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
                    skgCertDesc.pKeyBlob, skgCertDesc.keyBlobLength, NULL,
                    &asymKey);
                if (OK != status)
                {
                    verbosePrintError("Unable to deserialize est_skg_clientkey.", status);
                    goto exit;
                }

                pEstArgs->skKeyType = asymKey.type;

                DIGI_FREE((void**)&skgCertDesc.pKeyBlob);
                status = KEYBLOB_makeKeyBlobEx(&asymKey, &skgCertDesc.pKeyBlob, &skgCertDesc.keyBlobLength);
                CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
                if (OK != status)
                {
                    verbosePrintError("Unable to make est_skg_clientkey keyblob.", status);
                    goto exit;
                }
            }
            else
            {
                if (0 != DIGI_STRNICMP((sbyte*)ESTC_EXT_DER, pEstArgs->pSkClntKey + DIGI_STRLEN(pEstArgs->pSkClntKey) - DIGI_STRLEN((sbyte*)ESTC_EXT_DER),
                                      DIGI_STRLEN((sbyte*)ESTC_EXT_DER)))
                {
                    status = ERR_BAD_KEY;
                    verbosePrintError("Invalid est_skg_clientkey.", status);
                    goto exit;
                }
            }
            if (0 == DIGI_STRNICMP((sbyte*)ESTC_EXT_PEM, pEstArgs->pSkClntCert + DIGI_STRLEN(pEstArgs->pSkClntCert) - DIGI_STRLEN((sbyte*)ESTC_EXT_PEM),
                                  DIGI_STRLEN((sbyte*)ESTC_EXT_PEM)))
            {
                ubyte4 length = 0;
                /* PEM file deocde the content*/
                status = CA_MGMT_decodeCertificate(skgCertDesc.pCertificate, skgCertDesc.certLength,
                                        &skgCertificate.data, &length);
                skgCertificate.length = length;
                DIGI_FREE((void**)&skgCertDesc.pCertificate);
                if (OK != status)
                {
                    verbosePrintError("Unable to decode est_skg_clientcert.", status);
                    goto exit;
                }
                /* Assign the skgCertificate.data address to skgCertDesc.pCertificate so that it gets freed below. */
                skgCertDesc.pCertificate = skgCertificate.data;
            }
            else if (0 == DIGI_STRNICMP((sbyte*)ESTC_EXT_DER, pEstArgs->pSkClntCert + DIGI_STRLEN(pEstArgs->pSkClntCert) - DIGI_STRLEN((sbyte*)ESTC_EXT_DER),
                                       DIGI_STRLEN((sbyte*)ESTC_EXT_DER)))
            {
                skgCertificate.length = skgCertDesc.certLength;
                skgCertificate.data = skgCertDesc.pCertificate;
            }
            else
            {
                status = ERR_CERT;
                verbosePrintError("Invalid est_skg_clientcert.", status);
                goto exit;
            }

            status = CERT_STORE_addIdentityWithCertificateChainEx(pCertStore,
                            (ubyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS,
                            DIGI_STRLEN((const sbyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS),
                            &skgCertificate, 1,
                            skgCertDesc.pKeyBlob, skgCertDesc.keyBlobLength);

            if(skgCertDesc.pCertificate)
                DIGI_FREE((void **)&skgCertDesc.pCertificate);
            if(skgCertDesc.pKeyBlob)
                DIGI_FREE((void **)&skgCertDesc.pKeyBlob);
            if (OK != status)
            {
                verbosePrintError("Unable to add est_skg_clientcert and est_skg_clientkey into certstore.", status);
                goto exit;
            }

        }
    }

exit:
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if (certDesc.pCertificate)
        DIGI_FREE((void **)&certDesc.pCertificate);
    if (certDesc.pKeyBlob)
        DIGI_FREE((void **)&certDesc.pKeyBlob);
    if (pPskSecret)
        DIGI_FREE((void **)&pPskSecret);
    return status;
}

MOC_STATIC MSTATUS
getKeyIdentifiderFromCSR(ubyte *pCsr, ubyte4 csrLen, ubyte4 *pKeyId)
{
    ASN1_ITEMPTR pReqRoot       = NULL;
    ASN1_ITEMPTR pAsnAttrItem   = NULL;
    ASN1_ITEMPTR pCertReqInfo   = NULL;
    CStream      reqStream;
    MemFile      mf;
    ubyte        *pDecodedData  = NULL;
    ubyte4       decodedDataLen = 0;
    MSTATUS      status         = OK;
    ubyte decryptKeyIdentifier_OID[] = { 11, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x25 };
    ubyte asymmetricDecryptKeyIdentifier_OID[] = { 11, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x36 };

    /* Decode the key data from Base64 */
    if (OK > (status = CA_MGMT_decodeCertificate(pCsr, csrLen, &pDecodedData, &decodedDataLen)))
    {
        goto exit;
    }

    MF_attach(&mf, decodedDataLen, (ubyte*)pDecodedData );
    CS_AttachMemFile(&reqStream, &mf);
    if (OK > (status = ASN1_Parse(reqStream, &pReqRoot)))
    {
        goto exit;
    }

    /*Read attributes part of certificate request*/
    pAsnAttrItem = ASN1_FIRST_CHILD(pReqRoot);
    pAsnAttrItem = ASN1_FIRST_CHILD(pAsnAttrItem);
    if (OK > (status = ASN1_GetChildWithTag(pAsnAttrItem, 0, &pCertReqInfo)))
    {
        goto exit;
    }
    if (pCertReqInfo != NULL)
    {
        do
        {
            /* Find the DecryptKeyIdentifier Attrribute */
            pAsnAttrItem = ASN1_FIRST_CHILD(pCertReqInfo);
            if (pAsnAttrItem->tag == OID)
            {
                ubyte* oid = (ubyte *)CS_memaccess(reqStream, pAsnAttrItem->dataOffset - 1, pAsnAttrItem->length + 1);
                if (EqualOID(decryptKeyIdentifier_OID, oid))
                {
                    *pKeyId = DECRYPT_KEY_ID;
                }
                else if (EqualOID(asymmetricDecryptKeyIdentifier_OID, oid))
                {
                    *pKeyId = ASYM_DECRYPT_KEY_ID;
                }
            }
        } while ((pCertReqInfo = ASN1_NEXT_SIBLING(pCertReqInfo)) != NULL);
    }
exit:
    if(pReqRoot)
        TREE_DeleteTreeItem((TreeItem*)pReqRoot);
    if(pDecodedData)
        DIGI_FREE((void **)&pDecodedData);
    return status;
}

#define TRUSTEDGE_EST_MAX_FILE_COPY_BYTES 4096

/*------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_EST_addExtension(
    ubyte *pFile, ubyte *pExt, ubyte **ppRetFile)
{
    MSTATUS status;
    ubyte *pNewFile = NULL, *pIter;

    status = DIGI_MALLOC(
        (void **) &pNewFile, DIGI_STRLEN((sbyte *)pFile) + DIGI_STRLEN((sbyte *)pExt) + 1);
    if (OK != status)
    {
        goto exit;
    }

    pIter = pNewFile;

    status = DIGI_MEMCPY(pIter, pFile, DIGI_STRLEN((sbyte *)pFile));
    if (OK != status)
    {
        goto exit;
    }
    pIter += DIGI_STRLEN((sbyte *)pFile);

    status = DIGI_MEMCPY(pIter, pExt, DIGI_STRLEN((sbyte *)pExt));
    if (OK != status)
    {
        goto exit;
    }
    pIter += DIGI_STRLEN((sbyte *)pExt);

    *pIter = '\0';

    *ppRetFile = pNewFile;
    pNewFile = NULL;

exit:

    if (NULL != pNewFile)
    {
        DIGI_FREE((void **) &pNewFile);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_EST_copyFile(
    ubyte *pComponent, ubyte *pCurFile, ubyte *pCopyFile)
{
    MSTATUS status = OK;
    ubyte *pPath, *pCurFilePath, *pCopyFilePath;
    intBoolean fileExist;

    pPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, (char *)pComponent);
    pCurFilePath = (ubyte *) EST_CERT_UTIL_getFullPath(
        (char *)pPath, (char *) pCurFile, (char **) &pCurFilePath);
    pCopyFilePath = (ubyte *) EST_CERT_UTIL_getFullPath(
        (char *)pPath, (char *) pCopyFile, (char **) &pCopyFilePath);

    /* Only copy the file if it exists.
     */
    status = DIGICERT_checkFile((char *)pCurFilePath, NULL, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        status = DIGICERT_copyFile((char *) pCurFilePath, (char *) pCopyFilePath);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:

    if (NULL != pPath)
    {
        FREE(pPath);
    }

    if (NULL != pCurFilePath)
    {
        FREE(pCurFilePath);
    }

    if (NULL != pCopyFilePath)
    {
        FREE(pCopyFilePath);
    }

    return status;
}

static MSTATUS TRUSTEDGE_EST_copyFileByAlias(
    ubyte *pCurFile, ubyte *pCopyFile, ubyte4 fileBaseLength,
    ubyte4 copyBaseLen, ubyte *pExt, ubyte *pCopyExt)
{
    MSTATUS status;

    status = DIGI_MEMCPY(
        pCurFile + fileBaseLength, pExt, DIGI_STRLEN((sbyte *)pExt));
    if (OK != status)
    {
        goto exit;
    }
    pCurFile[fileBaseLength + DIGI_STRLEN((sbyte *)pExt)] = '\0';

    status = DIGI_MEMCPY(
        pCopyFile + copyBaseLen, pCopyExt, DIGI_STRLEN((sbyte *)pCopyExt));
    if (OK != status)
    {
        goto exit;
    }
    pCopyFile[copyBaseLen + DIGI_STRLEN((sbyte *)pCopyExt)] = '\0';

    status = TRUSTEDGE_EST_copyFile((ubyte *) CERTS_PKI_COMPONENT, pCurFile, pCopyFile);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_copyFile((ubyte *) KEYS_PKI_COMPONENT, pCurFile, pCopyFile);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS TRUSTEDGE_EST_backupKeysAndCert(
    ubyte *pKeyAlias, ubyte4 keyAliasLen)
{
    MSTATUS status;
    ubyte *pOldFile = NULL, *pCurFile = NULL;
    ubyte4 extLen, oldExtLen;

    /* Get the largest extension length for the existing file.
     */
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Get the largest extension length for the old key file. This will just be
     * the largest extension length of the existing file + the length of the
     * extension used to specify that the file is old.
     */
    oldExtLen = extLen + DIGI_STRLEN((sbyte *)ESTC_EXT_OLD);

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate a buffer for the file that will be created.
     */
    status = DIGI_CALLOC((void **) &pOldFile, 1, keyAliasLen + oldExtLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pOldFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .der key and cert with .der.old extension if they
     * exist.
     */
    status = TRUSTEDGE_EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .pem key and cert with .pem.old extension if they
     * exist.
     */
    status = TRUSTEDGE_EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PEM,
        (ubyte *) ESTC_EXT_PEM ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .der key and cert with .der.old extension if they
     * exist.
     */
    status = TRUSTEDGE_EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .tapkey key and cert with .tapkey.old extension if they
     * exist.
     */
    status = TRUSTEDGE_EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY,
        (ubyte *) ESTC_EXT_TAPKEY ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .pfx key/cert with .pfx.old extension if they
     * exist.
     */
    status = TRUSTEDGE_EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12,
        (ubyte *) ESTC_EXT_PKCS12 ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    if (NULL != pOldFile)
    {
        DIGI_FREE((void **) &pOldFile);
    }

    return status;
}

/*------------------------------------------------------------------*/

/* Method loads in the specified certificate which must be DER encoded and
 * checks whether the certificate is within the renew window or if the
 * certificate is expired. If the certificate is within the renew window or if
 * the certificate is expired then pExpiring is set to TRUE otherwise it is
 * FALSE.
 */
static MSTATUS TRUSTEDGE_EST_validateCertRenewWindow(TrustEdgeEstCtx *pEstArgs,
    ubyte *pCert, ubyte4 certLen, intBoolean *pExpiring)
{
    MSTATUS status;
    certDistinguishedName *pCertInfo = NULL;
    TimeDate certEndTime = { 0 };
    TimeDate renewWindow = { 0 };
    TimeDate curTime = { 0 };
    sbyte4 renewSeconds;

    if ( (NULL == pCert) || (NULL == pExpiring) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    /* Extract certficiate time information.
     */
    status = CA_MGMT_extractCertTimes(pCert, certLen, pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = DATETIME_convertFromValidityString(
        pCertInfo->pEndDate, &certEndTime);
    if (OK != status)
    {
        goto exit;
    }

    status = RTOS_timeGMT(&curTime);
    if (OK != status)
    {
        goto exit;
    }

    /* Convert days to seconds.
     */
    renewSeconds = pEstArgs->renewWindow * (60 * 60 * 24);

    /* Get the rewew window date.
     */
    status = DATETIME_getNewTime(&curTime, renewSeconds, &renewWindow);
    if (OK != status)
    {
        goto exit;
    }

    /* If the certificate is expired or the certificate expiration is within the
     * renew window then set the expiring flag to TRUE otherwise set it to
     * FALSE.
     */
    if (DIGI_cmpTimeDate(&certEndTime, &renewWindow) <= 0)
    {
        *pExpiring = TRUE;
    }
    else
    {
        *pExpiring = FALSE;
    }

exit:

    if (pCertInfo != NULL)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }

    return status;
}

/*------------------------------------------------------------------*/

/* Method checks whether the certificate is within the renew window time and
 * sets the pReOp flag accordingly. If the certificate is within the renew
 * window time or it is expired then the pReOp flag is set to TRUE, otherwise it
 * is set to false.
 */
static MSTATUS TRUSTEDGE_EST_checkCertificateRenewWindow(TrustEdgeEstCtx *pEstArgs, intBoolean *pReOp)
{
    MSTATUS status;
    ubyte *pPath = NULL, *pBasePath = NULL, *pFullPath = NULL;
    intBoolean fileBool;
    ubyte *pCert = NULL, *pDecodedCert = NULL;
    ubyte4 certLen = 0, decodedCertLen = 0;

    if ( (NULL == pReOp) || (NULL == pEstArgs->pKeyAlias) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath(
        (char *) pPkiDatabase, CERTS_PKI_COMPONENT);
    EST_CERT_UTIL_getFullPath((char *) pPath, (char *)pEstArgs->pKeyAlias, (char **) &pBasePath);

    status = TRUSTEDGE_EST_addExtension(pBasePath, (ubyte *) ESTC_EXT_DER, &pFullPath);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_checkFile((char *) pFullPath, NULL, &fileBool);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == fileBool)
    {
        DIGI_FREE((void **) &pFullPath);

        status = TRUSTEDGE_EST_addExtension(pBasePath, (ubyte *) ESTC_EXT_PEM, &pFullPath);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGICERT_checkFile((char *) pFullPath, NULL, &fileBool);
        if (OK != status)
        {
            goto exit;
        }

        if (FALSE == fileBool)
        {
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }

        /* Set to FALSE to indicate that this file is PEM.
         */
        fileBool = FALSE;
    }

    status = DIGICERT_readFile((char *) pFullPath, &pCert, &certLen);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == fileBool)
    {
        status = CA_MGMT_decodeCertificate(
            pCert, certLen, &pDecodedCert, &decodedCertLen);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pCert);
        pCert = pDecodedCert;
        certLen = decodedCertLen;
    }

    status = TRUSTEDGE_EST_validateCertRenewWindow(pEstArgs, pCert, certLen, pReOp);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    if (NULL != pPath)
    {
        FREE(pPath);
    }

    if (NULL != pBasePath)
    {
        FREE(pBasePath);
    }

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_EST_rekeyOverrideAliasFile(
    ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte *pNewKeyAlias,
    ubyte4 newKeyAliasLen)
{
    MSTATUS status;
    ubyte *pNewFile = NULL, *pCurFile = NULL;
    ubyte4 extLen;

    /* Get the largest extension length for the existing file.
     */
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate a buffer for the file that will be created.
     */
    status = DIGI_CALLOC((void **) &pNewFile, 1, newKeyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the new key alias name.
     */
    status = DIGI_MEMCPY(pNewFile, pNewKeyAlias, newKeyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Delete the files with the extension if they exist.
     */
    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PEM);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen,(ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PEM,
        (ubyte *) ESTC_EXT_PEM);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY,
        (ubyte *) ESTC_EXT_TAPKEY);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12,
        (ubyte *) ESTC_EXT_PKCS12);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    if (NULL != pNewFile)
    {
        DIGI_FREE((void **) &pNewFile);
    }

    return status;
}

static void TRUSTEDGE_EST_deleteOldCertsAndKeys(
    ubyte *pKeyAlias, ubyte4 keyAliasLen)
{
    MSTATUS status;
    ubyte *pCurFile = NULL;
    ubyte4 oldExtLen;

    /* Get the largest extension length for the existing file.
     */
    oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > oldExtLen)
    {
        oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > oldExtLen)
    {
        oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > oldExtLen)
    {
        oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Get the largest extension length for the old key file. This will just be
     * the largest extension length of the existing file + the length of the
     * extension used to specify that the file is old.
     */
    oldExtLen += DIGI_STRLEN((sbyte *)ESTC_EXT_OLD);

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + oldExtLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PEM ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12 ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    return;
}

static MSTATUS TRUSTEDGE_EST_getPskAlgId(
    sbyte *pAlg, ubyte **ppAlgId, ubyte4 *pAlgIdLen)
{
    MSTATUS status;
    ubyte i;
    EstPskList pAlgStrings[] = {
        {
            (sbyte *) "aes192",
            (sbyte *) ESTC_ENC_ALGO_ID_AES_192
        },
        {
            (sbyte *) "3des",
            (sbyte *) ESTC_ENC_ALGO_ID_3DES
        }
    };

    /* Check if the caller provided an algorithm. If not then use the default.
     */
    if (NULL != pAlg)
    {
        for (i = 0; i < COUNTOF(pAlgStrings); i++)
        {
            if ((DIGI_STRLEN(pAlg) == DIGI_STRLEN(pAlgStrings[i].pCmdArg)) &&
                0 == DIGI_STRNICMP((const sbyte *) pAlgStrings[i].pCmdArg, pAlg, DIGI_STRLEN(pAlg)))
            {
                break;
            }
        }

        if (i == COUNTOF(pAlgStrings))
        {
            status = ERR_UNKNOWN_DATA;
            goto exit;
        }

        if (NULL != ppAlgId)
        {
            *ppAlgId = (ubyte *) pAlgStrings[i].pOid;
            *pAlgIdLen = DIGI_STRLEN(pAlgStrings[i].pOid);
        }
    }
    else
    {
        if (NULL != ppAlgId)
        {
            *ppAlgId = (ubyte *) ESTC_DEF_ENC_ALGO_ID;
            *pAlgIdLen = DIGI_STRLEN((const sbyte *) ESTC_DEF_ENC_ALGO_ID);
        }
    }

    status = OK;

exit:

    return status;
}

static MSTATUS TRUSTEDGE_EST_writeTrustedCerts(
    TrustEdgeEstCtx *pEstArgs, struct SizedBuffer *pCerts, ubyte4 certCount)
{
    MSTATUS status;
    ubyte4 i;
    sbyte4 j;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    ubyte4 offset = 0;
    ubyte pCertFileName[MAX_FILE_NAME + 7]; /* we use the end of the buffer as temp
                                               space for the sha1 output, 87 bytes are
                                               file name and so use 13 + 7 more bytes for sha1 */
    sbyte *pPkiComponentPath = NULL;
    sbyte *pFullPath = NULL;
    intBoolean fileExist;

    if (NULL == pCerts)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pPkiComponentPath = TRUSTEDGE_EST_getTrustStorePathCopy();

    for (i = 0; i < certCount; i++)
    {
        ubyte4 len = 0;
        ubyte4 hashSize = SHA1_RESULT_SIZE;
        DIGI_FREE((void **) &pDerCert);

        /* Retrieve the DER certificate.
         */
        status = CA_MGMT_decodeCertificate(
            pCerts[i].data, pCerts[i].length, &pDerCert, &derCertLen);
        if (OK != status)
        {
            goto exit;
        }

        /* Default will be to use the fingerprint of the DER certificate as the
         * file name, otherwise a default name will be chosen.
         */
        if (pEstArgs->cacertTag == 1)
        {
            /* Compute the "fingerprint" of the certificate. This will be the
             * file name used to store the certificate. If -caprefix is provided, it will be
             * prepended to the fingerprint.
             */
            if (NULL != pEstArgs->pCAPrefix)
            {
                len = DIGI_STRLEN((sbyte *)pEstArgs->pCAPrefix);
                hashSize = 4;
                if (len > MAX_FILE_NAME - 8 - 2 - 4) /* 8 bytes for SHA1 output, 1 byte for _, 4 bytes for .der/.pem, 1 byte for NULL */
                {
                    status = ERR_FILE_NAME_TOO_LONG;
                    verbosePrintError("Provide a shorter ca prefix string.", status);
                    goto exit;
                }

                DIGI_MEMCPY(
                    pCertFileName, pEstArgs->pCAPrefix, len);
                pCertFileName[len] = '_';
                len++;
            }

            status = SHA1_completeDigest(MOC_HASH(gHwAccelCtx) pDerCert, derCertLen, pCertFileName + len);
            if (OK != status)
            {
                goto exit;
            }

            /* Convert the SHA-1 result into an ASCII string.
             */
            for (j = hashSize - 1; j >= 0; j--)
            {
                pCertFileName[(2 * j) + 1 + len] = returnHexDigit(pCertFileName[j + len]);
                pCertFileName[2 * j + len] = returnHexDigit(pCertFileName[j + len] >> 4);
            }

            DIGI_MEMCPY(
                pCertFileName + (2 * hashSize) + len, (ubyte *) ESTC_EXT_DER,
                DIGI_STRLEN((sbyte *)ESTC_EXT_DER));
            pCertFileName[(2 * hashSize) + len + DIGI_STRLEN((sbyte *)ESTC_EXT_DER)] = '\0';

            DIGI_FREE((void **) &pFullPath);
            EST_CERT_UTIL_getFullPath(
                (char *) pPkiComponentPath, (char *) pCertFileName, (char **) &pFullPath);

            /* Check if the .der file exists. If it does not then write out the
             * certificate, otherwise the certificate will not be written out
             * since its already on the file system.
             */
            status = DIGICERT_checkFile((char *) pFullPath, NULL, &fileExist);
            if (OK != status)
            {
                goto exit;
            }

            verbosePrintNL(MSG_LOG_INFO, "Fetching Certificate..");
            if (TRUE == fileExist)
            {
                verbosePrintLengthNL(
                    MSG_LOG_INFO, (char *) pCertFileName,
                    DIGI_STRLEN((sbyte *)pCertFileName) - DIGI_STRLEN((sbyte *)ESTC_EXT_DER));
                verbosePrintNL(MSG_LOG_INFO, "Already exists!!");
            }
        }
        else
        {
            DIGI_MEMSET(pCertFileName, 0x00, MAX_FILE_NAME);

#ifdef __RTOS_WIN32__
            sprintf_s(
                (char *) pCertFileName, MAX_FILE_NAME, "%s%d.der",
                CACERTS_RESP_FILE, i);
#else
            snprintf(
                (char *) pCertFileName, MAX_FILE_NAME, "%s%d.der",
                CACERTS_RESP_FILE, (int)i);
#endif
            DIGI_FREE((void **) &pFullPath);
            EST_CERT_UTIL_getFullPath(
                (char *) pPkiComponentPath, (const char *) pCertFileName,
                (char **) &pFullPath);
            fileExist = FALSE;
        }

        if (FALSE == fileExist)
        {
            status = DIGICERT_writeFile( (char *)
                pFullPath, pDerCert, derCertLen);
            if (OK != status)
            {
                verbosePrintStringError(
                    "Unable to write DER-formatted CA certificate to file",
                    pFullPath);
                verbosePrintError(
                    "Unable to write DER-formatted CA certificate to file.",
                    status);
                goto exit;
            }

            verbosePrintStringNL(
                MSG_LOG_INFO, "Writing certificate in DER format: ",
                pFullPath);

            if (pEstArgs->cacertTag == 1)
            {
                DIGI_MEMCPY(
                    pCertFileName + (2 * hashSize) + len, (ubyte *) ESTC_EXT_PEM,
                    DIGI_STRLEN((sbyte *)ESTC_EXT_PEM));
                pCertFileName[(2 * hashSize) + len + DIGI_STRLEN((sbyte *) ESTC_EXT_PEM)] = '\0';
            }
            else
            {
#ifdef __RTOS_WIN32__
                sprintf_s(
                    (char *) pCertFileName, MAX_FILE_NAME, "%s%d.pem",
                    CACERTS_RESP_FILE, i + offset);
#else
                snprintf(
                    (char *) pCertFileName, MAX_FILE_NAME, "%s%d.pem",
                    CACERTS_RESP_FILE, (int)(i + offset));
#endif
            }

            DIGI_FREE((void **) &pFullPath);
            EST_CERT_UTIL_getFullPath(
                (char *) pPkiComponentPath, (char *) pCertFileName, (char **) &pFullPath);

            status = DIGICERT_writeFile( (char *)
                pFullPath, pCerts[i].data, pCerts[i].length);
            if (OK != status)
            {
                verbosePrintStringError(
                    "Unable to write PEM-formatted CA certificate to file",
                    pFullPath);
                verbosePrintError(
                    "Unable to write PEM-formatted CA certificate to file.",
                    status);
                goto exit;
            }

            verbosePrintStringNL(
                MSG_LOG_INFO, "Writing certificate in PEM format: ",
                pFullPath);
        }
    }

    status = OK;

exit:

    if (NULL != pDerCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

    if (NULL != pPkiComponentPath)
    {
        DIGI_FREE((void **) &pPkiComponentPath);
    }

    return status;
}

MOC_STATIC CertEnrollAlg
TRUSTEDGE_EST_keyArgsToKeyAlgorithm(
    TrustEdgeEstCtx *pEstArgs,
    KeyGenArgs *pKeyArgs)
{
    CertEnrollAlg alg = certEnrollAlgUndefined;
    MOC_UNUSED(pKeyArgs);
    if (NULL != pEstArgs && NULL != pEstArgs->pKeyType)
    {
        if (0 == DIGI_STRCMP(pEstArgs->pKeyType, KEY_TYPE_ECDSA))
        {
            if (pEstArgs->usKeySize == 256)
            {
                alg = ecdsaP256;
            }
            else if (pEstArgs->usKeySize == 384)
            {
                alg = ecdsaP384;
            }
            else if (pEstArgs->usKeySize == 521)
            {
                alg = ecdsaP521;
            }
        }
        else if (0 == DIGI_STRCMP(pEstArgs->pKeyType, KEY_TYPE_EDDSA))
        {
            if (pEstArgs->usKeySize == 255)
            {
                alg = eddsaEd25519;
            }
            else if (pEstArgs->usKeySize == 448)
            {
                alg = eddsaEd448;
            }
        }
        else if (0 == DIGI_STRCMP(pEstArgs->pKeyType, KEY_TYPE_RSA))
        {
            if (pEstArgs->usKeySize == 2048)
            {
                alg = rsa2048;
            }
            else if (pEstArgs->usKeySize == 3072)
            {
                alg = rsa3072;
            }
            else if (pEstArgs->usKeySize == 4096)
            {
                alg = rsa4096;
            }
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (0 == DIGI_STRCMP(pEstArgs->pKeyType, KEY_TYPE_QS))
        {
            if (pKeyArgs->gQsAlg == cid_PQC_MLDSA_44)
            {
                alg = mldsa44;
            }
            else if (pKeyArgs->gQsAlg == cid_PQC_MLDSA_65)
            {
                alg = mldsa65;
            }
            else if (pKeyArgs->gQsAlg == cid_PQC_MLDSA_87)
            {
                alg = mldsa87;
            }
        }
#endif
    }
    return alg;
}

MOC_STATIC MSTATUS
TRUSTEDGE_EST_prepareAndSendRequest(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs, ubyte *pCsrConfigFile, ubyte *pExtAttrFile, ubyte4 config_type, ubyte *pHashType, ubyte4 hashTypeLen, sbyte4 mode, ubyte **ppCsrReqBytes, ubyte4 *pCsrReqLen)
{
    MOC_UNUSED(pKeyArgs);
    MSTATUS   status              = OK;
    char     *pPkiComponentPath  = NULL;
    ubyte     *pFullPath          = NULL;
#if  !defined(__FREERTOS_RTOS__) && !defined(__AZURE_RTOS__)
    char    *pCSRFile	  	  = NULL;
#endif
    ubyte     *pAlgoId            = NULL;
    ubyte4    algoIdLen           = 0;
    ubyte *pKeyAlias              = NULL;
    ubyte4 keyAliasLen			  = 0;
    ubyte4 keyType				  = akt_undefined;
    ubyte *pNewKeyAlias = NULL;
    ubyte4 newKeyAliasLen = 0;
    ubyte4 newKeyType = akt_rsa;
    httpAuthScheme scheme = UNKNOWN;

    if (NULL != pEstArgs->pNewKeyType)
    {
        if(DIGI_STRCMP((const sbyte *)pEstArgs->pNewKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            newKeyType = akt_ecc;
        }
        else if(DIGI_STRCMP((const sbyte *)pEstArgs->pNewKeyType, (const sbyte *)KEY_TYPE_EDDSA) == 0)
        {
            newKeyType = akt_ecc_ed;
        }
    }

    if ((pEstArgs->requestType == SIMPLE_ENROLL) || (pEstArgs->requestType == SIMPLE_REENROLL))
    {
#if  !defined(__FREERTOS_RTOS__) && !defined(__AZURE_RTOS__)
        pCSRFile = (pEstArgs->requestType == SIMPLE_ENROLL) ? SIMPLE_ENROLL_CSR_FILE : SIMPLE_REENROLL_CSR_FILE;
#endif
        if (pEstArgs->pKeyAlias != NULL)
        {
            pKeyAlias = pEstArgs->pKeyAlias;
            keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        }
        else
        {
            status = ERR_INTERNAL_ERROR;
            verbosePrintError("Missing simple enroll/re-enroll alias.", status);
            goto exit;
        }

        /* For simple re-enroll, if a rekey alias is provided then use that to
         * perform a rekey operation.
         */
        if ( (SIMPLE_REENROLL == pEstArgs->requestType) && (NULL != pEstArgs->pKeyAlias2) )
        {
            pKeyAlias = pEstArgs->pKeyAlias2;
            keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        }
        keyType = akt_rsa;


#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
            keyType = akt_tap_rsa;
#endif
        if(DIGI_STRCMP((const sbyte *)pEstArgs->pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            keyType = akt_ecc;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
            keyType = akt_tap_ecc;
#endif
        }
        else if(DIGI_STRCMP((const sbyte *)pEstArgs->pKeyType, (const sbyte *)KEY_TYPE_EDDSA) == 0)
        {
            keyType = akt_ecc_ed;
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            if (pKeyArgs->gTap)
            {
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
            }
#elif !defined(__ENABLE_DIGICERT_TEE__)
            if (pKeyArgs->gTap)
            {
                keyType = akt_tap_ecc;
            }
#endif
#endif
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if(DIGI_STRCMP((const sbyte *)pEstArgs->pKeyType, (const sbyte *)KEY_TYPE_QS) == 0)
        {
            keyType = akt_qs;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
            if (pKeyArgs->gTap)
               keyType = akt_tap_qs;
#endif
        }
#endif

        if ((NULL == *ppCsrReqBytes) || (*pCsrReqLen == 0))
        { /* New Request generation */
            /* Generate CSR Request */
            if (OK > (status = EST_generateCSRRequestFromConfigWithPolicy(MOC_HW(gHwAccelCtx) pCertStore,
                            gSslConnectionInstance,
                            pCsrConfigFile,
                            pExtAttrFile, config_type,
                            pKeyAlias, keyAliasLen, gpPrevAsymKey, keyType, TRUSTEDGE_EST_keyArgsToKeyAlgorithm(pEstArgs, pKeyArgs),
                            pHashType, hashTypeLen,
                            ppCsrReqBytes, pCsrReqLen, pEstArgs->flow, TRUSTEDGE_utilsEval, NULL)))
            {
                verbosePrintError("Unable to create CSR from CSR config file.", status);
                goto exit;
            }
        }
    }
    else if (pEstArgs->requestType == FULLCMC)
    {
        if (pEstArgs->pKeyAlias != NULL)
        {
            pKeyAlias = pEstArgs->pKeyAlias;
        }
        else
        {
            status = ERR_INTERNAL_ERROR;
            verbosePrintError("Missing fullcmc alias.", status);
            goto exit;
        }
        keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        keyType = akt_rsa;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
            keyType = akt_tap_rsa;
#endif
        if(DIGI_STRCMP((const sbyte *)pEstArgs->pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {

            keyType = akt_ecc;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
        if (pKeyArgs->gTap)
            keyType = akt_tap_ecc;
#endif
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if(DIGI_STRCMP((const sbyte *)pEstArgs->pKeyType, (const sbyte *)KEY_TYPE_QS) == 0)
        {
            keyType = akt_qs;
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
            if (pKeyArgs->gTap)
               keyType = akt_tap_qs;
#endif
        }
#endif

#if  !defined(__FREERTOS_RTOS__) && !defined(__AZURE_RTOS__)
        pCSRFile = FULLCMC_CSR_FILE;
#endif
        if (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL) == 0)
        {
            pEstArgs->fullCMCRequestType = ENROLL;
        }
        else if (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0)
        {
            pEstArgs->fullCMCRequestType = RENEW;
        }
        else if (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0)
        {
            pEstArgs->fullCMCRequestType = REKEY;
        }
        else
        {
            status = ERR_NOT_FOUND;
            verbosePrintError("Provided FullCMC request type is not supported.", status);
            goto exit;
        }
        if (REKEY == pEstArgs->fullCMCRequestType)
        {
            if (pEstArgs->pKeyAlias2 != NULL)
            {
                pNewKeyAlias = pEstArgs->pKeyAlias2;
            }
            else
            {
                status = ERR_INTERNAL_ERROR;
                verbosePrintError("The re-key alias is required for FullCMC rekey operation.", status);
                goto exit;
            }
            newKeyAliasLen = DIGI_STRLEN((const sbyte*)pNewKeyAlias);
        }

        if ((NULL == *ppCsrReqBytes) || (*pCsrReqLen == 0))
        {
            if (OK > (status = EST_createPKCS7RequestFromConfigWithPolicy(MOC_HW(gHwAccelCtx) pCertStore, pCsrConfigFile, pExtAttrFile,
                            config_type, pKeyAlias, keyAliasLen, gpPrevAsymKey, keyType, TRUSTEDGE_EST_keyArgsToKeyAlgorithm(pEstArgs, pKeyArgs),
                            pNewKeyAlias, newKeyAliasLen, newKeyType, pHashType, hashTypeLen,
                            gSslConnectionInstance, pEstArgs->fullCMCRequestType, pEstArgs->renewinlinecert, ppCsrReqBytes, pCsrReqLen, pEstArgs->flow, TRUSTEDGE_utilsEval, NULL)))
            {
                verbosePrintError("Unable to create CSR from CSR config file.", status);
                goto exit;
            }
        }
    }
    else if (pEstArgs->requestType == SERVER_KEYGEN)
    {
#if  !defined(__FREERTOS_RTOS__) && !defined(__AZURE_RTOS__)
        pCSRFile = SERVERKEYGEN_CSR_FILE;
#endif
        if(pEstArgs->pSkPskAlias || pEstArgs->pSkClntCert)
        {
            /* Get the encryption algorithm ID.
             */
            status = TRUSTEDGE_EST_getPskAlgId(pEstArgs->pSkAlg, &pAlgoId, &algoIdLen);
            if (OK != status)
            {
                verbosePrintError("Unable to retrieve encryption algorithm.", status);
                goto exit;
            }

            if(pEstArgs->pSkClntCert)
            {
                keyType = pEstArgs->skKeyType;
                pKeyAlias = (ubyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS;
                keyAliasLen = DIGI_STRLEN((const sbyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS);
            }
            else
            {
                keyType = akt_custom;
                pKeyAlias = (ubyte *)pEstArgs->pSkPskAlias;
                keyAliasLen = DIGI_STRLEN((const sbyte *)pEstArgs->pSkPskAlias);
                while (keyAliasLen > 0 && pKeyAlias[keyAliasLen - 1] != '.')
                {
                    keyAliasLen--;
                }
                if (keyAliasLen < 2)
                {
                    status = ERR_BAD_LENGTH;
                    verbosePrintStringError("Unable to get PSK alias", pEstArgs->pSkPskAlias);
                    goto exit;
                }
                keyAliasLen--;
            }
        }

        if ((NULL == *ppCsrReqBytes) || (*pCsrReqLen == 0))
        {
            /* Generate CSR Request */
            if (OK > (status = EST_generateCSRRequestFromConfigExWithPolicy(MOC_HW(gHwAccelCtx) pCertStore, pCsrConfigFile,
                            pExtAttrFile, config_type, pAlgoId, algoIdLen,
                            pKeyAlias, keyAliasLen,
                            keyType, TRUSTEDGE_EST_keyArgsToKeyAlgorithm(pEstArgs, pKeyArgs), pHashType, hashTypeLen,
                            gSslConnectionInstance, ppCsrReqBytes, pCsrReqLen,
                            pEstArgs->flow, TRUSTEDGE_utilsEval, NULL)))
            {
                verbosePrintError("Unable to create CSR from CSR config file.", status);
                goto exit;
            }
        }
    }

#if  !defined(__FREERTOS_RTOS__) && !defined(__AZURE_RTOS__)
    /* Write CSR to a file */
    pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, REQ_PKI_COMPONENT);
    if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath((const char*)pPkiComponentPath,
                        (const char *) pCSRFile, (char **)&pFullPath), *ppCsrReqBytes, *pCsrReqLen)))
    {
        verbosePrintStringError("Unable to write CSR to file", (sbyte *)pFullPath);
        verbosePrintError("Unable to write CSR to file.", status);
    }
#endif

    if ((NULL != pEstArgs->pAuthScheme) && (NULL == strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD)) &&
        (NULL == strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD)) && (NULL == strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)))
    {
        if ((0 == DIGI_STRCMP(pEstArgs->pAuthScheme, "BASIC")) || (0 == DIGI_STRCMP(pEstArgs->pAuthScheme, "basic")))
        {
            scheme = BASIC;
        }
        else if ((0 == DIGI_STRCMP(pEstArgs->pAuthScheme, "DIGEST")) || (0 == DIGI_STRCMP(pEstArgs->pAuthScheme, "digest")))
        {
            scheme = DIGEST;
        }

        switch (scheme)
        {
            case BASIC:
                (void) DIGI_FREE((void**)&pEstArgs->pAuthStr);
                HTTP_AUTH_generateBasicAuthorization(pEstArgs->pHttpContext,
                            pEstArgs->pUserName, DIGI_STRLEN(pEstArgs->pUserName),
                            pEstArgs->pUserPasswd, DIGI_STRLEN(pEstArgs->pUserPasswd),
                            &pEstArgs->pAuthStr, &pEstArgs->authStrLen);
                pEstArgs->index = Authorization;
                break;

            case DIGEST:
                status = ERR_NOT_IMPLEMENTED;
                verbosePrintError("DIGEST authentication scheme not implemented.", status);
                goto exit;

            default:
                status = ERR_HTTP;
                goto exit;
        }
    }
    if (mode == 1)
    {
        (void) DIGI_FREE((void**)&pEstArgs->pAuthStr);
        if (OK > (status = HTTP_AUTH_generateAuthorization(pEstArgs->pHttpContext, &pEstArgs->index, &pEstArgs->pAuthStr, &pEstArgs->authStrLen)))
        {
            verbosePrintError("HTTP auth generation failed.", status);
            goto exit;
        }
    }
    if ((mode == 0) || (mode == 1) || (mode == 2))
    {
        if (OK > (status = HTTP_CONTEXT_resetContext(pEstArgs->pHttpContext)))
        {
            verbosePrintError("HTTP context reset failed.", status);
            goto exit;
        }
        if (pEstArgs->authStrLen > 0)
        {
            if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pEstArgs->pHttpContext, pEstArgs->index, pEstArgs->pAuthStr, pEstArgs->authStrLen)))
            {
                verbosePrintError("HTTP failed to set auth header.", status);
                goto exit;
            }
        }
    }

    if (OK > (status = EST_setCookie(pEstArgs->pHttpContext, *ppCsrReqBytes, *pCsrReqLen)))
    {
        verbosePrintError("EST client failed to set cookie.", status);
        goto exit;
    }

    if ((pEstArgs->requestType == SIMPLE_ENROLL) || (pEstArgs->requestType == SIMPLE_REENROLL))
    {
        verbosePrintString(MSG_LOG_INFO, "Sending simple enroll/re-enroll request\n");
        if (OK > (status = EST_sendSimpleEnrollRequest(pEstArgs->pHttpContext,
                        gSslConnectionInstance,  (ubyte*)pEstArgs->pUrl, DIGI_STRLEN(pEstArgs->pUrl),
                        *pCsrReqLen, (ubyte*)pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName), pEstArgs->pUserAgent)))
        {
            goto exit;
        }
    }
    else if (pEstArgs->requestType == FULLCMC)
    {
        verbosePrintString(MSG_LOG_INFO, "Sending fullcmc request\n");
        if (OK > (status = EST_sendFullCmcRequest(pEstArgs->pHttpContext, gSslConnectionInstance,
                        (ubyte*)pEstArgs->pUrl, DIGI_STRLEN(pEstArgs->pUrl), *pCsrReqLen,
                        (ubyte*)pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName), pEstArgs->fullCMCRequestType, pEstArgs->pUserAgent)))
        {
            goto exit;
        }
    }
    else if (pEstArgs->requestType == SERVER_KEYGEN)
    {
        verbosePrintString(MSG_LOG_INFO, "Sending server keygen request\n");
        if (OK > (status = EST_sendServerKeyGenRequest(pEstArgs->pHttpContext, gSslConnectionInstance,
                        (ubyte*)pEstArgs->pUrl, DIGI_STRLEN(pEstArgs->pUrl), *pCsrReqLen,
                        (ubyte*)pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName), pEstArgs->pUserAgent)))
        {
            goto exit;
        }
    }

exit:
    EST_freeCookie(pEstArgs->pHttpContext);
    if (pPkiComponentPath)
        DIGI_FREE((void **)&pPkiComponentPath);
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);
    return status;
}

static MSTATUS TRUSTEDGE_EST_writeKey(TrustEdgeEstCtx *pEstArgs, ubyte *pKeyBlob, ubyte4 keyBlobLen)
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};
    ubyte *pKeyFile = NULL;
    char  *pPkiComponentPath = NULL;
    ubyte *pFullPath = NULL;
    ubyte *pContents = NULL;
    ubyte4 contentsLen = 0;
    ubyte *pDerKey = NULL;
    ubyte4 derKeyLen = 0;

    if (pEstArgs->pKeyAlias != NULL)
    {
        if (OK != (status = DIGI_CALLOC((void**)&pKeyFile, 1, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias) + 5))) /* .pem + '/0'*/
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMCPY((ubyte*)pKeyFile, pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pKeyFile+DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK != (status = DIGI_CALLOC((void**)&pKeyFile, 1, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE) + 5))) /* .pem + '/0' */
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMCPY((ubyte*)pKeyFile, SERVERKEYGEN_KEY_FILE, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pKeyFile+DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }
    }

    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
        pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pEstArgs->pPkcs8Pw)
    {
        status = PKCS8_encodePrivateKeyPEM(
            g_pRandomContext, pKeyBlob, keyBlobLen,
            pEstArgs->pkcs8EncType, PKCS8_PrfType_undefined /* uses default */,
            (ubyte *)pEstArgs->pPkcs8Pw, DIGI_STRLEN(pEstArgs->pPkcs8Pw),
            &pContents, &contentsLen);
    }
    else
    {
        status = CRYPTO_serializeAsymKey (
            MOC_ASYM(gHwAccelCtx) &asymKey, privateKeyPem,
            &pContents, &contentsLen);
    }
    if (OK != status)
    {
        goto exit;
    }

    pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, KEYS_PKI_COMPONENT);
    if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                        (const char *) pKeyFile, (char**)&pFullPath), pContents, contentsLen)))
    {
        verbosePrintStringError("Unable to write PEM key to file", (sbyte *)pFullPath);
        verbosePrintError("Unable to write PEM key to file.", status);
    }
    verbosePrintStringNL(MSG_LOG_INFO, "Writing key in PEM format: ", (sbyte *)pFullPath);
    if(pFullPath) DIGI_FREE((void **)&pFullPath);

    status = CA_MGMT_decodeCertificate(
        pContents, contentsLen, &pDerKey, &derKeyLen);
    if (OK != status)
    {
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pKeyFile+DIGI_STRLEN((sbyte*)pKeyFile)-4, (ubyte *) ESTC_EXT_DER, 4)))
    {
        goto exit;
    }
    if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                    (const char *) pKeyFile, (char**)&pFullPath), pDerKey, derKeyLen)))
    {
        verbosePrintStringError("Unable to write DER key to file", (sbyte *)pFullPath);
        verbosePrintError("Unable to write DER key to file.", status);
    }
    verbosePrintStringNL(MSG_LOG_INFO, "Writing key in DER format: ", (sbyte *)pFullPath);
    if(pFullPath) DIGI_FREE((void **)&pFullPath);

exit:
    if (pDerKey) DIGI_FREE((void**)&pDerKey);
    if(pPkiComponentPath) DIGI_FREE((void **)&pPkiComponentPath);
    if (pContents) DIGI_FREE((void**)&pContents);
    if (pKeyFile)  DIGI_FREE((void**)&pKeyFile);
    CRYPTO_uninitAsymmetricKey (&asymKey, NULL);
    return status;
}

/*---------------------------------------------------------------------------*/

/**
 * Response from EST server will be as follows
 *
 *     certificates
 *         Newly issued certificate
 *         Other certificates
 *
 * This API takes in a SizedBuffer which contains the Newly issued certificate
 * and the Other certificates, and returns a SizedBuffer with just the newly
 * issued certificate and any intermediate certificate(s) which correspond to
 * the issued certificate. The SizedBuffer will contain the certificate chain
 * in the correct order (issued certificate starting at index 0 with the
 * remaining chain following in subsequent indexes).
 */
extern MSTATUS TRUSTEDGE_EST_removeOtherCertificates(
    SizedBuffer **ppCerts, ubyte4 *pCertCount)
{
    MSTATUS status;
    sbyte4 *pParents = NULL;
    sbyte4 index;
    ubyte4 i, j, count = 0;
    CStream cs, parentCs;
    MemFile mf, parentMf;
    ASN1_ITEMPTR pCertRoot = NULL, pParentRoot = NULL;
    SizedBuffer *pNewCerts = NULL;
    ubyte *pDerCert = NULL, *pDerParent = NULL;
    ubyte4 derCertLen = 0, derParentLen = 0;
    byteBoolean noMoreCerts = FALSE;

    if ( (NULL == ppCerts ) || (NULL == pCertCount) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Must contain at least 1 certificate */
    if (0 == *pCertCount)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* If there is only 1 certificate then the SizedBuffer can remain
     * the same */
    if (1 == *pCertCount)
    {
        status = OK;
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &pParents, 1, sizeof(sbyte4) * (*pCertCount));
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(
        (*ppCerts)[0].data, (*ppCerts)[0].length, &pDerCert, &derCertLen);
    if (OK != status)
    {
        goto exit;
    }

    MF_attach(&mf, derCertLen, pDerCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pCertRoot);
    if (OK != status)
    {
        goto exit;
    }

    /* Check if the issued certificate is self-signed. If it is self-signed then
     * there is no need to process the remaining certificates. Set the count to 1
     * and pParent index appropriately so only the issued certificate is copied
     * over.
     *
     * If the certificate is not self-signed then check if any intermediate
     * certificates are provided corresponding to the issued certificate. */
    status = X509_isRootCertificate(ASN1_FIRST_CHILD(pCertRoot), cs);
    if (OK == status)
    {
        count = 1;
        pParents[0] = -1;
    }
    else if (ERR_FALSE == status)
    {
        /* By default initialize to -1 to identify that no parent has been found. */
        for (i = 0; i < *pCertCount; i++)
        {
            pParents[i] = -1;
        }

        /* This while loop attempts to find the certificate chain corresponding
         * to the issued certificate. The index of the current certificate (i)
         * starts at the issued certificate. The loop will search the Other Certificates
         * provided in the EST server response for the issuer. Once the issuer is found,
         * if the issuer is a CA certificate then the loop exits otherwise the loop
         * set the current certificate to the issuer and then searches for the next
         * issuer certificate. */
        i = 0;
        count = 1;
        do
        {
            /* If the parent is already found then the certificate chain is cyclic which
             * is an error condition. */
            if (-1 != pParents[i])
            {
                status = ERR_CERT_BUFFER_OVERFLOW;
                goto exit;
            }

            /* Search for the issuer certificate. We know the issued certificate is at index
             * 0 so the search can start at index 1 where the Other Certificates from the EST
             * response are stored. */
            for (j = 1; j < *pCertCount; j++)
            {
                /* If j and i match then no need to check if the link is valid since they
                 * are the same certificate. */
                if (j != i)
                {
                    status = CA_MGMT_decodeCertificate(
                        (*ppCerts)[j].data, (*ppCerts)[j].length, &pDerParent, &derParentLen);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    MF_attach(&parentMf, derParentLen, pDerParent);
                    CS_AttachMemFile(&parentCs, &parentMf);

                    status = X509_parseCertificate(parentCs, &pParentRoot);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    /* Check if the link is valid. There are 3 possibilities
                     * here.
                     *
                     * 1 - Link is valid and the issuer is not a root certificate. In
                     *     this case mark the parent in the pParents array and increment
                     *     the count of certificates in the chain. Exit the this inner
                     *     loop since the issuer was found.
                     * 2 - Link is valid and the issuer is a root certificate. In this
                     *     case exit both the inner for loop and outer while loop. The
                     *     chain is complete and there are no more certificates to process.
                     *     Note that we do not want to increment the count of certificates
                     *     in the chain since we don't want to include CA certificates
                     *     in our chain.
                     * 3 - Link is not valid. Check the link with the next certificate.
                     */
                    status = X509_validateLink(
                        ASN1_FIRST_CHILD(pCertRoot), cs,
                        ASN1_FIRST_CHILD(pParentRoot), parentCs, 0);
                    if (OK == status)
                    {
                        status = X509_isRootCertificate(
                            ASN1_FIRST_CHILD(pParentRoot), parentCs);
                        if (OK == status)
                        {
                            /* Link is valid and the issuer is a root certificate.
                             * Exit the outer loop. */
                            noMoreCerts = TRUE;
                            break;
                        }
                        else if (ERR_FALSE == status)
                        {
                            /* Link is valid and the issuer is not a root certificate. */

                            /* Free current certificate and transfer ASN.1 variables of the
                             * issuer to the current certificate to prepare for the next
                             * iteration. Avoids parsing the entire ASN.1 structure again. */
                            TREE_DeleteTreeItem((TreeItem *) pCertRoot);
                            pCertRoot = NULL;
                            DIGI_FREE((void **) &pDerCert);
                            pDerCert = pDerParent;
                            pDerParent = NULL;
                            derCertLen = derParentLen;
                            mf = parentMf;
                            cs = parentCs;
                            pCertRoot = pParentRoot;
                            pParentRoot = NULL;

                            /* Set the current increment the count of certificates in the chain
                             * and store the index to the issuer certificate in the pParents
                             * array. */
                            count++;
                            pParents[i] = j;

                            /* Set the issuer certificate as the current certificate
                             * for the next iteration.
                             */
                            i = j;
                            status = OK;
                            break;
                        }
                        else
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        TREE_DeleteTreeItem((TreeItem *) pParentRoot);
                        pParentRoot = NULL;
                        DIGI_FREE((void **) &pDerParent);
                        status = OK;
                    }
                }
            }

            /* If no issuer was found in the for loop above then exit the main
             * while loop. */
            if (j == *pCertCount)
            {
                noMoreCerts = TRUE;
            }

        } while ( (OK == status) && (noMoreCerts == FALSE) );

        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        goto exit;
    }

    TREE_DeleteTreeItem((TreeItem *) pCertRoot);
    pCertRoot = NULL;
    DIGI_FREE((void **) &pDerCert);

    /* Allocate the new SizedBuffer which will only hold the issued certificate and
     * corresponding intermediate certificate(s). */
    status = DIGI_CALLOC((void **) &pNewCerts, 1, count * sizeof(SizedBuffer));
    if (OK != status)
    {
        goto exit;
    }

    /* Loop through the new SizedBuffer and copy over each certificate from the original
     * SizedBuffer. Free the certificates from the original SizedBuffer as we go to avoid
     * extraneous memory usage. */
    index = 0;
    for (i = 0; i < count; i++)
    {
        /* Copy over certificate */
        status = DIGI_MALLOC_MEMCPY(
            (void **) &(pNewCerts[i].data), (*ppCerts)[index].length,
            (*ppCerts)[index].data, (*ppCerts)[index].length);
        if (OK != status)
        {
            goto exit;
        }
        pNewCerts[i].length = (*ppCerts)[index].length;

        /* Free certificate from original buffer */
        DIGI_FREE((void **) &((*ppCerts)[index].data));
        (*ppCerts)[index].length = 0;

        index = pParents[index];
    }

    /* Free any remaining certificates from the original SizedBuffer */
    for (i = 0; i < *pCertCount; i++)
    {
        if (NULL != (*ppCerts)[i].data)
        {
            DIGI_FREE((void **) &((*ppCerts)[i].data));
            (*ppCerts)[i].length = 0;
        }
    }
    DIGI_FREE((void **) ppCerts);

    *ppCerts = pNewCerts;
    *pCertCount = count;
    pNewCerts = NULL;

exit:

    if (NULL != pNewCerts)
    {
        for (i = 0; i < count; i++)
        {
            if (NULL != pNewCerts[i].data)
            {
                DIGI_FREE((void **) &(pNewCerts[i].data));
            }
        }
        DIGI_FREE((void **) &pNewCerts);
    }

    if (NULL != pParentRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pParentRoot);
    }

    if (NULL != pDerParent)
    {
        DIGI_FREE((void **) &pDerParent);
    }

    if (NULL != pCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);
    }

    if (NULL != pDerCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }

    if (NULL != pParents)
    {
        DIGI_FREE((void **) &pParents);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_EST_getTrustedChainPem(
    ubyte *pCert, ubyte4 certLen, SizedBuffer **ppChain, ubyte4 *pChainCount)
{
    MSTATUS status;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    SizedBuffer *pDerChain = NULL;
    SizedBuffer *pRetChain = NULL;
    ubyte4 derChainCount = 0, retChainCount = 0;
    intBoolean hasSelfSigned = 1;

    if ( (NULL == ppChain) || (NULL == pChainCount) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Release the certstore to fix Memory leak for Trust point.*/
    if (NULL == pCertStore)
    {
        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
        {
            verbosePrintError("Unable to create certstore for getting trust chain.", status);
            goto exit;
        }

        status = TRUSTEDGE_EST_constructCertStoreFromDir(pCertStore, NULL);
        if (OK != status)
        {
            verbosePrintError("Unable to load in CA certificates.", status);
            goto exit;
        }

    }

    status = CA_MGMT_decodeCertificate(
        pCert, certLen, &pDerCert, &derCertLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_getTrustedChain(MOC_ASYM(gHwAccelCtx)
        pDerCert, derCertLen, pCertStore, &pDerChain, &derChainCount);
    if (OK != status)
    {
        verbosePrintError("Unable to get trusted certificates.", status);
        goto exit;
    }

    if (NULL != pDerChain)
    {
        status = CRYPTO_UTILS_isRootCertificate(
            (pDerChain + derChainCount - 1)->data,
            (pDerChain + derChainCount - 1)->length);
        if (ERR_FALSE == status)
        {
            hasSelfSigned = 0;
            status = OK;
        }
        if (OK != status)
        {
            verbosePrintError("Unable to get trusted certificates.", status);
            goto exit;
        }

        retChainCount = derChainCount - hasSelfSigned;

        if (0 != retChainCount)
        {
            status = CRYPTO_UTILS_createPemChainFromDerChain(
                pDerChain, retChainCount, &pRetChain);
            if (OK != status)
            {
                verbosePrintError("Unable to convert DER certificate to PEM certificate.", status);
                goto exit;
            }
        }
    }

    *ppChain = pRetChain;
    *pChainCount = retChainCount;
    pRetChain = NULL;

exit:

    CRYPTO_UTILS_freeCertificates(&pRetChain, retChainCount);
    CRYPTO_UTILS_freeCertificates(&pDerChain, derChainCount);
    DIGI_FREE((void **) &pDerCert);

    return status;
}

static MSTATUS TRUSTEDGE_EST_handleServerkeygenResponse(TrustEdgeEstCtx *pEstArgs, ubyte *pCsrReqBytes, ubyte4 csrReqLen, sbyte4 httpStatusCode, byteBoolean isRetry)
{
    MSTATUS status = OK;
    ubyte *pContentType = NULL;
    ubyte4 contentTypeLen = 0;
    ubyte *pHttpResp = NULL;
    ubyte4 httpRespLen = 0;
    ubyte *pKey = NULL;
    ubyte4 keyLength = 0;
    ubyte *pKeyContentType = NULL;
    ubyte4 keyContentTypeLen = 0;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;

    if (OK > (status = HTTP_REQUEST_getContentType(pEstArgs->pHttpContext, (const ubyte**)&pContentType, &contentTypeLen)))
    {
        verbosePrintError("Unable to get response content type.", status);
        goto exit;
    }

    if(NULL == pContentType)
    {
        status = ERR_HTTP;
        goto exit;
    }

    if (OK > (status = HTTP_REQUEST_getResponseContent(pEstArgs->pHttpContext, &pHttpResp, &httpRespLen)))
    {
        verbosePrintError("Unable to get response content.", status);
        goto exit;
    }

    /* Separate the key and certificate parts */
    if (OK > (status = EST_filterMultiPartContent(pHttpResp, httpRespLen, (ubyte *)pContentType, contentTypeLen,
                    &pKey, &keyLength, &pKeyContentType,
                    &keyContentTypeLen, NULL, NULL, NULL, NULL, isRetry, httpStatusCode)))
    {
        verbosePrintError("Unable to get multi-part content response.", status);
        goto exit;
    }

    if (0 == DIGI_STRNICMP((const sbyte*)EST_PKCS8, (const sbyte*)pKeyContentType, keyContentTypeLen))
    {
        pKeyBlob = pKey;
        keyBlobLen = keyLength;
        pKey = NULL;
    }
    else if (0 == DIGI_STRNICMP((const sbyte*)EST_FULL_CMC_PKCS_MIME, (const sbyte*)pKeyContentType, keyContentTypeLen))
    {
        sbyte4 keyId = -1;
        if (OK > (status = getKeyIdentifiderFromCSR(pCsrReqBytes, csrReqLen, (ubyte4*)&keyId)))
        {
            verbosePrintError("Unable to get key identifier from CSR.", status);
            goto exit;
        }
        if (keyId == DECRYPT_KEY_ID)
        {
            if (OK > (status = EST_getPemKeyFromPkcs7EnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
            {
                verbosePrintError("Unable to extract key from PKCS7 envelop data.", status);
                goto exit;
            }
        }
        else if (keyId == ASYM_DECRYPT_KEY_ID)
        {
            if (OK > (status = EST_getPemKeyFromCmsEnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
            {
                verbosePrintError("Unable to extract key from CMS envelop data.", status);
                goto exit;
            }
        }
    }

    if (OK != (status = TRUSTEDGE_EST_writeKey(pEstArgs, pKeyBlob, keyBlobLen)))
    {
        verbosePrintError("Unable to write serverkeygen keyblob to file.", status);
        goto exit;
    }

    /* Irrespective of verbose enabled or debug log enabled. this log should get printed */
    verbosePrintNL(MSG_LOG_INFO, "Key file received successfully.");

exit:
    if (pHttpResp) DIGI_FREE((void **)&pHttpResp);
    if (pKeyContentType) DIGI_FREE((void **)&pKeyContentType);
    if (pKey) DIGI_FREE((void **)&pKey);
    if (pKeyBlob) DIGI_FREE((void**)&pKeyBlob);

    return status;
}

extern MSTATUS TRUSTEDGE_EST_constructCertStoreFromDir(struct certStore* pCertStoreForValidation, sbyte *pCertPath)
{
    MSTATUS status;
    byteBoolean validateCerts = TRUE;

    if (NULL == pCertPath)
    {
        pCertPath = (char *)TRUSTEDGE_EST_getTrustStorePathCopy();
    }

    /* Load in certificates from the CA directory */
    status = CRYPTO_UTILS_addTrustPointCertsByDir(
        pCertStoreForValidation, NULL, (sbyte *) pCertPath, validateCerts);
    if (OK != status)
    {
        verbosePrintError("Unable to load trusted certificates by directory.", status);
    }

    if (pCertPath)
    {
        DIGI_FREE((void **)&pCertPath);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_EST_verifyFullcmcResponseWithValidateCb(
    ASN1_ITEMPTR pRoot,
    CStream pkcs7Stream,
    void *pArg,
    PKCS7_ValidateRootCertificate validationCb,
    ASN1_ITEMPTR *pSignerIssuer,
    ASN1_ITEMPTR *pSignerSerial)
{
    MSTATUS      status = OK;
    sbyte4       numKnownSigners    = 0;
    ASN1_ITEMPTR pkcs7Content = NULL;
    ASN1_ITEMPTR signerInfo = NULL;
    WalkerStep   asn1WalkerStep[] =
    {
        {GoFirstChild, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNextSibling, 0, 0},
        { VerifyType, MOC_SET, 0},
        {GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        {GoFirstChild, 0, 0},
        { VerifyType, INTEGER, 0},
        {GoNextSibling, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { Complete, 0, 0}
    };

    if (OK > (status = ASN1_GetChildWithTag(ASN1_FIRST_CHILD(pRoot), 0, &pkcs7Content)))
    {
        goto exit;
    }
    if (OK > (status = PKCS7_VerifySignedData(MOC_RSA(gHwAccelCtx) pkcs7Content, pkcs7Stream,
             pArg,
             NULL,
             validationCb,
             NULL,
             0,
             &numKnownSigners)))
    {
        verbosePrintError("Unable to verify FullCMC response data.", status);
        goto exit;
    }
    if (OK > (status = ASN1_WalkTree(pkcs7Content, pkcs7Stream, asn1WalkerStep, &signerInfo)))
    {
        verbosePrintError("Unable to get signer info from response data.", status);
        goto exit;
    }

    *pSignerIssuer = ASN1_FIRST_CHILD(signerInfo);
    *pSignerSerial = ASN1_NEXT_SIBLING(*pSignerIssuer);

exit:
    return status;
}

extern MSTATUS TRUSTEDGE_EST_verifyFullcmcResponse(ASN1_ITEMPTR pRoot, CStream pkcs7Stream, certStorePtr pStore, ASN1_ITEMPTR *pSignerIssuer, ASN1_ITEMPTR *pSignerSerial)
{
    return TRUSTEDGE_EST_verifyFullcmcResponseWithValidateCb(
        pRoot, pkcs7Stream, pStore, TRUSTEDGE_EST_CB_validateRootCertificate,
        pSignerIssuer, pSignerSerial);
}

extern MSTATUS TRUSTEDGE_EST_parseEndpoint(sbyte *pEndpoint, sbyte **ppServerName, sbyte **ppUrl)
{
    return EST_parseEndpoint(pEndpoint, ppServerName, ppUrl);
}

#ifdef __ENABLE_DIGICERT_PKCS12__
static MSTATUS TRUSTEDGE_EST_getParentCertificate(
    ubyte *pCert, ubyte4 certLen, const ubyte **ppParent, ubyte4 *pParentLen)
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRoot = NULL, pIssuer = NULL;

    if (NULL == pCertStore)
    {
        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
            goto exit;

        status = TRUSTEDGE_EST_constructCertStoreFromDir(pCertStore, NULL);
        if (OK != status)
            goto exit;
    }

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
        goto exit;

    status = X509_getCertificateIssuerSerialNumber(
        ASN1_FIRST_CHILD(pRoot), &pIssuer, NULL);
    if (OK != status)
        goto exit;

    status = CERT_STORE_findTrustPointBySubjectFirst(
        pCertStore, pCert + pIssuer->dataOffset, pIssuer->length,
        ppParent, pParentLen, NULL);
    if (OK != status)
        goto exit;



exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

static MSTATUS TRUSTEDGE_EST_writeP12File(
    TrustEdgeEstCtx *pEstArgs,
    sbyte *pKeyAlias, SizedBuffer *pCerts, ubyte4 certsCount,
    SizedBuffer *pTrustedCerts, ubyte4 trustedCertCount)
{
    MSTATUS status;
    SizedBuffer *pAllCerts = NULL;
    ubyte4 allCertsCount = 0, hasSelfSigned = 0, i;
    ubyte *pKey = NULL, *pKeyFile = NULL, *pKeyPath = NULL, *pFullPath = NULL;
    const ubyte *pCA = NULL;
    ubyte4 keyLen = 0, caLen = 0;
    sbyte4 aliasLen, extLen;
    ubyte *pPkcs12Data = NULL;
    ubyte4 pkcs12DataLen = 0;

    if (NULL == pKeyAlias || NULL == pCerts)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certsCount)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    allCertsCount = certsCount + trustedCertCount;
    status = DIGI_MALLOC(
        (void **) &pAllCerts, sizeof(SizedBuffer) * allCertsCount);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < certsCount; i++)
    {
        status = CA_MGMT_decodeCertificate(
            pCerts[i].data, pCerts[i].length, &(pAllCerts[i].data),
            &(pAllCerts[i].length));
        if (OK != status)
            goto exit;
    }
    for (i = 0; i < trustedCertCount; i++)
    {
        status = CA_MGMT_decodeCertificate(
            pTrustedCerts[i].data, pTrustedCerts[i].length,
            &(pAllCerts[i + certsCount].data),
            &(pAllCerts[i + certsCount].length));
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_UTILS_isRootCertificate(
        pAllCerts[allCertsCount - 1].data, pAllCerts[allCertsCount - 1].length);
    if (OK == status)
    {
        pCA = pAllCerts[allCertsCount - 1].data;
        caLen = pAllCerts[allCertsCount - 1].length;
        hasSelfSigned = 1;
    }
    else if (ERR_FALSE == status)
    {
        status = TRUSTEDGE_EST_getParentCertificate(
            pAllCerts[allCertsCount - 1].data,
            pAllCerts[allCertsCount - 1].length, &pCA, &caLen);
        if (OK != status)
            goto exit;
    }
    else
    {
        goto exit;
    }

    aliasLen = DIGI_STRLEN((sbyte *) pKeyAlias);
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);

    status = DIGI_MALLOC((void **) &pKeyFile, aliasLen + extLen + 1);
    if (OK != status)
        goto exit;

    DIGI_MEMCPY(pKeyFile, pKeyAlias, aliasLen);
    DIGI_MEMCPY(pKeyFile + aliasLen,  (ubyte *) ESTC_EXT_PEM, extLen);
    pKeyFile[aliasLen + extLen] = '\0';

    pKeyPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, KEYS_PKI_COMPONENT);
    EST_CERT_UTIL_getFullPath((char *) pKeyPath, (char *) pKeyFile, (char **) &pFullPath);
    status = DIGICERT_readFile((char *) pFullPath, &pKey, &keyLen);
    if (OK != status)
        goto exit;

    status = PKCS12_EncryptPFXPduPwMode(
        g_pRandomContext, pAllCerts, allCertsCount - hasSelfSigned,
        pKey, keyLen, (ubyte *) pCA, caLen,
        (ubyte *)pEstArgs->pPkcs12KeyPw, pEstArgs->pPkcs12KeyPw ? DIGI_STRLEN(pEstArgs->pPkcs12KeyPw) : 0,
        pEstArgs->pkcs12EncType,
        (ubyte *)pEstArgs->pPkcs12PriPw, pEstArgs->pPkcs12PriPw ? DIGI_STRLEN(pEstArgs->pPkcs12PriPw) : 0,
        (ubyte *)pEstArgs->pPkcs12IntPw, pEstArgs->pPkcs12IntPw ? DIGI_STRLEN(pEstArgs->pPkcs12IntPw) : 0,
        &pPkcs12Data, &pkcs12DataLen);
    if (OK != status)
    {
        goto exit;
    }

    /* PKCS12 extension of .pfx is same length as .pem extension */
    DIGI_MEMCPY(pKeyFile + aliasLen, ESTC_EXT_PKCS12, extLen);

    DIGI_FREE((void **) &pFullPath);
    EST_CERT_UTIL_getFullPath((char *) pKeyPath, (char *) pKeyFile, (char **) &pFullPath);
    status = DIGICERT_writeFile((char *)pFullPath, pPkcs12Data, pkcs12DataLen);

exit:

    if (OK == status)
    {
        verbosePrintStringNL(MSG_LOG_INFO, "Writing certificate and key in DER format: ", (sbyte *) pFullPath);
    }
    else
    {
        verbosePrintNL(MSG_LOG_INFO, "warning: unable to generate PKCS12 file");
    }

    if (NULL != pPkcs12Data)
    {
        DIGI_FREE((void **) &pPkcs12Data);
    }
    if (NULL != pKeyFile)
    {
        DIGI_FREE((void **) &pKeyFile);
    }
    if (NULL != pKeyPath)
    {
        DIGI_FREE((void **) &pKeyPath);
    }
    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }
    if (NULL != pKey)
    {
        DIGI_MEMSET_FREE(&pKey, keyLen);
    }
    if (NULL != pAllCerts)
    {
        CRYPTO_UTILS_freeCertificates(&pAllCerts, allCertsCount);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PKCS12__ */

#if defined(__ENABLE_DIGICERT_TAP__)
static MSTATUS TRUSTEDGE_EST_writeKeyById(
    sbyte *pKeyAlias, ubyte4 keyAliasLen, TAP_Buffer *pKeyId,
    TAP_KeyInfo *pKeyInfo, KeyGenTapArgs *pEstTapContext)
{
    MSTATUS status;
    sbyte *pKeyPath = NULL;
    sbyte *ppExtensions[] = {
        ESTC_EXT_DER,
        ESTC_EXT_PEM,
        ESTC_EXT_TAPKEY,
        NULL
    };
    sbyte **ppExt;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    ubyte *pBlob = NULL;
    ubyte4 blobLen = 0;
    sbyte *pFileName = NULL;
    ubyte4 fileNameLen = 0;
    sbyte *pFullPath = NULL;

    if ( (NULL == pKeyAlias) || (NULL == pKeyId) || (NULL == pKeyId->pBuffer) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKeyPath = (sbyte *) EST_CERT_UTIL_buildKeyStoreFullPath(
        (char *) pPkiDatabase, KEYS_PKI_COMPONENT);

    ppExt = ppExtensions;
    while (NULL != *ppExt)
    {
        if (NULL != pKeyBlob)
        {
            DIGI_FREE((void **) &pKeyBlob);
            keyBlobLen = 0;
        }

        if (NULL != pFileName)
        {
            DIGI_FREE((void **) &pFileName);
        }

        if (NULL != pFullPath)
        {
            DIGI_FREE((void **) &pFullPath);
        }

        if (0 == DIGI_STRCMP(*ppExt, (sbyte *) ESTC_EXT_DER))
        {
            status = CRYPTO_INTERFACE_TAP_serializeKeyById(
                pEstTapContext->gpTapCtx,
                pEstTapContext->gpTapEntityCredList,
                pEstTapContext->gpTapCredList, pKeyInfo, pKeyId->pBuffer,
                pKeyId->bufferLen, privateKeyInfoDer, &pKeyBlob, &keyBlobLen);
            if (OK != status)
            {
                verbosePrintError("Failed to retrieve DER key blob by ID", status);
                goto exit;
            }

            pBlob = pKeyBlob;
            blobLen = keyBlobLen;
        }
        else if (0 == DIGI_STRCMP(*ppExt, (sbyte *) ESTC_EXT_PEM))
        {
            status = CRYPTO_INTERFACE_TAP_serializeKeyById(
                pEstTapContext->gpTapCtx,
                pEstTapContext->gpTapEntityCredList,
                pEstTapContext->gpTapCredList, pKeyInfo, pKeyId->pBuffer,
                pKeyId->bufferLen, privateKeyPem, &pKeyBlob, &keyBlobLen);
            if (OK != status)
            {
                verbosePrintError("Failed to retrieve PEM key blob by ID", status);
                goto exit;
            }

            pBlob = pKeyBlob;
            blobLen = keyBlobLen;
        }
        else if (0 == DIGI_STRCMP(*ppExt, (sbyte *) ESTC_EXT_TAPKEY))
        {
            status = CRYPTO_INTERFACE_TAP_serializeKeyById(
                pEstTapContext->gpTapCtx,
                pEstTapContext->gpTapEntityCredList,
                pEstTapContext->gpTapCredList, pKeyInfo, pKeyId->pBuffer,
                pKeyId->bufferLen, mocanaBlobVersion2, &pKeyBlob, &keyBlobLen);
            if (OK != status)
            {
                verbosePrintError("Failed to retrieve Mocana key blob by ID", status);
                goto exit;
            }

            if (TAP_KEY_ALGORITHM_ECC == pKeyInfo->keyAlgorithm)
            {
                pBlob = pKeyBlob + MOC_ECC_TAP_BLOB_START_LEN;
                blobLen = keyBlobLen - MOC_ECC_TAP_BLOB_START_LEN;
            }
            else
            {
                pBlob = pKeyBlob + MOC_RSA_TAP_BLOB_START_LEN;
                blobLen = keyBlobLen - MOC_RSA_TAP_BLOB_START_LEN;
            }
        }

        fileNameLen = keyAliasLen + DIGI_STRLEN(*ppExt);
        status = DIGI_CALLOC((void **) &pFileName, 1, fileNameLen + 1);
        if (OK != status)
        {
            verbosePrintError("Failed to allocate file name", status);
            goto exit;
        }
        DIGI_STRCAT(pFileName, pKeyAlias);
        DIGI_STRCAT(pFileName, *ppExt);
        pFileName[fileNameLen] = '\0';

        EST_CERT_UTIL_getFullPath(pKeyPath, pFileName, (char **) &pFullPath);
        status = DIGICERT_writeFile( (char *)
            pFullPath, pBlob, blobLen);
        if (OK != status)
        {
            verbosePrintError("Failed to write out key blob file", status);
            goto exit;
        }

        ppExt++;
    }

exit:

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

    if (NULL != pFileName)
    {
        DIGI_FREE((void **) &pFileName);
    }

    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void **) &pKeyBlob);
    }

    if (NULL != pKeyPath)
    {
        DIGI_FREE((void **) &pKeyPath);
    }

    return status;
}

static MSTATUS TRUSTEDGE_EST_persistKey(TrustEdgeEstCtx *pEstArgs,
    TAP_Buffer *pKeyId, sbyte *pKeyAlias, ubyte4 keyAliasLen,
    struct certStore *pStore, KeyGenTapArgs *pEstTapContext)
{
    MSTATUS status;
    AsymmetricKey *pKey = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_KeyInfo keyInfo = { 0 };

    status = CERT_STORE_findIdentityByAlias(
        pStore, pKeyAlias, keyAliasLen, &pKey, NULL, NULL);
    if (OK != status)
    {
        verbosePrintError("Failed to retrieve key by alias", status);
        goto exit;
    }

    status = CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
    if (OK != status)
    {
        verbosePrintError("Failed to retrieve TAP key from Asymmetric key object", status);
        goto exit;
    }

    status = TAP_loadKey(
        pEstTapContext->gpTapCtx, pEstTapContext->gpTapEntityCredList,
        pTapKey, pEstTapContext->gpTapCredList, NULL, NULL);
    if (OK != status)
    {
        verbosePrintError("Failed to load TAP key object", status);
        /* Set pTapKey to NULL to avoid TAP_unloadKey in exit leg */
        pTapKey = NULL;
        goto exit;
    }

    status = TAP_persistObject(
        pEstTapContext->gpTapCtx, pTapKey, pKeyId, NULL);
    if (OK != status)
    {
        verbosePrintError("Failed to persist TAP key object", status);
        goto exit;
    }

    keyInfo.keyAlgorithm = pTapKey->keyData.keyAlgorithm;
    keyInfo.keyUsage = pTapKey->keyData.keyUsage;
    keyInfo.algKeyInfo = pTapKey->keyData.algKeyInfo;

    TAP_unloadKey(pTapKey, NULL);
    pTapKey = NULL;

    status = TRUSTEDGE_EST_writeKeyById(
        pKeyAlias, keyAliasLen, pKeyId, &keyInfo, pEstTapContext);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pTapKey)
    {
        TAP_unloadKey(pTapKey, NULL);
    }

    if (OK == status)
    {
        verbosePrintString(MSG_LOG_INFO, "Persisted key at index (or id): ");
    }
    else
    {
        verbosePrintString(MSG_LOG_INFO, "WARNING: Unable to persist key at index (or id): ");
    }

    if (pEstArgs->isIdHex)
    {
        ubyte4 i = 0;

        verbosePrintString(MSG_LOG_INFO, "0x");
        for (i = 0; i < pKeyId->bufferLen; i++)
        {
            verbosePrintString1Hex(MSG_LOG_INFO, pKeyId->pBuffer[i]);
        }
    }
    else
    {
        verbosePrintString(MSG_LOG_INFO, (sbyte *) pKeyId->pBuffer);
    }

    return status;
}

#endif

MOC_STATIC MSTATUS TRUSTEDGE_EST_executeRequest(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs, TrustEdgeServiceCtx *pSrvCtx, void *pEstTapContext)
{
    MOC_UNUSED(pEstTapContext);
    ubyte       *pHttpResp = NULL;
    ubyte4      httpRespLen;
    ubyte       *pPkcs7Out = NULL;
    ubyte4      pkcs7OutLen = 0;
    byteBoolean armorDetected = FALSE;
    const ubyte *pContentType = NULL;
    ubyte4 		contentTypeLen;
    char  		*pFullPath = NULL;
    char 		*pPkiComponentPath = NULL;
    ubyte4 filteredLen = 0;
    ubyte4 httpStatusCode = 0;
    struct SizedBuffer *pCerts = NULL;
    ubyte4              numCerts = 0;
    ubyte4 i = 0;
    ubyte *pFinalResponse = NULL;
    ubyte4 finalResponseLen = 0;
    ubyte4 finalResponseCopiedLen = 0;
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS tmpStatus;
#endif
    sbyte4 retryCount = 0;
    sbyte4 mode = 0;
    ubyte4 config_type = EST_CONFIG_FILE;
    ubyte *pCsrConfigFile = NULL;
    ubyte *pExtConfigFile = NULL;
    ubyte *pKey = NULL;
    ubyte4 keyLength = 0;
    ubyte *pPKeyContentType = NULL;
    ubyte4 keyContentTypeLen = 0;
    ubyte *pCertContentType = NULL;
    ubyte4 certContentTypeLen = 0;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    ubyte  *pCsrReqBytes = NULL;
    ubyte4 csrReqLen = 0;
    ubyte *pEntityType   = NULL;
    ubyte4 entityTypeLen = 0;
    ubyte *pRetryAfter   = NULL;
    sbyte4 retryAfter    = 0;
    char *pRespFile = NULL;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    byteBoolean isRetry = FALSE;
    ASN1_ITEMPTR pPkcs7Root         = NULL;
    ASN1_ITEMPTR pSignerIssuer = NULL;
    ASN1_ITEMPTR pSignerSerial = NULL;
    MemFile      mfPkcs7;
    ubyte        *pDecodedPkcs7  = NULL;
    ubyte4       decodedPkcs7Len = 0;
    CStream      pkcs7Stream;
    SizedBuffer  *pTrustedChain = NULL;
    ubyte4       trustedChainCount = 0;
    byteBoolean isInvalidPem = FALSE;
    AsymmetricKey *pAsymKey = NULL;

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    byteBoolean tapAttest = FALSE;
#endif
    switch (pEstArgs->requestType)
    {
        case FULLCMC:
            if ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) != 0) &&
                (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) != 0))
            {
                break;
            }

            /* fall-through */

        case SIMPLE_REENROLL:
            if (NULL != pEstArgs->pKeyAlias)
            {
                status = TRUSTEDGE_EST_backupKeysAndCert(
                    pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte *)pEstArgs->pKeyAlias));
                if (OK != status)
                {
                    goto exit;
                }
            }

        default:
            break;
    }

    if (pEstArgs->requestType == CA_CERTS || pEstArgs->requestType == CERTS_DOWNLOAD)
    {
        if (OK > (status = EST_sendCaCertsRequest(pEstArgs->pHttpContext, gSslConnectionInstance,  (ubyte*)pEstArgs->pUrl, DIGI_STRLEN(pEstArgs->pUrl), (ubyte*)pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName), pEstArgs->pUserAgent)))
        {
            verbosePrintNL(MSG_LOG_INFO, "Failed to get CA Certificates");
            verbosePrintError("Unable to get CA Certificates.", status);
            if (OK <= HTTP_REQUEST_getStatusCode(pEstArgs->pHttpContext, &httpStatusCode))
            {
                verboseDumpResponse(
                    MSG_LOG_INFO, NULL, 0, httpStatusCode);
            }
            goto exit;
        }
    }
    else if (pEstArgs->requestType == CSR_ATTRS)
    {
        if (OK > (status = EST_sendCsrAttrsRequest(pEstArgs->pHttpContext, gSslConnectionInstance,  (ubyte*)pEstArgs->pUrl, DIGI_STRLEN(pEstArgs->pUrl), (ubyte*)pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName), pEstArgs->pUserAgent)))
        {
            verbosePrintNL(MSG_LOG_INFO, "Failed to get CSR attributes");
            verbosePrintError("Unable to get CSR attributes.", status);
            goto exit;
        }
        pRespFile = CSRATTRS_RESP_FILE;
    }
    else
    {
        if (pCsrConfigFile)
        {
            DIGI_FREE((void **)&pCsrConfigFile);
            pCsrConfigFile = NULL;
        }
        if (TRUE == pEstArgs->serviceCtx.serviceMode)
        {
            config_type = EST_CONFIG_JSON;
            pCsrConfigFile = pEstArgs->serviceCtx.pCSRAttrBuffer;
            pEstArgs->serviceCtx.pCSRAttrBuffer = NULL;
        }
        else
        {
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CONF_PKI_COMPONENT);
            EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char *)pKeyArgs->gpInCsrFile, (char **)&pCsrConfigFile);
            pExtConfigFile = (ubyte *)pEstArgs->pExtAttrConfFile;
        }
        while(retryCount < pEstArgs->serviceCtx.maxRetryCount)
        {
            httpStatusCode = 0;
            status = TRUSTEDGE_EST_prepareAndSendRequest(pEstArgs, pKeyArgs, pCsrConfigFile,
                    pExtConfigFile, config_type, (ubyte*)pEstArgs->pDigestName, DIGI_STRLEN(pEstArgs->pDigestName),
                    mode, &pCsrReqBytes, &csrReqLen);
            if (status != OK)
            {
                if (ERR_EST_MISSING_REQUEST_INFO == status)
                {
                    verbosePrintError("Mandatory attribute [commonName or localityName] missing in CSR config", status);
                    goto exit;
                }
                HTTP_REQUEST_getStatusCode(pEstArgs->pHttpContext, (ubyte4*)&httpStatusCode);
                /* Irrespective of verbose or debug enabled. These below logs should get printed.*/
                if (202 != httpStatusCode && 200 != httpStatusCode)
                {
                    if (OK <= HTTP_REQUEST_getResponseContent(pEstArgs->pHttpContext, &pHttpResp, &httpRespLen) && NULL != pHttpResp)
                    {
                        if ((0 != mode) || (401 != httpStatusCode))
                        {
                            verboseDumpResponse(MSG_LOG_INFO,
                                    pHttpResp, httpRespLen, httpStatusCode);
                        }
                        DIGI_FREE((void **)&pHttpResp);
                    }
                }

                /* Retry behaviour checks
                 *
                 * - Retry if an error occurred due to networking issue
                 * - Retry if HTTP status code is 401, this time with auth credentials
                 * - Retry if HTTP status code is 202 in case of server keygen
                 */
                if ( (ERR_TCP_SOCKET_CLOSED == status) ||
                     (ERR_TCP_READ_ERROR == status) ||
                     (ERR_TCP_READ_TIMEOUT == status) )
                {
                    sbyte4 ret = 0;

                    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);

                    /* Re-open the connection here. Loop here in case network
                     * error occurs, update retry accordingly */
                    while (++retryCount < pEstArgs->serviceCtx.maxRetryCount)
                    {
                        verbosePrintString1Int1NL(MSG_LOG_INFO, "WARNING: Retrying request connection, previous attempt status= ", status);
                        ret = EST_reOpenSSLConnection(pCertStore, pEstArgs->pHttpContext,
                                pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName),
                                (ubyte*)pEstArgs->pServerIp, DIGI_STRLEN(pEstArgs->pServerIp),
                                pEstArgs->usServerPort, &gSslConnectionInstance, pEstArgs->isOcspRequired, pEstArgs->requirePQC);
                        if (OK <= ret || ERR_TCP_CONNECT_ERROR != ret)
                        {
                            if (OK <= ret)
                            {
                                if (OK > (status = HTTP_CONTEXT_resetContext(pEstArgs->pHttpContext)))
                                {
                                    verbosePrintError("HTTP context reset failed.", status);
                                    goto exit;
                                }
                            }
                            break;
                        }
                    }

                    if (ret < 0)
                    {
                        status = ret;
                        verbosePrintError("Network error, failed to reopen connection.", status);
                        goto exit;
                    }
                }
                else if (httpStatusCode == 401)
                {
                    sbyte4 ret = 0;
                    sbyte4 firstTry = 1;
                    mode = 1;

                    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);

                    /* Re-open the connection here. Loop here in case network
                     * error occurs, update retry accordingly */
                    while (++retryCount < pEstArgs->serviceCtx.maxRetryCount)
                    {
                        if (0 == firstTry)
                        {
                            verbosePrintString1Int1NL(MSG_LOG_INFO, "WARNING: Retrying connection, previous attempt status= ", ret);
                        }
                        ret = EST_reOpenSSLConnection(pCertStore, pEstArgs->pHttpContext,
                                pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName),
                                (ubyte*)pEstArgs->pServerIp, DIGI_STRLEN(pEstArgs->pServerIp),
                                pEstArgs->usServerPort, &gSslConnectionInstance, pEstArgs->isOcspRequired, pEstArgs->requirePQC);
                        if (OK <= ret || ERR_TCP_CONNECT_ERROR != ret)
                        {
                            break;
                        }
                        firstTry = 0;
                    }

                    if (ret < 0)
                    {
                        status = ret;
                        verbosePrintError("HTTP 401: Failed to reopen connection.", status);
                        goto exit;
                    }
                }
                else if (httpStatusCode == 202)
                {
                    mode = 2;
                    isRetry = TRUE;
                    /* Special case to handle the 202 scenario for serverkeygen */
                    verbosePrintString1Int1NL(MSG_LOG_INFO, "HTTP status code= ", httpStatusCode);
                    if (pEstArgs->requestType == SERVER_KEYGEN)
                    {
                        /* If the request is serverkeygen and the status code is 202.
                           Then server may send the empty multipart message or multi-part
                           message containing a private key with out certificate in the response.
                           Key will be sent at first response itself and from the second retry
                           no key will be sent.
                         */
                        if (retryCount == 1)
                        {
                            if (OK != (status = TRUSTEDGE_EST_handleServerkeygenResponse(pEstArgs, pCsrReqBytes,
                                            csrReqLen, httpStatusCode, isRetry)))
                            {
                                verbosePrintError("Unable to handle serverkeygen pending response.", status);
                                goto exit;
                            }
                        }
                    }

                    retryCount++;
                    if (retryCount == pEstArgs->serviceCtx.maxRetryCount)
                    {
                        /* Already reached max retry count, exit loop with
                         * current error status */
                        verbosePrintError("HTTP 202: Max retries reached.", status);
                        break;
                    }

                    if (OK > (status = HTTP_REQUEST_getEntityByIndex(pEstArgs->pHttpContext, 3, (const ubyte**)&pEntityType, &entityTypeLen)))
                    {
                        verbosePrintError("Unable to get Retry-After info.", status);
                        goto exit;
                    }
                    if (pEntityType == NULL)
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }
                    if (pRetryAfter != NULL)
                    {
                        DIGI_FREE((void**)&pRetryAfter);
                    }
                    if (OK > (status = DIGI_MALLOC((void**)&pRetryAfter, entityTypeLen+1)))
                    {
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMSET(pRetryAfter, 0x00, entityTypeLen+1)))
                    {
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMCPY(pRetryAfter, pEntityType, entityTypeLen)))
                    {
                        goto exit;
                    }

                    retryAfter = DIGI_ATOL((const sbyte *)pRetryAfter, NULL);

                    if (retryAfter < ESTC_RETRY_WAIT_SECONDS_MAX)
                    {
                        SLEEP(retryAfter);
                    }
                    else
                    {
                        verbosePrintNL(MSG_LOG_INFO, "Certificate enroll pending on CA");
                        status = ERR_INTERNAL_ERROR;
                        verbosePrintError("Retry-After value is greater than maximum wait time.", status);
                        goto exit;
                    }
                }
                else
                {
                    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);
                    break;
                }
            }
            else
            {
                /* Authentication error or other error could've occurred and
                 * retry attempt might succeed */
                break;/*SUCCESS */
            }
        }

        if (OK != status)
        {
            verbosePrintError("HTTP request/response failure.", status);
        }

        if(pPkiComponentPath) DIGI_FREE((void **)&pPkiComponentPath);
    }

    pEstArgs->serviceCtx.cmdStatus = status;
    /* Get http status code */
    if (OK > (status = HTTP_REQUEST_getStatusCode(pEstArgs->pHttpContext, (ubyte4*)&httpStatusCode)))
    {
        verbosePrintError("Unable to get HTTP response code.", status);
        goto exit;
    }

    if (pEstArgs->requestType == SERVER_KEYGEN || pEstArgs->requestType == SIMPLE_ENROLL ||
            pEstArgs->requestType == SIMPLE_REENROLL || pEstArgs->requestType == FULLCMC)
    {
        if (httpStatusCode == 200)
        {
            verbosePrintString1Int1NL(MSG_LOG_INFO, "HTTP status code= ", httpStatusCode);
            if (OK > (status = HTTP_REQUEST_getContentType(pEstArgs->pHttpContext, (const ubyte**)&pContentType, &contentTypeLen)))
            {
                verbosePrintError("Unable to get response content type.", status);
                goto exit;
            }

            if(NULL == pContentType)
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pEstArgs->pHttpContext, &pHttpResp, &httpRespLen)))
            {
                verbosePrintError("Unable to get response content.", status);
                goto exit;
            }

            if (pEstArgs->requestType == SERVER_KEYGEN)
            {
                /* Separate the key and certificate parts */
                if (OK > (status = EST_filterMultiPartContent(pHttpResp, httpRespLen, (ubyte *)pContentType, contentTypeLen,
                                &pKey, &keyLength, &pPKeyContentType,
                                &keyContentTypeLen, &pPkcs7Out, &pkcs7OutLen,
                                &pCertContentType, &certContentTypeLen,
                                isRetry, httpStatusCode)))
                {
                    verbosePrintError("Unable to get multi-part content from response", status);
                    goto exit;
                }
                pContentType = pCertContentType;
                contentTypeLen = certContentTypeLen;
                /* In case of pending retry pKey will be NULL */
                if (pKey != NULL)
                {
                    if (0 == DIGI_STRNICMP((const sbyte*)EST_PKCS8, (const sbyte*)pPKeyContentType, keyContentTypeLen))
                    {
                        pKeyBlob = pKey;
                        keyBlobLen = keyLength;
                    }
                    else if (0 == DIGI_STRNICMP((const sbyte*)EST_FULL_CMC_PKCS_MIME, (const sbyte*)pPKeyContentType, keyContentTypeLen))
                    {
                        sbyte4 keyId = -1;
                        if (OK > (status = getKeyIdentifiderFromCSR(pCsrReqBytes, csrReqLen, (ubyte4*)&keyId)))
                        {
                            verbosePrintError("Unable to get key identifier from CSR.", status);
                            goto exit;
                        }
                        if (keyId == DECRYPT_KEY_ID)
                        {
                            if (OK > (status = EST_getPemKeyFromPkcs7EnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
                            {
                                verbosePrintError("Unable to get PEM key from PKCS7 envelop data.", status);
                                goto exit;
                            }
                        }
                        else if (keyId == ASYM_DECRYPT_KEY_ID)
                        {
                            if (OK > (status = EST_getPemKeyFromCmsEnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
                            {
                                verbosePrintError("Unable to get PEM key from CMS envelop data.", status);
                                goto exit;
                            }
                        }
                        if(pKey) DIGI_FREE((void **)&pKey);
                    }

                    if (keyBlobLen > 0)
                    {
                        /* Irrespective of verbose enabled or debug log enabled. this log should get printed */
                        verbosePrintNL(MSG_LOG_INFO, "Key file received successfully.");
                    }
                }
                filteredLen = 0;

            }
            else
            {
                if (OK > (status = EST_filterPkcs7Banner(pHttpResp, httpRespLen, &pPkcs7Out, &pkcs7OutLen, &armorDetected)))
                {
                    verbosePrintError("Unable to filter PKCS7 banner from HTTP response data.", status);
                    goto exit;
                }

                if (armorDetected == 0)
                {
                    if (pHttpResp == pPkcs7Out)
                    {
                        pHttpResp = NULL; /* To avoid double free corruption */
                    }
                }
            }

            if (pEstArgs->requestType == FULLCMC)
            {
                if (OK > (status = CA_MGMT_decodeCertificate(pPkcs7Out, pkcs7OutLen, &pDecodedPkcs7, &decodedPkcs7Len)))
                {
                    goto exit;
                }

                MF_attach(&mfPkcs7, decodedPkcs7Len, (ubyte*)pDecodedPkcs7);
                CS_AttachMemFile(&pkcs7Stream, &mfPkcs7);
                if (OK > (status = ASN1_Parse(pkcs7Stream, &pPkcs7Root)))
                {
                    goto exit;
                }

                if (OK > (status = TRUSTEDGE_EST_verifyFullcmcResponse(pPkcs7Root, pkcs7Stream, NULL, &pSignerIssuer, &pSignerSerial)))
                {
                    verbosePrintError("Unable to verify FullCMC response data signature.", status);
                    verbosePrintNL(MSG_LOG_INFO, "FullCMC response data signature verification failed.");
#ifndef __ENABLE_DIGICERT_FORCE_DUMP_CERT__
                    goto exit;
#endif
                }
            }

            if (OK > (status = EST_filterPkcs7Message(pPkcs7Out, pkcs7OutLen, &filteredLen)))
            {
                verbosePrintError("Unable to filter PKCS7 message from HTTP response data.", status);
                goto exit;
            }
#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            if (pKeyArgs->gTap)
            {
                if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
                        (NULL != pEstArgs->fullCmcReq.pFullCmcReqType) &&
                        ( (0 == DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL))))
                {
                    TAP_Key *pTapKey = NULL;

                    /*Get the AIK private key from the certstore */
                    if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                                    pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias),
                                    &pAsymKey,
                                    NULL, NULL)))
                    {
                        goto exit;
                    }

                    status = CRYPTO_INTERFACE_getTapKey(pAsymKey, &pTapKey);
                    if (OK != status)
                        goto exit;

                    if (pTapKey->keyData.keyUsage == TAP_KEY_USAGE_ATTESTATION)
                    {
                        tapAttest = TRUE;
                    }

                }
            }
            if (tapAttest == TRUE)
            {
                if (OK > (status = EST_handleFullcmcEnrollResponse(MOC_HW(gHwAccelCtx) pAsymKey,
                                pPkcs7Out, filteredLen,
                                (ubyte*)pContentType, contentTypeLen,
                                &pCerts, &numCerts)))
                {
                    verbosePrintError("TRUSTEDGE_EST_handleFullcmcEnrollResponse failed with status: ", status);
                    goto exit;
                }
            }
            else
#endif
            {
               /* Get the private key from the certstore for certificate chain filtering */
               if (NULL != pEstArgs->pKeyAlias)
               {
                   status = CERT_STORE_findIdentityByAlias(pCertStore,
                                   pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias),
                                   &pAsymKey,
                                   NULL, NULL);
                   if (OK != status)
                   {
                       /* Key not found, continue without it */
                       pAsymKey = NULL;
                       status = OK;
                   }
               }

               if (OK > (status = EST_receiveResponse((ubyte *)pContentType, contentTypeLen, pPkcs7Out, filteredLen,
                                pAsymKey, &pCerts, &numCerts)))
                {
                    verbosePrintError("Unable to parse PKCS7 response data.", status);
                    goto exit;
                }
            }

            verbosePrintNL(MSG_LOG_INFO, "Certificate enrolled successfully.");

            if (OK > (status = TRUSTEDGE_EST_removeOtherCertificates(&pCerts, &numCerts)))
            {
                verbosePrintError("Unable to remove other certificates.", status);
                goto exit;
            }

            for (; i < numCerts; i++)
            {
                finalResponseLen += pCerts[i].length;
            }
            if (OK > (status = TRUSTEDGE_EST_getTrustedChainPem(
                pCerts[numCerts-1].data, pCerts[numCerts-1].length, &pTrustedChain, &trustedChainCount)))
            {
                goto exit;
            }
            for (i = 0; i < trustedChainCount; i++)
            {
                finalResponseLen += pTrustedChain[i].length;
            }
            if (OK != status)
            {
                goto exit;
            }
            if (OK > (status = DIGI_MALLOC((void **)&pFinalResponse, finalResponseLen)))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMSET(pFinalResponse, 0x00, finalResponseLen)))
            {
                goto exit;
            }
            finalResponseCopiedLen = 0;
            for (i = 0; i < numCerts; i++)
            {
                if (OK > (status = DIGI_MEMCPY(pFinalResponse + finalResponseCopiedLen, pCerts[i].data, pCerts[i].length)))
                {
                    goto exit;
                }
                finalResponseCopiedLen += pCerts[i].length;
            }
            for (i = 0; i < trustedChainCount; i++)
            {
                if (OK > (status = DIGI_MEMCPY(pFinalResponse + finalResponseCopiedLen, pTrustedChain[i].data, pTrustedChain[i].length)))
                {
                    goto exit;
                }
                finalResponseCopiedLen += pTrustedChain[i].length;
            }
            if (!pEstArgs->disableCACert)
            {
                if(OK > (status = EST_validateReceivedCertificate(MOC_HW(gHwAccelCtx) pCertStore, pFinalResponse, finalResponseCopiedLen, NULL)))
                {
                    switch (status)
                    {
                        case ERR_CERT_START_TIME_VALID_IN_FUTURE:
                            verbosePrintError("Issued certificate validity time is in the future: ", status);
                            break;

                        default:
                            verbosePrintError("Issued certificate is not validated with its CA Certs: ", status);
                    }
                }
                else
                {
                    verbosePrintNL(MSG_LOG_INFO, "Issued certificate is validated with CA Certs.");
                }
            }

            char pOutCertFile[MAX_FILE_NAME];
            if (OK > (status = DIGI_MEMSET((ubyte*)pOutCertFile, 0x00, MAX_FILE_NAME)))
            {
                goto exit;
            }
            if ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
                ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) &&
                 (NULL != pEstArgs->pKeyAlias2)))
            {
                if (OK > (status = DIGI_MEMCPY(pOutCertFile, pEstArgs->pKeyAlias2, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias2))))
                {
                    goto exit;
                }
            }
            else
            {

                if (pEstArgs->pKeyAlias != NULL)
                {
                    if (OK > (status = DIGI_MEMCPY(pOutCertFile, pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias))))
                    {
                        goto exit;
                    }
                }
                else
                {
                    if (pEstArgs->requestType == SERVER_KEYGEN)
                    {
                        /* If it is a serverkeygen case. pEstArgs->pKeyAlias might be null, in case if not passed
                           as command line argument */
                        if (OK > (status = DIGI_MEMCPY(pOutCertFile, SERVERKEYGEN_KEY_FILE, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE))))
                        {
                            goto exit;
                        }
                    }
                }
            }

            /* Write to .pem format */
            if (OK > (status = DIGI_MEMCPY(pOutCertFile+DIGI_STRLEN((sbyte*)pOutCertFile), (ubyte *) ESTC_EXT_PEM, 4)))
            {
                goto exit;
            }
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);
            EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char *) pOutCertFile, &pFullPath);
            if (TRUE == FMGMT_pathExists(pFullPath, NULL))
            {
                status = TRUSTEDGE_EST_backupKeysAndCert(pEstArgs->pKeyAlias, DIGI_STRLEN(pEstArgs->pKeyAlias));
                if (OK != status)
                {
                   verbosePrintError("Unable to backup existing certificate PEM data to file.", status);
                   goto exit;
                }
            }
            if (OK > (status = DIGICERT_writeFile((const char *)pFullPath, pFinalResponse, finalResponseCopiedLen)))
            {
                verbosePrintStringError("Unable to write issued certificate PEM data to file", (sbyte *)pFullPath);
                verbosePrintError("Unable to write issued certificate PEM data to file.", status);
                isInvalidPem = TRUE;
            }
            verbosePrintStringNL(MSG_LOG_INFO, "Writing certificate in PEM format: ", (sbyte *)pFullPath);
            if(pFullPath) DIGI_FREE((void **)&pFullPath);

            /*Write to .der format */
            if (OK > (status = CA_MGMT_decodeCertificate(pFinalResponse, finalResponseCopiedLen, &pDerCert, &derCertLen)))
            {
                goto exit;
            }
            if (TRUE == pEstArgs->serviceCtx.serviceMode)
            {
                status = TRUSTEDGE_utilsGetCertInfo(pSrvCtx, pDerCert, derCertLen);
                if (OK != status)
                {
                    goto exit;
                }
            }
            if (OK > (status = DIGI_MEMCPY(pOutCertFile+DIGI_STRLEN((sbyte*)pOutCertFile)-4, (ubyte *) ESTC_EXT_DER, 4)))
            {
                goto exit;
            }
            EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char *) pOutCertFile, &pFullPath);
            if (TRUE == isInvalidPem && TRUE == FMGMT_pathExists(pFullPath, NULL))
            {
                status = TRUSTEDGE_EST_backupKeysAndCert(pEstArgs->pKeyAlias, DIGI_STRLEN(pEstArgs->pKeyAlias));
                if (OK != status)
                {
                   verbosePrintError("Unable to backup existing certificate DER data to file.", status);
                   goto exit;
                }
            }
            if (OK > (status = DIGICERT_writeFile((const char *)pFullPath, pDerCert, derCertLen)))
            {
                verbosePrintStringError("Unable to write issued certificate DER data to file", (sbyte *)pFullPath);
                verbosePrintError("Unable to write issued certificate DER data to file.", status);
            }
            verbosePrintStringNL(MSG_LOG_INFO, "Writing certificate in DER format: ", (sbyte *)pFullPath);
            if(pPkiComponentPath) DIGI_FREE((void **)&pPkiComponentPath);
            if(pFullPath) DIGI_FREE((void **)&pFullPath);

            if (pEstArgs->pkcs12Gen)
            {
#ifdef __ENABLE_DIGICERT_PKCS12__
                /* Do not exit here with a fatal error, PKCS12 file is
                 * optional. The function will warn the user if the file was
                 * unable to be generated. */
                (void) TRUSTEDGE_EST_writeP12File(
                    pEstArgs, (sbyte *)pEstArgs->pKeyAlias, pCerts, numCerts, pTrustedChain,
                    trustedChainCount);
#else
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
#endif
            }

            if (pEstArgs->requestType == SERVER_KEYGEN)
            {
                /* In case of pending retry. pKeyBlob will be NULL. */
                if (pKeyBlob != NULL)
                {
                    if (OK != (status = TRUSTEDGE_EST_writeKey(pEstArgs, pKeyBlob, keyBlobLen)))
                    {
                        verbosePrintError("Unable to write server generated key data to file.", status);
                        goto exit;
                    }
                }
            }

#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_TEE__)
            if (!pEstArgs->useTEE)
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            if (!pEstArgs->useNanoRoot)
#endif
            {
                /* Only persist non-primary keys at this point. Primary keys are
                * persisted during creation */
                if (TRUE == pEstArgs->tapKeyHandleSet && FALSE == pEstArgs->tapKeyPrimary)
                {
                    (void) TRUSTEDGE_EST_persistKey(pEstArgs, &pEstArgs->tapKeyHandle, pEstArgs->pKeyAlias, DIGI_STRLEN(pEstArgs->pKeyAlias), pCertStore, pEstTapContext);
                }

                if (TRUE == pEstArgs->tapCertificateNvIndexSet)
                {
                    tmpStatus = TRUSTEDGE_EST_removeNVIndex(pEstArgs->tapCertificateNvIndex, TRUE == pEstArgs->tapKeyPrimary ? TAP_AUTH_CONTEXT_PLATFORM : TAP_AUTH_CONTEXT_NONE, (KeyGenTapArgs *) pEstTapContext);
                    if (OK == tmpStatus)
                    {
                        /* Do not override status here */
                        tmpStatus = TRUSTEDGE_EST_persistDataAtNVIndex(
                            pEstArgs->tapCertificateNvIndex, pDerCert, derCertLen, TRUE == pEstArgs->tapKeyPrimary ? TAP_AUTH_CONTEXT_PLATFORM : TAP_AUTH_CONTEXT_NONE, (KeyGenTapArgs *) pEstTapContext);
                        if (OK == tmpStatus)
                        {
                            verbosePrintString1Hex1NL(MSG_LOG_INFO, "Persisted certificate at index: 0x", pEstArgs->tapCertificateNvIndex);
                        }
                        else
                        {
                            verbosePrintString1Int1NL(MSG_LOG_INFO, "WARNING: Failed to persist certificate, status= ", tmpStatus);
                            verbosePrintString1Hex1NL(MSG_LOG_INFO, "WARNING: Unable to persist certificate at index: 0x", pEstArgs->tapCertificateNvIndex);
                        }
                    }
                    else
                    {
                        verbosePrintString1Int1NL(MSG_LOG_INFO, "WARNING: Failed to remove NV index, status= ", tmpStatus);
                        verbosePrintString1Hex1NL(MSG_LOG_INFO, "WARNING: Unable to remove index: 0x", pEstArgs->tapCertificateNvIndex);
                    }
                }
            }
#endif
        }
        else
        {
            verbosePrintNL(MSG_LOG_INFO, "Certificate enroll failed");
        }
    }
    else
    {
        if (OK > (status = HTTP_REQUEST_getContentType(pEstArgs->pHttpContext, (const ubyte**)&pContentType, &contentTypeLen)))
        {
            verbosePrintError("Unable to get response content type.", status);
            goto exit;
        }

        if(NULL == pContentType)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (OK > (status = HTTP_REQUEST_getResponseContent(pEstArgs->pHttpContext, &pHttpResp, &httpRespLen)))
        {
            verbosePrintError("Unable to get response content.", status);
            goto exit;
        }

        if (pEstArgs->requestType == CA_CERTS || pEstArgs->requestType == CERTS_DOWNLOAD)
        {
            if (OK > (status = EST_filterPkcs7Banner(pHttpResp, httpRespLen, &pPkcs7Out, &pkcs7OutLen, &armorDetected)))
            {
                verbosePrintError("Unable to filter PKCS banners from response.", status);
                goto exit;
            }
            if (armorDetected == 0)
            {
                if (pHttpResp == pPkcs7Out)
                    pHttpResp = NULL; /* To avoid double free corruption */
            }
            if (OK > (status = EST_filterPkcs7Message(pPkcs7Out, pkcs7OutLen, &filteredLen)))
            {
                verbosePrintError("Unable to filter PKCS message from response.", status);
                goto exit;
            }

            if (OK > (status = EST_receiveResponse((ubyte *)pContentType, contentTypeLen, pPkcs7Out, filteredLen,
                            NULL, &pCerts, &numCerts)))
            {
                verbosePrintError("Unable to parse PKCS7 response data.", status);
                goto exit;
            }

            status = TRUSTEDGE_EST_writeTrustedCerts(pEstArgs, pCerts, numCerts);
            if (OK != status)
            {
                verbosePrintError("Unable to write CA certificates.", status);
                goto exit;
            }

            verbosePrintNL(MSG_LOG_INFO, "Got CA Certificates successfully");
        }
        else
        {
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CONF_PKI_COMPONENT);
            if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) pRespFile, &pFullPath), pHttpResp, httpRespLen)))
            {
                verbosePrintStringError("Unable to write csratts response data to file", (sbyte *)pFullPath);
                verbosePrintError("Unable to write csratts response data to file.", status);
                goto exit;
            }

            verbosePrintStringNL(MSG_LOG_INFO, "Writing file: ", (sbyte *)pFullPath);
            verbosePrintNL(MSG_LOG_INFO, "Got CSR attributes successfully");
        }
    }

    if (((FULLCMC == pEstArgs->requestType) && (REKEY == pEstArgs->fullCMCRequestType)) ||
        ((pEstArgs->requestType == SIMPLE_REENROLL) && (NULL != pEstArgs->pKeyAlias2)))
    {
        if (OK == status)
        {
            status = TRUSTEDGE_EST_rekeyOverrideAliasFile(
                pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte *)pEstArgs->pKeyAlias),
                pEstArgs->pKeyAlias2, DIGI_STRLEN((sbyte *)pEstArgs->pKeyAlias2));
        }
        else
        {
            TRUSTEDGE_EST_deleteCertsAndKeys(
                pEstArgs->pKeyAlias2, DIGI_STRLEN((sbyte *)pEstArgs->pKeyAlias2));
            TRUSTEDGE_EST_deleteOldCertsAndKeys(
                pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte *)pEstArgs->pKeyAlias));
        }
    }

    if ( (((FULLCMC == pEstArgs->requestType) && (RENEW == pEstArgs->fullCMCRequestType)) ||
        (SIMPLE_REENROLL == pEstArgs->requestType)) && ((OK != status)) )
    {
        TRUSTEDGE_EST_deleteOldCertsAndKeys(
            pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte *)pEstArgs->pKeyAlias));
    }

exit:
    if(OK > status)
    {
            verbosePrintError("EST client request failed.", status);
    }
    if (OK > (status = HTTP_CONTEXT_resetContext(pEstArgs->pHttpContext)))
    {
        verbosePrintError("Unable to reset HTTP context.", status);
    }
    if (OK > (status = EST_closeConnection(pEstArgs->pHttpContext, gSslConnectionInstance)))
    {
        verbosePrintError("Unable to close connection", status);
    }
    pEstArgs->pHttpContext = NULL;
    if (pRetryAfter != NULL)
        DIGI_FREE((void**)&pRetryAfter);

    if(pHttpResp)
    {
        DIGI_FREE((void **)&pHttpResp);
    }
    if (pFinalResponse)
    {
        DIGI_FREE((void **)&pFinalResponse);
    }
    if (pCsrConfigFile)
    {
        DIGI_FREE((void **)&pCsrConfigFile);
        pCsrConfigFile = NULL;
    }
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pPkiComponentPath)
        DIGI_FREE((void **)&pPkiComponentPath);
    if(pCerts)
    {
        for(i = 0; i < numCerts; i++)
        {
            if(pCerts[i].data) DIGI_FREE((void **)&pCerts[i].data);
        }
        DIGI_FREE((void **)&pCerts);
    }
    if(pPKeyContentType) DIGI_FREE((void **)&pPKeyContentType);
    if(pPkcs7Out) DIGI_FREE((void **)&pPkcs7Out);
    if(pCertContentType) DIGI_FREE((void **)&pCertContentType);
    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);
    if(pKeyBlob) DIGI_FREE((void **)&pKeyBlob);
    if (pDerCert) DIGI_FREE((void**)&pDerCert);

    if (pPkcs7Root)
    {
        TREE_DeleteTreeItem((TreeItem*)pPkcs7Root);
    }
    if(pDecodedPkcs7) DIGI_FREE((void **)&pDecodedPkcs7);
    if(pTrustedChain) CRYPTO_UTILS_freeCertificates(&pTrustedChain, trustedChainCount);
    return status;
}

MOC_STATIC MSTATUS
TRUSTEDGE_EST_processRequest(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs, TrustEdgeServiceCtx *pSrvCtx, void *pEstTapContext)
{
    MSTATUS status = OK;

    if (NULL != strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD))
    {
        pEstArgs->requestType = CA_CERTS;
    }
    else if (NULL != strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD))
    {
        pEstArgs->requestType = CSR_ATTRS;
    }
    else if (NULL != strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD))
    {
        pEstArgs->requestType = SERVER_KEYGEN;
    }
    else if (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD))
    {
        pEstArgs->requestType = SIMPLE_ENROLL;
    }
    else if (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD))
    {
        pEstArgs->requestType = SIMPLE_REENROLL;
    }
    else if (NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD))
    {
        pEstArgs->requestType = FULLCMC;
    }
    else
    {
        pEstArgs->requestType = CERTS_DOWNLOAD;
        /*verbosePrintStringError("This operation is not supported", (sbyte *)pEstArgs->pUrl);
        status = ERR_EST_BAD_REQUEST;
        goto exit;*/
    }

    if (OK > (status = TRUSTEDGE_EST_executeRequest(pEstArgs, pKeyArgs, pSrvCtx, pEstTapContext)))
    {
        verbosePrintError("Unable to execute request.", status);
        goto exit;
    }
exit:
    return status;

}

extern sbyte4
TRUSTEDGE_EST_uninitUpcallsAndCertStores()
{
    MSTATUS status = OK;
    if(pCertStore)
        CERT_STORE_releaseStore(&pCertStore);
    if(pPkiDatabase)
        DIGI_FREE((void **)&pPkiDatabase);

    gpPrevAsymKey = NULL;

    return status;
}

static
MSTATUS TRUSTEDGE_EST_validateArguments(TrustEdgeEstCtx *pEstArgs, KeyGenArgs *pKeyArgs)
{
    MSTATUS status = OK;
    char *pPkiComponentPath = NULL;
    ubyte *pContents = NULL;
    ubyte4 contentsLen = 0;
    char *pFullPath = NULL;
    ubyte file[MAX_FILE_NAME];
    ubyte pemFile[MAX_FILE_NAME];
    byteBoolean foundEncAlg;
    ubyte4 encAlgLen;

    /* For serverkeygen case, check if keyalias file already exists in keystore */
    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)))
    {
        ubyte *pFile = NULL;

        /* Free the resource before using it */
        DIGI_FREE((void**)&pPkiComponentPath);
        DIGI_FREE((void**)&pFullPath);

        if (NULL != pEstArgs->pSkAlg)
        {
            status = TRUSTEDGE_EST_getPskAlgId(pEstArgs->pSkAlg, NULL, NULL);
            if (OK != status)
            {
                verbosePrintError("Invalid server keygen encryption algorithm.", status);
                goto exit;
            }
        }

        if (pEstArgs->pSkClntCert || pEstArgs->pSkClntKey)
        {
            if ( (NULL == pEstArgs->pSkClntCert) || (NULL == pEstArgs->pSkClntKey) )
            {
                status = ERR_INVALID_INPUT;
                verbosePrintError("Asymmetric server keygen must provide key and certificate ", status);
                goto exit;
            }
        }

        if (pEstArgs->pKeyAlias != NULL)
        {
            if (OK != (status = DIGI_CALLOC((void**)&pFile, 1, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias) + 5))) /* .pem + '\0'*/
            {
                goto exit;
            }
            if (OK != (status = DIGI_MEMCPY((ubyte*)pFile, pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias))))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMCPY(pFile + DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias), (ubyte *) ESTC_EXT_PEM, 4)))
            {
                goto exit;
            }
        }
        else
        {
            if (OK != (status = DIGI_CALLOC((void**)&pFile, 1, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE) + 5))) /* .pem + '\0' */
            {
                goto exit;
            }
            if (OK != (status = DIGI_MEMCPY((ubyte*)pFile, SERVERKEYGEN_KEY_FILE, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE))))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMCPY(pFile + DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE), (ubyte *) ESTC_EXT_PEM, 4)))
            {
                goto exit;
            }
        }

        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, KEYS_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char*)pFile, (char**)&pFullPath);

        /* Check if file is already present. If present then throw error */
        if (TRUE == FMGMT_pathExists (pFullPath, NULL))
        {
            status = ERR_FILE_EXISTS;
            verbosePrintError("Key file with same name already exists ", status);
        }
        DIGI_FREE((void**)&pFullPath);
        DIGI_FREE((void**)&pPkiComponentPath);
        if (OK != status)
        {
            goto exit;
        }

        /* Check if cert file is already present. If present then throw error */
        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, CERTS_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char*)pFile, (char**)&pFullPath);
        if (TRUE == FMGMT_pathExists (pFullPath, NULL))
        {
            status = ERR_FILE_EXISTS;
            verbosePrintError("Certificate file with same name already exists ", status);
        }

        DIGI_FREE((void**)&pFile);
        DIGI_FREE((void**)&pFullPath);
        DIGI_FREE((void**)&pPkiComponentPath);
        if (OK != status)
        {
            goto exit;
        }
    }

    /*Validate fullcmc reqtype arguments */
    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
        (NULL != pEstArgs->fullCmcReq.pFullCmcReqType) &&
        (!( (0 == DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW)) ||
            (0 == DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) ||
            (0 == DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL)) )))
    {
        status = ERR_INVALID_ARG;
        verbosePrintError("Invalid FullCMC request type argument.", status);
        goto exit;
    }

    /* For simpleenroll and fullcmc enrollment, ensure key type is provided */
    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD)) ||
        ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
         ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL) == 0))))
    {
        if (NULL == pEstArgs->pKeyType)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("Missing key type argument.", status);
            goto exit;
        }
    }

    /* Validation of keyAlias argument */
    /* For Simple-reenroll, Fullcmc (renew/rekey) requests keyAlias is Madatory */
    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) ||
        ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
         ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
         (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))))
    {
        /* keyAlias is a Mandatory Argument in case of simple-reenroll fullcmc rekey and fullcmc renew requests */
        /* Simple-reenroll, renew, rekey */
        if (NULL == pEstArgs->pKeyAlias)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("The -ka/--key-alias parameter is missing in arguments.", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)file, 0x00, MAX_FILE_NAME)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(file, pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pemFile, 0x00, MAX_FILE_NAME)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pemFile, pEstArgs->pKeyAlias, DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias))))
        {
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY(pemFile+DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }

        if ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
            (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
            ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) &&
             (NULL != pEstArgs->pKeyAlias2)))
        {/*fullcmc renew/rekey */
            if (OK > (status = DIGI_MEMCPY(file+DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias), (ubyte *) ESTC_EXT_DER, 4)))
            {
                goto exit;
            }

            /* Check if either the .pem or .der certifcate path is present in the keystore with mentioned alias name */
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, CERTS_PKI_COMPONENT);
            if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) file, &pFullPath), &pContents, &contentsLen)))
            {
                DIGI_FREE((void**)&pFullPath);

                if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                    (const char *) pemFile, &pFullPath), &pContents, &contentsLen)))
                {
                    verbosePrintError("Unable to read DER/PEM formatted cert with given alias.", status);
                }
            }
            DIGI_FREE((void**)&pFullPath);
            if (pContents == NULL)
            {
                status = (status != OK) ? status : ERR_NOT_FOUND;
                verbosePrintError("No certificate found with provided alias.", status);
                goto exit;
            }
            DIGI_FREE((void**)&pContents);
        }

        /* Check if either the .pem or .der key path is present in the keystore with mentioned alias name */
        if (OK > (status = DIGI_MEMCPY(file+DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias), (ubyte *) ESTC_EXT_DER, 4)))
        {
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY(pemFile+DIGI_STRLEN((sbyte*)pEstArgs->pKeyAlias), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }

        DIGI_FREE((void**)&pPkiComponentPath);
        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pKeyArgs->gpKeyStorePath, KEYS_PKI_COMPONENT);
        if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                            (const char *) file, &pFullPath), &pContents, &contentsLen)))
        {
            DIGI_FREE((void**)&pFullPath);

            if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath((char*)pPkiComponentPath,
                                (const char *) pemFile, &pFullPath), &pContents, &contentsLen)))
            {
                verbosePrintError("Unable to read DER/PEM formatted key with provided alias.", status);
            }
        }
        DIGI_FREE((void**)&pFullPath);
        if (pContents == NULL)
        {
            status = (status != OK) ? status : ERR_NOT_FOUND;
            verbosePrintError("No key file found with provided alias.", status);
            goto exit;
        }
    }

    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) ||
        ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
         ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
         (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))))
    {
        if (TRUE == pEstArgs->renewWindowSet)
        {
            /* Renew window must be non-negative.
             */
            if (0 > pEstArgs->renewWindow)
            {
                status = ERR_INVALID_INPUT;
                verbosePrintError("Negative renew windows value not allowed.", status);
                goto exit;
            }

#if ESTC_MAX_RENEW_WINDOW_SIZE != 0
            /* Check against maximum allowed renew window size
             */
            if (ESTC_MAX_RENEW_WINDOW_SIZE < pEstArgs->renewWindow)
            {
                status = ERR_INVALID_INPUT;
                verbosePrintError("Renew window value to large.", status);
                goto exit;
            }
#endif
        }
    }

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    if ( (NULL != strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD)) ||
         (NULL != strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD)) ||
         (NULL != strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)) )
    {
        pKeyArgs->gTap = FALSE;
    }

    if (pKeyArgs->gTap)
    {
        sbyte *pKeyType = pEstArgs->pKeyType;
        if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
                (0 == DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) )
        {
            pKeyType = pEstArgs->pNewKeyType;
        }
        if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            if (pKeyArgs->gKeyUsage < 1 || pKeyArgs->gKeyUsage > 4)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The tap key usage parameter value is invalid. Possible values are:", status);
                verbosePrintNL(MSG_LOG_INFO, "  TAP_KEY_USAGE_SIGNING,  TAP_KEY_USAGE_DECRYPT,  TAP_KEY_USAGE_GENERAL,  TAP_KEY_USAGE_ATTESTATION");
                goto exit;
            }
            if (pKeyArgs->gEncScheme > 3)
            {
                status = ERR_INVALID_ARG;

                verbosePrintError("The tap enc scheme parameter value is invalid. Possible values are:", status);
                verbosePrintNL(MSG_LOG_INFO, "  TAP_ENC_SCHEME_PKCS1_5,  TAP_ENC_SCHEME_OAEP_SHA1,  TAP_ENC_SCHEME_OAEP_SHA256");
                goto exit;
            }
            if (pKeyArgs->gSigScheme > 6)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The tap sign scheme parameter value is invalid. Possible values for RSA are:", status);
                verbosePrintNL(MSG_LOG_INFO, "  TAP_SIG_SCHEME_PKCS1_5,  TAP_SIG_SCHEME_PSS_SHA1,  TAP_SIG_SCHEME_PSS_SHA256,\n \
                TAP_SIG_SCHEME_PKCS1_5_SHA1,  TAP_SIG_SCHEME_PKCS1_5_SHA256,  TAP_SIG_SCHEME_PKCS1_5_DER");
                goto exit;
            }
        }
        else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            if ((pKeyArgs->gKeyUsage != TAP_KEY_USAGE_SIGNING) && (pKeyArgs->gKeyUsage != TAP_KEY_USAGE_ATTESTATION)
                                                            && (pKeyArgs->gKeyUsage != TAP_KEY_USAGE_GENERAL))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The tap key usage parameter value is invalid. Possible values are:", status);
                verbosePrintNL(MSG_LOG_INFO, "  TAP_KEY_USAGE_SIGNING\n  TAP_KEY_USAGE_GENERAL\n  TAP_KEY_USAGE_ATTESTATION");
                goto exit;
            }
            if ((0 != pKeyArgs->gSigScheme) && ((pKeyArgs->gSigScheme < 7) || (pKeyArgs->gSigScheme > 11)))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The tap sign scheme parameter value is invalid. Possible values for ECDSA are:", status);
                verbosePrintNL(MSG_LOG_INFO, "  TAP_SIG_SCHEME_ECDSA_SHA1,  TAP_SIG_SCHEME_ECDSA_SHA224,  TAP_SIG_SCHEME_ECDSA_SHA256,\n \
                TAP_SIG_SCHEME_ECDSA_SHA384,  TAP_SIG_SCHEME_ECDSA_SHA512");
                goto exit;
            }
        }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        if (NULL == pKeyArgs->gpServer)
        {
            status = ERR_EST;
            verbosePrintError("Mandatory argument -ts/--tap-server is not set.", status);
            goto exit;
        }
        if (-1 == pKeyArgs->gPort)
        {
            status = ERR_EST;
            verbosePrintError("Mandatory argument -tp/--tap-port is not set.", status);
            goto exit;
        }
#endif
    }
#endif

    if (pEstArgs->pPkcs8Pw && pEstArgs->pPkcs8EncAlg)
    {
        foundEncAlg = FALSE;
        encAlgLen = DIGI_STRLEN(pEstArgs->pPkcs8EncAlg);
#if defined(__ENABLE_DIGICERT_PKCS5__)
#if defined(__ENABLE_DES_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_DES))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_sha1_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_RC2) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_RC2))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_sha1_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_DES_CIPHER__) && defined(__ENABLE_DIGICERT_MD2__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_DES))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md2_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_RC2) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_RC2))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md2_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_DES_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_DES))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md5_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_RC2) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_RC2))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md5_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_3DES_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_3DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_3DES))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_3des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_DES_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_DES))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_RC2) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg,(sbyte *) PKCS8_ENC_ALG_P5_V2_RC2))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_AES_CIPHERS__)
#if !defined(__DISABLE_AES128_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_AES128) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_AES128))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_aes128;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_AES192_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_AES192) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_AES192))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_aes192;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_AES256_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_AES256) && 0 == DIGI_STRCMP(pEstArgs->pPkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_AES256))
        {
            pEstArgs->pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_aes256;
            foundEncAlg = TRUE;
        }
#endif
#endif /* !defined(__DISABLE_AES_CIPHERS__) */
#endif /*  __ENABLE_DIGICERT_PKCS5__  */
        if (FALSE == foundEncAlg)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS8 encryption algorithm is not valid.", status);
            goto exit;
        }
    }

    if (TRUE == pEstArgs->pkcs12Gen)
    {
        if (pEstArgs->pPkcs12EncAlg)
        {
            foundEncAlg = FALSE;
            encAlgLen = DIGI_STRLEN(pEstArgs->pPkcs12EncAlg);
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_2DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_2DES))
            {
                pEstArgs->pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_2des;
                foundEncAlg = TRUE;
            }
#endif
#if !defined(__DISABLE_3DES_CIPHERS__)
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_3DES) && 0 == DIGI_STRCMP(pEstArgs->pPkcs12EncAlg, (sbyte *) PKCS12_ENC_ALG_SHA_3DES))
            {
                pEstArgs->pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_3des;
                foundEncAlg = TRUE;
            }
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC2_40) && 0 == DIGI_STRCMP(pEstArgs->pPkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC2_40))
            {
                pEstArgs->pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc2_40;
                foundEncAlg = TRUE;
            }
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC2_128) && 0 == DIGI_STRCMP(pEstArgs->pPkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC2_128))
            {
                pEstArgs->pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc2_128;
                foundEncAlg = TRUE;
            }
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC4_40) && 0 == DIGI_STRCMP(pEstArgs->pPkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC4_40))
            {
                pEstArgs->pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc4_40;
                foundEncAlg = TRUE;
            }
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC4_128) && 0 == DIGI_STRCMP(pEstArgs->pPkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC4_128))
            {
                pEstArgs->pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc4_128;
                foundEncAlg = TRUE;
            }
#endif
            if (FALSE == foundEncAlg)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("PKCS12 encryption algorithm is not valid.", status);
                goto exit;
            }
        }

        if (pEstArgs->pPkcs12IntPw && DIGI_STRLEN((sbyte *)pEstArgs->pPkcs12IntPw) < 4)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS12 integrity password must be at least 4 characters.", status);
            goto exit;
        }
        if (pEstArgs->pPkcs12PriPw && DIGI_STRLEN((sbyte *)pEstArgs->pPkcs12PriPw) < 4)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS12 privacy password must be at least 4 characters.", status);
            goto exit;
        }
        if (pEstArgs->pPkcs12KeyPw && DIGI_STRLEN((sbyte *)pEstArgs->pPkcs12KeyPw) < 4)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS12 key password must be at least 4 characters.", status);
            goto exit;
        }
    }
exit:
    DIGI_FREE((void**)&pPkiComponentPath);
    DIGI_FREE((void**)&pContents);
    return status;
}

extern MSTATUS
TRUSTEDGE_EST_main(KeyGenArgs *pKeyArgs, TrustEdgeEstCtx *pEstArgs, TrustEdgeServiceCtx *pSrvCtx, void *pTapArgs)
{
    MSTATUS status = OK, tmpStatus = OK;
    intBoolean reOp = FALSE;
    sbyte4 retryCount = 0;

    (void) TRUSTEDGE_EST_init_defaults(pEstArgs, pKeyArgs);

    if (OK > (status = TRUSTEDGE_EST_validateArguments(pEstArgs, pKeyArgs)))
    {
        return status;
    }

    verbosePrintStringNL(MSG_LOG_INFO, "ServerIpAddr: ", pEstArgs->pServerIp);
    verbosePrintString1Int1NL(MSG_LOG_INFO, "ServerPort: ", pEstArgs->usServerPort);
    verbosePrintStringNL(MSG_LOG_INFO, "ServerURL: ", pEstArgs->pUrl);
    if (NULL != pEstArgs->pUserName)
    {
        verbosePrintStringNL(MSG_LOG_INFO, "User: ", pEstArgs->pUserName);
    }
    verbosePrintStringNL(MSG_LOG_INFO, "KeyStore: ", pKeyArgs->gpKeyStorePath);
    if (pEstArgs->pTlsCert != NULL)
    {
        verbosePrintStringNL(MSG_LOG_INFO, "TLSCert: ", pEstArgs->pTlsCert);
    }
    verbosePrintStringNL(MSG_LOG_INFO, "ServerName: ", pEstArgs->pServerName);
    if ((NULL != pEstArgs->pUrl) &&
            (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD) ||
            NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD) ||
            NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD) ||
            NULL != strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)))
    {
        if (NULL != pEstArgs->pKeyType)
        {
            verbosePrintStringNL(MSG_LOG_INFO, "KeyType: ", pEstArgs->pKeyType);
        }
#ifdef __ENABLE_DIGICERT_TAP__
        if (TRUE == pKeyArgs->gTap)
        {
            verbosePrintString1Int1NL(MSG_LOG_INFO, "TapModuleId: ", pKeyArgs->gModNum);
            if (NULL != pEstArgs->pTapKeyHandleStr)
            {
                verbosePrintStringNL(MSG_LOG_INFO, "TapKeyHandle: ", pEstArgs->pTapKeyHandleStr);
            }
#if !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            if (0 != pEstArgs->tapKeyPrimary)
            {
                verbosePrintString1Int1NL(MSG_LOG_INFO, "TapKeyPrimary: ", pEstArgs->tapKeyPrimary);
            }
            if (NULL != pEstArgs->pTapKeyTokenHierarchy)
            {
                verbosePrintStringNL(MSG_LOG_INFO, "TapTokenHierarchy: ", pEstArgs->pTapKeyTokenHierarchy);
            }
            if (NULL != pEstArgs->pTapKeyNonceNvIndex)
            {
                verbosePrintStringNL(MSG_LOG_INFO, "TapKeyNonceNvIndex: ", pEstArgs->pTapKeyNonceNvIndex);
            }
            if (NULL != pEstArgs->pTapCertificateNvIndexStr)
            {
                verbosePrintStringNL(MSG_LOG_INFO, "TapCertificateNvIndex: ", pEstArgs->pTapCertificateNvIndexStr);
            }
            verbosePrintString1Int1NL(MSG_LOG_INFO, "TapKeyUsage: ", pKeyArgs->gKeyUsage);
            if (0 != pKeyArgs->gSigScheme)
            {
                verbosePrintString1Int1NL(MSG_LOG_INFO, "TapSignScheme: ", pKeyArgs->gSigScheme);
            }
            if (0 != pKeyArgs->gEncScheme)
            {
                verbosePrintString1Int1NL(MSG_LOG_INFO, "TapEncScheme: ", pKeyArgs->gEncScheme);
            }
#endif
        }

        if (EXT_ENROLL_FLOW_TPM2_IDEVID == pEstArgs->flow)
        {
            if (TAP_KEY_USAGE_GENERAL != pKeyArgs->gKeyUsage)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("TPM2 IDevID enrollment requires TAP general key", status);
                goto exit;
            }
        }
        else if (EXT_ENROLL_FLOW_TPM2_IAK == pEstArgs->flow)
        {
            if (TAP_KEY_USAGE_ATTESTATION != pKeyArgs->gKeyUsage)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("TPM2 IAK enrollment requires TAP attest key", status);
                goto exit;
            }
        }
#endif
        verbosePrintStringNL(MSG_LOG_INFO, "KeySource: ", pEstArgs->pKeySource);
        verbosePrintString1Int1NL(MSG_LOG_INFO, "KeySize: ", pEstArgs->usKeySize);
        verbosePrintString1Int1NL(MSG_LOG_INFO, "HasExtendedAttributes: ", pEstArgs->hasAttrib);
        verbosePrintStringNL(MSG_LOG_INFO, "CSRConf: ", (FALSE == pEstArgs->serviceCtx.serviceMode) ? pKeyArgs->gpInCsrFile : (sbyte *)"Inline JSON");

        if (NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD))
        {
            verbosePrintStringNL(MSG_LOG_INFO, "FullCMCReqType: ", pEstArgs->fullCmcReq.pFullCmcReqType);
        }
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EST, &gHwAccelCtx);
    if (OK != status)
        goto exit;

    if (OK > (status = TRUSTEDGE_EST_initUpcallsAndCertStores(pEstArgs, pKeyArgs, pTapArgs)))
    {
        verbosePrintError("Error in initializing certstore - ", status);
        goto exit;
    }

    ubyte4 tlsCertLen = ((pEstArgs->pTlsCert != NULL) ? DIGI_STRLEN(pEstArgs->pTlsCert) : 0);

    if ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) ||
    ((NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
        ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
        (DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))))
    {
        if (TRUE == pEstArgs->renewWindowSet)
        {
            /* If the est renew window argument was provided then check
                * if the rekey/renew/simplereenroll operations need to be
                * performed.
                */
            status = TRUSTEDGE_EST_checkCertificateRenewWindow(pEstArgs, &reOp);
            if (OK != status)
            {
                verbosePrintError(
                    "Failed to check certificate renew window.", status);
                goto exit;
            }

            /* If the renewal operation is not required based on the window
                * then exit.
                */
            if (FALSE == reOp)
            {
                verbosePrintNL(
                    MSG_LOG_INFO,
                    "Certificate renewal operation not required");
                goto exit;
            }
        }
    }

    while (retryCount < pEstArgs->serviceCtx.maxRetryCount)
    {
        status = EST_openConnection(pCertStore, (ubyte*)pEstArgs->pServerIp, DIGI_STRLEN(pEstArgs->pServerIp),
                            pEstArgs->usServerPort, (ubyte*)pEstArgs->pServerName, DIGI_STRLEN(pEstArgs->pServerName),
                            &gSslConnectionInstance, &pEstArgs->pHttpContext, pEstArgs->pTlsCert, tlsCertLen, pEstArgs->isOcspRequired, pEstArgs->requirePQC);
        retryCount++;
        if (OK > status)
        {
            if (retryCount == pEstArgs->serviceCtx.maxRetryCount || ERR_TCP_CONNECT_ERROR != status)
            {
                verbosePrintError("Unable to connect to the server. ", status);
                goto exit;
            }
            else
            {
                verbosePrintString1Int1NL(MSG_LOG_INFO, "WARNING: Retrying initial connection, previous attempt status= ", status);
            }
        }
        else
        {
            break;
        }
    }
    if (OK > (status = TRUSTEDGE_EST_processRequest(pEstArgs, pKeyArgs, pSrvCtx, pTapArgs)))
    {
        verbosePrintError("Unable to process the request. ", status);
        goto exit;
    }

    if (OK != pEstArgs->serviceCtx.cmdStatus)
    {
        status = pEstArgs->serviceCtx.cmdStatus;
    }
exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EST, &gHwAccelCtx);

    if(pEstArgs->pHttpContext)
    {
        if (OK > (tmpStatus = HTTP_CONTEXT_releaseContext(&pEstArgs->pHttpContext)))
        {
            status = tmpStatus;
            verbosePrintError("Unable to release HTTP context. ", status);
        }
    }

    if (pEstArgs->pAuthStr)
        DIGI_FREE((void **)&pEstArgs->pAuthStr);

    TRUSTEDGE_EST_uninitUpcallsAndCertStores();
#ifndef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
    if(gMocanaAppsRunning)
        gMocanaAppsRunning--;
#endif
    return status;
}

static MSTATUS TRUSTEDGE_EST_CB_validateRootCertificate(const void* arg,
    CStream cs,
    struct ASN1_ITEM* pCertificate,
    sbyte4 chainLength)
{
    MOC_UNUSED(chainLength);
    MSTATUS status = OK;
    ubyte* buffer = NULL;
    ubyte* pEncodedCert = NULL;
    ubyte4 encodedCertLen = 0;

    buffer = (ubyte*)CS_memaccess(cs, (/*FSL*/sbyte4)(pCertificate->dataOffset - pCertificate->headerSize),
        (/*FSL*/sbyte4)(pCertificate->length + pCertificate->headerSize));

    if (OK > (status = BASE64_encodeMessage(buffer, pCertificate->length + pCertificate->headerSize,
        &pEncodedCert, &encodedCertLen)))
    {
        verbosePrintError("Unable to encode root certificate.", status);
        goto exit;
    }
    if (NULL != arg)
    {
        if (OK > (status = EST_validateReceivedCertificate(MOC_HW(gHwAccelCtx) (struct certStore *) arg, pEncodedCert, encodedCertLen, NULL)))
        {
            verbosePrintError("Unable to validate certificate.", status);
            goto exit;
        }
    }
    else
    {
        if (!pCertStore)
        {
            if (OK > (status = CERT_STORE_createStore(&pCertStore)))
            {
                verbosePrintError("Unable to create certstore for validating root certificate.", status);
                goto exit;
            }
            if (OK > (status = TRUSTEDGE_EST_constructCertStoreFromDir(pCertStore, NULL)))
            {
                verbosePrintError("Unable to construct certstore for validating root certificate.", status);
                goto exit;
            }
        }
        if (OK > (status = EST_validateReceivedCertificate(MOC_HW(gHwAccelCtx) pCertStore, pEncodedCert, encodedCertLen, NULL)))
        {
            verbosePrintError("Unable to validate certificate.", status);
            goto exit;
        }
    }


exit:
    if (pEncodedCert)
    {
        DIGI_FREE((void **)&pEncodedCert);
    }
    if (buffer)
        CS_stopaccess(cs, buffer);
    return status;
}
