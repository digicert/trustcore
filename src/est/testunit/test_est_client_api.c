/*
 * test_est_client_api.c
 *
 * Unit tests for EST Client API functions
 *
 * Copyright Digicert 2026 All Rights Reserved.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "cmocka.h"
#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mtcp.h"
#include "common/mocana.h"
#include "common/mfmgmt.h"
#include "common/debug_console.h"
#include "common/sizedbuffer.h"
#include "common/random.h"
#include "common/base64.h"
#include "crypto/cert_store.h"
#include "crypto/crypto.h"
#include "crypto/pubcrypto.h"
#include "crypto/hw_accel.h"
#include "crypto/rsa.h"
#include "crypto/keyblob.h"
#include "crypto/pkcs10.h"
#include "crypto_interface/cryptointerface.h"
#include "http/http_context.h"
#include "http/http.h"
#include "http/http_auth.h"
#include "http/http_common.h"
#include "http/client/http_request.h"
#include "ssl/ssl.h"
#include "est/est_client_api.h"

struct certStore;

static ubyte *g_pCsrData = NULL;
static ubyte4 g_csrDataLen = 0;
static ubyte *g_pAuthString = NULL;
static ubyte4 g_authStringLen = 0;
static ubyte *g_pEnrolledCert = NULL;
static ubyte4 g_enrolledCertLen = 0;
static ubyte *g_pEnrolledKeyBlob = NULL;
static ubyte4 g_enrolledKeyBlobLen = 0;
static ubyte *g_pContentType = NULL;
static ubyte4 g_contentTypeLen = 0;

static sbyte4 test_http_requestBodyCallback(httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie)
{
    MOC_UNUSED(pRequestBodyCookie);

    if (g_pCsrData != NULL && g_csrDataLen > 0)
    {
        *ppDataToSend = MALLOC(g_csrDataLen);
        if (*ppDataToSend == NULL)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        DIGI_MEMCPY(*ppDataToSend, g_pCsrData, g_csrDataLen);
        *pDataLength = g_csrDataLen;
        pHttpContext->isBodyDone = TRUE;

        return OK;
    }

    return EST_requestBodyCallback(pHttpContext, ppDataToSend, pDataLength, pRequestBodyCookie);
}

static sbyte4 test_http_responseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(isContinueFromBlock);

    if (pHttpContext->httpStatusResponse >= 400)
    {
        DB_PRINT("DEBUG: HTTP error response received\n");
    }
    return OK;
}

static sbyte4 test_http_responseBodyCallback(httpContext *pHttpContext, ubyte *pDataReceived, ubyte4 dataLength, sbyte4 isContinueFromBlock)
{
    return EST_responseBodyCallbackHandle(pHttpContext, pDataReceived, dataLength, isContinueFromBlock);
}

static sbyte4 test_http_tcpSendCallback(httpContext *pHttpContext, sbyte4 socket,
        ubyte *pDataToSend, ubyte4 numBytesToSend,
        ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(socket);
    MOC_UNUSED(pDataToSend);
    MOC_UNUSED(isContinueFromBlock);

    *pRetNumBytesSent = numBytesToSend;
    return OK;
}

static sbyte4 test_http_sslSendCallback(httpContext *pHttpContext, sbyte4 socket,
        ubyte *pDataToSend, ubyte4 numBytesToSend,
        ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);

    sbyte4 sslConnectionInst = SSL_getInstanceFromSocket(socket);
    *pRetNumBytesSent = SSL_send(sslConnectionInst, (sbyte*)pDataToSend, numBytesToSend);

    return OK;
}

static struct certStore *g_pCertStore = NULL;
static const ubyte g_realServerAddr[] = "clientauth.demo.one.digicert.com";
static const ubyte g_estCaCertsPath[] = "/.well-known/est/IOT_c75d6gui/cacerts";
static const ubyte g_estCsrAttrsPath[] = "/.well-known/est/IOT_c75d6gui/csrattrs";
static const ubyte g_estSimpleEnrollPath[] = "/.well-known/est/IOT_c75d6gui/simpleenroll";
static const ubyte g_estSimpleReenrollPath[] = "/.well-known/est/IOT_c75d6gui/simplereenroll";
static const sbyte g_defaultUserAgent[] = "EST Test Client";
static const ubyte g_mockKeyAlias[] = "test_key";
static const ubyte g_mockHashType[] = "SHA256";
static ubyte g_mockConfigFile[256] = {0};
static const ubyte g_estUsername[] = "estuser";
static const ubyte *g_estPassword = NULL;

/* DigiCert Global Root G2 certificate
 * downloaded from http://cacerts.digicert.com/DigiCertGlobalRootG2.crt)
 */
static const ubyte digicert_global_root_g2_crt[] =
{
  0x30, 0x82, 0x03, 0x8e, 0x30, 0x82, 0x02, 0x76, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x10, 0x03, 0x3a, 0xf1, 0xe6, 0xa7, 0x11, 0xa9, 0xa0, 0xbb,
  0x28, 0x64, 0xb1, 0x1d, 0x09, 0xfa, 0xe5, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x61,
  0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
  0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c,
  0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63,
  0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77,
  0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e,
  0x63, 0x6f, 0x6d, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47,
  0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x47,
  0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x33, 0x30, 0x38, 0x30, 0x31, 0x31,
  0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x38, 0x30, 0x31,
  0x31, 0x35, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x61, 0x31,
  0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
  0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44,
  0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31,
  0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77, 0x77,
  0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63,
  0x6f, 0x6d, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
  0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6c,
  0x6f, 0x62, 0x61, 0x6c, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x47, 0x32,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbb, 0x37, 0xcd,
  0x34, 0xdc, 0x7b, 0x6b, 0xc9, 0xb2, 0x68, 0x90, 0xad, 0x4a, 0x75, 0xff,
  0x46, 0xba, 0x21, 0x0a, 0x08, 0x8d, 0xf5, 0x19, 0x54, 0xc9, 0xfb, 0x88,
  0xdb, 0xf3, 0xae, 0xf2, 0x3a, 0x89, 0x91, 0x3c, 0x7a, 0xe6, 0xab, 0x06,
  0x1a, 0x6b, 0xcf, 0xac, 0x2d, 0xe8, 0x5e, 0x09, 0x24, 0x44, 0xba, 0x62,
  0x9a, 0x7e, 0xd6, 0xa3, 0xa8, 0x7e, 0xe0, 0x54, 0x75, 0x20, 0x05, 0xac,
  0x50, 0xb7, 0x9c, 0x63, 0x1a, 0x6c, 0x30, 0xdc, 0xda, 0x1f, 0x19, 0xb1,
  0xd7, 0x1e, 0xde, 0xfd, 0xd7, 0xe0, 0xcb, 0x94, 0x83, 0x37, 0xae, 0xec,
  0x1f, 0x43, 0x4e, 0xdd, 0x7b, 0x2c, 0xd2, 0xbd, 0x2e, 0xa5, 0x2f, 0xe4,
  0xa9, 0xb8, 0xad, 0x3a, 0xd4, 0x99, 0xa4, 0xb6, 0x25, 0xe9, 0x9b, 0x6b,
  0x00, 0x60, 0x92, 0x60, 0xff, 0x4f, 0x21, 0x49, 0x18, 0xf7, 0x67, 0x90,
  0xab, 0x61, 0x06, 0x9c, 0x8f, 0xf2, 0xba, 0xe9, 0xb4, 0xe9, 0x92, 0x32,
  0x6b, 0xb5, 0xf3, 0x57, 0xe8, 0x5d, 0x1b, 0xcd, 0x8c, 0x1d, 0xab, 0x95,
  0x04, 0x95, 0x49, 0xf3, 0x35, 0x2d, 0x96, 0xe3, 0x49, 0x6d, 0xdd, 0x77,
  0xe3, 0xfb, 0x49, 0x4b, 0xb4, 0xac, 0x55, 0x07, 0xa9, 0x8f, 0x95, 0xb3,
  0xb4, 0x23, 0xbb, 0x4c, 0x6d, 0x45, 0xf0, 0xf6, 0xa9, 0xb2, 0x95, 0x30,
  0xb4, 0xfd, 0x4c, 0x55, 0x8c, 0x27, 0x4a, 0x57, 0x14, 0x7c, 0x82, 0x9d,
  0xcd, 0x73, 0x92, 0xd3, 0x16, 0x4a, 0x06, 0x0c, 0x8c, 0x50, 0xd1, 0x8f,
  0x1e, 0x09, 0xbe, 0x17, 0xa1, 0xe6, 0x21, 0xca, 0xfd, 0x83, 0xe5, 0x10,
  0xbc, 0x83, 0xa5, 0x0a, 0xc4, 0x67, 0x28, 0xf6, 0x73, 0x14, 0x14, 0x3d,
  0x46, 0x76, 0xc3, 0x87, 0x14, 0x89, 0x21, 0x34, 0x4d, 0xaf, 0x0f, 0x45,
  0x0c, 0xa6, 0x49, 0xa1, 0xba, 0xbb, 0x9c, 0xc5, 0xb1, 0x33, 0x83, 0x29,
  0x85, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f,
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
  0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
  0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1d, 0x06, 0x03, 0x55,
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x4e, 0x22, 0x54, 0x20, 0x18, 0x95,
  0xe6, 0xe3, 0x6e, 0xe6, 0x0f, 0xfa, 0xfa, 0xb9, 0x12, 0xed, 0x06, 0x17,
  0x8f, 0x39, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x60, 0x67,
  0x28, 0x94, 0x6f, 0x0e, 0x48, 0x63, 0xeb, 0x31, 0xdd, 0xea, 0x67, 0x18,
  0xd5, 0x89, 0x7d, 0x3c, 0xc5, 0x8b, 0x4a, 0x7f, 0xe9, 0xbe, 0xdb, 0x2b,
  0x17, 0xdf, 0xb0, 0x5f, 0x73, 0x77, 0x2a, 0x32, 0x13, 0x39, 0x81, 0x67,
  0x42, 0x84, 0x23, 0xf2, 0x45, 0x67, 0x35, 0xec, 0x88, 0xbf, 0xf8, 0x8f,
  0xb0, 0x61, 0x0c, 0x34, 0xa4, 0xae, 0x20, 0x4c, 0x84, 0xc6, 0xdb, 0xf8,
  0x35, 0xe1, 0x76, 0xd9, 0xdf, 0xa6, 0x42, 0xbb, 0xc7, 0x44, 0x08, 0x86,
  0x7f, 0x36, 0x74, 0x24, 0x5a, 0xda, 0x6c, 0x0d, 0x14, 0x59, 0x35, 0xbd,
  0xf2, 0x49, 0xdd, 0xb6, 0x1f, 0xc9, 0xb3, 0x0d, 0x47, 0x2a, 0x3d, 0x99,
  0x2f, 0xbb, 0x5c, 0xbb, 0xb5, 0xd4, 0x20, 0xe1, 0x99, 0x5f, 0x53, 0x46,
  0x15, 0xdb, 0x68, 0x9b, 0xf0, 0xf3, 0x30, 0xd5, 0x3e, 0x31, 0xe2, 0x8d,
  0x84, 0x9e, 0xe3, 0x8a, 0xda, 0xda, 0x96, 0x3e, 0x35, 0x13, 0xa5, 0x5f,
  0xf0, 0xf9, 0x70, 0x50, 0x70, 0x47, 0x41, 0x11, 0x57, 0x19, 0x4e, 0xc0,
  0x8f, 0xae, 0x06, 0xc4, 0x95, 0x13, 0x17, 0x2f, 0x1b, 0x25, 0x9f, 0x75,
  0xf2, 0xb1, 0x8e, 0x99, 0xa1, 0x6f, 0x13, 0xb1, 0x41, 0x71, 0xfe, 0x88,
  0x2a, 0xc8, 0x4f, 0x10, 0x20, 0x55, 0xd7, 0xf3, 0x14, 0x45, 0xe5, 0xe0,
  0x44, 0xf4, 0xea, 0x87, 0x95, 0x32, 0x93, 0x0e, 0xfe, 0x53, 0x46, 0xfa,
  0x2c, 0x9d, 0xff, 0x8b, 0x22, 0xb9, 0x4b, 0xd9, 0x09, 0x45, 0xa4, 0xde,
  0xa4, 0xb8, 0x9a, 0x58, 0xdd, 0x1b, 0x7d, 0x52, 0x9f, 0x8e, 0x59, 0x43,
  0x88, 0x81, 0xa4, 0x9e, 0x26, 0xd5, 0x6f, 0xad, 0xdd, 0x0d, 0xc6, 0x37,
  0x7d, 0xed, 0x03, 0x92, 0x1b, 0xe5, 0x77, 0x5f, 0x76, 0xee, 0x3c, 0x8d,
  0xc4, 0x5d, 0x56, 0x5b, 0xa2, 0xd9, 0x66, 0x6e, 0xb3, 0x35, 0x37, 0xe5,
  0x32, 0xb6
};

static const ubyte4 digicert_global_root_g2_crt_len = 914;

static MSTATUS setup_cert_store_with_roots(struct certStore **ppCertStore)
{
    MSTATUS status = OK;
    struct certStore *pCertStore = NULL;

    status = CERT_STORE_createStore(&pCertStore);
    if (OK != status)
    {
        DB_PRINT("ERROR: CERT_STORE_createStore failed with status %d\n", status);
        goto exit;
    }

    status = CERT_STORE_addTrustPoint(pCertStore,
                                     digicert_global_root_g2_crt,
                                     digicert_global_root_g2_crt_len);
    if (OK != status)
    {
        DB_PRINT("ERROR: CERT_STORE_addTrustPoint failed with status %d\n", status);
        goto exit;
    }

    *ppCertStore = pCertStore;
    pCertStore = NULL;

exit:

    if (pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }
    return status;
}

static MSTATUS create_test_config_file(void)
{
    MSTATUS status = OK;
    FileDescriptor pFile = NULL;
    ubyte4 written = 0;
    const sbyte pConfigContent[] =
        "##Subject\n"
        "countryName=IN\n"
        "commonName=est-test-client\n"
        "stateOrProvinceName=Delhi\n"
        "localityName=Delhi\n"
        "organizationName=DigiCert\n"
        "organizationalUnitName=RnD\n"
        "##Requested Extensions\n"
        "hasBasicConstraints=true\n"
        "isCA=false\n"
        "certPathLen=-1\n"
        "keyUsage=digitalSignature\n"
        "##subjectAltNames=numSANs; value1, type1; valueN, typeN\n"
        "##subjectAltNames=2; *.mydomain.com, 2; *.mydomain.net, 2\n";

    sprintf((char*)g_mockConfigFile, "/tmp/test_csr_config_%d.toml", (int)time(NULL));

    status = FMGMT_fopen((char*)g_mockConfigFile, "w", &pFile);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to create config file %s\n", g_mockConfigFile);
        goto exit;
    }

    status = FMGMT_fwrite(pConfigContent, 1, DIGI_STRLEN(pConfigContent), pFile, &written);
    if (OK != status || DIGI_STRLEN(pConfigContent) != written)
    {
        DB_PRINT("ERROR: Failed to write config file content\n");
        goto exit;
    }

exit:

    FMGMT_fclose(&pFile);
    return status;
}

static MSTATUS cleanup_test_config_file(void)
{
    if (DIGI_STRLEN((char*)g_mockConfigFile) > 0)
    {
        if (OK != FMGMT_remove((char*)g_mockConfigFile, FALSE))
        {
            DB_PRINT("WARNING: Failed to remove config file %s\n", g_mockConfigFile);
        }
        DIGI_MEMSET(g_mockConfigFile, 0, sizeof(g_mockConfigFile));
    }

    return OK;
}

static int est_client_setup(void **state)
{
    MOC_UNUSED(state);
    MSTATUS status = OK;

    const char *envPassword = getenv("EST_PASS");
    if (envPassword == NULL)
    {
        DB_PRINT("ERROR: EST_PASS environment variable is not set\n");
        return ERR_NULL_POINTER;
    }

    g_estPassword = (const ubyte *)envPassword;

    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        DB_PRINT("ERROR: DIGICERT_initDigicert failed with status %d\n", status);
        goto exit;
    }

    status = SSL_init(0, 10);
    if (OK != status)
    {
        DB_PRINT("ERROR: SSL_init failed with status %d\n", status);
        goto exit;
    }

    status = HTTP_initClient(10);
    if (OK != status)
    {
        DB_PRINT("ERROR: HTTP_initClient failed with status %d\n", status);
        goto exit;
    }

    HTTP_httpSettings()->funcPtrHttpTcpSend = test_http_sslSendCallback;
    HTTP_httpSettings()->funcPtrRequestBodyCallback = test_http_requestBodyCallback;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = test_http_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = test_http_responseBodyCallback;

    status = create_test_config_file();
    if (OK != status)
    {
        DB_PRINT("ERROR: create_test_config_file failed with status %d\n", status);
        goto exit;
    }

exit:
    return status;
}

static int est_client_teardown(void **state)
{
    MOC_UNUSED(state);
    MSTATUS status = OK;

    if (NULL != g_pEnrolledCert)
    {
        DIGI_FREE((void**)&g_pEnrolledCert);
        g_enrolledCertLen = 0;
    }

    if (NULL != g_pEnrolledKeyBlob)
    {
        DIGI_FREE((void**)&g_pEnrolledKeyBlob);
        g_enrolledKeyBlobLen = 0;
    }

    cleanup_test_config_file();

    status = SSL_releaseTables();
    if (OK != status)
    {
        DB_PRINT("ERROR: SSL_releaseTables failed with status %d\n", status);
        goto exit;
    }

    status = DIGICERT_freeDigicert();
    if (OK != status)
    {
        DB_PRINT("ERROR: DIGICERT_freeDigicert failed with status %d\n", status);
        goto exit;
    }

exit:
    return status;
}

static void test_est_send_ca_certs_request(void **state)
{
    MOC_UNUSED(state);
    struct certStore *pCertStore = NULL;
    sbyte4 connectionHandle = 0;
    httpContext *pHttpCtx = NULL;
    MSTATUS status = OK;

    status = setup_cert_store_with_roots(&pCertStore);
    assert_non_null(pCertStore);

    status = EST_openConnection(
        pCertStore,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        443,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        &connectionHandle,
        &pHttpCtx,
        NULL,
        0,
        FALSE,
        FALSE
    );

    assert_int_equal(status, OK);
    assert_non_null(pHttpCtx);

    status = EST_sendCaCertsRequest(
        pHttpCtx,
        connectionHandle,
        (ubyte*)g_estCaCertsPath,
        (ubyte4)DIGI_STRLEN((char*)g_estCaCertsPath),
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        (sbyte*)g_defaultUserAgent
    );

    assert_true(OK == status);

    EST_closeConnection(pHttpCtx, connectionHandle);

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }
}

static void test_est_send_csr_attrs_request(void **state)
{
    MOC_UNUSED(state);
    struct certStore *pCertStore = NULL;
    sbyte4 connectionHandle = 0;
    httpContext *pHttpCtx = NULL;
    MSTATUS status = OK;

    status = setup_cert_store_with_roots(&pCertStore);
    assert_non_null(pCertStore);

    status = EST_openConnection(
        pCertStore,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        443,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        &connectionHandle,
        &pHttpCtx,
        NULL,
        0,
        FALSE,
        FALSE
    );

    assert_int_equal(status, OK);
    assert_non_null(pHttpCtx);

    status = EST_sendCsrAttrsRequest(
        pHttpCtx,
        connectionHandle,
        (ubyte*)g_estCsrAttrsPath,
        (ubyte4)DIGI_STRLEN((char*)g_estCsrAttrsPath),
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        (sbyte*)g_defaultUserAgent
    );

    assert_true(OK == status);

    EST_closeConnection(pHttpCtx, connectionHandle);

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }
}

static void test_est_send_simple_enroll_request(void **state)
{
    MOC_UNUSED(state);
    struct certStore *pCertStore = NULL;
    sbyte4 connectionHandle = 0;
    httpContext *pHttpCtx = NULL;
    MSTATUS status = OK;
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;
    RSAKey *pRsaKey = NULL;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    randomContext *pRandomCtx = NULL;

    status = setup_cert_store_with_roots(&pCertStore);
    assert_non_null(pCertStore);

    status = RSA_createKey(&pRsaKey);
    if (OK != status)
    {
        DB_PRINT("ERROR: RSA_createKey failed with status %d\n", status);
        goto exit;
    }

    status = RANDOM_acquireContext(&pRandomCtx);
    if (OK != status)
    {
        DB_PRINT("ERROR: RANDOM_acquireContext failed with status %d\n", status);
        goto exit;
    }

    status = RSA_generateKey(MOC_RSA(NULL) pRandomCtx, pRsaKey, 2048, NULL);

    MSTATUS releaseStatus = RANDOM_releaseContext(&pRandomCtx);
    if (OK != releaseStatus)
    {
        DB_PRINT("ERROR: RANDOM_releaseContext failed with status %d\n", releaseStatus);
    }

    if (OK != status)
    {
        DB_PRINT("ERROR: RSA_generateKey failed with status %d\n", status);
        goto exit;
    }

    status = KEYBLOB_makeRSAKeyBlob(MOC_RSA(NULL) pRsaKey, &pKeyBlob, &keyBlobLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: KEYBLOB_makeRSAKeyBlob failed with status %d\n", status);
        goto exit;
    }

    status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                              (ubyte*)g_mockKeyAlias,
                                              (ubyte4)DIGI_STRLEN((char*)g_mockKeyAlias),
                                              pKeyBlob,
                                              keyBlobLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: CERT_STORE_addIdentityNakedKeyEx failed with status %d\n", status);
        goto exit;
    }

    status = EST_generateCSRRequestFromConfig(
        MOC_HW(NULL)
        pCertStore,
        0,
        (ubyte*)g_mockConfigFile,
        NULL,
        2,
        (ubyte*)g_mockKeyAlias,
        (ubyte4)DIGI_STRLEN((char*)g_mockKeyAlias),
        NULL,
        akt_rsa,
        0,
        (ubyte*)g_mockHashType,
        (ubyte4)DIGI_STRLEN((char*)g_mockHashType),
        &pCsr,
        &csrLen
    );

    if (OK != status)
    {
        DB_PRINT("ERROR: EST_generateCSRRequestFromConfig failed with status %d\n", status);
        goto exit;
    }

    g_pCsrData = pCsr;
    g_csrDataLen = csrLen;

    status = EST_openConnection(
        pCertStore,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        443,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        &connectionHandle,
        &pHttpCtx,
        NULL,
        0,
        FALSE,
        FALSE
    );

    assert_int_equal(status, OK);
    assert_non_null(pHttpCtx);

    status = HTTP_AUTH_generateBasicAuthorization(pHttpCtx,
                        (ubyte*)g_estUsername, (ubyte4)DIGI_STRLEN((char*)g_estUsername),
                        (ubyte*)g_estPassword, (ubyte4)DIGI_STRLEN((char*)g_estPassword),
                        &g_pAuthString, &g_authStringLen);

    if (OK == status&& g_authStringLen > 0)
    {
        status = HTTP_COMMON_setHeaderIfNotSet(pHttpCtx, Authorization, g_pAuthString, g_authStringLen);
        if (OK != status)
        {
            DB_PRINT("DEBUG: Failed to set Authorization header, status = %d\n", status);
        }
    }
    else
    {
        DB_PRINT("DEBUG: Failed to generate basic authorization, status = %d\n", status);
    }

    status = EST_sendSimpleEnrollRequest(
        pHttpCtx,
        connectionHandle,
        (ubyte*)g_estSimpleEnrollPath,
        (ubyte4)DIGI_STRLEN((char*)g_estSimpleEnrollPath),
        csrLen,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        (sbyte*)g_defaultUserAgent
    );

exit:
    if (NULL != pRsaKey)
    {
        RSA_freeKey(&pRsaKey, NULL);
    }

    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void**)&pKeyBlob);
    }

    if (NULL != pCsr)
    {
        DIGI_FREE((void**)&pCsr);
        g_pCsrData = NULL;
        g_csrDataLen = 0;
    }

    if (NULL != g_pAuthString)
    {
        DIGI_FREE((void**)&g_pAuthString);
        g_authStringLen = 0;
    }

    EST_closeConnection(pHttpCtx, connectionHandle);

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }

    assert_true(OK == status);
}

static void test_est_send_simple_reenroll_request(void **state)
{
    MOC_UNUSED(state);
    struct certStore *pCertStore = NULL;
    sbyte4 connectionHandle = 0;
    httpContext *pHttpCtx = NULL;
    MSTATUS status = OK;
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;
    ubyte *pLocalEnrolledCert = NULL;
    ubyte4 localEnrolledCertLen = 0;
    ubyte *pLocalEnrolledKeyBlob = NULL;
    ubyte4 localEnrolledKeyBlobLen = 0;
    struct SizedBuffer *pParsedCertificates = NULL;
    ubyte4 numParsedCerts = 0;
    ubyte *pContentType = NULL;
    ubyte4 contentTypeLen = 0;
    ubyte *pHttpResponse = NULL;
    ubyte4 httpResponseLen = 0;
    ubyte *pDecodedResponse = NULL;
    ubyte4 decodedResponseLen = 0;
    ubyte *pDerCert = NULL;
    RSAKey *pRsaKey = NULL;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    randomContext *pRandomCtx = NULL;
    ubyte4 filteredLen = 0;
    ubyte *pSimpleContentType = "application/pkcs7-mime";
    ubyte4 derCertLen = 0;
    sbyte pTempCertFile[256] = {0};
    sbyte pTempKeyFile[256] = {0};
    FileDescriptor pCertFile = NULL;
    ubyte4 written = 0;
    ubyte* pReadCert = NULL;
    ubyte4 readCertLen = 0;
    FileDescriptor pKeyFile = NULL;
    ubyte* pReadKeyBlob = NULL;
    ubyte4 readKeyBlobLen = 0;
    ubyte *pClientKeyAlias = "reenroll_identity";
    struct SizedBuffer certificate;

    status = setup_cert_store_with_roots(&pCertStore);
    assert_non_null(pCertStore);

    status = RSA_createKey(&pRsaKey);
    if (OK != status)
    {
        DB_PRINT("ERROR: RSA_createKey failed with status %d\n", status);
        goto exit;
    }

    status = RANDOM_acquireContext(&pRandomCtx);
    if (OK != status)
    {
        DB_PRINT("ERROR: RANDOM_acquireContext failed with status %d\n", status);
        goto exit;
    }

    status = RSA_generateKey(MOC_RSA(NULL) pRandomCtx, pRsaKey, 2048, NULL);

    MSTATUS releaseStatus = RANDOM_releaseContext(&pRandomCtx);
    if (OK != releaseStatus)
    {
        DB_PRINT("ERROR: RANDOM_releaseContext failed with status %d\n", releaseStatus);
    }

    if (OK != status)
    {
        DB_PRINT("ERROR: RSA_generateKey failed with status %d\n", status);
        goto exit;
    }

    status = KEYBLOB_makeRSAKeyBlob(MOC_RSA(NULL) pRsaKey, &pKeyBlob, &keyBlobLen);
    if (status != OK)
    {
        DB_PRINT("ERROR: KEYBLOB_makeRSAKeyBlob failed with status %d\n", status);
        goto exit;
    }

    status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                              (ubyte*)g_mockKeyAlias,
                                              (ubyte4)DIGI_STRLEN((char*)g_mockKeyAlias),
                                              pKeyBlob,
                                              keyBlobLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: CERT_STORE_addIdentityNakedKeyEx failed with status %d\n", status);
        goto exit;
    }

    status = EST_generateCSRRequestFromConfig(
        MOC_HW(NULL)
        pCertStore,
        0,
        (ubyte*)g_mockConfigFile,
        NULL,
        2,
        (ubyte*)g_mockKeyAlias,
        (ubyte4)DIGI_STRLEN((char*)g_mockKeyAlias),
        NULL,
        akt_rsa,
        0,
        (ubyte*)g_mockHashType,
        (ubyte4)DIGI_STRLEN((char*)g_mockHashType),
        &pCsr,
        &csrLen
    );

    if (OK != status)
    {
        DB_PRINT("ERROR: EST_generateCSRRequestFromConfig for enrollment failed with status %d\n", status);
        goto exit;
    }

    g_pCsrData = pCsr;
    g_csrDataLen = csrLen;

    status = EST_openConnection(
        pCertStore,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        443,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        &connectionHandle,
        &pHttpCtx,
        NULL,
        0,
        FALSE,
        FALSE
    );

    if (OK != status)
    {
        DB_PRINT("ERROR: EST_openConnection for enrollment failed with status %d\n", status);
        goto exit;
    }

    status = HTTP_AUTH_generateBasicAuthorization(pHttpCtx,
                        (ubyte*)g_estUsername, (ubyte4)DIGI_STRLEN((char*)g_estUsername),
                        (ubyte*)g_estPassword, (ubyte4)DIGI_STRLEN((char*)g_estPassword),
                        &g_pAuthString, &g_authStringLen);

    if (OK == status && g_authStringLen > 0)
    {
        status = HTTP_COMMON_setHeaderIfNotSet(pHttpCtx, Authorization, g_pAuthString, g_authStringLen);
    }

    status = EST_sendSimpleEnrollRequest(
        pHttpCtx,
        connectionHandle,
        (ubyte*)g_estSimpleEnrollPath,
        (ubyte4)DIGI_STRLEN((char*)g_estSimpleEnrollPath),
        csrLen,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        (sbyte*)g_defaultUserAgent
    );

    if (OK != status)
    {
        DB_PRINT("ERROR: EST_sendSimpleEnrollRequest failed with status %d\n", status);
        goto exit;
    }

    status = HTTP_REQUEST_getContentType(pHttpCtx, (const ubyte **)&pContentType, &contentTypeLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: HTTP_REQUEST_getContentType failed with status %d\n", status);
        goto exit;
    }

    status = HTTP_REQUEST_getResponseContent(pHttpCtx, &pHttpResponse, &httpResponseLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: HTTP_REQUEST_getResponseContent failed with status %d\n", status);
        goto exit;
    }

    status = EST_filterPkcs7Message(pHttpResponse, httpResponseLen, &filteredLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: EST_filterPkcs7Message failed with error: %d, using original length\n", status);
        filteredLen = httpResponseLen;
    }

    status = EST_receiveResponse(pContentType, contentTypeLen,
                               pHttpResponse, filteredLen,
                               NULL, &pParsedCertificates, &numParsedCerts);
    if (OK != status)
    {
        DB_PRINT("ERROR: EST_receiveResponse failed with status: %d\n", status);
        goto exit;
    }

    EST_closeConnection(pHttpCtx, connectionHandle);
    pHttpCtx = NULL;

    if (0 == numParsedCerts || NULL == pParsedCertificates)
    {
        DB_PRINT("ERROR: No certificates extracted from enrollment response\n");
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pParsedCertificates[0].length > 27 &&
        DIGI_STRNCMP((char*)pParsedCertificates[0].data, "-----BEGIN CERTIFICATE-----", 27) == 0)
    {

        status = CA_MGMT_decodeCertificate(pParsedCertificates[0].data, pParsedCertificates[0].length,
                                         &pDerCert, &derCertLen);
        if (status != OK) {
            DB_PRINT("ERROR: PEM to DER conversion failed with status: %d\n", status);
            goto exit;
        }

        pLocalEnrolledCert = pDerCert;
        localEnrolledCertLen = derCertLen;
    } else
    {
        pLocalEnrolledCert = pParsedCertificates[0].data;
        localEnrolledCertLen = pParsedCertificates[0].length;
    }

    if (NULL != pKeyBlob && keyBlobLen > 0)
    {
        if (OK == DIGI_MALLOC((void**)&pLocalEnrolledKeyBlob, keyBlobLen))
        {
            DIGI_MEMCPY(pLocalEnrolledKeyBlob, pKeyBlob, keyBlobLen);
            localEnrolledKeyBlobLen = keyBlobLen;
        }
        else
        {
            DB_PRINT("ERROR: Failed to allocate memory for local enrolled key blob\n");
            goto exit;
        }
    }

    sprintf(pTempCertFile, "/tmp/enrolled_cert_%d.der", (int)time(NULL));
    sprintf(pTempKeyFile, "/tmp/enrolled_key_%d.blob", (int)time(NULL));

    status = FMGMT_fopen(pTempCertFile, "wb", &pCertFile);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to create temp cert file %s\n", pTempCertFile);
        goto exit;
    }

    status = FMGMT_fwrite(pLocalEnrolledCert, 1, localEnrolledCertLen, pCertFile, &written);
    FMGMT_fclose(&pCertFile);

    if (OK != status || written != localEnrolledCertLen)
    {
        DB_PRINT("ERROR: Failed to write certificate to temp file\n");
        FMGMT_remove(pTempCertFile, FALSE);
        goto exit;
    }

    status = FMGMT_fopen(pTempKeyFile, "wb", &pKeyFile);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to create temp key file %s\n", pTempKeyFile);
        FMGMT_remove(pTempCertFile, FALSE);
        goto exit;
    }

    status = FMGMT_fwrite(pLocalEnrolledKeyBlob, 1, localEnrolledKeyBlobLen, pKeyFile, &written);
    FMGMT_fclose(&pKeyFile);

    if (OK != status || written != localEnrolledKeyBlobLen)
    {
        DB_PRINT("ERROR: Failed to write key blob to temp file\n");
        FMGMT_remove(pTempCertFile, FALSE);
        FMGMT_remove(pTempKeyFile, FALSE);
        goto exit;
    }

    CERT_STORE_releaseStore(&pCertStore);
    status = setup_cert_store_with_roots(&pCertStore);
    if (OK != status)
    {
        FMGMT_remove(pTempCertFile, FALSE);
        FMGMT_remove(pTempKeyFile, FALSE);
        goto exit;
    }

    status = DIGICERT_readFile(pTempCertFile, &pReadCert, &readCertLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to read certificate from %s, status %d\n", pTempCertFile, status);
        FMGMT_remove(pTempCertFile, FALSE);
        FMGMT_remove(pTempKeyFile, FALSE);
        goto exit;
    }

    status = DIGICERT_readFile(pTempKeyFile, &pReadKeyBlob, &readKeyBlobLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to read key blob from %s, status %d\n", pTempKeyFile, status);
        DIGICERT_freeReadFile(&pReadCert);
        FMGMT_remove(pTempCertFile, FALSE);
        FMGMT_remove(pTempKeyFile, FALSE);
        goto exit;
    }

    FMGMT_remove(pTempCertFile, FALSE);
    FMGMT_remove(pTempKeyFile, FALSE);

    status = CERT_STORE_addTrustPoint(pCertStore, pReadCert, readCertLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: CERT_STORE_addTrustPoint failed with status %d\n", status);
    }

    if (readCertLen <= 0 || pReadCert[0] != 0x30)
    {
        DB_PRINT("ERROR: Certificate does not start with 0x30 (first byte: 0x%02x)\n",
                 readCertLen > 0 ? pReadCert[0] : 0);
    }

    certificate.data = pReadCert;
    certificate.length = readCertLen;

    status = CERT_STORE_addGenericIdentity(
        pCertStore,
        pClientKeyAlias,
        (ubyte4)DIGI_STRLEN((sbyte*)pClientKeyAlias),
        pReadKeyBlob,
        readKeyBlobLen,
        CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
        &certificate,
        1,
        NULL
    );

    DIGICERT_freeReadFile(&pReadCert);
    DIGICERT_freeReadFile(&pReadKeyBlob);

    if (OK != status)
    {
        DB_PRINT("ERROR: CERT_STORE_addGenericIdentity failed with status %d\n", status);
        goto exit;
    }

    if (NULL != pCsr)
    {
        DIGI_FREE((void**)&pCsr);
        g_pCsrData = NULL;
        g_csrDataLen = 0;
    }

    status = EST_generateCSRRequestFromConfig(
        MOC_HW(NULL)
        pCertStore,
        0,
        (ubyte*)g_mockConfigFile,
        NULL,
        2,
        pClientKeyAlias,
        (ubyte4)DIGI_STRLEN((sbyte*)pClientKeyAlias),
        NULL,
        akt_rsa,
        0,
        (ubyte*)g_mockHashType,
        (ubyte4)DIGI_STRLEN((char*)g_mockHashType),
        &pCsr,
        &csrLen
    );

    if (OK != status)
    {
        DB_PRINT("ERROR: EST_generateCSRRequestFromConfig for reenroll failed with status %d\n", status);
        goto exit;
    }

    g_pCsrData = pCsr;
    g_csrDataLen = csrLen;

    status = EST_openConnection(
        pCertStore,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        443,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        &connectionHandle,
        &pHttpCtx,
        pClientKeyAlias,
        (ubyte4)DIGI_STRLEN((sbyte*)pClientKeyAlias),
        FALSE,
        FALSE
    );

    assert_int_equal(status, OK);
    assert_non_null(pHttpCtx);

    status = EST_sendSimpleEnrollRequest(
        pHttpCtx,
        connectionHandle,
        (ubyte*)g_estSimpleReenrollPath,
        (ubyte4)DIGI_STRLEN((char*)g_estSimpleReenrollPath),
        csrLen,
        (ubyte*)g_realServerAddr,
        (ubyte4)DIGI_STRLEN((char*)g_realServerAddr),
        (sbyte*)g_defaultUserAgent
    );

    if (OK != status)
    {
        DB_PRINT("ERROR: EST reenroll failed with status %d\n", status);
    }

exit:
    if (NULL != pRsaKey)
    {
        RSA_freeKey(&pRsaKey, NULL);
    }

    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void**)&pKeyBlob);
    }

    if (NULL != pCsr)
    {
        DIGI_FREE((void**)&pCsr);
        g_pCsrData = NULL;
        g_csrDataLen = 0;
    }

    if (NULL != pParsedCertificates)
    {
        for (ubyte4 i = 0; i < numParsedCerts; i++)
        {
            if (NULL != pParsedCertificates[i].data)
            {
                DIGI_FREE((void**)&pParsedCertificates[i].data);
            }
        }
        DIGI_FREE((void**)&pParsedCertificates);
    }

    if (NULL != pDerCert)
    {
        DIGI_FREE((void**)&pDerCert);
    }

    if (NULL != pLocalEnrolledKeyBlob)
    {
        DIGI_FREE((void**)&pLocalEnrolledKeyBlob);
    }

    if (NULL != pHttpResponse)
    {
        DIGI_FREE((void**)&pHttpResponse);
    }

    if (NULL != g_pAuthString)
    {
        DIGI_FREE((void**)&g_pAuthString);
        g_authStringLen = 0;
    }

    if (NULL != pHttpCtx)
    {
        HTTP_CONTEXT_resetContext(pHttpCtx);
        EST_closeConnection(pHttpCtx, connectionHandle);
    }

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }

    assert_true(OK == status);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_est_send_ca_certs_request,
                                       est_client_setup, est_client_teardown),
        /*
        cmocka_unit_test_setup_teardown(test_est_send_csr_attrs_request,
                                       est_client_setup, est_client_teardown)
        */
        cmocka_unit_test_setup_teardown(test_est_send_simple_enroll_request,
                                       est_client_setup, est_client_teardown),
        cmocka_unit_test_setup_teardown(test_est_send_simple_reenroll_request,
                                       est_client_setup, est_client_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
