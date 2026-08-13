/*
 * trustedge_cloud_service_azure.c
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
 *
 */

#include "../../common/moptions.h"

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE__)

/* TPM2 support is brought over as is from TPUC, but has not been refactoed to
 * use the new TrustEdge agent context, config, structures, and TAP context. If
 * TPM2 support is needed, this code will need to be refactored accordingly and
 * the following flag needs to be enabled. */
/* #define __ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__ */


#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/datetime.h"
#include "../../common/base64.h"
#include "../../common/uri.h"
#include "../../http/http_context.h"
#include "../../http/http_common.h"
#include "../../http/client/http_request.h"
#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../smp/smp_tpm2/smp_tap_tpm2.h"
#include "../../smp/smp_tpm2/tpm2_lib/tpm2_types.h"
#include "../../smp/smp_tpm2/tpm2_lib/tap_serialize_tpm2.h"
#include "../../smp/smp_tpm2/tpm2_lib/fapi2/fapi2_types.h"
#include "../../smp/smp_tpm2/tpm2_lib/sapi2/sapi2_serialize.h"

#include "trustedge_cloud_service_azure.h"
#include "../../trustedge/http/trustedge_https_util.h"
#include "../../trustedge/utils/trustedge_tap.h"
#include "../../trustedge/agent/trustedge_agent_certificate.h"

/*----------------------------------------------------------------------------*/

#define TRUSTEDGE_AZURE_IDENTITY_NAME       "AZURE_IDENTITY_CERT"

/*----------------------------------------------------------------------------*/

typedef enum
{
    AZURE_X509_REG,
    AZURE_TPM_REG
} AzureRegMode;

typedef struct
{
    TrustEdgeAgentCtx *pAgentCtx;
    HttpsClientCtx *pHttpCtx;
    sbyte *pSchemeAndHost;
    sbyte *pHost;
    ubyte *pURI;
    ubyte4 port;
    ubyte pPortStr[11];
    ubyte4 portStrLen;
    ubyte4 retryMaxCount;
    ubyte4 retryDelaySecondsOrig;
    ubyte4 retryDelaySeconds;
    ubyte *pMsg;
    ubyte4 msgLen;
    sbyte *pIdScope;
    ubyte4 idScopeLen;
    ubyte *pRegId;
    ubyte4 regIdLen;
    sbyte *pOpId;
    ubyte4 opIdLen;
    sbyte *pHub;
    ubyte4 hubLen;
    sbyte *pDevId;
    ubyte4 devIdLen;
    AzureRegMode mode;
    sbyte4 sigExpireTime;
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    ubyte *pAuthKey;
    ubyte4 authKeyLen;
#endif
    sbyte *pKeyName;
    ubyte4 httpStatusCode;
    byteBoolean error;
    ubyte *pServerRsp;
    ubyte4 serverRspLen;
} CloudServiceAzureCtx;

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)

typedef struct
{
    TPM2B_ID_OBJECT encKeyBlob;
    TPM2B_ENCRYPTED_SECRET tpmEncSecret;
    TPM2B_PRIVATE idKeyDupBlob;
    TPM2B_ENCRYPTED_SECRET encryptWrapKey;
    TPM2B_PUBLIC idKeyPublic;
    ubyte2 encDataSize;
} AzureTpmAuthKey;

tap_shadow_struct TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(AzureTpmAuthKey),
    .numFields = 6,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {
        {TAP_OFFSETOF(AzureTpmAuthKey, encKeyBlob), NULL},
        {TAP_OFFSETOF(AzureTpmAuthKey, tpmEncSecret), NULL},
        {TAP_OFFSETOF(AzureTpmAuthKey, idKeyDupBlob), NULL},
        {TAP_OFFSETOF(AzureTpmAuthKey, encryptWrapKey), NULL},
        {TAP_OFFSETOF(AzureTpmAuthKey, idKeyPublic), NULL},
        {TAP_OFFSETOF(AzureTpmAuthKey, encDataSize), NULL},
    }
};

#endif

/*----------------------------------------------------------------------------*/

#define MIN_RETRY_DELAY_SECONDS     (1)
#define MAX_RETRY_DELAY_SECONDS     (300)

/* Azure message defines */
#define AZURE_REGISTRATIONS         "registrations"
#define AZURE_API_VERSION           "api-version=2019-03-31"
/* registration - header */
#define AZURE_REGISTER              "register"
/* registration - body */
#define AZURE_REGISTRATION_ID       "registrationId"
#define AZURE_TPM                   "tpm"
#define AZURE_ENDORSEMENT_KEY       "endorsementKey"
#define AZURE_STORAGE_ROOT_KEY      "storageRootKey"
/* registration - response */
#define AZURE_OPERATION_ID          "operationId"
#define AZURE_AUTHENTICATION_KEY    "authenticationKey"
#define AZURE_KEY_NAME              "keyName"
/* registration - uri and message */
#define AZURE_REGISTER_URI          "%s:%.*s/%.*s/%s/%.*s/%s?%s"
#define AZURE_REGISTER_X509_MSG     "{\"%s\":\"%.*s\"}"
#define AZURE_REGISTER_TPM_MSG      "{\"%s\":\"%.*s\",\"%s\":{\"%s\":\"%.*s\",\"%s\":\"%.*s\"}}"

/* operation status lookup - header */
#define AZURE_OPERATIONS            "operations"
/* operation status lookup - response */
#define AZURE_STATUS                "status"
#define AZURE_STATUS_ASSIGNED       "assigned"
#define AZURE_STATUS_ASSIGNING      "assigning"
#define AZURE_STATUS_UNASSIGNED     "unassigned"
#define AZURE_REGISTRATION_STATE    "registrationState"
#define AZURE_ASSIGNED_HUB          "assignedHub"
#define AZURE_DEVICE_ID             "deviceId"
/* operation status lookup - uri */
#define AZURE_OP_STATUS_URI         "%s:%.*s/%.*s/%s/%.*s/%s/%.*s?%s"

/* TPM SAS token signature */
#define AZURE_TPM_SAS_SIGNATURE     "%.*s%%2f%s%%2f%.*s\n%d"
#define AZURE_TPM_SAS_TOKEN         "SharedAccessSignature sr=%.*s%%2f%s%%2f%.*s&sig=%.*s&se=%d&skn=%s"

/* configuration - common */
#define AZURE_CONFIG_IOTHUB_URL             "iothub_url"
#define AZURE_CONFIG_DEVICE_ID              "device_id"
/* configuration - X.509 */
#define AZURE_CONFIG_DEVICE_CERT            "device_cert"
#define AZURE_CONFIG_DEVICE_KEY             "device_key"
/* configuration - TPM */
#define AZURE_CONFIG_KEY_TYPE               "key_type"
#define AZURE_CONFIG_KEY_TYPE_TAP           "TAP"
#define AZURE_CONFIG_KEY_INFO               "key_info"
#define AZURE_CONFIG_KEY_INFO_MODULE        "module"
#define AZURE_CONFIG_KEY_INFO_MODULE_TPM2   "TPM2"
#define AZURE_CONFIG_KEY_INFO_KEY_FILE      "key_file"
/* TODO: Need to determine name and format */
#define AZURE_KEY_FILE                      "keys/azure_tpm_key.tapkey"
#define AZURE_SERVICE_CONFIG_X509           "{\n" \
                                            "    \"%s\": \"%.*s\",\n" \
                                            "    \"%s\": \"%.*s\",\n" \
                                            "    \"%s\": \"%s\",\n" \
                                            "    \"%s\": \"%s\"\n" \
                                            "}\n"
#define AZURE_SERVICE_CONFIG_TPM            "{\n" \
                                            "    \"%s\": \"%.*s\",\n" \
                                            "    \"%s\": \"%.*s\",\n" \
                                            "    \"%s\": \"%s\",\n" \
                                            "    \"%s\": {\n" \
                                            "        \"%s\": \"%s\",\n" \
                                            "        \"%s\": \"%s\"\n" \
                                            "    }\n" \
                                            "}\n"
/* configuration - file */
#define AZURE_SERVICE_CONFIG_FILE   "azure_iot_hub.json"

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)

static MSTATUS TRUSTEDGE_cloudServiceAzureGetUnwrapParams(
    TAP_Context *pTapCtx,
    TAP_EntityCredentialList *pTapEntityCredList,
    TAP_CredentialList *pTapCredList,
    void *pUserArg,
    TAP_Key **ppTapKey,
    TAP_Key **ppRoTKey,
    TAP_Blob *pTapBlob)
{
    MSTATUS status;
    TAP_KeyInfo keyInfo = {0};
    TAP_Key *pTapKey = NULL;
    TAP_Key *pRoTKey = NULL;
    TPM2_MAKE_CREDENTIAL_RSP_PARAMS blob = {0};
    ubyte pBlob[sizeof(TPM2_MAKE_CREDENTIAL_RSP_PARAMS)];
    ubyte *pBase64Blob = NULL;
    ubyte4 base64BlobLen = 0;
    ubyte4 offset;
    AzureTpmAuthKey *pAuthKey = (AzureTpmAuthKey *) pUserArg;

    MOC_UNUSED(pTapEntityCredList);
    MOC_UNUSED(pTapCredList);

    keyInfo.objectId = SRK_OBJECT_ID_START;
    status = TAP_getRootOfTrustKey(
        pTapCtx, &keyInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN, &pTapKey, NULL);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    keyInfo.objectId = EK_OBJECT_ID;
    status = TAP_getRootOfTrustKey(
        pTapCtx, &keyInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN, &pRoTKey, NULL);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* TAP_unwrapKeyValidatedSecret expects the blob to be a base64
     * encoding of both the credential blob and the secret. Marshall the
     * credential blob and secret portion of the umarshalled data into
     * TPM2_MAKE_CREDENTIAL_RSP_PARAMS structure. */
    DIGI_MEMCPY(
        &(blob.credentialBlob), &(pAuthKey->encKeyBlob),
        sizeof(TPM2B_ID_OBJECT));
    DIGI_MEMCPY(
        &(blob.secret), &(pAuthKey->tpmEncSecret),
        sizeof(TPM2B_ENCRYPTED_SECRET));

    offset = 0;
    status = SAPI2_SERIALIZE_serialize(
        SAPI2_ST_TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_RSP_PARAMS, TAP_SD_IN,
        (ubyte *) &blob, sizeof(TPM2_MAKE_CREDENTIAL_RSP_PARAMS),
        pBlob, sizeof(pBlob), &offset);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = BASE64_encodeMessage(pBlob, offset, &pBase64Blob, &base64BlobLen);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppTapKey = pTapKey;
    pTapKey = NULL;

    *ppRoTKey = pRoTKey;
    pRoTKey = NULL;

    pTapBlob->format = TAP_BLOB_FORMAT_MOCANA;
    pTapBlob->encoding = TAP_BLOB_ENCODING_BASE64;
    pTapBlob->blob.pBuffer = pBase64Blob;
    pTapBlob->blob.bufferLen = base64BlobLen;
    pBase64Blob = NULL;

exit:

    if (NULL != pBase64Blob)
    {
        DIGI_FREE((void **) &pBase64Blob);
    }

    if (NULL != pRoTKey)
    {
        TAP_unloadKey(pRoTKey, NULL);
        TAP_freeKey(&pRoTKey);
    }

    if (NULL != pTapKey)
    {
        TAP_unloadKey(pTapKey, NULL);
        TAP_freeKey(&pTapKey);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_cloudServiceAzureGetImportParams(
    TAP_Context *pTapCtx,
    TAP_EntityCredentialList *pTapEntityCredList,
    TAP_CredentialList *pTapCredList,
    TAP_Buffer *pSecret,
    void *pUserArg,
    TAP_KeyInfo *pKeyInfo,
    TAP_Buffer *pDuplicateBuf,
    TAP_AttributeList *pKeyAttributes)
{
    MSTATUS status;
    FAPI2_DuplicateOut duplicate = {0};
    ubyte *pDup = NULL;
    ubyte4 offset;
    AzureTpmAuthKey *pAuthKey = (AzureTpmAuthKey *) pUserArg;

    MOC_UNUSED(pTapCtx);
    MOC_UNUSED(pTapEntityCredList);
    MOC_UNUSED(pTapCredList);
    MOC_UNUSED(pKeyAttributes);

    if (pSecret->bufferLen > sizeof(duplicate.encryptionKeyOut.buffer))
    {
        status = ERR_BAD_LENGTH;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    DIGI_MEMCPY(
        duplicate.encryptionKeyOut.buffer, pSecret->pBuffer,
        pSecret->bufferLen);
    duplicate.encryptionKeyOut.size = pSecret->bufferLen;

    DIGI_MEMCPY(
        &(duplicate.duplicate), &(pAuthKey->idKeyDupBlob),
        sizeof(TPM2B_PRIVATE));
    DIGI_MEMCPY(
        &(duplicate.outSymSeed), &(pAuthKey->encryptWrapKey),
        sizeof(TPM2B_ENCRYPTED_SECRET));

    duplicate.symmetricAlg.algorithm = TPM2_ALG_AES;
    duplicate.symmetricAlg.keyBits.aes = 128;
    duplicate.symmetricAlg.mode.aes = TPM2_ALG_CFB;

    DIGI_MEMCPY(
        &(duplicate.objectPublic), &(pAuthKey->idKeyPublic),
        sizeof(TPM2B_PUBLIC));

    /* Set duplicate */
    status = DIGI_MALLOC((void **) &pDup, sizeof(FAPI2_DuplicateOut));
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    offset = 0;
    status = SAPI2_SERIALIZE_serialize(
        SAPI2_ST_TPM2_FAPI2_DUPLICATEOUT, TAP_SD_IN,
        (ubyte *) &duplicate, sizeof(FAPI2_DuplicateOut),
        (ubyte *) pDup, sizeof(FAPI2_DuplicateOut), &offset);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pDuplicateBuf->pBuffer = pDup;
    pDuplicateBuf->bufferLen = offset;
    pDup = NULL;

    pKeyInfo->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    pKeyInfo->keyUsage = TAP_KEY_USAGE_GENERAL;
    pKeyInfo->algKeyInfo.hmacInfo.keyLen = 0;
    pKeyInfo->algKeyInfo.hmacInfo.hashAlg = TAP_HASH_ALG_SHA256;

exit:

    if (NULL != pDup)
    {
        DIGI_FREE((void **) &pDup);
    }

    return status;
}

#endif

/*----------------------------------------------------------------------------*/

/* Method used to delete the Azure context */
static MSTATUS TRUSTEDGE_cloudServiceAzureContextDelete(
    CloudServiceAzureCtx **ppCtx)
{
    MSTATUS status = OK;

    if ((NULL != ppCtx) && (NULL != *ppCtx))
    {
        if (NULL != (*ppCtx)->pHttpCtx)
            TRUSTEDGE_clientHttpsLocalReleaseContext(&((*ppCtx)->pHttpCtx));

        if (NULL != (*ppCtx)->pSchemeAndHost)
            DIGI_FREE((void **) &(*ppCtx)->pSchemeAndHost);

        if (NULL != (*ppCtx)->pURI)
            DIGI_FREE((void **) &(*ppCtx)->pURI);

        if (NULL != (*ppCtx)->pMsg)
            DIGI_FREE((void **) &(*ppCtx)->pMsg);

        if (NULL != (*ppCtx)->pIdScope)
            DIGI_FREE((void **) &(*ppCtx)->pIdScope);

        if (NULL != (*ppCtx)->pRegId)
            DIGI_FREE((void **) &(*ppCtx)->pRegId);

        if (NULL != (*ppCtx)->pOpId)
            DIGI_FREE((void **) &(*ppCtx)->pOpId);

        if (NULL != (*ppCtx)->pHub)
            DIGI_FREE((void **) &(*ppCtx)->pHub);

        if (NULL != (*ppCtx)->pDevId)
            DIGI_FREE((void **) &(*ppCtx)->pDevId);

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
        if (NULL != (*ppCtx)->pAuthKey)
            DIGI_FREE((void **) &(*ppCtx)->pAuthKey);
#endif

        if (NULL != (*ppCtx)->pKeyName)
            DIGI_FREE((void **) &(*ppCtx)->pKeyName);

        if (NULL != (*ppCtx)->pServerRsp)
            DIGI_FREE((void **) &(*ppCtx)->pServerRsp);

        DIGI_FREE((void **) ppCtx);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* Parses the following JSON structure
 *
{
  "operationId": "cloud platform policy id",
  "brokerType": "AZURE_IOT_DPS"
  "attributes": [
  { "key": "service_endpoint",          "value": "global.azure-devices-provisioning.net" },
  { "key": "service_endpoint_port",     "value": 443 },
  { "key": "service_endpoint_ca_certs", "value": "-----BEGIN PKCS7-----\\n...\\n-----END PKCS7-----" },
  { "key": "attestation_mode",          "value": "X509_CERTIFICATE | TPM" },
  { "key": "id_scope",                  "value": "0ne00000000" },
  { "key": "retry_count",               "value": 1..20 },
  { "key": "retry_interval",            "value": 1..300 },
  { "key": "signature_expiry_time",     "value": 3600 },
  { "key": "registration_id",           "value": "<id>" }
]
}
 *
 * where "signature_expiry_time" and "registration_id" are optional
 */
MSTATUS TRUSTEDGE_cloudServiceAzureParseProviderInfo(
    CloudServiceAzureCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen)
{
  MSTATUS status;
  JSON_ContextType *pJsonCtx = NULL;
  ubyte4 numTokens;
  ubyte4 ndx;
  ubyte4 i;
  JSON_TokenType token = { 0 };
  sbyte *pKey = NULL;
  sbyte *pValue = NULL;
  ubyte4 httpsPrefixLen;
  certDescriptor *pCertDescArray = NULL;
  ubyte4 certDescArrayLen = 0;
  ubyte *pPkcs7Data = NULL;
  ubyte4 pkcs7DataLen = 0;

  #define PROVIDER_INFO_ATTRIBUTES       "attributes"
  #define PROVIDER_INFO_KEY              "key"
  #define PROVIDER_INFO_VALUE            "value"
  #define PROVIDER_INFO_ID_SCOPE         "id_scope"
  #define PROVIDER_INFO_SERVICE_ENDPOINT "service_endpoint"
  #define PROVIDER_INFO_ENDPOINT         "endpoint"
  #define PROVIDER_INFO_SERVICE_ENDPOINT_PORT "service_endpoint_port"
  #define PROVIDER_INFO_ATTESTATION_MODE "attestation_mode"
  #define PROVIDER_INFO_ATTESTATION_MODE_X509 "X509_CERTIFICATE"
  #define PROVIDER_INFO_ATTESTATION_MODE_TPM  "TPM"
  #define PROVIDER_INFO_RETRY_COUNT      "retry_count"
  #define PROVIDER_INFO_RETRY_INTERVAL   "retry_interval"
  #define PROVIDER_INFO_SERVICE_ENDPOINT_CA_CERTS "service_endpoint_ca_certs"
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
  #define PROVIDER_INFO_REGISTRATION_ID  "registration_id"
  #define PROVIDER_INFO_SIG_EXPIRY_TIME  "signature_expiry_time"
#endif

  if (NULL == pCtx || NULL == pJson)
  {
    status = ERR_NULL_POINTER;
    MSG_LOG_print(MSG_LOG_ERROR,
        "%s line %d status: %d = %s\n",
        __func__, __LINE__, status,
        MERROR_lookUpErrorCode(status));
    goto exit;
  }

  /* Default values */
  pCtx->port = 443;

  /* Acquire JSON context and parse */
  status = JSON_acquireContext(&pJsonCtx);
  if (OK != status)
  {
    MSG_LOG_print(MSG_LOG_ERROR,
        "%s line %d status: %d = %s\n",
        __func__, __LINE__, status,
        MERROR_lookUpErrorCode(status));
    goto exit;
  }

  status = JSON_parse(pJsonCtx, pJson, jsonLen, &numTokens);
  if (OK != status)
  {
    MSG_LOG_print(MSG_LOG_ERROR,
        "%s line %d status: %d = %s\n",
        __func__, __LINE__, status,
        MERROR_lookUpErrorCode(status));
    goto exit;
  }

  /* Parse the attributes array */
  status = JSON_getJsonArrayValue(
      pJsonCtx, 0, PROVIDER_INFO_ATTRIBUTES, &ndx, &token, TRUE);
  if (OK != status)
  {
    MSG_LOG_print(MSG_LOG_ERROR,
        "Failed to find '%s' array: %s line %d status: %d = %s\n",
        PROVIDER_INFO_ATTRIBUTES, __func__, __LINE__, status,
        MERROR_lookUpErrorCode(status));
    goto exit;
  }

  ndx++;
  for (i = 0; i < token.elemCnt; i++)
  {
    /* Get the key for this attribute */
    DIGI_FREE((void **) &pKey);
    status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_KEY, &pKey, TRUE);
    if (OK != status)
    {
      goto next_attr;
    }

    /* Check if this is id_scope */
    if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_ID_SCOPE))
    {
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            PROVIDER_INFO_ID_SCOPE, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      status = DIGI_MALLOC_MEMCPY(
          (void **) &pCtx->pIdScope, DIGI_STRLEN(pValue) + 1,
          (void *) pValue, DIGI_STRLEN(pValue));
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }
      pCtx->pIdScope[DIGI_STRLEN(pValue)] = '\0';
      pCtx->idScopeLen = DIGI_STRLEN(pValue);

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed id_scope: %.*s\n", pCtx->idScopeLen, pCtx->pIdScope);
    }
    /* Check if this is service_endpoint or endpoint */
    else if ((0 == DIGI_STRCMP(pKey, PROVIDER_INFO_SERVICE_ENDPOINT)) ||
             (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_ENDPOINT)))
    {
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            pKey, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      /* Store service endpoint as scheme+host */
      httpsPrefixLen = DIGI_STRLEN(HTTPS_PREFIX);
      status = DIGI_MALLOC((void **) &pCtx->pSchemeAndHost,
          httpsPrefixLen + DIGI_STRLEN(pValue) + 1);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }
      DIGI_MEMCPY(pCtx->pSchemeAndHost, HTTPS_PREFIX, httpsPrefixLen);
      DIGI_STRCBCPY(pCtx->pSchemeAndHost + httpsPrefixLen,
          DIGI_STRLEN(pValue) + 1, pValue);
      pCtx->pHost = pCtx->pSchemeAndHost + httpsPrefixLen;

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed endpoint: %s\n", pCtx->pSchemeAndHost);
    }
    /* Check if this is service_endpoint_port */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_SERVICE_ENDPOINT_PORT))
    {
      sbyte4 portValue = 0;
      status = JSON_getJsonIntegerValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &portValue, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            PROVIDER_INFO_SERVICE_ENDPOINT_PORT, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      pCtx->port = (ubyte2) portValue;

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed service_endpoint_port: %d\n", pCtx->port);
    }
    /* Check if this is attestation_mode */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_ATTESTATION_MODE))
    {
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            PROVIDER_INFO_ATTESTATION_MODE, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      if (0 == DIGI_STRCMP(pValue, PROVIDER_INFO_ATTESTATION_MODE_X509))
      {
        pCtx->mode = AZURE_X509_REG;
      }
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
      else if (0 == DIGI_STRCMP(pValue, PROVIDER_INFO_ATTESTATION_MODE_TPM))
      {
        pCtx->mode = AZURE_TPM_REG;
      }
#endif
      else
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Unknown attestation_mode: %s\n", pValue);
        status = ERR_INVALID_ARG;
        goto exit;
      }

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed attestation_mode: %s\n", pValue);
    }
    /* Check if this is retry_count */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_RETRY_COUNT))
    {
      sbyte4 retryCount = 0;

      /* Try parsing as string first (backend may send "5" instead of 5) */
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK == status)
      {
        retryCount = (sbyte4) DIGI_ATOL(pValue, NULL);
      }
      else
      {
        /* Fall back to integer parsing */
        status = JSON_getJsonIntegerValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &retryCount, TRUE);
        if (OK != status)
        {
          MSG_LOG_print(MSG_LOG_ERROR,
              "Failed to get value for '%s': %s line %d status: %d = %s\n",
              PROVIDER_INFO_RETRY_COUNT, __func__, __LINE__, status,
              MERROR_lookUpErrorCode(status));
          goto exit;
        }
      }

      pCtx->retryMaxCount = (ubyte4) retryCount;

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed retry_count: %u\n", pCtx->retryMaxCount);
    }
    /* Check if this is retry_interval */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_RETRY_INTERVAL))
    {
      sbyte4 retryInterval = 0;

      /* Try parsing as string first (backend may send "30" instead of 30) */
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK == status)
      {
        retryInterval = (sbyte4) DIGI_ATOL(pValue, NULL);
      }
      else
      {
        /* Fall back to integer parsing */
        status = JSON_getJsonIntegerValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &retryInterval, TRUE);
        if (OK != status)
        {
          MSG_LOG_print(MSG_LOG_ERROR,
              "Failed to get value for '%s': %s line %d status: %d = %s\n",
              PROVIDER_INFO_RETRY_INTERVAL, __func__, __LINE__, status,
              MERROR_lookUpErrorCode(status));
          goto exit;
        }
      }

      pCtx->retryDelaySeconds = (ubyte4) retryInterval;
      pCtx->retryDelaySecondsOrig = pCtx->retryDelaySeconds;

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed retry_interval: %u\n", pCtx->retryDelaySeconds);
    }
    /* Check if this is service_endpoint_ca_certs */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_SERVICE_ENDPOINT_CA_CERTS))
    {
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            PROVIDER_INFO_SERVICE_ENDPOINT_CA_CERTS, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      /* Allocate buffer and copy the PKCS7 data for unescaping */
      pkcs7DataLen = DIGI_STRLEN(pValue);
      status = DIGI_MALLOC_MEMCPY((void **) &pPkcs7Data, pkcs7DataLen + 1,
          (void *) pValue, pkcs7DataLen);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }
      pPkcs7Data[pkcs7DataLen] = '\0';

      /* Unescape JSON formatting */
      status = COMMON_UTILS_unescapeNewLine(pPkcs7Data, &pkcs7DataLen);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to unescape PKCS7 data: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      /* Unescape newline formatting */
      status = COMMON_UTILS_unescapeNewLine(pPkcs7Data, &pkcs7DataLen);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to unescape PKCS7 data: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      /* Parse the PKCS7 response */
      status = CERT_ENROLL_parseResponse(pPkcs7Data, pkcs7DataLen, NULL, FALSE,
          &pCertDescArray, &certDescArrayLen);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to parse CA certs PKCS7: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      /* Add certificates to cert store and write to filesystem */
      for (i = 0; i < certDescArrayLen; i++)
      {
        status = CERT_STORE_addTrustPoint(
            pCtx->pAgentCtx->pTrustedStore,
            pCertDescArray[i].pCertificate, pCertDescArray[i].certLength);
        if (OK != status)
        {
          MSG_LOG_print(MSG_LOG_ERROR,
              "Failed to add CA cert to store: %s line %d status: %d = %s\n",
              __func__, __LINE__, status,
              MERROR_lookUpErrorCode(status));
          goto exit;
        }

        status = TRUSTEDGE_utilsWriteTrustedCert(
            pCtx->pAgentCtx->pConfig,
            pCertDescArray[i].pCertificate, pCertDescArray[i].certLength);
        if (OK != status)
        {
          MSG_LOG_print(MSG_LOG_ERROR,
              "Failed to write CA cert to filesystem: %s line %d status: %d = %s\n",
              __func__, __LINE__, status,
              MERROR_lookUpErrorCode(status));
          goto exit;
        }
      }

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed service_endpoint_ca_certs: %u certificates\n", certDescArrayLen);
    }
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    /* Check if this is registration_id (TPM mode only) */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_REGISTRATION_ID))
    {
      DIGI_FREE((void **) &pValue);
      status = JSON_getJsonStringValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &pValue, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            PROVIDER_INFO_REGISTRATION_ID, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      status = DIGI_MALLOC_MEMCPY(
          (void **) &pCtx->pRegId, DIGI_STRLEN(pValue) + 1,
          (void *) pValue, DIGI_STRLEN(pValue));
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }
      pCtx->pRegId[DIGI_STRLEN(pValue)] = '\0';
      pCtx->regIdLen = DIGI_STRLEN(pValue);

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed registration_id: %.*s\n", pCtx->regIdLen, pCtx->pRegId);
    }
    /* Check if this is signature_expiry_time (TPM mode only) */
    else if (0 == DIGI_STRCMP(pKey, PROVIDER_INFO_SIG_EXPIRY_TIME))
    {
      sbyte4 sigExpiry = 0;
      status = JSON_getJsonIntegerValue(pJsonCtx, ndx, PROVIDER_INFO_VALUE, &sigExpiry, TRUE);
      if (OK != status)
      {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get value for '%s': %s line %d status: %d = %s\n",
            PROVIDER_INFO_SIG_EXPIRY_TIME, __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
      }

      pCtx->sigExpireTime = sigExpiry;

      MSG_LOG_print(MSG_LOG_DEBUG,
          "Parsed signature_expiry_time: %d\n", pCtx->sigExpireTime);
    }
#endif

next_attr:
    status = JSON_getLastIndexInObject(pJsonCtx, ndx, &ndx);
    if (OK != status)
    {
      MSG_LOG_print(MSG_LOG_ERROR,
          "%s line %d status: %d = %s\n",
          __func__, __LINE__, status,
          MERROR_lookUpErrorCode(status));
      goto exit;
    }
    ndx++;
  }

  /* Validate required fields */
  if (NULL == pCtx->pIdScope)
  {
    status = ERR_UM_JSON_PARSE_FAILED;
    MSG_LOG_print(MSG_LOG_ERROR,
        "Missing required attribute '%s': %s line %d status: %d = %s\n",
        PROVIDER_INFO_ID_SCOPE, __func__, __LINE__, status,
        MERROR_lookUpErrorCode(status));
    goto exit;
  }

  if (NULL == pCtx->pSchemeAndHost)
  {
    status = ERR_UM_JSON_PARSE_FAILED;
    MSG_LOG_print(MSG_LOG_ERROR,
        "Missing required attribute '%s' or '%s': %s line %d status: %d = %s\n",
        PROVIDER_INFO_SERVICE_ENDPOINT, PROVIDER_INFO_ENDPOINT,
        __func__, __LINE__, status,
        MERROR_lookUpErrorCode(status));
    goto exit;
  }

  status = OK;

exit:
  DIGI_FREE((void **) &pKey);
  DIGI_FREE((void **) &pValue);
  DIGI_FREE((void **) &pPkcs7Data);

  if (NULL != pCertDescArray)
  {
    for (i = 0; i < certDescArrayLen; i++)
    {
      DIGI_FREE((void **) &pCertDescArray[i].pCertificate);
    }
    DIGI_FREE((void **) &pCertDescArray);
  }

  if (NULL != pJsonCtx)
  {
    JSON_releaseContext(&pJsonCtx);
  }

  return status;
}

/* Method used to create the Azure context. Parses Azure specific arguments in
 * the provided JSON. The following Azure JSON attributes are expected
 *
 * {
 *     "service_type": "azure_dps",
 *     "service_attrs": {
 *         "uri": "https://global.azure-devices-provisioning.net",
 *         "port": 443,
 *         "retry_max_count": 3,
 *         "retry_delay_seconds": 1,
 *         "id_scope": "<ID SCOPE>"
 *     }
 * }
 *
 * uri - URI to connect to
 * port - Port to connect to
 * retry_max_count - Max retry attempts
 * retry_delay_seconds - Delay between each retry attempt
 * id_scope - Specifies which Azure DPS instance to connect to
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureContextCreate(
    ubyte *pJson,
    ubyte4 jsonLen,
    TrustEdgeAgentCtx *pAgentCtx,
    CloudServiceAzureCtx **ppCtx)
{
    MSTATUS status;
    CloudServiceAzureCtx *pCtx = NULL;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    AsymmetricKey *pAsymKey = NULL;

    if (NULL == pAgentCtx)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pCtx, 1, sizeof(CloudServiceAzureCtx));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->pAgentCtx = pAgentCtx;

    status = TRUSTEDGE_cloudServiceAzureParseProviderInfo(pCtx, pJson, jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (pCtx->mode == AZURE_X509_REG)
    {
        /* Retrieve the identity certificate */
        status = TRUSTEDGE_getCertificateByPolicyId(
            pAgentCtx,
            pAgentCtx->curPolicy.pPolicy->pDependency->pPolicies->pPolicyId,
            &pCert, &certLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_getKeyByPolicyId(
            pAgentCtx,
            pAgentCtx->curPolicy.pPolicy->pDependency->pPolicies->pPolicyId,
            &pAsymKey);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Retrieve the certificate common name. This is used as the registration
         * ID. */
        status = TRUSTEDGE_utilsRetrieveCertificateCN(
            pCert, certLen, &pCtx->pRegId, &pCtx->regIdLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_utilsLoadCertificateAndKey(
            pCtx->pAgentCtx->pTrustedStore,
            TRUSTEDGE_AZURE_IDENTITY_NAME,
            pCert, certLen, pAsymKey);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    MSG_LOG_print(
        MSG_LOG_DEBUG,
        "Azure Registration ID '%.*s'\n",
        pCtx->regIdLen, pCtx->pRegId);

    /* Create local HTTPS context, used to connect to Azure. */
    status = TRUSTEDGE_clientHttpsLocalAcquireContext(
        pAgentCtx->pConfig->pProviderCredsDir, &pCtx->pHttpCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_clientHttpsLocalApplyServerConfig(
        pCtx->pHttpCtx, pCtx->pHost, pCtx->port,
        pCtx->pAgentCtx->pTrustedStore, TRUSTEDGE_AZURE_IDENTITY_NAME);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppCtx = pCtx;
    pCtx = NULL;

exit:

    if (NULL != pAsymKey)
    {
        CRYPTO_uninitAsymmetricKey(pAsymKey, NULL);
        DIGI_FREE((void **) &pAsymKey);
    }

    if (NULL != pCert)
        DIGI_FREE((void **) &pCert);

    if (NULL != pCtx)
        TRUSTEDGE_cloudServiceAzureContextDelete(&pCtx);

    return status;
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)

static MSTATUS TRUSTEDGE_cloudServiceAzureGenerateAuth(
    HttpsClientCtx *pCtx,
    httpContext *pHttpContext,
    ubyte *pAuthKey,
    ubyte4 authKeyLen,
    ubyte4 *pIndex,
    ubyte **ppRetAuthString,
    ubyte4 *pRetAuthStringLength)
{
    MSTATUS status;
    CloudServiceAzureCtx *pAzureCtx = NULL;
    int ret = 0;
    TimeDate td, expire;
    TimeDate epochTime = { 0, 1, 1, 0, 0, 0 }; /* start of epoch */
    sbyte4 seconds;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pSig = NULL, *pBase64Sig = NULL, *pEscapedSig = NULL;
    ubyte4 sigLen = 0, base64SigLen = 0, escapedSigLen = 0;
    ubyte *pSas = NULL;
    ubyte4 sasLen = 0;

    status = TRUSTEDGE_clientHttpsLocalGetUserData(pCtx, (void **) &pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* HTTP authorization token only required for TPM registration. If this is
     * not a TPM registration, return an error. */
    if (AZURE_TPM_REG != pAzureCtx->mode)
    {
        status = ERR_AUTH_UNKNOWN_METHOD;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = RTOS_timeGMT(&td);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DATETIME_getNewTime(&td, pAzureCtx->sigExpireTime, &expire);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DATETIME_diffTime(&expire, &epochTime, &seconds);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Generate SAS token */
    ret = snprintf(NULL, 0, AZURE_TPM_SAS_SIGNATURE,
                    pAzureCtx->idScopeLen, pAzureCtx->pIdScope,
                    AZURE_REGISTRATIONS,
                    pAzureCtx->regIdLen, pAzureCtx->pRegId,
                    seconds);
    if (0 > ret)
    {
        status = ERR_UM_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }
    msgLen = ret;

    status = DIGI_MALLOC((void **) &pMsg, msgLen + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(pMsg, msgLen + 1, AZURE_TPM_SAS_SIGNATURE,
                    pAzureCtx->idScopeLen, pAzureCtx->pIdScope,
                    AZURE_REGISTRATIONS,
                    pAzureCtx->regIdLen, pAzureCtx->pRegId,
                    seconds);
    if ((0 > ret) || (msgLen != ret))
    {
        status = ERR_UM_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_clientTapSignData(
        pAuthKey, authKeyLen, pMsg, msgLen, &pSig, &sigLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = BASE64_encodeMessage(pSig, sigLen, &pBase64Sig, &base64SigLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = URI_GetEscapedLength(
        QUERY, pBase64Sig, base64SigLen, &escapedSigLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pEscapedSig, escapedSigLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = URI_Escape(
        QUERY, pBase64Sig, base64SigLen, pEscapedSig, &escapedSigLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(NULL, 0, AZURE_TPM_SAS_TOKEN,
                        pAzureCtx->idScopeLen, pAzureCtx->pIdScope,
                        AZURE_REGISTRATIONS,
                        pAzureCtx->regIdLen, pAzureCtx->pRegId,
                        escapedSigLen, pEscapedSig,
                        seconds,
                        pAzureCtx->pKeyName);
    if (0 > ret)
    {
        status = ERR_UM_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }
    sasLen = ret;

    status = DIGI_MALLOC((void **) &pSas, sasLen + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(pSas, sasLen + 1, AZURE_TPM_SAS_TOKEN,
                        pAzureCtx->idScopeLen, pAzureCtx->pIdScope,
                        AZURE_REGISTRATIONS,
                        pAzureCtx->regIdLen, pAzureCtx->pRegId,
                        escapedSigLen, pEscapedSig,
                        seconds,
                        pAzureCtx->pKeyName);
    if ((0 > ret) || (sasLen != ret))
    {
        status = ERR_UM_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pIndex = Authorization;
    *ppRetAuthString = pSas; pSas = NULL;
    *pRetAuthStringLength = sasLen;

exit:

    if (NULL != pSas)
        DIGI_FREE((void **) &pSas);

    if (NULL != pEscapedSig)
        DIGI_FREE((void **) &pEscapedSig);

    if (NULL != pBase64Sig)
        DIGI_FREE((void **) &pBase64Sig);

    if (NULL != pSig)
        DIGI_FREE((void **) &pSig);

    if (NULL != pMsg)
        DIGI_FREE((void **) &pMsg);

    return status;
}

#endif

/*---------------------------------------------------------------------------*/

/* HTTP callback used to set the HTTP header request. Handles both registration
 * and operation status lookup messages.
 *
 * Registration headers are constructed as follows
 *
 *     PUT /{idScope}/registrations/{registrationId}/register?api-version={apiVersion} HTTP/1.1
 *     UserAgent: {tpucUserAgent}
 *     Accept: application/json
 *     Connection: keep-alive
 *     Content-Type: application/json
 *     Host: global.azure-devices-provisioning.net
 *     Content-length: {httpBodyLength}
 *
 * Operation status lookup headers are constructed as follows
 *
 *     GET /{idScope}/registrations/{registrationId}/operations/{operationId}?api-version={apiVersion} HTTP/1.1
 *     UserAgent: {tpucUserAgent}
 *     Accept: application/json
 *     Connection: keep-alive
 *     Content-Type: application/json
 *     Host: global.azure-devices-provisioning.net
 *     Content-length: 0
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureRegisterOrOpStatusPrepareHeaderRequest(
    HttpsClientCtx *pCtx,
    httpContext *pHttpContext)
{
    MSTATUS status;
    CloudServiceAzureCtx *pAzureCtx = NULL;
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    ubyte *pSas = NULL;
    ubyte4 sasLen = 0;
    ubyte4 index;
#endif

    status = TRUSTEDGE_clientHttpsLocalGetUserData(pCtx, (void **) &pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* If the request message length is 0 then assume this is a operation status
     * lookup request and set the request method to GET, otherwise assume this
     * is a registration message and set the request method to PUT. */
    if (0 == pCtx->requestMsgLen)
    {
        status = HTTP_REQUEST_setRequestMethodIfNotSet (
                    pHttpContext, &mHttpMethods[GET]);
    }
    else
    {
        status = HTTP_REQUEST_setRequestMethodIfNotSet (
                    pHttpContext, &mHttpMethods[PUT]);
    }
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set UserAgent as the TPUC client */
    status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, UserAgent,
            (ubyte*)USER_AGENT, DIGI_STRLEN((sbyte *)USER_AGENT));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set Accept to JSON */
    status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, Accept,
                (ubyte *)CONTENT_TYPE_JSON,
                DIGI_STRLEN((sbyte *)CONTENT_TYPE_JSON));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set Connection to keep alive */
    status = HTTP_COMMON_setHeaderIfNotSet(
        pHttpContext, NUM_HTTP_REQUESTS + Connection,
        CONNECTION_KEEP_ALIVE, DIGI_STRLEN(CONNECTION_KEEP_ALIVE));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set ContentType to JSON */
    status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext,
                NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + ContentType,
                (ubyte *)CONTENT_TYPE_JSON, DIGI_STRLEN((sbyte *)CONTENT_TYPE_JSON));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,
                   "Azure URI    = %s\n",
                   pAzureCtx->pURI);

    /* Set the Host to the Azure URI */
    status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext,
                pAzureCtx->pURI);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set the Content-length */
    status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext,
        pCtx->requestMsgLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    /* If an auth key is provided, generate SAS token for HTTP authorization */
    if (NULL != pAzureCtx->pAuthKey)
    {
        status = TRUSTEDGE_cloudServiceAzureGenerateAuth(
            pCtx, pHttpContext, pAzureCtx->pAuthKey, pAzureCtx->authKeyLen,
            &index, &pSas, &sasLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = HTTP_COMMON_setHeaderIfNotSet(
            pHttpContext, index, pSas, sasLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
#endif

exit:

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    if (NULL != pSas)
        DIGI_FREE((void **) &pSas);
#endif

    return status;
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)

static tap_shadow_struct *UM_cloudServiceAzureGetAuthKeyStruct(void)
{
    TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY.pFieldList[0].pField = TAP_SERIALIZE_TPM2_getTpm2BIdObject();
    TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY.pFieldList[1].pField = TAP_SERIALIZE_TPM2_getTpm2BEncryptedSecret();
    TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY.pFieldList[2].pField = TAP_SERIALIZE_TPM2_getTpm2BPrivate();
    TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY.pFieldList[3].pField = TAP_SERIALIZE_TPM2_getTpm2BEncryptedSecret();
    TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY.pFieldList[4].pField = TAP_SERIALIZE_TPM2_getTpm2BPublic();
    TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY.pFieldList[5].pField = TAP_SERIALIZE_getUbyte2();

    return &TAP_SHADOW_AZURE_DPS_TPM_AUTH_KEY;
}

static MSTATUS TRUSTEDGE_cloudServiceAzureImportKey(
    sbyte *pBase64AuthKey,
    ubyte **ppTapKey,
    ubyte4 *pTapKeyLen)
{
    MSTATUS status;
    AzureTpmAuthKey authKey = {0};
    ubyte4 offset;
    ubyte *pAuthKey = NULL;
    ubyte4 authKeyLen = 0;

    /* Base64 decode auth key */
    status = BASE64_decodeMessage(
        pBase64AuthKey, DIGI_STRLEN(pBase64AuthKey), &pAuthKey, &authKeyLen);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Unmarshal the authentication key */
    offset = 0;
    status = TAP_SERIALIZE_serialize(
        TRUSTEDGE_cloudServiceAzureGetAuthKeyStruct(), TAP_SD_OUT, pAuthKey, authKeyLen,
        (ubyte *) &authKey, sizeof(AzureTpmAuthKey), &offset);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_clientTapImportKey(
        TRUSTEDGE_cloudServiceAzureGetUnwrapParams, &authKey,
        TRUSTEDGE_cloudServiceAzureGetImportParams, &authKey,
        ppTapKey, pTapKeyLen);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pAuthKey)
    {
        DIGI_FREE((void **) &pAuthKey);
    }

    return status;
}

#endif

static MSTATUS TRUSTEDGE_actionSaveEventServerResponse(
    CloudServiceAzureCtx *pCloudSvcCtx,
    ubyte4 httpStatusCode,
    ubyte *pRsp,
    ubyte4 rspLen)
{
    MSTATUS status;

    if (NULL == pCloudSvcCtx || NULL == pRsp)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pCloudSvcCtx->pServerRsp)
    {
        DIGI_FREE((void **) &(pCloudSvcCtx->pServerRsp));
        pCloudSvcCtx->serverRspLen = 0;
    }

    pCloudSvcCtx->httpStatusCode = httpStatusCode;
    pCloudSvcCtx->pServerRsp = pRsp;
    pCloudSvcCtx->serverRspLen = rspLen;
    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

/* HTTP callback used to parse a registration response. Refer to
 * https://docs.microsoft.com/en-us/rest/api/iot-dps/device/runtime-registration/register-device
 * for acceptable HTTP status codes and return values.
 *
 * Method retrieves the operation ID, used to query information about the
 * device in subsequent HTTP requests.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureRegisterResponseParse(
    HttpsClientCtx *pCtx)
{
    MSTATUS status;
    CloudServiceAzureCtx *pAzureCtx = NULL;
    ubyte *pRsp = NULL;
    ubyte4 rspLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 index = 0, subIndex = 0;
    sbyte4 cmpRes;
    ubyte4 tokensFound = 0;
    JSON_TokenType token = {0};
    sbyte *pAuthKey = NULL;

    status = TRUSTEDGE_clientHttpsLocalGetUserData(pCtx, (void **) &pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pCtx->responseBodyTempFileName, &pRsp, &rspLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_INFO, "Response - %.*s\n", rspLen, pRsp);

    status = TRUSTEDGE_actionSaveEventServerResponse(
        pAzureCtx, pCtx->responseStatus, pRsp, rspLen);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pRsp, rspLen, &tokensFound);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

#ifdef DBG_DUMP_JSON
    JSON_DBG_dumpContextInfo( pJCtx);
    JSON_DBG_dumpAllTokens( pJCtx, FALSE);
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    if (401 == pCtx->responseStatus)
    {
        if (AZURE_TPM_REG != pAzureCtx->mode)
        {
            status = OK;
            pAzureCtx->error = TRUE;
            goto exit;
        }

        status = JSON_utilReadJsonString(
            pJCtx, 0, NULL, AZURE_AUTHENTICATION_KEY, &pAuthKey, FALSE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (NULL != pAzureCtx->pAuthKey)
        {
            DIGI_FREE((void **) &(pAzureCtx->pAuthKey));
        }

        status = TRUSTEDGE_cloudServiceAzureImportKey(
            pAuthKey, &(pAzureCtx->pAuthKey), &(pAzureCtx->authKeyLen));
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pAzureCtx->pKeyName);
        status = JSON_utilReadJsonString(
            pJCtx, 0, NULL, AZURE_KEY_NAME, &pAzureCtx->pKeyName, FALSE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
#endif
    if ( (202 == pCtx->responseStatus) || (200 == pCtx->responseStatus) )
    {
        status = JSON_getObjectIndex(
            pJCtx, (sbyte *) AZURE_STATUS, index + 1, &subIndex, FALSE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, subIndex + 1, &token);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != token.type)
        {
            status = ERR_UM_JSON_PARSE_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        cmpRes = -1;
        if ( (200 == pCtx->responseStatus) &&
             (token.len == DIGI_STRLEN(AZURE_STATUS_ASSIGNED)) )
        {
            cmpRes = DIGI_STRNCMP(token.pStart, AZURE_STATUS_ASSIGNED, token.len);
        }
        else if ( (202 == pCtx->responseStatus) &&
                  (token.len == DIGI_STRLEN(AZURE_STATUS_ASSIGNING)) )
        {
            cmpRes = DIGI_STRNCMP(token.pStart, AZURE_STATUS_ASSIGNING, token.len);
        }
        if (0 != cmpRes)
        {
            status = OK;
            pAzureCtx->error = TRUE;
            goto exit;
        }

        /* Retrieve the operation ID. Used to retrieve information about the
         * device. */
        status = JSON_getObjectIndex(
            pJCtx, (sbyte *) AZURE_OPERATION_ID, index + 1, &index, FALSE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, index + 1, &token);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != token.type)
        {
            status = ERR_UM_JSON_PARSE_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY(
            (void **) &pAzureCtx->pOpId, token.len,
            (void *) token.pStart, token.len);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pAzureCtx->opIdLen = token.len;
    }
    else
    {
        pAzureCtx->error = TRUE;
        goto exit;
    }

exit:

    if (OK != status)
    {
        pCtx->workerStatus = status;
    }

    if (NULL != pAuthKey)
        DIGI_FREE((void **) &pAuthKey);

    if (NULL != pJCtx)
        JSON_releaseContext(&pJCtx);

    return status;
}

/*---------------------------------------------------------------------------*/

static ubyte4 TRUSTEDGE_cloudServiceAzureSetRetryDelaySeconds(
    CloudServiceAzureCtx *pAzureCtx, httpContext *pHttpCtx)
{
    MSTATUS status;
    ubyte4 retryDelaySeconds = pAzureCtx->retryDelaySecondsOrig; /* Set to default */
    ubyte4 retryAfter;
    ubyte *pRsp = NULL, *pRetryAfter = NULL;
    ubyte4 rspLen = 0;

    /* Get 'Retry-After' from HTTP header */
    status = HTTP_REQUEST_getEntityByIndex(
        pHttpCtx, 3, (const ubyte **) &pRsp, &rspLen);
    if (OK != status)
        goto exit;

    /* Format can either be date or number of seconds. Ignore date value, only
     * process number of seconds. */
    if (NULL != pRsp && rspLen > 0 && TRUE == DIGI_ISDIGIT(pRsp[0]))
    {
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pRetryAfter, rspLen + 1, pRsp, rspLen);
        if (OK != status)
            goto exit;

        pRetryAfter[rspLen] = '\0';

        retryAfter = DIGI_ATOL(pRetryAfter, NULL);
        /* Only set retry seconds provided by server if its within min and max
         * boundry and is greater then the retry count provided by the publisher
         */
        if ( (retryAfter > retryDelaySeconds) &&
             (retryAfter >= MIN_RETRY_DELAY_SECONDS) &&
             (retryAfter <= MAX_RETRY_DELAY_SECONDS) )
        {
            retryDelaySeconds = retryAfter;
        }
    }

exit:

    if (NULL != pRetryAfter)
        DIGI_FREE((void **) &pRetryAfter);

    return retryDelaySeconds;
}

/*---------------------------------------------------------------------------*/

/**
 * @brief Construct response JSON for 202 status.
 * @details Parses the server response to extract the "status" field and
 *          constructs a simplified JSON response with retry attempt information.
 *
 * @param pAzureCtx       Pointer to the Azure context containing the server response.
 * @param retryAttempts   Retry attempt count.
 * @param pLastAttemptTime Last attempt time string.
 *
 * @return OK on success, or an error code on failure.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureConstruct202Response(
    CloudServiceAzureCtx *pAzureCtx,
    ubyte4 retryAttempts,
    sbyte *pLastAttemptTime)
{
    MSTATUS status = OK;
    sbyte *pStatusValue = NULL;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 tokensFound = 0;
    ubyte4 jsonLen = 0;
    ubyte *pJsonRsp = NULL;

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pAzureCtx->pServerRsp, pAzureCtx->serverRspLen,
                        &tokensFound);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Get the "status" field value */
    status = JSON_utilReadJsonString(pJCtx, 0, NULL,
                                     (sbyte *) AZURE_STATUS, &pStatusValue, FALSE);
    if (OK != status || NULL == pStatusValue)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d: Failed to get status field\n",
                __func__, __LINE__);
        goto exit;
    }

    /* Calculate JSON length:
     * {"status":"...","attemptDateTimeUtc":"...","retryAttempt":...}
     * Base template is about 60 chars + status + time + number */
    jsonLen = 64 + DIGI_STRLEN(pStatusValue) + DIGI_STRLEN(pLastAttemptTime) + 10;

    status = DIGI_MALLOC((void **) &pJsonRsp, jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct the JSON response */
    jsonLen = sprintf((sbyte *) pJsonRsp,
        "{\"status\":\"%s\",\"attemptDateTimeUtc\":\"%s\",\"retryAttempt\":%u}",
        pStatusValue, pLastAttemptTime, retryAttempts);

    /* Replace the server response with our constructed JSON */
    DIGI_FREE((void **) &(pAzureCtx->pServerRsp));
    pAzureCtx->pServerRsp = pJsonRsp;
    pAzureCtx->serverRspLen = jsonLen;
    pJsonRsp = NULL;  /* Prevent cleanup from freeing it */

    MSG_LOG_print(MSG_LOG_INFO,
            "Constructed 202 response: %.*s\n",
            pAzureCtx->serverRspLen, pAzureCtx->pServerRsp);

exit:
    if (NULL != pStatusValue)
        DIGI_FREE((void **) &pStatusValue);

    if (NULL != pJsonRsp)
        DIGI_FREE((void **) &pJsonRsp);

    if (NULL != pJCtx)
        JSON_releaseContext(&pJCtx);

    return status;
}

/*---------------------------------------------------------------------------*/

/**
 * @brief Extract the "registrationState" object from a 200 response.
 * @details Parses the server response JSON and replaces pServerRsp with just
 *          the "registrationState" object content.
 *
 * @param pAzureCtx Pointer to the Azure context containing the server response.
 *
 * @return OK on success, or an error code on failure.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureConstruct200Response(
    CloudServiceAzureCtx *pAzureCtx)
{
    MSTATUS status = OK;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 index = 0;
    ubyte4 tokensFound = 0;
    JSON_TokenType token = {0};
    ubyte *pNewRsp = NULL;

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pAzureCtx->pServerRsp, pAzureCtx->serverRspLen,
                        &tokensFound);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Find the "registrationState" object */
    status = JSON_getObjectIndex(
        pJCtx, (sbyte *) AZURE_REGISTRATION_STATE, 0, &index, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Get the token for the registrationState object value */
    status = JSON_getToken(pJCtx, index + 1, &token);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Verify it's an object */
    if (JSON_Object != token.type)
    {
        status = ERR_UM_JSON_PARSE_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Allocate new buffer and copy the registrationState object */
    status = DIGI_MALLOC((void **) &pNewRsp, token.len + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    DIGI_MEMCPY(pNewRsp, token.pStart, token.len);
    pNewRsp[token.len] = '\0';

    /* Replace the server response with just the registrationState object */
    DIGI_FREE((void **) &(pAzureCtx->pServerRsp));
    pAzureCtx->pServerRsp = pNewRsp;
    pAzureCtx->serverRspLen = token.len;
    pNewRsp = NULL;  /* Prevent cleanup from freeing it */

    MSG_LOG_print(MSG_LOG_INFO,
            "Extracted registrationState: %.*s\n",
            pAzureCtx->serverRspLen, pAzureCtx->pServerRsp);

exit:
    if (NULL != pNewRsp)
        DIGI_FREE((void **) &pNewRsp);

    if (NULL != pJCtx)
        JSON_releaseContext(&pJCtx);

    return status;
}

/*---------------------------------------------------------------------------*/

/**
 * @brief Construct response JSON for error HTTP status codes.
 * @details Wraps the original Azure response in a JSON object with status,
 *          lastAttemptDateTime, and retryAttempt fields.
 *
 * @param pAzureCtx       Pointer to the Azure context containing the server response.
 * @param retryAttempts   Retry attempt count.
 * @param pLastAttemptTime Last attempt time string.
 *
 * @return OK on success, or an error code on failure.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureConstructErrorResponse(
    CloudServiceAzureCtx *pAzureCtx,
    ubyte4 retryAttempts,
    sbyte *pLastAttemptTime)
{
    MSTATUS status = OK;
    ubyte4 jsonLen = 0;
    ubyte *pJsonRsp = NULL;

    /* Calculate JSON length:
     * {"response":...,"status":"failed","lastAttemptDateTime":"...","retryAttempt":...}
     * Base template is about 70 chars + original response + time + number */
    jsonLen = 80 + pAzureCtx->serverRspLen + DIGI_STRLEN(pLastAttemptTime) + 10;

    status = DIGI_MALLOC((void **) &pJsonRsp, jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct the JSON response */
    jsonLen = sprintf((sbyte *) pJsonRsp,
        "{\"response\":%.*s,\"status\":\"failed\",\"lastAttemptDateTime\":\"%s\",\"retryAttempt\":%u}",
        pAzureCtx->serverRspLen, pAzureCtx->pServerRsp,
        pLastAttemptTime, retryAttempts);

    /* Replace the server response with our constructed JSON */
    DIGI_FREE((void **) &(pAzureCtx->pServerRsp));
    pAzureCtx->pServerRsp = pJsonRsp;
    pAzureCtx->serverRspLen = jsonLen;
    pJsonRsp = NULL;  /* Prevent cleanup from freeing it */

    MSG_LOG_print(MSG_LOG_INFO,
            "Constructed error response: %.*s\n",
            pAzureCtx->serverRspLen, pAzureCtx->pServerRsp);

exit:
    if (NULL != pJsonRsp)
        DIGI_FREE((void **) &pJsonRsp);

    return status;
}

/*---------------------------------------------------------------------------*/

/**
 * @brief Construct the appropriate response based on result of Azure DPS
 *        registration.
 * @details Constructs a JSON response based on TrustEdge error, Azure DPS HTTP
 *          status code, and/or server response.
 *
 * @param pAzureCtx       Pointer to the Azure context containing the server response.
 * @param retryAttempts   Retry attempt count.
 * @param pLastAttemptTime Last attempt time string.
 *
 * @return OK on success, or an error code on failure.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureConstructResponse(
    CloudServiceAzureCtx *pAzureCtx,
    ubyte4 retryAttempts,
    sbyte *pLastAttemptTime)
{
    if (NULL == pAzureCtx)
    {
        return ERR_NULL_POINTER;
    }

    if (NULL == pAzureCtx->pServerRsp || 0 == pAzureCtx->serverRspLen)
    {
        return OK;
    }

    if (200 == pAzureCtx->httpStatusCode)
    {
        return TRUSTEDGE_cloudServiceAzureConstruct200Response(pAzureCtx);
    }

    if (202 == pAzureCtx->httpStatusCode)
    {
        return TRUSTEDGE_cloudServiceAzureConstruct202Response(
            pAzureCtx, retryAttempts, pLastAttemptTime);
    }

    /* All other HTTP status codes are treated as errors */
    return TRUSTEDGE_cloudServiceAzureConstructErrorResponse(
        pAzureCtx, retryAttempts, pLastAttemptTime);
}

/*---------------------------------------------------------------------------*/

/* HTTP callback used to parse a operation status lookup response. Refer to
 * https://docs.microsoft.com/en-us/rest/api/iot-dps/device/runtime-registration/operation-status-lookup
 * for acceptable HTTP status codes and return values.
 *
 * Method retrieves the assigned IotHub.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureOpStatusResponseParse(
    HttpsClientCtx *pCtx)
{
    MSTATUS status;
    CloudServiceAzureCtx *pAzureCtx = NULL;
    ubyte *pRsp = NULL;
    ubyte4 rspLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 index = 0;
    ubyte4 tokenIdx = 0;
    ubyte4 tokensFound = 0;
    JSON_TokenType token = {0};
    sbyte *pAuthKey = NULL;

    status = TRUSTEDGE_clientHttpsLocalGetUserData(pCtx, (void **) &pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pCtx->responseBodyTempFileName, &pRsp, &rspLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_INFO, "Response - %.*s\n", rspLen, pRsp);

    status = TRUSTEDGE_actionSaveEventServerResponse(
        pAzureCtx, pCtx->responseStatus, pRsp, rspLen);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pRsp, rspLen, &tokensFound);
    if( OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

#ifdef DBG_DUMP_JSON
    JSON_DBG_dumpContextInfo( pJCtx);
    JSON_DBG_dumpAllTokens( pJCtx, FALSE);
#endif

    if ( (202 == pCtx->responseStatus) || (200 == pCtx->responseStatus) )
    {
        status = JSON_getObjectIndex(
            pJCtx, (sbyte *) AZURE_STATUS, index, &tokenIdx, TRUE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, tokenIdx + 1, &token);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != token.type)
        {
            status = ERR_UM_JSON_PARSE_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (202 == pCtx->responseStatus)
        {
            if ((token.len == DIGI_STRLEN(AZURE_STATUS_ASSIGNING)) &&
                (0 == DIGI_STRNCMP(AZURE_STATUS_ASSIGNING, token.pStart, token.len)))
            {
                /* Set retry interval if provided */
                pAzureCtx->retryDelaySeconds = TRUSTEDGE_cloudServiceAzureSetRetryDelaySeconds(pAzureCtx, pCtx->pCurrHttpContext);

                /* Don't report error here, only a verbose message. Caller will
                 * determine if retry needs to be done. */
                status = ERR_UM_RETRY;
                MSG_LOG_print(MSG_LOG_VERBOSE,
                        "Operation status set to '%s':"
                        " %s line %d status: %d = %s\n",
                        AZURE_STATUS_ASSIGNING,
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            else
            {
                status = OK;
                pAzureCtx->error = TRUE;
                goto exit;
            }
        }
        else if (200 == pCtx->responseStatus)
        {
            if ((token.len != DIGI_STRLEN(AZURE_STATUS_ASSIGNED)) ||
                (0 != DIGI_STRNCMP(AZURE_STATUS_ASSIGNED, token.pStart, token.len)))
            {
                status = OK;
                pAzureCtx->error = TRUE;
                goto exit;
            }
        }

        status = JSON_getObjectIndex(
            pJCtx, (sbyte *) AZURE_REGISTRATION_STATE, index, &index, TRUE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, index + 1, &token);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_Object != token.type)
        {
            status = ERR_UM_JSON_PARSE_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
        /* Get the authentication key to write out */
        if (AZURE_TPM_REG == pAzureCtx->mode)
        {
            status = JSON_utilReadJsonString(
                pJCtx, index, NULL, AZURE_AUTHENTICATION_KEY, &pAuthKey, TRUE);
            if( OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (NULL != pAzureCtx->pAuthKey)
            {
                DIGI_FREE((void **) &(pAzureCtx->pAuthKey));
            }

            status = TRUSTEDGE_cloudServiceAzureImportKey(
                pAuthKey, &(pAzureCtx->pAuthKey), &(pAzureCtx->authKeyLen));
            if( OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
#endif

        /* Retrieve the assigned IotHub. */
        status = JSON_getObjectIndex(
            pJCtx, (sbyte *) AZURE_ASSIGNED_HUB, index + 1, &tokenIdx, TRUE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, tokenIdx + 1, &token);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != token.type)
        {
            status = ERR_UM_JSON_PARSE_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY(
            (void **) &pAzureCtx->pHub, token.len,
            (void *) token.pStart, token.len);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pAzureCtx->hubLen = token.len;

        /* Retrieve the device ID from the response */
        status = JSON_getObjectIndex(
            pJCtx, (sbyte *) AZURE_DEVICE_ID, index + 1, &tokenIdx, TRUE);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, tokenIdx + 1, &token);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != token.type)
        {
            status = ERR_UM_JSON_PARSE_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY(
            (void **) &pAzureCtx->pDevId, token.len,
            (void *) token.pStart, token.len);
        if( OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pAzureCtx->devIdLen = token.len;
    }
    else
    {
        status = OK;
        pAzureCtx->error = TRUE;
        goto exit;
    }

exit:

    if (OK != status)
    {
        pCtx->workerStatus = status;
    }

    if (NULL != pAuthKey)
        DIGI_FREE((void **) &pAuthKey);

    if (NULL != pJCtx)
        JSON_releaseContext(&pJCtx);

    return status;
}

/*---------------------------------------------------------------------------*/

/* Method to create the registration URI and message. The URI and message is
 * constructed as per
 * https://docs.microsoft.com/en-us/rest/api/iot-dps/device/runtime-registration/register-device
 *
 * The URI is constructed as follows
 *
 *     https://global.azure-devices-provisioning.net:443/{idScope}/registrations/{registrationId}/register?api-version=2021-06-01
 *
 * The message is constructed as follows for X.509 enrollment
 *
 *     {"registrationId":"<registrationId>"}
 *
 * For TPM enrollment
 *
 *     {
 *         "registrationId" : "<registrationId>", <= Base32 of the EK with no padding and all lowercase
 *         "tpm" : {
 *             "endorsementKey" : "<EK>", <= Base64 of EK public key
 *             "storageRootKey": "<SRK>" <= Base64 of SRK public key
 *         }
 *     }
 *
 * where registrationId is the certificate common name.
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureBuildRegisterUriAndMsg(
    CloudServiceAzureCtx *pCtx)
{
    MSTATUS status;
    int length = 0;
    int ret = 0;
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    sbyte *pBase64EK = NULL, *pBase64SRK = NULL;
    ubyte4 base64EKLen = 0, base64SRKLen = 0;
#endif

    /* Free the existing message */
    if (NULL != pCtx->pURI)
        DIGI_FREE((void **) &pCtx->pURI);
    if (NULL != pCtx->pMsg)
        DIGI_FREE((void **) &pCtx->pMsg);

    pCtx->msgLen = 0;

    /* Get the total URI length and allocate memory for it */
    length = snprintf(NULL, 0, AZURE_REGISTER_URI,
                pCtx->pSchemeAndHost,
                pCtx->portStrLen, pCtx->pPortStr,
                pCtx->idScopeLen, pCtx->pIdScope,
                AZURE_REGISTRATIONS,
                pCtx->regIdLen, pCtx->pRegId,
                AZURE_REGISTER,
                AZURE_API_VERSION);
    status = DIGI_MALLOC((void **) &pCtx->pURI, length + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct the URI */
    ret = snprintf(pCtx->pURI, length + 1, AZURE_REGISTER_URI,
                pCtx->pSchemeAndHost,
                pCtx->portStrLen, pCtx->pPortStr,
                pCtx->idScopeLen, pCtx->pIdScope,
                AZURE_REGISTRATIONS,
                pCtx->regIdLen, pCtx->pRegId,
                AZURE_REGISTER,
                AZURE_API_VERSION);
    if ((0 > ret) || (length != ret))
    {
        status = ERR_UM_URL_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    if (AZURE_TPM_REG == pCtx->mode) /* TPM enrollment */
    {
        status = TRUSTEDGE_clientTapGetBase64RoTKeyblob(
            TAP_PROVIDER_TPM2, 0, EK_OBJECT_ID, TRUE, &pBase64EK);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        base64EKLen = DIGI_STRLEN(pBase64EK);

        status = TRUSTEDGE_clientTapGetBase64RoTKeyblob(
            TAP_PROVIDER_TPM2, 0, SRK_OBJECT_ID_START, TRUE, &pBase64SRK);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        base64SRKLen = DIGI_STRLEN(pBase64EK);

        length = snprintf(NULL, 0, AZURE_REGISTER_TPM_MSG,
                    AZURE_REGISTRATION_ID,
                    pCtx->regIdLen, pCtx->pRegId,
                    AZURE_TPM,
                    AZURE_ENDORSEMENT_KEY,
                    base64EKLen, pBase64EK,
                    AZURE_STORAGE_ROOT_KEY,
                    base64SRKLen, pBase64SRK);
        status = DIGI_MALLOC((void **) &pCtx->pMsg, length + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Construct the message */
        ret = snprintf(pCtx->pMsg, length + 1, AZURE_REGISTER_TPM_MSG,
                    AZURE_REGISTRATION_ID,
                    pCtx->regIdLen, pCtx->pRegId,
                    AZURE_TPM,
                    AZURE_ENDORSEMENT_KEY,
                    base64EKLen, pBase64EK,
                    AZURE_STORAGE_ROOT_KEY,
                    base64SRKLen, pBase64SRK);
        if ((0 > ret) || (length != ret))
        {
            status = ERR_UM_URL_CREATION_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->msgLen = length;
    }
    else
#endif
    {
        /* Get the total message length and allocate memory for it */
        length = snprintf(NULL, 0, AZURE_REGISTER_X509_MSG,
                    AZURE_REGISTRATION_ID,
                    pCtx->regIdLen, pCtx->pRegId);
        status = DIGI_MALLOC((void **) &pCtx->pMsg, length + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Construct the message */
        ret = snprintf(pCtx->pMsg, length + 1, AZURE_REGISTER_X509_MSG,
                    AZURE_REGISTRATION_ID,
                    pCtx->regIdLen, pCtx->pRegId);
        if ((0 > ret) || (length != ret))
        {
            status = ERR_UM_URL_CREATION_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->msgLen = length;
    }

    /* Set the message, user data, HTTP header callback, and HTTP response
     * callback. */
    status = TRUSTEDGE_clientHttpsLocalSetCustomMsg(
        pCtx->pHttpCtx, pCtx->pMsg, pCtx->msgLen, pCtx,
        TRUSTEDGE_cloudServiceAzureRegisterOrOpStatusPrepareHeaderRequest,
        TRUSTEDGE_cloudServiceAzureRegisterResponseParse);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    if (NULL != pBase64SRK)
        DIGI_FREE((void **) &pBase64SRK);

    if (NULL != pBase64EK)
        DIGI_FREE((void **) &pBase64EK);
#endif

    return status;
}

/*---------------------------------------------------------------------------*/

/* Method to create the operation status lookup URI. The URI is constructed as
 * per
 * https://docs.microsoft.com/en-us/rest/api/iot-dps/device/runtime-registration/operation-status-lookup
 *
 * The URI is constructed as follows
 *
 *     https://global.azure-devices-provisioning.net/{idScope}/registrations/{registrationId}/operations/{operationId}?api-version=2021-06-01
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureBuildOpStatusUriAndMsg(
    CloudServiceAzureCtx *pCtx)
{
    MSTATUS status;
    int length = 0;
    int ret = 0;

    /* Free the existing URI and message */
    if (NULL != pCtx->pURI)
        DIGI_FREE((void **) &pCtx->pURI);

    if (NULL != pCtx->pMsg)
        DIGI_FREE((void **) &pCtx->pMsg);

    pCtx->msgLen = 0;

    /* Get the total URI length and allocate memory for it */
    length = snprintf(NULL, 0, AZURE_OP_STATUS_URI,
                pCtx->pSchemeAndHost,
                pCtx->portStrLen, pCtx->pPortStr,
                pCtx->idScopeLen, pCtx->pIdScope,
                AZURE_REGISTRATIONS,
                pCtx->regIdLen, pCtx->pRegId,
                AZURE_OPERATIONS,
                pCtx->opIdLen, pCtx->pOpId,
                AZURE_API_VERSION);
    status = DIGI_MALLOC((void **) &pCtx->pURI, length + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct the URI */
    ret = snprintf(pCtx->pURI, length + 1, AZURE_OP_STATUS_URI,
                pCtx->pSchemeAndHost,
                pCtx->portStrLen, pCtx->pPortStr,
                pCtx->idScopeLen, pCtx->pIdScope,
                AZURE_REGISTRATIONS,
                pCtx->regIdLen, pCtx->pRegId,
                AZURE_OPERATIONS,
                pCtx->opIdLen, pCtx->pOpId,
                AZURE_API_VERSION);
    if ((0 > ret) || (length != ret))
    {
        status = ERR_UM_URL_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set the message, user data, HTTP header callback, and HTTP response
     * callback. */
    status = TRUSTEDGE_clientHttpsLocalSetCustomMsg(
        pCtx->pHttpCtx, NULL, 0, pCtx,
        TRUSTEDGE_cloudServiceAzureRegisterOrOpStatusPrepareHeaderRequest,
        TRUSTEDGE_cloudServiceAzureOpStatusResponseParse);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

/* Method constructs the Azure cloud service information stored on the file
 * system. The output file is a JSON file with the following key/value pairs
 *
 * {
 *     "iothub_url": "<ASSIGNED_HUB>",
 *     "device_id": "<DEVICE_ID>",
 *     "device_cert": "<CERT_FILE>",
 *     "device_key": "<KEY_FILE>"
 * }
 *
 * iothub_url - This is the hub assigned by the Azure DPS instance
 * device_id - This is the device ID assigned by the Azure DPS instance
 * device_cert - This is the file containing the certificate used for
 *     registration
 * device_key - This is the file containing the key used for registration
 */
static MSTATUS TRUSTEDGE_cloudServiceAzureGenerateServiceConfig(
    CloudServiceAzureCtx *pAzureCtx,
    ubyte **ppProviderCredJson,
    ubyte4 *pProviderCredJsonLen)
{
    MSTATUS status;
    int ret;
    ubyte *pConf = NULL;
    int confLen;
    sbyte *pKeyPath = NULL;
    sbyte *pCertPath = NULL;

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TPM2__) && defined(__ENABLE_DIGICERT_TRUSTEDGE_CLOUD_SERVICE_AZURE_TPM2__)
    if (AZURE_TPM_REG == pAzureCtx->mode)
    {
        status = COMMON_UTILS_addPathComponent(
            pAzureCtx->pAgentCtx->pConfig->pKeystoreDir,
            AZURE_KEY_FILE, &pKeyPath);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGICERT_writeFile(
            pKeyPath, pAzureCtx->pAuthKey, pAzureCtx->authKeyLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        ret = snprintf(NULL, 0, AZURE_SERVICE_CONFIG_TPM,
                        AZURE_CONFIG_IOTHUB_URL, pAzureCtx->hubLen, pAzureCtx->pHub,
                        AZURE_CONFIG_DEVICE_ID, pAzureCtx->devIdLen, pAzureCtx->pDevId,
                        AZURE_CONFIG_KEY_TYPE, AZURE_CONFIG_KEY_TYPE_TAP,
                        AZURE_CONFIG_KEY_INFO,
                        AZURE_CONFIG_KEY_INFO_MODULE, AZURE_CONFIG_KEY_INFO_MODULE_TPM2,
                        AZURE_CONFIG_KEY_INFO_KEY_FILE, pKeyPath);
        if (0 > ret)
        {
            status = ERR_UM_MSG_CREATION_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
        confLen = ret;

        status = DIGI_CALLOC((void **) &pConf, 1, confLen + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Construct the config file */
        ret = snprintf(pConf, confLen + 1, AZURE_SERVICE_CONFIG_TPM,
                        AZURE_CONFIG_IOTHUB_URL, pAzureCtx->hubLen, pAzureCtx->pHub,
                        AZURE_CONFIG_DEVICE_ID, pAzureCtx->devIdLen, pAzureCtx->pDevId,
                        AZURE_CONFIG_KEY_TYPE, AZURE_CONFIG_KEY_TYPE_TAP,
                        AZURE_CONFIG_KEY_INFO,
                        AZURE_CONFIG_KEY_INFO_MODULE, AZURE_CONFIG_KEY_INFO_MODULE_TPM2,
                        AZURE_CONFIG_KEY_INFO_KEY_FILE, pKeyPath);
        if ((0 > ret) || (confLen != ret))
        {
            status = ERR_UM_MSG_CREATION_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
#endif
    {

        status = TRUSTEDGE_getCertificateAndKeyPathByPolicyId(
            pAzureCtx->pAgentCtx,
            pAzureCtx->pAgentCtx->curPolicy.pPolicy->pDependency->pPolicies->pPolicyId,
            &pCertPath, &pKeyPath);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Get the total length of the config file and allocate memory for it */
        confLen = snprintf(NULL, 0, AZURE_SERVICE_CONFIG_X509,
                            AZURE_CONFIG_IOTHUB_URL, pAzureCtx->hubLen, pAzureCtx->pHub,
                            AZURE_CONFIG_DEVICE_ID, pAzureCtx->devIdLen, pAzureCtx->pDevId,
                            AZURE_CONFIG_DEVICE_CERT, pCertPath,
                            AZURE_CONFIG_DEVICE_KEY, pKeyPath);

        status = DIGI_CALLOC((void **) &pConf, 1, confLen + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Construct the config file */
        ret = snprintf(pConf, confLen + 1, AZURE_SERVICE_CONFIG_X509,
                            AZURE_CONFIG_IOTHUB_URL, pAzureCtx->hubLen, pAzureCtx->pHub,
                            AZURE_CONFIG_DEVICE_ID, pAzureCtx->devIdLen, pAzureCtx->pDevId,
                            AZURE_CONFIG_DEVICE_CERT, pCertPath,
                            AZURE_CONFIG_DEVICE_KEY, pKeyPath);
        if ((0 > ret) || (confLen != ret))
        {
            status = ERR_UM_MSG_CREATION_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    *ppProviderCredJson = pConf;
    *pProviderCredJsonLen = confLen;
    pConf = NULL; /* Ownership transferred to caller */

exit:

    if (NULL != pConf)
        DIGI_FREE((void **) &pConf);

    if (NULL != pKeyPath)
        DIGI_FREE((void **) &pKeyPath);

    if (NULL != pCertPath)
        DIGI_FREE((void **) &pCertPath);

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_cloudServiceAzureRunClient(
    CloudServiceAzureCtx *pAzureCtx)
{
    MSTATUS status;

    /* Make the connection and send HTTPS message */
    status = TRUSTEDGE_HTTPS_UTIL_runClient(pAzureCtx->pHttpCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (OK != pAzureCtx->pHttpCtx->workerStatus)
    {
        status = pAzureCtx->pHttpCtx->workerStatus;
        goto exit;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_cloudServiceAzurePerformRequest(
    CloudServiceAzureCtx *pAzureCtx)
{
    MSTATUS status;

    pAzureCtx->pHttpCtx->workerStatus = OK;
    pAzureCtx->httpStatusCode = 0;
    pAzureCtx->error = FALSE;

    /* Currently connection is made directly, not through a thread. Default
     * system timeouts will be used. Could use TRUSTEDGE_clientHttps
     * methods directly to control timeout if necessary. */

    status = TRUSTEDGE_cloudServiceAzureRunClient(pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Try one more time with reauthentication */
    if ( (401 == pAzureCtx->httpStatusCode) &&
         (FALSE == pAzureCtx->error) )
    {
        status = TRUSTEDGE_cloudServiceAzureRunClient(pAzureCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

/* Method is used to register against Azure DPS instance. It expects a JSON
 * context and index into the context pointing to the Azure JSON attributes.
 */
extern MSTATUS TRUSTEDGE_cloudServiceAzureRegister(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen,
    ubyte4 *pHttpStatusCode,
    ubyte **ppServerRsp,
    ubyte4 *pServerRspLen,
    ubyte **ppProviderCredJson,
    ubyte4 *pProviderCredJsonLen)
{
    MSTATUS status, tmpStatus;
    CloudServiceAzureCtx *pAzureCtx = NULL;
    byteBoolean retry;
    ubyte4 attempts = 0;
    sbyte *pLastAttemptTimestamp = NULL;

    /* Parse the JSON Azure attributes and create an Azure context. */
    status = TRUSTEDGE_cloudServiceAzureContextCreate(
        pJson, jsonLen, pCtx, &pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Create the register URI and message. */
    status = TRUSTEDGE_cloudServiceAzureBuildRegisterUriAndMsg(pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    DIGI_FREE((void **) &pLastAttemptTimestamp);
    status = TRUSTEDGE_utilsGetTime(&pLastAttemptTimestamp, 0);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_cloudServiceAzurePerformRequest(pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "Failed to send register message:"
                " %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == pAzureCtx->error)
    {
        status = ERR_TRUSTEDGE_AZURE_REGISTRATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "Azure registration failed:"
                " %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Create the operation status lookup URI. */
    status = TRUSTEDGE_cloudServiceAzureBuildOpStatusUriAndMsg(pAzureCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    retry = TRUE;
    attempts = 0;
    do
    {
        DIGI_FREE((void **) &pLastAttemptTimestamp);
        status = TRUSTEDGE_utilsGetTime(&pLastAttemptTimestamp, 0);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_cloudServiceAzurePerformRequest(pAzureCtx);
        if ((OK == status) || (++attempts > pAzureCtx->retryMaxCount))
        {
            retry = FALSE;
        }
        else if (ERR_UM_RETRY == status)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE,
                    "Attempting to retry operation status lookup request in %d seconds:"
                    " %s line %d status: %d = %s\n",
                    pAzureCtx->retryDelaySeconds,
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            if (0 != pAzureCtx->retryDelaySeconds)
                RTOS_sleepMS(pAzureCtx->retryDelaySeconds * 1000);
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "Fatal error when performing operation status lookup:"
                    " %s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

    } while (retry);

    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "Failed to perform operation status lookup:"
                " %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == pAzureCtx->error)
    {
        status = ERR_TRUSTEDGE_AZURE_REGISTRATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "Azure registration failed:"
                " %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_INFO,
        "Azure Registration ID: %.*s\n", pAzureCtx->regIdLen, pAzureCtx->pRegId);

    /* Generate the Azure service config information */
    status = TRUSTEDGE_cloudServiceAzureGenerateServiceConfig(
        pAzureCtx, ppProviderCredJson, pProviderCredJsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pAzureCtx)
    {
        /* Construct response sent to DTM based on Azure response */
        tmpStatus = TRUSTEDGE_cloudServiceAzureConstructResponse(
            pAzureCtx, attempts, pLastAttemptTimestamp);
        if (OK == status)
            status = tmpStatus;

        *pHttpStatusCode = pAzureCtx->httpStatusCode;
        *ppServerRsp = pAzureCtx->pServerRsp;
        *pServerRspLen = pAzureCtx->serverRspLen;
        pAzureCtx->pServerRsp = NULL;
        pAzureCtx->serverRspLen = 0;
        TRUSTEDGE_cloudServiceAzureContextDelete(&pAzureCtx);
    }

    DIGI_FREE((void **) &pLastAttemptTimestamp);

    return status;
}

/*---------------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_TPUC_CLOUD_SERVICE_AZURE__ */
