/*
 * trustedge_agent_certificate.c
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

#include "../../trustedge/agent/trustedge_agent_certificate.h"
#include "../../trustedge/agent/trustedge_agent_policy.h"
#include "../../trustedge/agent/trustedge_agent_persist.h"

#ifdef __ENABLE_DIGICERT_PQC__
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_sig.h"
#endif

#define SELECTED_CERT_ALIAS_JSTR    "selectedCertAlias"
#define CERT_EXPIRE_TIME_JSTR       "certExpireTime"
#define LAST_RENEW_REQUEST_JSTR     "lastRenewRequest"
#define LAST_RENEW_RESPONSE_JSTR    "lastRenewResponse"

#define SC_DEVICE_ID_JSTR               "deviceId"
#define SC_ACCOUNT_ID_JSTR              "accountId"
#define SC_DEVICE_GROUP_ID_JSTR         "deviceGroupId"
#define SC_CERTIFICATE_POLICY_ID_JSTR   "certificatePolicyId"
#define SC_REQUEST_JSTR                 "request"

#define CERTIFICATE_RENEW_UUID      "DeviceTM_Certificate_Policy_Renew_Request"

#define MQTT_CERTIFICATE_RENEW_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_policy_renew_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"renewRequest\":\"%.*s\",\n" \
    "    \"renewRequestSignature\": {\n" \
    "        \"algorithm\":\"%s\",\n" \
    "        \"signature\":\"%s\"\n" \
    "    }\n" \
    "}\n"

#define RENEW_DATA_MSG \
    "{\n" \
    "    \"csr\":\"%s\",\n" \
    "    \"csrFormat\":\"pkcs10\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"certificate\":\"%.*s\"\n" \
    "}\n"

#define DEFAULT_RENEW_REQUEST_BACKOFF_HOURS     12

/* Create renew data in the following format
 *
 * {
 *     "csr": "<csr>"
 *     "csrFormat": "pkcs10",
 *     "certificatePolicyId" : "<id>",
 *     "timestamp": "<timestamp>",
 *     "certificate": "<certificate>"
 * }
 *
 * Returns both the JSON renew data and base encoded renew data
 */
static MSTATUS TRUSTEDGE_agentCertificateCreateRenewData(
    TrustEdgeAgentCtx *pCtx,
    JSON_ContextType *pJCtx,
    ubyte **ppRenewData,
    ubyte4 *pRenewDataLen,
    ubyte **ppSign,
    ubyte4 *pSignLen)
{
    MSTATUS status;
    sbyte *pPolicyId = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte *pAlias = NULL;
    sbyte *pFilePath = NULL;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pOneLineCert = NULL;
    ubyte4 oneLineCertLen = 0;
    ubyte *pRenewData = NULL;
    ubyte4 size = 0;
    sbyte *pRequest = NULL;

    /* Get values from issued JSON file */
    status = JSON_getJsonStringValue(
        pJCtx, 0, SC_CERTIFICATE_POLICY_ID_JSTR, &pPolicyId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SELECTED_CERT_ALIAS_JSTR, &pAlias, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SC_REQUEST_JSTR, &pRequest, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Get certificate to use for renew data request */
    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pKeystoreCertsDir, pAlias, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(
        pFilePath, ".pem", &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pCert, &certLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct certificate in single line format */
    status = TRUSTEDGE_utilsOneLineCert(
        pCert, certLen, &pOneLineCert, &oneLineCertLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct renew data message */
    size = snprintf(NULL, 0, RENEW_DATA_MSG,
                pRequest,
                pPolicyId,
                pTimeStamp,
                oneLineCertLen, pOneLineCert);

    status = DIGI_MALLOC((void **) &pRenewData, size + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    snprintf(pRenewData, size + 1, RENEW_DATA_MSG,
                pRequest,
                pPolicyId,
                pTimeStamp,
                oneLineCertLen, pOneLineCert);

    status = BASE64_encodeMessage(pRenewData, size, ppRenewData, pRenewDataLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppSign = pRenewData;
    *pSignLen = size;

exit:

    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pTimeStamp);
    DIGI_FREE((void **) &pAlias);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pCert);
    DIGI_FREE((void **) &pOneLineCert);
    DIGI_FREE((void **) &pRequest);

    return status;
}

static MSTATUS TRUSTEDGE_agentCertificateAlgToString(
    JWSAlg alg,
    sbyte **ppAlgStr)
{
    MSTATUS status;

    switch (alg)
    {
        case JWS_ALG_RS256:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_RS256;
            break;
        case JWS_ALG_RS384:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_RS384;
            break;
        case JWS_ALG_RS512:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_RS512;
            break;
        case JWS_ALG_ES256:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_ES256;
            break;
        case JWS_ALG_ES384:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_ES384;
            break;
        case JWS_ALG_ES512:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_ES512;
            break;
        case JWS_ALG_PS256:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_PS256;
            break;
        case JWS_ALG_PS384:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_PS384;
            break;
        case JWS_ALG_PS512:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_PS512;
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_MLDSA44;
            break;
        case JWS_ALG_MLDSA65:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_MLDSA65;
            break;
        case JWS_ALG_MLDSA87:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_MLDSA87;
            break;
        case JWS_ALG_SLHDSA_SHA2_128F:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128F;
            break;
        case JWS_ALG_SLHDSA_SHA2_128S:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128S;
            break;
        case JWS_ALG_SLHDSA_SHA2_192F:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192F;
            break;
        case JWS_ALG_SLHDSA_SHA2_192S:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192S;
            break;
        case JWS_ALG_SLHDSA_SHA2_256F:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256F;
            break;
        case JWS_ALG_SLHDSA_SHA2_256S:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256S;
            break;
        case JWS_ALG_SLHDSA_SHAKE_128F:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128F;
            break;
        case JWS_ALG_SLHDSA_SHAKE_128S:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128S;
            break;
        case JWS_ALG_SLHDSA_SHAKE_192F:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192F;
            break;
        case JWS_ALG_SLHDSA_SHAKE_192S:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192S;
            break;
        case JWS_ALG_SLHDSA_SHAKE_256F:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256F;
            break;
        case JWS_ALG_SLHDSA_SHAKE_256S:
            *ppAlgStr = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256S;
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
            goto exit;
    }

    status = OK;

exit:

    return status;
}

static MSTATUS TRUSTEDGE_agentCertificateGetSigAlg(
    AsymmetricKey *pAsymKey,
    JWSAlg *pAlg)
{
    MSTATUS status;
    sbyte4 lenRsaN;
    ubyte4 curveId;

    switch (pAsymKey->type & 0xFF)
    {
        case akt_rsa:
            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(
                pAsymKey->key.pRSA, &lenRsaN);
            if (OK != status)
            {
                goto exit;
            }

            if (NULL != pAsymKey->pAlgoId &&
                ALG_ID_RSA_SSA_PSS_OID == pAsymKey->pAlgoId->oidFlag)
            {
                if (256 == lenRsaN)
                    *pAlg = JWS_ALG_PS256;
                else if (384 == lenRsaN)
                    *pAlg = JWS_ALG_PS384;
                else if (512 == lenRsaN)
                    *pAlg = JWS_ALG_PS512;
                else
                {
                    status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
                    goto exit;
                }
            }
            else
            {
                if (256 == lenRsaN)
                    *pAlg = JWS_ALG_RS256;
                else if (384 == lenRsaN)
                    *pAlg = JWS_ALG_RS384;
                else if (512 == lenRsaN)
                    *pAlg = JWS_ALG_RS512;
                else
                {
                    status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
                    goto exit;
                }
            }
            break;

        case akt_ecc:
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(
                pAsymKey->key.pECC, &curveId);
            if (OK != status)
            {
                goto exit;
            }

            if (cid_EC_P256 == curveId)
                *pAlg = JWS_ALG_ES256;
            else if (cid_EC_P384 == curveId)
                *pAlg = JWS_ALG_ES384;
            else if (cid_EC_P521 == curveId)
                *pAlg = JWS_ALG_ES512;
            else
            {
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
            }
            break;

#ifdef __ENABLE_DIGICERT_PQC__
        case akt_qs:
            status = CRYPTO_INTERFACE_QS_getAlg(pAsymKey->pQsCtx, &curveId); /* reuse curveId var for pqc alg */
            if (OK != status)
            {
                goto exit;
            }

            if (cid_PQC_MLDSA_44 == curveId)
                *pAlg = JWS_ALG_MLDSA44;
            else if (cid_PQC_MLDSA_65 == curveId)
                *pAlg = JWS_ALG_MLDSA65;
            else if (cid_PQC_MLDSA_87 == curveId)
                *pAlg = JWS_ALG_MLDSA87;
            else if (cid_PQC_SLHDSA_SHA2_128F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_128F;
            else if (cid_PQC_SLHDSA_SHA2_128S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_128S;
            else if (cid_PQC_SLHDSA_SHA2_192F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_192F;
            else if (cid_PQC_SLHDSA_SHA2_192S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_192S;
            else if (cid_PQC_SLHDSA_SHA2_256F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_256F;
            else if (cid_PQC_SLHDSA_SHA2_256S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_256S;
            else if (cid_PQC_SLHDSA_SHAKE_128F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_128F;
            else if (cid_PQC_SLHDSA_SHAKE_128S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_128S;
            else if (cid_PQC_SLHDSA_SHAKE_192F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_192F;
            else if (cid_PQC_SLHDSA_SHAKE_192S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_192S;
            else if (cid_PQC_SLHDSA_SHAKE_256F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_256F;
            else if (cid_PQC_SLHDSA_SHAKE_256S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_256S;
            else
            {
                status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
                goto exit;
            }
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
            break;
    }

exit:

    return status;
}

static MSTATUS TRUSTEDGE_agentCertificateCreateRenewSignature(
    TrustEdgeAgentCtx *pAgentCtx,
    AsymmetricKey *pAsymKey,
    JWSAlg alg,
    ubyte *pRenewData,
    ubyte4 renewDataLen,
    sbyte **ppSignature)
{
    MOC_UNUSED(pAgentCtx);
    MSTATUS status;
    BulkCtx pCtx = NULL;
    ubyte pDigest[SHA512_RESULT_SIZE];
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;
    sbyte4 sigLen = 0;
    ubyte *pSig = NULL;
    ubyte4 len;
    BulkHashAlgo *pBulkHashAlgo = NULL;
    ubyte4 hashId = 0;
    ubyte4 saltLen = 0;
    ubyte *pFullMsg = NULL;
    ubyte4 fullMsgLen = 0;

    switch (alg)
    {
        case JWS_ALG_RS256:
            status = CRYPTO_getRSAHashAlgo(ht_sha256, (const BulkHashAlgo **) &pBulkHashAlgo);
            break;

        case JWS_ALG_RS384:
            status = CRYPTO_getRSAHashAlgo(ht_sha384, (const BulkHashAlgo **) &pBulkHashAlgo);
            break;

        case JWS_ALG_RS512:
            status = CRYPTO_getRSAHashAlgo(ht_sha512, (const BulkHashAlgo **) &pBulkHashAlgo);
            break;

        case JWS_ALG_ES256:
            status = CRYPTO_getECCHashAlgo(ht_sha256, &pBulkHashAlgo);
            break;

        case JWS_ALG_ES384:
            status = CRYPTO_getECCHashAlgo(ht_sha384, &pBulkHashAlgo);
            break;

        case JWS_ALG_ES512:
            status = CRYPTO_getECCHashAlgo(ht_sha512, &pBulkHashAlgo);
            break;

        case JWS_ALG_PS256:
            hashId = ht_sha256;
            saltLen = SHA256_RESULT_SIZE;
            status = OK;
            break;
        case JWS_ALG_PS384:
            hashId = ht_sha384;
            saltLen = SHA384_RESULT_SIZE;
            status = OK;
            break;
        case JWS_ALG_PS512:
            hashId = ht_sha512;
            saltLen = SHA512_RESULT_SIZE;
            status = OK;
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
        case JWS_ALG_MLDSA65:
        case JWS_ALG_MLDSA87:
        case JWS_ALG_SLHDSA_SHA2_128F:
        case JWS_ALG_SLHDSA_SHA2_128S:
        case JWS_ALG_SLHDSA_SHA2_192F:
        case JWS_ALG_SLHDSA_SHA2_192S:
        case JWS_ALG_SLHDSA_SHA2_256F:
        case JWS_ALG_SLHDSA_SHA2_256S:
        case JWS_ALG_SLHDSA_SHAKE_128F:
        case JWS_ALG_SLHDSA_SHAKE_128S:
        case JWS_ALG_SLHDSA_SHAKE_192F:
        case JWS_ALG_SLHDSA_SHAKE_192S:
        case JWS_ALG_SLHDSA_SHAKE_256F:
        case JWS_ALG_SLHDSA_SHAKE_256S:
            hashId = ht_none;
            saltLen = 0;
            status = OK;
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
            break;
    }
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pBulkHashAlgo)
    {
        status = pBulkHashAlgo->allocFunc(&pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->initFunc(pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->updateFunc(
            pCtx, pRenewData, renewDataLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->finalFunc(pCtx, pDigest);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
    {
        fullMsgLen = renewDataLen;

        status = DIGI_MALLOC((void **) &pFullMsg, fullMsgLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_MEMCPY(pFullMsg, pRenewData, renewDataLen);
    }

    switch (alg)
    {
        case JWS_ALG_RS256:
        case JWS_ALG_RS384:
        case JWS_ALG_RS512:
            status = ASN1_buildDigestInfoAlloc(
                pDigest, pBulkHashAlgo->digestSize, pBulkHashAlgo->hashId,
                &pDigestInfo, &digestInfoLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(
                pAsymKey->key.pRSA, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case JWS_ALG_ES256:
        case JWS_ALG_ES384:
        case JWS_ALG_ES512:
            status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
                pAsymKey->key.pECC, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            sigLen *= 2;
            break;

        case JWS_ALG_PS256:
        case JWS_ALG_PS384:
        case JWS_ALG_PS512:
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
        case JWS_ALG_MLDSA65:
        case JWS_ALG_MLDSA87:
        case JWS_ALG_SLHDSA_SHA2_128F:
        case JWS_ALG_SLHDSA_SHA2_128S:
        case JWS_ALG_SLHDSA_SHA2_192F:
        case JWS_ALG_SLHDSA_SHA2_192S:
        case JWS_ALG_SLHDSA_SHA2_256F:
        case JWS_ALG_SLHDSA_SHA2_256S:
        case JWS_ALG_SLHDSA_SHAKE_128F:
        case JWS_ALG_SLHDSA_SHAKE_128S:
        case JWS_ALG_SLHDSA_SHAKE_192F:
        case JWS_ALG_SLHDSA_SHAKE_192S:
        case JWS_ALG_SLHDSA_SHAKE_256F:
        case JWS_ALG_SLHDSA_SHAKE_256S:
            status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pAsymKey->pQsCtx, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;
#endif
        case JWS_ALG_NONE:
            status = ERR_TRUSTEDGE_AGENT;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
    }

    if (0 != sigLen)
    {
        status = DIGI_MALLOC((void **) &pSig, sigLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    switch (alg)
    {
        case JWS_ALG_RS256:
        case JWS_ALG_RS384:
        case JWS_ALG_RS512:
            status = CRYPTO_INTERFACE_RSA_signMessageAux(
                pAsymKey->key.pRSA, pDigestInfo, digestInfoLen, pSig, NULL);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case JWS_ALG_ES256:
        case JWS_ALG_ES384:
        case JWS_ALG_ES512:
            status = CRYPTO_INTERFACE_ECDSA_signDigestAux(
                pAsymKey->key.pECC, RANDOM_rngFun, g_pRandomContext, pDigest,
                pBulkHashAlgo->digestSize, pSig, sigLen, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case JWS_ALG_PS256:
        case JWS_ALG_PS384:
        case JWS_ALG_PS512:
            status = CRYPTO_INTERFACE_PKCS1_rsaPssSign(
                g_pRandomContext, pAsymKey->key.pRSA, hashId,
                MOC_PKCS1_ALG_MGF1, hashId, pFullMsg, fullMsgLen, saltLen,
                &pSig, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
        case JWS_ALG_MLDSA65:
        case JWS_ALG_MLDSA87:
        case JWS_ALG_SLHDSA_SHA2_128F:
        case JWS_ALG_SLHDSA_SHA2_128S:
        case JWS_ALG_SLHDSA_SHA2_192F:
        case JWS_ALG_SLHDSA_SHA2_192S:
        case JWS_ALG_SLHDSA_SHA2_256F:
        case JWS_ALG_SLHDSA_SHA2_256S:
        case JWS_ALG_SLHDSA_SHAKE_128F:
        case JWS_ALG_SLHDSA_SHAKE_128S:
        case JWS_ALG_SLHDSA_SHAKE_192F:
        case JWS_ALG_SLHDSA_SHAKE_192S:
        case JWS_ALG_SLHDSA_SHAKE_256F:
        case JWS_ALG_SLHDSA_SHAKE_256S:
            status = CRYPTO_INTERFACE_QS_SIG_sign(pAsymKey->pQsCtx, RANDOM_rngFun, g_pRandomContext, pFullMsg, fullMsgLen,
                                                  pSig, sigLen, &sigLen);

            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;
#endif
        case JWS_ALG_NONE:
            status = ERR_TRUSTEDGE_AGENT;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
    }

    status = BASE64_encodeMessage(
        pSig, sigLen, (ubyte **) ppSignature, &len);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppSignature)[len] = '\0';

exit:

    DIGI_FREE((void **) &pFullMsg);
    DIGI_FREE((void **) &pDigestInfo);
    CRYPTO_INTERFACE_SHA256_freeDigest(&pCtx);
    DIGI_FREE((void **) &pSig);

    return status;
}

/* Construct signature over renew data. This function returns base64 encoded
 * signature and algorithm used for signing.
 */
static MSTATUS TRUSTEDGE_agentCertificateGetRenewSignature(
    TrustEdgeAgentCtx *pCtx,
    AsymmetricKey *pAsymKey,
    ubyte *pRenewData,
    ubyte4 renewDataLen,
    sbyte **ppAlgorithm,
    sbyte **ppSignature)
{
    MSTATUS status;
    sbyte *pAlias = NULL;
    sbyte *pFilePath = NULL;
    ubyte *pKey = NULL;
    JWSAlg alg;

    /* Determine algorithm based on key */
    status = TRUSTEDGE_agentCertificateGetSigAlg(pAsymKey, &alg);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Get algorithm as string */
    status = TRUSTEDGE_agentCertificateAlgToString(alg, ppAlgorithm);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Create signature over renew data using private key */
    status = TRUSTEDGE_agentCertificateCreateRenewSignature(
        pCtx, pAsymKey, alg, pRenewData, renewDataLen, ppSignature);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pKey);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pAlias);

    return status;
}

/* Performs renew operation for single issued JSON file
 */
static MSTATUS TRUSTEDGE_agentCertificateRenewOperation(
    TrustEdgeAgentCtx *pCtx,
    JSON_ContextType *pJCtx)
{
    MSTATUS status;
    sbyte *pDeviceId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pDeviceGroupId = NULL;
    sbyte *pPolicyId = NULL;
    ubyte *pRenewData = NULL;
    ubyte4 renewDataLen = 0;
    sbyte *pAlgorithm = NULL;
    sbyte *pSignature = NULL;
    sbyte *pMsg = NULL;
    ubyte4 size = 0;
    ubyte *pProtobuf = NULL;
    ubyte4 protobufLen = 0;
    sbyte *pTimeStamp = NULL;
    ubyte *pSign = NULL;
    ubyte4 signLen = 0;
    AsymmetricKey asymKey = { 0 };
    sbyte *pAlias = NULL;
    sbyte *pFilePath = NULL;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    CRYPTO_initAsymmetricKey(&asymKey);

    /* Get ID values from issued certificate file */
    status = JSON_getJsonStringValue(
        pJCtx, 0, SC_DEVICE_ID_JSTR, &pDeviceId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SC_ACCOUNT_ID_JSTR, &pAccountId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SC_DEVICE_GROUP_ID_JSTR, &pDeviceGroupId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SC_CERTIFICATE_POLICY_ID_JSTR, &pPolicyId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Validate IDs and ensure policy has been applied */
    status = TRUSTEDGE_validateAppliedPolicy(
        pCtx, pDeviceId, pAccountId, pDeviceGroupId,
        pPolicyId, TE_POLICY_TYPE_CERTIFICATE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Retrieve the key used for signing */
    status = JSON_getJsonStringValue(
        pJCtx, 0, "selectedKeyAlias", &pAlias, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pKeystoreKeysDir, pAlias, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(
        pFilePath, ".pem", &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pKey, &keyLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, &asymKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Create renew data */
    status = TRUSTEDGE_agentCertificateCreateRenewData(
        pCtx, pJCtx, &pRenewData, &renewDataLen, &pSign, &signLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Sign renew data */
    status = TRUSTEDGE_agentCertificateGetRenewSignature(
        pCtx, &asymKey, pSign, signLen, &pAlgorithm, &pSignature);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Construct renew request */
    size = snprintf(NULL, 0, MQTT_CERTIFICATE_RENEW_MSG,
                pDeviceId,
                pAccountId,
                pTimeStamp,
                pDeviceGroupId,
                pPolicyId,
                renewDataLen, pRenewData,
                pAlgorithm,
                pSignature);

    status = DIGI_MALLOC((void **) &pMsg, size + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    snprintf(pMsg, size + 1, MQTT_CERTIFICATE_RENEW_MSG,
                pDeviceId,
                pAccountId,
                pTimeStamp,
                pDeviceGroupId,
                pPolicyId,
                renewDataLen, pRenewData,
                pAlgorithm,
                pSignature);

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, CERTIFICATE_RENEW_UUID, pMsg, size,
        &pProtobuf, &protobufLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_INFO, "Sending renew request for policy %s\n", pPolicyId);

    /* Publish renew request */
    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pProtobuf, protobufLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Save timestamp at when renew request was sent */
    status = TRUSTEDGE_agentPersistCertSpecAddOrUpdateRenewRequestTime(
        pCtx, pPolicyId);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pKey);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pAlias);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pRenewData);
    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pMsg);
    DIGI_FREE((void **) &pProtobuf);
    DIGI_FREE((void **) &pTimeStamp);
    DIGI_FREE((void **) &pSign);

    return status;
}

static MSTATUS TRUSTEDGE_agentCertificateRenewalPendingInternal(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pFilePath,
    byteBoolean *pIsPending)
{
    MSTATUS status;
    ubyte *pJson = NULL;
    ubyte4 jsonLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    sbyte *pTime = NULL;
    sbyte *pRspTime = NULL;

    *pIsPending = FALSE;

    if (FALSE == FMGMT_pathExists(pFilePath, NULL))
    {
        status = OK;
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pJson, &jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
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

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, CERT_EXPIRE_TIME_JSTR, &pTime, TRUE);
    if (ERR_NOT_FOUND == status)
    {
        status = OK;
        goto exit;
    }
    else if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == TRUSTEDGE_utilsIsExpired(pTime, pCtx->pConfig->agentRenewalHours * 60 * 60))
    {
        goto exit;
    }

    /* Check when the last renewal request was sent */
    DIGI_FREE((void **) &pTime);
    status = JSON_getJsonStringValue(
        pJCtx, 0, LAST_RENEW_REQUEST_JSTR, &pTime, TRUE);
    if (OK == status)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, LAST_RENEW_RESPONSE_JSTR, &pRspTime, TRUE);
        if (ERR_NOT_FOUND == status)
        {
            status = OK;
            *pIsPending = TRUE;
            goto exit;
        }
        else if (OK == status)
        {
            /* If pTime > pRspTime then agent needs to wait for response */
            if (FALSE == TRUSTEDGE_utilsInValidTimeWindowStr(pTime, pRspTime))
            {
                *pIsPending = TRUE;
                goto exit;
            }
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    else if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pJson);
    DIGI_FREE((void **) &pTime);
    DIGI_FREE((void **) &pRspTime);
    JSON_releaseContext(&pJCtx);

    return status;
}

extern MSTATUS TRUSTEDGE_agentCertificateRenewalPending(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    byteBoolean *pIsPending)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pIssuedCertDir, pId, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(pFilePath, JSON_EXT, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentCertificateRenewalPendingInternal(
        pCtx, pFilePath, pIsPending);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pFilePath);

    return status;
}

extern MSTATUS TRUSTEDGE_agentCertificateAnyRenewalPending(
    TrustEdgeAgentCtx *pCtx,
    byteBoolean *pIsPending)
{
    MSTATUS status;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEntry = { 0 };
    sbyte *pFilePath = NULL;

    status = FMGMT_getFirstFile(
        pCtx->pIssuedCertDir, &pDir, &dirEntry);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    while (FTNone != dirEntry.type)
    {
        if (FTFile == dirEntry.type)
        {
            status = COMMON_UTILS_addPathComponentWithLength(
                pCtx->pIssuedCertDir, dirEntry.pName, dirEntry.nameLength,
                &pFilePath);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = TRUSTEDGE_agentCertificateRenewalPendingInternal(
                pCtx, pFilePath, pIsPending);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                        "Failed renewal check/processing on %s file, %d status (%s)\n",
                        pFilePath, status, MERROR_lookUpErrorCode(status));
                status = OK;
            }

            if (TRUE == *pIsPending)
            {
                break;
            }
        }

        status = FMGMT_getNextFile (pDir, &dirEntry);
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

    if (NULL != pDir)
    {
        FMGMT_closeDir(&pDir);
    }

    DIGI_FREE((void **) &pFilePath);

    return status;
}

static MSTATUS TRUSTEDGE_agentCertificateRenew(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pFilePath)
{
    MSTATUS status;
    ubyte *pJson = NULL;
    ubyte4 jsonLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    sbyte *pAlias = NULL;
    sbyte *pTime = NULL;
    sbyte *pRspTime = NULL;

    MSG_LOG_print(
        MSG_LOG_VERBOSE, "Checking if renewal required for %s\n", pFilePath);

    status = DIGICERT_readFile(pFilePath, &pJson, &jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
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

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SELECTED_CERT_ALIAS_JSTR, &pAlias, TRUE);
    if (ERR_NOT_FOUND == status)
    {
        /* Certificate not issued, exit with OK */
        status = OK;
        goto exit;
    }
    else if (OK != status)
    {
        /* Error occurred while looking for certificate alias */
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, CERT_EXPIRE_TIME_JSTR, &pTime, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == TRUSTEDGE_utilsIsExpired(pTime, pCtx->pConfig->agentRenewalHours * 60 * 60))
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE, "Skipping renew operation, time %s outside renewal window hours of %d\n",
            pTime, pCtx->pConfig->agentRenewalHours);
        status = OK;
        goto exit;
    }

    /* Check when the last renewal request was sent */
    DIGI_FREE((void **) &pTime);
    status = JSON_getJsonStringValue(
        pJCtx, 0, LAST_RENEW_REQUEST_JSTR, &pTime, TRUE);
    if (OK == status)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, LAST_RENEW_RESPONSE_JSTR, &pRspTime, TRUE);
        if (ERR_NOT_FOUND == status)
        {
            /* No response found, agent needs to wait for response */
            MSG_LOG_print(
                MSG_LOG_VERBOSE, "Renew response not found, waiting for response for last request sent at %s\n",
                pTime);
            status = OK;
        }
        else if (OK == status)
        {
            /* If pTime > pRspTime then agent needs to wait for response */
            if (FALSE == TRUSTEDGE_utilsInValidTimeWindowStr(pTime, pRspTime))
            {
                MSG_LOG_print(
                    MSG_LOG_VERBOSE, "Renew response %s outdated, waiting for response for last request sent at %s\n",
                    pRspTime, pTime);
                goto exit;
            }

            /* If the request time is within the backoff hours then do not
             * send another request */
            if (FALSE == TRUSTEDGE_utilsInValidTimeWindow(pTime, DEFAULT_RENEW_REQUEST_BACKOFF_HOURS * 60))
            {
                MSG_LOG_print(
                    MSG_LOG_VERBOSE, "Last request sent within %d hours, waiting for response for last request sent at %s\n",
                    DEFAULT_RENEW_REQUEST_BACKOFF_HOURS, pTime);
                goto exit;
            }
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    else if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_VERBOSE, "Performing renew operation for %s\n", pFilePath);

    status = TRUSTEDGE_agentCertificateRenewOperation(pCtx, pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    DIGI_FREE((void **) &pJson);
    DIGI_FREE((void **) &pAlias);
    DIGI_FREE((void **) &pTime);
    DIGI_FREE((void **) &pRspTime);

    return status;
}

/* Loop through all issued JSON files and check if they require a renewal
 * operation
 */
extern MSTATUS TRUSTEDGE_agentCertificateRenewAll(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEntry = { 0 };
    sbyte *pFilePath = NULL;

    status = FMGMT_getFirstFile(
        pCtx->pIssuedCertDir, &pDir, &dirEntry);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    while (FTNone != dirEntry.type)
    {
        if (FTFile == dirEntry.type)
        {
            status = COMMON_UTILS_addPathComponentWithLength(
                pCtx->pIssuedCertDir, dirEntry.pName, dirEntry.nameLength,
                &pFilePath);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = TRUSTEDGE_agentCertificateRenew(pCtx, pFilePath);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                        "Failed renewal check/processing on %s file, %d status (%s)\n",
                        pFilePath, status, MERROR_lookUpErrorCode(status));
                status = OK;
            }
        }

        status = FMGMT_getNextFile (pDir, &dirEntry);
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

    if (NULL != pDir)
    {
        FMGMT_closeDir(&pDir);
    }

    DIGI_FREE((void **) &pFilePath);

    return status;
}

typedef struct mimeCertificateHandlerData {
    TrustEdgeAgentCtx *pCtx;    /* in */
    sbyte *pPkcs7Data;          /* out */
    sbyte4 pkcs7DataLen;        /* out */
    AsymmetricKey *pKey;        /* out */
    sbyte *pId;                 /* out */
} mimeCertificateHandlerData;

static MimePartProcessArg *createCertificateHandlerData (TrustEdgeAgentCtx *pCtx)
{
    mimeCertificateHandlerData *pStruct;

    if (OK != DIGI_MALLOC((void **) &pStruct, sizeof(*pStruct)))
    {
        return NULL;
    }

    if (OK != DIGI_MEMSET ((ubyte *)pStruct, 0x00, sizeof(*pStruct)))
    {
        DIGI_FREE((void **) &pStruct);
        return NULL;
    }

    pStruct->pCtx = pCtx;

    return (MimePartProcessArg *) pStruct;
}

static void freeCertificateHandlerData (MimePartProcessArg **ppStruct)
{
    if (NULL == ppStruct) return;
    mimeCertificateHandlerData *pStruct = *ppStruct;

    if (NULL != pStruct->pKey)
    {
        CRYPTO_uninitAsymmetricKey(pStruct->pKey, NULL);
        DIGI_FREE((void **) &(pStruct->pKey));
    }
    DIGI_FREE((void **) &(pStruct->pId));
    DIGI_FREE((void **) &(pStruct->pPkcs7Data));
    DIGI_FREE((void **) ppStruct);
}

#define PKCS7_HEADER        "-----BEGIN PKCS7-----\n"
#define PKCS7_FOOTER        "-----END PKCS7-----\n"

static MSTATUS TRUSTEDGE_getKeyById(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    AsymmetricKey **ppKey)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;
    AsymmetricKey *pAsymKey = NULL;
    ubyte *pJson = NULL;
    ubyte4 jsonLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    sbyte *pAlias = NULL;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    status = DIGI_CALLOC((void **) &pAsymKey, 1, sizeof(AsymmetricKey));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    CRYPTO_initAsymmetricKey(pAsymKey);

    status = COMMON_UTILS_addPathComponent(
        pCtx->pIssuedCertDir, pId, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(pFilePath, JSON_EXT, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pJson, &jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
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

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, SELECTED_CERT_ALIAS_JSTR, &pAlias, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pKeystoreKeysDir, pAlias, &pFilePath);
    if (OK != status)
        goto exit;

    status = COMMON_UTILS_addPathExtension(
        pFilePath, ".pem", &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pKey, &keyLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, pAsymKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppKey = pAsymKey;
    pAsymKey = NULL;

exit:

    DIGI_FREE((void **) &pKey);
    DIGI_FREE((void **) &pJson);
    DIGI_FREE((void **) &pAlias);
    DIGI_FREE((void **) &pFilePath);
    JSON_releaseContext(&pJCtx);
    if (NULL != pAsymKey)
    {
        CRYPTO_uninitAsymmetricKey(pAsymKey, NULL);
        DIGI_FREE((void **) &pAsymKey);
    }

    return status;
}

static MSTATUS processCertificateRenewMimePart(
    MimePart *pPart,
    MimePartProcessArg *pInfo)
{
    MSTATUS status;
    mimeCertificateHandlerData *pState;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte *pPkcs7Start, *pPkcs7End;
    sbyte *pId = NULL;
    sbyte *pPkcs7Data = NULL;
    sbyte4 pkcs7DataLen;
    sbyte *pKeyData = NULL;
    byteBoolean isPending = FALSE;

    if (NULL == pPart || NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pState = (mimeCertificateHandlerData *) pInfo;

    if (MIME_CONTENT_TYPE_JSON == pPart->contentType)
    {
        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
        {
            goto exit;
        }

        status = JSON_parse(pJCtx, pPart->pData, pPart->dataLen, &numTokens);
        if (OK != status)
        {
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, SC_CERTIFICATE_POLICY_ID_JSTR, &pId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = TRUSTEDGE_agentCertificateRenewalPending(
            pState->pCtx, pId, &isPending);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        if (FALSE == isPending)
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "Renewal not required for policy %s\n", pId);
            status = OK;
            goto exit;
        }
        else
        {
            MSG_LOG_print(MSG_LOG_INFO,
                "Recieved renew response for policy %s\n", pId);
        }

        /* Mark that we got a response, might fail later on in the parsing */
        status = TRUSTEDGE_agentPersistCertSpecUpdate(
            pState->pCtx, pId, NULL, 0);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_getKeyById(
            pState->pCtx, pId, &pState->pKey);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pState->pId = pId;
        pId = NULL;
    }
    else if (MIME_CONTENT_TYPE_PKCS7_MIME == pPart->contentType)
    {
        pPkcs7Data = NULL;
        if (pPart->dataLen >= DIGI_STRLEN(PKCS7_HEADER) && 0 == DIGI_STRNCMP(pPart->pData, PKCS7_HEADER, DIGI_STRLEN(PKCS7_HEADER)))
        {
            pPkcs7Start = pPart->pData + DIGI_STRLEN(PKCS7_HEADER);
        }
        else
        {
            pPkcs7Start = pPart->pData;
        }
        if (pPart->dataLen >= DIGI_STRLEN(PKCS7_FOOTER) && 0 == DIGI_STRNCMP(pPart->pData + pPart->dataLen - DIGI_STRLEN(PKCS7_FOOTER), PKCS7_FOOTER, DIGI_STRLEN(PKCS7_FOOTER)))
        {
            pPkcs7End = pPart->pData + pPart->dataLen - DIGI_STRLEN(PKCS7_FOOTER);
        }
        else
        {
            pPkcs7End = pPart->pData + pPart->dataLen;
        }

        pkcs7DataLen = pPkcs7End - pPkcs7Start;
        status = DIGI_MALLOC_MEMCPY ((void **) &pPkcs7Data, pkcs7DataLen, pPkcs7Start, pkcs7DataLen);
        if (OK != status)
            goto exit;

        pState->pPkcs7Data = pPkcs7Data;
        pState->pkcs7DataLen = pkcs7DataLen;
        pPkcs7Data = NULL;
    }
    else
    {
        status = OK;
    }
exit:

    JSON_releaseContext(&pJCtx);

    DIGI_FREE((void **) &pPkcs7Data);
    DIGI_FREE((void **) &pKeyData);
    DIGI_FREE((void **) &pId);
    return status;
}

extern MSTATUS TRUSTEDGE_agentParseCertificateRenew(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pBody,
    ubyte4 bodyLen)
{
    MSTATUS status;
    MimePartProcessArg *pHandlerData = NULL;
    MimePayload payloadData = { 0 };
    mimeCertificateHandlerData *pCertData;
    certDescriptor *pCertDescArray = NULL;
    ubyte4 certDescArrayLen = 0, i;

    pHandlerData = createCertificateHandlerData (pCtx);
    if (NULL == pHandlerData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    payloadData.pFile = NULL;
    payloadData.pPayLoad = pBody;
    payloadData.payloadLen = bodyLen;
    status = MIME_process (&payloadData, processCertificateRenewMimePart, pHandlerData);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCertData = (mimeCertificateHandlerData*) pHandlerData;
    if (NULL == pCertData->pPkcs7Data)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = CERT_ENROLL_parseResponse(pCertData->pPkcs7Data, pCertData->pkcs7DataLen, pCertData->pKey, TRUE,
                                    &pCertDescArray, &certDescArrayLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to process PKCS7 renew response %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Update with the actual renewed certificate */
    status = TRUSTEDGE_agentPersistCertSpecUpdate(
        pCtx, pCertData->pId, pCertDescArray[0].pCertificate,
        pCertDescArray[0].certLength);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pCertDescArray)
    {
        for (i = 0; i < certDescArrayLen; i++)
        {
            DIGI_FREE((void **) &pCertDescArray[i].pCertificate);
        }
        DIGI_FREE((void **) &pCertDescArray);
    }

    freeCertificateHandlerData (&pHandlerData);

    return status;
}
