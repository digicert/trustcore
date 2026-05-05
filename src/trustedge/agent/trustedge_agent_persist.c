/*
 * trustedge_agent_persist.c
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

#include "../../trustedge/agent/trustedge_agent_persist.h"
#include "../../trustedge/agent/trustedge_agent_policy.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/trustedge_certificate_main.h"

#include <stdio.h>

#define ADD_SUFFIX(x, y) x y
#define PENDING_POLICY_FILE             "pending_policy.json"
#define PROCESSING_POLICY_FILE          "processing_policy.json"
#define APPLIED_POLICY_FILE             "applied_policy.json"
#define FAILED_POLICY_FILE              "failed_policy.json"

#define CERT_SPEC_JSON_FILE             "cert_spec.json"

#define UNKNOWN_TYPE                    "UNKNOWN"
#define CERTIFICATE_TPYE                "CERTIFICATE"
#define UPDATE_TYPE                     "UPDATE"
#define CLOUDPLATFORM_TYPE              "CLOUDPLATFORM"

#define LAST_RENEW_REQUEST_JSTR             "lastRenewRequest"
#define LAST_RENEW_REQUEST_QUOTED           "\"" LAST_RENEW_REQUEST_JSTR "\""
#define LAST_RENEW_RESPONSE_JSTR            "lastRenewResponse"
#define LAST_RENEW_RESPONSE_QUOTED          "\"" LAST_RENEW_RESPONSE_JSTR "\""
#define CERT_ISSUED_TIME_JSTR               "certIssuedTime"
#define CERT_ISSUED_TIME_QUOTED             "\"" CERT_ISSUED_TIME_JSTR "\""
#define CERT_EXPIRE_TIME_JSTR               "certExpireTime"
#define CERT_EXPIRE_TIME_QUOTED             "\"" CERT_EXPIRE_TIME_JSTR "\""

#define PERSISTED_CERT_SPEC_JSON \
    "{\n" \
    "    \"originalCertSpec\": %.*s,\n" \
    "    \"selectedKeySource\": \"%.*s\",\n" \
    "    \"selectedKeyAlgorithm\": \"%.*s\",\n" \
    "    \"selectedKeyAlias\": \"%s\"\n" \
    "}\n"

#define PERSISTED_CERT_SPEC_CERT_EXT_JSON \
    "%.*s,\n" \
    "    \"request\": \"%.*s\",\n" \
    "    \"selectedCertAlias\": \"%s\",\n" \
    "    " CERT_ISSUED_TIME_QUOTED ": \"%s\",\n" \
    "    " CERT_EXPIRE_TIME_QUOTED ": \"%s\"\n" \
    "}"

#define PERSISTED_CERT_SPEC_CERT_RENEW_JSON \
    "%.*s,\n" \
    "    " LAST_RENEW_REQUEST_QUOTED ": \"%s\"\n" \
    "}"

#define PERSISTED_CERT_SPEC_CERT_RENEW_RSP_JSON \
    "%.*s,\n" \
    "    " LAST_RENEW_RESPONSE_QUOTED ": \"%s\"\n" \
    "}"

#ifdef __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__
#ifndef __RTOS_LINUX__
#error __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__ only works on linux
#endif
static sbyte4 snapshotCounter = 0;

static void copyPersistedFiles(TrustEdgeAgentCtx *pCtx, sbyte *pFileName, sbyte4 counter, sbyte4 read)
{
    MSTATUS status;
    FileDescriptorInfo fdInfo = { 0 };
    sbyte *pOutFile = NULL;
    sbyte4 ret;
    sbyte *pOperation;
    ubyte *pData = NULL;
    ubyte4 dataLen;

    sbyte *pInFile = NULL;


    if (NULL == pCtx->pConfig->pDebugDir)
    {
        status = OK;
        MSG_LOG_print(MSG_LOG_DEBUG,
            "%s line %d status: %d = %s. no debug dir, skip operation..\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pCtx->pConfig->pConfDir)
    {
        status = OK;
        MSG_LOG_print(MSG_LOG_DEBUG,
            "%s line %d status: %d = %s. no config dir, skip operation..\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, pFileName, &pInFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pInFile, &fdInfo))
    {
        MSG_LOG_print(MSG_LOG_DEBUG,
            "%s line %d status: %d = %s. %s does not exist..\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pInFile);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pCtx->pDebugDir, &fdInfo))
    {
        status = FMGMT_mkdir(pCtx->pDebugDir, 0744);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (FTDirectory != fdInfo.type)
    {
        status = ERR_DIR_NOT_DIRECTORY;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (read)
        pOperation = "read";
    else
        pOperation = "write";

    ret = snprintf(NULL, 0, "%s/seqnum%d.%s.%s", pCtx->pDebugDir, counter, pOperation, pFileName);
    if (ret <= 0)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MALLOC((void **) &pOutFile, ret + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(pOutFile, ret + 1, "%s/seqnum%d.%s.%s", pCtx->pDebugDir, counter, pOperation, pFileName);
    if (ret <= 0)
    {
        status = ERR_TRUSTEDGE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,
        "copying %s to %s\n", pInFile, pOutFile);

    status = DIGICERT_readFile(pInFile, &pData, &dataLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_writeFile(pOutFile, pData, dataLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pInFile);
    DIGI_FREE((void **) &pOutFile);
    DIGI_FREE((void **) &pData);
}

static void copyAllPersistedFiles(TrustEdgeAgentCtx *pCtx, sbyte4 counter, sbyte4 read)
{
    copyPersistedFiles(pCtx, PENDING_POLICY_FILE, counter, read);
    copyPersistedFiles(pCtx, PROCESSING_POLICY_FILE, counter, read);
    copyPersistedFiles(pCtx, APPLIED_POLICY_FILE, counter, read);
    copyPersistedFiles(pCtx, FAILED_POLICY_FILE, counter, read);
}
#endif

static MSTATUS TRUSTEDGE_agentPersistErrorPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pTmpFilePath = NULL;
    sbyte *pFilePath = NULL;
    FileDescriptor pFile = NULL;
    TrustEdgeAgentPolicyNode *pNode;
    sbyte *pType;
    sbyte *pState;
    sbyte *pMsgType;
    TrustEdgeAgentArtifactNode *pArtifact;
    ubyte4 i = 0;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, ADD_SUFFIX(FAILED_POLICY_FILE, ".tmp"), &pTmpFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, FAILED_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pNode = pCtx->pErrorPolicies;

    status = FMGMT_fopen(pTmpFilePath, "w", &pFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    FMGMT_fprintf(pFile, "{\n");
    FMGMT_fprintf(pFile, "    \"failedPolicies\": [\n");
    while (NULL != pNode)
    {
        if (pNode != pCtx->curPolicy.pPolicy)
        {
            if (TE_POLICY_TYPE_CERTIFICATE == pNode->type)
            {
                pType = CERTIFICATE_TPYE;
            }
            else if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                pType = UPDATE_TYPE;
            }
            else if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                pType = CLOUDPLATFORM_TYPE;
            }
            else
            {
                pType = UNKNOWN_TYPE;
            }

            FMGMT_fprintf(pFile, "        {\n");
            FMGMT_fprintf(pFile, "            \"deviceGroupId\": \"%s\",\n", pNode->pDeviceGroupId);
            FMGMT_fprintf(pFile, "            \"policyType\": \"%s\",\n", pType);
            FMGMT_fprintf(pFile, "            \"policyId\": \"%s\",\n", pNode->pId);
            if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"deploymentId\": \"%s\",\n", pNode->pDeploymentId);
            }
            FMGMT_fprintf(pFile, "            \"priority\": %d,\n", pNode->priority);
            if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"policyDependency\": [\n");
                for (i = 0; i < pNode->pDependency->count; i++)
                {
                    FMGMT_fprintf(pFile, "                {\n");
                    FMGMT_fprintf(pFile, "                    \"policyType\": \"%s\",\n", pNode->pDependency->pPolicies[i].pPolicyType);
                    FMGMT_fprintf(pFile, "                    \"policyId\": \"%s\"\n", pNode->pDependency->pPolicies[i].pPolicyId);

                    if (i < pNode->pDependency->count - 1)
                    {
                        FMGMT_fprintf(pFile, "                },\n");
                    }
                    else
                    {
                        FMGMT_fprintf(pFile, "                }\n");
                    }
                }
                FMGMT_fprintf(pFile, "            ],\n");
            }
            FMGMT_fprintf(pFile, "            \"policyErrorResponses\": %d,\n", pNode->errorResponseCount);
            FMGMT_fprintf(pFile, "            \"creationTimestamp\": \"%s\",\n", pNode->pCreationTimestamp);
            FMGMT_fprintf(pFile, "            \"processTimestamp\": \"%s\",\n", pNode->pProccessingTimestamp);
            FMGMT_fprintf(pFile, "            \"errorTimestamp\": \"%s\",\n", pNode->pCompletionTimestamp); /* used for error timestamp as well*/

            FMGMT_fprintf(pFile, "            \"status\": \"FAILED\",\n");

            if (TE_POLICY_TYPE_CERTIFICATE == pNode->type || TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                switch(pNode->lastMsgSentType)
                {
                    case TE_MSG_TYPE_CERTIFICATE_SPECIFICATION:
                        pMsgType = "SPECIFICATION";
                        break;
                    case TE_MSG_TYPE_ISSUED_CERTIFICATE:
                        pMsgType = "CERTIFICATE";
                        break;
                    case TE_MSG_TYPE_CLOUDPLATFORM:
                        pMsgType = "CLOUDPLATFORM";
                        break;
                    case TE_MSG_TYPE_PENDING_POLICIES:
                    default:
                        pMsgType = "PENDING";
                        break;
                }
                FMGMT_fprintf(pFile, "            \"policyState\": \"%s\"\n", pMsgType);
            }
            else if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"policyData\": {\n");
                FMGMT_fprintf(pFile, "                \"artifactList\": [\n");
                pArtifact = pNode->pArtifactList;

                while (NULL != pArtifact)
                {
                    pState = TRUSTEDGE_getArtifactProgressToString(pArtifact->state);
                    FMGMT_fprintf(pFile, "                    {\n");
                    FMGMT_fprintf(pFile, "                        \"artifactId\": \"%s\",\n", pArtifact->pId);
                    FMGMT_fprintf(pFile, "                        \"artifactName\": \"%s\",\n", pArtifact->pName);
                    FMGMT_fprintf(pFile, "                        \"artifactVersion\": \"%s\",\n", pArtifact->pVersion);
                    FMGMT_fprintf(pFile, "                        \"artifactTimestamp\": \"%s\",\n", pArtifact->pTimestamp);
                    FMGMT_fprintf(pFile, "                        \"artifactSize\": %d,\n", pArtifact->size);
                    FMGMT_fprintf(pFile, "                        \"artifactState\": \"%s\",\n", pState);
                    FMGMT_fprintf(pFile, "                        \"artifactAsync\": %s,\n", (pArtifact->isAsync ? "true": "false"));
                    FMGMT_fprintf(pFile, "                        \"artifactIgnore\": %s\n", (pArtifact->ignore ? "true": "false"));
                    FMGMT_fprintf(pFile, "                    }%s\n", (NULL == pArtifact->pNext) ? "" : ",");

                    pArtifact = pArtifact->pNext;
                }
                FMGMT_fprintf(pFile, "                ]\n");
                FMGMT_fprintf(pFile, "            }\n");
            }
            FMGMT_fprintf(pFile, "        }%s\n", (NULL == pNode->pNext) ? "" : ",");
        }

        pNode = pNode->pNext;
    }
    FMGMT_fprintf(pFile, "    ]\n");
    FMGMT_fprintf(pFile, "}\n");

exit:

    if (pFile)
    {
        FMGMT_fflush(pFile);
        FMGMT_fclose(&pFile);
        if (OK == status)
            FMGMT_rename(pTmpFilePath, pFilePath);
    }

    DIGI_FREE((void **) &pTmpFilePath);
    DIGI_FREE((void **) &pFilePath);

    return status;
}

static MSTATUS TRUSTEDGE_agentPersistPendingPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pTmpFilePath = NULL;
    sbyte *pFilePath = NULL;
    FileDescriptor pFile = NULL;
    TrustEdgeAgentPolicyNode *pNode;
    sbyte *pType;
    ubyte4 i = 0;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, ADD_SUFFIX(PENDING_POLICY_FILE, ".tmp"), &pTmpFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, PENDING_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pNode = pCtx->pPendingPolicies;

    status = FMGMT_fopen(pTmpFilePath, "w", &pFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    FMGMT_fprintf(pFile, "{\n");
    FMGMT_fprintf(pFile, "    \"pendingPolicies\": [\n");
    while (NULL != pNode)
    {
        if (pNode != pCtx->curPolicy.pPolicy)
        {
            if (TE_POLICY_TYPE_CERTIFICATE == pNode->type)
            {
                pType = CERTIFICATE_TPYE;
            }
            else if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                pType = UPDATE_TYPE;
            }
            else if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                pType = CLOUDPLATFORM_TYPE;
            }
            else
            {
                pType = UNKNOWN_TYPE;
            }

            FMGMT_fprintf(pFile, "        {\n");
            FMGMT_fprintf(pFile, "            \"deviceGroupId\": \"%s\",\n", pNode->pDeviceGroupId);
            FMGMT_fprintf(pFile, "            \"policyType\": \"%s\",\n", pType);
            FMGMT_fprintf(pFile, "            \"policyId\": \"%s\",\n", pNode->pId);
            if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"deploymentId\": \"%s\",\n", pNode->pDeploymentId);
            }
            FMGMT_fprintf(pFile, "            \"priority\": %d,\n", pNode->priority);
            if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"policyDependency\": [\n");
                for (i = 0; i < pNode->pDependency->count; i++)
                {
                    FMGMT_fprintf(pFile, "                {\n");
                    FMGMT_fprintf(pFile, "                    \"policyType\": \"%s\",\n", pNode->pDependency->pPolicies[i].pPolicyType);
                    FMGMT_fprintf(pFile, "                    \"policyId\": \"%s\"\n", pNode->pDependency->pPolicies[i].pPolicyId);

                    if (i < pNode->pDependency->count - 1)
                    {
                        FMGMT_fprintf(pFile, "                },\n");
                    }
                    else
                    {
                        FMGMT_fprintf(pFile, "                }\n");
                    }
                }
                FMGMT_fprintf(pFile, "            ],\n");
            }
            FMGMT_fprintf(pFile, "            \"policyErrorResponses\": %d,\n", pNode->errorResponseCount);
            FMGMT_fprintf(pFile, "            \"creationTimestamp\": \"%s\"\n", pNode->pCreationTimestamp);
            FMGMT_fprintf(pFile, "        }%s\n", (NULL == pNode->pNext) ? "" : ",");
        }

        pNode = pNode->pNext;
    }
    FMGMT_fprintf(pFile, "    ]\n");
    FMGMT_fprintf(pFile, "}\n");

exit:

    if (pFile)
    {
        FMGMT_fflush(pFile);
        FMGMT_fclose(&pFile);
        if (OK == status)
            FMGMT_rename(pTmpFilePath, pFilePath);
    }

    DIGI_FREE((void **) &pTmpFilePath);
    DIGI_FREE((void **) &pFilePath);

    return status;
}

static MSTATUS TRUSTEDGE_agentPersistProcessingPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pTmpFilePath = NULL;
    sbyte *pFilePath = NULL;
    FileDescriptor pFile = NULL;
    TrustEdgeAgentPolicyNode *pNode;
    TrustEdgeAgentArtifactNode *pArtifact;
    sbyte *pState;
    sbyte *pMsgType;
    sbyte *pInMsgType;
    sbyte *pType;
    sbyte *pCertSpecJsonFile = NULL;
    ubyte4 i = 0;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, ADD_SUFFIX(PROCESSING_POLICY_FILE, ".tmp"), &pTmpFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, PROCESSING_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, CERT_SPEC_JSON_FILE, &pCertSpecJsonFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pNode = pCtx->curPolicy.pPolicy;

    status = FMGMT_fopen(pTmpFilePath, "w", &pFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    FMGMT_fprintf(pFile, "{\n");
    FMGMT_fprintf(pFile, "    \"processingPolicies\": [\n");
    if (NULL != pNode)
    {
        if (TE_POLICY_TYPE_CERTIFICATE == pNode->type)
        {
            pType = CERTIFICATE_TPYE;
        }
        else if (TE_POLICY_TYPE_UPDATE == pNode->type)
        {
            pType = UPDATE_TYPE;
        }
        else if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
        {
            pType = CLOUDPLATFORM_TYPE;
        }
        else
        {
            pType = UNKNOWN_TYPE;
        }

        FMGMT_fprintf(pFile, "        {\n");
        FMGMT_fprintf(pFile, "            \"deviceGroupId\": \"%s\",\n", pNode->pDeviceGroupId);
        FMGMT_fprintf(pFile, "            \"policyType\": \"%s\",\n", pType);
        FMGMT_fprintf(pFile, "            \"policyId\": \"%s\",\n", pNode->pId);
        if (TE_POLICY_TYPE_UPDATE == pNode->type)
        {
            if (TE_POLICY_STATUS_ROLLBACK == pNode->status)
            {
                FMGMT_fprintf(pFile, "            \"policyMode\": \"ROLLBACK\",\n");
            }
            else if (TE_POLICY_STATUS_FAILURE == pNode->status)
            {
                FMGMT_fprintf(pFile, "            \"policyMode\": \"FAILURE\",\n");
            }
            else
            {
                FMGMT_fprintf(pFile, "            \"policyMode\": \"PROCESSING\",\n");
            }
            FMGMT_fprintf(pFile, "            \"deploymentId\": \"%s\",\n", pNode->pDeploymentId);
        }
        else if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
        {
            FMGMT_fprintf(pFile, "            \"policyDependency\": [\n");
            for (i = 0; i < pNode->pDependency->count; i++)
            {
                FMGMT_fprintf(pFile, "                {\n");
                FMGMT_fprintf(pFile, "                    \"policyType\": \"%s\",\n", pNode->pDependency->pPolicies[i].pPolicyType);
                FMGMT_fprintf(pFile, "                    \"policyId\": \"%s\"\n", pNode->pDependency->pPolicies[i].pPolicyId);

                if (i < pNode->pDependency->count - 1)
                {
                    FMGMT_fprintf(pFile, "                },\n");
                }
                else
                {
                    FMGMT_fprintf(pFile, "                }\n");
                }
            }
            FMGMT_fprintf(pFile, "            ],\n");
        }

        switch(pCtx->curPolicy.lastPolicyMsgType)
        {
            case TE_MSG_TYPE_CERTIFICATE_SPECIFICATION:
                pInMsgType = "SPECIFICATION";
                break;
            case TE_MSG_TYPE_ISSUED_CERTIFICATE:
                pInMsgType = "CERTIFICATE";
                break;
            case TE_MSG_TYPE_RELEASE_ARTIFACT_LIST:
                pInMsgType = "ARTIFACT_LIST";
                break;
            case TE_MSG_TYPE_ARTIFACT_DOWNLOAD:
                pInMsgType = "ARTIFACT_DOWNLOAD";
                break;
            case TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK:
                pInMsgType = "ARTIFACT_DOWNLOAD_CHUNK";
                break;
            case TE_MSG_TYPE_CLOUDPLATFORM:
                pInMsgType = "CLOUDPLATFORM";
                break;
            case TE_MSG_TYPE_PENDING_POLICIES:
            default:
                pInMsgType = "PENDING";
                break;
        }

        FMGMT_fprintf(pFile, "            \"policyRecvState\": \"%s\",\n", pInMsgType);

        switch(pNode->lastMsgSentType)
        {
            case TE_MSG_TYPE_CERTIFICATE_SPECIFICATION:
                pMsgType = "SPECIFICATION";
                break;
            case TE_MSG_TYPE_ISSUED_CERTIFICATE:
                pMsgType = "CERTIFICATE";
                break;
            case TE_MSG_TYPE_RELEASE_ARTIFACT_LIST:
                pMsgType = "ARTIFACT_LIST";
                break;
            case TE_MSG_TYPE_ARTIFACT_DOWNLOAD:
                pMsgType = "ARTIFACT_DOWNLOAD";
                break;
            case TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK:
                pMsgType = "ARTIFACT_DOWNLOAD_CHUNK";
                break;
            case TE_MSG_TYPE_CLOUDPLATFORM:
                pMsgType = "CLOUDPLATFORM";
                break;
            case TE_MSG_TYPE_PENDING_POLICIES:
            default:
                pMsgType = "PENDING";
                break;
        }
        FMGMT_fprintf(pFile, "            \"policyState\": \"%s\",\n", pMsgType);
        FMGMT_fprintf(pFile, "            \"policyErrorResponses\": %d,\n", pNode->errorResponseCount);
        FMGMT_fprintf(pFile, "            \"policyHasFailed\": %s,\n", pNode->hasFailed ? "true" : "false");
        FMGMT_fprintf(pFile, "            \"priority\": %d,\n", pNode->priority);
        FMGMT_fprintf(pFile, "            \"creationTimestamp\": \"%s\",\n", pNode->pCreationTimestamp);
        FMGMT_fprintf(pFile, "            \"processTimestamp\": \"%s\"%s\n", pNode->pProccessingTimestamp, (TE_POLICY_TYPE_UPDATE == pNode->type || (TE_POLICY_TYPE_CERTIFICATE == pNode->type && NULL != pNode->pAlias)) ? "," : "");
        if (TE_POLICY_TYPE_UPDATE == pNode->type)
        {
            FMGMT_fprintf(pFile, "            \"policyData\": {\n");
            FMGMT_fprintf(pFile, "                \"artifactList\": [\n");
            pArtifact = pCtx->curPolicy.data.ups.pArtifactHead;
            while (NULL != pArtifact)
            {
                pState = TRUSTEDGE_getArtifactProgressToString(pArtifact->state);
                FMGMT_fprintf(pFile, "                    {\n");
                FMGMT_fprintf(pFile, "                        \"artifactId\": \"%s\",\n", pArtifact->pId);
                FMGMT_fprintf(pFile, "                        \"artifactName\": \"%s\",\n", pArtifact->pName);
                FMGMT_fprintf(pFile, "                        \"artifactVersion\": \"%s\",\n", pArtifact->pVersion);
                FMGMT_fprintf(pFile, "                        \"artifactTimestamp\": \"%s\",\n", pArtifact->pTimestamp);
                FMGMT_fprintf(pFile, "                        \"artifactSize\": %d,\n", pArtifact->size);
                FMGMT_fprintf(pFile, "                        \"artifactState\": \"%s\",\n", pState);
                if (TRUE == pArtifact->chunking)
                {
                    FMGMT_fprintf(pFile, "                        \"artifactDownloadedBytes\": %d,\n", pArtifact->downloadedSize);
                    FMGMT_fprintf(pFile, "                        \"artifactChunking\": {\n");
                    FMGMT_fprintf(pFile, "                            \"seqNum\": %d,\n", pArtifact->seqNum);
                    FMGMT_fprintf(pFile, "                            \"chunkSize\": %d,\n", pArtifact->chunkSize);
                    FMGMT_fprintf(pFile, "                            \"windowSize\": %d\n", pArtifact->chunkWindowSize);
                    FMGMT_fprintf(pFile, "                        },\n");
                }
                FMGMT_fprintf(pFile, "                        \"artifactAsync\": %s,\n", (pArtifact->isAsync ? "true": "false"));
                FMGMT_fprintf(pFile, "                        \"artifactIgnore\": %s\n", (pArtifact->ignore ? "true": "false"));
                FMGMT_fprintf(pFile, "                    }%s\n", (NULL == pArtifact->pNext) ? "" : ",");

                pArtifact = pArtifact->pNext;
            }
            FMGMT_fprintf(pFile, "                ]\n");
            FMGMT_fprintf(pFile, "            }\n");
        }
        else if (TE_POLICY_TYPE_CERTIFICATE == pNode->type)
        {
            if (NULL != pNode->pAlias)
            {
                FMGMT_fprintf(pFile, "            \"alias\": \"%s\"%s\n", pNode->pAlias, (NULL != pNode->pCertSpecJson) ? "," : "");
                if (NULL != pNode->pCertSpecJson)
                {
                    FMGMT_fprintf(pFile, "            \"certSpecJsonFile\": \"%s\"\n", pCertSpecJsonFile);
                    status = DIGICERT_writeFile(pCertSpecJsonFile, pNode->pCertSpecJson, pNode->certSpecJsonLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }
            }
        }
        FMGMT_fprintf(pFile, "        }\n");
    }
    FMGMT_fprintf(pFile, "    ]\n");
    FMGMT_fprintf(pFile, "}\n");

exit:

    if (pFile)
    {
        FMGMT_fflush(pFile);
        FMGMT_fclose(&pFile);
        if (OK == status)
            FMGMT_rename(pTmpFilePath, pFilePath);
    }

    DIGI_FREE((void **) &pTmpFilePath);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pCertSpecJsonFile);

    return status;
}

static MSTATUS TRUSTEDGE_agentPersistAppliedPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pTmpFilePath = NULL;
    sbyte *pFilePath = NULL;
    FileDescriptor pFile = NULL;
    TrustEdgeAgentPolicyNode *pNode;
    sbyte *pType;
    sbyte *pState;
    TrustEdgeAgentArtifactNode *pArtifact;
    ubyte4 i = 0;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, ADD_SUFFIX(APPLIED_POLICY_FILE, ".tmp"), &pTmpFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, APPLIED_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pNode = pCtx->pAppliedPolicies;

    status = FMGMT_fopen(pTmpFilePath, "w", &pFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    FMGMT_fprintf(pFile, "{\n");
    FMGMT_fprintf(pFile, "    \"appliedPolicies\": [\n");
    while (NULL != pNode)
    {
        if (pNode != pCtx->curPolicy.pPolicy)
        {
            if (TE_POLICY_TYPE_CERTIFICATE == pNode->type)
            {
                pType = CERTIFICATE_TPYE;
            }
            else if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                pType = UPDATE_TYPE;
            }
            else if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                pType = CLOUDPLATFORM_TYPE;
            }
            else
            {
                pType = UNKNOWN_TYPE;
            }

            FMGMT_fprintf(pFile, "        {\n");
            FMGMT_fprintf(pFile, "            \"deviceGroupId\": \"%s\",\n", pNode->pDeviceGroupId);
            FMGMT_fprintf(pFile, "            \"policyType\": \"%s\",\n", pType);
            FMGMT_fprintf(pFile, "            \"policyId\": \"%s\",\n", pNode->pId);
            if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"deploymentId\": \"%s\",\n", pNode->pDeploymentId);
            }
            FMGMT_fprintf(pFile, "            \"priority\": %d,\n", pNode->priority);
            if (TE_POLICY_TYPE_CLOUDPLATFORM == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"policyDependency\": [\n");
                for (i = 0; i < pNode->pDependency->count; i++)
                {
                    FMGMT_fprintf(pFile, "                {\n");
                    FMGMT_fprintf(pFile, "                    \"policyType\": \"%s\",\n", pNode->pDependency->pPolicies[i].pPolicyType);
                    FMGMT_fprintf(pFile, "                    \"policyId\": \"%s\"\n", pNode->pDependency->pPolicies[i].pPolicyId);

                    if (i < pNode->pDependency->count - 1)
                    {
                        FMGMT_fprintf(pFile, "                },\n");
                    }
                    else
                    {
                        FMGMT_fprintf(pFile, "                }\n");
                    }
                }
                FMGMT_fprintf(pFile, "            ],\n");
            }
            FMGMT_fprintf(pFile, "            \"policyErrorResponses\": %d,\n", pNode->errorResponseCount);
            FMGMT_fprintf(pFile, "            \"creationTimestamp\": \"%s\",\n", pNode->pCreationTimestamp);
            FMGMT_fprintf(pFile, "            \"processTimestamp\": \"%s\",\n", pNode->pProccessingTimestamp);
            FMGMT_fprintf(pFile, "            \"completionTimestamp\": \"%s\",\n", pNode->pCompletionTimestamp);
            if (TE_POLICY_STATUS_SUCCESS == pNode->status)
            {
                if (TE_POLICY_TYPE_CERTIFICATE == pNode->type)
                {
                    FMGMT_fprintf(pFile, "            \"alias\": \"%s\",\n", pNode->pAlias);
                }
                FMGMT_fprintf(pFile, "            \"status\": \"SUCCESS\"%s\n", (TE_POLICY_TYPE_UPDATE == pNode->type) ? "," : "");
            }
            else
            {
                FMGMT_fprintf(pFile, "            \"status\": \"FAILURE\"%s\n", (TE_POLICY_TYPE_UPDATE == pNode->type) ? "," : "");
            }

            if (TE_POLICY_TYPE_UPDATE == pNode->type)
            {
                FMGMT_fprintf(pFile, "            \"policyData\": {\n");
                FMGMT_fprintf(pFile, "                \"artifactList\": [\n");
                pArtifact = pNode->pArtifactList;

                while (NULL != pArtifact)
                {
                    pState = TRUSTEDGE_getArtifactProgressToString(pArtifact->state);
                    FMGMT_fprintf(pFile, "                    {\n");
                    FMGMT_fprintf(pFile, "                        \"artifactId\": \"%s\",\n", pArtifact->pId);
                    FMGMT_fprintf(pFile, "                        \"artifactName\": \"%s\",\n", pArtifact->pName);
                    FMGMT_fprintf(pFile, "                        \"artifactVersion\": \"%s\",\n", pArtifact->pVersion);
                    FMGMT_fprintf(pFile, "                        \"artifactTimestamp\": \"%s\",\n", pArtifact->pTimestamp);
                    FMGMT_fprintf(pFile, "                        \"artifactSize\": %d,\n", pArtifact->size);
                    FMGMT_fprintf(pFile, "                        \"artifactState\": \"%s\",\n", pState);
                    FMGMT_fprintf(pFile, "                        \"artifactAsync\": %s,\n", (pArtifact->isAsync ? "true": "false"));
                    FMGMT_fprintf(pFile, "                        \"artifactIgnore\": %s\n", (pArtifact->ignore ? "true": "false"));
                    FMGMT_fprintf(pFile, "                    }%s\n", (NULL == pArtifact->pNext) ? "" : ",");

                    pArtifact = pArtifact->pNext;
                }
                FMGMT_fprintf(pFile, "                ]\n");
                FMGMT_fprintf(pFile, "            }\n");
            }
            FMGMT_fprintf(pFile, "        }%s\n", (NULL == pNode->pNext) ? "" : ",");
        }

        pNode = pNode->pNext;
    }
    FMGMT_fprintf(pFile, "    ]\n");
    FMGMT_fprintf(pFile, "}\n");

exit:

    if (pFile)
    {
        FMGMT_fflush(pFile);
        FMGMT_fclose(&pFile);
        if (OK == status)
            FMGMT_rename(pTmpFilePath, pFilePath);
    }

    DIGI_FREE((void **) &pTmpFilePath);
    DIGI_FREE((void **) &pFilePath);

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistConfiguration(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;

    status = TRUSTEDGE_agentPersistPendingPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to persist pending policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistProcessingPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to persist processing policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistAppliedPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to persist applied policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistErrorPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to persist error policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
#ifdef __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__
    /* copy files we have just updated */
    copyAllPersistedFiles(pCtx, snapshotCounter++, 0);
#endif

    return status;
}

static MSTATUS TRUSTEDGE_agentProcessDependentPolicies(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    TrustEdgeAgentPolicyDependency **ppDependentPolicy
)
{
    MSTATUS status;
    JSON_TokenType dependencyToken = { 0 };
    ubyte4 dependencyNdx = 0;
    ubyte4 i = 0;

    status = JSON_getJsonArrayValue(
        pJCtx, ndx, "policyDependency", &dependencyNdx, &dependencyToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (dependencyToken.elemCnt > 0)
    {
        status = DIGI_CALLOC((void **) ppDependentPolicy, 1, sizeof(TrustEdgeAgentPolicyDependency));
        if (OK != status)
        {
            goto exit;
        }

        (*ppDependentPolicy)->count = dependencyToken.elemCnt;

        status = DIGI_CALLOC((void **) &(*ppDependentPolicy)->pPolicies, dependencyToken.elemCnt, sizeof(TrustEdgeAgentPolicyDependencyFields));
        if (OK != status)
        {
            goto exit;
        }
    }

    for (i = 0; i < dependencyToken.elemCnt; i++)
    {
        dependencyNdx++;

        status = JSON_getJsonStringValue(
            pJCtx, dependencyNdx, "policyType", &(*ppDependentPolicy)->pPolicies[i].pPolicyType, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, dependencyNdx, "policyId", &(*ppDependentPolicy)->pPolicies[i].pPolicyId, TRUE);

        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getLastIndexInObject(pJCtx, dependencyNdx, &dependencyNdx);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:

    return status;
}

extern void TRUSTEDGE_freeDependentPolicies(
    TrustEdgeAgentPolicyDependency *pDependentPolicy)
{
    ubyte4 i = 0;

    if (NULL != pDependentPolicy)
    {
        for (i = 0; i < pDependentPolicy->count; i++)
        {
            if (NULL != pDependentPolicy->pPolicies[i].pPolicyType)
            {
                DIGI_FREE((void **) &pDependentPolicy->pPolicies[i].pPolicyType);
            }
            if (NULL != pDependentPolicy->pPolicies[i].pPolicyId)
            {
                DIGI_FREE((void **) &pDependentPolicy->pPolicies[i].pPolicyId);
            }
        }
        if (NULL != pDependentPolicy->pPolicies)
        {
            DIGI_FREE((void **) &pDependentPolicy->pPolicies);
        }
        DIGI_FREE((void **) &pDependentPolicy);
    }
}

static MSTATUS TRUSTEDGE_agentPersistLoadPendingPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    ubyte4 i, ndx;
    JSON_TokenType token = { 0 };
    JSON_TokenType policyToken = { 0 };
    sbyte *pDeviceGroupId = NULL;
    sbyte *pPolicyType = NULL;
    TrustEdgeAgentPolicyType policyType;
    sbyte *pPolicyId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte4 priority;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    sbyte *pFilePath = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen;
    sbyte *pCreationTimestamp = NULL;
    sbyte4 errorResponseCount = 0;
    TrustEdgeAgentPolicyDependency *pDependentPolicy = NULL;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, PENDING_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pFilePath, NULL))
    {
        status = OK;
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
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

    status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "pendingPolicies", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &policyToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_Object != policyToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pDeviceGroupId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "deviceGroupId", &pDeviceGroupId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyType);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyType", &pPolicyType, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRCMP(pPolicyType, "CERTIFICATE"))
        {
            policyType = TE_POLICY_TYPE_CERTIFICATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "UPDATE"))
        {
            policyType = TE_POLICY_TYPE_UPDATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "CLOUDPLATFORM"))
        {
            policyType = TE_POLICY_TYPE_CLOUDPLATFORM;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_UNKNOWN_POLICY_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "priority", &priority, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "policyErrorResponses", &errorResponseCount, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TE_POLICY_TYPE_UPDATE == policyType)
        {
            DIGI_FREE((void **) &pDeploymentId);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "deploymentId", &pDeploymentId, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if (TE_POLICY_TYPE_CLOUDPLATFORM == policyType)
        {
            status = TRUSTEDGE_agentProcessDependentPolicies(
                pJCtx, ndx, &pDependentPolicy);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        DIGI_FREE((void **) &pCreationTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "creationTimestamp", &pCreationTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_agentPolicyAddNode(
            policyType, &pDeviceGroupId, &pPolicyId, &pDeploymentId,
            priority, &pCreationTimestamp, NULL, NULL, &pDependentPolicy, FALSE, errorResponseCount, &pCtx->pPendingPolicies);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
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

    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pCreationTimestamp);
    DIGI_FREE((void **) &pPolicyType);
    TRUSTEDGE_freeDependentPolicies(pDependentPolicy);

    DIGI_FREE((void **) &pFilePath);
    DIGICERT_freeReadFile(&pData);
    JSON_releaseContext(&pJCtx);
    return status;
}

static MSTATUS TRUSTEDGE_agentPersistLoadProcessingPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    ubyte4 i, ndx;
    JSON_TokenType token = { 0 };
    JSON_TokenType policyToken = { 0 };
    sbyte *pDeviceGroupId = NULL;
    sbyte *pPolicyType = NULL;
    TrustEdgeAgentPolicyType policyType;
    sbyte *pPolicyId = NULL, *pLocalId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte *pPolicyState = NULL;
    sbyte *pPolicyInState = NULL;
    sbyte4 priority;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    sbyte *pFilePath = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen;
    sbyte *pCreationTimestamp = NULL;
    sbyte *pProcessingTimestamp = NULL;
    TrustEdgeAgentPolicyNode *pFound = NULL;
    sbyte *pAlias = NULL;
    sbyte *pFile = NULL;
    intBoolean hasFailed = FALSE;
    intBoolean ignoreArtifact = FALSE;
    sbyte4 errorResponseCount = 0;

    sbyte *pPolicyMode = NULL;

    JSON_TokenType tokenList = { 0 };
    JSON_TokenType artifact = { 0 };
    ubyte4 chunkNdx;

    sbyte *pArtifactId = NULL;
    sbyte *pArtifactName = NULL;
    sbyte *pArtifactTimestamp = NULL;
    sbyte *pArtifactVersion = NULL;
    sbyte *pArtifactState = NULL;
    sbyte4 artifactSize;
    intBoolean isAsync;
    byteBoolean chunking;
    ubyte4 downloadedBytes;
    ubyte4 seqNum;
    ubyte4 chunkSize;
    ubyte4 windowSize;

    TrustEdgeAgentPolicyStatus nodeStatus = TE_POLICY_STATUS_PENDING;
    TrustEdgeAgentMessageType  policyInState;
    TrustEdgeAgentMessageType  policyState;
    TrustEdgeAgentArtifactNode *pArtifactList = NULL;
    TrustEdgeAgentArtifactNode *pNode = NULL;

    TrustEdgeAgentPolicyDependency *pDependentPolicy = NULL;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, PROCESSING_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pFilePath, NULL))
    {
        status = OK;
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
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

    status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "processingPolicies", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &policyToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_Object != policyToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pDeviceGroupId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "deviceGroupId", &pDeviceGroupId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyType);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyType", &pPolicyType, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRCMP(pPolicyType, "CERTIFICATE"))
        {
            policyType = TE_POLICY_TYPE_CERTIFICATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "UPDATE"))
        {
            policyType = TE_POLICY_TYPE_UPDATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "CLOUDPLATFORM"))
        {
            policyType = TE_POLICY_TYPE_CLOUDPLATFORM;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_UNKNOWN_POLICY_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TE_POLICY_TYPE_UPDATE == policyType)
        {
            DIGI_FREE((void **) &pPolicyMode);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "policyMode", &pPolicyMode, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (0 == DIGI_STRNCMP("ROLLBACK", pPolicyMode, DIGI_STRLEN(pPolicyMode)))
            {
                nodeStatus = TE_POLICY_STATUS_ROLLBACK;
            }
            else if (0 == DIGI_STRNCMP("FAILURE", pPolicyMode, DIGI_STRLEN(pPolicyMode)))
            {
                nodeStatus = TE_POLICY_STATUS_FAILURE;
            }
            else
            {
                nodeStatus = TE_POLICY_STATUS_PENDING;
            }

            DIGI_FREE((void **) &pDeploymentId);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "deploymentId", &pDeploymentId, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if (TE_POLICY_TYPE_CLOUDPLATFORM == policyType)
        {
            status = TRUSTEDGE_agentProcessDependentPolicies(
                pJCtx, ndx, &pDependentPolicy);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        status = JSON_getJsonBooleanValue(
            pJCtx, ndx, "policyHasFailed", &hasFailed, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyInState);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyRecvState", &pPolicyInState, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRNCMP("SPECIFICATION", pPolicyInState, DIGI_STRLEN(pPolicyInState)))
        {
            policyInState = TE_MSG_TYPE_CERTIFICATE_SPECIFICATION;
        }
        else if (0 == DIGI_STRNCMP("CERTIFICATE", pPolicyInState, DIGI_STRLEN(pPolicyInState)))
        {
            policyInState = TE_MSG_TYPE_ISSUED_CERTIFICATE;
        }
        else if (0 == DIGI_STRNCMP("ARTIFACT_LIST", pPolicyInState, DIGI_STRLEN(pPolicyInState)))
        {
            policyInState = TE_MSG_TYPE_RELEASE_ARTIFACT_LIST;
        }
        else if (0 == DIGI_STRNCMP("ARTIFACT_DOWNLOAD", pPolicyInState, DIGI_STRLEN(pPolicyInState)))
        {
            policyInState = TE_MSG_TYPE_ARTIFACT_DOWNLOAD;
        }
        else if (0 == DIGI_STRNCMP("ARTIFACT_DOWNLOAD_CHUNK", pPolicyInState, DIGI_STRLEN(pPolicyInState)))
        {
            policyInState = TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK;
        }
        else
        {
            policyInState = TE_MSG_TYPE_PENDING_POLICIES;
        }

        DIGI_FREE((void **) &pPolicyState);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyState", &pPolicyState, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRNCMP("SPECIFICATION", pPolicyState, DIGI_STRLEN(pPolicyState)))
        {
            policyState = TE_MSG_TYPE_CERTIFICATE_SPECIFICATION;
        }
        else if (0 == DIGI_STRNCMP("CERTIFICATE", pPolicyState, DIGI_STRLEN(pPolicyState)))
        {
            policyState = TE_MSG_TYPE_ISSUED_CERTIFICATE;
        }
        else if (0 == DIGI_STRNCMP("ARTIFACT_LIST", pPolicyState, DIGI_STRLEN(pPolicyState)))
        {
            policyState = TE_MSG_TYPE_RELEASE_ARTIFACT_LIST;
        }
        else if (0 == DIGI_STRNCMP("ARTIFACT_DOWNLOAD", pPolicyState, DIGI_STRLEN(pPolicyState)))
        {
            policyState = TE_MSG_TYPE_ARTIFACT_DOWNLOAD;
        }
        else if (0 == DIGI_STRNCMP("ARTIFACT_DOWNLOAD_CHUNK", pPolicyInState, DIGI_STRLEN(pPolicyInState)))
        {
            policyState = TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK;
        }
        else
        {
            policyState = TE_MSG_TYPE_PENDING_POLICIES;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "priority", &priority, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "policyErrorResponses", &errorResponseCount, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pCreationTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "creationTimestamp", &pCreationTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pProcessingTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "processTimestamp", &pProcessingTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pLocalId = pPolicyId;
        status = TRUSTEDGE_agentPolicyAddNode(
            policyType, &pDeviceGroupId, &pPolicyId, &pDeploymentId,
            priority, &pCreationTimestamp, &pProcessingTimestamp, NULL, &pDependentPolicy, hasFailed, errorResponseCount, &pCtx->pPendingPolicies);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
            pCtx->pPendingPolicies, pLocalId, policyType, &pFound);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TE_POLICY_TYPE_UPDATE == policyType)
        {
            status = JSON_getJsonArrayValue(
                pJCtx, ndx, "artifactList", &ndx, &tokenList, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            for(unsigned int j = 0; j < tokenList.elemCnt; j++)
            {
                ndx++;
                status = JSON_getToken(pJCtx, ndx, &artifact);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                if (JSON_Object != artifact.type)
                {
                    status = ERR_JSON_UNEXPECTED_TYPE;
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }


                DIGI_FREE((void **) &pArtifactId);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactId", &pArtifactId, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactName);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactName", &pArtifactName, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactVersion);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactVersion", &pArtifactVersion, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactTimestamp);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactTimestamp", &pArtifactTimestamp, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndx, "artifactSize", &artifactSize, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactState);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactState", &pArtifactState, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonObjectIndex(
                    pJCtx, ndx, "artifactChunking",
                    &chunkNdx, TRUE);
                if (ERR_NOT_FOUND == status)
                {
                    chunking = FALSE;
                    downloadedBytes = 0;
                    seqNum = 0;
                    windowSize = 0;
                    chunkSize = 0;
                    status = OK;
                }
                else if (OK == status)
                {
                    chunking = TRUE;

                    status = JSON_getJsonIntegerValue(
                        pJCtx, ndx, "artifactDownloadedBytes", &downloadedBytes, TRUE);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    status = JSON_getJsonIntegerValue(
                        pJCtx, chunkNdx, "seqNum", &seqNum, TRUE);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    status = JSON_getJsonIntegerValue(
                        pJCtx, chunkNdx, "windowSize", &windowSize, TRUE);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    status = JSON_getJsonIntegerValue(
                        pJCtx, chunkNdx, "chunkSize", &chunkSize, TRUE);
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
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonBooleanValue(
                    pJCtx, ndx, "artifactAsync", &isAsync, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonBooleanValue(
                    pJCtx, ndx, "artifactIgnore", &ignoreArtifact, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = TRUSTEDGE_agentArtifactAddNode(
                    &pArtifactId, &pArtifactName, &pArtifactVersion,
                    &pArtifactTimestamp, pArtifactState, artifactSize,
                    isAsync, ignoreArtifact, chunking, downloadedBytes, seqNum,
                    chunkSize, windowSize, &pArtifactList);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            if (NULL != pFound && NULL != pArtifactList)
            {
                pCtx->curPolicy.data.ups.pArtifactHead = pArtifactList;
                /* find the artifact we are trying to download */
                pNode = pArtifactList;
                pCtx->curPolicy.data.ups.pArtifact = NULL;
                status = ERR_NOT_FOUND;
                if (TE_POLICY_STATUS_ROLLBACK == nodeStatus)
                {
                    /* first check if we already sent an artifact
                     * request for an artifact to rollback */
                    while (pNode)
                    {
                        if (TE_ARTIFACT_STATE_DOWNLOADING == pNode->state)
                        {
                            pCtx->curPolicy.data.ups.pArtifact = pNode;
                            status = OK;
                        }

                        pNode = pNode->pNext;
                    }

                    if (ERR_NOT_FOUND == status)
                    {
                        /* find last artifact that was installed */
                        pNode = pArtifactList;
                        while (pNode)
                        {
                            if (TE_ARTIFACT_STATE_INSTALLED == pNode->state)
                            {
                                pCtx->curPolicy.data.ups.pArtifact = pNode;
                                status = OK;
                            }

                            pNode = pNode->pNext;
                        }

                        if (ERR_NOT_FOUND == status)
                        {
                            /* if no more applied artifacts, we are done */
                            nodeStatus = TE_POLICY_STATUS_FAILURE;
                        }
                        status = OK;
                    }
                }
                else if (TE_POLICY_STATUS_FAILURE == nodeStatus)
                {
                    /* find last artifact node, this allows
                     * us to reverse search for installed artifacts
                     * in case we need to rollback */
                    pNode = pArtifactList;
                    if (NULL != pNode)
                    {
                        while (NULL != pNode->pNext) pNode = pNode->pNext;
                    }

                    pCtx->curPolicy.data.ups.pArtifact = pNode;
                    status = OK;
                }
                else
                {
                    while (pNode)
                    {
                        if (TE_ARTIFACT_STATE_DOWNLOADING == pNode->state ||
                            TE_ARTIFACT_STATE_INSTALLING  == pNode->state)
                        {
                            pCtx->curPolicy.data.ups.pArtifact = pNode;
                            status = OK;
                            break;
                        }

                        pNode = pNode->pNext;
                    }

                    if (ERR_NOT_FOUND == status)
                    {
                        /* if none are downloading, find the first one pending,
                        * we need to send the download request message
                        * for that artifact */
                        pCtx->curPolicy.data.ups.pArtifact = pArtifactList;
                        pNode = pArtifactList;
                        while (pNode)
                        {
                            if (TE_ARTIFACT_STATE_PENDING == pNode->state)
                            {
                                pCtx->curPolicy.data.ups.pArtifact = pNode;
                                status = OK;
                                break;
                            }

                            pNode = pNode->pNext;
                        }

                        if (ERR_NOT_FOUND == status)
                        {
                            status = OK;
                            pCtx->curPolicy.data.ups.pArtifact = NULL;
                        }
                    }
                }

                pArtifactList = NULL;
            }
        }
        else if (TE_POLICY_TYPE_CERTIFICATE == policyType)
        {
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "alias", &pAlias, TRUE);
            if (OK == status)
            {
                pFound->pAlias = pAlias; pAlias = NULL;
            }

            status = JSON_getJsonStringValue(
                pJCtx, ndx, "certSpecJsonFile", &pFile, TRUE);
            if (OK == status)
            {
                status = DIGICERT_readFile(
                    pFile, &pFound->pCertSpecJson, &pFound->certSpecJsonLen);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        pCtx->curPolicy.pPolicy = pFound;
        if (NULL != pFound)
        {
            pFound->lastMsgSentType = policyState;
            pCtx->curPolicy.pPolicy->status = nodeStatus;
        }
        pCtx->curPolicy.lastPolicyMsgType = policyInState;
        pCtx->needToProcessResponse = TRUE;

        /* Only load in the first one */
        break;
    }

exit:
    TRUSTEDGE_agentFreeAgentArtifactList(&pArtifactList);
    TRUSTEDGE_freeDependentPolicies(pDependentPolicy);

    DIGI_FREE((void **) &pDeviceGroupId);

    DIGI_FREE((void **) &pArtifactId);
    DIGI_FREE((void **) &pArtifactTimestamp);
    DIGI_FREE((void **) &pArtifactState);
    DIGI_FREE((void **) &pArtifactVersion);
    DIGI_FREE((void **) &pArtifactName);

    DIGI_FREE((void **) &pPolicyMode);
    DIGI_FREE((void **) &pFile);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pPolicyType);
    DIGI_FREE((void **) &pPolicyMode);
    DIGI_FREE((void **) &pPolicyState);
    DIGI_FREE((void **) &pPolicyInState);
    DIGICERT_freeReadFile(&pData);
    JSON_releaseContext(&pJCtx);

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistLoadAppliedPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    ubyte4 i, ndx;
    JSON_TokenType token = { 0 };
    JSON_TokenType policyToken = { 0 };
    sbyte *pDeviceGroupId = NULL;
    sbyte *pPolicyType = NULL;
    TrustEdgeAgentPolicyType policyType;
    sbyte *pPolicyId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte4 priority;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    sbyte *pFilePath = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen;
    sbyte *pCreationTimestamp = NULL;
    sbyte *pProcessingTimestamp = NULL;
    sbyte *pCompletionTimestamp = NULL;
    sbyte *pAlias = NULL;
    sbyte *pStatus = NULL;
    sbyte4 errorResponseCount = 0;

    JSON_TokenType tokenList = { 0 };
    JSON_TokenType artifact = { 0 };
    sbyte *pArtifactId = NULL;
    sbyte *pArtifactName = NULL;
    sbyte *pArtifactTimestamp = NULL;
    sbyte *pArtifactVersion = NULL;
    sbyte *pArtifactState = NULL;
    sbyte4 artifactSize;
    intBoolean isAsync = FALSE;
    intBoolean ignoreArtifact = FALSE;

    TrustEdgeAgentPolicyStatus nodeStatus;
    TrustEdgeAgentMessageType  policyState;
    TrustEdgeAgentArtifactNode *pArtifactList = NULL;

    TrustEdgeAgentPolicyDependency *pDependentPolicy = NULL;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, APPLIED_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pFilePath, NULL))
    {
        status = OK;
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
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

    status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "appliedPolicies", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &policyToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_Object != policyToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pDeviceGroupId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "deviceGroupId", &pDeviceGroupId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyType);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyType", &pPolicyType, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRCMP(pPolicyType, "CERTIFICATE"))
        {
            policyType = TE_POLICY_TYPE_CERTIFICATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "UPDATE"))
        {
            policyType = TE_POLICY_TYPE_UPDATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "CLOUDPLATFORM"))
        {
            policyType = TE_POLICY_TYPE_CLOUDPLATFORM;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_UNKNOWN_POLICY_TYPE;
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "priority", &priority, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "policyErrorResponses", &errorResponseCount, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TE_POLICY_TYPE_UPDATE == policyType)
        {
            DIGI_FREE((void **) &pDeploymentId);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "deploymentId", &pDeploymentId, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if (TE_POLICY_TYPE_CLOUDPLATFORM == policyType)
        {
            status = TRUSTEDGE_agentProcessDependentPolicies(
                pJCtx, ndx, &pDependentPolicy);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        DIGI_FREE((void **) &pCreationTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "creationTimestamp", &pCreationTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pProcessingTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "processTimestamp", &pProcessingTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pCompletionTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "completionTimestamp", &pCompletionTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pStatus);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "status", &pStatus, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRCMP(pStatus, "SUCCESS"))
        {
            nodeStatus = TE_POLICY_STATUS_SUCCESS;
        }
        else if (0 == DIGI_STRCMP(pStatus, "FAILURE"))
        {
            nodeStatus = TE_POLICY_STATUS_FAILURE;
        }
        else
        {
            nodeStatus = TE_POLICY_STATUS_UNKNOWN;
        }

        if (TE_POLICY_TYPE_UPDATE == policyType)
        {

            status = JSON_getJsonArrayValue(
                pJCtx, ndx, "artifactList", &ndx, &tokenList, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            for(unsigned int j = 0; j < tokenList.elemCnt; j++)
            {
                ndx++;
                status = JSON_getToken(pJCtx, ndx, &artifact);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                if (JSON_Object != artifact.type)
                {
                    status = ERR_JSON_UNEXPECTED_TYPE;
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }


                DIGI_FREE((void **) &pArtifactId);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactId", &pArtifactId, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactName);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactName", &pArtifactName, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactVersion);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactVersion", &pArtifactVersion, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactTimestamp);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactTimestamp", &pArtifactTimestamp, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndx, "artifactSize", &artifactSize, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactState);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactState", &pArtifactState, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonBooleanValue(
                    pJCtx, ndx, "artifactAsync", &isAsync, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonBooleanValue(
                    pJCtx, ndx, "artifactIgnore", &ignoreArtifact, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = TRUSTEDGE_agentArtifactAddNode(
                    &pArtifactId, &pArtifactName, &pArtifactVersion,
                    &pArtifactTimestamp, pArtifactState, artifactSize,
                    isAsync, ignoreArtifact, FALSE, 0, 0, 0, 0, &pArtifactList);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            /* Final state for update policy */
            policyState = TE_MSG_TYPE_ARTIFACT_DOWNLOAD;
        }
        else
        {
            DIGI_FREE((void **) &pAlias);
            (void) JSON_getJsonStringValue(
                pJCtx, ndx, "alias", &pAlias, TRUE);

            /* Final state for certificate policy */
            policyState = TE_MSG_TYPE_ISSUED_CERTIFICATE;

            status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        status = TRUSTEDGE_agentPolicyAddNodeFinal(
            policyType, &pDeviceGroupId, &pPolicyId, &pDeploymentId,
            priority, &pCreationTimestamp, &pProcessingTimestamp, &pCompletionTimestamp,
            nodeStatus, policyState, &pAlias, &pArtifactList, &pDependentPolicy, FALSE, errorResponseCount, &pCtx->pAppliedPolicies);
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

    JSON_releaseContext(&pJCtx);
    DIGICERT_freeReadFile(&pData);
    DIGI_FREE((void **) &pFilePath);

    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pPolicyType);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pCreationTimestamp);
    DIGI_FREE((void **) &pProcessingTimestamp);
    DIGI_FREE((void **) &pCompletionTimestamp);

    DIGI_FREE((void **) &pArtifactId);
    DIGI_FREE((void **) &pArtifactTimestamp);
    DIGI_FREE((void **) &pArtifactState);
    DIGI_FREE((void **) &pArtifactVersion);
    DIGI_FREE((void **) &pArtifactName);

    TRUSTEDGE_freeDependentPolicies(pDependentPolicy);

    DIGI_FREE((void **) &pStatus);
    DIGI_FREE((void **) &pAlias);

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistLoadErrorPolicies(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    ubyte4 i, ndx;
    JSON_TokenType token = { 0 };
    JSON_TokenType policyToken = { 0 };
    sbyte *pDeviceGroupId = NULL;
    sbyte *pPolicyType = NULL;
    TrustEdgeAgentPolicyType policyType;
    sbyte *pPolicyId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte4 priority;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    sbyte *pFilePath = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen;
    sbyte *pCreationTimestamp = NULL;
    sbyte *pProcessingTimestamp = NULL;
    sbyte *pCompletionTimestamp = NULL;
    sbyte *pPolicyState = NULL;
    sbyte *pAlias = NULL;
    sbyte *pStatus = NULL;
    sbyte4 errorResponseCount = 0;

    JSON_TokenType tokenList = { 0 };
    JSON_TokenType artifact = { 0 };
    sbyte *pArtifactId = NULL;
    sbyte *pArtifactName = NULL;
    sbyte *pArtifactTimestamp = NULL;
    sbyte *pArtifactVersion = NULL;
    sbyte *pArtifactState = NULL;
    sbyte4 artifactSize;
    intBoolean isAsync;
    intBoolean ignoreArtifact = FALSE;

    TrustEdgeAgentPolicyStatus nodeStatus;
    TrustEdgeAgentMessageType   policyState = TE_MSG_TYPE_UNKNOWN;
    TrustEdgeAgentArtifactNode *pArtifactList = NULL;

    TrustEdgeAgentPolicyDependency *pDependentPolicy = NULL;

    /* TODO: Read in pending, processing, and applied policy configuration
     *
     * - pending populates pCtx->pPendingPolicies
     * - processing populates pCtx->curPolicy
     * - applied populates pCtx->pAppliedPolicies
     */

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, FAILED_POLICY_FILE, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pFilePath, NULL))
    {
        status = OK;
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
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

    status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "failedPolicies", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &policyToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_Object != policyToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pDeviceGroupId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "deviceGroupId", &pDeviceGroupId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyType);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyType", &pPolicyType, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRCMP(pPolicyType, "CERTIFICATE"))
        {
            policyType = TE_POLICY_TYPE_CERTIFICATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "UPDATE"))
        {
            policyType = TE_POLICY_TYPE_UPDATE;
        }
        else if (0 == DIGI_STRCMP(pPolicyType, "CLOUDPLATFORM"))
        {
            policyType = TE_POLICY_TYPE_CLOUDPLATFORM;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_UNKNOWN_POLICY_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pPolicyId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "policyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "priority", &priority, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "policyErrorResponses", &errorResponseCount, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TE_POLICY_TYPE_UPDATE == policyType)
        {
            DIGI_FREE((void **) &pDeploymentId);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "deploymentId", &pDeploymentId, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        DIGI_FREE((void **) &pCreationTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "creationTimestamp", &pCreationTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pProcessingTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "processTimestamp", &pProcessingTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pCompletionTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "errorTimestamp", &pCompletionTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_FREE((void **) &pStatus);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "status", &pStatus, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRCMP(pStatus, "FAILED"))
        {
            nodeStatus = TE_POLICY_STATUS_FAILURE;
        }
        else
        {
            nodeStatus = TE_POLICY_STATUS_UNKNOWN;
        }

        if (TE_POLICY_TYPE_CERTIFICATE == policyType)
        {
            DIGI_FREE((void **) &pPolicyState);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "policyState", &pPolicyState, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (0 == DIGI_STRNCMP("SPECIFICATION", pPolicyState, DIGI_STRLEN(pPolicyState)))
            {
                policyState = TE_MSG_TYPE_CERTIFICATE_SPECIFICATION;
            }
            else if (0 == DIGI_STRNCMP("CERTIFICATE", pPolicyState, DIGI_STRLEN(pPolicyState)))
            {
                policyState = TE_MSG_TYPE_ISSUED_CERTIFICATE;
            }
            else
            {
                policyState = TE_MSG_TYPE_PENDING_POLICIES;
            }

            status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        else if (TE_POLICY_TYPE_UPDATE == policyType)
        {
            status = JSON_getJsonArrayValue(
                pJCtx, ndx, "artifactList", &ndx, &tokenList, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            for(unsigned int j = 0; j < tokenList.elemCnt; j++)
            {
                ndx++;
                status = JSON_getToken(pJCtx, ndx, &artifact);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                if (JSON_Object != artifact.type)
                {
                    status = ERR_JSON_UNEXPECTED_TYPE;
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }


                DIGI_FREE((void **) &pArtifactId);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactId", &pArtifactId, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactName);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactName", &pArtifactName, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactVersion);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactVersion", &pArtifactVersion, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactTimestamp);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactTimestamp", &pArtifactTimestamp, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndx, "artifactSize", &artifactSize, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                DIGI_FREE((void **) &pArtifactState);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "artifactState", &pArtifactState, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonBooleanValue(
                    pJCtx, ndx, "artifactAsync", &isAsync, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getJsonBooleanValue(
                    pJCtx, ndx, "artifactIgnore", &ignoreArtifact, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = TRUSTEDGE_agentArtifactAddNode(
                    &pArtifactId, &pArtifactName, &pArtifactVersion,
                    &pArtifactTimestamp, pArtifactState, artifactSize,
                    isAsync, ignoreArtifact, FALSE, 0, 0, 0, 0, &pArtifactList);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            if (0 == tokenList.elemCnt)
            {
                status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
        }
        else if (TE_POLICY_TYPE_CLOUDPLATFORM == policyType)
        {
            status = TRUSTEDGE_agentProcessDependentPolicies(
                pJCtx, ndx, &pDependentPolicy);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
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
            status = ERR_TRUSTEDGE_AGENT_UNKNOWN_POLICY_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_agentPolicyAddNodeFinal(
            policyType, &pDeviceGroupId, &pPolicyId, &pDeploymentId,
            priority, &pCreationTimestamp, &pProcessingTimestamp, &pCompletionTimestamp,
            nodeStatus, policyState, &pAlias, &pArtifactList, &pDependentPolicy, TRUE, errorResponseCount, &pCtx->pErrorPolicies);
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

    JSON_releaseContext(&pJCtx);
    DIGICERT_freeReadFile(&pData);
    DIGI_FREE((void **) &pFilePath);

    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pPolicyType);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pCreationTimestamp);
    DIGI_FREE((void **) &pProcessingTimestamp);
    DIGI_FREE((void **) &pCompletionTimestamp);
    DIGI_FREE((void **) &pPolicyState);

    DIGI_FREE((void **) &pArtifactId);
    DIGI_FREE((void **) &pArtifactTimestamp);
    DIGI_FREE((void **) &pArtifactState);
    DIGI_FREE((void **) &pArtifactVersion);
    DIGI_FREE((void **) &pArtifactName);

    TRUSTEDGE_freeDependentPolicies(pDependentPolicy);

    DIGI_FREE((void **) &pStatus);
    DIGI_FREE((void **) &pAlias);

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistLoadConfiguration(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__
    /* make copy of files we are about to read */
    copyAllPersistedFiles(pCtx, snapshotCounter++, 1);
#endif

    status = TRUSTEDGE_agentPersistLoadPendingPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to load pending policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistLoadProcessingPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to load processing policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistLoadAppliedPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to load applied policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistLoadErrorPolicies(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to load applied policies\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistDelete(
    TrustEdgeConfig *pConfig)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, PENDING_POLICY_FILE,
        &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, PROCESSING_POLICY_FILE,
        &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, APPLIED_POLICY_FILE,
        &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, FAILED_POLICY_FILE,
        &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, CERT_SPEC_JSON_FILE,
        &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

exit:

    if (NULL != pFilePath)
    {
        DIGI_FREE((void **) &pFilePath);
    }

    return status;
}

static MSTATUS TRUSTEDGE_agentPersistCertSpecGetFilePath(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pCertSpec,
    ubyte4 certSpecLen,
    sbyte **ppFilePath)
{
    MSTATUS status;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    sbyte *pId = NULL;

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pCertSpec, certSpecLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "certificatePolicyId", &pId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pIssuedCertDir, pId, ppFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(
        *ppFilePath, JSON_EXT, ppFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pId)
    {
        DIGI_FREE((void **) &pId);
    }

    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    return status;
}

static MSTATUS TRUSTEDGE_agentPersistCertSpecWrite(
    ubyte *pCertSpec,
    ubyte4 certSpecLen,
    sbyte *pKeySource,
    ubyte4 keySourceLen,
    sbyte *pKeyAlgorithm,
    ubyte4 keyAlgorithmLen,
    sbyte *pKeyAlias,
    sbyte *pFile)
{
    MSTATUS status;
    sbyte4 ret;
    ubyte *pMsg = NULL;

    ret = snprintf(NULL, 0, PERSISTED_CERT_SPEC_JSON,
                    certSpecLen, pCertSpec,
                    keySourceLen, pKeySource,
                    keyAlgorithmLen, pKeyAlgorithm,
                    pKeyAlias);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    ret = snprintf(pMsg, ret + 1, PERSISTED_CERT_SPEC_JSON,
                    certSpecLen, pCertSpec,
                    keySourceLen, pKeySource,
                    keyAlgorithmLen, pKeyAlgorithm,
                    pKeyAlias);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGICERT_writeFile(pFile, pMsg, ret);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pMsg)
    {
        DIGI_FREE((void **) &pMsg);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistCertSpec(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pCertSpec,
    ubyte4 certSpecLen,
    sbyte *pKeySource,
    ubyte4 keySourceLen,
    sbyte *pKeyAlgorithm,
    ubyte4 keyAlgorithmLen,
    sbyte *pKeyAlias)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;

    if (NULL == pCertSpec)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TRUSTEDGE_agentPersistCertSpecGetFilePath(
        pCtx, pCertSpec, certSpecLen, &pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentPersistCertSpecWrite(
        pCertSpec, certSpecLen,
        pKeySource, keySourceLen,
        pKeyAlgorithm, keyAlgorithmLen, pKeyAlias, pFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pFilePath)
    {
        DIGI_FREE((void **) &pFilePath);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistCertSpecAddCert(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    ubyte *pCSR,
    ubyte4 csrLen,
    sbyte *pCertAlias,
    ubyte *pCert,
    ubyte4 certLen)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;
    certDistinguishedName *pCertInfo = NULL;
    ubyte *pDecodedCert = NULL;
    ubyte4 decodedCertLen = 0;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0, i;
    sbyte4 ret;
    ubyte *pMsg = NULL;

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

    status = CA_MGMT_decodeCertificate(
        pCert, certLen, &pDecodedCert, &decodedCertLen);
    if (OK == status)
    {
        pCert = pDecodedCert;
        certLen = decodedCertLen;
    }

    status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_extractCertTimes(pCert, certLen, pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    i = dataLen - 1;
    while ('}' != pData[i])
        i--;

    i--;

    ret = snprintf(NULL, 0, PERSISTED_CERT_SPEC_CERT_EXT_JSON,
                    i, pData,
                    csrLen, pCSR,
                    pCertAlias,
                    pCertInfo->pStartDate,
                    pCertInfo->pEndDate);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    ret = snprintf(pMsg, ret + 1, PERSISTED_CERT_SPEC_CERT_EXT_JSON,
                    i, pData,
                    csrLen, pCSR,
                    pCertAlias,
                    pCertInfo->pStartDate,
                    pCertInfo->pEndDate);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGICERT_writeFile(pFilePath, pMsg, ret);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pCertInfo)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }

    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }

    if (NULL != pMsg)
    {
        DIGI_FREE((void **) &pMsg);
    }

    if (NULL != pDecodedCert)
    {
        DIGI_FREE((void **) &pDecodedCert);
    }

    if (NULL != pFilePath)
    {
        DIGI_FREE((void **) &pFilePath);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistCertSpecAddOrUpdateRenewRequestTime(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0, i;
    sbyte4 ret;
    ubyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte4 timeStampLen, len;

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

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
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

    timeStampLen = DIGI_STRLEN(pTimeStamp);
    len = DIGI_STRLEN(LAST_RENEW_REQUEST_QUOTED);
    for (i = 0; i < dataLen - timeStampLen; i++)
    {
        if (0 == DIGI_STRNCMP(pData + i, LAST_RENEW_REQUEST_QUOTED, len))
        {
            break;
        }
    }

    if (i == dataLen - timeStampLen)
    {
        i = dataLen - 1;
        while ('}' != pData[i])
            i--;

        i--;

        ret = snprintf(NULL, 0, PERSISTED_CERT_SPEC_CERT_RENEW_JSON,
                        i, pData,
                        pTimeStamp);
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;

        ret = snprintf(pMsg, ret + 1, PERSISTED_CERT_SPEC_CERT_RENEW_JSON,
                        i, pData,
                        pTimeStamp);
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGICERT_writeFile(pFilePath, pMsg, ret);
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
        i += len;
        for (; i < dataLen; i++)
        {
            if (pData[i] == '"')
            {
                i++;
                DIGI_MEMCPY(pData + i, pTimeStamp, timeStampLen);
                break;
            }
        }

        status = DIGICERT_writeFile(pFilePath, pData, dataLen);
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

    if (NULL != pTimeStamp)
    {
        DIGI_FREE((void **) &pTimeStamp);
    }

    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }

    if (NULL != pMsg)
    {
        DIGI_FREE((void **) &pMsg);
    }

    if (NULL != pFilePath)
    {
        DIGI_FREE((void **) &pFilePath);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentPersistCertSpecUpdate(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    ubyte *pCert,
    ubyte4 certLen)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0, i;
    ubyte *pMsg = NULL;
    sbyte4 len;
    ubyte *pDecodedCert = NULL;
    ubyte4 decodedCertLen = 0;
    certDistinguishedName *pCertInfo = NULL;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    sbyte *pAlias = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte4 timeStampLen, ret;

    /* Extract certificate start and expire time */
    if (NULL != pCert)
    {
        status = CA_MGMT_decodeCertificate(
            pCert, certLen, &pDecodedCert, &decodedCertLen);
        if (OK == status)
        {
            pCert = pDecodedCert;
            certLen = decodedCertLen;
        }

        status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CA_MGMT_extractCertTimes(pCert, certLen, pCertInfo);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Get path to certificate */
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

    status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
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

    status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCert)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "selectedCertAlias", &pAlias, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Update certificate on file system */
        status = TRUSTEDGE_utilsWriteKeyAndCert(
            pCtx->pConfig, pAlias, NULL, pCert, certLen
#if defined(__ENABLE_DIGICERT_TAP__)
            , NULL
#endif
            );
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Update issued certificate file with new certificate values */

        /* Update issued time */
        len = DIGI_STRLEN(CERT_ISSUED_TIME_QUOTED);
        for (i = 0; i < dataLen - len; i++)
        {
            if (0 == DIGI_STRNCMP(pData + i, CERT_ISSUED_TIME_QUOTED, len))
            {
                break;
            }
        }

        if (i == dataLen - len)
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_FORMAT;
            goto exit;
        }

        i += len;
        for (; i < dataLen; i++)
        {
            if (pData[i] == '"')
            {
                i++;
                DIGI_MEMCPY(pData + i, pCertInfo->pStartDate, DIGI_STRLEN(pCertInfo->pStartDate));
                break;
            }
        }

        /* Update expire time */
        len = DIGI_STRLEN(CERT_EXPIRE_TIME_QUOTED);
        for (i = 0; i < dataLen - len; i++)
        {
            if (0 == DIGI_STRNCMP(pData + i, CERT_EXPIRE_TIME_QUOTED, len))
            {
                break;
            }
        }

        if (i == dataLen - len)
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_FORMAT;
            goto exit;
        }

        i += len;
        for (; i < dataLen; i++)
        {
            if (pData[i] == '"')
            {
                i++;
                DIGI_MEMCPY(pData + i, pCertInfo->pEndDate, DIGI_STRLEN(pCertInfo->pEndDate));
                break;
            }
        }
    }

    /* Add or update response time to JSON file */
    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    timeStampLen = DIGI_STRLEN(pTimeStamp);
    len = DIGI_STRLEN(LAST_RENEW_RESPONSE_QUOTED);
    for (i = 0; i < dataLen - timeStampLen; i++)
    {
        if (0 == DIGI_STRNCMP(pData + i, LAST_RENEW_RESPONSE_QUOTED, len))
        {
            break;
        }
    }

    if (i == dataLen - timeStampLen)
    {
        i = dataLen - 1;
        while ('}' != pData[i])
            i--;

        i--;

        ret = snprintf(NULL, 0, PERSISTED_CERT_SPEC_CERT_RENEW_RSP_JSON,
                        i, pData,
                        pTimeStamp);
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;

        ret = snprintf(pMsg, ret + 1, PERSISTED_CERT_SPEC_CERT_RENEW_RSP_JSON,
                        i, pData,
                        pTimeStamp);
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGICERT_writeFile(pFilePath, pMsg, ret);
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
        i += len;
        for (; i < dataLen; i++)
        {
            if (pData[i] == '"')
            {
                i++;
                DIGI_MEMCPY(pData + i, pTimeStamp, timeStampLen);
                break;
            }
        }

        status = DIGICERT_writeFile(pFilePath, pData, dataLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    if (NULL != pCert)
    {
        /* Certificate was updated, send out notification(s) */
        status = COMMON_UTILS_addPathExtension(pAlias, TRUSTEDGE_SUFFIX_PEM, &pAlias);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pCtx->pConfig->pKeystoreCertsDir, pAlias, &pAlias);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_ENROLL_resourceUpdateHandler(pAlias);
        if (ERR_CERT_NOT_FOUND == status)
        {
            /* No one has subscribed to this resource */
            status = OK;
        }
        else if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: Failed to send resouce update for %s, %d = %s\n",
                __func__, __LINE__, pAlias, status,
                MERROR_lookUpErrorCode(status));
            /* continue with OK status, failure to update resources is not a
             * fatal error */
            status = OK;
        }
    }
#endif

exit:

    if (NULL != pTimeStamp)
    {
        DIGI_FREE((void **) &pTimeStamp);
    }

    if (NULL != pDecodedCert)
    {
        DIGI_FREE((void **) &pDecodedCert);
    }

    if (NULL != pCertInfo)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }

    if (NULL != pAlias)
    {
        DIGI_FREE((void **) &pAlias);
    }

    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }

    if (NULL != pMsg)
    {
        DIGI_FREE((void **) &pMsg);
    }

    if (NULL != pFilePath)
    {
        DIGI_FREE((void **) &pFilePath);
    }

    return status;
}
