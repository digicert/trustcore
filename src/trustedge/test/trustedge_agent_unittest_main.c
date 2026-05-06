/*
 * trustedge_agent_unittest_main.c
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

#include <unistd.h>
#include "../utils/trustedge_utils.h"
#include "../agent/trustedge_agent_persist.h"
#include "../agent/trustedge_agent_unittest.h"
#include "../agent/trustedge_agent_policy_unittest.h"

#include "../../common/mdefs.h"
#include "../../common/mocana.h"

#include "../../../unit_tests/unittest.h"

int trustedge_agent_unittest_parse_config()
{
    int retVal = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;
    sbyte *pStr;
    sbyte4 strLen;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_3072.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_3072.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_4096.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_4096.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

#if 0
    /* RSA PSS unittests do not pass */
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_pss_2048.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_pss_2048.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_pss_3072.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_pss_3072.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_pss_4096.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_pss_4096.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));
#endif

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_ec_256.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_ec_256.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_ec_384.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_ec_384.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_ec_521.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_ec_521.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    return retVal;
}

int trustedge_agent_unittest_nbirth_body()
{
    int retVal = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    sbyte *pMsgBody = "{\"deviceId\":\"abd104bd-54c4-49a8-b9be-db7edc576787\",\"accountId\":\"ddcef16b-891e-4b08-93c2-df6cac44f407\",\"divisionId\":\"0c56d835-c1c5-4862-963f-5943e9ed5480\",\"deviceGroupId\":\"c30853d1-1961-4507-a416-fac2b63585c5\",\"deviceState\":\"Updated\"}";
    sbyte *pStr;
    sbyte4 strLen;
    sbyte4 cmpRes = -1;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentCreateNBirthMsg_unit(pCtx, &pMsg, &msgLen));
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(pMsg + msgLen - DIGI_STRLEN(pMsgBody), pMsgBody, DIGI_STRLEN(pMsgBody), &cmpRes));
    retVal += UNITTEST_INT(__MOC_LINE__, cmpRes, 0);

    DIGI_FREE((void **) &pMsg);

    return retVal;
}

typedef struct
{
    sbyte *pFile;
    TrustEdgeAgentPolicyNode *pExpected;
} PendingPolicyTest;

static int compare_policy_nodes(TrustEdgeAgentPolicyNode *pNode, TrustEdgeAgentPolicyNode *pExpected)
{
    int retVal = 0;

    do
    {
        if (NULL == pExpected)
        {
            if (NULL != pNode)
                retVal += UNITTEST_STATUS(__MOC_LINE__, ERR_GENERAL);

            break;
        }
        else if (NULL == pNode)
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, ERR_GENERAL);
            break;
        }

        retVal += UNITTEST_INT(__MOC_LINE__, pNode->type, pExpected->type);
        retVal += UNITTEST_INT(__MOC_LINE__, DIGI_STRCMP(pNode->pId, pExpected->pId), 0);
        if (NULL != pExpected->pDeploymentId)
            retVal += UNITTEST_INT(__MOC_LINE__, DIGI_STRCMP(pNode->pDeploymentId, pExpected->pDeploymentId), 0);
        else if (NULL != pNode->pDeploymentId)
            retVal += UNITTEST_STATUS(__MOC_LINE__, ERR_GENERAL);
        retVal += UNITTEST_INT(__MOC_LINE__, DIGI_STRCMP(pNode->pDeviceGroupId, pExpected->pDeviceGroupId), 0);
        retVal += UNITTEST_INT(__MOC_LINE__, pNode->priority, pExpected->priority);

        pNode = pNode->pNext;
        pExpected = pExpected->pNext;

    } while (NULL != pExpected);

    return retVal;
}

static int test_pending_policy(int h, PendingPolicyTest *pTest)
{
    int retVal = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;
    sbyte *pStr;
    sbyte4 strLen;

    retVal += UNITTEST_STATUS(h, DIGICERT_readFile(pTest->pFile, &pMsg, &msgLen));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(h, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    retVal += UNITTEST_STATUS(h, TRUSTEDGE_agentParsePendingPolicies_unit(pCtx, pMsg, msgLen));
    retVal += compare_policy_nodes(((TrustEdgeAgentCtx *) pCtx)->pPendingPolicies, pTest->pExpected);
    retVal += UNITTEST_STATUS(h, TRUSTEDGE_agentContextRelease(&pCtx));

    DIGI_FREE((void **) &pMsg);

    return retVal;
}

int trustedge_agent_unittest_pending_policies()
{
    int retVal = 0;
    ubyte4 i;
    TrustEdgeAgentPolicyNode pending_policy_basic = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820113",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 0,
        .pNext = NULL
    };

    TrustEdgeAgentPolicyNode pending_policy_basic_2 = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "IOT_9343cc63-ca25-4f3c-a180-3c4d18bb8bcc",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 1,
        .pNext = NULL
    };

    TrustEdgeAgentPolicyNode pending_policy_priority_ordering_4 = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820115",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 15,
        .pNext = NULL
    };
    TrustEdgeAgentPolicyNode pending_policy_priority_ordering_3 = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820126",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 9,
        .pNext = &pending_policy_priority_ordering_4
    };
    TrustEdgeAgentPolicyNode pending_policy_priority_ordering_2 = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820119",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 9,
        .pNext = &pending_policy_priority_ordering_3
    };
    TrustEdgeAgentPolicyNode pending_policy_priority_ordering_1 = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820114",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 5,
        .pNext = &pending_policy_priority_ordering_2
    };
    TrustEdgeAgentPolicyNode pending_policy_priority_ordering = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820110",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 0,
        .pNext = &pending_policy_priority_ordering_1
    };

    TrustEdgeAgentPolicyNode pending_policy_all_policy_types_1 = {
        .type = TE_POLICY_TYPE_CERTIFICATE,
        .pId = "294820115",
        .pDeploymentId = NULL,
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 1,
        .pNext = NULL
    };
    TrustEdgeAgentPolicyNode pending_policy_all_policy_types = {
        .type = TE_POLICY_TYPE_UPDATE,
        .pId = "294820116",
        .pDeploymentId = "5088534",
        .pDeviceGroupId = "c30853d1-1961-4507-a416-fac2b63585c5",
        .priority = 0,
        .pNext = &pending_policy_all_policy_types_1
    };

    PendingPolicyTest tests[] = {
        {
            "./src/trustedge/test/data/pending_policy_basic.json",
            &pending_policy_basic
        },
        {
            "./src/trustedge/test/data/pending_policy_basic_2.json",
            &pending_policy_basic_2
        },
        {
            "./src/trustedge/test/data/pending_policy_priority_ordering.json",
            &pending_policy_priority_ordering
        },
        {
            "./src/trustedge/test/data/pending_policy_all_policy_types.json",
            &pending_policy_all_policy_types
        }
    };

    for (i = 0; i < COUNTOF(tests); i++)
        retVal += test_pending_policy(i, tests + i);

    return retVal;
}

static int test_cert_template(int h, char *pKeyFile, char *pFile)
{
    int retVal = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeAgentCtx *pContext = NULL;
    TrustEdgeConfig *pConfig = NULL;
    TrustEdgeAgentPolicyNode node = {
        .pId = "TEST_POLICY_ID_DO_NOT_CHANGE"
    };
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;
    AsymmetricKey *pAsymKey = NULL;
    sbyte *pStr;
    sbyte strLen;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    retVal += UNITTEST_STATUS(h, DIGICERT_readFile(pFile, &pMsg, &msgLen));

    retVal += UNITTEST_STATUS(h, DIGICERT_readFile(pKeyFile, &pKey, &keyLen));
    retVal += UNITTEST_STATUS(h, DIGI_CALLOC((void **) &pAsymKey, sizeof(AsymmetricKey), 1));
    retVal += UNITTEST_STATUS(h, CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, pAsymKey));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(h, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    pContext = pCtx;
    pContext->curPolicy.pPolicy = &node;
    pContext->curPolicy.data.cps.pNewKey = pAsymKey;
    pContext->curPolicy.pPolicy->pCertSpecJson = pMsg;
    pContext->curPolicy.pPolicy->certSpecJsonLen = msgLen;
    retVal += UNITTEST_STATUS(h, TRUSTEDGE_agentConstructCertificateRequest_unit(pCtx, &pReq, &reqLen));
    retVal += UNITTEST_STATUS(h, TRUSTEDGE_agentContextRelease(&pCtx));

    DIGI_FREE((void **) &pKey);
    DIGI_FREE((void **) &pReq);
    DIGI_FREE((void **) &pMsg);
    DIGI_FREE((void **) &pReq);
    DIGI_FREE((void **) &pKey);

    return retVal;
}

int trustedge_agent_unittest_cert_template()
{
    char *pCertTemplateFiles[] = {
        "./src/trustedge/test/data/cert_template_rsa_2048_basic.json",
        "./src/trustedge/test/data/cert_template_ec_256_basic.json",
        "./src/trustedge/test/data/cert_template_san.json",
        "./src/trustedge/test/data/cert_template_ext_attrs.json"
    };
    char *pKeyFiles[] = {
        "./projects/trustedge/sample/Keystore/keys/rsa_2048.pem",
        "./projects/trustedge/sample/Keystore/keys/ec_256.pem",
        "./projects/trustedge/sample/Keystore/keys/rsa_2048.pem",
        "./projects/trustedge/sample/Keystore/keys/rsa_2048.pem"
    };
    int retVal = 0;
    unsigned int i;

    for (i = 0; i < COUNTOF(pCertTemplateFiles); i++)
        retVal += test_cert_template(i, pKeyFiles[i], pCertTemplateFiles[i]);

    return retVal;
}

static int trustedge_utils_unittest_valid_window_test()
{
    int ret = 0;
    sbyte *pCurrentTime = NULL;
    int timeWindow = 3;

    ret = UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsGetTime(&pCurrentTime, 0));
    if (ret > 0)
        goto exit;

    sleep(1);
    if (FALSE == TRUSTEDGE_utilsInValidTimeWindow(pCurrentTime, timeWindow))
    {
        ret = 1;
    }

    sleep(3);
    if (TRUE == TRUSTEDGE_utilsInValidTimeWindow(pCurrentTime, timeWindow))
    {
        ret = 1;
    }

exit:

    DIGI_FREE((void **) &pCurrentTime);
    return ret;
}

static int trustedge_agent_unittest_persist_cert_spec(
    sbyte *pFile,
    ubyte *pReq,
    ubyte4 reqLen,
    sbyte *pKeySource,
    sbyte *pKeyAlgorithm,
    sbyte *pKeyAlias,
    sbyte *pId,
    sbyte *pCertAlias,
    sbyte *pCertFile)
{
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    int retVal = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;
    sbyte *pStr;
    sbyte4 strLen;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));
    if (retVal > 0)
        goto exit;

    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapConfig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapConfig[strLen] = '\0';
    pStr = "./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig";
    strLen = DIGI_STRLEN(pStr);
    DIGI_MALLOC_MEMCPY ((void **)&pConfig->pBootstrapSig, strLen + 1, pStr, strLen);
    pConfig->pBootstrapSig[strLen] = '\0';
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    if (retVal > 0)
        goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGICERT_readFile(pFile, &pData, &dataLen));
    if (retVal > 0)
        goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentPersistCertSpec(pCtx, pData, dataLen, pKeySource, DIGI_STRLEN(pKeySource), pKeyAlgorithm, DIGI_STRLEN(pKeyAlgorithm), pKeyAlias));
    if (retVal > 0)
        goto exit;

    DIGI_FREE((void **) &pData);
    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGICERT_readFile(pCertFile, &pData, &dataLen));
    if (retVal > 0)
        goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentPersistCertSpecAddCert(pCtx, pId, pReq, reqLen, pCertAlias, pData, dataLen));
    if (retVal > 0)
        goto exit;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));
    if (retVal > 0)
        goto exit;

exit:

    DIGI_FREE((void **) &pData);

    return retVal;
}

static int trustedge_agent_unittest_persist_cert_spec_all()
{
    int retVal = 0;

    retVal += trustedge_agent_unittest_persist_cert_spec(
        "./projects/trustedge/sample/messages/cert_policy_flow/data/cert_spec.json",
        "test",
        4,
        "SW",
        "RSA+2048",
        "294820113",
        "294820113",
        "294820113",
        "./src/crypto/test/testRsaJsonCert.pem");

    return retVal;
}

int main()
{
    int retVal = 0;

    DIGICERT_initDigicert();
    MSG_LOG_init(MSG_LOG_ERROR);

    putenv("TRUSTEDGE_CONFIG=./projects/trustedge/sample/trustedge_configuration/trustedge.json");

    retVal += trustedge_utils_unittest_valid_window_test();
    retVal += trustedge_agent_unittest_parse_config();
    retVal += trustedge_agent_unittest_nbirth_body();
    retVal += trustedge_agent_unittest_pending_policies();
    retVal += trustedge_agent_unittest_cert_template();
    retVal += trustedge_agent_unittest_persist_cert_spec_all();

    MSG_LOG_uninit();
    DIGICERT_freeDigicert();

    return retVal;
}
