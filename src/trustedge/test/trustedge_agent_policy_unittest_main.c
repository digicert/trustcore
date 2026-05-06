/*
 * trustedge_agent_policy_unittest_main.c
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

#include "../agent/trustedge_agent_policy_unittest.h"

#include "../../common/mdefs.h"
#include "../../common/mocana.h"

#include "../../../unit_tests/unittest.h"

#include <jansson.h>
#include <string.h>
#include <regex.h>

/* returns 1 if timestamp format matches pattern, 0 otherwise */
int test_timestamp_format(const sbyte *pTimeStamp)
{
    regex_t regex;
    int result;
    /* Pattern matches exactly the datetime format "%4d-%02d-%02dT%02d:%02d:%02d.000Z" */
#if defined(__ENABLE_DIGICERT_TIMESTAMP_MILLISECONDS__)
    const char* pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3}Z$";
#else
    const char* pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$";
#endif

    result = regcomp(&regex, pattern, REG_EXTENDED);
    if (result)
        return 0;

    result = regexec(&regex, pTimeStamp, 0, NULL, 0); 
    regfree(&regex);

    if (result == 0)
        return 1;
    
    return 0;
}

int check_json_string(json_t *pJson, sbyte *pKey, sbyte *pValue)
{
    const sbyte *pJsonValue = json_string_value(json_object_get(pJson, pKey));
    return strcmp(pJsonValue, pValue);
}

int trustedge_agent_policy_unittest_policy_progress()
{
    MSTATUS status;
    int retVal = 0;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;

    json_error_t error;
    json_t *json = NULL;

    status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentProgress_unit(
        "dev_id",
        "account_id",
        "dev_group_id",
        "update_policy_id",
        "deployment_id",
        "artifact_id",
        NULL,
        TE_ARTIFACT_STATE_PENDING,
        &pData,
        &dataLen
    );
    if (OK != status)
    {
        return 1;
    }

    json = json_loads(pData, 0, &error);
    if (NULL == json)
    {
        (void) DIGI_FREE((void **) &pData);
        return 1;
    }

    if(check_json_string(json, "policyService", "UpdatePolicy"))
    {
        retVal++;
    }

    if(check_json_string(json, "deviceId", "dev_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "accountId", "account_id"))
    {
        retVal++;
    }

    if (!test_timestamp_format(json_string_value(json_object_get(json, "timestamp"))))
    {
        retVal++;
    }

    if(check_json_string(json, "mode", "update_policy_deployment_progress"))
    {
        retVal++;
    }

    if(check_json_string(json, "deviceGroupId", "dev_group_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "updatePolicyId", "update_policy_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "deploymentId", "deployment_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "artifactId", "artifact_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "progressState", "Pending"))
    {
        retVal++;
    }

    (void) json_decref(json);
    (void) DIGI_FREE((void **) &pData);

    return retVal;
}

int trustedge_agent_policy_unittest_policy_status()
{
    MSTATUS status;
    int retVal = 0;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;

    json_error_t error;
    json_t *json = NULL;

    status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus_unit(
        "dev_id",
        "account_id",
        "dev_group_id",
        "update_policy_id",
        "deployment_id",
        NULL,
        TRUE,
        "placeholder",
        "placeholder",
        &pData,
        &dataLen
    );
    if (OK != status)
    {
        return 1;
    }

    json = json_loads(pData, 0, &error);
    if (NULL == json)
    {
        (void) DIGI_FREE((void **) &pData);
        return 1;
    }

    if(check_json_string(json, "policyService", "UpdatePolicy"))
    {
        retVal++;
    }

    if(check_json_string(json, "deviceId", "dev_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "accountId", "account_id"))
    {
        retVal++;
    }

    if (!test_timestamp_format(json_string_value(json_object_get(json, "timestamp"))))
    {
        retVal++;
    }

    if(check_json_string(json, "mode", "update_policy_deployment_completed"))
    {
        retVal++;
    }

    if(check_json_string(json, "deviceGroupId", "dev_group_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "updatePolicyId", "update_policy_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "deploymentId", "deployment_id"))
    {
        retVal++;
    }

    (void) json_decref(json); json = NULL;
    (void) DIGI_FREE((void **) &pData);
    status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus_unit(
        "dev_id",
        "account_id",
        "dev_group_id",
        "update_policy_id",
        "deployment_id",
        NULL,
        FALSE,
        "placeholder",
        "placeholder",
        &pData,
        &dataLen
    );
    if (OK != status)
    {
        return retVal + 1;
    }

    json = json_loads(pData, 0, &error);
    if (NULL == json)
    {
        (void) DIGI_FREE((void **) &pData);
        return retVal + 1;
    }

    if(check_json_string(json, "policyService", "UpdatePolicy"))
    {
        retVal++;
    }

    if(check_json_string(json, "deviceId", "dev_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "accountId", "account_id"))
    {
        retVal++;
    }

    if (!test_timestamp_format(json_string_value(json_object_get(json, "timestamp"))))
    {
        retVal++;
    }

    if(check_json_string(json, "mode", "update_policy_deployment_failed"))
    {
        retVal++;
    }

    if(check_json_string(json, "deviceGroupId", "dev_group_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "updatePolicyId", "update_policy_id"))
    {
        retVal++;
    }

    if(check_json_string(json, "deploymentId", "deployment_id"))
    {
        retVal++;
    }

    (void) json_decref(json);
    (void) DIGI_FREE((void **) &pData);

    return retVal;
}

int main()
{
    int retVal = 0;

    DIGICERT_initDigicert();

    putenv("TRUSTEDGE_CONFIG=./projects/trustedge/sample/trustedge_configuration/trustedge.json");

    retVal += trustedge_agent_policy_unittest_policy_progress();
    retVal += trustedge_agent_policy_unittest_policy_status();

    DIGICERT_freeDigicert();

    return retVal;
}
