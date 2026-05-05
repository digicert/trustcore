/*
 * trustedge_agent_updatepolicy_unittest_main.c
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
#include "../agent/trustedge_agent_priv.h"
#include "../agent/trustedge_agent_actionhandler.h"
#include "../utils/trustedge_utils.h"
#include "../../common/mfmgmt.h"

#include "../../../unit_tests/unittest.h"
#include "../agent/trustedge_agent_updatepolicy.c"

int test_update_pkg(char *pArtifactMimeFile, TrustEdgeAgentActionType type)
{
    int retVal = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    ubyte copyCmd[1024];
    TrustEdgeAgentCtx *pAgentCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;
    TrustEdgeAgentPolicyNode node = {
        .type = TE_POLICY_TYPE_UPDATE
    };
    TrustEdgeAgentArtifactNode artifact = {
        .pId = "d9013cba-fc66-4fe6-a461-6242055b8359",
        .state = TE_ARTIFACT_STATE_DOWNLOADING
    };
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;


    snprintf(copyCmd, 1024, "cp %s %s", pArtifactMimeFile, "projects/trustedge/sample/workspace/payload.mime");
    if (TRUE == FMGMT_pathExists("projects/trustedge/sample/workspace/artifact", NULL))
    {
        FMGMT_remove("projects/trustedge/sample/workspace/artifact", TRUE);
    }
    system("mkdir -p projects/trustedge/sample/workspace/artifact");
    system(copyCmd);

    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGICERT_readFile(pArtifactMimeFile, &pMsg, &msgLen));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig (&pConfig));

    pConfig->pBootstrapConfig = TRUSTEDGE_utilsCloneString("./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json");
    pConfig->pBootstrapSig = TRUSTEDGE_utilsCloneString("./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig");

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    pAgentCtx = pCtx;
    pAgentCtx->curPolicy.pPolicy = &node;
    pAgentCtx->curPolicy.data.ups.pArtifact = &artifact;
    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentParseArtifactDownload(pCtx, pMsg, msgLen, type));

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextRelease(&pCtx));

    if (TRUE == FMGMT_pathExists("projects/trustedge/sample/workspace/rawfile.zip", NULL))
    {
        FMGMT_remove("projects/trustedge/sample/workspace/rawfile.zip", TRUE);
    }
    DIGI_FREE((void **) &pMsg);
    return retVal;
}

/*
 *  test.zip content:
 *  test_dir/
 *  ├── emptydir
 *  ├── subdir
 *  │   ├── test_file2.txt
 *  │   └── test_file3.txt
 *  └── test_file1.txt
 */
int test_extract_api(char *pZipFile, char *pDst)
{
    int ret;
    int failCount = 0;
    FileDescriptorInfo fd = {0};
    sbyte filePath[256];

    sbyte *filenames[] = {
        "emptydir",
        "test_file1.txt",
        "subdir/test_file2.txt",
        "subdir/test_file3.txt"
    };
    sbyte4 filenameSize = 4;

    ret = UNITTEST_STATUS(__MOC_LINE__, FMGMT_mkdir(pDst, 0777));
    if (0 < ret)
    {
        failCount++;
        goto exit;
    }

    ret = UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsExtractZip(pZipFile, pDst));
    if (0 < ret)
    {
        failCount++;
        goto exit;
    }

    for(int i = 0; i < filenameSize; i++)
    {
        snprintf(filePath, 256, "%s/%s", pDst, filenames[i]);
        if (FALSE == FMGMT_pathExists(filePath, &fd))
        {
            failCount++;
            continue;
        }

        if (0 == DIGI_STRCMP("emptydir", filenames[i]))
        {
            if (FTDirectory != fd.type)
            {
                failCount++;
                continue;
            }
        }
    }

exit:
    FMGMT_remove(pDst, TRUE);
    return failCount;
}

static void writeListToFile(TrustEdgeAgentArtifactNode *pList, FileDescriptor pFile)
{
    int bytesWritten;
    TrustEdgeAgentArtifactNode *pLast = NULL;

    FMGMT_fwrite("-----------------\n", 1, DIGI_STRLEN("-----------------\n"), pFile, &bytesWritten);
    while (NULL != pList)
    {
        FMGMT_fprintf(pFile, "%p = %s\n", pList, pList->pId);
        pLast = pList;
        pList = pList->pNext;
    }
    FMGMT_fwrite("**---------------\n", 1, DIGI_STRLEN("**---------------\n"), pFile, &bytesWritten);
    while (NULL != pLast)
    {
        FMGMT_fprintf(pFile, "%p = %s\n", pLast, pLast->pId);
        pLast = pLast->pPrev;
    }
    FMGMT_fwrite("-----------------\n", 1, DIGI_STRLEN("-----------------\n"), pFile, &bytesWritten);
}

static sbyte* toString(sbyte *str)
{
    int len = DIGI_STRLEN(str);
    sbyte *s = NULL;

    DIGI_MALLOC((void **) &s, len + 1);
    snprintf(s, len+1, "%s", str);

    return s;
}

int test_artifact_linked_list()
{
    int status;
    int retVal = 0;
    TrustEdgeAgentArtifactNode *pList = NULL;
    sbyte *pId;
    sbyte *pName;
    sbyte *pVersion;
    sbyte *pTimestamp;
    sbyte *pStatus;
    ubyte4 size;
    FileDescriptor pFile;

    status = FMGMT_fopen("artifact_prints.txt", "w", &pFile);
    if (0 != status)
    {
        retVal++;
        return retVal;
    }

    writeListToFile(pList, pFile);

    pId = toString("aID");
    pName = toString("aNAME");
    pVersion = toString("aVERSION");
    pTimestamp = toString("aTIMESTAMP");
    pStatus = toString("SUCCESS");
    size = 100;

    status = TRUSTEDGE_agentArtifactAddNode(
        &pId,
        &pName,
        &pVersion,
        &pTimestamp,
        pStatus,
        size,
        FALSE,
        FALSE,
        FALSE,
        0,
        0,
        0,
        0,
        &pList
    );
    if (0 != status)
    {
        retVal++;
        return retVal;
    }

    writeListToFile(pList, pFile);

    pId = toString("bID");
    pName = toString("bNAME");
    pVersion = toString("bVERSION");
    pTimestamp = toString("bTIMESTAMP");
    size = 100;

    status = TRUSTEDGE_agentArtifactAddNode(
        &pId,
        &pName,
        &pVersion,
        &pTimestamp,
        pStatus,
        size,
        FALSE,
        FALSE,
        FALSE,
        0,
        0,
        0,
        0,
        &pList
    );
    if (0 != status)
    {
        retVal++;
        return retVal;
    }

    writeListToFile(pList, pFile);

    pId = toString("cID");
    pName = toString("cNAME");
    pVersion = toString("cVERSION");
    pTimestamp = toString("cTIMESTAMP");
    size = 100;

    status = TRUSTEDGE_agentArtifactAddNode(
        &pId,
        &pName,
        &pVersion,
        &pTimestamp,
        pStatus,
        size,
        FALSE,
        FALSE,
        FALSE,
        0,
        0,
        0,
        0,
        &pList
    );
    if (0 != status)
    {
        retVal++;
        return retVal;
    }

    writeListToFile(pList, pFile);
    FMGMT_fclose(&pFile);

    TRUSTEDGE_agentFreeAgentArtifactList(&pList);

    DIGI_FREE((void **) &pStatus);

    return retVal;
}

int test_manifest_parsing()
{
    int retVal = 0;
    int status;
    TrustEdgeArtifactManifest manifest;

    certStorePtr pTrustedStore;


    status = CERT_STORE_createStore(&pTrustedStore);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_addTrustPointCertsByDir(
        pTrustedStore, NULL, "projects/trustedge/sample/Keystore/ca",
        FALSE);
    if (OK != status)
    {
        goto exit;
    }

    initManifest(&manifest);

    if (system("mkdir -p projects/trustedge/sample/workspace/artifact"))
    {
        retVal++;
        goto exit;
    }

    if (system("cp projects/trustedge/sample/test_data/sig_verify/payload.zip projects/trustedge/sample/workspace/artifact/payload.zip"))
    {
        retVal++;
        goto exit;
    }
    if (system("cp projects/trustedge/sample/test_data/sig_verify/rsa_manifest.json projects/trustedge/sample/workspace/artifact/manifest.json"))
    {
        retVal++;
        goto exit;
    }

    status = TRUSTEDGE_agentmanifesthandler(&manifest, "projects/trustedge/sample/workspace/artifact");
    if (OK != status)
    {
        retVal++;
    }

    status = TRUSTEDGE_agentsignaturehandler(pTrustedStore, &manifest);
    cleanUpManifest(&manifest);
    if (OK != status)
    {
        retVal++;
    }

    system("cp projects/trustedge/sample/test_data/sig_verify/pss_manifest.json projects/trustedge/sample/workspace/artifact/manifest.json");

    status = TRUSTEDGE_agentmanifesthandler(&manifest, "projects/trustedge/sample/workspace/artifact");
    if (OK != status)
    {
        retVal++;
    }

    status = TRUSTEDGE_agentsignaturehandler(pTrustedStore, &manifest);
    cleanUpManifest(&manifest);
    if (OK != status)
    {
        retVal++;
    }

#if 0
    /* TRUSTEDGE_utilsValidateCert returns ERR_CERT_EXPIRED for this test. */
    system("cp projects/trustedge/sample/test_data/sig_verify/ecc_manifest.json projects/trustedge/sample/workspace/artifact/manifest.json", TRUE);

    status = TRUSTEDGE_agentmanifesthandler(&manifest, "projects/trustedge/sample/workspace/artifact");
    if (OK != status)
    {
        retVal++;
    }

    status = TRUSTEDGE_agentsignaturehandler(pTrustedStore, &manifest);
    if (OK != status)
    {
        retVal++;
    }
    cleanUpManifest(&manifest);
#endif
exit:
    CERT_STORE_releaseStore (&pTrustedStore);
    return retVal;
}

int test_compute_digest_apis()
{
    int status;
    int retVal = 0;
    ubyte *pData = NULL;
    ubyte4 dataLen;
    sbyte *pDigest = NULL;
    sbyte4 digestLen;
    sbyte *pDigestStr = NULL;
    sbyte *pDigestStr2 = NULL;

    sbyte *pExpectedHash = "ec80eab2ce16d2469bbb856c1e8e76570d0d9718b63736379a899b0413a66c91";

    status = DIGICERT_readFile("projects/trustedge/sample/test_data/sig_verify/payload.zip", &pData, &dataLen);
    if (OK != status)
    {
        retVal++;
        goto exit;
    }

    status = TRUSTEDGE_utilsComputeRawDigest (pData, dataLen, ht_sha256, &pDigest, &digestLen);
    if (OK != status)
    {
        retVal++;
        goto exit;
    }

    status = TRUSTEDGE_utilsBinToString (pDigest, digestLen, &pDigestStr);
    if (OK != status)
    {
        retVal++;
        goto exit;
    }

    if (DIGI_STRNCMP(pExpectedHash, pDigestStr, DIGI_STRLEN(pExpectedHash)))
    {
        retVal++;
        goto exit;
    }

    status = TRUSTEDGE_utilsComputeAsciiDigest(pData, dataLen, ht_sha256, &pDigestStr2);
    if (OK != status)
    {
        retVal++;
        goto exit;
    }

    if (DIGI_STRNCMP(pExpectedHash, pDigestStr2, DIGI_STRLEN(pExpectedHash)))
    {
        retVal++;
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pData);
    DIGI_FREE((void **) &pDigest);
    DIGI_FREE((void **) &pDigestStr);
    DIGI_FREE((void **) &pDigestStr2);

    return retVal;
}

int test_deb_pkg()
{
    int retVal = 0;
    sbyte *pFilePath = "projects/trustedge/sample/test_data";
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeAgentCtx *pAgentCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;

    TrustEdgeAgentPolicyNode node = {
        .type = TE_POLICY_TYPE_UPDATE
    };

    TrustEdgeAgentArtifactNode artifact = {
        .pId = "d9013cba-fc66-4fe6-a461-6242055b8359",
        .state = TE_ARTIFACT_STATE_DOWNLOADING
    };

    TrustEdgeArtifactAction action = { 0 };

    action.type = TE_ACTION_INSTALL;
    action.handler.type = TE_ACTION_HANDLER_PKG_MGR_TYPE;
    action.handler.subtype = TE_ACTION_HANDLER_SUBTYPE_DPKG;
    action.pActionPath = "./action_handler/digicertdemopkg.deb";
    action.pActionArgument = "--refuse-downgrade";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig(&pConfig));

    pConfig->pBootstrapConfig = TRUSTEDGE_utilsCloneString("./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json");
    pConfig->pBootstrapSig = TRUSTEDGE_utilsCloneString("./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig");

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    if (retVal != 0)
        return retVal;

    pAgentCtx = pCtx;
    pAgentCtx->curPolicy.pPolicy = &node;
    pAgentCtx->curPolicy.data.ups.pArtifact = &artifact;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler(&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs (&action);

    action.type = TE_ACTION_ROLLBACK;
    action.pActionPath = NULL;
    action.pActionArgument = "digicert-demo-package";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler(&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs (&action);

    return retVal;
}

int test_launch_process()
{
    int status;
    int retVal = 0;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeAgentCtx *pAgentCtx = NULL;
    TrustEdgeConfig *pConfig = NULL;

    TrustEdgeAgentPolicyNode node = {
        .type = TE_POLICY_TYPE_UPDATE
    };

    TrustEdgeAgentArtifactNode artifact = {
        .pId = "d9013cba-fc66-4fe6-a461-6242055b8359",
        .state = TE_ARTIFACT_STATE_DOWNLOADING
    };

    sbyte *pFilePath = "projects/trustedge/sample/test_data";
    TrustEdgeArtifactAction action = { 0 };

    action.type = TE_ACTION_INSTALL;
    action.handler.type = TE_ACTION_HANDLER_SCRIPT;
    action.handler.subtype = TE_ACTION_HANDLER_SUBTYPE_BASH;
    action.pActionPath = "./action_handler/test_script.sh";
    action.pActionArgument = NULL;
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_utilsReadConfig(&pConfig));

    pConfig->pBootstrapConfig = TRUSTEDGE_utilsCloneString("./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.json");
    pConfig->pBootstrapSig = TRUSTEDGE_utilsCloneString("./projects/trustedge/sample/bootstrap_configuration/config_rsa_2048.sig");

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_agentContextAcquire(&pCtx, &pConfig));
    pAgentCtx = pCtx;
    pAgentCtx->curPolicy.pPolicy = &node;
    pAgentCtx->curPolicy.data.ups.pArtifact = &artifact;
    pAgentCtx->actionHandlerTimeout = 15;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    action.pActionPath = "./action_handler/test_script_arg.sh";
    action.pActionArgument = "Digicert";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__,  TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    /* negative test : ERROR: action exited with status: 84 */
    action.pActionArgument = NULL;
    action.pActionPath = "./action_handler/test_script2.sh";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    status = TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, TRUE, OK != status ? TRUE : FALSE);
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    /* negative test : ERROR: action exited with status: 1 */
    action.pActionPath = "./action_handler/test_script_failed.sh";

    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    status = TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, TRUE, OK != status ? TRUE : FALSE);
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    /* negative test */
    action.pActionPath = "./action_handler/test_script_timeout.sh";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);
    pAgentCtx->actionHandlerTimeout = 5;

    status = TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_TRUSTEDGE_AGENT_ACTION_TIMEOUT);
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    action.handler.subtype = TE_ACTION_HANDLER_SUBTYPE_PYTHON3;
    action.pActionPath = "./action_handler/test_script.py";
    action.pActionArgument = NULL;
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);
    pAgentCtx->actionHandlerTimeout = 15;

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    action.pActionPath = "./action_handler/test_script_arg.py";
    action.pActionArgument = "Digicert";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    system("rm -f projects/trustedge/sample/test_data/action_handler/sample_segfault_c_binary || true");
    system("gcc projects/trustedge/sample/test_data/action_handler/sample_segfault_main.c -o projects/trustedge/sample/test_data/action_handler/sample_segfault_c_binary");

    /* test a binary that crashes : ERROR: action exited abnormally */
    action.type = TE_ACTION_INSTALL;
    action.handler.type = TE_ACTION_HANDLER_EXE;
    action.handler.subtype = TE_ACTION_HANDLER_SUBTYPE_UNKNOWN;
    action.pActionPath = "./action_handler/sample_segfault_c_binary";
    action.pActionArgument = TRUSTEDGE_utilsCloneString(" arg1 arg2 arg3   arg4   ");
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    status = TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, TRUE, OK != status ? TRUE : FALSE);
    TRUSTEDGE_actionHandlerDeleteArgs(&action);
    DIGI_FREE((void **) &action.pActionArgument);

    system("rm -f projects/trustedge/sample/test_data/action_handler/sample_c_binary || true");
    system("gcc projects/trustedge/sample/test_data/action_handler/sample_main.c -o projects/trustedge/sample/test_data/action_handler/sample_c_binary");

    action.type = TE_ACTION_INSTALL;
    action.handler.type = TE_ACTION_HANDLER_EXE;
    action.handler.subtype = TE_ACTION_HANDLER_SUBTYPE_UNKNOWN;
    action.pActionPath = "./action_handler/sample_c_binary";
    action.pActionArgument = NULL;
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    action.pActionArgument = "argument1";
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(&action);

    retVal += UNITTEST_STATUS(__MOC_LINE__, TRUSTEDGE_launchActionHandler (&action, pFilePath, pCtx));
    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    return retVal;
}

int test_all_update_pkg()
{
    int retVal = 0;
    int ret;
    putenv("TRUSTEDGE_CONFIG=./projects/trustedge/sample/trustedge_configuration/trustedge.json");

    ret = test_update_pkg("src/trustedge/test/data/artifact_python/Generic/artifact/artifact_download.mime", TE_ACTION_INSTALL);
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_update_pkg("src/trustedge/test/data/artifact_python/Generic/artifact/artifact_download.mime", TE_ACTION_ROLLBACK);
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_update_pkg("src/trustedge/test/data/artifact_app_deb/artifact/artifact_download.mime", TE_ACTION_INSTALL);
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_update_pkg("src/trustedge/test/data/artifact_app_deb/artifact/artifact_download.mime", TE_ACTION_ROLLBACK);
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    system("rm -f projects/trustedge/sample/conf/applied_policy.json;  cp src/trustedge/test/data/applied_policy.json projects/trustedge/sample/conf/");

    ret = test_update_pkg("src/trustedge/test/data/artifact_python/InstalledDependicies/artifact/artifact_download.mime", TE_ACTION_INSTALL);
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_update_pkg("src/trustedge/test/data/artifact_python/InstalledDependicies/artifact/artifact_download.mime", TE_ACTION_ROLLBACK);
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    /* Negative Test */
    /* retVal += test_update_pkg("src/trustedge/test/data/artifact_python/NotInstalledDependicies/artifact/artifact_download.mime"); */

    system("rm -f projects/trustedge/sample/conf/applied_policy.json");

    return retVal;
}

static int generate_args(
    TrustEdgeAgentActionType type,
    TrustEdgeAgentActionHandlerType handlerType,
    TrustEdgeAgentActionHandlerSubType handlerSubType,
    sbyte *pActionPath,
    sbyte *pActionArgument)

{
    int ret;
    TrustEdgeArtifactAction action = { 0 };

    action.type = type;
    action.handler.type = handlerType;
    action.handler.subtype = handlerSubType;
    action.pActionPath = TRUSTEDGE_utilsCloneString(pActionPath);
    action.pActionArgument = TRUSTEDGE_utilsCloneString(pActionArgument);
    action.ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs (&action);

    ret = (NULL == action.ppActionArgs) ? 1 : 0; /* error if no args generated */

    TRUSTEDGE_actionHandlerDeleteArgs(&action);

    DIGI_FREE((void **) &(action.pActionPath));
    DIGI_FREE((void **) &(action.pActionArgument));

    return ret;
}

static int test_generate_executable_args()
{
    int retVal = 0;

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        NULL,
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        "./action_handler/script.sh",
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        "./action_handler/script.sh",
        ""));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        "./action_handler/script.sh",
        " x y z "));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        NULL,
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        "./action_handler/rollback_script.sh",
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        "./action_handler/rollback_script.sh",
        ""));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_EXE,
        TE_ACTION_HANDLER_SUBTYPE_UNKNOWN,
        "./action_handler/rollback_script.sh",
        " x y z "));

    return retVal;
}

static int test_generate_script_args()
{
    int retVal = 0;

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        NULL,
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        "./action_handler/script.sh",
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        "./action_handler/script.sh",
        ""));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        "./action_handler/script.sh",
        " a b c "));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        NULL,
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        "./action_handler/rollback_script.sh",
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        "./action_handler/rollback_script.sh",
        ""));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_SCRIPT,
        TE_ACTION_HANDLER_SUBTYPE_BASH,
        "./action_handler/rollback_script.sh",
        " a b c "));

    return retVal;
}

static int test_generate_deb_args()
{
    int retVal = 0;

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        NULL,
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        "./action_handler/digicertdemopkg.deb",
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        "./action_handler/digicertdemopkg.deb",
        ""));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_INSTALL,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        "./action_handler/digicertdemopkg.deb",
        " a  b c    d e    "));

    /* rollback */

    /* negative test : ERROR: action type rollback for handler type pkgmngr requires package name */
    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        NULL,
        NULL));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        NULL,
        "digicert-demo-package"));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        NULL,
        "digicert-demo-package a b d f"));

    retVal += UNITTEST_STATUS(__MOC_LINE__, generate_args(
        TE_ACTION_ROLLBACK,
        TE_ACTION_HANDLER_PKG_MGR_TYPE,
        TE_ACTION_HANDLER_SUBTYPE_DPKG,
        NULL,
        "  digicert-demo-package   "));

    return retVal;
}

static int test_all_arg_types()
{
    int ret;

    ret  = test_generate_deb_args();
    ret += test_generate_script_args();
    ret += test_generate_executable_args();

    return ret;
}

int main(int argc, char *ppArgv[])
{
    MOC_UNUSED(argc);
    MOC_UNUSED(ppArgv);
    int retVal = 0;
    int ret;

    DIGICERT_initDigicert();
    MSG_LOG_init(MSG_LOG_ERROR);

    putenv("TRUSTEDGE_CONFIG=./projects/trustedge/sample/trustedge_configuration/trustedge.json");

    if (0 == geteuid())
    {
        /* only run these tests if running in sudo */
        ret = test_all_update_pkg();
        retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

        ret = test_deb_pkg();
        retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);
    }

    ret = test_extract_api("./src/trustedge/test/data/test.zip", "./bin/trustedge_testing");
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_artifact_linked_list();
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_manifest_parsing();
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_compute_digest_apis();
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_all_arg_types();
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    ret = test_launch_process();
    retVal += UNITTEST_INT(__MOC_LINE__, ret, 0);

    MSG_LOG_uninit();
    DIGICERT_freeDigicert();

    return retVal;
}
