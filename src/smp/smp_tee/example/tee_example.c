/*
 * tee_example.c
 *
 * example for tee smp with TAP local or remote.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */
#include "../../../tap/tap.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"
#include "../../../tap/tap_utils.h"
#include "../../../smp/smp_tee/smp_tap_tee.h"

#include <stdio.h>

#ifdef __ENABLE_TAP_REMOTE__

#include "../../../tap/tap_conf_common.h"

#ifndef TAP_SERVER_NAME
#define TAP_SERVER_NAME "127.0.0.1"
#endif

#ifndef TAP_SERVER_PORT
#define TAP_SERVER_PORT 8277
#endif

#else

#ifndef TEE_CONFIG_PATH
#define TEE_CONFIG_PATH "/etc/mocana/tee_smp.conf"
#endif

#endif /* __ENABLE_TAP_REMOTE__ */

/* SAMPLE KEY in PEM form. In practice data we can store can be in any form. */
char *gpKey =
"-----BEGIN PRIVATE KEY-----\n"
"MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgmeRvfl5ovFn3KrWA"
"dIpMEyb/AdgnCgb4hmU9omDVpU+gCgYIKoZIzj0DAQehRANCAAQY1oB9PvS4p0wq"
"lQ8yjBcQ2r+CJXrUZ8TftvIkoBQ9nVCNYrQzxYynmecrtwYJLTqMUJyNspjtKCoX"
"HY18i2D9\n-----END PRIVATE KEY-----\n";

/* SAMPLE KEY HANDLE or identifier for the key */
char *gpKeyHandle =
"MY_ECDSA_P256_KEY";

/* Global error context used for all TAP steps */
TAP_ErrorContext gErrContext = {0};

/* -------------------------------------------------------------------------- */

static MSTATUS secure_storage_example(TAP_Context *pTapContext)
{
    MSTATUS status = OK;

    /* Compare for testing that the retrieved data matches the original */
    sbyte4 cmp = -1;

    /* The data handle (ie Key Handle in our case), and sometimes the token, (ie the
     * TA being used for secure storage) will need to be set as a TAP_Attribute. */
    TAP_AttributeList attributes = {0};

    /* Setting and Getting data will require a TAP_ObjectInfo instance */
    TAP_ObjectInfo objInfo = {0};

    /* Deleting data will require a TAP_StorageInfo instance */
    TAP_StorageInfo storageInfo = {0};

    /* The TA (trusted application) being accessed */
    ubyte4 tokenId = TEE_SECURE_STORAGE;

    /* Buffer for data Handle */
    TAP_Buffer handleIdBuf = {0};

    /* Buffer for inputing the data */
    TAP_Buffer dataBuf = {0};

    /* Buffer for the retrieved data */
    TAP_Buffer recData = {0};

    /* Set the buffer for the input data and its handle */
    dataBuf.pBuffer = (ubyte *) gpKey;
    dataBuf.bufferLen = DIGI_STRLEN((sbyte *) gpKey);

    handleIdBuf.pBuffer = (ubyte *) gpKeyHandle;
    handleIdBuf.bufferLen = DIGI_STRLEN((sbyte *) gpKeyHandle);

    /* We put both the handleIdBuf and tokenId as attibutes since we are doing all
     * three operations, set, get, and delete. We allocate a list of length 2.
     * If only doing set or get operations then you only need the first attribute 
     * and a list of length one would suffice. */
    status = DIGI_MALLOC((void **) &attributes.pAttributeList, 2 * sizeof(TAP_Attribute));
    if (OK != status)
        goto exit;

    attributes.pAttributeList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    attributes.pAttributeList[0].length = sizeof(handleIdBuf);
    attributes.pAttributeList[0].pStructOfType = (void *)&handleIdBuf;

    attributes.pAttributeList[1].type = TAP_ATTR_TOKEN_TYPE;
    attributes.pAttributeList[1].length = sizeof(ubyte4);
    attributes.pAttributeList[1].pStructOfType = (void *)&tokenId;

    attributes.listLen = 2;

    /* Store the list in the objInfo object too, and for get and set operations
     * we can truncate to the first item in the list as already mentioned
     * (ie set objInfo.objectAttributes.listLen = 1)
     */
    objInfo.objectAttributes.pAttributeList = attributes.pAttributeList;
    objInfo.objectAttributes.listLen = 1;
    objInfo.tokenId = tokenId;
    objInfo.providerType = TAP_PROVIDER_TEE; /* ok to set this but not needed */
  
    /* Now we're ready to store the data in secure storage */
    status = TAP_setPolicyStorage(pTapContext, NULL, &objInfo, NULL, &dataBuf, &gErrContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* Let's retieve the data now, on error we goto a different exit block so that 
     * we can cleanup the stored data correctly */
    status = TAP_getPolicyStorage(pTapContext, NULL, &objInfo, NULL, &recData, &gErrContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit1;
    }

    /* Now validate we got back the same data that we stored */
    if (recData.bufferLen != dataBuf.bufferLen)
    {
        printf("ERROR: line = %d, recData.bufferLen = %d, dataBuf.bufferLen = %d\n", __LINE__,
           recData.bufferLen, dataBuf.bufferLen);
        goto exit1;
    }

    status = DIGI_MEMCMP(recData.pBuffer, dataBuf.pBuffer, dataBuf.bufferLen, &cmp);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit1;
    }

    if (cmp)
    {
        printf("ERROR: line = %d, cmp = %d\n", __LINE__, cmp);
    }

exit1:

    /* Now we delete the data from secure storage, we use the storageInfo object in this case
     * We add the attribute list as it originally was with both items, ie attributes.listLen 
     * still has a value of 2.
     */
    storageInfo.pAttributes = &attributes;
    status = TAP_freePolicyStorage(pTapContext, NULL, &storageInfo, &gErrContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
    }

exit:

    /* The GET operation allocated a new buffer for the received data, we must clean it up */
    if (NULL != recData.pBuffer)
    {
        (void) DIGI_FREE((void **) &recData.pBuffer);
    }

    /* And of course cleanup the attribute list we allocated */
    if (NULL != attributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &attributes.pAttributeList);
    }

    if (OK == status)
    {
        printf("Secure Storage Example completed successfully.\n");
    }
    /* else error already printed */

    return status;
}

/* -------------------------------------------------------------------------- */

static MSTATUS tap_init_example(TAP_Context **ppNewTapContext)
{
    MSTATUS status = OK;

    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ConfigInfo config = {0};
    TAP_ConfigInfoList configInfoList = {0,};
    
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

    config.provider = TAP_PROVIDER_TEE;
    configInfoList.count = 1;
    configInfoList.pConfig = &config;

#ifndef __ENABLE_TAP_REMOTE__

    /* For TAP local we directly read the config file */
    status = TAP_readConfigFile((char *) TEE_CONFIG_PATH, &configInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
    {
        printf("ERROR: TAP_readConfigFile, line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

#endif /* __ENABLE_TAP_REMOTE__ */

    /* Initialize TAP */
    status = TAP_init(&configInfoList, &gErrContext);
    if (OK != status)
    {
        printf("ERROR: TAP_init, line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* Discover TAP modules */
#ifdef __ENABLE_TAP_REMOTE__

    connInfo.serverName.pBuffer = (ubyte *) TAP_SERVER_NAME;
    connInfo.serverName.bufferLen = DIGI_STRLEN((sbyte *) TAP_SERVER_NAME);
    connInfo.serverPort = TAP_SERVER_PORT;

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TEE, NULL,
            &moduleList, &gErrContext);
#else

    /* We can do this the same way as the TAP REMOTE case except for no connInfo.
     * Alternatively if we already know the module we are using we can just
     * set a TAP_Module variable directly, for example
     *
     * TAP_Module module = {0};
     * module.providerType = TAP_PROVIDER_TEE;
     * module.moduleId = 1;
     */
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TEE, NULL,
            &moduleList, &gErrContext);
#endif
    if (OK != status)
    {
        printf("ERROR: TAP_getModuleList, line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }
  
    if (0 == moduleList.numModules)
    {
        status = ERR_INVALID_INPUT;
        printf("ERROR: No TEE modules found\n");
        goto exit;
    }

    /* Now we create a TapContext. We assume the first module is the one we want.
     * If dealing with multiple modules in the tee_smp.conf file then one would 
     * need to loop through the list and check the id until you find the one you want. 
     * If you're doing TAP LOCAL and set the TAP_Module directly you can just pass
     * a reference to that in the first arg here.
     */
    status = TAP_initContext(&(moduleList.pModuleList[0]), NULL, NULL, &pTapContext, &gErrContext);
    if (OK != status)
    {
        printf("ERROR: TAP_initContext, line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    *ppNewTapContext = pTapContext; pTapContext = NULL;

exit:
 
    /* clean up the configInfo (ok if it's empty as in the TAP remote case) */
    (void) TAP_UTILS_freeBuffer(&(configInfoList.pConfig[0].configInfo));

    /* clean up the module List */
    if (NULL != moduleList.pModuleList)
    {
        (void) TAP_freeModuleList(&moduleList);
    }

    /* pTapContext was created in final step, so even on error no cleanup of it is needed */

    return status;
}

/* -------------------------------------------------------------------------- */

static void tap_uninit_example(TAP_Context **ppTapContext)
{
    if (NULL != *ppTapContext)
        (void) TAP_uninitContext(ppTapContext, &gErrContext);
    
    (void) TAP_uninit(&gErrContext);
}

/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    int retVal = 0;
    MSTATUS status = OK;

    TAP_Context *pTapContext = NULL;

    /* Initialize TAP and get the context */
    status = tap_init_example(&pTapContext);
    if (OK != status)
        goto exit;  /* error already printed */

    /* Run the secure storage example */
    status = secure_storage_example(pTapContext);
    
exit:

    /* Cleanup and uninitialize TAP */
    tap_uninit_example(&pTapContext);

    if (OK != status)
        retVal = 1;

    return retVal;
}
