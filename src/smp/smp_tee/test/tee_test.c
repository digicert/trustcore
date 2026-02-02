/*
 * tee_test.c
 *
 * test for tee smp
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

#define __ENABLE_DIGICERT_TAP__
#define __ENABLE_DIGICERT_CRYPTO_INTERFACE__

#include "../../../common/initmocana.h"
#include "../../../crypto/mocasym.h"
#include "../../../crypto/pubcrypto.h"
#include "../../../crypto_interface/cryptointerface.h"

#include "../../../tap/tap.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"
#include "../../../tap/tap_utils.h"
#include "../../../smp/smp_tee/smp_tap_tee.h"

#include <stdio.h>

#ifndef TEE_CONFIG_PATH
#define TEE_CONFIG_PATH "/etc/mocana/tee_smp.conf"
#endif

char *gpKey =
"-----BEGIN PRIVATE KEY-----\n"
"MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgmeRvfl5ovFn3KrWA"
"dIpMEyb/AdgnCgb4hmU9omDVpU+gCgYIKoZIzj0DAQehRANCAAQY1oB9PvS4p0wq"
"lQ8yjBcQ2r+CJXrUZ8TftvIkoBQ9nVCNYrQzxYynmecrtwYJLTqMUJyNspjtKCoX"
"HY18i2D9\n-----END PRIVATE KEY-----\n";

static TAP_Context *gpTapCtx = NULL;

static MSTATUS TAP_EXAMPLE_getCtx(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext)
{
    if (1 == getContext)
    {
        *ppTapCtx = gpTapCtx;
    }
    else
    {
        *ppTapCtx = NULL;
    }

    return OK;
}

static int single_test(void)
{
    MSTATUS status = OK;
    sbyte4 cmp = -1;

    TAP_ErrorContext errContext = {0};
    TAP_AttributeList attributes = {0};
    TAP_ObjectInfo objInfo = {0};
    TAP_StorageInfo storageInfo = {0};

    ubyte4 tokenId = TEE_SECURE_STORAGE;

    char *pId = "myObjectId";
    TAP_Buffer idBuf = {0};

    TAP_Buffer dataBuf = {0};
    TAP_Buffer recData = {0};

    ubyte pData[24] = {0xde, 0xca, 0xf, 0xc0, 0xff, 0xee, 0xde, 0xad, 0xc0, 0xde, 0xbe, 0xef,
                       0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33 };

    dataBuf.pBuffer = pData;
    dataBuf.bufferLen = 24;

    idBuf.pBuffer = (ubyte *) pId;
    idBuf.bufferLen = 10; /* DIGI_STRLEN(pId) */

    /* We set the object Id as an attribute and for the TAP_freePolicyStorage API we need the tokenId too */
    status = DIGI_MALLOC((void **) &attributes.pAttributeList, 2 * sizeof(TAP_Attribute));
    if (OK != status)
        goto exit;

    attributes.pAttributeList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    attributes.pAttributeList[0].length = sizeof(idBuf);
    attributes.pAttributeList[0].pStructOfType = (void *)&idBuf;

    attributes.pAttributeList[1].type = TAP_ATTR_TOKEN_TYPE;
    attributes.pAttributeList[1].length = sizeof(ubyte4);
    attributes.pAttributeList[1].pStructOfType = (void *)&tokenId;

    attributes.listLen = 2;

    /* we just need the objectId attribute for set/getPolicy storage */
    objInfo.objectAttributes.pAttributeList = attributes.pAttributeList;
    objInfo.objectAttributes.listLen = 1;
    objInfo.tokenId = tokenId;
    objInfo.providerType = TAP_PROVIDER_TEE; /* ok to set this but not needed */
  
    status = TAP_setPolicyStorage(gpTapCtx, NULL, &objInfo, NULL, &dataBuf, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    status = TAP_getPolicyStorage(gpTapCtx, NULL, &objInfo, NULL, &recData, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit1;
    }

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

    storageInfo.pAttributes = &attributes;
    status = TAP_freePolicyStorage(gpTapCtx, NULL, &storageInfo, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
    }

exit:

    if (NULL != recData.pBuffer)
    {
        (void) DIGI_FREE((void **) &recData.pBuffer);
    }

    if (NULL != attributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &attributes.pAttributeList);
    }

    if (OK == status)
    {
        printf("Single test completed successfully\n");
        return 0;
    }
    return 1;
}

static int serialize_test(void)
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};

    ubyte *pPem = NULL;
    ubyte4 pemLen = 0;

    ubyte *pDer = NULL;
    ubyte4 derLen = 0;

    AsymmetricKey asymKeyOutPem = {0};
    AsymmetricKey asymKeyOutDer = {0};

    char pId[4] = {'m', 'y', 'I', 'd'};
    char pId2[4] = {'d', 'e', 'r', '2'};
    ubyte4 idLen = 4;

    /* For now need to also delete the data from storage, might have a crypto API to do this eventually */
    TAP_ErrorContext errContext = {0};
    TAP_AttributeList attributes = {0};
    TAP_StorageInfo storageInfo = {0};
    TAP_Buffer idBuf = {0};
    ubyte4 tokenId = TEE_SECURE_STORAGE;

#ifndef __DISABLE_TEE_TEST_OUTPUT__
    sbyte4 i = 0;
#endif

    status = CRYPTO_deserializeAsymKey (gpKey, DIGI_STRLEN(gpKey), NULL, &asymKey);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    status = CRYPTO_serializeAsymKeyToStorage (&asymKey, privateKeyPem, (ubyte *) pId, idLen, TEE_SECURE_STORAGE, &pPem, &pemLen);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* use a different ID to test calling the API to give back DER */
    status = CRYPTO_serializeAsymKeyToStorage (&asymKey, privateKeyInfoDer, (ubyte *) pId2, idLen, TEE_SECURE_STORAGE, &pDer, &derLen);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit1;
    }

#ifndef __DISABLE_TEE_TEST_OUTPUT__
    /* print out keys so we can visually check the formatting */
    printf("PEM KEY =\n%s\n", pPem);
    printf("DER KEY =\n");
    for (i = 0; i < derLen; i++)
    {
        printf("%02x", pDer[i]);
    }
    printf("\n\n");
#endif

    /* make sure each key can deserialize ok */
    status = CRYPTO_deserializeAsymKey (pPem, pemLen, NULL, &asymKeyOutPem);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit1;
    }

    status = CRYPTO_deserializeAsymKey (pDer, derLen, NULL, &asymKeyOutDer);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
    }

exit1:

    /* We set the object Id as an attribute and for the TAP_freePolicyStorage API we need the tokenId too */
    idBuf.pBuffer = (ubyte *) pId;
    idBuf.bufferLen = idLen;

    status = DIGI_MALLOC((void **) &attributes.pAttributeList, 2 * sizeof(TAP_Attribute));
    if (OK != status)
        goto exit;

    attributes.pAttributeList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    attributes.pAttributeList[0].length = sizeof(idBuf);
    attributes.pAttributeList[0].pStructOfType = (void *)&idBuf;

    attributes.pAttributeList[1].type = TAP_ATTR_TOKEN_TYPE;
    attributes.pAttributeList[1].length = sizeof(ubyte4);
    attributes.pAttributeList[1].pStructOfType = (void *)&tokenId;

    attributes.listLen = 2;

    storageInfo.pAttributes = &attributes;
    status = TAP_freePolicyStorage(gpTapCtx, NULL, &storageInfo, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        /* keep going */
    }

    idBuf.pBuffer = (ubyte *) pId2;
    status = TAP_freePolicyStorage(gpTapCtx, NULL, &storageInfo, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
    }

exit:

    if (NULL != pDer)
    {
        (void) DIGI_FREE((void **) &pDer);
    }

    if (NULL != pPem)
    {
        (void) DIGI_FREE((void **) &pPem);
    }

    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&asymKeyOutDer, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&asymKeyOutPem, NULL);
    
    if (NULL != attributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &attributes.pAttributeList);
    }

    if (OK == status)
    {
        printf("Serialize test completed successfully\n");
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[])
{
    int ret = 0;

    MSTATUS status = OK;

    TAP_Module module = {0};
    TAP_ConfigInfo config = {0};
    TAP_ConfigInfoList configInfoList = {0,};
    TAP_ErrorContext errContext = {0};

    config.provider = TAP_PROVIDER_TEE;
    configInfoList.count = 1;
    configInfoList.pConfig = &config;

    module.providerType = TAP_PROVIDER_TEE;
    module.moduleId = 1;

    /* We set up TAP for both tests */
    status = TAP_readConfigFile((char *) TEE_CONFIG_PATH, &configInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
        goto exit;

    status = TAP_init(&configInfoList, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    status = TAP_initContext(&module, NULL, NULL, &gpTapCtx, &errContext);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    status = CRYPTO_INTERFACE_registerTapCtxCallback(TAP_EXAMPLE_getCtx);
    if (OK != status)
    {
        printf("ERROR: line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    ret += single_test();
    ret += serialize_test();

exit:
    
    if (OK != status)
        ret++;

    (void) TAP_uninitContext(&gpTapCtx, &errContext);
    (void) TAP_uninit(&errContext);

    return ret;
}
