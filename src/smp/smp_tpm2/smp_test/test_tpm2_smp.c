/*
 * test_tpm2_smp_bin.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 * @file       test_tpm2_smp_bin.c
 * @brief      Unit test application for TPM2 SMP APIs
 * @details    Unit test application for TPM2 SMP APIs
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/mstdlib.h"
#include "../../../common/debug_console.h"
#include "../../smp.h"
#include "../../smp_interface.h"
#include "../smp_tpm2_api.h"
#include "../smp_tpm2_interface.h"
#include "../smp_tap_tpm2.h"
#include "../tpm2_lib/tools/tpm2_server_helpers.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#else
#include "tpm2_test_utils.h"
#endif

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../../../common/tpm2_path.h"
#endif

#if defined(__RTOS_WIN32__)
#include "../../../common/mcmdline.h"
#endif

#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
static TAP_ErrorAttributes *pErrorRules = NULL;
static TAP_ErrorAttributes **ppErrAttrReturned = NULL;
#endif
/*-----------------------------------------------------------------------------------*/
static
byteBoolean isFunctionalitySupported(TAP_CmdCodeList *pSupportedOpCodes, ubyte2 opCode);

static
MSTATUS createAsymmetricKey(TAP_CmdCodeList *pSupportedOpCodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
                     TAP_ObjectId objectId, TAP_KeyAttributes *pKeyAttr, byteBoolean keyInitFlag, TAP_ObjectId *pKeyObjectId, 
                     TAP_ObjectAttributes *pCreatedKeyAttr, TAP_ObjectHandle *pKeyHandle);

MSTATUS signBuffer(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectHandle keyHandle, 
        TAP_SIG_SCHEME sigScheme, 
        TAP_Buffer *pCsrRequest, TAP_Signature **ppSignature);

static
MSTATUS createSymmetricKey(TAP_CmdCodeList *pSupportedOpCodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
                     TAP_ObjectId objectId, TAP_KeyAttributes *pKeyAttr, byteBoolean keyInitFlag, TAP_ObjectId *pKeyObjectId, 
                     TAP_ObjectAttributes *pCreatedKeyAttr, TAP_ObjectHandle *pKeyHandle);

static 
MSTATUS initModule(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleId moduleId, TAP_ModuleHandle *pModuleHandle);

static 
MSTATUS getPublicKey(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
        TAP_ObjectHandle keyHandle, TAP_PublicKey **pPublicKey);

MSTATUS associateObjectCredentials(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
    TAP_ObjectHandle objectHandle, TAP_EntityCredentialList *pCredentialsList);

static 
MSTATUS initObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials, 
        TAP_ObjectHandle *pObjectHandle, TAP_ObjectId *pObjectIdOut);

static 
MSTATUS createObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials, 
        TAP_ObjectHandle *pObjectHandle, TAP_ObjectId *pObjectIdOut);

static 
MSTATUS uninitObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectHandle objectHandle);

static 
MSTATUS uninitModule(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle);


static 
MSTATUS exportObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
        TAP_ObjectHandle keyHandle, TAP_Blob *pBlob);


static 
MSTATUS importObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
        TAP_Blob *pBlob, TAP_ObjectCapabilityAttributes *pObjectAttributes, TAP_EntityCredentialList *pCredentials, 
        TAP_ObjectHandle *pObjectHandle);


static
MSTATUS getTrustedData(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle,
                       TAP_TRUSTED_DATA_TYPE trustedDataType, TAP_TrustedDataInfo *pTrustedDataInfo, TAP_Buffer *pPcrData);


static 
MSTATUS freeModuleList(TAP_CmdCodeList *pSupportedOpcodes, TAP_EntityList *pModuleList);

/*-----------------------------------------------------------------------------------*/

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define TPM2_DEBUG_PRINT_NO_ARGS(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define LOG_MESSAGE(fmt, ...) \
    do {\
        printf(fmt"\n", ##__VA_ARGS__);\
    } while (0)

#define LOG_MESSAGE_NONL(fmt, ...) \
    do {\
        printf(fmt, ##__VA_ARGS__);\
    } while (0)

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

typedef struct {
    byteBoolean exitAfterParse;

} cmdLineOpts;

typedef struct
{
    TAP_KEY_ALGORITHM keyAlgorithm;
    TAP_KEY_USAGE keyUsage;
    TAP_KEY_SIZE keySize;
    TAP_ENC_SCHEME encScheme;
    TAP_SIG_SCHEME sigScheme;
    TAP_ECC_CURVE eccCurve;
} KEY_INFO;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("test_smp: Help Menu\n");
    LOG_MESSAGE("This tests SMP APIs.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [Display command line options]");
    LOG_MESSAGE("                   Help menu\n");
    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] = {
            {"h", no_argument, NULL, 1},
            {NULL, 0, NULL, 0},
    };

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameters.");
        goto exit;
    }

    while (TRUE)
    {
        c = getopt_long(argc, argv, optstring, options, &options_index);
        if ((-1 == c))
            break;

        switch (c)
        {
        case 1:
            printHelp();
            pOpts->exitAfterParse = TRUE;
            break;

        default:
            goto exit;
            break;
        }
    }
    retval = 0;
exit:
    return retval;
}
#endif

MSTATUS getKeyInfo(TAP_ObjectAttributes *pCreatedKeyAttrList, KEY_INFO *pKeyInfo)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    TAP_Attribute *pCreatedKeyAttr = NULL;

    if (NULL == pCreatedKeyAttrList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
   
    DIGI_MEMSET((ubyte *)pKeyInfo, 0, sizeof(*pKeyInfo));

    for(count = 0; count < pCreatedKeyAttrList->listLen; count++)
    {
        pCreatedKeyAttr = &pCreatedKeyAttrList->pAttributeList[count];
        switch (pCreatedKeyAttr->type)
        {
            case TAP_ATTR_KEY_ALGORITHM:
                if (sizeof (pKeyInfo->keyAlgorithm) == pCreatedKeyAttr->length)
                {
                    status = DIGI_MEMCPY((ubyte *)&pKeyInfo->keyAlgorithm,
                            pCreatedKeyAttr->pStructOfType, 
                            sizeof(pKeyInfo->keyAlgorithm));
                    if (OK != status)
                    {
                        LOG_ERROR("Error copying key algorithm attribute");
                        goto exit;
                    }
                }
                break;

            case TAP_ATTR_KEY_SIZE:
                if (sizeof (pKeyInfo->keySize) == pCreatedKeyAttr->length)
                {
                    status = DIGI_MEMCPY((ubyte *)&pKeyInfo->keySize,
                            pCreatedKeyAttr->pStructOfType, 
                            sizeof(pKeyInfo->keySize));
                    if (OK != status)
                    {
                        LOG_ERROR("Error copying key size attribute");
                        goto exit;
                    }
                }
                break;

            case TAP_ATTR_KEY_USAGE:
                if (sizeof (pKeyInfo->keyUsage) == pCreatedKeyAttr->length)
                {
                    status = DIGI_MEMCPY((ubyte *)&pKeyInfo->keyUsage,
                            pCreatedKeyAttr->pStructOfType, 
                            sizeof(pKeyInfo->keyUsage));
                    if (OK != status)
                    {
                        LOG_ERROR("Error copying key usage attribute");
                        goto exit;
                    }
                }
                break;

            case TAP_ATTR_ENC_SCHEME:
                if (sizeof (pKeyInfo->encScheme) == pCreatedKeyAttr->length)
                {
                    status = DIGI_MEMCPY((ubyte *)&pKeyInfo->encScheme,
                            pCreatedKeyAttr->pStructOfType, 
                            sizeof(pKeyInfo->encScheme));
                    if (OK != status)
                    {
                        LOG_ERROR("Error copying encryption scheme attribute");
                        goto exit;
                    }
                }
                break;

            case TAP_ATTR_SIG_SCHEME:
                if (sizeof (pKeyInfo->sigScheme) == pCreatedKeyAttr->length)
                {
                    status = DIGI_MEMCPY((ubyte *)&pKeyInfo->sigScheme,
                            pCreatedKeyAttr->pStructOfType, 
                            sizeof(pKeyInfo->sigScheme));
                    if (OK != status)
                    {
                        LOG_ERROR("Error copying signing scheme attribute");
                        goto exit;
                    }
                }
                break;

            case TAP_ATTR_CURVE:
                if (sizeof (pKeyInfo->eccCurve) == pCreatedKeyAttr->length)
                {
                    status = DIGI_MEMCPY((ubyte *)&pKeyInfo->eccCurve,
                            pCreatedKeyAttr->pStructOfType, 
                            sizeof(pKeyInfo->eccCurve));
                    if (OK != status)
                    {
                        LOG_ERROR("Error copying eccCurve ID attribute");
                        goto exit;
                    }
                }
                break;

            default:
                break;
        }

        pCreatedKeyAttr++;
    }

exit:

    return status;
}

static
MSTATUS getTrustedData(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle,
                       TAP_TRUSTED_DATA_TYPE trustedDataType, TAP_TrustedDataInfo *pTrustedDataInfo, TAP_Buffer *pPcrData)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality getTrustedData is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_TRUSTED_DATA))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getTrustData Not supported");
        goto exit;
    }
    /*Call to getTrustedData through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_TRUSTED_DATA;
    cmdReq.reqParams.getTrustedData.moduleHandle = moduleHandle;
    cmdReq.reqParams.getTrustedData.tokenHandle = tokenHandle;
    cmdReq.reqParams.getTrustedData.trustedDataType = trustedDataType;
    cmdReq.reqParams.getTrustedData.pTrustedDataInfo = pTrustedDataInfo;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_getTrustedData failed with error %d\n", status);
        goto exit;
    }
    *pPcrData = cmdRsp.rspParams.getTrustedData.dataValue;

exit:

    return status;
}

MSTATUS doPolicyStorage(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle,
    TAP_ObjectHandle objectHandle, TAP_EntityCredentialList *pCredentialList,
    ubyte *pBuffer, ubyte4 bufferLen, byteBoolean writeOp)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    ubyte2 opCode = SMP_CC_GET_POLICY_STORAGE;
    TAP_Buffer pInput = {0};
    static ubyte writeOper = 1;
    static ubyte readOper = 1;
    static TAP_Attribute writeOpAttribute[] = {
        {TAP_ATTR_WRITE_OP, sizeof(writeOper), &writeOper}
    };
    static TAP_OperationAttributes writeOpAttributeList = {
        sizeof(writeOpAttribute) / sizeof(TAP_Attribute), writeOpAttribute
    };
    static TAP_Attribute readOpAttribute[] = {
        {TAP_ATTR_READ_OP, sizeof(readOper), &readOper}
    };
    static TAP_OperationAttributes readOpAttributeList = {
        sizeof(readOpAttribute) / sizeof(TAP_Attribute), readOpAttribute
    };

    opCode = writeOp ? SMP_CC_SET_POLICY_STORAGE : SMP_CC_GET_POLICY_STORAGE;
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, opCode))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 %s Not supported", writeOp ? "SetPolicyStorage" : 
                "GetPolicyStorage");
        goto exit;
    }

	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = opCode;
    if (writeOp)
    {
        pInput.pBuffer = pBuffer;
        pInput.bufferLen = bufferLen;
        cmdReq.reqParams.setPolicyStorage.moduleHandle = moduleHandle;
        cmdReq.reqParams.setPolicyStorage.tokenHandle = tokenHandle;
        cmdReq.reqParams.setPolicyStorage.objectHandle = objectHandle;
        cmdReq.reqParams.setPolicyStorage.pPolicyAttributes = NULL;
        cmdReq.reqParams.setPolicyStorage.pOpAttributes = &writeOpAttributeList;
        cmdReq.reqParams.setPolicyStorage.pData = &pInput;
    }
    else
    {
        cmdReq.reqParams.getPolicyStorage.moduleHandle = moduleHandle;
        cmdReq.reqParams.getPolicyStorage.tokenHandle = tokenHandle;
        cmdReq.reqParams.getPolicyStorage.objectHandle = objectHandle;
        cmdReq.reqParams.getPolicyStorage.pOpAttributes = &readOpAttributeList;
    }
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
            , NULL
            , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 %s failed with error %d", writeOp ? "SetPolicyStorage" :
                "GetPolicyStorage", status);
        goto exit;
    }

    if (!writeOp)
    {
        status = DIGI_MEMCPY(pBuffer, cmdRsp.rspParams.getPolicyStorage.data.pBuffer, 
                cmdRsp.rspParams.getPolicyStorage.data.bufferLen);
        if (OK != status)
        {
            LOG_ERROR("Error copying GetPolicy response buffer, status %d", 
                    status);
            goto exit;
        }
    }

exit:
    if (FALSE == writeOp && NULL != cmdRsp.rspParams.getPolicyStorage.data.pBuffer)
    {
        DIGI_FREE((void **) &(cmdRsp.rspParams.getPolicyStorage.data.pBuffer));
    }
    return status;
}


MSTATUS deleteObject(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle,
    TAP_ObjectHandle objectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* DeleteObject */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_DELETE_OBJECT))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 deleteObject Not supported");
        goto exit;
    }

    /*Call to deleteObject through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_DELETE_OBJECT;
    cmdReq.reqParams.deleteObject.moduleHandle = moduleHandle;
    cmdReq.reqParams.deleteObject.tokenHandle = tokenHandle;
    cmdReq.reqParams.deleteObject.objectHandle = objectHandle;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 deleteObject failed with error %d", status);
        goto exit;
    }

exit:
    return status;
}

MSTATUS freeSignature(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_Signature **ppSignature)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* freePublicKey */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_FREE_SIGNATURE_BUFFER))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 free signature buffer not supported");
        goto exit;
    }

    /*Call to freepublickey through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_FREE_SIGNATURE_BUFFER;
    cmdReq.reqParams.freeSignature.ppSignature = ppSignature;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 free signature buffer failed with error %d", status);
        goto exit;
    }

exit:
    return status;
}

MSTATUS freePublicKey(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_PublicKey **ppPublicKey)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* freePublicKey */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_FREE_PUBLIC_KEY))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 free public key Not supported");
        goto exit;
    }

    /*Call to freepublickey through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_FREE_PUBLIC_KEY;
    cmdReq.reqParams.freePublicKey.ppPublicKey = ppPublicKey;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 freePublicKey failed with error %d", status);
        goto exit;
    }

exit:
    return status;
}

MSTATUS unwrapKeyValidatedSecret(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
    TAP_ObjectHandle objectHandle, TAP_ObjectHandle rtKeyHandle,
    TAP_Blob *pBlob, TAP_Buffer *pSecret)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* unwrapKeyValidatedSecret */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_UNWRAP_KEY_VALIDATED_SECRET))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getRootOfTrustCertificate Not supported");
        goto exit;
    }

    /*Call to unwrapKeyValidatedSecret through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_UNWRAP_KEY_VALIDATED_SECRET;
    cmdReq.reqParams.unwrapKeyValidatedSecret.moduleHandle = moduleHandle;
    cmdReq.reqParams.unwrapKeyValidatedSecret.tokenHandle = tokenHandle;
    cmdReq.reqParams.unwrapKeyValidatedSecret.objectHandle = objectHandle;
    cmdReq.reqParams.unwrapKeyValidatedSecret.rtKeyHandle = rtKeyHandle;
    cmdReq.reqParams.unwrapKeyValidatedSecret.pBlob = pBlob;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 unwrapKeyValidatedSecret failed with error %d", status);
        goto exit;
    }

    *pSecret = cmdRsp.rspParams.unwrapKeyValidatedSecret.secret;

exit:
    if (NULL != pSecret->pBuffer)
    {
        if (OK != DIGI_FREE((void **) &pSecret->pBuffer));
    }

    return status;
}

MSTATUS getCertificateRequestValidationAttrs(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
    TAP_ObjectHandle objectHandle, TAP_CSRAttributes *pCSRattributes, 
    TAP_Blob *pExtendedCert)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* getCertificateRequestValidationAttrs */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getRootOfTrustCertificate Not supported");
        goto exit;
    }

    /*Call to getRandom through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS;
    cmdReq.reqParams.getCertReqValAttrs.moduleHandle = moduleHandle;
    cmdReq.reqParams.getCertReqValAttrs.tokenHandle = tokenHandle;
    cmdReq.reqParams.getCertReqValAttrs.objectHandle = objectHandle;
    cmdReq.reqParams.getCertReqValAttrs.pCSRattributes = pCSRattributes;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 getCertificateRequestValidationAttrs failed with error %d", status);
        goto exit;
    }

    *pExtendedCert = cmdRsp.rspParams.getCertReqValAttrs.blob;

exit:
    return status;
}

MSTATUS getRootOfTrustCertificate(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_ObjectId objectId, 
    TAP_ROOT_OF_TRUST_TYPE type, TAP_Blob *pCertificate)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* getRootOfTrustCertificate */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getRootOfTrustCertificate Not supported");
        goto exit;
    }

    /*Call to getRandom through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE;
    cmdReq.reqParams.getRootOfTrustCertificate.moduleHandle = moduleHandle;
    cmdReq.reqParams.getRootOfTrustCertificate.objectId = objectId;
    cmdReq.reqParams.getRootOfTrustCertificate.type = type;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 getRootOfTrustCertificate failed with error %d", status);
        goto exit;
    }
    *pCertificate = cmdRsp.rspParams.getRootOfTrustCertificate.certificate;

exit:
    return status;
}

#define NVRAM_SIZE      64
#define NVRAM_ID        0x01000001

MSTATUS testPolicyStorage(TAP_CmdCodeList *pSupportedOpcodes,
        TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle,
        TAP_ObjectId nvramId, TAP_EntityCredentialList *pCredentialList)
{
    MSTATUS status = OK;
    TAP_ObjectHandle nvHandle = 0;
    TAP_ObjectId nvId = 0;
    static ubyte4 nvSize = NVRAM_SIZE;
    ubyte writeBuf[NVRAM_SIZE] = {0};
    ubyte readBuf[NVRAM_SIZE] = {0};
    static TAP_Attribute nvAttributes [] = {
        {TAP_ATTR_STORAGE_SIZE, sizeof(nvSize), &nvSize}
    };
    static TAP_ObjectAttributes nvAttributeList = {
        sizeof(nvAttributes) / sizeof(TAP_Attribute), nvAttributes
    };
    sbyte4 cmpResult = 1;

    DIGI_MEMSET(writeBuf, 0x55, sizeof(writeBuf));

    /* Create object */
    status = createObject(pSupportedOpcodes, moduleHandle, tokenHandle,
            nvramId, &nvAttributeList, pCredentialList, &nvHandle,
            &nvId);
    if (OK != status)
    {
        LOG_ERROR("NVRAM creation failed, status %d\n", status);
        goto exit;
    }

    /* Must do a write before a read */
    status = doPolicyStorage(pSupportedOpcodes, moduleHandle, tokenHandle,
            nvHandle, pCredentialList, writeBuf, sizeof(writeBuf), 1);
    if (OK != status)
    {
        LOG_ERROR("NVRAM write failed, status %d\n", status);
        goto exit;
    }

    status = doPolicyStorage(pSupportedOpcodes, moduleHandle, tokenHandle,
            nvHandle, pCredentialList, readBuf, sizeof(readBuf), 0);
    if (OK != status)
    {
        LOG_ERROR("NVRAM read failed, status %d\n", status);
        goto exit;
    }

    status = DIGI_MEMCMP(readBuf, writeBuf, sizeof(writeBuf), &cmpResult);
    if (OK != status)
    {
        LOG_ERROR("NVRAM read write buffer compare failed, status %d\n", status);
        goto exit;
    }

    if (cmpResult)
        LOG_ERROR("NVRAM read write buffer compare mismatch\n");
    else
        LOG_MESSAGE("NVRAM Read Write test passed\n");

    /* Delete NVRAM object */
    status = deleteObject(pSupportedOpcodes, moduleHandle, tokenHandle,
            nvHandle);
    if (OK != status)
    {
        LOG_ERROR("NVRAM delete failed, status %d\n", status);
        goto exit;
    }

exit:
    return status;
}


MSTATUS testIdentityKeyGeneration(TAP_CmdCodeList *pSupportedOpcodes, 
        TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle,
        TAP_EntityCredentialList *pCredentialList, ubyte *pSymKeyCredential,
        ubyte4 symKeyCredentialLen)
{
    MSTATUS status = OK;
    sbyte4 cmpResult = 1;
    ubyte4 exponent;
    TAP_Buffer keyCredential = {0};
    TAP_Blob serverWrappedCredential = {0};
    AsymmetricKey asymAKPublicKey = {0};
    AsymmetricKey asymEKPublicKey = {0};
    TAP_PublicKey *pAkPublicKey = NULL;
    TAP_PublicKey *pEkPublicKey = NULL;
    TAP_Buffer secret = {0};
    TAP_Blob extendedCert = {0};
    TAP_ObjectHandle ekHandle = 0;
    TAP_ObjectId aikObjectId = 0;
    TAP_ObjectAttributes createdKey = {0};
    static TAP_KEY_ALGORITHM attrKeyAlg = TAP_KEY_ALGORITHM_RSA;
    static TAP_KEY_USAGE attrKeyUsage = TAP_KEY_USAGE_ATTESTATION;
    static TAP_Attribute akAttr[] = {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(attrKeyAlg), &attrKeyAlg},
        {TAP_ATTR_KEY_USAGE, sizeof(attrKeyUsage), &attrKeyUsage},
    };
    static TAP_KeyAttributes akAttrList = {
        sizeof(akAttr)/sizeof(TAP_Attribute), akAttr
    };
    TAP_ObjectHandle aikHandle = 0;
    TAP_Buffer csrRequest = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5;
    TAP_Signature *pSignature = NULL;
    static TAP_Credential aikCredential = {
        TAP_CREDENTIAL_TYPE_PASSWORD,
        TAP_CREDENTIAL_FORMAT_PLAINTEXT,
        TAP_CREDENTIAL_CONTEXT_ENTITY,
        {0, (ubyte *)""}
    };
    static TAP_EntityCredential aikEntityCredential = {
        0, /* Parent Type */
        0, /* Parent ID */
        TAP_ENTITY_TYPE_OBJECT,
#ifdef USE_INIT_OBJECT
        AIK_OBJECT_ID_START, /* Entity Id */
#else
        0, /* Entity Id */
#endif
        {1, &aikCredential}
    };
    TAP_EntityCredentialList aikEntityCredentialList = {
        1, &aikEntityCredential 
    };
    TAP_ObjectId ekObjectId = EK_OBJECT_ID;
    TAP_Blob ekCertificate = { 0 };

#ifdef USE_INIT_OBJECT
    LOG_MESSAGE("\nTrying AIK key object initialization ... FAPI will create object if necessary");

    status = initObject(pSupportedOpcodes, moduleHandle, tokenHandle,
            AIK_OBJECT_ID_START, 
            NULL, pCredentialList, &aikHandle, &aikObjectId);
    if (OK != status)
#endif
    {
#ifdef USE_INIT_OBJECT
        LOG_MESSAGE("\nInit AIK key failed ... creating AIK key");
#else
        LOG_MESSAGE("\nCreating AIK key");
#endif
        status = createAsymmetricKey(pSupportedOpcodes, moduleHandle, tokenHandle,
#ifdef USE_INIT_OBJECT
                AIK_OBJECT_ID_START, 
#else
                0,
#endif
                &akAttrList, 0, &aikObjectId, &createdKey, 
                &aikHandle);

        if (OK != status)
        {
            LOG_ERROR("AIK key creation failed, status %d\n", status);
            goto exit;
        }

        LOG_MESSAGE("AIK Key created successfully\n");
    }
#ifdef USE_INIT_OBJECT
    else
        LOG_MESSAGE("AIK Key initialized successfully\n");
#endif
    /* Get AIK public key */
    status = getPublicKey(pSupportedOpcodes, moduleHandle, tokenHandle, 
            aikHandle, &pAkPublicKey);
    if (OK != status)
    {
        LOG_ERROR("getPublicKey failed, status %d\n", status);
        goto exit;
    }

    /* Associate AIK credentials */
    status = associateObjectCredentials(pSupportedOpcodes, moduleHandle, tokenHandle,
            aikHandle, &aikEntityCredentialList);
    if (OK != status)
    {
        LOG_ERROR("associateObjectCredentials failed, status %d\n", status);
        goto exit;
    }

    /* Generate CSR Request using public key */
    status = signBuffer(pSupportedOpcodes, moduleHandle, tokenHandle,
            aikHandle, sigScheme, &csrRequest, &pSignature);
    if (OK != status)
    {
        LOG_ERROR("signBuffer failed, status %d\n", status);
        goto exit;
    }

    status = getRootOfTrustCertificate(pSupportedOpcodes, moduleHandle,
            ekObjectId, 0, &ekCertificate);
    if (OK != status)
    {
        LOG_ERROR("getRootOfTrustCertificate failed, status %d\n", status);
        goto exit;
    }

    status = getCertificateRequestValidationAttrs(pSupportedOpcodes, moduleHandle,
            tokenHandle, aikHandle, NULL, &extendedCert);
    if (OK != status)
    {
        LOG_ERROR("getCertificateRequestValidationAttrs failed, status %d\n", status);
        goto exit;
    }

    /* Get EK to decode the certificate */
    status = initObject(pSupportedOpcodes, moduleHandle, tokenHandle,
            EK_OBJECT_ID, NULL, pCredentialList, &ekHandle, &ekObjectId);
    if (OK != status)
    {
        LOG_ERROR("initObject failed, status %d\n", status);
        goto exit;
    }

    /* Get EK public key */
    status = getPublicKey(pSupportedOpcodes, moduleHandle, tokenHandle, 
            ekHandle, &pEkPublicKey);
    if (OK != status)
    {
        LOG_ERROR("getPublicKey for EK failed, status %d\n", status);
        goto exit;
    }

    /* Make the keyCredential here on behalf of the server */
    keyCredential.pBuffer = pSymKeyCredential;
    keyCredential.bufferLen = symKeyCredentialLen;

    /* Get AIK and EK Public Key in Asymmetric key format */
    switch (pAkPublicKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            if (OK != (status = CRYPTO_initAsymmetricKey(&asymAKPublicKey)))
            {
                LOG_ERROR("Error %d initializing Asymmetric key\n", status);
                goto exit;
            }

            asymAKPublicKey.type = akt_rsa;

            status = RSA_createKey(&asymAKPublicKey.key.pRSA);
            if (OK != status)
            {
                LOG_ERROR("Error %d creating RSA Asymmetric key\n", status);
                goto exit;
            }

            if (pAkPublicKey->publicKey.rsaKey.exponentLen != sizeof(exponent))
            {
                LOG_ERROR("Mismatched exponent size, keySize %d does not match "
                        "exponent size of %d bytes\n", 
                        (int)pAkPublicKey->publicKey.rsaKey.exponentLen, 
                        (int)sizeof(exponent));
                goto exit;
            }

            exponent = *(ubyte4 *)pAkPublicKey->publicKey.rsaKey.pExponent;

            status = RSA_setPublicKeyParameters(asymAKPublicKey.key.pRSA,
                    exponent,
                    pAkPublicKey->publicKey.rsaKey.pModulus,
                    pAkPublicKey->publicKey.rsaKey.modulusLen, NULL);
            if (OK != status)
            {
                LOG_ERROR("Error %d setting RSA Asymmetric key public parameters\n", status);
                goto exit;
            }
            break;
        case TAP_KEY_ALGORITHM_ECC:
            /* todo */
            break;

        default:
            LOG_ERROR("Unsupported key algorithm %d\n", 
                    (int)pAkPublicKey->keyAlgorithm);
            goto exit;
            break;
    }

    switch (pEkPublicKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            if (OK != (status = CRYPTO_initAsymmetricKey(&asymEKPublicKey)))
            {
                LOG_ERROR("Error %d initializing EK Asymmetric key\n", status);
                goto exit;
            }

            asymEKPublicKey.type = akt_rsa;

            status = RSA_createKey(&asymEKPublicKey.key.pRSA);
            if (OK != status)
            {
                LOG_ERROR("Error %d creating EK RSA Asymmetric key\n", status);
                goto exit;
            }

            if (pEkPublicKey->publicKey.rsaKey.exponentLen != sizeof(exponent))
            {
                LOG_ERROR("Mismatched EK exponent size, keySize %d does not match "
                        "exponent size of %d bytes\n", 
                        (int)pEkPublicKey->publicKey.rsaKey.exponentLen, 
                        (int)sizeof(exponent));
                goto exit;
            }

            exponent = *(ubyte4 *)pEkPublicKey->publicKey.rsaKey.pExponent;

            status = RSA_setPublicKeyParameters(asymEKPublicKey.key.pRSA,
                    exponent,
                    pEkPublicKey->publicKey.rsaKey.pModulus,
                    pEkPublicKey->publicKey.rsaKey.modulusLen, NULL);
            if (OK != status)
            {
                LOG_ERROR("Error %d setting EK RSA Asymmetric key public parameters\n", status);
                goto exit;
            }
            break;
        case TAP_KEY_ALGORITHM_ECC:
            /* todo */
            break;

        default:
            LOG_ERROR("Unsupported EK key algorithm %d\n", 
                    (int)pEkPublicKey->keyAlgorithm);
            goto exit;
            break;
    }

    status = SMP_TPM2_wrapCredentialSecret(&asymAKPublicKey,
            &asymEKPublicKey,
            extendedCert.blob.pBuffer,
            extendedCert.blob.bufferLen,
            keyCredential.pBuffer,
            keyCredential.bufferLen,
            &serverWrappedCredential.blob.pBuffer,
            &serverWrappedCredential.blob.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Failed to wrap credential into base64 blob. error=%d\n", status);
        goto exit;
    }

    status = unwrapKeyValidatedSecret(pSupportedOpcodes, moduleHandle, tokenHandle,
            aikHandle, ekHandle, &serverWrappedCredential, &secret);
    if (OK != status)
    {
        LOG_ERROR("unwrapKeyValidatedSecret failed, status %d\n", status);
        goto exit;
    }

    /* Compare the resulting secret with the symmetric key passed in */
    if (secret.bufferLen != symKeyCredentialLen)
    {
        LOG_ERROR("Extracted symmetric key length mismatched, secret length %d ! = %d\n", 
                secret.bufferLen, symKeyCredentialLen);
        goto exit;
    }

    status = DIGI_MEMCMP(secret.pBuffer, pSymKeyCredential, symKeyCredentialLen,
            &cmpResult);
    if (!((OK == status) && (!cmpResult)))
    {
        LOG_ERROR("Extracted symmetric key did not match one generated by server\n");
        goto exit;
    }

    LOG_MESSAGE_NONL("\n====================================================\n");
    LOG_MESSAGE("Attestation use case using Identity key verified");
    LOG_MESSAGE_NONL("====================================================\n");
exit:
    if (asymAKPublicKey.key.pRSA)
        RSA_freeKey(&asymAKPublicKey.key.pRSA, NULL);

    if (asymEKPublicKey.key.pRSA)
        RSA_freeKey(&asymEKPublicKey.key.pRSA, NULL);

    if (pSignature)
        freeSignature(pSupportedOpcodes, &pSignature);

    if (pAkPublicKey)
        freePublicKey(pSupportedOpcodes, &pAkPublicKey);

    if (NULL != pEkPublicKey)
        DIGI_FREE((void **) &pEkPublicKey);

    return status;
}

int testRootOfTrust(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle, TAP_ObjectId objectId)
{
    MSTATUS status = OK;
    int retval = 0;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_ObjectId objectIdOut = 0;
    TAP_ObjectHandle keyHandle = 0;

    /* Check if the functionality is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 Root of Trust key handle not supported");
        goto exit;
    }
    LOG_MESSAGE("\nGet Root of Trust Key Handle\n");
    /*Call to updateTrustedData through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE;
    cmdReq.reqParams.getRootOfTrustKeyHandle.moduleHandle = moduleHandle;
    cmdReq.reqParams.getRootOfTrustKeyHandle.objectId = objectId;
    cmdReq.reqParams.getRootOfTrustKeyHandle.type = 0;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        retval = -1;
        LOG_ERROR("SMP_TPM2_getRootOfTrustKeyHandle call failed with error %d\n", status);
        goto exit;
    }
    
    LOG_MESSAGE("getRootOfTrustKeyHandle returns key %p\n",
            (void *)cmdRsp.rspParams.getRootOfTrustKeyHandle.keyHandle);
    
    LOG_MESSAGE("\nClosing Trust Key Handle\n");
    status = uninitObject(pSupportedOpcodes, moduleHandle, tokenHandle, 
            cmdRsp.rspParams.getRootOfTrustKeyHandle.keyHandle);
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        retval = -1;
        LOG_ERROR("SMP_TPM2_uninitObject call failed with error %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("\nClosed Trust Key Handle successfully\n");

    LOG_MESSAGE("\nCalling InitObject on Trust Key\n");
    status = initObject(pSupportedOpcodes, moduleHandle, tokenHandle, 
            objectId, NULL, NULL, &keyHandle, &objectIdOut);
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        retval = -1;
        LOG_ERROR("SMP_TPM2_initObject call failed with error %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("initObject returns key %p\n", (void *)keyHandle);

    LOG_MESSAGE("\nClosing Trust Key Handle\n");
    status = uninitObject(pSupportedOpcodes, moduleHandle, tokenHandle, 
            keyHandle);
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        retval = -1;
        LOG_ERROR("SMP_TPM2_uninitObject call failed with error %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("\nClosed Trust Key Handle successfully\n");
exit:

    return retval;
}

int testDigest(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle)
{
    int retval = 0;
    MSTATUS status = OK;
    static TAP_HASH_ALG hashAlg = TAP_HASH_ALG_SHA256;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    static ubyte buffer[] = "Buffer to digest";
    ubyte4 bufLen = DIGI_STRLEN((const sbyte *)buffer);
    TAP_Buffer inputBuffer = {bufLen, buffer};
    sbyte4 cmpResult = 1;
    ubyte sha256Digest[SHA256_RESULT_SIZE];
    TAP_Attribute digestAttr[] = 
    {
        {TAP_ATTR_HASH_ALG, sizeof(hashAlg), &hashAlg},
    };
    TAP_MechanismAttributes mechanism = { 
        sizeof(digestAttr)/sizeof(TAP_Attribute), digestAttr 
    };

    /* Check if the functionality updateTrustedData is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, 
                SMP_CC_DIGEST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 Digest Not supported");
        goto exit;
    }

    LOG_MESSAGE("\nComputing digest of string \"%s\"\n", buffer);
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_DIGEST;
    cmdReq.reqParams.digest.moduleHandle = moduleHandle;
    cmdReq.reqParams.digest.tokenHandle = tokenHandle;
    cmdReq.reqParams.digest.pMechanism = &mechanism;
    cmdReq.reqParams.digest.pInputBuffer = &inputBuffer;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        retval = -1;
        LOG_ERROR("SMP_TPM2_digest call failed with error %d\n", status);
        goto exit;
    }

    /* Compute digest using software */

    /* Compare result */
    if (TAP_HASH_ALG_SHA256 == hashAlg)
    {
        status = SHA256_completeDigest(buffer, bufLen, sha256Digest);

        if (OK != status)
        {
            LOG_ERROR("SHA256_completeDigest call failed with error %d\n", status);
            goto exit;
        }

        status = DIGI_MEMCMP(cmdRsp.rspParams.digest.buffer.pBuffer, sha256Digest, 
                sizeof(sha256Digest), &cmpResult);
        if (OK != status)
        {
            LOG_ERROR("Digest memcmp call failed with error %d\n", status);
            goto exit;
        }

        if (!cmpResult)
            LOG_MESSAGE("Digest operation verified successfully\n");
        else
            LOG_ERROR("SHA256_completeDigest call failed with error  %d\n",
                    cmpResult);
    }

exit:
    if (NULL != cmdRsp.rspParams.digest.buffer.pBuffer)
    {
        DIGI_FREE((void**)&(cmdRsp.rspParams.digest.buffer.pBuffer));
    }
    return retval;
}

int testPCR(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle)
{
    int retval = 0;
    MSTATUS status = OK;
    TAP_Buffer pcrData = {0};
    static ubyte pcrIndex[24] = {0};
    static TAP_Buffer pcrIndexBuf = {1, pcrIndex};
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_Attribute trustedDataAttr[] = 
    {
        {TAP_ATTR_TRUSTED_DATA_KEY, sizeof(pcrIndexBuf), &pcrIndexBuf},
        {TAP_ATTR_NONE, 0, NULL}
    };
    TAP_TrustedDataInfo trustedDataInfo = { 
        1, /* Sub Type */
        {sizeof(trustedDataAttr)/sizeof(TAP_Attribute), trustedDataAttr} 
    };
    int i, j;
    static ubyte digest[32];
    TAP_Buffer pcrDigest = {sizeof(digest), digest};
    TAP_Buffer updatedPcrValue = {0};

    /* Update PCR 12 */
    /* Check if the functionality updateTrustedData is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_UPDATE_TRUSTED_DATA))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 updateTrustData Not supported");
        goto exit;
    }
    pcrIndex[0] = 12;
    pcrIndexBuf.bufferLen = 1;
    LOG_MESSAGE("\nUpdating trusted data on index %d\n", pcrIndex[0]);
    /*Call to updateTrustedData through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_UPDATE_TRUSTED_DATA;
    cmdReq.reqParams.updateTrustedData.moduleHandle = moduleHandle;
    cmdReq.reqParams.updateTrustedData.tokenHandle = tokenHandle;
    cmdReq.reqParams.updateTrustedData.trustedDataType = TAP_TRUSTED_DATA_TYPE_MEASUREMENT;
    cmdReq.reqParams.updateTrustedData.pTrustedDataInfo = &trustedDataInfo;
    cmdReq.reqParams.updateTrustedData.trustedDataOp = TAP_TRUSTED_DATA_OPERATION_UPDATE;
    cmdReq.reqParams.updateTrustedData.pDataValue = &pcrDigest;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        retval = -1;
        LOG_ERROR("SMP_TPM2_updateTrustedData call failed with error %d\n", status);
        goto exit;
    }
    updatedPcrValue = cmdRsp.rspParams.updateTrustedData.updatedDataValue;

    LOG_MESSAGE_NONL("Updated PCR Index %02d, value : ", pcrIndex[0]);
    for (j = 0; j < updatedPcrValue.bufferLen; j++)
            LOG_MESSAGE_NONL("%02x ", updatedPcrValue.pBuffer[j]);
    LOG_MESSAGE_NONL("\n\n");
    DIGI_FREE((void **)&updatedPcrValue.pBuffer);

    /*status = CALL_SMP_API_NO_RET(TPM2, updateTrustedData,moduleHandle, tokenHandle,
        TAP_TRUSTED_DATA_TYPE_MEASUREMENT, &trustedDataInfo,
        TAP_TRUSTED_DATA_OPERATION_UPDATE, &pcrDigest, &updatedPcrValue); */
    LOG_MESSAGE("Reading ALL Trusted data indexes\n");
    status = getTrustedData(pSupportedOpcodes, moduleHandle, tokenHandle, TAP_TRUSTED_DATA_TYPE_MEASUREMENT, NULL,
            &pcrData);
    if (OK != status)
    {
        retval = -1;
        LOG_ERROR("SMP_TPM2_getTrustedData failed with error %d\n", status);
        goto exit;
    }

    for (j = 0; j < pcrData.bufferLen; j++)
            LOG_MESSAGE_NONL("%02x ", pcrData.pBuffer[j]);
    LOG_MESSAGE_NONL("\n\n");
    DIGI_FREE((void **)&pcrData.pBuffer);

    LOG_MESSAGE("\nReading trusted data from indexes 0 - 24\n");

    /* Read PCR Values */
    for (i = 0; i < 24; i++)
    {
        for (j = 0; j < (i+1); j++)
        {
            pcrIndex[j] = j; 
        }
        pcrIndexBuf.bufferLen = j;

        status = getTrustedData(pSupportedOpcodes, moduleHandle, tokenHandle,
                TAP_TRUSTED_DATA_TYPE_MEASUREMENT, &trustedDataInfo,
                &pcrData);
        if (OK != status)
        {
            LOG_ERROR("SMP_TPM2_getTrustedData failed with error %d\n", status);
            retval = -1;
            goto exit;
        }
        else
        {
            LOG_MESSAGE_NONL("PCR Index %02d, value : ", i);
            for (j = 0; j < pcrData.bufferLen; j++)
                    LOG_MESSAGE_NONL("%02x ", pcrData.pBuffer[j]);
            LOG_MESSAGE_NONL("\n\n");
            DIGI_FREE((void **)&pcrData.pBuffer);
        }
    }

exit: 
    return retval;
}

MSTATUS signBuffer(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectHandle keyHandle, 
        TAP_SIG_SCHEME sigScheme, TAP_Buffer *pCsrRequest, 
        TAP_Signature **ppSignature)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    static ubyte *csrBuffer = (ubyte *)"Test CSR Request payload";

    /* Check if the functionality sign is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_SIGN_BUFFER))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 signBuffer Not supported");
        goto exit;
    }

    pCsrRequest->pBuffer = csrBuffer;
    pCsrRequest->bufferLen = DIGI_STRLEN((const sbyte *)csrBuffer);

    /* Sign buffer */
    /*Call to signDigest through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_SIGN_BUFFER;
    cmdReq.reqParams.signBuffer.moduleHandle = moduleHandle;
    cmdReq.reqParams.signBuffer.tokenHandle = tokenHandle;
    cmdReq.reqParams.signBuffer.keyHandle = keyHandle;
    cmdReq.reqParams.signBuffer.pDigest = pCsrRequest;
    cmdReq.reqParams.signBuffer.type = sigScheme;
    cmdReq.reqParams.signBuffer.pSignatureAttributes = NULL;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_signBuffer call failed with error %d\n", status);
        goto exit;
    }

    *ppSignature = cmdRsp.rspParams.signBuffer.pSignature;

exit:
    return status;
}

MSTATUS testKeySignOperation(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectHandle keyHandle, TAP_SIG_SCHEME sigScheme, char *keyUsage, ubyte *pInput, ubyte4 inputLen)
{
    MSTATUS status = OK;
    static ubyte shaBuf[SHA256_RESULT_SIZE] = { 0 };
    TAP_Buffer digest = {sizeof(shaBuf), shaBuf};
    TAP_Signature *pSignature = NULL;
    byteBoolean signatureValid = 0;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    static TAP_KEY_ALGORITHM verifyKeyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    static TAP_SIG_SCHEME verifySigScheme = TAP_SIG_SCHEME_PSS_SHA256; 
    //static TAP_SIG_SCHEME verifySigScheme = TAP_SIG_SCHEME_PKCS1_5; 
    static TAP_ENC_SCHEME verifyEncScheme = TAP_ENC_SCHEME_OAEP_SHA1;
    static TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    static TAP_Attribute verifyKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(verifyKeyAlgorithm), &verifyKeyAlgorithm},
        {TAP_ATTR_SIG_SCHEME, sizeof(verifySigScheme), &verifySigScheme},
        {TAP_ATTR_ENC_SCHEME, sizeof(verifyEncScheme), &verifyEncScheme},
        {TAP_ATTR_OP_EXEC_FLAG, sizeof(opExecFlag), &opExecFlag},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_KeyAttributes verifyKeyAttrList = { 
        sizeof(verifyKeyAttr)/sizeof(TAP_Attribute), verifyKeyAttr
    };
    TAP_Buffer inputDigest = {0};

    DIGI_MEMSET(shaBuf, 0x55, sizeof(shaBuf));

    LOG_MESSAGE("\n==== %s test ==== .... \nSigning digest ...\n", keyUsage);
    /* Check if the functionality sign is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_SIGN_DIGEST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 signDigest Not supported");
        goto exit;
    }

    SHA256_completeDigest(pInput, inputLen, digest.pBuffer);

    /* Sign buffer digest */
    /*Call to signDigest through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_SIGN_DIGEST;
    cmdReq.reqParams.signDigest.moduleHandle = moduleHandle;
    cmdReq.reqParams.signDigest.tokenHandle = tokenHandle;
    cmdReq.reqParams.signDigest.keyHandle = keyHandle;
    cmdReq.reqParams.signDigest.pDigest = &digest;
    cmdReq.reqParams.signDigest.type = verifySigScheme;
    cmdReq.reqParams.signDigest.pSignatureAttributes = NULL;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_signDigest call failed with error %d\n", status);
        goto exit;
    }
    pSignature = cmdRsp.rspParams.signDigest.pSignature;
 
    /*status = CALL_SMP_API_NO_RET(TPM2, signDigest,moduleHandle, tokenHandle, keyHandle,
            &digest, sigScheme, NULL, &pSignature);
    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_signDigest call failed with error %d\n", status);
    }*/

    LOG_MESSAGE("Verifying Signature ...");
    /* Verify signed buffer digest */
    /* Check if the functionality sign is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_VERIFY))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 verifyDigest Not supported");
        goto exit;
    }

    inputDigest.pBuffer = pInput;
    inputDigest.bufferLen = inputLen;

    /*Call to verifyDigest through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_VERIFY;
    cmdReq.reqParams.verify.moduleHandle = moduleHandle;
    cmdReq.reqParams.verify.tokenHandle = tokenHandle;
    cmdReq.reqParams.verify.keyHandle = keyHandle;
    cmdReq.reqParams.verify.pDigest = &digest;
    cmdReq.reqParams.verify.pMechanism = &verifyKeyAttrList;
    cmdReq.reqParams.verify.pSignature = pSignature;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_verifySignature call failed with error %d\n", status);
        goto exit;
    }
    signatureValid = cmdRsp.rspParams.verify.signatureValid;

    /*status = CALL_SMP_API_NO_RET(TPM2, verify,moduleHandle, tokenHandle, keyHandle,
            NULL, &digest, pSignature, &signatureValid);
    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_verifySignature call failed with error %d\n", status);
    }*/

    if (signatureValid)
        LOG_MESSAGE("Signature validated successfully !\n");
    else
        LOG_MESSAGE("Signature validation failed !\n");
exit:
    if (NULL != pSignature)
    {
        DIGI_FREE((void**)&pSignature);
    }
    return status;
}

MSTATUS testKeyEncryptDecryptOperation(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle, TAP_ObjectHandle keyHandle,
        TAP_KeyAttributes *pGeneralDecryptKeyAttrList,
        TAP_Buffer *pDataToEncrypt, TAP_Buffer *pEncryptedData,
        TAP_Buffer *pDecryptedData, char *keyUsage)
{
    MSTATUS status = OK;
    sbyte4 cmpResult = 1;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Encrypt */
    LOG_MESSAGE("\n===== %s test ==== ...\nEncryption ... ", keyUsage);
    /* Check if the functionality encrypt is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_ENCRYPT))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 encrypt Not supported");
        goto exit;
    }
    /*Call to encrypt through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_ENCRYPT;
    cmdReq.reqParams.encrypt.moduleHandle = moduleHandle;
    cmdReq.reqParams.encrypt.tokenHandle = tokenHandle;
    cmdReq.reqParams.encrypt.keyHandle = keyHandle;
    cmdReq.reqParams.encrypt.pMechanism = pGeneralDecryptKeyAttrList;
    cmdReq.reqParams.encrypt.pBuffer = pDataToEncrypt;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_encrypt call failed with error %d\n", status);
        goto exit;
    }
    *pEncryptedData = cmdRsp.rspParams.encrypt.cipherBuffer;
    LOG_MESSAGE("Encryption done\n");

    /* Decrypt */
    LOG_MESSAGE("Decryption in progress ...");
    /* Check if the functionality decrypt is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_DECRYPT))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 decrypt Not supported");
        goto exit;
    }
    /*Call to decrypt through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_DECRYPT;
    cmdReq.reqParams.decrypt.moduleHandle = moduleHandle;
    cmdReq.reqParams.decrypt.tokenHandle = tokenHandle;
    cmdReq.reqParams.decrypt.keyHandle = keyHandle;
    cmdReq.reqParams.decrypt.pMechanism = pGeneralDecryptKeyAttrList;
    cmdReq.reqParams.decrypt.pCipherBuffer = pEncryptedData;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_decrypt failed with error %d\n", status);
        goto exit;
    }
    *pDecryptedData = cmdRsp.rspParams.decrypt.buffer;

    /*status = CALL_SMP_API_NO_RET(TPM2, decrypt,moduleHandle, tokenHandle, keyHandle,
            (TAP_MechanismAttributes *)pGeneralDecryptKeyAttrList, 
            pEncryptedData, pDecryptedData);*/
   if (pDataToEncrypt->bufferLen == pDecryptedData->bufferLen)
    {
        status = DIGI_MEMCMP(pDecryptedData->pBuffer, 
                pDataToEncrypt->pBuffer,
                pDataToEncrypt->bufferLen, &cmpResult);
        if (OK != status)
        {
            LOG_ERROR("Failed to compare decrypted data, error %d\n", status);
        }
        else
        {
            if (0 == cmpResult)
                LOG_MESSAGE("Decrypt successful !");
            else
                LOG_ERROR("Decryption failed !\n");
        }
    }
    else
    {
        LOG_ERROR("Data length mismatch Input buffer length %d != Decrypted buffer length %d\n", 
                (int)pDataToEncrypt->bufferLen, 
                (int)pDecryptedData->bufferLen);
    }
exit:

    return status;
}

static
byteBoolean isFunctionalitySupported(TAP_CmdCodeList *pSupportedOpCodes, ubyte2 opCode)
{
    byteBoolean supported  = FALSE;
    int         i          = 0;


    if (NULL == pSupportedOpCodes)
    {
        goto exit;
    }

    for (i = 0; i < pSupportedOpCodes->listLen; i++)
    {
        if (pSupportedOpCodes->pCmdList[i] == opCode)
        {
            supported = TRUE;
        }
    }

exit:
    return supported;
}

static 
MSTATUS createObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials, 
        TAP_ObjectHandle *pObjectHandle, TAP_ObjectId *pObjectIdOut)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality createObject is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_CREATE_OBJECT))
    {
        LOG_ERROR("TPM2 createObject Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }

    /* Call to createObject through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_CREATE_OBJECT;
    cmdReq.reqParams.createObject.moduleHandle = moduleHandle;
    cmdReq.reqParams.createObject.tokenHandle = tokenHandle;
    cmdReq.reqParams.createObject.objectIdIn = objectIdIn;
    cmdReq.reqParams.createObject.pObjectAttributes = pObjectAttributes;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_createObject failed with error %d", status);
        goto exit;
    }
    *pObjectHandle = cmdRsp.rspParams.createObject.handle;
    *pObjectIdOut = cmdRsp.rspParams.createObject.objectIdOut;

exit:

    return status;
}
static 
MSTATUS initObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials, 
        TAP_ObjectHandle *pObjectHandle, TAP_ObjectId *pObjectIdOut)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality initObject is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_INIT_OBJECT))
    {
        LOG_ERROR("TPM2 initObject Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }

    /* Call to uninitObject through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_INIT_OBJECT;
    cmdReq.reqParams.initObject.moduleHandle = moduleHandle;
    cmdReq.reqParams.initObject.tokenHandle = tokenHandle;
    cmdReq.reqParams.initObject.objectIdIn = objectIdIn;
    cmdReq.reqParams.initObject.pObjectAttributes = pObjectAttributes;
    cmdReq.reqParams.initObject.pCredentialList = pCredentials;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_initObject failed with error %d", status);
        goto exit;
    }
    *pObjectHandle = cmdRsp.rspParams.initObject.objectHandle;
    *pObjectIdOut = cmdRsp.rspParams.initObject.objectIdOut;

exit:

    return status;
}

static 
MSTATUS uninitObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, 
        TAP_TokenHandle tokenHandle, TAP_ObjectHandle objectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality uninitObject is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_UNINIT_OBJECT))
    {
        LOG_ERROR("TPM2 uninitObject Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }

    /* Call to uninitObject through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_UNINIT_OBJECT;
    cmdReq.reqParams.unintObject.moduleHandle = moduleHandle;
    cmdReq.reqParams.unintObject.tokenHandle = tokenHandle;
    cmdReq.reqParams.unintObject.objectHandle = objectHandle;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_uninitObject failed with error %d", status);
        goto exit;
    }

exit:

    return status;
}

static 
MSTATUS uninitModule(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality initModule is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_UNINIT_MODULE))
    {
        LOG_ERROR("TPM2 uninitModule Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }
    /* Initialize context on first module*/
    /*Call to uninitModule through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_UNINIT_MODULE;
    cmdReq.reqParams.uninitModule.moduleHandle = moduleHandle;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_uninitModule failed with error %d", status);
        goto exit;
    }

exit:

    return status;

}

static 
MSTATUS initModule(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleId moduleId, TAP_ModuleHandle *pModuleHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality initModule is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_INIT_MODULE))
    {
        LOG_ERROR("TPM2 initModule Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }
    /* Initialize context on first module*/
    /*Call to initModule through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_INIT_MODULE;
    cmdReq.reqParams.initModule.moduleId = moduleId;
    cmdReq.reqParams.initModule.pModuleAttributes = NULL;
    cmdReq.reqParams.initModule.pCredentialList = NULL;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_initModule failed with error %d", status);
        goto exit;
    }
    *pModuleHandle = cmdRsp.rspParams.initModule.moduleHandle;

exit:

    return status;
}

static 
MSTATUS freeModuleList(TAP_CmdCodeList *pSupportedOpcodes, TAP_EntityList *pModuleList)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    /* Check if the functionality getModuelList is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_FREE_MODULE_LIST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 freeModuleList Not supported");
        goto exit;
    }
    /*Call to freeModuleList through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_FREE_MODULE_LIST;
    cmdReq.reqParams.freeModuleList.pModuleList = pModuleList;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_freeModuleList failed with error %d", status);
        goto exit;
    }
exit:

    return status;

}

static 
MSTATUS importObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
        TAP_Blob *pBlob, TAP_ObjectCapabilityAttributes *pObjectAttributes, TAP_EntityCredentialList *pCredentials, 
        TAP_ObjectHandle *pObjectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality import Object is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_EXPORT_OBJECT))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 importObject Not supported");
        goto exit;
    }
    /*Call to importObject through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_IMPORT_OBJECT;
    cmdReq.reqParams.importObject.moduleHandle = moduleHandle;
    cmdReq.reqParams.importObject.tokenHandle = tokenHandle;
    cmdReq.reqParams.importObject.pBlob = pBlob;
    cmdReq.reqParams.importObject.pObjectAttributes = pObjectAttributes;
    cmdReq.reqParams.importObject.pCredentialList = pCredentials;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_importObject failed with error %d", status);
        goto exit;
    }
    *pObjectHandle = cmdRsp.rspParams.importObject.objectHandle;

exit:

    return status;


}
static 
MSTATUS exportObject(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
        TAP_ObjectHandle keyHandle, TAP_Blob *pBlob)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality exportObject is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_EXPORT_OBJECT))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 exportObject Not supported");
        goto exit;
    }
    /*Call to exportObject through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_EXPORT_OBJECT;
    cmdReq.reqParams.exportObject.moduleHandle = moduleHandle;
    cmdReq.reqParams.exportObject.tokenHandle = tokenHandle;
    cmdReq.reqParams.exportObject.objectHandle = keyHandle;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_exportObject failed with error %d", status);
        goto exit;
    }
    *pBlob = cmdRsp.rspParams.exportObject.exportedObject;

exit:

    return status;


}

static 
MSTATUS getPublicKey(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
        TAP_ObjectHandle keyHandle, TAP_PublicKey **ppPublicKey)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality getModuelList is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_PUBLIC_KEY))
    {
        LOG_ERROR("TPM2 getPublicKey Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }
    /*Call to getPublicKey through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_PUBLIC_KEY;
    cmdReq.reqParams.getPublicKey.moduleHandle = moduleHandle;
    cmdReq.reqParams.getPublicKey.tokenHandle = tokenHandle;
    cmdReq.reqParams.getPublicKey.objectHandle = keyHandle;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_getPublicKey failed with error %d", status);
        goto exit;
    }
    *ppPublicKey = cmdRsp.rspParams.getPublicKey.pPublicKey;

exit:

    return status;

}

static
MSTATUS createAsymmetricKey(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
                     TAP_ObjectId objectId, TAP_KeyAttributes *pKeyAttr, byteBoolean keyInitFlag, TAP_ObjectId *pKeyObjectId, 
                     TAP_ObjectAttributes *pCreatedKeyAttr, TAP_ObjectHandle *pKeyHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality getModuelList is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_CREATE_ASYMMETRIC_KEY))
    {
        LOG_ERROR("TPM2 createAsymmetricKey Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }
    /*Call to createAsymmetricKey through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_CREATE_ASYMMETRIC_KEY;
    cmdReq.reqParams.createAsymmetricKey.moduleHandle = moduleHandle;
    cmdReq.reqParams.createAsymmetricKey.tokenHandle = tokenHandle;
    cmdReq.reqParams.createAsymmetricKey.objectId = objectId;
    cmdReq.reqParams.createAsymmetricKey.initFlag = keyInitFlag;
    cmdReq.reqParams.createAsymmetricKey.pKeyAttributes = pKeyAttr;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_createAsymmetricKey failed with error %d", status);
        goto exit;
    }
    *pKeyObjectId = cmdRsp.rspParams.createAsymmetricKey.objectIdOut;
    *pCreatedKeyAttr = cmdRsp.rspParams.createAsymmetricKey.objectAttributes;
    *pKeyHandle = cmdRsp.rspParams.createAsymmetricKey.keyHandle;

exit:

    return status;
}

static
MSTATUS createSymmetricKey(TAP_CmdCodeList *pSupportedOpcodes, TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
                     TAP_ObjectId objectId, TAP_KeyAttributes *pKeyAttr, byteBoolean keyInitFlag, TAP_ObjectId *pKeyObjectId, 
                     TAP_ObjectAttributes *pCreatedKeyAttr, TAP_ObjectHandle *pKeyHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* Check if the functionality getModuelList is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_CREATE_SYMMETRIC_KEY))
    {
        LOG_ERROR("TPM2 createSymmetricKey Not supported");
        status = ERR_TPM_CMD_UNSUPPORTED;
        goto exit;
    }
    /*Call to createSymmetricKey through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_CREATE_SYMMETRIC_KEY;
    cmdReq.reqParams.createSymmetricKey.moduleHandle = moduleHandle;
    cmdReq.reqParams.createSymmetricKey.tokenHandle = tokenHandle;
    cmdReq.reqParams.createSymmetricKey.objectId = objectId;
    cmdReq.reqParams.createSymmetricKey.initFlag = keyInitFlag;
    cmdReq.reqParams.createSymmetricKey.pAttributeKey = pKeyAttr;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("SMP_TPM2_createSymmetricKey failed with error %d", status);
        goto exit;
    }

    *pKeyObjectId = cmdRsp.rspParams.createSymmetricKey.objectIdOut;
    *pCreatedKeyAttr = cmdRsp.rspParams.createSymmetricKey.objectAttributes;
    *pKeyHandle = cmdRsp.rspParams.createSymmetricKey.keyHandle;

exit:

    return status;
}

MSTATUS initTokenAndObjectList(TAP_CmdCodeList *pSupportedOpcodes, 
        TAP_ModuleHandle moduleHandle, TAP_TokenHandle *pTokenHandle,
        TAP_EntityList *pObjectList, TAP_ObjectId tokenId)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_TokenCapabilityAttributes tokenCapabilityAttrs = {0};
    TAP_Attribute getTokenListAttr = {0};
    ubyte keyUsage = TAP_KEY_USAGE_SIGNING;
    TAP_EntityList tokenList = { 0 };
    ubyte4 i;

    /* Get Token List */
    /* Check if the functionality getTokenList is supported */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_TOKEN_LIST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getTokenList Not supported");
        goto exit;
    }

    /*Call to getTokenList through dispatcher */
    if (SMP_TPM2_ATTESTATION_TOKEN_ID == tokenId)
    {
        keyUsage = TAP_KEY_USAGE_ATTESTATION;
    }
    getTokenListAttr.type = TAP_ATTR_KEY_USAGE;
    getTokenListAttr.length = sizeof(keyUsage);
    getTokenListAttr.pStructOfType = &keyUsage;

    tokenCapabilityAttrs.listLen = 1;
    tokenCapabilityAttrs.pAttributeList = &getTokenListAttr;
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_TOKEN_LIST;
    cmdReq.reqParams.getTokenList.moduleHandle = moduleHandle;
    cmdReq.reqParams.getTokenList.tokenType = 0; /* TODO */
    cmdReq.reqParams.getTokenList.pTokenAttributes = &tokenCapabilityAttrs;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 getTokenList failed with error %d", status);
        goto exit;
    }
    if (cmdRsp.rspParams.getTokenList.tokenIdList.entityIdList.numEntities <= 0)
    {
        LOG_ERROR("No token present in TPM2 Module");
        goto exit;
    }
    tokenList = cmdRsp.rspParams.getTokenList.tokenIdList;

    /* Initialize Token */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_INIT_TOKEN))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 initToken Not supported");
        goto exit;
    }
    /*Call to initToken through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_INIT_TOKEN;
    cmdReq.reqParams.initToken.moduleHandle = moduleHandle;
    cmdReq.reqParams.initToken.tokenId = tokenList.entityIdList.pEntityIdList[0];
    cmdReq.reqParams.initToken.pTokenAttributes = NULL;
    cmdReq.reqParams.initToken.pCredentialList = NULL;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 initToken failed with error %d", status);
        goto exit;
    }
    *pTokenHandle = cmdRsp.rspParams.initToken.tokenHandle;

    /* getObjectList */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_OBJECT_LIST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getObjectList Not supported");
        goto exit;
    }
    /*Call to getObjectList through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_OBJECT_LIST;
    cmdReq.reqParams.getObjectList.moduleHandle = moduleHandle;
    cmdReq.reqParams.getObjectList.tokenHandle = *pTokenHandle;
    cmdReq.reqParams.getObjectList.pObjectAttributes = NULL;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 getObjectList failed with error %d", status);
        goto exit;
    }
    *pObjectList = cmdRsp.rspParams.getObjectList.objectIdList;

    LOG_MESSAGE_NONL("SMP_TPM2_getObjectList successful, received %d objects\n",
            (int)pObjectList->entityIdList.numEntities);
    for (i = 0; i < pObjectList->entityIdList.numEntities; i++)
    {
        LOG_MESSAGE_NONL("Object Id %d => 0x%08x\n", (int)i, 
                (unsigned int)pObjectList->entityIdList.pEntityIdList[i]);
    }

exit:
    return status;
}

MSTATUS associateObjectCredentials(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
    TAP_ObjectHandle objectHandle, TAP_EntityCredentialList *pCredentialsList)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};

    /* GetRandom */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 associateObjectCredentials Not supported");
        goto exit;
    }

    /*Call to getRandom through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS;
    cmdReq.reqParams.associateObjectCredentials.moduleHandle = moduleHandle;
    cmdReq.reqParams.associateObjectCredentials.tokenHandle = tokenHandle;
    cmdReq.reqParams.associateObjectCredentials.objectHandle = objectHandle;
    cmdReq.reqParams.associateObjectCredentials.pCredentialsList = pCredentialsList;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 associateObjectCredentials failed with error %d", status);
        goto exit;
    }

exit:
    return status;
}

MSTATUS testRandomNo(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
    ubyte4 numBytes, TAP_Buffer *pRandomData)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    ubyte4 i = 0;

    /* GetRandom */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_GET_RANDOM))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getRandom Not supported");
        goto exit;
    }

    /*Call to getRandom through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_RANDOM;
    cmdReq.reqParams.getRandom.moduleHandle = moduleHandle;
    cmdReq.reqParams.getRandom.tokenHandle = tokenHandle;
    cmdReq.reqParams.getRandom.pRngRequest = NULL;
    cmdReq.reqParams.getRandom.bytesRequested = numBytes;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 getRandom failed with error %d", status);
        goto exit;
    }
    *pRandomData = cmdRsp.rspParams.getRandom.random;

    LOG_MESSAGE_NONL("SMP_TPM2_getRandom successful, received %d bytes\n",
            (int)pRandomData->bufferLen);
    /* Print Random data */
    for (i = 0; i < pRandomData->bufferLen; i++)
    {
        if (!(i % 16))
            LOG_MESSAGE_NONL("\n");
        LOG_MESSAGE_NONL("%02x ", pRandomData->pBuffer[i]);
    }
exit:
    return status;
}

MSTATUS testRandomNoFunction(TAP_CmdCodeList *pSupportedOpcodes, 
    TAP_ModuleHandle moduleHandle, TAP_TokenHandle tokenHandle, 
    ubyte4 numBytes, TAP_RngAttributes *pRngAttributes, 
    TAP_Buffer *pRandom)
{
    MSTATUS status = OK;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_Buffer stirredRandomData = {0};
    sbyte4 cmpResult = 0;

    if (OK != (status = testRandomNo(pSupportedOpcodes, moduleHandle,
                    tokenHandle, numBytes, pRandom)))
    {
        goto exit;
    }

    LOG_MESSAGE("\n\nStir Random number generator ...\n");
    /* Stir Random */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_STIR_RANDOM))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 stirRandom Not supported");
        goto exit;
    }

    /*Call to getRandom through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_STIR_RANDOM;
    cmdReq.reqParams.stirRandom.moduleHandle = moduleHandle;
    cmdReq.reqParams.stirRandom.tokenHandle = tokenHandle;
    cmdReq.reqParams.stirRandom.pRngRequest = pRngAttributes;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 stirRandom failed with error %d", status);
        goto exit;
    }
    LOG_MESSAGE("\n\nStir Random number successful !\n");

    LOG_MESSAGE("\nGet Random number after stirring\n");
    if (OK != (status = testRandomNo(pSupportedOpcodes, moduleHandle,
                    tokenHandle, numBytes, &stirredRandomData)))
    {
        goto exit;
    }

    if (pRandom->bufferLen != stirredRandomData.bufferLen)
    {
        status = ERR_TAP_CMD_FAILED;
        LOG_ERROR("Stirred buffer length %d does not match random data buffer"
                " length %d\n", (int)stirredRandomData.bufferLen,
                (int)pRandom->bufferLen);
        goto exit;
    }

    /* The data needs to be different */
    status = DIGI_MEMCMP(pRandom->pBuffer, stirredRandomData.pBuffer,
        pRandom->bufferLen, &cmpResult);

    if (OK != status)
    {
        LOG_ERROR("Stirred random data memory compare failed, "
                " status %d\n", (int)status);
    
        goto exit;
    }

    if (!cmpResult)
        LOG_ERROR("Stir Failure ! Stirred random same as random value before stirring\n");
    else
        LOG_MESSAGE("\n\nGet Random number after stirring successful !\n");

exit:
    return status;
}

static MSTATUS freeAttrList(TAP_AttributeList *pAttrs)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    TAP_Attribute *pAttr = NULL;

    if ((NULL == pAttrs) || (NULL == pAttrs->pAttributeList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pAttr = pAttrs->pAttributeList;

    for (count = 0; count < pAttrs->listLen; count++)
    {
        if (NULL == pAttr)
        {
            /* stop on encountering null element */
            break;
        }

        if (OK != DIGI_FREE((void **)(&(pAttr->pStructOfType))))
        {
            DB_PRINT("%s.%d Failed freeing memory of pAttr->pStructOfType at %p\n",
                __FUNCTION__, __LINE__, pAttr->pStructOfType);
        }

        pAttr++;
    }

    /* Free the memory allocated to complete attr-list */
    if (OK != DIGI_FREE((void **)(&(pAttrs->pAttributeList))))
    {
        DB_PRINT("%s.%d Failed freeing memory of pAttrs->pAttributeList "
                "to attribute list at %p\n",
            __FUNCTION__, __LINE__, pAttrs->pAttributeList);
    }

    pAttrs->listLen = 0;

exit:
    return status;
}

MSTATUS testSelfTest(TAP_CmdCodeList *pSupportedOpcodes, 
        TAP_ModuleHandle moduleHandle)
{
    MSTATUS status = OK;
    static TAP_TEST_MODE testMode = TAP_TEST_MODE_FULL;
    static TAP_TEST_MODE testPoll = TAP_TEST_MODE_LAST_RESULTS;
    static TAP_Attribute selfTestAttr[] = 
    {
        {TAP_ATTR_TEST_MODE, sizeof(testMode), &testMode},
    };
    static TAP_TestRequestAttributes selfTestAttrList = { 
        sizeof(selfTestAttr)/sizeof(TAP_Attribute), selfTestAttr
    };
    static TAP_Attribute selfTestPollAttr[] = 
    {
        {TAP_ATTR_TEST_MODE, sizeof(testPoll), &testPoll},
    };
    static TAP_TestRequestAttributes selfTestPollAttrList = { 
        sizeof(selfTestPollAttr)/sizeof(TAP_Attribute), selfTestPollAttr
    };
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_TestResponseAttributes selfTestRespAttrList = {0};

    /* start test */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_SELF_TEST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 selfTest Not supported");
        goto exit;
    }

    /*Call to selfTest through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_SELF_TEST;
    cmdReq.reqParams.selfTest.moduleHandle = moduleHandle;
    cmdReq.reqParams.selfTest.pTestRequest = &selfTestAttrList;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 selfTest failed with error %d", status);
        goto exit;
    }

    selfTestRespAttrList = cmdRsp.rspParams.selfTest.testResponse;

    if (selfTestRespAttrList.listLen)
    {
        if (TAP_TEST_STATUS_SUCCESS == *(TAP_TEST_STATUS *)
                (selfTestRespAttrList.pAttributeList[0].pStructOfType))
            LOG_MESSAGE("TPM2 selfTest was completed successfully\n");
        else
            LOG_ERROR("TPM2 selfTest failed\n");
    }
    else
    {
        LOG_ERROR("Self test response did not return any result\n");
        goto exit;
    }

    /* Release self test result memory */
    freeAttrList(&selfTestRespAttrList);

    LOG_MESSAGE("\nGet results of the last self test\n");

    /* get last test results */
    if (FALSE == isFunctionalitySupported(pSupportedOpcodes, SMP_CC_SELF_TEST_POLL))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 selfTest Poll Not supported");
        goto exit;
    }

    /*Call to selfTest through dispatcher */
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_SELF_TEST_POLL;
    cmdReq.reqParams.selfTestPoll.moduleHandle = moduleHandle;
    cmdReq.reqParams.selfTestPoll.pTestRequest = &selfTestPollAttrList;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );
    if (OK != status || OK != cmdRsp.returnCode)
    {
        status = (status == OK) ? cmdRsp.returnCode : status;
        LOG_ERROR("TPM2 selfTest Poll failed with error %d", status);
        goto exit;
    }

    selfTestRespAttrList = cmdRsp.rspParams.selfTestPoll.testResponse;

    if (selfTestRespAttrList.listLen)
    {
        if (TAP_TEST_STATUS_SUCCESS == *(TAP_TEST_STATUS *)
                (selfTestRespAttrList.pAttributeList[0].pStructOfType))
            LOG_MESSAGE("Last selfTest was completed successfully\n");
        else
            LOG_ERROR("Last selfTest failed\n");
    }
    else
    {
        LOG_ERROR("Self test response did not return any result\n");
        goto exit;
    }

exit:
    freeAttrList(&selfTestRespAttrList);

    return status;
}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = OK;
    TAP_SIG_SCHEME savedSignScheme[6] = {0};
    TAP_Blob keyBlob[6] = {0};
    KEY_INFO keyInfo[6] = { 0 };
    TAP_EntityList moduleList = { 0 };
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle cryptoTokenHandle = 0;
    TAP_TokenHandle akTokenHandle = 0;
    TAP_ObjectId cryptoObjectId = 0;
    TAP_EntityList cryptoObjectList = {0};
    TAP_EntityList akObjectList = {0};
    TAP_ObjectId objectIdOut = 0;
    TAP_ObjectHandle keyHandle = 0;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_KeyAttributes *pKeyAttr = NULL;
    static TAP_KEY_USAGE generalKeyType = TAP_KEY_USAGE_GENERAL;
    static TAP_KEY_USAGE decryptKeyType = TAP_KEY_USAGE_DECRYPT;
    static TAP_KEY_USAGE signKeyType = TAP_KEY_USAGE_SIGNING;
    static TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5; 
    //static TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PSS_SHA256; 
    static TAP_KEY_ALGORITHM asymKeyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    static TAP_KEY_ALGORITHM symKeyAlgorithmDecrypt = TAP_KEY_ALGORITHM_AES;
    static TAP_KEY_ALGORITHM symKeyAlgorithmSigning = TAP_KEY_ALGORITHM_HMAC;
    static TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_OAEP_SHA1;
    static TAP_Attribute generalDecryptKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(asymKeyAlgorithm), &asymKeyAlgorithm},
        {TAP_ATTR_KEY_USAGE, sizeof(generalKeyType), &generalKeyType},
        {TAP_ATTR_ENC_SCHEME, sizeof(encScheme), &encScheme},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_Attribute generalSignKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(asymKeyAlgorithm), &asymKeyAlgorithm},
        {TAP_ATTR_SIG_SCHEME, sizeof(sigScheme), &sigScheme},
        {TAP_ATTR_KEY_USAGE, sizeof(generalKeyType), &generalKeyType},
        {TAP_ATTR_ENC_SCHEME, sizeof(encScheme), &encScheme},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_Attribute decryptKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(asymKeyAlgorithm), &asymKeyAlgorithm},
        {TAP_ATTR_KEY_USAGE, sizeof(decryptKeyType), &decryptKeyType},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_Attribute signKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(asymKeyAlgorithm), &asymKeyAlgorithm},
        {TAP_ATTR_SIG_SCHEME, sizeof(sigScheme), &sigScheme},
        {TAP_ATTR_KEY_USAGE, sizeof(signKeyType), &signKeyType},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_KeyAttributes generalDecryptKeyAttrList = { 
        sizeof(generalDecryptKeyAttr)/sizeof(TAP_Attribute), generalDecryptKeyAttr
    };
    static TAP_KeyAttributes generalSignKeyAttrList = { 
        sizeof(generalSignKeyAttr)/sizeof(TAP_Attribute), generalSignKeyAttr
    };
    static TAP_KeyAttributes decryptKeyAttrList = { 
        sizeof(decryptKeyAttr)/sizeof(TAP_Attribute), decryptKeyAttr
    };
    static TAP_KeyAttributes signKeyAttrList = { 
        sizeof(signKeyAttr)/sizeof(TAP_Attribute), signKeyAttr 
    };
    static TAP_Attribute symDecryptKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(symKeyAlgorithmDecrypt), &symKeyAlgorithmDecrypt},
        {TAP_ATTR_KEY_USAGE, sizeof(decryptKeyType), &decryptKeyType},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_Attribute symSignKeyAttr[] = 
    {
        {TAP_ATTR_KEY_ALGORITHM, sizeof(symKeyAlgorithmSigning), &symKeyAlgorithmSigning},
        {TAP_ATTR_KEY_USAGE, sizeof(signKeyType), &signKeyType},
        {TAP_ATTR_NONE, 0, NULL}
    };
    static TAP_KeyAttributes symDecryptKeyAttrList = { 
        3, symDecryptKeyAttr
    };
    static TAP_KeyAttributes symSignKeyAttrList = { 
        3, symSignKeyAttr 
    };
    static TAP_KeyAttributes *keyAttrList[] = {
        &generalDecryptKeyAttrList,
        &generalSignKeyAttrList,
        &signKeyAttrList,
        &decryptKeyAttrList,
        &symSignKeyAttrList,
        &symDecryptKeyAttrList,
        NULL
    };
    ubyte4 keyType = 0;
    TAP_ObjectAttributes createdKeyAttr = {0};
    TAP_PublicKey *pPublicKey = NULL;
    TAP_Buffer encryptedData = {0};
    TAP_Buffer dataToEncrypt = {33, (ubyte *)"This is the house that jack built"};
    TAP_Buffer decryptedData = {0};
    byteBoolean keyInitFlag = 0;
    byteBoolean isModuleInitialized = 0;
    TAP_ConfigInfo configInfo = {0};
    TAP_CmdCodeList supportedOpcodes = {0};
    TAP_Version tapVersion = {0};
    TAP_ObjectId keyObjectId = 0;
    TAP_SMPVersion smpVersion = {SMP_VERSION_MAJOR, SMP_VERSION_MINOR};
    TAP_Buffer randomData = {0};
    int i = 0;
    TAP_ModuleCapabilityAttributes moduleCap = {0};
    const char* pMocanaConfigFile = NULL;

    if (!pOpts)
    {
        LOG_ERROR("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

#if defined(__RTOS_WIN32__)
    status = TPM2_TEST_UTILS_getTapWinConfigFilePath(&pMocanaConfigFile, TPM2_CONFIGURATION_FILE);
    if (OK != status)
    {
        retval = -1;
        goto exit;
    }
#else
    pMocanaConfigFile = TPM2_CONFIGURATION_FILE;
#endif

    /* Load TPM2 configuration file */
    status = DIGICERT_readFile(pMocanaConfigFile, &configInfo.configInfo.pBuffer,
            &configInfo.configInfo.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("MOC_readFile failed with error %d", status);
        goto exit;
    }

    configInfo.provider = TAP_PROVIDER_TPM2;

    status = SMP_TPM2_register(TAP_PROVIDER_TPM2, smpVersion, tapVersion,
            &configInfo, &supportedOpcodes);
    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_register failed with error %d", status);
        goto exit;
    }
    /* Check if the functionality getModuelList is supported */
    if (FALSE == isFunctionalitySupported(&supportedOpcodes, SMP_CC_GET_MODULE_LIST))
    {
        status = ERR_TPM_CMD_UNSUPPORTED;
        LOG_ERROR("TPM2 getModuleList Not supported");
        goto exit;
    }
    /*Call to getModuleList through dispatcher */ 
	memset(&cmdReq, 0, sizeof(cmdReq));
    memset(&cmdRsp, 0, sizeof(cmdRsp));
    cmdReq.cmdCode = SMP_CC_GET_MODULE_LIST;
    cmdReq.reqParams.getModuleList.pModuleAttributes = NULL;
    status = SMP_TPM2_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , NULL
       , NULL
#endif
            );

    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_getModuleList failed with error %d", status);
        goto exit;
    }
    moduleList = cmdRsp.rspParams.getModuleList.moduleList;

    if (0 == moduleList.entityIdList.numEntities)
    {
        LOG_ERROR("No TPM2 modules found");
        goto exit;
    }

    /* Todo: ensure that we have Entity type set to Module */
    status = CALL_SMP_API_NO_RET(TPM2, getModuleInfo, 
            moduleList.entityIdList.pEntityIdList[0], NULL, &moduleCap);
    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_getModuleInfo failed with error %d", status);
    }
    else
    {
        /* Dump Capabilities */
        for (i = 0; i < moduleCap.listLen; i++)
        {
            switch(moduleCap.pAttributeList[i].type)
            {
                case TAP_ATTR_MODULE_PROVISION_STATE:
                    if (moduleCap.pAttributeList[i].pStructOfType)
                        LOG_MESSAGE("Module is %s\n", 
                            *(TAP_MODULE_PROVISION_STATE *)moduleCap.pAttributeList[i].pStructOfType ? "Provisioned" : "NOT Provisioned");
                    else
                        LOG_ERROR("Invalid attribute list structure pointer\n");
                    break;
            }
        }
    }

    status = initModule(&supportedOpcodes, moduleList.entityIdList.pEntityIdList[0], &moduleHandle);
    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_initModule failed with error %d", status);
        goto exit;
    }

    if (OK != (status = initTokenAndObjectList(&supportedOpcodes, moduleHandle, 
                    &cryptoTokenHandle, &cryptoObjectList,
            SMP_TPM2_CRYPTO_TOKEN_ID)))
    {
        LOG_ERROR("initTokenAndObjectList for token %d, failed with error %d",
                SMP_TPM2_CRYPTO_TOKEN_ID, status);
        goto exit;
    }
    cryptoObjectId = cryptoObjectList.entityIdList.pEntityIdList[0];

    if (OK != (status = initTokenAndObjectList(&supportedOpcodes, 
                    moduleHandle, &akTokenHandle, &akObjectList, 
            SMP_TPM2_ATTESTATION_TOKEN_ID)))
    {
        LOG_ERROR("initTokenAndObjectList for token %d, failed with error %d",
                SMP_TPM2_ATTESTATION_TOKEN_ID, status);
        goto exit;
    }

    /* Random number functionality */
    testRandomNoFunction(&supportedOpcodes, moduleHandle, cryptoTokenHandle, 
            128, NULL, &randomData);

    /* Test PolicyStorage (NVRAM) */
    testPolicyStorage(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
            NVRAM_ID, NULL);

    /* Test AIK flow, todo pass credentials */
    testIdentityKeyGeneration(&supportedOpcodes, moduleHandle, akTokenHandle,
            NULL, randomData.pBuffer, 
            randomData.bufferLen > 32 ? 32 : randomData.bufferLen);

    for (keyType = 0; keyAttrList[keyType]; keyType++)
    {
        /*  TODO: Fix link error to TAP_SERIALIZE_freeDeserializedStructure
            if (createdKeyAttr.listLen)
            {
            TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_AttributeList,
            (ubyte *)&createdKeyAttr, sizeof(createdKeyAttr));
            }
         */
        pKeyAttr = keyAttrList[keyType];

        if (TAP_KEY_ALGORITHM_RSA == 
                *((TAP_KEY_ALGORITHM *)((keyAttrList[keyType]->pAttributeList))->pStructOfType))
        {
            /* Read in key parameters */
            status = createAsymmetricKey(&supportedOpcodes, moduleHandle, cryptoTokenHandle, keyObjectId,
                     pKeyAttr, keyInitFlag, &objectIdOut, &createdKeyAttr, &keyHandle);
  
            /*status = CALL_SMP_API_NO_RET(TPM2, createAsymmetricKey,moduleHandle, cryptoTokenHandle, objectId,
                    pKeyAttr, keyInitFlag, &keyObjectId, &createdKeyAttr, &keyHandle);*/
            if (OK != status)
            {
                LOG_ERROR("SMP_TPM2_createAsymKey failed with error %d", status);
                goto exit;
            }
            LOG_MESSAGE_NONL("SMP_TPM2_createAsymmetricKey is successful\n");

            /* Get Public Key */
            status = getPublicKey(&supportedOpcodes, moduleHandle, cryptoTokenHandle, keyHandle, &pPublicKey);
            /*status = CALL_SMP_API_NO_RET(TPM2, getPublicKey,moduleHandle, tokenHandle, keyHandle,
                    &pPublicKey);*/
            if (OK != status)
            {
                LOG_ERROR("SMP_TPM2_getPublicKey failed with error %d", status);
                goto exit;
            }
            LOG_MESSAGE_NONL("SMP_TPM2_getPublicKey is successful\n");
            if (pPublicKey)
                freePublicKey(&supportedOpcodes, &pPublicKey);
        }
        else
        {
            status = createSymmetricKey(&supportedOpcodes, moduleHandle, cryptoTokenHandle, keyObjectId,
                     pKeyAttr, keyInitFlag, &objectIdOut, &createdKeyAttr, &keyHandle);
            /*status = CALL_SMP_API_NO_RET(TPM2, createSymmetricKey,moduleHandle, tokenHandle, objectId,
                    pKeyAttr, keyInitFlag, &objectIdOut, &createdKeyAttr, &keyHandle);*/
            if (OK != status)
            {
                LOG_ERROR("SMP_TPM2_createSymmetricKey failed with error %d", status);
                goto exit;
            }
        }

        status = getKeyInfo(&createdKeyAttr, &keyInfo[keyType]);
        if (OK != status)
        {
            LOG_ERROR("getKeyInfo failed with error %d", status);
            goto exit;
        }

        if (keyBlob[keyType].blob.pBuffer)
            DIGI_FREE((void **)&keyBlob[keyType].blob.pBuffer);

        /* Serialized key into blob */
        status = exportObject(&supportedOpcodes, moduleHandle, cryptoTokenHandle, keyHandle, &keyBlob[keyType]);

        /*status = CALL_SMP_API_NO_RET(TPM2, exportObject,moduleHandle, tokenHandle, keyHandle,
                &keyBlob[keyType]);*/
        if (OK != status)
        {
            LOG_ERROR("SMP_TPM2_exportObject failed with error %d", status);
            goto exit;
        }
        else
            savedSignScheme[keyType] = keyInfo[keyType].sigScheme;

        /* Run test based on key type */
        if (TAP_KEY_USAGE_DECRYPT == keyInfo[keyType].keyUsage)
        {
           testKeyEncryptDecryptOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                   keyHandle, &generalDecryptKeyAttrList, &dataToEncrypt, 
                   &encryptedData, &decryptedData, "Decrypt key");

            if (decryptedData.pBuffer)
                DIGI_FREE((void **)&decryptedData.pBuffer);

            if (encryptedData.pBuffer)
                DIGI_FREE((void **)&encryptedData.pBuffer);
        }
        else if (TAP_KEY_USAGE_SIGNING == keyInfo[keyType].keyUsage)
        {
           testKeySignOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                   keyHandle, keyInfo[keyType].sigScheme, "Signing Key", 
                   randomData.pBuffer, SHA256_RESULT_SIZE);
        }
        else if (TAP_KEY_USAGE_GENERAL == keyInfo[keyType].keyUsage)
        {
            /* General key, use the first instance for decryption, 
               next to test signing
               */
            if (keyType)
            {
               testKeySignOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                       keyHandle, keyInfo[keyType].sigScheme, "General Key",
                       randomData.pBuffer, SHA256_RESULT_SIZE);
            }
            else
            {
               testKeyEncryptDecryptOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                       keyHandle, &generalDecryptKeyAttrList, &dataToEncrypt, 
                       &encryptedData, &decryptedData, "General key");
            }
            if (decryptedData.pBuffer)
                DIGI_FREE((void **)&decryptedData.pBuffer);

            if (encryptedData.pBuffer)
                DIGI_FREE((void **)&encryptedData.pBuffer);

        }
    }

    /* Test PCR Read and Update */
    testPCR(&supportedOpcodes, moduleHandle, cryptoTokenHandle);

    /* Test Digest */
    testDigest(&supportedOpcodes, moduleHandle, cryptoTokenHandle);

    /* Test Root of Trust */
    testRootOfTrust(&supportedOpcodes, moduleHandle, akTokenHandle, 
            akObjectList.entityIdList.pEntityIdList[0]);

    /* Self Test */
    testSelfTest(&supportedOpcodes, moduleHandle);

    /* Deinitialize context */
    status = uninitModule(&supportedOpcodes, moduleHandle);
    if (OK != status)
    {
        LOG_ERROR("SMP_TPM2_uninitModule call failed with error %d\n", status);
    }

    /* Test Import / Export functionality */
    for (keyType = 0; keyType < sizeof(keyBlob)/sizeof(TAP_Blob); keyType++)
    {
        /* Init */
        status = initModule(&supportedOpcodes, moduleList.entityIdList.pEntityIdList[0], &moduleHandle);
        if (OK != status)
        {
            LOG_ERROR("SMP_TPM2_initModule failed with error %d", status);
            goto exit;
        }
        isModuleInitialized = TRUE;

        LOG_MESSAGE("Importing key ...");

        /* Import object */
        status = importObject(&supportedOpcodes, moduleHandle, cryptoTokenHandle, &keyBlob[keyType], NULL, NULL, &keyHandle);
        /*status = CALL_SMP_API_NO_RET(TPM2, importObject,moduleHandle, tokenHandle,
                &keyBlob[keyType], NULL, NULL, &keyHandle);*/
        if (OK != status)
        {
            LOG_ERROR("SMP_TPM2_importObject failed with error %d", status);
            goto exit;
        }

        LOG_MESSAGE("Imported key successfully\n");

        if (TAP_KEY_USAGE_DECRYPT == keyInfo[keyType].keyUsage)
        {
            testKeyEncryptDecryptOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                    keyHandle, &decryptKeyAttrList, &dataToEncrypt, 
                    &encryptedData, &decryptedData, "Imported Decrypt Key");
        }
        else if (TAP_KEY_USAGE_SIGNING == keyInfo[keyType].keyUsage)
        {
           testKeySignOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                       keyHandle, savedSignScheme[keyType], "Imported Signing Key",
                       randomData.pBuffer, SHA256_RESULT_SIZE);
        }
        else if (TAP_KEY_USAGE_GENERAL == keyInfo[keyType].keyUsage)
        {
            /* General key, use the first instance for decryption, 
               next to test signing
               */
            if (keyType)
            {
               testKeySignOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                       keyHandle, keyInfo[keyType].sigScheme, "Imported General Key",
                       randomData.pBuffer, SHA256_RESULT_SIZE);
            }
            else
            {
               testKeyEncryptDecryptOperation(&supportedOpcodes, moduleHandle, cryptoTokenHandle,
                       keyHandle, &generalDecryptKeyAttrList, &dataToEncrypt, 
                       &encryptedData, &decryptedData, "Imported General key");
            }
        }

        if (decryptedData.pBuffer)
            DIGI_FREE((void **)&decryptedData.pBuffer);

        if (encryptedData.pBuffer)
            DIGI_FREE((void **)&encryptedData.pBuffer);

        /* Uninit */
        status = uninitModule(&supportedOpcodes, moduleHandle);
        if (OK != status)
        {
            LOG_ERROR("SMP_TPM2_uninitModule call failed with error %d\n", status);
        }
        isModuleInitialized = FALSE;
    }

    DIGI_FREE((void **)&randomData.pBuffer);
    retval = 0;
exit:
/*  TODO: Fix link error to TAP_SERIALIZE_freeDeserializedStructure
    if (pSignature)
    {
        TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_Signature,
                (ubyte *)pSignature, sizeof(*pSignature));
        DIGI_FREE((void **)&pSignature);
    }
    

    if (decryptedData.bufferLen)
    {
        TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_Buffer,
                (ubyte *)&decryptedData, sizeof(decryptedData));
    }

    if (encryptedData.bufferLen)
    {
        TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_Buffer,
                (ubyte *)&encryptedData, sizeof(encryptedData));
    }

    if (keyBlob.blob.bufferLen)
    {
        TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_Buffer,
                (ubyte *)&(keyBlob.blob), sizeof(keyBlob.blob));
    }

    if (createdKeyAttr.listLen)
    {
        TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_AttributeList,
                (ubyte *)&createdKeyAttr, sizeof(createdKeyAttr));
    }

    if (pPublicKey)
    {
        TAP_SERIALIZE_freeDeserializedStructure(&TAP_SHADOW_TAP_PublicKey,
                (ubyte *)pPublicKey, sizeof(*pPublicKey));
    }
*/
    if (TRUE == isModuleInitialized)
    {
        /* Uninitialze module if test exited without uninitializing */
        status = uninitModule(&supportedOpcodes, moduleHandle);
        if (OK != status)
        {
            LOG_ERROR("SMP_TPM2_uninitModule call failed with error %d\n", status);
        }
    }

    if (configInfo.configInfo.pBuffer)
        DIGICERT_freeReadFile(&configInfo.configInfo.pBuffer);

    if (moduleList.entityIdList.numEntities)
    {
        freeModuleList(&supportedOpcodes, &moduleList);
    }

    if (NULL != supportedOpcodes.pCmdList)
    {
        if (OK != DIGI_FREE((void **)&(supportedOpcodes.pCmdList)))
	{
            DB_PRINT("%s.%d Failed to free command list\n",
		    __FUNCTION__, __LINE__);
        }
        supportedOpcodes.listLen = 0;
    }
    return retval;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    cmdLineOpts *pOpts = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif

    DIGICERT_initDigicert();

    if (NULL == platCmdLineParser)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Test execution Failed\n");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("***** Test execution failed *****");

    DIGICERT_freeDigicert();
    return retval;
}

