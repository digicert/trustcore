/**
 * @file fapi2_admin.c
 * @brief This file contains code and structures required for provisioning
 * the TPM2.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
 */
#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../crypto/hw_accel.h"
#include "../../../../common/debug_console.h"
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2_dispatcher.h"
#include "fapi2.h"
#include "fapi2_internal.h"

typedef TSS2_RC (*noArgFunc)(FAPI2_CONTEXT *pCtx);
typedef TSS2_RC (*oneArgFunc)(FAPI2_CONTEXT *pCtx, void *pInOrOut);
typedef TSS2_RC (*twoArgFunc)(FAPI2_CONTEXT *pCtx, void *pIn, void *pOut);

typedef enum {
    DISPATCH_FUNC_TYPE_INVALID,
    DISPATCH_FUNC_TYPE_NOARG,
    DISPATCH_FUNC_TYPE_ONEARG,
    DISPATCH_FUNC_TYPE_TWOARG,
    DISPATCH_FUNC_TYPE_END
} DispatchFuncType;

typedef union {
    noArgFunc noArg;
    oneArgFunc oneArg;
    twoArgFunc twoArg;
} DispatchFunc;

typedef struct {
    FAPI2_CC commandCode;
    DispatchFuncType funcType;
    DispatchFunc dispatchFunc;
    ubyte4 inSize;
    ubyte4 outSize;
} DispatchTable;

#pragma GCC diagnostic ignored "-Wcast-function-type"

/*
 * Note: Getting the table right is absolutely critical to code
 * security. This method of dispatching does not provide compiler enforced
 * type safety for the function pointer whatsoever so a wrong function
 * pointer or wrong funcType entry in the table, or pretty much any
 * wrong entry in the table, could lead to horrible bugs.
 * The choice for the dispatcher is either to use generic function
 * pointer definitions, or to convert all the definitions of the FAPI
 * functions to take in void * and cast it internally. Changing all FAPI
 * to use void * would be very inconvenient for users who invoke FAPI
 * directly. Using the dispatcher with void * function pointers and
 * type casting the function pointers on the other hand provides
 * flexibility. It just requires careful writing of the DispatchTable.
 */
const DispatchTable dispatchTable[] =
{
        {FAPI2_CC_INVALID, DISPATCH_FUNC_TYPE_INVALID, { NULL }, 0, 0},

        {
                .commandCode = FAPI2_CC_RNG_GET_RANDOM,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_RNG_getRandomData},
                .inSize = sizeof(RngGetRandomDataIn),
                .outSize = sizeof(RngGetRandomDataOut),
        },

        {
                .commandCode = FAPI2_CC_RNG_STIR_RANDOM,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_RNG_stirRNG},
                .inSize = sizeof(RngStirRNGIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_ASYM_CREATE_KEY,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_createAsymKey},
                .inSize = sizeof(AsymCreateKeyIn),
                .outSize = sizeof(AsymCreateKeyOut),
        },

        {
                .commandCode = FAPI2_CC_ASYM_SIGN,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_sign},
                .inSize = sizeof(AsymSignIn),
                .outSize = sizeof(AsymSignOut),
        },

        {
                .commandCode = FAPI2_CC_ASYM_VERIFY_SIG,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_verifySig},
                .inSize = sizeof(AsymVerifySigIn),
                .outSize = sizeof(AsymVerifySigOut),
        },

        {
                .commandCode = FAPI2_CC_ASYM_RSA_ENCRYPT,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_RSAencrypt},
                .inSize = sizeof(AsymRsaEncryptIn),
                .outSize = sizeof(AsymRsaEncryptOut),
        },

        {
                .commandCode = FAPI2_CC_ASYM_RSA_DECRYPT,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_RSAdecrypt},
                .inSize = sizeof(AsymRsaDecryptIn),
                .outSize = sizeof(AsymRsaDecryptOut),
        },

        {
                .commandCode = FAPI2_CC_ADMIN_TAKE_OWNERSHIP,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_ADMIN_takeOwnership},
                .inSize = sizeof(AdminTakeOwnershipIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_ADMIN_RELEASE_OWNERSHIP,
                .funcType = DISPATCH_FUNC_TYPE_NOARG,
                .dispatchFunc = {.noArg = (noArgFunc)FAPI2_ADMIN_releaseOwnership},
                .inSize = 0,
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_ADMIN_CREATE_EK,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_ADMIN_createEK},
                .inSize = sizeof(AdminCreateEKIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_ADMIN_CREATE_SRK,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_ADMIN_createSRK},
                .inSize = sizeof(AdminCreateSRKIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_ADMIN_CREATE_AK,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_ADMIN_createAK},
                .inSize = sizeof(AdminCreateAKIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_SET_HIERARCHY_AUTH,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_setHierarchyAuth},
                .inSize = sizeof(ContextSetHierarchyAuthIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_SET_PRIMARY_KEY_AUTH,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_setPrimaryKeyAuth},
                .inSize = sizeof(ContextSetPrimaryKeyAuthIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_GET_AUTHVALUE_LEN,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_getMaxAuthValueLength},
                .inSize = 0,
                .outSize = sizeof(ContextGetAuthValueLengthOut),
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_LOAD_OBJECT,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_CONTEXT_loadObject},
                .inSize = sizeof(ContextLoadObjectIn),
                .outSize = sizeof(ContextLoadObjectOut),
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_FLUSH_OBJECT,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_flushObject},
                .inSize = sizeof(ContextFlushObjectIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_DATA_SEAL,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_DATA_seal},
                .inSize = sizeof(DataSealIn),
                .outSize = sizeof(DataSealOut),
        },

        {
                .commandCode = FAPI2_CC_DATA_UNSEAL,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_DATA_unseal},
                .inSize = sizeof(DataUnsealIn),
                .outSize = sizeof(DataUnsealOut),
        },

        {
                .commandCode = FAPI2_CC_MGMT_GETCAP,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_MGMT_getCapability},
                .inSize = sizeof(MgmtCapabilityIn),
                .outSize = sizeof(MgmtCapabilityOut),
        },

        {
                .commandCode = FAPI2_CC_MGMT_GET_PCR_SELECTION,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_MGMT_getPCRSelection},
                .inSize = sizeof(MgmtGetPcrSelectionIn),
                .outSize = sizeof(MgmtGetPcrSelectionOut),
        },

        {
                .commandCode = FAPI2_CC_NV_DEFINE,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_NV_define},
                .inSize = sizeof(NVDefineIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_NV_WRITEOP,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_NV_writeOp},
                .inSize = sizeof(NVWriteOpIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_NV_READOP,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_NV_readOp},
                .inSize = sizeof(NVReadOpIn),
                .outSize = sizeof(NVReadOpOut),
        },

        {
                .commandCode = FAPI2_CC_NV_UNDEFINE,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_NV_undefine},
                .inSize = sizeof(NVUndefineIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_GET_LAST_TPM_ERROR,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_getLastTpmError},
                .inSize = 0,
                .outSize = sizeof(ContextGetLastTpmErrorOut),
        },

        {
                .commandCode = FAPI2_CC_SYM_CREATE_CIPHER_KEY,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_SYM_createCipherKey},
                .inSize = sizeof(SymCreateCipherKeyIn),
                .outSize = sizeof(SymCreateCipherKeyOut),
        },

        {
                .commandCode = FAPI2_CC_SYM_CREATE_SIGNING_KEY,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_SYM_createSigningKey},
                .inSize = sizeof(SymCreateSigningKeyIn),
                .outSize = sizeof(SymCreateSigningKeyOut),
        },

        {
                .commandCode = FAPI2_CC_SYM_ENCRYPT_DECRYPT,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_SYM_encryptDecrypt},
                .inSize = sizeof(SymEncryptDecryptIn),
                .outSize = sizeof(SymEncryptDecryptOut),
        },

        {
                .commandCode = FAPI2_CC_SYM_SIGN,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_SYM_sign},
                .inSize = sizeof(SymSignIn),
                .outSize = sizeof(SymSignOut),
        },

        {
                .commandCode = FAPI2_CC_SYM_VERIFY_SIG,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_SYM_verifySig},
                .inSize = sizeof(SymVerifySigIn),
                .outSize = sizeof(SymVerifySigOut),
        },

        {
                .commandCode = FAPI2_CC_ASYM_GET_PUBLIC_KEY,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_getPublicKey},
                .inSize = sizeof(AsymGetPublicKeyIn),
                .outSize = sizeof(AsymGetPublicKeyOut),
        },

        {
                .commandCode = FAPI2_CC_ADMIN_GET_PRIMARY_PUBLIC_KEY,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ADMIN_getPrimaryPublicKey},
                .inSize = sizeof(AdminGetPrimaryPublicKeyIn),
                .outSize = sizeof(AdminGetPrimaryPublicKeyOut),
        },

        {
                .commandCode = FAPI2_CC_DATA_DIGEST,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_DATA_digest},
                .inSize = sizeof(DataDigestIn),
                .outSize = sizeof(DataDigestOut),
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_IS_TPM_PROVISIONED,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_isTpmProvisioned},
                .inSize = 0,
                .outSize = sizeof(ContextIsTpmProvisionedOut),
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_GET_PRIMARY_OBJECT_NAME,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_CONTEXT_getPrimaryObjectName},
                .inSize = sizeof(ContextGetPrimaryObjectNameIn),
                .outSize = sizeof(ContextGetPrimaryObjectNameOut),
        },

        {
                .commandCode = FAPI2_CC_CONTEXT_SET_OBJECT_AUTH,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_CONTEXT_setObjectAuth},
                .inSize = sizeof(ContextSetObjectAuthIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_ASYM_RESTRICTED_SIGN,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ASYM_restrictedSign},
                .inSize = sizeof(AsymRestrictedSignIn),
                .outSize = sizeof(AsymRestrictedSignOut),
        },

        {
                .commandCode = FAPI2_CC_ATTESTATION_GET_QUOTE,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_ATTESTATION_getQuote},
                .inSize = sizeof(AttestationGetQuoteIn),
                .outSize = sizeof(AttestationGetQuoteOut),
        },

        {
                .commandCode = FAPI2_CC_CREDENTIAL_ACTIVATE,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_CREDENTIAL_activate},
                .inSize = sizeof(CredentialActivateIn),
                .outSize = sizeof(CredentialActivateOut),
        },

        {
                .commandCode = FAPI2_CC_CREDENTIAL_MAKE,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_CREDENTIAL_make},
                .inSize = sizeof(CredentialMakeIn),
                .outSize = sizeof(CredentialMakeOut),
        },

        {
                .commandCode = FAPI2_CC_NV_READ_PUBLC,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_NV_readPublic},
                .inSize = sizeof(NVReadPubIn),
                .outSize = sizeof(NVReadPubOut),
        },

        {
                .commandCode = FAPI2_CC_TESTING_SELF_TEST,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_TESTING_SelfTest},
                .inSize = sizeof(TestingSelfTestIn),
                .outSize = sizeof(TestingSelfTestOut),
        },

        {
                .commandCode = FAPI2_CC_TESTING_GET_TEST_RESULT,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_TESTING_getTestResult},
                .inSize = 0,
                .outSize = sizeof(TestingSelfTestOut),
        },

        {
                .commandCode = FAPI2_CC_CREDENTIAL_GET_CSR_ATTR,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_CREDENTIAL_getCSRAttr},
                .inSize = sizeof(CredentialGetCsrAttrIn),
                .outSize = sizeof(CredentialGetCsrAttrOut),
        },

        {
                .commandCode = FAPI2_CC_CREDENTIAL_UNWRAP_SECRET,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_CREDENTIAL_unwrapSecret},
                .inSize = sizeof(CredentialUnwrapSecretIn),
                .outSize = sizeof(CredentialUnwrapSecretOut),
        },

        {
                .commandCode = FAPI2_CC_INTEGRITY_PCR_RESET,
                .funcType = DISPATCH_FUNC_TYPE_ONEARG,
                .dispatchFunc = {.oneArg = (oneArgFunc)FAPI2_INTEGRITY_pcrReset},
                .inSize = sizeof(IntegrityPcrResetIn),
                .outSize = 0,
        },

        {
                .commandCode = FAPI2_CC_INTEGRITY_PCR_READ,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_INTEGRITY_pcrRead},
                .inSize = sizeof(IntegrityPcrReadIn),
                .outSize = sizeof(IntegrityPcrReadOut),
        },

        {
                .commandCode = FAPI2_CC_INTEGRITY_PCR_EXTEND,
                .funcType = DISPATCH_FUNC_TYPE_TWOARG,
                .dispatchFunc = {.twoArg = (twoArgFunc)FAPI2_INTEGRITY_pcrExtend},
                .inSize = sizeof(IntegrityPcrExtendIn),
                .outSize = 0,
        },

        {FAPI2_CC_END, DISPATCH_FUNC_TYPE_INVALID, { NULL }, 0, 0},
};

TSS2_RC FAPI2_DISPATCHER_lookupCmdRspSize(
        FAPI2_CC cmdCode,
        ubyte4 *cmdSize,
        ubyte4 *rspSize
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((cmdCode <= FAPI2_CC_INVALID) || (cmdCode >= FAPI2_CC_END))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid command code, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (cmdSize)
        *cmdSize = dispatchTable[cmdCode].inSize;

    if (rspSize)
        *rspSize = dispatchTable[cmdCode].outSize;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC FAPI2_DISPATCHER_dispatch(
        FAPI2_CONTEXT *pCtx,
        FAPI2_CC commandCode,
        void *pIn,
        ubyte4 inSize,
        void *pOut,
        ubyte4 outSize
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    const DispatchTable *pTableEntry = NULL;

    if (!pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((commandCode <= FAPI2_CC_INVALID) || (commandCode >= FAPI2_CC_END))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid command code, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pTableEntry = &dispatchTable[commandCode];

    if ((inSize != pTableEntry->inSize) || ((outSize != pTableEntry->outSize)))
    {
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid in/out size for command code, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    switch (pTableEntry->funcType)
    {
    case DISPATCH_FUNC_TYPE_NOARG:
        rc = pTableEntry->dispatchFunc.noArg(pCtx);
        break;
    case DISPATCH_FUNC_TYPE_ONEARG:
        if (pIn && (inSize != 0))
        {
            rc = pTableEntry->dispatchFunc.oneArg(pCtx, pIn);
        }
        else
        {
            if (pOut && (outSize != 0))
                rc = pTableEntry->dispatchFunc.oneArg(pCtx, pOut);
        }
        break;
    case DISPATCH_FUNC_TYPE_TWOARG:
        rc = pTableEntry->dispatchFunc.twoArg(pCtx, pIn, pOut);
        break;
    default:
        rc = TSS2_SYS_RC_ABI_MISMATCH;
        DB_PRINT("%s.%d Internal FAPI error. Unknown func type. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
        break;
    }
exit:
    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
