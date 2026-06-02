/**
 * test_smptpm2_errors.c
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
 * @file       test_smptpm2_errors.c
 * @brief      Unit test application for SMP-TPM2 status-codes
 * @details    Unit test application for verifying the MSTATUS return codes
 *             returned by SMP-TPM2 mapped from TSS2_RC
 */

#include <stdio.h>
#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mdefs.h"

#include "../../../common/debug_console.h"

#include "../../../smp/smp_tpm2/tpm2_lib/tpm2_types.h"
#include "../../../smp/smp_tpm2/smp_tpm2_utils.h"

#define PRINT_HEADER(X)         printf("\n****************************************\n" \
                                       "%s" \
                                       "\n****************************************\n", \
                                       X);


typedef struct
{
    TSS2_RC testCode;
    MSTATUS status;
} SMP_TAP_ERR_CODE_ENTRY;

static void printStatus(SMP_TAP_ERR_CODE_ENTRY *pEntry,
			 MSTATUS statusCode)
{
    byteBoolean result = (statusCode == pEntry->status) ? TRUE : FALSE;
    printf("TSS2_RC(0x%08x) : MSTATUS(%d) : %s\n",
            pEntry->testCode, pEntry->status,
            result ? "PASSED" : "FAILED");
    if (FALSE == result)
    {
        DB_PRINT("\t**** FAILED ****:"
            "TSS2_RC  TPM2-Error-Code = 0x%08x, EXPECTED MSTATUS = %d, "
            "RETURNED MSTATUS = %d\n", pEntry->testCode, pEntry->status,
            statusCode);
    }
}

static int testTPMLevelFMT1ErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY fmtErrCodesTable[] = {
        /* Error codes for FMT1 category of errors */
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_FMT1), ERR_TAP_RC_FMT1},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_ASYMMETRIC), ERR_TAP_RC_ASYMMETRIC},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_ATTRIBUTES), ERR_TAP_RC_ATTRIBUTES},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_HASH), ERR_TAP_RC_HASH},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_VALUE), ERR_TAP_RC_VALUE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_HIERARCHY), ERR_TAP_RC_HIERARCHY},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_KEY_SIZE), ERR_TAP_RC_KEY_SIZE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_MGF), ERR_TAP_RC_MGF},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_MODE), ERR_TAP_RC_MODE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_TYPE), ERR_TAP_RC_TYPE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_HANDLE), ERR_TAP_RC_HANDLE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_KDF), ERR_TAP_RC_KDF},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_RANGE), ERR_TAP_RC_RANGE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_AUTH_FAIL), ERR_TAP_RC_AUTH_FAIL},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NONCE), ERR_TAP_RC_NONCE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_PP), ERR_TAP_RC_PP},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SCHEME), ERR_TAP_RC_SCHEME},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SIZE), ERR_TAP_RC_SIZE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SYMMETRIC), ERR_TAP_RC_SYMMETRIC},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_TAG), ERR_TAP_RC_TAG},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SELECTOR), ERR_TAP_RC_SELECTOR},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_INSUFFICIENT), ERR_TAP_RC_INSUFFICIENT},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SIGNATURE), ERR_TAP_RC_SIGNATURE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_KEY), ERR_TAP_RC_KEY},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_POLICY_FAIL), ERR_TAP_RC_POLICY_FAIL},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_INTEGRITY), ERR_TAP_RC_INTEGRITY},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_TICKET), ERR_TAP_RC_TICKET},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_RESERVED_BITS), ERR_TAP_RC_RESERVED_BITS},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_BAD_AUTH), ERR_TAP_RC_BAD_AUTH},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_EXPIRED), ERR_TAP_RC_EXPIRED},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_POLICY_CC), ERR_TAP_RC_POLICY_CC},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_BINDING), ERR_TAP_RC_BINDING},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_CURVE), ERR_TAP_RC_CURVE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_ECC_POINT), ERR_TAP_RC_ECC_POINT},
        /* Test some random unknown error-codes in the FMT1 category */
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_ECC_POINT+1), ERR_GENERAL},
        {-1, -1} /* Last entry */
    };

    pEntry = fmtErrCodesTable;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}

static int testTPMLevelWARNnFMT1ErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY fmtWarnErrCodesTable[] = {
        /* Error codes for FMT1 category of errors */
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_FMT1), ERR_TAP_RC_FMT1},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_ASYMMETRIC), ERR_TAP_RC_ASYMMETRIC},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_ATTRIBUTES), ERR_TAP_RC_ATTRIBUTES},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_HASH), ERR_TAP_RC_HASH},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_VALUE), ERR_TAP_RC_VALUE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_HIERARCHY), ERR_TAP_RC_HIERARCHY},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_KEY_SIZE), ERR_TAP_RC_KEY_SIZE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_MGF), ERR_TAP_RC_MGF},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_MODE), ERR_TAP_RC_MODE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_TYPE), ERR_TAP_RC_TYPE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_HANDLE), ERR_TAP_RC_HANDLE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_KDF), ERR_TAP_RC_KDF},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_RANGE), ERR_TAP_RC_RANGE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_AUTH_FAIL), ERR_TAP_RC_AUTH_FAIL},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_NONCE), ERR_TAP_RC_NONCE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_PP), ERR_TAP_RC_PP},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_SCHEME), ERR_TAP_RC_SCHEME},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_SIZE), ERR_TAP_RC_SIZE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_SYMMETRIC), ERR_TAP_RC_SYMMETRIC},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_TAG), ERR_TAP_RC_TAG},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_SELECTOR), ERR_TAP_RC_SELECTOR},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_INSUFFICIENT), ERR_TAP_RC_INSUFFICIENT},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_SIGNATURE), ERR_TAP_RC_SIGNATURE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_KEY), ERR_TAP_RC_KEY},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_POLICY_FAIL), ERR_TAP_RC_POLICY_FAIL},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_INTEGRITY), ERR_TAP_RC_INTEGRITY},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_TICKET), ERR_TAP_RC_TICKET},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_RESERVED_BITS), ERR_TAP_RC_RESERVED_BITS},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_BAD_AUTH), ERR_TAP_RC_BAD_AUTH},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_EXPIRED), ERR_TAP_RC_EXPIRED},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_POLICY_CC), ERR_TAP_RC_POLICY_CC},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_BINDING), ERR_TAP_RC_BINDING},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_CURVE), ERR_TAP_RC_CURVE},
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_ECC_POINT), ERR_TAP_RC_ECC_POINT},
        /* Test some random unknown error-codes in the FMT1 category */
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN | TPM2_RC_ECC_POINT+1), ERR_GENERAL},
        {-1, -1} /* Last entry */
    };

    pEntry = fmtWarnErrCodesTable;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}

static int testTPMLevelVER1ErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY ver1ErrCodesTable[] = {
        /* Error codes for VER1 category of errors */
        { (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_VER1), ERR_TAP_RC_VER1 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_INITIALIZE), ERR_TAP_RC_INITIALIZE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_FAILURE), ERR_TAP_RC_FAILURE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SEQUENCE), ERR_TAP_RC_SEQUENCE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_PRIVATE), ERR_TAP_RC_PRIVATE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_HMAC), ERR_TAP_RC_HMAC },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_DISABLED), ERR_TAP_RC_DISABLED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_EXCLUSIVE), ERR_TAP_RC_EXCLUSIVE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_AUTH_TYPE), ERR_TAP_RC_AUTH_TYPE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_AUTH_MISSING), ERR_TAP_RC_AUTH_MISSING },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_POLICY), ERR_TAP_RC_POLICY },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_PCR), ERR_TAP_RC_PCR },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_PCR_CHANGED), ERR_TAP_RC_PCR_CHANGED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_UPGRADE), ERR_TAP_RC_UPGRADE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_TOO_MANY_CONTEXTS), ERR_TAP_RC_TOO_MANY_CONTEXTS },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_AUTH_UNAVAILABLE), ERR_TAP_RC_AUTH_UNAVAILABLE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REBOOT), ERR_TAP_RC_REBOOT },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_UNBALANCED), ERR_TAP_RC_UNBALANCED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_COMMAND_SIZE), ERR_TAP_RC_COMMAND_SIZE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_COMMAND_CODE), ERR_TAP_RC_COMMAND_CODE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_AUTHSIZE), ERR_TAP_RC_AUTHSIZE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_AUTH_CONTEXT), ERR_TAP_RC_AUTH_CONTEXT },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_RANGE), ERR_TAP_RC_NV_RANGE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_SIZE), ERR_TAP_RC_NV_SIZE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_LOCKED), ERR_TAP_RC_NV_LOCKED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_AUTHORIZATION), ERR_TAP_RC_NV_AUTHORIZATION },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_UNINITIALIZED), ERR_TAP_RC_NV_UNINITIALIZED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_SPACE), ERR_TAP_RC_NV_SPACE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_DEFINED), ERR_TAP_NV_INDEX_EXISTS},
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_BAD_CONTEXT), ERR_TAP_RC_BAD_CONTEXT },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_CPHASH), ERR_TAP_RC_CPHASH },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_PARENT), ERR_TAP_RC_PARENT },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NEEDS_TEST), ERR_TAP_RC_NEEDS_TEST },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NO_RESULT), ERR_TAP_RC_NO_RESULT },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SENSITIVE), ERR_TAP_RC_SENSITIVE },

        /* Test some random unknown error-codes in the FMT1 category */
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_MAX_FM0), ERR_GENERAL },

        {-1, -1} /* Last entry */
    };

    pEntry = ver1ErrCodesTable;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}

static int testTPMLevelWARNErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY warnErrCodesTable[] = {
        /* Error codes for WARN category of errors */
		{(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_WARN), ERR_TAP_RC_WARN},
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_CONTEXT_GAP), ERR_TAP_RC_CONTEXT_GAP },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_OBJECT_MEMORY), ERR_TAP_RC_OBJECT_MEMORY },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SESSION_MEMORY), ERR_TAP_RC_SESSION_MEMORY },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_MEMORY), ERR_TAP_RC_MEMORY },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SESSION_HANDLES), ERR_TAP_RC_SESSION_HANDLES },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_OBJECT_HANDLES), ERR_TAP_RC_OBJECT_HANDLES },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_LOCALITY), ERR_TAP_RC_LOCALITY },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_YIELDED), ERR_TAP_RC_YIELDED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_CANCELED), ERR_TAP_RC_CANCELED },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_TESTING), ERR_TAP_RC_TESTING },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H0), ERR_TAP_RC_REFERENCE_H0 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H1), ERR_TAP_RC_REFERENCE_H1 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H2), ERR_TAP_RC_REFERENCE_H2 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H3), ERR_TAP_RC_REFERENCE_H3 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H4), ERR_TAP_RC_REFERENCE_H4 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H5), ERR_TAP_RC_REFERENCE_H5 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_H6), ERR_TAP_RC_REFERENCE_H6 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S0), ERR_TAP_RC_REFERENCE_S0 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S1), ERR_TAP_RC_REFERENCE_S1 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S2), ERR_TAP_RC_REFERENCE_S2 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S3), ERR_TAP_RC_REFERENCE_S3 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S4), ERR_TAP_RC_REFERENCE_S4 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S5), ERR_TAP_RC_REFERENCE_S5 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_REFERENCE_S6), ERR_TAP_RC_REFERENCE_S6 },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_RATE), ERR_TAP_RC_NV_RATE },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_LOCKOUT), ERR_TAP_RC_LOCKOUT },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_RETRY), ERR_TAP_RC_RETRY },
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NV_UNAVAILABLE), ERR_TAP_RC_NV_UNAVAILABLE },
        /* Test some random unknown error-codes in the FMT1 category */
		{ (TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_NOT_USED), ERR_TAP_RC_NOT_USED },
        /* Last entry */
        {-1, -1}
    };

    pEntry = warnErrCodesTable;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}

static int testSysLevelErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY sysLevelErrTbl[] = {
        /* Error codes for SYS category of errors */
		{ TSS2_SYS_RC_GENERAL_FAILURE, ERR_TAP_RC_SYS_GENERAL_FAILURE },
		{ TSS2_SYS_RC_BAD_CONTEXT, ERR_TAP_RC_SYS_BAD_CONTEXT },
		{ TSS2_SYS_RC_ABI_MISMATCH, ERR_TAP_RC_SYS_ABI_MISMATCH },
		{ TSS2_SYS_RC_BAD_REFERENCE, ERR_TAP_RC_SYS_BAD_REFERENCE },
		{ TSS2_SYS_RC_INSUFFICIENT_BUFFER, ERR_TAP_RC_SYS_INSUFFICIENT_BUFFER },
		{ TSS2_SYS_RC_BAD_SEQUENCE, ERR_TAP_RC_SYS_BAD_SEQUENCE },
		{ TSS2_SYS_RC_IO_ERROR, ERR_TAP_RC_SYS_IO_ERROR },
		{ TSS2_SYS_RC_BAD_VALUE, ERR_TAP_RC_SYS_BAD_VALUE },
		{ TSS2_SYS_RC_NOT_PERMITTED, ERR_TAP_RC_SYS_NOT_PERMITTED },
		{ TSS2_SYS_RC_INVALID_SESSIONS, ERR_TAP_RC_SYS_INVALID_SESSIONS },
		{ TSS2_SYS_RC_NO_DECRYPT_PARAM, ERR_TAP_RC_SYS_NO_DECRYPT_PARAM },
		{ TSS2_SYS_RC_NO_ENCRYPT_PARAM, ERR_TAP_RC_SYS_NO_ENCRYPT_PARAM },
		{ TSS2_SYS_RC_BAD_SIZE, ERR_TAP_RC_SYS_BAD_SIZE },
		{ TSS2_SYS_RC_MALFORMED_RESPONSE, ERR_TAP_RC_SYS_MALFORMED_RESPONSE },
		{ TSS2_SYS_RC_INSUFFICIENT_CONTEXT, ERR_TAP_RC_SYS_INSUFFICIENT_CONTEXT },
		{ TSS2_SYS_RC_INSUFFICIENT_RESPONSE, ERR_TAP_RC_SYS_INSUFFICIENT_RESPONSE },
		{ TSS2_SYS_RC_INCOMPATIBLE_TCTI, ERR_TAP_RC_SYS_INCOMPATIBLE_TCTI },
		{ TSS2_SYS_RC_NOT_SUPPORTED, ERR_TAP_RC_SYS_NOT_SUPPORTED },
		{ TSS2_SYS_RC_BAD_TCTI_STRUCTURE, ERR_TAP_RC_SYS_BAD_TCTI_STRUCTURE },
	    /* Test some random unknown error-codes in the FMT1 category */
		{ TSS2_SYS_RC_BAD_TCTI_STRUCTURE + 1, ERR_GENERAL },
        /* Last entry */
        {-1, -1}
    };

    pEntry = sysLevelErrTbl;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}

static int testTctiLevelErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY tctiLevelErrTbl[] = {
        /* Error codes for TCTI category of errors */
		{ TSS2_TCTI_RC_GENERAL_FAILURE, ERR_TAP_RC_TCTI_GENERAL_FAILURE },
		{ TSS2_TCTI_RC_BAD_CONTEXT, ERR_TAP_RC_TCTI_BAD_CONTEXT },
		{ TSS2_TCTI_RC_ABI_MISMATCH, ERR_TAP_RC_TCTI_ABI_MISMATCH },
		{ TSS2_TCTI_RC_BAD_REFERENCE, ERR_TAP_RC_TCTI_BAD_REFERENCE },
		{ TSS2_TCTI_RC_INSUFFICIENT_BUFFER, ERR_TAP_RC_TCTI_INSUFFICIENT_BUFFER },
		{ TSS2_TCTI_RC_BAD_SEQUENCE, ERR_TAP_RC_TCTI_BAD_SEQUENCE },
		{ TSS2_TCTI_RC_IO_ERROR, ERR_TAP_RC_TCTI_IO_ERROR },
		{ TSS2_TCTI_RC_BAD_VALUE, ERR_TAP_RC_TCTI_BAD_VALUE },
		{ TSS2_TCTI_RC_NOT_PERMITTED, ERR_TAP_RC_TCTI_NOT_PERMITTED },
		{ TSS2_TCTI_RC_MALFORMED_RESPONSE, ERR_TAP_RC_TCTI_MALFORMED_RESPONSE },
		{ TSS2_TCTI_RC_NOT_SUPPORTED, ERR_TAP_RC_TCTI_NOT_SUPPORTED },
	    /* Test some random unknown error-codes in the FMT1 category */
		{ (TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | TSS2_BASE_RC_BAD_TCTI_STRUCTURE+1), ERR_GENERAL },
        /* Last entry */
        {-1, -1}
    };

    pEntry = tctiLevelErrTbl;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}

static int testFapiLevelErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY fapiLevelErrTbl[] = {
        /* Error codes for FAPI category of errors */
		{ TSS2_FAPI_RC_GENERAL_FAILURE, ERR_TAP_RC_FAPI_GENERAL_FAILURE },
		{ TSS2_FAPI_RC_BAD_CONTEXT, ERR_TAP_RC_FAPI_BAD_CONTEXT },
		{ TSS2_FAPI_RC_ABI_MISMATCH, ERR_TAP_RC_FAPI_ABI_MISMATCH },
		{ TSS2_FAPI_RC_BAD_REFERENCE, ERR_TAP_RC_FAPI_BAD_REFERENCE },
		{ TSS2_FAPI_RC_INSUFFICIENT_BUFFER, ERR_TAP_RC_FAPI_INSUFFICIENT_BUFFER },
		{ TSS2_FAPI_RC_BAD_SEQUENCE, ERR_TAP_RC_FAPI_BAD_SEQUENCE },
		{ TSS2_FAPI_RC_IO_ERROR, ERR_TAP_RC_FAPI_IO_ERROR },
		{ TSS2_FAPI_RC_BAD_VALUE, ERR_TAP_RC_FAPI_BAD_VALUE },
		{ TSS2_FAPI_RC_NOT_PERMITTED, ERR_TAP_RC_FAPI_NOT_PERMITTED },
		{ TSS2_FAPI_RC_MALFORMED_RESPONSE, ERR_TAP_RC_FAPI_MALFORMED_RESPONSE },
		{ TSS2_FAPI_RC_NOT_SUPPORTED, ERR_TAP_RC_FAPI_NOT_SUPPORTED },
        /* Last entry */
        {-1, -1}
    };

    pEntry = fapiLevelErrTbl;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;
}


static int testTpmGeneralErrorCodes()
{
    int failure_count=0;
    SMP_TAP_ERR_CODE_ENTRY *pEntry = NULL;
    MSTATUS statusCode;

    SMP_TAP_ERR_CODE_ENTRY tpmGeneralCodesTable[] = {
        /* Success Case*/
        {(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_SUCCESS), OK},
        /* Bad Tag */
        {(TSS2_RC)(TSS2_TPM_RC_LEVEL | TPM2_RC_BAD_TAG), ERR_GENERAL},
        /* Last entry */
        {-1, -1}
    };

    pEntry = tpmGeneralCodesTable;
    while (NULL != pEntry && -1 != pEntry->testCode)
    {
        /* get digicert error code */
        statusCode =
            SMP_TPM2_UTILS_getMocanaError(pEntry->testCode);
        printStatus(pEntry, statusCode);
        /* Explicitly print failures */
        if (statusCode != pEntry->status)
        {
            failure_count++;
        }
        pEntry++;
    }

    return failure_count;

}

int main(int argc, char **argv)
{
    int failure_count=0;
    int total_failures=0;

    /* Test TPM FMT1 error codes */
    PRINT_HEADER("TPM Level - FMT1 category Error Codes");
    failure_count = testTPMLevelFMT1ErrorCodes();
    printf("\n %d Failures in TPM level's FMT1 error codes\n", failure_count);
    total_failures += failure_count;

    /* Test TPM VER1 error codes */
    PRINT_HEADER("TPM Level - VER1 category Error Codes");
    failure_count = testTPMLevelVER1ErrorCodes();
    printf("\n %d Failures in TPM level's VER1  error codes\n", failure_count);
    total_failures += failure_count;

    /* Test TPM WARN error codes */
    PRINT_HEADER("TPM Level - WARN category Error Codes");
    failure_count=testTPMLevelWARNErrorCodes();
    printf("\n %d Failures in TPM level's WARN error codes\n", failure_count);
    total_failures += failure_count;

    /* Test TPM WARN|FMT1 error codes
     * FMT1 error codes could be masked as warning+fmt1 type errors */
    PRINT_HEADER("TPM Level - WARN|FMT1 category Error Codes");
    failure_count=testTPMLevelWARNnFMT1ErrorCodes();
    printf("\n %d Failures in TPM level's WARN|FMT1 error codes\n", failure_count);
    total_failures += failure_count;

    /* Test SYS Level error codes */
    PRINT_HEADER("SYS/SAPI Level Error Codes");
    failure_count=testSysLevelErrorCodes();
    printf("\n %d Failures in SYS/SAPI level error codes\n", failure_count);
    total_failures += failure_count;

    /* Test TCTI Level error codes */
    PRINT_HEADER("TCTI Level Error Codes");
    failure_count=testTctiLevelErrorCodes();
    printf("\n %d Failures in TCTI level error codes\n", failure_count);
    total_failures += failure_count;

    /* Test FAPI Level error codes */
    PRINT_HEADER("FAPI Level Error Codes");
    failure_count=testFapiLevelErrorCodes();
    printf("\n %d Failures in FAPI level error codes\n", failure_count);
    total_failures += failure_count;

    /* Test other TPM error codes */
    PRINT_HEADER("TPM general Error Codes");
    failure_count=testTpmGeneralErrorCodes();
    printf("\n %d Failures in TPM general error codes\n", failure_count);
    total_failures += failure_count;

    printf("\n****************************************\n"
           "TOTAL FAILURE = %d"
           "\n****************************************\n",
            total_failures);

    return total_failures;
}

