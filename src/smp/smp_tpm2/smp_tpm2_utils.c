/*
 * smp_tpm2_utils.c
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
#include "../../common/moptions.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__))
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"

#include "../../smp/smp_tpm2/tpm2_lib/tpm2_types.h"
#include "../../smp/smp_tpm2/tpm2_lib/tpm_common/tss2_error.h"

/* TPM Level error per category highest known error code */
#define TPM2_RC_FMT1_MAX_KNOWN_CODE     TPM2_RC_ECC_POINT
#define TPM2_RC_VER1_MAX_KNOWN_CODE     TPM2_RC_SENSITIVE
#define TPM2_RC_WARN_MAX_KNOWN_CODE     TPM2_RC_NV_UNAVAILABLE

/* TPM Base/common highest error code for all Levels */
#define TPM2_BASE_RC_MAX_KNOWN_OFFSET   TSS2_BASE_RC_BAD_TCTI_STRUCTURE


/* Maps TPM Level error codes to Digicert error codes */
static MSTATUS getTpmLevelErrorCode(ubyte2 tpmError)
{
    MSTATUS errorCode=ERR_GENERAL;
    ubyte2 offset=0;
    /* Error category are the bytes except for the error-bits (least 7 bits) */
    ubyte2 errClass = tpmError & ~(0x7f);

    /* Set status accroding to the error category/class */
    switch (errClass)
    {
        case (TPM2_RC_FMT1):
        {
            if (TPM2_RC_FMT1_MAX_KNOWN_CODE < tpmError)
            {
                /*To-Review: Should we define a new code for UNKNOWN error codes */
                errorCode = ERR_GENERAL;
            }
            else
            {
                offset = tpmError - TPM2_RC_FMT1;
                errorCode = ERR_TAP_RC_FMT1 + offset;
            }
        }
        break;

        case (TPM2_RC_VER1):
        {
            if (TPM2_RC_VER1_MAX_KNOWN_CODE < tpmError)
            {
                /*To-Review: Should we define a new code for UNKNOWN error codes */
                errorCode = ERR_GENERAL;
            }
            else
            {
                offset = tpmError - TPM2_RC_VER1;
                errorCode = ERR_TAP_RC_VER1 + offset;
            }
        }
        break;

        case(TPM2_RC_WARN):
        {
            if ((TPM2_RC_WARN_MAX_KNOWN_CODE >= tpmError)
                    || (TPM2_RC_NOT_USED == tpmError))
            {
                offset = tpmError - TPM2_RC_WARN;
                errorCode = ERR_TAP_RC_WARN + offset;
            }
            else
            {
                /*To-Review: Should we define a new code for UNKNOWN error codes */
                errorCode = ERR_GENERAL;
            }
        }
        break;

        case(TPM2_RC_WARN | TPM2_RC_FMT1):
        {
            offset = tpmError - (TPM2_RC_WARN | TPM2_RC_FMT1);
            if ((TPM2_RC_FMT1_MAX_KNOWN_CODE - TPM2_RC_FMT1) < offset)
            {
                /*To-Review: Should we define a new code for UNKNOWN error codes */
                errorCode = ERR_GENERAL;
            }
            else
            {
                errorCode = ERR_TAP_RC_FMT1 + offset;
            }
        }
        break;

        default:
            errorCode=ERR_GENERAL;
            break;
    }

    return errorCode;
}

/* Maps SYS (SAPI) Level error codes to Digicert error codes */
static MSTATUS getSysLevelErrorCode(ubyte2 tpmError)
{
    MSTATUS errorCode=ERR_GENERAL;
    ubyte2 offset=tpmError;

    if (TPM2_BASE_RC_MAX_KNOWN_OFFSET < offset)
    {
        /*To-Review: Should we define a new code for UNKNOWN error codes */
        errorCode = ERR_GENERAL;
    }
    else
    {
        errorCode = ERR_TAP_RC_SYS + offset;
    }

    return errorCode;
}

/* Maps TCTI Level error codes to Digicert error codes */
static MSTATUS getTctiLevelErrorCode(ubyte2 tpmError)
{
    MSTATUS errorCode=ERR_GENERAL;
    ubyte2 offset=tpmError;

    if (TPM2_BASE_RC_MAX_KNOWN_OFFSET < offset)
    {
        /*To-Review: Should we define a new code for UNKNOWN error codes */
        errorCode = ERR_GENERAL;
    }
    else
    {
        errorCode = ERR_TAP_RC_TCTI + offset;
    }

    return errorCode;
}

/* Maps FAPI Level error codes to Digicert error codes */
static MSTATUS getFapiLevelErrorCode(ubyte2 tpmError)
{
    MSTATUS errorCode=ERR_GENERAL;
    ubyte2 offset=tpmError;

    if (TPM2_BASE_RC_MAX_KNOWN_OFFSET < offset)
    {
        errorCode = ERR_GENERAL;
    }
    else
    {
        errorCode = ERR_TAP_RC_FAPI + offset;
    }

    return errorCode;
}

/* Returns MSTATUS for TAP layer */
MSTATUS SMP_TPM2_UTILS_getMocanaError(TSS2_RC smpErrorCode)
{
    MSTATUS errorCode = ERR_GENERAL;
    ubyte2  tpmError = 0;
    ubyte4  tpmErrLevel = TSS2_TPM_RC_LEVEL;

    /* Return OK if rc is success */
    if (TSS2_RC_SUCCESS == smpErrorCode)
    {
        errorCode = OK;
        goto exit;
    }

    /* Get the Error-Level BYTE */
    tpmErrLevel = TSS2_RC_LEVEL(smpErrorCode);
    /* Get the last 2 bytes representing the error code and class/category */
    tpmError= smpErrorCode & 0xffff;

    switch(tpmErrLevel)
    {
        case TSS2_TPM_RC_LEVEL:
            errorCode = getTpmLevelErrorCode(tpmError);
            break;

        case TSS2_SYS_ERROR_LEVEL:
            errorCode = getSysLevelErrorCode(tpmError);
            break;

        case TSS2_TCTI_ERROR_LEVEL:
            errorCode = getTctiLevelErrorCode(tpmError);
            break;

        case TSS2_SYS_PART2_RC_LEVEL:
            errorCode = getFapiLevelErrorCode(tpmError);
            break;

        default:
            errorCode = ERR_GENERAL;
            break;
    }

exit:
    return errorCode;
}

#endif /*__ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_TPM2__*/
