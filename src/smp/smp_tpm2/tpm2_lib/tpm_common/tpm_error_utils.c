/*
 * tpm_error_utils.c
 *
 * Error utility functions needed by TPM 1.2 code
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

#if (defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__))

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#define __ENABLE_DIGICERT_TPM2__
#endif

#include "../../../../common/mtypes.h"
#include "../../../../common/mocana.h"
#include "../../../../common/merrors.h"
#include "../../../../common/base64.h"
#include "../../../../common/debug_console.h"

#include "tpm_error_utils.h"
#include "../tpm_common/tss2_error.h"

/**
 * @internal
 * @brief Helper/Debug function to print out text string for a TPM 2.0 return code
 *
 * @note  2.0 has 2 types of response codes:
 *         Format 0: lower 7 bits is actual error code
 *         Format 1: lower 6 bits is actual error code (bit 6 indicates parameter association)
 *         Bit 7 = format bit indicating which format to use
 */
char *tss2_err_string(TSS2_RC rc)
{
    int format = TSS2_RC_FORMAT(rc);
    int errCode = 0;
    int rcLevel = TSS2_RC_LEVEL(rc);
    
    /* Get base error code based on format */
    if (0 == format)
        errCode = TSS2_RC_ERROR_FORMAT0(rc);
    else
        errCode = TSS2_RC_ERROR_FORMAT1(rc);

    /* First check for the common return code for all layers. */
    if (TSS2_RC_SUCCESS == errCode)
    {
        return "TSS2_RC_SUCCESS";
    }

    switch (errCode)
    {
        case TSS2_BASE_RC_GENERAL_FAILURE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_GENERAL_FAILURE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_GENERAL_FAILURE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_GENERAL_FAILURE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_GENERAL_FAILURE";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
        case TSS2_BASE_RC_NOT_IMPLEMENTED:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_NOT_IMPLEMENTED";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_NOT_IMPLEMENTED";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_NOT_IMPLEMENTED";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_BAD_CONTEXT:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_BAD_CONTEXT";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_BAD_CONTEXT";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_BAD_CONTEXT";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_ABI_MISMATCH:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_ABI_MISMATCH";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_ABI_MISMATCH";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_ABI_MISMATCH";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_ABI_MISMATCH";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_BAD_REFERENCE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_BAD_REFERENCE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_BAD_REFERENCE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_BAD_REFERENCE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_BAD_REFERENCE";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_INSUFFICIENT_BUFFER:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_INSUFFICIENT_BUFFER";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_INSUFFICIENT_BUFFER";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_INSUFFICIENT_BUFFER";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_INSUFFICIENT_BUFFER";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_BAD_SEQUENCE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_BAD_SEQUENCE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_BAD_SEQUENCE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_BAD_SEQUENCE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_BAD_SEQUENCE";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_NO_CONNECTION:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_NO_CONNECTION";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_NO_CONNECTION";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_NO_CONNECTION";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_TRY_AGAIN:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_TRY_AGAIN";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_TRY_AGAIN";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_TRY_AGAIN";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_IO_ERROR:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_IO_ERROR";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_IO_ERROR";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_IO_ERROR";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_IO_ERROR";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_BAD_VALUE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_BAD_VALUE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_BAD_VALUE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_BAD_VALUE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_BAD_VALUE";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_NOT_PERMITTED:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_NOT_PERMITTED";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_NOT_PERMITTED";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_NOT_PERMITTED";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_NOT_PERMITTED";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_INVALID_SESSIONS:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_INVALID_SESSIONS";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_INVALID_SESSIONS";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_INVALID_SESSIONS";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_NO_DECRYPT_PARAM:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_NO_DECRYPT_PARAM";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_NO_DECRYPT_PARAM";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_NO_DECRYPT_PARAM";
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_NO_ENCRYPT_PARAM:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_NO_ENCRYPT_PARAM";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_NO_ENCRYPT_PARAM";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_NO_ENCRYPT_PARAM";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_BAD_SIZE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_BAD_SIZE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_BAD_SIZE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_BAD_SIZE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_MALFORMED_RESPONSE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_MALFORMED_RESPONSE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_MALFORMED_RESPONSE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_MALFORMED_RESPONSE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_MALFORMED_RESPONSE";
                    break;
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_INSUFFICIENT_CONTEXT:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_INSUFFICIENT_CONTEXT";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_INSUFFICIENT_CONTEXT";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_INSUFFICIENT_CONTEXT";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_INSUFFICIENT_RESPONSE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_INSUFFICIENT_RESPONSE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_INSUFFICIENT_RESPONSE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_INSUFFICIENT_RESPONSE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
             break;
        case TSS2_BASE_RC_INCOMPATIBLE_TCTI:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_INCOMPATIBLE_TCTI";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_INCOMPATIBLE_TCTI";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_INCOMPATIBLE_TCTI";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_NOT_SUPPORTED:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_NOT_SUPPORTED";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                    return "[TCTI] TSS2_TCTI_RC_NOT_SUPPORTED";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_NOT_SUPPORTED";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        case TSS2_BASE_RC_BAD_TCTI_STRUCTURE:
            switch(rcLevel)
            {
                case TSS2_TPM_RC_LEVEL:
                    return "[TPM] TSS2_BASE_RC_BAD_TCTI_STRUCTURE";
                    break;
                case TSS2_SYS_ERROR_LEVEL:
                    return "[SAPI] TSS2_SYS_RC_BAD_TCTI_STRUCTURE";
                    break;
                case TSS2_SYS_PART2_RC_LEVEL:
                    return "[PART2] TSS2_FAPI_RC_BAD_TCTI_STRUCTURE";
                    break;
                case TSS2_TCTI_ERROR_LEVEL:
                default:
                    return "Invalid RC level and error code combination";
                    break;
            }
            break;
        default:
            return "Unrecognized error code";
            break;               
    }
        
}


#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
