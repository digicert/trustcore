/**
 * @file sapi2_errors.c
 * @brief This file contains the response code processing functions for TPM2.
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

#include <stdio.h>
#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/debug_console.h"
#include "sapi2_errors.h"


char succesStr[]="SUCCESS";

#ifdef  __ENABLE_LOOKUP_TABLE__
char errStr[]="ERROR";
char warnStr[]="WARNING";
char paramStr[]="Parameter";
char handleStr[]="Handle";
char sessionStr[]="Session";
char unSupErrStr[]="Unsupported error code";
char unSupStr[]="Unsupported code";


/* Table for Format 1 error messages */
char* fmt1ErrTab[MAX_FMT1_NUM] =
{
/* 0x000 */ unSupErrStr,
/* 0x001 */ "asymmetric algorithm not supported or not correct",
/* 0x002 */ "inconsistent attributes",
/* 0x003 */ "hash algorithm not supported or not appropriate",
/* 0x004 */ "value is out of range or is not correct for the context",
/* 0x005 */ "hierarchy is not enabled or is not correct for the use",
/* 0x006 */ unSupErrStr,
/* 0x007 */ "key size is not supported",
/* 0x008 */ "mask generation function not supported",
/* 0x009 */ "mode of operation not supported",
/* 0x00A */ "the type of the value is not appropriate for the use",
/* 0x00B */ "the handle is not correct for the use",
/* 0x00C */ "unsupported key derivation function or function not appropriate for use",
/* 0x00D */ "value was out of allowed range",
/* 0x00E */ "the authorization HMAC check failed and DA counter incremented",
/* 0x00F */ "invalid nonce size or nonce value mismatch",
/* 0x010 */ "authorization requires assertion of PP",
/* 0x011 */ unSupErrStr,
/* 0x012 */ "unsupported or incompatible scheme",
/* 0x013 */ unSupErrStr,
/* 0x014 */ unSupErrStr,
/* 0x015 */ "structure is the wrong size",
/* 0x016 */ "unsupported symmetric algorithm or key size, or not appropriate for instance",
/* 0x017 */ "incorrect structure tag",
/* 0x018 */ "union selector is incorrect",
/* 0x019 */ unSupErrStr,
/* 0x01A */ "unable to unmarshal a value because there were not enough octets in the input buffer",
/* 0x01B */ "the signature is not valid",
/* 0x01C */ "key fields are not compatible with the selected use",
/* 0x01D */ "a policy check failed",
/* 0x01E */ unSupErrStr,
/* 0x01F */ "integrity check failure; invalid structure size",
/* 0x020 */ "invalid ticket",
/* 0x021 */ "reserved bits not set to zero as required",
/* 0x022 */ "authorization failure without DA implications",
/* 0x023 */ "the policy has expired",
/* 0x024 */ "Command code mismatch or command not implemented",
/* 0x025 */ "public and sensitive portions of an object are not cryptographically bound",
/* 0x026 */ "curve not supported",
/* 0x027 */ "point is not on the required curve."
};


/* Table for Format 0 - Error messages */
char* ver1ErrTab[MAX_VER1_NUM] =
{
/* 0x000 */ "TPM not initialized by TPM2_Startup or already initialized",
/* 0x001 */ "commands not being accepted because of a TPM failure",
/* 0x002 */ unSupStr,
/* 0x003 */ "improper use of a sequence handle",
/* 0x004 */ unSupStr,
/* 0x005 */ unSupStr,
/* 0x006 */ unSupStr,
/* 0x007 */ unSupStr,
/* 0x008 */ unSupStr,
/* 0x009 */ unSupStr,
/* 0x00A */ unSupStr,
/* 0x00B */ "not currently used",
/* 0x00C */ unSupStr,
/* 0x00D */ unSupStr,
/* 0x00E */ unSupStr,
/* 0x00F */ unSupStr,
/* 0x010 */ unSupStr,
/* 0x011 */ unSupStr,
/* 0x012 */ unSupStr,
/* 0x013 */ unSupStr,
/* 0x014 */ unSupStr,
/* 0x015 */ unSupStr,
/* 0x016 */ unSupStr,
/* 0x017 */ unSupStr,
/* 0x018 */ unSupStr,
/* 0x019 */ "not currently used",
/* 0x01A */ unSupStr,
/* 0x01B */ unSupStr,
/* 0x01C */ unSupStr,
/* 0x01D */ unSupStr,
/* 0x01E */ unSupStr,
/* 0x01F */ unSupStr,
/* 0x020 */ "the command is disabled",
/* 0x021 */ "command failed because audit sequence required exclusivity",
/* 0x022 */ unSupStr,
/* 0x023 */ unSupStr,
/* 0x024 */ "authorization handle is not correct for command",
/* 0x025 */ "command requires an authorization session for handle and it is not present",
/* 0x026 */ "policy failure in math operation or an invalid authPolicy value",
/* 0x027 */ "PCR check fail",
/* 0x028 */ "PCR have changed since checked",
/* 0x029 */ unSupStr,
/* 0x02A */ unSupStr,
/* 0x02B */ unSupStr,
/* 0x02C */ unSupStr,
/* 0x02D */ "not in field upgrade mode for TPM2_FieldUpgradeData; in field upgrade mode for all other commands",
/* 0x02E */ "context ID counter is at maximum",
/* 0x02F */ "authValue or authPolicy is not available for selected entity",
/* 0x030 */ "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation",
/* 0x031 */ "The digest size of the hash must be larger than the key size of the symmetric algorithm.",
/* 0x032 */ unSupStr,
/* 0x033 */ unSupStr,
/* 0x034 */ unSupStr,
/* 0x035 */ unSupStr,
/* 0x036 */ unSupStr,
/* 0x037 */ unSupStr,
/* 0x038 */ unSupStr,
/* 0x039 */ unSupStr,
/* 0x03A */ unSupStr,
/* 0x03B */ unSupStr,
/* 0x03C */ unSupStr,
/* 0x03D */ unSupStr,
/* 0x03E */ unSupStr,
/* 0x03F */ unSupStr,
/* 0x040 */ unSupStr,
/* 0x041 */ unSupStr,
/* 0x042 */ "command commandSize value is inconsistent with contents of the command buffer",
/* 0x043 */ "command code not supported",
/* 0x044 */ "the value of authorizationSize is out of range or greater than required",
/* 0x045 */ "authorization session used when not allowed",
/* 0x046 */ "NV offset+size is out of range",
/* 0x047 */ "Requested allocation size is larger than allowed",
/* 0x048 */ "NV access locked",
/* 0x049 */ "NV access authorization fails in command actions",
/* 0x04A */ "an NV Index is used before being initialized or saved state could not be restored",
/* 0x04B */ "insufficient space for NV allocation",
/* 0x04C */ "NV Index or persistent object already defined",
/* 0x04D */ unSupStr,
/* 0x04E */ unSupStr,
/* 0x04F */ unSupStr,
/* 0x050 */ "context in TPM2_ContextLoad() is not valid",
/* 0x051 */ "cpHash value already set or not correct for use",
/* 0x052 */ "handle for parent is not a valid parent",
/* 0x053 */ "some function needs testing",
/* 0x054 */ "internal function cannot process a request due to an unspecified problem",
/* 0x055 */ "the sensitive area did not unmarshal correctly after decryption"
};


/* Table for Format 0 - Warning messages */
char* warnTab[MAX_WARN_NUM] =
{
/* 0x000 */ unSupStr,
/* 0x001 */ "gap for context ID is too large",
/* 0x002 */ "out of memory for object contexts",
/* 0x003 */ "out of memory for session contexts",
/* 0x004 */ "out of shared object/session memory or need space for internal operations",
/* 0x005 */ "out of session handles – a session must be flushed before a new session may be created",
/* 0x006 */ "out of object handles – the handle space for objects is depleted and a reboot is required",
/* 0x007 */ "bad locality",
/* 0x008 */ "TPM has suspended command operation; command may be retried",
/* 0x009 */ "the command was canceled",
/* 0x00A */ "TPM is performing self-tests",
/* 0x00B */ unSupStr,
/* 0x00C */ unSupStr,
/* 0x00D */ unSupStr,
/* 0x00E */ unSupStr,
/* 0x00F */ unSupStr,
/* 0x010 */ "the 1st handle in the handle area references a transient object or session that is not loaded",
/* 0x011 */ "the 2nd handle in the handle area references a transient object or session that is not loaded",
/* 0x012 */ "the 3rd handle in the handle area references a transient object or session that is not loaded",
/* 0x013 */ "the 4th handle in the handle area references a transient object or session that is not loaded",
/* 0x014 */ "the 5th handle in the handle area references a transient object or session that is not loaded",
/* 0x015 */ "the 6th handle in the handle area references a transient object or session that is not loaded",
/* 0x016 */ "the 7th handle in the handle area references a transient object or session that is not loaded",
/* 0x017 */ unSupStr,
/* 0x018 */ "the 1st authorization session handle references a session that is not loaded",
/* 0x019 */ "the 2nd authorization session handle references a session that is not loaded",
/* 0x01A */ "the 3rd authorization session handle references a session that is not loaded",
/* 0x01B */ "the 4th authorization session handle references a session that is not loaded",
/* 0x01C */ "the 5th session handle references a session that is not loaded",
/* 0x01D */ "the 6th session handle references a session that is not loaded",
/* 0x01E */ "the 7th authorization session handle references a session that is not loaded",
/* 0x01F */ unSupStr,
/* 0x020 */ "the TPM is rate-limiting accesses to prevent wearout of NV",
/* 0x021 */ "TPM is in DA lockout mode, authorizations for objects subject to DA protection are not allowed",
/* 0x022 */ "the TPM was not able to start the command",
/* 0x023 */ "the command may require writing of NV and NV is not current accessible"
};


char* SAPI2_ERRORS_getFMT1Error(ubyte codeNum)
{
    if (codeNum >= MAX_FMT1_NUM)
        return unSupErrStr;
    return fmt1ErrTab[codeNum];
}


char* SAPI2_ERRORS_getVER1Error(ubyte codeNum)
{
    if (codeNum >= MAX_VER1_NUM)
        return unSupErrStr;
    return ver1ErrTab[codeNum];
}


char* SAPI2_ERRORS_getWarning(ubyte codeNum)
{
    if (codeNum >= MAX_WARN_NUM)
        return unSupStr;
    return warnTab[codeNum];
}


char* SAPI2_ERRORS_processFormat1(ubyte4 respCode, char *pBuf, ubyte2 bufSize)
{
    char *str1, *str2;
    ubyte codeNum, num=0;

    if ( NULL == pBuf || 0 == respCode)
    {
        DB_PRINT("%s.%d Invalid Buffer pointer or response code, rc 0x%02x = %d\n", __FUNCTION__, __LINE__, respCode, respCode);
        return NULL;
    }

    num = GET_RESP_N(respCode);
    if (IS_P_BIT_SET(respCode))
    {
        /* Parameter */
        str1 = paramStr;
    }
    else
    {
        /* Handle or Session */
        if (num <= MAX_HANDLE_ERROR)
            str1 = handleStr;
        else
            str1 = sessionStr;
    }
    codeNum = GET_RESP_CODE_NUM_F1(respCode);
    str2 = SAPI2_ERRORS_getFMT1Error(codeNum);
    #ifdef __RTOS_WIN32__
    sprintf_s(pBuf, bufSize, "%s: 0x%03X %s number %d - %s", errStr, codeNum, str1, num, str2);
    #else
    snprintf(pBuf, bufSize, "%s: 0x%03X %s number %d - %s", errStr, codeNum, str1, num, str2);
    #endif
    return pBuf;
}


char* SAPI2_ERRORS_processFormat0(ubyte4 respCode, char *pBuf)
{
    ubyte codeNum;
    char *str1, *str2;

    if (IS_V_BIT_SET(respCode))
    {
        if (IS_T_BIT_SET(respCode))
        {
            /* Vendor specific codes. */
            sprintf(pBuf, "Vendor specific error. No further info.");
            goto exit;
        }
        else
        {
            /* TCG defined codes */
            codeNum = GET_RESP_CODE_NUM_F0(respCode);
            if (IS_S_BIT_SET(respCode))
            {
                /* Warning, RC_WARN codes */
                str1 = warnStr;
                str2 = SAPI2_ERRORS_getWarning(codeNum);
            }
            else
            {
                /* Error, RC_VER1 codes */
                str1 = errStr;
                str2 = SAPI2_ERRORS_getVER1Error(codeNum);
            }
        }
    }
    else
    {
        /* TPM 1.2 errors */
        sprintf(pBuf, "TPM 1.2 error. No further info.");
        goto exit;
    }

    sprintf(pBuf, "%s: 0x%03X %s", str1, codeNum, str2);

exit:
    return pBuf;
}

#endif

char* SAPI2_ERRORS_processRespCode(ubyte4 respCode, char *pBuf, ubyte2 bufSize)
{
    char *pStr=NULL;

    /* Check inputs */
    if ( NULL == pBuf || bufSize < RESP_STR_SIZE)
    {
        DB_PRINT("%s.%d Invalid Buffer pointer or length, rc 0x%02x = %s\n", __FUNCTION__, __LINE__, respCode, respCode);
        goto exit;
    }

     pStr = pBuf;
    /* Check  for success */
    if (0 == GET_RESP_CODE(respCode))
    {
        sprintf(pBuf, "%s", succesStr);
        goto exit;
    }

#ifdef   __ENABLE_LOOKUP_TABLE__
    /* Process response code */
    if (IS_FORMAT_1(respCode))
        pStr = SAPI2_ERRORS_processFormat1(respCode, pBuf, bufSize);
    else
        pStr = SAPI2_ERRORS_processFormat0(respCode, pBuf);
#else
    sprintf(pBuf, "0x%03X", GET_RESP_CODE(respCode));
#endif
    exit:
    return pStr;
}

#endif /* (defined(__ENABLE_DIGICERT_TPM2__)) */

