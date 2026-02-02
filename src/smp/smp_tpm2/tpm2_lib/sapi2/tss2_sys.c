/*
 *  tss2_sys.c
 *
 *  This file is the SAPI implementation for TPM 2.0 chips
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
#ifdef __ENABLE_DIGICERT_TPM2__
#include "tss2_sys.h"

#define MAX_TSS2_CMD_RSP_SIZE 200

typedef struct
{
    _TSS2_TCTI_OPAQUE_CONTEXT_BLOB *tctiContext;
    TSS2_ABI_VERSION *abiVersion;
    ubyte4 *cpParamSize;
    ubyte **cpParams;
} _TSS2_SYS_OPAQUE_CONTEXT_BLOB;


typedef struct
{
    ubyte cmdAuthsCount;   /* 0-3 when not restricted to TPM_ST_NO_SESSIONS */
    TPMS_AUTH_COMMAND **cmdAuths;
} TSS2_SYS_CMD_AUTHS;

typedef struct
{
    ubyte rspAuthsCount;   /* 0-3 when not restricted to TPM_ST_NO_SESSIONS */
    TPMS_AUTH_RESPONSE **rspAuths;
} TSS2_SYS_RSP_AUTHS;


/* Command Context Allocation functions */
/* Command Context Setup functions */

/* Returns the required size for the opaque SAPI command context, which caller must allocate 
 * if maxCommandResponseSize = 0, returns maximum possible context needed.
 * It is highly recommended to pass 0, unless you truly understand the TPM spec.
 * See 8.7.1.1
 */
size_t Tss2_Sys_GetContextSize(size_t maxCommandResponseSize)
{
    size_t sysContextSize = 0;

    if (0 == maxCommandResponseSize)
    {
        /* Return maximum possible context needed */
        MAX_TSS2_CMD_RSP_SIZE +  ? 

    }
    else
    {
        /* Calculate context size needed */
        
    }

    if (0 == sysContextSize)
    {
        DEBUG_PRINT(DEBUG_SECMOD_MESSAGES, "TSS2_SYS_getContextSize called with unsupported TPM type");
        goto exit;
    }

    return sysContextSize;
}


/* See 8.7.1.2 */
TSS2_RC Tss2_Sys_Initialize(TSS2_SYS_CONTEXT *sysContext, size_t contextSize,
                            TSS2_TCTI_CONTEXT *tctiContext, TSS2_ABI_VERSION *abiVersion);

/* See 8.7.1.3 */
TSS2_RC Tss2_Sys_Finalize(TSS2_SYS_CONTEXT *sysContext);

/* See 8.7.1.4 */
TSS2_RC Tss2_Sys_GetTctiContext(TSS2_SYS_CONTEXT *sysContext, TSS2_TCTI_CONTEXT **tctiContext);

/* Command Preparation functions -  Format is:
 *     TSS2_RC Tss2_Sys_xxxx_Prepare(TSS2_SYS_CONTEXT *sysContext, inHandles, inParams)
 * See Part 3 Commands
 */

/* Command Execution functions - Tss2_Sys_xxxx  */
/* See sec 8.7.3:
 *   Tss2_Sys_ExecuteAsync
 *   Tss2_Sys_ExecuteFinish
 *   Tss2_Sys_Execute
 *   Tss2_Sys_xxxx
 */

/* Command Completion functions - Tss2_Sys_xxxx_Complete */
/* See sec 8.7.4
 *   Tss2_Sys_GetCommandCode
 *   Tss2_Sys_GetRspAuths
 *   Tss2_Sys_XXXX_Complete
 *   Tss2_Sys_GetEncryptParam
 *   Tss2_Sys_SetEncryptParam
 *   Tss2_Sys_GetRpBuffer
 */

#endif

