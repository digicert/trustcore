/*
 * smp_tee.h
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

/**
@file       smp_tee.h
@ingroup    nanosmp_tree
@brief      TEE specific header file
@details    This header file contains structures required to work with NanoSMP
            and helper function declarations required by TEE API.
*/

#ifndef __SMP_TEE_HEADER__
#define __SMP_TEE_HEADER__

#include "../../common/mrtos.h"
#include "../../common/debug_console.h"

#include "smp_tap_tee.h"

#define SMP_TEE_MAX_TOKENS TEE_NUM_TRUSTED_APPLICATIONS
#define SMP_TEE_MAX_NAME_STR_LEN 1024 /* allocated buffer, large length ok */
#define SMP_TEE_MAX_ID_STR_LEN 33 /* 32 plus extra '\0' char */
#define SMP_TEE_MAX_TOKEN_STR_LEN 1024 /* also large length ok */

typedef struct _Tee_Config
{
    ubyte4 moduleId; /* Module Id, identifies a particular module */
    ubyte* modDesc;  /* Module description */
    ubyte deviceModuleIdStr[SMP_TEE_MAX_ID_STR_LEN];
    ubyte4 tokens[SMP_TEE_MAX_TOKENS];
    ubyte4 numTokens;

} Tee_Config;

typedef struct _Tee_Token
{
    TAP_TokenId    uuid;
    TEEC_Context   ctx;
    TEEC_Session   sess;
    byteBoolean    sessionActive;
    struct _Tee_Token *pNext;

} Tee_Token;

typedef struct _Tee_Module
{
    Tee_Config *pConfig;
    Tee_Token *pTokenHead;
    
} Tee_Module;

#endif /* __SMP_TEE_HEADER__ */
