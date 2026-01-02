/*
 * smp_nanoroot.h
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
@file       smp_nanoroot.h
@ingroup    nanosmp_tree
@brief      NanoROOT specific header file
@details    This header file contains structures and
            helper function declarations required by NanoROOT API.
*/

#ifndef __SMP_NanoROOT_HEADER__
#define __SMP_NanoROOT_HEADER__

#if (defined (__ENABLE_MOCANA_SMP__) && defined (__ENABLE_MOCANA_SMP_NANOROOT__))

#include <stdlib.h>
#include <stdio.h>

#include "common/mrtos.h"
#include "common/debug_console.h"
#include "smp_nanoroot_device_protect.h"

/* The id from which the unique identification for the
   object starts */
#define NanoROOT_OBJECT_ID_START 0x01

#define NanoROOTMODULE_ID  0x01
#define NanoROOTTOKEN_ID   0x01

#define NanoROOTMAX_ERROR_BUFFER 128
#define NanoROOTMAX_SLOT_DESC_SZ 65

#ifndef NanoROOTMAX_SEAL_DATA_SIZE
#define NanoROOTMAX_SEAL_DATA_SIZE    (512 * 1024)
#endif

#ifndef NanoROOTMAX_SIGN_DATA_SIZE
#define NanoROOTMAX_SIGN_DATA_SIZE    (512 * 1024)
#endif

#define SHA1_HASH_LENGTH 20
#define SHA224_HASH_LENGTH 28
#define SHA256_HASH_LENGTH 32
#define SHA384_HASH_LENGTH 48
#define SHA512_HASH_LENGTH 64

#define RSA_DEFAULT_KEY_SZ 2048

#define RSA_4096_SIGN_LENGTH 512


typedef struct NanoROOT_Module NanoROOT_Module;
typedef struct NanoROOT_Config NanoROOT_Config;
typedef struct NanoROOT_Object NanoROOT_Object;
typedef struct NanoROOT_Token NanoROOT_Token;
typedef struct CRED_CTX CRED_CTX;

struct CRED_CTX
{
    NROOTKdfElement    *pFPElement;
    ubyte4              numOfFPElement;
    ubyte               *pInitSeed;
    ubyte4              initSeedLen;
    ubyte4              kdf;
    ubyte4              mech;
};

struct NanoROOT_Config
{
    ubyte4      moduleId; /* Module Id, identifies a particular module */
    ubyte       *modDesc; /* Module description */
    ubyte       deviceModuleIdStr[SHA256_RESULT_SIZE];
    TAP_Buffer  credentialFile; /* Credential File */
    CRED_CTX    cred_ctx;
};


/* Structure holding NanoROOT asymmetric keys */
struct NanoROOT_Object
{
    TAP_Buffer      objectId;
    AsymmetricKey   privKey;
    ubyte4          refCount;
};

struct NanoROOT_Token
{
    TAP_TokenId     tokenId;
    NanoROOT_Object  object;
};

struct NanoROOT_Module
{
    TAP_ModuleId    moduleId;
    NanoROOT_Token  token;
    NROOT_FP_CTX    *pCtx;
    ubyte4          mech;
    TAP_Error       error;
};

/*
 * Init routine called from SMP_NanoROOT_register API.
 * Allocate all necessary objects and also initialize module if config
 * file is provided and initialize nanoroot library.
 */

MSTATUS NanoROOT_init(TAP_ConfigInfo *pConfigInfo);

/*
 * DeInit routine called from SMP_NanoROOT_unregister API.
 * Free all allocations done for the nanoroot modules and finalize cryptoki library.
 */
MSTATUS NanoROOT_deInit();

/* Fill the last error */
void NanoROOT_FillError(TAP_Error* error, MSTATUS* pStatus, MSTATUS statusVal, const char* pErrString);

#endif /* __ENABLE_MOCANA_SMP__ && __ENABLE_MOCANA_SMP_NANOROOT__ */

#endif /* __SMP_NanoROOT_HEADER__ */
