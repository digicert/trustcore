/*
 * tap_extern.h
 *
 * @details  This file contains the TAP Extern functions declaration
 *
 * Trust Anchor Platform APIs
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
@file       tap_extern.h
@brief      TAP Extern APIs
@details    This file contains TAP Extern APIs.

@filedoc    tap_extern.h
*/
#ifndef TAP_EXTERN_H
#define TAP_EXTERN_H

#include "../smp/smp_cc.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/cryptointerface.h"

#if (defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_EXTERN__))
/**
@brief      Initialize TAP and the TapContext callback

@details    This function initializes TAP and TapContext callback
            for applications using TAP keys and cannot modify their
            init sequence to initialize TAP. This function obtains
            TAP config values needed from environment variables.
            If using TAP in local mode,
            MOCANA_CONFIGFILE environment variable should be set to config file

            If using TAP in remote mode,
            MOCANA_TAPSERVERNAME env variable should be set to tap servername
            MOCANA_TAPSERVERPORT env variable should be set to port of the tap server

@param      ppFuncPtrGetTapContext  pointer to funcPtr to get the Tap Context

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/

MOC_EXTERN sbyte4 DIGICERT_TAPExternInit(void **ppFuncPtrGetTapContext);

/**
@brief      Uninitialize TAP and the TapContext callback

@details    This function uninitializes TAP, and sets the TapContext callback to NULL

@param      ppFuncPtrGetTapContext  pointer to funcPtr to get the Tap Context

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/

MOC_EXTERN sbyte4 DIGICERT_TAPExternDeinit(void **ppFuncPtrGetTapContext);

/**
@brief      TapContext callback

@details    This function initializes/uninitializes TAP context for the given key

@param      ppTapContext     pointer to the Tap Context
@param      ppTapEntityCred  pointer to the Tap Entity Credentials
@param      ppTapKeyCred     pointer to the Tap Key Credentials
@param      pKey             MocAsymKey or MocSymCtx depending on the operation
@param      op               Tap operation
@param      getContext       if 1, create a new Tap Context.
                             else, destroy the Tap Context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN sbyte4
DIGICERT_TAP_EXTERN_getTapContext(TAP_Context **ppTapContext,
                                TAP_EntityCredentialList **ppTapEntityCred,
                                TAP_CredentialList **ppTapKeyCred,
                                void *pKey, TapOperation op, ubyte getContext);

#endif
#endif
