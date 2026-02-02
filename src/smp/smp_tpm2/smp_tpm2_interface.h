/*
 * smp_tpm2_interface.h
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
 *@file      smp_tpm2_interface.h
 *@brief     NanoSMP provider Interface that an application(NanoTAP) will use to
 *           communicate/manage TPM2 SMP module plugin.
 *@details   This header file contains definitions, enumerations, and function
 *           declarations used by NanoTAP to communicate/manage TPM2 NanoSMP
 *           module plugin.
 */

#ifndef __SMP_TPM2_INTERFACE_HEADER__
#define __SMP_TPM2_INTERFACE_HEADER__

/*------------------------------------------------------------------*/
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__))

#include "../smp_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup smp_definitions
 * @details This function is invoked by TAP to initialize global resources needed by 
 *     <p> this SMP and to get the list of registered Opcodes
 *     <p> supported by TPM2 security provider. Input parameters specify the version
 *     <p> compatible with this implementation. Input configuration buffer contains
 *     <p> configuration information for this SMP including the instance configuration
 *     <p> of all the instances controlled by this SMP module
 * @param [in]  type Specifies the type of SMP provider, should be set to TAP_PROVIDER_TPM2 
 * @param [in]  version Specifies the minimum version of SMP, required by caller
 * @param [in]  tapVersion Specifies the version of TAP, supported by caller
 * @param [in]  *pRegisteredOpcodes Pointer to list, that will be populated with the opcodes supported by this TPM2 SMP
 * @param [in]  *pConfigBuffer Pointer to buffer containing configuration information for all the instances supported by this TPM2 SMP
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_TPM2_register(
        TAP_PROVIDER type,
        TAP_SMPVersion version,
        TAP_Version tapVersion,
        TAP_ConfigInfo *pConfigInfo,
        TAP_CmdCodeList *pRegisteredOpcodes
);

/**
 * @ingroup smp_definitions
 * @details This function cleans up the global resources allocated by SMP_TPM2_register()  
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_TPM2_unregister();

MOC_EXTERN MSTATUS SMP_TPM2_dispatcher(
        TAP_RequestContext *pCtx,
        SMP_CmdReq *pCmdReq,
        SMP_CmdRsp *pCmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , TAP_ErrorAttributes *pErrorRules
       , TAP_ErrorAttributes **ppErrAttrReturned
#endif
);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_TPM2__ */
#endif /* __SMP_TPM2_INTERFACE_HEADER__ */

