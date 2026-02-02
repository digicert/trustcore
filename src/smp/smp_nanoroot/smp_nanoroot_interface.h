/*
 * smp_nanoroot_interface.h
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
 *@file      smp_nanoroot_interface.h
 *@brief     NanoSMP provider Interface that an application(NanoTAP) will use to
 *           communicate/manage NanoROOT SMP module plugin.
 *@details   This header file contains definitions, enumerations, and function
 *           declarations used by NanoTAP to communicate/manage NanoROOT NanoSMP
 *           module plugin.
 */

#ifndef __SMP_NANOROOT_INTERFACE_HEADER__
#define __SMP_NANOROOT_INTERFACE_HEADER__

/*------------------------------------------------------------------*/

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__))

#ifndef __SMP_INTERFACE_HEADER__
#include "../smp_interface.h"
#endif

/**
 * @ingroup smp_functions
 * @brief This API initializes the SMP and returns the list of opcodes supported in @p pRegisteredOpcodes
 * @details This API initializes the SMP and returns the list of opcodes supported in @p pRegisteredOpcodes
 * @param [in]  type
 * @param [in]  version
 * @param [in]  tapVersion
 * @param [in]  pConfigInfo
 * @param [out]  pRegisteredOpcodes
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_NanoROOT_register(
        TAP_PROVIDER type,
        TAP_SMPVersion version,
        TAP_Version tapVersion,
        TAP_ConfigInfo *pConfigInfo,
        TAP_CmdCodeList *pRegisteredOpcodes
);

/**
 * @ingroup smp_functions
 * @brief This API uninitializes the SMP and free's all resources acquired by the SMP.
 * @details This API uninitializes the SMP and free's all resources acquired by the SMP.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_NanoROOT_unregister();

/**
 * @ingroup smp_functions
 * @brief This API dispatches the SMP methods corresponding to the opcode with @p pCmdReq and populates @p pCmdRsp.
 * @details This API dispatches the SMP methods corresponding to the opcode with @p pCmdReq and populates @p pCmdRsp.
 * @param [in]  pCtx
 * @param [in]  pCmdReq
 * @param [out]  pCmdRsp
 * @return OK on success
 */
MSTATUS SMP_NanoROOT_dispatcher(
        TAP_RequestContext *pCtx,
        SMP_CmdReq *pCmdReq,
        SMP_CmdRsp *pCmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , TAP_ErrorAttributes *pErrorRules
       , TAP_ErrorAttributes **ppErrAttrReturned
#endif
);

#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_SMP_NANOROOT__ */

#endif /* __SMP_NANOROOT_INTERFACE_HEADER__ */
