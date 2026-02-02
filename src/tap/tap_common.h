/**
 * @file tap_common.h
 *
 * @brief Trust Anchor Platform (TAP) Definitions and Types for Client-Server communication.
 * @details This file contains definitions and functions needed by both Trust Anchor Platform (TAP) client and server modules.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular security module:
 *    + \c \__ENABLE_DIGICERT_TPM2__
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


/*------------------------------------------------------------------*/

#ifndef __TAP_COMMON_HEADER__
#define __TAP_COMMON_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/random.h"
#include "../crypto/hw_accel.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha256.h"
#include "../crypto/cert_store.h"
#include "tap.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! @cond */
#ifdef __ENABLE_DIGICERT_TAP__
/*! @endcond */

#ifdef __ENABLE_DIGICERT_SMP__
#include "../smp/smp_interface.h"
#endif


#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
/* --- Bitmask Macros --- */
#define NanoROOT_MAKE_ALGO_ID(algo, subtype)   ((((ubyte8)(algo)) << 32) | ((ubyte8)(subtype)))
#define NanoROOT_GET_ALGO_ID(value)            ((ubyte4)(((value) >> 32) & 0xFFFFFFFF))
#define NanoROOT_GET_SUBTYPE(value)            ((ubyte4)((value) & 0xFFFFFFFF))

/* --- Algorithm IDs --- */
#define NanoROOT_ALGO_RSA      0x00000001
#define NanoROOT_ALGO_MLDSA    0x00000002
#define NanoROOT_ALGO_ECC      0x00000003

/* --- RSA Key Sizes --- */
#define NanoROOT_RSA_2048      0x00000002
#define NanoROOT_RSA_3072      0x00000003
#define NanoROOT_RSA_4096      0x00000004
#define NanoROOT_RSA_8192      0x00000005

/* --- MLDSA Subtypes --- */
#define NanoROOT_MLDSA_44      0x00000001
#define NanoROOT_MLDSA_65      0x00000002
#define NanoROOT_MLDSA_87      0x00000003

/* --- ECC Curves --- */
#define NanoROOT_ECC_P256       0x00000001
#define NanoROOT_ECC_P384       0x00000002
#define NanoROOT_ECC_P521       0x00000003

#endif
/***************************************************************
   Constant Definitions
****************************************************************/

/***************************************************************
   General Structure Definitions
****************************************************************/



/***************************************************************
   Function Definitions
****************************************************************/

#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
MSTATUS TAP_NanoROOT_parse_algorithm_info(ubyte8 value, TAP_KEY_ALGORITHM *keyAlgorithm,
				TAP_KEY_SIZE *keySize, ubyte4 *subKeyType);
#endif

/**
 * @ingroup tap_functions
 * @details Function to check if a TAP_PROVIDER is supported on the host.
 *
 * @param [in]  tapProvider  The provider to check.
 *
 * @return  OK if tapProvider is valid and supported on host.
 * @return  ERR_TAP_UNSUPPORTED if tapProvider is valid but not supported on host.
 * @return  ERR_TAP_INVALID_TAP_PROVIDER if tapProvider is not valid.
 */
MOC_EXTERN MSTATUS TAP_COMMON_checkTapProvider(TAP_PROVIDER tapProvider);


#ifdef __ENABLE_DIGICERT_SMP__
/**
 * @ingroup tap_functions
 * @details Function to check if a command is supported by a provider.
 *
 * @param [in]  pProviderList  The list returned by each provider during registration.
 * @param [in]  tapProvider    The provider to check.
 * @param [in]  cmdCode        The command code to check.
 *
 * @return  OK if tapProvider is valid and supports the cmdCode on host.
 * @return  ERR_TAP_UNSUPPORTED if tap Provider is not supported or tapProvider is valid but does not support the command code on host.
 * @return  ERR_TAP_INVALID_TAP_PROVIDER if tapProvider is not valid.
 */
MOC_EXTERN MSTATUS TAP_COMMON_checkCmdSupport(TAP_ProviderList *pProviderList, TAP_PROVIDER tapProvider, SMP_CC cmdCode);
#endif

/**
 * @ingroup tap_functions
 * @details Function to register the specified TAP_PROVIDER.
 *
 * @param [in]  tapProvider   The provider to register.
 * @param [in]  pConfigInfo   The configuration information to be passed to the provider.
 * @param [in]  pCmdCodeList  The list of supported command codes returned by the provider.
 *                            This is expected to be the list corresponding to the provider, maintained by the caller.
 *
 * @return  OK   If tapProvider is valid and supported on host.
 * @return  ERR_NULL_POINTER    If a required input is not given.
 * @return  ERR_TAP_UNSUPPORTED If tapProvider is not supported on host.
 * @return  ERR_TAP_INVALID_TAP_PROVIDER If tapProvider is not valid.
 * @return  Error code from provider's register function if unsuccessful.
 *
 * @memory  This function allocates memory for the pCmdCodeList.
 * @memory  The caller must make sure the pCmdCodeList is protected with a mutex, or other appropriate mechanism, prior to this call.
 *          This function is not thread safe independently.
 */
MOC_EXTERN MSTATUS TAP_COMMON_registerProvider(TAP_PROVIDER provider, TAP_ConfigInfo *pConfigInfo,
                                TAP_CmdCodeList *pCmdCodeList);

/**
 * @ingroup tap_functions
 * @details Function to unregister the specified TAP_PROVIDER.
 *
 * @param [in]  tapProvider   The provider to unregister.
 * @param [in]  pCmdCodeList  The list of supported command codes returned by the provider during registerProvider.
 *                            This is expected to be the list corresponding to the provider, maintained by the caller.
 *
 * @return  OK   If tapProvider is valid and supported on host.
 * @return  ERR_NULL_POINTER    If a required input is not given.
 * @return  ERR_TAP_UNSUPPORTED If tapProvider is not supported on host.
 * @return  ERR_TAP_INVALID_TAP_PROVIDER If tapProvider is not valid.
 * @return  Error code from provider's unregister function if unsuccessful.
 *
 * @memory  This function frees memory for the pCmdCodeList.
 * @memory  The caller must make sure the pCmdCodeList is protected with a mutex, or other appropriate mechanism, prior to this call.
 *          This function is not thread safe independently.
 */
MOC_EXTERN MSTATUS TAP_COMMON_unregisterProvider(TAP_PROVIDER provider, TAP_CmdCodeList *pCmdCodeList);

/**
 * @ingroup tap_functions
 * @details Function to copy the local provider list.  The local list is created during initialization.
 *          The copy is returned by TAP_getProviderList, either for the local host or a remote host.
 *
 * @param [in]  pLocalList   The local provider list.
 * @param [in]  pNewList     The new copy of the local provider list.
 *
 * @return  OK   On Success.
 * @return  ERR_NULL_POINTER    If a required input is not given.
 * @return  ERR_MEM_ALLOC_SIZE  or ERR_MEM_ALLOC_FAIL if failed to allocate memory for the new list.
 *
 * @memory  This function allocates memory for the pNewList.
 */
MOC_EXTERN MSTATUS TAP_COMMON_copyProviderList(TAP_ProviderList *pLocalList, TAP_ProviderList *pNewList);

/**
 * @ingroup tap_functions
 * @details Function to register all providers on the host.
 *
 * @param [in]   pConfigInfoList   The list containing the configuration information for all providers.
 * @param [out]  pProviderList     The provider list generated containing all available providers on the host,
 *                                 along with a list of supported command codes returned by the provider.
 *                                 This is expected to be the global list of providers, maintained by the caller.
 *
 * @return  OK   On Success.
 * @return  ERR_NULL_POINTER    If a required input is not given.
 * @return  Error code from provider's register function if unsuccessful.
 *
 * @memory  This function allocates memory for the pProviderList, which must be freed by TAP_UTILS_freeProviderList.
 * @memory  The caller must make sure the pProviderList is protected with a mutex, or other appropriate mechanism, prior to this call.
 *          This function is not thread safe independently.
 */
MOC_EXTERN MSTATUS TAP_COMMON_registerLocalProviders(TAP_ConfigInfoList *pConfigInfoList, TAP_ProviderList *pProviderList);

/**
 * @ingroup tap_functions
 * @details Function to unregister all providers on the host.
 *
 * @param [in,out]  pProviderList  The provider list, generated registerLocalProviders, of all available providers on the host,
 *                                 along with a list of supported command codes returned by the provider.
 *                                 This is expected to be the global list of providers, maintained by the caller.
 *
 * @return  OK   On Success.
 * @return  ERR_NULL_POINTER    If a required input is not given.
 * @return  Error code from provider's unregister function if unsuccessful.
 *
 * @memory  This function frees memory allocated within the pProviderList.  It does not free the pProviderList itself.
 * @memory  The caller must make sure the pProviderList is protected with a mutex, or other appropriate mechanism, prior to this call.
 *          This function is not thread safe independently.
 */
MOC_EXTERN MSTATUS TAP_COMMON_unregisterLocalProviders(TAP_ProviderList *pProviderList);

/*! @cond */
#endif /* __ENABLE_DIGICERT_TAP__ */
/*! @endcond */

#ifdef __cplusplus
}
#endif

#endif /* __TAP_COMMON_HEADER__ */
