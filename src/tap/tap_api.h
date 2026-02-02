/**
 * @file tap_api.h
 *
 * @ingroup nanotap_tree
 *
 * @brief Trust Anchor Platform (TAP) Client APIs
 * @details This file contains the Mocana Trust Anchor Platform (TAP) Client APIs
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

#ifndef __TAP_API_HEADER__
#define __TAP_API_HEADER__

/*! @cond */
#ifdef __ENABLE_DIGICERT_TAP__
/*! @endcond */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "tap_common.h"
#include "../data_protection/tap_data_protect.h"

#ifdef __cplusplus
MOC_EXTERN "C" {
#endif

/***************************************************************
   Definitions
****************************************************************/

/*! @cond */

/*! Current version of #TAP_Key structure */
#define TAP_KEY_VERSION 1

/*! @endcond */

/***************************************************************
   Module Callback Definitions
****************************************************************/

/*! @cond */

/**
 * @private
 * @internal
 */
typedef MSTATUS (*tapCopyKeyCallback)(TAP_Key *pDestKey, TAP_Key *pSrcKey);

/**
 * @private
 * @internal
 */
typedef MSTATUS (*tapFreeKeyCallback)(TAP_Key *pKey);

/*! @endcond */


/***************************************************************
   Structure Definitions
****************************************************************/

/**
 * @private
 * @internal
 */
typedef struct
{
    TAP_PROVIDER            providerType;
    byteBoolean             isRemoteAllowed;
    tapCopyKeyCallback      copyKeyCallback;
    tapFreeKeyCallback      freeKeyCallback;
} TAP_ModuleInfo;



/***************************************************************
   Function Prototypes
****************************************************************/

#ifndef __ENABLE_TAP_REMOTE__
/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to get Module credentials from the credentials file
 * @details Function to get Module credentials from the credentials file. This function may be overridden by application developers if there is a need to provide credentials in any other mechanism than through a credentials file.
 * @param [in] pModule Module for which credentials are being initialized.
 * @param [in] pConfigFile Pointer to configuration file that contains the credentials
 * @param [in] useSpecifiedConfigFilePath Boolean flag to indicate if the configuration path is valid
 * @param [out] ppEntityCredentialList Pointer to pointer of a Entity credentials list
 * @param [out] pErrContext   In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return Appropriate error code otherwise.
 *
 * @note This function allocates memory for entity credentials list which must be freed by the caller
 */
MOC_EXTERN MSTATUS TAP_getModuleCredentials(TAP_Module *pModule, const char *pConfigFile,
        byteBoolean useSpecifiedConfigFilePath,
        TAP_EntityCredentialList **ppEntityCredentialList,
        TAP_ErrorContext *pErrContext);
#endif

/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to initialize the TAP abstraction layer.
 * @details Function to initialize the TAP abstraction layer.  This calls the supported security
 *          modules to do any initialization needed, including retrieving a list of their supported
 *          functionality.
 *        <p> This function must be called before invoking any other TAP functions.
 *
 * @param [in]  pConfigInfo   Optional config file list
 * @param [out] pErrContext   In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return Appropriate error code otherwise.
 *
 * @note This function allocates global memory, which must be freed by calling TAP_uninit.
 */
MOC_EXTERN MSTATUS TAP_init(TAP_ConfigInfoList *pConfigInfo, TAP_ErrorContext *pErrContext);

#ifdef __ENABLE_TAP_REMOTE__

/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to initialize the TAP abstraction layer for Non filesystem modes.
 * @details Function to initialize the TAP abstraction layer for systems which does not
 *          have file systems.
 *        <p> This function must be called before invoking any other TAP functions.
 *
 * @param [in]  tapClientConfig   Config file list as buffer
 * @param [out] pCertStore        Certificate store.
 *
 * @return OK on success
 * @return Appropriate error code otherwise.
 *
 */
MOC_EXTERN MSTATUS TAP_initEx(TAP_Buffer* tapClientConfig, certStorePtr pCertStore);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to uninitialize the TAP abstraction layer for non filsystem mode.
 * @details Function to uninitialize the TAP abstraction layer for systems which does
 *          not have file systems.
 *        <p> This function must be called before when an application no longer needs to use TAP or
 *        underlying security module functions.
 *
 * @return OK on success
 * @return Appropriate error code otherwise.
 *
 */

MOC_EXTERN MSTATUS TAP_uninitEx();

#endif
/**
 * @ingroup tap_api_functions
 *
 * @brief Function to uninitialize the TAP abstraction layer.
 * @details Function to uninitialize the TAP abstraction layer.  This calls the supported security
 *         modules to do any ninitialization needed, including freeing any global memory.
 *        <p> This function must be called before when an application no longer needs to use TAP or
 *        underlying security module functions.
 *
 * @param [out] pErrContext   In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return Appropriate error code otherwise.
 *
 * @note This function frees all global memory allocated by  TAP_init.
 */
MOC_EXTERN MSTATUS TAP_uninit(TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to obtain the providerType and moduleId from a tap context.
 * @details Function to obtain the providerType and moduleId from a tap context.
 *
 * @param [in] pContext         The input context.
 * @param [out] pProviderType   Contents will be set to the providerType.
 * @param [out] pModuleId       Contents will be set to the module Id.
 *
 * @return OK on success
 * @return Appropriate error code otherwise.
 */
MOC_EXTERN MSTATUS TAP_getTapInfo(TAP_Context *pCtx, ubyte4 *pProviderType, ubyte4 *pModuleId);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to return a list of available providers.
 * @details Function to return a list of providers supported on the specified hose.  This is the list
 *          of SMPs and not the individual modules (instances of a secure element).
 *          <p> The providers in the list are those compiled on the host.  It does not necessarily mean
 *              that a module of that type exists on the host.  TAP_getModuleList will need to be called
 *              to determine if a module exists on the host.
 *
 * @param [in]     pConnInfo       Host to query for available modules.
 * @param [in,out] pProviderList   Pointer to structure containing list of available providers.
 * @param [out]    pErrContext     In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for TAP_ProviderList.pProviderList, which must be freed by the caller via DIGI_FREE.
 */
MOC_EXTERN MSTATUS TAP_getProviderList(TAP_ConnectionInfo *pConnInfo,
                                   TAP_ProviderList *pProviderList,
                                   TAP_ErrorContext *pErrContext);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to return a list of available modules.
 * @details Function to return a list of available modules on the specified host.
 *          This may include any available emulators for testing purposes, if supported by the SMP.
 *
 * @param [in]   pConnInfo              Host to query for available modules.
 * @param [in]   provider               If TAP_PROVIDER_UNDEFINED, gets list of available modules of all types.
 *                                      Otherwise, returns only the list of the specified TAP_PROVIDER.
 * @param [in]   pCapabilityAttributes  List of TAP_AttributeModuleCapability types to use as a filter.
 * @param [out]  pModuleList            Pointer to structure containing list of available modules.
 * @param [out]  pErrContext            In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for TAP_ModuleList elements and must be freed by caller via TAP_freeModuleList.
 */
MOC_EXTERN MSTATUS TAP_getModuleList(TAP_ConnectionInfo *pConnInfo, TAP_PROVIDER provider,
                                 TAP_ModuleCapabilityAttributes *pCapabilityAttributes,
                                 TAP_ModuleList *pModuleList, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to free a list of  modules.
 * @details Function to free a list of modules returned by TAP_getModuleList.
 *
 * @param [in,out] pModuleList   Pointer to structure containing list of available modules.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This frees any memory allocated by TAP_getModuleList.
 */
MOC_EXTERN MSTATUS TAP_freeModuleList(TAP_ModuleList *pModuleList);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to initialize a TAP context to a specific module.
 * @details Function to initialize a TAP context to a specific module. This must be called before invoking
 *          any of the security APIs.
 *
 * @param [in]  pModule             Module for which to initialize a context.  This is obtained by TAP_getModuleList.
 * @param [in]  pModuleCredentials  Optional list of credentials an SMP may need to create a context.
 *                                  If credentials are required to talk to the SMP, these must be obtained from an
 *                                  administrator and provided here.
 * @param [in]  pAttributes         Optional attribute list containing information an SMP may need to create a context.
 * @param [out] ppTapContext        Pointer to a pointer to the new TAP context
 * @param [out] pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note Any sensitive information, including credentials, will be cleared from the input arguments before returning.
 * The caller must make sure they have a copy of this information if it is needed after this call.
 * @memory  TAP_uninitContext must be called to free all memory allocated by this function for the TAP and module-specific context structures.
 */
MOC_EXTERN MSTATUS TAP_initContext(TAP_Module *pModule, TAP_EntityCredentialList *pModuleCredentials,
                               TAP_AttributeList *pAttributes, TAP_Context **ppTapContext,
                               TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to associate a credential with a previously initialized TAP context.
 * @details Function to associate a credential with a previously initialized TAP context.
 *
 * @param [in,out]  pTapContext         Context with which to associate credential(s).
 * @param [in]      pModuleCredentials  The credential(s) to associate with the module context.
 * @param [in]      pAttributes         Optional attribute list containing information an SMP may need.
 * @param [out]     pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note Any sensitive information, including credentials, will be cleared from the input arguments before returning.
 * The caller must make sure they have a copy of this information if it is needed after this call.
 */
MOC_EXTERN MSTATUS TAP_associateCredentialWithContext(TAP_Context *pTapContext,
                                                  TAP_EntityCredentialList *pModuleCredentials,
                                                  TAP_AttributeList *pAttributes,
                                                  TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to uninitialize a TAP context.
 * @details Function to uninitialize a TAP context.
 *
 * @param [in,out] ppTapContext   Pointer to a pointer to the TAP context to uninitialize.
 * @param [out]    pErrContext    In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This frees all memory allocated by TAP_initContext, including the calls to the underlying module context structures.
 */
MOC_EXTERN MSTATUS TAP_uninitContext(TAP_Context **ppTapContext, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to verify if underlying security module has been initialized
 * @details Function to verify if underlying security module has been initialized
 *
 * @param [in]  pModule          Pointer to the TAP module returned by TAP_getModuleList.
 * @param [out] pIsProvisioned   TRUE (1) if the module is provisioned; FALSE (0) otherwise.
 * @param [out] pErrContext      In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_isModuleProvisioned(TAP_Module *pModule, byteBoolean *pIsProvisioned,
                                       TAP_ErrorContext *pErrContext);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to provision a module.
 * @details Function to provision a module if some action is required.  This may involve the creation of certain keys or
 *          taking ownership of the module. This may not be applicable to all SMPs, but all SMPs must appropriately respond.
 *          <p>Refer to the documentation for the underlying SMP for details on the input that must be provided.
 *
 * @param [in]   pTapContext     Pointer to the TAP context associated with the module to provision.
 * @param [in]  pUsageCredentials     Optional list of credentials an SMP may need to provision a module.
 * @param [in]  pAttributes      Optional attribute list containing information an SMP may need to provision a module.
 * @param [out] pErrContext      In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note Any sensitive information, including credentials, will be cleared from the input arguments before returning.
 * The caller must make sure they have a copy of this information if it is needed after this call.
 * @memory  TAP_uninitContext must be called to free all memory allocated by this function for the TAP and module-specific context structures.
 */
MOC_EXTERN MSTATUS TAP_provisionModule(TAP_Context *pTapContext,
                                   TAP_CredentialList *pUsageCredentials,
                                   TAP_ModuleProvisionAttributes *pAttributes,
                                   TAP_ErrorContext *pErrContext);

/**
* @ingroup tap_api_functions
*
* @brief Function to return information and capabilities of the specified module.
* @details Function to return information and capabilities of the specified module.  This does not require a context, as this will most
*          often be use to choose a module before initializing a context.
*
* @param [in]  pModule                Pointer to the module for which to obtain capabilities.
* @param [out] pCapPropertySelection   Optional pointer to the TAP_AttributeList containing the capabilities for
*                                     which a value is requested.  If NULL, all capabilities will be returned.
* @param [out] pModuleCapProperties    Pointer to the TAP_AttributeList containing the module capabilities.
* @param [out] pErrContext            In debug mode, returns debug error information.
*
* @return OK on success
* @return ERR_NULL_POINTER if a NULL pointer is passed
* @return ERR_INVALID_ARG if an invalid argument is specified
*
* @memory  This function allocates memory for pModuleCapProperties, which must be freed via TAP_freeAttributeList.
*/
MOC_EXTERN MSTATUS TAP_getModuleCapability(TAP_Module *pModule, TAP_ModuleCapPropertyAttributes *pCapPropertySelection,
    TAP_ModuleCapPropertyList *pModuleCapProperties, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to return information and capabilities of the specified module.
 * @details Function to return information and capabilities of the specified module.  This does not require a context, as this will most
 *          often be use to choose a module before initializing a context.
 *
 * @param [in]  pModule                Pointer to the module for which to obtain capabilities.
 * @param [out] pCapabilitySelection   Optional pointer to the TAP_AttributeList containing the capabilities for
 *                                     which a value is requested.  If NULL, all capabilities will be returned.
 * @param [out] pModuleCapabilities    Pointer to the TAP_AttributeList containing the module capabilities.
 * @param [out] pErrContext            In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory  This function allocates memory for pModuleCapabilities, which must be freed via TAP_freeAttributeList.
 */
MOC_EXTERN MSTATUS TAP_getModuleInfo(TAP_Module *pModule, TAP_AttributeList *pCapabilitySelection,
                                 TAP_AttributeList *pModuleCapabilities, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to return information about the specified module.
 * @details Function to return information about the specified module.  This typically is the hardware and/or firmware
 *          version of the module, but is module-specific.  Refer to the SMP documentation for details.
 *
 * @param [in]  pModule        Pointer to the module for which to obtain version information.
 * @param [out] pModuleInfo    Pointer to the TAP_AttributeList containing the module version information.
 * @param [out] pErrContext    In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory  This function allocates memory for pModuleInfo, which must be freed via TAP_freeAttributeList.
 * @note    This API returns a subset of TAP_getModuleInfo details.  It is separated into a separate API for ease of use, as this is a common request.
 */
MOC_EXTERN MSTATUS TAP_getModuleVersionInfo(TAP_Module *pModule, TAP_AttributeList *pModuleInfo,
                                        TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to free a TAP_AttributeList.
 * @details Function to free a TAP_AttributeList.
 *
 * @param [out] pAttributes    Pointer to the TAP_AttributeList to be freed.
 * @param [out] pErrContext    In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the attributes within the list, and not the TAP_AttributeList structure itself.
 *         If memory for pAttributes was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_freeAttributeList(TAP_AttributeList *pAttributes, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to obtain a the last module-specific error(s) for the given module.
 * @details Function to obtain a the last module-specific error(s) and optional status information for the given module.
 *
 * @param [in]  pTapContext    Pointer to the TAP context associated with the module.
 * @param [out] pError         Pointer to the error structure returned.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for the TAP_Error structure.  This must be freed by TAP_freeErrorInfo.
 */
MOC_EXTERN MSTATUS TAP_getLastErrorInfo(TAP_Context *pTapContext, TAP_Error *pError);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to free the error structure returned by TAP_getLastErrorInfo.
 * @details Function to free the error structure returned by TAP_getLastErrorInfo.
 *
 * @param [out] pError        Pointer to the error structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the attributes within the error structure, and not the TAP_Error structure itself.
 *         If memory for pError was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_freeErrorInfo(TAP_Error *pError);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to start selftest on the security module.
 * @details Function to start selftest on the security module.
 *
 * @param [in]  pTapContext          Pointer to the TAP context associated with the module.
 * @param [in]  pRequestAttributes   Indicates the type of test and optional and/or module-specific information.
 * @param [out] pResponseAttributes  The results of the test.  If the request indicated an incremental test, this will
 *                                   include a context to complete the test or retrieve the test results.
 * @param [out]  pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 */
MOC_EXTERN MSTATUS TAP_selfTest(TAP_Context *pTapContext,
                            TAP_TestRequestAttributes *pRequestAttributes,
                            TAP_TestResponseAttributes *pResponseAttributes,
                            TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to get a random number from the underlying security module
 * @details Function to get a random number from the underlying security module
 *
 * @param [in]   pTapContext     Pointer to the TAP context associated with the module.
 * @param [in]   bytesRequested  The number of random bytes requested
 * @param [in]   pAttributes     Optional attribute list containing information an SMP may need to generate a random number.
 *                               This may include information such as a random source.
 * @param [out]  pData           Pointer to the TAP_Buffer containing the random data
 * @param [out]  pErrContext     In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_getRandom(TAP_Context *pTapContext, ubyte4 bytesRequested, TAP_AttributeList *pAttributes,
                             TAP_Buffer *pData, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to stir the entropy of the random number generator of the underlying security module
 * @details Function to stir the entropy of the random number generator of the underlying security module
 *
 * @param [in]   pTapContext     Pointer to the TAP context associated with the module.
 * @param [in]   numBytes        The number of bytes to be used to stir the RNG.
 * @param [in]   pAttributes     Optional attribute list containing input data to stir the entropy of the
 *                               random number generator, a source from which to obtain entropy data, etc.
 * @param [in]   pEntropy        Optional buffer containing input data to stir the entropy of the RNG.
 * @param [out]  pErrContext     In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_stirRandom(TAP_Context *pTapContext, ubyte4 numBytes,
                              TAP_RngAttributes *pAttributes, TAP_Buffer *pEntropy,
                              TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to generate an asymmetric key using underlying security module.
 * @details Function to generate key an asymmetric key using underlying security module.  This function requires that the following functions be called prior to this call:
 *   - TAP_init
 *   - TAP_initContext
 * <p> All information needed must be provided in the module-specific pKeyParams structure, including any key credential(s).
 * <p> If the caller intends to use the generated key in the CRYPTO APIs, the corresponding CRYPTO call to generate a key should be used instead.
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module.
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pKeyInfo          Algorithm and corresponding information of the key to generate (RSA, ECC, etc).
 * @param [in]  pKeyAttributes    Optional list of additional information that may be needed or supported by the
 *                                module to generate an asymmetric key.
 * @param [in]  pKeyCredential    Optional credential an SMP may need/support to generate a key.
 * @param [out] ppTapKey          TAP_Key generated, which includes the underlying module-specific key structure
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for the underlying key and must be freed by TAP_freeKey.
 *
 * @note   This function automatically loads the key so it is ready for use.  The user must call TAP_unloadKey when done with the key.
 * @note   When a key with a usage of TAP_KEY_USAGE_GENERAL, is created, whether or not a default sigScheme or encScheme is
 *         allowed is up to the discretion of the underlying security provider.  The provider may return an error if an
 *         invalid scheme is provided, or it may simply ignore the scheme(s).  As such, TAP does not save any values specified
 *         on input.  The provider may ignore these schemes or require explicit schemes to be specified during key use.
 *         As such, a valid scheme must be provided when using a general key for encryption, decryption, signing or verification.
 */
MOC_EXTERN MSTATUS TAP_asymGenerateKey(TAP_Context *pTapContext,
                                   TAP_EntityCredentialList *pUsageCredentials,
                                   TAP_KeyInfo *pKeyInfo,
                                   TAP_AttributeList *pKeyAttributes,
                                   TAP_CredentialList *pKeyCredentials,
                                   TAP_Key **ppTapKey,
                                   TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to generate a symmetric key using underlying security module.
 * @details Function to generate key a symmetric key using underlying security module.  This function requires that the following functions be called prior to this call:
 *   - TAP_init
 *   - TAP_initContext
 * <p> All information needed must be provided in the module-specific pKeyParams structure, including any key credential(s).
 * <p> If the caller intends to use the generated key in the CRYPTO APIs, the corresponding CRYPTO call to generate a key should be used instead.
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module.
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pKeyInfo          Algorithm and corresponding information of the key to generate (AES, HMAC, etc).
 * @param [in]  pKeyAttributes    Optional list of additional information that may be needed or supported by the
 *                                module to generate a symmetric key.
 * @param [in]  pKeyCredential    Optional credential an SMP may need/support to generate a key.
 * @param [out] ppTapKey          TAP_Key generated, which includes the underlying module-specific key structure
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for the underlying key and must be freed by TAP_freeKey.
 *
 * @note   This function automatically loads the key so it is ready for use.  The user must call TAP_unloadKey when done with the key.
 */
MOC_EXTERN MSTATUS TAP_symGenerateKey(TAP_Context *pTapContext,
                                  TAP_EntityCredentialList *pUsageCredentials,
                                  TAP_KeyInfo *pKeyInfo,
                                  TAP_AttributeList *pKeyAttributes,
                                  TAP_CredentialList *pKeyCredentials,
                                  TAP_Key **ppTapKey,
                                  TAP_ErrorContext *pErrContext);

/**
 * @private
 * @internal
 */
MOC_EXTERN MSTATUS TAP_symCreateKey(TAP_Context *pTapContext,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_KeyInfo *pKeyInfo,
                           TAP_AttributeList *pKeyAttributes,
                           TAP_CredentialList *pKeyCredentials,
                           TAP_Key **ppTapKey,
                           TAP_ErrorContext *pErrContext);
/**
 * @private
 * @internal
 */
MOC_EXTERN MSTATUS TAP_symImportExternalKey(TAP_Context *pTapContext,
                                 TAP_EntityCredentialList *pUsageCredentials,
                                 TAP_KeyInfo *pKeyInfo,
                                 TAP_AttributeList *pKeyAttributes,
                                 TAP_CredentialList *pKeyCredentials,
                                 TAP_Key **ppTapKey,
                                 TAP_ErrorContext *pErrContext);

/**
 * @private
 * @internal
 */
MOC_EXTERN MSTATUS TAP_asymCreatePubKey(TAP_Context *pTapContext,
                                 TAP_EntityCredentialList *pUsageCredentials,
                                 TAP_KeyInfo *pKeyInfo,
                                 TAP_AttributeList *pKeyAttributes,
                                 TAP_CredentialList *pKeyCredentials,
                                 TAP_Key **ppTapKey,
                                 TAP_ErrorContext *pErrContext);

/**
 * TO DO is this private?
 * @private
 * @internal
 */
MOC_EXTERN MSTATUS TAP_importKeyFromID(TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_KeyInfo *pKeyInfo,
                            TAP_Buffer *pKeyId,
                            TAP_AttributeList *pKeyAttributes,
                            TAP_CredentialList *pKeyCredentials,
                            TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to sign data using an asymmetric key.
 * @details Function to sign data using an asymmetric key. Signing data encrypts it with the private key.
 *
 * @param [in]  pTapKey           Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes     Optional attribute list containing additional information for the SMP to perform the sign operation.
 * @param [in]  sigScheme         Signature scheme, if one not specified during key creation, module supports multiple, or key usage is TAP_KEY_USAGE_GENERAL.
 *                                or if the module supports multiple schemes.
 *                                If TAP_SIG_SCHEME_NONE is provided, the signature scheme already associated with the key will be used.
 * @param [in]  isDataNotDigest   TRUE if data is not in digest form.  FALSE if already in digest form.
 * @param [in]  pInData           TAP_Buffer containing the the data to sign.  If data is a digest, the hash used to create the digest must be consistent with the signature scheme.
 * @param [out] pSignature        Pointer to a TAP_Signature structure.
 *                                <p>TAP converts the algorithm-specific signature into a single DER-encoded buffer.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSignature fields and must be freed by calling TAP_freeTapSignature.
 *         If memory was allocated for the TAP_Signature itself, that must be freed by the caller.
 *
 * @note  A module may either ignore or require the sigScheme, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Sign.
 * @note  When using a key with a usage of TAP_KEY_USAGE_GENERAL, the sigScheme is required, even if it was specified
 *        during key creation.
 */
MOC_EXTERN MSTATUS TAP_asymSign(TAP_Key *pTapKey,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_AttributeList *pOpAttributes,
                            TAP_SIG_SCHEME sigScheme, byteBoolean isDataNotDigest,
                            TAP_Buffer *pInData, TAP_Signature *pSignature,
                            TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to sign data using an asymmetric key with padding done in software.
 * @details Function to sign data using an asymmetric key. Padding is done in software and signing data encrypts it with the private key.
 *
 * @param [in]  pTapKey           Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes     Optional attribute list containing additional information for the SMP to perform the sign operation.
 * @param [in]  pSigInfo          Signature information. Must specify signing scheme along with any additional parameters the signing scheme requires.
 * @param [in]  pInData           TAP_Buffer containing the the data to sign.  If data is a digest, the hash used to create the digest must be consistent with the signature scheme.
 * @param [out] pSignature        Pointer to a TAP_Signature structure.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSignature fields and must be freed by calling TAP_freeTapSignature.
 *         If memory was allocated for the TAP_Signature itself, that must be freed by the caller.
 *
 * @note  The signature scheme must be provided through the TAP_SignatureInfo structure.
 * @note  This API performs the signature padding operation in software and performs the raw sign operation in
 *        hardware.
 */
MOC_EXTERN MSTATUS TAP_asymSignEx(TAP_Key *pTapKey,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_AttributeList *pOpAttributes,
                              TAP_SignatureInfo *pSigInfo,
                              TAP_Buffer *pInData, TAP_Signature *pSignature,
                              TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to sign data using a symmetric key.
 * @details Function to sign data using a symmetric key. Signing data encrypts it with the private key.
 *
 * @param [in]  pTapKey             Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the sign operation.
 * @param [in]  isDataNotDigest    TRUE if data is not in digest form.  FALSE if already in digest form.
 * @param [in]  pInData            TAP_Buffer containing the the data to sign.  If data is a digest, the hash used to create the digest must be consistent with the signature scheme.
 * @param [out] pSignature         Pointer to a TAP_Signature structure.
 *                                 <p>TAP converts the algorithm-specific signature into a single DER-encoded buffer.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSignature fields and must be freed by calling TAP_freeTapSignature.
 *         If memory was allocated for the TAP_Signature itself, that must be freed by the caller.
 */
MOC_EXTERN MSTATUS TAP_symSign(TAP_Key *pTapKey,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_AttributeList *pOpAttributes,
                           byteBoolean isDataNotDigest,
                           TAP_Buffer *pInData, TAP_Signature *pSignature,
                           TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Method to initialize the signing operation using a symmetric key.
 * @details Method to initialize the signing operation using a symmetric key.
 *
 * @param [in]  pTapKey             Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the sign operation.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 */
MOC_EXTERN MSTATUS TAP_symSignInit(TAP_Key *pTapKey,
                                   TAP_EntityCredentialList *pUsageCredentials,
                                   TAP_AttributeList *pOpAttributes,
                                   TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Method to update the state with input data for a symmetric key signature routine.
 * @details Method to update the state with input data for a symmetric key signature routine.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pInData            TAP_Buffer containing the the data to sign.  If data is a digest, the hash used to create the digest must be consistent with the signature scheme.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 */
MOC_EXTERN MSTATUS TAP_symSignUpdate(TAP_Key *pTapKey,
                                     TAP_Buffer *pInData,
                                     TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Method to finalize a symmetric key signature routine.
 * @details Method to finalize a symmetric key signature routine.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [out] pSignature         Pointer to a TAP_Signature structure.
 *                                 <p>TAP converts the algorithm-specific signature into a single DER-encoded buffer.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSignature fields and must be freed by calling TAP_freeTapSignature.
 *         If memory was allocated for the TAP_Signature itself, that must be freed by the caller.
 */
MOC_EXTERN MSTATUS TAP_symSignFinal(TAP_Key *pTapKey,
                                    TAP_Signature *pSignature,
                                    TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to verify the signature of input buffer with the specified hash algorithm
 * @details Function to verify the signature of input buffer with the specified hash algorithm
 *
 * @param [in]  pTapKey             Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes       Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  opExecFlag          Flag indicating where the operation should be performed, in HW or SW.
 *                                  Not all modules will support public key operations in HW.
 *                                  Not all modules will support public key operations in HW.
 * @param [in]  sigScheme           Signature scheme, if one not specified during key creation, module supports multiple, or key usage is TAP_KEY_USAGE_GENERAL.
 *                                  If TAP_SIG_SCHEME_NONE is provided, the signature scheme already associated with the key will be used.
 * @param [in]  pInDigest           TAP_Buffer containing the digest of the data to be verified.   The hash used to create the digest must be consistent with the signature scheme.
 * @param [in]  pSignature          The signature structure returned by TAP_sign.
                                    <p>TAP converts the buffer back to an algorithm-specific signature.
 * @param [out] pIsSigValid         TRUE (1) if signature matches.  FALSE (0) otherwise.
 * @param [out] pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  A module may either ignore or require the sigScheme, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for VerifySignature.
 *        If a sigScheme is provided and used by the module, it should match the information provided during Sign.
 * @note  When using a key with a usage of TAP_KEY_USAGE_GENERAL, the sigScheme is required, even if it was specified
 *        during key creation.
 */
MOC_EXTERN MSTATUS TAP_asymVerifySignature(TAP_Key *pTapKey,
                                       TAP_EntityCredentialList *pUsageCredentials,
                                       TAP_AttributeList *pOpAttributes,
                                       TAP_OP_EXEC_FLAG opExecFlag, TAP_SIG_SCHEME sigScheme,
                                       TAP_Buffer *pInDigest, TAP_Signature *pSignature,
                                       byteBoolean *pIsSigValid, TAP_ErrorContext *pErrContext);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to verify the signature of input buffer with the specified hash algorithm
 * @details Function to verify the signature of input buffer with the specified hash algorithm
 *
 * @param [in]  pTapKey             Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes       Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  pInDigest           TAP_Buffer containing the digest of the data to be verified.   The hash used to create the digest must be consistent with the signature scheme.
 * @param [in]  pSignature          The signature structure returned by TAP_sign.
                                    <p>TAP converts the buffer back to an algorithm-specific signature.
 * @param [out] pIsSigValid         TRUE (1) if signature matches.  FALSE (0) otherwise.
 * @param [out] pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  A module may either ignore or require the sigScheme, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for VerifySignature.
 *        If a sigScheme is provided and used by the module, it should match the information provided during Sign.
 */
MOC_EXTERN MSTATUS TAP_symVerifySignature(TAP_Key *pTapKey,
                                      TAP_EntityCredentialList *pUsageCredentials,
                                      TAP_AttributeList *pOpAttributes,
                                      TAP_Buffer *pInDigest, TAP_Signature *pSignature,
                                      byteBoolean *pIsSigValid, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to free a TAP_Signature
 * @details Function to free a TAP_Signature
 *
 * @param [in]  pSignature         The signature structure to be freed.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 *
 * @memory This function only frees the attributes within the signature structure, and not the TAP_Signature structure itself.
 *         If memory for pSignature was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_freeSignature(TAP_Signature *pSignature);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to encrypt data using an asymmetric key.
 * @details Function to encrypt data using an asymmetric key. Note that the length of the input data must be smaller than the encryptable payload for the given key.
 *       <p>  This function may be implemented in software, as only the public key is used.  However, modules may choose to implement this in hardware.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  opExecFlag         Flag indicating where the operation should be performed, in HW or SW.
 *                                 Not all modules will support public key operations in HW.
 * @param [in]  encScheme          Encryption scheme, if one not specified during key creation, module supports multiple, or key usage is TAP_KEY_USAGE_GENERAL.
 *                                 If TAP_ENC_SCHEME_NONE is provided, the encryption scheme already associated with the key will be used.
 * @param [in]  pPlainText         TAP_Buffer containing the data to be encrypted
 * @param [out] pCipherText        TAP_Buffer containing the encrypted data
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success, ppCipherText holds the encrypted data
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pCipherText and must be freed by the caller.
 *
 * @note  A module may either ignore or require the encScheme, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Encrypt.
 * @note  When using a key with a usage of TAP_KEY_USAGE_GENERAL, the encScheme is required, even if it was specified
 *        during key creation.
 */
MOC_EXTERN MSTATUS TAP_asymEncrypt(TAP_Key *pTapKey,
                               TAP_EntityCredentialList *pUsageCredentials,
                               TAP_AttributeList *pOpAttributes,
                               TAP_OP_EXEC_FLAG opExecFlag,  TAP_ENC_SCHEME encScheme,
                               TAP_Buffer *pPlainText, TAP_Buffer *pCipherText,
                               TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to encrypt data using a symmetric key.
 * @details Function to encrypt data using a symmetric key. Note that the length of the input data must be smaller than the encryptable payload for the given key.
 *       <p>  This function may be implemented in software.  However, modules may choose to implement this in hardware.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional symmetric cipher mode, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pIV                TAP_Buffer containing the IV to be used for encryption
 * @param [in]  pPlainText         TAP_Buffer containing the data to be encrypted
 * @param [out] pCipherText        TAP_Buffer containing the encrypted data
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success, pCipherText holds the encrypted data
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pCipherText and must be freed by the caller.
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symEncrypt(TAP_Key *pTapKey,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_AttributeList *pOpAttributes,
                              TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV,
                              TAP_Buffer *pPlainText, TAP_Buffer *pCipherText,
                              TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to initialize an internal context for encryption via a symmetric key.
 * @details Function to initialize an internal context for encryption via a symmetric key.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional symmetric cipher mode, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pIV                TAP_Buffer containing the IV to be used for encryption
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symEncryptInit(TAP_Key *pTapKey,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_AttributeList *pOpAttributes,
                              TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV,
                              TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to encrypt data using a previously initialized internal context.
 * @details Function to encrypt data using a previously initialized internal context. Note that the length of the input data must be smaller than the encryptable payload for the given key.
 *       <p>  This function may be implemented in software.  However, modules may choose to implement this in hardware.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional symmetric cipher mode, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pPlainText         TAP_Buffer containing the data to be encrypted
 * @param [out] pCipherText        TAP_Buffer containing the encrypted data
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success, pCipherText holds the encrypted data
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pCipherText and must be freed by the caller.
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symEncryptUpdate(TAP_Key *pTapKey,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_AttributeList *pOpAttributes,
                              TAP_SYM_KEY_MODE symMode,
                              TAP_Buffer *pPlainText, TAP_Buffer *pCipherText,
                              TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to finalize an internal context that was created for encryption.
 * @details Function to finalize an internal context that was created for encryption.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional symmetric cipher mode, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [out] pCipherText        TAP_Buffer containing any final encryption output, like an AEAD tag.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symEncryptFinal(TAP_Key *pTapKey,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_AttributeList *pOpAttributes,
                              TAP_SYM_KEY_MODE symMode,
                              TAP_Buffer *pCipherText,
                              TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to decrypt data using an asymmetric key.
 * @details Function to decrypt data using an asymmetric key.
 *
 * @param [in]  pTapKey             Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes       Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  encScheme           Encryption scheme, if one not specified during key creation, module supports multiple, or key usage is TAP_KEY_USAGE_GENERAL.
 *                                  If TAP_ENC_SCHEME_NONE is provided, the encryption scheme already associated with the key will be used.
 * @param [in]  pCipherText         TAP_Buffer containing the data to be decrypted
 * @param [out] pPlainText          TAP_Buffer containing the decrypted data
 * @param [out] pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on Success, ppPlainText holds the decrypted data
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for ppPlainText and must be freed by the caller.
 *
 * @note  A module may either ignore or require the encScheme, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Decrypt.
 *        If an encScheme is provided and used by the module, it should match the information provided during Encrypt.
 * @note  When using a key with a usage of TAP_KEY_USAGE_GENERAL, the encScheme is required, even if it was specified
 *        during key creation.
 */
MOC_EXTERN MSTATUS TAP_asymDecrypt(TAP_Key *pTapKey,
                               TAP_EntityCredentialList *pUsageCredentials,
                               TAP_AttributeList *pOpAttributes,
                               TAP_ENC_SCHEME encScheme, TAP_Buffer *pCipherText,
                               TAP_Buffer *pPlainText, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to decrypt data using a symmetric key.
 * @details Function to decrypt data using a symmetric key.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional mode of operation, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pIV                TAP_Buffer containing the IV to be used for decryption
 * @param [in]  pCipherText        TAP_Buffer containing the data to be decrypted
 * @param [out] pPlainText         TAP_Buffer containing the decrypted data
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success, ppPlainText holds the decrypted data
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for ppPlainText and must be freed by the caller.
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Decrypt.
 *        If an symMode is provided and used by the module, it should match the information provided during Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symDecrypt(TAP_Key *pTapKey,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_AttributeList *pOpAttributes,
                              TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV, TAP_Buffer *pCipherText,
                              TAP_Buffer *pPlainText, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to initialize an internal context for decryption via a symmetric key.
 * @details Function to initialize an internal context for decryption via a symmetric key.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional mode of operation, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pIV                TAP_Buffer containing the IV to be used for decryption
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Decrypt.
 *        If an symMode is provided and used by the module, it should match the information provided during Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symDecryptInit(TAP_Key *pTapKey,
                                      TAP_EntityCredentialList *pUsageCredentials,
                                      TAP_AttributeList *pOpAttributes,
                                      TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV,
                                      TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to decrypt data using a previously initialized internal context.
 * @details Function to decrypt data using a previously initialized internal context.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional mode of operation, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pCipherText        TAP_Buffer containing the data to be decrypted
 * @param [out] pPlainText         TAP_Buffer containing the decrypted data
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success, pPlainText holds the decrypted data
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pPlainText and must be freed by the caller.
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Decrypt.
 *        If an symMode is provided and used by the module, it should match the information provided during Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symDecryptUpdate(TAP_Key *pTapKey,
                                        TAP_EntityCredentialList *pUsageCredentials,
                                        TAP_AttributeList *pOpAttributes,
                                        TAP_SYM_KEY_MODE symMode, TAP_Buffer *pCipherText,
                                        TAP_Buffer *pPlainText, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to finalize an internal context that was created for decryption.
 * @details Function to finalize an internal context that was created for decryption.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes      Optional attribute list containing additional information for the SMP to perform the operation.
 * @param [in]  symMode            Optional mode of operation, if one not specified during key creation or module supports multiple.
 *                                 If TAP_SYM_KEY_MODE_UNDEFINED is provided, the mode already associated with the key will be used.
 * @param [in]  pCipherText        TAP_Buffer containing any input to the decryption finalization, like an AEAD tag.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  A module may either ignore or require the symMode, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Decrypt.
 *        If an symMode is provided and used by the module, it should match the information provided during Encrypt.
 */
MOC_EXTERN MSTATUS TAP_symDecryptFinal(TAP_Key *pTapKey,
                                       TAP_EntityCredentialList *pUsageCredentials,
                                       TAP_AttributeList *pOpAttributes,
                                       TAP_SYM_KEY_MODE symMode,
                                       TAP_Buffer *pCipherText,
                                       TAP_ErrorContext *pErrContext);

/* TODO: Add digest functions
       TAP_digest
       TAP_digestInit
       TAP_digestUpdate
       TAP_digestFinal
 */

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to free a TAP_Key created by TAP_asymGenerateKey or TAP_symGenerateKey.
 * @details Function to free a TAP_Key created by TAP_asymGenerateKey or TAP_symGenerateKey.
 * <p> If the caller generated the key via the CRYPTO APIs, the corresponding CRYPTO call to free the key should be used instead.
 *
 * @param [out] ppKey        TAP_Key to be freed.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This frees all memory allocated by TAP_asymGenerateKey or TAP_symGenerateKey.
 * @note   TAP_unloadKey should be called before this function so the provider can free any memory and clean
 *         up any context associated with its internal key.
 */
MOC_EXTERN MSTATUS TAP_freeKey(TAP_Key **ppKey);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to copy a TAP_Key created by TAP_asymGenerateKey or TAP_symGenerateKey.
 * @details Function to free a TAP_Key created by TAP_asymGenerateKey or TAP_symGenerateKey.
 *          This function calls the underlying security module to copy its key structure.
 * <p> If the caller generated the key via the CRYPTO APIs, the corresponding CRYPTO call to copy the key should be used instead.
 *
 * @param [out] ppNewKey       New TAP_Key created.
 * @param [in]  pSrcKey        TAP_Key to be copied.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function allocates memory for the underlying module-specific key, which must be freed by TAP_freeKey.
 */
MOC_EXTERN MSTATUS TAP_copyKey(TAP_Key **ppNewKey, TAP_Key *pSrcKey);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to serialize a TAP_Key.
 * @details Function to serialize a TAP_Key. This calls the underlying security module to serialize the module-specific key structure.
 *       <p> If the caller generated the key via the CRYPTO APIs and plans to use CRYPTO APIs in the future, the corresponding CRYPTO call to serialize the key should be used instead.
 *       <p> This calls gets the serialized key blob from the provider, and serializes that along with the TAP_Key fields.
 *           If the key has an objectID, this function results in a call to SMP_serializeObject;
 *           If the key has a keyHandle, this function results in a call to SMP_exportObject.
 *       <p> The pTapKey is modified only in that it will have the newly serialized module blob associated with it.
 *
 * @param [in]  pTapKey               TAP_Key to be serialized
 * @param [in]  format                Format in which to serialized the key.
 * @param [in]  encoding              Encoding for the serialized the key.
 * @param [out] pSerializedKeyBuffer  Serialized key blob.
 * @param [out] pErrContext           In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for pSerializedKeyBuffer and must be freed by a call to TAP_UTILS_freeBuffer.
 * @note   Currently, only the Mocana blob format is supported.
 */
MOC_EXTERN MSTATUS TAP_serializeKey(TAP_Key *pTapKey, TAP_BLOB_FORMAT format, TAP_BLOB_ENCODING encoding,
                                TAP_Buffer *pSerializedKeyBuffer, TAP_ErrorContext *pErrContext);

MOC_EXTERN MSTATUS TAP_extractPrivateKeyBlob(
        TAP_Key *pTapKey,
        TAP_Buffer *pPrivBlob,
        TAP_ErrorContext *pErrContext);

MOC_EXTERN MSTATUS TAP_extractPublicKeyBlob(
        TAP_Key *pTapKey,
        TAP_Buffer *pPubBlob,
        TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to deserialize a TAP_Key.
 * @details Function to deserialize a TAP_Key. This calls the underlying security module to deserialize the module-specific key structure.
 *       <p> If the caller serialize the key via the CRYPTO APIs, the corresponding CRYPTO call to deserialize the key should be used instead.
 *       <p> If have objectID, must call initObject to "deserialize"; Otherwise, call loadObject to "deserialize"
 * @param [in]  pSerializedKeyBuffer  The serialized key buffer, created by TAP_serializeKey.
 * @param [out] ppTapKey              TAP_Key created from the serialized blob.
 * @param [out] pErrContext           In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for ppTapKey and must be freed by a call to TAP_freeKey.
 */
MOC_EXTERN MSTATUS TAP_deserializeKey(TAP_Buffer *pSerializedKeyBuffer, TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext);




/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to prepare a TAP_Key for use.
 * @details Function to prepare a TAP_Key for use.  This includes associating a TAP context and optional module-specific information
 *          with a TAP_Key.  If required or supported by the underlying module, it will also load the key into HW.
 *
 * @param [in]     pTapContext       Pointer to TAP context to associate with the key
 * @param [in]     pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in,out] pTapKey           TAP_Key to load.
 * @param [in]     pKeyCredentials   Optional TAP_EntityCredentialList containing key credential(s)
 * @param [in]     pAttributes       Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [out]    pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note TAP_deserializeKey should be called when reading the key from storage to get the TAP_Key.
 * @note TAP_unloadKey must be called when done with key.
 */
MOC_EXTERN MSTATUS TAP_loadKey(TAP_Context *pTapContext,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_Key *pTapKey,
                           TAP_CredentialList *pKeyCredentials,
                           TAP_AttributeList *pAttributes,
                           TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unload a TAP_Key.
 * @details Function to unload a TAP_Key.  This includes disassociating the TAP context from the key.  If required
 *          or supported by the underlying module, it will also unload the key from HW.
 *
 * @param [in]   pTapKey          Pointer to TAP_Key to be unloaded
 * @param [out]  pErrContext      In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note TAP_serializeKey should be called to serialize the key for writing the key to storage before unloading the key.
 */
MOC_EXTERN MSTATUS TAP_unloadKey(TAP_Key *pTapKey, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unloads the internal SMP key or key handle associated originally with a TAP key.
 * @details Function to unloads the internal SMP key or key handle associated originally with a TAP key.
 *
 * @param [in]   pTapCtx          Pointer to TAP Context associate with the key to be unloaded.
 * @param [in]   pTokenHandle     The handle of the token associated with the key to be unloaded.
 * @param [in]   pKeyHandle       The handle of the key to be unloaded.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note TAP_serializeKey should be called to serialize the key for writing the key to storage before unloading the key.
 */
MOC_EXTERN MSTATUS TAP_unloadSmpKey(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle, TAP_KeyHandle keyHandle);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unloads the internal SMP token.
 * @details Function to unloads the internal SMP token.
 *
 * @param [in]   pTapCtx          Pointer to TAP Context associate with the token to be uninitialized.
 * @param [in]   tokenHandle     The handle of the token.to be uninitialized.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 */
MOC_EXTERN MSTATUS TAP_uninitToken(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to set the global deferred token unload flag.
 * @details Function to set the global deferred token unload flag.
 *
 * @param [in] defer TRUE to set global token deferment.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 */
MOC_EXTERN void TAP_setGlobalDeferredTokenUnload(ubyte defer);

/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to generate an object.
 * @details Function to generate an object.
 *
 * @param [in]   pTapContext        Pointer to TAP context to associate with the object
 * @param [in]   pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]   pObjectAttributes  Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [in]   pObjectCredentials Optional credential(s) to associate with the object.
 * @param [out]  pObjectType        The object type/structure generated.
 * @param [out]  ppObject           The object generated. Can be a TAP_Object or TAP_StorageObject.
 * @param [out]  pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for ppObject and must be freed via TAP_freeObject.
 */
MOC_EXTERN MSTATUS TAP_generateObject(TAP_Context *pTapContext,
                                  TAP_EntityCredentialList *pUsageCredentials,
                                  TAP_AttributeList *pObjectAttributes,
                                  TAP_CredentialList *pObjectCredentials,
                                  TAP_OBJECT_TYPE *pObjectType, void **ppObject,
                                  TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to prepare a persistent object for use.
 * @details Function to prepare a persistent object for use. This includes associating a TAP context and optional module-specific information with the object.
 *
 * @param [in]   pTapContext        Pointer to TAP context to associate with the object
 * @param [in]   pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]   pObjectInfo        Information about the object to initialize.
 * @param [in]   pObjectAttributes  Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [out]  pObjectType        The object type/structure.
 * @param [out]  ppObject           The object initialized. Can be a TAP_Object or TAP_StorageObject.  TAP_loadKey should be used for key objects.
 * @param [out]  pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for ppObject and must be freed via TAP_freeObject.
 * @note TAP_unloadObject must be called when done with the object.
 */
MOC_EXTERN MSTATUS TAP_initObject(TAP_Context *pTapContext,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_ObjectInfo *pObjectInfo,
                              TAP_AttributeList *pObjectAttributes,
                              TAP_OBJECT_TYPE *pObjectType, void **ppObject,
                              TAP_ErrorContext *pErrContext);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to serialize a TAP_Object.
 * @details Function to serialize a TAP_Object. This calls the underlying security module to serialize the module-specific object structure.
 *       <p> This calls gets the serialized object blob from the provider, and serializes that along with the TAP_Object fields.
 *           If the object has an objectID, this function results in a call to SMP_serializeObject;
 *           If the object has an objectHandle, this function results in a call to SMP_exportObject.
 *       <p> The pObject is modified only in that it will have the newly serialized module blob associated with it.
 *
 * @param [in]   objectType               The object type/structure to be serialize.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in]   pObject                  The object to be serialized. Can be a TAP_Object or TAP_StorageObject.  TAP_serializeKey should be used for key objects.
 * @param [in]   format                   Format in which to serialized the object.
 * @param [in]   encoding                 Encoding for the serialized the object.
 * @param [out]  pSerializedObjectBuffer  Serialized object blob.
 * @param [out]  pErrContext              In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for pObjectBlob and must be freed by a call to TAP_UTILS_freeBuffer.
 * @note   Currently, only the Mocana blob format is supported.
 */
MOC_EXTERN MSTATUS TAP_serializeObject(TAP_OBJECT_TYPE objectType, void *pObject,
                                   TAP_BLOB_FORMAT format, TAP_BLOB_ENCODING encoding,
                                   TAP_Buffer *pSerializedObjectBuffer, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to deserialize a TAP_Object.
 * @details Function to deserialize a TAP_Object. This calls the underlying security module to deserialize the module-specific object structure.
 *
 * @param [in]  pSerializedObjectBuffer The serialized object blob.
 * @param [out] pObjectType             The object type/structure deserialized.
 * @param [out] ppObject                Object created from the serialized blob. The structure is determined by objectType
 * @param [out] pErrContext             In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for ppObject and must be freed by a call to TAP_freeObject.
 */
MOC_EXTERN MSTATUS TAP_deserializeObject(TAP_Buffer *pSerializedObjectBuffer,
                                     TAP_OBJECT_TYPE *pObjectType, void **ppObject,
                                     TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to associate a credential with a previously initialized TAP context.
 * @details Function to associate a credential with a previously initialized TAP context.
 *
 * @param [in]   objectType          The object type/structure.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in]   pObject             Object with which to associated the credential(s)
 * @param [in]   pObjectCredentials  Optional credential(s) to associate with the object.
 * @param [out]  pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note Any sensitive information, including credentials, will be cleared from the input arguments before returning.
 * The caller must make sure they have a copy of this information if it is needed after this call.
 */
MOC_EXTERN MSTATUS TAP_associateCredentialWithObject(TAP_OBJECT_TYPE objType, void *pObject,
                                                 TAP_EntityCredentialList *pObjectCredentials,
                                                 TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief   Function to prepare a TAP_Object for use.
 * @details Function to prepare a TAP_Object for use.  This includes associating a TAP context and optional module-specific information
 *          with a TAP_Object.  If required or supported by the underlying module, it will also load the object into HW.
 *
 * @param [in]     pTapContext        Pointer to TAP context to associate with the object
 * @param [in]     pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]     objectType         The object type/structure to load.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in,out] pObject            The object to load.
 * @param [in]     pObjectCredentials Optional credential(s) to associate with the object.
 * @param [in]     pAttributes        Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [out]    pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note TAP_deserializeObject should be called when reading the object from storage to get the Object.
 * @note TAP_unloadKey should be called when done with object.
 */
MOC_EXTERN MSTATUS TAP_loadObject(TAP_Context *pTapContext,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_OBJECT_TYPE objectType, void *pObject,
                              TAP_CredentialList *pObjectCredentials,
                              TAP_AttributeList *pAttributes,
                              TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unload a TAP_Object.
 * @details Function to unload a TAP_Object.  This includes disassociating the TAP context from the object.  If required
 *          or supported by the underlying module, it will also unload the object from HW.
 *
 * @param [in]   objectType      The object type/structure to unload.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in]   pObject         Pointer to TAP_Object to be unloaded
 * @param [out]  pErrContext     In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note TAP_serializeObject should be called to serialize the object for writing the object to storage before calling this API.
 */
MOC_EXTERN MSTATUS TAP_unloadObject(TAP_OBJECT_TYPE objectType, void *pObject, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to free a TAP_Object or a TAP_StorageObject.
 * @details Function to free a TAP_Object or a TAP_StorageObject.
 *
 * @param [in]   objectType     The object type/structure to free.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in,out] ppObject     The object to be freed.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This frees all memory allocated for the object.
 * @note   TAP_unloadObject should be called before this function so the provider can free any memory and clean
 *         up any context associated with its internal object.
 */
MOC_EXTERN MSTATUS TAP_freeObject(TAP_OBJECT_TYPE objectType, void **ppObject);



/**
 * @ingroup tap_api_functions
 *
 * @brief Function to obtain a quote for attestation.
 * @details Function to obtain a quote for attestation.
 *
 * @param [in]  pTapKey            Pointer to TAP_Key to use for attestation, which must have an associated TAP context
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  dataType           Value indicating the type of trusted data (measurement, identifier, report).
 * @param [in]  pDataInfo          Structure containing a module-specific data subtype and corresponding attributes.
 *                                 <p> Users should refer to the SMP documentation for details on valid values.
 * @param [in]  pQualifyingData    Optional qualifying data, which is typically a nonce.
 * @param [in]  pAttributes        Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [out] pAttestationData   Pointer to a TAP_Blob containing the attestation information.
 * @param [out] pSignature         Pointer to the signed quote data returned.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSignature and must be freed by calling TAP_UTILS_freeTapSignatureFields.
 *         If memory was allocated for the TAP_Signature itself, it should be freed via TAP_UTILS_freeTapSignature.
 *
 * @note  A module may either ignore or require the sigScheme, depending on whether or not this was provided during
 *        key creation.  Refer to the module-specific documentation for Sign.
 */
MOC_EXTERN MSTATUS TAP_getQuote(TAP_Key *pTapKey,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_TRUSTED_DATA_TYPE dataType,
                            TAP_TrustedDataInfo *pDataInfo,
                            TAP_Buffer *pQualifyingData,
                            TAP_AttributeList *pAttributes,
                            TAP_Blob *pAttestationData,
                            TAP_Signature *pSignature,
                            TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to seal data using measured storage.
 * @details Function to seal data using measured storage. Sealing data locks it to the current state of the module and/or system.
 *
 * @param [in]  pTapContext        Pointer to TAP context to associate with the module.  This can be NULL if an object with a
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 *                                 valid context is provided.
 * @param [in]  objectType         The object type/structure to be used.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in]  pObject            Pointer to the object.
 * @param [in]  pObjectCredential  Optional credential to use for sealing data.  If an object credential is supplied during the seal operation,
 *                                 that credential must be supplied in the usage credentials for the unseal operation.
 *                                 Some SMPs may not require or support a credential.
 * @param [in]  pSealAttributes    Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [in]  pDataToSeal        Pointer to a TAP_Buffer containing the data to seal.
 * @param [out] pSealedData        Pointer to a TAP_Buffer containing the sealed data buffer.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSealedData and must be freed by via DIGI_FREE().
 *
 * @note  A module may either ignore or require the a TAP_Key and/or a credential.
 */
MOC_EXTERN MSTATUS TAP_sealWithTrustedData(TAP_Context *pTapContext,
                                       TAP_EntityCredentialList *pUsageCredentials,
                                       TAP_OBJECT_TYPE objectType, void *pObject,
                                       TAP_CredentialList *pObjectCredentials,
                                       TAP_SealAttributes *pSealAttributes, TAP_Buffer *pDataToSeal,
                                       TAP_Buffer *pSealedData, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unseal data.
 * @details Function to unseal data. Sealed data can only be unsealed if the current state matches the state when sealed.
 *
 * @param [in]  pTapContext        Pointer to TAP context to associate with the module.  This can be NULL if an object with a
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 *                                 This must include any object credential(s) providing during the seal operation.
 * @param [in]  objectType         The object type/structure to be used.  Must be a valid TAP_OBJECT_TYPE.
 * @param [in]  pObject            Pointer to the object.
 * @param [in]  pAttributes        Optional attribute list containing additional information for the SMP not supplied by the input parameters.
 * @param [out] pSealedData        Pointer to a TAP_Buffer containing the sealed data buffer.
 * @param [in]  pUnsealedData      Pointer to a TAP_Buffer containing the unsealed data.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pSealedData and must be freed by via DIGI_FREE().
 *
 * @note  A module may either ignore or require the a TAP_Key and/or a credential.
 * @note  pExtraInfo must point to a module-specific structure. Refer to the module-specific documentation for Seal.
 */
MOC_EXTERN MSTATUS TAP_unsealWithTrustedData(TAP_Context *pTapContext,
                                         TAP_EntityCredentialList *pUsageCredentials,
                                         TAP_OBJECT_TYPE objectType, void *pObject,
                                         TAP_SealAttributes *pUnsealAttributes, TAP_Buffer *pSealedData,
                                         TAP_Buffer *pUnsealedData, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to configure a new policy authenticated storage location.
 * @details Function to configure a new policy authenticated storage location.
 *          This maps to the SMP createObject API.
 *
 * @param [in]  pTapContext       Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  pStorageInfo      TAP_StorageInfo structure containing information needed to allocate the policy storage.
 *                                Any TAP_PolicyStorageAttributes needed should be included in this structure.
 * @param [in]  pAttributes       Optional TAP_ObjectAttributes containing additional information for the SMP not supplied by
 *                                the input parameters.
 * @param [in]  pStorageCredentials  Optional credential to use for allocating policy storage.
 *                                Some SMPs may not require or support a credential.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for the new TAP_StorageObject.  This must be freed via TAP_freeObject.
 * @note  A module may either ignore or require the credential.
 */
MOC_EXTERN MSTATUS TAP_allocatePolicyStorage(TAP_Context *pTapContext,
                                         TAP_EntityCredentialList *pUsageCredentials,
                                         TAP_StorageInfo *pStorageInfo,
                                         TAP_ObjectAttributes *pAttributes,
                                         TAP_CredentialList *pStorageCredentials,
                                         TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unconfigure a policy authenticated storage location.
 * @details Function to unconfigure a policy authenticated storage location.
 *          This maps to the SMP deleteObject API.
 *
 * @param [in]  pTapContext         Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  pStorageInfo        Structure containing information about the Policy storage object to be freed
 * @param [out] pErrContext         In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 */
MOC_EXTERN MSTATUS TAP_freePolicyStorage(TAP_Context *pTapContext,
                                     TAP_EntityCredentialList *pUsageCredentials,
                                     TAP_StorageInfo *pStorageInfo,
                                     TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to return a list of policy authenticated storage locations.
 * @details Function to return a list of policy authenticated storage locations.
 *          This is a wrapper function around the getObjectList API to simplify obtaining the list of policy storage locations.
 *
 * @param [in]  pTapContext       Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  pAttributes       Optional attribute list containing information for the SMP to filter out locations.
 *                                This can include one or more storage locations, type(s), etc.
 * @param [out] pObjectInfoList   The list of policy storage locations returned.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_getPolicyStorageList(TAP_Context *pTapContext,
                                        TAP_EntityCredentialList *pUsageCredentials,
                                        TAP_PolicyStorageAttributes *pAttributes,
                                        TAP_ObjectInfoList *pObjectInfoList,
                                        TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to return information about policy authenticated storage location(s) and the details associated with the location(s).
 * @details Function to return information about policy authenticated storage location(s) and the details associated with the location(s).
 *          This maps to SMP getObjectList and getObjectInfo APIs.
 *
 * @param [in]  pTapContext       Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  pAttributes       Optional attribute list containing information for the SMP to filter out locations.
 * @param [in]  pObjectInfoList   Optional list of policy storage locations for which details are requested.  If none provided,
 *                                it is expected that the SMP will return details for all locations.
 * @param [out] pDetailsList      Returned list containing the details of the requested policy storage location(s).
 *                                <p>  The objects in the list are not ready for use and must be initialized via TAP_initObject.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_getPolicyStorageDetails(TAP_Context *pTapContext,
                                           TAP_EntityCredentialList *pUsageCredentials,
                                           TAP_PolicyStorageAttributes *pAttributes,
                                           TAP_ObjectInfoList *pObjectInfoList,
                                           TAP_StorageObjectList *pDetailsList,
                                           TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to read contents of the specified policy authenticated storage location.
 * @details Function to read contents of the specified policy authenticated storage location.
 *          This maps to the SMP initObject and getPolicyStorage APIs
 *
 * @param [in]  pTapContext        Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  pObjectInfo        The #TAP_ObjectInfo for the policy storage location from which data is to be read.
 * @param [in]  pOpAttributes      Attribute list containing information for the read operation.  This may include
 *                                 an offset, size, etc.
 * @param [out] pOutData           Pointer to the data buffer containing contents of the policy storage location.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pNVOutData and must be freed by via DIGI_FREE().
 *
 * @note  A module may either ignore or require the a credential.
 * @note pOpAttributes may include TAP_ATTR_SIZE and TAP_ATTR_OFFSET, TAP_ATTR_READ_OP
 */
MOC_EXTERN MSTATUS TAP_getPolicyStorage(TAP_Context *pTapContext,
                                    TAP_EntityCredentialList *pUsageCredentials,
                                    TAP_ObjectInfo *pObjectInfo,
                                    TAP_OperationAttributes *pOpAttributes,
                                    TAP_Buffer *pOutData,
                                    TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to write data to specified policy authenticated storage location.
 * @details Function to write data to specified policy authenticated storage location.
 *          This maps to the SMP initObject and setPolicyStorage APIs
 *
 * @param [in]  pTapContext          Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials    Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  pObjectInfo          The #TAP_ObjectInfo for the policy storage location to which data is to be written.
 * @param [in]  pOpAttributes        Attribute list containing information for the write operation.  This may include
 *                                   TAP_ATTR_OFFSET, TAP_ATTR_SIZE, etc.
 * @param [out] pInData              Pointer to the data buffer containing buffer to write to authenticated storage location.
 * @param [out] pErrContext          In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 * @note  A module may either ignore or require the a credential.
 * @note pOpAttributes may include TAP_ATTR_SIZE and TAP_ATTR_OFFSET, TAP_ATTR_WRITE_OP
 */
MOC_EXTERN MSTATUS TAP_setPolicyStorage(TAP_Context *pTapContext,
                                    TAP_EntityCredentialList *pUsageCredentials,
                                    TAP_ObjectInfo *pObjectInfo,
                                    TAP_OperationAttributes *pOpAttributes,
                                    TAP_Buffer *pInData,
                                    TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to read trusted data.
 * @details Function to read trusted data.
 *
 * @param [in]  pTapContext       Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials   Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  dataType          Value indicating the type of trusted data (measurement, identifier, report).
 * @param [in]  pDataInfo         Structure containing a module-specific data subtype and corresponding attributes.
 *                                <p> Users should refer to the SMP documentation for details on valid values indicating which trusted data to read.
 * @param [out] pTrustedData      Pointer to the buffer containing the trusted data read.
 *                                Refer to the SMP documentation for the data and format returned for the various type/subtype requests.
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 * @note  A module may either ignore or require the a credential.
 *
 * @memory  Memory is allocated for the pTrustedData->pBuffer.  This must be freed by the caller via DIGI_FREE.
 */
MOC_EXTERN MSTATUS TAP_getTrustedData(TAP_Context *pTapContext,
                                  TAP_EntityCredentialList *pUsageCredentials,
                                  TAP_TRUSTED_DATA_TYPE dataType,
                                  TAP_TrustedDataInfo *pDataInfo,
                                  TAP_Buffer *pTrustedData, TAP_ErrorContext *pErrContext);


/**
 * @ingroup tap_api_functions
 *
 * @brief Function to update trusted data.
 * @details Function to update trusted data.
 *
 * @param [in]  pTapContext       Pointer to TAP_Context to use.
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or key credentials, etc.
 * @param [in]  dataType          Value indicating the type of trusted data (measurement, identifier, report).
 * @param [in]  pDataInfo         Structure containing a module-specific data subtype and corresponding attributes.
 *                                <p> Users should refer to the SMP documentation for details on valid values indicating which trusted data to update.
 * @param [in]  operation         Value indicating the trusted data operation.  This can be a write, update, reset, etc.
 * @param [in]  pInData           Pointer to the buffer containing the data to be used to update the trusted data.
 *
 * @param [out] pOutData          Pointer to the buffer containing the updated trusted data.
 *                                Refer to the SMP documentation for the data and format returned for the various type/subtype requests.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 * @note  A module may either ignore or require the a credential.
 */
MOC_EXTERN MSTATUS TAP_updateTrustedData(TAP_Context *pTapContext,
                                     TAP_EntityCredentialList *pUsageCredentials,
                                     TAP_TRUSTED_DATA_TYPE dataType,
                                     TAP_TrustedDataInfo *pDataInfo,
                                     TAP_TRUSTED_DATA_OPERATION operation,
                                     TAP_Buffer *pInData,
                                     TAP_Buffer *pOutData, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief This API is used in the privacy CA protocol of generating and activating a credential for an attestation key.
 * @details This API is used in the privacy CA protocol of generating and activating a credential for an attestation key. It generates Base-64 encoded blob containing public attributes of the secure element and attesation key, it will be used by the privacy CA to determine if it can provide a credential for the given key.
 *
 * @param [in]  pTapKey           Attestation key for which the credential request blob is to be generated
 * @param [in]  pCSRattributes    Optional additional information needed by the secure element to generate the privacy CA blob.
 *
 * @param [out] pBlob             Pointer to the buffer that will contain the blob to be used by privacy CA.
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 */
MOC_EXTERN MSTATUS TAP_getCertificateRequestValidationAttrs(
        TAP_Key *pTapKey,
        TAP_CSRAttributes *pCSRattributes,
        TAP_Blob *pBlob,
        TAP_ErrorContext *pErrContext
);

/**
 * @ingroup tap_api_functions
 *
 * @brief This API can be used to recover the secret wrapped by a credential provider
 * @details This API can be used to recover the secret wrapped by a credential provider
 *
 * @param [in]  pTapContext        Pointer to TAP context to associate with the object
 * @param [in]  pUsageCredentials  Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pTapKey            Attestation key for which the credential request blob is to be generated
 * @param [in]  pRoTKey            Root of Trust key of this secure element
 * @param [in]  pBlob              Pointer to the buffer containing wrapped credential from the Privacy CA
 * @param [out] pSecret            Pointer to the buffer that will contain the unwrapped credential from secure element
 * @param [out] pErrContext        In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 */
MOC_EXTERN MSTATUS TAP_unwrapKeyValidatedSecret(
        TAP_Context *pTapContext,
        TAP_EntityCredentialList *pUsageCredentials,
        TAP_Key *pTapKey,
        TAP_Key *pRoTKey,
        TAP_Blob *pBlob,
        TAP_Buffer *pSecret,
        TAP_ErrorContext *pErrContext
);

/**
 * @ingroup tap_api_functions
 *
 * @brief This API can be used to retrieve the Root of Trust certificate from the secure element
 * @details This API can be used to retrieve the Root of Trust certificate from the secure element
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module whose Root of Trust certificate is requested.
 * @param [in]  pRoTInfo          Root of Trust key information that contains the ID of Root of Trust key (See SMP documentation for valid values of Root of Trust Identifiers)
 * @param [in]  type              Type of Certificate (see the SMP documentation for details on applicable values)
 * @param [out] pCertificate      Pointer to the buffer that will contain the unwrapped credential from secure element
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 */
MOC_EXTERN MSTATUS TAP_getRootOfTrustCertificate(
        TAP_Context *pTapContext,
        TAP_ObjectInfo *pRotInfo,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Blob *pCertificate,
        TAP_ErrorContext *pErrContext
);

/**
 * @ingroup tap_api_functions
 *
 * @brief This API can be used to retrieve the Root of Trust key
 * @details This API can be used to retrieve the Root of Trust key, needed for TAP_unwrapKeyValidatedSecret
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module whose Root of Trust certificate is requested.
 * @param [in]  pRoTKeyInfo       Root of Trust key information that contains the ID of Root of Trust key (See SMP documentation for valid values of Root of Trust Identifiers)
 * @param [in]  type              Type of Certificate (see the SMP documentation for details on applicable values)
 * @param [out] ppRotKey          Pointer to a pointer that will contain the Root of Trust Key
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 */
MOC_EXTERN MSTATUS TAP_getRootOfTrustKey(
        TAP_Context *pTapContext,
        TAP_KeyInfo *pRotKeyInfo,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Key **ppRotKey,
        TAP_ErrorContext *pErrContext
);

/**
 * @ingroup tap_api_functions
 *
 * @brief This API can be used to retrieve the Root of Trust key from TPM in Mocana internal blob format
 * @details This API can be used to retrieve the Root of Trust key from TPM in Mocana internal blob format
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module whose Root of Trust certificate is requested.
 * @param [in]  objectId          the objectID of Root of Trust key (See SMP documentation for valid values of Root of Trust Identifiers)
 * @param [in]  type              Type of Certificate (see the SMP documentation for details on applicable values)
 * @param [out] pPubKey           Pointer to a TAP_Buffer that will contain the Root of Trust Key in Mocana internal blob format
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 *
 */

MOC_EXTERN MSTATUS TAP_getRootOfTrustPublicKeyBlob(TAP_Context *pTapContext,
        TAP_ObjectId objectId, TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Buffer *pPubKey, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to duplicate an asymmetric key.
 * @details Function to duplicate an asymmetric key.
 *
 * @param [in]  pTapKey           Pointer to TAP_Key to use, which must have an associated TAP context
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pOpAttributes     Optional attribute list containing additional information for the SMP to perform the duplicate operation.
 * @param [in]  pInPeerPublic     TAP_Buffer containing the public key blob of the new parent.
 * @param [out] pOutDuplicate     Pointer to a TAP_Buffer structure. The Duplicate datastructure returned by the TPM is formatted in Mocana internal format
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory On success, memory is allocated for pOutDuplicate->pBuffer fields and must be freed by calling application.
 *
 */
MOC_EXTERN MSTATUS TAP_exportDuplicateKey(
    TAP_Key *pTapKey,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_AttributeList *pOpAttributes,
    TAP_Buffer *pInPeerPublic,
    TAP_Buffer *pOutDuplicate,
    TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to import an asymmetric key using underlying security module.
 * @details Function to import an asymmetric key using underlying security module. This function requires that the following functions be called prior to this call:
 *   - TAP_init
 *   - TAP_initContext
 * <p> All information needed must be provided in the module-specific pKeyParams structure, including any key credential(s).
 * <p> If the caller intends to use the generated key in the CRYPTO APIs, the corresponding CRYPTO call to generate a key should be used instead.
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module.
 * @param [in]  pUsageCredentials Optional credential(s) an SMP may need/support to perform the operation. This can include module credentials (if not associated with the context), token or parent key credentials, etc.
 * @param [in]  pKeyInfo          Algorithm and corresponding information of the key to generate (RSA, ECC, etc).
 * @param [in]  pDuplicateBuf     Pointer to a TAP_Buffer containing the duplicated key blob to be imported into this TPM.
 * @param [in]  pKeyAttributes    Optional list of additional information that may be needed or supported by the
 *                                module to generate an asymmetric key.
 * @param [in]  pKeyCredential    Optional credential an SMP may need/support to generate a key.
 * @param [out] ppTapKey          TAP_Key generated, which includes the underlying module-specific key structure
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory Memory is allocated for the underlying key and must be freed by TAP_freeKey.
 *
 * @note   This function automatically loads the key so it is ready for use.  The user must call TAP_unloadKey when done with the key.
 */

MOC_EXTERN MSTATUS TAP_importDuplicateKey(TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_KeyInfo *pKeyInfo,
                            TAP_Buffer *pDuplicateBuf,
                            TAP_AttributeList *pKeyAttributes,
                            TAP_CredentialList *pKeyCredentials,
                            TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to check if TAP provider is loaded.
 * @details Function takes in a provider specified by the caller and checks the
 *          existing list of loaded providers. If the provider is found then
 *          pFound is set to TRUE otherwise it is FALSE.
 *
 * @param [in]  provider          Provider to search for.
 * @param [in]  pFound            Boolean value specifying whether provider is loaded or not. TRUE is loaded otherwise FALSE.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 *
 */
MOC_EXTERN MSTATUS TAP_checkForProvider(TAP_PROVIDER provider, intBoolean *pFound);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to unpersist a previously created and persistent key using underlying security module.
 * @details Function to remove persistent asymmetric key from the underlying security module.
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module.
 * @param [in]  pObjectId         Persistent ID at which this key is present (in Big Endian byte array form)
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note  This function removes only the persistent state of the key, it does not remove the key from the file system.
 */
MOC_EXTERN MSTATUS TAP_evictObject(TAP_Context *pTapContext,
                                   TAP_Buffer *pObjectId,
                                   TAP_AttributeList *pAttributes,
                                   TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Function to persist a previously created key using underlying security module.
 * @details Function to persist a key in the underlying security module.
 *
 * @param [in]  pTapContext       Pointer to the TAP context associated with the module.
 * @param [in]  pTapKey           Pointer to the TAP key to persist.
 * @param [in]  pObjectId         Index or id where the key is to be persisted (in big Endian byte array form)
 * @param [out] pErrContext       In debug mode, returns debug error information.
 *
 * @return OK on Success
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @note This function persists the key at the given index, it does not modify the existing key into a persistent key.
 */
MOC_EXTERN MSTATUS TAP_persistObject(TAP_Context *pTapContext,
                                TAP_Key *pTapKey,
                                TAP_Buffer *pObjectId,
                                TAP_ErrorContext *pErrContext);

/**
 * @ingroup tap_api_functions
 *
 * @brief Callback implementation that could be used to extend the device specific seed calculations.
 * @details Callback implementation that could be used to extend the device specific seed calculations. Currently
 *          this does not do any extensions, but later it could be modified to make the seed depend on TAP specific details.
 *
 * @param [out]  pSeedBuffer      Pointer to the buffer that will be filled with the resulting seed.
 * @param [out]  pSeedLen         Will be set to the length of the resulting seed in bytes.
 * @param [in]   pArg             (Optional) Pointer to data that may be needed by your implementation. Currently
 *                                this is not used.
 *
 * @return OK on Success and a negative error code from merrors.h on failure.
 */
MOC_EXTERN MSTATUS TAP_DP_seedCallback(ubyte *pSeedBuffer, ubyte4 *pSeedLen, void *pArg);


/**
 * @ingroup tap_api_functions
 *
 * @brief Callback implementation that will extend the existing device global fingerprint with one dependent on the TAP root public key.
 * @details Callback implementation that will extend the existing device global fingerprint with one dependent on the TAP root public key.
 *
 * @param [out]  ppElements      Location that will hold a pointer to a newly allocated list of all fingerprint elements.
 * @param [out]  pNumElements    Will be set to the number of fingerprint elements allocated.
 * @param [in]   pArg            (Optional) Pointer to data that may be needed by your implementation. Currently
 *                               this is not used.
 *
 * @return OK on Success and a negative error code from merrors.h on failure.
 *
 * @memory Memory is allocated for pNumElements fingerprint elements. Be sure to also register \c TAP_DP_freeFingerprintCallback
 *         so that memory is properly freed.
 */
MOC_EXTERN MSTATUS TAP_DP_fingerprintCallback(FingerprintElement **ppElements, ubyte4 *pNumElements, void *pArg);


/**
 * @ingroup tap_api_functions
 *
 * @brief Callback implementation that will zero and free the device global fingerprint.
 * @details Callback implementation that will zero and free the device global fingerprint, including any new fingerprints allocatd by
 *          the \c TAP_DP_fingerprintCallback API.

 * @param [in]  ppElements      Location whos pointer will be zeroed and freed.
 * @param [in]  numElements     The number of fingerprint elements to zero out.
 * @param [in]  pArg            (Optional) Pointer to data that may be needed by your implementation. Currently
 *                              this is not used.
 *
 * @return OK on Success and a negative error code from merrors.h on failure.
 */
MOC_EXTERN MSTATUS TAP_DP_freeFingerprintCallback(FingerprintElement **ppElements, ubyte4 numElements, void *pArg);

#ifdef __cplusplus
}
#endif

/*! @cond */
#endif /* __ENABLE_DIGICERT_TAP__ */
/*! @endcond */

#endif /* __TAP_API_HEADER__ */
