/*
 * smp_tee_api.h
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
@file       smp_tee_api.h
@ingroup    nanosmp_tree
@brief      NanoSMP module feature API header for TEE.
@details    This header file contains enumerations, and function
            declarations for feature APIs implemented by the TEE NanoSMP.
@flags      This file requires that the following flags be defined:
    + \c \__ENABLE_DIGICERT_SMP__
    + \c \__ENABLE_DIGICERT_TEE__
*/

#ifndef __SMP_TEE_API_HEADER__
#define __SMP_TEE_API_HEADER__

/*------------------------------------------------------------------*/

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"

/*! @cond */
#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__))
/*! @endcond */

#include "../smp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup smp_functions
 * @brief Function reads and initializes the global module with the configuration.
 * @details Function reads and initializes the global module with the configuration.
 * @param [in]  pConfigInfo Pointer to the configuration data.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_TEE_init(TAP_ConfigInfo *pConfigInfo);

/**
 * @ingroup smp_functions
 * @brief Function cleans up and frees memory associated with the global module and configuration.
 * @details Function cleans up and frees memory associated with the global module and configuration.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_TEE_uninit(void);

/**
 * @ingroup smp_functions
 * @brief Function obtains the list of modules initialized.
 * @details Function obtains the list of modules initialized.
 * @param [in]  pModuleAttributes Optional, attributes that can be used to verify module id
 * @param [out]  pModuleIdList Pointer to the output module list.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, getModuleList,
    TAP_ModuleCapabilityAttributes *pModuleAttributes,
    TAP_EntityList *pModuleIdList
);

/**
 * @ingroup smp_functions
 * @brief Function initializes the module context and returns a handle for future operations on the module.
 * @details Function initializes the module context and returns a handle for future operations on the module.
 *          The module for which the context is initialized is identified by the @p moduleId and verified
 *          against an optional @p pModuleAttribute.
 * @param [in]  moduleId Module identifier
 * @param [in]  pModuleAttributes Optional, attributes that can be used to verify module id
 * @param [in]  pCredentials Pointer to credentials
 * @param [out]  pModuleHandle Pointer to the Module context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, initModule,
    TAP_ModuleId moduleId,
    TAP_ModuleCapabilityAttributes* pModuleAttributes,
    TAP_CredentialList *pCredentials,
    TAP_ModuleHandle *pModuleHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to free resources allocated to module context.
 * @details Function to free resources allocated to a previously initialized module context.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, uninitModule,
    TAP_ModuleHandle moduleHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to create a new token context.
 * @details Function to create a new token context. The token for which the
 *          context is uniquely indentified by @p tokenId and/or verfied against
 *          @p pTokenAttributes.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  pTokenAttributes Optional, attributes to specify the type of token to create
 * @param [in]  tokenId Token identifier
 * @param [in]  pCredentials pointer to the credentials
 * @param [out]  pTokenHandle Pointer to the Token context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, initToken,
    TAP_ModuleHandle moduleHandle,
    TAP_TokenCapabilityAttributes *pTokenAttributes,
    TAP_TokenId tokenId,
    TAP_EntityCredentialList *pCredentials,
    TAP_TokenHandle *pTokenHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to free resources allocated to the token context.
 * @details Function to free resources allocated to the token context.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, uninitToken,
    TAP_ModuleHandle moduleHandle,
    TAP_TokenHandle tokenHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to create a new object context.
 * @details Function to create a new object. The object for which the context is
 *          created is uniquely identified by @p objectIdIn and/or verified against
 *          attributes specified in @p pObjectAttributes.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectIdIn Optional objectId. An ID  passed in via attributes will take precedence.
 * @param [in]  pObjectAttributes Optional
 * @param [in]  pCredentials Optional
 * @param [out]  pObjectHandle Handle to the Object Contex
 * @param [out]  pObjectIdOut Pointer to initialized object identifier if 8 bytes or less.
 * @param [out] pObjectAttributesOut Optional pointer to attributes that contains
 *              attributes of the newly created object
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, initObject,
    TAP_ModuleHandle moduleHandle,
    TAP_TokenHandle tokenHandle,
    TAP_ObjectId objectIdIn,
    TAP_ObjectCapabilityAttributes *pObjectAttributes,
    TAP_EntityCredentialList *pCredentials,
    TAP_ObjectHandle *pObjectHandle,
    TAP_ObjectId *pObjectIdOut,
    TAP_ObjectAttributes *pObjectAttributesOut
);

/**
 * @ingroup smp_functions
 * @brief This API deletes the object and corresponding context, identified by @p objectHandle
 * @details This API deletes the object and corresponding context, identified by @p objectHandle
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, deleteObject,
    TAP_ModuleHandle moduleHandle,
    TAP_TokenHandle tokenHandle,
    TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief This API sets the data in a storage object which is saved on the secure element, with an associated policy.
 * @details This API sets the data in a storage object which is saved on the secure element, with an associated policy.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  pPolicyAttributes Optional, attributes used for the set operation.
 * @param [in]  pOpAttributes Attributes used to pass information for set operation.
 * @param [in] pData Pointer to buffer containing data to save
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, setPolicyStorage,
    TAP_ModuleHandle moduleHandle,
    TAP_TokenHandle tokenHandle,
    TAP_ObjectHandle objectHandle,
    TAP_PolicyStorageAttributes *pPolicyAttributes,
    TAP_OperationAttributes *pOpAttributes,
    TAP_Buffer *pData
);

/**
 * @ingroup smp_functions
 * @brief This API gets the data in a storage object which is saved on the secure element, with an associated policy.
 * @details This API gets the data in a storage object which is saved on the secure element, with an associated policy.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  pOpAttributes Attributes containing information on operational
 *              parameters.
 * @param [out] pData Pointer to buffer containing retrieved data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TEE, getPolicyStorage,
    TAP_ModuleHandle moduleHandle,
    TAP_TokenHandle tokenHandle,
    TAP_ObjectHandle objectHandle,
    TAP_OperationAttributes *pOpAttributes,
    TAP_Buffer *pData
);

#ifdef __cplusplus
}
#endif
/*! @cond */
#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_TEE__ */
/*! @endcond */
#endif /* __SMP_TEE_API_HEADER__ */
