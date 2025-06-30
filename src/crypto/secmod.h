/**
 * @file secmod.h
 *
 * @ingroup crypto_nanotap_tree
 *
 * @brief Security Module (SECMOD) General Definitions & Types Header
 * @details Security Module (SECMOD)  General Definitions & Types Header
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_HW_SECURITY_MODULE__
 *
 * <p>Whether the following flags are defined determines whether or not support is enabled for a particular HW security module:
 *    + \c \__ENABLE_MOCANA_TPM__
 *
 * Copyright (c) Mocana Corp 2017. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


/*------------------------------------------------------------------*/

#ifndef __SECMOD_HEADER__
#define __SECMOD_HEADER__

/*! @cond */
/*if a secmod is enabled, this will allow the context to be passed into the CRYPTO_* functions in pubcrypto.c*/
#ifdef __ENABLE_MOCANA_HW_SECURITY_MODULE__
#define MOC_SECMOD(X)   X,
#else
/*! MOC_SECMOD is ignored if  __ENABLE_MOCANA_HW_SECURITY_MODULE__ flag not enabled; if flag is enabled, MOC_SECMOD passes X through withouth translation. */
#define MOC_SECMOD(X)
#endif
/*! @endcond */

#include "../common/mtypes.h"
#include "../common/merrors.h"
#ifdef __ENABLE_MOCANA_HW_SECURITY_MODULE__
#include "../smp/smp_tpm12/tpm12_lib/secmod_types.h"
#ifdef __ENABLE_MOCANA_TPM__
#include "../smp/smp_tpm12/tpm12_lib/tpm/tpm12_rsa.h"
#include "../smp/smp_tpm12/tpm12_lib/tpm/sapi/sapi_context.h"
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_TPM__
/*! Current TPM 1.2 NanoTAP Code Version */
#define SECMOD_TPM_VERSION "1.2.2"
#endif

/**
 * @ingroup crypto_nanotap_definitions
 * @details The security module descriptor
 */
typedef struct secModDescr
{
    /*! Type of security module */
    SECMOD_TYPE         type;
    /*! ID of the security module */
    ubyte4              id;
    /*! The error returned from the lower level security module (e.g. TPM, etc) */
    void                *lastErr;
    /*! The eKeyBox storage */
    void                *pEkeyBoxListHead;
#ifdef __ENABLE_MOCANA_TPM__
    /*! Context based on security module type */
    union
    {
        /*! The TPM 1.2 context */
        TSS_SYS_CONTEXT *TPM12Ctx;
    } secmodCtx;
#endif
} secModDescr;

struct AsymmetricKey;

/**
 * @brief Initialize a hardware security module
 * @details This function initializes a hardware security module.
 *
 * @ingroup crypto_nanotap_functions
 *
 * @param [in,out] secModContext  secModDescr to initialize
 * @param [in] secmodType         type of secModDescr to initialize (e.g. secmod_TPM12)
 * @param [in] serverNameLen      Length of server name
 * @param [in] pServerName        Server name for connection
 * @param [in] serverPort         Server port for connection
 * @param [in] params             extra paramaters needed to initialize the secModDescr (can be NULL)
 *
 * @return OK on success
 * @return ERR_SECMOD_INVALID_SECMOD_TYPE if the structure is invalid
 *
 * @note This function calls the init function corresponding to the secmodType.
 *
 * @memory  SECMOD_uninit must be called to free memory allocated by this function.
 */
MOC_EXTERN MSTATUS SECMOD_init(secModDescr* secModContext, SECMOD_TYPE secmodType, ubyte4 serverNameLen, ubyte *pServerName, ubyte2 serverPort, void* params);


/**
 * @brief Uninitialize a hardware security module
 * @details This function uninitializes a hardware security module.
 *
 * @ingroup crypto_nanotap_functions
 *
 * @param [in,out] secModContext  secModDescr to uninitialize
 *
 * @return OK on success
 * @return ERR_SECMOD_INVALID_SECMOD_TYPE if the structure is invalid
 *
 * @note This function calls the uninit function corresponding to the secmodType.
 *
 * @memory  This function frees memory allocated by SECMOD_init.
 */
MOC_EXTERN MSTATUS SECMOD_uninit(secModDescr* secModContext);

/**
 * @brief Free a secModDescr
 * @details This function frees a secModDescr
 *
 * @ingroup crypto_nanotap_functions
 *
 * @param [in,out] secModContext  secModDescr to free
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if secModContext is NULL
 *
 * @note This function also frees up the HSM specific context held in the secModDescr
 */
MOC_EXTERN MSTATUS SECMOD_free_secModDescr(secModDescr *secModContext);


/**
 * @private
 * @internal
 *
 * @brief Function to copy a secModDescr
 *
 * @param [in,out] pDestContext  secModDescr to copy to
 * @param [in] pSrcContext       secModDescr to copy from
 *
 * @return OK on success
 * @return ERR_NULL_POINTER if secModContext is NULL
 */
MOC_EXTERN MSTATUS SECMOD_copy_secModDescr(secModDescr *pDestContext, secModDescr *pSrcContext);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_MOCANA_HW_SECURITY_MODULE__ */

#endif /* __SECMOD_HEADER__ */
