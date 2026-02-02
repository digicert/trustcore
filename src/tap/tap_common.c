/*
 * tap_common.c
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
 */
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "tap.h"
#include "tap_common.h"

#include "tap_serialize.h"
#include "tap_serialize_smp.h"
#include "tap_base_serialize.h"
#include "tap_client_comm.h"
#include "tap_utils.h"

/***************************************************************
   Constant Definitions
****************************************************************/

TAP_Version tapVersion = {TAP_VERSION_MAJOR, TAP_VERSION_MINOR};
#ifdef __ENABLE_DIGICERT_SMP__
TAP_SMPVersion smpVersion = {SMP_VERSION_MAJOR, SMP_VERSION_MINOR};
#else
TAP_SMPVersion smpVersion = {0, 0};
#endif

/*------------------------------------------------------------------*/
/*  Functions        */
/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_checkTapProvider(TAP_PROVIDER tapProvider)
{
    MSTATUS status = ERR_TAP_INVALID_TAP_PROVIDER;

    switch(tapProvider)
    {
        case TAP_PROVIDER_TPM:
#ifdef __ENABLE_DIGICERT_TPM__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_TPM2:
#ifdef __ENABLE_DIGICERT_TPM2__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_SGX:
#ifdef __ENABLE_DIGICERT_SGX__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_STSAFE:
#ifdef __ENABLE_DIGICERT_STSAFE__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_NXPA71:
#ifdef __ENABLE_DIGICERT_NXPA71__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_GEMSIM:
#ifdef __ENABLE_DIGICERT_GEMALTO__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_PKCS11:
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_RENS5:
#ifdef __ENABLE_DIGICERT_RENS5__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_TRUSTX:
#ifdef __ENABLE_DIGICERT_TRUSTX__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_ARMM23:
#ifdef __ENABLE_DIGICERT_ARMM23__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_ARMM33:
#ifdef __ENABLE_DIGICERT_ARMM33__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_EPID:
#ifdef __ENABLE_DIGICERT_EPID__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_TEE:
#ifdef __ENABLE_DIGICERT_TEE__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_SW:
            status = ERR_TAP_UNSUPPORTED;
            break;
        case TAP_PROVIDER_NANOROOT:
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_UNDEFINED:
        default:
            status = ERR_TAP_INVALID_TAP_PROVIDER;
            break;
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_checkCmdSupport(TAP_ProviderList *pProviderList, TAP_PROVIDER tapProvider, SMP_CC cmdCode)
{
    MSTATUS status = ERR_TAP_UNSUPPORTED;
    byteBoolean providerFound = FALSE;
    byteBoolean cmdSupported = FALSE;
    ubyte4 providerIndex = 0;
    ubyte4 cmdIndex = 0;

    if (NULL == pProviderList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_COMMON_checkTapProvider(tapProvider);
    if (OK != status)
    {
        goto exit;
    }

    providerFound = FALSE;
    /* First check if the provider returned a cmdCodeList during registration */
    for (providerIndex = 0; providerIndex < pProviderList->listLen; providerIndex++)
    {
        if (tapProvider == pProviderList->pProviderCmdList[providerIndex].provider)
        {
            providerFound = TRUE;
            break;
        }
    }

    if (FALSE == providerFound)
    {
        status = ERR_TAP_UNSUPPORTED;
        goto exit;
    }

    /* Now check the cmdCode against the list the provider returned. */
    for (cmdIndex = 0; cmdIndex < pProviderList->pProviderCmdList[providerIndex].cmdList.listLen; cmdIndex++)
    {
        if (cmdCode == (SMP_CC)(pProviderList->pProviderCmdList[providerIndex].cmdList.pCmdList[cmdIndex]))
        {
            cmdSupported = TRUE;
            break;
        }
    }

    if (TRUE == cmdSupported)
        status = OK;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_registerProvider(TAP_PROVIDER provider, TAP_ConfigInfo *pConfigInfo, TAP_CmdCodeList *pCmdCodeList)
{
    MSTATUS status = OK;

    if ((NULL == pConfigInfo) || (NULL == pCmdCodeList))

    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (provider)
    {
        case TAP_PROVIDER_SW:
            status = ERR_TAP_UNSUPPORTED;
            break;
        case TAP_PROVIDER_TPM:
        #ifdef  __ENABLE_DIGICERT_TPM__
            status = SMP_TPM12_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_TPM2:
        #ifdef  __ENABLE_DIGICERT_TPM2__
            status = SMP_TPM2_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_SGX:
        #ifdef  __ENABLE_DIGICERT_SGX__
            status = SMP_SGX_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_STSAFE:
        #ifdef  __ENABLE_DIGICERT_STSAFE__
            status = SMP_STSAFE_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_NXPA71:
        #ifdef  __ENABLE_DIGICERT_NXPA71__
            status = SMP_NXPA71_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_GEMSIM:
        #ifdef  __ENABLE_DIGICERT_GEMALTO__
            status = SMP_GEMALTO_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_PKCS11:
        #ifdef  __ENABLE_DIGICERT_SMP_PKCS11__
            status = SMP_PKCS11_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_RENS5:
        #ifdef  __ENABLE_DIGICERT_RENS5__
            status = SMP_RENS5_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_TRUSTX:
        #ifdef  __ENABLE_DIGICERT_TRUSTX__
            status = SMP_TRUSTX_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_ARMM23:
        #ifdef  __ENABLE_DIGICERT_ARMM23__
            status = SMP_ARMM23_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_ARMM33:
        #ifdef  __ENABLE_DIGICERT_ARMM33__
            status = SMP_ARMM33_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_EPID:
        #ifdef  __ENABLE_DIGICERT_EPID__
            status = SMP_EPID_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_TEE:
        #ifdef  __ENABLE_DIGICERT_TEE__
            status = SMP_TEE_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_NANOROOT:
        #ifdef  __ENABLE_DIGICERT_SMP_NANOROOT__
            status = SMP_NanoROOT_register(provider, smpVersion, tapVersion, pConfigInfo, pCmdCodeList);
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        default:
            status = ERR_TAP_INVALID_TAP_PROVIDER;
            DB_PRINT("%s.%d Invalid TAP_PROVIDER %d, status %d = %s\n", __FUNCTION__,
                __LINE__, provider, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }
    if (ERR_TAP_UNSUPPORTED == status)
    {
        DB_PRINT("%s.%d Provider %d (%s) not available - did not register, status %d = %s\n", __FUNCTION__,
                __LINE__, provider, TAP_UTILS_getProviderName(provider),
                status, MERROR_lookUpErrorCode(status));
        status = OK;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_unregisterProvider(TAP_PROVIDER provider, TAP_CmdCodeList *pCmdCodeList)
{
    MSTATUS status = OK;
    MSTATUS freeStatus = OK;
    byteBoolean freeList = FALSE;

    if (NULL == pCmdCodeList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (provider)
    {
        case TAP_PROVIDER_SW:
            status = ERR_TAP_UNSUPPORTED;
            break;
        case TAP_PROVIDER_TPM:
        #ifdef  __ENABLE_DIGICERT_TPM__
            status = SMP_TPM12_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_TPM2:
        #ifdef  __ENABLE_DIGICERT_TPM2__
            status = SMP_TPM2_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_SGX:
        #ifdef  __ENABLE_DIGICERT_SGX__
            status = SMP_SGX_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_STSAFE:
        #ifdef  __ENABLE_DIGICERT_STSAFE__
            status = SMP_STSAFE_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_NXPA71:
        #ifdef  __ENABLE_DIGICERT_NXPA71__
            status = SMP_NXPA71_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_GEMSIM:
        #ifdef  __ENABLE_DIGICERT_GEMALTO__
            status = SMP_GEMALTO_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_PKCS11:
        #ifdef  __ENABLE_DIGICERT_SMP_PKCS11__
            status = SMP_PKCS11_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_RENS5:
        #ifdef  __ENABLE_DIGICERT_RENS5__
            status = SMP_RENS5_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_TRUSTX:
        #ifdef  __ENABLE_DIGICERT_TRUSTX__
            status = SMP_TRUSTX_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_ARMM23:
        #ifdef  __ENABLE_DIGICERT_ARMM23__
            status = SMP_ARMM23_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_ARMM33:
        #ifdef  __ENABLE_DIGICERT_ARMM33__
            status = SMP_ARMM33_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_EPID:
        #ifdef  __ENABLE_DIGICERT_EPID__
            status = SMP_EPID_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_TEE:
        #ifdef  __ENABLE_DIGICERT_TEE__
            status = SMP_TEE_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        case TAP_PROVIDER_NANOROOT:
        #ifdef  __ENABLE_DIGICERT_SMP_NANOROOT__
            status = SMP_NanoROOT_unregister();
            freeList = TRUE;
        #else
            status = ERR_TAP_UNSUPPORTED;
        #endif
            break;
        default:
            status = ERR_TAP_INVALID_TAP_PROVIDER;
            DB_PRINT("%s.%d Invalid TAP_PROVIDER %d, status %d = %s\n", __FUNCTION__,
                __LINE__, provider, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }
    if (ERR_TAP_UNSUPPORTED == status)
    {
        DB_PRINT("%s.%d Provider %d (%s) not available - did not unregister, status %d = %s\n", __FUNCTION__,
                __LINE__, provider, TAP_UTILS_getProviderName(provider),
                status, MERROR_lookUpErrorCode(status));
        status = OK;
    }
    if (status != OK)
    {
        DB_PRINT("%s.%d Failed to unregister provider %d (%s), status %d = %s\n", __FUNCTION__,
                __LINE__, provider, TAP_UTILS_getProviderName(provider),
                status, MERROR_lookUpErrorCode(status));
    }

    /* Now free the command code list for the provider */
    if (TRUE == freeList)
    {
        freeStatus =  DIGI_FREE((void **)&(pCmdCodeList->pCmdList));
        if (OK != freeStatus)
        {
            DB_PRINT("%s.%d Failed to free command list for provider %d (%s), status %d = %s\n", __FUNCTION__,
                __LINE__, provider, TAP_UTILS_getProviderName(provider),
                freeStatus, MERROR_lookUpErrorCode(freeStatus));
            /* It's more important that we return the result of the SMP call, so only override the return status
               on a FREE error if the SMP returned OK */
            if (OK == status)
                status = freeStatus;
        }
        pCmdCodeList->listLen = 0;
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_copyProviderList(TAP_ProviderList *pLocalList, TAP_ProviderList *pNewList)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 i = 0;

    if ((NULL == pLocalList) || (NULL == pNewList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pNewList->listLen = 0;
    pNewList->pProviderCmdList = NULL;

    if (1 > pLocalList->listLen)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pNewList->pProviderCmdList), pLocalList->listLen, sizeof(TAP_ProviderCmdList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for provider list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < pLocalList->listLen; i++)
    {
        /* Copy the command list */
        if (0 < pLocalList->pProviderCmdList[i].cmdList.listLen)
        {
            status = DIGI_CALLOC((void **)&(pNewList->pProviderCmdList[i].cmdList.pCmdList),
                                 pLocalList->pProviderCmdList[i].cmdList.listLen,
                                 sizeof(SMP_CC));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for command list, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
            status = DIGI_MEMCPY(pNewList->pProviderCmdList[i].cmdList.pCmdList,
                                pLocalList->pProviderCmdList[i].cmdList.pCmdList,
                                pLocalList->pProviderCmdList[i].cmdList.listLen * sizeof(SMP_CC));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy memory for command list, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        pNewList->pProviderCmdList[i].cmdList.listLen = pLocalList->pProviderCmdList[i].cmdList.listLen;
        pNewList->pProviderCmdList[i].provider = pLocalList->pProviderCmdList[i].provider;
    }
    pNewList->listLen = pLocalList->listLen;

exit:

    if (OK != status)
    {
        /* Free list */
        exitStatus = TAP_UTILS_freeProviderList(pNewList);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory for provider list on error, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_registerLocalProviders(TAP_ConfigInfoList *pConfigInfoList, TAP_ProviderList *pProviderList)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 i = 0;

    if ((NULL == pConfigInfoList) || (NULL == pProviderList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (1 > pConfigInfoList->count)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Empty configInfoList provided, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pConfigInfoList->pConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pProviderList->pProviderCmdList), 1,
                        pConfigInfoList->count * sizeof(TAP_ProviderCmdList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pProviderList->listLen = pConfigInfoList->count;

    for (i = 0; i < pConfigInfoList->count; i++)
    {
        status = TAP_COMMON_registerProvider(pConfigInfoList->pConfig[i].provider, &(pConfigInfoList->pConfig[i]),
                                             &(pProviderList->pProviderCmdList[i].cmdList));
        if (OK != status)
        {
                DB_PRINT("%s.%d Failed to register provider %d (%s), status %d = %s\n", __FUNCTION__,
                        __LINE__, pConfigInfoList->pConfig[i].provider,
                TAP_UTILS_getProviderName(pConfigInfoList->pConfig[i].provider),
                        status, MERROR_lookUpErrorCode(status));
                /* TODO: What do we want to do if a valid register call fails during TAP_init?
                   Should we still try the other SMPs?  Or should we exit? */
        }
        pProviderList->pProviderCmdList[i].provider = pConfigInfoList->pConfig[i].provider;
    }

exit:

    /* On error, free the provider list */
    if ((OK != status) && (NULL != pProviderList) && 
            (NULL != pProviderList->pProviderCmdList))
    {
        for (i = 0; i < pProviderList->listLen; i++)
        {
            if (NULL != pProviderList->pProviderCmdList[i].cmdList.pCmdList)
            {
                exitStatus = DIGI_FREE((void **)&(pProviderList->pProviderCmdList[i].cmdList.pCmdList));
                if (OK != exitStatus)
                {
                    DB_PRINT("%s.%d Failed to free memory for provider list, status %d = %s\n", __FUNCTION__,
                            __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
                }
                pProviderList->pProviderCmdList[i].cmdList.pCmdList = NULL;
                pProviderList->pProviderCmdList[i].cmdList.listLen = 0;
            }
        }
        pProviderList->listLen = 0;

        exitStatus = DIGI_FREE((void **)&(pProviderList->pProviderCmdList));
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory for provider list, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_COMMON_unregisterLocalProviders(TAP_ProviderList *pProviderList)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pProviderList)
    {
        goto exit;
    }

    for (i = 0 ; i < pProviderList->listLen; i++)
    {
         if (NULL != pProviderList->pProviderCmdList[i].cmdList.pCmdList)
         {
              status = TAP_COMMON_unregisterProvider(pProviderList->pProviderCmdList[i].provider, &(pProviderList->pProviderCmdList[i].cmdList));

              if ((OK != status) && (ERR_TAP_UNSUPPORTED != status))
              {
                  /* TODO: What do we want to do if a valid unregister call fails during TAP_uninit?
                          For now, we are just logging the error.
                  */
                 DB_PRINT("%s.%d Failed to unregister provider %d (%s), status %d = %s\n", __FUNCTION__,
                          __LINE__, pProviderList->pProviderCmdList[i].provider,
                TAP_UTILS_getProviderName(pProviderList->pProviderCmdList[i].provider),
                          status, MERROR_lookUpErrorCode(status));
              }
         }
    }

    status = TAP_UTILS_freeProviderList(pProviderList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free provider list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}


#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
MSTATUS TAP_NanoROOT_parse_algorithm_info(ubyte8 value,
				TAP_KEY_ALGORITHM *keyAlgorithm,
				TAP_KEY_SIZE *keySize,
				ubyte4 *subKeyType
			    )
{
    ubyte4 algo = NanoROOT_GET_ALGO_ID(value);
    ubyte4 subtype = NanoROOT_GET_SUBTYPE(value);

    if( 0 == value || NULL == keyAlgorithm || NULL == keySize || NULL == subKeyType)
    {
        DB_PRINT("%s.%d Error invalid input. status=%d\n",
                  __FUNCTION__,__LINE__, ERR_INVALID_INPUT);
        return ERR_INVALID_INPUT;
    }

    DB_PRINT("Raw 64-bit Value: 0x%016llX\n", (unsigned long long)value);

    switch (algo) {
        case NanoROOT_ALGO_RSA:
            DB_PRINT("Algorithm       : RSA\n");
            *keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            switch (subtype) {
                case NanoROOT_RSA_2048:
                    DB_PRINT("Key Size        : 2048 bits\n");
                    *keySize = TAP_KEY_SIZE_2048;
                    *subKeyType = 2048;
                    break;

                case NanoROOT_RSA_3072:
                    DB_PRINT("Key Size        : 3072 bits\n");
                    *keySize = TAP_KEY_SIZE_3072;
                    *subKeyType = 3072;
                    break;

                case NanoROOT_RSA_4096:
                    DB_PRINT("Key Size        : 4096 bits\n");
                    *keySize = TAP_KEY_SIZE_4096;
                    *subKeyType = 4096;
                    break;

                case NanoROOT_RSA_8192:
                    DB_PRINT("Key Size        : 8192 bits\n");
                    *keySize = TAP_KEY_SIZE_8192;
                    *subKeyType = 8192;
                    break;

                default:
                    DB_PRINT("Key Size        : Unknown (0x%08X)\n", subtype);
                    return ERR_TAP_INVALID_ALGORITHM;
            }
            break;

#ifdef __ENABLE_DIGICERT_PQC__
        case NanoROOT_ALGO_MLDSA:
            DB_PRINT("Algorithm       : MLDSA\n");
            *keyAlgorithm = TAP_KEY_ALGORITHM_MLDSA;
            switch (subtype) {
                case NanoROOT_MLDSA_44:
                    DB_PRINT("Subtype         : 44\n");
                    *subKeyType = cid_PQC_MLDSA_44;
                    break;

                case NanoROOT_MLDSA_65:
                    DB_PRINT("Subtype         : 65\n");
                    *subKeyType = cid_PQC_MLDSA_65;
                    break;

                case NanoROOT_MLDSA_87:
                    DB_PRINT("Subtype         : 87\n");
                    *subKeyType = cid_PQC_MLDSA_87;
                    break;

                default:
                    DB_PRINT("Subtype         : Unknown (0x%08X)\n", subtype);
                    return ERR_TAP_INVALID_ALGORITHM;
            }
            break;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
        case NanoROOT_ALGO_ECC:
            DB_PRINT("Algorithm       : ECC\n");
            *keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            switch (subtype) {
                case NanoROOT_ECC_P256:
                    DB_PRINT("Curve         : P256\n");
                    *subKeyType = cid_EC_P256;
                    break;

                case NanoROOT_ECC_P384:
                    DB_PRINT("Curve         : P384\n");
                    *subKeyType = cid_EC_P384;
                    break;

                case NanoROOT_ECC_P521:
                    DB_PRINT("Curve         : P521\n");
                    *subKeyType = cid_EC_P521;
                    break;

                default:
                    DB_PRINT("Curve         : Unknown (0x%08X)\n", subtype);
                    return ERR_TAP_INVALID_ALGORITHM;
            }
            break;
#endif

        default:
            DB_PRINT("Algorithm       : Unknown (0x%08X)\n", algo);
            DB_PRINT("Subtype         : 0x%08X\n", subtype);
            return ERR_TAP_INVALID_ALGORITHM;
    }

    return OK;
}
#endif



/*------------------------------------------------------------------*/

#endif  /*  __ENABLE_DIGICERT_TAP__ */

