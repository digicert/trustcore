/*
 * tbs_utils.h
 *
 * Functions needed from TBS by TPM 2.0
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#ifdef __RTOS_WIN32__

#ifndef __TPM2_TBS_UTILS_H
#define __TPM2_TBS_UTILS_H

#if defined(__ENABLE_DIGICERT_TPM2__)

typedef void* TPM2_TBS_CONTEXT;

typedef enum
{

    /* Full Owner authorization */
    TPM2_TBS_OWNERAUTH_TYPE_FULL,

    /* Endorsement Owner authorization */
    TPM2_TBS_OWNERAUTH_TYPE_ENDORSEMENT,

    /* Administrator Owner authorization */
    TPM2_TBS_OWNERAUTH_TYPE_OWNER_ADMIN

} TPM2_TBS_OWNERAUTH_TYPE;


/**
 * @brief Function to create TBS Context
 * @note  Function to create TBS Context
 */
MSTATUS TBS_UTIL_ContextCreate(TPM2_TBS_CONTEXT * pTbsContext);


/**
 * @brief Function to close TBS Context
 * @note  Function to close TBS Context
 */
MSTATUS TBS_UTIL_ContextClose(TPM2_TBS_CONTEXT * pTbsContext);


/**
 * @brief Function to retrieve owner-auth from TBS
 * @note  Function to retrieve owner-auth from TBS
 */
MOC_EXTERN MSTATUS TPM2_TBS_UTIL_GetOwnerAuth(TPM2_TBS_OWNERAUTH_TYPE ownerAuthType,
                              ubyte **ppOwnerAuth, ubyte4 *pOwnerAuthLen);


#endif /* __ENABLE_DIGICERT_TPM2__ */

#endif /* __TPM2_TBS_UTILS_H */
#endif /* __RTOS_WIN32__ */

