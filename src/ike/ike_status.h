/**
 * @file  ike_status.h
 * @brief IKE status definitions.
 *
 * @details    IKE status codes and error definitions.
 * @since      3.0
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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


#ifndef __IKE_STATUS_HEADER__
#define __IKE_STATUS_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/* Category */

typedef enum
{
    ISC_CFG,            /* [v1] XAUTH, Mode-Cfg */
    ISC_CHILDSA,
    ISC_MOB,            /* [v2] MOBIKE */
    ISC_SA,

} IKE_STATUS_CATEGORY;


/*------------------------------------------------------------------*/
/* Type */

typedef enum
{
    IST_FAIL,
    IST_SUCCESS,

    /* SA */
    IST_DELETED,
    IST_DPD,
    IST_INITIAL_CONTACT,
    IST_REAUTH,         /* [v2] rfc4478 */
    IST_CACPIN,

} IKE_STATUS_TYPE;


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_STATUS_HEADER__ */

