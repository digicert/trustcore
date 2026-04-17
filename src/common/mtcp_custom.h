/*
 * mtcp_custom.h
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
 */
#ifndef __MTCP_CUSTOM_HEADER__
#define __MTCP_CUSTOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/
/*                Add your own custom #defines here                 */
/*------------------------------------------------------------------*/

#if defined(__MYOS_TCP__)
#define __CUSTOM_TCP__

/* Map TCP_ macros from mtcp.h for the appropriate methods/structures.
 * For example:
 *   #define TCP_INIT       MYOS_TCP_init
 *
 * where MYOS_TCP_init is an user defined method.
 */


#endif

/*------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
#endif
