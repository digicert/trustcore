/*
 * mrtos_custom.h
 *
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
#ifndef __MRTOS_CUSTOM_HEADER__
#define __MRTOS_CUSTOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
/*------------------------------------------------------------------*/
/*                Add your own custom #defines here                 */
/*------------------------------------------------------------------*/

#if defined(__MYOS_RTOS__)
#define  __CUSTOM_RTOS__

/* Map RTOS_ macros from mrtos.h for the appropriate methods/structures.
 * For example:
 *   #define RTOS_rtosInit       MYOS_rtosInit
 *
 * where MYOS_rtosInit is an user defined method.
 */
#define RTOS_malloc                 MYOS_malloc
#define RTOS_free                   MYOS_free

#endif

/*------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
#endif
