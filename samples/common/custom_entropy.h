/*
 * custom_entropy.h
 *
 * APIs for custom entropy injection.
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

#ifndef __CUSTOM_ENTROPY_HEADER__
#define __CUSTOM_ENTROPY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MOC_CUSTOM_ENTROPY_LEN
#define MOC_CUSTOM_ENTROPY_LEN 48
#endif

MOC_EXTERN MSTATUS DIGICERT_CUSTOM_getEntropy(
    ubyte *pBuffer,
    ubyte4 bufferLen
    );

#endif /* ifndef __CUSTOM_ENTROPY_HEADER__ */
