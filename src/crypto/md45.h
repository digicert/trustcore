/*
 * md45.h
 *
 * Routines and constants common to md4 and md5
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


#ifndef __MD45_H__
#define __MD45_H__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN void MD45_encode(ubyte *, const ubyte4 *, ubyte4);
MOC_EXTERN void MD45_decode(ubyte4 *, const ubyte *, ubyte4);

MOC_EXTERN const ubyte MD45_PADDING[64];

#ifdef __cplusplus
}
#endif

#endif
