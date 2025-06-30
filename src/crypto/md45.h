/*
 * md45.h
 *
 * Routines and constants common to md4 and md5
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
