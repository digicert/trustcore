/*
 * sizedbuffer.h
 *
 * Simple utility to keep track of allocated memory and its size.
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


/*------------------------------------------------------------------*/

#ifndef __SIZEDBUFFER_H__
#define __SIZEDBUFFER_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SizedBuffer
{
    ubyte4    length;
    ubyte*    pHeader;
    ubyte*    data;

} SizedBuffer;


/*------------------------------------------------------------------*/


MOC_EXTERN MSTATUS  SB_Allocate(SizedBuffer* pSB, ubyte4 len);
MOC_EXTERN void     SB_Release (SizedBuffer* pSB);

#ifdef __cplusplus
}
#endif

#endif
