/*
 * sizedbuffer.h
 *
 * Simple utility to keep track of allocated memory and its size.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
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
