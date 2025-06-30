/*
 * memfile.h
 *
 * Mocana Memory File System Abstraction Layer
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

#ifndef __MEMFILE_H__
#define __MEMFILE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MemFile
{
    ubyte*      buff; /* data */
    sbyte4      size; /* size of m_buff */
    sbyte4      pos;  /* pos in file */

} MemFile;


/*------------------------------------------------------------------*/

MOC_EXTERN const AbsStreamFuncs gMemFileAbsStreamFuncs;

MOC_EXTERN sbyte4 MF_attach( MemFile* pMF, sbyte4 size, ubyte* buff);


#ifdef __cplusplus
}
#endif


#endif

