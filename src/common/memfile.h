/*
 * memfile.h
 *
 * Mocana Memory File System Abstraction Layer
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

