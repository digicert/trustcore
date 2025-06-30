/*
 * absstream.h
 *
 * Mocana ABS Stream Abstraction Layer
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

#ifndef __ABSSTREAM_H__
#define __ABSSTREAM_H__

#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MOCANA_SEEK_SET     1
#define MOCANA_SEEK_CUR     2
#define MOCANA_SEEK_END     3


/*------------------------------------------------------------------*/

typedef void* AbsStream;
typedef MSTATUS (*AS_getc)(AbsStream as, ubyte *pRetVal);
typedef sbyte4 (*AS_ungetc)(sbyte4 c, AbsStream as);
typedef sbyte4 (*AS_tell)(AbsStream as);
typedef MSTATUS (*AS_seek)(AbsStream as, sbyte4 offset, sbyte4 origin);
typedef sbyte4 (*AS_eof)(AbsStream as);
typedef sbyte4 (*AS_read)(void* buffer, sbyte4 size, sbyte4 count, AbsStream as);
typedef const void* (*AS_memaccess)(AbsStream as, sbyte4 offset, sbyte4 size);
typedef sbyte4 (*AS_stopaccess)(AbsStream as, const void* memaccess);

typedef struct AbsStreamFuncs
{
    AS_getc         m_getc;
    AS_ungetc       m_ungetc;
    AS_tell         m_tell;
    AS_seek         m_seek;
    AS_eof          m_eof;
    AS_read         m_read;
    AS_memaccess    m_memaccess;
    AS_stopaccess   m_stopaccess;
} AbsStreamFuncs;

typedef struct CStream
{
    AbsStream pStream;
    const AbsStreamFuncs* pFuncs;
} CStream;

MOC_EXTERN MSTATUS     CS_getc(CStream s, ubyte *pRetChar);
MOC_EXTERN sbyte4      CS_ungetc( sbyte4 c, CStream s);
MOC_EXTERN sbyte4      CS_tell( CStream s);
MOC_EXTERN MSTATUS     CS_seek( CStream s, sbyte4 offset, sbyte4 origin);
MOC_EXTERN sbyte4      CS_eof( CStream s);
MOC_EXTERN sbyte4      CS_read( void* buffer, sbyte4 size, sbyte4 count, CStream s);
MOC_EXTERN const void* CS_memaccess( CStream s, sbyte4 offset, sbyte4 size);
MOC_EXTERN sbyte4      CS_stopaccess( CStream s, const void* memaccess);

MOC_EXTERN void CS_AttachMemFile(CStream* cs, void* mf);
MOC_EXTERN void CS_AttachStdCFile(CStream* cs, void* f);

/*------------------------------------------------------------------*/

MOC_EXTERN const AbsStreamFuncs gStdCFileAbsStreamFuncs;

#ifdef __cplusplus
}
#endif    
    
#endif
