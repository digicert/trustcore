/*
 * absstream.c
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

#include "../common/moptions.h"

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/absstream.h"
#include "../common/memfile.h"


/*------------------------------------------------------------------*/

#if defined( __ENABLE_MOCANA_ANSI_FILESYS_STREAM__) || defined( __ENABLE_ALL_TESTS__)

#include <stdio.h>


/*------------------------------------------------------------------*/

static MSTATUS
stdc_getc(AbsStream as, ubyte *pRetVal)
{
    int     ch = getc((FILE*)as);
    MSTATUS status = OK;

    if (NULL == pRetVal)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetVal = 0;

    if (EOF == ch)
    {
        status = ERR_EOF;
        goto exit;
    }

    *pRetVal = (ubyte) ch;
exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4 stdc_ungetc(sbyte4 c, AbsStream as)
{
    return ungetc((int) c, (FILE*) as);
}


/*------------------------------------------------------------------*/

static sbyte4 stdc_tell(AbsStream as)
{
    return ftell( (FILE*) as);
}


/*------------------------------------------------------------------*/

static MSTATUS stdc_seek(AbsStream as, sbyte4 offset, sbyte4 origin)
{
    switch (origin)
    {
        case MOCANA_SEEK_SET:
            origin = SEEK_SET;
            break;
        case MOCANA_SEEK_CUR:
            origin = SEEK_CUR;
            break;
        case MOCANA_SEEK_END:
            origin = SEEK_END;
            break;
        default:
            break;
    }

    return (0 == fseek((FILE*) as, offset, (int) origin)) ? OK : ERR_FILE_SEEK_FAILED;
}


/*------------------------------------------------------------------*/

static sbyte4 stdc_eof(AbsStream as)
{
    return feof( (FILE*) as);
}


/*------------------------------------------------------------------*/

static sbyte4 stdc_read(void* buffer, sbyte4 size, sbyte4 count, AbsStream as)
{
    return (sbyte4) fread(buffer, (int) size, (int) count, (FILE*) as);
}


/*------------------------------------------------------------------*/

static const void* stdc_memaccess(AbsStream as, sbyte4 offset, sbyte4 size)
{
    FILE* f = (FILE*) as;
    void* ret = MALLOC(size);
    ubyte4 numBytes = 0;

    if ( ret)
    {
        fseek( f, offset, SEEK_SET);
        numBytes = (ubyte4) fread( ret, (int) size, 1, f);
        (void) numBytes; /* not used */
    }
    return ret;
}


/*------------------------------------------------------------------*/

static sbyte4 stdc_stopaccess(AbsStream as, const void* memaccess)
{
    MOC_UNUSED(as);

    if ( 0 == memaccess)
    {
        return ERR_NULL_POINTER;
    }

    FREE( (void*) memaccess);
    return (sbyte4) OK;
}


/*-----------------------------------------------------------------*/

extern void
CS_AttachStdCFile( CStream* cs, void* f)
{
    cs->pStream = (FILE*) f;
    cs->pFuncs = &gStdCFileAbsStreamFuncs;
}


/*------------------------------------------------------------------*/

const AbsStreamFuncs gStdCFileAbsStreamFuncs =
{
    stdc_getc,
    stdc_ungetc,
    stdc_tell,
    stdc_seek,
    stdc_eof,
    stdc_read,
    stdc_memaccess,
    stdc_stopaccess
};

#endif /* __ENABLE_MOCANA_ANSI_FILESYS_STREAM__ */


/*-----------------------------------------------------------------*/

extern void
CS_AttachMemFile( CStream* cs, void* mf)
{
    cs->pStream = mf;
    cs->pFuncs = &gMemFileAbsStreamFuncs;
}


/*-----------------------------------------------------------------*/

/* wrapper functions */
extern MSTATUS
CS_getc(CStream s, ubyte *pRetChar)
{
    return s.pFuncs->m_getc(s.pStream, pRetChar);
}


/*-----------------------------------------------------------------*/

extern sbyte4
CS_ungetc( sbyte4 c, CStream s)
{
    return s.pFuncs->m_ungetc( c, s.pStream);
}


/*-----------------------------------------------------------------*/

extern sbyte4
CS_tell( CStream s)
{
    return s.pFuncs->m_tell( s.pStream);
}


/*-----------------------------------------------------------------*/

extern MSTATUS
CS_seek( CStream s, sbyte4 offset, sbyte4 origin)
{
    return s.pFuncs->m_seek( s.pStream, offset, origin);
}


/*-----------------------------------------------------------------*/

extern sbyte4
CS_eof( CStream s)
{
    return s.pFuncs->m_eof( s.pStream);
}


/*-----------------------------------------------------------------*/

extern sbyte4
CS_read( void* buffer, sbyte4 size, sbyte4 count, CStream s)
{
    return s.pFuncs->m_read( buffer, size, count, s.pStream);
}


/*-----------------------------------------------------------------*/

extern const
void* CS_memaccess( CStream s, sbyte4 offset, sbyte4 size)
{
    return s.pFuncs->m_memaccess( s.pStream, offset, size);
}


/*-----------------------------------------------------------------*/

extern sbyte4
CS_stopaccess( CStream s, const void* memaccess)
{
    return s.pFuncs->m_stopaccess( s.pStream, memaccess);
}
