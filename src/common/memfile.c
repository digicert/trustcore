/*
 * memfile.c
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

#include "../common/moptions.h"

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/absstream.h"
#include "../common/memfile.h"

#if (!defined(__DISABLE_DIGICERT_COMMON_MEM_FS_ABS_LAYER__))

/*------------------------------------------------------------------*/

static sbyte4
MF_eof(AbsStream as)
{
    MemFile* pMF = (MemFile*) as;
    if (NULL == pMF)
    {
        return ERR_NULL_POINTER;
    }

    return ((pMF->pos >= pMF->size) || (0 > pMF->pos)) ? TRUE : FALSE;
}


/*------------------------------------------------------------------*/

extern MemFile* MF_create( sbyte4 size)
{
    MemFile* pMF = (MemFile*) MALLOC( sizeof(MemFile) + size);
    if ( pMF)
    {
        pMF->buff = (ubyte*) (pMF+1);
        pMF->pos = 0;
        pMF->size = size;
    }
    return pMF;
}


/*------------------------------------------------------------------*/

extern void
MF_delete( MemFile* pMF)
{
    if (NULL != pMF)
    {
        FREE(pMF);
    }
}


/*------------------------------------------------------------------*/

extern sbyte4
MF_attach( MemFile* pMF, sbyte4 size, ubyte* buff)
{
    if (NULL == pMF)
    {
        return ERR_NULL_POINTER;
    }

    pMF->buff = buff;
    pMF->size = size;
    pMF->pos = 0;

    return 0;
}


/*------------------------------------------------------------------*/

static MSTATUS
MF_getc(AbsStream as, ubyte *pRetChar)
{
    MSTATUS status = ERR_EOF;
    MemFile* pMF = (MemFile*) as;

    if ((NULL == pMF) || (NULL == pMF->buff))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 <= pMF->pos) && (pMF->pos < pMF->size))
    {
        *pRetChar = pMF->buff[pMF->pos++];
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
MF_ungetc(sbyte4 c, AbsStream as)
{
    MemFile* pMF = (MemFile*) as;

    if ((NULL == pMF) || (NULL == pMF->buff))
    {
        return ERR_NULL_POINTER;
    }

    if ( pMF->pos > 0)
    {
        pMF->buff[ --pMF->pos] = (ubyte) c;
        return c;
    }

    return ERR_EOF;
}


/*------------------------------------------------------------------*/

static sbyte4
MF_tell(AbsStream as)
{
    MemFile* pMF = (MemFile*) as;

    if (NULL == pMF)
    {
        return ERR_NULL_POINTER;
    }
    return pMF->pos;
}


/*------------------------------------------------------------------*/

static MSTATUS
MF_seek(AbsStream as, sbyte4 offset, sbyte4 origin)
{
    MSTATUS  status = OK;
    MemFile* pMF = (MemFile*) as;

    if (NULL == pMF)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (origin)
    {
        case MOCANA_SEEK_SET:
            pMF->pos = offset;
            break;
        case MOCANA_SEEK_END:
            pMF->pos = pMF->size - offset;
            break;
        case MOCANA_SEEK_CUR:
            pMF->pos += offset;
            break;
    }


exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4 MF_read(void* buffer, sbyte4 size, sbyte4 count, AbsStream as)
{
    MemFile* pMF = (MemFile*) as;
    sbyte4 numRead = 0;
    ubyte* dest = (ubyte*) buffer;

    if ((NULL == pMF) || (NULL == pMF->buff) || (NULL == dest))
    {
        return ERR_NULL_POINTER;
    }

    if (0 > pMF->pos)
    {
        return ERR_EOF;
    }

    if (0 < size)
    {
        numRead = (pMF->size - pMF->pos) / size;
        if (numRead > count)
        {
            numRead = count;
        }

        DIGI_MEMCPY( dest, pMF->buff + pMF->pos, numRead*size);
        pMF->pos += numRead*size;
    }

    return numRead;
}


/*------------------------------------------------------------------*/

static const void* MF_memaccess(AbsStream as, sbyte4 offset, sbyte4 size)
{
    MemFile* pMF = (MemFile*) as;

    if ((NULL == pMF) || (NULL == pMF->buff))
    {
        /* the caller always checks for NULL */
        return NULL;
    }
    /* check for buffer overruns! */
    if ( offset + size > pMF->size)
    {
        return NULL;
    }

    return pMF->buff + offset;
}


/*------------------------------------------------------------------*/

static sbyte4 MF_stopaccess(AbsStream as, const void* memaccess)
{
    MOC_UNUSED(as);
    MOC_UNUSED(memaccess);

    return OK;
}


/*------------------------------------------------------------------*/

const AbsStreamFuncs gMemFileAbsStreamFuncs =
{
    MF_getc,
    MF_ungetc,
    MF_tell,
    MF_seek,
    MF_eof,
    MF_read,
    MF_memaccess,
    MF_stopaccess
};

#endif /* (!defined(__DISABLE_DIGICERT_COMMON_MEM_FS_ABS_LAYER__)) */
