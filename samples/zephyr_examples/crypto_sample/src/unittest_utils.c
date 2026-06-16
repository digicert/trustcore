/*
 * unittest_utils.c
 *
 * functions useful for writing tests
 *
 * Copyright Mocana Corp 2009. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


#ifndef __RTOS_ZEPHYR__
#define __RTOS_LINUX__
#define __RTOS_ZEPHYR__
#endif

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/mocana.h"
#include "crypto/hw_accel.h"

#include "common/mdefs.h"
#include "common/merrors.h"
#include "common/mstdlib.h"
#include "common/mrtos.h"
#include "unittest_utils.h"


/*---------------------------------------------------------------------------*/

static ubyte UNITTEST_UTILS_ValOfHexChar( sbyte c)
{
    if ('0' <= c && c <= '9')
    {
        return (ubyte) (c - '0');
    }
    else if ( 'A' <= c && c <= 'F')
    {
        return (ubyte) ( c + 10 - 'A');
    }
    else if ( 'a' <= c && c <= 'f')
    {
        return (ubyte) ( c + 10 - 'a');
    }
    return 0; /* ??? */
}


/*---------------------------------------------------------------------------*/

ubyte4 UNITTEST_UTILS_str_to_byteStr( const sbyte* s, ubyte** bs)
{
    ubyte* buffer = 0;
    ubyte4 bsLen;
    ubyte4 sLen = DIGI_STRLEN( s);
    ubyte* pTemp;

    bsLen = (sLen+1)/2;
    buffer = MALLOC( bsLen + 1); /* to prevent a malloc 0 */
    if (!buffer)
    {
        *bs = 0;
        return 0;
    }

    pTemp = buffer;

    if ( sLen & 1)
    {
        *pTemp++ = UNITTEST_UTILS_ValOfHexChar(*s++);
    }
    while ( *s)
    {
        *pTemp = (ubyte) ((UNITTEST_UTILS_ValOfHexChar(*s++)) << 4);
        *pTemp++ |= (UNITTEST_UTILS_ValOfHexChar(*s++));
    }
    *bs = buffer;
    return bsLen;
}


/*-----------------------------------------------------------------*/

void
UNITTEST_UTILS_make_file_name( const sbyte* root, const TimeDate* td, sbyte buffer[])
{
    ubyte4 len;

    len = DIGI_STRLEN( root);
    DIGI_MEMCPY( buffer, root, len);
    buffer += len;
    *buffer++ = '_';

    DIGI_UTOA( td->m_year + 1970, (ubyte*) buffer, &len);
    buffer += len;
    *buffer++ = '_';

    DIGI_UTOA( td->m_month, (ubyte*) buffer, &len);
    buffer += len;
    *buffer++ = '_';

    DIGI_UTOA( td->m_day, (ubyte*) buffer, &len);
    buffer += len;
    *buffer++ = '_';

    DIGI_UTOA( td->m_hour, (ubyte*) buffer, &len);
    buffer += len;
    *buffer++ = '_';

    DIGI_UTOA( td->m_minute, (ubyte*) buffer, &len);
    buffer += len;
    *buffer++ = '_';

    DIGI_UTOA( td->m_second, (ubyte*) buffer, &len);
    buffer += len;
    *buffer++ = 0;
}
