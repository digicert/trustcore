/*
 * uri.c
 *
 * Mocana URI implementation
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

#ifdef __ENABLE_MOCANA_URI__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/uri.h"


/*------------------------------------------------------------------*/
static void URI_initMask();

static void
URI_GetEffectiveRange(ubyte order, ubyte low, ubyte high,
                      ubyte* effectiveLow, ubyte* effectiveHigh);

/* it's a range; [low, high> */
static ubyte4
URI_GetBitmaskRange(ubyte order, ubyte low, ubyte high);

/* get the bitmask given the character string */
static ubyte4
URI_GetBitmask(ubyte order, ubyte* chars, ubyte4 len);

static void
URI_GetToEscapeMask(componentType type, ubyte4 *toEscape);

/* returns true is ch matches one of the set mask in the bitmasks */
static byteBoolean
URI_match(ubyte ch, ubyte4* bitmasks);

/* get the unescaped component based on type */
static MSTATUS
URI_GetComponent(componentType type, URI* uri, sbyte** component);

static MSTATUS
URI_GetUnescapedLength(ubyte* component, ubyte4 componentLen,
                     ubyte4* unescapedLen);

static MSTATUS
URI_ParseAuthority(URI* uri);
/*------------------------------------------------------------------*/
/* for efficient comparisons, use a 4 ubyte4, a total of 128 bits, to represent
the bitmask for ASCII characters */
static byteBoolean isMaskInitialized = FALSE;
static ubyte4 excluded[4];
static ubyte4 reserved_authority[4];
static ubyte4 reserved_path[4];
static ubyte4 reserved_query[4];
static ubyte hexDigits[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

static void URI_initMask()
{
    ubyte4 control[4];
    ubyte4 space[4];
    ubyte4 delims[4];
    ubyte4 unwise[4];

    /* excluded characters: need to be escaped always
        control     = <US-ASCII coded characters 00-1F and 7F hexadecimal>
        space       = <US-ASCII coded character 20 hexadecimal>
        delims      = "<" | ">" | "#" | "%" | <">
        unwise      = "{" | "}" | "|" | "\" | "^" | "[" | "]" | "`"
    */
    control[0]= URI_GetBitmaskRange(0, 00, 0x20) | URI_GetBitmaskRange(0, 0x7F, 0x80);
    control[1]= URI_GetBitmaskRange(1, 00,  0x20) | URI_GetBitmaskRange(1,  0x7F,  0x80);
    control[2]= URI_GetBitmaskRange(2, 00,  0x20) | URI_GetBitmaskRange(2,  0x7F,  0x80);
    control[3]= URI_GetBitmaskRange(3, 00,  0x20) | URI_GetBitmaskRange(3,  0x7F,  0x80);

    space[0] = URI_GetBitmaskRange(0, 20, 21);
    space[1] = 0;
    space[2] = 0;
    space[3] = 0;

    delims[0] = URI_GetBitmask(0, (ubyte *)"<>#%\"", 5);
    delims[1] = URI_GetBitmask(1, (ubyte *)"<>#%\"", 5);
    delims[2] = URI_GetBitmask(2, (ubyte *)"<>#%\"", 5);
    delims[3] = URI_GetBitmask(3, (ubyte *)"<>#%\"", 5);

    unwise[0] = URI_GetBitmask(0, (ubyte *)"{}|\\^[]`", 8);
    unwise[1] = URI_GetBitmask(1, (ubyte *)"{}|\\^[]`", 8);
    unwise[2] = URI_GetBitmask(2, (ubyte *)"{}|\\^[]`", 8);
    unwise[3] = URI_GetBitmask(3, (ubyte *)"{}|\\^[]`", 8);

    excluded[0] = control[0] | space[0] | delims[0] |unwise[0];
    excluded[1] = control[1] | space[1] | delims[1] |unwise[1];
    excluded[2] = control[2] | space[2] | delims[2] |unwise[2];
    excluded[3] = control[3] | space[3] | delims[3] |unwise[3];

    /* reserved characters: component specific */
    /*
    reserved_authority = ";" | ":" | "@" | "?" | "/"
    reserved_path = "/" | ";" | "=" | "?"
    reserved_query = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "," | "$"
    */
    reserved_authority[0] = URI_GetBitmask(0, (ubyte *)";:@?/", 5);
    reserved_authority[1] = URI_GetBitmask(1, (ubyte *)";:@?/", 5);
    reserved_authority[2] = URI_GetBitmask(2, (ubyte *)";:@?/", 5);
    reserved_authority[3] = URI_GetBitmask(3, (ubyte *)";:@?/", 5);

    reserved_path[0] = URI_GetBitmask(0, (ubyte *)"/;=?", 4);
    reserved_path[1] = URI_GetBitmask(1, (ubyte *)"/;=?", 4);
    reserved_path[2] = URI_GetBitmask(2, (ubyte *)"/;=?", 4);
    reserved_path[3] = URI_GetBitmask(3, (ubyte *)"/;=?", 4);

    reserved_query[0] = URI_GetBitmask(0, (ubyte *)";/?:@&=+,$", 10);
    reserved_query[1] = URI_GetBitmask(1, (ubyte *)";/?:@&=+,$", 10);
    reserved_query[2] = URI_GetBitmask(2, (ubyte *)";/?:@&=+,$", 10);
    reserved_query[3] = URI_GetBitmask(3, (ubyte *)";/?:@&=+,$", 10);

    isMaskInitialized = TRUE;
}

/*------------------------------------------------------------------*/
static void
URI_GetEffectiveRange(ubyte order, ubyte low, ubyte high, ubyte* effectiveLow, ubyte* effectiveHigh)
{
    ubyte lowMargin = order*32;
    ubyte highMargin = (order+1)*32;

    if (low > highMargin || high < lowMargin)
    {
        *effectiveLow = *effectiveHigh = 0;
        return;
    }
    if (low < lowMargin)
        low = lowMargin;
    if (high > highMargin)
        high = highMargin;

    *effectiveLow = low - lowMargin;
    *effectiveHigh = high - lowMargin;
}

/* it's a range; if one number, let low==high */
static ubyte4
URI_GetBitmaskRange(ubyte order, ubyte low, ubyte high)
{
    ubyte4 i;
    ubyte4 mask = 0;
    ubyte effectiveLow;
    ubyte effectiveHigh;
    URI_GetEffectiveRange(order, low, high, &effectiveLow, &effectiveHigh);
    for (i = effectiveLow; i < effectiveHigh; i++)
    {
        mask |= 1 << i;
    }
    return mask;
}

/* get the bitmask given the character string */
static ubyte4
URI_GetBitmask(ubyte order, ubyte* chars, ubyte4 len)
{
    ubyte4 i;
    ubyte4 mask = 0;
    for (i = 0; i < len; i++)
    {
        mask |= URI_GetBitmaskRange(order, *(chars+i), *(chars+i)+1);
    }
    return mask;
}

static byteBoolean
URI_match(ubyte ch, ubyte4* bitmasks)
{
    if (ch < 32)
    {
        return ((1 << ch) & bitmasks[0]) != 0;
    }
    if (ch < 64)
    {
        return ((1 << (ch-32)) & bitmasks[1]) != 0;
    }
    if (ch < 96)
    {
        return ((1 << (ch-64)) & bitmasks[2]) != 0;
    }
    if (ch < 128)
    {
        return ((1 << (ch-96)) & bitmasks[3]) != 0;
    }
    return FALSE;
}

/*------------------------------------------------------------------*/
static void
URI_GetToEscapeMask(componentType type, ubyte4 *toEscape)
{
    if (!isMaskInitialized)
        URI_initMask();
    switch (type)
    {
    case SCHEME:
    case FRAGMENT:
        toEscape[0] = excluded[0];
        toEscape[1] = excluded[1];
        toEscape[2] = excluded[2];
        toEscape[3] = excluded[3];
        break;
    case AUTHORITY:
        toEscape[0] = excluded[0] | reserved_authority[0];
        toEscape[1] = excluded[1] | reserved_authority[1];
        toEscape[2] = excluded[2] | reserved_authority[2];
        toEscape[3] = excluded[3] | reserved_authority[3];
        break;
    case PATH:
        toEscape[0] = excluded[0] | reserved_path[0];
        toEscape[1] = excluded[1] | reserved_path[1];
        toEscape[2] = excluded[2] | reserved_path[2];
        toEscape[3] = excluded[3] | reserved_path[3];
        break;
    case QUERY:
        toEscape[0] = excluded[0] | reserved_query[0];
        toEscape[1] = excluded[1] | reserved_query[1];
        toEscape[2] = excluded[2] | reserved_query[2];
        toEscape[3] = excluded[3] | reserved_query[3];
        break;
    case EXCLUDED: /* excluded chars minus %=dec(37) */
        toEscape[0] = excluded[0];
        toEscape[1] = excluded[1] & (~((1 << (37-32)) & 0xffffffff));
        toEscape[2] = excluded[2];
        toEscape[3] = excluded[3];
        break;
    default:
        /* shouldn't happen */
        break;
    }
}

/*------------------------------------------------------------------*/

static MSTATUS
URI_GetUnescapedLength(ubyte* component, ubyte4 componentLen,
                     ubyte4* unescapedLen)
{
    MSTATUS status = OK;
    ubyte4 matchedLen = 0;
    ubyte4 i;
    /* componentLen - (the number of %)*3 */

    for (i = 0; i < componentLen; i++)
    {
        ubyte ch = *(component+i);
        if (ch == '%')
        {
            matchedLen ++;
            if (i+2 >= componentLen ||
                !MOC_ISXDIGIT(*(component+i+1)) ||
                !MOC_ISXDIGIT(*(component+i+2)))
            {
                status = ERR_URI_INVALID_FORMAT;
                goto exit;
            }
        }

    }
    *unescapedLen = componentLen - matchedLen*2;
exit:
    return status;
}
/*------------------------------------------------------------------*/

extern MSTATUS
URI_Unescape(ubyte* component, ubyte4 componentLen,
             sbyte** unescaped)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte p[2];
    ubyte4 offset = 0;
    ubyte4 unescapedLen;

    if (!unescaped)
    {
        return ERR_NULL_POINTER;
    }
    *unescaped = NULL;

    if (OK > (status = URI_GetUnescapedLength(component, componentLen, &unescapedLen)))
        goto exit;
    *unescaped = (sbyte*)MALLOC(unescapedLen+1);
    if (!(*unescaped))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    *((*unescaped)+unescapedLen) = '\0';
    while ( i < componentLen)
    {
        ubyte ch = *(component+i);
        if (ch == '%') /* convert %HEXHEX to one char */
        {
            if (i+2 >= componentLen)
            {
                status = ERR_URI_INVALID_FORMAT;
                goto exit;
            }
            p[0] = *(component+i+1);
            p[0] = p[0] <= '9'? (p[0] - '0') : (p[0] - 'A' + 10);
            p[1] = *(component+i+2);
            p[1] = p[1] <= '9'? (p[1] - '0') : (p[1] - 'A' + 10);
            ch = ((p[0] << 4) & 0xf0) + (p[1] & 0x0f);
            i += 3;
        }
        else
        {
            i++;
        }
        *((*unescaped)+offset++) = ch;
    }
exit:
    if (OK > status)
    {
        if (*unescaped)
        {
            FREE(*unescaped);
            *unescaped = NULL;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
URI_GetEscapedLength(componentType type, sbyte* component, ubyte4 componentLen,
                     ubyte4* escapedLen)
{
    ubyte4 toEscape[4];
    ubyte4 totalLen = 0;
    ubyte4 i;
    /* the number of matches*3, 3 because one char becomes %HEXHEX */

    URI_GetToEscapeMask(type, toEscape);

    for (i = 0; i < componentLen; i++)
    {
        ubyte ch = *(component+i);
        if (URI_match(ch, toEscape))
        {
            totalLen += 3;
        } else
        {
            totalLen++;
        }
    }
    *escapedLen = totalLen;
    return 0;
}

/*------------------------------------------------------------------*/

extern MSTATUS
URI_Escape(componentType type, sbyte* component, ubyte4 componentLen,
           ubyte* escaped, ubyte4* escapedLen)
{
    MSTATUS status = 0;
    ubyte4 toEscape[4];
    ubyte4 i;
    ubyte4 offset = 0;

    URI_GetToEscapeMask(type, toEscape);

    for (i = 0; i < componentLen; i++)
    {
        ubyte ch = *(component+i);
        if (URI_match(ch, toEscape))
        {
            /* need to escape */
            *(escaped+offset++) = '%';
            *(escaped+offset++) = hexDigits[(ch >> 4) & 0x0f];
            *(escaped+offset++) = hexDigits[ch & 0x0f];
        } else
        {
            /* donot need to escape */
            *(escaped+offset++) = ch;
        }
    }
    *escapedLen = offset;
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
URI_CreateURI1(sbyte* scheme,
            sbyte* host,
            sbyte2 port,
            sbyte* path,
            URI** uri)
{
    return URI_CreateURI2(scheme, NULL, host, port, path, NULL, NULL, uri);
}
/*------------------------------------------------------------------*/

extern MSTATUS
URI_CreateURI2(sbyte* scheme,
            sbyte* userInfo,
            sbyte* host,
            sbyte2 port,
            sbyte* path,
            sbyte* query,
            sbyte* fragment,
            URI** uri)
{
    MSTATUS status;
    ubyte4 escapedLen = 0;
    sbyte* authority = NULL;
    ubyte4 authorityLen = 0;
    ubyte4 offset = 0;
    ubyte portStr[5];
    ubyte4 portLen;

    if (port > 0)
    {
        ubyte *ptr = (ubyte*)MOC_LTOA(port, (sbyte *)portStr, 5);
        portLen = (ubyte4)(ptr-portStr);
    }
    else
    {
        portLen = 0;
    }

    /* create authority first */
   if (OK > (status = URI_GetEscapedLength(AUTHORITY, userInfo, MOC_STRLEN(userInfo), &escapedLen)))
        goto exit;
   authorityLen += escapedLen + (MOC_STRLEN(userInfo) > 0? 1 : 0); /* @ */

   if (OK > (status = URI_GetEscapedLength(AUTHORITY, host, MOC_STRLEN(host), &escapedLen)))
        goto exit;
   authorityLen += escapedLen + (portLen> 0? 1 : 0); /* : */
   authorityLen += portLen;
   if (NULL == (authority = (sbyte*)MALLOC(authorityLen+1)))
   {
        status = ERR_NULL_POINTER;
        goto exit;
   }

   if (OK > (status = URI_Escape(AUTHORITY, userInfo, MOC_STRLEN(userInfo), (ubyte*)(authority+offset), &escapedLen)))
       goto exit;
    offset += escapedLen;
    if (MOC_STRLEN(userInfo) > 0)
    {
        if (OK > (status = MOC_MEMCPY(authority+offset, "@", 1)))
            goto exit;
        offset += 1; /* @ */
    }
   if (OK > (status = URI_Escape(AUTHORITY, host, MOC_STRLEN(host), (ubyte*)(authority+offset), &escapedLen)))
       goto exit;
    offset += escapedLen;
    if (portLen > 0)
    {
        if (OK > (status = MOC_MEMCPY(authority+offset, ":", 1)))
            goto exit;
        offset += 1; /* @ */
        if (OK > (status = MOC_MEMCPY(authority+offset, portStr, portLen)))
            goto exit;
    }
    *(authority+offset+portLen) = '\0';
    status = URI_CreateURI4(scheme, authority, path, query, fragment, uri);

exit:
    if (authority)
    {
        FREE(authority);
    }
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
URI_CreateURI3(sbyte* scheme,
            sbyte* authority,
            sbyte* path,
            URI** uri)
{
    return URI_CreateURI4(scheme,authority, path, NULL, NULL, uri);
}
/*------------------------------------------------------------------*/

/* will escape each component */
extern MSTATUS
URI_CreateURI4(sbyte* scheme,
          sbyte* authority,
          sbyte* path,
          sbyte* query,
          sbyte* fragment,
          URI** uri)
{
    MSTATUS status;
    ubyte4 totalEscapedLen = 0;
    ubyte4 escapedLen;
    ubyte* escapedBuffer = NULL;

    if (!uri)
    {
        return ERR_NULL_POINTER;
    }

    /* calculate the total buffer size */
    totalEscapedLen += MOC_STRLEN(scheme) + 3; /* :// */
    /* use EXCLUDED because authority is non-atomic component */
    if (OK > (status = URI_GetEscapedLength(EXCLUDED, authority, MOC_STRLEN(authority), &escapedLen)))
        goto exit;
    totalEscapedLen += escapedLen; /* / */
    /* use EXCLUDED because path is non-atomic component */
    if (OK > (status = URI_GetEscapedLength(EXCLUDED, path, MOC_STRLEN(path), &escapedLen)))
        goto exit;
    totalEscapedLen += escapedLen + (MOC_STRLEN(query) > 0? 1 : 0); /* ? */
    if (OK > (status = URI_GetEscapedLength(QUERY, query, MOC_STRLEN(query), &escapedLen)))
        goto exit;
    totalEscapedLen += escapedLen + (MOC_STRLEN(fragment) > 0? 1 : 0); /* # */
    if (OK > (status = URI_GetEscapedLength(FRAGMENT, fragment, MOC_STRLEN(fragment), &escapedLen)))
        goto exit;
    totalEscapedLen += escapedLen;

    escapedBuffer = (ubyte*) MALLOC(totalEscapedLen);
    if (!escapedBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL ==(*uri = (URI*) MALLOC(sizeof(URI))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    (*uri)->uriBuf = escapedBuffer;
    (*uri)->uriLen = totalEscapedLen;

    escapedBuffer = NULL;
    totalEscapedLen = 0;

    /* escape each components until done */
    (*uri)->componentPtr[SCHEME] = (*uri)->uriBuf;
    if (OK > (status = URI_Escape(SCHEME, scheme, MOC_STRLEN(scheme), (*uri)->componentPtr[SCHEME], &((*uri)->componentLen[SCHEME]))))
        goto exit;
    *((*uri)->componentPtr[SCHEME]+(*uri)->componentLen[SCHEME]) = ':';
    (*uri)->componentPtr[AUTHORITY] = (*uri)->componentPtr[SCHEME]+(*uri)->componentLen[SCHEME]+1;

    if (MOC_STRLEN(authority) > 0)
    {
        *((*uri)->componentPtr[AUTHORITY]) = '/';
        *((*uri)->componentPtr[AUTHORITY]+1) = '/';
        (*uri)->componentPtr[AUTHORITY] = (*uri)->componentPtr[AUTHORITY]+2;

    }
    if (OK > (status = URI_Escape(EXCLUDED, authority, MOC_STRLEN(authority), (*uri)->componentPtr[AUTHORITY], &((*uri)->componentLen[AUTHORITY]))))
        goto exit;
    (*uri)->componentPtr[PATH] = (*uri)->componentPtr[AUTHORITY] + (*uri)->componentLen[AUTHORITY];
    if (OK > (status = URI_Escape(EXCLUDED, path, MOC_STRLEN(path), (*uri)->componentPtr[PATH], &((*uri)->componentLen[PATH]))))
        goto exit;
    if (MOC_STRLEN(query) > 0)
    {
        *((*uri)->componentPtr[PATH]+(*uri)->componentLen[PATH]) =  '?';
    }
    (*uri)->componentPtr[QUERY] = (*uri)->componentPtr[PATH] + (*uri)->componentLen[PATH] + (MOC_STRLEN(query) > 0? 1: 0);
    if (OK > (status = URI_Escape(QUERY, query, MOC_STRLEN(query), (*uri)->componentPtr[QUERY], &((*uri)->componentLen[QUERY]))))
        goto exit;
    if (MOC_STRLEN(fragment) > 0)
    {
        *((*uri)->componentPtr[QUERY]+(*uri)->componentLen[QUERY]) = '#';
    }
    (*uri)->componentPtr[FRAGMENT] = (*uri)->componentPtr[QUERY] + (*uri)->componentLen[QUERY] + (MOC_STRLEN(fragment) > 0? 1 : 0);
    if (OK > (status = URI_Escape(FRAGMENT, fragment, MOC_STRLEN(fragment), (*uri)->componentPtr[FRAGMENT], &((*uri)->componentLen[FRAGMENT]))))
        goto exit;

exit:
    if (escapedBuffer)
    {
        FREE(escapedBuffer);
    }

    if (OK > status)
    {
        if (uri && *uri)
        {
            URI_DELETE(*uri);
            *uri = NULL;
        }
    }

    return status;
}

MOC_EXTERN MSTATUS
URI_ParseURI(sbyte* uriStr, URI** uri)
{
    MSTATUS status;
    ubyte4 len;
    ubyte ch;
    componentType type;
    ubyte4 offset = 0;
    ubyte ch1;
    ubyte ch2;
    ubyte4 uriLen;

    if ((NULL == uriStr) || (NULL == uri))
        return ERR_NULL_POINTER;

    uriLen = MOC_STRLEN(uriStr) + 1;

    /* initialize result */
    *uri = (URI*)MALLOC(sizeof(URI));
    if (!(*uri))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    (*uri)->uriBuf = (ubyte*) MALLOC(uriLen);
    if (!(*uri)->uriBuf)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = MOC_MEMCPY((*uri)->uriBuf, uriStr, uriLen)))
        goto exit;
    (*uri)->uriLen = uriLen;
    (*uri)->componentLen[SCHEME] = 0;
    (*uri)->componentLen[AUTHORITY] = 0;
    (*uri)->componentLen[FULLPATH] = 0;
    (*uri)->componentLen[PATH] = 0;
    (*uri)->componentLen[QUERY] = 0;
    (*uri)->componentLen[FRAGMENT] = 0;
    (*uri)->authorityLen[USERINFO] = 0;
    (*uri)->authorityLen[HOST] = 0;
    (*uri)->port = 0;

    (*uri)->componentPtr[SCHEME] = (*uri)->uriBuf;
    type = SCHEME;
    len = 0;
    while (offset < uriLen)
    {
        ch = *(uriStr+offset);
        len++;
        offset++;
        switch(ch)
        {
        case ':':
            if (type == SCHEME)
            {
                (*uri)->componentLen[type] = len-1; /* discount the separator */
                /* look ahead and skip two // */
                ch1 = *(uriStr+offset);
                ch2 = *(uriStr+offset+1);
                if (ch1 == '/' && ch2 == '/')
                {
                    type = AUTHORITY;
                    offset += 2;
                    (*uri)->componentPtr[type] = (*uri)->uriBuf + offset; /* one passed the separator */
                }
                len = 0; /* reset */

            }
            break;
        case '/':
            if (type < PATH)
            {
                (*uri)->componentLen[FULLPATH] = uriLen - offset + 1; /* discount the separator */
                (*uri)->componentPtr[FULLPATH] = (*uri)->uriBuf + offset - 1; /* path include / */

                (*uri)->componentLen[type] = len-1; /* discount the separator */
                type = PATH;
                (*uri)->componentPtr[type] = (*uri)->uriBuf + offset - 1; /* path include / */
                len = 0; /* reset */
            }
            break;
        case '?':

            if (type < QUERY)
            {
                if (type == PATH)
                {
                    (*uri)->componentLen[type] = len; /* path include / */
                } else
                {
                    (*uri)->componentLen[type] = len - 1; /* discount the separator */
                }

                type = QUERY;
                (*uri)->componentPtr[type] = (*uri)->uriBuf + offset;
                len = 0; /* reset */
            }
            break;
        case '#':
            if (type < FRAGMENT)
            {
                if (0 != (*uri)->componentLen[FULLPATH])
                {
                    (*uri)->componentLen[FULLPATH] -= (uriLen - offset + 1);
                }

                if (type == PATH)
                {
                    (*uri)->componentLen[type] = len; /* path include / */
                } else
                {
                    (*uri)->componentLen[type] = len - 1; /* discount the separator */
                }

                type = FRAGMENT;
                (*uri)->componentPtr[type] = (*uri)->uriBuf + offset;
                len = 0; /* reset */
            }
            break;
        default:
            /* not a separator */
            break;
        }
    }
    /* assign len to the last component */
    if (type == PATH)
    {
        (*uri)->componentLen[type] = len+1;
    } else
    {
        (*uri)->componentLen[type] = len;
    }
exit:
    if (OK > status)
    {
        if (*uri)
        {
            URI_DELETE(*uri);
            *uri = NULL;
        }
    }

    return status;

}

/*------------------------------------------------------------------*/

/* will return unescaped atomic component; otherwise it will be in escaped form */
static MSTATUS
URI_GetComponent(componentType type, URI* uri, sbyte** component)
{
    MSTATUS status = OK;

    if (!component)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *component = NULL;

    if (type == AUTHORITY || type == FULLPATH || type == PATH || type == QUERY)
    {
        /* most malloc implementations will return 0 or an
           invalid pointer when the argument is 0 */
        ubyte4 mallocLen = uri->componentLen[type];

        if ((type == FULLPATH) && (mallocLen == 0))
        {
            mallocLen = uri->componentLen[type] = 1;
            uri->componentPtr[type] = (ubyte*)"/";
        }

        *component = (sbyte*)MALLOC(mallocLen+1);
        if (!(*component))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        if (0 < uri->componentLen[type])
        {
            if (OK > (status = MOC_MEMCPY(*component, uri->componentPtr[type], uri->componentLen[type])))
                goto exit;
        }
        *(*component + mallocLen) = '\0';
    }
    else
    {
        if (OK > (status = URI_Unescape(uri->componentPtr[type], uri->componentLen[type], component)))
            goto exit;
    }
exit:
    return status;
}

extern MSTATUS
URI_GetScheme(URI* uri, sbyte** scheme)
{
    return URI_GetComponent(SCHEME, uri, scheme);
}

/*------------------------------------------------------------------*/

extern MSTATUS
URI_GetAuthority(URI* uri, sbyte** authority)
{
    return URI_GetComponent(AUTHORITY, uri, authority);
}
/*------------------------------------------------------------------*/

extern MSTATUS
URI_GetFullPath(URI* uri, sbyte** path)
{
    return URI_GetComponent(FULLPATH, uri, path);
}
/*------------------------------------------------------------------*/

extern MSTATUS
URI_GetPath(URI* uri, sbyte** path)
{
    return URI_GetComponent(PATH, uri, path);
}
/*------------------------------------------------------------------*/

extern MSTATUS
URI_GetQuery(URI* uri, sbyte** query)
{
    return URI_GetComponent(QUERY, uri, query);
}
/*------------------------------------------------------------------*/

extern MSTATUS
URI_GetFragment(URI* uri, sbyte** fragment)
{
    return URI_GetComponent(FRAGMENT, uri, fragment);
}

/* NOTE: only support Server-based Naming Authority for now
    <userinfo>@<host>:<port> */
static MSTATUS
URI_ParseAuthority(URI* uri)
{
    MSTATUS status = OK;
    ubyte* authority;
    ubyte4 authorityLen;
    ubyte4 len;
    ubyte ch;
    authorityComponentType type;
    ubyte4 offset = 0;
    sbyte* stop;
    ubyte* portPtr = NULL;
    ubyte4 portLen = 0;
    authority = uri->componentPtr[AUTHORITY];
    authorityLen = uri->componentLen[AUTHORITY];

    if (authorityLen <=0)
    {
        goto exit;
    }
    uri->authorityPtr[USERINFO] = authority;
    type = USERINFO;
    len = 0;
    while (offset < authorityLen)
    {
        ch = *(authority+offset);
        len++;
        offset++;
        switch(ch)
        {
        case '@':
            uri->authorityLen[type] = len-1; /* discount the separator */
            type = HOST;
            uri->authorityPtr[type] = authority + offset;
            len = 0; /* reset */
            break;
        case ':':
            /* USERINFO is present only when there is a @ separator, otherwise it is HOST */
            if (type == USERINFO)
            {
                uri->authorityPtr[type+1] = uri->authorityPtr[type];
                uri->authorityPtr[type] = NULL;
                type++; /* no userinfo present */
            }
            uri->authorityLen[type] = len-1; /* discount the separator */
            portPtr = authority + offset;
            type = PORT;
            len = 0; /* reset */
            break;
        default:
            /* not a separator*/
            break;
        }
    }
    /* we will have USERINFO part only when there is @ present.
    if type == USERINFO at this point, it means there is no separator.
    thus only HOST is present. */
    if (type == USERINFO)
    {
        uri->authorityPtr[type+1] = uri->authorityPtr[type];
        uri->authorityPtr[type] = NULL;
        type++; /* no userinfo present */
    }
    /* assign len to the last component */
    if (type == PORT)
    {
        portLen = len;
    } else
    {
        uri->authorityLen[type] = len;
    }
    if (portLen > 0)
    {
        uri->port = MOC_ATOL((sbyte *)portPtr, (const sbyte**)&stop);
    }

exit:
    return status;
}

extern MSTATUS
URI_GetUserinfo(URI* uri, sbyte** userinfo)
{
    MSTATUS status;

    if (!userinfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *userinfo = NULL;
    if (uri->componentLen[AUTHORITY] > 0 && uri->authorityLen[HOST] == 0)
    {
        if (OK > (status = URI_ParseAuthority(uri)))
            goto exit;
    }
    return URI_Unescape(uri->authorityPtr[USERINFO], uri->authorityLen[USERINFO], userinfo);
exit:
    return status;

}

MOC_EXTERN MSTATUS
URI_GetHost(URI* uri, sbyte** host)
{
    MSTATUS status;

    if (!host)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *host = NULL;
    if (uri->componentLen[AUTHORITY] > 0 && uri->authorityLen[HOST] == 0)
    {
        if (OK > (status = URI_ParseAuthority(uri)))
            goto exit;
    }
    return URI_Unescape(uri->authorityPtr[HOST], uri->authorityLen[HOST], host);
exit:
    return status;
}

MOC_EXTERN MSTATUS
URI_GetPort(URI* uri, sbyte2* port)
{
    MSTATUS status = OK;
    *port = 0;
    if (uri->componentLen[AUTHORITY] > 0 && uri->authorityLen[HOST] == 0)
    {
        if (OK > (status = URI_ParseAuthority(uri)))
            goto exit;
    }
    *port = uri->port;
exit:
    return status;

}

MOC_EXTERN MSTATUS
URI_DELETE(URI* uri)
{
    MSTATUS status = 0;

    if (NULL != uri)
    {
        if (uri->uriBuf)
            FREE(uri->uriBuf);
        uri->uriLen = 0;
        FREE(uri);
    }

    return status;
}

#endif /* #ifdef __ENABLE_MOCANA_URI__ */
