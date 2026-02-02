/*
 * uri.h
 *
 * Mocana URI implementation RFC 2396 -- only support hierarchical URI for now; no character encoding for now.
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

#ifndef __URI_H__
#define __URI_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_URI__

typedef enum
{
    SCHEME, AUTHORITY, FULLPATH, PATH, QUERY, FRAGMENT, EXCLUDED
} componentType;

typedef enum
{
    USERINFO, HOST, PORT
} authorityComponentType;

typedef struct
{
    ubyte* uriBuf;
    ubyte4 uriLen;
    /* the followings are pointers into the uri buffer */
    /* the index used is componentType */
    ubyte* componentPtr[6];
    ubyte4 componentLen[6];
    /* the followings are pointers into the componentPtr[AUTHORITY] buffer */
    /* the index used is authorityComponentType, excluding PORT */
    ubyte* authorityPtr[2];
    ubyte4 authorityLen[2];
    ubyte2 port;
} URI;

/*------------------------------------------------------------------*/
/* NOTE: NO UTF-8 support yet.
 1. any atomic component will be escaped where necessary;
 2. any non-atomic component is assumed to be already escaped
    for its specific reserved characters.
    it will be further escaped for excluded characters other than '%'.
    '%' will be assumed to be already escaped in this case,
    otherwise will result in ambiguity.
The atomic components are: scheme, userinfo, host, port, query, fragment;
while the following are NOT atomic: authority, path */
MOC_EXTERN MSTATUS
URI_CreateURI1(sbyte* scheme,
            sbyte* host,
            sbyte2 port,
            sbyte* path,
            URI** uri);

MOC_EXTERN MSTATUS
URI_CreateURI2(sbyte* scheme,
            sbyte* userInfo,
            sbyte* host,
            sbyte2 port,
            sbyte* path,
            sbyte* query,
            sbyte* fragment,
            URI** uri);

MOC_EXTERN MSTATUS
URI_CreateURI3(sbyte* scheme,
            sbyte* authority,
            sbyte* path,
            URI** uri);

MOC_EXTERN MSTATUS
URI_CreateURI4(sbyte* scheme,
          sbyte* authority,
          sbyte* path,
          sbyte* query,
          sbyte* fragment,
          URI** uri);

/* Parse a uri string into components,
   can then call get<Component> to get to individual components;
   or access the escaped version by reaching into the URI structure. */
MOC_EXTERN MSTATUS
URI_ParseURI(sbyte* uriStr, URI** uri);

/* will return unescaped form for atomic component;
 otherwise the returned component will be in escaped form.
To get the escaped version, use URI structure */
MOC_EXTERN MSTATUS
URI_GetScheme(URI* uri, sbyte** scheme);

MOC_EXTERN MSTATUS
URI_GetAuthority(URI* uri, sbyte** authority);

MOC_EXTERN MSTATUS
URI_GetFullPath(URI* uri, sbyte** path);

MOC_EXTERN MSTATUS
URI_GetPath(URI* uri, sbyte** path);

MOC_EXTERN MSTATUS
URI_GetQuery(URI* uri, sbyte** query);

MOC_EXTERN MSTATUS
URI_GetFragment(URI* uri, sbyte** fragment);

MOC_EXTERN MSTATUS
URI_GetUserinfo(URI* uri, sbyte** userinfo);

MOC_EXTERN MSTATUS
URI_GetHost(URI* uri, sbyte** host);

MOC_EXTERN MSTATUS
URI_GetPort(URI* uri, sbyte2* port);

/* return the length of the component in escaped form */
MOC_EXTERN MSTATUS
URI_GetEscapedLength(componentType type, sbyte* component, ubyte4 componentLen,
                     ubyte4* escapedLen);

/* return the escaped component.
   the return buffer is passed in for efficient memory allocation purposes.
   */
MOC_EXTERN MSTATUS
URI_Escape(componentType type, sbyte* component, ubyte4 componentLen,
           ubyte* escaped, ubyte4 *escapedLen);

/* return the unescaped component or component part */
MOC_EXTERN MSTATUS
URI_Unescape(ubyte* component, ubyte4 componentLen,
             sbyte** unescaped);

/* release memory */
MOC_EXTERN MSTATUS
URI_DELETE(URI* uri);

#endif /* #ifdef __ENABLE_DIGICERT_URI__ */

#ifdef __cplusplus
}
#endif

#endif
