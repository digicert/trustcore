/*
 * mdefs.h
 *
 * Mocana Definitions
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

#ifndef __MDEFS_HEADER__
#define __MDEFS_HEADER__

#ifndef NULL
#define NULL                            (0)
#endif

#ifndef MOC_UNUSED
#define MOC_UNUSED(X)
#endif

#define CR                              '\x0d'
#define LF                              '\x0a'
#define CRLF                            "\x0d\x0a"
#define TAB                             '\x09'
#define QMARK                           '\x3f'
#define SP                              '\x20'

#ifndef TRUE
#define TRUE                            (1)
#endif

#ifndef FALSE
#define FALSE                           (0)
#endif

#ifndef COUNTOF
#define COUNTOF(a)                      (sizeof(a)/sizeof(a[0]))
#endif

#ifndef OFFSETOF
#ifdef  offsetof
#define OFFSETOF(s,m)    offsetof(s,m)
#else
#define OFFSETOF(s,m)   (ubyte4)((uintptr)&(((s *)0)->m))
#endif
#endif

#ifndef MOCANA_UPPER_PRIVILEGE_PORT
#define MOCANA_UPPER_PRIVILEGE_PORT     (1024)
#endif

#endif /* __MDEFS_HEADER__ */
