/*
 * mprintf.h
 *
 * Mocana printf
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

#ifndef __MPRINTF_HEADER__
#define __MPRINTF_HEADER__

#if defined(__ENABLE_DIGICERT_PRINTF__)

#include <stdarg.h>

/*
 * Implementation of va_list is architecture depended,
 * the purpose of this structure is to workaround compiler
 * type warning when passing the list as argument or
 * making assignment.
 */
typedef struct moc_va_list
{
    va_list ap;

} moc_va_list;

struct mocSegDesrc;

MOC_EXTERN sbyte4 MPRINTF(struct mocSegDescr *pBufSeg, struct mocSegDescr **ppRetBufSeg, const ubyte *pFormatString, ...);

MOC_EXTERN sbyte4 DIGI_SNPRINTF(sbyte *buffer, sbyte4 bufSize, const ubyte *pFormatString, ...);

MOC_EXTERN sbyte4 DIGI_VSNPRINTF(sbyte *buffer, sbyte4 bufSize,
                                const ubyte *pFormatString, moc_va_list *ap);

#endif /* __ENABLE_DIGICERT_PRINTF__ */

#endif /* __MPRINTF_HEADER__ */
