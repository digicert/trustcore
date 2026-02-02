/*
 * tp_version.c
 *
 * Implementation of Version information for TrustPoint Products
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

#if defined(__ENABLE_DIGICERT_PRODUCT_VERSION__) && (defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || defined(__RTOS_OSX__))

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "tp_version.h"

#include <stdio.h>

#define PLATFORM_HDR      "Platform:"
#define VERSION_HDR       "Version:"
#define BUILD_HDR         "Build:"
#define DATE_HDR          "Date:"
#define GEN_UNKNOWN       "(unknown)"
#define SPACE_PADDING     40  /* Big enough for two UNKNOWNS and extra spaces */

#ifndef TP_BUILD_PLATFORM_STR
#define TP_BUILD_PLATFORM_STR "(unknown)"
#endif

#ifndef TP_BUILD_TAPINFO_STR
#define TP_BUILD_TAPINFO_STR "(unknown)"
#endif

#ifndef TP_BUILD_TYPE_STR
#define TP_BUILD_TYPE_STR "(unknown)"
#endif

#ifndef TP_BUILD_VERSION_STR
#define TP_BUILD_VERSION_STR "(unknown)"
#endif

#ifndef TP_BUILD_IDENTITY_STR
#define TP_BUILD_IDENTITY_STR "(unknown)"
#endif

#ifndef TP_BUILD_DATE_STR
#define TP_BUILD_DATE_STR "(unknown)"
#endif

/*------------------------------------------------------------------*/


MOC_EXTERN MSTATUS
TP_getVersion (ubyte* pRetBuffer, ubyte4 retBufLength)
{
  MSTATUS status = OK;
  int total = 0;

  total =  DIGI_STRLEN((sbyte*)PLATFORM_HDR) + DIGI_STRLEN((sbyte*)VERSION_HDR)
           + DIGI_STRLEN((sbyte*)BUILD_HDR) + DIGI_STRLEN((sbyte*)DATE_HDR)
           + SPACE_PADDING;
  /* The last number leaves some room for a few extra spaces */

  total += DIGI_STRLEN((sbyte*)TP_BUILD_PLATFORM_STR) + DIGI_STRLEN((sbyte*)TP_BUILD_TAPINFO_STR)
           + DIGI_STRLEN((sbyte*)TP_BUILD_TYPE_STR) + DIGI_STRLEN((sbyte*)TP_BUILD_VERSION_STR)
           + DIGI_STRLEN((sbyte*)TP_BUILD_IDENTITY_STR) + DIGI_STRLEN((sbyte*)TP_BUILD_DATE_STR);

  if ((total >= (int)retBufLength) || (total >= TP_MAX_VERSION_LEN))
  {
    return ERR_BUFFER_OVERFLOW;
  }

  pRetBuffer[0] = '\0';

  /* Only print platform if it is defined */
  if (0 != DIGI_STRLEN((const sbyte *)TP_BUILD_PLATFORM_STR))
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)PLATFORM_HDR);
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)TP_BUILD_PLATFORM_STR);
    /* Only print tap-info if it is defined */
    if (0 != DIGI_STRLEN((const sbyte *)TP_BUILD_TAPINFO_STR))
    {
      DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)"(");
      DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)TP_BUILD_TAPINFO_STR);
      DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)") ");
    }
    else
    {
      DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)" ");
    }
  }

  /* Only print build-type if it is defined */
  if (0 != DIGI_STRLEN((const sbyte *)TP_BUILD_TYPE_STR))
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)TP_BUILD_TYPE_STR);
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)" ");
  }

  /* Always print version, so it should always be defined. */
  DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)VERSION_HDR);
  if (0 != DIGI_STRLEN((const sbyte *)TP_BUILD_VERSION_STR))
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)TP_BUILD_VERSION_STR);
  }
  else
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)GEN_UNKNOWN);
  }
  DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)" ");

  /* Only print build-identity if it is defined */
  if (0 != DIGI_STRLEN((const sbyte *)TP_BUILD_IDENTITY_STR))
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)BUILD_HDR);
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)TP_BUILD_IDENTITY_STR);
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)" ");
  }

  /* Always print date, so it should always be defined. */
  DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)DATE_HDR);
  if (0 != DIGI_STRLEN((const sbyte *)TP_BUILD_DATE_STR))
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)TP_BUILD_DATE_STR);
  }
  else
  {
    DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)GEN_UNKNOWN);
  }

  return status;

}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
TP_printVersion (void)
{
  MSTATUS status = OK;
  char *pVersion = NULL;

  printf ("Copyright (c) 2006-%d Digicert Inc\n", CURR_YEAR);
  status = DIGI_CALLOC ((void **) &pVersion, 1, TP_MAX_VERSION_LEN);
  if (OK == status)
  {
    status = TP_getVersion ((ubyte *) pVersion, TP_MAX_VERSION_LEN);
    printf ("  Version: %s", pVersion);
    DIGI_FREE ((void **) &pVersion);
  }
  printf ("\n\n");

  if (NULL != pVersion)
  {
    DIGI_FREE ((void **) &pVersion);
  }

  return status;
}

#endif /* if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) */
