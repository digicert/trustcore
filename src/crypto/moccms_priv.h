/*
 * moccms_priv.h
 *
 * Internal Declarations and Definitions for the Mocana CMS Implementation
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
@file       moccms_priv.h

@brief      Header file for the Mocana SoT Platform API for
              Cryptographic Message Syntax (CMS) support.
              DO NOT include in any source code using the public API!

@filedoc    moccms_priv.h
*/

#ifndef __MOCANA_CMS_PRIV_HEADER__
#define __MOCANA_CMS_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/************************************************************************/

/** This enum reflects the 'streaming' support of the CMS data being processed.
 *  <p>The creator of a CMS message can use two methods:
 *  <ul>
 *   <li>Streaming: The size of the payload is not predetermined, and so the
 *                  outer layer of the CMS ASN1 encoding uses 'indefinite' length;</li>
 *   <li>Definite:  The size of the payload is known from the beginning, and so
 *                  the outer layer of the CMS ASN1 has a definite length field;</li>
 *  </ul>
 *  <p>The CMS context contains this value to adjust parsing of the payload, if
 *  needed.
 */
typedef enum MOC_CMS_StreamType
{
    E_MOC_CMS_st_undetermined = 0,
    E_MOC_CMS_st_definite     = 1,
    E_MOC_CMS_st_streaming    = 2,
} MOC_CMS_StreamType;

#ifdef __cplusplus
}
#endif

#endif  /* __MOCANA_CMS_PRIV_HEADER__ */
