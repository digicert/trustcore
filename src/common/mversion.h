/*
 * mversion.h
 *
 * Mocana version header
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

/**
@file       mversion.h 
@brief      Mocana SoT Platform library version function header file.
@details    This header file contains the version information for binary libraries.

@since 1.41
@version 2.02 and later

*/


/*------------------------------------------------------------------*/

#ifndef __MVERSION_HEADER__
#define __MVERSION_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
enum versionType
{
	VT_MAIN = 0x01,
	VT_BUILD = 0x02,
	VT_TIMESTAMP = 0x04,
	VT_ALL = 0xFF
};


/*------------------------------------------------------------------*/

MOC_EXTERN sbyte4 DIGICERT_readVersion(sbyte4 type, ubyte *pRetBuffer, ubyte4 retBufLength);

/*------------------------------------------------------------------*/
 

#ifdef __cplusplus
}
#endif

#endif /* __MVERSION_HEADER__ */
