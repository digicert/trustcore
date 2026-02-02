/*
 * unittest_utils.h
 *
 * functions useful for writing tests
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

#ifndef __UNITTEST_UTILS__
#define __UNITTEST_UTILS__

ubyte4 UNITTEST_UTILS_str_to_byteStr( const sbyte* s, ubyte** bs);
void UNITTEST_UTILS_make_file_name( const sbyte* root, const TimeDate* td, sbyte buffer[]);


#endif