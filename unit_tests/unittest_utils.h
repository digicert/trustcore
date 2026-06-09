/*
 * unittest_utils.h
 *
 * functions useful for writing tests
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#ifndef __UNITTEST_UTILS__
#define __UNITTEST_UTILS__

ubyte4 UNITTEST_UTILS_str_to_byteStr( const sbyte* s, ubyte** bs);
void UNITTEST_UTILS_make_file_name( const sbyte* root, const TimeDate* td, sbyte buffer[]);


#endif
