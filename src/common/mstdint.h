/**
 * @file mstdint.h
 *
 * @ingroup common_tree
 * @ingroup common_nanotap_tree
 *
 * @brief DigiCert Standard Types
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

#include  "../common/mtypes.h"
#include  "../common/mrtos.h"

#ifndef __DISABLE_DIGICERT_STDINT__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#else

typedef ubyte uint8_t;
typedef ubyte2 uint16_t;
typedef ubyte4 uint32_t;
typedef ubyte8 uint64_t;
typedef sbyte int8_t;
typedef sbyte2 int16_t;
typedef sbyte4 int32_t;
typedef sbyte8 int64_t;
/* size_t will probably require some additional conditions to be typedef'd here */
typedef usize size_t;

typedef enum {false, true} bool;

#endif
