/**
 * @file mstdint.h
 *
 * @ingroup common_tree
 * @ingroup common_nanotap_tree
 *
 * @brief DigiCert Standard Types
 *
 * Copyright DigiCert Corp 2024. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#include  "../common/mtypes.h"
#include  "../common/mrtos.h"

#ifndef __DISABLE_MOCANA_STDINT__

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
