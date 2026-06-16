/*
 * unittest_utils.h
 *
 * functions useful for writing tests
 *
 * Copyright Mocana Corp 2009. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#ifndef __UNITTEST_UTILS__
#define __UNITTEST_UTILS__

ubyte4 UNITTEST_UTILS_str_to_byteStr( const sbyte* s, ubyte** bs);
void UNITTEST_UTILS_make_file_name( const sbyte* root, const TimeDate* td, sbyte buffer[]);


#endif