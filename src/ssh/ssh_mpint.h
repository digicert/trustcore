/*
 * ssh_mpint.h
 *
 * Functions for converting between raw byte arrays to mpint byte arrays and vice versa
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
@file       ssh_mpint.h
@brief      SSH byte array to mpint byte array conversions.
@details    This header file contains definitions and function declarations used
            by for SSH bytes array to mpint array

@flags
Whether the following flag is defined determines which function declarations are
enabled:

*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/memory_debug.h"
#include "../common/asm_math.h"
#include "../crypto/hw_accel.h"
#ifndef __SSH_MPINT_HEADER__
#define __SSH_MPINT_HEADER__

/**
 * @brief Converts a raw byte array to an SSH mpint-formatted byte string.
 *
 * @param pValue    Input byte array.
 * @param valueLen  Length of input array.
 * @param sign      Nonzero for negative, zero for positive.
 * @param ppDest    Output: pointer to allocated mpint byte string.
 * @param pRetLen   Output: length of mpint byte string.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */ 
MOC_EXTERN MSTATUS SSH_mpintByteStringFromByteString (
  const ubyte* pValue,
  ubyte4 valueLen,
  ubyte sign,
  ubyte** ppDest,
  sbyte4* pRetLen
  );

/**
 *  @brief Converts an SSH string (mpint or not) into a byte buffer.
 *         Does not handle mpint padding bytes.
 *
 * @param pArray           Input SSH string (may be mpint).
 * @param bytesAvailable   Number of bytes available in input.
 * @param ppNewArray       Output: pointer to allocated value buffer.
 * @param pRetNumBytesUsed Output: number of bytes extracted.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_getByteStringFromMpintBytes(
  const ubyte *pArray, 
  ubyte4 bytesAvailable,
  ubyte **ppNewArray,  
  ubyte4 *pRetNumBytesUsed
  );

#endif /* __SSH_MPINT_HEADER__ */
