/**
 * @file tss2_error.h
 *
 * @brief TSS 2.0 Error codes
 * @details TSS 2.0 Error codes
 *
 * See TSS system API section 6.1
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

#ifndef __TSS2_ERROR_H__
#define __TSS2_ERROR_H__


#include "../../../../common/moptions.h"
#include "../../../../common/mtypes.h"
#include "../../../../common/mocana.h"


/* TPM 2.0 chips have a 32-bit response code.
   The TPM will always set the upper 20 bits (31:12) to 0
   and the low-order 12 bits (11:00) will contain the response code
*/

/********************************************************************
 Common Error Codes [Section 6.1.2.1]
 ********************************************************************/

/**
 * @ingroup tpm_common_definitions
 * @brief TSS2 Return Code
 * @details 
 *  <p> TSS2_RC is one of the following values:
 *  - #TSS2_RC_SUCCESS
 *  - #TSS2_BASE_RC_GENERAL_FAILURE
 *  - #TSS2_BASE_RC_NOT_IMPLEMENTED
 *  - #TSS2_BASE_RC_BAD_CONTEXT
 *  - #TSS2_BASE_RC_ABI_MISMATCH
 *  - #TSS2_BASE_RC_BAD_REFERENCE
 *  - #TSS2_BASE_RC_INSUFFICIENT_BUFFER
 *  - #TSS2_BASE_RC_BAD_SEQUENCE
 *  - #TSS2_BASE_RC_NO_CONNECTION
 *  - #TSS2_BASE_RC_TRY_AGAIN
 *  - #TSS2_BASE_RC_IO_ERROR
 *  - #TSS2_BASE_RC_BAD_VALUE
 *  - #TSS2_BASE_RC_NOT_PERMITTED
 *  - #TSS2_BASE_RC_INVALID_SESSIONS
 *  - #TSS2_BASE_RC_NO_DECRYPT_PARAM
 *  - #TSS2_BASE_RC_NO_ENCRYPT_PARAM
 *  - #TSS2_BASE_RC_BAD_SIZE
 *  - #TSS2_BASE_RC_MALFORMED_RESPONSE
 *  - #TSS2_BASE_RC_INSUFFICIENT_CONTEXT
 *  - #TSS2_BASE_RC_INSUFFICIENT_RESPONSE
 *  - #TSS2_BASE_RC_INCOMPATIBLE_TCTI
 *  - #TSS2_BASE_RC_NOT_SUPPORTED
 *  - #TSS2_BASE_RC_BAD_TCTI_STRUCTURE
 */
typedef ubyte4 TSS2_RC;

/**
 * @ingroup tpm_common_definitions
 * @brief TSS2 Success Return Code
 * @details TSS2 Success Return Code
 */
#define TSS2_RC_SUCCESS 0

/*! @cond */

/**
 * @private
 * @internal
 * @details  Shift value used to locate the TSS layer indicator is 16.
 *  This means bits 23:16 contain the layer indicator for response codes
 */
#define TSS2_RC_LEVEL_SHIFT 16

/*! @endcond */


/*! @brief Mask for errors coming from the TPM itself */
#define TSS2_TPM_RC_LEVEL       0
/*! @brief Mask for errors coming from the TCTI layer */
#define TSS2_TCTI_ERROR_LEVEL   (10 << TSS2_RC_LEVEL_SHIFT)
/*! @brief Mask for errors coming from the SAPI layer */
#define TSS2_SYS_ERROR_LEVEL    (8 << TSS2_RC_LEVEL_SHIFT)
/*! @brief Mask for errors coming from implementation rather than TPM itself */
#define TSS2_SYS_PART2_RC_LEVEL (9 << TSS2_RC_LEVEL_SHIFT)

/*! @brief Mask for error bits 23-16 */
#define TSS2_RC_LEVEL_MASK 0xFF0000
/*! @brief Macro to get the error level. */
#define TSS2_RC_LEVEL(x) (x & TSS2_RC_LEVEL_MASK)

/********************************************************************
 Bit layer indicator masks - bits 15-12
 ********************************************************************/

/********************************************************************
 Format 0 and 1 error masks and macros - derived from spec
 ********************************************************************/

/*! TSS2 error format bit mask
 * <p> TPM 2.0 erros have 2 error formats: 0 and 1.  This bit indicates which format the error is in.
 */
#define TSS2_RC_FORMAT_BIT_MASK (1<<7)
/*! TPM 2.0 Error Format 0 mask; low 7 bits */
#define TSS2_RC_ERROR_MASK_FORMAT0 0x7F
/*! TPM 2.0 Error Format 1 mask; low 6 bits */
#define TSS2_RC_ERROR_MASK_FORMAT1 0x3F

/*! @brief Macro to get the error format. */
#define TSS2_RC_FORMAT(x) (x & TSS2_RC_FORMAT_BIT_MASK)
/*! @brief Macro to test if error is in format 0. */
#define TSS2_RC_ERROR_FORMAT0(x) (x & TSS2_RC_ERROR_MASK_FORMAT0)
/*! @brief Macro to test if error is in format 1. */
#define TSS2_RC_ERROR_FORMAT1(x) (x & TSS2_RC_ERROR_MASK_FORMAT1)

/*! Macro to return error code from either Format0 or Format1 error, based on format bit */
#define TSS2_RC_ERROR(x) ((x & TSS2_RC_FORMAT(x)) ? TSS2_RC_ERROR_FORMAT1(x) ? TSS2_RC_ERROR_FORMAT0(x))


/********************************************************************
 Base error codes: [Section 6.1.2.2]
   Base error codes are not returned directly, but are combined with
   an ERROR_LEVEL to produce the error codes for each layer.
 ********************************************************************/

/*! Catch all - general error */
#define TSS2_BASE_RC_GENERAL_FAILURE       (ubyte4)(1)
/*! If called functionality is NOT implemented */
#define TSS2_BASE_RC_NOT_IMPLEMENTED       (ubyte4)(2)
/*! A context structure is bad */
#define TSS2_BASE_RC_BAD_CONTEXT           (ubyte4)(3)
/*! Passed in ABI version doesn't match called module's ABI version */
#define TSS2_BASE_RC_ABI_MISMATCH          (ubyte4)(4)
/*! A pointer is NULL that must not be NULL */
#define TSS2_BASE_RC_BAD_REFERENCE         (ubyte4)(5)
/*! A buffer isn't large enough */
#define TSS2_BASE_RC_INSUFFICIENT_BUFFER   (ubyte4)(6)
/*! Function called in wrong order */
#define TSS2_BASE_RC_BAD_SEQUENCE          (ubyte4)(7)
/*! Fails to connect to next lower layer */
#define TSS2_BASE_RC_NO_CONNECTION         (ubyte4)(8)
/*! Operation timed out; function must be called again to complete */
#define TSS2_BASE_RC_TRY_AGAIN             (ubyte4)(9)
/*! IO failure */
#define TSS2_BASE_RC_IO_ERROR              (ubyte4)(10)
/*! A parameter has a bad value */
#define TSS2_BASE_RC_BAD_VALUE             (ubyte4)(11)
/*! Operation not permitted */
#define TSS2_BASE_RC_NOT_PERMITTED         (ubyte4)(12)
/*! Session structures were sent, but cmd doesn't use them or
   doesn't use the specified number of them */
#define TSS2_BASE_RC_INVALID_SESSIONS      (ubyte4)(13)
/*! Function called that uses decrypt param, but cmd doesn't support decrypt param */
#define TSS2_BASE_RC_NO_DECRYPT_PARAM      (ubyte4)(14)
/*! Function called that uses encrypt param, but cmd doesn't support encrypt param */
#define TSS2_BASE_RC_NO_ENCRYPT_PARAM      (ubyte4)(15)
/*! If size of a parameter is incorrect */
#define TSS2_BASE_RC_BAD_SIZE              (ubyte4)(16)
/*! Response is malformed */
#define TSS2_BASE_RC_MALFORMED_RESPONSE    (ubyte4)(17)
/*! Context is not large enough */
#define TSS2_BASE_RC_INSUFFICIENT_CONTEXT  (ubyte4)(18)
/*! Response is not large enough */
#define TSS2_BASE_RC_INSUFFICIENT_RESPONSE (ubyte4)(19)
/*! Unknown or unusable TCTI version */
#define TSS2_BASE_RC_INCOMPATIBLE_TCTI     (ubyte4)(20)
/**************************************************************
 * Spec has last 2 defined as 21 - but guessing that's a typo
 **************************************************************/
/*! Functionality not supported */
#define TSS2_BASE_RC_NOT_SUPPORTED         (ubyte4)(21)
/*! TCTI context is bad */
#define TSS2_BASE_RC_BAD_TCTI_STRUCTURE    (ubyte4)(22)

/********************************************************************
 TCTI error codes: [Section 6.1.2.3]
   Bits 23:16 indicate TCTI layer
   Bits 11:0 contain TCTI specific error as detailed below
 ********************************************************************/

/*! Bits 23:16 - TCTI layer indicator */

/*! TCTI layer error: Catch all - general error */
#define TSS2_TCTI_RC_GENERAL_FAILURE        ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_GENERAL_FAILURE))
/*! TCTI layer error: If called functionality is NOT implemented */
#define TSS2_TCTI_RC_NOT_IMPLEMENTED        ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NOT_IMPLEMENTED))
/*! TCTI layer error: A context structure is bad */
#define TSS2_TCTI_RC_BAD_CONTEXT            ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_BAD_CONTEXT))
/*! TCTI layer error: Passed in ABI version doesn't match called module's ABI version */
#define TSS2_TCTI_RC_ABI_MISMATCH           ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_ABI_MISMATCH))
/*! TCTI layer error: A pointer is NULL that must not be NULL */
#define TSS2_TCTI_RC_BAD_REFERENCE          ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_BAD_REFERENCE))
/*! TCTI layer error: A buffer isn't large enough */
#define TSS2_TCTI_RC_INSUFFICIENT_BUFFER    ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_INSUFFICIENT_BUFFER))
/*! TCTI layer error: Function called in wrong order */
#define TSS2_TCTI_RC_BAD_SEQUENCE           ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_BAD_SEQUENCE))
/*! TCTI layer error: Fails to connect to next lower layer */
#define TSS2_TCTI_RC_NO_CONNECTION          ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NO_CONNECTION))
/*! TCTI layer error: Operation timed out; function must be called again to complete */
#define TSS2_TCTI_RC_TRY_AGAIN              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_TRY_AGAIN))
/*! TCTI layer error: IO failure */
#define TSS2_TCTI_RC_IO_ERROR               ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_IO_ERROR))
/*! TCTI layer error: A parameter has a bad value */
#define TSS2_TCTI_RC_BAD_VALUE              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_BAD_VALUE))
/*! TCTI layer error: Operation not permitted */
#define TSS2_TCTI_RC_NOT_PERMITTED          ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NOT_PERMITTED))
/*! TCTI layer error: Response is malformed */
#define TSS2_TCTI_RC_MALFORMED_RESPONSE     ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_MALFORMED_RESPONSE))
/*! TCTI layer error: Functionality not supported */
#define TSS2_TCTI_RC_NOT_SUPPORTED          ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NOT_SUPPORTED))


/********************************************************************
 SAPI error codes: [Section 6.1.2.4]
   Bits 23:16 indicate SAPI layer
   Bits 11:0 contain SAPI specific error as detailed below
 ********************************************************************/

/* Bits 23:16 - SAPI layer indicator */

/*! SAPI layer error: Catch all - general error */
#define TSS2_SYS_RC_GENERAL_FAILURE        ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_GENERAL_FAILURE))
/*! SAPI layer error: A context structure is bad */
#define TSS2_SYS_RC_BAD_CONTEXT            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                              TSS2_BASE_RC_BAD_CONTEXT))
/*! SAPI layer error: Passed in ABI version doesn't match called module's ABI version */
#define TSS2_SYS_RC_ABI_MISMATCH           ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_ABI_MISMATCH))
/*! SAPI layer error: A pointer is NULL that must not be NULL */
#define TSS2_SYS_RC_BAD_REFERENCE          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_BAD_REFERENCE))
/*! SAPI layer error: A buffer isn't large enough */
#define TSS2_SYS_RC_INSUFFICIENT_BUFFER    ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_INSUFFICIENT_BUFFER))
/*! SAPI layer error: Function called in wrong order */
#define TSS2_SYS_RC_BAD_SEQUENCE           ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_BAD_SEQUENCE))
/*! SAPI layer error: IO failure */
#define TSS2_SYS_RC_IO_ERROR               ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_IO_ERROR))
/*! SAPI layer error: A parameter has a bad value */
#define TSS2_SYS_RC_BAD_VALUE              ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_BAD_VALUE))
/*! SAPI layer error: Operation not permitted */
#define TSS2_SYS_RC_NOT_PERMITTED          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_NOT_PERMITTED))
/*! SAPI layer error: Session structures were sent, but cmd doesn't use them or
   doesn't use the specified number of them */
#define TSS2_SYS_RC_INVALID_SESSIONS       ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_INVALID_SESSIONS))
/*! SAPI layer error: Function called that uses decrypt param, but cmd doesn't support decrypt param */
#define TSS2_SYS_RC_NO_DECRYPT_PARAM       ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NO_DECRYPT_PARAM))
/*! SAPI layer error: Function called that uses encrypt param, but cmd doesn't support encrypt param */
#define TSS2_SYS_RC_NO_ENCRYPT_PARAM       ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NO_ENCRYPT_PARAM))
/*! SAPI layer error: If size of a parameter is incorrect */
#define TSS2_SYS_RC_BAD_SIZE               ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_BAD_SIZE))
/*! SAPI layer error: Response is malformed */
#define TSS2_SYS_RC_MALFORMED_RESPONSE     ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_MALFORMED_RESPONSE))
/*! SAPI layer error: Context is not large enough */
#define TSS2_SYS_RC_INSUFFICIENT_CONTEXT   ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
/*! SAPI layer error: Response is not large enough */
#define TSS2_SYS_RC_INSUFFICIENT_RESPONSE  ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
/*! SAPI layer error: Unknown or unusable TCTI version */
#define TSS2_SYS_RC_INCOMPATIBLE_TCTI      ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_INCOMPATIBLE_TCTI))
/*! SAPI layer error: Functionality not supported */
#define TSS2_SYS_RC_NOT_SUPPORTED          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                              TSS2_BASE_RC_NOT_SUPPORTED))
/*! SAPI layer error: TCTI context is bad */
#define TSS2_SYS_RC_BAD_TCTI_STRUCTURE     ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
                                             TSS2_BASE_RC_BAD_TCTI_STRUCTURE))


/********************************************************************
 TPM error codes: [Section 6.1.2.5]
   Bits 23:16 indicate TPM = 0
   Bits 11:0 contain BASE error as detailed above
 ********************************************************************/




/* Temporary FAPI defs until TCG defines a FAPI bit shift value  */

/*! FAPI layer error: Catch all - general error */
#define TSS2_FAPI_RC_GENERAL_FAILURE      ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_GENERAL_FAILURE))
/*! FAPI layer error: If called functionality is NOT implemented */
#define TSS2_FAPI_RC_NOT_IMPLEMENTED      ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_NOT_IMPLEMENTED))
/*! FAPI layer error: A context structure is bad */
#define TSS2_FAPI_RC_BAD_CONTEXT          ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_BAD_CONTEXT))
/*! FAPI layer error: Passed in ABI version doesn't match called module's ABI version */
#define TSS2_FAPI_RC_ABI_MISMATCH         ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_ABI_MISMATCH))
/*! FAPI layer error: A pointer is NULL that must not be NULL */
#define TSS2_FAPI_RC_BAD_REFERENCE        ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_BAD_REFERENCE))
/*! FAPI layer error: A buffer isn't large enough */
#define TSS2_FAPI_RC_INSUFFICIENT_BUFFER  ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_INSUFFICIENT_BUFFER))
/*! FAPI layer error: Function called in wrong order */
#define TSS2_FAPI_RC_BAD_SEQUENCE         ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_BAD_SEQUENCE))
/*! FAPI layer error: Fails to connect to next lower layer */
#define TSS2_FAPI_RC_NO_CONNECTION        ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_NO_CONNECTION))
/*! FAPI layer error: Operation timed out; function must be called again to complete */
#define TSS2_FAPI_RC_TRY_AGAIN            ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_TRY_AGAIN))
/*! FAPI layer error: IO failure */
#define TSS2_FAPI_RC_IO_ERROR             ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_IO_ERROR))
/*! FAPI layer error: A parameter has a bad value */
#define TSS2_FAPI_RC_BAD_VALUE            ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_BAD_VALUE))
/*! FAPI layer error: Operation not permitted */
#define TSS2_FAPI_RC_NOT_PERMITTED        ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_NOT_PERMITTED))
/*! FAPI layer error: Session structures were sent, but cmd doesn't use them or
   doesn't use the specified number of them */
#define TSS2_FAPI_RC_INVALID_SESSIONS     ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_INVALID_SESSIONS))
/*! FAPI layer error: Function called that uses decrypt param, but cmd doesn't support decrypt param */
#define TSS2_FAPI_RC_NO_DECRYPT_PARAM     ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_NO_DECRYPT_PARAM))
/*! FAPI layer error: Function called that uses encrypt param, but cmd doesn't support encrypt param */
#define TSS2_FAPI_RC_NO_ENCRYPT_PARAM     ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_NO_ENCRYPT_PARAM))
/*! FAPI layer error: If size of a parameter is incorrect */
#define TSS2_FAPI_RC_BAD_SIZE             ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_BAD_SIZE))
/*! FAPI layer error: Response is malformed */
#define TSS2_FAPI_RC_MALFORMED_RESPONSE   ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_MALFORMED_RESPONSE))
/*! FAPI layer error: Context is not large enough */
#define TSS2_FAPI_RC_INSUFFICIENT_CONTEXT ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
/*! FAPI layer error: Response is not large enough */
#define TSS2_FAPI_RC_INSUFFICIENT_RESPONSE ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
/*! FAPI layer error: Unknown or unusable TCTI version */
#define TSS2_FAPI_RC_INCOMPATIBLE_TCTI    ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_INCOMPATIBLE_TCTI))
/*! FAPI layer error: Functionality not supported */
#define TSS2_FAPI_RC_NOT_SUPPORTED        ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_NOT_SUPPORTED))
/*! FAPI layer error: TCTI context is bad */
#define TSS2_FAPI_RC_BAD_TCTI_STRUCTURE   ((TSS2_RC)(TSS2_SYS_PART2_RC_LEVEL | \
                                              TSS2_BASE_RC_BAD_TCTI_STRUCTURE))
#endif /* __TSS2_ERROR_H__ */
