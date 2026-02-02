/**
 * @file sapi2_errors.h
 * @brief The header file for the response code processing functions for TPM2.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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

#ifndef MSS_SAPI2_ERRORS_H
#define MSS_SAPI2_ERRORS_H


#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../../../../common/mtypes.h"
#include "../../../../common/mdefs.h"
#include "../tpm2_types.h"


#define RESP_STR_SIZE               200
#define MAX_HANDLE_ERROR            7
#define PBIT_MASK                   (1 << 6)
#define FORMAT_MASK                 (1 << 7)
#define VBIT_MASK                   (1 << 8)
#define TBIT_MASK                   (1 << 10)
#define SBIT_MASK                   (1 << 11)
#define NBIT_MASK                   0xF00
#define RESPCODE_MASK               0xFFF
#define RESPCODE_NUM_MASK_F0        0x07F
#define RESPCODE_NUM_MASK_F1        0x03F

#define IS_P_BIT_SET(x)             ((x) & PBIT_MASK)
#define IS_V_BIT_SET(x)             ((x) & VBIT_MASK)
#define IS_T_BIT_SET(x)             ((x) & TBIT_MASK)
#define IS_S_BIT_SET(x)             ((x) & SBIT_MASK)
#define IS_FORMAT_1(x)              ((x) & FORMAT_MASK)

#define GET_RESP_N(x)               (((x) & NBIT_MASK) >> 8)
#define GET_RESP_CODE(x)            ((x) & RESPCODE_MASK)
#define GET_RESP_CODE_NUM_F0(x)     ((x) & RESPCODE_NUM_MASK_F0)
#define GET_RESP_CODE_NUM_F1(x)     ((x) & RESPCODE_NUM_MASK_F1)

#define TPM_RC_ECC_POINT            0x27
#define TPM_RC_NV_UNAVAILABLE       0x23
#define TPM_RC_SENSITIVE            0x55
#define MAX_FMT1_NUM                (TPM_RC_ECC_POINT+1)
#define MAX_WARN_NUM                (TPM_RC_NV_UNAVAILABLE+1)
#define MAX_VER1_NUM                (TPM_RC_SENSITIVE+1)

MOC_EXTERN char* SAPI2_ERRORS_processRespCode(ubyte4 respCode, char *pBuf, ubyte2 bufSize);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif  /* MSS_SAPI2_ERRORS_H */
