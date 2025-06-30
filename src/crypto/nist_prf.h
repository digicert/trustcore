/*
 * nist_prf.h
 *
 * Implementation of the PRFs described in NIST 800-108
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
 * @file       nist_prf.h
 *
 * @brief      Header file for the NanoCrypto NIST Pseudo Random Function constructions.
 *
 * @details    This header file contains definitions, enumerations, structures, and function
 *             declarations used for NIST PRF constructions as described in NIST 800-108.
 *
 * @filedoc    nist_prf.h
 */

/*------------------------------------------------------------------*/

#ifndef __NIST_PRF_HEADER__
#define __NIST_PRF_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MOC_EXTERN_NIST_PRF_H
#undef MOC_EXTERN_NIST_PRF_H
#endif /* MOC_EXTERN_NIST_PRF_H */

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_CRYPTO
#define MOC_EXTERN_NIST_PRF_H __declspec(dllexport)
#else
#define MOC_EXTERN_NIST_PRF_H __declspec(dllimport) extern 
#endif /* WIN_EXPORT_CRYPTO */

#ifdef WIN_STATIC
#undef MOC_EXTERN_NIST_PRF_H
#define MOC_EXTERN_NIST_PRF_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_NIST_PRF_H extern

#endif /* RTOS_WIN32 */

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif /* MOC_EXTERN_P */

#define MOC_EXTERN_P MOC_EXTERN_NIST_PRF_H



/*------------------------------------------------------------------*/

/*  Function prototypes  */

/* This are the function that must be implemented by the PRF -- see example for HMAC and CMAC */

/**
 * @brief       Function pointer type for a method that gets the output size of a PRF.
 *
 * @details     Function pointer type for a method that gets the output size of a Pseudo Random Function (PRF).
 *
 * @inc_file    nist_prf.h
 *
 * @param ctx      Pointer to a PRF context.
 * @param size     Contents should be set to the output size in bytes of the PRF associated with that context.
 *
 * @return      Must return \c OK (0) if successful and non-zero if unsuccessful.
 *
 * @callbackdoc nist_prf.h
 */
typedef MSTATUS (*PRFOutputSizeFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx, ubyte4* size);

/**
 * @brief       Function pointer type for a method that updates a PRF context with data.
 *
 * @details     Function pointer type for a method that updates a PRF context with data.
 *
 * @inc_file    nist_prf.h
 *
 * @param ctx      Pointer to a PRF context that has been previously initialized.
 * @param data     Buffer holding the input data.
 * @param dataLen  The length of the data in bytes.
 *
 * @return      Must return \c OK (0) if successful and non-zero if unsuccessful.
 *
 * @callbackdoc nist_prf.h
 */
typedef MSTATUS (*PRFUpdateFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx, const ubyte *data, ubyte4 dataLen);

/**
 * @brief       Function pointer type for a method that finalizes a PRF context and outputs a result.
 *
 * @details     Function pointer type for a method that finalizes a PRF context and outputs a result.
 *
 * @inc_file    nist_prf.h
 *
 * @param ctx      Pointer to a PRF context that has been previously initialized and updated.
 * @param result   Buffer that will hold the resulting output. This can not write more bytes
 *                 than the output size determined by your \c PRFOutputSizeFunc.
 *
 * @return      Must return \c OK (0) if successful and non-zero if unsuccessful.
 *
 * @callbackdoc nist_prf.h
 */
typedef MSTATUS (*PRFFinalFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx, ubyte *result);

/**
 * @brief      Structure that holds a trio of function pointers to the PRF implementations.
 *
 * @details    Structure that holds a trio of function pointers to the PRF implementations.
 */
typedef struct PRF_NIST_108
{
    PRFOutputSizeFunc   outputSizeFunc;
    PRFUpdateFunc       updateFunc;
    PRFFinalFunc        finalFunc;
} PRF_NIST_108;

MOC_EXTERN_NIST_PRF_H const PRF_NIST_108 NIST_PRF_Hmac;

#if (!defined(__DISABLE_AES_CMAC__))
MOC_EXTERN_NIST_PRF_H const PRF_NIST_108 NIST_PRF_AesCmac;
#endif

#ifdef __cplusplus
}
#endif

#endif /* __NIST_PRF_HEADER__ */

