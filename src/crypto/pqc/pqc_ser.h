/*
 * pqc_ser.h
 *
 * Header file for PQC key serialization methods.
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
 @file       pqc_ser.h
 @brief      Header file for PQC key serialization methods

 @filedoc    pqc_ser.h
 */
#ifndef __PQC_SER_HEADER__
#define __PQC_SER_HEADER__

#include "../../crypto/pqc/mldsa.h"
#include "../../crypto/pqc/mlkem.h"
#include "../../crypto/pqc/slhdsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    Serializes a key into a basic blob format
 *
 * @details  Serializes a key into a basic blob format
 *
 * @param[in] ctx           Pointer to the context to be serialized.
 * @param[in] pubOnly       Set to \c TRUE for serializing only the public portion of the key.
 * @param[out] serKey       Pointer to the location that will receive a newly allocated buffer holding the serialization.
 * @param[in,out] serKeyLen Will receive the length of the new buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_serializeKeyAlloc(MLKEMCtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen);

/**
 * @brief    Deserializes a blob format key into a ML-KEM context structure.
 *
 * @details  Deserializes a blob format key into a ML-KEM context structure.
 *
 * @param[in,out] ctx       Pointer to the empty key shell.
 * @param[in] pubOnly       Set to \c TRUE for deserializing only the public portion of the key.
 * @param[in] serKey        THe buffer holding the serialized key.
 * @param[in] serKeyLen     The length of the serialized key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_deserializeKey(MLKEMCtx *ctx, bool pubOnly, ubyte *serKey, ubyte4 serKeyLen);

/**
 * @brief    Serializes a key into a basic blob format
 *
 * @details  Serializes a key into a basic blob format
 *
 * @param[in] ctx           Pointer to the context to be serialized.
 * @param[in] pubOnly       Set to \c TRUE for serializing only the public portion of the key.
 * @param[out] serKey       Pointer to the location that will receive a newly allocated buffer holding the serialization.
 * @param[in,out] serKeyLen Will receive the length of the new buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_serializeKeyAlloc(MLDSACtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen);

/**
 * @brief    Deserializes a blob format key into a ML-DSA context structure.
 *
 * @details  Deserializes a blob format key into a ML-DSA context structure.
 *
 * @param[in,out] ctx       Pointer to the empty key shell.
 * @param[in] pubOnly       Set to \c TRUE for deserializing only the public portion of the key.
 * @param[in] serKey        THe buffer holding the serialized key.
 * @param[in] serKeyLen     The length of the serialized key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_deserializeKey(MLDSACtx *ctx, bool pubOnly, ubyte *serKey, ubyte4 serKeyLen);

/**
 * @brief    Sets a flag to determine if key serialization includes the seed or longform private key.
 *
 * @details  Sets a flag to determine if key serialization includes the seed or longform private key.
 *           Default setting is the seed only.
 *
 * @param[in] format Input \c TRUE for long form key serialization, \c FALSE otherwise. 
 *
 * @warning  This method is not thread safe and should be just called once upon startup.
 *
 */
MOC_EXTERN void MLDSA_setLongFormPrivKeyFormat(byteBoolean format);

/**
 * @brief    Serializes a key into a basic blob format
 *
 * @details  Serializes a key into a basic blob format
 *
 * @param pKey       Pointer to the key to be serialized.
 * @param pubOnly    Set to \c TRUE for serializing only the public portion of the key.
 * @param ppSerKey   Pointer to the location that will receive a newly allocated buffer holding the serialization.
 * @param pSerKeyLen Will receive the length of the new buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_serializeKeyAlloc(SLHDSACtx *ctx, bool pubOnly,
                                            uint8_t **serKey, size_t *serKeyLen);

/**
 * @brief    Deserializes a blob format key into a SLHDSA Key.
 *
 * @details  Deserializes a blob format key into a SLHDSA Key. One must know ahead
 *           of time the SLHDSA algorithm (ie hash mode).
 *
 * @param pKey       Pointer to the empty key shell.
 * @param pubOnly    Set to \c TRUE for deserializing only the public portion of the key.
 * @param pSerKey    THe buffer holding the serialized key.
 * @param serKeyLen  The length of the serialized key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_deserializeKey(SLHDSACtx *ctx, bool pubOnly,
                                         uint8_t *serKey, size_t serKeyLen);

#ifdef __cplusplus
}
#endif

#endif /* __PQC_SER_HEADER__ */
