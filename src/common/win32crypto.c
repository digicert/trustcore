/*
 * win32crypto.c
 *
 * General crypto stack definitions since Windows cannot accept pointers
 * for certain symbols.
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

#ifdef __RTOS_WIN32__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../common/random.h"
#ifdef __ENABLE_ARC2_CIPHERS__
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#endif
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#ifdef __ENABLE_BLOWFISH_CIPHERS__
#include "../crypto/blowfish.h"
#endif
#ifdef __ENABLE_NIL_CIPHER__
#include "../crypto/nil.h"
#endif
#include "../asn1/oiddefs.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_aes_ctr.h"
#include "../crypto_interface/crypto_interface_blowfish.h"
#include "../crypto_interface/crypto_interface_des.h"
#include "../crypto_interface/crypto_interface_tdes.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#include "../crypto_interface/crypto_interface_md4.h"
#include "../crypto_interface/crypto_interface_md5.h"
#include "../crypto_interface/crypto_interface_arc4.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif

#ifndef __DISABLE_3DES_CIPHERS__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_TripleDESSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { THREE_DES_BLOCK_SIZE, CRYPTO_INTERFACE_Create3DESCtx, CRYPTO_INTERFACE_Delete3DESCtx, CRYPTO_INTERFACE_Do3DESEx, CRYPTO_INTERFACE_Clone3DESCtx };
#else
    { THREE_DES_BLOCK_SIZE, Create3DESCtx, Delete3DESCtx, Do3DES, Clone3DESCtx };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifndef __DISABLE_3DES_TWO_KEY_CIPHER__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_TwoKeyTripleDESSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { THREE_DES_BLOCK_SIZE, CRYPTO_INTERFACE_Create2Key3DESCtx, CRYPTO_INTERFACE_Delete3DESCtx, CRYPTO_INTERFACE_Do3DESEx, CRYPTO_INTERFACE_Clone3DESCtx };
#else
    { THREE_DES_BLOCK_SIZE, Create2Key3DESCtx, Delete3DESCtx, Do3DES, Clone3DESCtx };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* __DISABLE_3DES_TWO_KEY_CIPHER__ */
#endif /* __DISABLE_3DES_CIPHERS__ */

#ifdef __ENABLE_DES_CIPHER__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_DESSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { DES_BLOCK_SIZE, CRYPTO_INTERFACE_CreateDESCtx, CRYPTO_INTERFACE_DeleteDESCtx, CRYPTO_INTERFACE_DoDESEx, CRYPTO_INTERFACE_CloneDESCtx };
#else
    { DES_BLOCK_SIZE, CreateDESCtx, DeleteDESCtx, DoDES, CloneDESCtx };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_DES_CIPHER__ */

#ifndef __DISABLE_ARC4_CIPHERS__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_RC4Suite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { 0, CRYPTO_INTERFACE_CreateRC4Ctx, CRYPTO_INTERFACE_DeleteRC4Ctx, CRYPTO_INTERFACE_DoRC4, CRYPTO_INTERFACE_CloneRC4Ctx };
#else
    { 0, CreateRC4Ctx, DeleteRC4Ctx, DoRC4, CloneRC4Ctx };
#endif
#endif /* __DISABLE_ARC4_CIPHERS__ */

#ifdef __ENABLE_ARC2_CIPHERS__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_RC2Suite =
    { RC2_BLOCK_SIZE, CreateRC2Ctx, DeleteRC2Ctx, DoRC2, CloneRC2Ctx };
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_RC2EffectiveBitsSuite =
    { RC2_BLOCK_SIZE, CreateRC2Ctx2, DeleteRC2Ctx, DoRC2, CloneRC2Ctx };
#endif

#ifdef __ENABLE_BLOWFISH_CIPHERS__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_BlowfishSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { BLOWFISH_BLOCK_SIZE/*8*/, CRYPTO_INTERFACE_CreateBlowfishCtx, CRYPTO_INTERFACE_DeleteBlowfishCtx, CRYPTO_INTERFACE_DoBlowfishEx };
#else
    { BLOWFISH_BLOCK_SIZE/*8*/, CreateBlowfishCtx, DeleteBlowfishCtx, DoBlowfish };
#endif
#endif /* __ENABLE_BLOWFISH_CIPHERS__ */

#ifndef __DISABLE_AES_CIPHERS__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_AESSuite =
    { AES_BLOCK_SIZE, CRYPTO_INTERFACE_CreateAESCtx, CRYPTO_INTERFACE_DeleteAESCtx, CRYPTO_INTERFACE_DoAESEx, CRYPTO_INTERFACE_CloneAESCtx };
#ifndef __DISABLE_AES_CTR_CIPHER__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_AESCtrSuite =
#ifdef __UCOS_DIRECT_RTOS__
    { 0, CRYPTO_INTERFACE_CreateAESCTRCtx, CRYPTO_INTERFACE_DeleteAESCTRCtx, CRYPTO_INTERFACE_DoAESCTR, CRYPTO_INTERFACE_CloneAESCTRCtx };
#else
    { 0, (CreateBulkCtxFunc)CRYPTO_INTERFACE_CreateAESCTRCtx, CRYPTO_INTERFACE_DeleteAESCTRCtx, CRYPTO_INTERFACE_DoAESCTR, CRYPTO_INTERFACE_CloneAESCTRCtx };
#endif /* __UCOS_DIRECT_RTOS__ */
#endif /* __DISABLE_AES_CTR_CIPHER__ */
#else
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_AESSuite =
    { AES_BLOCK_SIZE, CreateAESCtx, DeleteAESCtx, DoAES, CloneAESCtx };
#ifndef __DISABLE_AES_CTR_CIPHER__
MOC_EXTERN_DATA_DEF const BulkEncryptionAlgo CRYPTO_AESCtrSuite =
#ifdef __UCOS_DIRECT_RTOS__
    { 0, CreateAESCTRCtx, DeleteAESCTRCtx, DoAESCTR, CloneAESCTRCtx };
#else
    { 0, (CreateBulkCtxFunc)CreateAESCTRCtx, DeleteAESCTRCtx, DoAESCTR, CloneAESCTRCtx };
#endif /* __UCOS_DIRECT_RTOS__ */
#endif /* __DISABLE_AES_CTR_CIPHER__ */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#endif /* RTOS_WIN32 */
