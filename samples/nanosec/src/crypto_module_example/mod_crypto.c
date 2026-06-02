/*
 * mod_crypto.c
 *
 * Crypto kernel module
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


#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>


#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/debug_console.h"
#include "../../common/mem_pool.h"
#include "../../common/dynarray.h"
#include "../../common/random.h"
#include "../../common/rng_seed.h"
#include "../../common/vlong.h"
#ifdef __ENABLE_DIGICERT_MEM_PART__
#include "../../common/mem_part.h"
#endif
#include "../../crypto/crypto.h"
#include "../../harness/harness.h"
#include "../../crypto/md5.h"
#include "../../crypto/md4.h"
#include "../../crypto/md2.h"

#include "../../crypto/aes.h"
#include "../../crypto/aesalgo.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto/aes_ccm.h"
#include "../../crypto/aes_cmac.h"
#include "../../crypto/aes_ecb.h"
#include "../../crypto/aes_xcbc_mac_96.h"
#include "../../crypto/aes_eax.h"
#include "../../crypto/aes_xts.h"

#include "../../crypto/gcm.h"

#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/hmac.h"

#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/fips.h"
#include "../../crypto/fips_priv.h"
#include "../../crypto/nist_rng.h"

#include "../../common/mversion.h"

MODULE_AUTHOR("www.digicert.com");
MODULE_DESCRIPTION("DigiCert FIPS Crypto Module");
MODULE_LICENSE("DIGICERT INC");

#ifndef __DISABLE_DIGICERT_INIT__
extern MSTATUS CRYPTO_DIGI_init(void);
extern MSTATUS CRYPTO_DIGI_free(void);
#endif

static int
mss_crypto_init(void)
{
    int status = 0;
    /*  */
    return status;

}
static void __exit
mss_crypto_fini(void)
{
    /* */
}

#ifdef __ENABLE_DIGICERT_FIPS_AES__
EXPORT_SYMBOL(AESCCM_decrypt);
EXPORT_SYMBOL(AESCCM_encrypt);
EXPORT_SYMBOL(AESCCM_createCtx);
EXPORT_SYMBOL(AESCCM_deleteCtx);
EXPORT_SYMBOL(AESCCM_clone);
EXPORT_SYMBOL(AESCCM_cipher);
EXPORT_SYMBOL(AESCMAC_final);
EXPORT_SYMBOL(AESCMAC_init);
EXPORT_SYMBOL(AESCMAC_update);
EXPORT_SYMBOL(AES_EAX_final);
EXPORT_SYMBOL(AES_EAX_init);
EXPORT_SYMBOL(AES_EAX_updateHeader);
EXPORT_SYMBOL(AES_XCBC_MAC_96_final);
EXPORT_SYMBOL(AES_XCBC_MAC_96_init);
EXPORT_SYMBOL(AES_XCBC_MAC_96_update);
EXPORT_SYMBOL(CreateAESCFBCtx);
EXPORT_SYMBOL(CreateAESCTRCtx);
EXPORT_SYMBOL(CreateAesCtrCtx);
EXPORT_SYMBOL(CreateAESCtx);
EXPORT_SYMBOL(CreateAESECBCtx);
EXPORT_SYMBOL(CreateAESOFBCtx);
EXPORT_SYMBOL(CreateAESXTSCtx);
EXPORT_SYMBOL(CloneAESCtx);
EXPORT_SYMBOL(CloneAESCTRCtx);
EXPORT_SYMBOL(DeleteAESCTRCtx);
EXPORT_SYMBOL(DeleteAESCtx);
EXPORT_SYMBOL(DeleteAESECBCtx);
EXPORT_SYMBOL(DeleteAESXTSCtx);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_AES__
EXPORT_SYMBOL(aesEncrypt);
EXPORT_SYMBOL(aesDecrypt);
EXPORT_SYMBOL(aesKeySetupEnc);
EXPORT_SYMBOL(aesKeySetupDec);

EXPORT_SYMBOL(DoAesCtr);
EXPORT_SYMBOL(DoAesCtrEx);
EXPORT_SYMBOL(DoAESCTR);
EXPORT_SYMBOL(DoAESECB);
EXPORT_SYMBOL(DoAES);
EXPORT_SYMBOL(DoAESXTS);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_3DES__
EXPORT_SYMBOL(Create2Key3DESCtx);
EXPORT_SYMBOL(Create3DESCtx);
EXPORT_SYMBOL(Clone3DESCtx);
EXPORT_SYMBOL(Delete3DESCtx);
EXPORT_SYMBOL(Do3DES);
EXPORT_SYMBOL(THREE_DES_encipher);
EXPORT_SYMBOL(THREE_DES_initKey);
#endif


#ifdef __FIPS_OPS_TEST__
EXPORT_SYMBOL(triggerRNGFail);
EXPORT_SYMBOL(triggerDRBGFail);
EXPORT_SYMBOL(triggerSeedFail);
EXPORT_SYMBOL(FIPS_triggerStartupFail);
EXPORT_SYMBOL(FIPS_resetStartupFail);
EXPORT_SYMBOL(resetRNGFail);
EXPORT_SYMBOL(resetDRBGFail);
EXPORT_SYMBOL(resetSeedFail);
#endif

#ifdef __ENABLE_FIPS_POWERUP_TEST__
EXPORT_SYMBOL(FIPS_getDefaultConfig);
EXPORT_SYMBOL(FIPS_powerupSelfTestEx);
#endif

#ifdef __ENABLE_DIGICERT_GCM_256B__
EXPORT_SYMBOL(GCM_createCtx_256b);
EXPORT_SYMBOL(GCM_deleteCtx_256b);
EXPORT_SYMBOL(GCM_final_256b);
EXPORT_SYMBOL(GCM_init_256b);
EXPORT_SYMBOL(GCM_clone_256b);
EXPORT_SYMBOL(GCM_cipher_256b);
EXPORT_SYMBOL(GCM_update_decrypt_256b);
EXPORT_SYMBOL(GCM_update_encrypt_256b);
#endif


#ifdef __ENABLE_DIGICERT_GCM_4K__
EXPORT_SYMBOL(GCM_createCtx_4k);
EXPORT_SYMBOL(GCM_deleteCtx_4k);
EXPORT_SYMBOL(GCM_final_4k);
EXPORT_SYMBOL(GCM_init_4k);
EXPORT_SYMBOL(GCM_clone_4k);
EXPORT_SYMBOL(GCM_cipher_4k);
EXPORT_SYMBOL(GCM_update_decrypt_4k);
EXPORT_SYMBOL(GCM_update_encrypt_4k);
#endif


#ifdef __ENABLE_DIGICERT_GCM_64K__
EXPORT_SYMBOL(GCM_createCtx_64k);
EXPORT_SYMBOL(GCM_deleteCtx_64k);
EXPORT_SYMBOL(GCM_final_64k);
EXPORT_SYMBOL(GCM_init_64k);
EXPORT_SYMBOL(GCM_clone_64k);
EXPORT_SYMBOL(GCM_cipher_64k);
EXPORT_SYMBOL(GCM_update_decrypt_64k);
EXPORT_SYMBOL(GCM_update_encrypt_64k);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_HMAC__
EXPORT_SYMBOL(HmacCreate);
EXPORT_SYMBOL(HmacDelete);
EXPORT_SYMBOL(HmacFinal);
EXPORT_SYMBOL(HmacKey);
EXPORT_SYMBOL(HMAC_SHA1);
EXPORT_SYMBOL(HMAC_SHA1_quick);
EXPORT_SYMBOL(HMAC_MD5_quick);
EXPORT_SYMBOL(HmacUpdate);
EXPORT_SYMBOL(HmacQuickerEx);
EXPORT_SYMBOL(HmacQuickerInlineEx);
EXPORT_SYMBOL(HmacQuickerInline);
EXPORT_SYMBOL(HmacQuicker);
EXPORT_SYMBOL(HmacQuickEx);
EXPORT_SYMBOL(HmacQuick);
#endif

#if (defined(__ENABLE_DIGICERT_MD2__))
EXPORT_SYMBOL(MD2Final);
EXPORT_SYMBOL(MD2Init);
EXPORT_SYMBOL(MD2Update);
#endif

#if (defined(__ENABLE_DIGICERT_MD4__))
EXPORT_SYMBOL(MD4Final);
EXPORT_SYMBOL(MD4Init);
EXPORT_SYMBOL(MD4Update);
EXPORT_SYMBOL(MD5Final_m);
EXPORT_SYMBOL(MD5Init_m);
EXPORT_SYMBOL(MD5Update_m);
EXPORT_SYMBOL(MD5_completeDigest);
#endif

#if (defined(__ENABLE_DIGICERT_RNG_DRBG_CTR__))
EXPORT_SYMBOL(RNG_SEED_initDepotState);
EXPORT_SYMBOL(RNG_SEED_freeDepotState);
EXPORT_SYMBOL(RNG_SEED_extractDepotBits);
EXPORT_SYMBOL(DIGICERT_addEntropyBit);
EXPORT_SYMBOL(DIGICERT_addEntropy32Bits);
#endif
#if (defined(__ENABLE_DIGICERT_RNG_DRBG_CTR__))
EXPORT_SYMBOL(NIST_CTRDRBG_deleteContext);
EXPORT_SYMBOL(NIST_CTRDRBG_generate);
EXPORT_SYMBOL(NIST_CTRDRBG_newContext);
EXPORT_SYMBOL(NIST_CTRDRBG_reseed);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_RANDOM__))
EXPORT_SYMBOL(RANDOM_acquireContextEx);
EXPORT_SYMBOL(RANDOM_acquireContext);
EXPORT_SYMBOL(RANDOM_addEntropyBit);
EXPORT_SYMBOL(RANDOM_newFIPS186Context);
EXPORT_SYMBOL(RANDOM_numberGenerator);
EXPORT_SYMBOL(RANDOM_releaseContext);
EXPORT_SYMBOL(RANDOM_setEntropySource);
EXPORT_SYMBOL(RANDOM_rngFun);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA1__))
EXPORT_SYMBOL(SHA1_allocDigest);
EXPORT_SYMBOL(SHA1_completeDigest);
EXPORT_SYMBOL(SHA1_finalDigest);
EXPORT_SYMBOL(SHA1_freeDigest);
EXPORT_SYMBOL(SHA1_initDigest);
EXPORT_SYMBOL(SHA1_updateDigest);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA256__))
EXPORT_SYMBOL(SHA224_completeDigest);
EXPORT_SYMBOL(SHA224_finalDigest);
EXPORT_SYMBOL(SHA224_initDigest);
EXPORT_SYMBOL(SHA256_allocDigest);
EXPORT_SYMBOL(SHA256_completeDigest);
EXPORT_SYMBOL(SHA256_finalDigest);
EXPORT_SYMBOL(SHA256_freeDigest);
EXPORT_SYMBOL(SHA256_initDigest);
EXPORT_SYMBOL(SHA256_updateDigest);
EXPORT_SYMBOL(SHA384_completeDigest);
EXPORT_SYMBOL(SHA384_finalDigest);
EXPORT_SYMBOL(SHA384_initDigest);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA512__))
EXPORT_SYMBOL(SHA512_allocDigest);
EXPORT_SYMBOL(SHA512_completeDigest);
EXPORT_SYMBOL(SHA512_finalDigest);
EXPORT_SYMBOL(SHA512_freeDigest);
EXPORT_SYMBOL(SHA512_initDigest);
EXPORT_SYMBOL(SHA512_updateDigest);
#endif

EXPORT_SYMBOL(DIGICERT_readVersion);
#ifndef __DISABLE_DIGICERT_INIT__
EXPORT_SYMBOL(CRYPTO_DIGI_init);
EXPORT_SYMBOL(CRYPTO_DIGI_free);
#endif

EXPORT_SYMBOL(g_pRandomContext);

EXPORT_SYMBOL(VLONG_compareSignedVlongs);
EXPORT_SYMBOL(VLONG_freeVlongQueue);
EXPORT_SYMBOL(VLONG_makeVlongFromVlong);

module_init(mss_crypto_init);
module_exit(mss_crypto_fini);
