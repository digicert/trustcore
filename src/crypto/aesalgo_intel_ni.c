/*
 * aesalgo_intel_ni.c
 *
 * AES NI Implementation Using Intel Provided assembly code
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
@file       aesalgo_intel_ni.c
@brief      C Source file for NanoCrypto AES-NI symmetric cipher functions
            in ECB, CBC, CTR, CFB, and OFB modes.

@details    This file contains the NanoCrypto functions for AES-NI symmetric cipher
            functions.  This functions replace the default AES functions when
            __ENABLE_DIGICERT_AES_NI__ or __ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ are
            defined.

@copydoc    overview_aes_ccm

@flags
To enable any of the functions in aesalgo_intel_ni.{c,h}, the following flags must \b not
be defined in moptions.h:
+ \c \__DISABLE_AES_CIPHERS__
+ \c \__AES_HARDWARE_CIPHER__

To enable any of the functions in aesalgo_intel_ni.{c,h}, one and only one of the following
flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_AES_NI__
+ \c \__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__

@filedoc    aesalgo_intel_ni.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_INTERNAL__

/*------------------------------------------------------------------*/
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if ((defined(__ENABLE_DIGICERT_AES_NI__)) || \
     (defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))) && \
	 (!defined(__DISABLE_AES_CIPHERS__))

  #if (defined(__ENABLE_DIGICERT_AES_NI__)) && \
      (defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
  #error Invalid combination, __ENABLE_DIGICERT_AES_NI__ and \
         __ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ are mutually exclusive
  #endif
#endif

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#include "../crypto/aesalgo_intel_ni.h"

/* Intel AES-NI */
#include "../crypto/intel_aes_ni/include/iaes_asm_interface.h"

#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) && \
         defined(__DBG_VERBOSE_PAA__) )
#include "../crypto/fips.h"
FIPS_TESTLOG_IMPORT;
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
/* For FIPS: Enable the ability to forcefully disable AES-NI support even if the process supports it. */
static intBoolean is_aesNI_forced_off = FALSE;
#endif

#if defined(__ENABLE_DIGICERT_AES_NI__) || \
    defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__)

static intBoolean is_aesNI_supported = FALSE;
static intBoolean aesNI_has_been_checked = FALSE;

#if !defined (__RTOS_LINUX__) && !defined (__RTOS_OSX__)

#include <intrin.h>

#else

static void __cpuid(unsigned int where[4], unsigned int leaf) {
  asm volatile("cpuid":"=a"(*where),"=b"(*(where+1)), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
  return;
}
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
/* For FIPS: Enable the ability to forcefully disable AES-NI support even if the process supports it. */
/*------------------------------------------------------------------*/
/*
 * reset_to_default_aes_instructions()
 *   allow check_for_aes_instructions() to return real chip AES instruction support.
 */
MOC_EXTERN  void reset_to_default_aes_instructions(void)
{
	is_aesNI_forced_off = FALSE;
}
/*------------------------------------------------------------------*/
/*
 * force_disable_aes_instructions()
 *   force check_for_aes_instructions() to return FALSE to disable PAA for testing.
 */
MOC_EXTERN  void force_disable_aes_instructions(void)
{
	is_aesNI_forced_off = TRUE;
}
/*------------------------------------------------------------------*/
/*
 * is_force_disable_aes_instructions()
 *   return TRUE if AES-NI is forcefully disabled.
 */
MOC_EXTERN  intBoolean is_force_disable_aes_instructions(void)
{
	return is_aesNI_forced_off;
}

#endif

/*------------------------------------------------------------------*/
/*
 * check_for_aes_instructions()
 *   return TRUE if AES-NI is supported and FALSE if not supported
 */

MOC_EXTERN intBoolean
check_for_aes_instructions(void)
{
	unsigned int cpuid_results[4];

	/* If we have already been here then don't do the check again */
	if (aesNI_has_been_checked)
		goto exit;

	is_aesNI_supported = FALSE;
	aesNI_has_been_checked = TRUE;
	/**/

	__cpuid(cpuid_results,1);

	if (cpuid_results[2] & AES_INSTRCTIONS_CPUID_BIT)
		is_aesNI_supported = TRUE;

exit:
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )

#if ( defined(__DBG_VERBOSE_PAA__) )
        if ((!is_aesNI_forced_off) && is_aesNI_supported)
        {
            FIPS_TESTLOG(1080, "FIPS PAA DEBUG: check_for_aes_instructions() returning TRUE.");
        }
        else
        {
            FIPS_TESTLOG(1081, "FIPS PAA DEBUG: check_for_aes_instructions() returning FALSE.");
        }
#endif

	return ((!is_aesNI_forced_off) && is_aesNI_supported);
#else
	return is_aesNI_supported;
#endif
}

/*------------------------------------------------------------------*/

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return  the number of rounds for the given cipher key size.
 */
MOC_EXTERN sbyte4
aesNiKeySetupEnc(ubyte4 rk[/*4*(Nr + 1)*/], ubyte cipherKey[], sbyte4 keyBits)
{
    switch (keyBits)
    {
        case 128:
            iEncExpandKey128(cipherKey, (ubyte*) rk);
            return 10;

        case 192:
            iEncExpandKey192(cipherKey, (ubyte*) rk);
            return 12;

        case 256:
            iEncExpandKey256(cipherKey, (ubyte*) rk);
           return 14;

        default:
            return 0;
    }
}


/*------------------------------------------------------------------*/

/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return  the number of rounds for the given cipher key size.
 */
MOC_EXTERN sbyte4
aesNiKeySetupDec(ubyte4 rk[/*4*(Nr + 1)*/], ubyte cipherKey[], sbyte4 keyBits)
{
    switch (keyBits)
    {
        case 128:
            iDecExpandKey128(cipherKey, (ubyte*) rk);
            return 10;

        case 192:
            iDecExpandKey192(cipherKey, (ubyte*) rk);
            return 12;

        case 256:
            iDecExpandKey256(cipherKey, (ubyte*) rk);
            return 14;

        default:
            return 0;
    }
}


/*------------------------------------------------------------------*/
/**
 * Encrypt using AES-ECB over any number of blocks
 */
MOC_EXTERN void
aesNiEncrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks)
{
	sAesData aesData;

	aesData.in_block = pt;
	aesData.out_block = ct;
	aesData.expanded_key = (ubyte*) rk;
	aesData.num_blocks = numBlocks;

	switch (Nr)
	{
		case 10:
    		iEnc128(&aesData);
			break;

		case 12:
    		iEnc192(&aesData);
			break;

		case 14:
    		iEnc256(&aesData);
			break;

		default:
    		iEnc128(&aesData);
			break;
	}
}

/*------------------------------------------------------------------*/
/**
 * Decrypt using AES-ECB over any number of blocks
 */
MOC_EXTERN void
aesNiDecrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* ct, ubyte* pt, ubyte4 numBlocks)
{
	sAesData aesData;

	aesData.in_block = ct;
	aesData.out_block = pt;
	aesData.expanded_key = (ubyte*) rk;
	aesData.num_blocks = numBlocks;

	switch (Nr)
	{
		case 10:
    		iDec128(&aesData);
			break;

		case 12:
    		iDec192(&aesData);
			break;

		case 14:
    		iDec256(&aesData);
			break;

		default:
    		iDec128(&aesData);
			break;
	}
}

/*------------------------------------------------------------------*/
/**
 * Encrypt or Decrypt using AES-CTR over any number of blocks
 */
MOC_EXTERN void
aesNiEncDecCTR(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks, ubyte* ic)
{
	sAesData aesData;

	aesData.in_block = pt;
	aesData.out_block = ct;
	aesData.expanded_key = (ubyte*) rk;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	switch (Nr)
	{
		case 10:
      		iEnc128_CTR(&aesData);
			break;

		case 12:
			iEnc192_CTR(&aesData);
			break;

		case 14:
			iEnc256_CTR(&aesData);
			break;

		default:
			iEnc128_CTR(&aesData);
			break;
	}
}

/*------------------------------------------------------------------*/
/**
 * Encrypt using AES-CBC over any number of blocks
 */
MOC_EXTERN void
aesNiEncryptCBC(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks, ubyte* iv)
{
	sAesData aesData;

	aesData.in_block = pt;
	aesData.out_block = ct;
	aesData.expanded_key = (ubyte*) rk;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	switch (Nr)
	{
		case 10:
    		iEnc128_CBC(&aesData);
			break;

		case 12:
    		iEnc192_CBC(&aesData);
			break;

		case 14:
    		iEnc256_CBC(&aesData);
			break;

		default:
    		iEnc128_CBC(&aesData);
			break;
	}
}

/**
 * Decrypt using AES-CBC over any number of blocks
 */
MOC_EXTERN void
aesNiDecryptCBC(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks, ubyte* iv)
{
	sAesData aesData;

	aesData.in_block = pt;
	aesData.out_block = ct;
	aesData.expanded_key = (ubyte*) rk;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	switch (Nr)
	{
		case 10:
    		iDec128_CBC(&aesData);
			break;

		case 12:
    		iDec192_CBC(&aesData);
			break;

		case 14:
    		iDec256_CBC(&aesData);
			break;

		default:
    		iDec128_CBC(&aesData);
			break;
	}
}

/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__

/**
 * Encrypt using AES-ECB over a single block
 */
MOC_EXTERN void
aesEncrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, const ubyte pt[16], ubyte ct[16])
{
	aesNiEncrypt(rk, Nr, (ubyte*)pt, ct, 1);
}

/*------------------------------------------------------------------*/
/**
 * Decrypt using AES-ECB over a single block
 */
MOC_EXTERN void
aesDecrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, const ubyte ct[16], ubyte pt[16])
{
	aesNiDecrypt(rk, Nr, (ubyte*)ct, pt, 1);
}


MOC_EXTERN sbyte4
aesKeySetupEnc(ubyte4 rk[/*4*(Nr + 1)*/], const ubyte cipherKey[], sbyte4 keyBits)
{
	return aesNiKeySetupEnc(rk, (ubyte*)cipherKey, keyBits);
}

MOC_EXTERN sbyte4
aesKeySetupDec(ubyte4 rk[/*4*(Nr + 1)*/], const ubyte cipherKey[], sbyte4 keyBits)
{
	return aesNiKeySetupDec(rk, (ubyte*)cipherKey, keyBits);
}

#endif

extern MSTATUS AESALGO_blockEncryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  ubyte* iv,
  ubyte *input,
  sbyte4 inputLen,
  ubyte *outBuffer,
  sbyte4 *pRetLength
  )
{
  /* Just call the Intel version.
   */
  return (AESALGO_blockEncrypt (
    pAesContext, iv, input, inputLen, outBuffer, pRetLength));
}

/*------------------------------------------------------------------*/
/**
@private
@internal
@todo_add_ask    (New in .c file since 5.3.1; labeled as "internal
                  prototypes" in aes.h)
@ingroup    aes_cbc_functions
*/
MOC_EXTERN MSTATUS
AESALGO_blockEncrypt(aesCipherContext *pAesContext, ubyte* iv,
                     ubyte *input, sbyte4 inputLen, ubyte *outBuffer,
                     sbyte4 *pRetLength)
{
    sbyte4  i, numBlocks;
    ubyte4  block[AES_BLOCK_SIZE/4];   /* use a ubyte4[] for alignment */
    MSTATUS status = OK;

    if ((NULL == pAesContext) || (NULL == input))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (FALSE == pAesContext->encrypt)
    {
        status = ERR_AES_BAD_OPERATION;
        goto exit;
    }

    /* AES_BLOCK_SIZE is in bytes, inputLen is in bits. */
    if (0 >= inputLen)
    {
        *pRetLength = 0;
        goto exit; /* nothing to do */
    }
    else if ( (MODE_ECB == pAesContext->mode || MODE_CBC == pAesContext->mode) && 0 != inputLen%(AES_BLOCK_SIZE*8) )
    {
        status = ERR_AES_BAD_LENGTH;
        *pRetLength = 0;
        goto exit;
    }

    numBlocks = inputLen/(AES_BLOCK_SIZE*8);

    switch (pAesContext->mode)
    {
        case MODE_ECB:
        {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
		if (check_for_aes_instructions())
#else
		if (is_aesNI_supported)
#endif
        	{
        		/* We have AESNI instructions */
        		aesNiEncrypt(pAesContext->rk, pAesContext->Nr, input, outBuffer, numBlocks);
        	}
        	else
        	{
        		for (i = numBlocks; i > 0; i--)
        		{
        			aesEncrypt(pAesContext->rk, pAesContext->Nr, input, outBuffer);
        			input += AES_BLOCK_SIZE;
        			outBuffer += AES_BLOCK_SIZE;
        		}
        	}
            break;
        }

        case MODE_CBC:
        {
            if ((NULL == iv))
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
		if (check_for_aes_instructions())
#else
		if (is_aesNI_supported)
#endif
            {
            	/* We have AESNI instructions */
           		aesNiEncryptCBC(pAesContext->rk, pAesContext->Nr, input, outBuffer, numBlocks, iv);
            }
           	else
           	{

#if __LONG_MAX__ == __INT_MAX__
           		if ( (((ubyte4)(uintptr)input) | ((ubyte4)(uintptr)iv)) & 3) /* one or both are not aligned on 4 byte boundary */
#else
           		if ( (((ubyte8)(uintptr)input) | ((ubyte8)(uintptr)iv)) & 3) /* one or both are not aligned on 4 byte boundary */
#endif
           		{
					for (i = numBlocks; i > 0; i--)
					{
						sbyte4 j;
						for (j = 0; j < AES_BLOCK_SIZE; ++j)
						{
							((ubyte*)block)[j] = (input[j] ^ iv[j]);
						}
						aesEncrypt(pAesContext->rk, pAesContext->Nr, (ubyte*) block, outBuffer);
						DIGI_MEMCPY(iv, outBuffer, AES_BLOCK_SIZE);
						input += AES_BLOCK_SIZE;
						outBuffer += AES_BLOCK_SIZE;
					}
           		}
				else /* assume we can use 4 bytes ops */
				{
					for (i = numBlocks; i > 0; i--)
					{
						block[0] = ((ubyte4*)input)[0] ^ ((ubyte4*)iv)[0];
						block[1] = ((ubyte4*)input)[1] ^ ((ubyte4*)iv)[1];
						block[2] = ((ubyte4*)input)[2] ^ ((ubyte4*)iv)[2];
						block[3] = ((ubyte4*)input)[3] ^ ((ubyte4*)iv)[3];

						aesEncrypt(pAesContext->rk, pAesContext->Nr, (ubyte*) block, outBuffer);
						DIGI_MEMCPY(iv, outBuffer, AES_BLOCK_SIZE);
						input += AES_BLOCK_SIZE;
						outBuffer += AES_BLOCK_SIZE;
					}
				}
           	}
            break;
        }

        case MODE_CFB128:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte*) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--) {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    iv[j] = input[j] ^ tmpBlock[j];
                }
                DIGI_MEMCPY(outBuffer, iv, AES_BLOCK_SIZE);
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        case MODE_OFB:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte *) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--) {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                DIGI_MEMCPY(iv, tmpBlock, AES_BLOCK_SIZE);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    outBuffer[j] = input[j] ^ tmpBlock[j];

                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        default:
        {
            status = ERR_AES_BAD_CIPHER_MODE;
            goto exit;
        }
    }

    *pRetLength = (128 * numBlocks);

exit:
    return status;

} /* AESALGO_blockEncrypt */


/*------------------------------------------------------------------*/

extern MSTATUS AESALGO_blockDecryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  ubyte* iv,
  ubyte *input,
  sbyte4 inputLen,
  ubyte *outBuffer,
  sbyte4 *pRetLength
  )
{
  /* Just call the Intel version.
   */
  return (AESALGO_blockDecrypt (
    pAesContext, iv, input, inputLen, outBuffer, pRetLength));
}

/**
@private
@internal
@todo_add_ask    (New in .c file since 5.3.1; labeled as "internal
                  prototypes" in aes.h)
@ingroup    aes_cbc_functions
*/
MOC_EXTERN MSTATUS
AESALGO_blockDecrypt(aesCipherContext *pAesContext, ubyte* iv,
                     ubyte *input, sbyte4 inputLen, ubyte *outBuffer,
                     sbyte4 *pRetLength)
{
    sbyte4  i, numBlocks;
    ubyte4  block[AES_BLOCK_SIZE/4];  /* use a ubyte4[] for alignment */
    MSTATUS status = OK;

    if ((NULL == pAesContext) || (NULL == input))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((pAesContext->mode != MODE_CFB1) && (pAesContext->encrypt))
    {
        status = ERR_AES_BAD_OPERATION;
        goto exit;
    }

    /* AES_BLOCK_SIZE is in bytes, inputLen is in bits. */
    if (0 >= inputLen)
    {
        *pRetLength = 0;
        goto exit; /* nothing to do */
    }
    else if ( (MODE_ECB == pAesContext->mode || MODE_CBC == pAesContext->mode) && 0 != inputLen%(AES_BLOCK_SIZE*8) )
    {
        status = ERR_AES_BAD_LENGTH;
        *pRetLength = 0;
        goto exit;
    }

    numBlocks = inputLen/(AES_BLOCK_SIZE*8);

    switch (pAesContext->mode)
    {
        case MODE_ECB:
        {
#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
		if (check_for_aes_instructions())
#else
		if (is_aesNI_supported)
#endif
        	{
        		aesNiDecrypt(pAesContext->rk, pAesContext->Nr, input, outBuffer, numBlocks);
        	}
        	else
        	{
				for (i = numBlocks; i > 0; i--)
				{
					aesDecrypt(pAesContext->rk, pAesContext->Nr, input, outBuffer);
					input += AES_BLOCK_SIZE;
					outBuffer += AES_BLOCK_SIZE;
				}
        	}
            break;
        }

        case MODE_CBC:
        {
        	if ((NULL == iv))
        	{
        		status = ERR_NULL_POINTER;
        	    goto exit;
        	}

#if (defined(__ENABLE_DIGICERT_FIPS_MODULE__) && \
	 defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
		if (check_for_aes_instructions())
#else
		if (is_aesNI_supported)
#endif
            {
           		aesNiDecryptCBC(pAesContext->rk, pAesContext->Nr, input, outBuffer, numBlocks, iv);
            }
           	else
           	{

#if __LONG_MAX__ == __INT_MAX__
           		if ( ((ubyte4) (uintptr)iv) & 3)
#else
           		if ( ((ubyte8) (uintptr)iv) & 3)
#endif
				{
					for (i = numBlocks; i > 0; i--)
					{
						sbyte4 j;

						aesDecrypt(pAesContext->rk, pAesContext->Nr, input, (ubyte*)block);
						for (j = 0; j < AES_BLOCK_SIZE; ++j)
						{
							((ubyte*)block)[j] ^= iv[j];
						}
						DIGI_MEMCPY(iv, input, AES_BLOCK_SIZE);
						DIGI_MEMCPY(outBuffer, block, AES_BLOCK_SIZE);
						input += AES_BLOCK_SIZE;
						outBuffer += AES_BLOCK_SIZE;
					}
				}
				else
				{
					for (i = numBlocks; i > 0; i--)
					{
						aesDecrypt(pAesContext->rk, pAesContext->Nr, input, (ubyte*) block);

						block[0] ^= ((ubyte4*)iv)[0];
						block[1] ^= ((ubyte4*)iv)[1];
						block[2] ^= ((ubyte4*)iv)[2];
						block[3] ^= ((ubyte4*)iv)[3];

						DIGI_MEMCPY(iv, input, AES_BLOCK_SIZE);
						DIGI_MEMCPY(outBuffer, block, AES_BLOCK_SIZE);
						input += AES_BLOCK_SIZE;
						outBuffer += AES_BLOCK_SIZE;
					}
				}
           	}
            break;
        }

        case MODE_CFB128:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte *) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--) {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    iv[j] = input[j];   /* save curr input for next iv. */
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        case MODE_OFB:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte *) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--) {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                DIGI_MEMCPY(iv, tmpBlock, AES_BLOCK_SIZE);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        default:
        {
            status = ERR_AES_BAD_OPERATION;
            break;
        }
    }

    *pRetLength = (128 * numBlocks);

exit:
    return status;

} /* AESALGO_blockDecrypt */

#endif /* defined(__ENABLE_DIGICERT_AES_NI__) && !defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) */
