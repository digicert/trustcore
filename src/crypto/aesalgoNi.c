/*
 * aesalgoNi.c
 *
 * AES-NI Implementation
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__AES_NI__) && !defined(__DISABLE_AES_CIPHERS__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../mocana_crypto/aesalgo.h"
#include "../mocana_crypto/aes.h"

/* AES-NI */
#include <string.h>
#include <wmmintrin.h>


#define AES_128_key_exp(K, RCON) \
      aes_128_key_expansion(K, _mm_aeskeygenassist_si128(K, RCON))


#define AES_192_key_exp(RCON, EK_OFF)                         \
   aes_192_key_expansion(&K0, &K1,                            \
                         _mm_aeskeygenassist_si128(K1, RCON), \
                         (ubyte4*)&sk[EK_OFF], EK_OFF == 48)

#define AES_ENC_4_ROUNDS(K)                     \
   do                                           \
      {                                         \
      B0 = _mm_aesenc_si128(B0, K);             \
      B1 = _mm_aesenc_si128(B1, K);             \
      B2 = _mm_aesenc_si128(B2, K);             \
      B3 = _mm_aesenc_si128(B3, K);             \
      } while(0)

#define AES_ENC_4_LAST_ROUNDS(K)                \
   do                                           \
      {                                         \
      B0 = _mm_aesenclast_si128(B0, K);         \
      B1 = _mm_aesenclast_si128(B1, K);         \
      B2 = _mm_aesenclast_si128(B2, K);         \
      B3 = _mm_aesenclast_si128(B3, K);         \
      } while(0)

#define AES_DEC_4_ROUNDS(K)                     \
   do                                           \
      {                                         \
      B0 = _mm_aesdec_si128(B0, K);             \
      B1 = _mm_aesdec_si128(B1, K);             \
      B2 = _mm_aesdec_si128(B2, K);             \
      B3 = _mm_aesdec_si128(B3, K);             \
      } while(0)

#define AES_DEC_4_LAST_ROUNDS(K)                \
   do                                           \
      {                                         \
      B0 = _mm_aesdeclast_si128(B0, K);         \
      B1 = _mm_aesdeclast_si128(B1, K);         \
      B2 = _mm_aesdeclast_si128(B2, K);         \
      B3 = _mm_aesdeclast_si128(B3, K);         \
      } while(0)


/*------------------------------------------------------------------*/

#define GETU32( pt) (((ubyte4)(pt)[0] << 24) ^ ((ubyte4)(pt)[1] << 16) ^ ((ubyte4)(pt)[2] <<  8) ^ ((ubyte4)(pt)[3]))
#define PUTU32( ct, st) { (ct)[0] = (ubyte)((st) >> 24); (ct)[1] = (ubyte)((st) >> 16); (ct)[2] = (ubyte)((st) >>  8); (ct)[3] = (ubyte)(st); }

/*------------------------------------------------------------------*/

__m128i aes_128_key_expansion(__m128i key, __m128i key_with_rcon)
{
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3,3,3,3));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   return _mm_xor_si128(key, key_with_rcon);
}

void aes_192_key_expansion(__m128i* K1, __m128i* K2, __m128i key2_with_rcon,
                           ubyte4 out[], sbyte last)
{
   __m128i key1 = *K1;
   __m128i key2 = *K2;

   key2_with_rcon  = _mm_shuffle_epi32(key2_with_rcon, _MM_SHUFFLE(1,1,1,1));
   key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
   key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
   key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
   key1 = _mm_xor_si128(key1, key2_with_rcon);

   *K1 = key1;
   _mm_storeu_si128((__m128i*)out, key1);

   if(last)
      return;

   key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
   key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3,3,3,3)));

   *K2 = key2;
   out[4] = _mm_cvtsi128_si32(key2);
   out[5] = _mm_cvtsi128_si32(_mm_srli_si128(key2, 4));
}

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
__m128i aes_256_key_expansion(__m128i key, __m128i key2)
{
   __m128i key_with_rcon = _mm_aeskeygenassist_si128(key2, 0x00);
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2,2,2,2));

   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   return _mm_xor_si128(key, key_with_rcon);
}


/*
* AES-128 Key Schedule
*/
void key_schedule128(const ubyte key[], ubyte4 rk[], sbyte flag)
{

   __m128i K0  = _mm_loadu_si128((const __m128i*)(key));
   __m128i K1  = AES_128_key_exp(K0, 0x01);
   __m128i K2  = AES_128_key_exp(K1, 0x02);
   __m128i K3  = AES_128_key_exp(K2, 0x04);
   __m128i K4  = AES_128_key_exp(K3, 0x08);
   __m128i K5  = AES_128_key_exp(K4, 0x10);
   __m128i K6  = AES_128_key_exp(K5, 0x20);
   __m128i K7  = AES_128_key_exp(K6, 0x40);
   __m128i K8  = AES_128_key_exp(K7, 0x80);
   __m128i K9  = AES_128_key_exp(K8, 0x1B);
   __m128i K10 = AES_128_key_exp(K9, 0x36);

   if (flag == TRUE)
   {
       __m128i* EK_mm = (__m128i*)&rk[0];
       _mm_storeu_si128(EK_mm     , K0);
       _mm_storeu_si128(EK_mm +  1, K1);
       _mm_storeu_si128(EK_mm +  2, K2);
       _mm_storeu_si128(EK_mm +  3, K3);
       _mm_storeu_si128(EK_mm +  4, K4);
       _mm_storeu_si128(EK_mm +  5, K5);
       _mm_storeu_si128(EK_mm +  6, K6);
       _mm_storeu_si128(EK_mm +  7, K7);
       _mm_storeu_si128(EK_mm +  8, K8);
       _mm_storeu_si128(EK_mm +  9, K9);
       _mm_storeu_si128(EK_mm + 10, K10);
   }
   else
   {
       /* Now generate decryption keys */
       __m128i* DK_mm = (__m128i*)&rk[0];
       _mm_storeu_si128(DK_mm     , K10);
       _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K9));
       _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K8));
       _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K7));
       _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K6));
       _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K5));
       _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K4));
       _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K3));
       _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K2));
       _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K1));
       _mm_storeu_si128(DK_mm + 10, K0);
   }
}

/*
* AES-192 Key Schedule
*/
void key_schedule192(const ubyte key[], ubyte4 rk[], sbyte flag)
{
    ubyte4 sk[13*4];
    const __m128i* EK_mm = (const __m128i*)&sk[0];
    __m128i K0 = _mm_loadu_si128((const __m128i*)(key));
    __m128i K1 = _mm_loadu_si128((const __m128i*)(key + 8));
    K1 = _mm_srli_si128(K1, 8);

    memcpy((void *)&sk[0], &key[0], 24);


    AES_192_key_exp(0x01, 6);
    AES_192_key_exp(0x02, 12);
    AES_192_key_exp(0x04, 18);
    AES_192_key_exp(0x08, 24);
    AES_192_key_exp(0x10, 30);
    AES_192_key_exp(0x20, 36);
    AES_192_key_exp(0x40, 42);
    AES_192_key_exp(0x80, 48);

   /* Now generate decryption keys */
    if (flag == TRUE)
    {
        __m128i* EK_mmt = (__m128i*)&rk[0];
        _mm_storeu_si128(EK_mmt, EK_mm[0]);
        _mm_storeu_si128(EK_mmt + 1, EK_mm[1]);
        _mm_storeu_si128(EK_mmt + 2, EK_mm[2]);
        _mm_storeu_si128(EK_mmt + 3, EK_mm[3]);
        _mm_storeu_si128(EK_mmt + 4, EK_mm[4]);
        _mm_storeu_si128(EK_mmt + 5, EK_mm[5]);
        _mm_storeu_si128(EK_mmt + 6, EK_mm[6]);
        _mm_storeu_si128(EK_mmt + 7, EK_mm[7]);
        _mm_storeu_si128(EK_mmt + 8, EK_mm[8]);
        _mm_storeu_si128(EK_mmt + 9, EK_mm[9]);
        _mm_storeu_si128(EK_mmt + 10, EK_mm[10]);
        _mm_storeu_si128(EK_mmt + 11, EK_mm[11]);
        _mm_storeu_si128(EK_mmt + 12, EK_mm[12]);       
    }
    else
    {
        __m128i* DK_mm = (__m128i*)&rk[0];
        _mm_storeu_si128(DK_mm     , EK_mm[12]);
        _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(EK_mm[11]));
        _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(EK_mm[10]));
        _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(EK_mm[9]));
        _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(EK_mm[8]));
        _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(EK_mm[7]));
        _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(EK_mm[6]));
        _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(EK_mm[5]));
        _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(EK_mm[4]));
        _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(EK_mm[3]));
        _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(EK_mm[2]));
        _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(EK_mm[1]));
        _mm_storeu_si128(DK_mm + 12, EK_mm[0]);
    }
}

/*
* AES-256 Key Schedule
*/
void key_schedule256(const ubyte key[], ubyte4 rk[], sbyte flag)
{
   __m128i K0 = _mm_loadu_si128((const __m128i*)(key));
   __m128i K1 = _mm_loadu_si128((const __m128i*)(key + 16));

   __m128i K2 = aes_128_key_expansion(K0, _mm_aeskeygenassist_si128(K1, 0x01));
   __m128i K3 = aes_256_key_expansion(K1, K2);

   __m128i K4 = aes_128_key_expansion(K2, _mm_aeskeygenassist_si128(K3, 0x02));
   __m128i K5 = aes_256_key_expansion(K3, K4);

   __m128i K6 = aes_128_key_expansion(K4, _mm_aeskeygenassist_si128(K5, 0x04));
   __m128i K7 = aes_256_key_expansion(K5, K6);

   __m128i K8 = aes_128_key_expansion(K6, _mm_aeskeygenassist_si128(K7, 0x08));
   __m128i K9 = aes_256_key_expansion(K7, K8);

   __m128i K10 = aes_128_key_expansion(K8, _mm_aeskeygenassist_si128(K9, 0x10));
   __m128i K11 = aes_256_key_expansion(K9, K10);

   __m128i K12 = aes_128_key_expansion(K10, _mm_aeskeygenassist_si128(K11, 0x20));
   __m128i K13 = aes_256_key_expansion(K11, K12);

   __m128i K14 = aes_128_key_expansion(K12, _mm_aeskeygenassist_si128(K13, 0x40));

   if (flag == TRUE)
   {
       __m128i* EK_mm = (__m128i*)&rk[0];
       _mm_storeu_si128(EK_mm     , K0);
       _mm_storeu_si128(EK_mm +  1, K1);
       _mm_storeu_si128(EK_mm +  2, K2);
       _mm_storeu_si128(EK_mm +  3, K3);
       _mm_storeu_si128(EK_mm +  4, K4);
       _mm_storeu_si128(EK_mm +  5, K5);
       _mm_storeu_si128(EK_mm +  6, K6);
       _mm_storeu_si128(EK_mm +  7, K7);
       _mm_storeu_si128(EK_mm +  8, K8);
       _mm_storeu_si128(EK_mm +  9, K9);
       _mm_storeu_si128(EK_mm + 10, K10);
       _mm_storeu_si128(EK_mm + 11, K11);
       _mm_storeu_si128(EK_mm + 12, K12);
       _mm_storeu_si128(EK_mm + 13, K13);
       _mm_storeu_si128(EK_mm + 14, K14);
   }
   else
   {
       /* Now generate decryption keys */
       __m128i* DK_mm = (__m128i*)&rk[0];
       _mm_storeu_si128(DK_mm     , K14);
       _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K13));
       _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K12));
       _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K11));
       _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K10));
       _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K9));
       _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K8));
       _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K7));
       _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K6));
       _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K5));
       _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(K4));
       _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(K3));
       _mm_storeu_si128(DK_mm + 12, _mm_aesimc_si128(K2));
       _mm_storeu_si128(DK_mm + 13, _mm_aesimc_si128(K1));
       _mm_storeu_si128(DK_mm + 14, K0);
   }
}

/*------------------------------------------------------------------*/

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return  the number of rounds for the given cipher key size.
 */
extern sbyte4
aesKeySetupEnc(ubyte4 rk[/*4*(Nr + 1)*/], const ubyte cipherKey[], sbyte4 keyBits)
{
    switch (keyBits)
    {
        case 128:
            key_schedule128(cipherKey, rk, TRUE);
            return 10;
    
        case 192:
            key_schedule192(cipherKey, rk, TRUE);
            return 12;

        case 256:
            key_schedule256(cipherKey, rk, TRUE);
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
extern sbyte4
aesKeySetupDec(ubyte4 rk[/*4*(Nr + 1)*/], const ubyte cipherKey[], sbyte4 keyBits)
{
    switch (keyBits)
    {
        case 128:
            key_schedule128(cipherKey, rk, FALSE);
            return 10;
    
        case 192:
            key_schedule192(cipherKey, rk, FALSE);
            return 12;

        case 256:
            key_schedule256(cipherKey, rk, FALSE);
            return 14;
        default:
            return 0;
    }
}


/*------------------------------------------------------------------*/

static inline void
aesNiEncrypt(sbyte4 Nr, const ubyte pt[16], ubyte ct[16], const __m128i* K)
{
    const __m128i* in_mm = (const __m128i*)pt;
    __m128i* out_mm = (__m128i*)ct;
    __m128i B;
    
    B = _mm_loadu_si128(in_mm);

    B = _mm_xor_si128(B, K[0]);

    B = _mm_aesenc_si128(B, K[1]);
    B = _mm_aesenc_si128(B, K[2]);
    B = _mm_aesenc_si128(B, K[3]);
    B = _mm_aesenc_si128(B, K[4]);
    B = _mm_aesenc_si128(B, K[5]);
    B = _mm_aesenc_si128(B, K[6]);
    B = _mm_aesenc_si128(B, K[7]);
    B = _mm_aesenc_si128(B, K[8]);
    B = _mm_aesenc_si128(B, K[9]);
    switch (Nr)
    {
        case 10:
            B = _mm_aesenclast_si128(B, K[10]);
            break;
        case 12:
            B = _mm_aesenc_si128(B, K[10]);
            B = _mm_aesenc_si128(B, K[11]);
            B = _mm_aesenclast_si128(B, K[12]);
            break;
        case 14:
            B = _mm_aesenc_si128(B, K[10]);
            B = _mm_aesenc_si128(B, K[11]);
            B = _mm_aesenc_si128(B, K[12]);
            B = _mm_aesenc_si128(B, K[13]);
            B = _mm_aesenclast_si128(B, K[14]);
            break;
    }
    _mm_storeu_si128(out_mm, B);

}


/*------------------------------------------------------------------*/

static inline void
aesNiDecrypt(sbyte4 Nr, ubyte *ct, const ubyte *pt, const __m128i* K, sbyte4 blocks)
{
    const __m128i* in_mm = (const __m128i*)ct;
    __m128i* out_mm = (__m128i*)pt;
    __m128i B; 
    
    while(blocks >= 4)
    {
        __m128i B0 = _mm_loadu_si128(in_mm + 0);
        __m128i B1 = _mm_loadu_si128(in_mm + 1);
        __m128i B2 = _mm_loadu_si128(in_mm + 2);
        __m128i B3 = _mm_loadu_si128(in_mm + 3);

        B0 = _mm_xor_si128(B0, K[0]);
        B1 = _mm_xor_si128(B1, K[0]);
        B2 = _mm_xor_si128(B2, K[0]);
        B3 = _mm_xor_si128(B3, K[0]);

        AES_DEC_4_ROUNDS(K[1]);
        AES_DEC_4_ROUNDS(K[2]);
        AES_DEC_4_ROUNDS(K[3]);
        AES_DEC_4_ROUNDS(K[4]);
        AES_DEC_4_ROUNDS(K[5]);
        AES_DEC_4_ROUNDS(K[6]);
        AES_DEC_4_ROUNDS(K[7]);
        AES_DEC_4_ROUNDS(K[8]);
        AES_DEC_4_ROUNDS(K[9]);
        switch (Nr)
        {
            case 10:
                AES_DEC_4_LAST_ROUNDS(K[10]);
                break;
            case 12:
                AES_DEC_4_ROUNDS(K[10]);
                AES_DEC_4_ROUNDS(K[11]);
                AES_DEC_4_LAST_ROUNDS(K[12]);
                break;
            case 14:
                AES_DEC_4_ROUNDS(K[10]);
                AES_DEC_4_ROUNDS(K[11]);
                AES_DEC_4_ROUNDS(K[12]);
                AES_DEC_4_ROUNDS(K[13]);
                AES_DEC_4_LAST_ROUNDS(K[14]);
                break;
        }
        

        _mm_storeu_si128(out_mm + 0, B0);
        _mm_storeu_si128(out_mm + 1, B1);
        _mm_storeu_si128(out_mm + 2, B2);
        _mm_storeu_si128(out_mm + 3, B3);

        blocks -= 4;
        in_mm += 4;
        out_mm += 4;
    }
    
    /* for(i = 0; i != blocks; ++i) */
    while (blocks > 0)
    {

        B = _mm_loadu_si128(in_mm++);
        B = _mm_xor_si128(B, K[0]);
        B = _mm_aesdec_si128(B, K[1]);
        B = _mm_aesdec_si128(B, K[2]);
        B = _mm_aesdec_si128(B, K[3]);
        B = _mm_aesdec_si128(B, K[4]);
        B = _mm_aesdec_si128(B, K[5]);
        B = _mm_aesdec_si128(B, K[6]);
        B = _mm_aesdec_si128(B, K[7]);
        B = _mm_aesdec_si128(B, K[8]);
        B = _mm_aesdec_si128(B, K[9]);
        switch (Nr)
        {
            case 10:
                B = _mm_aesdeclast_si128(B, K[10]);
                break;
            case 12:
                B = _mm_aesdec_si128(B, K[10]);
                B = _mm_aesdec_si128(B, K[11]);
                B = _mm_aesdeclast_si128(B, K[12]);
                break;
            case 14:
                B = _mm_aesdec_si128(B, K[10]);
                B = _mm_aesdec_si128(B, K[11]);
                B = _mm_aesdec_si128(B, K[12]);
                B = _mm_aesdec_si128(B, K[13]);
                B = _mm_aesdeclast_si128(B, K[14]);
                break;
        }
        _mm_storeu_si128(out_mm++, B);
        blocks--;
    }

}

/*------------------------------------------------------------------*/

static MSTATUS
aesLoadKey(ubyte4 rk[], sbyte4 Nr ,__m128i* K)
{
    const __m128i* key_mm = (const __m128i*)&rk[0];
    
    K[0]  = _mm_loadu_si128(key_mm);
    K[1]  = _mm_loadu_si128(key_mm+1);
    K[2]  = _mm_loadu_si128(key_mm+2);
    K[3]  = _mm_loadu_si128(key_mm+3);
    K[4]  = _mm_loadu_si128(key_mm+4);
    K[5]  = _mm_loadu_si128(key_mm+5);
    K[6]  = _mm_loadu_si128(key_mm+6);
    K[7]  = _mm_loadu_si128(key_mm+7);
    K[8]  = _mm_loadu_si128(key_mm+8);
    K[9]  = _mm_loadu_si128(key_mm+9);
    K[10]  = _mm_loadu_si128(key_mm+10);
    if (Nr > 10)
    {
	K[11] = _mm_loadu_si128(key_mm + 11);
	K[12] = _mm_loadu_si128(key_mm + 12);
    }
    if (Nr > 12)
    {
	K[13] = _mm_loadu_si128(key_mm + 13);
	K[14] = _mm_loadu_si128(key_mm + 14);
    }
    return OK;
}

extern void
aesEncrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, const ubyte pt[16], ubyte ct[16])
{
    __m128i K[15];
    aesLoadKey(rk, Nr, K);
    aesNiEncrypt(Nr, pt, ct, K);
}

extern void
aesDecrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, const ubyte pt[16], ubyte ct[16])
{
    __m128i K[15];
    aesLoadKey(rk, Nr, K);
    aesNiDecrypt(Nr, pt, ct, K, 1);
}


/*------------------------------------------------------------------*/

extern MSTATUS
AESALGO_blockEncrypt(aesCipherContext *pAesContext, ubyte* iv,
                     ubyte *input, sbyte4 inputLen, ubyte *outBuffer,
                     sbyte4 *pRetLength)
{
    sbyte4  i, numBlocks;
    ubyte4  block[AES_BLOCK_SIZE/4];   /* use a ubyte4[] for alignment */
    MSTATUS status = OK;
    __m128i K[15];
    
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

    if (0 >= inputLen)
    {
        *pRetLength = 0;
        goto exit; /* nothing to do */
    }

    numBlocks = inputLen/128;
    aesLoadKey(pAesContext->rk, pAesContext->Nr,&K[0]);
    
    switch (pAesContext->mode)
    {
        case MODE_ECB:
        {
            for (i = numBlocks; i > 0; i--)
            {
                aesNiEncrypt(pAesContext->Nr, input, outBuffer, K);
                input += AES_BLOCK_SIZE;
                outBuffer += AES_BLOCK_SIZE;
            }
            break;
        }

        case MODE_CBC:
        {
#if __DIGICERT_MAX_INT__ == 64
            if ( (((ubyte8)input) | ((ubyte8)iv)) & 3) /* one or both are not aligned on 4 byte boundary */
#else
            if ( (((ubyte4)input) | ((ubyte4)iv)) & 3) /* one or both are not aligned on 4 byte boundary */
#endif
            {
                for (i = numBlocks; i > 0; i--)
                {
                    sbyte4 j;
                    for (j = 0; j < AES_BLOCK_SIZE; ++j)
                    {
                        ((ubyte*)block)[j] = (input[j] ^ iv[j]);
                    }
                    aesNiEncrypt(pAesContext->Nr, (ubyte*) block, outBuffer, K);
                    memcpy(iv, outBuffer, AES_BLOCK_SIZE);
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

                    aesNiEncrypt(pAesContext->Nr, (ubyte*) block, outBuffer, K);
                    memcpy(iv, outBuffer, AES_BLOCK_SIZE);
                    input += AES_BLOCK_SIZE;
                    outBuffer += AES_BLOCK_SIZE;
                }
            }
            break;
        }

        case MODE_CFB128:
        {
            sbyte4 j;
            ubyte *tmpBlock;

            tmpBlock = (ubyte *) block;

            for (i = numBlocks; i > 0; i--) {
                aesNiEncrypt(pAesContext->Nr, iv, tmpBlock, K);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    iv[j] = input[j] ^ tmpBlock[j];

                }
                memcpy(outBuffer, iv, AES_BLOCK_SIZE);
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }


            break;
        }

        case MODE_OFB:
        {
            sbyte4 j;
            ubyte *tmpBlock;

            tmpBlock = (ubyte *) block;

            for (i = numBlocks; i > 0; i--) {
                aesNiEncrypt(pAesContext->Nr, iv, tmpBlock, K);
                memcpy(iv, tmpBlock, AES_BLOCK_SIZE);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    outBuffer[j] = input[j] ^ tmpBlock[j];

                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
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

extern MSTATUS
AESALGO_blockDecrypt(aesCipherContext *pAesContext, ubyte* iv,
                     ubyte *input, sbyte4 inputLen, ubyte *outBuffer,
                     sbyte4 *pRetLength)
{
    sbyte4  i, numBlocks, totalLenToDecrypt;
    ubyte*   decBuf = NULL;
	const ubyte4 decBufSize = 4096;
    MSTATUS status = OK;
    __m128i K[15];

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

    if (0 >= inputLen)
    {
        *pRetLength = 0; /* nothing to do */
        goto exit;
    }

    numBlocks = inputLen/128;
    
    aesLoadKey(pAesContext->rk, pAesContext->Nr,&K[0]);
    
    switch (pAesContext->mode)
    {
        case MODE_ECB:
        {
            aesNiDecrypt(pAesContext->Nr, input, outBuffer, K, numBlocks);
            for (i = numBlocks; i > 0; i--)
            {
                input += AES_BLOCK_SIZE;
                outBuffer += AES_BLOCK_SIZE;
            }
            break;
        }

        case MODE_CBC:
        {
	        if(NULL == (decBuf = MALLOC(decBufSize)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
			totalLenToDecrypt = inputLen;
			if ( ((ubyte4) iv) & 3)
            {
                __m128i* out_mm = (__m128i*)outBuffer;
                const __m128i* b = (const __m128i*)decBuf;
                __m128i B, I;
                I = _mm_loadu_si128((__m128i*)iv);
				while(totalLenToDecrypt > 0)
				{
					if (totalLenToDecrypt > (decBufSize*8))
					{
						numBlocks = (decBufSize*8)/128;
						totalLenToDecrypt = totalLenToDecrypt - (decBufSize*8);
					}
					else
					{
						numBlocks = totalLenToDecrypt/128;
						totalLenToDecrypt = 0;
					}
					b = (const __m128i*)decBuf;
					aesNiDecrypt(pAesContext->Nr, input, (ubyte*)decBuf, K, numBlocks);
					for (i = numBlocks; i > 0; i--)
					{
						B = _mm_loadu_si128(b);
						B = _mm_xor_si128(B , I);
						I = _mm_loadu_si128((__m128i*)input);
						_mm_storeu_si128(out_mm, B);
						input += AES_BLOCK_SIZE;
						out_mm++;
						b++;
					}					
				}
				_mm_storeu_si128((__m128i*)iv, I);
            }
            else
            {
                const __m128i* b = (const __m128i*)decBuf;
                __m128i* out_mm = (__m128i*)outBuffer;
                __m128i B, I;
				I = _mm_loadu_si128((__m128i*)iv);
				while(totalLenToDecrypt > 0)
				{
					if (totalLenToDecrypt > (decBufSize*8))
					{
						numBlocks = (decBufSize*8)/128;
						totalLenToDecrypt = totalLenToDecrypt - (decBufSize*8);
					}
					else
					{
						numBlocks = totalLenToDecrypt/128;
						totalLenToDecrypt = 0;
					}
					b = (const __m128i*)decBuf;
					aesNiDecrypt(pAesContext->Nr, input, (ubyte*) decBuf, K, numBlocks);
					for (i = numBlocks; i > 0; i--)
					{
						B = _mm_loadu_si128(b);
						B = _mm_xor_si128(B , I);
						I = _mm_loadu_si128((__m128i*)input);
						_mm_storeu_si128(out_mm, B);
						input += AES_BLOCK_SIZE;
						out_mm++;
						b++;
					}
                }
				_mm_storeu_si128((__m128i*)iv, I);
			}
			numBlocks = inputLen/128;
			FREE(decBuf);
            break;
        }

        case MODE_CFB128:
        {
            sbyte4 j;
            ubyte4 block[AES_BLOCK_SIZE/4];
            ubyte* tmpBlock = (ubyte*) block;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--) {
                aesNiEncrypt(pAesContext->Nr, iv, (ubyte*)tmpBlock, K);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    iv[j] = input[j];   /* save curr input for next iv. */
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            break;
        }

        case MODE_OFB:
        {
            sbyte4 j;
            ubyte4 block[AES_BLOCK_SIZE/4];
            ubyte* tmpBlock = (ubyte*) block;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--) {
                aesNiEncrypt(pAesContext->Nr, iv, (ubyte*)tmpBlock, K);
                memcpy(iv, tmpBlock, AES_BLOCK_SIZE);
                for (j = 0; j< AES_BLOCK_SIZE; j++) {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
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

#endif


