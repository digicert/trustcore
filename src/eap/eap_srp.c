/**
 * @file  eap_srp.c
 * @brief EAP-SRP method implementation
 *
 * @details    Secure Remote Password
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_SRP__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
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
 *
 */


/* Add to your makefile */
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if defined(__ENABLE_DIGICERT_EAP_SRP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../harness/harness.h"
#include "../common/random.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_srp.h"
#include "../eap/eap_session.h"


/*------------------------------------------------------------------*/

ubyte SRP_defaultModulus[] = {0xAC, 0x6B, 0xDB, 0x41, 0x32, 0x4A, 0x9A, 0x9B,
                              0xF1, 0x66, 0xDE, 0x5E, 0x13, 0x89, 0x58, 0x2F,
                              0xAF, 0x72, 0xB6, 0x65, 0x19, 0x87, 0xEE, 0x07,
                              0xFC, 0x31, 0x92, 0x94, 0x3D, 0xB5, 0x60, 0x50,
                              0xA3, 0x73, 0x29, 0xCB, 0xB4, 0xA0, 0x99, 0xED,
                              0x81, 0x93, 0xE0, 0x75, 0x77, 0x67, 0xA1, 0x3D,
                              0xD5, 0x23, 0x12, 0xAB, 0x4B, 0x03, 0x31, 0x0D,
                              0xCD, 0x7F, 0x48, 0xA9, 0xDA, 0x04, 0xFD, 0x50,
                              0xE8, 0x08, 0x39, 0x69, 0xED, 0xB7, 0x67, 0xB0,
                              0xCF, 0x60, 0x95, 0x17, 0x9A, 0x16, 0x3A, 0xB3,
                              0x66, 0x1A, 0x05, 0xFB, 0xD5, 0xFA, 0xAA, 0xE8,
                              0x29, 0x18, 0xA9, 0x96, 0x2F, 0x0B, 0x93, 0xB8,
                              0x55, 0xF9, 0x79, 0x93, 0xEC, 0x97, 0x5E, 0xEA,
                              0xA8, 0x0D, 0x74, 0x0A, 0xDB, 0xF4, 0xFF, 0x74,
                              0x73, 0x59, 0xD0, 0x41, 0xD5, 0xC3, 0x3E, 0xA7,
                              0x1D, 0x28, 0x1E, 0x44, 0x6B, 0x14, 0x77, 0x3B,
                              0xCA, 0x97, 0xB4, 0x3A, 0x23, 0xFB, 0x80, 0x16,
                              0x76, 0xBD, 0x20, 0x7A, 0x43, 0x6C, 0x64, 0x81,
                              0xF1, 0xD2, 0xB9, 0x07, 0x87, 0x17, 0x46, 0x1A,
                              0x5B, 0x9D, 0x32, 0xE6, 0x88, 0xF8, 0x77, 0x48,
                              0x54, 0x45, 0x23, 0xB5, 0x24, 0xB0, 0xD5, 0x7D,
                              0x5E, 0xA7, 0x7A, 0x27, 0x75, 0xD2, 0xEC, 0xFA,
                              0x03, 0x2C, 0xFB, 0xDB, 0xF5, 0x2F, 0xB3, 0x78,
                              0x61, 0x60, 0x27, 0x90, 0x04, 0xE5, 0x7A, 0xE6,
                              0xAF, 0x87, 0x4E, 0x73, 0x03, 0xCE, 0x53, 0x29,
                              0x9C, 0xCC, 0x04, 0x1C, 0x7B, 0xC3, 0x08, 0xD8,
                              0x2A, 0x56, 0x98, 0xF3, 0xA8, 0xD0, 0xC3, 0x82,
                              0x71, 0xAE, 0x35, 0xF8, 0xE9, 0xDB, 0xFB, 0xB6,
                              0x94, 0xB5, 0xC8, 0x03, 0xD8, 0x9F, 0x7A, 0xE4,
                              0x35, 0xDE, 0x23, 0x6D, 0x52, 0x5F, 0x54, 0x75,
                              0x9B, 0x65, 0xE3, 0x72, 0xFC, 0xD6, 0x8E, 0xF2,
                              0x0F, 0xA7, 0x11, 0x1F, 0x9E, 0x4A, 0xFF, 0x73
};


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
flushSRPstate(eapSessionCb_t *eapSession, ubyte srpState)
{
    if (eapSession->srpUsernameLen != 0 && eapSession->srpUsername)
    {
        FREE(eapSession->srpUsername);
        eapSession->srpUsername = NULL;
    }
    if (eapSession->srpPasswordLen != 0 && eapSession->srpPassword)
    {
        FREE(eapSession->srpPassword);
        eapSession->srpPassword = NULL;
    }
    if (eapSession->srpSaltLen != 0 && eapSession->srpSalt)
    {
        FREE(eapSession->srpSalt);
        eapSession->srpSalt = NULL;
    }
    if (eapSession->srpGenLen != 0 && eapSession->srpGenerator)
    {
        FREE(eapSession->srpGenerator);
        eapSession->srpGenerator = NULL;
    }
    if (eapSession->srpModulusLen != 0 && eapSession->srpModulus &&
        eapSession->srpModulus != SRP_defaultModulus)
    {
        FREE(eapSession->srpModulus);
        eapSession->srpModulus = NULL;
    }
    if (eapSession->len_A != 0 && eapSession->srpValueA)
    {
        FREE(eapSession->srpValueA);
        eapSession->srpValueA = NULL;
    }
    if (eapSession->len_a != 0 && eapSession->srpValue_a)
    {
        FREE(eapSession->srpValue_a);
        eapSession->srpValue_a = NULL;
    }
    if (eapSession->len_b != 0 && eapSession->srpValue_b)
    {
        FREE(eapSession->srpValue_b);
        eapSession->srpValue_b = NULL;
    }
    if (eapSession->len_B != 0 && eapSession->srpValueB)
    {
        FREE(eapSession->srpValueB);
        eapSession->srpValueB = NULL;
    }
    if (eapSession->srpValue_x)
    {
        FREE(eapSession->srpValue_x);
        eapSession->srpValue_x = NULL;
    }
    if (eapSession->len_v != 0 && eapSession->srpValue_v)
    {
        FREE(eapSession->srpValue_v);
        eapSession->srpValue_v = NULL;
    }
    eapSession->srp_state = srpState;
    eapSession->srpId = 0;

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_SHAInterleave(ubyte *result, ubyte *key, ubyte4 keylen)
{
    ubyte4          i;
    ubyte4          klen;
    ubyte*          Eptr;
    ubyte*          Fptr;
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        shaContext;
    ubyte*          pos = key;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* Skip leading 0's */
    while(keylen > 0 && 0 == *pos)
    {
      --keylen;
      ++pos;
    }

    if (keylen % 2 != 0)
    {
        /* keylen is odd */
        --keylen;
        ++pos;
    }

    klen = keylen / 2;
    Eptr = MALLOC(klen);
    Fptr = MALLOC(klen);

    if ((NULL == Eptr) || (NULL == Fptr))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for(i = 0; i < klen; i++)
    {
        Eptr[i] = pos[2*i];
        Fptr[i] = pos[2*i + 1];
    }

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, Eptr, klen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    for (i = 0; i < SHA_HASH_RESULT_SIZE; i++)
        result[2 * i] = shaOutput[i];

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, Fptr, klen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    for(i = 0; i < SHA_HASH_RESULT_SIZE; i++)
        result[2 * i + 1] = shaOutput[i];

exit:
    if (Eptr)
        FREE(Eptr);

    if (Fptr)
        FREE(Fptr);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_calcM2(eapSessionCb_t *eapSession, ubyte *M2,
           ubyte *M1, ubyte *key, ubyte4 keylen)
{
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        shaContext;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    /* SHA1(A) */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpValueA, eapSession->len_A)))
        goto exit;

    /* SHA1(M1) */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, M1, 20)))
        goto exit;

    /* SHA1(key) */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, key, keylen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    DIGI_MEMCPY(M2, shaOutput, SHA_HASH_RESULT_SIZE);

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_calcHash(eapSessionCb_t *eapSession, ubyte *M1, ubyte *key, ubyte4 keylen)
{
    ubyte           shaOutput1[SHA_HASH_RESULT_SIZE];
    ubyte           shaOutput2[SHA_HASH_RESULT_SIZE];
    shaDescr        shaContext;
    shaDescr        shaHashContext;
    ubyte           type = EAP_TYPE_SRP_SHA1;
    ubyte           i;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* SHA1(N) */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpModulus, eapSession->srpModulusLen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput1)))
        goto exit;

    /* SHA1(g) */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpGenerator, eapSession->srpGenLen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput2)))
        goto exit;

    /* SHA1(N) XOR SHA1(g) */
    for(i = 0; i < sizeof(shaOutput1); i++)
        shaOutput1[i] ^= shaOutput2[i];

    /* SHA1(username) */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpUsername, eapSession->srpUsernameLen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput2)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaHashContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, shaOutput1, SHA_HASH_RESULT_SIZE)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, shaOutput2, SHA_HASH_RESULT_SIZE)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, eapSession->srpSalt, eapSession->srpSaltLen)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, eapSession->srpValueA, eapSession->len_A)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, eapSession->srpValueB, eapSession->len_B)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, key, keylen)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, &eapSession->srpId, 1)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaHashContext, &type, 1)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaHashContext, shaOutput1)))
        goto exit;

    DIGI_MEMCPY(M1, shaOutput1, SHA_HASH_RESULT_SIZE);

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpCalcRechallengeResponse(eapSessionCb_t *eapSession,
                               ubyte *challenge, ubyte4 challengeLen, ubyte *result)
{
    shaDescr        shaContext;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                                         &eapSession->srpId, 1)))
    {
        goto exit;
    }

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                                         eapSession->srpKey, 2*SHA_HASH_RESULT_SIZE)))
    {
        goto exit;
    }

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                                         challenge, challengeLen)))
    {
        goto exit;
    }

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                                         eapSession->srpUsername, eapSession->srpUsernameLen)))
    {
        goto exit;
    }

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, result)))
        goto exit;

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpAuthProcessClientKey(eapSessionCb_t *eapSession, ubyte id,
                            ubyte *data, ubyte4 len,
                            ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*          pos;
    ubyte*          eapRsp;
    ubyte4          length;
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        shaContext;
    ubyte*          str         = NULL;
    vlong*          x           = NULL;
    vlong*          mod         = NULL;
    vlong*          g           = NULL;
    vlong*          v           = NULL;
    vlong*          pVlongQueue = NULL;
    vlong*          b           = NULL;
    vlong*          B           = NULL;
    vlong*          A           = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status      = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* save id for future */
    eapSession->srpId = id;

    /* check validity of A : (value of A != 0 mod N) */
    /* if error, disconnect link */
    if (OK > (status = VLONG_vlongFromByteString((data + 2), (len - 2), &A, &pVlongQueue)))
        goto exit;

    if (TRUE == VLONG_isVlongZero(A))
    {
        status = ERR_EAP_SRP_AUTH_ERROR;
        flushSRPstate(eapSession, EAPSRP_AUTH_STATE_NONE);
        goto exit;
    }

    eapSession->len_A = len - 2;
    eapSession->srpValueA = MALLOC(eapSession->len_A);

    if (NULL == eapSession->srpValueA)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* save a copy of A */
    DIGI_MEMCPY(eapSession->srpValueA, (data + 2), eapSession->len_A);

    /* Calculate x */
    length = eapSession->srpUsernameLen + eapSession->srpPasswordLen + 1;

    str = MALLOC(length);
    if (NULL == str)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = str;
    DIGI_MEMCPY(pos, eapSession->srpUsername, eapSession->srpUsernameLen);
    pos += eapSession->srpUsernameLen;
    *pos++ = ':';
    DIGI_MEMCPY(pos, eapSession->srpPassword, eapSession->srpPasswordLen);

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, str, length)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpSalt, eapSession->srpSaltLen)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput, SHA_HASH_RESULT_SIZE)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    eapSession->srpValue_x = MALLOC(SHA_HASH_RESULT_SIZE);
    if (NULL == eapSession->srpValue_x)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpValue_x, shaOutput, SHA_HASH_RESULT_SIZE);

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_x, SHA_HASH_RESULT_SIZE,
                              &x, &pVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpModulus,
                              eapSession->srpModulusLen,
                              &mod, &pVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpGenerator,
                              eapSession->srpGenLen,
                              &g, &pVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) g, x, mod, &v, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(v, NULL, &eapSession->len_v)))
        goto exit;

    eapSession->srpValue_v = MALLOC(eapSession->len_v);

    if (OK > (status = VLONG_byteStringFromVlong(v, eapSession->srpValue_v, &eapSession->len_v)))
        goto exit;

    /* random number b */
    eapSession->len_b = eapSession->srpModulusLen;
    eapSession->srpValue_b = MALLOC(eapSession->len_b);
    if (NULL == eapSession->srpValue_b)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                    eapSession->srpValue_b,
                                    eapSession->len_b)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_b,
                              eapSession->len_b, &b, &pVlongQueue)))
    {
        goto exit;
    }

    /* calculate B = (v + g^b) % N */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) g, b, mod, &B, &pVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_addSignedVlongs(B, v, &pVlongQueue)))
    {
        goto exit;
    }

    if (VLONG_compareSignedVlongs(B, mod) > 0)
    {
        VLONG_subtractSignedVlongs(B, mod, &pVlongQueue);
    }

    if (OK > (status = VLONG_byteStringFromVlong(B, NULL, &eapSession->len_B)))
    {
        goto exit;
    }

    eapSession->srpValueB = MALLOC(eapSession->len_B);
    if (NULL == eapSession->srpValueB)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(B, eapSession->srpValueB, &eapSession->len_B)))
    {
        goto exit;
    }

    /* allocate eapRespData and copy subtye = 2 and B to it.*/
    eapRsp = MALLOC(1 + eapSession->len_B);
    if (NULL == eapRsp)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRsp = EAP_SRP_SERVER_KEY;
    DIGI_MEMCPY(eapRsp + 1, eapSession->srpValueB, eapSession->len_B);
    *eapRespData = eapRsp;
    *eapRespLen = eapSession->len_B + 1;

exit:
    if(str)
        FREE(str);

    VLONG_freeVlong(&mod, 0);
    VLONG_freeVlong(&x, 0);
    VLONG_freeVlong(&v, 0);
    VLONG_freeVlong(&b, 0);
    VLONG_freeVlong(&B, 0);
    VLONG_freeVlong(&A, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/*! Generate an SRP challenge packet.
This function generates an SRP challenge and builds an $EAP_SRP_CHALLENGE$ packet
(which is returned through the $reqData$ parameter). The SRP authenticator uses
this function after it receives an identity response from the peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SRP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_srp.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param username         User name.
\param usernameLen      Number of bytes in user name.
\param password         Session password for the response.
\param passwordLen      Number of bytes in $password$.
\param method_type      On return, pointer to method type to include in response packet (see $eapMethodType$ enumerated values in eap_proto.h).
\param reqData          On return, pointer to generated EAP packet.
\param reqLen           On return, pointer to number of bytes in generated EAP packet ($reqData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SRPbuildChallenge(ubyte *eapSessionHdl, ubyte4 instanceId,
                      ubyte *username, ubyte4 usernameLen,
                      ubyte *password, ubyte4 passwordLen,
                      eapMethodType *method_type,
                      ubyte **reqData, ubyte4 *reqLen)
{
    eapSessionCb_t* eapSession = NULL;
    ubyte           server_name_len = 0;
    ubyte           server_name[] = "srp_server";
    ubyte           eapReqLen;
    ubyte*          eapRequest = NULL;
    ubyte*          pos = NULL;
    MSTATUS         status;

    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl), instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    /* using the default values for generator and prime modulus */
    /* generate new salt - 80 bits */
    if (eapSession->srpSalt)
        FREE(eapSession->srpSalt);

    eapSession->srpSalt = MALLOC(EAP_SRP_SALTLEN);
    if (NULL == eapSession->srpSalt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = RANDOM_numberGenerator(g_pRandomContext,
                                    eapSession->srpSalt, EAP_SRP_SALTLEN);

    if (OK > status)
        goto exit;

    eapSession->srpSaltLen = EAP_SRP_SALTLEN;

    /* Save default values of g and N */
    eapSession->srpGenLen = 1;
    eapSession->srpGenerator = MALLOC(1);
    if (NULL == eapSession->srpGenerator)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapSession->srpGenerator = 2;

    /* set Modulus to default value */
    eapSession->srpModulus = SRP_defaultModulus;
    eapSession->srpModulusLen = 256;

    /* Save username and password */
    eapSession->srpUsername = MALLOC(usernameLen);
    if (NULL == eapSession->srpUsername)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpUsername, username, usernameLen);
    eapSession->srpUsernameLen = usernameLen;

    eapSession->srpPassword = MALLOC(passwordLen);
    if (NULL == eapSession->srpPassword)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpPassword, password, passwordLen);
    eapSession->srpPasswordLen = (ubyte)passwordLen;

    server_name_len = (ubyte)DIGI_STRLEN((sbyte *)server_name);
    eapReqLen = 4 + server_name_len + eapSession->srpSaltLen;
    eapRequest = (ubyte *) MALLOC(eapReqLen);

    if (NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapRequest;
    *pos++ = EAP_SRP_CHALLENGE;
    *pos++ = server_name_len;
    DIGI_MEMCPY(pos, server_name, server_name_len);

    pos += server_name_len;
    *pos++ = eapSession->srpSaltLen;
    DIGI_MEMCPY(pos, eapSession->srpSalt, eapSession->srpSaltLen);

    pos += eapSession->srpSaltLen;

    /* use default generator value of 2, and default prime modulus */
    *pos++ = 0;
    *reqData = eapRequest;
    *reqLen = eapReqLen;
    *method_type = EAP_TYPE_SRP_SHA1;
    eapSession->srp_state = EAPSRP_AUTH_STATE_CHALLENGE;

exit:
    return status;

} /* EAP_SRPbuildChallenge */


/*------------------------------------------------------------------*/

/*! Build an EAP-SRP lightweight challenge packet for reauthentication.
This function builds an EAP-SRP lightweight challenge packet at the
authenticator for reauthentication. (For information about lightweight
challenges, refer to the following RFC Draft:
http://www3.ietf.org/proceedings/01dec/I-D/draft-ietf-pppext-eap-srp-03.txt )

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SRP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_srp.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param method_type      On return, pointer to method type to include in response packet (see $eapMethodType$ enumerated values in eap_proto.h).
\param reqData          On return, pointer to generated EAP packet.
\param reqLen           On return, pointer to number of bytes in generated EAP packet ($reqData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SRPbuildLightweightChallenge(ubyte *eapSessionHdl, ubyte4 instanceId,
                      eapMethodType *method_type,
                      ubyte **reqData, ubyte4 *reqLen)
{
    eapSessionCb_t* eapSession = NULL;
    ubyte           eapReqLen;
    ubyte*          eapRequest = NULL;
    ubyte*          pos = NULL;
    MSTATUS         status;

    status = eap_lookupSession ((ubyte4)((uintptr)eapSessionHdl), instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    eapReqLen = EAP_SRP_RECHALLENGE_LEN + 1;
    eapRequest = (ubyte *) MALLOC(eapReqLen);

    if (NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapRequest;
    *pos++ = EAP_SRP_LIGHTWEIGHT_RECHALLENGE;

    eapSession->srpRechallenge = MALLOC(EAP_SRP_RECHALLENGE_LEN);
    if (NULL == eapSession->srpRechallenge)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = RANDOM_numberGenerator(g_pRandomContext,
                                    eapSession->srpRechallenge,
                                    EAP_SRP_RECHALLENGE_LEN);

    DIGI_MEMCPY(pos, eapSession->srpRechallenge, EAP_SRP_RECHALLENGE_LEN);

    *reqData = eapRequest;
    *reqLen = eapReqLen;
    *method_type = EAP_TYPE_SRP_SHA1;
    eapSession->srp_state = EAPSRP_AUTH_STATE_RECHALLENGE;

exit:
    return status;

} /* EAP_SRPbuildLightweightChallenge */


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpAuthProcessClientValidator(eapSessionCb_t *eapSession, ubyte *data,
                              ubyte4 len, ubyte **eapRespData,
                              ubyte4 *eapRespLen)
{
    ubyte*          eapRsp = NULL;
    ubyte*          pos = NULL;
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        shaContext;
    vlong*          b = NULL;
    vlong*          u = NULL;
    vlong*          v = NULL;
    vlong*          S = NULL;
    vlong*          mod = NULL;
    vlong*          t1 = NULL;
    vlong*          t2 = NULL;
    vlong*          A = NULL;
    vlong*          calc_M1 = NULL;
    vlong*          recvd_M1 = NULL;
    vlong*          rem = NULL;
    vlong*          pVlongQueue = NULL;
    sbyte4          len_S;
    ubyte*          S_str = NULL;
    ubyte           M1[SHA_HASH_RESULT_SIZE], M2[SHA_HASH_RESULT_SIZE];
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    MOC_UNUSED(len);

    /* validate M1. If invalid, terminate connection */
    /* Calculate K */
    /* calculate u from B as the first 32 bits of the SHA1 hash of B */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpValueB, eapSession->len_B)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(shaOutput, 4, &u, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_v, eapSession->len_v, &v, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpModulus,
                              eapSession->srpModulusLen,
                              &mod, &pVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValueA, eapSession->len_A, &A, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) v, u, mod, &t1, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&t2, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongSignedMultiply(t2, A, t1)))
        goto exit;

    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) t2, mod, &rem, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_b, eapSession->len_b, &b, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) rem, b, mod, &S, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(S, NULL, &len_S)))
        goto exit;

    S_str = MALLOC(len_S);
    if (NULL == S_str)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(S, S_str, &len_S)))
        goto exit;

    if (OK > (status = eap_SHAInterleave(eapSession->srpKey, S_str, len_S)))
        goto exit;

    if (OK > (status = eap_calcHash(eapSession, M1, eapSession->srpKey, 2*SHA_HASH_RESULT_SIZE)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(M1, SHA_HASH_RESULT_SIZE, &calc_M1, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(data + 6, SHA_HASH_RESULT_SIZE, &recvd_M1, &pVlongQueue)))
        goto exit;

    if (VLONG_compareSignedVlongs(calc_M1, recvd_M1) != 0)
    {
        flushSRPstate(eapSession, EAPSRP_AUTH_STATE_NONE);
        status = ERR_EAP_SRP_AUTH_ERROR;
        goto exit;
    }

    /* calculate M2 */
    if (OK > (status = eap_calcM2(eapSession, M2, M1, eapSession->srpKey, 2*SHA_HASH_RESULT_SIZE)))
        goto exit;

    eapRsp = MALLOC(25);
    if (NULL == eapRsp)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapRsp;
    *pos++ = EAP_SRP_SERVER_VALIDATOR;
    status = DIGI_MEMSET(pos, 0, 4);
    pos += 4;
    DIGI_MEMCPY(pos, M2, 20);
    *eapRespData = eapRsp;
    *eapRespLen = 25;

exit:
    if (S_str)
        FREE(S_str);

    VLONG_freeVlong(&u, 0);
    VLONG_freeVlong(&v, 0);
    VLONG_freeVlong(&S, 0);
    VLONG_freeVlong(&A, 0);
    VLONG_freeVlong(&b, 0);
    VLONG_freeVlong(&t1, 0);
    VLONG_freeVlong(&t2, 0);
    VLONG_freeVlong(&rem, 0);
    VLONG_freeVlong(&calc_M1, 0);
    VLONG_freeVlong(&recvd_M1, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;

} /* eap_srpAuthProcessClientValidator */


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpAuthProcessRechallenge(eapSessionCb_t *eapSession, ubyte *data, ubyte4 len)
{
    ubyte   calcResp[SHA_HASH_RESULT_SIZE];
    sbyte4  result;
    MSTATUS status = OK;

    if (len != (SHA_HASH_RESULT_SIZE + 2))
    {
        status = ERR_EAP_SRP_AUTH_ERROR;
        goto exit;
    }

    status = eap_srpCalcRechallengeResponse(eapSession, eapSession->srpRechallenge,
                                            EAP_SRP_RECHALLENGE_LEN, calcResp);

    if (OK > status)
        goto exit;

    if (OK > (status = DIGI_MEMCMP(calcResp, (data + 2), SHA_HASH_RESULT_SIZE, &result)))
        goto exit;

    if (0 != result)
        status = ERR_EAP_SRP_AUTH_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the EAP payload from a message received by an SRP authenticator.
This function processes a message received by an SRP authenticator and returns
the resultant EAP payload through the $eapRespData$ parameter. Additionally, the
response status is returned (throught the $code$ parameter), which your application
should use to update the EAP processing state machine variables, $methodState$ and
$decision$, according to application requirements.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SRP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_srp.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param id               EAP packet ID.
\param data             EAP payload to process.
\param len              Number of bytes in EAP payload ($data$).
\param passwordString   Session password for the response.
\param passLen          Number of bytes in session password ($passwordString$).
\param eapRespData      On return, pointer to EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in EAP response payload ($eapRespData$).
\param code             On return, pointer to response status to include in
response packet (one of the $eapCode$ enumerated values in eap_proto.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_SRPprocessAuth(ubyte *appSessionHdl, ubyte *eapSessionHdl,
                   ubyte4 instanceId, ubyte id,
                   ubyte *data, ubyte4 len,
                   ubyte *passwordString,ubyte4 passLen,
                   ubyte **eapRespData, ubyte4 *eapRespLen, ubyte *code)
{
    eapSessionCb_t* eapSession = NULL;
    ubyte           subtype;
    MSTATUS         status;
    MOC_UNUSED(appSessionHdl);
    MOC_UNUSED(passwordString);
    MOC_UNUSED(passLen);

    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl), instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    subtype = data[1];

    switch(subtype)
    {
        case EAP_SRP_CLIENT_KEY:
        {
            if (eapSession->srp_state != EAPSRP_AUTH_STATE_CHALLENGE)
            {
                /* terminate the connection */
                flushSRPstate(eapSession, EAPSRP_AUTH_STATE_NONE);
                status = ERR_EAP_SRP_INVALID_STATE;
                break;
            }

            status = eap_srpAuthProcessClientKey(eapSession, id, data, len,
                                                 eapRespData, eapRespLen);
            if (OK == status)
            {
                eapSession->srp_state = EAPSRP_AUTH_STATE_SERVER_KEY;
                *code = EAP_CODE_REQUEST;
            }
            else
            {
                flushSRPstate(eapSession, EAPSRP_AUTH_STATE_NONE);
                *code = 0;
            }

            break;
        }

        case EAP_SRP_CLIENT_VALIDATOR:
        {
            if (eapSession->srp_state != EAPSRP_AUTH_STATE_SERVER_KEY)
            {
                /* terminate the connection */
                flushSRPstate(eapSession, EAPSRP_AUTH_STATE_NONE);
                break;
            }
            status = eap_srpAuthProcessClientValidator(eapSession, data,
                              len, eapRespData, eapRespLen);
            if (OK == status && eapRespLen != 0)
            {
                eapSession->srp_state = EAPSRP_AUTH_STATE_SERVER_VALIDATOR;
                *code = EAP_CODE_REQUEST;
            }
            else
            {
                eapSession->srp_state = EAPSRP_AUTH_STATE_NONE;
                *code = 0;
            }

            break;
        }

        case EAP_SRP_SUBTYPE3_RESPONSE:
        {
            if (eapSession->srp_state != EAPSRP_AUTH_STATE_SERVER_VALIDATOR)
                break;

            eapSession->srp_state = EAPSRP_AUTH_STATE_SUCCESS;
            *code = EAP_CODE_SUCCESS;

            break;
        }

        case EAP_SRP_LIGHTWEIGHT_RECHALLENGE:
        {
            if (eapSession->srp_state != EAPSRP_AUTH_STATE_RECHALLENGE)
                break;

            status = eap_srpAuthProcessRechallenge(eapSession, data, len);

            if (OK == status)
            {
                eapSession->srp_state = EAPSRP_AUTH_STATE_SUCCESS;
                *code = EAP_CODE_SUCCESS;
            }
            else
            {
                eapSession->srp_state = EAPSRP_AUTH_STATE_FAILURE;
                *code = EAP_CODE_FAILURE;
            }

            break;
        }

        default:
        {
            status = ERR_EAP_SRP_INVALID_SUBTYPE;
            break;
        }
    }

exit:
    return status;

} /* EAP_SRPprocessAuth */


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpPeerProcessServerValidator(eapSessionCb_t *eapSession, ubyte *data,
                                  ubyte4 len, ubyte **eapRespData,
                                  ubyte4 *eapRespLen)
{
    ubyte   M2[SHA_HASH_RESULT_SIZE];
    vlong*  calc_M2 = NULL;
    vlong*  recvd_M2 = NULL;
    vlong*  pVlongQueue = NULL;
    ubyte*  eapRsp = NULL;
    MSTATUS status = OK;
    MOC_UNUSED(len);

    /* Validate M2 */
    if (OK > (status = eap_calcM2(eapSession, M2, eapSession->srpValue_M1, eapSession->srpKey, 2*SHA_HASH_RESULT_SIZE)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(M2, SHA_HASH_RESULT_SIZE, &calc_M2, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(data + 6, SHA_HASH_RESULT_SIZE, &recvd_M2, &pVlongQueue)))
        goto exit;

    if (0 != VLONG_compareSignedVlongs(calc_M2, recvd_M2))
    {
        flushSRPstate(eapSession, EAPSRP_PEER_STATE_NONE);
        status = ERR_EAP_SRP_AUTH_ERROR;
        goto exit;
    }

    eapRsp = MALLOC(1);
    if (NULL == eapRsp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRsp = EAP_SRP_SUBTYPE3_RESPONSE;
    *eapRespData = eapRsp;
    *eapRespLen = 1;

exit:
    VLONG_freeVlong(&calc_M2, 0);
    VLONG_freeVlong(&recvd_M2, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* eap_srpPeerProcessServerValidator */


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpPeerProcessServerKey(eapSessionCb_t *eapSession, ubyte *data, ubyte4 len,
                            ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*          eapRsp      = NULL;
    ubyte*          pos         = NULL;
    ubyte*          str         = NULL;
    ubyte*          S_str       = NULL;
    vlong*          B           = NULL;
    vlong*          S           = NULL;
    vlong*          u           = NULL;
    vlong*          a           = NULL;
    vlong*          e           = NULL;
    vlong*          g           = NULL;
    vlong*          x           = NULL;
    vlong*          mod         = NULL;
    vlong*          v           = NULL;
    vlong*          pVlongQueue = NULL;
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        shaContext;
    ubyte4          length;
    sbyte4          len_S;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* data contains B. save in eapSession->srpValueB */
    pos = data + 1;

    if (OK > (status = VLONG_vlongFromByteString((data + 2), (len - 2), &B, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpModulus, eapSession->srpModulusLen, &mod, &pVlongQueue)))
        goto exit;

    if ((0 == VLONG_compareSignedVlongs(B, mod)) ||
        (TRUE == VLONG_isVlongZero(B)))
    {
        status = ERR_EAP_SRP_AUTH_ERROR;
        flushSRPstate(eapSession, EAPSRP_PEER_STATE_NONE);
        goto exit;
    }

    eapSession->len_B = len - 2;
    eapSession->srpValueB = MALLOC(eapSession->len_B);

    if (NULL == eapSession->srpValueB)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpValueB, (data + 2), eapSession->len_B);

    /* Calculate x = SHA(s | SHA(U | ":" | p)) */
    length = eapSession->srpUsernameLen + eapSession->srpPasswordLen + 1;

    str = MALLOC(length);
    if (NULL == str)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = str;

    DIGI_MEMCPY(pos, eapSession->srpUsername, eapSession->srpUsernameLen);
    pos += eapSession->srpUsernameLen;

    *pos++ = ':';

    DIGI_MEMCPY(pos, eapSession->srpPassword, eapSession->srpPasswordLen);

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, str, length)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpSalt, eapSession->srpSaltLen)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput, SHA_HASH_RESULT_SIZE)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    eapSession->srpValue_x = MALLOC(SHA_HASH_RESULT_SIZE);
    if (NULL == eapSession->srpValue_x)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpValue_x, shaOutput, SHA_HASH_RESULT_SIZE);

    /* v = g^x % N */
    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_x, SHA_HASH_RESULT_SIZE, &x, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpModulus, eapSession->srpModulusLen, &mod, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpGenerator, eapSession->srpGenLen, &g, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) g, x, mod, &v, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(v, NULL, &eapSession->len_v)))
        goto exit;

    if (NULL == (eapSession->srpValue_v = MALLOC(eapSession->len_v)))
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(v, eapSession->srpValue_v, &eapSession->len_v)))
        goto exit;

    /* (B - g^x) */
    if (VLONG_compareSignedVlongs(B, v) < 0)
    {
        if (OK > (status = VLONG_addSignedVlongs(B, mod, &pVlongQueue)))
            goto exit;
    }

    if (OK > (status = VLONG_subtractSignedVlongs(B, v, &pVlongQueue)))
        goto exit;

    /* Calculate (a + u * x) % N */
    /* calculate u from B as the first 32 bits of the SHA1 hash of B */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, eapSession->srpValueB, eapSession->len_B)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, shaOutput)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(shaOutput, 4, &u, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_a, eapSession->len_a, &a, &pVlongQueue)))
        goto exit;

     /* e = a + ux */
    if (OK > (status = VLONG_allocVlong(&e, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongSignedMultiply(e, u, x)))
        goto exit;

    if (OK > (status = VLONG_addSignedVlongs(e, a, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) B, e, mod, &S, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(S, NULL, &len_S)))
        goto exit;

    S_str = MALLOC(len_S);
    if (NULL == S_str)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(S, S_str, &len_S)))
        goto exit;

    if (OK > (status = eap_SHAInterleave(eapSession->srpKey, S_str, len_S)))
        goto exit;

    if (OK > (status = eap_calcHash(eapSession, eapSession->srpValue_M1, eapSession->srpKey, 2*SHA_HASH_RESULT_SIZE)))
        goto exit;

    /* Form response packet */
    eapRsp = MALLOC(25);
    if (NULL == eapRsp)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapRsp;
    *pos++ = EAP_SRP_CLIENT_VALIDATOR;
    status = DIGI_MEMSET(pos, 0, 4);
    pos += 4;

    DIGI_MEMCPY(pos, eapSession->srpValue_M1, SHA_HASH_RESULT_SIZE);

    *eapRespData = eapRsp;
    *eapRespLen = 25;

exit:
    if (str)
        FREE(str);

    if (S_str)
        FREE(S_str);

    VLONG_freeVlong(&g, 0);
    VLONG_freeVlong(&B, 0);
    VLONG_freeVlong(&S, 0);
    VLONG_freeVlong(&mod, 0);
    VLONG_freeVlong(&v, 0);
    VLONG_freeVlong(&u, 0);
    VLONG_freeVlong(&x, 0);
    VLONG_freeVlong(&a, 0);
    VLONG_freeVlong(&e, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;

} /* eap_srpPeerProcessServerKey */


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpPeerProcessChallenge(eapSessionCb_t *eapSession, ubyte id, ubyte *data,
                            ubyte4 len, ubyte *username, ubyte4 usernameLen,
                            ubyte *passwordString,ubyte4 passLen,
                            ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*          pos = data + 2;
    ubyte           serverNameLen;
    ubyte*          eapRsp      = NULL;
    ubyte*          end         = data + len;
    vlong*          g           = NULL;
    vlong*          mod         = NULL;
    vlong*          A           = NULL;
    vlong*          a           = NULL;
    vlong*          pVlongQueue = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status      = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* save id for later use */
    eapSession->srpId = id;

    /* save username & password */
    eapSession->srpUsernameLen = usernameLen;
    eapSession->srpUsername = MALLOC(usernameLen);

    if (NULL == eapSession->srpUsername)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpUsername, username, usernameLen);

    eapSession->srpPasswordLen = (ubyte)passLen;
    eapSession->srpPassword = MALLOC(passLen);

    if (NULL == eapSession->srpPassword)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpPassword, passwordString, passLen);

    /* extract salt, generator and Modulus from data and save in eapSession */
    if (eapSession->srpSaltLen != 0 && eapSession->srpSalt)
        FREE(eapSession->srpSalt);

    serverNameLen = *pos;
    pos = pos + serverNameLen + 1;
    eapSession->srpSaltLen = *pos;
    pos++;

    eapSession->srpSalt = MALLOC(eapSession->srpSaltLen);
    if (NULL == eapSession->srpSalt)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSession->srpSalt, pos, eapSession->srpSaltLen);
    pos += eapSession->srpSaltLen;

    eapSession->srpGenLen = *pos;
    if (0 == eapSession->srpGenLen)
    {
        /* set generator to default value */
        eapSession->srpGenLen = 1;
        eapSession->srpGenerator = MALLOC(1);
        if (NULL == eapSession->srpGenerator)
        {
            status =  ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapSession->srpGenerator = 2;
        /* set Modulus to default value */
        eapSession->srpModulus = SRP_defaultModulus;
        eapSession->srpModulusLen = 256;
    }
    else
    {
        eapSession->srpGenerator = MALLOC(eapSession->srpGenLen);
        if (NULL == eapSession->srpGenerator)
        {
            status =  ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        pos++;
        DIGI_MEMCPY(eapSession->srpGenerator, pos, eapSession->srpGenLen);
        pos += eapSession->srpGenLen;

        if (pos != end)
        {
            eapSession->srpModulusLen = end - pos;
            eapSession->srpModulus = MALLOC(eapSession->srpModulusLen);
            if (NULL == eapSession->srpModulus)
            {
                status =  ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(eapSession->srpModulus, pos, eapSession->srpModulusLen);
        }
        else
        {
            /* default generator */
            eapSession->srpModulus = SRP_defaultModulus;
            eapSession->srpModulusLen = 256;
        }
    }

   /* Assign value to 'a' */
    eapSession->srpValue_a = MALLOC(eapSession->srpModulusLen);
    if (NULL == eapSession->srpValue_a)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = RANDOM_numberGenerator(g_pRandomContext,
                                    eapSession->srpValue_a,
                                    eapSession->srpModulusLen);

    if (OK > status)
        goto exit;

    eapSession->len_a = eapSession->srpModulusLen;

   /* Calculate A and save in eapSession->srpValueA
      and length in eapSession->len_A */
    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpModulus, eapSession->srpModulusLen, &mod, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpGenerator, eapSession->srpGenLen, &g, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(eapSession->srpValue_a, eapSession->len_a, &a, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) g, a, mod, &A, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(A, NULL, &eapSession->len_A)))
        goto exit;

    eapSession->srpValueA = MALLOC(eapSession->len_A);

    if (NULL == eapSession->srpValueA)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(A, eapSession->srpValueA, &eapSession->len_A)))
        goto exit;

    eapRsp = MALLOC(1 + eapSession->len_A);

    if (NULL == eapRsp)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRsp = EAP_SRP_CLIENT_KEY;
    DIGI_MEMCPY(eapRsp + 1, eapSession->srpValueA, eapSession->len_A);

    *eapRespData = eapRsp;
    *eapRespLen = eapSession->len_A + 1;

    status = OK;

exit:
    VLONG_freeVlong(&g, 0);
    VLONG_freeVlong(&mod, 0);
    VLONG_freeVlong(&a, 0);
    VLONG_freeVlong(&A, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;

} /* eap_srpPeerProcessChallenge */


/*------------------------------------------------------------------*/

static MSTATUS
eap_srpPeerProcessRechallenge(eapSessionCb_t *eapSession, ubyte *data,
                              ubyte4 len, ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte   shaOutput[SHA_HASH_RESULT_SIZE];
    ubyte4  challengeLen = len - 2;
    ubyte*  eapRsp;
    MSTATUS status;

    *eapRespLen = 0;

    status = eap_srpCalcRechallengeResponse(eapSession, (data + 2), challengeLen, shaOutput);

    if (OK > status)
        goto exit;

    eapRsp = MALLOC(SHA_HASH_RESULT_SIZE + 1);

    if (NULL == eapRsp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRespLen = SHA_HASH_RESULT_SIZE + 1;
    *eapRsp = EAP_SRP_LIGHTWEIGHT_RECHALLENGE;

    DIGI_MEMCPY(eapRsp + 1, shaOutput, SHA_HASH_RESULT_SIZE);

    *eapRespData = eapRsp;

exit:
    return status;

} /* eap_srpPeerProcessRechallenge */


/*------------------------------------------------------------------*/

/*! Get the EAP payload from an SRP-SHA1 message received by an SRP peer.
This function processes a message received by an SRP peer and returns the
resultant EAP payload through the $eapRespData$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SRP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_srp.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param id               EAP packet ID.
\param data             EAP payload to process.
\param len              Number of bytes in EAP payload ($data$).
\param username         User name.
\param usernameLen      Number of bytes in user name ($username$).
\param passwordString   Session password for the response.
\param passLen          Number of bytes in session password ($passwordString$).
\param eapRespData      On return, pointer to EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in EAP response payload ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SRPprocessPeer(ubyte* appSessionHdl, ubyte* eapSessionHdl,
                   ubyte4 instanceId, ubyte id,
                   ubyte* data, ubyte4 len,
                   ubyte* username, ubyte4 usernameLen,
                   ubyte* passwordString, ubyte4 passLen,
                   ubyte* *eapRespData, ubyte4* eapRespLen)
{
    eapSessionCb_t* eapSession = NULL;
    ubyte           subtype;
    MSTATUS         status = OK;
    MOC_UNUSED(appSessionHdl);

    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl), instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    subtype = data[1];

    switch(subtype)
    {
        case EAP_SRP_CHALLENGE:
        {
            if (eapSession->srp_state != EAPSRP_PEER_STATE_NONE)
            {
                status = ERR_EAP_SRP_INVALID_STATE;
                break;
            }

            status = eap_srpPeerProcessChallenge(eapSession, id, data, len,
                                                 username, usernameLen,
                                                 passwordString, passLen,
                                                 eapRespData, eapRespLen);
            if (OK == status)
            {
                eapSession->srp_state = EAPSRP_PEER_STATE_CLIENT_KEY;
            }
            else
            {
                eapSession->srp_state = EAPSRP_PEER_STATE_NONE;
                eapRespLen = 0;
            }

            break;
        }

        case EAP_SRP_SERVER_KEY:
        {
            if (eapSession->srp_state != EAPSRP_PEER_STATE_CLIENT_KEY)
            {
                flushSRPstate(eapSession, EAPSRP_PEER_STATE_NONE);
                status = ERR_EAP_SRP_INVALID_STATE;
                break;
            }

            status = eap_srpPeerProcessServerKey(eapSession, data, len,
                                                 eapRespData, eapRespLen);

            if (OK == status)
            {
                eapSession->srp_state = EAPSRP_PEER_STATE_CLIENT_VALIDATOR;
            }
            else
            {
                eapSession->srp_state = EAPSRP_PEER_STATE_NONE;
            }

            break;
        }

        case EAP_SRP_SERVER_VALIDATOR:
        {
            if (eapSession->srp_state != EAPSRP_PEER_STATE_CLIENT_VALIDATOR)
            {
                flushSRPstate(eapSession, EAPSRP_PEER_STATE_NONE);
                status = ERR_EAP_SRP_INVALID_STATE;
                break;
            }

            status = eap_srpPeerProcessServerValidator(eapSession, data, len,
                                                       eapRespData, eapRespLen);

            if (OK == status)
            {
                eapSession->srp_state = EAPSRP_PEER_STATE_SUBTYPE3_RESPONSE;
            }
            else
            {
                eapSession->srp_state = EAPSRP_PEER_STATE_NONE;
            }

            break;
        }

        case EAP_SRP_LIGHTWEIGHT_RECHALLENGE:
        {
            if (eapSession->srp_state != EAPSRP_PEER_STATE_SUBTYPE3_RESPONSE)
            {
                flushSRPstate(eapSession, EAPSRP_PEER_STATE_NONE);
                status = ERR_EAP_SRP_INVALID_STATE;
                break;
            }

            status = eap_srpPeerProcessRechallenge(eapSession, data, len,
                                                   eapRespData, eapRespLen);

            break;
         }

        default:
        {
            status = ERR_EAP_SRP_INVALID_SUBTYPE;
            break;
        }
    }

exit:
    return status;

} /* EAP_SRPprocessPeer */

#endif /*defined(__ENABLE_DIGICERT_EAP_SRP__)  */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
