/*
 * otp.c
 *
 * One-Time-Password and S/Key implementation
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

#ifdef __ENABLE_DIGICERT_OTP__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"

#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"


#include "../crypto/otp.h"

#ifdef __ENABLE_DIGICERT_MD4__
/*--------------------------------------------------------------------------*/

static MSTATUS
OTP_md4(MOC_HASH(hwAccelDescr hwAccelCtx) const sbyte* seed, ubyte4 seedLen, const sbyte* pwd, ubyte4 seq,
         ubyte res[8])
{
    MSTATUS status;
    MD4_CTX ctx;
    ubyte output[MD4_RESULT_SIZE];
    ubyte4 i;

    if (OK > ( status = MD4Init(MOC_HASH(hwAccelCtx) &ctx)))
        goto exit;

    if (OK > ( status = MD4Update(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)seed, seedLen)))
        goto exit;

    if (OK > ( status = MD4Update(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)pwd, DIGI_STRLEN(pwd))))
        goto exit;

    if (OK > ( status = MD4Final(MOC_HASH(hwAccelCtx) &ctx, output)))
        goto exit;

    /* Fold into 64 bits as described by RFC 2289 */
    for (i = 0; i < 8; ++i)
        res[i] = output[i] ^ output[i+8];

    for (; seq; --seq)
    {
        if (OK > ( status = MD4Init(MOC_HASH(hwAccelCtx) &ctx)))
            goto exit;

        if (OK > ( status = MD4Update(MOC_HASH(hwAccelCtx) &ctx, res, 8)))
            goto exit;

        if (OK > ( status = MD4Final(MOC_HASH(hwAccelCtx) &ctx, output)))
            goto exit;

        /* Fold into 64 bits as described by RFC 2289 */
        for (i = 0; i < 8; ++i)
            res[i] = output[i] ^ output[i+8];
    }

exit:

    return status;
}

#endif


/*--------------------------------------------------------------------------*/

static MSTATUS
OTP_md5(MOC_HASH(hwAccelDescr hwAccelCtx) const sbyte* seed, ubyte4 seedLen, const sbyte* pwd, ubyte4 seq,
         ubyte res[8])
{
    MSTATUS status;
    MD5_CTX ctx;
    ubyte output[MD5_RESULT_SIZE];
    ubyte4 i;

    if (OK > ( status = MD5Init_m(MOC_HASH(hwAccelCtx) &ctx)))
        goto exit;

    if (OK > ( status = MD5Update_m(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)seed, seedLen)))
        goto exit;

    if (OK > ( status = MD5Update_m(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)pwd, DIGI_STRLEN(pwd))))
        goto exit;

    if (OK > ( status = MD5Final_m(MOC_HASH(hwAccelCtx) &ctx, output)))
        goto exit;

    /* Fold into 64 bits as described by RFC 2289 */
    for (i = 0; i < 8; ++i)
        res[i] = output[i] ^ output[i+8];

    for (; seq; --seq)
    {
        if (OK > ( status = MD5Init_m(MOC_HASH(hwAccelCtx) &ctx)))
            goto exit;

        if (OK > ( status = MD5Update_m(MOC_HASH(hwAccelCtx) &ctx, res, 8)))
            goto exit;

        if (OK > ( status = MD5Final_m(MOC_HASH(hwAccelCtx) &ctx, output)))
            goto exit;

        /* Fold into 64 bits as described by RFC 2289 */
        for (i = 0; i < 8; ++i)
            res[i] = output[i] ^ output[i+8];
    }

exit:

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
OTP_sha1(MOC_HASH(hwAccelDescr hwAccelCtx) const sbyte* seed, ubyte4 seedLen, const sbyte* pwd, ubyte4 seq,
         ubyte res[8])
{
    SHA1_CTX    ctx;
    ubyte4      output[(((sizeof(ubyte4)-1) + SHA1_RESULT_SIZE) / sizeof(ubyte4))];
    ubyte4      i, j;
    MSTATUS     status;

    if (OK > ( status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &ctx)))
        goto exit;

    if (OK > ( status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)seed, seedLen)))
        goto exit;

    if (OK > ( status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)pwd, DIGI_STRLEN(pwd))))
        goto exit;

    if (OK > ( status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &ctx, (ubyte *)output)))
        goto exit;

    /* Fold into 64 bits as described by RFC 2289 -- ugly! */
    /* For Cavium processors, we need to do something a little different than the RFC implementation. */
    /* And it makes the code little prettier than the original RFC implementation. */
    output[0] ^= output[2];
    output[0] ^= output[4];
    output[1] ^= output[3];

    /* jic (little endian) - need to convert from network to native */
    output[0] = DIGI_NTOHL((ubyte *)(&output[0]));
    output[1] = DIGI_NTOHL((ubyte *)(&output[1]));

    for (i = 0, j = 0; j < 8; i++, j += 4)
    {
        res[j]   = (unsigned char)(output[i] & 0xff);
        res[j+1] = (unsigned char)((output[i] >> 8) & 0xff);
        res[j+2] = (unsigned char)((output[i] >> 16) & 0xff);
        res[j+3] = (unsigned char)((output[i] >> 24) & 0xff);
    }

    for (; seq; --seq)
    {
        if (OK > ( status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &ctx)))
            goto exit;

        if (OK > ( status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &ctx, (const ubyte*)res, 8)))
            goto exit;

        if (OK > ( status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &ctx, (ubyte *)output)))
            goto exit;

        /* Fold into 64 bits as described by RFC 2289 -- ugly! */
        output[0] ^= output[2];
        output[0] ^= output[4];
        output[1] ^= output[3];

        /* jic (little endian) - need to convert from network to native */
        output[0] = DIGI_NTOHL((ubyte *)(&output[0]));
        output[1] = DIGI_NTOHL((ubyte *)(&output[1]));

        for (i = 0, j = 0; j < 8; i++, j += 4)
        {
            res[j]   = (unsigned char)(output[i] & 0xff);
            res[j+1] = (unsigned char)((output[i] >> 8) & 0xff);
            res[j+2] = (unsigned char)((output[i] >> 16) & 0xff);
            res[j+3] = (unsigned char)((output[i] >> 24) & 0xff);
        }
    }

exit:

    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
OTP_otp(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte ht_type, const sbyte* seed, const sbyte* pwd,
         ubyte4 seq, ubyte res[8])
{
    sbyte convSeed[16]; /* seed coverted to lower case */
    sbyte4 i;

    if (!seed || !pwd || !res)
        return ERR_NULL_POINTER;

    /* convert seed to lower case, truncate to 16 if necessary */
    for (i = 0; i < 16; ++i, ++seed)
    {
        if (0 == *seed)
            break;

        if ('A' <= *seed && *seed <= 'Z')
        {
            convSeed[i] = *seed + 'a' - 'A';
        }
        else
        {
            convSeed[i] = *seed;
        }
    }

    switch (ht_type)
    {
#ifdef __ENABLE_DIGICERT_MD4__
    case ht_md4:
        return OTP_md4(MOC_HASH(hwAccelCtx) convSeed, i, pwd, seq, res);
        break;
#endif

    case ht_md5:
        return OTP_md5(MOC_HASH(hwAccelCtx) convSeed, i, pwd, seq, res);
        break;

    case ht_sha1:
        return OTP_sha1(MOC_HASH(hwAccelCtx) convSeed, i, pwd, seq, res);
        break;

    }

    return ERR_OTP_UNSUPPORTED_ALGORITHM;
}



/*--------------------------------------------------------------------------*/

extern MSTATUS
OTP_otpEx(MOC_HASH(hwAccelDescr hwAccelCtx) const sbyte* challenge, const sbyte* pwd, sbyte res[20])
{
    MSTATUS status;
    sbyte4 i;
    ubyte ht_type;
    ubyte4 seq;
    const sbyte* stop;
    ubyte4 seedLen;
    ubyte otpRes[OTP_RESULT_SIZE];

    if ( !challenge || !pwd || !res)
        return ERR_NULL_POINTER;

    DIGI_MEMCMP((const ubyte*)challenge,(const ubyte*) "otp-", 4, &i);

    if (i)
    {
        return ERR_OTP_INVALID_CHALLENGE;
    }

    challenge += 4;
    DIGI_MEMCMP((const ubyte*)challenge,(const ubyte*)"md", 2, &i);
    if (i)
    {
        DIGI_MEMCMP((const ubyte*)challenge, (const ubyte*)"sha1", 4, &i);
        if ( i)
        {
            return ERR_OTP_INVALID_ALGORITHM;
        }
        ht_type = ht_sha1;
        challenge += 4;
    }
    else
    {
        challenge += 2;
        if ( '4' == *challenge)
            ht_type = ht_md4;
        else if ( '5' == *challenge)
            ht_type = ht_md5;
        else
             return ERR_OTP_INVALID_ALGORITHM;
        ++challenge;
    }

    /* sequence */
    seq = DIGI_ATOL( challenge, &stop);

    /* next field -> seed */
    challenge = stop;
    while (DIGI_ISSPACE( *challenge)) challenge++;

    seedLen = DIGI_STRLEN( challenge);

    if ( seedLen < 1 || seedLen > 16)
    {
        return ERR_OTP_INVALID_SEED;
    }

    if (OK > ( status = OTP_otp(MOC_HASH(hwAccelCtx) ht_type, challenge, pwd, seq, otpRes)))
        return status;

    /* write out otpRes as a string */
    for (i = 0; i < OTP_RESULT_SIZE; ++i)
    {
        ubyte hh;

        hh = (otpRes[i]) >> 4;
        *res++ = ( hh < 10) ? '0' + hh : 'A' + hh - 10;
        hh = otpRes[i] & 0xF;
        *res++ = ( hh < 10) ? '0' + hh : 'A' + hh - 10;

        if ( i & 1)
        {
            *res++ = ' ';
        }
    }
    *(--res) = '\0'; /* replace last space by NUL */

    return OK;

}


#endif /* __ENABLE_DIGICERT_OTP__ */

