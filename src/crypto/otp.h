/*
 * otp.h
 *
 * One-Time-Password and S/Key Header
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
 * @file       otp.h
 *
 * @brief      Header file for declaring One-Time-Password and S/Key methods.
 * @details    Header file for declaring One-Time-Password and S/Key methods.
 *
 * @flags      To enable the methods in this file please define:
 *             + \c \__ENABLE_DIGICERT_OTP__
 *
 * @filedoc    otp.h
 */

#ifndef __OTP_HEADER__
#define __OTP_HEADER__

/*------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

#define OTP_RESULT_SIZE (8)
#define OTP_STR_RESULT_SIZE (20)

/**
 * @brief   Computes a one-time password.
 *
 * @details Computes a one-time password from a hash type, seed, initial password, and sequence number.
 *
 * @param ht_type  Hash type identifier from ca_mgmt.h. This is one of
 *                 + ht_md4
 *                 + ht_md5
 *                 + ht_sha1
 *
 * @param seed     The initial seed as a character string. This is case insensitive and may be the empty string.
 * @param pwd      The initial password as a character string. This is NOT case insensitive and
 *                 there is no limit on the length of this string.
 * @param seq      The sequence number. This is the number of hashing iterations that will be performed.
 * @param res      Buffer to hold the resulting one time password as a byte array.
 *                 This is 64 bits (8 bytes) in length.
 *
 * @flags      To enable this method please define:
 *             + \c \__ENABLE_DIGICERT_OTP__
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS OTP_otp(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte ht_type, const sbyte* seed, const sbyte* pwd, ubyte4 seq, ubyte res[8]);

/**
 * @brief   Computes a one-time password from a challange string.
 *
 * @details Computes a one-time password from a challange string. This string as described in RFC
 *          2289 consists of "otp-<hash identifier> <sequence integer> <seed>" where the spaces shown
 *          must be present and hash identifier is "md4", "md5", or "sha1".
 *
 * @param challenge A challange string in the form described above.
 * @param pwd       The initial password as a character string. This is NOT case insensitive and
 *                  there is no limit on the length of this string.
 * @param res       Buffer to hold the resulting one time password as a string. This will be 19 characters
 *                  plus the '\0' terminating character.
 *
 * @flags      To enable this method please define:
 *             + \c \__ENABLE_DIGICERT_OTP__
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS OTP_otpEx(MOC_HASH(hwAccelDescr hwAccelCtx) const sbyte* challenge, const sbyte* pwd, sbyte res[20]);

#ifdef __cplusplus
}
#endif

#endif /* __OTP_HEADER__ */

