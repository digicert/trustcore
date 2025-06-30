/*
 * srp.h
 *
 * Secure Remote Protocol
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
 * @file       srp.h
 *
 * @brief      Header file for declaring Secure Remote Protocol methods.
 * @details    Header file for declaring Secure Remote Protocol methods.
 *
 * @flags      To enable the methods in this file please define:
 *             + \c \__ENABLE_MOCANA_SRP__
 *
 * @filedoc    srp.h
 */

/*------------------------------------------------------------------*/

#ifndef __SRP_HEADER__
#define __SRP_HEADER__

#ifndef __MOCANA_MIN_SRP_BITS__
#define __MOCANA_MIN_SRP_BITS__   (2048)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Gets the SRP Group parameters.
 *
 * @details Gets the SRP Group parameters, which are fixed groups dependent on the bit size requested.
 *          This method will allocate three \vlong elements. Be sure to call \c VLONG_freeVlong on
 *          each when done with them.
 *
 * @param bitNum     The bit size requested. The acceptable values are 2048, 3072, 4096, 6144, and 8192.
 *                   If + \c \__MOCANA_MIN_SRP_BITS__ is defined to 1024, or 1536 then those sizes are also acceptable.
 * @param modulus    Pointer to the location of the modulus for the bit size requested.
 * @param generator  Pointer to the location of the group generator for the bit size requested.
 * @param k          Pointer to the location of the k parameter (a SHA1 hash dependent on the modulus and generator).
 *
 * @flags      To enable this method please define:
 *             + \c \__ENABLE_MOCANA_SRP__
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS SRP_getGroupParameters( ubyte4 bitNum,
                                           vlong** modulus,
                                           vlong** generator,
                                           vlong** k);

/**
 * @brief   Gets the SRP Group parameters in Big Endian byte array form.
 *
 * @details Gets the SRP Group parameters, which are fixed groups dependent on the bit size requested.
 *          This method will get them in Big Endian byte array form. This method does not allocate
 *          any memeory.
 *
 * @param bitNum       The bit size requested. The acceptable values are 2048, 3072, 4096, 6144, and 8192.
 *                     If + \c \__MOCANA_MIN_SRP_BITS__ is defined to 1024, or 1536 then those sizes are also acceptable.
 * @param modulus      Contents will be set to the location of the modulus for the bit size requested.
 * @param modulusLen   Contents will be set to the size of the modulus in bytes.
 * @param generator    Contents will be set to the location of the group generator for the bit size requested.
 * @param generatorLen Contents will be set to the size of the group generator in bytes.
 * @param k            Contents will be set to the location of the k parameter (a SHA1 hash dependent on
 *                     the modulus and generator). The size of k in bytes is always 20.
 *
 * @flags      To enable this method please define:
 *             + \c \__ENABLE_MOCANA_SRP__
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS SRP_getGroupParameters2( ubyte4 bitNum,
                                            const ubyte** modulus,
                                            sbyte4* modulusLen,
                                            const ubyte** generator,
                                            sbyte4* generatorLen,
                                            const ubyte** k);

/**
 * @brief   Computes the verifier for a user.
 *
 * @details Computes the verifier for a user. This is dependent on the user's username and password, and
 *          the user's random salt. Memory will be allocated for a buffer to hold the verifier. Be sure to free
 *          this buffer when done with it.
 *
 * @param salt         The user's randomly generated salt.
 * @param saltLen      The length of the salt in bytes.
 * @param uname        The username as a byte array.
 * @param unameLen     The length of the username in bytes.
 * @param pw           The user's password as a byte array.
 * @param pwLen        The length of the user's password in bytes.
 * @param bitNum       The bit size for the group requested. The acceptable values are 2048, 3072, 4096, 6144, and 8192.
 *                     If + \c \__MOCANA_MIN_SRP_BITS__ is defined to 1024, or 1536 then those sizes are also acceptable.
 * @param verifier     Pointer to the location that will receive the verifier as a newly allocated byte array.
 * @param verifierLen  Contents will be set to the length of the verifier in bytes.
 *
 * @flags      To enable this method please define:
 *             + \c \__ENABLE_MOCANA_SRP__
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS SRP_computeVerifier(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           const ubyte* salt, ubyte4 saltLen,
                                           const ubyte* uname, ubyte4 unameLen,
                                           const ubyte* pw, ubyte4 pwLen,
                                           ubyte4 bitNum,
                                           ubyte** verifier, ubyte4* verifierLen);

#ifdef __cplusplus
}
#endif

#endif /* __SRP_HEADER__ */
