/*
 * rsa_simple.h
 *
 * RSA public key encryption
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


/*------------------------------------------------------------------*/

#ifndef __RSA_SIMPLE_H__
#define __RSA_SIMPLE_H__

#if (defined(__ENABLE_MOCANA_RSA_SIMPLE__) && defined(__ENABLE_MOCANA_ECC__))

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS RSA_SIMPLE_verifySignature(sbyte4 k,
                            const pf_unit modulus[/*k+1*/],
                            const pf_unit mu[/*k+1*/],
                            sbyte4 modulusLen,
                            ubyte4 e,
                            const ubyte cipherText[/*modulusLen*/],
                            const ubyte* plainText,
                            ubyte4 plainTextLen);

MOC_EXTERN MSTATUS RSA_SIMPLE_sign(sbyte4 n,
                        ubyte s[/*n*sizeof(pf_unit)*/],
                        const ubyte* msg, ubyte4 msgLen,
                        const pf_unit p[/*n/2+1*/],
                        const pf_unit mu_p[/*n/2+1*/],
                        const pf_unit dp[/*n/2*/],
                        const pf_unit q[/*n/2+1*/],
                        const pf_unit mu_q[/*n/2+1*/],
                        const pf_unit dq[/*n/2*/],
                        const pf_unit qinv[/*n/2*/]);

MOC_EXTERN MSTATUS RSA_SIMPLE_sign_blind(sbyte4 n,
                        ubyte s[/*n*sizeof(pf_unit)*/],
                        const ubyte* msg, ubyte4 msgLen,
                        const pf_unit p[/*n/2+1*/],
                        const pf_unit mu_p[/*n/2+1*/],
                        const pf_unit dp[/*n/2*/],
                        const pf_unit q[/*n/2+1*/],
                        const pf_unit mu_q[/*n/2+1*/],
                        const pf_unit dq[/*n/2*/],
                        const pf_unit qinv[/*n/2*/],
                        const pf_unit modulus[/*n+1*/],
                        const pf_unit mu_modulus[/*n+1*/],
                        pf_unit re[/*n*/],
                        pf_unit r1[/*n*/]);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_MOCANA_RSA_SIMPLE__ */

#endif /* __RSA_SIMPLE_H__ */
