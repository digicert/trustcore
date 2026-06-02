/**
 * @file  ike2_nist.h
 * @brief IKEv2 NIST SP 800-135 test functions
 *
 * @details    Function prototypes for testing IKEv2 against SP 800-135
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_SP800_135_ACVP__
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

#ifndef __IKE2_NIST_H__
#define __IKE2_NIST_H__

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

enum {
    IkeInitiatorNonce = 1,
    IkeResponderNonce = 2,
    IkeInitiatorIndex = 3,
    IkeResponderIndex = 4,
    IkeSharedSecret =   5,
    IkeSKEYSEED =       6,
    IkeDKM =            7,
    IkeDKMChildSa =     8
};

/* Set the IKE SA */
MSTATUS setIKESA(IKE_context pCtx, IKESA pSa);

/* Set the IKE old SA */
MSTATUS setIKEOldSA(IKE_context pCtx, IKESA pSa);

/* Set the desired length of the Derived Keying Material (DKM) */
MSTATUS setIKEDkmLen(IKESA pSa, ubyte hashAlg, ubyte4 dkmLen);

/* Set the desired length of the Derived Keying Material (DKM) for the child SA */
MSTATUS setIKEChildDkmLen(IKE_context pCtx, ubyte hashAlg, ubyte4 childDkmLen);

/* Set the new shared secret g^ir (new). This function is only 
 * used for setting g^ir (new) for generating Child SA DH DKM */
MSTATUS setIKENewSharedSecret(IKE_context pCtx, ubyte *pValue, ubyte4 valueLen);

/* Set a value in the IKE SA. Type must be one of 
 * {IkeInitiatorNonce, IkeResponderNonce, IkeInitiatorIndex, IkeResponderIndex, IkeSharedSecret} */
MSTATUS setIKEValue(IKESA pSa, ubyte type, ubyte *pValue, ubyte4 valueLen);

/* Get a value from the IKE ctx. Type must be one of {IkeSKEYSEED, IkeDKM, IkeDKMChildSa}.
 * Values are allocated by this function, caller responsible for freeing newly allocated bufffer */
MSTATUS getIKEValue(IKE_context ctx, ubyte type, ubyte **ppValue, ubyte4 *pValueLen);

/* IKE function that performs key derivation */
extern MSTATUS DoKe(IKE_context ctx);

/* IKE function that generates Child SA DKM */
extern MSTATUS DoKe2(IKE_context ctx);

/* IKE function to free an allocated SA */
void FreeSa(IKESA pxSa);

#endif
#endif
