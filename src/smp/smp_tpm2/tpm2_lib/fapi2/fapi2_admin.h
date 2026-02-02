/**
 * @file fapi2_admin.h
 * @brief This file contains code and structures required for provisioning
 * the TPM2.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __FAPI2_ADMIN_H__
#define __FAPI2_ADMIN_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This API clears the TPM2 using TPM2_Clear() and changes
 * the hierarchy authorizations using TPM2_HierarchyChangeAuth()
 * for the LockOut, Owner and Endorsement Hierarchies.
 * Clearing the TPM requires the lockout or platform authorization
 * but typical administrators will not have the platform authorization,
 * which is usually set by firmware/OEM.
 * The passwords/authorization values must have high entropy and
 * typically be at least 32 bytes long for good security.
 * They can be a random number or passwords that have been hashed
 * or run through algorithms like PBKDF2.
 * All new authValues must be provided. The value set in the context via
 * FAPI2_CONTEXT_setHierarchyAuth will be used for lockoutAuth.
 */

MOC_EXTERN TSS2_RC FAPI2_ADMIN_takeOwnership(
        FAPI2_CONTEXT *pCtx,
        AdminTakeOwnershipIn *pIn
        );

/*
 * This API clears the TPM2 using TPM2_Clear(). All existing TPM objects
 * are invalidated and all authValues are cleared. This requires lockout
 * authorization or platform authorization. Platform authorization will
 * typically not be available since it is set by firmware/OEM. The lockOut
 * authValue must be set in the context passed into this command.
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_releaseOwnership(
        FAPI2_CONTEXT *pCtx
);

/*
 * This API clears the TPM2 using TPM2_Clear(). All existing TPM objects
 * are invalidated and all authValues are cleared. This function uses 
 * platform authorization. 
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_forceClear(
        FAPI2_CONTEXT *pCtx
);

/*
 * This function creates the RSA or ECC endorsement key for the TPM
 * using the default templates provided in the
 * TCG EK Credential Profile document.
 * If the EK is deemed to be privacy sensitive, the key is created as a
 * restricted decryption key. If not, it will be created as a restricted
 * signing key, essentially making the EK an attestation key(AK or AIK).
 * An authValue may be provided in the input. If an authValue of size 0 is
 * provided, the authValue is set to the endorsement hierarchy password.
 * The authValue supplied is only used if the key is not privacy sensitive.
 * The TCG default policy will be used, which requires the endorsement hierarchy
 * password to use the EK.
 * The authPolicy is set per the TCG EK Credential Profile document as well.
 * No values are returned since the EK will be persisted at a known location.
 * If the key is an RSA key:
 * RSA Key size: 2048 bits, exponent = 65535, Signature scheme:RSASSA_PKSC1V1.5
 * with SHA256 or NULL if the EK is privacy sensitive.
 * if the key is an ECC Key:
 * ECC curveID: TPM2_ECC_NIST_P256, Signature scheme:TPM2_ALG_ECDSA if the
 * key is an attestation key(not privacy sensitive) and
 * TPM2_ALG_NULL if the EK is privacy sensitive.
 * The EK is created at the handle FAPI2_RH_EK
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_createEK(
        FAPI2_CONTEXT *pCtx,
        AdminCreateEKIn *pIn
);

/*
 * This function creates the RSA or ECC storage root key for the TPM
 * using the default templates provided in the
 * TCG EK Credential Profile document.
 * An authValue may be provided in the input. If an authValue of size 0
 * us provided, the authValue is used as is.
 * No values are returned since the SRK will be persisted at a known location.
 * If the key is an RSA key:
 * RSA Key size: 2048 bits, exponent = 65535.
 * if the key is an ECC Key:
 * ECC curveID: TPM2_ECC_NIST_P256
 * The SRK is created at the handle FAPI2_RH_SRK
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_createSRK(
        FAPI2_CONTEXT *pCtx,
        AdminCreateSRKIn *pIn
);

/*
 * This function creates the RSA or ECC Attestation Key for the TPM
 * using the template provided in the input parameters.
 * No values are returned since the AK will be persisted at a known location.
 * The AK is created at the handle provided in the input parameters.
 */

MOC_EXTERN TSS2_RC FAPI2_ADMIN_createAK(
        FAPI2_CONTEXT *pCtx,
        AdminCreateAKIn *pIn
);

/*
 * This API can be used to get the public key of primary keys from the TPM.
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_getPrimaryPublicKey(
        FAPI2_CONTEXT *pCtx,
        AdminGetPrimaryPublicKeyIn *pIn,
        AdminGetPrimaryPublicKeyOut *pOut
);

/*
 * This API can be used to clear locked out TPM 
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_clearDALockout(
        FAPI2_CONTEXT *pCtx
);

/*
 * This API programs DA lockout parameters on TPM2 using TPM2_DictonaryAttackParameters(). 
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_setDAParameters(
        FAPI2_CONTEXT *pCtx, ubyte4 maxAuthFailures, ubyte4 recoveryTime,
        ubyte4 lockoutRecoveryTime
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_ADMIN_H__ */
