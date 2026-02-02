/*
 * smp_tap_tpm2.h
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
 * @file       smp_tap_tpm2.h
 * @brief      TAP-TPM2 interface header file
 * @details    This header file contains TPM2 specific definitions needed by TAP 
 */


#ifndef __SMP_TAP_TPM2_HEADER__
#define __SMP_TAP_TPM2_HEADER__ 

#define SMP_TPM2_UNKNOWN_TOKEN_ID           0
/*! This token id includes all the crypto objects and NVRAM and SRK objects */
#define SMP_TPM2_CRYPTO_TOKEN_ID            1
/*! This token id has the Endorsement key object and can be used for generating
    attestation keys */
#define SMP_TPM2_ATTESTATION_TOKEN_ID       2
#define SMP_TPM2_PLATFORM_TOKEN_ID          3

#define AIK_OBJECT_ID_START                 0x81010001
#define AIK_OBJECT_ID_END                   (AIK_OBJECT_ID_START + 0xFFF0)

#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
#define EK_OBJECT_ID                        0x81010001
#define SRK_OBJECT_ID_START                 0x81000001
#define SRK_OBJECT_ID_END                   (SRK_OBJECT_ID_START + 0xFFFE)
#else
#define EK_OBJECT_ID                        0x81010000
#define SRK_OBJECT_ID_START                 0x81000000
#define SRK_OBJECT_ID_END                   (SRK_OBJECT_ID_START + 0xFFFF)
#endif

/* TPM2 Entity IDs, used during authorization */
#define TAP_TPM2_RH_SRK_ID             0x40000000
#define TAP_TPM2_RH_EK_ID              0x40000006
#define TAP_TPM2_RH_OWNER_ID           0x40000001
#define TAP_TPM2_RH_ENDORSEMENT_ID     0x4000000B
#define TAP_TPM2_RH_LOCKOUT_ID         0x4000000A

/* TPM2 Capability IDs, used during getcapability */
typedef ubyte4  TAP_TPM2_CAP_T;
#define TAP_TPM2_CAP_FIRST                 ((ubyte4)0x00000000)
#define TAP_TPM2_CAP_ALGS                  ((ubyte4)0x00000000)
#define TAP_TPM2_CAP_HANDLES               ((ubyte4)0x00000001)
#define TAP_TPM2_CAP_COMMANDS              ((ubyte4)0x00000002)
#define TAP_TPM2_CAP_PP_COMMANDS           ((ubyte4)0x00000003)
#define TAP_TPM2_CAP_AUDIT_COMMANDS        ((ubyte4)0x00000004)
#define TAP_TPM2_CAP_PCRS                  ((ubyte4)0x00000005)
#define TAP_TPM2_CAP_TPM_PROPERTIES        ((ubyte4)0x00000006)
#define TAP_TPM2_CAP_PCR_PROPERTIES        ((ubyte4)0x00000007)
#define TAP_TPM2_CAP_ECC_CURVES            ((ubyte4)0x00000008)
#define TAP_TPM2_CAP_LAST                  ((ubyte4)0x00000008)

typedef ubyte4  TAP_TPM2_PT;
#define TAP_TPM2_PT_NONE                   ((ubyte4)0x00000000)
#define TAP_TPM2_PT_GROUP                  ((ubyte4)0x00000100)
#define TAP_TPM2_PT_FIXED                  ((ubyte4)(TAP_TPM2_PT_GROUP * 1))
#define TAP_TPM2_PT_VAR                    ((ubyte4)(TAP_TPM2_PT_GROUP * 2))

#endif /* __SMP_TAP_TPM2_HEADER__ */

