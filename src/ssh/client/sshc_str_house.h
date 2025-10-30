/*
 * sshc_str_house.h
 *
 * SSHC String Storehouse Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __SSHC_STR_HOUSE_HEADER__
#define __SSHC_STR_HOUSE_HEADER__

MOC_EXTERN sshStringBuffer sshc_disconnectMesg;
MOC_EXTERN sshStringBuffer sshc_languageTag;

MOC_EXTERN sshStringBuffer sshc_kexMethods;
MOC_EXTERN sshStringBuffer sshc_hostKeyMethods;
MOC_EXTERN sshStringBuffer sshc_encC2SMethods;
MOC_EXTERN sshStringBuffer sshc_encS2CMethods;
MOC_EXTERN sshStringBuffer sshc_macC2SMethods;
MOC_EXTERN sshStringBuffer sshc_macS2CMethods;
MOC_EXTERN sshStringBuffer sshc_compC2SMethods;
MOC_EXTERN sshStringBuffer sshc_compS2CMethods;
MOC_EXTERN sshStringBuffer sshc_langC2SMethods;
MOC_EXTERN sshStringBuffer sshc_langS2CMethods;

MOC_EXTERN sshStringBuffer sshc_dss_signature;
MOC_EXTERN sshStringBuffer sshc_rsa_signature;
MOC_EXTERN sshStringBuffer sshc_rsa2048sha256_signature;
MOC_EXTERN sshStringBuffer sshc_rsa2048sha512_signature;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature_p192;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature_p224;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature_p256;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature_p384;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature_p521;
MOC_EXTERN sshStringBuffer sshc_ecdsa_signature_ed25519;
MOC_EXTERN sshStringBuffer sshc_ecdsa_curve_p192;
MOC_EXTERN sshStringBuffer sshc_ecdsa_curve_p224;
MOC_EXTERN sshStringBuffer sshc_ecdsa_curve_p256;
MOC_EXTERN sshStringBuffer sshc_ecdsa_curve_p384;
MOC_EXTERN sshStringBuffer sshc_ecdsa_curve_p521;

#ifdef __ENABLE_MOCANA_PQC__
MOC_EXTERN sshStringBuffer sshc_mldsa44_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa65_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa87_signature;
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
MOC_EXTERN sshStringBuffer sshc_cert_mldsa44_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa65_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa87_signature;
#endif
#endif /* __ENABLE_MOCANA_PQC__ */

#ifdef __ENABLE_MOCANA_PQC_COMPOSITE__
MOC_EXTERN sshStringBuffer sshc_mldsa44_p256_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa65_p256_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa87_p384_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa44_ed25519_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa65_ed25519_signature;
MOC_EXTERN sshStringBuffer sshc_mldsa87_ed448_signature;
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
MOC_EXTERN sshStringBuffer sshc_cert_mldsa44_p256_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa65_p256_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa87_p384_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa44_ed25519_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa65_ed25519_signature;
MOC_EXTERN sshStringBuffer sshc_cert_mldsa87_ed448_signature;
#endif
#endif /* __ENABLE_MOCANA_PQC_COMPOSITE__ */

MOC_EXTERN sshStringBuffer sshc_cert_sign_signature;
MOC_EXTERN sshStringBuffer sshc_rsa2048_cert_sign_signature;
MOC_EXTERN sshStringBuffer sshc_rsa2048sha256_cert_signature;
MOC_EXTERN sshStringBuffer sshc_ecdsa_cert_signature_p192;
MOC_EXTERN sshStringBuffer sshc_ecdsa_cert_signature_p224;
MOC_EXTERN sshStringBuffer sshc_ecdsa_cert_signature_p256;
MOC_EXTERN sshStringBuffer sshc_ecdsa_cert_signature_p384;
MOC_EXTERN sshStringBuffer sshc_ecdsa_cert_signature_p521;
MOC_EXTERN sshStringBuffer sshc_ecdsasha256_signature;
MOC_EXTERN sshStringBuffer sshc_ecdsasha384_signature;
MOC_EXTERN sshStringBuffer sshc_ecdsasha512_signature;
MOC_EXTERN sshStringBuffer sshc_userAuthService;
MOC_EXTERN sshStringBuffer sshc_connectService;
MOC_EXTERN sshStringBuffer sshc_authMethods;

MOC_EXTERN sshStringBuffer sshc_sessionService;
MOC_EXTERN sshStringBuffer sshc_lpfSessionService;
MOC_EXTERN sshStringBuffer sshc_rpfForwardService;
MOC_EXTERN sshStringBuffer sshc_rpfCancelForwardService;
MOC_EXTERN sshStringBuffer sshc_channelUnknown;
MOC_EXTERN sshStringBuffer sshc_resourceShort;
MOC_EXTERN sshStringBuffer sshc_ptyTerminal;
MOC_EXTERN sshStringBuffer sshc_terminalEnv;
MOC_EXTERN sshStringBuffer sshc_shellType;
MOC_EXTERN sshStringBuffer sshc_subSystem;
MOC_EXTERN sshStringBuffer sshc_windowChange;
MOC_EXTERN sshStringBuffer sshc_breakOperation;

MOC_EXTERN sshStringBuffer sshc_sftpExec;

MOC_EXTERN sshStringBuffer sshc_authPassword;
MOC_EXTERN sshStringBuffer sshc_authPublicKey;


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_STR_HOUSE_initStringBuffer(sshStringBuffer *p_sshStringBuffer, sbyte *pString);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_STR_HOUSE_initStringBuffers(void);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_STR_HOUSE_freeStringBuffers(void);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_STR_HOUSE_createFromList(sshStringBuffer *p_sshStringBuffer, sbyte *(*callbackList)(ubyte4, ubyte4 *, ubyte4), ubyte4 cookie);

#endif /* __SSHC_STR_HOUSE_HEADER__ */
