/*
 * ssh_str_house.h
 *
 * SSH String Storehouse Header
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

#ifndef __SSH_STR_HOUSE_HEADER__
#define __SSH_STR_HOUSE_HEADER__

MOC_EXTERN sshStringBuffer ssh_disconnectMesg;
MOC_EXTERN sshStringBuffer ssh_disconnectAuthMesg;
MOC_EXTERN sshStringBuffer ssh_languageTag;

MOC_EXTERN sshStringBuffer ssh_kexMethods;
MOC_EXTERN sshStringBuffer ssh_hostKeyMethods;
MOC_EXTERN sshStringBuffer ssh_encC2SMethods;
MOC_EXTERN sshStringBuffer ssh_encS2CMethods;
MOC_EXTERN sshStringBuffer ssh_macC2SMethods;
MOC_EXTERN sshStringBuffer ssh_macS2CMethods;
MOC_EXTERN sshStringBuffer ssh_compC2SMethods;
MOC_EXTERN sshStringBuffer ssh_compS2CMethods;
MOC_EXTERN sshStringBuffer ssh_langC2SMethods;
MOC_EXTERN sshStringBuffer ssh_langS2CMethods;

MOC_EXTERN sshStringBuffer ssh_dss_signature;
MOC_EXTERN sshStringBuffer ssh_rsa_signature;
MOC_EXTERN sshStringBuffer ssh_rsasha256_signature;
MOC_EXTERN sshStringBuffer ssh_rsasha512_signature;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature_p192;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature_p224;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature_p256;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature_p384;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature_p521;
MOC_EXTERN sshStringBuffer ssh_ecdsa_signature_ed25519;
MOC_EXTERN sshStringBuffer ssh_ecdsa_curve_p192;
MOC_EXTERN sshStringBuffer ssh_ecdsa_curve_p224;
MOC_EXTERN sshStringBuffer ssh_ecdsa_curve_p256;
MOC_EXTERN sshStringBuffer ssh_ecdsa_curve_p384;
MOC_EXTERN sshStringBuffer ssh_ecdsa_curve_p521;
#ifdef __ENABLE_MOCANA_PQC__
MOC_EXTERN sshStringBuffer ssh_mldsa44_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa65_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa87_signature;
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
MOC_EXTERN sshStringBuffer ssh_cert_mldsa44_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa65_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa87_signature;
#endif
#endif /* __ENABLE_MOCANA_PQC__ */
#ifdef __ENABLE_MOCANA_PQC_COMPOSITE__
MOC_EXTERN sshStringBuffer ssh_mldsa44_p256_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa65_p256_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa87_p384_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa44_ed25519_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa65_ed25519_signature;
MOC_EXTERN sshStringBuffer ssh_mldsa87_ed448_signature;
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
MOC_EXTERN sshStringBuffer ssh_cert_mldsa44_p256_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa65_p256_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa87_p384_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa44_ed25519_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa65_ed25519_signature;
MOC_EXTERN sshStringBuffer ssh_cert_mldsa87_ed448_signature;
#endif
#endif /* __ENABLE_MOCANA_PQC_COMPOSITE__ */
MOC_EXTERN sshStringBuffer ssh_rsa_sha1_signature;
MOC_EXTERN sshStringBuffer ssh_rsa_cert_sign_signature;
MOC_EXTERN sshStringBuffer ssh_rsa2048_cert_sign_signature;
MOC_EXTERN sshStringBuffer ssh_rsasha256_cert_signature;
MOC_EXTERN sshStringBuffer ssh_ecdsa_cert_signature_p192;
MOC_EXTERN sshStringBuffer ssh_ecdsa_cert_signature_p224;
MOC_EXTERN sshStringBuffer ssh_ecdsa_cert_signature_p256;
MOC_EXTERN sshStringBuffer ssh_ecdsa_cert_signature_p384;
MOC_EXTERN sshStringBuffer ssh_ecdsa_cert_signature_p521;
MOC_EXTERN sshStringBuffer ssh_userAuthService;
MOC_EXTERN sshStringBuffer ssh_connectService;
MOC_EXTERN sshStringBuffer ssh_authMethods;

MOC_EXTERN sshStringBuffer ssh_sessionService;
MOC_EXTERN sshStringBuffer ssh_forwardService;
MOC_EXTERN sshStringBuffer ssh_cancelforwardService;
MOC_EXTERN sshStringBuffer ssh_forwardedService;
MOC_EXTERN sshStringBuffer ssh_directService;
MOC_EXTERN sshStringBuffer ssh_channelUnknown;
MOC_EXTERN sshStringBuffer ssh_resourceShort;
MOC_EXTERN sshStringBuffer ssh_terminalType;
MOC_EXTERN sshStringBuffer ssh_shellType;
MOC_EXTERN sshStringBuffer ssh_execRequest;
MOC_EXTERN sshStringBuffer ssh_subSystem;
MOC_EXTERN sshStringBuffer ssh_windowChange;
MOC_EXTERN sshStringBuffer ssh_breakOperation;

#ifdef __ENABLE_MOCANA_SSH_PING__
MOC_EXTERN sshStringBuffer ssh_pingChannel;
#endif


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_HOUSE_initStringBuffer(sshStringBuffer *p_sshStringBuffer, sbyte *pString);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_HOUSE_initStringBuffers(void);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_HOUSE_freeStringBuffers(void);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_HOUSE_createFromList(sshStringBuffer *p_sshStringBuffer, sbyte *(*callbackList)(ubyte4, ubyte4 *, ubyte4), ubyte4 cookie);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_HOUSE_createFromList1(sshStringBuffer *p_sshStringBuffer, sbyte4 iterations, sbyte *(*callbackList)(ubyte4, ubyte4 *, void *), void *pCookie);

#endif /* __SSH_STR_HOUSE_HEADER__ */
