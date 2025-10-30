
/**
 * @file smp_cc.h
 *
 * @brief This file contains the NanoSMP command codes
 * @details This file contains the NanoSMP command codes
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_SMP__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#ifndef __SMP_CC_HEADER__
#define __SMP_CC_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"

#if defined(__ENABLE_MOCANA_SMP__)

typedef ubyte2 SMP_CC;

#define SMP_CC_INVALID                                  (SMP_CC)0
#define SMP_CC_GET_MODULE_LIST                          (SMP_CC)1
#define SMP_CC_FREE_MODULE_LIST                         (SMP_CC)2
#define SMP_CC_GET_MODULE_INFO                          (SMP_CC)3
#define SMP_CC_GET_MODULE_SLOTS                         (SMP_CC)4
#define SMP_CC_GET_TOKEN_LIST                           (SMP_CC)5
#define SMP_CC_GET_TOKEN_INFO                           (SMP_CC)6
#define SMP_CC_GET_OBJECT_LIST                          (SMP_CC)7
#define SMP_CC_GET_OBJECT_INFO                          (SMP_CC)8
#define SMP_CC_PROVISION_MODULE                         (SMP_CC)9
#define SMP_CC_RESET_MODULE                             (SMP_CC)10
#define SMP_CC_PROVISION_TOKEN                          (SMP_CC)11
#define SMP_CC_RESET_TOKEN                              (SMP_CC)12
#define SMP_CC_DELETE_TOKEN                             (SMP_CC)13
#define SMP_CC_INIT_MODULE                              (SMP_CC)14
#define SMP_CC_UNINIT_MODULE                            (SMP_CC)15
#define SMP_CC_ASSOCIATE_MODULE_CREDENTIALS             (SMP_CC)16
#define SMP_CC_INIT_TOKEN                               (SMP_CC)17
#define SMP_CC_UNINIT_TOKEN                             (SMP_CC)18
#define SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS              (SMP_CC)19
#define SMP_CC_INIT_OBJECT                              (SMP_CC)20
#define SMP_CC_IMPORT_OBJECT                            (SMP_CC)21
#define SMP_CC_UNINIT_OBJECT                            (SMP_CC)22
#define SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS             (SMP_CC)23
#define SMP_CC_VERIFY                                   (SMP_CC)24
#define SMP_CC_VERIFY_INIT                              (SMP_CC)25
#define SMP_CC_VERIFY_UPDATE                            (SMP_CC)26
#define SMP_CC_VERIFY_FINAL                             (SMP_CC)27
#define SMP_CC_SIGN_DIGEST                              (SMP_CC)28
#define SMP_CC_SIGN_BUFFER                              (SMP_CC)29
#define SMP_CC_SIGN_INIT                                (SMP_CC)30
#define SMP_CC_SIGN_UPDATE                              (SMP_CC)31
#define SMP_CC_SIGN_FINAL                               (SMP_CC)32
#define SMP_CC_FREE_SIGNATURE_BUFFER                    (SMP_CC)33
#define SMP_CC_ENCRYPT                                  (SMP_CC)34
#define SMP_CC_ENCRYPT_INIT                             (SMP_CC)35
#define SMP_CC_ENCRYPT_UPDATE                           (SMP_CC)36
#define SMP_CC_ENCRYPT_FINAL                            (SMP_CC)37
#define SMP_CC_DECRYPT                                  (SMP_CC)38
#define SMP_CC_DECRYPT_INIT                             (SMP_CC)39
#define SMP_CC_DECRYPT_UPDATE                           (SMP_CC)40
#define SMP_CC_DECRYPT_FINAL                            (SMP_CC)41
#define SMP_CC_DIGEST                                   (SMP_CC)42
#define SMP_CC_DIGEST_INIT                              (SMP_CC)43
#define SMP_CC_DIGEST_UPDATE                            (SMP_CC)44
#define SMP_CC_DIGEST_FINAL                             (SMP_CC)45
#define SMP_CC_GET_RANDOM                               (SMP_CC)46
#define SMP_CC_STIR_RANDOM                              (SMP_CC)47
#define SMP_CC_GET_TRUSTED_DATA                         (SMP_CC)48
#define SMP_CC_UPDATE_TRUSTED_DATA                      (SMP_CC)49
#define SMP_CC_SEAL_WITH_TRUSTED_DATA                   (SMP_CC)50
#define SMP_CC_UNSEAL_WITH_TRUSTED_DATA                 (SMP_CC)51
#define SMP_CC_SET_POLICY_STORAGE                       (SMP_CC)52
#define SMP_CC_GET_POLICY_STORAGE                       (SMP_CC)53
#define SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS (SMP_CC)54
#define SMP_CC_UNWRAP_KEY_VALIDATED_SECRET              (SMP_CC)55
#define SMP_CC_SMP_GET_QUOTE                            (SMP_CC)56
#define SMP_CC_CREATE_ASYMMETRIC_KEY                    (SMP_CC)57
#define SMP_CC_GET_PUBLIC_KEY                           (SMP_CC)58
#define SMP_CC_FREE_PUBLIC_KEY                          (SMP_CC)59
#define SMP_CC_CREATE_SYMMETRIC_KEY                     (SMP_CC)60
#define SMP_CC_EXPORT_OBJECT                            (SMP_CC)61
#define SMP_CC_SERIALIZE_OBJECT                         (SMP_CC)62
#define SMP_CC_CREATE_OBJECT                            (SMP_CC)63
#define SMP_CC_DELETE_OBJECT                            (SMP_CC)64
#define SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE            (SMP_CC)65
#define SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE             (SMP_CC)66
#define SMP_CC_GET_LAST_ERROR                           (SMP_CC)67
#define SMP_CC_SELF_TEST                                (SMP_CC)68
#define SMP_CC_SELF_TEST_POLL                           (SMP_CC)69
#define SMP_CC_GET_PUBLIC_KEY_BLOB                      (SMP_CC)70
#define SMP_CC_DUPLICATEKEY                             (SMP_CC)71
#define SMP_CC_IMPORTDUPLICATEKEY                       (SMP_CC)72
#define SMP_CC_GET_MODULE_CAPABILITY                    (SMP_CC)73
#define SMP_CC_ECDH_GENERATE_SHARED_SECRET              (SMP_CC)74
#define SMP_CC_PURGE_OBJECT                             (SMP_CC)75
#define SMP_CC_IMPORT_EXTERNAL_KEY                      (SMP_CC)76
#define SMP_CC_EVICT_OBJECT                             (SMP_CC)77
#define SMP_CC_PERSIST_OBJECT                           (SMP_CC)78
#define SMP_CC_GET_PRIVATE_KEY_BLOB                     (SMP_CC)79
#define SMP_CC_LAST                                     (SMP_CC_GET_PRIVATE_KEY_BLOB+1)

#endif /* __ENABLE_MOCANA_SMP__ */
#endif /* __SMP_CC_HEADER__ */
