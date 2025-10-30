/*
 * oiddefs.h
 *
 * OID Definitions
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

#ifndef __OIDDEFS_HEADER__
#define __OIDDEFS_HEADER__


#ifdef __cplusplus
extern "C" {
#endif

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif

#ifdef __RTOS_WIN32__
  #ifdef WIN_ASN1_EXPORT
    #define MOC_EXTERN_P __declspec(dllexport)
  #else
    #define MOC_EXTERN_P __declspec(dllimport)
  #endif /* WIN_ASN1_EXPORT */

  #ifdef WIN_STATIC
    #undef MOC_EXTERN_P
    #define MOC_EXTERN_P extern
  #endif
#else
  #define MOC_EXTERN_P extern
#endif /* RTOS_WIN32 */

/* all OIDS are length prefixed, i.e. the first byte is the length of the rest */

/* OID */
MOC_EXTERN const ubyte pkcs1_OID[]; /* 1.2.840.113549.1.1 */
#define PKCS1_OID_LEN   (8)
#define MAX_SIG_OID_LEN (1 + PKCS1_OID_LEN)
#define MAX_PQC_OID_LEN 12 /* 11 bytes plus a length */

#if 0
enum {
    rsaEncryption = 1,
    md2withRSAEncryption = 2,
    md4withRSAEncryption = 3,
    md5withRSAEncryption = 4,
    sha1withRSAEncryption = 5,
    sha256withRSAEncryption = 11,
    sha384withRSAEncryption = 12,
    sha512withRSAEncryption = 13,
    sha224withRSAEncryption = 14
};
#endif

MOC_EXTERN const ubyte rsaEncryption_OID[];             /* 1.2.840.113549.1.1.1  (repeat for convenience)*/
MOC_EXTERN const ubyte rsaEsOaep_OID[];                    /* 1.2.840.113549.1.1.7  (repeat for convenience)*/
MOC_EXTERN const ubyte pkcs1Mgf_OID[];                     /* 1.2.840.113549.1.1.8   (repeat for convenience)*/
MOC_EXTERN const ubyte pSpecified_OID[];                    /* 1.2.840.113549.1.1.9  (repeat for convenience)*/
MOC_EXTERN const ubyte rsaSsaPss_OID[];                    /* 1.2.840.113549.1.1.10  (repeat for convenience)*/
MOC_EXTERN const ubyte md5withRSAEncryption_OID[];      /* 1.2.840.113549.1.1.4  (repeat for convenience)*/
MOC_EXTERN const ubyte sha1withRSAEncryption_OID[];      /* 1.2.840.113549.1.1.5  (repeat for convenience)*/
MOC_EXTERN const ubyte sha256withRSAEncryption_OID[];      /* 1.2.840.113549.1.1.11  (repeat for convenience)*/
MOC_EXTERN const ubyte sha384withRSAEncryption_OID[];      /* 1.2.840.113549.1.1.12 (repeat for convenience)*/
MOC_EXTERN const ubyte sha512withRSAEncryption_OID[];      /* 1.2.840.113549.1.1.13 (repeat for convenience)*/
MOC_EXTERN const ubyte sha224withRSAEncryption_OID[];      /* 1.2.840.113549.1.1.14 (repeat for convenience)*/

#ifdef __ENABLE_MOCANA_CV_CERT__
MOC_EXTERN const ubyte cvc_rsaWithSha1_OID[]; /* 0.4.0.127.0.7.2.2.2.1.1 */

MOC_EXTERN const ubyte cvc_rsaWithSha256_OID[]; /* 0.4.0.127.0.7.2.2.2.1.2 */

MOC_EXTERN const ubyte cvc_rsaPssWithSha1_OID[]; /* 0.4.0.127.0.7.2.2.2.1.3 */

MOC_EXTERN const ubyte cvc_rsaPssWithSha256_OID[]; /* 0.4.0.127.0.7.2.2.2.1.4 */
#endif

MOC_EXTERN const ubyte rsaDSI_OID[];            /* 1 2 840 113549 2 */
/* suffixes of rsaDSI_OID */
enum {
    md2Digest = 2,
    md4Digest = 4,
    md5Digest = 5,
    hmacSHA1Digest = 7,
    hmacSHA224Digest = 8,
    hmacSHA256Digest = 9,
    hmacSHA384Digest = 10,
    hmacSHA512Digest = 11
};

MOC_EXTERN const ubyte md5_OID[];            /*1 2 840 113549 2 5 (repeat for convenience) */
MOC_EXTERN const ubyte hmacWithSHA1_OID[];   /*1 2 840 113549 2 7 (repeat for convenience) */
MOC_EXTERN const ubyte hmacWithSHA224_OID[]; /*1 2 840 113549 2 8 (repeat for convenience) */
MOC_EXTERN const ubyte hmacWithSHA256_OID[]; /*1 2 840 113549 2 9 (repeat for convenience) */
MOC_EXTERN const ubyte hmacWithSHA384_OID[]; /*1 2 840 113549 2 10 (repeat for convenience) */
MOC_EXTERN const ubyte hmacWithSHA512_OID[]; /*1 2 840 113549 2 11 (repeat for convenience) */

MOC_EXTERN const ubyte commonName_OID[];				/* 2.5.4.3 */
MOC_EXTERN const ubyte serialNumber_OID[];				/* 2.5.4.5 */
MOC_EXTERN const ubyte countryName_OID[];               /* 2.5.4.6 */
MOC_EXTERN const ubyte localityName_OID[];              /* 2 5 4 7 */
MOC_EXTERN const ubyte stateOrProvinceName_OID[];       /* 2 5 4 8 */
MOC_EXTERN const ubyte organizationName_OID[];          /* 2 5 4 10 */
MOC_EXTERN const ubyte organizationalUnitName_OID[];    /* 2 5 4 11 */

MOC_EXTERN const ubyte businessCategory_OID[];          /* 2 5 4 15 */
MOC_EXTERN const ubyte postalCode_OID[];                /* 2 5 4 17 */
MOC_EXTERN const ubyte streetAddress_OID[];             /* 2 5 4 9 */

MOC_EXTERN const ubyte surname_OID[];                   /* 2 5 4 4 */
MOC_EXTERN const ubyte title_OID[];                     /* 2 5 4 12 */
MOC_EXTERN const ubyte givenName_OID[];                 /* 2 5 4 42 */
MOC_EXTERN const ubyte initials_OID[];                  /* 2 5 4 43 */
MOC_EXTERN const ubyte pseudonym_OID[];                 /* 2 5 4 65 */
MOC_EXTERN const ubyte generationQualifier_OID[];       /* 2 5 4 44 */

/* "ji" stands for "jurisdictionOfIncorporation"
 */
MOC_EXTERN const ubyte jiCountryName_OID[];             /* 1 3 6 1 4 1 311 60 2 1 3 */
MOC_EXTERN const ubyte jiStateOrProvinceName_OID[];     /* 1 3 6 1 4 1 311 60 2 1 2 */
MOC_EXTERN const ubyte jiLocalityName_OID[];            /* 1 3 6 1 4 1 311 60 2 1 1 */

MOC_EXTERN const ubyte domainComponent_OID[]; /* 0 9 2342 19200300 100 1 25 from rfc2247 */

MOC_EXTERN const ubyte userID_OID[]; /* 0.9.2342.19200300.100.1.1 from RFC 4519, 1274 */

MOC_EXTERN const ubyte subjectDirectory_OID[];     /* 2.5.29.9 */
MOC_EXTERN const ubyte subjectKeyIdentifier_OID[]; /* 2.5.29.14 */
MOC_EXTERN const ubyte keyUsage_OID[];          /* 2.5.29.15 */
MOC_EXTERN const ubyte subjectAltName_OID[]; /* 2.5.29.17 */
MOC_EXTERN const ubyte issuerAltName_OID[]; /* 2.5.29.18 */
MOC_EXTERN const ubyte basicConstraints_OID[];  /* 2.5.29.19 */
MOC_EXTERN const ubyte crlNumber_OID[];         /* 2.5.29.20 */
MOC_EXTERN const ubyte crlReason_OID[];         /* 2.5.29.21 */
MOC_EXTERN const ubyte invalidityDate_OID[];    /* 2.5.29.24 */
MOC_EXTERN const ubyte nameConstraints_OID[];   /* 2.5.29.30 */
MOC_EXTERN const ubyte crl_OID[];               /* 2.5.29.31 cRLDistributionPoints */
MOC_EXTERN const ubyte certificatePolicies_OID[]; /* 2.5.29.32 */
MOC_EXTERN const ubyte authorityKeyIdentifier_OID[]; /* 2.5.29.35 */
MOC_EXTERN const ubyte extendedKeyUsage_OID[]; /* 2.5.29.37 */
MOC_EXTERN const ubyte id_kp_smartCardLogon_OID[]; /* 1.3.6.1.4.1.311.20.2.2 */
MOC_EXTERN const ubyte userPrincipalName_OID[];    /* 1.3.6.1.4.1.311.20.2.3 */
MOC_EXTERN const ubyte dnQualifier_OID[];       /* 2 5 4 46 */
MOC_EXTERN const ubyte productIdentifier_OID[]; /* 1.3.6.1.4.1.2745.1.4 */
MOC_EXTERN const ubyte vendorIdentifier_OID[];  /* 1.3.6.1.4.1.4399.2.1.10.2.104 */

MOC_EXTERN const ubyte sha1_OID[];                  /* 1 3 14 3 2 26 */
MOC_EXTERN const ubyte sha1withRsaSignature_OID[];  /* 1 3 14 3 2 29 */

MOC_EXTERN const ubyte noSignature_OID[];    /* 1.3.6.1.5.5.7.6.2 */

MOC_EXTERN const ubyte sha2_OID[];                  /* 2 16 840 1 101 3 4 2 */
/* suffixes of sha2_OID */
enum {
    sha256Digest = 1,
    sha384Digest = 2,
    sha512Digest = 3,
    sha224Digest = 4
};
/* repeat for convenience */
MOC_EXTERN const ubyte sha224_OID[];                  /* 2 16 840 1 101 3 4 2 4 */
MOC_EXTERN const ubyte sha256_OID[];                  /* 2 16 840 1 101 3 4 2 1 */
MOC_EXTERN const ubyte sha384_OID[];                  /* 2 16 840 1 101 3 4 2 2 */
MOC_EXTERN const ubyte sha512_OID[];                  /* 2 16 840 1 101 3 4 2 3 */

MOC_EXTERN const ubyte sha3_224_OID[]; /* 2 16 840 1 101 3 4 2 7 */
MOC_EXTERN const ubyte sha3_256_OID[]; /* 2 16 840 1 101 3 4 2 8 */
MOC_EXTERN const ubyte sha3_384_OID[]; /* 2 16 840 1 101 3 4 2 9 */
MOC_EXTERN const ubyte sha3_512_OID[]; /* 2 16 840 1 101 3 4 2 10 */
MOC_EXTERN const ubyte shake128_OID[]; /* 2 16 840 1 101 3 4 2 11 */
MOC_EXTERN const ubyte shake256_OID[]; /* 2 16 840 1 101 3 4 2 12 */

MOC_EXTERN const ubyte desCBC_OID[];        /* 1 3 14 3 2 7 */

MOC_EXTERN const ubyte aes_OID[];           /* 2.16.840.1.101.3.4.1 */

MOC_EXTERN const ubyte aes128CBC_OID[];     /* 2.16.840.1.101.3.4.1.2 */
MOC_EXTERN const ubyte aes192CBC_OID[];     /* 2.16.840.1.101.3.4.1.22 */
MOC_EXTERN const ubyte aes256CBC_OID[];     /* 2.16.840.1.101.3.4.1.42 */

MOC_EXTERN const ubyte aes128GCM_OID[];     /* 2.16.840.1.101.3.4.1.6 */
MOC_EXTERN const ubyte aes192GCM_OID[];     /* 2.16.840.1.101.3.4.1.26 */
MOC_EXTERN const ubyte aes256GCM_OID[];     /* 2.16.840.1.101.3.4.1.46 */

MOC_EXTERN const ubyte dsa_OID[];           /* 1 2 840 10040 4 1*/
MOC_EXTERN const ubyte dsaWithSHA1_OID[];   /* 1 2 840 10040 4 3*/

MOC_EXTERN const ubyte dsaWithSHA2_OID[];   /* 2 16 840 1 101 3 4 3 */
MOC_EXTERN const ubyte dsaWithSHA256_OID[];   /* 2 16 840 1 101 3 4 2 */

MOC_EXTERN const ubyte rsaEncryptionAlgoRoot_OID[]; /* 1.2.840.113549.3 */
/* subtypes */
MOC_EXTERN const ubyte rc2CBC_OID[];        /* 1.2.840.113549.3.2 */
MOC_EXTERN const ubyte rc4_OID[];           /* 1.2.840.113549.3.4 */
MOC_EXTERN const ubyte desEDE3CBC_OID[];    /* 1.2.840.113549.3.7 */

/* PKCS 7 */
MOC_EXTERN const ubyte pkcs7_root_OID[]; /* 1.2.840.113549.1.7 */
MOC_EXTERN const ubyte pkcs7_data_OID[]; /* 1.2.840.113549.1.7.1 */
MOC_EXTERN const ubyte pkcs7_signedData_OID[]; /* 1.2.840.113549.1.7.2 */
MOC_EXTERN const ubyte pkcs7_envelopedData_OID[]; /* 1.2.840.113549.1.7.3 */
MOC_EXTERN const ubyte pkcs7_signedAndEnvelopedData_OID[]; /* 1.2.840.113549.1.7.4 */
MOC_EXTERN const ubyte pkcs7_digestedData_OID[]; /* 1.2.840.113549.1.7.5 */
MOC_EXTERN const ubyte pkcs7_encryptedData_OID[]; /* 1.2.840.113549.1.7.6 */

/* PKCS 9 */
MOC_EXTERN const ubyte pkcs9_emailAddress_OID[]; /*1 2 840 113549 1 9 1*/
MOC_EXTERN const ubyte pkcs9_unstructuredName_OID[]; /*1 2 840 113549 1 9 2*/
MOC_EXTERN const ubyte pkcs9_contentType_OID[]; /*1 2 840 113549 1 9 3*/
MOC_EXTERN const ubyte pkcs9_messageDigest_OID[]; /*1 2 840 113549 1 9 4*/
MOC_EXTERN const ubyte pkcs9_signingTime_OID[]; /*1 2 840 113549 1 9 5*/
MOC_EXTERN const ubyte pkcs9_challengePassword_OID[]; /* 1.2.840.113549.1.9.7 */
MOC_EXTERN const ubyte pkcs9_unstructuredAddress_OID[]; /* 1.2.840.113549.1.9.8 */
MOC_EXTERN const ubyte pkcs9_extensionRequest_OID[]; /* 1.2.840.113549.1.9.14 */
MOC_EXTERN const ubyte pkcs9_friendlyName_OID[];  /* 1.2.840.113549.1.9.20 */
MOC_EXTERN const ubyte pkcs9_localKeyId_OID[];    /* 1.2.840.113549.1.9.21 */

/* Other X509 Objects */
MOC_EXTERN const ubyte x509_description_OID[];    /* 2.5.4.13 */
MOC_EXTERN const ubyte x509_uniqueIdentifier_OID[];    /* 2.5.4.45 */

#if (defined(__ENABLE_MOCANA_CMS__))
/* S/MIME */
MOC_EXTERN const ubyte smime_capabilities_OID[]; /* 1.2.840.113549.1.9.15 */
/* S/MIME content types */
MOC_EXTERN const ubyte smime_receipt_OID[]; /* 1.2.840.113549.1.9.16.1.1 */
/* S/MIME Authenticated Attributes */
MOC_EXTERN const ubyte smime_receiptRequest_OID[]; /* 1.2.840.113549.1.9.16.2.1 */
MOC_EXTERN const ubyte smime_msgSigDigest_OID[];   /* 1.2.840.113549.1.9.16.2.5 */
#endif

/* ECDSA */
#if (defined(__ENABLE_MOCANA_ECC__))

MOC_EXTERN const ubyte ecPublicKey_OID[];       /* 1 2 840 10045 2 1 */
MOC_EXTERN const ubyte ecdsaWithSHA1_OID[];     /* 1 2 840 10045 4 1 */
MOC_EXTERN const ubyte ecdsaWithSHA2_OID[];     /* 1 2 840 10045 4 3 */

MOC_EXTERN const ubyte ansiX962CurvesPrime_OID[];   /* 1.2.840.10045.3.1 */

MOC_EXTERN const ubyte secp192r1_OID[];             /* 1.2.840.10045.3.1.1 */
MOC_EXTERN const ubyte secp256r1_OID[];             /* 1.2.840.10045.3.1.7 */

MOC_EXTERN const ubyte ecced_OID[];            /* 1 3 101 */
    
MOC_EXTERN const ubyte ecdh25519_OID[];        /* 1 3 101 110 */
MOC_EXTERN const ubyte ecdh448_OID[];          /* 1 3 101 111 */
MOC_EXTERN const ubyte ed25519sig_OID[];       /* 1 3 101 112 */
MOC_EXTERN const ubyte ed448sig_OID[];         /* 1 3 101 113 */

MOC_EXTERN const ubyte certicomCurve_OID[];    /* 1 3 132 0 */

MOC_EXTERN const ubyte secp224r1_OID[];        /* 1 3 132 0 33 */
MOC_EXTERN const ubyte secp384r1_OID[];        /* 1 3 132 0 34 */
MOC_EXTERN const ubyte secp521r1_OID[];        /* 1 3 132 0 35 */

#ifdef __ENABLE_MOCANA_CV_CERT__
MOC_EXTERN const ubyte cvc_ecdsaWithSha1_OID[]; /* 0.4.0.127.0.7.2.2.2.2.1 */

MOC_EXTERN const ubyte cvc_ecdsaWithSha224_OID[]; /* 0.4.0.127.0.7.2.2.2.2.2 */

MOC_EXTERN const ubyte cvc_ecdsaWithSha256_OID[]; /* 0.4.0.127.0.7.2.2.2.2.3 */

MOC_EXTERN const ubyte cvc_ecdsaWithSha384_OID[]; /* 0.4.0.127.0.7.2.2.2.2.4 */

MOC_EXTERN const ubyte cvc_ecdsaWithSha512_OID[]; /* 0.4.0.127.0.7.2.2.2.2.5 */
#endif
    
#if (defined(__ENABLE_MOCANA_PKCS7__)||defined(__ENABLE_MOCANA_CMS__))
/* for the moment, these are only used for PKCS7/CMS */

MOC_EXTERN const ubyte dhSinglePassStdDHSha1KDF_OID[]; /* 1 3 133 16 840 63 0 2 */
MOC_EXTERN const ubyte dhSinglePassStdDHSha256KDF_OID[]; /* 1 3 132 1 11 1 */
MOC_EXTERN const ubyte dhSinglePassStdDHSha384KDF_OID[]; /* 1 3 132 1 11 2 */
MOC_EXTERN const ubyte dhSinglePassStdDHSha224KDF_OID[]; /* 1 3 132 1 11 0 */
MOC_EXTERN const ubyte dhSinglePassStdDHSha512KDF_OID[]; /* 1 3 132 1 11 3 */

MOC_EXTERN const ubyte aes128Wrap_OID[];     /* 2.16.840.1.101.3.4.1.5 */
MOC_EXTERN const ubyte aes192Wrap_OID[];     /* 2.16.840.1.101.3.4.1.25 */
MOC_EXTERN const ubyte aes256Wrap_OID[];     /* 2.16.840.1.101.3.4.1.45 */
#endif

#endif

/* OCSP */
MOC_EXTERN const ubyte id_pkix_ocsp_OID[];       /* 1 3 6 1 5 5 7 48 1 */
MOC_EXTERN const ubyte id_pkix_ocsp_basic_OID[]; /* 1 3 6 1 5 5 7 48 1  1*/
MOC_EXTERN const ubyte id_pkix_ocsp_nonce_OID[]; /* 1 3 6 1 5 5 7 48 1  2*/
MOC_EXTERN const ubyte id_pkix_ocsp_crl_OID[];   /* 1 3 6 1 5 5 7 48 1  3*/
MOC_EXTERN const ubyte id_pkix_ocsp_service_locator[];  /* 1 3 6 1 5 5 7 48 1  7*/
MOC_EXTERN const ubyte id_pe_authorityInfoAcess_OID[]; /* 1.3.6.1.5.5.7.1.1  */
MOC_EXTERN const ubyte id_ad_ocsp[]; /* 1.3.6.1.5.5.7.48.1 */
MOC_EXTERN const ubyte id_kp_OCSPSigning_OID[]; /* 1.3.6.1.5.5.7.3.9 */

/* Extended Key Usage */
MOC_EXTERN const ubyte id_ce_extKeyUsage_OID[];              /* 2.5.29.37 */
MOC_EXTERN const ubyte id_kp_serverAuth_OID[];      /* 1.3.6.1.5.5.7.3.1 */
MOC_EXTERN const ubyte id_kp_clientAuth_OID[];      /* 1.3.6.1.5.5.7.3.2 */
MOC_EXTERN const ubyte id_kp_codeSigning_OID[];     /* 1.3.6.1.5.5.7.3.3 */
MOC_EXTERN const ubyte id_kp_emailProtection_OID[]; /* 1.3.6.1.5.5.7.3.4 */
MOC_EXTERN const ubyte id_kp_timeStamping_OID[];    /* 1.3.6.1.5.5.7.3.8 */

/* CMPv2 */
MOC_EXTERN const ubyte password_based_mac_OID[];
MOC_EXTERN const ubyte hmac_sha1_OID[];
MOC_EXTERN const ubyte id_aa_signingCertificate[];
MOC_EXTERN const ubyte id_regCtrl_oldCertID_OID[];

/* RFC 6187 support for SSH */
MOC_EXTERN const ubyte id_kp_secureShellClient[]; /* 1.3.6.1.5.5.7.3.21 */
MOC_EXTERN const ubyte id_kp_secureShellServer[]; /* 1.3.6.1.5.5.7.3.22 */

/* 1.3.6.1.4.1.14421
 *
 * is the OID for Mocana Corp. Call it mocana.
 *
 * iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1)
 * mocana (14421)
 *
 *   06 07 2B 06 01 04 01 F0 55
 *
 * For example,
 *
 *   mocana-cert-extension   OBJECT IDENTIFIER ::= { mocana 1 }
 *   06 08 2B 06 01 04 01 F0 55 01
 *
 * Here are the Mocana OIDs defined.
 *
 *   mocana-cert-extension   OBJECT IDENTIFIER ::= { mocana 1 }
 *   mocana-voip             OBJECT IDENTIFIER ::= { mocana 2 }
 *   mocana-network-linker   OBJECT IDENTIFIER ::= { mocana 3 }
 *   mocana-tpm              OBJECT IDENTIFIER ::= { mocana 18 }
 *   mocana-tpm-1.2          OBJECT IDENTIFIER ::= { mocana-tpm 1 }
 *   mocana-tpm-2.0          OBJECT IDENTIFIER ::= { mocana-tpm 2 }
 *   mocana-tpm-1.2-rsakey   OBJECT IDENTIFIER ::= { mocana-tpm-1.2 1 }
 *
 *   mocana-tap              OBJECT IDENTIFIER ::= { mocana 19 }
 *   mocana-tap-rsakey       OBJECT IDENTIFIER ::= { mocana-tap 1 }
 *
 *   mocana-provider-tpm-2.0(1)
 *   mocana-cms-extended-attrs OBJECT IDENTIFIER ::= { mocana 20 }
 *   mocana-controlsequence    OBJECT IDENTIFIER ::= { mocana-cms-extended-attrs 1 }
 *   mocana-othermsgsequence   OBJECT IDENTIFIER ::= { mocana-cms-extended-attrs 2 }
 *   mocana-validation-attrs   OBJECT IDENTIFIER ::= { mocana-othermsgsequence mocana-provider-tpm-2.0 }
 *   mocana-attest-tpm2        OBJECT IDENTIFIER ::= { mocana-controlsequence mocana-provider-tpm-2.0 }
 *
 *   mocana-quantum-safe              OBJECT IDENTIFIER ::= { mocana 21 }
 *   mocana-quantum-safe-hybrid-key   OBJECT IDENTIFIER ::= {mocana-quantum-safe classical-alg quantum-alg }
 */

/* Mocana Proprietary User Privilege Extension */
MOC_EXTERN const ubyte mocana_cert_extension_OID[]; /* 1.3.6.1.4.1.14421.1 */
MOC_EXTERN const ubyte mocana_voip_OID[];           /* 1.3.6.1.4.1.14421.2 */

MOC_EXTERN const ubyte mocana_attest_tpm2_oid[]; /* 1.3.6.1.4.1.14421.20.1.1 */

MOC_EXTERN const ubyte mocana_validation_attrs_oid[]; /* 1.3.6.1.4.1.14421.20.2.1 */

MOC_EXTERN const ubyte tcg_at_hwType_OID[]; /* 2.23.133.1.2 */

MOC_EXTERN const ubyte tcg_at_tpmManufacturer_OID[]; /* 2.23.133.2.1 */

MOC_EXTERN const ubyte tcg_cap_verifiedTPMResidency_OID[]; /* 2.23.133.11.1.1 */
MOC_EXTERN const ubyte tcg_cap_verifiedTPMFixed_OID[]; /* 2.23.133.11.1.2 */
MOC_EXTERN const ubyte tcg_cap_verifiedTPMRestricted_OID[]; /* 2.23.133.11.1.3 */

MOC_EXTERN const ubyte tcg_on_ekPermIdSha256_OID[]; /* 2.23.133.12.1 */

MOC_EXTERN const ubyte id_on_permanentIdentifier_OID[]; /* 1.3.6.1.5.5.7.8.3 */
MOC_EXTERN const ubyte id_on_hardwareModuleName_OID[]; /* 1.3.6.1.5.5.7.8.4 */

/* Mocana Proprietary NetworkLinker Host/Port Extension */
MOC_EXTERN const ubyte mocana_networkLinker_OID[];  /* 1.3.6.1.4.1.14421.3 */

MOC_EXTERN const ubyte pure_pqc_sig_OID[];    /* 2.16.840.1.101.3.4.3.x      for x=17 to 31 */
MOC_EXTERN const ubyte mldsa_composite_OID[]; /* 2.16.840.1.114027.80.8.1.x  for x=60 to 75 */

MOC_EXTERN const ubyte fndsa_512_OID[];       /* 1.3.9999.3.6 */               
MOC_EXTERN const ubyte fndsa_1024_OID[];      /* 1.3.9999.3.9 */   

MOC_EXTERN const ubyte cct_pkiData_oid[]; /* 1.3.6.1.5.5.7.12.2 */
MOC_EXTERN const ubyte cct_PKIResponse_OID[]; /* 1.3.6.1.5.5.7.12.3 */
MOC_EXTERN const ubyte statusInfoV2_oid[]; /* 1.3.6.1.5.5.7.7.25 */
MOC_EXTERN const ubyte batchRequests_oid[]; /* 1.3.6.1.5.5.7.7.28 */
MOC_EXTERN const ubyte batchResponses_oid[]; /* 1.3.6.1.5.5.7.7.29 */

/* Here is the ASN.1 definition of the key data to accompany
 * mocana-tpm-1.2-rsakey.
 * That is, the tpm 1.2 RSA key OID will be used in a PKCS 8 encoding. The P8
 * definition specifies an AlgId for the algorithm, then an OCTETT STRING that is
 * the private key data. The OCTETT STRING wraps the DER encoding of an ASN.1
 * definition of the actual key data. This is that ASN.1 definition.
 *   MocanaTPM1.2RSAKeyData ::= SEQUENCE {
 *     OCTET STRING   encryptedPrivateKey,
 *     INTEGER        modulus,
 *     INTEGER        publicExponent }
 * The encryptedPrivateKey is simply the "key blob" returned by the TPM. It is
 * the actual private key data, encrypted using an on-board AES key, along with
 * some identifying bytes.
 * When using this OID in an algorithm identifier, there are no params
 * (use 05 00).
 */

/* utility function */
MOC_EXTERN intBoolean EqualOID( const ubyte* oid1, const ubyte* oid2);

#ifdef __cplusplus
}
#endif

#endif /* __OIDDEFS_HEADER__ */
