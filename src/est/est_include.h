/**
 * @file  est_include.h
 * @brief Mocana include file for EST.
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

#ifndef __EST_INCLUDE_H__
#define __EST_INCLUDE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TP_CSR_ATTRIB        "csr_attrs"
#define TP_CSR_ATTRIB_CN     "commonName"
#define TP_CSR_ATTRIB_C      "countryName"
#define TP_CSR_ATTRIB_ST     "stateOrProvinceName"
#define TP_CSR_ATTRIB_L      "localityName"
#define TP_CSR_ATTRIB_O      "organizationName"
#define TP_CSR_ATTRIB_OU     "organizationalUnitName"
#define TP_CSR_ATTRIB_EMAIL  "emailAddress"
#define TP_CSR_ATTRIB_SALTNM  "subjectAltNames"
#define TP_CSR_ATTRIB_BCONS  "hasBasicConstraints"
#define TP_CSR_ATTRIB_ISCA   "isCA"
#define TP_CSR_ATTRIB_CERTPLEN  "certPathLen"
#define TP_CSR_ATTRIB_KEYUSG  "keyUsage"
#define TP_CSR_ATTRIB_EXTKEYUSG "extendedKeyUsage"
#define TP_CSR_ATTRIB_SERIALNUMBER "serialNumber"

#define TP_EXTCSR_ATTRIB   "ext_csr_attrs"
#define TP_EXTCSR_ATTRIB_OID   "oid"
#define TP_EXTCSR_ATTRIB_TLVS  "tlvs"
#define TP_EXTCSR_ATTRIB_TLV   "tlv"

#define TP_ACTION_JSTR      "action"
#define TP_SERVER_HOST      "server_host"
#define TP_SERVER_PORT      "server_port"
#define TP_TENENT_CA_LBL    "tenant_ca_label"
#define TP_SERVER_IDENTITY  "server_identity"     /* pTpecServerName */
#define TP_USER_LOGIN       "user_login"
#define TP_USER_PASSWORD    "user_password"
#define TP_CERT_PATH        "keystore_path"
#define TP_KEY_TYPE         "key_type"
#define TP_KEY_SIZE         "key_size"
#define TP_KEY_SOURCE       "key_source"
#define TP_KEY_ALIAS        "key_alias"
#define TP_ROOT_CA_FILE     "root_ca_file"
#define TP_SSL_TRUST_STORE  "ssl_truststore"
#define TP_CA_CERT_FILE     "ca_cert_file"
#define TP_CSR_FILE         "csr_file"
#define TP_FULL_CMC_REQ     "full_cmc_req"
#define TP_FULLCMC_REQ_TYPE  "fullcmc_req_type"
#define TP_FC_RKEY_KEY_TYPE  "rekey_key_type"
#define TP_FC_RKEY_KEY_ALIAS "rekey_key_alias"
#define TP_FC_RKEY_KEY_SZ    "rekey_key_size"
#define TP_TAP_INFO          "tap_info"
#define TP_TAP_CONFIG_FILE   "tap_config_file"
#define TP_TAP_MOD_ID        "module_id"
#define TP_TAP_KEY_USAGE     "tap_key_usage"
#define TP_TAP_SIG_SCHEME    "tap_sig_scheme"
#define TP_TAP_ENC_SCHEME    "tap_enc_scheme"
#define TP_TAP_KEY_PASSWD    "tap_key_password"
#define TP_TAP_SERVER_NAME   "tap_server_name"
#define TP_TAP_SERVER_PORT   "tap_server_port"
#define TP_SK_PSKALIAS       "skg_psk_alias"
#define TP_SK_CLNTCERT       "skg_client_cert"
#define TP_SK_CLNTKEY        "skg_client_key"
#define TP_SK_CLKYTYPE       "skg_client_key_type"
#define TP_OCSP_REQUIRED     "ocsp_required"
#define TP_DIGEST_NAME       "sig_digest"
#define TP_SK_ALG            "skg_alg"
#define TP_CREATED_ON        "created_on"
#define TP_USER_AGENT        "user_agent"
#define TP_P8_PW             "pkcs8_pw"
#define TP_P8_ENC_ALG        "pkcs8_enc_alg"
#define TP_P12               "pkcs12"
#define TP_P12_ENC_ALG       "pkcs12_enc_alg"
#define TP_P12_INTEGRITY_PW  "pkcs12_integrity_pw"
#define TP_P12_PRIVACY_PW    "pkcs12_privacy_pw"
#define TP_P12_KEY_PW        "pkcs12_key_pw"

#define TP_JSON_CONFIGURATION    "configuration"
#define TP_JSON_SIGNATURE        "signature"
#define TP_SIG_ALGID             "algo_id"
#define TP_SIG_VALUE            "sig_value"
#define TP_SIG_CERT              "sig_cert"

#define TP_RENEW_WINDOW      "renew_window"
#define TP_INLINE_CERT       "renew_inline_cert"

#define TP_KEY_HANDLE           "key_handle"
#define TP_CERTIFICATE_NV_INDEX "certificate_nv_index"
#define TP_KEY_PRIMARY          "key_primary"
#define TP_KEY_NONCE_NV_INDEX   "key_nonce_nv_index"
#define TP_KEY_TOKEN_HIERARCHY  "key_token_hierarchy"

/* TAP key usage enumerations */
#define ESTC_TAP_KEY_USAGE_SIGNING  "SIGNING"
#define ESTC_TAP_KEY_USAGE_DECRYPT  "DECRYPT"
#define ESTC_TAP_KEY_USAGE_GENERAL  "GENERAL"
#define ESTC_TAP_KEY_USAGE_ATTEST   "ATTEST"

/* TAP signing scheme enumerations */
#define ESTC_TAP_SIG_SCHEME_NONE            "NONE"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5         "PKCS1_5"
#define ESTC_TAP_SIG_SCHEME_PSS_SHA1        "PSS_SHA1"
#define ESTC_TAP_SIG_SCHEME_PSS_SHA256      "PSS_SHA256"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5_SHA1    "PKCS1_5_SHA1"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5_SHA256  "PKCS1_5_SHA256"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5_DER     "PKCS1_5_DER"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA1      "ECDSA_SHA1"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA224    "ECDSA_SHA224"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA256    "ECDSA_SHA256"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA384    "ECDSA_SHA384"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA512    "ECDSA_SHA512"

/* TAP encryption scheme enumerations */
#define ESTC_TAP_ENC_SCHEME_NONE            "NONE"
#define ESTC_TAP_ENC_SCHEME_PKCS1_5         "PKCS1_5"
#define ESTC_TAP_ENC_SCHEME_OAEP_SHA1       "OAEP_SHA1"
#define ESTC_TAP_ENC_SCHEME_OAEP_SHA256     "OAEP_SHA256"

/* TAP hierarchy enumerations */
#define ESTC_TAP_HIERARCHY_STORAGE      "STORAGE"
#define ESTC_TAP_HIERARCHY_ENDORSEMENT  "ENDORSEMENT"
#define ESTC_TAP_HIERARCHY_PLATFORM     "PLATFORM"

enum TpecJsonTagKey{
    TK_ACTION_JSTR = 1,
    TK_SERVER_HOST,
    TK_SERVER_PORT,
    TK_TENENT_CA_LBL,
    TK_SERVER_IDENTITY,
    TK_USER_LOGIN,
    TK_USER_PASSWORD,
    TK_CERT_PATH,
    TK_KEY_TYPE,
    TK_KEY_SIZE,
    TK_KEY_SOURCE,
    TK_KEY_ALIAS,
    TK_ROOT_CA_FILE,
    TK_SSL_TRUST_STORE,
    TK_CA_CERT_FILE,
    TK_CSR_FILE,
    TK_FULL_CMC_REQ,
    TK_FULLCMC_REQ_TYPE,
    TK_FC_RKEY_KEY_TYPE,
    TK_FC_RKEY_KEY_ALIAS,
    TK_FC_RKEY_KEY_SZ,
    TK_TAP_INFO,
    TK_TAP_CONFIG_FILE,
    TK_TAP_MOD_ID,
    TK_TAP_KEY_USAGE,
    TK_TAP_SIG_SCHEME,
    TK_TAP_ENC_SCHEME,
    TK_TAP_KEY_PASSWD,
    TK_SK_PSKALIAS,
    TK_SK_CLNTCERT,
    TK_SK_CLNTKEY,
    TK_SK_CLKYTYPE,
    TK_OCSP_REQUIRED,
    TK_DIGEST_NAME,
    TK_SK_ALG,
    TK_USER_AGENT,

    TK_CSR_ATTRIB,
    TK_CSR_ATTRIB_CN,
    TK_CSR_ATTRIB_C,
    TK_CSR_ATTRIB_ST,
    TK_CSR_ATTRIB_L,
    TK_CSR_ATTRIB_O,
    TK_CSR_ATTRIB_OU,
    TK_CSR_ATTRIB_EMAIL,
    TK_CSR_ATTRIB_SALTNM,
    TK_CSR_ATTRIB_BCONS,
    TK_CSR_ATTRIB_ISCA,
    TK_CSR_ATTRIB_CERTPLEN,
    TK_CSR_ATTRIB_KEYUSG,
    TK_CSR_ATTRIB_SERIALNUMBER,

    TK_EXTCSR_ATTRIB,
    TK_EXTCSR_ATTRIB_OID,
    TK_EXTCSR_ATTRIB_TLVS,
    TK_EXTCSR_ATTRIB_TLV,

    TK_P8_PW,
    TK_P8_ENC_ALG,
    TK_P12,
    TK_P12_ENC_ALG,
    TK_P12_INTEGRITY_PW,
    TK_P12_PRIVACY_PW,
    TK_P12_KEY_PW,

    TK_JSON_CONFIGURATION,
    TK_JSON_SIGNATURE,
    TK_SIG_ALGID,
    TK_SIG_VALUE,
    TK_SIG_CERT,
    TK_CSR_ATTRIB_EXTKEYUSG,

    TK_RENEW_WINDOW,
    TK_INLINE_CERT,

    TK_KEY_HANDLE,
    TK_CERTIFICATE_NV_INDEX,
    TK_KEY_PRIMARY,
    TK_KEY_NONCE_NV_INDEX,
    TK_KEY_TOKEN_HIERARCHY
};

enum TpecOperation{
  TPEC_GETCA_CERTS=1,
  TPEC_GETCSR_ATTRS,
  TPEC_FULLCMC,
  TPEC_SERVERKEYGEN,
  TPEC_SIMPLE_ENROLL,
  TPEC_SIMPLE_REENROLL,
  TPEC_TCUS_SIGNING_CERTS,
  TPEC_TCUS_TRUST_CERTS
};

typedef struct TpecPskList_s {
    sbyte *pCmdArg;
    sbyte *pOid;
} TpecPskList_t;

typedef struct TpecJsonStrings_s {
    const char *tag;
    ubyte tag_key;
    ubyte tag_type;
    ubyte optional;
}TpecJsonStrings_t;

typedef struct TpecCmdFullCmcInfo_s {
    sbyte *pFullCmcReqType;
    sbyte  *pRekeyKeyType;
    sbyte *pRekeyKeyAlias;
    ubyte2  usRekeyKeySize;

}TpecCmdFullCmcInfo_t;

typedef struct TpecTapInfo_s {
    sbyte  *pTpecTapConfFile;
    ubyte2  usTpecTapModId;
    ubyte2  usTpecTapKeyUsage;
    ubyte2  usTpecTapSigScheme;
    ubyte2  usTpecTapEncScheme;
    sbyte   *pTpecTapKeyPasswd;
    sbyte   *pTpecTapServerName;
    sbyte4  tpecTapServerPort;
    intBoolean tpecTapServerPortSet;
}TpecTapInfo_t;

typedef struct TpecCmdArgs_s {
    ubyte *pCmd_str;
    sbyte *pTpecServerIp;
    ubyte4 cmd_code;
    ubyte2  usTpecServerPort;
    ubyte2  usTpecKeySize;
    sbyte *pTpecTenantLbl;
    sbyte *pTpecServerName;
    sbyte  *pTpecUserName;
    sbyte *pTpecUserPasswd;
    sbyte *pTpecCertPath;
    sbyte  *pTpecRootCA;
    sbyte  *pSslTrustCA;
    sbyte  *pTpecKeyType;
    sbyte  *pTpecKeySoure;
    sbyte  *pTpecCACertFile;
    sbyte  *pTpecKeyAlias;
    sbyte  *pTpecCsrFile;
    sbyte  *pSkPskAlias;
    sbyte  *pSkClntCert;
    sbyte  *pSkClntKey;
    sbyte  *pSkKeyType;
    sbyte  *pDigestName;
    sbyte  *pSkAlg;
    sbyte  *pCreatedOn;
    sbyte  *pUserAgent;
    sbyte   ocsp_required;
    TpecCmdFullCmcInfo_t fullCmcReq;
    TpecTapInfo_t TpecTapInfo;
    sbyte  *csrAttrib ;
    sbyte  *extCsrAttrib;
    sbyte  *pEstUrl;
    sbyte  *pPkcs8Pw;
    sbyte  *pPkcs8EncAlg;
    sbyte   pkcs12Gen;
    sbyte  *pPkcs12EncAlg;
    sbyte  *pPkcs12IntPw;
    sbyte  *pPkcs12PriPw;
    sbyte  *pPkcs12KeyPw;
    sbyte4  renewWindow;
    intBoolean renewWindowSet;
    sbyte   renewinlinecert;
    sbyte  *pTapKeyHandle;
    sbyte  *pTapCertificateNvIndex;
    intBoolean tapKeyPrimary;
    intBoolean tapKeyPrimarySet;
    sbyte  *pTapKeyNonceNvIndex;
    sbyte  *pTapKeyTokenHierarchy;
}TpecCmdArgs_t ;

typedef struct TpecCmdResult_s {
    intBoolean renewed;
} TpecCmdResult_t;

/* definition of a user supplied callback method that will handle management of the key and certificate, rather than having them
   output to the local filesystem. */
typedef MSTATUS (*EST_CLIENT_keyAndCertificateCallback) (void *pUserData, ubyte *pKey, ubyte4 keyLen, ubyte *pCert, ubyte4 certLen);

MOC_EXTERN MSTATUS EST_CLIENT_init_defaults(void);

/* Registers the user supplied callback method that will handle 
 * management of the key and certificate rather than having them
 * output to the file system.
 *
 * @param dataCb      Function pointer to the callback method.
 * @param pUserData   Data or context that can be used to handle or
 *                    store the key and certificate.
 *
 * @return 0 on success.
 */
MOC_EXTERN MSTATUS EST_CLIENT_registerKeyAndCertificateCallback(EST_CLIENT_keyAndCertificateCallback dataCb, void *pUserData);

/* Sets the key and optionally the certificate into program memory
 * rather than trying to read them from the file system. The key is
 * the AsymmetricKey. The cert may be PEM or DER.
 *
 * @param pAsymKey AsymmetricKey initialized by the caller.
 * @param pCert    (Optional) Buffer holding the input certificate.
 * @param certLen  The length of the certificate in bytes.
 *
 * @return 0 on success.
 */
MOC_EXTERN MSTATUS EST_CLIENT_setKeyAndCertificate(AsymmetricKey *pAsymKey, ubyte *pCert, ubyte4 certLen);

/* Sets the password to be used to pkcs8 protect a newly generated
 * private key.
 *
 * @param pPw     Buffer holding the input password.
 * @param pwLen   The length of the password in bytes.
 *
 * @return 0 on success.
 */
MOC_EXTERN MSTATUS EST_CLIENT_setNewKeyPass(ubyte *pPw, ubyte4 pwLen);

MOC_EXTERN MSTATUS EST_CLIENT_setProxy(sbyte *pProxy, sbyte4 proxyLen);
MOC_EXTERN MSTATUS EST_CLIENT_setKeyStorePath(const sbyte *pCertPath);
MOC_EXTERN sbyte4 EST_CLIENT_parse_json(TpecCmdArgs_t *pTpecCmd, TpecJsonStrings_t *pTpecJsonTokens, ubyte4 tpecTokensLen, const sbyte *pJsonBuf, ubyte4 jsonBufLen, intBoolean appendExtAttr);
MOC_EXTERN sbyte4 EST_CLIENT_parse_tpec_json(sbyte *pJsonBuf, sbyte4 bufLen, TpecCmdArgs_t *pTpecCmd);
MOC_EXTERN MSTATUS EST_CLIENT_free_tpecCmd(TpecCmdArgs_t *pTpecCmd);
MOC_EXTERN MSTATUS EST_CLIENT_apply_config(TpecCmdArgs_t *pTpecCmd, ubyte skip_init);
MOC_EXTERN sbyte4 EST_CLIENT_get_cmd_status(void);
MOC_EXTERN sbyte4 EST_CLIENT_get_cmd_status_code(void);
MOC_EXTERN void EST_CLIENT_get_cmd_result(TpecCmdResult_t *pTpecResult);
MOC_EXTERN void EST_CLIENT_setVerboseLevel(ubyte4 level);
/* Retrieve the last error from the most recent EST run.
 *
 * @param ppErrStr      Location where the error string is returned. If no
 *                      error occurred then this is NULL otherwise it will
 *                      contain the error string. This must be freed using
 *                      MOC_FREE.
 * @param pErrStrLen    Location where the error string length is returned.
 * @param pErrStatus    Locationg where the MSTATUS error is returned. If no
 *                      error occurred then this will be set to OK.
 */
MOC_EXTERN MSTATUS EST_CLIENT_getLastError(ubyte **ppErrStr, ubyte4 *pErrStrLen, MSTATUS *pErrStatus);

#ifdef __cplusplus
}
#endif

#endif /* __EST_INCLUDE_H__  */
