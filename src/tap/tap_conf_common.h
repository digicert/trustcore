/**
 * @file tap_common_conf.h
 *
 * @ingroup nanotap_tree
 *
 * @brief Common Trust Anchor Platform (TAP) Definitions and Types
 * @details This file contains definitions and utility functions common to all Trust Anchor Platform (TAP) client and server modules.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular HW security module:
 *    + \c \__ENABLE_DIGICERT_TPM__
 *    + \c \__ENABLE_DIGICERT_TPM2__
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

#ifndef __TAP_CONF_COMMON_HEADER__
#define __TAP_CONF_COMMON_HEADER__

#include "../common/mtypes.h"
#include "../common/merrors.h"
#ifdef __cplusplus
extern "C" {
#endif

/*! @cond */

#ifdef __ENABLE_DIGICERT_TAP__

/*! @endcond */

/***************************************************************
   "enum" Definitions - use #defines for compiler compatibility
****************************************************************/

#pragma pack(push, 1)

/***************************************************************
   Constant Definitions
****************************************************************/
#define TAP_DEFAULT_SERVER_PORT_NO 6544
#define MAX_SSL_CLIENT_CONNECTIONS  16
#define MAX_SSL_SERVER_CONNECTIONS_ALLOWED  100

#define TAP_UNIX_DOMAIN_SOCKET  210
#define DEFAULT_UNIX_DOMAIN_PATH    "/tmp/tapsunixsocket"

#ifndef __RTOS_WIN32__
#define TAP_SERVER_MODULE_CONFIG_FILES_PATH "/etc/digicert"
#else
#define TAP_SERVER_MODULE_CONFIG_FILES_PATH "."
#endif

/** @private
 *  @internal
 */
/* root certs */
typedef struct TAP_ROOT_CERT_INFO
{
    struct TAP_ROOT_CERT_INFO *next;

    char* fileName;
    ubyte* certData;
    ubyte4 certLength;
} TAP_ROOT_CERT_INFO;

typedef struct _TAP_MODULE_CONFIG_FILE_INFO 
{
    TAP_Buffer   name;
    struct _TAP_MODULE_CONFIG_FILE_INFO *pNext;
} TAP_MODULE_CONFIG_FILE_INFO;

/** @private
 *  @internal
 */
typedef struct _TAP_OPERATIONAL_INFO
{
    ubyte4 enableMutualAuth;
    ubyte4 enableunsecurecomms;
    char *certificateFileName;
    char *certificateKeyFileName;
    certStorePtr pSslCertStore;
    TAP_ROOT_CERT_INFO *pRootCerts;
    TAP_MODULE_CONFIG_FILE_INFO *pModuleConfInfo;
    ubyte4 serverPort;
    ubyte4  isNonFsMode;
    TAP_Buffer configData;
    char *pServerName;
    int isSharedContext;
    char *pBindAddr;
} TAP_OPERATIONAL_INFO;

/*! @cond */
#ifdef __ENABLE_DIGICERT_TPM2__
/*! @endcond */

/** @private
 *  @internal
 */
typedef struct
{
    ubyte4 placeHolder;
} TPM2_CONF_INFO;

/*! @cond */
#endif
/*! @endcond */

#define TAP_MODULE_STATE_INIT   0
#define TAP_MODULE_STATE_OPEN   1


/*! @cond */
#if !defined (MOCANA_TAP_THREAD_TIMEOUT)
/*! @endcond */
#define MOCANA_TAP_THREAD_TIMEOUT 100
/*! @cond */
#endif
/*! @endcond */

#define SOCKET_STATE_FREE           0
#define SOCKET_STATE_CONNECTED      1
#define SOCKET_STATE_TERMINATED     2

/*! @cond */
#if !defined (MOCANA_MAX_CLIENT_CONNECTIONS) 
/*! @endcond */
#define MOCANA_MAX_CLIENT_CONNECTIONS 16
/*! @cond */
#endif
/*! @endcond */


typedef struct
{
    union
    {
        ubyte4 *pIntValue;
        ubyte **ppStrValue;
        ubyte *pContext;
        TAP_MODULE_CONFIG_FILE_INFO **ppModuleConfigFileList;
        TAP_ROOT_CERT_INFO **ppRootCerts;
    } u;
    char *name;
} TAP_PARSE_PARMS;


/*! @cond */
#ifndef __RTOS_WIN32__
/*! @endcond */
#define TAP_SERVER_CONFIG_FILE "/etc/digicert/taps.conf"
#define TAP_CLIENT_CONFIG_FILE "/etc/digicert/tapc.conf"
#define TAP_CLIENT_CONFIG_FILE_LOCAL "tapc.conf"
/*! @cond */
#else
/*! @endcond */
#define TAP_SERVER_CONFIG_FILE "taps.conf"
#define TAP_CLIENT_CONFIG_FILE "tapc.conf"
#define TAP_CLIENT_CONFIG_FILE_LOCAL "tapc.conf"
#endif
/*! @endcond */

/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS TAP_CONF_COMMON_freeModuleConfigFileInfo(
        TAP_MODULE_CONFIG_FILE_INFO **ppModuleConfigFileInfo);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_freeCertStore(TAP_OPERATIONAL_INFO *pTapCert);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_freeCertFilenameBuffers(TAP_OPERATIONAL_INFO *pTapCert);


/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_ParseModuleConfigFileLine(ubyte* line, ubyte4 bytesLeft, void* arg,
    ubyte4* bytesUsed);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to release resources used to create the certificate store 
 * @details
 *
 * @return OK on success
 *
 */
MSTATUS
TAP_COMMMON_CONF_freeCertStore(TAP_ROOT_CERT_INFO *pTapCert);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to load PEM format certificate and private (PKCS1/PKCS8) key on SSL connections 
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_loadCertificateAndKey(const char *certificateFileName,
        const char *certificateKeyFileName,
        certStorePtr pSslCertStore);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to populate the certificate store with root CA
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_setCertStore(TAP_OPERATIONAL_INFO *pTapModInfo);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to parse a string value from a config file line
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_ParseStrValue(ubyte* line, ubyte4 bytesLeft, void* arg, 
        ubyte4* bytesUsed);

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to parse an integer value from a config file line
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_ParseIntValue(ubyte* line, ubyte4 bytesLeft, void* arg, 
        ubyte4* bytesUsed);


/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to parse Root certificate file name from a config file line
 * @details
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_CONF_COMMON_ParseRootCertificateFileLine(ubyte* line, ubyte4 bytesLeft, 
        void* arg, ubyte4* bytesUsed);

/**
 * @private
 * @internal
 *
 * @ingroup tapc_functions
 *
 * @brief  Function to parse configuration file
 * @details Parses the TAP communications configuration file to get
 * 		SSL configuration and other operational information 
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
parseCommConfiguration(TAP_OPERATIONAL_INFO *pTapClientInfo, const char *fullPath);

#pragma pack (pop)



#endif /* __ENABLE_DIGICERT_TAP__ */

#ifdef __cplusplus
}
#endif

#endif /* __TAP_CONF_COMMON_HEADER__ */
