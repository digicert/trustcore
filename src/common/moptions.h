/*
 * moptions.h
 *
 * Mocana Option Definitions used by the testing framework
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

#ifndef __MOPTIONS_HEADER__
#define __MOPTIONS_HEADER__

#ifndef __MOCANA_DSF_VERSION_STR__
#define __MOCANA_DSF_VERSION_STR__ "rel.trustcore.7.1.0"
#endif

#ifdef MOPTIONS_CUSTOM_HEADER
#include MOPTIONS_CUSTOM_HEADER
#else
#include "../common/moptions_custom.h"
#endif
/* @CODEGEN-START */
/* @CODEGEN-END   */

#if ((defined (__ENABLE_MOCANA_TPM__) || defined(__ENABLE_MOCANA_TPM2__)) && !defined(__DISABLE_MOCANA_TPM_MUTEX__))
#define __ENABLE_MOCANA_GLOBAL_MUTEX__
#endif
#if defined( __RTOS_DUMMY__ )
#define __DUMMY_RTOS__
#define __DUMMY_TCP__
#define __DUMMY_UDP__
#elif defined( __RTOS_VXWORKS__ )
    #if defined( __MOC_IPV4_STACK__ )
      #define __MOCANA_TCP__
      #define __MOCANA_UDP__
      #define __MOCANA_IPSTACK__
    #endif  /* __MOC_IPV4_STACK__ */
#define __VXWORKS_RTOS__
#define __VXWORKS_TCP__
#define __VXWORKS_UDP__
#define __VXWORKS_FMGMT__
#define __DUMMY_EXAMPLE_FP_CALLBACKS__
#define __DISABLE_MOCANA_FP_EXTERNAL_SEED__
/* the following handles cases where the compiler uses non-standard definitions of some macros */
#undef __SIZEOF_LONG__
#undef __LONG_MAX__
#undef __LONG_LONG_MAX__
#undef __INT_MAX__
#define __INT_MAX__ 0x7fffffff
    #if (defined (__LP64__) || defined (_LP64))
      #define __SIZEOF_LONG__ 8
      #define __LONG_LONG_MAX__ 9223372036854775807LL
    #else
      #define __SIZEOF_LONG__ 4
      #define __LONG_MAX__ 2147483647L
    #endif /* defined (__LP64__) || defined (_LP64) */
#define __MOCANA_DISABLE_CERT_TIME_VERIFY__
#undef MOC_UNUSED
#define MOC_UNUSED(param) ((void)param)
#elif defined( __RTOS_SOLARIS__ )
#define __SOLARIS_RTOS__
#define __SOLARIS_TCP__
#define __SOLARIS_UDP__
#elif (defined( __RTOS_LINUX__ ) && defined( __MOC_IPV4_STACK__ ))
#define __LINUX_RTOS__
#define __LINUX_TCP__
#define __LINUX_UDP__
#define __MOCANA_TCP__
#define __MOCANA_UDP__
#define __MOCANA_IPSTACK__
#undef MOC_UNUSED
#define MOC_UNUSED(param) ((void)param)
#elif (defined( __RTOS_LINUX__ ) && defined( __LWIP_STACK__ ))
#define __LINUX_RTOS__
#define __LWIP_TCP__
#define __LWIP_UDP__
#undef MOC_UNUSED
#define MOC_UNUSED(param) ((void)param)
#elif defined( __RTOS_LINUX__ )
#define __LINUX_RTOS__
#define __LINUX_TCP__
#define __LINUX_UDP__
#define __LINUX_FMGMT__
#undef MOC_UNUSED
#define MOC_UNUSED(param) ((void)param)
#elif defined( __RTOS_WIN32__ )
#define __WIN32_RTOS__
#define __WIN32_TCP__
#define __WIN32_UDP__
#define __WIN32_FMGMT__
#elif defined( __RTOS_NNOS__ )
#define __NNOS_RTOS__
#define __NNOS_TCP__
#define __NNOS_UDP__
#elif defined( __RTOS_PSOS__ )
#define __PSOS_RTOS__
#define __PSOS_TCP__
#define __PSOS_UDP__
#elif defined( __RTOS_NUCLEUS__ )
#define __NUCLEUS_RTOS__
#define __NUCLEUS_TCP__
#define __NUCLEUS_UDP__
#elif defined( __RTOS_ARC__ )
#define __MQX_RTOS__
#define __RTCS_TCP__
#define __RTCS_UDP__
#elif defined( __RTOS_CYGWIN__ ) && defined( __MOC_IPV4_STACK__)
#define __CYGWIN_RTOS__
#define __CYGWIN_TCP__
#define __CYGWIN_UDP__
#define __MOCANA_TCP__
#define __MOCANA_UDP__
#define __MOCANA_IPSTACK__
#elif defined( __RTOS_CYGWIN__ )
#define __CYGWIN_RTOS__
#define __CYGWIN_TCP__
#define __CYGWIN_UDP__
#elif defined( __RTOS_OSX__ ) && defined( __LWIP_STACK__ )
#define __OSX_RTOS__
#define __LWIP_TCP__
#define __LWIP_UDP__
#elif defined( __RTOS_OSX__ )
#define __OSX_RTOS__
#define __OSX_TCP__
#define __OSX_UDP__
#define __OSX_FMGMT__
#elif defined( __RTOS_THREADX__ )
#define __THREADX_RTOS__
#define __THREADX_TCP__
#define __THREADX_UDP__
#if defined( __RTOS_AZURE__ )
#define __AZURE_RTOS__
#define __AZURE_TCP__
#define __AZURE_UDP__
#define __AZURE_FMGMT__
#endif
#elif defined( __RTOS_OSE__ )
#define __OSE_RTOS__
#define __OSE_TCP__
#define __OSE_UDP__
#elif defined( __RTOS_NETBURNER__ )
#define __NETBURNER_RTOS__
#define __NETBURNER_TCP__
#define __NETBURNER_UDP__
#elif defined( __RTOS_OPENBSD__ )
#define __OPENBSD_RTOS__
#define __OPENBSD_TCP__
#define __OPENBSD_UDP__
#elif defined( __RTOS_NUTOS__ )
#define __NUTOS_RTOS__
#define __NUTOS_TCP__
#define __NUTOS_UDP__
#elif defined( __RTOS_INTEGRITY__ )
#define __INTEGRITY_RTOS__
#define __INTEGRITY_TCP__
#define __INTEGRITY_UDP__
#elif (defined( __RTOS_ANDROID__ ) && defined( __MOC_IPV4_STACK__ ))
#define __ANDROID_RTOS__
#define __ANDROID_TCP__
#define __ANDROID_UDP__
#define __MOCANA_TCP__
#define __MOCANA_UDP__
#define __MOCANA_IPSTACK__
#elif defined( __RTOS_ANDROID__ ) && defined( __LWIP_STACK__ )
#define __ANDROID_RTOS__
#define __LWIP_TCP__
#define __LWIP_UDP__
#elif defined( __RTOS_ANDROID__ )
#define __ANDROID_RTOS__
#define __ANDROID_TCP__
#define __ANDROID_UDP__
#elif defined( __RTOS_FREEBSD__ )
#define __FREEBSD_RTOS__
#define __FREEBSD_TCP__
#define __FREEBSD_UDP__
#elif defined( __RTOS_IRIX__ )
#define __IRIX_RTOS__
#define __IRIX_TCP__
#define __IRIX_UDP__
#elif defined( __RTOS_QNX__ )
#define __QNX_RTOS__
#define __QNX_TCP__
#define __QNX_UDP__
#define __QNX_FMGMT__
#define __ENABLE_MOCANA_FFLUSH_LOGS__
#define __DUMMY_EXAMPLE_FP_CALLBACKS__
#define __DISABLE_MOCANA_FP_EXTERNAL_SEED__
#ifndef __RTOS_QNX_7__
typedef int ssize_t;
#endif
#elif defined( __RTOS_UITRON__ )
#define __UITRON_RTOS__
#define __UITRON_TCP__
#define __UITRON_UDP__
#elif defined( __RTOS_WINCE__ )
#define __WINCE_RTOS__
#define __WINCE_TCP__
#define __WINCE_UDP__
#elif defined ( __RTOS_SYMBIAN32__ )
#define __SYMBIAN_RTOS__
#define __SYMBIAN_TCP__
#define __SYMBIAN_UDP__
#elif defined( __RTOS_WTOS__ )
#define __WTOS_RTOS__
#define __WTOS_TCP__
#define __WTOS_UDP__
#elif defined( __RTOS_ECOS__ )
#define __ECOS_RTOS__
#define __ECOS_TCP__
#define __ECOS_UDP__
#elif (defined( __RTOS_FREERTOS__ ) && defined ( __LWIP_STACK__ ))
#define __FREERTOS_RTOS__
#define __LWIP_TCP__
#define __LWIP_UDP__
typedef int ssize_t;
#if defined(__RTOS_FREERTOS_ESP32__)
#define __LINUX_FMGMT__
#define __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#endif
#elif (defined( __RTOS_FREERTOS__ ) && defined (__WIZNET_STACK__))
#define __FREERTOS_RTOS__
#define __WIZNET_TCP__
#define __WIZNET_UDP__

#elif defined( __RTOS_FREERTOS__ )
#define __FREERTOS_RTOS__
#define __FREERTOS_TCP__
#define __FREERTOS_UDP__
#ifndef __FREERTOS_SIMULATOR__
typedef int ssize_t;
#endif
#ifdef __FREERTOS_SIMULATOR__
/* Use Linux FMGMT for freertos simulator */
#define __LINUX_FMGMT__
#endif

#define AF_INET FREERTOS_AF_INET
#define AF_INET6 FREERTOS_AF_INET6

#elif defined( __RTOS_DEOS__ )
#define __DEOS_RTOS__
#define __DEOS_TCP__
#define __DEOS_UDP__
#elif (defined (__ENABLE_MOCANA_SEC_BOOT__) || defined(__ENABLE_CUSTOM_RTOS__))
/* NanoBoot does not need any OS */
#else
#error RTOS NOT DEFINED.  [ __RTOS_VXWORKS__ , __RTOS_LINUX__ , __RTOS_SOLARIS__ , __RTOS_WIN32__ , __RTOS_NNOS__ , __RTOS_PSOS__ , __RTOS_NUCLEUS__ , __RTOS_ARC__ , __RTOS_CYGWIN__ , __RTOS_OSX__ , __RTOS_THREADX__ , __RTOS_NETBURNER__ , __RTOS_OPENBSD__ , __RTOS_NUTOS__ , __RTOS_INTEGRITY__ , __RTOS_ANDROID__ , __RTOS_FREEBSD__, __RTOS_IRIX__ ]
#endif

#if !defined( __ENABLE_MOCANA_SSH_SERVER__ ) && defined( __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ )
#define __ENABLE_MOCANA_SSH_SERVER__
#endif

#if defined __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
#if !defined __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
#define __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
#define __ENABLE_MOCANA_PEM_CONVERSION__
#endif
#if 0
#define __ENABLE_MOCANA_SSH_OCSP_SUPPORT__
#define __ENABLE_MOCANA_OCSP_CLIENT__
#define __ENABLE_MOCANA_HTTP_CLIENT__
#define __ENABLE_MOCANA_URI__
#endif
#endif

#if defined(__ENABLE_MOCANA_LDAP_CLIENT__)
#if !defined(__ENABLE_MOCANA_HTTP_CLIENT__)
#define __ENABLE_MOCANA_URI__
#endif
#endif

#if defined(__ENABLE_MOCANA_ECC_EDDSA_25519__) || defined(__ENABLE_MOCANA_ECC_EDDSA_448__) || \
    defined(__ENABLE_MOCANA_ECC_EDDH_25519__) || defined(__ENABLE_MOCANA_ECC_EDDH_448__)
#define __ENABLE_MOCANA_ECC_ED_COMMON__
#endif

#if defined(__ENABLE_MOCANA_ECC_EDDSA_25519__) || defined(__ENABLE_MOCANA_ECC_EDDSA_448__)
#define __ENABLE_MOCANA_ECC_EDDSA__
#endif

#if defined(__ENABLE_MOCANA_ECC_EDDH_25519__) || defined(__ENABLE_MOCANA_ECC_EDDH_448__)
#define __ENABLE_MOCANA_ECC_EDDH__
#endif

#ifdef __ENABLE_MOCANA_IPSEC_LINUX_EXAMPLE__
#define __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
#define __ENABLE_MOCANA_IKE_SERVER__
#define __ENABLE_MOCANA_IPSEC_SERVICE__
#define __ENABLE_IPSEC_NAT_T__
#define __ENABLE_MOCANA_SUPPORT_FOR_NATIVE_STDLIB__
#define __ENABLE_MOCANA_MEM_PART__
#define __DISABLE_MOCANA_RAND_ENTROPY_THREADS__
#define __ENABLE_ALL_DEBUGGING__
#define __ENABLE_MOCANA_DEBUG_CONSOLE__
#define __MOCANA_DUMP_CONSOLE_TO_STDOUT__
#endif /* __ENABLE_MOCANA_IPSEC_LINUX_EXAMPLE__ */

#ifdef __ENABLE_MOCANA_IKE_LINUX_EXAMPLE__
#define __ENABLE_MOCANA_IKE_SERVER__
#define __ENABLE_IPSEC_NAT_T__
#define __PLATFORM_HAS_GETOPT__
#define __ENABLE_MOCANA_SUPPORT_FOR_NATIVE_STDLIB__
#define __ENABLE_MOCANA_CERTIFICATE_SEARCH_SUPPORT__
#define __ENABLE_MOCANA_EXAMPLES__
#define __ENABLE_MOCANA_MEM_PART__
#define __ENABLE_ALL_DEBUGGING__
#define __ENABLE_MOCANA_DEBUG_CONSOLE__
#define __MOCANA_DUMP_CONSOLE_TO_STDOUT__
#endif /* __ENABLE_MOCANA_IKE_LINUX_EXAMPLE__ */

#if defined( __ENABLE_MOCANA_DTLS_SERVER__ )
#if !defined(__ENABLE_MOCANA_SSL_SERVER__)
#define __ENABLE_MOCANA_SSL_SERVER__
#endif
#if !defined(__ENABLE_MOCANA_SSL_SERVER_EXAMPLE__)
#define __ENABLE_MOCANA_SSL_SERVER_EXAMPLE__
#endif
#if !defined(__ENABLE_MOCANA_SSL_ASYNC_SERVER_API__)
#define __ENABLE_MOCANA_SSL_ASYNC_SERVER_API__
#endif
#if !defined(__ENABLE_MOCANA_SSL_ASYNC_API_EXTENSIONS__)
#define __ENABLE_MOCANA_SSL_ASYNC_API_EXTENSIONS__
#endif
#endif

#if defined __ENABLE_MOCANA_OCSP_CLIENT__
#ifndef __ENABLE_MOCANA_HTTP_CLIENT__
#define __ENABLE_MOCANA_HTTP_CLIENT__
#endif
#ifndef __ENABLE_MOCANA_URI__
#define __ENABLE_MOCANA_URI__
#endif
#ifndef __ENABLE_MOCANA_DER_CONVERSION__
#define __ENABLE_MOCANA_DER_CONVERSION__
#endif
#endif

#if defined( __ENABLE_MOCANA_DTLS_CLIENT__ )
#if !defined(__ENABLE_MOCANA_SSL_CLIENT__)
#define __ENABLE_MOCANA_SSL_CLIENT__
#endif
#if !defined(__ENABLE_MOCANA_SSL_CLIENT_EXAMPLE__)
#define __ENABLE_MOCANA_SSL_CLIENT_EXAMPLE__
#endif
#if !defined(__ENABLE_MOCANA_SSL_ASYNC_CLIENT_API__)
#define __ENABLE_MOCANA_SSL_ASYNC_CLIENT_API__
#endif
#if !defined(__ENABLE_MOCANA_SSL_ASYNC_API_EXTENSIONS__)
#define __ENABLE_MOCANA_SSL_ASYNC_API_EXTENSIONS__
#endif
#endif

#if !defined( __ENABLE_MOCANA_SSL_SERVER__ ) && defined( __ENABLE_MOCANA_SSL_ASYNC_SERVER_API__ )
#define __ENABLE_MOCANA_SSL_SERVER__
#endif

#if !defined( __ENABLE_MOCANA_SSL_CLIENT__ ) && defined( __ENABLE_MOCANA_SSL_ASYNC_CLIENT_API__ )
#define __ENABLE_MOCANA_SSL_CLIENT__
#endif

#if ((defined( __ENABLE_MOCANA_SSL_CLIENT__ ) || defined( __ENABLE_MOCANA_SSL_SERVER__ )) && \
     (defined(__ENABLE_MOCANA_AEAD_CIPHER__) && defined( __ENABLE_MOCANA_CCM_8__ )))
#ifndef __ENABLE_MOCANA_ECC__
#define __ENABLE_MOCANA_ECC__
#endif
#ifndef __ENABLE_MOCANA_SSL_ECDHE_SUPPORT__
#define __ENABLE_MOCANA_SSL_ECDHE_SUPPORT__
#endif
#endif


#if 0
#if !defined( __ENABLE_MOCANA_SSL_SERVER__ ) && !defined( __ENABLE_MOCANA_SSH_SERVER__ ) && !defined(__ENABLE_MOCANA_SSL_CLIENT__) && !defined(__ENABLE_MOCANA_IPSEC_SERVICE__) && !defined(__ENABLE_MOCANA_IKE_SERVER__) && !defined(__ENABLE_MOCANA_RADIUS_CLIENT__) && !defined(__ENABLE_MOCANA_SSH_CLIENT__) && !defined(__ENABLE_MOCANA_EAP_AUTH__) && !defined(__ENABLE_MOCANA_EAP_PEER__) && !defined( __ENABLE_MOCANA_HTTP_CLIENT__ ) && !defined(__ENABLE_MOCANA_HTTPCC_SERVER__) && !defined( __ENABLE_MOCANA_SCEP_CLIENT__ ) && !defined(__ENABLE_MOCANA_SCEPCC_SERVER__ ) && !defined(__ENABLE_MOCANA_EST_CLIENT__ ) && !defined(__MOC_IPV4_STACK__) && !defined( __ENABLE_MOCANA_SSLCC_CLIENT__ ) && !defined(__ENABLE_MOCANA_SSLCC_SERVER__) && !defined(__ENABLE_MOCANA_HARNESS__) && !defined(__ENABLE_MOCANA_UMP__) && !defined(__ENABLE_MOCANA_SEC_BOOT__) && !defined(__ENABLE_MOCANA_SIGN_BOOT__) && !defined(__ENABLE_MOCANA_WPA2__) && !defined(__ENABLE_MOCANA_NTP_CLIENT__) && !defined(__ENABLE_MOCANA_SRTP__) && !defined(__ENABLE_MOCANA_LDAP_CLIENT__)
#error MOCANA PRODUCT NOT DEFINED. [ __ENABLE_MOCANA_SSL_SERVER__ , __ENABLE_MOCANA_SSH_SERVER__ , __ENABLE_MOCANA_SSL_CLIENT__ , __ENABLE_MOCANA_IPSEC_SERVICE__ , __ENABLE_MOCANA_IKE_SERVER__ , __ENABLE_MOCANA_RADIUS_CLIENT__ , __ENABLE_MOCANA_SSH_CLIENT__ , __ENABLE_MOCANA_EAP_AUTH__ , __ENABLE_MOCANA_EAP_PEER__ , __ENABLE_MOCANA_HTTP_CLIENT__ , __ENABLE_MOCANA_HTTPCC_SERVER__ , __ENABLE_MOCANA_SCEP_CLIENT__, __ENABLE_MOCANA_SCEPCC_SERVER__, __ENABLE_MOCANA_EST_CLIENT__, __MOC_IPV4_STACK__ , __ENABLE_MOCANA_SSLCC_CLIENT__ , __ENABLE_MOCANA_SSLCC_SERVER__, __ENABLE_MOCANA_HARNESS__  , __ENABLE_MOCANA_UMP__ , __ENABLE_MOCANA_SEC_BOOT__ , __ENABLE_MOCANA_SIGN_BOOT__, __ENABLE_MOCANA_WPA2__, __ENABLE_MOCANA_NTP_CLIENT__, __ENABLE_MOCANA_SRTP__, __ENABLE_MOCANA_LDAP_CLIENT__]
#endif
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_NO_INLINE__
#define MOC_INLINE
#else
#define MOC_INLINE inline
#endif

#ifndef MOC_EXTERN
#if defined(__RTOS_WIN32__) && defined(_USRDLL)
#define MOC_EXTERN __declspec(dllexport) extern
#else
#define MOC_EXTERN extern
#endif
#endif /*__RTOS_WIN32__*/

#undef MOC_EXTERN_DATA_DEF
#if defined(__RTOS_WIN32__) && defined(_USRDLL)
#define MOC_EXTERN_DATA_DEF __declspec(dllexport)
#else
#define MOC_EXTERN_DATA_DEF
#endif

#undef MOC_EXTERN_DATA_DECL
#if defined(__RTOS_WIN32__) && defined(_USRDLL)
#define MOC_EXTERN_DATA_DECL __declspec(dllimport) extern
#else
#define MOC_EXTERN_DATA_DECL extern
#endif

#if defined(__ENABLE_MOCANA_UNITTEST__)
#define MOC_STATIC
#else
#define MOC_STATIC static
#endif

#define MOCANA_DEBUG_CONSOLE_PORT           4097

#ifdef __RTOS_WIN32__
#define MOC_UNUSED(X) ((void)(X))
#endif


#define MOCANA_YIELD_PROCESSOR()

#ifdef _MSC_VER
#pragma warning( error: 4013 4020 4024 4028 4029 4047 4133 4716 )
#pragma warning( disable: 4200 4206)
#if _MSC_VER >= 8 && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE
#endif
#ifndef __ENABLE_MOCANA_DEBUG_MEMORY__
#define _CRTDBG_MAP_ALLOC
#ifdef __RTOS_WIN32__
#include <stdlib.h>
#include <crtdbg.h>
#endif /* __RTOS_WIN32__ */
#define MALLOC CONVERT_MALLOC
#define FREE CONVERT_FREE
#define MC_MALLOC malloc
#define MC_FREE free
#endif
#endif

#if (defined(__ENABLE_MOCANA_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_MOCANA_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_MOCANA_SSL_ECDH_ANON_SUPPORT__))
#if !defined(__ENABLE_MOCANA_ECC__) /* only if not on to prevent warnings */
#define __ENABLE_MOCANA_ECC__ /* turn ECC on of course! */
#endif
#endif

/* If def example, turn feature definition into examples also */
#ifndef __DISABLE_MOCANA_AUTO_EXAMPLES__
#ifdef __ENABLE_MOCANA_EXAMPLES__
  #if defined(__ENABLE_MOCANA_SSH_CLIENT__)
    #define __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_SSH_SERVER__)
    #define __ENABLE_MOCANA_SSH_SERVER_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_DTLS_CLIENT__)
    #define __ENABLE_MOCANA_DTLS_CLIENT_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_DTLS_SERVER__)
    #define __ENABLE_MOCANA_DTLS_SERVER_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_IKE_SERVER__)
    #define __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_SSL_CLIENT__) && \
       !defined(__ENABLE_MOCANA_SYSLOG_CLIENT_EXAMPLE__)
    #ifndef __ENABLE_MOCANA_SSL_CLIENT_EXAMPLE__
        #define __ENABLE_MOCANA_SSL_CLIENT_EXAMPLE__
    #endif
  #elif defined(__ENABLE_MOCANA_SSL_SERVER__)
    #define __ENABLE_MOCANA_SSL_SERVER_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_SCEP_CLIENT__)
    #if (!defined(__ENABLE_MOCANA_SCEP_CLIENT_EXAMPLE__) && !defined(__ENABLE_MOCANA_SCEPC__)) /* only if not on to prevent warnings */
    #define __ENABLE_MOCANA_SCEP_CLIENT_EXAMPLE__
    #endif
  #elif defined(__ENABLE_MOCANA_SCEPCC_SERVER__)
    #define __ENABLE_MOCANA_SCEPCC_SERVER_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_EST_CLIENT__)
    #define __ENABLE_MOCANA_EST_CLIENT_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_OCSP_CLIENT__)
    #define __ENABLE_MOCANA_OCSP_CLIENT_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_HTTP_CLIENT__)
    #define __ENABLE_MOCANA_HTTP_CLIENT_EXAMPLE__
  #elif defined(__ENABLE_MOCANA_RADIUS_CLIENT__)
    #define __ENABLE_MOCANA_RADIUS_CLIENT_EXAMPLE__
  #endif
#endif
#endif

#ifndef EAP_PACKED
#define EAP_PACKED
#endif

#ifndef EAP_PACKED_POST
#ifdef __GNUC__
#define EAP_PACKED_POST    __attribute__ ((__packed__))
#else
#define EAP_PACKED_POST
#endif
#endif

#if defined(__ENABLE_MOCANA_SRTP__)
#define __ENABLE_NIL_CIPHER__
#ifdef __ENABLE_MOCANA_GCM__
#define __ENABLE_MOCANA_GCM_256B__
#endif
#if defined(__ENABLE_MOCANA_SRTP_EXAMPLE__)
#define __DISABLE_3DES_CIPHERS__
#define __DISABLE_ARC4_CIPHERS__
#define __DISABLE_MOCANA_SHA224__
#define __DISABLE_MOCANA_SHA256__
#define __DISABLE_MOCANA_SHA384__
#define __DISABLE_MOCANA_SHA512__
#endif
#endif

#if defined(OPENSSL_ENGINE)
#define SHA1Result  MOC_SHA1Result
#endif

/* ipsec defines its own set of algorithms and flags.
 */
#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)) && \
    (!defined(__DISABLE_MOCANA_CRYPTO_DEFAULT_ALGOS__))

/* Base the mbedtls flags on the NanoCrypto flags. If there is no flag
 * then enable the algorithm by default.
 */

#ifdef __ENABLE_MOCANA_MBED_DIGEST_OPERATORS__

#if defined(__ENABLE_MOCANA_MD4__) && !defined(__ENABLE_MOCANA_MD4_OPERATOR__)
#define __ENABLE_MOCANA_MD4_OPERATOR__
#define __ENABLE_MOCANA_MD4_MBED__
#endif

#if !defined(__ENABLE_MOCANA_MD5_OPERATOR__)
#define __ENABLE_MOCANA_MD5_OPERATOR__
#define __ENABLE_MOCANA_MD5_MBED__
#endif

#if !defined(__ENABLE_MOCANA_SHA1_OPERATOR__)
#define __ENABLE_MOCANA_SHA1_OPERATOR__
#define __ENABLE_MOCANA_SHA1_MBED__
#endif

#if !defined(__DISABLE_MOCANA_SHA224__) && !defined(__ENABLE_MOCANA_SHA224_OPERATOR__)
#define __ENABLE_MOCANA_SHA224_OPERATOR__
#define __ENABLE_MOCANA_SHA224_MBED__
#endif

#if !defined(__DISABLE_MOCANA_SHA256__) && !defined(__ENABLE_MOCANA_SHA256_OPERATOR__)
#define __ENABLE_MOCANA_SHA256_OPERATOR__
#define __ENABLE_MOCANA_SHA256_MBED__
#endif

#if !defined(__DISABLE_MOCANA_SHA384__) && !defined(__ENABLE_MOCANA_SHA384_OPERATOR__)
#define __ENABLE_MOCANA_SHA384_OPERATOR__
#define __ENABLE_MOCANA_SHA384_MBED__
#endif

#if !defined(__DISABLE_MOCANA_SHA512__) && !defined(__ENABLE_MOCANA_SHA512_OPERATOR__)
#define __ENABLE_MOCANA_SHA512_OPERATOR__
#define __ENABLE_MOCANA_SHA512_MBED__
#endif

#endif /* __ENABLE_MOCANA_MBED_DIGEST_OPERATORS__ */

#ifdef __ENABLE_MOCANA_MBED_SYM_OPERATORS__

#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__ENABLE_MOCANA_AES_CBC_OPERATOR__)
#define __ENABLE_MOCANA_AES_CBC_OPERATOR__
#define __ENABLE_MOCANA_AES_CBC_MBED__
#endif
#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__ENABLE_MOCANA_AES_CFB128_OPERATOR__)
#define __ENABLE_MOCANA_AES_CFB128_OPERATOR__
#define __ENABLE_MOCANA_AES_CFB128_MBED__
#define MBEDTLS_CIPHER_MODE_CFB
#endif
#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__ENABLE_MOCANA_AES_ECB_OPERATOR__)
#define __ENABLE_MOCANA_AES_ECB_OPERATOR__
#define __ENABLE_MOCANA_AES_ECB_MBED__
#endif
#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__ENABLE_MOCANA_AES_OFB_OPERATOR__)
#define __ENABLE_MOCANA_AES_OFB_OPERATOR__
#define __ENABLE_MOCANA_AES_OFB_MBED__
#define MBEDTLS_CIPHER_MODE_OFB
#endif

#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_CMAC__) && !defined(__ENABLE_MOCANA_AES_CMAC_OPERATOR__)
#define __ENABLE_MOCANA_AES_CMAC_OPERATOR__
#define __ENABLE_MOCANA_AES_CMAC_MBED__
#endif

#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_CTR_CIPHER__) && !defined(__ENABLE_MOCANA_AES_CTR_OPERATOR__)
#define __ENABLE_MOCANA_AES_CTR_OPERATOR__
#define __ENABLE_MOCANA_AES_CTR_MBED__
#endif

#if (defined(__ENABLE_MOCANA_GCM__) || defined(__ENABLE_MOCANA_GCM_256B__) || \
     defined(__ENABLE_MOCANA_GCM_4K__) || defined(__ENABLE_MOCANA_GCM_64K__)) && \
     !defined(__ENABLE_MOCANA_AES_GCM_OPERATOR__)
#define __ENABLE_MOCANA_AES_GCM_OPERATOR__
#define __ENABLE_MOCANA_AES_GCM_MBED__
#endif

#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XTS__) && !defined(__ENABLE_MOCANA_AES_XTS_OPERATOR__)
#define __ENABLE_MOCANA_AES_XTS_OPERATOR__
#define __ENABLE_MOCANA_AES_XTS_MBED__
#endif

#if !defined(__DISABLE_ARC4_CIPHERS__) && !defined(__ENABLE_MOCANA_ARC4_OPERATOR__)
#define __ENABLE_MOCANA_ARC4_OPERATOR__
#define __ENABLE_MOCANA_ARC4_MBED__
#endif

#if defined(__ENABLE_BLOWFISH_CIPHERS__) && !defined(__ENABLE_MOCANA_BLOWFISH_OPERATOR__)
#define __ENABLE_MOCANA_BLOWFISH_OPERATOR__
#define __ENABLE_MOCANA_BLOWFISH_MBED__
#endif

#if defined(__ENABLE_MOCANA_CHACHA20__) && !defined(__ENABLE_MOCANA_CHACHA20_OPERATOR__)
#define __ENABLE_MOCANA_CHACHA20_OPERATOR__
#define __ENABLE_MOCANA_CHACHA20_MBED__

#if defined(__ENABLE_MOCANA_POLY1305__) && !defined(__ENABLE_MOCANA_CHACHA_POLY_OPERATOR__)
#define __ENABLE_MOCANA_CHACHA_POLY_OPERATOR__
#endif

#endif /* __ENABLE_MOCANA_CHACHA20__ && !__ENABLE_MOCANA_CHACHA20_OPERATOR__ */

#if defined(__ENABLE_DES_CIPHER__) && !defined(__ENABLE_MOCANA_DES_ECB_OPERATOR__) && !defined(__ENABLE_MOCANA_DES_CBC_OPERATOR__)
#define __ENABLE_MOCANA_DES_ECB_OPERATOR__
#define __ENABLE_MOCANA_DES_CBC_OPERATOR__
#define __ENABLE_MOCANA_DES_MBED__
#endif /* __ENABLE_DES_CIPHER__ */

#if defined(__ENABLE_MOCANA_PKCS5__) && !defined(__ENABLE_MOCANA_PKCS5_OPERATOR__)
#define __ENABLE_MOCANA_PKCS5_OPERATOR__
#define __ENABLE_MOCANA_PKCS5_MBED__
#endif

#if !defined(__DISABLE_MOCANA_RNG__) && !defined(__ENABLE_MOCANA_CTR_DRBG_AES_OPERATOR__)
#define __ENABLE_MOCANA_CTR_DRBG_AES_OPERATOR__
#define __ENABLE_MOCANA_CTR_DRBG_AES_MBED__
#endif

#if !defined(__DISABLE_3DES_CIPHERS__) && !defined(__ENABLE_MOCANA_TDES_ECB_OPERATOR__) && !defined(__ENABLE_MOCANA_TDES_CBC_OPERATOR__)
#define __ENABLE_MOCANA_TDES_ECB_OPERATOR__
#define __ENABLE_MOCANA_TDES_CBC_OPERATOR__
#define __ENABLE_MOCANA_TDES_MBED__
#endif /* __DISABLE_3DES_CIPHERS__ */

#if !defined(__ENABLE_MOCANA_HMAC_OPERATOR__)
#define __ENABLE_MOCANA_HMAC_OPERATOR__
#define __ENABLE_MOCANA_HMAC_MBED__
#endif

#if !defined(__ENABLE_MOCANA_HMAC_KDF_OPERATOR__)
#define __ENABLE_MOCANA_HMAC_KDF_OPERATOR__
#define __ENABLE_MOCANA_HMAC_KDF_MBED__
#endif

#if defined(__ENABLE_MOCANA_POLY1305__) && !defined(__ENABLE_MOCANA_POLY1305_OPERATOR__)
#define __ENABLE_MOCANA_POLY1305_OPERATOR__
#define __ENABLE_MOCANA_POLY1305_MBED__
#endif

#endif /* __ENABLE_MOCANA_MBED_SYM_OPERATORS__ */

#ifdef __ENABLE_MOCANA_MBED_KEY_OPERATORS__

#if !defined(__DISABLE_MOCANA_DIFFIE_HELLMAN__) && !defined(__ENABLE_MOCANA_DH_OPERATOR__)
#define __ENABLE_MOCANA_DH_OPERATOR__
#define __ENABLE_MOCANA_DH_MBED__
#define __ENABLE_MOCANA_DH_MBED_MOCANA_GROUPS__
#endif

#ifdef __ENABLE_MOCANA_ECC__

#if defined(__ENABLE_MOCANA_ECC_P192__) && !defined(__ENABLE_MOCANA_ECC_P192_OPERATOR__)
#define __ENABLE_MOCANA_ECC_P192_OPERATOR__
#define __ENABLE_MOCANA_ECC_P192_MBED__
#endif
#ifndef __ENABLE_MOCANA_ECC_P224_OPERATOR__
#define __ENABLE_MOCANA_ECC_P224_OPERATOR__
#define __ENABLE_MOCANA_ECC_P224_MBED__
#endif
#ifndef __ENABLE_MOCANA_ECC_P256_OPERATOR__
#define __ENABLE_MOCANA_ECC_P256_OPERATOR__
#define __ENABLE_MOCANA_ECC_P256_MBED__
#endif
#ifndef __ENABLE_MOCANA_ECC_P384_OPERATOR__
#define __ENABLE_MOCANA_ECC_P384_OPERATOR__
#define __ENABLE_MOCANA_ECC_P384_MBED__
#endif
#ifndef __ENABLE_MOCANA_ECC_P521_OPERATOR__
#define __ENABLE_MOCANA_ECC_P521_OPERATOR__
#define __ENABLE_MOCANA_ECC_P521_MBED__
#endif

#endif /* __ENABLE_MOCANA_ECC__ */

#if (defined(__ENABLE_MOCANA_PKCS1__) || !defined(__DISABLE_MOCANA_RSA__)) && !defined(__ENABLE_MOCANA_RSA_OPERATOR__)
#define __ENABLE_MOCANA_RSA_OPERATOR__
#define __ENABLE_MOCANA_RSA_MBED__
#endif

#endif /* __ENABLE_MOCANA_MBED_KEY_OPERATORS__ */

#ifdef __ENABLE_MOCANA_OQS_OPERATORS__

#define __ENABLE_MOCANA_KEM_OQS__
#define __ENABLE_MOCANA_SIG_OQS__

#ifndef __ENABLE_MOCANA_QS_KYBER_OPERATOR__
#define __ENABLE_MOCANA_QS_KYBER_OPERATOR__
#endif

#ifndef __ENABLE_MOCANA_QS_SPHINCS_OPERATOR__
#define __ENABLE_MOCANA_QS_SPHINCS_OPERATOR__
#endif

#ifndef __ENABLE_MOCANA_QS_DILITHIUM_OPERATOR__
#define __ENABLE_MOCANA_QS_DILITHIUM_OPERATOR__
#endif

#ifndef __ENABLE_MOCANA_QS_FALCON_OPERATOR__
#define __ENABLE_MOCANA_QS_FALCON_OPERATOR__
#endif

#endif /* __ENABLE_MOCANA_OQS_OPERATORS__ */

/* Define digest, sym, or key operator macros if any such operator is defined */
#if defined(__ENABLE_MOCANA_MD4_OPERATOR__) || defined(__ENABLE_MOCANA_MD5_OPERATOR__) || defined(__ENABLE_MOCANA_SHA1_OPERATOR__) || \
    defined(__ENABLE_MOCANA_SHA224_OPERATOR__) || defined(__ENABLE_MOCANA_SHA256_OPERATOR__) || defined(__ENABLE_MOCANA_SHA384_OPERATOR__) || \
    defined(__ENABLE_MOCANA_SHA512_OPERATOR__) || defined(__ENABLE_MOCANA_SHA3_OPERATOR__)
#define __ENABLE_MOCANA_DIGEST_OPERATORS__
#endif

#if defined(__ENABLE_MOCANA_AES_CBC_OPERATOR__) || defined(__ENABLE_MOCANA_AES_CFB128_OPERATOR__) || defined(__ENABLE_MOCANA_AES_ECB_OPERATOR__) || \
    defined(__ENABLE_MOCANA_AES_OFB_OPERATOR__) || defined(__ENABLE_MOCANA_AES_CMAC_OPERATOR__) || defined(__ENABLE_MOCANA_AES_CTR_OPERATOR__) || \
    defined(__ENABLE_MOCANA_AES_GCM_OPERATOR__) || defined(__ENABLE_MOCANA_AES_XTS_OPERATOR__) || defined(__ENABLE_MOCANA_ARC4_OPERATOR__) || \
    defined(__ENABLE_MOCANA_BLOWFISH_OPERATOR__) || defined(__ENABLE_MOCANA_CHACHA20_OPERATOR__) || defined(__ENABLE_MOCANA_CHACHA_POLY_OPERATOR__) || \
    defined(__ENABLE_MOCANA_DES_ECB_OPERATOR__)  ||  defined(__ENABLE_MOCANA_DES_CBC_OPERATOR__) || defined(__ENABLE_MOCANA_TDES_ECB_OPERATOR__) || \
    defined(__ENABLE_MOCANA_TDES_CBC_OPERATOR__) || defined(__ENABLE_MOCANA_PKCS5_OPERATOR__) || defined(__ENABLE_MOCANA_CTR_DRBG_AES_OPERATOR__) || \
    defined(__ENABLE_MOCANA_HMAC_OPERATOR__) || defined(__ENABLE_MOCANA_HMAC_KDF_OPERATOR__) || defined(__ENABLE_MOCANA_POLY1305_OPERATOR__) || \
    defined(__ENABLE_MOCANA_AES_CFB1_OPERATOR__)
#define __ENABLE_MOCANA_SYM_OPERATORS__
#endif

#if defined(__ENABLE_MOCANA_DH_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P192_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P224_OPERATOR__) || \
    defined(__ENABLE_MOCANA_ECC_P256_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P384_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P521_OPERATOR__) || \
    defined(__ENABLE_MOCANA_RSA_OPERATOR__) || \
    defined(__ENABLE_MOCANA_QS_KYBER_OPERATOR__) || defined(__ENABLE_MOCANA_QS_SPHINCS_OPERATOR__) || \
    defined(__ENABLE_MOCANA_QS_DILITHIUM_OPERATOR__) || defined(__ENABLE_MOCANA_QS_FALCON_OPERATOR__)
#define __ENABLE_MOCANA_KEY_OPERATORS__
#endif
/* Base the Crypto Interface flag on the NanoCrypto flag. If there is no flag
 * then enable the algorithm by default.
 */

/* Enable the crypto interface based on the mocana enable flag or the operator flag */
#if !defined(__DISABLE_AES_CIPHERS__) || defined(__ENABLE_MOCANA_AES_CBC_OPERATOR__) || defined(__ENABLE_MOCANA_AES_ECB_OPERATOR__) || \
    defined(__ENABLE_MOCANA_AES_OFB_OPERATOR__) || defined(__ENABLE_MOCANA_AES_CFB128_OPERATOR__) || defined(__ENABLE_MOCANA_AES_CFB1_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES__
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_CMAC__)) || defined(__ENABLE_MOCANA_AES_CMAC_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CMAC__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CMAC__
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_CTR_CIPHER__)) || defined(__ENABLE_MOCANA_AES_CTR_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CTR__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CTR__
#endif
#endif

#if ((!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CCM__)))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CCM__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CCM__
#endif
#endif

#if ((!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_XTS__)))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_XTS__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_XTS__
#endif
#endif

#if defined(__ENABLE_MOCANA_GCM__) || defined(__ENABLE_MOCANA_GCM_256B__) || defined(__ENABLE_MOCANA_GCM_4K__) || \
    defined(__ENABLE_MOCANA_GCM_64K__) || defined(__ENABLE_MOCANA_AES_GCM_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_GCM__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_GCM__
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XCBC_MAC_96__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_XCBC__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_XCBC__
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XTS__)) || defined(__ENABLE_MOCANA_AES_XTS_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_XTS__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_XTS__
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_EAX__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_EAX__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_EAX__
#endif
#endif

#if !defined(__DISABLE_AES_CIPHERS__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_KEYWRAP__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_AES_KEYWRAP__
#endif
#endif

#if !defined(__DISABLE_ARC4_CIPHERS__) || defined(__ENABLE_MOCANA_ARC4_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_ARC4__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_ARC4__
#endif
#endif

/* no operators available yet for rc5/blake2 etc */
#ifdef __ENABLE_MOCANA_RC5__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_RC5__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_RC5__
#endif
#endif

#ifdef __ENABLE_MOCANA_BLAKE_2B__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2B__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2B__
#endif
#endif

#ifdef __ENABLE_MOCANA_BLAKE_2S__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2S__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2S__
#endif
#endif

#if defined(__ENABLE_BLOWFISH_CIPHERS__) || defined(__ENABLE_MOCANA_BLOWFISH_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_BLOWFISH__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_BLOWFISH__
#endif
#endif

#if defined(__ENABLE_MOCANA_CHACHA20__) || defined(__ENABLE_MOCANA_CHACHA20_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_CHACHA20__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_CHACHA20__
#endif
#endif

#if defined(__ENABLE_DES_CIPHER__) || defined(__ENABLE_MOCANA_DES_ECB_OPERATOR__) || defined(__ENABLE_MOCANA_DES_CBC_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_DES__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_DES__
#endif
#endif

#if !defined(__DISABLE_MOCANA_DIFFIE_HELLMAN__) || defined(__ENABLE_MOCANA_DH_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_DH__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_DH__
#endif
#endif

#if defined(__ENABLE_MOCANA_ECC__) || defined(__ENABLE_MOCANA_ECC_P192_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P224_OPERATOR__) || \
    defined(__ENABLE_MOCANA_ECC_P256_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P384_OPERATOR__) || defined(__ENABLE_MOCANA_ECC_P521_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_ECC__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_ECC__
#endif

#ifdef __ENABLE_MOCANA_ECC_EDDSA__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_EDDSA__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_EDDSA__
#endif
#endif

#ifdef __ENABLE_MOCANA_ECC_ELGAMAL__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_ECC_ELGAMAL__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_ECC_ELGAMAL__
#endif
#endif

#endif /* __ENABLE_MOCANA_ECC__ */

#ifdef __ENABLE_MOCANA_DSA__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_DSA__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_DSA__
#endif
#endif

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_HMAC__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_HMAC__
#endif

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_HMAC_KDF__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_HMAC_KDF__
#endif

#ifndef __DISABLE_MOCANA_NIST_KDF__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_NIST_KDF__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_NIST_KDF__
#endif
#endif

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_ANSIX9_63_KDF__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_ANSIX9_63_KDF__
#endif

#if defined(__ENABLE_MOCANA_MD4__) || defined(__ENABLE_MOCANA_MD4_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_MD4__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_MD4__
#endif
#endif

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_MD5__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_MD5__
#endif

#ifdef __ENABLE_MOCANA_PKCS1__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS1__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS1__
#endif
#endif

#if defined(__ENABLE_MOCANA_PKCS5__) || defined(__ENABLE_MOCANA_PKCS5_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS5__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS5__
#endif
#endif

#if defined(__ENABLE_MOCANA_POLY1305__) || defined(__ENABLE_MOCANA_POLY1305_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_POLY1305__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_POLY1305__
#endif
#endif

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_PUBCRYPTO__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_PUBCRYPTO__
#endif

#ifndef __DISABLE_MOCANA_RNG__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_RANDOM__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_RANDOM__
#endif
#endif

#if !defined(__DISABLE_MOCANA_NIST_CTR_DRBG__) || defined(__ENABLE_MOCANA_CTR_DRBG_AES_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_NIST_CTR_DRBG__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_NIST_CTR_DRBG__
#endif
#endif

#ifdef __ENABLE_MOCANA_NIST_DRBG_HASH__
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_NIST_DRBG_HASH__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_NIST_DRBG_HASH__
#endif
#endif

#if (!defined(__DISABLE_MOCANA_KSRC_GENERATOR__)) || \
    (!defined(__DISABLE_MOCANA_FIPS186_RNG__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_FIPS186__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_FIPS186__
#endif
#endif

#if !defined(__DISABLE_MOCANA_RSA__) || defined(__ENABLE_MOCANA_RSA_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_RSA__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_RSA__
#endif
#endif

#if defined(__ENABLE_MOCANA_PQC_KEM__) || defined(__ENABLE_MOCANA_QS_KYBER_OPERATOR__) 
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_PQC_KEM__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_PQC_KEM__
#endif
#endif

#if defined(__ENABLE_MOCANA_PQC_SIG__) || defined(__ENABLE_MOCANA_QS_SPHINCS_OPERATOR__) || defined(__ENABLE_MOCANA_QS_DILITHIUM_OPERATOR__) || \
    defined(__ENABLE_MOCANA_QS_FALCON_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_PQC_SIG__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_PQC_SIG__
#endif
#endif

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA1__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA1__
#endif

#if !defined(__DISABLE_MOCANA_SHA224__) || defined(__ENABLE_MOCANA_SHA224_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA224__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA224__
#endif
#endif

#if !defined(__DISABLE_MOCANA_SHA256__) || defined(__ENABLE_MOCANA_SHA256_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA256__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA256__
#endif
#endif

#if !defined(__DISABLE_MOCANA_SHA384__) || defined(__ENABLE_MOCANA_SHA384_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA384__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA384__
#endif
#endif

#if !defined(__DISABLE_MOCANA_SHA512__) || defined(__ENABLE_MOCANA_SHA512_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA512__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA512__
#endif
#endif

#if defined(__ENABLE_MOCANA_SHA3__) || defined(__ENABLE_MOCANA_SHA3_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA3__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_SHA3__
#endif
#endif

#if !defined(__DISABLE_3DES_CIPHERS__) || defined(__ENABLE_MOCANA_TDES_ECB_OPERATOR__) || defined(__ENABLE_MOCANA_TDES_CBC_OPERATOR__)
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE_TDES__
#define __ENABLE_MOCANA_CRYPTO_INTERFACE_TDES__
#endif
#endif

#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ && !__ENABLE_MOCANA_IPSEC_SERVICE__ */

#ifdef __ENABLE_MOCANA_FIPS_MODULE__
/* FIPS Power-up status check, FIPS Event / Algorithm logging & related #defines */
/* These are macros only used within FIPS boundary crypto code. */

/* Declare FIPS Event log variables to be used within a function */
#define FIPS_LOG_DECL_SESSION ubyte4 FAlgoSessionId = 0
#define FIPS_LOG_DECL_FALGO int FAlgoId = 0

/* Mapping functions to map from algo mode to Algo-ID */
#define FIPS_GET_SHA3_FALGO(fa,mode) fa = FIPS_SHA3AlgoFromMode(mode)
#define FIPS_GET_AES_FALGO(fa,mode) fa = FIPS_AESAlgoFromMode(mode)

/* Logging functions */
#define FIPS_LOG_START_SVC(alg,key) FIPS_logAlgoEvent(FIPS_ApprovedServiceStart,alg,&FAlgoSessionId,key)
#define FIPS_LOG_END_SVC(alg,key)   FIPS_logAlgoEvent(FIPS_ApprovedServiceEnd,alg,&FAlgoSessionId,key)
#define FIPS_LOG_START_ALG(alg,key) FIPS_logAlgoEvent(FIPS_ApprovedAlgoStart,alg,&FAlgoSessionId,key)
#define FIPS_LOG_END_ALG(alg,key)   FIPS_logAlgoEvent(FIPS_ApprovedAlgoEnd,alg,&FAlgoSessionId,key)

/* FIPS STatus check functions */
#define FIPS_GET_STATUS_RETURN_IF_BAD(alg) \
    do { if (OK != getFIPS_powerupStatus(alg)) return getFIPS_powerupStatus(alg); } while (0)

#define FIPS_GET_STATUS_RETURN_NULL_IF_BAD(alg) \
    do { if (OK != getFIPS_powerupStatus(alg)) return NULL; } while (0)

#else /* __ENABLE_MOCANA_FIPS_MODULE__ */
/* Non-FIPS version does not use these same macros. */

#define FIPS_LOG_DECL_SESSION
#define FIPS_LOG_DECL_FALGO

#define FIPS_GET_SHA3_FALGO(fa,mode)
#define FIPS_GET_AES_FALGO(fa,mode)

#define FIPS_LOG_DECL_SESSION
#define FIPS_LOG_START_SVC(alg,key)
#define FIPS_LOG_END_SVC(alg,key)
#define FIPS_LOG_START_ALG(alg,key)
#define FIPS_LOG_END_ALG(alg,key)

#define FIPS_GET_STATUS_RETURN_IF_BAD(alg)
#define FIPS_GET_STATUS_RETURN_NULL_IF_BAD(alg)

#endif /* __ENABLE_MOCANA_FIPS_MODULE__ */

#endif /* __MOPTIONS_HEADER__ */
