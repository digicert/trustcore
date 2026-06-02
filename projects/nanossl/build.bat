@echo OFF
SETLOCAL ENABLEDELAYEDEXPANSION

:: Check if VSINSTALLDIR is set (Visual Studio environment required)
if not defined VSINSTALLDIR (
    echo ERROR: VSINSTALLDIR is not set. Visual Studio build environment is required.
    echo Please run this script from a Visual Studio Developer Command Prompt or use vsdevcmd.bat
    exit /b 1
)

:: Detect VS version using string substitution (most reliable method)
set "VS_PATH=%VSINSTALLDIR%"

:: Check for VS 2026 (path contains \18\)
if not "!VS_PATH:\18\=!"=="!VS_PATH!" (
    echo Detected Visual Studio 2026
    set VSIDE_GENERATOR_x64="Visual Studio 18 2026" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 18 2026" -A Win32
    goto :VS_DETECTED
)

:: Check for VS 2022 (path contains \2022\)
if not "!VS_PATH:\2022\=!"=="!VS_PATH!" (
    echo Detected Visual Studio 2022
    set VSIDE_GENERATOR_x64="Visual Studio 17 2022" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 17 2022" -A Win32
    goto :VS_DETECTED
)

:: Check for VS 2019 (path contains \2019\)
if not "!VS_PATH:\2019\=!"=="!VS_PATH!" (
    echo Detected Visual Studio 2019
    set VSIDE_GENERATOR_x64="Visual Studio 16 2019" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 16 2019" -A Win32
    goto :VS_DETECTED
)

:: If we get here, VSINSTALLDIR is set but version is unknown
echo ERROR: Unsupported Visual Studio version. VSINSTALLDIR=%VSINSTALLDIR%
echo Supported versions: Visual Studio 2019, 2022, 2026
exit /b 1

:VS_DETECTED
:: Set CMAKE path based on VSINSTALLDIR
set "CMAKE_PATH=%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set CMAKE_BIN="!CMAKE_PATH!\cmake.exe"

:: Check if CMAKE binary exists at the VS path
if exist "!CMAKE_PATH!\cmake.exe" (
    echo Using CMake from Visual Studio: !CMAKE_BIN!
    goto :CMAKE_READY
)

:: CMAKE not found in VS, check if it's in PATH
where cmake >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo CMake not found in Visual Studio installation, using cmake from PATH
    set CMAKE_BIN=cmake.exe
    goto :CMAKE_READY
)

:: CMAKE not found anywhere
echo ERROR: CMake is required but not found.
echo CMake was not found in Visual Studio installation at: !CMAKE_PATH!
echo CMake is also not available in PATH.
echo Please install CMake or use a Visual Studio installation that includes CMake.
exit /b 1

:CMAKE_READY

set TAP_OPT_ALLOWED=1
set BUILD_OPTIONS=
set BUILD_TYPE=
set BUILD_TARGET=
::Log file path
set LOG_FILE="build_bat.out"
set IS_STATIC_BUILD=0
set VS_PLATFORM=x64
set PROJECT_NAME=nanossl
set IS_64BIT_BUILD=0
set IS_32BIT_BUILD=0
set TARGET_TYPE=LIB

:argactionstart
if "-%~1-"=="--" goto argactionend

if "%~1"=="--help" call:usage & EXIT /B %ERRORLEVEL%
if "%~1"=="--gdb" set BUILD_TYPE=Debug& goto next
if "%~1"=="--pg" echo Enabling callstack tracing build...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PG=ON& goto next
if "%~1"=="--debug" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON& goto next
if "%~1"=="--suiteb" echo suiteb is always enabled. Ignoring legacy --suiteb flag.& goto next
if "%~1"=="--redefine" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_PEM_R_BIO_REDEFINE=ON& goto next
if "%~1"=="--rehandshake" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_REHANDSHAKE=ON& goto next
if "%~1"=="--x64" set IS_64BIT_BUILD=1& set BUILD_TARGET=x64& goto next
if "%~1"=="--x32" set IS_32BIT_BUILD=1& set BUILD_TARGET=x32& set VS_PLATFORM=Win32& goto next
if "%~1"=="--libtype" goto handle_libtype
if "%~1"=="--disable-tls13" echo Building without TLS 1.3 ...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TLS13=OFF& goto next
if "%~1"=="--disable-psk" echo Building without TLS 1.3 PSK ...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TLS13_PSK=OFF& goto next
if "%~1"=="--disable-0rtt" echo Building without TLS 1.3 0-RTT ...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TLS13_0RTT=OFF& goto next
if "%~1"=="--tap-off" goto next
if "%~1"=="--tap" echo Building with tap ...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON -DCM_ENABLE_NANOSSL_TAP=ON& goto next
if "%~1"=="--tap-local" echo Building with tap local...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_LOCAL=ON& goto next
if "%~1"=="--tap-remote" echo Building with tap remote...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE=ON& goto next
if "%~1"=="--tap-remote-tcp" echo Building with tap remote tcp...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE_TCP=ON& goto next
if "%~1"=="--tap-extern" echo Building with tap extern...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP_EXTERN=ON& goto next
if "%~1"=="--tap-deferred-unload" echo Building with tap deferred unload...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP_DEFER_UNLOADKEY=ON& goto next
if "%~1"=="--proxy" echo Building with handlers for ssl proxy support& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_PROXY_CONNECT=ON& goto next
if "%~1"=="--forcelink" echo Setting flags to force linkage ...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_WIN_FORCE_LINKAGE=ON& goto next
if "%~1"=="--ocsp" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OCSP=ON& goto next
if "%~1"=="--dtls" echo Building with dtls...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DTLS=ON& goto next
if "%~1"=="--srtp" echo Building with srtp dtls...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SRTP=ON& goto next
if "%~1"=="--openssl_3_0_7" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_3_0_7=ON& goto next
if "%~1"=="--openssl_3_0_12" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_3_0_12=ON& goto next
if "%~1"=="--openssl_3_5_0" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_3_5_0=ON& goto next
if "%~1"=="--openssl_1_1_1" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_1_1_1=ON& goto next
if "%~1"=="--openssl_1_1_1i" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_1_1_1I=ON& goto next
if "%~1"=="--openssl_1_1_1k" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_1_1_1K=ON& goto next
if "%~1"=="--openssl_1_0_2u" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_1_0_2U=ON& goto next
if "%~1"=="--openssl_1_0_2t" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_OPENSSL_LIB_1_0_2T=ON& goto next
if "%~1"=="--osslc_thread_safe" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSLC_THREAD_SAFE=ON& goto next
if "%~1"=="--openssl_shim" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OPENSSL_SHIM=ON& goto next
if "%~1"=="--ossl_multipacket_read" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_MULTIPACKET_READ=ON& goto next
if "%~1"=="--ossl_multipacket_bio_retry" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_MULTIPACKET_BIO_RETRY=ON& goto next
if "%~1"=="--disable_peek_error" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_PEER_ERROR=ON& goto next
if "%~1"=="openssl_shim_lib" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_OPENSSL_SHIM_LIB=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE& set PROJECT_NAME=openssl_shim& goto next
if "%~1"=="nanossl" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_NANOSSL_LIB=ON& set PROJECT_NAME=nanossl& goto next
if "%~1"=="--export" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_EXPORT_ED=ON -DCM_DISABLE_PQC& goto next
if "%~1"=="--mbed" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_EXPORT_ED=ON& goto next
if "%~1"=="--mbed-path" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_MBED_PATH=%~2& shift& goto next
if "%~1"=="--mauth" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_MAUTH_SUPPORT=ON& goto next
if "%~1"=="--nil-cipher" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_NIL=ON& goto next
if "%~1"=="--ossl-tls-unique" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_TLS_UNIQUE=ON& goto next
if "%~1"=="--openssl_load_algos" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_LOAD_ALGOS=ON& goto next
if "%~1"=="--self_signed" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_SELF_SIGNED_CERT=ON& goto next
if "%~1"=="--non_trusted" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_NONTRUSTED_CERT=ON& goto next
if "%~1"=="--cert_status_override" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_CERT_STATUS_OVERRIDE=ON& goto next
if "%~1"=="--force_cert_chain" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_FORCE_CERT_CHAIN=ON& goto next
if "%~1"=="--rsa1024" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_RSA_1024_SUPPORT=ON& goto next
if "%~1"=="--rsa_8k" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_RSA_8K=ON& goto next
if "%~1"=="--sha1" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SHA1_SUPPORT=ON& goto next
if "%~1"=="--dsa" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DSA_SUPPORT=ON& goto next
if "%~1"=="--enable_3des" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_3DES_SUPPORT=OFF& goto next
if "%~1"=="--disable_polychacha_tls12" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_POLYCHACHA_TLS12_SUPPORT=ON& goto next
if "%~1"=="--anon-support" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_ANON=ON& goto next
if "%~1"=="--fips" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FIPS=ON& goto next
if "%~1"=="--strict_dh" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_STRICT_DH=ON& goto next
if "%~1"=="--enable_ticket_tls12" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SESSION_TICKET_RFC_5077=ON& goto next
if "%~1"=="--ossl_rx_buf_8k" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_RX_BUF_8K=ON& goto next
if "%~1"=="--ossl_rx_buf_4k" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_RX_BUF_4K=ON& goto next
if "%~1"=="--ossl_rx_buf_2k" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_RX_BUF_2K=ON& goto next
if "%~1"=="--ossl_rx_buf_1k" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_RX_BUF_1K=ON& goto next
if "%~1"=="--keylog" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_KEYLOG_FILE=ON& goto next
if "%~1"=="--keylog_env_var" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_KEYLOG_ENV_VAR=ON& goto next
if "%~1"=="--ipv6" echo Building with IPV6 enabled ...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_IPV6=ON& goto next
if "%~1"=="--disable-pqc" echo Building with pqc disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_PQC=ON& goto next
if "%~1"=="--pqc-composite" echo Building with pqc composite...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PQC_COMPOSITE=ON& goto next
if "%~1"=="--oqs" echo Building with OQS...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OQS=ON& goto next
if "%~1"=="--pqc" echo PQC is enabled by default.& goto next
if "%~1"=="--cmake-opt" echo Setting extra flags for cmake execution...& set BUILD_OPTIONS=%BUILD_OPTIONS% %~2& shift& goto next
if "%~1"=="--clean" echo Clean build& goto next
if "%~1"=="--ossl_disable_read_ahead" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_OSSL_READ_AHEAD=ON& goto next
if "%~1"=="--ossl_single_read" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_OSSL_READ_AHEAD=ON -DCM_ENABLE_OSSL_RX_BUF_1K=ON& goto next
if "%~1"=="--extended-key" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_EXTENDED_KEYUSAGE=ON& goto next
if "%~1"=="--disable-servername-validation" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_SSL_SERVER_NAME=ON& goto next
if "%~1"=="--disable-client-commonname-validation" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_SSL_CLIENT_COMMON_NAME_VALIDATION=ON& goto next
if "%~1"=="--disable_ossl_default_trust_certs" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_OSSL_DEFAULT_TRUST_CERTS=ON& goto next
if "%~1"=="--version-logging" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_VERSION_LOGGING=ON& goto next
if "%~1"=="--redirect-log" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_LOGGING_REDIRECT=ON& goto next
if "%~1"=="--ossl_log" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_LOG=ON& goto next
if "%~1"=="--srp" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_SRP=ON& goto next
if "%~1"=="--disable-dual-mode-api" echo Building without dual mode APIs...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_DUAL_MODE_API=ON& goto next
if "%~1"=="--disable-server-async" echo Building without server async APIs...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_SERVER_ASYNC_API=ON& goto next
if "%~1"=="--disable-client-async" echo Building without client async APIs...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_CLIENT_ASYNC_API=ON& goto next
if "%~1"=="--disable-server" echo Building without server APIs...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_SERVER_API=ON& goto next
if "%~1"=="--disable-ciphersuite-select" echo Building without ciphersuite select APIs...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_CIPHERSUITE_SELECT=ON& goto next
if "%~1"=="--disable-key-expansion" echo Building without SSL key expansion...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_SSL_KEY_EXPANSION=ON& goto next
if "%~1"=="--psk" echo Building with PSK support for TLS 1.2 and below...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PSK=ON& goto next
if "%~1"=="--pss-auto-recover" echo Building with PSS auto recover...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PSS_AUTO_RECOVER=ON& goto next
if "%~1"=="--gcc_profile" echo Building with gcc profile...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_GCC_PROFILING=ON& goto next
if "%~1"=="--no-cryptointerface" echo Building with crypto interface disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_CI=ON& goto next
if "%~1"=="--disable_rsa" echo Building with RSA disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_RSA_SUPPORT=ON& goto next
if "%~1"=="--enable_des" echo Building with DES enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DES_SUPPORT=ON& goto next
if "%~1"=="--disable-cbc" echo Building with CBC disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_CBC_SUPPORT=ON& goto next
if "%~1"=="--enable_ecp192" echo Building with EC P-192 enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ECP192_SUPPORT=ON& goto next
if "%~1"=="--dh_pub_pad" echo Building with DH public key padding...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DH_PUB_PAD=ON& goto next
if "%~1"=="--enable_eap_fast" echo Building with EAP fast enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_EAP_FAST=ON& goto next
if "%~1"=="--aes-gcm-4k" echo Building with AES-GCM 4K table...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_AES_GCM_4K=ON& goto next
if "%~1"=="--aes-gcm-256b" echo Building with AES-GCM 256b table...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_AES_GCM_256B=ON& goto next
if "%~1"=="--tls12-fallback" echo Building with TLS 1.2 fallback enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TLS12_FALLBACK=ON& goto next
if "%~1"=="--defer-encoding-client-cert-auth" echo Building with deferred encoding...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEFER_CLIENT_AUTH=ON& goto next
if "%~1"=="--monolithic" echo Building as monolithic...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MONOLITHIC_BUILD=ON& goto next
if "%~1"=="--nanossl-common" echo Linking to common nanossl library...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_COMMON_LINK=ON& goto next
if "%~1"=="--enable_heartbeat" echo Building with heartbeat protocol handling...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_HEARTBEAT_RFC_6520=ON& goto next
if "%~1"=="--enable_extended_master_secret" echo Building with extended master secret support...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_EXTENDED_MASTERSECRET_RFC_7627=ON& goto next
if "%~1"=="--enable_session_id" echo Building with session ID support...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL_SESSION_CACHE=ON& goto next
if "%~1"=="--opensslld_override" echo Building with ld override option...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OSSL_LD_OVERRIDE=ON& goto next
if "%~1"=="--enforce_cert_sig_algo" echo Building with certificate signature algorithm checks enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ENFORCE_CERT_SIG_ALGO=ON& goto next
if "%~1"=="--ssl_client_example_aesgcm" echo Building with AES-GCM ciphers only on SSL Client Example...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_EXAMPLE_AESGCM_CIPHERS_ONLY=ON& goto next
if "%~1"=="--ssl_interop_test" echo Building ssl example with interop test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_TEST=ON& goto next
if "%~1"=="--ssl_interop_psk_test" echo Building ssl example with interop PSK test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_PSK_TEST=ON& goto next
if "%~1"=="--ssl_interop_ex_psk_test" echo Building ssl example with interop external PSK test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_EXTERNAL_PSK_TEST=ON& goto next
if "%~1"=="--ssl_interop_ticket_test" echo Building ssl example with interop ticket and heartbeat test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_TICKET_TEST=ON& goto next
if "%~1"=="--ssl_interop_sessionid_test" echo Building ssl example with interop session ID test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_SESSIONID_TEST=ON& goto next
if "%~1"=="--dtls_interop_test" echo Building dtls example with interop test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_DTLS_EXAMPLE_INTEROP_TEST=ON& goto next
if "%~1"=="--dtls_interop_rehandshake_test" echo Building dtls example with interop rehandshake test updates...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_DTLS_EXAMPLE_INTEROP_REHANDSHAKE_TEST=ON& goto next
if "%~1"=="--cvc" echo Building with CVC support...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_CVC=ON& goto next
if "%~1"=="--client-cert-cb" echo Building with client certificate callback...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_CLIENT_CERT_CB=ON& goto next
if "%~1"=="--graceful_shutdown" echo Building with graceful shutdown...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_SSL_EXAMPLE_GRACEFUL_SHUTDOWN=ON& goto next
if "%~1"=="--post_client_auth" echo Enable TLSv1.3 post client authentication example...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_SSL_POST_CLIENT_AUTH_EXAMPLE=ON& goto next
if "%~1"=="--pkcs12" echo Building with server example using PKCS12 cert...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_PKCS12_CERT=ON& goto next
if "%~1"=="--disable-weak-ciphers" echo Building with weak ciphers disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_WEAK_CIPHERS=ON& goto next
if "%~1"=="--ssl-example-smart-card" echo Building with ssl example smart card...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_SSL_EXAMPLE_SMART_CARD=ON& goto next
if "%~1"=="--enable-no-cipher-match" echo Building DTLS server for no cipher match to stop the timer...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ERR_SSL_NO_CIPHER_MATCH=ON& goto next
if "%~1"=="--disable_chacha20poly1305" echo Building with ChaCha20-Poly1305 disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_CHACHA20POLY1305=ON& goto next
if "%~1"=="--disable-aes-ccm" echo Building with AES-CCM disabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_AES_CCM=ON& goto next
if "%~1"=="--data-protect" echo Building with data protect...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MOCANA_DATA_PROTECTION=ON& goto next
if "%~1"=="--sp800-135" echo Building for testing SP800-135...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SP800_135=ON& goto next
if "%~1"=="ssl_client" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_CLIENT=ON& set PROJECT_NAME=ssl_client& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_client_async" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_CLIENT_ASYNC=ON& set PROJECT_NAME=ssl_client_async& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_client_async_external_psk" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_CLIENT_ASYNC_EXTERNAL_PSK=ON& set PROJECT_NAME=ssl_client_async_external_psk& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_client_sp800_135" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_CLIENT_SP800_135=ON& set PROJECT_NAME=ssl_client_sp800_135& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_server" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_SERVER=ON& set PROJECT_NAME=ssl_server& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_server_async" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_SERVER_ASYNC=ON& set PROJECT_NAME=ssl_server_async& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_server_async_external_psk" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_SERVER_ASYNC_EXTERNAL_PSK=ON& set PROJECT_NAME=ssl_server_async_external_psk& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_server_gw" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_SERVER_GW=ON& set PROJECT_NAME=ssl_server_gw& set TARGET_TYPE=EXE& goto next
if "%~1"=="ssl_serialize_psk" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_SSL_SERIALIZE_PSK=ON& set PROJECT_NAME=ssl_serialize_psk& set TARGET_TYPE=EXE& goto next
if "%~1"=="dtls_client" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_DTLS_CLIENT=ON& set PROJECT_NAME=dtls_client& set TARGET_TYPE=EXE& goto next
if "%~1"=="dtls_server" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_DTLS_SERVER=ON& set PROJECT_NAME=dtls_server& set TARGET_TYPE=EXE& goto next
if "%~1"=="nanodtls_client" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_NANO_DTLS_CLIENT=ON& set PROJECT_NAME=nanodtls_client& set TARGET_TYPE=LIB& goto next
if "%~1"=="nanodtls_server" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_NANO_DTLS_SERVER=ON& set PROJECT_NAME=nanodtls_server& set TARGET_TYPE=LIB& goto next
if "%~1"=="--build-for-osi" set BUILD_OPTIONS=%BUILD_OPTIONS% -DBUILD_FOR_OSI=ON& goto next
if "%~1"=="--log" goto handle_log

echo invalid option %1
call:usage
EXIT /B 1

:handle_libtype
if "%~2"=="static" (
    set IS_STATIC_BUILD=1
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
) else if "%~2"=="shared" (
    set IS_STATIC_BUILD=0
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
) else (
    echo "Error reading libtype %2 switching to default - shared"
    set IS_STATIC_BUILD=0
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
)
shift
goto next

:handle_log
if "%~2"=="" (
    echo "Error reading log file path %2"
    exit /b 1
)
set LOG_FILE="%~2"
shift
goto next

:next
shift
goto argactionstart

:argactionend

if ""== "%BUILD_TYPE%" (
  set BUILD_TYPE=Release
)

if ""== "%BUILD_TARGET%" (
  set IS_64BIT_BUILD=1
  set BUILD_TARGET=x64
)

if %IS_32BIT_BUILD%==1 (
  if %IS_64BIT_BUILD%==1 (
    echo "Error: Both the flags --x32 and --x64 should not be passed. Either one of the flags --x32 or x64 flag should be passed."
    EXIT /B 1
  )
)


echo Building %PROJECT_NAME% library.
call clean.bat %PROJECT_NAME% %TARGET_TYPE%

echo ********** Building %PROJECT_NAME% library ********** >>%LOG_FILE%
if %BUILD_TARGET%==x64 (
    call %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt 1>>%LOG_FILE% 2>>&1
) else (
    call %CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt 1>>%LOG_FILE% 2>>&1
)

call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1

if NOT %ERRORLEVEL% == 0 (
   echo Build failed
   echo Exited with error %ERRORLEVEL%
   echo Refer file "%LOG_FILE%" for details.
   exit /b %ERRORLEVEL%
)

echo Build Successful

EXIT /B %ERRORLEVEL%

:usage
  echo.
  echo    "./build.bat --help --gdb --debug --libtype <static | shared> --x64 --log <log_file>"
  echo.
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --disable-tls13   - Build with TLS 1.3 disabled."
  echo "   --disable-psk     - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt    - Build with TLS 1.3 0-RTT disabled."
  echo "   --disable-dual-mode-api - Build without dual mode APIs."
  echo "   --disable-server-async - Build without server async APIs."
  echo "   --disable-client-async - Build without client async APIs."
  echo "   --disable-server  - Build without server APIs."
  echo "   --disable-ciphersuite-select - Build without ciphersuite select APIs."
  echo "   --disable-key-expansion - Build without SSL key expansion."
  echo "   --psk             - Build with PSK support for TLS 1.2 and below."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --tap             - Build with tap for nanossl library."
  echo "   --tap-local       - Build with tap-local."
  echo "   --tap-remote      - Build with tap-remote."
  echo "   --tap-remote-tcp  - Build with tap-remote-tcp."
  echo "   --tap-extern      - Build with tap-extern."
  echo "   --tap-deferred-unload - Build with tap-deferred-unload."
  echo "   --proxy           - Build with transport handlers for proxy support."
  echo "   --dtls            - Build with dtls."
  echo "   --srtp            - Build with SRTP profiles for dtls."
  echo "   --mauth           - Build with mutual authentication."
  echo "   --pss-auto-recover - Allow NanoSSL to recover the salt length for PSS signatures."
  echo "   --ossl-tls-unique - Build with additional TLS unique support for the OpenSSL shim/connector."
  echo "   --openssl_shim    - Build with openssl_shim enabled."
  echo "   --ossl_multipacket_read - Enable reading of multiple records in a loop."
  echo "   --ossl_multipacket_bio_retry - Enable read until data is received."
  echo "   --disable-pqc     - Build without pqc."
  echo "   --pqc-composite   - Build with pqc composite signature algs."
  echo "   --oqs             - Build with OQS support."
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --nil-cipher      - Build with Nil Cipher enabled."
  echo "   --mbed            - Enable mbed Operators."
  echo "   --export          - Build the Export Edition of this library."
  echo "   --self_signed     - Enable self signed cert."
  echo "   --non_trusted     - Enable non trust cert."
  echo "   --cert_status_override - Override the OpenSSL shim certificate status if NanoSSL certificate validation is successful."
  echo "   --force_cert_chain - Enable loading of full cert chain along with the leaf cert."
  echo "   --ocsp            - Enable OCSP."
  echo "   --rsa_8k          - Enable RSA 8K."
  echo "   --gcc_profile     - Enable gcc profile."
  echo "   --fips            - Enable fips module."
  echo "   --strict_dh       - Build with strict DH enabled."
  echo "   --no-cryptointerface - Build with Crypto Interface disabled."
  echo "   --disable_rsa     - Disable rsa support."
  echo "   --enable_des      - Enable DES cipher support."
  echo "   --enable_3des     - Enable 3DES cipher support."
  echo "   --disable-cbc     - Disable CBC cipher support."
  echo "   --disable_polychacha_tls12 - Disable CHACHA20-POLY1305 ciphers for TLS 1.2 and lower versions."
  echo "   --disable_chacha20poly1305 - Disable ChaCha20-Poly1305."
  echo "   --disable-aes-ccm - Disable AES-CCM."
  echo "   --enable_ecp192   - Enable EC P-192 curve support."
  echo "   --dh_pub_pad      - Pad DH public keys."
  echo "   --enable_eap_fast - Enable EAP fast support."
  echo "   --redefine        - Enable redefine."
  echo "   --rehandshake     - Enable rehandshake."
  echo "   --anon-support    - Enable anonymous suites."
  echo "   --openssl_1_1_1i  - Build with openssl 1_1_1i."
  echo "   --openssl_1_1_1k  - Build with openssl 1_1_1k."
  echo "   --openssl_3_0_7   - Build with openssl 3_0_7."
  echo "   --openssl_3_0_12  - Build with openssl 3_0_12."
  echo "   --openssl_3_5_0   - Build with openssl 3_5_0."
  echo "   --openssl_load_algos - Build option to load all algorithms."
  echo "   --osslc_thread_safe - Build with thread safe handling for OpenSSL connector client."
  echo "   --extended-key    - Enable extended key usage."
  echo "   --rsa1024         - Set the minimum RSA key size to 1024 (unsecure)."
  echo "   --sha1            - Build NanoSSL with the SHA-1 algorithm allowed."
  echo "   --dsa             - Build NanoSSL with the DSA support."
  echo "   --aes-gcm-4k      - Build with AES-GCM 4K table."
  echo "   --aes-gcm-256b    - Build with AES-GCM 256b table."
  echo "   --tls12-fallback  - Build NanoSSL TLS 1.2 fallback enabled."
  echo "   --disable-servername-validation - Server flag to ignore the certificate common name."
  echo "   --disable-client-commonname-validation - Client flag to ignore the certificate common name check."
  echo "   --disable_ossl_default_trust_certs - Disable loading of default CA Certs."
  echo "   --defer-encoding-client-cert-auth - Defer encoding of client certificate authentication digest message."
  echo "   --version-logging - Enable version_logging."
  echo "   --redirect-log    - Redirect printf logs to stderr in OpenSSL Connector."
  echo "   --ossl_log        - Enable logging in OpenSSL Connector."
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --clean           - Clean build."
  echo "   --srp             - Enable SRP(Secure Remote Password)."
  echo "   --monolithic      - Build executables as a single binary with all dependencies."
  echo "   --nanossl-common  - Link to common nanossl library."
  echo "   --enable_ticket_tls12 - Enable server side session ticket implementation as per RFC 5077."
  echo "   --enable_heartbeat - Enable the heart beat protocol as per RFC 6520."
  echo "   --enable_extended_master_secret - Enable support for computation of Extended Master Secret as per RFC 7627."
  echo "   --enable_session_id - Enable session resumption with session ID."
  echo "   --ossl_rx_buf_8k  - Build with 8K receive buffer."
  echo "   --ossl_rx_buf_4k  - Build with 4K receive buffer."
  echo "   --ossl_rx_buf_2k  - Build with 2K receive buffer."
  echo "   --ossl_rx_buf_1k  - Build with 1K receive buffer."
  echo "   --opensslld_override - Build with ld file from thirdparty directory."
  echo "   --disable_peek_error - Building with peer error disabled."
  echo "   --keylog          - Building with key logging enabled."
  echo "   --keylog_env_var  - Use environment variable for key logging."
  echo "   --ossl_disable_read_ahead - Disable read ahead by default."
  echo "   --ossl_single_read - Build with 1K buffer and single read."
  echo "   --enforce_cert_sig_algo - Enforce certificate signature check when validating peer certificate chain."
  echo "   --ssl_client_example_aesgcm - Enable only AES-GCM ciphers on SSL Client Example."
  echo "   --ssl_interop_test - Build ssl example with interop test updates."
  echo "   --ssl_interop_psk_test - Build ssl client example with interop PSK test updates."
  echo "   --ssl_interop_ex_psk_test - Build ssl client example with interop external PSK test updates."
  echo "   --ssl_interop_ticket_test - Build ssl client example with interop ticket and heartbeat test updates."
  echo "   --ssl_interop_sessionid_test - Build ssl client example with interop session ID test updates."
  echo "   --dtls_interop_test - Build dtls example with interop test updates."
  echo "   --dtls_interop_rehandshake_test - Build dtls example with interop rehandshake test updates."
  echo "   --cvc             - Enable support for Card Verifiable Certificates."
  echo "   --client-cert-cb  - Enable client cert callback."
  echo "   --graceful_shutdown - Shutdown the server or client example gracefully."
  echo "   --post_client_auth - Enable Post Client Authentication example."
  echo "   --pkcs12          - Build server with PKCS12 support."
  echo "   --disable-weak-ciphers - Build ssl server example with ssl weak ciphers disabled."
  echo "   --ssl-example-smart-card - Build ssl server example with ssl smart card."
  echo "   --enable-no-cipher-match - Build DTLS server for no cipher match condition to stop the timer."
  echo "   --data-protect    - Build with data protect."
  echo "   --sp800-135       - Build for testing SP800-135."
  echo "     ssl_server      - Build the SSL Server."
  echo "     ssl_server_async - Build the SSL Async Server."
  echo "     ssl_server_gw   - Build the SSL Server Gateway."
  echo "     ssl_server_async_external_psk - Build the SSL Async Server with External PSK."
  echo "     ssl_client      - Build the SSL Client."
  echo "     ssl_client_async - Build the SSL Async Client."
  echo "     ssl_client_async_external_psk - Build the SSL Async Client with External PSK."
  echo "     ssl_client_sp800_135 - Build the SSL Client for SP800-135 testing."
  echo "     ssl_serialize_psk - Build the SSL serialize PSK application."
  echo "     dtls_server     - Build the DTLS Server."
  echo "     dtls_client     - Build the DTLS Client."
  echo "     nanossl         - Build the nanossl library."
  echo "     nanodtls_client - Build the nanodtls Client."
  echo "     nanodtls_server - Build the nanodtls Server."
  echo "     openssl_shim_lib - Build the openssl-shim library."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   --log <log_file>  - Dump compilation logs to specified log file."
  echo.
EXIT /B 0
