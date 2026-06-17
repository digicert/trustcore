@echo off
setlocal enabledelayedexpansion

:: Set script directory
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: Source configuration
call "%SCRIPT_DIR%\configuration.bat"

:: Set paths
set "MSS_DIR=%SCRIPT_DIR%\..\..\..\"
pushd "%MSS_DIR%"
set "MSS_DIR=%CD%"
popd
set "MSS_PROJECTS_DIR=%MSS_DIR%\projects"
set "BIN_DIR=%MSS_DIR%\bin"

:: Check if building for OSI
:: OSI build is detected if digicert_example.c exists and is not a symlink
set "OSI_BUILD=0"
set "IS_SYMLINK="
set "CHECK_FILE=%MSS_DIR%\samples\common\digicert_example.c"
if exist "%CHECK_FILE%" (
  :: Check if it's a symbolic link (reparse point)
  for /f "tokens=*" %%A in ('dir /AL "%CHECK_FILE%" 2^>nul ^| find "SYMLINK"') do set "IS_SYMLINK=1"
  if not defined IS_SYMLINK (
    set "OSI_BUILD=1"
    echo Building for OSI...
  )
)

:: Default global build options
if "%OSI_BUILD%"=="1" (
  set "BUILD_OPTIONS= --build-for-osi"
) else (
  set "BUILD_OPTIONS="
)
:: Library specific build options
set "COMMON_BUILD_OPTIONS=--libtype static --debug --debug-forward --build-info --arg-parser --msg-logger --uri --common-utils --protobuf --mime-parser"
set "PLATFORM_BUILD_OPTIONS=--process --term --signal --libtype static"
set "ASN1_BUILD_OPTIONS=--libtype static --cms"
set "INITIALIZE_BUILD_OPTIONS=--libtype static"
set "NANOCAP_BUILD_OPTIONS=--libtype static --suiteb"
set "CERT_ENROLL_BUILD_OPTIONS=--libtype static"
set "CRYPTO_BUILD_OPTIONS=--libtype static --debug --suiteb --ssl --keygen"
set "NANOCERT_BUILD_OPTIONS=--libtype static --suiteb --cert --json-verify --cmc --est --debug --status-log"
set "NANOSSL_BUILD_OPTIONS=--libtype static --clean --suiteb --keylog --keylog_env_var"
set "NANOMQTT_BUILD_OPTIONS=--libtype static --ssl --library --streaming"
set "TRUSTEDGE_BUILD_OPTIONS=--debug --disable-rest-api"

set "UNITTEST_ARG=0"
set "PACKAGE=0"
set "MONOLITHIC=0"

set "NO_REBUILD=0"
set "TAP_ARG="
set "PKCS11_ARG="
set "PKCS11_PATH="
set "SMP_ARG="
set "SMP_PKCS11_ARG= --pkcs11"
set "SMP_TPM2_ARG="
set "TAP_MODE="
set "TAP_COMMON_ARG="
set "COMMON_ARG="
set "CVC_ARG="
set "PQC_ARG= --disable-pqc"
set "PQC_COMPOSITE_ARG="
set "OQS_ARG="
set "OQS_PATH="
set "EXPORT_ARG="
set "MBED_ARG="
set "OCSP_ARG="
set "VERSION_STRING="
set "DIGICERT_SCEP="
set "PROXY_ARG="
set "PC_ARG="
set "MEM_PROFILE_ARG="
set "GCM_OPT= --aes-gcm-256b"

:: Parse command line arguments
:parse_args
if "%~1"=="" goto :end_parse_args

if /i "%~1"=="--help" (
  call :show_usage
  exit /b 0
)
if /i "%~1"=="--gdb" (
  set "BUILD_OPTIONS=!BUILD_OPTIONS! --gdb"
  goto :next_arg
)
if /i "%~1"=="--no-lib-rebuild" (
  echo NOT building supporting libraries.
  set "NO_REBUILD=1"
  goto :next_arg
)
if /i "%~1"=="--aes-gcm-4k" (
  echo Building with AES-GCM 4k table.
  set "GCM_OPT= --aes-gcm-4k"
  goto :next_arg
)
if /i "%~1"=="--aes-gcm-64k" (
  echo Building with AES-GCM 64k table.
  set "GCM_OPT="
  goto :next_arg
)
if /i "%~1"=="--pkcs11-dynamic" (
  echo -- Building with pkcs11 dynamic load enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-local"
  set "SMP_TPM2_ARG= --tpm2"
  set "PKCS11_ARG= --pkcs11-dynamic"
  set "SMP_ARG= --pkcs11"
  set "COMMON_ARG= --dynamic-load"
  set "OCSP_ARG= --ocsp"
  goto :next_arg
)
if /i "%~1"=="--softhsm2" (
  echo -- Building with pkcs11 softhsm2 enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-local"
  set "SMP_TPM2_ARG= --tpm2"
  set "PKCS11_ARG= --softhsm2"
  set "SMP_ARG= --pkcs11"
  set "OCSP_ARG= --ocsp"
  goto :next_arg
)
if /i "%~1"=="--cloudhsm" (
  echo -- Building with pkcs11 cloudhsm enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-local"
  set "SMP_TPM2_ARG= --tpm2"
  set "PKCS11_ARG= --cloudhsm"
  set "SMP_ARG= --pkcs11"
  set "OCSP_ARG= --ocsp"
  goto :next_arg
)
if /i "%~1"=="--dssm" (
  echo -- Building with pkcs11 dssm enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-local"
  set "SMP_TPM2_ARG= --tpm2"
  set "PKCS11_ARG= --dssm"
  set "SMP_ARG= --pkcs11"
  set "OCSP_ARG= --ocsp"
  goto :next_arg
)
if /i "%~1"=="--pkcs11-tee" (
  echo -- Building with pkcs11 tee enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-local"
  set "SMP_TPM2_ARG= --tpm2"
  set "PKCS11_ARG= --pkcs11-tee"
  set "SMP_ARG= --pkcs11"
  set "OCSP_ARG= --ocsp"
  goto :next_arg
)
if /i "%~1"=="--tpm2" (
  echo -- Building with tpm2 enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-local"
  set "SMP_TPM2_ARG= --tpm2"
  set "SMP_ARG= --tpm2"
  set "SMP_PKCS11_ARG="
  set "OCSP_ARG= --ocsp"
  set "CERT_ENROLL_BUILD_OPTIONS=!CERT_ENROLL_BUILD_OPTIONS! --tap"
  set "CRYPTO_BUILD_OPTIONS=!CRYPTO_BUILD_OPTIONS! --tap-hybrid-sign"
  goto :next_arg
)
if /i "%~1"=="--pkcs11-path" (
  set "PKCS11_PATH=%~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--tap-remote" (
  echo -- Building with TAP remote enabled...
  set "TAP_ARG= --tap"
  set "TAP_MODE= --tap-remote"
  set "OCSP_ARG= --ocsp"
  goto :next_arg
)
if /i "%~1"=="--cvc" (
  set "CVC_ARG= --cvc"
  echo Building with cvc cert support...
  goto :next_arg
)
if /i "%~1"=="--enable-pc" (
  set "PC_ARG= --enable-pc"
  echo Building with cert/csr printing support...
  goto :next_arg
)
if /i "%~1"=="--pqc" (
  set "PQC_ARG= --pqc"
  echo Building with PQC support...
  goto :next_arg
)
if /i "%~1"=="--pqc-composite" (
  set "PQC_COMPOSITE_ARG= --pqc-composite"
  echo Building with PQC composite support...
  goto :next_arg
)
if /i "%~1"=="--oqs" (
  set "PQC_ARG= --pqc"
  set "OQS_ARG= --oqs"
  echo Building with PQC/OQS support...
  goto :next_arg
)
if /i "%~1"=="--oqs-path" (
  set "OQS_PATH= --oqs-path %~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--mbed" (
  set "EXPORT_ARG= --export"
  echo Building with export support...
  goto :next_arg
)
if /i "%~1"=="--mbed-path" (
  set "MBED_ARG= --mbed --mbed-path %~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--digicert" (
  set "DIGICERT_SCEP= --digicert"
  goto :next_arg
)
if /i "%~1"=="--unittest" (
  set "UNITTEST_ARG=1"
  goto :next_arg
)
if /i "%~1"=="--debug-internals" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1"
  goto :next_arg
)
if /i "%~1"=="--monolithic" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1"
  set "MONOLITHIC=1"
  goto :next_arg
)
if /i "%~1"=="--library" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! --disable-rest-api --monolithic %~1"
  set "MONOLITHIC=1"
  goto :next_arg
)
if /i "%~1"=="--libtype" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! --libtype %~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--msg-timestamp" (
  set "COMMON_BUILD_OPTIONS=!COMMON_BUILD_OPTIONS! %~1"
  goto :next_arg
)
if /i "%~1"=="--persist-artifact" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1"
  goto :next_arg
)
if /i "%~1"=="--proxy" (
  set "PROXY_ARG= --proxy"
  goto :next_arg
)
if /i "%~1"=="--minimal" (
  echo Building with minimal ciphers
  set "CM_ENV_STRIP_FUNC=1"
  set "COMMON_BUILD_OPTIONS=!COMMON_BUILD_OPTIONS! --disable-error-code-lookup"
  set "CRYPTO_BUILD_OPTIONS=!CRYPTO_BUILD_OPTIONS! --disable-aes-ccm --disable-aes-cmac --disable-aes-eax --disable-aes-mmo --disable-aes-xcbc-mac-96 --disable-aes-xts --disable-rc4 --disable-chacha20 --disable-poly1305 --disable-des --disable-dsa --disable-fips186-rng --disable-rc5 --disable-ec-elgamal --disable-ec-mqv --small-footprint"
  set "NANOCERT_BUILD_OPTIONS=!NANOCERT_BUILD_OPTIONS! --disable-dsa"
  set "NANOSSL_BUILD_OPTIONS=!NANOSSL_BUILD_OPTIONS! --disable-weak-ciphers --disable-aes-ccm --disable_chacha20poly1305 --disable-psk --disable-0rtt --disable-dual-mode-api --disable-client-async --disable-server-async --disable-server --disable-ciphersuite-select --disable-key-expansion"
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! --disable-rest-api"
  goto :next_arg
)
if /i "%~1"=="--package" (
  set "PACKAGE=1"
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! package"
  goto :next_arg
)
if /i "%~1"=="--pre-release" (
  if "%~2"=="" (
    call :show_usage "Missing pre-release string"
    exit /b 1
  )
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1 %~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--toolchain" (
  echo Cross-compiling for %~2
  set "BUILD_OPTIONS=!BUILD_OPTIONS! %~1 %~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--esp32" (
  echo Cross compiling for ESP32
  set "BUILD_OPTIONS=!BUILD_OPTIONS! --toolchain esp32"
  goto :next_arg
)
if /i "%~1"=="--esp32-version" (
  echo ESP IDF version
  set "BUILD_OPTIONS=!BUILD_OPTIONS! --cmake-opt -DESP32_VERSION=%~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--esp32-idf-path" (
  set "BUILD_OPTIONS=!BUILD_OPTIONS! --cmake-opt -DESP32_IDF_PATH=%~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--esp32-sdkconfig-path" (
  set "BUILD_OPTIONS=!BUILD_OPTIONS! --cmake-opt -DESP32_SDKCONFIG_PATH=%~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--x32" (
  set "BUILD_OPTIONS=!BUILD_OPTIONS! %~1"
  echo Building for x32 machine...
  goto :next_arg
)
if /i "%~1"=="--x64" (
  set "BUILD_OPTIONS=!BUILD_OPTIONS! %~1"
  echo Building for x64 machine...
  goto :next_arg
)
if /i "%~1"=="--service-certificate" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1"
  echo Building with service certificate mode conf...
  goto :next_arg
)
if /i "%~1"=="--valgrind-tool" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1 %~2"
  echo Enabling valgrind tool %~2...
  shift
  goto :next_arg
)
if /i "%~1"=="--mem-profile" (
  set "MEM_PROFILE_ARG= --mem-profile"
  echo Enabling memory profiling.
  goto :next_arg
)
if /i "%~1"=="--version-string" (
  echo Version string: %~2
  set "VERSION_STRING=--version-string %~2"
  shift
  goto :next_arg
)
if /i "%~1"=="--enable-coverage" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1"
  goto :next_arg
)
if /i "%~1"=="--enable-token-fallback" (
  set "TRUSTEDGE_BUILD_OPTIONS=!TRUSTEDGE_BUILD_OPTIONS! %~1"
  goto :next_arg
)

:: Invalid option
call :show_usage "Invalid option: %~1"
exit /b 1

:next_arg
shift
goto :parse_args

:end_parse_args

:: Cleanup previous build
if "%NO_REBUILD%"=="0" (
  if exist "%MSS_DIR%\bin\*.dll" del /f /q "%MSS_DIR%\bin\*.dll" 2>nul
  if exist "%MSS_DIR%\bin_static\*.lib" del /f /q "%MSS_DIR%\bin_static\*.lib" 2>nul
)
if exist "%MSS_DIR%\bin\trustedge.exe" del /f /q "%MSS_DIR%\bin\trustedge.exe"
if exist "%MSS_DIR%\bin_static\trustedge.exe" del /f /q "%MSS_DIR%\bin_static\trustedge.exe"

:: Copy PKCS11 library if needed (Windows equivalent)
if "%SMP_ARG%"==" --pkcs11" (
  echo Copying PKCS11 library(s^) from %PKCS11_PATH%
  if "%PKCS11_ARG%"==" --pkcs11-tee" (
    copy "%PKCS11_PATH%\libckteec.dll" "%BIN_DIR%\"
    copy "%PKCS11_PATH%\libteec.dll" "%BIN_DIR%\"
  ) else if not "%PKCS11_ARG%"==" --pkcs11-dynamic" (
    copy "%PKCS11_PATH%" "%BIN_DIR%\"
  )
)

:: Set TAP_COMMON_ARG based on TAP_MODE
if not "%TAP_MODE%"=="" (
  if "%TAP_MODE%"==" --tap-local" (
    set TAP_COMMON_ARG=--cmake-opt "-DCM_TAP_TYPE=LOCAL"
  ) else (
    set TAP_COMMON_ARG=--cmake-opt "-DCM_TAP_TYPE=REMOTE"
  )
)

:: Handle EXPORT_ARG and OQS_ARG
if not "%EXPORT_ARG%"=="" (
  if "%OQS_ARG%"=="" (
    echo Export Build with no oqs, disabling PQC
    set "PQC_ARG= --disable-pqc"
  )
)

:: Build libraries
if "%NO_REBUILD%"=="0" (
  echo Building common library...
  pushd "%MSS_PROJECTS_DIR%\common"
  call clean.bat
  call build.bat %MEM_PROFILE_ARG% %TAP_COMMON_ARG% %COMMON_ARG% %BUILD_OPTIONS% %COMMON_BUILD_OPTIONS% %VERSION_STRING%
  if errorlevel 1 goto :build_error
  popd

  echo Building platform library...
  pushd "%MSS_PROJECTS_DIR%\platform"
  call clean.bat
  call build.bat %BUILD_OPTIONS% %PLATFORM_BUILD_OPTIONS%
  if errorlevel 1 goto :build_error
  popd

  echo Building asn1 library...
  pushd "%MSS_PROJECTS_DIR%\asn1"
  call clean.bat
  call build.bat %CVC_ARG% %PQC_ARG% %BUILD_OPTIONS% %ASN1_BUILD_OPTIONS%
  if errorlevel 1 goto :build_error
  popd

  echo Building initialize library...
  pushd "%MSS_PROJECTS_DIR%\initialize"
  call clean.bat
  call build.bat %MEM_PROFILE_ARG% %BUILD_OPTIONS% %INITIALIZE_BUILD_OPTIONS%
  if errorlevel 1 goto :build_error
  popd

  echo Building nanocap library...
  pushd "%MSS_PROJECTS_DIR%\nanocap"
  call clean.bat
  call build.bat %BUILD_OPTIONS% %NANOCAP_BUILD_OPTIONS%
  if errorlevel 1 goto :build_error
  popd

  echo Building crypto library...
  pushd "%MSS_PROJECTS_DIR%\crypto"
  call clean.bat
  call build.bat %CVC_ARG% %TAP_ARG% %TAP_MODE% %PC_ARG% %SMP_TPM2_ARG% %PQC_ARG% %OQS_ARG% %OQS_PATH% %EXPORT_ARG% %MBED_ARG% %CRYPTO_BUILD_OPTIONS% %GCM_OPT% %BUILD_OPTIONS%
  if errorlevel 1 goto :build_error
  popd

  echo Building nanocert library...
  pushd "%MSS_PROJECTS_DIR%\nanocert"
  call clean.bat
  call build.bat %TAP_ARG% %OCSP_ARG% %PC_ARG% %PQC_ARG% %CVC_ARG% %EXPORT_ARG% %BUILD_OPTIONS% %NANOCERT_BUILD_OPTIONS% %PROXY_ARG%
  if errorlevel 1 goto :build_error
  popd

  echo Building cert_enroll library...
  pushd "%MSS_PROJECTS_DIR%\cert_enroll"
  call clean.bat
  call build.bat %BUILD_OPTIONS% %CERT_ENROLL_BUILD_OPTIONS%
  if errorlevel 1 goto :build_error
  popd

  :: TAP builds
  if not "%TAP_MODE%"=="" (
    echo Building nanotap2_common library...
    pushd "%MSS_PROJECTS_DIR%\nanotap2_common"
    call clean.bat
    call build.bat --libtype static %BUILD_OPTIONS% --suiteb %SMP_ARG% %TAP_MODE%
    if errorlevel 1 goto :build_error
    popd

    echo Building nanotap2 library...
    pushd "%MSS_PROJECTS_DIR%\nanotap2"
    call clean.bat
    call build.bat --libtype static %BUILD_OPTIONS% %SMP_ARG% %TAP_MODE% nanotap2
    if errorlevel 1 goto :build_error
    popd

    echo Building nanotap2_configparser library...
    pushd "%MSS_PROJECTS_DIR%\nanotap2_configparser"
    call clean.bat
    call build.bat --libtype static %BUILD_OPTIONS%
    if errorlevel 1 goto :build_error
    popd

    if "%TAP_MODE%"==" --tap-remote" (
      echo Building nanotap2 clientcomm...
      pushd "%MSS_PROJECTS_DIR%\nanotap2"
      call build.bat --libtype static --tap-remote %BUILD_OPTIONS% clientcomm
      if errorlevel 1 goto :build_error
      popd
    ) else (
      echo Building tpm2 library...
      pushd "%MSS_PROJECTS_DIR%\tpm2"
      call clean.bat
      call build.bat --libtype static %BUILD_OPTIONS% --suiteb %SMP_PKCS11_ARG%
      if errorlevel 1 goto :build_error
      popd

      if "%SMP_ARG%"==" --pkcs11" (
        echo Building smp_pkcs11 library...
        pushd "%MSS_PROJECTS_DIR%\smp_pkcs11"
        call clean.bat
        call build.bat --libtype static %BUILD_OPTIONS% --suiteb %PKCS11_ARG%
        if errorlevel 1 goto :build_error
        popd
      ) else (
        echo Building smp_tpm2 library...
        pushd "%MSS_PROJECTS_DIR%\smp_tpm2"
        call build.bat --libtype static %BUILD_OPTIONS% --suiteb --x64
        if errorlevel 1 goto :build_error
        popd
      )
    )

    echo Building nanossl library with TAP...
    pushd "%MSS_PROJECTS_DIR%\nanossl"
    call clean.bat
    call build.bat %BUILD_OPTIONS% %EXPORT_ARG% %NANOSSL_BUILD_OPTIONS% %GCM_OPT% --ocsp nanossl --mauth %PQC_ARG% %PQC_COMPOSITE_ARG% %OQS_ARG% %PROXY_ARG%
    if errorlevel 1 goto :build_error
    popd
  ) else (
    echo Building nanossl library...
    pushd "%MSS_PROJECTS_DIR%\nanossl"
    call clean.bat
    call build.bat %BUILD_OPTIONS% %EXPORT_ARG% %NANOSSL_BUILD_OPTIONS% %GCM_OPT% nanossl %PQC_ARG% %PQC_COMPOSITE_ARG% %OQS_ARG% %PROXY_ARG%
    if errorlevel 1 goto :build_error
    popd
  )

  echo Building mqtt_client nanomqtt...
  pushd "%MSS_PROJECTS_DIR%\mqtt_client"
  call clean.bat
  call build.bat %BUILD_OPTIONS% %NANOMQTT_BUILD_OPTIONS% %PQC_ARG% nanomqtt
  if errorlevel 1 goto :build_error
  popd

  echo Building mqtt_client sample...
  pushd "%MSS_PROJECTS_DIR%\mqtt_client"
  call clean.bat
  call build.bat %BUILD_OPTIONS% %NANOMQTT_BUILD_OPTIONS% %PQC_ARG% mqtt_client_sample %PROXY_ARG%
  if errorlevel 1 goto :build_error
  popd
)

:: Build trustedge binary
if "%PACKAGE%"=="1" (
  set "TRUSTEDGE_PROJ_DIR=%MSS_PROJECTS_DIR%\trustedge"
  pushd "%MSS_DIR%"
  if exist dist rmdir /s /q dist
  mkdir dist
  popd
)

:: For Windows, TGZ and MSI are supported (DEB/RPM are Linux formats)
for %%G in (TGZ MSI) do (
  echo cd %MSS_PROJECTS_DIR%\trustedge ^&^& clean.bat ^&^& build.bat %VERSION_STRING% %SMP_ARG% %TAP_MODE% %PKCS11_ARG% %CVC_ARG% %PC_ARG% %OQS_ARG% %PQC_ARG% %EXPORT_ARG% %DIGICERT_SCEP% %BUILD_OPTIONS% %TRUSTEDGE_BUILD_OPTIONS% --generator %%G %PROXY_ARG%
  
  pushd "%MSS_PROJECTS_DIR%\trustedge"
  call clean.bat
  call build.bat %VERSION_STRING% %SMP_ARG% %TAP_MODE% %PKCS11_ARG% %CVC_ARG% %PC_ARG% %OQS_ARG% %PQC_ARG% %EXPORT_ARG% %DIGICERT_SCEP% %BUILD_OPTIONS% %TRUSTEDGE_BUILD_OPTIONS% --generator %%G %PROXY_ARG%
  if errorlevel 1 goto :build_error
  popd

  if "%PACKAGE%"=="1" (
    if "%%G"=="DEB" (
      copy "%TRUSTEDGE_PROJ_DIR%\build\*.deb" "%MSS_DIR%\dist\" 2>nul
    )
    if "%%G"=="RPM" (
      copy "%TRUSTEDGE_PROJ_DIR%\build\*.rpm" "%MSS_DIR%\dist\" 2>nul
    )
    if "%%G"=="TGZ" (
      copy "%TRUSTEDGE_PROJ_DIR%\build\*.tar.gz" "%MSS_DIR%\dist\" 2>nul
    )
    if "%%G"=="MSI" (
      copy "%TRUSTEDGE_PROJ_DIR%\build\*.msi" "%MSS_DIR%\dist\" 2>nul
    )
  )
)

:: Build with unittest if requested
if "%UNITTEST_ARG%"=="1" (
  echo cd %MSS_PROJECTS_DIR%\trustedge ^&^& clean.bat ^&^& build.bat %SMP_ARG% %TAP_MODE% %PKCS11_ARG% %CVC_ARG% %OQS_ARG% %PQC_ARG% %EXPORT_ARG% %BUILD_OPTIONS% %TRUSTEDGE_BUILD_OPTIONS% --unittest --library
  
  pushd "%MSS_PROJECTS_DIR%\trustedge"
  call clean.bat
  call build.bat %SMP_ARG% %TAP_MODE% %PKCS11_ARG% %CVC_ARG% %OQS_ARG% %PQC_ARG% %EXPORT_ARG% %BUILD_OPTIONS% %TRUSTEDGE_BUILD_OPTIONS% --unittest --library
  if errorlevel 1 goto :build_error
  popd
)

echo Build completed successfully.
exit /b 0

:build_error
echo Build failed!
popd 2>nul
exit /b 1

:: Show usage function
:show_usage
echo Usage: %~nx0 [options]
echo Options:
echo   --help                 - Show help options
echo   --gdb                  - Build with debug symbols
echo   --aes-gcm-4k           - Build with AES-GCM 4k table (rather than 256b default)
echo   --aes-gcm-64k          - Build with AES-GCM 64k table (rather than 256b default)
echo   --pkcs11-dynamic       - Build with dynamic loading for multiple pkcs11 libraries
echo   --softhsm2             - Build with softhsm2 pkcs11 support.
echo   --cloudhsm             - Build with cloudhsm pkcs11 support.
echo   --dssm                 - Build with Digicert SSM PKCS11 library
echo   --pkcs11-tee           - Build with tee pkcs11 support.
echo   --tpm2                 - Build with tpm2 support.
echo   --pkcs11-path          - Path to pkcs11 library. Must be followed by the path.
echo   --tap-remote           - Build with TAP remote support.
echo   --no-lib-rebuild       - Don't rebuild the suporting libraries.
echo   --cvc                  - Build with CV Certificate support.
echo   --enable-pc            - Enable Certificate/CSR printing.
echo   --pqc                  - Build with PQC support.
echo   --pqc-composite        - Build with PQC composite support.
echo   --oqs                  - Build with PQC/OQS support.
echo   --oqs-path             - Path to oqs install location, can be absolute or relative.
echo   --mbed                 - Build with mbedtls support
echo   --mbed-path            - Path to mbed install location, can be absolute or relative.
echo   --digicert             - Add support for Digicert SCEP.
echo   --unittest             - Build with unittesting
echo   --debug-internals      - Internal debug logging
echo   --monolithic           - Build monolithic binary
echo   --library              - Build as library (disables REST API, enables monolithic)
echo   --libtype ^<shared ^| static^> - Specify library type
echo   --minimal              - Build with minimal code footprint
echo   --package              - Package artifacts
echo   --pre-release          - Specify pre-release string
echo   --msg-timestamp        - Enable timestamps in log messages.
echo   --persist-artifact     - Enable persisting artifact payload.
echo   --proxy                - Build with proxy support enabled.
echo   --x32                  - Build for 32-bit platforms.
echo   --x64                  - Build for 64-bit platforms.
echo   --service-certificate  - Build with service certificate mode support.
echo   --valgrind-tool ^<tool^> - Enable valgrind with selected tool.
echo                              memcheck
echo                              massif
echo   --mem-profile          - Build with memory profiling.
echo   --version-string       - Version information for release.
echo   --enable-coverage      - Build with gcov code coverage support.
echo   --enable-token-fallback - Enable fallback when authorization token missing.
echo   --toolchain ^<rpi32 ^| rpi64 ^| bbb ^| android^> - Specify the toolchain to be used
echo                         rpi32     For Raspberry Pi 32-bit
echo                         rpi64     For Raspberry Pi 64-bit
echo                         bbb       For BeagleBone Black
echo                         android   For android
echo   --esp32                - Cross compile for ESP32
echo   --esp32-version        - ESP IDF version. Must be followed by the version.
echo   --esp32-idf-path       - Path to ESP IDF install location. Must be followed by the path.
echo   --esp32-sdkconfig-path - Path to ESP32 sdkconfig file. Must be followed by the path.
echo.
if not "%~1"=="" (
  echo %~1
  echo.
  exit /b 1
)
exit /b 0
