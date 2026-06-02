::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: BAT script to build OpenSSL connector for Windows
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

@echo off

SETLOCAL ENABLEEXTENSIONS
SETLOCAL ENABLEDELAYEDEXPANSION

:: Constant declarations.
set DEBUG_OPTIONS=
set DTLS_OPTION=
set DTLS_SRTP_OPTION=
set MAUTH_OPTION=
set EXPORT_OPTION=
set MBED_OPTION=
set MBED_PATH_OPTION=
set MBED_PATH=
set DISABLE_PQC=
set REDEFINE_OPTION=
set TAP_OPTION=
set TAP_TYPE_OPTION=
set TPM_OPTION=
set FIPS_OPTION=
set OPENSSL_OPTION=--openssl_1_0_2t
set OPENSSL_CONFIG_OPTION=enable-mocana-cryptointerface
set OPENSSL_LIB_OPTION=openssl-1.0.2t
set OPENSSL_VER=1.0.2
set TAP_HYBRID_SIGN_OPTION=
set OPENSSL_1_0_2_NMAKE_GEN=
set OPENSSL_CLIENT_TARGET=openssl_client_local
set IS_GDB_BUILD=0
set IS_DEBUG_BUILD=0
set OPENSSL_ENGINE_TYPE=enable-static-engine
set OSSL_COMPILER_PARAM=VC-WIN64A
set IS_64BIT_BUILD=0
set IS_32BIT_BUILD=0
set IS_TAP_BUILD=0
set IS_FIPS_BUILD=0
set BUILD_LIBMSS=0
set DO_CLEAN=1
set CUSTOM_ENTROPY_OPTION=
set TLS13_OPTION=
set RSA1024_OPTION=
set RSA8K_OPTION=
set SHA1_OPTION=
set RC5_DISABLE_CRYPTO_OPTION=
set OSSL3_RC5_OPTION=enable-rc5
set OCSP_OPTION=
set OCSP_CERT_OPTION=
set URI_OPTION=
set NANOSSL_OSSL_OPTIONS=
set DISABLE_STRICT_CA_CHECK_OPTION=
set DISABLE_CERT_EXT_CHECK_OPTION=
set STRICT_DH_OPTION=
set OSI_OPTION=
set BUILD_FOR_OSI=0

:: Variable declarations
set BAT_DIR=%~dp0
set WORKSPACE=%BAT_DIR%..\..\..
set MSS_DIR=%WORKSPACE%
set MSS_PROJECTS_DIR=%MSS_DIR%\projects
set SMP_DEP_FLAG=
set PASS_PARAM=
set FIRST_PASS_PARAM=--forcelink
set OSSL_LIBSSL_NAME=libssl
set OSSL_LIBSSL_WVER_NAME=
set OSSL_LIBCRYPTO_NAME=libcrypto
set OSSL_LIBCRYPTO_WVER_NAME=
set STATIC_LIBS=
set STATIC_BUILD=

:: ERROR values declarations
set SUCCESS=0
set ERR_EXIT=1
set ERR_INV_ARGS=2

:: Print variables
echo WORKSPACE=%WORKSPACE%

::
GOTO:MAIN


:clean
    if %DO_CLEAN%==1 (
        echo ***************************************************************
        echo *** Cleaning binaries and libraries
        echo ***************************************************************
        del /s /q "%MSS_DIR%\bin_win32\*.dll"
        del /s /q "%MSS_DIR%\bin_win32\*.lib"
        del /s /q "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%\sample\%OPENSSL_CLIENT_TARGET%"
        del /s /q "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%\sample\openssl_server"
    )
EXIT /B %ERRORLEVEL%


:build

if not exist "%MSS_DIR%\bin_win32" mkdir "%MSS_DIR%\bin_win32"
if not "%STATIC_BUILD%"=="" (
    if not exist "%MSS_DIR%\bin_win32_static" mkdir "%MSS_DIR%\bin_win32_static"
)

echo ***************************************************************
echo *** Building OpenSSL shim with CAP...
echo **************************************************************
FOR %%G IN (first second) DO (
    if %%G==first (
        echo Setting extra parameters for first pass
        set PASS_PARAM=!FIRST_PASS_PARAM!
    ) else (
        set PASS_PARAM=
    )

    :: First confirm the openssl dir exists
    if not exist "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%" (
      echo.
      echo Error: Directory "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%" does not exist. Exiting.
      goto:end 1
    )

    echo Building common library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\common"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !FIPS_OPTION! ^
                        !TARGET_ARCH_PARAM! !URI_OPTION! !STATIC_LIBS! !OSI_OPTION!

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !FIPS_OPTION! ^
             !TARGET_ARCH_PARAM! !URI_OPTION! !STATIC_LIBS! !OSI_OPTION!
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    echo Building platform library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\platform"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !FIPS_OPTION! ^
                        !TARGET_ARCH_PARAM! !STATIC_LIBS! !OSI_OPTION!

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !FIPS_OPTION! ^
             !TARGET_ARCH_PARAM! !STATIC_LIBS! !OSI_OPTION!
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    if %%G==first (
      if %BUILD_LIBMSS%==1 (
        pushd "%MSS_PROJECTS_DIR%\fips\libmss"
        echo Executing: build.bat !DEBUG_OPTIONS! !STATIC_BUILD! !TARGET_ARCH_PARAM!
        call build.bat --disable-integ-test !DEBUG_OPTIONS! !STATIC_BUILD! !TARGET_ARCH_PARAM!
        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd
      )
    )

    echo Building asn1 library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\asn1"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !DISABLE_PQC! !FIPS_OPTION! ^
                        !TARGET_ARCH_PARAM! !STATIC_LIBS! !OSI_OPTION! --no-datalib

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !DISABLE_PQC! !FIPS_OPTION! ^
             !TARGET_ARCH_PARAM! !STATIC_LIBS! !OSI_OPTION! --no-datalib
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    echo Building initialize library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\initialize"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !FIPS_OPTION! ^
                        !TARGET_ARCH_PARAM! !CUSTOM_ENTROPY_OPTION! !STATIC_LIBS! !OSI_OPTION!

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !FIPS_OPTION! ^
             !TARGET_ARCH_PARAM! !CUSTOM_ENTROPY_OPTION! !STATIC_LIBS! !OSI_OPTION!
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    echo Building nanocap library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\nanocap"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                        !FIPS_OPTION! --suiteb !STATIC_LIBS! !OSI_OPTION!

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
             !FIPS_OPTION! --suiteb !STATIC_LIBS! !OSI_OPTION!
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    echo Building crypto library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\crypto"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! --suiteb ^
                      --ssl --openssl!OSSL_VER! !TAP_OPTION! !TPM2_OPTION! !EXPORT_OPTION! ^
                      !RC5_DISABLE_CRYPTO_OPTION! !FIPS_OPTION! !STATIC_LIBS! --no-datalib ^
                      !MBED_OPTION! !DISABLE_PQC! !MBED_PATH_OPTION! "!MBED_PATH!" !RSA8K_OPTION! ^
                      !TAP_HYBRID_SIGN_OPTION! !OSI_OPTION!

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! --suiteb ^
          --ssl --openssl!OSSL_VER! !TAP_OPTION! !TPM2_OPTION! !EXPORT_OPTION! ^
          !RC5_DISABLE_CRYPTO_OPTION! !FIPS_OPTION! !STATIC_LIBS! --no-datalib ^
          !MBED_OPTION! !DISABLE_PQC! !MBED_PATH_OPTION! "!MBED_PATH!" !RSA8K_OPTION! !OSI_OPTION!
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    if %IS_TAP_BUILD%==1 (
        echo Building nanotap2_common library in %%G pass
        pushd "%MSS_PROJECTS_DIR%\nanotap2_common"
        if %DO_CLEAN%==1 call clean.bat
        echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                          !FIPS_OPTION! !TAP_TYPE_OPTION! !TPM2_OPTION! !OSI_OPTION!

        call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
              !FIPS_OPTION! !TAP_TYPE_OPTION! !TPM2_OPTION! !OSI_OPTION!
        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd

        echo Building nanotap2_configparser library in %%G pass
        pushd "%MSS_PROJECTS_DIR%\nanotap2_configparser"
        if %DO_CLEAN%==1 call clean.bat
        echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! ^
                            !FIPS_OPTION! !TARGET_ARCH_PARAM! !OSI_OPTION!
        call build.bat !PASS_PARAM! !DEBUG_OPTIONS! ^
                 !FIPS_OPTION! !TARGET_ARCH_PARAM! !OSI_OPTION!
        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd

        echo Building nanotap2 library in %%G pass
        pushd "%MSS_PROJECTS_DIR%\nanotap2"
        if %DO_CLEAN%==1 call clean.bat
        echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                          !FIPS_OPTION! !TAP_TYPE_OPTION! !TPM2_OPTION! !OSI_OPTION! nanotap2

        call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                !FIPS_OPTION! !TAP_TYPE_OPTION! !TPM2_OPTION! !OSI_OPTION! nanotap2
        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd
    )

    echo Building nanocert library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\nanocert"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                        !FIPS_OPTION! --suiteb --openssl !DISABLE_PQC! !TAP_OPTION! !EXPORT_OPTION! ^
                        !OCSP_OPTION! !OCSP_CERT_OPTION! !DISABLE_STRICT_CA_CHECK_OPTION! ^
                        !DISABLE_CERT_EXT_CHECK_OPTION! !STATIC_LIBS! !RSA8K_OPTION! !OSI_OPTION!

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
             !FIPS_OPTION! --suiteb --openssl !DISABLE_PQC! !TAP_OPTION! !EXPORT_OPTION! ^
             !OCSP_OPTION! !OCSP_CERT_OPTION! !DISABLE_STRICT_CA_CHECK_OPTION! ^
             !DISABLE_CERT_EXT_CHECK_OPTION! !STATIC_LIBS! !RSA8K_OPTION! !OSI_OPTION!
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    if %%G==first (
        pushd "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%"
        ::Configure
        echo Configuring %OPENSSL_LIB_OPTION%, with params - "%OSSL_COMPILER_PARAM% %OPENSSL_CONFIG_OPTION% %OPENSSL_ENGINE_TYPE%"
        call perl Configure %OSSL_COMPILER_PARAM% %OPENSSL_CONFIG_OPTION% %OPENSSL_ENGINE_TYPE%
        set status = !ERRORLEVEL!
        IF !status! NEQ 0 (
            echo Error in Configure for OpenSSL - !status!
            goto:end !status!
        )

        ::Build using nmake
        if "!OPENSSL_VER!"=="1.0.2" (
            echo Building OpenSSL libraries.
            echo Executing - "!OPENSSL_1_0_2_NMAKE_GEN!"
            call !OPENSSL_1_0_2_NMAKE_GEN!
            if "%STATIC_BUILD%"=="" (
                echo Executing - "nmake -f ms\ntdll.mak"
                call nmake -f ms\ntdll.mak
            ) else (
                echo Executing - "nmake -f ms\nt.mak"
                call nmake -f ms\nt.mak
            )
            if errorlevel 1 goto:end !ERRORLEVEL!
            echo Copying libraries to bin_win32
            call copy_to_mss_bin_win32.bat %STATIC_BUILD%
        ) else (
            echo Building OpenSSL libraries.
            echo Executing - "nmake clean all"
            call nmake clean all
            if errorlevel 1 goto:end !ERRORLEVEL!

            if "%STATIC_BUILD%"=="" (
                echo Copying OSSL libcrypto.dll
                XCOPY /Y "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%\!OSSL_LIBCRYPTO_WVER_NAME!".* "%MSS_DIR%\bin_win32"
                echo Copying OSSL libcrypto.lib
                XCOPY /Y "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%\!OSSL_LIBCRYPTO_NAME!".lib "%MSS_DIR%\bin_win32"
            ) else (
                echo Copying OSSL libcrypto.lib
                XCOPY /Y "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%\!OSSL_LIBCRYPTO_NAME!".lib "%MSS_DIR%\bin_win32_static"
            )
        )

        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd
    )

    if %IS_TAP_BUILD%==1 (
        echo Building tpm2 library in %%G pass
        pushd "%MSS_PROJECTS_DIR%\tpm2"
        if %DO_CLEAN%==1 call clean.bat
        echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                            !FIPS_OPTION! !OSI_OPTION! --suiteb --openssl_shim

        call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                 !FIPS_OPTION! !OSI_OPTION! --suiteb --openssl_shim
        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd

        echo Building smp_tpm2 library in %%G pass
        pushd "%MSS_PROJECTS_DIR%\smp_tpm2"
        if %DO_CLEAN%==1 call clean.bat
        echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                            !FIPS_OPTION! !OSI_OPTION! --suiteb --openssl_shim

        call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                 !FIPS_OPTION! !OSI_OPTION! --suiteb --openssl_shim
        IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
        popd
    )

    echo Building nanossl library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\nanossl"
    if %DO_CLEAN%==1 call clean.bat
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
                        --suiteb --openssl_shim !DISABLE_PQC! !EXPORT_OPTION! !DTLS_OPTION! !DTLS_SRTP_OPTION! ^
                        !FIPS_OPTION! !MAUTH_OPTION! !OPENSSL_OPTION! !TAP_OPTION! ^
                        !TLS13_OPTION! !RSA1024_OPTION! !SHA1_OPTION! !OCSP_OPTION! ^
                        !STRICT_DH_OPTION! !NANOSSL_OSSL_OPTIONS! !STATIC_LIBS! ^
                        !RSA8K_OPTION! !OSI_OPTION! nanossl

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !TARGET_ARCH_PARAM! ^
             --suiteb --openssl_shim !DISABLE_PQC! !EXPORT_OPTION! !DTLS_OPTION! !DTLS_SRTP_OPTION! ^
             !FIPS_OPTION! !MAUTH_OPTION! !OPENSSL_OPTION! !TAP_OPTION! ^
             !TLS13_OPTION! !RSA1024_OPTION! !SHA1_OPTION! !OCSP_OPTION! ^
             !STRICT_DH_OPTION! !NANOSSL_OSSL_OPTIONS! !STATIC_LIBS! ^
             !RSA8K_OPTION! !OSI_OPTION! nanossl
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    echo Building openssl shim library in %%G pass
    pushd "%MSS_PROJECTS_DIR%\nanossl"
    if %DO_CLEAN%==1 call clean.bat openssl_shim_lib
    echo Executing: build.bat !PASS_PARAM! !DEBUG_OPTIONS! !REDEFINE_OPTION! ^
                        !TARGET_ARCH_PARAM! --suiteb !DISABLE_PQC! !TAP_TYPE_OPTION! ^
                        --openssl_shim !EXPORT_OPTION! !DTLS_OPTION! ^
                        !FIPS_OPTION! !MAUTH_OPTION! !OPENSSL_OPTION! !OCSP_OPTION! ^
                        !NANOSSL_OSSL_OPTIONS! !STATIC_LIBS! !OSI_OPTION! openssl_shim_lib

    call build.bat !PASS_PARAM! !DEBUG_OPTIONS! !REDEFINE_OPTION! ^
             !TARGET_ARCH_PARAM! --suiteb !DISABLE_PQC! !TAP_TYPE_OPTION! ^
             --openssl_shim !EXPORT_OPTION! !DTLS_OPTION! ^
             !FIPS_OPTION! !MAUTH_OPTION! !OPENSSL_OPTION! !OCSP_OPTION! ^
             !NANOSSL_OSSL_OPTIONS! !STATIC_LIBS! !OSI_OPTION! openssl_shim_lib
    IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
    popd

    if !ERRORLEVEL! NEQ 0 (
        echo *********************************************
        echo **** Library build failed on %%G pass  ****
        echo *********************************************
        EXIT /B ERR_EXIT
    ) else (
        echo ***********************************************
        echo *****  %%G pass library build successful  *****
        echo ***********************************************
    )

    if "!OPENSSL_VER!"=="1.0.2" (
        if "%STATIC_BUILD%"=="" (
            pushd "!MSS_DIR!\bin_win32"
        ) else (
            pushd "!MSS_DIR!\bin_win32_static"
        )
        echo Creating symbolic links to openssl_shim
        for %%f in (openssl_shim.*) do (
            call :create_link !OSSL_LIBSSL_WVER_NAME!%%~xf , %%~nf%%~xf
        )
        popd
    ) else (
        if NOT "%OPENSSL_OPTION%"=="" (
          if "%STATIC_BUILD%"=="" (
            pushd "!MSS_DIR!\bin_win32"
            echo Executing - call :create_link !OSSL_LIBSSL_WVER_NAME!.dll , openssl_shim.dll
            call :create_link !OSSL_LIBSSL_WVER_NAME!.dll , openssl_shim.dll
            IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
            echo Executing - call :create_link !OSSL_LIBSSL_NAME!.lib , openssl_shim.lib
            call :create_link !OSSL_LIBSSL_NAME!.lib , openssl_shim.lib
            popd
          ) else (
            pushd "!MSS_DIR!\bin_win32_static"
            echo Executing - call :create_link !OSSL_LIBSSL_NAME!.lib , openssl_shim.lib
            call :create_link !OSSL_LIBSSL_NAME!.lib , openssl_shim.lib
            popd
          )
        )
    )

    if %%G==second (
        ::Build binaries only on the second pass
        pushd "%MSS_DIR%\thirdparty\%OPENSSL_LIB_OPTION%\sample"
        :: if %DO_CLEAN%==1 call clean.bat openssl_client_local
        echo Executing: build.bat !DEBUG_OPTIONS! !MAUTH_OPTION! ^
                            !TARGET_ARCH_PARAM! !TAP_OPTION! !FIPS_OPTION! !STATIC_LIBS! ^
                            !OPENSSL_CLIENT_TARGET!

        call build.bat !DEBUG_OPTIONS! !MAUTH_OPTION! ^
                 !TARGET_ARCH_PARAM! !TAP_OPTION! !FIPS_OPTION! !STATIC_LIBS! ^
                 !OPENSSL_CLIENT_TARGET!
        if !ERRORLEVEL! NEQ 0 (
            echo ********************************
            echo **** Binaries build failed  ****
            echo ********************************
            EXIT /B ERR_EXIT
        )
        :: if %DO_CLEAN%==1 call clean.bat openssl_server
        echo Executing: build.bat !DEBUG_OPTIONS! !MAUTH_OPTION! ^
                            !TARGET_ARCH_PARAM! !TAP_OPTION! !FIPS_OPTION! !STATIC_LIBS! ^
                            openssl_server

        call build.bat !DEBUG_OPTIONS! !MAUTH_OPTION! ^
                 !TARGET_ARCH_PARAM! !TAP_OPTION! !FIPS_OPTION! !STATIC_LIBS! ^
                 openssl_server
        if !ERRORLEVEL! NEQ 0 (
            echo ********************************
            echo **** Binaries build failed  ****
            echo ********************************
            EXIT /B ERR_EXIT
        ) else (
            echo **************************************
            echo **** Binaries built successfully  ****
            echo **************************************
        )
    )

)

EXIT /B %ERRORLEVEL%


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to parse arguments

:argactionstart
    set arg1=%~1
    if "-%~1-"=="--" goto argactionend
    if "%~1"=="--help" (
        call:show_usage
        EXIT /B %ERR_EXIT%
    ) else if "%~1"=="--x64" (
        set IS_64BIT_BUILD=1
        set TARGET_ARCH_PARAM=--x64
        set OSSL_COMPILER_PARAM=VC-WIN64A
        set OPENSSL_1_0_2_NMAKE_GEN=ms\do_win64a.bat
        goto next
    ) else if "%~1"=="--x32" (
        set IS_32BIT_BUILD=1
        set TARGET_ARCH_PARAM=--x32
        set OSSL_COMPILER_PARAM=VC-WIN32
        set OPENSSL_1_0_2_NMAKE_GEN=ms\do_nasm.bat
        goto next
    ) else if "%~1"=="--redefine" (
        echo Building with redefine...
        set REDEFINE_OPTION=%~1
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-redefine"
        goto next
    ) else if "%~1"=="--fips" (
        echo Linking to libmss...
        set FIPS_OPTION=%~1
        set IS_FIPS_BUILD=1
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-fips"
        goto next
    ) else if "%~1"=="--build-libmss" (
        echo Building libmss...
        set BUILD_LIBMSS=1
        goto next
    ) else if "%~1"=="--openssl_1_0_2u" (
        echo Building for OpenSSL 1.0.2u...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-1.0.2u
        set OPENSSL_VER=1.0.2
        goto next
    ) else if "%~1"=="--openssl_1_1_1" (
        echo Building for OpenSSL 1.1.1c...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-1.1.1c
        set OPENSSL_VER=1.1.1
        goto next
    ) else if "%~1"=="--openssl_1_1_1f" (
        echo Building for OpenSSL 1.1.1f...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-1.1.1f
        set OPENSSL_VER=1.1.1
        goto next
    ) else if "%~1"=="--openssl_1_1_1i" (
        echo Building for OpenSSL 1.1.1i...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-1.1.1i
        set OPENSSL_VER=1.1.1
        goto next
    ) else if "%~1"=="--openssl_1_1_1k" (
        echo Building for OpenSSL 1.1.1k...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-1.1.1k
        set OPENSSL_VER=1.1.1
        goto next
    ) else if "%~1"=="--openssl_3_0_7" (
        echo Building for OpenSSL 3.0.7...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-3.0.7
        set OPENSSL_VER=3
        set OSSL_VER=3
        set OPENSSL_ENGINE_TYPE=
        goto next
    ) else if "%~1"=="--openssl_3_0_12" (
        echo Building for OpenSSL 3.0.12...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-3.0.12
        set OPENSSL_VER=3
        set OSSL_VER=3
        set OPENSSL_ENGINE_TYPE=
        goto next
    ) else if "%~1"=="--openssl_3_5_0" (
        echo Building for OpenSSL 3.5.0...
        set OPENSSL_OPTION=%~1
        set OPENSSL_LIB_OPTION=openssl-3.5.0
        set OPENSSL_VER=3
        set OSSL_VER=3
        set OPENSSL_ENGINE_TYPE=
        goto next
    ) else if "%~1"=="--mbed-path" (
        echo Building with mbed...
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-export"
        set "EXPORT_OPTION=--export"
        set "DISABLE_PQC=--disable-pqc"
        set "MBED_OPTION=--mbed"
        set "MBED_PATH_OPTION=--mbed-path"
        set "MBED_PATH=%~2"
        shift
        goto next
    ) else if "%~1"=="--gdb" (
        echo Enabling Debug build...
        set "DEBUG_OPTIONS=!DEBUG_OPTIONS! %~1"
        ::To Pass --debug option to openssl's perl configure command
        set IS_GDB_BUILD=1
        goto next
    ) else if "%~1"=="--debug" (
        echo Building with Debug logs enabled...
        set "DEBUG_OPTIONS=!DEBUG_OPTIONS! %~1"
        :: --debug option
        set IS_DEBUG_BUILD=1
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION!"
        goto next
    ) else if "%~1"=="--dtls" (
        echo Building with DTLS enabled...
        set DTLS_OPTION=%~1
        goto next
    ) else if "%~1"=="--tap-hybrid-sign" (
        echo Building with TAP hybrid signing enabled...
        set TAP_HYBRID_SIGN_OPTION=%~1
        goto next
    ) else if "%~1"=="--srtp" (
        echo Building with DTLS SRTP enabled...
        set DTLS_SRTP_OPTION=%~1
        goto next
    ) else if "%~1"=="--mauth" (
        echo Building with Mutual Authentication...
        set MAUTH_OPTION=%~1
        goto next
    ) else if "%~1"=="--tap-local" (
        echo Building with TAP-Local...
        set "TAP_OPTION=--tap"
        set "TAP_TYPE_OPTION=--tap-local"
        set "TPM2_OPTION=--tpm2"
        set "OPENSSL_CONFIG_OPTION=%OPENSSL_CONFIG_OPTION% enable-mocana-tap"
        set "OPENSSL_CLIENT_TARGET=openssl_client_tap"
        set IS_TAP_BUILD=1
        goto next
    ) else if "%~1"=="--test" (
        echo Building with EVP tests...
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-test"
        goto next
    ) else if "%~1"=="--no-clean" (
        echo Disabling clean build...
        set DO_CLEAN=0
        goto next
    ) else if "%~1"=="--force-static" (
        echo Setting CM_ENV_FORCE_STATIC_LINK to preserve '/MD'
        set CM_ENV_FORCE_STATIC_LINK=1
        goto next
    ) else if "%~1"=="--custom-entropy" (
        echo Building with custom entropy...
        set "CUSTOM_ENTROPY_OPTION=--custom-entropy"
        goto next
    ) else if "%~1"=="--disable-tls13" (
        echo Building with TLS 1.3 disabled...
        set "TLS13_OPTION=!TLS13_OPTION! --disable-tls13"
        goto next
    ) else if "%~1"=="--disable-psk" (
        echo Building with TLS 1.3 PSK disabled...
        set "TLS13_OPTION=!TLS13_OPTION! --disable-psk"
        goto next
    ) else if "%~1"=="--disable-0rtt" (
        echo Building with TLS 1.3 0-RTT disabled...
        set "TLS13_OPTION=!TLS13_OPTION! --disable-0rtt"
        goto next
    ) else if "%~1"=="--rsa1024" (
        echo Build with support for RSA 1024
        set "RSA1024_OPTION=--rsa1024"
        goto next
    ) else if "%~1"=="--rsa_8k" (
        echo Build with support for RSA 8K
        set "RSA8K_OPTION=--rsa_8k"
        goto next
    ) else if "%~1"=="--sha1" (
        echo Build with support for SHA1
        set "SHA1_OPTION=--sha1"
        goto next
    ) else if "%~1"=="--disable-rc5" (
        echo Build with RC5 disabled
        set "RC5_DISABLE_CRYPTO_OPTION=--disable-rc5"
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-no-rc5"
        set "OSSL3_RC5_OPTION="
        goto next
    ) else if "%~1"=="--ocsp" (
        echo Build with OCSP support..
        set "OCSP_OPTION=--ocsp"
        set "URI_OPTION=--uri"
        goto next
    ) else if "%~1"=="--ocsp_cert" (
        echo Build with OCSP Cert support..
        set "OCSP_CERT_OPTION=--ocsp_cert"
        goto next
    ) else if "%~1"=="--disable-servername-validation" (
        echo Building with no server name check ...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --disable-servername-validation"
        goto next
    ) else if "%~1"=="--disable-client-commonname-validation" (
        echo Building with no client common name verification ...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --disable-client-commonname-validation"
        goto next
    ) else if "%~1"=="--dsa" (
        echo Building with DSA enabled...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --dsa"
        goto next
    ) else if "%~1"=="--enable_3des" (
        echo Building with 3DES enabled...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --enable_3des"
        goto next
    ) else if "%~1"=="--strict_dh" (
        echo Building with strict DH...
        set "STRICT_DH_OPTION=--strict_dh"
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-strict-dh"
        goto next
    ) else if "%~1"=="--openssl_load_algos" (
        echo Build option to load all algorithms
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --openssl_load_algos"
        goto next
    ) else if "%~1"=="--ossl_multipacket_read" (
        echo Building with ossl multipacket read...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_multipacket_read"
        goto next
    ) else if "%~1"=="--ossl_multipacket_bio_retry" (
        echo Building with ossl multipacket bio retry...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_multipacket_bio_retry"
        goto next
    ) else if "%~1"=="--ossl_log" (
        echo Building with ossl_log ...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_log"
        goto next
    ) else if "%~1"=="--osslc_thread_safe" (
        echo Build with thread safe handling for OpenSSL connector client
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --osslc_thread_safe"
        goto next
    ) else if "%~1"=="--ossl_rx_buf_8k" (
        echo Building with 8K RX buffer for OpenSSL shim...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_rx_buf_8k"
        goto next
    ) else if "%~1"=="--ossl_rx_buf_4k" (
        echo Building with 4K RX buffer for OpenSSL shim...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_rx_buf_4k"
        goto next
    ) else if "%~1"=="--ossl_rx_buf_2k" (
        echo Building with 2K RX buffer for OpenSSL shim...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_rx_buf_2k"
        goto next
    ) else if "%~1"=="--enable_ticket_tls12" (
        echo Building with server side session ticket handling...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --enable_ticket_tls12"
        goto next
    ) else if "%~1"=="--self_signed" (
        echo Building with self signed cert...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --self_signed"
        goto next
    ) else if "%~1"=="--non_trusted" (
        echo Building with non trusted cert...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --non_trusted"
        goto next
    ) else if "%~1"=="--cert_status_override" (
        echo Building with certificate status override...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --cert_status_override"
        goto next
    ) else if "%~1"=="--force_cert_chain" (
        echo Building with cert chain load
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --force_cert_chain"
        goto next
    ) else if "%~1"=="--rehandshake" (
        echo Building with rehandshake feature ...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --rehandshake"
        goto next
    ) else if "%~1"=="--srp" (
        echo Building with SRP
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --srp"
        goto next
    ) else if "%~1"=="--disable_polychacha_tls12" (
        echo Building with disable polychacha for TLS 1.2
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --disable_polychacha_tls12"
        goto next
    ) else if "%~1"=="--extended-key" (
        echo Building with extended key usage feature ...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --extended-key"
        goto next
    ) else if "%~1"=="--disable_ossl_default_trust_certs" (
        echo Building with disable default trust certs...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --disable_ossl_default_trust_certs"
        goto next
    ) else if "%~1"=="--disable_peek_error" (
        echo Building with peer error disabled...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --disable_peek_error"
        goto next
    ) else if "%~1"=="--disable-strict-ca-check" (
        echo Disable strict CA check...
        set "DISABLE_STRICT_CA_CHECK_OPTION=--disable-strict-ca-check"
        goto next
    ) else if "%~1"=="--disable_cert_ext_check" (
        echo Disable certificate extension check...
        set "DISABLE_CERT_EXT_CHECK_OPTION=--disable_cert_ext_check"
        goto next
    ) else if "%~1"=="--keylog" (
        echo Building with key logging enabled....
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --keylog"
        goto next
    ) else if "%~1"=="--ossl_disable_read_ahead" (
        echo Disable read ahead by default...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_disable_read_ahead"
        goto next
    ) else if "%~1"=="--ossl_single_read" (
        echo Build with 1K receive buffer and read ahead disabled
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --ossl_single_read"
        goto next
    ) else if "%~1"=="--version-logging" (
        echo Building with version_logging...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --version-logging"
        goto next
    ) else if "%~1"=="--redirect-log" (
        echo Building with redirect-log...
        set "NANOSSL_OSSL_OPTIONS=!NANOSSL_OSSL_OPTIONS! --redirect-log"
        goto next
    ) else if "%~1"=="--static" (
        echo Building static libraries...
        set STATIC_LIBS=--libtype static
        set STATIC_BUILD=--static
        set CM_ENV_FORCE_STATIC_LINK=1
        goto next
    ) else if "%~1"=="--build-for-osi" (
        echo "Enabling BUILD_FOR_OSI..."
        set "BUILD_FOR_OSI=1"
        set "OSI_OPTION=--build-for-osi"
        goto next
    )
    echo invalid option %1
    call:show_usage
    EXIT /B %ERR_EXIT%
    :next
    shift
    goto argactionstart
:argactionend


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to validate arguments

:validate_args
    set RET_VAL=%SUCCESS%

    if %IS_64BIT_BUILD%==1  (
        if %IS_32BIT_BUILD%==1  (
            echo Choose either --x64 or --x32.
            set RET_VAL=%ERR_INV_ARGS%
            goto validate_args_end
        )
    )

    if %IS_64BIT_BUILD%==0  (
        if %IS_32BIT_BUILD%==0  (
            echo Choose either --x64 or --x32.
            set RET_VAL=%ERR_INV_ARGS%
            goto validate_args_end
        )
    )

    if "%OSSL_COMPILER_PARAM%"=="" (
        echo OpenSSL compiler target to configure cannot be empty
        set RET_VAL=%ERR_INV_ARGS%
        goto validate_args_end
    )

    set PLATFORM_SUFFIX=-x64
    if %IS_32BIT_BUILD%==1 (
        set PLATFORM_SUFFIX=
    )

    if "%OPENSSL_VER%"=="3" (
        set OSSL_LIBSSL_WVER_NAME=libssl-3!PLATFORM_SUFFIX!
        set OSSL_LIBCRYPTO_WVER_NAME=libcrypto-3!PLATFORM_SUFFIX!
        set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! !OSSL3_RC5_OPTION!"
    ) else if "%OPENSSL_VER%"=="1.1.1" (
        set OSSL_LIBSSL_WVER_NAME=libssl-1_1!PLATFORM_SUFFIX!
        set OSSL_LIBCRYPTO_WVER_NAME=libcrypto-1_1!PLATFORM_SUFFIX!
    ) else (
        set OSSL_LIBSSL_WVER_NAME=ssleay32
    )

    if %IS_GDB_BUILD%==1 (
        if "%OPENSSL_VER%"=="1.0.2" (
            set OSSL_COMPILER_PARAM=debug-%OSSL_COMPILER_PARAM%
        ) else if "%OPENSSL_VER%"=="3" (
            set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! -d"
        ) else (
            set OPENSSL_CONFIG_OPTION=%OPENSSL_CONFIG_OPTION% --debug
        )
    )

    if %IS_DEBUG_BUILD%==1 (
        if NOT [!OSSL_VER!]==[3] (
            set "OPENSSL_CONFIG_OPTION=!OPENSSL_CONFIG_OPTION! enable-mocana-debug"
        )
    )

    if "%OPENSSL_VER%"=="1.1.1" (
        if "%STATIC_BUILD%"=="--static" (
            set OPENSSL_CONFIG_OPTION=%OPENSSL_CONFIG_OPTION% no-shared
        )
    )

:validate_args_end
    if %RET_VAL% NEQ %SUCCESS% (
        call:show_usage
    )
EXIT /B %RET_VAL%


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to print variables after parsing argument values

:print_args
    echo.
    echo DEBUG_OPTIONS=%DEBUG_OPTIONS%
    echo.
    echo OPENSSL_CONFIG_OPTION=%OPENSSL_CONFIG_OPTION%
    echo.
    echo DTLS_OPTION=%DTLS_OPTION%
    echo.
EXIT /B %ERRORLEVEL%


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to print usage of this BAT script

:show_usage
    echo.
    echo build.bat [Options]
    echo.
    echo    --x32 ^| --x64      - Choose x32 for 32 bit build, and x64 for 64 bit. ^(x64 is default^)
    echo    --gdb              - Enable debug version.
    echo    --debug            - Build with Mocana logging enabled for specific build executable.
    echo    --no-clean         - Do not do a clean build. By default clean build is enforced.
    echo    --dtls             - Build with DTLS support.
    echo    --tap-hybrid-sign  - Build with TAP hybrid signing.
    echo    --mbed-path        - Path to mbedtls (Changes build to Export Edition)
    echo    --redefine         - Redefine the PEM_read_bio_PrivateKey function.
    echo    --openssl_1_1_1    - Build for OpenSSL 1.1.1c.
    echo    --openssl_1_1_1f   - Build for OpenSSL 1.1.1f.
    echo    --openssl_1_1_1i   - Build for OpenSSL 1.1.1i.
    echo    --openssl_3_0_7    - Build for OpenSSL 3.0.7.
    echo    --openssl_3_0_12   - Build for OpenSSL 3.0.12.
    echo    --openssl_3_5_0    - Build for OpenSSL 3.5.0.
    echo    --tap-local        - Build with TAP-Local
    echo    --fips             - Build w/ libmss
    echo    --custom-entropy   - Build with custom entropy.
    echo    --disable-tls13    - Disable with TLS 1.3.
    echo    --disable-psk      - Build with TLS 1.3 PSK disabled.
    echo    --disable-0rtt     - Build with TLS 1.3 0-RTT disabled.
    echo    --rsa1024          - Build with RSA 1024 support.
    echo    --rsa_8k           - Build with RSA 8K support.
    echo    --sha1             - Build with support for SHA1.
    echo    --ocsp             - Build with OCSP support.
    echo    --disable-servername-validation - Server flag to ignore the certificate common name.
    echo    --disable-client-commonname-validation - Client flag to ignore the certificate common name check.
    echo    --dsa              - Build NanoSSL with the DSA support
    echo    --enable_3des      - Enable 3DES cipher support
    echo    --openssl_load_algos - Build option to load all algorithms
    echo    --ossl_multipacket_read - Enable reading of multiple records in a loop.
    echo    --ossl_multipacket_bio_retry - Enable read until data is recieved.
    echo    --ossl_log         - Enable logging in OpenSSL Connector.
    echo    --osslc_thread_safe - Build with thread safe handling for OpenSSL connector client.
    echo    --ossl_rx_buf_8k   - Build with 8K receive buffer.
    echo    --ossl_rx_buf_4k   - Build with 4K receive buffer.
    echo    --ossl_rx_buf_2k   - Build with 2K receive buffer.
    echo    --enable_ticket_tls12 - Enable server side session ticket implementation as per RFC 5077.
    echo    --self_signed      - Enable self signed cert
    echo    --non_trusted      - Enable non trust cert
    echo    --cert_status_override   - Override the OpenSSL shim certificate status if NanoSSL certificate validation is successful.
    echo    --rehandshake      - Enable rehandshake
    echo    --srp              - Enable SRP(Secure Remote Password).
    echo    --disable_polychacha_tls12 - Diable CHACHA20-POLY1305 ciphers for TLS 1.2 and lower versions
    echo    --extended-key     - Enable extended key usage
    echo    --disable_ossl_default_trust_certs     - Disable loading of default CA Certs
    echo    --disable_peek_error - Building with peer error disabled.
    echo    --disable-strict-ca-check - Disable strict CA check. 
    echo    --disable_cert_ext_check - Disable certificate extension check.
    echo    --keylog           - Building with key logging enabled.
    echo    --ossl_disable_read_ahead - Disable read ahead by default.
    echo    --version-logging  - Enable version_logging
    echo    --redirect-log     - Redirect printf logs to stderr in OpenSSL Connector.
    echo.
EXIT /B %ERRORLEVEL%


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: create_link - Function to create link to another file
:: create_link <link_name> <target_name>

:create_link
    :: Checking if a link already exists
    echo Verifying if link "%1" to file "%2" exists
    dir /A:L %1 > nul 2>&1
    :: Create link only if it doesnt exist
    if ERRORLEVEL 1 (
        echo Executing - mklink %1 %2
        mklink %1 %2
    ) else (
        echo Link "%1" already exists
    )
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if ERRORLEVEL 1 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
EXIT /b %1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: MAIN() - main entry point, called first

:MAIN

echo args: %*

call:argactionstart %* & IF ERRORLEVEL 1 goto:end %errorlevel%

call:print_args & IF ERRORLEVEL 1 goto:end %errorlevel%

call:clean

call:build & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0
