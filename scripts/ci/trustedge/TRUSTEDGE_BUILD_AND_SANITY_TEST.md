# TrustEdge v2.0 Build Instructions

## Dependencies

## Build Command

### Linux

Refer to script help for build options

    ./scripts/ci/trustedge/ci_trustedge_build.sh --help

### Windows

#### Pre-requisites

- Visual Studio Enterprise 2026
- Visual Studio Enterprise C/C++ Development Extensions (CMake)
- WIX Toolset v3.14
    - https://github.com/wixtoolset/wix3/releases/tag/wix3141rtm - use wix314.exe to install
    - Add WIX to PATH
        - C:\Program Files (x86)\WiX Toolset v3.14\bin (default install PATH)

Build instructions

1. Open `Command Prompt`
2. Setup build 

        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x86_x64

3. Build TrustEdge

        scripts\ci\trustedge\ci_trustedge_build.bat --version-string 0.0.0 --monolithic --package --tpm2 --cvc --proxy --pqc --pqc-composite --enable-pc

## Run

Help

    ./bin/trustedge --help

Version

    ./bin/trustedge --version

Agent mode - bootstrap configuration file samples are located in `projects/trustedge/sample/bootstrap_configuration`

    ./bin/trustedge agent --help
    ./bin/trustedge agent --bootstrap_configuration <file>

## Sanity Testing

### Windows

1. Uninstall any existing Trustedge application

2. Open command prompt with admin privleges

3. Set the path to the MSI location. If using the build commands above, set the path as follows

        set MSI_DIR_PATH=.\dist

2. Open command prompt with admin privleges and set environment variable to set API key against DTM backend (currently only works against DEMO environment)

        set DEMO_API_KEY=<key>

3. Run sanity test script

        python3 scripts\ci\trustedge\trustedge_sanity_test.py --package-dir %MSI_DIR_PATH% --register-device