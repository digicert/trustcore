#Requires -Version 5.1
<#
.SYNOPSIS
    TrustEdge Sanity Test Script for Windows

.DESCRIPTION
    This script performs sanity tests on the TrustEdge Windows build including:
    - MSI installation and uninstallation
    - TGZ extraction and verification
    - TrustEdge command-line tests
    - Certificate operations
    - MQTT functionality
    - Agent configuration and operation

.NOTES
    Author: DigiCert
    Version: 1.0
#>

$ErrorActionPreference = "Stop"

# Configuration
$DIGICERT_PATH = "$env:ProgramData\digicert"
$KEYSTORE_CA_DIR = "$DIGICERT_PATH\keystore\ca"
$KEYSTORE_CERTS_DIR = "$DIGICERT_PATH\keystore\certs"
$KEYSTORE_KEYS_DIR = "$DIGICERT_PATH\keystore\keys"
$KEYSTORE_REQ_DIR = "$DIGICERT_PATH\keystore\req"
$KEYSTORE_CONF_DIR = "$DIGICERT_PATH\keystore\conf"
$CONF_DIR = "$DIGICERT_PATH\conf"
$CLOUD_DIR = "$DIGICERT_PATH\cloudprovider"

$TRUSTEDGE_EXE = "$env:ProgramFiles\DigiCert\TrustEdge\bin\trustedge.exe"

# Test tracking
$script:TestResults = [ordered]@{}
$script:OrderedTests = @()
$script:AllTestsPassed = $true
$script:DeviceId = $null

function Collect-TestResult {
    param(
        [string]$TestName,
        [string]$Result
    )
    $script:TestResults[$TestName] = $Result
    $script:OrderedTests += $TestName
    if ($Result -eq "FAIL") {
        $script:AllTestsPassed = $false
    }
}

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "*************************************************************************"
    Write-Host "*** $Message"
    Write-Host "*************************************************************************"
}

function Display-Summary {
    Write-Host ""
    Write-Host "*************************************************************************"
    Write-Host "*************************** Test Summary ********************************"
    Write-Host "*************************************************************************"
    Write-Host "| Test Name                                                    | Result |"
    Write-Host "|--------------------------------------------------------------|--------|"
    
    foreach ($test in $script:OrderedTests) {
        $result = $script:TestResults[$test]
        $formattedTest = $test.PadRight(60).Substring(0, 60)
        $formattedResult = $result.PadRight(6).Substring(0, 6)
        Write-Host "| $formattedTest | $formattedResult |"
        Write-Host "|--------------------------------------------------------------|--------|"
    }
}

function Cleanup {
    Display-Summary
    
    if ($script:AllTestsPassed) {
        Write-Host "All tests passed"
    } else {
        Write-Host "Some tests failed or skipped"
    }
    
    Write-Host "Cleaning up..."
    
    # Cleanup device registration
    if ($script:DeviceId -and (Test-Path ".\disable_delete_device.py")) {
        python .\disable_delete_device.py $script:DeviceId
    }
    
    # Remove bootstrap.zip if exists
    if (Test-Path ".\bootstrap.zip") {
        Remove-Item -Path ".\bootstrap.zip" -Force
    }
    
    # Remove device_id.txt if exists
    if (Test-Path ".\device_id.txt") {
        Remove-Item -Path ".\device_id.txt" -Force
    }
}

# ======================================================================
# MSI Installation/Uninstallation Tests
# ======================================================================

function Test-MSIInstallation {
    Write-Section "Starting TrustEdge MSI install/uninstall test"
    
    $msiFile = Get-ChildItem -Path "." -Filter "trustedge*.msi" | Select-Object -First 1
    if (-not $msiFile) {
        Write-Host "**********[Test Failed] No TrustEdge MSI file found"
        Collect-TestResult "TrustEdge MSI installation" "FAIL"
        return $false
    }
    
    # Install MSI
    Write-Section "Installing TrustEdge MSI: $($msiFile.Name)"
    $installArgs = "/i `"$($msiFile.FullName)`" /qn ACCEPT_EULA=1"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Host "**********[Test Failed] TrustEdge MSI installation failed with exit code: $($process.ExitCode)"
        Collect-TestResult "TrustEdge MSI installation" "FAIL"
        return $false
    }
    
    # Verify installation
    if (Test-Path $TRUSTEDGE_EXE) {
        Write-Host "**********[Test Passed] TrustEdge MSI installation successful"
        Collect-TestResult "TrustEdge MSI installation" "PASS"
    } else {
        Write-Host "**********[Test Failed] TrustEdge executable not found after installation"
        Collect-TestResult "TrustEdge MSI installation" "FAIL"
        return $false
    }
    
    # Uninstall MSI
    Write-Section "Uninstalling TrustEdge MSI"
    $uninstallArgs = "/x `"$($msiFile.FullName)`" /qn"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Host "**********[Test Failed] TrustEdge MSI uninstallation failed with exit code: $($process.ExitCode)"
        Collect-TestResult "TrustEdge MSI uninstallation" "FAIL"
        return $false
    }
    
    # Verify uninstallation
    if (-not (Test-Path $TRUSTEDGE_EXE)) {
        Write-Host "**********[Test Passed] TrustEdge MSI uninstallation successful"
        Collect-TestResult "TrustEdge MSI uninstallation" "PASS"
    } else {
        Write-Host "**********[Test Failed] TrustEdge executable still exists after uninstallation"
        Collect-TestResult "TrustEdge MSI uninstallation" "FAIL"
        return $false
    }
    
    Collect-TestResult "TrustEdge install/uninstall (MSI)" "PASS"
    return $true
}

# ======================================================================
# TGZ Extraction Test
# ======================================================================

function Test-TGZExtraction {
    Write-Section "Starting TrustEdge TGZ extraction test"
    
    $tgzFile = Get-ChildItem -Path "." -Filter "trustedge*.tar.gz" | Select-Object -First 1
    if (-not $tgzFile) {
        Write-Host "**********[Test Failed] No TrustEdge TGZ file found"
        Collect-TestResult "TrustEdge TGZ extraction" "FAIL"
        return $false
    }
    
    $extractPath = "$env:TEMP\trustedge_tgz_test"
    
    # Create extraction directory
    if (Test-Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    
    # Extract TGZ
    Write-Host "Extracting: $($tgzFile.Name)"
    tar -xzf $tgzFile.FullName -C $extractPath
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "**********[Test Failed] TrustEdge TGZ extraction failed"
        Collect-TestResult "TrustEdge TGZ extraction" "FAIL"
        return $false
    }
    
    Write-Host "**********[Test Passed] TrustEdge TGZ extraction successful"
    Collect-TestResult "TrustEdge TGZ extraction" "PASS"
    
    # Verify file structure
    $requiredPaths = @(
        "$extractPath\bin",
        "$extractPath\bin\trustedge.exe",
        "$extractPath\conf",
        "$extractPath\keystore",
        "$extractPath\scripts",
        "$extractPath\trustedge.json"
    )
    
    $allPathsExist = $true
    foreach ($path in $requiredPaths) {
        if (-not (Test-Path $path)) {
            Write-Host "Missing: $path"
            $allPathsExist = $false
        }
    }
    
    if ($allPathsExist) {
        Write-Host "**********[Test Passed] TrustEdge TGZ file structure verified"
        Collect-TestResult "TrustEdge TGZ file structure" "PASS"
    } else {
        Write-Host "**********[Test Failed] TrustEdge TGZ file structure verification failed"
        Collect-TestResult "TrustEdge TGZ file structure" "FAIL"
    }
    
    # Cleanup
    Remove-Item -Path $extractPath -Recurse -Force
    Write-Host "**********[Test Passed] TrustEdge TGZ cleanup successful"
    Collect-TestResult "TrustEdge TGZ cleanup" "PASS"
    
    return $allPathsExist
}

# ======================================================================
# TrustEdge Command Tests
# ======================================================================

function Test-TrustEdgeHelpVersion {
    Write-Section "Running TrustEdge help and version tests"
    
    # Test --help
    & $TRUSTEDGE_EXE --help
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge --help successful"
        Collect-TestResult "TrustEdge --help" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge --help failed"
        Collect-TestResult "TrustEdge --help" "FAIL"
        return $false
    }
    
    # Test --version
    & $TRUSTEDGE_EXE --version
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge --version successful"
        Collect-TestResult "TrustEdge --version" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge --version failed"
        Collect-TestResult "TrustEdge --version" "FAIL"
        return $false
    }
    
    return $true
}

function Test-TrustEdgeAgent {
    Write-Section "Running TrustEdge agent tests"
    
    # Test agent --help
    & $TRUSTEDGE_EXE agent --help
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge agent --help successful"
        Collect-TestResult "TrustEdge agent --help" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge agent --help failed"
        Collect-TestResult "TrustEdge agent --help" "FAIL"
        return $false
    }
    
    # Register device and get bootstrap config
    Write-Host ""
    Write-Host ">>>Generating bootstrap config"
    Write-Host ""
    
    if (-not (Register-DeviceAndGetBootstrap)) {
        return $false
    }
    
    # Configure TrustEdge
    Write-Host ""
    Write-Host ">>>Configuring TrustEdge"
    Write-Host ""
    
    & $TRUSTEDGE_EXE agent --configure --bootstrap-zip .\bootstrap.zip
    if ($LASTEXITCODE -ne 0) {
        Write-Host "**********[Test Failed] trustedge agent --configure failed"
        Collect-TestResult "TrustEdge agent --configure" "FAIL"
        return $false
    }
    Collect-TestResult "TrustEdge agent --configure" "PASS"
    
    # Verify configuration
    if (-not (Test-TrustEdgeConfiguration)) {
        return $false
    }
    
    # Run trustedge agent
    Write-Host ""
    Write-Host ">>>Running trustedge agent"
    Write-Host ""
    
    & $TRUSTEDGE_EXE agent --log-level VERBOSE
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge agent --log-level VERBOSE successful"
        Collect-TestResult "TrustEdge agent --log-level VERBOSE" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge agent --log-level VERBOSE failed"
        Collect-TestResult "TrustEdge agent --log-level VERBOSE" "FAIL"
        return $false
    }
    
    Collect-TestResult "TrustEdge agent test" "PASS"
    return $true
}

function Register-DeviceAndGetBootstrap {
    # Run Python registration script
    python .\register_device.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "**********[Test Failed] Device registration failed"
        Collect-TestResult "Device registration" "FAIL"
        return $false
    }
    
    # Get device ID
    if (Test-Path ".\device_id.txt") {
        $script:DeviceId = Get-Content ".\device_id.txt"
        Write-Host "Device ID: $script:DeviceId"
    }
    
    # Verify bootstrap.zip
    if (Test-Path ".\bootstrap.zip") {
        Write-Host "Bootstrap config generated successfully"
        Collect-TestResult "Device registration" "PASS"
        return $true
    } else {
        Write-Host "**********[Test Failed] Bootstrap config not generated"
        Collect-TestResult "Device registration" "FAIL"
        return $false
    }
}

function Test-TrustEdgeConfiguration {
    Write-Section "Checking TrustEdge configuration"
    
    if (Test-Path "$DIGICERT_PATH\trustedge.json") {
        Write-Host "trustedge.json exists"
    } else {
        Write-Host "trustedge.json does not exist"
        Write-Host "**********[Test Failed] TrustEdge configuration failed"
        Collect-TestResult "TrustEdge configuration" "FAIL"
        return $false
    }
    
    if (Test-Path "$CONF_DIR\bootstrap_config.json") {
        Write-Host "bootstrap_config.json exists"
    } else {
        Write-Host "bootstrap_config.json does not exist"
        Write-Host "**********[Test Failed] TrustEdge configuration failed"
        Collect-TestResult "TrustEdge configuration" "FAIL"
        return $false
    }
    
    Collect-TestResult "TrustEdge configuration" "PASS"
    return $true
}

function Test-TrustEdgeAgentReset {
    Write-Section "Resetting TrustEdge agent"
    
    & $TRUSTEDGE_EXE agent --reset
    
    $paths = @(
        @{Path = $KEYSTORE_CA_DIR; Name = "keystore/ca"},
        @{Path = $KEYSTORE_CERTS_DIR; Name = "keystore/certs"},
        @{Path = $KEYSTORE_KEYS_DIR; Name = "keystore/keys"},
        @{Path = $KEYSTORE_REQ_DIR; Name = "keystore/req"},
        @{Path = $CLOUD_DIR; Name = "cloudprovider"}
    )
    
    foreach ($item in $paths) {
        if (Test-Path $item.Path) {
            $contents = Get-ChildItem -Path $item.Path -Force
            if ($contents.Count -gt 0) {
                Write-Host "$($item.Name) is not empty"
                Write-Host "**********[Test Failed] TrustEdge agent reset failed"
                Collect-TestResult "TrustEdge agent reset" "FAIL"
                return $false
            }
        }
        Write-Host "$($item.Name) is empty"
    }
    
    $filesToCheck = @(
        "metrics.pb",
        "desired_attributes.pb",
        "applied_policy.json",
        "policy_authorization.jwt",
        "failed_policy.json",
        "processing_policy.json",
        "pending_policy.json",
        "bootstrap_config.json",
        "cert_spec.json"
    )
    
    foreach ($file in $filesToCheck) {
        if (Test-Path "$CONF_DIR\$file") {
            Write-Host "$file exists"
            Write-Host "**********[Test Failed] TrustEdge agent reset failed"
            Collect-TestResult "TrustEdge agent reset" "FAIL"
            return $false
        }
        Write-Host "$file does not exist"
    }
    
    Write-Host "**********[Test Passed] TrustEdge agent reset successful"
    Collect-TestResult "TrustEdge agent reset" "PASS"
    return $true
}

# ======================================================================
# Certificate Tests
# ======================================================================

function Test-TrustEdgeCertificate {
    Write-Section "Testing TrustEdge certificate"
    
    # Test certificate --help
    & $TRUSTEDGE_EXE certificate --help
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge certificate --help successful"
        Collect-TestResult "TrustEdge certificate --help" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge certificate --help failed"
        Collect-TestResult "TrustEdge certificate --help" "FAIL"
        return $false
    }
    
    # Generate RSA 2048 private key
    Write-Host ""
    Write-Host ">>>Generating software-based private key (RSA 2048)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --algorithm RSA --size 2048 --output-file RSA_2048.pem
    if ($LASTEXITCODE -ne 0) {
        Write-Host "**********[Test Failed] Generate RSA 2048 private key failed"
        Collect-TestResult "TrustEdge certificate: Generate RSA 2048 private key" "FAIL"
        return $false
    }
    
    if (Test-Path "$KEYSTORE_KEYS_DIR\RSA_2048.pem") {
        Write-Host "**********[Test Passed] Generate RSA 2048 private key successful"
        Collect-TestResult "TrustEdge certificate: Generate RSA 2048 private key" "PASS"
    } else {
        Write-Host "**********[Test Failed] RSA_2048.pem not found"
        Collect-TestResult "TrustEdge certificate: Generate RSA 2048 private key" "FAIL"
        return $false
    }
    
    # Generate ECC P256 private key
    Write-Host ""
    Write-Host ">>>Generating software-based private key (ECC P256)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --algorithm ECC --curve P256 --output-file ECC_P256.pem
    if ($LASTEXITCODE -ne 0) {
        Write-Host "**********[Test Failed] Generate ECC P256 private key failed"
        Collect-TestResult "TrustEdge certificate: Generate ECC P256 private key" "FAIL"
        return $false
    }
    
    if (Test-Path "$KEYSTORE_KEYS_DIR\ECC_P256.pem") {
        Write-Host "**********[Test Passed] Generate ECC P256 private key successful"
        Collect-TestResult "TrustEdge certificate: Generate ECC P256 private key" "PASS"
    } else {
        Write-Host "**********[Test Failed] ECC_P256.pem not found"
        Collect-TestResult "TrustEdge certificate: Generate ECC P256 private key" "FAIL"
        return $false
    }
    
    # Create CSR configuration file
    Write-Host ""
    Write-Host ">>>Creating CSR configuration"
    Write-Host ""
    $csrConfig = @"
##Subject
countryName=US
commonName=iot-device101
stateOrProvinceName=California
localityName=San Francisco
organizationName=DBA
organizationalUnitName=BU
##Requested Extensions
hasBasicConstraints=true
isCA=true
certPathLen=-1
keyUsage=keyEncipherment, digitalSignature, keyCertSign
subjectAltNames=2; *.mydomain.com, 2; *.mydomain.net, 2
"@
    
    if (-not (Test-Path $KEYSTORE_CONF_DIR)) {
        New-Item -ItemType Directory -Path $KEYSTORE_CONF_DIR -Force | Out-Null
    }
    $csrConfig | Out-File -FilePath "$KEYSTORE_CONF_DIR\sample_csr.cnf" -Encoding UTF8
    
    # Generate CSR with RSA key
    Write-Host ""
    Write-Host ">>>Generating CSR (RSA 2048)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --cert-sign-req --output-file CSR_RSA_2048.pem --signing-key RSA_2048.pem --csr-conf sample_csr.cnf --digest SHA256
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] Generate CSR (RSA 2048) successful"
        Collect-TestResult "TrustEdge certificate: Generate CSR RSA 2048" "PASS"
    } else {
        Write-Host "**********[Test Failed] Generate CSR (RSA 2048) failed"
        Collect-TestResult "TrustEdge certificate: Generate CSR RSA 2048" "FAIL"
        return $false
    }
    
    # Generate CSR with ECC key
    Write-Host ""
    Write-Host ">>>Generating CSR (ECC P256)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --cert-sign-req --output-file CSR_ECC_P256.pem --signing-key ECC_P256.pem --csr-conf sample_csr.cnf --digest SHA256
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] Generate CSR (ECC P256) successful"
        Collect-TestResult "TrustEdge certificate: Generate CSR ECC P256" "PASS"
    } else {
        Write-Host "**********[Test Failed] Generate CSR (ECC P256) failed"
        Collect-TestResult "TrustEdge certificate: Generate CSR ECC P256" "FAIL"
        return $false
    }
    
    # Verify CSR
    Write-Host ""
    Write-Host ">>>Verifying CSR (RSA 2048)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --print-cert "$KEYSTORE_REQ_DIR\CSR_RSA_2048.pem"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] Print CSR RSA 2048 successful"
        Collect-TestResult "TrustEdge certificate: --print-cert CSR_RSA_2048" "PASS"
    } else {
        Write-Host "**********[Test Failed] Print CSR RSA 2048 failed"
        Collect-TestResult "TrustEdge certificate: --print-cert CSR_RSA_2048" "FAIL"
        return $false
    }
    
    # Generate self-signed X.509 certificate
    Write-Host ""
    Write-Host ">>>Generating X.509 certificate (RSA 2048)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --algorithm RSA --size 2048 --output-file RSA_CERT_2048.pem --csr-conf sample_csr.cnf --x509-cert RSA_CERT_2048.pem --days 365
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] Generate X.509 cert RSA 2048 successful"
        Collect-TestResult "TrustEdge certificate: --x509-cert RSA_CERT_2048" "PASS"
    } else {
        Write-Host "**********[Test Failed] Generate X.509 cert RSA 2048 failed"
        Collect-TestResult "TrustEdge certificate: --x509-cert RSA_CERT_2048" "FAIL"
        return $false
    }
    
    # Verify certificate
    Write-Host ""
    Write-Host ">>>Verifying X.509 certificate (RSA 2048)"
    Write-Host ""
    & $TRUSTEDGE_EXE certificate --print-cert "$KEYSTORE_CERTS_DIR\RSA_CERT_2048.pem"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] Print cert RSA 2048 successful"
        Collect-TestResult "TrustEdge certificate: --print-cert RSA_CERT_2048" "PASS"
    } else {
        Write-Host "**********[Test Failed] Print cert RSA 2048 failed"
        Collect-TestResult "TrustEdge certificate: --print-cert RSA_CERT_2048" "FAIL"
        return $false
    }
    
    # Test EST help
    & $TRUSTEDGE_EXE certificate est --help
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge certificate est --help successful"
        Collect-TestResult "TrustEdge certificate est --help" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge certificate est --help failed"
        Collect-TestResult "TrustEdge certificate est --help" "FAIL"
    }
    
    # Test SCEP help
    & $TRUSTEDGE_EXE certificate scep --help
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge certificate scep --help successful"
        Collect-TestResult "TrustEdge certificate scep --help" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge certificate scep --help failed"
        Collect-TestResult "TrustEdge certificate scep --help" "FAIL"
    }
    
    return $true
}

# ======================================================================
# MQTT Tests
# ======================================================================

function Test-TrustEdgeMQTT {
    Write-Section "Testing TrustEdge MQTT"
    
    # Test MQTT --help
    & $TRUSTEDGE_EXE mqtt --help
    if ($LASTEXITCODE -eq 0) {
        Write-Host "**********[Test Passed] trustedge mqtt --help successful"
        Collect-TestResult "TrustEdge mqtt --help" "PASS"
    } else {
        Write-Host "**********[Test Failed] trustedge mqtt --help failed"
        Collect-TestResult "TrustEdge mqtt --help" "FAIL"
        return $false
    }
    
    # Note: Full MQTT pub/sub tests require a running MQTT broker
    # These tests are limited to help verification for now
    
    return $true
}

# ======================================================================
# Windows Service Tests  
# ======================================================================

function Test-TrustEdgeService {
    Write-Section "Testing TrustEdge Windows Service"
    
    $serviceName = "TrustEdge"
    
    # Check if service exists
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "TrustEdge service not found - skipping service tests"
        Collect-TestResult "TrustEdge service (not installed)" "SKIP"
        return $true
    }
    
    # Check initial status
    if ($service.Status -eq "Stopped") {
        Write-Host "**********[Test Passed] TrustEdge service initial status: Stopped"
        Collect-TestResult "TrustEdge service initial status" "PASS"
    } else {
        Write-Host "TrustEdge service status: $($service.Status)"
    }
    
    # Start service
    Write-Section "Starting TrustEdge service"
    Start-Service -Name $serviceName
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq "Running") {
        Write-Host "**********[Test Passed] TrustEdge service start successful"
        Collect-TestResult "TrustEdge service start" "PASS"
    } else {
        Write-Host "**********[Test Failed] TrustEdge service start failed"
        Collect-TestResult "TrustEdge service start" "FAIL"
    }
    
    # Stop service
    Write-Section "Stopping TrustEdge service"
    Stop-Service -Name $serviceName
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq "Stopped") {
        Write-Host "**********[Test Passed] TrustEdge service stop successful"
        Collect-TestResult "TrustEdge service stop" "PASS"
    } else {
        Write-Host "**********[Test Failed] TrustEdge service stop failed"
        Collect-TestResult "TrustEdge service stop" "FAIL"
    }
    
    return $true
}

# ======================================================================
# Main Test Execution
# ======================================================================

try {
    Write-Host "Starting TrustEdge Windows Sanity Tests"
    Write-Host "========================================"
    
    # MSI Installation/Uninstallation Test
    Test-MSIInstallation
    
    # TGZ Extraction Test
    Test-TGZExtraction
    
    # Reinstall MSI for remaining tests
    Write-Section "Reinstalling TrustEdge for functional tests"
    $msiFile = Get-ChildItem -Path "." -Filter "trustedge*.msi" | Select-Object -First 1
    if ($msiFile) {
        $installArgs = "/i `"$($msiFile.FullName)`" /qn ACCEPT_EULA=1"
        Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait
        Collect-TestResult "TrustEdge reinstallation" "PASS"
    }
    
    # TrustEdge Help and Version
    Test-TrustEdgeHelpVersion
    
    # TrustEdge Agent Tests
    Test-TrustEdgeAgent
    
    # TrustEdge Certificate Tests
    Test-TrustEdgeCertificate
    
    # TrustEdge MQTT Tests
    Test-TrustEdgeMQTT
    
    # TrustEdge Service Tests
    Test-TrustEdgeService
    
    # Agent Reset Test
    Test-TrustEdgeAgentReset
    
} catch {
    Write-Host "An error occurred: $_"
    $script:AllTestsPassed = $false
} finally {
    Cleanup
}

if ($script:AllTestsPassed) {
    exit 0
} else {
    exit 1
}
