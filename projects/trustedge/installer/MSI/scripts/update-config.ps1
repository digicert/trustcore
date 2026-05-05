# update-config.ps1
# Updates trustedge.json with the actual data directory path chosen during installation
# This script is called as a custom action during MSI installation

param(
    [Parameter(Mandatory=$true)]
    [string]$DataDir
)

$ErrorActionPreference = "Stop"

try {
    # Normalize path (remove trailing backslash if present)
    $DataDir = $DataDir.TrimEnd('\')
    
    # Path to trustedge.json
    $configPath = Join-Path $DataDir "trustedge.json"
    
    # Wait for file to be available (installer may still be copying)
    $maxRetries = 10
    $retryCount = 0
    while (-not (Test-Path $configPath) -and $retryCount -lt $maxRetries) {
        Start-Sleep -Milliseconds 500
        $retryCount++
    }
    
    if (-not (Test-Path $configPath)) {
        Write-Error "Configuration file not found: $configPath"
        exit 1
    }
    
    # Read the JSON config
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    
    # Update paths to use the actual data directory
    # Use forward slashes or escaped backslashes for JSON
    $escapedPath = $DataDir -replace '\\', '\\'
    
    $config.root_dir = $DataDir
    $config.keystore_dir = "$DataDir\keystore"
    $config.conf_dir = "$DataDir\conf"
    $config.service_dir = "$DataDir\service"
    $config.cloudprovider_dir = "$DataDir\cloudprovider"
    $config.log_file = "$DataDir\trustedge.log"
    
    # Write updated config back to file
    $config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
    
    Write-Host "Successfully updated configuration with data directory: $DataDir"
    exit 0
}
catch {
    Write-Error "Failed to update configuration: $_"
    exit 1
}
