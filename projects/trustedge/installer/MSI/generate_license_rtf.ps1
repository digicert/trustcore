<#
.SYNOPSIS
    Converts eula.txt to license.rtf for MSI installer.

.DESCRIPTION
    This script reads the EULA text file and converts it to RTF format
    suitable for display in the WiX/MSI installer license dialog.

.PARAMETER EulaPath
    Path to the source eula.txt file.

.PARAMETER OutputPath
    Path to the output license.rtf file.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$EulaPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

# Verify source file exists
if (-not (Test-Path $EulaPath)) {
    Write-Error "EULA file not found: $EulaPath"
    exit 1
}

Write-Host "Converting EULA to RTF..."
Write-Host "  Source: $EulaPath"
Write-Host "  Output: $OutputPath"

# Read the EULA content
$eula = Get-Content $EulaPath -Raw -Encoding UTF8

# Escape RTF special characters (order matters: backslash first)
$escaped = $eula -replace '\\', '\\'
$escaped = $escaped -replace '\{', '\{'
$escaped = $escaped -replace '\}', '\}'

# Replace double quotes with single quotes for readability
$escaped = $escaped -replace '"', "'"

# Convert paragraphs (double newlines) to RTF paragraph breaks
$escaped = $escaped -replace "`r`n`r`n", "\par`r`n\par`r`n"

# Convert single newlines to spaces (within paragraphs)
$escaped = $escaped -replace "`r`n", " "

# Clean up multiple spaces
$escaped = $escaped -replace "  +", " "

# Build the RTF document
$rtfHeader = "{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fswiss\fcharset0 Arial;}}"
$rtfGenerator = "{\*\generator TrustEdge EULA Converter}\viewkind4\uc1"
$rtfFormat = "\pard\sa200\sl276\slmult1\f0\fs18"
$rtfFooter = "\par`r`n}"

$rtf = "$rtfHeader`r`n$rtfGenerator`r`n$rtfFormat`r`n$escaped`r`n$rtfFooter"

# Write the RTF file
$rtf | Set-Content $OutputPath -Encoding ASCII

Write-Host "License RTF generated successfully."
exit 0
