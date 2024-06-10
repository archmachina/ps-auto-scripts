<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName
)

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Global variables
$serviceRoot = "C:\svc"

# Read configuration from stdin and save to file encrypted (using DPAPI)
$content = [System.Console]::In.ReadToEnd() | Out-String
$config = $content | ConvertTo-SecureString -AsPlainText | ConvertFrom-SecureString
$config | Out-File -Encoding UTF8 "$serviceRoot\$ServiceName\config"

