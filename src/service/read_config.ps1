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

# Read encrypted config from file, decrypt and output
$secureStr = Get-Content -Encoding UTF8 "$serviceRoot\$ServiceName\config" |
    ConvertTo-SecureString
$config = [System.Net.NetworkCredential]::New('', $secureStr).Password
$config

