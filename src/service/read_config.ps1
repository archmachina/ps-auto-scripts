<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceRoot,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName
)

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Global variables
$servicePath = ([System.IO.Path]::Combine($ServiceRoot, $ServiceName))
$serviceConfigPath = ([System.IO.Path]::Combine($ServicePath, "config"))

# Read encrypted config from file, decrypt and output
$secureStr = Get-Content -Encoding UTF8 $serviceConfigPath | ConvertTo-SecureString
$config = [System.Net.NetworkCredential]::New('', $secureStr).Password
$config

