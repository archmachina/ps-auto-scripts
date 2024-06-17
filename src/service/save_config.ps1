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

# Read configuration from stdin and save to file encrypted (using DPAPI)
$content = [System.Console]::In.ReadToEnd() | Out-String
$config = $content | ConvertTo-SecureString -AsPlainText | ConvertFrom-SecureString
$config | Out-File -Encoding UTF8 $serviceConfigPath

