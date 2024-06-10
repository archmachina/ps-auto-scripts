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

try { $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText } catch {}

# Global variables
$serviceRoot = "C:\svc"
$logPath = "C:\svc\${ServiceName}\log.txt"

# Read general config
Set-Location $serviceRoot
. ./service_config.ps1

# Modules
Set-PSRepository PSGallery -InstallationPolicy Trusted
@("SvcProc") | ForEach-Object {
    Install-Module -Scope CurrentUser -Confirm:$false $_ -EA Ignore
    Update-Module -Confirm:$false $_ -EA Ignore
    Import-Module $_
}

$script:failed = $false

$output = Invoke-ServiceRun -RotateSizeKB 512 -Iterations 1 -LogPath $logPath -ScriptBlock {
    $scriptPath = "$serviceRoot\$ServiceName\entrypoint.ps1"
    Write-Information "Script Path: $scriptPath"

    try {
        # Check to make sure we have an entrypoint script
        if (!(Test-Path -PathType Leaf $scriptPath))
        {
            Write-Error "Could not find entrypoint script or not a file"
        }

        # Change to service directory
        Write-Information "Changing to $serviceRoot\$ServiceName"
        Set-Location -Path "$serviceRoot\$ServiceName"

        # Read service configuration
        Write-Information "Reading service configuration"
        $config = & "$serviceRoot\read_config.ps1" -ServiceName $ServiceName | Out-String

        Write-Information "Calling entrypoint: $scriptPath"
        $config | & pwsh -NoProfile $scriptPath | Out-String -Stream
        Write-Information "Entrypoint finished"
    } catch {
        Write-Information "Script encountered an error: $_"
        $script:failed = $true
    }

    Write-Information "Finished"
} *>&1

if ($failed)
{
    & "$serviceRoot\notify.ps1" -Subject "Task: $ServiceName Failure" -Body ($output | Out-String)
}

