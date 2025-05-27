[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [switch]$Install = $false,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [int]$AgeThreshold = 14,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$CabFile = "wsusscn2.cab",

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [switch]$CanReboot = $false,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Proxy = $null
)

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Output management
try {
    $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
} catch {}

# Proxy configuration
if (![string]::IsNullOrEmpty($Proxy))
{
    $Env:HTTP_PROXY = $Proxy
    $Env:HTTPS_PROXY = $Proxy

    try {
        [System.Net.Http.HttpClient]::DefaultProxy = [System.Net.WebProxy]::new($proxy)
        [System.Net.Http.HttpClient]::DefaultProxy.BypassProxyOnLocal = $true
    } catch {
        Write-Information "Failed to set HttpClient proxy: $_"
    }

    try {
        [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
        [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true
    } catch {
        Write-Information "Failed to set WebRequest proxy: $_"
    }
}

# Import modules
# Older versions of powershell don't seem to support '-EA Ignore'
$ErrorActionPreference = "Ignore"
Install-Module -Scope CurrentUser WinUpd
Update-Module WinUpd

$ErrorActionPreference = "Stop"
Import-Module WinUpd

# Global Variables
$script:LogFile = "log.txt"
$script:LogMessageUseInfo = $null

Function LogMessage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message
    )

    process
    {
        # Check if we can use Write-Information
        if ($null -eq $script:LogMessageUseInfo)
        {
            $script:LogMessageUseInfo = $false
            try
            {
                Write-Information "test" 6>&1 | Out-Null
                $script:LogMessageUseInfo = $true
            } catch {}
        }

        $dateFmt = ([DateTime]::Now.ToString("o"))
        $Message = "${dateFmt}: $Message"

        # Write out the actual message
        if (![string]::IsNullOrEmpty($LogFile))
        {
            $Message | Out-File -Encoding UTF8 -Append $LogFile
        }

        if ($script:LogMessageUseInfo)
        {
            Write-Information $Message
        } else {
            Write-Host $Message
        }
    }
}

# Make sure we start in the script directory
Set-Location $PSScriptRoot

# Truncate log file
if (![string]::IsNullOrEmpty($LogFile))
{
    $content = ""
    if (Test-Path $LogFile)
    {
        $content = Get-Content -Encoding UTF8 $LogFile | Select-Object -Last 2000
    }
    $content | Out-File $LogFile -Encoding UTF8
}

# Start patching process
& {
    try {
        "Updating cab file"
        Update-WinUpdCabFile -Path $CabFile -Verbose

        "Update scan service"
        $serviceId = Update-WinUpdOfflineScan -CabFile $CabFile -Verbose

        # Are we installing patches
        if ($Install)
        {
            "Retrieving a patch list for install"
            $patches = Get-WinUpdUpdates

            $age = [Math]::Abs($AgeThreshold)

            "Filtering patches by age: $age"
            $patches = $patches | Where-Object { $_.LastDeploymentChangeTime -lt ([DateTime]::Now.AddDays(-$age)) }

            if (($patches | Measure-Object).Count -gt 0)
            {
                "Installing patches"
                $patches | Format-Table -Property LastDeploymentChangeTime,MsrcSeverity,Title | Out-String
                Install-WinUpdUpdates -Updates $patches
            } else {
                "No updates to install"
            }
        }

        "Retrieving a patch list"
        $patches = Get-WinUpdUpdates
        $patches | Format-Table -Property LastDeploymentChangeTime,MsrcSeverity,Title | Out-String

        "Writing patch list to json"
        $patches | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 "patches.json"

        "Writing patch list to CSV"
        $patches | Export-CSV -Encoding UTF8 "patches.csv"

        ("Reboot required: " + (Get-WinUpdRebootRequired))

        if ($Install -and $CanReboot -and (Get-WinUpdRebootRequired))
        {
            "Reboot required for system and CanReboot is true. Scheduling reboot"
            shutdown -r -f -t 60
        }

    } catch {
        "Patch apply failed: $_"
    }
} *>&1 | ForEach-Object {
    LogMessage ($_ | Out-String).Trim()
}
