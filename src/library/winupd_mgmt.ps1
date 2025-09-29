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
    [string]$Proxy = $null,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [switch]$UseCab = $false
)

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Output management
try {
    $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
} catch {}

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

        # Make sure we start in the script directory
        "Changing to $PSScriptRoot"
        Set-Location $PSScriptRoot

        # Proxy configuration
        if (![string]::IsNullOrEmpty($Proxy))
        {
            $Env:HTTP_PROXY = $Proxy
            $Env:HTTPS_PROXY = $Proxy

            try {
                [System.Net.Http.HttpClient]::DefaultProxy = [System.Net.WebProxy]::new($proxy)
                [System.Net.Http.HttpClient]::DefaultProxy.BypassProxyOnLocal = $true
            } catch {
                "Failed to set HttpClient proxy: $_"
            }

            try {
                [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
                [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true
            } catch {
                "Failed to set WebRequest proxy: $_"
            }
        }

        # Import modules
        "Install NuGet package provider"
        try {
            # Set TLS support to 1.1 and 1.2 explicitly
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false -Scope CurrentUser
        } catch {
            "Error updating package provider: $_"
        }

        "Trusting PSGallery"
        try {
            Set-PSRepository PSGallery -InstallationPolicy Trusted
        } catch {
            "Error trusting PSGallery: $_"
        }

        "Installing WinUpd"
        try {
            Install-Module -Scope CurrentUser -RequiredVersion 0.1.6 WinUpd -Confirm:$false
        } catch {
            "Error installing WinUpd module: $_"
        }

        "Importing WinUpd"
        Import-Module WinUpd -RequiredVersion 0.1.6

        $updArgs = @{}
        if ($UseCab)
        {
            "Updating cab file"
            try {
                Update-WinUpdCabFile -Path $CabFile -Verbose
            } catch {
                "Failed to update cab file: $_"
            }

            "Update scan service"
            $serviceId = Update-WinUpdOfflineScan -CabFile $CabFile -Verbose
            $updArgs["ServiceId"] = $serviceId
        }

        # Are we installing patches
        if ($Install)
        {
            "Retrieving a patch list for install"
            $patches = Get-WinUpdUpdates @updArgs

            $age = [Math]::Abs($AgeThreshold)

            "Filtering patches by age: $age"
            $patches = $patches | Where-Object { $_.LastDeploymentChangeTime -lt ([DateTime]::Now.AddDays(-$age)) }

			"Accepting EULAs"
			$patches | ForEach-Object {
				try {
					$_.AcceptEula()
				} catch {
					"Error accepting Eula: $_"
				}
			}

            if (($patches | Measure-Object).Count -gt 0)
            {
                "Installing patches"
                $patches | Format-Table -Property LastDeploymentChangeTime,MsrcSeverity,Title | Out-String
                $result = Install-WinUpdUpdates -Updates $patches
                $result.Download | Format-Table -Property * | Out-String -Width 300
                $result.Install | Format-Table -Property * | Out-String -Width 300
            } else {
                "No updates to install"
            }
        }

        "Retrieving a patch list"
        $patches = Get-WinUpdUpdates @updArgs
        $patches | Format-Table -Property LastDeploymentChangeTime,MsrcSeverity,Title | Out-String

        "Writing raw patch list to json"
        $patches |
            Select-Object -ExcludeProperty DownloadContents |
            ConvertTo-Json |
            Out-File -Encoding UTF8 "patches_raw.json"

        "Writing patch list to json"
        $summaryPatches = $patches |
            ForEach-Object {
                [PSCustomObject]@{
                    Title = $_.Title
                    RebootRequired = $_.RebootRequired
                    LastDeploymentChangeTime = $_.LastDeploymentChangeTime
                    KBArticleIDs = $_.KBArticleIDs
                    Description = $_.Description
                    Categories = $_.Categories
                    MsrcSeverity = $_.MsrcSeverity
                    CveIDs = $_.CveIDs
                }
            }
        $summaryPatches |
            ConvertTo-Json |
            Out-File -Encoding UTF8 "patches.json"

        "Writing patch list to CSV"
        $patches |
            ForEach-Object {
                [PSCustomObject]@{
                    Title = $_.Title
                    RebootRequired = $_.RebootRequired
                    LastDeploymentChangeTime = $_.LastDeploymentChangeTime.ToString("o")
                    KBArticleIDs = [string]::Join(", ", $_.KBArticleIDs)
                    Description = $_.Description
                    MsrcSeverity = $_.MsrcSeverity
                    CveIDs = [string]::Join(", ", $_.CveIDs)
                }
            } |
            Export-CSV -NoTypeInformation -Encoding UTF8 "patches.csv"

        # Write a system state out to file
        "Writing system state json"
        $stateUpdates = $summaryPatches
        if (($stateUpdates | Measure-Object).Count -eq 0)
        {
            # This is to handle peculiarities with the PS5 convert to json command - Empty collections
            # end up as empty dictionaries in json.
            $stateUpdates = @()
        }
        $patchState = [PSCustomObject]@{
            Hostname = ([System.Net.DNS]::GetHostname())
            DateUtc = [DateTime]::UtcNow
            DateUtcStr = [DateTime]::UtcNow.ToString("o")
            Updates = $stateUpdates
            CabModificationTime = (Get-Item $CabFile).LastWriteTimeUtc
            CabModificationTimeStr = (Get-Item $CabFile).LastWriteTimeUtc.ToString("o")
        }
        $patchState | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 "state.json"

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
    if ($null -eq $_)
    {
        return
    }

    LogMessage ($_ | Out-String).Trim()
}
