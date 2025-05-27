<#
#>

[CmdletBinding()]
param()

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"


Function Get-WinEventServer
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string[]]$Servers,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogName,

        [Parameter(mandatory=$false)]
        [ValidateNotNull()]
        [int]$MaxSamples = 10000,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [string]$ExecuteFrom = ""
    )

    process
    {
        # Record of which servers failed during log query
        $failed = @()

        # Query each listed server
        $events = $Servers | ForEach-Object {
            $server = $_

            $failure = $null
            try {
                Write-Information "Checking logs for $server"

                # Execute script, locally or from another machine
                if ([string]::IsNullOrEmpty($ExecuteFrom))
                {
                    Get-WinEvent -ComputerName $server -LogName $LogName -FilterXPath $Filter -MaxEvents $MaxSamples
                } else {
                    Invoke-Command -ComputerName $ExecuteFrom -ScriptBlock {
                        param($server,$LogName,$Filter,$MaxSamples)

                        Get-WinEvent -ComputerName $server -LogName $LogName -FilterXPath $Filter -MaxEvents $MaxSamples |
                            ConvertTo-Json -Depth 3 |
                            ConvertFrom-Json
                    } -ArgumentList $server,$LogName,$Filter,$MaxSamples
                }
            } catch {
                $failure = [string]$_

                # Get-WinEvent generates an ErrorRecord when there are no matches, but we still want to
                # catch other issues.
                if ($failure -like "*No events were found*")
                {
                    $failure = $null
                }
            }

            # Check if we failed to capture logs
            if ($null -ne $failure)
            {
                Write-Information "Server log query failure for $server"
                $failed += [PSCustomObject]@{
                    Name = $server
                    Error = $failure | Out-String
                }
            }

        } | ForEach-Object { $_ }

        # Return the logs and list any failed servers
        [PSCustomObject]@{
            Events = $events
            Failures = $failed
        }
    }
}

