<#
#>

[CmdletBinding()]
param()

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Modules
Import-Module AutomationUtils

# Functions

Register-Automation -Name prtg.alert_history -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $endpoint,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeDays = 7,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiToken = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$UriParameters = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$SkipCertificateCheck = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$AlwaysReport = $false
    )

    process
    {
        # Starting uri
        $uri = ("{0}/api/table.json?content=messages&count=*&columns=datetime,name,sensor,device,message,status" -f $Endpoint.TrimEnd("/"))

        # Starting date
        $AgeDays = [Math]::Abs($AgeDays)
        $start = ([DateTime]::Now.AddDays(-($AgeDays)))
        $startStr = $start.ToString("yyyy-MM-dd-HH-mm-ss")
        $uri += "&filter_dstart=$startStr"

        # Add the API Token, if specified
        if (![string]::IsNullOrEmpty($ApiToken))
        {
            $uri += "&apitoken=$ApiToken"
        }

        # Add additional Uri parameters, if specified
        if (![string]::IsNullOrEmpty($UriParameters))
        {
            $uri += $UriParameters
        }

        # Parameters for the iwr call to the PRTG endpoint
        $iwrParams = @{
            Uri = $uri
            UseBasicParsing = $true
            SkipCertificateCheck = $SkipCertificateCheck
        }

        # Make the actual request to the endpoint
        $result = Invoke-WebRequest @iwrParams

        # The result content should be JSON
        $content = $result.Content | ConvertFrom-Json

        # Filter for warning or down sensors and group by sensor
        $events = $content.messages |
            Where-Object { $_.status -in @("Warning", "Down") } |
            Group-Object -Property name,device,sensor,status | ForEach-Object {

                # Latest occurance of the alert state
                $latest = ($_.Group | Sort-Object -Property datetime -Descending | Select-Object -First 1).datetime

                [PSCustomObject]@{
                    Device = ($_.Group[0].device | Limit-StringLength -Length 40)
                    Sensor = ($_.Group[0].sensor | Limit-StringLength -Length 30)
                    Status = $_.Group[0].status
                    Count = $_.Count
                    Latest = $latest
                }
            } | Sort-Object -Property Device,Sensor

        # Log information on what was found
        $capture = New-Capture
        & {
            Write-Information ("PRTG warning and down sensors for the last {0} days:" -f $AgeDays)
            $events | Format-Table -Property Device,Sensor,Status,Count,Latest -Wrap
        } *>&1 | Copy-ToCapture -Capture $capture

        # Send notification with alert history
        if ($AlwaysReport -or ($events | Measure-Object).Count -gt 0)
        {
            New-Notification -Title alert_history -Body $capture.ToString()
        }
    }
}

Register-Automation -Name prtg.alert_summary -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $endpoint,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiToken = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$UriParameters = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$SkipCertificateCheck = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int[]]$Statuses = @(5,4),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$AlwaysReport = $false
    )

    process
    {
        # Starting uri
        $uri = ("{0}/api/table.json?content=sensors&count=*&columns=sensor,device,message,status" -f $Endpoint.TrimEnd("/"))

        # Filter for status
        $Statuses | ForEach-Object {
            $uri += "&filter_status=$_"
        }

        # Add the API Token, if specified
        if (![string]::IsNullOrEmpty($ApiToken))
        {
            $uri += "&apitoken=$ApiToken"
        }

        # Add additional Uri parameters, if specified
        if (![string]::IsNullOrEmpty($UriParameters))
        {
            $uri += $UriParameters
        }

        # Parameters for the iwr call to the PRTG endpoint
        $iwrParams = @{
            Uri = $uri
            UseBasicParsing = $true
            SkipCertificateCheck = $SkipCertificateCheck
        }

        # Make the actual request to the endpoint
        $result = Invoke-WebRequest @iwrParams

        # The result content should be JSON
        $content = $result.Content | ConvertFrom-Json
        $sensors = $content.sensors | ForEach-Object {
            [PSCustomObject]@{
                Device = ($_.device | Limit-StringLength -Length 40)
                Sensor = ($_.sensor | Limit-StringLength -Length 30)
                Status = $_.status
                Message = ($_.message_raw | Limit-StringLength -Length 40)
            }
        } | Sort-Object -Property Device,Sensor

        # Log information on what was found
        $capture = New-Capture
        & {
            Write-Information "Current sensor status:"
            $sensors | Format-Table -Property Device,Sensor,Status,Message -Wrap
        } *>&1 | Copy-ToCapture -Capture $capture

        # Send notification with alert summary
        if ($AlwaysReport -or ($sensors | Measure-Object).Count -gt 0)
        {
            New-Notification -Title alert_summary -Body $capture.ToString()
        }
    }
}

