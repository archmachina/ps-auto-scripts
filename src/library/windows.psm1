<#
#>

[CmdletBinding()]
param()

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Modules
Import-Module ActiveDirectory

# Functions

Register-Automation -Name active_directory.inactive_users -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Users,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$WarningDays,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$DisableDays,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$IgnoreString = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$DryRun = $true
    )

    process
    {
        # Make sure Day thresholds are positive
        $WarningDays = [Math]::Abs($WarningDays)
        $DisableDays = [Math]::Abs($DisableDays)
        Write-Information "WarningDays: $WarningDays"
        Write-Information "DisableDays: $DisableDays"
        Write-Information "Note: Using created date when no last logon present"

        # Filter for enabled users and convert to a more useful object
        $workingUsers = $Users | Where-Object {
            $_.Enabled
        } | ForEach-Object {

            # Make sure where is a value for LastLogon
            $lastLogon = $_.lastLogonDate
            if ($null -eq $lastLogon -or [DateTime]::MinValue -eq $lastLogon)
            {
                $lastLogon = $_.Created
            }

            if ($null -eq $lastLogon)
            {
                $lastLogon = [DateTime]::MinValue
            }

            [PSCustomObject]@{
                Login = $_.SamAccountName
                DisplayName = $_.DisplayName
                LastLogon = $lastLogon
                DistinguishedName = $_.DistinguishedName
                Description = $_.Description
                Age = ([Math]::Round(([DateTime]::Now - $lastLogon).TotalDays, 2))
            }
        }

        Write-Information ("Found {0} enabled AD users" -f ($workingUsers | Measure-Object).Count)

        # Filter out users matching the ignore filter
        if (![string]::IsNullOrEmpty($IgnoreString))
        {
            $filtered = $workingUsers | Where-Object { $_.Description -like $IgnoreString }
            $workingUsers = $workingUsers | Where-Object { $_.Description -notlike $IgnoreString }
            Write-Information ("Found {0} users matching ignore string:" -f ($filtered | Measure-Object).Count)
            $filtered | Format-Table -Property Login,DisplayName,LastLogon,Age,Description
        }

        # Identify users in the warning range
        $warningUsers = $workingUsers | Where-Object {
            $_.LastLogon -lt ([DateTime]::Now.AddDays(-($WarningDays))) -and
            $_.LastLogon -ge ([DateTime]::Now.AddDays(-($DisableDays)))
        } | Sort-Object -Property Age -Descending
        $warningCount = ($warningUsers | Measure-Object).Count

        # Log any users nearing the warning threshold
        $capture = New-Capture
        & {
            Write-Information ("Found {0} users nearing the disable threshold:" -f $warningCount)
            $warningUsers | Format-Table -Property Login,DisplayName,LastLogon,Age,Description
        } *>&1 | Copy-ToCapture -Capture $capture

        # Log the results and send a notification if there are any warning users
        if ($warningCount -gt 0)
        {
            New-Notification -Title "Users nearing disable threshold" -Body ($capture.Content | Out-String)
        }

        # Identify users who should be disabled
        $disableUsers = $workingUsers | Where-Object {
            $_.LastLogon -lt ([DateTime]::Now.AddDays(-($DisableDays)))
        } | Sort-Object -Property Age -Descending
        $disableCount = ($disableUsers | Measure-Object).Count

        # Disable user accounts
        Write-Information "Disabling user accounts"
        if ($DryRun)
        {
            Write-Information "DryRun - Not disabling user accounts"
        } else {
            $disableUsers | ForEach-Object {
                Write-Information ("Disabling user: {0}" -f $_.DistinguishedName)
                Disable-ADAccount -Identity $_.DistinguishedName | Out-Null
            }
        }

        # Log any users disabled by age threshold
        $capture = New-Capture
        & {
            Write-Information ("Disabled {0} users due to age threshold (DryRun {1}):" -f $disableCount, $DryRun)
            $disableUsers | Format-Table -Property Login,DisplayName,LastLogon,Age,Description
        } *>&1 | Copy-ToCapture -Capture $capture

        # Log the results and send a notification if there are any disabled users
        if ($disableCount -gt 0)
        {
            New-Notification -Title "Users disabled by age threshold" -Body ($capture.Content | Out-String)
        }
    }
}

Register-Automation -Name active_directory.lockedout_users -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Users,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)

        # Filter for users who have been locked out recently
        $records = $Users | Where-Object {
            $_.AccountLockoutTime -gt ([DateTime]::Now.AddHours(-($AgeHours)))
        }

        # Transform records
        $records = $records | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                LockedOut = $_.LockedOut
                LockoutTime = $_.AccountLockoutTime
            }
        }

        # Report for logs
        Write-Information ("Found {0} recently locked out users" -f ($records | Measure-Object).Count)

        # Notification for any locked out users
        if (($records | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information ("Found {0} recently locked out users" -f ($records | Measure-Object).Count)
                $records | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Recently locked out users" -Body ($capture.ToString())
        }
    }
}

Register-Automation -Name active_directory.lockedout_user_log -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string[]]$Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)
        $ageSearch = $AgeHours * 60 * 60 * 1000

        # XPath string
        $xPath = "*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= {0}]]]" -f $ageSearch
        Write-Information "XPath string: $xPath"

        # Get event logs that match the xpath search in Security
        $result = Get-WinEventServers -Servers $Servers -LogName Security -Filter $xPath
        $events = $result.Events

        # Notification for any failed servers
        if (($result.Failures | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Server log query failed"
                $result.Failures | Format-Table -Wrap | Out-String -Width 300
            }
        }

        # Transform records
        $records = $events | ForEach-Object {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $_.Properties[0].Value
                Domain = $_.Properties[5].Value
                Source = $_.Properties[1].Value
            }
        }

        # Report for logs
        Write-Information ("Found {0} lockout logs" -f ($records | Measure-Object).Count)

        # Notification for any locked out users
        if (($records | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information ("Found {0} lockout logs" -f ($records | Measure-Object).Count)
                $records | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Lockout log entries" -Body ($capture.ToString())
        }
    }
}

Register-Automation -Name active_directory.failed_logins -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$GroupResults = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$UserIgnore = @()
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)
        $ageSearch = $AgeHours * 60 * 60 * 1000

        # XPath string
        $xPath = "*[System[band(Keywords,4503599627370496) and (EventID=4625 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= {0}]]]" -f $ageSearch
        Write-Information "XPath string: $xPath"

        # Get event logs that match the xpath search in Security
        $result = Get-WinEventServers -Servers $Servers -LogName Security -Filter $xPath
        $events = $result.Events

        # Notification for any failed servers
        if (($result.Failures | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Server log query failed"
                $result.Failures | Format-Table -Wrap | Out-String -Width 300
            }
        }

        # Transform records
        $records = $events | ForEach-Object {
            $record = $_

            switch ($record.Id)
            {
                4771 {
                    [PSCustomObject]@{
                        Time = $record.TimeCreated
                        User = $record.Properties[0].Value
                        Domain = ""
                        Workstation = ""
                        Address = $record.Properties[6].Value
                        Method = "Kerberos"
                        LogonType = ""
                    }

                    break
                }
                4625 {
                    [PSCustomObject]@{
                        Time = $record.TimeCreated
                        User = $record.Properties[5].Value
                        Domain = $record.Properties[6].Value
                        Workstation = $record.Properties[13].Value
                        Address = $record.Properties[19].Value
                        Method = $record.Properties[12].Value
                        LogonType = $record.Properties[10].Value
                    }

                    break
                }
            }
        }

        # Ignore users that match the ignore filter
        $records = $records | ForEach-Object {
            $record = $_

            foreach ($item in $UserIgnore)
            {
                if ($record.User -match $item)
                {
                    return
                }
            }

            $record
        }

        # Group results and provide a count of the number of failed logins, if requested
        if ($GroupResults)
        {
            $records = $records | Group-Object -Property User,Domain,Workstation,Address,Method | ForEach-Object {
                [PSCustomObject]@{
                    FailureCount = $_.Count
                    User = $_.Group[0].User
                    Domain = $_.Group[0].Domain
                    Workstation = $_.Group[0].Workstation
                    Address = $_.Group[0].Address
                    Method = $_.Group[0].Method
                    LogonType = $_.Group[0].LogonType
                }
            }
        }

        # Report for logs
        Write-Information ("Found {0} failed login logs" -f ($records | Measure-Object).Count)

        # Notification for any failed logins
        if (($records | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information ("Found {0} failed logins" -f ($records | Measure-Object).Count)
                $records | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Failed logins" -Body ($capture.ToString())
        }
    }

}

Function Get-WinEventServers
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
        [string]$Filter
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
                Get-WinEvent -ComputerName $server -LogName $LogName -FilterXPath $Filter -MaxEvents $MaxSamples
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

