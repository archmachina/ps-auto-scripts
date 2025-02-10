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
        $Server,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)

        # XPath string
        $ageSearch = $AgeHours * 60 * 60 * 1000
        $xPath = "*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= {0}]]]" -f $ageSearch
        Write-Information "XPath string: $xPath"

        # Get event logs that match the xpath search in Security
        try {
            $events = Get-WinEvent -ComputerName $Server -LogName Security -FilterXPath $xPath -MaxEvents 10000
        } catch {
            # Get-WinEvent generates an ErrorRecord when there are no matches, but we still want to
            # catch other issues.
            if ($_ -is [System.Management.Automation.ErrorRecord] -and $_.Exception.Message -like "*No events were found*")
            {
                Write-Information "Search returned no results"
                $events = @()
            } else {
                Write-Error $_
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

