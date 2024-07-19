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

        # Filter for enabled users and convert to a more useful object
        $workingUsers = $Users | Where-Object {
            $_.Enabled
        } | ForEach-Object {

            # Make sure where is a value for LastLogon
            $lastLogon = $_.lastLogonDate
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
                # Disable-ADAccount -Identity $_.DistinguishedName | Out-Null
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

