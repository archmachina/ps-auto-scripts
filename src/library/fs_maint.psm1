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

Register-Automation -Name fs_maint.purge_files -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.IO.FileInfo[]]$FileList,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$WarningAgeDays,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$PurgeAgeDays,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$Notify = $true,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$DryRun = $true
    )

    process
    {
        # Just return if a null or empty list was provided
        if (($FileList | Measure-Object).Count -eq 0)
        {
            return
        }

        # Make sure we have positive values
        $WarningAgeDays = [Math]::Abs($WarningAgeDays)
        $PurgeAgeDays = [Math]::Abs($PurgeAgeDays)

        # Make sure the warning age is <= the purge age
        if ($WarningAgeDays -gt $PurgeAgeDays)
        {
            Write-Error "Warning age is greater than the purge age"
        }

        # Calculate thresholds for warnings and purging
        $now = [DateTime]::Now
        $warningThreshold = $now.AddDays(-$WarningAgeDays)
        $purgeThreshold = $now.AddDays(-$PurgeAgeDays)
        Write-Information "Warning Threshold: $warningThreshold"
        Write-Information "Purge Threshold: $purgeThreshold"

        # Create a separate object to work with
        $files = $FileList | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                LastWriteTime = $_.LastWriteTime
                AgeDays = [Math]::Round(($now - $_.LastWriteTime).TotalDays, 2)
                Original = $_
            }
        } | Sort-Object -Property AgeDays -Descending

        # Determine warning and purge file lists
        $warningFiles = $files | Where-Object {
            $_.LastWriteTime -lt $warningThreshold -and
            $_.LastWriteTime -ge $purgeThreshold
        }

        $purgeFiles = $files | Where-Object { $_.LastWriteTime -lt $purgeThreshold }

        # Notification for warning files
        if (($warningFiles | Measure-Object).Count -gt 0)
        {
            # Capture information on warning files for logs regardless
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Files nearing purge age ($Name):"
                $warningFiles | Format-Table -Property Name,LastWriteTime,AgeDays | Out-String -Width 300
            }

            # Send notification on warning files, if configured to notify
            if ($Notify)
            {
                New-Notification -Title "Files nearing purge age ($Name)" -Body ($capture.ToString())
            }
        }

        # Notification for purge files
        if (($purgeFiles | Measure-Object).Count -gt 0)
        {
            # Capture information on purge files for logs regardless
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Files purged by age ($Name):"
                $purgeFiles | Format-Table -Property Name,LastWriteTime,AgeDays | Out-String -Width 300
            }

            # Send notification on purged files, if configured to notify
            if ($Notify)
            {
                New-Notification -Title "Files purged by age ($Name)" -Body ($capture.ToString())
            }

            # Actual removal of files
            if ($DryRun)
            {
                Write-Information "Dry Run - not purging"
            } else {
                $failed = @()

                # Attempt to remove the files
                $purgeFiles | ForEach-Object {
                    $file = $_.Original

                    try {
                        Remove-Item -Force $file
                    } catch {
                        $failed += [PSCustomObject]@{
                            FullName = $file.FullName
                            Excetion = [str]$_
                        }
                    }
                }

                # Send a notification for any files that failed removal (whether notify is enabled or not)
                $capture = New-Capture
                Invoke-CaptureScript -Capture $capture -ScriptBlock {
                    Write-Information "Some files failed removal:"
                    $failed | Format-Table -Wrap | Out-String -Width 300
                }
            }
        }
    }
}

