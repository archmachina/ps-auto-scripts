<#
#>

[CmdletBinding()]
param()

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Modules
Set-PSRepository PSGallery -InstallationPolicy Trusted
@("VMware.VimAutomation.Core") | ForEach-Object {
    Install-Module -Scope CurrentUser -Confirm:$false $_ -EA Ignore
    Import-Module $_
}

Import-Module AutomationUtils

# Functions

Register-Automation -Name vmware.snapshot_cleanup -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vms,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$Age
    )

    process
    {
        # Retrieve snapshots older than Age
        $snapshots = $vms | Get-Snapshot | Where-Object { $_.Created -lt ([DateTime]::Now.AddDays(-($Age))) }

        # Finish here if no snapshots found
        if (($snapshots | Measure-Object).Count -lt 1)
        {
            Write-Information "No snapshots meeting age threshold found"
            return
        }

        # Remove each snapshot
        $snapshots | ForEach-Object {
            $snapshot = $_

            Write-Information ("Removing snapshot: " + $snapshot.Name)
            $_ | Remove-Snapshot -Confirm:$false | Out-Null
        }

        # Log a notification for the removed snapshots
        New-Notification -Title "Snapshots removed" -ScriptBlock {
            Write-Information "Removed snapshots:"
            Write-Information ($snapshots | Format-Table VM,Name,Created,SizeGB | Out-String)
        }
    }
}

Register-Automation -Name vmware.vm_consolidate -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [AllowEmptyCollection()]
        $vms
    )

    process
    {
        # Consolidate VMs requiring it and record VMs changed
        $consolidated = $vms | ForEach-Object {
            $vm = $_

            # Do nothing if this VM doesn't require consolidation
            if (!$vm.ExtensionData.Runtime.ConsolidationNeeded)
            {
                return
            }

            # Consolidate VM
            Write-Information ("Consolidating VM: " + $vm.Name)
            $vm.ExtensionData.ConsolidateVMDisks()

            $vm
        }

        # Finish here if no VMs required consolidation
        if (($consolidated | Measure-Object).Count -lt 1)
        {
            Write-Information "No VMs required consolidation"
            return
        }

        # Log a notification as we consolidated some VMs
        New-Notification -Title "VMs Consolidated" -ScriptBlock {
            Write-Information "VMs consolidated:"
            Write-Information ($consolidated | ForEach-Object { $_.Name })
        }
    }
}

Register-Automation -Name vmware.host_health -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        $VMHosts,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$IncludeAcknowledged = $false
    )

    process
    {
        # Check for hosts that are not connected
        Write-Information "Checking hosts connection state"
        $notConnected = $VMHosts | Where-Object { $_.ConnectionState -ne "Connected" }
        $count = ($notConnected | Measure-Object).Count
        if ($count -gt 0)
        {
            # Some hosts are not in the Connected state, so we should generate an alert
            New-Notification -Title "VM Hosts not connected" -ScriptBlock {
                Write-Information "Some VM hosts are not connected:"
                $notConnected | Format-Table -Property Name,ConnectionState
            }
        } else {
            Write-Information "All hosts in 'Connected' state"
        }

        # Check for hosts with alerts
        Write-Information "Checking for hosts with 'overall status' issues"
        $hosts = $VMHosts | Where-Object {$_.ExtensionData.OverallStatus.ToString() -ne "green"}
        $count = ($hosts | Measure-Object).Count
        if ($count -gt 0)
        {
            New-Notification -Title "VM Hosts with status issues" -ScriptBlock {
                $hosts | Select-Object -Property Name,@{N="OverallStatus";E={$_.ExtensionData.OverallStatus.ToString()}} | Format-Table
            }
        } else {
            Write-Information "No hosts with overall status issues"
        }

        # Check for config status
        Write-Information "Checking for hosts with config issues"
        $hosts = $vmhosts | Where-Object {$_.ExtensionData.ConfigStatus.ToString() -ne "green"}
        $count = ($hosts | Measure-Object).Count
        if ($count -gt 0)
        {
            New-Notification -Title "VM Hosts with config issues" -ScriptBlock {
                $hosts | Select-Object -Property Name,@{N="ConfigStatus";E={$_.ExtensionData.ConfigStatus.ToString()}} | Format-Table
            }
        } else {
            Write-Information "No hosts with config status issues"
        }

        # Check for triggered alarms
        Write-Information "Checking for triggered alarms for hosts"
        $allAlarms = $vmhosts | ForEach-Object {
            $vmhost = $_

            $vmhost.ExtensionData.TriggeredAlarmState | ForEach-Object {
                $state = $_

                $names = Get-View -Id $state.Alarm |
                    ForEach-Object { $_.Info.Name } |
                    Select-Object -Unique |
                    Split-StringLength -WrapLength 60 |
                    Out-String

                [PSCustomObject]@{
                    Name = $vmhost.Name
                    Description = $names
                    Time = $state.Time
                    Acknowledged = $state.Acknowledged
                    AcknowledgedByUser = $state.AcknowledgedByUser
                }
            }
        }

        # Filter out acknowledged alarms, if required
        if (-not $IncludeAcknowledged)
        {
            $allAlarms = $allAlarms | Where-Object { -not $_.Acknowledged }
        }

        # Notification on current alarms for hosts
        if (($allAlarms | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Host Alarms" -ScriptBlock {
                $allAlarms |
                    Format-Table -Wrap -Property Name,Time,Acknowledged,AcknowledgedByUser,Description |
                    Out-String -Width 300
            }
        } else {
            Write-Information "No hosts with triggered alarms"
        }
    }
}

Register-Automation -Name vmware.cluster_health -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        $Clusters,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$IncludeAcknowledged = $false
    )

    process
    {
        # Check for clusters with alerts
        Write-Information "Checking for clusters with 'overall status' issues"
        $errClusters = $Clusters | Where-Object {$_.ExtensionData.OverallStatus.ToString() -ne "green"}
        $count = ($errClusters | Measure-Object).Count
        if ($count -gt 0)
        {
            New-Notification -Title "Clusters with status issues" -ScriptBlock {
                $errClusters | Select-Object -Property Name,@{N="OverallStatus";E={$_.ExtensionData.OverallStatus.ToString()}} |
                    Format-Table
            }
        } else {
            Write-Information "No clusters with overall status issues"
        }

        # Check for config status
        Write-Information "Checking for clusters with config issues"
        $errCLusters = $Clusters | Where-Object {$_.ExtensionData.ConfigStatus.ToString() -ne "green"}
        $count = ($errClusters | Measure-Object).Count
        if ($count -gt 0)
        {
            New-Notification -Title "Clusters with config issues" -ScriptBlock {
                $errClusters | Select-Object -Property Name,@{N="ConfigStatus";E={$_.ExtensionData.ConfigStatus.ToString()}} |
                    Format-Table
            }
        } else {
            Write-Information "No clusters with config status issues"
        }

        # Check for triggered alarms
        Write-Information "Checking for triggered alarms for clusters"
        $allAlarms = $Clusters | ForEach-Object {
            $cluster = $_

            $cluster.ExtensionData.TriggeredAlarmState | ForEach-Object {
                $state = $_

                $names = Get-View -Id $state.Alarm |
                    ForEach-Object { $_.Info.Name } |
                    Select-Object -Unique |
                    Split-StringLength -WrapLength 60 |
                    Out-String

                [PSCustomObject]@{
                    Name = $cluster.Name
                    Description = $names
                    Time = $state.Time
                    Acknowledged = $state.Acknowledged
                    AcknowledgedByUser = $state.AcknowledgedByUser
                }
            }
        }

        # Filter out acknowledged alarms, if required
        if (-not $IncludeAcknowledged)
        {
            $allAlarms = $allAlarms | Where-Object { -not $_.Acknowledged }
        }

        # Notification on current alarms for clusters
        if (($allAlarms | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Cluster Alarms" -ScriptBlock {
                $allAlarms |
                    Format-Table -Wrap -Property Name,Time,Acknowledged,AcknowledgedByUser,Description |
                    Out-String -Width 300
            }
        } else {
            Write-Information "No clusters with triggered alarms"
        }
    }
}

Register-Automation -Name vmware.failed_logins -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        $Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$MaxSamples = 100000,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$FailureThreshold = 3
    )

    process
    {
        # Make sure the age is positive
        $AgeHours = [Math]::Abs($AgeHours)

        # Calculate the start time for event collection
        $start = [DateTime]::Now.AddHours(-$AgeHours)

        # Process failed logins per vcenter server
        $Servers | ForEach-Object {
            $server = $_

            # Capture failed login events
            $events = Get-VIEvent -Server $server -Start $start -MaxSamples $MaxSamples |
                Where-Object { $_ -is "VMware.Vim.EventEx" -and $_.EventTypeId -eq "com.vmware.sso.LoginFailure" }

            # Group by username to capture total failed logins
            $failedUsers = $events | Group-Object -Property UserName
            Write-Information "Failed logins over the last $Agehours hours ($Server):"
            $failedUsers | Format-Table -Property Name,Count

            # Identify users over the threshold
            $alertUsers = $failedUsers | Where-Object { $_.Count -ge $FailureThreshold }

            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Failed logins over threshold ($FailureThreshold) over the last $Agehours hours ($Server):"
                $alertUsers | Format-Table -Property Name,Count
            }

            # Send a notification if there are any alert users
            if (($alertUsers | Measure-Object).Count -gt 0)
            {
                New-Notification -Title "Failed logins over threshold - last $AgeHours hours ($Server)" -Body ($capture.ToString())
            }
        }
    }
}

Register-Automation -Name vmware.event_history -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        $Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$MaxSamples = 100000,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Types = @("Error", "Warning")
    )

    process
    {
        # Make sure the age is positive
        $AgeHours = [Math]::Abs($AgeHours)

        # Calculate the start time for event collection
        $start = [DateTime]::Now.AddHours(-$AgeHours)

        # Process events per vcenter server
        $Servers | ForEach-Object {
            $server = $_

            # Capture relevant events
            $events = Get-VIEvent -Server $server -Start $start -MaxSamples $MaxSamples -Types $Types |
                Where-Object { -not [string]::IsNullOrEmpty($_.FullFormattedMessage) }

            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "vCenter events over the last $AgeHours hours ($Server):"
                $events | Format-Table -Property CreatedTime,FullFormattedMessage | Out-String -Width 300
            }

            # Send a notification if there are any events
            if (($events | Measure-Object).Count -gt 0)
            {
                New-Notification -Title "vCenter events over the last $AgeHours hours ($Server)" -Body ($capture.ToString())
            }
        }
    }
}

