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
        [ValidateNotNullOrEmpty()]
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

