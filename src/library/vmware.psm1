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
    Update-Module -Confirm:$false $_ -EA Ignore
    Import-Module $_
}

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
            Write-Information ("Removing snapshot: " + $snapshot.Name)
            $_ | Remove-Snapshot -Confirm:$false | Out-Null
        }

        # Log a notification for the removed snapshots
        $capture = New-Capture
        & {
            Write-Information "Removed snapshots:"
            Write-Information ($snapshots | Format-Table VM,Name,Created,SizeGB | Out-String)
        } *>&1 | Copy-ToCapture -Capture $capture

        New-Notification -Title "Snapshots removed" -Body ($capture | Out-String)
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
        $capture = New-Capture
        & {
            Write-Information "VMs consolidated:"
            Write-Information ($consolidated | ForEach-Object { $_.Name })
        } *>&1 | Copy-ToCapture -Capture $capture

        New-Notification -Title "VMs Consolidated" -Body ($capture | Out-String)
    }
}

