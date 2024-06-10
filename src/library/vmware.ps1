<#
#>

[CmdletBinding()]
param()

# Modules
Set-PSRepository PSGallery -InstallationPolicy Trusted
@("VMware.VimAutomation.Core") | ForEach-Object {
    Install-Module -Scope CurrentUser -Confirm:$false $_ -EA Ignore
    Update-Module -Confirm:$false $_ -EA Ignore
    Import-Module $_
}

# Functions

Function Remove-VMSnapshots
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $vms,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$Age
    )

    process
    {
        # Retrieving snapshots
        Write-Information "Retrieving snapshots"
        $snapshots = $vms | Get-Snapshot

        # Finish here if no snapshots found
        if (($snapshots | Measure-Object).Count -lt 1)
        {
            Write-Information "No snapshots found"
            return
        }

        Write-Information "Snapshot list:"
        $snapshots |
            Select-Object -Property VM,Name,@{N="Age";E={([DateTime]::Now - $_.Created).TotalDays}},SizeGB |
            Format-Table

        # Filter to snapshots older than the threshold
        $snapshots = $snapshots | Where-Object { $_.Created -lt ([DateTIme]::Now.AddDays(-($Age))) }

        # Finish here if no snapshots found
        if (($snapshots | Measure-Object).Count -lt 1)
        {
            Write-Information "No snapshots over threshold found"
            return
        }

        # Display all snapshots
        Write-Information "Snapshot to purge, based on age:"
        $snapshots |
            Select-Object -Property VM,Name,@{N="Age";E={([DateTime]::Now - $_.Created).TotalDays}},SizeGB |
            Format-Table

        # Remove each snapshot and log progress information
        Write-Information "Removing snapshots"
        $snapshots | ForEach-Object {
            Write-Information ("Removing snapshot {0} for {1}" -f $_.Name, $_.VM)
            $_ | Remove-Snapshot -Confirm:$false
        }

        # Update body with snapshot information for notification
        $body += "Snapshots cleaned up due to age:"
        $body += $snapshots | Format-Table -Property VM,Name,Created,SizeGB | Out-String
    }
}

Function Invoke-VMConsolidate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $vms
    )

    process
    {
        Write-Information "Checking for VMs requiring consolidation"
        $needed = $vms | Where-Object { $_.ExtensionData.Runtime.ConsolidationNeeded }

        # Finish here if no VMs require consolidation
        if (($needed | Measure-Object).Count -lt 1)
        {
            Write-Information "No VMs require consolidation"
            return
        }

        # Record VMs requiring consolidation
        Write-Information "VMs requiring consolidation:"
        $needed | ForEach-Object { $_.Name }

        # Consolidate VMs
        $needed | ForEach-Object {
            Write-Information ("Consolidating {0}" -f $_.Name)
            $_.ExtensionData.ConsolidateVMDisks()
        }

        # Add list of consolidated VMs to body list for notification
        $body += "Consolidated VMs:"
        $needed | ForEach-Object {
            $body += $_.Name
        }
    }
}


