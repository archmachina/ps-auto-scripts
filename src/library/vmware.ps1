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
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        $vm,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$Age
    )

    process
    {
        # Retrieve snapshots older than Age
        $snapshots = $vm | Get-Snapshot | Where-Object { $_.Created -lt ([DateTime]::Now.AddDays(-($Age))) }

        # Finish here if no snapshots found
        if (($snapshots | Measure-Object).Count -lt 1)
        {
            return
        }

        # Remove each snapshot and return a copy of the snapshot object
        $snapshots | ForEach-Object {
            $_
            $_ | Remove-Snapshot -Confirm:$false
        }
    }
}

Function Invoke-VMConsolidate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        $vm
    )

    process
    {
        # Do nothing if this VM doesn't require consolidation
        if (!$vm.ExtensionData.Runtime.ConsolidationNeeded)
        {
            return
        }

        # Consolidate VM
        $vm.ExtensionData.ConsolidateVMDisks()

        $vm
    }
}


