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
@("VMware.PowerCli") | ForEach-Object {
    Install-Module -Scope CurrentUser -Confirm:$false $_ -EA Ignore
    Import-Module $_
}

Import-Module AutomationUtils

# Functions

Function Replace-StringNewlines
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [string]$Value,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Replacement
    )

    process
    {
        $Value.Replace([Environment]::Newline, $Replacement).Replace("`n", $Replacement).Replace("`r", $Replacement)
    }
}

Function Add-ObjToDict
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [HashTable]$Dict,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        $Obj,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [AllowEmptyCollection()]
        [string[]]$IncludeType = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [HashTable]$VisitList = @{},

        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        #[ValidateNotNullOrEmpty()]
        [string[]]$ExcludePath = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$MaxDepth = 3
    )

    process
    {
        $MaxDepth--

        # Quit here if this is an excluded path
        if (($ExcludePath | Where-Object { $Key -match $_ } | Measure-Object).Count -gt 0)
        {
            return
        }

        # Convert a null to empty string
        if ($null -eq $Obj)
        {
            $Dict[$Key] = ""

            return
        }

        # Record the object in the visit list
        # Only used if we're going to descending in to the object
        $VisitList[$Obj] = $Obj

        if ($Obj -is [System.Enum])
        {
            $Dict[$Key] = $Obj | Out-String | Replace-StringNewlines -Replacement " "

            return
        }

        # If obj is a container, descend in to it
        if ([System.Collections.ICollection].IsAssignableFrom($Obj.GetType()))
        {
            $index = 0
            $Obj | ForEach-Object {
                if ($_ -notin $VisitList -and $MaxDepth -gt 0)
                {
                    Add-ObjToDict -Dict $Dict -Key ($Key + "." + $index) -Obj $_ -IncludeType $IncludeType -VisitList $VisitList -ExcludePath $ExcludePath -MaxDepth $MaxDepth
                }

                $index++
            }

            return
        }

        # If the type matches a type filter, then process the properties
        $objType = $Obj.GetType().FullName
        if (($IncludeType | Where-Object { $objType -match $_ } | Measure-Object).Count -gt 0)
        {
            $Obj.PSObject.Properties | ForEach-Object {
                $name = $_.Name
                $value = $_.Value

                if ($value -notin $VisitList -and $MaxDepth -gt 0)
                {
                    Add-ObjToDict -Dict $Dict -Key ($Key + "." + $name) -Obj $value -IncludeType $IncludeType -VisitList $VisitList -ExcludePath $ExcludePath -MaxDepth $MaxDepth
                }
            }

            return
        }

        # Unknown type and not collection, so just convert to string
        $Dict[$Key] = $Obj | Out-String | Replace-StringNewlines -Replacement " "
    }
}

Function Get-VMSpec
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        $VM
    )

    process
    {
        $vmSpec = @{}

        # Add VM network information
        $index = 0
        $vm | Get-NetworkAdapter | ForEach-Object {
            Add-ObjToDict -Dict $vmSpec -Key "network.$index" -Obj $_ -IncludeType @("^VMware.*") -ExcludePath @(
                "^network\..*.Parent"
            )

            $index++
        }

        # Add VM harddisk information
        $index = 0
        $vm | Get-HardDisk | ForEach-Object {
            Add-ObjToDict -Dict $vmSpec -Key "harddisk.$index" -Obj $_ -IncludeType @("^VMware.*") -ExcludePath @(
                "^harddisk\..*.Parent"
            )
        }

        # Add guest information
        Add-ObjToDict -Dict $vmSpec -Key "guest" -Obj $vm.ExtensionData.Guest -IncludeType @("^VMware.*")

        # Add config information
        Add-ObjToDict -Dict $vmSpec -Key "config" -Obj $vm.ExtensionData.Config -IncludeType @("^VMware.*") -ExcludePath @(
            "^config.ExtraConfig\..*",
            "^config.VmxConfigChecksum"
        )

        # Add extra config information
        $vm.ExtensionData.Config.ExtraConfig | ForEach-Object {
            Add-ObjToDict -Dict $vmSpec -Key ("config.ExtraConfig." + $_.Key) -Obj $_.Value -ExcludePath @(
                "^config.ExtraConfig.guestinfo.appInfo"
            )
        }

        # Add VM resource config
        Add-ObjToDict -Dict $vmSpec -Key "resourceconfig" -Obj $vm.ExtensionData.ResourceConfig -IncludeType @("^VMware.*")

        # Add VM resourcepool config
        Add-ObjToDict -Dict $vmSpec -Key "resourcepool" -Obj ($vm | Get-ResourcePool) -IncludeType @("^VMware.*") -ExcludePath @(
            "^resourcepool.ExtensionData",
            "^resourcepool.CustomFields",
            "^resourcepool.Parent"
        )

        $vmSpec
    }
}

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
        $failed = @()
        $completed = @()

        $snapshots | ForEach-Object {
            $snapshot = $_

            Write-Information ("Removing snapshot: " + $snapshot.Name)
            try {
                $snapshot | Remove-Snapshot -Confirm:$false | Out-Null
                $completed += $snapshot
            } catch {
                Write-Information "Failed to remove snapshot: $_"
                $failed += $snapshot
            }
        }

        # Log a notification for the removed snapshots
        if (($completed | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Snapshots removed" -ScriptBlock {
                Write-Information "Removed snapshots:"
                Write-Information ($completed | Format-Table VM,Name,Created,SizeGB | Out-String)
            }
        }

        # Notification for any failed snapshots
        if (($failed | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Snapshots failed to remove" -ScriptBlock {
                Write-Information "Failed to remove snapshots:"
                Write-Information ($failed | Format-Table VM,Name,Created,SizeGB | Out-String)
            }
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
        $failed = @()
        $completed = @()

        $vms | ForEach-Object {
            $vm = $_

            # Do nothing if this VM doesn't require consolidation
            if (!$vm.ExtensionData.Runtime.ConsolidationNeeded)
            {
                return
            }

            # Consolidate VM
            Write-Information ("Consolidating VM: " + $vm.Name)
            try {
                $vm.ExtensionData.ConsolidateVMDisks()
                $completed += $vm
            } catch {
                Write-Information "Failed to consolidate VM: $_"
                $failed += $vm
            }
        }

        # Log a notification for consolidated VMs
        if (($completed | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "VMs Consolidated" -ScriptBlock {
                Write-Information "VMs consolidated:"
                Write-Information ($completed | Format-Table -Property Name | Out-String)
            }
        }

        # Log a message for VMs failed to consolidate
        if (($failed | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "VMs Failed Consolidation" -ScriptBlock {
                Write-Information "VMs Failed Consolidation:"
                Write-Information ($failed | Format-Table -Property Name | Out-String)
            }
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

            # Generate a failed login summary
            $summary = Get-VIEvent -Server $server -Start $start -MaxSamples $MaxSamples | Where-Object {
                ($_ -is "VMware.Vim.EventEx" -and $_.EventTypeId -eq "com.vmware.sso.LoginFailure") -or
                ($_ -is "Vmware.Vim.BadUsernameSessionEvent")
            } | Group-Object -Property UserName | ForEach-Object {
                [PSCustomObject]@{
                    Count = $_.Count
                    UserName = $_.Group[0].UserName
                    Message = $_.Group[0].FullFormattedMessage
                }
            }

            # Display all failed logins
            Write-Information "Failed logins over the last $Agehours hours ($Server):"
            $summary | Format-Table -Property UserName,Count,Message

            # Identify users over the threshold
            $alertUsers = $summary | Where-Object { $_.Count -ge $FailureThreshold }

            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Failed logins over threshold ($FailureThreshold) over the last $Agehours hours ($Server):"
                $alertUsers | Format-Table -Property UserName,Count,Message
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
        [string[]]$Types = @("Error", "Warning"),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$GroupMessage = $false
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
                if ($GroupMessage)
                {
                    $events | Group-Object -Property FullFormattedMessage | ForEach-Object {
                        [PSCustomObject]@{
                            Count = $_.Count
                            Message = $_.Name
                        }
                    } | Format-Table Count,Message | Out-String -Width 300
                } else {
                    $events | ForEach-Object {
                        [PSCustomObject]@{
                            Time = $_.CreatedTime
                            Message = $_.FullFormattedMessage
                        }
                    } | Format-Table -Property Time,Message | Out-String -Width 300
                }
            }

            # Send a notification if there are any events
            if (($events | Measure-Object).Count -gt 0)
            {
                New-Notification -Title "vCenter events over the last $AgeHours hours ($Server)" -Body ($capture.ToString())
            }
        }
    }
}

Register-Automation -Name vmware.vm_compare_config -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vms,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckPath,

        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [string[]]$IgnoreFilter = @()
    )

    process
    {
        # For each VM, capture the current configuration
        # and compare against the existing configuration
        # on disk, if any

        $vms | ForEach-Object {
            $vm = $_

            # Capture current VM configuration
            Write-Information "Capturing VM configuration for $vm"
            $spec = Get-VMSpec -VM $vm

            # Remove any keys that match an ignore filter
            # Duplicate the key list before removing keys from the dictionary
            $specKeys = $spec.Keys | ForEach-Object { $_ }
            $specKeys | ForEach-Object {
                $key = $_

                if (($IgnoreFilter | Where-Object { $key -match $_ } | Measure-Object).Count -gt 0)
                {
                    $spec.Remove($key)
                }
            }

            $current = $spec.Keys | ForEach-Object { "{0} = {1}" -f $_, $spec[$_] } | Sort-Object

            # Read any existing configuration
            $path = [System.IO.Path]::Combine($CheckPath, $vm.Name + ".txt")
            if (Test-Path $path)
            {
                $content = Get-Content -Encoding UTF8 $path

                # Compare configurations
                $existingCfg = [System.Collections.Generic.HashSet[string]]::New()
                $newCfg = [System.Collections.Generic.HashSet[string]]::New()

                $content | ForEach-Object { $existingCfg.Add($_) | Out-Null }
                $current | ForEach-Object { $newCfg.Add($_) | Out-Null }

                # Capture common configuration
                $common = [System.Collections.Generic.HashSet[string]]::New($existingCfg)
                $common.IntersectWith($newCfg)

                # Determine differences
                $newCfg.ExceptWith($common)
                $existingCfg.ExceptWith($common)

                if ($newCfg.Count -gt 0 -or $existingCfg.Count -gt 0)
                {
                    $capture = New-Capture
                    Invoke-CaptureScript -Capture $capture -ScriptBlock {
                        Write-Information "VM configuration differences identified ($vm)"
                        Write-Information ""
                        Write-Information "Old Values:"
                        $existingCfg
                        Write-Information ""

                        Write-Information "New Values:"
                        $newCfg
                        Write-Information ""
                    }

                    New-Notification -Title "VM Configuration Differences ($vm)" -Body ($capture.ToString())

                } else {
                    Write-Information "No differences"
                }

            } else {
                Write-Information "No existing configuration"
            }

            # Save the current configuration to file
            Write-Information "Saving configuration"
            $current | Out-File -Encoding UTF8 $path
        }
    }
}

Register-Automation -Name vmware.vmtools_check -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vms
    )

    process
    {
        # Collect a list of the VMs that are no 'toolsOk'

        $vmMatch = $vms | Select-Object Name,PowerState,@{
            N="ToolsStatus"
            E={ $_.Guest.ExtensionData.ToolsStatus }
        } | Where-Object {
            $_.ToolsStatus -ne 'toolsOk' -and $_.PowerState -eq 'PoweredOn'
        } | Sort-Object -Property Name

        if (($vmMatch | Measure-Object).Count -gt 0)
        {
            # Found some VMs that are not 'toolsOk'
            $capture = new-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "VMs with missing or old VMware Tools installs identified"
                Write-Information ""
                $vmMatch | Format-Table -Property Name,ToolsStatus | Out-String -Width 300
            }

            New-Notification -Title "VMs with missing or old VMTools" -Body ($capture.ToString())
        }

    }
}

Register-Automation -Name vmware.vmhost_compliance -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vmhosts,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$TestCompliance = $false
    )

    process
    {
        # If required, test compliance for the hosts
        if ($TestCompliance)
        {
            Write-Information "Running compliance check against hosts"
            try {
                $vmhosts | Test-Compliance
            } catch {
                New-Notification -Title "Failed host compliance update" -Body ($_ | Out-String)
            }
        }

        # Collect compliance information for all vmhosts
        Write-Information "Collecting compliance information"
        $compliance = $vmhosts | Get-Compliance -Detailed

        # Organise compliance by host, baseline and patches
        Write-Information "Formatting compliance information"
        $compliance = $compliance | ForEach-Object {
            $obj = [PSCustomObject]@{
                Entity = $_.Entity.Name | Out-String -NoNewline
                Status = $_.Status | Out-String -NoNewline
                Baseline = $_.Baseline.Name | Out-String -NoNewline
                NotCompliantPatches = "N/A"
                StagedPatches = "N/A"
            }

            if (($_ | Get-Member).Name -contains "NotCompliantPatches")
            {
                $obj.NotCompliantPatches = ($_.NotCompliantPatches | Measure).Count | Out-String -NoNewline
            }

            # Staged patches don't appear as 'NotCompliantPatches', so separate column for these
            if (($_ | Get-Member).Name -contains "StagedPatches")
            {
                $obj.StagedPatches = ($_.StagedPatches | Measure).Count | Out-String -NoNewline
            }

            $obj
        }

        # Display host compliance status
        $capture = New-Capture
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Host compliance status"
            Write-Information ""
            $compliance | Format-Table -Wrap | Out-String -Width 300
        }

        New-Notification -Title "Host compliance state" -Body ($capture.ToString())
    }
}

 
