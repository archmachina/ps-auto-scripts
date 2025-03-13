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

Function Convert-StringNewLine
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
            $Dict[$Key] = $Obj | Out-String | Convert-StringNewLine -Replacement " "

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
        $Dict[$Key] = $Obj | Out-String | Convert-StringNewLine -Replacement " "
    }
}

Function Get-VMSpec
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
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
                $obj.NotCompliantPatches = ($_.NotCompliantPatches | Measure-Object).Count | Out-String -NoNewline
            }

            # Staged patches don't appear as 'NotCompliantPatches', so separate column for these
            if (($_ | Get-Member).Name -contains "StagedPatches")
            {
                $obj.StagedPatches = ($_.StagedPatches | Measure-Object).Count | Out-String -NoNewline
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

Register-Automation -Name vmware.vm_uptime_check -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vms,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$LowThreshold = 3,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$HighThreshold = 365
    )

    process
    {
        # Make sure thresholds are positive
        $HighThreshold = [Math]::Abs($HighThreshold)
        $LowThreshold = [Math]::Abs($LowThreshold)

        # For each VM, get the current uptime
        $records = $vms | ForEach-Object {
            $vm = $_

            $uptime = $vm | Get-Stat -MaxSamples 1 -Realtime -Stat "sys.osuptime.latest" -EA Ignore

            if ($null -ne $uptime)
            {
                [PSCustomObject]@{
                    Name = $vm.Name
                    UptimeDays = ([Math]::Round($uptime.Value / 60 / 60 / 24, 2))
                }
            }
        }

        # Reporting on VMs with low uptime
        $lowRecords = $records | Where-Object { $_.UptimeDays -lt $LowThreshold }
        if (($lowRecords | Measure-Object).Count -gt 0)
        {
            # Display Low records
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Hosts recently restarted"
                Write-Information ""
                $lowRecords | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Hosts recently restarted" -Body ($capture.ToString())
        }

        # Reporting on VMs with high uptime
        $highRecords = $records | Where-Object { $_.UptimeDays -gt $HighThreshold }
        if (($highRecords | Measure-Object).Count -gt 0)
        {
            # Display High records
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Hosts with high uptime"
                Write-Information ""
                $highRecords | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Hosts with high uptime" -Body ($capture.ToString())
        }
    }
}

Register-Automation -Name vmware.offline_vms -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vms,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [string[]]$IgnoreFilter = @()
    )

    process
    {
        # Filter for offline VMs
        $offline = $vms | Where-Object {
            $_.PowerState -ne "PoweredOn"
        } | ForEach-Object {
            $vm = $_

            # Find filters that match the VM name
            $result = $IgnoreFilter | Where-Object {
                $vm.Name -match $_
            }

            # Pass the VM on in the pipeline, if there was no match
            if (($result | Measure-Object).Count -eq 0)
            {
                $vm
            }
        }

        # Reporting on offline VMs
        if (($offline | Measure-Object).Count -gt 0)
        {
            # Display offline VMs
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Offline VMs"
                Write-Information ""
                $offline | Format-Table -Property Name,PowerState -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Offline VMs" -Body ($capture.ToString())
        }
    }
}

Register-Automation -Name vmware.vmhost_time_check -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vmhosts,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$ThresholdSec = 30
    )

    process
    {
        # Get an ESXCLI interface for each of the VMs
        Write-Information "Getting ESXCLI interfaces for vmhosts"
        $interfaces = $vmhosts | ForEach-Object {
            [PSCustomObject]@{
                vmhost = $_
                cli = $_ | Get-EsxCli -V2
            }
        }

        # Get the time for each ESXi host
        Write-Information "Collecting host time skew data"
        $records = $interfaces | ForEach-Object {
            $hostTime = [DateTime]::Parse($_.cli.system.time.get.Invoke()).ToUniversalTime()
            $clientTime = [DateTime]::UtcNow

            # Create a record representing the host and skew
            [PSCustomObject]@{
                Name = $_.vmhost.Name
                SkewSeconds = ($hostTime - $clientTime).TotalSeconds
            }
        }

        # Display host skew information for logs
        $records | Format-Table | Out-String -Width 300

        # Filter for records over the threshold
        Write-Information "Filtering for hosts with time skew"
        $skewed = $records | Where-Object {
            [Math]::Abs($_.SkewSeconds) -gt $ThresholdSec
        }

        # Reporting on skewed hosts
        if (($skewed | Measure-Object).Count -gt 0)
        {
            # Display skewed hosts
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Hosts with time skew"
                Write-Information ""
                $skewed | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Hosts with time skew" -Body ($capture.ToString())
        }
    }
}

Function Get-VMwareEntityStat
{
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        $Entity,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$AgeHours,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Stat,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$Realtime = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$IntervalMins = 5,

        [Parameter(Mandatory=$false)]
        $MissingValue = $null
    )

    process
    {
        # Collect stats information for the entity
        $params = @{
            Stat = $Stat
            Start = ([DateTime]::Now.AddHours(-($AgeHours)))
            Realtime = $Realtime
            IntervalMins = $IntervalMins
            ErrorAction = "Ignore"
        }
        $statRecords = $Entity | Get-Stat @params

        # Result object
        $result = [PSCustomObject]@{
            Name = $Entity.Name
            Stats = $statRecords
            Minimum = $MissingValue
            Average = $MissingValue
            Maximum = $MissingValue
        }

        # Extract summary information from the stats
        if ($null -ne $statRecords)
        {
            $summary = ($statRecords | Measure-Object -Maximum -Average -Minimum -Property Value)

            $result.Minimum = [Math]::Round($summary.Minimum, 2)
            $result.Average = [Math]::Round($summary.Average, 2)
            $result.Maximum = [Math]::Round($summary.Maximum, 2)
        }

        # Pass on the result object
        $result
    }
}

Register-Automation -Name vmware.vm_latency -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vms,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Nullable[int]]$ThresholdAvgMs = $null,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Nullable[int]]$ThresholdMaxMs = $null,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 1
    )

    process
    {
        # Check input values
        if ($null -ne $ThresholdMaxMs)
        {
            $ThresholdMaxMs = [Math]::Abs($ThresholdMaxMs)
        }

        if ($null -ne $ThresholdAvgMs)
        {
            $ThresholdAvgMs = [Math]::Abs($ThresholdAvgMs)
        }

        $AgeHours = [Math]::Abs($AgeHours)

        # For each VM, retrieve the disk latency
        $records = $vms | Get-VMwareEntityStat -AgeHours $AgeHours -Stat "disk.maxTotalLatency.latest" -MissingValue 0

        # Record VM latency for logs
        Write-Information "VM latency"
        $records | Format-Table -Wrap -Property Name,Average,Maximum | Out-String -Width 300

        # Reporting on VMs with high uptime
        $highRecords = $records | Where-Object {
            # Average is above the threshold OR
            ($null -ne $ThresholdAvgMs -and $_.Average -gt $ThresholdAvgMs) -or

            # Max is above the threshold
            ($null -ne $ThresholdMaxMs -and $_.Maximum -gt $ThresholdMaxMs)
        }

        # Display notification for high latency records
        if (($highRecords | Measure-Object).Count -gt 0)
        {
            # Display High records
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "VMs with high latency"
                Write-Information ""
                Write-Information "Average latency threshold: $ThresholdAvgMs"
                Write-Information "Maximum latency threshold: $ThresholdMaxMs"
                Write-Information ""
                $highRecords | Format-Table -Wrap -Property Name,Average,Maximum | Out-String -Width 300
            }

            New-Notification -Title "VMs with high disk latency" -Body ($capture.ToString())
        }
    }
}


Register-Automation -Name vmware.vmhost_latency -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        $vmhosts,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Nullable[int]]$ThresholdAvgMs = $null,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Nullable[int]]$ThresholdMaxMs = $null,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 1
    )

    process
    {
        # Check input values
        if ($null -ne $ThresholdMaxMs)
        {
            $ThresholdMaxMs = [Math]::Abs($ThresholdMaxMs)
        }

        if ($null -ne $ThresholdAvgMs)
        {
            $ThresholdAvgMs = [Math]::Abs($ThresholdAvgMs)
        }

        $AgeHours = [Math]::Abs($AgeHours)

        # For each VMHost, retrieve the disk latency
        $records = $vmhosts | Get-VMwareEntityStat -AgeHours $AgeHours -Stat "disk.maxTotalLatency.latest" -MissingValue 0

        # Record VMHost latency for logs
        Write-Information "VMHost latency"
        $records | Format-Table -Wrap -Property Name,Average,Maximum | Out-String -Width 300

        # Reporting on VMHosts with high uptime
        $highRecords = $records | Where-Object {
            # Average is above the threshold OR
            ($null -ne $ThresholdAvgMs -and $_.Average -gt $ThresholdAvgMs) -or

            # Max is above the threshold
            ($null -ne $ThresholdMaxMs -and $_.Maximum -gt $ThresholdMaxMs)
        }

        # Display notification for high latency records
        if (($highRecords | Measure-Object).Count -gt 0)
        {
            # Display High records
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "VMHosts with high latency"
                Write-Information ""
                Write-Information "Average latency threshold: $ThresholdAvgMs"
                Write-Information "Maximum latency threshold: $ThresholdMaxMs"
                Write-Information ""
                $highRecords | Format-Table -Wrap -Property Name,Average,Maximum | Out-String -Width 300
            }

            New-Notification -Title "VMHosts with high disk latency" -Body ($capture.ToString())
        }
    }
}

Register-Automation -Name vmware.vcenter_patch_check -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string[]]$Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$IgnorePriority = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$IgnoreSeverity = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$IgnoreType = @()
    )

    process
    {
        $failed = @()

        # Retrieve information on all updates
        $allUpdates = $Servers | ForEach-Object {
            $server = $_

            Write-Information "Checking vCenter patches for: $server"
            try {
                # Retrieve pending updates
                $pending = Get-CisService -Server $server -Name com.vmware.appliance.update.pending
                $updates = $pending.list("LOCAL_AND_ONLINE")
            } catch {
                $err = $_

                # An exception is generated when no updates are found
                if ([string]$err -like "*no_updates_found*")
                {
                    # Don't record this as an error
                    return
                }

                Write-Information "Failed to list updates for $server"
                $failed += [PSCustomObject]@{
                    Server = $server
                    Failure = [string]$err
                }

                return
            }

            # Transform update objects
            $updates | ForEach-Object {
                $obj = [ordered]@{
                    Server = $server
                }

                if (($_ | Get-Member).Name -contains "Name")
                {
                    $obj["Name"] = $_.Name
                }

                $obj["Version"] = $_.version

                $obj["Priority"] = $_.priority
                $obj["Severity"] = $_.severity

                $obj["UpdateType"] = $_.update_type
                $obj["Reboot"] = $_.reboot_required
                $obj["Released"] = $_.release_date
                $obj["Size"] = $_.size

                [PSCustomObject]$obj
            }
        }

        # Log a notification for any failed servers
        if (($failed | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Failures listing appliance updates"
                $failed | Format-Table -Wrap | Out-String -Width 300
            }
            New-Notification -Title "Failure retrieving appliance updates" -Body ($capture.ToString())
        }

        # Filter updates
        $allUpdates = $allUpdates | Where-Object {
            $_.Priority -notin $IgnorePriority
        } | Where-Object {
            $_.Severity -notin $IgnoreSeverity
        } | Where-Object {
            $_.UpdateType -notin $IgnoreType
        }

        # Notify of available updates
        if (($allUpdates | Measure-Object).Count -gt 0)
        {
            Write-Information "Found pending vCenter patches"

            $groups = $allUpdates | Group-Object -Property Server

            $groups | ForEach-Object {
                $group = $_

                $name = $group.Group[0].Server

                $capture = New-Capture
                Invoke-CaptureScript -Capture $capture -ScriptBlock {
                    Write-Information "Updates for vCenter appliance: $name"
                    $group.Group | Sort-Object -Property Released -Descending | Format-Table -Wrap | Out-String -Width 300
                }
                New-Notification -Title "Updates for vCenter appliance: $name" -Body ($capture.ToString())
            }
        } else {
            Write-Information "No pending vCenter patches found"
        }
    }
}

Register-Automation -Name vmware.vm_top_usage -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $vms,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 1,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$Cpu = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$Memory = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$Disk = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$Network = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$TopCount = 10,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$IntervalMins = 5
    )

    process
    {
        # Check input values
        $AgeHours = [Math]::Abs($AgeHours)
        $TopCount = [Math]::Abs($TopCount)

        # Report on top CPU usage
        if ($Cpu)
        {
            # Collect records
            Write-Information "Collecting CPU usage stats"
            $records = $vms |
                Get-VMwareEntityStat -AgeHours $AgeHours -Stat "cpu.usagemhz.average" -IntervalMins $IntervalMins |
                Sort-Object -Property Average -Descending |
                Select-Object -First $TopCount

            # Display top usage
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Top CPU Usage (MHz)"
                Write-Information ""
                $records |
                    Select-Object -Property Name,@{N="Average";E={ $_.Average.ToString("0.00") }} |
                    Format-Table -Wrap -Property Name,Average | Out-String -Width 300
            }

            New-Notification -Title "Top CPU Usage (MHz)" -Body ($capture.ToString())
        }

        # Report on top disk usage
        if ($Disk)
        {
            # Collect records
            Write-Information "Collecting disk usage stats"
            $records = $vms |
                Get-VMwareEntityStat -AgeHours $AgeHours -Stat "disk.usage.average" -IntervalMins $IntervalMins |
                Sort-Object -Property Average -Descending |
                Select-Object -First $TopCount

            # Display top usage
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Top Disk Usage (KBps)"
                Write-Information ""
                $records |
                    Select-Object -Property Name,@{N="Average";E={ $_.Average.ToString("0.00") }} |
                    Format-Table -Wrap -Property Name,Average | Out-String -Width 300
            }

            New-Notification -Title "Top Disk Usage (KBps)" -Body ($capture.ToString())
        }

        # Report on top memory usage
        if ($Memory)
        {
            # Collect records
            Write-Information "Collecting memory usage stats"
            $records = $vms |
                Get-VMwareEntityStat -AgeHours $AgeHours -Stat "mem.consumed.average" -IntervalMins $IntervalMins |
                Sort-Object -Property Average -Descending |
                Select-Object -First $TopCount

            # Display top usage
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Top Memory Usage (MB)"
                Write-Information ""
                $records |
                    Select-Object -Property Name,@{N="Average";E={ ($_.Average / 1024).ToString("0.00") }} |
                    Format-Table -Wrap -Property Name,Average | Out-String -Width 300
            }

            New-Notification -Title "Top Memory Usage (MB)" -Body ($capture.ToString())
        }

        # Report on top network usage
        if ($Network)
        {
            # Collect records
            Write-Information "Collecting network usage stats"
            $records = $vms |
                Get-VMwareEntityStat -AgeHours $AgeHours -Stat "net.usage.average" -IntervalMins $IntervalMins |
                Sort-Object -Property Average -Descending |
                Select-Object -First $TopCount

            # Display top usage
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Top Network Usage (KBps)"
                Write-Information ""
                $records |
                    Select-Object -Property Name,@{N="Average";E={ $_.Average.ToString("0.00") }} |
                    Format-Table -Wrap -Property Name,Average | Out-String -Width 300
            }

            New-Notification -Title "Top Network Usage (KBps)" -Body ($capture.ToString())
        }
    }
}

