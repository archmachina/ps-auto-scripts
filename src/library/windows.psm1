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
Import-Module $PSScriptRoot\common.psm1
Import-Module AutomationUtils

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
        [string[]]$Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)
        $ageSearch = $AgeHours * 60 * 60 * 1000

        # XPath string
        $xPath = "*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= {0}]]]" -f $ageSearch
        Write-Information "XPath string: $xPath"

        # Get event logs that match the xpath search in Security
        $result = Get-WinEventServer -Servers $Servers -LogName Security -Filter $xPath
        $events = $result.Events

        # Notification for any failed servers
        if (($result.Failures | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Server log query failed"
                $result.Failures | Format-Table -Wrap | Out-String -Width 300
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

Register-Automation -Name active_directory.failed_logins -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$GroupResults = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$UserIgnore = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$Threshold = 3
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)
        $ageSearch = $AgeHours * 60 * 60 * 1000

        # XPath string
        $xPath = "*[System[band(Keywords,4503599627370496) and (EventID=4625 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= {0}]]]" -f $ageSearch
        Write-Information "XPath string: $xPath"

        # Get event logs that match the xpath search in Security
        $result = Get-WinEventServer -Servers $Servers -LogName Security -Filter $xPath
        $events = $result.Events

        # Notification for any failed servers
        if (($result.Failures | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Server log query failed"
                $result.Failures | Format-Table -Wrap | Out-String -Width 300
            }
        }

        # Transform records
        $records = $events | ForEach-Object {
            $record = $_

            switch ($record.Id)
            {
                4771 {
                    [PSCustomObject]@{
                        Time = $record.TimeCreated
                        User = $record.Properties[0].Value
                        Domain = ""
                        Workstation = ""
                        Address = $record.Properties[6].Value
                        Method = "Kerberos"
                        LogonType = ""
                    }

                    break
                }
                4625 {
                    [PSCustomObject]@{
                        Time = $record.TimeCreated
                        User = $record.Properties[5].Value
                        Domain = $record.Properties[6].Value
                        Workstation = $record.Properties[13].Value
                        Address = $record.Properties[19].Value
                        Method = $record.Properties[12].Value
                        LogonType = $record.Properties[10].Value
                    }

                    break
                }
            }
        }

        # Ignore users that match the ignore filter
        $records = $records | ForEach-Object {
            $record = $_

            foreach ($item in $UserIgnore)
            {
                if ($record.User -match $item)
                {
                    return
                }
            }

            $record
        }

        # Group results and provide a count of the number of failed logins, if requested
        if ($GroupResults)
        {
            $records = $records | Group-Object -Property User,Domain,Workstation,Address,Method | ForEach-Object {
                [PSCustomObject]@{
                    FailureCount = $_.Count
                    User = $_.Group[0].User
                    Domain = $_.Group[0].Domain
                    Workstation = $_.Group[0].Workstation
                    Address = $_.Group[0].Address
                    Method = $_.Group[0].Method
                    LogonType = $_.Group[0].LogonType
                }
            } | Where-Object {
                # Apply the threshold filter to the grouping
                $_.FailureCount -ge $Threshold
            }

        }

        # Report for logs
        Write-Information ("Found {0} failed login logs" -f ($records | Measure-Object).Count)

        # Notification for any failed logins
        if (($records | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information ("Found {0} failed logins" -f ($records | Measure-Object).Count)
                $records | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Failed logins" -Body ($capture.ToString())
        }
    }

}

Register-Automation -Name active_directory.os_check -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Server = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$Ignore = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string[]]$Deprecated = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Filter = "*",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$Summary = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeDays = 45
    )

    process
    {
        # Make sure AgeDays is positive
        $AgeDays = [Math]::Abs($AgeDays)

        # Parameters for the AD computer query
        $getParams = @{
            Filter = $Filter
            Properties = @("OperatingSystem", "LastLogonDate", "Enabled")
        }

        if (![string]::IsNullOrEmpty($Server))
        {
            $getParams["Server"] = $Server
        }

        if (![string]::IsNullOrEmpty($SearchBase))
        {
            $getParams["SearchBase"] = $SearchBase
        }

        # Get a list of the in-scope systems
        $systems = Get-ADComputer @getParams | Where-Object {
            # Filter for machines that have logged on to the domain with the last 'AgeDays' days
            $_.LastLogonDate -gt ([DateTime]::Now.AddDays(-($AgeDays)))
        } | Where-Object {
            # Only report on machines that are enabled
            $_.Enabled
        } | Sort-Object -Property OperatingSystem

        # Filter out systems based on ignore lists
        # Ignore is processed before anything else, so anything ignored won't appear
        # as deprecated or in anything
        $systems = $systems | ForEach-Object {
            $system = $_
            if (($Ignore | Where-Object { $system.OperatingSystem -match $_ } | Measure-Object).Count -eq 0)
            {
                $system
            }
        }

        # Are we reporting on deprecated operating systems
        # This will just change the title of the notification
        $deprecatedReport = $false
        if (($Deprecated | Measure-Object).Count -gt 0)
        {
            $deprecatedReport = $true
        }

        # Filter for anything deprecated
        if ($deprecatedReport)
        {
            $systems = $systems | ForEach-Object {
                $system = $_
                if (($Deprecated | Where-Object { $system.OperatingSystem -match $_ } | Measure-Object).Count -gt 0)
                {
                    $system
                }
            }
        }

        # Title for the generated notification. Summary or not and deprecated or not.
        $title = ""
        if ($deprecatedReport)
        {
            $title = "Deprecated "
        }

        $title += "Operating Systems"

        if ($Summary)
        {
            $title += " Summary"
        }

        # Generate the notification
        $capture = New-Capture
        if ($Summary) {
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information $title
                $systems | Group-Object -Property OperatingSystem | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        Count = ($_.Group | Measure-Object).Count
                    }
                } | Format-Table -Wrap | Out-String -Width 300
            }
        } else {
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information $title
                $systems | Format-Table -Property Name,OperatingSystem -Wrap | Out-String -Width 300
            }
        }

        New-Notification -Title $title -Body ($capture.ToString())
    }
}

Register-Automation -Name active_directory.account_management_events -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int[]]$Add = @(),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int[]]$Remove = @()
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)
        $ageSearch = $AgeHours * 60 * 60 * 1000

        # Event IDs for account related activities
        $eventids = [System.Collections.Generic.HashSet[int]]::New()
        @(
            # User Management
            4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4780, 4781, 4794, 5376, 5377,

            # Computer Management
            4741, 4742, 4743,

            # Security Group Management
            4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764
        ) | ForEach-Object { $eventids.Add($_) | Out-Null }

        # Process any Adds
        $Add | ForEach-Object { $eventids.Add($_) | Out-Null }

        # Process any Removes
        $Remove | ForEach-Object { $eventids.Remove($_) | Out-Null }

        # Split the events in to batches of 10 as xpath filter fails on large queries
        $batches = @{}
        $count = 0
        foreach ($item in $eventids)
        {
            $index = [int]([Math]::Floor($count/10))
            if (!$batches.ContainsKey($index))
            {
                $batches[$index] = @()
            }

            $batches[$index] += $item
            $count++
        }

        # Query using each batch
        $results = $batches.Values | ForEach-Object {
            $batch =  $_

            # Filter string for the event ids
            $eventFilter = (($batch | ForEach-Object { "EventID=" + $_ }) -join " or ")

            # XPath string
            $xPath = "*[System[({0}) and TimeCreated[timediff(@SystemTime) <= {1}]]]" -f $eventFilter,$ageSearch
            Write-Information "XPath string: $xPath"

            # Get event logs that match the xpath search in Security
            Get-WinEventServer -Servers $Servers -LogName Security -Filter $xPath
        }

        # Flatten events and failures
        $events = $results |
            ForEach-Object { $_.Events } |
            ForEach-Object { $_ } |
            Sort-Object -Property TimeCreated
        $failures = $results |
            ForEach-Object { $_.Failures } |
            ForEach-Object { $_ } |
            Group-Object -Property Name,Error |
            ForEach-Object { $_.Group[0] }

        # Notification for any failed servers
        if (($failures | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Server log query failed"
                $failures | Format-Table -Wrap | Out-String -Width 300
            }
        }

        # Transform records
        $records = $events | ForEach-Object {
            $record = $_

            [PSCustomObject]@{
                Time = $record.TimeCreated
                Machine = $record.MachineName
                User = $record.UserId
                EventId = $record.Id
                Message = $record.Message
            }
        }

        # Report for logs
        Write-Information ("Found {0} records" -f ($records | Measure-Object).Count)

        # Notification for any account management events
        if (($records | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information ("Found {0} account management events" -f ($records | Measure-Object).Count)
                $records | Format-Table -Wrap | Out-String -Width 300
            }

            New-Notification -Title "Account Management Events" -Body ($capture.ToString())
        }
    }
}

Register-Automation -Name windows.service_restart_logs -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Servers,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 24,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$GroupResults = $false,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string[]]$ServiceFilter,

        [Parameter(Mandatory=$false)]
        [string]$ExecuteFrom = ""
    )

    process
    {
        # Make sure AgeHours is positive
        $AgeHours = [Math]::Abs($AgeHours)
        $ageSearch = $AgeHours * 60 * 60 * 1000

        # XPath string
        $xPath = "*[System[(EventID=7036) and TimeCreated[timediff(@SystemTime) <= {0}]]]" -f $ageSearch
        Write-Information "XPath string: $xPath"

        # Get event logs that match the xpath search in System
        $result = Get-WinEventServer -Servers $Servers -LogName System -Filter $xPath -ExecuteFrom $ExecuteFrom
        $events = $result.Events

        # Notification for any failed servers
        if (($result.Failures | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Failed server log query" -Script {
                Write-Information "Server log query failed"
                $result.Failures | Format-Table -Wrap | Out-String -Width 300
            }
        }

        # Transform records
        $records = $events | ForEach-Object {
            $record = $_

            switch ($record.Id)
            {
                7036 {
                    [PSCustomObject]@{
                        Machine = $record.MachineName
                        Time = $record.TimeCreated
                        Service = $record.Properties[0].Value
                        State = $record.Properties[1].Value
                    }

                    break
                }
            }
        }

        # Filter logs
        Write-Information ("Found {0} records before filter" -f ($records | Measure-Object).Count)
        $records = $records | ForEach-Object {
            $record = $_

            foreach ($filter in $ServiceFilter) {
                if ($record.Service -match $filter) {
                    $record
                    break
                }
            }
        }
        Write-Information ("{0} records after filter" -f ($records | Measure-Object).Count)

        # Group results and provide a count of the number of failed logins, if requested
        if ($GroupResults)
        {
            $records = $records | Group-Object -Property Machine,Service,State | ForEach-Object {
                [PSCustomObject]@{
                    Count = $_.Count
                    Machine = $_.Group[0].Machine
                    Service = $_.Group[0].Service
                    State = $_.Group[0].State
                }
            }
        }

        # Report for logs
        Write-Information ("Found {0} restart logs" -f ($records | Measure-Object).Count)

        # Notification for any restarts
        if (($records | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Restart logs" -Script {
                Write-Information ("Found {0} restart logs" -f ($records | Measure-Object).Count)
                $records | Format-Table -Wrap | Out-String -Width 300
            }
        }
    }
}

Register-Automation -Name windows.refresh_patch_task -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [HashTable]$Systems,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ThrottleLimit = 5,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$JobLimitSeconds = 60,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$TotalLimitSeconds = (60 * 5),

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Proxy = $null
    )

    process
    {
        # Create state objects for each system
        $states = $Systems.Keys | ForEach-Object {
            $system = [string]$_
            $config = [HashTable]$Systems[$system]

            $obj = @{
                System = $system
                Config = $config
                ScriptPath = ([System.IO.Path]::Combine($PSScriptRoot, "winupd_mgmt.ps1"))
                Proxy = $Proxy
                ReportSchedule = $null
                InstallSchedule = $null
                Completed = $false
                Error = $null
                InactiveSchedule = ([DateTime]::New(1990, 1, 1))
            }

            if ($config.Keys -contains "report_schedule")
            {
                $obj["ReportSchedule"] = [HashTable]$config["report_schedule"]
            }

            if ($config.Keys -contains "install_schedule")
            {
                $obj["InstallSchedule"] = [HashTable]$config["install_schedule"]
            }

            [PSCustomObject]$obj
        }

        # Process each system in the system list
        Write-Information "Scheduling patch install for systems"
        $parentJob = $states | ForEach-Object -Parallel {
            $state = $_

            # Script settings
            $ErrorActionPreference = "Stop"
            $InformationPreference = "Continue"
            Set-StrictMode -Version 2


            try {
                # Extract the config
                $config = $state.Config
                $system = $state.System

                # Create a new session for the target
                Write-Information "${system}: Creating PSSession"
                $session = New-PSSession -ComputerName $state.System

                # Ensure the _patching directory exists
                Write-Information "${system}: Creating _patching directory"
                Invoke-Command -Session $session -ScriptBlock {
                    New-Item -ItemType Directory "C:\_patching" -EA Ignore | Out-Null

                    Get-Item "C:\_patching" | Out-Null
                }

                # Copy the patching script to the target
                Write-Information "${system}: Copying script"
                Copy-Item -Force $state.ScriptPath "C:\_patching\" -ToSession $session

                # Configure the reporting scheduled task
                Write-Information "${system}: Creating report scheduled task"
                Invoke-Command -Session $session -ArgumentList $state -ScriptBlock {
                    param($state)

                    # Settings
                    $ErrorActionPreference = "Stop"
                    $InformationPreference = "Continue"
                    Set-StrictMode -Version 2

                    $argument = "-NonInteractive C:\_patching\winupd_mgmt.ps1 -UseCab"
                    if (![string]::IsNullOrEmpty($state.Proxy))
                    {
                        $argument += (" -Proxy " + $state.Proxy)
                    }
                    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument $argument

                    # Trigger to run the scheduled task
                    $trigger = @(
                        # Default trigger for something in the past - Set-ScheduledTask doesn't remove triggers when an
                        # empty trigger list is provided
                        New-ScheduledTaskTrigger -Once -At $state.InactiveSchedule
                    )

                    $report_schedule = $state.ReportSchedule
                    if ($null -ne $report_schedule)
                    {
                        $trigger = New-ScheduledTaskTrigger @report_schedule
                    }

                    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $task = New-ScheduledTask -Principal $principal -Action $action -Trigger $trigger

                    # Attempt to create the task, but ignore failure
                    Register-ScheduledTask -Taskname "SystemPatching - Report" -InputObject $task -EA Ignore | Out-Null

                    # Update settings for the scheduled task
                    Set-ScheduledTask -TaskName "SystemPatching - Report" -Trigger $trigger -Action $action -Principal $principal | Out-Null
                }

                # Configure the patching scheduled task
                Write-Information "${system}: Creating patch scheduled task"
                Invoke-Command -Session $session -ArgumentList $state -ScriptBlock {
                    param($state)

                    # Settings
                    $ErrorActionPreference = "Stop"
                    $InformationPreference = "Continue"
                    Set-StrictMode -Version 2

                    $argument = "-NonInteractive C:\_patching\winupd_mgmt.ps1 -Install -CanReboot -UseCab"
                    if (![string]::IsNullOrEmpty($state.Proxy))
                    {
                        $argument += (" -Proxy " + $state.Proxy)
                    }
                    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument $argument

                    # Trigger to run the scheduled task
                    $trigger = @(
                        # Default trigger for something in the past - Set-ScheduledTask doesn't remove triggers when an
                        # empty trigger list is provided
                        New-ScheduledTaskTrigger -Once -At $state.InactiveSchedule
                    )

                    $install_schedule = $state.InstallSchedule
                    if ($null -ne $install_schedule)
                    {
                        $trigger = New-ScheduledTaskTrigger @install_schedule
                    }

                    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $task = New-ScheduledTask -Principal $principal -Action $action -Trigger $trigger

                    # Attempt to create the task, but ignore failure
                    Register-ScheduledTask -Taskname "SystemPatching - Install" -InputObject $task -EA Ignore | Out-Null

                    # Update settings for the scheduled task
                    Set-ScheduledTask -TaskName "SystemPatching - Install" -Trigger $trigger -Action $action -Principal $principal | Out-Null
                }

                Write-Information "${system}: Completed patching task refresh"
                $state.Completed = $true

            } catch {
                Write-Information "${system}: Failed to apply patch task: $_"
                $state.Error = $_
            }

        } -ThrottleLimit $ThrottleLimit -AsJob

        # Process child jobs
        $start = [DateTime]::Now
        Write-Information "Processing child jobs"
        while ($true)
        {
            # Receive any child jobs
            $parentJob.ChildJobs | Where-Object {
                $null -ne $_.PSEndTime -and $_.HasMoreData
            } | ForEach-Object {
                $job = $_

                try {
                    Receive-Job $job
                } catch {
                    Write-Information "Exception from job: $_"
                    Write-Information $_.ScriptStackTrace
                }
            }

            # Stop any jobs that have taken too long (hung accessing a remote system?)
            $parentJob.ChildJobs | Where-Object {
                $null -ne $_.PSBeginTime -and
                $_.PSBeginTime -lt ([DateTime]::Now.AddSeconds(-$JobLimitSeconds)) -and
                $null -eq $_.PSEndTime
            } | ForEach-Object {
                Write-Information "Found stuck job"
                $_ | Format-List -Property Id,Name,PSBeginTime,PSEndTime,State,HasMoreData
                Stop-Job $_
            }

            # Stop all jobs if over the threshold
            if ([DateTime]::Now -gt $start.AddSeconds($TotalLimitSeconds))
            {
                Write-Information "Over threshold for time. Stopping jobs"
                Stop-Job $parentJob
                try {
                    Receive-Job $parentJob
                } catch {
                    Write-Information "Exception receiving parent job: $_"
                    Write-Information $_.ScriptStackTrace
                }
                break
            }

            # Remove the parent job if everything is finished
            if ($null -ne $parentJob.PSEndTime)
            {
                Write-Information "Parent job finished"
                try {
                    Receive-Job $parentJob
                } catch {
                    Write-Information "Exception receiving parent job: $_"
                    Write-Information $_.ScriptStackTrace
                }
                Remove-Job $parentJob
                break
            }

            # Wait for more jobs to complete
            Start-Sleep -Seconds 5
        }

        # Report on any failed systems
        $failed = $states | Where-Object { -not $_.Completed }
        if (($failed | Measure-Object).Count -gt 0)
        {
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Failed to apply patch task for systems:"
                $failed | Format-Table System,Completed,Error | Out-String -Width 300
            }
            New-Notification -Title "Failed to apply patch task" -Body ($capture.ToString())
        }

        # Display information for the logs
        Write-Information "Patch apply state:"
        $states | Format-Table -Property System,Completed,Error | Out-String -Width 300
    }
}

Register-Automation -Name windows.report_patch_state -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string[]]$Systems,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ThrottleLimit = 5,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$JobLimitSeconds = 60,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$TotalLimitSeconds = (60 * 5)
    )

    process
    {
        # Create state objects for each system
        $states = $Systems | ForEach-Object {
            $system = [string]$_

            $obj = @{
                System = $system
                PatchState = $null
                Completed = $false
                Error = $null
            }

            [PSCustomObject]$obj
        }

        # Process each system in the system list
        Write-Information "Checking patch state for systems"
        $parentJob = $states | ForEach-Object -Parallel {
            $state = $_

            # Script settings
            $ErrorActionPreference = "Stop"
            $InformationPreference = "Continue"
            Set-StrictMode -Version 2

            try {
                # Extract the config
                $system = $state.System

                # Create a new session for the target
                Write-Information "${system}: Creating PSSession"
                $session = New-PSSession -ComputerName $state.System

                # Make sure we have a recent state file
                $writeTime = Invoke-Command -Session $session -ScriptBlock {
                    (Get-Item "C:\_patching\state.json").LastWriteTime
                }

                if ($writeTime -lt ([DateTime]::Now.AddDays(-3)))
                {
                    Write-Error "${system}: Patching information is too old: $writeTime"
                }

                # Get patching state from the remote system
                $state.PatchState = Invoke-Command -Session $session -ScriptBlock {
                    Get-Content "C:\_patching\state.json"
                } | ConvertFrom-Json

                Write-Information "${system}: Completed patch state collection"
                $state.Completed = $true

            } catch {
                Write-Information "${system}: Failed to check patch state: $_"
                $state.Error = $_
            }

        } -ThrottleLimit $ThrottleLimit -AsJob

        # Process child jobs
        $start = [DateTime]::Now
        Write-Information "Processing child jobs"
        while ($true)
        {
            # Receive any child jobs
            $parentJob.ChildJobs | Where-Object {
                $null -ne $_.PSEndTime -and $_.HasMoreData
            } | ForEach-Object {
                $job = $_

                try {
                    Receive-Job $job
                } catch {
                    Write-Information "Exception from job: $_"
                    Write-Information $_.ScriptStackTrace
                }
            }

            # Stop any jobs that have taken too long (hung accessing a remote system?)
            $parentJob.ChildJobs | Where-Object {
                $null -ne $_.PSBeginTime -and
                $_.PSBeginTime -lt ([DateTime]::Now.AddSeconds(-$JobLimitSeconds)) -and
                $null -eq $_.PSEndTime
            } | ForEach-Object {
                Write-Information "Found stuck job"
                $_ | Format-List -Property Id,Name,PSBeginTime,PSEndTime,State,HasMoreData
                Stop-Job $_
            }

            # Stop all jobs if over the threshold
            if ([DateTime]::Now -gt $start.AddSeconds($TotalLimitSeconds))
            {
                Write-Information "Over threshold for time. Stopping jobs"
                Stop-Job $parentJob
                try {
                    Receive-Job $parentJob
                } catch {
                    Write-Information "Exception receiving parent job: $_"
                    Write-Information $_.ScriptStackTrace
                }
                break
            }

            # Remove the parent job if everything is finished
            if ($null -ne $parentJob.PSEndTime)
            {
                Write-Information "Parent job finished"
                try {
                    Receive-Job $parentJob
                } catch {
                    Write-Information "Exception receiving parent job: $_"
                    Write-Information $_.ScriptStackTrace
                }
                Remove-Job $parentJob
                break
            }

            # Wait for more jobs to complete
            Start-Sleep -Seconds 5
        }

        # Report on any failed systems
        $failed = $states | Where-Object { -not $_.Completed }
        if (($failed | Measure-Object).Count -gt 0)
        {
            Write-Information ""
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Failed to collect patch state for systems:"
                $failed | Format-Table System,Completed,Error | Out-String -Width 300
            }
            New-Notification -Title "Failed to collect patch state" -Body ($capture.ToString())
        }

        # Organise patches by patch
        Write-Information "Generating patch list"
        $parseFailure = @()
        $patchList = @{}
        $states | Where-Object { $null -ne $_.PatchState } | ForEach-Object {
            $state = $_
            $system = $state.System

            try {
                if ([DateTime]$state.PatchState.DateUtc -lt ([DateTime]::Now.AddDays(-3)))
                {
                    Write-Error ("Patch state is too stale: " + $state.PatchState.DateUtc.ToString("o"))
                }

                $state.PatchState.Updates | ForEach-Object {
                    $title = $_.Title

                    if ($title -notin $patchList.Keys)
                    {
                        $patchList[$title] = [PSCustomObject]@{
                            Title = $title
                            LastDeploymentChangeTime = $_.LastDeploymentChangeTime
                            Systems = @()
                        }
                    }

                    $patchList[$title].Systems += $system
                }
            } catch {
                Write-Information "Failed to parse patch information for ${system}: $_"
                $parseFailure += $system
            }
        }

        # Notify on systems failed parsing
        if (($parseFailure | Measure-Object).Count -gt 0)
        {
            Write-Information ""
            $capture = New-Capture
            Invoke-CaptureScript -Capture $capture -ScriptBlock {
                Write-Information "Parse failure:"
                $parseFailure
            }
            New-Notification -Title "Parse failure" -Body ($capture.ToString())
        }

        # Display summary by patch
        $capture = New-Capture
        Write-Information ""
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Summary by update:"
            $patchList.Values | Sort-Object -Property LastDeploymentChangeTime | ForEach-Object {
                [PSCustomObject]@{
                    Systems = ($_.Systems | Measure-Object).Count
                    Released = $_.LastDeploymentChangeTime
                    Update = (Split-StringLength -Str $_.Title -WrapLength 80 | Out-String).Trim()
                }
            } | Format-Table -Wrap | Out-String -Width 300
        }
        New-Notification -Title "Summary by update" -Body ($capture.ToString())

        # Display summary by system
        $capture = New-Capture
        Write-Information ""
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Summary by system:"
            $states | ForEach-Object {
                $obj = [PSCustomObject]@{
                    System = $_.System
                    Critical = 0
                    Important = 0
                    Moderate = 0
                    Low = 0
                    Other = 0
                    Total = 0
                    Oldest = $null
                }

                if ($null -ne $_.PatchState -and ($_.PatchState.Updates | Measure-Object).Count -gt 0)
                {
                    $obj.Critical = ($_.PatchState.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" } | Measure-Object).Count
                    $obj.Important = ($_.PatchState.Updates | Where-Object { $_.MsrcSeverity -eq "Important" } | Measure-Object).Count
                    $obj.Moderate = ($_.PatchState.Updates | Where-Object { $_.MsrcSeverity -eq "Moderate" } | Measure-Object).Count
                    $obj.Low = ($_.PatchState.Updates | Where-Object { $_.MsrcSeverity -eq "Low" } | Measure-Object).Count
                    $obj.Other = ($_.PatchState.Updates | Where-Object {
                        [string]::IsNullOrEmpty($_.MsrcSeverity) -or $_.MsrcSeverity -notin @("Critical", "Important", "Moderate", "Low")
                    } | Measure-Object).Count
                    $obj.Total = ($_.PatchState.Updates | Measure-Object).Count
                    $obj.Oldest = ($_.PatchState.Updates | Sort-Object -Property LastDeploymentChangeTime)[0].LastDeploymentChangeTime
                }

                $obj
            } | Sort-Object -Property System | Format-Table -Wrap | Out-String -Width 300
        }
        New-Notification -Title "Summary by system" -Body ($capture.ToString())

        # Display detail by patch
        $capture = New-Capture
        Write-Information ""
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Detail by update:"
            $patchList.Values | Sort-Object -Property LastDeploymentChangeTime | ForEach-Object {
                Write-Information ""
                Write-Information ("Title: " + $_.Title)
                Write-Information ("Date: " + $_.LastDeploymentChangeTime)
                Write-Information ("Systems: " + ($_.Systems -join ", "))
            }
        }
        New-Notification -Title "Detail by update" -Body ($capture.ToString())

        # Display detail by system
        $capture = New-Capture
        Write-Information ""
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Detail by system:"
            $states | ForEach-Object {
                Write-Information ""
                Write-Information ("System: " + $_.System)
                if ($null -ne $_.PatchState)
                {
                    $_.PatchState.Updates |
                        Sort-Object -Property LastDeploymentChangeTime |
                        Format-Table -HideTableHeaders -Property LastDeploymentChangeTime,Title
                }
            }
        }
        New-Notification -Title "Detail by system" -Body ($capture.ToString())
    }
}
