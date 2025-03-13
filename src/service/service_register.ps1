<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceRoot,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("present", "absent", "inactive")]
    [string]$State
)

# Global Settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

try { $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText } catch {}

# Global Vars
$taskName = "Auto-$ServiceName"
$serviceCall = ([System.IO.Path]::Combine($ServiceRoot, "service_call.ps1"))

$taskUser = $Env:TASK_USERNAME
if ([string]::IsNullOrEmpty($taskUser))
{
    Write-Error "Empty TASK_USERNAME environment variable"
}

$taskPass = $Env:TASK_PASSWORD
if ([string]::IsNullOrEmpty($taskPass))
{
    Write-Error "Empty TASK_PASSWORD environment variable"
}


Function Enable-Schedule
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [switch]$EnableTriggers = $false
    )

    process
    {
        Write-Information "Enabling scheduled task: $taskName"

        # Actions for the scheduled task
        $actions = @(
            $actionParams = @{
                Execute = "pwsh.exe"
                Argument = "-NoProfile -NonInteractive $serviceCall -ServiceRoot $ServiceRoot -ServiceName $ServiceName"
                WorkingDirectory = $ServiceRoot
            }
            New-ScheduledTaskAction @actionParams
        )

        # Default trigger list for the scheduled task
        # Set-ScheduledTask doesn't support an empty list for triggers, so the default is scheduled once in 1990.
        # The task scheduler also doesn't support [DateTime]::MinValue (too old?), but 1990 works.
        $triggers = @(
            New-ScheduledTaskTrigger -Once -At ([DateTime]::New(1990, 1, 1))
        )

        # Enable triggers for this scheduled task, if requested
        if ($EnableTriggers)
        {
            # Triggers for the scheduled task
            # Need to call the schedule.ps1 script to collect triggers for the scheduled task
            $triggers = & ([System.IO.Path]::Combine($ServiceRoot, $serviceName, "schedule.ps1"))

            Write-Information "Collecting trigger configuration for scheduled task"
            $triggers | ForEach-Object {
                if ($null -eq $_ -or $_.GetType().FullName -ne "Microsoft.Management.Infrastructure.CimInstance" -or
                    $_.CimClass.CimSuperClass.ToString() -ne "ROOT/Microsoft/Windows/TaskScheduler:MSFT_TaskTrigger")
                {
                    Write-Error "Invalid object returned from the service schedule.ps1 script"
                }
            }
        }

        # Get a list of all of the scheduled tasks
        $tasks = Get-ScheduledTask | ForEach-Object { $_.TaskName }

        # Create the task, if it doesn't exist
        if ($tasks -notcontains $taskName)
        {
            Write-Information "Registering task"

            $registerParams = @{
                TaskName = $taskName
                Action = $actions
                Trigger = $triggers
                RunLevel = "Highest"
                User = $taskUser
                Password = $taskPass
            }

            Register-ScheduledTask @registerParams | Out-Null
        } else {
            Write-Information "Task already exists"
        }

        # Update settings for the scheduled task
        Write-Information "Updating task settings"

        $setParams = @{
            TaskName = $taskName
            Action = $actions
            Trigger = $triggers
            User = $taskUser
            Password = $taskPass
        }
        Set-ScheduledTask @setParams | Out-Null

        Write-Information "Task Information:"
        Get-ScheduledTask -TaskName $taskName | Format-List -Property *
    }
}

Function Remove-Schedule
{
    [CmdletBinding()]
    param()

    process
    {
        Write-Information "Removing scheduled task: $taskName"

        # Get a list of all of the scheduled tasks
        $tasks = Get-ScheduledTask | ForEach-Object { $_.TaskName }

        # Remove the task, if it exists
        if ($tasks -contains $taskName)
        {
            Write-Information "Unregistering task"
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
        } else {
            Write-Information "Task not found"
        }
    }
}

switch ($State)
{
    "inactive" {
        Enable-Schedule
    }
    "present" {
        Enable-Schedule -EnableTriggers
    }
    "absent" {
        Remove-Schedule
    }
    default {
        Write-Error "Unknown action supplied: $State"
    }
}
