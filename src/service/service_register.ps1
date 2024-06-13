<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("present", "absent")]
    [string]$State
)

# Global Settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

try { $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText } catch {}

# Global Vars
$serviceRoot = "C:\svc"
$taskName = "Auto-$ServiceName"

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
    param()

    process
    {
        Write-Information "Enabling scheduled task: $taskName"

        # Actions for the scheduled task
        $actions = @(
            $actionParams = @{
                Execute = "pwsh.exe"
                Argument = "-NoProfile C:\svc\service_call.ps1 -ServiceName $ServiceName"
                WorkingDirectory = $serviceRoot
            }
            New-ScheduledTaskAction @actionParams
        )

        # Triggers for the scheduled task
        # Need to call the schedule.ps1 script to collect triggers for the scheduled task
        $triggers = & "$serviceRoot\$serviceName\schedule.ps1"

        $triggers | ForEach-Object {
            if ($null -eq $_ -or $_.GetType().FullName -ne "Microsoft.Management.Infrastructure.CimInstance" -or
                $_.CimClass.CimSuperClass.ToString() -ne "ROOT/Microsoft/Windows/TaskScheduler:MSFT_TaskTrigger")
            {
                Write-Error "Invalid object returned from the service schedule.ps1 script"
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
    "present" {
        Enable-Schedule
    }
    "absent" {
        Remove-Schedule
    }
    default {
        Write-Error "Unknown action supplied: $State"
    }
}
