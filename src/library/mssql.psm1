<#
#>

[CmdletBinding()]
param()

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Modules
Import-Module AutomationUtils

# Global vars
$backupCheck = @"
WITH DBBackups AS (
    SELECT
        database_name,
        backup_start_date,
        type as backup_type,
        ROW_NUMBER() OVER (PARTITION BY database_name,type ORDER BY backup_start_date DESC) as rn
    FROM msdb.dbo.backupset as bs
    WHERE bs.is_copy_only = 0
)
SELECT
    sdb.name as database_name,
    sdb.state as state,
    sdb.state_desc as state_desc,
    sdb.recovery_model as recovery_model,
    sdb.recovery_model_desc as recovery_model_desc,
    dbb.backup_type as backup_type,
    dbb.backup_start_date as last_backup,
    getdate() as current_datetime
FROM sys.databases as sdb
LEFT JOIN DBBackups as dbb
    ON dbb.database_name = sdb.name AND
    rn = 1
"@

$jobCheck = @"
SELECT
    sj.name as job_name,
    sjh.step_name,
    sjh.run_status,
    sjh.message,
    msdb.dbo.agent_datetime(sjh.run_date, sjh.run_time) as run_datetime
FROM msdb.dbo.sysjobhistory as sjh
INNER JOIN msdb.dbo.sysjobs AS sj ON sj.job_id = sjh.job_id
WHERE
    sj.enabled = 1 AND
    --sjh.run_status in (0,2) AND
    msdb.dbo.agent_datetime(sjh.run_date, sjh.run_time) > DATEADD(HOUR, {0}, getdate())
ORDER BY run_datetime ASC
"@

$queryScript = {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandText
    )

    # Settings
    $ErrorActionPreference = "Stop"
    $InformationPreference = "Continue"
    Set-StrictMode -Version 2

    # Establish connection to the SQL instance
    Write-Information "Connecting to instance: $Name"
    $sqlconn = New-Object System.Data.SqlClient.SqlConnection
    $sqlconn.ConnectionString = $ConnectionString
    $sqlconn.Open()

    # Perform query against the instance
    $sqlcmd = $sqlconn.CreateCommand()
    $sqlcmd.CommandText = $CommandText
    $adp = New-Object System.Data.SqlClient.SqlDataAdapter $sqlcmd
    $data = New-Object System.Data.DataSet
    $records = $adp.Fill($data)
    Write-Information "Retrieved $records records"

    # Close the connection
    $sqlconn.Close()

    # Check for errors in the output
    if ($data.HasErrors)
    {
        Write-Error "DataSet has errors"
    }

    # Return an empty list, if there were no matching records
    if ($records -eq 0)
    {
        @()
        return
    }


    $data.Tables.Rows | ConvertTo-CSV
}


# Functions

Register-Automation -Name mssql.backup_check -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject[]]$Policies,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExecuteFrom = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ExcludeFilter = @("tempdb"),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$OnlineOnly = $true,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$StatusReport = $false
    )

    process
    {
        Write-Information "Connection: $Name"

        # Invoke command parameters
        $invokeArgs = @{
            ScriptBlock = $queryScript
            ArgumentList = $Name,$ConnectionString,$backupCheck
        }

        # Determine what machine to run the check from
        if ([string]::IsNullOrEmpty($ExecuteFrom))
        {
            Write-Information "Executing locally"
        } else {
            $invokeArgs["ComputerName"] = $ExecuteFrom
            Write-Information "Executing from $ExecuteFrom"
        }

        # Invoke check scripts
        $result = Invoke-Command @invokeArgs

        # Deserialise the database status
        $dbBackupRecords = $result | ConvertFrom-CSV

        # Convert the results to something easier to work with
        $dbBackupState = @{}
        $dbBackupRecords | ForEach-Object {
            $dbName = $_.database_name
            $dbState = $_

            # Exclude this database, if it matches a filter
            $filterMatches = $ExcludeFilter | Where-Object { $_ -match $dbName }
            if (($filterMatches | Measure-Object).Count -gt 0)
            {
                # Found a match for the database name, so finish here
                return
            }

            # Exclude the database, if it's not online and OnlineOnly is true
            if ($OnlineOnly -and $_.state -ne 0)
            {
                return
            }

            # Create a db state entry, if it doesn't already exist
            if (-not $dbBackupState.ContainsKey($dbName))
            {
                $dbBackupState[$dbName] = [PSCustomObject]@{
                    name = $dbName
                    recovery_model = $dbState.recovery_model_desc

                    last_log_date = $null
                    last_log_hours = $null

                    last_full_date = $null
                    last_full_hours = $null

                    policy_log_hours = $null
                    policy_full_hours = $null
                }
            }

            # Extract DateTime values
            $last_backup = $null
            if (![string]::IsNullOrEmpty($dbState.last_backup))
            {
                $last_backup = [DateTime]::Parse($dbState.last_backup)
            }
            $now = [DateTime]::Parse($dbState.current_datetime)

            # Extract specific types of backups
            switch ($_.backup_type)
            {
                "L" {
                    $dbBackupState[$dbName].last_log_date = $last_backup
                    if ($null -ne $last_backup)
                    {
                        $dbBackupState[$dbName].last_log_hours = [Math]::Round(($now - $last_backup).TotalHours, 2)
                    }
                }
                "D" {
                    $dbBackupState[$dbName].last_full_date = $last_backup
                    if ($null -ne $last_backup)
                    {
                        $dbBackupState[$dbName].last_full_hours = [Math]::Round(($now - $last_backup).TotalHours, 2)
                    }
                }
            }
        }

        # Update each database entry with policy/threshold
        $policies | ForEach-Object {
            $policy = $_

            if ($null -eq $policy)
            {
                Write-Error "Null or missing policy entry"
            }

            # List the databases that match the policy
            $keys = $dbBackupState.Keys | Where-Object { $_ -match $policy["Match"] } | ForEach-Object { $_ }

            $keys | ForEach-Object {
                $db = $_

                if ($policy.ContainsKey("full_backup_hours") -and $null -ne $policy["full_backup_hours"])
                {
                    $dbBackupState[$db].policy_full_hours = [Math]::Abs([int]$policy["full_backup_hours"])
                }

                if ($policy.ContainsKey("log_backup_hours") -and $null -ne $policy["log_backup_hours"])
                {
                    $dbBackupState[$db].policy_log_hours = [Math]::Abs([int]$policy["log_backup_hours"])
                }
            }
        }

        # Log the database backup status
        $capture = New-Capture
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Current database backup status:"
            $dbBackupState.Values | Format-Table | Out-String -Width 300
        }

        # Send a notification with the backup status for all databases, if requested
        # This is mutually exclusive with reporting on individual databases over thresholds
        if ($StatusReport)
        {
            New-Notification -Title "Backup Status: $Name" -Body $capture.ToString()
            return
        }

        # Check each database entry against policy
        $errant = $dbBackupState.Keys | ForEach-Object {
            $db = $_
            $dbEntry = $dbBackupState[$_]

            # If the dbentry doesn't meet the log backup requirements, return it
            if ($dbEntry.recovery_model -eq "FULL" -and
                $null -ne $dbEntry.policy_log_hours -and
                $dbEntry.policy_log_hours -gt 0 -and
                ($dbEntry.last_log_hours -gt $dbEntry.policy_log_hours -or $null -eq $dbEntry.last_log_hours))
            {
                $dbEntry
                return
            }

            # If the dbentry doesn't meet the full backup requirements, return it
            if ($null -ne $dbEntry.policy_full_hours -and
                $dbEntry.policy_full_hours -gt 0 -and
                ($dbEntry.last_full_hours -gt $dbEntry.policy_full_hours -or $null -eq $dbEntry.last_full_hours))
            {
                $dbEntry
                return
            }
        }

        # Send a notification if there are any missing backups
        if (($errant | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Missing Database Backups: $Name" -ScriptBlock {
                Write-Information "Databases missing a recent log or full backup ($Name):"
                $errant | Format-Table | Out-String -Width 300
            }
        }
    }
}

Register-Automation -Name mssql.job_status -ScriptBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConnectionString,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExecuteFrom = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeHours = 1,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$StatusReport = $false
    )

    process
    {
        Write-Information "Connection: $Name"

        # Query age must be positive
        $AgeHours = [Math]::Abs($AgeHours)

        # Invoke command parameters
        $invokeArgs = @{
            ScriptBlock = $queryScript
            ArgumentList = $Name,$ConnectionString,($jobCheck -f (-$AgeHours))
        }

        # Determine what machine to run the check from
        if ([string]::IsNullOrEmpty($ExecuteFrom))
        {
            Write-Information "Executing locally"
        } else {
            $invokeArgs["ComputerName"] = $ExecuteFrom
            Write-Information "Executing from $ExecuteFrom"
        }

        # Invoke check scripts
        $result = Invoke-Command @invokeArgs

        # Deserialise the records and transform
        $records = $result | ConvertFrom-CSV | ForEach-Object {
            # Perform any transforms on the record
            [PSCustomObject]@{
                job_name = $_.job_name
                step_name = $_.step_name
                run_status = $_.run_status
                message = $_.message
                run_datetime = [DateTime]::Parse($_.run_datetime)
            }
        }

        Write-Information ("Found {0} job records" -f ($records | Measure-Object).Count)

        # Group objects by job,step and run status
        # ignore message as we just want the last message for the run_status (i.e. last failure message)
        $summary = $records | Sort-Object -Property run_datetime -Descending |
            Group-Object -Property job_name,step_name,run_status |
            ForEach-Object {
                [PSCustomObject]@{
                    job_name = $_.Group[0].job_name | Limit-StringLength -Length 40
                    step_name = $_.Group[0].step_name | Limit-StringLength -Length 40
                    run_status = $_.Group[0].run_status
                    count = $_.Count
                    last_run = $_.Group[0].run_datetime
                    message = $_.Group[0].message | Limit-StringLength -Length 80
                }
            }

        Write-Information ("Grouped to {0} job summaries" -f ($summary | Measure-Object).Count)

        # Log the job status
        $capture = New-Capture
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Job Status Report ($Name) (last $AgeHours hours):"
            $summary | Format-Table | Out-String -Width 300
        }

        # Just display everything, if this is a status report
        if ($StatusReport)
        {
            New-Notification -Title "Job Status Report ($Name)" -Body $capture.ToString()
            return
        }

        # Send a notification if any jobs have error statuses
        $errorSummary = $summary | Where-Object { $_.run_status -in @(0,2) }
        if (($errorSummary | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Job errors found ($Name)" -ScriptBlock {
                Write-Information "Job errors found ($Name):"
                $errorSummary | Format-Table | Out-String -Width 300
            }
        }
    }
}

