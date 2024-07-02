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


$maintPlanCheck = @"
SELECT
    mpp.name as 'plan_name',
    mps.subplan_name as 'subplan_name',
    --mpld.command,
    mpld.start_time,
    mpld.end_time,
    CAST(mpld.succeeded as INTEGER) as succeeded,
    mpld.error_message
FROM msdb.dbo.sysmaintplan_log as mpl
INNER JOIN msdb.dbo.sysmaintplan_subplans as mps ON mpl.subplan_id = mps.subplan_id
INNER JOIN msdb.dbo.sysmaintplan_plans as mpp ON mps.plan_id = mpp.id
INNER JOIN msdb.dbo.sysmaintplan_logdetail as mpld on mpl.task_detail_id = mpld.task_detail_id
WHERE
	mpld.end_time IS NOT NULL AND
	mpld.start_time > DATEADD(HOUR, {0}, GETDATE())
"@

$fragmentationCheck = @"
CREATE TABLE #FragmentationCapture
(
	database_name nvarchar(128),
	schema_name nvarchar(128),
	table_name nvarchar(128),
	index_name nvarchar(128),
	avg_frag_pct float,
	page_count bigint
);

INSERT INTO #FragmentationCapture
exec SP_MSforeachdb @command1 = '
IF ''?'' NOT IN (''master'', ''model'', ''msdb'', ''tempdb'')
BEGIN
use [?]
SELECT
    DB_NAME(DB_ID()) as database_name,
    S.name as schema_name,
    T.name as table_name,
    I.name as index_name,
    ROUND(DDIPS.avg_fragmentation_in_percent, 2) as avg_frag_pct,
    DDIPS.page_count
FROM sys.dm_db_index_physical_stats (DB_ID(), NULL, NULL, NULL, NULL) AS DDIPS
INNER JOIN sys.tables T on T.object_id = DDIPS.object_id
INNER JOIN sys.schemas S on T.schema_id = S.schema_id
INNER JOIN sys.indexes I ON I.object_id = DDIPS.object_id
    AND DDIPS.index_id = I.index_id
WHERE DDIPS.database_id = DB_ID()
    and I.name is not null
ORDER BY DDIPS.avg_fragmentation_in_percent desc
END
'

SELECT
	*
FROM #FragmentationCapture
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
    $sqlcmd.CommandTimeout = 360
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

Register-Automation -Name mssql.maint_plan_status -ScriptBlock {
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
            ArgumentList = $Name,$ConnectionString,($maintPlanCheck -f (-$AgeHours))
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
            $error_message = ""
            if (![string]::IsNullOrEmpty($_.error_message))
            {
                $error_message = $_.error_message
            }

            [PSCustomObject]@{
                plan_name = $_.plan_name
                subplan_name = $_.subplan_name
                start_time = [DateTime]::Parse($_.start_time)
                end_time = [DateTime]::Parse($_.end_time)
                succeeded = [int]$_.succeeded
                error_message = $error_message
            }
        }

        Write-Information ("Found {0} maintenance plan records" -f ($records | Measure-Object).Count)

        # Group objects by plan,subplan and succeeded
        # ignore error message as we just want the last error message
        $summary = $records | Sort-Object -Property start_time -Descending |
            Group-Object -Property plan_name,subplan_name,succeeded |
            ForEach-Object {
                [PSCustomObject]@{
                    plan_name = $_.Group[0].plan_name | Limit-StringLength -Length 40
                    subplan_name = $_.Group[0].subplan_name | Limit-StringLength -Length 40
                    succeeded = $_.Group[0].succeeded
                    count = $_.Count
                    last_run = $_.Group[0].start_time
                    error_message = $_.Group[0].error_message | Limit-StringLength -Length 80
                }
            }

        Write-Information ("Grouped to {0} maint plan summaries" -f ($summary | Measure-Object).Count)

        # Log the maint plan status
        $capture = New-Capture
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Maint Plan Task Status Report ($Name) (last $AgeHours hours):"
            $summary | Format-Table | Out-String -Width 300
        }

        # Just display everything, if this is a status report
        if ($StatusReport)
        {
            New-Notification -Title "Maint Plan Task Status Report ($Name)" -Body $capture.ToString()
            return
        }

        # Send a notification if any maintenance plans have error statuses
        $errorSummary = $summary | Where-Object { $_.succeeded -ne 1 }
        if (($errorSummary | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Maint plan task errors found ($Name)" -ScriptBlock {
                Write-Information "Maint plan task errors found ($Name):"
                $errorSummary | Format-Table | Out-String -Width 300
            }
        }
    }
}

Register-Automation -Name mssql.fragmentation_check -ScriptBlock {
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
        [int]$PageMinimum = 1000,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$FragThreshold = 80,

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
            ArgumentList = $Name,$ConnectionString,$fragmentationCheck
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
                database_name = $_.database_name | Limit-StringLength -Length 40
                schema_name = $_.schema_name | Limit-StringLength -Length 40
                table_name = $_.table_name | Limit-StringLength -Length 40
                index_name = $_.index_name | Limit-StringLength -Length 40
                avg_frag_pct = [float]$_.avg_frag_pct
                page_count = [int]$_.page_count
            }
        }

        Write-Information ("Found {0} fragmentation records" -f ($records | Measure-Object).Count)

        # Filter out entries with low page count
        $records = $records | Where-Object { $_.page_count -ge $PageMinimum }
        Write-Information ("{0} records after page count filter" -f ($records | Measure-Object).Count)

        # Create a per database summary
        $databaseSummary = $records | Group-Object -Property database_name | ForEach-Object {
            $group = $_

            # Determine the average fragmentation for the database
            $stat = $_.Group | ForEach-Object { $_.avg_frag_pct } | Measure-Object -Average -Maximum
            $avg_frag_pct = [Math]::Round($stat.Average, 2)
            $max_frag_pct = $stat.Maximum

            [PSCustomObject]@{
                database_name = $_.Group[0].database_name
                avg_frag_pct = [float]$avg_frag_pct
                max_frag_pct = [float]$max_frag_pct
            }
        }

        # Log the database summary and detail
        $capture = New-Capture
        Invoke-CaptureScript -Capture $capture -ScriptBlock {
            Write-Information "Database average fragmentation:"
            $databaseSummary | Format-Table | Out-String -Width 300
        }

        # Just display everything, if this is a status report
        if ($StatusReport)
        {
            New-Notification -Title "Database Fragmentation Status Report ($Name)" -Body $capture.ToString()
            return
        }

        # Create a notification for databases over the fragmentation average
        $fragDatabases = $databaseSummary | Where-Object {
            $_.avg_frag_pct -ge $FragThreshold -or $_.max_frag_pct -ge $FragThreshold
        }

        if (($fragDatabases | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Databases with high fragmentation:" -ScriptBlock {
                Write-Information "Databases with high fragmentation:"
                $fragDatabases | Format-Table | Out-String -Width 300
            }
        }

        # Create a notification for indexes over the threshold
        $fragIndexes = $records | Where-Object { $_.avg_frag_pct -ge $FragThreshold }
        if (($fragIndexes | Measure-Object).Count -gt 0)
        {
            New-Notification -Title "Indexes with high fragmentation:" -ScriptBlock {
                Write-Information "Indexes with high fragmentation:"
                $fragIndexes | Format-Table | Out-String -Width 300
            }
        }
    }
}

