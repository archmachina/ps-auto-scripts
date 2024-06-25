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
    sdb.recovery_model as recovery_model,
    sdb.recovery_model_desc as recovery_model_desc,
    dbb.backup_type as backup_type,
    dbb.backup_start_date as last_backup
FROM sys.databases as sdb
LEFT JOIN DBBackups as dbb
    ON dbb.database_name = sdb.name AND
    rn = 1
WHERE
    sdb.name != 'tempdb'
"@

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
        [string]$ExecuteFrom = ""
    )

    process
    {
        $checkScript = {
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

            # Close the connection
            $sqlconn.Close()

            # Check for errors in the output
            if ($data.HasErrors)
            {
                Write-Error "DataSet has errors"
            }

            $data.Tables.Rows |
                Select-Object -Property database_name,recovery_model,recovery_model_desc,backup_type,last_backup |
                ConvertTo-Json
        }

        Write-Information "Connection: $Name"

        # Invoke command parameters
        $invokeArgs = @{
            ScriptBlock = $checkScript
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
        $dbBackupRecords = $result | ConvertFrom-Json

        # Convert the results to something easier to work with
        $dbBackupState = @{}
        $dbBackupRecords | ForEach-Object {
            $dbName = $_.database_name
            $dbState = $_

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

            # Make sure we're working in local time
            $last_backup = $dbState.last_backup
            if ($null -ne $last_backup)
            {
                $last_backup = $last_backup.ToLocalTime()
            }

            # Extract specific types of backups
            switch ($_.backup_type)
            {
                "L" {
                    $dbBackupState[$dbName].last_log_date = $last_backup
                    if ($null -ne $last_backup)
                    {
                        $dbBackupState[$dbName].last_log_hours = [Math]::Round(([DateTime]::Now - $last_backup).TotalHours, 2)
                    }
                }
                "D" {
                    $dbBackupState[$dbName].last_full_date = $last_backup
                    if ($null -ne $last_backup)
                    {
                        $dbBackupState[$dbName].last_full_hours = [Math]::Round(([DateTime]::Now - $last_backup).TotalHours, 2)
                    }
                }
            }
        }

        # Log the database backup status
        $dbBackupState.Values |
            Format-Table -Property name,recovery_model,last_log_date,last_log_hours,last_full_date,last_full_hours |
            Out-String -Width 300

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
 
