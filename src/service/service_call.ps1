<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceRoot,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName
)

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

try { $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText } catch {}

# Global variables
$servicePath = ([System.IO.Path]::Combine($ServiceRoot, $ServiceName))
$logPath = ([System.IO.Path]::Combine($ServicePath, "log.txt"))

# Read general config
Set-Location $ServiceRoot
. ./service_config.ps1

# Default handler for notifications
$defaultNotifier = {
    $batch = $_

    # Batch name is the subject
    $subject = ("Task: {0}" -f $batch.Name)

    # Send a single email with all notifications
    $body = $batch.Notifications | ForEach-Object {
        ("Source: {0}/{1}" -f $_.Source, $_.Title)
        $_.Body
        ""
    } | Out-String

    # Recipients
    $mailTo = $Env:MAIL_TO.Split(",").Trim()

    $messageParams = @{
        Subject = $subject
        To = $mailTo
        Body = ("<html><body><pre>" + $body + "</pre></body></html>")
        SmtpServer = $Env:MAIL_SERVER
        From = $Env:MAIL_FROM
        Port = $Env:MAIL_PORT
        BodyAsHtml = $true
    }

    Send-MailMessage @messageParams -Verbose
}

try {
    # Import modules
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    @("AutomationUtils") | ForEach-Object {
        Install-Module -Scope CurrentUser -Confirm:$false $_ -EA Ignore
        Update-Module -Confirm:$false $_ -EA Ignore
        Import-Module $_
    }

    # Create the service directory, if it doesn't exist
    if (!(Test-Path -Path $servicePath -PathType Container))
    {
        New-Item -ItemType Directory $servicePath
    }

    # Rotate the log file, if required
    Reset-LogFile -LogPath $logPath -RotateSizeKB 512 -PreserveCount 5

    # Create capture to allow streaming of content to console as well
    $capture = New-Capture

    & {
        # Register default notifier
        Register-Notifier -ScriptBlock $defaultNotifier

        # Location of the entrypoint script to run for this task
        $scriptPath = ([System.IO.Path]::Combine($servicePath, "entrypoint.ps1"))
        Write-Information "Script Path: $scriptPath"

        # Check to make sure we have an entrypoint script
        if (!(Test-Path -PathType Leaf $scriptPath))
        {
            Write-Error "Could not find entrypoint script or not a file"
        }

        # Change to service directory
        Write-Information "Changing to $ServicePath"
        Set-Location -Path $ServicePath

        # Read service configuration
        Write-Information "Reading service configuration"
        $config = & ([System.IO.Path]::Combine($ServiceRoot, "read_config.ps1")) -ServiceRoot $ServiceRoot -ServiceName $ServiceName |
            Out-String | ConvertFrom-Json

        try {
            & {
                Write-Information "Calling entrypoint: $scriptPath"
                $global:LASTEXITCODE = 0
                & $scriptPath -Config $config

                if ($global:LASTEXITCODE -ne 0)
                {
                    Write-Error ("Script call failed with exit code: " + $global:LASTEXITCODE)
                }

                Write-Information "Entrypoint finished"
            } *>&1 | Select-ForType -Type AutomationUtilsNotification -Derived -Process {
                Write-Information ("Notification generated: {0}" -f $_.Title)
                $_
            } | Send-Notifications -Name $ServiceName -Pass
        } catch {
            $_
            try { $_.ScriptStackTrace | Format-List } catch {}
            Write-Error "Entrypoint script failed with error: $_"
        }
    } *>&1 |
        Format-AsLog |
        Out-String -Stream |
        Copy-ToCapture -Capture $capture |
        Tee-Object -Encoding UTF8 -Append -FilePath $logPath

} catch {
    Write-Information "Service failed: $_"
    try { $_.ScriptStackTrace | Format-List } catch {}
    Write-Information "Sending notification"

    # Best effort convert capture to a string and information on the exception
    $body = ""

    try {
        $body += "Capture Content: "
        $body += $capture.Content | Out-String
    } catch {}

    try {
        $body += "Exception: "
        $body += $_ | Out-String
    } catch {}

    try {
        $body += "Stack Trace: "
        $body += ($_.ScriptStackTrace | Format-List | Out-String)
    } catch {}

    # Recipients
    $mailTo = $Env:MAIL_TO.Split(",").Trim()

    # Send email using Send-MailMessage. Don't use registered notifiers as they could generate
    # additional exceptions preventing any notification from being sent
    $messageParams = @{
        Subject = "Task: $ServiceName Failure"
        To = $mailTo
        Body = ("<html><body><pre>" + $body + "</pre></body></html>")
        SmtpServer = $Env:MAIL_SERVER
        From = $Env:MAIL_FROM
        Port = $Env:MAIL_PORT
        BodyAsHtml = $true
    }

    Send-MailMessage @messageParams -Verbose
}

