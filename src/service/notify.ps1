<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Subject,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Body
)

# Global settings
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$messageParams = @{
    Subject = $Subject
    To = $Env:MAIL_TO
    Body = ("<html><body><pre>" + $Body + "</pre></body></html>")
    SmtpServer = $Env:MAIL_SERVER
    From = $Env:MAIL_FROM
    Port = $Env:MAIL_PORT
    BodyAsHtml = $true
}

Send-MailMessage @messageParams -Verbose

