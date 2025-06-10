<#
.SYNOPSIS
    Real-time Azure AD sign-in log monitoring and threat detection script.

.DESCRIPTION
    This script provides continuous, real-time monitoring of Azure AD sign-in logs using Microsoft Graph.
    It filters events based on application name, operating system, and browser version, while excluding
    sign-ins from specified regions (e.g., Texas, Utah, etc...) and IPv6 traffic to reduce noise—particularly useful 
    when known attacker TTPs primarily leverage IPv4.

    Designed for use across red team, blue team, and SOC workflows:
      - Red teams can use it to simulate detection scenarios and validate alerting mechanisms.
      - Blue teams can proactively detect unauthorized access attempts and anomalous logins.
      - SOC teams can automate triage workflows by launching targeted investigations based on new activity.

    The script supports pop-up alerts, formatted output, and automated execution of a follow-up
    investigation script per unique user, making it ideal for threat hunting, adversary simulation,
    and lightweight SOC automation.

.PARAMETER AppName
    The application to monitor in the sign-in logs (default: 'OfficeHome').

.PARAMETER OS
    The operating system to filter logins by (default: 'Windows10').

.PARAMETER Browser
    The browser version to filter logins by (default: 'Chrome 134.0.0').

.PARAMETER sleepValue
    Number of seconds between each log check (default: 60 seconds).

.PARAMETER lookback
    Time window in minutes to search backward in the logs (default: 30 minutes).

.PARAMETER ExcludedState
    Specifies a U.S. state to exclude from sign-in log analysis. This is helpful when you want to filter out activity from a trusted location   (e.g., where most of your organization operates), allowing you to focus on unexpected or unauthorized access attempts. 

.NOTES
    Author: Sandie Hazelwood
    Last Updated: 6/10/2025
    Requires: Microsoft Graph PowerShell SDK, AuditLog.Read.All permission
#>


param(
    [string]$AppName = "OfficeHome",                    # App to filter sign-in logs by (case-sensitive)
    [string]$OS = "Windows10",                          # Operating system to filter logs by
    [string]$Browser = "Chrome 134.0.0",                # Browser version to filter logs by
    [int]$sleepValue = 60,                              # Time (in seconds) to wait between checks
    [int]$lookback = 30,                                # Time window (in minutes) to query past logs
    [string]$ExcludedState = "TrustedRegion"            # State to exclude from results (e.g., to omit known safe logins)
)

# Load Windows Forms library for popup alert functionality
Add-Type -AssemblyName System.Windows.Forms

# Define the Central Time Zone for date/time formatting
$centralZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time")

# Initialize tracking for the most recent seen log and prior results
$lastSeenDateTime = [datetime]::MinValue                 # Used to detect new login events
$previousResults = @()                                   # Stores past entries to compare changes

$init = 0
while ($init -lt 1) {                                    # Infinite loop, script re-runs on interval

    $MinutesAgo = $lookback                              # Set time window for log query

    # Display header with current filters
    Write-Host "`n`n=====================================================" -ForegroundColor Gray
    Write-Host "       Azure Sign-in Logs for last $lookback Minutes" -ForegroundColor White
    Write-Host "                Threat Hunting" -ForegroundColor DarkMagenta
    Write-Host "   $AppName $OS $Browser" -ForegroundColor White
    Write-Host "       Excludes $ExcludedState and IPV6 Results" -ForegroundColor Red
    Write-Host "=====================================================`n`n" -ForegroundColor Gray

    # Get current Central time and show when script last ran
    $runTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $centralZone).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "Script last ran at: $runTime`n" -ForegroundColor Yellow

    if (-not $MinutesAgo) {
        $MinutesAgo = Read-Host "Enter the number of minutes to filter logs from"  # Prompt if lookback isn't set
    }

    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome                     # Authenticate to Microsoft Graph
    }

    # Get ISO timestamp from the specified lookback period
    $lastDay = (Get-Date).AddMinutes(-$MinutesAgo).ToString("o")
    Write-Host "$lastDay - Search Scope"                                           # Show the query starting point

    # Build Microsoft Graph filter query with specified criteria
    $filterQuery = "(appDisplayName eq '$AppName') and (deviceDetail/operatingSystem eq '$OS') and (deviceDetail/browser eq '$Browser') and (location/state ne '$ExcludedState') and (createdDateTime ge $lastDay)"

    # Fetch filtered sign-in events
    $results = Get-MgAuditLogSignIn -Filter $filterQuery

# Remove IPv6 addresses (those containing ":")
# This filters out any sign-in entries with an IPv6 address by checking if the IP contains a colon.
# IPv6 addresses contain ":", whereas IPv4 addresses do not.


$filteredResults = $results | Where-Object { $_.IPAddress -notmatch ":" }



# --- To REMOVE the IPv6 exclusion (i.e., include both IPv4 and IPv6) ---
# Simply comment out or delete the line above, and instead use:
# $filteredResults = $results

# --- To EXCLUDE IPv4 instead (i.e., only analyze IPv6 traffic) ---
# Replace the line above with the following:
# $filteredResults = $results | Where-Object { $_.IPAddress -match ":" }

# Note: Tailor this behavior based on attacker TTPs or the environment's network profile.


    # Identify new logins that haven't been seen yet
    $newEntries = $filteredResults | Where-Object { $_.createdDateTime -gt $lastSeenDateTime }
    $oldEntries = $filteredResults | Where-Object { $_.createdDateTime -le $lastSeenDateTime }

    # If new sign-ins were found, process them
    if ($newEntries.Count -gt 0) {
        # Update last seen time with the latest event time
        $maxNewTime = ($newEntries | Measure-Object -Property createdDateTime -Maximum).Maximum
        if ($maxNewTime -gt $lastSeenDateTime) {
            $lastSeenDateTime = $maxNewTime
        }

        # Format new entries with friendly column names and CDT time
        $formattedNew = $newEntries | Select-Object @{
            Name = "DateTime (CDT)"; 
            Expression = { 
                [System.TimeZoneInfo]::ConvertTimeFromUtc(($_.createdDateTime).ToUniversalTime(), $centralZone).ToString('yyyy-MM-dd HH:mm:ss') 
            }
        }, userPrincipalName, @{
            Name = "Application"; Expression = { $_.appDisplayName }
        }, @{
            Name = "City"; Expression = { $_.location.city }
        }, @{
            Name = "State"; Expression = { $_.location.state }
        }, IPAddress,
        @{Name = "CAS"; Expression = { $_.ConditionalAccessStatus }},
        @{
            Name = "Status"; Expression = { $_.Status.FailureReason }
        }

        # Show a popup alert to notify user of new matching login attempts
        [System.Windows.Forms.MessageBox]::Show("New attempts made via $Browser on $OS!", "$Browser - Threat Alert", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)

        Write-Host "`n*** New Results ***`n" -ForegroundColor Green
        Write-Host "`n*** DOUBLE CHECK IF STATUS IS NOT APPLIED!! ***`n" -ForegroundColor Red   #reminder to check and see if password was a success
        $formattedNew | Format-Table -AutoSize                                             # Display new entries in a table

        # Append new entries to list of previous results
        $previousResults += $formattedNew

        # Define path to external investigation script
        $scriptPath = "<path_to_review_script>"  #replace with the path to the UserSessionReview script on your device

        # Get unique users from new entries
        $newUserUPNs = $newEntries | Select-Object -ExpandProperty userPrincipalName -Unique

        # Launch the external script for each new user
        foreach ($upn in $newUserUPNs) {
            Start-Process powershell.exe -ArgumentList @(
                "-File", "`"$scriptPath`"",
                "-userPrincipalName", "`"$upn`""
            )
        }
    } else {
        Write-Host "`nNo new results found.`n" -ForegroundColor Red                   # Notify if no new logins were detected
    }

    # If any previous results exist, sort and display them
    if ($previousResults.Count -gt 0) {
        $sortedPreviousResults = $previousResults | Sort-Object -Property "DateTime (CDT)" -Descending
        Write-Host "`n*** Previous Results ***`n" -ForegroundColor Cyan
        $sortedPreviousResults | Format-Table -AutoSize
    }

    Start-Sleep -Seconds $sleepValue      # Wait before looping again
    Write-host "script will rerun in $sleepValue seconds..."                         # Notify of next check
}
