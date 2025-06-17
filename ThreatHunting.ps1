<#
.SYNOPSIS
    Real-time Azure AD sign-in log monitoring and threat detection script.

.DESCRIPTION
    This script connects to Microsoft Graph and queries Azure AD sign-in logs using customizable filters to target specific activity. 
    It allows filtering by application name (e.g., OfficeHome), operating system (e.g., Windows10), and browser version (e.g., Chrome 137.0.0), 
    while also supporting optional geographic scoping by city, state, or country. Administrators can exclude results from a designated state (e.g., Texas) 
    and optionally filter out IPv4 or IPv6 traffic. Direct IP address matching is also supported, enabling more precise threat hunting tailored to known indicators.

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

.PARAMETER City, State, Country
    Narrows sign-in results to a specific geographic location based on user sign-in metadata. 

.PARAMETER ExcludedState
    Specifies a U.S. state to exclude from sign-in log analysis. This is helpful when you want to filter out activity from a trusted location   (e.g., where most of your organization operates), 
    allowing you to focus on unexpected or unauthorized access attempts. 

.PARAMETER IPAddress
    Filters sign-in results to show only those that match a specific IP address. 

.PARAMETER IPVersion
    Filters sign-in results by excluding either IPv4 or IPv6 addresses from the output. 



.NOTES
    Author: Sandie Hazelwood
    Last Updated: 6/17/2025
    Requires: Microsoft Graph PowerShell SDK, AuditLog.Read.All permission
#>


param(
    [string]$AppName = "OfficeHome",                  # App to filter sign-ins by
    [string]$OS = "Windows10",                        # OS to filter sign-ins by
    [string]$Browser = "Chrome 134.0.0",              # Browser version to filter sign-ins by
    [int]$sleepValue = 60,                            # Wait time (in seconds) between each check
    [int]$lookback = 30,                              # Time window (in minutes) to look back for sign-ins
    [string]$City = "",                               # Optional city filter
    [string]$State = "",                              # Optional state filter
    [string]$Country = "",                            # Optional country filter
    [string]$ExcludedState = "Texas",                 # Exclude this state from results
    [string]$IPAddress = "",                          # Specific IP to filter on (if any)
    [string]$IPVersion = "IPv6"                       # Optionally exclude IPv6 or IPv4
)

function Write-Centered {
    param (
        [string]$Text,
        [ConsoleColor]$Color = 'Gray'
    )
    $consoleWidth = [System.Console]::WindowWidth                   # Get console width
    $padding = [Math]::Floor(($consoleWidth - $Text.Length) / 2)   # Calculate left padding for centering
    if ($padding -lt 0) { $padding = 0 }                            # Prevent negative padding

    Write-Host (" " * $padding) -NoNewline                          # Add spaces to center the text
    Write-Host $Text -ForegroundColor $Color                        # Display centered text
}

function Write-CenteredRuleLine {
    param (
        [char]$Char = '=',
        [ConsoleColor]$Color = 'Gray',
        [int]$LineLength = 50
    )
    $consoleWidth = [System.Console]::WindowWidth                   # Get console width
    $lineString = ([string]$Char) * $LineLength                     # Create a line of repeated characters
    $padding = [Math]::Floor(($consoleWidth - $LineLength) / 2)     # Center the line

    Write-Host (" " * $padding) -NoNewline                          # Pad with spaces
    Write-Host $lineString -ForegroundColor $Color                  # Display the line in the desired color
}

Add-Type -AssemblyName System.Windows.Forms                         # Add support for Windows Forms (used for popups)

$centralZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time")  # Get Central Time zone
$lastSeenDateTime = [datetime]::MinValue                            # Initialize last seen time
$previousResults = @()                                              # Initialize an empty array to store previous results

$init = 0
while ($init -lt 1) {
    $MinutesAgo = $lookback                                         # Define how far back to search for logs

    Write-Host ""
    Write-CenteredRuleLine -Char '=' -Color Gray -LineLength 50     # Print a divider
    Write-Centered "Azure Sign-in Logs for last $lookback Minutes" -Color White       # Title
    Write-Centered "Threat Hunting" -Color DarkMagenta              # Subtitle
    Write-Centered "$AppName $OS $Browser" -Color Cyan              # Display current filters
    Write-Centered "$City $State $Country $IPAddress" -Color White  # Display geo/IP filters
    Write-Centered "Excludes $ExcludedState and filters out: $IPVersion" -Color Red    # Exclusion summary
    Write-CenteredRuleLine -Char '=' -Color Gray -LineLength 50     # End divider

    $runTime = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $centralZone).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Centered "Current Time: $runTime`n" -ForegroundColor Yellow    # Print the current Central Time

    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome      # Connect to Microsoft Graph if not connected
    }

    $lastDay = (Get-Date).AddMinutes(-$MinutesAgo).ToString("o")    # Calculate the starting time for the query
    Write-Centered "Searching Scope"                                 # Inform user search is starting

    $filterParts = @()                                              # Start building filter conditions
    if ($AppName)       { $filterParts += "(appDisplayName eq '$AppName')" }           # Filter by app name
    if ($OS)            { $filterParts += "(deviceDetail/operatingSystem eq '$OS')" }  # Filter by OS
    if ($Browser)       { $filterParts += "(deviceDetail/browser eq '$Browser')" }     # Filter by browser
    if ($City)          { $filterParts += "(location/city eq '$City')" }               # Optional city filter
    if ($State)         { $filterParts += "(location/state eq '$State')" }             # Optional state filter
    if ($Country)       { $filterParts += "(location/countryOrRegion eq '$Country')" } # Optional country filter
    if ($ExcludedState) { $filterParts += "(location/state ne '$ExcludedState')" }     # Exclude this state
    if ($IPAddress)     { $filterParts += "(ipAddress eq '$IPAddress')" }              # Filter by specific IP

    $filterParts += "(createdDateTime ge $lastDay)"                  # Filter to only recent sign-ins
    $filterQuery = $filterParts -join " and "                        # Combine all filters with "and"

    $results = Get-MgAuditLogSignIn -Filter $filterQuery             # Query Microsoft Graph sign-in logs

    switch ($IPVersion) {
        "IPv6" { $filteredResults = $results | Where-Object { $_.IPAddress -notmatch ":" } }  # Exclude IPv6
        "IPv4" { $filteredResults = $results | Where-Object { $_.IPAddress -match ":" } }     # Exclude IPv4
        default { $filteredResults = $results }                                                # No IP version filter
    }

    $newEntries = $filteredResults | Where-Object { $_.createdDateTime -gt $lastSeenDateTime } # Filter only new sign-ins
    $oldEntries = $filteredResults | Where-Object { $_.createdDateTime -le $lastSeenDateTime } # Older sign-ins

    if ($newEntries.Count -gt 0) {
        $maxNewTime = ($newEntries | Measure-Object -Property createdDateTime -Maximum).Maximum  # Get latest event time
        if ($maxNewTime -gt $lastSeenDateTime) {
            $lastSeenDateTime = $maxNewTime                      # Update last seen time
        }

        $formattedNew = $newEntries | Select-Object @{           # Format new entries for display
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
        @{Name = "Status"; Expression = { $_.Status.FailureReason }}

        [System.Windows.Forms.MessageBox]::Show("New attempts made via $Browser on $OS!", "$Browser - Threat Alert", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        # Show a Windows popup alert for detected threats

        Write-Host "`n*** New Results ***`n" -ForegroundColor Green   # Display new entries in green
        Write-Host "`n*** DOUBLE CHECK IF NOT APPLIED!! ***`n" -ForegroundColor Red   # Warning message
        $formattedNew | Format-Table -AutoSize                        # Display formatted results

        $previousResults += $formattedNew                             # Save new entries for later reference

        $scriptPath = "<path_to_review_script>"                       # Path to secondary review script
        $newUserUPNs = $newEntries | Select-Object -ExpandProperty userPrincipalName -Unique  # Get unique UPNs

        foreach ($upn in $newUserUPNs) {
            Start-Process powershell.exe -ArgumentList @(             # Launch the review script for each new UPN
                "-File", "`"$scriptPath`"",
                "-userPrincipalName", "`"$upn`"",
                "`"$AppName`""
            )
        }
    } else {
        Write-Host "`nNo new results found.`n" -ForegroundColor Red   # No new results to show
    }

    if ($previousResults.Count -gt 0) {
        $sortedPreviousResults = $previousResults | Sort-Object -Property "DateTime (CDT)" -Descending
        Write-Host "`n*** Previous Results ***`n" -ForegroundColor Cyan     # Display prior findings
        $sortedPreviousResults | Format-Table -AutoSize
    }

    Start-Sleep -Seconds $sleepValue                                 # Wait before rerunning the loop
    Write-Host "Script will rerun in $sleepValue seconds..."         # Let user know the wait time
}
