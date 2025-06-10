<#
.SYNOPSIS
    Reviews and optionally revokes Azure AD sign-in sessions for a specific user.

.DESCRIPTION
    This script retrieves the last 5 days of sign-in activity for a given Azure AD user 
    (using their User Principal Name) via Microsoft Graph. It provides a formatted 
    console summary of each sign-in event, including application used, location, device 
    registration, and status information.

    - Results are displayed in a table and optionally in Out-GridView for GUI analysis (Windows only).
    - Provides an interactive prompt to revoke all active sessions for the user.
    - Designed for use in security operations, incident response, or threat hunting workflows 
      to quickly assess and act on suspicious user activity.

.PARAMETER UserPrincipalName
    The UPN (e.g., someone@domain.com) of the user whose sign-in history you want to investigate.

.NOTES
    Author: Sandie Hazelwood
    Last Updated: 6/10/2025
    Requires Microsoft Graph PowerShell SDK with AuditLog.Read.All permission.
    Script assumes Central Time for consistent output formatting.
#>


param(
    [string]$UserPrincipalName  # Takes in the UPN (email) of the user to investigate
)

Write-Host "Received: $UserPrincipalName"  # Echoes back the provided UPN for confirmation

# Set Central Time Zone (needed for formatting)
$centralZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time")  # Converts UTC to Central Time for consistency

# Connect to Microsoft Graph if not already connected
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome  # Authenticates with Microsoft Graph using AuditLog permissions
}

# Get sign-in history for the last 5 days
$historyStart = (Get-Date).AddDays(-5).ToString("o")  # Defines the start time (5 days ago) in ISO 8601 format
$historyQuery = "(userPrincipalName eq '$UserPrincipalName') and (createdDateTime ge $historyStart)"  # Filter for user and date range
$userHistory = Get-MgAuditLogSignIn -Filter $historyQuery | Sort-Object -Property createdDateTime -Descending  # Retrieves and sorts the user's sign-in logs

# Handle no sign-in results
if (-not $userHistory -or $userHistory.Count -eq 0) {
    Write-Host "No sign-in history for $UserPrincipalName in the last 5 days." -ForegroundColor Yellow  # Warns if no sign-ins are found
} else {

    # Format the sign-in records
    $formattedHistory = $userHistory | Select-Object @{

        # Converts UTC time to Central and formats nicely
        Name = "DateTime (CDT)";
        Expression = {
            [System.TimeZoneInfo]::ConvertTimeFromUtc($_.createdDateTime.ToUniversalTime(), $centralZone).ToString('yyyy-MM-dd HH:mm:ss')
        }
    }, @{

        Name = "Application"; Expression = { $_.appDisplayName }  # Displays the app used in the sign-in
    }, @{

        # Checks if the device is registered (based on presence of deviceId)
        Name = "Registered Device"; Expression = {
            if ($_.deviceDetail.deviceId) { "Yes" } else { "" }
        }
    }, @{

        Name = "City"; Expression = { $_.location.city }  # Shows city of sign-in
    }, @{

        Name = "State"; Expression = { $_.location.state }  # Shows state of sign-in
    }, @{

        Name = "IPAddress"; Expression = { $_.ipAddress }  # Displays IP address used
    }, @{

        Name = "CAS"; Expression = { $_.conditionalAccessStatus }  # Shows result of Conditional Access evaluation
    }, @{

        Name = "Status"; Expression = { $_.status.failureReason }  # Shows failure reason if sign-in failed
    }

    # Show results in console
    Write-Host "`n=== 5-Day Log History for $UserPrincipalName ===" -ForegroundColor Cyan
    $formattedHistory | Format-Table -Wrap -AutoSize  # Outputs the formatted sign-in history in a table

    # Prompt to optionally show Out-GridView
    $showGrid = Read-Host "`nWould you like to view this data in Out-GridView?(Windows only devices) (y/n)"
    if ($showGrid -eq 'y') {
        $formattedHistory | Out-GridView -Title "Sign-In History for $UserPrincipalName"  # Opens a GUI view of the data if chosen
    }

    # Ask about revoking sessions
    $decision = Read-Host "`nDo you want to revoke sessions for $UserPrincipalName? (y/n)"
    if ($decision -eq "y") {
        Write-Host "`n>> [ACTION] Revoke sessions for $UserPrincipalName via API." -ForegroundColor Red
        Revoke-MgUserSignInSession -UserId $UserPrincipalName  # Revokes all active sign-in sessions for the user
    } else {
        Write-Host "Skipping session revocation for $UserPrincipalName." -ForegroundColor Gray  # Skips revocation if not selected
    }
}

# Final pause and error output if needed
if ($Error.Count -gt 0) {
    Write-Host "`n--- ERROR ---" -ForegroundColor Red
    $Error[0] | Format-List * -Force  # Shows the first error encountered during execution
}

Read-Host -Prompt "`nPress Enter to exit"  # Prevents the console window from closing immediately
