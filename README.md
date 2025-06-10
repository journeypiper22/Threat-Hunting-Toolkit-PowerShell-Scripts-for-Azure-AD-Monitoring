# Threat Hunting Toolkit – PowerShell Scripts for Azure AD Monitoring

This GitHub repository includes two PowerShell scripts designed to support real-time **threat hunting**, **adversary simulation**, and **SOC-level automation** using **Microsoft Graph** and **Azure AD sign-in logs**.

---

## Contents

* `ThreatHunter.ps1`: Continuously monitors sign-in logs for suspicious activity using filters like app, OS, browser, and excluded region. Automatically launches a second script for deeper inspection.
* `UserSessionReview.ps1`: Retrieves and formats detailed sign-in history for a given user over the last 5 days, supports session revocation, and optional GUI output.

---

## `ThreatHunter.ps1`

### Description

This script provides **continuous, real-time monitoring** of Azure AD sign-in logs using the Microsoft Graph API. It filters events by:

* Application name (e.g., `OfficeHome`)
* Operating system (e.g., `Windows10`)
* Browser version (e.g., `Chrome 134.0.0`)
* Excludes IPv6 addresses (can be modified)
* Excludes sign-ins from a specific U.S. state (e.g., `Texas`, `Utah`) — this can help suppress expected internal activity

> **Note:** The script has been reviewed to ensure it contains no identifying information about the organization or environment it was originally used in. It is safe for public use, research, or demonstration purposes.

### Use Cases

* **Red Team**: Test detection coverage and simulate adversary behavior.
* **Blue Team**: Monitor for unauthorized or anomalous access attempts.
* **SOC Analysts**: Automate triage workflows with integrated alerting and follow-up scripting.

### Features

* Graph API filtering by sign-in metadata
* IPv6 exclusion to reduce noise (optional)
* Pop-up alerts for new activity
* Launches `UserSessionReview.ps1` for each new user detected
* Outputs formatted tables and preserves results

### Parameters

| Parameter        | Description                                      |
| ---------------- | ------------------------------------------------ |
| `$AppName`       | Application to filter by (default: `OfficeHome`) |
| `$OS`            | OS to filter by (default: `Windows10`)           |
| `$Browser`       | Browser version (default: `Chrome 134.0.0`)      |
| `$sleepValue`    | Delay between checks (in seconds)                |
| `$lookback`      | Time window for log collection (minutes)         |
| `$ExcludedState` | U.S. region to ignore (e.g., `Texas`)            |

---

## `UserSessionReview.ps1`

### Description

This script is automatically called by the main threat hunter, or can be run manually to perform a **targeted investigation** into a specific user's sign-in activity.

### Use Cases

* Review historical logins for a specific user
* Determine geographic or behavioral anomalies
* Optionally revoke active sessions if compromise is suspected

### Features

* Pulls 5 days of sign-in history for a specified user
* Converts timestamps to Central Time
* Displays sign-in app, location, device status, and Conditional Access
* Optionally opens data in Out-GridView
* Option to revoke active sessions via Microsoft Graph

### Parameters

| Parameter            | Description                        |
| -------------------- | ---------------------------------- |
| `$UserPrincipalName` | UPN (email) of user to investigate |

---

## Requirements

* PowerShell 5.1+
* Microsoft Graph PowerShell SDK installed:

  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
* Azure AD `AuditLog.Read.All` permissions (delegated)
* Internet access to reach Microsoft Graph

---

## Optional Customizations

* To **include IPv6 addresses**, remove or comment out this line in `ThreatHunter.ps1`:

  ```powershell
  $filteredResults = $results | Where-Object { $_.IPAddress -notmatch ":" }
  ```

* To **exclude IPv4 instead**, modify the condition like so:

  ```powershell
  $filteredResults = $results | Where-Object { $_.IPAddress -match ":" }
  ```

---

## Example Usage

### Run threat hunting script (manual test)

```powershell
.\ThreatHunter.ps1 -AppName "OfficeHome" -OS "Windows10" -Browser "Chrome 134.0.0" -ExcludedState "Texas" -sleepValue 60 -lookback 30
```

### Run individual user session review

```powershell
.\UserSessionReview.ps1 -UserPrincipalName "jdoe@yourdomain.com"
```

---

## Notes

* Allow PowerShell scripts to execute if restricted:

  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

* `ThreatHunter.ps1` script will re-run automatically every `$sleepValue` seconds to maintain real-time visibility.

---

## Credits

This toolkit was developed and maintained by Sandie Hazelwood to support defenders and threat hunters in Azure AD environments.

If you find this useful, feel free to fork, or share feedback.


