# Threat Hunting Toolkit – PowerShell Scripts for Azure AD Monitoring

This GitHub repository includes two PowerShell scripts designed to support real-time **threat hunting**, **adversary simulation**, and **SOC-level automation** using **Microsoft Graph** and **Azure AD sign-in logs**.

Designed to quickly identify and monitor active compromises in Azure AD environments. This toolkit helps track suspicious activity for as long as needed to ensure incidents are fully resolved. It’s especially critical during large-scale attack campaigns or Adversary-in-the-Middle (AiTM) attacks, where rapid intervention is necessary to prevent attackers from successfully exploiting MFA approvals.

---

## Contents

* `ThreatHunter.ps1`: Continuously monitors sign-in logs for suspicious activity using filters like app, OS, browser, location, IP address, and version. Automatically launches a second script for deeper inspection.
* `UserSessionReview.ps1`: Retrieves and formats detailed sign-in history for a given user over the last 5 days, supports session revocation, and optional GUI output.

---

## `ThreatHunter.ps1`

![image](https://github.com/user-attachments/assets/ff6b40e0-bdf3-4cf8-ba78-85c2566e759c)

![image](https://github.com/user-attachments/assets/0133a90a-46bc-4543-aaef-5173c0af20e4)

### Description

This script provides **continuous, real-time monitoring** of Azure AD sign-in logs using the Microsoft Graph API. It filters events by:

* Application name (e.g., `OfficeHome`)
* Operating system (e.g., `Windows10`)
* Browser version (e.g., `Chrome 137.0.0`)
* City, state, or country
* IPv4 or IPv6 address (optional)
* Excludes sign-ins from a specific U.S. state (e.g., `Texas`, `Utah`)
* Optional filtering by IP address and IP version (`IPv4`, `IPv6`, or both)


### Use Cases

* **Red Team**: Test detection coverage and simulate adversary behavior.
* **Blue Team**: Monitor for unauthorized or anomalous access attempts.
* **SOC Analysts**: Automate triage workflows with integrated alerting and follow-up scripting.

### Features

* Microsoft Graph API filtering by sign-in metadata
* Optional exclusion of IPv4 or IPv6 traffic
* New parameter to search for specific IP address
* Pop-up alerts for new activity
* Launches `UserSessionReview.ps1` for each new user detected
* Displays formatted tables in Central Time (CDT)
* Automatically loops at defined intervals for continuous monitoring
* Case-insensitive parameter support for IP version

### Setup Note
Before running ThreatHunter.ps1, you must update the following line with the actual path to the UserSessionReview.ps1 script on your system:
```powershell
$scriptPath = "<path_to_review_script>"  # Replace this with the real path, e.g., "C:\Scripts\UserSessionReview.ps1"
```
If this path is not set correctly, the follow-up investigations for each new user sign-in will not work.



### Parameters

| Parameter        | Description                                    |
| ---------------- | ---------------------------------------------- |
| `$AppName`       | Application to filter (e.g., `OfficeHome`)     |
| `$OS`            | Operating System (e.g., `Windows10`)           |
| `$Browser`       | Browser version (e.g., `Chrome 137.0.0`)       |
| `$City`          | City for geo-filtering (optional)              |
| `$State`         | State to include in filtering                  |
| `$Country`       | Country or region                              |
| `$ExcludedState` | U.S. state to exclude (e.g., `Texas`)          |
| `$IPAddress`     | Search for specific IP address (optional)      |
| `$IPVersion`     | Choose `IPv4`, `IPv6`, or leave blank for both |
| `$sleepValue`    | Delay between scans in seconds (e.g., `60`)    |
| `$lookback`      | Lookback window in minutes (e.g., `60`)        |

> **Note:** IP version selection is case-insensitive.

---

## `UserSessionReview.ps1`

![image](https://github.com/user-attachments/assets/dbfe5fc0-c1e7-436d-954f-81ee83c242b3)


### Description

This script is automatically called by the main threat hunter, or can be run manually to perform a **targeted investigation** into a specific user's sign-in activity.

### Use Cases

* Review historical logins for a specific user
* Determine geographic or behavioral anomalies
* Revoke active sessions if compromise is suspected

### Features

* Retrieves 5 days of sign-in history for a user
* Converts timestamps to Central Time (CDT)
* Displays app, IP, device, and CA status
* Optionally opens results in `Out-GridView`
* Supports revoking active sessions via Graph API

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


---

## Optional Customizations

* To **include all IP types**, leave the `-IPVersion` parameter blank

* To **only include IPv6**, use:

  ```powershell
  -IPVersion "IPv6"
  ```

* To **search for a specific IP address**, use:

  ```powershell
  -IPAddress "10.1.2.3"
  ```


---

## Example Usage

### Run threat hunting script (manual test)

```powershell
.\ThreatHunter.ps1 -AppName "OfficeHome" -OS "Windows10" -Browser "Chrome 137.0.0" -ExcludedState "Texas" -IPVersion "IPv4" -sleepValue 60 -lookback 30
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

This toolkit was developed and maintained by **Sandie Hazelwood** to support defenders and threat hunters in Azure AD environments.

If you find this useful, feel free to star, or share feedback.


