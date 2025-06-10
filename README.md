# Threat-Hunting-Toolkit-PowerShell-Scripts-for-Azure-AD-Monitoring
This GitHub repository includes two PowerShell scripts designed to support real-time threat hunting, adversary simulation, and SOC-level automation using Microsoft Graph and Azure AD sign-in logs.


# Threat Hunting Toolkit for Azure AD Sign-In Logs

This repository contains two purpose-built PowerShell scripts designed for **real-time threat detection, incident triage, and session analysis** within Microsoft 365 environments. They leverage the **Microsoft Graph API** to extract and analyze Azure AD sign-in data, providing security teams with actionable insights during red team exercises, blue team investigations, and SOC workflows.

---

## 📁 Contents

- **`ThreatHunter.ps1`** – Actively monitors Azure AD sign-in logs in real time. Filters out known traffic, flags anomalies, and triggers secondary analysis tools.
- **`UserSessionReview.ps1`** – Gathers historical sign-in activity for a specific user. Presents data in human-readable form and offers the option to revoke sessions.

---

##  Prerequisites

Before using these scripts, ensure the following:

1. **PowerShell 5.1+** or PowerShell Core (cross-platform).
2. **Microsoft Graph PowerShell SDK** installed:
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
