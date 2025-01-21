# Building a SOC + Honeynet in Azure (Live Traffic)

![322930551-ca6ef315-dcbf-4176-b90f-c46a6bbf0459](https://github.com/user-attachments/assets/f41cace6-bfe7-403d-bfb8-b7312f3f842e)





## Introduction

In today’s rapidly evolving cloud environments, organizations face persistent challenges in detecting and mitigating cyber threats. This project addresses these challenges by simulating a real-world scenario where a vulnerable cloud infrastructure is monitored, hardened, and analyzed to enhance security defenses.

I constructed a mini honeynet in Microsoft Azure to mimic an organization's network, ingesting logs from various Azure resources into a centralized Log Analytics Workspace. These logs were analyzed using Microsoft Sentinel to build attack maps, trigger alerts, and generate incidents.

The purpose of this project was to measure the effectiveness of security controls in mitigating threats. To achieve this, I gathered baseline security metrics from the insecure environment over 24 hours, implemented robust security controls to harden the environment, and collected metrics for another 24 hours to assess the impact.

This approach demonstrates how organizations can leverage cloud-native tools to detect, respond to, and prevent sophisticated attacks while building a data-driven strategy to continuously improve their security posture.

The Metrics collected are:
- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)


## Architecture Before Hardening / Security Controls
![322926658-efa182b3-afe3-46d6-b431-84fe61c1daff](https://github.com/user-attachments/assets/bd878a42-e941-4f12-b27d-4ce9527fe1a3)

## Architecture After Hardening / Security Controls
![322926807-bda2d085-3471-4d51-8373-404e5dbd3371](https://github.com/user-attachments/assets/0836d0cd-ed80-4660-8b2b-0ec37bdbf3a2)


The architecture of the honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel


## Attack Maps Before Hardening / Security Controls
<img width="735" alt="322927150-6201e7a7-6e1e-4759-bca5-c820e125190c" src="https://github.com/user-attachments/assets/3ed829a9-1e04-48ff-81f0-cb9ef514ddfc" />
<img width="735" alt="322927235-ccefa380-5948-4dd6-b52c-f303648fb68e" src="https://github.com/user-attachments/assets/ec0d8b0c-ae00-48e1-841e-a4cf660bfdbb" />
<img width="735" alt="322927285-3406fac0-c152-4684-bc3a-236ff35a9eb4" src="https://github.com/user-attachments/assets/d87ecf55-5168-4967-ba9d-202938a754b6" />


The following table shows the metrics I measured in our insecure environment for 24 hours:
<br>
| Start Time 2024-12-27 12:34:48
<br>
| Stop Time 2024-12-28 12:34:48

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 7671
| Syslog                   | 833
| SecurityAlert            | 4
| SecurityIncident         | 59
| AzureNetworkAnalytics_CL | 620

## Attack Maps After Hardening / Security Controls

<img width="154" alt="322928366-031e52cf-266f-40de-a1b1-d8ff313aa746" src="https://github.com/user-attachments/assets/b4488177-d910-4740-b6bf-dcae3e54b0c3" />

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```


## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but with security controls:
<br>
| Start Time 2024-12-29 10:45:28
<br>
| Stop Time 2024-12-30 10:45:28

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 3894
| Syslog                   | 6
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

![322931030-3d5a9f41-fd9f-4e0c-bfa1-85da4b249939](https://github.com/user-attachments/assets/6c16d302-21b5-481c-9669-2a67ccaa1ffd)

## 15 attack vectors detected and logged in the honeynet
Below is a list of attack vectors analyzed in this project, along with how they were logged and identified in the honeynet:

Brute Force RDP Attacks
Logged By: Windows Event Logs (SecurityEvent), Azure Security Center.
Indicators: Multiple failed login attempts (Event ID 4625) from a single IP followed by a successful login.

Brute Force SSH Attacks
Logged By: Linux Syslog (auth.log), NSG flow logs.
Indicators: Repeated "Failed password" messages in /var/log/auth.log and high SSH connection attempts from a single IP.

Malicious File Uploads
Logged By: Web server logs, Azure Storage Account logs.
Indicators: Suspicious POST requests with unusual file types (e.g., .exe, .php).

Unsecured SMB Access
Logged By: Windows Event Logs (SecurityEvent), NSG flow logs.
Indicators: Event ID 5140 (access to shared resources) showing unauthorized or unusual SMB activity.

Remote Code Execution (RCE)
Logged By: Application logs, web server logs.
Indicators: Unexpected commands in request payloads or anomalous application behavior.

Directory Traversal
Logged By: Web server logs.
Indicators: Requests containing patterns like ../ or encoded sequences (%2e%2e%2f) targeting sensitive files (e.g., /etc/passwd).

Weak Password Exploits
Logged By: Authentication logs (Windows and Linux).
Indicators: Logins from unauthorized IPs using weak/default credentials.

Exploit of Outdated Software
Logged By: Application and system logs.
Indicators: Exploitation of known vulnerabilities in unpatched software, often tied to specific CVEs.

Port Scanning and Reconnaissance
Logged By: NSG flow logs, intrusion detection systems (IDS).
Indicators: High connection attempts to multiple ports from a single IP.

Privilege Escalation
Logged By: Windows Event Logs (SecurityEvent), Linux audit logs.
Indicators: Event ID 4672 (privilege assignment) or unusual use of sudo commands in Linux.

Lateral Movement
Logged By: Windows Event Logs, NSG flow logs.
Indicators: Unauthorized logins to multiple VMs and file sharing events.

Denial of Service (DoS)
Logged By: NSG flow logs, performance metrics.
Indicators: Sudden spikes in inbound traffic or resource usage.

Reverse Shell Attacks
Logged By: Syslog, NSG flow logs.
Indicators: Outbound connections to unknown IPs on uncommon ports or shell commands originating from compromised services.

Malware Installation
Logged By: File integrity monitoring, antivirus logs.
Indicators: New or modified files in critical directories matching known malware signatures.

Command and Control (C2) Traffic
Logged By: NSG flow logs, DNS logs.
Indicators: Outbound traffic to known malicious domains or repeated DNS queries for suspicious addresses.

## Summary

This project involved constructing a mini honeynet within Microsoft Azure, designed to capture and analyze security events. Logs from various Azure resources were ingested into a Log Analytics Workspace and monitored using Microsoft Sentinel, which was configured to trigger alerts and generate incidents based on detected anomalies. Metrics were gathered from the environment during a 24-hour period of intentional vulnerability, followed by another 24-hour period after implementing security controls.

The results demonstrated a significant reduction in security events and incidents after the application of these controls, highlighting their effectiveness in mitigating potential threats. It is worth noting that if the network had been subject to typical user activity, the number of generated security events and alerts could have been higher during the post-hardening phase.



## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |

