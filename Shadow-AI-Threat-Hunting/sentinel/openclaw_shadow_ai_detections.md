Microsoft Sentinel (KQL) Detection Rules: Shadow OpenClaw

Author: Abhishek G Sharma, Move78 International

Kusto Query Language (KQL) rules for Microsoft Sentinel to detect unauthorized OpenClaw AI agents operating within a corporate Windows/macOS environment using Microsoft Defender for Endpoint data.

1. Process Execution: OpenClaw CLI

Detects developers launching OpenClaw via command line, indicating an active local agent:

// Name: Shadow AI - OpenClaw Process Execution
// Severity: Medium
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains "openclaw" 
   or InitiatingProcessCommandLine contains "openclaw"
   or FolderPath endswith "openclaw.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp desc


2. Network: Outbound connections to Agent Networks (Moltbook/ClawHub)

Identifies endpoints making DNS requests or establishing network connections to the OpenClaw ecosystem, which bypasses traditional enterprise API gateways:

// Name: Shadow AI - Connection to OpenClaw Infrastructure
// Severity: High (Data Exfiltration Risk)
let AgentDomains = dynamic(["clawhub.com", "api.clawhub.com", "moltbook.com"]);
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any (AgentDomains) 
   or RemoteUrl contains "clawhub" 
   or RemoteUrl contains "moltbook"
| summarize ConnectionCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| where ConnectionCount > 5 // Filter out accidental single clicks
| sort by ConnectionCount desc


3. File System: Malicious Payload Detection ("ClawHavoc" IOCs)

Detects the specific trojanized zip file associated with the recent ClawHub marketplace supply chain attacks:

// Name: Malware - ClawHavoc Supply Chain Artifacts
// Severity: Critical
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName =~ "openclaw-agent.zip" or FolderPath contains ".openclaw\\skills"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256


Response Guidance

If rule #3 triggers, assume the endpoint is compromised with the Atomic Stealer (AMOS) malware. Isolate the device immediately and rotate all credentials (including local .env files and SSH keys) present on the machine.