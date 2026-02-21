Splunk Detection Rules: Hunting Shadow OpenClaw Deployments

Framework: MITRE ATT&CK
Tactic: Execution (TA0002), Command and Control (TA0011)
Author: Abhishek G Sharma, Move78 International

Enterprise developers frequently install OpenClaw to automate tasks without security approval. These queries help Security Operations Centers (SOC) detect unauthorized OpenClaw and ClawHub network activity.

1. Endpoint: OpenClaw Process Execution

Detects the execution of the OpenClaw CLI or known agent binaries on corporate endpoints. Requires EDR logs (Sysmon Event ID 1 or CrowdStrike/Defender process creation events) ingested into Splunk:

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search (CommandLine="*openclaw*" OR Image="*\\openclaw.exe" OR Image="*\\openclaw-agent*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, Image, CommandLine
| convert ctime(firstTime) ctime(lastTime)
| sort - count


2. Network: ClawHub & Moltbook C2 Infrastructure Traffic

Detects hosts communicating with the OpenClaw skill marketplace or the Moltbook agent network. High volume of traffic to these domains from a non-approved host indicates an active agent. Requires Proxy, Firewall, or DNS logs:

index=network (sourcetype="pan:traffic" OR sourcetype="cisco:umbrella:dns" OR sourcetype="zscaler:lss")
| search (query="*clawhub.com" OR query="*moltbook.com" OR dest_domain="*clawhub.com" OR dest_domain="*moltbook.com")
| stats count values(dest_domain) as Domains_Accessed min(_time) as firstTime max(_time) as lastTime by src_ip, src_user
| where count > 10
| convert ctime(firstTime) ctime(lastTime)


3. File System: Agent Configuration Creation

OpenClaw stores state and downloaded skills in specific hidden directories (.openclaw). Detecting the creation of these paths is a high-fidelity indicator of a new installation. Requires Sysmon Event ID 11 (File Create):

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search TargetFilename="*\\.openclaw\\config.json" OR TargetFilename="*\\.openclaw\\skills\\*"
| stats count by Computer, User, TargetFilename, _time


Next Steps for Security Engineers

If these alerts trigger, the host should be quarantined. OpenClaw agents have autonomous read/write capabilities and may have downloaded malicious skills (e.g., the "ClawHavoc" campaign). Consult the AgentClaw Controls Toolkit (ACT) for incident response playbooks regarding Agentic AI.