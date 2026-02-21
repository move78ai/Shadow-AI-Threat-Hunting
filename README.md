Shadow AI Threat Hunting: OpenClaw & Agentic AI Detections

![A4_portrait_aspect_2k_202602220217](https://github.com/user-attachments/assets/64bcb8e2-dba0-4131-839a-a7f4a1c7aedd)


This repository contains ready-to-use SIEM detection rules to identify unauthorized, unmanaged, or malicious deployments of autonomous AI agents (such as OpenClaw, Moltbot, and ClawdBot) in enterprise environments.

The Threat:

The rapid adoption of local AI agents has created a massive "Shadow AI" attack surface. These agents require broad system access (file system, shell execution, external network access) to function. Recent supply chain attacks on agent skill registries (like the "ClawHavoc" campaign) have weaponized these agents, using them to pipe malicious scripts and exfiltrate credentials to C2 servers.

Detections Provided:

We provide detection logic for the following SIEM platforms:

• Splunk (SPL)

• Microsoft Sentinel (KQL)

• Elastic Security (EQL)

These queries hunt for:

1. Agent Process Execution: Unapproved initialization of AI agent gateways.

2. Network & C2 Traffic: Connections to default WebSocket ports (e.g., 18789) and known malicious IPs.

3. Malicious Skill Execution: Obfuscated shell commands spawned by the agent runtime.

Enterprise Agent Governance:

Detection is only the first step. If these queries trigger alerts in your environment, your agents are operating without appropriate boundaries.
