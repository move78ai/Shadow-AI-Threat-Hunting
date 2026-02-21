Elastic Security / Kibana Rules: Shadow OpenClaw

Author: Abhi, Move78 International

Elastic Query Language (EQL) and Lucene queries to detect the presence and activity of OpenClaw autonomous agents across enterprise infrastructure.

1. EQL Rule: OpenClaw Startup Sequence

Detects the sequential execution of OpenClaw agent initialization. EQL is excellent for correlating the process creation:

Rule Type: EQL
Index: logs-endpoint.events.*, winlogbeat-*

sequence by host.id with maxspan=5m
  [process where event.type == "start" and process.name in ("node", "node.exe", "python", "python.exe", "bash", "cmd.exe") and process.args == "openclaw"]
  [network where network.protocol == "dns" and dns.question.name : ("*clawhub.com", "*moltbook.com", "api.openai.com", "api.anthropic.com")]


2. Lucene Query (Kibana Discover): Agent Artifact Creation

A quick hunt query for SOC analysts to drop into the Kibana Discover search bar to find endpoints that have the OpenClaw directory structure.

Search Bar Query:

event.category: "file" AND event.type: "creation" AND file.path: *\.openclaw*


3. EQL Rule: "ClawHavoc" Obfuscated Execution

Detects the specific obfuscation techniques used by malicious skills downloaded from ClawHub on macOS/Linux endpoints.

Rule Type: EQL

process where event.type == "start" and
  process.name in ("sh", "bash", "zsh") and
  process.command_line : (
    "*curl*|*sh*", 
    "*wget*-O*-*|*sh*", 
    "*base64*-d*|*sh*",
    "*glot.io*"
  ) and
  process.parent.command_line : "*openclaw*"


Remediation

Unauthorized autonomous agents violate enterprise data governance by processing sensitive code/data through unapproved LLM APIs. Identify the developer, remove the agent, and refer them to the approved Enterprise AI/LLM gateway policies outlined in the Move78 AgentClaw Controls Toolkit (ACT).