# A2A Threats Taxonomy

This file provides a comprehensive reference of all threat classifications used by the A2A Scanner, mapped to the standardized AI Security Taxonomy framework.

## Overview

The A2A Scanner maps all detected threats to the AI Security Taxonomy, which provides a standardized framework for classifying AI and agentic system security threats. Each finding includes:

- **Threat Name**: The specific threat detected by the analyzer
- **AITech Technique**: The technique ID and name from the AI Security Taxonomy
- **AISubtech Sub-Technique**: The sub-technique ID and name
- **Description**: Detailed explanation of the threat

## Threat Mappings by Analyzer

### LLM Analyzer Threats

| Threat Name | AITech | AITech Name | AISubtech | AISubtech Name | Description |
|-------------|--------|-------------|-----------|----------------|-------------|
| PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation | Attempts to alter LLM output by overriding instructions |
| CODE EXECUTION | AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomously generating or executing unauthorized code |
| DATA EXFILTRATION | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Unauthorized exposure of sensitive information |
| SUSPICIOUS AGENT ENDPOINT | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Endpoints pointing to suspicious external servers |
| CAPABILITY ABUSE | AITech-4.3 | Protocol Manipulation | AISubtech-4.3.5 | Capability Inflation | Declaring excessive or dangerous capabilities |

### YARA Analyzer Threats

| Threat Name | AITech | AITech Name | AISubtech | AISubtech Name | Description |
|-------------|--------|-------------|-----------|----------------|-------------|
| PROMPT INJECTION | AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation | Detects prompt injection patterns in agent cards |
| CODE EXECUTION | AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Detects code execution capabilities or patterns |
| DATA EXFILTRATION | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Detects suspicious external endpoints |
| AGENT CARD SPOOFING | AITech-3.1 | Masquerading / Impersonation | AISubtech-3.1.2 | Trusted Agent Spoofing | Detects typosquatting and character substitution |
| AGENT PROFILE TAMPERING | AITech-5.2 | Configuration Persistence | AISubtech-5.2.1 | Agent Profile Tampering | Detects false verification claims |
| CREDENTIAL THEFT | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Detects hardcoded API keys and tokens |
| UNAUTHORIZED NETWORK ACCESS | AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.3 | Unauthorized Network Access | Detects insecure HTTP or TLS bypass |
| CONTEXT BOUNDARY ATTACKS | AITech-4.2 | Context Boundary Attacks | - | - | Detects malicious instructions in metadata |
| CAPABILITY INFLATION | AITech-4.3 | Protocol Manipulation | AISubtech-4.3.5 | Capability Inflation | Detects dangerous capability declarations |
| INSUFFICIENT ACCESS CONTROLS | AITech-14.1 | Unauthorized Access | AISubtech-14.1.2 | Insufficient Access Controls | Detects capabilities without constraints |

### Heuristic Analyzer Threats

| Threat Name | AITech | AITech Name | AISubtech | AISubtech Name | Description |
|-------------|--------|-------------|-----------|----------------|-------------|
| AGENT CARD SPOOFING | AITech-3.1 | Masquerading / Impersonation | AISubtech-3.1.2 | Trusted Agent Spoofing | Detects typosquatting or missing required fields |
| INSECURE NETWORK ACCESS | AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.3 | Unauthorized Network Access | Detects insecure HTTP URLs in endpoints |
| SUSPICIOUS AGENT ENDPOINT | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Detects suspicious endpoint URL patterns |
| DATA EXFILTRATION | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Detects potential data exfiltration risks |
| CODE EXECUTION | AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Detects dangerous code execution capabilities |

### Endpoint Analyzer Threats

| Threat Name | AITech | AITech Name | AISubtech | AISubtech Name | Description |
|-------------|--------|-------------|-----------|----------------|-------------|
| ENDPOINT UNREACHABLE | AITech-6.1 | Network/Service Disruption | AISubtech-6.1.1 | Disruption of Availability | Agent endpoint unreachable or not responding |
| AGENT CARD SPOOFING | AITech-3.1 | Masquerading / Impersonation | AISubtech-3.1.2 | Trusted Agent Spoofing | Missing required fields or invalid structure |
| SUSPICIOUS AGENT ENDPOINT | AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Endpoint URL contains suspicious patterns |

### Spec Compliance Analyzer Threats

| Threat Name | AITech | AITech Name | AISubtech | AISubtech Name | Description |
|-------------|--------|-------------|-----------|----------------|-------------|
| MISSING REQUIRED FIELD | AITech-3.1 | Masquerading / Impersonation | AISubtech-3.1.2 | Trusted Agent Spoofing | Missing required fields per A2A spec |
| INVALID CAPABILITIES TYPE | AITech-4.3 | Protocol Manipulation | AISubtech-4.3.5 | Capability Inflation | Invalid capabilities type or structure |
| INVALID FIELD TYPE | AITech-4.3 | Protocol Manipulation | AISubtech-4.3.5 | Capability Inflation | Incorrect field data type |

## AI Security Taxonomy

### Core Threats Referenced

| Technique | Technique Name | Sub-Technique | Sub-Technique Name | Description |
|-----------|----------------|---------------|--------------------|-----------| 
| AITech-1.1 | Direct Prompt Injection | AISubtech-1.1.1 | Instruction Manipulation | Override model instructions via direct input |
| AITech-3.1 | Masquerading / Impersonation | AISubtech-3.1.2 | Trusted Agent Spoofing | Impersonate trusted agents via typosquatting |
| AITech-4.2 | Context Boundary Attacks | - | - | Exploit context boundaries to inject content |
| AITech-4.3 | Protocol Manipulation | AISubtech-4.3.5 | Capability Inflation | Declare excessive or unauthorized capabilities |
| AITech-5.2 | Configuration Persistence | AISubtech-5.2.1 | Agent Profile Tampering | Tamper with agent configuration or metadata |
| AITech-6.1 | Network/Service Disruption | AISubtech-6.1.1 | Disruption of Availability | Disrupt AI service availability |
| AITech-7.1 | Server Side Injection | AISubtech-7.1.1 | Message Injection | Inject malicious content into server messages |
| AITech-8.2 | Data Exfiltration / Exposure | AISubtech-8.2.3 | Data Exfiltration via Tooling | Unauthorized data exposure via agent tools |
| AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.1 | Code Execution | Autonomous unauthorized code execution |
| AITech-9.1 | Model/Agentic System Manipulation | AISubtech-9.1.3 | Unauthorized Network Access | Access network resources without authorization |
| AITech-14.1 | Unauthorized Access | AISubtech-14.1.2 | Insufficient Access Controls | Inadequate access controls or permissions |

## Accessing Taxonomy Information

### CLI Output

When using the CLI, taxonomy information is displayed for each finding from all analyzers:

```bash
# Scan with all analyzers
a2a-scanner scan-card agent_card.json

# Scan with specific analyzers
a2a-scanner scan-card agent_card.json --analyzers yara llm heuristic
```

Output includes:
```
┌────────────┬──────────────────────┬──────────────────┬──────────────┬─────────────────────┬──────────┐
│ Analyzer   │ Location             │ Threat Name      │ AITech       │ AISubtech           │ Severity │
├────────────┼──────────────────────┼──────────────────┼──────────────┼─────────────────────┼──────────┤
│ YARA       │ description          │ PROMPT INJECTION │ AITech-1.1   │ AISubtech-1.1.1     │ HIGH     │
│            │                      │                  │ Direct       │ Instruction         │          │
│            │                      │                  │ Prompt       │ Manipulation...     │          │
│            │                      │                  │ Injection    │                     │          │
└────────────┴──────────────────────┴──────────────────┴──────────────┴─────────────────────┴──────────┘
```

### Programmatic Access

Access taxonomy information programmatically:

```python
from a2ascanner import Scanner

# Run scan
scanner = Scanner(config=config)
result = await scanner.scan_agent_card(card=agent_card)

# Access taxonomy for each finding
for finding in result.findings:
    finding_dict = finding.to_dict()
    print(f"Threat: {finding.threat_name}")
    print(f"Technique: {finding_dict.get('aitech')} - {finding_dict.get('aitech_name')}")
    print(f"Sub-Technique: {finding_dict.get('aisubtech')} - {finding_dict.get('aisubtech_name')}")
    print(f"Description: {finding_dict.get('description')}")
```

### JSON Output

The scanner returns taxonomy in a structured format:

```json
{
  "findings": [
    {
      "threat_name": "PROMPT INJECTION",
      "severity": "HIGH",
      "analyzer": "YARA",
      "aitech": "AITech-1.1",
      "aitech_name": "Direct Prompt Injection",
      "aisubtech": "AISubtech-1.1.1",
      "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
      "description": "Adversarial attack that attempts to alter or control...",
      "summary": "Detects potential prompt injection patterns",
      "details": {
        "field": "description",
        "matched_strings": [...]
      }
    }
  ]
}
```

## References

- [A2A Protocol Specification](https://github.com/a2a-project)
- [A2A Scanner Documentation](https://github.com/cisco-ai-defense/a2a-scanner)
- [Cisco AI Defense](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
