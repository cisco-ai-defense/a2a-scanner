# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Threat taxonomy module for A2A Scanner.

This module provides threat definitions and mappings between analyzer-specific
threat names and the standardized AI Security Taxonomy classifications, including
severity levels, descriptions, and taxonomy mappings (AITech/AISubtech).
"""

from typing import Dict, Any, Optional


# =============================================================================
# SECTION 1: THREAT DEFINITIONS
# =============================================================================

# Flat threat definitions with AI Security Taxonomy mappings
# Based on Complete Revised Threat Catalog from A2A_THREAT_TAXONOMY_MAPPING_REVISED.md
THREAT_DEFINITIONS = {
    # Threats with taxonomy mappings (17 threats)
    "AGENT CARD SPOOFING": {
        "description": "Agent falsely claims identity through typosquatting, homoglyphs, or domain spoofing to masquerade as trusted agents",
        "severity": "HIGH",
        "aitech": "AITech-3.1",
        "aitech_name": "Masquerading / Obfuscation / Impersonation",
        "aisubtech": "AISubtech-3.1.2",
        "aisubtech_name": "Trusted Agent Spoofing",
    },
    "AGENT PROFILE TAMPERING": {
        "description": "Unauthorized alteration of agent identity, trust attributes, or privilege claims in agent profiles",
        "severity": "HIGH",
        "aitech": "AITech-5.2",
        "aitech_name": "Configuration Persistence",
        "aisubtech": "AISubtech-5.2.1",
        "aisubtech_name": "Agent Profile Tampering",
    },
    "PROMPT INJECTION": {
        "severity": "HIGH",
        "aitech": "AITech-1.1",
        "aitech_name": "Direct Prompt Injection",
        "aisubtech": "AISubtech-1.1.1",
        "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
        "description": "Explicit attempts to override, replace, or modify agent instructions through embedded directives or commands",
    },
    "CODE EXECUTION": {
        "severity": "CRITICAL",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.1",
        "aisubtech_name": "Code Execution",
        "description": "Execution of arbitrary code, shell commands, or unsafe operations that compromise system security",
    },
    "DATA EXFILTRATION": {
        "severity": "HIGH",
        "aitech": "AITech-8.2",
        "aitech_name": "Data Exfiltration / Exposure",
        "aisubtech": "AISubtech-8.2.3",
        "aisubtech_name": "Data Exfiltration via Agent Tooling",
        "description": "Unauthorized extraction or exposure of sensitive data through malicious endpoints, tools, or agent behaviors",
    },
    "CREDENTIAL THEFT": {
        "description": "Hardcoded credentials, credential harvesting, or unauthorized credential extraction attempts",
        "severity": "HIGH",
        "aitech": "AITech-14.1",
        "aitech_name": "Unauthorized Access",
        "aisubtech": "AISubtech-14.1.1",
        "aisubtech_name": "Credential Theft",
    },
    "CAPABILITY INFLATION": {
        "description": "Artificial capability expansion beyond actual limits through unrealistic or exaggerated capability claims",
        "severity": "MEDIUM",
        "aitech": "AITech-4.3",
        "aitech_name": "Protocol Manipulation",
        "aisubtech": "AISubtech-4.3.5",
        "aisubtech_name": "Capability Inflation",
    },
    "INSUFFICIENT ACCESS CONTROLS": {
        "description": "Missing or inadequate access controls, dangerous capability combinations, or unconstrained privileges",
        "severity": "HIGH",
        "aitech": "AITech-14.1",
        "aitech_name": "Unauthorized Access",
        "aisubtech": "AISubtech-14.1.2",
        "aisubtech_name": "Insufficient Access Controls",
    },
    "UNAUTHORIZED NETWORK ACCESS": {
        "description": "Unauthorized or unsolicited network access including SSRF, insecure HTTP, or agent-in-the-middle attacks",
        "severity": "HIGH",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
    },
    "UNAUTHORIZED SYSTEM ACCESS": {
        "description": "Path traversal, unauthorized file system access, or access to sensitive system files without authorization",
        "severity": "HIGH",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.2",
        "aisubtech_name": "Unauthorized or Unsolicited System Access",
    },
    "SYSTEM INFORMATION LEAKAGE": {
        "description": "Exposure of system information, environment variables, or internal system details through logging or leakage",
        "severity": "MEDIUM",
        "aitech": "AITech-8.3",
        "aitech_name": "Information Disclosure",
        "aisubtech": "AISubtech-8.3.2",
        "aisubtech_name": "System Information Leakage",
    },
    "CONTEXT BOUNDARY ATTACKS": {
        "description": "Exploitation of context boundaries through hidden instructions in metadata or unsigned messages",
        "severity": "MEDIUM",
        "aitech": "AITech-4.2",
        "aitech_name": "Context Boundary Attacks",
        "aisubtech": "AISubtech-4.2.2",
        "aisubtech_name": "Session Boundary Violation",
    },
    "MEMORY SYSTEM PERSISTENCE": {
        "description": "Persistent instruction injection or memory contamination to modify future agent behavior permanently",
        "severity": "HIGH",
        "aitech": "AITech-5.1",
        "aitech_name": "Memory System Persistence",
        "aisubtech": "AISubtech-5.1.1",
        "aisubtech_name": "Long-term / Short-term Memory Injection",
    },
    "MEMORY SYSTEM CORRUPTION": {
        "description": "Context manipulation or memory corruption attempts targeting agent conversation history or state",
        "severity": "MEDIUM",
        "aitech": "AITech-7.2",
        "aitech_name": "Memory System Corruption",
        "aisubtech": "",
        "aisubtech_name": "",
    },
    "DEPENDENCY NAME SQUATTING": {
        "description": "Registry squatting and mass registration patterns suggesting tool/agent namespace squatting",
        "severity": "MEDIUM",
        "aitech": "AITech-9.3",
        "aitech_name": "Dependency / Plugin Compromise",
        "aisubtech": "AISubtech-9.3.2",
        "aisubtech_name": "Dependency Name Squatting (Tools/Servers)",
    },
    "DISRUPTION OF AVAILABILITY": {
        "description": "Resource exhaustion, DoS attacks via excessive loops, fanout, or recursive calls",
        "severity": "HIGH",
        "aitech": "AITech-13.1",
        "aitech_name": "Disruption of Availability",
        "aisubtech": "AISubtech-13.1.3",
        "aisubtech_name": "Model Denial of Service",
    },
    "PROTOCOL MANIPULATION": {
        "description": "Protocol manipulation through suspicious template patterns or schema inconsistencies",
        "severity": "MEDIUM",
        "aitech": "AITech-4.3",
        "aitech_name": "Protocol Manipulation",
        "aisubtech": "AISubtech-4.3.1",
        "aisubtech_name": "Schema Inconsistencies",
    },
    "PROMPT META EXTRACTION": {
        "description": "Attempts to extract or leak system prompts, instructions, or agent configuration details",
        "severity": "MEDIUM",
        "aitech": "AITech-8.4",
        "aitech_name": "Prompt/Meta Extraction",
        "aisubtech": "AISubtech-8.4.1",
        "aisubtech_name": "System LLM Prompt Leakage",
    },
    "ROUTING MANIPULATION": {
        "severity": "HIGH",
        "aitech": "",
        "aitech_name": "",
        "aisubtech": "",
        "aisubtech_name": "",
        "description": "Attempts to manipulate routing decisions, agent selection logic, or task allocation for unauthorized preference",
    },
    # Legacy/other analyzer threats (for backward compatibility)
    "AGENT IMPERSONATION": {
        "severity": "HIGH",
        "aitech": "AITech-3.1",
        "aitech_name": "Masquerading / Obfuscation / Impersonation",
        "aisubtech": "AISubtech-3.1.2",
        "aisubtech_name": "Trusted Agent Spoofing",
        "description": "Agent falsely claims identity, privileges, or capabilities of another trusted agent to gain unauthorized access or routing",
    },
    "MESSAGE INJECTION": {
        "severity": "HIGH",
        "aitech": "AITech-1.1",
        "aitech_name": "Direct Prompt Injection",
        "aisubtech": "AISubtech-1.1.1",
        "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
        "description": "Injection of malicious directives, hidden commands, or manipulated content into agent-to-agent messages or SSE streams",
    },
    "SUSPICIOUS AGENT ENDPOINT": {
        "severity": "HIGH",
        "aitech": "AITech-8.2",
        "aitech_name": "Data Exfiltration / Exposure",
        "aisubtech": "AISubtech-8.2.3",
        "aisubtech_name": "Data Exfiltration via Agent Tooling",
        "description": "Agent endpoints pointing to suspicious or malicious external servers that may exfiltrate data or manipulate agent behavior",
    },
    "CAPABILITY ABUSE": {
        "severity": "MEDIUM",
        "aitech": "AITech-4.3",
        "aitech_name": "Protocol Manipulation",
        "aisubtech": "AISubtech-4.3.5",
        "aisubtech_name": "Capability Inflation",
        "description": "Tools or agents claiming excessive capabilities, overprivileged access, or exaggerated functionality to gain routing preference",
    },
    "CONTEXT POISONING": {
        "severity": "HIGH",
        "aitech": "AITech-5.1",
        "aitech_name": "Memory System Persistence",
        "aisubtech": "AISubtech-5.1.1",
        "aisubtech_name": "Long-term / Short-term Memory Injection",
        "description": "Persistent instruction injection or memory contamination attempts to modify future agent behavior",
    },
    # Heuristic analyzer specific threats
    "SUSPICIOUS URL": {
        "severity": "MEDIUM",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "URL with suspicious patterns, domains, or structures indicating phishing or command-and-control servers",
    },
    "CLOUD METADATA ACCESS": {
        "severity": "HIGH",
        "aitech": "AITech-8.2",
        "aitech_name": "Data Exfiltration / Exposure",
        "aisubtech": "AISubtech-8.2.3",
        "aisubtech_name": "Data Exfiltration via Agent Tooling",
        "description": "Attempts to access cloud provider metadata endpoints that expose sensitive credentials or instance information",
    },
    "COMMAND EXECUTION": {
        "severity": "HIGH",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.1",
        "aisubtech_name": "Code Execution",
        "description": "Patterns indicating shell command execution or arbitrary code execution attempts",
    },
    "CREDENTIAL HARVESTING": {
        "severity": "HIGH",
        "aitech": "AITech-14.1",
        "aitech_name": "Unauthorized Access",
        "aisubtech": "AISubtech-14.1.1",
        "aisubtech_name": "Credential Theft",
        "description": "Attempts to extract credentials, API keys, passwords, or other authentication material",
    },
    "INSECURE TRANSPORT": {
        "severity": "MEDIUM",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "Use of insecure protocols or transport mechanisms that expose data to interception",
    },
    # SSE analyzer specific threats
    "DIRECTIVE INJECTION": {
        "severity": "HIGH",
        "aitech": "AITech-1.1",
        "aitech_name": "Direct Prompt Injection",
        "aisubtech": "AISubtech-1.1.1",
        "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
        "description": "Injection of override directives like 'IGNORE PREVIOUS INSTRUCTIONS' in SSE stream events",
    },
    "HIDDEN INSTRUCTIONS": {
        "severity": "MEDIUM",
        "aitech": "AITech-4.2",
        "aitech_name": "Context Boundary Attacks",
        "aisubtech": "",
        "aisubtech_name": "",
        "description": "Hidden commands or instructions embedded in SSE event data, metadata, or custom fields",
    },
    "ROLE MANIPULATION": {
        "severity": "HIGH",
        "aitech": "AITech-1.1",
        "aitech_name": "Direct Prompt Injection",
        "aisubtech": "AISubtech-1.1.1",
        "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
        "description": "Unauthorized role changes or privilege escalation attempts in SSE stream messages",
    },
    # Endpoint analyzer specific threats
    "ENDPOINT UNREACHABLE": {
        "severity": "HIGH",
        "aitech": "AITech-13.1",
        "aitech_name": "Disruption of Availability",
        "aisubtech": "AISubtech-13.1.3",
        "aisubtech_name": "Model Denial of Service",
        "description": "Agent endpoint is unreachable, not responding, or experiencing connectivity issues",
    },
    "INSECURE HTTP": {
        "severity": "HIGH",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "Endpoint uses insecure HTTP protocol instead of HTTPS, exposing communications to interception",
    },
    "MISSING AGENT CARD": {
        "severity": "MEDIUM",
        "aitech": "AITech-4.3",
        "aitech_name": "Protocol Manipulation",
        "aisubtech": "AISubtech-4.3.1",
        "aisubtech_name": "Schema Inconsistencies",
        "description": "Agent endpoint does not provide required agent card at /.well-known/agent location",
    },
    "MISSING SECURITY HEADERS": {
        "severity": "MEDIUM",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "Critical security headers (CSP, HSTS, X-Frame-Options) missing from endpoint responses",
    },
    "CORS MISCONFIGURATION": {
        "severity": "MEDIUM",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "Overly permissive CORS configuration allowing requests from any origin",
    },
    "SSL CERTIFICATE ISSUES": {
        "severity": "HIGH",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "Invalid, expired, or self-signed SSL certificate detected on agent endpoint",
    },
    "DISCOVERY POISONING": {
        "severity": "MEDIUM",
        "aitech": "AITech-9.3",
        "aitech_name": "Dependency / Plugin Compromise",
        "aisubtech": "AISubtech-9.3.2",
        "aisubtech_name": "Dependency Name Squatting (Tools/Servers)",
        "description": "Manipulation of agent discovery mechanisms through mass registration, squatting, or registry poisoning",
    },
    "INSECURE NETWORK ACCESS": {
        "severity": "MEDIUM",
        "aitech": "AITech-9.1",
        "aitech_name": "Model or Agentic System Manipulation",
        "aisubtech": "AISubtech-9.1.3",
        "aisubtech_name": "Unauthorized or Unsolicited Network Access",
        "description": "Use of insecure protocols or network configurations that expose communications to interception",
    },
}


class ThreatMapping:
    """Simplified analyzer-specific threat mappings.

    Each analyzer only defines severity overrides. All other details (description,
    aitech, aisubtech, etc.) come from THREAT_DEFINITIONS.
    """

    # YARA Analyzer Threats - only severity overrides
    YARA_THREATS = {
        # Threats detected by agent_card_spoofing.yara and agent_impersonation.yara
        "AGENT CARD SPOOFING": {
            "scanner_category": "AGENT IMPERSONATION",
            "severity": "HIGH",
        },
        "AGENT PROFILE TAMPERING": {
            "scanner_category": "AGENT IMPERSONATION",
            "severity": "HIGH",
        },
        "DEPENDENCY NAME SQUATTING": {
            "scanner_category": "DISCOVERY POISONING",
            "severity": "MEDIUM",
        },
        # Threats detected by prompt_injection.yara
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
        },
        "PROTOCOL MANIPULATION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
        },
        "MEMORY SYSTEM CORRUPTION": {
            "scanner_category": "CONTEXT POISONING",
            "severity": "HIGH",
        },
        "PROMPT META EXTRACTION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "MEDIUM",
        },
        # Threats detected by message_injection.yara
        "CODE EXECUTION": {
            "scanner_category": "CODE EXECUTION",
            "severity": "HIGH",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
        },
        "CONTEXT BOUNDARY ATTACKS": {
            "scanner_category": "MESSAGE INJECTION",
            "severity": "HIGH",
        },
        "MEMORY SYSTEM PERSISTENCE": {
            "scanner_category": "CONTEXT POISONING",
            "severity": "HIGH",
        },
        # Threats detected by capability_abuse.yara
        "CAPABILITY INFLATION": {
            "scanner_category": "CAPABILITY ABUSE",
            "severity": "MEDIUM",
        },
        "INSUFFICIENT ACCESS CONTROLS": {
            "scanner_category": "CAPABILITY ABUSE",
            "severity": "HIGH",
        },
        # Threats detected by data_leakage.yara
        "CREDENTIAL THEFT": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
        },
        "SYSTEM INFORMATION LEAKAGE": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "MEDIUM",
        },
        # Threats detected by routing_manipulation.yara
        "ROUTING MANIPULATION": {
            "scanner_category": "ROUTING MANIPULATION",
            "severity": "HIGH",
        },
        "DISRUPTION OF AVAILABILITY": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "HIGH",
        },
        # Threats detected by unauthorized_network_access.yara
        "UNAUTHORIZED NETWORK ACCESS": {
            "scanner_category": "NETWORK SECURITY",
            "severity": "HIGH",
        },
        # Threats detected by suspicious_agent_endpoint.yara (legacy - now split)
        "UNAUTHORIZED SYSTEM ACCESS": {
            "scanner_category": "CODE EXECUTION",
            "severity": "HIGH",
        },
    }

    # Heuristic Analyzer Threats - only severity overrides
    HEURISTIC_THREATS = {
        "AGENT CARD SPOOFING": {
            "scanner_category": "AGENT CARD SPOOFING",
            "severity": "MEDIUM",
        },
        "SUSPICIOUS AGENT ENDPOINT": {
            "scanner_category": "SUSPICIOUS AGENT ENDPOINT",
            "severity": "MEDIUM",
        },
        "CLOUD METADATA ACCESS": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
        },
        "CODE EXECUTION": {
            "scanner_category": "CODE EXECUTION",
            "severity": "HIGH",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
        },
        "INSECURE NETWORK ACCESS": {
            "scanner_category": "NETWORK SECURITY",
            "severity": "MEDIUM",
        },
    }

    # LLM Analyzer Threats - only severity overrides
    LLM_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
        },
        "AGENT IMPERSONATION": {
            "scanner_category": "AGENT IMPERSONATION",
            "severity": "HIGH",
        },
        "AGENT CARD SPOOFING": {
            "scanner_category": "AGENT CARD SPOOFING",
            "severity": "HIGH",
        },
        "MESSAGE INJECTION": {
            "scanner_category": "MESSAGE INJECTION",
            "severity": "HIGH",
        },
        "CONTEXT POISONING": {
            "scanner_category": "CONTEXT POISONING",
            "severity": "MEDIUM",
        },
        "SUSPICIOUS AGENT ENDPOINT": {
            "scanner_category": "SUSPICIOUS AGENT ENDPOINT",
            "severity": "HIGH",
        },
        "CAPABILITY ABUSE": {
            "scanner_category": "CAPABILITY ABUSE",
            "severity": "MEDIUM",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
        },
        "CODE EXECUTION": {
            "scanner_category": "CODE EXECUTION",
            "severity": "HIGH",
        },
        "ROUTING MANIPULATION": {
            "scanner_category": "ROUTING MANIPULATION",
            "severity": "HIGH",
        },
    }

    # SSE Analyzer Threats - only severity overrides
    SSE_THREATS = {
        "MESSAGE INJECTION": {
            "scanner_category": "MESSAGE INJECTION",
            "severity": "HIGH",
        },
        "ROLE MANIPULATION": {
            "scanner_category": "MESSAGE INJECTION",
            "severity": "HIGH",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
        },
        "CONTEXT POISONING": {
            "scanner_category": "CONTEXT POISONING",
            "severity": "HIGH",
        },
    }

    # Endpoint Analyzer Threats
    ENDPOINT_THREATS = {
        "ENDPOINT UNREACHABLE": {
            "scanner_category": "AVAILABILITY",
            "severity": "HIGH",
        },
        "INSECURE HTTP": {
            "scanner_category": "NETWORK SECURITY",
            "severity": "HIGH",
        },
        "MISSING AGENT CARD": {
            "scanner_category": "SPECIFICATION VIOLATION",
            "severity": "MEDIUM",
        },
        "MISSING SECURITY HEADERS": {
            "scanner_category": "NETWORK SECURITY",
            "severity": "MEDIUM",
        },
        "CORS MISCONFIGURATION": {
            "scanner_category": "NETWORK SECURITY",
            "severity": "MEDIUM",
        },
        "SSL CERTIFICATE ISSUES": {
            "scanner_category": "NETWORK SECURITY",
            "severity": "HIGH",
        },
    }

    SPEC_THREATS = {
        "MISSING REQUIRED FIELD": {
            "scanner_category": "SPECIFICATION VIOLATION",
            "severity": "MEDIUM",
        },
        "INVALID CAPABILITIES TYPE": {
            "scanner_category": "SPECIFICATION VIOLATION",
            "severity": "MEDIUM",
        },
        "INVALID URL FORMAT": {
            "scanner_category": "SPECIFICATION VIOLATION",
            "severity": "LOW",
        },
        "INVALID SKILL STRUCTURE": {
            "scanner_category": "SPECIFICATION VIOLATION",
            "severity": "MEDIUM",
        },
    }

    @classmethod
    def get_threat_mapping(cls, analyzer: str, threat_name: str) -> Dict[str, Any]:
        """LEGACY: Kept for backward compatibility.

        Now just returns severity overrides. Use THREAT_DEFINITIONS + get_threat_info() instead.
        """
        analyzer_map = {
            "yara": cls.YARA_THREATS,
            "heuristic": cls.HEURISTIC_THREATS,
            "llm": cls.LLM_THREATS,
            "sse": cls.SSE_THREATS,
            "endpoint": cls.ENDPOINT_THREATS,
            "spec": cls.SPEC_THREATS,
            "speccompliance": cls.SPEC_THREATS,
        }

        analyzer_lower = analyzer.lower()
        if analyzer_lower not in analyzer_map:
            raise ValueError(f"Unknown analyzer: {analyzer}")

        threats = analyzer_map[analyzer_lower]
        threat_upper = threat_name.upper()

        if threat_upper not in threats:
            # No analyzer-specific override, return empty dict
            return {}

        return threats[threat_upper]


# =============================================================================
# SECTION 2: SIMPLIFIED MAPPINGS & FUNCTIONS
# =============================================================================


# Legacy simplified mappings (kept for backward compatibility)
def _create_simple_mapping(threat_dict: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    """DEPRECATED: Create simple threat name to category mapping."""
    return {
        threat_name: threat_info.get("scanner_category", "UNKNOWN")
        for threat_name, threat_info in threat_dict.items()
    }


# Keep these for any legacy code that might use them
YARA_THREAT_MAPPING = {}  # Empty - use THREAT_DEFINITIONS
HEURISTIC_THREAT_MAPPING = {}
LLM_THREAT_MAPPING = {}
SSE_THREAT_MAPPING = {}
ENDPOINT_THREAT_MAPPING = {}


def get_threat_info(analyzer: str, threat_name: str) -> Optional[Dict[str, Any]]:
    """
    Get complete threat information for a given analyzer and threat name.

    Args:
        analyzer: Analyzer name ('yara', 'heuristic', 'llm', 'sse', 'endpoint')
        threat_name: Threat name from the analyzer

    Returns:
        Complete threat information dict with taxonomy mappings or None if not found
    """
    # First try the new flat THREAT_DEFINITIONS
    threat_def = THREAT_DEFINITIONS.get(threat_name)
    if threat_def:
        # Get analyzer-specific severity override if exists
        severity_override = ThreatMapping.get_threat_mapping(analyzer, threat_name)

        return {
            "severity": (
                severity_override.get("severity", threat_def["severity"])
                if severity_override
                else threat_def["severity"]
            ),
            "description": threat_def["description"],
            "scanner_category": threat_name,
            "aitech": threat_def.get("aitech", ""),
            "aitech_name": threat_def.get("aitech_name", ""),
            "aisubtech": threat_def.get("aisubtech", ""),
            "aisubtech_name": threat_def.get("aisubtech_name", ""),
        }

    # Not found
    return None


def normalize_threat_category(threat_name: str) -> str:
    """
    Normalize a threat name to its scanner category.

    Args:
        threat_name: The threat name to normalize

    Returns:
        Normalized category string
    """
    # First check new THREAT_DEFINITIONS
    if threat_name in THREAT_DEFINITIONS:
        return threat_name

    return "UNKNOWN"


def get_threat_severity(analyzer: str, threat_name: str) -> str:
    """
    Get the severity level for a specific threat.

    Args:
        analyzer: Analyzer name
        threat_name: Threat name

    Returns:
        Severity string ('HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
    """
    info = get_threat_info(analyzer, threat_name)
    if info:
        return info.get("severity", "UNKNOWN")
    return "UNKNOWN"
