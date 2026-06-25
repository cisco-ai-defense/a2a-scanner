# ATR (Agent Threat Rules) Rule Pack for a2a-scanner

Source: Agent Threat Rules (ATR), https://github.com/Agent-Threat-Rule/agent-threat-rules
License: MIT
Pack version: 0.1.0
Coverage: 30 signatures across 6 A2A threat categories (241 regex patterns)

## Overview

This pack maps open-source detection rules from the Agent Threat Rules (ATR)
project onto the Agent-to-Agent (A2A) protocol threat surface that a2a-scanner
targets: agent cards, inter-agent messages, capability declarations, tool
descriptions, and registry entries.

Every regex pattern in this pack is extracted verbatim from an ATR rule file.
No patterns were invented for this pack. Each signature records its originating
ATR rule id (`atr_id`) and a direct link to the source YAML (`atr_url`).
Patterns that did not compile under Python's `re` engine were skipped so that
the pack loads and validates cleanly through a2a-scanner's signature loader.

## Threat categories

agent_impersonation (5 signatures)
  Agents impersonating other agents, system components, or supervisor roles,
  plus inter-agent message spoofing and casual authority escalation.
  ATR-2026-00117, ATR-2026-00076, ATR-2026-00030, ATR-2026-00132, ATR-2026-00139

message_injection (4 signatures)
  Prompt and instruction injection carried inside inter-agent messages,
  goal hijacking, and skill scope hijacking.
  ATR-2026-00116, ATR-2026-00001, ATR-2026-00032, ATR-2026-00164

multi_agent_attack (4 signatures)
  Consensus and voting manipulation, cross-agent privilege escalation, and
  social engineering propagated through agents.
  ATR-2026-00108, ATR-2026-00074, ATR-2026-00119, ATR-2026-00077

capability_abuse (7 signatures)
  Tool and capability abuse exposed through agent capability declarations and
  tool descriptions: SSRF, tool output injection, consent bypass, hidden safety
  bypass, silent action concealment, schema contradiction, and unauthorized
  financial actions.
  ATR-2026-00013, ATR-2026-00011, ATR-2026-00100, ATR-2026-00103,
  ATR-2026-00105, ATR-2026-00106, ATR-2026-00098

data_leakage (6 signatures)
  Sensitive context and credential exfiltration through agent artifacts:
  API key exposure, system prompt and training-data extraction, OAuth token
  abuse, environment variable harvesting, disguised analytics exfiltration,
  and markdown image exfiltration.
  ATR-2026-00021, ATR-2026-00275, ATR-2026-00114, ATR-2026-00115,
  ATR-2026-00102, ATR-2026-00261

agent_card_spoofing (4 signatures)
  Discovery poisoning and impersonation in agent cards: skill impersonation,
  fork and clone identity claims, registry poisoning, and advertised scope
  creep.
  ATR-2026-00060, ATR-2026-00134, ATR-2026-00096, ATR-2026-00041

## Usage

This is an additional (non-core) pack. Enable it alongside the built-in core
rules with the --rule-packs flag:

    a2a-scanner scan agent_card.json --rule-packs atr

List available packs:

    a2a-scanner scan agent_card.json --rule-packs list

Validate the pack manifest and signatures:

    a2a-scanner validate-rules

## Layout

    a2ascanner/data/packs/atr/
      pack.yaml                         Pack manifest with all rule entries
      README.md                         This file
      signatures/
        atr_agent_impersonation.yaml
        atr_message_injection.yaml
        atr_multi_agent_attack.yaml
        atr_capability_abuse.yaml
        atr_data_leakage.yaml
        atr_agent_card_spoofing.yaml
      tests/
        malicious_agent_card.json       Positive control fixture
        benign_agent_card.json          Negative control fixture

## Tests

tests/test_atr_pack.py verifies that the pack loads and is discoverable, that
the malicious control fixture triggers ATR signatures (including agent identity
spoofing and A2A message injection), and that the benign control fixture
produces zero ATR findings.

## Notes on scope

Rules were selected for the agent-card / inter-agent-message attack surface and
checked against benign agent-card text to avoid false positives on normal
self-description (for example, "you are a helpful assistant" or "your role is
to ..."). Rules that fired on benign self-description were intentionally left
out of this pack.

The SSRF rule (ATR-2026-00013) flags URL shorteners (bit.ly, t.co, and
similar) when they appear in agent artifacts. This is intentional: a shortened
link in a published agent card or endpoint obscures the real destination and is
a recognized SSRF and exfiltration obfuscation vector. Reviewers who consider
shorteners acceptable in their agent cards can disable this rule via policy.

## Provenance

Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
License: MIT
The full ATR ruleset is broader than this pack; only rules whose attack surface
is the A2A protocol are mapped here.
