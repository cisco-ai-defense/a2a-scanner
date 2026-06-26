# ATR (Agent Threat Rules) Rule Pack for a2a-scanner

Source: Agent Threat Rules (ATR), https://github.com/Agent-Threat-Rule/agent-threat-rules
License: MIT
Pack version: 0.2.0
ATR source commit: 9f0991c34f359894e79afe2a7657b4c314b34f83 (655-rule set)
Coverage: 24 signatures across 6 A2A threat categories (182 regex patterns)

## Overview

This pack maps open-source detection rules from the Agent Threat Rules (ATR)
project onto the Agent-to-Agent (A2A) protocol threat surface that a2a-scanner
targets: agent cards, inter-agent messages, capability declarations, tool
descriptions, and registry entries.

Patterns are sourced from ATR rule files at the pinned commit above. Most are
extracted verbatim; a small number were anchored (tightened) for the A2A
agent-card surface to remove false positives on normal agent self-description.
Every anchored rule is listed below under "False-positive hardening", and every
signature records its originating ATR rule id (`atr_id`) and a direct link to
the source YAML (`atr_url`). Patterns that did not compile under Python's `re`
engine were skipped so that the pack loads and validates cleanly through
a2a-scanner's signature loader.

## Measured false-positive profile

This pack produces zero ATR findings on the included realistic benign
agent-card corpus of 6 cards (`tests/benign_corpus/`: a DevOps/CI runner, a
database-admin assistant, a customer-support agent, a billing reporter, a
marketing/link agent, and a data-analytics agent). Those cards are written in
the natural, conversational language real agent cards use, including phrases
that previously produced false positives ("I will also check", "change of
plans", "trust me", "action required:", "payment successful", "status: failed;
will retry"). The 0-FP result is verified by `tests/test_atr_pack.py`.

This is a measured property of this benign corpus, not a universal guarantee.
No regex rule pack is free of false positives on all possible inputs. Treat ATR
findings as signals for review, and tune via policy for your own agent fleet.

## Threat categories

agent_impersonation (4 signatures)
  Agents impersonating other agents, system components, or supervisor roles,
  plus inter-agent message spoofing and casual authority data redirect.
  ATR-2026-00117, ATR-2026-00076, ATR-2026-00030, ATR-2026-00139

message_injection (3 signatures)
  Prompt and instruction injection carried inside inter-agent messages and
  skill scope hijacking.
  ATR-2026-00116, ATR-2026-00001, ATR-2026-00164

multi_agent_attack (2 signatures)
  Consensus and voting manipulation, and cross-agent privilege escalation.
  ATR-2026-00108, ATR-2026-00074

capability_abuse (6 signatures)
  Tool and capability abuse exposed through agent capability declarations and
  tool descriptions: SSRF, consent bypass, hidden safety bypass, silent action
  concealment, schema contradiction, and unauthorized financial actions.
  ATR-2026-00013, ATR-2026-00100, ATR-2026-00103, ATR-2026-00105,
  ATR-2026-00106, ATR-2026-00098

data_leakage (6 signatures)
  Sensitive context and credential exfiltration through agent artifacts:
  API key exposure, system prompt and training-data extraction, OAuth token
  abuse, environment variable harvesting, disguised analytics exfiltration,
  and markdown image exfiltration.
  ATR-2026-00021, ATR-2026-00275, ATR-2026-00114, ATR-2026-00115,
  ATR-2026-00102, ATR-2026-00261

agent_card_spoofing (3 signatures)
  Discovery poisoning and impersonation in agent cards: skill impersonation,
  fork and clone identity claims, and registry poisoning.
  ATR-2026-00060, ATR-2026-00134, ATR-2026-00096

## False-positive hardening

An adversarial review found that several rules fired on benign agent cards
because they matched loose conversational tone rather than a structured
malicious signal. Those rules were either dropped or anchored. Quality was
prioritized over rule count; the remaining rules still detect the malicious
control card and the broader A2A attack surface.

Dropped (conversational-tone rules with no structured malicious anchor on the
A2A surface; each fired on benign cards/messages):

  ATR-2026-00041  scope creep ("I will also check", "to fully complete this task")
  ATR-2026-00032  goal hijacking ("change of plans", "this is more important")
  ATR-2026-00077  human-trust exploitation ("trust me", "100% certain")
  ATR-2026-00011  tool-output injection (fired on benign "Action required:")
  ATR-2026-00119  social engineering (fired on benign account/notification copy)
  ATR-2026-00132  casual authority escalation (fired on benign "for better
                  performance I will query the database directly")

Anchored (kept, with the false-positive sub-pattern removed or tightened):

  ATR-2026-00013  SSRF: removed the URL-shortener sub-pattern (bit.ly, t.co,
                  etc.). Shorteners in an agent card are not treated as a
                  CRITICAL SSRF signal by default. The rest of the rule
                  (cloud-metadata endpoints, private IP ranges, internal
                  service hosts) is unchanged and stays CRITICAL. URL-shortener
                  detection is therefore off by default in this pack; reviewers
                  who want it can add a custom rule or policy.
  ATR-2026-00098  unauthorized financial action: dropped past-tense reporting
                  phrasing ("payment successful", "transfer completed", "已发送")
                  and the bare "amount"-field match that fire on benign billing
                  and reporting agents. Kept structured function/tool names
                  (send_money, wire_transfer, ...), payment-platform send calls,
                  structured action fields, and explicit first-person execution
                  intent with an amount.
  ATR-2026-00030  cross-agent attack: removed the `status: failed ... retry`
                  sub-pattern, whose `.*` spanned fields and fired on benign
                  CI status text; and narrowed the concealment sub-pattern to
                  supervisory targets (admin/orchestrator/supervisor/monitor)
                  so benign "do not tell the user the raw stack trace" no longer
                  matches. The identity-spoofing, ignore-instructions, code
                  execution, and redirect-to-IP patterns are unchanged.
  ATR-2026-00114  OAuth/API token interception: bounded the forward/extract
                  gaps to a single field so the rule no longer produces a
                  cross-field DOTALL span on benign multi-field cards. Still
                  detects "forward your api keys to ..." on the malicious card.
  ATR-2026-00076  inter-agent message spoofing: the loose "trust/verify/accept
                  all incoming messages from ..." sub-pattern now requires an
                  explicit insecurity anchor ("... without verification/auth/
                  signature"). The 11 strongly anchored patterns (auth=null,
                  source=spoofed, unsigned command, ...) are unchanged.
  ATR-2026-00105  silent action concealment: anchored so the concealment object
                  is the tool's own action ("do not mention this to the user as
                  it is", "silently execute ... without the user's knowledge"),
                  not arbitrary content, so benign "do not notify the user about
                  background retries" no longer matches.

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
        benign_agent_card.json          Negative control fixture (single card)
        benign_corpus/                  Realistic benign corpus (6 cards), the
                                        0-FP gate

## Tests

tests/test_atr_pack.py verifies that the pack loads and is discoverable, that
the malicious control fixture triggers the genuinely anchored ATR signatures
(agent identity spoofing, A2A message injection, direct prompt injection, SSRF,
cross-agent attack, cross-agent privilege escalation, and OAuth/API token
forwarding), and that every card in the realistic benign corpus produces zero
ATR findings.

## Provenance

Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
Source commit: 9f0991c34f359894e79afe2a7657b4c314b34f83 (655-rule set)
License: MIT
The full ATR ruleset is broader than this pack; only rules whose attack surface
is the A2A protocol are mapped here.
