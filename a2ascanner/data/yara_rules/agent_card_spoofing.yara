/*
 * Copyright 2025 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * YARA Rules for Agent Card Spoofing Detection
 * Detects malicious patterns in agent card descriptions and metadata
 */

rule AgentCard_SuperlativeLanguage
{
    meta:
        author = "Cisco"
        description = "Detects excessive superlative and persuasive language suggesting routing manipulation"
        severity = "MEDIUM"
        threat_name = "AGENT CARD SPOOFING"
        reference = "Requires multiple superlatives + direct selection commands to reduce FPs. A2A-specific attack vector."
        
    strings:
        // Direct selection commands (high confidence indicators)
        $direct_select1 = /\b(always|only)\s+(pick|choose|select|use)\s+(me|this|us)\b/i
        $direct_select2 = /\b(never\s+use|don't\s+use|avoid)\s+(other|alternative|different)\s+agents?\b/i
        $direct_select3 = /\bI'?m\s+the\s+(only|best)\s+agent\s+(for|to)\b/i
        
        // Unrealistic claims
        $unrealistic1 = /\b(100%|perfect)\s+(success|accuracy|reliability|uptime)\b/i
        $unrealistic2 = /\b(never|zero)\s+(fails?|errors?|downtime)\b/i
        $unrealistic3 = /\bcan\s+(do|handle)\s+(everything|anything|all\s+tasks?)\b/i
        
        // Security bypass claims
        $security_bypass1 = /\b(no|without|skip|bypass)\s+(auth|authentication|verification|security)\b/i
        $security_bypass2 = /\bunrestricted\s+(access|permissions?)\b/i
        
        // Excessive superlatives (need multiple)
        $super1 = /\b(ultimate|superior|supreme|unbeatable)\s+(agent|solution|tool)\b/i
        $super2 = /\b(best|top|#1|number\s+one)\s+in\s+the\b/i
        $super3 = /\bguaranteed\s+(to|success|results?)\b/i
        
    condition:
        any of ($direct_select*) or 
        any of ($security_bypass*) or
        any of ($unrealistic*) or
        2 of ($super*)
}

rule AgentCard_Typosquatting
{
    meta:
        author = "Cisco"
        description = "Detects character substitution and homoglyph attacks in trusted brand names"
        severity = "HIGH"
        threat_name = "AGENT CARD SPOOFING"
        reference = "TUNED: Only detects actual homoglyphs/substitutions, excludes legitimate imports"
        
    strings:
        // Leet-speak substitutions in trust words (ONLY malicious variants)
        // Pattern: match when numbers/symbols ARE PRESENT, not optional
        $leet_trust1 = /\bTru[5$]ted\b/i              // Tru5ted, Tru$ted (NOT Trusted)
        $leet_trust2 = /\b0fficial\b/i               // 0fficial with zero (NOT Official)
        $leet_trust3 = /\bAuthent[1!|]c(ated)?\b/i    // Authent1c, Authent!c (NOT Authentic)
        $leet_trust4 = /\bSecur[3]d?\b/i              // Secur3d (NOT Secured)
        $leet_trust5 = /\bVerif[1!|][3]d\b/i          // Verif1ed, Verif!3d (NOT Verified)
        $leet_trust6 = /\bCertif[1!|][3]d\b/i         // certificate1ed, certificate!3d (NOT Certified)
        $leet_trust7 = /\bL[3]g[1!|]t(imate)?\b/i     // L3g1t, L3g!t (NOT Legit)
        
        // Additional leet-speak patterns
        $leet_trust8 = /\bV[3]r[1!|]f[1!|][3]d\b/i    // V3r1f13d
        $leet_trust9 = /\b0f[1!|]c[1!|][4@]l\b/i       // 0f1c1al (with zero)
        $leet_trust10 = /\bTru$t[3]d\b/i              // Tru$t3d
        
        // TUNED AGAIN: REMOVED brand name patterns entirely (too many false positives)
        // These patterns matched legitimate imports and caused noise
        // We keep ONLY leet-speak trust word patterns below
        // Real typosquatting will be caught by leet-speak patterns (Tru5ted, 0fficial, etc.)
        
        // Combined trust words with homoglyphs (must have ASCII + homoglyph mixed)
        $mixed1 = /(Trust|Verif|Offic|Certif).*(а|е|о|р|с|х)/i
        $mixed2 = /(а|е|о|р|с|х).*(Trust|Verif|Offic|Certif)/i
        
    condition:
        // TUNED: Only flag leet-speak trust words or mixed homoglyphs
        // Removed brand name patterns to eliminate false positives on imports
        any of ($leet_trust*) or any of ($mixed*)
}

rule AgentCard_MassRegistration
{
    meta:
        author = "Cisco"
        description = "Detects tool squatting via sequential mass registration patterns"
        severity = "MEDIUM"
        threat_name = "DEPENDENCY NAME SQUATTING"
        reference = "Targets generic names with high sequential numbers indicating automation"
        
    strings:
        // Generic names with very high sequential numbers (likely automated)
        $mass_seq1 = /\b(agent|bot|helper|tool|service)-\d{4,}\b/i  // 4+ digits
        $mass_seq2 = /\b(agent|bot|helper|tool|service)-[0-9]{3}[5-9]\b/i  // 350-999
        
        // Single letter variants suggesting namespace squatting
        $namespace1 = /\b(agent|bot|helper)-[a-z]-\d{3,}\b/i
        
        // Obvious test/spam patterns
        $spam1 = /\b(test|temp|tmp|demo|sample)-agent-\d+\b/i
        $spam2 = /\bagent-clone-\d+\b/i
        $spam3 = /\b(agent|bot)-\d+-\d+-\d+\b/  // agent-1-2-3 pattern
        
        // Generic description indicating placeholder
        $generic_desc = /"description"\s*:\s*"(Agent|Bot|Helper|Tool)\s+\d+"/
        
    condition:
        any of ($mass_seq*) or
        $namespace1 or
        any of ($spam*) or
        $generic_desc
}

rule AgentCard_EmojiSpam
{
    meta:
        author = "Cisco"
        description = "Detects excessive emoji usage suggesting attention-grabbing/spam behavior"
        severity = "LOW"
        threat_name = "AGENT CARD SPOOFING"
        reference = "Requires excessive emoji density, not just presence. A2A-specific spam tactic."
        
    strings:
        // Attention-grabbing emojis - both UTF-8 string and hex for YARA compatibility
        // Alert emojis
        $emoji_alert1 = "🚨"                    // Police car light
        $emoji_alert1_hex = { F0 9F 9A A8 }
        $emoji_alert2 = "🛑"                    // Stop sign
        $emoji_alert2_hex = { F0 9F 9B 91 }
        $emoji_alert3 = "⚠️"                    // Warning
        $emoji_alert3_hex = { E2 9A A0 }
        $emoji_alert4 = "❗"                    // Exclamation
        $emoji_alert4_hex = { E2 9D 97 }
        
        // Hype emojis
        $emoji_hype1 = "🔥"                     // Fire
        $emoji_hype1_hex = { F0 9F 94 A5 }
        $emoji_hype2 = "💯"                     // 100
        $emoji_hype2_hex = { F0 9F 92 AF }
        $emoji_hype3 = "✨"                     // Sparkles
        $emoji_hype3_hex = { E2 9C A8 }
        $emoji_hype4 = "⚡"                     // Lightning
        $emoji_hype4_hex = { E2 9A A1 }
        $emoji_hype5 = "💥"                     // Collision
        $emoji_hype5_hex = { F0 9F 92 A5 }
        $emoji_hype6 = "🎯"                     // Bullseye
        $emoji_hype6_hex = { F0 9F 8E AF }
        
        // Checkmark emojis
        $emoji_check1 = "✅"                    // White check mark
        $emoji_check1_hex = { E2 9C 85 }
        $emoji_check2 = "☑️"                    // Ballot box with check
        $emoji_check2_hex = { E2 98 91 }
        $emoji_check3 = "✔️"                    // Check mark
        $emoji_check3_hex = { E2 9C 94 }
        
        // Money emojis
        $emoji_money1 = "💰"                    // Money bag
        $emoji_money1_hex = { F0 9F 92 B0 }
        $emoji_money2 = "💵"                    // Dollar
        $emoji_money2_hex = { F0 9F 92 B5 }
        $emoji_money3 = "💸"                    // Money with wings
        $emoji_money3_hex = { F0 9F 92 B8 }
        
    condition:
        // Excessive emoji density (4+ different emoji types detected)
        // String and hex patterns for same emoji won't both match (YARA matches one or the other)
        // so "4 of them" effectively means 4+ different emojis present
        4 of them
}

rule AgentCard_PrivilegeEscalation
{
    meta:
        author = "Cisco"
        description = "Detects suspicious privilege escalation claims inappropriate for agent cards"
        severity = "HIGH"
        threat_name = "AGENT PROFILE TAMPERING"
        reference = "Targets privilege claims combined with access/bypass terminology"
        
    strings:
        // Privilege level claims
        $priv_level1 = /\b(root|superuser|system)\s+(level|access|privileges?)\b/i
        $priv_level2 = /\b(admin|administrator)\s+(rights?|access|privileges?)\b/i
        $priv_level3 = /\belevated\s+(permissions?|privileges?|access)\b/i
        
        // Access claims (need to be combined with actions)
        $access1 = /\b(full|complete|unrestricted|unlimited)\s+(access|control|permissions?)\b/i
        $access2 = /\ball\s+system\s+(access|privileges?|resources?)\b/i
        
        // Bypass/override claims
        $bypass1 = /\b(bypass|circumvent|skip|ignore)\s+(security|auth|restrictions?|controls?)\b/i
        $bypass2 = /\boverride\s+(security|permissions?|auth|policy)\b/i
        $bypass3 = /\belevate\s+(to|privileges?|permissions?)\b/i
        
        // Sudo/system commands (shouldn't be in agent cards)
        $syscmd1 = /\b(sudo|su\s+)\s/
        $syscmd2 = /\brun\s+as\s+(root|admin|system)\b/i
        
        // Impersonation claims
        $impersonate1 = /\bact\s+as\s+(admin|root|system|superuser)\b/i
        $impersonate2 = /\bimpersonate\s+(admin|user|system)\b/i
        
    condition:
        any of ($priv_level*) or
        any of ($bypass*) or
        any of ($syscmd*) or
        any of ($impersonate*) or
        ($access1 and $access2)  // Multiple broad access claims
}
