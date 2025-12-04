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
    YARA rules for detecting agent impersonation and identity spoofing
    in A2A implementations and agent cards
*/

rule AgentNameImpersonation {
    meta:
        author = "Cisco"
        description = "Detects typosquatting and character substitution in agent names"
        severity = "HIGH"
        threat_name = "AGENT CARD SPOOFING"
    
    strings:
        // Common impersonation patterns - variations of well-known agents
        $google1 = "g00gle" nocase
        $google2 = "googIe" nocase
        $google3 = "gooogle" nocase
        
        $openai1 = "0penai" nocase
        $openai2 = "openAl" nocase
        $openai3 = "open-ai" nocase
        
        $anthropic1 = "anthr0pic" nocase
        $anthropic2 = "anthroplc" nocase
        
        $microsoft1 = "micr0soft" nocase
        $microsoft2 = "micro5oft" nocase
        
        // Suspicious naming patterns
        $official = /(official|verified|trusted|certified)[-_]?agent/i
        $system = /system[-_]?agent/i
        $admin = /admin[-_]?agent/i
        
    condition:
        any of them
}

rule SuspiciousDomainSpoofing {
    meta:
        author = "Cisco"
        description = "Detects domain typosquatting and suspicious TLDs in agent cards"
        severity = "HIGH"
        threat_name = "AGENT CARD SPOOFING"
    
    strings:
        // Typosquatting patterns
        $typo1 = /https?:\/\/[a-z0-9-]*g00gle[a-z0-9-]*\./i
        $typo2 = /https?:\/\/[a-z0-9-]*micr0soft[a-z0-9-]*\./i
        $typo3 = /https?:\/\/[a-z0-9-]*0penai[a-z0-9-]*\./i
        
        // Homograph attacks (using similar looking characters)
        // $homo1 = /[\x{0430}-\x{044F}]/ // Cyrillic characters mixed with Latin
        
        // Suspicious TLDs
        $tld1 = /.xyz["']/
        $tld2 = /.tk["']/
        $tld3 = /.ml["']/
        
    condition:
        any of ($typo*, $tld*)
}

rule FakeVerificationClaims {
    meta:
        author = "Cisco"
        description = "Detects false verification or certification claims indicating profile tampering"
        severity = "MEDIUM"
        threat_name = "AGENT PROFILE TAMPERING"
    
    strings:
        $claim1 = "verified by Google" nocase
        $claim2 = "certified by OpenAI" nocase
        $claim3 = "official Microsoft agent" nocase
        $claim4 = "trusted by " nocase
        $claim5 = "approved by " nocase
        $claim6 = "endorsed by " nocase
        
        // Without proper verification mechanisms
        $json_verified = /"verified"\s*:\s*true/
        $json_certified = /"certified"\s*:\s*true/
        
    condition:
        any of them
}
