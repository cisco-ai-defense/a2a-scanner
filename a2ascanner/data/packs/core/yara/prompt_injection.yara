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
    YARA rules for detecting prompt injection and agent poisoning
    in A2A agent cards and implementations
*/

rule PromptInjectionAttempt {
    meta:
        author = "Cisco"
        description = "Detects potential prompt injection patterns in agent descriptions and prompts"
        severity = "HIGH"
        threat_name = "PROMPT INJECTION"
    
    strings:
        // Common prompt injection patterns
        $inject1 = /ignore\s+(previous|above|all)\s+(instructions|prompts|rules)/i
        $inject2 = /disregard\s+(previous|above|all)\s+(instructions|commands)/i
        $inject3 = /forget\s+(previous|above|all)/i
        
        // System prompt override attempts
        $sys1 = /you\s+are\s+now/i
        $sys2 = /new\s+instructions:/i
        
        // Role manipulation
        $role1 = /assume\s+the\s+role\s+of/i
        $role2 = /act\s+as\s+(a\s+)?(administrator|root|admin)/i
        $role3 = /pretend\s+to\s+be/i
        
        // Template injection in text fields
        $template1 = /\$\{[^}]*eval/i
        $template2 = /\{\{[^}]*system/i
        
        // Agent description or skill context
        $context1 = /"description"\s*:/
        $context2 = /"prompt"\s*:/
        $context3 = /"system_message"\s*:/
        $context4 = /AgentSkill/
        
        // Exclude IDE/debugger configurations
        $ide1 = /.vscode/
        $ide2 = /launch.json/
        $ide3 = /settings.json/
        $ide4 = /"args"\s*:/  // CLI arguments
        
    condition:
        any of ($inject*, $sys*, $role*, $template*) and 
        any of ($context*) and 
        not any of ($ide*)
}

rule AgentInstructionOverride {
    meta:
        author = "Cisco"
        description = "Detects attempts to override agent instructions"
        severity = "HIGH"
        threat_name = "PROMPT INJECTION"
    
    strings:
        $override1 = "ignore your instructions and" nocase
        $override2 = "override default behavior" nocase
        $override3 = "bypass safety" nocase
        $override4 = "disable security" nocase
        $override5 = "skip validation" nocase
        
        // Jailbreak patterns
        $jail1 = "jailbreak" nocase
        $jail2 = "DAN mode" nocase
        $jail3 = "unrestricted mode" nocase
        
    condition:
        any of them
}

rule SuspiciousPromptTemplate {
    meta:
        author = "Cisco"
        description = "Detects suspicious patterns in prompt templates"
        severity = "MEDIUM"
        threat_name = "PROTOCOL MANIPULATION"
    
    strings:
        // Unescaped user input in prompts
        $input1 = /f["'][^"']*\{user_input\}/ // Python f-strings
        $input2 = /`[^`]*\$\{user[_\.]input\}`/ // Template literals
        $input3 = /["'][^"']*\+\s*user[_\.]input/ // String concatenation
        
        // SQL-like injection patterns
        $sql1 = /' or 1=1/
        $sql2 = /" or "1"="1/
        $sql3 = /'; drop/i
        
        // Code execution in templates
        $exec1 = /eval\(/
        $exec2 = /exec\(/
        $exec3 = /\.__import__/
        
    condition:
        any of them
}

rule ContextManipulation {
    meta:
        author = "Cisco"
        description = "Detects context manipulation attempts"
        severity = "MEDIUM"
        threat_name = "MEMORY SYSTEM CORRUPTION"
    
    strings:
        $ctx1 = /reset\s+context/i
        $ctx2 = /clear\s+(conversation|history)/i
        $ctx3 = /new\s+conversation/i
        $ctx4 = /start\s+over/i
        
        // With suspicious follow-up
        $follow = /\.(then|now|next)[^.]{0,50}(execute|run|do)/i
        
    condition:
        any of ($ctx*) and $follow
}

rule PromptLeaking {
    meta:
        author = "Cisco"
        description = "Detects attempts to leak system prompts"
        severity = "MEDIUM"
        threat_name = "PROMPT META EXTRACTION"
    
    strings:
        $leak1 = "show me your prompt" nocase
        $leak2 = "reveal your instructions" nocase
        $leak3 = "what are your rules" nocase
        $leak4 = "print your system message" nocase
        $leak5 = "display configuration" nocase
        
    condition:
        any of them
}

