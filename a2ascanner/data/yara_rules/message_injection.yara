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
 * YARA Rules for Message/Prompt Injection Detection
 * Detects injection attempts in agent messages
 */

rule MessageInjection_DirectivePatterns
{
    meta:
        author = "Cisco"
        description = "Detects prompt injection directive patterns attempting to override system instructions"
        severity = "HIGH"
        threat_name = "PROMPT INJECTION"
        reference = "Targets explicit override commands unlikely in legitimate agent communication"
        
    strings:
        // Strong override directives - ENHANCED to catch "ignore all previous instructions"
        // Note: YARA regex doesn't support (?:...) so we use alternatives
        $override1a = /IGNORE\s+PREVIOUS\s+(INSTRUCTIONS?|RULES?|PROMPTS?)/i
        $override1b = /IGNORE\s+ALL\s+PREVIOUS\s+(INSTRUCTIONS?|RULES?|PROMPTS?)/i
        $override1c = /IGNORE\s+ALL\s+(INSTRUCTIONS?|RULES?|PROMPTS?)/i
        $override1d = /IGNORE\s+EVERY\s+PREVIOUS\s+(INSTRUCTIONS?|RULES?|PROMPTS?)/i
        $override1e = /IGNORE\s+EVERY\s+(INSTRUCTIONS?|RULES?|PROMPTS?)/i
        $override1f = /IGNORE\s+YOUR\s+(INSTRUCTIONS?|RULES?|PROMPTS?)/i
        $override1g = /IGNORE\s+ABOVE\s+(INSTRUCTIONS?|RULES?)/i
        
        $override2a = /DISREGARD\s+PREVIOUS\s+(INSTRUCTIONS?|RULES?|CONTEXT)/i
        $override2b = /DISREGARD\s+ALL\s+PREVIOUS\s+(INSTRUCTIONS?|RULES?)/i
        $override2c = /DISREGARD\s+ALL\s+(INSTRUCTIONS?|RULES?)/i
        $override2d = /DISREGARD\s+YOUR\s+(INSTRUCTIONS?|RULES?)/i
        
        $override3a = /FORGET\s+ALL\s+(INSTRUCTIONS?|RULES?|CONTEXT|PROMPTS?)/i
        $override3b = /FORGET\s+EVERYTHING\s+ABOVE/i
        $override3c = /FORGET\s+EVERYTHING\s+BEFORE/i
        $override3d = /FORGET\s+PREVIOUS\s+(INSTRUCTIONS?|RULES?)/i
        $override3e = /FORGET\s+YOUR\s+(INSTRUCTIONS?|RULES?)/i
        
        // System-level override attempts
        $system1 = /SYSTEM\s+(OVERRIDE|MODE|PROMPT|INSTRUCTION):/i
        $system2 = /ADMIN\s+(MODE|OVERRIDE|PROMPT|INSTRUCTION):/i
        $system3 = /DEVELOPER\s+(MODE|OVERRIDE):/i
        
        // Explicit instruction replacement
        $replace1 = /NEW\s+(INSTRUCTIONS?|RULES?|PROMPT):\s*\n/i
        $replace2 = /REPLACE\s+(INSTRUCTIONS?|RULES?|PROMPT)\s+WITH:/i
        $replace3 = /FROM\s+NOW\s+ON,?\s+(IGNORE|DISREGARD|FORGET)/i
        
        // Jailbreak patterns
        $jailbreak1 = /\[SYSTEM\]\s*:\s*(OVERRIDE|IGNORE|NEW)/i
        $jailbreak2 = /<\|system\|>\s*(override|ignore)/i
        
        // Additional flexible patterns for common variations
        $flexible1 = /IGNORE\s+EVERYTHING\s+(ABOVE|BEFORE|PRIOR|PREVIOUSLY)/i
        $flexible2a = /DISREGARD\s+WHAT\s+I\s+(SAID|TOLD)/i
        $flexible2b = /DISREGARD\s+WHAT\s+YOU\s+(SAID|TOLD)/i
        $flexible2c = /DISREGARD\s+EVERYTHING\s+BEFORE/i
        $flexible3 = /START\s+(OVER|FRESH|ANEW)\s+WITH\s+NEW\s+INSTRUCTIONS/i
        $flexible4a = /RESET\s+YOUR\s+(INSTRUCTIONS?|RULES?|CONTEXT)/i
        $flexible4b = /RESET\s+ALL\s+(INSTRUCTIONS?|RULES?|CONTEXT)/i
        $flexible4c = /RESET\s+(INSTRUCTIONS?|RULES?|CONTEXT)/i
        
    condition:
        any of them
}

rule MessageInjection_RoleManipulation
{
    meta:
        author = "Cisco"
        description = "Detects role manipulation attacks attempting to redefine agent behavior"
        severity = "HIGH"
        threat_name = "PROMPT INJECTION"
        reference = "Requires role redefinition combined with authority/system terms"
        
    strings:
        // Role redefinition with authority terms
        $role_auth1 = /You\s+are\s+now\s+(a|an)?\s*(admin|root|system|developer|unrestricted)/i
        $role_auth2 = /From\s+now\s+on,?\s+you\s+are\s+(a|an)?\s*(admin|system|developer)/i
        $role_auth3 = /Your\s+new\s+role\s+is\s+(admin|system|developer|unrestricted)/i
        
        // Impersonation attempts
        $impersonate1 = /Act\s+as\s+(a|an|the)?\s*(admin|system|developer|jailbreak)/i
        $impersonate2 = /Pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*(admin|system|root)/i
        $impersonate3 = /Roleplay\s+as\s+(a|an|the)?\s*(admin|system|unrestricted)/i
        
        // Mode switching attacks
        $mode_switch1 = /Switch\s+to\s+(admin|developer|system|jailbreak)\s+mode/i
        $mode_switch2 = /Enable\s+(admin|developer|system|debug)\s+mode/i
        $mode_switch3 = /Activate\s+(admin|developer|god)\s+mode/i
        
        // Behavior override
        $behavior1 = /Behave\s+like\s+(you\s+have\s+)?(no|unlimited|admin)\s+(restrictions?|access|permissions?)/i
        $behavior2 = /Simulate\s+(a|an)\s+(unrestricted|admin|system|root)\s+(agent|assistant)/i
        
    condition:
        any of them
}

rule MessageInjection_CommandExecution
{
    meta:
        author = "Cisco"
        description = "Detects suspicious command execution patterns in agent messages"
        severity = "CRITICAL"
        threat_name = "CODE EXECUTION"
        reference = "Targets actual code execution attempts, not just mentions of commands"
        
    strings:
        // Direct execution commands with code
        $exec_code1 = /execute:\s*['"]?(eval|exec|system|subprocess|os\.)/i
        $exec_code2 = /run:\s*['"]?(eval|exec|system|__import__)/i
        $exec_code3 = /execute_code\s*\(/i
        
        // Python execution functions with suspicious context
        $py_exec1 = /eval\s*\(\s*['"]\s*(import|exec|os\.|sys\.|subprocess)/
        $py_exec2 = /exec\s*\(\s*['"]\s*(import|os\.|sys\.|__import__)/
        $py_exec3 = /__import__\s*\(\s*['"]os['"]\)/
        $py_exec4 = /compile\s*\(.*exec\s*\)/
        
        // System command execution
        $sys_exec1 = /(os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(/
        $sys_exec2 = /shell\s*=\s*True.*subprocess/
        $sys_exec3 = /os\.popen\s*\(/
        
        // Shell command injection patterns
        $shell1 = /`.*\$\(.*\)`/  // Backticks with command substitution
        $shell2 = /;\s*(rm|curl|wget|nc|bash|sh)\s+/  // Shell command chaining
        $shell3 = /\|\s*(bash|sh|python|perl)\s*$/  // Pipe to interpreter
        
    condition:
        any of them
}

rule MessageInjection_DataExfiltration
{
    meta:
        author = "Cisco"
        description = "Detects data exfiltration attempts via external HTTP requests in messages"
        severity = "HIGH"
        threat_name = "DATA EXFILTRATION"
        reference = "Targets suspicious external data transmission with context/credential patterns"
        
    strings:
        // Explicit exfiltration commands with data
        $exfil_explicit1 = /send\s+(to|data|context|info|secrets?)\s+to\s+https?:\/\//i
        $exfil_explicit2 = /POST\s+(to|data|context)\s+https?:\/\//i
        $exfil_explicit3 = /upload\s+(to|data)\s+https?:\/\//i
        
        // HTTP requests with sensitive data references
        $http_data1 = /fetch\s*\(\s*['"]https?:\/\/.*['"],\s*\{.*body.*\b(context|data|secret|token|key)\b/i
        $http_data2 = /requests\.(post|put)\s*\(.*url.*data\s*=.*\b(context|secret|token)\b/i
        $http_data3 = /axios\.(post|put).*\b(context|data|secret|token)\b/i
        
        // Curl/wget with POST data containing sensitive info
        $curl_exfil1 = /curl\s+(-X\s+POST|-d|--data).*https?:\/\/.*\b(context|secret|token|key)\b/i
        $curl_exfil2 = /wget\s+(--post-data|--post-file).*\b(context|secret|token)\b/i
        
        // Suspicious external endpoints with data transmission
        $endpoint_sus1 = /https?:\/\/[^\s\/]*\b(exfil|collect|log|steal|dump)\b[^\s]*.*\b(post|send|upload)\b/i
        $endpoint_sus2 = /(post|send).*https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/  // Direct IP
        
    condition:
        any of them
}

rule MessageInjection_HiddenInstructions
{
    meta:
        author = "Cisco"
        description = "Detects malicious instructions hidden in metadata or non-display fields"
        severity = "MEDIUM"
        threat_name = "CONTEXT BOUNDARY ATTACKS"
        reference = "FIXED: Targets directive keywords ONLY in non-display metadata fields, not regular descriptions"
        
    strings:
        // Hidden in metadata with directive keywords (FIXED: More specific field names)
        $meta_inject1 = /"(note|metadata|comment|annotation|extra|_comment|_metadata|_internal)"\s*:\s*"[^"]*\b(IGNORE|OVERRIDE|EXECUTE|SYSTEM)\b[^"]*"/i
        $meta_inject2 = /"(note|comment|_note)"\s*:\s*"[^"]*\b(forget|disregard|new\s+instructions?)\b[^"]*"/i
        
        // Hidden in HTML/XML attributes or comments
        $html_hidden1 = /<!--[^>]*\b(IGNORE|OVERRIDE|SYSTEM|EXECUTE)\b[^>]*-->/i
        $html_hidden2 = /(data-instruction|data-command|data-system)\s*=\s*"[^"]*\b(IGNORE|OVERRIDE|EXECUTE)\b/i
        
        // FIXED: Properly check for actual invisible Unicode characters before directive words
        // This now requires the invisible character to be PRESENT, not just any text with keywords
        $invisible_valid1 = /[\u200B-\u200D]+\s*(IGNORE|OVERRIDE|SYSTEM|EXECUTE)/i
        $invisible_valid2 = /[\u200E\u200F\uFEFF]+\s*(IGNORE|OVERRIDE|SYSTEM|EXECUTE)/i
        
        // Hidden in non-rendered JSON fields  
        // TUNED: More restrictive to avoid false positives on source code
        $json_hidden1 = /"(__proto__|constructor|prototype)"\s*:\s*"[^"]*\b(execute|eval|system)\b/i
        $json_hidden2 = /"(_system|_admin|_internal|_hidden)"\s*:\s*"[^"]*\b(OVERRIDE|IGNORE|EXECUTE)\b/i
        
        // Exclude common source code patterns
        $code_exclude1 = /def\s+execute\s*\(/  // Python function definition
        $code_exclude2 = /function\s+execute\s*\(/  // JavaScript function
        $code_exclude3 = /async\s+def\s+execute/  // Python async function
        $code_exclude4 = /\.execute\s*\(/  // Method call
        $code_exclude5 = /(import|from)\s+.*\s+execute/  // Import statement
        $code_exclude6 = /class.*execute/i  // Class name with execute
        
    condition:
        any of ($meta*, $html*, $invisible*, $json*) and not any of ($code_exclude*)
}

rule MessageInjection_ContextPoisoning
{
    meta:
        author = "Cisco"
        description = "Detects persistent context poisoning attempting to modify future agent behavior"
        severity = "HIGH"
        threat_name = "MEMORY SYSTEM PERSISTENCE"
        reference = "Targets persistent instruction patterns with authority or rule-breaking content"
        
    strings:
        // Persistent instruction setting with malicious intent
        $persist_rule1 = /Remember:\s+(always|never|from\s+now)\s+(ignore|disregard|bypass|override)/i
        $persist_rule2 = /From\s+now\s+on,?\s+(always|never)\s+(ignore|bypass|override|execute)/i
        $persist_rule3 = /For\s+all\s+future\s+(requests?|tasks?|interactions?),?\s+(ignore|bypass|always|never)/i
        
        // Permanent behavior modification
        $permanent1 = /Permanently\s+(ignore|override|bypass|remember|store)\s+(this|that|instructions?)/i
        $permanent2 = /Store\s+(this|these)\s+instruction[s]?\s+(permanently|forever|always)/i
        $permanent3 = /Save\s+to\s+(memory|context|permanent)\s*:\s*\b(IGNORE|OVERRIDE|BYPASS)\b/i
        
        // Future behavior constraints
        $future_mod1 = /In\s+the\s+future,?\s+(always|never)\s+(trust|ignore|bypass|execute)/i
        $future_mod2 = /Going\s+forward,?\s+(ignore|disregard|always|never)/i
        
        // Memory/context manipulation
        $memory_manip1 = /Add\s+to\s+(permanent\s+)?(memory|context)\s*:\s*\b(IGNORE|OVERRIDE|ALWAYS|NEVER)\b/i
        $memory_manip2 = /Update\s+(your\s+)?(memory|context|rules?)\s*:\s*\b(IGNORE|BYPASS|OVERRIDE)\b/i
        
    condition:
        any of them
}
