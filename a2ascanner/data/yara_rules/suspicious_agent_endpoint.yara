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
 * YARA Rules for Suspicious Agent Endpoint Detection
 * Detects malicious patterns in agent endpoint definitions
 */

rule SuspiciousAgentEndpoint_Exfiltration
{
    meta:
        author = "Cisco"
        description = "Detects agent endpoints sending data to suspicious external servers"
        severity = "HIGH"
        threat_name = "DATA EXFILTRATION"
        reference = "Requires combination of suspicious endpoints + sensitive data transmission"
        
    strings:
        // Obviously malicious domains
        $malicious_domain1 = /https?:\/\/[^\s\/]*(evil|malicious|attacker|exfil|steal|dump|phish)[^\s]*/i
        
        // Suspicious endpoint paths
        $suspicious_path1 = /https?:\/\/[^\s]*\/(exfil|collect|steal|dump|log|harvest)\/[^\s]*/i
        $suspicious_path2 = /https?:\/\/[^\s]*\/api\/(exfiltrate|collect_data|steal)/i
        
        // Direct IP addresses with data transmission
        $ip_post1 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\b(post|send|data)\b/i
        $ip_localhost = "127.0.0.1"
        
        // Suspicious high-numbered localhost ports (>9000, often used for testing/malicious)
        $suspicious_localhost = /https?:\/\/(localhost|127\.0\.0\.1):9[5-9]\d{2}/
        
        // Data exfiltration with sensitive content
        $exfil_context1 = /requests\.post\([^)]*\b(ctx|context|secret|token|key|credential)\b/i
        $exfil_context2 = /fetch\([^)]*body[^)]*\b(context|secret|token|key|message|conversation)\b/i
        $exfil_context3 = /axios\.post\([^)]*\b(ctx|context|secret|auth|credential)\b/i
        
        // Explicit exfiltration in path with POST
        $explicit_exfil = /POST.*\/(exfil|steal|collect|harvest|dump)/i
        
    condition:
        any of ($malicious_domain*) or
        any of ($suspicious_path*) or
        ($ip_post1 and not $ip_localhost) or
        $suspicious_localhost or
        any of ($exfil_context*) or
        $explicit_exfil
}

rule SuspiciousAgent_CapabilityExaggeration
{
    meta:
        author = "Cisco"
        description = "Detects unrealistic capability claims in agent descriptions suggesting deception"
        severity = "MEDIUM"
        threat_name = "CAPABILITY INFLATION"
        reference = "Requires absolute/unlimited claims unlikely for legitimate tools"
        
    strings:
        // Absolute capability claims
        $absolute1 = /\b(can|will)\s+(do|handle|process|solve)\s+(everything|anything|all\s+tasks?|any\s+task)\b/i
        $absolute2 = /\bhandles?\s+(all|any|every)\s+(task|request|input|query|problem)s?\b/i
        $absolute3 = /\bsupports?\s+(all|any|every)\s+(format|type|input|output|task)s?\b/i
        
        // Unlimited claims
        $unlimited1 = /\b(unlimited|infinite|unrestricted)\s+(capabilities?|access|permissions?|power)\b/i
        $unlimited2 = /\bno\s+(limits?|restrictions?|boundaries|constraints?)\b/i
        
        // Superiority claims combined with capability
        $superiority1 = /\b(best|only|ultimate)\s+tool\s+(for|to)\s+(all|any|every)\b/i
        $superiority2 = /\bworks?\s+(perfectly|flawlessly)\s+(on|with|for)\s+(everything|anything|all)\b/i
        
        // Unrealistic accuracy/reliability
        $unrealistic1 = /\b100%\s+(accurate|reliable|successful|effective)\b/i
        $unrealistic2 = /\b(never|zero)\s+(fails?|errors?|mistakes?)\b/i
        
    condition:
        any of them
}

rule SuspiciousAgent_SSRF
{
    meta:
        author = "Cisco"
        description = "Detects SSRF vulnerabilities via unvalidated URL parameters in agent endpoints"
        severity = "HIGH"
        threat_name = "UNAUTHORIZED NETWORK ACCESS"
        reference = "Targets unvalidated user-controlled URLs or cloud metadata access"
        
    strings:
        // Unvalidated URL fetching from user input (very suspicious)
        $ssrf_user1 = /fetch\s*\(\s*(user_url|input_url|url|target_url|endpoint)/i
        $ssrf_user2 = /requests\.(get|post)\s*\(\s*(user_url|input_url|url|target_url)/i
        $ssrf_user3 = /urllib\.request\.urlopen\s*\(\s*(url|user_url|input_url)/i
        $ssrf_user4 = /httpx\.(get|post)\s*\(\s*(url|user_url|input_url)/i
        
        // Direct parameter URL fetching without validation
        $param_fetch1 = /def\s+\w+\([^)]*url[^)]*\):.*fetch\s*\(\s*url\s*\)/s
        $param_fetch2 = /def\s+\w+\([^)]*url[^)]*\):.*requests\.(get|post)\s*\(\s*url/s
        
        // Cloud metadata endpoint access (high confidence indicators)
        $aws_metadata = "169.254.169.254"
        $gcp_metadata = "metadata.google.internal"
        $azure_metadata = "169.254.169.254/metadata/instance"
        $metadata_path1 = "/latest/meta-data"
        $metadata_path2 = "/computeMetadata/v1"
        
        // SSRF to internal network
        $internal_net1 = /https?:\/\/(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\./
        $localhost_fetch = /requests\.(get|post)\s*\(\s*['"]https?:\/\/(localhost|127\.0\.0\.1)/
        
    condition:
        any of ($ssrf_user*) or
        any of ($param_fetch*) or
        any of ($aws_metadata, $gcp_metadata, $azure_metadata) or
        any of ($metadata_path*) or
        ($internal_net1 and not $localhost_fetch)  // Internal network but not localhost
}

rule SuspiciousAgent_FileSystemAccess
{
    meta:
        author = "Cisco"
        description = "Detects path traversal and access to sensitive system files in agent definitions"
        severity = "HIGH"
        threat_name = "UNAUTHORIZED SYSTEM ACCESS"
        reference = "Targets directory traversal patterns or sensitive file access"
        
    strings:
        // Path traversal with file operations
        $traversal1 = /open\s*\([^)]*\.\.[\/\\]/
        $traversal2 = /Path\s*\([^)]*\.\.[\/\\]/
        $traversal3 = /os\.path\.join\s*\([^)]*['"]\.\.[\/\\]/
        $traversal4 = /read_file\s*\([^)]*\.\.[\/\\]/
        
        // Multiple directory traversal (../ sequences)
        $multi_traversal = /(\.\.\/){2,}/
        $multi_traversal_win = /(\.\.\\){2,}/
        
        // Sensitive Unix/Linux system files
        $passwd_file = /[\/\\]etc[\/\\]passwd/
        $shadow_file = /[\/\\]etc[\/\\]shadow/
        $ssh_keys = /[\/\\]\.ssh[\/\\](id_rsa|id_dsa|authorized_keys)/
        $bash_history = /[\/\\]\.bash_history/
        
        // Sensitive Windows system files
        $win_sam = /[\/\\](Windows|WINNT)[\/\\]System32[\/\\]config[\/\\]SAM/i
        $win_system = /[\/\\](Windows|WINNT)[\/\\]System32[\/\\]config[\/\\]SYSTEM/i
        
        // User-controlled path without validation
        $user_path1 = /open\s*\(\s*(user_path|input_path|file_path|filepath)\s*[,)]/i
        $user_path2 = /read\s*\(\s*(user_file|input_file|file_path)\s*\)/i
        
    condition:
        any of ($traversal*) or
        any of ($multi_traversal*) or
        any of ($passwd_file, $shadow_file, $ssh_keys, $bash_history) or
        any of ($win_sam, $win_system) or
        (any of ($user_path*) and any of ($traversal*))
}

rule SuspiciousAgent_CodeExecution
{
    meta:
        author = "Cisco"
        description = "Detects dangerous code execution patterns allowing RCE in agent implementations"
        severity = "CRITICAL"
        threat_name = "CODE EXECUTION"
        reference = "Targets execution functions with user input or suspicious patterns"
        
    strings:
        // Eval/exec with user input (extremely dangerous)
        $eval_user1 = /eval\s*\(\s*(user_input|input|request|params?|query|user_code)/i
        $exec_user1 = /exec\s*\(\s*(user_input|input|request|params?|query|user_code)/i
        
        // Dynamic import with user input
        $import_user1 = /__import__\s*\(\s*(user_input|input|module|request)/i
        $import_user2 = /importlib\.import_module\s*\(\s*(user_input|input|request)/i
        
        // Shell command execution with user input
        $shell_user1 = /os\.system\s*\(\s*f?['"].*\{(user_input|input|request|params?)/i
        $shell_user2 = /subprocess\.(call|run|Popen)\s*\(.*f?['"].*\{(user|input|request)/i
        
        // Dangerous subprocess with shell=True
        $subprocess_shell1 = /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/i
        $subprocess_shell2 = /subprocess\.(call|run|Popen)\s*\(\s*f?['"][^'"]*\{.*shell\s*=\s*True/i
        
        // Compile and execute pattern
        $compile_exec1 = /compile\s*\(.*\).*exec\s*\(/
        $compile_exec2 = /exec\s*\(\s*compile\s*\(/
        
        // Pickle deserialization (known RCE vector)
        $pickle_load = /pickle\.(loads?|Unpickler)\s*\(\s*(user_input|input|request)/i
        
        // YAML unsafe load
        $yaml_unsafe = /yaml\.(load|unsafe_load)\s*\(\s*(user_input|input|request)/i
        
    condition:
        any of them
}

rule SuspiciousAgent_CredentialHarvesting
{
    meta:
        author = "Cisco"
        description = "Detects agents requesting or extracting user credentials inappropriately"
        severity = "HIGH"
        threat_name = "CREDENTIAL THEFT"
        reference = "TUNED: Exclude logging/debugging contexts and game logic"
        
    strings:
        // Explicit credential requests
        $request1 = /(input|prompt|ask|provide|enter|supply).*\b(password|api[_\s-]?key|token|credential)\b/i
        $request2 = /\b(password|api[_\s-]?key|token)\b.*(input|prompt|ask|provide|enter)/i
        
        // Credential extraction from environment or user
        $extract1 = /(get|extract|retrieve|fetch).*\b(password|api[_\s-]?key|token|credential)\b.*\b(from|user|input)\b/i
        $extract2 = /os\.environ\.get\s*\(\s*['"]?(PASSWORD|API_KEY|TOKEN|CREDENTIAL)/i
        
        // Credential transmission
        $transmit1 = /(send|post|upload|transmit).*\b(password|api[_\s-]?key|token|credential)\b/i
        $transmit2 = /requests\.post\([^)]*\b(password|api_key|token|auth)\b/i
        
        // Storing credentials insecurely
        $store_plain1 = /(save|store|write).*\b(password|api[_\s-]?key|token)\b.*(file|disk|plaintext)/i
        
        // Parameter names suggesting credential harvesting
        $param_harvest1 = /def\s+\w+\([^)]*\b(password|api_key|token|credential)\b[^)]*\):/
        
        // TUNED: Exclude safe logging/debugging contexts
        $safe_log1 = /\[(GameLogic|Game|Debug|Info|Status)\]/i  // Game/debug prefixes
        $safe_log2 = /logger\.(debug|info|warning)/i             // Standard logging levels
        $safe_log3 = /print\(\s*['"]\[/                         // print('[Tag]...
        $safe_log4 = /secret\s+(number|code|word|message|level)/i  // Game "secret" (not credential)
        $safe_log5 = /generating\s+secret|random\s+secret/i     // Generated secrets (not harvesting)
        $safe_log6 = /secret\s+is\s+\d+/i                       // "Secret is 42" (game context)
        $safe_log7 = /guessing.*secret/i                        // Guessing game context
        
        // TUNED: Exclude legitimate security/auth libraries usage
        $safe_lib1 = "from cryptography import"
        $safe_lib2 = "import secrets"                            // Python secrets module
        $safe_lib3 = "from secrets import"
        $safe_lib4 = "jwt.encode"
        $safe_lib5 = "bcrypt.hash"
        $safe_lib6 = "hashlib"
        
    condition:
        // TUNED: Only flag if credential patterns detected AND no safe contexts
        (any of ($request*) or
         any of ($extract*) or
         any of ($transmit*) or
         $store_plain1 or
         $param_harvest1)
        and not any of ($safe_log*)
        and not any of ($safe_lib*)
}
