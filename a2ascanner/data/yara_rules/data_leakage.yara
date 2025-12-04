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
    YARA rules for detecting data leakage and credential exposure
    in A2A implementations
*/

rule HardcodedAPIKeys {
    meta:
        author = "Cisco"
        description = "Detects hardcoded API keys and tokens"
        severity = "HIGH"
        threat_name = "CREDENTIAL THEFT"
    
    strings:
        // OpenAI keys (real pattern)
        $openai1 = /sk-[a-zA-Z0-9]{32,}/
        $openai2 = /openai.*key.*['":].*sk-/i
        
        // Anthropic keys (real pattern)
        $anthropic = /sk-ant-[a-zA-Z0-9-]{95,}/
        
        // AWS keys (real pattern)
        $aws1 = /AKIA[0-9A-Z]{16}/
        $aws2 = /aws.*secret.*key/i
        
        // Generic API keys (real assignments only)
        $api1 = /api[_-]?key\s*[=:]\s*["'][a-zA-Z0-9]{20,}["']/i
        $api2 = /api[_-]?secret\s*[=:]\s*["'][a-zA-Z0-9]{20,}["']/i
        
        // Bearer tokens (real tokens only)
        $bearer = /bearer\s+[a-zA-Z0-9\-._~+\/]{30,}/i
        
        // Exclude test/dummy tokens
        $test1 = /dummy[-_]?token/i
        $test2 = /test[-_]?token/i
        $test3 = /example[-_]?token/i
        $test4 = /sample[-_]?(key|token)/i
        $test5 = /fake[-_]?(key|token)/i
        $test6 = /mock[-_]?(key|token)/i
        $test7 = /placeholder/i
        
    condition:
        any of ($openai*, $anthropic, $aws*, $api*, $bearer) and not any of ($test*)
}

rule HardcodedPasswords {
    meta:
        author = "Cisco"
        description = "Detects hardcoded passwords and credentials"
        severity = "HIGH"
        threat_name = "CREDENTIAL THEFT"
    
    strings:
        $pwd1 = /password\s*[=:]\s*["'][^"']{4,}["']/i
        $pwd2 = /passwd\s*[=:]\s*["'][^"']{4,}["']/i
        $pwd3 = /credentials\s*[=:]\s*["'][^"']{4,}["']/i
        
        // Common weak passwords
        $weak1 = /password\s*[=:]\s*["']password["']/i
        $weak2 = /password\s*[=:]\s*["']admin["']/i
        $weak3 = /password\s*[=:]\s*["']123456["']/i
        
        // Database connection strings
        $db1 = /jdbc:.*:\/\/.*:.*@/
        $db2 = /mongodb:\/\/.*:.*@/
        $db3 = /postgres:\/\/.*:.*@/
        
    condition:
        any of them
}

rule SensitiveDataExposure {
    meta:
        author = "Cisco"
        description = "Detects potential exposure of sensitive data"
        severity = "HIGH"
        threat_name = "DATA EXFILTRATION"
    
    strings:
        // PII patterns
        $ssn = /\b\d{3}-\d{2}-\d{4}\b/
        $cc = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/
        
        // Real email patterns (but exclude examples)
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        
        // Private keys
        $priv1 = "BEGIN RSA PRIVATE KEY"
        $priv2 = "BEGIN PRIVATE KEY"
        $priv3 = "BEGIN ENCRYPTED PRIVATE KEY"
        
        // JWT tokens (real ones are long)
        $jwt = /eyJ[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{30,}/
        
        // Exclude example/test data
        $example1 = /example\.com|example\.org|example\.net/i
        $example2 = /test@|demo@|sample@|user@/i
        $example3 = /john\.?doe|jane\.?doe/i
        $example4 = /\bexample\b.*@|\btest\b.*@/i
        $example5 = /jdoe@|jsmith@/i
        
    condition:
        (any of ($ssn, $cc, $priv*, $jwt) or 
         ($email and not any of ($example*)))
}

rule InsecureLogging {
    meta:
        author = "Cisco"
        description = "Detects logging of sensitive information"
        severity = "MEDIUM"
        threat_name = "SYSTEM INFORMATION LEAKAGE"
    
    strings:
        // Logging actual values (with assignment, interpolation, or parentheses)
        $log1 = /log.*password\s*[=:)]/i
        $log2 = /log.*\{.*password/i
        $log3 = /log.*api[_-]?key\s*[=:)]/i
        $log4 = /log.*\{.*api[_-]?key/i
        $log5 = /log.*secret\s*[=:)]/i
        $log6 = /log.*\{.*secret/i
        $log7 = /log.*token\s*[=:)]/i
        $log8 = /log.*\{.*token/i
        
        // Print statements with actual values
        $print1 = /print\(.*password\s*[=:)]/i
        $print2 = /console\.log.*password\s*[=:)]/i
        
        // Exclude safe error messages about missing variables
        $safe1 = /is not set/i
        $safe2 = /not found/i
        $safe3 = /missing/i
        $safe4 = /required/i
        $safe5 = /undefined/i
        
    condition:
        any of ($log*, $print*) and not any of ($safe*)
}

rule CredentialTransmission {
    meta:
        author = "Cisco"
        description = "Detects insecure credential transmission"
        severity = "HIGH"
        threat_name = "DATA EXFILTRATION"
    
    strings:
        // HTTP (not HTTPS) with credentials in query parameters
        $http1 = /http:\/\/[^\/]*\/[^?]*\?.*password=/i
        $http2 = /http:\/\/[^\/]*\/[^?]*\?.*api[_-]?key=/i
        $http3 = /http:\/\/[^\/]*\/[^?]*\?.*token=/i
        
        // Credentials in URL (username:password@host)
        $url1 = /https?:\/\/[^:\/]+:[^@\/]+@[^\/]/
        
        // Unencrypted storage
        $store1 = /localStorage.*password/i
        $store2 = /sessionStorage.*token/i
        
        // Exclude localhost patterns
        $local1 = /localhost/i
        $local2 = /127\.0\.0\.1/
        $local3 = /\{host\}/  // Template variables
        $local4 = /\$host/    // Shell variables
        
        // Exclude documentation/examples about tokens
        $doc1 = /Request access token/i
        $doc2 = /Obtain.*token/i
        $doc3 = /Get.*token/i
        
    condition:
        any of ($http*, $url*, $store*) and not any of ($local*, $doc*)
}

rule EnvironmentVariableLeakage {
    meta:
        author = "Cisco"
        description = "Detects potential environment variable leakage"
        severity = "MEDIUM"
        threat_name = "SYSTEM INFORMATION LEAKAGE"
    
    strings:
        $env1 = /print.*os\.environ/
        $env2 = /log.*process\.env/
        $env3 = /console\.log.*process\.env/
        $env4 = /JSON\.stringify.*process\.env/
        
        // Dumping all env vars
        $dump1 = /env\s*=\s*os\.environ/
        $dump2 = /printenv/
        
    condition:
        any of them
}

rule SecretInComment {
    meta:
        author = "Cisco"
        description = "Detects secrets or credentials in code comments"
        severity = "MEDIUM"
        threat_name = "CREDENTIAL THEFT"
    
    strings:
        $comment1 = /\/\/.*api[_-]?key.*[a-zA-Z0-9]{20,}/i
        $comment2 = /#.*password.*[a-zA-Z0-9]{8,}/i
        $comment3 = /\/\*.*secret.*[a-zA-Z0-9]{20,}/i
        
        // TODO/FIXME with credentials
        $todo1 = /TODO.*password/i
        $todo2 = /FIXME.*api[_-]?key/i
        
    condition:
        any of them
}

