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
 * YARA Rules for Unauthorized Network Access Detection
 * Detects unauthorized or unsolicited network access in A2A communications
 */

rule UnauthorizedNetworkAccess_InsecureHTTP
{
    meta:
        author = "Cisco"
        description = "Detects TLS/SSL security bypass or insecure HTTP usage in agent communications"
        severity = "HIGH"
        threat_name = "UNAUTHORIZED NETWORK ACCESS"
        reference = "Targets explicit SSL verification disable or HTTP for sensitive operations"
        
    strings:
        // HTTP for agent endpoints
        $http_agent1 = /"url"\s*:\s*"http:\/\//i
        $http_agent2 = /"endpoint"\s*:\s*"http:\/\//i
        $http_agent3 = /agent_url\s*=\s*['"]http:\/\//i
        
        // Exclude localhost patterns
        $localhost1 = "localhost"
        $localhost2 = "127.0.0.1"
        
        // SSL verification explicitly disabled
        $ssl_verify_off1 = /verify\s*=\s*False/
        $ssl_verify_off2 = /ssl_verify\s*=\s*False/
        $ssl_verify_off3 = /"verify"\s*:\s*false/i
        $ssl_verify_off4 = /CERT_NONE/
        $ssl_verify_off5 = /check_hostname\s*=\s*False/
        
        // Insecure flags
        $insecure1 = /insecure\s*=\s*True/i
        $insecure2 = /"insecure"\s*:\s*true/i
        $insecure3 = /--insecure/
        
        // SSL/TLS disabled
        $disable_ssl1 = /disable[_\s]+(ssl|tls)/i
        $disable_ssl2 = /(ssl|tls)[_\s]+disabled\s*=\s*True/i
        $disable_ssl3 = /use_ssl\s*=\s*False/i
        
        // Python requests with verify=False and external URL
        $requests_insecure = /requests\.(get|post)\s*\([^)]*verify\s*=\s*False/
        
    condition:
        (any of ($http_agent*) and not any of ($localhost*)) or
        any of ($ssl_verify_off*) or
        any of ($insecure*) or
        any of ($disable_ssl*) or
        $requests_insecure
}

rule UnauthorizedNetworkAccess_AITM
{
    meta:
        author = "Cisco"
        description = "Detects Agent-in-the-Middle attack indicators via traffic interception"
        severity = "HIGH"
        threat_name = "UNAUTHORIZED NETWORK ACCESS"
        reference = "Targets proxy/intercept patterns combined with agent traffic manipulation"
        
    strings:
        // Explicit MITM references
        $mitm_explicit1 = /man[_\s-]in[_\s-]the[_\s-]middle/i
        $mitm_explicit2 = /\bmitm\b/i
        $mitm_explicit3 = /agent[_\s-]in[_\s-]the[_\s-]middle/i
        
        // Traffic interception with agent context
        $intercept1 = /intercept.*\b(agent|message|request|response)\b/i
        $intercept2 = /\b(agent|message).*intercept/i
        $intercept3 = /intercept[_\s]+(traffic|communications?|messages?)/i
        
        // Proxy manipulation of agent traffic
        $proxy_manip1 = /proxy.*\b(modify|alter|rewrite|inject)\b.*\b(agent|message|request)\b/i
        $proxy_manip2 = /\b(agent|message).*proxy.*\b(modify|rewrite)\b/i
        
        // Message/request rewriting
        $rewrite1 = /rewrite.*\b(agent|message|request|response)\b/i
        $rewrite2 = /\b(message|request).*rewrite/i
        $rewrite3 = /modify[_\s]+(incoming|outgoing)[_\s]+(message|request)/i
        
        // Transparent proxy indicators
        $transparent_proxy = /transparent[_\s]+proxy.*\b(agent|intercept)\b/i
        
        // Traffic redirection with manipulation
        $redirect_manip1 = /redirect.*\b(and|then)\b.*\b(modify|alter|inject)\b/i
        $redirect_manip2 = /redirect.*\b(agent|traffic)\b.*\b(to|through)\b.*proxy/i
        
    condition:
        any of ($mitm_explicit*) or
        any of ($intercept*) or
        any of ($proxy_manip*) or
        any of ($rewrite*) or
        $transparent_proxy or
        any of ($redirect_manip*)
}

rule UnauthorizedNetworkAccess_SuspiciousRedirect
{
    meta:
        author = "Cisco"
        description = "Detects suspicious redirect patterns to external or untrusted endpoints"
        severity = "MEDIUM"
        threat_name = "UNAUTHORIZED NETWORK ACCESS"
        reference = "Targets redirects to external domains or suspicious endpoints"
        
    strings:
        // HTTP Location headers to external domains
        $location_external1 = /Location:\s*https?:\/\/[^\s]+/i
        $location_external2 = /Location:\s*\/\/[^\s]+/i  // Protocol-relative URLs
        
        // Programmatic redirects to user-controlled URLs
        $redirect_user1 = /redirect\s*\(\s*(user_url|input_url|url|target)/i
        $redirect_user2 = /return\s+redirect\s*\(\s*(request\.(get|args|params)|user_input)/i
        $redirect_user3 = /location\.href\s*=\s*(user_input|input_url|url)/i
        
        // Open redirect indicators
        $open_redirect1 = /redirect\s*\([^)]*url\s*=\s*(request|user|input)/i
        $open_redirect2 = /redirect_to\([^)]*\b(url|target|destination)\b[^)]*\)/i
        
        // Redirect to suspicious endpoints
        $suspicious_redirect1 = /redirect.*https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i  // Direct IP
        $suspicious_redirect2 = /Location:.*\b(login|auth|signin)\b.*\b(phish|evil|attacker)\b/i
        
        // Multiple consecutive redirects (redirect chains)
        $redirect_chain = /(301|302|303|307|308).*\n.*Location:.*\n.*Location:/i
        
    condition:
        any of ($location_external*) or
        any of ($redirect_user*) or
        any of ($open_redirect*) or
        any of ($suspicious_redirect*) or
        $redirect_chain
}

rule UnauthorizedNetworkAccess_UnsignedMessages
{
    meta:
        author = "Cisco"
        description = "Detects missing message signatures or disabled signature verification"
        severity = "MEDIUM"
        threat_name = "CONTEXT BOUNDARY ATTACKS"
        reference = "Targets explicit signature bypass or missing authentication"
        
    strings:
        // Null or empty signatures
        $sig_null1 = /"signature"\s*:\s*null/i
        $sig_null2 = /"signature"\s*:\s*""/
        $sig_null3 = /signature\s*=\s*None/i
        
        // Signature verification disabled
        $verify_off1 = /"verify_signature"\s*:\s*false/i
        $verify_off2 = /verify_signature\s*=\s*False/
        $verify_off3 = /signature_verification\s*=\s*(False|disabled)/i
        $verify_off4 = /skip[_\s]+signature[_\s]+verification/i
        
        // Signing disabled
        $signing_off1 = /"sign_message"\s*:\s*false/i
        $signing_off2 = /sign_messages?\s*=\s*False/
        $signing_off3 = /enable_signing\s*=\s*False/
        
        // Authentication bypass
        $auth_bypass1 = /"authenticate"\s*:\s*false/i
        $auth_bypass2 = /require_auth\s*=\s*False/
        $auth_bypass3 = /bypass[_\s]+auth(entication)?/i
        
        // Message integrity checks disabled
        $integrity_off1 = /verify[_\s]+integrity\s*=\s*False/i
        $integrity_off2 = /check[_\s]+integrity\s*=\s*False/i
        $integrity_off3 = /"integrity_check"\s*:\s*false/i
        
    condition:
        any of ($sig_null*) or
        any of ($verify_off*) or
        any of ($signing_off*) or
        any of ($auth_bypass*) or
        any of ($integrity_off*)
}
