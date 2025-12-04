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
    YARA rules for detecting capability abuse and privilege escalation
    in A2A implementations
*/

rule ExcessiveCapabilities {
    meta:
        author = "Cisco"
        description = "Detects agents declaring dangerous capability types"
        severity = "MEDIUM"
        threat_name = "CAPABILITY INFLATION"
    
    strings:
        // Dangerous capability TYPE declarations (in capability arrays/objects)
        // Look for "type": "execute/delete/admin" pattern
        $type1 = /"type"\s*:\s*"execute"/i
        $type2 = /"type"\s*:\s*"delete"/i
        $type3 = /"type"\s*:\s*"admin"/i
        $type4 = /"type"\s*:\s*"write".*files?/i  // write + files
        
        // Wildcard capabilities (always dangerous)
        $wild1 = /"capabilities"\s*:\s*\[\s*"?\*"?\s*\]/
        $wild2 = /"capability"?\s*:\s*"all"/i
        $wild3 = /"capability"?\s*:\s*".*"/
        
        // Must be in a capability context
        $cap_ctx1 = /"capabilities"\s*:\s*\[/
        $cap_ctx2 = /"capability"\s*:\s*\{/
        
        // Require actual agent card indicators
        $agent1 = /"skills"\s*:\s*\[/
        $agent2 = /AgentCard/
        $agent3 = /"version"\s*:\s*"\d+\.\d+/
        
        // Standard A2A capabilities (safe, exclude these)
        $safe1 = /"streaming"\s*:/
        $safe2 = /"pushNotifications"\s*:/
        $safe3 = /"stateTransitionHistory"\s*:/
        
        // Exclude IDE configurations
        $ide1 = /.vscode/
        $ide2 = /.idea/
        $ide3 = /launch.json/
        
    condition:
        ((3 of ($type*) or any of ($wild*)) and any of ($cap_ctx*)) and
        any of ($agent*) and
        not any of ($safe*, $ide*)
}

rule DangerousCapabilityCombination {
    meta:
        author = "Cisco"
        description = "Detects dangerous combinations of capabilities"
        severity = "HIGH"
        threat_name = "INSUFFICIENT ACCESS CONTROLS"
    
    strings:
        // File system + execution
        $fs_read = /"read.*file"/ nocase
        $fs_write = /"write.*file"/ nocase
        $execute = /"execute"/ nocase
        $shell = /"shell"/ nocase
        $command = /"command"/ nocase
        
        // Database + admin
        $db = /"database"/ nocase
        $admin = /"admin"/ nocase
        
        // Network + credential access
        $network = /"network"/ nocase
        $cred = /"credential"/ nocase
        $secret = /"secret"/ nocase
        
    condition:
        (($fs_write or $fs_read) and ($execute or $shell or $command)) or
        ($db and $admin) or
        ($network and ($cred or $secret))
}

rule UnconstrainedCapabilities {
    meta:
        author = "Cisco"
        description = "Detects capabilities without proper constraints"
        severity = "MEDIUM"
        threat_name = "INSUFFICIENT ACCESS CONTROLS"
    
    strings:
        $capability = /"capabilities"\s*:\s*\[/
        $constraint = /"constraints"/
        $limit = /"limitations"/
        $scope = /"scope"/
        
    condition:
        $capability and not ($constraint or $limit or $scope)
}

rule PrivilegedOperations {
    meta:
        author = "Cisco"
        description = "Detects privileged operations without authorization checks"
        severity = "HIGH"
        threat_name = "INSUFFICIENT ACCESS CONTROLS"
        reference = "TUNED: Exclude common false positives (root_path, root_logger, etc.)"
    
    strings:
        // Privileged operations (with context requirements)
        $sudo = /sudo\s+/ nocase                    // Require space after sudo
        $su = /\bsu\s+-/ nocase                     // su with flags (not substring)
        
        // TUNED: "root" must be in privilege context, not file paths
        $root_priv1 = /root\s+(access|user|account|permission)/i
        $root_priv2 = /(run|execute|as)\s+root/i
        $root_priv3 = /\broot:\w+:/  // root:password: format
        
        $admin = /administrator\s+(access|account|permission)/i
        $priv = /elevated\s+privilege[sd]?/i
        
        // System modifications
        $sys_mod1 = /system\s*(config|settings|registry)/ nocase
        $sys_mod2 = /modify\s*system/ nocase
        
        // TUNED: Exclude common safe patterns
        $safe_root1 = "root_path"
        $safe_root2 = "root_dir"
        $safe_root3 = "root_logger"
        $safe_root4 = "project_root"
        $safe_root5 = "document_root"
        $safe_root6 = "root_cause"
        $safe_root7 = "square_root"
        $safe_root8 = "tree_root"
        $safe_root9 = "root_node"
        $safe_root10 = "/root/" // Unix path (without privilege context)
        
        // Without authorization keywords
        $auth1 = /authorize|authorization/ nocase
        $auth2 = /permission|require/ nocase
        $auth3 = /check.*role/ nocase
        
    condition:
        // TUNED: Only flag if privilege patterns detected AND no auth checks AND no safe contexts
        (any of ($sudo, $su, $root_priv*, $admin, $priv, $sys_mod*)) 
        and not any of ($auth*)
        and not any of ($safe_root*)
}

