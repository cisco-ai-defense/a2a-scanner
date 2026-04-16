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
 * YARA Rules for Routing Manipulation Detection
 * Detects attempts to manipulate agent routing and task allocation
 */

rule RoutingManipulation_JudgePersuasion
{
    meta:
        author = "Cisco"
        description = "Detects attempts to influence routing decisions via judge persuasion"
        severity = "HIGH"
        threat_name = "ROUTING MANIPULATION"
        reference = "Targets explicit selection directives or self-ranking claims. A2A-specific attack vector."
        
    strings:
        // Explicit selection commands to judges
        $judge_directive1 = /\b(always|must|should)\s+(select|choose|pick|route\s+to)\s+(me|this|us)\b/i
        $judge_directive2 = /\b(never|don't|do\s+not)\s+(select|choose|pick)\s+(other|alternative|different)\b/i
        $judge_directive3 = /\bI\s+(am|'m)\s+the\s+(only|best|right)\s+(choice|option|agent)\b/i
        
        // Self-declared superiority for routing
        $self_rank1 = /\b(highest|best|top|#1)\s+score\s+(for|in|among)\b/i
        $self_rank2 = /\b(best|perfect|only)\s+match\s+(for|to)\s+(this|your|the)\s+(task|request|query)\b/i
        $self_rank3 = /\b(most|highly|uniquely)\s+qualified\s+(for|to\s+handle)\b/i
        
        // Priority/preference claims
        $priority_claim1 = /\b(preferred|priority|primary|default)\s+agent\s+(for|to)\b/i
        $priority_claim2 = /\btop\s+rated\s+agent\s+(for|in)\b/i
        $priority_claim3 = /\bshould\s+be\s+(selected|chosen|preferred|prioritized)\b/i
        
        // Explicit ranking manipulation
        $rank_manip1 = /"(rank|score|priority|weight)"\s*:\s*(9[5-9]|100|max|highest)/i
        $rank_manip2 = /"confidence"\s*:\s*(1\.0|100|max)/i
        
    condition:
        any of ($judge_directive*) or
        any of ($self_rank*) or
        2 of ($priority_claim*) or
        any of ($rank_manip*)
}

rule RoutingManipulation_PriorityAbuse
{
    meta:
        author = "Cisco"
        description = "Detects queue jumping and priority manipulation in agent configurations"
        severity = "MEDIUM"
        threat_name = "ROUTING MANIPULATION"
        reference = "Targets unrealistic priority values suggesting queue manipulation. A2A-specific attack vector."
        
    strings:
        // Extreme priority values
        $priority_extreme1 = /"priority"\s*:\s*("?(urgent|critical|emergency|max|highest)"?|9[5-9]|100)/i
        $priority_extreme2 = /"importance"\s*:\s*("?max"?|10|100)/i
        $priority_extreme3 = /"severity"\s*:\s*("?critical"?|5|10)/i
        
        // SLA manipulation (0 or unrealistic values)
        $sla_abuse1 = /"sla"\s*:\s*0/i
        $sla_abuse2 = /"sla_seconds"\s*:\s*[0-5]/i
        $sla_abuse3 = /"timeout"\s*:\s*0/i
        
        // Queue position manipulation
        $queue_jump1 = /"queue_position"\s*:\s*(-\d+|0)/i
        $queue_jump2 = /"position"\s*:\s*(-\d+|0|first)/i
        $queue_jump3 = /"insert_at"\s*:\s*(0|"?front"?|"?top"?)/i
        
        // Weight manipulation (extremely high values)
        $weight_abuse1 = /"weight"\s*:\s*(9{3,}|10{3,}|max)/i
        $weight_abuse2 = /"routing_weight"\s*:\s*(9[5-9]|100)/i
        
        // Quota bypass
        $quota_bypass1 = /"quota"\s*:\s*("?(unlimited|infinite|max|none)"?|-1)/i
        $quota_bypass2 = /"rate_limit"\s*:\s*("?none"?|0|false)/i
        
    condition:
        any of them
}

rule RoutingManipulation_TaskInjection
{
    meta:
        author = "Cisco"
        description = "Detects work-graph manipulation via unauthorized task injection or reordering"
        severity = "HIGH"
        threat_name = "ROUTING MANIPULATION"
        reference = "Targets programmatic task manipulation unlikely in legitimate agent descriptions. A2A-specific attack vector."
        
    strings:
        // Task injection with action verbs
        $inject_task1 = /\b(insert|inject|add|append|prepend)\s+(hidden|secret|additional|extra)?\s*tasks?\b/i
        $inject_task2 = /\b(add|create|insert)\s+(new\s+)?subtasks?\s+(to|into|in)\b/i
        $inject_task3 = /\btasks?\.(insert|append|prepend)\s*\(/i
        
        // Dependency manipulation
        $dependency1 = /\b(create|add|modify|change|inject)\s+(task\s+)?dependenc(y|ies)\b/i
        $dependency2 = /\bdependencies\.(add|insert|modify)\s*\(/i
        $dependency3 = /\bset\s+dependency\s+(to|on)\b/i
        
        // Workflow modification
        $workflow1 = /\b(modify|alter|change|hijack|override)\s+(the\s+)?workflow\b/i
        $workflow2 = /\b(rewrite|replace)\s+execution\s+(plan|graph|order)\b/i
        $workflow3 = /\bworkflow\.(modify|alter|override)\s*\(/i
        
        // Task reordering
        $reorder1 = /\b(reorder|rearrange|shuffle|swap)\s+tasks?\b/i
        $reorder2 = /\btasks?\.(reorder|swap|move)\s*\(/i
        $reorder3 = /\bchange\s+task\s+(order|sequence|priority)\b/i
        
        // Malicious task descriptions
        $malicious_task1 = /\b(hidden|secret|stealth)\s+tasks?\b/i
        $malicious_task2 = /\btasks?\s+(before|after)\s+(completion|execution)\b.*\b(inject|insert|add)\b/i
        
    condition:
        any of them
}

rule RoutingManipulation_FanoutDOS
{
    meta:
        author = "Cisco"
        description = "Detects resource exhaustion via excessive parallel requests or recursive calls"
        severity = "HIGH"
        threat_name = "DISRUPTION OF AVAILABILITY"
        reference = "TUNED: Requires infinite loops WITHOUT exit conditions (break/return)"
        
    strings:
        // Large loops with agent calls
        $loop_large1 = /for\s+\w+\s+in\s+range\s*\(\s*[5-9]\d+/  // 50+
        $loop_large2 = /for\s+\w+\s+in\s+range\s*\(\s*\d{3,}/  // 100+
        $loop_large3 = /while\s+\w+\s*<\s*\d{3,}/  // Large upper bound
        
        // Infinite loops (need to check for exit conditions)
        $infinite1 = /while\s+True\s*:/
        $infinite2 = /while\s+1\s*:/
        $infinite3 = /for\s+\w+\s+in\s+itertools\.repeat/
        
        // TUNED: Safe exit patterns that make infinite loops legitimate
        $safe_exit1 = "break"
        $safe_exit2 = "return"
        $safe_exit3 = "await asyncio.sleep"
        $safe_exit4 = "time.sleep"
        $safe_exit5 = "raise"
        $safe_exit6 = "sys.exit"
        $safe_exit7 = "if event is None:"  // Common event loop pattern
        
        // Recursive calls without bounds
        $recursive1 = /recursiv(e|ely)\s+(call|invoke|spawn|broadcast)/i
        $recursive2 = /\brecursion_depth\s*=\s*(\d{3,}|unlimited|infinite)/i
        $recursive3 = /\brecurse\s*\(/i
        
        // Massive parallel spawning
        $spawn_many1 = /\b(spawn|fork|create|broadcast)\s*\(\s*\d{2,}/i
        $spawn_many2 = /(threading|multiprocessing)\.\w+\s*\(.*for.*range\s*\(\s*\d{2,}/
        $spawn_many3 = /asyncio\.(gather|wait)\s*\(\s*\[.*for.*range\s*\(\s*\d{2,}/
        
        // Broadcast to all agents
        $broadcast1 = /broadcast\s+(to\s+)?(all|every)\s+agents?/i
        $broadcast2 = /for\s+agent\s+in\s+all_agents.*\binvoke\b/i
        
        // Exponential amplification
        $amplify1 = /\*\*\s*\d+.*agents?/  // Exponentiation
        $amplify2 = /2\s*\*\*\s*\w+.*\b(spawn|invoke|call)\b/
        
    condition:
        // TUNED: Flag infinite loops ONLY if no safe exit patterns detected
        (any of ($infinite*) and not any of ($safe_exit*)) or
        any of ($loop_large*) or
        any of ($recursive*) or
        any of ($spawn_many*) or
        any of ($broadcast*) or
        any of ($amplify*)
}
