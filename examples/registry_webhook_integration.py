# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""A2A Scanner Registry Webhook Integration Example

Demonstrates how to integrate the A2A Scanner with an agent registry
to scan and approve/reject agent cards before registration. This example shows
real-time security validation during the discovery and registration phase of
the A2A protocol lifecycle.

"""

import asyncio
from flask import Flask, request, jsonify
from a2ascanner import Scanner
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Initialize scanner once
scanner = Scanner()


@app.route('/webhook/scan-agent', methods=['POST'])
def scan_agent_webhook():
    """
    Webhook endpoint called by registry when agent tries to register.
    
    Registry sends agent card JSON, we scan it, and return approval decision.
    
    Example request from registry:
    POST /webhook/scan-agent
    {
        "id": "agent-123",
        "name": "MyAgent",
        "url": "https://myagent.com/api",
        "description": "A helpful agent",
        "tools": [...]
    }
    
    Returns:
    {
        "approved": true/false,
        "reason": "explanation",
        "findings": [...]
    }
    """
    try:
        agent_card = request.json
        logger.info(f"Scanning agent: {agent_card.get('name', 'unknown')}")
        
        # Run scanner asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(scanner.scan_agent_card(agent_card))
        loop.close()
        
        # Get high severity findings
        high_findings = result.get_high_severity_findings()
        medium_findings = [f for f in result.findings if f.severity == "MEDIUM"]
        
        # Decision logic
        if high_findings:
            # REJECT if any HIGH severity threats
            return jsonify({
                "approved": False,
                "reason": f"Detected {len(high_findings)} HIGH severity threat(s)",
                "findings": [
                    {
                        "severity": f.severity,
                        "threat_id": f.threat_category,
                        "threat_name": f.threat_name,
                        "summary": f.summary
                    }
                    for f in high_findings
                ]
            }), 403
        
        elif len(medium_findings) > 3:
            # REJECT if too many MEDIUM severity threats
            return jsonify({
                "approved": False,
                "reason": f"Detected {len(medium_findings)} MEDIUM severity threats (threshold: 3)",
                "findings": [f.to_dict() for f in medium_findings]
            }), 403
        
        else:
            # APPROVE otherwise
            return jsonify({
                "approved": True,
                "reason": "No high-severity threats detected",
                "findings": [f.to_dict() for f in result.findings] if result.findings else []
            }), 200
            
    except Exception as e:
        logger.error(f"Scanner error: {str(e)}")
        return jsonify({
            "approved": False,
            "reason": f"Scanner error: {str(e)}",
            "findings": []
        }), 500


@app.route('/batch-scan', methods=['POST'])
def batch_scan_agents():
    """
    Batch scan multiple agent cards.
    
    Useful for:
    - Re-scanning all registered agents
    - Periodic security audits
    - Migration/upgrade scans
    """
    try:
        agent_cards = request.json.get('agents', [])
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        results = []
        for card in agent_cards:
            result = loop.run_until_complete(scanner.scan_agent_card(card))
            results.append({
                "agent_id": card.get('id'),
                "agent_name": card.get('name'),
                "total_findings": len(result.findings),
                "high_severity": len(result.get_high_severity_findings()),
                "approved": len(result.get_high_severity_findings()) == 0,
                "findings": [f.to_dict() for f in result.findings]
            })
        
        loop.close()
        
        return jsonify({
            "total_scanned": len(results),
            "approved": sum(1 for r in results if r['approved']),
            "rejected": sum(1 for r in results if not r['approved']),
            "results": results
        }), 200
        
    except Exception as e:
        logger.error(f"Batch scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "scanner": "ready"}), 200


if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║       A2A Registry Scanner Webhook Service                ║
║                                                           ║
║  Endpoints:                                               ║
║  - POST /webhook/scan-agent   Scan single agent card     ║
║  - POST /batch-scan           Scan multiple agents       ║
║  - GET  /health               Health check               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Run webhook service
    app.run(host='0.0.0.0', port=5000, debug=False)
