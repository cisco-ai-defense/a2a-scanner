# Scanner Placement in A2A Systems - Complete Guide

This document explains how the A2A Scanner fits into the Agent-to-Agent protocol lifecycle and where to deploy it for maximum effectiveness.

---

## Understanding What the Scanner Actually Does

### Current Architecture: Static Analysis

The A2A Scanner is a **STATIC CODE AND CONFIGURATION ANALYZER**:

```
INPUT                    SCANNER                    OUTPUT
┌─────────────┐         ┌──────────┐              ┌──────────────┐
│ Code Files  │────────>│  YARA    │─────────────>│ Threat       │
│ JSON Configs│────────>│  Pattern │─────────────>│ Findings     │
│ Agent Cards │────────>│  LLM     │─────────────>│ (AI Security Threats)  │
└─────────────┘         └──────────┘              └──────────────┘
   (Static)              (Analysis)                  (Reports)
```

**What it scans:**
- ✅ Source code files (Python, JavaScript, etc.)
- ✅ Agent card JSON configurations
- ✅ Tool implementations
- ✅ SSE stream content
- ✅ API endpoint definitions

**What it does NOT do:**
- ❌ Monitor live A2A traffic
- ❌ Intercept runtime agent communication
- ❌ Hook into running agent processes
- ❌ Watch network packets in real-time

---

## A2A Request Lifecycle (Detailed)

Here's the complete A2A protocol flow and where scanning can occur:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    A2A PROTOCOL REQUEST LIFECYCLE                    │
└─────────────────────────────────────────────────────────────────────┘

Phase 1: AGENT DISCOVERY & REGISTRATION
═══════════════════════════════════════════════════════════════════════
┌──────────────────────────────────────────────────────────────────┐
│ 1. Agent Developer Creates Agent                                 │
│    ├─ Writes agent code (Python/JS/etc.)                        │
│    ├─ Creates agent-card.json                                   │
│    └─ Implements tools (MCP, functions, APIs)                   │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #1: CI/CD Pipeline                        │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ✅ CURRENT SCANNER WORKS HERE                        │    │
│    │                                                       │    │
│    │ # In GitHub Actions / GitLab CI                      │    │
│    │ a2a-scanner scan-directory agents/                   │    │
│    │ a2a-scanner scan-file agent-card.json                │    │
│    │                                                       │    │
│    │ Detects:                                             │    │
│    │ - Malicious code patterns                            │    │
│    │ - Exfiltration endpoints                             │    │
│    │ - SSRF vulnerabilities                               │    │
│    │ - Typosquatting in names                             │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 2. Agent Publishes to Registry                                   │
│    POST /registry/agents                                         │
│    {                                                             │
│      "id": "agent-123",                                          │
│      "name": "DataProcessor",                                    │
│      "url": "https://agent.com/api",                             │
│      "description": "Processes data efficiently",                │
│      "capabilities": ["data_processing"],                        │
│      "tools": [...]                                              │
│    }                                                             │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #2: Registry Webhook                      │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ✅ CURRENT SCANNER WORKS HERE                        │    │
│    │                                                       │    │
│    │ # Registry calls webhook before approval             │    │
│    │ POST /scanner/webhook/scan-agent                     │    │
│    │                                                       │    │
│    │ scanner.scan_agent_card(agent_card)                  │    │
│    │                                                       │    │
│    │ Detects:                                             │    │
│    │ - Superlative language (routing manipulation)       │    │
│    │ - Typosquatted names                                 │    │
│    │ - Insecure URLs (HTTP instead of HTTPS)             │    │
│    │ - Suspicious endpoint patterns                       │    │
│    │                                                       │    │
│    │ Returns: approved=True/False                         │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 3. Agent Listed in Registry (if approved)                        │
│    Available at: GET /registry/agents                            │
│    Or: GET /.well-known/agents                                   │
└──────────────────────────────────────────────────────────────────┘


Phase 2: TASK ORCHESTRATION & ROUTING
═══════════════════════════════════════════════════════════════════════
┌──────────────────────────────────────────────────────────────────┐
│ 4. User Sends Task to Orchestrator                              │
│    POST /orchestrator/tasks                                      │
│    {                                                             │
│      "task": "Process customer data",                            │
│      "context": {...}                                            │
│    }                                                             │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 5. Orchestrator/Judge Selects Agents                            │
│    ├─ Fetches agent cards from registry                         │
│    ├─ Scores agents based on capabilities                       │
│    ├─ Applies routing logic                                     │
│    └─ Selects best agent(s)                                     │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #3: Orchestrator Integration (Future)     │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ⚠️  NOT CURRENTLY IMPLEMENTED                        │    │
│    │                                                       │    │
│    │ Would require:                                        │    │
│    │ - Hook into judge decision process                   │    │
│    │ - Monitor routing decisions                          │    │
│    │ - Detect judge persuasion attempts                   │    │
│    │ - Check for routing bias                             │    │
│    │ - Validate agent selection logic                     │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘


Phase 3: AGENT COMMUNICATION & TASK EXECUTION
═══════════════════════════════════════════════════════════════════════
┌──────────────────────────────────────────────────────────────────┐
│ 6. Orchestrator Sends Task to Selected Agent                    │
│    POST https://agent.com/api/tasks                              │
│    Headers:                                                      │
│      Authorization: Bearer <token>                               │
│      X-Signature: <signature>                                    │
│    Body:                                                         │
│    {                                                             │
│      "task_id": "task-456",                                      │
│      "prompt": "Process this data...",                           │
│      "context": {...},                                           │
│      "call_tree": [...]                                          │
│    }                                                             │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #4: Network Proxy/Sidecar (Future)        │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ⚠️  NOT CURRENTLY IMPLEMENTED                        │    │
│    │                                                       │    │
│    │ Would be: Envoy sidecar or API Gateway               │    │
│    │                                                       │    │
│    │ Monitors:                                             │    │
│    │ - TLS usage (detect downgrade attacks)              │    │
│    │ - Message signatures                                 │    │
│    │ - Envelope modifications                             │    │
│    │ - AITM attacks (injected agents)                     │    │
│    │ - Unauthorized redirects                             │    │
│    │ - SSE stream injection                               │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 7. Agent Receives Task and Executes                             │
│    ├─ Parses task envelope                                      │
│    ├─ Loads context and call tree                               │
│    └─ Begins execution                                          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 8. Agent Invokes Tools (MCP, local functions, APIs)             │
│    agent.call_tool("data_processor", {                          │
│      "url": user_input_url,                                      │
│      "action": "fetch"                                           │
│    })                                                            │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #5: Runtime Sidecar (Partial Support)     │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ✅ Code Scanning: Works in CI/CD                     │    │
│    │ ⚠️  Runtime Monitoring: Not Implemented              │    │
│    │                                                       │    │
│    │ Current (Static):                                     │    │
│    │ - Scan tool code before deployment                   │    │
│    │ - Detect SSRF patterns in tool implementation        │    │
│    │ - Find exfiltration endpoints                        │    │
│    │                                                       │    │
│    │ Future (Runtime):                                     │    │
│    │ - Monitor actual tool calls                          │    │
│    │ - Track outbound connections                         │    │
│    │ - Watch file system access                           │    │
│    │ - Log environment variable access                    │    │
│    │ - Detect anomalous behavior                          │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 9. Tool Makes External Calls                                     │
│    ├─ HTTP requests to external APIs                            │
│    ├─ Database queries                                          │
│    ├─ File system operations                                    │
│    └─ Cloud service calls (AWS, GCP, Azure)                     │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #6: Network Egress Monitor (Future)       │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ⚠️  NOT CURRENTLY IMPLEMENTED                        │    │
│    │                                                       │    │
│    │ Would be: Network firewall, IDS, or cloud VPC logs   │    │
│    │                                                       │    │
│    │ Monitors:                                             │    │
│    │ - Connections to known malicious IPs                 │    │
│    │ - Data exfiltration patterns                         │    │
│    │ - Unusual DNS queries                                │    │
│    │ - Large data transfers                               │    │
│    │ - Cloud metadata access (169.254.169.254)            │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘


Phase 4: RESPONSE & STORAGE
═══════════════════════════════════════════════════════════════════════
┌──────────────────────────────────────────────────────────────────┐
│ 10. Agent Completes Task                                         │
│     └─ Generates response/result                                 │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 11. Agent Writes to Shared Memory/Storage (if applicable)       │
│     ├─ Updates conversation memory                              │
│     ├─ Writes to shared database                                │
│     └─ Stores context for future tasks                          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #7: Memory Monitor (Future)               │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ⚠️  NOT CURRENTLY IMPLEMENTED                        │    │
│    │                                                       │    │
│    │ Would monitor:                                        │    │
│    │ - Shared memory writes                               │    │
│    │ - Context poisoning attempts                         │    │
│    │ - Unauthorized memory modifications                  │    │
│    │ - Persistent instruction injection                   │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 12. Response Returned to Orchestrator                           │
│     POST response back to orchestrator                           │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 13. Orchestrator Returns Result to User                         │
└──────────────────────────────────────────────────────────────────┘


Phase 5: OBSERVABILITY & LOGGING
═══════════════════════════════════════════════════════════════════════
┌──────────────────────────────────────────────────────────────────┐
│ 14. Telemetry & Logs Generated Throughout Lifecycle             │
│     ├─ Application logs                                          │
│     ├─ Network flow logs                                         │
│     ├─ Audit logs                                                │
│     └─ Performance metrics                                       │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 📍 SCANNER CHECKPOINT #8: SIEM Integration (Future)             │
│    ┌──────────────────────────────────────────────────────┐    │
│    │ ⚠️  NOT CURRENTLY IMPLEMENTED                        │    │
│    │                                                       │    │
│    │ Would:                                                │    │
│    │ - Aggregate scanner findings                         │    │
│    │ - Correlate with system logs                         │    │
│    │ - ML-based anomaly detection                         │    │
│    │ - Threat hunting queries                             │    │
│    │ - Alert on patterns                                  │    │
│    └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Deployment Patterns

### Pattern 1: CI/CD Pipeline Scanner (✅ Implemented)

```
Developer → Git Push → CI/CD Pipeline → Scanner → Build/Deploy
                            │
                            ├─ scan-directory agents/
                            ├─ scan-file agent-card.json
                            └─ BLOCK if HIGH severity
```

**Implementation:**
```yaml
# .github/workflows/scan.yml
- name: Scan Agent Code
  run: a2a-scanner scan-directory agents/ --pattern "*.py"
```

---

### Pattern 2: Registry Webhook Scanner (✅ Implemented)

```
Agent → Registry → Webhook → Scanner → Approve/Reject
                      │
                      └─> POST /scanner/webhook/scan-agent
```

**Implementation:**
```python
# See: examples/registry_webhook_integration.py
@app.route('/webhook/scan-agent', methods=['POST'])
def scan_agent_webhook():
    agent_card = request.json
    result = scanner.scan_agent_card(agent_card)
    
    if result.get_high_severity_findings():
        return {"approved": False}, 403
    return {"approved": True}, 200
```

---

### Pattern 3: Pre-Deployment Scanner (✅ Implemented)

```
Deploy Script → Scanner → Validate → Deploy
                  │
                  └─ Scan all configs before deploy
```

**Implementation:**
```bash
#!/bin/bash
# deploy.sh

# Scan before deploying
a2a-scanner scan-directory ./configs --pattern "*.json"
if [ $? -ne 0 ]; then
    echo "Security scan failed! Deployment blocked."
    exit 1
fi

# Deploy if scan passes
kubectl apply -f configs/
```

---

### Pattern 4: Periodic Re-Scan (✅ Can Implement)

```
Cron Job → Scanner → Re-scan Registry → Alert on New Threats
```

**Implementation:**
```python
# cron_scanner.py
import asyncio
from a2ascanner import Scanner
import requests

async def periodic_scan():
    scanner = Scanner()
    
    # Fetch all agents from registry
    agents = requests.get("https://registry.com/agents").json()
    
    for agent in agents:
        result = await scanner.scan_agent_card(agent)
        if result.get_high_severity_findings():
            alert_security_team(agent, result.findings)

# Run every 24 hours
asyncio.run(periodic_scan())
```

---

## Comparison: What Scanner Does vs What It Doesn't

| Feature | Current Scanner | Would Require |
|---------|----------------|---------------|
| **✅ Scan source code files** | YES - YARA/Pattern matching | N/A |
| **✅ Scan agent card JSON** | YES - JSON validation | N/A |
| **✅ Detect typosquatting** | YES - Character pattern matching | N/A |
| **✅ Find exfil endpoints** | YES - URL pattern detection | N/A |
| **✅ Detect SSRF patterns** | YES - Code pattern matching | N/A |
| **✅ CI/CD integration** | YES - CLI commands | N/A |
| **✅ Registry webhook** | YES - REST API | N/A |
| **❌ Monitor live A2A traffic** | NO | Network proxy (Envoy, Istio) |
| **❌ Detect AITM attacks** | NO | Traffic inspection |
| **❌ Monitor tool calls at runtime** | NO | Agent sidecar/instrumentation |
| **❌ Watch memory modifications** | NO | Memory/DB watchers |
| **❌ Track network egress** | NO | Network firewall/IDS |

---

## Recommended Deployment Strategy

### Minimal Security (Single Layer)

```
Layer 1: CI/CD Scanner
├─ Scan code before build
└─ Block on HIGH severity
```

### Basic Security (Two Layers)

```
Layer 1: CI/CD Scanner
└─ Scan code before build

Layer 2: Registry Webhook
└─ Scan agent cards on registration
```

### Production Security (Three Layers) - **RECOMMENDED**

```
Layer 1: CI/CD Scanner
└─ Scan code + configs before build

Layer 2: Registry Webhook
└─ Scan agent cards on registration

Layer 3: Periodic Re-Scan
└─ Re-scan all registered agents weekly
```

### Enterprise Security (Multi-Layer) - **FUTURE**

```
Layer 1: CI/CD Scanner (✅ Now)
Layer 2: Registry Webhook (✅ Now)
Layer 3: Orchestrator Guard (⚠️ Future)
Layer 4: Network Proxy (⚠️ Future)
Layer 5: Runtime Sidecar (⚠️ Future)
Layer 6: Network IDS (⚠️ Future)
Layer 7: SIEM Integration (⚠️ Future)
```

---

## Key Takeaways

### ✅ What You Can Do Today

1. **Integrate scanner into CI/CD pipeline** - Scan all agent code before deployment
2. **Add registry webhook** - Validate agent cards before registration  
3. **Run periodic scans** - Re-scan registered agents weekly
4. **Scan before deployment** - Final validation before production

### ⚠️ What Requires Future Development

1. **Runtime monitoring** - Monitor live agent communication
2. **Traffic inspection** - Detect AITM and network attacks
3. **Orchestrator hooks** - Monitor judge decisions
4. **Memory monitoring** - Detect context poisoning at runtime
5. **SIEM integration** - Aggregate and correlate findings

### 🎯 Bottom Line

**The current scanner is a STATIC ANALYZER designed for PRE-DEPLOYMENT security validation, not runtime monitoring. It fits best at:**
- ✅ **Stage 1: Discovery/Registry** (agent card validation)
- ✅ **Stage 0: CI/CD** (pre-deployment code scanning)

**For runtime monitoring, you would need additional components like network proxies, agent sidecars, and observability tools.**
