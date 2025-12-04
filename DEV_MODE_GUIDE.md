<!--
Copyright 2025 Cisco Systems, Inc. and its affiliates

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Development Mode (`--dev`) Usage Guide

## Overview

The A2A Scanner includes a **Development Mode** (`--dev`) that relaxes security checks for easier local testing. This mode is designed for development and testing environments only.

## ⚠️ Security Warning

**DO NOT USE DEVELOPMENT MODE IN PRODUCTION!**

Dev mode disables critical security features and should only be used in controlled development environments.

---

## What Dev Mode Does

When development mode is enabled, the scanner relaxes the following security checks:

### 1. **Allows Localhost URLs**
- Production: `http://localhost:8000` → ❌ Blocked (SSRF protection)
- Dev Mode: `http://localhost:8000` → ✅ Allowed

### 2. **Allows Private IP Addresses**
- Production: `http://192.168.1.1` → ❌ Blocked (SSRF protection)
- Dev Mode: `http://192.168.1.1` → ✅ Allowed

### 3. **Skips SSL Certificate Verification**
- Production: Self-signed certs → ❌ Rejected
- Dev Mode: Self-signed certs → ✅ Accepted

### 4. **Allows HTTP (Insecure) Connections**
- Production: HTTP flagged as HIGH severity
- Dev Mode: HTTP allowed without warnings (for local testing)

---

## Usage

### CLI Usage

Add the `--dev` flag to any scanner command:

```bash
# Scan a local agent endpoint
a2a-scanner --dev scan-endpoint http://localhost:8000

# Scan an agent card from local URL
a2a-scanner --dev scan-card agent.json

# Fetch agent card from local server
# (POST with agent_card_url to API)

# Combine with debug for more visibility
a2a-scanner --dev --debug scan-endpoint http://localhost:9999
```

### API Usage

Set the environment variable before starting the API server:

```bash
# Enable dev mode via environment variable
export A2A_SCANNER_DEV_MODE=true

# Start API server
uvicorn a2ascanner.api.server:app --reload

# Now all API requests will use dev mode
curl -X POST http://localhost:8000/scan/endpoint \
  -H "Content-Type: application/json" \
  -d '{"endpoint_url": "http://localhost:8000"}'
```

### Programmatic Usage

Enable dev mode when creating the Config object:

```python
from a2ascanner.config.config import Config
from a2ascanner.core.scanner import Scanner

# Enable dev mode
config = Config(dev_mode=True)
scanner = Scanner(config)

# Now scanner allows localhost and skips SSL verification
result = await scanner.scan_endpoint("http://localhost:8000")
```

---

## Configuration Options

### Environment Variable

```bash
# Enable dev mode
export A2A_SCANNER_DEV_MODE=true

# Disable dev mode (default)
export A2A_SCANNER_DEV_MODE=false
# or unset
unset A2A_SCANNER_DEV_MODE
```

### Config Object

```python
# Enable dev mode
config = Config(dev_mode=True)

# Disable dev mode (default)
config = Config(dev_mode=False)
# or simply
config = Config()
```

### CLI Flag

```bash
# Enable dev mode
a2a-scanner --dev scan-endpoint http://localhost:8000

# Disable dev mode (default)
a2a-scanner scan-endpoint https://agent.example.com
```

---

## Common Use Cases

### 1. Testing Local Agent Development

```bash
# Start your agent locally
python my_agent.py

# Scan it with dev mode
a2a-scanner --dev scan-endpoint http://localhost:8000
```

### 2. Testing with Self-Signed Certificates

```bash
# Scan agent with self-signed cert
a2a-scanner --dev scan-endpoint https://localhost:8443
```

### 3. Testing on Internal Network

```bash
# Scan agent on private network
a2a-scanner --dev scan-endpoint http://192.168.1.100:8000
```

### 4. CI/CD Testing

```yaml
# .github/workflows/test.yml
- name: Test A2A Scanner
  env:
    A2A_SCANNER_DEV_MODE: true
  run: |
    python -m pytest tests/
```

---

## Dev Mode Indicators

When dev mode is enabled via CLI, you'll see a warning:

```
⚠️  Development mode enabled:
   - Localhost URLs allowed
   - Private IP addresses allowed
   - SSL certificate verification disabled
   - HTTP connections allowed
   DO NOT use in production!
```

---

## What Stays Enabled in Dev Mode

Dev mode only relaxes network-related security checks. The following still work normally:

✅ **YARA Rules** - All pattern detection rules
✅ **Heuristic Analysis** - Suspicious code patterns
✅ **LLM Analysis** - AI-powered threat detection
✅ **Agent Card Validation** - Schema validation
✅ **Threat Detection** - All threat categories
✅ **Finding Reports** - Full scan results

---

## Best Practices

### ✅ DO Use Dev Mode For:
- Local agent development and testing
- Internal network testing
- CI/CD pipelines in isolated environments
- Development workstations
- Integration tests with mock agents

### ❌ DON'T Use Dev Mode For:
- Production deployments
- Public-facing agents
- Security assessments of real agents
- Compliance scanning
- Any internet-facing services

---

## Troubleshooting

### "SSRF protection blocked URL" Error

**Problem**: Getting SSRF errors when testing locally

**Solution**: Enable dev mode
```bash
a2a-scanner --dev scan-endpoint http://localhost:8000
```

### "SSL certificate verification failed" Error

**Problem**: Self-signed certificate rejected

**Solution**: Enable dev mode to skip SSL verification
```bash
a2a-scanner --dev scan-endpoint https://localhost:8443
```

### "Private IP addresses not allowed" Error

**Problem**: Cannot scan agents on private network

**Solution**: Enable dev mode
```bash
a2a-scanner --dev scan-endpoint http://192.168.1.100
```

---

## Implementation Details

### Files Modified

1. **`a2ascanner/config/config.py`**
   - Added `dev_mode` parameter
   - Added `A2A_SCANNER_DEV_MODE` environment variable

2. **`a2ascanner/utils/http_client.py`**
   - Added `allow_private_ips` parameter to `fetch_agent_card()`

3. **`a2ascanner/api/routes.py`**
   - Uses `config.dev_mode` for URL fetching and endpoint scanning

4. **`a2ascanner/cli.py`**
   - Added `--dev` flag to CLI
   - Shows warning when dev mode enabled

5. **`a2ascanner/core/scanner.py`**
   - Passes dev mode settings to analyzers

---

## Security Notes

### Why These Restrictions Exist

1. **SSRF Protection**: Prevents scanning of internal services that might expose sensitive data
2. **SSL Verification**: Ensures you're connecting to the intended server
3. **Private IP Blocking**: Prevents access to internal network resources
4. **HTTP Restrictions**: Encourages secure communication

### When to Keep Restrictions

Always keep security restrictions enabled when:
- Scanning production agents
- Scanning third-party agents
- Running in cloud environments
- Performing security audits
- Operating in shared environments

---

## Examples

### Example 1: Full Local Development Workflow

```bash
# Terminal 1: Start local agent
cd my-agent
python agent.py
# Listening on http://localhost:8000

# Terminal 2: Scan with dev mode
cd a2a-scanner
a2a-scanner --dev scan-endpoint http://localhost:8000

# Output shows findings without SSRF errors
```

### Example 2: Testing Agent Card Fetching

```bash
# Agent card hosted locally
a2a-scanner --dev scan-card --url http://localhost:8000/agent-card.json
```

### Example 3: API Testing with Dev Mode

```python
import requests

# Enable dev mode in API server first:
# export A2A_SCANNER_DEV_MODE=true

# Scan local endpoint via API
response = requests.post(
    "http://localhost:8000/scan/endpoint",
    json={"endpoint_url": "http://localhost:9999"}
)

print(response.json())
```

---

## Summary

**Dev mode (`--dev`)** is a powerful feature for local development that:
- ✅ Makes testing easier by allowing localhost and private IPs
- ✅ Skips SSL verification for self-signed certificates
- ✅ Maintains all security analysis capabilities
- ⚠️ Should NEVER be used in production environments

**Usage**: `a2a-scanner --dev <command>` or `export A2A_SCANNER_DEV_MODE=true`

