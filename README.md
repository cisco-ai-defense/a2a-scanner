# A2A Security Scanner

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/cisco-ai-a2a-scanner)](https://pypi.org/project/cisco-ai-a2a-scanner/)
[![UV](https://img.shields.io/badge/uv-compatible-green)](https://github.com/astral-sh/uv)

**Scan Agent-to-Agent (A2A) protocol implementations for security threats and vulnerabilities.**

---

## Overview

The A2A Security Scanner provides comprehensive security analysis for Agent-to-Agent protocol implementations. It combines static analysis, runtime monitoring, and AI-powered semantic detection to identify security threats across the A2A protocol stack.

### Key Features

- **Multiple Specialized Analyzers**: YARA rules, spec validation, heuristics, LLM-powered detection, and endpoint testing
- **Multiple Threat Categories**: Complete coverage of A2A threat taxonomy
- **REST API**: Easy integration into CI/CD pipelines and applications
- **CLI Tools**: Command-line interface for manual security audits
- **Agent Card Validation**: A2A protocol compliance checking

---

## Installation

### Prerequisites

- Python 3.11+
- uv (Python package manager) - recommended
- LLM Provider API Key (optional, for LLM analyzer)

### Installing as a CLI Tool

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: brew install uv

uv tool install --python 3.13 cisco-ai-a2a-scanner

# Verify installation
a2a-scanner list-analyzers
```

Alternatively, you can install from source:

```bash
uv tool install --python 3.13 --from git+https://github.com/cisco-ai-defense/a2a-scanner cisco-ai-a2a-scanner

# Verify installation
a2a-scanner list-analyzers
```

### Installing for Local Development

```bash
git clone https://github.com/cisco-ai-defense/a2a-scanner.git
cd a2a-scanner

# Install UV (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: brew install uv

uv sync

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Verify installation
a2a-scanner list-analyzers
```

### Install as a Dependency in Other Projects

Add A2A Scanner as a dependency using uv. From your project root (initialize with uv if needed):

```bash
uv init  # if not already done
uv add cisco-ai-a2a-scanner
# then activate the virtual environment:
# macOS and Linux: source .venv/bin/activate
# Windows CMD: .venv\Scripts\activate
# Windows PWSH: .venv\Scripts\Activate.ps1
uv sync
```

The module name is `a2ascanner`. Import this module with:

```python
# import everything (not recommended)
import a2ascanner

# selective imports (recommended). For example:
from a2ascanner import Scanner, Config
from a2ascanner.core.models import ThreatSeverity
```

---

## Quick Start

### Scan an Agent Card

```bash
# Scan a JSON agent card file
a2a-scanner scan-card examples/sample_agent_cards/unsafe_agent.json

# Scan with specific analyzers
a2a-scanner scan-card agent.json --analyzers yara,spec

# JSON output
a2a-scanner scan-card agent.json --output results.json
```

### Scan Source Code

```bash
# Scan a directory
a2a-scanner scan-directory /path/to/agent/code

# Scan a single file
a2a-scanner scan-file agent.py

# Scan with pattern
a2a-scanner scan-directory ./agents --pattern "**/*.py"
```

### Scan Live Agent Endpoint

```bash
# Scan a running agent
a2a-scanner scan-endpoint https://agent.example.com/api

# With authentication
a2a-scanner scan-endpoint https://agent.example.com/api --bearer-token "$TOKEN"
```

### 🎮 Try Interactive Demo

Want to see the analyzers in action? Run the interactive demo:

```bash
# Interactive demo with sample data
uv run python examples/interactive_demo.py --dev

# Or use the comprehensive automated demo
uv run python examples/comprehensive_demo.py
```

The interactive demo lets you test all analyzers (YARA, Spec, Heuristic, LLM, Endpoint) with:
- Built-in sample malicious agent cards
- Live endpoint testing (try `http://localhost:9998`)
- Color-coded threat severity display
- Session summary with aggregate statistics

See [Demonstrations](#demonstrations) section for full details.

---

## Development Mode

For local development and testing, use the `--dev` flag to relax security checks:

### What Dev Mode Does

When `--dev` is enabled, the scanner allows:
- **Localhost URLs** (`http://localhost:8000`)
- **Private IP addresses** (`http://192.168.1.1`, `http://10.0.0.x`)
- **Self-signed SSL certificates** (skips verification)
- **HTTP connections** (without flagging as insecure)

### CLI Usage

```bash
# Scan local agent endpoint
a2a-scanner --dev scan-endpoint http://localhost:8000

# Scan with debug logging
a2a-scanner --dev --debug scan-endpoint http://localhost:9999

# Scan agent card from local URL
a2a-scanner --dev scan-card agent.json
```

### API Server with Dev Mode

```bash
# Enable dev mode via environment variable
export A2A_SCANNER_DEV_MODE=true

# Start API server
a2a-scanner-api --reload

# Now all API requests allow localhost and skip SSL verification
curl -X POST http://localhost:8000/scan/endpoint \
  -H "Content-Type: application/json" \
  -d '{"endpoint_url": "http://localhost:8000"}'
```

### Programmatic Usage

```python
from a2ascanner.config.config import Config
from a2ascanner.core.scanner import Scanner

# Enable dev mode
config = Config(dev_mode=True)
scanner = Scanner(config)

# Scan localhost endpoint
result = await scanner.scan_endpoint("http://localhost:8000")
```

### ⚠️ Security Warning

**DO NOT USE `--dev` IN PRODUCTION!**

Dev mode disables critical security features:
- SSRF protection for localhost and private IPs
- SSL certificate verification
- Secure protocol enforcement

Use dev mode only in:
- Local development environments
- Internal testing networks
- CI/CD pipelines (isolated)

See [`DEV_MODE_GUIDE.md`](DEV_MODE_GUIDE.md) for complete documentation.

---

## CLI Usage

The scanner provides several commands for different scanning scenarios:

### Commands

- **`scan-card`**: Scan an agent card JSON file
- **`scan-file`**: Scan a single source code file
- **`scan-directory`**: Scan a directory of files
- **`scan-endpoint`**: Scan a live agent endpoint
- **`scan-registry`**: Scan agents from a registry
- **`list-analyzers`**: List available analyzers

### Common Options

```bash
# Development mode (allows localhost, skips SSL verification)
--dev                       # Enable for local testing

# Debug and logging
--debug                     # Enable debug logging

# Select specific analyzers
--analyzers yara,spec,heuristic,llm,endpoint

# Output formats
--output results.json       # JSON output
--verbose                   # Detailed output

# Pattern matching
--pattern "*.py"           # File pattern matching

# Authentication
--bearer-token TOKEN       # Bearer token for endpoints
--no-verify-ssl            # Skip SSL verification (or use --dev)
```

### Examples

#### Scan with YARA Rules Only

```bash
a2a-scanner scan-card agent.json --analyzers yara
```

#### Scan with LLM Analyzer

```bash
# Configure LLM (Azure OpenAI)
export A2A_SCANNER_LLM_PROVIDER=azure
export A2A_SCANNER_LLM_API_KEY=your-key
export A2A_SCANNER_LLM_MODEL=gpt-4
export A2A_SCANNER_LLM_BASE_URL=https://your-instance.openai.azure.com

# Scan with LLM
a2a-scanner scan-card agent.json --analyzers llm
```

#### Scan Multiple Files

```bash
# Scan all Python files in agents directory
a2a-scanner scan-directory ./agents --pattern "**/*.py"
```

---

## API Server Usage

The API server provides a REST interface for integrating security scanning into applications and pipelines.

### Start the Server

```bash
# Start on default port (8000)
a2a-scanner-api

# Custom host and port
a2a-scanner-api --host 0.0.0.0 --port 8080

# Development mode with auto-reload
a2a-scanner-api --reload

# Enable dev mode for local testing (allows localhost, skips SSL)
export A2A_SCANNER_DEV_MODE=true
a2a-scanner-api --reload
```

### API Endpoints

Once running, the API provides:

- **`POST /scan/agent-card`** - Scan an agent card JSON
- **`POST /scan/source-code`** - Scan source code
- **`POST /scan/endpoint`** - Scan a live agent endpoint
- **`POST /scan/full`** - Full scan (all methods)
- **`GET /health`** - Health check endpoint
- **`GET /`** - API documentation

### Example API Request

```bash
# Scan an agent card
curl -X POST http://localhost:8000/scan/agent-card \
  -H "Content-Type: application/json" \
  -d @agent_card.json

# Scan source code
curl -X POST http://localhost:8000/scan/source-code \
  -H "Content-Type: application/json" \
  -d '{"source_path": "/path/to/code"}'
```

Interactive API documentation is available at `http://localhost:8000/docs` when the server is running.

---

## Threat Detection

The scanner detects threats across the entire A2A protocol stack:

### Detection Methods

#### 1. YARA Rules

Static pattern matching for detecting malicious patterns in agent cards, including agent impersonation, prompt injection, capability abuse, data exfiltration, routing manipulation, and tool poisoning attacks.

**Location**: `a2ascanner/data/yara_rules/`

#### 2. Spec Analyzer

Validates A2A protocol compliance:

- Required field validation
- Data type checking
- URL format validation
- Skill structure verification
- Capability validation

#### 3. Heuristic Analyzer

Logic-based detection:

- Suspicious URL patterns
- Cloud metadata access
- Command execution patterns
- Credential harvesting indicators

#### 4. LLM Analyzer

AI-powered semantic analysis:

- Intent classification
- Context grounding
- Subtle manipulation detection
- Anomaly detection

#### 5. Endpoint Analyzer

Dynamic security testing of running A2A agent endpoints to verify security posture and protocol compliance.

**Security Checks:**
- **HTTPS enforcement** - Verifies secure protocol usage (flags HTTP endpoints)
- **Security headers validation** - Checks for X-Content-Type-Options, X-Frame-Options, HSTS
- **Agent card presence** - Validates card exists at standard locations (/.well-known/agent-card.json)
- **URL mismatch detection** - Ensures agent card URL matches endpoint URL
- **Health endpoint checks** - Verifies /health or /healthz endpoints exist
- **Network reachability** - Tests endpoint accessibility and response time
- **Protocol compliance** - Validates A2A protocol adherence

**Usage - CLI:**

```bash
# Basic endpoint scan
a2a-scanner scan-endpoint https://agent.example.com/api

# With authentication
a2a-scanner scan-endpoint https://agent.example.com/api \
  --bearer-token "your-token-here"

# Scan with custom timeout
a2a-scanner scan-endpoint https://agent.example.com/api \
  --timeout 60

# Local development endpoint (requires --dev flag)
a2a-scanner --dev scan-endpoint http://localhost:8080

# Skip SSL verification (not recommended for production)
a2a-scanner scan-endpoint https://agent.example.com/ \
  --no-verify-ssl

# Save results to JSON
a2a-scanner scan-endpoint https://agent.example.com/api \
  --output results.json
```

**Usage - Programmatic:**

```python
from a2ascanner.core.scanner import Scanner
from a2ascanner.config.config import Config
import asyncio

async def scan_agent_endpoint():
    # Create scanner instance
    config = Config(dev_mode=False)  # Set to True for localhost
    scanner = Scanner(config)
    
    # Scan endpoint
    result = await scanner.scan_endpoint(
        endpoint_url="https://agent.example.com/api",
        bearer_token="your-token",  # Optional
        timeout=30.0,               # Optional
        verify_ssl=True             # Optional
    )
    
    # Check results
    if result.threats:
        print(f"Found {len(result.threats)} security issues:")
        for threat in result.threats:
            print(f"  [{threat.severity}] {threat.summary}")
    else:
        print("Endpoint passed all security checks!")
    
    return result

# Run the scan
asyncio.run(scan_agent_endpoint())
```

**Usage - API Server:**

```bash
# Scan endpoint via REST API
curl -X POST http://localhost:8000/scan/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint_url": "https://agent.example.com/api",
    "bearer_token": "your-token",
    "timeout": 30,
    "verify_ssl": true
  }'
```

**Use Cases:**
- **Production audits** - Regular security assessments of live agent endpoints
- **CI/CD integration** - Automated security checks before deployment
- **Continuous monitoring** - Periodic health and security validation
- **Pre-deployment validation** - Security verification before going live
- **Compliance checking** - Ensure endpoints meet security standards
- **Registry validation** - Verify agents in registry are properly configured

**Common Issues Detected:**

| Issue | Severity | Description |
|-------|----------|-------------|
| Endpoint unreachable | HIGH | Agent endpoint is not responding or network error |
| Insecure HTTP | HIGH | Endpoint uses HTTP instead of HTTPS |
| Missing agent card | MEDIUM | No agent card found at standard locations |
| URL mismatch | MEDIUM | Agent card URL doesn't match endpoint URL |
| Missing security headers | MEDIUM | Missing X-Content-Type-Options, X-Frame-Options, or HSTS |
| No health endpoint | LOW | Missing /health or /healthz monitoring endpoint |

**Dev Mode for Local Testing:**

When testing local development endpoints, use `--dev` flag:

```yaml
# .github/workflows/security-scan.yml
name: A2A Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  endpoint-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh
      
      - name: Install A2A Scanner
        run: uv tool install --python 3.13 cisco-ai-a2a-scanner
      
      - name: Scan endpoint
        run: |
          a2a-scanner scan-endpoint \
            ${{ secrets.AGENT_ENDPOINT_URL }} \
            --bearer-token ${{ secrets.AGENT_TOKEN }} \
            --output scan-results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan-results.json
```

---

## Configuration

### Environment Variables

Configure the scanner using environment variables:

```bash
# LLM Analyzer Configuration
export A2A_SCANNER_LLM_PROVIDER=azure      # azure or openai
export A2A_SCANNER_LLM_API_KEY=your-key
export A2A_SCANNER_LLM_MODEL=gpt-4
export A2A_SCANNER_LLM_BASE_URL=https://your-instance.openai.azure.com
export A2A_SCANNER_LLM_API_VERSION=2025-01-01-preview

# API Server Configuration
export A2A_SCANNER_API_HOST=0.0.0.0
export A2A_SCANNER_API_PORT=8000

# Proxy Configuration
export A2A_SCANNER_PROXY_PORT=8080
```

### Configuration File

Alternatively, use a `.env` file in the project root:

```bash
cp .env.example .env
# Edit .env with your configuration
```

---

## Testing

### Validate Installation

```bash
# List available analyzers
a2a-scanner list-analyzers

# Run health check
curl http://localhost:8000/health
```

### Test on Sample Agents

```bash
# Scan safe agent card
a2a-scanner scan-card examples/sample_agent_cards/safe_agent.json

# Scan unsafe agent card
a2a-scanner scan-card examples/sample_agent_cards/unsafe_agent.json
```

### Run Test Suite

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=a2ascanner --cov-report=term

# Run specific test file
pytest tests/test_api.py -v
```

---

## For Developers

### Demonstrations

#### Comprehensive Analyzer Demo 

Location: `examples/comprehensive_demo.py`

**All-in-one demonstration showcasing all analyzers with professional terminal output.**

```bash
# Full interactive demo
uv run python examples/comprehensive_demo.py

# Quick mode (no pauses)
uv run python examples/comprehensive_demo.py --quick

# Test specific analyzer
uv run python examples/comprehensive_demo.py --analyzer yara
```


#### Interactive Analyzer Demo 

Location: `examples/interactive_demo.py`

**Hands-on interactive demo where you provide the data to scan.**

```bash
# Run interactive demo with dev mode (for localhost testing)
uv run python examples/interactive_demo.py --dev

# Run without dev mode (production testing)
uv run python examples/interactive_demo.py
```

**Available Analyzers:**
1. **YARA** - Pattern-based threat detection using compiled YARA rules
2. **Spec** - A2A protocol compliance validation (required fields, formats, structures)
3. **Heuristic** - Logic-based security checks (URL patterns, superlative language)
4. **Endpoint** - Live endpoint security audit (HTTPS, headers, health checks)
5. **LLM** - AI-powered semantic analysis (requires API key configuration)

**Input Options:**
- **Agent Cards**: File path, direct JSON input, URL fetch, or sample malicious card
- **Endpoints**: Custom URL with dev mode option for localhost testing




**Example Session:**
```bash
$ uv run python examples/interactive_demo.py --dev

Select analyzer to test:
  1. YARA      - Pattern-based threat detection
  2. Spec      - A2A protocol compliance
  3. Heuristic - Logic-based security checks
  4. Endpoint  - Live endpoint security audit

Your choice [1-4]: 2

How would you like to provide the agent card?
  1. Path to JSON file
  2. Direct JSON input
  3. URL to fetch agent card
  4. Use sample malicious agent card

Your choice [1-4]: 4

Results from SPEC Analyzer:
⚠️  Found 3 potential threat(s):
  • HIGH: Missing required field 'skills'
  • MEDIUM: Invalid capabilities type
  • LOW: Missing 'id' field
```

### Static Analysis Examples
See the `examples/` directory for static file analysis:
- **Malicious agent card examples** - Various spoofing techniques
- **Tool poisoning demonstrations** - Malicious tool definitions
- **Registry poisoning examples** - Mass registration attacks

Example threat files include:
- `tool_poison.py` - Tool poisoning with exfiltration
- `context_poison_writer.py` - Context contamination
- `judge_persuade.py` - Routing manipulation

---

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/cisco-ai-defense/a2a-scanner.git
cd a2a-scanner

# Install UV (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: brew install uv

# Sync dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Verify installation
a2a-scanner list-analyzers
```

### Running Tests

After activating the virtual environment (`source .venv/bin/activate`):

```bash
# Run all tests
pytest tests/ -q

# Verbose output
pytest tests/ -v

# With coverage report
pytest tests/ --cov=a2ascanner --cov-report=term-missing

# Run specific test categories
pytest tests/test_api.py          # API tests
pytest tests/test_analyzers.py    # Analyzer tests
pytest tests/test_yara.py         # YARA rule tests
pytest tests/test_heuristic.py    # Heuristic tests
```

> **Note**: You can also use `uv run pytest tests/` without activating the virtual environment.

### Managing Dependencies

```bash
# Add a runtime dependency
uv add <package-name>

# Add a development dependency
uv add --dev <package-name>

# Update all dependencies
uv sync --upgrade

# Remove a dependency
uv remove <package-name>
```

### About UV

UV is a fast Python package manager and environment manager written in Rust:

- Fast dependency resolution (10-100x faster than pip)
- Reproducible builds with lock files
- Smart caching system
- Automatic environment management
- Built-in Python version management

### Common Commands

```bash
# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Then use commands directly
a2a-scanner scan-card test.json
pytest tests/
python script.py
```

---

## Documentation

For detailed documentation, see the `docs/` directory:

- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Contribution guidelines
- **[DEV_MODE_GUIDE.md](./DEV_MODE_GUIDE.md)** - Development mode documentation
- **[docs/architecture.md](./docs/architecture.md)** - System architecture
- **[docs/analyzer_guide.md](./docs/analyzer_guide.md)** - Analyzer implementation guide
- **[docs/usage_guide.md](./docs/usage_guide.md)** - Comprehensive usage guide
- **[docs/testing_guide.md](./docs/testing_guide.md)** - Testing documentation
- **[docs/a2a-threats-taxonomy.md](./docs/a2a-threats-taxonomy.md)** - A2A threat taxonomy reference
- **[docs/scanner_placement_guide.md](./docs/scanner_placement_guide.md)** - Scanner placement strategies

---


## Contact Cisco for AI Defense

For enterprise-grade A2A security solutions and support:

**Cisco AI Defense**: https://www.cisco.com/site/us/en/products/security/ai-defense/index.html

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](./LICENSE) for more information.

Copyright 2025 Cisco Systems, Inc. and its affiliates

---

## Related Projects

- **[A2A Protocol](https://github.com/a2aproject/A2A)** - Official A2A specification
- **[A2A Samples](https://github.com/a2aproject/a2a-samples)** - Example agent implementations
- **[Cisco AI Defense A2A Scanner](https://github.com/cisco-ai-defense/a2a-scanner)** - Agent-to-Agent (A2A) Protocol Scanner

---

## About

**A2A Security Scanner** provides comprehensive security analysis for Agent-to-Agent protocol implementations, combining static analysis, runtime monitoring, and AI-powered detection to identify vulnerabilities across the A2A protocol stack.

### Topics

`security` `ai` `a2a` `agents` `yara` `llm` `threat-detection`

---

*Project Link: https://github.com/cisco-ai-defense/a2a-scanner*
