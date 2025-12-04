# A2A Scanner Architecture

## Overview

The A2A Scanner provides comprehensive security analysis for Agent-to-Agent protocol implementations through a modular, extensible architecture. Multiple analyzers work concurrently to detect threats across different layers of the A2A protocol stack.

## Core Components

### 1. Scanner (`core/scanner.py`)

The main orchestrator coordinating all analyzers and managing scan workflows.

**Key Responsibilities:**
- Initialize and manage analyzer instances
- Coordinate concurrent analysis using asyncio
- Aggregate findings from all analyzers
- Provide scan methods for different target types

**Methods:**
- `scan_agent_card(agent_card: Dict)` - Scan individual agent cards
- `scan_file(file_path: str)` - Scan files (Python, JSON, JS)
- `scan_endpoint(endpoint_url: str)` - Scan live agent endpoints
- `get_available_analyzers()` - List registered analyzers

### 2. Base Analyzer (`core/analyzers/base.py`)

Abstract base class defining the analyzer interface.

**Key Features:**
- Standardized `analyze()` method signature
- `SecurityFinding` creation helpers
- Severity normalization (HIGH, MEDIUM, LOW, SAFE, UNKNOWN)
- Error handling and logging
- Threat category mapping

**All analyzers must implement:**
```python
async def analyze(
    self, 
    content: str, 
    context: Optional[Dict[str, Any]] = None
) -> List[SecurityFinding]
```

### 3. Analyzer Implementations

#### YARA Analyzer (`core/analyzers/yara_analyzer.py`)

Pattern-based detection using compiled YARA rules.

**Features:**
- Loads rules from `data/yara_rules/` directory
- Compiles rules at initialization for performance
- Extracts metadata from matched rules
- Tuned patterns to reduce false positives

**Rule Categories:**
- `agent_card_spoofing.yara` - Impersonation, Typosquatting
- `message_injection.yara` - Directive Patterns, Hidden Instructions
- `tool_poisoning.yara` - Credential Harvesting, Malicious Skills
- `routing_manipulation.yara` - Fan-Out DoS, Routing Hijacking
- `capability_abuse.yar` - Privilege Escalation
- `data_leakage.yar` - Secrets in Transit
- `network_security.yara` - Insecure Communication

#### Heuristic Analyzer (`core/analyzers/heuristic_analyzer.py`)

Python-based heuristic detection using regex and logic rules.

**Features:**
- Compiled regex patterns for performance
- JSON structure analysis
- URL validation and security checks
- Context-aware detection
- Tuned to minimize false positives

**Detection Categories:**
- Superlative language patterns (e.g., "best", "always works")
- Suspicious URL patterns (non-HTTPS, localhost, internal IPs)
- Cloud metadata endpoints (AWS, Azure, GCP)
- Command injection patterns (eval, exec, shell=True)
- Credential harvesting attempts
- Unsafe logging practices

#### LLM Analyzer (`core/analyzers/llm_analyzer.py`)

AI-powered semantic threat detection using large language models.

**Features:**
- Multi-provider support via LiteLLM (Azure OpenAI, OpenAI, Anthropic, Ollama)
- Structured JSON output parsing
- Configurable via environment variables
- Semantic understanding of threats

**Configuration:**
```bash
A2A_SCANNER_LLM_PROVIDER=azure
A2A_SCANNER_LLM_API_KEY=<your-key>
A2A_SCANNER_LLM_MODEL=gpt-4.1
A2A_SCANNER_LLM_BASE_URL=https://your-endpoint.openai.azure.com
A2A_SCANNER_LLM_API_VERSION=2025-01-01-preview
```

**Security Measures:**
- Structured prompt design
- Output validation and parsing
- Low temperature for consistent results
- Falls back gracefully if unavailable

#### Spec Analyzer (`core/analyzers/spec_analyzer.py`)

Validates A2A protocol compliance by checking agent card structure and required fields.

**Features:**
- Required field validation
- Data type checking
- URL format validation
- Skill structure verification
- Capability validation

#### Endpoint Analyzer (`core/analyzers/endpoint_analyzer.py`)

Dynamic security testing of live A2A agent endpoints.

**Features:**
- HTTPS enforcement checks
- Security headers validation
- Agent card presence verification
- Health endpoint detection
- Response time monitoring

**Detection Focus:**
- Missing security headers
- Insecure HTTP connections
- Missing or malformed agent cards
- Configuration issues

## Data Flow

```
Input (Agent Card/File/Stream)
    ↓
Scanner.scan_*()
    ↓
Content Preparation & Context Building
    ↓
Parallel Analyzer Execution (asyncio.gather)
    ↓
┌─────────────┬──────────────┬─────────────┬──────────────┐
│ YARA        │ Heuristic    │ LLM         │ Endpoint     │
│ Analyzer    │ Analyzer     │ Analyzer    │ Analyzer     │
└─────────────┴──────────────┴─────────────┴──────────────┘
    ↓           ↓              ↓             ↓
SecurityFinding SecurityFinding SecurityFinding SecurityFinding
    ↓           ↓              ↓             ↓
    └───────────┴──────────────┴─────────────┘
                    ↓
            Findings Aggregation
                    ↓
              ScanResult
                    ↓
        Output (Console/JSON/API)
```

## Configuration System

### Config Class (`config/config.py`)

Centralized configuration management using environment variables.

**Configuration Sources:**
1. Environment variables (highest priority)
2. `.env` file
3. Default values (lowest priority)

**Key Settings:**
```python
# LLM Configuration
llm_provider: str = "azure"
llm_api_key: Optional[str] = None
llm_model: str = "gpt-4"
llm_base_url: Optional[str] = None
llm_api_version: str = "2025-01-01-preview"

# Scanner Configuration
scanner_timeout: int = 300
max_file_size: int = 10 * 1024 * 1024  # 10MB
```

## Models

### SecurityFinding (`core/analyzers/base.py`)

Represents a single security threat detection.

**Attributes:**
- `severity: str` - HIGH, MEDIUM, LOW, SAFE, UNKNOWN
- `threat_category: str` - AITech and AISubtech identifiers
- `threat_name: str` - Human-readable name
- `summary: str` - Brief description
- `analyzer: str` - Source analyzer name
- `details: Dict[str, Any]` - Additional context

**Methods:**
- `to_dict()` - Convert to dictionary for JSON serialization

### ScanResult (`core/results/results.py`)

Represents the complete result of a scan operation.

**Attributes:**
- `target_name: str` - Name of scanned target
- `target_type: str` - Type (agent_card, source_code, endpoint)
- `status: str` - completed, failed, partial
- `analyzers: List[str]` - List of analyzers used
- `findings: List[SecurityFinding]` - All detected threats
- `metadata: Dict[str, Any]` - Additional scan metadata

**Methods:**
- `to_dict()` - Convert to dictionary
- `findings_by_severity()` - Group findings by severity

### ThreatCategory (`core/threats/definitions.py`)

Threat taxonomy mapping using the AI Security Taxonomy framework.

**Categories Include:**
- - Agent Card Spoofing
- - Message Injection
- - Secrets in Transit
- - Insecure Communication
- - Routing Manipulation
- And 24 more categories...

## Extensibility

### Adding Custom Analyzers

1. **Inherit from BaseAnalyzer:**
```python
from a2ascanner.core.analyzers.base import BaseAnalyzer, SecurityFinding

class CustomAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("Custom")
```

2. **Implement analyze() method:**
```python
async def analyze(self, content: str, context: Optional[Dict] = None) -> List[SecurityFinding]:
    findings = []
    
    # Your detection logic here
    if "suspicious_pattern" in content:
        findings.append(
            self.create_security_finding(
                severity="HIGH",
                summary="Suspicious pattern detected",
                threat_name="Custom Threat",
                details={"pattern": "suspicious_pattern"}
            )
        )
    
    return findings
```

3. **Register with Scanner:**
```python
from a2ascanner.config.config import Config

config = Config()
scanner = Scanner(config)
# Custom analyzers can be added via config
```

### Adding YARA Rules

1. Create `.yara` file in `a2ascanner/data/yara_rules/`
2. Include required metadata:
```yara
rule MyCustomRule
{
    meta:
        description = "Detects custom threat pattern"
        threat_name = "Custom Threat Detection"
        severity = "HIGH"
        
    strings:
        $pattern = "malicious_pattern"
        
    condition:
        $pattern
}
```
3. Rules are automatically loaded at scanner initialization

## Performance Considerations

### Concurrent Analysis

All analyzers run concurrently using `asyncio.gather()`:
- Maximizes throughput
- Reduces total scan time (typically 2-5 seconds per scan)
- Handles analyzer failures gracefully

### YARA Rule Compilation

Rules are compiled once at initialization:
- Faster matching during scans
- Lower memory overhead
- Efficient pattern matching engine

### Pattern Caching

Regex patterns are compiled at analyzer initialization:
- Avoids recompilation overhead
- Consistent performance across scans
- Memory-efficient reuse

### LLM Rate Limiting

LLM analyzer includes built-in handling:
- Graceful fallback if rate limited
- Error logging without crashing scanner
- Optional for non-critical workflows

## Error Handling

### Analyzer-Level

- Each analyzer handles its own exceptions
- Failures don't affect other analyzers
- Errors logged with context
- Returns empty findings list on error

### Scanner-Level

- Graceful degradation if analyzers fail
- Partial results returned when possible
- Clear error reporting in scan results
- Status tracking (completed, partial, failed)

## Logging

Structured logging throughout:
```python
import logging

logger = logging.getLogger(__name__)

# Module-level loggers
logger.info("Scanner initialized")
logger.warning("LLM analyzer not available")
logger.error("Failed to load YARA rules")
```

- Configurable log levels
- Context-rich log messages
- Performance metrics

## Security Considerations

### Input Validation

All analyzers validate input:
- Content size limits (10MB default)
- Format validation
- Type checking
- Sanitization where needed

### Safe Execution

- No arbitrary code execution
- Read-only operations
- Timeout protection
- Sandboxed analysis

### Dependency Security

- Pinned dependencies in `pyproject.toml`
- Regular security updates
- Minimal dependency surface
- Well-maintained packages only
