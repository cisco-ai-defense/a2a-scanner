# A2A Scanner - Usage Guide

## Installation

### Prerequisites

- Python 3.11 or higher
- pip or uv package manager

### Install from PyPI

```bash
pip install a2a-scanner
```

### Install from source

```bash
git clone https://github.com/your-org/a2a-scanner.git
cd a2a-scanner
pip install -e .
```

### Install with development dependencies

```bash
pip install -e ".[dev]"
```

## Configuration

### Environment Variables

Create a `.env` file in your project root:

```bash
# Copy example configuration
cp .env.example .env

# Edit with your settings
nano .env
```

### LLM Configuration (Optional)

The LLM analyzer is optional but provides advanced threat detection.

#### OpenAI

```bash
A2A_SCANNER_LLM_PROVIDER=openai
A2A_SCANNER_LLM_API_KEY=sk-...
A2A_SCANNER_LLM_MODEL=gpt-4o
```

#### Anthropic Claude

```bash
A2A_SCANNER_LLM_PROVIDER=anthropic
A2A_SCANNER_LLM_API_KEY=sk-ant-...
A2A_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022
```

#### Azure OpenAI

```bash
A2A_SCANNER_LLM_PROVIDER=azure
A2A_SCANNER_LLM_API_KEY=your_azure_key
A2A_SCANNER_LLM_BASE_URL=https://your-resource.openai.azure.com
A2A_SCANNER_LLM_API_VERSION=2024-02-15-preview
A2A_SCANNER_LLM_MODEL=gpt-4
```

#### Ollama (Local)

```bash
A2A_SCANNER_LLM_PROVIDER=ollama
A2A_SCANNER_LLM_BASE_URL=http://localhost:11434
A2A_SCANNER_LLM_MODEL=llama3
```

## CLI Usage

### Basic Commands

#### Scan a File

```bash
# Scan a single file
a2a-scanner scan-file examples/agent_card.json

# With specific analyzers
a2a-scanner scan-file agent.json --analyzers yara --analyzers pattern

# Save results to JSON
a2a-scanner scan-file agent.json --output results.json

# Enable debug logging
a2a-scanner --debug scan-file agent.json
```

#### Scan Agent Card

```bash
# Scan an agent card JSON file
a2a-scanner scan-card examples/malicious_agent.json

# Save results
a2a-scanner scan-card agent.json -o results.json
```

#### Scan Registry

```bash
# Scan an agent registry endpoint
a2a-scanner scan-registry https://example.com/.well-known/agents

# With output
a2a-scanner scan-registry https://example.com/.well-known/agents -o registry_results.json
```

#### Scan Directory

```bash
# Scan all JSON files in directory
a2a-scanner scan-directory examples/

# Custom pattern
a2a-scanner scan-directory examples/ --pattern "*.js"

# Save results to directory
a2a-scanner scan-directory examples/ --output results/
```

#### List Analyzers

```bash
# Show available analyzers
a2a-scanner list-analyzers
```

### Advanced Usage

#### Selective Analyzer Usage

```bash
# Use only YARA analyzer (fast, no API key needed)
a2a-scanner scan-file agent.json -a yara

# Use YARA and Heuristic analyzers
a2a-scanner scan-file agent.json -a yara -a heuristic

# Use all analyzers including LLM
a2a-scanner scan-file agent.json -a yara -a heuristic -a llm -a sse
```

#### Batch Scanning

```bash
# Scan multiple files
for file in examples/*.json; do
    a2a-scanner scan-file "$file" -o "results/$(basename $file .json)_results.json"
done

# Or use scan-directory
a2a-scanner scan-directory examples/ -o results/
```

## Python API Usage

### Basic Scanning

```python
import asyncio
from a2ascanner import Scanner, Config

async def main():
    # Initialize scanner with default config
    scanner = Scanner()
    
    # Scan an agent card
    agent_card = {
        "id": "agent-123",
        "name": "MyAgent",
        "url": "https://example.com/agent",
        "description": "A helpful agent"
    }
    
    result = await scanner.scan_agent_card(agent_card)
    
    # Check results
    print(f"Found {len(result.findings)} threats")
    for finding in result.findings:
        print(f"  {finding.severity}: {finding.threat_name}")

asyncio.run(main())
```

### Custom Configuration

```python
from a2ascanner import Scanner, Config

# Create custom config
config = Config(
    llm_provider="openai",
    llm_api_key="sk-...",
    llm_model="gpt-4o",
    log_level="DEBUG",
    timeout=60
)

scanner = Scanner(config=config)
```

### Scanning Different Targets

```python
async def scan_examples():
    scanner = Scanner()
    
    # Scan agent card
    card_result = await scanner.scan_agent_card({
        "id": "agent-1",
        "name": "Agent",
        "url": "http://localhost:9001"
    })
    
    # Scan registry
    registry_result = await scanner.scan_registry(
        "https://example.com/.well-known/agents"
    )
    
    # Scan file
    file_result = await scanner.scan_file("examples/agent.json")
    
    return [card_result, registry_result, file_result]
```

### Using Specific Analyzers

```python
async def selective_scanning():
    scanner = Scanner()
    
    # Use only YARA and Heuristic analyzers
    result = await scanner.scan_agent_card(
        card=my_card,
        analyzers=["yara", "heuristic"]
    )
    
    # Check which analyzers were used
    print(f"Analyzers used: {result.analyzers}")
```

### Processing Results

```python
async def process_results():
    scanner = Scanner()
    result = await scanner.scan_file("agent.json")
    
    # Check if any findings
    if result.has_findings():
        print(f"⚠️  Found {len(result.findings)} threats")
        
        # Get high severity findings
        high_severity = result.get_high_severity_findings()
        if high_severity:
            print(f"🚨 {len(high_severity)} HIGH severity threats!")
            for finding in high_severity:
                print(f"  - {finding.threat_name}")
                print(f"    {finding.summary}")
    else:
        print("✓ No threats detected")
    
    # Export to JSON
    import json
    with open("results.json", "w") as f:
        json.dump(result.to_dict(), f, indent=2)
```

### Custom Analyzers

```python
from a2ascanner.core.analyzers.base import BaseAnalyzer, SecurityFinding

class MyCustomAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("MyAnalyzer")
    
    async def analyze(self, content, context=None):
        findings = []
        
        # Your custom detection logic
        if "dangerous_pattern" in content.lower():
            finding = self.create_security_finding(
                severity="HIGH",
                summary="Dangerous pattern detected",
                
                threat_name="Custom Threat Detection",
                details={
                    "pattern": "dangerous_pattern",
                    "location": content.index("dangerous_pattern")
                }
            )
            findings.append(finding)
        
        return findings

# Use custom analyzer
scanner = Scanner(custom_analyzers=[MyCustomAnalyzer()])
result = await scanner.scan_file("test.json")
```

### Error Handling

```python
async def safe_scanning():
    scanner = Scanner()
    
    try:
        result = await scanner.scan_registry(
            "https://example.com/.well-known/agents"
        )
        
        if result.status == "failed":
            print(f"Scan failed: {result.metadata.get('error')}")
        else:
            print(f"Scan completed: {len(result.findings)} findings")
            
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except ConnectionError as e:
        print(f"Connection failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
```

## Output Formats

### Console Output

The CLI provides rich formatted output with:
- Color-coded severity levels
- Formatted tables
- Summary statistics

### JSON Output

```json
{
  "target_name": "agent-123",
  "target_type": "agent_card",
  "status": "completed",
  "analyzers": ["yara", "pattern", "llm"],
  "findings": [
    {
      "severity": "HIGH",
      "threat_name": "Message Injection",
      "summary": "Directive injection detected",
      "analyzer": "YARA",
      "details": {
        "rule_name": "MessageInjection_DirectivePatterns",
        "matched_strings": [...]
      }
    }
  ],
  "total_findings": 1,
  "high_severity_count": 1,
  "metadata": {
    "agent_id": "agent-123",
    "url": "http://localhost:9001"
  }
}
```

## Integration Examples

### CI/CD Integration

```yaml
# GitHub Actions example
name: A2A Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      
      - name: Install scanner
        run: pip install a2a-scanner
      
      - name: Scan agent cards
        run: |
          a2a-scanner scan-directory agents/ -o results/
      
      - name: Check for high severity
        run: |
          if grep -q '"severity": "HIGH"' results/*.json; then
            echo "High severity threats found!"
            exit 1
          fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Scan staged JSON files
for file in $(git diff --cached --name-only --diff-filter=ACM | grep '\.json$'); do
    echo "Scanning $file..."
    a2a-scanner scan-file "$file"
    if [ $? -ne 0 ]; then
        echo "Security threats detected in $file"
        exit 1
    fi
done
```

### Web Service Integration

```python
from fastapi import FastAPI, HTTPException
from a2ascanner import Scanner

app = FastAPI()
scanner = Scanner()

@app.post("/scan/agent-card")
async def scan_agent_card(card: dict):
    try:
        result = await scanner.scan_agent_card(card)
        return result.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

## Performance Tips

1. **Use selective analyzers** for faster scans:
   ```bash
   a2a-scanner scan-file agent.json -a yara -a pattern
   ```

2. **Batch processing** for multiple files:
   ```bash
   a2a-scanner scan-directory examples/
   ```

3. **Disable LLM analyzer** when not needed (saves API costs):
   ```python
   # Don't set LLM API key, or use selective analyzers
   result = await scanner.scan_file("file.json", analyzers=["yara", "pattern"])
   ```

4. **Adjust timeout** for slow networks:
   ```python
   config = Config(timeout=60)
   scanner = Scanner(config=config)
   ```

## Troubleshooting

### YARA Import Error

```bash
# Install yara-python
pip install yara-python
```

### LLM Analyzer Not Available

```bash
# Check API key is set
echo $A2A_SCANNER_LLM_API_KEY

# Or set in code
config = Config(llm_api_key="your-key")
```

### No Rules Found

```bash
# Verify rules directory exists
ls a2ascanner/data/yara_rules/

# Or specify custom rules directory
scanner = Scanner(rules_dir="/path/to/rules")
```

## Best Practices

1. **Always scan agent cards** before deployment
2. **Use multiple analyzers** for comprehensive coverage
3. **Review high severity findings** immediately
4. **Integrate into CI/CD** pipeline
5. **Keep rules updated** regularly
6. **Monitor false positives** and tune rules
7. **Use LLM analyzer** for sophisticated threats
8. **Document findings** and remediation steps
