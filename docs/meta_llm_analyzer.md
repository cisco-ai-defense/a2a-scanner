# Meta LLM Analyzer Documentation

The Meta LLM Analyzer is a second-pass analysis system that reviews and refines security findings from all primary analyzers. It uses an LLM to intelligently filter false positives, prioritize findings by actual risk, correlate related issues, and provide actionable remediation guidance.

## Overview

Unlike the primary LLM Analyzer that directly analyzes content, the Meta Analyzer operates on the **results** of all other analyzers, providing expert-level review of their collective findings.

### Key Capabilities

| Feature                        | Description                                                      |
|--------------------------------|------------------------------------------------------------------|
| **False Positive Pruning**     | Identifies and filters out likely false positives based on context |
| **Risk Prioritization**        | Ranks findings by actual exploitability and business impact      |
| **Finding Correlation**        | Groups related findings that represent the same underlying issue |
| **Actionable Recommendations** | Provides specific code fixes and remediation steps               |

---

## Architecture Flow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             USER RUNS SCAN                                  │
│              a2a-scanner scan-file agent.json --meta                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: cli.py - scan_file() or scan_card()                               │
│  File: a2ascanner/cli.py                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: scanner.py - scan_file() / scan_agent_card()                      │
│  Runs ALL primary analyzers FIRST (YARA, Heuristic, LLM, Spec)             │
│  File: a2ascanner/core/scanner.py                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
                ▼                     ▼                     ▼
       ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
       │  YaraAnalyzer  │    │   Heuristic    │    │  LLMAnalyzer   │  ...
       │    (rules)     │    │   Analyzer     │    │   (primary)    │
       └────────────────┘    └────────────────┘    └────────────────┘
                │                     │                     │
                └─────────────────────┼─────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: All findings are COLLECTED into ScanResult                        │
│  ScanResult contains findings from ALL analyzers                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: IF --meta flag is set AND there are findings:                     │
│  scanner.run_meta_analysis(scan_result, original_content)                  │
│  File: a2ascanner/core/scanner.py                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: LLMMetaAnalyzer.analyze_findings()                                │
│  RECEIVES: All findings from Step 3 + original content                     │
│  File: a2ascanner/core/analyzers/meta_analyzer.py                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 6: LLM API Call with:                                                │
│  - System Prompt: meta_analysis_prompt.md                                  │
│  - User Prompt: JSON of ALL findings + original scanned content            │
│  File: a2ascanner/data/prompts/meta_analysis_prompt.md                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 7: Parse LLM response → MetaAnalysisResult                           │
│  Contains: validated_findings, false_positives, recommendations            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 8: scanner.apply_meta_analysis() - Filter & Enrich                   │
│  Removes false positives, adds enrichments to remaining findings           │
│  File: a2ascanner/core/scanner.py                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  FINAL: Display filtered results + recommendations to user                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Step-by-Step Flow

### Step 1: CLI Entry Point

When the user runs a scan with the `--meta` flag, the CLI captures this option:

```bash
a2a-scanner scan-file agent.json --meta
```

**File:** `a2ascanner/cli.py`

The `scan_file()` or `scan_card()` function receives the `meta` flag and prepares to run meta-analysis after the primary scan.

---

### Step 2: Primary Analyzers Execute

The scanner runs all configured primary analyzers concurrently:

**File:** `a2ascanner/core/scanner.py` → `_run_analyzers()`

```python
# Run analyzers concurrently
tasks = [analyzer.analyze(content, context) for analyzer in analyzers_to_run]
results = await asyncio.gather(*tasks, return_exceptions=True)

# Collect findings from ALL analyzers
all_findings = []
for result in results:
    if isinstance(result, list):
        all_findings.extend(result)
```

**Primary Analyzers:**

| Analyzer                 | Purpose                                      |
|--------------------------|----------------------------------------------|
| `YaraAnalyzer`           | Pattern-based threat detection using YARA rules |
| `HeuristicAnalyzer`      | Suspicious pattern detection via heuristics  |
| `LLMAnalyzer`            | Semantic threat analysis using LLM           |
| `SpecComplianceAnalyzer` | A2A protocol compliance checking             |
| `EndpointAnalyzer`       | Live endpoint security testing               |

---

### Step 3: Findings Collection

All findings from primary analyzers are aggregated into a single `ScanResult`:

```python
result = ScanResult(
    target_name=card_name,
    target_type="agent_card",
    status="completed",
    analyzers=list(self.analyzers),
    findings=findings,  # Combined findings from ALL analyzers
    metadata={...},
)
```

---

### Step 4: Meta-Analysis Trigger

If the `--meta` flag is set AND there are findings, meta-analysis begins:

**File:** `a2ascanner/cli.py`

```python
if meta and result.has_findings():
    meta_result = await scanner.run_meta_analysis(result, file_content)
    result = scanner.apply_meta_analysis(result, meta_result)
```

---

### Step 5: Meta-Analyzer Initialization

**File:** `a2ascanner/core/scanner.py` → `run_meta_analysis()`

```python
async def run_meta_analysis(
    self,
    scan_result: ScanResult,      # Contains ALL primary findings
    original_content: Optional[str] = None,
) -> MetaAnalysisResult:
    """Run LLM meta-analysis on scan findings."""

    return await self.meta_analyzer.analyze_findings(
        findings=scan_result.findings,  # Pass ALL findings
        original_content=content,
        context=context,
    )
```

---

### Step 6: LLM API Call

**File:** `a2ascanner/core/analyzers/meta_analyzer.py` → `analyze_findings()`

The meta-analyzer builds a comprehensive prompt containing:

1. **System Prompt** (from `meta_analysis_prompt.md`):
   - Instructions for false positive identification
   - Prioritization criteria
   - Expected JSON output format

2. **User Prompt** (dynamically built):
   - JSON array of ALL findings with their source analyzers
   - Original scanned content for context

```python
def _build_user_prompt(self, findings, original_content, context, ...):
    findings_data = []
    for i, finding in enumerate(findings):
        finding_dict = {
            "severity": finding.severity,
            "summary": finding.summary,
            "threat_name": finding.threat_name,
            "analyzer": finding.analyzer,  # Shows source: YARA, LLM, etc.
            "details": finding.details,
            "_index": i,
        }
        findings_data.append(finding_dict)

    return f"""## Security Findings to Analyze

### Findings from Analyzers
{json.dumps(findings_data, indent=2)}

### Original Scanned Content
{original_content}
"""
```

---

### Step 7: Response Parsing

**File:** `a2ascanner/core/analyzers/meta_analyzer.py` → `_parse_meta_response()`

The LLM response is parsed into a structured `MetaAnalysisResult`:

```python
@dataclass
class MetaAnalysisResult:
    validated_findings: List[Dict]    # Confirmed true positives
    false_positives: List[Dict]       # Identified false positives
    priority_order: List[int]         # Ordered indices by priority
    correlations: List[Dict]          # Related finding groups
    recommendations: List[Dict]       # Actionable fixes
    overall_risk_assessment: Dict     # Summary risk level
```

---

### Step 8: Apply Meta-Analysis

**File:** `a2ascanner/core/scanner.py` → `apply_meta_analysis()`

```python
def apply_meta_analysis(
    self,
    scan_result: ScanResult,
    meta_result: MetaAnalysisResult,
    remove_false_positives: bool = True,
) -> ScanResult:
    """Apply meta-analysis results to filter and enrich findings."""

    # Convert validated findings back to SecurityFinding objects
    new_findings = meta_result.get_findings_as_security_findings()

    # Create new result with enriched metadata
    return ScanResult(
        ...
        findings=new_findings,
        metadata={
            **scan_result.metadata,
            "meta_analysis": {
                "applied": True,
                "false_positives_removed": len(meta_result.false_positives),
                "recommendations": meta_result.recommendations,
                ...
            },
        },
    )
```

---

## Configuration

### Environment Variables

The meta-analyzer can use separate LLM configuration from the primary analyzer:

| Variable                          | Description                        | Fallback                      |
|-----------------------------------|------------------------------------|-------------------------------|
| `A2A_SCANNER_META_LLM_PROVIDER`   | LLM provider (openai, azure, etc.) | `A2A_SCANNER_LLM_PROVIDER`    |
| `A2A_SCANNER_META_LLM_API_KEY`    | API key for meta-analyzer          | `A2A_SCANNER_LLM_API_KEY`     |
| `A2A_SCANNER_META_LLM_MODEL`      | Model name (e.g., gpt-4o)          | `A2A_SCANNER_LLM_MODEL`       |
| `A2A_SCANNER_META_LLM_BASE_URL`   | Base URL (for Azure/Ollama)        | `A2A_SCANNER_LLM_BASE_URL`    |
| `A2A_SCANNER_META_LLM_API_VERSION`| API version (for Azure)            | `A2A_SCANNER_LLM_API_VERSION` |

### CLI Options

```bash
# Enable meta-analysis
a2a-scanner scan-file agent.json --meta

# Use specific model for meta-analysis
a2a-scanner scan-file agent.json --meta --meta-model gpt-4o

# Use separate API key
a2a-scanner scan-file agent.json --meta --meta-api-key sk-xxx
```

---

## Programmatic Usage

### Basic Usage

```python
import asyncio
from a2ascanner.config.config import Config
from a2ascanner.core.scanner import Scanner

async def main():
    config = Config()
    scanner = Scanner(config=config, enable_meta_analysis=True)

    agent_card = {"id": "agent-1", "name": "My Agent", ...}

    # Option 1: Combined scan + meta-analysis
    scan_result, meta_result = await scanner.scan_with_meta_analysis(agent_card)

    # Option 2: Separate steps
    scan_result = await scanner.scan_agent_card(agent_card)
    meta_result = await scanner.run_meta_analysis(scan_result, json.dumps(agent_card))
    filtered_result = scanner.apply_meta_analysis(scan_result, meta_result)

asyncio.run(main())
```

### Accessing Results

```python
# Meta-analysis results
print(f"Validated: {len(meta_result.validated_findings)}")
print(f"False Positives: {len(meta_result.false_positives)}")
print(f"Risk Level: {meta_result.overall_risk_assessment.get('risk_level')}")

# Recommendations
for rec in meta_result.recommendations:
    print(f"[{rec['priority']}] {rec['title']}")
    print(f"  Fix: {rec.get('fix', 'N/A')}")

# Get prioritized findings
prioritized = scanner.meta_analyzer.get_prioritized_findings(meta_result)

# Get formatted recommendations
formatted = scanner.meta_analyzer.format_recommendations(meta_result)
```

---

## Output Format

### MetaAnalysisResult JSON Structure

```json
{
  "validated_findings": [
    {
      "_index": 0,
      "severity": "HIGH",
      "threat_name": "PROMPT INJECTION",
      "summary": "Malicious instruction detected in agent description",
      "analyzer": "LLM",
      "confidence": "HIGH",
      "confidence_reason": "Clear instruction override pattern detected",
      "exploitability": "Easy - requires no authentication",
      "impact": "Could lead to unauthorized data access",
      "enriched_details": {
        "attack_vector": "User-controlled input flows to system prompt",
        "prerequisites": ["Public agent endpoint"],
        "affected_components": ["description", "system_prompt"]
      }
    }
  ],
  "false_positives": [
    {
      "_index": 2,
      "original_threat_name": "SUSPICIOUS KEYWORD",
      "original_summary": "Found 'admin' in description",
      "false_positive_reason": "Standard role documentation, not an attack",
      "confidence": "HIGH"
    }
  ],
  "priority_order": [0, 3, 1],
  "correlations": [
    {
      "group_name": "Injection Attack Chain",
      "finding_indices": [0, 3],
      "relationship": "Prompt injection enables data exfiltration",
      "combined_severity": "CRITICAL"
    }
  ],
  "recommendations": [
    {
      "priority": "HIGH",
      "title": "Sanitize Agent Description Input",
      "description": "The agent description contains injection vectors",
      "affected_findings": [0, 3],
      "fix": "def sanitize(desc):\n    return re.sub(r'ignore.*instructions', '', desc)",
      "effort": "LOW",
      "impact": "HIGH"
    }
  ],
  "overall_risk_assessment": {
    "risk_level": "HIGH",
    "summary": "Multiple injection vulnerabilities detected",
    "critical_issues": ["Prompt injection in description"],
    "immediate_actions": ["Sanitize user inputs", "Add input validation"],
    "attack_scenarios": [
      {
        "name": "Data Exfiltration via Injection",
        "description": "Attacker injects prompt to extract sensitive data",
        "likelihood": "MEDIUM",
        "impact": "HIGH"
      }
    ]
  }
}
```

---

## Why Two LLM Calls?

| Aspect      | Primary LLM Analyzer              | Meta LLM Analyzer                        |
|-------------|-----------------------------------|------------------------------------------|
| **Input**   | Raw scanned content               | Findings from ALL analyzers              |
| **Purpose** | Find semantic threats             | Review & refine findings                 |
| **Output**  | Individual findings               | Validated findings + recommendations     |
| **Model**   | Can use faster/cheaper model      | Can use smarter model for reasoning      |
| **When**    | Always (if LLM enabled)           | Only with `--meta` flag                  |

### Example Scenario

1. **YARA Analyzer** flags "admin" as suspicious → False positive (just documentation)
2. **Heuristic Analyzer** flags "execute" as code injection → False positive (legitimate API)
3. **LLM Analyzer** flags a real prompt injection in description → True positive
4. **Meta Analyzer** reviews all 3:
   - Removes the 2 false positives
   - Keeps the real threat
   - Provides a specific code fix
   - Assesses overall risk as HIGH

---

## File References

| File                                             | Purpose                                    |
|--------------------------------------------------|--------------------------------------------|
| `a2ascanner/cli.py`                              | CLI entry point, `--meta` flag handling    |
| `a2ascanner/core/scanner.py`                     | Scanner orchestration, `run_meta_analysis()` |
| `a2ascanner/core/analyzers/meta_analyzer.py`     | `LLMMetaAnalyzer` class implementation     |
| `a2ascanner/data/prompts/meta_analysis_prompt.md`| System prompt template                     |
| `a2ascanner/config/config.py`                    | Meta LLM configuration settings            |

---

## Best Practices

1. **Use for high-value scans**: Meta-analysis adds latency and cost; use it when accuracy matters most.

2. **Configure appropriate models**: Use a capable model (GPT-4, Claude 3) for better reasoning.

3. **Review false positives**: Check the `false_positives` array to understand what was filtered.

4. **Act on recommendations**: The `recommendations` array contains actionable fixes with code.

5. **Monitor API usage**: Meta-analysis requires additional LLM API calls; monitor costs.
