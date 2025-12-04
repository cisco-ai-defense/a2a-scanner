# Analyzer Development Guide

## Overview

This guide explains how to develop and extend analyzers for the A2A Scanner.

## Analyzer Architecture

All analyzers inherit from `BaseAnalyzer` and implement the `analyze()` method:

```python
from a2ascanner.core.analyzers.base import BaseAnalyzer, SecurityFinding
from typing import Any, Dict, List, Optional

class MyAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("MyAnalyzer")
        # Initialize your analyzer
    
    async def analyze(
        self, 
        content: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        # Your detection logic
        findings = []
        return findings
```

## BaseAnalyzer Features

### Automatic Logging

```python
self.logger.info("Starting analysis")
self.logger.debug(f"Content length: {len(content)}")
self.logger.error("Analysis failed")
```

### Input Validation

```python
# Automatically validates content
self.validate_content(content)  # Raises ValueError if invalid
```

### Finding Creation Helper

```python
finding = self.create_security_finding(
    severity="HIGH",
    summary="Threat detected",
    ,
    threat_name="Message Injection",
    details={"key": "value"}
)
```

## Creating a Custom Analyzer

### Step 1: Define Your Analyzer Class

```python
from a2ascanner.core.analyzers.base import BaseAnalyzer, SecurityFinding
import re

class KeywordAnalyzer(BaseAnalyzer):
    """Detects specific keywords in content."""
    
    def __init__(self, keywords: List[str]):
        super().__init__("Keyword")
        self.keywords = keywords
        self.logger.info(f"Initialized with {len(keywords)} keywords")
```

### Step 2: Implement Detection Logic

```python
    async def analyze(
        self, 
        content: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze content for keywords."""
        findings = []
        context = context or {}
        
        # Convert to lowercase for case-insensitive matching
        content_lower = content.lower()
        
        for keyword in self.keywords:
            if keyword.lower() in content_lower:
                finding = self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"Keyword '{keyword}' detected",
                    ,
                    threat_name="Keyword Detection",
                    details={
                        "keyword": keyword,
                        "context": context
                    }
                )
                findings.append(finding)
        
        return findings
```

### Step 3: Use Your Analyzer

```python
from a2ascanner import Scanner

# Create analyzer instance
keyword_analyzer = KeywordAnalyzer(
    keywords=["malicious", "exploit", "backdoor"]
)

# Add to scanner
scanner = Scanner(custom_analyzers=[keyword_analyzer])

# Use it
result = await scanner.scan_file("test.json")
```

## Advanced Patterns

### Pattern Compilation

Compile regex patterns in `__init__` for performance:

```python
class RegexAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("Regex")
        # Compile patterns once
        self.patterns = {
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "ip": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            "url": re.compile(r'https?://[^\s]+')
        }
    
    async def analyze(self, content, context=None):
        findings = []
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            if matches:
                finding = self.create_security_finding(
                    severity="LOW",
                    summary=f"Found {len(matches)} {pattern_name} patterns",
                    ,
                    threat_name="Sensitive Data Detection",
                    details={"pattern": pattern_name, "matches": matches[:5]}
                )
                findings.append(finding)
        
        return findings
```

### JSON Structure Analysis

```python
import json

class StructureAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("Structure")
    
    async def analyze(self, content, context=None):
        findings = []
        
        try:
            data = json.loads(content)
            
            # Check for suspicious structure
            if isinstance(data, dict):
                # Check for missing required fields
                required = ["id", "name", "url"]
                missing = [f for f in required if f not in data]
                
                if missing:
                    finding = self.create_security_finding(
                        severity="LOW",
                        summary=f"Missing required fields: {', '.join(missing)}",
                        ,
                        threat_name="Incomplete Metadata",
                        details={"missing_fields": missing}
                    )
                    findings.append(finding)
                
                # Check for suspicious nested depth
                max_depth = self._get_depth(data)
                if max_depth > 10:
                    finding = self.create_security_finding(
                        severity="MEDIUM",
                        summary=f"Excessive nesting depth: {max_depth}",
                        ,
                        threat_name="Structure Complexity",
                        details={"depth": max_depth}
                    )
                    findings.append(finding)
        
        except json.JSONDecodeError:
            # Not JSON, skip
            pass
        
        return findings
    
    def _get_depth(self, obj, current_depth=0):
        """Calculate maximum nesting depth."""
        if not isinstance(obj, (dict, list)):
            return current_depth
        
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._get_depth(v, current_depth + 1) for v in obj.values())
        
        if isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._get_depth(item, current_depth + 1) for item in obj)
```

### External API Integration

```python
import httpx

class ReputationAnalyzer(BaseAnalyzer):
    def __init__(self, api_key: str):
        super().__init__("Reputation")
        self.api_key = api_key
        self.api_url = "https://api.reputation-service.com/check"
    
    async def analyze(self, content, context=None):
        findings = []
        
        # Extract URLs from content
        urls = self._extract_urls(content)
        
        # Check each URL's reputation
        async with httpx.AsyncClient() as client:
            for url in urls:
                try:
                    response = await client.post(
                        self.api_url,
                        json={"url": url},
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        timeout=10.0
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("malicious"):
                            finding = self.create_security_finding(
                                severity="HIGH",
                                summary=f"Malicious URL detected: {url}",
                                ,
                                threat_name="Malicious Endpoint",
                                details={
                                    "url": url,
                                    "reputation_score": data.get("score"),
                                    "categories": data.get("categories", [])
                                }
                            )
                            findings.append(finding)
                
                except Exception as e:
                    self.logger.error(f"Reputation check failed for {url}: {e}")
        
        return findings
    
    def _extract_urls(self, content):
        """Extract URLs from content."""
        import re
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        return url_pattern.findall(content)
```

### Stateful Analysis

```python
class SequenceAnalyzer(BaseAnalyzer):
    """Analyzer that maintains state across multiple scans."""
    
    def __init__(self):
        super().__init__("Sequence")
        self.seen_ids = set()
        self.scan_count = 0
    
    async def analyze(self, content, context=None):
        findings = []
        self.scan_count += 1
        
        try:
            data = json.loads(content)
            agent_id = data.get("id")
            
            if agent_id:
                if agent_id in self.seen_ids:
                    finding = self.create_security_finding(
                        severity="MEDIUM",
                        summary=f"Duplicate agent ID detected: {agent_id}",
                        ,
                        threat_name="Registry Poisoning - Duplicate ID",
                        details={
                            "agent_id": agent_id,
                            "scan_number": self.scan_count
                        }
                    )
                    findings.append(finding)
                else:
                    self.seen_ids.add(agent_id)
        
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def reset_state(self):
        """Reset analyzer state."""
        self.seen_ids.clear()
        self.scan_count = 0
```

## YARA Rule Development

### Rule Structure

```yara
rule RuleName : ThreatCategory
{
    meta:
        description = "Description of what this rule detects"
        
        threat_name = "Human-readable threat name"
        severity = "HIGH"
        author = "Your Name"
        date = "2024-01-01"
    
    strings:
        $pattern1 = "exact string"
        $pattern2 = /regex pattern/i
        $pattern3 = { 48 65 6C 6C 6F }  // hex pattern
    
    condition:
        any of them
}
```

### Example Rules

```yara
rule SuspiciousCommand 
{
    meta:
        description = "Detects suspicious command execution patterns"
        
        threat_name = "Command Execution"
        severity = "HIGH"
    
    strings:
        $cmd1 = /eval\s*\(/
        $cmd2 = /exec\s*\(/
        $cmd3 = /subprocess\.(call|run|Popen)/
        $cmd4 = /os\.system\(/
    
    condition:
        any of them
}

rule DataExfiltration 
{
    meta:
        description = "Detects data exfiltration patterns"
        
        threat_name = "Data Exfiltration"
        severity = "HIGH"
    
    strings:
        $http = /https?:\/\//
        $post = /POST|post/
        $data = /(data|payload|content):/
    
    condition:
        all of them
}
```

### Testing YARA Rules

```python
import yara

# Compile rule
rules = yara.compile(filepath="my_rule.yara")

# Test against content
matches = rules.match(data="test content")

for match in matches:
    print(f"Rule matched: {match.rule}")
    print(f"Namespace: {match.namespace}")
    print(f"Tags: {match.tags}")
    print(f"Meta: {match.meta}")
```

## Testing Your Analyzer

### Unit Tests

```python
import pytest
from my_analyzer import MyAnalyzer

@pytest.mark.asyncio
async def test_keyword_detection():
    analyzer = MyAnalyzer()
    
    # Test positive case
    content = "This contains a malicious keyword"
    findings = await analyzer.analyze(content)
    assert len(findings) > 0
    assert findings[0].severity == "HIGH"
    
    # Test negative case
    content = "This is clean content"
    findings = await analyzer.analyze(content)
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_with_context():
    analyzer = MyAnalyzer()
    context = {"target_type": "agent_card", "agent_id": "test-123"}
    
    content = "malicious content"
    findings = await analyzer.analyze(content, context)
    
    assert len(findings) > 0
    assert findings[0].details.get("context") == context
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_analyzer_in_scanner():
    from a2ascanner import Scanner
    
    analyzer = MyAnalyzer()
    scanner = Scanner(custom_analyzers=[analyzer])
    
    result = await scanner.scan_file("test_file.json")
    
    assert "MyAnalyzer" in result.analyzers
    assert result.status == "completed"
```

## Best Practices

1. **Performance**
   - Compile patterns in `__init__`
   - Use async operations for I/O
   - Avoid blocking operations

2. **Error Handling**
   - Catch and log exceptions
   - Return empty list on error
   - Don't crash the scanner

3. **Logging**
   - Use appropriate log levels
   - Include context in messages
   - Log performance metrics

4. **Documentation**
   - Document detection logic
   - Provide usage examples
   - Explain severity levels

5. **Testing**
   - Write unit tests
   - Test edge cases
   - Verify false positive rate

## Example: Complete Analyzer

```python
"""
Custom analyzer for detecting cryptocurrency addresses.
"""

import re
from typing import Any, Dict, List, Optional
from a2ascanner.core.analyzers.base import BaseAnalyzer, SecurityFinding

class CryptoAnalyzer(BaseAnalyzer):
    """Detects cryptocurrency addresses in content."""
    
    # Address patterns
    PATTERNS = {
        "bitcoin": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "ethereum": r'\b0x[a-fA-F0-9]{40}\b',
        "monero": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
    }
    
    def __init__(self):
        super().__init__("Crypto")
        
        # Compile patterns
        self.compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in self.PATTERNS.items()
        }
        
        self.logger.info(
            f"Initialized with {len(self.compiled_patterns)} crypto patterns"
        )
    
    async def analyze(
        self, 
        content: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze content for cryptocurrency addresses.
        
        Args:
            content: Content to analyze
            context: Optional context information
            
        Returns:
            List of security findings
        """
        findings = []
        context = context or {}
        
        for crypto_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(content)
            
            if matches:
                # Remove duplicates
                unique_matches = list(set(matches))
                
                finding = self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"Found {len(unique_matches)} {crypto_type} address(es)",
                    ,
                    threat_name="Cryptocurrency Address Detection",
                    details={
                        "crypto_type": crypto_type,
                        "count": len(unique_matches),
                        "addresses": unique_matches[:3],  # First 3 only
                        "context": context
                    }
                )
                findings.append(finding)
                
                self.logger.info(
                    f"Detected {len(unique_matches)} {crypto_type} addresses"
                )
        
        return findings

# Usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        analyzer = CryptoAnalyzer()
        
        test_content = """
        Send payment to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        ETH address: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
        """
        
        findings = await analyzer.analyze(test_content)
        
        for finding in findings:
            print(f"{finding.severity}: {finding.summary}")
            print(f"  Details: {finding.details}")
    
    asyncio.run(main())
```
