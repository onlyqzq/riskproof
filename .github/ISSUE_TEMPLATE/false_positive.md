---
name: False Positive Report
about: RiskProof blocked (or asked about) a safe tool call
title: "false positive: "
labels: ["false-positive"]
assignees: []
---

**What was blocked**
Describe the tool call RiskProof wrongly flagged (tool name, capabilities if known, and the decision it returned).

**Tool sequence**
The sequence of tool calls leading up to it, in order. Redact sensitive values.

**Why it is safe**
Explain why this flow should be allowed.

**Arguments (redacted)**
```json
{ "to": "colleague@internal.example", "body": "[redacted]" }
```

**Relevant config**
```yaml
# classification.overrides and policy.internalDomains, if any
```

**Additional context**
- RiskProof version:
- DSH version:
