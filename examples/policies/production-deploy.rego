package riskproof

import rego.v1

# Compile with:
#   opa build -t wasm -e riskproof/decision examples/policies/production-deploy.rego
decision := {"matches": matches}

matches contains {
  "id": "production_deploy_requires_approval",
  "decision": "require_approval",
  "riskLevel": "high",
  "triggeredArgs": ["command"],
  "evidence": ["command contains a production deployment target"],
  "reason": "Production deployments require an independent reviewer",
} if {
  input.input.tool == "shell_exec"
  contains(lower(input.input.args.command), "production")
}
