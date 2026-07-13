# RiskProof Development Guide

## Product Direction

RiskProof is a risk-aware approval layer for high-risk AI Agent tool calls.

It is NOT:
- a generic chatbot guardrail
- a generic content moderation system
- a pure observability dashboard
- a full enterprise security platform in MVP

It IS:
- a pluggable approval security layer
- focused on high-risk tool calls
- designed to explain risk before user approval

## Core Idea

Current Agent approval often only shows what action will be executed.
RiskProof shows:
- what action will be executed
- where each critical argument came from
- whether the arguments contain sensitive data
- whether untrusted sources influenced the action
- which policies were matched
- what consequences approval may cause
- what action is recommended

## MVP Scope

Only implement the first closed loop:

ToolCall
→ Provenance
→ Taint
→ Policy
→ Risk Explanation
→ Approval Decision
→ Proof JSON

## First Supported Tools

- send_email
- http_request
- shell_exec

## Core Modules

1. Tool Call Interceptor
2. Provenance Collector
3. Taint Analyzer
4. Policy Engine
5. Risk Explanation Generator
6. Approval CLI
7. Proof Store

## Do Not Drift

- Do not build UI before the CLI proof loop works.
- Do not build a generic security platform.
- Do not rely on LLMs for final security decisions.
- Do not execute real shell/email/http actions in MVP.
- Use mock tools first.
- Every feature must include tests.
- Every high-risk tool call must produce a structured proof object.

## Engineering Rules

Before coding:
- read docs/IDEA.md
- explain the task
- propose a file-level plan
- list acceptance criteria

During coding:
- make small changes
- avoid unnecessary dependencies
- keep types explicit
- prefer deterministic logic over LLM judgment

After coding:
- run tests
- summarize changed files
- explain how the implementation matches the architecture
