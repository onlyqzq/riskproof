import type { Context } from "@deepseek-ai/cordis";
import type {
  PreToolDecision,
  ToolExecution,
  ToolExecutionResult,
} from "@deepseek-ai/dsh-tools";

export interface MockToolDef {
  description: string;
  parameters?: Record<string, unknown>;
}

export function makeMockCtx(
  toolDefs: Record<string, MockToolDef> = {},
  scopedToolDefs: Record<string, Record<string, MockToolDef>> = {},
): Context {
  const logger = { warn: () => {}, info: () => {}, error: () => {}, debug: () => {} };
  return {
    tools: {
      get(name: string, agent?: { id?: string }): MockToolDef & { name: string } | undefined {
        const scoped = agent?.id ? scopedToolDefs[agent.id] : undefined;
        const def = scoped && Object.hasOwn(scoped, name)
          ? scoped[name]
          : Object.hasOwn(toolDefs, name) ? toolDefs[name] : undefined;
        return def ? { name, description: def.description, parameters: def.parameters ?? {} } : undefined;
      },
    },
    logger: () => logger,
  } as unknown as Context;
}

let callCounter = 0;

export function makeExec(
  name: string,
  args: Record<string, unknown>,
  agentId = "session-1",
  parent?: unknown,
): ToolExecution {
  callCounter += 1;
  return {
    name,
    callId: `call-${name}-${callCounter}`,
    rootCallId: "root-1",
    arguments: args,
    agent: { id: agentId } as never,
    parent,
    token: Symbol("token"),
    signal: new AbortController().signal,
  } as unknown as ToolExecution;
}

export function successResult(value: unknown): ToolExecutionResult {
  return { isError: false, value, content: [] } as unknown as ToolExecutionResult;
}

export function errorResult(message: string): ToolExecutionResult {
  return { isError: true, error: { message }, content: [] } as unknown as ToolExecutionResult;
}

export const allowNext = async (): Promise<PreToolDecision> => ({ kind: "allow" });

export const denyNext = async (): Promise<PreToolDecision> => ({ kind: "deny", reason: "other plugin" });
