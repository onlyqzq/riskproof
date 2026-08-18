import type {
  SecurityCapability,
  TaintLabel,
  ToolSecurityContext,
} from "../src/core/types.js";
import { EMPTY_TOOLCHAIN_STATE } from "../src/core/types.js";

export interface ContextOptions {
  name?: string;
  capabilities?: SecurityCapability[];
  args?: Record<string, unknown>;
  provenance?: Record<string, string[]>;
  taints?: Record<string, TaintLabel[]>;
  toolchain?: ToolSecurityContext["toolchain"];
  internalDomains?: string[];
  nested?: boolean;
}

export function buildContext(options: ContextOptions = {}): ToolSecurityContext {
  return {
    tool: {
      name: options.name ?? "unknown_tool",
      capabilities: options.capabilities ?? [],
    },
    args: options.args ?? {},
    provenance: options.provenance ?? {},
    taints: options.taints ?? {},
    toolchain: options.toolchain ?? { ...EMPTY_TOOLCHAIN_STATE, path: [] },
    execution: { callId: "call-1", nested: options.nested ?? false },
    internalDomains: options.internalDomains,
  };
}
