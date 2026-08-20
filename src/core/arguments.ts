// ============================================================================
// dsh-riskproof - bounded JSON argument traversal
// ============================================================================
// DSH arguments are losslessly JSON-serializable, but tool schemas may place
// security-relevant values below nested objects and arrays. This module gives
// provenance, taint, and destination analysis one collision-resistant path
// representation without mutating the original arguments.
// ============================================================================

export interface ArgumentLeaf {
  path: string;
  field: string;
  value: unknown;
}

export const ARGUMENT_TRAVERSAL_LIMITS = Object.freeze({
  maxNodes: 10_000,
  maxDepth: 64,
});

/** Preserve ordinary object arguments and give root scalars/arrays a stable key. */
export function argumentsAsRecord(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return { $: value };
}

/** Flatten JSON leaves into stable paths such as `message.body` and `items[0]`. */
export function argumentLeaves(
  args: Record<string, unknown>,
  maxNodes: number = ARGUMENT_TRAVERSAL_LIMITS.maxNodes,
  maxDepth: number = ARGUMENT_TRAVERSAL_LIMITS.maxDepth,
): ArgumentLeaf[] {
  const leaves: ArgumentLeaf[] = [];
  const pending: Array<{ value: unknown; path: string; field: string; depth: number }> = [];

  const entries = Object.entries(args);
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const [field, value] = entries[index];
    pending.push({ value, path: renderRootField(field), field, depth: 0 });
  }

  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    nodes += 1;
    if (nodes > maxNodes) {
      throw new RangeError(`tool arguments exceed maximum node count of ${maxNodes}`);
    }
    if (current.depth > maxDepth) {
      throw new RangeError(`tool arguments exceed maximum depth of ${maxDepth}`);
    }

    if (Array.isArray(current.value)) {
      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        pending.push({
          value: current.value[index],
          path: `${current.path}[${index}]`,
          field: current.field,
          depth: current.depth + 1,
        });
      }
      continue;
    }

    if (typeof current.value === "object" && current.value !== null) {
      const children = Object.entries(current.value as Record<string, unknown>);
      for (let index = children.length - 1; index >= 0; index -= 1) {
        const [field, value] = children[index];
        pending.push({
          value,
          path: appendField(current.path, field),
          field,
          depth: current.depth + 1,
        });
      }
      continue;
    }

    leaves.push({
      path: current.path,
      field: current.field,
      value: current.value,
    });
  }

  return leaves;
}

export function flattenArguments(args: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(argumentLeaves(args).map(({ path, value }) => [path, value]));
}

function renderRootField(field: string): string {
  return isSimpleField(field) ? field : `[${JSON.stringify(field)}]`;
}

function appendField(parent: string, field: string): string {
  return isSimpleField(field)
    ? `${parent}.${field}`
    : `${parent}[${JSON.stringify(field)}]`;
}

function isSimpleField(field: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$-]*$/.test(field);
}
