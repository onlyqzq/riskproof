import { describe, expect, it } from "vitest";
import {
  findSensitivePaths,
  matchesPathPattern,
  normalizePathForPolicy,
} from "../../src/core/path-policy.js";

describe("sensitive path policy", () => {
  it("recognizes common credential files without exposing the path", () => {
    expect(findSensitivePaths({ path: "/home/user/.aws/credentials" })).toEqual([
      { field: "path", category: "cloud credentials" },
    ]);
    expect(findSensitivePaths({ file_path: "C:\\Users\\me\\.ssh\\id_ed25519" })[0].category).toBe("SSH private key");
    expect(findSensitivePaths({ path: "/proc/self/environ" })[0].category).toBe("process environment");
    expect(findSensitivePaths({ path: "/home/me/.config/gh/hosts.yml" })[0].category).toBe("developer service credentials");
  });

  it("allows documented environment templates", () => {
    expect(findSensitivePaths({ path: ".env.example" })).toEqual([]);
    expect(findSensitivePaths({ path: "config/.env.template" })).toEqual([]);
  });

  it("does not reinterpret message content as a path", () => {
    expect(findSensitivePaths({ body: "Please review .env before release" })).toEqual([]);
  });

  it("supports bounded operator patterns", () => {
    expect(findSensitivePaths(
      { request: { file_path: "project/private/signing.asc" } },
      ["**/private/*.asc"],
    )).toEqual([{ field: "request.file_path", category: "operator-configured sensitive path" }]);
  });

  it("normalizes separators and parent segments", () => {
    expect(normalizePathForPolicy("a/b/../private/key.txt")).toBe("a/private/key.txt");
    expect(matchesPathPattern("a/private/key.txt", "**/private/*.txt")).toBe(true);
  });
});
