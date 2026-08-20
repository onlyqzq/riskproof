import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const errors = [];

function requireCondition(condition, message) {
  if (!condition) errors.push(message);
}

const canonicalRepository =
  "git+https://github.com/onlyqzq/dsh-riskproof.git";
const patchPath = manifest.dsh?.bundle?.patch;
const officialRuntimePeers = [
  "@deepseek-ai/cordis",
  "@deepseek-ai/dsh-agent",
  "@deepseek-ai/dsh-tools",
  "@deepseek-ai/schemastery",
];

requireCondition(
  manifest.repository?.url === canonicalRepository,
  `repository.url must be ${canonicalRepository}`,
);
requireCondition(
  manifest.homepage === "https://github.com/onlyqzq/dsh-riskproof#readme",
  "homepage must point to the canonical repository",
);
requireCondition(
  manifest.bugs?.url === "https://github.com/onlyqzq/dsh-riskproof/issues",
  "bugs.url must point to the canonical repository",
);
requireCondition(
  typeof patchPath === "string" && patchPath.length > 0,
  "dsh.bundle.patch must be declared",
);
requireCondition(
  manifest.files?.includes("cordis.patch.yml"),
  "the bundled patch must be included in the npm file set",
);
requireCondition(
  manifest.files?.includes("dist"),
  "the prebuilt dist directory must be included in the npm file set",
);
requireCondition(
  manifest.scripts?.prepare === "npm run build",
  "prepare must build source installs",
);

const misplacedOfficialDependencies = Object.keys(manifest.dependencies ?? {})
  .filter((name) => name.startsWith("@deepseek-ai/"));
requireCondition(
  misplacedOfficialDependencies.length === 0,
  `official packages must be peerDependencies: ${misplacedOfficialDependencies.join(", ")}`,
);

for (const dependency of officialRuntimePeers) {
  requireCondition(
    typeof manifest.peerDependencies?.[dependency] === "string",
    `${dependency} must be declared as a peerDependency`,
  );
  requireCondition(
    typeof manifest.devDependencies?.[dependency] === "string",
    `${dependency} must also be available for local development`,
  );
}

for (const dependency of [
  "@deepseek-ai/dsh-agent",
  "@deepseek-ai/dsh-tools",
]) {
  requireCondition(
    manifest.peerDependencies?.[dependency]?.includes("0.1.0-"),
    `${dependency} must explicitly admit the DSH 0.1.0 prerelease line`,
  );
}

if (patchPath) {
  try {
    await access(resolve(root, patchPath));
  } catch {
    errors.push(`declared bundle patch does not exist: ${patchPath}`);
  }
}

if (errors.length > 0) {
  console.error("Marketplace readiness check failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log("Marketplace readiness check passed.");
