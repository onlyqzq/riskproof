#!/usr/bin/env node

import { copyFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const outputDir = resolve(import.meta.dirname, "../dist");

for (const name of ["riskproof.schema.json", "riskproof.example.json"]) {
  copyFileSync(resolve(repositoryRoot, name), resolve(outputDir, name));
}
