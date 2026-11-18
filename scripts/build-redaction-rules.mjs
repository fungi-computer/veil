import { mkdir, readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { parse } from "smol-toml";
import { RE2JS } from "re2js";

// No generated source is committed. Every Veil build (including consumer
// prerequisite builds) produces these modules inside its declared dist output.
const root = new URL("../", import.meta.url);
const { values } = parseArgs({
  options: { check: { type: "boolean", default: false } },
});
const config = parse(
  values.check
    ? readFileSync(0, "utf8")
    : await readFile(new URL("vendor/gitleaks.toml", root), "utf8"),
);
const failures = [];
function compilePattern(source, id) {
  try {
    return RE2JS.compile(source);
  } catch (error) {
    console.error(`gitleaks rule ${id} could not compile:`, error);
    failures.push(id);
    return undefined;
  }
}
function validatePatterns(value, id) {
  for (const [key, field] of Object.entries(value)) {
    if (["regex", "path"].includes(key)) {
      compilePattern(field, `${id} (${key})`);
    } else if (["regexes", "paths"].includes(key)) {
      for (const pattern of field) {
        compilePattern(pattern, `${id} (${key})`);
      }
    } else if (key === "allowlists") {
      for (const allowlist of field) validatePatterns(allowlist, id);
    }
  }
}
validatePatterns(config.allowlist, "global allowlist");
for (const rule of config.rules) {
  validatePatterns(rule, rule.id);
  if (rule.regex === undefined && rule.path === undefined)
    failures.push(`${rule.id}: neither content regex nor path rule`);
  if (rule.regex !== undefined && rule.secretGroup !== undefined) {
    const expression = compilePattern(rule.regex, rule.id);
    if (expression && rule.secretGroup > expression.groupCount())
      failures.push(`${rule.id}: secretGroup exceeds capture groups`);
  }
}
if (failures.length > 0) {
  throw new Error(`gitleaks rules could not compile:\n${failures.join("\n")}`);
}
console.log(`Validated ${config.rules.length} gitleaks rules with re2js.`);
console.log(
  `Filename-only rules (not applicable to text): ${config.rules
    .filter((rule) => rule.regex === undefined)
    .map((rule) => rule.id)
    .join(", ")}`,
);
if (!values.check) {
  await mkdir(new URL("dist/", root), { recursive: true });
  await writeFile(
    new URL("dist/redaction-rules.js", root),
    `// Generated from vendor/gitleaks.toml; do not edit.\nexport const configuration = ${JSON.stringify(config)};\n`,
  );
  await writeFile(
    new URL("dist/redaction-rules.d.ts", root),
    "export declare const configuration: unknown;\n",
  );
}
