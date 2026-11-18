import { performance } from "node:perf_hooks";
import {
  createFingerprintRedactor,
  createFingerprintSet,
  createKnownValueRedactor,
  createPatternRedactor,
  type RedactionResult,
} from "@fungi.computer/veil/redaction";

// A local measurement, not a CI throughput budget. Every pass sees exactly
// 64 KiB, including keyword-bearing benign output and a positive match.
const secret = ["ghp_", "7Zk9P2mQa4Wv6Xc8Bn0Ds3Fg5Hj1Lr9Ty2Ui"].join("");
const line =
  "exec build: api_key configuration absent; completed source checks\n";
const text =
  line.repeat(Math.ceil(65536 / line.length)).slice(0, 65536 - secret.length) +
  secret;
const patterns = createPatternRedactor();
const fingerprints = await createFingerprintRedactor(
  await createFingerprintSet(new Uint8Array(32).fill(7), [secret]),
);
const owner = createKnownValueRedactor([secret]);
const passes: readonly (readonly [
  string,
  (text: string) => Promise<RedactionResult> | RedactionResult,
])[] = [
  ["known-value-fingerprints (Session)", (input) => fingerprints.redact(input)],
  ["known-value-raw (owner)", (input) => owner.redact(input)],
  ["gitleaks-patterns", (input) => patterns.redact(input)],
];
for (const [name, redact] of passes) {
  for (let warmup = 0; warmup < 3; warmup++) await redact(text);
  const start = performance.now();
  let iterations = 0;
  do {
    const result = await redact(text);
    if (result.status !== "redacted" || result.text.includes(secret))
      throw new Error(`${name}: measurement did not redact the canary`);
    iterations++;
  } while (performance.now() - start < 1000 && iterations < 10000);
  const seconds = (performance.now() - start) / 1000;
  console.log(
    JSON.stringify({
      pass: name,
      bytesPerOutput: Buffer.byteLength(text),
      iterations,
      seconds,
      megabytesPerSecond:
        (iterations * Buffer.byteLength(text)) / 1_000_000 / seconds,
    }),
  );
}
