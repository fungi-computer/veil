import { expect, it } from "vitest";
import { patternRedactorLoader } from "../src/redaction.js";
import { configuration } from "../src/redaction-rules.generated.js";

it("retries the rule table after a parse failure instead of keeping it cached", async () => {
  const broken = {
    ...configuration,
    rules: configuration.rules.map((rule) => ({ ...rule, regex: "(" })),
  };
  const tables = [broken, configuration];
  let reads = 0;
  const load = patternRedactorLoader(() => {
    const table = tables[reads];
    reads += 1;
    if (table === undefined) throw new Error("The rule table was read again");
    return Promise.resolve(table);
  });

  await expect(load()).rejects.toThrow();
  const token = ["ghp_", "7Zk9P2mQa4Wv6Xc8Bn0Ds3Fg5Hj1Lr9Ty2Ui"].join("");
  const redactor = await load();
  expect(redactor.contains(`use ${token} here`)).toBe(true);
  await load();
  expect(reads).toBe(2);
});
