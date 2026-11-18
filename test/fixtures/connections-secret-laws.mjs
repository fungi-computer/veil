/* global Buffer, Response */
import assert from "node:assert/strict";

/**
 * The secret laws every Connections owner keeps, run through that owner's own
 * public methods: Hub's Team owner and Oyster's instance owner alike. Plain
 * JavaScript so Oyster's node:test suite and Hub's Vitest suite share it.
 *
 * @param {import("./connections-secret-laws.d.mts").SecretOwner} owner
 */
export async function proveSecretOwner(owner) {
  const value = owner.secret;
  const leaks = [];
  const remember = (thing) => {
    leaks.push(thing);
    return thing;
  };
  const send = async (subject, ref, url, init = {}) =>
    remember(
      await owner.send(subject, ref, {
        url,
        method: init.method ?? "GET",
        headers: [],
        body: null,
      }),
    );
  const refusal = (outcome) =>
    outcome instanceof Response
      ? `status:${String(outcome.status)}`
      : outcome.error;

  const id = await owner.add({
    name: "payments",
    destinations: [
      { host: "api.example.com", pathPrefix: "/v1/", methods: ["GET"] },
    ],
    placement: "bearer",
    secret: value,
  });
  const { agent, computer, app, teamKey, deadKey } = owner.subjects;
  // Every subject kind the Vault serves. Apps hold no Vault power yet.
  const everyone = [agent, computer, teamKey];
  const granted = async (connectionId, subject) => {
    const outcome = await owner.grant(connectionId, subject);
    assert.ok(!("refusal" in outcome), `${subject.kind} grant refused`);
    return remember(outcome);
  };
  const refs = {};
  for (const subject of everyone)
    refs[subject.kind] = await granted(id, subject);
  // Grants are checked when given: no App, and no key that is not live.
  for (const subject of [app, deadKey]) {
    const outcome = remember(await owner.grant(id, subject));
    assert.ok("refusal" in outcome, `${subject.kind}:${subject.id} granted`);
  }
  assert.deepEqual(
    (await owner.list())
      .find((view) => view.connectionId === id)
      ?.grants.map((grant) => grant.subject.kind)
      .sort(),
    ["agent", "computer", "team-key"],
  );
  remember(await owner.list());

  // Each subject kind's grant admits a send, once, at the bound site.
  for (const subject of everyone) {
    const before = owner.sent().length;
    const ok = await send(
      subject,
      refs[subject.kind],
      "https://api.example.com/v1/items",
    );
    assert.equal(refusal(ok), "status:200", subject.kind);
    assert.equal(owner.sent().length, before + 1);
    assert.equal(
      owner.sent().at(-1)?.headers.get("authorization"),
      `Bearer ${value}`,
    );
  }

  // Exact-host binding through the URL parser; nothing leaves on refusal.
  const sentBefore = owner.sent().length;
  for (const url of [
    "https://api.example.com.evil.example/v1/items",
    "https://evil-api.example.com/v1/items",
    "https://xn--pi-7ka.example.com/v1/items",
    "https://аpi.example.com/v1/items",
    "https://api.example.com./v1/items",
    "https://user:pass@api.example.com/v1/items",
    "https://api.example.com:8443/v1/items",
    "http://api.example.com/v1/items",
    "https://93.184.216.34/v1/items",
    "https://[2606:2800:220:1::]/v1/items",
    "https://api.example.com/v2/items",
    "https://api.example.com/v1",
  ])
    assert.equal(
      refusal(await send(computer, refs.computer, url)),
      "denied",
      url,
    );
  assert.equal(
    refusal(
      await send(computer, refs.computer, "https://api.example.com/v1/items", {
        method: "POST",
      }),
    ),
    "denied",
  );
  // A reference is inert for any subject without its own grant, even one
  // sharing the granted subject's id under another kind.
  for (const holder of everyone)
    for (const other of [...everyone, app].filter(
      (subject) => subject.kind !== holder.kind,
    ))
      assert.equal(
        refusal(
          await send(
            { kind: other.kind, id: holder.id },
            refs[holder.kind],
            "https://api.example.com/v1/items",
          ),
        ),
        "revoked",
        `${holder.kind} -> ${other.kind}`,
      );
  assert.equal(
    refusal(
      await send(
        { ...computer, id: `${computer.id}-other` },
        refs.computer,
        "https://api.example.com/v1/items",
      ),
    ),
    "revoked",
  );
  assert.equal(owner.sent().length, sentBefore);

  // A subject's grant stands only while the subject does: every send asks.
  const live = await owner.add({
    name: "liveness",
    destinations: [{ host: "api.example.com", methods: ["GET"] }],
    placement: "bearer",
    secret: value,
  });
  for (const subject of everyone) {
    const ref = await granted(live, subject);
    const url = "https://api.example.com/items";
    assert.equal(refusal(await send(subject, ref, url)), "status:200");
    const before = owner.sent().length;
    owner.end(subject);
    assert.equal(
      refusal(await send(subject, ref, url)),
      "denied",
      `ended ${subject.kind} still sends`,
    );
    assert.equal(owner.sent().length, before, `ended ${subject.kind} sent`);
  }
  const liveUsage = remember(await owner.usage(live));
  assert.equal(
    liveUsage
      .filter((row) => row.outcome === "refused_grant")
      .map((row) => row.subject.kind)
      .sort()
      .join(),
    ["agent", "computer", "team-key"].join(),
  );

  // Revocation is observed by the very next send, with no restart.
  const beforeRevoke = owner.sent().length;
  await owner.ungrant(id, computer);
  assert.equal(
    refusal(
      await send(computer, refs.computer, "https://api.example.com/v1/items"),
    ),
    "revoked",
  );
  await owner.revoke(id);
  assert.equal(
    refusal(await send(agent, refs.agent, "https://api.example.com/v1/items")),
    "revoked",
  );
  assert.equal(owner.sent().length, beforeRevoke);

  const usage = remember(await owner.usage(id));
  const outcomes = new Set(usage.map((row) => row.outcome));
  for (const outcome of [
    "placed",
    "upstream_status",
    "refused_destination",
    "refused_grant",
  ])
    assert.ok(outcomes.has(outcome), outcome);
  assert.ok(usage.every((row) => row.count >= 1));

  // A grantor who loses authority stops every use before it leaves. Ended
  // subjects stay ended, so this uses a fresh Computer.
  if (owner.demote !== undefined) {
    const second = await owner.add({
      name: "storage",
      destinations: [{ host: "files.example.com", methods: ["GET"] }],
      placement: "basic",
      secret: `user:${value}`,
    });
    const fresh = { kind: "computer", id: `${computer.id}-fresh` };
    const ref = await granted(second, fresh);
    owner.demote();
    const before = owner.sent().length;
    assert.equal(
      refusal(await send(fresh, ref, "https://files.example.com/")),
      "denied",
    );
    assert.equal(owner.sent().length, before);
  }

  const seen = Buffer.from(
    JSON.stringify(leaks, (_key, item) =>
      item instanceof Response ? item.status : item,
    ),
  );
  assert.equal(
    seen.includes(Buffer.from(value)),
    false,
    "owner results hold no value",
  );
  assert.equal(
    Buffer.from(await owner.storedBytes()).includes(Buffer.from(value)),
    false,
    "owner store holds no value",
  );
}
