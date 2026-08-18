/**
 * Protected action registry tests.
 * @license Apache-2.0
 */
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  createGate,
  createProtectedActionRegistry
} from "./index.js";
function canonicalize(value) {
  if (value === null || value === void 0) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
function signer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKey,
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64url")
  };
}
function receipt(privateKey, action, id) {
  const payload = {
    receipt_id: id,
    subject: "agent:test",
    issuer: "ep:org:test",
    created_at: (/* @__PURE__ */ new Date()).toISOString(),
    claim: { action_type: action, outcome: "allow" }
  };
  const value = crypto.sign(
    null,
    Buffer.from(canonicalize(payload), "utf8"),
    privateKey
  ).toString("base64url");
  return {
    "@version": "EP-RECEIPT-v1",
    payload,
    signature: { algorithm: "Ed25519", value }
  };
}
const MANIFEST = {
  "@version": "EP-ACTION-RISK-MANIFEST-v0.1",
  actions: [
    {
      id: "change-payee",
      action_type: "finance.change_payee",
      receipt_required: true,
      risk: "high",
      assurance_class: "software",
      match: { protocol: "mcp", tool: "change_payee" }
    },
    {
      id: "read-balance",
      action_type: "finance.read_balance",
      receipt_required: false,
      match: { protocol: "mcp", tool: "read_balance" }
    }
  ]
};
const validPayee = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const input = value;
  return typeof input.vendor_id === "string" && typeof input.account_digest === "string" && Object.keys(input).every((key) => ["vendor_id", "account_digest"].includes(key));
};
test("registry accepts trusted-startup registration and seals an inspectable handler-free manifest", () => {
  const registry = createProtectedActionRegistry();
  const handler = async () => "ok";
  registry.register("finance.change_payee", validPayee, handler);
  registry.seal();
  assert.deepEqual(registry.describe(), {
    version: "EP-PROTECTED-ACTION-REGISTRY-v1",
    sealed: true,
    actions: ["finance.change_payee"]
  });
  assert.equal(JSON.stringify(registry.describe()).includes("handler"), false);
});
test("duplicate registration and every mutation after seal refuse", () => {
  const registry = createProtectedActionRegistry();
  registry.register("finance.change_payee", validPayee, async () => "ok");
  assert.throws(
    () => registry.register("finance.change_payee", validPayee, async () => "other"),
    /protected_action_duplicate/
  );
  registry.seal();
  assert.throws(
    () => registry.register("finance.read_balance", () => true, async () => "read"),
    /protected_action_registry_sealed/
  );
  assert.throws(() => registry.seal(), /protected_action_registry_sealed/);
});
test("runRegistered refuses unsealed, unknown, invalid, and counterfeit registries before handler entry", async () => {
  let calls = 0;
  const gate = createGate({ manifest: MANIFEST, allowEphemeralStore: true });
  const unsealed = createProtectedActionRegistry();
  unsealed.register("finance.read_balance", () => true, async () => {
    calls += 1;
  });
  const unsealedResult = await gate.runRegistered({
    selector: { protocol: "mcp", tool: "read_balance" },
    observedAction: {}
  }, unsealed);
  assert.equal(unsealedResult.ok, false);
  assert.equal(unsealedResult.reason, "protected_action_registry_unsealed");
  const sealed = createProtectedActionRegistry();
  sealed.register("finance.change_payee", validPayee, async () => {
    calls += 1;
  });
  sealed.seal();
  const unknown = await gate.runRegistered({
    selector: { protocol: "mcp", tool: "read_balance" },
    observedAction: {}
  }, sealed);
  assert.equal(unknown.ok, false);
  assert.equal(unknown.reason, "protected_action_unknown");
  const invalid = await gate.runRegistered({
    selector: { protocol: "mcp", tool: "change_payee" },
    observedAction: { vendor_id: "vendor-1", account_digest: 42 }
  }, sealed);
  assert.equal(invalid.ok, false);
  assert.equal(invalid.reason, "protected_action_parameters_invalid");
  const counterfeit = await gate.runRegistered({
    selector: { protocol: "mcp", tool: "change_payee" },
    observedAction: { vendor_id: "vendor-1", account_digest: "sha256:abc" }
  }, {
    sealed: true,
    resolve: () => ({ handler: async () => {
      calls += 1;
    } })
  });
  assert.equal(counterfeit.ok, false);
  assert.equal(counterfeit.reason, "protected_action_registry_invalid");
  assert.equal(calls, 0);
});
test("selector accessors cannot change the manifest-selected handler between preflight and admission", async () => {
  let calls = 0;
  let reads = 0;
  const registry = createProtectedActionRegistry();
  registry.register("finance.read_balance", () => true, async () => {
    calls += 1;
  });
  registry.register("finance.change_payee", validPayee, async () => {
    calls += 1;
  });
  registry.seal();
  const gate = createGate({ manifest: MANIFEST, allowEphemeralStore: true });
  const selector = {
    protocol: "mcp",
    get tool() {
      reads += 1;
      return reads === 1 ? "read_balance" : "change_payee";
    }
  };
  const result = await gate.runRegistered({ selector, observedAction: {} }, registry);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "protected_action_selector_invalid");
  assert.equal(calls, 0);
});
test("manifest resolution selects the handler and agent-carried names cannot redirect it", async () => {
  const calls = [];
  const registry = createProtectedActionRegistry();
  registry.register("finance.read_balance", () => true, async (parameters) => {
    calls.push("read");
    assert.equal(parameters.agent_selected_action, "finance.change_payee");
    assert.equal(Object.isFrozen(parameters), true);
    assert.throws(() => {
      parameters.agent_selected_action = "mutated";
    }, TypeError);
    return "balance";
  });
  registry.register("finance.change_payee", validPayee, async () => {
    calls.push("change");
    return "changed";
  });
  registry.seal();
  const gate = createGate({ manifest: MANIFEST, allowEphemeralStore: true });
  const result = await gate.runRegistered({
    selector: { protocol: "mcp", tool: "read_balance" },
    observedAction: { agent_selected_action: "finance.change_payee" }
  }, registry);
  assert.equal(result.ok, true);
  assert.equal(result.result, "balance");
  assert.deepEqual(calls, ["read"]);
});
test("guarded registered action reserves before handler, commits after return, and refuses replay", async () => {
  const phases = [];
  const states = /* @__PURE__ */ new Map();
  const store = {
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    async consume(id) {
      if (states.has(id)) return false;
      states.set(id, "committed");
      return true;
    },
    async reserve(id) {
      phases.push("reserve");
      if (states.has(id)) return false;
      states.set(id, "reserved");
      return true;
    },
    async commit(id) {
      phases.push("commit");
      if (states.get(id) !== "reserved") return false;
      states.set(id, "committed");
      return true;
    },
    async release(id) {
      phases.push("release");
      if (states.get(id) !== "reserved") return false;
      states.delete(id);
      return true;
    }
  };
  const keys = signer();
  const registry = createProtectedActionRegistry();
  registry.register("finance.change_payee", validPayee, async (parameters) => {
    phases.push("handler");
    assert.equal(states.size, 1, "authority must be reserved before provider entry");
    assert.equal(Object.isFrozen(parameters), true);
    return { provider_reference: "provider-1" };
  });
  registry.seal();
  const gate = createGate({
    manifest: MANIFEST,
    trustedKeys: [keys.publicKey],
    store
  });
  const authorization = receipt(keys.privateKey, "finance.change_payee", "registry-once");
  const input = {
    selector: { protocol: "mcp", tool: "change_payee" },
    receipt: authorization,
    observedAction: { vendor_id: "vendor-1", account_digest: "sha256:abc" }
  };
  const result = await gate.runRegistered(input, registry);
  assert.equal(result.ok, true);
  assert.deepEqual(phases, ["reserve", "handler", "commit"]);
  const replay = await gate.runRegistered(input, registry);
  assert.equal(replay.ok, false);
  assert.equal(replay.authorization.reason, "replay_refused");
});
test("handler exception keeps authority spent and reports an indeterminate effect", async () => {
  const states = /* @__PURE__ */ new Map();
  const store = {
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    async consume(id) {
      if (states.has(id)) return false;
      states.set(id, "committed");
      return true;
    },
    async reserve(id) {
      if (states.has(id)) return false;
      states.set(id, "reserved");
      return true;
    },
    async commit(id) {
      states.set(id, "committed");
      return true;
    },
    async release(id) {
      states.delete(id);
      return true;
    }
  };
  const keys = signer();
  const registry = createProtectedActionRegistry();
  registry.register("finance.change_payee", validPayee, async () => {
    throw new Error("provider acknowledgement lost");
  });
  registry.seal();
  const gate = createGate({ manifest: MANIFEST, trustedKeys: [keys.publicKey], store });
  await assert.rejects(
    gate.runRegistered({
      selector: { protocol: "mcp", tool: "change_payee" },
      receipt: receipt(keys.privateKey, "finance.change_payee", "registry-unknown"),
      observedAction: { vendor_id: "vendor-1", account_digest: "sha256:abc" }
    }, registry),
    (error) => {
      assert.equal(error.emiliaGateOutcome?.outcome, "indeterminate");
      return true;
    }
  );
  assert.deepEqual([...states.values()], ["committed"]);
});
