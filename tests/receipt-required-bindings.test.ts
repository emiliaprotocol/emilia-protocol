// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { computeCaid } from "../caid/impl/js/caid.mjs";
import {
  evaluateBindingVectors,
  projectBoundAction,
  validateBindingRegistry,
} from "../bindings/receipt-required/validate.js";

const readJson = (path: string) =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));

const registry = readJson("../bindings/receipt-required/registry.v1.json");
const vectors = readJson(
  "../conformance/vectors/receipt-required-bindings.v1.json",
);
const clone = <T>(value: T): T => structuredClone(value);

describe("Receipt Required protocol binding registry", () => {
  it("is closed, complete, and honest about every profile implementation state", () => {
    const result = validateBindingRegistry(registry);
    expect(result).toEqual({ valid: true, errors: [] });
    expect(registry.profiles.map((profile) => profile.protocol_id)).toEqual([
      "http",
      "mcp",
      "a2a",
      "x402",
      "ap2",
      "wimse",
    ]);
    expect(
      registry.profiles.find((profile) => profile.protocol_id === "ap2")
        .implementation_status,
    ).toBe("synthetic_binding_profile");
    expect(
      registry.profiles.find((profile) => profile.protocol_id === "wimse")
        .implementation_status,
    ).toBe("verification_context_only");
  });

  it("rejects unknown keys at every contract level", () => {
    const badRegistry = clone(registry);
    badRegistry.marketing_claim = "universal adoption";
    expect(validateBindingRegistry(badRegistry).errors).toContain(
      "registry.marketing_claim is not allowed",
    );

    const badProfile = clone(registry);
    badProfile.profiles[0].challenge_carrier.magic = true;
    expect(validateBindingRegistry(badProfile).errors).toContain(
      "profiles[0].challenge_carrier.magic is not allowed",
    );
  });

  it("rejects ambiguous match selectors", () => {
    const ambiguous = clone(registry);
    ambiguous.profiles[1].match_selector = clone(
      ambiguous.profiles[0].match_selector,
    );
    const result = validateBindingRegistry(ambiguous);
    expect(result.valid).toBe(false);
    expect(result.errors.join("\n")).toMatch(/ambiguous match selector/i);
  });

  it("rejects missing binding fields before projection", () => {
    const fixture = clone(vectors.fixtures.http);
    const http = registry.profiles.find(
      (profile) => profile.protocol_id === "http",
    );
    delete fixture.artifact.request.body.currency;
    expect(() => projectBoundAction(http, fixture.artifact)).toThrow(
      /missing required binding.*currency/i,
    );
  });

  it("binds every carrier to the same real CAID and action hash", () => {
    const results = evaluateBindingVectors(registry, vectors);
    expect(results).toEqual([
      { id: "accept_same_action", valid: true, reason: null },
      { id: "reject_caid_mismatch", valid: false, reason: "caid_mismatch" },
      {
        id: "reject_action_hash_mismatch",
        valid: false,
        reason: "action_hash_mismatch",
      },
      {
        id: "reject_missing_protocol_binding",
        valid: false,
        reason: "missing_binding",
      },
    ]);

    const computed = computeCaid(vectors.canonical_action, {
      suite: "jcs-sha256",
      definitions: vectors.definitions,
    });
    expect(computed).toMatchObject({
      caid: vectors.expected_caid,
      digest: vectors.expected_action_hash,
    });
  });

  it("labels every foreign presentation as a synthetic fixture", () => {
    for (const [protocolId, fixture] of Object.entries(vectors.fixtures)) {
      if (
        protocolId === "http" ||
        protocolId === "mcp" ||
        protocolId === "x402"
      )
        continue;
      expect(fixture.fixture_class).toBe("synthetic_foreign_artifact");
    }
  });
});
