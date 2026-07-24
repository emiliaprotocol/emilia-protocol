// SPDX-License-Identifier: Apache-2.0

import path from "node:path";
import type { Projection, ProjectionScalar } from "./types.mjs";

const TOP_KEYS = new Set([
  "@version",
  "scope",
  "limitations",
  "models",
  "traces",
]);
const MODEL_KEYS = new Set(["config", "variables", "projections", "actions"]);
const TRACE_KEYS = new Set([
  "id",
  "claim_id",
  "model",
  "adapter",
  "scenario",
  "kind",
  "runtime_sources",
  "obligations",
  "formal_prefix",
  "steps",
  "mutation",
]);
const STEP_KEYS = new Set(["operator", "accepted", "projection"]);
const MUTATION_KEYS = new Set([
  "operator",
  "defined_in_model",
  "precondition",
  "assignments",
  "obligation",
]);

export type TraceStepContract = {
  operator: string;
  accepted: boolean;
  projection: Projection;
};

export type MutationContract = {
  operator: string;
  defined_in_model: boolean;
  precondition?: string;
  assignments?: Projection;
  obligation: string;
};

export type TraceContract = {
  id: string;
  claim_id: string;
  model: string;
  adapter: string;
  scenario: string;
  kind: "sound" | "unsafe_mutation";
  runtime_sources: string[];
  obligations: string[];
  formal_prefix: string[];
  steps: TraceStepContract[];
  mutation?: MutationContract;
};

export type ModelContract = {
  config: string;
  variables: string[];
  projections: Record<string, string>;
  actions: Record<string, string>;
};

export type TraceManifest = {
  "@version": "EP-FORMAL-RUNTIME-TRACES-v2";
  scope: string;
  limitations: string[];
  models: Record<string, ModelContract>;
  traces: TraceContract[];
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireClosedKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0)
    throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
}

function requireString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function requireStringArray(
  value: unknown,
  label: string,
): asserts value is string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must be a non-empty string array`);
  }
  for (const [index, item] of value.entries())
    requireString(item, `${label}[${index}]`);
  if (new Set(value).size !== value.length)
    throw new Error(`${label} contains duplicates`);
}

function requireRelativeFile(
  value: unknown,
  label: string,
): asserts value is string {
  requireString(value, label);
  if (path.isAbsolute(value) || value.split(/[\\/]/u).includes("..")) {
    throw new Error(`${label} must stay inside the repository`);
  }
}

function requireIdentifier(
  value: unknown,
  label: string,
): asserts value is string {
  requireString(value, label);
  if (!/^[A-Za-z][A-Za-z0-9_]*$/u.test(value)) {
    throw new Error(`${label} must be a TLA+ identifier`);
  }
}

function requireAction(value: unknown, label: string): asserts value is string {
  requireString(value, label);
  if (!/^[A-Za-z][A-Za-z0-9_]*(?:\([A-Za-z0-9_, ]+\))?$/u.test(value)) {
    throw new Error(`${label} must be a closed TLA+ action expression`);
  }
}

function requireProjection(
  value: unknown,
  label: string,
): asserts value is Projection {
  if (!isObject(value) || Object.keys(value).length === 0) {
    throw new Error(`${label} must be a non-empty scalar projection`);
  }
  for (const [key, scalar] of Object.entries(value)) {
    requireIdentifier(key, `${label}.${key}`);
    if (!["string", "number", "boolean"].includes(typeof scalar)) {
      throw new Error(`${label}.${key} must be a scalar`);
    }
    if (
      typeof scalar === "number" &&
      (!Number.isSafeInteger(scalar) || scalar < 0)
    ) {
      throw new Error(`${label}.${key} must be a non-negative safe integer`);
    }
  }
}

function requireTlaExpression(
  value: unknown,
  label: string,
): asserts value is string {
  requireString(value, label);
  if (
    value.length > 240 ||
    /[\r\n;]/u.test(value) ||
    !/^[A-Za-z0-9_()[\] .,"'=#!<>+\-\\/{|}>:]+$/u.test(value)
  ) {
    throw new Error(`${label} must be a closed single-line TLA+ expression`);
  }
}

export function validateTraceManifest(input: unknown): TraceManifest {
  if (!isObject(input)) throw new Error("trace manifest must be an object");
  requireClosedKeys(input, TOP_KEYS, "trace manifest");
  if (input["@version"] !== "EP-FORMAL-RUNTIME-TRACES-v2") {
    throw new Error(
      "trace manifest version must be EP-FORMAL-RUNTIME-TRACES-v2",
    );
  }
  requireString(input.scope, "trace manifest scope");
  requireStringArray(input.limitations, "trace manifest limitations");
  if (!isObject(input.models) || Object.keys(input.models).length === 0) {
    throw new Error("trace manifest models must be a non-empty object");
  }

  const models: Record<string, ModelContract> = {};
  for (const [modelPath, rawModel] of Object.entries(input.models)) {
    requireRelativeFile(modelPath, `models.${modelPath}`);
    if (!isObject(rawModel))
      throw new Error(`models.${modelPath} must be an object`);
    requireClosedKeys(rawModel, MODEL_KEYS, `models.${modelPath}`);
    requireRelativeFile(rawModel.config, `models.${modelPath}.config`);
    requireStringArray(rawModel.variables, `models.${modelPath}.variables`);
    for (const [index, variable] of rawModel.variables.entries()) {
      requireIdentifier(variable, `models.${modelPath}.variables[${index}]`);
    }
    if (
      !isObject(rawModel.projections) ||
      Object.keys(rawModel.projections).length === 0
    ) {
      throw new Error(
        `models.${modelPath}.projections must be a non-empty object`,
      );
    }
    const projections: Record<string, string> = {};
    for (const [name, expression] of Object.entries(rawModel.projections)) {
      requireIdentifier(name, `models.${modelPath}.projections.${name}`);
      requireTlaExpression(
        expression,
        `models.${modelPath}.projections.${name}`,
      );
      projections[name] = expression;
    }
    const actions: Record<string, string> = {};
    if (rawModel.actions !== undefined) {
      if (!isObject(rawModel.actions)) {
        throw new Error(`models.${modelPath}.actions must be an object`);
      }
      for (const [name, expression] of Object.entries(rawModel.actions)) {
        requireAction(name, `models.${modelPath}.actions.${name}`);
        requireTlaExpression(expression, `models.${modelPath}.actions.${name}`);
        actions[name] = expression;
      }
    }
    models[modelPath] = {
      config: rawModel.config,
      variables: rawModel.variables,
      projections,
      actions,
    };
  }

  if (!Array.isArray(input.traces) || input.traces.length === 0) {
    throw new Error("trace manifest traces must be a non-empty array");
  }
  const ids = new Set<string>();
  const traces = input.traces.map((rawTrace, index): TraceContract => {
    const label = `traces[${index}]`;
    if (!isObject(rawTrace)) throw new Error(`${label} must be an object`);
    requireClosedKeys(rawTrace, TRACE_KEYS, label);
    requireString(rawTrace.id, `${label}.id`);
    if (ids.has(rawTrace.id))
      throw new Error(`duplicate trace id: ${rawTrace.id}`);
    ids.add(rawTrace.id);
    requireString(rawTrace.claim_id, `${label}.claim_id`);
    requireRelativeFile(rawTrace.model, `${label}.model`);
    if (!models[rawTrace.model])
      throw new Error(`${label}.model is not registered`);
    requireString(rawTrace.adapter, `${label}.adapter`);
    requireString(rawTrace.scenario, `${label}.scenario`);
    if (rawTrace.kind !== "sound" && rawTrace.kind !== "unsafe_mutation") {
      throw new Error(`${label}.kind must be sound or unsafe_mutation`);
    }
    requireStringArray(rawTrace.runtime_sources, `${label}.runtime_sources`);
    rawTrace.runtime_sources.forEach((file, fileIndex) =>
      requireRelativeFile(file, `${label}.runtime_sources[${fileIndex}]`),
    );
    requireStringArray(rawTrace.obligations, `${label}.obligations`);
    rawTrace.obligations.forEach((obligation, obligationIndex) =>
      requireIdentifier(obligation, `${label}.obligations[${obligationIndex}]`),
    );
    const formalPrefix =
      rawTrace.formal_prefix === undefined ? [] : rawTrace.formal_prefix;
    if (!Array.isArray(formalPrefix)) {
      throw new Error(`${label}.formal_prefix must be an array`);
    }
    formalPrefix.forEach((action, actionIndex) =>
      requireAction(action, `${label}.formal_prefix[${actionIndex}]`),
    );
    if (!Array.isArray(rawTrace.steps) || rawTrace.steps.length === 0) {
      throw new Error(`${label}.steps must be a non-empty array`);
    }
    const projections = new Set(
      Object.keys(models[rawTrace.model].projections),
    );
    const steps = rawTrace.steps.map(
      (rawStep, stepIndex): TraceStepContract => {
        const stepLabel = `${label}.steps[${stepIndex}]`;
        if (!isObject(rawStep))
          throw new Error(`${stepLabel} must be an object`);
        requireClosedKeys(rawStep, STEP_KEYS, stepLabel);
        requireAction(rawStep.operator, `${stepLabel}.operator`);
        if (typeof rawStep.accepted !== "boolean") {
          throw new Error(`${stepLabel}.accepted must be boolean`);
        }
        requireProjection(rawStep.projection, `${stepLabel}.projection`);
        for (const projection of Object.keys(rawStep.projection)) {
          if (!projections.has(projection)) {
            throw new Error(
              `${stepLabel}.projection references unknown projection ${projection}`,
            );
          }
        }
        return {
          operator: rawStep.operator,
          accepted: rawStep.accepted,
          projection: rawStep.projection,
        };
      },
    );

    let mutation: MutationContract | undefined;
    if (rawTrace.kind === "unsafe_mutation") {
      if (!isObject(rawTrace.mutation))
        throw new Error(`${label}.mutation is required`);
      requireClosedKeys(rawTrace.mutation, MUTATION_KEYS, `${label}.mutation`);
      requireIdentifier(
        rawTrace.mutation.operator,
        `${label}.mutation.operator`,
      );
      requireIdentifier(
        rawTrace.mutation.obligation,
        `${label}.mutation.obligation`,
      );
      const definedInModel = rawTrace.mutation.defined_in_model === true;
      if (
        rawTrace.mutation.defined_in_model !== undefined &&
        typeof rawTrace.mutation.defined_in_model !== "boolean"
      ) {
        throw new Error(`${label}.mutation.defined_in_model must be boolean`);
      }
      if (!definedInModel) {
        requireString(
          rawTrace.mutation.precondition,
          `${label}.mutation.precondition`,
        );
        requireProjection(
          rawTrace.mutation.assignments,
          `${label}.mutation.assignments`,
        );
      } else if (
        rawTrace.mutation.precondition !== undefined ||
        rawTrace.mutation.assignments !== undefined
      ) {
        throw new Error(
          `${label}.mutation model-defined operator cannot include assignments`,
        );
      }
      if (!rawTrace.obligations.includes(rawTrace.mutation.obligation)) {
        throw new Error(
          `${label}.mutation.obligation must appear in obligations`,
        );
      }
      for (const variable of Object.keys(rawTrace.mutation.assignments ?? {})) {
        if (!models[rawTrace.model].variables.includes(variable)) {
          throw new Error(
            `${label}.mutation references unknown variable ${variable}`,
          );
        }
      }
      mutation = {
        operator: rawTrace.mutation.operator,
        defined_in_model: definedInModel,
        ...(definedInModel
          ? {}
          : {
              precondition: rawTrace.mutation.precondition as string,
              assignments: rawTrace.mutation.assignments as Projection,
            }),
        obligation: rawTrace.mutation.obligation,
      };
    } else if (rawTrace.mutation !== undefined) {
      throw new Error(
        `${label}.mutation is allowed only for unsafe_mutation traces`,
      );
    }

    return {
      id: rawTrace.id,
      claim_id: rawTrace.claim_id,
      model: rawTrace.model,
      adapter: rawTrace.adapter,
      scenario: rawTrace.scenario,
      kind: rawTrace.kind,
      runtime_sources: rawTrace.runtime_sources,
      obligations: rawTrace.obligations,
      formal_prefix: formalPrefix,
      steps,
      ...(mutation ? { mutation } : {}),
    };
  });

  return {
    "@version": "EP-FORMAL-RUNTIME-TRACES-v2",
    scope: input.scope,
    limitations: input.limitations,
    models,
    traces,
  };
}

export function canonicalProjection(
  projection: Record<string, ProjectionScalar>,
): Projection {
  return Object.fromEntries(
    Object.entries(projection).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
}
