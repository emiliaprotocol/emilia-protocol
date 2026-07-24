// SPDX-License-Identifier: Apache-2.0

export type ProjectionScalar = string | number | boolean;
export type Projection = Record<string, ProjectionScalar>;

export type RuntimeStep = {
  operator: string;
  accepted: boolean;
  projection: Projection;
};

export type RuntimeScenarioResult = {
  scenario: string;
  steps: RuntimeStep[];
};

export type RuntimeAdapter = (
  scenario: string,
) => Promise<RuntimeScenarioResult>;
