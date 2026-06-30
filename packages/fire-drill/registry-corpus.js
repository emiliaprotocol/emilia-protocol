// SPDX-License-Identifier: Apache-2.0
// Real MCP-registry servers that ADVERTISE a high-risk capability (name +
// description signal) AND publish a repository. Harvested by ingest from
// registry.modelcontextprotocol.io. This is a registry-level signal — NOT a
// tool-level scan and NOT a vulnerability claim. Used to render honest,
// repo-backlinked /fire-drill/registry/<slug> result pages.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(fs.readFileSync(path.join(here, 'registry-corpus.json'), 'utf8'));

export const REGISTRY_CORPUS = data.servers || [];
export const REGISTRY_CORPUS_META = {
  source: data.source,
  count: data.count,
  note: data.note,
};
