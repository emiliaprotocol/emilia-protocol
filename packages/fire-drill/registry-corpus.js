// SPDX-License-Identifier: Apache-2.0
// Real MCP-registry servers that ADVERTISE a high-risk capability (name +
// description signal) AND publish a repository. Harvested by ingest from
// registry.modelcontextprotocol.io. This is a registry-level signal — NOT a
// tool-level scan and NOT a vulnerability claim. Used to render honest,
// repo-backlinked /fire-drill/registry/<slug> result pages.

// Import the JSON directly — do NOT fs.readFileSync a computed path. On the
// dynamic /fire-drill/registry route this module runs inside a Vercel
// serverless function, and Next's file tracer won't bundle a runtime
// readFileSync target → ENOENT 500 in prod (while working locally, where the
// file is on disk). A static JSON import is inlined into every consumer's
// bundle, so the data is always present at runtime — same mechanism as the
// already-working reports.json / registry-index.json imports.
import data from './registry-corpus.json';

export const REGISTRY_CORPUS = data.servers || [];
export const REGISTRY_CORPUS_META = {
  source: data.source,
  count: data.count,
  note: data.note,
};
