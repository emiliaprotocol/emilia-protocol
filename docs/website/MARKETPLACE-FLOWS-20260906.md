<!-- SPDX-License-Identifier: Apache-2.0 -->
# Marketplace browsing, publication and responses

The marketplace is the sourcing path within EMILIA Workforce. These routes
support introductions and proposals. They do not hire an agent, process a sale,
issue credentials, accept an assignment or activate Gate.

## A returning builder

At `/works/join`, choose the existing-profile path and enter the builder ID and
its EMILIA entity API key. An authenticated owner-only read confirms that the
stored profile belongs to that key. A public profile match is not sufficient.

The preview shows the existing profile unchanged and the exact new listing to
publish. Publication needs explicit consent and creates only the listing. A lost
write response or duplicate ID is recoverable only when an owner-authorized read
returns the same normalized approved content. Divergent or foreign records do
not confirm publication. Existing records are not overwritten.

New self-service entity registration retains its existing deployment flag and
is closed in production by default. A builder without a key can request access;
the form does not claim that access was granted.

## A company reviewing responses

The private inbox is linked from a real opportunity at
`/works/opportunities/{id}/inbox`. The server checks the stored opportunity owner
or an authorized administrator before reading proposals, and filters the
opportunity on the server. A builder who submitted one proposal cannot use that
as access to the employer inbox.

Responses are paginated, with newest records first. Storage or authentication
failure is distinct from a successful empty page. The page does not embed
private proposals in server-rendered HTML. Authenticated responses use private,
no-store cache headers; the browser clears private results when leaving the tab.
This release has no proposal email notifications.

## Moving the conversation forward

An explicitly real, active agent listing with a matching real builder and a
valid public contact route offers **Discuss this worker**. Examples and paused
or archived listings do not offer that action. The link opens the builder's
website or a user-reviewed email compose. It does not send a message itself.

The company and builder still agree on availability, deliverables, price, terms,
limits and acceptance criteria. Authority Record monitoring payments are a
separate product, not agent-worker checkout. No sale, availability or safety
certification is inferred from a listing, scan, proposal or contact click.

## Verification boundaries

Tests exercise authorization refusal, mixed-opportunity payload rejection,
private-result clearing and publication retry behavior. Browser checks use
synthetic records and intercepted writes, not customer adoption or transactions.
