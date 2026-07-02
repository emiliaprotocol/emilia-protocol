<!-- SPDX-License-Identifier: Apache-2.0 -->
# create-ep-app

Zero to a verified **EMILIA Protocol** trust system in five minutes — no Supabase,
no Vercel, no blockchain wallet. Just Node.js 20+.

```bash
npx @emilia-protocol/create-ep-app my-trust-system
cd my-trust-system
npm install
npm run dev
```

## What it scaffolds

A minimal but complete EP-powered app that demonstrates the core loop:

- Entity registration
- Receipt submission + verification
- Trust profile view
- Handshake ceremony demo
- Self-verifying receipt generation
- **Offline** receipt verification (no server required to check a receipt)

It exists so a developer can hold a working, offline-verifiable authorization
receipt in their hands before reading a spec — the top of the adoption funnel
for the [EMILIA Protocol](https://www.emiliaprotocol.ai) consequence firewall.

## Requirements

- Node.js >= 20

## Note on the package name

Always run the **scoped** name `@emilia-protocol/create-ep-app`. The unscoped
`create-ep-app` name on npm belongs to an unrelated third party — do not run it.

## License

Apache-2.0
