# A refund tool that stays within its approval

Run a real Hugging Face `smolagents.Tool` through EMILIA's receipt check. The
example approves $42 to Alice, then tries the exact refund, a changed amount,
a changed recipient, no approval, a repeated call, and a lost provider response.
No model, payment account, or API key is needed. No money moves.

**Let your agent prepare the action. Decide what it may execute.**

For a ready-to-run folder, download `EMILIA-Hugging-Face-Space.zip` from the
[community release](https://github.com/emiliaprotocol/emilia-protocol/releases/tag/smolagents-preview-v0.1.0).
Unzip it, verify `SHA256SUMS`, then install `requirements.txt` in a fresh virtual
environment and run `python app.py`. The included wheels avoid waiting for the
separate PyPI releases. This is free, Apache-2.0 source and a synthetic demo, not a
hosted production Gate.

## Run it from this checkout

Use Python 3.10 or later. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ./packages/python-verify ./packages/crewai ./packages/smolagents 'gradio==6.26.0'
python examples/huggingface-refund-space/demo.py
python examples/huggingface-refund-space/app.py
```

Open the local address printed by Gradio. Each click starts a **new simulated
session**. The replay and lost-response scenarios make two calls inside that
session, using the same approval and consumption store.

| Scenario | Synthetic refunds recorded | Result |
| --- | ---: | --- |
| Exact approved call | 1 | Provider returns |
| No approval | 0 | Refused before provider entry |
| Changed amount or recipient | 0 | Refused before provider entry |
| Same approval twice | 1 | Second call refused |
| Provider records refund, then times out | 1 | Outcome unknown to adapter; reuse refused |

The final row is important: the test fixture can inspect its own recorded refund.
The adapter cannot infer that result from a timeout. A real integration must
reconcile with its provider before deciding what to do next. A new approval for
the same business operation is a separate problem; this adapter does not supply
business-operation deduplication or provider settlement evidence.

## Make a Hugging Face Space bundle

```sh
python examples/huggingface-refund-space/bundle_space.py --output /tmp/emilia-refund-space
```

Choose a new output directory. The script refuses to overwrite an existing one.
It builds the three local EMILIA wheels, copies the app, demo tests, Dockerfile,
and documentation, adds Docker Space metadata, and records the source commit and
file hashes. It does **not**
create an account, upload files, or publish anything.

To validate that folder separately:

```sh
cd /tmp/emilia-refund-space
shasum -a 256 -c SHA256SUMS
python3 -m venv /tmp/emilia-refund-space-venv
/tmp/emilia-refund-space-venv/bin/python -m pip install --upgrade pip
/tmp/emilia-refund-space-venv/bin/python -m pip install -r requirements.txt
/tmp/emilia-refund-space-venv/bin/python demo.py
```

To test the same folder as a container:

```sh
docker build -t emilia-refund-space .
docker run --rm -p 127.0.0.1:7860:7860 emilia-refund-space
```

After reviewing it, upload the folder to a
[Docker Space](https://huggingface.co/docs/hub/spaces-sdks-docker). The generated
README sets `sdk: docker` and `app_port: 7860`; this also changes an existing
Space to the Docker builder. The app itself is still Gradio. Its managed Gradio
builder installs `requirements.txt` before copying the app, so the included
`./wheels/` paths are not available at that point. The Dockerfile copies those
wheels before installation and verifies every file listed in `SHA256SUMS`.

The container uses the pinned official Python 3.12.14 slim image, a dedicated
virtual environment, and an unprivileged UID 1000. It installs dependencies at
build time and serves on port 7860 without model credentials or runtime package
installation. The local Python commands above remain supported.

Use the included wheels: the adapter requires `emilia-crewai>=0.3.4` and
`emilia-verify>=2.8.4`.
Those source versions include required security fixes and were not yet published
on PyPI when this example was built. No standalone `pip install emilia-smolagents`
release is claimed here.

## Use it in an agent

See [the adapter](../../packages/smolagents/README.md) for `ToolCallingAgent`
setup and host-owned receipt lookup. Receipt data does not become a model-chosen
tool argument. The wrapper preserves the tool's normal result on success.

This local demo uses a fresh software signer and process-local consumption state.
It does not establish a human approval ceremony, persistence across restarts, or
protection from code that calls the provider directly. A production path needs
provider credentials outside the agent runtime and a shared durable atomic store.
Wrapping a tool alone does not provide the full EMILIA authority-account runtime.

The package is an independent EMILIA integration using Hugging Face's
[native tools API](https://huggingface.co/docs/smolagents/tutorials/tools).
[Spaces](https://huggingface.co/docs/hub/spaces-overview) is a distribution option
for this synthetic demo, not the durable execution service.
