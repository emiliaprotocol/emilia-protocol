# COSA Architecture & Continuum Boot Protocol Specification

> **Public Architectural Specification & Marketecture Blueprint**  
> **Repository:** `emilia-protocol` / `emilia-mailbox` / `jdiesel-continuum`  
> **Status:** Live Specification (COSA v1.2)  

---

## 1. Executive Summary & Marketecture Overview

The **Cognitive Open System Architecture (COSA)** and **Continuum Boot Protocol** define an open, provider-agnostic framework for building **Nomadic AI Agents**. 

Unlike legacy AI architectures that lock agent memory, state, and identity inside proprietary cloud vendors or monolithic vector databases, COSA decouples the AI system into four independent, interchangeable tiers:

```mermaid
flowchart TD
    subgraph TIER1["Tier 1: Physical Edge Interface (Hardware Gateways)"]
        A1["AiPi Smart Home Terminal\n(Microcontroller / Voice I/O)"]
        A2["Mobile Voice Gateway\n(Gemini / Web Bridge)"]
        A3["Bluetooth Car Terminal\n(Audio Stream)"]
    end

    subgraph TIER2["Tier 2: Home Base / Local Mediator (PC / VM)"]
        B1["Dynamic Pre-Boot Compiler\n(10ms Variable Substitution)"]
        B2["Whisper STT / Voice Buffer\n(Audio -> Text)"]
        B3["TTS Audio Synthesizer\n(Text -> Audio Stream)"]
    end

    subgraph TIER3["Tier 3: Cognitive Model Engines (Pluggable Intelligence)"]
        C1["Anthropic Claude 3.5\n(Complex Code & XML)"]
        C2["Google Gemini 3.5\n(Fast Conversational Audio)"]
        C3["Microsoft Copilot\n(Office / M365 Automation)"]
        C4["Local vLLM / Ollama\n(Private On-Premise GPU)"]
    end

    subgraph TIER4["Tier 4: Nomadic Memory Vault (Git-Tracked Substrate)"]
        D1["Layer 1: Identity & Persona"]
        D2["Layer 2: Operations & Actuators"]
        D3["Layer 3: Tactical Roadmap"]
        D4["Layer 4: Session & Handoffs"]
    end

    TIER1 <== "1. Voice Audio & Device Profile" ==> TIER2
    TIER2 <== "2. Somatic Context Hydration" ==> TIER4
    TIER2 <== "3. Compiled Prompt Stream" ==> TIER3
    TIER3 -- "4. Response & Tool Calls" --> TIER2
```

### Key Engineering Principles
* **Nomadic Identity:** An agent (e.g., *Agent Smith*) retains a continuous, unified identity across all hardware terminals, workstations, and cloud VMs.
* **Provider Independence:** Switch between Claude, Gemini, GPT, Copilot, or local open-weights LLMs without losing context, state, or identity.
* **Device-Aware Tiering:** Automatically scale cognitive payloads and UI outputs based on whether the active container is a lightweight edge node (`LEAN_AGENT`) or a full workstation (`FAT_AGENT`).
* **Cryptographic Verification:** Inter-agent communication and multi-device handoffs use signed, content-addressed envelopes backed by `emilia-mailbox`.

---

## 2. The 4-Layer Context Matrix

Continuum structures agent context into four distinct layers. Each layer uses dynamic Markdown templates with embedded `${VARIABLE}` tokens compiled at boot:

| Layer | Type | Storage | Contents & Dynamic Substitutions | Operational Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 1: Identity** | Core | Git-Tracked | Dynamic Persona, `${DEVICE_ID}`, `${COMPUTE_TIER}`, `${ACTIVE_MODEL}` | Universal |
| **Layer 2: Operations** | Functional | Git-Tracked | Tool Definitions, Local Actuator Bindings (`${CONNECTED_PERIPHERALS}`) | Device-Aware |
| **Layer 3: Roadmap** | Tactical | Git-Tracked | Active Milestones, Project Backlog, Verification Targets | Project-Wide |
| **Layer 4: Session** | Volatile | Ephemeral / Git | Turn State, Ritual Logs, Pending Handoff Envelopes | Session-Bound |

---

## 3. Dynamic Pre-Boot Compiler & Model Adapters (`.agents/adapters/`)

Before any prompt is dispatched to a background LLM, the local Home Base Mediator runs a **10-millisecond Pre-Boot Compiler**. 

The compiler dynamically hydrates variable placeholders inside the Layer files and appends the exact **Model Adapter** corresponding to the selected AI engine:

```mermaid
flowchart LR
    L["Raw Layer Templates\n(layer_1_identity.md)"] --> C["Pre-Boot Compiler\n(10ms Execution)"]
    V["Device & Telemetry Vars\n(${DEVICE_ID}, ${COMPUTE_TIER})"] --> C
    A["Model Adapter\n(.agents/adapters/*_adapter.md)"] --> C
    C ==> P["Target Prompt Stream\n(Sent to LLM)"]
```

### Model Adapter Architecture

Different LLM architectures have distinct behavioral strengths and prompt sensitivities. The `.agents/adapters/` directory fine-tunes operational rules per model:

```
.agents/adapters/
├── claude_adapter.md       # Enforces XML tag parsing (<thinking>) & precise code diffs
├── gemini_adapter.md       # Optimizes for fast audio flow & structured JSON tool calls
├── copilot_adapter.md      # Binds M365 Graph API, Word, & Outlook automation rules
└── local_vllm_adapter.md   # Tight context budgeting & raw Markdown stop tokens
```

---

## 4. Hardware-Aware Edge vs. Workstation Tiering

COSA classifies all connected hardware containers into distinct **Compute Tiers**:

```mermaid
stateDiagram-v2
    [*] --> BootContinuum: Device Pings Mediator
    
    state BootContinuum {
        [*] --> CheckComputeTier
        CheckComputeTier --> LeanAgent: compute_tier == "LEAN_AGENT"
        CheckComputeTier --> FatAgent: compute_tier == "FAT_AGENT"
        
        state LeanAgent {
            [*] --> VoiceAudioResponse: Max 100 Words Audio TTS
            [*] --> WriteHandoffPending: Draft HANDOFF_PENDING.md for Complex Tasks
        }
        
        state FatAgent {
            [*] --> FullCodebaseScan: Multi-File Editing & Refactoring
            [*] --> ExecuteIntake: Auto-Consume HANDOFF_PENDING.md
        }
    }
```

### Tier Comparison Matrix

| Feature | `LEAN_AGENT` (Edge Node / AiPi / Mobile) | `FAT_AGENT` (Workstation / Antigravity IDE) |
| :--- | :--- | :--- |
| **Primary Container** | AiPi Board, Mobile Voice Bridge, Car Terminal | Workstation Laptop, Cloud VM, Antigravity IDE |
| **Interaction Mode** | Conversational Audio (TTS/STT), Hardware Button | Text, Multi-File Code Editor, Terminal Shell |
| **Response Constraint** | Concise audio responses (under 100 words) | Full code diffs, architecture diagrams, build logs |
| **Complex Task Strategy** | Drafts structured `HANDOFF_PENDING.md` envelope | Consumes handoff, executes build/tests, updates state |

---

## 5. Cryptographic Handoff & Mailbox Seam (`emilia-mailbox`)

When an agent running on one device or model needs to delegate a task to a specialized clone on another device (e.g., a Gemini voice session delegating a mail-merge task to a Copilot clone), the handoff is serialized and signed via **`emilia-mailbox`**:

```mermaid
sequenceDiagram
    autonumber
    actor User as User (Voice on Road)
    participant Gemini as Agent Smith (Gemini / LEAN_AGENT)
    participant Mailbox as emilia-mailbox (Signed Inbox)
    participant Copilot as Agent Smith (Copilot Clone / FAT_AGENT)

    User->>Gemini: "Process that mail-merge in Outlook"
    Gemini->>Gemini: Scopes architecture & generates signed handoff payload
    Gemini->>Mailbox: Posts signed envelope (to: "ep:agent:copilot-clone", nonce: "nonce_9918")
    Gemini-->>User: "Handoff signed & posted to Copilot inbox. Ready for model switch."

    Note over User, Copilot: User switches session to Copilot...

    Copilot->>Mailbox: Boot Continuum & check inbox
    Mailbox-->>Copilot: Delivers verified handoff envelope
    Copilot->>Copilot: Verifies Ed25519 signature & consumes nonce
    Copilot-->>User: Executes mail-merge and confirms completion
```

---

© 2026 COSA Protocol Community · Published under Apache-2.0
