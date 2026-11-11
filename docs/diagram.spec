TITLE@one host: one Claude Code session; hooks registered in ~/.claude/settings.json
┌─ decision model ─────┐@ weights          @┌─ xksid-distil (offline) ─────┐@@
│ operator's pick, TBD │@─────────────────▶@│ token vectors F32 + head     │@@
│ run offline, once    │@@│ written to dvec.f32          │@@
└──────────────────────┘@@└──────────────┬───────────────┘@@
RAW@{57}▼@
┌─ untrusted inbound ──┐@ PostToolUse      @┌─ xksid scan ─────────────────┐@@┌─ ledger ───────┐
│ web fetch, search,   │@ stdin JSON       @│ L0 normalise, decode <= 3    │@@│ append-only,   │
│ file read, shell     │@─────────────────▶@│ L1 unicode    L2 structure   │@───▶@│ on disk:       │
│ stdout, MCP tools    │@@│ L3 lexical    L4 anomaly     │@@│ taint atoms    │
└──────────────────────┘@@│ L5 sinks      L6 dvec -> S   │@@│ trust atoms    │
@@└──────────────┬───────────────┘@@│ T/S/E bits     │
RAW@model context: rule id + offset + hash, no payload ◀─────┘@│ canary token   │
┌─ trusted inbound ────┐@ UserPromptSubmit @┌─ xksid trust ────────────────┐@@│ alert log      │
│ operator-typed text  │@─────────────────▶@│ atoms typed by the operator  │@───▶@│                │
│ (pastes are scanned) │@@│ become the trusted set       │@@│                │
└──────────────────────┘@@└──────────────────────────────┘@@│                │
┌─ model tool call ────┐@ PreToolUse       @┌─ xksid gate ─────────────────┐@@│                │
│ shell, file write,   │@─────────────────▶@│ provenance   sensitivity     │@◀───@│                │
│ network, MCP tools   │@@│ T and S and E   canary       │@@│                │
└──────────────────────┘@@└──────────────┬───────────────┘@@└────────────────┘
RAW@{57}▼@
RAW@{22}verdict as stdout JSON: allow | annotate | ask | deny. Kills nothing.@
