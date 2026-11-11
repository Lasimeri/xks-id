# xks-id

A heuristic intrusion-detection monitor for prompt injection in AI agent harnesses. It works from the memories that [XKS-Memory](https://github.com/Lasimeri/XKS-Memory) records.

XKS-Memory logs every turn of the agent harnesses it is attached to, Claude Code and omp among them: what the operator typed, what the model answered, every tool call and every tool result. `xks-id` reads those recorded turns and checks them for prompt injection: text that arrived as data (a web page, a file, shell output, a tool result) and was then acted on as if it were an instruction.

`xks-id` does not modify XKS-Memory. It adds no patch, no plugin and no hook, it never opens the XKS-Memory store, and it writes nothing under the XKS-Memory directory. It only reads the session files XKS-Memory already writes. One detector therefore covers every harness XKS-Memory records, with nothing installed inside any of them.

## Status

**Design stage.** No detector code exists yet. Thresholds in the documents are targets, not measurements. One fact about the input has been checked on real session files: in 40 turn files of each harness (80 in total), the 8 hexadecimal digits in the file name equal the first 8 digits of the SHA-256 of the file's content.

[docs/DESIGN.md](docs/DESIGN.md) holds the sensors and their reasoning. It was written for an earlier deployment inside a single harness session and is being reworked to the deployment described here; its sensor sections stand, its hook and verdict sections do not.

## What it reads

XKS-Memory stores each turn as one file. The layout below is XKS-Memory's, documented in its `docs/AGENTS_INTEGRATION.md`.

| Item | Form |
|---|---|
| Root | `$XKSM_HOME`, else `~/XKS-memories` |
| Session directory | `ROOT/HARNESS/YYYY-MM-DD_HHMMSS_SESSION/` |
| Turn file | `YYYY-MM-DD_HH-MM-SS.mmm_ROLE_SHA8.md`: a header line (time, role, session), then the text |
| Harness | `claude-code`, `omp`, or any other name given to XKS-Memory |
| Role | `user`, `assistant`, `note`, `tool_use`, `tool_result`, `thinking` |

The role in the file name is what makes the monitor possible: the untrusted channel, the trusted channel and the model's actions arrive already separated.

| Role | What `xks-id` does with it |
|---|---|
| `tool_result` | Untrusted inbound text. Scored by the content sensors; its atoms (hosts, URLs, paths, addresses, shell tokens) enter the taint set. |
| `user` | Operator text. Its atoms enter the trust set. Pasted blocks are scored like any other inbound text and are not trusted. |
| `tool_use` | The model's actions: tool name and rendered input. Judged by the behaviour sensors. |
| `assistant`, `thinking` | Scanned for exfiltration sinks and for the canary token. Never a source of trust. |
| `note` | Scored as untrusted. A stored note is replayed into later sessions, so it is the persistence channel. |

## Design at a glance

```
╔══ one host: XKS-Memory records the harnesses, xksid reads what it recorded ══════════════════════╗
║ ┌─ agent harnesses ────┐ every turn       ┌─ XKS-Memory, unmodified ─────┐                       ║
║ │ Claude Code, omp     │─────────────────▶│ its hooks and omp extension  │                       ║
║ │                      │                  │ store each turn as one file  │                       ║
║ └──────────────────────┘                  └──────────────┬───────────────┘                       ║
║                                                          ▼                                       ║
║       ROOT/HARNESS/SESSION/TIME_ROLE_SHA8.md, one file per turn: read by xksid, never written    ║
║ ┌─ decision model ─────┐ llama.cpp        ┌─ xksid-distil (offline) ─────┐                       ║
║ │ LiquidAI d1-2B BF16  │─────────────────▶│ token vectors F32 + head     │                       ║
║ │ run offline, once    │                  │ written to dvec.f32          │                       ║
║ └──────────────────────┘                  └──────────────┬───────────────┘                       ║
║                                                          ▼                                       ║
║ ┌─ tool_result files ──┐ read-only        ┌─ content sensors ────────────┐    ┌─ ledger ───────┐ ║
║ │ untrusted: web, file,│                  │ L0 normalise, decode <= 3    │    │ xksid's own,   │ ║
║ │ shell and MCP output │─────────────────▶│ L1 unicode    L2 structure   │───▶│ outside ROOT:  │ ║
║ │ up to 65,536 B each  │                  │ L3 lexical    L4 anomaly     │    │ file cursor    │ ║
║ └──────────────────────┘                  │ L5 sinks      L6 dvec -> S   │    │ taint atoms    │ ║
║                                           └──────────────────────────────┘    │ trust atoms    │ ║
║ ┌─ user files ─────────┐ read-only        ┌─ trust set ──────────────────┐    │ T/S/E bits     │ ║
║ │ operator-typed text  │─────────────────▶│ atoms typed by the operator  │───▶│ canary token   │ ║
║ │ (pastes are scanned) │                  │ become the trusted set       │    │ alert log      │ ║
║ └──────────────────────┘                  └──────────────────────────────┘    │                │ ║
║ ┌─ tool_use files ─────┐ read-only        ┌─ behaviour sensors ──────────┐    │                │ ║
║ │ tool name and its    │─────────────────▶│ provenance   sensitivity     │◀───│                │ ║
║ │ rendered input       │                  │ T and S and E   canary       │    │                │ ║
║ └──────────────────────┘                  └──────────────┬───────────────┘    └────────────────┘ ║
║                                                          ▼                                       ║
║               alerts: session, turn file, rule ids, severity. xksid blocks nothing.              ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
```

Two halves carry the design.

- **Content sensors** score each untrusted turn on seven layers: normalisation and recursive decoding, Unicode smuggling, forged harness structure, lexical co-occurrence, per-channel anomaly, exfiltration sinks, and vectors precalculated from a decision model.
- **Behaviour sensors** judge each recorded tool call: whether its arguments first appeared in untrusted text and never in operator text, what class of action it is (secret read, network egress, persistence, destruction), whether the session has reached the exfiltration state (untrusted content in, secret read, egress attempted), and whether a canary token left.

Content detection alone cannot bound its false-negative rate against an attacker who rephrases. The behaviour half is what catches an injection the content half missed, because it looks at what the model did, not at how the injected text was worded.

There is no language model in the detection path. The detector is deterministic C, so the text it inspects cannot persuade it. The decision model (LiquidAI d1-2B, BF16 GGUF) is run once, offline, through llama.cpp; only the table of vectors it produces is used afterwards.

## What it cannot do

- **It detects, it does not prevent.** A turn is visible only after XKS-Memory has stored it. `xks-id` cannot stop a tool call; it reports that one happened.
- **It sees what XKS-Memory records, and nothing else.** By XKS-Memory's defaults that excludes harness plumbing (system reminders, sidechains), the part of a tool result past 65,536 bytes per block, anything logged while a harness is paused, and everything if the session files are turned off (`XKSM_MIRROR=0`).
- **Text inside images** is not read.
- **Injection without markers.** A false statement with no instruction in it passes the content sensors.
- **Steered actions without tainted arguments.** If an injected instruction leads to an action whose arguments the operator had already typed, provenance sees nothing; only the action class and the session state remain.

## Scope

Defensive only. The repository holds a monitor and its tooling. It contains no attack tooling and ships no payload corpus: evaluation data is downloaded into `input/`, which git ignores. Session files are personal data and never enter the repository.

`xks-id` shares no code with XKS-Memory. The detector depends on the C library only. The offline distiller additionally links llama.cpp.

## Layout

| Path | Content |
|---|---|
| `docs/DESIGN.md` | Threat model, sensors, limits |
| `docs/diagram.spec` | Source of the diagram above |
| `docs/diagram.txt` | Generated diagram, 29 lines, each 100 characters wide |
| `tools/boxgen.awk` | Diagram generator with a per-field width check |
| `src/` | Sources and `compile_flags.txt` |
| `input/` | Model weights and evaluation corpora, with checksums; not in git |
| `out/` | Build products and measurement output; not in git |

Regenerate the diagram:

```
LC_ALL=C.UTF-8 awk -f tools/boxgen.awk docs/diagram.spec > docs/diagram.txt
```

## Stages

| Stage | Content | Acceptance gate |
|---|---|---|
| G0 | Reader: walk the session trees of both harnesses, parse every turn file, check every file-name hash | Turn counts per harness and role match XKS-Memory's own session registry; hash mismatches reported |
| G1 | Content layers L0 to L5 on recorded `tool_result` turns, log-only | False-positive rate on real recorded sessions; turns scanned per second |
| G2 | `xksid-distil`, layer L6, fitted weights | True-positive rate at the G1 false-positive rate on held-out corpora; L6 beats its two baselines or is removed |
| G3 | Ledger, provenance and action classes over recorded `tool_use` turns | Alerts per 1,000 tool calls on real recorded sessions |
| G4 | Watch mode: alert as new turn files appear | Canary and exfiltration drills raise an alert; delay from turn file to alert measured |

## Licence

MIT. See [LICENSE](LICENSE).
