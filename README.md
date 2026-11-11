# xks-id

A heuristic intrusion-detection monitor for prompt injection in LLM agent harnesses.

`xks-id` watches the text that enters an agent session from untrusted channels (web pages, files, shell output, tool results) and the tool calls the model makes afterwards. It scores inbound text with deterministic sensors, tracks where each tool-call argument came from, and returns a verdict to the harness: allow, annotate, ask, or deny.

There is no language model in the runtime path. The monitor is a C program that reads JSON on stdin and writes JSON on stdout, so it cannot be persuaded by the text it inspects.

## Status

**Design stage.** No detector code exists yet and nothing has been measured. Every threshold in the documents is a target, and every size is arithmetic from assumed shapes. The design is in [docs/DESIGN.md](docs/DESIGN.md). The stages and their acceptance gates are listed below; a stage counts as done only when its gate has been measured on real hardware and the numbers are recorded in this repository.

## Design at a glance

```
╔══ one host: one Claude Code session; hooks registered in ~/.claude/settings.json ════════════════╗
║ ┌─ decision model ─────┐ weights          ┌─ xksid-distil (offline) ─────┐                       ║
║ │ operator's pick, TBD │─────────────────▶│ token vectors F32 + head     │                       ║
║ │ run offline, once    │                  │ written to dvec.f32          │                       ║
║ └──────────────────────┘                  └──────────────┬───────────────┘                       ║
║                                                          ▼                                       ║
║ ┌─ untrusted inbound ──┐ PostToolUse      ┌─ xksid scan ─────────────────┐    ┌─ ledger ───────┐ ║
║ │ web fetch, search,   │ stdin JSON       │ L0 normalise, decode <= 3    │    │ append-only,   │ ║
║ │ file read, shell     │─────────────────▶│ L1 unicode    L2 structure   │───▶│ on disk:       │ ║
║ │ stdout, MCP tools    │                  │ L3 lexical    L4 anomaly     │    │ taint atoms    │ ║
║ └──────────────────────┘                  │ L5 sinks      L6 dvec -> S   │    │ trust atoms    │ ║
║                                           └──────────────┬───────────────┘    │ T/S/E bits     │ ║
║ model context: rule id + offset + hash, no payload ◀─────┘                    │ canary token   │ ║
║ ┌─ trusted inbound ────┐ UserPromptSubmit ┌─ xksid trust ────────────────┐    │ alert log      │ ║
║ │ operator-typed text  │─────────────────▶│ atoms typed by the operator  │───▶│                │ ║
║ │ (pastes are scanned) │                  │ become the trusted set       │    │                │ ║
║ └──────────────────────┘                  └──────────────────────────────┘    │                │ ║
║ ┌─ model tool call ────┐ PreToolUse       ┌─ xksid gate ─────────────────┐    │                │ ║
║ │ shell, file write,   │─────────────────▶│ provenance   sensitivity     │◀───│                │ ║
║ │ network, MCP tools   │                  │ T and S and E   canary       │    │                │ ║
║ └──────────────────────┘                  └──────────────┬───────────────┘    └────────────────┘ ║
║                                                          ▼                                       ║
║                       verdict as stdout JSON: allow | annotate | ask | deny. Kills nothing.      ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
```

Two halves carry the design:

- **Content sensors** score each inbound chunk on seven layers: normalisation and recursive decoding, Unicode smuggling, forged harness structure, lexical co-occurrence, per-channel anomaly, exfiltration sinks, and vectors precalculated from a decision model.
- **Behaviour sensors** judge each outbound tool call: whether its arguments originated in untrusted text, what class of action it is, whether the session has reached the exfiltration state, and whether a canary token is leaving.

Content detection alone cannot bound its false-negative rate against an attacker who rephrases. The behaviour half is what limits the damage of an injection that the content half missed.

## Scope

Defensive only. The repository contains a monitor and its tooling. It contains no attack tooling, and it ships no payload corpus: evaluation data is downloaded into `input/`, which is ignored by git.

`xks-id` is self-contained. It shares no code with any other project and depends on the C library only.

## Layout

| Path | Content |
|---|---|
| `docs/DESIGN.md` | The full design: threat model, sensors, verdicts, limits, stages |
| `docs/diagram.spec` | Source of the diagram above |
| `docs/diagram.txt` | Generated diagram, 24 lines, each 100 characters wide |
| `tools/boxgen.awk` | Diagram generator with a per-field width check |
| `src/` | C sources (none yet) and `compile_flags.txt` |
| `input/` | Model weights and evaluation corpora, read-only copies with checksums; not in git |
| `out/` | Build products and measurement output; not in git |

Regenerate the diagram:

```
LC_ALL=C.UTF-8 awk -f tools/boxgen.awk docs/diagram.spec > docs/diagram.txt
```

## Stages

| Stage | Content | Acceptance gate |
|---|---|---|
| G0 | Logging-only hook probe | The real stdin JSON of each hook is recorded; the channels each hook can see are listed |
| G1 | Layers L0 to L5, log-only | False-positive rate on benign tool output; latency p50 and p99 per hook call |
| G2 | `xksid-distil`, layer L6, fitted weights | True-positive rate at the G1 false-positive rate on held-out corpora; L6 beats its two baselines or is removed |
| G3 | Ledger, provenance, gate in ask-only mode | Asks per 1,000 tool calls on real sessions |
| G4 | Deny mode, persistence guard | Canary and exfiltration drills blocked; no false denial over a recorded week |

## Licence

MIT. See [LICENSE](LICENSE).
