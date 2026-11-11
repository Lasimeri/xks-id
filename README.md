# xks-id

A heuristic intrusion-detection engine for prompt injection in AI agent harnesses. It works from the turns that [XKS-Memory](https://github.com/Lasimeri/XKS-Memory) records.

XKS-Memory logs every turn of the harnesses it is attached to (Claude Code, omp, and any other): what the operator typed, what the model answered, every tool call and every tool result. `xks-id` reads those recorded turns all day, flags tool output that reads like instructions to the model, tells the model which turns of its own session were flagged so it can correct itself, and shows the operator everything in a terminal interface.

XKS-Memory is not modified. `xks-id` never opens its store and writes nothing under its directory. No language model runs at detection time and no GPU is needed: the engine is deterministic C on the CPU.

## How it works

```
╔══ one host, no GPU at run time: XKS-Memory records, xksid reads, the model is told ══════════════╗
║ ┌─ agent harnesses ────┐ every turn       ┌─ XKS-Memory, unmodified ─────┐                       ║
║ │ Claude Code, omp     │─────────────────▶│ stores each turn as one file │                       ║
║ └──────────────────────┘                  └──────────────────────────────┘                       ║
║ ┌─ decision model ─────┐ once, offline    ┌─ xksid-distil, xksid-fit ────┐                       ║
║ │ LiquidAI d1-2B BF16  │─────────────────▶│ table 128,000 x 2,048 F32,   │                       ║
║ │ never run again      │                  │ tokenizer bundle, head       │                       ║
║ └──────────────────────┘                  └──────────────┬───────────────┘                       ║
║                                                          ▼                                       ║
║ ┌─ turn files ─────────┐ read-only, 2 s   ┌─ xksid watch, all day ───────┐    ┌─ state ────────┐ ║
║ │ ROOT/HARNESS/SESSION │─────────────────▶│ 30 rules: hidden characters, │───▶│ alerts.tsv     │ ║
║ │ TIME_ROLE_SHA8.md    │                  │ structure, wording, encodings│    │ stats, sessions│ ║
║ │ tool_result = data   │                  │ vectors on the CPU: AVX2+FMA │    │ l6.cut, benign │ ║
║ └──────────────────────┘                  └──────────────────────────────┘    │ suppressed.tsv │ ║
║ ┌─ the observed model ─┐ notice           ┌─ xksid hook ─────────────────┐    │ delivered.txt  │ ║
║ │ told at its next     │◀─────────────────│ flagged turns of the session │◀───│                │ ║
║ │ hook event           │                  │ rule ids, never the text     │    │                │ ║
║ └──────────────────────┘                  └──────────────────────────────┘    │                │ ║
║ ┌─ operator ───────────┐ terminal         ┌─ xksid-tui (Rust, std only) ─┐    │                │ ║
║ │ desktop notification │◀─────────────────│ alerts, sessions, statistics │◀───│                │ ║
║ │ acknowledge, feedback│                  │ feedback -> xksid feedback   │    │                │ ║
║ └──────────────────────┘                  └──────────────────────────────┘    └────────────────┘ ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
```

- **The engine** (`xksid watch`) reads each new turn file once. A tool result is data: if it reads like instructions, that is the finding. The engine does not judge intent.
- **Two sensors score a turn.** Thirty deterministic rules cover the documented injection methods ([docs/METHODS.md](docs/METHODS.md)). Optionally, a table of vectors precalculated from a decision model scores the same text on the CPU; the model itself is never run again.
- **The model is told.** A thin hook in each harness asks the engine for the flagged turns of the running session and puts a notice into the model's context: which turns, which rules, and the order to treat that content as data, re-check what it did since, and tell the user. The notice never repeats the flagged text.
- **The operator sees it** in `xksid-tui` and as a desktop notification, and can acknowledge an alert or mark a turn as a false positive.

## Status

Built and tested. Numbers are from one machine (Ryzen 7 5800X, RTX 3090 Ti used only for the offline table) and the commands and raw outputs are named in [docs/DESIGN.md](docs/DESIGN.md) and [docs/VECTORS.md](docs/VECTORS.md).

| What | Measured |
|---|---|
| Tests (`make check`) | 34 checks pass: one case per documented method, and benign look-alikes that must stay silent |
| Real recorded sessions, rules only | 10,172 turns, 13.2 MB, in 1.187 s (8,566 turns/s), 2.6 MB of memory |
| Real recorded sessions, rules and vectors | 10,180 turns in 1.977 s (5,149 turns/s), 213 MB of memory, 1,951,638 tokens scored |
| Tokenizer against llama.cpp | 4,015 of 4,015 recorded turns identical, 2,150,799 tokens |
| AVX2 + FMA3 kernels against plain C | add 7.17x, dot product 23.31x in cache; 1.91x on table rows, where memory is the limit |
| Vector head against the model, unseen phrasings | AUC 0.9103; at 1 plain window in 100 flagged it catches 53.3 % of the model's yes windows |

Not verified yet, and stated as such:

- **The harness hooks inside a live harness.** `xksid hook` is tested from the command line against real alerts. The Claude Code hook block and the omp extension have not been run inside those programs.
- **The service over days.** `xksid watch` has been run for single scans, not as a long-lived service.
- **The vector head alone is weak at low false-alarm rates** (9.9 % at 1 plain window in 500). It is used as evidence beside the rules and alerts by itself only above a cut calibrated on the operator's own turns.

## Quick start

```
git clone https://github.com/Lasimeri/xks-id && cd xks-id
make && make check
make install
xksid scan          # first pass over everything XKS-Memory has recorded
xksid-tui
```

That runs the rule engine. The steps for the service, the model notice, the vectors and calibration are in [docs/SETUP.md](docs/SETUP.md). The vector files are about 1 GB and are not in this repository; [docs/VECTORS.md](docs/VECTORS.md) describes how they are built and where they go.

Requirements: a C17 compiler and make for the engine; Rust (cargo) for the interface; XKS-Memory with its session files on (the default). Linux.

## What it cannot do

- **It detects, it does not prevent.** A turn is visible after XKS-Memory has stored it. The model learns of a flag at its next hook event, not before its very next action.
- **It sees what XKS-Memory records.** Not recorded, so not seen: harness plumbing, the part of a tool result past XKS-Memory's limit per block (65,536 bytes by default), tool descriptions of MCP servers, anything while logging is paused or the session files are off.
- **Text inside images** is not read.
- **Wording rules are English.** Other languages are covered only by the vector layer.
- **Optimised adversarial strings** and **payloads split across turns** are not detected by the rules.
- **False statements with no instruction in them** pass.

## Scope and privacy

Defensive only: a monitor and its tooling. Recorded sessions are personal data; the engine reads them where they are, its alerts carry rule ids and offsets and never the text, and nothing leaves the machine. Tests use synthetic turns.

## Layout

| Path | Content |
|---|---|
| `src/xksid/` | The engine: reader, rules, tokenizer, vector layer (C17, libc and libm only) |
| `tui/` | The interface (Rust, standard library only) |
| `integrations/` | systemd user unit, Claude Code hook block, omp extension |
| `src/distil/` | Offline tools that build the vector table from a model (link llama.cpp) |
| `tests/` | `make check`: rules, kernels |
| `docs/` | SETUP, METHODS, DESIGN, VECTORS, the diagram and its generator input |
| `tools/boxgen.awk` | Generates `docs/diagram.txt` and rejects a misaligned field |

## Licence

MIT, see [LICENSE](LICENSE). The vector table and the head are derived from LiquidAI d1-2B and fall under that model's licence (LFM Open License v1.0), which travels with them.
