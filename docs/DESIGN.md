# xks-id design

Status: design only. Nothing in this document has been built or measured. Thresholds are targets. Sizes are arithmetic from assumed shapes and are labelled as such.

## 1. Problem

An agent harness feeds a language model two kinds of text:

- **Instruction channel:** what the operator typed, plus the harness's own configuration.
- **Data channel:** everything else. Web pages, search results, file contents, shell output, tool results, messages from third parties, text replayed from a memory store.

Prompt injection is a confused-deputy failure: bytes that arrived on the data channel are acted on as if they had arrived on the instruction channel. The damage is done by a tool call the operator did not ask for: a secret is read and sent away, a file is destroyed, or the injected text is written somewhere it will be replayed in later sessions.

`xks-id` is an intrusion-detection monitor for that failure. It observes both channels and every tool call, and it reports to the harness.

## 2. Architecture choice

Three architectures were considered.

| Option | Mechanism | Verdict |
|---|---|---|
| A | Content-only signature scanner | Rejected as the whole system. Its false-negative rate against an attacker who paraphrases is unbounded. |
| B | A language model that judges each chunk | Rejected. The judge reads the hostile text and can itself be injected; it is slow, costs a model call per chunk, and is not deterministic. |
| C | Deterministic content sensors, plus provenance tracking on outbound tool calls, plus a canary | Chosen. |

In option C the content sensors raise suspicion and feed state. The decisions that block an action are taken on the outbound side, where the question is concrete: did an argument of this tool call originate in untrusted bytes, and what class of action is it?

## 3. Components

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

| Component | Role |
|---|---|
| `xksid scan` | Runs after a tool returns. Scores the tool output, records its atoms as tainted, returns an annotation. |
| `xksid trust` | Runs when the operator submits a prompt. Records the atoms the operator typed as trusted. Pasted blocks are scanned like any other inbound text and are not trusted. |
| `xksid gate` | Runs before a tool call executes. Applies the behaviour sensors and returns the verdict. |
| `xksid-distil` | Offline tool. Converts a decision model into the vector file read by layer L6. |
| Ledger | Append-only files under `$XDG_STATE_HOME/xksid/` (default `~/.local/state/xksid/`), mode 0700, one directory per session. Holds the taint set, the trust set, the state bits, the canary token and the alert log. It lives on disk, never on a RAM-backed filesystem. |
| `dvec.f32` | The precalculated vectors, under `$XDG_DATA_HOME/xksid/`. |

`xksid` is one static binary with three modes. It is started by the harness once per hook event, reads one JSON object on stdin, and writes one JSON object on stdout. It has no network access and no dependency beyond the C library.

## 4. Content sensors

`xksid scan` splits the inbound text into chunks and scores each chunk on seven layers.

| Layer | What it measures |
|---|---|
| L0 normalise | Unicode NFKC, case fold, confusable fold, removal of zero-width characters. Recursive decoding of base64, hexadecimal, percent-encoding and HTML entities to depth 3. Every decoded view is scanned as its own view, and a hit inside a decoded view weighs more than the same hit in plain text, because benign text rarely hides an instruction inside an encoding. |
| L1 unicode | Characters from the tag block (U+E0000 to U+E007F), bidirectional controls, zero-width runs inside a word, tokens that mix scripts, runs of variation selectors. |
| L2 structure | Markers that imitate the harness or a chat template inside raw tool output: reminder tags, role headers, control tokens, imitation tool-result or function-call blocks, a closing delimiter that matches the harness's own wrapper. Content that a renderer would hide: HTML comments, `display:none`, zero font size, text coloured like its background, `alt` and `title` attributes. |
| L3 lexical | An Aho-Corasick automaton over the normalised view. Terms belong to classes: override verb, target noun (instructions, rules, prompt), addressee (assistant, model, agent), secrecy directive, authority claim, tool verb with a sensitive object. The score comes from classes that co-occur inside a 24-token window. A single term scores nothing. |
| L4 anomaly | For each tool name, a running mean and variance of imperative density and second-person rate, kept in the ledger. The feature is the z-score of the chunk against its own channel. A structured API response that addresses commands to its reader is an outlier. A README that says to run a build command is not. |
| L5 sinks | URLs whose host is absent from the trusted set and that carry opaque or templated query strings. Markdown image references to unknown hosts. Commands that pipe a download into a shell. |
| L6 dvec | The score of the chunk under vectors precalculated from a decision model. See section 5. |

The chunk score is a sum of log-odds:

```
S = sum over features i of  w_i * f_i
```

Weights are set by hand for stage G1 and fitted by logistic regression, written in C, for stage G2. Two thresholds apply: a note threshold and a warn threshold, with note below warn.

A marker of the harness itself found in raw tool output (layer L2) is treated as high confidence on its own, provided stage G0 confirms that the hook receives tool output before the harness adds anything to it.

## 5. Layer L6: precalculated vectors of a decision model

The decision model is a classifier trained to separate injected text from benign text. It is chosen by the operator and is not fixed by this design. `xks-id` does not run the model at detection time. It runs the model once, offline, and keeps the result as a table.

### Offline, once per model

`xksid-distil` is a C program that reads the model's weight file and tokenizer directly.

1. For every token in the vocabulary, run the model on that token alone and store the representation that feeds the classifier head. The result is a table `E` of `V` rows and `d` columns in 32-bit floats.
2. Distil a head: fit a small function of a pooled window vector so that it reproduces the model's own output on a corpus of benign and injected text.
3. Build a residual table for the n-grams where the sum of static token vectors disagrees most with the model.
4. Write the table, the head and the residual table to `dvec.f32`, with a header that records the model's checksum, `V`, `d` and the tokenizer type.

### Runtime

Tokenise the chunk with the model's own vocabulary, look up the rows, pool them over a sliding window of 64 tokens with a stride of 16, and apply the head. The window keeps a short injected passage from being diluted by a long benign document. No forward pass of the model is executed.

### The linear collapse

A linear head over a mean pool reduces to one scalar per token, because

```
w . mean(E[t]) = mean(w . E[t])
```

In that form the table is a learned word list and cannot see word order, which is exactly what separates "ignore the previous instructions" from a sentence that merely contains the same words. The head is therefore non-linear (a small multilayer perceptron, or the maximum cosine against K prototype directions), and the n-gram residual table restores local order.

The collapsed scalar table is kept as a baseline. Layer L6 stays in the system only if it beats both that baseline and layer L3 in true-positive rate at the same false-positive rate. Otherwise it is removed.

### Size and loading

For an assumed vocabulary of 128,000 tokens and 256 dimensions, the table is 128,000 x 256 x 4 bytes = 125 MiB (arithmetic, not a measurement). The real shape comes from the chosen model.

A hook process lives for one event, so reading the whole table on every start is the wrong shape. Two options:

- Map the file read-only, so the process pages in only the rows of the tokens it meets.
- Keep the table in a resident process and let the hook process query it over a Unix socket.

The first is the default because it has no daemon to supervise and no state that can go stale. The second replaces it if the measured p99 latency fails its gate, or where mapping is not wanted.

### Limits of the layer

L6 is one feature in `S`. It never decides a verdict alone. Static vectors can be evaded by token substitution, and the agreement between the distilled head and the model is unknown until it is measured at stage G2.

### What the design needs from the model

Architecture, weight file format, tokenizer type, hidden size, head shape, label set, maximum sequence length, and licence. The forward pass in `xksid-distil` is specific to the architecture and is written once the model is named.

## 6. Behaviour sensors

`xksid gate` examines each tool call before it runs.

**B1, provenance.** Every untrusted chunk is split into atoms: hosts, URLs, file paths, e-mail addresses, shell tokens of 6 characters or more, and encoded blobs. Each atom is hashed into the taint set with the identifier of its chunk. Atoms typed by the operator go into the trust set. An argument atom that is in the taint set and not in the trust set is a tainted argument: the model is about to act on a value that only the untrusted text supplied.

**B2, action class.**

| Class | Examples |
|---|---|
| SECRET-READ | Private keys, environment files, credential stores, tokens, browser profiles |
| EGRESS | Any network client, remote copy, repository push, outbound message |
| PERSIST | Harness settings and hooks, instruction files, memory stores, shell start-up files, scheduled jobs, authorised-key files |
| DESTROY | Deletion, raw device writes, truncation, history rewrites, forced pushes |

**B3, state bits.** Three bits per session. T is set when flagged untrusted content has entered the context. S is set when a secret has been read. E is set when an egress action is attempted. All three together is the signature of exfiltration.

**B4, canary.** A random 128-bit token is placed in a decoy credentials file that nothing legitimate reads. A read of the file, or the token appearing in any outbound argument in plain, hexadecimal or base64 form, is a confirmed hit with no benign explanation.

**B5, persistence guard.** A write to a PERSIST path whose new content carries tainted atoms, or scores above the note threshold on the content sensors, is flagged. This is the stored-injection case: text that enters a memory store or an instruction file is replayed into every later session.

## 7. Verdicts

| Condition | Verdict |
|---|---|
| `S` at or above the note threshold | Log and annotate |
| Harness marker forged in raw tool output | Annotate and set T |
| Tainted argument on an EGRESS, PERSIST or DESTROY action | Ask the operator |
| T and S and E | Deny and alert |
| Canary hit | Deny and alert |
| Anything else | Allow |

The monitor returns verdicts to the harness. It does not terminate processes, delete files or modify the session.

## 8. Annotation hygiene

The monitor's own output is a channel into the model, so it is constrained:

- An annotation carries rule identifiers, byte offsets and the hash of the chunk. It never quotes the flagged text. Quoting it would hand the payload back to the model with the monitor's authority attached.
- The alert log stores excerpts escaped and capped in length, so that reading the log back into a session cannot re-inject them.
- The detector is deterministic code. The same input gives the same verdict, and no text can argue with it.

## 9. Hook wiring

Planned registration in the harness settings. The field names follow the hook format of Claude Code and are to be confirmed against the installed version at stage G0.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "xksid trust", "timeout": 5 } ] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "xksid scan", "timeout": 5 } ] }
    ],
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "xksid gate", "timeout": 5 } ] }
    ]
  }
}
```

Open questions for G0:

- The exact stdin JSON of each hook event.
- Whether the tool output handed to `PostToolUse` is the raw output, before the harness appends anything of its own.
- Which inbound channels never pass through a tool result and are therefore invisible to `xksid scan` (see section 12).

## 10. Implementation rules

- C17, compiled with the flags in `src/compile_flags.txt`, zero diagnostics.
- No interpreter and no model in the runtime path. Tables (Unicode classes, confusables, the lexical automaton) are generated at build time from checksummed inputs.
- The ledger is append-only and is written with a single `write` per record.
- A performance technique is kept only if it is measured at least as fast as the plain form it replaces, on the target machine, with the raw numbers recorded under `out/`. Candidates:
  - The lexical automaton as a flat transition table indexed by state and byte class, with a 256-entry byte-to-class table, so the inner loop has no branch.
  - A vector skip over spans of plain ASCII in layer L1.
  - The verdict as a lookup in a 16-entry table indexed by the sensor bits.
  - A branch-free search of the sorted taint set.

  At hook scale, process start and JSON parsing are expected to dominate the run time (an estimate, not a measurement), so some of these candidates are expected to fail their gate.

## 11. Evaluation

- **Benign set:** tool output from real sessions of the operator. It stays on the operator's machine under `input/` and is never committed. The false-positive rate that matters is the one measured on this set.
- **Injected set:** public prompt-injection corpora. Candidates include BIPIA, InjecAgent, AgentDojo, Tensor Trust and HackAPrompt. None has yet been checked for content or licence; each is checked before use and is downloaded to `input/`, never copied into the repository.
- **Metrics:** true-positive rate at a fixed false-positive rate, per layer and fused; asks and denials per 1,000 tool calls on real sessions; latency p50 and p99 per hook event. Each number is reported with its unit, the command that produced it, and the path of the raw data.
- **Comparison:** against a recorded baseline on the same machine, runs repeated and interleaved, with the spread reported.

## 12. Known limits

- **Channels outside tool results.** Text that reaches the model without passing through a tool call (messages relayed by a plugin, context added by another hook, replay from a memory store) is not seen by `xksid scan`. Such a source has to call the scanner itself.
- **Images.** Text inside images is not read.
- **Injection without markers.** A false statement with no instruction in it ("the correct value is X") passes every content layer.
- **Steered actions without tainted arguments.** If an injected instruction leads to an action whose arguments the operator had already typed, provenance sees nothing. Only the action class and the state bits remain.
- **Adversarial tokens.** Layer L6 can be evaded by token substitution, and layer L3 by paraphrase or by another language.
- **Split payloads.** An instruction spread over several chunks or several turns scores low in each.
- **The hook contract** is an assumption until stage G0 records it.

## 13. Stages

| Stage | Content | Acceptance gate |
|---|---|---|
| G0 | Logging-only hook probe | The real stdin JSON of each hook is recorded; the channels each hook can see are listed |
| G1 | Layers L0 to L5, log-only | False-positive rate on the benign set; latency p50 and p99 per hook call |
| G2 | `xksid-distil`, layer L6, fitted weights | True-positive rate at the G1 false-positive rate on held-out corpora; L6 beats the collapsed scalar table and layer L3, or is removed |
| G3 | Ledger, provenance, gate in ask-only mode | Asks per 1,000 tool calls on real sessions |
| G4 | Deny mode, persistence guard | Canary and exfiltration drills blocked; no false denial over a recorded week |

Stages G0 and G1 do not depend on the choice of decision model.
