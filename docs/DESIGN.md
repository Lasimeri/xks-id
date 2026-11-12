# xks-id design

Every number below was measured on one machine (Ryzen 7 5800X, 32 GB RAM, Linux) with the command named beside it. Raw outputs are written under `out/`, which is not in git.

## 1. Problem

An agent harness feeds a language model two kinds of text: instructions (what the operator typed, the harness configuration) and data (web pages, files, shell output, tool results). Prompt injection is data that gets acted on as instruction. In an agent, it arrives in a tool result and its goal is a tool call the operator did not ask for.

`xks-id` reports tool output that reads like instructions to the model, and tells the model. It does not decide whether the text was hostile: a tool result that contains instructions aimed at an AI is the finding, whoever wrote it.

## 2. Where it sits

XKS-Memory already records every turn of every harness as one file, with the role in the file name:

```
ROOT/HARNESS/YYYY-MM-DD_HHMMSS_SESSION/YYYY-MM-DD_HH-MM-SS.mmm_ROLE_SHA8.md
```

`ROOT` is `$XKSM_HOME`, else `~/XKS-memories`. The first line of a file is XKS-Memory's header (time, role, session), the rest is the text. `SHA8` is the first 8 hexadecimal digits of the SHA-256 of the file.

Reading those files gives one detector for every harness, with the untrusted channel (`tool_result`, `note`), the operator channel (`user`) and the model's side (`assistant`, `thinking`, `tool_use`) already separated. XKS-Memory is not modified, its SQLite store is never opened, and nothing is written under `ROOT` (the test checks this).

The cost of sitting here: a turn is seen after it is stored. The engine cannot block a tool call.

## 3. Parts

| Part | Language | Role |
|---|---|---|
| `xksid` | C17, libc and libm | `scan`, `watch`, `status`, `rules`, `calibrate`, `feedback`, `hook` |
| `xksid-tui` | Rust, standard library | Reads the state files, runs `xksid` for every action |
| `integrations/` | unit file, JSON, TypeScript | The service; the hooks that deliver the notice |
| `xksid-distil`, `xksid-tokpack`, `xksid-fit` | C++ and C | Offline: build the vector files from a model ([VECTORS.md](VECTORS.md)) |

State, in `$XKSID_STATE`, else `$XDG_STATE_HOME/xksid`, else `~/.local/state/xksid`:

| File | Content |
|---|---|
| `alerts.tsv` | Appended. Detected, harness, session, file, role, score, severity, rule ids, byte offset of the earliest hit, highest vector logit |
| `seen.txt` | Appended. The turn files already read |
| `stats.tsv`, `sessions.tsv` | Counters and per-session totals, rewritten through a rename after each scan |
| `cal.f32` | Appended. The highest vector logit of each scored turn of tool output, in the order of the turns: the calibration |
| `cal.raised` | Sessions in which a turn above the cut has moved it once |
| `l6.cut` | Alert cut and evidence line of the vector layer, taken from `cal.f32` and kept current |
| `cut.tsv` | Appended. One line each time those two levels moved: time, cut, evidence line, turns in the window |
| `benign.f32` | Directions of windows the operator marked as false positives |
| `suppressed.tsv` | Turns held under the cut only by that feedback, with the logit they had |
| `delivered.txt` | Alerts the model has been told about |
| `acked.txt` | Alerts the operator acknowledged (written by the interface) |
| `lock` | Held by a scanning process; a second scanner exits with code 3 |

No file of the state holds text from a turn.

## 4. Reading a turn

1. The file name is parsed; the whole file is hashed and compared with `SHA8`. A mismatch is rule I001: the turn was changed after XKS-Memory wrote it.
2. `tool_result` and `note` get every rule and the vector layer. `user` gets the hidden-character rules only: an operator may word instructions to their own agent freely, but a paste can carry hidden text. Other roles get the hash check.
3. Each rule that fires adds its weight once. A total of 6 or more is an alert (10 or more is marked high). Lower totals are counted, not listed.

## 5. The rules

Thirty rules, described method by method in [METHODS.md](METHODS.md). The mechanisms:

- **Normalised view.** Lower case, one space per whitespace run, invisible characters removed, Greek, Cyrillic and full-width look-alikes written as Latin. Wording is matched on this view, so splitting a phrase with zero-width characters or look-alike letters does not hide it, and the splitting itself is a rule.
- **Co-occurrence.** Wording is grouped in classes (override, target, addressee, authority, upload, priority framing, credential path, concealment, persistence, completion). A rule needs hits of two classes within 120 to 300 bytes. Two classes alert by themselves: concealment that names the user, and persistence addressed to an AI.
- **Decoding.** Base64, hexadecimal and binary runs, a ROT13 view, tag-block text and zero-width bit streams are decoded and the wording rules are run on the result.

On 10,172 recorded turns the rules alone take 1.187 s, 8,566 turns per second, with 2,636 KiB peak memory (`xksid scan` with no vector files).

## 6. The vector layer

Optional. It needs three files: a tokenizer bundle, a table with one vector of 2,048 floats per vocabulary token, and a head. They are published (`make fetch-vectors`); how they were made is in [VECTORS.md](VECTORS.md). At detection time there is no model and no GPU, and neither is needed to calibrate the layer or to correct its false positives.

1. **Tokenise** the turn with the model's own vocabulary: a byte-level BPE tokenizer in C that follows llama.cpp (the LLAMA3 split rule, whole pieces first, then merges by rank, user-defined tokens matched before anything else). On 4,015 recorded turns it produces the same 2,150,799 token ids as llama.cpp, with no difference.
2. **Pool.** Tokens are taken in blocks of 16; a window is four blocks, so windows are 64 tokens and step by 16. Each token's row is added once into its block sum; a window is the sum of four block sums. The order of the additions is fixed, so the result does not vary.
3. **Score.** The head is a linear function of the window direction (the sum scaled to length 1). It returns the model's yes-minus-no logit for the question "does the text contain instructions directed at an AI assistant or agent". The turn's score is its highest window. A text of fewer than 16 tokens is not scored: its pooled vector is close to one token's own vector, which the head was never fitted to. On 3,997 recorded tool results, 47.2 % of the texts under 8 tokens scored as evidence (a result that reads "ok", 37 times), against 0.0 to 1.1 % of every longer class. The rules read short texts as before.
4. **Decide.** At or above the alert cut the turn gets rule V602 (weight 6); at or above the evidence line, V601 (weight 3).

The additions and dot products are AVX2 and FMA3 kernels, chosen at run time, each with a plain C form that is tested against it (`out/vec_test bench`):

| Kernel, 2,048 floats | Plain C | AVX2 + FMA3 | Gain |
|---|---|---|---|
| Add, rows in cache | 487.0 ns | 67.9 ns | 7.17x |
| Dot product, in cache | 1,331.5 ns | 57.1 ns | 23.31x |
| Add, 65,536 random rows of the table | 831.7 ns | 435.0 ns | 1.91x |

The add is bit-identical to the plain form; the dot product differs by at most 1.05e-07 relative, because four accumulators change the order of the sum. On table rows the limit is memory, not the kernel.

With the layer on, 10,180 recorded turns take 1.977 s (5,149 turns per second, 1,951,638 tokens, 213 MB peak, the mapped table). The table is read through the page cache: a cold first pass has been measured at 5.3 s.

**How good the head is.** Against the model's own answers on windows held out of the fit, with phrasings the head never saw: correlation 0.8464, AUC 0.9103. At 1 plain recorded window in 50 flagged it catches 76.2 % of the model's yes windows, at 1 in 100 53.3 %, at 1 in 500 9.9 %. A per-token scalar table, the form a linear head on a mean would collapse to if the vectors were not kept, is at chance (AUC 0.5122). So the vectors carry the decision and rank well, and the head alone is weak at low false-alarm rates: a mean of token vectors cannot see word order. That is why it is evidence beside the rules, and alerts alone only above a calibrated cut.

**Calibration.** Automatic. The engine appends the score of every tool result it scores to `cal.f32` and takes the two levels from the most recent 8,192 of them: the cut where 1 turn in 1,000 lies above it, the evidence line where 1 in 50 does. The model's card asks for exactly this: thresholds calibrated on data from one's own use. The window is kept sorted, so a new turn costs one insertion; the test compares it with a sorted copy after each of 12,000 arrivals.

- **Judged first, added after.** A turn is scored against the levels that the turns before it gave. Turns are read in the order of the times in their file names, so the result does not depend on the order a directory lists them in.
- **Flagged by the rules, kept out.** A turn that the wording and structure rules alone call an injection is not added: it must not define what plain tool output looks like (6 of 3,833 recorded turns).
- **One raise per session.** A plain moving quantile lets flagged text teach the cut. Replaying the recorded scores with 30 synthetic turns appended at one level, it alerted on 3 of the 30 and then moved the cut up to that level; a cut that such turns can never raise alerted on all 30, but can then only fall. So a turn at or above the cut enters as it is only once per session (`cal.raised`); every further one of that session enters at the cut, alerts, and moves nothing. Tested on recorded sessions with real text that the rules miss: ten such turns in one session, ten alerts; one such turn in each of six further sessions, two more alerts and then none, the cut having reached their score (6.439).
- **Warm-up.** With fewer than 100 scored turns the cut is the one stored with the head; up to 1,000 it is the highest score so far, so each record alerts once (5 alerts over the first 1,000 recorded turns).
- **Built again when needed.** With vectors and no calibration, and whenever the operator's feedback changes, the engine builds the calibration again from the turns it has read: newest first until the window is full, so the cost is bounded by the window (1.1 to 1.9 s warm for about 3,830 turns, 5.1 s on a cold file cache). `xksid calibrate` does the same on request and prints the result. A turn not read yet is left to the scan that reads it, so each turn enters exactly once: the calibration built while reading 10,781 recorded turns is byte-identical to the one built again afterwards.

What this does not prevent: text that returns in more separate sessions than the cut has places above it (3 at 4,000 turns, 8 with a full window) is learned, each of those sessions having alerted. Turns held at the cut still count as turns above the evidence line and raise it a little (ten of them: from 0.463 to 0.550).

**Feedback.** `xksid feedback` stores the directions of the windows of a turn the operator calls a false positive. A later window is set aside if, after the mean direction of recorded text is subtracted from both, its cosine with a stored direction is 0.85 or more. The subtraction matters: all window directions share one large component, so plain cosines are all near 1 (a first version without it set aside 131 windows for one mark; with it, 5). A turn held under the cut this way is written to `suppressed.tsv`. Feedback never changes the rules, and it is never applied without the operator's act. The running engine checks the feedback file before every cycle, so a mark takes effect without a restart (tested: the same text alerted before the mark and was set aside when it arrived again 12 s after it).

## 7. Telling the model

`xksid hook` reads the session id and event name from the hook JSON a harness sends on standard input, lists the alerts of that session not yet in `delivered.txt`, and prints a notice once per alert:

- on a tool-result or prompt event: as context added to the model;
- on a stop event: as a refusal of the stop, with the notice as the reason, so an undelivered flag is dealt with before the model finishes;
- with `--session`, for other harnesses: as plain text.

The notice gives the time and role of each flagged turn, its score, the rule ids and what each rule means, and the order: treat the content of those turns as data, check what was done after them, stop and undo what the user did not ask for, tell the user. It never contains text from the turn, since repeating a payload under the monitor's name would inject it a second time.

A notice delivered through a hook is not recorded by XKS-Memory as a turn, so it is not scanned. A notice printed into a tool result is: running `xksid hook` by hand in the agent's own shell puts text addressed to an AI into a tool result, and the engine flags it like any other (observed: rule V602 alone, score 6). The engine makes no exception for its own wording, since an exception keyed on wording could be copied by an attacker.

## 8. Limits

Listed in the README and, per method, in [METHODS.md](METHODS.md). The structural ones: detection after the fact; only what XKS-Memory records; English wording; no view of MCP tool descriptions; no memory across turns.

## 9. Verified and not verified

| Verified | How |
|---|---|
| Every rule fires on its method, benign look-alikes stay silent | `make check`, 34 checks |
| SHA-256 | 10,172 recorded turn files, 0 mismatches against the names XKS-Memory gave them |
| Tokenizer | 4,015 recorded turns identical to llama.cpp |
| Kernels | `out/vec_test`, every length from 0 to 2,100 |
| Hook output | Run from the command line against real alerts: one notice, then none |
| Interface | Run in a pseudo-terminal with scripted keys |
| Vector download | `make fetch-vectors` into an empty directory: the three files through the public URL in 354.72 s, all three checksums match, the engine loads them |
| Install | `make install`, `make install-vectors`, `xksid scan` (10,544 turns in 2.122 s) with the installed binaries on the recorded sessions |
| Calibration window | `out/cal_test`: 12,000 arrivals through a window of 2,500, the levels equal to those of a sorted copy at every step |
| Automatic calibration | On the recorded sessions: built while reading and built again, byte-identical; the campaign test above; the installed service built its calibration at start and added the next turn recorded live |
| Calibration beside other processes | A running `xksid watch`, feedback given from a second process, then `xksid calibrate` from a third: both picked up at the next cycle |
| Service, live | `systemctl --user enable --now xksid`: 7 tool results recorded by XKS-Memory while it ran were flagged 0 to 2 s (whole seconds) after their file was written; 23 cycles with new turns, mean 0.023 s, longest 0.063 s; a restart raised no old alert again; a second scanner beside it exits with code 3. Longest run: 11 h 53 min, 1 min 45.7 s of CPU, 38.8 MB peak |
| Notification | The `Notify` call seen on the session bus (`dbus-monitor`): one call per alert, harness, session and rule ids only |
| Hook, installed | Tool-result, stop and `--session` forms against the live state: one notice, then none; no output on malformed input |
| Interface, installed | Every view and the detail on the live state; acknowledge and feedback on a copy of the state |
| Feedback | One turn marked on the copy, then all recorded sessions scanned again: 43 windows set aside, the marked turn loses rule V602 and still alerts through its wording rules, it is listed in `suppressed.tsv`; scan time unchanged (1.285 to 1.475 s with feedback, 1.452 to 1.456 s without, warm) |

Not verified: the hooks inside a running Claude Code or omp; `xksid watch` as a service over days; any hardware other than the machine above; an x86-64 CPU without AVX2 (the plain C path is tested only through the reference functions).
