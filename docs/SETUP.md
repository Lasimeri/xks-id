# Setting up xks-id

Each step is separate. Nothing here is done for you by `make install`: it copies files and starts nothing.

## 1. Build, test, install

```
make && make check
make install            # xksid and xksid-tui to ~/.local/bin, the service file to ~/.config/systemd/user
```

`make out/xksid` builds the engine alone, with a C compiler and nothing else.

## 2. First scan

```
xksid scan
xksid status
```

The first scan reads every turn XKS-Memory has recorded. Later scans read only new turn files.

| What | Where | Override |
|---|---|---|
| Recorded turns, read only | `~/XKS-memories` | `XKSM_HOME` (the same variable XKS-Memory uses) |
| The engine's own state | `~/.local/state/xksid` | `XKSID_STATE`, `XDG_STATE_HOME` |
| Vector files, optional | `~/.local/share/xksid` | `XKSID_MODEL`, `XDG_DATA_HOME` |

## 3. Run it all day

```
systemctl --user enable --now xksid
systemctl --user status xksid
```

The service runs `xksid watch --interval 2 --notify`: one cycle every 2 seconds over the new turn files, and a desktop notification (through `notify-send`, if present) per batch of alerts. The notification names the harness, the session and the rule ids, never the flagged text.

While the service runs, `xksid scan` exits with code 3: the engine is already reading.

## 4. Tell the model

The engine writes alerts; a hook in the harness delivers them to the model. The hook detects nothing. It runs `xksid hook`, which prints a notice for the flagged turns of that session that the model has not been told about, once each.

**Claude Code.** Merge the three entries of `integrations/claude-code/hooks.json` into the `hooks` object of `~/.claude/settings.json`, next to the hooks already there:

- `PostToolUse` and `UserPromptSubmit`: the notice is added to the model's context.
- `Stop`: if an alert is still undelivered when the model wants to stop, the stop is refused once and the notice is the reason.

**omp.** Link `integrations/omp/xks-id.ts` into the hook directory of the profile, `~/.omp/agent/hooks/pre/` for the default profile. The notice arrives at the next prompt.

**Any other harness.** `xksid hook --session ID` prints the notice as plain text, or nothing.

XKS-Memory stores a tool result a moment after the tool call. The notice for a tool result therefore reaches the model at its next hook event.

## 5. The interface

```
xksid-tui
```

| Key | Action |
|---|---|
| `1` to `5`, Tab | Alerts, Sessions, Statistics, Suppressed, Help |
| `j` `k`, arrows | Move |
| Enter | Detail of an alert: its rules, and the recorded text near the hit with every non-printable byte shown as a dot |
| `a` | Acknowledge |
| `f` | False positive (decision vectors only, see step 7) |
| `s` | Scan now |
| `n` | Desktop notification from this window (off by default; the service already sends one) |
| `q` | Quit |

## 6. Decision vectors, optional

Three files in `~/.local/share/xksid`: `dvec.tok`, `dvec.vec.f32`, `dvec.head`. With them the engine also scores every tool result against vectors precalculated from a decision model. Without them it runs the rules alone and says so in `xksid status`.

```
make install-vectors VECTORS=/path/to/the/three/files
xksid status            # decision vectors: on, kernel avx2+fma
xksid calibrate
```

`xksid calibrate` scores your own recorded tool output and sets the alert cut where 1 turn in 1,000 of that history lies above it, and the evidence line where 1 in 50 does. It prints the highest turns of your history: look at them. No GPU and no model are involved; a history of 3,760 turns takes about 5 seconds.

The kernels use AVX2 and FMA3 when the CPU has both and plain C otherwise.

## 7. False positives

- **A rule alert that is not a problem:** acknowledge it (`a`). The rules are not changed by feedback.
- **A vector alert that is not a problem:** `f` in the interface, or `xksid feedback HARNESS/SESSION/FILE`. The directions of that turn's windows are stored, and later windows that point the same way no longer count for the vectors. A turn held under the cut this way is listed under Suppressed with the score it had, so nothing disappears unseen. To undo all feedback, remove `benign.f32` from the state directory.

A marked turn can still alert through the rules.

## 8. Remove

```
systemctl --user disable --now xksid
```

Then remove the two binaries, the service file, the hook entries, and the state and vector directories named in step 2. XKS-Memory is untouched throughout.
