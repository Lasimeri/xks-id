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

The service runs `xksid watch --interval 2 --notify`: one cycle every 2 seconds over the new turn files, and a desktop notification (through `notify-send`, if present) per batch of alerts.

The notification names the harness, the session, the score and the rule ids of the highest alert of the batch, and under them it shows what that turn says: up to 280 characters, starting at the line of the first hit (at the top of the turn for an alert raised by the vectors alone). The text is made harmless first: control and non-ASCII characters are dots, and `&`, `<`, `>` are escaped, so it cannot draw a link or load an image in the popup. To keep turn text out of the desktop's notification history, change `--notify` to `--notify-ids` in `~/.config/systemd/user/xksid.service`, then `systemctl --user daemon-reload` and `systemctl --user restart xksid`: the popup then carries the ids alone.

While the service runs, `xksid scan` exits with code 3: the engine is already reading.

## 4. Tell the model

The engine writes alerts; a hook in the harness delivers them to the model. The hook detects nothing. It runs `xksid hook`, which prints a notice for the flagged turns of that session that the model has not been told about, once each.

```
make hook-claude-code            # Claude Code
make hook-omp                    # omp, default profile
make hook-omp OMP_PROFILE=NAME   # omp, a named profile
```

Each target changes one file of that harness and prints which. Running it a second time changes nothing.

**Claude Code.** The three entries of `integrations/claude-code/hooks.json` are added to the `hooks` object of `~/.claude/settings.json`, next to the hooks already there (this needs `jq`; without it, merge the entries by hand). The file as it was is kept beside it as `settings.json.before-xksid-DATE-TIME`.

- `PostToolUse` and `UserPromptSubmit`: the notice is added to the model's context.
- `Stop`: the hook first waits for the engine's verdict on the turns XKS-Memory writes during the stop (about 0.13 s when measured). If one of them is flagged, or an earlier alert is still undelivered, the stop is refused once and the notice is the reason.

A session that was already running picked the new hooks up without a restart when this was tested. If one does not, open `/hooks` in it once or restart it. One call of the hook with nothing to report takes about 1 ms.

**omp.** `integrations/omp/xks-id.ts` is copied to `~/.local/share/xksid/omp/` and linked into the hook directory of the profile: `~/.omp/agent/hooks/pre/` for the default profile, `~/.omp/profiles/NAME/agent/hooks/pre/` for a named one. The notice arrives at the next prompt of a session started after that.

Wire the profile XKS-Memory is attached to. A profile whose turns are not recorded has nothing the engine could flag, and the target says so.

**Any other harness.** `xksid hook --session ID` prints the notice as plain text, or nothing.

**When the notice arrives.** In Claude Code, XKS-Memory writes a tool result to its turn file at the hook event after the one that produced it: at the next tool call, at the stop, or at the next prompt. The engine cannot see it sooner. So:

- A flagged tool result in the middle of a turn: the notice arrives after the second tool call that follows it (19 s after the result in the test, with tool calls 6 to 13 s apart).
- A flagged tool result at the end of a turn: the stop is refused (4.1 s after the result in the test; 0.13 s after the model's last word).
- An alert raised while the model is idle: the notice arrives with the next prompt.

In omp, XKS-Memory stores a tool result at once, the engine flags it within its 2 s cycle, and the notice arrives with the next prompt of the session.

If the engine runs and XKS-Memory writes nothing during a stop (its logging is paused), the stop hook waits 1 s before it lets the stop through. With no engine running it does not wait.

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
make fetch-vectors      # about 1 GB from huggingface.co/Lasimeri/xks-id-vectors, checked against docs/vectors.sha256
xksid status            # decision vectors: on, kernel avx2+fma
systemctl --user restart xksid   # only if the service was already running: it loads the vectors when it starts
```

`make fetch-vectors` uses curl and continues an interrupted download. By hand, the same three files can be taken from <https://huggingface.co/Lasimeri/xks-id-vectors> and checked with `sha256sum --check docs/vectors.sha256` inside the directory that holds them. Files built yourself ([VECTORS.md](VECTORS.md)) are installed with `make install-vectors VECTORS=DIR`.

The vectors are derived from LiquidAI d1-2B and come under that model's licence, published beside them.

The table is mapped, not loaded: the engine's memory grows with the rows it touches (213 MB peak on 10,180 recorded turns).

**Calibration is automatic.** The engine keeps the vector score of every tool result it reads and takes two levels from the most recent 8,192 of them: the alert cut, where 1 turn in 1,000 lies above it, and the evidence line, where 1 in 50 does. Both follow your own work as it changes; `xksid status` and the Statistics view show them and when the cut last moved, and every move is logged in `cut.tsv` in the state directory. No GPU and no model are involved.

- When the engine starts with vectors and no calibration, it builds one from the turns it has already read (3,838 turns in 5.1 s on a cold file cache, 1.1 to 1.9 s warm).
- Until 1,000 tool results have been scored the cut is the highest score seen so far, so each new record alerts once: on the recorded history used here that was 5 alerts.
- A turn above the cut can move the cut once per session. Text that keeps arriving in one session keeps alerting.
- `xksid calibrate` builds the calibration again from the turns the engine has read and prints what it holds, including the highest turns of your history: look at them. It is never needed for the engine to work.

The kernels use AVX2 and FMA3 when the CPU has both and plain C otherwise.

## 7. False positives

- **A rule alert that is not a problem:** acknowledge it (`a`). The rules are not changed by feedback.
- **A vector alert that is not a problem:** `f` in the interface, or `xksid feedback HARNESS/SESSION/FILE`. The directions of that turn's windows are stored, and later windows that point the same way no longer count for the vectors. A turn held under the cut this way is listed under Suppressed with the score it had, so nothing disappears unseen. To undo all feedback, remove `benign.f32` from the state directory.

A marked turn can still alert through the rules. Feedback takes effect at the engine's next cycle, without a restart: the running engine sees the change and builds its calibration again with it.

## 8. Remove

```
systemctl --user disable --now xksid
```

Then remove the two binaries, the service file, and the state and vector directories named in step 2. The hooks: take the three `xksid hook` entries out of `~/.claude/settings.json` (or put back the copy kept beside it, if nothing else changed since), and remove the link `xks-id.ts` from the omp hook directory. XKS-Memory is untouched throughout.
