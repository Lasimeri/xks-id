/**
 * xks-id for omp: tells the model which recorded turns of its own session were flagged as
 * possible prompt injection, so it can correct itself. It detects nothing: the xksid engine
 * does that from the turn files XKS-Memory records. This extension only asks xksid for the
 * alerts of the session that the model has not been told about yet.
 *
 * Install: copy (or link) this file to ~/.omp/agent/hooks/pre/xks-id.ts (default profile) or
 * ~/.omp/profiles/<name>/agent/hooks/pre/ (named profile). Needs the xksid binary: $XKSID_BIN,
 * ~/.local/bin/xksid, or xksid on PATH.
 *
 * Event (omp extension API):
 *   before_agent_start  "xksid hook --session ID" prints a notice when there are new alerts;
 *                       it is returned as a persisted message, shown to the user as well.
 * The notice names turns, scores and rules. It never carries the flagged text.
 * Environment: XKSID_OMP_DISABLE=1 turns it off; XKSID_STATE as for the CLI.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename } from "node:path";

function xksidBinary(): string | null {
  const candidates = [process.env.XKSID_BIN, `${homedir()}/.local/bin/xksid`];
  for (const c of candidates) if (c && existsSync(c)) return c;
  const which = spawnSync("sh", ["-c", "command -v xksid"], { encoding: "utf8" });
  const p = which.stdout?.trim();
  return p ? p : null;
}

const BIN = process.env.XKSID_OMP_DISABLE === "1" ? null : xksidBinary();

/** the id XKS-Memory records the session under: the session manager's id, else the file name */
function sessionId(ctx: any): string {
  const sm = ctx?.sessionManager;
  try {
    const id = sm?.getSessionId?.();
    if (typeof id === "string" && id) return id;
    const file = sm?.getSessionFile?.();
    if (typeof file === "string" && file) return basename(file).replace(/\.jsonl$/, "");
  } catch {
    /* no session id: no notice */
  }
  return "";
}

export default function xksId(pi: any) {
  if (!BIN) return;

  pi.on("before_agent_start", (_event: any, ctx: any) => {
    const session = sessionId(ctx);
    if (!session) return;
    const r = spawnSync(BIN, ["hook", "--session", session], { encoding: "utf8", timeout: 5000 });
    const notice = r.status === 0 ? (r.stdout || "").trim() : "";
    if (!notice) return;
    return {
      message: {
        customType: "xks-id",
        content: notice,
        display: true,
        details: { session },
      },
    };
  });
}
