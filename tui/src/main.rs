//! xksid-tui: the management interface of xks-id.
//!
//! It shows what the xksid engine found and lets the operator act on it: acknowledge an
//! alert, mark a turn as a false positive, run a scan, and be notified of new alerts.
//! It reads the state files xksid writes and runs the xksid binary for every action; the
//! two share no code. Everything printed from a recorded turn is reduced to printable
//! ASCII first, so recorded text cannot drive the terminal.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---- terminal: raw mode, size and input through libc, nothing else

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn tcgetattr(fd: i32, t: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, act: i32, t: *const Termios) -> i32;
    fn cfmakeraw(t: *mut Termios);
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn poll(fds: *mut PollFd, n: u64, timeout: i32) -> i32;
    fn read(fd: i32, buf: *mut std::ffi::c_void, n: usize) -> isize;
    fn flock(fd: i32, op: i32) -> i32;
}

const TIOCGWINSZ: u64 = 0x5413;
const ENTER_SCREEN: &str = "\x1b[?1049h\x1b[?25l";
const LEAVE_SCREEN: &str = "\x1b[?25h\x1b[?1049l";

struct Terminal {
    saved: Termios,
}

impl Terminal {
    fn enter() -> Option<Terminal> {
        let mut saved = Termios { c_iflag: 0, c_oflag: 0, c_cflag: 0, c_lflag: 0, c_line: 0, c_cc: [0; 32], c_ispeed: 0, c_ospeed: 0 };
        // SAFETY: saved is a valid termios for the calls to fill and read.
        unsafe {
            if tcgetattr(0, &mut saved) != 0 {
                return None;
            }
            let mut raw = saved;
            cfmakeraw(&mut raw);
            if tcsetattr(0, 0, &raw) != 0 {
                return None;
            }
        }
        print!("{ENTER_SCREEN}");
        Some(Terminal { saved })
    }

    fn size() -> (usize, usize) {
        let mut ws = Winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
        // SAFETY: TIOCGWINSZ writes one winsize.
        let ok = unsafe { ioctl(1, TIOCGWINSZ, &mut ws as *mut Winsize) } == 0;
        if ok && ws.ws_row > 0 && ws.ws_col > 0 {
            (ws.ws_row as usize, ws.ws_col as usize)
        } else {
            (24, 80)
        }
    }

    /// bytes typed within the timeout, empty if none
    fn input(timeout_ms: i32) -> Vec<u8> {
        let mut fds = PollFd { fd: 0, events: 1, revents: 0 };
        let mut buf = [0u8; 32];
        // SAFETY: one pollfd, and a buffer of the stated size.
        unsafe {
            if poll(&mut fds, 1, timeout_ms) <= 0 {
                return Vec::new();
            }
            let n = read(0, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                return Vec::new();
            }
            buf[..n as usize].to_vec()
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // SAFETY: restores the attributes read at entry.
        unsafe {
            tcsetattr(0, 0, &self.saved);
        }
        print!("{LEAVE_SCREEN}");
        let _ = io::stdout().flush();
    }
}

// ---- data: the state files of xksid

struct Alert {
    detected: String,
    harness: String,
    session: String,
    file: String,
    role: String,
    score: i32,
    rules: String,
    offset: i64,
    logit: String,
}

impl Alert {
    fn key(&self) -> String {
        format!("{}/{}", self.session, self.file)
    }
}

struct Session {
    harness: String,
    name: String,
    turns: i64,
    alerts: i64,
    max_score: i64,
    last: String,
}

struct Paths {
    root: PathBuf,
    state: PathBuf,
    bin: PathBuf,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

impl Paths {
    fn find() -> Paths {
        let home = env_path("HOME").unwrap_or_else(|| PathBuf::from("."));
        let root = env_path("XKSM_HOME").unwrap_or_else(|| home.join("XKS-memories"));
        let state = env_path("XKSID_STATE")
            .or_else(|| env_path("XDG_STATE_HOME").map(|p| p.join("xksid")))
            .unwrap_or_else(|| home.join(".local/state/xksid"));
        let beside = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("xksid")));
        let bin = env_path("XKSID_BIN")
            .or_else(|| beside.filter(|p| p.exists()))
            .unwrap_or_else(|| PathBuf::from("xksid"));
        Paths { root, state, bin }
    }
}

fn rows(path: PathBuf) -> Vec<Vec<String>> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

fn load_alerts(p: &Paths) -> Vec<Alert> {
    rows(p.state.join("alerts.tsv"))
        .into_iter()
        .filter(|f| f.len() >= 9)
        .map(|f| Alert {
            detected: f[0].clone(),
            harness: f[1].clone(),
            session: f[2].clone(),
            file: f[3].clone(),
            role: f[4].clone(),
            score: f[5].parse().unwrap_or(0),
            rules: f[7].clone(),
            offset: f[8].parse().unwrap_or(-1),
            logit: f.get(9).cloned().unwrap_or_else(|| "-".to_string()),
        })
        .collect()
}

fn load_sessions(p: &Paths) -> Vec<Session> {
    let mut all: Vec<Session> = rows(p.state.join("sessions.tsv"))
        .into_iter()
        .filter(|f| f.len() >= 6)
        .map(|f| Session {
            harness: f[0].clone(),
            name: f[1].clone(),
            turns: f[2].parse().unwrap_or(0),
            alerts: f[3].parse().unwrap_or(0),
            max_score: f[4].parse().unwrap_or(0),
            last: f[5].clone(),
        })
        .collect();
    all.sort_by(|a, b| b.last.cmp(&a.last));
    all
}

/// printable ASCII only: recorded text is shown, never obeyed by the terminal
fn plain(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else if b == b'\n' || b == b'\t' { ' ' } else { '.' }).collect()
}

fn clip(s: &str, width: usize) -> String {
    s.chars().take(width).collect()
}

// ---- the application

const TABS: [&str; 5] = ["Alerts", "Sessions", "Statistics", "Suppressed", "Help"];

struct App {
    paths: Paths,
    alerts: Vec<Alert>,
    acked: HashSet<String>,
    sessions: Vec<Session>,
    stats: Vec<(String, i64)>,
    suppressed: Vec<Vec<String>>,
    rules: HashMap<String, (String, String)>,
    status: Vec<String>,
    tab: usize,
    sel: usize,
    detail: bool,
    notify: bool,
    engine: bool,
    message: String,
    stamp: (u64, u64),
}

impl App {
    fn run(&self, args: &[&str]) -> (i32, String) {
        match Command::new(&self.paths.bin).args(args).output() {
            Ok(o) => {
                let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&o.stderr));
                (o.status.code().unwrap_or(-1), text)
            }
            Err(e) => (-1, format!("cannot run {}: {e}", self.paths.bin.display())),
        }
    }

    fn new() -> App {
        let mut app = App {
            paths: Paths::find(),
            alerts: Vec::new(),
            acked: HashSet::new(),
            sessions: Vec::new(),
            stats: Vec::new(),
            suppressed: Vec::new(),
            rules: HashMap::new(),
            status: Vec::new(),
            tab: 0,
            sel: 0,
            detail: false,
            notify: false,
            engine: false,
            message: String::new(),
            stamp: (0, 0),
        };
        let (_, text) = app.run(&["rules"]);
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() == 3 {
                app.rules.insert(f[0].to_string(), (f[1].to_string(), f[2].to_string()));
            }
        }
        app.reload(true);
        app
    }

    fn file_stamp(&self) -> (u64, u64) {
        let len = |name: &str| fs::metadata(self.paths.state.join(name)).map(|m| m.len()).unwrap_or(0);
        (len("alerts.tsv"), len("stats.tsv") + len("suppressed.tsv") + len("benign.f32"))
    }

    /// true while an xksid process holds the state lock, which the watcher does for its whole life
    fn engine_running(&self) -> bool {
        let Ok(f) = fs::File::open(self.paths.state.join("lock")) else { return false };
        // SAFETY: flock on an open descriptor; 6 = exclusive, non-blocking; 8 = unlock.
        unsafe {
            if flock(f.as_raw_fd(), 6) != 0 {
                return true;
            }
            flock(f.as_raw_fd(), 8);
        }
        false
    }

    fn reload(&mut self, first: bool) {
        let before = self.alerts.len();
        self.alerts = load_alerts(&self.paths);
        self.sessions = load_sessions(&self.paths);
        self.suppressed = rows(self.paths.state.join("suppressed.tsv"));
        self.acked = fs::read_to_string(self.paths.state.join("acked.txt")).unwrap_or_default().lines().map(str::to_string).collect();
        self.stats = rows(self.paths.state.join("stats.tsv")).into_iter().filter(|f| f.len() == 2).map(|f| (f[0].clone(), f[1].parse().unwrap_or(0))).collect();
        self.status = self.run(&["status"]).1.lines().take(9).map(str::to_string).collect();
        self.engine = self.engine_running();
        self.stamp = self.file_stamp();
        if !first && self.alerts.len() > before {
            let fresh = &self.alerts[before..];
            let top = fresh.iter().max_by_key(|a| a.score).expect("a new alert");
            self.message = format!("{} new alert(s), highest score {}", fresh.len(), top.score);
            print!("\x07");
            if self.notify {
                let body = format!("{} new alert(s). Highest score {}: {} {}", fresh.len(), top.score, plain(top.harness.as_bytes()), plain(top.rules.as_bytes()));
                let urgency = if top.score >= 10 { "critical" } else { "normal" };
                let _ = Command::new("notify-send").args(["-a", "xks-id", "-u", urgency, "xks-id: possible prompt injection", &body]).spawn();
            }
        }
        let n = self.list_len();
        if self.sel >= n {
            self.sel = n.saturating_sub(1);
        }
    }

    fn list_len(&self) -> usize {
        match self.tab {
            0 => self.alerts.len(),
            1 => self.sessions.len(),
            3 => self.suppressed.len(),
            _ => 0,
        }
    }

    /// alerts are listed newest first
    fn alert_at(&self, row: usize) -> Option<&Alert> {
        self.alerts.len().checked_sub(row + 1).and_then(|i| self.alerts.get(i))
    }

    fn acknowledge(&mut self) {
        let Some(key) = self.alert_at(self.sel).map(Alert::key) else { return };
        if self.acked.insert(key.clone()) {
            let path = self.paths.state.join("acked.txt");
            let mut all = fs::read_to_string(&path).unwrap_or_default();
            all.push_str(&key);
            all.push('\n');
            self.message = match fs::write(&path, all) {
                Ok(()) => "acknowledged".to_string(),
                Err(e) => format!("cannot write acked.txt: {e}"),
            };
        }
    }

    fn feedback(&mut self) {
        let Some(a) = self.alert_at(self.sel) else { return };
        let turn = format!("{}/{}/{}", a.harness, a.session, a.file);
        let (code, text) = self.run(&["feedback", &turn]);
        let last = text.lines().last().unwrap_or("").to_string();
        self.message = if code == 0 { format!("false positive: {last}") } else { format!("feedback failed: {last}") };
        if code == 0 {
            self.acknowledge();
        }
    }

    fn scan(&mut self) {
        let (code, text) = self.run(&["scan"]);
        self.message = match code {
            0 => text.lines().last().unwrap_or("").to_string(),
            3 => "the engine is running and scans every cycle; nothing to do".to_string(),
            _ => format!("scan failed: {}", text.lines().last().unwrap_or("")),
        };
        self.reload(false);
    }

    fn excerpt(&self, a: &Alert, width: usize, lines: usize) -> Vec<String> {
        let path = self.paths.root.join(&a.harness).join(&a.session).join(&a.file);
        let Ok(bytes) = fs::read(&path) else { return vec!["(the turn file cannot be read)".to_string()] };
        let at = if a.offset < 0 { 0 } else { (a.offset as usize).min(bytes.len()) };
        let start = at.saturating_sub(120);
        let end = (at + width * lines).min(bytes.len());
        let text = plain(&bytes[start..end]);
        text.as_bytes().chunks(width.max(1)).take(lines).map(|c| String::from_utf8_lossy(c).into_owned()).collect()
    }

    fn body(&self, height: usize, width: usize) -> Vec<String> {
        let mut out = Vec::new();
        match self.tab {
            0 => {
                out.push(format!("  {:<19} {:<11} {:<11} {:>5} {:>8}  {}", "detected", "harness", "role", "score", "vectors", "rules"));
                let detail = if self.detail { (height / 2).max(8) } else { 0 };
                let list = height.saturating_sub(1 + detail);
                let top = self.sel.saturating_sub(list.saturating_sub(1));
                for row in top..(top + list).min(self.alerts.len()) {
                    let a = self.alert_at(row).expect("row in range");
                    let mark = if self.acked.contains(&a.key()) { ' ' } else { '!' };
                    let line = format!("{mark} {:<19} {:<11} {:<11} {:>5} {:>8}  {}", clip(&a.detected, 19), clip(&a.harness, 11), clip(&a.role, 11), a.score, clip(&a.logit, 8), a.rules);
                    out.push(if row == self.sel { format!("\x1b[7m{}\x1b[0m", clip(&format!("{line:<width$}"), width)) } else { line });
                }
                if self.alerts.is_empty() {
                    out.push("  no alerts. The engine has found nothing, or it has not run yet (press s).".to_string());
                }
                if let (true, Some(a)) = (self.detail, self.alert_at(self.sel)) {
                    while out.len() < 1 + list {
                        out.push(String::new());
                    }
                    out.push("-".repeat(width));
                    out.push(format!(" session  {}", a.session));
                    out.push(format!(" turn     {}   byte {}", a.file, a.offset));
                    for id in a.rules.split(',') {
                        let (weight, text) = self.rules.get(id).cloned().unwrap_or_default();
                        out.push(format!(" {id}  +{weight}  {text}"));
                    }
                    out.push(" recorded text near the hit (non-printable bytes shown as dots):".to_string());
                    let room = detail.saturating_sub(out.len() - 1 - list);
                    out.extend(self.excerpt(a, width.saturating_sub(2), room).into_iter().map(|l| format!(" {l}")));
                }
            }
            1 => {
                out.push(format!("  {:<11} {:<19} {:<38} {:>7} {:>7} {:>6}", "harness", "last turn", "session", "turns", "alerts", "max"));
                let list = height.saturating_sub(1);
                let top = self.sel.saturating_sub(list.saturating_sub(1));
                for (row, s) in self.sessions.iter().enumerate().skip(top).take(list) {
                    let id = s.name.splitn(3, '_').nth(2).unwrap_or(&s.name);
                    let line = format!("  {:<11} {:<19} {:<38} {:>7} {:>7} {:>6}", clip(&s.harness, 11), clip(&s.last, 19), clip(id, 38), s.turns, s.alerts, s.max_score);
                    out.push(if row == self.sel { format!("\x1b[7m{}\x1b[0m", clip(&format!("{line:<width$}"), width)) } else { line });
                }
            }
            2 => {
                out.extend(self.status.iter().map(|l| format!("  {}", l.replace('\t', ": "))));
                out.push(String::new());
                let total = |prefix: &str| -> i64 { self.stats.iter().filter(|(k, _)| k.starts_with(prefix)).map(|(_, v)| v).sum() };
                out.push(format!("  turns read {}   alerts {}   below the threshold {}", total("turns."), total("alerts."), total("below.")));
                let get = |key: &str| self.stats.iter().find(|(k, _)| k == key).map(|(_, v)| *v).unwrap_or(0);
                out.push(format!("  vectors: {} tokens scored, {} windows set aside by feedback, {} turns suppressed", get("l6.tokens"), get("l6.vetoed"), get("l6.suppressed")));
                let age = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) - get("scan.last_epoch");
                out.push(format!("  last scan: {} s ago, {} new turns, {:.3} s", age, get("scan.last_files"), get("scan.last_micros") as f64 / 1e6));
                out.push(String::new());
                out.push("  rule    hits  what it means".to_string());
                let mut hits: Vec<(&str, i64)> = self.stats.iter().filter_map(|(k, v)| k.strip_prefix("rule.").map(|id| (id, *v))).collect();
                hits.sort_by(|a, b| b.1.cmp(&a.1));
                for (id, n) in hits {
                    out.push(format!("  {id:<6} {n:>5}  {}", self.rules.get(id).map(|r| r.1.as_str()).unwrap_or("")));
                }
            }
            3 => {
                out.push("  turns kept under the alert cut only by your feedback (logit before the feedback)".to_string());
                out.push(format!("  {:<19} {:<11} {:<11} {:>8}  {}", "detected", "harness", "role", "logit", "turn"));
                for (row, f) in self.suppressed.iter().enumerate().take(height.saturating_sub(2)) {
                    if f.len() >= 6 {
                        let line = format!("  {:<19} {:<11} {:<11} {:>8}  {}", clip(&f[0], 19), clip(&f[1], 11), clip(&f[4], 11), f[5], f[3]);
                        out.push(if row == self.sel { format!("\x1b[7m{}\x1b[0m", clip(&format!("{line:<width$}"), width)) } else { line });
                    }
                }
            }
            _ => {
                for line in [
                    "  xks-id reads the turns XKS-Memory records and reports text that looks like prompt injection.",
                    "",
                    "  1 to 5, Tab   switch view              j k, arrows   move",
                    "  Enter         show or hide the detail of an alert",
                    "  a             acknowledge the alert: it stays listed, without the mark",
                    "  f             false positive: turns like this one no longer count for the decision",
                    "                vectors (the rule engine is not changed); the turn is kept under Suppressed",
                    "  s             read the new turns now       r   reload",
                    "  n             desktop notification from this window for new alerts (off by default:",
                    "                the engine service already sends one)",
                    "  q             quit",
                    "",
                    "  engine, all day:   systemctl --user enable --now xksid",
                    "  decision vectors (about 1 GB, no GPU needed):   make fetch-vectors",
                    "  alert cut from your own turns:   xksid calibrate",
                    "  the model is told about flagged turns through the harness hooks: see docs/SETUP.md",
                ] {
                    out.push(line.to_string());
                }
            }
        }
        out
    }

    fn draw(&self) {
        let (height, width) = Terminal::size();
        let mut screen = String::from("\x1b[H");
        let mut head = String::from(" xks-id  ");
        for (i, name) in TABS.iter().enumerate() {
            head.push_str(&if i == self.tab { format!("\x1b[7m {} {name} \x1b[0m", i + 1) } else { format!(" {} {name} ", i + 1) });
        }
        let unacked = self.alerts.iter().filter(|a| !self.acked.contains(&a.key())).count();
        let high = self.alerts.iter().filter(|a| a.score >= 10).count();
        let state = format!(
            " engine: {}   alerts {} ({} new, {} high)   notifications here: {}",
            if self.engine { "running" } else { "not running" },
            self.alerts.len(),
            unacked,
            high,
            if self.notify { "on" } else { "off" }
        );
        let mut lines = vec![head, clip(&state, width), String::new()];
        lines.extend(self.body(height.saturating_sub(4), width));
        lines.truncate(height.saturating_sub(1));
        while lines.len() < height.saturating_sub(1) {
            lines.push(String::new());
        }
        lines.push(clip(&format!(" {}", if self.message.is_empty() { "q quit   5 help" } else { &self.message }), width));
        for (i, line) in lines.iter().enumerate() {
            // a line with a highlight already has its width; any other is cut to the screen
            screen.push_str(&if line.contains('\x1b') { line.clone() } else { clip(line, width) });
            screen.push_str("\x1b[K");
            if i + 1 < lines.len() {
                screen.push_str("\r\n");
            }
        }
        print!("{screen}");
        let _ = io::stdout().flush();
    }

    /// false when the operator quits
    fn key(&mut self, bytes: &[u8]) -> bool {
        let down = bytes == b"j" || bytes == b"\x1b[B";
        let up = bytes == b"k" || bytes == b"\x1b[A";
        if down && self.sel + 1 < self.list_len() {
            self.sel += 1;
        } else if up {
            self.sel = self.sel.saturating_sub(1);
        } else if bytes.len() == 1 {
            match bytes[0] {
                b'q' | 3 => return false,
                b'1'..=b'5' => {
                    self.tab = (bytes[0] - b'1') as usize;
                    self.sel = 0;
                }
                b'\t' => {
                    self.tab = (self.tab + 1) % TABS.len();
                    self.sel = 0;
                }
                b'\r' | b'\n' if self.tab == 0 => self.detail = !self.detail,
                b'a' if self.tab == 0 => self.acknowledge(),
                b'f' if self.tab == 0 => self.feedback(),
                b's' => self.scan(),
                b'r' => {
                    self.reload(false);
                    self.message = "reloaded".to_string();
                }
                b'n' => self.notify = !self.notify,
                _ => {}
            }
        }
        true
    }
}

fn main() {
    let Some(terminal) = Terminal::enter() else {
        eprintln!("xksid-tui: needs a terminal");
        std::process::exit(1);
    };
    let mut app = App::new();
    let mut checked = Instant::now();
    loop {
        app.draw();
        let bytes = Terminal::input(250);
        if !bytes.is_empty() && !app.key(&bytes) {
            break;
        }
        if checked.elapsed() >= Duration::from_secs(1) {
            checked = Instant::now();
            if app.file_stamp() != app.stamp || app.engine != app.engine_running() {
                app.reload(false);
            }
        }
    }
    drop(terminal);
}
