use crate::runner::Runner;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// Parses a strict `MAJOR.MINOR.PATCH` token; any non-numeric part rejects it.
fn parse_semver(tok: &str) -> Option<(u32, u32, u32)> {
    let p: Result<Vec<u32>, _> = tok.split('.').map(str::parse::<u32>).collect();
    match p.ok()?.as_slice() {
        [a, b, c] => Some((*a, *b, *c)),
        _ => None,
    }
}

pub fn ensure_nuclei_version(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>> {
    let out = runner.run_text("nuclei", &["-version".into()], &[])?;
    // Prefer a v-prefixed token; fall back to a bare one.
    let ver = out
        .split_whitespace()
        .find_map(|w| w.strip_prefix('v').and_then(parse_semver))
        .or_else(|| out.split_whitespace().find_map(parse_semver));
    match ver {
        Some(v) if v >= (3, 10, 0) => Ok(()),
        _ => Err("nuclei >= v3.10.0 required (CVE-2026-76802)".into()),
    }
}

/// A fresh, process-unique path in the system temp directory (nothing is created).
fn unique_temp_path(suffix: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ascent-nuclei-{}-{nanos}-{}{suffix}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ))
}

/// Writes `lines` (one per line) to a NEW file at `p`; never follows or reuses an
/// existing file.
pub fn write_new_lines(p: &Path, lines: &[String]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    f.write_all((lines.join("\n") + "\n").as_bytes())
}

/// A temporary URL list that is deleted when dropped (also on error or panic).
struct ListFile(PathBuf);
impl ListFile {
    fn create(lines: &[String]) -> std::io::Result<Self> {
        let p = unique_temp_path(".txt");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)?;
        let file = ListFile(p);
        f.write_all((lines.join("\n") + "\n").as_bytes())?;
        Ok(file)
    }
}
impl Drop for ListFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A fresh private temporary directory, removed with everything in it when dropped
/// (also on error or panic). Creation fails rather than reuse an existing path, and
/// on Unix only the owner can enter it, so no other local user can plant, swap or
/// read a file in it (a trace log path is handed to nuclei before the file exists).
pub struct TempDir(PathBuf);
impl TempDir {
    pub fn create() -> std::io::Result<Self> {
        let p = unique_temp_path(".d");
        #[cfg(unix)]
        let b = {
            use std::os::unix::fs::DirBuilderExt;
            let mut b = std::fs::DirBuilder::new();
            b.mode(0o700);
            b
        };
        #[cfg(not(unix))]
        let b = std::fs::DirBuilder::new();
        b.create(&p)?;
        Ok(TempDir(p))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The hosts (scope targets) and the URLs nuclei is given, derived in one pass so
/// every URL nuclei scans has its host scope-checked; URLs without a host are never
/// scanned.
fn scannable(urls: &[String]) -> (BTreeSet<String>, Vec<String>) {
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut listed: Vec<String> = Vec::new();
    for u in urls {
        if let Some(h) = Url::parse(u)
            .ok()
            .and_then(|p| p.host_str().map(String::from))
        {
            hosts.insert(h);
            listed.push(u.clone());
        }
    }
    (hosts, listed)
}

/// How many of `urls` the nuclei scan would list (0: nuclei is not run).
pub fn listed_count(urls: &[String]) -> usize {
    scannable(urls).1.len()
}

/// Runs nuclei and returns its raw JSON rows, with an optional wall-clock deadline.
///
/// **Invariant:** Caller guarantees all URLs in `urls` have already been filtered
/// through the scope guard (see `filter_in_scope` in `dast.rs`).
///
/// **Dry-run handling:** If `runner.supports_timeout()` is false, or `deadline` is
/// `None`, the call is forwarded to `runner.run_json`, which enforces any dry-run
/// check. When `runner.supports_timeout()` is true the caller (`run_dast`) must
/// have set `deadline = None` for a dry run — the real-spawn path below is never
/// reached for dry runs because `run_dast` passes `deadline = None` whenever
/// `!live`.
///
/// Returns `(rows, timed_out)`.  When the runner does not support timeouts
/// (`runner.supports_timeout()` is false) or `deadline` is `None`, this
/// falls through to `runner.run_json` and always returns `timed_out = false`.
///
/// When the deadline is reached while nuclei is still running:
/// 1. Send `SIGTERM` to the nuclei process.
/// 2. Wait up to 10 seconds for it to exit.
/// 3. Send `SIGKILL` if still alive.
/// 4. Return any JSONL rows nuclei already wrote to stdout (`timed_out = true`).
pub fn scan_rows_with_deadline(
    runner: &dyn Runner,
    urls: &[String],
    args: &[String],
    deadline: Option<std::time::Instant>,
    secret: Option<&str>,
) -> Result<(Vec<serde_json::Value>, bool), Box<dyn std::error::Error>> {
    let (hosts, listed) = scannable(urls);
    if hosts.is_empty() {
        return Ok((vec![], false));
    }
    let list = ListFile::create(&listed)?;
    let mut full_args: Vec<String> = args.to_vec();
    full_args.push("-l".into());
    full_args.push(list.0.to_string_lossy().into_owned());
    let hv: Vec<String> = hosts.into_iter().collect();

    // When the runner is not a real process-spawner, fall through to the normal path.
    let Some(dl) = deadline.filter(|_| runner.supports_timeout()) else {
        let rows = runner.run_json("nuclei", &full_args, &hv)?;
        return Ok((rows, false));
    };

    // `secret` must be captured by value in the stderr thread; clone it once here.
    let secret_owned: Option<String> = secret.map(str::to_owned);

    // Already past the deadline before we even start.
    let now = std::time::Instant::now();
    if now >= dl {
        return Ok((vec![], true));
    }

    // Spawn nuclei directly so we can kill it on timeout.
    let mut child = std::process::Command::new("nuclei")
        .args(&full_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Read stdout in a background thread (nuclei may flush lazily).
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| -> Box<dyn std::error::Error> { "nuclei stdout pipe missing".into() })?;
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = std::io::BufReader::new(child_stdout).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    // Read stderr in a background thread; scrub each line before printing so
    // the auth header value never surfaces in output.  The last scrubbed line
    // is forwarded to the main thread for use in error messages.
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| -> Box<dyn std::error::Error> { "nuclei stderr pipe missing".into() })?;
    let (etx, erx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(child_stderr);
        let mut last = String::new();
        for line in reader.lines().map_while(Result::ok) {
            let scrubbed = match &secret_owned {
                Some(v) if !v.is_empty() => line.replace(v.as_str(), "***"),
                _ => line,
            };
            eprintln!("{scrubbed}");
            last = scrubbed;
        }
        let _ = etx.send(last);
    });

    // Poll until done or deadline.
    let timed_out = loop {
        match child.try_wait()? {
            Some(status) => {
                if !status.success() {
                    let code = status.code().unwrap_or(-1);
                    let last_stderr = erx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap_or_default();
                    if last_stderr.is_empty() {
                        return Err(format!("nuclei exited with code {code}").into());
                    }
                    return Err(format!("nuclei exited with code {code}: {last_stderr}").into());
                }
                break false;
            }
            None => {
                if std::time::Instant::now() >= dl {
                    // Deadline reached: SIGTERM, wait up to 10 s, then SIGKILL.
                    let _ = send_sigterm(child.id());
                    let kill_at = std::time::Instant::now() + std::time::Duration::from_secs(10);
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        if child.try_wait()?.is_some() || std::time::Instant::now() >= kill_at {
                            break;
                        }
                    }
                    let _ = child.kill(); // SIGKILL if still alive
                    let _ = child.wait(); // reap zombie
                    break true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    };

    // Collect whatever nuclei wrote before it was killed.
    let stdout = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_default();
    let rows = crate::runner::parse_jsonl(&String::from_utf8_lossy(&stdout));
    Ok((rows, timed_out))
}

/// Send SIGTERM to a process by PID. On non-Unix platforms this is a no-op;
/// the subsequent SIGKILL (via `Child::kill`) will handle it.
#[cfg(unix)]
fn send_sigterm(pid: u32) -> std::io::Result<()> {
    // `kill` is part of the C standard library: no extra crate needed.
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let ret = unsafe { kill(pid as i32, 15) }; // 15 = SIGTERM
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn send_sigterm(_pid: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use serde_json::Value;

    #[test]
    fn temp_dir_is_fresh_and_removed_with_its_contents() {
        let (a, b) = (TempDir::create().unwrap(), TempDir::create().unwrap());
        assert_ne!(a.path(), b.path());
        assert!(a.path().is_dir());
        let f = a.path().join("exclude.txt");
        write_new_lines(&f, &["x".into(), "y".into()]).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "x\ny\n");
        // never overwrites an existing file
        assert!(write_new_lines(&f, &["z".into()]).is_err());
        std::fs::write(a.path().join("trace.jsonl"), "{}").unwrap();
        let p = a.path().to_path_buf();
        drop(a);
        assert!(!p.exists(), "temp dir left behind");
    }

    #[cfg(unix)]
    #[test]
    fn temp_dir_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::create().unwrap();
        let mode = std::fs::metadata(d.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }

    struct Ver(&'static str);
    impl Runner for Ver {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![])
        }
        fn run_text(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn nuclei_version_gate() {
        for ok in ["[INF] Nuclei Engine Version: v3.10.1", "3.10.0", "v3.10.0"] {
            assert!(ensure_nuclei_version(&Ver(ok)).is_ok(), "{ok}");
        }
        for bad in ["v3.9.9", "", "garbage", "x.3.10", "v2.99.99"] {
            assert!(ensure_nuclei_version(&Ver(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn nuclei_version_prefers_v_prefixed_token() {
        // An unrelated 3-number token must not be mistaken for the version.
        let out = "[INF] build 9.9.9 Nuclei Engine Version: v3.9.0";
        assert!(ensure_nuclei_version(&Ver(out)).is_err());
    }
}
