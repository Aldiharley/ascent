use crate::runner::Runner;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
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

/// A temporary URL list that is deleted when dropped (also on error or panic).
struct ListFile(PathBuf);
impl ListFile {
    fn create(lines: &[String]) -> std::io::Result<Self> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "ascent-nuclei-{}-{nanos}-{}.txt",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
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

/// Runs nuclei with the caller's flags and returns its raw JSON rows. `args` are
/// passed verbatim, followed by `-l <file>` listing the URLs (one `-u` per URL would
/// overflow Windows' 32K command line on a real app).
pub fn scan_rows(
    runner: &dyn Runner,
    urls: &[String],
    args: &[String],
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    // Targets and the URL list are derived in one pass so every URL nuclei scans has
    // its host scope-checked; URLs without a host are never scanned.
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
    if hosts.is_empty() {
        return Ok(vec![]);
    }
    let list = ListFile::create(&listed)?;
    let mut args: Vec<String> = args.to_vec();
    args.push("-l".into());
    args.push(list.0.to_string_lossy().into_owned());
    let hv: Vec<String> = hosts.into_iter().collect();
    runner.run_json("nuclei", &args, &hv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalise::normalise_nuclei;
    use crate::runner::Runner;
    use serde_json::{json, Value};
    struct Fake;
    impl Runner for Fake {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![
                json!({"template-id":"CVE-1","info":{"name":"x","severity":"high"},
                "matched-at":"https://app.example.com/"}),
            ])
        }
        fn run_text(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(String::new())
        }
    }
    fn jsonl() -> Vec<String> {
        vec!["-silent".into(), "-jsonl".into()]
    }

    #[test]
    fn scan_rows_returns_raw_rows() {
        let rows = scan_rows(&Fake, &["https://app.example.com/".into()], &jsonl()).unwrap();
        assert_eq!(rows[0]["template-id"], "CVE-1");
        let out = normalise_nuclei(&rows);
        assert_eq!(out[0].tool, "nuclei");
        assert_eq!(out[0].severity, "HIGH");
    }

    #[test]
    fn caller_args_pass_verbatim_then_a_list_file() {
        let rec = Rec::default();
        let mut args = jsonl();
        args.extend(["-tags".into(), "xss".into()]);
        scan_rows(&rec, &["https://app.example.com/".to_string()], &args).unwrap();
        let calls = rec.calls.borrow();
        let (_, got, targets) = &calls[0];
        assert_eq!(got.len(), 6, "{got:?}");
        assert_eq!(&got[..5], &["-silent", "-jsonl", "-tags", "xss", "-l"]);
        assert!(!got.iter().any(|a| a == "-u"), "{got:?}");
        assert_eq!(targets, &vec!["app.example.com".to_string()]);
        assert_eq!(rec.lists.borrow()[0], vec!["https://app.example.com/"]);
        assert!(!std::path::Path::new(&got[5]).exists(), "list file left behind");
    }

    #[test]
    fn a_long_surface_goes_through_one_list_file() {
        let rec = Rec::default();
        let urls: Vec<String> = (0..3000).map(|i| format!("https://app.example.com/p/{i}?q=1")).collect();
        scan_rows(&rec, &urls, &jsonl()).unwrap();
        let calls = rec.calls.borrow();
        let (_, got, _) = &calls[0];
        assert!(got.iter().map(String::len).sum::<usize>() < 1024, "command line grows with the surface");
        assert_eq!(rec.lists.borrow()[0], urls);
    }

    #[test]
    fn list_file_is_removed_when_nuclei_fails_and_names_are_unique() {
        let rec = Rec { fail: true, ..Default::default() };
        assert!(scan_rows(&rec, &["https://app.example.com/".to_string()], &jsonl()).is_err());
        assert!(scan_rows(&rec, &["https://app.example.com/".to_string()], &jsonl()).is_err());
        let calls = rec.calls.borrow();
        let (a, b) = (calls[0].1.last().unwrap(), calls[1].1.last().unwrap());
        assert_ne!(a, b);
        assert!(!std::path::Path::new(a).exists() && !std::path::Path::new(b).exists());
    }

    use std::cell::RefCell;
    type Call = (String, Vec<String>, Vec<String>);
    #[derive(Default)]
    struct Rec {
        calls: RefCell<Vec<Call>>,
        /// The `-l` file's lines, read while the call runs.
        lists: RefCell<Vec<Vec<String>>>,
        fail: bool,
    }
    impl Runner for Rec {
        fn run_json(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            self.calls
                .borrow_mut()
                .push((t.to_string(), a.to_vec(), g.to_vec()));
            if let Some(w) = a.windows(2).find(|w| w[0] == "-l") {
                let text = std::fs::read_to_string(&w[1]).unwrap();
                self.lists.borrow_mut().push(text.lines().map(String::from).collect());
            }
            if self.fail {
                return Err("nuclei crashed".into());
            }
            Ok(vec![])
        }
        fn run_text(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(String::new())
        }
    }

    #[test]
    fn host_less_url_is_neither_scanned_nor_gate_bypassing() {
        let rec = Rec::default();
        let urls = vec![
            "https://app.example.com/".to_string(),
            "evil.com:8080/x".to_string(),
        ];
        scan_rows(&rec, &urls, &jsonl()).unwrap();
        let calls = rec.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (tool, args, targets) = &calls[0];
        assert_eq!(tool, "nuclei");
        assert_eq!(targets, &vec!["app.example.com".to_string()]);
        assert!(!args.iter().any(|a| a.contains("evil.com")));
        assert_eq!(rec.lists.borrow()[0], vec!["https://app.example.com/"]);
    }

    #[test]
    fn all_host_less_input_does_not_call_runner() {
        let rec = Rec::default();
        let urls = vec!["evil.com/x".to_string(), "evil.com:8080/x".to_string()];
        let out = scan_rows(&rec, &urls, &jsonl()).unwrap();
        assert!(out.is_empty());
        assert!(rec.calls.borrow().is_empty());
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
