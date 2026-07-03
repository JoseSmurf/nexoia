//! daemon.rs — NexoIA Heartbeat
//!
//! Processo que verifica saudabilidade do sistema e gera relatório com BLAKE3.
//! Uso: cargo run --bin daemon

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn canonical_hash(data: &str) -> String {
    blake3::hash(data.as_bytes()).to_hex().to_string()
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn run_cmd(exe: &str, args: &[&str], cwd: &PathBuf) -> (bool, String) {
    match Command::new(exe).args(args).current_dir(cwd).output() {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            (out.status.success(), stderr)
        }
        Err(e) => (false, format!("exec error: {e}")),
    }
}

fn count_warnings(output: &str) -> usize {
    output.lines().filter(|l| l.contains("warning:")).count()
}

fn parse_test_results(output: &str) -> (usize, usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut ignored = 0usize;
    for line in output.lines() {
        if !line.contains("test result:") {
            continue;
        }
        // Format: "test result: ok. 226 passed; 0 failed; 0 ignored; ..."
        if let Some(rest) = line.split("test result:").nth(1) {
            let rest = rest.trim();
            if let Some(p) = rest.split("passed").next() {
                if let Some(n) = p.split_whitespace().last() {
                    passed += n.parse().unwrap_or(0);
                }
            }
            if let Some(f) = rest.split("failed").next() {
                if let Some(past_passed) = f.split("passed;").nth(1) {
                    if let Some(n) = past_passed.trim().split_whitespace().next() {
                        failed += n.parse().unwrap_or(0);
                    }
                }
            }
            if let Some(i) = rest.split("ignored").next() {
                if let Some(past_failed) = i.split("failed;").nth(1) {
                    if let Some(n) = past_failed.trim().split_whitespace().next() {
                        ignored += n.parse().unwrap_or(0);
                    }
                }
            }
        }
    }
    (passed, failed, ignored)
}

fn cargo_path() -> String {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    format!("{}\\.cargo\\bin\\cargo.exe", home)
}

fn main() {
    println!("╔═══════════════════════════════════════════════╗");
    println!("║  NexoIA Daemon — Heartbeat                    ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_dir = project_dir.join("data").join("health");
    fs::create_dir_all(&data_dir).ok();

    let cargo = cargo_path();
    let timestamp = now_timestamp();
    let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();

    // 1. Build
    println!("[1/4] cargo build...");
    let (build_ok, build_err) = run_cmd(&cargo, &["build"], &project_dir);
    let build_warnings = count_warnings(&build_err);
    println!("  → {} ({} warnings)", if build_ok { "OK" } else { "FAIL" }, build_warnings);

    // 2. Test
    println!("[2/4] cargo test...");
    let (_, test_err) = run_cmd(&cargo, &["test"], &project_dir);
    let (tp, tf, ti) = parse_test_results(&test_err);
    println!("  → {} passed, {} failed, {} ignored", tp, tf, ti);

    // 3. Clippy
    println!("[3/4] cargo clippy...");
    let (clippy_ok, clippy_err) = run_cmd(&cargo, &["clippy", "--all-targets", "--", "-D", "warnings"], &project_dir);
    let clippy_warnings = count_warnings(&clippy_err);
    println!("  → {} ({} warnings)", if clippy_ok { "OK" } else { "FAIL" }, clippy_warnings);

    // 4. Fmt
    println!("[4/4] cargo fmt --check...");
    let (fmt_ok, _) = run_cmd(&cargo, &["fmt", "--check"], &project_dir);
    println!("  → {}", if fmt_ok { "OK" } else { "NEEDS FMT" });

    // Compute overall hash
    let overall_content = format!("{}:{}:{}:{}:{}:{}:{}", build_ok, build_warnings, tp, tf, clippy_ok, clippy_warnings, fmt_ok);
    let overall_hash = canonical_hash(&overall_content);

    let healthy = build_ok && tf == 0 && clippy_ok && fmt_ok;

    // Build JSON report
    let report = format!(
        r#"{{
  "timestamp": {},
  "timestamp_iso": "{}",
  "project": "nexoia",
  "build_ok": {},
  "build_warnings": {},
  "tests_passed": {},
  "tests_failed": {},
  "tests_ignored": {},
  "clippy_ok": {},
  "clippy_warnings": {},
  "fmt_ok": {},
  "healthy": {},
  "overall_hash": "{}"
}}"#,
        timestamp, timestamp_iso, build_ok, build_warnings, tp, tf, ti, clippy_ok, clippy_warnings, fmt_ok, healthy, overall_hash
    );

    // Save report
    let filename = format!("health_{}.json", timestamp);
    let filepath = data_dir.join(&filename);
    fs::write(&filepath, &report).ok();
    fs::write(data_dir.join("latest.json"), &report).ok();

    println!("\n═══════════════════════════════════════════════");
    println!("Health Hash: {}", &overall_hash[..16]);
    println!("Status: {}", if healthy { "HEALTHY ✓" } else { "NEEDS ATTENTION ⚠" });
    println!("Report: {}", filepath.display());
    println!("═══════════════════════════════════════════════");
}
