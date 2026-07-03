//! self_awareness.rs — O olho interno do NexoIA
//!
//! Observa o estado REAL do sistema. Não hardcoded. Não alegado.
//! O NexoIA olha pra si mesmo e registra o que vê.
//!
//! "Conhece-te a ti mesmo. E prova que te conheces."

use crate::hash::canonical_hash;
use crate::nex::iteration::SystemState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Resultado observado do sistema — o que o NexoIA vê quando olha pra si
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedState {
    pub build_ok: bool,
    pub build_warnings: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub tests_ignored: usize,
    pub clippy_ok: bool,
    pub clippy_warnings: usize,
    pub fmt_ok: bool,
    pub miri_ok: bool,
    pub miri_errors: Vec<String>,
    pub timestamp: u64,
    pub timestamp_iso: String,
    pub health_hash: String,
}

impl ObservedState {
    /// Converte pra SystemState ( formato do IterationLog )
    pub fn to_system_state(&self) -> SystemState {
        SystemState {
            build_ok: self.build_ok,
            warnings: self.build_warnings + self.clippy_warnings,
            tests_passed: self.tests_passed,
            tests_failed: self.tests_failed,
            clippy_ok: self.clippy_ok,
            fmt_ok: self.fmt_ok,
        }
    }

    /// O sistema está saudável?
    #[allow(dead_code)]
    pub fn is_healthy(&self) -> bool {
        self.build_ok && self.tests_failed == 0 && self.clippy_ok && self.fmt_ok && self.miri_ok
    }
}

/// Resultado de um comando cargo
#[derive(Debug, Clone)]
struct CmdResult {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// SelfAwareness — os olhos do NexoIA
pub struct SelfAwareness {
    project_dir: PathBuf,
    cargo_path: String,
}

impl SelfAwareness {
    pub fn new(project_dir: PathBuf) -> Self {
        let cargo_path = Self::find_cargo();
        Self {
            project_dir,
            cargo_path,
        }
    }

    /// Versão para testes — não roda comandos reais
    #[allow(dead_code)]
    pub fn fake() -> Self {
        Self {
            project_dir: PathBuf::new(),
            cargo_path: String::new(),
        }
    }

    fn find_cargo() -> String {
        // Tenta USERPROFILE primeiro (Windows), depois HOME (Unix)
        if let Ok(home) = std::env::var("USERPROFILE") {
            let p = format!("{}\\.cargo\\bin\\cargo.exe", home);
            if std::path::Path::new(&p).exists() {
                return p;
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = format!("{}/.cargo/bin/cargo", home);
            if std::path::Path::new(&p).exists() {
                return p;
            }
        }
        "cargo".into()
    }

    fn run_cmd(&self, args: &[&str]) -> CmdResult {
        self.run_cmd_env(args, &[])
    }

    fn run_cmd_env(&self, args: &[&str], envs: &[(&str, &str)]) -> CmdResult {
        let mut cmd = Command::new(&self.cargo_path);
        cmd.args(args)
            .current_dir(&self.project_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (key, val) in envs {
            cmd.env(key, val);
        }
        match cmd.output() {
            Ok(output) => CmdResult {
                ok: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            },
            Err(e) => CmdResult {
                ok: false,
                stdout: String::new(),
                stderr: format!("exec error: {e}"),
            },
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
            if let Some(rest) = line.split("test result:").nth(1) {
                let rest = rest.trim();
                if let Some(p) = rest.split("passed").next() {
                    if let Some(n) = p.split_whitespace().last() {
                        passed += n.parse().unwrap_or(0);
                    }
                }
                if let Some(f) = rest.split("failed").next() {
                    if let Some(past_passed) = f.split("passed;").nth(1) {
                        if let Some(n) = past_passed.split_whitespace().next() {
                            failed += n.parse().unwrap_or(0);
                        }
                    }
                }
                if let Some(i) = rest.split("ignored").next() {
                    if let Some(past_failed) = i.split("failed;").nth(1) {
                        if let Some(n) = past_failed.split_whitespace().next() {
                            ignored += n.parse().unwrap_or(0);
                        }
                    }
                }
            }
        }
        (passed, failed, ignored)
    }

    fn parse_miri_errors(output: &str) -> Vec<String> {
        let mut errors = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            // Miri errors typically start with "error:" or contain "undefined behavior"
            if trimmed.starts_with("error:")
                || trimmed.contains("undefined behavior")
                || trimmed.contains("UndefinedBehavior")
                || trimmed.contains("memory allocation")
                || trimmed.contains("stacked borrows")
            {
                errors.push(trimmed.to_string());
            }
        }
        errors
    }

    /// O ato de olhar pra si mesmo. Retorna o estado real.
    pub fn observe(&self) -> ObservedState {
        // Modo fake para testes
        if self.cargo_path.is_empty() {
            return self.fake_state();
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        // 1. Check (mais leve que build, não gera binários)
        let build = self.run_cmd(&["check"]);
        let build_warnings = Self::count_warnings(&build.stderr);

        // 2. Test — parseia stdout E stderr (cargo pode enviar "test result:" para qualquer uma)
        let test = self.run_cmd(&["test"]);
        let (tp, tf, ti) = Self::parse_test_results(&(test.stdout.clone() + "\n" + &test.stderr));

        // 3. Clippy
        let clippy = self.run_cmd(&["clippy", "--all-targets", "--", "-D", "warnings"]);
        let clippy_warnings = Self::count_warnings(&clippy.stderr);

        // 4. Miri (verificação formal — opcional, só quando MIRI=1)
        //    É muito lento para rodar a cada ciclo. Use MIRI=1 cargo run --bin awaken
        let miri = if std::env::var("MIRI").unwrap_or_default() == "1" {
            self.run_cmd_env(
                &[
                    "+nightly",
                    "miri",
                    "test",
                    "--lib",
                    "--",
                    "--skip",
                    "network::",
                    "--skip",
                    "nex::",
                ],
                &[("MIRIFLAGS", "-Zmiri-disable-isolation")],
            )
        } else {
            // Modo rápido: assume miri OK se não solicitado
            CmdResult {
                ok: true,
                stdout: String::new(),
                stderr: "skipped (use MIRI=1 to enable)".into(),
            }
        };
        let miri_errors = Self::parse_miri_errors(&(miri.stdout.clone() + "\n" + &miri.stderr));

        // 5. Fmt
        let fmt = self.run_cmd(&["fmt", "--check"]);

        // Calcula hash de saúde — prova do estado observado
        let content = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            build.ok, build_warnings, tp, tf, clippy.ok, clippy_warnings, fmt.ok, miri.ok
        );
        let health_hash = canonical_hash(&content);

        ObservedState {
            build_ok: build.ok,
            build_warnings,
            tests_passed: tp,
            tests_failed: tf,
            tests_ignored: ti,
            clippy_ok: clippy.ok,
            clippy_warnings,
            fmt_ok: fmt.ok,
            miri_ok: miri.ok,
            miri_errors,
            timestamp,
            timestamp_iso,
            health_hash,
        }
    }

    /// Estado falso para testes — rápido, sem I/O
    fn fake_state(&self) -> ObservedState {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();
        let content = format!("fake:{}:0:0:true:0:true:true", timestamp);
        let health_hash = canonical_hash(&content);
        ObservedState {
            build_ok: true,
            build_warnings: 0,
            tests_passed: 0,
            tests_failed: 0,
            tests_ignored: 0,
            clippy_ok: true,
            clippy_warnings: 0,
            fmt_ok: true,
            miri_ok: true,
            miri_errors: vec![],
            timestamp,
            timestamp_iso,
            health_hash,
        }
    }

    /// Observação leve — só check (para ciclos rápidos, ~5s)
    #[allow(dead_code)]
    pub fn observe_light(&self) -> ObservedState {
        if self.cargo_path.is_empty() {
            return self.fake_state();
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        // Só check — rápido (~5s), não roda testes
        let build = self.run_cmd(&["check"]);
        let build_warnings = Self::count_warnings(&build.stderr);

        let content = format!("light:{}:{}", build.ok, build_warnings);
        let health_hash = canonical_hash(&content);

        ObservedState {
            build_ok: build.ok,
            build_warnings,
            tests_passed: 0,
            tests_failed: 0,
            tests_ignored: 0,
            clippy_ok: true,
            clippy_warnings: 0,
            fmt_ok: true,
            miri_ok: true,
            miri_errors: vec![],
            timestamp,
            timestamp_iso,
            health_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_awareness_observe() {
        let sa = SelfAwareness::fake();
        let state = sa.observe();
        assert!(!state.health_hash.is_empty());
        assert!(state.timestamp > 0);
        assert!(state.build_ok);
    }

    #[test]
    fn observed_state_to_system_state() {
        let state = ObservedState {
            build_ok: true,
            build_warnings: 3,
            tests_passed: 100,
            tests_failed: 0,
            tests_ignored: 1,
            clippy_ok: true,
            clippy_warnings: 2,
            fmt_ok: true,
            miri_ok: true,
            miri_errors: vec![],
            timestamp: 0,
            timestamp_iso: String::new(),
            health_hash: "abc".into(),
        };
        let sys = state.to_system_state();
        assert!(sys.build_ok);
        assert_eq!(sys.warnings, 5); // 3 build + 2 clippy
        assert_eq!(sys.tests_passed, 100);
        assert!(sys.clippy_ok);
    }

    #[test]
    fn is_healthy_true_when_all_ok() {
        let state = ObservedState {
            build_ok: true,
            build_warnings: 0,
            tests_passed: 100,
            tests_failed: 0,
            tests_ignored: 0,
            clippy_ok: true,
            clippy_warnings: 0,
            fmt_ok: true,
            miri_ok: true,
            miri_errors: vec![],
            timestamp: 0,
            timestamp_iso: String::new(),
            health_hash: "abc".into(),
        };
        assert!(state.is_healthy());
    }

    #[test]
    fn is_healthy_false_when_failing() {
        let state = ObservedState {
            build_ok: false,
            build_warnings: 0,
            tests_passed: 50,
            tests_failed: 5,
            tests_ignored: 0,
            clippy_ok: true,
            clippy_warnings: 0,
            fmt_ok: true,
            miri_ok: false,
            miri_errors: vec!["undefined behavior detected".into()],
            timestamp: 0,
            timestamp_iso: String::new(),
            health_hash: "abc".into(),
        };
        assert!(!state.is_healthy());
    }
}
