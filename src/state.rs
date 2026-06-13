use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Scenario {
    Auto,
    Ok,
    Violacao,
    Absterse,
}

impl Scenario {
    fn from_env(raw: Option<String>) -> Result<Self, String> {
        let value = raw.unwrap_or_else(|| "auto".to_string());
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "ok" => Ok(Self::Ok),
            "violacao" => Ok(Self::Violacao),
            "absterse" | "abster-se" | "abstain" => Ok(Self::Absterse),
            other => Err(format!(
                "invalid NEXOIA_SCENARIO value '{other}'. Use auto, ok, violacao, or absterse."
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "AUTO",
            Self::Ok => "OK",
            Self::Violacao => "VIOLACAO",
            Self::Absterse => "ABSTERSE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub project: String,
    pub run_id: Uuid,
    pub generated_at_utc: DateTime<Utc>,
    pub scenario: Scenario,
    pub subject: String,
    pub threshold: i64,
    pub input_value: Option<i64>,
}

impl State {
    pub fn from_env() -> Result<Self, String> {
        let project = "nexoia".to_string();
        let scenario = Scenario::from_env(env::var("NEXOIA_SCENARIO").ok())?;
        let subject =
            env::var("NEXOIA_SUBJECT").unwrap_or_else(|_| "default-evaluation".to_string());
        let threshold = parse_i64_env("NEXOIA_THRESHOLD", 50)?;
        let input_value = parse_optional_i64_env("NEXOIA_INPUT_VALUE", Some(60))?;
        let generated_at_utc = Utc::now();
        let run_id = deterministic_run_id(&project, scenario, &subject, threshold, input_value);

        Ok(Self {
            project,
            run_id,
            generated_at_utc,
            scenario,
            subject,
            threshold,
            input_value,
        })
    }
}

fn parse_i64_env(name: &str, default: i64) -> Result<i64, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .parse::<i64>()
            .map_err(|err| format!("invalid {name} value '{value}': {err}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(format!("failed to read {name}: {err}")),
    }
}

fn parse_optional_i64_env(name: &str, default: Option<i64>) -> Result<Option<i64>, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .parse::<i64>()
            .map(Some)
            .map_err(|err| format!("invalid {name} value '{value}': {err}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(format!("failed to read {name}: {err}")),
    }
}

fn deterministic_run_id(
    project: &str,
    scenario: Scenario,
    subject: &str,
    threshold: i64,
    input_value: Option<i64>,
) -> Uuid {
    let name = format!(
        "{project}|{}|{subject}|{threshold}|{:?}",
        scenario.as_str(),
        input_value
    );
    Uuid::new_v5(&Uuid::NAMESPACE_URL, name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{deterministic_run_id, Scenario};
    use uuid::Uuid;

    #[test]
    fn deterministic_run_id_is_stable() {
        let a = deterministic_run_id("nexoia", Scenario::Ok, "subject", 50, Some(60));
        let b = deterministic_run_id("nexoia", Scenario::Ok, "subject", 50, Some(60));
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_as_str_matches_output_contract() {
        assert_eq!(Scenario::Auto.as_str(), "AUTO");
        assert_eq!(Scenario::Ok.as_str(), "OK");
        assert_eq!(Scenario::Violacao.as_str(), "VIOLACAO");
        assert_eq!(Scenario::Absterse.as_str(), "ABSTERSE");
    }

    #[test]
    fn deterministic_run_id_changes_when_inputs_change() {
        let a = deterministic_run_id("nexoia", Scenario::Ok, "subject", 50, Some(60));
        let b = deterministic_run_id("nexoia", Scenario::Violacao, "subject", 50, Some(60));
        assert_ne!(a, b);
        assert_ne!(a, Uuid::nil());
    }
}
