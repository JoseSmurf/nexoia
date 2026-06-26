use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LawfulBasis {
    Consentimento,
    Contrato,
    ObrigacaoLegal,
    InteresseLegitimo,
    VidaFisica,
    FuncaoPublica,
    InteresseVital,
}

impl fmt::Display for LawfulBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Consentimento => "Consentimento",
            Self::Contrato => "Contrato",
            Self::ObrigacaoLegal => "Obrigacao Legal",
            Self::InteresseLegitimo => "Interesse Legitimo",
            Self::VidaFisica => "Vida Fisica ou Saude",
            Self::FuncaoPublica => "Execucao de Politica Publica",
            Self::InteresseVital => "Protecao da Vida",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LgpdMetadata {
    pub lawful_basis: LawfulBasis,
    pub purpose: String,
    pub retention_days: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_subject_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpia_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LgpdError {
    EmptyPurpose,
    ZeroRetention,
}

impl fmt::Display for LgpdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPurpose => write!(f, "LGPD purpose must not be empty"),
            Self::ZeroRetention => write!(f, "LGPD retention_days must be > 0"),
        }
    }
}

impl std::error::Error for LgpdError {}

impl LgpdMetadata {
    pub fn validate(&self) -> Result<(), LgpdError> {
        if self.purpose.trim().is_empty() {
            return Err(LgpdError::EmptyPurpose);
        }
        if self.retention_days == 0 {
            return Err(LgpdError::ZeroRetention);
        }
        Ok(())
    }
}

pub fn parse_lgpd_basis(raw: &str) -> Result<LawfulBasis, String> {
    match raw.to_ascii_lowercase().as_str() {
        "consentimento" | "consent" => Ok(LawfulBasis::Consentimento),
        "contrato" | "contract" => Ok(LawfulBasis::Contrato),
        "obrigacao_legal" | "obrigacao-legal" | "legal_obligation" => {
            Ok(LawfulBasis::ObrigacaoLegal)
        }
        "interesse_legitimo" | "interesse-legitimo" | "legitimate_interest" => {
            Ok(LawfulBasis::InteresseLegitimo)
        }
        "vida_fisica" | "vida-fisica" | "life" => Ok(LawfulBasis::VidaFisica),
        "funcao_publica" | "funcao-publica" | "public_policy" => Ok(LawfulBasis::FuncaoPublica),
        "interesse_vital" | "interesse-vital" | "vital_interest" => Ok(LawfulBasis::InteresseVital),
        other => Err(format!(
            "invalid LGPD lawful basis '{other}'. Use: consentimento, contrato, obrigacao_legal, \
             interesse_legitimo, vida_fisica, funcao_publica, interesse_vital"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> LgpdMetadata {
        LgpdMetadata {
            lawful_basis: LawfulBasis::Consentimento,
            purpose: "processamento_pedido".to_string(),
            retention_days: 365,
            data_subject_hash: Some("a1b2c3d4e5f6".to_string()),
            dpia_ref: None,
            consent_id: Some("consent_abc123".to_string()),
        }
    }

    #[test]
    fn valid_metadata_passes_validation() {
        let meta = sample_metadata();
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn empty_purpose_fails_validation() {
        let mut meta = sample_metadata();
        meta.purpose = "  ".to_string();
        assert_eq!(meta.validate(), Err(LgpdError::EmptyPurpose));
    }

    #[test]
    fn zero_retention_fails_validation() {
        let mut meta = sample_metadata();
        meta.retention_days = 0;
        assert_eq!(meta.validate(), Err(LgpdError::ZeroRetention));
    }

    #[test]
    fn serialization_skips_none_fields() {
        let meta = LgpdMetadata {
            lawful_basis: LawfulBasis::Contrato,
            purpose: "execucao_contrato".to_string(),
            retention_days: 730,
            data_subject_hash: None,
            dpia_ref: None,
            consent_id: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("data_subject_hash"));
        assert!(!json.contains("dpia_ref"));
        assert!(!json.contains("consent_id"));
        assert!(json.contains("lawful_basis"));
        assert!(json.contains("purpose"));
        assert!(json.contains("retention_days"));
    }

    #[test]
    fn serialization_includes_some_fields() {
        let meta = sample_metadata();
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("data_subject_hash"));
        assert!(json.contains("consent_id"));
    }

    #[test]
    fn parse_lgpd_basis_valid() {
        assert_eq!(
            parse_lgpd_basis("consentimento").unwrap(),
            LawfulBasis::Consentimento
        );
        assert_eq!(
            parse_lgpd_basis("obrigacao_legal").unwrap(),
            LawfulBasis::ObrigacaoLegal
        );
        assert_eq!(
            parse_lgpd_basis("CONSENT").unwrap(),
            LawfulBasis::Consentimento
        );
    }

    #[test]
    fn parse_lgpd_basis_invalid() {
        assert!(parse_lgpd_basis("invalido").is_err());
        assert!(parse_lgpd_basis("").is_err());
    }

    #[test]
    fn lawful_basis_display() {
        assert_eq!(LawfulBasis::Consentimento.to_string(), "Consentimento");
        assert_eq!(LawfulBasis::ObrigacaoLegal.to_string(), "Obrigacao Legal");
        assert_eq!(LawfulBasis::VidaFisica.to_string(), "Vida Fisica ou Saude");
    }

    #[test]
    fn metadata_roundtrip() {
        let meta = sample_metadata();
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: LgpdMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, deserialized);
    }
}
