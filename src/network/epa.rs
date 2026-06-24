use crate::hash::canonical_hash;
use crate::network::crypto::{self, KeyPair};
use crate::network::identity::{verify_signature, NodeIdentity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Janela de validade do timestamp: 5 minutos para trás e 2 minutos para frente.
const TIMESTAMP_MAX_AGE_SECS: i64 = 300;
const TIMESTAMP_MAX_FUTURE_SECS: i64 = 120;

/// EPA compartilhável na rede P2P.
/// Inclui assinatura Ed25519 real e timestamp para prevenir replay attacks.
/// Suporta payload encriptado opcional para privacidade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedEPA {
    pub epa_id: String,
    pub node_id: String,
    pub public_key: String,
    pub ed25519_signature: Vec<u8>,
    pub state_hash: String,
    pub evidence_hash: String,
    pub decision_hash: String,
    pub manifest_hash: String,
    pub timestamp: String,
    pub integrity_hash: String,
    /// Payload encriptado (opcional). Formato: nonce (12 bytes) + ciphertext.
    pub encrypted_payload: Option<Vec<u8>>,
    /// Chave pública efêmera X25519 usada na encriptação (obtida via ECDH).
    /// Presente apenas quando `encrypted_payload` é Some.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ephemeral_public_key: Option<Vec<u8>>,
}

/// Resultado da verificação de EPA.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyError {
    IntegrityFailed,
    SignatureFailed,
    TimestampExpired,
    TimestampTooNew,
    TimestampInvalid,
    MissingPublicKey,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::IntegrityFailed => write!(f, "integrity hash mismatch"),
            VerifyError::SignatureFailed => write!(f, "Ed25519 signature invalid"),
            VerifyError::TimestampExpired => write!(f, "timestamp older than 5 minutes"),
            VerifyError::TimestampTooNew => {
                write!(f, "timestamp more than 2 minutes in the future")
            }
            VerifyError::TimestampInvalid => write!(f, "timestamp parse error"),
            VerifyError::MissingPublicKey => write!(f, "public key not provided"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl SharedEPA {
    /// Cria EPA com assinatura Ed25519 (sem encriptação).
    pub fn create(
        node: &NodeIdentity,
        state_json: &str,
        evidence_jsonl: &str,
        decisions_jsonl: &str,
        manifest_json: &str,
    ) -> Self {
        let state_hash = canonical_hash(state_json);
        let evidence_hash = canonical_hash(evidence_jsonl);
        let decision_hash = canonical_hash(decisions_jsonl);
        let manifest_hash = canonical_hash(manifest_json);

        let content = format!(
            "{}:{}:{}:{}:{}",
            node.node_id, state_hash, evidence_hash, decision_hash, manifest_hash
        );
        let integrity_hash = canonical_hash(&content);

        // Assina o integrity_hash com Ed25519
        let signature = node.sign(&integrity_hash);

        Self {
            epa_id: integrity_hash[..16].to_string(),
            node_id: node.node_id.clone(),
            public_key: node.public_key.clone(),
            ed25519_signature: signature,
            state_hash,
            evidence_hash,
            decision_hash,
            manifest_hash,
            timestamp: Utc::now().to_rfc3339(),
            integrity_hash,
            encrypted_payload: None,
            ephemeral_public_key: None,
        }
    }

    /// Cria EPA com payload encriptado para um destinatário específico.
    pub fn create_encrypted(
        node: &NodeIdentity,
        state_json: &str,
        evidence_jsonl: &str,
        decisions_jsonl: &str,
        manifest_json: &str,
        recipient_public_key: &[u8; 32],
    ) -> Result<Self, String> {
        let mut epa = Self::create(
            node,
            state_json,
            evidence_jsonl,
            decisions_jsonl,
            manifest_json,
        );

        // Encripta o conteúdo sensível
        let sensitive_data = format!(
            "{}|{}|{}|{}",
            state_json, evidence_jsonl, decisions_jsonl, manifest_json
        );

        let keypair = KeyPair::generate();
        let cipher = keypair.derive_cipher(recipient_public_key)?;
        let encrypted = crypto::encrypt(sensitive_data.as_bytes(), &cipher)?;

        epa.encrypted_payload = Some(encrypted);
        epa.ephemeral_public_key = Some(keypair.public_bytes().to_vec());
        Ok(epa)
    }

    /// Decripta o payload usando chave privada do destinatário.
    /// A chave pública efêmera é obtida do campo `ephemeral_public_key` do EPA.
    pub fn decrypt_payload(
        &self,
        recipient_keypair: &KeyPair,
    ) -> Result<String, String> {
        let encrypted = self
            .encrypted_payload
            .as_ref()
            .ok_or("No encrypted payload")?;

        let ephemeral_pub = self
            .ephemeral_public_key
            .as_ref()
            .ok_or("No ephemeral public key in EPA")?;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(ephemeral_pub);

        let cipher = recipient_keypair.derive_cipher(&key_arr)?;
        let decrypted = crypto::decrypt(encrypted, &cipher)?;

        String::from_utf8(decrypted).map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    /// Verifica integridade do hash (sem assinatura).
    pub fn verify_integrity(&self) -> bool {
        let content = format!(
            "{}:{}:{}:{}:{}",
            self.node_id,
            self.state_hash,
            self.evidence_hash,
            self.decision_hash,
            self.manifest_hash
        );
        let expected = canonical_hash(&content);
        self.integrity_hash == expected
    }

    /// Verifica assinatura Ed25519 completa.
    pub fn verify_signature(&self) -> Result<(), VerifyError> {
        if self.public_key.is_empty() {
            return Err(VerifyError::MissingPublicKey);
        }

        let sig_valid = verify_signature(
            &self.public_key,
            self.integrity_hash.as_bytes(),
            &self.ed25519_signature,
        )
        .unwrap_or(false);

        if !sig_valid {
            return Err(VerifyError::SignatureFailed);
        }

        Ok(())
    }

    /// Verifica se o timestamp está dentro da janela aceitável.
    /// Rejeita timestamps muito antigos (>5 min) ou muito futuros (>2 min).
    pub fn verify_timestamp(&self) -> Result<(), VerifyError> {
        let ts: DateTime<Utc> = self
            .timestamp
            .parse()
            .map_err(|_| VerifyError::TimestampInvalid)?;

        let now = Utc::now();
        let age = now - ts;

        // Rejeita se muito antigo (replay attack)
        if age.num_seconds() > TIMESTAMP_MAX_AGE_SECS {
            return Err(VerifyError::TimestampExpired);
        }

        // Rejeita se muito no futuro (clock skew attack)
        if age.num_seconds() < -TIMESTAMP_MAX_FUTURE_SECS {
            return Err(VerifyError::TimestampTooNew);
        }

        Ok(())
    }

    /// Verificação completa: integridade + assinatura + timestamp.
    pub fn verify_full(&self) -> Result<(), VerifyError> {
        if !self.verify_integrity() {
            return Err(VerifyError::IntegrityFailed);
        }
        self.verify_signature()?;
        self.verify_timestamp()?;
        Ok(())
    }
}

impl fmt::Display for SharedEPA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EPA({}) from {} @ {}",
            self.epa_id,
            &self.node_id[..12.min(self.node_id.len())],
            &self.timestamp[..10.min(self.timestamp.len())]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> (String, String, String, String) {
        (
            r#"{"project":"test"}"#.to_string(),
            r#"{"evidence":"data"}"#.to_string(),
            r#"{"decision":"ok"}"#.to_string(),
            r#"{"manifest":"v1"}"#.to_string(),
        )
    }

    #[test]
    fn create_and_verify_full() {
        let node = NodeIdentity::generate("test_node");
        let (state, evidence, decision, manifest) = sample_data();

        let epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        assert!(epa.verify_full().is_ok());
    }

    #[test]
    fn tampered_epa_fails_integrity() {
        let node = NodeIdentity::generate("test_node");
        let (state, evidence, decision, manifest) = sample_data();

        let mut epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        epa.state_hash = "tampered".to_string();

        assert_eq!(epa.verify_full(), Err(VerifyError::IntegrityFailed));
    }

    #[test]
    fn wrong_signature_fails() {
        let node = NodeIdentity::generate("test_node");
        let wrong_node = NodeIdentity::generate("wrong_node");
        let (state, evidence, decision, manifest) = sample_data();

        let mut epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        // Re-assina com chave errada
        epa.ed25519_signature = wrong_node.sign(&epa.integrity_hash);

        assert_eq!(epa.verify_full(), Err(VerifyError::SignatureFailed));
    }

    #[test]
    fn expired_timestamp_fails() {
        let node = NodeIdentity::generate("test_node");
        let (state, evidence, decision, manifest) = sample_data();

        let mut epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        // Timestamp de 10 minutos atrás
        epa.timestamp = (Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();

        assert_eq!(epa.verify_full(), Err(VerifyError::TimestampExpired));
    }
}
