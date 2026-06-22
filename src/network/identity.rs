use crate::hash::canonical_hash;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Identidade do nó na rede P2P.
/// Usa Ed25519 para assinatura e verificação de mensagens.
#[derive(Clone)]
pub struct NodeIdentity {
    pub node_id: String,
    pub public_key: String,
    pub created_at: String,
    signing_key: SigningKey,
}

impl NodeIdentity {
    /// Gera nova identidade com chaves Ed25519 aleatórias.
    pub fn generate(name: &str) -> Self {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let public_key = hex::encode(verifying_key.to_bytes());
        let timestamp = chrono::Utc::now().to_rfc3339();
        let node_id = canonical_hash(&format!("node:{}:{}", name, public_key));

        Self {
            node_id,
            public_key,
            created_at: timestamp,
            signing_key,
        }
    }

    /// Carrega identidade de arquivo ou cria nova.
    pub fn load_or_create(path: &Path, name: &str) -> Result<Self, std::io::Error> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            let saved: SavedIdentity = serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let key_bytes: [u8; 32] = saved.secret_key_bytes.try_into().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key length")
            })?;
            let signing_key = SigningKey::from_bytes(&key_bytes);

            Ok(Self {
                node_id: saved.node_id,
                public_key: saved.public_key,
                created_at: saved.created_at,
                signing_key,
            })
        } else {
            let identity = Self::generate(name);
            identity.save(path)?;
            Ok(identity)
        }
    }

    /// Salva identidade (incluindo chave privada) em arquivo.
    /// Força permissões 0600 no Unix (somente owner pode ler/escrever).
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let saved = SavedIdentity {
            node_id: self.node_id.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at.clone(),
            secret_key_bytes: self.signing_key.to_bytes().to_vec(),
        };
        let data = serde_json::to_string_pretty(&saved)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, data)?;

        // Força permissões 0600 no Unix (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Assina dados com a chave privada Ed25519.
    pub fn sign(&self, data: &str) -> Vec<u8> {
        self.signing_key.sign(data.as_bytes()).to_bytes().to_vec()
    }

    /// Retorna o VerifyingKey (chave pública Ed25519).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl Serialize for NodeIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let saved = SavedIdentity {
            node_id: self.node_id.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at.clone(),
            secret_key_bytes: self.signing_key.to_bytes().to_vec(),
        };
        saved.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodeIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let saved = SavedIdentity::deserialize(deserializer)?;
        let key_bytes: [u8; 32] = saved
            .secret_key_bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Self {
            node_id: saved.node_id,
            public_key: saved.public_key,
            created_at: saved.created_at,
            signing_key,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedIdentity {
    node_id: String,
    public_key: String,
    created_at: String,
    secret_key_bytes: Vec<u8>,
}

impl fmt::Display for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({})", &self.node_id[..12.min(self.node_id.len())])
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("public_key", &self.public_key)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Verifica assinatura Ed25519 de dados.
pub fn verify_signature(
    public_key_hex: &str,
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(public_key_hex)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid public key length")?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)?;

    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "invalid signature length")?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(data, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_creates_unique_identities() {
        let a = NodeIdentity::generate("node_a");
        let b = NodeIdentity::generate("node_b");
        assert_ne!(a.node_id, b.node_id);
    }

    #[test]
    fn sign_and_verify_with_ed25519() {
        let node = NodeIdentity::generate("test_node");
        let data = "important evidence";
        let sig = node.sign(data);

        let result = verify_signature(&node.public_key, data.as_bytes(), &sig);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let node = NodeIdentity::generate("test_node");
        let wrong_node = NodeIdentity::generate("wrong_node");
        let data = "important evidence";
        let sig = node.sign(data);

        let result = verify_signature(&wrong_node.public_key, data.as_bytes(), &sig);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn tampered_data_fails_verification() {
        let node = NodeIdentity::generate("test_node");
        let data = "important evidence";
        let sig = node.sign(data);

        let result = verify_signature(&node.public_key, b"tampered data", &sig);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");

        let a = NodeIdentity::load_or_create(&path, "persist_test").unwrap();
        let b = NodeIdentity::load_or_create(&path, "persist_test").unwrap();

        assert_eq!(a.node_id, b.node_id);
        assert_eq!(a.public_key, b.public_key);
    }
}
