use crate::hash::canonical_hash;
use crate::network::crypto::{KeyPair, MlKemKeyPair};
use crate::network::crypto_key;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Identidade do nó na rede P2P.
/// Usa Ed25519 para assinatura, X25519 para encriptação e ML-KEM-768 para proteção pós-quântica.
#[derive(Clone)]
pub struct NodeIdentity {
    pub node_id: String,
    pub public_key: String,
    pub created_at: String,
    signing_key: SigningKey,
    /// Par de chaves X25519 para encriptação de payload
    pub encryption_keypair: KeyPair,
    /// Par de chaves ML-KEM-768 para proteção pós-quântica
    pub ml_kem_keypair: MlKemKeyPair,
}

impl NodeIdentity {
    /// Gera nova identidade com chaves Ed25519, X25519 e ML-KEM-768.
    pub fn generate(name: &str) -> Self {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let public_key = hex::encode(verifying_key.to_bytes());
        let timestamp = chrono::Utc::now().to_rfc3339();
        let node_id = canonical_hash(&format!("node:{}:{}", name, public_key));

        // Gera par de chaves X25519 para encriptação
        let encryption_keypair = KeyPair::generate();

        // Gera par de chaves ML-KEM-768 para proteção pós-quântica
        let ml_kem_keypair = MlKemKeyPair::generate();

        Self {
            node_id,
            public_key,
            created_at: timestamp,
            signing_key,
            encryption_keypair,
            ml_kem_keypair,
        }
    }

    /// Carrega identidade de arquivo ou cria nova.
    /// Se passphrase for fornecida, descriptografa as chaves privadas.
    pub fn load_or_create(
        path: &Path,
        name: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, std::io::Error> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            let saved: SavedIdentity = serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            // Descriptografa ou usa texto puro
            let signing_key = if let Some(encrypted) = &saved.encrypted_secret_key {
                let pass = passphrase.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Passphrase required to decrypt identity",
                    )
                })?;
                let decrypted = crypto_key::decrypt_with_passphrase(encrypted, pass)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let key_bytes: [u8; 32] = decrypted.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid key length after decrypt",
                    )
                })?;
                SigningKey::from_bytes(&key_bytes)
            } else {
                // Texto puro (compatibilidade)
                let key_bytes: [u8; 32] = saved.secret_key_bytes.try_into().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key length")
                })?;
                SigningKey::from_bytes(&key_bytes)
            };

            // Carrega par de chaves X25519
            let encryption_keypair = if let Some(encrypted) = &saved.encrypted_encryption_key {
                let pass = passphrase.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Passphrase required to decrypt encryption key",
                    )
                })?;
                let decrypted = crypto_key::decrypt_with_passphrase(encrypted, pass)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let secret_bytes: [u8; 32] = decrypted.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid encryption key after decrypt",
                    )
                })?;
                KeyPair::from_secret(secret_bytes)
            } else if !saved.encryption_secret_bytes.is_empty() {
                let secret_bytes: [u8; 32] =
                    saved.encryption_secret_bytes.try_into().map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid encryption key",
                        )
                    })?;
                KeyPair::from_secret(secret_bytes)
            } else {
                KeyPair::generate()
            };

            // Carrega par de chaves ML-KEM-768
            let ml_kem_keypair = {
                let ek_bytes = if let Some(encrypted) = &saved.ml_kem_encapsulation_key {
                    let pass = passphrase.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Passphrase required to decrypt ML-KEM key",
                        )
                    })?;
                    crypto_key::decrypt_with_passphrase(encrypted, pass)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                } else {
                    saved.ml_kem_encapsulation_key_bytes.clone()
                };
                let dk_bytes = if let Some(encrypted) = &saved.ml_kem_decapsulation_key {
                    let pass = passphrase.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Passphrase required to decrypt ML-KEM key",
                        )
                    })?;
                    crypto_key::decrypt_with_passphrase(encrypted, pass)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                } else {
                    saved.ml_kem_decapsulation_key_bytes.clone()
                };
                MlKemKeyPair::from_bytes(&ek_bytes, &dk_bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            };

            Ok(Self {
                node_id: saved.node_id,
                public_key: saved.public_key,
                created_at: saved.created_at,
                signing_key,
                encryption_keypair,
                ml_kem_keypair,
            })
        } else {
            let identity = Self::generate(name);
            identity.save(path, passphrase)?;
            Ok(identity)
        }
    }

    /// Salva identidade em arquivo.
    /// Se passphrase for fornecida, criptografa as chaves privadas.
    /// Força permissões 0600 no Unix.
    pub fn save(&self, path: &Path, passphrase: Option<&[u8]>) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let (
            secret_key_bytes,
            encryption_secret_bytes,
            encrypted_secret,
            encrypted_encryption,
            ml_kem_encapsulation_key_bytes,
            ml_kem_decapsulation_key_bytes,
            encrypted_ml_kem_ek,
            encrypted_ml_kem_dk,
        ) = if let Some(pass) = passphrase {
            // Criptografa chaves com passphrase
            let secret_encrypted =
                crypto_key::encrypt_with_passphrase(&self.signing_key.to_bytes(), pass)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let enc_key_encrypted =
                crypto_key::encrypt_with_passphrase(&self.encryption_keypair.secret_bytes(), pass)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            // Criptografa chaves ML-KEM
            let ml_kem_ek_encrypted =
                crypto_key::encrypt_with_passphrase(&self.ml_kem_keypair.encapsulation_key, pass)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let ml_kem_dk_encrypted = crypto_key::encrypt_with_passphrase(
                self.ml_kem_keypair.decapsulation_key_seed_bytes(),
                pass,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            (
                vec![], // Texto puro vazio
                vec![],
                Some(secret_encrypted),
                Some(enc_key_encrypted),
                vec![],
                vec![],
                Some(ml_kem_ek_encrypted),
                Some(ml_kem_dk_encrypted),
            )
        } else {
            // Sem passphrase — salva em texto puro com warning
            eprintln!(
                "⚠ WARNING: Saving identity WITHOUT passphrase. \
                 Set NEXOIA_PASSPHRASE to encrypt private keys."
            );
            (
                self.signing_key.to_bytes().to_vec(),
                self.encryption_keypair.secret_bytes().to_vec(),
                None,
                None,
                self.ml_kem_keypair.encapsulation_key.clone(),
                self.ml_kem_keypair.decapsulation_key_seed_bytes().to_vec(),
                None,
                None,
            )
        };

        let saved = SavedIdentity {
            node_id: self.node_id.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at.clone(),
            secret_key_bytes,
            encryption_secret_bytes,
            encryption_public_bytes: self.encryption_keypair.public_bytes().to_vec(),
            encrypted_secret_key: encrypted_secret,
            encrypted_encryption_key: encrypted_encryption,
            ml_kem_encapsulation_key_bytes,
            ml_kem_decapsulation_key_bytes,
            ml_kem_encapsulation_key: encrypted_ml_kem_ek,
            ml_kem_decapsulation_key: encrypted_ml_kem_dk,
        };

        let data = serde_json::to_string_pretty(&saved)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, data)?;

        // Força permissões 0600 no Unix
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
            encryption_secret_bytes: self.encryption_keypair.secret_bytes().to_vec(),
            encryption_public_bytes: self.encryption_keypair.public_bytes().to_vec(),
            ml_kem_encapsulation_key_bytes: self.ml_kem_keypair.encapsulation_key.clone(),
            ml_kem_decapsulation_key_bytes: self.ml_kem_keypair.decapsulation_key_seed_bytes().to_vec(),
            encrypted_secret_key: None,
            encrypted_encryption_key: None,
            ml_kem_encapsulation_key: None,
            ml_kem_decapsulation_key: None,
        };
        saved.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodeIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let saved = SavedIdentity::deserialize(deserializer)?;

        // Descriptografa ou usa texto puro
        let signing_key = if let Some(encrypted) = &saved.encrypted_secret_key {
            // Não podemos descriptografar sem passphrase no contexto de deserialização
            // Retorna erro indicando que passphrase é necessária
            return Err(serde::de::Error::custom(
                "Encrypted identity requires passphrase. Use load_or_create() instead.",
            ));
        } else {
            let key_bytes: [u8; 32] = saved
                .secret_key_bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid key length"))?;
            SigningKey::from_bytes(&key_bytes)
        };

        // Carrega par de chaves X25519
        let encryption_keypair = if let Some(encrypted) = &saved.encrypted_encryption_key {
            return Err(serde::de::Error::custom(
                "Encrypted identity requires passphrase. Use load_or_create() instead.",
            ));
        } else if !saved.encryption_secret_bytes.is_empty() {
            let secret_bytes: [u8; 32] = saved
                .encryption_secret_bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid encryption key"))?;
            KeyPair::from_secret(secret_bytes)
        } else {
            KeyPair::generate()
        };

        // Carrega par de chaves ML-KEM-768
        let ml_kem_keypair = if saved.ml_kem_encapsulation_key.is_some()
            || saved.ml_kem_decapsulation_key.is_some()
        {
            return Err(serde::de::Error::custom(
                "Encrypted ML-KEM identity requires passphrase. Use load_or_create() instead.",
            ));
        } else if !saved.ml_kem_encapsulation_key_bytes.is_empty() {
            MlKemKeyPair::from_bytes(&saved.ml_kem_encapsulation_key_bytes, &saved.ml_kem_decapsulation_key_bytes)
                .map_err(|e| serde::de::Error::custom(format!("invalid ML-KEM key: {}", e)))?
        } else {
            MlKemKeyPair::generate()
        };

        Ok(Self {
            node_id: saved.node_id,
            public_key: saved.public_key,
            created_at: saved.created_at,
            signing_key,
            encryption_keypair,
            ml_kem_keypair,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedIdentity {
    node_id: String,
    public_key: String,
    created_at: String,
    /// Chaves em texto puro (quando não há passphrase)
    secret_key_bytes: Vec<u8>,
    encryption_secret_bytes: Vec<u8>,
    encryption_public_bytes: Vec<u8>,
    /// Chaves ML-KEM em texto puro (quando não há passphrase)
    #[serde(default)]
    ml_kem_encapsulation_key_bytes: Vec<u8>,
    #[serde(default)]
    ml_kem_decapsulation_key_bytes: Vec<u8>,
    /// Chaves criptografadas (quando há passphrase)
    encrypted_secret_key: Option<Vec<u8>>,
    encrypted_encryption_key: Option<Vec<u8>>,
    /// Chaves ML-KEM criptografadas (quando há passphrase)
    #[serde(default)]
    ml_kem_encapsulation_key: Option<Vec<u8>>,
    #[serde(default)]
    ml_kem_decapsulation_key: Option<Vec<u8>>,
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

        let a = NodeIdentity::load_or_create(&path, "persist_test", None).unwrap();
        let b = NodeIdentity::load_or_create(&path, "persist_test", None).unwrap();

        assert_eq!(a.node_id, b.node_id);
        assert_eq!(a.public_key, b.public_key);
    }

    #[test]
    fn load_or_create_with_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let passphrase = b"test-passphrase";

        // Cria identidade com passphrase
        let a = NodeIdentity::load_or_create(&path, "passphrase_test", Some(passphrase)).unwrap();

        // Carrega com mesma passphrase
        let b = NodeIdentity::load_or_create(&path, "passphrase_test", Some(passphrase)).unwrap();
        assert_eq!(a.node_id, b.node_id);
        assert_eq!(a.public_key, b.public_key);

        // Falha com passphrase errada
        let c = NodeIdentity::load_or_create(&path, "passphrase_test", Some(b"wrong"));
        assert!(c.is_err());
    }
}
