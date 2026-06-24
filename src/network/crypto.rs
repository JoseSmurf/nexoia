use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Generate, KeyExport, MlKem768, Seed};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Par de chaves X25519 para troca segura.
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    secret: StaticSecret,
}

impl KeyPair {
    /// Gera novo par de chaves X25519.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { public_key, secret }
    }

    /// Cria par de chaves a partir de secret bytes (para carregar de arquivo).
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public_key = PublicKey::from(&secret);
        Self { public_key, secret }
    }

    /// Retorna a chave pública como bytes.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Retorna a chave privada como bytes (para persistência).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Realiza Diffie-Hellman X25519 e retorna o shared secret.
    pub fn diffie_hellman(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        *shared_secret.as_bytes()
    }

    /// Deriva shared secret com outro nó e cria cipher para encriptação.
    pub fn derive_cipher(&self, peer_public_bytes: &[u8; 32]) -> Result<ChaCha20Poly1305, String> {
        let shared_secret_bytes = self.diffie_hellman(peer_public_bytes);

        // Derive key usando HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(None, &shared_secret_bytes);
        let mut key = [0u8; 32];
        hk.expand(b"nexoia-epa-encryption", &mut key)
            .map_err(|e| format!("HKDF error: {}", e))?;

        Ok(ChaCha20Poly1305::new(&key.into()))
    }
}

/// Par de chaves ML-KEM-768 para proteção pós-quântica.
/// ML-KEM-768 é o padrão NIST FIPS 203, security category 3 (192-bit).
#[derive(Clone)]
pub struct MlKemKeyPair {
    /// Chave de encapsulamento (pública) — usada para criar shared secret.
    pub encapsulation_key: Vec<u8>,
    /// Seed de desencapsulamento (privada) — 64 bytes, usada para decapsular.
    decapsulation_key_seed: Vec<u8>,
}

/// Tamanho do ciphertext ML-KEM-768 em bytes (FIPS 203).
pub const ML_KEM_768_CT_SIZE: usize = 1088;

impl MlKemKeyPair {
    pub fn generate() -> Self {
        let dk = ml_kem::DecapsulationKey::<MlKem768>::generate();
        let ek = dk.encapsulation_key();
        Self {
            encapsulation_key: ek.to_bytes().to_vec(),
            decapsulation_key_seed: dk.to_bytes().to_vec(),
        }
    }

    pub fn from_bytes(
        encapsulation_key: &[u8],
        decapsulation_key_seed: &[u8],
    ) -> Result<Self, String> {
        let seed = Seed::try_from(decapsulation_key_seed)
            .map_err(|_| "Invalid decapsulation key seed length".to_string())?;
        let _dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
        Ok(Self {
            encapsulation_key: encapsulation_key.to_vec(),
            decapsulation_key_seed: decapsulation_key_seed.to_vec(),
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; 32]), String> {
        let dk = self.reconstruct_decapsulation_key()?;
        let ek = dk.encapsulation_key();
        let (ct, shared_secret) = ek.encapsulate();
        Ok((ct.to_vec(), *shared_secret.as_ref()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], String> {
        let dk = self.reconstruct_decapsulation_key()?;
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|e| format!("Invalid ciphertext: {:?}", e))?;
        let shared_secret = dk.decapsulate(&ct);
        Ok(*shared_secret.as_ref())
    }

    pub fn ciphertext_size() -> usize {
        ML_KEM_768_CT_SIZE
    }

    pub fn decapsulation_key_seed_bytes(&self) -> &[u8] {
        &self.decapsulation_key_seed
    }

    fn reconstruct_decapsulation_key(&self) -> Result<ml_kem::DecapsulationKey<MlKem768>, String> {
        let seed = Seed::try_from(self.decapsulation_key_seed.as_slice())
            .map_err(|_| "Invalid decapsulation key seed".to_string())?;
        Ok(ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed))
    }
}

/// Deriva chave de sessão híbrida combinando X25519 + ML-KEM.
///
/// A abordagem híbrida garante:
/// - X25519: Proteção contra falhas em implementações ML-KEM
/// - ML-KEM: Proteção contra ataques quânticos (harvest now, decrypt later)
///
/// Formato do IKM (Input Keying Material):
///   [32 bytes: x25519_shared] [32 bytes: ml_kem_shared] [32 bytes: nonce_local] [32 bytes: nonce_remote]
pub fn derive_hybrid_session_key(
    x25519_shared: &[u8; 32],
    ml_kem_shared: &[u8; 32],
    nonce_local: &[u8; 32],
    nonce_remote: &[u8; 32],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(ml_kem_shared);
    ikm.extend_from_slice(nonce_local);
    ikm.extend_from_slice(nonce_remote);

    // HKDF-SHA256 com info contextual
    let hk = Hkdf::<Sha256>::new(Some(b"nexoia-hybrid-session-v1"), &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"session-key", &mut key)
        .expect("HKDF expand failed");

    key
}

/// Encripta dados usando ChaCha20-Poly1305.
pub fn encrypt(data: &[u8], cipher: &ChaCha20Poly1305) -> Result<Vec<u8>, String> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut output = nonce.to_vec();
    output.extend(ciphertext);
    Ok(output)
}

/// Decripta dados usando ChaCha20-Poly1305.
pub fn decrypt(encrypted: &[u8], cipher: &ChaCha20Poly1305) -> Result<Vec<u8>, String> {
    if encrypted.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keypair_generate_and_dh() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared_alice = alice.diffie_hellman(&bob.public_bytes());
        let shared_bob = bob.diffie_hellman(&alice.public_bytes());

        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn ml_kem_keypair_generate_and_encapsulate() {
        let keypair = MlKemKeyPair::generate();
        let (ct, shared_secret_send) = keypair.encapsulate().unwrap();
        let shared_secret_recv = keypair.decapsulate(&ct).unwrap();

        assert_eq!(shared_secret_send, shared_secret_recv);
        assert_eq!(ct.len(), MlKemKeyPair::ciphertext_size());
    }

    #[test]
    fn hybrid_session_key_deterministic() {
        let x25519_shared = [1u8; 32];
        let ml_kem_shared = [2u8; 32];
        let nonce_a = [3u8; 32];
        let nonce_b = [4u8; 32];

        let key1 = derive_hybrid_session_key(&x25519_shared, &ml_kem_shared, &nonce_a, &nonce_b);
        let key2 = derive_hybrid_session_key(&x25519_shared, &ml_kem_shared, &nonce_a, &nonce_b);

        assert_eq!(key1, key2);
    }

    #[test]
    fn hybrid_key_different_inputs() {
        let key1 = derive_hybrid_session_key(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32]);
        let key2 = derive_hybrid_session_key(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[5u8; 32]);

        assert_ne!(key1, key2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let cipher_alice = alice.derive_cipher(&bob.public_bytes()).unwrap();
        let cipher_bob = bob.derive_cipher(&alice.public_bytes()).unwrap();

        let message = b"Hello, NexoIA!";
        let encrypted = encrypt(message, &cipher_alice).unwrap();
        let decrypted = decrypt(&encrypted, &cipher_bob).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let eve = KeyPair::generate();

        let cipher_alice = alice.derive_cipher(&bob.public_bytes()).unwrap();
        let cipher_eve = eve.derive_cipher(&bob.public_bytes()).unwrap();

        let message = b"Secret message";
        let encrypted = encrypt(message, &cipher_alice).unwrap();

        let result = decrypt(&encrypted, &cipher_eve);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let cipher_alice = alice.derive_cipher(&bob.public_bytes()).unwrap();
        let cipher_bob = bob.derive_cipher(&alice.public_bytes()).unwrap();

        let message = b"Important data";
        let mut encrypted = encrypt(message, &cipher_alice).unwrap();

        let last = encrypted.last_mut().unwrap();
        *last ^= 0xff;

        let result = decrypt(&encrypted, &cipher_bob);
        assert!(result.is_err());
    }
}
