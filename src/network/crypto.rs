use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

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

    /// Deriva shared secret com outro nó e cria cipher para encriptação.
    pub fn derive_cipher(&self, peer_public_bytes: &[u8; 32]) -> Result<ChaCha20Poly1305, String> {
        let peer_public = PublicKey::from(*peer_public_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_public);

        // Derive key usando HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"nexoia-epa-encryption", &mut key)
            .map_err(|e| format!("HKDF error: {}", e))?;

        Ok(ChaCha20Poly1305::new(&key.into()))
    }
}

/// Encripta dados usando ChaCha20-Poly1305.
pub fn encrypt(data: &[u8], cipher: &ChaCha20Poly1305) -> Result<Vec<u8>, String> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    // Formato: nonce (12 bytes) + ciphertext
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

        // Eve tenta decriptar com sua chave
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

        // Altera último byte
        let last = encrypted.last_mut().unwrap();
        *last ^= 0xff;

        let result = decrypt(&encrypted, &cipher_bob);
        assert!(result.is_err());
    }
}
