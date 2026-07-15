//! crypto_key.rs — Proteção de chaves privadas com passphrase
//!
//! Criptografa/descriptografa chaves privadas usando PBKDF2 + AES-256-GCM.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Criptografa dados com passphrase.
/// Formato: salt (16 bytes) + nonce (12 bytes) + ciphertext
pub fn encrypt_with_passphrase(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    use rand::RngCore;
    OsRng.fill_bytes(&mut salt);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(passphrase, &salt, PBKDF2_ITERATIONS, key.as_mut());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut output = salt.to_vec();
    output.extend(nonce.to_vec());
    output.extend(ciphertext);
    Ok(output)
}

/// Descriptografa dados com passphrase.
pub fn decrypt_with_passphrase(encrypted: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted.len() < SALT_LEN + NONCE_LEN {
        return Err("Encrypted data too short".to_string());
    }

    let (salt, rest) = encrypted.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let mut salt_arr = [0u8; SALT_LEN];
    salt_arr.copy_from_slice(salt);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(passphrase, &salt_arr, PBKDF2_ITERATIONS, key.as_mut());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
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
        let data = b"secret private key bytes";
        let passphrase = b"my-strong-passphrase";

        let encrypted = encrypt_with_passphrase(data, passphrase).unwrap();
        let decrypted = decrypt_with_passphrase(&encrypted, passphrase).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let data = b"secret data";
        let encrypted = encrypt_with_passphrase(data, b"correct").unwrap();
        let result = decrypt_with_passphrase(&encrypted, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn different_salts_produce_different_ciphertext() {
        let data = b"same data";
        let passphrase = b"passphrase";

        let enc1 = encrypt_with_passphrase(data, passphrase).unwrap();
        let enc2 = encrypt_with_passphrase(data, passphrase).unwrap();

        // Salt diferentes → ciphertext diferentes
        assert_ne!(enc1, enc2);
    }
}
