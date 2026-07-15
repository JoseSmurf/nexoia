//! secure_transport.rs — Mensagem segura com encriptação e anti-replay
//!
//! Formato da mensagem segura:
//!   [4 bytes: total_len] [12 bytes: nonce] [8 bytes: counter] [N bytes: ciphertext] [16 bytes: auth_tag]
//!
//! Decisões criptográficas:
//! - ChaCha20-Poly1305: AEAD rápido, resistente a timing attacks, 256-bit key
//! - Nonce de 12 bytes (96 bits): padrão RFC 8439, evitar reuso
//! - Contador de 8 bytes (64 bits): anti-replay simples, janela de 2^64 mensagens

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};

/// Tamanho do nonce ChaCha20-Poly1305 (RFC 8439).
const NONCE_LEN: usize = 12;

/// Tamanho do counter.
const COUNTER_LEN: usize = 8;

/// Tamanho do header (length prefix).
const HEADER_LEN: usize = 4;

/// Mensagem segura encriptada.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    /// Nonce único para esta mensagem (12 bytes).
    pub nonce: [u8; NONCE_LEN],
    /// Contador anti-replay (8 bytes, big-endian).
    pub counter: u64,
    /// Payload encriptado (ciphertext + auth tag).
    pub encrypted_payload: Vec<u8>,
}

impl SecureMessage {
    /// Encripta uma mensagem usando a chave de sessão.
    ///
    /// Formato do plaintext: [counter: 8 bytes] [payload: N bytes]
    /// O counter é incluído no plaintext para binding.
    pub fn encrypt(
        payload: &[u8],
        session_key: &[u8; 32],
        counter: u64,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, String> {
        let cipher = ChaCha20Poly1305::new(session_key.into());

        // Prepara plaintext: counter + payload
        let mut plaintext = Vec::with_capacity(COUNTER_LEN + payload.len());
        plaintext.extend_from_slice(&counter.to_be_bytes());
        plaintext.extend_from_slice(payload);

        // Encripta
        let nonce_slice = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce_slice, plaintext.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        Ok(SecureMessage {
            nonce: *nonce,
            counter,
            encrypted_payload: ciphertext,
        })
    }

    /// Decripta uma mensagem usando a chave de sessão.
    ///
    /// Retorna (counter, payload) se sucesso.
    pub fn decrypt(&self, session_key: &[u8; 32]) -> Result<(u64, Vec<u8>), String> {
        let cipher = ChaCha20Poly1305::new(session_key.into());

        let nonce_slice = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce_slice, self.encrypted_payload.as_ref())
            .map_err(|e| format!("Decryption error: {}", e))?;

        if plaintext.len() < COUNTER_LEN {
            return Err("Plaintext too short".to_string());
        }

        // Extrai counter
        let mut counter_bytes = [0u8; COUNTER_LEN];
        counter_bytes.copy_from_slice(&plaintext[..COUNTER_LEN]);
        let counter = u64::from_be_bytes(counter_bytes);

        // Extrai payload
        let payload = plaintext[COUNTER_LEN..].to_vec();

        Ok((counter, payload))
    }

    /// Serializa para bytes (para envio via UDP).
    ///
    /// Formato: [4 bytes: total_len] [12 bytes: nonce] [8 bytes: counter] [N bytes: encrypted_payload]
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = NONCE_LEN + COUNTER_LEN + self.encrypted_payload.len();
        let mut buf = Vec::with_capacity(HEADER_LEN + total_len);

        // Length prefix (big-endian)
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());

        // Nonce
        buf.extend_from_slice(&self.nonce);

        // Counter
        buf.extend_from_slice(&self.counter.to_be_bytes());

        // Encrypted payload (já inclui auth tag)
        buf.extend_from_slice(&self.encrypted_payload);

        buf
    }

    /// Deserializa de bytes (recebido via UDP).
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < HEADER_LEN {
            return Err("Data too short for header".to_string());
        }

        // Lê length prefix
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[..HEADER_LEN]);
        let total_len = u32::from_be_bytes(len_bytes) as usize;

        if data.len() < HEADER_LEN + total_len {
            return Err("Data too short for declared length".to_string());
        }

        let offset = HEADER_LEN;

        // Nonce
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[offset..offset + NONCE_LEN]);

        // Counter
        let mut counter_bytes = [0u8; COUNTER_LEN];
        counter_bytes.copy_from_slice(&data[offset + NONCE_LEN..offset + NONCE_LEN + COUNTER_LEN]);
        let counter = u64::from_be_bytes(counter_bytes);

        // Encrypted payload
        let payload_offset = offset + NONCE_LEN + COUNTER_LEN;
        let encrypted_payload = data[payload_offset..offset + total_len].to_vec();

        Ok(SecureMessage {
            nonce,
            counter,
            encrypted_payload,
        })
    }
}

/// Gera nonce aleatório para ChaCha20-Poly1305 (12 bytes).
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Gera nonce aleatório para handshake (32 bytes).
pub fn generate_handshake_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let counter = 42u64;
        let payload = b"Hello, NexoIA!";

        let msg = SecureMessage::encrypt(payload, &key, counter, &nonce).unwrap();
        let (dec_counter, dec_payload) = msg.decrypt(&key).unwrap();

        assert_eq!(counter, dec_counter);
        assert_eq!(payload.to_vec(), dec_payload);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let counter = 0u64;
        let payload = b"Secret data";

        let msg = SecureMessage::encrypt(payload, &key, counter, &nonce).unwrap();
        let result = msg.decrypt(&wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let counter = 0u64;
        let payload = b"Important data";

        let mut msg = SecureMessage::encrypt(payload, &key, counter, &nonce).unwrap();

        // Altera último byte do ciphertext
        let last = msg.encrypted_payload.last_mut().unwrap();
        *last ^= 0xff;

        let result = msg.decrypt(&key);
        assert!(result.is_err());
    }

    #[test]
    fn serialization_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let counter = 12345u64;
        let payload = b"Test message";

        let msg = SecureMessage::encrypt(payload, &key, counter, &nonce).unwrap();
        let bytes = msg.to_bytes();
        let decoded = SecureMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.nonce, decoded.nonce);
        assert_eq!(msg.counter, decoded.counter);
        assert_eq!(msg.encrypted_payload, decoded.encrypted_payload);
    }

    #[test]
    fn different_counters_different_ciphertext() {
        let key = [42u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let payload = b"Same content";

        let msg1 = SecureMessage::encrypt(payload, &key, 0, &nonce).unwrap();
        let msg2 = SecureMessage::encrypt(payload, &key, 1, &nonce).unwrap();

        // Counter diferente → ciphertext diferente (mesmo com mesmo nonce)
        assert_ne!(msg1.encrypted_payload, msg2.encrypted_payload);
    }
}
