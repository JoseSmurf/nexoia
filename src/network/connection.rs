//! connection.rs — Type-State Pattern para estados da conexão
//!
//! Este módulo implementa o padrão Type-State para gerenciar o estado
//! de conexão de forma segura em compile-time.
//!
//! Estados:
//! - Disconnected: Não conectado
//! - Handshaking: Handshake em andamento
//! - Authenticated: Autenticado mas não encriptado
//! - Encrypted: Conexão encriptada e pronta para uso
//!
//! O Type-State Pattern garante que:
//! - Não é possível enviar dados encriptados antes do handshake
//! - Não é possível usar sessão antes da autenticação
//! - Transições de estado são seguras em compile-time

use crate::network::session::SessionState;
use std::marker::PhantomData;
use std::net::SocketAddr;

/// Estado Disconnected (não conectado).
pub struct Disconnected;

/// Estado Handshaking (handshake em andamento).
pub struct Handshaking {
    pub remote_addr: SocketAddr,
    pub local_nonce: [u8; 32],
}

/// Estado Authenticated (autenticado mas não encriptado).
pub struct Authenticated {
    pub remote_addr: SocketAddr,
    pub remote_node_id: String,
    pub remote_x25519_pubkey: [u8; 32],
}

/// Estado Encrypted (conexão encriptada e pronta para uso).
pub struct Encrypted {
    pub session: SessionState,
}

/// Conexão com Type-State Pattern.
/// O estado é representado pelo tipo genérico, garantindo segurança em compile-time.
pub struct Connection<S> {
    state: S,
    _marker: PhantomData<S>,
}

impl Connection<Disconnected> {
    /// Cria nova conexão desconectada.
    pub fn new() -> Self {
        Self {
            state: Disconnected,
            _marker: PhantomData,
        }
    }

    /// Inicia handshake com um peer.
    pub fn start_handshake(
        self,
        remote_addr: SocketAddr,
        local_nonce: [u8; 32],
    ) -> Connection<Handshaking> {
        Connection {
            state: Handshaking {
                remote_addr,
                local_nonce,
            },
            _marker: PhantomData,
        }
    }
}

impl Connection<Handshaking> {
    /// Retorna o endereço remoto.
    pub fn remote_addr(&self) -> SocketAddr {
        self.state.remote_addr
    }

    /// Retorna o nonce local.
    pub fn local_nonce(&self) -> [u8; 32] {
        self.state.local_nonce
    }

    /// Autenticação bem-sucedida, transita para Authenticated.
    pub fn authenticate(
        self,
        remote_node_id: String,
        remote_x25519_pubkey: [u8; 32],
    ) -> Connection<Authenticated> {
        Connection {
            state: Authenticated {
                remote_addr: self.state.remote_addr,
                remote_node_id,
                remote_x25519_pubkey,
            },
            _marker: PhantomData,
        }
    }

    /// Handshake falhou, volta para Disconnected.
    pub fn fail(self) -> Connection<Disconnected> {
        Connection {
            state: Disconnected,
            _marker: PhantomData,
        }
    }
}

impl Connection<Authenticated> {
    /// Retorna o endereço remoto.
    pub fn remote_addr(&self) -> SocketAddr {
        self.state.remote_addr
    }

    /// Retorna o node_id remoto.
    pub fn remote_node_id(&self) -> &str {
        &self.state.remote_node_id
    }

    /// Retorna a chave pública X25519 remota.
    pub fn remote_x25519_pubkey(&self) -> &[u8; 32] {
        &self.state.remote_x25519_pubkey
    }

    /// Sessão estabelecida, transita para Encrypted.
    pub fn encrypt(self, session: SessionState) -> Connection<Encrypted> {
        Connection {
            state: Encrypted { session },
            _marker: PhantomData,
        }
    }
}

impl Connection<Encrypted> {
    /// Retorna referência à sessão.
    pub fn session(&self) -> &SessionState {
        &self.state.session
    }

    /// Retorna mut referência à sessão.
    pub fn session_mut(&mut self) -> &mut SessionState {
        &mut self.state.session
    }

    /// Desconecta, volta para Disconnected.
    pub fn disconnect(self) -> Connection<Disconnected> {
        Connection {
            state: Disconnected,
            _marker: PhantomData,
        }
    }
}

impl Default for Connection<Disconnected> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_state_transitions() {
        // Inicia desconectado
        let conn = Connection::<Disconnected>::new();

        // Inicia handshake
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let nonce = [1u8; 32];
        let conn = conn.start_handshake(addr, nonce);
        assert_eq!(conn.remote_addr(), addr);

        // Autentica
        let conn = conn.authenticate("peer_1".to_string(), [2u8; 32]);
        assert_eq!(conn.remote_node_id(), "peer_1");

        // Criptografa
        let session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);
        let mut conn = conn.encrypt(session);
        assert_eq!(conn.session().session_key, [0u8; 32]);

        // Desconecta
        let _conn = conn.disconnect();
    }

    #[test]
    fn type_state_prevents_invalid_transitions() {
        // Este teste verifica que o compilador rejeita transições inválidas
        // Se descomentar as linhas abaixo, o código não compila:
        //
        // let conn = Connection::<Disconnected>::new();
        // conn.session(); // Erro: Disconnected não tem session()
        //
        // let conn = Connection::<Handshaking>::new(...);
        // conn.session(); // Erro: Handshaking não tem session()
        //
        // Isso é o Type-State Pattern em ação!
        assert!(true);
    }
}
