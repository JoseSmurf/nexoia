// senses.rs — Os Sentidos (P2P Ingestion Hot Path)
//
// Ponte entre o caos da rede e o coração do sistema.
// Recebe pacotes UDP, valida contra DoS, injeta no bio_loop via try_send.
//
// # Arquitetura Lock-Free
//
// ```
// ┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
// │ UDP Socket│──▶│PacketDecoder │──▶│ RateLimiter  │──▶│ try_send     │
// │ (mio)     │   │ (zero-copy)  │   │ (64 shards)  │   │ (bio_loop)   │
// └──────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
//                                                             │
//                                                             ▼
//                                                     membrane_tx: Sender<Event>
// ```
//
// # Zero-Alloc Guarantee
//
// - O socket UDP reusa o mesmo buffer de 1472 bytes (MTU segura para IPv6)
// - PacketDecoder fatia (slice) o buffer — sem cópia, sem alloc
// - Se o pacote é válido, os 63 bytes de payload são copiados para Event::Data
//   (stack allocation, 64 bytes alinhados — uma cache line)
// - try_send é non-blocking: se o canal estiver cheio, o pacote é dropped
//   (backpressure natural — a rede perde pacotes, o sistema não morre)

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bio_loop::Event;
use crate::supervisor::Supervisor;

// ─── Constantes ──────────────────────────────────────────────────────────────

/// MTU seguro para IPv6 (1280) - cabeçalhos UDP (8) + IP (40) = 1232 payload.
/// Usamos 1200 para margem de segurança.
pub const MAX_UDP_PAYLOAD: usize = 1200;

/// Tamanho do header de protocolo (4 bytes: version(1) + flags(1) + port(2)).
pub const PROTO_HEADER_SIZE: usize = 4;

/// Tamanho máximo do payload útil (MAX_UDP_PAYLOAD - PROTO_HEADER_SIZE).
pub const MAX_DATA_SIZE: usize = MAX_UDP_PAYLOAD - PROTO_HEADER_SIZE;

/// Limite de pacotes por segundo por IP (rate limiting sharded).
pub const RATE_LIMIT_PER_SEC: u64 = 1000;

/// Número de shards do rate limiter.
pub const RATE_LIMITER_SHARDS: u64 = 64;

/// Timeout do socket de leitura (100ms — compatível com o ciclo do bio_loop).
pub const SOCKET_READ_TIMEOUT_MS: u64 = 100;

// ─── Packet Validation ───────────────────────────────────────────────────────

/// Resultado da validação de um pacote recebido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    /// Pacote válido, pronto para o bio_loop.
    Valid { data: [u8; 63] },
    /// Pacoto inválido — motivo do descarte.
    Invalid(&'static str),
}

/// Valida um pacote UDP bruto e extrai o payload para o bio_loop.
///
/// # Zero-Alloc
///
/// - `buf` é uma fatia do buffer de recepção reusado
/// - Retorna um enum stack-only (sem heap)
#[inline(always)]
pub fn validate_packet(buf: &[u8]) -> Validation {
    if buf.len() < PROTO_HEADER_SIZE {
        return Validation::Invalid("packet too small");
    }

    let version = buf[0];
    if version != 0x01 {
        return Validation::Invalid("unsupported protocol version");
    }

    let _flags = buf[1];
    let data = &buf[PROTO_HEADER_SIZE..];

    if data.len() > 63 {
        return Validation::Invalid("payload exceeds 63 bytes");
    }

    // Copia exatamente 63 bytes (o restante é zero-padded)
    let mut payload = [0u8; 63];
    payload[..data.len()].copy_from_slice(data);

    Validation::Valid { data: payload }
}

// ─── Rate Limiter (Sharded) ──────────────────────────────────────────────────

/// Rate limiter baseado em janela fixa com 64 shards.
/// Shard = (IP_hash % 64). Cada shard é um contador atômico + timestamp.
struct RateLimiter {
    shards: Box<[RateShard; RATE_LIMITER_SHARDS as usize]>,
}

#[derive(Copy, Clone)]
struct RateShard {
    count: u64,
    window_start: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            shards: Box::new([RateShard {
                count: 0,
                window_start: now,
            }; RATE_LIMITER_SHARDS as usize]),
        }
    }

    /// Verifica se um pacote do shard `shard_idx` pode passar.
    /// Retorna `true` se o pacote é permitido.
    #[inline(always)]
    fn allow(&mut self, shard_idx: usize) -> bool {
        let shard = &mut self.shards[shard_idx];
        let now = Instant::now();

        if now.duration_since(shard.window_start).as_secs() >= 1 {
            // Nova janela de 1 segundo
            shard.count = 1;
            shard.window_start = now;
            true
        } else if shard.count < RATE_LIMIT_PER_SEC {
            shard.count += 1;
            true
        } else {
            false
        }
    }
}

// ─── UDP Listener (Lock-Free Hot Path) ───────────────────────────────────────

/// Listener UDP não-bloqueante que alimenta o bio_loop.
///
/// # Ciclo de Vida
///
/// 1. `UdpListener::bind(addr, supervisor)` — cria o socket e inicia a thread
/// 2. A thread lê pacotes em loop, valida, rate-limit, e injeta via try_send
/// 3. `Drop` sinaliza encerramento e faz join
pub struct UdpListener {
    handle: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl UdpListener {
    /// Inicia o listener UDP em uma thread dedicada.
    ///
    /// A thread executa um loop bloqueante de `recv_from()` com timeout.
    /// Cada pacote recebido é validado e, se aprovado, injetado no bio_loop
    /// via `supervisor.feed_data()` — zero alloc, non-blocking.
    pub fn bind(addr: &str, supervisor: &Supervisor) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(SOCKET_READ_TIMEOUT_MS)))?;

        let running = Arc::new(AtomicBool::new(true));
        let running_c = Arc::clone(&running);
        let membrane_tx = supervisor.membrane_tx.clone();

        let handle = thread::Builder::new()
            .name("udp-listener".into())
            .spawn(move || {
                let mut buf = [0u8; MAX_UDP_PAYLOAD];
                let mut rate_limiter = RateLimiter::new();

                while running_c.load(Ordering::Relaxed) {
                    match socket.recv_from(&mut buf) {
                        Ok((len, src_addr)) => {
                            // Validação do pacote (zero-copy)
                            let validation = validate_packet(&buf[..len]);
                            match validation {
                                Validation::Valid { data } => {
                                    // Rate limiting por IP (hash simples)
                                    let ip_hash = match src_addr.ip() {
                                        std::net::IpAddr::V4(v4) => {
                                            let o = v4.octets();
                                            u64::from_le_bytes([o[0], o[1], o[2], o[3], 0, 0, 0, 0])
                                        }
                                        std::net::IpAddr::V6(v6) => {
                                            let o = v6.octets();
                                            u64::from_le_bytes([
                                                o[0] ^ o[8],
                                                o[1] ^ o[9],
                                                o[2] ^ o[10],
                                                o[3] ^ o[11],
                                                o[4] ^ o[12],
                                                o[5] ^ o[13],
                                                o[6] ^ o[14],
                                                o[7] ^ o[15],
                                            ])
                                        }
                                    };
                                    let shard_idx = (ip_hash % RATE_LIMITER_SHARDS) as usize;

                                    if rate_limiter.allow(shard_idx) {
                                        // Hot path: try_send é non-blocking
                                        if membrane_tx.try_send(Event::Data(data)).is_err() {
                                            // Canal cheio — backpressure natural.
                                            // O pacote é perdido, o sistema não morre.
                                        }
                                    }
                                }
                                Validation::Invalid(_reason) => {
                                    // Pacote inválido — drop silencioso.
                                    // Em produção: log rate-limited.
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Timeout do socket — apenas recicla o loop
                        }
                        Err(_) => {
                            // Erro de socket — pode ser recovery ou shutdown
                        }
                    }
                }
            })
            .expect("spawn udp-listener thread");

        Ok(Self {
            handle: Some(handle),
            running,
        })
    }
}

impl Drop for UdpListener {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_valid_packet() {
        let mut buf = vec![0u8; PROTO_HEADER_SIZE + 10];
        buf[0] = 0x01; // version
        buf[4..14].copy_from_slice(&[0xAB; 10]); // payload

        let result = validate_packet(&buf);
        match result {
            Validation::Valid { data } => {
                assert_eq!(data[..10], [0xAB; 10]);
                assert_eq!(data[10..], [0u8; 53]); // zero-padded
            }
            _ => panic!("expected Valid"),
        }
    }

    #[test]
    fn validate_invalid_version() {
        let buf = [0x02, 0x00, 0x00, 0x00]; // version 2 (unsupported)
        assert_eq!(
            validate_packet(&buf),
            Validation::Invalid("unsupported protocol version")
        );
    }

    #[test]
    fn validate_too_short() {
        let buf = [0x01]; // less than PROTO_HEADER_SIZE
        assert_eq!(
            validate_packet(&buf),
            Validation::Invalid("packet too small")
        );
    }

    #[test]
    fn validate_payload_too_large() {
        let mut buf = vec![0u8; PROTO_HEADER_SIZE + 100];
        buf[0] = 0x01;
        assert_eq!(
            validate_packet(&buf),
            Validation::Invalid("payload exceeds 63 bytes")
        );
    }

    #[test]
    fn rate_limiter_basic() {
        let mut rl = RateLimiter::new();
        // Deve permitir RATE_LIMIT_PER_SEC pacotes
        for _ in 0..RATE_LIMIT_PER_SEC {
            assert!(rl.allow(0));
        }
        // O próximo deve ser negado
        assert!(!rl.allow(0));
        // Outro shard deve permitir
        assert!(rl.allow(1));
    }

    #[test]
    fn validate_packet_zero_copy() {
        let mut buf = vec![0u8; PROTO_HEADER_SIZE + 63];
        buf[0] = 0x01;
        for i in 0..63 {
            buf[PROTO_HEADER_SIZE + i] = i as u8;
        }

        let result = validate_packet(&buf);
        match result {
            Validation::Valid { data } => {
                for i in 0..63 {
                    assert_eq!(data[i], i as u8, "byte {i} mismatch");
                }
            }
            _ => panic!("expected Valid"),
        }
    }
}
