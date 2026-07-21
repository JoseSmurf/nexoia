use crossbeam_channel::{bounded, Receiver, Sender};

pub mod digest;
pub mod heart;

/// Evento que circula pela Membrana.
///
/// INVARIANTE DE ZERO-ALLOCATION:
/// Todos os variantes têm tamanho fixo conhecido em tempo de compilação.
/// O enum inteiro cabe numa única cache line (64 bytes):
///   - Data:      1 byte tag + 63 bytes payload  = 64 bytes
///   - Heartbeat: 1 byte tag + 8 bytes u64 + pad = 64 bytes (alinhado)
///   - Shutdown:  1 byte tag                      = 64 bytes (pad)
///
/// Nenhuma variante aloca heap. O canal crossbeam copia o valor por memcpy.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))] // força alinhamento de cache line
pub enum Event {
    /// Dado bruto a ser digerido. Payload fixo de 63 bytes — stack only.
    Data([u8; 63]),
    /// Pulso do Coração. Carrega o contador de tick monotônico.
    Heartbeat(u64),
    /// Encerramento gracioso solicitado ao loop de digestão.
    Shutdown,
}

/// Cria a Membrana: o par `(Sender, Receiver)` do canal bounded.
/// A capacidade máxima é definida em `digest::MEMBRANE_CAPACITY`.
///
/// O canal bounded é a única barreira entre o mundo externo e o núcleo
/// cognitivo. Ao encher, ele aplica backpressure natural: `try_send`
/// retorna `Err(Full)` sem bloquear o chamador e sem alocar.
pub fn create_membrane() -> (Sender<Event>, Receiver<Event>) {
    bounded(digest::MEMBRANE_CAPACITY)
}
