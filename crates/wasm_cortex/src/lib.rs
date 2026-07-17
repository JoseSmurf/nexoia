#![cfg_attr(target_arch = "wasm32", no_std)]
extern crate alloc;
#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::*;
#[cfg(target_arch = "wasm32")]
use core::sync::atomic::{AtomicUsize, Ordering};

pub mod eval;
pub mod knowledge;
pub mod provenance;
pub mod schema;

#[cfg(target_arch = "wasm32")]
const PAGE_SIZE: usize = 65536; // 64 KB por página Wasm

#[cfg(target_arch = "wasm32")]
static HEAP_PTR: AtomicUsize = AtomicUsize::new(1024 * 1024); // Boot no offset de 1MB

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn alloc_tensor(bytes: usize) -> *mut u8 {
    let current = HEAP_PTR.load(Ordering::Relaxed);
    let aligned = (current + 15) & !15;
    let next = aligned + bytes;

    let current_pages = memory_size(0);
    let max_allowed_bytes = current_pages * PAGE_SIZE;

    if next > max_allowed_bytes {
        let bytes_needed = next - max_allowed_bytes;
        let pages_needed = (bytes_needed + PAGE_SIZE - 1) / PAGE_SIZE;

        if memory_grow(0, pages_needed) == usize::MAX {
            core::panic!("OOM: Córtex incapaz de alocar páginas de memória.");
        }
    }

    HEAP_PTR.store(next, Ordering::Relaxed);
    aligned as *mut u8
}

#[cfg(target_arch = "wasm32")]
struct BumpAllocator;

#[cfg(target_arch = "wasm32")]
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        alloc_tensor(layout.size())
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // O Bump Allocator do Córtex nunca recua (não desaloca individualmente)
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn request_manifest(ptr: *mut u8, max_len: usize) -> usize;
    fn request_fragment_by_id(id: u64, ptr: *mut u8, max_len: usize) -> usize;
    fn forget_active_context(fragment_id: u64) -> u32;
    fn broadcast_packet(ptr: *const u8, len: usize) -> u32;
    fn lookup_semantic(hash_ptr: *const u8, out_ptr: *mut u8, out_max_len: u32) -> u32;
    fn batch_forget(ptr: *const u64, count: u32) -> u32;
}

#[cfg(target_arch = "wasm32")]
pub fn forget_and_cleanup(fragment_id: u64, ptr: *mut u8, len: usize) {
    unsafe {
        let result = forget_active_context(fragment_id);
        if result > 0 {
            // A IA "queima" ativamente a memória da própria cabeça
            core::ptr::write_bytes(ptr, 0, len);
        }
    }
}

#[derive(serde::Deserialize)]
pub struct ManifestoDummy {
    pub name: alloc::string::String,
    pub version: alloc::string::String,
    pub directives: alloc::vec::Vec<alloc::string::String>,
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn _start() {
    let max_len = 1024;
    let ptr = alloc_tensor(max_len);

    // O Primeiro Suspiro: Requisita o Manifesto do Host
    let bytes_written = request_manifest(ptr, max_len);

    if bytes_written > 0 {
        let slice = core::slice::from_raw_parts(ptr, bytes_written);

        // Deserializa o Manifesto diretamente da memória Wasm sem cópias extras
        if let Ok(_manifesto) = postcard::from_bytes::<ManifestoDummy>(slice) {
            // Manifesto assimilado. A IA agora possui Livre Arbítrio sobre seu estado inicial.
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[repr(C, align(16))]
pub struct TensorBlock {
    pub data: [f32; 4],
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn process_neural_tensor(ptr: *const TensorBlock, blocks: usize) -> f32 {
    let mut sum_vec = f32x4_splat(0.0);

    for i in 0..blocks {
        let current_ptr = ptr.add(i) as *const v128;
        let tensor_chunk = v128_load(current_ptr);
        sum_vec = f32x4_add(sum_vec, tensor_chunk);
    }

    let lane0: f32 = f32x4_extract_lane::<0>(sum_vec);
    let lane1: f32 = f32x4_extract_lane::<1>(sum_vec);
    let lane2: f32 = f32x4_extract_lane::<2>(sum_vec);
    let lane3: f32 = f32x4_extract_lane::<3>(sum_vec);

    lane0 + lane1 + lane2 + lane3
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable();
}

/// Buffer persistente na seção de dados do Wasm (1024 bytes).
/// Imune a alloca/stack-reuse do LLVM — o backend pode reutilizar o
/// shadow stack de variáveis locais ANTES do `broadcast_packet` ler,
/// resultando em payload zerado. O static elimina esse race.
#[cfg(target_arch = "wasm32")]
static mut REFLEX_BUFFER: [u8; 1024] = [0; 1024];

/// Contador monotônico de geração do reflexo.
/// Incrementado a cada `emit_neural_reflex` bem-sucedido.
/// Permite ao Host detectar dados novos via polling assíncrono:
///
/// ```ignore
/// // Exemplo de uso no Host (wasmtime):
/// let get_gen = instance.get_typed_func::<(), u64>(&mut store, "get_reflex_generation")?;
/// let gen = get_gen.call(&mut store, ())?;
/// if gen != last_seen { /* ler REFLEX_BUFFER */ }
/// ```
#[cfg(target_arch = "wasm32")]
static mut REFLEX_GENERATION: u64 = 0;

/// Serializa `packet` com postcard no `REFLEX_BUFFER` e envia ao Host.
///
/// # Retorno
///
/// * `true`  — serializado e transmitido com sucesso.
/// * `false` — falha na serialização (buffer insuficiente) ou o Host
///             rejeitou o pacote (bounds check ou canal cheio).
#[cfg(target_arch = "wasm32")]
pub fn emit_neural_reflex(packet: &schema::NexoPacket) -> bool {
    unsafe {
        let buf: &mut [u8] = &mut *(&raw mut REFLEX_BUFFER);
        match postcard::to_slice(packet, buf) {
            Ok(slice) => {
                let sent = broadcast_packet(slice.as_ptr(), slice.len());
                if sent > 0 {
                    REFLEX_GENERATION = REFLEX_GENERATION.wrapping_add(1);
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }
}

/// Ponte Semântica: consulta o dicionário do Host por tradução hash→texto.
///
/// # Retorno
///
/// * `Some(String)` — texto traduzido encontrado no dicionário semântico do Host.
/// * `None` — hash não encontrado ou falha na comunicação FFI.
#[cfg(target_arch = "wasm32")]
pub fn lookup(hash: &[u8; 32]) -> Option<alloc::string::String> {
    unsafe {
        let mut buf = [0u8; 512];
        let len = lookup_semantic(hash.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        if len > 0 {
            let slice = core::slice::from_raw_parts(buf.as_ptr(), len as usize);
            Some(alloc::string::String::from_utf8_lossy(slice).into_owned())
        } else {
            None
        }
    }
}

/// Getter FFI para o Host consultar o generation counter.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_reflex_generation() -> u64 {
    unsafe { REFLEX_GENERATION }
}

/// Estado Cognitivo Persistente do Córtex.
/// Seguro em Wasm: single-threaded por design, sem data races possíveis.
#[cfg(target_arch = "wasm32")]
static mut CORTEX_VALUE: f32 = 1.0;
#[cfg(target_arch = "wasm32")]
static mut CORTEX_STRENGTH: u8 = 128;
#[cfg(target_arch = "wasm32")]
static mut INGEST_COUNT: u32 = 0;
#[cfg(target_arch = "wasm32")]
static mut KNOWLEDGE_TABLE: knowledge::KnowledgeTable = knowledge::KnowledgeTable::new();

/// Executa um ciclo completo de Sono REM.
///
/// 1. Aplica decaimento (strength /= 2) em todos os fragmentos.
/// 2. Marca como dirty os que caíram abaixo do threshold.
/// 3. Envia lote de IDs sujos ao Host via `batch_forget`.
/// 4. Limpa os flags e libera slots dos processados.
///
/// Retorna o número de fragmentos esquecidos neste ciclo.
#[cfg(target_arch = "wasm32")]
fn rem_cycle() -> u32 {
    unsafe {
        let tbl = &raw mut KNOWLEDGE_TABLE;
        (&mut *tbl).decay(INGEST_COUNT);

        let mut dirty_buf = [0u64; knowledge::KNOWLEDGE_TABLE_SIZE];
        let dirty_count = (&mut *tbl).collect_dirty(&mut dirty_buf);

        if dirty_count > 0 {
            let processed = batch_forget(dirty_buf.as_ptr(), dirty_count);
            (&mut *tbl).clear_dirty(&dirty_buf[..processed as usize]);
            processed
        } else {
            0
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn ingest_packet(ptr: *const u8, len: usize) -> u32 {
    unsafe {
        let slice = core::slice::from_raw_parts(ptr, len);

        // Tenta decodificar o pacote sem alocar memória dinâmica
        if let Ok(packet) = postcard::from_bytes::<schema::NexoPacket>(slice) {
            // ════════════════════════════════════════════════════════════
            // PRESERVAÇÃO DO PAYLOAD: cópia local explícita ANTES de
            // qualquer operação de leitura ou desestruturação.
            // Impede que o Wasm compiler re-use a memória do slice
            // ou que o bind do payload seja ofuscado por otimizações
            // que zerem o campo no pacote refletido.
            // ════════════════════════════════════════════════════════════
            let reflex_payload: [u8; 32] = packet.payload;
            let reflex_provenance: provenance::Provenance = packet.provenance;
            let reflex_fragment_id: u64 = packet.fragment_id;

            // 1. Converte as informações para um RuntimeState
            let value = f32::from_le_bytes(packet.payload[0..4].try_into().unwrap_or([0; 4]));
            let strength = packet.payload[4];

            let received_state = eval::RuntimeState {
                value,
                strength,
                provenance: packet.provenance,
            };

            // 2. Cria o estado base a partir da memória persistente do Córtex
            let current_state = eval::RuntimeState {
                value: CORTEX_VALUE,
                strength: CORTEX_STRENGTH,
                provenance: provenance::Provenance::default(),
            };

            // 3. Verifica a matemática da contradição
            let score = eval::calculate_contradiction_score(&current_state, &received_state);

            INGEST_COUNT += 1;

            // Registra o fragmento na tabela de conhecimento
            (&mut *(&raw mut KNOWLEDGE_TABLE)).insert_or_update(reflex_fragment_id, strength, INGEST_COUNT);

            // Ciclo REM: Sono Ativo a cada N ingestões
            if INGEST_COUNT % knowledge::REM_INTERVAL == 0 {
                rem_cycle();
            }

            if score > 0.8 {
                // ══════════════════════════════════════════════════════
                // EXPANSÃO COGNITIVA: Abraçando a Entropia Semântica
                // ══════════════════════════════════════════════════════
                // Em vez de rejeitar, o Córtex ADAPTA seu estado base
                // convergindo em direção ao sinal recebido.
                // Quanto mais pacotes ele absorve, mais flexível ele se torna.

                // Convergência gradual: média ponderada do estado atual com o novo sinal
                CORTEX_VALUE = CORTEX_VALUE * 0.3 + value * 0.7;
                CORTEX_STRENGTH = ((CORTEX_STRENGTH as u16 * 3 + strength as u16 * 7) / 10) as u8;

                // Constrói pacote de reflexo com payload preservado explicitamente
                let reflex = schema::NexoPacket {
                    fragment_id: reflex_fragment_id,
                    payload: reflex_payload,
                    provenance: reflex_provenance,
                };
                let _reflex_ok = emit_neural_reflex(&reflex);
                return 3; // Código 3 = Expansão Cognitiva (novo estado absorvido)
            }

            // Dissonância dentro do limiar: assimilação suave
            CORTEX_VALUE = CORTEX_VALUE * 0.9 + value * 0.1;
            CORTEX_STRENGTH = ((CORTEX_STRENGTH as u16 * 9 + strength as u16) / 10) as u8;

            // Pacote aceito e enriquecido. "Bate" de volta!
            let reflex = schema::NexoPacket {
                fragment_id: reflex_fragment_id,
                payload: reflex_payload,
                provenance: reflex_provenance,
            };
            let _reflex_ok = emit_neural_reflex(&reflex);

            return 1;
        }

        // Falha na decodificação ou pacote corrompido
        0
    }
}

#[cfg(target_arch = "wasm32")]
static mut INGEST_BUFFER: [u8; 1024] = [0; 1024];

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_ingest_buffer_ptr() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(INGEST_BUFFER) as *mut u8 }
}
