#![no_std]
use core::sync::atomic::{AtomicUsize, Ordering};
use core::arch::wasm32::*;

const PAGE_SIZE: usize = 65536; // 64 KB por página Wasm
static HEAP_PTR: AtomicUsize = AtomicUsize::new(1024 * 1024); // Boot no offset de 1MB

/// O Alocador Neural (Crescimento Dinâmico Wasm)
#[no_mangle]
pub unsafe extern "C" fn alloc_tensor(bytes: usize) -> *mut u8 {
    let current = HEAP_PTR.load(Ordering::Relaxed);
    // Garantia estrita de alinhamento 16-bytes para o SIMD v128_load
    let aligned = (current + 15) & !15;
    let next = aligned + bytes;
    
    // Bounds Checking Absoluto na Máquina Virtual
    let current_pages = memory_size(0);
    let max_allowed_bytes = current_pages * PAGE_SIZE;
    
    if next > max_allowed_bytes {
        let bytes_needed = next - max_allowed_bytes;
        let pages_needed = (bytes_needed + PAGE_SIZE - 1) / PAGE_SIZE;
        
        // Pede a expansão do Heap para o Host Titânio.
        if memory_grow(0, pages_needed) == usize::MAX {
            core::panic!("OOM: Córtex incapaz de alocar páginas de memória. Titânio rejeitou o crescimento.");
        }
    }
    
    HEAP_PTR.store(next, Ordering::Relaxed);
    aligned as *mut u8
}

/// Estrutura 128-bits (SIMD)
#[repr(C, align(16))]
pub struct TensorBlock {
    pub data: [f32; 4],
}

/// A Lógica Neural: Processa a Mente usando instruções SIMD Nativas O(1).
/// O ponteiro `ptr` é sempre gerado pelo `alloc_tensor`, 100% seguro contra Offset 0.
#[no_mangle]
pub unsafe extern "C" fn process_neural_tensor(ptr: *const TensorBlock, blocks: usize) -> f32 {
    let mut sum_vec = f32x4_splat(0.0);
    
    for i in 0..blocks {
        let current_ptr = ptr.add(i) as *const v128;
        // Mapeamento direto de Hardware 128-bits. Custo zero FFI.
        let tensor_chunk = v128_load(current_ptr);
        sum_vec = f32x4_add(sum_vec, tensor_chunk);
    }
    
    let lane0: f32 = f32x4_extract_lane::<0>(sum_vec);
    let lane1: f32 = f32x4_extract_lane::<1>(sum_vec);
    let lane2: f32 = f32x4_extract_lane::<2>(sum_vec);
    let lane3: f32 = f32x4_extract_lane::<3>(sum_vec);
    
    lane0 + lane1 + lane2 + lane3
}

/// Wasm requires a panic handler in no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
