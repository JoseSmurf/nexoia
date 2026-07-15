#![no_std]

#[cfg(target_arch = "wasm32")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::*;

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    
    #[cfg(not(target_arch = "wasm32"))]
    loop {}
}
