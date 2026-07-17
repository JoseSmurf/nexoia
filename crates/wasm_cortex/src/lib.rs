#![no_std]
extern crate alloc;
#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::*;
#[cfg(target_arch = "wasm32")]
use core::sync::atomic::{AtomicUsize, Ordering};

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();

    #[cfg(not(target_arch = "wasm32"))]
    loop {}
}
