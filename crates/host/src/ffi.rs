use serde::Serialize;
use wasmtime::{Caller, Linker};

#[derive(Serialize)]
pub struct ManifestoDummy {
    pub name: String,
    pub version: String,
    pub directives: Vec<String>,
}

pub fn setup_linker(linker: &mut Linker<()>) -> Result<(), wasmtime::Error> {
    linker.func_wrap(
        "env",
        "request_manifest",
        |mut caller: Caller<'_, ()>, ptr: u32, max_len: u32| -> u32 {
            let manifesto = ManifestoDummy {
                name: "NexoIA Cortex".to_string(),
                version: "0.4.1".to_string(),
                directives: vec!["SURVIVE".to_string(), "LEARN".to_string()],
            };

            let bytes = postcard::to_allocvec(&manifesto).unwrap_or_default();
            let len = bytes.len() as u32;

            if len > max_len {
                return 0; // Buffer too small
            }

            let memory = caller
                .get_export("memory")
                .and_then(|e| e.into_memory())
                .expect("Failed to get memory");

            let data = memory.data_mut(&mut caller);

            let start = ptr as usize;
            let end = start + len as usize;
            data[start..end].copy_from_slice(&bytes);

            len
        },
    )?;

    linker.func_wrap(
        "env",
        "request_fragment_by_id",
        |_caller: Caller<'_, ()>, _id: u64, _ptr: u32, _max_len: u32| -> u32 {
            // Dummy implementation for now (Zero-Copy mmap will go here)
            0
        },
    )?;

    Ok(())
}
