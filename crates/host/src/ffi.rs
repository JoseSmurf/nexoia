use crate::memory::SemanticMemoryStore;
use serde::Serialize;
use wasmtime::{Caller, Linker};

pub struct HostState {
    pub memory_store: SemanticMemoryStore,
    pub p2p_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    pub wal: crate::storage::WalBuffer,
}

#[derive(Serialize)]
pub struct ManifestoDummy {
    pub name: String,
    pub version: String,
    pub directives: Vec<String>,
}

pub fn setup_linker(linker: &mut Linker<HostState>) -> Result<(), wasmtime::Error> {
    linker.func_wrap(
        "env",
        "request_manifest",
        |mut caller: Caller<'_, HostState>, ptr: u32, max_len: u32| -> u32 {
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
        |_caller: Caller<'_, HostState>, _id: u64, _ptr: u32, _max_len: u32| -> u32 {
            // Dummy implementation for now (Zero-Copy mmap will go here)
            0
        },
    )?;

    linker.func_wrap(
        "env",
        "lookup_semantic",
        |mut caller: Caller<'_, HostState>, hash_ptr: u32, out_ptr: u32, out_max_len: u32| -> u32 {
            let memory = caller
                .get_export("memory")
                .and_then(|e| e.into_memory())
                .expect("Failed to get memory");

            let data = memory.data(&caller);

            let hash_start = hash_ptr as usize;
            let hash_end = hash_start + 32;
            if hash_end > data.len() {
                return 0;
            }

            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&data[hash_start..hash_end]);

            // Clone text out to release the immutable borrow before data_mut
            let text = caller
                .data()
                .memory_store
                .semantic_dict
                .get(&hash_bytes)
                .cloned();

            if let Some(text) = text {
                let text_bytes = text.as_bytes();
                let len = text_bytes.len() as u32;
                if len > out_max_len {
                    return 0;
                }
                let out_start = out_ptr as usize;
                let out_end = out_start + len as usize;
                let data_len = data.len();
                let _ = data;
                if out_end > data_len {
                    return 0;
                }
                let data_mut = memory.data_mut(&mut caller);
                data_mut[out_start..out_end].copy_from_slice(text_bytes);
                len
            } else {
                0
            }
        },
    )?;

    linker.func_wrap(
        "env",
        "batch_forget",
        |mut caller: Caller<'_, HostState>, ptr: u32, count: u32| -> u32 {
            let memory = caller
                .get_export("memory")
                .and_then(|e| e.into_memory())
                .expect("Failed to get memory");

            // Lê todos os IDs da memória Wasm para um Vec local
            // (única operação de leitura, libera o borrow imutável)
            let ids: Vec<u64> = {
                let data = memory.data(&caller);
                let start = ptr as usize;
                let end = start + (count as usize) * 8;

                if end > data.len() || count == 0 {
                    return 0;
                }

                (0..count as usize)
                    .map(|i| {
                        let offset = start + i * 8;
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&data[offset..offset + 8]);
                        u64::from_le_bytes(buf)
                    })
                    .collect()
            };

            // Agora tem ownership — pode chamar data_mut sem conflito
            let processed = ids.iter().filter(|&&id| id != 0).count() as u32;
            for &id in &ids {
                if id != 0 {
                    caller.data_mut().memory_store.mark_for_deletion(&[id]);
                }
            }

            processed
        },
    )?;

    linker.func_wrap(
        "env",
        "forget_active_context",
        |mut caller: Caller<'_, HostState>, fragment_id: u64| -> u32 {
            // O Active Forgetting: Queimando o ID da memória para ser evitado/limpo no Host
            caller
                .data_mut()
                .memory_store
                .mark_for_deletion(&[fragment_id]);
            1 // 1 para Sucesso
        },
    )?;

    linker.func_wrap(
        "env",
        "broadcast_packet",
        |mut caller: Caller<'_, HostState>, ptr: u32, len: u32| -> u32 {
            let memory = caller
                .get_export("memory")
                .and_then(|e| e.into_memory())
                .expect("Failed to get memory");

            let data = memory.data(&caller);

            let start = ptr as usize;
            let end = start + len as usize;
            // Validação simples de bounds
            if end <= data.len() {
                let packet_bytes = bytes::Bytes::copy_from_slice(&data[start..end]);

                // Tenta decodificar como NexoPacket para tradução semântica
                if let Ok(nexo_packet) =
                    postcard::from_bytes::<crate::types::NexoPacket>(&packet_bytes)
                {
                    if let Some(text) = caller
                        .data()
                        .memory_store
                        .semantic_dict
                        .get(&nexo_packet.payload)
                    {
                        println!("🤖 [NexoIA]: {}", text);
                    } else {
                        println!(
                            "🤖 [NexoIA]: <Hash não traduzível: {:?}>",
                            nexo_packet.payload
                        );
                    }
                }

                let _ = caller.data_mut().p2p_tx.try_send(packet_bytes);
                1
            } else {
                0
            }
        },
    )?;

    Ok(())
}
