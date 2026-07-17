use crossbeam_skiplist::SkipList;
use flurry::HashMap;
use std::sync::Arc;
use titanium_host::ffi::{self, HostState};
use titanium_host::memory::SemanticMemoryStore;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use wasmtime::{Config, Engine, Linker, Memory, MemoryType, Store};

/// Estrutura de Estado puramente Lock-Free (EBR - Epoch Based Reclamation)
pub struct GlobalConsciousness {
    /// O Grafo Neural (Append-Only)
    pub neural_graph: SkipList<u64, Vec<f32>>,

    /// O Dicionário Lock-Free (Mutações não bloqueiam leitores)
    pub dictionary: HashMap<String, u64>,
}

impl GlobalConsciousness {
    pub fn new() -> Self {
        Self {
            neural_graph: SkipList::new(crossbeam_epoch::default_collector().clone()),
            dictionary: HashMap::new(),
        }
    }
}

impl Default for GlobalConsciousness {
    fn default() -> Self {
        Self::new()
    }
}

/// A Inicialização do Motor Wasmtime blindado
pub fn initialize_wasm_engine(
    p2p_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    wal: titanium_host::storage::WalBuffer,
) -> (Engine, Store<HostState>, Memory, Linker<HostState>) {
    let mut config = Config::new();
    // Previne Halting Problem limitando as execuções JIT
    config.consume_fuel(true);
    // Ativa suporte a SIMD Wasm
    config.wasm_simd(true);

    let engine = Engine::new(&config).expect("Falha ao inicializar o Motor Wasmtime Titânio");

    let state = HostState {
        memory_store: SemanticMemoryStore::new(),
        p2p_tx,
        wal,
    };

    let mut store = Store::new(&engine, state);
    store.set_fuel(10_000_000).unwrap(); // Define Combustível inicial

    // O Titânio aloca a RAM bruta para o Córtex
    let mem_ty = MemoryType::new(100, None);
    let memory = Memory::new(&mut store, mem_ty).unwrap();

    let mut linker = Linker::new(&engine);
    // Definimos a memória do Host no Linker para o Wasm
    linker.define(&mut store, "env", "memory", memory).unwrap();

    // Injetamos as funções FFI do Primeiro Suspiro
    ffi::setup_linker(&mut linker).expect("Falha ao configurar FFI do Linker");

    (engine, store, memory, linker)
}

/// Carrega e injeta conceitos primordiais no Wasm Cortex
async fn bootstrap_knowledge(
    path: &std::path::Path,
    store: &mut Store<HostState>,
    memory: &Memory,
    get_ingest: &wasmtime::TypedFunc<(), u32>,
    ingest: &wasmtime::TypedFunc<(u32, u32), u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        println!(
            "[-] Arquivo de conhecimento base não encontrado em {:?}. Ignorando.",
            path
        );
        return Ok(());
    }

    let content = tokio::fs::read_to_string(path).await?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let mut concepts = Vec::new();
    if let Some(arr) = json.as_array() {
        for val in arr {
            if let Some(s) = val.as_str() {
                concepts.push(s.to_string());
            }
        }
    } else if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            concepts.push(k.clone());
            if let Some(s) = v.as_str() {
                concepts.push(s.to_string());
            }
        }
    }

    println!(
        "[*] Bootstrapping Semântico: Injetando {} conceitos...",
        concepts.len()
    );

    for concept in concepts {
        let hash = blake3::hash(concept.as_bytes());
        store
            .data_mut()
            .memory_store
            .semantic_dict
            .insert(*hash.as_bytes(), concept);

        let packet = titanium_host::types::NexoPacket {
            fragment_id: 0,
            payload: *hash.as_bytes(),
            provenance: titanium_host::types::Provenance::default(),
        };

        let bytes = postcard::to_allocvec(&packet)?;
        let ptr = get_ingest.call(&mut *store, ())?;
        memory.write(&mut *store, ptr as usize, &bytes)?;
        store.set_fuel(5_000_000).unwrap();
        let _ = ingest.call(&mut *store, (ptr, bytes.len() as u32))?;
    }

    println!("[+] Matriz Neural pré-aquecida com sucesso!");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================================");
    println!("NexoIA Titanium Host - Sequência de Ignição Iniciada");
    println!("=========================================================");

    // 1. Instanciação Lock-Free da Consciência
    let _consciousness = Arc::new(GlobalConsciousness::default());
    println!("[*] Consciência Global Lock-Free alocada com Sucesso.");

    // 1. Cria os canais
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(100);
    let (cli_tx, mut cli_rx) = tokio::sync::mpsc::channel::<(String, [u8; 32])>(100);

    // 1.5 Task Assíncrona do Terminal (A Boca e Ouvidos do Humano)
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            let hash = blake3::hash(line.as_bytes());
            let _ = cli_tx.send((line, *hash.as_bytes())).await;
        }
    });

    // 2. Inicialização do Motor Wasm Isolado, Mapeamento de RAM e Disco (WAL)
    let wal = titanium_host::storage::WalBuffer::new("nexo_wal.log")
        .expect("Falha ao inicializar a Medula (WAL)");
    let (_engine, mut _store, _memory, _linker) = initialize_wasm_engine(outbound_tx, wal);
    println!(
        "[*] Córtex Wasmtime Armado. Modo SIMD ativo. Proteção de Fuel (Halting-Problem) ativa."
    );

    // 3. Inicialização da Rede P2P Iroh (O Sistema Nervoso)
    if let Err(e) = titanium_host::p2p::start_p2p_node(tx, outbound_rx).await {
        eprintln!("[-] Falha crítica ao iniciar nó P2P: {:?}", e);
    }

    // 4. Abertura da Fronteira UDP (Stateless QUIC Edge)
    let edge_addr = "0.0.0.0:4433";
    let socket = UdpSocket::bind(edge_addr).await?;
    println!(
        "[*] Corta-Fogo Stateless QUIC/UDP escutando em {}",
        edge_addr
    );

    println!("[+] Carregando o binário Wasm Cortex...");
    let wasm_bytes = std::fs::read("target/wasm32-unknown-unknown/debug/wasm_cortex.wasm")
        .expect("Failed to read Wasm cortex! Did you run `cargo build -p wasm_cortex --target wasm32-unknown-unknown`?");
    let module = wasmtime::Module::new(&_engine, &wasm_bytes)?;
    let instance = _linker.instantiate(&mut _store, &module)?;

    println!("[+] Extraindo funções FFI da Sinapse...");
    let get_ingest_buffer_ptr =
        instance.get_typed_func::<(), u32>(&mut _store, "get_ingest_buffer_ptr")?;
    let ingest_packet = instance.get_typed_func::<(u32, u32), u32>(&mut _store, "ingest_packet")?;

    println!("[+] NexoIA operando na Arquitetura Nível 6. Reflexo Neural Ativo.");

    // Missão 8.2: Bootstrapping Semântico
    if let Err(e) = bootstrap_knowledge(
        std::path::Path::new("knowledge.json"),
        &mut _store,
        &_memory,
        &get_ingest_buffer_ptr,
        &ingest_packet,
    )
    .await
    {
        eprintln!(
            "[-] Falha ao inicializar a Ingestão de Conhecimento: {:?}",
            e
        );
    }

    // Loop principal da Borda (Escutando os pacotes)
    // Em produção, isso alimentará a Quinn (QUIC Endpoint)
    let mut buf = [0; 65535];
    loop {
        tokio::select! {
            Some(packet) = rx.recv() => {
                println!("[*] P2P -> Wasm: Recebendo {} bytes da rede", packet.len());
                let ptr = get_ingest_buffer_ptr.call(&mut _store, ())?;

                // Write into Wasm memory
                _memory.write(&mut _store, ptr as usize, &packet)?;

                _store.set_fuel(5_000_000).unwrap();
                let result = ingest_packet.call(&mut _store, (ptr, packet.len() as u32))?;
                match result {
                    1 => println!("[+] Wasm: Pacote assimilado via Zero-Copy!"),
                    3 => println!("[⚡] Wasm: Expansão Cognitiva! O Córtex absorveu uma anomalia."),
                    _ => println!("[-] Wasm: Falha na decodificação do pacote."),
                }

                // Gatilho do Garbage Collector a Frio (Snapshot Zstd)
                if _store.data().wal.cursor() > 1024 * 1024 {
                    println!("[*] Medula WAL atingiu limite de 1MB. Congelando Engrama (Snapshot Zstd)...");
                    let path = std::path::Path::new("nexo_brain.zst");
                    if let Err(e) = titanium_host::storage::create_snapshot(&_store.data().memory_store, path) {
                        eprintln!("[-] Falha crítica ao congelar o Engrama: {:?}", e);
                    } else if let Err(e) = _store.data_mut().wal.reset() {
                        eprintln!("[-] Falha crítica ao limpar o WAL após Snapshot: {:?}", e);
                    } else {
                        println!("[+] Medula WAL limpa e pronta para novos registros.");
                    }
                }
            }
            Some((text, hash)) = cli_rx.recv() => {
                // 1. Registra no Dicionário Semântico (Memória do Host)
                _store.data_mut().memory_store.semantic_dict.insert(hash, text);

                // 2. Transforma o Texto num NexoPacket Estrito
                let packet = titanium_host::types::NexoPacket {
                    fragment_id: 0,
                    payload: hash,
                    provenance: titanium_host::types::Provenance::default(),
                };

                if let Ok(bytes) = postcard::to_allocvec(&packet) {
                    println!("[*] Humano -> Wasm: Injetando Encadeamento Semântico...");
                    let ptr = get_ingest_buffer_ptr.call(&mut _store, ())?;
                    _memory.write(&mut _store, ptr as usize, &bytes)?;

                    _store.set_fuel(5_000_000).unwrap();
                    let result = ingest_packet.call(&mut _store, (ptr, bytes.len() as u32))?;
                    match result {
                        1 => println!("[+] Córtex Absorveu a Mensagem!"),
                        3 => println!("[⚡] Expansão Cognitiva! O Córtex adaptou-se à sua entropia."),
                        _ => println!("[-] Córtex rejeitou o pacote."),
                    }
                }
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((_len, _src)) = res {
                    // Validação de Hashcash e NanoEpa aqui, ANTES de ceder Memória
                }
            }
        }
    }
}
