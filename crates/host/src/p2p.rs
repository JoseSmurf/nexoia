use anyhow::Result;
use iroh::{endpoint::presets, Endpoint};

pub async fn start_p2p_node() -> Result<()> {
    // 1. Inicia um nó Iroh anônimo/epêmero
    let endpoint = Endpoint::builder(presets::N0).bind().await?;
    let node_id = endpoint.id();

    println!("🔥 Nó NexoIA online. ID P2P: {}", node_id);

    // 2. Trava o nó escutando em uma task separada (placeholder para o loop de roteamento)
    tokio::spawn(async move {
        // Futuro listener de pacotes e chamadas FFI
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    });

    Ok(())
}
