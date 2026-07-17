use anyhow::Result;
use bytes::Bytes;
use iroh::{endpoint::presets, Endpoint};
use tokio::sync::mpsc;

pub async fn start_p2p_node(
    tx: mpsc::Sender<Bytes>,
    mut outbound_rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    // 1. Inicia um nó Iroh anônimo/epêmero
    let endpoint = Endpoint::builder(presets::N0).bind().await?;
    let node_id = endpoint.id();

    println!("🔥 Nó NexoIA online. ID P2P: {}", node_id);

    // 2. Trava o nó escutando em uma task separada (placeholder para o loop de roteamento)
    tokio::spawn(async move {
        // Simulando a chegada de um pacote UDP P2P
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
                    // Dummy payload (vamos disparar falhas propositais no schema primeiro)
                    let dummy_data = Bytes::from_static(&[0u8; 64]);
                    let _ = tx.send(dummy_data).await;
                }
                Some(packet) = outbound_rx.recv() => {
                    println!("🌐 [P2P ROUTER] Transmitindo reflexo de {} bytes para o enxame Iroh...", packet.len());
                }
            }
        }
    });

    Ok(())
}
