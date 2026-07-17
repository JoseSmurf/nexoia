use anyhow::Result;
use bytes::Bytes;
use futures_util::{stream::FusedStream, StreamExt};
use iroh::{endpoint::presets, protocol::Router, Endpoint};
use iroh_gossip::{api::Event, net::Gossip, TopicId, ALPN};
use tokio::sync::mpsc;

pub async fn start_p2p_node(
    tx: mpsc::Sender<Bytes>,
    mut outbound_rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    // 1. Inicia um nó Iroh anônimo/epêmero
    let endpoint = Endpoint::builder(presets::N0).bind().await?;
    let node_id = endpoint.id();

    println!("🔥 Nó NexoIA online. ID P2P: {}", node_id);

    // 2. Constrói o protocolo Gossip e o Roteador
    let gossip = Gossip::builder().spawn(endpoint.clone());

    let _router = Router::builder(endpoint)
        .accept(ALPN, gossip.clone())
        .spawn();

    // 3. Define o Tópico Neural do Enxame
    let topic_id = TopicId::from_bytes([23u8; 32]);
    let gossip_topic = gossip.subscribe(topic_id, vec![]).await?;

    // 4. Laço de Ingestão e Transmissão
    tokio::spawn(async move {
        let (broadcast, events) = gossip_topic.split();
        let mut events = events.fuse();
        loop {
            tokio::select! {
                Some(packet) = outbound_rx.recv() => {
                    println!("🌐 [P2P ROUTER] Transmitindo reflexo de {} bytes para o enxame Iroh...", packet.len());
                    let _ = broadcast.broadcast(packet).await;
                }
                event = events.next(), if !events.is_terminated() => {
                    match event {
                        Some(Ok(Event::Received(msg))) => {
                            if msg.content.len() <= 1024 {
                                let _ = tx.send(msg.content).await;
                            }
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
        }
    });

    Ok(())
}
