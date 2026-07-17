use anyhow::Result;
use iroh::node::Node;

pub async fn start_p2p_node() -> Result<()> {
    // 1. Inicia um nó Iroh anônimo/epêmero com store em memória
    let node = Node::memory().spawn().await?;
    let node_id = node.node_id();

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
