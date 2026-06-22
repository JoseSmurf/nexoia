use nexoia::network::epa::SharedEPA;
use nexoia::network::identity::NodeIdentity;
use nexoia::network::transport::{NetworkMessage, PeerState, TrustedPeerList, UdpTransport};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Nó simplificado para testes
struct TestNode {
    identity: NodeIdentity,
    transport: UdpTransport,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
}

impl TestNode {
    async fn new(name: &str, port: u16) -> Self {
        let identity = NodeIdentity::generate(name);
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let transport = UdpTransport::bind(addr).await.unwrap();
        let trusted_peers = Arc::new(RwLock::new(TrustedPeerList::new(10)));

        Self {
            identity,
            transport,
            trusted_peers,
        }
    }

    async fn send(&self, msg: &NetworkMessage, target: SocketAddr) {
        let _ = self.transport.send(msg, target).await;
    }
}

// ============================================================================
// CENÁRIO 1: Subida básica de múltiplos nós
// ============================================================================

#[tokio::test]
async fn test_three_nodes_send_hello() {
    // Arrange
    let node_a = TestNode::new("alpha", 18100).await;
    let node_b = TestNode::new("beta", 18101).await;
    let node_c = TestNode::new("gamma", 18102).await;

    let addr_a: SocketAddr = "127.0.0.1:18100".parse().unwrap();

    // Act: Cada nó envia Hello
    let hello_a = NetworkMessage::Hello {
        node_id: node_a.identity.node_id.clone(),
        public_key: node_a.identity.public_key.clone(),
        encryption_public_key: node_a.identity.encryption_keypair.public_bytes().to_vec(),
    };
    let hello_b = NetworkMessage::Hello {
        node_id: node_b.identity.node_id.clone(),
        public_key: node_b.identity.public_key.clone(),
        encryption_public_key: node_b.identity.encryption_keypair.public_bytes().to_vec(),
    };
    let hello_c = NetworkMessage::Hello {
        node_id: node_c.identity.node_id.clone(),
        public_key: node_c.identity.public_key.clone(),
        encryption_public_key: node_c.identity.encryption_keypair.public_bytes().to_vec(),
    };

    node_b.send(&hello_b, addr_a).await;
    node_c.send(&hello_c, addr_a).await;

    // Assert: Mensagens são serializadas corretamente
    let serialized = serde_json::to_vec(&hello_a).unwrap();
    let deserialized: NetworkMessage = serde_json::from_slice(&serialized).unwrap();

    match deserialized {
        NetworkMessage::Hello { node_id, .. } => {
            assert_eq!(node_id, node_a.identity.node_id);
        }
        _ => panic!("Expected Hello message"),
    }
}

#[tokio::test]
async fn test_handshake_challenge_response_flow() {
    // Arrange
    let node_a = TestNode::new("alpha", 18200).await;
    let node_b = TestNode::new("beta", 18201).await;

    // Act: Node A cria challenge
    let challenge_hash = "abc123";
    let challenge = NetworkMessage::Challenge {
        challenge_hash: challenge_hash.to_string(),
    };

    // Node B assina o challenge
    let signature = node_b.identity.sign(challenge_hash);

    // Assert: Assinatura é válida
    assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes

    // Verificar que a resposta é serializável
    let response = NetworkMessage::ChallengeResponse { signature };
    let serialized = serde_json::to_vec(&response).unwrap();
    let deserialized: NetworkMessage = serde_json::from_slice(&serialized).unwrap();

    match deserialized {
        NetworkMessage::ChallengeResponse { signature: sig } => {
            assert_eq!(sig.len(), 64);
        }
        _ => panic!("Expected ChallengeResponse message"),
    }
}

#[tokio::test]
async fn test_epa_signature_is_ed25519() {
    // Arrange
    let node = TestNode::new("sender", 18300).await;

    // Act
    let epa = SharedEPA::create(
        &node.identity,
        r#"{"project":"test"}"#,
        r#"{"evidence":"data"}"#,
        r#"{"decision":"ok"}"#,
        r#"{"manifest":"v1"}"#,
    );

    // Assert
    assert!(epa.verify_integrity());
    assert!(epa.verify_signature().is_ok());
    assert_eq!(epa.ed25519_signature.len(), 64);
}

#[tokio::test]
async fn test_multiple_nodes_create_unique_epas() {
    // Arrange
    let node_a = TestNode::new("alpha", 18400).await;
    let node_b = TestNode::new("beta", 18401).await;
    let node_c = TestNode::new("gamma", 18402).await;

    // Act
    let epa_a = SharedEPA::create(
        &node_a.identity,
        r#"{"from":"alpha"}"#,
        r#"{"evidence":"a"}"#,
        r#"{"decision":"ok"}"#,
        r#"{"manifest":"v1"}"#,
    );

    let epa_b = SharedEPA::create(
        &node_b.identity,
        r#"{"from":"beta"}"#,
        r#"{"evidence":"b"}"#,
        r#"{"decision":"ok"}"#,
        r#"{"manifest":"v1"}"#,
    );

    let epa_c = SharedEPA::create(
        &node_c.identity,
        r#"{"from":"gamma"}"#,
        r#"{"evidence":"c"}"#,
        r#"{"decision":"ok"}"#,
        r#"{"manifest":"v1"}"#,
    );

    // Assert: Cada EPA tem assinatura e hash únicos
    assert_ne!(epa_a.ed25519_signature, epa_b.ed25519_signature);
    assert_ne!(epa_b.ed25519_signature, epa_c.ed25519_signature);
    assert_ne!(epa_a.integrity_hash, epa_b.integrity_hash);
    assert_ne!(epa_b.integrity_hash, epa_c.integrity_hash);
}

// ============================================================================
// CENÁRIO 2: Heartbeat e detecção de falhas
// ============================================================================

#[tokio::test]
async fn test_peer_state_heartbeat_tracking() {
    // Arrange
    let mut state = PeerState::new();

    // Act & Assert: Estado inicial
    assert_eq!(state.consecutive_misses, 0);

    // Act: Simular heartbeat
    state.record_heartbeat();
    assert!(!state.is_inactive(30));
    assert_eq!(state.consecutive_misses, 0);

    // Act: Simular misses (mas menos que o mínimo)
    state.record_miss();
    assert_eq!(state.consecutive_misses, 1);
    // Ainda não inativo (precisa de 3+ misses)
    assert!(!state.is_inactive(30));

    // Act: Heartbeat reseta misses
    state.record_heartbeat();
    assert_eq!(state.consecutive_misses, 0);
    assert!(!state.is_inactive(30));
}

#[tokio::test]
async fn test_heartbeat_message_serialization() {
    // Arrange
    let msg = NetworkMessage::Heartbeat {
        node_id: "node_1".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // Act
    let serialized = serde_json::to_vec(&msg).unwrap();
    let deserialized: NetworkMessage = serde_json::from_slice(&serialized).unwrap();

    // Assert
    match deserialized {
        NetworkMessage::Heartbeat { node_id, timestamp } => {
            assert_eq!(node_id, "node_1");
            assert!(!timestamp.is_empty());
        }
        _ => panic!("Expected Heartbeat message"),
    }
}

#[tokio::test]
async fn test_heartbeat_ack_serialization() {
    // Arrange
    let msg = NetworkMessage::HeartbeatAck {
        node_id: "node_2".to_string(),
    };

    // Act
    let serialized = serde_json::to_vec(&msg).unwrap();
    let deserialized: NetworkMessage = serde_json::from_slice(&serialized).unwrap();

    // Assert
    match deserialized {
        NetworkMessage::HeartbeatAck { node_id } => {
            assert_eq!(node_id, "node_2");
        }
        _ => panic!("Expected HeartbeatAck message"),
    }
}

// ============================================================================
// CENÁRIO 3: Reputação e banimento
// ============================================================================

#[tokio::test]
async fn test_reputation_ban_after_failures() {
    use nexoia::network::reputation::ReputationStore;

    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reputation.json");
    let mut store = ReputationStore::with_path(path);

    // Act: Simular 10 falhas
    for _ in 0..10 {
        store.record_failure("bad_node");
    }

    // Assert: Nó está banido
    assert!(store.is_banned("bad_node"));

    // Act: Nó bom não está banido
    store.record_success("good_node");
    assert!(!store.is_banned("good_node"));
}

// ============================================================================
// CENÁRIO 4: Persistência
// ============================================================================

#[tokio::test]
async fn test_persistence_roundtrip() {
    use nexoia::network::persistence::{self, PersistedData};

    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_data.json");

    let mut data = PersistedData::default();
    data.peers.push("127.0.0.1:9001".to_string());
    data.peers.push("127.0.0.1:9002".to_string());

    // Act
    persistence::save_data(&path, &data).unwrap();
    let loaded = persistence::load_data(&path).unwrap();

    // Assert
    assert_eq!(loaded.peers.len(), 2);
    assert_eq!(loaded.peers[0], "127.0.0.1:9001");
    assert_eq!(loaded.peers[1], "127.0.0.1:9002");
}

#[tokio::test]
async fn test_persistence_skips_invalid_peers() {
    use nexoia::network::persistence::{self, PersistedData};

    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_data.json");

    let mut data = PersistedData::default();
    data.peers.push("127.0.0.1:9001".to_string());
    data.peers.push("invalid_addr".to_string());
    data.peers.push("127.0.0.1:9002".to_string());

    // Act
    persistence::save_data(&path, &data).unwrap();
    let loaded = persistence::load_data(&path).unwrap();

    // Assert: Endereço inválido foi removido
    assert_eq!(loaded.peers.len(), 2);
}
