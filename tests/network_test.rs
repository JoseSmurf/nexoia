use nexoia::network::epa::SharedEPA;
use nexoia::network::identity::NodeIdentity;
use nexoia::network::persistence::{self, PersistedData};
use nexoia::network::transport::{NetworkMessage, PeerList, UdpTransport};
use nexoia::network::verify::{verify_epa, VerifyResult};
use std::net::SocketAddr;

#[tokio::test]
async fn two_nodes_can_communicate() {
    let node_a = NodeIdentity::generate("node_a");

    let addr_a: SocketAddr = "127.0.0.1:19100".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:19101".parse().unwrap();

    let transport_a = UdpTransport::bind(addr_a).await.unwrap();
    let transport_b = UdpTransport::bind(addr_b).await.unwrap();

    let ping = NetworkMessage::Ping {
        node_id: node_a.node_id.clone(),
    };

    transport_a.send(&ping, addr_b).await.unwrap();

    let mut buf = [0u8; 65536];
    let (msg, from) = transport_b.recv(&mut buf).await.unwrap();
    assert!(matches!(msg, NetworkMessage::Ping { .. }));
    assert_eq!(from, addr_a);
}

#[tokio::test]
async fn epa_sharing_between_nodes() {
    let node_a = NodeIdentity::generate("sharer");

    let addr_a: SocketAddr = "127.0.0.1:19102".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:19103".parse().unwrap();

    let transport_a = UdpTransport::bind(addr_a).await.unwrap();
    let transport_b = UdpTransport::bind(addr_b).await.unwrap();

    let state = r#"{"project":"test"}"#;
    let evidence = r#"{"evidence":"data"}"#;
    let decision = r#"{"decision":"ok"}"#;
    let manifest = r#"{"manifest":"v1"}"#;

    let epa = SharedEPA::create(&node_a, state, evidence, decision, manifest);

    let msg = NetworkMessage::EPA(epa.clone());
    transport_a.send(&msg, addr_b).await.unwrap();

    let mut buf = [0u8; 65536];
    let (received, _) = transport_b.recv(&mut buf).await.unwrap();
    if let NetworkMessage::EPA(received_epa) = received {
        assert!(received_epa.verify_full().is_ok());
        assert_eq!(received_epa.epa_id, epa.epa_id);
    } else {
        panic!("Expected EPA message");
    }
}

#[test]
fn persistence_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("network.json");

    let mut data = PersistedData::default();
    data.peers.push("127.0.0.1:9001".to_string());
    data.peers.push("127.0.0.1:9002".to_string());

    persistence::save_data(&path, &data).unwrap();
    let loaded = persistence::load_data(&path).unwrap();

    assert_eq!(loaded.peers.len(), 2);
}

#[test]
fn node_identity_persists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.json");

    let a = NodeIdentity::load_or_create(&path, "persist_test", None).unwrap();
    let b = NodeIdentity::load_or_create(&path, "persist_test", None).unwrap();

    assert_eq!(a.node_id, b.node_id);
    assert_eq!(a.public_key, b.public_key);
}

#[test]
fn epa_verification_works() {
    let node = NodeIdentity::generate("verifier");
    let state = r#"{"project":"test"}"#;
    let evidence = r#"{"evidence":"data"}"#;
    let decision = r#"{"decision":"ok"}"#;
    let manifest = r#"{"manifest":"v1"}"#;

    let epa = SharedEPA::create(&node, state, evidence, decision, manifest);

    let result = verify_epa(&epa);
    assert!(matches!(result, VerifyResult::Valid));
}

#[test]
fn peer_list_management() {
    let mut list = PeerList::new(3);
    let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    let addr3: SocketAddr = "127.0.0.1:9003".parse().unwrap();

    assert!(list.add(addr1));
    assert!(list.add(addr2));
    assert!(list.add(addr3));
    assert!(!list.add(addr1));
    assert_eq!(list.len(), 3);
}
