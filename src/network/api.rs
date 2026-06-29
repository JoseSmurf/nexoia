use crate::defense::RateLimiter;
use crate::lgpd_rights::{
    self, AnonymizationResult, EpaRef, LgpdIndex, RevocationResult, TitularExport,
};
use crate::limits::MAX_EPA_ENTRIES;
use crate::network::epa::SharedEPA;
use crate::network::identity::NodeIdentity;
use crate::network::transport::{NetworkMessage, PeerList, UdpTransport};
use crate::network::verify::{verify_epa, VerifyResult};
use axum::{
    extract::{ConnectInfo, Json, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ApiState {
    pub node_id: String,
    pub public_key: String,
    pub node_identity: NodeIdentity,
    pub epas: Arc<RwLock<Vec<SharedEPA>>>,
    pub peers: Arc<RwLock<PeerList>>,
    pub transport: Arc<UdpTransport>,
    pub lgpd_index: Arc<RwLock<LgpdIndex>>,
    pub rate_limiter: Arc<RateLimiter>,
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct NodeListResponse {
    pub node_id: String,
    pub epa_count: usize,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: String,
    pub epa_id: String,
}

#[derive(Deserialize)]
pub struct EncryptedEpaRequest {
    pub state_json: String,
    pub evidence_jsonl: String,
    pub decisions_jsonl: String,
    pub manifest_json: String,
    pub recipient_public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct QuickVerifyResponse {
    pub signature_valid: bool,
    pub integrity_valid: bool,
    pub epa_id: String,
}

/// Broadcasts EPA to all known peers via UDP.
async fn broadcast_epa(state: &ApiState, epa: &SharedEPA) {
    let peer_list = state.peers.read().await;
    let addrs: Vec<SocketAddr> = peer_list.peers().to_vec();
    drop(peer_list);

    if addrs.is_empty() {
        return;
    }

    let msg = NetworkMessage::EPA(epa.clone());
    let mut sent = 0usize;
    for addr in &addrs {
        if state.transport.send(&msg, *addr).await.is_ok() {
            sent += 1;
        }
    }
    if sent > 0 {
        println!(
            "→ Broadcast EPA {} to {}/{} peers",
            epa.epa_id,
            sent,
            addrs.len()
        );
    }
}

/// Middleware de rate limiting.
async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<ApiState>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Health check é livre (para load balancers)
    if request.uri().path() == "/health" {
        return Ok(next.run(request).await);
    }

    let key = addr.ip().to_string();
    if !state.rate_limiter.check(&key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

pub async fn create_api(state: ApiState, addr: SocketAddr) -> Result<(), std::io::Error> {
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

pub async fn create_api_tls(
    state: ApiState,
    addr: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(), std::io::Error> {
    use std::io::BufReader;

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, format!("TLS cert: {e}")))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, format!("TLS key: {e}")))?;

    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cert parse: {e}")))?;

    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("key parse: {e}")))?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found"))?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("TLS config: {e}")))?;

    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("TLS API listening on https://{}", addr);

    loop {
        let (stream, _remote_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let hyper_service = hyper_util::service::TowerToHyperService::new(app);
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(tls_stream),
                        hyper_service,
                    )
                    .await
                    {
                        eprintln!("TLS session error: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("TLS handshake failed: {}", e);
                }
            }
        });
    }
}

fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/node", get(node_info))
        .route("/epa", post(receive_epa))
        .route("/epa/encrypted", post(receive_encrypted_epa))
        .route("/epa/list", get(list_epas))
        .route("/epa/:id/verify", post(verify_epa_endpoint))
        .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
        .route("/titular/:hash/dados", get(titular_dados))
        .route("/titular/:hash/export", get(titular_export))
        .route("/titular/:hash", delete(titular_anonymize))
        .route("/titular/:hash/revogar", post(titular_revoke))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
}

async fn health() -> Json<ApiResponse> {
    Json(ApiResponse {
        status: "ok".to_string(),
        message: "nexoia node is running".to_string(),
    })
}

async fn node_info(State(state): State<ApiState>) -> Json<NodeListResponse> {
    let epas = state.epas.read().await;
    Json(NodeListResponse {
        node_id: state.node_id.clone(),
        epa_count: epas.len(),
    })
}

async fn receive_epa(
    State(state): State<ApiState>,
    Json(epa): Json<SharedEPA>,
) -> Result<Json<ApiResponse>, StatusCode> {
    let result = verify_epa(&epa);

    match result {
        VerifyResult::Valid => {
            let mut epas = state.epas.write().await;
            if epas.len() >= MAX_EPA_ENTRIES {
                // Evict oldest (first element)
                epas.remove(0);
            }
            epas.push(epa.clone());
            drop(epas);
            broadcast_epa(&state, &epa).await;
            Ok(Json(ApiResponse {
                status: "accepted".to_string(),
                message: "EPA received and verified".to_string(),
            }))
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn list_epas(State(state): State<ApiState>) -> Json<Vec<SharedEPA>> {
    let epas = state.epas.read().await;
    Json(epas.clone())
}

async fn verify_epa_endpoint(
    State(state): State<ApiState>,
    axum::extract::Path(epa_id): axum::extract::Path<String>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    let epas = state.epas.read().await;
    let epa = epas
        .iter()
        .find(|e| e.epa_id == epa_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let result = verify_epa(epa);

    Ok(Json(VerifyResponse {
        result: result.to_string(),
        epa_id: epa.epa_id.clone(),
    }))
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn receive_encrypted_epa(
    State(state): State<ApiState>,
    Json(req): Json<EncryptedEpaRequest>,
) -> Result<Json<SharedEPA>, (StatusCode, Json<ErrorResponse>)> {
    let recipient_key_bytes = hex::decode(&req.recipient_public_key).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid hex in recipient_public_key: {}", e),
            }),
        )
    })?;

    if recipient_key_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "recipient_public_key must be 32 bytes, got {}",
                    recipient_key_bytes.len()
                ),
            }),
        ));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&recipient_key_bytes);

    // Extract LGPD metadata from request if present (for index insertion)
    let lgpd_metadata = None; // Could be extended to accept LGPD in request

    let epa = SharedEPA::create_encrypted(
        &state.node_identity,
        &req.state_json,
        &req.evidence_jsonl,
        &req.decisions_jsonl,
        &req.manifest_json,
        &key_arr,
        lgpd_metadata,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("encryption failed: {}", e),
            }),
        )
    })?;

    let mut epas = state.epas.write().await;
    if epas.len() >= MAX_EPA_ENTRIES {
        epas.remove(0);
    }
    epas.push(epa.clone());
    drop(epas);

    broadcast_epa(&state, &epa).await;

    Ok(Json(epa))
}

async fn verify_quick_endpoint(
    State(state): State<ApiState>,
    axum::extract::Path(epa_id): axum::extract::Path<String>,
) -> Result<Json<QuickVerifyResponse>, StatusCode> {
    let epas = state.epas.read().await;
    let epa = epas
        .iter()
        .find(|e| e.epa_id == epa_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let signature_valid = epa.verify_signature().is_ok();
    let integrity_valid = epa.verify_integrity();

    Ok(Json(QuickVerifyResponse {
        signature_valid,
        integrity_valid,
        epa_id: epa.epa_id.clone(),
    }))
}

// ── LGPD Nível 2: Direitos do Titular ─────────────────────

/// GET /titular/:hash/dados — lista todos os EPAs de um titular.
async fn titular_dados(
    State(state): State<ApiState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Json<Vec<EpaRef>>, StatusCode> {
    let index = state.lgpd_index.read().await;
    let refs = index.lookup(&hash);
    Ok(Json(refs.into_iter().cloned().collect()))
}

/// GET /titular/:hash/export — portabilidade JSON.
async fn titular_export(
    State(state): State<ApiState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Json<TitularExport>, StatusCode> {
    let index = state.lgpd_index.read().await;
    let refs: Vec<EpaRef> = index.lookup(&hash).into_iter().cloned().collect();

    Ok(Json(TitularExport {
        data_subject_hash: hash,
        epas: refs,
        exported_at: chrono::Utc::now(),
    }))
}

/// DELETE /titular/:hash — anonimiza dados pessoais + gera EPA de supressão.
/// Lock order: lgpd_index (read) -> epas (write) -> lgpd_index (write)
/// epas lock is dropped BEFORE broadcast_epa (which acquires peers lock)
async fn titular_anonymize(
    State(state): State<ApiState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Json<Vec<AnonymizationResult>>, StatusCode> {
    let index = state.lgpd_index.read().await;
    let refs: Vec<EpaRef> = index.lookup(&hash).into_iter().cloned().collect();
    drop(index);

    if refs.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut results = Vec::new();
    let mut suppressions = Vec::new();

    {
        let mut epas = state.epas.write().await;

        for epa_ref in &refs {
            if let Some(epa) = epas.iter_mut().find(|e| e.epa_id == epa_ref.epa_id) {
                let fields = lgpd_rights::anonymize_epa_fields(epa);

                let suppression = lgpd_rights::create_suppression_epa(&state.node_identity, epa);

                let result = AnonymizationResult {
                    original_epa_id: epa_ref.epa_id.clone(),
                    suppression_epa_id: suppression.epa_id.clone(),
                    fields_anonymized: fields,
                    timestamp: chrono::Utc::now(),
                };

                if epas.len() >= MAX_EPA_ENTRIES {
                    epas.remove(0);
                }
                epas.push(suppression.clone());
                suppressions.push(suppression);

                results.push(result);
            }
        }
    } // epas lock dropped here

    // Broadcast suppression EPAs (acquires peers lock - must come after epas lock)
    for suppression in &suppressions {
        broadcast_epa(&state, suppression).await;
    }

    // Atualiza índice
    let mut index = state.lgpd_index.write().await;
    for r in &results {
        index.remove_epa(&hash, &r.original_epa_id);
        index.insert(
            hash.clone(),
            EpaRef {
                epa_id: r.suppression_epa_id.clone(),
                epa_hash: crate::hash::canonical_hash(&r.suppression_epa_id),
                lawful_basis: crate::lgpd::LawfulBasis::ObrigacaoLegal,
                purpose: "lgpd_suppression".to_string(),
                created_at: r.timestamp,
                expires_at: r.timestamp + chrono::Duration::days(365 * 10),
            },
        );
    }

    Ok(Json(results))
}

/// POST /titular/:hash/revogar — revoga consentimento.
async fn titular_revoke(
    State(state): State<ApiState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Json<Vec<RevocationResult>>, StatusCode> {
    let index = state.lgpd_index.read().await;
    let refs: Vec<EpaRef> = index.lookup(&hash).into_iter().cloned().collect();
    drop(index);

    if refs.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut results = Vec::new();
    let mut index = state.lgpd_index.write().await;

    for epa_ref in &refs {
        if epa_ref.lawful_basis == crate::lgpd::LawfulBasis::Consentimento {
            let result = RevocationResult {
                epa_id: epa_ref.epa_id.clone(),
                revoked_at: chrono::Utc::now(),
                lawful_basis_before: epa_ref.lawful_basis,
            };
            index.remove_epa(&hash, &epa_ref.epa_id);
            results.push(result);
        }
    }

    Ok(Json(results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::NodeIdentity;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn test_state() -> ApiState {
        let node = NodeIdentity::generate("test");
        let transport = Arc::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        ApiState {
            node_id: node.node_id.clone(),
            public_key: node.public_key.clone(),
            node_identity: node.clone(),
            epas: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(PeerList::new(10))),
            transport,
            lgpd_index: Arc::new(RwLock::new(LgpdIndex::new())),
            rate_limiter: Arc::new(RateLimiter::new(100, std::time::Duration::from_secs(60))),
        }
    }

    fn test_app(state: ApiState) -> Router {
        Router::new()
            .route("/health", get(health))
            .route("/node", get(node_info))
            .route("/epa", post(receive_epa))
            .route("/epa/encrypted", post(receive_encrypted_epa))
            .route("/epa/list", get(list_epas))
            .route("/epa/:id/verify", post(verify_epa_endpoint))
            .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
            .route("/titular/:hash/dados", get(titular_dados))
            .route("/titular/:hash/export", get(titular_export))
            .route("/titular/:hash", delete(titular_anonymize))
            .route("/titular/:hash/revogar", post(titular_revoke))
            .with_state(state)
    }

    // ── Health ──────────────────────────────────────────────

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let state = test_state().await;
        let app = test_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Rate Limiter ────────────────────────────────────────

    #[tokio::test]
    async fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, std::time::Duration::from_secs(1));

        assert!(limiter.check("127.0.0.1"));
        assert!(limiter.check("127.0.0.1"));
        assert!(!limiter.check("127.0.0.1"));
    }

    #[tokio::test]
    async fn rate_limiter_allows_different_ips() {
        let limiter = RateLimiter::new(1, std::time::Duration::from_secs(1));

        assert!(limiter.check("127.0.0.1"));
        assert!(limiter.check("127.0.0.2"));
        assert!(!limiter.check("127.0.0.1"));
    }

    #[tokio::test]
    async fn rate_limiter_resets_after_window() {
        let limiter = RateLimiter::new(1, std::time::Duration::from_millis(100));

        assert!(limiter.check("127.0.0.1"));
        assert!(!limiter.check("127.0.0.1"));

        std::thread::sleep(std::time::Duration::from_millis(150));

        assert!(limiter.check("127.0.0.1"));
    }

    // ── POST /epa/encrypted ─────────────────────────────────

    #[tokio::test]
    async fn encrypted_epa_valid_request() {
        let state = test_state().await;
        let app = test_app(state);
        let recipient = NodeIdentity::generate("recipient");
        let recipient_pub = hex::encode(&recipient.encryption_keypair.public_bytes()[..32]);

        let body = serde_json::to_string(&serde_json::json!({
            "state_json": r#"{"project":"test"}"#,
            "evidence_jsonl": r#"{"evidence":"ok"}"#,
            "decisions_jsonl": r#"{"decision":"ok"}"#,
            "manifest_json": r#"{"manifest":"v1"}"#,
            "recipient_public_key": recipient_pub,
        }))
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/epa/encrypted")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let epa: SharedEPA = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!epa.epa_id.is_empty());
        assert!(epa.encrypted_payload.is_some());
        assert!(epa.ephemeral_public_key.is_some());
    }

    #[tokio::test]
    async fn encrypted_epa_invalid_hex_key() {
        let state = test_state().await;
        let app = test_app(state);

        let body = serde_json::to_string(&serde_json::json!({
            "state_json": r#"{"project":"test"}"#,
            "evidence_jsonl": r#"{"evidence":"ok"}"#,
            "decisions_jsonl": r#"{"decision":"ok"}"#,
            "manifest_json": r#"{"manifest":"v1"}"#,
            "recipient_public_key": "not-valid-hex!!!",
        }))
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/epa/encrypted")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(err.error.contains("invalid hex"));
    }

    #[tokio::test]
    async fn encrypted_epa_key_wrong_length() {
        let state = test_state().await;
        let app = test_app(state);

        let body = serde_json::to_string(&serde_json::json!({
            "state_json": r#"{"project":"test"}"#,
            "evidence_jsonl": r#"{"evidence":"ok"}"#,
            "decisions_jsonl": r#"{"decision":"ok"}"#,
            "manifest_json": r#"{"manifest":"v1"}"#,
            "recipient_public_key": "ab", // 1 byte, needs 32
        }))
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/epa/encrypted")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(err.error.contains("32 bytes"));
    }

    #[tokio::test]
    async fn encrypted_epa_missing_field() {
        let state = test_state().await;
        let app = test_app(state);

        let body = serde_json::to_string(&serde_json::json!({
            "state_json": r#"{"project":"test"}"#,
            "evidence_jsonl": r#"{"evidence":"ok"}"#,
            "decisions_jsonl": r#"{"decision":"ok"}"#,
            // missing manifest_json and recipient_public_key
        }))
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/epa/encrypted")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY); // 422
    }

    // ── GET /epa/{id}/verify-quick ──────────────────────────

    #[tokio::test]
    async fn verify_quick_existing_epa() {
        let state = test_state().await;
        let node = state.node_identity.clone();

        let epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );
        let epa_id = epa.epa_id.clone();

        state.epas.write().await.push(epa);

        let app = Router::new()
            .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/epa/{}/verify-quick", epa_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: QuickVerifyResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(resp.signature_valid);
        assert_eq!(resp.epa_id, epa_id);
    }

    #[tokio::test]
    async fn verify_quick_nonexistent_epa() {
        let state = test_state().await;

        let app = Router::new()
            .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/epa/nonexistent_id/verify-quick")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_quick_tampered_epa() {
        let state = test_state().await;
        let node = state.node_identity.clone();

        let mut epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );
        let epa_id = epa.epa_id.clone();

        // Tamper with the state_hash — breaks integrity but signature check
        // still passes (signature is over original integrity_hash, not state_hash)
        epa.state_hash = "tampered".to_string();
        state.epas.write().await.push(epa);

        let app = Router::new()
            .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/epa/{}/verify-quick", epa_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: QuickVerifyResponse = serde_json::from_slice(&body_bytes).unwrap();
        // verify_quick only checks Ed25519 signature, not integrity
        assert!(resp.signature_valid);
        assert_eq!(resp.epa_id, epa_id);
    }

    // ── POST /epa (receive_epa) ─────────────────────────────

    #[tokio::test]
    async fn receive_epa_valid() {
        let state = test_state().await;
        let node = state.node_identity.clone();

        let epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );

        let app = Router::new()
            .route("/epa", post(receive_epa))
            .with_state(state.clone());

        let body = serde_json::to_string(&epa).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/epa")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.epas.read().await.len(), 1);
    }

    #[tokio::test]
    async fn receive_epa_tampered_rejected() {
        let state = test_state().await;
        let node = state.node_identity.clone();

        let mut epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );
        epa.state_hash = "tampered".to_string();

        let app = Router::new()
            .route("/epa", post(receive_epa))
            .with_state(state.clone());

        let body = serde_json::to_string(&epa).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/epa")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.epas.read().await.len(), 0);
    }

    // ── LGPD endpoints ─────────────────────────────────────

    #[tokio::test]
    async fn titular_dados_empty() {
        let state = test_state().await;
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/titular/abc123/dados")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let refs: Vec<EpaRef> = serde_json::from_slice(&body).unwrap();
        assert!(refs.is_empty());
    }

    #[tokio::test]
    async fn titular_dados_with_indexed_epa() {
        let state = test_state().await;
        let entry = EpaRef {
            epa_id: "epa1".to_string(),
            epa_hash: "hash1".to_string(),
            lawful_basis: crate::lgpd::LawfulBasis::Consentimento,
            purpose: "test".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        state
            .lgpd_index
            .write()
            .await
            .insert("subject_hash".to_string(), entry);

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/titular/subject_hash/dados")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let refs: Vec<EpaRef> = serde_json::from_slice(&body).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].epa_id, "epa1");
    }

    #[tokio::test]
    async fn titular_export_returns_portability() {
        let state = test_state().await;
        let entry = EpaRef {
            epa_id: "epa2".to_string(),
            epa_hash: "hash2".to_string(),
            lawful_basis: crate::lgpd::LawfulBasis::Contrato,
            purpose: "export_test".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        state
            .lgpd_index
            .write()
            .await
            .insert("subj2".to_string(), entry);

        let app = test_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/titular/subj2/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let export: TitularExport = serde_json::from_slice(&body).unwrap();
        assert_eq!(export.data_subject_hash, "subj2");
        assert_eq!(export.epas.len(), 1);
    }

    #[tokio::test]
    async fn titular_anonymize_not_found() {
        let state = test_state().await;
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/titular/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn titular_anonymize_with_epa() {
        let state = test_state().await;
        let node = state.node_identity.clone();

        // Create and store a real EPA
        let mut epa = SharedEPA::create(
            &node,
            r#"{"name":"João"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );
        epa.encrypted_payload = Some(vec![1, 2, 3]);
        epa.ephemeral_public_key = Some(vec![4, 5, 6]);
        let epa_id = epa.epa_id.clone();
        state.epas.write().await.push(epa);

        // Index it under a data subject
        let entry = EpaRef {
            epa_id: epa_id.clone(),
            epa_hash: "hash".to_string(),
            lawful_basis: crate::lgpd::LawfulBasis::Consentimento,
            purpose: "test".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        state
            .lgpd_index
            .write()
            .await
            .insert("subject1".to_string(), entry);

        let app = test_app(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/titular/subject1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let results: Vec<AnonymizationResult> = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].original_epa_id, epa_id);
        assert!(!results[0].fields_anonymized.is_empty());

        // Original EPA should be anonymized
        let epas = state.epas.read().await;
        let original = epas.iter().find(|e| e.epa_id == epa_id).unwrap();
        assert!(original.encrypted_payload.is_none());
        assert!(original.ephemeral_public_key.is_none());

        // Suppression EPA should exist
        assert!(epas
            .iter()
            .any(|e| e.epa_id == results[0].suppression_epa_id));
    }

    #[tokio::test]
    async fn titular_revoke_not_found() {
        let state = test_state().await;
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/titular/nonexistent/revogar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn titular_revoke_consentimento() {
        let state = test_state().await;

        let entry = EpaRef {
            epa_id: "epa_consent".to_string(),
            epa_hash: "hash".to_string(),
            lawful_basis: crate::lgpd::LawfulBasis::Consentimento,
            purpose: "test".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        state
            .lgpd_index
            .write()
            .await
            .insert("subject3".to_string(), entry);

        let app = test_app(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/titular/subject3/revogar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let results: Vec<RevocationResult> = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].epa_id, "epa_consent");

        // Should be removed from index
        let index = state.lgpd_index.read().await;
        assert!(index.lookup("subject3").is_empty());
    }

    #[tokio::test]
    async fn titular_revoke_non_consentimento_not_revoked() {
        let state = test_state().await;

        let entry = EpaRef {
            epa_id: "epa_contract".to_string(),
            epa_hash: "hash".to_string(),
            lawful_basis: crate::lgpd::LawfulBasis::Contrato,
            purpose: "test".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        };
        state
            .lgpd_index
            .write()
            .await
            .insert("subject4".to_string(), entry);

        let app = test_app(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/titular/subject4/revogar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let results: Vec<RevocationResult> = serde_json::from_slice(&body).unwrap();
        assert!(results.is_empty()); // Contrato cannot be revoked

        let index = state.lgpd_index.read().await;
        assert_eq!(index.lookup("subject4").len(), 1);
    }
}
