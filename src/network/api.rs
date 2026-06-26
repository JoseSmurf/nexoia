use crate::limits::MAX_EPA_ENTRIES;
use crate::network::epa::SharedEPA;
use crate::network::identity::NodeIdentity;
use crate::network::verify::{verify_epa, VerifyResult};
use axum::{
    extract::{ConnectInfo, Json, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter simples por IP.
/// Mantém janela de requisições e rejeita se exceder o limite.
struct RateLimiterInner {
    /// Mapa de IP → (count, window_start)
    clients: HashMap<IpAddr, ClientRate>,
    max_requests: u32,
    window: Duration,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct IpAddr(std::net::IpAddr);

struct ClientRate {
    count: u32,
    window_start: Instant,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RwLock<RateLimiterInner>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RateLimiterInner {
                clients: HashMap::new(),
                max_requests,
                window,
            })),
        }
    }

    async fn check(&self, ip: std::net::IpAddr) -> bool {
        let mut inner = self.inner.write().await;
        let now = Instant::now();
        let key = IpAddr(ip);

        let window = inner.window;
        let max_requests = inner.max_requests;

        let client = inner.clients.entry(key).or_insert(ClientRate {
            count: 0,
            window_start: now,
        });

        // Reset janela se expirou
        if now.duration_since(client.window_start) >= window {
            client.count = 0;
            client.window_start = now;
        }

        client.count += 1;
        client.count <= max_requests
    }
}

#[derive(Clone)]
pub struct ApiState {
    pub node_id: String,
    pub public_key: String,
    pub node_identity: NodeIdentity,
    pub epas: Arc<RwLock<Vec<SharedEPA>>>,
    pub rate_limiter: RateLimiter,
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
    pub epa_id: String,
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

    if !state.rate_limiter.check(addr.ip()).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

pub async fn create_api(state: ApiState, addr: SocketAddr) -> Result<(), std::io::Error> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/node", get(node_info))
        .route("/epa", post(receive_epa))
        .route("/epa/encrypted", post(receive_encrypted_epa))
        .route("/epa/list", get(list_epas))
        .route("/epa/:id/verify", post(verify_epa_endpoint))
        .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
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
            epas.push(epa);
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

    let epa = SharedEPA::create_encrypted(
        &state.node_identity,
        &req.state_json,
        &req.evidence_jsonl,
        &req.decisions_jsonl,
        &req.manifest_json,
        &key_arr,
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

    Ok(Json(QuickVerifyResponse {
        signature_valid,
        epa_id: epa.epa_id.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::NodeIdentity;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> ApiState {
        let node = NodeIdentity::generate("test");
        ApiState {
            node_id: node.node_id.clone(),
            public_key: node.public_key.clone(),
            node_identity: node.clone(),
            epas: Arc::new(RwLock::new(Vec::new())),
            rate_limiter: RateLimiter::new(100, Duration::from_secs(60)),
        }
    }

    fn test_app() -> Router {
        let state = test_state();
        Router::new()
            .route("/health", get(health))
            .route("/node", get(node_info))
            .route("/epa", post(receive_epa))
            .route("/epa/encrypted", post(receive_encrypted_epa))
            .route("/epa/list", get(list_epas))
            .route("/epa/:id/verify", post(verify_epa_endpoint))
            .route("/epa/:id/verify-quick", get(verify_quick_endpoint))
            .with_state(state)
    }

    // ── Health ──────────────────────────────────────────────

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = test_app();
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
        let limiter = RateLimiter::new(2, Duration::from_secs(1));
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        assert!(limiter.check(ip).await);
        assert!(limiter.check(ip).await);
        assert!(!limiter.check(ip).await);
    }

    #[tokio::test]
    async fn rate_limiter_allows_different_ips() {
        let limiter = RateLimiter::new(1, Duration::from_secs(1));
        let ip1: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: std::net::IpAddr = "127.0.0.2".parse().unwrap();

        assert!(limiter.check(ip1).await);
        assert!(limiter.check(ip2).await);
        assert!(!limiter.check(ip1).await);
    }

    #[tokio::test]
    async fn rate_limiter_resets_after_window() {
        let limiter = RateLimiter::new(1, Duration::from_millis(100));
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        assert!(limiter.check(ip).await);
        assert!(!limiter.check(ip).await);

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(limiter.check(ip).await);
    }

    // ── POST /epa/encrypted ─────────────────────────────────

    #[tokio::test]
    async fn encrypted_epa_valid_request() {
        let app = test_app();
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
        let app = test_app();

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
        let app = test_app();

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
        let app = test_app();

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
        let state = test_state();
        let node = state.node_identity.clone();

        let epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
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
        let state = test_state();

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
        let state = test_state();
        let node = state.node_identity.clone();

        let mut epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
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
        let state = test_state();
        let node = state.node_identity.clone();

        let epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
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
        let state = test_state();
        let node = state.node_identity.clone();

        let mut epa = SharedEPA::create(
            &node,
            r#"{"project":"test"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
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
}
