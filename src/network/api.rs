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

#[derive(Serialize)]
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

async fn receive_encrypted_epa(
    State(state): State<ApiState>,
    Json(req): Json<EncryptedEpaRequest>,
) -> Result<Json<SharedEPA>, StatusCode> {
    let recipient_key_bytes =
        hex::decode(&req.recipient_public_key).map_err(|_| StatusCode::BAD_REQUEST)?;
    if recipient_key_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let node = NodeIdentity::generate("test");
        let state = ApiState {
            node_id: node.node_id.clone(),
            public_key: node.public_key.clone(),
            node_identity: node.clone(),
            epas: Arc::new(RwLock::new(Vec::new())),
            rate_limiter: RateLimiter::new(100, Duration::from_secs(60)),
        };

        assert_eq!(state.node_id.len(), 64);
        assert_eq!(state.epas.read().await.len(), 0);
    }

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
}
