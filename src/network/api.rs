use crate::network::epa::SharedEPA;
use crate::network::verify::verify_epa;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
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
    pub epas: Arc<RwLock<Vec<SharedEPA>>>,
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

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub state_json: Option<String>,
    pub evidence_jsonl: Option<String>,
    pub decisions_jsonl: Option<String>,
    pub manifest_json: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: String,
    pub epa_id: String,
}

pub async fn create_api(state: ApiState, addr: SocketAddr) -> Result<(), std::io::Error> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/node", get(node_info))
        .route("/epa", post(receive_epa))
        .route("/epa/list", get(list_epas))
        .route("/epa/:id/verify", post(verify_epa_endpoint))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
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
    if !epa.verify_integrity() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !epa.verify_signature(&state.public_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut epas = state.epas.write().await;
    epas.push(epa);

    Ok(Json(ApiResponse {
        status: "accepted".to_string(),
        message: "EPA received and verified".to_string(),
    }))
}

async fn list_epas(State(state): State<ApiState>) -> Json<Vec<SharedEPA>> {
    let epas = state.epas.read().await;
    Json(epas.clone())
}

async fn verify_epa_endpoint(
    State(state): State<ApiState>,
    axum::extract::Path(epa_id): axum::extract::Path<String>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    let epas = state.epas.read().await;
    let epa = epas
        .iter()
        .find(|e| e.epa_id == epa_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let result = verify_epa(
        epa,
        req.state_json.as_deref(),
        req.evidence_jsonl.as_deref(),
        req.decisions_jsonl.as_deref(),
        req.manifest_json.as_deref(),
        Some(&state.public_key),
    );

    Ok(Json(VerifyResponse {
        result: result.to_string(),
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
            epas: Arc::new(RwLock::new(Vec::new())),
        };

        assert_eq!(state.node_id.len(), 64);
        assert_eq!(state.epas.read().await.len(), 0);
    }
}
