//! HTTP API 处理器（本地验证界面）。
//!
//! 所有 `/api/accounts*` 与 `/api/audit` 接口要求 `X-Session-Token` 头；
//! 揭示高敏感字段还需在请求体中再次提供主密码（二次验证）。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use security_core::cipher::CryptoRng;
use vault_store::{AccountDetail, AccountInput, AccountSummary, AuditEntry, FieldType};

use crate::state::{ApiError, AppState, Unlocked};

/// 服务状态。
#[derive(Serialize)]
pub struct StatusResp {
    /// 数据库是否已初始化。
    pub initialized: bool,
    /// 当前是否已解锁。
    pub unlocked: bool,
}

/// 初始化请求。
#[derive(Deserialize)]
pub struct InitReq {
    /// 主密码。
    pub master_password: String,
}

/// 初始化响应（含恢复密钥，仅此一次返回）。
#[derive(Serialize)]
pub struct InitResp {
    /// 恢复密钥显示串。
    pub recovery_key: String,
}

/// 解锁请求。
#[derive(Deserialize)]
pub struct UnlockReq {
    /// 主密码。
    pub master_password: String,
}

/// 解锁响应。
#[derive(Serialize)]
pub struct UnlockResp {
    /// 会话令牌。
    pub token: String,
}

/// 恢复请求。
#[derive(Deserialize)]
pub struct RecoverReq {
    /// 恢复密钥显示串。
    pub recovery_key: String,
    /// 新主密码。
    pub new_master_password: String,
}

/// 检索查询参数。
#[derive(Deserialize)]
pub struct ListQuery {
    /// 关键词。
    #[serde(default)]
    pub q: Option<String>,
}

/// 揭示请求（含二次验证主密码）。
#[derive(Deserialize)]
pub struct RevealReq {
    /// 卡片 ID。
    pub account_id: String,
    /// 字段类型。
    pub field_type: FieldType,
    /// 二次验证：当前主密码。
    pub master_password: String,
}

/// 揭示响应。
#[derive(Serialize)]
pub struct RevealResp {
    /// 字段明文（仅本次响应返回）。
    pub value: String,
}

/// 提示词响应。
#[derive(Serialize)]
pub struct HintResp {
    /// 密码提示词。
    pub hint: Option<String>,
}

fn new_token() -> String {
    URL_SAFE_NO_PAD.encode(CryptoRng::bytes(32))
}

/// `GET /api/status`
pub async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResp> {
    Json(StatusResp {
        initialized: state.db_path.exists(),
        unlocked: state.is_unlocked(),
    })
}

/// `GET /api/hint`（未认证；提示词为用户自选的非机密信息）
pub async fn hint(State(state): State<Arc<AppState>>) -> Result<Json<HintResp>, ApiError> {
    if !state.db_path.exists() {
        return Ok(Json(HintResp { hint: None }));
    }
    let token = state
        .session
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|u| u.token.clone()));
    if let Some(token) = token {
        let hint = state.with_vault(&token, |v| v.hint())?;
        return Ok(Json(HintResp { hint }));
    }
    Ok(Json(HintResp { hint: None }))
}

/// `POST /api/initialize`
pub async fn initialize(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitReq>,
) -> Result<Json<InitResp>, ApiError> {
    let result = vault_store::initialize(&state.db_path, &req.master_password)
        .map_err(ApiError::from_vault)?;
    Ok(Json(InitResp {
        recovery_key: result.recovery_key_display,
    }))
}

/// `POST /api/unlock`
pub async fn unlock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlockReq>,
) -> Result<Json<UnlockResp>, ApiError> {
    let vault =
        vault_store::unlock(&state.db_path, &req.master_password).map_err(ApiError::from_vault)?;
    let token = new_token();
    let mut guard = state
        .session
        .lock()
        .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
    *guard = Some(Unlocked {
        token: token.clone(),
        vault,
    });
    Ok(Json(UnlockResp { token }))
}

/// `POST /api/lock`
pub async fn lock(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<()>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
    match guard.as_ref() {
        Some(u) if u.token == token => {
            *guard = None;
            Ok(Json(()))
        }
        _ => Err(ApiError::Unauthorized),
    }
}

/// `POST /api/recover`
pub async fn recover(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecoverReq>,
) -> Result<Json<()>, ApiError> {
    vault_store::recover(&state.db_path, &req.recovery_key, &req.new_master_password)
        .map_err(ApiError::from_vault)?;
    if let Ok(mut guard) = state.session.lock() {
        *guard = None;
    }
    Ok(Json(()))
}

/// `GET /api/accounts?q=`
pub async fn list_accounts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<AccountSummary>>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let items = state.with_vault(&token, |v| match query.q.as_deref() {
        Some(q) if !q.trim().is_empty() => v.search_accounts(q),
        _ => v.list_accounts(),
    })?;
    Ok(Json(items))
}

/// `GET /api/accounts/:id`
pub async fn get_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<AccountDetail>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let detail = state.with_vault(&token, |v| v.get_account(&id))?;
    Ok(Json(detail))
}

/// `POST /api/accounts`
pub async fn create_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<AccountInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let id = state.with_vault(&token, |v| v.create_account(&input))?;
    Ok(Json(serde_json::json!({ "id": id })))
}

/// `PUT /api/accounts/:id`
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<AccountInput>,
) -> Result<Json<()>, ApiError> {
    let token = AppState::token_from(&headers)?;
    state.with_vault(&token, |v| v.update_account(&id, &input))?;
    Ok(Json(()))
}

/// `DELETE /api/accounts/:id`
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, ApiError> {
    let token = AppState::token_from(&headers)?;
    state.with_vault(&token, |v| v.delete_account(&id))?;
    Ok(Json(()))
}

/// `POST /api/reveal`（二次验证：需再次提供主密码）
pub async fn reveal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RevealReq>,
) -> Result<Json<RevealResp>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let verified = vault_store::verify_master_password(&state.db_path, &req.master_password)
        .map_err(ApiError::from_vault)?;
    if !verified {
        return Err(ApiError::BadRequest(
            "second-factor verification failed".to_owned(),
        ));
    }
    let value = state.with_vault(&token, |v| v.reveal_secret(&req.account_id, req.field_type))?;
    Ok(Json(RevealResp { value }))
}

/// `GET /api/audit`
pub async fn audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let entries = state.with_vault(&token, |v| v.list_audit(100))?;
    Ok(Json(entries))
}
