//! 找回服务的 HTTP 接口（契约见 `docs/04-数据库与远程接口.md` §2）。
//!
//! 设计约束：
//! - 所有响应**只含密文包裹**，绝无明文凭证；
//! - 错误信息不区分「未绑定」与「已绑定但验证码错」，降低账号枚举风险；
//! - 服务端不落任何明文日志。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::{Binding, ChallengeIssued, ContactType, RecoveryError, RecoveryService, VerifyResult};

/// 共享状态。
pub struct AppState {
    /// 找回服务实例。
    pub service: RecoveryService,
}

/// 绑定请求。
#[derive(Deserialize)]
pub struct BindReq {
    /// 联系方式不可逆哈希。
    pub contact_hash: String,
    /// 联系方式类型。
    pub contact_type: ContactType,
    /// 恢复密钥加密的 DEK 包裹。
    pub recoverywrap: String,
}

/// 发起挑战请求。
#[derive(Deserialize)]
pub struct ChallengeReq {
    /// 联系方式不可逆哈希。
    pub contact_hash: String,
}

/// 校验验证码请求。
#[derive(Deserialize)]
pub struct VerifyReq {
    /// 一次性请求 ID。
    pub request_id: String,
    /// 验证码。
    pub code: String,
}

/// 取回包裹请求。
#[derive(Deserialize)]
pub struct RedeemReq {
    /// 短寿命令牌。
    pub token: String,
}

/// 取回包裹响应。
#[derive(Serialize)]
pub struct RedeemResp {
    /// 恢复密钥加密的 DEK 包裹（密文）。
    pub recoverywrap: String,
}

/// API 错误包装。
pub struct ApiError(RecoveryError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self.0 {
            // 统一口径，避免账号枚举
            RecoveryError::NotBound => (StatusCode::NOT_FOUND, "未找到该联系方式的找回绑定"),
            RecoveryError::RateLimited | RecoveryError::TooManyAttempts => {
                (StatusCode::TOO_MANY_REQUESTS, "请求过于频繁，请稍后重试")
            }
            RecoveryError::IncorrectCode => (StatusCode::BAD_REQUEST, "验证码错误"),
            RecoveryError::CodeExpired => (StatusCode::BAD_REQUEST, "验证码已过期或不存在"),
            RecoveryError::InvalidToken => (StatusCode::UNAUTHORIZED, "令牌无效或已过期"),
        };
        let body = Json(serde_json::json!({ "error": { "message": message } }));
        (status, body).into_response()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn new_token() -> String {
    use security_core::cipher::CryptoRng;
    let bytes = CryptoRng::bytes(32);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `POST /v1/recovery/bind`
pub async fn bind(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BindReq>,
) -> Result<StatusCode, ApiError> {
    if req.contact_hash.is_empty() || req.recoverywrap.is_empty() {
        return Err(ApiError(RecoveryError::NotBound));
    }
    state.service.bind(Binding {
        contact_hash: req.contact_hash,
        contact_type: req.contact_type,
        recoverywrap: req.recoverywrap,
    });
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/recovery/challenge`
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChallengeReq>,
) -> Result<Json<ChallengeIssued>, ApiError> {
    state
        .service
        .challenge(&req.contact_hash, now_ms())
        .map(Json)
        .map_err(ApiError)
}

/// `POST /v1/recovery/verify`
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResult>, ApiError> {
    state
        .service
        .verify(&req.request_id, &req.code, now_ms(), new_token())
        .map(Json)
        .map_err(ApiError)
}

/// `POST /v1/recovery/wrap`
pub async fn redeem(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, ApiError> {
    state
        .service
        .redeem(&req.token, now_ms())
        .map(|recoverywrap| Json(RedeemResp { recoverywrap }))
        .map_err(ApiError)
}
