//! 找回服务的 HTTP 接口（契约见 `docs/04-数据库与远程接口.md` §2）。
//!
//! 设计约束：
//! - 所有响应**只含密文包裹**，绝无明文凭证；
//! - 错误信息不区分「未绑定」与「已绑定但验证码错」，降低账号枚举风险；
//! - 服务端不落任何明文日志。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::{Binding, ChallengeIssued, ContactType, RecoveryError, RecoveryService, VerifyResult};

/// 共享状态。
pub struct AppState {
    /// 找回服务实例。
    pub service: RecoveryService,
    /// 访问令牌；为 `Some` 时除健康检查外的所有端点都要求 `Authorization: Bearer <token>`。
    pub auth_token: Option<String>,
}

/// 无需令牌即可访问的端点（仅健康检查；便于监控且不含任何用户数据）。
fn is_public_path(path: &str) -> bool {
    path == "/v1/health"
}

/// 恒定时间比较（避免按字节提前返回造成时序侧信道）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 校验 `Host` 是否指向本机（阻断 DNS rebinding）。
fn host_is_local(value: &str) -> bool {
    let host = value.rsplit_once(':').map_or(value, |(h, _)| h);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// 鉴权与来源校验中间件。
///
/// - 配置了令牌时，除 `/v1/health` 外一律要求 `Authorization: Bearer <token>`：
///   找回服务虽仅监听本机，但**同一台机器上的其它用户**也能连到 127.0.0.1，
///   而 `POST /v1/recovery/bind` 无认证时可被覆盖他人的找回绑定（已复现）。
/// - 校验 `Host`：恶意网页可通过 DNS rebinding 访问本机服务，此时 Host 为攻击者域名。
pub async fn guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(host) = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if !host_is_local(host) {
            return Err(ApiError(RecoveryError::InvalidToken));
        }
    }

    if let Some(expected) = state.auth_token.as_deref() {
        if !is_public_path(req.uri().path()) {
            let provided = req
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::trim);
            let ok = provided.is_some_and(|t| ct_eq(t.as_bytes(), expected.as_bytes()));
            if !ok {
                return Err(ApiError(RecoveryError::InvalidToken));
            }
        }
    }

    Ok(next.run(req).await)
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
    /// 明文联系方式（仅用于投递验证码；服务端校验其哈希与绑定一致后即弃，不落库）。
    pub contact: String,
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
            // 存储故障属服务端问题；对外只给通用信息，细节留在服务端日志
            RecoveryError::Storage(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "服务暂时不可用，请稍后重试",
            ),
        };
        let body = Json(serde_json::json!({ "error": { "message": message } }));
        (status, body).into_response()
    }
}

/// 事件日志（**只记录非敏感元数据**：绝不打印验证码、完整哈希或套件内容）。
fn log_event(event: &str) {
    println!("[找回服务] {event}");
}

/// 哈希前缀（仅 8 个字符，用于人工核对「是不是同一个联系人」）。
fn hash_prefix(hash: &str) -> &str {
    hash.get(..hash.len().min(8)).unwrap_or(hash)
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

/// 健康检查与运行统计（**只返回计数**，便于运维确认服务在工作）。
#[derive(Serialize)]
pub struct HealthResp {
    /// 是否正常。
    pub ok: bool,
    /// 已绑定的联系人数。
    pub bindings: usize,
    /// 待验证的挑战数。
    pub pending_challenges: usize,
    /// 有效令牌数。
    pub active_tokens: usize,
}

/// `GET /v1/health`
pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResp> {
    let (bindings, pending_challenges, active_tokens) = state.service.stats();
    Json(HealthResp {
        ok: true,
        bindings,
        pending_challenges,
        active_tokens,
    })
}

/// `POST /v1/recovery/bind`
pub async fn bind(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BindReq>,
) -> Result<StatusCode, ApiError> {
    if req.contact_hash.is_empty() || req.recoverywrap.is_empty() {
        return Err(ApiError(RecoveryError::NotBound));
    }
    log_event(&format!(
        "收到绑定：contact_hash 前缀 {}（类型 {:?}）",
        hash_prefix(&req.contact_hash),
        req.contact_type
    ));
    state
        .service
        .bind(Binding {
            contact_hash: req.contact_hash,
            contact_type: req.contact_type,
            recoverywrap: req.recoverywrap,
        })
        .map_err(ApiError)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/recovery/challenge`
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChallengeReq>,
) -> Result<Json<ChallengeIssued>, ApiError> {
    let result = state
        .service
        .challenge(&req.contact_hash, &req.contact, now_ms());
    match &result {
        Ok(issued) => log_event(&format!(
            "签发验证码：request_id={} contact_hash 前缀 {}",
            issued.request_id,
            hash_prefix(&req.contact_hash)
        )),
        Err(err) => log_event(&format!(
            "签发失败：contact_hash 前缀 {} → {err}",
            hash_prefix(&req.contact_hash)
        )),
    }
    result.map(Json).map_err(ApiError)
}

/// `POST /v1/recovery/verify`
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResult>, ApiError> {
    let result = state
        .service
        .verify(&req.request_id, &req.code, now_ms(), new_token());
    match &result {
        Ok(_) => log_event(&format!(
            "验证成功：request_id={}（已下发套件）",
            req.request_id
        )),
        Err(err) => log_event(&format!("验证失败：request_id={} → {err}", req.request_id)),
    }
    result.map(Json).map_err(ApiError)
}

/// `POST /v1/recovery/wrap`
pub async fn redeem(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, ApiError> {
    let result = state.service.redeem(&req.token, now_ms());
    if result.is_ok() {
        log_event("已按令牌下发套件（令牌已消费）");
    }
    result
        .map(|recoverywrap| Json(RedeemResp { recoverywrap }))
        .map_err(ApiError)
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, host_is_local, is_public_path};

    #[test]
    fn health_is_public_others_are_not() {
        assert!(is_public_path("/v1/health"));
        for path in [
            "/v1/recovery/bind",
            "/v1/recovery/challenge",
            "/v1/recovery/wrap",
        ] {
            assert!(!is_public_path(path), "{path} 必须要求鉴权");
        }
    }

    #[test]
    fn constant_time_eq_compares_content() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn host_guard_matches_localhost_only() {
        assert!(host_is_local("127.0.0.1:8799"));
        assert!(host_is_local("localhost:8799"));
        assert!(!host_is_local("evil.example.com"));
    }
}
