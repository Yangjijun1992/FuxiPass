//! 应用状态与 API 错误类型。

use std::path::PathBuf;
use std::sync::Mutex;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use vault_store::{Vault, VaultError};

/// 已解锁会话：会话令牌 + 已解锁保险库。
pub struct Unlocked {
    /// 会话令牌（随机，仅存内存）。
    pub token: String,
    /// 已解锁的保险库。
    pub vault: Vault,
}

/// 全局应用状态。
pub struct AppState {
    /// 保险库数据库路径。
    pub db_path: PathBuf,
    /// 当前会话（同一时刻仅支持一个解锁会话）。
    pub session: Mutex<Option<Unlocked>>,
}

/// API 错误。
#[derive(Debug)]
pub enum ApiError {
    /// 请求参数错误。
    BadRequest(String),
    /// 会话令牌缺失或无效。
    Unauthorized,
    /// 尚未解锁。
    Locked,
    /// 资源不存在。
    NotFound(String),
    /// 资源冲突（如已初始化、卡片已存在）。
    Conflict(String),
    /// 服务端内部错误。
    Internal(String),
}

impl ApiError {
    /// 从数据层错误映射。
    pub fn from_vault(err: VaultError) -> Self {
        match err {
            VaultError::AlreadyExists => Self::Conflict("vault already exists".to_owned()),
            VaultError::NotInitialized => Self::Conflict("vault is not initialized".to_owned()),
            VaultError::AccountNotFound(id) => Self::NotFound(format!("account {id}")),
            VaultError::SecretNotFound(t) => Self::NotFound(format!("secret field {t}")),
            VaultError::InvalidInput(m) => Self::BadRequest(m),
            VaultError::RecoveryFailed => Self::BadRequest("invalid recovery key".to_owned()),
            other => Self::Internal(other.to_string()),
        }
    }

    /// HTTP 状态码。
    const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Locked => StatusCode::LOCKED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 错误码字面量。
    const fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Locked => "LOCKED",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Internal(_) => "INTERNAL",
        }
    }

    /// 错误消息。
    fn message(&self) -> String {
        match self {
            Self::BadRequest(m) | Self::NotFound(m) | Self::Conflict(m) | Self::Internal(m) => {
                m.clone()
            }
            Self::Unauthorized => "missing or invalid session token".to_owned(),
            Self::Locked => "vault is locked".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": { "code": self.code(), "message": self.message() }
        }));
        (self.status(), body).into_response()
    }
}

impl AppState {
    /// 读取请求头中的会话令牌。
    pub fn token_from(headers: &axum::http::HeaderMap) -> Result<String, ApiError> {
        headers
            .get("x-session-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or(ApiError::Unauthorized)
    }

    /// 在已解锁保险库上执行只读/写操作（校验令牌）。
    pub fn with_vault<T>(
        &self,
        token: &str,
        f: impl FnOnce(&Vault) -> Result<T, VaultError>,
    ) -> Result<T, ApiError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
        let Some(unlocked) = guard.as_ref() else {
            return Err(ApiError::Locked);
        };
        if unlocked.token != token {
            return Err(ApiError::Unauthorized);
        }
        f(&unlocked.vault).map_err(ApiError::from_vault)
    }

    /// 当前是否已解锁（用于状态查询）。
    pub fn is_unlocked(&self) -> bool {
        self.session
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }
}
