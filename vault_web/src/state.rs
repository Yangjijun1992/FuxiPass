//! 应用状态与 API 错误类型。

use std::path::PathBuf;
use std::sync::Mutex;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use vault_store::{Vault, VaultError};

/// 已解锁会话：会话令牌 + 已解锁保险库 + 最近活跃时间。
pub struct Unlocked {
    /// 会话令牌（随机，仅存内存）。
    pub token: String,
    /// 已解锁的保险库。
    pub vault: Vault,
    /// 最近一次成功请求的时间（epoch 毫秒），用于空闲自动锁定。
    pub last_activity_ms: u64,
}

/// 全局应用状态。
pub struct AppState {
    /// 保险库数据库路径。
    pub db_path: PathBuf,
    /// 当前会话（同一时刻仅支持一个解锁会话）。
    pub session: Mutex<Option<Unlocked>>,
    /// 空闲自动锁定秒数（`0` 表示关闭）。默认 300 秒（5 分钟）。
    pub idle_timeout_secs: u64,
    /// 找回服务地址（未配置则关闭邮箱绑定入口）。
    pub recovery_service_url: Option<String>,
}

impl Unlocked {
    /// 新建会话（活跃时间置为当前）。
    pub fn new(token: String, vault: Vault) -> Self {
        Self {
            token,
            vault,
            last_activity_ms: now_ms(),
        }
    }
}

/// 读取当前时间（epoch 毫秒）。
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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
    /// 会话因长时间空闲已自动锁定。
    SessionExpired,
    /// 资源不存在。
    NotFound(String),
    /// 资源冲突（如已初始化、卡片已存在）。
    Conflict(String),
    /// 因连续输错被退避锁定。
    TooManyAttempts {
        /// 剩余锁定秒数。
        remaining_secs: u64,
    },
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
            VaultError::Locked { remaining_secs } => Self::TooManyAttempts { remaining_secs },
            other => Self::Internal(other.to_string()),
        }
    }

    /// HTTP 状态码。
    const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Locked | Self::SessionExpired => StatusCode::LOCKED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooManyAttempts { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 错误码字面量。
    const fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Locked => "LOCKED",
            Self::SessionExpired => "SESSION_EXPIRED",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::TooManyAttempts { .. } => "TOO_MANY_ATTEMPTS",
            Self::Internal(_) => "INTERNAL",
        }
    }

    /// 错误消息。
    fn message(&self) -> String {
        match self {
            Self::BadRequest(m) | Self::NotFound(m) | Self::Conflict(m) | Self::Internal(m) => {
                m.clone()
            }
            Self::TooManyAttempts { remaining_secs } => {
                format!("连续输错次数过多，请在 {remaining_secs} 秒后重试（数据未被清除）")
            }
            Self::Unauthorized => "missing or invalid session token".to_owned(),
            Self::Locked => "vault is locked".to_owned(),
            Self::SessionExpired => "会话因长时间空闲已自动锁定，请重新解锁".to_owned(),
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

    /// 校验令牌并刷新活跃时间；空闲超时则**自动锁定**并返回 `SessionExpired`。
    ///
    /// 这是「闲置自动锁定」的执行点：任何已认证请求都会经过它。
    pub fn check_and_touch(&self, token: &str) -> Result<(), ApiError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
        let now = now_ms();
        let expired = {
            let Some(unlocked) = guard.as_ref() else {
                return Err(ApiError::Locked);
            };
            if unlocked.token != token {
                return Err(ApiError::Unauthorized);
            }
            is_idle_expired(unlocked.last_activity_ms, now, self.idle_timeout_secs)
        };
        if expired {
            // 自动锁定：清除会话（Vault 被 drop，密钥经 zeroize 擦除）。
            *guard = None;
            return Err(ApiError::SessionExpired);
        }
        if let Some(unlocked) = guard.as_mut() {
            unlocked.last_activity_ms = now;
        }
        Ok(())
    }

    /// 在已解锁保险库上执行只读/写操作（校验令牌 + 空闲超时）。
    pub fn with_vault<T>(
        &self,
        token: &str,
        f: impl FnOnce(&Vault) -> Result<T, VaultError>,
    ) -> Result<T, ApiError> {
        self.check_and_touch(token)?;
        let guard = self
            .session
            .lock()
            .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
        let Some(unlocked) = guard.as_ref() else {
            return Err(ApiError::Locked);
        };
        f(&unlocked.vault).map_err(ApiError::from_vault)
    }

    /// 二次验证 + 在已解锁保险库上执行操作。
    ///
    /// 与 `with_vault` 的区别：先要求主密码校验（并解包 FDEK，使高敏感字段可读写）。
    /// 校验受退避锁定约束；失败返回 `BAD_REQUEST`，锁定返回 `TOO_MANY_ATTEMPTS`。
    pub fn with_second_factor<T>(
        &self,
        token: &str,
        master_password: &str,
        f: impl FnOnce(&Vault) -> Result<T, VaultError>,
    ) -> Result<T, ApiError> {
        self.check_and_touch(token)?;
        let guard = self
            .session
            .lock()
            .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
        let Some(unlocked) = guard.as_ref() else {
            return Err(ApiError::Locked);
        };
        let verified = unlocked
            .vault
            .unlock_second_factor(master_password)
            .map_err(ApiError::from_vault)?;
        if !verified {
            return Err(ApiError::BadRequest(
                "second-factor verification failed".to_owned(),
            ));
        }
        f(&unlocked.vault).map_err(ApiError::from_vault)
    }

    /// 当前是否已解锁（用于状态查询）。
    pub fn is_unlocked(&self) -> bool {
        self.session.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

/// 判断会话是否因空闲超时（纯函数，便于测试）。
///
/// `timeout_secs == 0` 表示关闭自动锁定。
pub(crate) fn is_idle_expired(last_activity_ms: u64, now_ms: u64, timeout_secs: u64) -> bool {
    timeout_secs > 0 && now_ms.saturating_sub(last_activity_ms) > timeout_secs.saturating_mul(1000)
}

#[cfg(test)]
mod tests {
    use super::is_idle_expired;

    #[test]
    fn disabled_timeout_never_expires() {
        assert!(!is_idle_expired(0, u64::MAX, 0));
    }

    #[test]
    fn exactly_at_threshold_is_still_alive() {
        // 边界：恰好等于阈值不算过期（判定用 `>` 而非 `>=`）
        assert!(!is_idle_expired(0, 300_000, 300));
    }

    #[test]
    fn just_over_threshold_expires() {
        assert!(is_idle_expired(0, 300_001, 300));
    }

    #[test]
    fn recent_activity_keeps_session_alive() {
        assert!(!is_idle_expired(299_000, 300_000, 300));
    }
}
