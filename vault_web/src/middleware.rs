//! 前置鉴权中间件：在请求体解析之前校验会话令牌。
//!
//! 这样未认证请求即便携带非法请求体，也会先得到 401/423，而不会泄漏校验细节。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::{ApiError, AppState};

/// 校验 `X-Session-Token` 头对应的会话是否已解锁。
pub async fn require_session(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = AppState::token_from(req.headers())?;
    {
        let guard = state
            .session
            .lock()
            .map_err(|_| ApiError::Internal("session lock poisoned".to_owned()))?;
        match guard.as_ref() {
            Some(unlocked) if unlocked.token == token => {}
            Some(_) => return Err(ApiError::Unauthorized),
            None => return Err(ApiError::Locked),
        }
    }
    Ok(next.run(req).await)
}
