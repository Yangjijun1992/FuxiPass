//! 前置鉴权中间件：在请求体解析之前校验会话令牌。
//!
//! 这样未认证请求即便携带非法请求体，也会先得到 401/423，而不会泄漏校验细节。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::{ApiError, AppState};

/// 校验 `Host` 头对应的主机名是否为本机。
///
/// 本地服务仅监听 `127.0.0.1`，但恶意网页可用 **DNS rebinding** 把自有域名解析到
/// `127.0.0.1`，使跨站请求变成"同源"，从而绕过同源策略直接读写本服务。
/// 该场景下浏览器发送的 `Host` 仍是攻击者域名 —— 因此校验 Host 即可切断攻击链。
fn host_is_local(value: &str) -> bool {
    let host = value.rsplit_once(':').map_or(value, |(h, _)| h);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// 校验 `Host` 与浏览器来源头（防 DNS rebinding 与 CSRF）。
///
/// - `Host` 缺失时放行：浏览器**必定**发送 Host，缺失意味着非浏览器客户端（CLI/curl）。
/// - `Origin` 存在时必须指向本机；`Sec-Fetch-Site` 存在时必须是 `same-origin`/`none`。
pub async fn guard_local_origin(req: Request, next: Next) -> Result<Response, ApiError> {
    let headers = req.headers();

    if let Some(host) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if !host_is_local(host) {
            return Err(ApiError::Unauthorized);
        }
    }

    if let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        let after_scheme = origin.rsplit_once("://").map_or("", |(_, rest)| rest);
        let host = after_scheme.split('/').next().unwrap_or("");
        if !host_is_local(host) {
            return Err(ApiError::Unauthorized);
        }
    }

    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !matches!(site, "same-origin" | "none") {
            return Err(ApiError::Unauthorized);
        }
    }

    Ok(next.run(req).await)
}

/// 校验 `X-Session-Token` 头对应的会话是否已解锁。
pub async fn require_session(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = AppState::token_from(req.headers())?;
    // 校验令牌并刷新活跃时间；空闲超时会在此自动锁定。
    state.check_and_touch(&token)?;
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::host_is_local;

    #[test]
    fn accepts_local_hosts() {
        for host in [
            "127.0.0.1:8787",
            "localhost:8787",
            "[::1]:8787",
            "127.0.0.1",
            "localhost",
        ] {
            assert!(host_is_local(host), "应放行本机 Host: {host}");
        }
    }

    #[test]
    fn rejects_foreign_hosts() {
        for host in [
            "evil.example.com",
            "evil.example.com:8787",
            "192.168.1.5:8787",
            "127.0.0.1.evil.example.com:8787",
        ] {
            assert!(
                !host_is_local(host),
                "应拒绝外部 Host（DNS rebinding）: {host}"
            );
        }
    }
}
