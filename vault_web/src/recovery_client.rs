//! 调用本地找回服务的最小 HTTP 客户端（T2.4）。
//!
//! **为什么不用 HTTP 库**：本项目需在较旧工具链（rustc 1.75）上构建，而常见
//! HTTP 客户端的传递依赖已要求 edition2024。此处只需向**本机**找回服务发一个
//! JSON POST，故实现最小必要子集：
//!
//! - 仅支持 `http://host:port` 形式的明文地址（找回服务默认只监听 127.0.0.1）
//! - HTTP/1.1 POST + `Content-Type: application/json` + `Connection: close`
//! - 读至 EOF 后解析状态行与响应体（不处理 chunked / 重定向 / HTTPS）
//!
//! 若将来需要访问远程服务，应改用成熟的 HTTP 客户端并启用 TLS。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// 客户端错误。
#[derive(Debug, Clone, thiserror::Error)]
pub enum RecoveryClientError {
    /// 地址格式不合法（仅支持 `http://host:port`）。
    #[error("invalid recovery service url: {0}")]
    InvalidUrl(String),
    /// 网络或 IO 失败。
    #[error("recovery service io error: {0}")]
    Io(String),
    /// 响应格式无法解析。
    #[error("malformed response from recovery service")]
    MalformedResponse,
}

/// 最小 HTTP 客户端。
pub struct RecoveryClient {
    host: String,
    port: u16,
    timeout: Duration,
}

impl RecoveryClient {
    /// 由 `http://host:port` 构造。
    pub fn new(base_url: &str) -> Result<Self, RecoveryClientError> {
        let rest = base_url
            .trim()
            .strip_prefix("http://")
            .ok_or_else(|| RecoveryClientError::InvalidUrl("仅支持 http://".to_owned()))?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (
                h.to_owned(),
                p.parse::<u16>()
                    .map_err(|_| RecoveryClientError::InvalidUrl("端口不合法".to_owned()))?,
            ),
            None => (rest.to_owned(), 80),
        };
        if host.is_empty() {
            return Err(RecoveryClientError::InvalidUrl("主机为空".to_owned()));
        }
        Ok(Self {
            host,
            port,
            timeout: Duration::from_secs(10),
        })
    }

    /// 发送 JSON POST，返回 `(状态码, 响应体)`。
    pub fn post_json(&self, path: &str, body: &str) -> Result<(u16, String), RecoveryClientError> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| RecoveryClientError::Io(e.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| RecoveryClientError::Io(e.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| RecoveryClientError::Io(e.to_string()))?;

        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\r\n{body}",
            len = body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| RecoveryClientError::Io(e.to_string()))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| RecoveryClientError::Io(e.to_string()))?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        parse_response(&text)
    }
}

/// 从原始响应文本解析 `(状态码, 响应体)`。
fn parse_response(raw: &str) -> Result<(u16, String), RecoveryClientError> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or(RecoveryClientError::MalformedResponse)?;
    let status_line = head
        .lines()
        .next()
        .ok_or(RecoveryClientError::MalformedResponse)?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or(RecoveryClientError::MalformedResponse)?;
    Ok((code, body.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_url_with_port() {
        let c = RecoveryClient::new("http://127.0.0.1:8799").unwrap();
        assert_eq!(c.host, "127.0.0.1");
        assert_eq!(c.port, 8799);
    }

    #[test]
    fn parses_url_with_trailing_slash() {
        let c = RecoveryClient::new("http://localhost:8799/").unwrap();
        assert_eq!(c.host, "localhost");
        assert_eq!(c.port, 8799);
    }

    #[test]
    fn rejects_https_and_garbage() {
        assert!(matches!(
            RecoveryClient::new("https://example.com"),
            Err(RecoveryClientError::InvalidUrl(_))
        ));
        assert!(matches!(
            RecoveryClient::new("http://host:not-a-port"),
            Err(RecoveryClientError::InvalidUrl(_))
        ));
    }

    #[test]
    fn parses_status_and_body() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn parses_error_status() {
        let raw = "HTTP/1.1 429 Too Many Requests\r\n\r\n{\"error\":{}}";
        let (code, _) = parse_response(raw).unwrap();
        assert_eq!(code, 429);
    }

    #[test]
    fn malformed_response_is_rejected() {
        assert!(matches!(
            parse_response("garbage"),
            Err(RecoveryClientError::MalformedResponse)
        ));
    }
}
