//! 邮件发送（SMTP，经系统 `curl`）。
//!
//! # 为什么用 curl
//!
//! 本项目需在较旧工具链（rustc 1.75）上构建，而 Rust 生态的 SMTP 客户端要么依赖
//! 新版 TLS 栈（edition2024），要么依赖 OpenSSL 绑定。`curl` 在 Linux/macOS 上
//! 普遍预装且原生支持 SMTPS，用它发送最省依赖、也最易审计。
//!
//! # 安全
//!
//! 授权码**不进入命令行参数**（避免 `ps` 泄露）：写入 0600 临时配置文件，
//! 用 `--config` 传入，发送后立即删除。

use std::io::Write;
use std::path::PathBuf;

use crate::RecoveryError;

/// SMTP 配置。
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP 地址，如 `smtps://smtp.qq.com:465`（加密）或 `smtp://127.0.0.1:25`（本地中继）。
    pub url: String,
    /// 登录账号（同时作为默认发件人）。
    pub user: String,
    /// 授权码/密码（**不落盘、不进 argv**）。
    pub password: String,
    /// 发件人地址（默认与 `user` 相同）。
    pub from: String,
}

/// 发送验证码邮件。
///
/// # Errors
/// curl 不可用、SMTP 拒绝或超时，均返回 [`RecoveryError::Storage`]（含简短原因）。
pub fn send_verification_code(
    config: &SmtpConfig,
    recipient: &str,
    code: &str,
    ttl_secs: u64,
) -> Result<(), RecoveryError> {
    let message = build_message(&config.from, recipient, code, ttl_secs);

    // 临时消息文件
    let msg_path = temp_path("msg");
    let mut f =
        std::fs::File::create(&msg_path).map_err(|e| RecoveryError::Storage(e.to_string()))?;
    f.write_all(message.as_bytes())
        .map_err(|e| RecoveryError::Storage(e.to_string()))?;
    drop(f);

    // 临时配置（含凭据；0600）
    let conf_path = temp_path("conf");
    {
        let mut c =
            std::fs::File::create(&conf_path).map_err(|e| RecoveryError::Storage(e.to_string()))?;
        writeln!(c, "user = \"{}:{}\"", config.user, config.password)
            .map_err(|e| RecoveryError::Storage(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    let output = std::process::Command::new("curl")
        .args([
            "--url",
            &smtp_url_with_ehlo(&config.url, &config.from),
            "--mail-from",
            &config.from,
            "--mail-rcpt",
            recipient,
            "--upload-file",
        ])
        .arg(&msg_path)
        .arg("--config")
        .arg(&conf_path)
        .args(["--silent", "--show-error", "--max-time", "20"])
        .output();

    // 无论成败都立即删除临时文件（凭据不留盘）
    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&conf_path);

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // 只保留前 200 字符，避免日志过长；不回显凭据（curl 不会打印它）
            let brief: String = stderr.chars().take(200).collect();
            Err(RecoveryError::Storage(format!("curl 发送失败: {brief}")))
        }
        Err(e) => Err(RecoveryError::Storage(format!(
            "无法执行 curl（请确认已安装）: {e}"
        ))),
    }
}

/// 构造 RFC 5322 邮件正文（UTF-8，含主题与正文）。
fn build_message(from: &str, to: &str, code: &str, ttl_secs: u64) -> String {
    let minutes = ttl_secs / 60;
    let body = format!(
        "你的 FuxiPass 找回验证码是：{code}\r\n\r\n\
         该验证码 {minutes} 分钟内有效，且只能使用一次。\r\n\
         如果这不是你本人的操作，请忽略本邮件，并考虑更换绑定的邮箱密码。\r\n\r\n\
         —— 提示：仅凭验证码无法解开你的保险库，重置主密码还需要你手上的「恢复密钥」。\r\n"
    );
    format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Subject: =?UTF-8?B?{subject_b64}?=\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=UTF-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n{body}",
        subject_b64 = base64_subject("FuxiPass 找回验证码")
    )
}

/// 主题用 Base64 编码（RFC 2047），避免非 ASCII 头被拒。
fn base64_subject(text: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(text.as_bytes())
}

/// 给 SMTP URL 补上 EHLO 域名。
///
/// curl 在 SMTP 模式下把 URL 的路径部分用作 EHLO 参数；路径为空时会退化成
/// **上传文件名**（如 `fuxipass_msg_123_456`）——含下划线，是非法域名，
/// 会被真实服务器以语法错误拒收。故显式使用发件人域名。
fn smtp_url_with_ehlo(url: &str, from: &str) -> String {
    let authority_has_path = url
        .split_once("://")
        .map(|(_, rest)| rest.contains('/'))
        .unwrap_or(false);
    if authority_has_path {
        return url.to_owned();
    }
    let domain = from.rsplit_once('@').map(|(_, d)| d.trim()).unwrap_or("");
    let domain = if domain.is_empty() || domain.contains('/') || domain.contains('@') {
        "localhost"
    } else {
        domain
    };
    format!("{}/{domain}", url.trim_end_matches('/'))
}

fn temp_path(kind: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut p = std::env::temp_dir();
    p.push(format!("fuxipass_{kind}_{}_{nanos}", std::process::id()));
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_has_headers_and_code() {
        let m = build_message("a@x.com", "b@y.com", "123456", 300);
        assert!(m.contains("From: a@x.com"));
        assert!(m.contains("To: b@y.com"));
        assert!(m.contains("Subject: =?UTF-8?B?"));
        assert!(m.contains("123456"));
        assert!(m.contains("5 分钟内有效"));
        assert!(m.contains("恢复密钥"), "应提醒还需要恢复密钥");
    }

    #[test]
    fn message_uses_crlf_line_endings() {
        let m = build_message("a@x.com", "b@y.com", "111111", 300);
        assert!(m.contains("\r\n"), "SMTP 要求 CRLF 换行");
    }

    #[test]
    fn ehlo_domain_comes_from_sender() {
        assert_eq!(
            smtp_url_with_ehlo("smtps://smtp.qq.com:465", "owner@qq.com"),
            "smtps://smtp.qq.com:465/qq.com"
        );
    }

    #[test]
    fn ehlo_domain_keeps_existing_path() {
        assert_eq!(
            smtp_url_with_ehlo("smtp://127.0.0.1:25/custom.example", "a@b.com"),
            "smtp://127.0.0.1:25/custom.example"
        );
    }

    #[test]
    fn ehlo_domain_falls_back_when_sender_is_malformed() {
        assert_eq!(
            smtp_url_with_ehlo("smtp://127.0.0.1:25", "not-an-email"),
            "smtp://127.0.0.1:25/localhost"
        );
    }
}
