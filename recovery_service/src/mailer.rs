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
//!
//! # `--sasl-ir` 不可省略
//!
//! QQ 邮箱的 `AUTH PLAIN` 只接受**一行内带初始响应**的形式。curl 默认先发一个
//! 空的 `AUTH PLAIN` 等挑战，QQ 会再回一个 `334`，curl 随即以 `(67) Login denied`
//! 放弃认证 —— 凭据本身完全正确（同一凭据用 smtplib 可正常登录）。
//! 加 `--sasl-ir` 后 curl 发送 `AUTH PLAIN <base64>` 单行形式，QQ 才回 `235`。

use std::io::Write;
use std::path::{Path, PathBuf};

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

/// 校验邮箱地址：非空、长度合理、恰有一个 `@`，且不含空白/CR/LF/尖括号。
///
/// CR/LF 若进入 `To:` 头会造成 **SMTP 头注入**（追加 Bcc 等）；尖括号可破坏
/// 信封地址结构。该值来自绑定时填写的联系方式，属服务端可控性输入，必须校验。
fn validate_address(addr: &str) -> Result<(), RecoveryError> {
    let invalid = addr.is_empty()
        || addr.len() > 254
        || addr.matches('@').count() != 1
        || addr
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '\r' | '\n' | '\0' | '<' | '>' | ','));
    if invalid {
        return Err(RecoveryError::Storage("邮箱地址不合法".to_owned()));
    }
    Ok(())
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
    validate_address(recipient)?;
    validate_address(&config.from)?;

    let message = build_message(&config.from, recipient, code, ttl_secs);

    // 临时消息文件（含明文验证码；创建即 0600，不跟随符号链接）
    let msg_path = temp_path("msg");
    let mut f =
        create_private_file(&msg_path).map_err(|e| RecoveryError::Storage(e.to_string()))?;
    f.write_all(message.as_bytes())
        .map_err(|e| RecoveryError::Storage(e.to_string()))?;
    drop(f);

    // 临时配置（含 SMTP 授权码）
    let conf_path = temp_path("conf");
    {
        let mut c =
            create_private_file(&conf_path).map_err(|e| RecoveryError::Storage(e.to_string()))?;
        writeln!(c, "user = \"{}:{}\"", config.user, config.password)
            .map_err(|e| RecoveryError::Storage(e.to_string()))?;
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
        .args(["--silent", "--show-error", "--sasl-ir", "--max-time", "20"])
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

/// 创建仅属主可读写的文件（`O_EXCL` + 创建即 0600）。
///
/// 供本模块与令牌文件写入复用：既不跟随已存在的符号链接，也无「先创建后 chmod」
/// 之间按 umask 短暂可读的窗口。
pub fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// 生成不可预测的临时文件路径（CSPRNG，96-bit 随机）。
fn temp_path(kind: &str) -> PathBuf {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let suffix = URL_SAFE_NO_PAD.encode(security_core::cipher::CryptoRng::bytes(12));
    let mut p = std::env::temp_dir();
    p.push(format!("fuxipass_{kind}_{suffix}"));
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

    #[test]
    fn rejects_malformed_addresses() {
        assert!(validate_address("owner@example.com").is_ok());
        assert!(
            validate_address("a@b.com\r\nBcc: evil@x.com").is_err(),
            "CRLF 头注入"
        );
        assert!(
            validate_address("a@b.com\nBcc: evil@x.com").is_err(),
            "换行头注入"
        );
        assert!(validate_address("no-at-sign").is_err());
        assert!(validate_address("two@@at.com").is_err());
        assert!(validate_address("a b@c.com").is_err());
        assert!(validate_address("<a@b.com>").is_err());
        assert!(validate_address("").is_err());
    }

    #[test]
    fn temp_path_is_unpredictable() {
        let a = temp_path("msg");
        let b = temp_path("msg");
        assert_ne!(a, b, "临时文件名必须不可预测（防预置符号链接）");
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("fuxipass_msg_"), "保留可识别前缀: {name}");
        assert!(
            !name.contains(&std::process::id().to_string()),
            "文件名不应含 PID（可预测）: {name}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perm");
        let file = create_private_file(&path).expect("创建临时文件");
        drop(file);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600, "临时文件必须创建即 0600（实际 {mode:o}）");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_refuses_existing_path() {
        let target = temp_path("target");
        std::fs::write(&target, b"original").unwrap();
        let link = temp_path("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = create_private_file(&link);
        let after = std::fs::read(&target).unwrap();
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);

        assert!(err.is_err(), "已存在的路径必须因 O_EXCL 而拒绝");
        assert_eq!(after, b"original", "不得经符号链接写入目标文件");
    }
}
