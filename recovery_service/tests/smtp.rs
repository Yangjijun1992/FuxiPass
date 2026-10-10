//! SMTP 投递测试：用一个**内置的假 SMTP 服务器**验证真实发信链路。
//!
//! 覆盖：EHLO/AUTH/MAIL/RCPT/DATA 全流程、邮件头与验证码内容、
//! 以及**授权码不落盘**（临时配置文件发送后被删除）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver};
use std::thread;

use recovery_service::mailer::{send_verification_code, SmtpConfig};

/// 启动假 SMTP 服务器，返回端口与「收到的邮件原文」通道。
fn spawn_fake_smtp() -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定随机端口");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();

    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let data = serve_session(stream);
        let _ = tx.send(data);
    });

    (port, rx)
}

fn serve_session(stream: TcpStream) -> String {
    let mut writer = stream.try_clone().expect("克隆句柄");
    let mut reader = BufReader::new(stream);
    let reply = |w: &mut TcpStream, text: &str| {
        let _ = w.write_all(text.as_bytes());
    };

    reply(&mut writer, "220 fake ESMTP\r\n");

    let mut line = String::new();
    let mut data = String::new();
    let mut in_data = false;
    let mut awaiting_auth_payload = false;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if in_data {
            if line.trim_end() == "." {
                in_data = false;
                reply(&mut writer, "250 queued\r\n");
            } else {
                data.push_str(&line);
            }
            continue;
        }
        if awaiting_auth_payload {
            awaiting_auth_payload = false;
            // 模拟 QQ：裸 AUTH PLAIN 即使随后收到正确凭据也拒绝（curl 缺 --sasl-ir 时会走到这里）
            reply(&mut writer, "535 authentication failed\r\n");
            continue;
        }
        let cmd = line.trim_end().to_uppercase();
        if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
            reply(&mut writer, "250-fake\r\n250 AUTH PLAIN LOGIN\r\n");
        } else if cmd.starts_with("AUTH PLAIN") {
            if cmd.split_whitespace().count() > 2 {
                reply(&mut writer, "235 authenticated\r\n");
            } else {
                awaiting_auth_payload = true;
                reply(&mut writer, "334 \r\n");
            }
        } else if cmd.starts_with("AUTH LOGIN") {
            awaiting_auth_payload = true;
            reply(&mut writer, "334 VXNlcm5hbWU6\r\n");
        } else if cmd.starts_with("MAIL FROM") || cmd.starts_with("RCPT TO") {
            reply(&mut writer, "250 ok\r\n");
        } else if cmd.starts_with("DATA") {
            in_data = true;
            reply(&mut writer, "354 send data\r\n");
        } else if cmd.starts_with("QUIT") {
            reply(&mut writer, "221 bye\r\n");
            break;
        } else {
            reply(&mut writer, "250 ok\r\n");
        }
    }
    data
}

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
fn sends_code_email_through_smtp() {
    if !curl_available() {
        eprintln!("跳过：环境无 curl");
        return;
    }
    let (port, rx) = spawn_fake_smtp();
    let config = SmtpConfig {
        url: format!("smtp://127.0.0.1:{port}"),
        user: "sender@example.com".to_owned(),
        password: "s3cr3t-authorization-code".to_owned(),
        from: "sender@example.com".to_owned(),
    };

    send_verification_code(&config, "owner@example.com", "654321", 300).expect("应能发送成功");

    let mail = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("假服务器应收到邮件");

    assert!(mail.contains("To: owner@example.com"), "缺少收件人: {mail}");
    assert!(
        mail.contains("From: sender@example.com"),
        "缺少发件人: {mail}"
    );
    assert!(mail.contains("654321"), "邮件正文缺少验证码: {mail}");
    assert!(mail.contains("恢复密钥"), "应说明还需恢复密钥: {mail}");
    assert!(mail.contains("\r\n"), "SMTP 要求 CRLF");
}

#[test]
fn smtp_failure_is_reported() {
    if !curl_available() {
        eprintln!("跳过：环境无 curl");
        return;
    }
    // 指向一个无人监听的端口 → 必须返回错误而不是静默成功
    let config = SmtpConfig {
        url: "smtp://127.0.0.1:9".to_owned(),
        user: "sender@example.com".to_owned(),
        password: "x".to_owned(),
        from: "sender@example.com".to_owned(),
    };
    let err = send_verification_code(&config, "owner@example.com", "111111", 300).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("curl"), "错误信息应说明发送失败: {msg}");
}

#[test]
fn credentials_are_not_left_on_disk() {
    if !curl_available() {
        eprintln!("跳过：环境无 curl");
        return;
    }
    let marker = "uniquely-identifiable-secret-9f3a7c";
    let (port, _rx) = spawn_fake_smtp();
    let config = SmtpConfig {
        url: format!("smtp://127.0.0.1:{port}"),
        user: "sender@example.com".to_owned(),
        password: marker.to_owned(),
        from: "sender@example.com".to_owned(),
    };
    let _ = send_verification_code(&config, "owner@example.com", "222222", 300);

    // 临时目录中不得残留含**本次**授权码的文件（用唯一标记，避免与其他并行测试的临时文件混淆）
    let tmp = std::env::temp_dir();
    let leaked = std::fs::read_dir(&tmp).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let path = entry.path();
            path.is_file()
                && std::fs::read_to_string(&path).is_ok_and(|content| content.contains(marker))
        })
    });
    assert!(!leaked, "授权码不得残留于磁盘");
}
