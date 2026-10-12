//! 找回服务可执行入口。
//!
//! 用法：
//! `cargo run -p recovery_service -- [--port 8799] [--db ./recovery.db] [--dev-echo-code]`
//! `  [--smtp-url smtps://smtp.qq.com:465 --smtp-user you@qq.com --smtp-pass-file ./smtp.pass]`
//!
//! `--db` 指定持久化文件（**绑定重启不丢**）；传 `--db :memory:` 则使用内存存储。
//!
//! ⚠️ `--dev-echo-code` 会**在响应中回显验证码**，仅用于本地联调；
//! 生产环境必须关闭，或改用 `--smtp-*` 真实投递。
//! ⚠️ 授权码只从 `--smtp-pass-file` 读取（不进 argv / shell 历史）。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;

use recovery_service::{api, RecoveryService};

/// 读取令牌文件；不存在则生成一个不可预测的令牌并以 0600 落盘。
fn load_or_create_token(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(std::fs::read_to_string(path)?.trim().to_owned());
    }
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let token = URL_SAFE_NO_PAD.encode(security_core::cipher::CryptoRng::bytes(32));
    let mut file = recovery_service::mailer::create_private_file(path)?;
    std::io::Write::write_all(&mut file, token.as_bytes())?;
    println!("已生成访问令牌（请让网页端加 --recovery-token-file 指向它）");
    Ok(token)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut port: u16 = 8799;
    let mut dev_echo_code = false;
    // 默认持久化到当前目录（`:memory:` 表示不持久化）；绑定数据本身非敏感（哈希+密文）
    let mut db_path = PathBuf::from("./recovery.db");
    let mut smtp_url: Option<String> = None;
    let mut smtp_user: Option<String> = None;
    let mut smtp_pass: Option<String> = None;
    let mut mail_from: Option<String> = None;
    let mut auth_token_file: Option<PathBuf> = None;
    let mut no_auth = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args.get(i).ok_or("--port 需要端口")?.parse()?;
            }
            "--db" => {
                i += 1;
                let v = args.get(i).ok_or("--db 需要路径（或用 :memory:）")?;
                db_path = if v == ":memory:" {
                    PathBuf::new()
                } else {
                    PathBuf::from(v)
                };
            }
            "--dev-echo-code" => dev_echo_code = true,
            "--smtp-url" => {
                i += 1;
                smtp_url = Some(args.get(i).ok_or("--smtp-url 需要地址")?.clone());
            }
            "--smtp-user" => {
                i += 1;
                smtp_user = Some(args.get(i).ok_or("--smtp-user 需要账号")?.clone());
            }
            "--smtp-pass-file" => {
                i += 1;
                let path = args.get(i).ok_or("--smtp-pass-file 需要路径")?;
                smtp_pass = Some(std::fs::read_to_string(path)?.trim().to_owned());
            }
            "--mail-from" => {
                i += 1;
                mail_from = Some(args.get(i).ok_or("--mail-from 需要地址")?.clone());
            }
            "--no-auth" => no_auth = true,
            "--auth-token-file" => {
                i += 1;
                auth_token_file = Some(PathBuf::from(
                    args.get(i).ok_or("--auth-token-file 需要路径")?,
                ));
            }
            _ => {}
        }
        i += 1;
    }

    let service = if db_path.as_os_str().is_empty() {
        println!("存储：内存（重启后绑定丢失）");
        RecoveryService::new(dev_echo_code)
    } else {
        println!("存储：{}", db_path.display());
        RecoveryService::open(dev_echo_code, &db_path)?
    };
    let service = match (smtp_url, smtp_user, smtp_pass) {
        (Some(url), Some(user), Some(password)) => {
            println!("发信：{url}（账号 {user}，授权码已从文件读取）");
            service.with_smtp(recovery_service::mailer::SmtpConfig {
                url,
                from: mail_from.clone().unwrap_or_else(|| user.clone()),
                user,
                password,
            })
        }
        (None, None, None) => {
            println!("⚠️ 未配置 SMTP：验证码不会真实投递（仅 --dev-echo-code 回显）");
            service
        }
        _ => return Err("--smtp-url / --smtp-user / --smtp-pass-file 必须同时提供".into()),
    };
    let auth_token = if no_auth {
        println!("⚠️ 已禁用鉴权（--no-auth）：仅限本地调试，切勿用于正式环境");
        None
    } else {
        let path = auth_token_file.unwrap_or_else(|| {
            if db_path.as_os_str().is_empty() {
                PathBuf::from("./recovery.token")
            } else {
                let mut p = db_path.clone();
                p.set_extension("token");
                p
            }
        });
        let token = load_or_create_token(&path)?;
        println!("鉴权：已启用（令牌文件 {}）", path.display());
        Some(token)
    };

    let state = Arc::new(api::AppState {
        service,
        auth_token,
    });

    let app = Router::new()
        .route("/v1/recovery/bind", post(api::bind))
        .route("/v1/recovery/challenge", post(api::challenge))
        .route("/v1/recovery/verify", post(api::verify))
        .route("/v1/recovery/wrap", post(api::redeem))
        .route("/v1/health", get(api::health))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api::guard,
        ))
        .with_state(state);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("零知识找回服务已启动: http://127.0.0.1:{port}");
    if dev_echo_code {
        println!("⚠️ 开发模式：验证码会回显在响应中（切勿用于生产）");
    }
    axum::serve(listener, app).await?;
    Ok(())
}
