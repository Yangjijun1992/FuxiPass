//! 找回服务可执行入口。
//!
//! 用法：`cargo run -p recovery_service -- [--port 8799] [--db ./recovery.db] [--dev-echo-code]`
//!
//! `--db` 指定持久化文件（**绑定重启不丢**）；传 `--db :memory:` 则使用内存存储。
//!
//! ⚠️ `--dev-echo-code` 会**在响应中回显验证码**，仅用于本地联调；
//! 生产环境必须关闭，并通过真实邮件/短信通道下发。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use recovery_service::{api, RecoveryService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut port: u16 = 8799;
    let mut dev_echo_code = false;
    // 默认持久化到当前目录（`:memory:` 表示不持久化）；绑定数据本身非敏感（哈希+密文）
    let mut db_path = PathBuf::from("./recovery.db");
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
    let state = Arc::new(api::AppState { service });

    let app = Router::new()
        .route("/v1/recovery/bind", post(api::bind))
        .route("/v1/recovery/challenge", post(api::challenge))
        .route("/v1/recovery/verify", post(api::verify))
        .route("/v1/recovery/wrap", post(api::redeem))
        .route("/v1/health", get(api::health))
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
