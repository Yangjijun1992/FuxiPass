//! 找回服务可执行入口。
//!
//! 用法：`cargo run -p recovery_service -- [--port 8799] [--dev-echo-code]`
//!
//! ⚠️ `--dev-echo-code` 会**在响应中回显验证码**，仅用于本地联调；
//! 生产环境必须关闭，并通过真实邮件/短信通道下发。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use recovery_service::{api, RecoveryService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut port: u16 = 8799;
    let mut dev_echo_code = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args.get(i).ok_or("--port 需要端口")?.parse()?;
            }
            "--dev-echo-code" => dev_echo_code = true,
            _ => {}
        }
        i += 1;
    }

    let state = Arc::new(api::AppState {
        service: RecoveryService::new(dev_echo_code),
    });

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
