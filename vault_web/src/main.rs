//! vault_web —— 安全密码管家 PC 端本地 Web 验证界面。
//!
//! **仅监听 127.0.0.1**，用于阶段性功能验证（解锁/检索/查看/增删/二次验证/审计）。
//! 非生产形态；生产形态为移动端 App（见 docs/01 架构规格）。

mod api;
mod api_compliance;
mod api_data;
mod api_recovery;
mod api_reset;
mod middleware;
mod recovery_client;
mod state;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::response::Html;
use axum::routing::{get, post};
use axum::{middleware as axum_mw, Router};
use vault_store::{AccountInput, Importance};

use crate::state::AppState;

const INDEX_HTML: &str = include_str!("index.html");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = parse_args(&args)?;

    if let Some(master) = config.seed_demo.as_deref() {
        seed_demo(&config.db_path, master)?;
    }

    let shared = Arc::new(AppState {
        db_path: config.db_path.clone(),
        session: Mutex::new(None),
        idle_timeout_secs: config.idle_timeout_secs,
        recovery_service_url: config.recovery_service_url.clone(),
        recovery: Mutex::new(None),
    });

    let protected = Router::new()
        .route("/api/lock", post(api::lock))
        .route("/api/settings/hint", post(api::set_hint))
        .route(
            "/api/recovery-key/regenerate",
            post(api::regenerate_recovery_key),
        )
        .route("/api/import/parse", post(api_data::import_parse))
        .route("/api/import/commit", post(api_data::import_commit))
        .route("/api/backup/export", post(api_data::export_backup))
        .route("/api/backup/import", post(api_data::import_backup))
        .route(
            "/api/accounts",
            get(api::list_accounts).post(api::create_account),
        )
        .route(
            "/api/accounts/:id",
            get(api::get_account)
                .put(api::update_account)
                .delete(api::delete_account),
        )
        .route("/api/reveal", post(api::reveal))
        .route("/api/audit", get(api_compliance::audit))
        .route("/api/audit/export", get(api_compliance::audit_export))
        .route("/api/compliance/summary", get(api_compliance::summary))
        .route("/api/vault/purge", post(api_compliance::purge))
        .route("/api/recovery/status", get(api_recovery::status))
        .route("/api/recovery/bind", post(api_recovery::bind))
        .route("/api/recovery/unbind", post(api_recovery::unbind))
        .route_layer(axum_mw::from_fn_with_state(
            shared.clone(),
            middleware::require_session,
        ));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(api::status))
        .route("/api/hint", get(api::hint))
        .route("/api/initialize", post(api::initialize))
        .route("/api/unlock", post(api::unlock))
        .route("/api/recover", post(api::recover))
        .route("/api/recover/request-code", post(api_reset::request_code))
        .route("/api/recover/verify-code", post(api_reset::verify_code))
        .route("/api/recover/reset", post(api_reset::reset))
        .merge(protected)
        .with_state(shared);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("FuxiPass 本地验证界面");
    println!("  数据库 : {}", config.db_path.display());
    println!("  访问   : http://127.0.0.1:{}", config.port);
    if let Some(url) = &config.recovery_service_url {
        println!("  找回服务: {url}");
    } else {
        println!("  找回服务: 未配置（邮箱绑定入口关闭）");
    }
    if config.idle_timeout_secs > 0 {
        println!("  自动锁定: 空闲 {} 秒后", config.idle_timeout_secs);
    } else {
        println!("  自动锁定: 已关闭（不推荐）");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

struct Config {
    db_path: PathBuf,
    port: u16,
    seed_demo: Option<String>,
    /// 空闲自动锁定秒数（0 = 关闭）。
    idle_timeout_secs: u64,
    /// 找回服务地址（可选）。
    recovery_service_url: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Config, Box<dyn std::error::Error>> {
    let mut db_path = PathBuf::from("fuxipass.vault.db");
    let mut port: u16 = 8787;
    let mut seed_demo = None;
    // 默认 5 分钟：与 PRD「闲置即锁定」一致；浏览器无法可靠感知切后台，故以请求空闲为准。
    let mut idle_timeout_secs: u64 = 300;
    let mut recovery_service_url: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db_path = PathBuf::from(args.get(i).ok_or("--db 需要一个路径参数")?);
            }
            "--port" => {
                i += 1;
                port = args.get(i).ok_or("--port 需要一个端口参数")?.parse()?;
            }
            "--recovery-service" => {
                i += 1;
                recovery_service_url =
                    Some(args.get(i).ok_or("--recovery-service 需要 URL")?.clone());
            }
            "--idle-timeout" => {
                i += 1;
                idle_timeout_secs = args
                    .get(i)
                    .ok_or("--idle-timeout 需要秒数（0 表示关闭）")?
                    .parse()?;
            }
            "--seed-demo" => {
                i += 1;
                seed_demo = Some(args.get(i).ok_or("--seed-demo 需要一个主密码参数")?.clone());
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("未知参数: {other}").into()),
        }
        i += 1;
    }
    Ok(Config {
        db_path,
        port,
        seed_demo,
        idle_timeout_secs,
        recovery_service_url,
    })
}

fn print_help() {
    println!("用法: vault_web [选项]");
    println!("  --db <路径>              保险库数据库路径（默认 fuxipass.vault.db）");
    println!("  --port <端口>            监听端口（默认 8787，仅绑定 127.0.0.1）");
    println!("  --seed-demo <主密码>     若库不存在则创建并写入演示数据");
    println!("  --idle-timeout <秒>      空闲自动锁定秒数（默认 300，0=关闭）");
    println!("  --recovery-service <URL> 找回服务地址（如 http://127.0.0.1:8799），启用邮箱绑定");
}

fn seed_demo(path: &Path, master: &str) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        println!("数据库已存在，跳过初始化: {}", path.display());
    } else {
        let init = vault_store::initialize(path, master)?;
        println!("已创建演示保险库: {}", path.display());
        println!("恢复密钥（请离线妥善保存）: {}", init.recovery_key_display);
    }
    let vault = vault_store::unlock(path, master)?;
    if vault.list_accounts()?.is_empty() {
        for input in demo_accounts() {
            let _ = vault.create_account(&input)?;
        }
        println!("已写入演示账号数据");
    }
    Ok(())
}

fn demo_accounts() -> Vec<AccountInput> {
    vec![
        AccountInput {
            app_name: "中国建设银行".to_owned(),
            url: Some("https://ebank.ccb.com".to_owned()),
            username: Some("zhangsan_123".to_owned()),
            notes: Some("预留手机号：138****0000".to_owned()),
            importance: Importance::Finance,
            login_password: Some("Ccb@2024Login".to_owned()),
            secondary_password: Some("888444".to_owned()),
            payment_password: Some("666777".to_owned()),
            api_key: None,
        },
        AccountInput {
            app_name: "淘宝".to_owned(),
            url: Some("https://www.taobao.com".to_owned()),
            username: Some("13800000000".to_owned()),
            notes: Some("常用购物账号".to_owned()),
            importance: Importance::Common,
            login_password: Some("Taobao#2024".to_owned()),
            secondary_password: None,
            payment_password: None,
            api_key: None,
        },
        AccountInput {
            app_name: "中国国家图书馆".to_owned(),
            url: Some("https://www.nlc.cn".to_owned()),
            username: Some("reader_zhang".to_owned()),
            notes: Some("注册于 2021 年".to_owned()),
            importance: Importance::LowFrequency,
            login_password: Some("Nlc$Read2021".to_owned()),
            secondary_password: None,
            payment_password: None,
            api_key: None,
        },
        AccountInput {
            app_name: "GitHub".to_owned(),
            url: Some("https://github.com".to_owned()),
            username: Some("zhangsan-dev".to_owned()),
            notes: Some("开发账号".to_owned()),
            importance: Importance::Social,
            login_password: Some("Gh!Dev2024".to_owned()),
            secondary_password: None,
            payment_password: None,
            api_key: Some("ghp_XXXXXXXXXXXXXXXXXXXX".to_owned()),
        },
    ]
}
