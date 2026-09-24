//! 解析给定文本文件并打印候选账号摘要。
//!
//! 用法：`cargo run -p vault_store --example parse_file -- <路径>`
//! 输出中账号与密码一律脱敏，避免敏感值进入终端日志。

use std::env;
use std::fs;

fn mask(value: &Option<String>) -> String {
    match value {
        None => "—".to_owned(),
        Some(s) => {
            let n = s.chars().count();
            if n <= 2 {
                "*".repeat(n.max(1))
            } else {
                let head: String = s.chars().take(2).collect();
                format!("{head}{}", "*".repeat(n - 2))
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("用法: parse_file <路径>")?;
    let text = fs::read_to_string(&path)?;
    let candidates = vault_store::parse_notes(&text);

    println!("解析出 {} 条候选\n", candidates.len());
    let mut flagged = 0_usize;
    for (i, c) in candidates.iter().enumerate() {
        let flag = if c.issues.is_empty() {
            "OK  "
        } else {
            flagged += 1;
            "WARN"
        };
        println!(
            "[{flag}] #{:<2} 平台={:<26} 账号={:<18} 登录={:<8} 二级={:<6} 支付={:<6} 密钥={:<6} 网址={}",
            i + 1,
            c.app_name.as_deref().unwrap_or("—"),
            mask(&c.username),
            mask(&c.login_password),
            mask(&c.secondary_password),
            mask(&c.payment_password),
            mask(&c.api_key),
            c.url.as_deref().unwrap_or("—")
        );
        for issue in &c.issues {
            println!("          ↳ {issue}");
        }
    }
    println!("\n合计 {} 条，其中 {} 条带告警", candidates.len(), flagged);
    Ok(())
}
