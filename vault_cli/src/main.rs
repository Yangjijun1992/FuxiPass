//! 安全密码管家离线运维 CLI。
//!
//! 主密码来源（二选一）：
//! - `--password-file <路径>`：从文件读取（**推荐**，无终端回显、不进入 shell 历史）
//! - 省略时从 stdin 读取一行
//!
//! 用法：
//! ```text
//! vault_cli import --db <库路径> --text <导入文本> [--password-file <密码文件>]
//! vault_cli list   --db <库路径> [--password-file <密码文件>]
//! ```
//! 输出中不打印任何密码明文。

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use vault_store::{initialize, parse_notes, unlock, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("import") => cmd_import(&args[1..]),
        Some("list") => cmd_list(&args[1..]),
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    println!("vault_cli —— 安全密码管家离线运维");
    println!();
    println!("  import --db <路径> --text <导入文本> [--password-file <密码文件>]");
    println!("  list   --db <路径> [--password-file <密码文件>]");
    println!();
    println!("说明：主密码建议用 --password-file 传入，避免终端回显与 shell 历史留痕。");
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn read_password(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = flag(args, "--password-file") {
        let raw = fs::read_to_string(path)?;
        return Ok(raw.trim_end_matches(['\n', '\r']).to_owned());
    }
    eprintln!("请输入主密码后回车（提示：用 --password-file 可避免回显）：");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

fn open_or_init(db: &Path, password: &str) -> Result<Vault, Box<dyn std::error::Error>> {
    if db.exists() {
        return Ok(unlock(db, password)?);
    }
    let init = initialize(db, password)?;
    println!("已创建保险库：{}", db.display());
    println!("恢复密钥（请立即离线保存，仅显示一次）：");
    println!("  {}", init.recovery_key_display);
    Ok(unlock(db, password)?)
}

fn cmd_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = PathBuf::from(flag(args, "--db").ok_or("缺少 --db")?);
    let text_path = flag(args, "--text").ok_or("缺少 --text")?;
    if !Path::new(text_path).exists() {
        return Err(format!("导入文本不存在：{text_path}").into());
    }
    let password = read_password(args)?;
    let mut text = String::new();
    fs::File::open(text_path)?.read_to_string(&mut text)?;

    let vault = open_or_init(&db, &password)?;
    let candidates = parse_notes(&text);
    println!("解析出 {} 条候选", candidates.len());

    let outcome = vault.import_candidates(&candidates);
    println!("成功导入 {} 条", outcome.imported);
    for failure in &outcome.failed {
        println!("  未导入 {failure}");
    }
    let missing: Vec<&str> = candidates
        .iter()
        .filter(|c| {
            c.login_password.is_none()
                && c.secondary_password.is_none()
                && c.payment_password.is_none()
                && c.api_key.is_none()
        })
        .filter_map(|c| c.app_name.as_deref())
        .collect();
    if !missing.is_empty() {
        println!("以下条目缺密码（已导入但需补全）：{}", missing.join("、"));
    }
    println!("库内现有 {} 条账号", vault.list_accounts()?.len());
    Ok(())
}

fn cmd_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = PathBuf::from(flag(args, "--db").ok_or("缺少 --db")?);
    let password = read_password(args)?;
    let vault = unlock(&db, &password)?;
    let accounts = vault.list_accounts()?;
    println!("共 {} 条账号：", accounts.len());
    for account in accounts {
        let fields = account.field_types.len();
        println!("  {:<28} 字段 {} 个", account.app_name, fields);
    }
    Ok(())
}
