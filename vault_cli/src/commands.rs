//! CLI 子命令实现。

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use vault_store::{initialize, parse_notes, unlock, Vault};

/// 从 `--<name> <path>` 指定的文件读取口令（保留末尾之外的空白）。
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// 读取口令：优先文件，其次 stdin。
fn read_secret(args: &[String], flag_name: &str, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = flag(args, flag_name) {
        let raw = fs::read_to_string(path)?;
        return Ok(raw.trim_end_matches(['\n', '\r']).to_owned());
    }
    eprintln!("{prompt}（提示：用 {flag_name} 可避免回显）：");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

fn master_password(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    read_secret(args, "--password-file", "请输入主密码后回车")
}

fn require_db(args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(flag(args, "--db").ok_or("缺少 --db")?))
}

/// 打开已有库；若不存在则初始化并打印恢复密钥。
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

fn report(outcome: &vault_store::ImportOutcome) {
    println!("成功导入 {} 条", outcome.imported);
    for failure in &outcome.failed {
        println!("  未导入 {failure}");
    }
}

/// `import`：从文本批量导入。
pub fn cmd_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = require_db(args)?;
    let text_path = flag(args, "--text").ok_or("缺少 --text")?;
    if !Path::new(text_path).exists() {
        return Err(format!("导入文本不存在：{text_path}").into());
    }
    let password = master_password(args)?;
    let mut text = String::new();
    fs::File::open(text_path)?.read_to_string(&mut text)?;

    let vault = open_or_init(&db, &password)?;
    let candidates = parse_notes(&text);
    println!("解析出 {} 条候选", candidates.len());

    let outcome = vault.import_candidates(&candidates);
    report(&outcome);
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

/// `list`：列出账号（仅平台名与字段数，不含任何密码）。
pub fn cmd_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = require_db(args)?;
    let password = master_password(args)?;
    let vault = unlock(&db, &password)?;
    let accounts = vault.list_accounts()?;
    println!("共 {} 条账号：", accounts.len());
    for account in accounts {
        println!("  {:<28} 字段 {} 个", account.app_name, account.field_types.len());
    }
    Ok(())
}

/// `export`：导出加密备份。
pub fn cmd_export(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = require_db(args)?;
    let out = flag(args, "--out").ok_or("缺少 --out")?;
    let password = master_password(args)?;
    let backup_pw = read_secret(args, "--backup-passphrase-file", "请输入备份口令（可与主密码不同）")?;

    let vault = unlock(&db, &password)?;
    let data = vault.export_backup(&backup_pw)?;
    fs::write(out, &data)?;
    println!("已导出加密备份：{out}（{} 字节）", data.len());
    println!("请牢记备份口令——丢失后备份无法恢复。");
    Ok(())
}

/// `import-backup`：从加密备份恢复/合并。
pub fn cmd_import_backup(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = require_db(args)?;
    let input = flag(args, "--in").ok_or("缺少 --in")?;
    let password = master_password(args)?;
    let backup_pw = read_secret(args, "--backup-passphrase-file", "请输入备份口令")?;

    let vault = open_or_init(&db, &password)?;
    let data = fs::read(input)?;
    let outcome = vault.import_backup(&data, &backup_pw)?;
    report(&outcome);
    println!("库内现有 {} 条账号", vault.list_accounts()?.len());
    Ok(())
}

/// `change-password`：修改主密码（仅重包 DEK，不重加密全量数据）。
pub fn cmd_change_password(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = require_db(args)?;
    let password = master_password(args)?;
    let new_password = read_secret(args, "--new-password-file", "请输入新主密码")?;

    let mut vault = unlock(&db, &password)?;
    vault.change_master_password(&new_password)?;
    println!("主密码已更新（仅重包 DEK，数据未重新加密）。");
    Ok(())
}

/// 帮助信息。
pub fn print_help() {
    println!("vault_cli —— 安全密码管家离线运维");
    println!();
    println!("  import          --db <库> --text <文本>       [--password-file <文件>]");
    println!("  list            --db <库>                     [--password-file <文件>]");
    println!("  export          --db <库> --out <备份文件>     [--backup-passphrase-file <文件>]");
    println!("  import-backup   --db <库> --in <备份文件>      [--backup-passphrase-file <文件>]");
    println!("  change-password --db <库>                     [--new-password-file <文件>]");
    println!();
    println!("说明：所有口令建议用 --*-file 传入，避免终端回显与 shell 历史留痕。");
}
