//! 安全密码管家离线运维 CLI。
//!
//! 口令来源（二选一）：
//! - `--password-file` / `--backup-passphrase-file` / `--new-password-file`：
//!   从文件读取（**推荐**，无终端回显、不进入 shell 历史）
//! - 省略时从 stdin 读取一行
//!
//! 输出中不打印任何密码明文。

mod commands;

use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("import") => commands::cmd_import(&args[1..]),
        Some("list") => commands::cmd_list(&args[1..]),
        Some("export") => commands::cmd_export(&args[1..]),
        Some("import-backup") => commands::cmd_import_backup(&args[1..]),
        Some("change-password") => commands::cmd_change_password(&args[1..]),
        Some("delete") => commands::cmd_delete(&args[1..]),
        Some("recover") => commands::cmd_recover(&args[1..]),
        _ => {
            commands::print_help();
            Ok(())
        }
    }
}
