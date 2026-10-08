//! 集成测试共用夹具（`tests/common/mod.rs` 不是独立测试目标，供各测试文件 `mod common;` 引入）。
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;
use vault_store::{initialize, unlock, AccountInput, Importance, Vault};

/// 测试用统一主密码。
pub const MASTER: &str = "correct horse battery staple";

/// 测试用临时保险库，析构时自动清理（含 WAL/SHM 附属文件）。
pub struct TempVault {
    path: PathBuf,
}

impl TempVault {
    /// 新建一个尚未初始化的临时库路径。
    pub fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fuxipass_test_{}.db",
            URL_SAFE_NO_PAD.encode(CryptoRng::bytes(12))
        ));
        Self { path }
    }

    /// 临时库路径。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut p = self.path.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }
}

/// 覆盖普通/高敏感字段的样例账号输入。
pub fn sample_input() -> AccountInput {
    AccountInput {
        app_name: "中国建设银行".to_owned(),
        url: Some("https://ebank.ccb.com".to_owned()),
        username: Some("zhangsan_123".to_owned()),
        notes: Some("密保答案：蓝色".to_owned()),
        importance: Importance::Finance,
        login_password: Some("LoginPw!234".to_owned()),
        secondary_password: Some("888444".to_owned()),
        payment_password: None,
        api_key: None,
    }
}

/// 初始化并解锁一个临时库，返回（临时库、已解锁 Vault、恢复密钥）。
pub fn bootstrapped() -> (TempVault, Vault, String) {
    let tv = TempVault::new();
    let init = initialize(tv.path(), MASTER).unwrap();
    let vault = unlock(tv.path(), MASTER).unwrap();
    (tv, vault, init.recovery_key_display)
}
