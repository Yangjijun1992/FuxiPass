//! 加密备份导出/导入验收测试（T3.6）。
//!
//! 关键性质：备份文件不含明文；口令错误/文件被篡改必须失败；
//! 换机迁移（A 库导出 → B 库导入）后全部字段可无损还原。

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;
use vault_store::{
    initialize, unlock, AccountInput, FieldType, Importance, Vault, VaultError,
};

struct TempVault {
    path: PathBuf,
}

impl TempVault {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fuxipass_backup_{tag}_{}.db",
            URL_SAFE_NO_PAD.encode(CryptoRng::bytes(10))
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
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

const MASTER: &str = "master-password-123";
const BACKUP_PW: &str = "backup-passphrase-456";

fn rich_input() -> AccountInput {
    AccountInput {
        app_name: "中国建设银行".to_owned(),
        url: Some("https://ebank.ccb.com".to_owned()),
        username: Some("zhangsan_123".to_owned()),
        notes: Some("密保答案：蓝色".to_owned()),
        importance: Importance::Finance,
        login_password: Some("LoginPw!234".to_owned()),
        secondary_password: Some("888444".to_owned()),
        payment_password: Some("666777".to_owned()),
        api_key: Some("sk-backup-test".to_owned()),
    }
}

fn fresh_vault(tag: &str) -> (TempVault, Vault) {
    let tv = TempVault::new(tag);
    let _ = initialize(tv.path(), MASTER).unwrap();
    let vault = unlock(tv.path(), MASTER).unwrap();
    (tv, vault)
}

#[test]
fn export_then_import_into_fresh_vault_restores_every_field() {
    let (_source_tv, source) = fresh_vault("src");
    let id = source.create_account(&rich_input()).unwrap();
    let backup = source.export_backup(BACKUP_PW).unwrap();
    drop(source);

    let (target_tv, target) = fresh_vault("dst");
    let outcome = target.import_backup(&backup, BACKUP_PW).unwrap();
    assert_eq!(outcome.imported, 1);
    assert!(outcome.failed.is_empty());

    let accounts = target.list_accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    let restored = &accounts[0];
    assert_eq!(restored.app_name, "中国建设银行");
    assert_eq!(restored.username.as_deref(), Some("zhangsan_123"));
    assert_eq!(restored.url.as_deref(), Some("https://ebank.ccb.com"));
    assert_eq!(restored.importance, Importance::Finance);

    let detail = target.get_account(&restored.id).unwrap();
    assert_eq!(detail.notes.as_deref(), Some("密保答案：蓝色"));
    assert_eq!(
        target.reveal_secret(&restored.id, FieldType::LoginPassword).unwrap(),
        "LoginPw!234"
    );
    assert_eq!(
        target.reveal_secret(&restored.id, FieldType::SecondaryPassword).unwrap(),
        "888444"
    );
    assert_eq!(
        target.reveal_secret(&restored.id, FieldType::PaymentPassword).unwrap(),
        "666777"
    );
    assert_eq!(
        target.reveal_secret(&restored.id, FieldType::ApiKey).unwrap(),
        "sk-backup-test"
    );
    assert!(!id.is_empty());
    drop(target_tv);
}

#[test]
fn backup_file_contains_no_plaintext() {
    let (_tv, vault) = fresh_vault("plain");
    let _ = vault.create_account(&rich_input()).unwrap();
    let backup = vault.export_backup(BACKUP_PW).unwrap();

    for needle in [
        "LoginPw!234",
        "888444",
        "666777",
        "sk-backup-test",
        "中国建设银行",
        "zhangsan_123",
        "密保答案",
    ] {
        assert!(
            !backup
                .windows(needle.len())
                .any(|w| w == needle.as_bytes()),
            "备份文件不得包含明文：{needle}"
        );
    }
}

#[test]
fn wrong_backup_passphrase_is_rejected() {
    let (_tv, vault) = fresh_vault("wrongpw");
    let _ = vault.create_account(&rich_input()).unwrap();
    let backup = vault.export_backup(BACKUP_PW).unwrap();

    let (target_tv, target) = fresh_vault("wrongpw_dst");
    let err = target.import_backup(&backup, "totally-wrong-pw").unwrap_err();
    assert!(
        matches!(err, VaultError::InvalidInput(_)),
        "口令错误应被拒绝，实际 {err}"
    );
    assert_eq!(target.list_accounts().unwrap().len(), 0, "不得写入任何数据");
    drop(target_tv);
}

#[test]
fn tampered_backup_is_rejected() {
    let (_tv, vault) = fresh_vault("tamper");
    let _ = vault.create_account(&rich_input()).unwrap();
    let mut backup = vault.export_backup(BACKUP_PW).unwrap();

    // 篡改密文中的一个字符
    let mid = backup.len() / 2;
    backup[mid] = if backup[mid] == b'A' { b'B' } else { b'A' };

    let (target_tv, target) = fresh_vault("tamper_dst");
    assert!(target.import_backup(&backup, BACKUP_PW).is_err(), "篡改必须被发现");
    drop(target_tv);
}

#[test]
fn short_backup_passphrase_is_rejected() {
    let (_tv, vault) = fresh_vault("short");
    assert!(matches!(
        vault.export_backup("short"),
        Err(VaultError::InvalidInput(_))
    ));
}

#[test]
fn merging_backup_into_non_empty_vault_adds_accounts() {
    let (_src_tv, source) = fresh_vault("merge_src");
    let _ = source.create_account(&rich_input()).unwrap();
    let backup = source.export_backup(BACKUP_PW).unwrap();
    drop(source);

    let target_tv = TempVault::new("merge_dst");
    let _ = initialize(target_tv.path(), MASTER).unwrap();
    let target = unlock(target_tv.path(), MASTER).unwrap();
    let mut other = rich_input();
    other.app_name = "淘宝".to_owned();
    let _ = target.create_account(&other).unwrap();

    let outcome = target.import_backup(&backup, BACKUP_PW).unwrap();
    assert_eq!(outcome.imported, 1);
    assert_eq!(target.list_accounts().unwrap().len(), 2);
    drop(target_tv);
}

#[test]
fn export_and_import_are_audited() {
    let (_tv, vault) = fresh_vault("audit");
    let backup = vault.export_backup(BACKUP_PW).unwrap();
    let _ = vault.import_backup(&backup, BACKUP_PW).unwrap();
    let operations: Vec<String> = vault
        .list_audit(20)
        .unwrap()
        .into_iter()
        .map(|e| e.operation)
        .collect();
    assert!(operations.iter().any(|o| o == "export_backup"));
    assert!(operations.iter().any(|o| o == "import_backup"));
}
