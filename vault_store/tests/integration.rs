//! vault_store 端到端验收测试：初始化 → 解锁 → CRUD → 检索 → 揭示 → 改密 → 恢复。
//!
//! 关键安全断言（对应 docs/03）：数据库文件内不得出现任何明文敏感数据。

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;
use vault_store::{
    initialize, recover, unlock, AccountInput, FieldType, Importance, Vault, VaultError,
};

/// 测试用临时保险库，析构时自动清理（含 WAL/SHM 附属文件）。
struct TempVault {
    path: PathBuf,
}

impl TempVault {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fuxipass_test_{}.db",
            URL_SAFE_NO_PAD.encode(CryptoRng::bytes(12))
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

const MASTER: &str = "correct horse battery staple";

fn sample_input() -> AccountInput {
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

fn bootstrapped() -> (TempVault, Vault, String) {
    let tv = TempVault::new();
    let init = initialize(tv.path(), MASTER).unwrap();
    let vault = unlock(tv.path(), MASTER).unwrap();
    (tv, vault, init.recovery_key_display)
}

#[test]
fn initialize_then_unlock_succeeds() {
    let (_tv, vault, recovery_key) = bootstrapped();
    assert!(!recovery_key.is_empty());
    assert!(vault.list_accounts().unwrap().is_empty());
}

#[test]
fn initialize_refuses_to_overwrite_existing_vault() {
    let tv = TempVault::new();
    let _ = initialize(tv.path(), MASTER).unwrap();
    assert!(matches!(
        initialize(tv.path(), MASTER),
        Err(VaultError::AlreadyExists)
    ));
}

#[test]
fn unlock_with_wrong_password_fails() {
    let tv = TempVault::new();
    let _ = initialize(tv.path(), MASTER).unwrap();
    assert!(matches!(
        unlock(tv.path(), "wrong password"),
        Err(VaultError::InvalidInput(_))
    ));
    // 失败后数据仍完好，正确密码依旧可解锁（防爆破不毁数据）。
    let vault = unlock(tv.path(), MASTER).unwrap();
    assert!(vault.list_accounts().unwrap().is_empty());
}

#[test]
fn create_list_search_and_fetch_account() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();

    let all = vault.list_accounts().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].app_name, "中国建设银行");
    assert_eq!(all[0].username.as_deref(), Some("zhangsan_123"));
    assert!(all[0].field_types.contains(&FieldType::SecondaryPassword));

    // 检索：命中 app 名 / 网址 / 账号
    assert_eq!(vault.search_accounts("建设").unwrap().len(), 1);
    assert_eq!(vault.search_accounts("ccb").unwrap().len(), 1);
    assert_eq!(vault.search_accounts("ZHANGSAN").unwrap().len(), 1);
    assert!(vault.search_accounts("不存在的站").unwrap().is_empty());

    // 详情：密码仅以脱敏形式出现
    let detail = vault.get_account(&id).unwrap();
    assert_eq!(detail.notes.as_deref(), Some("密保答案：蓝色"));
    let secondary = detail
        .secrets
        .iter()
        .find(|s| s.field_type == FieldType::SecondaryPassword)
        .unwrap();
    assert!(secondary.requires_second_factor);
    assert_eq!(secondary.masked_preview, "88****");
    assert!(!detail
        .secrets
        .iter()
        .any(|s| s.masked_preview.contains("888444")));
}

#[test]
fn database_file_contains_no_plaintext() {
    let (tv, vault, _rk) = bootstrapped();
    let _ = vault.create_account(&sample_input()).unwrap();
    drop(vault);

    let bytes = std::fs::read(tv.path()).unwrap();
    for needle in [
        b"LoginPw!234".as_slice(),
        b"888444".as_slice(),
        "中国建设银行".as_bytes(),
        "zhangsan_123".as_bytes(),
        "密保答案".as_bytes(),
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "database file must not contain plaintext"
        );
    }
}

#[test]
fn reveal_secret_returns_value_and_writes_audit() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();

    let value = vault.reveal_secret(&id, FieldType::SecondaryPassword).unwrap();
    assert_eq!(value, "888444");
    let login = vault.reveal_secret(&id, FieldType::LoginPassword).unwrap();
    assert_eq!(login, "LoginPw!234");

    // 审计：记录了揭示操作与字段类别，但绝不含明文
    let audit = vault.list_audit(50).unwrap();
    assert!(audit
        .iter()
        .any(|e| e.operation == "reveal_secret"
            && e.field_category.as_deref() == Some("secondary_password")));
    assert!(audit.iter().all(|e| !e.operation.contains("888444")));

    assert!(matches!(
        vault.reveal_secret(&id, FieldType::PaymentPassword),
        Err(VaultError::SecretNotFound(_))
    ));
}

#[test]
fn update_account_replaces_values() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();

    let mut updated = sample_input();
    updated.app_name = "建设银行(新)".to_owned();
    updated.secondary_password = None;
    updated.payment_password = Some("666777".to_owned());
    vault.update_account(&id, &updated).unwrap();

    let detail = vault.get_account(&id).unwrap();
    assert_eq!(detail.summary.app_name, "建设银行(新)");
    assert!(!detail
        .summary
        .field_types
        .contains(&FieldType::SecondaryPassword));
    assert!(detail
        .summary
        .field_types
        .contains(&FieldType::PaymentPassword));
    assert_eq!(
        vault.reveal_secret(&id, FieldType::PaymentPassword).unwrap(),
        "666777"
    );
}

#[test]
fn delete_account_cascades_secret_fields() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();
    vault.delete_account(&id).unwrap();
    assert!(vault.list_accounts().unwrap().is_empty());
    assert!(matches!(
        vault.get_account(&id),
        Err(VaultError::AccountNotFound(_))
    ));
    assert!(matches!(
        vault.reveal_secret(&id, FieldType::LoginPassword),
        Err(VaultError::SecretNotFound(_))
    ));
}

#[test]
fn change_master_password_preserves_data() {
    let (tv, mut vault, _rk) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();
    vault.change_master_password("new-master-pw").unwrap();
    drop(vault);

    // 旧密码失效，新密码可解锁，且数据（含密文）完好。
    assert!(unlock(tv.path(), MASTER).is_err());
    let vault = unlock(tv.path(), "new-master-pw").unwrap();
    assert_eq!(
        vault.reveal_secret(&id, FieldType::SecondaryPassword).unwrap(),
        "888444"
    );
}

#[test]
fn recover_with_recovery_key_resets_password_and_keeps_data() {
    let (tv, vault, recovery_key) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();
    drop(vault);

    // 忘记主密码：用恢复密钥重设
    recover(tv.path(), &recovery_key, "recovered-master").unwrap();
    let vault = unlock(tv.path(), "recovered-master").unwrap();
    assert_eq!(vault.list_accounts().unwrap().len(), 1);
    assert_eq!(
        vault.reveal_secret(&id, FieldType::LoginPassword).unwrap(),
        "LoginPw!234"
    );

    // 错误恢复密钥被拒绝
    let bad = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-MMMM-NNNN-PPPP";
    assert!(matches!(
        recover(tv.path(), bad, "x-master"),
        Err(VaultError::RecoveryFailed)
    ));
}

#[test]
fn valid_input_rejects_empty_app_name() {
    let (_tv, vault, _rk) = bootstrapped();
    let mut input = sample_input();
    input.app_name = "   ".to_owned();
    assert!(matches!(
        vault.create_account(&input),
        Err(VaultError::InvalidInput(_))
    ));
}

#[test]
fn hint_is_readable_while_locked() {
    let (tv, vault, _rk) = bootstrapped();
    assert!(vault.hint().unwrap().is_none());

    vault.set_hint(Some("我最喜欢的颜色 + 生日")).unwrap();
    drop(vault);

    // 关键：未解锁（无 DEK）也能读到提示词，用于解锁界面。
    let hint = vault_store::read_hint(tv.path()).unwrap();
    assert_eq!(hint.as_deref(), Some("我最喜欢的颜色 + 生日"));

    // 库未初始化时应报错而非返回空。
    let empty = TempVault::new();
    assert!(matches!(
        vault_store::read_hint(empty.path()),
        Err(VaultError::NotInitialized)
    ));
}

#[test]
fn regenerating_recovery_key_invalidates_previous_key() {
    let (tv, vault, old_key) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();

    let new_key = vault.regenerate_recovery_key().unwrap();
    assert_ne!(old_key, new_key);
    drop(vault);

    // 旧恢复密钥失效
    assert!(matches!(
        recover(tv.path(), &old_key, "pw-via-old"),
        Err(VaultError::RecoveryFailed)
    ));
    // 新恢复密钥可用，且数据完好
    recover(tv.path(), &new_key, "pw-via-new").unwrap();
    let vault = unlock(tv.path(), "pw-via-new").unwrap();
    assert_eq!(
        vault.reveal_secret(&id, FieldType::LoginPassword).unwrap(),
        "LoginPw!234"
    );
    // 恢复操作在审计中留痕（不含明文）
    assert!(vault
        .list_audit(50)
        .unwrap()
        .iter()
        .any(|e| e.operation == "regenerate_recovery_key"));
}

#[test]
fn imported_candidates_are_persisted_and_searchable() {
    let (_tv, vault, _rk) = bootstrapped();
    let text = "淘宝\n账号：tb_user\n密码：Tb#2024\n\n---\n\n京东\n账号：jd_user\n密码：Jd#2024";
    let candidates = vault_store::parse_notes(text);
    assert_eq!(candidates.len(), 2);

    let outcome = vault.import_candidates(&candidates);
    assert_eq!(outcome.imported, 2);
    assert!(outcome.failed.is_empty());

    assert_eq!(vault.search_accounts("淘宝").unwrap().len(), 1);
    assert_eq!(vault.search_accounts("jd_user").unwrap().len(), 1);
    assert_eq!(vault.list_accounts().unwrap().len(), 2);
}

#[test]
fn import_reports_failed_item_without_aborting_others() {
    let (_tv, vault, _rk) = bootstrapped();
    let candidates = vec![
        vault_store::ImportCandidate {
            app_name: Some("有效站点".to_owned()),
            username: Some("u".to_owned()),
            login_password: Some("p".to_owned()),
            ..Default::default()
        },
        vault_store::ImportCandidate {
            app_name: Some("   ".to_owned()),
            ..Default::default()
        },
    ];
    let outcome = vault.import_candidates(&candidates);
    assert_eq!(outcome.imported, 1);
    assert_eq!(outcome.failed.len(), 1);
    assert_eq!(vault.list_accounts().unwrap().len(), 1);
}

#[test]
fn hint_is_plaintext_by_design_while_credentials_stay_encrypted() {
    let (tv, vault, _rk) = bootstrapped();
    let _ = vault.create_account(&sample_input()).unwrap();
    vault.set_hint(Some("记忆线索-非密码")).unwrap();
    drop(vault);

    let bytes = std::fs::read(tv.path()).unwrap();
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);

    // 凭证字段必须加密落库。
    assert!(!contains("LoginPw!234".as_bytes()));
    assert!(!contains("888444".as_bytes()));
    assert!(!contains("中国建设银行".as_bytes()));

    // 提示词按设计为明文（ADR-012），此断言用于把该设计意图固化。
    assert!(contains("记忆线索-非密码".as_bytes()));
}
