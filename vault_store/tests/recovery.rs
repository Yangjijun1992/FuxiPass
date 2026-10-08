//! 恢复与导入链路验收测试：改密、恢复码、提示词、文本导入。

mod common;

use vault_store::{recover, unlock, FieldType, VaultError};

use common::{bootstrapped, sample_input, TempVault, MASTER};

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
