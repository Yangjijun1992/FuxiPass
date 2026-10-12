// 集成测试为**纯测试代码**，允许 unwrap/expect/panic（生产代码 src/ 仍全局 deny）。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! 核心账号链路验收测试：初始化、解锁、CRUD、检索、揭示、审计。

mod common;

use vault_store::{initialize, unlock, FieldType, VaultError};

use common::{bootstrapped, sample_input, TempVault, MASTER};

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

    let value = vault
        .reveal_secret(&id, FieldType::SecondaryPassword)
        .unwrap();
    assert_eq!(value, "888444");
    let login = vault.reveal_secret(&id, FieldType::LoginPassword).unwrap();
    assert_eq!(login, "LoginPw!234");

    // 审计：记录了揭示操作与字段类别，但绝不含明文
    let audit = vault.list_audit(50).unwrap();
    assert!(audit.iter().any(|e| e.operation == "reveal_secret"
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
        vault
            .reveal_secret(&id, FieldType::PaymentPassword)
            .unwrap(),
        "666777"
    );
}

#[test]
fn delete_moves_to_trash_then_restore_or_purge() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault.create_account(&sample_input()).unwrap();

    // 软删除：进入回收站，active 列表/单查都看不到
    vault.delete_account(&id).unwrap();
    assert!(vault.list_accounts().unwrap().is_empty());
    assert!(matches!(
        vault.get_account(&id),
        Err(VaultError::AccountNotFound(_))
    ));

    // 回收站可见，且已软删
    let trash = vault.list_trash().unwrap();
    assert_eq!(trash.len(), 1);
    assert!(trash[0].deleted_at.is_some());

    // 可恢复
    vault.restore_account(&id).unwrap();
    assert_eq!(vault.list_accounts().unwrap().len(), 1);
    assert!(vault.list_trash().unwrap().is_empty());

    // 再次软删 + 永久清除 → 级联删除高敏感字段（回收站清空、字段消失）
    vault.delete_account(&id).unwrap();
    vault.purge_account(&id).unwrap();
    assert!(vault.list_trash().unwrap().is_empty());
    assert!(matches!(
        vault.reveal_secret(&id, FieldType::LoginPassword),
        Err(VaultError::SecretNotFound(_))
    ));
}

#[test]
fn empty_trash_removes_all_deleted() {
    let (_tv, vault, _rk) = bootstrapped();
    let a = vault.create_account(&sample_input()).unwrap();
    let b = vault.create_account(&sample_input()).unwrap();
    vault.delete_account(&a).unwrap();
    vault.delete_account(&b).unwrap();
    assert_eq!(vault.list_trash().unwrap().len(), 2);

    let removed = vault.empty_trash().unwrap();
    assert_eq!(removed, 2);
    assert!(vault.list_trash().unwrap().is_empty());
    assert!(vault.list_accounts().unwrap().is_empty());
}
