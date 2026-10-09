//! FDEK 字段级独立密钥验收测试（T2.2）。
//!
//! 核心安全性质：**库已解锁（DEK 可用）但未完成二次验证时，高敏感字段不可读**。

// 集成测试为纯测试代码，允许 unwrap/expect/panic（src/ 仍全局 deny）。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vault_store::{initialize, unlock, AccountInput, FieldType, Importance, VaultError};

mod common;
use common::{bootstrapped, TempVault, MASTER};

fn input_with_high_sensitivity() -> AccountInput {
    AccountInput {
        app_name: "中国建设银行".to_owned(),
        url: None,
        username: Some("u1".to_owned()),
        notes: None,
        importance: Importance::Finance,
        login_password: Some("LoginPw!234".to_owned()),
        secondary_password: Some("888444".to_owned()),
        payment_password: Some("666777".to_owned()),
        api_key: Some("sk-test".to_owned()),
    }
}

#[test]
fn unlocked_vault_without_second_factor_cannot_read_high_sensitivity() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault
        .create_account(&input_with_high_sensitivity())
        .unwrap();

    // 结束二次验证会话：库仍是解锁状态（DEK 可用）
    vault.lock_second_factor();
    assert!(!vault.is_second_factor_unlocked());

    // 普通字段依旧可读
    assert_eq!(vault.list_accounts().unwrap().len(), 1);
    assert_eq!(
        vault.reveal_secret(&id, FieldType::LoginPassword).unwrap(),
        "LoginPw!234"
    );

    // 高敏感字段一律拒绝——这才是 FDEK 的意义
    for field in [
        FieldType::SecondaryPassword,
        FieldType::PaymentPassword,
        FieldType::ApiKey,
    ] {
        let err = vault.reveal_secret(&id, field).unwrap_err();
        assert!(
            matches!(err, VaultError::SecondFactorRequired),
            "{field:?} 应要求二次验证，实际 {err}"
        );
    }
}

#[test]
fn writing_high_sensitivity_requires_second_factor() {
    let (_tv, vault, _rk) = bootstrapped();
    vault.lock_second_factor();
    let err = vault
        .create_account(&input_with_high_sensitivity())
        .unwrap_err();
    assert!(matches!(err, VaultError::SecondFactorRequired));

    // 不含高敏感字段的账号仍可正常创建
    let mut plain = input_with_high_sensitivity();
    plain.secondary_password = None;
    plain.payment_password = None;
    plain.api_key = None;
    assert!(vault.create_account(&plain).is_ok());
}

#[test]
fn second_factor_unlock_restores_access() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault
        .create_account(&input_with_high_sensitivity())
        .unwrap();
    vault.lock_second_factor();

    assert!(vault.unlock_second_factor(MASTER).unwrap());
    assert_eq!(
        vault
            .reveal_secret(&id, FieldType::PaymentPassword)
            .unwrap(),
        "666777"
    );
}

#[test]
fn wrong_password_does_not_unlock_second_factor() {
    let (_tv, vault, _rk) = bootstrapped();
    let id = vault
        .create_account(&input_with_high_sensitivity())
        .unwrap();
    vault.lock_second_factor();

    assert!(!vault.unlock_second_factor("not-the-password").unwrap());
    assert!(!vault.is_second_factor_unlocked());
    let err = vault.reveal_secret(&id, FieldType::ApiKey).unwrap_err();
    assert!(matches!(err, VaultError::SecondFactorRequired));
}

#[test]
fn new_vault_has_fdek_enabled() {
    let (_tv, vault, _rk) = bootstrapped();
    assert!(vault.has_fdek(), "新库应默认启用 FDEK");
}

#[test]
fn legacy_vault_without_fdek_works_and_can_be_upgraded() {
    let tv = TempVault::new();
    let init = initialize(tv.path(), MASTER).unwrap();
    let vault = unlock(tv.path(), MASTER).unwrap();
    assert!(vault.has_fdek());
    drop(vault);

    // 模拟「从未启用 FDEK 的旧库」：清空 FDEK 元数据（等价于 v2 库迁移后的初始状态）
    {
        let conn = rusqlite::Connection::open(tv.path()).unwrap();
        conn.execute(
            "UPDATE meta SET fdek_kdf = NULL, fdek_wrap = NULL, fdek_wrap_recovery = NULL WHERE id = 1",
            [],
        )
        .unwrap();
    }

    // 兼容模式：库可用，高敏感字段由 DEK 保护，不做二次验证拦截
    let mut vault = unlock(tv.path(), MASTER).unwrap();
    assert!(!vault.has_fdek());
    let id = vault
        .create_account(&input_with_high_sensitivity())
        .unwrap();
    assert_eq!(
        vault
            .reveal_secret(&id, FieldType::SecondaryPassword)
            .unwrap(),
        "888444"
    );

    // 显式升级：需要主密码 + 恢复密钥
    vault
        .enable_fdek(MASTER, &init.recovery_key_display)
        .unwrap();
    assert!(vault.has_fdek());
    assert!(matches!(
        vault.reveal_secret(&id, FieldType::SecondaryPassword),
        Err(VaultError::SecondFactorRequired)
    ));

    // 升级后二次验证可读回原有数据（证明迁移正确重封装）
    assert!(vault.unlock_second_factor(MASTER).unwrap());
    assert_eq!(
        vault
            .reveal_secret(&id, FieldType::SecondaryPassword)
            .unwrap(),
        "888444"
    );
}

#[test]
fn upgrading_twice_is_rejected() {
    let (_tv, mut vault, rk) = bootstrapped();
    let err = vault.enable_fdek(MASTER, &rk).unwrap_err();
    assert!(matches!(err, VaultError::InvalidInput(_)));
}

#[test]
fn high_sensitivity_survives_reopen_with_second_factor() {
    let (tv, vault, _rk) = bootstrapped();
    let id = vault
        .create_account(&input_with_high_sensitivity())
        .unwrap();
    drop(vault);

    let vault = unlock(tv.path(), MASTER).unwrap();
    // 重开后未做二次验证 → 拒读
    assert!(matches!(
        vault.reveal_secret(&id, FieldType::PaymentPassword),
        Err(VaultError::SecondFactorRequired)
    ));
    // 二次验证后可读
    assert!(vault.unlock_second_factor(MASTER).unwrap());
    assert_eq!(
        vault
            .reveal_secret(&id, FieldType::PaymentPassword)
            .unwrap(),
        "666777"
    );
}
