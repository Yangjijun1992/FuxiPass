//! 找回服务绑定（客户端侧）验收测试（T2.4）。

// 集成测试为纯测试代码，允许 unwrap/expect/panic（src/ 仍全局 deny）。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vault_store::{contact_hash, unlock, VaultError};

mod common;
use common::{bootstrapped, MASTER};

#[test]
fn contact_hash_is_deterministic() {
    let a = contact_hash("User@Example.com").unwrap();
    let b = contact_hash("user@example.com").unwrap();
    assert_eq!(a, b, "同一联系方式（大小写/空白不敏感）必须得到同一哈希");
    assert!(!a.is_empty());
}

#[test]
fn contact_hash_differs_across_contacts() {
    let a = contact_hash("a@example.com").unwrap();
    let b = contact_hash("b@example.com").unwrap();
    assert_ne!(a, b);
}

#[test]
fn contact_hash_normalizes_whitespace_and_case() {
    let a = contact_hash("  Foo@Bar.com  ").unwrap();
    let b = contact_hash("foo@bar.com").unwrap();
    assert_eq!(a, b);
}

#[test]
fn contact_hash_rejects_empty() {
    assert!(matches!(
        contact_hash("   "),
        Err(VaultError::InvalidInput(_))
    ));
}

#[test]
fn contact_hash_does_not_reveal_plaintext() {
    let hash = contact_hash("yangjijun@example.com").unwrap();
    assert!(!hash.contains('@'), "哈希中不得含 @");
    assert!(
        !hash.to_lowercase().contains("example") && !hash.to_lowercase().contains("yangjijun"),
        "哈希中不得残留明文片段"
    );
}

#[test]
fn recovery_kit_contains_only_ciphertext() {
    let (_tv, vault, _rk) = bootstrapped();
    let _ = vault.create_account(&common::sample_input()).unwrap();
    let kit = vault.recovery_kit().unwrap();

    assert_eq!(kit.version, 1);
    assert!(kit.recovery_wrap.contains("ciphertext"), "应含包裹密文");
    // 套件整体不得含任何明文凭证
    let json = serde_json::to_string(&kit).unwrap();
    for needle in ["LoginPw!234", "888444", "中国建设银行", MASTER] {
        assert!(!json.contains(needle), "套件不得含明文: {needle}");
    }
    // 启用了 FDEK 的库应同时带上 FDEK 的恢复包裹
    assert!(
        kit.fdek_wrap_recovery.is_some(),
        "启用 FDEK 后应含其恢复包裹"
    );
}

#[test]
fn bind_and_unbind_recovery_contact_is_recorded() {
    let (_tv, vault, _rk) = bootstrapped();
    assert!(vault.recovery_contact().unwrap().is_none());

    let hash = contact_hash("owner@example.com").unwrap();
    vault.set_recovery_contact(Some(&hash)).unwrap();
    assert_eq!(
        vault.recovery_contact().unwrap().as_deref(),
        Some(hash.as_str())
    );

    // 绑定与解除都应留痕
    let ops: Vec<String> = vault
        .list_audit(50)
        .unwrap()
        .into_iter()
        .map(|e| e.operation)
        .collect();
    assert!(ops.iter().any(|o| o == "bind_recovery"));

    vault.set_recovery_contact(None).unwrap();
    assert!(vault.recovery_contact().unwrap().is_none());
}

#[test]
fn binding_survives_reopen() {
    let (tv, vault, _rk) = bootstrapped();
    let hash = contact_hash("persist@example.com").unwrap();
    vault.set_recovery_contact(Some(&hash)).unwrap();
    drop(vault);

    let vault = unlock(tv.path(), MASTER).unwrap();
    assert_eq!(
        vault.recovery_contact().unwrap().as_deref(),
        Some(hash.as_str())
    );
}

#[test]
fn reset_password_with_kit_restores_access_and_keeps_data() {
    use vault_store::recover_with_kit;

    let (tv, vault, recovery_key) = bootstrapped();
    let id = vault.create_account(&common::sample_input()).unwrap();
    // 取套件（模拟「绑定邮箱时上传到服务端」的内容）
    let kit = vault.recovery_kit().unwrap();
    drop(vault);

    // 忘记主密码：用套件 + 恢复密钥重置
    recover_with_kit(tv.path(), &kit, &recovery_key, "kit-reset-password").unwrap();

    // 旧密码失效
    assert!(vault_store::unlock(tv.path(), MASTER).is_err());
    // 新密码可用，且数据完好
    let vault = vault_store::unlock(tv.path(), "kit-reset-password").unwrap();
    assert_eq!(vault.list_accounts().unwrap().len(), 1);
    // 高敏感字段也仍可读（需二次验证）
    assert!(vault.unlock_second_factor("kit-reset-password").unwrap());
    assert_eq!(
        vault
            .reveal_secret(&id, vault_store::FieldType::SecondaryPassword)
            .unwrap(),
        "888444"
    );
}

#[test]
fn reset_with_kit_rejects_wrong_recovery_key() {
    use vault_store::recover_with_kit;

    let (tv, vault, _rk) = bootstrapped();
    let _ = vault.create_account(&common::sample_input()).unwrap();
    let kit = vault.recovery_kit().unwrap();
    drop(vault);

    let wrong = security_core::generate_recovery_key().to_display();
    assert!(matches!(
        recover_with_kit(tv.path(), &kit, &wrong, "new-pw-12345"),
        Err(VaultError::RecoveryFailed)
    ));
    // 旧密码依然有效（未破坏）
    assert!(vault_store::unlock(tv.path(), MASTER).is_ok());
}

#[test]
fn reset_with_kit_rejects_corrupted_kit() {
    use vault_store::recover_with_kit;

    let (tv, vault, recovery_key) = bootstrapped();
    let mut kit = vault.recovery_kit().unwrap();
    drop(vault);

    kit.recovery_wrap = "{\"broken\":true}".to_owned();
    assert!(matches!(
        recover_with_kit(tv.path(), &kit, &recovery_key, "new-pw-12345"),
        Err(VaultError::RecoveryFailed)
    ));
}

#[test]
fn reset_with_kit_rejects_unsupported_version() {
    use vault_store::recover_with_kit;

    let (tv, vault, recovery_key) = bootstrapped();
    let mut kit = vault.recovery_kit().unwrap();
    drop(vault);

    kit.version = 99;
    assert!(matches!(
        recover_with_kit(tv.path(), &kit, &recovery_key, "new-pw-12345"),
        Err(VaultError::InvalidInput(_))
    ));
}
