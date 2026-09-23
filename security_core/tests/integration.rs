//! SecurityCore 端到端验收测试：驱动真实初始化 → 解锁 → 改密 → 恢复流程。
//!
//! 对应 PRD §8.1（密钥架构/加密）、§8.2（恢复/重置）的自动化验收用例。

use security_core::{
    change_master_password, derive_kek, generate_dek, generate_recovery_key,
    recover_and_reset, unwrap_dek, unwrap_dek_via_recovery, wrap_dek, wrap_dek_via_recovery,
    KdfParams, SecurityError, Wrap,
};

/// 一个已被初始化、可直接演练全部流程的测试夹具。
struct Vault {
    kek: security_core::Kek,
    dek: security_core::Dek,
    recovery: security_core::RecoveryKey,
    dekwrap: Wrap,
    recovery_wrap: Wrap,
}

fn bootstrap(master_password: &[u8]) -> Vault {
    let params = KdfParams::with_random_salt();
    let kek = derive_kek(master_password, &params).unwrap();
    let dek = generate_dek();
    let recovery = generate_recovery_key();
    let dekwrap = wrap_dek(&kek, &dek, Some(params.clone())).unwrap();
    let recovery_wrap = wrap_dek_via_recovery(&recovery, &dek).unwrap();
    Vault {
        kek,
        dek,
        recovery,
        dekwrap,
        recovery_wrap,
    }
}

#[test]
fn full_unlock_flow_restores_original_dek() {
    let v = bootstrap(b"master-pw");
    let unlocked = unwrap_dek(&v.kek, &v.dekwrap).unwrap();
    assert_eq!(unlocked.as_bytes(), v.dek.as_bytes());
}

#[test]
fn change_master_password_preserves_data_key() {
    let v = bootstrap(b"old-pw");
    let new_pw = b"brand-new-pw";
    let new_params = KdfParams::with_random_salt();
    let new_dekwrap =
        change_master_password(&v.kek, &v.dekwrap, new_pw, &new_params).unwrap();
    let new_kek = derive_kek(new_pw, &new_params).unwrap();
    let dek_after = unwrap_dek(&new_kek, &new_dekwrap).unwrap();
    assert_eq!(dek_after.as_bytes(), v.dek.as_bytes());
    // 旧 KEK 应无法再解新包裹（证明 DEK 已在新 KEK 下）
    assert!(matches!(
        unwrap_dek(&v.kek, &new_dekwrap),
        Err(SecurityError::Decryption)
    ));
}

#[test]
fn forgot_master_password_recovered_via_recovery_key() {
    let v = bootstrap(b"lost-pw");
    // 模拟忘记主密码：无法用任何猜测解包 —— 只能走恢复。
    let guessed = derive_kek(b"guess", &KdfParams::with_random_salt()).unwrap();
    assert!(matches!(
        unwrap_dek(&guessed, &v.dekwrap),
        Err(SecurityError::Decryption)
    ));

    // 用恢复密钥解出 DEK，并重设新主密码。
    let new_pw = b"recovered-pw";
    let new_params = KdfParams::with_random_salt();
    let new_dekwrap =
        recover_and_reset(&v.recovery, &v.recovery_wrap, new_pw, &new_params).unwrap();
    let new_kek = derive_kek(new_pw, &new_params).unwrap();
    let dek_after = unwrap_dek(&new_kek, &new_dekwrap).unwrap();
    assert_eq!(dek_after.as_bytes(), v.dek.as_bytes());
}

#[test]
fn wrong_recovery_key_does_not_decrypt() {
    let v = bootstrap(b"pw");
    let imposter = generate_recovery_key();
    assert!(matches!(
        unwrap_dek_via_recovery(&imposter, &v.recovery_wrap),
        Err(SecurityError::Decryption)
    ));
    // 但正确的恢复密钥仍可解（未破坏原始包裹）。
    let ok = unwrap_dek_via_recovery(&v.recovery, &v.recovery_wrap).unwrap();
    assert_eq!(ok.as_bytes(), v.dek.as_bytes());
}

#[test]
fn serialized_wrap_roundtrips_through_json() {
    let v = bootstrap(b"pw");
    let json = serde_json::to_string(&v.dekwrap).unwrap();
    let back: Wrap = serde_json::from_str(&json).unwrap();
    let unlocked = unwrap_dek(&v.kek, &back).unwrap();
    assert_eq!(unlocked.as_bytes(), v.dek.as_bytes());
    // kdf 必须保留，供日后重新派生 KEK。
    assert!(back.kdf.is_some());
}

#[test]
fn recovery_wrap_carries_no_kdf() {
    let v = bootstrap(b"pw");
    assert!(v.recovery_wrap.kdf.is_none());
}

#[test]
fn empty_master_password_rejected_at_derive() {
    let params = KdfParams::with_random_salt();
    assert!(matches!(
        derive_kek(b"", &params),
        Err(SecurityError::EmptyMasterPassword)
    ));
}

#[test]
fn same_plaintext_yields_different_ciphertext_each_wrap() {
    // 每个包裹的非索引 —— 用包装函数做两次相同明文包裹，应得到不同 nonce/密文。
    let v = bootstrap(b"pw");
    // 构造第二个 DEK 相同但独立包裹（用同一 KEK 包裹同一 DEK 两次）
    let w1 = wrap_dek(&v.kek, &v.dek, Some(KdfParams::with_random_salt())).unwrap();
    let w2 = wrap_dek(&v.kek, &v.dek, Some(KdfParams::with_random_salt())).unwrap();
    // nonce 不同 → 密文不同（AEAD 安全要求）。
    assert_ne!(w1.cipher.nonce.0, w2.cipher.nonce.0);
    assert_ne!(w1.ciphertext.0, w2.ciphertext.0);
}

#[test]
fn tampered_wrap_fails_authentication() {
    let v = bootstrap(b"pw");
    let mut tampered = v.dekwrap.clone();
    tampered.ciphertext.0[0] ^= 0x01;
    assert!(matches!(
        unwrap_dek(&v.kek, &tampered),
        Err(SecurityError::Decryption)
    ));
}
