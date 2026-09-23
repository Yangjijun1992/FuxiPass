//! 顶层编排（KeyHierarchy）：将 KDF、密钥、包裹组合成可用的密钥管理 API。
//!
//! 覆盖 PRD §2.1 密钥体系与 §2.2 恢复流程：
//! - 初始化：主密码 → KEK，随机 DEK + RecoveryKey，生成 DEK/Recovery 包裹。
//! - 解锁：主密码 → KEK → 解包 DEK。
//! - 改密：仅用新 KEK 重新包裹 DEK（DEK 不变，不重加密全量）。
//! - 恢复：用 RecoveryKey 解包 DEK，重设主密码。

use crate::error::SecurityError;
use crate::kdf::KdfParams;
use crate::keys::{Dek, Kek, RecoveryKey};
use crate::wrap::{self, Wrap};

/// 由主密码派生 KEK。
pub fn derive_kek(master_password: &[u8], params: &KdfParams) -> Result<Kek, SecurityError> {
    params.derive_kek(master_password)
}

/// 生成随机 DEK。
pub fn generate_dek() -> Dek {
    Dek::generate()
}

/// 生成随机恢复密钥。
pub fn generate_recovery_key() -> RecoveryKey {
    RecoveryKey::generate()
}

/// 用 KEK 包裹 DEK（`kdf` 应为 `Some(params)`，供日后重新派生 KEK）。
pub fn wrap_dek(kek: &Kek, dek: &Dek, kdf: Option<KdfParams>) -> Result<Wrap, SecurityError> {
    wrap::wrap_with_key(kek.as_array(), kdf, dek.as_bytes())
}

/// 用 KEK 解包 DEK（解锁主流程）。
pub fn unwrap_dek(kek: &Kek, dekwrap: &Wrap) -> Result<Dek, SecurityError> {
    let raw = wrap::unwrap_with_key(kek.as_array(), dekwrap)?;
    Dek::from_bytes(&raw)
}

/// 用恢复密钥包裹 DEK（Recovery 包裹，`kdf` 为 `None`）。
pub fn wrap_dek_via_recovery(
    recovery: &RecoveryKey,
    dek: &Dek,
) -> Result<Wrap, SecurityError> {
    wrap::wrap_with_key(recovery.as_array(), None, dek.as_bytes())
}

/// 用恢复密钥解包 DEK（忘记主密码时的恢复）。
pub fn unwrap_dek_via_recovery(
    recovery: &RecoveryKey,
    recovery_wrap: &Wrap,
) -> Result<Dek, SecurityError> {
    let raw = wrap::unwrap_with_key(recovery.as_array(), recovery_wrap)?;
    Dek::from_bytes(&raw)
}

/// 修改主密码：用旧 KEK 解出 DEK，再用新密码+新参数重新包裹，DEK 保持不变。
pub fn change_master_password(
    old_kek: &Kek,
    old_dekwrap: &Wrap,
    new_password: &[u8],
    new_params: &KdfParams,
) -> Result<Wrap, SecurityError> {
    let dek = unwrap_dek(old_kek, old_dekwrap)?;
    let new_kek = derive_kek(new_password, new_params)?;
    wrap_dek(&new_kek, &dek, Some(new_params.clone()))
}

/// 忘记主密码：用恢复密钥解出 DEK，再重设新主密码（DEK 不变，数据不丢）。
pub fn recover_and_reset(
    recovery: &RecoveryKey,
    recovery_wrap: &Wrap,
    new_password: &[u8],
    new_params: &KdfParams,
) -> Result<Wrap, SecurityError> {
    let dek = unwrap_dek_via_recovery(recovery, recovery_wrap)?;
    let new_kek = derive_kek(new_password, new_params)?;
    wrap_dek(&new_kek, &dek, Some(new_params.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw() -> &'static [u8] {
        b"correct horse battery staple"
    }

    fn params() -> KdfParams {
        KdfParams::with_random_salt()
    }

    /// 完整初始化：主密码 → KEK；生成 DEK 与恢复码；生成两份包裹。
    fn init() -> (Kek, Dek, RecoveryKey, Wrap, Wrap) {
        let p = params();
        let kek = derive_kek(pw(), &p).unwrap();
        let dek = generate_dek();
        let recovery = generate_recovery_key();
        let dekwrap = wrap_dek(&kek, &dek, Some(p.clone())).unwrap();
        let recovery_wrap = wrap_dek_via_recovery(&recovery, &dek).unwrap();
        (kek, dek, recovery, dekwrap, recovery_wrap)
    }

    #[test]
    fn init_then_unlock_reauthenticates_dek() {
        let (kek, dek, _rec, dekwrap, _rw) = init();
        let unlocked = unwrap_dek(&kek, &dekwrap).unwrap();
        assert_eq!(unlocked.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn change_password_preserves_dek() {
        let (old_kek, dek, _rec, old_dekwrap, _rw) = init();
        let new_pw = b"new master password";
        let new_params = params();
        let new_dekwrap = change_master_password(&old_kek, &old_dekwrap, new_pw, &new_params)
            .unwrap();
        let new_kek = derive_kek(new_pw, &new_params).unwrap();
        let dek_after = unwrap_dek(&new_kek, &new_dekwrap).unwrap();
        // DEK 不变：数据无需重加密。
        assert_eq!(dek_after.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn recovery_resets_master_without_losing_dek() {
        let (_kek, dek, recovery, _dekwrap, recovery_wrap) = init();
        let new_pw = b"recovered password";
        let new_params = params();
        let new_dekwrap = recover_and_reset(&recovery, &recovery_wrap, new_pw, &new_params)
            .unwrap();
        let new_kek = derive_kek(new_pw, &new_params).unwrap();
        let dek_after = unwrap_dek(&new_kek, &new_dekwrap).unwrap();
        assert_eq!(dek_after.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn wrong_recovery_key_cannot_unwrap() {
        let (_kek, _dek, recovery, _dekwrap, recovery_wrap) = init();
        let wrong = generate_recovery_key();
        // 概率上不会撞到，且长度 32，仅密钥不同。
        assert!(matches!(
            unwrap_dek_via_recovery(&wrong, &recovery_wrap),
            Err(SecurityError::Decryption)
        ));
        let _ = recovery; // silence unused in this narrow test
    }

    #[test]
    fn wrong_master_password_derives_different_kek() {
        let (kek, _dek, _rec, dekwrap, _rw) = init();
        let wrong_params = params();
        let wrong_kek = derive_kek(b"something else", &wrong_params).unwrap();
        assert!(matches!(
            unwrap_dek(&wrong_kek, &dekwrap),
            Err(SecurityError::Decryption)
        ));
        let _ = kek;
    }
}
