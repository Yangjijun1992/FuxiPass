//! Argon2id 密钥派生。主密码 → KEK。
//!
//! 每个 Vault 在初始化时生成随机 salt，并固化 KDF 参数（内存/迭代/并行度），
//! 参数随 DEKWrap 一起序列化，保证同 salt + 同参数可稳定重建 KEK。

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::bytes::Base64Bytes;
use crate::error::SecurityError;
use crate::keys::Kek;

/// Argon2id 派生出的 KEK 长度（字节）。AES-256 密钥，正好 32 字节。
pub const KEK_LEN: usize = 32;

/// 默认 Argon2id 内存代价（KiB）。19 MiB = 19 * 1024 = 19456 KiB，OWASP 建议基准。
pub const DEFAULT_M_COST_KIB: u32 = 19 * 1024;
/// 默认迭代次数。
pub const DEFAULT_T_COST: u32 = 2;
/// 默认并行度。
pub const DEFAULT_P_COST: u32 = 1;
/// 派生 salt 长度（字节）。
pub const SALT_LEN: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// Argon2id 派生参数。`m_cost_kib` 为内存代价（KiB），`t_cost` 为迭代，`p_cost` 为并行度。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// 派生算法。
    pub algorithm: KdfAlgorithm,
    /// 随机 salt（Base64 序列化）。
    pub salt: Base64Bytes,
    /// 内存代价（KiB）。
    pub m_cost_kib: u32,
    /// 迭代次数。
    pub t_cost: u32,
    /// 并行度。
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            salt: Base64Bytes(vec![0u8; SALT_LEN]),
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// 以默认成本参数 + 随机 salt 构造（供初始化使用）。
    pub fn with_random_salt() -> Self {
        use crate::cipher::CryptoRng;
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            salt: Base64Bytes(CryptoRng::bytes(SALT_LEN)),
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }

    /// 校验参数是否在 Argon2id 允许范围内。
    pub fn validate(&self) -> Result<(), SecurityError> {
        if !matches!(self.algorithm, KdfAlgorithm::Argon2id) {
            return Err(SecurityError::InvalidKdf(
                "unsupported algorithm".to_owned(),
            ));
        }
        if self.salt.0.len() < 8 {
            return Err(SecurityError::InvalidKdf(
                "salt must be at least 8 bytes".to_owned(),
            ));
        }
        if self.m_cost_kib < 8 || self.t_cost < 1 || self.p_cost < 1 {
            return Err(SecurityError::InvalidKdf(
                "m_cost_kib>=8, t_cost>=1, p_cost>=1 required".to_owned(),
            ));
        }
        Ok(())
    }

    /// 由主密码派生 KEK（32 字节，zeroize 保护）。相同参数 + 相同 salt 结果确定。
    pub fn derive_kek(&self, master_password: &[u8]) -> Result<Kek, SecurityError> {
        if master_password.is_empty() {
            return Err(SecurityError::EmptyMasterPassword);
        }
        self.validate()?;
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEK_LEN))
            .map_err(|e| SecurityError::InvalidKdf(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; KEK_LEN]);
        argon2
            .hash_password_into(master_password, &self.salt.0, &mut *out)
            .map_err(|_| SecurityError::KeyDerivation)?;
        Kek::from_bytes(&*out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_same_params() {
        let params = KdfParams::with_random_salt();
        let a = params.derive_kek(b"pw").unwrap();
        let b = params.derive_kek(b"pw").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_differs_across_salt() {
        let a = KdfParams::with_random_salt();
        let b = KdfParams::with_random_salt();
        let ka = a.derive_kek(b"pw").unwrap();
        let kb = b.derive_kek(b"pw").unwrap();
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn derive_rejects_empty_password() {
        let params = KdfParams::with_random_salt();
        assert!(matches!(
            params.derive_kek(b""),
            Err(SecurityError::EmptyMasterPassword)
        ));
    }
}
