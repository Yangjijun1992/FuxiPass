//! 联系方式哈希（用于零知识找回的绑定索引）。
//!
//! 设计目标：
//! 1. **确定性**：同一联系方式总是得到同一哈希（服务端据此查找绑定）；
//! 2. **抗枚举**：联系方式（邮箱/手机号）是低熵的，用 Argon2id 提高批量枚举成本；
//! 3. **不可逆**：只存哈希，不存明文联系方式。
//!
//! 固定应用盐（非机密）：仅用于区分不同应用的哈希域，不影响安全性。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::bytes::Base64Bytes;
use crate::error::SecurityError;
use crate::kdf::{KdfAlgorithm, KdfParams};

/// 联系方式哈希的固定应用盐。
const CONTACT_SALT: &[u8] = b"fuxipass.contact.v1";

/// Argon2id 参数（内存 KiB / 迭代 / 并行度）——兼顾移动端耗时与抗枚举强度。
const CONTACT_M_COST_KIB: u32 = 19 * 1024;
const CONTACT_T_COST: u32 = 2;
const CONTACT_P_COST: u32 = 1;

/// 计算联系方式哈希（URL-safe Base64，无填充）。
///
/// 输入会先做 `trim` + 转小写归一化，因此大小写与首尾空白不影响结果。
///
/// # Errors
/// 输入为空，或 Argon2id 派生失败时返回错误。
pub fn contact_hash(contact: &str) -> Result<String, SecurityError> {
    let normalized = contact.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(SecurityError::EmptyMasterPassword);
    }
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        salt: Base64Bytes(CONTACT_SALT.to_vec()),
        m_cost_kib: CONTACT_M_COST_KIB,
        t_cost: CONTACT_T_COST,
        p_cost: CONTACT_P_COST,
    };
    let key = params.derive_kek(normalized.as_bytes())?;
    Ok(URL_SAFE_NO_PAD.encode(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_normalized() {
        assert_eq!(
            contact_hash("Owner@Example.com").unwrap(),
            contact_hash("  owner@example.com  ").unwrap()
        );
    }

    #[test]
    fn differs_across_contacts() {
        assert_ne!(
            contact_hash("a@example.com").unwrap(),
            contact_hash("b@example.com").unwrap()
        );
    }

    #[test]
    fn rejects_empty() {
        assert!(contact_hash("   ").is_err());
    }

    #[test]
    fn does_not_leak_plaintext() {
        let h = contact_hash("someone@example.com").unwrap();
        assert!(!h.contains('@'));
        assert!(!h.to_lowercase().contains("example"));
    }
}
