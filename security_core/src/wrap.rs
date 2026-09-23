//! 密钥包裹（Wrap）的结构与序列化。对照 docs/04 的 JSON 格式：
//!
//! ```json
//! {
//!   "version": 1,
//!   "kdf": { "algorithm":"argon2id", "salt":"...", "m_cost_kib":19456, "t_cost":2, "p_cost":1 },
//!   "cipher": { "algorithm":"aes-256-gcm", "nonce":"...", "tag":"..." },
//!   "ciphertext": "..."
//! }
//! ```
//!
//! - DEK 包裹：`kdf` 为 `Some`（含如何由主密码派生 KEK）。
//! - RecoveryKey 包裹：`kdf` 为 `None`（恢复密钥直接作为 AES-256 密钥使用）。

use serde::{Deserialize, Serialize};

use crate::bytes::Base64Bytes;
use crate::cipher::{self, TAG_LEN};
use crate::error::SecurityError;
use crate::kdf::KdfParams;

/// 当前包裹格式版本。
pub const CURRENT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    /// AES-256-GCM（认证加密，112-bit nonce + 128-bit tag）。
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

/// AEAD 密文配套参数（算法 + 随机 nonce + 认证标签）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherParams {
    /// 加密算法。
    pub algorithm: CipherAlgorithm,
    /// 随机 nonce（Base64）。
    pub nonce: Base64Bytes,
    /// 认证标签（Base64），与 `Wrap.ciphertext` 分离存储，见 docs/04。
    pub tag: Base64Bytes,
}

/// 一份密钥包裹（DEK 或恢复密钥加密的 DEK）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrap {
    /// 格式版本。
    pub version: u32,
    /// KDF 参数；DEK 包裹为含 KEK 派生参数，Recovery 包裹为 `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
    /// AEAD 参数。
    pub cipher: CipherParams,
    /// 密文去认证标签后的部分（Base64）。
    pub ciphertext: Base64Bytes,
}

impl Wrap {
    fn validate_version(&self) -> Result<(), SecurityError> {
        if self.version != CURRENT_VERSION {
            return Err(SecurityError::VersionMismatch {
                expected: CURRENT_VERSION,
                got: self.version,
            });
        }
        Ok(())
    }
}

/// 用 256-bit 密钥包裹明文（AES-256-GCM），生成 `Wrap`。
pub fn wrap_with_key(
    key: &[u8; 32],
    kdf: Option<KdfParams>,
    plaintext: &[u8],
) -> Result<Wrap, SecurityError> {
    let (nonce, ct_with_tag) = cipher::encrypt(key, plaintext)?;
    if ct_with_tag.len() < TAG_LEN {
        return Err(SecurityError::CiphertextTooShort);
    }
    let split = ct_with_tag.len() - TAG_LEN;
    let (body, tag) = ct_with_tag.split_at(split);
    Ok(Wrap {
        version: CURRENT_VERSION,
        kdf,
        cipher: CipherParams {
            algorithm: CipherAlgorithm::Aes256Gcm,
            nonce: Base64Bytes(nonce),
            tag: Base64Bytes(tag.to_vec()),
        },
        ciphertext: Base64Bytes(body.to_vec()),
    })
}

/// 用 256-bit 密钥解开 `Wrap`，返回明文。
pub fn unwrap_with_key(key: &[u8; 32], wrap: &Wrap) -> Result<Vec<u8>, SecurityError> {
    wrap.validate_version()?;
    let mut combined = Vec::with_capacity(wrap.ciphertext.0.len() + wrap.cipher.tag.0.len());
    combined.extend_from_slice(&wrap.ciphertext.0);
    combined.extend_from_slice(&wrap.cipher.tag.0);
    cipher::decrypt(key, &wrap.cipher.nonce.0, &combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [3u8; 32]
    }

    #[test]
    fn wrap_roundtrip_without_kdf() {
        let wrap = wrap_with_key(&key(), None, b"plaintext").unwrap();
        let out = unwrap_with_key(&key(), &wrap).unwrap();
        assert_eq!(out, b"plaintext");
    }

    #[test]
    fn wrap_uses_separate_nonce_and_tag() {
        let wrap = wrap_with_key(&key(), None, b"data").unwrap();
        assert_eq!(wrap.cipher.nonce.0.len(), crate::cipher::NONCE_LEN);
        assert_eq!(wrap.cipher.tag.0.len(), TAG_LEN);
    }

    #[test]
    fn wrap_rejects_wrong_key() {
        let wrap = wrap_with_key(&key(), None, b"data").unwrap();
        let wrong = [1u8; 32];
        assert!(matches!(
            unwrap_with_key(&wrong, &wrap),
            Err(SecurityError::Decryption)
        ));
    }

    #[test]
    fn wrap_serialization_matches_json_shape() {
        let wrap = wrap_with_key(&key(), None, b"data").unwrap();
        let json = serde_json::to_string(&wrap).unwrap();
        // 必须包含文档约定的字段；nonce/tag/ciphertext 为 base64 字符串。
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["cipher"]["algorithm"], "aes-256-gcm");
        assert!(v["cipher"]["nonce"].is_string());
        assert!(v["cipher"]["tag"].is_string());
        assert!(v["ciphertext"].is_string());
        assert!(v.get("kdf").is_none()); // recovery wrap 无 kdf
    }

    #[test]
    fn wrap_deserializes_from_json() {
        let wrap = wrap_with_key(&key(), None, b"data").unwrap();
        let json = serde_json::to_string(&wrap).unwrap();
        let back: Wrap = serde_json::from_str(&json).unwrap();
        let out = unwrap_with_key(&key(), &back).unwrap();
        assert_eq!(out, b"data");
    }

    #[test]
    fn wrap_rejects_unknown_version() {
        let mut wrap = wrap_with_key(&key(), None, b"data").unwrap();
        wrap.version = 99;
        assert!(matches!(
            unwrap_with_key(&key(), &wrap),
            Err(SecurityError::VersionMismatch { .. })
        ));
    }
}
